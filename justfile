fixtures_image := "hereticus-fixtures"

# Compile the ARM32 and MIPS test fixtures, and build the Go fixture with
# garble. Tests that read them depend on this recipe. The build runs in a container, because the tests compare exact
# machine code and thus need the same compiler on every machine.
fixtures:
    docker build --quiet --tag {{fixtures_image}} fixtures
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --volume "{{justfile_directory()}}:/work" \
        --workdir /work \
        {{fixtures_image}} ./fixtures/build.sh

# Build real libraries before and after a real upstream fix, so a test can
# check the comparison against the functions the fix touched.
backports: fixtures
    python3 fixtures/backports.py
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --volume "{{justfile_directory()}}:/work" \
        --workdir /work \
        {{fixtures_image}} ./fixtures/backports.sh

# Download two OpenWrt releases for three boards, and extract the code the
# tests compare. Each file is pinned by its SHA-256, and a second run reads the
# cached downloads instead of the network.
firmware:
    python3 fixtures/firmware.py

rivals_image := "hereticus-rivals"

# Give the stripped backports to radiff2, so a test can check the comparison
# against what radiff2 reports on the same pairs.
rivals: backports
    docker build --quiet --target radare2 --tag {{rivals_image}}-radare2 fixtures/rivals
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --volume "{{justfile_directory()}}:/work" \
        --workdir /work \
        {{rivals_image}}-radare2 ./fixtures/rivals.sh radare2

# The same with Ghidra Version Tracking. The image is about 2 GB and a first
# run takes about ten minutes, so only `test` runs it.
rivals-ghidra: backports
    docker build --quiet --target ghidra --tag {{rivals_image}}-ghidra fixtures/rivals
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --env HOME=/tmp \
        --volume "{{justfile_directory()}}:/work" \
        --workdir /work \
        {{rivals_image}}-ghidra ./fixtures/rivals.sh ghidra

# Let Ghidra find the functions of one raw kernel, with its default and its
# aggressive analysis, so a test can count how many it finds.
rivals-kernel: firmware
    docker build --quiet --target ghidra --tag {{rivals_image}}-ghidra fixtures/rivals
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --env HOME=/tmp \
        --volume "{{justfile_directory()}}:/work" \
        --workdir /work \
        {{rivals_image}}-ghidra ./fixtures/rivals_kernel.sh

# Let Ghidra find the functions of each garbled Go fixture, so a test can
# count how many it finds.
rivals-go: fixtures
    docker build --quiet --target ghidra --tag {{rivals_image}}-ghidra fixtures/rivals
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --env HOME=/tmp \
        --volume "{{justfile_directory()}}:/work" \
        --workdir /work \
        {{rivals_image}}-ghidra ./fixtures/rivals_go.sh

# Build the Ghidra extension of ghidra/ with its unit tests, and run it in
# headless Ghidra on stripped backports, a raw stub and two backport pairs, so
# a test can check what it finds and pairs.
ghidra-extension: build backports firmware
    docker build --quiet --target ghidra --tag {{rivals_image}}-ghidra fixtures/rivals
    docker build --quiet --tag {{rivals_image}}-ghidra-extension fixtures/ghidra-extension
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --env HOME=/tmp \
        --volume "{{justfile_directory()}}:/work" \
        --workdir /work \
        {{rivals_image}}-ghidra-extension ./fixtures/ghidra_extension.sh

# Show how long hereticus, radiff2 and Ghidra take on each backport pair.
rival-times: build rivals rivals-ghidra
    cargo nextest run --release --no-capture -E 'test(/times/)'

# Cargo publishes each crate after the crates it needs. Give `--dry-run` to
# check without upload.
# Publish every crate of the workspace to crates.io.
publish *args:
    cargo publish --workspace {{args}}

# Matches build-test-native
build:
    cargo build --release

# Build the static binary that a release attaches, in
# target/x86_64-unknown-linux-musl/dist/.
dist:
    cargo build --locked --profile dist --bin hereticus

# Build the Ghidra extension zip that a release attaches, in ghidra/dist/. The
# zip installs only in the Ghidra release that fixtures/rivals/Dockerfile pins.
ghidra-dist:
    docker build --quiet --target ghidra --tag {{rivals_image}}-ghidra fixtures/rivals
    docker build --quiet --tag {{rivals_image}}-ghidra-extension fixtures/ghidra-extension
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --env HOME=/tmp \
        --env GRADLE_USER_HOME=/work/fixtures/build/gradle \
        --volume "{{justfile_directory()}}:/work" \
        --workdir /work/ghidra \
        {{rivals_image}}-ghidra-extension gradle --quiet --no-daemon clean buildExtension

# Put the assets of a release in target/release-assets/: the binary with the
# README and licenses, and the Ghidra extension, named for the Ghidra release
# it installs in. Give the tag of the release, as `v0.1.0`.
release-assets tag: dist ghidra-dist
    #!/usr/bin/env bash
    set -euo pipefail
    target=x86_64-unknown-linux-musl
    out=target/release-assets
    rm -rf "$out"
    mkdir -p "$out"
    tar -czf "$out/hereticus-{{tag}}-$target.tar.gz" \
        -C "target/$target/dist" hereticus \
        -C "{{justfile_directory()}}" README.md LICENSE-APACHE LICENSE-MIT
    zip="$(echo ghidra/dist/ghidra_*_Hereticus.zip)"
    ghidra="$(basename "$zip" | sed -E 's/^(ghidra_[^_]+)_.*/\1/')"
    cp "$zip" "$out/hereticus-{{tag}}-$ghidra.zip"
    ls "$out"

# The tests in `truth_*` files check the results against the truth: the pairs
# of the OpenWrt kernels and of 218 Ubuntu security updates against the symbols
# of their builds, and the rank of each published fix of `real-life-reports/`
# and of the Ubuntu updates. They read about 1.6 GB that `truth` downloads to
# ~/.cache once, so `quick-test` skips them.
truth_tests := "binary(/^truth_/)"

# Fetch and pin what the `truth_*` tests read. The Apple binaries need the
# `ipsw` tool; `fixtures/cve_binaries.py` names the commands.
truth: firmware rivals-ghidra rivals-kernel rivals-go
    python3 fixtures/openwrt_debug.py
    python3 fixtures/cve_binaries.py
    python3 fixtures/ubuntu_cves.py

# `ghidra_extension` runs the Ghidra extension in headless Ghidra, from an
# image of about 2 GB, so `quick-test` skips it too.
ghidra_tests := "binary(ghidra_extension)"

test *args: build fixtures firmware backports truth ghidra-extension
    cargo nextest run --release {{args}}

# Skips tests marked slow, the `truth_*` tests and the Ghidra extension tests,
# for a fast inner loop
quick-test *args: build fixtures firmware backports rivals
    cargo nextest run --release -E 'not test(/slow/) and not {{truth_tests}} and not {{ghidra_tests}}' {{args}}

# Compare the two firmware fixtures, as a reader would compare two releases.
#
# Both sides build at the same optimization level, which is what a real pair of
# releases does: the difference on show is the source edit, not the compiler.
# Pass a level to see how much the optimizer changes the picture.
run level="O2" *args: fixtures
    cargo run --release --quiet -p hereticus-cli -- --show-retouched \
        fixtures/build/{{level}}/firmware.o \
        fixtures/build/{{level}}/firmware_v2.o {{args}}

bench:
    cargo bench

lint:
    cargo fmt
    cargo clippy

# Run one property test under a coverage-guided fuzzer. Needs nightly and
# `cargo install cargo-bolero`. The same tests run on stable under `just test`.
fuzz target:
    cargo bolero test {{target}} -p hereticus
