fixtures_image := "hereticus-fixtures"

# Compile the ARM32 and MIPS test fixtures. Tests that read them depend on this
# recipe. The build runs in a container, because the tests compare exact
# machine code and thus need the same compiler on every machine.
fixtures:
    docker build --quiet --tag {{fixtures_image}} fixtures
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --volume "{{justfile_directory()}}:/work" \
        --workdir /work \
        {{fixtures_image}} ./fixtures/build.sh

# Matches build-test-native
build:
    cargo build --release

test *args: build fixtures
    cargo nextest run --release {{args}}

# Skips tests marked slow, for a fast inner loop
quick-test *args: build fixtures
    cargo nextest run --release -E 'not test(/slow/)' {{args}}

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
