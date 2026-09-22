# Compile the ARM32 test fixtures. Tests that read them depend on this recipe.
fixtures:
    ./fixtures/build.sh

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
    cargo run --release --quiet -p heresy-cli -- --show-retouched \
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
    cargo bolero test {{target}} -p heresy
