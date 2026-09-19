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

bench:
    cargo bench

lint:
    cargo fmt
    cargo clippy
