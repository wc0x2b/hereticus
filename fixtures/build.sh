#!/usr/bin/env bash
# Compile the fixture C sources to ARM32 ELF objects at several optimization
# levels. Run by `just fixtures`.
#
# The corpus is generated, not committed, so it stays readable as C source and
# regenerates on demand. Tests skip themselves if clang cannot target ARM.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$here/src"
build="$here/build"
target="arm-linux-gnueabi"

if ! command -v clang >/dev/null 2>&1; then
    echo "fixtures: clang not found, cannot build ARM32 fixtures" >&2
    exit 1
fi

mkdir -p "$build"

for opt in O0 O1 O2 Os; do
    mkdir -p "$build/$opt"
    for source in "$src"/*.c; do
        name="$(basename "$source" .c)"
        clang --target="$target" -march=armv7-a -marm \
            -c "-$opt" -g \
            "$source" -o "$build/$opt/$name.o"
    done
done

# Stripped copies, for the tests that check recovery without symbols. The
# unstripped original stays, so a test can use its symbol table as the answer.
if command -v llvm-strip >/dev/null 2>&1; then
    strip_tool=llvm-strip
elif command -v strip >/dev/null 2>&1; then
    strip_tool=strip
else
    strip_tool=
fi

if [ -n "$strip_tool" ]; then
    for opt in O0 O1 O2 Os; do
        mkdir -p "$build/$opt-stripped"
        for object in "$build/$opt"/*.o; do
            name="$(basename "$object")"
            cp "$object" "$build/$opt-stripped/$name"
            "$strip_tool" "$build/$opt-stripped/$name"
        done
    done

    # One object with the exception index removed as well, so the tests cover
    # the path where nothing but the code itself is left.
    if command -v llvm-objcopy >/dev/null 2>&1; then
        mkdir -p "$build/bare"
        llvm-objcopy --remove-section=.ARM.exidx --remove-section=.ARM.extab \
            "$build/O2-stripped/basic.o" "$build/bare/basic.o"
    fi
else
    echo "fixtures: no strip tool found, skipping the stripped copies" >&2
fi

echo "fixtures: built $(find "$build" -name '*.o' | wc -l) objects in $build"
