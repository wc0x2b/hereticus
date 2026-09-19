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

echo "fixtures: built $(find "$build" -name '*.o' | wc -l) objects in $build"
