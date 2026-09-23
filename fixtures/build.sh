#!/usr/bin/env bash
# Compile the fixture C sources to ARM32 and MIPS32 ELF objects at several
# optimization levels. Run by `just fixtures`.
#
# The corpus is generated, not committed, so it stays readable as C source and
# regenerates on demand. Tests skip themselves if clang cannot target ARM.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$here/src"
build="$here/build"
target="arm-linux-gnueabi"
# MIPS ships in both byte orders, and both are read, so both are built.
mips_target="mipsel-linux-gnu"
mipsbe_target="mips-linux-gnu"

# Where the vector-table fixture is linked. Tests check the load-address
# check against this exact value, so the two must agree.
VECTOR_BASE="0x08000000"

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

# MIPS objects, in their own tree so the ARM fixtures keep their paths. Only
# the levels the MIPS tests use, because nothing needs the full matrix yet.
# Both byte orders, because both are read and each has its own decoder.
for opt in O0 O2; do
    mkdir -p "$build/mips-$opt" "$build/mipsbe-$opt"
    for source in "$src"/*.c; do
        name="$(basename "$source" .c)"
        clang --target="$mips_target" -c "-$opt" -g \
            "$source" -o "$build/mips-$opt/$name.o"
        clang --target="$mipsbe_target" -c "-$opt" -g \
            "$source" -o "$build/mipsbe-$opt/$name.o"
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

        # Raw images: the code with no container at all, as a flash dump is.
        # The symbol table of the object they came from is the answer.
        mkdir -p "$build/raw"
        for opt in O1 O2 Os; do
            for source in "$src"/*.c; do
                name="$(basename "$source" .c)"
                llvm-objcopy -O binary --only-section=.text \
                    "$build/$opt/$name.o" "$build/raw/$opt-$name.bin"
            done
        done
    fi
else
    echo "fixtures: no strip tool found, skipping the stripped copies" >&2
fi

# The vector table is the only fixture holding absolute addresses, so it is
# the only one that can exercise the load-address check. It must be linked,
# not just assembled, for those addresses to be real.
if command -v ld.lld >/dev/null 2>&1 && command -v llvm-objcopy >/dev/null 2>&1; then
    mkdir -p "$build/raw"
    clang --target="$target" -march=armv7-a -marm \
        -c "$src/vectors.s" -o "$build/raw/vectors.o"
    ld.lld -Ttext="$VECTOR_BASE" -e _start --no-dynamic-linker \
        "$build/raw/vectors.o" -o "$build/raw/vectors.elf"
    llvm-objcopy -O binary "$build/raw/vectors.elf" "$build/raw/vectors.bin"
    rm -f "$build/raw/vectors.o"
    echo "fixtures: vector table linked at $VECTOR_BASE"
else
    echo "fixtures: no ld.lld, skipping the vector table" >&2
fi

echo "fixtures: built $(find "$build" -name '*.o' -o -name '*.bin' | wc -l) files in $build"
