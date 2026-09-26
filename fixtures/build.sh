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
# The same for the MIPS vector table: the start of KSEG0, where MIPS firmware
# loads.
MIPS_VECTOR_BASE="0x80000000"

# Each distribution patches its own defaults into clang: Arch turns on the
# stack protector and NEON, Debian turns off the FPU on armel. Every flag that
# changes the code is stated here, thus the fixtures do not depend on which
# clang builds them.
common_flags=(-fstack-protector-strong)
arm_flags=(-march=armv7-a -marm -mfloat-abi=softfp -mfpu=neon)

if ! command -v clang >/dev/null 2>&1; then
    echo "fixtures: clang not found, cannot build ARM32 fixtures" >&2
    exit 1
fi

mkdir -p "$build"

for opt in O0 O1 O2 Os; do
    mkdir -p "$build/$opt"
    for source in "$src"/*.c; do
        name="$(basename "$source" .c)"
        clang --target="$target" "${arm_flags[@]}" "${common_flags[@]}" \
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
        clang --target="$mips_target" "${common_flags[@]}" -c "-$opt" -g \
            "$source" -o "$build/mips-$opt/$name.o"
        clang --target="$mipsbe_target" "${common_flags[@]}" -c "-$opt" -g \
            "$source" -o "$build/mipsbe-$opt/$name.o"
    done
done

# MIPS ABI PIC, which is what a shared object and most firmware is built as.
# It opens every non-leaf function with the `_gp_disp` preamble and calls
# through the GOT, so it exercises code no non-PIC fixture reaches. The
# matching non-PIC build sits beside it, because the interesting measurement is
# the difference between the two.
for opt in O0 O2; do
    mkdir -p "$build/mips-pic-$opt" "$build/mips-nopic-$opt"
    for source in "$src"/*.c; do
        name="$(basename "$source" .c)"
        clang --target="$mips_target" "${common_flags[@]}" -fPIC -c "-$opt" -g \
            "$source" -o "$build/mips-pic-$opt/$name.o"
        clang --target="$mips_target" "${common_flags[@]}" \
            -fno-pic -mno-abicalls -c "-$opt" -g \
            "$source" -o "$build/mips-nopic-$opt/$name.o"
    done
done

# The same pair in big-endian, which is the order shipped firmware uses. The
# PIC rules read decoded text rather than bytes, so both orders must give one
# answer; this is what lets a test say so.
mkdir -p "$build/mipsbe-pic-O2" "$build/mipsbe-nopic-O2"
for source in "$src"/*.c; do
    name="$(basename "$source" .c)"
    clang --target="$mipsbe_target" "${common_flags[@]}" -fPIC -c -O2 -g \
        "$source" -o "$build/mipsbe-pic-O2/$name.o"
    clang --target="$mipsbe_target" "${common_flags[@]}" \
        -fno-pic -mno-abicalls -c -O2 -g \
        "$source" -o "$build/mipsbe-nopic-O2/$name.o"
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

    # A stripped PIC object, so a test can check that function recovery finds
    # the start of a function whose prologue sits behind the PIC preamble.
    mkdir -p "$build/mips-pic-O2-stripped"
    for object in "$build/mips-pic-O2"/*.o; do
        name="$(basename "$object")"
        cp "$object" "$build/mips-pic-O2-stripped/$name"
        "$strip_tool" "$build/mips-pic-O2-stripped/$name"
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

        # MIPS raw images, named after the object tree they came from. Both
        # byte orders, and PIC beside non-PIC, because each reads differently.
        for tree in mips-O0 mips-O2 mipsbe-O0 mipsbe-O2 \
            mips-pic-O2 mipsbe-pic-O2 mips-nopic-O2 mipsbe-nopic-O2; do
            for source in "$src"/*.c; do
                name="$(basename "$source" .c)"
                llvm-objcopy -O binary --only-section=.text \
                    "$build/$tree/$name.o" "$build/raw/$tree-$name.bin"
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
    clang --target="$target" "${arm_flags[@]}" "${common_flags[@]}" \
        -c "$src/vectors.s" -o "$build/raw/vectors.o"
    ld.lld -Ttext="$VECTOR_BASE" -e _start --no-dynamic-linker \
        "$build/raw/vectors.o" -o "$build/raw/vectors.elf"
    llvm-objcopy -O binary "$build/raw/vectors.elf" "$build/raw/vectors.bin"
    rm -f "$build/raw/vectors.o"
    echo "fixtures: vector table linked at $VECTOR_BASE"

    for order in mipsel:mips mips:mipsbe; do
        triple="${order%%:*}-linux-gnu"
        stem="vectors-${order##*:}"
        clang --target="$triple" -c "$src/vectors_mips.s" \
            -o "$build/raw/$stem.o"
        ld.lld -Ttext="$MIPS_VECTOR_BASE" -e _start --no-dynamic-linker \
            "$build/raw/$stem.o" -o "$build/raw/$stem.elf"
        # Only .text: lld adds the MIPS ABI sections 64 KiB further on, and
        # the gap would fill the image with zeros.
        llvm-objcopy -O binary --only-section=.text \
            "$build/raw/$stem.elf" "$build/raw/$stem.bin"
        rm -f "$build/raw/$stem.o"
    done
    echo "fixtures: MIPS vector tables linked at $MIPS_VECTOR_BASE"
else
    echo "fixtures: no ld.lld, skipping the vector table" >&2
fi

echo "fixtures: built $(find "$build" -name '*.o' -o -name '*.bin' | wc -l) files in $build"
