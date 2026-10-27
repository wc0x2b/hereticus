#!/usr/bin/env bash
# Link the fixture C sources as Windows DLLs, as MSVC builds them, for
# x86-64, 32-bit x86 and ARM64. Run by `fixtures/build.sh`.
#
# Each DLL imports its undefined functions from `host.dll`, so each call
# to one goes through a slot of the import address table. Each exports one
# function, as a DLL exports some of its functions and not all. The symbol
# table that `/debug:symtab` keeps names every function, and a stripped
# copy keeps only the exception directory, the exports and the imports.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$here/src"
pe="$here/build/pe"
common_flags=(-fstack-protector-strong)

if ! command -v lld-link >/dev/null 2>&1 || ! command -v llvm-dlltool >/dev/null 2>&1; then
    echo "fixtures: no lld-link or llvm-dlltool, skipping the PE DLLs" >&2
    exit 0
fi
rm -rf "$pe"
mkdir -p "$pe"

# The clang target, the llvm-dlltool machine and the lld-link machine of
# each architecture.
declare -A targets=([x86_64]=x86_64-pc-windows-msvc [i686]=i686-pc-windows-msvc
    [arm64]=aarch64-pc-windows-msvc)
declare -A dlltool_machines=([x86_64]=i386:x86-64 [i686]=i386 [arm64]=arm64)
declare -A link_machines=([x86_64]=x64 [i686]=x86 [arm64]=arm64)

# Compile `source` for `arch` to `$pe/$name.obj`, and write the import
# library of `host.dll` for its undefined functions. `ordinals` imports
# each by an ordinal, with no name.
compile() {
    local arch="$1" source="$2" name="$3" imports="$4" extra="${5:-}"
    # `-ffreestanding` turns off the unwind tables, which MSVC always
    # writes, and which give the exception directory. `extra` passes the
    # obfuscation plugin, where there is one.
    # shellcheck disable=SC2086
    clang --target="${targets[$arch]}" "${common_flags[@]}" $extra \
        -ffreestanding -fasynchronous-unwind-tables -c -O2 "$source" -o "$pe/$name.obj"
    local ordinal=1 symbol
    {
        echo "LIBRARY host.dll"
        echo "EXPORTS"
        for symbol in $(llvm-nm --undefined-only --format=just-symbols "$pe/$name.obj"); do
            # 32-bit x86 decorates a C name with a leading `_`, and the
            # definition file names it bare.
            [[ $arch == i686 ]] && symbol="${symbol#_}"
            case "$imports" in
            names) echo "  $symbol" ;;
            ordinals) echo "  $symbol @$ordinal NONAME" ;;
            esac
            ordinal=$((ordinal + 1))
        done
    } >"$pe/$name-host.def"
    llvm-dlltool -m "${dlltool_machines[$arch]}" -d "$pe/$name-host.def" \
        -l "$pe/$name-host.lib"
}

# Link `$pe/$name.obj` with `link_flags`, strip a copy, and remove what
# the tests do not read.
link() {
    local arch="$1" name="$2" out="$3"
    shift 3
    lld-link /nodefaultlib /debug:symtab "/machine:${link_machines[$arch]}" "$@" \
        "/out:$pe/$out" "$pe/$name.obj" "$pe/$name-host.lib"
    llvm-strip --strip-all "$pe/$out" -o "$pe/${out%.*}-stripped.${out##*.}"
    rm -f "$pe/$name.obj" "$pe/${out%.*}.lib" "$pe/$name-host.def" "$pe/$name-host.lib"
}

build_dll() {
    local arch="$1" source="$2" export="$3"
    local name
    name="$arch-$(basename "$source" .c)"
    compile "$arch" "$source" "$name" names
    link "$arch" "$name" "$name.dll" /dll /noentry "/export:$export"
}

for arch in x86_64 i686 arm64; do
    build_dll "$arch" "$src/basic.c" call_chain
    build_dll "$arch" "$src/basic_v2.c" call_chain
    build_dll "$arch" "$src/firmware.c" handle
    build_dll "$arch" "$src/firmware_v2.c" handle
    build_dll "$arch" "$src/calls.c" nested
done

# An executable, whose entry point is `handle`.
for source in "$src/firmware.c" "$src/firmware_v2.c"; do
    name="x86_64-$(basename "$source" .c)"
    compile x86_64 "$source" "$name" names
    link x86_64 "$name" "$name.exe" /entry:handle /subsystem:console
done

# A DLL that imports by ordinal, and one that loads `host.dll` on its
# first call, through the delay-load directory.
for source in "$src/firmware.c" "$src/firmware_v2.c"; do
    base="$(basename "$source" .c)"
    compile x86_64 "$source" "x86_64-$base-ordinals" ordinals
    link x86_64 "x86_64-$base-ordinals" "x86_64-$base-ordinals.dll" /dll /noentry /export:handle

    name="x86_64-$base-delayed"
    compile x86_64 "$source" "$name" names
    clang --target=x86_64-pc-windows-msvc -ffreestanding -c -O2 \
        "$here/pe/delay_helper.c" -o "$pe/$name-helper.obj"
    link x86_64 "$name" "$name.dll" /dll /noentry /export:handle \
        /delayload:host.dll "$pe/$name-helper.obj"
    rm "$pe/$name-helper.obj"
done

# An LLVM pass plugin that flattens the control flow of a function, as an
# obfuscator does, so a test can check that `hereticus` still pairs the
# functions of a binary a mutation engine rewrote. It needs the LLVM
# development files and CMake, which the fixture image holds. See
# `fixtures/obfuscate`.
plugin=""
if command -v cmake >/dev/null 2>&1 && command -v ninja >/dev/null 2>&1 \
    && [ -d /usr/lib/llvm-22/lib/cmake/llvm ]; then
    plugin_build="$here/build/obfuscate"
    cmake -G Ninja -DCMAKE_CXX_COMPILER=clang++ \
        -DLLVM_DIR=/usr/lib/llvm-22/lib/cmake/llvm -B "$plugin_build" \
        "$here/obfuscate" >/dev/null
    ninja -C "$plugin_build" >/dev/null
    plugin="$plugin_build/HereticusObfuscate.so"
fi

if [ -n "$plugin" ]; then
    # One copy with its control flow flattened, and one with bogus flow,
    # as `HERETICUS_OBFUSCATE` selects. Each names the function after the
    # transform, so a test can read them apart.
    for pass in flattened bogus; do
        for source in "$src/firmware.c" "$src/firmware_v2.c"; do
            name="x86_64-$(basename "$source" .c)-$pass"
            HERETICUS_OBFUSCATE="${pass/flattened/flatten}" \
                compile x86_64 "$source" "$name" names "-fpass-plugin=$plugin"
            link x86_64 "$name" "$name.dll" /dll /noentry /export:handle
        done
    done
    echo "fixtures: obfuscated PE DLLs built in $pe"
else
    echo "fixtures: no LLVM development files, skipping the obfuscated DLLs" >&2
fi

echo "fixtures: PE files built in $pe"
