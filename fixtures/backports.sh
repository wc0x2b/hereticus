#!/usr/bin/env bash
# Build real libraries before and after a real upstream fix. Run by
# `just backports`, after fixtures/backports.py has fetched the tarballs.
#
# A vendor ships a fix as a backport: the old release with one patch on top.
# Each pair here is that, so the functions the patch touches are the answer
# the comparison must give. For each project, target and level this writes:
#
#   lib.so           unstripped, whose symbol table is the answer
#   lib-stripped.so  what the tool reads, with no symbols
#   lib.text.bin     the code alone, as a flash dump holds it
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/build/backports"
downloads="$out/download"
patches="$here/patches"

# The flags that change the code are stated, as in build.sh, so the result
# does not depend on the defaults a distribution patches into clang.
arm_flags=(-march=armv7-a -marm -mfloat-abi=softfp -mfpu=neon)
common_flags=(-fPIC -fno-stack-protector -w)

# name:triple, one per architecture the tool reads.
targets=(arm:arm-linux-gnueabi mips:mips-linux-gnu mipsel:mipsel-linux-gnu)
levels=(O2 Os)

# Sources that make up each library, relative to the unpacked tree.
zlib_sources=(adler32 compress crc32 deflate gzclose gzlib gzread gzwrite
    infback inffast inflate inftrees trees uncompr zutil)
lua_sources=(lapi lcode ldebug ldo ldump lfunc lgc llex lmem lobject lopcodes
    lparser lstate lstring ltable ltm lundump lvm lzio lauxlib lbaselib ldblib
    liolib lmathlib loslib ltablib lstrlib loadlib linit)

# Unpack a tarball into $out/src/<name>-<variant>, patched when asked.
unpack() {
    local tarball="$1" name="$2" variant="$3" patch="${4:-}"
    local tree="$out/src/$name-$variant"
    rm -rf "$tree"
    mkdir -p "$tree"
    tar xzf "$downloads/$tarball" -C "$tree" --strip-components=1
    if [ -n "$patch" ]; then
        patch --quiet -p1 -d "$tree" < "$patches/$patch"
    fi
}

# Compile the listed sources of one tree and link them into a shared library.
# `project_flags` holds the defines a project's own configure step would set.
build() {
    local name="$1" variant="$2" source_dir="$3"
    shift 3
    local sources=("$@")

    for target in "${targets[@]}"; do
        local arch="${target%%:*}" triple="${target##*:}"
        local flags=("${common_flags[@]}" "${project_flags[@]}")
        [ "$arch" = arm ] && flags+=("${arm_flags[@]}")

        for level in "${levels[@]}"; do
            local dest="$out/$name-$variant/$arch-$level"
            local objects="$dest/obj"
            mkdir -p "$objects"
            for source in "${sources[@]}"; do
                clang --target="$triple" "${flags[@]}" "-$level" \
                    -c "$source_dir/$source.c" -o "$objects/$source.o"
            done
            ld.lld -shared -o "$dest/lib.so" "$objects"/*.o
            llvm-strip -o "$dest/lib-stripped.so" "$dest/lib.so"
            llvm-objcopy -O binary --only-section=.text "$dest/lib.so" "$dest/lib.text.bin"
            rm -rf "$objects"
        done
    done
}

unpack zlib-1.2.12.tar.gz zlib before
unpack zlib-1.2.12.tar.gz zlib after zlib-1.2.12-cve-2022-37434.patch
unpack lua-5.1.5.tar.gz lua before
unpack lua-5.1.5.tar.gz lua after lua-5.1.5-bug-2.patch

for variant in before after; do
    # zlib's configure finds <unistd.h>, which the gz* functions need.
    project_flags=(-DHAVE_UNISTD_H)
    build zlib "$variant" "$out/src/zlib-$variant" "${zlib_sources[@]}"
    project_flags=()
    build lua "$variant" "$out/src/lua-$variant/src" "${lua_sources[@]}"
done

echo "backports: built $(find "$out" -name lib.so | wc -l) libraries in $out"
