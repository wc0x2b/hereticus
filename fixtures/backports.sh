#!/usr/bin/env bash
# Build real libraries before and after a real upstream fix. Run by
# `just backports`, after fixtures/backports.py has fetched the tarballs.
#
# A vendor ships a fix as a backport: the old release with one patch on top.
# Each pair here is that, so the functions the patch touches are the answer
# the comparison must give. zlib and Lua are C, tinyxml2 is C++, and
# smallvec is Rust. For each project, target and level this writes:
#
#   lib.so           unstripped, whose symbol table is the answer
#   lib-stripped.so  what the tool reads, with no symbols
#   lib.bin          the loaded image alone, code and data, as a flash dump
#                    holds it
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/build/backports"
downloads="$out/download"
patches="$here/patches"

# The flags that change the code are stated, as in build.sh, so the result
# does not depend on the defaults a distribution patches into clang.
arm_flags=(-march=armv7-a -marm -mfloat-abi=softfp -mfpu=neon)
thumb_flags=(-march=armv7-a -mthumb -mfloat-abi=softfp -mfpu=neon)
common_flags=(-fPIC -fno-stack-protector -w)

# name:triple, one per architecture the tool reads.
targets=(arm:arm-linux-gnueabi thumb:arm-linux-gnueabi mips:mips-linux-gnu
    mipsel:mipsel-linux-gnu)
# clang at every level that ships, and GCC with GNU ld at the two most
# firmware uses. A GCC build lands in `<arch>-gcc-<level>`.
levels=(O1 O2 O3 Os)
gcc_levels=(O2 Os)
gcc_version=14

# Sources that make up each library, relative to the unpacked tree.
zlib_sources=(adler32 compress crc32 deflate gzclose gzlib gzread gzwrite
    infback inffast inflate inftrees trees uncompr zutil)
lua_sources=(lapi lcode ldebug ldo ldump lfunc lgc llex lmem lobject lopcodes
    lparser lstate lstring ltable ltm lundump lvm lzio lauxlib lbaselib ldblib
    liolib lmathlib loslib ltablib lstrlib loadlib linit)
tinyxml2_sources=(tinyxml2)

# The compiler and source suffix of the project being built. C++ keeps the
# default exceptions, so each function carries an unwind entry, as shipped
# C++ does.
compiler=(clang)
suffix=c
gcc_standard=()

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
        [ "$arch" = thumb ] && flags+=("${thumb_flags[@]}")

        for level in "${levels[@]}"; do
            local dest="$out/$name-$variant/$arch-$level"
            local objects="$dest/obj"
            mkdir -p "$objects"
            for source in "${sources[@]}"; do
                "${compiler[@]}" --target="$triple" "${flags[@]}" "-$level" \
                    -c "$source_dir/$source.$suffix" -o "$objects/$source.o"
            done
            ld.lld -shared -o "$dest/lib.so" "$objects"/*.o
            finish "$dest"
        done

        # GCC builds the same sources and GNU ld links them, as a vendor's
        # toolchain does.
        local gcc_compiler="$triple-gcc-$gcc_version"
        [ "$suffix" = cpp ] && gcc_compiler="$triple-g++-$gcc_version"
        for level in "${gcc_levels[@]}"; do
            local dest="$out/$name-$variant/$arch-gcc-$level"
            local objects="$dest/obj"
            mkdir -p "$objects"
            for source in "${sources[@]}"; do
                "$gcc_compiler" "${flags[@]}" "${gcc_standard[@]}" "-$level" \
                    -c "$source_dir/$source.$suffix" -o "$objects/$source.o"
            done
            "$gcc_compiler" -shared -nostdlib -o "$dest/lib.so" "$objects"/*.o
            finish "$dest"
        done
    done
}

# Write the stripped library and the raw image of a linked `lib.so`.
finish() {
    local dest="$1"
    llvm-strip -o "$dest/lib-stripped.so" "$dest/lib.so"
    llvm-objcopy -O binary "$dest/lib.so" "$dest/lib.bin"
    rm -rf "$dest/obj"
}

# Build the Rust harness in fixtures/smallvec-harness against the smallvec
# tree as it is now, at each clang level, into $out/smallvec-<variant>.
#
# Both variants build from the same tree, patched in place between them,
# because a Rust symbol holds a hash of where its crate came from. Each
# target and level keeps its own cargo target directory, so the second
# variant builds only smallvec and the harness again.
build_rust() {
    local variant="$1"
    local rust_targets=(arm:armv7-unknown-linux-gnueabi:arm-linux-gnueabi
        mips:mips-unknown-linux-gnu:mips-linux-gnu
        mipsel:mipsel-unknown-linux-gnu:mipsel-linux-gnu)

    # Only the toolchain is in the image; the crates the standard library
    # needs are downloaded once, into the build directory.
    export CARGO_HOME="$here/build/cargo-home"
    # Build scripts run on the host, which has clang but no `cc`.
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=clang

    for target in "${rust_targets[@]}"; do
        local arch="${target%%:*}" rest="${target#*:}"
        local rust_triple="${rest%%:*}" triple="${rest##*:}"
        for level in "${levels[@]}"; do
            local target_dir="$here/build/cargo-target/$arch-$level"
            local opt_level="${level#O}"
            opt_level="${opt_level,,}"
            # rustup picks the toolchain the harness pins from the
            # directory cargo runs in.
            (cd "$here/smallvec-harness" &&
                RUSTFLAGS="--cap-lints allow -C opt-level=$opt_level -C linker=clang \
                    -C link-arg=--target=$triple -C link-arg=-fuse-ld=lld \
                    -C link-arg=-nostdlib" \
                    cargo build --quiet --release --locked \
                    -Zbuild-std=core,alloc --target "$rust_triple" \
                    --target-dir "$target_dir")
            local dest="$out/smallvec-$variant/$arch-$level"
            mkdir -p "$dest"
            cp "$target_dir/$rust_triple/release/libharness.so" "$dest/lib.so"
            finish "$dest"
        done
    done
}

unpack zlib-1.2.12.tar.gz zlib before
unpack zlib-1.2.12.tar.gz zlib after zlib-1.2.12-cve-2022-37434.patch
unpack lua-5.1.5.tar.gz lua before
unpack lua-5.1.5.tar.gz lua after lua-5.1.5-bug-2.patch
unpack tinyxml2-9.0.0.tar.gz tinyxml2 before
unpack tinyxml2-9.0.0.tar.gz tinyxml2 after tinyxml2-9.0.0-parse-deep-delete.patch

for variant in before after; do
    # zlib's configure finds <unistd.h>, which the gz* functions need.
    project_flags=(-DHAVE_UNISTD_H)
    build zlib "$variant" "$out/src/zlib-$variant" "${zlib_sources[@]}"
    project_flags=()
    build lua "$variant" "$out/src/lua-$variant/src" "${lua_sources[@]}"

    compiler=(clang++ -std=c++17)
    gcc_standard=(-std=c++17)
    suffix=cpp
    build tinyxml2 "$variant" "$out/src/tinyxml2-$variant" "${tinyxml2_sources[@]}"
    compiler=(clang)
    gcc_standard=()
    suffix=c
done

# A crate unpacks with the dates of its release. Cargo takes a source older
# than its last build for unchanged, so every file is given the time now.
unpack smallvec-1.6.0.crate smallvec before
find "$out/src/smallvec-before" -exec touch {} +
rm -rf "$out/src/smallvec"
mv "$out/src/smallvec-before" "$out/src/smallvec"
build_rust before
patch --quiet -p1 -d "$out/src/smallvec" < "$patches/smallvec-1.6.0-cve-2021-25900.patch"
build_rust after

# Consecutive releases of the same projects, each built one way with clang
# and one way with GCC, for the comparisons across versions. The symbols of
# each release are the answer there too.
out="$here/build/versions"
levels=(O2)
gcc_levels=(O2)
lua53_sources=(lapi lcode lctype ldebug ldo ldump lfunc lgc llex lmem lobject
    lopcodes lparser lstate lstring ltable ltm lundump lvm lzio lauxlib
    lbaselib lbitlib lcorolib ldblib liolib lmathlib loslib lstrlib ltablib
    lutf8lib loadlib linit)
for version in 1.2.11 1.2.12 1.2.13 1.3; do
    unpack "zlib-$version.tar.gz" zlib "$version"
    project_flags=(-DHAVE_UNISTD_H)
    build zlib "$version" "$out/src/zlib-$version" "${zlib_sources[@]}"
done
project_flags=()
for version in 5.1.4 5.1.5; do
    unpack "lua-$version.tar.gz" lua "$version"
    build lua "$version" "$out/src/lua-$version/src" "${lua_sources[@]}"
done
for version in 5.3.5 5.3.6; do
    unpack "lua-$version.tar.gz" lua "$version"
    build lua "$version" "$out/src/lua-$version/src" "${lua53_sources[@]}"
done
# expat: 2.4.5 fixes five CVEs, and 2.4.9 fixes CVE-2022-40674.
project_flags=(-I"$here/expat")
for version in 2.4.4 2.4.5 2.4.8 2.4.9; do
    unpack "expat-$version.tar.gz" expat "$version"
    build expat "$version" "$out/src/expat-$version/lib" xmlparse xmlrole xmltok
done
project_flags=()
compiler=(clang++ -std=c++17)
gcc_standard=(-std=c++17)
suffix=cpp
for version in 8.0.0 9.0.0 10.0.0; do
    unpack "tinyxml2-$version.tar.gz" tinyxml2 "$version"
    build tinyxml2 "$version" "$out/src/tinyxml2-$version" "${tinyxml2_sources[@]}"
done
compiler=(clang)
gcc_standard=()
suffix=c
echo "versions: built $(find "$out" -name lib.so | wc -l) libraries in $out"

out="$here/build/backports"
echo "backports: built $(find "$out" -name lib.so | wc -l) libraries in $out"
