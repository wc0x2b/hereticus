#!/usr/bin/env bash
# Build the Go fixture, two releases of shfmt, with garble for each
# architecture, as Go malware is obfuscated, and write the function table
# of each build beside it. Run by `fixtures/build.sh`.
#
# garble scrambles the names and hides the function table from Ghidra and
# the like, so the scan reads the code alone. Each build writes
# build/go/shfmt-<version>-<arch>.bin and .truth, one "entry end name" a
# line, with the names that `garble reverse` gives back, so a test can tell
# which functions of two releases are the same. hereticus/tests/go_garbled.rs
# reads them.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/build/go"
mkdir -p "$out"

if ! command -v garble >/dev/null; then
    echo "fixtures: no garble, skipping the Go fixture" >&2
    exit 0
fi

# The module cache and the build caches stay under build/, as the image is
# read only, and no toolchain other than the image's is fetched.
export GOMODCACHE="$here/build/go-home/mod"
export GOCACHE="$here/build/go-home/cache"
export XDG_CACHE_HOME="$here/build/go-home/xdg"
export GOFLAGS=-mod=readonly
export GOTOOLCHAIN=local

# Each architecture as `GOARCH[:variant]`. MIPS soft float, as routers run.
targets=(amd64 386 arm64 arm:7 arm:5 mips:softfloat mipsle:softfloat)

for version in 3.11.0 3.12.0; do
cd "$here/go/shfmt-$version"
for target in "${targets[@]}"; do
    goarch="${target%%:*}"
    variant="${target#*:}"
    [ "$variant" = "$target" ] && variant=""
    name="shfmt-$version-$goarch${variant:+-$variant}"
    env=(GOOS=linux "GOARCH=$goarch")
    case "$goarch" in
        arm) env+=("GOARM=$variant") ;;
        mips | mipsle) env+=("GOMIPS=$variant") ;;
    esac
    env "${env[@]}" garble build -o "$out/$name.bin" mvdan.cc/sh/v3/cmd/shfmt
    # `garble reverse` maps the names back for the same package and the
    # same target only.
    pcln "$out/$name.bin" >"$out/$name.names"
    env "${env[@]}" garble reverse mvdan.cc/sh/v3/cmd/shfmt "$out/$name.names" >"$out/$name.truth"
    rm "$out/$name.names"
done
done
echo "fixtures: garbled Go built in $out"
