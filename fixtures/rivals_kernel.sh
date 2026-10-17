#!/usr/bin/env bash
# Let Ghidra find the functions of one raw OpenWrt kernel, and write where
# each starts. Run by `just rivals-kernel`, in the `ghidra` stage of
# fixtures/rivals/Dockerfile.
#
# A raw image has no symbols and no sections, as a flash dump holds it.
# Ghidra analyses it twice: with its default analyzers, and with the
# Aggressive Instruction Finder too. Each run writes
# build/rivals/ghidra-kernel/<setting>.txt, one hexadecimal entry a line,
# which hereticus/tests/truth_function_starts.rs reads.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
kernel="$here/build/openwrt/mipsel-mt300nv2-kernel-22.03.2.bin"
out="$here/build/rivals/ghidra-kernel"

# Each run takes about six minutes, so a second run with the same inputs
# keeps what the first wrote.
inputs_hash="$(
    {
        cat "$here/rivals_kernel.sh" "$here/rivals/Dockerfile" "$kernel" \
            "$here/rivals/HereticusFunctionStarts.java" "$here/rivals/HereticusAggressive.java"
        cat "$GHIDRA_HOME/Ghidra/application.properties"
    } | sha256sum | cut -d' ' -f1
)"
stamp="$out/.inputs"
if [ -z "${RIVALS_FORCE:-}" ] && [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$inputs_hash" ]; then
    echo "rivals-kernel: up to date in $out"
    exit 0
fi
rm -rf "$out"
mkdir -p "$out"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp "$kernel" "$work/kernel.bin"

# The kernel of the GL.iNet GL-MT300N v2 is MIPS32 little-endian, linked at
# 0x80000000, as hereticus/tests/openwrt.rs says.
analyse() {
    local setting="$1"
    shift
    mkdir -p "$work/$setting"
    "$GHIDRA_HOME/support/analyzeHeadless" "$work/$setting" kernel \
        -import "$work/kernel.bin" -loader BinaryLoader -loader-baseAddr 0x80000000 \
        -processor MIPS:LE:32:default -scriptPath "$here/rivals" "$@" \
        -postScript HereticusFunctionStarts.java "$out/$setting.txt" \
        >"$work/$setting.log" 2>&1 \
        || { cat "$work/$setting.log" >&2; return 1; }
    # The headless analyzer exits with zero when the analysis fails.
    [ -s "$out/$setting.txt" ] || { cat "$work/$setting.log" >&2; return 1; }
    echo "rivals-kernel: $setting"
}

# Both runs at once. A kernel needs more than the default heap of 2 GB.
export GHIDRA_MAXMEM=16G
analyse default &
default=$!
analyse aggressive -preScript HereticusAggressive.java &
aggressive=$!
wait "$default"
wait "$aggressive"
echo "$inputs_hash" >"$stamp"
