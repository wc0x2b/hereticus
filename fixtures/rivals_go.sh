#!/usr/bin/env bash
# Let Ghidra find the functions of each garbled build of the newer Go
# fixture, and write where each starts. Run by `just rivals-go`, in the `ghidra` stage of
# fixtures/rivals/Dockerfile.
#
# Each run writes build/rivals/ghidra-go/<build>.txt, one hexadecimal entry
# a line, which hereticus/tests/go_garbled.rs reads.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
in="$here/build/go"
out="$here/build/rivals/ghidra-go"

# A second run with the same inputs keeps what the first wrote.
inputs_hash="$(
    {
        cat "$here/rivals_go.sh" "$here/rivals/Dockerfile" "$in"/shfmt-3.12.0-*.bin \
            "$here/rivals/HereticusFunctionStarts.java"
        cat "$GHIDRA_HOME/Ghidra/application.properties"
    } | sha256sum | cut -d' ' -f1
)"
stamp="$out/.inputs"
if [ -z "${RIVALS_FORCE:-}" ] && [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$inputs_hash" ]; then
    echo "rivals-go: up to date in $out"
    exit 0
fi
rm -rf "$out"
mkdir -p "$out"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Ghidra picks the language from the ELF header, as for any file it is
# given, and runs its default analyzers.
export GHIDRA_MAXMEM=4G
for bin in "$in"/shfmt-3.12.0-*.bin; do
    name="$(basename "$bin" .bin)"
    (
        mkdir -p "$work/$name"
        "$GHIDRA_HOME/support/analyzeHeadless" "$work/$name" p -import "$bin" \
            -scriptPath "$here/rivals" \
            -postScript HereticusFunctionStarts.java "$out/$name.txt" \
            >"$work/$name.log" 2>&1 || { cat "$work/$name.log" >&2; exit 1; }
        # The headless analyzer exits with zero when the analysis fails.
        [ -s "$out/$name.txt" ] || { cat "$work/$name.log" >&2; exit 1; }
        echo "rivals-go: $name"
    ) &
done
wait
echo "$inputs_hash" >"$stamp"
