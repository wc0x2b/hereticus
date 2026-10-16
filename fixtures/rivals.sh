#!/usr/bin/env bash
# Give the stripped backport pairs to another diff tool, and write what it
# reports. Run by `just rivals` and `just rivals-ghidra`, in the image of
# fixtures/rivals/Dockerfile.
#
# Usage: rivals.sh radare2|ghidra
#
# For each build of fixtures/rivals/builds.txt this writes
# build/rivals/<tool>/<project>-<arch>-<level>.json, which holds the rows the
# tool reports, the lowest score first:
#
#   {"rows": [{"before": 1234, "after": 1250, "score": 0.82}, ...]}
#
# A row with no "after" is a function that is gone, and a row with no
# "before" is a new function. An address is where the file links the
# function. hereticus-cli/tests/rivals.rs reads these files.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tool="${1:?usage: rivals.sh radare2|ghidra}"
backports="$here/build/backports"
out="$here/build/rivals/$tool"
builds="$here/rivals/builds.txt"

case "$tool" in
    radare2) version="$(radiff2 -v | head -n 1)" ;;
    ghidra) version="$(cat "$GHIDRA_HOME/Ghidra/application.properties")" ;;
    *) echo "rivals: unknown tool $tool" >&2; exit 2 ;;
esac

# What decides the output: this script and what it reads, the tool, and the
# binaries. Ghidra takes half an hour over every build, so a second run with
# the same inputs keeps what the first wrote.
inputs_hash="$(
    {
        cat "$here/rivals.sh" "$builds" "$here/rivals/Dockerfile" "$here/rivals"/*.java "$here/rivals"/*.py
        echo "$version"
        grep -v '^#' "$builds" | while read -r project arch level; do
            for variant in before after; do
                cat "$backports/$project-$variant/$arch-$level/lib-stripped.so"
            done
        done
    } | sha256sum | cut -d' ' -f1
)"
stamp="$out/.inputs"
if [ -z "${RIVALS_FORCE:-}" ] && [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$inputs_hash" ]; then
    echo "rivals: $tool up to date in $out"
    exit 0
fi
rm -rf "$out"
mkdir -p "$out"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# radiff2 with the analysis of `aaa`, as its manual shows for a code diff.
run_radare2() {
    local before="$1" after="$2" result="$3"
    radiff2 -A -C -j "$before" "$after" 2>/dev/null >"$work/radiff2.json"
    python3 "$here/rivals/rows.py" radare2 "$work/radiff2.json" "$result"
}

# Ghidra analyses each program with its default analyzers, and then Auto
# Version Tracking pairs them.
run_ghidra() {
    local before="$1" after="$2" result="$3"
    local project="$work/ghidra"
    rm -rf "$project"
    mkdir -p "$project"
    cp "$before" "$work/before.so"
    cp "$after" "$work/after.so"
    local headless="$GHIDRA_HOME/support/analyzeHeadless"
    "$headless" "$project" rivals -import "$work/before.so" "$work/after.so" \
        >"$work/ghidra-import.log" 2>&1 \
        || { cat "$work/ghidra-import.log" >&2; return 1; }
    "$headless" "$project" rivals -process after.so -noanalysis \
        -scriptPath "$here/rivals" \
        -postScript HereticusVersionTracking.java before.so "$work/ghidra.json" \
        >"$work/ghidra-vt.log" 2>&1 \
        || { cat "$work/ghidra-vt.log" >&2; return 1; }
    # The headless analyzer exits with zero when a script throws.
    [ -f "$work/ghidra.json" ] || { cat "$work/ghidra-vt.log" >&2; return 1; }
    python3 "$here/rivals/rows.py" ghidra "$work/ghidra.json" "$result"
    rm "$work/ghidra.json"
}

grep -v '^#' "$builds" | while read -r project arch level; do
    name="$project-$arch-$level"
    echo "rivals: $tool $name"
    "run_$tool" \
        "$backports/$project-before/$arch-$level/lib-stripped.so" \
        "$backports/$project-after/$arch-$level/lib-stripped.so" \
        "$out/$name.json"
done
echo "$version" | head -n 1 >"$out/VERSION"
echo "$inputs_hash" >"$stamp"
