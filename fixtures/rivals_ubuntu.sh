#!/usr/bin/env bash
# Give the pairs of the Ubuntu security updates to another diff tool, and
# write what it reports. Run by `just rivals-ubuntu`, in the image of
# fixtures/rivals/Dockerfile, with the cache of fixtures/ubuntu_cves.py at
# /cache.
#
# Usage: rivals_ubuntu.sh radare2|ghidra
#
# For each case of fixtures/ubuntu_cases.json this writes
# build/rivals/<tool>-ubuntu/<library>-<arch>-<before>-<after>.json in the
# form of fixtures/rivals.sh: the rows the tool reports, the lowest score
# first. The tools read each library as Ubuntu ships it, with the names of
# the functions it exports. hereticus/tests/truth_ubuntu_rivals.rs reads
# these files.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tool="${1:?usage: rivals_ubuntu.sh radare2|ghidra}"
cache=/cache
cases="$here/ubuntu_cases.json"
out="$here/build/rivals/$tool-ubuntu"

case "$tool" in
    radare2) version="$(radiff2 -v | head -n 1)" ;;
    ghidra) version="$(cat "$GHIDRA_HOME/Ghidra/application.properties")" ;;
    *) echo "rivals-ubuntu: unknown tool $tool" >&2; exit 2 ;;
esac

# One line for each case: its name, and the library before and after.
list_cases() {
    python3 - "$cases" <<'EOF'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as file:
    for case in json.load(file):
        name = "-".join([case["library"], case["arch"], case["before"], case["after"]])
        print(name, case["files"][0][0]["path"], case["files"][1][0]["path"])
EOF
}

# The cases are pinned by their SHA-256, so the list and the tool decide the
# output. Ghidra takes hours over every case, so a second run with the same
# inputs keeps what the first wrote.
inputs_hash="$(
    cat "$here/rivals_ubuntu.sh" "$cases" "$here/rivals/Dockerfile" \
        "$here/rivals/HereticusVersionTracking.java" "$here/rivals/rows.py" \
        <(echo "$version") | sha256sum | cut -d' ' -f1
)"
stamp="$out/.inputs"
if [ -z "${RIVALS_FORCE:-}" ] && [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$inputs_hash" ]; then
    echo "rivals-ubuntu: $tool up to date in $out"
    exit 0
fi
rm -rf "$out"
mkdir -p "$out"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# radiff2 with the analysis of `aaa`, as for the backports.
run_radare2() {
    local before="$1" after="$2" dir="$3"
    radiff2 -A -C -j "$before" "$after" 2>/dev/null >"$dir/report.json"
}

# Auto Version Tracking, as for the backports.
run_ghidra() {
    local before="$1" after="$2" dir="$3"
    local headless="$GHIDRA_HOME/support/analyzeHeadless"
    mkdir -p "$dir/project"
    cp "$before" "$dir/before.so"
    cp "$after" "$dir/after.so"
    "$headless" "$dir/project" ubuntu -import "$dir/before.so" "$dir/after.so" \
        >"$dir/ghidra-import.log" 2>&1 \
        || { cat "$dir/ghidra-import.log" >&2; return 1; }
    "$headless" "$dir/project" ubuntu -process after.so -noanalysis \
        -scriptPath "$here/rivals" \
        -postScript HereticusVersionTracking.java before.so "$dir/report.json" default \
        >"$dir/ghidra-vt.log" 2>&1 \
        || { cat "$dir/ghidra-vt.log" >&2; return 1; }
    # The headless analyzer exits with zero when a script throws.
    [ -f "$dir/report.json" ] || { cat "$dir/ghidra-vt.log" >&2; return 1; }
}

# One case, timed, into its JSON file.
compare() {
    local name="$1" before="$2" after="$3"
    # A version can hold `:` and `+`, and Ghidra takes neither in a path.
    local dir="$work/${name//[^A-Za-z0-9._-]/_}"
    mkdir -p "$dir"
    local start end
    start="$(date +%s.%N)"
    "run_$tool" "$cache/$before" "$cache/$after" "$dir"
    end="$(date +%s.%N)"
    python3 "$here/rivals/rows.py" "$tool" "$dir/report.json" "$out/$name.json" \
        "$(python3 -c "print(round($end - $start, 3))")"
    rm -rf "$dir"
    echo "rivals-ubuntu: $tool $name"
}

# Four cases at once. Each Ghidra run is single threaded for the most part.
export GHIDRA_MAXMEM=8G
pids=()
failed=0
while read -r name before after; do
    compare "$name" "$before" "$after" &
    pids+=("$!")
    if [ "${#pids[@]}" -eq 4 ]; then
        for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
        pids=()
    fi
done < <(list_cases)
for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
# A failed comparison printed its log. Without the stamp, the next run
# compares again.
[ "$failed" -eq 0 ] || exit 1
echo "$version" | head -n 1 >"$out/VERSION"
echo "$inputs_hash" >"$stamp"
