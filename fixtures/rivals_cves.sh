#!/usr/bin/env bash
# Give the binaries before and after each published fix of
# real-life-reports/ to another diff tool, and write what it reports. Run by
# `just rivals-cves`, in the image of fixtures/rivals/Dockerfile, with
# ~/.cache, where fixtures/cve_binaries.py keeps the binaries, at /cache.
#
# Usage: rivals_cves.sh radare2|ghidra
#
# For each fix of fixtures/rivals/cves.txt this writes
# build/rivals/<tool>-cves/<name>.json, with each run of characters other
# than letters and digits of the name of the fix as one `-`, in the form of
# fixtures/rivals.sh: the rows the tool reports, the lowest score first.
# hereticus-cli/tests/truth_cves.rs reads these files.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tool="${1:?usage: rivals_cves.sh radare2|ghidra}"
cache=/cache
cases="$here/rivals/cves.txt"
out="$here/build/rivals/$tool-cves"

case "$tool" in
    radare2) version="$(radiff2 -v | head -n 1)" ;;
    ghidra) version="$(cat "$GHIDRA_HOME/Ghidra/application.properties")" ;;
    *) echo "rivals-cves: unknown tool $tool" >&2; exit 2 ;;
esac

# One line for each fix: its name for a file, and the binary before and after.
list_cases() {
    grep -v '^#' "$cases" | while IFS='|' read -r name before after; do
        echo "$(echo "$name" | sed -E 's/[^A-Za-z0-9]+/-/g') $before $after"
    done
}

# fixtures/cve_binaries.py pins the binaries by their SHA-256, so the list
# and the tool decide the output. A second run with the same inputs keeps
# what the first wrote.
inputs_hash="$(
    cat "$here/rivals_cves.sh" "$cases" "$here/rivals/Dockerfile" \
        "$here/rivals/HereticusVersionTracking.java" "$here/rivals/rows.py" \
        <(echo "$version") | sha256sum | cut -d' ' -f1
)"
stamp="$out/.inputs"
if [ -z "${RIVALS_FORCE:-}" ] && [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$inputs_hash" ]; then
    echo "rivals-cves: $tool up to date in $out"
    exit 0
fi
rm -rf "$out"
mkdir -p "$out"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# radiff2 with the analysis of `aaa`, and with `anal.hasnext`, as for the
# kernels: on these stripped executables, `-A` alone finds one fixed
# function of 38. It writes no list for a kext of Apple, which it cannot
# read, and then it reports no row.
run_radare2() {
    local before="$1" after="$2" dir="$3"
    radiff2 -A -e anal.hasnext=true -C -j "$before" "$after" 2>/dev/null >"$dir/report.json" || true
    grep -q '^\[' "$dir/report.json" || echo '[]' >"$dir/report.json"
}

# Auto Version Tracking, as for the backports.
run_ghidra() {
    local before="$1" after="$2" dir="$3"
    local headless="$GHIDRA_HOME/support/analyzeHeadless"
    mkdir -p "$dir/project"
    cp "$before" "$dir/before.so"
    cp "$after" "$dir/after.so"
    "$headless" "$dir/project" cves -import "$dir/before.so" "$dir/after.so" \
        >"$dir/ghidra-import.log" 2>&1 \
        || { cat "$dir/ghidra-import.log" >&2; return 1; }
    "$headless" "$dir/project" cves -process after.so -noanalysis \
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
    echo "rivals-cves: $tool $name"
}

# Four cases at once. Each Ghidra run is single threaded for the most part.
# Each start of Ghidra saves the JDK it found in a file of its settings, and
# starts at once can each find that file half written, and stop to ask for
# the JDK. One save first leaves the file whole.
export GHIDRA_MAXMEM=8G
if [ "$tool" = ghidra ]; then
    java -cp "$GHIDRA_HOME/support/LaunchSupport.jar" LaunchSupport "$GHIDRA_HOME" \
        -jdk_home -save >/dev/null
fi
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
