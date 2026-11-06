#!/usr/bin/env bash
# Give the two garbled releases of the Go fixture to another diff tool, and
# write every pair of functions it makes. Run by `just rivals-go-pairs`, in
# the image of fixtures/rivals/Dockerfile.
#
# Usage: rivals_go_pairs.sh radare2|ghidra
#
# For each build of fixtures/build/go, the tool compares shfmt 3.11.0 with
# shfmt 3.12.0. This writes build/rivals/<tool>-go-pairs/<build>.json:
#
#   {"seconds": 81.2, "pairs": [[4198400, 4198400], ...]}
#
# Each pair is the start of a function of the older release and of the one
# the tool pairs it with in the newer release. hereticus/tests/go_garbled.rs
# judges the pairs by the names that `garble reverse` gives back.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tool="${1:?usage: rivals_go_pairs.sh radare2|ghidra}"
in="$here/build/go"
out="$here/build/rivals/$tool-go-pairs"
older=3.11.0
newer=3.12.0

case "$tool" in
    radare2) version="$(radiff2 -v | head -n 1)" ;;
    ghidra) version="$(cat "$GHIDRA_HOME/Ghidra/application.properties")" ;;
    *) echo "rivals-go-pairs: unknown tool $tool" >&2; exit 2 ;;
esac

# A second run with the same inputs keeps what the first wrote.
inputs_hash="$(
    {
        cat "$here/rivals_go_pairs.sh" "$here/rivals/Dockerfile" \
            "$here/rivals/HereticusVersionTracking.java" "$in"/shfmt-*.bin
        echo "$version"
    } | sha256sum | cut -d' ' -f1
)"
stamp="$out/.inputs"
if [ -z "${RIVALS_FORCE:-}" ] && [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$inputs_hash" ]; then
    echo "rivals-go-pairs: $tool up to date in $out"
    exit 0
fi
rm -rf "$out"
mkdir -p "$out"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# radiff2 with the analysis of `aaa`, and with `anal.hasnext`, as for the
# kernels: with `-A` alone, radiff2 shows one row for a stripped build of Go,
# though `aaa` in radare2 finds thousands of functions in it.
run_radare2() {
    local before="$1" after="$2" dir="$3"
    radiff2 -A -e anal.hasnext=true -C -j "$before" "$after" 2>"$dir/radiff2.log" >"$dir/report.json" \
        || { cat "$dir/radiff2.log" >&2; return 1; }
    python3 - "$dir/report.json" "$dir/pairs.json" <<'EOF'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as file:
    report = json.load(file)
pairs = [[row["addr"], row["diff_addr"]] for row in report if row.get("diff_addr")]
with open(sys.argv[2], "w", encoding="utf-8") as file:
    json.dump(pairs, file)
EOF
}

# Ghidra analyses each build with its default analyzers, and then Auto
# Version Tracking pairs them.
run_ghidra() {
    local before="$1" after="$2" dir="$3"
    local headless="$GHIDRA_HOME/support/analyzeHeadless"
    mkdir -p "$dir/project"
    cp "$before" "$dir/before.bin"
    cp "$after" "$dir/after.bin"
    "$headless" "$dir/project" go -import "$dir/before.bin" "$dir/after.bin" \
        >"$dir/ghidra-import.log" 2>&1 \
        || { cat "$dir/ghidra-import.log" >&2; return 1; }
    "$headless" "$dir/project" go -process after.bin -noanalysis \
        -scriptPath "$here/rivals" \
        -postScript HereticusVersionTracking.java before.bin "$dir/report.json" default \
        >"$dir/ghidra-vt.log" 2>&1 \
        || { cat "$dir/ghidra-vt.log" >&2; return 1; }
    # The headless analyzer exits with zero when a script throws.
    [ -f "$dir/report.json" ] || { cat "$dir/ghidra-vt.log" >&2; return 1; }
    python3 - "$dir/report.json" "$dir/pairs.json" <<'EOF'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as file:
    report = json.load(file)
with open(sys.argv[2], "w", encoding="utf-8") as file:
    json.dump(report["pairs"], file)
EOF
}

# One build, timed, into its JSON file.
compare() {
    local build="$1"
    local dir="$work/$build"
    mkdir -p "$dir"
    local start end
    start="$(date +%s.%N)"
    "run_$tool" "$in/shfmt-$older-$build.bin" "$in/shfmt-$newer-$build.bin" "$dir"
    end="$(date +%s.%N)"
    python3 - "$dir/pairs.json" "$out/$build.json" "$start" "$end" <<'EOF'
import json
import sys

pairs_path, target, start, end = sys.argv[1:]
with open(pairs_path, encoding="utf-8") as file:
    pairs = json.load(file)
with open(target, "w", encoding="utf-8") as file:
    json.dump({"seconds": round(float(end) - float(start), 3), "pairs": sorted(pairs)}, file)
    file.write("\n")
EOF
    echo "rivals-go-pairs: $tool $build"
}

# Four builds at once. Each start of Ghidra saves the JDK it found in a file
# of its settings, and starts at once can each find that file half written,
# and stop to ask for the JDK. One save first leaves the file whole.
export GHIDRA_MAXMEM=8G
if [ "$tool" = ghidra ]; then
    java -cp "$GHIDRA_HOME/support/LaunchSupport.jar" LaunchSupport "$GHIDRA_HOME" \
        -jdk_home -save >/dev/null
fi
pids=()
failed=0
for bin in "$in"/shfmt-"$older"-*.bin; do
    build="$(basename "$bin" .bin)"
    build="${build#shfmt-$older-}"
    compare "$build" &
    pids+=("$!")
    if [ "${#pids[@]}" -eq 4 ]; then
        for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
        pids=()
    fi
done
for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
# A failed comparison printed its log. Without the stamp, the next run
# compares again.
[ "$failed" -eq 0 ] || exit 1
echo "$version" | head -n 1 >"$out/VERSION"
echo "$inputs_hash" >"$stamp"
