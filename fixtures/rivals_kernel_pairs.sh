#!/usr/bin/env bash
# Give the raw OpenWrt kernels of two releases to another diff tool, and
# write every pair of functions it makes. Run by `just rivals-kernel-pairs`,
# in the image of fixtures/rivals/Dockerfile.
#
# Usage: rivals_kernel_pairs.sh radare2|ghidra [OLDER NEWER]
#
# For each board of BOARDS below that has a kernel of both releases, the tool
# compares the kernel of OLDER with the kernel of NEWER, 22.03.2 and 22.03.5
# by default. This writes build/rivals/<tool>-kernels/<board>.json for the
# default releases, and else
# build/rivals/<tool>-kernels-<older>-<newer>/<board>.json:
#
#   {"seconds": 812.4, "pairs": [[2147483648, 2147483648], ...]}
#
# Each pair is the start of a function of the earlier kernel and of the one
# the tool pairs it with in the later kernel, where the kernel is linked.
# hereticus/tests/truth_kernel_rivals.rs checks the pairs against the
# symbols of each build.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tool="${1:?usage: rivals_kernel_pairs.sh radare2|ghidra [OLDER NEWER]}"
older="${2:-22.03.2}"
newer="${3:-22.03.5}"
firmware="$here/build/openwrt"
out="$here/build/rivals/$tool-kernels"
[ "$older/$newer" = 22.03.2/22.03.5 ] || out="$out-$older-$newer"

# The boards of hereticus/tests/truth_kernels.rs: the name its files carry,
# the architecture, and where its kernel is linked.
ALL_BOARDS="
arm-ex6100v2 arm 0xc0208000
mipsbe-eap245v3 mipsbe 0x80060000
mipsel-r6220 mips 0x80001000
arm-a385dbap arm 0xc0008000
mipsbe-vr200 mipsbe 0x80002000
mipsel-mt300nv2 mips 0x80000000
"
# The boards with a kernel of both releases.
BOARDS="$(echo "$ALL_BOARDS" | while read -r board arch base; do
    [ -n "$board" ] || continue
    [ -f "$firmware/$board-kernel-$older.bin" ] && [ -f "$firmware/$board-kernel-$newer.bin" ] \
        && echo "$board $arch $base"
done)"

case "$tool" in
    radare2) version="$(radiff2 -v | head -n 1)" ;;
    ghidra) version="$(cat "$GHIDRA_HOME/Ghidra/application.properties")" ;;
    *) echo "rivals-kernel-pairs: unknown tool $tool" >&2; exit 2 ;;
esac

# Ghidra takes about an hour over every board, so a second run with the same
# inputs keeps what the first wrote.
inputs_hash="$(
    {
        cat "$here/rivals_kernel_pairs.sh" "$here/rivals/Dockerfile" \
            "$here/rivals/HereticusVersionTracking.java" "$here/rivals/wrap.py"
        echo "$version"
        echo "$BOARDS" | while read -r board _ _; do
            [ -n "$board" ] || continue
            cat "$firmware/$board-kernel-$older.bin" "$firmware/$board-kernel-$newer.bin"
        done
    } | sha256sum | cut -d' ' -f1
)"
stamp="$out/.inputs"
if [ -z "${RIVALS_FORCE:-}" ] && [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$inputs_hash" ]; then
    echo "rivals-kernel-pairs: $tool up to date in $out"
    exit 0
fi
rm -rf "$out"
mkdir -p "$out"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# radiff2 with the analysis of `aaa`, as for the backports, and with
# `anal.hasnext`, which reads on past the end of each function for the next.
# Without it, `-A` and `-AA` read a kernel as one function, and radiff2 shows
# two rows. It reads a raw image at zero, so each kernel goes to it in an ELF
# file that loads it at its base.
run_radare2() {
    local board="$1" arch="$2" base="$3" dir="$4"
    for release in "$older" "$newer"; do
        python3 "$here/rivals/wrap.py" "$firmware/$board-kernel-$release.bin" \
            "$dir/$release.elf" "$arch" "$base"
    done
    radiff2 -A -e anal.hasnext=true -C -j "$dir/$older.elf" "$dir/$newer.elf" 2>"$dir/radiff2.log" >"$dir/report.json" \
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

# Ghidra analyses each raw kernel with its default analyzers, as
# fixtures/rivals_kernel.sh does, and then Auto Version Tracking pairs them.
run_ghidra() {
    local board="$1" arch="$2" base="$3" dir="$4"
    local processor
    case "$arch" in
        arm) processor=ARM:LE:32:v7 ;;
        mips) processor=MIPS:LE:32:default ;;
        mipsbe) processor=MIPS:BE:32:default ;;
    esac
    local headless="$GHIDRA_HOME/support/analyzeHeadless"
    mkdir -p "$dir/project"
    cp "$firmware/$board-kernel-$older.bin" "$dir/before.bin"
    cp "$firmware/$board-kernel-$newer.bin" "$dir/after.bin"
    "$headless" "$dir/project" kernels -import "$dir/before.bin" "$dir/after.bin" \
        -loader BinaryLoader -loader-baseAddr "$base" -processor "$processor" \
        >"$dir/ghidra-import.log" 2>&1 \
        || { cat "$dir/ghidra-import.log" >&2; return 1; }
    "$headless" "$dir/project" kernels -process after.bin -noanalysis \
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

# One board, timed, into its JSON file.
compare() {
    local board="$1" arch="$2" base="$3"
    local dir="$work/$board"
    mkdir -p "$dir"
    local start end
    start="$(date +%s.%N)"
    "run_$tool" "$board" "$arch" "$base" "$dir"
    end="$(date +%s.%N)"
    python3 - "$dir/pairs.json" "$out/$board.json" "$start" "$end" <<'EOF'
import json
import sys

pairs_path, target, start, end = sys.argv[1:]
with open(pairs_path, encoding="utf-8") as file:
    pairs = json.load(file)
with open(target, "w", encoding="utf-8") as file:
    json.dump({"seconds": round(float(end) - float(start), 3), "pairs": sorted(pairs)}, file)
    file.write("\n")
EOF
    echo "rivals-kernel-pairs: $tool $board"
}

# Three boards at once. A kernel needs more than the default heap of 2 GB.
export GHIDRA_MAXMEM=16G
# Each start of Ghidra saves the JDK it found in a file of its settings,
# and starts at once can each find that file half written, and stop to ask
# for the JDK. One save first leaves the file whole.
if [ "$tool" = ghidra ]; then
    java -cp "$GHIDRA_HOME/support/LaunchSupport.jar" LaunchSupport "$GHIDRA_HOME" \
        -jdk_home -save >/dev/null
fi
pids=()
failed=0
while read -r board arch base; do
    [ -n "$board" ] || continue
    compare "$board" "$arch" "$base" &
    pids+=("$!")
    if [ "${#pids[@]}" -eq 3 ]; then
        for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
        pids=()
    fi
done <<<"$BOARDS"
for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
# A failed comparison printed its log. Without the stamp, the next run
# compares again.
[ "$failed" -eq 0 ] || exit 1
echo "$version" | head -n 1 >"$out/VERSION"
echo "$inputs_hash" >"$stamp"
