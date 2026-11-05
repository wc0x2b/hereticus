#!/usr/bin/env bash
# Give the stripped backport pairs to another diff tool, and write what it
# reports. Run by `just rivals` and `just rivals-ghidra`, in the image of
# fixtures/rivals/Dockerfile.
#
# Usage: rivals.sh radare2|ghidra [default|deeper|unnamed|crossed]
#
# The setup says how the tool runs, and on what:
#
#   default  its default analysis, on lib-stripped.so
#   deeper   its deepest analysis: `radiff2 -AA`, or Ghidra with the
#            correlators that Auto Version Tracking leaves out
#   unnamed  its default analysis, on a copy of lib-stripped.so with no
#            symbol that the library defines, as rivals/unname.py writes
#   crossed  its default analysis, on the builds of rivals/crossed-builds.txt,
#            whose two sides are built by other compilers or at other levels
#
# For each build of fixtures/rivals/builds.txt this writes
# build/rivals/<tool>[-<setup>]/<project>-<arch>-<level>.json, which holds the
# rows the tool reports, the lowest score first:
#
#   {"seconds": 0.14, "rows": [{"before": 1234, "after": 1250, "score": 0.82}, ...]}
#
# "seconds" is the wall time of the tool on the pair, from the start of the
# analysis to the report.
# A row with no "after" is a function that is gone, and a row with no
# "before" is a new function. An address is where the file links the
# function. hereticus-cli/tests/rivals/mod.rs reads these files, and the
# unnamed copies in build/rivals/unnamed/<project>-<arch>-<level>/.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tool="${1:?usage: rivals.sh radare2|ghidra [default|deeper|unnamed|crossed]}"
setup="${2:-default}"
backports="$here/build/backports"
unnamed="$here/build/rivals/unnamed"
builds="$here/rivals/builds.txt"
[ "$setup" = crossed ] && builds="$here/rivals/crossed-builds.txt"
case "$setup" in
    default) out="$here/build/rivals/$tool" ;;
    deeper | unnamed | crossed) out="$here/build/rivals/$tool-$setup" ;;
    *) echo "rivals: unknown setup $setup" >&2; exit 2 ;;
esac

# Each build of builds.txt, one a line: its name, its project and arch, and
# the level of each side. A line with no fourth field builds both sides at
# one level.
each_build() {
    grep -v '^#' "$builds" | while read -r project arch level after; do
        [ -n "$project" ] || continue
        if [ -n "$after" ]; then
            echo "$project-$arch-$level-to-$after $project $arch $level $after"
        else
            echo "$project-$arch-$level $project $arch $level $level"
        fi
    done
}

# The stripped library of one side of a build.
stripped() {
    local project="$1" arch="$2" before="$3" after="$4" variant="$5"
    local level="$before"
    [ "$variant" = after ] && level="$after"
    echo "$backports/$project-$variant/$arch-$level/lib-stripped.so"
}

# The library of one side of a build, as the setup gives it to the tool.
library() {
    local name="$1" variant="$6"
    case "$setup" in
        unnamed) echo "$unnamed/$name/$variant.so" ;;
        *) stripped "${@:2}" ;;
    esac
}

# The unnamed copies take less than a second, so each run writes them again.
# A move puts each one in place whole, as another run can read it.
each_build | while read -r name project arch before after; do
    mkdir -p "$unnamed/$name"
    for variant in before after; do
        copy="$unnamed/$name/$variant.so"
        python3 "$here/rivals/unname.py" \
            "$(stripped "$project" "$arch" "$before" "$after" "$variant")" "$copy.$$"
        mv "$copy.$$" "$copy"
    done
done

case "$tool" in
    radare2) version="$(radiff2 -v | head -n 1)" ;;
    ghidra) version="$(cat "$GHIDRA_HOME/Ghidra/application.properties")" ;;
    *) echo "rivals: unknown tool $tool" >&2; exit 2 ;;
esac

# What decides the output: this script and what it reads, the tool, and the
# binaries. Ghidra takes about ten minutes over every build, so a second run with
# the same inputs keeps what the first wrote.
inputs_hash="$(
    {
        cat "$here/rivals.sh" "$builds" "$here/rivals/Dockerfile" \
            "$here/rivals/HereticusVersionTracking.java" "$here/rivals/rows.py"
        echo "$version $setup"
        each_build | while read -r name project arch before after; do
            for variant in before after; do
                cat "$(library "$name" "$project" "$arch" "$before" "$after" "$variant")"
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

# radiff2 with the analysis of `aaa`, as its manual shows for a code diff, or
# with the analysis of `aaaa` for the deeper setup.
run_radare2() {
    local before="$1" after="$2" report="$3"
    local analysis=-A
    [ "$setup" = deeper ] && analysis=-AA
    radiff2 "$analysis" -C -j "$before" "$after" 2>/dev/null >"$report"
}

# Ghidra analyses each program with its default analyzers, and then Auto
# Version Tracking pairs them. The deeper setup then runs more correlators.
run_ghidra() {
    local before="$1" after="$2" report="$3"
    local project="$work/ghidra"
    local correlators=default
    [ "$setup" = deeper ] && correlators=deeper
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
        -postScript HereticusVersionTracking.java before.so "$report" "$correlators" \
        >"$work/ghidra-vt.log" 2>&1 \
        || { cat "$work/ghidra-vt.log" >&2; return 1; }
    # The headless analyzer exits with zero when a script throws.
    [ -f "$report" ] || { cat "$work/ghidra-vt.log" >&2; return 1; }
}

each_build | while read -r name project arch before after; do
    echo "rivals: $tool $setup $name"
    rm -f "$work/report.json"
    start="$(date +%s.%N)"
    "run_$tool" \
        "$(library "$name" "$project" "$arch" "$before" "$after" before)" \
        "$(library "$name" "$project" "$arch" "$before" "$after" after)" \
        "$work/report.json"
    end="$(date +%s.%N)"
    python3 "$here/rivals/rows.py" "$tool" "$work/report.json" "$out/$name.json" \
        "$(python3 -c "print(round($end - $start, 3))")"
done
echo "$version" | head -n 1 >"$out/VERSION"
echo "$inputs_hash" >"$stamp"
