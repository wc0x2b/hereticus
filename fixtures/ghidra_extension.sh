#!/usr/bin/env bash
# Build the Ghidra extension of ghidra/, install it in headless Ghidra, and
# write what it does. Run by `just ghidra-extension`, in the
# `ghidra-extension` stage of fixtures/rivals/Dockerfile.
#
# The Gradle build runs the unit tests of the extension first. Then, in
# build/ghidra-extension/:
#
#   starts/<name>-off.txt, starts/<name>-on.txt
#       the linked address of each function Ghidra finds in one binary, one
#       hexadecimal address a line, without and with the Hereticus Function
#       Finder. A raw stub is linked where it loads.
#   matches/<name>.json
#       the matches the Hereticus Function Match correlator proposes for one
#       backport pair.
#
# hereticus-cli/tests/ghidra_extension.rs reads these files.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$here")"
hereticus="$root/target/x86_64-unknown-linux-musl/release/hereticus"
backports="$here/build/backports"
stub="$here/build/openwrt/arm-ex6100v2-stub-22.03.2.bin"
out="$here/build/ghidra-extension"
# The stripped backports the finder runs on: project, arch and level.
finds=(
    "zlib arm O2"
    "zlib thumb O2"
    "zlib aarch64 O2"
    "zlib mips O2"
)
# The backport pairs the correlator runs on.
pairs=(
    "zlib arm O2"
    "zlib mips O2"
)

[ -x "$hereticus" ] || { echo "ghidra-extension: run \`just build\` first" >&2; exit 1; }

# What decides the output: this script, the extension, the scripts it runs,
# Ghidra, hereticus, and the binaries.
inputs_hash="$(
    {
        cat "$here/ghidra_extension.sh" "$here/rivals/Dockerfile" "$hereticus" "$stub"
        find "$root/ghidra" -path "$root/ghidra/build" -prune -o -path "$root/ghidra/dist" -prune \
            -o -path "$root/ghidra/.gradle" -prune -o -type f -print | sort | xargs cat
        cat "$here"/ghidra-extension/*.java
        cat "$GHIDRA_HOME/Ghidra/application.properties"
        for entry in "${finds[@]}" "${pairs[@]}"; do
            read -r project arch level <<<"$entry"
            for variant in before after; do
                cat "$backports/$project-$variant/$arch-$level/lib-stripped.so"
            done
        done
    } | sha256sum | cut -d' ' -f1
)"
stamp="$out/.inputs"
if [ -z "${RIVALS_FORCE:-}" ] && [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$inputs_hash" ]; then
    echo "ghidra-extension: up to date in $out"
    exit 0
fi
rm -rf "$out"
mkdir -p "$out/starts" "$out/matches" "$out/logs"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Gradle keeps what it downloads, JUnit, under build/, so a second run needs
# no network.
export GRADLE_USER_HOME="$here/build/gradle"
(cd "$root/ghidra" && gradle --quiet --no-daemon clean buildExtension)

# Headless Ghidra loads the extensions of the user settings directory, as an
# install from the Ghidra window puts them there.
version="$(sed -n 's/^application.version=//p' "$GHIDRA_HOME/Ghidra/application.properties")"
release="$(sed -n 's/^application.release.name=//p' "$GHIDRA_HOME/Ghidra/application.properties")"
extensions="$HOME/.config/ghidra/ghidra_${version}_${release}/Extensions"
rm -rf "$extensions/Hereticus"
mkdir -p "$extensions"
unzip -q "$root"/ghidra/dist/*_Hereticus.zip -d "$extensions"

headless="$GHIDRA_HOME/support/analyzeHeadless"

# Import one binary, analyse it with the finder on or off, and write the
# start of each function it finds. The rest of the arguments go to the
# importer, as a loader and a processor for a raw image.
find_starts() {
    local name="$1" binary="$2" setting="$3"
    shift 3
    local project="$work/find-$name-$setting"
    mkdir -p "$project"
    cp "$binary" "$project/$name"
    "$headless" "$project" find -import "$project/$name" "$@" \
        -scriptPath "$here/ghidra-extension" \
        -preScript HereticusSetup.java "$hereticus" "$setting" \
        -postScript HereticusExtensionStarts.java "$out/starts/$name-$setting.txt" \
        >"$out/logs/find-$name-$setting.log" 2>&1 \
        || { cat "$out/logs/find-$name-$setting.log" >&2; return 1; }
    # The headless analyzer exits with zero when a script throws.
    [ -s "$out/starts/$name-$setting.txt" ] \
        || { cat "$out/logs/find-$name-$setting.log" >&2; return 1; }
    echo "ghidra-extension: $name finder $setting"
}

# Import both sides of one pair, analyse each with the finder, and write the
# matches the correlator proposes.
correlate() {
    local name="$1" before="$2" after="$3"
    local project="$work/pair-$name"
    mkdir -p "$project"
    cp "$before" "$project/before.so"
    cp "$after" "$project/after.so"
    "$headless" "$project" pair -import "$project/before.so" "$project/after.so" \
        -scriptPath "$here/ghidra-extension" \
        -preScript HereticusSetup.java "$hereticus" on \
        >"$out/logs/pair-$name-import.log" 2>&1 \
        || { cat "$out/logs/pair-$name-import.log" >&2; return 1; }
    "$headless" "$project" pair -process after.so -noanalysis \
        -scriptPath "$here/ghidra-extension" \
        -postScript HereticusCorrelate.java before.so "$hereticus" "$out/matches/$name.json" \
        >"$out/logs/pair-$name.log" 2>&1 \
        || { cat "$out/logs/pair-$name.log" >&2; return 1; }
    [ -s "$out/matches/$name.json" ] || { cat "$out/logs/pair-$name.log" >&2; return 1; }
    echo "ghidra-extension: $name correlator"
}

jobs=()
for entry in "${finds[@]}"; do
    read -r project arch level <<<"$entry"
    binary="$backports/$project-after/$arch-$level/lib-stripped.so"
    for setting in off on; do
        find_starts "$project-$arch-$level" "$binary" "$setting" &
        jobs+=($!)
    done
done
# The stub of the Netgear EX6100v2 loads at 0x80208000, as
# hereticus-cli/tests/cli_openwrt.rs says.
for setting in off on; do
    find_starts arm-stub "$stub" "$setting" -loader BinaryLoader \
        -loader-baseAddr 0x80208000 -processor ARM:LE:32:v7 &
    jobs+=($!)
done
for entry in "${pairs[@]}"; do
    read -r project arch level <<<"$entry"
    correlate "$project-$arch-$level" \
        "$backports/$project-before/$arch-$level/lib-stripped.so" \
        "$backports/$project-after/$arch-$level/lib-stripped.so" &
    jobs+=($!)
done
for job in "${jobs[@]}"; do
    wait "$job"
done
echo "$inputs_hash" >"$stamp"
