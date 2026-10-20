#!/usr/bin/env python3
"""List the version pairs of Assemblage-DeepHistory, to measure hereticus.

Assemblage-DeepHistory (https://arxiv.org/abs/2605.21615, CC0) builds 248
C and C++ projects at many versions. Each Linux file keeps its DWARF and
its symbols, so the symbols are the answer for the pairs, as for the
Ubuntu set. This reads its DuckDB, takes the files that GCC 13.3 built at
-O2 for x86-64, and pairs each with the next version of the same file.

A pair whose older file a CVE affects and whose newer file it does not
names the functions that the dataset maps the CVE to. These are the fix.

Setup, in ~/.cache/hereticus-assemblage (about 680 GB):

1. Download `deephistory.duckdb.tar.zst` from
   https://huggingface.co/datasets/changliu8541/assemblage-deephistory
   and unpack it.
2. `fixtures/assemblage.py --paths` writes `subset.paths`.
3. Stream the 201 GiB archive and keep only those files:
   curl -L .../binaries.tar.zst | zstd -dc | tar -x -T subset.paths
4. `fixtures/assemblage.py` writes `cases.json`, which
   `examples/research_bench.rs --assemblage` reads.

DuckDB comes from a venv: `uv venv .venv && uv pip install duckdb`, then
run this script with `.venv/bin/python`.
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import duckdb

CACHE = Path.home() / ".cache" / "hereticus-assemblage"

# A shared object keeps its version in its name, as `libpng16.so.16.43.0`;
# leave it out, so that two versions of the file have one name.
BASE_NAME = r"regexp_replace(file_name, '(\.so)(\.[0-9]+)+$', '\1')"

SUBSET = f"""
with l as (
    select *, {BASE_NAME} as base from binaries
    where platform = 'linux' and binary_format = 'ELF'
      and optimization = '-O2' and toolset_version = 'gcc-13.3.0'
),
g as (select package_name, base from l group by all having count(distinct version) >= 2)
select l.id, l.package_name, l.base, l.version, l.repo_last_update, l.hash, l.path
from l join g using (package_name, base)
order by l.package_name, l.base, l.id
"""

# The functions of each CVE that affects one file and not the next.
FIXES = """
select m.binary_id, l.cve_id, l.has_vulnerability, m.source_function
from cve_binary_labels l
join cve_function_mappings m using (cve_id, binary_id)
where l.binary_id in (select unnest(?))
"""


def release(version: str) -> tuple[int, ...]:
    """The numbers of a version, so that `v1.2.11`, `1.2.11` and `R_1_2_11`
    are one release and sort in order."""
    return tuple(int(number) for number in re.findall(r"\d+", version))


def consecutive(files: list[tuple]) -> list[tuple[tuple, tuple]]:
    """Each file with the next release of it. A second build of one
    release, or a file identical to the one before it, starts no pair."""
    pairs = []
    previous = None
    for file in sorted(files, key=lambda file: (release(file[3]), file[0])):
        if previous and release(file[3]) != release(previous[3]) and file[5] != previous[5]:
            pairs.append((previous, file))
        if not previous or release(file[3]) != release(previous[3]):
            previous = file
    return pairs


def main() -> None:
    con = duckdb.connect(str(CACHE / "deephistory.duckdb"), read_only=True)
    rows = con.execute(SUBSET).fetchall()
    if "--paths" in sys.argv[1:]:
        (CACHE / "subset.paths").write_text("".join(f"binaries/{row[6]}\n" for row in rows))
        print(f"{len(rows)} files in {CACHE / 'subset.paths'}", file=sys.stderr)
        return

    groups = defaultdict(list)
    for row in rows:
        if (CACHE / "binaries" / row[6]).is_file():
            groups[(row[1], row[2])].append(row)
    pairs = [pair for files in groups.values() for pair in consecutive(files)]

    ids = sorted({file[0] for pair in pairs for file in pair})
    affected = defaultdict(dict)  # binary -> CVE -> whether it is affected
    functions = defaultdict(set)  # (binary, CVE) -> functions
    for binary, cve, vulnerable, function in con.execute(FIXES, [ids]).fetchall():
        affected[binary][cve] = vulnerable
        if function:
            functions[(binary, cve)].add(function)

    cases = []
    for older, newer in pairs:
        fixed = [
            cve for cve, vulnerable in affected[older[0]].items()
            if vulnerable and affected[newer[0]].get(cve) is False
        ]
        fixes = set()
        for cve in fixed:
            fixes |= functions[(older[0], cve)] | functions[(newer[0], cve)]
        paths = [str(CACHE / "binaries" / file[6]) for file in (older, newer)]
        cases.append(
            {
                # The bench sums by library; a package holds many files.
                "library": older[1],
                "arch": "amd64",
                "before": f"{older[2]} {older[3]}",
                "after": newer[3],
                # Each file holds its own symbols, so it is its debug file too.
                "files": [[paths[0], paths[0]], [paths[1], paths[1]]],
                "fixes": sorted(fixes),
            }
        )
    (CACHE / "cases.json").write_text(json.dumps(cases, indent=1))
    with_fix = sum(1 for case in cases if case["fixes"])
    print(
        f"{len(cases)} pairs of {len(groups)} files, {with_fix} with a fix, "
        f"in {CACHE / 'cases.json'}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
