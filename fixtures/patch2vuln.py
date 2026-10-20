#!/usr/bin/env python3
"""Run hereticus on the Ubuntu security updates of Patch2Vuln.

Patch2Vuln (https://arxiv.org/abs/2605.06601) diffs 20 Ubuntu security
updates with ghidriff, and reports for each whether the function of the
fix reached its agent. This fetches the same amd64 packages and their
`-dbgsym` debug files, runs hereticus on the stripped binaries as shipped,
and prints the row of the report where the first function of the fix
sits.

Each pair spans many updates, and Patch2Vuln counts a case as found when
its agent finds any function a security fix touched. Here, likewise, the
functions of the fix are those the paper names, and those the hunks of
every CVE patch the later version added sit in. The debug file names each
address of the report. Where the archive no longer holds the `-dbgsym`
package, the dynamic symbols name only the exported functions.

Downloads land in ~/.cache/hereticus-ubuntu-cve, beside those of
`ubuntu_cves.py`.
"""

import json
import subprocess
import sys
from pathlib import Path

from ubuntu_cves import CACHE, FILES, build_id, deb_members, fetch, patches, touched_functions

ROOT = Path(__file__).resolve().parent.parent
HERETICUS = ROOT / "target" / "x86_64-unknown-linux-musl" / "release" / "hereticus"
ARCH = "amd64"

# (binary package, source package, file in the package, before, after,
#  CVEs, functions the paper names, whether the paper's agent found the fix)
CASES = [
    ("tcpdump", "tcpdump", "tcpdump", "4.9.2-3", "4.9.3-0ubuntu0.18.04.2",
     ["CVE-2018-16301", "CVE-2020-8037"], ["read_infile", "ppp_hdlc"], True),
    ("tcpdump", "tcpdump", "tcpdump", "4.7.4-1ubuntu1", "4.9.3-0ubuntu0.16.04.1",
     ["CVE-2018-14464", "CVE-2018-19519"], ["ldp_tlv_print", "icmp_print"], False),
    ("libexpat1", "expat", "libexpat.so.1", "2.2.5-3", "2.2.5-3ubuntu0.9",
     ["CVE-2022-43680", "CVE-2022-25235"], ["XML_GetBuffer", "copyString"], True),
    ("libarchive13", "libarchive", "libarchive.so.13", "3.2.2-3.1", "3.2.2-3.1ubuntu0.7",
     ["CVE-2021-31566", "CVE-2022-36227"], [], True),
    ("libxml2", "libxml2", "libxml2.so.2", "2.9.4+dfsg1-6.1ubuntu1", "2.9.4+dfsg1-6.1ubuntu1.9",
     ["CVE-2023-28484", "CVE-2023-29469"], [], True),
    ("libxml2", "libxml2", "libxml2.so.2", "2.9.10+dfsg-5", "2.9.10+dfsg-5ubuntu0.20.04.10",
     ["CVE-2025-32414", "CVE-2025-32415"], ["xmlSchemaIDCFillNodeTables"], True),
    ("libtiff5", "tiff", "libtiff.so.5", "4.0.9-5", "4.0.9-5ubuntu0.10",
     ["CVE-2023-0795", "CVE-2023-0796"], [], True),
    ("libtiff5", "tiff", "libtiff.so.5", "4.1.0+git191117-2build1",
     "4.1.0+git191117-2ubuntu0.20.04.14", ["CVE-2024-7006"], [], True),
    ("libssl1.1", "openssl", "libcrypto.so.1.1", "1.1.1f-1ubuntu2", "1.1.1f-1ubuntu2.24",
     ["CVE-2023-2650", "CVE-2023-0464"], [], False),
    ("libmagic1", "file", "libmagic.so.1", "1:5.32-2", "1:5.32-2ubuntu0.4",
     ["CVE-2019-8904", "CVE-2019-8905"], [], False),
    ("libcurl4", "curl", "libcurl.so.4", "7.58.0-2ubuntu3", "7.58.0-2ubuntu3.24",
     ["CVE-2023-27533", "CVE-2023-27538"], [], False),
    ("zlib1g", "zlib", "libz.so.1", "1:1.2.11.dfsg-0ubuntu2", "1:1.2.11.dfsg-0ubuntu2.2",
     ["CVE-2022-37434"], ["inflate"], False),
    ("libfreetype6", "freetype", "libfreetype.so.6", "2.8.1-2ubuntu2", "2.8.1-2ubuntu2.2",
     ["CVE-2022-27404", "CVE-2022-27406"],
     ["sfnt_init_face", "woff2_open_font", "FT_Request_Size"], False),
    ("libsndfile1", "libsndfile", "libsndfile.so.1", "1.0.28-4", "1.0.28-4ubuntu0.18.04.2",
     ["CVE-2021-3246"], ["wavlike_msadpcm_init"], True),
    ("libjpeg-turbo8", "libjpeg-turbo", "libjpeg.so.8", "1.5.2-0ubuntu5",
     "1.5.2-0ubuntu5.18.04.6", ["CVE-2020-17541", "CVE-2021-46822"], [], True),
    ("libwebp6", "libwebp", "libwebp.so.6", "0.6.1-2", "0.6.1-2ubuntu0.18.04.2",
     ["CVE-2023-1999"], ["EncodeAlphaInternal"], False),
    ("libsqlite3-0", "sqlite3", "libsqlite3.so.0", "3.22.0-1", "3.22.0-1ubuntu0.7",
     ["CVE-2022-35737"], ["sqlite3_str_vappendf"], True),
    ("libopenjp2-7", "openjpeg2", "libopenjp2.so", "2.3.1-1ubuntu4", "2.3.1-1ubuntu4.20.04.4",
     ["CVE-2024-56826", "CVE-2024-56827"], ["opj_j2k_add_tlmarker"], False),
    ("libpoppler73", "poppler", "libpoppler.so.73", "0.62.0-2ubuntu2", "0.62.0-2ubuntu2.14",
     ["CVE-2022-38784", "CVE-2022-38785"], [], False),
    ("libgnutls30", "gnutls28", "libgnutls.so.30", "3.5.18-1ubuntu1", "3.5.18-1ubuntu1.6",
     ["CVE-2021-4209", "CVE-2022-2509"], [], False),
]


def fix_functions(
    source: str, before: str, after: str, cves: list[str], named: list[str]
) -> tuple[set[str], set[str]]:
    """The functions every CVE patch the later version added touches, and
    the functions of the CVEs the paper names alone. Both hold the
    functions the paper names."""
    every, own = set(named), set(named)
    earlier = patches(source, before)
    for name, text in patches(source, after).items():
        if name in earlier:
            continue
        head = (name + text[:2000]).lower()
        if "cve" in head:
            every |= touched_functions(text)
        if any(cve.lower() in head for cve in cves):
            own |= touched_functions(text)
    return every, own


def package(binary: str, version: str, so: str) -> tuple[Path, Path | None] | None:
    """The file of a package, and its debug file where the archive still
    holds one."""
    stem = CACHE / binary / ARCH / version
    path = stem / so
    debug = stem / (so + ".debug")
    if path.exists():
        return path, debug if debug.exists() else None
    quoted = version.split(":", 1)[-1]
    try:
        deb = fetch(f"{FILES}/{binary}_{quoted}_{ARCH}.deb", stem / "pkg.deb")
    except Exception as error:  # noqa: BLE001 - any failure skips the case
        print(f"  skip {binary} {version}: {error}", file=sys.stderr)
        return None
    found = [data for name, data in deb_members(deb).items() if Path(name).name.startswith(so)]
    if not found:
        print(f"  skip {binary} {version}: no {so}", file=sys.stderr)
        return None
    elf = max(found, key=len)
    path.write_bytes(elf)
    try:
        ddeb = fetch(f"{FILES}/{binary}-dbgsym_{quoted}_{ARCH}.ddeb", stem / "pkg.ddeb")
    except Exception:  # noqa: BLE001 - the dynamic symbols stand in
        return path, None
    identity = build_id(elf)
    for name, data in deb_members(ddeb).items():
        if identity and name.endswith(f"{identity[:2]}/{identity[2:]}.debug"):
            debug.write_bytes(data)
            return path, debug
    return path, None


def plain(symbol: str) -> str:
    """A demangled symbol without its version, clone suffix, class and
    parameters, as a C function or a patch hunk names it."""
    return symbol.split("(")[0].split("::")[-1].split("@")[0].split(".")[0]


def symbols(path: Path, debug: Path | None) -> dict[int, str]:
    """The function symbols of the debug file, or else the dynamic symbols
    of the file, by address."""
    source = ["--defined-only", str(debug)] if debug else ["-D", "--defined-only", str(path)]
    result = subprocess.run(["nm", "-C", *source], capture_output=True, text=True, check=True)
    names = {}
    for line in result.stdout.splitlines():
        address, kind, *rest = line.split(maxsplit=2) + [""]
        if kind in ("t", "T", "w", "W") and rest[0]:
            names.setdefault(int(address, 16), plain(rest[0]))
    return names


def row_names(row: dict, before: dict[int, str], after: dict[int, str]) -> set[str]:
    """The names of the functions a row of the JSON report covers."""
    names = set()
    for side, table in (("before", before), ("after", after)):
        entry = row.get(side) or {}
        if entry.get("address") in table:
            names.add(table[entry["address"]])
        if entry.get("name"):
            names.add(plain(entry["name"]))
    return names


def row_of(diff: dict, fixes: set[str], before: dict[int, str], after: dict[int, str]) -> str:
    """The row of the report where the first function of `fixes` sits."""
    if not fixes:
        return "not in the file"
    for index, row in enumerate(diff["pairs"], 1):
        if row_names(row, before, after) & fixes:
            return str(index)
    unmatched = [{"before": row["function"]} for row in diff["gone"]]
    unmatched += [{"after": row["function"]} for row in diff["new"]]
    if any(row_names(row, before, after) & fixes for row in unmatched):
        return "gone or new"
    return "absent"


def main() -> None:
    subprocess.run(["just", "build"], cwd=ROOT, check=True, capture_output=True)
    print("| Update | Symbols | Rows | Any CVE fix | The paper's CVEs | Patch2Vuln |")
    print("|---|---|---|---|---|---|")
    for binary, source, so, before, after, cves, named, agent in CASES:
        label = f"{source} {before} → {after}"
        verdict = "found" if agent else "missed"
        old = package(binary, before, so)
        new = package(binary, after, so)
        if old is None or new is None:
            print(f"| {label} | | | not fetched | | {verdict} |")
            continue
        before_names, after_names = symbols(*old), symbols(*new)
        known = {*before_names.values(), *after_names.values()}
        every, own = fix_functions(source, before, after, cves, named)
        report = subprocess.run(
            [str(HERETICUS), "--format", "json", str(old[0]), str(new[0])],
            capture_output=True, text=True, check=True,
        )
        diff = json.loads(report.stdout)
        print(
            f"| {label} | {'debug' if old[1] and new[1] else 'dynamic'} "
            f"| {len(diff['pairs'])} "
            f"| {row_of(diff, every & known, before_names, after_names)} "
            f"| {row_of(diff, own & known, before_names, after_names)} | {verdict} |",
            flush=True,
        )


if __name__ == "__main__":
    sys.exit(main())
