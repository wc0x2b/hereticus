#!/usr/bin/env python3
"""Fetch Ubuntu security updates of C libraries, to measure hereticus on them.

Each update is a real vendor backport: the same compiler and flags on both
sides, and a published fix in between. For each pair of consecutive
security releases of a library, this downloads:

* the library from both binary packages,
* the debug file of each from the `-dbgsym` package, whose symbols are the
  answer for which function is which,
* the patches the later release added, whose hunks name the functions the
  fix touched.

Everything lands in ~/.cache/hereticus-ubuntu-cve, with `cases.json` that
lists each pair. A second run reads the cache instead of the network.
`examples/research_bench.rs --ubuntu` reads `cases.json`.
"""

import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

CACHE = Path.home() / ".cache" / "hereticus-ubuntu-cve"
SERIES = "jammy"
API = "https://api.launchpad.net/devel"
FILES = "https://launchpad.net/ubuntu/+archive/primary/+files"

# (binary package, source package, shared object in the package)
LIBRARIES = [
    ("libexpat1", "expat", "libexpat.so.1"),
    ("zlib1g", "zlib", "libz.so.1"),
    ("libxml2", "libxml2", "libxml2.so.2"),
    ("libtiff5", "tiff", "libtiff.so.5"),
    ("libpng16-16", "libpng1.6", "libpng16.so.16"),
    ("libwebp7", "libwebp", "libwebp.so.7"),
    ("libarchive13", "libarchive", "libarchive.so.13"),
    ("libsqlite3-0", "sqlite3", "libsqlite3.so.0"),
    ("libcurl4", "curl", "libcurl.so.4"),
    ("liblzma5", "xz-utils", "liblzma.so.5"),
    ("libjpeg-turbo8", "libjpeg-turbo", "libjpeg.so.8"),
    ("libksba8", "libksba", "libksba.so.8"),
    ("libssh-4", "libssh", "libssh.so.4"),
    ("libgnutls30", "gnutls28", "libgnutls.so.30"),
    ("libldap-2.5-0", "openldap", "libldap.so.2"),
]
ARCHES = ["arm64", "armhf"]


def read_url(url: str) -> bytes:
    """The body at `url`. Launchpad answers 503 when it is asked too
    often, so a failure waits and tries again."""
    for attempt in range(6):
        try:
            with urllib.request.urlopen(url, timeout=120) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            if error.code not in (429, 500, 502, 503, 504) or attempt == 5:
                raise
        except urllib.error.URLError:
            if attempt == 5:
                raise
        time.sleep(10 * 2**attempt)
    raise AssertionError("unreachable")


def fetch(url: str, path: Path) -> Path:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(read_url(url))
    return path


def security_versions(binary: str, arch: str) -> list[str]:
    """Every version published to the security pocket, oldest first, after
    the release version."""
    url = (
        f"{API}/ubuntu/+archive/primary?ws.op=getPublishedBinaries"
        f"&binary_name={binary}&exact_match=true"
        f"&distro_arch_series={API}/ubuntu/{SERIES}/{arch}"
    )
    versions = []
    while url:
        page = json.loads(read_url(url))
        for entry in page["entries"]:
            if entry["pocket"] in ("Security", "Release"):
                versions.append(entry["binary_package_version"])
        url = page.get("next_collection_link")
    # The API lists newest first. Keep each version once.
    ordered = list(dict.fromkeys(reversed(versions)))
    return ordered


def deb_members(deb: Path) -> dict[str, bytes]:
    """The files of a .deb or .ddeb, by path."""
    with tempfile.TemporaryDirectory() as work:
        subprocess.run(["ar", "x", str(deb.resolve())], cwd=work, check=True)
        data = next(Path(work).glob("data.tar.*"))
        out = Path(work) / "out"
        out.mkdir()
        subprocess.run(["bsdtar", "-xf", str(data), "-C", str(out)], check=True)
        members = {}
        for path in out.rglob("*"):
            if path.is_file() and not path.is_symlink():
                members[str(path.relative_to(out))] = path.read_bytes()
        return members


def build_id(elf: bytes) -> str | None:
    """The GNU build ID of an ELF file, as hex."""
    with tempfile.NamedTemporaryFile() as file:
        file.write(elf)
        file.flush()
        result = subprocess.run(["readelf", "-n", file.name], capture_output=True, check=False)
    found = re.search(rb"Build ID: ([0-9a-f]+)", result.stdout)
    return found.group(1).decode() if found else None


def library(binary: str, version: str, arch: str, so: str) -> tuple[Path, Path] | None:
    """The shared object and its debug file, extracted into the cache."""
    stem = CACHE / binary / arch / version
    lib_path, debug_path = stem / so, stem / (so + ".debug")
    if lib_path.exists() and debug_path.exists():
        return lib_path, debug_path
    # A file name in the archive leaves out the epoch.
    quoted = version.split(":", 1)[-1]
    try:
        deb = fetch(f"{FILES}/{binary}_{quoted}_{arch}.deb", stem / "pkg.deb")
        ddeb = fetch(f"{FILES}/{binary}-dbgsym_{quoted}_{arch}.ddeb", stem / "pkg.ddeb")
    except Exception as error:  # noqa: BLE001 - any failure skips the version
        print(f"  skip {binary} {version} {arch}: {error}", file=sys.stderr)
        return None
    members = deb_members(deb)
    found = [data for path, data in members.items() if Path(path).name.startswith(so)]
    if not found:
        print(f"  skip {binary} {version} {arch}: no {so}", file=sys.stderr)
        return None
    elf = max(found, key=len)
    identity = build_id(elf)
    debug = [
        data
        for path, data in deb_members(ddeb).items()
        if identity and path.endswith(f"{identity[:2]}/{identity[2:]}.debug")
    ]
    if not debug:
        print(f"  skip {binary} {version} {arch}: no debug file", file=sys.stderr)
        return None
    lib_path.write_bytes(elf)
    debug_path.write_bytes(debug[0])
    return lib_path, debug_path


def patches(source: str, version: str) -> dict[str, str]:
    """The patches of a source version, by name."""
    plain = version.split(":", 1)[-1]
    path = CACHE / "src" / f"{source}_{plain}.debian.tar.xz"
    try:
        fetch(f"{FILES}/{source}_{plain}.debian.tar.xz", path)
    except Exception as error:  # noqa: BLE001
        print(f"  skip source {source} {version}: {error}", file=sys.stderr)
        return {}
    found = {}
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            if member.isfile() and "/patches/" in member.name and not member.name.endswith("series"):
                data = archive.extractfile(member)
                if data:
                    found[Path(member.name).name] = data.read().decode("utf-8", "replace")
    return found


HUNK = re.compile(r"^@@ [^@]* @@ ?(.*)$")
NAME = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
NOT_FUNCTIONS = {"if", "for", "while", "switch", "return", "sizeof", "defined"}


def touched_functions(patch: str) -> set[str]:
    """The functions the hunks of a C patch sit in, by their headers, and
    the functions a hunk starts, by its added lines."""
    names = set()
    current_file_is_c = False
    for line in patch.splitlines():
        if line.startswith("+++ "):
            current_file_is_c = bool(re.search(r"\.(c|h|cc|cpp)\b", line))
            continue
        if not current_file_is_c:
            continue
        hunk = HUNK.match(line)
        if hunk:
            found = NAME.findall(hunk.group(1))
            names.update(name for name in found[:1] if name not in NOT_FUNCTIONS)
    return names


def main() -> None:
    cases = []
    for binary, source, so in LIBRARIES:
        for arch in ARCHES:
            try:
                versions = security_versions(binary, arch)
            except Exception as error:  # noqa: BLE001
                print(f"skip {binary} {arch}: {error}", file=sys.stderr)
                continue
            print(f"{binary} {arch}: {len(versions)} versions", file=sys.stderr)
            for before, after in zip(versions, versions[1:]):
                old_patches, new_patches = patches(source, before), patches(source, after)
                added = {
                    name: text
                    for name, text in new_patches.items()
                    if old_patches.get(name) != text
                }
                fixes = set()
                for text in added.values():
                    fixes |= touched_functions(text)
                if not fixes:
                    continue
                pair = [library(binary, version, arch, so) for version in (before, after)]
                if None in pair:
                    continue
                cases.append(
                    {
                        "library": binary,
                        "arch": arch,
                        "before": before,
                        "after": after,
                        "files": [[str(path) for path in side] for side in pair],
                        "patches": sorted(added),
                        "fixes": sorted(fixes),
                    }
                )
                print(f"  {before} -> {after}: {sorted(fixes)[:6]}", file=sys.stderr)
    CACHE.mkdir(parents=True, exist_ok=True)
    (CACHE / "cases.json").write_text(json.dumps(cases, indent=1))
    print(f"{len(cases)} cases in {CACHE / 'cases.json'}", file=sys.stderr)


if __name__ == "__main__":
    main()
