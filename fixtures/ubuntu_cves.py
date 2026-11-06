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

The pairs are pinned in `ubuntu_cases.json` beside this script: each
version, the functions its patches touched, and the SHA-256 of each file,
because `tests/truth_ubuntu.rs` locks the counts they give. A plain run
fetches exactly those and stops at a changed file. `--refresh` asks
Launchpad for the security releases published since, and pins them anew.
`--refix` reads the functions that the patches of the pinned cases touch
again, as `touched_functions` reads them now.
"""

import bisect
import hashlib
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
PINNED = Path(__file__).resolve().parent / "ubuntu_cases.json"
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
# A macro that defines a function takes its name alone, as
# `SSH_PACKET_CALLBACK(ssh_packet_kexinit)` of libssh and
# `DECLAREwriteFunc(putContig8bitTile)` of libtiff do. Its own name begins
# with two capitals.
DEFINING_MACRO = re.compile(r"^(?:static\s+)?([A-Z]{2}[A-Za-z0-9_]*)\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)")
# zlib declares a prototype as `local void compress_block OF((...))`, with
# the name of the function before `OF`.
OLD_PROTOTYPE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s+OF\s*\(\(")
TYPES = {"void", "int", "char", "long", "short", "unsigned", "signed", "float", "double"}


def header_function(header: str) -> str | None:
    """The function that a hunk header names, or None.

    >>> header_function("static SSH_PACKET_CALLBACK(ssh_packet_client_dh_init){")
    'ssh_packet_client_dh_init'
    >>> header_function("local void compress_block OF((deflate_state *s,")
    'compress_block'
    >>> header_function("static int deflate_stored(deflate_state *s, int flush)")
    'deflate_stored'
    >>> header_function("int xmlFoo(void)")
    'xmlFoo'
    >>> header_function("if (x)") is None
    True
    """
    defined = DEFINING_MACRO.match(header.strip())
    if defined and defined.group(2) not in TYPES:
        return defined.group(2)
    prototype = OLD_PROTOTYPE.search(header)
    if prototype:
        return prototype.group(1)
    found = [name for name in NAME.findall(header)[:1] if name not in NOT_FUNCTIONS]
    return found[0] if found else None


# The header of a hunk in a type names no function, as `struct X {` does.
TYPE_HEADER = re.compile(r"^\s*(typedef|struct|union|enum)\b")
# The start lines of a hunk: `@@ -866,6 +866,21 @@`.
HUNK_LINES = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")

FunctionStarts = dict[str, list[tuple[int, str]]]


def function_starts(debug: Path) -> FunctionStarts:
    """The first line of each function of a debug file, by its source file,
    from the `DW_TAG_subprogram` entries that name their file and line."""
    out = subprocess.run(
        ["llvm-dwarfdump", "--debug-info", str(debug)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    starts: dict[str, set[tuple[int, str]]] = {}
    tag, attributes = None, {}

    def flush() -> None:
        if tag == "DW_TAG_subprogram" and {"name", "file", "line"} <= attributes.keys():
            if attributes["line"] > 0:
                # libxml2 calls a function by an alias of its own, and GCC
                # names a part or a copy by a suffix after a dot: the source
                # names the function without either.
                name = attributes["name"].split(".")[0].removesuffix("__internal_alias")
                starts.setdefault(attributes["file"], set()).add((attributes["line"], name))

    for line in out.splitlines():
        entry = re.match(r"0x[0-9a-f]+:\s+(DW_TAG_\w+)", line)
        if entry:
            flush()
            tag, attributes = entry.group(1), {}
            continue
        attribute = re.search(r"DW_AT_(name|decl_file|decl_line)\s+\((.*)\)\s*$", line)
        if attribute:
            key, value = attribute.groups()
            value = value.strip('"')
            if key == "decl_line":
                attributes["line"] = int(value)
            else:
                attributes["name" if key == "name" else "file"] = value
    flush()
    return {file: sorted(lines) for file, lines in starts.items()}


def function_at(starts: FunctionStarts, path: str, line: int) -> str | None:
    """The function whose first line is the last at or before `line` in the
    source file whose path ends with `path`.

    >>> starts = {"/build/x/lib/a.c": [(10, "f"), (40, "g")], "./lib/a.c": [(70, "h")]}
    >>> function_at(starts, "lib/a.c", 45)
    'g'
    >>> function_at(starts, "lib/a.c", 70)
    'h'
    >>> function_at(starts, "lib/a.c", 5) is None
    True
    >>> function_at(starts, "lib/b.c", 45) is None
    True
    """
    lines = sorted(
        {
            entry
            for file, entries in starts.items()
            if file == path or file.endswith("/" + path)
            for entry in entries
        }
    )
    at = bisect.bisect_right([first for first, _ in lines], line) - 1
    return lines[at][1] if at >= 0 else None


def touched_functions(
    patch: str, starts: tuple[FunctionStarts, FunctionStarts] | None = None
) -> set[str]:
    """The functions the hunks of a C patch sit in, by their headers.

    A header can name no function: diff cuts a long one short, as
    `static enum TIFFReadDirEntryErr TIFFRead` of libtiff, and a hunk at the
    top of a function has none. Given the first line of each function of
    the debug files before and after, as `function_starts` reads them, the
    lines such a hunk removes and adds then name their functions. A header
    in a type, as `struct X {`, names none.

    >>> patch = "\\n".join([
    ...     "+++ b/lib/a.c",
    ...     "@@ -11,2 +11,3 @@ static enum Err Read",
    ...     " context",
    ...     "+added",
    ...     "@@ -50,1 +51,1 @@ struct S {",
    ...     "-int x;",
    ...     "@@ -60,1 +61,1 @@ int g(void)",
    ...     "-old",
    ... ])
    >>> starts = {"/build/lib/a.c": [(10, "read_entry"), (40, "f")]}
    >>> sorted(touched_functions(patch, (starts, starts)))
    ['g', 'read_entry']
    >>> sorted(touched_functions(patch))
    ['g']
    """
    names = set()
    current_file_is_c = False
    path = ""
    old_line = new_line = 0
    by_lines = False
    for line in patch.splitlines():
        if line.startswith("+++ "):
            current_file_is_c = bool(re.search(r"\.(c|h|cc|cpp)\b", line))
            # `b/lib/x.c` or `tiff-4.3.0/libtiff/x.c`: the path in the source.
            path = line[4:].split("\t")[0].strip().split("/", 1)[-1]
            by_lines = False
            continue
        if not current_file_is_c:
            continue
        hunk = HUNK.match(line)
        if hunk:
            name = header_function(hunk.group(1))
            if name:
                names.add(name)
            numbers = HUNK_LINES.match(line)
            old_line, new_line = (int(numbers.group(1)), int(numbers.group(2))) if numbers else (0, 0)
            by_lines = (
                starts is not None and name is None and not TYPE_HEADER.match(hunk.group(1))
            )
            continue
        if line.startswith("-") and not line.startswith("---"):
            if by_lines:
                found = function_at(starts[0], path, old_line)
                names.update([found] if found else [])
            old_line += 1
        elif line.startswith("+"):
            if by_lines:
                found = function_at(starts[1], path, new_line)
                names.update([found] if found else [])
            new_line += 1
        elif line.startswith(" "):
            old_line += 1
            new_line += 1
    return names


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pin(cases: list[dict]) -> list[dict]:
    """The cases as `ubuntu_cases.json` keeps them: paths under the cache,
    and the SHA-256 of each file."""
    pinned = []
    for case in cases:
        files = [[Path(path) for path in side] for side in case["files"]]
        pinned.append(
            {
                "library": case["library"],
                "arch": case["arch"],
                "before": case["before"],
                "after": case["after"],
                "files": [
                    [{"path": str(path.relative_to(CACHE)), "sha256": sha256(path)} for path in side]
                    for side in files
                ],
                "patches": case["patches"],
                "fixes": case["fixes"],
            }
        )
    return pinned


def fetch_pinned() -> list[dict]:
    """The cases of `ubuntu_cases.json`, fetched and checked."""
    shared_object = {binary: so for binary, _, so in LIBRARIES}
    cases = []
    for case in json.loads(PINNED.read_text()):
        sides = []
        for version, side in zip((case["before"], case["after"]), case["files"]):
            pair = library(case["library"], version, case["arch"], shared_object[case["library"]])
            if pair is None:
                raise SystemExit(f"{case['library']} {version} {case['arch']}: not fetched")
            for path, pinned in zip(pair, side):
                if sha256(path) != pinned["sha256"]:
                    raise SystemExit(f"{path}: SHA-256 is {sha256(path)}, expected {pinned['sha256']}")
            sides.append([str(path) for path in pair])
        cases.append({**case, "files": sides})
    return cases


def refix() -> None:
    """Find the functions that the patches of each pinned case touch anew,
    from the cached sources, and pin them."""
    sources = {binary: source for binary, source, _ in LIBRARIES}
    pinned = json.loads(PINNED.read_text())
    for case in pinned:
        source = sources[case["library"]]
        old_patches = patches(source, case["before"])
        new_patches = patches(source, case["after"])
        starts = tuple(function_starts(CACHE / case["files"][side][1]["path"]) for side in (0, 1))
        fixes = set()
        for name, text in new_patches.items():
            if old_patches.get(name) != text:
                fixes |= touched_functions(text, starts)
        case["fixes"] = sorted(fixes)
    PINNED.write_text(json.dumps(pinned, indent=1) + "\n")
    print(f"{len(pinned)} cases pinned anew in {PINNED}", file=sys.stderr)


def main() -> None:
    if "--refix" in sys.argv[1:]:
        refix()
        return
    if "--refresh" not in sys.argv[1:]:
        cases = fetch_pinned()
        CACHE.mkdir(parents=True, exist_ok=True)
        (CACHE / "cases.json").write_text(json.dumps(cases, indent=1))
        print(f"{len(cases)} pinned cases in {CACHE / 'cases.json'}", file=sys.stderr)
        return
    discover()


def discover() -> None:
    """Ask Launchpad for every pair of security releases, and pin them."""
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
                starts = tuple(function_starts(side[1]) for side in pair)
                for text in added.values():
                    fixes |= touched_functions(text, starts)
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
    PINNED.write_text(json.dumps(pin(cases), indent=1) + "\n")
    print(f"{len(cases)} cases in {CACHE / 'cases.json'}, pinned in {PINNED}", file=sys.stderr)


if __name__ == "__main__":
    main()
