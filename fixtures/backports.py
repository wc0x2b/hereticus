#!/usr/bin/env python3
"""Download the upstream releases the backport fixtures are built from.

Run by `just backports`, before `fixtures/backports.sh` builds them. Each
tarball is pinned by its SHA-256, so every machine builds the same source,
and a second run reads the cached copy instead of the network.

The fixes applied on top live in `fixtures/patches`, in the repository.
"""

import hashlib
import sys
import urllib.request
from pathlib import Path

DOWNLOADS = Path(__file__).resolve().parent / "build" / "backports" / "download"

TARBALLS = {
    "zlib-1.2.12.tar.gz": (
        "https://zlib.net/fossils/zlib-1.2.12.tar.gz",
        "91844808532e5ce316b3c010929493c0244f3d37593afd6de04f71821d5136d9",
    ),
    "lua-5.1.5.tar.gz": (
        "https://www.lua.org/ftp/lua-5.1.5.tar.gz",
        "2640fc56a795f29d28ef15e13c34a47e223960b0240e8cb0a82d9b0738695333",
    ),
    "tinyxml2-9.0.0.tar.gz": (
        "https://github.com/leethomason/tinyxml2/archive/refs/tags/9.0.0.tar.gz",
        "cc2f1417c308b1f6acc54f88eb70771a0bf65f76282ce5c40e54cfe52952702c",
    ),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    DOWNLOADS.mkdir(parents=True, exist_ok=True)

    for name, (url, expected) in TARBALLS.items():
        cached = DOWNLOADS / name
        if cached.exists() and sha256(cached.read_bytes()) == expected:
            continue

        print(f"backports: downloading {url}", file=sys.stderr)
        with urllib.request.urlopen(url, timeout=120) as response:
            data = response.read()
        if sha256(data) != expected:
            print(f"backports: {name}: SHA-256 is {sha256(data)}, expected {expected}", file=sys.stderr)
            return 1
        cached.write_bytes(data)

    print(f"backports: {len(TARBALLS)} tarballs in {DOWNLOADS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
