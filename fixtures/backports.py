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
    "smallvec-1.6.0.crate": (
        "https://static.crates.io/crates/smallvec/smallvec-1.6.0.crate",
        "1a55ca5f3b68e41c979bf8c46a6f1da892ca4db8f94023ce0bd32407573b1ac0",
    ),
    # Consecutive releases, for the comparisons across versions.
    "zlib-1.2.11.tar.gz": (
        "https://zlib.net/fossils/zlib-1.2.11.tar.gz",
        "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1",
    ),
    "zlib-1.2.13.tar.gz": (
        "https://zlib.net/fossils/zlib-1.2.13.tar.gz",
        "b3a24de97a8fdbc835b9833169501030b8977031bcb54b3b3ac13740f846ab30",
    ),
    "zlib-1.3.tar.gz": (
        "https://zlib.net/fossils/zlib-1.3.tar.gz",
        "ff0ba4c292013dbc27530b3a81e1f9a813cd39de01ca5e0f8bf355702efa593e",
    ),
    "lua-5.1.4.tar.gz": (
        "https://www.lua.org/ftp/lua-5.1.4.tar.gz",
        "b038e225eaf2a5b57c9bcc35cd13aa8c6c8288ef493d52970c9545074098af3a",
    ),
    "lua-5.3.5.tar.gz": (
        "https://www.lua.org/ftp/lua-5.3.5.tar.gz",
        "0c2eed3f960446e1a3e4b9a1ca2f3ff893b6ce41942cf54d5dd59ab4b3b058ac",
    ),
    "lua-5.3.6.tar.gz": (
        "https://www.lua.org/ftp/lua-5.3.6.tar.gz",
        "fc5fd69bb8736323f026672b1b7235da613d7177e72558893a0bdcd320466d60",
    ),
    "tinyxml2-8.0.0.tar.gz": (
        "https://github.com/leethomason/tinyxml2/archive/refs/tags/8.0.0.tar.gz",
        "6ce574fbb46751842d23089485ae73d3db12c1b6639cda7721bf3a7ee862012c",
    ),
    "tinyxml2-10.0.0.tar.gz": (
        "https://github.com/leethomason/tinyxml2/archive/refs/tags/10.0.0.tar.gz",
        "3bdf15128ba16686e69bce256cc468e76c7b94ff2c7f391cc5ec09e40bff3839",
    ),
    "expat-2.4.4.tar.gz": (
        "https://github.com/libexpat/libexpat/releases/download/R_2_4_4/expat-2.4.4.tar.gz",
        "5963005ff8720735beb2d2db669afc681adcbcb43dd1eb397d5c2dd7adbc631f",
    ),
    "expat-2.4.5.tar.gz": (
        "https://github.com/libexpat/libexpat/releases/download/R_2_4_5/expat-2.4.5.tar.gz",
        "9e88fb86a0220ab5c1fcf42c187857c2151534b7a4d88741c9405df5be449a3d",
    ),
    "expat-2.4.8.tar.gz": (
        "https://github.com/libexpat/libexpat/releases/download/R_2_4_8/expat-2.4.8.tar.gz",
        "398f6d95bf808d3108e27547b372cb4ac8dc2298a3c4251eb7aa3d4c6d4bb3e2",
    ),
    "expat-2.4.9.tar.gz": (
        "https://github.com/libexpat/libexpat/releases/download/R_2_4_9/expat-2.4.9.tar.gz",
        "4415710268555b32c4e5ab06a583bea9fec8ff89333b218b70b43d4ca10e38fa",
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
