#!/usr/bin/env python3
"""Fetch the kernel symbols of the OpenWrt releases the tests compare.

OpenWrt publishes, beside the images of each target, `kernel-debug.tar.zst`:
the `vmlinux` of that build, with its symbols but without its code. Its
symbols are the answer for which function of a shipped kernel is which, so
`examples/research_bench.rs --kernels` checks the pairs of the kernels of
`tests/openwrt.rs` against them.

The release builds the kernel of a target once, so every board of the
target shares it. Each `vmlinux` lands in
~/.cache/hereticus-openwrt-debug/<release>/<target>/vmlinux, about 45 MB,
and a second run reads the cache instead of the network. The symbols are
not pinned: nothing that a test locks reads them.

Needs `zstd` on the path, or Python 3.14, which reads zstd itself.
"""

import io
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

from firmware import BOARDS, MIRROR, RELEASES

CACHE = Path.home() / ".cache" / "hereticus-openwrt-debug"


def decompress(data: bytes) -> bytes:
    """The bytes of a zstd stream."""
    try:
        from compression import zstd
    except ImportError:
        return subprocess.run(
            ["zstd", "-dc"], input=data, capture_output=True, check=True
        ).stdout
    return zstd.decompress(data)


def fetch(release: str, target: str) -> Path:
    """The `vmlinux` of one target of one release, downloaded once."""
    out = CACHE / release / target.replace("/", "-") / "vmlinux"
    if out.exists():
        return out

    url = f"{MIRROR}/{release}/targets/{target}/kernel-debug.tar.zst"
    print(f"openwrt_debug: downloading {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=600) as response:
        archive = decompress(response.read())

    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        member = tar.extractfile("debug/vmlinux")
        if member is None:
            raise FileNotFoundError(f"{url} holds no debug/vmlinux")
        out.parent.mkdir(parents=True, exist_ok=True)
        # Written whole, then renamed, so a stopped run leaves no half file
        # that the next run takes as cached.
        partial = out.with_suffix(".partial")
        partial.write_bytes(member.read())
        partial.rename(out)
    return out


def main() -> int:
    targets = {
        (release, board["path"])
        for board in BOARDS.values()
        for release in board.get("releases", RELEASES)
    }
    for release, target in sorted(targets):
        fetch(release, target)
    print(f"openwrt_debug: {len(targets)} kernels in {CACHE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
