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
and a second run reads the cache instead of the network. Each `vmlinux`
is pinned by its SHA-256, because `tests/truth_kernels.rs` locks the counts
it gives: a changed file fails here, not as a changed snapshot.

Needs `zstd` on the path, or Python 3.14, which reads zstd itself.
"""

import hashlib
import io
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

from firmware import BOARDS, MIRROR, RELEASES

CACHE = Path.home() / ".cache" / "hereticus-openwrt-debug"

# The SHA-256 of each `vmlinux`, by release and target.
PINNED = {
    ("21.02.7", "ath79/generic"): "57ee305e2c9b1605e7906c7cb386bff3f8c974cc4d61d520262d59748dafca04",
    ("21.02.7", "ipq40xx/generic"): "77864cec194a0ea277bdaa903c63fd2cfe944681f5a8fe08b52623ca8042d892",
    ("21.02.7", "ramips/mt7621"): "172da0ccdca05dc8eda8979f649d03b6064917df7118bce9eff158ed882332e4",
    ("22.03.2", "ath79/generic"): "f6050302ab8e6272bd11db0839fc2965b30d048379605f4ddb72ddf0ad198402",
    ("22.03.2", "ipq40xx/generic"): "c689e6ee8d3c62843883fae8fde88b1e00430eaf6df616c48cae040726323887",
    ("22.03.2", "lantiq/xrx200"): "1783d5c097aa0aec9ae73b1d5d86cd3a77e921d0009907db3bb9b9e45a4bbd21",
    ("22.03.2", "mvebu/cortexa9"): "7fd8c5aa6156645b410336203a9e3bccba62d2a837b36c3cefee0d6f5b3045e9",
    ("22.03.2", "ramips/mt7621"): "b565ee944ef05dce4b8e0020fa3b72ed56b3cffa3c8e27033300d0c96bda7604",
    ("22.03.2", "ramips/mt76x8"): "2b48da34a1ea8e2e2ca1b999714ebbb5d19f71e7c2220269dd90c87e652d207f",
    ("22.03.5", "ath79/generic"): "94ee41e86fe971e37cf881407c8cbb0a6786cf77edd10240f1471fdab80feee6",
    ("22.03.5", "ipq40xx/generic"): "6e8a51c55091c036ebb2c9e53b858bdc1655f63d795eb650f1bec0d26ec2f7f8",
    ("22.03.5", "lantiq/xrx200"): "e1d472c68032e8f5dc60e84ad389fef766498ce0641bb05f007ee88377d4b74c",
    ("22.03.5", "mvebu/cortexa9"): "3fb1538ca42eac5fcf5c927f4cb0bd70896b410b4db0ce0918f43f608c4ceebe",
    ("22.03.5", "ramips/mt7621"): "bec0692def6a5580e918ba7c90b2c837e98faf30e18d93bde61b490591e735e4",
    ("22.03.5", "ramips/mt76x8"): "10ed0c143d6a6c3056b1cc63092cd2c55ecb454b4272d87c6b4df94e5f63ae5c",
    ("23.05.5", "ath79/generic"): "4618b2bb6f62a1c7239bec02f9dcc6d75fd14ac84a525db9f59f57b50e1caf3c",
    ("23.05.5", "ipq40xx/generic"): "beccf322e9ead1b38a2e11a397e0df3de3b7cb061205087f535658190a17e0b8",
    ("23.05.5", "ramips/mt7621"): "d224fac66757bdec848086f5ad145cb17ead8d754ca44bbb41ac0b130dde9696",
}


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
        check(out, PINNED[(release, target)])
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
        check(partial, PINNED[(release, target)])
        partial.rename(out)
    return out


def check(path: Path, expected: str) -> None:
    """Stop if the file at `path` is not the pinned one."""
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"{path}: SHA-256 is {actual}, expected {expected}")


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
