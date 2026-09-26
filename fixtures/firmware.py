#!/usr/bin/env python3
"""Download real OpenWrt firmware and extract the code the tests compare.

Run by `just firmware`. Each board ships in two releases, 22.03.2 and 22.03.5,
so the tests compare what one real release changed. The images are not
committed: they are large and are not ours to redistribute. Instead each
download and each extracted file is pinned by its SHA-256, so every machine
tests the same bytes, and a changed mirror fails here rather than as a
confusing test failure.

Each board gives two images per release:

* a stub: the small program that decompresses the kernel. It is 5 to 15 KiB,
  so its report is small enough to read in full.
* a kernel: the decompressed Linux kernel, 7 to 11 MiB. The tests that read
  it are marked slow.

Only the Python standard library is used, so no container is necessary.
"""

import hashlib
import lzma
import struct
import sys
import urllib.request
from pathlib import Path

MIRROR = "https://downloads.openwrt.org/releases"
RELEASES = ("22.03.2", "22.03.5")

OUT = Path(__file__).resolve().parent / "build" / "openwrt"
DOWNLOADS = OUT / "download"

# The zImage magic word, at offset 0x24 of an ARM zImage.
ZIMAGE_MAGIC = struct.pack("<I", 0x016F2818)
XZ_MAGIC = b"\xfd7zXZ\x00"
# The header OpenWrt's lzma-loader payload starts with: `-lc1 -lp2`, which is
# the properties byte 0x6d, then a dictionary of 8 MiB.
LZMA_HEADER = b"\x6d\x00\x00\x80\x00"

BOARDS = {
    # ARM, little endian. The kernel is a zImage inside a FIT image.
    "arm-ex6100v2": {
        "path": "ipq40xx/generic",
        "file": "openwrt-{release}-ipq40xx-generic-netgear_ex6100v2-squashfs-sysupgrade.bin",
        "download": {
            "22.03.2": "f0287b365cb9d850ca3bab8720d39fdb799233ad03429b4b85c12ab24f9e69d2",
            "22.03.5": "588d24cdbd440f6d49b983e74ff04936bc201d7f815de743cf873552470b1f2d",
        },
    },
    # MIPS, big endian. The kernel partition is an ELF lzma-loader.
    "mipsbe-eap245v3": {
        "path": "ath79/generic",
        "file": "openwrt-{release}-ath79-generic-tplink_eap245-v3-squashfs-sysupgrade.bin",
        "download": {
            "22.03.2": "2080568ecccd6bbb17272dc829b40fd128ee51f50b8945631ec85724edfd90e9",
            "22.03.5": "2eb311d0006e39e0288066ed8d5c75ae1abde30805d8b4a24d45e30b2428484f",
        },
    },
    # MIPS, little endian. The kernel is an lzma-loader inside a uImage.
    "mipsel-r6220": {
        "path": "ramips/mt7621",
        "file": "openwrt-{release}-ramips-mt7621-netgear_r6220-squashfs-kernel.bin",
        "download": {
            "22.03.2": "f56e428b24b618dfc6de26ae19a9e634d8c3b9086265b451bb868b1dacab6ac6",
            "22.03.5": "f02e7feac346935a682f6f9cc137fed9e1d0f70a4fe00c69aa8e529b95498c11",
        },
    },
}

# The SHA-256 of every extracted file. A change to the extraction that moves
# one byte fails here.
EXTRACTED = {
    "arm-ex6100v2-stub-22.03.2.bin": "d265e563c30d7e4ef5db39b1404f75e39096053f8945263a22b9f498af7e1e85",
    "arm-ex6100v2-stub-22.03.5.bin": "ebcd57cb98d25dd3ef0b894c696072e5cfe63b79609da992b5f8dbaf8efb6831",
    "arm-ex6100v2-kernel-22.03.2.bin": "ea8a0b97470a762b1877de164bac1ae585c70026ac93fb0f25346efdb5beff43",
    "arm-ex6100v2-kernel-22.03.5.bin": "362812f590c69b7afd74d43299d834251d1275df424617eb0432221e2d26190a",
    "mipsbe-eap245v3-stub-22.03.2.bin": "c52289bc353a3cf065cbefd9f53a283321ef92ddad930eb5635a21dfa257a51b",
    "mipsbe-eap245v3-stub-22.03.5.bin": "f652e96c77c5a90c680fe913c4905f724e7e279e86744384988cd02770794871",
    "mipsbe-eap245v3-kernel-22.03.2.bin": "4a82d66bdcba27007b3003b5d71f0cba61e0a4fe45bf9b3b177712c4151994ca",
    "mipsbe-eap245v3-kernel-22.03.5.bin": "f01a6044422a2fb65d0b362f6a37b2a0e9ecb46d81e6c957606d2d03ff73b02d",
    "mipsel-r6220-stub-22.03.2.bin": "6255fe06adef5811316170095ef1f13c4602697cf69d13a26c5a2aa312298464",
    "mipsel-r6220-stub-22.03.5.bin": "6bcaa6178a616d4f3de4e115779a994e7eceb19e33195e7294a1ba709586a7b2",
    "mipsel-r6220-kernel-22.03.2.bin": "b3bd89a127791aba348e2f61c51ebedbca2bd0a5fc9ef89fae74bd3574aba436",
    "mipsel-r6220-kernel-22.03.5.bin": "f9bac282a059f69ebfb5e37c59d4c5d431839bf8bc61b6cd5c8313c0d8ca1ae6",
}


class ExtractError(Exception):
    """The image does not hold what this script expects."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(board: dict, release: str) -> bytes:
    """Return the image, downloading it only when no good copy is cached."""
    name = board["file"].format(release=release)
    expected = board["download"][release]
    cached = DOWNLOADS / name

    if cached.exists() and sha256(cached.read_bytes()) == expected:
        return cached.read_bytes()

    url = f"{MIRROR}/{release}/targets/{board['path']}/{name}"
    print(f"firmware: downloading {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()

    actual = sha256(data)
    if actual != expected:
        raise ExtractError(f"{name}: SHA-256 is {actual}, expected {expected}")

    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    cached.write_bytes(data)
    return data


def first_stream(data: bytes, start: int, end: int, magic: bytes, fmt: int) -> tuple[int, bytes]:
    """Find the first compressed stream in `data[start:end]` that decodes.

    The magic alone is not enough: a decompressor holds its own format's magic
    as a constant, so the first match can sit inside the stub. The ARM stub
    does exactly this, 231 bytes before the real payload.
    """
    offset = data.find(magic, start, end)
    while offset != -1:
        try:
            decoder = lzma.LZMADecompressor(format=fmt)
            return offset, decoder.decompress(data[offset:end])
        except lzma.LZMAError:
            offset = data.find(magic, offset + 1, end)
    raise ExtractError(f"no stream with magic {magic.hex()} decodes")


def extract_arm_zimage(image: bytes) -> tuple[bytes, bytes]:
    """Split a zImage into its decompressor stub and the kernel it holds."""
    magic = image.find(ZIMAGE_MAGIC)
    if magic == -1:
        raise ExtractError("no zImage")
    zimage = magic - 0x24
    _, end = struct.unpack("<II", image[magic + 4 : magic + 12])

    payload, kernel = first_stream(image, zimage, zimage + end, XZ_MAGIC, lzma.FORMAT_XZ)
    return image[zimage:payload], kernel


def extract_elf_loader(image: bytes) -> tuple[bytes, bytes]:
    """Split a big-endian ELF lzma-loader into its code and the kernel."""
    if image[:6] != b"\x7fELF\x01\x02":
        raise ExtractError("no 32-bit big-endian ELF")
    phoff = struct.unpack(">I", image[28:32])[0]
    # The first program header loads the loader and its payload together.
    _, offset, _, _, filesz = struct.unpack(">5I", image[phoff : phoff + 20])

    payload, kernel = first_stream(image, offset, offset + filesz, LZMA_HEADER, lzma.FORMAT_ALONE)
    return image[offset:payload], kernel


def extract_uimage_loader(image: bytes) -> tuple[bytes, bytes]:
    """Split an uncompressed uImage lzma-loader into its code and the kernel."""
    if image[:4] != b"\x27\x05\x19\x56":
        raise ExtractError("no uImage")
    size = struct.unpack(">I", image[12:16])[0]
    body = 64

    payload, kernel = first_stream(image, body, body + size, LZMA_HEADER, lzma.FORMAT_ALONE)
    return image[body:payload], kernel


EXTRACTORS = {
    "arm-ex6100v2": extract_arm_zimage,
    "mipsbe-eap245v3": extract_elf_loader,
    "mipsel-r6220": extract_uimage_loader,
}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    failures = []

    for name, board in BOARDS.items():
        for release in RELEASES:
            stub, kernel = EXTRACTORS[name](fetch(board, release))
            for part, data in (("stub", stub), ("kernel", kernel)):
                file = f"{name}-{part}-{release}.bin"
                (OUT / file).write_bytes(data)
                if sha256(data) != EXTRACTED[file]:
                    failures.append(f"{file}: SHA-256 is {sha256(data)}, expected {EXTRACTED[file]}")

    for failure in failures:
        print(f"firmware: {failure}", file=sys.stderr)
    if failures:
        return 1

    print(f"firmware: extracted {len(EXTRACTED)} files in {OUT}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ExtractError as error:
        print(f"firmware: {error}", file=sys.stderr)
        sys.exit(1)
