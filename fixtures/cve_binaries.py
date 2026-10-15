#!/usr/bin/env python3
"""Fetch and pin the shipped binaries of the published fixes.

`hereticus-cli/tests/truth_cves.rs` locks where the report ranks each fix of
`real-life-reports/`. Each binary is pinned by its SHA-256, so a snapshot
always tells of the same bytes.

The `ubusd`, `dropbear` and `uhttpd` builds of OpenWrt come from the root file
system of each release, which this script downloads. The Apple binaries come from an IPSW
with the `ipsw` tool, which this script does not run: a missing one stops
it with the commands that get it.

The files land in ~/.cache, where `examples/research_bench.rs --cves` reads
them too.
"""

import gzip
import hashlib
import sys
import urllib.request
from pathlib import Path

CACHE = Path.home() / ".cache"
MIRROR = "https://downloads.openwrt.org/releases"

# The SHA-256 of each binary, by its path under CACHE.
PINNED = {
    "hereticus-apple/cve/15.0.1/19A348__iPhone12,1/kernelcache.release.iPhone12,1":
        "2607a165f19cbfedbe315cb96520165de654f3b334cb53ea27891680d2188a64",
    "hereticus-apple/cve/15.0.2/19A404__iPhone12,1/kernelcache.release.iPhone12,1":
        "85e47c37c3eab9fc862c21537aa1a80709c6e9387c496d32124395cc2c8cf609",
    "hereticus-apple/cve/17.3.1/com.apple.driver.AppleDiskImages2":
        "26ff9f786f2199a50e56b5d9fc56ebe875d478a7df5dadb1aa4ca847fe31d300",
    "hereticus-apple/cve/17.4/com.apple.driver.AppleDiskImages2":
        "771ac1be2a4a91eabf17a3341f1066e36df559c222c48614d7e1c30990c02597",
    "hereticus-apple/cve/18.3.2/com.apple.iokit.IOGPUFamily":
        "d813e474514e45712e736d647b8ed53e2b447b2408ccdb378646ffd33c89ccb7",
    "hereticus-apple/cve/18.4/com.apple.iokit.IOGPUFamily":
        "77c28e8043744afb9db3ad6f471ff142463f2920e82afe13307ff926fdc4842e",
    "hereticus-apple/cve/26.3.1/com.apple.filesystems.smbfs":
        "3722f187d8b9eb5a516ce80a2c0367899e3b9953c230b732ef55f409845247d1",
    "hereticus-apple/cve/25E246/com.apple.filesystems.smbfs":
        "a1462cfbe8d89502035c025109c3d870befbe326291d67ebd240cf50b002b1b9",
    "hereticus-openwrt-cve/24.10.3/armsr-armv7/sbin/ubusd":
        "d61614e909ab0e77a06e0087f24ee2f1eafc467d56c97d211d905234b79b14a7",
    "hereticus-openwrt-cve/24.10.3/armsr-armv8/sbin/ubusd":
        "56ce3953bf266b46dfdcad723f9d7fa5fad3d543dbbb1b022caa5fc1ab98b01c",
    "hereticus-openwrt-cve/24.10.3/malta-be/sbin/ubusd":
        "055fd5ebe233a92a190a4dabf06c3250edb878ba0ebaf9092f21439c2f62ec01",
    "hereticus-openwrt-cve/24.10.3/malta-le/sbin/ubusd":
        "d464aa05d1815308e25e74baf3c63a8507bf01a799ef97a5d27f4d7b2ec10ec5",
    "hereticus-openwrt-cve/24.10.4/armsr-armv7/sbin/ubusd":
        "f2b3c3afd5337e5dbda4a206f2577c587cba2923a1bfa5ddb276715f34470ab3",
    "hereticus-openwrt-cve/24.10.4/armsr-armv8/sbin/ubusd":
        "6b329c4c193eed1556da5feca66fc173ea933c877bbd7cf496370be55a372ca1",
    "hereticus-openwrt-cve/24.10.4/malta-be/sbin/ubusd":
        "4bd440a4a9ff97036b52126eb474fbdaa888dd5a01d5e5db0cec8e12ccc1e1b4",
    "hereticus-openwrt-cve/24.10.4/malta-le/sbin/ubusd":
        "cffa52774419885a10052f06aaf1257bb226aa34fa999365db2674586f47916f",
    "hereticus-openwrt-cve/24.10.4/armsr-armv7/usr/sbin/dropbear":
        "b0773a24dfbff1a511c582831a36a6572eb7dd1cc637a4a87189dbbf6d5949af",
    "hereticus-openwrt-cve/24.10.4/armsr-armv8/usr/sbin/dropbear":
        "cce48e316b43bcefb5c5457fd5bd2e9a838ca58e9da006f7b2695a09396911d0",
    "hereticus-openwrt-cve/24.10.4/malta-be/usr/sbin/dropbear":
        "7512316d87ff5c6c3e3f9ccc4f0c4384a52adcdc9d57289fb56c31bae9ebb90b",
    "hereticus-openwrt-cve/24.10.4/malta-le/usr/sbin/dropbear":
        "9b4470c6f642f0549f5185299de272dd003f81b1e79d505932a99025569d944e",
    "hereticus-openwrt-cve/24.10.5/armsr-armv7/usr/sbin/dropbear":
        "279b9f3973593ac5c6575e1b933da5faa374725b29f4270afa0045f26b140e5c",
    "hereticus-openwrt-cve/24.10.5/armsr-armv8/usr/sbin/dropbear":
        "87c5cebea6fc4d6d5474af37453d1d54382451d0730ea93594a757c466e0e26f",
    "hereticus-openwrt-cve/24.10.5/malta-be/usr/sbin/dropbear":
        "50a3fb3996a73ebf1ed32b8320c411ad5becead2d94128a893b443064fa578fa",
    "hereticus-openwrt-cve/24.10.5/malta-le/usr/sbin/dropbear":
        "c21e21d8fdd80dc67fc46504973021fd0490a776db72a976c3b01eb3e3402726",
    "hereticus-openwrt-cve/24.10.7/armsr-armv7/usr/sbin/uhttpd":
        "bd90b99ece8e8d7ec4cb1b7e008c71895096964f43552c9fefea047652dbc341",
    "hereticus-openwrt-cve/24.10.7/armsr-armv8/usr/sbin/uhttpd":
        "3e5c0ce4cbaa41b77bd3592c628a767ece5dcce16af2ac12cee6eff255b910de",
    "hereticus-openwrt-cve/24.10.7/malta-be/usr/sbin/uhttpd":
        "f13513d33286b2597d16979e5ba9499231d732b2f590844512b8d82a57d7ad62",
    "hereticus-openwrt-cve/24.10.7/malta-le/usr/sbin/uhttpd":
        "2384f481beb862c4b87441b9109eabd065c55364c138bab82daefd6ad82669e7",
    "hereticus-openwrt-cve/24.10.8/armsr-armv7/usr/sbin/uhttpd":
        "ff51377eb7796a4f27ed2bda2b78dda0dfbbc03d957300677a2cd22c8dddd913",
    "hereticus-openwrt-cve/24.10.8/armsr-armv8/usr/sbin/uhttpd":
        "5fddaa309fa5183ffba5f3dce8a079b6d68e0664815e452f4c6619c25a71c491",
    "hereticus-openwrt-cve/24.10.8/malta-be/usr/sbin/uhttpd":
        "43239e6a246c35897123c12c1ccc2f64842174b24a8545b5b93ef2cd663dba56",
    "hereticus-openwrt-cve/24.10.8/malta-le/usr/sbin/uhttpd":
        "d8f0c68027892eaa1106ff63868d467f550e55915538f587a767dc1e57c8182b",
}

# The commands that put the Apple binaries in CACHE / "hereticus-apple/cve",
# as `real-life-reports/` gives them.
IPSW_COMMANDS = """\
ipsw download ipsw --device iPhone12,1 --build 19A348 --kernel --output 15.0.1
ipsw download ipsw --device iPhone12,1 --build 19A404 --kernel --output 15.0.2
ipsw download ipsw --device iPhone15,4 --build 21D61 --kernel --output 17.3.1
ipsw download ipsw --device iPhone15,4 --build 21E219 --kernel --output 17.4
ipsw kernel extract 17.3.1/*/kernelcache.release.iPhone15,4 com.apple.driver.AppleDiskImages2 --output 17.3.1
ipsw kernel extract 17.4/*/kernelcache.release.iPhone15,4 com.apple.driver.AppleDiskImages2 --output 17.4
ipsw download ipsw --device iPhone15,2 --build 22D82 --kernel --output 18.3.2
ipsw download ipsw --device iPhone15,2 --build 22E240 --kernel --output 18.4
ipsw kernel extract 18.3.2/*/kernelcache.release.iPhone15,2 com.apple.iokit.IOGPUFamily --output 18.3.2
ipsw kernel extract 18.4/*/kernelcache.release.iPhone15,2 com.apple.iokit.IOGPUFamily --output 18.4
ipsw download ipsw --macos --device VirtualMac2,1 --build 25D2128 --kernel --output 26.3.1
ipsw download ipsw --macos --device VirtualMac2,1 --build 25E246 --kernel --output 25E246
ipsw kernel extract 26.3.1/*/kernelcache.release.VirtualMac2,1 com.apple.filesystems.smbfs --output 26.3.1
ipsw kernel extract 25E246/*/kernelcache.release.VirtualMac2,1 com.apple.filesystems.smbfs --output 25E246
"""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cpio_member(archive: bytes, wanted: str) -> bytes:
    """The bytes of one file of a `newc` cpio archive."""
    at = 0
    while at < len(archive):
        header = archive[at : at + 110]
        if header[:6] != b"070701":
            raise ValueError(f"no cpio header at {at}")
        size = int(header[54:62], 16)
        name_size = int(header[94:102], 16)
        name = archive[at + 110 : at + 110 + name_size - 1].decode()
        # The name and the data each pad to a multiple of four bytes.
        data_at = (at + 110 + name_size + 3) & ~3
        if name == "TRAILER!!!":
            break
        if name.lstrip("./") == wanted:
            return archive[data_at : data_at + size]
        at = (data_at + size + 3) & ~3
    raise FileNotFoundError(wanted)


def fetch_from_rootfs(path: str) -> bytes:
    """Download a file of the root file system of its release."""
    # hereticus-openwrt-cve/<release>/<target>-<subtarget>/<file>
    _, release, target, *member = path.split("/")
    board, subtarget = target.split("-")
    url = (
        f"{MIRROR}/{release}/targets/{board}/{subtarget}/"
        f"openwrt-{release}-{target}-rootfs.cpio.gz"
    )
    print(f"cve_binaries: downloading {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=600) as response:
        archive = gzip.decompress(response.read())
    return cpio_member(archive, "/".join(member))


def main() -> int:
    missing_apple = []
    for path, expected in PINNED.items():
        out = CACHE / path
        if out.exists():
            data = out.read_bytes()
        elif path.startswith("hereticus-openwrt-cve/"):
            data = fetch_from_rootfs(path)
        else:
            missing_apple.append(path)
            continue
        actual = sha256(data)
        if actual != expected:
            print(f"{out}: SHA-256 is {actual}, expected {expected}", file=sys.stderr)
            return 1
        if not out.exists():
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
    if missing_apple:
        print("cve_binaries: missing, from an IPSW:", file=sys.stderr)
        for path in missing_apple:
            print(f"  {CACHE / path}", file=sys.stderr)
        print(
            f"Install `ipsw`, then in {CACHE / 'hereticus-apple/cve'} run:\n{IPSW_COMMANDS}",
            file=sys.stderr,
        )
        return 1
    print(f"cve_binaries: {len(PINNED)} binaries in {CACHE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
