#!/usr/bin/env python3
"""Fetch and pin the shipped binaries of the published fixes.

`hereticus-cli/tests/truth_cves.rs` locks where the report ranks each fix of
`real-life-reports/`. Each binary is pinned by its SHA-256, so a snapshot
always tells of the same bytes.

The `ubusd`, `dropbear`, `uhttpd`, `odhcpd`, `procd`, `jsonfilter` and
`libblobmsg_json` builds of OpenWrt come
from the root file system of each release, or from the initramfs of its
kernel where it ships none, and the `ltq-ptm` kernel
module from its package, which this script downloads. The Apple binaries
come from an IPSW with the `ipsw` tool, which this script does not run: a
missing one stops it with the commands that get it.

The files land in ~/.cache, where `examples/research_bench.rs --cves` reads
them too.
"""

import gzip
import hashlib
import io
import re
import sys
import tarfile
import urllib.error
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
    "hereticus-openwrt-cve/24.10.7/armsr-armv7/usr/sbin/odhcpd":
        "9a6fa1e61cafaf9d7ea16704972450bb2f71948d6eed0f51f25dd18bb00f033b",
    "hereticus-openwrt-cve/24.10.7/armsr-armv8/usr/sbin/odhcpd":
        "e8dc4908a656aa91f0bb707cc798abbb7614974c6cecbd7fed4173907ddbcc1c",
    "hereticus-openwrt-cve/24.10.7/malta-be/usr/sbin/odhcpd":
        "e083b82c75e01a175aad25a0c2cf2e9f4eb1010d517e1e8d20aa9746b774f160",
    "hereticus-openwrt-cve/24.10.7/malta-le/usr/sbin/odhcpd":
        "03843f30c6ea82c374adcbfd39adb2c04bb2a3e2b62255abce6149ecab10338c",
    "hereticus-openwrt-cve/24.10.8/armsr-armv7/usr/sbin/odhcpd":
        "9b4cd5b86e2909a7d2737540608948bf396548c5ef85aa6d9024990cc308e420",
    "hereticus-openwrt-cve/24.10.8/armsr-armv8/usr/sbin/odhcpd":
        "db21cfb72e4bdfd4e5eaa3cf05b69d0d86e2047049a2eb25db3653c211f861d3",
    "hereticus-openwrt-cve/24.10.8/malta-be/usr/sbin/odhcpd":
        "92eb5b2bdb1dec79f53793dbc3b8b286db0e6efb20052caeea54bcc1c033ff83",
    "hereticus-openwrt-cve/24.10.8/malta-le/usr/sbin/odhcpd":
        "440e1659e44aec570fb502136ddcf2d24e6cb1d496929e08dad98e487eb33ef0",
    "hereticus-openwrt-cve/24.10.7/armsr-armv7/usr/sbin/dropbear":
        "279b9f3973593ac5c6575e1b933da5faa374725b29f4270afa0045f26b140e5c",
    "hereticus-openwrt-cve/24.10.7/armsr-armv8/usr/sbin/dropbear":
        "87c5cebea6fc4d6d5474af37453d1d54382451d0730ea93594a757c466e0e26f",
    "hereticus-openwrt-cve/24.10.7/malta-be/usr/sbin/dropbear":
        "50a3fb3996a73ebf1ed32b8320c411ad5becead2d94128a893b443064fa578fa",
    "hereticus-openwrt-cve/24.10.7/malta-le/usr/sbin/dropbear":
        "c21e21d8fdd80dc67fc46504973021fd0490a776db72a976c3b01eb3e3402726",
    "hereticus-openwrt-cve/24.10.8/armsr-armv7/usr/sbin/dropbear":
        "79cc7cdaff6e81d8c4f1db8e83ff2ec646655255e71eb23981e1aa2a730f0152",
    "hereticus-openwrt-cve/24.10.8/armsr-armv8/usr/sbin/dropbear":
        "613a87671b6a3a361da41ff330a69e34bf00926f5cbdf92e7da7126cb65930a6",
    "hereticus-openwrt-cve/24.10.8/malta-be/usr/sbin/dropbear":
        "6cc99aa25d942d3d9cd5a23fc76c32f6029e09fb0f40b04d0e5ee1c935a74a1d",
    "hereticus-openwrt-cve/24.10.8/malta-le/usr/sbin/dropbear":
        "0916a47632470d571b0ec1c144a331ca6242ab0249f46b4db42fefeb06cc1945",
    "hereticus-openwrt-cve/24.10.5/armsr-armv7/sbin/procd":
        "d11654f4151d509144f6b98325edc490fa3e6ae629938cbf909655ee528c12d4",
    "hereticus-openwrt-cve/24.10.5/armsr-armv8/sbin/procd":
        "7112955bab62ef58d90b456c4e8e74a6a6a7880db66931239465e149c3df8630",
    "hereticus-openwrt-cve/24.10.5/malta-be/sbin/procd":
        "24a88ed01acc1179a00495d3e95bff46a6236a7a49c359f271aeef810964b31d",
    "hereticus-openwrt-cve/24.10.5/malta-le/sbin/procd":
        "0b40f209887f0a1789667fd9c4ddea0e2a92f262a56247380a4cd0d79774ab7f",
    "hereticus-openwrt-cve/24.10.6/armsr-armv7/sbin/procd":
        "1fa7fd8e46f987f5272d0fb9030c06b6afaad347089f3645994d2c8bd1fee191",
    "hereticus-openwrt-cve/24.10.6/armsr-armv8/sbin/procd":
        "d95bbc2d7e6859ecda95018916a3cb959731a0e4d3ca120e0aac9348ec5cd751",
    "hereticus-openwrt-cve/24.10.6/malta-be/sbin/procd":
        "38437a6b4e363461b4e9d53a637228b2e2250f1b4f28cb614ac10edcee604496",
    "hereticus-openwrt-cve/24.10.6/malta-le/sbin/procd":
        "0986a9fd489f756102183b9fbe390e70284009ed0eefc7e34fc645666226bdfb",
    "hereticus-openwrt-cve/24.10.5/armsr-armv7/usr/bin/jsonfilter":
        "18bd0efd2245e34be7054109129428deb1b835fe9fc1a2e25dd66f139cc93f40",
    "hereticus-openwrt-cve/24.10.5/armsr-armv8/usr/bin/jsonfilter":
        "c5422e061f558766371c656a7fcf328d769c61f3246d34c15f9032769be6313f",
    "hereticus-openwrt-cve/24.10.5/malta-be/usr/bin/jsonfilter":
        "9f6f3432188fd3c065a5fa34a720584982cef4b597258c62e7dd6b8063dc938b",
    "hereticus-openwrt-cve/24.10.5/malta-le/usr/bin/jsonfilter":
        "2b1b21c752ee348fe41aa135774fec40aaf1629ef713352572a9e018763d0838",
    "hereticus-openwrt-cve/24.10.6/armsr-armv7/usr/bin/jsonfilter":
        "aec8d23dc84576770a739debad201adb982a5dfa7ef45769c79154cf9d0e8568",
    "hereticus-openwrt-cve/24.10.6/armsr-armv8/usr/bin/jsonfilter":
        "35f002a6b55f04993880a2ce635aa3581aaa1d4feb8a341b2bf6fdd4567f7cd9",
    "hereticus-openwrt-cve/24.10.6/malta-be/usr/bin/jsonfilter":
        "1ce3171e3503e0af6893c6732dc4f50a9ca8cc865c8fc04c8c19d32fd73a76f3",
    "hereticus-openwrt-cve/24.10.6/malta-le/usr/bin/jsonfilter":
        "aac0c73dd4e872c902e4043a552d83872631790666be7414d604e82f02b5d13d",
    "hereticus-openwrt-cve/24.10.3/lantiq-xrx200/kmod/kmod-ltq-ptm-vr9/ltq_ptm_vr9.ko":
        "894254504b177e26a17b0d84ce3776ec23065373fc3e9594e4ab754e78be5509",
    "hereticus-openwrt-cve/24.10.4/lantiq-xrx200/kmod/kmod-ltq-ptm-vr9/ltq_ptm_vr9.ko":
        "36acfb05c54365983c94ba27516870dad3c19c29226f5635c7ac7c4d0c5c131e",
    "hereticus-openwrt-cve/19.07.0/armvirt-32/lib/libblobmsg_json.so":
        "72f059db90c6ac5a44ccb3aa67f2e9e8664698c18679d5b608de5fd7e5122694",
    "hereticus-openwrt-cve/19.07.0/armvirt-64/lib/libblobmsg_json.so":
        "4077a1da5237228ce55d8aa2008cbfa745234c32ac194c074683fe9ac152854c",
    "hereticus-openwrt-cve/19.07.1/armvirt-32/lib/libblobmsg_json.so":
        "3f91cca8e214c38bb1084d857bf9c9b8b575c915f14f8711578571cc9a84c865",
    "hereticus-openwrt-cve/19.07.1/armvirt-64/lib/libblobmsg_json.so":
        "8f811f00b500887ffdd8640eacb9bbbbca8f4c4f247ebabe2f21a39abd4a134e",
    "hereticus-openwrt-cve/18.06.5/armvirt-32/usr/sbin/uhttpd":
        "f30a12be242c2e64d4f2709bce10ad44966210fe4f647e15641a1fb7aff1040f",
    "hereticus-openwrt-cve/18.06.5/armvirt-64/usr/sbin/uhttpd":
        "b32ccb39fa690761a641ff09d7710b86fbefcfeab322e3e321c48d585069645d",
    "hereticus-openwrt-cve/18.06.6/armvirt-32/usr/sbin/uhttpd":
        "adcf264d25fab36d12ca943025dd55060edfc01403f34e0c199b2209ffa356f8",
    "hereticus-openwrt-cve/18.06.6/armvirt-64/usr/sbin/uhttpd":
        "a3f9cf3f3656ecb35e629aa3c8d16b2330b76ed9c603654a74241bd01ed1bec9",
    "hereticus-openwrt-cve/19.07.0/malta-be/lib/libblobmsg_json.so":
        "f5748a9e250fe610a038ee4d5645549e65d1e8bb8819ae94877a6fbbea4a1d55",
    "hereticus-openwrt-cve/19.07.1/malta-be/lib/libblobmsg_json.so":
        "03507b37509b4c9ebf19a65ecbf08ddc1f1f9a7b0a161fa0b179c30c6e0b0c21",
    "hereticus-openwrt-cve/18.06.5/malta-be/usr/sbin/uhttpd":
        "b78a5c0e2735bfe84f5712b32c561fa6d5f7f7568e2762b71193411461580247",
    "hereticus-openwrt-cve/18.06.6/malta-be/usr/sbin/uhttpd":
        "02492c2cc82d2c9c611e46c85974b2732ad636ff00916c530fb981f54d5528a3",
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
    """Download a file of the root file system of its release.

    Releases before 21.02 ship an empty `rootfs.cpio.gz` for `armvirt`, and
    the same files in `default-rootfs.tar.gz`, which is read instead. They
    ship no root file system for `malta` at all, but a kernel that holds it
    as its initramfs, which is read then.
    """
    # hereticus-openwrt-cve/<release>/<target>-<subtarget>/<file>
    _, release, target, *member = path.split("/")
    board, subtarget = target.split("-")
    base = f"{MIRROR}/{release}/targets/{board}/{subtarget}/openwrt-{release}-{target}"
    url = f"{base}-rootfs.cpio.gz"
    print(f"cve_binaries: downloading {url}", file=sys.stderr)
    try:
        with urllib.request.urlopen(url, timeout=600) as response:
            archive = gzip.decompress(response.read())
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        return initramfs_member(f"{base}-vmlinux-initramfs.elf", "/".join(member))
    if archive:
        return cpio_member(archive, "/".join(member))
    url = f"{base}-default-rootfs.tar.gz"
    print(f"cve_binaries: downloading {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=600) as response:
        tar = tarfile.open(fileobj=io.BytesIO(response.read()))
    return tar.extractfile("./" + "/".join(member)).read()


def initramfs_member(url: str, wanted: str) -> bytes:
    """The bytes of one file of the initramfs that the kernel at `url`
    holds, as an uncompressed `newc` cpio archive."""
    print(f"cve_binaries: downloading {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=600) as response:
        kernel = response.read()
    # The kernel holds the text `070701` too, so the archive starts at the
    # first one that a header of hex digits follows.
    start = re.search(rb"070701[0-9A-Fa-f]{104}", kernel)
    if not start:
        raise FileNotFoundError(f"no initramfs in {url}")
    return cpio_member(kernel[start.start() :], wanted)


def fetch_kmod(path: str) -> bytes:
    """Download a kernel module from the package of its release."""
    # hereticus-openwrt-cve/<release>/<target>-<subtarget>/kmod/<package>/<file>.ko
    _, release, target, _, package, name = path.split("/")
    board, subtarget = target.split("-")
    kmods = f"{MIRROR}/{release}/targets/{board}/{subtarget}/kmods/"
    with urllib.request.urlopen(kmods, timeout=600) as response:
        listing = response.read().decode()
    # The one directory of the kernel the release builds.
    kernel = re.findall(r'href="([0-9][^"]*/)"', listing)[0]
    with urllib.request.urlopen(kmods + kernel, timeout=600) as response:
        listing = response.read().decode()
    ipk = re.findall(rf'href="({re.escape(package)}_[^"]*\.ipk)"', listing)[0]
    print(f"cve_binaries: downloading {kmods}{kernel}{ipk}", file=sys.stderr)
    with urllib.request.urlopen(kmods + kernel + ipk, timeout=600) as response:
        outer = tarfile.open(fileobj=io.BytesIO(response.read()))
    data = outer.extractfile("./data.tar.gz").read()
    inner = tarfile.open(fileobj=io.BytesIO(data))
    member = next(member for member in inner.getmembers() if member.name.endswith("/" + name))
    return inner.extractfile(member).read()


def main() -> int:
    missing_apple = []
    for path, expected in PINNED.items():
        out = CACHE / path
        if out.exists():
            data = out.read_bytes()
        elif path.startswith("hereticus-openwrt-cve/") and "/kmod/" in path:
            data = fetch_kmod(path)
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
