//! Unpacking an OpenWrt image gives the parts `fixtures/firmware.py` takes
//! out of it, byte for byte.
//!
//! The script extracts each part with Python's `lzma` and pins its SHA-256,
//! so equal bytes here prove the Rust unpacking reads every container the
//! tests use as the script does.

use std::path::{Path, PathBuf};

use hereticus::unpack::{Container, unpack};
use rstest::rstest;

fn openwrt() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/openwrt")
}

/// The image of `board` at `release`, as `firmware.py` downloaded it.
fn image(board: &str, release: &str) -> Option<Vec<u8>> {
    let pattern = match board {
        "arm-ex6100v2" => "ipq40xx-generic-netgear_ex6100v2-squashfs-sysupgrade",
        "mipsbe-eap245v3" => "ath79-generic-tplink_eap245-v3-squashfs-sysupgrade",
        "mipsel-r6220" => "ramips-mt7621-netgear_r6220-squashfs-kernel",
        "arm-a385dbap" => "mvebu-cortexa9-marvell_a385-db-ap-squashfs-sysupgrade",
        "mipsbe-vr200" => "lantiq-xrx200-tplink_vr200-squashfs-sysupgrade",
        "mipsel-mt300nv2" => "ramips-mt76x8-glinet_gl-mt300n-v2-squashfs-sysupgrade",
        _ => unreachable!("no such board"),
    };
    std::fs::read(openwrt().join(format!("download/openwrt-{release}-{pattern}.bin"))).ok()
}

/// What `firmware.py` extracted.
fn extracted(board: &str, part: &str, release: &str) -> Vec<u8> {
    let path = openwrt().join(format!("{board}-{part}-{release}.bin"));
    std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{}: {err}, run `just firmware`", path.display()))
}

#[rstest]
#[case::arm_ex6100v2("arm-ex6100v2", Container::ZImage, true)]
#[case::mipsbe_eap245v3("mipsbe-eap245v3", Container::ElfLoader, true)]
#[case::mipsel_r6220("mipsel-r6220", Container::UImageLoader, true)]
#[case::arm_a385dbap("arm-a385dbap", Container::SysupgradeTar, true)]
#[case::mipsbe_vr200("mipsbe-vr200", Container::TpLinkV2, false)]
#[case::mipsel_mt300nv2("mipsel-mt300nv2", Container::UImageKernel, false)]
fn an_image_unpacks_as_the_fixture_script_does(
    #[case] board: &str,
    #[case] container: Container,
    #[case] has_stub: bool,
    #[values("21.02.7", "22.03.2", "22.03.5", "23.05.5")] release: &str,
) {
    let Some(image) = image(board, release) else { return };
    let unpacked = unpack(&image).unwrap_or_else(|err| panic!("{board} {release}: {err}"));
    assert_eq!(unpacked.container, container, "{board} {release}");
    assert!(
        unpacked.kernel.bytes == extracted(board, "kernel", release),
        "{board} {release}: the kernel differs"
    );
    match unpacked.stub {
        Some(stub) => {
            assert!(has_stub, "{board} {release}: a stub where none is expected");
            assert!(
                stub.bytes == extracted(board, "stub", release),
                "{board} {release}: the stub differs"
            );
        }
        None => assert!(!has_stub, "{board} {release}: no stub"),
    }
}

/// A uImage and an ELF loader say where they load.
#[test]
fn a_container_names_where_its_parts_load() {
    let Some(r6220) = image("mipsel-r6220", "22.03.5") else { return };
    assert_eq!(unpack(&r6220).expect("unpacks").stub.and_then(|stub| stub.load), Some(0x8000_1000));
    let Some(mt300) = image("mipsel-mt300nv2", "22.03.5") else { return };
    assert_eq!(unpack(&mt300).expect("unpacks").kernel.load, Some(0x8000_0000));
}
