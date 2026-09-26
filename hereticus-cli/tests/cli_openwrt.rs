//! Lock what the command line tool prints for real OpenWrt firmware.
//!
//! Each test compares the kernel decompressor stub of 22.03.2 with that of
//! 22.03.5 for one board, as the README example does. `just firmware` fetches
//! and pins the files. Run `cargo insta review` to accept a change on purpose.

use std::path::Path;
use std::process::Command;

use insta_cmd::assert_cmd_snapshot;

/// The tool under test, with the working directory fixed.
fn hereticus() -> Command {
    let mut command = Command::new(insta_cmd::get_cargo_bin("hereticus"));
    command.current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join(".."));
    command
}

/// The tool set up to compare the stubs of one board.
fn compare_stubs(board: &str, arch: &str, base: &str) -> Command {
    let file = |release: &str| format!("fixtures/build/openwrt/{board}-stub-{release}.bin");
    for release in ["22.03.2", "22.03.5"] {
        assert!(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(file(release)).exists(),
            "{} is missing, run `just firmware` first",
            file(release)
        );
    }

    let mut command = hereticus();
    command.args(["--progress", "never", "--raw", "--base", base, "--arch", arch]);
    command.args([file("22.03.2"), file("22.03.5")]);
    command
}

/// The README example: the ARM zImage stub of the Netgear EX6100v2.
#[test]
fn compares_the_arm_stubs_of_two_openwrt_releases() {
    assert_cmd_snapshot!(compare_stubs("arm-ex6100v2", "arm32", "0x80208000"));
}

#[test]
fn lists_the_retouched_arm_stub_functions() {
    assert_cmd_snapshot!(
        compare_stubs("arm-ex6100v2", "arm32", "0x80208000").arg("--show-retouched")
    );
}

#[test]
fn diffs_one_arm_stub_function() {
    assert_cmd_snapshot!(
        compare_stubs("arm-ex6100v2", "arm32", "0x80208000").args(["--diff", "sub_802082bc"])
    );
}

/// The big-endian MIPS lzma-loader of the TP-Link EAP245 v3.
#[test]
fn compares_the_big_endian_mips_stubs_of_two_openwrt_releases() {
    assert_cmd_snapshot!(
        compare_stubs("mipsbe-eap245v3", "mips32-be", "0x80060000").arg("--show-retouched")
    );
}

#[test]
fn diffs_one_big_endian_mips_stub_function() {
    assert_cmd_snapshot!(
        compare_stubs("mipsbe-eap245v3", "mips32-be", "0x80060000")
            .args(["--diff", "sub_8006005c"])
    );
}

/// The little-endian MIPS lzma-loader of the Netgear R6220.
#[test]
fn compares_the_little_endian_mips_stubs_of_two_openwrt_releases() {
    assert_cmd_snapshot!(
        compare_stubs("mipsel-r6220", "mips32", "0x80001000").arg("--show-retouched")
    );
}

#[test]
fn diffs_one_little_endian_mips_stub_function() {
    assert_cmd_snapshot!(
        compare_stubs("mipsel-r6220", "mips32", "0x80001000").args(["--diff", "sub_80001044"])
    );
}

/// Every changed stub is reported, so `--exit-code` fails for each board.
#[test]
fn a_changed_stub_sets_the_exit_status() {
    for (board, arch, base) in [
        ("arm-ex6100v2", "arm32", "0x80208000"),
        ("mipsbe-eap245v3", "mips32-be", "0x80060000"),
        ("mipsel-r6220", "mips32", "0x80001000"),
    ] {
        let output = compare_stubs(board, arch, base)
            .args(["--show-retouched", "--exit-code"])
            .output()
            .expect("the tool runs");
        assert_eq!(output.status.code(), Some(1), "{board}");
    }
}
