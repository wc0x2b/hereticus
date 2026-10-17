//! Lock what the command line tool prints for real OpenWrt firmware.
//!
//! Each test compares the kernel decompressor stub of 22.03.2 with that of
//! 22.03.5 for one board, as the example in the book does. `just firmware` fetches
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

/// The example in the book: the ARM zImage stub of the Netgear EX6100v2.
///
/// `book/src/examples.md` shows this output, and `tests/docs_output.rs` checks that it
/// agrees.
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
        compare_stubs("arm-ex6100v2", "arm32", "0x80208000").args(["--diff", "sub_80208b78"])
    );
}

/// `--unpack` takes the stub out of the image as downloaded, so the report
/// is the one the extracted stub gives.
#[test]
fn unpacks_the_stub_of_a_downloaded_image() {
    let image = |release: &str| {
        format!(
            "fixtures/build/openwrt/download/openwrt-{release}-ipq40xx-generic-netgear_ex6100v2-squashfs-sysupgrade.bin"
        )
    };
    if !Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(image("22.03.2")).exists() {
        eprintln!("skipped: run `just firmware` first");
        return;
    }
    let unpacked = hereticus()
        .args(["--progress", "never", "--raw", "--base", "0x80208000", "--arch", "arm32"])
        .args(["--unpack", "stub", &image("22.03.2"), &image("22.03.5")])
        .output()
        .expect("the tool runs");
    let extracted =
        compare_stubs("arm-ex6100v2", "arm32", "0x80208000").output().expect("the tool runs");
    assert!(unpacked.status.success(), "{}", String::from_utf8_lossy(&unpacked.stderr));
    assert_eq!(
        String::from_utf8_lossy(&unpacked.stdout),
        String::from_utf8_lossy(&extracted.stdout)
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

/// The tables and zero fill after a MIPS kernel's code are hidden as data,
/// and `--show-data` lists every one of them.
#[test]
fn slow_hides_the_data_regions_of_a_mips_kernel() {
    let file =
        |release: &str| format!("fixtures/build/openwrt/mipsbe-eap245v3-kernel-{release}.bin");
    let run = |extra: &[&str]| {
        let output = hereticus()
            .args(["--progress", "never", "--raw", "--base", "0x80060000", "--arch", "mips32-be"])
            .args(extra)
            .args([file("22.03.2"), file("22.03.5")])
            .output()
            .expect("the tool runs");
        String::from_utf8(output.stdout).expect("the report is text")
    };

    let hidden = run(&[]);
    assert!(!hidden.contains("changed data"), "no data row by default");
    assert!(hidden.contains("5 data regions changed, hidden. Use --show-data to list them."));

    let shown = run(&["--show-data"]);
    assert_eq!(shown.matches("changed data").count(), 5, "every hidden region is listed");
    assert!(!shown.contains("data regions changed, hidden"));
}

/// Without `--base`, the tool says where a MIPS kernel loads, from its calls,
/// and still refuses to guess.
#[test]
fn slow_suggests_a_base_for_a_mips_kernel() {
    let output = hereticus()
        .args(["--progress", "never", "--raw", "--arch", "mips32-be"])
        .args(["fixtures/build/openwrt/mipsbe-vr200-kernel-22.03.2.bin"; 2])
        .output()
        .expect("the tool runs");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("the error is text");
    assert!(
        stderr.contains(
            "--raw needs --base, because a raw image does not say where it loads. Its calls \
             show that it loads at --base 0x80002000"
        ),
        "got {stderr}"
    );
}

/// A base a page off draws a warning that names the right one.
#[test]
fn slow_warns_about_a_mips_kernel_base_a_page_off() {
    let output = hereticus()
        .args(["--progress", "never", "--raw", "--base", "0x80003000", "--arch", "mips32-be"])
        .args(["fixtures/build/openwrt/mipsbe-vr200-kernel-22.03.2.bin"; 2])
        .output()
        .expect("the tool runs");

    let stderr = String::from_utf8(output.stderr).expect("the warning is text");
    assert!(stderr.contains("may not load at 0x80003000"), "got {stderr}");
    assert!(stderr.contains("58113 do at 0x80002000"), "got {stderr}");
}

/// Across a major version, data regions go as well as change. They are
/// hidden with the changed ones, and `--show-data` lists each.
#[test]
fn slow_hides_the_data_regions_that_go_or_come() {
    let file =
        |release: &str| format!("fixtures/build/openwrt/mipsbe-eap245v3-kernel-{release}.bin");
    let run = |extra: &[&str]| {
        let output = hereticus()
            .args(["--progress", "never", "--raw", "--base", "0x80060000", "--arch", "mips32-be"])
            .args(extra)
            .args([file("21.02.7"), file("22.03.2")])
            .output()
            .expect("the tool runs");
        String::from_utf8(output.stdout).expect("the report is text")
    };

    let hidden = run(&[]);
    assert!(!hidden.contains("gone data") && !hidden.contains("new data"));
    assert!(hidden.contains("6 data regions changed, hidden. Use --show-data to list them."));

    let shown = run(&["--show-data"]);
    let listed =
        ["changed data", ": gone data", ": new data"].map(|word| shown.matches(word).count());
    assert_eq!(listed, [5, 1, 0], "changed, gone and new data regions");
}

/// `--functions` on a raw stub lists what the scan recovered, and marks the
/// tables after the code as data, so a tool does not make functions there.
#[test]
fn lists_the_functions_a_scan_recovers_from_a_raw_stub() {
    let stub = "fixtures/build/openwrt/arm-ex6100v2-stub-22.03.2.bin";
    if !Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(stub).exists() {
        eprintln!("skipped: run `just firmware` first");
        return;
    }

    let output = hereticus()
        .args(["--raw", "--base", "0x80208000", "--arch", "arm32"])
        .args(["--functions", "--format", "json", stub])
        .output()
        .expect("the tool runs");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let listing: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the listing is JSON");
    assert_eq!(listing["found_by"], "scanning");
    let functions = listing["functions"].as_array().expect("a list");
    assert_eq!(functions[0]["address"].as_u64(), Some(0x8020_8000), "the scan starts at the base");
    assert!(functions.iter().any(|function| function["holds"] == "code"));
}
