//! Lock the shape of what the command line tool prints for raw MIPS images.
//!
//! The MIPS twin of the raw tests in `cli.rs`. Each image is read with the
//! `--arch` it was built for, at `0x80000000`, the start of KSEG0, where MIPS
//! firmware loads. Run `cargo insta review` to accept a change on purpose.

use std::path::Path;
use std::process::{Command, Output};

use insta_cmd::assert_cmd_snapshot;

/// Where MIPS images load in these tests, and where the MIPS vector tables
/// are linked by `fixtures/build.sh`.
const KSEG0: &str = "0x80000000";

/// The tool under test, with the working directory fixed.
fn hereticus() -> Command {
    let mut command = Command::new(insta_cmd::get_cargo_bin("hereticus"));
    command.current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join(".."));
    command
}

/// The path of a raw image, after checking it was built.
fn raw(name: &str) -> String {
    let path = format!("fixtures/build/raw/{name}.bin");
    assert!(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(&path).exists(),
        "{path} is missing, run `just fixtures` first"
    );
    path
}

/// The tool set up to compare two raw MIPS images at KSEG0.
fn compare(arch: &str, before: &str, after: &str) -> Command {
    let mut command = hereticus();
    command.args(["--progress", "never", "--raw", "--base", KSEG0, "--arch", arch]);
    command.args([raw(before), raw(after)]);
    command
}

fn run(command: &mut Command) -> Output {
    command.output().expect("the tool runs")
}

#[test]
fn compares_little_endian_mips_images() {
    assert_cmd_snapshot!(compare("mips32", "mips-O2-basic", "mips-O2-basic_v2"));
}

#[test]
fn compares_big_endian_mips_images() {
    assert_cmd_snapshot!(compare("mips32-be", "mipsbe-O2-basic", "mipsbe-O2-basic_v2"));
}

#[test]
fn compares_unoptimized_big_endian_mips_images() {
    assert_cmd_snapshot!(compare("mips32-be", "mipsbe-O0-basic", "mipsbe-O0-basic_v2"));
}

/// Two firmware versions, with the changes that touch only a constant shown.
#[test]
fn names_the_kind_of_edit_between_two_mips_firmware_images() {
    assert_cmd_snapshot!(
        compare("mips32-be", "mipsbe-O2-firmware", "mipsbe-O2-firmware_v2").arg("--show-retouched")
    );
}

/// PIC firmware, as a shared object and most shipped MIPS code is built.
#[test]
fn compares_position_independent_mips_firmware_images() {
    assert_cmd_snapshot!(
        compare("mips32-be", "mipsbe-pic-O2-firmware", "mipsbe-pic-O2-firmware_v2")
            .arg("--show-retouched")
    );
}

#[test]
fn reports_every_mips_function_when_asked() {
    assert_cmd_snapshot!(
        compare("mips32-be", "mipsbe-O2-basic", "mipsbe-O2-basic_v2").arg("--all")
    );
}

#[test]
fn sorts_the_mips_report_by_how_much_changed() {
    assert_cmd_snapshot!(
        compare("mips32-be", "mipsbe-O2-firmware", "mipsbe-O2-firmware_v2")
            .args(["--sort", "modified"])
    );
}

#[test]
fn prints_a_compact_mips_report() {
    assert_cmd_snapshot!(
        compare("mips32-be", "mipsbe-O2-firmware", "mipsbe-O2-firmware_v2").args([
            "--show-retouched",
            "--format",
            "compact"
        ])
    );
}

/// A raw function has no name, so it is asked for by the name the report
/// gives it.
#[test]
fn diffs_one_raw_mips_function_at_instruction_level() {
    assert_cmd_snapshot!(
        compare("mips32-be", "mipsbe-O2-basic", "mipsbe-O2-basic_v2")
            .args(["--diff", "sub_80000050"])
    );
}

#[test]
fn diffs_one_little_endian_mips_function_at_instruction_level() {
    assert_cmd_snapshot!(
        compare("mips32", "mips-O2-basic", "mips-O2-basic_v2").args(["--diff", "sub_80000050"])
    );
}

/// A change sets the exit status when a script asks for it.
#[test]
fn a_mips_change_sets_the_exit_status_when_asked() {
    assert_cmd_snapshot!(
        compare("mips32-be", "mipsbe-O2-basic", "mipsbe-O2-basic_v2").arg("--exit-code")
    );
}

#[test]
fn a_mips_image_compared_with_itself_reports_nothing() {
    assert_cmd_snapshot!(
        compare("mips32-be", "mipsbe-O2-firmware", "mipsbe-O2-firmware").arg("--exit-code")
    );
}

/// A base wrong by a little is worth saying so about, in either order.
#[test]
fn warns_about_a_big_endian_mips_base_that_looks_wrong() {
    let mut command = hereticus();
    command.args(["--progress", "never", "--raw", "--base", "0x80000400", "--arch", "mips32-be"]);
    command.args([raw("vectors-mipsbe"), raw("vectors-mipsbe")]);
    assert_cmd_snapshot!(command);
}

#[test]
fn warns_about_a_little_endian_mips_base_that_looks_wrong() {
    let mut command = hereticus();
    command.args(["--progress", "never", "--raw", "--base", "0x80000400", "--arch", "mips32"]);
    command.args([raw("vectors-mips"), raw("vectors-mips")]);
    assert_cmd_snapshot!(command);
}

/// The base a table was linked at draws no warning.
#[test]
fn stays_quiet_about_the_right_mips_base() {
    assert_cmd_snapshot!(compare("mips32-be", "vectors-mipsbe", "vectors-mipsbe"));
}

/// Reading a big-endian image as little endian cannot be detected, so the
/// tool reads nonsense quietly. This records what the user then sees.
#[test]
fn reads_a_mips_image_given_the_wrong_byte_order() {
    assert_cmd_snapshot!(compare("mips32", "mipsbe-O2-basic", "mipsbe-O2-basic_v2"));
}

/// `--arch` means nothing without `--raw`, because an object names its own.
#[test]
fn arch_without_raw_is_refused() {
    assert_cmd_snapshot!(hereticus().args([
        "--arch",
        "mips32-be",
        "fixtures/build/mipsbe-O2/basic.o",
        "fixtures/build/mipsbe-O2/basic_v2.o",
    ]));
}

#[test]
fn an_unknown_arch_is_refused() {
    assert_cmd_snapshot!(hereticus().args([
        "--raw",
        "--base",
        KSEG0,
        "--arch",
        "mips64",
        "fixtures/build/raw/mipsbe-O2-basic.bin",
        "fixtures/build/raw/mipsbe-O2-basic_v2.bin",
    ]));
}

/// The same code in either byte order prints the same report.
#[test]
fn both_byte_orders_print_one_report() {
    for (name, flags) in [
        ("basic", &[][..]),
        ("firmware", &["--show-retouched"][..]),
        ("basic", &["--all"][..]),
        ("basic", &["--diff", "sub_800000a0"][..]),
        ("firmware", &["--format", "compact"][..]),
    ] {
        let v2 = format!("{name}_v2");
        let little = run(
            compare("mips32", &format!("mips-O2-{name}"), &format!("mips-O2-{v2}")).args(flags)
        );
        let big =
            run(compare("mips32-be", &format!("mipsbe-O2-{name}"), &format!("mipsbe-O2-{v2}"))
                .args(flags));

        assert!(little.status.success() && big.status.success(), "{name} {flags:?}");
        assert_eq!(
            String::from_utf8_lossy(&little.stdout),
            String::from_utf8_lossy(&big.stdout),
            "{name} {flags:?}: the byte order changed the report"
        );
    }
}

/// A raw image reports the changes its objects report.
///
/// The object report names each function, and the raw one numbers it by
/// address, so the rows are compared without the two name columns.
#[test]
fn a_raw_mips_report_matches_the_object_report() {
    let object = run(hereticus().args([
        "--progress",
        "never",
        "--ignore-names",
        "--show-retouched",
        "--format",
        "compact",
        "fixtures/build/mipsbe-O2/firmware.o",
        "fixtures/build/mipsbe-O2/firmware_v2.o",
    ]));
    let raw = run(compare("mips32-be", "mipsbe-O2-firmware", "mipsbe-O2-firmware_v2").args([
        "--show-retouched",
        "--format",
        "compact",
    ]));

    let rows = |output: &Output| -> Vec<String> {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|line| {
                let fields: Vec<&str> = line.split('\t').collect();
                [&fields[..1], &fields[3..]].concat().join("\t")
            })
            .collect()
    };

    let raw_rows = rows(&raw);
    assert_eq!(raw_rows.len(), 6, "two matched, two gone, two new");
    assert_eq!(raw_rows, rows(&object));
}

#[test]
fn the_object_report_of_mips_firmware_is_stable() {
    assert_cmd_snapshot!(hereticus().args([
        "--progress",
        "never",
        "--ignore-names",
        "--show-retouched",
        "--format",
        "compact",
        "fixtures/build/mipsbe-O2/firmware.o",
        "fixtures/build/mipsbe-O2/firmware_v2.o",
    ]));
}
