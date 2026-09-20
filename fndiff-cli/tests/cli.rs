//! Lock the shape of what the command line tool prints.
//!
//! These are snapshot tests. They do not judge whether the output is right,
//! only that it has not changed without someone meaning it to. Run
//! `cargo insta review` to accept a change on purpose.

use std::path::{Path, PathBuf};
use std::process::Command;

use insta_cmd::assert_cmd_snapshot;

fn fixture(level: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/build")
        .join(level)
        .join(format!("{name}.o"))
}

/// The tool under test, with the working directory fixed.
///
/// Paths appear in error messages, so they must not change with where the
/// test ran from.
fn fndiff() -> Command {
    let mut command = Command::new(insta_cmd::get_cargo_bin("fndiff"));
    command.current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join(".."));
    command
}

fn fixtures_present() -> bool {
    fixture("O2", "basic").exists()
}

#[test]
fn reports_the_functions_that_changed() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(
        fndiff().args(["fixtures/build/O2/basic.o", "fixtures/build/O2/basic_v2.o"])
    );
}

#[test]
fn reports_every_function_when_asked() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(fndiff().args([
        "--all",
        "fixtures/build/O2/basic.o",
        "fixtures/build/O2/basic_v2.o"
    ]));
}

/// Functions that only changed a constant are listed when asked for.
///
/// The default report holds these back, so this is the only place the edited
/// constant in `mul_by_constant` — and its inlined copy in `call_chain` — is
/// still visible end to end.
#[test]
fn lists_retouched_functions_when_asked() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(fndiff().args([
        "--show-retouched",
        "fixtures/build/O2/basic.o",
        "fixtures/build/O2/basic_v2.o"
    ]));
}

/// The compact format is for scripts, so its columns must stay put.
#[test]
fn compact_format_is_stable() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(fndiff().args([
        "--format",
        "compact",
        "fixtures/build/O2/basic.o",
        "fixtures/build/O2/basic_v2.o",
    ]));
}

/// Matching without names is the stripped-binary case.
#[test]
fn reports_functions_that_only_one_side_has() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(fndiff().args([
        "--ignore-names",
        "fixtures/build/O1/basic.o",
        "fixtures/build/O2/basic.o",
    ]));
}

#[test]
fn comparing_a_binary_with_itself_reports_nothing() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(fndiff().args(["fixtures/build/O2/basic.o", "fixtures/build/O2/basic.o"]));
}

/// The most-rewritten function comes first with `--sort modified`.
#[test]
fn sorts_the_report_by_how_much_changed() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(fndiff().args([
        "--all",
        "--sort",
        "modified",
        "fixtures/build/O2/basic.o",
        "fixtures/build/O2/basic_v2.o",
    ]));
}

/// A changed constant shows as one line, with the old and new value.
#[test]
fn diffs_one_function_at_instruction_level() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(fndiff().args([
        "--color",
        "never",
        "--diff",
        "mul_by_constant",
        "fixtures/build/O2/basic.o",
        "fixtures/build/O2/basic_v2.o",
    ]));
}

/// A name the earlier binary does not hold is refused with a clear message.
#[test]
fn diff_of_an_unknown_function_is_refused() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(fndiff().args([
        "--diff",
        "no_such_function",
        "fixtures/build/O2/basic.o",
        "fixtures/build/O2/basic_v2.o",
    ]));
}

/// Lowering the floor shows the weaker guesses as well.
#[test]
fn near_miss_floor_controls_what_is_shown() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(fndiff().args([
        "--ignore-names",
        "--near-miss",
        "0.0",
        "fixtures/build/O1/basic.o",
        "fixtures/build/O2/basic.o",
    ]));
}

/// A firmware image with no container format.
#[test]
fn compares_raw_images() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(fndiff().args([
        "--raw",
        "--base",
        "0x0",
        "fixtures/build/raw/O2-basic.bin",
        "fixtures/build/raw/O2-basic_v2.bin",
    ]));
}

/// A raw image needs a load address, and there is no safe default.
#[test]
fn raw_without_a_base_is_refused() {
    assert_cmd_snapshot!(fndiff().args([
        "--raw",
        "fixtures/build/raw/O2-basic.bin",
        "fixtures/build/raw/O2-basic_v2.bin",
    ]));
}

/// A base that is wrong by a little is worth saying so about.
#[test]
fn warns_about_a_base_that_looks_wrong() {
    if !Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/raw/vectors.bin").exists() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(fndiff().args([
        "--raw",
        "--base",
        "0x08000400",
        "fixtures/build/raw/vectors.bin",
        "fixtures/build/raw/vectors.bin",
    ]));
}

#[test]
fn explains_a_file_it_cannot_find() {
    assert_cmd_snapshot!(fndiff().args(["does-not-exist.o", "fixtures/build/O2/basic.o"]));
}

#[test]
fn explains_a_file_that_is_not_an_object() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(fndiff().args(["fixtures/src/basic.c", "fixtures/build/O2/basic.o"]));
}

#[test]
fn rejects_a_threshold_outside_its_range() {
    assert_cmd_snapshot!(fndiff().args([
        "--threshold",
        "2.0",
        "fixtures/build/O2/basic.o",
        "fixtures/build/O2/basic.o",
    ]));
}

/// The bar must never reach standard output.
///
/// A report that a script reads goes to standard output. Drawing a bar there
/// would corrupt it, so the bar goes to standard error. `--progress always`
/// draws the bar even when nothing is a terminal, which is what makes this
/// testable at all.
#[test]
fn a_forced_progress_bar_stays_off_standard_output() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    let quiet = fndiff()
        .args(["--progress", "never", "fixtures/build/O2/basic.o", "fixtures/build/O2/basic_v2.o"])
        .output()
        .expect("the tool runs");

    let loud = fndiff()
        .args(["--progress", "always", "fixtures/build/O2/basic.o", "fixtures/build/O2/basic_v2.o"])
        .output()
        .expect("the tool runs");

    assert_eq!(
        String::from_utf8_lossy(&quiet.stdout),
        String::from_utf8_lossy(&loud.stdout),
        "the report must not change when a bar is drawn"
    );
    assert!(!loud.stderr.is_empty(), "a forced bar writes something to standard error");
}

/// A redirected report must stay plain text.
///
/// The tests capture standard output through a pipe, so `--color auto` must
/// decide against color here. If it did not, every escape code would land in
/// the snapshots and in any report a user redirects to a file.
#[test]
fn a_redirected_report_carries_no_color() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    let plain = fndiff()
        .args(["--progress", "never", "fixtures/build/O2/basic.o", "fixtures/build/O2/basic_v2.o"])
        .output()
        .expect("the tool runs");

    assert!(
        !plain.stdout.contains(&ESCAPE),
        "a report that is not going to a terminal must hold no escape codes"
    );
}

/// `--color always` overrides the test for a terminal.
///
/// Color is the only difference: the same rows, in the same order, with the
/// same values.
#[test]
fn forced_color_paints_the_report() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    let painted = fndiff()
        .args([
            "--progress",
            "never",
            "--color",
            "always",
            "fixtures/build/O2/basic.o",
            "fixtures/build/O2/basic_v2.o",
        ])
        .output()
        .expect("the tool runs");

    assert!(painted.stdout.contains(&ESCAPE), "a forced color report holds escape codes");

    let plain = fndiff()
        .args([
            "--progress",
            "never",
            "--color",
            "never",
            "fixtures/build/O2/basic.o",
            "fixtures/build/O2/basic_v2.o",
        ])
        .output()
        .expect("the tool runs");

    assert!(!plain.stdout.contains(&ESCAPE), "`--color never` holds none");
    assert_eq!(
        strip_color(&painted.stdout),
        String::from_utf8_lossy(&plain.stdout),
        "color must not change what the report says"
    );
}

/// The byte that opens an ANSI escape sequence.
const ESCAPE: u8 = 0x1b;

/// Remove ANSI escape sequences, so two reports compare on their text alone.
///
/// Every sequence the report writes is a Select Graphic Rendition one, which
/// ends at `m`.
fn strip_color(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut plain = String::with_capacity(text.len());
    let mut rest = text.as_ref();

    while let Some(start) = rest.find(char::from(ESCAPE)) {
        plain.push_str(&rest[..start]);
        match rest[start..].find('m') {
            Some(end) => rest = &rest[start + end + 1..],
            None => return plain,
        }
    }
    plain.push_str(rest);
    plain
}
