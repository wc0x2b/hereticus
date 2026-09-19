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
