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
fn hereticus() -> Command {
    let mut command = Command::new(insta_cmd::get_cargo_bin("hereticus"));
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
        hereticus().args(["fixtures/build/O2/basic.o", "fixtures/build/O2/basic_v2.o"])
    );
}

/// The `TOUCHED` column names what kind of code a large rewrite changed.
///
/// Comparing two optimization levels rewrites whole functions, which is where
/// the column earns its place: the `CHANGE` column can only say `changed`.
#[test]
fn names_the_kind_of_code_a_rewrite_touched() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(
        hereticus().args(["fixtures/build/O1/basic.o", "fixtures/build/Os/basic.o"])
    );
}

/// Two versions of one firmware, built the same way.
///
/// This is the shape a reader actually compares: the same source at the same
/// optimization level, one release apart. Each function changed in one known
/// way, so the `TOUCHED` column can be checked against a real answer rather
/// than against whatever the compiler happened to do.
#[test]
fn names_the_kind_of_edit_between_two_firmware_versions() {
    if !fixture("O2", "firmware").exists() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(hereticus().args([
        "--show-retouched",
        "fixtures/build/O2/firmware.o",
        "fixtures/build/O2/firmware_v2.o",
    ]));
}

/// The added authentication call is reported at every optimization level.
///
/// The counts around it move with the optimizer, but `check_header` gains a
/// call to `crypto_verify` in the source, so the column must say so whatever
/// the compiler did with the code around it.
#[test]
fn an_added_call_is_reported_at_every_optimization_level() {
    if !fixture("O2", "firmware").exists() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    for level in ["O0", "O1", "O2", "Os"] {
        let output = hereticus()
            .args([
                format!("fixtures/build/{level}/firmware.o"),
                format!("fixtures/build/{level}/firmware_v2.o"),
            ])
            .output()
            .expect("hereticus runs");
        let report = String::from_utf8(output.stdout).expect("the report is text");

        let row = report
            .lines()
            .find(|line| line.contains("check_header"))
            .unwrap_or_else(|| panic!("at -{level} the report names check_header:\n{report}"));
        assert!(row.contains("1 call"), "at -{level} the added call is named, got:\n{row}");

        // The control must stay out of the report at every level.
        assert!(
            !report.contains("checksum"),
            "at -{level} the untouched function is reported as changed:\n{report}"
        );
    }
}

/// The browser needs a terminal, and says so before the comparison runs.
#[test]
fn the_tui_stops_without_a_terminal() {
    assert_cmd_snapshot!(hereticus().args(["--tui", "missing.o", "missing_v2.o"]));
}

/// The browser shows the report, so it takes no other way to print one.
#[test]
fn the_tui_takes_no_other_output() {
    assert_cmd_snapshot!(hereticus().args(["--tui", "--format", "json", "a.o", "b.o"]));
}

#[test]
fn reports_every_function_when_asked() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(hereticus().args([
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

    assert_cmd_snapshot!(hereticus().args([
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

    assert_cmd_snapshot!(hereticus().args([
        "--format",
        "compact",
        "fixtures/build/O2/basic.o",
        "fixtures/build/O2/basic_v2.o",
    ]));
}

/// The markdown format is for documents, so its table must stay put.
#[test]
fn markdown_format_is_stable() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(hereticus().args([
        "--format",
        "markdown",
        "--ignore-names",
        "fixtures/build/O1/basic.o",
        "fixtures/build/O2/basic.o",
    ]));
}

/// The JSON format is for tools, so its fields must stay put.
#[test]
fn json_format_is_stable() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(hereticus().args([
        "--format",
        "json",
        "--ignore-names",
        "fixtures/build/O1/basic.o",
        "fixtures/build/O2/basic.o",
    ]));
}

/// The IL view shows a diff as IL statements.
#[test]
fn the_il_view_shows_statements() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(hereticus().args([
        "--view",
        "il",
        "--diff-all",
        "fixtures/build/O2/firmware.o",
        "fixtures/build/O2/firmware_v2.o",
    ]));
}

/// The JSON report parses, and its totals agree with what it lists.
#[test]
fn the_json_report_parses_and_adds_up() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    let output = hereticus()
        .args([
            "--format",
            "json",
            "--all",
            "--ignore-names",
            "fixtures/build/O1/basic.o",
            "fixtures/build/O2/basic.o",
        ])
        .output()
        .expect("hereticus runs");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the report is JSON");
    let count = |key: &str| report[key].as_array().expect("a list").len();
    let totals = &report["totals"];
    assert_eq!(totals["matched"].as_u64(), Some(count("pairs") as u64), "--all lists every pair");
    assert_eq!(totals["gone"].as_u64(), Some(count("gone") as u64));
    assert_eq!(totals["new"].as_u64(), Some(count("new") as u64));
    let first = &report["pairs"][0];
    assert!(first["before"]["name"].is_string() && first["after"]["address"].is_u64());
}

/// Matching without names is the stripped-binary case.
#[test]
fn reports_functions_that_only_one_side_has() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(hereticus().args([
        "--ignore-names",
        "fixtures/build/O0/basic.o",
        "fixtures/build/O2/basic.o",
    ]));
}

#[test]
fn comparing_a_binary_with_itself_reports_nothing() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(
        hereticus().args(["fixtures/build/O2/basic.o", "fixtures/build/O2/basic.o"])
    );
}

/// The most-rewritten function comes first with `--sort modified`.
#[test]
fn sorts_the_report_by_how_much_changed() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(hereticus().args([
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

    assert_cmd_snapshot!(hereticus().args([
        "--color",
        "never",
        "--diff",
        "mul_by_constant",
        "fixtures/build/O2/basic.o",
        "fixtures/build/O2/basic_v2.o",
    ]));
}

/// Every changed function prints its diff, in the order of the report.
#[test]
fn diffs_every_changed_function() {
    if !fixture("O2", "firmware").exists() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(hereticus().args([
        "--color",
        "never",
        "--diff-all",
        "fixtures/build/O2/firmware.o",
        "fixtures/build/O2/firmware_v2.o",
    ]));
}

/// One function or all of them, not both.
#[test]
fn diff_all_and_one_diff_are_refused_together() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    let output = hereticus()
        .args([
            "--diff-all",
            "--diff",
            "mul_by_constant",
            "fixtures/build/O2/basic.o",
            "fixtures/build/O2/basic_v2.o",
        ])
        .output()
        .expect("the binary runs");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be used with"));
}

/// A name the earlier binary does not hold is refused with a clear message.
#[test]
fn diff_of_an_unknown_function_is_refused() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(hereticus().args([
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

    assert_cmd_snapshot!(hereticus().args([
        "--ignore-names",
        "--near-miss",
        "0.0",
        "fixtures/build/O0/basic.o",
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

    assert_cmd_snapshot!(hereticus().args([
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
    assert_cmd_snapshot!(hereticus().args([
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

    assert_cmd_snapshot!(hereticus().args([
        "--raw",
        "--base",
        "0x08000400",
        "fixtures/build/raw/vectors.bin",
        "fixtures/build/raw/vectors.bin",
    ]));
}

/// zlib built as Cortex-M firmware and linked into flash at `0x08000000`,
/// as `just backports` writes its flash image.
const FIRMWARE: &str = "fixtures/build/backports/zlib-before/cortex-m3-O2/lib.bin";
const FIRMWARE_FIXED: &str = "fixtures/build/backports/zlib-after/cortex-m3-O2/lib.bin";

fn firmware_present() -> bool {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(FIRMWARE).exists()
}

/// The table gives the evidence for each base, and the line after it the
/// base that stands out.
#[test]
fn finds_the_base_of_firmware() {
    if !firmware_present() {
        eprintln!("skipped: run `just backports` first");
        return;
    }
    assert_cmd_snapshot!(hereticus().args(["--find-base", "--raw", "--arch", "thumb2", FIRMWARE]));
}

#[test]
fn the_bases_parse_as_json() {
    if !firmware_present() {
        eprintln!("skipped: run `just backports` first");
        return;
    }
    let output = hereticus()
        .args(["--find-base", "--raw", "--arch", "thumb2", "--format", "json", FIRMWARE])
        .output()
        .expect("the tool runs");
    let found: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(found["base"], 0x0800_0000);
    assert_eq!(found["candidates"][0]["base"], 0x0800_0000);
    assert!(found["candidates"][0]["evidence"].as_f64().is_some_and(|evidence| evidence > 0.0));
}

/// Where no base stands out, the tool says so and names none.
#[test]
fn finds_no_base_in_noise() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }
    let output = hereticus()
        .args(["--find-base", "--raw", "--format", "json", "fixtures/build/raw/O2-basic.bin"])
        .output()
        .expect("the tool runs");
    let found: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(found["base"], serde_json::Value::Null);
}

/// `--base auto` takes the base that each image shows, and says which.
#[test]
fn compares_firmware_at_the_base_it_shows() {
    if !firmware_present() {
        eprintln!("skipped: run `just backports` first");
        return;
    }
    let auto = hereticus()
        .args(["--raw", "--arch", "thumb2", "--base", "auto", "--format", "compact"])
        .args([FIRMWARE, FIRMWARE_FIXED])
        .output()
        .expect("the tool runs");
    let given = hereticus()
        .args(["--raw", "--arch", "thumb2", "--base", "0x08000000", "--format", "compact"])
        .args([FIRMWARE, FIRMWARE_FIXED])
        .output()
        .expect("the tool runs");
    assert_eq!(String::from_utf8_lossy(&auto.stdout), String::from_utf8_lossy(&given.stdout));
    let said = String::from_utf8_lossy(&auto.stderr);
    assert!(said.contains(&format!("{FIRMWARE} loads at 0x8000000")), "{said}");
}

/// `--base auto` stops where no base stands out, as a missing base does.
#[test]
fn auto_stops_where_no_base_stands_out() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }
    assert_cmd_snapshot!(hereticus().args([
        "--raw",
        "--base",
        "auto",
        "fixtures/build/raw/O2-basic.bin",
        "fixtures/build/raw/O2-basic_v2.bin",
    ]));
}

/// The search reads one raw image, so it takes no second one and no base.
#[test]
fn the_base_search_takes_one_raw_image() {
    for args in [
        &["--find-base", "a.bin"][..],
        &["--find-base", "--raw", "a.bin", "b.bin"],
        &["--find-base", "--raw", "--base", "0x1000", "a.bin"],
    ] {
        let output = hereticus().args(args).output().expect("the tool runs");
        assert_eq!(output.status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn explains_a_file_it_cannot_find() {
    assert_cmd_snapshot!(hereticus().args(["does-not-exist.o", "fixtures/build/O2/basic.o"]));
}

#[test]
fn explains_a_file_that_is_not_an_object() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(hereticus().args(["fixtures/src/basic.c", "fixtures/build/O2/basic.o"]));
}

#[test]
fn rejects_a_threshold_outside_its_range() {
    assert_cmd_snapshot!(hereticus().args([
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

    let quiet = hereticus()
        .args(["--progress", "never", "fixtures/build/O2/basic.o", "fixtures/build/O2/basic_v2.o"])
        .output()
        .expect("the tool runs");

    let loud = hereticus()
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

    let plain = hereticus()
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

    let painted = hereticus()
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

    let plain = hereticus()
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

/// A function gone or new names the function of the other side that sits in
/// its place. A stripped library keeps the names of what it exports, and
/// these say whether the place is right.
#[test]
fn a_function_gone_names_the_one_in_its_place() {
    let backport = |variant: &str, level: &str| {
        format!("fixtures/build/backports/zlib-{variant}/arm-{level}/lib-stripped.so")
    };
    let (before, after) = (backport("before", "O1"), backport("after", "O2"));
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    if !root.join(&before).exists() {
        eprintln!("skipped: run `just backports` first");
        return;
    }

    let text = hereticus().args(["--ignore-names", &before, &after]).output().expect("runs");
    let text = String::from_utf8(text.stdout).expect("the report is text");
    assert!(text.contains("inflateInit_: gone, same place as inflateInit_\n"), "{text}");
    assert!(
        text.contains("inflateInit_: new, closest _tr_init at 0.26, same place as inflateInit_\n"),
        "{text}"
    );

    let json = hereticus()
        .args(["--format", "json", "--ignore-names", &before, &after])
        .output()
        .expect("runs");
    let report: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("the report is JSON");
    let gone = report["gone"].as_array().expect("a list");
    let init = gone.iter().find(|gone| gone["function"]["name"] == "inflateInit_").expect("listed");
    assert_eq!(init["in_place"]["name"], "inflateInit_");
    assert!(gone.iter().all(|gone| gone.get("in_place").is_some()), "every row holds the field");
}

/// `--functions` lists one binary as a table for a person to read.
#[test]
fn lists_the_functions_of_one_binary() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(hereticus().args(["--functions", "fixtures/build/O2/basic.o"]));
}

/// A reader that closes the pipe early, as `head` does, ends the tool with
/// no panic.
#[cfg(unix)]
#[test]
fn a_closed_pipe_ends_the_tool_quietly() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;

    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    // The reading end closes before the tool starts, so its first write
    // finds no reader.
    let (reader, writer) = std::io::pipe().expect("a pipe opens");
    drop(reader);
    let output = hereticus()
        .args(["--functions", "fixtures/build/O2/basic.o"])
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .expect("the tool runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
    // `SIGPIPE` is 13 on every Unix.
    assert_eq!(output.status.signal(), Some(13), "{:?}", output.status);
}

/// The JSON listing is for tools, as a Ghidra script, so its fields must stay
/// put.
#[test]
fn the_json_function_listing_is_stable() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    assert_cmd_snapshot!(hereticus().args([
        "--functions",
        "--format",
        "json",
        "fixtures/build/O2/basic.o",
    ]));
}

/// The JSON listing parses, and its functions are in address order and do
/// not overlap, so a tool can make one function at each address.
#[test]
fn the_json_function_listing_parses_in_address_order() {
    if !fixtures_present() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    let output = hereticus()
        .args(["--functions", "--format", "json", "fixtures/build/O2/firmware.o"])
        .output()
        .expect("hereticus runs");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let listing: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the listing is JSON");
    assert_eq!(listing["isa"], "arm32");
    assert_eq!(listing["found_by"], "symbols");
    let functions = listing["functions"].as_array().expect("a list");
    assert!(!functions.is_empty());
    let spans: Vec<(u64, u64)> = functions
        .iter()
        .map(|function| {
            assert!(function["name"].is_string());
            assert_eq!(function["holds"], "code");
            let address = function["address"].as_u64().expect("a number");
            (address, address + function["size"].as_u64().expect("a number"))
        })
        .collect();
    for pair in spans.windows(2) {
        assert!(pair[0].1 <= pair[1].0, "{pair:x?} overlap or are out of order");
    }
}

/// `--functions` reads one binary, so a second is a mistake to report.
#[test]
fn listing_functions_rejects_a_second_binary() {
    assert_cmd_snapshot!(hereticus().args(["--functions", "a.o", "b.o"]));
}

/// A comparison still needs two binaries.
#[test]
fn a_comparison_needs_a_second_binary() {
    assert_cmd_snapshot!(hereticus().arg("a.o"));
}
