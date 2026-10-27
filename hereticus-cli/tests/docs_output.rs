//! Keep the output the docs show in step with what the tool prints.
//!
//! The docs mark each shown output with the arguments that make it, and
//! close it:
//!
//! ```text
//! <!-- output: --diff mul_by_constant fixtures/build/O2/basic.o fixtures/build/O2/basic_v2.o -->
//! ...
//! <!-- end output -->
//! ```
//!
//! The text between the two, without code fences and the `$ ` lines of a
//! shown command, must appear as one run in what the tool prints with those
//! arguments, run from the root of the repository. The docs may show a part
//! of the output. An argument that starts with `~/` names a file under the
//! home folder: the binaries of the reports, which `just truth` fetches to
//! `~/.cache`. `just quick-test` checks each report whose binaries are
//! there, but for the few in [`SLOW_REPORTS`], and `just test` checks all.
//!
//! `just docs-output` writes what the tool prints into each output that no
//! longer agrees, where only the lines of the jumps at the left, the indent
//! or the spaces changed. Any other change it names, for a person to choose
//! the part to show.

use std::path::{Path, PathBuf};
use std::process::Command;

const OUTPUT_START: &str = "<!-- output: ";
const OUTPUT_END: &str = "<!-- end output -->";

/// The reports whose outputs take too long for `just quick-test`. The fix
/// of CVE-2021-30883 is in an iPhone kernelcache, and each of its two
/// outputs takes 45 seconds, where the outputs of all other reports take
/// 2 seconds.
const SLOW_REPORTS: &[&str] = &["cve-2021-30883.md"];

/// What a check does with an output that names a binary of `~/.cache` that
/// is not there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Missing {
    /// Leave the output out, and say so: `just quick-test` runs where the
    /// binaries of the reports were never fetched.
    Skip,
    /// Fail: `just test` fetches each binary first.
    Fail,
}

/// What a check does with an output that does not agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Fail.
    Check,
    /// Write what the tool prints into the doc, where it can.
    Update,
}

impl Mode {
    /// `Update` where `DOCS_OUTPUT_UPDATE` is set, as `just docs-output`
    /// sets it.
    fn from_env() -> Self {
        match std::env::var_os("DOCS_OUTPUT_UPDATE") {
            Some(_) => Self::Update,
            None => Self::Check,
        }
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// The Markdown files of the folders `dirs` of the repository.
fn markdown_in(dirs: &[&str]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for dir in dirs {
        for entry in std::fs::read_dir(root().join(dir)).expect("a docs folder").flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|extension| extension == "md") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").expect("HOME is set"))
}

/// An argument of a marker, with a leading `~/` made the home folder.
fn expand(arg: &str) -> String {
    match arg.strip_prefix("~/") {
        Some(rest) => home().join(rest).display().to_string(),
        None => arg.to_owned(),
    }
}

/// An output a doc shows, and the arguments that make it.
#[derive(Debug, PartialEq)]
struct Shown {
    line: usize,
    args: Vec<String>,
    text: String,
    /// Where the body, between the marker and its end, sits in the doc.
    body: core::ops::Range<usize>,
}

/// Whether `at` is inside a fenced code block of `text`, which shows a
/// marker and does not use it.
fn in_code_block(text: &str, at: usize) -> bool {
    text[..at].lines().filter(|line| line.trim_start().starts_with("```")).count() % 2 == 1
}

/// Every marked output of `doc`, or the first marker that is malformed.
fn shown(doc: &str) -> Result<Vec<Shown>, String> {
    let mut found = Vec::new();
    for (start, _) in doc.match_indices(OUTPUT_START) {
        if in_code_block(doc, start) {
            continue;
        }
        let line = doc[..start].matches('\n').count() + 1;
        let rest = &doc[start + OUTPUT_START.len()..];
        let args_end =
            rest.find("-->").ok_or_else(|| format!("line {line}: the marker has no `-->`"))?;
        let args: Vec<String> = rest[..args_end].split_whitespace().map(str::to_owned).collect();
        if args.is_empty() {
            return Err(format!("line {line}: the marker names no arguments"));
        }
        let body_start = start + OUTPUT_START.len() + args_end + "-->".len();
        let body = &rest[args_end + "-->".len()..];
        let body_end = body
            .find(OUTPUT_END)
            .ok_or_else(|| format!("line {line}: the output has no `{OUTPUT_END}`"))?;
        if body[..body_end].contains(OUTPUT_START) {
            return Err(format!("line {line}: the output has no `{OUTPUT_END}`"));
        }
        let text = body[..body_end]
            .lines()
            .filter(|line| !line.starts_with("```") && !line.starts_with("$ "))
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_owned();
        if text.is_empty() {
            return Err(format!("line {line}: the output shows nothing"));
        }
        found.push(Shown { line, args, text, body: body_start..body_start + body_end });
    }
    Ok(found)
}

/// What the tool prints with `args`, standard output after standard error,
/// as a terminal shows both.
fn run(args: &[String]) -> String {
    let output = Command::new(insta_cmd::get_cargo_bin("hereticus"))
        .current_dir(root())
        .args(["--color", "never", "--progress", "never"])
        .args(args)
        .output()
        .expect("the tool runs");
    let stdout = String::from_utf8(output.stdout).expect("the report is text");
    let stderr = String::from_utf8(output.stderr).expect("the errors are text");
    format!("{stderr}\n{stdout}")
}

/// Whether `shown` appears in `printed` as one run, line by line, with the
/// spaces at the ends of the lines left out. A line `...` in `shown`, or a
/// table row of `...`, stands for lines left out, so the runs between such
/// lines must appear in order.
fn appears_in(shown: &str, printed: &str) -> bool {
    let printed: Vec<&str> = printed.lines().map(str::trim_end).collect();
    let printed = format!("\n{}\n", printed.join("\n"));
    let shown: Vec<&str> = shown.lines().map(str::trim_end).collect();
    let mut rest = printed.as_str();
    for run in shown.split(|line| is_elision(line)).filter(|run| !run.is_empty()) {
        let run = format!("\n{}\n", run.join("\n"));
        let Some(at) = rest.find(&run) else { return false };
        // The next run may start on the line this one ends with.
        rest = &rest[at + run.len() - 1..];
    }
    true
}

/// Whether `line` stands for lines left out: `...`, or a table row whose
/// cells are `...` or empty.
fn is_elision(line: &str) -> bool {
    let cells: Vec<&str> = line.trim().trim_matches('|').split('|').map(str::trim).collect();
    cells.contains(&"...") && cells.iter().all(|cell| cell.is_empty() || *cell == "...")
}

/// The README and the pages of the book, which read only the fixtures.
#[test]
fn every_output_the_docs_show_is_what_the_tool_prints() {
    let mut docs = markdown_in(&["book/src"]);
    docs.push(root().join("README.md"));
    check(&docs, Missing::Fail, Mode::from_env());
}

/// The reports, which read the binaries that `just truth` fetches, but for
/// the [`SLOW_REPORTS`]. A report whose binaries were not fetched is left
/// out.
#[test]
fn every_output_the_reports_show_is_what_the_tool_prints() {
    let reports: Vec<PathBuf> = markdown_in(&["real-life-reports", "malware-reports"])
        .into_iter()
        .filter(|doc| !SLOW_REPORTS.iter().any(|slow| doc.ends_with(slow)))
        .collect();
    check(&reports, Missing::Skip, Mode::from_env());
}

/// Each report, which `just test` fetches the binaries of first. An update
/// writes only the [`SLOW_REPORTS`]: the test of the other reports writes
/// those, and two tests that write one file at once can lose a write.
#[test]
fn slow_every_output_the_reports_show_is_what_the_tool_prints() {
    let mode = Mode::from_env();
    let reports: Vec<PathBuf> = markdown_in(&["real-life-reports", "malware-reports"])
        .into_iter()
        .filter(|doc| mode == Mode::Check || SLOW_REPORTS.iter().any(|slow| doc.ends_with(slow)))
        .collect();
    check(&reports, Missing::Fail, mode);
}

#[test]
fn each_slow_report_is_a_report() {
    for slow in SLOW_REPORTS {
        assert!(root().join("real-life-reports").join(slow).exists(), "{slow} is no report");
    }
}

/// Run the tool for each output that `docs` show, and fail where a doc
/// shows another. In [`Mode::Update`], write what the tool prints into the
/// doc where [`updated`] can, and fail only where it cannot.
fn check(docs: &[PathBuf], missing: Missing, mode: Mode) {
    let mut problems = Vec::new();
    let mut checked = 0;
    for doc in docs {
        let mut text = std::fs::read_to_string(doc).expect("a doc");
        let name = doc.strip_prefix(root()).unwrap_or(doc).display().to_string();
        let found = match shown(&text) {
            Ok(found) => found,
            Err(problem) => {
                problems.push(format!("{name}: {problem}"));
                continue;
            }
        };
        // The last first, so the places of the others stay right.
        let mut rewritten = false;
        for one in found.into_iter().rev() {
            let args: Vec<String> = one.args.iter().map(|arg| expand(arg)).collect();
            let absent = one.args.iter().zip(&args).find(|(arg, expanded)| {
                let fetched = arg.starts_with("fixtures/") || arg.starts_with("~/");
                fetched && !root().join(expanded).exists()
            });
            match (absent, missing) {
                (Some((arg, _)), Missing::Fail) => {
                    panic!("{arg} is missing, run `just test` to fetch it")
                }
                (Some((arg, _)), Missing::Skip) => {
                    eprintln!("skipped {name}:{}: {arg} is missing", one.line);
                    continue;
                }
                (None, _) => {}
            }
            checked += 1;
            let printed = run(&args);
            if appears_in(&one.text, &printed) {
                continue;
            }
            let body = &text[one.body.clone()];
            match (mode, updated(body, &printed)) {
                (Mode::Update, Ok(new_body)) => {
                    text.replace_range(one.body.clone(), &new_body);
                    rewritten = true;
                }
                (Mode::Update, Err(problem)) => problems.push(format!(
                    "{name}:{}: `hereticus {}` can not be written in: {problem}",
                    one.line,
                    one.args.join(" "),
                )),
                (Mode::Check, _) => problems.push(format!(
                    "{name}:{}: `hereticus {}` prints\n{printed}\nand not\n{}\n\n\
                     Run `just docs-output` to write the new output in.",
                    one.line,
                    one.args.join(" "),
                    one.text
                )),
            }
        }
        if rewritten {
            std::fs::write(doc, &text).expect("the doc is written");
            eprintln!("wrote {name}");
        }
    }
    assert!(problems.is_empty(), "outputs in the docs do not agree:\n\n{}", problems.join("\n\n"));
    assert!(
        checked > 0 || missing == Missing::Skip,
        "no doc shows an output with an `{OUTPUT_START}` marker"
    );
}

/// A line with what an update may change left out: the lines of the jumps
/// at the left, the indent, and the runs of spaces.
fn bare(line: &str) -> String {
    let start = line.trim_start_matches(|c: char| c.is_whitespace() || "│┌└┬┴┼─<>".contains(c));
    start.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The body of an output, with each run of its shown lines taken from the
/// same lines of `printed`, which match where [`bare`] leaves them alike.
/// The lines of the code fences, of the command and of an elision stay.
fn updated(body: &str, printed: &str) -> Result<String, String> {
    let printed: Vec<&str> = printed.lines().map(str::trim_end).collect();
    let bare_printed: Vec<String> = printed.iter().map(|line| bare(line)).collect();
    let mut lines: Vec<String> = body.split('\n').map(str::to_owned).collect();
    let kept = |line: &str| line.starts_with("```") || line.starts_with("$ ") || is_elision(line);
    // The runs of shown lines, without the empty lines at their ends.
    let mut runs: Vec<core::ops::Range<usize>> = Vec::new();
    let mut at = 0;
    while at < lines.len() {
        let start = at;
        while at < lines.len() && !kept(&lines[at]) {
            at += 1;
        }
        let mut run = start..at;
        while run.start < run.end && lines[run.start].trim().is_empty() {
            run.start += 1;
        }
        while run.start < run.end && lines[run.end - 1].trim().is_empty() {
            run.end -= 1;
        }
        if !run.is_empty() {
            runs.push(run);
        }
        at += 1;
    }
    let mut from = 0;
    for run in runs {
        let wanted: Vec<String> = lines[run.clone()].iter().map(|line| bare(line)).collect();
        let found = (from..=bare_printed.len().saturating_sub(wanted.len()))
            .find(|&start| bare_printed[start..].starts_with(&wanted))
            .ok_or_else(|| format!("`{}` is not printed", lines[run.start].trim()))?;
        for (offset, line) in run.clone().enumerate() {
            lines[line] = printed[found + offset].to_owned();
        }
        // The next run may start on the line this one ends with.
        from = found + wanted.len() - 1;
    }
    Ok(lines.join("\n"))
}

/// The bytes of the two stubs that differ, as the example in the book says.
#[test]
fn the_stub_example_counts_the_bytes_that_changed() {
    let read = |release: &str| {
        let path = root().join(format!("fixtures/build/openwrt/arm-ex6100v2-stub-{release}.bin"));
        std::fs::read(&path)
            .unwrap_or_else(|err| panic!("{}: {err}, run `just firmware` first", path.display()))
    };
    let (before, after) = (read("22.03.2"), read("22.03.5"));
    assert_eq!(before.len(), after.len(), "the two stubs have one size");
    let changed = before.iter().zip(&after).filter(|(a, b)| a != b).count();
    let claim = format!("{changed} of its {} bytes changed", with_commas(before.len()));
    let doc = root().join("book/src/examples.md");
    let text = std::fs::read_to_string(&doc).expect("a doc").replace('\n', " ");
    assert!(text.contains(&claim), "{} does not say `{claim}`", doc.display());
}

/// `15351` as `15,351`.
fn with_commas(number: usize) -> String {
    let digits = number.to_string();
    let mut out = String::new();
    for (at, digit) in digits.chars().enumerate() {
        if at > 0 && (digits.len() - at).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

#[test]
fn a_marked_output_takes_its_arguments_and_its_text() {
    let doc = "Text\n<!-- output: --diff f a.o b.o -->\n```console\n$ hereticus --diff f a.o b.o\n\
               f\n- mov r1, 0x25\n```\n<!-- end output -->\n";
    assert_eq!(
        shown(doc),
        Ok(vec![Shown {
            line: 2,
            args: vec!["--diff".into(), "f".into(), "a.o".into(), "b.o".into()],
            text: "f\n- mov r1, 0x25".into(),
            body: 38..100,
        }])
    );
    let body = &doc[38..100];
    assert!(body.starts_with("\n```console\n"), "the body starts after the marker");
    assert!(doc[100..].starts_with(OUTPUT_END), "and ends at its end");
    assert_eq!(shown("No marker. <!-- a plain comment -->"), Ok(Vec::new()));
    let example = "```markdown\n<!-- output: -h -->\n...\n<!-- end output -->\n```\n";
    assert_eq!(shown(example), Ok(Vec::new()));
}

#[test]
fn a_malformed_marker_is_an_error() {
    assert!(shown("<!-- output: -h -->\ntext").is_err());
    assert!(shown("<!-- output: -->\ntext\n<!-- end output -->").is_err());
    assert!(shown("<!-- output: -h -->\n```\n```\n<!-- end output -->").is_err());
    assert!(shown("<!-- output: -h\ntext").is_err());
    let unclosed = "<!-- output: -h -->\na\n<!-- output: -V -->\nb\n<!-- end output -->";
    assert!(shown(unclosed).is_err());
}

#[test]
fn a_shown_output_may_be_a_part_of_what_is_printed() {
    assert!(appears_in("b\nc", "a\nb  \nc\nd"));
    assert!(!appears_in("b\nd", "a\nb\nc\nd"));
    assert!(!appears_in("b\nc", "a\nb\nC"));
    assert!(appears_in("...\nb\n...\nd\n...", "a\nb\nc\nd\ne"));
    assert!(!appears_in("d\n...\nb", "a\nb\nc\nd"));
    assert!(!appears_in("b\n...\nx", "a\nb\nc\nd"));
    assert!(!appears_in("b", "ab\nc"));
    assert!(appears_in("| a |\n| ... |   |\n| d |", "| a |\n| b |\n| c |\n| d |"));
    assert!(is_elision("..."));
    assert!(is_elision("| ...  |    |  |"));
    assert!(!is_elision("|    |    |"));
    assert!(!is_elision("| ... | x |"));
}

#[test]
fn large_numbers_take_commas() {
    assert_eq!(with_commas(0), "0");
    assert_eq!(with_commas(999), "999");
    assert_eq!(with_commas(15351), "15,351");
    assert_eq!(with_commas(1234567), "1,234,567");
}

#[test]
fn an_argument_under_home_is_expanded() {
    assert_eq!(expand("~/.cache/a"), home().join(".cache/a").display().to_string());
    assert_eq!(expand("fixtures/a.o"), "fixtures/a.o");
    assert_eq!(expand("a~/b"), "a~/b");
}

#[test]
fn an_update_takes_the_lines_of_the_jumps_and_the_indent() {
    let body = "\n```console\n$ hereticus --diff f a b\n...\n  r1 = 1\n- goto $+0x8\n...\n```\n";
    let printed = "f\n┌───<   r0 = 0\n│         r1 = 1\n└───> -   goto $+0x8\n    return";
    assert_eq!(
        updated(body, printed),
        Ok("\n```console\n$ hereticus --diff f a b\n...\n│         r1 = 1\n└───> -   goto $+0x8\n...\n```\n"
            .to_owned())
    );
}

#[test]
fn an_update_keeps_the_order_of_the_runs() {
    let body = "a\n...\nc";
    assert_eq!(updated(body, "│ a\nb\n│ c"), Ok("│ a\n...\n│ c".to_owned()));
    assert!(updated("c\n...\na", "a\nb\nc").is_err(), "c comes after a");
}

#[test]
fn an_update_names_a_line_that_changed_in_its_text() {
    let problem = updated("- mov r1, 0x25", "- mov r1, 0x26").expect_err("the text changed");
    assert!(problem.contains("mov r1, 0x25"), "{problem}");
    assert!(updated("", "a").is_ok_and(|body| body.is_empty()));
}

#[test]
fn a_bare_line_leaves_out_the_jumps_the_indent_and_the_spaces() {
    assert_eq!(bare("│└┼─> -     if (x0 == 0) goto $+0x8"), "- if (x0 == 0) goto $+0x8");
    assert_eq!(bare("  mov\tx0,  x1  "), "mov x0, x1");
    assert_eq!(bare(""), "");
}
