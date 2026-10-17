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
//! `~/.cache`. Those reports are checked by a slow test, so `just
//! quick-test` skips them.

use std::path::{Path, PathBuf};
use std::process::Command;

const OUTPUT_START: &str = "<!-- output: ";
const OUTPUT_END: &str = "<!-- end output -->";

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
        found.push(Shown { line, args, text });
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
    check(&docs);
}

/// The reports, which read the binaries that `just truth` fetches.
#[test]
fn slow_every_output_the_reports_show_is_what_the_tool_prints() {
    check(&markdown_in(&["real-life-reports", "malware-reports"]));
}

/// Run the tool for each output that `docs` show, and fail on the first
/// doc that shows another.
fn check(docs: &[PathBuf]) {
    let mut problems = Vec::new();
    let mut checked = 0;
    for doc in docs {
        let text = std::fs::read_to_string(doc).expect("a doc");
        let name = doc.strip_prefix(root()).unwrap_or(doc).display().to_string();
        let found = match shown(&text) {
            Ok(found) => found,
            Err(problem) => {
                problems.push(format!("{name}: {problem}"));
                continue;
            }
        };
        for one in found {
            checked += 1;
            let args: Vec<String> = one.args.iter().map(|arg| expand(arg)).collect();
            for (arg, expanded) in one.args.iter().zip(&args) {
                let fetched = arg.starts_with("fixtures/") || arg.starts_with("~/");
                if fetched && !root().join(expanded).exists() {
                    panic!("{arg} is missing, run `just test` to fetch it");
                }
            }
            let printed = run(&args);
            if !appears_in(&one.text, &printed) {
                problems.push(format!(
                    "{name}:{}: `hereticus {}` prints\n{printed}\nand not\n{}",
                    one.line,
                    one.args.join(" "),
                    one.text
                ));
            }
        }
    }
    assert!(problems.is_empty(), "outputs in the docs do not agree:\n\n{}", problems.join("\n\n"));
    assert!(checked > 0, "no doc shows an output with an `{OUTPUT_START}` marker");
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
    for doc in [root().join("book/src/examples.md")] {
        let text = std::fs::read_to_string(&doc).expect("a doc").replace('\n', " ");
        assert!(text.contains(&claim), "{} does not say `{claim}`", doc.display());
    }
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
        }])
    );
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
