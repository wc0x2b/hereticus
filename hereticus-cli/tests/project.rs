//! Open a project, and get the report of a new run.
//!
//! Only the browser saves a project, and a test has no terminal to drive it.
//! So each test here writes a project by hand, as the browser does. That
//! also locks the layout of the file: a change that breaks these tests
//! breaks every project saved before it.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use hereticus::matching::diff;
use hereticus::obj::Binary;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FILES: [&str; 2] = ["firmware.o", "firmware_v2.o"];

fn hereticus() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hereticus"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The hash of the address and the size of each function, as a project
/// holds it.
fn functions_hash(binary: &Binary) -> String {
    let mut hasher = Sha256::new();
    for function in &binary.functions {
        hasher.update(function.address.to_le_bytes());
        hasher.update((function.code.len() as u64).to_le_bytes());
    }
    hex(&hasher.finalize())
}

/// Copies of the firmware fixture in a directory of their own, so that a
/// test can change them.
struct Scratch {
    directory: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Option<Self> {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/O2");
        if !fixtures.join(FILES[0]).exists() {
            eprintln!("skipped: run `just fixtures` first");
            return None;
        }
        let directory =
            std::env::temp_dir().join(format!("hereticus-project-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a directory");
        for file in FILES {
            std::fs::copy(fixtures.join(file), directory.join(file)).expect("a copy");
        }
        Some(Self { directory })
    }

    fn binary(&self, index: usize) -> PathBuf {
        self.directory.join(FILES[index])
    }

    fn project(&self) -> PathBuf {
        self.directory.join("firmware.hereticus.json")
    }

    /// A project of the two copies, as the browser saves it before any key.
    fn project_json(&self) -> Value {
        let bytes = [0, 1].map(|index| std::fs::read(self.binary(index)).expect("a copy reads"));
        let [before, after] =
            [0, 1].map(|index| Binary::parse(&bytes[index]).expect("a fixture parses"));
        let input = |index: usize, binary: &Binary| {
            json!({
                "path": self.binary(index),
                "sha256": hex(&Sha256::digest(&bytes[index])),
                "functions": functions_hash(binary),
            })
        };
        json!({
            "layout": 1,
            "hereticus": "0.0.0",
            "source": {
                "inputs": [input(0, &before), input(1, &after)],
                "raw": null,
                "threshold": 0.65,
                "names": "use",
            },
            "browser": {
                "sort": "added",
                "order": "descending",
                "touched": null,
                "scope": "changed",
                "hidden": { "retouched": "hide", "data": "hide" },
                "near_miss_floor": 0.25,
                "view": "Assembly",
                "layout": "side-by-side",
                "filter": "",
                "selected": null,
                "opened": null,
            },
            "marks": [{ "row": { "gone": { "function": 0 } }, "label": "a label" }],
            "diff": diff(&before, &after),
        })
    }

    fn write_project(&self, project: &Value) {
        std::fs::write(self.project(), project.to_string()).expect("a project");
    }

    /// Run the tool on the project, and on the two copies, with the same
    /// other flags.
    fn both(&self, flags: &[&str]) -> (Output, Output) {
        let opened = hereticus().arg("--open").arg(self.project()).args(flags).output();
        let fresh = hereticus().args(flags).arg(self.binary(0)).arg(self.binary(1)).output();
        (opened.expect("the tool runs"), fresh.expect("the tool runs"))
    }

    fn open(&self, flags: &[&str]) -> Output {
        hereticus().arg("--open").arg(self.project()).args(flags).output().expect("the tool runs")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn an_opened_project_prints_the_report_of_a_new_run() {
    let Some(scratch) = Scratch::new("same") else { return };
    scratch.write_project(&scratch.project_json());
    for flags in [
        &[][..],
        &["--all"],
        &["--format", "json"],
        &["--format", "compact", "--sort", "removed"],
        &["--format", "markdown", "--show-retouched"],
        &["--diff", "handle"],
        &["--diff-all", "--view", "il"],
        &["--exit-code"],
    ] {
        let (opened, fresh) = scratch.both(flags);
        assert!(!fresh.stdout.is_empty(), "{flags:?}: {}", stderr(&fresh));
        assert_eq!(
            String::from_utf8_lossy(&opened.stdout),
            String::from_utf8_lossy(&fresh.stdout),
            "{flags:?}: {}",
            stderr(&opened)
        );
        assert_eq!(opened.status.code(), fresh.status.code(), "{flags:?}");
    }
}

#[test]
fn a_changed_binary_stops_the_project() {
    let Some(scratch) = Scratch::new("changed") else { return };
    scratch.write_project(&scratch.project_json());
    let mut bytes = std::fs::read(scratch.binary(1)).expect("a copy reads");
    bytes.push(0);
    std::fs::write(scratch.binary(1), bytes).expect("a copy writes");

    let output = scratch.open(&[]);
    assert_eq!(output.status.code(), Some(2));
    let error = stderr(&output);
    assert!(error.contains("firmware_v2.o changed since the project was saved"), "{error}");
    assert!(output.stdout.is_empty());
}

#[test]
fn a_moved_binary_stops_the_project() {
    let Some(scratch) = Scratch::new("moved") else { return };
    scratch.write_project(&scratch.project_json());
    std::fs::remove_file(scratch.binary(0)).expect("a copy goes");

    let output = scratch.open(&[]);
    assert_eq!(output.status.code(), Some(2));
    let error = stderr(&output);
    assert!(error.contains("cannot read") && error.contains("firmware.o"), "{error}");
}

#[test]
fn other_functions_stop_the_project() {
    let Some(scratch) = Scratch::new("functions") else { return };
    let mut project = scratch.project_json();
    project["source"]["inputs"][0]["functions"] = json!("0");
    scratch.write_project(&project);

    let error = stderr(&scratch.open(&[]));
    assert!(error.contains("finds other functions in"), "{error}");
}

#[test]
fn a_result_that_does_not_fit_the_binaries_stops_the_project() {
    let Some(scratch) = Scratch::new("fit") else { return };
    let mut project = scratch.project_json();
    project["diff"]["matched"][0]["after"] = json!(100_000);
    scratch.write_project(&project);

    let error = stderr(&scratch.open(&[]));
    assert!(error.contains("names functions that the binaries do not hold"), "{error}");
}

#[test]
fn a_newer_layout_stops_the_project() {
    let Some(scratch) = Scratch::new("layout") else { return };
    let mut project = scratch.project_json();
    project["layout"] = json!(2);
    project["hereticus"] = json!("9.0.0");
    scratch.write_project(&project);

    let error = stderr(&scratch.open(&[]));
    assert!(error.contains("hereticus 9.0.0 saved it in layout 2"), "{error}");
}

#[test]
fn a_file_that_is_no_project_stops() {
    let Some(scratch) = Scratch::new("garbage") else { return };
    std::fs::write(scratch.project(), "{}").expect("a file");

    let error = stderr(&scratch.open(&[]));
    assert!(error.starts_with("hereticus: cannot open the project"), "{error}");
}

#[test]
fn a_project_takes_no_binaries_and_no_flags_that_read_them() {
    let Some(scratch) = Scratch::new("flags") else { return };
    scratch.write_project(&scratch.project_json());
    let binary = scratch.binary(0);
    let binary = binary.to_str().expect("a path in UTF-8");
    for flags in
        [&[binary][..], &["--raw"], &["--threshold", "0.5"], &["--ignore-names"], &["--functions"]]
    {
        let output = scratch.open(flags);
        assert_eq!(output.status.code(), Some(2), "{flags:?}");
        assert!(stderr(&output).contains("cannot be used with"), "{flags:?}: {}", stderr(&output));
    }
}

#[test]
fn the_browser_of_a_project_needs_a_terminal() {
    let Some(scratch) = Scratch::new("terminal") else { return };
    scratch.write_project(&scratch.project_json());

    let error = stderr(&scratch.open(&["--tui"]));
    assert!(error.contains("--tui needs a terminal"), "{error}");
}
