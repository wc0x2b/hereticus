//! Open a project, and get the report of a new run.
//!
//! Only the browser saves a project, and a test has no terminal to drive it.
//! So each test here writes a project by hand, as the browser does. That
//! also locks the layout of the file: a change that breaks these tests
//! breaks every project saved before it.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use hereticus::matching::{Options, UseNames, diff_with};
use hereticus::obj::Binary;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The firmware fixture before and after its edit.
const FIRMWARE: [(&str, &str); 2] = [("O2", "firmware.o"), ("O2", "firmware_v2.o")];

/// `basic` at two levels, which rewrite too much to pair from the code
/// alone: functions go and come.
const BASIC: [(&str, &str); 2] = [("O0", "basic.o"), ("O2", "basic.o")];

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

/// Copies of two fixtures in a directory of their own, so that a test can
/// change them.
struct Scratch {
    directory: PathBuf,
    binaries: [PathBuf; 2],
    names: UseNames,
}

impl Scratch {
    fn new(name: &str) -> Option<Self> {
        Self::of(name, FIRMWARE, UseNames::Yes)
    }

    /// Copies of `fixtures`, each as a level and a file of
    /// `fixtures/build`, compared with or without the names.
    fn of(name: &str, fixtures: [(&str, &str); 2], names: UseNames) -> Option<Self> {
        let build = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build");
        let sources = fixtures.map(|(level, file)| build.join(level).join(file));
        if !sources.iter().all(|source| source.exists()) {
            eprintln!("skipped: run `just fixtures` first");
            return None;
        }
        let directory =
            std::env::temp_dir().join(format!("hereticus-project-{name}-{}", std::process::id()));
        // Two fixtures can have one file name, so each goes in a directory.
        let binaries = [("before", &sources[0]), ("after", &sources[1])].map(|(side, source)| {
            let file = source.file_name().expect("a file name");
            let copy = directory.join(side).join(file);
            std::fs::create_dir_all(copy.parent().expect("a directory")).expect("a directory");
            std::fs::copy(source, &copy).expect("a copy");
            copy
        });
        Some(Self { directory, binaries, names })
    }

    fn binary(&self, index: usize) -> PathBuf {
        self.binaries[index].clone()
    }

    /// The path of a copy from the directory of the project, as a project
    /// names it.
    fn from_project(&self, index: usize) -> PathBuf {
        self.binary(index).strip_prefix(&self.directory).expect("a copy in the directory").into()
    }

    fn binaries(&self) -> [Binary; 2] {
        [0, 1].map(|index| {
            let bytes = std::fs::read(self.binary(index)).expect("a copy reads");
            Binary::parse(&bytes).expect("a fixture parses")
        })
    }

    fn project(&self) -> PathBuf {
        self.directory.join("firmware.hereticus.json")
    }

    /// A project of the two copies, as the browser saves it before any key.
    fn project_json(&self) -> Value {
        let bytes = [0, 1].map(|index| std::fs::read(self.binary(index)).expect("a copy reads"));
        let [before, after] = self.binaries();
        let options = Options { use_names: self.names, ..Options::default() };
        let input = |index: usize, binary: &Binary| {
            json!({
                "path": self.from_project(index),
                "sha256": hex(&Sha256::digest(&bytes[index])),
                "functions": functions_hash(binary),
            })
        };
        json!({
            "layout": 3,
            "hereticus": "0.0.0",
            "source": {
                "inputs": [input(0, &before), input(1, &after)],
                "raw": null,
                "threshold": 0.65,
                "names": if self.names == UseNames::Yes { "use" } else { "ignore" },
            },
            "browser": {
                "sort": "added",
                "order": "descending",
                "touched": null,
                "only": [],
                "scope": "changed",
                "hidden": { "retouched": "hide", "data": "hide" },
                "near_miss_floor": 0.25,
                "view": "Assembly",
                "layout": "side-by-side",
                "filter": "",
                "selected": null,
                "opened": null,
            },
            "marks": [],
            "diff": diff_with(&before, &after, options),
        })
    }

    fn write_project(&self, project: &Value) {
        std::fs::write(self.project(), project.to_string()).expect("a project");
    }

    /// Run the tool on the project, and on the two copies, with the same
    /// other flags.
    fn both(&self, flags: &[&str]) -> (Output, Output) {
        let opened = hereticus().arg("--open").arg(self.project()).args(flags).output();
        let mut fresh = hereticus();
        if self.names == UseNames::No {
            fresh.arg("--ignore-names");
        }
        let fresh = fresh.args(flags).arg(self.binary(0)).arg(self.binary(1)).output();
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

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The index of the function named `name`.
fn index_of(binary: &Binary, name: &str) -> usize {
    binary.functions.iter().position(|function| function.name == name).expect("the function")
}

/// The firmware with `handle` marked as `auth bypass`, and `checksum`,
/// which did not change, marked with no label.
fn marked_firmware() -> Option<Scratch> {
    let scratch = Scratch::new("marked")?;
    let [before, after] = scratch.binaries();
    let pair = |name: &str| json!({ "pair": { "before": index_of(&before, name), "after": index_of(&after, name) } });
    let mut project = scratch.project_json();
    project["marks"] = json!([
        { "row": pair("handle"), "label": "auth bypass" },
        { "row": pair("checksum"), "label": "" },
    ]);
    scratch.write_project(&project);
    Some(scratch)
}

#[test]
fn each_report_lists_the_marked_functions_first_with_their_labels() {
    let Some(scratch) = marked_firmware() else { return };

    let text = stdout(&scratch.open(&[]));
    let rows: Vec<&str> = text.lines().filter(|line| line.starts_with('│')).collect();
    assert!(rows[1].contains("◆ handle [auth bypass]"), "{text}");
    assert!(rows[2].contains("◆ checksum ") && rows[2].contains("same"), "hidden: {text}");
    assert!(rows[3].contains("dispatch"), "the rest keep their order: {text}");

    let compact = stdout(&scratch.open(&["--format", "compact"]));
    let lines: Vec<&str> = compact.lines().collect();
    assert_eq!(lines[0], "changed\thandle\thandle\t0.82\t8\t4\t2\t◆ auth bypass");
    assert!(lines[1].starts_with("same\tchecksum\tchecksum\t") && lines[1].ends_with("\t◆"));
    assert_eq!(lines[2].split('\t').count(), 7, "an unmarked line keeps seven columns");

    let markdown = stdout(&scratch.open(&["--format", "markdown"]));
    assert!(markdown.contains("| ◆ `handle` [auth bypass] |"), "{markdown}");

    let report: Value =
        serde_json::from_str(&stdout(&scratch.open(&["--format", "json"]))).expect("JSON");
    let pairs = report["pairs"].as_array().expect("pairs");
    assert_eq!(pairs[0]["before"]["name"], "handle");
    assert_eq!(pairs[0]["mark"], "auth bypass");
    assert_eq!(pairs[1]["mark"], "");
    assert!(pairs[2].get("mark").is_none(), "an unmarked pair has no mark");

    // `--diff` finds a function by its label, and each diff names it.
    let by_label = stdout(&scratch.open(&["--diff", "auth bypass"]));
    assert_eq!(by_label, stdout(&scratch.open(&["--diff", "handle"])));
    assert_eq!(by_label.lines().next(), Some("◆ handle [auth bypass]"));
    let every = stdout(&scratch.open(&["--diff-all"]));
    assert!(every.starts_with("◆ handle [auth bypass]\n"), "{every}");
    assert!(every.contains("\n◆ checksum\n"), "{every}");
}

#[test]
fn marked_functions_gone_and_new_come_first_in_their_lists() {
    let Some(scratch) = Scratch::of("unmatched", BASIC, UseNames::No) else { return };
    let mut project = scratch.project_json();
    let gone = project["diff"]["removed"].as_array().expect("gone").clone();
    let new = project["diff"]["added"].as_array().expect("new").clone();
    assert!(gone.len() > 1 && new.len() > 1, "the fixture is as expected");
    let [before, after] = scratch.binaries();
    let name = |binary: &Binary, index: &Value| {
        let index = usize::try_from(index.as_u64().expect("an index")).expect("an index");
        binary.functions[index].name.clone()
    };
    let (last_gone, last_new) = (gone.last().expect("gone"), new.last().expect("new"));
    project["marks"] = json!([
        { "row": { "gone": { "function": last_gone } }, "label": "went" },
        { "row": { "new": { "function": last_new } }, "label": "came" },
    ]);
    scratch.write_project(&project);

    let text = stdout(&scratch.open(&[]));
    let gone_line = format!("◆ {} [went]: gone", name(&before, last_gone));
    let new_line = format!("◆ {} [came]: new", name(&after, last_new));
    let lines: Vec<&str> = text.lines().collect();
    let first_gone = lines.iter().position(|line| line.contains(": gone")).expect("gone");
    let first_new = lines.iter().position(|line| line.contains(": new")).expect("new");
    assert!(lines[first_gone].starts_with(&gone_line), "{text}");
    assert!(lines[first_new].starts_with(&new_line), "{text}");

    let report: Value =
        serde_json::from_str(&stdout(&scratch.open(&["--format", "json"]))).expect("JSON");
    assert_eq!(report["gone"][0]["mark"], "went");
    assert_eq!(report["new"][0]["mark"], "came");

    let error = stderr(&scratch.open(&["--diff", "came"]));
    assert!(error.contains("`came` is new in the later binary"), "{error}");
}

#[test]
fn an_opened_project_prints_the_report_of_a_new_run() {
    let Some(scratch) = Scratch::new("same") else { return };
    scratch.write_project(&scratch.project_json());
    check_same_reports(&scratch, "handle");
    // Every function goes and comes, so `--diff` of one fails, the same way.
    let Some(scratch) = Scratch::of("same-unmatched", BASIC, UseNames::No) else { return };
    scratch.write_project(&scratch.project_json());
    check_same_reports(&scratch, "add");
}

/// Check that a project and a new run print the same, with `function` as
/// the one that `--diff` shows.
fn check_same_reports(scratch: &Scratch, function: &str) {
    for flags in [
        &[][..],
        &["--all"],
        &["--format", "json"],
        &["--format", "compact", "--sort", "removed"],
        &["--format", "markdown", "--show-retouched"],
        &["--diff", function],
        &["--diff-all", "--view", "il"],
        &["--exit-code"],
    ] {
        let (opened, fresh) = scratch.both(flags);
        if flags.is_empty() {
            assert!(!fresh.stdout.is_empty(), "the report always gives the totals");
        }
        assert_eq!(stdout(&opened), stdout(&fresh), "{flags:?}: {}", stderr(&opened));
        assert_eq!(stderr(&opened), stderr(&fresh), "{flags:?}");
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
    project["layout"] = json!(4);
    project["hereticus"] = json!("9.0.0");
    scratch.write_project(&project);

    let error = stderr(&scratch.open(&[]));
    assert!(error.contains("hereticus 9.0.0 saved it in layout 4"), "{error}");
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

#[test]
fn a_saved_project_holds_what_a_project_by_hand_holds() {
    let Some(scratch) = Scratch::new("save") else { return };
    let saved = scratch.directory.join("saved.json");
    // The binaries by their paths from the directory of the project, as the
    // project names them.
    let saving = hereticus()
        .current_dir(&scratch.directory)
        .arg("--save")
        .arg(&saved)
        .args(["before/firmware.o", "after/firmware_v2.o"])
        .output()
        .expect("the tool runs");
    let (_, fresh) = scratch.both(&[]);
    assert_eq!(stdout(&saving), stdout(&fresh), "a save reports as a run does");
    assert_eq!(saving.status.code(), Some(0), "{}", stderr(&saving));

    let read = |path: &Path| -> Value {
        serde_json::from_slice(&std::fs::read(path).expect("a project")).expect("JSON")
    };
    let project = read(&saved);
    let by_hand = scratch.project_json();
    for member in ["layout", "source", "browser", "marks", "diff"] {
        assert_eq!(project[member], by_hand[member], "{member}");
    }
    assert_eq!(project["hereticus"], env!("CARGO_PKG_VERSION"));

    let opened = hereticus().arg("--open").arg(&saved).output().expect("the tool runs");
    assert_eq!(stdout(&opened), stdout(&fresh));
}

#[test]
fn a_saved_project_names_each_binary_from_its_own_directory() {
    let Some(scratch) = Scratch::new("from-project") else { return };
    let projects = scratch.directory.join("projects");
    std::fs::create_dir(&projects).expect("a directory");
    let output = hereticus()
        .current_dir(&scratch.directory)
        .args(["--save", "projects/p.json", "before/firmware.o"])
        .arg(scratch.binary(1))
        .output()
        .expect("the tool runs");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let saved = projects.join("p.json");
    let project: Value =
        serde_json::from_slice(&std::fs::read(&saved).expect("a project")).expect("JSON");
    let inputs = &project["source"]["inputs"];
    assert_eq!(inputs[0]["path"], "../before/firmware.o", "a relative path");
    assert_eq!(inputs[1]["path"], json!(scratch.binary(1)), "an absolute path stays");

    // The project opens from any directory, as the paths start at its own.
    let opened = hereticus().arg("--open").arg(&saved).output().expect("the tool runs");
    assert_eq!(opened.status.code(), Some(0), "{}", stderr(&opened));
}

#[test]
fn a_project_moved_with_its_binaries_opens() {
    let Some(scratch) = Scratch::new("moved-together") else { return };
    scratch.write_project(&scratch.project_json());
    let (_, fresh) = scratch.both(&[]);
    let moved = scratch.directory.with_extension("moved");
    std::fs::rename(&scratch.directory, &moved).expect("a move");

    let opened = hereticus()
        .arg("--open")
        .arg(moved.join("firmware.hereticus.json"))
        .output()
        .expect("the tool runs");
    std::fs::rename(&moved, &scratch.directory).expect("a move back");
    assert_eq!(opened.status.code(), fresh.status.code(), "{}", stderr(&opened));
    assert_eq!(stdout(&opened), stdout(&fresh));
}

#[test]
fn a_layout_2_project_with_absolute_paths_opens() {
    let Some(scratch) = Scratch::new("layout-2") else { return };
    let mut project = scratch.project_json();
    project["layout"] = json!(2);
    for (index, input) in
        project["source"]["inputs"].as_array_mut().expect("two inputs").iter_mut().enumerate()
    {
        input["path"] = json!(scratch.binary(index));
    }
    scratch.write_project(&project);
    let (opened, fresh) = scratch.both(&[]);
    assert_eq!(opened.status.code(), fresh.status.code(), "{}", stderr(&opened));
    assert_eq!(stdout(&opened), stdout(&fresh));
}

#[test]
fn an_opened_project_saves_a_copy_with_its_marks() {
    let Some(scratch) = marked_firmware() else { return };
    let copy = scratch.directory.join("copy.json");
    let output = scratch.open(&["--save", copy.to_str().expect("a path in UTF-8")]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let read = |path: &Path| -> Value {
        serde_json::from_slice(&std::fs::read(path).expect("a project")).expect("JSON")
    };
    let (original, copied) = (read(&scratch.project()), read(&copy));
    for member in ["source", "browser", "marks", "diff"] {
        assert_eq!(copied[member], original[member], "{member}");
    }
}

#[test]
fn a_save_that_fails_stops_with_the_reason() {
    let Some(scratch) = Scratch::new("save-fails") else { return };
    let missing = scratch.directory.join("no such directory/p.json");
    let output = hereticus()
        .arg("--save")
        .arg(&missing)
        .arg(scratch.binary(0))
        .arg(scratch.binary(1))
        .output()
        .expect("the tool runs");
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("cannot save the project to"), "{}", stderr(&output));
    assert!(output.stdout.is_empty(), "no report after a failed save");

    let listing = hereticus()
        .args(["--functions", "--save", "p.json"])
        .arg(scratch.binary(0))
        .output()
        .expect("the tool runs");
    assert!(stderr(&listing).contains("cannot be used with"), "{}", stderr(&listing));
}
