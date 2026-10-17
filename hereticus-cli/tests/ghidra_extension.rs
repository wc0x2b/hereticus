//! Check what the Ghidra extension of `ghidra/` does in a real Ghidra.
//!
//! `just ghidra-extension` installs the extension in headless Ghidra and
//! writes what Ghidra finds without and with the Hereticus Function Finder,
//! and the matches of the Hereticus Function Match correlator.
//! `fixtures/ghidra_extension.sh` names the files. The finder must add
//! functions and lose none, and the correlator must propose the pairs of
//! hereticus and nothing else. The snapshot locks the counts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

const RECIPE: &str = "just ghidra-extension";

/// The binaries the finder runs on, as `fixtures/ghidra_extension.sh` names
/// them. A stripped backport is the after side of its pair.
const FINDS: [Find; 5] = [
    Find::Backport("zlib-arm-O2"),
    Find::Backport("zlib-thumb-O2"),
    Find::Backport("zlib-aarch64-O2"),
    Find::Backport("zlib-mips-O2"),
    Find::RawStub,
];

/// The backport pairs the correlator runs on.
const PAIRS: [&str; 2] = ["zlib-arm-O2", "zlib-mips-O2"];

/// One binary the finder runs on.
#[derive(Clone, Copy, Debug)]
enum Find {
    /// The stripped shared object of one backport build, as
    /// `<project>-<arch>-<level>`.
    Backport(&'static str),
    /// The raw zImage stub of the Netgear EX6100v2.
    RawStub,
}

/// Whether the finder ran.
#[derive(Clone, Copy, Debug)]
enum Setting {
    Off,
    On,
}

impl Find {
    fn name(self) -> &'static str {
        match self {
            Self::Backport(name) => name,
            Self::RawStub => "arm-stub",
        }
    }

    /// The arguments that make hereticus read the binary as Ghidra did.
    fn hereticus_arguments(self) -> Vec<String> {
        match self {
            Self::Backport(name) => vec![backport(name, "after").display().to_string()],
            Self::RawStub => ["--raw", "--base", "0x80208000", "--arch", "arm32"]
                .into_iter()
                .map(str::to_owned)
                .chain([fixtures()
                    .join("build/openwrt/arm-ex6100v2-stub-22.03.2.bin")
                    .display()
                    .to_string()])
                .collect(),
        }
    }

    /// The linked start of each function Ghidra found.
    fn ghidra_starts(self, setting: Setting) -> BTreeSet<u64> {
        let suffix = match setting {
            Setting::Off => "off",
            Setting::On => "on",
        };
        let path = output().join(format!("starts/{}-{suffix}.txt", self.name()));
        read(&path)
            .lines()
            .map(|line| {
                u64::from_str_radix(line.trim(), 16)
                    .unwrap_or_else(|err| panic!("{}: {line:?}: {err}", path.display()))
            })
            .collect()
    }

    /// The start of each function hereticus finds that holds code.
    fn hereticus_starts(self) -> BTreeSet<u64> {
        let mut arguments =
            vec!["--functions".to_owned(), "--format".to_owned(), "json".to_owned()];
        arguments.extend(self.hereticus_arguments());
        let listing = hereticus(&arguments);
        listing["functions"]
            .as_array()
            .expect("the functions are a list")
            .iter()
            .filter(|function| function["holds"] == "code")
            .map(|function| function["address"].as_u64().expect("an address"))
            .collect()
    }
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures")
}

fn output() -> PathBuf {
    fixtures().join("build/ghidra-extension")
}

/// The stripped shared object of one side of a backport build.
fn backport(name: &str, variant: &str) -> PathBuf {
    let (project, build) = name.split_once('-').expect("a project and a build");
    fixtures().join(format!("build/backports/{project}-{variant}/{build}/lib-stripped.so"))
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("{}: {err}, run `{RECIPE}` first", path.display()))
}

/// Runs hereticus with `arguments`, and reads its JSON.
fn hereticus(arguments: &[String]) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_hereticus"))
        .args(["--progress", "never"])
        .args(arguments)
        .output()
        .expect("the tool runs");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).expect("hereticus prints JSON")
}

/// What one match or pair says: its score and the tag it gets.
#[derive(Clone, Debug, PartialEq)]
struct Proposal {
    score: f64,
    tag: String,
}

/// The matches the correlator proposed for one pair, by linked addresses.
fn ghidra_matches(name: &str) -> BTreeMap<(u64, u64), Proposal> {
    let path = output().join(format!("matches/{name}.json"));
    let report: serde_json::Value = serde_json::from_str(&read(&path))
        .unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    report["matches"]
        .as_array()
        .expect("the matches are a list")
        .iter()
        .map(|found| {
            let key = (
                found["before"].as_u64().expect("an address"),
                found["after"].as_u64().expect("an address"),
            );
            let proposal = Proposal {
                score: found["score"].as_f64().expect("a score"),
                tag: found["tag"].as_str().expect("a tag").to_owned(),
            };
            (key, proposal)
        })
        .collect()
}

/// Every pair hereticus finds for one backport build, with the tag the
/// correlator gives it.
fn hereticus_pairs(name: &str) -> BTreeMap<(u64, u64), Proposal> {
    let report = hereticus(&[
        "--format".to_owned(),
        "json".to_owned(),
        "--all".to_owned(),
        backport(name, "before").display().to_string(),
        backport(name, "after").display().to_string(),
    ]);
    report["pairs"]
        .as_array()
        .expect("the pairs are a list")
        .iter()
        .map(|pair| {
            let key = (
                pair["before"]["address"].as_u64().expect("an address"),
                pair["after"]["address"].as_u64().expect("an address"),
            );
            let proposal = Proposal {
                score: pair["score"].as_f64().expect("a score"),
                tag: format!("hereticus: {}", pair["change"].as_str().expect("a change")),
            };
            (key, proposal)
        })
        .collect()
}

/// The finder adds to what Ghidra finds, and takes nothing away.
#[test]
fn the_finder_loses_no_function_ghidra_finds() {
    for find in FINDS {
        let off = find.ghidra_starts(Setting::Off);
        let on = find.ghidra_starts(Setting::On);
        let lost: Vec<String> = off.difference(&on).map(|start| format!("{start:#x}")).collect();
        assert!(lost.is_empty(), "{}: the finder lost {}", find.name(), lost.join(", "));
    }
}

/// Each function the finder adds is one hereticus found.
#[test]
fn the_finder_adds_only_what_hereticus_finds() {
    for find in FINDS {
        let off = find.ghidra_starts(Setting::Off);
        let hereticus = find.hereticus_starts();
        let foreign: Vec<String> = find
            .ghidra_starts(Setting::On)
            .difference(&off)
            .filter(|start| !hereticus.contains(start))
            .map(|start| format!("{start:#x}"))
            .collect();
        assert!(
            foreign.is_empty(),
            "{}: not found by hereticus: {}",
            find.name(),
            foreign.join(", ")
        );
    }
}

/// On a raw image Ghidra finds only what flows from the first byte, and the
/// finder adds the rest, which is where the extension earns its place.
#[test]
fn the_finder_more_than_doubles_the_functions_of_a_raw_stub() {
    let off = Find::RawStub.ghidra_starts(Setting::Off).len();
    let on = Find::RawStub.ghidra_starts(Setting::On).len();
    assert!(on > 2 * off, "{off} functions without the finder, {on} with it");
}

/// The correlator proposes the pairs of hereticus, with their scores and
/// tags, and no pair of its own.
#[test]
fn the_correlator_proposes_only_the_pairs_of_hereticus() {
    for name in PAIRS {
        let pairs = hereticus_pairs(name);
        for (key, found) in ghidra_matches(name) {
            let wanted = pairs.get(&key).unwrap_or_else(|| {
                panic!("{name}: {:#x} -> {:#x} is not a pair of hereticus", key.0, key.1)
            });
            // Version Tracking keeps a score to three decimals, as it shows it.
            assert!(
                (found.score - wanted.score).abs() <= 0.0005 + 1e-9,
                "{name}: {key:x?} {found:?} and not {wanted:?}"
            );
            assert_eq!(found.tag, wanted.tag, "{name}: {key:x?}");
        }
    }
}

/// Lock how many functions Ghidra finds with and without the finder, and how
/// many pairs the correlator proposes.
#[test]
fn the_counts_of_the_extension_are_locked() {
    let mut table = String::from("binary            off  on  hereticus  hereticus in on\n");
    for find in FINDS {
        let on = find.ghidra_starts(Setting::On);
        let hereticus = find.hereticus_starts();
        let _ = writeln!(
            table,
            "{:<16} {:>4} {:>3} {:>10} {:>16}",
            find.name(),
            find.ghidra_starts(Setting::Off).len(),
            on.len(),
            hereticus.len(),
            hereticus.intersection(&on).count(),
        );
    }
    table.push_str("\npair              matches  hereticus pairs\n");
    for name in PAIRS {
        let _ = writeln!(
            table,
            "{:<16} {:>8} {:>16}",
            name,
            ghidra_matches(name).len(),
            hereticus_pairs(name).len()
        );
    }
    insta::assert_snapshot!(table);
}
