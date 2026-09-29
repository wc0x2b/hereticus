//! Measure how well a stripped library's functions are recovered, with the
//! symbols as the answer.
//!
//! Every comparison of a stripped binary starts from the functions the scan
//! finds, so a function split in two or merged into its neighbour is wrong
//! in every report that follows. This reads each release that
//! `just backports` builds into `fixtures/build/versions`, stripped, and
//! compares the functions found against the symbol table of the same build.
//! The counts are locked, so a change to the scan shows what it gains and
//! what it costs.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hereticus::obj::Binary;

/// What recovery found, summed over every build.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Recovery {
    /// Functions of the symbol table.
    functions: usize,
    /// Functions found with the same start and end as a symbol.
    exact: usize,
    /// Starts found where no symbol starts: a function split in two.
    invented: usize,
    /// Symbol starts not found: a function merged into the one before.
    missed: usize,
}

fn builds() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/versions");
    let mut builds: Vec<PathBuf> = std::fs::read_dir(&root)
        .expect("run `just backports` first")
        .flatten()
        .flat_map(|release| std::fs::read_dir(release.path()).into_iter().flatten().flatten())
        .map(|build| build.path())
        .filter(|build| build.join("lib-stripped.so").exists())
        .collect();
    builds.sort();
    builds
}

/// The start and end of each function.
fn spans(binary: &Binary) -> BTreeSet<(u64, u64)> {
    binary
        .functions
        .iter()
        .map(|function| (function.address, function.address + function.code.len() as u64))
        .collect()
}

fn recovery_of(build: &Path) -> Recovery {
    let read = |file: &str| {
        let data = std::fs::read(build.join(file)).expect("the build exists");
        Binary::parse(&data).expect("the build parses")
    };
    let (truth, found) = (spans(&read("lib.so")), spans(&read("lib-stripped.so")));
    let starts = |spans: &BTreeSet<(u64, u64)>| -> BTreeSet<u64> {
        spans.iter().map(|&(start, _)| start).collect()
    };
    let (true_starts, found_starts) = (starts(&truth), starts(&found));
    Recovery {
        functions: truth.len(),
        exact: truth.intersection(&found).count(),
        invented: found_starts.difference(&true_starts).count(),
        missed: true_starts.difference(&found_starts).count(),
    }
}

#[test]
fn stripped_functions_are_recovered() {
    let builds = builds();
    assert!(!builds.is_empty(), "run `just backports` first");
    let total =
        builds.iter().map(|build| recovery_of(build)).fold(Recovery::default(), |sum, one| {
            Recovery {
                functions: sum.functions + one.functions,
                exact: sum.exact + one.exact,
                invented: sum.invented + one.invented,
                missed: sum.missed + one.missed,
            }
        });
    assert_eq!(
        total,
        Recovery { functions: 27500, exact: 26827, invented: 247, missed: 273 },
        "over {} builds",
        builds.len()
    );
}

/// A stripped library keeps its dynamic symbol table, so each function it
/// exports keeps its name, its start and its end.
#[test]
fn exported_functions_keep_their_names() {
    let build =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/versions/zlib-1.2.13/arm-O2");
    let read = |file: &str| {
        let data = std::fs::read(build.join(file)).expect("run `just backports` first");
        Binary::parse(&data).expect("the build parses")
    };
    let (symbols, stripped) = (read("lib.so"), read("lib-stripped.so"));
    for name in ["crc32", "crc32_z", "inflateEnd", "gzseek"] {
        let span_of = |binary: &Binary| {
            binary
                .functions
                .iter()
                .find(|function| function.name == name)
                .map(|function| (function.address, function.code.len()))
        };
        assert!(span_of(&symbols).is_some(), "{name} is in the symbol table");
        assert_eq!(span_of(&stripped), span_of(&symbols), "{name}");
    }
}
