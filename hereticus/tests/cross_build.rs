//! Measure how well stripped functions pair across builds that differ in how
//! they were compiled, with the symbols as the answer.
//!
//! A vendor rebuilds with other flags, or with another compiler, as often as
//! it edits the source. Each comparison here reads one backport library
//! built two ways, stripped, and checks every pair the matcher makes against
//! the symbol tables of the same builds. Every project and architecture is
//! counted together, and the tally is locked: a change that moves it must
//! update it here, so a gain shows as a gain and a loss fails.
//!
//! The "before" build is read at the first level and the "after" build at
//! the second, so the fix is part of each comparison too.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hereticus::matching::{Options, UseNames, diff_with};
use hereticus::obj::Binary;
use rstest::rstest;

/// What one comparison counts, summed over its builds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Tally {
    /// Pairs whose two functions share a symbol.
    right: usize,
    /// Pairs whose two functions share none.
    wrong: usize,
    /// Functions of the first build that paired with nothing.
    gone: usize,
    /// Functions of the second build that paired with nothing.
    new: usize,
}

fn backports() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/backports")
}

fn read(project: &str, variant: &str, arch: &str, level: &str, file: &str) -> Binary {
    let path = backports().join(format!("{project}-{variant}/{arch}-{level}/{file}"));
    let data = std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{}: {err}, run `just backports` first", path.display()));
    Binary::parse(&data).expect("a fixture library must parse")
}

/// A symbol name without the suffix GCC gives a copy it specialized, as
/// `g_iofile.isra.0`: the copy is still that function.
fn function_name(symbol: &str) -> &str {
    [".isra.", ".constprop.", ".part.", ".cold"]
        .iter()
        .filter_map(|suffix| symbol.find(suffix))
        .min()
        .map_or(symbol, |end| &symbol[..end])
}

/// The functions whose symbols overlap `range` in `symbols`.
fn names_over(symbols: &Binary, range: core::ops::Range<u64>) -> BTreeSet<String> {
    symbols
        .functions
        .iter()
        .filter(|symbol| {
            symbol.address < range.end && symbol.address + symbol.code.len() as u64 > range.start
        })
        .map(|symbol| function_name(&symbol.name).to_owned())
        .collect()
}

/// Compare `project` built at `first` with the fixed build at `second`,
/// stripped, and count the pairs against the symbols.
fn tally(project: &str, arch: &str, first: &str, second: &str) -> Tally {
    let symbols = [
        read(project, "before", arch, first, "lib.so"),
        read(project, "after", arch, second, "lib.so"),
    ];
    let stripped = [
        read(project, "before", arch, first, "lib-stripped.so"),
        read(project, "after", arch, second, "lib-stripped.so"),
    ];
    let diff = diff_with(
        &stripped[0],
        &stripped[1],
        Options { use_names: UseNames::No, ..Default::default() },
    );

    let names = |side: usize, index: usize| {
        let function = &stripped[side].functions[index];
        names_over(&symbols[side], function.address..function.address + function.code.len() as u64)
    };
    let mut tally = Tally { gone: diff.removed.len(), new: diff.added.len(), ..Tally::default() };
    for pair in &diff.matched {
        let (left, right) = (names(0, pair.before), names(1, pair.after));
        // Code that no symbol covers, as a PLT stub, has no answer.
        if left.is_empty() || right.is_empty() {
            continue;
        }
        if left.is_disjoint(&right) {
            tally.wrong += 1;
        } else {
            tally.right += 1;
        }
    }
    tally
}

/// Every project and architecture of one comparison, summed.
fn tally_all(first: &str, second: &str) -> Tally {
    tally_arches(first, second, &["arm", "thumb", "aarch64", "mips", "mipsel"])
}

/// Every project of one comparison on `arches`, summed.
fn tally_arches(first: &str, second: &str, arches: &[&str]) -> Tally {
    // Rust is built by LLVM alone, so it has no GCC builds.
    let built_by_gcc = first.starts_with("gcc") || second.starts_with("gcc");
    let projects: &[&str] = if built_by_gcc {
        &["zlib", "lua", "tinyxml2"]
    } else {
        &["zlib", "lua", "tinyxml2", "smallvec"]
    };
    let mut total = Tally::default();
    for project in projects {
        for &arch in arches {
            let one = tally(project, arch, first, second);
            total.right += one.right;
            total.wrong += one.wrong;
            total.gone += one.gone;
            total.new += one.new;
        }
    }
    total
}

#[rstest]
#[case::o1_o2("O1", "O2", Tally { right: 4402, wrong: 112, gone: 290, new: 203 })]
#[case::o2_o3("O2", "O3", Tally { right: 4509, wrong: 40, gone: 173, new: 144 })]
#[case::o2_os("O2", "Os", Tally { right: 3246, wrong: 245, gone: 1226, new: 1948 })]
#[case::o3_os("O3", "Os", Tally { right: 3110, wrong: 263, gone: 1322, new: 2073 })]
#[case::gcc_o2_gcc_os("gcc-O2", "gcc-Os", Tally { right: 3651, wrong: 106, gone: 729, new: 1185 })]
#[case::clang_gcc("O2", "gcc-O2", Tally { right: 2581, wrong: 281, gone: 1496, new: 1696 })]
fn pairs_across_builds_are_locked(
    #[case] first: &str,
    #[case] second: &str,
    #[case] expected: Tally,
) {
    assert_eq!(tally_all(first, second), expected, "{first} against {second}");
}

/// MIPS16e, which GCC alone builds, so only its two levels compare.
#[test]
fn mips16_pairs_across_builds_are_locked() {
    let found = tally_arches("gcc-O2", "gcc-Os", &["mips16"]);
    assert_eq!(found, Tally { right: 728, wrong: 42, gone: 139, new: 224 });
}
