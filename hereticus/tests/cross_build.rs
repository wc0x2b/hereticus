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

/// See `ALLOCATOR` in `hereticus-cli/src/main.rs`.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

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
/// The hints of a place that the rows of the functions gone and new give,
/// `NearMiss::in_place`, checked against the symbols.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Places {
    /// Hints whose two functions share a symbol.
    right: usize,
    /// Hints whose two functions share none.
    wrong: usize,
}

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
    compare(project, arch, first, second).0
}

/// As [`tally`], and count the hints of a place too.
fn compare(project: &str, arch: &str, first: &str, second: &str) -> (Tally, Places) {
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

    let hints: BTreeSet<(usize, usize)> = diff
        .near_misses
        .iter()
        .filter_map(|miss| Some((miss.unmatched, miss.in_place?)))
        .chain(
            diff.added_near_misses.iter().filter_map(|miss| Some((miss.in_place?, miss.unmatched))),
        )
        .collect();
    let mut places = Places::default();
    for &(before, after) in &hints {
        let (left, right) = (names(0, before), names(1, after));
        if left.is_empty() || right.is_empty() {
            continue;
        }
        if left.is_disjoint(&right) {
            places.wrong += 1;
        } else {
            places.right += 1;
        }
    }
    (tally, places)
}

/// The projects built at `first` and at `second`.
fn projects(first: &str, second: &str) -> &'static [&'static str] {
    // Rust is built by LLVM alone, so it has no GCC builds.
    let built_by_gcc = first.starts_with("gcc") || second.starts_with("gcc");
    if built_by_gcc {
        &["zlib", "lua", "tinyxml2"]
    } else {
        &["zlib", "lua", "tinyxml2", "smallvec"]
    }
}

const ARCHES: &[&str] = &["arm", "thumb", "aarch64", "mips", "mipsel"];

/// Every project and architecture of one comparison, summed.
fn tally_all(first: &str, second: &str) -> Tally {
    tally_arches(first, second, ARCHES)
}

/// Every project of one comparison on `arches`, summed.
fn tally_arches(first: &str, second: &str, arches: &[&str]) -> Tally {
    let mut total = Tally::default();
    for project in projects(first, second) {
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
#[case::o1_o2("O1", "O2", Tally { right: 4598, wrong: 45, gone: 178, new: 87 })]
#[case::o2_o3("O2", "O3", Tally { right: 4644, wrong: 17, gone: 77, new: 36 })]
#[case::o2_os("O2", "Os", Tally { right: 4323, wrong: 100, gone: 300, new: 1122 })]
#[case::o3_os("O3", "Os", Tally { right: 4245, wrong: 103, gone: 346, new: 1209 })]
#[case::gcc_o2_gcc_os("gcc-O2", "gcc-Os", Tally { right: 4225, wrong: 25, gone: 237, new: 749 })]
#[case::clang_gcc("O2", "gcc-O2", Tally { right: 3258, wrong: 48, gone: 1107, new: 1443 })]
fn pairs_across_builds_are_locked(
    #[case] first: &str,
    #[case] second: &str,
    #[case] expected: Tally,
) {
    assert_eq!(tally_all(first, second), expected, "{first} against {second}");
}

/// MIPS16e, which GCC alone builds, so only its two levels compare.
///
/// The literal pool after a function is its data. Read as a function of
/// its own, as before, a pool made a pair of its own: 2 more right, 1 more
/// wrong, 3 more gone and 6 more new.
#[test]
fn mips16_pairs_across_builds_are_locked() {
    let found = tally_arches("gcc-O2", "gcc-Os", &["mips16"]);
    assert_eq!(found, Tally { right: 848, wrong: 14, gone: 41, new: 123 });
}

/// The hints of a place over every comparison.
///
/// The book quotes the share of right hints.
#[test]
fn the_place_hints_are_locked() {
    use std::fmt::Write as _;
    let levels = [
        ("O1", "O2"),
        ("O2", "O3"),
        ("O2", "Os"),
        ("O3", "Os"),
        ("gcc-O2", "gcc-Os"),
        ("O2", "gcc-O2"),
    ];
    let mut out = format!("{:16} {:>6} {:>6} {:>7}\n", "places", "right", "wrong", "right%");
    let mut row = |label: &str, places: &Places| {
        let right = 100.0 * places.right as f64 / (places.right + places.wrong) as f64;
        writeln!(out, "{label:16} {:>6} {:>6} {right:>6.1}%", places.right, places.wrong).unwrap();
    };
    let mut all = Places::default();
    for (first, second) in levels {
        let mut sum = Places::default();
        for project in projects(first, second) {
            for arch in ARCHES {
                let (_, places) = compare(project, arch, first, second);
                sum.right += places.right;
                sum.wrong += places.wrong;
            }
        }
        row(&format!("{first}/{second}"), &sum);
        all.right += sum.right;
        all.wrong += sum.wrong;
    }
    row("all", &all);
    insta::assert_snapshot!(out);
}
