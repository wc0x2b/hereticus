//! Check the pairs of Ubuntu security updates against their debug symbols,
//! and lock the counts and the rank of each fix.
//!
//! Each case is a pair of consecutive security releases of a C library for
//! Ubuntu 22.04, arm64 or armhf: the same compiler and flags on both sides,
//! and a published fix in between. `fixtures/ubuntu_cves.py` fetches the
//! cases that `fixtures/ubuntu_cases.json` pins, each file by its SHA-256.
//!
//! A pair is right when the two functions overlap a symbol of the same
//! name in the `-dbgsym` debug files, and wrong when they share no name.
//! The pairing does not use the names the libraries export, as for a
//! stripped binary. The rank is the row of the first function the patches
//! of the update touched, in the order `--sort added` shows, where any
//! such function is in the library.
//!
//! The inputs are about 800 MB, so `just quick-test` skips this test.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use hereticus::matching::{Changed, Diff, Match, Options, UseNames, diff_with};
use hereticus::obj::Binary;
use rayon::prelude::*;

/// See `ALLOCATOR` in `hereticus-cli/src/main.rs`.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// A function symbol of a debug file: start, end and name.
type Symbol = (u64, u64, String);

/// One security update, as `fixtures/ubuntu_cases.json` pins it.
struct Case {
    library: String,
    arch: String,
    /// The library and its debug file, before and after.
    files: [[PathBuf; 2]; 2],
    /// The functions the patches of the update touched.
    fixes: BTreeSet<String>,
}

/// The counts of one library on one architecture, summed over its cases.
#[derive(Default)]
struct Tally {
    cases: usize,
    right: usize,
    wrong: usize,
    gone: usize,
    new: usize,
    /// Cases where a function the fix touched is in the library at all.
    /// A patch can touch only a tool or a test of the same source, as
    /// `tiffcrop` of libtiff, which no row can show.
    in_library: usize,
    /// Cases where a changed row holds a function the fix touched.
    found: usize,
    /// Over the found cases: the sum of the rank of the fix, from 1, and
    /// how often it is first and in the first five.
    rank_sum: usize,
    top1: usize,
    top5: usize,
}

impl core::ops::AddAssign<&Tally> for Tally {
    fn add_assign(&mut self, other: &Tally) {
        self.cases += other.cases;
        self.right += other.right;
        self.wrong += other.wrong;
        self.gone += other.gone;
        self.new += other.new;
        self.in_library += other.in_library;
        self.found += other.found;
        self.rank_sum += other.rank_sum;
        self.top1 += other.top1;
        self.top5 += other.top5;
    }
}

fn cache() -> PathBuf {
    Path::new(&std::env::var("HOME").expect("HOME is set")).join(".cache/hereticus-ubuntu-cve")
}

fn cases() -> Vec<Case> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/ubuntu_cases.json");
    let text = std::fs::read_to_string(&path).expect("the pinned cases are in the repository");
    let pinned: serde_json::Value = serde_json::from_str(&text).expect("the pinned cases parse");
    let string = |value: &serde_json::Value| value.as_str().expect("a string").to_owned();
    pinned
        .as_array()
        .expect("a list of cases")
        .iter()
        .map(|case| {
            let file = |side: usize, which: usize| {
                cache().join(string(&case["files"][side][which]["path"]))
            };
            Case {
                library: string(&case["library"]),
                arch: string(&case["arch"]),
                files: [[file(0, 0), file(0, 1)], [file(1, 0), file(1, 1)]],
                fixes: case["fixes"]
                    .as_array()
                    .expect("a list of names")
                    .iter()
                    .map(string)
                    .collect(),
            }
        })
        .collect()
}

/// The name of a function without the suffix of a GCC clone.
fn function_name(symbol: &str) -> &str {
    // GCC names a local function `.lto_priv.N` where it built with LTO,
    // as Ubuntu does for arm64 and not for armhf.
    [".isra.", ".constprop.", ".part.", ".cold", ".lto_priv."]
        .iter()
        .filter_map(|suffix| symbol.find(suffix))
        .min()
        .map_or(symbol, |end| &symbol[..end])
}

/// The function symbols of a debug file.
fn debug_symbols(path: &Path) -> Vec<Symbol> {
    use object::{Object, ObjectSymbol, SymbolKind};
    let data = std::fs::read(path)
        .unwrap_or_else(|err| panic!("{}: {err}; run `just test`", path.display()));
    let file = object::File::parse(&*data).expect("the debug file parses");
    file.symbols()
        .filter(|symbol| symbol.kind() == SymbolKind::Text && symbol.size() > 0)
        .filter_map(|symbol| {
            let name = symbol.name().ok()?;
            // GNU ld names each veneer of the Cortex-A53 erratum 843419 by
            // where it sits, so one veneer has another name in each build.
            if name.starts_with("e843419@") {
                return None;
            }
            let name = function_name(name).to_owned();
            // A Thumb symbol has its low bit set.
            let start = symbol.address() & !1;
            Some((start, start + symbol.size(), name))
        })
        .collect()
}

/// The rows the report shows by default, in the order of `--sort added`:
/// most instructions added first, then the lowest score.
fn rows(diff: &Diff) -> Vec<&Match> {
    let mut shown: Vec<&Match> = diff
        .changed()
        .filter(|pair| pair.changed != Changed::Data)
        .filter(|pair| {
            !(pair.edits.total() == 0
                && pair.kinds.callees == 0
                && pair.kinds.texts == 0
                && pair.score >= 1.0)
        })
        .collect();
    shown.sort_by(|a, b| {
        b.edits
            .added
            .cmp(&a.edits.added)
            .then_with(|| a.score.partial_cmp(&b.score).unwrap_or(core::cmp::Ordering::Equal))
    });
    shown
}

fn measure(case: &Case) -> Tally {
    let binaries = case.files.each_ref().map(|[library, _]| {
        let data = std::fs::read(library)
            .unwrap_or_else(|err| panic!("{}: {err}; run `just test`", library.display()));
        Binary::parse(&data).expect("the library parses")
    });
    let symbols = case.files.each_ref().map(|[_, debug]| debug_symbols(debug));
    let diff = diff_with(
        &binaries[0],
        &binaries[1],
        Options { use_names: UseNames::No, ..Default::default() },
    );
    let names = |side: usize, index: usize| -> BTreeSet<&str> {
        let function = &binaries[side].functions[index];
        let start = function.address & !1;
        let end = start + function.code.len() as u64;
        symbols[side]
            .iter()
            .filter(|(low, high, _)| *low < end && *high > start)
            .map(|(_, _, name)| name.as_str())
            .collect()
    };

    let mut tally =
        Tally { cases: 1, gone: diff.removed.len(), new: diff.added.len(), ..Tally::default() };
    for pair in &diff.matched {
        let (before, after) = (names(0, pair.before), names(1, pair.after));
        if before.is_empty() || after.is_empty() {
            continue;
        }
        if before.is_disjoint(&after) {
            tally.wrong += 1;
        } else {
            tally.right += 1;
        }
    }

    let in_library = symbols.iter().flatten().any(|(_, _, name)| case.fixes.contains(name));
    tally.in_library = usize::from(in_library);
    let is_fix = |pair: &&Match| {
        names(0, pair.before)
            .iter()
            .chain(&names(1, pair.after))
            .any(|name| case.fixes.contains(*name))
    };
    if let Some(rank) = rows(&diff).iter().position(is_fix) {
        tally.found = 1;
        tally.rank_sum = rank + 1;
        tally.top1 = usize::from(rank == 0);
        tally.top5 = usize::from(rank < 5);
    }
    tally
}

#[test]
fn the_ubuntu_updates_checked_against_their_symbols_are_locked() {
    let cases = cases();
    let tallies: Vec<Tally> = cases.par_iter().map(measure).collect();

    let mut libraries: BTreeMap<String, Tally> = BTreeMap::new();
    for (case, tally) in cases.iter().zip(&tallies) {
        *libraries.entry(format!("{} {}", case.library, case.arch)).or_default() += tally;
    }
    let mut all = Tally::default();
    for tally in libraries.values() {
        all += tally;
    }
    let mut out = String::new();
    writeln!(
        out,
        "{:22} {:>5} {:>6} {:>5} {:>5} {:>5} | {:>5} {:>5} {:>5} {:>4} {:>4}",
        "library",
        "cases",
        "right",
        "wrong",
        "gone",
        "new",
        "in lib",
        "found",
        "ranks",
        "top1",
        "top5"
    )
    .unwrap();
    for (library, tally) in libraries.iter().chain([(&"all".to_owned(), &all)]) {
        writeln!(
            out,
            "{library:22} {:>5} {:>6} {:>5} {:>5} {:>5} | {:>5} {:>5} {:>5} {:>4} {:>4}",
            tally.cases,
            tally.right,
            tally.wrong,
            tally.gone,
            tally.new,
            tally.in_library,
            tally.found,
            tally.rank_sum,
            tally.top1,
            tally.top5
        )
        .unwrap();
    }
    insta::assert_snapshot!(out);
}
