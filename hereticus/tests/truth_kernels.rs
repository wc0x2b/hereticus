//! Check the pairs of the OpenWrt kernels of `tests/openwrt.rs` against the
//! symbols of their builds, and lock the counts.
//!
//! OpenWrt publishes the `vmlinux` of each kernel it builds, with symbols and
//! without code. `fixtures/openwrt_debug.py` fetches it and pins it by its
//! SHA-256, so the counts below tell how often the tool pairs a function of
//! a shipped, stripped kernel with the right one.
//!
//! A pair is right when the two functions overlap a symbol of the same name,
//! and wrong when they share no name. A function renamed between releases
//! counts as wrong, so the wrong counts are an upper bound.
//!
//! The inputs are about 800 MB, so `just quick-test` skips this test.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use hereticus::matching::{Options, UseNames, diff_with};
use hereticus::obj::{Binary, Isa};
use rayon::prelude::*;

/// A board of `tests/openwrt.rs`: the name its files carry, the target whose
/// kernel it runs, how its code reads, and where its kernel is linked.
struct Board {
    name: &'static str,
    target: &'static str,
    isa: Isa,
    kernel_base: u64,
}

const BOARDS: &[Board] = &[
    Board {
        name: "arm-ex6100v2",
        target: "ipq40xx-generic",
        isa: Isa::Arm32,
        kernel_base: 0xc020_8000,
    },
    Board {
        name: "mipsbe-eap245v3",
        target: "ath79-generic",
        isa: Isa::Mips32Be,
        kernel_base: 0x8006_0000,
    },
    Board {
        name: "mipsel-r6220",
        target: "ramips-mt7621",
        isa: Isa::Mips32,
        kernel_base: 0x8000_1000,
    },
    Board {
        name: "arm-a385dbap",
        target: "mvebu-cortexa9",
        isa: Isa::Arm32,
        kernel_base: 0xc000_8000,
    },
    Board {
        name: "mipsbe-vr200",
        target: "lantiq-xrx200",
        isa: Isa::Mips32Be,
        kernel_base: 0x8000_2000,
    },
    Board {
        name: "mipsel-mt300nv2",
        target: "ramips-mt76x8",
        isa: Isa::Mips32,
        kernel_base: 0x8000_0000,
    },
];

/// The releases `tests/openwrt.rs` compares, and on how many of [`BOARDS`]:
/// the point release on all, the two kernel upgrades on the first three.
const RELEASES: &[(&str, &str, usize)] =
    &[("22.03.2", "22.03.5", 6), ("21.02.7", "22.03.2", 3), ("22.03.5", "23.05.5", 3)];

/// A function symbol of a debug file: start, end and name.
type Symbol = (u64, u64, String);

/// The pairs of one kernel upgrade, checked against the symbols.
#[derive(Default)]
struct Tally {
    /// Recovered functions that start where a symbol does, over both sides.
    starts_on_symbol: usize,
    functions: usize,
    right: usize,
    wrong: usize,
    gone: usize,
    new: usize,
    /// Right and wrong, by the stage that paired them.
    stages: BTreeMap<String, (usize, usize)>,
}

fn firmware() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/openwrt")
}

fn debug_cache() -> PathBuf {
    Path::new(&std::env::var("HOME").expect("HOME is set")).join(".cache/hereticus-openwrt-debug")
}

/// The name of a function without the suffix of a GCC clone.
fn function_name(symbol: &str) -> &str {
    [".isra.", ".constprop.", ".part.", ".cold"]
        .iter()
        .filter_map(|suffix| symbol.find(suffix))
        .min()
        .map_or(symbol, |end| &symbol[..end])
}

/// The function symbols of a debug file, sorted by their start.
fn debug_symbols(path: &Path) -> Vec<Symbol> {
    use object::{Object, ObjectSymbol, SymbolKind};
    let data = std::fs::read(path)
        .unwrap_or_else(|err| panic!("{}: {err}; run `just test`", path.display()));
    let file = object::File::parse(&*data).expect("the debug file parses");
    let mut symbols: Vec<Symbol> = file
        .symbols()
        .filter(|symbol| symbol.kind() == SymbolKind::Text && symbol.size() > 0)
        .filter_map(|symbol| {
            let name = function_name(symbol.name().ok()?).to_owned();
            // A Thumb symbol has its low bit set.
            let start = symbol.address() & !1;
            Some((start, start + symbol.size(), name))
        })
        .collect();
    symbols.sort();
    symbols
}

/// The names of the symbols that overlap `range`.
fn names_in(symbols: &[Symbol], range: core::ops::Range<u64>) -> BTreeSet<&str> {
    let first = symbols.partition_point(|symbol| symbol.0 <= range.start).saturating_sub(1);
    symbols[first..]
        .iter()
        .take_while(|symbol| symbol.0 < range.end)
        .filter(|symbol| symbol.1 > range.start)
        .map(|symbol| symbol.2.as_str())
        .collect()
}

fn measure(board: &Board, older: &str, newer: &str) -> Tally {
    let kernels = [older, newer].map(|release| {
        let path = firmware().join(format!("{}-kernel-{release}.bin", board.name));
        let data = std::fs::read(&path)
            .unwrap_or_else(|err| panic!("{}: {err}; run `just firmware`", path.display()));
        Binary::parse_raw(&data, board.kernel_base, board.isa).expect("the kernel reads")
    });
    let symbols = [older, newer].map(|release| {
        debug_symbols(&debug_cache().join(release).join(board.target).join("vmlinux"))
    });

    let mut tally = Tally::default();
    for (kernel, symbols) in kernels.iter().zip(&symbols) {
        let starts: BTreeSet<u64> = symbols.iter().map(|symbol| symbol.0).collect();
        tally.functions += kernel.functions.len();
        tally.starts_on_symbol +=
            kernel.functions.iter().filter(|function| starts.contains(&function.address)).count();
    }

    let diff = diff_with(
        &kernels[0],
        &kernels[1],
        Options { use_names: UseNames::No, ..Default::default() },
    );
    tally.gone = diff.removed.len();
    tally.new = diff.added.len();
    let names = |side: usize, index: usize| {
        let function = &kernels[side].functions[index];
        names_in(&symbols[side], function.address..function.address + function.code.len() as u64)
    };
    for pair in &diff.matched {
        let (before, after) = (names(0, pair.before), names(1, pair.after));
        // A function that overlaps no symbol has no answer to check.
        if before.is_empty() || after.is_empty() {
            continue;
        }
        let stage = tally.stages.entry(format!("{:?}", pair.confidence)).or_default();
        if before.is_disjoint(&after) {
            tally.wrong += 1;
            stage.1 += 1;
        } else {
            tally.right += 1;
            stage.0 += 1;
        }
    }
    tally
}

fn percent(part: usize, whole: usize) -> f64 {
    100.0 * part as f64 / whole as f64
}

#[test]
fn the_kernel_pairs_checked_against_their_symbols_are_locked() {
    let cases: Vec<(&Board, &str, &str)> = RELEASES
        .iter()
        .flat_map(|&(older, newer, boards)| BOARDS[..boards].iter().map(move |b| (b, older, newer)))
        .collect();
    let tallies: Vec<Tally> =
        cases.par_iter().map(|&(board, older, newer)| measure(board, older, newer)).collect();

    let mut out = String::new();
    writeln!(
        out,
        "{:36} {:>7} {:>7} {:>6} {:>7} {:>6} {:>6}",
        "kernel", "starts", "right", "wrong", "wrong%", "gone", "new"
    )
    .unwrap();
    let mut stages: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let mut by_release: BTreeMap<(&str, &str), (usize, usize)> = BTreeMap::new();
    for (&(board, older, newer), tally) in cases.iter().zip(&tallies) {
        // Most recovered functions start on a symbol only when the debug
        // file belongs to the same build.
        let starts = percent(tally.starts_on_symbol, tally.functions);
        assert!(starts > 95.0, "{} {older}: the debug file is of another build", board.name);
        writeln!(
            out,
            "{:36} {starts:>6.1}% {:>7} {:>6} {:>6.2}% {:>6} {:>6}",
            format!("{} {older}/{newer}", board.name),
            tally.right,
            tally.wrong,
            percent(tally.wrong, tally.right + tally.wrong),
            tally.gone,
            tally.new
        )
        .unwrap();
        for (stage, &(right, wrong)) in &tally.stages {
            let sum = stages.entry(stage).or_default();
            sum.0 += right;
            sum.1 += wrong;
        }
        let sum = by_release.entry((older, newer)).or_default();
        sum.0 += tally.right;
        sum.1 += tally.wrong;
    }

    writeln!(out, "\n{:36} {:>7} {:>6} {:>7}", "releases", "right", "wrong", "wrong%").unwrap();
    let (mut right, mut wrong) = (0, 0);
    for (&(older, newer), &(r, w)) in &by_release {
        writeln!(
            out,
            "{:36} {r:>7} {w:>6} {:>6.2}%",
            format!("{older}/{newer}"),
            percent(w, r + w)
        )
        .unwrap();
        right += r;
        wrong += w;
    }
    writeln!(out, "{:36} {right:>7} {wrong:>6} {:>6.2}%", "all", percent(wrong, right + wrong))
        .unwrap();

    writeln!(out, "\n{:36} {:>7} {:>6} {:>7}", "stage", "right", "wrong", "wrong%").unwrap();
    for (stage, &(r, w)) in &stages {
        writeln!(out, "{stage:36} {r:>7} {w:>6} {:>6.2}%", percent(w, r + w)).unwrap();
    }
    insta::assert_snapshot!(out);
}
