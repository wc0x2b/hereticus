//! Check the pairs of the OpenWrt kernels of `tests/openwrt.rs` against the
//! symbols of their builds, and lock the counts.
//!
//! OpenWrt publishes the `vmlinux` of each kernel it builds, with symbols and
//! DWARF and without code. `fixtures/openwrt_debug.py` fetches it and pins
//! it by its SHA-256, so the counts below tell how often the tool pairs a
//! function of a shipped, stripped kernel with the right one.
//!
//! Each pair gets a [`Verdict`]. A pair is right when the two functions
//! overlap a symbol of the same name from the same source file, as the
//! DWARF says: a name alone can belong to two static functions. A pair
//! whose names differ is not wrong by that alone: between kernel releases,
//! functions are renamed (`generic_make_request` became
//! `submit_bio_noacct`), and code moves into a new function
//! (`sock_init_data` into `sock_init_data_uid`). So the source file, the
//! names of the callers and the callees, which the tool never reads, and
//! the function that holds each name on the other side decide the rest.
//!
//! The inputs are about 800 MB, so `just quick-test` skips this test.

/// See `ALLOCATOR` in `hereticus-cli/src/main.rs`.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use hereticus::arch::decode_all;
use hereticus::callee::{Callee, callees};
use hereticus::matching::{Match, Options, UseNames, diff_with, similarity};
use hereticus::norm::{NormInsn, normalize_body_in};
use hereticus::obj::{Binary, Isa};

#[path = "common/dwarf.rs"]
mod dwarf;
use dwarf::{FileMoves, source_files};
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

/// What the symbols say of one pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Verdict {
    /// The two functions share a name and a source file.
    Right,
    /// The names differ, but the code went with the new name. One of the
    /// names is gone from the other side, no function that holds either
    /// name is closer to the other side than the pair is, the callers and
    /// callees agree by name, and the two come from the same source file
    /// where the debug file says.
    Renamed,
    /// As [`Self::Renamed`], but with too few callers and callees to agree
    /// or not: only the source file says the two may be one function. A
    /// large file holds many unrelated functions, and of these pairs about
    /// one in five read as wrong to a person.
    Unproven,
    /// The names differ, and the function that holds a name on the other
    /// side has the same normalized instructions as the one paired. Only the
    /// names tell the two apart, and the tool reads none.
    Twin,
    /// The two functions share a name but come from different source
    /// files: two static functions of one name, as two drivers' `probe`.
    Homonym,
    /// Anything else.
    Wrong,
}

/// How many verdicts of each kind, indexed by [`Verdict`].
type Counts = [usize; 6];

/// The share of callers and callees, by name, two functions must have in
/// common to count as renamed.
///
/// Over the pairs that share a name, 91% have at least half in common, and
/// 1% have none.
const SAME_NEIGHBOURS: f64 = 0.5;

/// The fewest callers and callees, by name, over both functions, for their
/// overlap to count.
///
/// An init function calls only a few common helpers, so two unrelated ones
/// can share all their neighbours.
const FEWEST_NEIGHBOURS: usize = 4;

/// The pairs of one kernel upgrade, checked against the symbols.
#[derive(Default)]
struct Tally {
    /// Recovered functions that start where a symbol does, over both sides.
    starts_on_symbol: usize,
    functions: usize,
    verdicts: Counts,
    gone: usize,
    new: usize,
    /// The verdicts, by the stage that paired them.
    stages: BTreeMap<String, Counts>,
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

/// One kernel and what its debug file says of it.
struct Side<'a> {
    kernel: &'a Binary,
    symbols: &'a [Symbol],
    /// The source file of each function the debug file describes.
    sources: &'a [Symbol],
    /// The index of the function that starts at each address.
    by_start: BTreeMap<u64, usize>,
    /// The names of the callers, as `<name`, and of the callees, as
    /// `>name`, of each function.
    neighbours: Vec<BTreeSet<String>>,
}

impl<'a> Side<'a> {
    fn new(kernel: &'a Binary, symbols: &'a [Symbol], sources: &'a [Symbol]) -> Self {
        let by_start =
            kernel.functions.iter().enumerate().map(|(index, f)| (f.address, index)).collect();
        let mut side = Self { kernel, symbols, sources, by_start, neighbours: Vec::new() };
        let calls: Vec<Vec<usize>> = kernel
            .functions
            .par_iter()
            .map(|function| {
                let arch = kernel.isa_of(function).arch();
                callees(arch, &kernel.links, &kernel.functions, function)
                    .into_iter()
                    .filter_map(|callee| match callee {
                        Callee::Function(index) => Some(index),
                        Callee::Named(_) | Callee::Unknown => None,
                    })
                    .collect()
            })
            .collect();
        let mut neighbours = vec![BTreeSet::new(); kernel.functions.len()];
        for (caller, called) in calls.iter().enumerate() {
            for &callee in called {
                if let Some(name) = side.name_at_start(callee) {
                    neighbours[caller].insert(format!(">{name}"));
                }
                if let Some(name) = side.name_at_start(caller) {
                    neighbours[callee].insert(format!("<{name}"));
                }
            }
        }
        side.neighbours = neighbours;
        side
    }

    /// The names of the symbols that overlap a function.
    fn names(&self, index: usize) -> BTreeSet<&'a str> {
        let function = &self.kernel.functions[index];
        names_in(self.symbols, function.address..function.address + function.code.len() as u64)
    }

    /// The source files of the functions of the debug file that overlap a
    /// function.
    fn files(&self, index: usize) -> BTreeSet<&'a str> {
        let function = &self.kernel.functions[index];
        names_in(self.sources, function.address..function.address + function.code.len() as u64)
    }

    fn name_at_start(&self, index: usize) -> Option<&'a str> {
        let start = self.kernel.functions[index].address;
        names_in(self.symbols, start..start + 1).into_iter().next()
    }

    /// The function that starts on a symbol named one of `names`.
    fn holder(&self, names: &BTreeSet<&str>) -> Option<usize> {
        self.symbols
            .iter()
            .filter(|symbol| names.contains(symbol.2.as_str()))
            .find_map(|symbol| self.by_start.get(&symbol.0).copied())
    }

    fn body(&self, index: usize) -> Vec<NormInsn> {
        let function = &self.kernel.functions[index];
        let arch = self.kernel.isa_of(function).arch();
        let (insns, _) = decode_all(arch, &function.code, function.address);
        normalize_body_in(arch, &function.code, &insns, &self.kernel.addresses)
    }
}

/// Judge one pair of functions whose names are `names`, both known.
fn judge(
    sides: &[Side; 2],
    moves: &FileMoves,
    pair: &Match,
    names: &[BTreeSet<&str>; 2],
) -> Verdict {
    let files = [sides[0].files(pair.before), sides[1].files(pair.after)];
    let files_known = files.iter().all(|files| !files.is_empty());
    let same_file = files[0]
        .iter()
        .any(|&before| files[1].iter().any(|&after| moves.corresponds(before, after)));
    if !names[0].is_disjoint(&names[1]) {
        return if files_known && !same_file { Verdict::Homonym } else { Verdict::Right };
    }
    let indices = [pair.before, pair.after];
    let bodies = [sides[0].body(pair.before), sides[1].body(pair.after)];
    let paired = similarity(&bodies[0], &bodies[1]);
    let mut followed_the_code = true;
    let mut names_held = 0;
    for (from, to) in [(0, 1), (1, 0)] {
        // The function on side `to` that holds the name of side `from`.
        let Some(holder) = sides[to].holder(&names[from]) else { continue };
        names_held += 1;
        let held = sides[to].body(holder);
        if held == bodies[to] {
            return Verdict::Twin;
        }
        followed_the_code &= paired >= similarity(&bodies[from], &held);
    }
    // Both functions live on under their own names, so the pair crossed
    // them.
    if names_held == 2 || !followed_the_code {
        return Verdict::Wrong;
    }
    if files_known && !same_file {
        return Verdict::Wrong;
    }
    // The callers and callees decide where there are enough of them.
    let [before, after] = [0, 1].map(|side| &sides[side].neighbours[indices[side]]);
    let all = before.union(after).count();
    let common = before.intersection(after).count();
    if all < FEWEST_NEIGHBOURS {
        return if files_known { Verdict::Unproven } else { Verdict::Wrong };
    }
    if common as f64 >= SAME_NEIGHBOURS * all as f64 { Verdict::Renamed } else { Verdict::Wrong }
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
    let sources = [older, newer].map(|release| {
        source_files(&debug_cache().join(release).join(board.target).join("vmlinux"))
    });
    let moves = FileMoves::new(&symbols, &sources);
    let sides = [
        Side::new(&kernels[0], &symbols[0], &sources[0]),
        Side::new(&kernels[1], &symbols[1], &sources[1]),
    ];
    let judged: Vec<(String, Verdict)> = diff
        .matched
        .par_iter()
        .filter_map(|pair| {
            let names = [sides[0].names(pair.before), sides[1].names(pair.after)];
            // A function that overlaps no symbol has no answer to check.
            if names.iter().any(BTreeSet::is_empty) {
                return None;
            }
            Some((format!("{:?}", pair.confidence), judge(&sides, &moves, pair, &names)))
        })
        .collect();
    for (stage, verdict) in judged {
        tally.verdicts[verdict as usize] += 1;
        tally.stages.entry(stage).or_default()[verdict as usize] += 1;
    }
    tally
}

fn add(sum: &mut Counts, counts: &Counts) {
    sum.iter_mut().zip(counts).for_each(|(sum, count)| *sum += count);
}

/// Write one row of counts: the verdicts, and the share of the wrong.
fn row(out: &mut String, label: &str, counts: &Counts) {
    let [right, renamed, unproven, twin, homonym, wrong] = *counts;
    let judged: usize = counts.iter().sum();
    writeln!(
        out,
        "{label:36} {right:>7} {renamed:>7} {unproven:>8} {twin:>5} {homonym:>7} {wrong:>6} \
         {:>6.2}% {:>6.2}%",
        percent(homonym + wrong, judged),
        percent(homonym + wrong + unproven, judged)
    )
    .unwrap();
}

/// The heading of the rows [`row`] writes.
fn heading(out: &mut String, label: &str) {
    writeln!(
        out,
        "\n{label:36} {:>7} {:>7} {:>8} {:>5} {:>7} {:>6} {:>7} {:>7}",
        "right", "renamed", "unproven", "twin", "homonym", "wrong", "wrong%", "at most"
    )
    .unwrap();
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
    writeln!(out, "{:36} {:>7} {:>6} {:>6}", "kernel", "starts", "gone", "new").unwrap();
    for (&(board, older, _), tally) in cases.iter().zip(&tallies) {
        // Most recovered functions start on a symbol only when the debug
        // file belongs to the same build.
        let starts = percent(tally.starts_on_symbol, tally.functions);
        assert!(starts > 95.0, "{} {older}: the debug file is of another build", board.name);
    }
    for (&(board, older, newer), tally) in cases.iter().zip(&tallies) {
        let starts = percent(tally.starts_on_symbol, tally.functions);
        writeln!(
            out,
            "{:36} {starts:>6.1}% {:>6} {:>6}",
            format!("{} {older}/{newer}", board.name),
            tally.gone,
            tally.new
        )
        .unwrap();
    }

    heading(&mut out, "kernel");
    let mut stages: BTreeMap<&str, Counts> = BTreeMap::new();
    let mut by_release: BTreeMap<(&str, &str), Counts> = BTreeMap::new();
    let mut all = Counts::default();
    for (&(board, older, newer), tally) in cases.iter().zip(&tallies) {
        row(&mut out, &format!("{} {older}/{newer}", board.name), &tally.verdicts);
        for (stage, counts) in &tally.stages {
            add(stages.entry(stage).or_default(), counts);
        }
        add(by_release.entry((older, newer)).or_default(), &tally.verdicts);
        add(&mut all, &tally.verdicts);
    }

    heading(&mut out, "releases");
    for (&(older, newer), counts) in &by_release {
        row(&mut out, &format!("{older}/{newer}"), counts);
    }
    row(&mut out, "all", &all);

    heading(&mut out, "stage");
    for (stage, counts) in &stages {
        row(&mut out, stage, counts);
    }
    insta::assert_snapshot!(out);
}
