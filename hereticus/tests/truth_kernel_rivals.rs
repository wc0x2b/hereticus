//! Check the pairs of radiff2, Ghidra and this tool on the raw OpenWrt
//! kernels of the point release against the symbols of their builds, and
//! lock the counts.
//!
//! `just rivals-kernel-pairs` runs `fixtures/rivals_kernel_pairs.sh`, which
//! gives the kernels of 22.03.2 and 22.03.5 of each board to radiff2 and to
//! Ghidra Version Tracking, and writes every pair of functions each makes.
//! This test pairs the same kernels with this tool, as `tests/openwrt.rs`
//! does.
//!
//! Each tool finds other functions, so `tests/truth_kernels.rs`, which judges
//! the functions this tool finds, cannot judge the others. Here one rule
//! judges every pair of every tool by where its two functions start:
//!
//! * a pair is **judged** where a symbol of the debug file starts at each
//!   of its two starts;
//! * a judged pair is **right** where the two symbols share a name, and
//!   come from source files that correspond, as [`FileMoves`] says;
//! * every other judged pair is **wrong**.
//!
//! A point release keeps the same kernel, so few functions are renamed, and
//! the rule calls a renamed function wrong for each tool alike. A pair that
//! starts inside a function, as where a tool splits one, is not judged.
//!
//! The inputs are about 800 MB, and Ghidra takes about an hour, so
//! `just quick-test` skips this test.

/// See `ALLOCATOR` in `hereticus-cli/src/main.rs`.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use hereticus::matching::{Options, UseNames, diff_with};
use hereticus::obj::Binary;

#[path = "common/boards.rs"]
mod boards;
#[path = "common/dwarf.rs"]
mod dwarf;
#[path = "common/symbols.rs"]
mod symbols;
use boards::{BOARDS, Board};
use dwarf::{FileMoves, source_files};
use rayon::prelude::*;
use symbols::{Symbol, debug_symbols};

/// The point release whose kernels each tool compares, as
/// `fixtures/rivals_kernel_pairs.sh` names them.
const OLDER: &str = "22.03.2";
const NEWER: &str = "22.03.5";

/// A tool whose pairs this test judges.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Tool {
    Hereticus,
    Radare2,
    Ghidra,
}

impl Tool {
    const ALL: [Tool; 3] = [Tool::Hereticus, Tool::Radare2, Tool::Ghidra];

    fn name(self) -> &'static str {
        match self {
            Self::Hereticus => "hereticus",
            Self::Radare2 => "radare2",
            Self::Ghidra => "ghidra",
        }
    }
}

/// The starts of a pair, before and after, and what the rule says of it.
type Judged = ((u64, u64), Verdict);

/// What the rule says of one pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// A start of the pair is not the start of a symbol.
    OffSymbols,
    Right,
    Wrong,
}

/// The verdicts of the pairs of one tool on one board.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Tally {
    pairs: usize,
    right: usize,
    wrong: usize,
}

impl Tally {
    fn add(&mut self, verdict: Verdict) {
        self.pairs += 1;
        match verdict {
            Verdict::OffSymbols => {}
            Verdict::Right => self.right += 1,
            Verdict::Wrong => self.wrong += 1,
        }
    }

    fn judged(self) -> usize {
        self.right + self.wrong
    }
}

impl core::ops::AddAssign for Tally {
    fn add_assign(&mut self, other: Tally) {
        self.pairs += other.pairs;
        self.right += other.right;
        self.wrong += other.wrong;
    }
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures")
}

fn debug_file(release: &str, board: &Board) -> PathBuf {
    Path::new(&std::env::var("HOME").expect("HOME is set"))
        .join(".cache/hereticus-openwrt-debug")
        .join(release)
        .join(board.target)
        .join("vmlinux")
}

/// What the debug files of one board say of its two kernels.
struct Answer {
    symbols: [Vec<Symbol>; 2],
    sources: [Vec<Symbol>; 2],
}

impl Answer {
    fn of(board: &Board) -> Self {
        let releases = [OLDER, NEWER];
        Self {
            symbols: releases.map(|release| debug_symbols(&debug_file(release, board))),
            sources: releases.map(|release| source_files(&debug_file(release, board))),
        }
    }
}

/// The names of the symbols of `symbols` that start at `address`.
fn names_at(symbols: &[Symbol], address: u64) -> BTreeSet<&str> {
    let first = symbols.partition_point(|symbol| symbol.0 < address);
    symbols[first..]
        .iter()
        .take_while(|symbol| symbol.0 == address)
        .map(|symbol| symbol.2.as_str())
        .collect()
}

/// The source files of the functions that overlap `address`.
fn files_at(sources: &[Symbol], address: u64) -> BTreeSet<&str> {
    let first = sources.partition_point(|source| source.0 <= address).saturating_sub(1);
    sources[first..]
        .iter()
        .take_while(|source| source.0 <= address)
        .filter(|source| address < source.1)
        .map(|source| source.2.as_str())
        .collect()
}

/// Judge the pair of the functions that start at `before` and `after`.
fn judge(answer: &Answer, moves: &FileMoves, before: u64, after: u64) -> Verdict {
    let names = [names_at(&answer.symbols[0], before), names_at(&answer.symbols[1], after)];
    if names.iter().any(BTreeSet::is_empty) {
        return Verdict::OffSymbols;
    }
    if names[0].is_disjoint(&names[1]) {
        return Verdict::Wrong;
    }
    let files = [files_at(&answer.sources[0], before), files_at(&answer.sources[1], after)];
    let files_known = files.iter().all(|files| !files.is_empty());
    let same_file = files[0]
        .iter()
        .any(|&before| files[1].iter().any(|&after| moves.corresponds(before, after)));
    match files_known && !same_file {
        // Two static functions of one name, as the `probe` of two drivers.
        true => Verdict::Wrong,
        false => Verdict::Right,
    }
}

/// The starts of each pair of this tool, run as `tests/openwrt.rs` runs it.
fn hereticus_pairs(board: &Board) -> Vec<(u64, u64)> {
    let kernels = [OLDER, NEWER].map(|release| {
        let path = fixtures().join(format!("build/openwrt/{}-kernel-{release}.bin", board.name));
        let data = std::fs::read(&path)
            .unwrap_or_else(|err| panic!("{}: {err}; run `just firmware`", path.display()));
        Binary::parse_raw(&data, board.kernel_base, board.isa).expect("the kernel reads")
    });
    let diff = diff_with(
        &kernels[0],
        &kernels[1],
        Options { use_names: UseNames::No, ..Default::default() },
    );
    diff.matched
        .iter()
        .map(|pair| {
            (kernels[0].functions[pair.before].address, kernels[1].functions[pair.after].address)
        })
        .collect()
}

/// The pairs that `fixtures/rivals_kernel_pairs.sh` wrote for `tool`.
fn rival_pairs(tool: Tool, board: &Board) -> Vec<(u64, u64)> {
    let path = fixtures()
        .join("build/rivals")
        .join(format!("{}-kernels", tool.name()))
        .join(format!("{}.json", board.name));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("{}: {err}, run `just rivals-kernel-pairs` first", path.display())
    });
    let report: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    report["pairs"]
        .as_array()
        .expect("the pairs are a list")
        .iter()
        .map(|pair| {
            let address = |at: usize| pair[at].as_u64().expect("an address");
            (address(0), address(1))
        })
        .collect()
}

fn pairs_of(tool: Tool, board: &Board) -> Vec<(u64, u64)> {
    match tool {
        Tool::Hereticus => hereticus_pairs(board),
        Tool::Radare2 | Tool::Ghidra => rival_pairs(tool, board),
    }
}

/// The tally of each tool on `board`.
/// What Ghidra does with the functions that this tool pairs wrong: how
/// many it pairs right, how many wrong, and how many it pairs with no
/// judged function or with none.
#[derive(Clone, Copy, Debug, Default)]
struct Crossed {
    right: usize,
    wrong: usize,
    unpaired: usize,
}

impl core::ops::AddAssign for Crossed {
    fn add_assign(&mut self, other: Crossed) {
        self.right += other.right;
        self.wrong += other.wrong;
        self.unpaired += other.unpaired;
    }
}

/// The tally of each tool on `board`, and what Ghidra does with the
/// functions that this tool pairs wrong.
fn measure(board: &Board) -> (BTreeMap<Tool, Tally>, Crossed) {
    let answer = Answer::of(board);
    let moves = FileMoves::new(&answer.symbols, &answer.sources);
    // A Thumb entry can carry bit 0, which is no part of where the code
    // lies.
    let judged = |(before, after): (u64, u64)| {
        ((before, after), judge(&answer, &moves, before & !1, after & !1))
    };
    let verdicts: BTreeMap<Tool, Vec<Judged>> = Tool::ALL
        .into_iter()
        .map(|tool| (tool, pairs_of(tool, board).into_iter().map(judged).collect()))
        .collect();
    let tallies = verdicts
        .iter()
        .map(|(&tool, verdicts)| {
            let mut tally = Tally::default();
            verdicts.iter().for_each(|&(_, verdict)| tally.add(verdict));
            (tool, tally)
        })
        .collect();

    let ghidra: BTreeMap<u64, Verdict> =
        verdicts[&Tool::Ghidra].iter().map(|&((before, _), verdict)| (before, verdict)).collect();
    let mut crossed = Crossed::default();
    for &((before, _), verdict) in &verdicts[&Tool::Hereticus] {
        if verdict != Verdict::Wrong {
            continue;
        }
        match ghidra.get(&before) {
            Some(Verdict::Right) => crossed.right += 1,
            Some(Verdict::Wrong) => crossed.wrong += 1,
            Some(Verdict::OffSymbols) | None => crossed.unpaired += 1,
        }
    }
    (tallies, crossed)
}

fn percent(part: usize, whole: usize) -> f64 {
    100.0 * part as f64 / whole as f64
}

fn row(out: &mut String, label: &str, tally: Tally) {
    writeln!(
        out,
        "{label:28} {:>7} {:>7} {:>7} {:>6} {:>7.2}%",
        tally.pairs,
        tally.judged(),
        tally.right,
        tally.wrong,
        percent(tally.wrong, tally.judged())
    )
    .unwrap();
}

#[test]
fn the_kernel_pairs_of_each_tool_checked_against_the_symbols_are_locked() {
    let (tallies, crossed): (Vec<BTreeMap<Tool, Tally>>, Vec<Crossed>) =
        BOARDS.par_iter().map(measure).unzip();

    let heading = |label: &str| {
        format!(
            "{label:28} {:>7} {:>7} {:>7} {:>6} {:>8}\n",
            "pairs", "judged", "right", "wrong", "wrong%"
        )
    };
    let mut out = heading("kernel");
    let mut all: BTreeMap<Tool, Tally> = BTreeMap::new();
    for (board, tallies) in BOARDS.iter().zip(&tallies) {
        for (&tool, &tally) in tallies {
            row(&mut out, &format!("{} {}", board.name, tool.name()), tally);
            *all.entry(tool).or_default() += tally;
        }
    }
    out += "\n";
    out += &heading("tool");
    for (tool, tally) in &all {
        row(&mut out, &format!("all {}", tool.name()), *tally);
    }

    // Where Ghidra makes fewer wrong pairs, these say whether it pairs the
    // same functions right, or leaves them.
    writeln!(
        out,
        "\n{:28} {:>12} {:>12} {:>15}",
        "hereticus-wrong", "ghidra-right", "ghidra-wrong", "ghidra-unpaired"
    )
    .unwrap();
    let mut all_crossed = Crossed::default();
    for (board, &one) in BOARDS.iter().zip(&crossed) {
        all_crossed += one;
        writeln!(out, "{:28} {:>12} {:>12} {:>15}", board.name, one.right, one.wrong, one.unpaired)
            .unwrap();
    }
    let Crossed { right, wrong, unpaired } = all_crossed;
    writeln!(out, "{:28} {right:>12} {wrong:>12} {unpaired:>15}", "all").unwrap();
    insta::assert_snapshot!(out);
}

#[test]
fn a_pair_judges_by_the_symbols_at_its_starts() {
    let symbol = |start: u64, name: &str| (start, start + 0x10, name.to_owned());
    let answer = Answer {
        symbols: [
            vec![symbol(0x100, "probe"), symbol(0x200, "init"), symbol(0x300, "read")],
            vec![symbol(0x110, "probe"), symbol(0x210, "init"), symbol(0x310, "write")],
        ],
        sources: [
            vec![symbol(0x100, "a.c"), symbol(0x200, "b.c"), symbol(0x300, "a.c")],
            vec![symbol(0x110, "a.c"), symbol(0x210, "c.c"), symbol(0x310, "a.c")],
        ],
    };
    let moves = FileMoves::new(&answer.symbols, &answer.sources);
    assert_eq!(judge(&answer, &moves, 0x100, 0x110), Verdict::Right);
    assert_eq!(judge(&answer, &moves, 0x300, 0x310), Verdict::Wrong);
    // Two functions of one name from files that do not correspond.
    assert_eq!(judge(&answer, &moves, 0x200, 0x210), Verdict::Wrong);
    // A start inside a function.
    assert_eq!(judge(&answer, &moves, 0x104, 0x110), Verdict::OffSymbols);
    assert_eq!(judge(&answer, &moves, 0x100, 0x400), Verdict::OffSymbols);
}

#[test]
fn the_names_at_an_address_are_those_of_the_symbols_that_start_there() {
    let symbols = vec![
        (0x100, 0x120, "alias".to_owned()),
        (0x100, 0x120, "name".to_owned()),
        (0x120, 0x130, "next".to_owned()),
    ];
    assert_eq!(names_at(&symbols, 0x100), BTreeSet::from(["alias", "name"]));
    assert_eq!(names_at(&symbols, 0x110), BTreeSet::new());
    assert_eq!(names_at(&symbols, 0x130), BTreeSet::new());
    assert_eq!(names_at(&[], 0x100), BTreeSet::new());
}
