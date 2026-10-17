//! Count the functions that this tool and Ghidra find in one raw kernel,
//! against the symbols of its build, and lock the counts.
//!
//! The kernel is OpenWrt 22.03.2 for the GL.iNet GL-MT300N v2, MIPS32
//! little-endian, read as a raw image with no symbols and no sections.
//! `just rivals-kernel` lets Ghidra analyse it twice: with its default
//! analyzers, and with the Aggressive Instruction Finder too. The `vmlinux`
//! that `fixtures/openwrt_debug.py` fetches says where each function
//! really starts.
//!
//! A start is **real** when a function symbol starts there. The second table
//! tells how the code reaches the real functions that this tool finds and
//! Ghidra does not: by a direct `jal`, or by an address that a data word
//! holds, as a table of callbacks does.
//!
//! Ghidra finds one function more or less from one run to the next, even on
//! one core: 0x8002ec24 comes and goes. A Ghidra count within
//! [`GHIDRA_JITTER`] of the locked one thus counts as the locked one, so the
//! snapshot, and the docs that quote it, change only when Ghidra really does.
//!
//! The inputs are about 50 MB and Ghidra takes minutes, so
//! `just quick-test` skips this test.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use hereticus::obj::{Binary, Isa};

#[path = "common/symbols.rs"]
mod symbols;
use symbols::debug_symbols;

const KERNEL: &str = "mipsel-mt300nv2-kernel-22.03.2.bin";
const KERNEL_BASE: u64 = 0x8000_0000;
const DEBUG: &str = "hereticus-openwrt-debug/22.03.2/ramips-mt76x8/vmlinux";

/// The Ghidra runs of `fixtures/rivals_kernel.sh`: the row name and the
/// file each writes.
const GHIDRA: &[(&str, &str)] =
    &[("ghidra default", "default"), ("ghidra aggressive", "aggressive")];

/// How far a count that rests on Ghidra can move from one run to the next.
const GHIDRA_JITTER: usize = 1;

/// The snapshot this test locks.
const SNAPSHOT: &str =
    "tests/snapshots/truth_function_starts__the_function_starts_of_a_raw_kernel_are_locked.snap";

/// The opcode of the MIPS `jal`, in bits 31 to 26.
const JAL: u32 = 3;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build")
}

fn kernel_bytes() -> Vec<u8> {
    let path = fixtures().join("openwrt").join(KERNEL);
    std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{}: {err}; run `just firmware`", path.display()))
}

/// The entries that Ghidra found with one setting.
fn ghidra_starts(setting: &str) -> BTreeSet<u64> {
    let path = fixtures().join("rivals/ghidra-kernel").join(format!("{setting}.txt"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("{}: {err}; run `just rivals-kernel`", path.display()))
        .lines()
        .map(|line| u64::from_str_radix(line.trim(), 16).expect("a hexadecimal entry"))
        .collect()
}

/// The targets of every `jal` in the image, and every value that an
/// aligned word holds.
///
/// A `jal` holds bits 27 to 2 of its target, and takes the rest from the
/// address of the instruction after it. The whole kernel lies in one
/// 256 MB region, so the base gives those bits.
fn jal_targets_and_words(image: &[u8]) -> (BTreeSet<u64>, BTreeSet<u64>) {
    let words: Vec<u32> =
        image.as_chunks::<4>().0.iter().map(|&word| u32::from_le_bytes(word)).collect();
    let jal_targets = words
        .iter()
        .filter(|&&word| word >> 26 == JAL)
        .map(|&word| (KERNEL_BASE & !0x0fff_ffff) | (u64::from(word & 0x03ff_ffff) << 2))
        .collect();
    let values = words.iter().map(|&word| u64::from(word)).collect();
    (jal_targets, values)
}

/// The counts of each row of the tables of a snapshot, by row name: the
/// numbers at the end of the row, in order.
fn locked_counts(snapshot: &str) -> BTreeMap<String, Vec<usize>> {
    snapshot
        .lines()
        .skip_while(|line| *line != "---")
        .skip(1)
        .skip_while(|line| *line != "---")
        .skip(1)
        .filter_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            let first_count = words.iter().position(|word| word.parse::<usize>().is_ok())?;
            let counts: Option<Vec<usize>> =
                words[first_count..].iter().map(|word| word.parse().ok()).collect();
            Some((words[..first_count].join(" "), counts?))
        })
        .collect()
}

/// The count to lock for one that rests on Ghidra: the locked count, if the
/// measured one is within [`GHIDRA_JITTER`] of it, and else the measured one,
/// so the snapshot fails.
fn settle(locked: Option<usize>, measured: usize) -> usize {
    match locked {
        Some(locked) if locked.abs_diff(measured) <= GHIDRA_JITTER => locked,
        _ => measured,
    }
}

fn percent(part: usize, whole: usize) -> f64 {
    100.0 * part as f64 / whole as f64
}

#[test]
fn the_function_starts_of_a_raw_kernel_are_locked() {
    let image = kernel_bytes();
    let kernel = Binary::parse_raw(&image, KERNEL_BASE, Isa::Mips32).expect("the kernel reads");
    let debug = Path::new(&std::env::var("HOME").expect("HOME is set")).join(".cache").join(DEBUG);
    let real: BTreeSet<u64> = debug_symbols(&debug).into_iter().map(|(start, ..)| start).collect();

    let ours: BTreeSet<u64> = kernel.functions.iter().map(|function| function.address).collect();
    let mut found = vec![("hereticus", ours.clone())];
    found.extend(GHIDRA.iter().map(|&(row, setting)| (row, ghidra_starts(setting))));

    let mut table =
        format!("{:18} {:>7} {:>6} {:>6} {:>8}\n", "tool", "symbols", "found", "real", "not real");
    let snapshot = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(SNAPSHOT))
        .unwrap_or_default();
    let locked = locked_counts(&snapshot);
    // The column of `locked` row `row`, where the measured count rests on Ghidra.
    let settled = |row: &str, column: usize, measured: usize| {
        if row == "hereticus" {
            return measured;
        }
        settle(locked.get(row).and_then(|counts| counts.get(column)).copied(), measured)
    };
    for (tool, starts) in &found {
        let hits = starts.intersection(&real).count();
        writeln!(
            table,
            "{tool:18} {:>7} {:>6} {:>6} {:>8}",
            real.len(),
            settled(tool, 1, starts.len()),
            settled(tool, 2, hits),
            settled(tool, 3, starts.len() - hits)
        )
        .unwrap();
    }

    let (jal_targets, words) = jal_targets_and_words(&image);
    writeln!(table, "\n{:24} {:>6} {:>5} {:>6}", "functions", "count", "jal%", "word%").unwrap();
    let ghidra = &found[1].1;
    let groups: [(&str, BTreeSet<u64>); 2] = [
        (
            "only hereticus finds",
            ours.intersection(&real).filter(|start| !ghidra.contains(start)).copied().collect(),
        ),
        ("ghidra default finds", ghidra.intersection(&real).copied().collect()),
    ];
    for (group, starts) in &groups {
        let called = starts.iter().filter(|start| jal_targets.contains(start)).count();
        let stored = starts.iter().filter(|start| words.contains(start)).count();
        // Both groups rest on Ghidra; the percentages round away a jitter of one.
        writeln!(
            table,
            "{group:24} {:>6} {:>5.0} {:>6.0}",
            settle(locked.get(*group).and_then(|counts| counts.first()).copied(), starts.len()),
            percent(called, starts.len()),
            percent(stored, starts.len())
        )
        .unwrap();
    }
    insta::assert_snapshot!(table);
}

#[test]
fn a_ghidra_count_within_the_jitter_settles_to_the_locked_one() {
    assert_eq!(settle(Some(13801), 13801), 13801);
    assert_eq!(settle(Some(13801), 13800), 13801);
    assert_eq!(settle(Some(13801), 13802), 13801);
}

#[test]
fn a_ghidra_count_past_the_jitter_or_with_no_lock_stays_as_measured() {
    assert_eq!(settle(Some(13801), 13799), 13799);
    assert_eq!(settle(Some(13801), 13803), 13803);
    assert_eq!(settle(None, 13800), 13800);
    assert_eq!(settle(Some(0), usize::MAX), usize::MAX);
}

#[test]
fn the_locked_counts_are_read_by_row() {
    let snapshot = "---\nsource: x\n---\ntool    symbols  found\n\
                    ghidra default  20988  13801\n\n\
                    functions  count  jal%\nonly hereticus finds  6097  5\n";
    let counts = locked_counts(snapshot);
    assert_eq!(counts.get("ghidra default"), Some(&vec![20988, 13801]));
    assert_eq!(counts.get("only hereticus finds"), Some(&vec![6097, 5]));
    assert_eq!(counts.get("tool"), None, "a heading has no counts");
    assert!(locked_counts("").is_empty());
}

#[test]
fn a_jal_names_its_target_and_a_word_its_value() {
    let target = 0x8012_3450_u32;
    let jal = (JAL << 26) | ((target >> 2) & 0x03ff_ffff);
    let pointer = 0x8000_0abc_u32;
    let not_a_jal = 0x2402_0001_u32; // `li v0, 1`
    let image: Vec<u8> =
        [jal, pointer, not_a_jal].iter().flat_map(|word| word.to_le_bytes()).collect();

    let (jal_targets, words) = jal_targets_and_words(&image);
    assert_eq!(jal_targets, BTreeSet::from([u64::from(target)]));
    assert_eq!(words, BTreeSet::from([u64::from(jal), u64::from(pointer), u64::from(not_a_jal)]));
}

#[test]
fn a_partial_word_at_the_end_is_not_read() {
    let (jal_targets, words) = jal_targets_and_words(&[0x0c, 0x00, 0x00]);
    assert!(jal_targets.is_empty() && words.is_empty());
}
