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
//! The inputs are about 50 MB and Ghidra takes minutes, so
//! `just quick-test` skips this test.

use std::collections::BTreeSet;
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
    for (tool, starts) in &found {
        let hits = starts.intersection(&real).count();
        writeln!(
            table,
            "{tool:18} {:>7} {:>6} {hits:>6} {:>8}",
            real.len(),
            starts.len(),
            starts.len() - hits
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
        writeln!(
            table,
            "{group:24} {:>6} {:>5.0} {:>6.0}",
            starts.len(),
            percent(called, starts.len()),
            percent(stored, starts.len())
        )
        .unwrap();
    }
    insta::assert_snapshot!(table);
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
