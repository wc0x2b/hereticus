//! What the relocations of MIPS code name of the address of data. The
//! relocations of o32 keep their addends in the instructions, so the two
//! halves of an address, at a `lui` and at the instruction that adds the
//! lower half, give the addend only as a pair.

use std::collections::BTreeMap;

use object::elf::{R_MIPS_32, R_MIPS_GPREL16, R_MIPS_HI16, R_MIPS_LO16, RelocationType};
use object::{RelocationFlags, RelocationTarget};

use crate::relocation::{DataReference, Part, Width, implicit_addend};

/// What each relocation of `relocations`, of a code section, names of the
/// address of data. `word` reads the instruction at an offset.
pub(super) fn data_references(
    relocations: &[(u64, object::Relocation)],
    word: &dyn Fn(u64) -> Option<u64>,
) -> Vec<DataReference> {
    let pairs = pairs(relocations, word);
    relocations
        .iter()
        .filter_map(|&(offset, ref relocation)| {
            let RelocationTarget::Symbol(symbol) = relocation.target() else { return None };
            let RelocationFlags::Elf { r_type } = relocation.flags() else { return None };
            let half = match r_type {
                R_MIPS_HI16 => Some(Half::Upper),
                R_MIPS_LO16 => Some(Half::Lower),
                _ => None,
            };
            let (addend, part) = match (relocation.has_implicit_addend(), r_type, half) {
                (false, R_MIPS_32, _) => (relocation.addend(), Part::Word(Width::Four)),
                (false, R_MIPS_GPREL16, _) => (relocation.addend(), Part::Low),
                (false, _, Some(Half::Upper)) => (relocation.addend(), Part::UpperOfPair),
                (false, _, Some(Half::Lower)) => (relocation.addend(), Part::LowerOfPair),
                (true, R_MIPS_32, _) => (implicit_addend(word, offset), Part::Word(Width::Four)),
                (true, R_MIPS_GPREL16, _) => {
                    (i64::from(word(offset).unwrap_or(0) as u16 as i16), Part::Low)
                }
                (true, _, Some(half)) => {
                    let pair = pairs.get(&offset)?;
                    (pair.addend, pair.part(half))
                }
                _ => return None,
            };
            Some(DataReference { offset, symbol, addend, part })
        })
        .collect()
}

/// A pair of `R_MIPS_HI16` and `R_MIPS_LO16` relocations, as [`pairs`]
/// reads it.
struct Pair {
    /// The addend the pair holds in the immediates of its two instructions.
    addend: i64,
    /// What the instruction of the relocation does with the lower half. For
    /// a `lui`, [`LowerHalf::Adds`] where each instruction that adds a lower
    /// half to it adds it.
    lower: LowerHalf,
}

/// What an instruction does with the lower half of a pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LowerHalf {
    /// Adds it, as `addiu` does.
    Adds,
    /// Reads or writes at the address, as a load or a store does, as `lw`.
    Accesses,
}

/// Which half of an address a relocation of a pair gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Half {
    /// `R_MIPS_HI16`, at a `lui`.
    Upper,
    /// `R_MIPS_LO16`.
    Lower,
}

impl Pair {
    /// What the instruction of `half`, one of the pair, holds of the
    /// address. An `addiu` shows the whole address, as on any architecture,
    /// and the `lui` of only such adds a page. A load or a store, which can
    /// add an index between, shows no offset, and its `lui` the whole
    /// address.
    fn part(&self, half: Half) -> Part {
        match (half, self.lower) {
            (Half::Upper, LowerHalf::Adds) => Part::High,
            (Half::Upper, LowerHalf::Accesses) => Part::UpperOfPair,
            (Half::Lower, LowerHalf::Adds) => Part::Low,
            (Half::Lower, LowerHalf::Accesses) => Part::LowerOfPair,
        }
    }
}

/// The pair of `R_MIPS_HI16` and `R_MIPS_LO16` relocations that each of
/// them in `relocations`, of one code section, is part of, by its offset.
/// `word` reads the instruction at an offset.
///
/// An `R_MIPS_LO16` pairs with the last `lui` before it, in the code, of
/// its symbol and into the register its instruction adds to or reads at.
/// The relocation table need not list them in pairs: in a module of
/// OpenWrt, a `lui` comes after the lower halves it pairs with.
fn pairs(
    relocations: &[(u64, object::Relocation)],
    word: &dyn Fn(u64) -> Option<u64>,
) -> BTreeMap<u64, Pair> {
    /// The opcodes of `addiu` and `addi`, in the top six bits of a word.
    const ADDS: [u64; 2] = [0x09, 0x08];
    let of_type = |relocation: &object::Relocation, r_type: RelocationType| {
        relocation.flags() == RelocationFlags::Elf { r_type }
    };
    // Each half, in the order of the code: its offset, its symbol, the
    // register it writes or reads, and its word.
    let mut halves: Vec<(u64, RelocationTarget, u64, u64, bool)> = relocations
        .iter()
        .filter_map(|(offset, relocation)| {
            let high = of_type(relocation, object::elf::R_MIPS_HI16);
            if !high && !of_type(relocation, object::elf::R_MIPS_LO16) {
                return None;
            }
            let word = word(*offset)?;
            // A `lui` writes `rt`; an `addiu` and a load read `rs`.
            let register = if high { word >> 16 & 0x1f } else { word >> 21 & 0x1f };
            Some((*offset, relocation.target(), register, word, high))
        })
        .collect();
    halves.sort_by_key(|half| half.0);
    // The `lui` of each lower half.
    let mut high_of: BTreeMap<u64, u64> = BTreeMap::new();
    for (at, &(offset, target, register, _, high)) in halves.iter().enumerate() {
        if high {
            continue;
        }
        let lui = halves[..at].iter().rev().find(|&&(_, other, written, _, is_high)| {
            is_high && other == target && written == register
        });
        if let Some(&(lui, ..)) = lui {
            high_of.insert(offset, lui);
        }
    }
    let word_at: BTreeMap<u64, u64> = halves.iter().map(|half| (half.0, half.3)).collect();
    let lower = |offset: u64| match word_at.get(&offset) {
        Some(word) if ADDS.contains(&(word >> 26)) => LowerHalf::Adds,
        _ => LowerHalf::Accesses,
    };
    // The halves add in 32 bits: `lui 0xffff` is the upper half of -0x10000.
    let addend = |high: Option<u64>, low: Option<u64>| {
        let upper = high
            .and_then(|high| word_at.get(&high))
            .map_or(0, |&word| (word as u32 & 0xffff) << 16);
        let lower = low
            .and_then(|low| word_at.get(&low))
            .map_or(0, |&word| word as u16 as i16 as i32 as u32);
        i64::from(upper.wrapping_add(lower) as i32)
    };
    let mut pairs = BTreeMap::new();
    for &(offset, _, _, _, high) in &halves {
        let pair = match high {
            true => {
                let lows: Vec<u64> = high_of
                    .iter()
                    .filter(|&(_, &lui)| lui == offset)
                    .map(|(&low, _)| low)
                    .collect();
                let adds =
                    !lows.is_empty() && lows.iter().all(|&low| lower(low) == LowerHalf::Adds);
                Pair {
                    addend: addend(Some(offset), lows.first().copied()),
                    lower: if adds { LowerHalf::Adds } else { LowerHalf::Accesses },
                }
            }
            false => Pair {
                addend: addend(high_of.get(&offset).copied(), Some(offset)),
                lower: lower(offset),
            },
        };
        pairs.insert(offset, pair);
    }
    pairs
}
