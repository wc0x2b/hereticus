//! Thumb-2 (T32) decoding, on top of `yaxpeax-arm`.
//!
//! T32 mixes instructions of 16 and 32 bits. Most of what [`Arm32`] knows
//! holds here too: the registers, the prologue, the literal pools, the
//! exception index and the PLT, whose stubs are A32 even in a T32 library.
//! So [`Thumb2`] asks [`Arm32`] wherever the two agree, and differs where
//! T32 does:
//!
//! * `pc` reads 4 bytes ahead, not 8, and a load from `[pc, imm]` rounds it
//!   down to a word first.
//! * `it` makes up to four instructions after it conditional, so a `bx lr`
//!   among them is an early exit, not the end of the function.
//! * `cbz` and `cbnz` branch on a register, and `tbb` and `tbh` jump through
//!   a table of distances that follows them.
//! * A pointer to a T32 function has bit 0 set, which is not part of its
//!   address.
//!
//! A binary that mixes A32 and T32 functions is read as one or the other.

pub use hereticus_il::arch::thumb::*;

use super::arm32::{
    Arm32, Decoded, Flags, PcModel, UNWIND_SECTION, call_targets_through_thunks, core_opcode,
    is_long_thunk, pool_loads, track_pool_words,
};
use super::{
    DataAmongCode, Decoder, Insn, InsnKind, JumpTable, Memory, Recovery, TableJumps, VectorTable,
};
use crate::address::{AddressSpace, ConstantKind};
use core::ops::Range;
use std::collections::BTreeSet;
use yaxpeax_arm::armv7::{ConditionCode, Opcode};

/// `bx pc` and `b.n` back, little endian: the T32 words GNU `ld` puts before
/// an A32 PLT stub that T32 code calls.
const THUMB_STUB_PREFIX: [u8; 4] = [0x78, 0x47, 0xfd, 0xe7];

/// More cases than any `switch` a compiler turns into one table.
const MOST_CASES: usize = 1024;

/// How far back the bound of a table may lie.
const TABLE_LOOK_BACK: usize = 16;

/// The halfwords a linker pads T32 code with, little endian: `nop`, the
/// older `mov r8, r8`, and the `0xd4d4` that LLD fills gaps with.
///
/// Not zeros: a function that ends with a pool can end with the upper half
/// of a small word. Measured on Lua built by GCC for Thumb-2, trimming zeros
/// cut 170 functions two bytes short.
const PADDING: [[u8; 2]; 3] = [[0x00, 0xbf], [0xc0, 0x46], [0xd4, 0xd4]];

impl Recovery for Thumb2 {
    /// T32 has no condition field to test, so the first instruction must
    /// read as one and not as padding.
    fn can_open_function(&self, bytes: &[u8]) -> bool {
        self.decode(bytes, 0, 0)
            .is_ok_and(|insn| insn.kind != InsnKind::Unknown && !self.is_padding(&insn))
    }

    fn data_addresses(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        memory: &Memory<'_>,
    ) -> Vec<u64> {
        match split_at_switch(code, body) {
            Some((offset, index)) => {
                let mut addresses =
                    track_pool_words(code, &body[..index], space, PcModel::T32).addresses;
                addresses.extend(Arm32.data_addresses(
                    &code[offset..],
                    &body[index..],
                    space,
                    memory,
                ));
                addresses
            }
            None => track_pool_words(code, body, space, PcModel::T32).addresses,
        }
    }

    fn literal_pool_words(&self, insns: &[Insn]) -> Vec<u64> {
        loads_outside_tables(insns).into_iter().map(|(_, word)| word).collect()
    }

    fn literal_pool_loads(&self, insns: &[Insn]) -> Vec<(u64, u64)> {
        loads_outside_tables(insns)
    }

    fn data_among_code(&self) -> DataAmongCode {
        DataAmongCode::LiteralPools
    }

    fn is_unread_extension(&self, insn: &Insn) -> bool {
        Arm32.is_unread_extension(insn)
    }

    /// `tbb [pc, rI]` and `tbh [pc, rI, lsl 1]` read a table of distances
    /// right after themselves, in halfwords from `pc`, which is 4 bytes past
    /// the jump. A `cmp rI, n` before it bounds the case number.
    fn jump_tables(&self, memory: &Memory<'_>, code: Range<u64>, insns: &[Insn]) -> Vec<JumpTable> {
        (0..insns.len())
            .filter_map(|index| read_branch_table(memory, &code, insns, index))
            .collect()
    }

    /// A Cortex-M image opens with its vector table: the stack it starts
    /// with, which is no address in the image, then the address of each
    /// handler with bit 0 set, or zero for one left out.
    fn vector_table(&self, code: &[u8], base: u64) -> Option<VectorTable> {
        /// The 16 system exceptions and 240 interrupts ARMv7-M allows.
        const MOST_ENTRIES: usize = 256;
        let end = base + code.len() as u64;
        let inside = |address: u64| (base..end).contains(&address);
        let mut words = code
            .as_chunks::<WORD>()
            .0
            .iter()
            .map(|word| u64::from(u32::from_le_bytes([word[0], word[1], word[2], word[3]])));
        let stack = words.next()?;
        if inside(stack) || !stack.is_multiple_of(WORD as u64) {
            return None;
        }
        let entries: Vec<u64> = words
            .take(MOST_ENTRIES - 1)
            .take_while(|&word| word == 0 || (word & 1 == 1 && inside(word & !1)))
            .collect();
        let handlers: BTreeSet<u64> =
            entries.iter().filter(|&&word| word != 0).map(|word| word & !1).collect();
        // Reset, and at least one more: a lone odd word is no table.
        let resets = entries.first().is_some_and(|&reset| reset != 0);
        (resets && handlers.len() >= 2).then(|| VectorTable {
            words: base..base + ((entries.len() + 1) * WORD) as u64,
            handlers: handlers.into_iter().collect(),
        })
    }

    /// T32 jumps through a table with `tbb` and `tbh`.
    fn table_jumps(&self) -> TableJumps {
        TableJumps::Distinct
    }

    fn call_targets(&self, insns: &[Insn]) -> Vec<(usize, Option<super::CallTarget>)> {
        call_targets_through_thunks(insns, PcModel::T32)
    }

    /// A T32 library calls through A32 stubs, as an A32 one does. GNU `ld`
    /// opens each stub a T32 call reaches with `bx pc; b.n` to switch to A32
    /// first.
    fn stub_slot(&self, code: &[u8], address: u64) -> Option<u64> {
        match code.split_at_checked(THUMB_STUB_PREFIX.len()) {
            Some((prefix, stub)) if prefix == THUMB_STUB_PREFIX => {
                Arm32.stub_slot(stub, address + THUMB_STUB_PREFIX.len() as u64)
            }
            _ => Arm32.stub_slot(code, address),
        }
    }

    fn is_prologue(&self, insn: &Insn) -> bool {
        Arm32.is_prologue(insn)
    }

    /// See [`is_long_thunk`].
    fn is_function_entry(&self, body: &[Insn]) -> bool {
        is_long_thunk(body)
    }

    /// GNU `ld` opens a veneer from T32 to A32 with `bx pc`, as
    /// `__f_from_thumb`. `pc` reads 4 bytes ahead, rounded down to a word,
    /// and the A32 code goes on from there.
    fn switch_at_start(&self, code: &[u8], address: u64) -> Option<(&'static dyn Recovery, u64)> {
        (code.get(..HALFWORD)? == BX_PC).then(|| {
            let lands = PcModel::T32.of_literal_load(address);
            (&Arm32 as &'static dyn Recovery, lands)
        })
    }

    fn preamble_before_prologue(&self, earlier: &[Insn]) -> usize {
        Arm32.preamble_before_prologue(earlier)
    }

    fn is_tail_call(&self, insn: &Insn) -> bool {
        Arm32.is_tail_call(insn)
    }

    /// A zero halfword reads as `lsls r0, r0, 0`, which changes nothing but
    /// the flags, and fills the gap before a word-aligned pool.
    fn is_padding(&self, insn: &Insn) -> bool {
        let is = |opcode, condition, flags| {
            insn.opcode == super::Opcode::Thumb(Decoded::Core { opcode, condition, flags })
        };
        let operands = || self.lift(insn).map(|lifted| lifted.operands).unwrap_or_default();
        let r = |number| hereticus_il::Operand::Reg(hereticus_il::Reg::General(number));
        let branches_back = |distance: u64| {
            insn.kind == (InsnKind::Branch { target: Some(insn.address.wrapping_sub(distance)) })
        };
        is(Opcode::NOP, ConditionCode::AL, Flags::Kept)
            || (is(Opcode::MOV, ConditionCode::AL, Flags::Kept)
                && operands().as_slice() == [r(8), r(8)])
            || (is(Opcode::LSL, ConditionCode::AL, Flags::Set)
                && operands().as_slice() == [r(0), r(0), hereticus_il::Operand::Const(0)])
            // LLD's fill, `0xd4d4`, reads as this branch back. No compiler
            // branches back into the middle of the fill before a function.
            || (is(Opcode::B, ConditionCode::MI, Flags::Kept) && branches_back(0x54))
            || (insn.kind == InsnKind::Unknown
                && insn.opcode != super::Opcode::Data
                && insn.bytes() == [0, 0])
    }

    /// Only whole halfwords at the end are removed, and only those a linker
    /// pads with.
    fn trim_padding<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        let mut end = bytes.len() - bytes.len() % HALFWORD;
        while end >= HALFWORD && PADDING.iter().any(|pad| bytes[end - HALFWORD..end] == *pad) {
            end -= HALFWORD;
        }
        &bytes[..end]
    }

    fn unwind_section(&self) -> Option<&'static str> {
        Some(UNWIND_SECTION)
    }

    fn stub_arch(&self) -> Option<&'static dyn Recovery> {
        Some(&Arm32)
    }

    fn function_address(&self, pointer: u64) -> u64 {
        pointer & !1
    }

    fn tagged_function(&self, word: u64) -> Option<u64> {
        (word & 1 == 1).then_some(word & !1)
    }

    fn distance_words(&self, code: &[u8], insns: &[Insn]) -> BTreeSet<u64> {
        track_pool_words(code, insns, &AddressSpace::default(), PcModel::T32).distances
    }
}


/// Where a body that opens

/// Where a body that opens with a switch to A32 goes on in A32: the offset
/// into `code`, and the index into `body`. See [`Recovery::switch_at_start`].
fn split_at_switch(code: &[u8], body: &[Insn]) -> Option<(usize, usize)> {
    let start = body.first()?.address;
    let (_, lands) = Thumb2.switch_at_start(code, start)?;
    let offset = usize::try_from(lands.checked_sub(start)?).ok()?;
    let index = body.partition_point(|insn| insn.address < lands);
    (offset < code.len() && index < body.len()).then_some((offset, index))
}

/// `bx pc`, little endian.
const BX_PC: [u8; 2] = [0x78, 0x47];

/// The bytes of the table a `tbb` or `tbh` at `insns[index]` jumps
/// through, and the width of an entry, from the instructions alone.
fn table_extent(insns: &[Insn], index: usize) -> Option<(Range<u64>, usize)> {
    let jump = &insns[index];
    let width = match jump.opcode {
        super::Opcode::Thumb(Decoded::Core {
            opcode: Opcode::TBB,
            condition: ConditionCode::AL,
            ..
        }) => 1,
        super::Opcode::Thumb(Decoded::Core {
            opcode: Opcode::TBH,
            condition: ConditionCode::AL,
            ..
        }) => 2,
        _ => return None,
    };
    let operands =
        |insn: &Insn| Thumb2.lift(insn).map(|lifted| lifted.operands).unwrap_or_default();
    // `tbb [pc, rI]` and `tbh [pc, rI, lsl #1]`.
    let index_register = operands(jump).iter().find_map(|operand| match operand {
        hereticus_il::Operand::Memory {
            base: Some(hereticus_il::Reg::ProgramCounter),
            index: Some((index, _)),
            ..
        } => Some(*index),
        _ => None,
    })?;

    // `cmp rI, n`: the cases run from 0 to n.
    let bound = insns[index.saturating_sub(TABLE_LOOK_BACK)..index].iter().rev().find_map(
        |insn| match (core_opcode(insn), operands(insn).as_slice()) {
            (
                Some(Opcode::CMP),
                [.., hereticus_il::Operand::Reg(register), hereticus_il::Operand::Const(bound)],
            ) if *register == index_register => Some(*bound),
            _ => None,
        },
    )?;
    let cases = usize::try_from(bound).ok()?.checked_add(1).filter(|&cases| cases <= MOST_CASES)?;
    let table = jump.address + WORD as u64;
    Some((table..table + (cases * width) as u64, width))
}

/// The loads from a literal pool in `insns`, but for those that are the
/// bytes of a `tbb` or `tbh` table read as code.
///
/// An entry of such a table can read as `ldr rX, [pc, imm]`, which names a
/// word of code as a pool word. Measured on zlib built by clang at `-O1` for
/// Cortex-M3, one such load put `deflateResetKeep` out of step.
fn loads_outside_tables(insns: &[Insn]) -> Vec<(u64, u64)> {
    let tables: Vec<Range<u64>> = (0..insns.len())
        .filter_map(|index| table_extent(insns, index))
        .map(|(bytes, _)| bytes)
        .collect();
    pool_loads(insns, PcModel::T32)
        .into_iter()
        .filter(|(load, _)| !tables.iter().any(|table| table.contains(load)))
        .collect()
}

/// Read the table a `tbb` or `tbh` at `insns[index]` jumps through.
fn read_branch_table(
    memory: &Memory<'_>,
    code: &Range<u64>,
    insns: &[Insn],
    index: usize,
) -> Option<JumpTable> {
    let jump = &insns[index];
    let (table_bytes, width) = table_extent(insns, index)?;
    let table = table_bytes.start;
    let cases = (table_bytes.end - table_bytes.start) as usize / width;
    let mut targets = Vec::with_capacity(cases);
    for case in 0..cases {
        let entry = memory.bytes(table + (case * width) as u64, width)?;
        let halfwords = match entry {
            [byte] => u64::from(*byte),
            [low, high] => u64::from(u16::from_le_bytes([*low, *high])),
            _ => return None,
        };
        let target = table + halfwords * HALFWORD as u64;
        if !code.contains(&target) {
            return None;
        }
        targets.push(target);
    }
    Some(JumpTable { jump: jump.address, words: table..table + (cases * width) as u64, targets })
}

