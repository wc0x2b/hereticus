//! The rules that find functions in T32 code.
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

use super::arm32::{
    PcModel, UNWIND_SECTION, call_targets_through_thunks, is_long_thunk, pool_loads,
    track_pool_words,
};
use super::{
    DataAmongCode, Decoder, Insn, InsnKind, JumpTable, Memory, Recovery, TableJumps, VectorTable,
};
use core::ops::Range;
use hereticus_il::arch::arm32::{Arm32, Decoded, Flags, core_opcode};
use hereticus_il::arch::thumb::*;
use hereticus_memory::AddressSpace;
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
    ///
    /// GCC for PIC can read a table of word distances instead; see
    /// [`word_table_extent`].
    fn jump_tables(&self, memory: &Memory<'_>, code: Range<u64>, insns: &[Insn]) -> Vec<JumpTable> {
        (0..insns.len())
            .filter_map(|index| {
                read_branch_table(memory, &code, insns, index)
                    .or_else(|| read_word_table(memory, &code, insns, index))
            })
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

    /// A stub that T32 code calls opens with the prefix that switches to
    /// A32, and the prefix is part of it.
    fn plt_entries(&self, code: &[u8], base: u64) -> Vec<Range<u64>> {
        super::arm32::plt_stubs(code, base, |stub, address| {
            let prefix = match stub.starts_with(&THUMB_STUB_PREFIX) {
                true => THUMB_STUB_PREFIX.len(),
                false => 0,
            };
            super::arm32::opens_a32_stub(&stub[prefix..])
                .then(|| self.stub_slot(stub, address))
                .flatten()?;
            Some(prefix + super::arm32::STUB_LENGTH)
        })
    }

    fn plt_header(&self, code: &[u8], base: u64, first_stub: u64) -> Option<u64> {
        Arm32.plt_header(code, base, first_stub)
    }

    fn is_prologue(&self, insn: &Insn) -> bool {
        Arm32.is_prologue(insn)
    }

    /// See `is_long_thunk`.
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

/// Where a body that opens with a switch to A32 goes on in A32: the offset
/// into `code`, and the index into `body`. See [`Recovery::switch_at_start`].
pub fn split_at_switch(code: &[u8], body: &[Insn]) -> Option<(usize, usize)> {
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
    // `tbb [pc, rI]` and `tbh [pc, rI, lsl #1]`.
    let index_register = operands(jump).iter().find_map(|operand| match operand {
        hereticus_il::Operand::Memory {
            base: Some(hereticus_il::Reg::ProgramCounter),
            index: Some((index, _)),
            ..
        } => Some(*index),
        _ => None,
    })?;

    let cases = cases_below(insns, index, index_register)?;
    let table = jump.address + WORD as u64;
    Some((table..table + (cases * width) as u64, width))
}

/// The number of cases that a `cmp rI, n` before `insns[index]` bounds:
/// the cases run from 0 to n.
fn cases_below(insns: &[Insn], index: usize, index_register: hereticus_il::Reg) -> Option<usize> {
    let bound = insns[index.saturating_sub(TABLE_LOOK_BACK)..index].iter().rev().find_map(
        |insn| match (core_opcode(insn), operands(insn).as_slice()) {
            (
                Some(Opcode::CMP),
                [.., hereticus_il::Operand::Reg(register), hereticus_il::Operand::Const(bound)],
            ) if *register == index_register => Some(*bound),
            _ => None,
        },
    )?;
    usize::try_from(bound).ok()?.checked_add(1).filter(|&cases| cases <= MOST_CASES)
}

fn operands(insn: &Insn) -> Vec<hereticus_il::Operand> {
    Thumb2.lift(insn).map(|lifted| lifted.operands.to_vec()).unwrap_or_default()
}

/// The words of the table that the `bx rB` at `insns[index]` jumps
/// through, where GCC for PIC reads a word distance from it:
///
/// ```text
/// cmp   rI, n
/// adr   rB, table
/// ldr.w rX, [rB, rI, lsl 2]
/// add   rB, rX
/// bx    rB
/// ```
///
/// T32 cannot add to `pc` as A32 does, so the sum goes through `bx`, and
/// each distance has bit 0 set to stay in T32. Unread, the words of such a
/// table decode as calls into the middle of other functions: measured on
/// SQLite of Ubuntu 22.04 for armhf, one split `isDate` in two.
fn word_table_extent(insns: &[Insn], index: usize) -> Option<Range<u64>> {
    use hereticus_il::Operand;

    let jump = &insns[index];
    let table_register = match (core_opcode(jump), operands(jump).as_slice()) {
        (Some(Opcode::BX), [Operand::Reg(register)]) => *register,
        _ => return None,
    };
    let earlier = &insns[index.saturating_sub(TABLE_LOOK_BACK)..index];
    // The last instruction before `insns[before]` to write `register`.
    let last_write = |before: usize, register: hereticus_il::Reg| {
        earlier[..before]
            .iter()
            .rposition(|insn| operands(insn).first() == Some(&Operand::Reg(register)))
    };

    let add = last_write(earlier.len(), table_register)?;
    let offset_register = match (core_opcode(&earlier[add]), operands(&earlier[add]).as_slice()) {
        (Some(Opcode::ADD), [_, Operand::Reg(augend), Operand::Reg(addend)])
            if *augend == table_register =>
        {
            *addend
        }
        _ => return None,
    };
    let load = last_write(add, offset_register)?;
    let index_register = match (core_opcode(&earlier[load]), operands(&earlier[load]).as_slice()) {
        (
            Some(Opcode::LDR),
            [
                _,
                Operand::Memory {
                    base: Some(base),
                    offset: None,
                    index: Some((index, 2)),
                    update: hereticus_il::Update::None,
                },
            ],
        ) if *base == table_register => *index,
        _ => return None,
    };
    let address = last_write(load, table_register)?;
    let table = match (core_opcode(&earlier[address]), operands(&earlier[address]).as_slice()) {
        (Some(Opcode::ADR), [_, Operand::Const(distance)]) => {
            PcModel::T32.of_literal_load(earlier[address].address).wrapping_add(*distance)
        }
        _ => return None,
    };
    let first = index.saturating_sub(TABLE_LOOK_BACK);
    let cases = cases_below(insns, first + load, index_register)?;
    Some(table..table + (cases * WORD) as u64)
}

/// Read the table of word distances behind `insns[index]`: see
/// [`word_table_extent`].
fn read_word_table(
    memory: &Memory<'_>,
    code: &Range<u64>,
    insns: &[Insn],
    index: usize,
) -> Option<JumpTable> {
    let words = word_table_extent(insns, index)?;
    let targets = words
        .clone()
        .step_by(WORD)
        .map(|word| {
            let bytes = memory.bytes(word, WORD)?;
            let distance = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let target =
                Thumb2.tagged_function(words.start.checked_add_signed(distance.into())?)?;
            code.contains(&target).then_some(target)
        })
        .collect::<Option<Vec<u64>>>()?;
    Some(JumpTable { jump: insns[index].address, words, targets })
}

/// The loads from a literal pool in `insns`, but for those that are the
/// bytes of a jump table read as code.
///
/// An entry of such a table can read as `ldr rX, [pc, imm]`, which names a
/// word of code as a pool word. Measured on zlib built by clang at `-O1` for
/// Cortex-M3, one such load put `deflateResetKeep` out of step.
fn loads_outside_tables(insns: &[Insn]) -> Vec<(u64, u64)> {
    let tables: Vec<Range<u64>> = (0..insns.len())
        .filter_map(|index| {
            table_extent(insns, index)
                .map(|(bytes, _)| bytes)
                .or_else(|| word_table_extent(insns, index))
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    use hereticus_il::arch::arm32::{NEON_TEXT, UNKNOWN_TEXT};

    use crate::arch::decode_all;

    /// T32 code from halfwords, little endian.
    fn halfwords(values: &[u16]) -> Vec<u8> {
        values.iter().flat_map(|value| value.to_le_bytes()).collect()
    }

    fn decode_one(values: &[u16]) -> Insn {
        Thumb2.decode(&halfwords(values), 0, 0x1000).expect("bytes must decode")
    }

    /// A Cortex-M image, loaded at 0x08000000, that opens with `entries`
    /// after the stack it starts with, then 0x40 bytes of `bx lr`.
    fn image_with_vectors(stack: u32, entries: &[u32]) -> Vec<u8> {
        let mut image: Vec<u8> = std::iter::once(stack)
            .chain(entries.iter().copied())
            .flat_map(|word| word.to_le_bytes())
            .collect();
        image.extend(halfwords(&[0x4770; 32]));
        image
    }

    #[test]
    fn a_vector_table_names_each_handler() {
        let image = image_with_vectors(0x2002_0000, &[0x0800_0011, 0x0800_0015, 0, 0x0800_0015]);
        let table = Thumb2.vector_table(&image, 0x0800_0000).expect("a table");
        assert_eq!(table.words, 0x0800_0000..0x0800_0014);
        assert_eq!(table.handlers, [0x0800_0010, 0x0800_0014]);
    }

    #[test]
    fn what_is_no_vector_table_is_none() {
        let base = 0x0800_0000;
        // The stack lies inside the image.
        let inside = image_with_vectors(0x0800_0020, &[0x0800_0011, 0x0800_0015]);
        assert_eq!(Thumb2.vector_table(&inside, base), None);
        // Only one handler.
        let lone = image_with_vectors(0x2002_0000, &[0x0800_0011, 0x1234]);
        assert_eq!(Thumb2.vector_table(&lone, base), None);
        // The reset entry is empty.
        let no_reset = image_with_vectors(0x2002_0000, &[0, 0x0800_0011, 0x0800_0015]);
        assert_eq!(Thumb2.vector_table(&no_reset, base), None);
    }

    /// The entries of a `tbb` table can read as loads from a pool, and name
    /// words of code. They name no pool words.
    #[test]
    fn the_bytes_of_a_table_load_no_pool_words() {
        // cmp r3, 3; tbb [pc, r3]; then 4 entries that read as
        // `ldr r1, [pc, 0x74]` twice.
        let code = halfwords(&[0x2b03, 0xe8df, 0xf003, 0x491d, 0x491d, 0x4770]);
        let (insns, _) = decode_all(&Thumb2, &code, 0x1000);
        assert!(Thumb2.literal_pool_words(&insns).is_empty());
    }

    #[test]
    fn a_tbh_table_holds_halfwords() {
        // cmp r2, 1; tbh [pc, r2, lsl 1]; then the table, 2 and 3 halfwords.
        let code = halfwords(&[0x2a01, 0xe8df, 0xf012, 0x0002, 0x0003, 0x4770, 0x4770, 0x4770]);
        let (insns, _) = decode_all(&Thumb2, &code, 0x1000);
        let regions = [(0x1000, code.as_slice())];
        let tables = Thumb2.jump_tables(&Memory::new(&regions), 0x1000..0x1010, &insns);
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].targets, [0x1006 + 4, 0x1006 + 6]);
    }

    #[test]
    fn an_it_block_names_each_condition() {
        // ite gt; movgt r0, #0; movle r0, #1; adds r0, #1
        let code = halfwords(&[0xbfcc, 0x2000, 0x2001, 0x3001]);
        let (insns, _) = decode_all(&Thumb2, &code, 0x1000);
        let names: Vec<String> = insns.iter().map(hereticus_il::arch::printed_name).collect();
        assert_eq!(names, ["ite", "movgt", "movle", "adds"]);
        let condition = |insn: &Insn| match insn.opcode {
            super::super::Opcode::Thumb(Decoded::Core { condition, flags, .. }) => {
                (condition, flags)
            }
            other => panic!("{other:?}"),
        };
        assert_eq!(condition(&insns[1]), (ConditionCode::GT, Flags::Kept));
        assert_eq!(condition(&insns[2]), (ConditionCode::LE, Flags::Kept));
        assert_eq!(condition(&insns[3]), (ConditionCode::AL, Flags::Set));
        // itet eq
        let eq_ne_eq = vec![ConditionCode::EQ, ConditionCode::NE, ConditionCode::EQ];
        assert_eq!(it_conditions(0, 0b1010), Some(eq_ne_eq));
        assert_eq!(it_conditions(14, 0b1000), None, "no condition to name");
    }

    #[test]
    fn a_thunk_to_a32_names_where_it_jumps() {
        // movw ip, 0xfaac; movt ip, 0xfffe; add ip, pc; bx ip
        let code = halfwords(&[0xf64f, 0x2cac, 0xf6cf, 0x7cfe, 0x44fc, 0x4760]);
        let (insns, _) = decode_all(&Thumb2, &code, 0x2f668);
        assert!(Thumb2.is_function_entry(&insns));
        let targets = Thumb2.call_targets(&insns);
        assert_eq!(targets, [(3, Some(super::super::CallTarget::Address(0x1f120)))]);
    }

    #[test]
    fn a_veneer_that_opens_with_bx_pc_goes_on_in_a32() {
        // bx pc; nop; then A32 `ldr ip, [pc]; add pc, ip, pc` and a distance.
        let mut code = halfwords(&[0x4778, 0x46c0]);
        for word in [0xe59f_c000u32, 0xe08c_f00f, 0x0000_1000] {
            code.extend(word.to_le_bytes());
        }
        let (insns, error) = decode_all(&Thumb2, &code, 0x1000);
        assert_eq!(error, None);
        let text: Vec<String> = insns.iter().map(|insn| insn.to_string()).collect();
        assert_eq!(text[..4], ["bx pc", "mov r8, r8", "ldr ip, [pc]", "add pc, ip, pc"]);
        assert_eq!(insns[2].address, 0x1004);
    }

    #[test]
    fn only_a_body_that_opens_with_bx_pc_switches() {
        let code = halfwords(&[0x46c0, 0x4778, 0x46c0]);
        assert!(Thumb2.switch_at_start(&code, 0x1000).is_none());
        assert_eq!(Thumb2.switch_at_start(&code[2..], 0x1002).map(|(_, at)| at), Some(0x1004));
    }

    #[test]
    fn t32_neon_data_processing_reads_as_its_a32_twin() {
        let insn = decode_one(&[0xefc0, 0x0050]);
        assert_eq!(insn.to_string(), "vmov.i32 q8, 0x0");
        assert_eq!(insn.kind, InsnKind::Normal);
    }

    /// `vadd.i32` of an odd `q` register is no instruction, but it is NEON.
    #[test]
    fn undefined_t32_neon_data_processing_is_unread_code() {
        let insn = decode_one(&[0xef60, 0x1844]);
        assert_eq!(
            (hereticus_il::arch::printed_name(&insn).as_str(), insn.kind),
            (NEON_TEXT, InsnKind::Unknown)
        );
        assert!(Thumb2.is_unread_extension(&insn));
    }

    #[test]
    fn a_t32_word_that_reads_as_a32_neon_is_not_neon() {
        // `f3f0 8000` is no instruction, though `0xf3f08000` would be A32
        // NEON data processing.
        let insn = decode_one(&[0xf3f0, 0x8000]);
        assert_eq!(hereticus_il::arch::printed_name(&insn), UNKNOWN_TEXT);
        assert!(!Thumb2.is_unread_extension(&insn));
    }

    #[test]
    fn a_push_with_lr_is_a_prologue_and_a_pop_with_pc_returns() {
        assert!(Thumb2.is_prologue(&decode_one(&[0xb5f0]))); // push {r4, r5, r6, r7, lr}
        assert_eq!(decode_one(&[0xbdf0]).kind, InsnKind::Return); // pop {r4, r5, r6, r7, pc}
    }

    /// A `bx lr` that an `it` made conditional is an early exit.
    #[test]
    fn a_return_in_an_it_block_is_a_branch() {
        let code = halfwords(&[
            0x2800, // cmp r0, 0
            0xbf08, // it eq
            0x4770, // bxeq lr
            0x2001, // movs r0, 1
            0x4770, // bx lr
        ]);
        let (insns, _) = decode_all(&Thumb2, &code, 0x1000);
        let kinds: Vec<InsnKind> = insns.iter().map(|insn| insn.kind).collect();
        assert_eq!(kinds[2], InsnKind::Branch { target: None });
        assert_eq!(kinds[4], InsnKind::Return);
    }

    /// `tbb` reads the byte table after itself, bounded by the `cmp` before.
    #[test]
    fn reads_a_byte_table_after_tbb() {
        let mut code = halfwords(&[
            0x2b02, // 0x1000 cmp r3, 2
            0xd804, // 0x1002 bhi
            0xe8df, 0xf003, // 0x1004 tbb [pc, r3]
        ]);
        code.extend([2, 3, 4, 0]); // 0x1008 the table: 0x100c, 0x100e, 0x1010
        code.extend(halfwords(&[0x4770, 0x4770, 0x4770])); // 0x100c the cases
        let (insns, _) = decode_all(&Thumb2, &code[..8], 0x1000);
        let regions = [(0x1000, code.as_slice())];
        assert_eq!(
            Thumb2.jump_tables(&Memory::new(&regions), 0x1000..0x1012, &insns),
            [JumpTable {
                jump: 0x1004,
                words: 0x1008..0x100b,
                targets: vec![0x100c, 0x100e, 0x1010]
            }]
        );
    }

    /// GCC for PIC adds a word distance from the table to the table's
    /// address, and jumps there with `bx`.
    #[test]
    fn reads_a_word_table_before_bx() {
        let mut code = halfwords(&[
            0x2b02, // 0x1000 cmp r3, 2
            0xd80b, // 0x1002 bhi
            0xa202, // 0x1004 adr r2, 8: (0x1008 & !3) + 8 = 0x1010
            0xf852, 0x3023, // 0x1006 ldr.w r3, [r2, r3, lsl 2]
            0x441a, // 0x100a add r2, r3
            0x4710, // 0x100c bx r2
            0xbf00, // 0x100e nop
        ]);
        // 0x1010 the table: 0x101c, 0x101e and 0x1020, each with bit 0 set
        code.extend([0x0d_u32, 0x0f, 0x11].iter().flat_map(|word| word.to_le_bytes()));
        code.extend(halfwords(&[0x4770, 0x4770, 0x4770])); // 0x101c the cases
        let (insns, _) = decode_all(&Thumb2, &code[..0x10], 0x1000);
        let regions = [(0x1000, code.as_slice())];
        let expected = JumpTable {
            jump: 0x100c,
            words: 0x1010..0x101c,
            targets: vec![0x101c, 0x101e, 0x1020],
        };
        assert_eq!(Thumb2.jump_tables(&Memory::new(&regions), 0x1000..0x1022, &insns), [expected]);
    }

    /// A jump through a register that no `cmp` bounds, or that another
    /// instruction wrote, reads no table.
    #[rstest::rstest]
    #[case::no_bound(&[0xbf00, 0xbf00])]
    #[case::bound_on_another_register(&[0x2a02, 0xd80b])]
    fn a_word_table_needs_its_bound(#[case] before: &[u16]) {
        let mut code = halfwords(before);
        code.extend(halfwords(&[0xa202, 0xf852, 0x3023, 0x441a, 0x4710, 0xbf00]));
        code.extend([0x0d_u32, 0x0f, 0x11].iter().flat_map(|word| word.to_le_bytes()));
        code.extend(halfwords(&[0x4770, 0x4770, 0x4770]));
        let (insns, _) = decode_all(&Thumb2, &code[..0x10], 0x1000);
        let regions = [(0x1000, code.as_slice())];
        assert_eq!(Thumb2.jump_tables(&Memory::new(&regions), 0x1000..0x1022, &insns), []);
    }

    /// `adr` sets a register to a pool, and a load through it reads the
    /// pool, as `ldrd` of a double does.
    #[test]
    fn a_load_through_adr_reads_the_pool() {
        // 0x1000 adr r3, 4: (0x1004 & !3) + 4 = 0x1008; ldrd r2, r3, [r3]
        let (insns, _) = decode_all(&Thumb2, &halfwords(&[0xa301, 0xe9d3, 0x2300]), 0x1000);
        assert_eq!(Thumb2.literal_pool_words(&insns), [0x1008, 0x100c]);
    }

    /// A register that another instruction wrote after the `adr`, or that
    /// a branch came between, no longer holds the pool.
    #[rstest::rstest]
    #[case::written(0x2300)] // movs r3, 0
    #[case::branch(0xd000)] // beq
    fn a_load_through_a_changed_register_reads_no_pool(#[case] between: u16) {
        let code = halfwords(&[0xa301, between, 0xe9d3, 0x2300]);
        let (insns, _) = decode_all(&Thumb2, &code, 0x1000);
        assert_eq!(Thumb2.literal_pool_words(&insns), []);
    }

    /// A table whose distance leaves the code is no table.
    #[test]
    fn a_word_table_stays_in_the_code() {
        let mut code = halfwords(&[0x2b02, 0xd80b, 0xa202, 0xf852, 0x3023, 0x441a, 0x4710, 0xbf00]);
        code.extend([0x0d_u32, 0x0f, 0x1001].iter().flat_map(|word| word.to_le_bytes()));
        code.extend(halfwords(&[0x4770, 0x4770, 0x4770]));
        let (insns, _) = decode_all(&Thumb2, &code[..0x10], 0x1000);
        let regions = [(0x1000, code.as_slice())];
        assert_eq!(Thumb2.jump_tables(&Memory::new(&regions), 0x1000..0x1022, &insns), []);
    }

    /// PIC code loads a distance from the pool, word aligned, and adds `pc`
    /// to it, 4 bytes past the `add`.
    #[test]
    fn a_distance_added_to_pc_forms_an_address() {
        let mut code = halfwords(&[
            0x4801, // 0x8000 ldr r0, [pc, 4]: the word at (0x8004 & !3) + 4 = 0x8008
            0x4478, // 0x8002 add r0, pc: 0x8006 + the word
            0x4770, // 0x8004 bx lr
            0xbf00, // 0x8006 nop
        ]);
        code.extend(0x0000_0040_u32.to_le_bytes()); // 0x8008 the distance
        let (insns, _) = decode_all(&Thumb2, &code, 0x8000);
        let space = AddressSpace::of_raw_image(0x8000, 0x100);
        let memory = Memory::new(&[]);
        assert_eq!(Thumb2.data_addresses(&code, &insns, &space, &memory), [0x8046]);
        assert_eq!(Thumb2.literal_pool_words(&insns), [0x8008]);
    }

    #[test]
    fn padding_is_trimmed_by_halfwords() {
        let code = halfwords(&[0x4770, 0xbf00, 0xd4d4]);
        assert_eq!(Thumb2.trim_padding(&code), &code[..2]);
        let pool = halfwords(&[0x4770, 0xbf00, 0x0040, 0x0000]);
        assert_eq!(Thumb2.trim_padding(&pool), &pool[..], "a pool word ends with zeros");
        assert!(Thumb2.is_padding(&decode_one(&[0xbf00])));
        assert!(Thumb2.is_padding(&decode_one(&[0x46c0])));
        assert!(Thumb2.is_padding(&decode_one(&[0x0000])), "lsls r0, r0, 0");
        assert!(!Thumb2.is_padding(&decode_one(&[0x0048])), "lsls r0, r1, 1");
    }

    /// The PLT stub of `malloc` in zlib for Thumb-2, as GNU `ld` wrote it:
    /// `bx pc; b.n`, then the A32 stub.
    #[test]
    fn reads_the_slot_of_a_stub_behind_the_thumb_prefix() {
        let stub: Vec<u8> = [0xe7fd_4778_u32, 0xe28f_c600, 0xe28c_ca1e, 0xe5bc_fb6c]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let slot = Arm32.stub_slot(&stub[4..], 0x14a0);
        assert!(slot.is_some());
        assert_eq!(Thumb2.stub_slot(&stub, 0x149c), slot);
        assert_eq!(Thumb2.stub_slot(&stub[4..], 0x14a0), slot, "a stub with no prefix");
    }

    /// A stub that T32 code calls starts at its prefix, and one that only
    /// A32 code calls has none: the PLT of zlib for Thumb-2, as GNU `ld`
    /// wrote it.
    #[test]
    fn a_plt_entry_starts_at_its_thumb_prefix() {
        let stub = [0xe28f_c600_u32, 0xe28c_ca1e, 0xe5bc_fb6c];
        let prefix = u32::from_le_bytes(THUMB_STUB_PREFIX);
        let code: Vec<u8> = [&[prefix][..], &stub, &stub, &[prefix], &stub]
            .concat()
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        assert_eq!(
            Thumb2.plt_entries(&code, 0x1494),
            [0x1494..0x14a4, 0x14a4..0x14b0, 0x14b0..0x14c0]
        );
        assert!(Thumb2.plt_entries(&code[..4], 0x1494).is_empty(), "a prefix alone");
    }

    #[test]
    fn a_range_extension_thunk_is_a_function_entry() {
        let code = halfwords(&[
            0xf240, 0x0cc4, // mov.w ip, 0xc4
            0xf2c0, 0x0c00, // movt ip, 0x0
            0x44fc, // add ip, pc
            0x4760, // bx ip
        ]);
        let (insns, _) = decode_all(&Thumb2, &code, 0x1000);
        assert!(Thumb2.is_function_entry(&insns));
        assert!(!Thumb2.is_function_entry(&insns[1..]));
        // `add ip, pc` at 0x1008 reads 0x100c, and 0x100c + 0xc4 = 0x10d0.
        assert_eq!(
            Thumb2.call_targets(&insns),
            [(3, Some(crate::arch::CallTarget::Address(0x10d0)))]
        );
    }

    #[test]
    fn a_pointer_to_a_function_drops_the_thumb_bit() {
        assert_eq!(Thumb2.function_address(0x1235), 0x1234);
    }

    /// The unwind index names a T32 function by its first instruction,
    /// which must read as one and not as padding.
    #[test]
    fn a_function_opens_with_an_instruction_that_is_no_padding() {
        assert!(Thumb2.can_open_function(&halfwords(&[0xb580])), "push {{r7, lr}}");
        assert!(!Thumb2.can_open_function(&halfwords(&[0x0000])), "zero fill");
        assert!(!Thumb2.can_open_function(&halfwords(&[0xbf00])), "nop");
        assert!(!Thumb2.can_open_function(&[]), "no bytes");
    }

    #[test]
    fn an_it_prints_its_condition_on_what_it_covers() {
        // itt mi; movmi r0, #0; then a word no decoder reads
        let code = halfwords(&[0xbf44, 0x2000, 0xeaa8, 0xe67d]);
        let (insns, _) = decode_all(&Thumb2, &code, 0x1000);
        let printed: Vec<String> = insns.iter().map(Insn::to_string).collect();
        // The unread word holds no condition to print.
        assert_eq!(printed, ["itt mi", "movmi r0, 0x0", "(unknown) e67deaa8"]);
    }
}
