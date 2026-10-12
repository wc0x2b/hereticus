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
    Arch, DataAmongCode, Decoder, Insn, InsnKind, JumpTable, Memory, TableJumps, VectorTable,
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

impl Arch for Thumb2 {
    fn is_frame_register(&self, reg: crate::il::Reg) -> bool {
        Arm32.is_frame_register(reg)
    }

    /// T32 has no condition field to test, so the first instruction must
    /// read as one and not as padding.
    fn can_open_function(&self, bytes: &[u8]) -> bool {
        self.decode(bytes, 0, 0)
            .is_ok_and(|insn| insn.kind != InsnKind::Unknown && !self.is_padding(&insn))
    }

    fn is_frame_management(&self, insn: &Insn) -> bool {
        Arm32.is_frame_management(insn)
    }

    fn constant_kinds(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
    ) -> Vec<ConstantKind> {
        match split_at_switch(code, body) {
            Some((offset, index)) => {
                let mut kinds = track_pool_words(code, &body[..index], space, PcModel::T32).kinds;
                kinds.extend(Arm32.constant_kinds(&code[offset..], &body[index..], space));
                kinds
            }
            None => track_pool_words(code, body, space, PcModel::T32).kinds,
        }
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
    fn switch_at_start(&self, code: &[u8], address: u64) -> Option<(&'static dyn Arch, u64)> {
        (code.get(..HALFWORD)? == BX_PC).then(|| {
            let lands = PcModel::T32.of_literal_load(address);
            (&Arm32 as &'static dyn Arch, lands)
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
        let r = |number| crate::il::Operand::Reg(crate::il::Reg::General(number));
        let branches_back = |distance: u64| {
            insn.kind == (InsnKind::Branch { target: Some(insn.address.wrapping_sub(distance)) })
        };
        is(Opcode::NOP, ConditionCode::AL, Flags::Kept)
            || (is(Opcode::MOV, ConditionCode::AL, Flags::Kept)
                && operands().as_slice() == [r(8), r(8)])
            || (is(Opcode::LSL, ConditionCode::AL, Flags::Set)
                && operands().as_slice() == [r(0), r(0), crate::il::Operand::Const(0)])
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

    fn stub_arch(&self) -> Option<&'static dyn Arch> {
        Some(&Arm32)
    }

    fn function_address(&self, pointer: u64) -> u64 {
        pointer & !1
    }

    fn tagged_function(&self, word: u64) -> Option<u64> {
        (word & 1 == 1).then_some(word & !1)
    }

    fn formed_addresses(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        _memory: &Memory<'_>,
    ) -> Vec<Option<u64>> {
        track_pool_words(code, body, space, PcModel::T32).formed
    }

    fn distance_words(&self, code: &[u8], insns: &[Insn]) -> BTreeSet<u64> {
        track_pool_words(code, insns, &AddressSpace::default(), PcModel::T32).distances
    }
}

/// Where a body that opens with a switch to A32 goes on in A32: the offset
/// into `code`, and the index into `body`. See [`Arch::switch_at_start`].
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
        crate::il::Operand::Memory {
            base: Some(crate::il::Reg::ProgramCounter),
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
                [.., crate::il::Operand::Reg(register), crate::il::Operand::Const(bound)],
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::arm32::{NEON_TEXT, UNKNOWN_TEXT, condition_name};

    /// Taking out a suffix by bytes gives what `str::replace` gives, for
    /// any text of dots, the two letters and others.
    #[test]
    fn a_suffix_comes_out_as_replace_takes_it() {
        bolero::check!().with_type::<Vec<u8>>().for_each(|picks| {
            let text: String =
                picks.iter().map(|pick| ['.', 'w', 'n', 'b', 'e'][*pick as usize % 5]).collect();
            for letter in *b"wn" {
                let pattern = format!(".{}", letter as char);
                assert_eq!(without_suffix(&text, letter), text.replace(&pattern, ""), "{text:?}");
            }
        });
    }

    /// The target of a branch replaces the first `$+` offset, or else the
    /// first `$-` one.
    #[test]
    fn a_branch_names_the_distance_to_its_target() {
        assert_eq!(with_target_text("$+0x2e", 0x100, 0x130), "$+0x30");
        assert_eq!(with_target_text("r0, $-0x4", 0x100, 0xf0), "r0, $-0x10");
        assert_eq!(with_target_text("r1, r2", 0x100, 0x130), "r1, r2");
        assert_eq!(with_target_text("$5, $+0x2", 0x100, 0x108), "$5, $+0x8");
    }

    /// The wide words `yaxpeax` misreads, against `llvm-mc`.
    #[test]
    fn reads_the_wide_words_the_decoder_misreads() {
        let cases: [(u16, u16, &str, &str); 9] = [
            (0xf06f, 0x0002, "mvn", "r0, 0x2"),
            (0xf07f, 0x4300, "mvns", "r3, 0x80000000"),
            (0xfa0c, 0xfc00, "lsl", "ip, ip, r0"),
            (0xfa2c, 0xfc00, "lsr", "ip, ip, r0"),
            (0xfa4c, 0xfc00, "asr", "ip, ip, r0"),
            (0xfa6c, 0xfc00, "ror", "ip, ip, r0"),
            (0xfa1f, 0xf29b, "uxth", "r2, fp, ror 0x8"),
            (0xf362, 0x3596, "bfi", "r5, r2, 0xe, 0x9"),
            (0xf36f, 0x209f, "bfc", "r0, 0xa, 0x16"),
        ];
        for (first, second, name, operands) in cases {
            let bytes = halfwords(&[first, second]);
            let insn = Thumb2.decode(&bytes, 0, 0).expect("the word reads");
            assert_eq!(insn.to_string(), format!("{name} {operands}"));
        }
        let lift = |first, second| {
            let bytes = halfwords(&[first, second]);
            Thumb2.lift(&Thumb2.decode(&bytes, 0, 0).unwrap()).expect("the word lifts")
        };
        // `mvn r0, #2` puts `~2` in `r0`.
        let not = lift(0xf06f, 0x0002);
        assert_eq!(not.op, crate::il::Op::Move);
        assert_eq!(not.operands[1], crate::il::Operand::Const(u64::from(!2u32)));
        assert_eq!(lift(0xfa4c, 0xfc00).op, crate::il::Op::ShiftRightArithmetic);
        assert_eq!(lift(0xfa6c, 0xfc00).op, crate::il::Op::Rotate);
        // `asr #32` is encoded as a shift of 0.
        let shifted = Thumb2.decode(&halfwords(&[0xea13, 0x0321]), 0, 0).unwrap();
        assert_eq!(crate::arch::printed_operands(&shifted), "r3, r3, r1, asr 0x20");
        let plain = Thumb2.decode(&halfwords(&[0xea13, 0x0301]), 0, 0).unwrap();
        assert_eq!(crate::arch::printed_operands(&plain), "r3, r3, r1");
    }

    /// Each pattern of `ThumbExpandImm`, and a rotated byte.
    #[test]
    fn a_t32_constant_expands() {
        assert_eq!(thumb_expand_constant(0x0ab), 0xab);
        assert_eq!(thumb_expand_constant(0x1ab), 0x00ab_00ab);
        assert_eq!(thumb_expand_constant(0x2ab), 0xab00_ab00);
        assert_eq!(thumb_expand_constant(0x3ab), 0xabab_abab);
        assert_eq!(thumb_expand_constant(0x400), 0x8000_0000);
        // A rotation of 31 puts the byte `0xff` at bits 1 to 8.
        assert_eq!(thumb_expand_constant(0xfff), 0x1fe);
    }

    /// A branch prints the distance from itself to where it goes, as
    /// `llvm-objdump` resolves it: `bne` at 0x14cf6 goes to 0x14d26.
    #[test]
    fn a_branch_prints_the_distance_to_its_target() {
        let cases: [(&[u8], &str, &str); 4] = [
            // `bne`, narrow and conditional.
            (&[0x16, 0xd1], "bne", "$+0x30"),
            // `cbz r1`, narrow.
            (&[0xd1, 0xb1], "cbz", "r1, $+0x38"),
            // `b.w`, wide.
            (&[0x00, 0xf0, 0x10, 0xb8], "b", "$+0x24"),
            // LLD's fill, a branch back.
            (&[0xd4, 0xd4], "bmi", "$-0x54"),
        ];
        for (bytes, name, operands) in cases {
            let insn = Thumb2.decode(bytes, 0, 0x1000).expect("the branch reads");
            assert_eq!(insn.to_string(), format!("{name} {operands}"));
            let (InsnKind::Branch { target: Some(target) }
            | InsnKind::Jump { target: Some(target) }) = insn.kind
            else {
                panic!("{bytes:x?} is a branch")
            };
            let distance = operands.rsplit('$').next().expect("a distance");
            let distance = i64::from_str_radix(&distance[3..], 16).expect("hex")
                * if distance.starts_with('-') { -1 } else { 1 };
            assert_eq!(target as i64 - 0x1000, distance, "{bytes:x?}");
        }
        assert_eq!(with_target_text("r1, $+0x2", 0x10, 0x8), "r1, $-0x8");
        assert_eq!(with_target_text("r1", 0x10, 0x8), "r1", "no distance to put right");
    }
    use crate::arch::decode_all;

    /// T32 code from halfwords, little endian.
    fn halfwords(values: &[u16]) -> Vec<u8> {
        values.iter().flat_map(|value| value.to_le_bytes()).collect()
    }

    fn decode_one(values: &[u16]) -> Insn {
        Thumb2.decode(&halfwords(values), 0, 0x1000).expect("bytes must decode")
    }

    fn lift_one(values: &[u16]) -> crate::il::Lifted {
        Thumb2.lift(&decode_one(values)).expect("the halfwords must lift")
    }

    fn guard_of(code: &[&[u16]]) -> Option<crate::il::Guard> {
        let lifted: Vec<_> = code.iter().map(|values| Some(lift_one(values))).collect();
        crate::il::find_guards(&lifted).first().map(|found| found.guard)
    }

    /// Encodings from `llvm-mc --triple=thumbv7m --show-encoding`.
    #[test]
    fn cbz_and_cmp_with_beq_are_one_guard() {
        use crate::il::{Cond, Reg, Value};
        const CBZ_R0: &[u16] = &[0xb120];
        const CMP_R0_0: &[u16] = &[0x2800];
        const BEQ: &[u16] = &[0xd004];
        const CBNZ_R1: &[u16] = &[0xb921];
        let cbz = guard_of(&[CBZ_R0]).unwrap();
        assert_eq!(guard_of(&[CMP_R0_0, BEQ]), Some(cbz));
        assert_eq!((cbz.cond, cbz.left), (Cond::Equal, Value::Reg(Reg::General(0))));
        assert_eq!(guard_of(&[CBNZ_R1]).unwrap().cond, Cond::NotEqual);
    }

    #[test]
    fn a_wide_compare_and_branch_are_one_guard() {
        use crate::il::{Cond, Reg, Value};
        const CMP_W_R8_256: &[u16] = &[0xf5b8, 0x7f80];
        const BHS_W: &[u16] = &[0xf080, 0x8020];
        let guard = guard_of(&[CMP_W_R8_256, BHS_W]).unwrap();
        assert_eq!(guard.cond, Cond::UnsignedGreaterOrEqual);
        assert_eq!((guard.left, guard.right), (Value::Reg(Reg::General(8)), Value::Const(256)));
    }

    #[test]
    fn an_it_block_reads_the_flags_and_ends_a_guard() {
        const CMP_R0_0: &[u16] = &[0x2800];
        const IT_EQ: &[u16] = &[0xbf08];
        const BEQ: &[u16] = &[0xd004];
        assert!(lift_one(IT_EQ).reads.contains(crate::il::Reg::Flags));
        assert_eq!(guard_of(&[CMP_R0_0, IT_EQ, BEQ]), None);
    }

    #[test]
    fn a_narrow_load_names_its_width() {
        const LDRB_R0_R1_3: &[u16] = &[0x78c8];
        let load = lift_one(LDRB_R0_R1_3);
        assert_eq!(load.memory.and_then(|access| access.width), Some(crate::il::Width::Bits8));
        assert!(load.writes.contains(crate::il::Reg::General(0)));
    }

    #[test]
    fn lifting_any_halfwords_never_panics() {
        bolero::check!().with_type::<(u16, u16)>().for_each(|&(first, second)| {
            let bytes = halfwords(&[first, second]);
            let Ok(insn) = Thumb2.decode(&bytes, 0, 0x1000) else { return };
            let _ = Thumb2.lift(&insn);
        });
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
    fn tbb_and_tbh_read_as_themselves() {
        let tbb = decode_one(&[0xe8df, 0xf002]);
        assert_eq!(tbb.to_string(), "tbb [pc, r2]");
        let tbh = decode_one(&[0xe8df, 0xf012]);
        assert_eq!(tbh.to_string(), "tbh [pc, r2, lsl 0x1]");
        assert_eq!(tbh.kind, InsnKind::Jump { target: None });
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
        let names: Vec<String> = insns.iter().map(crate::arch::printed_name).collect();
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
    fn a_wide_store_at_an_offset_reads_as_one() {
        // From `llvm-mc --triple=thumbv7`.
        let shown = |values: &[u16]| {
            let insn = decode_one(values);
            insn.to_string()
        };
        assert_eq!(shown(&[0xf8cd, 0x801c]), "str r8, [sp, 0x1c]");
        assert_eq!(shown(&[0xf8ad, 0x801c]), "strh r8, [sp, 0x1c]");
        assert_eq!(shown(&[0xf88d, 0x801c]), "strb r8, [sp, 0x1c]");
        assert_eq!(shown(&[0xf8cd, 0x8000]), "str r8, [sp]");
        assert_eq!(shown(&[0xf840, 0x8001]), "str r8, [r0, r1]", "the register form stays");
        let lifted = lift_one(&[0xf8c5, 0x8004]);
        assert_eq!(lifted.op, crate::il::Op::Store);
        assert_eq!(
            lifted.operands.last(),
            Some(&crate::il::Operand::memory(Some(crate::il::Reg::General(5)), Some(4)))
        );
    }

    #[test]
    fn a_wide_move_keeps_every_bit_of_its_value() {
        // movw ip, 0xfaac; movt ip, 0xfffe: imm4 is set in both.
        let low = decode_one(&[0xf64f, 0x2cac]);
        assert_eq!(low.to_string(), "mov ip, 0xfaac");
        let high = decode_one(&[0xf6cf, 0x7cfe]);
        assert_eq!(high.to_string(), "movt ip, 0xfffe");
        // The lift holds the same values the text shows.
        let constant = |values: &[u16]| lift_one(values).operands.last().copied();
        assert_eq!(constant(&[0xf64f, 0x2cac]), Some(crate::il::Operand::Const(0xfaac)));
        assert_eq!(constant(&[0xf6cf, 0x7cfe]), Some(crate::il::Operand::Const(0xfffe)));
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
    fn the_distance_a_veneer_adds_to_pc_is_a_stored_address() {
        let mut code = halfwords(&[0x4778, 0x46c0]);
        for word in [0xe59f_c000u32, 0xe08c_f00f, 0x0000_1000] {
            code.extend(word.to_le_bytes());
        }
        let (insns, _) = decode_all(&Thumb2, &code, 0x1000);
        let space = AddressSpace::of_raw_image(0x1000, 0x2000);
        let kinds = Thumb2.constant_kinds(&code, &insns, &space);
        // `pc` at the `add` is 0x1008 + 8, and the word adds 0x1000.
        assert_eq!(kinds.last(), Some(&ConstantKind::StoredAddress));
    }

    #[test]
    fn only_a_body_that_opens_with_bx_pc_switches() {
        let code = halfwords(&[0x46c0, 0x4778, 0x46c0]);
        assert!(Thumb2.switch_at_start(&code, 0x1000).is_none());
        assert_eq!(Thumb2.switch_at_start(&code[2..], 0x1002).map(|(_, at)| at), Some(0x1004));
    }

    #[test]
    fn a_t32_neon_store_reads_as_its_a32_twin() {
        let insn = decode_one(&[0xf941, 0x0a8d]);
        assert_eq!(crate::arch::printed_name(&insn), "vst1.32");
        assert_eq!(crate::arch::printed_operands(&insn), "{d16, d17}, [r1]!");
        assert_eq!((insn.bytes_len, insn.kind), (4, InsnKind::Normal));
    }

    #[test]
    fn t32_neon_data_processing_is_unread_code() {
        let insn = decode_one(&[0xefc0, 0x0050]);
        assert_eq!(
            (crate::arch::printed_name(&insn).as_str(), insn.kind),
            (NEON_TEXT, InsnKind::Unknown)
        );
        assert!(Thumb2.is_unread_extension(&insn));
    }

    #[test]
    fn a_t32_word_that_reads_as_a32_neon_is_not_neon() {
        // `f3f0 8000` is no instruction, though `0xf3f08000` would be A32
        // NEON data processing.
        let insn = decode_one(&[0xf3f0, 0x8000]);
        assert_eq!(crate::arch::printed_name(&insn), UNKNOWN_TEXT);
        assert!(!Thumb2.is_unread_extension(&insn));
    }

    #[test]
    fn narrow_and_wide_instructions_have_their_width() {
        let narrow = decode_one(&[0x4770]); // bx lr
        assert_eq!((crate::arch::printed_name(&narrow).as_str(), narrow.bytes_len), ("bx", 2));
        assert_eq!(narrow.kind, InsnKind::Return);
        let wide = decode_one(&[0xf04f, 0x0001]); // mov.w r0, 1
        assert_eq!(
            (crate::arch::printed_name(&wide).as_str(), wide.bytes_len),
            ("mov", 4),
            "no .w"
        );
    }

    #[test]
    fn a_push_with_lr_is_a_prologue_and_a_pop_with_pc_returns() {
        assert!(Thumb2.is_prologue(&decode_one(&[0xb5f0]))); // push {r4, r5, r6, r7, lr}
        assert_eq!(decode_one(&[0xbdf0]).kind, InsnKind::Return); // pop {r4, r5, r6, r7, pc}
    }

    /// Every branch form goes to `pc`, 4 bytes past it, plus twice its
    /// offset.
    #[test]
    fn branches_reach_their_targets() {
        // b.n with an offset of 1: 0x1004 + 2.
        assert_eq!(decode_one(&[0xe001]).kind, InsnKind::Jump { target: Some(0x1006) });
        // bne.n with an offset of 2: 0x1004 + 4.
        assert_eq!(decode_one(&[0xd102]).kind, InsnKind::Branch { target: Some(0x1008) });
        // cbz r0 with an offset of 6: 0x1004 + 12.
        assert_eq!(decode_one(&[0xb130]).kind, InsnKind::Branch { target: Some(0x1010) });
        // b.w with an offset of 0x7fe: 0x1004 + 0xffc.
        assert_eq!(decode_one(&[0xf000, 0xbffe]).kind, InsnKind::Jump { target: Some(0x2000) });
        // bl with an offset of 0x7fe: 0x1004 + 0xffc.
        assert_eq!(decode_one(&[0xf000, 0xfffe]).kind, InsnKind::Call { target: Some(0x2000) });
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

    /// Each `it` covers the conditions its name and its operand print:
    /// `t` the condition, and `e` its opposite.
    #[test]
    fn it_blocks_cover_what_they_print() {
        for condition in 0..14_u16 {
            for mask in 1..16_u16 {
                let insn = decode_one(&[0xbf00 | condition << 4 | mask]);
                assert!(is_it(&insn), "{insn}");
                let then = crate::arch::printed_operands(&insn);
                let names: Vec<&str> = it_conditions(condition as u8, mask as u8)
                    .expect("a condition with an opposite")
                    .into_iter()
                    .map(condition_name)
                    .collect();
                let pattern = &crate::arch::printed_name(&insn)[2..];
                assert_eq!(names.len(), pattern.len() + 1, "{insn}");
                assert_eq!(names[0], then, "{insn}");
                for (name, letter) in names[1..].iter().zip(pattern.chars()) {
                    assert_eq!(letter == 't', *name == then, "{insn}");
                }
            }
        }
        assert!(!is_it(&decode_one(&[0xbf00])), "nop");
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

    fn reg(number: u8) -> crate::il::Operand {
        crate::il::Operand::Reg(crate::il::Reg::General(number))
    }

    /// A 16-bit form names its destination once, and lifts as the 32-bit
    /// form that names it twice.
    #[test]
    fn a_two_address_form_names_its_destination_twice() {
        use crate::il::{Op, Operand};
        // `adds r0, #1` and `ands r0, r1`
        let add = lift_one(&[0x3001]);
        assert_eq!(
            (add.op, add.operands.as_slice()),
            (Op::Add, &[reg(0), reg(0), Operand::Const(1)][..])
        );
        let and = lift_one(&[0x4008]);
        assert_eq!((and.op, and.operands.as_slice()), (Op::And, &[reg(0), reg(0), reg(1)][..]));
        // `lsls r0, r1, #2` names three already.
        assert_eq!(lift_one(&[0x0088]).operands.len(), 3);
    }

    /// `negs r0, r1` is `rsbs r0, r1, #0`, which is `0 - r1`.
    #[test]
    fn a_reverse_subtract_from_zero_is_a_negate() {
        let negate = lift_one(&[0x4248]).canonical();
        assert_eq!(negate.op, crate::il::Op::Negate);
        assert_eq!(negate.operands.as_slice(), [reg(0), reg(1)]);
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
