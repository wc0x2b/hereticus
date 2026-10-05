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

use core::ops::Range;
use std::collections::BTreeSet;

use compact_str::CompactString;
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv7::{ConditionCode, InstDecoder, Instruction, Opcode, Operand};

use super::arm32::{
    Arm32, Encoding, IntegerWord, NEON_LOAD_STORE, NEON_MNEMONIC, PcModel, UNKNOWN_MNEMONIC,
    UNWIND_SECTION, call_targets_through_thunks, classify, decode_fallback, decoder_misreads,
    is_long_thunk, lift_with, parse_hex, pool_loads, split_mnemonic, track_pool_words,
};
use super::{
    Arch, DataAmongCode, DecodeError, Insn, InsnKind, JumpTable, Memory, TableJumps, VectorTable,
};
use crate::address::{AddressSpace, ConstantKind};

/// The narrow T32 instruction, and the alignment of every one.
const HALFWORD: usize = 2;

/// The wide T32 instruction.
const WORD: usize = 4;

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

/// ARM32 in T32 (Thumb-2) mode.
#[derive(Clone, Copy, Debug, Default)]
pub struct Thumb2;

impl Arch for Thumb2 {
    fn decode(&self, code: &[u8], offset: usize, address: u64) -> Result<Insn, DecodeError> {
        let bytes = code.get(offset..).ok_or(DecodeError::Truncated)?;
        let first = bytes.get(..HALFWORD).ok_or(DecodeError::Truncated)?;
        let width = if is_wide(u16::from_le_bytes([first[0], first[1]])) { WORD } else { HALFWORD };
        let bytes = bytes.get(..width).ok_or(DecodeError::Truncated)?;
        let insn_address = address + offset as u64;

        let mut reader = U8Reader::new(bytes);
        let mut inst = Instruction::default();
        let failed = InstDecoder::default_thumb().decode_into(&mut inst, &mut reader).is_err();
        let misread = match *bytes {
            [low, high, second_low, second_high] => decoder_misreads(
                as_a32(u32::from_le_bytes([second_low, second_high, low, high])),
                Encoding::T32,
            ),
            _ => false,
        };
        if failed || inst.opcode == Opcode::Invalid || misread {
            // `yaxpeax-arm` 0.4 reads no VFP in T32 either. A wide T32 `vldr`
            // is the A32 word with the condition that means always, so the
            // A32 reading serves: without it, the doubles a `vldr` loads
            // after a return read as code, as in Lua's `os_clock`.
            let word = match *bytes {
                [low, high, second_low, second_high] => {
                    Some(u32::from_le_bytes([second_low, second_high, low, high]))
                }
                _ => None,
            };
            let fallback = word.and_then(|word| decode_fallback(as_a32(word), Encoding::T32));
            if let Some((mnemonic, operands)) = fallback {
                return Ok(Insn {
                    address: insn_address,
                    bytes_len: width,
                    mnemonic,
                    operands,
                    kind: InsnKind::Normal,
                });
            }
            // The width comes from the first halfword, so stepping over an
            // unreadable instruction keeps the rest aligned. Its bytes go in
            // the operands, so that an edit to it still shows.
            let operands = bytes.iter().rev().map(|byte| format!("{byte:02x}")).collect();
            let is_neon = word.is_some_and(|word| matches!(word >> 24, 0xef | 0xff));
            let mnemonic = if is_neon { NEON_MNEMONIC } else { UNKNOWN_MNEMONIC };
            return Ok(Insn {
                address: insn_address,
                bytes_len: width,
                mnemonic: mnemonic.to_string(),
                operands,
                kind: InsnKind::Unknown,
            });
        }

        let text = inst.to_string();
        let (mnemonic, operands) = split_mnemonic(&text);
        // `.w` only says the encoding is wide, which the length already
        // does. Without it, the narrow and the wide form of one operation
        // compare alike, as A32 names them. A condition can follow it, as in
        // `b.wne`.
        let mnemonic = mnemonic.replace(".w", "").replace(".n", "");
        let (mnemonic, operands) = match *bytes {
            [low, high, second_low, second_high] => {
                let (first, second) = (
                    u16::from_le_bytes([low, high]),
                    u16::from_le_bytes([second_low, second_high]),
                );
                let fixed = wide_move_operands(first, second)
                    .map(|operands| (mnemonic.clone(), operands))
                    .or_else(|| {
                        wide_store(first, second)
                            .map(|store| (store.mnemonic().to_string(), store.operands()))
                    });
                match (table_branch(first, second), WideWord::of(first, second), fixed) {
                    (Some((mnemonic, operands)), ..) => (mnemonic.to_string(), operands),
                    (None, Some(word), _) => word.text(),
                    (None, None, Some(fixed)) => fixed,
                    (None, None, None) => (mnemonic, shift_of_32(first, second, operands)),
                }
            }
            _ => (mnemonic, operands),
        };
        let target = branch_target(&inst, insn_address, width);
        let operands = match target {
            Some(target) => with_target_text(&operands, insn_address, target),
            None => operands,
        };
        let kind = match inst.opcode {
            Opcode::CBZ | Opcode::CBNZ => InsnKind::Branch { target },
            Opcode::TBB | Opcode::TBH => InsnKind::Jump { target: None },
            Opcode::IT => InsnKind::Normal,
            _ => classify(&inst, target),
        };

        Ok(Insn { address: insn_address, bytes_len: width, mnemonic, operands, kind })
    }

    fn triple(&self) -> &'static str {
        "thumbv7-linux-gnueabi"
    }

    /// The narrow width, which every instruction is a multiple of and is
    /// aligned to.
    fn instruction_width(&self) -> usize {
        HALFWORD
    }

    fn is_register(&self, operand: &str) -> bool {
        Arm32.is_register(operand)
    }

    fn is_stack_register(&self, operand: &str) -> bool {
        Arm32.is_stack_register(operand)
    }

    fn is_frame_register(&self, reg: crate::il::Reg) -> bool {
        Arm32.is_frame_register(reg)
    }

    /// T32 has no condition field to test, so the first instruction must
    /// read as one and not as padding.
    fn can_open_function(&self, bytes: &[u8]) -> bool {
        self.decode(bytes, 0, 0)
            .is_ok_and(|insn| insn.kind != InsnKind::Unknown && !self.is_padding(&insn))
    }

    fn mentions_stack_slot(&self, operands: &str) -> bool {
        Arm32.mentions_stack_slot(operands)
    }

    fn is_register_list(&self, operand: &str) -> bool {
        Arm32.is_register_list(operand)
    }

    fn constant_value(&self, operand: &str) -> Option<u64> {
        Arm32.constant_value(operand)
    }

    fn normalize_operation(&self, mnemonic: &str) -> CompactString {
        Arm32.normalize_operation(mnemonic)
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
        insn.mnemonic == NEON_MNEMONIC
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
            .chunks_exact(WORD)
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

    fn before_pc_reference<'a>(&self, operands: &'a str) -> Option<&'a str> {
        Arm32.before_pc_reference(operands)
    }

    fn preamble_before_prologue(&self, earlier: &[Insn]) -> usize {
        Arm32.preamble_before_prologue(earlier)
    }

    fn is_tail_call(&self, insn: &Insn) -> bool {
        Arm32.is_tail_call(insn)
    }

    /// An `it` makes the next one to four instructions conditional: `itt`
    /// two, `itete` four. A return or a jump among them falls through when
    /// its condition fails, so it is a branch.
    fn after_decoding(&self, insns: &mut [Insn]) {
        // The conditions of the instructions an `it` covers, next first.
        let mut conditions: Vec<&'static str> = Vec::new();
        for insn in insns {
            if !conditions.is_empty() {
                let condition = conditions.remove(0);
                insn.kind = match insn.kind {
                    InsnKind::Return => InsnKind::Branch { target: None },
                    InsnKind::Jump { target } => InsnKind::Branch { target },
                    kind => kind,
                };
                // `yaxpeax-arm` prints no condition inside the block, so
                // `movgt r0, #0` read as `movs r0, 0x0`. A 16-bit form that
                // sets the flags outside a block does not inside one.
                let base = match insn.bytes_len == HALFWORD && insn.mnemonic.len() > 2 {
                    true => insn.mnemonic.strip_suffix('s').unwrap_or(&insn.mnemonic),
                    false => &insn.mnemonic,
                };
                if !base.ends_with(condition) {
                    insn.mnemonic = format!("{base}{condition}");
                }
            } else if let Some(covered) = it_conditions(&insn.mnemonic, &insn.operands) {
                conditions = covered;
            }
        }
    }

    /// A zero halfword reads as `lsls r0, r0, 0`, which changes nothing but
    /// the flags, and fills the gap before a word-aligned pool.
    fn is_padding(&self, insn: &Insn) -> bool {
        insn.mnemonic == "nop"
            || (insn.mnemonic == "mov" && insn.operands == "r8, r8")
            || (insn.mnemonic == "lsls" && insn.operands == "r0, r0, 0x0")
            // LLD's fill, `0xd4d4`, reads as this branch back. No compiler
            // branches back into the middle of the fill before a function.
            || (insn.mnemonic == "bmi" && insn.operands == "$-0x54")
            || (insn.kind == InsnKind::Unknown && insn.operands == "0000")
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

    fn pointer_width(&self) -> usize {
        WORD
    }

    fn lift(&self, insn: &Insn, word: &[u8]) -> Option<crate::il::Lifted> {
        if let [low, high, second_low, second_high] = *word
            && let Some(store) = wide_store(
                u16::from_le_bytes([low, high]),
                u16::from_le_bytes([second_low, second_high]),
            )
        {
            return Some(store.lifted());
        }
        if let [low, high, second_low, second_high] = *word
            && let Some(wide) = WideWord::of(
                u16::from_le_bytes([low, high]),
                u16::from_le_bytes([second_low, second_high]),
            )
        {
            return Some(wide.lifted());
        }
        let a32 = match *word {
            [low, high, second_low, second_high] => {
                Some(as_a32(u32::from_le_bytes([second_low, second_high, low, high])))
            }
            _ => None,
        };
        let mut lifted = lift_with(
            InstDecoder::default_thumb(),
            insn,
            word,
            a32.map(|a32| (a32, Encoding::T32)),
        )?;
        // `yaxpeax-arm` misplaces `imm4` of `movw` and `movt`, so the
        // constant is read again from the encoding, as the text is.
        if let [low, high, second_low, second_high] = *word
            && let Some(value) = wide_move_value(
                u16::from_le_bytes([low, high]),
                u16::from_le_bytes([second_low, second_high]),
            )
            && let Some(constant) = lifted
                .operands
                .iter_mut()
                .rev()
                .find(|operand| matches!(operand, crate::il::Operand::Const(_)))
        {
            *constant = crate::il::Operand::Const(u64::from(value));
        }
        Some(lifted)
    }

    fn read_pointer(&self, bytes: &[u8]) -> u64 {
        u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
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

/// The operands of a T32 `movw` or `movt`, read from the encoding:
///
/// ```text
/// 11110 i 10 0 1 0 0 imm4 | 0 imm3 Rd imm8      movw
/// 11110 i 10 1 1 0 0 imm4 | 0 imm3 Rd imm8      movt
/// ```
///
/// The value is `imm4:i:imm3:imm8`. `yaxpeax-arm` 0.4 puts `imm4` four bits
/// too high, so `movw ip, 0xfaac` reads as `0xf0aac`. Most values a thunk
/// builds have `imm4` clear, so only a far jump, as from T32 to an A32
/// function, showed it.
fn wide_move_operands(first: u16, second: u16) -> Option<String> {
    let value = wide_move_value(first, second)?;
    let register = REGISTER_NAMES[usize::from(second >> 8 & 0xf)];
    Some(format!("{register}, {value:#x}"))
}

/// A T32 store of a register at an offset from a base, read from the
/// encoding:
///
/// ```text
/// 1111 1000 1 sz 0 Rn | Rt imm12      str.w, strh.w, strb.w
/// ```
///
/// `yaxpeax-arm` 0.4 reads these as the store at an offset in a register,
/// so `str.w r8, [sp, #0x1c]` read as `str r8, [sp, ip, lsl 1]`. The loads
/// of the same form read right.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WideStore {
    value: u16,
    base: u16,
    offset: u16,
    width: crate::il::Width,
}

impl WideStore {
    /// The mnemonic, by the width stored. `yaxpeax-arm` 0.4 names a store
    /// whose offset has the bits `1110` at 8 to 11 `strt`: `str.w r1, [r8,
    /// #0xec4]` read as `strt`.
    fn mnemonic(self) -> &'static str {
        match self.width {
            crate::il::Width::Bits8 => "strb",
            crate::il::Width::Bits16 => "strh",
            _ => "str",
        }
    }

    /// The operands as the decoder prints those of a load.
    fn operands(self) -> String {
        let (value, base) =
            (REGISTER_NAMES[usize::from(self.value)], REGISTER_NAMES[usize::from(self.base)]);
        match self.offset {
            0 => format!("{value}, [{base}]"),
            offset => format!("{value}, [{base}, {offset:#x}]"),
        }
    }

    /// The store as the IL reads it.
    fn lifted(self) -> crate::il::Lifted {
        use crate::il::{AccessKind, Lifted, MemoryAccess, Op, Operand, Reg};
        let reg = |number: u16| match number {
            13 => Reg::Stack,
            number => Reg::General(number as u8),
        };
        let mut lifted = Lifted {
            op: Op::Store,
            memory: Some(MemoryAccess { kind: AccessKind::Store, width: Some(self.width) }),
            ..Lifted::default()
        };
        lifted.reads.insert(reg(self.value));
        lifted.reads.insert(reg(self.base));
        lifted.operands = [
            Operand::Reg(reg(self.value)),
            Operand::Memory { base: Some(reg(self.base)), offset: Some(i64::from(self.offset)) },
        ]
        .into_iter()
        .collect();
        lifted
    }
}

/// The wide store at an offset that `first` and `second` encode, if they
/// encode one: see [`WideStore`].
fn wide_store(first: u16, second: u16) -> Option<WideStore> {
    use crate::il::Width;
    let width = match first & 0xfff0 {
        0xf8c0 => Width::Bits32,
        0xf8a0 => Width::Bits16,
        0xf880 => Width::Bits8,
        _ => return None,
    };
    let (value, base) = (second >> 12, first & 0xf);
    // `pc` as either is another encoding, or none.
    (value != 15 && base != 15).then_some(WideStore { value, base, offset: second & 0xfff, width })
}

/// The 16-bit value of a T32 `movw` or `movt`: see [`wide_move_operands`].
fn wide_move_value(first: u16, second: u16) -> Option<u32> {
    const MOVW: u16 = 0xf240;
    const MOVT: u16 = 0xf2c0;
    const OPCODE_MASK: u16 = 0xfbf0;
    if !matches!(first & OPCODE_MASK, MOVW | MOVT) || second & 0x8000 != 0 {
        return None;
    }
    let imm4 = u32::from(first & 0xf);
    let i = u32::from(first >> 10 & 1);
    let imm3 = u32::from(second >> 12 & 0b111);
    let imm8 = u32::from(second & 0xff);
    Some(imm4 << 12 | i << 11 | imm3 << 8 | imm8)
}

/// A wide T32 word that `yaxpeax-arm` 0.4 reads wrong, read from the
/// encoding. `tests/differential.rs` found each against `llvm-objdump`:
///
/// ```text
/// 1111 0i00 011S 1111 | 0 imm3 Rd imm8          mvn rd, #const
/// 1111 1010 0 ty S Rn | 1111 Rd 0000 Rm         lsl rd, rn, rm, and kin
/// 1111 1010 0 op Rn   | 1111 Rd 10 rot Rm       uxtb rd, rm, ror #8, and kin
/// 1111 0011 0110 Rn   | 0 imm3 Rd imm2 0 msb    bfi rd, rn, #lsb, #width
/// ```
///
/// It read `mvn` as `mov`, every shift by a register as `lsl`, the
/// rotation of an extend from the wrong bits, and `bfi` with its last bit
/// for its width. The shift, the extend and the insert are the operations
/// A32 encodes too, so they read and lift as [`IntegerWord`] does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WideWord {
    /// `mvn rd, #value`, or `mvns`.
    NotConstant { rd: u32, value: u32, sets_flags: bool },
    /// `lsl rd, rn, rm` and kin, or `lsls`.
    Shift { kind: u32, sets_flags: bool, rd: u32, rn: u32, rm: u32 },
    /// An extend or a bit field insert.
    Integer(IntegerWord),
}

impl WideWord {
    fn of(first: u16, second: u16) -> Option<Self> {
        let (first, second) = (u32::from(first), u32::from(second));
        let field = |half: u32, shift: u32, width: u32| half >> shift & ((1 << width) - 1);
        let rd = field(second, 8, 4);
        let rn = field(first, 0, 4);
        let rm = field(second, 0, 4);
        if first & 0xfbef == 0xf06f && second & 0x8000 == 0 {
            let constant =
                field(first, 10, 1) << 11 | field(second, 12, 3) << 8 | field(second, 0, 8);
            return Some(Self::NotConstant {
                rd,
                value: thumb_expand_constant(constant),
                sets_flags: field(first, 4, 1) == 1,
            });
        }
        if first & 0xff80 == 0xfa00 && second & 0xf0f0 == 0xf000 {
            let (kind, sets_flags) = (field(first, 5, 2), field(first, 4, 1) == 1);
            return Some(Self::Shift { kind, sets_flags, rd, rn, rm });
        }
        if first & 0xff80 == 0xfa00 && second & 0xf0c0 == 0xf080 {
            let name = match field(first, 4, 3) {
                0b000 => "sxth",
                0b001 => "uxth",
                0b010 => "sxtb16",
                0b011 => "uxtb16",
                0b100 => "sxtb",
                0b101 => "uxtb",
                _ => return None,
            };
            let rn = (rn != 15).then_some(rn);
            let rotation = field(second, 4, 2) * 8;
            return Some(Self::Integer(IntegerWord::Extend { name, rd, rn, rm, rotation }));
        }
        if first & 0xfff0 == 0xf360 && second & 0x8020 == 0 {
            let lsb = field(second, 12, 3) << 2 | field(second, 6, 2);
            let width = field(second, 0, 5).checked_sub(lsb)? + 1;
            let rn = (rn != 15).then_some(rn);
            return Some(Self::Integer(IntegerWord::Insert { rd, rn, lsb, width }));
        }
        None
    }

    /// The mnemonic and the operands, as the decoder prints them.
    fn text(self) -> (String, String) {
        let name = |number: u32| REGISTER_NAMES[number as usize];
        let flags = |sets_flags: bool| if sets_flags { "s" } else { "" };
        match self {
            Self::NotConstant { rd, value, sets_flags } => {
                (format!("mvn{}", flags(sets_flags)), format!("{}, {value:#x}", name(rd)))
            }
            Self::Shift { kind, sets_flags, rd, rn, rm } => {
                let shift = ["lsl", "lsr", "asr", "ror"][kind as usize];
                (
                    format!("{shift}{}", flags(sets_flags)),
                    format!("{}, {}, {}", name(rd), name(rn), name(rm)),
                )
            }
            Self::Integer(word) => (word.mnemonic(), word.operands()),
        }
    }

    /// The IL form, as A32 lifts the same operation.
    fn lifted(self) -> crate::il::Lifted {
        use crate::il::{Lifted, Op, Operand, Reg};
        match self {
            // `mvn r0, #1` puts the constant `~1` in `r0`.
            Self::NotConstant { rd, value, sets_flags } => {
                let mut lifted = Lifted { op: Op::Move, ..Lifted::default() };
                let dest = match rd {
                    13 => Reg::Stack,
                    number => Reg::General(number as u8),
                };
                lifted.operands =
                    [Operand::Reg(dest), Operand::Const(u64::from(!value))].into_iter().collect();
                lifted.writes.insert(dest);
                if sets_flags {
                    lifted.writes.insert(Reg::Flags);
                }
                lifted
            }
            Self::Shift { kind, sets_flags, rd, rn, rm } => {
                IntegerWord::ShiftByRegister { not: false, sets_flags, rd, rm: rn, kind, rs: rm }
                    .lift()
            }
            Self::Integer(word) => word.lift(),
        }
    }
}

/// The 32-bit constant that the 12 bits of a T32 data processing word
/// stand for: `ThumbExpandImm` of the Arm architecture manual. A byte
/// repeated in a pattern, or a byte with its top bit set, rotated.
fn thumb_expand_constant(constant: u32) -> u32 {
    let byte = constant & 0xff;
    if constant >> 10 == 0 {
        return match constant >> 8 & 0b11 {
            0b00 => byte,
            0b01 => byte << 16 | byte,
            0b10 => byte << 24 | byte << 8,
            _ => byte * 0x0101_0101,
        };
    }
    (0x80 | constant & 0x7f).rotate_right(constant >> 7)
}

/// `operands` of a wide data processing word whose second value is
/// shifted, with a shift right of 0 put right: the encoding means 32.
///
/// ```text
/// 1110 101x xxxx Rn | 0 imm3 Rd imm2 type Rm
/// ```
///
/// `yaxpeax-arm` 0.4 prints the field, so `ands.w r3, r3, r1, asr #32`
/// read as `asr 0`.
fn shift_of_32(first: u16, second: u16, operands: String) -> String {
    let amount = (second >> 12 & 0b111) << 2 | (second >> 6 & 0b11);
    let kind = second >> 4 & 0b11;
    if first & 0xfe00 != 0xea00 || amount != 0 || !matches!(kind, 0b01 | 0b10) {
        return operands;
    }
    match operands.strip_suffix(" 0x0").or_else(|| operands.strip_suffix(" 0")) {
        Some(rest) => format!("{rest} 0x20"),
        None => operands,
    }
}

/// The T32 `tbb` or `tbh`, read from the encoding:
///
/// ```text
/// 1110 1000 1101 Rn | 1111 0000 000 H Rm
/// ```
///
/// `yaxpeax-arm` 0.4 reads `tbh [pc, r2, lsl 1]` as `tbb [pc, r2, lsl r0]`,
/// so a table of halfwords read as one of bytes. Measured on Lua built by GCC
/// at `-Os` for Thumb-2, the `tbh` of `luaV_execute` cut it in 19 pieces.
fn table_branch(first: u16, second: u16) -> Option<(&'static str, String)> {
    const TABLE_BRANCH: u16 = 0xe8d0;
    if first & 0xfff0 != TABLE_BRANCH || second & 0xffe0 != 0xf000 {
        return None;
    }
    let base = REGISTER_NAMES[usize::from(first & 0xf)];
    let index = REGISTER_NAMES[usize::from(second & 0xf)];
    Some(match second >> 4 & 1 {
        0 => ("tbb", format!("[{base}, {index}]")),
        _ => ("tbh", format!("[{base}, {index}, lsl 0x1]")),
    })
}

/// The names of the general registers, as `yaxpeax-arm` prints them.
const REGISTER_NAMES: [&str; 16] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "sb", "sl", "fp", "ip", "sp", "lr", "pc",
];

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

/// The A32 word for the wide T32 `word`, first halfword high, where the two
/// sets encode one instruction alike but for the top bits.
///
/// NEON data processing is `111U 1111` in T32 and `1111 001U` in A32, and a
/// NEON element or structure load or store is `1111 1001` in T32 and
/// `1111 0100` in A32. VFP is the same word in both, with the A32 condition
/// that means always.
fn as_a32(word: u32) -> u32 {
    const LOW: u32 = 0x00ff_ffff;
    match word >> 24 {
        0xef => 0xf200_0000 | word & LOW,
        0xff => 0xf300_0000 | word & LOW,
        0xf9 => NEON_LOAD_STORE << 24 | word & LOW,
        _ => word,
    }
}

/// Report whether the halfword `first` opens a 32-bit instruction.
fn is_wide(first: u16) -> bool {
    matches!(first >> 11, 0b11101..=0b11111)
}

/// Where a branch goes: `pc`, 4 bytes past the branch, plus twice the
/// offset it holds.
///
/// `yaxpeax` reports one more than the encoding holds for a narrow `cbz`,
/// `cbnz` and conditional `b`, and the encoding itself for the rest. A call
/// that switches to A32 goes to a word, so its target rounds down.
fn branch_target(inst: &Instruction, address: u64, width: usize) -> Option<u64> {
    let reported = inst.operands.iter().find_map(|operand| match operand {
        Operand::BranchThumbOffset(halfwords) => Some(i64::from(*halfwords)),
        _ => None,
    })?;
    let conditional = inst.condition != ConditionCode::AL;
    let biased = width == HALFWORD
        && (matches!(inst.opcode, Opcode::CBZ | Opcode::CBNZ)
            || (inst.opcode == Opcode::B && conditional));
    let halfwords = if biased { reported - 1 } else { reported };
    let pc = address as i64 + WORD as i64;
    let target = u64::try_from(pc + halfwords * HALFWORD as i64).ok()?;
    Some(if inst.opcode == Opcode::BLX { target & !3 } else { target })
}

/// `operands` with the distance `yaxpeax` prints, `$+0x2e`, put right: the
/// distance from the instruction to `target`.
///
/// `yaxpeax` 0.4 prints the offset of the encoding, which counts from the
/// program counter, 4 bytes on, and for a narrow conditional branch is one
/// halfword off besides: `bne $+0x2e` went to the instruction 0x30 on.
/// A32 prints the distance from the instruction, and so does this.
fn with_target_text(operands: &str, address: u64, target: u64) -> String {
    let Some(start) = operands.find("$+").or_else(|| operands.find("$-")) else {
        return operands.to_string();
    };
    let end = operands[start..].find(',').map_or(operands.len(), |at| start + at);
    let distance = target as i64 - address as i64;
    let sign = if distance < 0 { '-' } else { '+' };
    format!("{}${sign}{:#x}{}", &operands[..start], distance.unsigned_abs(), &operands[end..])
}

/// How many instructions after an `it` it makes conditional, if `mnemonic`
/// is one: one, and one more for each `t` or `e` after `it`.
/// The condition of each instruction an `it` covers, in order: `t` takes
/// the condition of the block, and `e` its opposite.
fn it_conditions(mnemonic: &str, condition: &str) -> Option<Vec<&'static str>> {
    const PAIRS: [(&str, &str); 7] = [
        ("eq", "ne"),
        ("hs", "lo"),
        ("mi", "pl"),
        ("vs", "vc"),
        ("hi", "ls"),
        ("ge", "lt"),
        ("gt", "le"),
    ];
    let condition = condition.trim();
    let (then, otherwise) = PAIRS.iter().find_map(|&(a, b)| {
        (condition == a).then_some((a, b)).or((condition == b).then_some((b, a)))
    })?;
    it_block_length(mnemonic)?;
    let pattern = &mnemonic[2..];
    let rest = pattern.chars().map(|letter| if letter == 't' { then } else { otherwise });
    Some(core::iter::once(then).chain(rest).collect())
}

/// How many instructions the `it` of `mnemonic` covers, or `None` where
/// `mnemonic` is no `it`.
pub(crate) fn it_block_length(mnemonic: &str) -> Option<usize> {
    let pattern = mnemonic.strip_prefix("it")?;
    (pattern.len() <= 3 && pattern.chars().all(|letter| letter == 't' || letter == 'e'))
        .then_some(pattern.len() + 1)
}

/// The bytes of the table a `tbb` or `tbh` at `insns[index]` jumps
/// through, and the width of an entry, from the instructions alone.
fn table_extent(insns: &[Insn], index: usize) -> Option<(Range<u64>, usize)> {
    let jump = &insns[index];
    let width = match jump.mnemonic.as_str() {
        "tbb" => 1,
        "tbh" => 2,
        _ => return None,
    };
    let inner = jump.operands.strip_prefix("[pc, ")?;
    let index_register = inner.split([',', ']']).next()?.trim();

    // `cmp rI, n`: the cases run from 0 to n.
    let bound =
        insns[index.saturating_sub(TABLE_LOOK_BACK)..index].iter().rev().find_map(|insn| {
            let operands: Vec<&str> = insn.operands.split(',').map(str::trim).collect();
            match (Arm32.normalize_operation(&insn.mnemonic).as_str(), operands.as_slice()) {
                ("cmp", [.., register, bound]) if *register == index_register => parse_hex(bound),
                _ => None,
            }
        })?;
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
        for (first, second, mnemonic, operands) in cases {
            let bytes = halfwords(&[first, second]);
            let insn = Thumb2.decode(&bytes, 0, 0).expect("the word reads");
            assert_eq!((insn.mnemonic.as_str(), insn.operands.as_str()), (mnemonic, operands));
        }
        let lift = |first, second| {
            let bytes = halfwords(&[first, second]);
            Thumb2.lift(&Thumb2.decode(&bytes, 0, 0).unwrap(), &bytes).expect("the word lifts")
        };
        // `mvn r0, #2` puts `~2` in `r0`.
        let not = lift(0xf06f, 0x0002);
        assert_eq!(not.op, crate::il::Op::Move);
        assert_eq!(not.operands[1], crate::il::Operand::Const(u64::from(!2u32)));
        assert_eq!(lift(0xfa4c, 0xfc00).op, crate::il::Op::ShiftRightArithmetic);
        assert_eq!(lift(0xfa6c, 0xfc00).op, crate::il::Op::Rotate);
        // `asr #32` is encoded as a shift of 0.
        let shifted = Thumb2.decode(&halfwords(&[0xea13, 0x0321]), 0, 0).unwrap();
        assert_eq!(shifted.operands, "r3, r3, r1, asr 0x20");
        let plain = Thumb2.decode(&halfwords(&[0xea13, 0x0301]), 0, 0).unwrap();
        assert_eq!(plain.operands, "r3, r3, r1");
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
        for (bytes, mnemonic, operands) in cases {
            let insn = Thumb2.decode(bytes, 0, 0x1000).expect("the branch reads");
            assert_eq!((insn.mnemonic.as_str(), insn.operands.as_str()), (mnemonic, operands));
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
        let bytes = halfwords(values);
        Thumb2.lift(&decode_one(values), &bytes).expect("the halfwords must lift")
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
            let _ = Thumb2.lift(&insn, &bytes[..insn.bytes_len]);
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
        assert_eq!((tbb.mnemonic.as_str(), tbb.operands.as_str()), ("tbb", "[pc, r2]"));
        let tbh = decode_one(&[0xe8df, 0xf012]);
        assert_eq!((tbh.mnemonic.as_str(), tbh.operands.as_str()), ("tbh", "[pc, r2, lsl 0x1]"));
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
        let mnemonics: Vec<&str> = insns.iter().map(|insn| insn.mnemonic.as_str()).collect();
        assert_eq!(mnemonics, ["ite", "movgt", "movle", "adds"]);
        assert_eq!(it_conditions("itet", "eq"), Some(vec!["eq", "ne", "eq"]));
        assert_eq!(it_conditions("it", "al"), None, "no condition to name");
    }

    #[test]
    fn a_wide_store_at_an_offset_reads_as_one() {
        // From `llvm-mc --triple=thumbv7`.
        let shown = |values: &[u16]| {
            let insn = decode_one(values);
            format!("{} {}", insn.mnemonic, insn.operands)
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
            Some(&crate::il::Operand::Memory {
                base: Some(crate::il::Reg::General(5)),
                offset: Some(4)
            })
        );
    }

    #[test]
    fn a_wide_move_keeps_every_bit_of_its_value() {
        // movw ip, 0xfaac; movt ip, 0xfffe: imm4 is set in both.
        let low = decode_one(&[0xf64f, 0x2cac]);
        assert_eq!((low.mnemonic.as_str(), low.operands.as_str()), ("mov", "ip, 0xfaac"));
        let high = decode_one(&[0xf6cf, 0x7cfe]);
        assert_eq!((high.mnemonic.as_str(), high.operands.as_str()), ("movt", "ip, 0xfffe"));
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
        assert_eq!(insn.mnemonic, "vst1.32");
        assert_eq!(insn.operands, "{d16, d17}, [r1]!");
        assert_eq!((insn.bytes_len, insn.kind), (4, InsnKind::Normal));
    }

    #[test]
    fn t32_neon_data_processing_is_unread_code() {
        let insn = decode_one(&[0xefc0, 0x0050]);
        assert_eq!((insn.mnemonic.as_str(), insn.kind), (NEON_MNEMONIC, InsnKind::Unknown));
        assert!(Thumb2.is_unread_extension(&insn));
    }

    #[test]
    fn a_t32_word_that_reads_as_a32_neon_is_not_neon() {
        // `f3f0 8000` is no instruction, though `0xf3f08000` would be A32
        // NEON data processing.
        let insn = decode_one(&[0xf3f0, 0x8000]);
        assert_eq!(insn.mnemonic, UNKNOWN_MNEMONIC);
        assert!(!Thumb2.is_unread_extension(&insn));
    }

    #[test]
    fn narrow_and_wide_instructions_have_their_width() {
        let narrow = decode_one(&[0x4770]); // bx lr
        assert_eq!((narrow.mnemonic.as_str(), narrow.bytes_len), ("bx", 2));
        assert_eq!(narrow.kind, InsnKind::Return);
        let wide = decode_one(&[0xf04f, 0x0001]); // mov.w r0, 1
        assert_eq!((wide.mnemonic.as_str(), wide.bytes_len), ("mov", 4), "no .w");
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

    #[test]
    fn it_blocks_cover_up_to_four() {
        assert_eq!(it_block_length("it"), Some(1));
        assert_eq!(it_block_length("ite"), Some(2));
        assert_eq!(it_block_length("ittee"), Some(4));
        assert_eq!(it_block_length("itteet"), None);
        assert_eq!(it_block_length("iteq"), None);
        assert_eq!(it_block_length("mov"), None);
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
}
