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
    Arm32, NEON_LOAD_STORE, NEON_MNEMONIC, PcModel, UNKNOWN_MNEMONIC, UNWIND_SECTION, classify,
    decode_fallback, parse_hex, pool_loads, pool_words_loaded, split_mnemonic, track_pool_words,
};
use super::{Arch, DataAmongCode, DecodeError, Insn, InsnKind, JumpTable, Memory};
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
        if failed || inst.opcode == Opcode::Invalid {
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
            let fallback = word.and_then(|word| decode_fallback(as_a32(word)));
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
        let target = branch_target(&inst, insn_address, width);
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
        track_pool_words(code, body, space, PcModel::T32).kinds
    }

    fn data_addresses(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        _memory: &Memory<'_>,
    ) -> Vec<u64> {
        track_pool_words(code, body, space, PcModel::T32).addresses
    }

    fn literal_pool_words(&self, insns: &[Insn]) -> Vec<u64> {
        pool_words_loaded(insns, PcModel::T32)
    }

    fn literal_pool_loads(&self, insns: &[Insn]) -> Vec<(u64, u64)> {
        pool_loads(insns, PcModel::T32)
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

    fn call_targets(&self, insns: &[Insn]) -> Vec<(usize, Option<super::CallTarget>)> {
        insns
            .iter()
            .enumerate()
            .filter_map(|(index, insn)| match insn.kind {
                InsnKind::Call { target } => Some((index, target.map(super::CallTarget::Address))),
                InsnKind::Jump { target: Some(target) } if super::leaves(insns, target) => {
                    Some((index, Some(super::CallTarget::Address(target))))
                }
                // A range extension thunk jumps to where it formed.
                InsnKind::Jump { target: None } if index >= 3 => thunk_target(&insns[index - 3..])
                    .map(|target| (index, Some(super::CallTarget::Address(target)))),
                _ => None,
            })
            .collect()
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

    /// LLD's range extension thunk is a function by itself:
    ///
    /// ```text
    /// movw ip, lo
    /// movt ip, hi
    /// add  ip, pc
    /// bx   ip
    /// ```
    ///
    /// A thunk that nothing in this build calls still starts there, and a
    /// run of them otherwise reads as one function.
    fn is_function_entry(&self, body: &[Insn]) -> bool {
        let [movw, movt, add, bx, ..] = body else { return false };
        movw.mnemonic == "mov"
            && movw.operands.starts_with("ip, 0x")
            && movt.mnemonic == "movt"
            && movt.operands.starts_with("ip, ")
            && add.mnemonic == "add"
            && add.operands == "ip, pc"
            && bx.mnemonic == "bx"
            && bx.operands == "ip"
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
        let mut conditional = 0;
        for insn in insns {
            if conditional > 0 {
                conditional -= 1;
                insn.kind = match insn.kind {
                    InsnKind::Return => InsnKind::Branch { target: None },
                    InsnKind::Jump { target } => InsnKind::Branch { target },
                    kind => kind,
                };
            } else if let Some(count) = it_block_length(&insn.mnemonic) {
                conditional = count;
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
            || (insn.mnemonic == "bmi" && insn.operands == "$-0x56")
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

    fn distance_words(&self, code: &[u8], insns: &[Insn]) -> BTreeSet<u64> {
        track_pool_words(code, insns, &AddressSpace::default(), PcModel::T32).distances
    }
}

/// Where the range extension thunk that `body` opens with jumps: the value
/// `movw` and `movt` build, plus `pc` at the `add`, without the T32 bit.
fn thunk_target(body: &[Insn]) -> Option<u64> {
    if !Thumb2.is_function_entry(body) {
        return None;
    }
    let low = parse_hex(body[0].operands.strip_prefix("ip, ")?)?;
    let high = parse_hex(body[1].operands.strip_prefix("ip, ")?)?;
    let distance = (high << 16 | low) as u32;
    let pc = PcModel::T32.of(body[2].address) as u32;
    Some(u64::from(pc.wrapping_add(distance) & !1))
}

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

/// How many instructions after an `it` it makes conditional, if `mnemonic`
/// is one: one, and one more for each `t` or `e` after `it`.
fn it_block_length(mnemonic: &str) -> Option<usize> {
    let pattern = mnemonic.strip_prefix("it")?;
    (pattern.len() <= 3 && pattern.chars().all(|letter| letter == 't' || letter == 'e'))
        .then_some(pattern.len() + 1)
}

/// Read the table a `tbb` or `tbh` at `insns[index]` jumps through.
fn read_branch_table(
    memory: &Memory<'_>,
    code: &Range<u64>,
    insns: &[Insn],
    index: usize,
) -> Option<JumpTable> {
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
    use crate::arch::decode_all;

    /// T32 code from halfwords, little endian.
    fn halfwords(values: &[u16]) -> Vec<u8> {
        values.iter().flat_map(|value| value.to_le_bytes()).collect()
    }

    fn decode_one(values: &[u16]) -> Insn {
        Thumb2.decode(&halfwords(values), 0, 0x1000).expect("bytes must decode")
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
}
