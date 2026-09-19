//! ARM32 (A32) decoding, on top of `yaxpeax-arm`.
//!
//! Two details of the `yaxpeax` API are easy to get wrong, so this module
//! handles both and the rest of `fndiff` never sees them:
//!
//! 1. `U8Reader` implements `Reader<u32, U32le>`, not `Reader<u32, u32>`.
//! 2. `total_offset()` counts **words**, not bytes. Multiplying by the
//!    instruction width is what makes reported addresses right.

use yaxpeax_arch::{Decoder, Reader, U8Reader, U32le};
use yaxpeax_arm::armv7::{ConditionCode, InstDecoder, Instruction, Opcode, Operand};

use super::{Arch, DecodeError, Insn, InsnKind};

/// Every A32 instruction is 4 bytes wide.
const INSN_WIDTH: usize = 4;

/// Mnemonic reported for bytes the decoder cannot read.
///
/// `yaxpeax-arm` 0.4 has no NEON or SIMD support and answers "incomplete
/// decoder" for those encodings. `clang` vectorizes automatically at `-O2`,
/// so real code reaches this path.
const UNKNOWN_MNEMONIC: &str = "(unknown)";

/// Register number of the program counter.
const REG_PC: u16 = 15;
/// Register number of the link register.
const REG_LR: u16 = 14;

/// ARM32 in A32 (not Thumb) mode.
#[derive(Clone, Copy, Debug, Default)]
pub struct Arm32;

impl Arch for Arm32 {
    fn decode(&self, code: &[u8], offset: usize, address: u64) -> Result<Insn, DecodeError> {
        let bytes = code.get(offset..).ok_or(DecodeError::Truncated)?;
        if bytes.len() < INSN_WIDTH {
            return Err(DecodeError::Truncated);
        }

        let insn_address = address + offset as u64;

        let mut reader = U8Reader::new(bytes);
        let mut inst = Instruction::default();

        // `yaxpeax` rejects a word it cannot read in two different ways: it
        // returns an error, or it succeeds and sets `Opcode::Invalid`. The
        // standard ARM `nop`, `0xe320f000`, takes the second path. Both mean
        // the same thing here.
        let failed = InstDecoder::default().decode_into(&mut inst, &mut reader).is_err();
        if failed || inst.opcode == Opcode::Invalid {
            // A32 instructions are all 4 bytes, so stepping over an
            // unreadable word keeps everything after it aligned. Reporting an
            // error instead would throw away the rest of the function.
            //
            // The raw word goes in the operand field. Without it every
            // unreadable instruction would look like every other one, and an
            // edit inside a NEON loop would be reported as no change at all.
            let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            return Ok(Insn {
                address: insn_address,
                bytes_len: INSN_WIDTH,
                mnemonic: UNKNOWN_MNEMONIC.to_string(),
                operands: format!("{word:#010x}"),
                kind: InsnKind::Unknown,
            });
        }

        // `total_offset` is in words; convert so the assertion below compares
        // like with like.
        let words = <U8Reader<'_> as Reader<u32, U32le>>::total_offset(&mut reader);
        let consumed = words as usize * INSN_WIDTH;
        debug_assert_eq!(consumed, INSN_WIDTH, "A32 instructions are always 4 bytes");

        let text = inst.to_string();
        let (mnemonic, operands) = split_mnemonic(&text);

        Ok(Insn {
            address: insn_address,
            bytes_len: INSN_WIDTH,
            mnemonic,
            operands,
            kind: classify(&inst, insn_address),
        })
    }

    fn triple(&self) -> &'static str {
        "arm-linux-gnueabi"
    }
}

/// Split rendered instruction text into the mnemonic and the rest.
fn split_mnemonic(text: &str) -> (String, String) {
    match text.split_once(char::is_whitespace) {
        Some((head, tail)) => (head.to_string(), tail.trim().to_string()),
        None => (text.to_string(), String::new()),
    }
}

/// Work out how an instruction moves control flow.
///
/// ARM has no single "return" opcode. A return is any write to the program
/// counter, so `pop {pc}` decodes as `LDR` and `mov pc, lr` as `MOV`. Reading
/// the opcode alone would miss both, so check the destination register too.
fn classify(inst: &Instruction, address: u64) -> InsnKind {
    let unconditional = inst.condition == ConditionCode::AL;

    match inst.opcode {
        Opcode::BL | Opcode::BLX => InsnKind::Call { target: branch_target(inst, address) },

        // `bx lr` returns; `bx <other>` is an indirect jump.
        Opcode::BX => match inst.operands[0] {
            Operand::Reg(reg) if reg.number() as u16 == REG_LR => InsnKind::Return,
            _ => InsnKind::Jump { target: None },
        },

        Opcode::B => {
            let target = branch_target(inst, address);
            if unconditional { InsnKind::Jump { target } } else { InsnKind::Branch { target } }
        }

        // Anything that writes the PC leaves the current block.
        _ if writes_pc(inst) => {
            if unconditional {
                InsnKind::Return
            } else {
                InsnKind::Branch { target: None }
            }
        }

        _ => InsnKind::Normal,
    }
}

/// Resolve a PC-relative branch to a virtual address.
///
/// `yaxpeax` reports the offset in **words**, measured from the instruction
/// itself, and has already removed the 8-byte pipeline bias that the ARM
/// encoding carries. A branch to itself therefore reports offset 0. Adding the
/// bias again here would put every target 8 bytes too far.
fn branch_target(inst: &Instruction, address: u64) -> Option<u64> {
    match inst.operands[0] {
        Operand::BranchOffset(words) => {
            let byte_offset = (words as i64) * INSN_WIDTH as i64;
            u64::try_from(address as i64 + byte_offset).ok()
        }
        _ => None,
    }
}

/// Report whether the instruction writes the program counter.
fn writes_pc(inst: &Instruction) -> bool {
    inst.operands.iter().any(|operand| match operand {
        Operand::Reg(reg) => reg.number() as u16 == REG_PC,
        Operand::RegWBack(reg, _) => reg.number() as u16 == REG_PC,
        // `pop {..., pc}` carries the PC as a bit in a register-list mask.
        Operand::RegList(mask) => mask & (1 << REG_PC) != 0,
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::decode_all;

    /// Decode one instruction from raw bytes at address 0.
    fn decode_one(bytes: [u8; 4]) -> Insn {
        Arm32.decode(&bytes, 0, 0).expect("bytes must decode")
    }

    #[test]
    fn decodes_simple_arithmetic() {
        let insn = decode_one([0x00, 0x00, 0x81, 0xe0]);
        assert_eq!(insn.mnemonic, "add");
        assert_eq!(insn.operands, "r0, r1, r0");
        assert_eq!(insn.bytes_len, 4);
        assert_eq!(insn.kind, InsnKind::Normal);
    }

    #[test]
    fn bx_lr_is_a_return() {
        assert_eq!(decode_one([0x1e, 0xff, 0x2f, 0xe1]).kind, InsnKind::Return);
    }

    /// `pop {pc}` decodes with opcode `LDR`, so only the PC check finds it.
    #[test]
    fn pop_pc_is_a_return() {
        assert_eq!(decode_one([0x04, 0xf0, 0x9d, 0xe4]).kind, InsnKind::Return);
    }

    /// `pop {fp, pc}` carries the PC in a register-list bitmask.
    #[test]
    fn pop_reglist_with_pc_is_a_return() {
        assert_eq!(decode_one([0x00, 0x88, 0xbd, 0xe8]).kind, InsnKind::Return);
    }

    /// `mov pc, lr` decodes with opcode `MOV`.
    #[test]
    fn mov_pc_lr_is_a_return() {
        assert_eq!(decode_one([0x0e, 0xf0, 0xa0, 0xe1]).kind, InsnKind::Return);
    }

    #[test]
    fn push_is_not_a_return() {
        assert_eq!(decode_one([0x00, 0x48, 0x2d, 0xe9]).kind, InsnKind::Normal);
    }

    #[test]
    fn bl_is_a_call() {
        let insn = decode_one([0xfe, 0xff, 0xff, 0xeb]);
        assert!(matches!(insn.kind, InsnKind::Call { .. }));
    }

    /// `b` and `beq` share opcode `B`; only the condition separates them.
    #[test]
    fn unconditional_branch_is_a_jump() {
        assert!(matches!(decode_one([0xfe, 0xff, 0xff, 0xea]).kind, InsnKind::Jump { .. }));
    }

    #[test]
    fn conditional_branch_can_fall_through() {
        assert!(matches!(decode_one([0xfe, 0xff, 0xff, 0x0a]).kind, InsnKind::Branch { .. }));
    }

    /// `yaxpeax` removes the pipeline bias, so a branch to self is offset 0.
    #[test]
    fn branch_to_self_resolves_to_its_own_address() {
        let insn = Arm32.decode(&[0xfe, 0xff, 0xff, 0xea], 0, 0x1000).unwrap();
        assert_eq!(insn.kind, InsnKind::Jump { target: Some(0x1000) });
    }

    /// Branching to itself cannot catch a wrong scale or sign, so check a
    /// forward and a backward branch too.
    #[test]
    fn branch_targets_scale_by_instruction_width() {
        let forward = Arm32.decode(&[0xff, 0xff, 0xff, 0xea], 0, 0x1000).unwrap();
        assert_eq!(forward.kind, InsnKind::Jump { target: Some(0x1004) });

        let backward = Arm32.decode(&[0xfd, 0xff, 0xff, 0xea], 0, 0x1000).unwrap();
        assert_eq!(backward.kind, InsnKind::Jump { target: Some(0x0ffc) });
    }

    #[test]
    fn address_tracks_the_offset() {
        let code = [0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
        assert_eq!(Arm32.decode(&code, 4, 0x8000).unwrap().address, 0x8004);
    }

    #[test]
    fn rejects_truncated_input() {
        assert_eq!(Arm32.decode(&[0x00, 0x00], 0, 0), Err(DecodeError::Truncated));
        assert_eq!(Arm32.decode(&[], 0, 0), Err(DecodeError::Truncated));
    }

    #[test]
    fn rejects_offset_past_the_end() {
        assert_eq!(Arm32.decode(&[0x00; 4], 8, 0), Err(DecodeError::Truncated));
    }

    /// Addresses must advance by 4 per instruction, not by 1. This is the
    /// regression test for the word-versus-byte offset trap.
    #[test]
    fn decode_all_advances_by_instruction_width() {
        // add, bx lr, add
        let code = [0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1, 0x00, 0x00, 0x81, 0xe0];
        let (insns, err) = decode_all(&Arm32, &code, 0x1000);
        assert_eq!(err, None);
        let addresses: Vec<u64> = insns.iter().map(|i| i.address).collect();
        assert_eq!(addresses, vec![0x1000, 0x1004, 0x1008]);
    }

    /// The usual ARM `nop` is one `yaxpeax` decodes "successfully" as
    /// `Opcode::Invalid`. It must still come back as unreadable, or a linker's
    /// padding looks like a real instruction.
    #[test]
    fn nop_encoding_decodes_as_unknown() {
        let insn = decode_one([0x00, 0xf0, 0x20, 0xe3]);
        assert_eq!(insn.kind, InsnKind::Unknown);
        assert_eq!(insn.operands, "0xe320f000", "the raw word must be kept");
    }

    /// NEON is outside what `yaxpeax-arm` 0.4 decodes. `vdup.32 q8, r2` must
    /// come back as opaque bytes, not as an error.
    #[test]
    fn neon_decodes_as_unknown() {
        let insn = decode_one([0x90, 0x2b, 0xa0, 0xee]);
        assert_eq!(insn.kind, InsnKind::Unknown);
        assert_eq!(insn.bytes_len, INSN_WIDTH);
    }

    /// Stepping over an unreadable word must keep the instructions after it
    /// aligned, which is the whole reason for the opaque kind.
    #[test]
    fn decoding_continues_past_unknown_bytes() {
        // add, vdup.32 (NEON), bx lr
        let code = [0x00, 0x00, 0x81, 0xe0, 0x90, 0x2b, 0xa0, 0xee, 0x1e, 0xff, 0x2f, 0xe1];
        let (insns, err) = decode_all(&Arm32, &code, 0x1000);

        assert_eq!(err, None, "unreadable bytes must not stop the decode");
        assert_eq!(insns.len(), 3);
        assert_eq!(insns[1].kind, InsnKind::Unknown);

        // The instruction after the opaque word must still be read correctly.
        assert_eq!(insns[2].kind, InsnKind::Return);
        assert_eq!(insns[2].address, 0x1008);
    }

    #[test]
    fn decode_all_reports_trailing_partial_bytes() {
        let code = [0x00, 0x00, 0x81, 0xe0, 0xff];
        let (insns, err) = decode_all(&Arm32, &code, 0);
        assert_eq!(insns.len(), 1);
        assert_eq!(err, Some(DecodeError::Truncated));
    }

    #[test]
    fn decode_all_handles_empty_input() {
        let (insns, err) = decode_all(&Arm32, &[], 0);
        assert!(insns.is_empty());
        assert_eq!(err, None);
    }
}
