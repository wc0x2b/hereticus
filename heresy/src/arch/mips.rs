//! MIPS32 decoding, little endian, on top of `rabbitizer`.
//!
//! Three details shape this module, and the rest of `heresy` sees none of
//! them:
//!
//! 1. `rabbitizer` renders registers with a `$` sigil and pads the mnemonic
//!    to a column. Both are stripped here, because `heresy` reserves a
//!    leading `$` for a branch target and compares operand text directly.
//! 2. MIPS ships in both byte orders and a whole image is one of them, so
//!    [`Mips32`] carries which. Reading at the wrong order does not fail:
//!    every word still decodes, into a different instruction. An ELF says
//!    which it is; a raw image is told by the caller.
//! 3. A MIPS branch counts its offset from the *delay slot*, and `j` and
//!    `jal` hold an address rather than a distance. `rabbitizer` resolves
//!    both, so neither correction is made here.

use compact_str::CompactString;
use rabbitizer::{
    Instruction, InstructionDisplayFlags, InstructionFlags, IsaVersion, Vram, opcodes::Opcode,
};

use super::{Arch, DecodeError, Insn, InsnKind};

/// Every MIPS32 instruction is 4 bytes wide.
const INSN_WIDTH: usize = 4;

/// Mnemonic reported for bytes the decoder cannot read.
const UNKNOWN_MNEMONIC: &str = "(unknown)";

/// The instruction set this decoder reads.
///
/// MIPS II covers what a compiler emits for a 32-bit target. A later level
/// adds instructions that would otherwise read as undecodable, so raising it
/// widens what can be read rather than changing what is already right.
const ISA: IsaVersion = IsaVersion::MIPS_II;

/// The byte order a word is stored in.
///
/// MIPS ships in both, and a whole image is one or the other. Reading an
/// image at the wrong order does not fail: every word still decodes, into a
/// different instruction, so the order has to be known rather than guessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    /// `mipsel`, as a desktop-built object usually is.
    Little,
    /// `mips`, as most shipped firmware is.
    Big,
}

impl ByteOrder {
    /// Assemble one stored word.
    fn read_word(self, bytes: [u8; INSN_WIDTH]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }
}

/// MIPS32, in either byte order.
#[derive(Clone, Copy, Debug)]
pub struct Mips32 {
    order: ByteOrder,
}

impl Mips32 {
    /// The decoder for a little-endian image.
    pub const LITTLE: Self = Self { order: ByteOrder::Little };
    /// The decoder for a big-endian image, which most firmware is.
    pub const BIG: Self = Self { order: ByteOrder::Big };
}

impl Arch for Mips32 {
    fn decode(&self, code: &[u8], offset: usize, address: u64) -> Result<Insn, DecodeError> {
        let bytes = code.get(offset..).ok_or(DecodeError::Truncated)?;
        if bytes.len() < INSN_WIDTH {
            return Err(DecodeError::Truncated);
        }

        let insn_address = address + offset as u64;
        let word = &bytes[..INSN_WIDTH];
        let raw = self.order.read_word([word[0], word[1], word[2], word[3]]);

        // `new_checked` rejects a word it cannot read rather than reading it
        // as something else, which is what makes stepping over the word safe.
        let decoded = Instruction::new_checked(
            raw,
            Vram::new(insn_address as u32),
            InstructionFlags::new(ISA),
        );

        let Some(inst) = decoded else {
            // Stepping over an unreadable word keeps everything after it
            // aligned, because every instruction is the same width. The raw
            // word goes in the operand field so that two unreadable words
            // still compare as different.
            return Ok(Insn {
                address: insn_address,
                bytes_len: INSN_WIDTH,
                mnemonic: UNKNOWN_MNEMONIC.to_string(),
                operands: format!("{raw:#010x}"),
                kind: InsnKind::Unknown,
            });
        };

        let text =
            inst.display::<&str>(&InstructionDisplayFlags::new_gnu_as(), None, 0).to_string();
        let (mnemonic, operands) = split_mnemonic(&text);

        Ok(Insn {
            address: insn_address,
            bytes_len: INSN_WIDTH,
            mnemonic,
            operands,
            kind: classify(&inst),
        })
    }

    fn triple(&self) -> &'static str {
        match self.order {
            ByteOrder::Little => "mipsel",
            ByteOrder::Big => "mips",
        }
    }

    fn instruction_width(&self) -> usize {
        INSN_WIDTH
    }

    fn is_register(&self, operand: &str) -> bool {
        is_register_name(operand)
    }

    fn is_stack_register(&self, operand: &str) -> bool {
        // `fp` is the frame pointer, which MIPS also calls `s8`.
        matches!(operand.trim(), "sp" | "fp" | "s8")
    }

    fn mentions_stack_slot(&self, operands: &str) -> bool {
        // A frame reference prints as `0x4(sp)`, so the register sits in
        // parentheses rather than in brackets as it does on ARM.
        operands.contains("(sp)") || operands.contains("(fp)") || operands.contains("(s8)")
    }

    fn constant_value(&self, operand: &str) -> Option<u64> {
        let text = operand.trim();
        if text.is_empty() {
            return None;
        }

        // A frame or object reference holds a constant, but that constant is
        // an offset that moves with unrelated edits. A branch target is not a
        // constant either.
        if text.contains('(') || text.contains(')') || text.starts_with('$') {
            return None;
        }

        // A negative immediate prints as `-0x1`.
        let (negative, digits) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text),
        };

        let value = match digits.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).ok()?,
            None => digits.parse::<u64>().ok()?,
        };

        // Negative immediates are compared as their two's complement form, so
        // that a constant keeps one spelling however it is printed.
        Some(if negative { (value as i64).wrapping_neg() as u64 } else { value })
    }

    /// MIPS mnemonics carry no condition or flag-setting suffix: the compare
    /// is part of the operation, as in `beq` against `bne`. There is nothing
    /// to strip, so the name passes through.
    fn normalize_operation(&self, mnemonic: &str) -> CompactString {
        mnemonic.trim().into()
    }

    fn is_frame_management(&self, insn: &Insn) -> bool {
        let operands = insn.operands.as_str();
        let first = operands.split(',').next().unwrap_or_default().trim();

        match insn.mnemonic.as_str() {
            // Moving the stack pointer, or setting up the frame pointer.
            // `move fp, sp` is how a frame is established.
            "addiu" | "addu" | "subu" | "move" => self.is_stack_register(first),

            // Spilling to and reloading from the frame.
            "sw" | "lw" | "swc1" | "lwc1" | "sd" | "ld" => self.mentions_stack_slot(operands),

            _ => false,
        }
    }

    /// A function that needs a frame opens by making room for it, so
    /// `addiu sp, sp, -N` is the first instruction of almost every one.
    ///
    /// Saving the return address was tried first and reports the start late.
    /// A prologue saves several registers and `sw ra` can be any of them: on
    /// a stripped MIPS kernel, 2593 of 13362 saved return addresses follow
    /// another register save, so the function had already begun. Allocating
    /// the frame cannot be preceded that way, and it appears 13426 times
    /// against 13362, so it also catches a leaf that makes room without
    /// calling anything.
    fn is_prologue(&self, insn: &Insn) -> bool {
        if insn.mnemonic != "addiu" {
            return false;
        }

        // `addiu sp, sp, -N`: the stack pointer is both the destination and
        // the source, and the immediate is negative. A positive immediate is
        // the matching unwind at the end of a function.
        let mut operands = insn.operands.split(',').map(str::trim);
        let (Some("sp"), Some("sp"), Some(immediate)) =
            (operands.next(), operands.next(), operands.next())
        else {
            return false;
        };

        immediate.starts_with('-')
    }

    fn is_padding(&self, insn: &Insn) -> bool {
        // A zero word decodes as `nop` on MIPS, so unlike ARM one test covers
        // both the encoding a linker pads with and the named instruction.
        insn.mnemonic == "nop"
    }

    fn trim_padding<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        /// `nop` and zero are the same word on MIPS: `sll zero, zero, 0`. Zero
        /// reads the same in either byte order.
        const NOP: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

        let mut end = bytes.len();
        while end >= INSN_WIDTH {
            if bytes[end - INSN_WIDTH..end] == NOP {
                end -= INSN_WIDTH;
            } else {
                break;
            }
        }

        &bytes[..end]
    }

    /// MIPS runs the instruction after a branch whether or not the branch is
    /// taken, so that instruction belongs to the branch.
    fn delay_slots(&self) -> usize {
        1
    }

    fn pointer_width(&self) -> usize {
        INSN_WIDTH
    }

    fn read_pointer(&self, bytes: &[u8]) -> u64 {
        u64::from(self.order.read_word([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

/// Split rendered instruction text into the mnemonic and the rest.
///
/// `rabbitizer` pads the mnemonic to a fixed column and writes every register
/// with a `$` sigil. The padding is noise, and the sigil would collide with
/// the `$+0x24` that `heresy` reserves for a branch target, so both go.
fn split_mnemonic(text: &str) -> (String, String) {
    match text.split_once(char::is_whitespace) {
        Some((head, tail)) => (head.to_string(), tail.trim().replace('$', "")),
        None => (text.to_string(), String::new()),
    }
}

/// Report whether an operand names a general register.
///
/// MIPS registers print by their ABI names, which are irregular enough to
/// list. `$4` style numbers do not appear in this decoder's output.
fn is_register_name(operand: &str) -> bool {
    matches!(
        operand.trim(),
        "zero"
            | "at"
            | "v0"
            | "v1"
            | "a0"
            | "a1"
            | "a2"
            | "a3"
            | "t0"
            | "t1"
            | "t2"
            | "t3"
            | "t4"
            | "t5"
            | "t6"
            | "t7"
            | "t8"
            | "t9"
            | "s0"
            | "s1"
            | "s2"
            | "s3"
            | "s4"
            | "s5"
            | "s6"
            | "s7"
            | "s8"
            | "k0"
            | "k1"
            | "gp"
            | "sp"
            | "fp"
            | "ra"
    )
}

/// Work out how an instruction moves control flow.
///
/// Read from the opcode rather than the printed text, so an alias or a
/// rendering change cannot alter the answer.
///
/// # Targets
///
/// `j` and `jal` hold an index that is shifted left two and joined to the top
/// bits of the program counter, so their target is an address inside the
/// region rather than a distance from here. A conditional branch holds a
/// signed offset counted from the delay slot, one instruction past itself.
/// `rabbitizer` resolves both forms, so neither correction is repeated here.
fn classify(inst: &Instruction) -> InsnKind {
    // A `jr` through the return-address register ends the function; through
    // any other register it is a tail call or a jump table.
    if inst.is_return() {
        return InsnKind::Return;
    }

    match inst.opcode() {
        // `jal` and `jalr` call. `bgezal` and friends also link, which
        // `is_function_call` already accounts for.
        Opcode::core_jalr => InsnKind::Call { target: None },
        Opcode::core_jal => InsnKind::Call { target: jump_target(inst) },
        Opcode::core_j => InsnKind::Jump { target: jump_target(inst) },
        Opcode::core_jr => InsnKind::Jump { target: None },

        _ if inst.is_function_call() => InsnKind::Call { target: branch_target(inst) },

        // An unconditional branch never falls through, so it is a jump
        // whatever it is spelled.
        _ if inst.is_unconditional_branch() => InsnKind::Jump { target: branch_target(inst) },

        // Anything else carrying a branch offset is conditional, and falls
        // through when it is not taken.
        _ if inst.get_branch_offset().is_some() => InsnKind::Branch { target: branch_target(inst) },

        _ => InsnKind::Normal,
    }
}

/// Resolve the absolute target of a `j` or `jal`.
fn jump_target(inst: &Instruction) -> Option<u64> {
    inst.get_instr_index_as_vram().map(|vram| u64::from(vram.inner()))
}

/// Resolve the target of a branch, which is relative to the delay slot.
fn branch_target(inst: &Instruction) -> Option<u64> {
    let offset = inst.get_branch_offset()?;
    let address = i64::from(inst.vram().inner());
    u64::try_from(address + i64::from(offset.inner())).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::decode_all;

    /// Decode one instruction from a little-endian word at address 0.
    fn decode_one(word: u32) -> Insn {
        Mips32::LITTLE.decode(&word.to_le_bytes(), 0, 0).expect("bytes must decode")
    }

    #[test]
    fn decodes_simple_arithmetic() {
        let insn = decode_one(0x0085_1021);
        assert_eq!(insn.mnemonic, "addu");
        assert_eq!(insn.operands, "v0, a0, a1");
        assert_eq!(insn.bytes_len, 4);
        assert_eq!(insn.kind, InsnKind::Normal);
    }

    #[test]
    fn jr_ra_is_a_return() {
        assert_eq!(decode_one(0x03e0_0008).kind, InsnKind::Return);
    }

    /// `jr` through any other register is a tail call or a switch, which
    /// leaves the block but does not end the function the way a return does.
    #[test]
    fn jr_through_another_register_is_an_indirect_jump() {
        assert_eq!(decode_one(0x0320_0008).kind, InsnKind::Jump { target: None });
    }

    #[test]
    fn jalr_is_a_call() {
        assert!(matches!(decode_one(0x0320_f809).kind, InsnKind::Call { .. }));
    }

    /// The J-type target is an address inside the region, not a distance from
    /// the instruction. The index `0x100` shifted left two is `0x400`, and
    /// that must be the answer whatever address the instruction sits at.
    #[test]
    fn a_jump_target_is_absolute_not_relative() {
        let at_zero = Mips32::LITTLE.decode(&0x0c00_0100u32.to_le_bytes(), 0, 0).unwrap();
        assert_eq!(at_zero.kind, InsnKind::Call { target: Some(0x400) });

        let moved = Mips32::LITTLE.decode(&0x0c00_0100u32.to_le_bytes(), 0, 0x1000).unwrap();
        assert_eq!(
            moved.kind,
            InsnKind::Call { target: Some(0x400) },
            "a region target must not move with the instruction address"
        );
    }

    #[test]
    fn j_is_an_unconditional_jump() {
        assert_eq!(decode_one(0x0800_0100).kind, InsnKind::Jump { target: Some(0x400) });
    }

    /// A branch offset counts from the delay slot, one instruction past the
    /// branch, so an offset of 5 from address 0 lands at `4 + (5 << 2)`.
    #[test]
    fn a_conditional_branch_can_fall_through() {
        assert_eq!(decode_one(0x1082_0005).kind, InsnKind::Branch { target: Some(24) });
        assert_eq!(decode_one(0x1482_0005).kind, InsnKind::Branch { target: Some(24) });
    }

    /// A backwards branch must resolve below the instruction, which catches a
    /// sign error that a forward-only test would miss.
    #[test]
    fn a_backwards_branch_resolves_below_itself() {
        let insn = Mips32::LITTLE.decode(&0x1082_fffeu32.to_le_bytes(), 0, 0x1000).unwrap();
        assert_eq!(insn.kind, InsnKind::Branch { target: Some(0x0ffc) });
    }

    /// A branch target moves with the instruction, unlike a jump target.
    #[test]
    fn a_branch_target_is_relative_to_the_instruction() {
        let insn = Mips32::LITTLE.decode(&0x1082_0005u32.to_le_bytes(), 0, 0x1000).unwrap();
        assert_eq!(insn.kind, InsnKind::Branch { target: Some(0x1018) });
    }

    /// `beq` of a register with itself renders as `b`, which never falls
    /// through.
    #[test]
    fn an_always_taken_branch_is_a_jump() {
        assert_eq!(decode_one(0x1000_0005).kind, InsnKind::Jump { target: Some(24) });
    }

    /// `break` begins with `b` but is not a branch.
    #[test]
    fn break_is_not_a_branch() {
        assert_eq!(decode_one(0x0000_000d).kind, InsnKind::Normal);
    }

    #[test]
    fn address_tracks_the_offset() {
        let mut code = Vec::new();
        code.extend_from_slice(&0x0085_1021u32.to_le_bytes());
        code.extend_from_slice(&0x03e0_0008u32.to_le_bytes());
        assert_eq!(Mips32::LITTLE.decode(&code, 4, 0x8000).unwrap().address, 0x8004);
    }

    #[test]
    fn rejects_truncated_input() {
        assert_eq!(Mips32::LITTLE.decode(&[0x00, 0x00], 0, 0), Err(DecodeError::Truncated));
        assert_eq!(Mips32::LITTLE.decode(&[], 0, 0), Err(DecodeError::Truncated));
    }

    #[test]
    fn rejects_offset_past_the_end() {
        assert_eq!(Mips32::LITTLE.decode(&[0x00; 4], 8, 0), Err(DecodeError::Truncated));
    }

    #[test]
    fn decode_all_advances_by_instruction_width() {
        let mut code = Vec::new();
        for word in [0x0085_1021u32, 0x03e0_0008, 0x0085_1021] {
            code.extend_from_slice(&word.to_le_bytes());
        }
        let (insns, err) = decode_all(&Mips32::LITTLE, &code, 0x1000);
        assert_eq!(err, None);
        let addresses: Vec<u64> = insns.iter().map(|insn| insn.address).collect();
        assert_eq!(addresses, vec![0x1000, 0x1004, 0x1008]);
    }

    #[test]
    fn decode_all_reports_trailing_partial_bytes() {
        let mut code = 0x0085_1021u32.to_le_bytes().to_vec();
        code.push(0xff);
        let (insns, err) = decode_all(&Mips32::LITTLE, &code, 0);
        assert_eq!(insns.len(), 1);
        assert_eq!(err, Some(DecodeError::Truncated));
    }

    #[test]
    fn decode_all_handles_empty_input() {
        let (insns, err) = decode_all(&Mips32::LITTLE, &[], 0);
        assert!(insns.is_empty());
        assert_eq!(err, None);
    }

    /// A zero word is `nop` on MIPS, so it is padding by name as well as by
    /// encoding.
    #[test]
    fn a_zero_word_is_padding() {
        let nop = decode_one(0x0000_0000);
        assert_eq!(nop.mnemonic, "nop");
        assert!(Mips32::LITTLE.is_padding(&nop));
        assert!(Mips32::LITTLE.trim_padding(&[0; 4]).is_empty());
    }

    #[test]
    fn trailing_padding_is_removed() {
        let mut code = 0x0085_1021u32.to_le_bytes().to_vec();
        code.extend_from_slice(&[0; 4]);
        assert_eq!(Mips32::LITTLE.trim_padding(&code), &code[..4]);
    }

    /// Padding inside a function is not padding, so it must stay.
    #[test]
    fn padding_before_real_code_is_kept() {
        let mut code = vec![0u8; 4];
        code.extend_from_slice(&0x0085_1021u32.to_le_bytes());
        assert_eq!(Mips32::LITTLE.trim_padding(&code), &code[..], "only the end is trimmed");
    }

    #[test]
    fn a_prologue_is_recognized_by_the_frame_it_makes() {
        // addiu sp, sp, -0x20
        let allocate = decode_one(0x27bd_ffe0);
        assert!(Mips32::LITTLE.is_prologue(&allocate));

        let add = decode_one(0x0085_1021);
        assert!(!Mips32::LITTLE.is_prologue(&add));
    }

    /// Releasing the frame ends a function; it must not be read as opening
    /// one, or every function start lands on the function before it.
    #[test]
    fn releasing_the_frame_is_not_a_prologue() {
        // addiu sp, sp, 0x28, the unwind that pairs with the allocation.
        let release = decode_one(0x27bd_0028);
        assert!(!Mips32::LITTLE.is_prologue(&release));
    }

    /// Saving the return address happens inside the prologue, not at its
    /// start, so it must not be taken for the start.
    #[test]
    fn saving_the_return_address_is_not_the_start() {
        // sw ra, 0x14(sp)
        let save_ra = decode_one(0xafbf_0014);
        assert_eq!(save_ra.to_string(), "sw ra, 0x14(sp)");
        assert!(!Mips32::LITTLE.is_prologue(&save_ra));
    }

    /// Adjusting another register, or adding to the stack pointer from
    /// somewhere else, is ordinary work.
    #[test]
    fn another_stack_adjustment_is_not_a_prologue() {
        // addiu a2, sp, 0x18, which takes the address of a frame slot.
        let address_of = decode_one(0x27a6_0018);
        assert!(!Mips32::LITTLE.is_prologue(&address_of));
    }

    #[test]
    fn frame_work_is_told_apart_from_real_work() {
        // addiu sp, sp, -0x20
        assert!(Mips32::LITTLE.is_frame_management(&decode_one(0x27bd_ffe0)));
        // sw ra, 0x14(sp)
        assert!(Mips32::LITTLE.is_frame_management(&decode_one(0xafbf_0014)));
        // addu v0, a0, a1 is the work itself
        assert!(!Mips32::LITTLE.is_frame_management(&decode_one(0x0085_1021)));
    }

    /// A load from an object is not a spill, even though both are `lw`.
    #[test]
    fn a_data_load_is_not_frame_work() {
        // lw v0, 0x0(a0)
        let load = decode_one(0x8c82_0000);
        assert!(!Mips32::LITTLE.is_frame_management(&load), "a load through a0 reads data");
    }

    #[test]
    fn registers_are_recognized_by_their_abi_names() {
        for name in ["zero", "a0", "v0", "t9", "s8", "sp", "fp", "ra", "gp"] {
            assert!(Mips32::LITTLE.is_register(name), "{name} names a register");
        }
        for other in ["", "0x4", "0x4(sp)", "$+0x8", "r0", "x0"] {
            assert!(!Mips32::LITTLE.is_register(other), "{other} does not name a register");
        }
    }

    #[test]
    fn the_stack_and_frame_pointers_are_told_apart() {
        for name in ["sp", "fp", "s8"] {
            assert!(Mips32::LITTLE.is_stack_register(name));
        }
        assert!(!Mips32::LITTLE.is_stack_register("a0"));
        assert!(!Mips32::LITTLE.is_stack_register("ra"));
    }

    #[test]
    fn a_frame_reference_is_told_apart_from_another_memory_reference() {
        assert!(Mips32::LITTLE.mentions_stack_slot("ra, 0x14(sp)"));
        assert!(Mips32::LITTLE.mentions_stack_slot("v0, 0x0(fp)"));
        assert!(!Mips32::LITTLE.mentions_stack_slot("v0, 0x0(a0)"));
    }

    #[test]
    fn a_constant_reads_in_hex_and_decimal() {
        assert_eq!(Mips32::LITTLE.constant_value("0x25"), Some(0x25));
        assert_eq!(Mips32::LITTLE.constant_value("37"), Some(37));
    }

    /// A negative immediate must read back as one value, not as its digits.
    #[test]
    fn a_negative_constant_keeps_one_spelling() {
        assert_eq!(Mips32::LITTLE.constant_value("-0x20"), Some((-0x20i64) as u64));
        assert_ne!(Mips32::LITTLE.constant_value("-0x20"), Mips32::LITTLE.constant_value("0x20"));
    }

    #[test]
    fn what_is_not_a_constant_reads_as_none() {
        for operand in ["a0", "0x4(sp)", "$+0x400", "", "ra"] {
            assert_eq!(Mips32::LITTLE.constant_value(operand), None, "{operand} is not a constant");
        }
    }

    /// MIPS puts the comparison in the mnemonic, so nothing is stripped and
    /// two different branches must stay different.
    #[test]
    fn normalizing_an_operation_keeps_distinct_branches_apart() {
        assert_eq!(Mips32::LITTLE.normalize_operation("addu"), "addu");
        assert_ne!(
            Mips32::LITTLE.normalize_operation("beq"),
            Mips32::LITTLE.normalize_operation("bne")
        );
    }

    /// The trait's default says this architecture has no unwind index, which
    /// makes function recovery fall back to calls and returns.
    #[test]
    fn there_is_no_unwind_section() {
        assert_eq!(Mips32::LITTLE.unwind_section(), None);
    }

    /// MIPS runs the instruction after a branch either way, so recovery must
    /// not read it as the start of the next function.
    #[test]
    fn a_branch_has_one_delay_slot() {
        assert_eq!(Mips32::LITTLE.delay_slots(), 1);
        assert_eq!(Mips32::BIG.delay_slots(), 1);
    }

    /// The same bytes are two different instructions in the two byte orders,
    /// which is why the order cannot be guessed.
    #[test]
    fn byte_order_decides_what_a_word_means() {
        // `addu v0, a0, a1` stored big endian.
        let stored = 0x0085_1021u32.to_be_bytes();

        let big = Mips32::BIG.decode(&stored, 0, 0).unwrap();
        assert_eq!(big.mnemonic, "addu");

        let little = Mips32::LITTLE.decode(&stored, 0, 0).unwrap();
        assert_ne!(little.mnemonic, "addu", "the wrong order reads another instruction");
    }

    /// A big-endian image decodes exactly as a little-endian one does once
    /// the word is assembled, so the whole trait works either way.
    #[test]
    fn big_endian_classifies_control_flow_the_same() {
        let jr_ra = Mips32::BIG.decode(&0x03e0_0008u32.to_be_bytes(), 0, 0).unwrap();
        assert_eq!(jr_ra.kind, InsnKind::Return);

        let jal = Mips32::BIG.decode(&0x0c00_0100u32.to_be_bytes(), 0, 0).unwrap();
        assert_eq!(jal.kind, InsnKind::Call { target: Some(0x400) });
    }

    /// Each order names the triple the differential test disassembles with.
    #[test]
    fn each_order_names_its_own_triple() {
        assert_eq!(Mips32::LITTLE.triple(), "mipsel");
        assert_eq!(Mips32::BIG.triple(), "mips");
    }

    /// A stored pointer follows the image byte order, as an instruction does.
    #[test]
    fn a_pointer_reads_in_the_image_byte_order() {
        let stored = 0x8000_0000u32.to_be_bytes();
        assert_eq!(Mips32::BIG.read_pointer(&stored), 0x8000_0000);
        assert_ne!(Mips32::LITTLE.read_pointer(&stored), 0x8000_0000);
    }
}
