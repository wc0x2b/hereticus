//! AArch64 (A64) decoding, on top of `yaxpeax-arm`.
//!
//! Every instruction is 4 bytes, and a pointer 8. A64 keeps no literal pool
//! among its code where a compiler builds for PIC: it forms an address from
//! the page of `pc` and an offset in that page,
//!
//! ```text
//! adrp x0, page       ; the 4 KiB page of the data, relative to pc
//! add  x0, x0, #lo12  ; the data itself, or `ldr x1, [x0, #lo12]`
//! ```
//!
//! so the offset in the page is part of an address, and moves with it. The
//! unwind tables are `.eh_frame`, which the scan reads for any architecture,
//! and a `switch` jumps through a table of distances in `.rodata`.

use core::ops::Range;

use compact_str::CompactString;
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{
    InstDecoder, Instruction, Opcode, Operand, SIMDSizeCode, ShiftStyle, SizeCode,
};

use super::arm32::split_mnemonic;
use super::{Arch, DecodeError, Insn, InsnKind, JumpTable, Memory};
use crate::address::{AddressSpace, ConstantKind};
use crate::il::{
    self, AccessKind, Comparison, Cond, Guard, Lifted, MemoryAccess, Op, Reg, RegSet, Test, Value,
    Width,
};

/// Every A64 instruction is 4 bytes wide.
const INSN_WIDTH: usize = 4;

/// A pointer is 8 bytes wide.
const POINTER_WIDTH: usize = 8;

/// A page, as `adrp` counts them.
const PAGE: u64 = 0x1000;

/// The bits that make a word `adr` or `adrp`: `x 0 0 1 0 0 0 0` at the top,
/// where `x` tells them apart.
const ADR_MASK: u32 = 0x1f00_0000;
const ADR_BITS: u32 = 0x1000_0000;

/// Mnemonic reported for bytes the decoder cannot read.
const UNKNOWN_MNEMONIC: &str = "(unknown)";

/// The A64 `nop` encoding, little endian.
const NOP_BYTES: [u8; 4] = [0x1f, 0x20, 0x03, 0xd5];

/// Zero words, which some linkers pad with instead.
const ZERO_BYTES: [u8; 4] = [0; 4];

/// How far back the parts of a table jump may lie.
const TABLE_LOOK_BACK: usize = 32;

/// More cases than any `switch` a compiler turns into one table.
const MOST_CASES: usize = 4096;

/// ARMv8-A in A64 (AArch64) mode.
#[derive(Clone, Copy, Debug, Default)]
pub struct Aarch64;

impl Arch for Aarch64 {
    fn decode(&self, code: &[u8], offset: usize, address: u64) -> Result<Insn, DecodeError> {
        let bytes = code.get(offset..offset + INSN_WIDTH).ok_or(DecodeError::Truncated)?;
        let insn_address = address + offset as u64;

        let mut reader = U8Reader::new(bytes);
        let mut inst = Instruction::default();
        if InstDecoder::default().decode_into(&mut inst, &mut reader).is_err() {
            // Every instruction is 4 bytes, so stepping over an unreadable
            // one keeps the rest aligned. Its word goes in the operands, so
            // that an edit to it still shows.
            let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            return Ok(Insn {
                address: insn_address,
                bytes_len: INSN_WIDTH,
                mnemonic: UNKNOWN_MNEMONIC.to_string(),
                operands: format!("{word:#010x}"),
                kind: InsnKind::Unknown,
                opcode: super::Opcode::None,
            });
        }

        let text = inst.to_string();
        let (mnemonic, operands) = split_mnemonic(&text);
        let operands = extended_register(inst.opcode, operands);
        let kind = classify(&inst, insn_address);
        let opcode =
            super::Opcode::Aarch64(Decoded { opcode: inst.opcode, alias: alias_of(&inst) });
        Ok(Insn { address: insn_address, bytes_len: INSN_WIDTH, mnemonic, operands, kind, opcode })
    }

    fn triple(&self) -> &'static str {
        "aarch64-linux-gnu"
    }

    fn instruction_width(&self) -> usize {
        INSN_WIDTH
    }

    fn is_register(&self, operand: &str) -> bool {
        let operand = operand.trim();
        matches!(operand, "sp" | "wsp" | "xzr" | "wzr" | "lr")
            || ["x", "w", "d", "s", "q", "h", "b", "v"].iter().any(|prefix| {
                operand.strip_prefix(prefix).is_some_and(|number| {
                    let number = number.split('.').next().unwrap_or_default();
                    !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
                })
            })
    }

    fn is_stack_register(&self, operand: &str) -> bool {
        matches!(operand.trim(), "sp" | "wsp" | "x29")
    }

    fn is_frame_register(&self, reg: Reg) -> bool {
        matches!(reg, Reg::Stack | FRAME)
    }

    fn mentions_stack_slot(&self, operands: &str) -> bool {
        operands.contains("[sp") || operands.contains("[x29")
    }

    fn constant_value(&self, operand: &str) -> Option<u64> {
        let text = operand.trim().trim_start_matches('#');
        if text.is_empty() || text.contains(['[', ']']) || text.starts_with('$') {
            return None;
        }
        let (negative, text) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let value = match text.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).ok()?,
            None => text.parse::<u64>().ok()?,
        };
        Some(if negative { value.wrapping_neg() } else { value })
    }

    /// The condition of `b.ne` is dropped, as A32 drops it from `bne`.
    fn normalize_operation(&self, mnemonic: &str) -> CompactString {
        let mnemonic = mnemonic.trim();
        match mnemonic.split_once('.') {
            Some((stem, _)) if stem == "b" => stem.into(),
            _ => mnemonic.into(),
        }
    }

    fn is_frame_management(&self, insn: &Insn) -> bool {
        let Some(Decoded { opcode, alias }) = decoded(insn) else { return false };
        let operands = insn.operands.as_str();
        let first = operands.split(',').next().unwrap_or_default();
        match (opcode, alias) {
            // Saving and restoring the frame and the registers it keeps.
            (Opcode::STP | Opcode::LDP | Opcode::STR | Opcode::LDR, _) => {
                self.mentions_stack_slot(operands)
            }
            // Moving the stack pointer, or setting up the frame pointer.
            (_, Alias::Move)
            | (Opcode::SUB | Opcode::ADD | Opcode::MOVZ | Opcode::MOVN, Alias::None) => {
                self.is_stack_register(first)
            }
            // Signing and checking the return address, and marking a branch
            // target, change nothing a function computes.
            (Opcode::PACIASP | Opcode::PACIBSP | Opcode::AUTIASP | Opcode::AUTIBSP, _)
            | (_, Alias::BranchTarget) => true,
            _ => false,
        }
    }

    /// Almost every function that calls another saves the frame pointer and
    /// the link register first, as `stp x29, x30, [sp, #-N]!`. A leaf that
    /// needs no frame has no prologue, which is why the scan treats this as
    /// one source among several.
    fn is_prologue(&self, insn: &Insn) -> bool {
        match opcode_of(insn) {
            Some(Opcode::STP) => insn.operands.starts_with("x29, x30, [sp"),
            Some(Opcode::STR) => {
                insn.operands.starts_with("x30, [sp") && insn.operands.ends_with('!')
            }
            _ => false,
        }
    }

    /// A signed return address, or a branch target mark, can come before
    /// the frame is made.
    fn preamble_before_prologue(&self, earlier: &[Insn]) -> usize {
        let Some(last) = earlier.last().and_then(decoded) else { return 0 };
        usize::from(matches!(
            (last.opcode, last.alias),
            (Opcode::PACIASP | Opcode::PACIBSP, _) | (_, Alias::BranchTarget)
        ))
    }

    fn is_padding(&self, insn: &Insn) -> bool {
        decoded(insn).is_some_and(|decoded| decoded.alias == Alias::Nop)
            || (insn.kind == InsnKind::Unknown && insn.operands == "0x00000000")
    }

    /// Only whole words at the end are removed, and only the two encodings a
    /// linker pads with.
    fn trim_padding<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        let mut end = bytes.len() - bytes.len() % INSN_WIDTH;
        while end >= INSN_WIDTH
            && (bytes[end - INSN_WIDTH..end] == NOP_BYTES
                || bytes[end - INSN_WIDTH..end] == ZERO_BYTES)
        {
            end -= INSN_WIDTH;
        }
        &bytes[..end]
    }

    /// The offset in a page that `add` or a load joins to an `adrp` is part
    /// of an address, and moves with the data it names.
    fn constant_kinds(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
    ) -> Vec<ConstantKind> {
        track_pages(code, body, space).kinds
    }

    fn formed_addresses(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        _memory: &Memory<'_>,
    ) -> Vec<Option<u64>> {
        track_pages(code, body, space).formed
    }

    /// The addresses a function forms from a page, and the pointers it
    /// loads from one where they point into the image: a text that only a
    /// table of pointers reaches is a text of the function too. A pointer
    /// of a Mach-O file reads as an address once its chained fixups are
    /// applied, as [`crate::callee::Links`] does.
    fn data_addresses(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        memory: &Memory<'_>,
    ) -> Vec<u64> {
        let pages = track_pages(code, body, space);
        let loaded = pages.pointer_loads.iter().filter_map(|&address| {
            let pointer = u64::from_le_bytes(memory.bytes(address, 8)?.try_into().ok()?);
            (pointer != address && space.contains_formed(pointer)).then_some(pointer)
        });
        pages.addresses.iter().copied().chain(loaded).collect()
    }

    /// Clang and GCC jump through a table of distances in `.rodata`:
    ///
    /// ```text
    /// adr  x28, table              ; or adrp and add
    /// ldrh w10, [x28, x9, lsl #1]  ; one entry, a count of instructions
    /// adr  x8, base
    /// add  x8, x8, x10, lsl #2     ; GCC: add x3, x3, w0, sxth #2
    /// br   x8
    /// ```
    ///
    /// A `cmp` of the case number before it bounds the table.
    fn jump_tables(&self, memory: &Memory<'_>, code: Range<u64>, insns: &[Insn]) -> Vec<JumpTable> {
        (0..insns.len()).filter_map(|index| read_jump_table(memory, &code, insns, index)).collect()
    }

    /// The stub LLD and GNU `ld` write for each PLT entry:
    ///
    /// ```text
    /// adrp x16, page
    /// ldr  x17, [x16, #lo12]
    /// add  x16, x16, #lo12
    /// br   x17
    /// ```
    fn stub_slot(&self, code: &[u8], address: u64) -> Option<u64> {
        // The scan asks at the target of every jump, so a word that is no
        // `adrp` or `adr` ends the question before anything decodes.
        let first = u32::from_le_bytes(code.get(..INSN_WIDTH)?.try_into().ok()?);
        if first & ADR_MASK != ADR_BITS {
            return None;
        }
        let (insns, _) = super::decode_all(self, code.get(..4 * INSN_WIDTH)?, address);
        let [adrp, load, add, jump] = insns.as_slice() else { return None };
        let page = page_of(adrp)?;
        // An offset of 0 prints as `[x16]`, with none.
        let reference = load.operands.strip_prefix("x17, [x16")?.strip_suffix(']')?;
        let low = match reference.strip_prefix(", ") {
            Some(offset) => self.constant_value(offset)?,
            None if reference.is_empty() => 0,
            None => return None,
        };
        let shape = opcode_of(load) == Some(Opcode::LDR)
            && add.operands.starts_with("x16, x16, ")
            && opcode_of(jump) == Some(Opcode::BR)
            && jump.operands == "x17";
        shape.then_some(page + low)
    }

    /// `br x16` and `br x17`: the ABI keeps these two for a jump the linker
    /// adds, a PLT stub or a veneer. A `switch` jumps through another.
    fn is_tail_call(&self, insn: &Insn) -> bool {
        opcode_of(insn) == Some(Opcode::BR) && matches!(insn.operands.as_str(), "x16" | "x17")
    }

    fn pointer_width(&self) -> usize {
        POINTER_WIDTH
    }

    fn lift(&self, insn: &Insn, word: &[u8]) -> Option<Lifted> {
        if insn.kind == InsnKind::Unknown {
            return None;
        }
        let mut inst = Instruction::default();
        InstDecoder::default().decode_into(&mut inst, &mut U8Reader::new(word)).ok()?;
        Some(lift(&inst))
    }

    fn read_pointer(&self, bytes: &[u8]) -> u64 {
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }
}

/// `operands`, with the extend of a 32-bit register named as it is.
///
/// `yaxpeax-arm` 0.4 prints `add x1, x3, w1, uxtw #4` as `add x1, x3, w1,
/// lsl #4`, and `add x23, x10, w8, uxtw` as `add x23, x10, w8`. `lsl`
/// shifts a register of the full width; a `w` register in a 64-bit
/// operation is zero-extended first, which is `uxtw`. Only an add, a
/// subtract or a compare extends so: `smull x0, w1, w2` reads `w`
/// registers as it is.
///
/// This runs on every instruction, so it searches for the comma, a single
/// byte, and not for `", "`: a search for a string builds a searcher each
/// time, which cost 8% of a whole comparison.
fn extended_register(opcode: Opcode, operands: String) -> String {
    let is_w = |name: &str| {
        name == "wzr" || (name.starts_with('w') && name[1..].bytes().all(|b| b.is_ascii_digit()))
    };
    let is_wide = |name: &str| name.starts_with('x') || name == "sp";
    /// The first and the last of operands that `", "` separates.
    fn ends(list: &str) -> (&str, &str) {
        let first = list.split(',').next().unwrap_or_default();
        let last = list.rsplit(',').next().unwrap_or_default().trim_start();
        (first, last)
    }
    let last_comma = operands.rfind(',');
    if let Some(comma) = last_comma
        && let Some(shift) = operands[comma..].strip_prefix(", lsl ")
    {
        let head = &operands[..comma];
        let (first, last) = ends(head);
        return if is_wide(first) && is_w(last) {
            format!("{head}, uxtw {shift}")
        } else {
            operands
        };
    }
    // `cmp` and `cmn` are a `subs` and an `adds`.
    let extends = matches!(opcode, Opcode::ADD | Opcode::ADDS | Opcode::SUB | Opcode::SUBS);
    if !extends || last_comma.is_none() {
        return operands;
    }
    let (first, last) = ends(&operands);
    if is_wide(first) && is_w(last) { format!("{operands}, uxtw") } else { operands }
}

/// How an instruction moves control. The pointer authentication forms of a
/// return, a jump and a call, as `retaa`, `braa` and `blraa`, move it as the
/// plain ones do.
fn classify(inst: &Instruction, address: u64) -> InsnKind {
    let target = inst.operands.iter().find_map(|operand| match operand {
        Operand::PCOffset(offset) => address.checked_add_signed(*offset),
        _ => None,
    });
    match inst.opcode {
        Opcode::BL => InsnKind::Call { target },
        Opcode::B => InsnKind::Jump { target },
        Opcode::Bcc(_)
        | Opcode::BCcc(_)
        | Opcode::CBZ
        | Opcode::CBNZ
        | Opcode::TBZ
        | Opcode::TBNZ => InsnKind::Branch { target },
        opcode if is_return(opcode) || is_exception_return(opcode) => InsnKind::Return,
        opcode if is_indirect_call(opcode) => InsnKind::Call { target: None },
        opcode if is_indirect_jump(opcode) => InsnKind::Jump { target: None },
        _ => InsnKind::Normal,
    }
}

/// `ret`, and the forms that check a signed return address.
fn is_return(opcode: Opcode) -> bool {
    matches!(
        opcode,
        Opcode::RET
            | Opcode::RETAA
            | Opcode::RETAB
            | Opcode::RETAASPPC
            | Opcode::RETABSPPC
            | Opcode::RETAASPPCR
            | Opcode::RETABSPPCR
    )
}

/// `eret`, which returns from an exception through `elr`, not the link
/// register.
fn is_exception_return(opcode: Opcode) -> bool {
    matches!(opcode, Opcode::ERET | Opcode::ERETAA | Opcode::ERETAB)
}

fn is_indirect_call(opcode: Opcode) -> bool {
    matches!(opcode, Opcode::BLR | Opcode::BLRAA | Opcode::BLRAAZ | Opcode::BLRAB | Opcode::BLRABZ)
}

/// `br` and its signed forms. `brk` traps, and control does not come back
/// to the next instruction, so it ends the code as a jump does.
fn is_indirect_jump(opcode: Opcode) -> bool {
    matches!(
        opcode,
        Opcode::BR | Opcode::BRAA | Opcode::BRAAZ | Opcode::BRAB | Opcode::BRABZ | Opcode::BRK
    )
}

/// The link register, which a call writes and a return reads.
const LINK: Reg = Reg::General(30);

/// The frame pointer, as the A64 procedure call standard names it.
const FRAME: Reg = Reg::General(29);

/// What an instruction does with its first operand, and with the flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// Writes its first operand from the others, as `add` does.
    Compute,
    /// Reads every operand and writes none, as `br` and `ccmp` do.
    ReadOnly,
    /// Reads every operand and writes memory, as `str` does.
    Store,
    /// Loads its first operand, or its first two for a pair.
    Load { registers: usize },
    /// An exclusive store, which writes its status to the first operand.
    StoreExclusive,
    /// Reads its first operand and loads into its second, as `swp` and
    /// `ldadd` do.
    Atomic,
}

/// Lift one decoded A64 instruction.
fn lift(inst: &Instruction) -> Lifted {
    let operands: Vec<Operand> =
        inst.operands.iter().copied().take_while(|operand| *operand != Operand::Nothing).collect();
    let mut lifted = Lifted::default();
    let mut reads = RegSet::EMPTY;
    let mut writes = RegSet::EMPTY;

    for operand in &operands {
        address_registers(*operand, &mut reads, &mut writes);
    }

    let alias = alias_of(inst);
    let role = role_of(inst.opcode, alias);
    for (index, operand) in operands.iter().enumerate() {
        let written = match role {
            Role::Compute => index == 0 && alias != Alias::Compare,
            Role::ReadOnly | Role::Store => false,
            Role::Load { registers } => index < registers,
            Role::StoreExclusive => index == 0,
            Role::Atomic => index == 1,
        };
        let regs = value_registers(*operand);
        if written {
            regs.iter().for_each(|reg| writes.insert(reg));
            if reads_destination(inst.opcode) {
                regs.iter().for_each(|reg| reads.insert(reg));
            }
        } else {
            regs.iter().for_each(|reg| reads.insert(reg));
        }
    }

    if reads_flags(inst.opcode) {
        reads.insert(Reg::Flags);
    }
    if writes_flags(inst.opcode) {
        writes.insert(Reg::Flags);
    }
    match inst.opcode {
        Opcode::BL => writes.insert(LINK),
        opcode if is_indirect_call(opcode) => writes.insert(LINK),
        // A plain `ret` names the link register as its operand.
        opcode if is_return(opcode) && operands.is_empty() => reads.insert(LINK),
        _ => {}
    }

    lifted.op = op_of(inst, alias, role, &operands);
    lifted.memory = memory_access(inst.opcode, role, &operands);
    lifted.test = test_of(inst, alias, &operands);
    lifted.reads = reads;
    lifted.writes = writes;
    lifted.operands = operands.iter().map(|operand| il_operand(*operand)).collect();
    lifted
}

/// An operand as the IL names it. Register 31 is the zero register as a
/// value and the stack pointer as a base.
fn il_operand(operand: Operand) -> il::Operand {
    let general = |number: u16| il::Operand::Reg(Reg::General(number as u8));
    let base = |number: u16, offset: Option<i64>| il::Operand::Memory {
        base: Some(if number == 31 { Reg::Stack } else { Reg::General(number as u8) }),
        offset,
    };
    match operand {
        Operand::Register(_, 31) | Operand::RegShift(_, _, _, 31) => il::Operand::Zero,
        Operand::Register(_, number)
        | Operand::RegShift(_, _, _, number)
        | Operand::RegisterPair(_, number) => general(number),
        Operand::RegisterOrSP(_, 31) => il::Operand::Reg(Reg::Stack),
        Operand::RegisterOrSP(_, number) => general(number),
        Operand::SIMDRegister(_, number)
        | Operand::SIMDRegisterElements(_, number, _)
        | Operand::SIMDRegisterElementsLane(_, number, _, _)
        | Operand::SIMDRegisterElementsMultipleLane(_, number, _, _, _)
        | Operand::SIMDRegisterGroup(_, number, _, _)
        | Operand::SIMDRegisterGroupLane(number, _, _, _) => {
            il::Operand::Reg(Reg::Vector((number % 32) as u8))
        }
        Operand::PCOffset(_) => il::Operand::Target,
        Operand::Immediate(value) => il::Operand::Const(value.into()),
        Operand::Imm16(value) => il::Operand::Const(value.into()),
        Operand::Imm64(value) => il::Operand::Const(value),
        Operand::ImmShift(value, shift) | Operand::ImmShiftMSL(value, shift) => {
            il::Operand::Const(u64::from(value) << shift)
        }
        Operand::RegPreIndex(number, offset, _) | Operand::RegPostIndex(number, offset) => {
            base(number, Some(offset.into()))
        }
        Operand::RegPostIndexReg(number, _) | Operand::RegRegOffset(number, ..) => {
            base(number, None)
        }
        _ => il::Operand::Other,
    }
}

/// What an A64 instruction computes. An alias the decoder prints in place
/// of its instruction, as `cmp` for a `subs` into the zero register, or
/// `lsl` for a `ubfm`, computes what the alias names.
fn op_of(inst: &Instruction, alias: Alias, role: Role, operands: &[Operand]) -> Op {
    match role {
        Role::Load { .. } if is_exclusive_load(inst.opcode) => return Op::Atomic,
        Role::Load { .. } => return Op::Load,
        Role::Atomic | Role::StoreExclusive => return Op::Atomic,
        Role::Store => return Op::Store,
        Role::ReadOnly | Role::Compute => {}
    }
    let is_vector = operands.iter().any(|operand| {
        matches!(
            operand,
            Operand::SIMDRegisterElements(..)
                | Operand::SIMDRegisterElementsLane(..)
                | Operand::SIMDRegisterElementsMultipleLane(..)
                | Operand::SIMDRegisterGroup(..)
        )
    });
    match inst.opcode {
        Opcode::B => Op::Jump,
        Opcode::Bcc(_)
        | Opcode::BCcc(_)
        | Opcode::CBZ
        | Opcode::CBNZ
        | Opcode::TBZ
        | Opcode::TBNZ => Op::Branch,
        Opcode::BL => Op::Call,
        opcode if is_indirect_call(opcode) => Op::Call,
        opcode if is_indirect_jump(opcode) => Op::Jump,
        opcode if is_return(opcode) || is_exception_return(opcode) => Op::Return,
        _ if is_vector => Op::Vector,
        _ => match alias {
            Alias::Compare => Op::Compare,
            Alias::Move => Op::Move,
            Alias::Negate => Op::Negate,
            Alias::Not => Op::Not,
            Alias::Multiply => Op::Multiply,
            Alias::ShiftLeft => Op::ShiftLeft,
            Alias::ShiftRight => Op::ShiftRight,
            Alias::ShiftRightArithmetic => Op::ShiftRightArithmetic,
            Alias::Extend => Op::Extend,
            Alias::None | Alias::AtomicStore | Alias::Nop | Alias::BranchTarget => {
                plain_op(inst.opcode)
            }
        },
    }
}

/// What an A64 instruction computes, where it prints as no alias of other
/// work.
fn plain_op(opcode: Opcode) -> Op {
    match opcode {
        Opcode::MOVZ | Opcode::MOVN | Opcode::MOVK | Opcode::FMOV => Op::Move,
        Opcode::ADR | Opcode::ADRP => Op::Address,
        Opcode::ADD | Opcode::ADDS | Opcode::ADC | Opcode::ADCS => Op::Add,
        Opcode::SUB | Opcode::SUBS | Opcode::SBC | Opcode::SBCS => Op::Subtract,
        Opcode::NEG => Op::Negate,
        Opcode::MUL | Opcode::UMULH | Opcode::SMULH | Opcode::UMULL | Opcode::SMULL => Op::Multiply,
        Opcode::MADD
        | Opcode::MSUB
        | Opcode::UMADDL
        | Opcode::SMADDL
        | Opcode::UMSUBL
        | Opcode::SMSUBL => Op::MultiplyAdd,
        Opcode::UDIV | Opcode::SDIV => Op::Divide,
        Opcode::AND | Opcode::ANDS => Op::And,
        Opcode::ORR => Op::Or,
        Opcode::EOR | Opcode::EON => Op::Xor,
        Opcode::BIC | Opcode::BICS => Op::AndNot,
        Opcode::ORN => Op::OrNot,
        Opcode::NOT => Op::Not,
        Opcode::LSLV => Op::ShiftLeft,
        Opcode::LSRV => Op::ShiftRight,
        Opcode::ASRV => Op::ShiftRightArithmetic,
        Opcode::RORV | Opcode::EXTR => Op::Rotate,
        Opcode::UBFM | Opcode::SBFM | Opcode::BFM => Op::BitField,
        Opcode::CLZ
        | Opcode::CLS
        | Opcode::RBIT
        | Opcode::REV
        | Opcode::REV16
        | Opcode::REV32
        | Opcode::REV64
        | Opcode::CNT => Op::Bits,
        Opcode::CSEL | Opcode::CSINC | Opcode::CSINV | Opcode::CSNEG | Opcode::FCSEL => Op::Select,
        Opcode::CCMP
        | Opcode::CCMN
        | Opcode::FCMP
        | Opcode::FCMPE
        | Opcode::FCCMP
        | Opcode::FCCMPE => Op::Compare,
        Opcode::HINT
        | Opcode::DMB(_)
        | Opcode::DSB(_)
        | Opcode::ISB
        | Opcode::MSR
        | Opcode::MRS
        | Opcode::SVC
        | Opcode::HVC
        | Opcode::SMC
        | Opcode::HLT
        | Opcode::UDF
        | Opcode::SYS(_)
        | Opcode::SYSL(_)
        | Opcode::CLREX
        | Opcode::PACIASP
        | Opcode::PACIBSP
        | Opcode::AUTIASP
        | Opcode::AUTIBSP
        | Opcode::PRFM
        | Opcode::PRFUM => Op::System,
        opcode => float_op(opcode).unwrap_or(Op::Other),
    }
}

/// What [`Insn::opcode`] holds for A64: the opcode, and the alias that
/// `yaxpeax-arm` prints in place of it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Decoded {
    pub opcode: Opcode,
    pub alias: Alias,
}

// `yaxpeax-arm` derives no `Eq` for `Opcode`, though it holds no float.
impl Eq for Decoded {}

/// An alias the decoder prints in place of an instruction, where the alias
/// names other work than the instruction does, or names one case of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alias {
    /// The instruction prints as itself, or as an alias for the same work.
    None,
    /// `cmp`, `cmn` and `tst`: a `subs`, an `adds` or an `ands` into the
    /// zero register, which writes only the flags. The first operand is
    /// the zero register, not a destination.
    Compare,
    /// `mov`: an `orr` from the zero register with no shift, or of a
    /// register with itself, or an `add` of zero to or from the stack
    /// pointer.
    Move,
    /// `neg`, `negs`, `ngc` and `ngcs`: a subtract from the zero register.
    Negate,
    /// `mvn`: an `orn` from the zero register.
    Not,
    /// `mul`, `mneg`, `smull` and the like: a multiply that adds to the
    /// zero register.
    Multiply,
    /// `lsl`, which is a `ubfm`.
    ShiftLeft,
    /// `lsr`, which is a `ubfm`.
    ShiftRight,
    /// `asr`, which is an `sbfm`.
    ShiftRightArithmetic,
    /// `uxtb`, `sxtw` and the like, which are a `ubfm` or an `sbfm`.
    Extend,
    /// `stadd` and the like: an atomic operation that keeps no old value,
    /// as `ldadd w1, wzr, [x0]`. Only the forms without acquire semantics
    /// have this alias.
    AtomicStore,
    /// `nop`, which is hint 0.
    Nop,
    /// `bti`, which marks where an indirect branch may land: hints 32, 34,
    /// 36 and 38.
    BranchTarget,
}

/// The alias `inst` prints as, by the rules of `yaxpeax-arm` 0.4.
fn alias_of(inst: &Instruction) -> Alias {
    let operands = &inst.operands;
    let zero = |index: usize| is_zero_register(operands[index]);
    match inst.opcode {
        Opcode::SUBS | Opcode::ADDS | Opcode::ANDS if zero(0) => Alias::Compare,
        Opcode::ORR if is_orr_move(operands) => Alias::Move,
        Opcode::ADD if is_add_move(operands) => Alias::Move,
        Opcode::SUB | Opcode::SUBS | Opcode::SBC | Opcode::SBCS if zero(1) => Alias::Negate,
        Opcode::ORN if zero(1) => Alias::Not,
        Opcode::MADD
        | Opcode::MSUB
        | Opcode::UMADDL
        | Opcode::SMADDL
        | Opcode::UMSUBL
        | Opcode::SMSUBL
            if zero(3) =>
        {
            Alias::Multiply
        }
        Opcode::UBFM => unsigned_bit_field_alias(operands),
        Opcode::SBFM => signed_bit_field_alias(operands),
        Opcode::HINT => match hint_number(operands) {
            Some(0) => Alias::Nop,
            Some(32 | 34 | 36 | 38) => Alias::BranchTarget,
            _ => Alias::None,
        },
        _ if is_atomic_store(inst) => Alias::AtomicStore,
        _ => Alias::None,
    }
}

/// Register 31 where it names the zero register, not the stack pointer.
fn is_zero_register(operand: Operand) -> bool {
    matches!(operand, Operand::Register(_, 31))
}

/// The number of a `hint`, from its two fields.
fn hint_number(operands: &[Operand]) -> Option<u16> {
    match (operands[0], operands[1]) {
        (Operand::ControlReg(crm), Operand::Immediate(op2)) => Some(crm << 3 | op2 as u16),
        _ => None,
    }
}

/// An `orr` that prints as `mov`.
fn is_orr_move(operands: &[Operand]) -> bool {
    match (operands[1], operands[2]) {
        (Operand::Register(_, 31), Operand::RegShift(style, amount, ..)) => {
            style == ShiftStyle::LSL && amount == 0
        }
        (Operand::Register(_, 31), _) => true,
        (first, second) => first == second,
    }
}

/// An `add` that prints as `mov`.
fn is_add_move(operands: &[Operand]) -> bool {
    let stack = |operand| matches!(operand, Operand::RegisterOrSP(_, 31));
    operands[2] == Operand::Immediate(0) && (stack(operands[0]) || stack(operands[1]))
}

/// The width of the register a bit field instruction writes, and its
/// `immr` and `imms` fields.
fn bit_field(operands: &[Operand]) -> Option<(u32, u32, u32)> {
    let size = match operands[0] {
        Operand::Register(SizeCode::W, _) => 32,
        Operand::Register(SizeCode::X, _) => 64,
        _ => return None,
    };
    match (operands[2], operands[3]) {
        (Operand::Immediate(immr), Operand::Immediate(imms)) => Some((size, immr, imms)),
        _ => None,
    }
}

/// `lsr`, `lsl`, `uxtb` and `uxth` are aliases of `ubfm`. `ubfx` and
/// `ubfiz` are too, but for the same work.
fn unsigned_bit_field_alias(operands: &[Operand]) -> Alias {
    let is_w = matches!(operands[1], Operand::Register(SizeCode::W, _));
    match bit_field(operands) {
        Some((32, 0, 7 | 15)) if is_w => Alias::Extend,
        Some((size, _, imms)) if imms == size - 1 => Alias::ShiftRight,
        Some((_, immr, imms)) if imms + 1 == immr => Alias::ShiftLeft,
        _ => Alias::None,
    }
}

/// `asr`, `sxtb`, `sxth` and `sxtw` are aliases of `sbfm`. `sbfx` and
/// `sbfiz` are too, but for the same work.
fn signed_bit_field_alias(operands: &[Operand]) -> Alias {
    match bit_field(operands) {
        Some((size, _, imms)) if imms == size - 1 => Alias::ShiftRightArithmetic,
        Some((_, 0, 7 | 15 | 31)) => Alias::Extend,
        _ => Alias::None,
    }
}

/// What an A64 floating point instruction computes, or `None` for one that
/// is not floating point. A conversion to an integer names its rounding:
/// `fcvtms` rounds down, as `floor` does.
fn float_op(opcode: Opcode) -> Option<Op> {
    Some(match opcode {
        Opcode::FADD => Op::FloatAdd,
        Opcode::FSUB => Op::FloatSubtract,
        Opcode::FMUL | Opcode::FNMUL => Op::FloatMultiply,
        Opcode::FMADD | Opcode::FMSUB | Opcode::FNMADD | Opcode::FNMSUB => Op::FloatMultiplyAdd,
        Opcode::FDIV => Op::FloatDivide,
        Opcode::FNEG | Opcode::FABS => Op::FloatSign,
        Opcode::FSQRT => Op::FloatSquareRoot,
        Opcode::FMIN | Opcode::FMAX | Opcode::FMINNM | Opcode::FMAXNM => Op::FloatMinMax,
        Opcode::FRINTM | Opcode::FCVTMS | Opcode::FCVTMU => Op::FloatRoundDown,
        Opcode::FRINTP | Opcode::FCVTPS | Opcode::FCVTPU => Op::FloatRoundUp,
        Opcode::FRINTZ | Opcode::FCVTZS | Opcode::FCVTZU => Op::FloatRoundTowardZero,
        Opcode::FRINTN
        | Opcode::FRINTA
        | Opcode::FRINTX
        | Opcode::FRINTI
        | Opcode::FCVTNS
        | Opcode::FCVTNU
        | Opcode::FCVTN
        | Opcode::FCVTN2
        | Opcode::FCVTAS
        | Opcode::FCVTAU => Op::FloatRoundNearest,
        Opcode::FCVT
        | Opcode::FCVTL
        | Opcode::FCVTL2
        | Opcode::FCVTXN
        | Opcode::FCVTXN2
        | Opcode::SCVTF
        | Opcode::UCVTF => Op::FloatConvert,
        Opcode::FRINT32Z
        | Opcode::FRINT32X
        | Opcode::FRINT64Z
        | Opcode::FRINT64X
        | Opcode::FMULX
        | Opcode::FMLSL
        | Opcode::FMLSL2
        | Opcode::FMLAL
        | Opcode::FMLAL2
        | Opcode::FCMLA
        | Opcode::FMLA
        | Opcode::FMLS
        | Opcode::FCMEQ
        | Opcode::FCMGE
        | Opcode::FCMGT
        | Opcode::FCMLT
        | Opcode::FCMLE
        | Opcode::FACGE
        | Opcode::FACGT
        | Opcode::FRECPS
        | Opcode::FRECPE
        | Opcode::FRECPX
        | Opcode::FRSQRTE
        | Opcode::FRSQRTS
        | Opcode::FMAXNMP
        | Opcode::FMINMNP
        | Opcode::FMINNMP
        | Opcode::FADDP
        | Opcode::FMAXP
        | Opcode::FMINP
        | Opcode::FMAXNMV
        | Opcode::FMINNMV
        | Opcode::FMAXV
        | Opcode::FMINV
        | Opcode::FABD
        | Opcode::FJCVTZS
        | Opcode::FCADD => Op::Float,
        _ => return None,
    })
}

/// `ldxr`, `ldaxr`, `ldxp` and `ldaxp`, which open an exclusive access.
fn is_exclusive_load(opcode: Opcode) -> bool {
    matches!(
        opcode,
        Opcode::LDXR
            | Opcode::LDXRB
            | Opcode::LDXRH
            | Opcode::LDAXR
            | Opcode::LDAXRB
            | Opcode::LDAXRH
            | Opcode::LDXP
            | Opcode::LDAXP
    )
}

/// See [`Alias::AtomicStore`].
fn is_atomic_store(inst: &Instruction) -> bool {
    let order = match inst.opcode {
        Opcode::LDADD(order)
        | Opcode::LDADDB(order)
        | Opcode::LDADDH(order)
        | Opcode::LDCLR(order)
        | Opcode::LDCLRB(order)
        | Opcode::LDCLRH(order)
        | Opcode::LDEOR(order)
        | Opcode::LDEORB(order)
        | Opcode::LDEORH(order)
        | Opcode::LDSET(order)
        | Opcode::LDSETB(order)
        | Opcode::LDSETH(order)
        | Opcode::LDSMAX(order)
        | Opcode::LDSMAXB(order)
        | Opcode::LDSMAXH(order)
        | Opcode::LDSMIN(order)
        | Opcode::LDSMINB(order)
        | Opcode::LDSMINH(order)
        | Opcode::LDUMAX(order)
        | Opcode::LDUMAXB(order)
        | Opcode::LDUMAXH(order)
        | Opcode::LDUMIN(order)
        | Opcode::LDUMINB(order)
        | Opcode::LDUMINH(order) => order,
        _ => return false,
    };
    const ACQUIRE: u8 = 0b10;
    order & ACQUIRE == 0 && is_zero_register(inst.operands[1])
}

fn role_of(opcode: Opcode, alias: Alias) -> Role {
    if alias == Alias::AtomicStore {
        return Role::Store;
    }
    match opcode {
        Opcode::SWP(_)
        | Opcode::SWPB(_)
        | Opcode::SWPH(_)
        | Opcode::LDADD(_)
        | Opcode::LDADDB(_)
        | Opcode::LDADDH(_)
        | Opcode::LDCLR(_)
        | Opcode::LDCLRB(_)
        | Opcode::LDCLRH(_)
        | Opcode::LDEOR(_)
        | Opcode::LDEORB(_)
        | Opcode::LDEORH(_)
        | Opcode::LDSET(_)
        | Opcode::LDSETB(_)
        | Opcode::LDSETH(_)
        | Opcode::LDSMAX(_)
        | Opcode::LDSMAXB(_)
        | Opcode::LDSMAXH(_)
        | Opcode::LDSMIN(_)
        | Opcode::LDSMINB(_)
        | Opcode::LDSMINH(_)
        | Opcode::LDUMAX(_)
        | Opcode::LDUMAXB(_)
        | Opcode::LDUMAXH(_)
        | Opcode::LDUMIN(_)
        | Opcode::LDUMINB(_)
        | Opcode::LDUMINH(_)
        | Opcode::CAS(_)
        | Opcode::CASB(_)
        | Opcode::CASH(_)
        | Opcode::CASP(_) => Role::Atomic,
        Opcode::LDP | Opcode::LDPSW | Opcode::LDNP | Opcode::LDXP | Opcode::LDAXP => {
            Role::Load { registers: 2 }
        }
        Opcode::LDAR
        | Opcode::LDLAR
        | Opcode::LDARB
        | Opcode::LDLARB
        | Opcode::LDARH
        | Opcode::LDLARH
        | Opcode::LDAXR
        | Opcode::LDAXRB
        | Opcode::LDAXRH
        | Opcode::LDXR
        | Opcode::LDXRB
        | Opcode::LDXRH
        | Opcode::LDR
        | Opcode::LDRB
        | Opcode::LDRH
        | Opcode::LDRSB
        | Opcode::LDRSH
        | Opcode::LDRSW
        | Opcode::LDTR
        | Opcode::LDTRB
        | Opcode::LDTRH
        | Opcode::LDTRSB
        | Opcode::LDTRSH
        | Opcode::LDTRSW
        | Opcode::LDUR
        | Opcode::LDURB
        | Opcode::LDURH
        | Opcode::LDURSB
        | Opcode::LDURSH
        | Opcode::LDURSW
        | Opcode::LDRAA
        | Opcode::LDRAB
        | Opcode::LDAPR
        | Opcode::LDAPRB
        | Opcode::LDAPRH
        | Opcode::LDAPUR
        | Opcode::LDAPURB
        | Opcode::LDAPURH
        | Opcode::LDAPURSB
        | Opcode::LDAPURSH
        | Opcode::LDAPURSW
        | Opcode::LDG
        | Opcode::LDGM
        | Opcode::LD1
        | Opcode::LD2
        | Opcode::LD3
        | Opcode::LD4
        | Opcode::LD1R
        | Opcode::LD2R
        | Opcode::LD3R
        | Opcode::LD4R => Role::Load { registers: 1 },
        Opcode::STXR
        | Opcode::STXRB
        | Opcode::STXRH
        | Opcode::STLXR
        | Opcode::STLXRB
        | Opcode::STLXRH
        | Opcode::STXP
        | Opcode::STLXP => Role::StoreExclusive,
        Opcode::STR
        | Opcode::STRB
        | Opcode::STRH
        | Opcode::STRW
        | Opcode::STUR
        | Opcode::STURB
        | Opcode::STURH
        | Opcode::STTR
        | Opcode::STTRB
        | Opcode::STTRH
        | Opcode::STP
        | Opcode::STNP
        | Opcode::STLR
        | Opcode::STLRB
        | Opcode::STLRH
        | Opcode::STLLR
        | Opcode::STLLRB
        | Opcode::STLLRH
        | Opcode::STLUR
        | Opcode::STLURB
        | Opcode::STLURH
        | Opcode::STG
        | Opcode::STZG
        | Opcode::ST2G
        | Opcode::STZ2G
        | Opcode::STGM
        | Opcode::STZGM
        | Opcode::ST1
        | Opcode::ST2
        | Opcode::ST3
        | Opcode::ST4 => Role::Store,
        Opcode::B
        | Opcode::BL
        | Opcode::Bcc(_)
        | Opcode::BCcc(_)
        | Opcode::CBZ
        | Opcode::CBNZ
        | Opcode::TBZ
        | Opcode::TBNZ
        | Opcode::MSR
        | Opcode::PRFM
        | Opcode::PRFUM
        | Opcode::CCMP
        | Opcode::CCMN
        | Opcode::FCMP
        | Opcode::FCMPE
        | Opcode::FCCMP
        | Opcode::FCCMPE => Role::ReadOnly,
        opcode
            if is_indirect_call(opcode)
                || is_indirect_jump(opcode)
                || is_return(opcode)
                || is_exception_return(opcode) =>
        {
            Role::ReadOnly
        }
        _ => Role::Compute,
    }
}

/// Instructions that keep part of their destination, so read it too.
fn reads_destination(opcode: Opcode) -> bool {
    matches!(
        opcode,
        Opcode::MOVK
            | Opcode::BFM
            | Opcode::INS
            | Opcode::BSL
            | Opcode::BIT
            | Opcode::BIF
            | Opcode::TBX
    )
}

fn reads_flags(opcode: Opcode) -> bool {
    matches!(
        opcode,
        Opcode::Bcc(_)
            | Opcode::BCcc(_)
            | Opcode::CSEL
            | Opcode::CSINC
            | Opcode::CSINV
            | Opcode::CSNEG
            | Opcode::FCSEL
            | Opcode::ADC
            | Opcode::ADCS
            | Opcode::SBC
            | Opcode::SBCS
            | Opcode::CCMP
            | Opcode::CCMN
            | Opcode::FCCMP
            | Opcode::FCCMPE
    )
}

fn writes_flags(opcode: Opcode) -> bool {
    matches!(
        opcode,
        Opcode::ADDS
            | Opcode::SUBS
            | Opcode::ANDS
            | Opcode::BICS
            | Opcode::ADCS
            | Opcode::SBCS
            | Opcode::CCMP
            | Opcode::CCMN
            | Opcode::FCMP
            | Opcode::FCMPE
            | Opcode::FCCMP
            | Opcode::FCCMPE
    )
}

/// The registers an operand that is a value names. A memory operand names
/// none here: see [`address_registers`].
fn value_registers(operand: Operand) -> RegSet {
    let general = |number: u16| Reg::General(number as u8);
    let vectors = |first: u16, count: u8| {
        (0..u16::from(count)).map(move |n| Reg::Vector(((first + n) % 32) as u8))
    };
    match operand {
        Operand::Register(_, 31) | Operand::RegShift(_, _, _, 31) => RegSet::EMPTY,
        Operand::Register(_, number) | Operand::RegShift(_, _, _, number) => {
            [general(number)].into_iter().collect()
        }
        Operand::RegisterOrSP(_, 31) => [Reg::Stack].into_iter().collect(),
        Operand::RegisterOrSP(_, number) => [general(number)].into_iter().collect(),
        Operand::RegisterPair(_, number) => {
            [general(number), general(number + 1)].into_iter().filter(|_| number < 31).collect()
        }
        Operand::SIMDRegister(_, number)
        | Operand::SIMDRegisterElements(_, number, _)
        | Operand::SIMDRegisterElementsLane(_, number, _, _)
        | Operand::SIMDRegisterElementsMultipleLane(_, number, _, _, _) => {
            [Reg::Vector((number % 32) as u8)].into_iter().collect()
        }
        Operand::SIMDRegisterGroup(_, first, _, count)
        | Operand::SIMDRegisterGroupLane(first, _, count, _) => vectors(first, count).collect(),
        _ => RegSet::EMPTY,
    }
}

/// The registers a memory operand reads to form its address, and the base
/// it writes back.
fn address_registers(operand: Operand, reads: &mut RegSet, writes: &mut RegSet) {
    let base = |number: u16| if number == 31 { Reg::Stack } else { Reg::General(number as u8) };
    let index = |number: u16| (number != 31).then_some(Reg::General(number as u8));
    match operand {
        Operand::RegPreIndex(number, _, write_back) => {
            reads.insert(base(number));
            if write_back {
                writes.insert(base(number));
            }
        }
        Operand::RegPostIndex(number, _) => {
            reads.insert(base(number));
            writes.insert(base(number));
        }
        Operand::RegPostIndexReg(number, offset) => {
            reads.insert(base(number));
            writes.insert(base(number));
            index(offset).into_iter().for_each(|reg| reads.insert(reg));
        }
        Operand::RegRegOffset(number, offset, ..) => {
            reads.insert(base(number));
            index(offset).into_iter().for_each(|reg| reads.insert(reg));
        }
        _ => {}
    }
}

fn is_memory(operand: &Operand) -> bool {
    matches!(
        operand,
        Operand::RegPreIndex(..)
            | Operand::RegPostIndex(..)
            | Operand::RegPostIndexReg(..)
            | Operand::RegRegOffset(..)
    )
}

fn memory_access(opcode: Opcode, role: Role, operands: &[Operand]) -> Option<MemoryAccess> {
    if !operands.iter().any(is_memory) {
        return None;
    }
    let kind = match role {
        Role::Load { .. } => AccessKind::Load,
        Role::Atomic => AccessKind::LoadStore,
        Role::Store | Role::StoreExclusive => AccessKind::Store,
        // A prefetch reads no value.
        Role::ReadOnly | Role::Compute => return None,
    };
    Some(MemoryAccess { kind, width: access_width(opcode, role, operands) })
}

/// The width of each value an access moves: the one the instruction names,
/// as `ldrb` and `ldrsw` do, else the width of the register moved.
fn access_width(opcode: Opcode, role: Role, operands: &[Operand]) -> Option<Width> {
    match opcode {
        Opcode::LDRSW | Opcode::LDURSW | Opcode::LDTRSW | Opcode::LDAPURSW | Opcode::LDPSW => {
            return Some(Width::Bits32);
        }
        Opcode::LDRB
        | Opcode::LDRSB
        | Opcode::LDURB
        | Opcode::LDURSB
        | Opcode::LDTRB
        | Opcode::LDTRSB
        | Opcode::LDARB
        | Opcode::LDLARB
        | Opcode::LDAXRB
        | Opcode::LDXRB
        | Opcode::LDAPRB
        | Opcode::LDAPURB
        | Opcode::LDAPURSB
        | Opcode::STRB
        | Opcode::STURB
        | Opcode::STTRB
        | Opcode::STLRB
        | Opcode::STLLRB
        | Opcode::STLXRB
        | Opcode::STXRB
        | Opcode::STLURB
        | Opcode::SWPB(_)
        | Opcode::CASB(_)
        | Opcode::LDADDB(_)
        | Opcode::LDCLRB(_)
        | Opcode::LDEORB(_)
        | Opcode::LDSETB(_)
        | Opcode::LDSMAXB(_)
        | Opcode::LDSMINB(_)
        | Opcode::LDUMAXB(_)
        | Opcode::LDUMINB(_) => return Some(Width::Bits8),
        Opcode::LDRH
        | Opcode::LDRSH
        | Opcode::LDURH
        | Opcode::LDURSH
        | Opcode::LDTRH
        | Opcode::LDTRSH
        | Opcode::LDARH
        | Opcode::LDLARH
        | Opcode::LDAXRH
        | Opcode::LDXRH
        | Opcode::LDAPRH
        | Opcode::LDAPURH
        | Opcode::LDAPURSH
        | Opcode::STRH
        | Opcode::STURH
        | Opcode::STTRH
        | Opcode::STLRH
        | Opcode::STLLRH
        | Opcode::STLXRH
        | Opcode::STXRH
        | Opcode::STLURH
        | Opcode::SWPH(_)
        | Opcode::CASH(_)
        | Opcode::LDADDH(_)
        | Opcode::LDCLRH(_)
        | Opcode::LDEORH(_)
        | Opcode::LDSETH(_)
        | Opcode::LDSMAXH(_)
        | Opcode::LDSMINH(_)
        | Opcode::LDUMAXH(_)
        | Opcode::LDUMINH(_) => return Some(Width::Bits16),
        _ => {}
    }
    let register = match role {
        Role::Atomic | Role::StoreExclusive => operands.get(1),
        _ => operands.first(),
    };
    match register? {
        Operand::Register(size, _) | Operand::RegisterOrSP(size, _) => Some(width_of(*size)),
        Operand::SIMDRegister(size, _) => Some(match size {
            SIMDSizeCode::B => Width::Bits8,
            SIMDSizeCode::H => Width::Bits16,
            SIMDSizeCode::S => Width::Bits32,
            SIMDSizeCode::D => Width::Bits64,
            SIMDSizeCode::Q => Width::Bits128,
        }),
        _ => None,
    }
}

fn width_of(size: SizeCode) -> Width {
    match size {
        SizeCode::W => Width::Bits32,
        SizeCode::X => Width::Bits64,
    }
}

/// What an operand gives as a value, at `width`.
fn value_of(operand: Operand, width: Width) -> Value {
    let value = match operand {
        Operand::Register(_, 31) | Operand::RegShift(ShiftStyle::LSL, 0, _, 31) => Value::Const(0),
        Operand::Register(_, number) | Operand::RegShift(ShiftStyle::LSL, 0, _, number) => {
            Value::Reg(Reg::General(number as u8))
        }
        Operand::RegisterOrSP(_, 31) => Value::Reg(Reg::Stack),
        Operand::RegisterOrSP(_, number) => Value::Reg(Reg::General(number as u8)),
        Operand::Immediate(value) => Value::Const(u64::from(value)),
        Operand::Imm64(value) => Value::Const(value),
        Operand::Imm16(value) => Value::Const(u64::from(value)),
        Operand::ImmShift(value, shift) => Value::Const(u64::from(value) << shift),
        _ => Value::Other,
    };
    match value {
        Value::Const(value) => Value::Const(value & width.mask()),
        other => other,
    }
}

/// The width of the general registers an instruction works on.
fn operation_width(operands: &[Operand]) -> Width {
    operands
        .iter()
        .find_map(|operand| match operand {
            Operand::Register(size, _) | Operand::RegisterOrSP(size, _) => Some(width_of(*size)),
            _ => None,
        })
        .unwrap_or(Width::Bits64)
}

fn test_of(inst: &Instruction, alias: Alias, operands: &[Operand]) -> Option<Test> {
    let width = operation_width(operands);
    let value = |index: usize| operands.get(index).map_or(Value::Other, |op| value_of(*op, width));
    let guard = |cond, right| Some(Test::Guard(Guard { cond, left: value(0), right, width }));
    match inst.opcode {
        Opcode::Bcc(code) | Opcode::BCcc(code) => {
            return Some(Test::OnFlags(Cond::from_arm(code)));
        }
        Opcode::CBZ => return guard(Cond::Equal, Value::Const(0)),
        Opcode::CBNZ => return guard(Cond::NotEqual, Value::Const(0)),
        Opcode::TBZ | Opcode::TBNZ => {
            let bit = match operands.get(1) {
                Some(Operand::Imm16(bit)) => u32::from(*bit),
                Some(Operand::Immediate(bit)) => *bit,
                _ => return None,
            };
            let mask = Value::Const(1_u64.checked_shl(bit)?);
            let cond = if inst.opcode == Opcode::TBZ { Cond::BitsClear } else { Cond::BitsSet };
            return guard(cond, mask);
        }
        _ => {}
    }

    if alias != Alias::Compare {
        return None;
    }
    // An alias names its operands from 1: the 0th is the zero register.
    let (left, right) = (value(1), value(2));
    let comparison = match inst.opcode {
        Opcode::SUBS => Comparison::Subtract { left, right },
        Opcode::ANDS => Comparison::And { left, right },
        // `cmn x, #k` sets the flags as `cmp x, #-k` does, for any `k` but
        // zero: both compare `x` with `-k`.
        Opcode::ADDS => match right {
            Value::Const(constant) if constant != 0 => Comparison::Subtract {
                left,
                right: Value::Const(constant.wrapping_neg() & width.mask()),
            },
            _ => Comparison::Add { left, right },
        },
        _ => return None,
    };
    Some(Test::Compare { comparison, width })
}

/// What the decoder read for `insn`, where it read A64.
pub(crate) fn decoded(insn: &Insn) -> Option<Decoded> {
    match insn.opcode {
        super::Opcode::Aarch64(decoded) => Some(decoded),
        _ => None,
    }
}

fn opcode_of(insn: &Insn) -> Option<Opcode> {
    decoded(insn).map(|decoded| decoded.opcode)
}

/// A load, or an atomic access that `yaxpeax-arm` names as one: every
/// instruction it prints with `ld` first.
pub(crate) fn is_named_load(decoded: Decoded) -> bool {
    match role_of(decoded.opcode, decoded.alias) {
        Role::Load { .. } => true,
        Role::Atomic => !matches!(
            decoded.opcode,
            Opcode::CAS(_)
                | Opcode::CASB(_)
                | Opcode::CASH(_)
                | Opcode::CASP(_)
                | Opcode::SWP(_)
                | Opcode::SWPB(_)
                | Opcode::SWPH(_)
        ),
        _ => false,
    }
}

/// A load, a store or an atomic access of memory.
fn accesses_memory(decoded: Decoded) -> bool {
    !matches!(role_of(decoded.opcode, decoded.alias), Role::Compute | Role::ReadOnly)
}

/// Whether `insn` may write the register its operands name first. A store
/// names first a register it reads, and a compare the value it compares.
fn may_write_first(insn: &Insn) -> bool {
    decoded(insn).is_none_or(|decoded| {
        decoded.alias != Alias::Compare
            && !matches!(role_of(decoded.opcode, decoded.alias), Role::Store | Role::StoreExclusive)
    })
}

/// The page an `adrp` names, or the address an `adr` does.
fn page_of(insn: &Insn) -> Option<u64> {
    let distance = insn.operands.split_once(", $")?.1;
    let (negative, digits) = match distance.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, distance.strip_prefix('+')?),
    };
    let offset = u64::from_str_radix(digits.strip_prefix("0x")?, 16).ok()?;
    let base = match opcode_of(insn)? {
        Opcode::ADRP => insn.address & !(PAGE - 1),
        Opcode::ADR => insn.address,
        _ => return None,
    };
    Some(if negative { base.wrapping_sub(offset) } else { base.wrapping_add(offset) })
}

/// What reading a function for its pages found.
struct Pages {
    kinds: Vec<ConstantKind>,
    /// The address each instruction forms or reads, or the page it takes.
    formed: Vec<Option<u64>>,
    addresses: Vec<u64>,
    /// Where a load of a whole pointer reads, from an address the page
    /// forms.
    pointer_loads: Vec<u64>,
}

/// Follow each register that holds a page from `adrp`, or an address from
/// `adr`, to the `add` or the load that joins an offset to it.
fn track_pages(code: &[u8], body: &[Insn], space: &AddressSpace) -> Pages {
    let mut kinds = vec![ConstantKind::Value; body.len()];
    let mut formed_at = vec![None; body.len()];
    let mut addresses = Vec::new();
    let mut pointer_loads = Vec::new();
    let Some(start) = body.first().map(|insn| insn.address) else {
        return Pages { kinds, formed: formed_at, addresses, pointer_loads };
    };
    // Registers holding a page, or an address.
    let mut held: Vec<(Tracked, u64)> = Vec::new();
    // The page each register last took from `adrp`. An `add` to itself
    // keeps it: on another path through the function, the register still
    // holds the page. GCC's `inflate_table` for AArch64 at `-Os` adds the
    // same offset to one page register on two paths.
    let mut pages = PageRegisters::default();
    fn values_of(list: &[(Tracked, u64)], register: Tracked) -> impl Iterator<Item = u64> + '_ {
        list.iter().filter(move |(held, _)| *held == register).map(|&(_, value)| value)
    }
    // The address a base register and an offset form, if what the register
    // holds, or a page it may hold, lands in the image.
    let formed = |held: &[(Tracked, u64)], pages: &PageRegisters, base: Tracked, low: u64| {
        values_of(held, base)
            .chain(pages.values(base).iter().copied())
            .map(|value| value.wrapping_add(low))
            .find(|&address| space.contains_formed(address))
    };

    for (index, insn) in body.iter().enumerate() {
        let after_an_end =
            index > 0 && matches!(body[index - 1].kind, InsnKind::Jump { .. } | InsnKind::Return);
        if after_an_end {
            pages.after_an_end();
        }
        // The operands as the decoder read them, from the word itself: the
        // text would have to be split and parsed again for each.
        let Some(decoded) = decoded(insn) else { continue };
        let Some(inst) = usize::try_from(insn.address - start)
            .ok()
            .and_then(|offset| code.get(offset..offset + INSN_WIDTH))
            .and_then(|word| {
                let mut inst = Instruction::default();
                InstDecoder::default().decode_into(&mut inst, &mut U8Reader::new(word)).ok()?;
                Some(inst)
            })
        else {
            continue;
        };
        let operands = &inst.operands;
        let destination = Tracked::of(operands[0]);
        match (decoded.opcode, decoded.alias, operands) {
            // The distance from `pc` to a page or to data moves whenever the
            // code or the data does.
            (Opcode::ADRP | Opcode::ADR, ..) => {
                kinds[index] = ConstantKind::Address;
                let Some(destination) = destination else { continue };
                held.retain(|(held, _)| *held != destination);
                pages.forget(destination);
                if let Some(value) = page_of(insn) {
                    formed_at[index] = Some(value);
                    if decoded.opcode == Opcode::ADR && space.contains_formed(value) {
                        addresses.push(value);
                    }
                    held.push((destination, value));
                    if decoded.opcode == Opcode::ADRP {
                        pages.take(destination, value);
                    }
                }
                continue;
            }
            // `add xD, xP, #lo12`: the address on the page.
            // A 32-bit add, as `add w20, w20, #0x1`, counts: it forms no
            // address, though it writes the register.
            (
                Opcode::ADD,
                Alias::None,
                [
                    Operand::RegisterOrSP(SizeCode::X, _),
                    source @ Operand::RegisterOrSP(SizeCode::X, _),
                    Operand::Immediate(low),
                    Operand::Nothing,
                ],
            ) => {
                let (Some(destination), Some(source)) = (destination, Tracked::of(*source)) else {
                    continue;
                };
                let low = u64::from(*low);
                let address = formed(&held, &pages, source, low);
                // An address outside what the image holds, as the data of a
                // kext linked apart, is still one to show.
                if address.is_none() {
                    formed_at[index] =
                        pages.values(source).first().map(|page| page.wrapping_add(low));
                }
                if let Some(address) = address {
                    kinds[index] = ConstantKind::Address;
                    formed_at[index] = Some(address);
                    addresses.push(address);
                    held.retain(|(held, _)| *held != destination);
                    held.push((destination, address));
                    if destination != source {
                        pages.forget(destination);
                    }
                    continue;
                }
            }
            // `ldr xD, [xP, #lo12]` and stores: data on the page. An index
            // register names no offset, but the page still moves.
            _ if accesses_memory(decoded) => {
                if let Some((base, low)) = operands.iter().find_map(|&operand| page_offset(operand))
                {
                    // A page outside the image, as the GOT can be, still moves.
                    let on_a_page = !pages.values(base).is_empty();
                    let address = low.and_then(|low| formed(&held, &pages, base, low));
                    if on_a_page || address.is_some() {
                        kinds[index] = ConstantKind::Address;
                    }
                    // A page outside the image, as the GOT of a kext can be,
                    // still names a slot.
                    formed_at[index] = address.or_else(|| {
                        let low = low?;
                        pages.values(base).first().map(|page| page.wrapping_add(low))
                    });
                    // `ldr x0, [x8, #lo12]` reads a whole pointer, as from a
                    // slot of the GOT or a table of texts.
                    if let Some(address) = address
                        && decoded.opcode == Opcode::LDR
                        && matches!(operands[0], Operand::Register(SizeCode::X, _))
                    {
                        pointer_loads.push(address);
                    }
                }
            }
            _ => {}
        }
        // Any other write of the register ends what it held. A write of
        // the low half, as `mov w24, w0`, clears the high half too, so it
        // ends it as well in truth; the text this replaced read `w24` and
        // `x24` as two registers, and that is kept until a measure says
        // which reads better (TODO.md).
        let writes_whole = matches!(
            operands[0],
            Operand::Register(SizeCode::X, _) | Operand::RegisterOrSP(SizeCode::X, _)
        );
        if let Some(destination) = destination
            && writes_whole
            && may_write_first(insn)
        {
            held.retain(|(held, _)| *held != destination);
            pages.forget(destination);
        }
    }
    Pages { kinds, formed: formed_at, addresses, pointer_loads }
}

/// A register [`track_pages`] follows: a general register by its number,
/// whichever width names it, or the stack pointer, as 31. The zero
/// register holds nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Tracked(u8);

impl Tracked {
    /// How many registers there are to follow.
    const COUNT: usize = 32;

    fn of(operand: Operand) -> Option<Self> {
        match operand {
            Operand::Register(_, 31) => None,
            Operand::Register(_, number) | Operand::RegisterOrSP(_, number) => {
                Some(Self(number.min(31) as u8))
            }
            _ => None,
        }
    }

    fn index(self) -> usize {
        usize::from(self.0)
    }
}

/// The base register of a memory operand that names an offset in a page,
/// and the offset, `None` for an index register. An offset of zero, as in
/// `[x8]`, joins no page. Nor does a load that writes its base back, as
/// `ldr w2, [x3, #0x48]!`: on libgnutls for arm64 that is a field of a
/// structure, and reading it as an address reported texts that are none.
fn page_offset(operand: Operand) -> Option<(Tracked, Option<u64>)> {
    let base = |number: u16| Tracked(number.min(31) as u8);
    match operand {
        Operand::RegPreIndex(number, offset, false) if offset != 0 => {
            Some((base(number), Some(i64::from(offset) as u64)))
        }
        // `[x1, x2]`. One that shifts or extends the index, as
        // `[x1, x14, lsl #2]`, indexes a table of its own.
        Operand::RegRegOffset(number, _, SizeCode::X, ShiftStyle::LSL, 0) => {
            Some((base(number), None))
        }
        _ => None,
    }
}

/// The pages each register may hold, as [`track_pages`] reads on.
///
/// Code that only a branch reaches, after a jump or a return, can find a
/// register as any path left it, and the path the page came by is not always
/// the one above: `inflate_table` copies over the page register just before
/// it jumps away. So each register keeps every page it ever took, and after
/// an end may hold any of them.
///
/// `track_pages` reads a whole region of a stripped library as one body, and
/// a library of 300000 instructions takes thousands of pages. A copy of every
/// page after each end then took 9.5 seconds on `libgnutls` for AArch64, so
/// a register after an end holds a count of its pages, not a copy. Only the
/// first page of a register that forms an address counts, so each page is
/// kept once, in the order it came.
struct PageRegisters {
    /// Every page each register took, each once, the first first.
    ever: [Vec<u64>; Tracked::COUNT],
    /// What each register holds on the path read now. `None` holds no page.
    now: [Option<MayHold>; Tracked::COUNT],
}

impl Default for PageRegisters {
    fn default() -> Self {
        Self { ever: core::array::from_fn(|_| Vec::new()), now: [None; Tracked::COUNT] }
    }
}

/// The pages a register may hold.
#[derive(Clone, Copy)]
enum MayHold {
    /// The first so many pages the register ever took.
    AnyOf(usize),
    /// The page it took last, on this path.
    One(u64),
}

impl PageRegisters {
    /// The pages `register` may hold, the most likely first.
    fn values(&self, register: Tracked) -> &[u64] {
        match &self.now[register.index()] {
            Some(MayHold::AnyOf(count)) => &self.ever[register.index()][..*count],
            Some(MayHold::One(page)) => core::slice::from_ref(page),
            None => &[],
        }
    }

    /// `register` takes `page` from `adrp`.
    fn take(&mut self, register: Tracked, page: u64) {
        self.now[register.index()] = Some(MayHold::One(page));
        let taken = &mut self.ever[register.index()];
        if !taken.contains(&page) {
            taken.push(page);
        }
    }

    /// `register` holds no page any more.
    fn forget(&mut self, register: Tracked) {
        self.now[register.index()] = None;
    }

    /// Past a jump or a return, each register may hold any page it took.
    fn after_an_end(&mut self) {
        for (now, taken) in self.now.iter_mut().zip(&self.ever) {
            *now = (!taken.is_empty()).then_some(MayHold::AnyOf(taken.len()));
        }
    }
}

/// Read the table a `br` at `insns[index]` jumps through.
fn read_jump_table(
    memory: &Memory<'_>,
    code: &Range<u64>,
    insns: &[Insn],
    index: usize,
) -> Option<JumpTable> {
    let jump = &insns[index];
    if opcode_of(jump) != Some(Opcode::BR) {
        return None;
    }
    let earlier = &insns[index.saturating_sub(TABLE_LOOK_BACK)..index];
    let last_write = |register: &str, before: u64| {
        earlier.iter().rev().filter(|insn| insn.address < before).find(|insn| {
            may_write_first(insn)
                && insn.operands.split(',').next().map(str::trim) == Some(register)
        })
    };
    // `add xT, xB, xE, lsl #2`, or GCC's `add xT, xB, wE, sxth #2`.
    let add = last_write(jump.operands.trim(), jump.address)?;
    let parts: Vec<&str> = add.operands.split(',').map(str::trim).collect();
    let [_, base_register, entry_register, extend] = parts.as_slice() else { return None };
    let signed = extend.starts_with("sxt");
    if opcode_of(add) != Some(Opcode::ADD) || !extend.ends_with("#2") {
        return None;
    }
    let base = page_of(last_write(base_register, add.address)?)?;

    // `ldrb wE, [xTab, xI, lsl #1]` and the like: one entry.
    let entry_name = format!("w{}", &entry_register[1..]);
    let load = last_write(&entry_name, add.address)?;
    let width = match opcode_of(load)? {
        Opcode::LDRB | Opcode::LDRSB => 1,
        Opcode::LDRH | Opcode::LDRSH => 2,
        Opcode::LDR | Opcode::LDRSW => 4,
        _ => return None,
    };
    let reference = load.operands.split_once('[')?.1;
    let mut fields = reference.split([',', ']']).map(str::trim);
    let (table_register, index_register) = (fields.next()?, fields.next()?);
    let table_insn = last_write(table_register, load.address)?;
    let table = match opcode_of(table_insn)? {
        Opcode::ADR => page_of(table_insn)?,
        Opcode::ADD => {
            let parts: Vec<&str> = table_insn.operands.split(',').map(str::trim).collect();
            let [_, page_register, low] = parts.as_slice() else { return None };
            let page = page_of(last_write(page_register, table_insn.address)?)?;
            page.wrapping_add(Aarch64.constant_value(low)?)
        }
        _ => return None,
    };

    // `cmp wI, #n`: the cases run from 0 to n.
    let index_number = &index_register[1..];
    let bound = earlier.iter().rev().find_map(|insn| {
        let parts: Vec<&str> = insn.operands.split(',').map(str::trim).collect();
        let is_cmp = decoded(insn).is_some_and(|decoded| {
            decoded.opcode == Opcode::SUBS && decoded.alias == Alias::Compare
        });
        match parts.as_slice() {
            [register, bound] if is_cmp && register.get(1..) == Some(index_number) => {
                Aarch64.constant_value(bound)
            }
            _ => None,
        }
    })?;
    let cases = usize::try_from(bound).ok()?.checked_add(1).filter(|&cases| cases <= MOST_CASES)?;

    let mut targets = Vec::with_capacity(cases);
    for case in 0..cases {
        let bytes = memory.bytes(table + (case * width) as u64, width)?;
        let entry = match (bytes, signed) {
            ([byte], false) => i64::from(*byte),
            ([byte], true) => i64::from(*byte as i8),
            ([low, high], false) => i64::from(u16::from_le_bytes([*low, *high])),
            ([low, high], true) => i64::from(i16::from_le_bytes([*low, *high])),
            ([a, b, c, d], _) => i64::from(i32::from_le_bytes([*a, *b, *c, *d])),
            _ => return None,
        };
        let target = base.checked_add_signed(entry * INSN_WIDTH as i64)?;
        if !code.contains(&target) {
            return None;
        }
        targets.push(target);
    }
    Some(JumpTable { jump: jump.address, words: table..table + (cases * width) as u64, targets })
}

#[cfg(test)]
mod extend_tests {
    use super::*;

    #[test]
    fn a_32_bit_register_in_a_64_bit_add_is_zero_extended() {
        let shown = |words: u32| {
            let code = words.to_le_bytes();
            let insn = Aarch64.decode(&code, 0, 0).expect("decodes");
            format!("{} {}", insn.mnemonic, insn.operands)
        };
        // From `llvm-mc --triple=aarch64`.
        assert_eq!(shown(0x8b21_5061), "add x1, x3, w1, uxtw #4");
        // `add x23, x10, w8, uxtw`, `sub x29, x6, w30, uxtw` and
        // `cmp x12, w11, uxtw`, as `llvm-mc` reads them.
        assert_eq!(shown(0x8b28_4157), "add x23, x10, w8, uxtw");
        assert_eq!(shown(0xcb3e_40dd), "sub x29, x6, w30, uxtw");
        assert_eq!(shown(0xeb2b_419f), "cmp x12, w11, uxtw");
        assert_eq!(shown(0x9b22_7c20), "smull x0, w1, w2");
        let extended = |opcode, operands: &str| extended_register(opcode, operands.into());
        assert_eq!(extended(Opcode::ADD, "x0, x1, x2, lsl #3"), "x0, x1, x2, lsl #3");
        assert_eq!(extended(Opcode::ADD, "w0, w1, w2, lsl #3"), "w0, w1, w2, lsl #3");
        assert_eq!(extended(Opcode::SMADDL, "x0, w1, w2"), "x0, w1, w2");
        assert_eq!(extended(Opcode::ADD, "x0, x1, w2, sxtw"), "x0, x1, w2, sxtw");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::decode_all;

    /// After an end, a register may hold any page it took, each once and
    /// the first first; a new page on the path read now replaces them.
    #[test]
    fn a_register_after_an_end_may_hold_any_page_it_took() {
        let mut pages = PageRegisters::default();
        pages.take(Tracked(8), 0x1000);
        pages.take(Tracked(8), 0x2000);
        pages.take(Tracked(8), 0x1000);
        pages.take(Tracked(9), 0x3000);
        assert_eq!(pages.values(Tracked(8)), [0x1000]);
        pages.forget(Tracked(9));
        assert!(pages.values(Tracked(9)).is_empty());

        pages.after_an_end();
        assert_eq!(pages.values(Tracked(8)), [0x1000, 0x2000]);
        assert_eq!(pages.values(Tracked(9)), [0x3000]);
        assert!(pages.values(Tracked(10)).is_empty());

        // A page taken later is not one this path may hold.
        pages.take(Tracked(9), 0x4000);
        pages.forget(Tracked(9));
        assert_eq!(pages.values(Tracked(8)), [0x1000, 0x2000]);
        pages.after_an_end();
        assert_eq!(pages.values(Tracked(9)), [0x3000, 0x4000]);
    }

    fn code(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn decode_one(word: u32) -> Insn {
        Aarch64.decode(&word.to_le_bytes(), 0, 0x1000).expect("the word must decode")
    }

    /// Encodings from `llvm-mc --triple=aarch64 -mattr=+lse --show-encoding`.
    mod words {
        pub const CBNZ_X8: u32 = 0xb500_00e8;
        pub const CBZ_X8: u32 = 0xb400_0068;
        pub const CMN_X8_1: u32 = 0xb100_051f;
        pub const B_NE: u32 = 0x5400_0121;
        pub const CMP_X8_0: u32 = 0xf100_011f;
        pub const CMP_W2_63: u32 = 0x7100_fc5f;
        pub const B_HI: u32 = 0x5400_0208;
        pub const TST_W0_4: u32 = 0x721e_001f;
        pub const B_EQ: u32 = 0x5400_0080;
        pub const TBZ_W0_2: u32 = 0x3610_0080;
        pub const ADD_X0_X1_X2: u32 = 0x8b02_0020;
        pub const LDR_X1_X2_8: u32 = 0xf940_0441;
        pub const LDP_X29_X30_SP_POST: u32 = 0xa8c1_7bfd;
        pub const STR_W3_X4_X5: u32 = 0xb825_6883;
        pub const STXR_W1_X2_X3: u32 = 0xc801_7c62;
        pub const BL: u32 = 0x9400_0040;
        pub const BLR_X8: u32 = 0xd63f_0100;
        pub const RET: u32 = 0xd65f_03c0;
        pub const CSEL_X8_XZR_X8_EQ: u32 = 0x9a88_03e8;
        pub const MOVK_X23: u32 = 0xf2e3_05d7;
        pub const SUBS_X0_X0_1: u32 = 0xf100_0400;
        pub const LDADD_W1_W2_X3: u32 = 0xb821_0062;
        pub const CMP_X1_X2: u32 = 0xeb02_003f;
    }

    fn lift_one(word: u32) -> Lifted {
        Aarch64.lift(&decode_one(word), &word.to_le_bytes()).expect("the word must lift")
    }

    fn regs(regs: &[Reg]) -> RegSet {
        regs.iter().copied().collect()
    }

    fn x(number: u8) -> Reg {
        Reg::General(number)
    }

    /// The first guard that `words` make, and how many words it takes.
    fn guard_of(words: &[u32]) -> Option<(usize, Guard)> {
        let lifted: Vec<Option<Lifted>> = words.iter().map(|&word| Some(lift_one(word))).collect();
        let found = *crate::il::find_guards(&lifted).first()?;
        Some((found.branch + 1 - found.compare.unwrap_or(found.branch), found.guard))
    }

    #[test]
    fn cbnz_and_cmp_with_b_ne_are_one_guard() {
        let (taken, fused) = guard_of(&[words::CMP_X8_0, words::B_NE]).unwrap();
        assert_eq!(taken, 2);
        assert_eq!(guard_of(&[words::CBNZ_X8]), Some((1, fused)));
        assert_eq!(fused.cond, Cond::NotEqual);
        assert_eq!(fused.left, Value::Reg(x(8)));
        assert_eq!(fused.right, Value::Const(0));
    }

    #[test]
    fn cbz_tests_for_zero() {
        let (_, guard) = guard_of(&[words::CBZ_X8]).unwrap();
        assert_eq!(guard.cond, Cond::Equal);
        assert_eq!(guard.width, Width::Bits64);
    }

    /// The check of CVE-2024-23265: `x8 != -1`.
    #[test]
    fn cmn_with_one_compares_with_minus_one() {
        let (_, guard) = guard_of(&[words::CMN_X8_1, words::B_NE]).unwrap();
        assert_eq!(guard.cond, Cond::NotEqual);
        assert_eq!(guard.right, Value::Const(u64::MAX));
    }

    /// The check of CVE-2025-24257: a size above 63.
    #[test]
    fn a_32_bit_bound_keeps_its_width() {
        let (_, guard) = guard_of(&[words::CMP_W2_63, words::B_HI]).unwrap();
        assert_eq!(guard.cond, Cond::UnsignedGreater);
        assert_eq!(guard.left, Value::Reg(x(2)));
        assert_eq!(guard.right, Value::Const(63));
        assert_eq!(guard.width, Width::Bits32);
    }

    #[test]
    fn tst_with_b_eq_and_tbz_are_one_guard() {
        let (_, tst) = guard_of(&[words::TST_W0_4, words::B_EQ]).unwrap();
        let (_, tbz) = guard_of(&[words::TBZ_W0_2]).unwrap();
        assert_eq!(tst, tbz);
        assert_eq!(tbz.cond, Cond::BitsClear);
        assert_eq!(tbz.right, Value::Const(4));
    }

    #[test]
    fn a_compare_of_two_registers_reads_both() {
        let lifted = lift_one(words::CMP_X1_X2);
        assert_eq!(lifted.reads, regs(&[x(1), x(2)]));
        assert_eq!(lifted.writes, regs(&[Reg::Flags]), "the zero register is no destination");
    }

    #[test]
    fn arithmetic_that_sets_flags_is_no_compare() {
        let lifted = lift_one(words::SUBS_X0_X0_1);
        assert_eq!(lifted.writes, regs(&[x(0), Reg::Flags]));
        assert_eq!(lifted.test, None, "a loop count is work, not a check");
    }

    #[test]
    fn computing_writes_the_first_operand() {
        let lifted = lift_one(words::ADD_X0_X1_X2);
        assert_eq!(lifted.writes, regs(&[x(0)]));
        assert_eq!(lifted.reads, regs(&[x(1), x(2)]));
        assert_eq!(lifted.memory, None);
    }

    #[test]
    fn loads_and_stores_name_their_registers_and_width() {
        let load = lift_one(words::LDR_X1_X2_8);
        assert_eq!((load.reads, load.writes), (regs(&[x(2)]), regs(&[x(1)])));
        assert_eq!(
            load.memory,
            Some(MemoryAccess { kind: AccessKind::Load, width: Some(Width::Bits64) })
        );

        let pair = lift_one(words::LDP_X29_X30_SP_POST);
        assert_eq!(pair.writes, regs(&[x(29), x(30), Reg::Stack]), "the base is written back");
        assert_eq!(pair.reads, regs(&[Reg::Stack]));

        let store = lift_one(words::STR_W3_X4_X5);
        assert_eq!(store.reads, regs(&[x(3), x(4), x(5)]));
        assert!(store.writes.is_empty());
        assert_eq!(
            store.memory,
            Some(MemoryAccess { kind: AccessKind::Store, width: Some(Width::Bits32) })
        );

        let exclusive = lift_one(words::STXR_W1_X2_X3);
        assert_eq!(exclusive.writes, regs(&[x(1)]), "the status");
        assert_eq!(exclusive.reads, regs(&[x(2), x(3)]));

        let atomic = lift_one(words::LDADD_W1_W2_X3);
        assert_eq!((atomic.reads, atomic.writes), (regs(&[x(1), x(3)]), regs(&[x(2)])));
        assert_eq!(atomic.memory.map(|access| access.kind), Some(AccessKind::LoadStore));
    }

    #[test]
    fn calls_and_returns_use_the_link_register() {
        assert_eq!(lift_one(words::BL).writes, regs(&[x(30)]));
        let indirect = lift_one(words::BLR_X8);
        assert_eq!((indirect.reads, indirect.writes), (regs(&[x(8)]), regs(&[x(30)])));
        assert!(lift_one(words::RET).reads.contains(x(30)));
    }

    #[test]
    fn a_select_reads_the_flags_and_a_movk_its_destination() {
        let select = lift_one(words::CSEL_X8_XZR_X8_EQ);
        assert_eq!(select.reads, regs(&[x(8), Reg::Flags]));
        assert_eq!(select.writes, regs(&[x(8)]));
        let movk = lift_one(words::MOVK_X23);
        assert_eq!((movk.reads, movk.writes), (regs(&[x(23)]), regs(&[x(23)])));
    }

    #[test]
    fn operands_come_in_printed_order() {
        use il::Operand::{Const, Other, Target, Zero};
        let reg = |number| il::Operand::Reg(x(number));
        let operands = |word| lift_one(word).operands.into_vec();
        assert_eq!(operands(words::SUBS_X0_X0_1), [reg(0), reg(0), Const(1)]);
        assert_eq!(operands(words::CSEL_X8_XZR_X8_EQ), [reg(8), Zero, reg(8), Other]);
        assert_eq!(operands(words::BL), [Target]);
        assert_eq!(operands(words::RET), [reg(30)], "the link register");
    }

    #[test]
    fn a_memory_operand_names_its_base_and_offset() {
        use il::Operand::Memory;
        let memory = |word| *lift_one(word).operands.last().expect("a memory operand");
        assert_eq!(memory(words::LDR_X1_X2_8), Memory { base: Some(x(2)), offset: Some(8) });
        assert_eq!(memory(words::STR_W3_X4_X5), Memory { base: Some(x(4)), offset: None });
        assert_eq!(
            memory(words::LDP_X29_X30_SP_POST),
            Memory { base: Some(Reg::Stack), offset: Some(16) }
        );
    }

    #[test]
    fn the_frame_registers_are_sp_and_x29() {
        assert!(Aarch64.is_frame_register(Reg::Stack));
        assert!(Aarch64.is_frame_register(x(29)));
        assert!(!Aarch64.is_frame_register(x(28)));
        assert!(!Aarch64.is_frame_register(Reg::Vector(29)));
    }

    #[test]
    fn lifting_any_word_never_panics() {
        bolero::check!().with_type::<u32>().for_each(|&word| {
            let bytes = word.to_le_bytes();
            let insn = Aarch64.decode(&bytes, 0, 0x1000).expect("every word decodes or is unknown");
            if let Some(lifted) = Aarch64.lift(&insn, &bytes)
                && let Some(Test::Guard(_) | Test::OnFlags(_)) = lifted.test
            {
                assert!(
                    matches!(insn.kind, InsnKind::Branch { .. }),
                    "{insn}: a test that branches"
                );
            }
        });
    }

    #[test]
    fn control_moves_as_the_instruction_says() {
        assert_eq!(decode_one(0xd65f_03c0).kind, InsnKind::Return); // ret
        assert_eq!(decode_one(0x9400_0004).kind, InsnKind::Call { target: Some(0x1010) }); // bl
        assert_eq!(decode_one(0x1400_0002).kind, InsnKind::Jump { target: Some(0x1008) }); // b
        assert_eq!(decode_one(0x5400_0041).kind, InsnKind::Branch { target: Some(0x1008) }); // b.ne
        assert_eq!(decode_one(0xb400_0060).kind, InsnKind::Branch { target: Some(0x100c) }); // cbz x0
        assert_eq!(decode_one(0xd61f_0220).kind, InsnKind::Jump { target: None }); // br x17
        assert_eq!(decode_one(0xd63f_0100).kind, InsnKind::Call { target: None }); // blr x8
    }

    #[test]
    fn the_frame_record_opens_a_function() {
        assert!(Aarch64.is_prologue(&decode_one(0xa9bd_7bfd))); // stp x29, x30, [sp, #-0x30]!
        assert!(!Aarch64.is_prologue(&decode_one(0xa901_57f6))); // stp x22, x21, [sp, #0x10]
        assert!(Aarch64.is_tail_call(&decode_one(0xd61f_0220))); // br x17
        assert!(!Aarch64.is_tail_call(&decode_one(0xd61f_0100))); // br x8
    }

    /// `adrp` and `add` form an address, and the offset in the page moves
    /// with it.
    #[test]
    fn a_page_and_an_offset_form_an_address() {
        let words = [
            0x9000_0080, // 0x1000 adrp x0, 0x11000
            0x9100_a000, // 0x1004 add x0, x0, #0x28
            0xd65f_03c0, // 0x1008 ret
        ];
        let (insns, _) = decode_all(&Aarch64, &code(&words), 0x1000);
        let space = AddressSpace::from_ranges(core::iter::once(0x1000..0x20000));
        assert_eq!(
            Aarch64.data_addresses(&code(&words), &insns, &space, &Memory::new(&[])),
            [0x11028]
        );
        let kinds = Aarch64.constant_kinds(&code(&words), &insns, &space);
        assert_eq!(kinds[..2], [ConstantKind::Address, ConstantKind::Address]);
    }

    /// A load from a page outside the image, as the GOT can be, still reads
    /// at an address that moves when the linker lays the image out again.
    #[test]
    fn a_load_from_any_page_reads_at_an_address() {
        let words = [
            0x9000_0080, // 0x1000 adrp x0, 0x11000
            0xf940_3408, // 0x1004 ldr x8, [x0, #0x68]
            0xf940_3428, // 0x1008 ldr x8, [x1, #0x68]
            0xd65f_03c0, // 0x100c ret
        ];
        let (insns, _) = decode_all(&Aarch64, &code(&words), 0x1000);
        let space = AddressSpace::from_ranges(core::iter::once(0x1000..0x2000));
        let kinds = Aarch64.constant_kinds(&code(&words), &insns, &space);
        assert_eq!(kinds[1], ConstantKind::Address, "through the page");
        assert_eq!(kinds[2], ConstantKind::Value, "through a register with no page");
    }

    /// The bits `stub_slot` tests first are those of `adr` and `adrp`.
    #[test]
    fn the_address_bits_are_adr_and_adrp() {
        bolero::check!().with_type::<u32>().for_each(|&word| {
            let opcode = opcode_of(&decode_one(word));
            let is_address = matches!(opcode, Some(Opcode::ADR | Opcode::ADRP));
            assert_eq!(word & ADR_MASK == ADR_BITS, is_address, "{word:#010x}");
        });
    }

    /// The PLT stub of LLD for AArch64, from zlib.
    #[test]
    fn reads_the_slot_a_plt_stub_jumps_through() {
        let stub = code(&[0x9000_0110, 0xf942_3e11, 0x9111_e210, 0xd61f_0220]);
        assert_eq!(Aarch64.stub_slot(&stub, 0x1a210), Some(0x3a478));
        assert_eq!(Aarch64.stub_slot(&stub[..8], 0x1a210), None, "too short");
        // The stub of `lua_settable` in Lua for AArch64 at `-Os`, whose slot
        // starts its page: `ldr x17, [x16]`.
        let at_page = code(&[0xd000_0110, 0xf940_0211, 0x9100_0210, 0xd61f_0220]);
        assert_eq!(Aarch64.stub_slot(&at_page, 0x36710), Some(0x58000));
    }

    /// `bti` marks where an indirect branch may land, and comes before the
    /// frame is made. `yaxpeax-arm` 0.4 prints it as `hint #0x22`.
    #[test]
    fn a_branch_target_mark_comes_before_the_prologue() {
        let bti_c = decode_one(0xd503_245f);
        assert_eq!(Aarch64.preamble_before_prologue(core::slice::from_ref(&bti_c)), 1);
        assert!(Aarch64.is_frame_management(&bti_c));
        let paciasp = decode_one(0xd503_233f);
        assert_eq!(Aarch64.preamble_before_prologue(&[paciasp]), 1);
        let nop = decode_one(0xd503_201f);
        assert_eq!(Aarch64.preamble_before_prologue(&[nop]), 0);
    }

    #[test]
    fn padding_is_nops_and_zeros() {
        let bytes = code(&[0xd65f_03c0, 0xd503_201f, 0]);
        assert_eq!(Aarch64.trim_padding(&bytes), &bytes[..4]);
        assert!(Aarch64.is_padding(&decode_one(0xd503_201f)));
    }

    #[test]
    fn constants_read_with_their_sign() {
        assert_eq!(Aarch64.constant_value("#0x30"), Some(0x30));
        assert_eq!(Aarch64.constant_value("#-0x30"), Some(0x30_u64.wrapping_neg()));
        assert_eq!(Aarch64.constant_value("[sp, #0x10]"), None);
    }

    /// An exclusive access is one step of an atomic sequence, never a plain
    /// load or store that a pair could stand for.
    #[test]
    fn an_exclusive_access_is_atomic() {
        assert_eq!(lift_one(words::STXR_W1_X2_X3).op, Op::Atomic);
        // `ldxp x1, x2, [x0]`
        assert_eq!(lift_one(0xc87f_0801).op, Op::Atomic);
        assert_eq!(lift_one(words::LDR_X1_X2_8).op, Op::Load);
    }

    /// `floor` and `ceil` inline as `frintm` and `frintp`, and Lua's
    /// `math_floor` and `math_ceil` are twins but for them.
    #[test]
    fn a_float_operation_names_what_it_computes() {
        let cases = [
            (0x1e61_0800_u32, Op::FloatMultiply),    // fmul d0, d0, d1
            (0x1e61_1800, Op::FloatDivide),          // fdiv d0, d0, d1
            (0x1e65_4000, Op::FloatRoundDown),       // frintm d0, d0
            (0x1e64_c000, Op::FloatRoundUp),         // frintp d0, d0
            (0x1e78_0000, Op::FloatRoundTowardZero), // fcvtzs w0, d0
            (0x1e62_0000, Op::FloatConvert),         // scvtf d0, w0
        ];
        for (word, op) in cases {
            assert_eq!(lift_one(word).op, op, "{word:#010x}");
        }
    }

    /// The decoder prints an alias in place of the instruction it stands
    /// for, and the alias names what the instruction computes.
    #[test]
    fn an_alias_computes_what_it_names() {
        let cases = [
            (0x2a01_03e0_u32, Op::Move),             // mov w0, w1 (orr)
            (0x9100_03e0, Op::Move),                 // mov x0, sp (add)
            (0x4b01_03e0, Op::Negate),               // neg w0, w1 (sub)
            (0xeb01_03e0, Op::Negate),               // negs x0, x1 (subs)
            (0xda01_03e0, Op::Negate),               // ngc x0, x1 (sbc)
            (0x2a21_03e0, Op::Not),                  // mvn w0, w1 (orn)
            (0x9b02_7c20, Op::Multiply),             // mul x0, x1, x2 (madd)
            (0x9b22_fc20, Op::Multiply),             // smnegl x0, w1, w2 (smsubl)
            (0xd37f_f800, Op::ShiftLeft),            // lsl x0, x0, #1 (ubfm)
            (0xd341_fc00, Op::ShiftRight),           // lsr x0, x0, #1 (ubfm)
            (0x5300_1c00, Op::Extend),               // uxtb w0, w0 (ubfm)
            (0xd344_1c00, Op::BitField),             // ubfx x0, x0, #4, #4 (ubfm)
            (0x1300_1c00, Op::Extend),               // sxtb w0, w0 (sbfm)
            (0x9340_7c00, Op::Extend),               // sxtw x0, w0 (sbfm)
            (0x9340_fc00, Op::ShiftRightArithmetic), // asr x0, x0, #0 (sbfm)
            (words::CMP_X1_X2, Op::Compare),         // cmp x1, x2 (subs)
            (words::TST_W0_4, Op::Compare),          // tst w0, #4 (ands)
            (words::SUBS_X0_X0_1, Op::Subtract),     // subs x0, x0, #1
        ];
        for (word, op) in cases {
            assert_eq!(lift_one(word).op, op, "{word:#010x}");
        }
    }

    /// `ldadd w1, wzr, [x0]` keeps no old value, and prints as `stadd`. An
    /// acquiring form has no such alias, as it orders what comes after it.
    #[test]
    fn an_atomic_that_keeps_no_value_is_a_store() {
        let store = lift_one(0xb821_001f); // stadd w1, [x0]
        assert_eq!(store.op, Op::Store);
        assert_eq!(store.memory.map(|access| access.kind), Some(AccessKind::Store));
        assert!(store.writes.is_empty());
        assert_eq!(lift_one(0xb8a1_001f).op, Op::Atomic); // ldadda w1, wzr, [x0]
    }

    /// Instructions that keep part of their destination read it.
    #[test]
    fn an_insert_reads_its_destination() {
        let insert = lift_one(0x4e0c_1c20); // mov v0.s[1], w1 (ins)
        assert!(insert.reads.contains(Reg::Vector(0)));
        assert!(insert.writes.contains(Reg::Vector(0)));
        let select = lift_one(0x6e62_1c20); // bsl v0.16b, v1.16b, v2.16b
        assert!(select.reads.contains(Reg::Vector(0)));
        assert!(select.writes.contains(Reg::Vector(0)));
    }

    /// `ldrab` loads a whole pointer, though its name ends in `b`.
    #[test]
    fn a_signed_pointer_load_moves_a_pointer() {
        let load = lift_one(0xf8bf_0c20); // ldrab x0, [x1, #0xf80]!
        assert_eq!(load.memory.and_then(|access| access.width), Some(Width::Bits64));
    }

    /// `bc.eq` branches as `b.eq` does, and `eret` returns.
    #[test]
    fn a_hinted_branch_and_an_exception_return_move_control() {
        let branch = decode_one(0x5400_0010); // bc.eq
        assert_eq!(branch.kind, InsnKind::Branch { target: Some(0x1000) });
        let lifted = lift_one(0x5400_0010);
        assert_eq!(lifted.test, Some(Test::OnFlags(Cond::Equal)));
        assert!(lifted.reads.contains(Reg::Flags));
        assert_eq!(decode_one(0xd69f_03e0).kind, InsnKind::Return);
        assert_eq!(lift_one(0xd69f_03e0).op, Op::Return);
        assert_eq!(lift_one(0xd503_229f).op, Op::System, "csdb");
    }

    /// A function that loads a pointer from a table points at what the
    /// pointer does, where it lands in the image.
    #[test]
    fn a_pointer_loaded_from_a_page_is_an_address_of_the_function() {
        let words = [
            0x9000_0088, // 0x1000 adrp x8, 0x11000
            0xf940_0900, // 0x1004 ldr x0, [x8, #0x10]
            0xd65f_03c0, // 0x1008 ret
        ];
        let (insns, _) = decode_all(&Aarch64, &code(&words), 0x1000);
        let space = AddressSpace::from_ranges(core::iter::once(0x1000..0x20000));
        let addresses = |pointer: u64| {
            let mut data = vec![0u8; 0x20];
            data[0x10..0x18].copy_from_slice(&pointer.to_le_bytes());
            let regions = [(0x11000, data.as_slice())];
            Aarch64.data_addresses(&code(&words), &insns, &space, &Memory::new(&regions))
        };
        assert!(addresses(0x12345).contains(&0x12345), "a pointer into the image");
        assert!(!addresses(0).contains(&0), "an unrelocated slot holds nothing");
        assert!(!addresses(0x9999_0000).contains(&0x9999_0000), "a pointer out of the image");
    }
}
