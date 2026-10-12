//! The decoder and the lifter of A64, which read one instruction at a
//! time and know nothing of the binary around it. The rules that read A64
//! code, as the pages that `adrp` forms and the tables a `switch` jumps
//! through, are in `hereticus`.

use crate as il;
use crate::arch::{DecodeError, Decoder, Insn, InsnKind, Printing, split_printed};
use crate::{
    AccessKind, Comparison, Cond, Guard, Lifted, MemoryAccess, Op, Reg, RegSet, Test, Value, Width,
};
use compact_str::CompactString;
use yaxpeax_arch::{Decoder as _, U8Reader};
use yaxpeax_arm::armv8::a64::{
    InstDecoder, Instruction, Opcode, Operand, SIMDSizeCode, ShiftStyle, SizeCode,
};

/// Every A64 instruction is 4 bytes wide.
pub const INSN_WIDTH: usize = 4;

/// A pointer is 8 bytes wide.
pub(crate) const POINTER_WIDTH: usize = 8;

/// The text of bytes the decoder cannot read.
pub(crate) const UNKNOWN_TEXT: &str = "(unknown)";

/// ARMv8-A in A64 (AArch64) mode.
#[derive(Clone, Copy, Debug, Default)]
pub struct Aarch64;

impl Aarch64 {
    /// The instruction at `offset` of `code`, which starts at `address`,
    /// and its text where `printing` asks for it.
    pub fn read(
        self,
        code: &[u8],
        offset: usize,
        address: u64,
        printing: Printing,
    ) -> Result<(Insn, String), DecodeError> {
        let bytes = code.get(offset..offset + INSN_WIDTH).ok_or(DecodeError::Truncated)?;
        let insn_address = address + offset as u64;

        let mut reader = U8Reader::new(bytes);
        let mut inst = Instruction::default();
        if InstDecoder::default().decode_into(&mut inst, &mut reader).is_err() {
            // Every instruction is 4 bytes, so stepping over an unreadable
            // one keeps the rest aligned. Its word goes in the operands, so
            // that an edit to it still shows.
            let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let insn = Insn::new(
                insn_address,
                bytes,
                InsnKind::Unknown,
                crate::arch::Opcode::Unread(crate::arch::InstructionSet::Aarch64),
            );
            return Ok((insn, printing.text(|| format!("{UNKNOWN_TEXT} {word:#010x}"))));
        }

        let kind = classify(&inst, insn_address);
        let opcode =
            crate::arch::Opcode::Aarch64(Decoded { opcode: inst.opcode, alias: alias_of(&inst) });
        let text = printing.text(|| {
            let printed = inst.to_string();
            let (name, operands) = split_printed(&printed);
            let operands = extended_register(inst.opcode, operands.to_string());
            format!("{name} {operands}")
        });
        Ok((Insn::new(insn_address, bytes, kind, opcode), text))
    }
}

impl Decoder for Aarch64 {
    /// The condition of `b.ne` is dropped, so a branch on any condition is
    /// one operation. A32 keeps it: see `TODO.md`. An alias the decoder
    /// prints names the operation it stands for: a `madd` into the zero
    /// register is `mul`, and a `subs` into it is `cmp`.
    fn operation_name(&self, insn: &Insn) -> CompactString {
        let Some(Decoded { opcode, alias }) = decoded(insn) else {
            return UNKNOWN_TEXT.into();
        };
        let name = match (opcode, alias) {
            (Opcode::B | Opcode::Bcc(_), _) => "b",
            (Opcode::BCcc(code), _) => return compact_str::format_compact!("bc{code}"),
            (Opcode::SUBS, Alias::Compare) => "cmp",
            (Opcode::ADDS, Alias::Compare) => "cmn",
            (Opcode::ANDS, Alias::Compare) => "tst",
            (_, Alias::Move) | (Opcode::MOVZ | Opcode::MOVN, _) => "mov",
            (Opcode::SUB, Alias::Negate) | (Opcode::NEG, _) => "neg",
            (Opcode::SUBS, Alias::Negate) => "negs",
            (Opcode::SBC, Alias::Negate) => "ngc",
            (Opcode::SBCS, Alias::Negate) => "ngcs",
            (Opcode::ORN, Alias::Not) | (Opcode::NOT, _) => "mvn",
            (Opcode::MADD, Alias::Multiply) | (Opcode::MUL, _) => "mul",
            (Opcode::MSUB, Alias::Multiply) => "mneg",
            (Opcode::SMADDL, Alias::Multiply) | (Opcode::SMULL, _) => "smull",
            (Opcode::SMSUBL, Alias::Multiply) => "smnegl",
            (Opcode::UMADDL, Alias::Multiply) | (Opcode::UMULL, _) => "umull",
            (Opcode::UMSUBL, Alias::Multiply) => "umnegl",
            (_, Alias::ShiftLeft) | (Opcode::LSLV, _) => "lsl",
            (_, Alias::ShiftRight) | (Opcode::LSRV, _) => "lsr",
            (_, Alias::ShiftRightArithmetic) | (Opcode::ASRV, _) => "asr",
            (Opcode::RORV, _) => "ror",
            (Opcode::SBFM, Alias::Extend(bits)) => {
                return compact_str::format_compact!("sxt{bits}");
            }
            (_, Alias::Extend(bits)) => return compact_str::format_compact!("uxt{bits}"),
            (_, Alias::BitField(form)) => {
                return compact_str::format_compact!("{opcode:?}-{form:?}").to_ascii_lowercase();
            }
            (_, Alias::Hint(number)) => return compact_str::format_compact!("hint{number}"),
            (_, Alias::Nop) => "nop",
            (_, Alias::BranchTarget) => "bti",
            // A barrier's option or a system register is an operand.
            (Opcode::DMB(_) | Opcode::DSB(_) | Opcode::SYS(_), _) => {
                let name = compact_str::format_compact!("{opcode:?}");
                return name.split('(').next().unwrap_or_default().to_ascii_lowercase().into();
            }
            _ => {
                return compact_str::format_compact!("{opcode:?}").to_ascii_lowercase();
            }
        };
        name.into()
    }

    fn decode(&self, code: &[u8], offset: usize, address: u64) -> Result<Insn, DecodeError> {
        self.read(code, offset, address, Printing::Skip).map(|(insn, _)| insn)
    }

    fn triple(&self) -> &'static str {
        "aarch64-linux-gnu"
    }

    fn instruction_width(&self) -> usize {
        INSN_WIDTH
    }

    fn pointer_width(&self) -> usize {
        POINTER_WIDTH
    }

    fn lift(&self, insn: &Insn) -> Option<Lifted> {
        Some(lift(&instruction(insn)?))
    }

    fn lift_named(&self, insn: &Insn) -> Option<il::Named> {
        let inst = instruction(insn)?;
        Some(il::Named { lifted: lift(&inst), names: names(&inst), write_back: write_back(&inst) })
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
pub fn extended_register(opcode: Opcode, operands: String) -> String {
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
pub(crate) fn classify(inst: &Instruction, address: u64) -> InsnKind {
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
pub(crate) fn is_return(opcode: Opcode) -> bool {
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
pub(crate) fn is_exception_return(opcode: Opcode) -> bool {
    matches!(opcode, Opcode::ERET | Opcode::ERETAA | Opcode::ERETAB)
}

pub(crate) fn is_indirect_call(opcode: Opcode) -> bool {
    matches!(opcode, Opcode::BLR | Opcode::BLRAA | Opcode::BLRAAZ | Opcode::BLRAB | Opcode::BLRABZ)
}

/// `br` and its signed forms. `brk` traps, and control does not come back
/// to the next instruction, so it ends the code as a jump does.
pub(crate) fn is_indirect_jump(opcode: Opcode) -> bool {
    matches!(
        opcode,
        Opcode::BR | Opcode::BRAA | Opcode::BRAAZ | Opcode::BRAB | Opcode::BRABZ | Opcode::BRK
    )
}

/// The link register, which a call writes and a return reads.
pub(crate) const LINK: Reg = Reg::General(30);

/// What an instruction does with its first operand, and with the flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Writes its first operand from the others, as `add` does.
    Compute,
    /// Reads every operand and writes none, as `br` and `ccmp` do.
    ReadOnly,
    /// Reads every operand and writes memory, as `str` does.
    Store,
    /// Loads its first operand, or its first two for a pair.
    Load {
        /// How many registers it loads.
        registers: usize,
    },
    /// An exclusive store, which writes its status to the first operand.
    StoreExclusive,
    /// Reads its first operand and loads into its second, as `swp` and
    /// `ldadd` do.
    Atomic,
}

/// Lift one decoded A64 instruction.
/// `insn` decoded again, where it is an instruction.
pub fn instruction(insn: &Insn) -> Option<Instruction> {
    if insn.kind == InsnKind::Unknown {
        return None;
    }
    let mut inst = Instruction::default();
    InstDecoder::default().decode_into(&mut inst, &mut U8Reader::new(insn.bytes())).ok()?;
    Some(inst)
}

/// The name of each operand that [`lift`] gives `inst`, in its order.
pub fn names(inst: &Instruction) -> il::Names {
    let operands = || inst.operands.iter().take_while(|operand| **operand != Operand::Nothing);
    // `add x0, x1, w2, lsl #3` reads `w2` zero extended: see
    // [`extended_register`].
    let wide_first = matches!(
        inst.operands[0],
        Operand::Register(SizeCode::X, _) | Operand::RegisterOrSP(SizeCode::X, _)
    );
    let extends = wide_first
        && matches!(inst.opcode, Opcode::ADD | Opcode::ADDS | Opcode::SUB | Opcode::SUBS);
    let mut names: il::Names = operands().map(|operand| operand_name(*operand, extends)).collect();
    alias_names(inst, &mut names);
    names
}

/// What a post-index access of `inst` adds to its base after it.
pub(crate) fn write_back(inst: &Instruction) -> Option<CompactString> {
    use compact_str::format_compact;
    inst.operands.iter().find_map(|operand| match *operand {
        Operand::RegPostIndex(_, offset) if offset < 0 => {
            Some(format_compact!("-{:#x}", offset.unsigned_abs()))
        }
        Operand::RegPostIndex(_, offset) => Some(format_compact!("{offset:#x}")),
        Operand::RegPostIndexReg(_, number) => Some(format_compact!("x{number}")),
        _ => None,
    })
}

/// Rename the operands of `inst` as the alias it prints as names them, by
/// the rules of `yaxpeax-arm` 0.4: an operand the alias leaves out has an
/// empty name, and a field it reads another way, as the `lsb` and `width`
/// of `ubfx`, names the value the alias shows.
pub(crate) fn alias_names(inst: &Instruction, names: &mut il::Names) {
    use compact_str::{ToCompactString, format_compact};
    let operands = &inst.operands;
    let immediate = |index: usize| match operands[index] {
        Operand::Immediate(value) => Some(value),
        _ => None,
    };
    let register = |index: usize| match operands[index] {
        Operand::Register(size, number) => Some((size, number)),
        _ => None,
    };
    let width = match register(0) {
        Some((SizeCode::X, _)) => 64,
        _ => 32,
    };
    let hex = |value: u32| format_compact!("#{value:#x}");
    let mut set = |index: usize, name: CompactString| {
        if let Some(slot) = names.get_mut(index) {
            *slot = name;
        }
    };
    let condition = |index: usize| match operands[index] {
        Operand::ConditionCode(code) if code < 0b1110 => Some(code),
        _ => None,
    };
    let inverted = |code: u8| Operand::ConditionCode(code ^ 1).to_compact_string();
    let is_zero = |index: usize| matches!(operands[index], Operand::Register(_, 31));
    match inst.opcode {
        Opcode::UBFM => {
            let (Some(immr), Some(imms)) = (immediate(2), immediate(3)) else { return };
            let narrow = matches!(
                (register(0), register(1)),
                (Some((SizeCode::W, _)), Some((SizeCode::W, _)))
            );
            if narrow && immr == 0 && matches!(imms, 7 | 15) {
                set(2, CompactString::default());
                set(3, CompactString::default());
            } else if imms == width - 1 {
                set(3, CompactString::default());
            } else if imms + 1 == immr {
                set(2, hex(width - imms - 1));
                set(3, CompactString::default());
            } else if imms < immr {
                set(2, hex(width - immr));
                set(3, hex(imms + 1));
            } else {
                set(3, hex(imms.wrapping_sub(immr).wrapping_add(1)));
            }
        }
        Opcode::BFM => {
            let (Some(immr), Some(imms)) = (immediate(2), immediate(3)) else { return };
            if imms < immr {
                let lsb = (immr as u8).wrapping_neg() & if width == 32 { 0x1f } else { 0x3f };
                if is_zero(1) {
                    set(1, CompactString::default());
                }
                set(2, hex(lsb.into()));
                set(3, hex(imms + 1));
            } else {
                set(3, hex(imms + 1 - immr));
            }
        }
        Opcode::SBFM => {
            let (Some(first), Some(second)) = (immediate(2), immediate(3)) else { return };
            if second == width - 1 {
                set(3, CompactString::default());
            } else if first == 0 && matches!(second, 7 | 15 | 31) {
                if let Some((_, number)) = register(1) {
                    set(1, Operand::Register(SizeCode::W, number).to_compact_string());
                }
                set(2, CompactString::default());
                set(3, CompactString::default());
            } else if second < first {
                set(2, hex(width - first));
                set(3, hex(second + 1));
            } else {
                set(3, hex(second.wrapping_sub(first).wrapping_add(1)));
            }
        }
        Opcode::EXTR => {
            if let (Some((_, left)), Some((_, right))) = (register(1), register(2))
                && left == right
            {
                set(1, CompactString::default());
            }
        }
        Opcode::CSNEG => {
            if let (Some((_, left)), Some((_, right)), Some(code)) =
                (register(1), register(2), condition(3))
                && left == right
            {
                set(1, CompactString::default());
                set(3, inverted(code));
            }
        }
        Opcode::CSINC | Opcode::CSINV => {
            if let (Some((_, left)), Some((_, right)), Some(code)) =
                (register(1), register(2), condition(3))
                && left == right
            {
                if left == 31 {
                    set(1, CompactString::default());
                }
                set(2, CompactString::default());
                set(3, inverted(code));
            }
        }
        Opcode::MADD
        | Opcode::MSUB
        | Opcode::SMADDL
        | Opcode::SMSUBL
        | Opcode::UMADDL
        | Opcode::UMSUBL
            if is_zero(3) =>
        {
            set(3, CompactString::default());
        }
        Opcode::ORR if is_zero(1) => match operands[2] {
            Operand::Immediate(0) => set(2, CompactString::default()),
            _ => set(1, CompactString::default()),
        },
        Opcode::ORR if operands[1] == operands[2] => set(2, CompactString::default()),
        Opcode::ORN if is_zero(1) => set(1, CompactString::default()),
        Opcode::ANDS | Opcode::ADDS | Opcode::SUBS if is_zero(0) => {
            set(0, CompactString::default());
        }
        Opcode::SUBS | Opcode::SUB | Opcode::SBC | Opcode::SBCS if is_zero(1) => {
            set(1, CompactString::default());
        }
        Opcode::ADD if is_add_move(operands) => set(2, CompactString::default()),
        Opcode::MOVN | Opcode::MOVZ => {
            let (Operand::ImmShift(value, shift), Some((size, _))) = (operands[1], register(0))
            else {
                return;
            };
            let value = u64::from(value) << shift;
            let value = if inst.opcode == Opcode::MOVN { !value } else { value };
            let value = if size == SizeCode::W { u64::from(value as u32) } else { value };
            set(1, format_compact!("#{value:#x}"));
        }
        Opcode::RET if operands[0] == Operand::Register(SizeCode::X, 30) => {
            set(0, CompactString::default());
        }
        Opcode::HINT => names.iter_mut().for_each(|name| *name = CompactString::default()),
        Opcode::ISB if operands[0] == Operand::Imm16(15) => set(0, CompactString::default()),
        _ => {}
    }
}

/// The name of `operand`. Where `extends`, a 32-bit register reads zero
/// extended to 64 bits.
pub(crate) fn operand_name(operand: Operand, extends: bool) -> CompactString {
    use compact_str::{ToCompactString, format_compact};
    let base = |number: u16| Operand::RegisterOrSP(SizeCode::X, number).to_compact_string();
    // A register with how it is shifted or extended, as `(w1 uxtw 2)`.
    let shifted = |name: CompactString, style: ShiftStyle, amount: u8| match amount {
        0 => format_compact!("({name} {style})"),
        _ => format_compact!("({name} {style} {amount})"),
    };
    match operand {
        Operand::RegShift(style, amount, size, number) => {
            let name = Operand::Register(size, number).to_compact_string();
            let style = match (extends, size, style) {
                (true, SizeCode::W, ShiftStyle::LSL) => ShiftStyle::UXTW,
                _ => style,
            };
            let plain = matches!(style, ShiftStyle::LSL)
                || (size == SizeCode::X && style == ShiftStyle::UXTX);
            match (plain && amount == 0, extends && size == SizeCode::W) {
                (true, true) => shifted(name, ShiftStyle::UXTW, 0),
                (true, false) => name,
                (false, _) => shifted(name, style, amount),
            }
        }
        Operand::Register(SizeCode::W, number) if extends && number != 31 => {
            shifted(operand.to_compact_string(), ShiftStyle::UXTW, 0)
        }
        Operand::RegRegOffset(number, index, size, extend, amount) => {
            let name = Operand::Register(size, index).to_compact_string();
            let index = match (extend, size, amount) {
                (ShiftStyle::LSL, _, 0) => name,
                (ShiftStyle::UXTW, SizeCode::W, 0) | (ShiftStyle::UXTX, SizeCode::X, 0) => {
                    shifted(name, extend, 0)
                }
                _ => format_compact!("({name} {extend} {amount})"),
            };
            il::memory_name(&base(number), Some(&index), None)
        }
        Operand::RegPreIndex(number, offset, _) => {
            il::memory_name(&base(number), None, Some(offset.into()))
        }
        Operand::RegPostIndex(number, _) | Operand::RegPostIndexReg(number, _) => {
            il::memory_name(&base(number), None, None)
        }
        Operand::PCOffset(distance) => il::target_name(distance),
        Operand::ImmShift(value, shift) if shift != 0 => {
            format_compact!("{} << {shift}", il::constant_name(value.into()))
        }
        // `msl` shifts ones in.
        Operand::ImmShiftMSL(value, shift) if shift != 0 => {
            format_compact!("{} msl {shift}", il::constant_name(value.into()))
        }
        _ => operand.to_compact_string(),
    }
}

/// Lift one decoded A64 instruction.
pub fn lift(inst: &Instruction) -> Lifted {
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
pub(crate) fn il_operand(operand: Operand) -> il::Operand {
    let general = |number: u16| il::Operand::Reg(Reg::General(number as u8));
    let written = |number: u16, offset: Option<i64>, update: il::Update| il::Operand::Memory {
        base: Some(if number == 31 { Reg::Stack } else { Reg::General(number as u8) }),
        offset,
        index: None,
        update,
    };
    let base = |number: u16, offset: Option<i64>| written(number, offset, il::Update::None);
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
        Operand::PCOffset(offset) => il::Operand::Target(Some(offset)),
        Operand::Immediate(value) => il::Operand::Const(value.into()),
        Operand::Imm16(value) => il::Operand::Const(value.into()),
        Operand::Imm64(value) => il::Operand::Const(value),
        Operand::ImmShift(value, shift) | Operand::ImmShiftMSL(value, shift) => {
            il::Operand::Const(u64::from(value) << shift)
        }
        Operand::RegPreIndex(number, offset, write_back) => {
            let update = if write_back { il::Update::Before } else { il::Update::None };
            written(number, Some(offset.into()), update)
        }
        Operand::RegPostIndex(number, offset) => {
            written(number, Some(offset.into()), il::Update::After)
        }
        Operand::RegPostIndexReg(number, index) => il::Operand::Memory {
            base: Some(if number == 31 { Reg::Stack } else { Reg::General(number as u8) }),
            offset: None,
            index: Some((Reg::General(index as u8), 0)),
            update: il::Update::After,
        },
        Operand::RegRegOffset(number, ..) => base(number, None),
        _ => il::Operand::Other,
    }
}

/// What an A64 instruction computes. An alias the decoder prints in place
/// of its instruction, as `cmp` for a `subs` into the zero register, or
/// `lsl` for a `ubfm`, computes what the alias names.
pub(crate) fn op_of(inst: &Instruction, alias: Alias, role: Role, operands: &[Operand]) -> Op {
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
            Alias::Extend(_) => Op::Extend,
            Alias::None
            | Alias::BitField(_)
            | Alias::Hint(_)
            | Alias::AtomicStore
            | Alias::Nop
            | Alias::BranchTarget => plain_op(inst.opcode),
        },
    }
}

/// What an A64 instruction computes, where it prints as no alias of other
/// work.
pub(crate) fn plain_op(opcode: Opcode) -> Op {
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
    /// The operation the word encodes.
    pub opcode: Opcode,
    /// The alias `yaxpeax-arm` prints it as, where it prints one.
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
    /// `uxtb`, `sxtw` and the like, which are a `ubfm` or an `sbfm`, from
    /// a value of this many bits.
    Extend(u8),
    /// `ubfx`, `sbfiz`, `bfi`, `bfc` and the like: one form of a `ubfm`,
    /// an `sbfm` or a `bfm` that the others are not.
    BitField(BitFieldForm),
    /// A `hint` by its number, other than `nop` and `bti`, as `yield`,
    /// `wfe` and `sev` are.
    Hint(u16),
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

/// What a bit field instruction does with its field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitFieldForm {
    /// Copies a field to the low bits, as `ubfx` and `bfxil` do.
    Extract,
    /// Copies the low bits to a field, as `ubfiz` and `bfi` do.
    Insert,
    /// Clears a field, as `bfc` does.
    Clear,
}

/// The form of a bit field instruction from its `immr` and `imms`.
pub(crate) fn bit_field_form(immr: u32, imms: u32) -> BitFieldForm {
    if imms < immr { BitFieldForm::Insert } else { BitFieldForm::Extract }
}

/// The alias `inst` prints as, by the rules of `yaxpeax-arm` 0.4.
pub(crate) fn alias_of(inst: &Instruction) -> Alias {
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
        Opcode::BFM if zero(1) => Alias::BitField(BitFieldForm::Clear),
        Opcode::BFM => bit_field(operands)
            .map_or(Alias::None, |(_, immr, imms)| Alias::BitField(bit_field_form(immr, imms))),
        Opcode::HINT => match hint_number(operands) {
            Some(0) => Alias::Nop,
            Some(32 | 34 | 36 | 38) => Alias::BranchTarget,
            Some(number) => Alias::Hint(number),
            None => Alias::None,
        },
        _ if is_atomic_store(inst) => Alias::AtomicStore,
        _ => Alias::None,
    }
}

/// Register 31 where it names the zero register, not the stack pointer.
pub(crate) fn is_zero_register(operand: Operand) -> bool {
    matches!(operand, Operand::Register(_, 31))
}

/// The number of a `hint`, from its two fields.
pub(crate) fn hint_number(operands: &[Operand]) -> Option<u16> {
    match (operands[0], operands[1]) {
        (Operand::ControlReg(crm), Operand::Immediate(op2)) => Some(crm << 3 | op2 as u16),
        _ => None,
    }
}

/// An `orr` that prints as `mov`.
pub(crate) fn is_orr_move(operands: &[Operand]) -> bool {
    match (operands[1], operands[2]) {
        (Operand::Register(_, 31), Operand::RegShift(style, amount, ..)) => {
            style == ShiftStyle::LSL && amount == 0
        }
        (Operand::Register(_, 31), _) => true,
        (first, second) => first == second,
    }
}

/// An `add` that prints as `mov`.
pub(crate) fn is_add_move(operands: &[Operand]) -> bool {
    let stack = |operand| matches!(operand, Operand::RegisterOrSP(_, 31));
    operands[2] == Operand::Immediate(0) && (stack(operands[0]) || stack(operands[1]))
}

/// The width of the register a bit field instruction writes, and its
/// `immr` and `imms` fields.
pub(crate) fn bit_field(operands: &[Operand]) -> Option<(u32, u32, u32)> {
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
pub(crate) fn unsigned_bit_field_alias(operands: &[Operand]) -> Alias {
    let is_w = matches!(operands[1], Operand::Register(SizeCode::W, _));
    match bit_field(operands) {
        Some((32, 0, imms @ (7 | 15))) if is_w => Alias::Extend(imms as u8 + 1),
        Some((size, _, imms)) if imms == size - 1 => Alias::ShiftRight,
        Some((_, immr, imms)) if imms + 1 == immr => Alias::ShiftLeft,
        Some((_, immr, imms)) => Alias::BitField(bit_field_form(immr, imms)),
        None => Alias::None,
    }
}

/// `asr`, `sxtb`, `sxth` and `sxtw` are aliases of `sbfm`. `sbfx` and
/// `sbfiz` are too, but for the same work.
pub(crate) fn signed_bit_field_alias(operands: &[Operand]) -> Alias {
    match bit_field(operands) {
        Some((size, _, imms)) if imms == size - 1 => Alias::ShiftRightArithmetic,
        Some((_, 0, imms @ (7 | 15 | 31))) => Alias::Extend(imms as u8 + 1),
        Some((_, immr, imms)) => Alias::BitField(bit_field_form(immr, imms)),
        None => Alias::None,
    }
}

/// What an A64 floating point instruction computes, or `None` for one that
/// is not floating point. A conversion to an integer names its rounding:
/// `fcvtms` rounds down, as `floor` does.
pub(crate) fn float_op(opcode: Opcode) -> Option<Op> {
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
pub(crate) fn is_exclusive_load(opcode: Opcode) -> bool {
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
pub(crate) fn is_atomic_store(inst: &Instruction) -> bool {
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

/// What an instruction of `opcode`, printed as `alias`, does with its operands.
pub fn role_of(opcode: Opcode, alias: Alias) -> Role {
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
pub(crate) fn reads_destination(opcode: Opcode) -> bool {
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

pub(crate) fn reads_flags(opcode: Opcode) -> bool {
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

pub(crate) fn writes_flags(opcode: Opcode) -> bool {
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
pub(crate) fn value_registers(operand: Operand) -> RegSet {
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
pub(crate) fn address_registers(operand: Operand, reads: &mut RegSet, writes: &mut RegSet) {
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

pub(crate) fn is_memory(operand: &Operand) -> bool {
    matches!(
        operand,
        Operand::RegPreIndex(..)
            | Operand::RegPostIndex(..)
            | Operand::RegPostIndexReg(..)
            | Operand::RegRegOffset(..)
    )
}

pub(crate) fn memory_access(
    opcode: Opcode,
    role: Role,
    operands: &[Operand],
) -> Option<MemoryAccess> {
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
pub(crate) fn access_width(opcode: Opcode, role: Role, operands: &[Operand]) -> Option<Width> {
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

pub(crate) fn width_of(size: SizeCode) -> Width {
    match size {
        SizeCode::W => Width::Bits32,
        SizeCode::X => Width::Bits64,
    }
}

/// What an operand gives as a value, at `width`.
pub(crate) fn value_of(operand: Operand, width: Width) -> Value {
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
pub(crate) fn operation_width(operands: &[Operand]) -> Width {
    operands
        .iter()
        .find_map(|operand| match operand {
            Operand::Register(size, _) | Operand::RegisterOrSP(size, _) => Some(width_of(*size)),
            _ => None,
        })
        .unwrap_or(Width::Bits64)
}

pub(crate) fn test_of(inst: &Instruction, alias: Alias, operands: &[Operand]) -> Option<Test> {
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
pub fn decoded(insn: &Insn) -> Option<Decoded> {
    match insn.opcode {
        crate::arch::Opcode::Aarch64(decoded) => Some(decoded),
        _ => None,
    }
}
