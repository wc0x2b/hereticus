//! The decoder and the lifter of MIPS32, which read one word at a time and
//! know nothing of the binary around it. The rules that read MIPS code, as
//! the addresses it forms through `gp` and the tables a `switch` jumps
//! through, are in `hereticus-recovery`, and the rules the matching reads
//! in `hereticus-arch`.

use crate as il;
use crate::arch::{DecodeError, Decoder, Insn, InsnKind, Printing, split_printed};
use compact_str::CompactString;
use rabbitizer::registers_meta::Register as _;
use rabbitizer::{
    Instruction, InstructionDisplayFlags, InstructionFlags, IsaVersion, Vram, opcodes::Opcode,
    operands::ValuedOperand,
};

/// Every MIPS32 instruction is 4 bytes wide.
pub const INSN_WIDTH: usize = 4;

/// What [`Insn::opcode`] holds for MIPS32 and MIPS16e.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decoded {
    /// A word `rabbitizer` reads, by its opcode, whose name it prints. A
    /// pseudo-instruction, such as `nop` or `beqz`, has an opcode of its
    /// own.
    Rabbitizer(Opcode),
    /// A MIPS32 or Release 2 word [`crate::arch::mips32`] reads.
    Mips32(crate::arch::mips32::Op),
    /// A MIPS16e instruction with no MIPS32 twin.
    Mips16(crate::arch::mips16::Op),
}

/// What the decoder read for `insn`, where it read MIPS.
pub fn decoded(insn: &Insn) -> Option<Decoded> {
    match insn.opcode {
        crate::arch::Opcode::Mips(decoded, _) | crate::arch::Opcode::Mips16(decoded, _) => {
            Some(decoded)
        }
        _ => None,
    }
}

/// `insn` lifted in the instruction set and the byte order that decoded
/// it, MIPS32 or MIPS16e. A rule both read can take either.
pub fn lifted(insn: &Insn) -> Option<il::Lifted> {
    match insn.opcode {
        crate::arch::Opcode::Mips(_, order) => Mips32::of(order).lift(insn),
        crate::arch::Opcode::Mips16(_, order) => {
            crate::arch::mips16::Mips16::of(Mips32::of(order)).lift(insn)
        }
        _ => None,
    }
}

/// The register `operand` names. The `zero` register names none.
pub fn register(operand: &il::Operand) -> Option<il::Reg> {
    match operand {
        il::Operand::Reg(reg) => Some(*reg),
        _ => None,
    }
}

/// The value of a constant operand. A negative one is in two's complement.
pub fn constant(operand: &il::Operand) -> Option<u64> {
    match operand {
        il::Operand::Const(value) => Some(*value),
        _ => None,
    }
}

/// The base and offset of an access `offset(base)`. A base of `zero` is
/// none.
pub fn access(operand: &il::Operand) -> Option<(Option<il::Reg>, u64)> {
    match operand {
        il::Operand::Memory { base, offset: Some(offset), .. } => Some((*base, *offset as u64)),
        _ => None,
    }
}

/// The opcode `rabbitizer` read for `insn`, where it read it.
pub fn rabbitizer_opcode(insn: &Insn) -> Option<Opcode> {
    match decoded(insn)? {
        Decoded::Rabbitizer(opcode) => Some(opcode),
        _ => None,
    }
}

/// Whether `rabbitizer` read `insn` as `opcode`.
pub fn is(insn: &Insn, opcode: Opcode) -> bool {
    decoded(insn) == Some(Decoded::Rabbitizer(opcode))
}

/// The text of bytes the decoder cannot read.
pub(crate) const UNKNOWN_TEXT: &str = "(unknown)";

/// The instruction set this decoder reads.
///
/// MIPS II covers most of what a compiler emits for a 32-bit target. The
/// MIPS32 and Release 2 words it refuses are read by [`crate::arch::mips32`]
/// instead, which leaves every word MIPS II reads as it was.
pub(crate) const ISA: IsaVersion = IsaVersion::MIPS_II;

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
    pub fn read_word(self, bytes: [u8; INSN_WIDTH]) -> u32 {
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

    /// The decoder for `order`.
    pub fn of(order: ByteOrder) -> Self {
        Self { order }
    }

    /// The byte order this decoder reads.
    pub fn order(self) -> ByteOrder {
        self.order
    }

    /// The instruction at `offset` of `code`, which starts at `address`,
    /// and its text where `printing` asks for it.
    pub fn read(
        self,
        code: &[u8],
        offset: usize,
        address: u64,
        printing: Printing,
    ) -> Result<(Insn, String), DecodeError> {
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
            // `rabbitizer` stops at MIPS IV, so a MIPS32 word it refuses may
            // still be one this crate reads.
            if let Some(word32) = crate::arch::mips32::decode(raw) {
                let kind = match crate::arch::mips32::branch_distance(raw) {
                    Some(distance) => {
                        InsnKind::Branch { target: insn_address.checked_add_signed(distance) }
                    }
                    None => word32.kind,
                };
                let insn = Insn::new(
                    insn_address,
                    word,
                    kind,
                    crate::arch::Opcode::Mips(Decoded::Mips32(word32.op), self.order),
                );
                let text = printing.text(|| format!("{} {}", word32.op.name(), word32.operands));
                return Ok((insn, text));
            }

            // Stepping over an unreadable word keeps everything after it
            // aligned, because every instruction is the same width. The raw
            // word goes in the operand field so that two unreadable words
            // still compare as different.
            let insn = Insn::new(
                insn_address,
                word,
                InsnKind::Unknown,
                crate::arch::Opcode::Unread(crate::arch::InstructionSet::Mips(self.order)),
            );
            return Ok((insn, printing.text(|| format!("{UNKNOWN_TEXT} {raw:#010x}"))));
        };

        let kind = classify(&inst);
        let text = printing.text(|| {
            let printed =
                inst.display::<&str>(&InstructionDisplayFlags::new_gnu_as(), None, 0).to_string();
            let (name, operands) = split_printed(&printed);
            // `rabbitizer` writes registers as `$a0`; the rest of `hereticus`
            // reads them as `a0`.
            let mut operands = operands.replace('$', "");

            // `rabbitizer` names a jump target as a label, such as
            // `func_80001000`, and a branch target as an expression, such as
            // `. + 4 + (0x7 << 2)`. Every decoder prints a resolved target in
            // the `$` form instead, which is how the rest of `hereticus` knows
            // it moves with the code rather than coming from the source.
            //
            // A branch is written from its offset rather than its target,
            // which cannot be resolved when it would lie below address zero.
            if let Some(distance) = target_distance(&inst, kind, insn_address) {
                operands = with_target(&operands, distance);
            }
            format!("{name} {operands}")
        });

        let opcode = crate::arch::Opcode::Mips(Decoded::Rabbitizer(inst.opcode()), self.order);
        Ok((Insn::new(insn_address, word, kind, opcode), text))
    }

    /// The bytes of `word`, stored in this byte order.
    pub fn word_bytes(self, word: u32) -> [u8; INSN_WIDTH] {
        match self.order {
            ByteOrder::Little => word.to_le_bytes(),
            ByteOrder::Big => word.to_be_bytes(),
        }
    }

    /// Assemble one stored halfword, as MIPS16e code is made of.
    pub fn read_halfword(self, bytes: [u8; 2]) -> u16 {
        match self.order {
            ByteOrder::Little => u16::from_le_bytes(bytes),
            ByteOrder::Big => u16::from_be_bytes(bytes),
        }
    }

    /// Report whether this is the big-endian decoder.
    pub fn is_big(self) -> bool {
        self.order == ByteOrder::Big
    }
}

impl Decoder for Mips32 {
    /// MIPS puts no condition or flag-setting suffix on an operation: the
    /// compare is part of it, as in `beq` against `bne`, which differ in
    /// the test they apply and so stay apart.
    ///
    /// The exception is the unconditional jump, which MIPS spells two ways.
    /// `j` holds an absolute address and `b` a distance from here, and a
    /// compiler picks between them on grounds that have nothing to do with
    /// the source: a PIC build must stay position independent, so it emits
    /// `b` where the same code built without PIC emits `j`. Measured on the
    /// PIC corpus the two account for six jumps each way, and they normalize
    /// alike in every other respect, so only the name kept them apart.
    ///
    /// A word that [`crate::arch::mips32`] or [`crate::arch::mips16`] reads takes the
    /// name `rabbitizer` gives the same instruction.
    fn operation_name(&self, insn: &Insn) -> CompactString {
        match decoded(insn) {
            Some(Decoded::Rabbitizer(Opcode::core_j | Opcode::core_b)) => "jump".into(),
            Some(Decoded::Rabbitizer(opcode)) => {
                let name = compact_str::format_compact!("{opcode:?}");
                name.strip_prefix("core_").unwrap_or(&name).into()
            }
            Some(Decoded::Mips32(op)) => op.operation_name(),
            Some(Decoded::Mips16(op)) => op.name().into(),
            None => UNKNOWN_TEXT.into(),
        }
    }

    fn decode(&self, code: &[u8], offset: usize, address: u64) -> Result<Insn, DecodeError> {
        self.read(code, offset, address, Printing::Skip).map(|(insn, _)| insn)
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

    /// MIPS runs the instruction after a branch whether or not the branch is
    /// taken, so that instruction belongs to the branch. An exception return
    /// is the exception: it leaves at once.
    fn delay_slots(&self, insn: &Insn) -> usize {
        match decoded(insn) {
            Some(Decoded::Mips32(op)) if crate::arch::mips32::is_exception_return(op) => 0,
            _ => 1,
        }
    }

    fn pointer_width(&self) -> usize {
        INSN_WIDTH
    }

    fn read_pointer(&self, bytes: &[u8]) -> u64 {
        u64::from(self.order.read_word([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// What `rabbitizer` reads is lifted from its decoded fields, and the
    /// MIPS32 words that [`crate::arch::mips32`] reads in its place by that
    /// module, where they compute a value.
    fn lift(&self, insn: &Insn) -> Option<il::Lifted> {
        let word = insn.bytes();
        if insn.kind == InsnKind::Unknown {
            return None;
        }
        let raw = self.order.read_word(word.try_into().ok()?);
        let flags = InstructionFlags::new(ISA);
        match Instruction::new_checked(raw, Vram::new(insn.address as u32), flags) {
            Some(inst) => Some(lift(&inst)),
            None => crate::arch::mips32::lift(raw),
        }
    }

    fn lift_named(&self, insn: &Insn) -> Option<il::Named> {
        let word = insn.bytes();
        if insn.kind == InsnKind::Unknown {
            return None;
        }
        let raw = self.order.read_word(word.try_into().ok()?);
        let flags = InstructionFlags::new(ISA);
        match Instruction::new_checked(raw, Vram::new(insn.address as u32), flags) {
            Some(inst) => {
                let names = names(&inst, insn.kind, insn.address);
                Some(il::Named { lifted: lift(&inst), names, write_back: None })
            }
            None => crate::arch::mips32::lift_named(raw),
        }
    }
}

/// Replace the last operand, which names the target, with the `$` form.
///
/// `distance` runs from the instruction to its target, which is how the ARM
/// decoder writes a target too.
pub(crate) fn with_target(operands: &str, distance: i64) -> String {
    let written = if distance < 0 {
        format!("$-{:#x}", distance.unsigned_abs())
    } else {
        format!("$+{distance:#x}")
    };
    match operands.rsplit_once(',') {
        Some((head, _)) => format!("{head}, {written}"),
        None => written,
    }
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
pub(crate) fn classify(inst: &Instruction) -> InsnKind {
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

        // A call on a condition. Compilers call with `bal`, which always
        // links, and never with these, but data decodes as them: a word of
        // `.rodata` in zlib for little-endian MIPS read as `bltzal t0` into
        // the middle of `gzrewind`. They still call, but name no target, so
        // they cannot start a function.
        Opcode::core_bltzal | Opcode::core_bgezal | Opcode::core_bltzall | Opcode::core_bgezall => {
            InsnKind::Call { target: None }
        }
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
pub(crate) fn jump_target(inst: &Instruction) -> Option<u64> {
    inst.get_instr_index_as_vram().map(|vram| u64::from(vram.inner()))
}

/// Resolve the target of a branch, which is relative to the delay slot.
pub(crate) fn branch_target(inst: &Instruction) -> Option<u64> {
    let offset = inst.get_branch_offset()?;
    let address = i64::from(inst.vram().inner());
    u64::try_from(address + i64::from(offset.inner())).ok()
}

/// Where the IL keeps `hi` and `lo`, after the 32 general registers.
pub const HI: il::Reg = il::Reg::General(32);

/// Where the IL keeps `lo`: see [`HI`].
pub const LO: il::Reg = il::Reg::General(33);

/// The return address register, which a call writes.
pub(crate) const RA: u8 = 31;

/// Every MIPS32 general register is 32 bits wide.
pub(crate) const WIDTH: il::Width = il::Width::Bits32;

/// Lift one instruction `rabbitizer` decoded, from what its opcode says it
/// reads, writes and accesses.
pub fn lift(inst: &Instruction) -> il::Lifted {
    let opcode = inst.opcode();
    let field = inst.field();
    let general = |reg: Option<rabbitizer::registers::Gpr>| {
        reg.map(|reg| reg.as_index())
            .filter(|&index| index != 0)
            .map(|index| il::Reg::General(index as u8))
    };
    let float = |reg: Option<rabbitizer::registers::Cop1>| {
        reg.map(|reg| il::Reg::Vector(reg.as_index() as u8))
    };

    let mut reads = il::RegSet::EMPTY;
    let mut writes = il::RegSet::EMPTY;
    let note = |set: &mut il::RegSet, wanted: bool, reg: Option<il::Reg>| {
        if let (true, Some(reg)) = (wanted, reg) {
            set.insert(reg);
        }
    };
    note(&mut reads, opcode.reads_rs(), general(field.rs()));
    note(&mut reads, opcode.reads_rt(), general(field.rt()));
    note(&mut reads, opcode.reads_rd(), general(field.rd()));
    note(&mut reads, opcode.reads_fs(), float(field.fs()));
    note(&mut reads, opcode.reads_ft(), float(field.ft()));
    note(&mut reads, opcode.reads_fd(), float(field.fd()));
    note(&mut reads, opcode.reads_hi(), Some(HI));
    note(&mut reads, opcode.reads_lo(), Some(LO));
    note(&mut writes, opcode.modifies_rs(), general(field.rs()));
    note(&mut writes, opcode.modifies_rt(), general(field.rt()));
    note(&mut writes, opcode.modifies_rd(), general(field.rd()));
    note(&mut writes, opcode.modifies_fs(), float(field.fs()));
    note(&mut writes, opcode.modifies_ft(), float(field.ft()));
    note(&mut writes, opcode.modifies_fd(), float(field.fd()));
    note(&mut writes, opcode.modifies_hi(), Some(HI));
    note(&mut writes, opcode.modifies_lo(), Some(LO));
    note(&mut writes, opcode.does_link(), Some(il::Reg::General(RA)));

    let kind = match (opcode.does_load(), opcode.does_store()) {
        (true, true) => Some(il::AccessKind::LoadStore),
        (true, false) => Some(il::AccessKind::Load),
        (false, true) => Some(il::AccessKind::Store),
        (false, false) => None,
    };
    let memory =
        kind.map(|kind| il::MemoryAccess { kind, width: access_width(opcode.access_type()) });

    let op = op_of(inst, kind);
    let operands = inst.valued_operands_iter().map(il_operand).collect();
    il::Lifted { op, reads, writes, memory, test: test_of(inst), operands }
}

/// How far the target of `inst`, which moves control as `kind` from
/// `address`, lies from it.
///
/// A branch is read from its offset rather than its target, which cannot
/// be resolved when it would lie below address zero.
pub(crate) fn target_distance(inst: &Instruction, kind: InsnKind, address: u64) -> Option<i64> {
    if let Some(offset) = inst.get_branch_offset() {
        return Some(i64::from(offset.inner()));
    }
    match kind {
        InsnKind::Call { target: Some(target) } | InsnKind::Jump { target: Some(target) } => {
            Some(target.wrapping_sub(address) as i64)
        }
        _ => None,
    }
}

/// The name of each operand that [`lift`] gives `inst`, in its order, as
/// `rabbitizer` writes it with no `$`. `inst` moves control as `kind`, from
/// `address`.
pub fn names(inst: &Instruction, kind: InsnKind, address: u64) -> il::Names {
    use compact_str::{CompactString, format_compact};
    let flags = InstructionDisplayFlags::new_gnu_as();
    let shown = |operand: ValuedOperand| -> CompactString {
        format_compact!("{}", operand.display::<&str>(inst, &flags, None)).replace('$', "").into()
    };
    inst.valued_operands_iter()
        .map(|operand| match operand {
            ValuedOperand::core_label(_) | ValuedOperand::core_branch_target_label(_) => {
                match target_distance(inst, kind, address) {
                    Some(distance) => il::target_name(distance),
                    None => shown(operand),
                }
            }
            // `offset(base)`, as `[base + offset]`.
            ValuedOperand::core_imm_rs(offset, base) => {
                let base = shown(ValuedOperand::core_rs(base));
                match offset {
                    0 => format_compact!("[{base}]"),
                    offset if offset < 0 => {
                        format_compact!("[{base} + -0x{:X}]", i32::from(offset).unsigned_abs())
                    }
                    offset => format_compact!("[{base} + 0x{offset:X}]"),
                }
            }
            // `jalr` and the GNU `div` print another register before the
            // one they read.
            ValuedOperand::core_maybe_rd_rs(_, reg)
            | ValuedOperand::core_maybe_zero_rs((), reg) => shown(ValuedOperand::core_rs(reg)),
            operand => shown(operand),
        })
        .collect()
}

/// An operand as the IL names it.
pub(crate) fn il_operand(operand: ValuedOperand) -> il::Operand {
    let general = |reg: rabbitizer::registers::Gpr| match reg.as_index() {
        0 => il::Operand::Zero,
        index => il::Operand::Reg(il::Reg::General(index as u8)),
    };
    let float =
        |reg: rabbitizer::registers::Cop1| il::Operand::Reg(il::Reg::Vector(reg.as_index() as u8));
    match operand {
        ValuedOperand::core_rs(reg) | ValuedOperand::core_rt(reg) | ValuedOperand::core_rd(reg) => {
            general(reg)
        }
        ValuedOperand::core_maybe_rd_rs(_, reg) | ValuedOperand::core_maybe_zero_rs((), reg) => {
            general(reg)
        }
        ValuedOperand::core_zero() => il::Operand::Zero,
        ValuedOperand::core_fs(reg) | ValuedOperand::core_ft(reg) | ValuedOperand::core_fd(reg) => {
            float(reg)
        }
        ValuedOperand::core_sa(value) => il::Operand::Const(value.into()),
        ValuedOperand::core_imm_i16(value) => il::Operand::Const(i64::from(value) as u64),
        ValuedOperand::core_imm_u16(value) => il::Operand::Const(value.into()),
        ValuedOperand::core_label(_) | ValuedOperand::core_branch_target_label(_) => {
            il::Operand::Target(None)
        }
        ValuedOperand::core_imm_rs(offset, base) => il::Operand::memory(
            Some(base.as_index())
                .filter(|&index| index != 0)
                .map(|index| il::Reg::General(index as u8)),
            Some(offset.into()),
        ),
        _ => il::Operand::Other,
    }
}

/// What a MIPS instruction computes. A pseudo-instruction, such as `not`
/// or `beqz`, has an opcode of its own.
pub(crate) fn op_of(inst: &Instruction, access: Option<il::AccessKind>) -> il::Op {
    use il::Op;
    match access {
        Some(il::AccessKind::Load) => return Op::Load,
        Some(il::AccessKind::Store) => return Op::Store,
        Some(il::AccessKind::LoadStore) => return Op::Atomic,
        None => {}
    }
    if inst.is_return() {
        return Op::Return;
    }
    if inst.is_function_call() {
        return Op::Call;
    }
    if inst.opcode().is_branch() || inst.opcode().is_branch_likely() {
        return if inst.is_unconditional_branch() { Op::Jump } else { Op::Branch };
    }
    match inst.opcode() {
        Opcode::core_j | Opcode::core_jr => Op::Jump,
        Opcode::core_mfhi
        | Opcode::core_mflo
        | Opcode::core_mthi
        | Opcode::core_mtlo
        | Opcode::core_mfc1
        | Opcode::core_mtc1 => Op::Move,
        Opcode::core_lui => Op::Address,
        Opcode::core_add | Opcode::core_addi | Opcode::core_addu | Opcode::core_addiu => Op::Add,
        Opcode::core_sub | Opcode::core_subu => Op::Subtract,
        Opcode::core_neg | Opcode::core_negu => Op::Negate,
        Opcode::core_mult | Opcode::core_multu => Op::Multiply,
        Opcode::core_div | Opcode::core_divu => Op::Divide,
        Opcode::core_and | Opcode::core_andi => Op::And,
        Opcode::core_or | Opcode::core_ori => Op::Or,
        Opcode::core_xor | Opcode::core_xori => Op::Xor,
        Opcode::core_nor | Opcode::core_not => Op::Not,
        Opcode::core_sll | Opcode::core_sllv => Op::ShiftLeft,
        Opcode::core_srl | Opcode::core_srlv => Op::ShiftRight,
        Opcode::core_sra | Opcode::core_srav => Op::ShiftRightArithmetic,
        Opcode::core_slt | Opcode::core_sltu | Opcode::core_slti | Opcode::core_sltiu => {
            Op::Compare
        }
        Opcode::core_nop
        | Opcode::core_syscall
        | Opcode::core_break
        | Opcode::core_sync
        | Opcode::core_cache
        | Opcode::core_mfc0
        | Opcode::core_mtc0
        | Opcode::core_teq
        | Opcode::core_tne
        | Opcode::core_tge
        | Opcode::core_tgeu
        | Opcode::core_tlt
        | Opcode::core_tltu => Op::System,
        opcode => float_op(opcode).unwrap_or(Op::Other),
    }
}

/// What a MIPS floating point instruction computes, or `None` for one that
/// is not floating point. A conversion to an integer names its rounding:
/// `floor.w.d` rounds down.
pub fn float_op(opcode: Opcode) -> Option<il::Op> {
    use il::Op;
    Some(match opcode {
        Opcode::core_add_s | Opcode::core_add_d => Op::FloatAdd,
        Opcode::core_sub_s | Opcode::core_sub_d => Op::FloatSubtract,
        Opcode::core_mul_s | Opcode::core_mul_d => Op::FloatMultiply,
        Opcode::core_div_s | Opcode::core_div_d => Op::FloatDivide,
        Opcode::core_neg_s | Opcode::core_neg_d | Opcode::core_abs_s | Opcode::core_abs_d => {
            Op::FloatSign
        }
        Opcode::core_sqrt_s | Opcode::core_sqrt_d => Op::FloatSquareRoot,
        Opcode::core_mov_s | Opcode::core_mov_d => Op::Move,
        Opcode::core_floor_w_s | Opcode::core_floor_w_d => Op::FloatRoundDown,
        Opcode::core_ceil_w_s | Opcode::core_ceil_w_d => Op::FloatRoundUp,
        Opcode::core_round_w_s | Opcode::core_round_w_d => Op::FloatRoundNearest,
        Opcode::core_trunc_w_s | Opcode::core_trunc_w_d => Op::FloatRoundTowardZero,
        Opcode::core_cvt_d_s
        | Opcode::core_cvt_w_s
        | Opcode::core_cvt_s_d
        | Opcode::core_cvt_w_d
        | Opcode::core_cvt_s_w
        | Opcode::core_cvt_d_w => Op::FloatConvert,
        Opcode::core_c_f_s
        | Opcode::core_c_un_s
        | Opcode::core_c_eq_s
        | Opcode::core_c_ueq_s
        | Opcode::core_c_olt_s
        | Opcode::core_c_ult_s
        | Opcode::core_c_ole_s
        | Opcode::core_c_ule_s
        | Opcode::core_c_sf_s
        | Opcode::core_c_ngle_s
        | Opcode::core_c_seq_s
        | Opcode::core_c_ngl_s
        | Opcode::core_c_lt_s
        | Opcode::core_c_nge_s
        | Opcode::core_c_le_s
        | Opcode::core_c_ngt_s
        | Opcode::core_c_f_d
        | Opcode::core_c_un_d
        | Opcode::core_c_eq_d
        | Opcode::core_c_ueq_d
        | Opcode::core_c_olt_d
        | Opcode::core_c_ult_d
        | Opcode::core_c_ole_d
        | Opcode::core_c_ule_d
        | Opcode::core_c_df_d
        | Opcode::core_c_ngle_d
        | Opcode::core_c_seq_d
        | Opcode::core_c_ngl_d
        | Opcode::core_c_lt_d
        | Opcode::core_c_nge_d
        | Opcode::core_c_le_d
        | Opcode::core_c_ngt_d => Op::Float,
        _ => return None,
    })
}

pub(crate) fn access_width(
    access: Option<rabbitizer::access_type::AccessType>,
) -> Option<il::Width> {
    use rabbitizer::access_type::AccessType;
    match access? {
        AccessType::BYTE => Some(il::Width::Bits8),
        AccessType::SHORT => Some(il::Width::Bits16),
        AccessType::WORD
        | AccessType::FLOAT
        | AccessType::WORD_COP2
        | AccessType::UNALIGNED_WORD_LEFT
        | AccessType::UNALIGNED_WORD_RIGHT => Some(il::Width::Bits32),
        AccessType::DOUBLEFLOAT | AccessType::DOUBLEWORD_COP2 => Some(il::Width::Bits64),
        _ => None,
    }
}

/// What a general register operand gives as a value: the zero register
/// gives 0.
pub(crate) fn register_value(reg: Option<rabbitizer::registers::Gpr>) -> il::Value {
    match reg.map(|reg| reg.as_index()) {
        Some(0) => il::Value::Const(0),
        Some(index) => il::Value::Reg(il::Reg::General(index as u8)),
        None => il::Value::Other,
    }
}

pub(crate) fn test_of(inst: &Instruction) -> Option<il::Test> {
    let field = inst.field();
    let (rs, rt) = (register_value(field.rs()), register_value(field.rt()));
    let zero = il::Value::Const(0);
    let guard =
        |cond, left, right| Some(il::Test::Guard(il::Guard { cond, left, right, width: WIDTH }));
    // `slti` and `sltiu` both extend the sign of their constant; `sltiu`
    // then compares without sign.
    let immediate =
        field.imm_i16().map(|value| il::Value::Const(i64::from(value) as u64 & WIDTH.mask()));
    let set = |cond, right| {
        let dest =
            field.rd().or(field.rt()).map(|reg| reg.as_index()).filter(|&index| index != 0)?;
        Some(il::Test::SetOnCompare {
            dest: il::Reg::General(dest as u8),
            cond,
            left: rs,
            right,
            width: WIDTH,
        })
    };
    match inst.opcode() {
        // `b` is `beq zero, zero`, which always branches.
        Opcode::core_beq | Opcode::core_beql if rs == zero && rt == zero => None,
        Opcode::core_beq | Opcode::core_beql => guard(il::Cond::Equal, rs, rt),
        Opcode::core_bne | Opcode::core_bnel => guard(il::Cond::NotEqual, rs, rt),
        Opcode::core_beqz => guard(il::Cond::Equal, rs, zero),
        Opcode::core_bnez => guard(il::Cond::NotEqual, rs, zero),
        Opcode::core_blez | Opcode::core_blezl => guard(il::Cond::SignedLessOrEqual, rs, zero),
        Opcode::core_bgtz | Opcode::core_bgtzl => guard(il::Cond::SignedGreater, rs, zero),
        Opcode::core_bltz | Opcode::core_bltzl => guard(il::Cond::SignedLess, rs, zero),
        Opcode::core_bgez | Opcode::core_bgezl => guard(il::Cond::SignedGreaterOrEqual, rs, zero),
        Opcode::core_slt => set(il::Cond::SignedLess, rt),
        Opcode::core_sltu => set(il::Cond::UnsignedLess, rt),
        Opcode::core_slti => set(il::Cond::SignedLess, immediate?),
        Opcode::core_sltiu => set(il::Cond::UnsignedLess, immediate?),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::DecodeError;
    use compact_str::CompactString;

    /// Decode one instruction from a little-endian word at address 0.
    fn decode_one(word: u32) -> Insn {
        Mips32::LITTLE.decode(&word.to_le_bytes(), 0, 0).expect("bytes must decode")
    }

    /// Encodings from `llvm-mc --triple=mips --show-encoding`, as words.
    mod words {
        pub const BEQ_A0_A1: u32 = 0x1085_0002;
        pub const BEQZ_A0: u32 = 0x1080_0002;
        pub const BNEZ_A0: u32 = 0x1480_0002;
        pub const BLEZ_A0: u32 = 0x1880_0002;
        pub const BGTZ_A0: u32 = 0x1c80_0002;
        pub const BLTZ_A0: u32 = 0x0480_0002;
        pub const BGEZ_A0: u32 = 0x0481_0002;
        pub const SLT_T0_A0_A1: u32 = 0x0085_402a;
        pub const SLTI_T0_A0_5: u32 = 0x2888_0005;
        pub const SLTIU_T0_A0_MINUS_1: u32 = 0x2c88_ffff;
        pub const BNEZ_T0: u32 = 0x1500_0002;
        pub const BEQZ_T0: u32 = 0x1100_0002;
        pub const LW_T0_SP_4: u32 = 0x8fa8_0004;
        pub const SB_T1_A0: u32 = 0xa089_0000;
        pub const JAL: u32 = 0x0c00_0040;
        pub const ADDU_V0_A0_A1: u32 = 0x0085_1021;
        pub const MULT_A0_A1: u32 = 0x0085_0018;
        pub const MFLO_V0: u32 = 0x0000_1012;
        pub const B: u32 = 0x1000_0002;
    }

    /// Lift a word in both byte orders, and check that they agree.
    fn lift_one(word: u32) -> il::Lifted {
        let big = Mips32::BIG.lift(&Mips32::BIG.decode(&word.to_be_bytes(), 0, 0).unwrap());
        let little = Mips32::LITTLE.lift(&decode_one(word));
        assert_eq!(big, little, "{word:#010x}: both byte orders lift alike");
        big.expect("the word must lift")
    }

    #[test]
    fn operands_come_in_printed_order() {
        use il::Operand::{Const, Target};
        let reg = |number| il::Operand::Reg(il::Reg::General(number));
        let operands = |word| lift_one(word).operands.into_vec();
        assert_eq!(operands(words::ADDU_V0_A0_A1), [reg(2), reg(4), reg(5)]);
        assert_eq!(operands(words::SLTIU_T0_A0_MINUS_1), [reg(8), reg(4), Const(u64::MAX)]);
        assert_eq!(operands(words::BEQZ_A0), [reg(4), Target(None)]);
    }

    #[test]
    fn a_memory_operand_names_its_base_and_offset() {
        let general = |number| Some(il::Reg::General(number));
        let memory = |word| *lift_one(word).operands.last().expect("a memory operand");
        // `lw t0, -8(a0)`
        const LW_T0_A0_MINUS_8: u32 = 0x8c88_fff8;
        assert_eq!(memory(words::LW_T0_SP_4), il::Operand::memory(general(29), Some(4)));
        assert_eq!(memory(LW_T0_A0_MINUS_8), il::Operand::memory(general(4), Some(-8)));
        assert_eq!(memory(words::SB_T1_A0), il::Operand::memory(general(4), Some(0)));
    }

    fn guards(words: &[u32]) -> Vec<il::FoundGuard> {
        let lifted: Vec<_> = words.iter().map(|&word| Some(lift_one(word))).collect();
        il::find_guards(&lifted)
    }

    fn reg(number: u8) -> il::Value {
        il::Value::Reg(il::Reg::General(number))
    }

    fn regs(numbers: &[u8]) -> il::RegSet {
        numbers.iter().map(|&number| il::Reg::General(number)).collect()
    }

    #[test]
    fn each_compare_and_branch_is_a_guard() {
        use il::Cond;
        for (word, cond, right) in [
            (words::BEQ_A0_A1, Cond::Equal, reg(5)),
            (words::BEQZ_A0, Cond::Equal, il::Value::Const(0)),
            (words::BNEZ_A0, Cond::NotEqual, il::Value::Const(0)),
            (words::BLEZ_A0, Cond::SignedLessOrEqual, il::Value::Const(0)),
            (words::BGTZ_A0, Cond::SignedGreater, il::Value::Const(0)),
            (words::BLTZ_A0, Cond::SignedLess, il::Value::Const(0)),
            (words::BGEZ_A0, Cond::SignedGreaterOrEqual, il::Value::Const(0)),
        ] {
            let found = guards(&[word]);
            assert_eq!(found.len(), 1, "{word:#010x}");
            assert_eq!(
                (found[0].guard.cond, found[0].guard.left, found[0].guard.right),
                (cond, reg(4), right)
            );
        }
        assert_eq!(guards(&[words::B]), [], "`b` always branches");
    }

    /// `slt t0, a0, a1` with `bnez t0` branches where `a0 < a1`.
    #[test]
    fn a_set_on_less_and_its_branch_are_one_guard() {
        let found = guards(&[words::SLT_T0_A0_A1, words::ADDU_V0_A0_A1, words::BNEZ_T0]);
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].compare, found[0].branch), (Some(0), 2));
        let guard = found[0].guard;
        assert_eq!((guard.cond, guard.left, guard.right), (il::Cond::SignedLess, reg(4), reg(5)));

        let found = guards(&[words::SLTI_T0_A0_5, words::BEQZ_T0]);
        assert_eq!(found[0].guard.cond, il::Cond::SignedGreaterOrEqual);
        assert_eq!(found[0].guard.right, il::Value::Const(5));
    }

    #[test]
    fn sltiu_extends_the_sign_of_its_constant() {
        let found = guards(&[words::SLTIU_T0_A0_MINUS_1, words::BNEZ_T0]);
        assert_eq!(found[0].guard.cond, il::Cond::UnsignedLess);
        assert_eq!(found[0].guard.right, il::Value::Const(0xffff_ffff));
    }

    #[test]
    fn registers_and_memory_are_named() {
        let load = lift_one(words::LW_T0_SP_4);
        assert_eq!((load.reads, load.writes), (regs(&[29]), regs(&[8])));
        assert_eq!(
            load.memory,
            Some(il::MemoryAccess { kind: il::AccessKind::Load, width: Some(il::Width::Bits32) })
        );
        let store = lift_one(words::SB_T1_A0);
        assert_eq!((store.reads, store.writes), (regs(&[4, 9]), il::RegSet::EMPTY));
        assert_eq!(store.memory.and_then(|access| access.width), Some(il::Width::Bits8));
        assert_eq!(lift_one(words::JAL).writes, regs(&[31]));
        let add = lift_one(words::ADDU_V0_A0_A1);
        assert_eq!((add.reads, add.writes), (regs(&[4, 5]), regs(&[2])));
        let multiply = lift_one(words::MULT_A0_A1);
        assert_eq!(
            (multiply.reads, multiply.writes),
            (regs(&[4, 5]), [HI, LO].into_iter().collect())
        );
        assert_eq!(lift_one(words::MFLO_V0).reads, [LO].into_iter().collect());
    }

    #[test]
    fn lifting_any_word_never_panics() {
        bolero::check!().with_type::<u32>().for_each(|&word| {
            let bytes = word.to_be_bytes();
            let Ok(insn) = Mips32::BIG.decode(&bytes, 0, 0) else { return };
            if let Some(lifted) = Mips32::BIG.lift(&insn)
                && let Some(il::Test::Guard(_)) = lifted.test
            {
                assert!(matches!(insn.kind, InsnKind::Branch { .. }), "{insn}: a guard branches");
            }
        });
    }

    #[test]
    fn decodes_simple_arithmetic() {
        let insn = decode_one(0x0085_1021);
        assert_eq!(crate::arch::printed_name(&insn), "addu");
        assert_eq!(crate::arch::printed_operands(&insn), "v0, a0, a1");
        assert_eq!(insn.bytes_len, 4);
        assert_eq!(insn.kind, InsnKind::Normal);
    }

    #[test]
    fn jr_ra_is_a_return() {
        assert_eq!(decode_one(0x03e0_0008).kind, InsnKind::Return);
    }

    #[test]
    fn jalr_is_a_call() {
        assert!(matches!(decode_one(0x0320_f809).kind, InsnKind::Call { .. }));
    }

    /// `bal` calls its target. `bltzal t0` calls only on a condition, which
    /// compiled code never does, so its target names no function.
    #[test]
    fn only_an_unconditional_link_names_its_target() {
        assert_eq!(decode_one(0x0411_0003).kind, InsnKind::Call { target: Some(0x10) }, "bal");
        assert_eq!(decode_one(0x0510_0003).kind, InsnKind::Call { target: None }, "bltzal t0");
        assert_eq!(decode_one(0x0511_0003).kind, InsnKind::Call { target: None }, "bgezal t0");
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

    /// The name of the operation of the MIPS32 `word`.
    fn operation_of(word: u32) -> CompactString {
        Mips32::LITTLE.operation_name(&decode_one(word))
    }

    /// MIPS puts the comparison in the operation, so two different branches
    /// stay different.
    #[test]
    fn distinct_branches_are_distinct_operations() {
        // addu v0, a0, a1; beq a0, a1; bne a0, a1.
        assert_eq!(operation_of(0x0085_1021), "addu");
        assert_ne!(operation_of(0x1085_0002), operation_of(0x1485_0002));
    }

    /// `b` and `j` are one jump spelled two ways, and which one a compiler picks
    /// follows from PIC rather than from the source.
    #[test]
    fn the_two_spellings_of_a_jump_are_one_operation() {
        assert_eq!(
            operation_of(0x0800_0004),
            operation_of(0x1000_0002),
            "a PIC build emits `b` where a non-PIC build emits `j`"
        );
    }

    /// Merging the jumps must not reach the conditional branches, nor the
    /// calling forms.
    #[test]
    fn merging_the_jumps_leaves_everything_else_apart() {
        let jump = operation_of(0x0800_0004);
        // beq, bne, bgez, blez and bltz on a0, jal, jalr t9 and jr ra.
        let others = [0x1085_0002, 0x1485_0002, 0x0481_0002, 0x1880_0002, 0x0480_0002, 0x0c00_0004];
        for word in others.into_iter().chain([0x0320_f809, 0x03e0_0008]) {
            assert_ne!(operation_of(word), jump, "{word:#010x} is not a plain jump");
        }
    }

    /// MIPS runs the instruction after a branch either way, so recovery must
    /// not read it as the start of the next function.
    #[test]
    fn a_branch_has_one_delay_slot() {
        let return_ = decode_one(0x03e0_0008);
        assert_eq!(Mips32::LITTLE.delay_slots(&return_), 1);
        assert_eq!(Mips32::BIG.delay_slots(&return_), 1);
    }

    /// `eret` and `deret` leave at once, so the word after them is not
    /// theirs.
    #[test]
    fn an_exception_return_has_no_delay_slot() {
        for word in [0x4200_0018, 0x4200_001f] {
            let insn = decode_one(word);
            assert_eq!(insn.kind, InsnKind::Return, "{insn}");
            assert_eq!(Mips32::LITTLE.delay_slots(&insn), 0, "{insn}");
        }
    }

    /// `jr.hb ra` returns, and `jr.hb` through another register jumps, as
    /// `jr` does.
    #[test]
    fn a_hazard_barrier_jump_moves_control_as_jr_does() {
        assert_eq!(decode_one(0x03e0_0408).kind, InsnKind::Return);
        assert_eq!(decode_one(0x0060_0408).kind, InsnKind::Jump { target: None });
        assert_eq!(decode_one(0x0320_fc09).kind, InsnKind::Call { target: None });
    }

    /// The same bytes are two different instructions in the two byte orders,
    /// which is why the order cannot be guessed.
    #[test]
    fn byte_order_decides_what_a_word_means() {
        // `addu v0, a0, a1` stored big endian.
        let stored = 0x0085_1021u32.to_be_bytes();

        let big = Mips32::BIG.decode(&stored, 0, 0).unwrap();
        assert_eq!(crate::arch::printed_name(&big), "addu");

        let little = Mips32::LITTLE.decode(&stored, 0, 0).unwrap();
        assert_ne!(
            crate::arch::printed_name(&little),
            "addu",
            "the wrong order reads another instruction"
        );
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

    #[test]
    fn a_float_operation_names_what_it_computes() {
        assert_eq!(float_op(Opcode::core_div_d), Some(il::Op::FloatDivide));
        assert_eq!(float_op(Opcode::core_mul_s), Some(il::Op::FloatMultiply));
        assert_eq!(float_op(Opcode::core_floor_w_d), Some(il::Op::FloatRoundDown));
        assert_eq!(float_op(Opcode::core_ceil_w_s), Some(il::Op::FloatRoundUp));
        assert_eq!(float_op(Opcode::core_trunc_w_d), Some(il::Op::FloatRoundTowardZero));
        assert_eq!(float_op(Opcode::core_mov_d), Some(il::Op::Move));
        assert_eq!(float_op(Opcode::core_c_lt_d), Some(il::Op::Float));
        assert_eq!(float_op(Opcode::core_addu), None, "no floating point");
    }
}
