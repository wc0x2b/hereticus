//! The decoder and the lifter of A32, which read one word at a time and
//! know nothing of the binary around it. T32 shares much of it. The rules
//! that read ARM code, as literal pools, long thunks and jump tables, are
//! in `hereticus-recovery`, and the rules the matching reads in
//! `hereticus-arch`.

use crate as il;
use crate::arch::{DecodeError, Decoder, Insn, InsnKind, Printing, split_printed};
use compact_str::CompactString;
use yaxpeax_arch::{Decoder as _, Reader, U8Reader, U32le};
use yaxpeax_arm::armv7::{
    ConditionCode, InstDecoder, Instruction, Opcode, Operand, Reg, RegShift, RegShiftStyle,
    ShiftStyle,
};

/// Every A32 instruction is 4 bytes wide.
pub const INSN_WIDTH: usize = 4;

/// The text of bytes the decoder cannot read.
///
/// `yaxpeax-arm` 0.4 has no NEON or SIMD support and answers "incomplete
/// decoder" for those encodings. `clang` vectorizes automatically at `-O2`,
/// so real code reaches this path.
pub const UNKNOWN_TEXT: &str = "(unknown)";

/// The text of a NEON data-processing instruction, which the decoder
/// cannot read either. It stays opaque, as an unreadable word does, but the
/// name says that it is code. See `Recovery::is_unread_extension` of `hereticus`.
pub const NEON_TEXT: &str = "(neon)";

/// Register number of the program counter.
pub(crate) const REG_PC: u16 = 15;

/// Register number of the link register.
pub(crate) const REG_LR: u16 = 14;

/// Register number of the stack pointer.
pub(crate) const REG_SP: u16 = 13;

/// What [`Insn::opcode`] holds for A32 and T32.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decoded {
    /// An integer instruction, by the opcode `yaxpeax-arm` names, whether it
    /// or this module reads the word. A store or a load of the stack that
    /// it prints as `push` or `pop` has that opcode.
    Core {
        /// The operation.
        opcode: Opcode,
        /// When it runs.
        condition: ConditionCode,
        /// Whether it sets the flags.
        flags: Flags,
    },
    /// `it`, which makes up to four instructions after it conditional: the
    /// condition of the first, and the mask that says the rest.
    It {
        /// The condition of the first instruction it covers.
        condition: u8,
        /// The mask that says the rest.
        mask: u8,
    },
    /// A VFP instruction this module reads, and its condition.
    Vfp {
        /// Which VFP instruction it is.
        vfp: Vfp,
        /// When it runs.
        condition: ConditionCode,
    },
    /// A NEON load or store this module reads.
    NeonAccess(NeonShape),
    /// NEON data processing, which nothing here reads.
    NeonData,
}

/// The name of the operation `decoded` does: see [`Decoder::operation_name`].
pub fn operation_name(decoded: Decoded) -> CompactString {
    use compact_str::format_compact;
    match decoded {
        // The condition of a branch is the test it applies, so `bne` and
        // `beq` stay apart. On other work it only says when the work runs.
        Decoded::Core { opcode: Opcode::B, condition, .. } => {
            format_compact!("b{}", condition_name(condition))
        }
        Decoded::Core { opcode, .. } => match opcode {
            // A load or store of a list is named by the way it steps
            // through memory, not by whether it writes the base back.
            Opcode::LDM(add, pre, ..) => format_compact!("ldm{}", list_step(add, pre)),
            Opcode::STM(add, pre, ..) => format_compact!("stm{}", list_step(add, pre)),
            // A coprocessor number or register in the opcode is an operand.
            Opcode::CDP2(..)
            | Opcode::LDC(..)
            | Opcode::LDC2(..)
            | Opcode::LDC2L(..)
            | Opcode::LDCL(..)
            | Opcode::STC(..)
            | Opcode::STC2(..)
            | Opcode::STC2L(..)
            | Opcode::STCL(..)
            | Opcode::MCR2(..)
            | Opcode::MRC2(..)
            | Opcode::MCRR(..)
            | Opcode::MCRR2(..)
            | Opcode::MRRC(..)
            | Opcode::MRRC2(..) => {
                let name = format_compact!("{opcode:?}");
                name.split('(').next().unwrap_or_default().to_ascii_lowercase().into()
            }
            other => format_compact!("{other:?}").to_ascii_lowercase(),
        },
        Decoded::It { condition, mask } => format_compact!("it{}", it_pattern(condition, mask)),
        Decoded::Vfp { vfp, .. } => match vfp {
            Vfp::Compare { operation, size } | Vfp::Compute { operation, size } => {
                if size.is_empty() {
                    operation.name().into()
                } else {
                    format_compact!("{}.{size}", operation.name())
                }
            }
            Vfp::Multiple(step, transfer) => format_compact!("vfp-{transfer:?}-{step:?}"),
            other => format_compact!("vfp-{other:?}"),
        },
        Decoded::NeonAccess(NeonShape { transfer, structures, size }) => {
            format_compact!("neon-{transfer:?}{structures}.{}", 8u32 << size)
        }
        Decoded::NeonData => NEON_TEXT.into(),
    }
}

/// How a load or store of a list steps, as the suffix of `ldmia` says.
pub(crate) fn list_step(add: bool, pre: bool) -> &'static str {
    match (add, pre) {
        (true, false) => "ia",
        (true, true) => "ib",
        (false, false) => "da",
        (false, true) => "db",
    }
}

/// The `t` and `e` of the instructions an `it` makes conditional after the
/// first, as `ite` says: each bit of `mask` above its lowest set bit is
/// then where it equals the low bit of `condition`, and else where not.
pub(crate) fn it_pattern(condition: u8, mask: u8) -> String {
    let lowest = mask.trailing_zeros();
    (lowest + 1..4)
        .rev()
        .map(|bit| if (mask >> bit) & 1 == condition & 1 { 't' } else { 'e' })
        .collect()
}

/// Whether an access reads memory or writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transfer {
    /// Reads memory.
    Load,
    /// Writes memory.
    Store,
}

impl Transfer {
    fn of(load: bool) -> Self {
        if load { Self::Load } else { Self::Store }
    }
}

/// What tells one NEON load or store from another: its direction, how many
/// elements make one structure, as `vld3` says, and the size of an
/// element, as a power of two of bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeonShape {
    /// Whether the access loads or stores.
    pub transfer: Transfer,
    /// How many elements make one structure, as the 3 of `vld3`.
    pub structures: u8,
    /// The size of an element, as a power of two of bytes.
    pub size: u8,
}

/// Whether an instruction sets the flags, as the `s` of `adds` says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flags {
    /// The instruction keeps the flags.
    Kept,
    /// The instruction sets the flags.
    Set,
}

impl Flags {
    /// `Set` where `sets_flags`, else `Kept`.
    pub fn of(sets_flags: bool) -> Self {
        if sets_flags { Self::Set } else { Self::Kept }
    }
}

/// Which VFP instruction this module read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vfp {
    /// `vldr`.
    Load,
    /// `vstr`.
    Store,
    /// `vmov` between a core register and a single.
    Move,
    /// `vmov` between two core registers and a double.
    MoveDouble,
    /// `vmrs`, which moves the status register to a core register.
    Status,
    /// `vpush`.
    Push,
    /// `vpop`.
    Pop,
    /// `vldm` and `vstm`, which step through memory as `step` says.
    Multiple(Step, Transfer),
    /// `vcmp` and `vcmpe`, on singles or doubles as `size` says.
    Compare {
        /// Which compare it is.
        operation: VfpOperation,
        /// `f32` or `f64`.
        size: &'static str,
    },
    /// The arithmetic, the conversions and `vmov` of a constant, on singles
    /// or doubles as `size` says. A conversion names its sizes in
    /// `operation`, and its `size` is empty.
    Compute {
        /// What it computes.
        operation: VfpOperation,
        /// `f32` or `f64`, or empty for a conversion.
        size: &'static str,
    },
}

/// Which way a load or store of a list steps through memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// From the base up: `ia`.
    IncrementAfter,
    /// From below the base up to it: `db`.
    DecrementBefore,
}

/// The conditions of A32, by the top four bits of a word.
pub(crate) const CONDITION_CODES: [ConditionCode; 15] = [
    ConditionCode::EQ,
    ConditionCode::NE,
    ConditionCode::HS,
    ConditionCode::LO,
    ConditionCode::MI,
    ConditionCode::PL,
    ConditionCode::VS,
    ConditionCode::VC,
    ConditionCode::HI,
    ConditionCode::LS,
    ConditionCode::GE,
    ConditionCode::LT,
    ConditionCode::GT,
    ConditionCode::LE,
    ConditionCode::AL,
];

/// The condition the top four bits of an A32 `word` name, or `None` for the
/// words that have none.
pub(crate) fn condition_of(word: u32) -> Option<ConditionCode> {
    CONDITION_CODES.get((word >> 28) as usize).copied()
}

/// What `inst` holds, as [`Insn::opcode`] keeps it.
pub(crate) fn decoded_of(inst: &Instruction) -> Decoded {
    if inst.opcode == Opcode::IT
        && let [Operand::Imm32(condition), Operand::Imm32(mask), ..] = inst.operands
    {
        return Decoded::It { condition: condition as u8, mask: mask as u8 };
    }
    Decoded::Core {
        opcode: printed_opcode(inst),
        condition: inst.condition,
        flags: Flags::of(inst.s()),
    }
}

/// The opcode of `inst`, or `push` or `pop` where `yaxpeax-arm` 0.4 prints
/// it so: a store of one register before `sp` that moves `sp`, a load of
/// one after it, and a store or a load of a list on `sp` that moves it.
pub(crate) fn printed_opcode(inst: &Instruction) -> Opcode {
    let is_sp = |reg: Reg| u16::from(reg.number()) == REG_SP;
    match (inst.opcode, inst.operands) {
        (
            Opcode::LDR,
            [
                Operand::Reg(_),
                Operand::RegDerefPostindexOffset(base, 4, true, false),
                Operand::Nothing,
                Operand::Nothing,
            ],
        ) if is_sp(base) => Opcode::POP,
        (
            Opcode::STR,
            [
                Operand::Reg(_),
                Operand::RegDerefPreindexOffset(base, 4, false, true),
                Operand::Nothing,
                Operand::Nothing,
            ],
        ) if is_sp(base) => Opcode::PUSH,
        (
            Opcode::LDM(true, false, false, _),
            [
                Operand::RegWBack(base, true),
                Operand::RegList(_),
                Operand::Nothing,
                Operand::Nothing,
            ],
        ) if is_sp(base) => Opcode::POP,
        (
            Opcode::STM(false, true, false, _),
            [
                Operand::RegWBack(base, true),
                Operand::RegList(_),
                Operand::Nothing,
                Operand::Nothing,
            ],
        ) if is_sp(base) => Opcode::PUSH,
        (opcode, _) => opcode,
    }
}

/// What the decoder read for `insn`, where it read A32 or T32.
pub fn decoded(insn: &Insn) -> Option<Decoded> {
    match insn.opcode {
        crate::arch::Opcode::Arm(decoded) | crate::arch::Opcode::Thumb(decoded) => Some(decoded),
        _ => None,
    }
}

/// `insn` lifted in the instruction set that decoded it, A32 or T32. A rule
/// that both read can take an instruction of either.
pub fn lifted(insn: &Insn) -> Option<il::Lifted> {
    match insn.opcode {
        crate::arch::Opcode::Thumb(_) => crate::arch::thumb::Thumb2.lift(insn),
        _ if insn.bytes_len == crate::arch::thumb::HALFWORD => {
            crate::arch::thumb::Thumb2.lift(insn)
        }
        _ => Arm32.lift(insn),
    }
}

/// The condition `insn` runs on, where it names one.
pub fn condition(insn: &Insn) -> Option<ConditionCode> {
    match decoded(insn)? {
        Decoded::Core { condition, .. } | Decoded::Vfp { condition, .. } => Some(condition),
        _ => None,
    }
}

/// The suffix an instruction prints with for `condition`.
pub fn condition_name(condition: ConditionCode) -> &'static str {
    match condition {
        ConditionCode::EQ => "eq",
        ConditionCode::NE => "ne",
        ConditionCode::HS => "hs",
        ConditionCode::LO => "lo",
        ConditionCode::MI => "mi",
        ConditionCode::PL => "pl",
        ConditionCode::VS => "vs",
        ConditionCode::VC => "vc",
        ConditionCode::HI => "hi",
        ConditionCode::LS => "ls",
        ConditionCode::GE => "ge",
        ConditionCode::LT => "lt",
        ConditionCode::GT => "gt",
        ConditionCode::LE => "le",
        ConditionCode::AL => "",
    }
}

/// The integer operation `insn` does, whatever its condition and flags.
pub fn core_opcode(insn: &Insn) -> Option<Opcode> {
    match decoded(insn)? {
        Decoded::Core { opcode, .. } => Some(opcode),
        _ => None,
    }
}

/// ARM32 in A32 (not Thumb) mode.
#[derive(Clone, Copy, Debug, Default)]
pub struct Arm32;

impl Arm32 {
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
        let bytes = &bytes[..INSN_WIDTH];
        let insn_address = address + offset as u64;

        let mut reader = U8Reader::new(bytes);
        let mut inst = Instruction::default();

        // `yaxpeax` rejects a word it cannot read in two different ways: it
        // returns an error, or it succeeds and sets `Opcode::Invalid`. The
        // standard ARM `nop`, `0xe320f000`, takes the second path. Both mean
        // the same thing here.
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let failed = InstDecoder::default().decode_into(&mut inst, &mut reader).is_err();
        if failed || inst.opcode == Opcode::Invalid || decoder_misreads(word, Encoding::A32) {
            // A32 instructions are all 4 bytes, so stepping over an
            // unreadable word keeps everything after it aligned. Reporting an
            // error instead would throw away the rest of the function.
            //
            // The raw word goes in the operand field. Without it every
            // unreadable instruction would look like every other one, and an
            // edit inside a NEON loop would be reported as no change at all.
            if let Some((name, operands, decoded)) = decode_fallback(word, Encoding::A32) {
                let opcode = crate::arch::Opcode::Arm(decoded);
                let insn = Insn::new(insn_address, bytes, InsnKind::Normal, opcode);
                return Ok((insn, printing.text(|| format!("{name} {operands}"))));
            }
            let insn = Insn::new(insn_address, bytes, InsnKind::Unknown, unread_opcode(word));
            return Ok((insn, printing.text(|| format!("{} {word:#010x}", unread_text(word)))));
        }

        // `total_offset` is in words; convert so the assertion below compares
        // like with like.
        let words = <U8Reader<'_> as Reader<u32, U32le>>::total_offset(&mut reader);
        let consumed = words as usize * INSN_WIDTH;
        debug_assert_eq!(consumed, INSN_WIDTH, "A32 instructions are always 4 bytes");

        let insn = Insn::new(
            insn_address,
            bytes,
            classify(&inst, branch_target(&inst, insn_address)),
            crate::arch::Opcode::Arm(decoded_of(&inst)),
        );
        Ok((insn, printing.text(|| printed(&inst))))
    }
}

impl Decoder for Arm32 {
    /// The condition of `addeq` and the `s` of `adds` are dropped: they say
    /// when the work runs and what it leaves in the flags, not what it
    /// computes. The condition of a branch is kept: it is the test.
    fn operation_name(&self, insn: &Insn) -> CompactString {
        let Some(decoded) = decoded(insn) else { return UNKNOWN_TEXT.into() };
        operation_name(decoded)
    }

    fn decode(&self, code: &[u8], offset: usize, address: u64) -> Result<Insn, DecodeError> {
        self.read(code, offset, address, Printing::Skip).map(|(insn, _)| insn)
    }

    fn triple(&self) -> &'static str {
        "arm-linux-gnueabi"
    }

    fn instruction_width(&self) -> usize {
        INSN_WIDTH
    }

    fn pointer_width(&self) -> usize {
        INSN_WIDTH
    }

    fn read_pointer(&self, bytes: &[u8]) -> u64 {
        u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn lift(&self, insn: &Insn) -> Option<il::Lifted> {
        let word = insn.bytes();
        let a32 = word.try_into().ok().map(u32::from_le_bytes);
        lift_with(InstDecoder::default(), insn, word, a32.map(|a32| (a32, Encoding::A32)))
    }

    fn lift_named(&self, insn: &Insn) -> Option<il::Named> {
        let word = insn.bytes();
        let a32 = word.try_into().ok().map(u32::from_le_bytes);
        let fallback = a32.map(|a32| (a32, Encoding::A32));
        lift_named_with(InstDecoder::default(), insn, word, fallback, Printing::Text)
    }
}

/// Decode `word` again with `decoder` and lift it. A word the decoder
/// refuses, or reads only through the fallback, lifts to nothing.
///
/// A word the decoder refuses lifts from `fallback`, its A32 form and the
/// encoding it came in, where [`lift_fallback`] reads it.
pub(crate) fn lift_with(
    decoder: InstDecoder,
    insn: &Insn,
    word: &[u8],
    fallback: Option<(u32, Encoding)>,
) -> Option<il::Lifted> {
    lift_named_with(decoder, insn, word, fallback, Printing::Skip).map(|named| named.lifted)
}

/// [`lift_with`], with the name of each operand where `printing` asks for
/// them: see [`il::Named`].
pub(crate) fn lift_named_with(
    decoder: InstDecoder,
    insn: &Insn,
    word: &[u8],
    fallback: Option<(u32, Encoding)>,
    printing: Printing,
) -> Option<il::Named> {
    if insn.kind == InsnKind::Unknown {
        return None;
    }
    let mut inst = Instruction::default();
    let decoded = decoder.decode_into(&mut inst, &mut U8Reader::new(word)).is_ok();
    let misread = fallback.is_some_and(|(a32, encoding)| decoder_misreads(a32, encoding));
    if decoded && inst.opcode != Opcode::Invalid && !misread {
        Some(lift_named(&inst, printing))
    } else {
        let (a32, encoding) = fallback?;
        let lifted = lift_fallback(a32, encoding)?;
        let names = match printing {
            Printing::Skip => il::Names::new(),
            Printing::Text => fallback_names(a32, encoding)?,
        };
        let write_back = match printing {
            Printing::Skip => None,
            Printing::Text => fallback_write_back(a32, encoding),
        };
        Some(il::Named { lifted, names, write_back })
    }
}

/// What an ARM instruction does with its first operands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    /// Writes its first `count` operands from the others, as `add` writes
    /// one and `umull` two.
    Compute { count: usize },
    /// Reads every operand and writes none, as `str`, `cmp` and `b` do.
    ReadOnly,
    /// Loads its first `count` operands, or the registers of its list.
    Load { count: usize },
    /// An exclusive store, which writes its status to the first operand.
    StoreExclusive,
}

/// Lift one decoded A32 or T32 instruction, with the name of each operand
/// where `printing` asks for them.
pub(crate) fn lift_named(inst: &Instruction, printing: Printing) -> il::Named {
    let mut operands: Vec<Operand> =
        inst.operands.iter().copied().take_while(|operand| *operand != Operand::Nothing).collect();
    // `yaxpeax` gives an A32 compare the unused destination field first, as
    // in `cmps r0, r0, 0x1`. T32 gives only the two values.
    if is_compare(inst.opcode) && operands.len() == 3 {
        operands.remove(0);
    }
    // It gives an A32 `mvn` of a constant the unused first value field too,
    // as in `mvn r0, r0, 0x1`.
    if matches!(inst.opcode, Opcode::MVN | Opcode::MOV) && operands.len() == 3 {
        operands.remove(1);
    }
    // The names follow each change to the operands below.
    let mut names: il::Names = match printing {
        Printing::Skip => il::Names::new(),
        Printing::Text => operands.iter().map(|operand| operand_name(*operand)).collect(),
    };
    let mut write_back = match printing {
        Printing::Skip => None,
        Printing::Text => operands.iter().find_map(|operand| write_back_name(*operand)),
    };
    // `yaxpeax-arm` prints a load or store of one register that steps `sp`
    // as `pop` or `push` of a list of one.
    let sp = Reg::from_u8(REG_SP as u8);
    if let (Opcode::LDR | Opcode::STR, [Operand::Reg(value), access], [_, _]) =
        (inst.opcode, operands.as_slice(), names.as_slice())
        && matches!(
            (inst.opcode, *access),
            (Opcode::LDR, Operand::RegDerefPostindexOffset(base, 4, true, false))
                | (Opcode::STR, Operand::RegDerefPreindexOffset(base, 4, false, true))
                if base == sp
        )
    {
        let list = compact_str::format_compact!("{{{}}}", register_name(*value));
        names = [list, CompactString::default()].into_iter().collect();
        write_back = None;
    }
    let mut reads = il::RegSet::EMPTY;
    let mut writes = il::RegSet::EMPTY;
    for operand in &operands {
        address_registers(*operand, &mut reads, &mut writes);
    }

    let role = role_of(inst.opcode);
    for (index, operand) in operands.iter().enumerate() {
        let regs = value_registers(*operand);
        let written = match role {
            Role::Compute { count } | Role::Load { count } => index < count,
            Role::StoreExclusive => index == 0,
            Role::ReadOnly => false,
        };
        let list_loaded =
            matches!(role, Role::Load { .. }) && matches!(operand, Operand::RegList(_));
        if written || list_loaded {
            regs.iter().for_each(|reg| writes.insert(reg));
            if reads_destination(inst.opcode) {
                regs.iter().for_each(|reg| reads.insert(reg));
            }
        } else {
            regs.iter().for_each(|reg| reads.insert(reg));
        }
    }

    match inst.opcode {
        Opcode::BL | Opcode::BLX => writes.insert(il::Reg::General(REG_LR as u8)),
        Opcode::PUSH | Opcode::POP => {
            reads.insert(il::Reg::Stack);
            writes.insert(il::Reg::Stack);
        }
        _ => {}
    }
    if inst.condition != ConditionCode::AL || matches!(inst.opcode, Opcode::IT) {
        reads.insert(il::Reg::Flags);
    }
    if inst.s() || is_compare(inst.opcode) {
        writes.insert(il::Reg::Flags);
    }

    let mut lifted = il::Lifted {
        op: op_of(inst, &operands),
        reads,
        writes,
        memory: memory_access(inst.opcode, &operands),
        test: test_of(inst, &operands),
        operands: operands.iter().map(|operand| il_operand(*operand)).collect(),
    };
    // A 16-bit Thumb form names its destination once, as `adds r0, #1`,
    // where the 32-bit form names it twice, as `add r0, r0, #1`.
    if is_binary(lifted.op) && lifted.operands.len() == 2 {
        let destination = lifted.operands[0];
        lifted.operands.insert(1, destination);
        if !names.is_empty() {
            names.insert(1, CompactString::default());
        }
    }
    // `rsb` subtracts the other way round, so its values swap to read as
    // `sub` does: `rsb r0, r1, #0` is `0 - r1`.
    if matches!(inst.opcode, Opcode::RSB | Opcode::RSC) && lifted.operands.len() == 3 {
        lifted.operands.swap(1, 2);
        if names.len() == 3 {
            names.swap(1, 2);
        }
    }
    // `mov r4, r1, lsl #4` is the shift `lsl r4, r1, #4`.
    if let (Opcode::MOV, [_, Operand::RegShift(shift)]) = (inst.opcode, operands.as_slice()) {
        let op_of_style = |style: ShiftStyle| match style {
            ShiftStyle::LSL => il::Op::ShiftLeft,
            ShiftStyle::LSR => il::Op::ShiftRight,
            ShiftStyle::ASR => il::Op::ShiftRightArithmetic,
            ShiftStyle::ROR => il::Op::Rotate,
        };
        let shifted = match shift.into_shift() {
            // A shift right of 0 encodes one of 32; a rotate of 0 is `rrx`,
            // and a shift left of 0 is no shift.
            RegShiftStyle::RegImm(shift) => match (shift.stype(), shift.imm()) {
                (ShiftStyle::LSL, 0) | (ShiftStyle::ROR, 0) => None,
                (style, 0) => Some((op_of_style(style), shift.shiftee(), il::Operand::Const(32))),
                (style, amount) => {
                    Some((op_of_style(style), shift.shiftee(), il::Operand::Const(amount.into())))
                }
            },
            RegShiftStyle::RegReg(shift) => il_reg(shift.shifter())
                .map(|by| (op_of_style(shift.stype()), shift.shiftee(), il::Operand::Reg(by))),
        };
        if let Some((op, source_reg, amount)) = shifted
            && let Some(source) = il_reg(source_reg)
        {
            lifted.op = op;
            lifted.operands =
                [lifted.operands[0], il::Operand::Reg(source), amount].into_iter().collect();
            if let [dest, _] = names.as_slice() {
                let amount_name = match shift.into_shift() {
                    RegShiftStyle::RegImm(shift) => compact_str::format_compact!("{}", shift.imm()),
                    RegShiftStyle::RegReg(shift) => register_name(shift.shifter()),
                };
                names =
                    [dest.clone(), register_name(source_reg), amount_name].into_iter().collect();
            }
        }
    }
    // `mvn r0, #1` puts the constant `~1` in `r0`, as `mov` would.
    if let (Opcode::MVN, [dest, il::Operand::Const(constant)]) =
        (inst.opcode, lifted.operands.as_slice())
    {
        let inverted = il::Operand::Const(u64::from(!(*constant as u32)));
        lifted.operands = [*dest, inverted].into_iter().collect();
        lifted.op = il::Op::Move;
    }
    il::Named { lifted, names, write_back }
}

/// The names `yaxpeax-arm` 0.4 prints for the general registers. Unlike
/// [`ARM_REGISTERS`], it calls `r10` by its number.
pub(crate) const PRINTED_REGISTERS: [&str; 16] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "sb", "r10", "fp", "ip", "sp", "lr", "pc",
];

/// The name of `reg`, as `yaxpeax-arm` prints it.
pub(crate) fn register_name(reg: Reg) -> CompactString {
    PRINTED_REGISTERS[usize::from(reg.number() & 15)].into()
}

/// `operand`, where it is no access and no shift, as `yaxpeax-arm` prints
/// it.
pub(crate) fn printed_operand(operand: Operand) -> CompactString {
    use compact_str::format_compact;
    let lower = |text: String| CompactString::from(text.to_ascii_lowercase());
    match operand {
        Operand::Reg(reg) | Operand::RegWBack(reg, false) => register_name(reg),
        Operand::RegWBack(reg, true) => format_compact!("{}!", register_name(reg)),
        Operand::RegList(list) => {
            let names: Vec<&str> = (0..16)
                .filter(|bit| list & (1 << bit) != 0)
                .map(|bit| PRINTED_REGISTERS[bit])
                .collect();
            format_compact!("{{{}}}", names.join(", "))
        }
        Operand::Imm12(value) => format_compact!("{value:#x}"),
        Operand::Imm32(value) => format_compact!("{value:#x}"),
        Operand::CoprocOption(number) => format_compact!("{{{number:#x}}}"),
        Operand::CReg(creg) => format_compact!("c{}", creg.number()),
        Operand::StatusRegMask(mask) => lower(format!("{mask:?}")),
        Operand::BankedReg(bank, reg) => {
            format_compact!(
                "{}_{}",
                PRINTED_REGISTERS[usize::from(reg.number() & 15)],
                lower(format!("{bank:?}"))
            )
        }
        Operand::BankedSPSR(bank) => format_compact!("spsr_{}", lower(format!("{bank:?}"))),
        Operand::APSR => "apsr".into(),
        Operand::SPSR => "spsr".into(),
        Operand::CPSR => "cpsr".into(),
        _ => CompactString::default(),
    }
}

/// The register `shift` shifts, and the shift as `yaxpeax-arm` prints
/// it, as `lsl 4` or `asr r2`. A left shift by zero is none.
pub(crate) fn shift_parts(shift: RegShift) -> (CompactString, Option<CompactString>) {
    use compact_str::format_compact;
    let style = |style: ShiftStyle| match style {
        ShiftStyle::LSL => "lsl",
        ShiftStyle::LSR => "lsr",
        ShiftStyle::ASR => "asr",
        ShiftStyle::ROR => "ror",
    };
    match shift.into_shift() {
        RegShiftStyle::RegImm(shift) if shift.imm() == 0 && shift.stype() == ShiftStyle::LSL => {
            (register_name(shift.shiftee()), None)
        }
        RegShiftStyle::RegImm(shift) => (
            register_name(shift.shiftee()),
            Some(format_compact!("{} {}", style(shift.stype()), shift.imm())),
        ),
        RegShiftStyle::RegReg(shift) => (
            register_name(shift.shiftee()),
            Some(format_compact!("{} {}", style(shift.stype()), register_name(shift.shifter()))),
        ),
    }
}

/// A register shifted by `shift`, as `(r1 lsl 4)`, or the register alone
/// where the shift is a left shift by zero. `minus` marks an index that the
/// access subtracts.
pub(crate) fn shift_name(shift: RegShift, minus: &str) -> CompactString {
    use compact_str::format_compact;
    match shift_parts(shift) {
        (reg, None) => format_compact!("{minus}{reg}"),
        (reg, Some(shift)) => format_compact!("({minus}{reg} {shift})"),
    }
}

/// The name of `operand`, as the IL view shows it: a register as
/// `yaxpeax-arm` prints it, an access as `[r0 + 0x4]`, and a target as
/// `$+0x24`.
pub(crate) fn operand_name(operand: Operand) -> CompactString {
    use compact_str::format_compact;
    let sign = |add: bool| if add { "+" } else { "-" };
    match operand {
        Operand::RegShift(shift) => shift_name(shift, ""),
        Operand::RegDeref(base)
        | Operand::RegDerefPostindexOffset(base, ..)
        | Operand::RegDerefPostindexReg(base, ..)
        | Operand::RegDerefPostindexRegShift(base, ..) => {
            format_compact!("[{}]", register_name(base))
        }
        Operand::RegDerefPreindexOffset(base, 0, ..) => {
            format_compact!("[{}]", register_name(base))
        }
        Operand::RegDerefPreindexOffset(base, offset, add, _) => {
            format_compact!("[{} {} {offset:#x}]", register_name(base), sign(add))
        }
        Operand::RegDerefPreindexReg(base, index, add, _) => {
            format_compact!("[{} {} {}]", register_name(base), sign(add), register_name(index))
        }
        Operand::RegDerefPreindexRegShift(base, shift, add, _) => match shift_parts(shift) {
            (index, None) => format_compact!("[{} {} {index}]", register_name(base), sign(add)),
            (_, Some(_)) => format_compact!(
                "[{} + {}]",
                register_name(base),
                shift_name(shift, if add { "" } else { "-" })
            ),
        },
        Operand::BranchOffset(words) => il::target_name(i64::from(words) << 2),
        Operand::BranchThumbOffset(halfwords) => il::target_name(i64::from(halfwords) << 1),
        Operand::Nothing => CompactString::default(),
        _ => printed_operand(operand),
    }
}

/// What a post-index access through `operand` adds to its base after it,
/// as `yaxpeax-arm` prints it.
pub(crate) fn write_back_name(operand: Operand) -> Option<CompactString> {
    use compact_str::format_compact;
    let minus = |add: bool| if add { "" } else { "-" };
    match operand {
        Operand::RegDerefPostindexOffset(_, 0, ..) => None,
        Operand::RegDerefPostindexOffset(_, offset, add, _) => {
            Some(format_compact!("{}{offset:#x}", minus(add)))
        }
        Operand::RegDerefPostindexReg(_, index, add, _) => {
            Some(format_compact!("{}{}", minus(add), register_name(index)))
        }
        Operand::RegDerefPostindexRegShift(_, shift, add, _) => {
            let shifted = match shift_parts(shift) {
                (reg, None) => reg,
                (reg, Some(shift)) => format_compact!("{reg}, {shift}"),
            };
            Some(match add {
                true => shifted,
                false => format_compact!("- {shifted}"),
            })
        }
        _ => None,
    }
}

/// Report whether `op` computes its result from two values.
pub(crate) fn is_binary(op: il::Op) -> bool {
    use il::Op;
    matches!(
        op,
        Op::Add
            | Op::Subtract
            | Op::Multiply
            | Op::And
            | Op::Or
            | Op::Xor
            | Op::AndNot
            | Op::OrNot
            | Op::ShiftLeft
            | Op::ShiftRight
            | Op::ShiftRightArithmetic
            | Op::Rotate
    )
}

/// An operand as the IL names it.
pub(crate) fn il_operand(operand: Operand) -> il::Operand {
    let register = |reg: Reg| il::Operand::Reg(operand_reg(reg));
    let memory = |base: Reg, offset, index, update| il::Operand::Memory {
        base: Some(operand_reg(base)),
        offset,
        index,
        update,
    };
    // `wback` of a pre-indexed access says whether it writes the base back;
    // a post-indexed one always does.
    let before = |write_back: bool| if write_back { il::Update::Before } else { il::Update::None };
    match operand {
        Operand::Reg(reg) | Operand::RegWBack(reg, _) => register(reg),
        Operand::RegShift(shift) => match shift.into_shift() {
            RegShiftStyle::RegImm(shift) => shifted(shift.shiftee(), shift.stype(), shift.imm()),
            RegShiftStyle::RegReg(shift) => register(shift.shiftee()),
        },
        Operand::RegList(list) => il::Operand::RegisterList(register_list(list)),
        Operand::RegDeref(base) => memory(base, Some(0), None, il::Update::None),
        Operand::RegDerefPreindexOffset(base, offset, add, write_back) => {
            let offset = i64::from(offset);
            memory(base, Some(if add { offset } else { -offset }), None, before(write_back))
        }
        Operand::RegDerefPostindexOffset(base, offset, add, _) => {
            let offset = i64::from(offset);
            memory(base, Some(if add { offset } else { -offset }), None, il::Update::After)
        }
        Operand::RegDerefPreindexReg(base, index, _, write_back) => {
            memory(base, None, Some((operand_reg(index), 0)), before(write_back))
        }
        Operand::RegDerefPostindexReg(base, index, ..) => {
            memory(base, None, Some((operand_reg(index), 0)), il::Update::After)
        }
        Operand::RegDerefPreindexRegShift(base, shift, _, write_back) => {
            memory(base, None, shifted_index(shift), before(write_back))
        }
        Operand::RegDerefPostindexRegShift(base, shift, ..) => {
            memory(base, None, shifted_index(shift), il::Update::After)
        }
        Operand::Imm12(value) => il::Operand::Const(value.into()),
        Operand::Imm32(value) => il::Operand::Const(value.into()),
        Operand::BranchOffset(words) => il::Operand::Target(Some(i64::from(words) * 4)),
        Operand::BranchThumbOffset(halfwords) => {
            il::Operand::Target(Some(i64::from(halfwords) * 2))
        }
        _ => il::Operand::Other,
    }
}

/// The register an operand names, where the program counter has a name of
/// its own.
pub(crate) fn operand_reg(reg: Reg) -> il::Reg {
    il_reg(reg).unwrap_or(il::Reg::ProgramCounter)
}

/// The general register `number`, as an operand names it.
pub(crate) fn operand_general(number: u32) -> il::Reg {
    operand_reg(Reg::from_u8(number as u8))
}

/// The registers of a list, as the bits of `push` and `ldm` name them.
pub(crate) fn register_list(list: u16) -> il::RegSet {
    (0..16)
        .filter(|bit| list & (1 << bit) != 0)
        .map(|bit| operand_reg(Reg::from_u8(bit as u8)))
        .collect()
}

/// `reg` shifted by the constant `amount` in `style`. A left shift by zero
/// is the register itself, and a rotate by zero is `rrx`.
pub fn shifted(reg: Reg, style: ShiftStyle, amount: u8) -> il::Operand {
    let shift = match (style, amount) {
        (ShiftStyle::LSL, 0) => return il::Operand::Reg(operand_reg(reg)),
        (ShiftStyle::LSL, _) => il::Shift::Left,
        (ShiftStyle::LSR, _) => il::Shift::Right,
        (ShiftStyle::ASR, _) => il::Shift::RightArithmetic,
        (ShiftStyle::ROR, 0) => il::Shift::RotateExtended,
        (ShiftStyle::ROR, _) => il::Shift::Rotate,
    };
    il::Operand::Shifted { reg: operand_reg(reg), shift, amount }
}

/// The index of an access, where it shifts its register left by a
/// constant, as `[r1, r2, lsl #2]`. Another shift scales no index.
///
/// No access shifts its index by a register. `yaxpeax-arm` 0.4 builds the
/// index of `tbh [pc, rI, lsl #1]` with the bit that, read back, says it
/// does, so that form is `tbh`'s shift by one.
pub(crate) fn shifted_index(shift: RegShift) -> Option<(il::Reg, u8)> {
    match shift.into_shift() {
        RegShiftStyle::RegImm(shift) if shift.stype() == ShiftStyle::LSL => {
            Some((operand_reg(shift.shiftee()), shift.imm()))
        }
        RegShiftStyle::RegReg(shift) => Some((operand_reg(shift.shiftee()), 1)),
        RegShiftStyle::RegImm(_) => None,
    }
}

/// What an A32 or T32 instruction computes.
pub(crate) fn op_of(inst: &Instruction, operands: &[Operand]) -> il::Op {
    use il::Op;
    let unconditional = inst.condition == ConditionCode::AL;
    let loads_pc = operands.iter().any(|operand| {
        matches!(operand, Operand::RegList(list) if list & (1 << REG_PC) != 0)
            || matches!(operand, Operand::Reg(reg) if u16::from(reg.number()) == REG_PC)
    });
    match inst.opcode {
        Opcode::B if unconditional => Op::Jump,
        Opcode::B | Opcode::CBZ | Opcode::CBNZ => Op::Branch,
        Opcode::BL | Opcode::BLX => Op::Call,
        Opcode::BX | Opcode::BXJ => match operands.first() {
            Some(Operand::Reg(reg)) if u16::from(reg.number()) == REG_LR => Op::Return,
            _ => Op::Jump,
        },
        Opcode::TBB | Opcode::TBH => Op::Jump,
        // `pop {r4, pc}` loads the return address into the program counter.
        Opcode::POP | Opcode::LDM(..) if loads_pc => Op::Return,
        Opcode::MOV => Op::Move,
        Opcode::MVN => Op::Not,
        Opcode::MOVT | Opcode::UBFX | Opcode::SBFX | Opcode::BFI | Opcode::BFC => Op::BitField,
        Opcode::ADR => Op::Address,
        Opcode::ADD | Opcode::ADC => Op::Add,
        Opcode::SUB | Opcode::SBC | Opcode::RSB | Opcode::RSC => Op::Subtract,
        Opcode::MUL
        | Opcode::UMULL
        | Opcode::SMULL
        | Opcode::SMUL(..)
        | Opcode::SMULW(_)
        | Opcode::SMMUL
        | Opcode::SMUAD
        | Opcode::SMUSD => Op::Multiply,
        Opcode::MLA
        | Opcode::MLS
        | Opcode::UMLAL
        | Opcode::SMLAL
        | Opcode::SMLAL_halfword(..)
        | Opcode::UMAAL
        | Opcode::SMLA(..)
        | Opcode::SMLAW(_)
        | Opcode::SMLALD(_)
        | Opcode::SMLSLD(_)
        | Opcode::SMLAD
        | Opcode::SMLSD
        | Opcode::SMMLA
        | Opcode::SMMLS
        | Opcode::SMAL(..)
        | Opcode::USADA8 => Op::MultiplyAdd,
        Opcode::SDIV | Opcode::UDIV => Op::Divide,
        Opcode::AND => Op::And,
        Opcode::ORR => Op::Or,
        Opcode::EOR => Op::Xor,
        Opcode::BIC => Op::AndNot,
        Opcode::ORN => Op::OrNot,
        Opcode::LSL => Op::ShiftLeft,
        Opcode::LSR => Op::ShiftRight,
        Opcode::ASR => Op::ShiftRightArithmetic,
        Opcode::ROR | Opcode::RRX => Op::Rotate,
        Opcode::SXTB
        | Opcode::SXTH
        | Opcode::UXTB
        | Opcode::UXTH
        | Opcode::SXTAB
        | Opcode::SXTAH
        | Opcode::UXTAB
        | Opcode::UXTAH
        | Opcode::SXTB16
        | Opcode::UXTB16
        | Opcode::SXTAB16
        | Opcode::UXTAB16 => Op::Extend,
        Opcode::CLZ | Opcode::RBIT | Opcode::REV | Opcode::REV16 | Opcode::REVSH => Op::Bits,
        Opcode::SEL => Op::Select,
        Opcode::CMP | Opcode::CMN | Opcode::TST | Opcode::TEQ => Op::Compare,
        Opcode::SWP | Opcode::SWPB => Op::Atomic,
        Opcode::IT
        | Opcode::NOP
        | Opcode::HINT
        | Opcode::YIELD
        | Opcode::WFE
        | Opcode::WFI
        | Opcode::SEV
        | Opcode::CSDB
        | Opcode::DMB
        | Opcode::DSB
        | Opcode::ISB
        | Opcode::SVC
        | Opcode::BKPT
        | Opcode::MSR
        | Opcode::MRS
        | Opcode::CPS(_)
        | Opcode::CPS_modeonly
        | Opcode::SETEND
        | Opcode::CLREX
        | Opcode::UDF
        | Opcode::DBG
        | Opcode::PLD
        | Opcode::PLI
        | Opcode::HVC
        | Opcode::SMC
        | Opcode::ERET
        | Opcode::LDC(_)
        | Opcode::LDCL(_)
        | Opcode::LDC2(_)
        | Opcode::LDC2L(_)
        | Opcode::STC(_)
        | Opcode::STCL(_)
        | Opcode::STC2(_)
        | Opcode::STC2L(_)
        | Opcode::MCR2(..)
        | Opcode::MCRR2(..)
        | Opcode::MRC2(..)
        | Opcode::MRRC2(..)
        | Opcode::MCRR(..)
        | Opcode::MRRC(..)
        | Opcode::CDP2(..) => Op::System,
        Opcode::LDREX | Opcode::LDREXB | Opcode::LDREXH | Opcode::LDREXD => Op::Atomic,
        opcode => match role_of(opcode) {
            Role::Load { .. } => Op::Load,
            Role::StoreExclusive => Op::Atomic,
            Role::ReadOnly if matches!(opcode, Opcode::STM(..) | Opcode::PUSH) => Op::Store,
            Role::ReadOnly if memory_access(opcode, operands).is_some() => Op::Store,
            Role::ReadOnly | Role::Compute { .. } => Op::Other,
        },
    }
}

pub(crate) fn is_compare(opcode: Opcode) -> bool {
    matches!(opcode, Opcode::CMP | Opcode::CMN | Opcode::TST | Opcode::TEQ)
}

/// Instructions that keep part of their destination, so read it too.
pub(crate) fn reads_destination(opcode: Opcode) -> bool {
    matches!(
        opcode,
        Opcode::MOVT | Opcode::BFI | Opcode::BFC | Opcode::UMLAL | Opcode::SMLAL | Opcode::UMAAL
    )
}

pub(crate) fn role_of(opcode: Opcode) -> Role {
    match opcode {
        Opcode::LDR
        | Opcode::LDRB
        | Opcode::LDRH
        | Opcode::LDRSB
        | Opcode::LDRSH
        | Opcode::LDRT
        | Opcode::LDRBT
        | Opcode::LDRHT
        | Opcode::LDRSBT
        | Opcode::LDRSHT
        | Opcode::LDREX
        | Opcode::LDREXB
        | Opcode::LDREXH
        | Opcode::SWP
        | Opcode::SWPB => Role::Load { count: 1 },
        Opcode::LDRD | Opcode::LDREXD => Role::Load { count: 2 },
        Opcode::LDM(..) | Opcode::POP => Role::Load { count: 0 },
        Opcode::STREX | Opcode::STREXB | Opcode::STREXH | Opcode::STREXD => Role::StoreExclusive,
        Opcode::STR
        | Opcode::STRB
        | Opcode::STRH
        | Opcode::STRD
        | Opcode::STRT
        | Opcode::STRBT
        | Opcode::STRHT
        | Opcode::STM(..)
        | Opcode::PUSH
        | Opcode::CMP
        | Opcode::CMN
        | Opcode::TST
        | Opcode::TEQ
        | Opcode::B
        | Opcode::BL
        | Opcode::BLX
        | Opcode::BX
        | Opcode::BXJ
        | Opcode::CBZ
        | Opcode::CBNZ
        | Opcode::TBB
        | Opcode::TBH
        | Opcode::IT
        | Opcode::MSR
        | Opcode::PLD
        | Opcode::PLI
        | Opcode::SVC
        | Opcode::BKPT
        | Opcode::NOP
        | Opcode::HINT
        | Opcode::DMB
        | Opcode::DSB
        | Opcode::ISB => Role::ReadOnly,
        Opcode::UMULL | Opcode::SMULL | Opcode::UMLAL | Opcode::SMLAL | Opcode::UMAAL => {
            Role::Compute { count: 2 }
        }
        _ => Role::Compute { count: 1 },
    }
}

/// The text of an A32 or T32 instruction, as `yaxpeax-arm` 0.4 prints it
/// with two of its slips mended.
///
/// It prints the first source of a compare, which a compare has none of,
/// and a flag-setting `s` it always has: `cmp r3, r2` reads `cmps r0, r3,
/// r2`. It prints the first source of `mov` and `mvn` too, which they do
/// not read: `mvn r0, #0` reads `mvn r0, r0, 0x0`. Measured on Lua by GCC,
/// 2601 of 28304 instructions printed so. And it prints the
/// increment-before form of a load or store of a list, `ldmib`, as `ldmia`,
/// the name of increment-after, which it prints as `ldm`.
pub fn printed(inst: &Instruction) -> String {
    let text = inst.to_string();
    let (name, operands) = split_printed(&text);
    let condition = condition_name(inst.condition);
    let is_shift =
        |part: &str| ["lsl", "lsr", "asr", "ror", "rrx"].iter().any(|s| part.starts_with(s));
    let parts: Vec<&str> = operands.split(", ").collect();
    match inst.opcode {
        Opcode::CMP | Opcode::CMN | Opcode::TST | Opcode::TEQ if parts.len() >= 3 => {
            let base = format!("{:?}", inst.opcode).to_ascii_lowercase();
            format!("{base}{condition} {}", parts[1..].join(", "))
        }
        Opcode::MOV | Opcode::MVN if parts.iter().filter(|part| !is_shift(part)).count() > 2 => {
            let kept: Vec<&str> =
                parts.iter().enumerate().filter(|&(i, _)| i != 1).map(|(_, p)| *p).collect();
            format!("{name} {}", kept.join(", "))
        }
        Opcode::LDM(true, true, ..) | Opcode::STM(true, true, ..) => {
            let base = if matches!(inst.opcode, Opcode::LDM(..)) { "ldmib" } else { "stmib" };
            format!("{base}{condition} {operands}")
        }
        _ => text,
    }
}

/// The register `reg` names, where it is one the IL tracks: the program
/// counter is not.
pub(crate) fn il_reg(reg: Reg) -> Option<il::Reg> {
    match u16::from(reg.number()) {
        REG_PC => None,
        REG_SP => Some(il::Reg::Stack),
        number => Some(il::Reg::General(number as u8)),
    }
}

/// The registers an operand that is a value names.
pub(crate) fn value_registers(operand: Operand) -> il::RegSet {
    match operand {
        Operand::Reg(reg) | Operand::RegWBack(reg, _) => il_reg(reg).into_iter().collect(),
        Operand::RegShift(shift) => match shift.into_shift() {
            RegShiftStyle::RegImm(shift) => il_reg(shift.shiftee()).into_iter().collect(),
            RegShiftStyle::RegReg(shift) => {
                [il_reg(shift.shiftee()), il_reg(shift.shifter())].into_iter().flatten().collect()
            }
        },
        Operand::RegList(list) => (0..16_u8)
            .filter(|bit| list & (1 << bit) != 0)
            .filter_map(|bit| il_reg(Reg::from_u8(bit)))
            .collect(),
        _ => il::RegSet::EMPTY,
    }
}

/// The registers a memory operand reads to form its address, and the base
/// it writes back. A base in the list of `ldm` or `stm` is a value, and its
/// write back is read from the operand.
pub(crate) fn address_registers(operand: Operand, reads: &mut il::RegSet, writes: &mut il::RegSet) {
    let mut base = |reg: Reg, write_back: bool| {
        if let Some(reg) = il_reg(reg) {
            reads.insert(reg);
            if write_back {
                writes.insert(reg);
            }
        }
    };
    match operand {
        Operand::RegDeref(reg) => base(reg, false),
        Operand::RegWBack(reg, true) => base(reg, true),
        Operand::RegDerefPreindexOffset(reg, _, _, write_back) => base(reg, write_back),
        Operand::RegDerefPostindexOffset(reg, ..) => base(reg, true),
        Operand::RegDerefPreindexReg(reg, index, _, write_back) => {
            base(reg, write_back);
            il_reg(index).into_iter().for_each(|reg| reads.insert(reg));
        }
        Operand::RegDerefPostindexReg(reg, index, ..) => {
            base(reg, true);
            il_reg(index).into_iter().for_each(|reg| reads.insert(reg));
        }
        Operand::RegDerefPreindexRegShift(reg, shift, _, write_back) => {
            base(reg, write_back);
            value_registers(Operand::RegShift(shift)).iter().for_each(|reg| reads.insert(reg));
        }
        Operand::RegDerefPostindexRegShift(reg, shift, ..) => {
            base(reg, true);
            value_registers(Operand::RegShift(shift)).iter().for_each(|reg| reads.insert(reg));
        }
        _ => {}
    }
}

pub(crate) fn memory_access(opcode: Opcode, operands: &[Operand]) -> Option<il::MemoryAccess> {
    let kind = match role_of(opcode) {
        Role::Load { .. } if matches!(opcode, Opcode::SWP | Opcode::SWPB) => {
            il::AccessKind::LoadStore
        }
        Role::Load { .. } => il::AccessKind::Load,
        Role::StoreExclusive => il::AccessKind::Store,
        Role::ReadOnly if matches!(opcode, Opcode::STM(..) | Opcode::PUSH) => il::AccessKind::Store,
        Role::ReadOnly
            if operands.iter().any(|operand| {
                matches!(
                    operand,
                    Operand::RegDeref(_)
                        | Operand::RegDerefPreindexOffset(..)
                        | Operand::RegDerefPostindexOffset(..)
                        | Operand::RegDerefPreindexReg(..)
                        | Operand::RegDerefPostindexReg(..)
                        | Operand::RegDerefPreindexRegShift(..)
                        | Operand::RegDerefPostindexRegShift(..)
                )
            }) && !matches!(opcode, Opcode::PLD | Opcode::PLI | Opcode::TBB | Opcode::TBH) =>
        {
            il::AccessKind::Store
        }
        _ => return None,
    };
    let width = match opcode {
        Opcode::LDRB
        | Opcode::STRB
        | Opcode::LDRSB
        | Opcode::LDRBT
        | Opcode::STRBT
        | Opcode::LDRSBT
        | Opcode::LDREXB
        | Opcode::STREXB
        | Opcode::SWPB => Some(il::Width::Bits8),
        Opcode::LDRH
        | Opcode::STRH
        | Opcode::LDRSH
        | Opcode::LDRHT
        | Opcode::STRHT
        | Opcode::LDRSHT
        | Opcode::LDREXH
        | Opcode::STREXH => Some(il::Width::Bits16),
        Opcode::LDM(..) | Opcode::STM(..) | Opcode::PUSH | Opcode::POP => None,
        _ => Some(il::Width::Bits32),
    };
    Some(il::MemoryAccess { kind, width })
}

/// What an operand gives as a value. The program counter, and a register
/// shifted by something, are no one value.
pub(crate) fn value_of(operand: Operand) -> il::Value {
    match operand {
        Operand::Reg(reg) => il_reg(reg).map_or(il::Value::Other, il::Value::Reg),
        Operand::Imm32(value) => il::Value::Const(u64::from(value)),
        Operand::Imm12(value) => il::Value::Const(u64::from(value)),
        Operand::RegShift(shift) => match shift.into_shift() {
            RegShiftStyle::RegImm(shift)
                if shift.imm() == 0 && shift.stype() == ShiftStyle::LSL =>
            {
                il_reg(shift.shiftee()).map_or(il::Value::Other, il::Value::Reg)
            }
            _ => il::Value::Other,
        },
        _ => il::Value::Other,
    }
}

pub(crate) fn test_of(inst: &Instruction, operands: &[Operand]) -> Option<il::Test> {
    /// Every ARM general register is 32 bits wide.
    const WIDTH: il::Width = il::Width::Bits32;
    let value = |index: usize| operands.get(index).map_or(il::Value::Other, |op| value_of(*op));
    let guard = |cond| {
        Some(il::Test::Guard(il::Guard {
            cond,
            left: value(0),
            right: il::Value::Const(0),
            width: WIDTH,
        }))
    };
    let (left, right) = (value(0), value(1));
    let comparison = match inst.opcode {
        Opcode::B if inst.condition != ConditionCode::AL => {
            return Some(il::Test::OnFlags(il::Cond::from_arm(inst.condition as u8)));
        }
        Opcode::CBZ => return guard(il::Cond::Equal),
        Opcode::CBNZ => return guard(il::Cond::NotEqual),
        // A compare that only runs on a condition tests nothing on its own.
        _ if inst.condition != ConditionCode::AL => return None,
        Opcode::CMP => il::Comparison::Subtract { left, right },
        Opcode::TST => il::Comparison::And { left, right },
        // `cmn r, #k` sets the flags as `cmp r, #-k` does, for any `k` but zero.
        Opcode::CMN => match right {
            il::Value::Const(constant) if constant != 0 => il::Comparison::Subtract {
                left,
                right: il::Value::Const(constant.wrapping_neg() & WIDTH.mask()),
            },
            _ => il::Comparison::Add { left, right },
        },
        _ => return None,
    };
    Some(il::Test::Compare { comparison, width: WIDTH })
}

/// Read the words `yaxpeax` refuses that this crate knows: the hints, and
/// the VFP loads and stores.
///
/// A VFP load reads a constant pool as `ldr` does, so a scan must see it to
/// know the pool is data. Measured on tinyxml2 built by GCC for ARM,
/// `vldr d16, [pc, 0x90]` did not decode, its offset changed whenever an
/// alignment `nop` moved the pool, and that read as an edit.
pub fn decode_fallback(word: u32, encoding: Encoding) -> Option<(String, String, Decoded)> {
    const CONDITIONS: [&str; 15] =
        ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", ""];
    if word >> 24 == NEON_LOAD_STORE {
        let (name, operands) = decode_neon_load_store(word)?;
        let access = NeonAccess::of(word)?;
        let shape = NeonShape {
            transfer: Transfer::of(access.load),
            structures: access.structures as u8,
            size: access.size as u8,
        };
        return Some((name, operands, Decoded::NeonAccess(shape)));
    }

    let condition = *CONDITIONS.get((word >> 28) as usize)?;
    let condition_code = condition_of(word)?;
    let core = |opcode, flags| Decoded::Core { opcode, condition: condition_code, flags };

    // The hints: `nop`, `yield`, `wfe`, `wfi` and `sev`.
    if word & 0x0fff_ff00 == 0x0320_f000 {
        const HINTS: [(&str, Opcode); 5] = [
            ("nop", Opcode::NOP),
            ("yield", Opcode::YIELD),
            ("wfe", Opcode::WFE),
            ("wfi", Opcode::WFI),
            ("sev", Opcode::SEV),
        ];
        let (hint, opcode) = HINTS.get((word & 0xff) as usize)?;
        return Some((format!("{hint}{condition}"), String::new(), core(*opcode, Flags::Kept)));
    }

    if let Some(word) = IntegerWord::of(word).filter(|_| encoding == Encoding::A32) {
        let decoded = core(word.opcode(), word.flags());
        return Some((format!("{}{condition}", word.printed_name()), word.operands(), decoded));
    }
    if let Some(word) = VfpWord::of(word) {
        let (name, operands) = word.text();
        let decoded = Decoded::Vfp { vfp: word.kind(), condition: condition_code };
        return Some((format!("{name}{condition}"), operands, decoded));
    }

    // `vldr` and `vstr`: 1101 U D 0 L Rn Vd 101 sz imm8.
    if word >> 24 & 0xf == 0b1101 && word >> 21 & 1 == 0 && word >> 9 & 0b111 == 0b101 {
        let load = word >> 20 & 1 == 1;
        let up = word >> 23 & 1 == 1;
        let (d, vd) = (word >> 22 & 1, word >> 12 & 0xf);
        let register = if word >> 8 & 1 == 1 {
            format!("d{}", d << 4 | vd)
        } else {
            format!("s{}", vd << 1 | d)
        };
        let base = ARM_REGISTERS[(word >> 16 & 0xf) as usize];
        let offset = (word & 0xff) * 4;
        let reference = match (offset, up) {
            (0, _) => format!("[{base}]"),
            (_, true) => format!("[{base}, {offset:#x}]"),
            (_, false) => format!("[{base}, -{offset:#x}]"),
        };
        let (operation, vfp) = if load { ("vldr", Vfp::Load) } else { ("vstr", Vfp::Store) };
        return Some((
            format!("{operation}{condition}"),
            format!("{register}, {reference}"),
            Decoded::Vfp { vfp, condition: condition_code },
        ));
    }
    None
}

/// An A32 integer word `yaxpeax` 0.4 refuses, though ARMv7 defines it.
///
/// Measured on the backport fixtures built for A32 by clang and GCC at
/// `-O2`, these made 520 of the 1,690 words it could not read: the byte and
/// halfword extends, the bit field operations, `mov` and `mvn` of a register
/// shifted by a register, and a halfword or signed byte load with no offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IntegerWord {
    /// `uxtb rd, rm` and kin, which may add `rn` and rotate `rm` first.
    Extend { kind: Extend, rd: u32, rn: Option<u32>, rm: u32, rotation: u32 },
    /// `bfi rd, rn, lsb, width`, or `bfc` with no `rn`.
    Insert { rd: u32, rn: Option<u32>, lsb: u32, width: u32 },
    /// `ubfx rd, rn, lsb, width` and `sbfx`.
    Extract { signed: bool, rd: u32, rn: u32, lsb: u32, width: u32 },
    /// `mov rd, rm, lsl rs` and kin, or `mvn` of the same.
    ShiftByRegister { not: bool, sets_flags: bool, rd: u32, rm: u32, kind: u32, rs: u32 },
    /// `smulbb rd, rn, rm` and kin. `top_n` and `top_m` take the top
    /// halfword of `rn` and of `rm`. A long form names `rdlo` as `ra`.
    HalfwordMultiply {
        kind: HalfwordMultiply,
        top_n: bool,
        top_m: bool,
        rd: u32,
        ra: u32,
        rn: u32,
        rm: u32,
    },
    /// `ldrsb rt, [rn, imm]` and the other loads and stores of a halfword,
    /// a signed byte or a pair.
    Halfword { access: HalfwordAccess, rt: u32, rn: u32, offset: i64, index: Indexing },
}

/// Which extend an [`IntegerWord::Extend`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Extend {
    /// Sign-extends two bytes, each to a halfword.
    Sxtb16,
    /// Sign-extends a byte.
    Sxtb,
    /// Sign-extends a halfword.
    Sxth,
    /// Zero-extends two bytes, each to a halfword.
    Uxtb16,
    /// Zero-extends a byte.
    Uxtb,
    /// Zero-extends a halfword.
    Uxth,
}

impl Extend {
    fn name(self) -> &'static str {
        match self {
            Self::Sxtb16 => "sxtb16",
            Self::Sxtb => "sxtb",
            Self::Sxth => "sxth",
            Self::Uxtb16 => "uxtb16",
            Self::Uxtb => "uxtb",
            Self::Uxth => "uxth",
        }
    }

    /// The opcode, or the one that adds `rn` after the extend, as `uxtab`.
    fn opcode(self, adds: bool) -> Opcode {
        match (self, adds) {
            (Self::Sxtb16, false) => Opcode::SXTB16,
            (Self::Sxtb16, true) => Opcode::SXTAB16,
            (Self::Uxtb16, false) => Opcode::UXTB16,
            (Self::Uxtb16, true) => Opcode::UXTAB16,
            (Self::Sxtb, false) => Opcode::SXTB,
            (Self::Sxtb, true) => Opcode::SXTAB,
            (Self::Sxth, false) => Opcode::SXTH,
            (Self::Sxth, true) => Opcode::SXTAH,
            (Self::Uxtb, false) => Opcode::UXTB,
            (Self::Uxtb, true) => Opcode::UXTAB,
            (Self::Uxth, false) => Opcode::UXTH,
            (Self::Uxth, true) => Opcode::UXTAH,
        }
    }
}

/// Which load or store an [`IntegerWord::Halfword`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HalfwordAccess {
    Ldrh,
    Ldrsb,
    Ldrsh,
    Strh,
    Ldrd,
    Strd,
}

impl HalfwordAccess {
    fn name(self) -> &'static str {
        match self {
            Self::Ldrh => "ldrh",
            Self::Ldrsb => "ldrsb",
            Self::Ldrsh => "ldrsh",
            Self::Strh => "strh",
            Self::Ldrd => "ldrd",
            Self::Strd => "strd",
        }
    }

    fn opcode(self) -> Opcode {
        match self {
            Self::Ldrh => Opcode::LDRH,
            Self::Ldrsb => Opcode::LDRSB,
            Self::Ldrsh => Opcode::LDRSH,
            Self::Strh => Opcode::STRH,
            Self::Ldrd => Opcode::LDRD,
            Self::Strd => Opcode::STRD,
        }
    }

    fn is_load(self) -> bool {
        !matches!(self, Self::Strh | Self::Strd)
    }

    /// `ldrd` and `strd`, which move two registers.
    fn is_pair(self) -> bool {
        matches!(self, Self::Ldrd | Self::Strd)
    }

    fn width(self) -> il::Width {
        match self {
            Self::Ldrsb => il::Width::Bits8,
            Self::Ldrh | Self::Ldrsh | Self::Strh => il::Width::Bits16,
            Self::Ldrd | Self::Strd => il::Width::Bits32,
        }
    }
}

/// How a load or store forms its address and moves its base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Indexing {
    /// `[rn, imm]`: the base stays.
    Offset,
    /// `[rn, imm]!`: the base moves first.
    PreIndex,
    /// `[rn], imm`: the base moves after.
    PostIndex,
}

impl IntegerWord {
    fn of(word: u32) -> Option<Self> {
        let field = |shift: u32, width: u32| word >> shift & ((1 << width) - 1);
        let (rn, rd, rm) = (field(16, 4), field(12, 4), field(0, 4));
        // cond 0001 0 op 0 Rd Ra Rm 1 y x 0 Rn
        if field(23, 5) == 0b00010 && field(20, 1) == 0 && field(7, 1) == 1 && field(4, 1) == 0 {
            let (top_n, top_m) = (field(5, 1) == 1, field(6, 1) == 1);
            let kind = match (field(21, 2), top_n) {
                (0b00, _) => HalfwordMultiply::MultiplyAdd,
                // In the word forms, `x` chooses the form, not a halfword.
                (0b01, false) => HalfwordMultiply::WordMultiplyAdd,
                (0b01, true) => HalfwordMultiply::WordMultiply,
                (0b10, _) => HalfwordMultiply::LongMultiplyAdd,
                _ => HalfwordMultiply::Multiply,
            };
            let top_n = top_n && !matches!(field(21, 2), 0b01);
            return Some(Self::HalfwordMultiply {
                kind,
                top_n,
                top_m,
                rd: field(16, 4),
                ra: field(12, 4),
                rn: field(0, 4),
                rm: field(8, 4),
            });
        }
        if field(23, 5) == 0b01101 && field(4, 4) == 0b0111 && field(8, 2) == 0 {
            let kind = match field(20, 3) {
                0b000 => Extend::Sxtb16,
                0b010 => Extend::Sxtb,
                0b011 => Extend::Sxth,
                0b100 => Extend::Uxtb16,
                0b110 => Extend::Uxtb,
                0b111 => Extend::Uxth,
                _ => return None,
            };
            let rn = (rn != 15).then_some(rn);
            return Some(Self::Extend { kind, rd, rn, rm, rotation: field(10, 2) * 8 });
        }
        if field(21, 7) == 0b011_1110 && field(4, 3) == 0b001 {
            let (msb, lsb) = (field(16, 5), field(7, 5));
            let width = msb.checked_sub(lsb)? + 1;
            return Some(Self::Insert { rd, rn: (rm != 15).then_some(rm), lsb, width });
        }
        if field(23, 5) == 0b01111 && field(21, 1) == 1 && field(4, 3) == 0b101 {
            let (lsb, width) = (field(7, 5), field(16, 5) + 1);
            return Some(Self::Extract { signed: field(22, 1) == 0, rd, rn: rm, lsb, width });
        }
        let move_op = field(21, 4);
        if field(25, 3) == 0
            && matches!(move_op, 0b1101 | 0b1111)
            && field(7, 1) == 0
            && field(4, 1) == 1
            && rn == 0
        {
            return Some(Self::ShiftByRegister {
                not: move_op == 0b1111,
                sets_flags: field(20, 1) == 1,
                rd,
                rm,
                kind: field(5, 2),
                rs: field(8, 4),
            });
        }
        if field(25, 3) == 0 && field(22, 1) == 1 && field(7, 1) == 1 && field(4, 1) == 1 {
            let access = match (field(20, 1), field(5, 2)) {
                (1, 0b01) => HalfwordAccess::Ldrh,
                (1, 0b10) => HalfwordAccess::Ldrsb,
                (1, 0b11) => HalfwordAccess::Ldrsh,
                (0, 0b01) => HalfwordAccess::Strh,
                (0, 0b10) => HalfwordAccess::Ldrd,
                (0, 0b11) => HalfwordAccess::Strd,
                _ => return None,
            };
            let magnitude = i64::from(field(8, 4) << 4 | field(0, 4));
            let offset = if field(23, 1) == 1 { magnitude } else { -magnitude };
            let index = match (field(24, 1), field(21, 1)) {
                (1, 0) => Indexing::Offset,
                (1, 1) => Indexing::PreIndex,
                (0, 0) => Indexing::PostIndex,
                _ => return None,
            };
            return Some(Self::Halfword { access, rt: rd, rn, offset, index });
        }
        None
    }

    /// The opcode `yaxpeax-arm` names this operation by.
    pub fn opcode(self) -> Opcode {
        match self {
            Self::Extend { kind, rn, .. } => kind.opcode(rn.is_some()),
            Self::Insert { rn: Some(_), .. } => Opcode::BFI,
            Self::Insert { rn: None, .. } => Opcode::BFC,
            Self::Extract { signed: true, .. } => Opcode::SBFX,
            Self::Extract { signed: false, .. } => Opcode::UBFX,
            Self::ShiftByRegister { not: true, .. } => Opcode::MVN,
            Self::ShiftByRegister { not: false, .. } => Opcode::MOV,
            Self::HalfwordMultiply { kind, top_n, top_m, .. } => match kind {
                HalfwordMultiply::Multiply => Opcode::SMUL(top_n, top_m),
                HalfwordMultiply::MultiplyAdd => Opcode::SMLA(top_n, top_m),
                HalfwordMultiply::WordMultiply => Opcode::SMULW(top_m),
                HalfwordMultiply::WordMultiplyAdd => Opcode::SMLAW(top_m),
                HalfwordMultiply::LongMultiplyAdd => Opcode::SMLAL_halfword(top_n, top_m),
            },
            Self::Halfword { access, .. } => access.opcode(),
        }
    }

    pub fn flags(self) -> Flags {
        match self {
            Self::ShiftByRegister { sets_flags, .. } => Flags::of(sets_flags),
            _ => Flags::Kept,
        }
    }

    pub fn printed_name(self) -> String {
        match self {
            Self::Extend { kind, rn: None, .. } => kind.name().to_string(),
            // `uxtab` adds the extended value to `rn`.
            Self::Extend { kind, rn: Some(_), .. } => {
                let name = kind.name();
                format!("{}a{}", &name[..3], &name[3..])
            }
            Self::Insert { rn: Some(_), .. } => "bfi".into(),
            Self::Insert { rn: None, .. } => "bfc".into(),
            Self::Extract { signed: true, .. } => "sbfx".into(),
            Self::Extract { signed: false, .. } => "ubfx".into(),
            Self::ShiftByRegister { not, sets_flags, .. } => {
                format!("{}{}", if not { "mvn" } else { "mov" }, if sets_flags { "s" } else { "" })
            }
            Self::HalfwordMultiply { kind, top_n, top_m, .. } => {
                let half = |top: bool| if top { 't' } else { 'b' };
                match kind {
                    HalfwordMultiply::Multiply => format!("smul{}{}", half(top_n), half(top_m)),
                    HalfwordMultiply::MultiplyAdd => format!("smla{}{}", half(top_n), half(top_m)),
                    HalfwordMultiply::WordMultiply => format!("smulw{}", half(top_m)),
                    HalfwordMultiply::WordMultiplyAdd => format!("smlaw{}", half(top_m)),
                    HalfwordMultiply::LongMultiplyAdd => {
                        format!("smlal{}{}", half(top_n), half(top_m))
                    }
                }
            }
            Self::Halfword { access, .. } => access.name().into(),
        }
    }

    pub fn operands(self) -> String {
        let name = |number: u32| ARM_REGISTERS[number as usize];
        match self {
            Self::Extend { rd, rn, rm, rotation, .. } => {
                let added = rn.map(|rn| format!("{}, ", name(rn))).unwrap_or_default();
                let rotated =
                    if rotation == 0 { String::new() } else { format!(", ror {rotation:#x}") };
                format!("{}, {added}{}{rotated}", name(rd), name(rm))
            }
            Self::Insert { rd, rn, lsb, width } => {
                let source = rn.map(|rn| format!("{}, ", name(rn))).unwrap_or_default();
                format!("{}, {source}{lsb:#x}, {width:#x}", name(rd))
            }
            Self::Extract { rd, rn, lsb, width, .. } => {
                format!("{}, {}, {lsb:#x}, {width:#x}", name(rd), name(rn))
            }
            Self::ShiftByRegister { rd, rm, kind, rs, .. } => {
                let shift = ["lsl", "lsr", "asr", "ror"][kind as usize];
                format!("{}, {}, {shift} {}", name(rd), name(rm), name(rs))
            }
            Self::HalfwordMultiply { kind, rd, ra, rn, rm, .. } => {
                let (rd, ra, rn, rm) = (name(rd), name(ra), name(rn), name(rm));
                match kind {
                    HalfwordMultiply::Multiply | HalfwordMultiply::WordMultiply => {
                        format!("{rd}, {rn}, {rm}")
                    }
                    HalfwordMultiply::MultiplyAdd | HalfwordMultiply::WordMultiplyAdd => {
                        format!("{rd}, {rn}, {rm}, {ra}")
                    }
                    HalfwordMultiply::LongMultiplyAdd => format!("{ra}, {rd}, {rn}, {rm}"),
                }
            }
            Self::Halfword { access, rt, rn, offset, index } => {
                let pair = if access.is_pair() {
                    format!("{}, ", name((rt + 1) & 15))
                } else {
                    String::new()
                };
                let amount = if offset < 0 {
                    format!("-{:#x}", offset.unsigned_abs())
                } else {
                    format!("{offset:#x}")
                };
                let base = name(rn);
                let address = match (index, offset) {
                    (Indexing::Offset, 0) => format!("[{base}]"),
                    (Indexing::Offset, _) => format!("[{base}, {amount}]"),
                    (Indexing::PreIndex, _) => format!("[{base}, {amount}]!"),
                    (Indexing::PostIndex, _) => format!("[{base}], {amount}"),
                };
                format!("{}, {pair}{address}", name(rt))
            }
        }
    }

    /// The name of each operand that [`IntegerWord::lift`] gives, as
    /// [`IntegerWord::operands`] prints it.
    pub fn names(self) -> il::Names {
        use compact_str::format_compact;
        let name = |number: u32| CompactString::from(ARM_REGISTERS[number as usize]);
        let hex = |value: u32| format_compact!("{value:#x}");
        match self {
            Self::Extend { rd, rn, rm, rotation, .. } => {
                let rotated = match rotation {
                    0 => name(rm),
                    _ => format_compact!("({} ror {rotation:#x})", name(rm)),
                };
                [Some(name(rd)), rn.map(name), Some(rotated)].into_iter().flatten().collect()
            }
            Self::Insert { rd, rn, lsb, width } => {
                [Some(name(rd)), rn.map(name), Some(hex(lsb)), Some(hex(width))]
                    .into_iter()
                    .flatten()
                    .collect()
            }
            Self::Extract { rd, rn, lsb, width, .. } => {
                [name(rd), name(rn), hex(lsb), hex(width)].into_iter().collect()
            }
            Self::ShiftByRegister { rd, rm, rs, .. } => {
                [name(rd), name(rm), name(rs)].into_iter().collect()
            }
            // As the lift lists them: written first, then each read that is
            // not written.
            Self::HalfwordMultiply { kind, rd, ra, rn, rm, .. } => {
                let (written, read_too): (&[u32], &[u32]) = match kind {
                    HalfwordMultiply::Multiply | HalfwordMultiply::WordMultiply => {
                        (&[rd], &[rn, rm])
                    }
                    HalfwordMultiply::MultiplyAdd | HalfwordMultiply::WordMultiplyAdd => {
                        (&[rd], &[rn, rm, ra])
                    }
                    HalfwordMultiply::LongMultiplyAdd => (&[ra, rd], &[ra, rd, rn, rm]),
                };
                let listed = written.iter().chain(read_too.iter().filter(|r| !written.contains(r)));
                listed.map(|&number| name(number)).collect()
            }
            Self::Halfword { access, rt, rn, offset, index } => {
                let pair = access.is_pair().then(|| name((rt + 1) & 15));
                let base = name(rn);
                let address = match (index, offset) {
                    (Indexing::PostIndex, _) | (_, 0) => format_compact!("[{base}]"),
                    (_, offset) if offset < 0 => {
                        format_compact!("[{base} - {:#x}]", offset.unsigned_abs())
                    }
                    (_, offset) => format_compact!("[{base} + {offset:#x}]"),
                };
                [Some(name(rt)), pair, Some(address)].into_iter().flatten().collect()
            }
        }
    }

    /// What a post-index access of this word adds to its base after it.
    fn write_back(self) -> Option<CompactString> {
        use compact_str::format_compact;
        match self {
            Self::Halfword { index: Indexing::PostIndex, offset, .. } if offset < 0 => {
                Some(format_compact!("-{:#x}", offset.unsigned_abs()))
            }
            Self::Halfword { index: Indexing::PostIndex, offset, .. } => {
                Some(format_compact!("{offset:#x}"))
            }
            _ => None,
        }
    }

    /// The IL form of this word, as [`lift_named`] gives for the words `yaxpeax`
    /// reads.
    pub fn lift(self) -> il::Lifted {
        use il::Op;
        let general = |number: u32| il_reg(Reg::from_u8(number as u8));
        let value = |number: u32| general(number).map_or(il::Operand::Other, il::Operand::Reg);
        let constant = |value: u32| il::Operand::Const(value.into());
        let mut lifted = il::Lifted::default();
        let read = |lifted: &mut il::Lifted, number: u32| {
            general(number).into_iter().for_each(|reg| lifted.reads.insert(reg));
        };
        let write = |lifted: &mut il::Lifted, number: u32| {
            general(number).into_iter().for_each(|reg| lifted.writes.insert(reg));
        };
        match self {
            Self::Extend { rd, rn, rm, .. } => {
                lifted.op = Op::Extend;
                lifted.operands = [Some(value(rd)), rn.map(value), Some(value(rm))]
                    .into_iter()
                    .flatten()
                    .collect();
                rn.into_iter().chain([rm]).for_each(|number| read(&mut lifted, number));
                write(&mut lifted, rd);
            }
            Self::Insert { rd, rn, lsb, width } => {
                lifted.op = Op::BitField;
                lifted.operands =
                    [Some(value(rd)), rn.map(value), Some(constant(lsb)), Some(constant(width))]
                        .into_iter()
                        .flatten()
                        .collect();
                // An insert keeps the bits around its field.
                rn.into_iter().chain([rd]).for_each(|number| read(&mut lifted, number));
                write(&mut lifted, rd);
            }
            Self::Extract { rd, rn, lsb, width, .. } => {
                lifted.op = Op::BitField;
                lifted.operands =
                    [value(rd), value(rn), constant(lsb), constant(width)].into_iter().collect();
                read(&mut lifted, rn);
                write(&mut lifted, rd);
            }
            Self::ShiftByRegister { not, sets_flags, rd, rm, kind, rs } => {
                lifted.op = match (not, kind) {
                    (true, _) => Op::Not,
                    (false, 0) => Op::ShiftLeft,
                    (false, 1) => Op::ShiftRight,
                    (false, 2) => Op::ShiftRightArithmetic,
                    (false, _) => Op::Rotate,
                };
                lifted.operands = [value(rd), value(rm), value(rs)].into_iter().collect();
                [rm, rs].into_iter().for_each(|number| read(&mut lifted, number));
                write(&mut lifted, rd);
                if sets_flags {
                    lifted.writes.insert(il::Reg::Flags);
                }
            }
            Self::HalfwordMultiply { kind, rd, ra, rn, rm, .. } => {
                // Written first, then read, as the operands list them.
                let (written, read_too): (&[u32], &[u32]) = match kind {
                    HalfwordMultiply::Multiply | HalfwordMultiply::WordMultiply => {
                        lifted.op = Op::Multiply;
                        (&[rd], &[rn, rm])
                    }
                    HalfwordMultiply::MultiplyAdd | HalfwordMultiply::WordMultiplyAdd => {
                        lifted.op = Op::MultiplyAdd;
                        (&[rd], &[rn, rm, ra])
                    }
                    // The sum is in the pair it adds to, low then high.
                    HalfwordMultiply::LongMultiplyAdd => {
                        lifted.op = Op::MultiplyAdd;
                        (&[ra, rd], &[ra, rd, rn, rm])
                    }
                };
                let listed = written.iter().chain(read_too.iter().filter(|r| !written.contains(r)));
                lifted.operands = listed.map(|&number| value(number)).collect();
                read_too.iter().for_each(|&number| read(&mut lifted, number));
                written.iter().for_each(|&number| write(&mut lifted, number));
            }
            Self::Halfword { access, rt, rn, offset, index } => {
                let load = access.is_load();
                let pair = access.is_pair();
                let width = access.width();
                let values: Vec<u32> = if pair { vec![rt, (rt + 1) & 15] } else { vec![rt] };
                let at = match index {
                    Indexing::PostIndex => 0,
                    Indexing::Offset | Indexing::PreIndex => offset,
                };
                let update = match index {
                    Indexing::PostIndex => il::Update::After,
                    Indexing::Offset | Indexing::PreIndex => il::Update::None,
                };
                let memory = il::Operand::Memory {
                    base: Some(operand_general(rn)),
                    offset: Some(at),
                    index: None,
                    update,
                };
                lifted.op = if load { Op::Load } else { Op::Store };
                lifted.operands =
                    values.iter().map(|&number| value(number)).chain([memory]).collect();
                read(&mut lifted, rn);
                for &number in &values {
                    if load { write(&mut lifted, number) } else { read(&mut lifted, number) }
                }
                if index != Indexing::Offset {
                    write(&mut lifted, rn);
                }
                let kind = if load { il::AccessKind::Load } else { il::AccessKind::Store };
                lifted.memory = Some(il::MemoryAccess { kind, width: Some(width) });
            }
        }
        lifted
    }
}

/// Whether `yaxpeax` 0.4 reads the A32 `word` but prints it wrong, so that
/// [`decode_fallback`] and [`lift_fallback`] read it instead.
///
/// It reads the VFP data processing words, but loses operands: `vmov.f32 s1,
/// #1.0` prints as `vmov.f32 s1`, `vmov.f64 d16, d8` as `vmov.f64 d16`, and
/// `vcvt.f64.u32 d0, s0` as `vmov.f64 d0`. An edit to what they read then
/// shows as no change.
///
/// In A32 it swaps `bb` and `tt` of the multiplies of halfwords, so that
/// `smulbb` reads as `smultt`, and reads `smulwb` as `smlawb`.
pub(crate) fn decoder_misreads(word: u32, encoding: Encoding) -> bool {
    let vfp =
        matches!(VfpWord::of(word), Some(VfpWord::Compute { .. } | VfpWord::MoveConstant { .. }));
    let multiply = encoding == Encoding::A32
        && matches!(IntegerWord::of(word), Some(IntegerWord::HalfwordMultiply { .. }));
    word >> 28 != 0b1111 && (vfp || multiply)
}

/// Which multiply of halfwords an A32 word is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HalfwordMultiply {
    /// `smulbb rd, rn, rm`: a halfword of each.
    Multiply,
    /// `smlabb rd, rn, rm, ra`: the product, plus `ra`.
    MultiplyAdd,
    /// `smulwb rd, rn, rm`: all of `rn` by a halfword of `rm`, the top 32
    /// bits of the 48.
    WordMultiply,
    /// `smlawb rd, rn, rm, ra`: the same, plus `ra`.
    WordMultiplyAdd,
    /// `smlalbb rdlo, rdhi, rn, rm`: the product, added to a 64-bit value.
    LongMultiplyAdd,
}

/// A VFP word `yaxpeax` 0.4 refuses: the moves between core and VFP
/// registers, the multiple loads and stores, and the data processing.
///
/// Measured on the backport fixtures built for A32 by clang and GCC at
/// `-O2`, these made 620 of the 1,690 words it could not read. A
/// `-mfloat-abi=softfp` build moves every double argument and result
/// through core registers, so `vmov d16, r0, r1` is common.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VfpWord {
    /// `vmov s0, r1` or `vmov r0, s0`.
    MoveSingle { to_core: bool, core: u32, single: u32 },
    /// `vmov d16, r0, r1` or `vmov r0, r1, d16`.
    MoveDouble { to_core: bool, low: u32, high: u32, double: u32 },
    /// `vmrs rt, fpscr`. `rt` 15 moves the compare flags to the core flags.
    StatusToCore { core: u32 },
    /// `vldmia rn!, {d8, d9}` and kin. `vpush` and `vpop` are the forms
    /// on `sp` that `push` and `pop` are.
    Multiple {
        load: bool,
        base: u32,
        write_back: bool,
        before: bool,
        first: u32,
        count: u32,
        double: bool,
    },
    /// The arithmetic, compares and conversions. A conversion names its
    /// sizes in `name`, as `vcvt.s32.f64`; the rest take `size`.
    Compute {
        operation: VfpOperation,
        size: &'static str,
        dest: Vector,
        sources: [Option<Vector>; 2],
    },
    /// `vmov.f32 s0, #1.0`: a constant of 8 bits, which a few floats fit.
    MoveConstant { dest: Vector, bits: u64 },
}

/// What a VFP data processing word computes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VfpOperation {
    /// `vmla`: adds the product to the destination.
    Vmla,
    /// `vmls`: subtracts the product from the destination.
    Vmls,
    /// `vnmls`: subtracts the destination from the product.
    Vnmls,
    /// `vnmla`: adds the destination to the product, and negates the sum.
    Vnmla,
    /// `vmul`: multiplies.
    Vmul,
    /// `vnmul`: multiplies, and negates the product.
    Vnmul,
    /// `vadd`: adds.
    Vadd,
    /// `vsub`: subtracts.
    Vsub,
    /// `vdiv`: divides.
    Vdiv,
    /// `vmov`: copies a register.
    Vmov,
    /// `vabs`: takes the magnitude.
    Vabs,
    /// `vneg`: negates.
    Vneg,
    /// `vsqrt`: takes the square root.
    Vsqrt,
    /// `vcmp`: compares.
    Vcmp,
    /// `vcmpe`: compares, and raises an exception on a NaN.
    Vcmpe,
    /// `vcvt` and `vcvtr`. The name holds the sizes, as `vcvt.s32.f64`.
    Convert {
        /// The name, as `vcvt.s32.f64`.
        name: &'static str,
        /// How the conversion rounds.
        rounding: Rounding,
    },
}

/// How a VFP conversion rounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rounding {
    /// Between `f32` and `f64`, or from an integer.
    Exact,
    /// To an integer, toward zero: `vcvt`.
    TowardZero,
    /// To an integer, as the status register says: `vcvtr`.
    AsStatus,
}

impl VfpOperation {
    fn name(self) -> &'static str {
        match self {
            Self::Vmla => "vmla",
            Self::Vmls => "vmls",
            Self::Vnmls => "vnmls",
            Self::Vnmla => "vnmla",
            Self::Vmul => "vmul",
            Self::Vnmul => "vnmul",
            Self::Vadd => "vadd",
            Self::Vsub => "vsub",
            Self::Vdiv => "vdiv",
            Self::Vmov => "vmov",
            Self::Vabs => "vabs",
            Self::Vneg => "vneg",
            Self::Vsqrt => "vsqrt",
            Self::Vcmp => "vcmp",
            Self::Vcmpe => "vcmpe",
            Self::Convert { name, .. } => name,
        }
    }

    fn is_compare(self) -> bool {
        matches!(self, Self::Vcmp | Self::Vcmpe)
    }

    /// `vmla` and kin, which add to their destination.
    fn adds_to_destination(self) -> bool {
        matches!(self, Self::Vmla | Self::Vmls | Self::Vnmla | Self::Vnmls)
    }

    /// What this computes. `vcvt` to an integer rounds toward zero, and
    /// `vcvtr` as the status register says.
    fn op(self) -> il::Op {
        use il::Op;
        match self {
            Self::Vmov => Op::Move,
            Self::Vadd => Op::FloatAdd,
            Self::Vsub => Op::FloatSubtract,
            Self::Vmul | Self::Vnmul => Op::FloatMultiply,
            Self::Vmla | Self::Vmls | Self::Vnmla | Self::Vnmls => Op::FloatMultiplyAdd,
            Self::Vdiv => Op::FloatDivide,
            Self::Vneg | Self::Vabs => Op::FloatSign,
            Self::Vsqrt => Op::FloatSquareRoot,
            Self::Vcmp | Self::Vcmpe => Op::Float,
            Self::Convert { rounding: Rounding::AsStatus, .. } => Op::FloatRoundNearest,
            Self::Convert { rounding: Rounding::TowardZero, .. } => Op::FloatRoundTowardZero,
            Self::Convert { rounding: Rounding::Exact, .. } => Op::FloatConvert,
        }
    }
}

/// A VFP register: `d` where `double`, else `s`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    double: bool,
    number: u32,
}

impl Vector {
    fn text(self) -> String {
        format!("{}{}", if self.double { 'd' } else { 's' }, self.number)
    }
}

impl VfpWord {
    fn of(word: u32) -> Option<Self> {
        let field = |shift: u32, width: u32| word >> shift & ((1 << width) - 1);
        let single = |high: u32, low: u32| high << 1 | low;
        let double = |high: u32, low: u32| low << 4 | high;
        let is_double = field(8, 1) == 1;
        let register =
            |four: u32, one: u32| if is_double { double(four, one) } else { single(four, one) };
        if field(21, 7) == 0b111_0000 && field(8, 4) == 0b1010 && field(0, 7) == 0b001_0000 {
            let to_core = field(20, 1) == 1;
            return Some(Self::MoveSingle {
                to_core,
                core: field(12, 4),
                single: single(field(16, 4), field(7, 1)),
            });
        }
        if field(21, 7) == 0b110_0010
            && field(8, 4) == 0b1011
            && field(6, 2) == 0
            && field(4, 1) == 1
        {
            return Some(Self::MoveDouble {
                to_core: field(20, 1) == 1,
                low: field(12, 4),
                high: field(16, 4),
                double: double(field(0, 4), field(5, 1)),
            });
        }
        if word & 0x0fff_0fff == 0x0ef1_0a10 {
            return Some(Self::StatusToCore { core: field(12, 4) });
        }
        if field(25, 3) == 0b110 && field(9, 3) == 0b101 {
            let (before, up, write_back) =
                (field(24, 1) == 1, field(23, 1) == 1, field(21, 1) == 1);
            // `before` without write back is `vldr` or `vstr`, and the rest
            // of the pairs are no access.
            if before == up || (before && !write_back) {
                return None;
            }
            let count = if is_double { field(1, 7) } else { field(0, 8) };
            if count == 0 {
                return None;
            }
            return Some(Self::Multiple {
                load: field(20, 1) == 1,
                base: field(16, 4),
                write_back,
                before,
                first: register(field(12, 4), field(22, 1)),
                count,
                double: is_double,
            });
        }
        if field(24, 4) == 0b1110 && field(4, 1) == 0 && field(9, 3) == 0b101 {
            let sized = |four: u32, one: u32, double: bool| Vector {
                double,
                number: if double { one << 4 | four } else { four << 1 | one },
            };
            let (vd, d, vn, n, vm, m) =
                (field(12, 4), field(22, 1), field(16, 4), field(7, 1), field(0, 4), field(5, 1));
            let dest = sized(vd, d, is_double);
            let both = [Some(sized(vn, n, is_double)), Some(sized(vm, m, is_double))];
            let one = [Some(sized(vm, m, is_double)), None];
            let size = if is_double { "f64" } else { "f32" };
            let float = |operation, sources| Some(Self::Compute { operation, size, dest, sources });
            let convert = |name, rounding| VfpOperation::Convert { name, rounding };
            return match (field(23, 1) << 2 | field(20, 2), field(6, 1)) {
                (0b000, 0) => float(VfpOperation::Vmla, both),
                (0b000, _) => float(VfpOperation::Vmls, both),
                (0b001, 0) => float(VfpOperation::Vnmls, both),
                (0b001, _) => float(VfpOperation::Vnmla, both),
                (0b010, 0) => float(VfpOperation::Vmul, both),
                (0b010, _) => float(VfpOperation::Vnmul, both),
                (0b011, 0) => float(VfpOperation::Vadd, both),
                (0b011, _) => float(VfpOperation::Vsub, both),
                (0b100, 0) => float(VfpOperation::Vdiv, both),
                (0b111, 0) => {
                    let constant = field(16, 4) << 4 | field(0, 4);
                    Some(Self::MoveConstant {
                        dest,
                        bits: expand_float_constant(constant, is_double),
                    })
                }
                (0b111, _) => match (field(16, 4), field(7, 1)) {
                    (0b0000, 0) => float(VfpOperation::Vmov, one),
                    (0b0000, _) => float(VfpOperation::Vabs, one),
                    (0b0001, 0) => float(VfpOperation::Vneg, one),
                    (0b0001, _) => float(VfpOperation::Vsqrt, one),
                    (0b0100, 0) => float(VfpOperation::Vcmp, one),
                    (0b0100, _) => float(VfpOperation::Vcmpe, one),
                    (0b0101, 0) => float(VfpOperation::Vcmp, [None, None]),
                    (0b0101, _) => float(VfpOperation::Vcmpe, [None, None]),
                    // Between `f32` and `f64`: the result is the other size.
                    (0b0111, 1) => {
                        let name = if is_double { "vcvt.f32.f64" } else { "vcvt.f64.f32" };
                        Some(Self::Compute {
                            operation: convert(name, Rounding::Exact),
                            size: "",
                            dest: sized(vd, d, !is_double),
                            sources: one,
                        })
                    }
                    // From a 32-bit integer in an `s` register.
                    (0b1000, signed) => {
                        let name = match (is_double, signed) {
                            (true, 1) => "vcvt.f64.s32",
                            (true, _) => "vcvt.f64.u32",
                            (false, 1) => "vcvt.f32.s32",
                            (false, _) => "vcvt.f32.u32",
                        };
                        let source = [Some(sized(vm, m, false)), None];
                        let operation = convert(name, Rounding::Exact);
                        Some(Self::Compute { operation, size: "", dest, sources: source })
                    }
                    // To a 32-bit integer in an `s` register. A clear bit 7
                    // rounds as the status register says, which `vcvtr` names.
                    (opc2 @ (0b1100 | 0b1101), toward_zero) => {
                        let name = match (opc2, toward_zero, is_double) {
                            (0b1101, 1, true) => "vcvt.s32.f64",
                            (0b1101, 1, false) => "vcvt.s32.f32",
                            (0b1101, _, true) => "vcvtr.s32.f64",
                            (0b1101, _, false) => "vcvtr.s32.f32",
                            (_, 1, true) => "vcvt.u32.f64",
                            (_, 1, false) => "vcvt.u32.f32",
                            (_, _, true) => "vcvtr.u32.f64",
                            (_, _, false) => "vcvtr.u32.f32",
                        };
                        let rounding = if toward_zero == 1 {
                            Rounding::TowardZero
                        } else {
                            Rounding::AsStatus
                        };
                        Some(Self::Compute {
                            operation: convert(name, rounding),
                            size: "",
                            dest: sized(vd, d, false),
                            sources: one,
                        })
                    }
                    _ => None,
                },
                _ => None,
            };
        }
        None
    }

    fn kind(self) -> Vfp {
        match self {
            Self::MoveSingle { .. } => Vfp::Move,
            Self::MoveDouble { .. } => Vfp::MoveDouble,
            Self::StatusToCore { .. } => Vfp::Status,
            // As `text` names them.
            Self::Multiple { load: false, base: 13, write_back: true, before: true, .. } => {
                Vfp::Push
            }
            Self::Multiple { load: true, base: 13, write_back: true, before: false, .. } => {
                Vfp::Pop
            }
            Self::Multiple { before: true, load, .. } => {
                Vfp::Multiple(Step::DecrementBefore, Transfer::of(load))
            }
            Self::Multiple { before: false, load, .. } => {
                Vfp::Multiple(Step::IncrementAfter, Transfer::of(load))
            }
            Self::Compute { operation, size, .. } if operation.is_compare() => {
                Vfp::Compare { operation, size }
            }
            Self::Compute { operation, size, .. } => Vfp::Compute { operation, size },
            Self::MoveConstant { dest, .. } => Vfp::Compute {
                operation: VfpOperation::Vmov,
                size: if dest.double { "f64" } else { "f32" },
            },
        }
    }

    fn text(self) -> (String, String) {
        let vector = |double: bool, number: u32| {
            if double { format!("d{number}") } else { format!("s{number}") }
        };
        let core = |number: u32| ARM_REGISTERS[number as usize];
        match self {
            Self::MoveSingle { to_core: true, core: rt, single } => {
                ("vmov".into(), format!("{}, s{single}", core(rt)))
            }
            Self::MoveSingle { to_core: false, core: rt, single } => {
                ("vmov".into(), format!("s{single}, {}", core(rt)))
            }
            Self::MoveDouble { to_core: true, low, high, double } => {
                ("vmov".into(), format!("{}, {}, d{double}", core(low), core(high)))
            }
            Self::MoveDouble { to_core: false, low, high, double } => {
                ("vmov".into(), format!("d{double}, {}, {}", core(low), core(high)))
            }
            Self::StatusToCore { core: 15 } => ("vmrs".into(), "APSR_nzcv, fpscr".into()),
            Self::StatusToCore { core: rt } => ("vmrs".into(), format!("{}, fpscr", core(rt))),
            Self::Multiple { load, base, write_back, before, first, count, double } => {
                let list: Vec<String> =
                    (first..first + count).map(|number| vector(double, number)).collect();
                let list = format!("{{{}}}", list.join(", "));
                match (load, base, write_back, before) {
                    (false, 13, true, true) => ("vpush".into(), list),
                    (true, 13, true, false) => ("vpop".into(), list),
                    _ => {
                        let name = format!(
                            "v{}m{}",
                            if load { "ld" } else { "st" },
                            if before { "db" } else { "ia" }
                        );
                        let bang = if write_back { "!" } else { "" };
                        (name, format!("{}{bang}, {list}", core(base)))
                    }
                }
            }
            Self::MoveConstant { dest, bits } => {
                let value = if dest.double {
                    f64::from_bits(bits)
                } else {
                    f64::from(f32::from_bits(bits as u32))
                };
                let size = if dest.double { "f64" } else { "f32" };
                (format!("vmov.{size}"), format!("{}, #{value:?}", dest.text()))
            }
            Self::Compute { operation, size, dest, sources } => {
                let mut operands = vec![dest.text()];
                operands.extend(sources.iter().flatten().map(|source| source.text()));
                if operation.is_compare() && sources == [None, None] {
                    operands.push("0x0".into());
                }
                let name = operation.name();
                let name =
                    if size.is_empty() { name.to_string() } else { format!("{name}.{size}") };
                (name, operands.join(", "))
            }
        }
    }

    /// The name of each operand that [`VfpWord::lift`] gives, as
    /// [`VfpWord::text`] prints it.
    fn names(self) -> il::Names {
        use compact_str::format_compact;
        let core = |number: u32| CompactString::from(ARM_REGISTERS[number as usize]);
        let vector = |double: bool, number: u32| {
            format_compact!("{}{number}", if double { 'd' } else { 's' })
        };
        match self {
            Self::MoveSingle { to_core: true, core: rt, single } => {
                [core(rt), vector(false, single)].into_iter().collect()
            }
            Self::MoveSingle { to_core: false, core: rt, single } => {
                [vector(false, single), core(rt)].into_iter().collect()
            }
            Self::MoveDouble { to_core: true, low, high, double } => {
                [core(low), core(high), vector(true, double)].into_iter().collect()
            }
            Self::MoveDouble { to_core: false, low, high, double } => {
                [vector(true, double), core(low), core(high)].into_iter().collect()
            }
            Self::StatusToCore { core: 15 } => ["APSR_nzcv".into()].into_iter().collect(),
            Self::StatusToCore { core: rt } => [core(rt)].into_iter().collect(),
            Self::Multiple { load, base, write_back, before, first, count, double } => {
                let list: Vec<CompactString> =
                    (first..first + count).map(|number| vector(double, number)).collect();
                let list = format_compact!("{{{}}}", list.join(", "));
                // `vpush` and `vpop` name no base.
                let base = match (load, base, write_back, before) {
                    (false, 13, true, true) | (true, 13, true, false) => CompactString::default(),
                    _ => format_compact!("{}{}", core(base), if write_back { "!" } else { "" }),
                };
                [list, base].into_iter().collect()
            }
            Self::MoveConstant { dest, bits } => {
                let value = if dest.double {
                    f64::from_bits(bits)
                } else {
                    f64::from(f32::from_bits(bits as u32))
                };
                [CompactString::from(dest.text()), format_compact!("#{value:?}")]
                    .into_iter()
                    .collect()
            }
            Self::Compute { operation, dest, sources, .. } => {
                let mut names: il::Names = [CompactString::from(dest.text())]
                    .into_iter()
                    .chain(sources.iter().flatten().map(|source| source.text().into()))
                    .collect();
                if operation.is_compare() && sources == [None, None] {
                    names.push("0x0".into());
                }
                names
            }
        }
    }

    /// The IL form of this word. The VFP registers are [`il::Reg::Vector`]
    /// by number, `s` and `d` alike.
    fn lift(self) -> il::Lifted {
        use il::Op;
        let general = |number: u32| il_reg(Reg::from_u8(number as u8));
        let core = |number: u32| general(number).map_or(il::Operand::Other, il::Operand::Reg);
        let vector = |number: u32| il::Reg::Vector(number as u8);
        let mut lifted = il::Lifted::default();
        match self {
            Self::MoveSingle { to_core, core: rt, single } => {
                lifted.op = Op::Move;
                let (dest, source) = if to_core {
                    (core(rt), il::Operand::Reg(vector(single)))
                } else {
                    (il::Operand::Reg(vector(single)), core(rt))
                };
                lifted.operands = [dest, source].into_iter().collect();
            }
            Self::MoveDouble { to_core, low, high, double } => {
                lifted.op = Op::Move;
                let pair = [core(low), core(high)];
                let vector = il::Operand::Reg(vector(double));
                lifted.operands = if to_core {
                    pair.into_iter().chain([vector]).collect()
                } else {
                    [vector].into_iter().chain(pair).collect()
                };
            }
            Self::StatusToCore { core: rt } => {
                lifted.op = Op::Move;
                lifted.operands = [core(rt)].into_iter().collect();
                if rt == 15 {
                    lifted.writes.insert(il::Reg::Flags);
                }
            }
            Self::Multiple { load, base, write_back, before, first, count, double } => {
                lifted.op = if load { Op::Load } else { Op::Store };
                let offset =
                    if before { -i64::from(count * if double { 8 } else { 4 }) } else { 0 };
                let update = if write_back { il::Update::Before } else { il::Update::None };
                let memory = il::Operand::Memory {
                    base: Some(operand_general(base)),
                    offset: Some(offset),
                    index: None,
                    update,
                };
                let list = (first..first + count).map(vector).collect();
                lifted.operands = [il::Operand::RegisterList(list), memory].into_iter().collect();
                let kind = if load { il::AccessKind::Load } else { il::AccessKind::Store };
                let width = if double { il::Width::Bits64 } else { il::Width::Bits32 };
                lifted.memory = Some(il::MemoryAccess { kind, width: Some(width) });
                let moved = if load { &mut lifted.writes } else { &mut lifted.reads };
                (first..first + count).for_each(|number| moved.insert(vector(number)));
                if write_back {
                    general(base).into_iter().for_each(|reg| lifted.writes.insert(reg));
                }
                general(base).into_iter().for_each(|reg| lifted.reads.insert(reg));
                return lifted;
            }
            Self::MoveConstant { dest, bits } => {
                lifted.op = Op::Move;
                let dest = il::Operand::Reg(vector(dest.number));
                lifted.operands = [dest, il::Operand::Const(bits)].into_iter().collect();
            }
            Self::Compute { dest, sources, operation, .. } => {
                lifted.op = operation.op();
                let vector = |register: Vector| il::Operand::Reg(vector(register.number));
                let values = sources.iter().flatten().map(|&source| vector(source));
                lifted.operands = [vector(dest)].into_iter().chain(values).collect();
                if operation.is_compare() {
                    if sources == [None, None] {
                        lifted.operands.push(il::Operand::Const(0));
                    }
                    // A compare writes only the VFP flags, which `vmrs`
                    // moves on: it reads every value it names.
                    for operand in lifted.operands.clone() {
                        if let il::Operand::Reg(reg) = operand {
                            lifted.reads.insert(reg);
                        }
                    }
                    return lifted;
                }
                // `vmla` and kin add to their destination.
                if operation.adds_to_destination() {
                    lifted.reads.insert(il::Reg::Vector(dest.number as u8));
                }
            }
        }
        // A move or computation reads every operand but the first, and
        // writes the first: two for a move of a double to core registers.
        let written = match self {
            Self::MoveDouble { to_core: true, .. } => 2,
            _ => 1,
        };
        for (index, operand) in lifted.operands.clone().iter().enumerate() {
            if let il::Operand::Reg(reg) = operand {
                if index < written { lifted.writes.insert(*reg) } else { lifted.reads.insert(*reg) }
            }
        }
        lifted
    }
}

/// The bits of the float that the 8-bit constant of a VFP `vmov` stands
/// for: `VFPExpandImm` of the Arm architecture manual. The constant holds a
/// sign, three bits of exponent and four of fraction.
pub fn expand_float_constant(constant: u32, double: bool) -> u64 {
    let constant = u64::from(constant);
    let sign = constant >> 7;
    let b = constant >> 6 & 1;
    let low_exponent = constant >> 4 & 0b11;
    let fraction = constant & 0b1111;
    // The exponent is NOT(b), then b again and again, then the two bits.
    let (repeats, width, fraction_shift) = if double { (8, 64, 48) } else { (5, 32, 19) };
    let copies = if b == 1 { (1 << repeats) - 1 } else { 0 };
    let exponent = (b ^ 1) << (repeats + 2) | copies << 2 | low_exponent;
    sign << (width - 1) | exponent << (width - 1 - (repeats + 3)) | fraction << fraction_shift
}

/// Which instruction set a word given as A32 came in. A T32 VFP or NEON
/// word reads as its A32 twin, but no other T32 word does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// An A32 word, as it is.
    A32,
    /// A wide T32 word, its halfwords swapped and its NEON prefix made A32.
    T32,
}

/// The names of the general registers, as the decoder prints them.
pub(crate) const ARM_REGISTERS: [&str; 16] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "sb", "sl", "fp", "ip", "sp", "lr", "pc",
];

/// The top byte of an A32 NEON element or structure load or store.
pub(crate) const NEON_LOAD_STORE: u32 = 0xf4;

/// The name for an A32 `word` the decoder cannot read: [`NEON_TEXT`]
/// for NEON data processing, `1111 001U`, else [`UNKNOWN_TEXT`].
pub(crate) fn unread_text(word: u32) -> &'static str {
    if is_neon_data(word) { NEON_TEXT } else { UNKNOWN_TEXT }
}

/// What [`Insn::opcode`] holds for an A32 `word` the decoder cannot read.
pub(crate) fn unread_opcode(word: u32) -> crate::arch::Opcode {
    match is_neon_data(word) {
        true => crate::arch::Opcode::Arm(Decoded::NeonData),
        false => crate::arch::Opcode::Unread(crate::arch::InstructionSet::Arm),
    }
}

/// NEON data processing, `1111 001U`.
pub(crate) fn is_neon_data(word: u32) -> bool {
    word >> 25 == 0b111_1001
}

/// Read an A32 NEON element or structure load or store:
///
/// ```text
/// 1111 0100 A D L 0 Rn Vd type size align Rm
/// ```
///
/// `A` clear moves whole structures, set moves one lane or all lanes. `Rm`
/// says how the base moves after: 15 not at all, 13 by the size moved, any
/// other by that register.
pub(crate) fn decode_neon_load_store(word: u32) -> Option<(String, String)> {
    let access = NeonAccess::of(word)?;
    let lane = match access.lanes {
        Lanes::Whole => String::new(),
        Lanes::All => "[]".to_string(),
        Lanes::One(lane) => format!("[{lane}]"),
    };
    let list: Vec<String> =
        access.registers().map(|register| format!("d{register}{lane}")).collect();
    let alignment = access.alignment.map(|bits| format!(":{bits}")).unwrap_or_default();
    let base = format!("[{}{alignment}]", ARM_REGISTERS[access.base as usize]);
    let address = match access.index {
        0b1111 => base,
        0b1101 => format!("{base}!"),
        index => format!("{base}, {}", ARM_REGISTERS[index as usize]),
    };
    let operation = if access.load { "vld" } else { "vst" };
    Some((
        format!("{operation}{}.{}", access.structures, 8 << access.size),
        format!("{{{}}}, {address}", list.join(", ")),
    ))
}

/// Lift an A32 `word` the decoder refuses but [`decode_fallback`] reads,
/// where it moves data: the VFP and NEON loads and stores. A T32 caller
/// gives the A32 form of its word.
pub fn lift_fallback(word: u32, encoding: Encoding) -> Option<il::Lifted> {
    let field = |shift: u32, width: u32| word >> shift & ((1 << width) - 1);
    // The hints, as `decode_fallback` reads them: they talk to the system
    // and compute nothing.
    if word & 0x0fff_ff00 == 0x0320_f000 && word & 0xff < 5 && word >> 28 != 0b1111 {
        let mut lifted = il::Lifted { op: il::Op::System, ..il::Lifted::default() };
        if word >> 28 != 0b1110 {
            lifted.reads.insert(il::Reg::Flags);
        }
        return Some(lifted);
    }
    if encoding == Encoding::A32
        && word >> 28 != 0b1111
        && let Some(integer) = IntegerWord::of(word)
    {
        let mut lifted = integer.lift();
        if word >> 28 != 0b1110 {
            lifted.reads.insert(il::Reg::Flags);
        }
        return Some(lifted);
    }
    if word >> 28 != 0b1111
        && let Some(vfp) = VfpWord::of(word)
    {
        let mut lifted = vfp.lift();
        if word >> 28 != 0b1110 {
            lifted.reads.insert(il::Reg::Flags);
        }
        return Some(lifted);
    }
    let general = |number: u32| il_reg(Reg::from_u8(number as u8));
    let mut reads = il::RegSet::EMPTY;
    let mut writes = il::RegSet::EMPTY;

    let (load, width, values, memory): (bool, il::Width, il::Operand, il::Operand) =
        if word >> 24 == NEON_LOAD_STORE {
            let access = NeonAccess::of(word)?;
            let base = general(access.base);
            base.into_iter().for_each(|reg| reads.insert(reg));
            // `Rm` 15 leaves the base, 13 steps it by the size moved, and any
            // other register steps it by that register.
            let offset = match access.index {
                0b1111 => Some(0),
                0b1101 => {
                    base.into_iter().for_each(|reg| writes.insert(reg));
                    Some(0)
                }
                index => {
                    base.into_iter().for_each(|reg| writes.insert(reg));
                    general(index).into_iter().for_each(|reg| reads.insert(reg));
                    None
                }
            };
            let moved = if access.load { &mut writes } else { &mut reads };
            access.registers().for_each(|number| moved.insert(il::Reg::Vector(number as u8)));
            let width = match access.size {
                0 => il::Width::Bits8,
                1 => il::Width::Bits16,
                2 => il::Width::Bits32,
                _ => il::Width::Bits64,
            };
            let memory = il::Operand::Memory {
                base: Some(operand_general(access.base)),
                offset,
                index: None,
                update: if access.index == 0b1111 { il::Update::None } else { il::Update::After },
            };
            let list = access.registers().map(|number| il::Reg::Vector(number as u8)).collect();
            (access.load, width, il::Operand::RegisterList(list), memory)
        } else {
            // `vldr` and `vstr`: 1101 U D 0 L Rn Vd 101 sz imm8.
            let (_, _, decoded) = decode_fallback(word, encoding)?;
            if !matches!(decoded, Decoded::Vfp { vfp: Vfp::Load | Vfp::Store, .. }) {
                return None;
            }
            let double = field(8, 1) == 1;
            let (d, vd) = (field(22, 1), field(12, 4));
            let register = il::Reg::Vector(if double { d << 4 | vd } else { vd << 1 | d } as u8);
            let base = general(field(16, 4));
            base.into_iter().for_each(|reg| reads.insert(reg));
            let load = field(20, 1) == 1;
            if load {
                writes.insert(register)
            } else {
                reads.insert(register)
            }
            let offset = i64::from(field(0, 8) * 4);
            let offset = if field(23, 1) == 1 { offset } else { -offset };
            let width = if double { il::Width::Bits64 } else { il::Width::Bits32 };
            let memory = il::Operand::memory(Some(operand_general(field(16, 4))), Some(offset));
            (load, width, il::Operand::Reg(register), memory)
        };
    if word >> 28 != 0b1110 && word >> 24 != NEON_LOAD_STORE {
        reads.insert(il::Reg::Flags);
    }
    let (op, kind) = if load {
        (il::Op::Load, il::AccessKind::Load)
    } else {
        (il::Op::Store, il::AccessKind::Store)
    };
    Some(il::Lifted {
        op,
        reads,
        writes,
        memory: Some(il::MemoryAccess { kind, width: Some(width) }),
        test: None,
        operands: [values, memory].into_iter().collect(),
    })
}

/// The name of each operand that [`lift_fallback`] gives `word`, as
/// [`decode_fallback`] prints it.
pub(crate) fn fallback_names(word: u32, encoding: Encoding) -> Option<il::Names> {
    use compact_str::format_compact;
    let field = |shift: u32, width: u32| word >> shift & ((1 << width) - 1);
    if word & 0x0fff_ff00 == 0x0320_f000 && word & 0xff < 5 && word >> 28 != 0b1111 {
        return Some(il::Names::new());
    }
    if encoding == Encoding::A32
        && word >> 28 != 0b1111
        && let Some(integer) = IntegerWord::of(word)
    {
        return Some(integer.names());
    }
    if word >> 28 != 0b1111
        && let Some(vfp) = VfpWord::of(word)
    {
        return Some(vfp.names());
    }
    if word >> 24 == NEON_LOAD_STORE {
        let access = NeonAccess::of(word)?;
        let lane = match access.lanes {
            Lanes::Whole => CompactString::default(),
            Lanes::All => "[]".into(),
            Lanes::One(lane) => format_compact!("[{lane}]"),
        };
        let list: Vec<CompactString> =
            access.registers().map(|register| format_compact!("d{register}{lane}")).collect();
        let alignment = access.alignment.map(|bits| format_compact!(":{bits}")).unwrap_or_default();
        let base = format_compact!("[{}{alignment}]", ARM_REGISTERS[access.base as usize]);
        return Some([format_compact!("{{{}}}", list.join(", ")), base].into_iter().collect());
    }
    // `vldr` and `vstr`: 1101 U D 0 L Rn Vd 101 sz imm8.
    let (d, vd) = (field(22, 1), field(12, 4));
    let register = match field(8, 1) {
        1 => format_compact!("d{}", d << 4 | vd),
        _ => format_compact!("s{}", vd << 1 | d),
    };
    let base = ARM_REGISTERS[field(16, 4) as usize];
    let offset = field(0, 8) * 4;
    let reference = match (offset, field(23, 1) == 1) {
        (0, _) => format_compact!("[{base}]"),
        (_, true) => format_compact!("[{base} + {offset:#x}]"),
        (_, false) => format_compact!("[{base} - {offset:#x}]"),
    };
    Some([register, reference].into_iter().collect())
}

/// What a post-index access of `word` adds to its base after it, as
/// [`decode_fallback`] prints it.
pub(crate) fn fallback_write_back(word: u32, encoding: Encoding) -> Option<CompactString> {
    if encoding == Encoding::A32
        && word >> 28 != 0b1111
        && let Some(integer) = IntegerWord::of(word)
    {
        return integer.write_back();
    }
    if word >> 24 != NEON_LOAD_STORE {
        return None;
    }
    let access = NeonAccess::of(word)?;
    match access.index {
        0b1111 | 0b1101 => None,
        index => Some(ARM_REGISTERS[index as usize].into()),
    }
}

/// The fields of an A32 NEON element or structure load or store.
pub(crate) struct NeonAccess {
    load: bool,
    structures: u32,
    /// The first `d` register, and how many follow it, how far apart.
    first: u32,
    count: u32,
    spacing: u32,
    /// The element size, as a power of two of bytes.
    size: u32,
    lanes: Lanes,
    /// The base register, and `Rm`, which says how the base moves after.
    base: u32,
    index: u32,
    /// The alignment the access asserts, in bits, as `[r3:64]` prints it.
    alignment: Option<u32>,
}

impl NeonAccess {
    fn of(word: u32) -> Option<Self> {
        let field = |shift: u32, width: u32| word >> shift & ((1 << width) - 1);
        let first = field(22, 1) << 4 | field(12, 4);
        let (structures, registers, spacing, size, lanes) = if field(23, 1) == 0 {
            let (structures, registers, spacing) = match field(8, 4) {
                0b0111 => (1, 1, 1),
                0b1010 => (1, 2, 1),
                0b0110 => (1, 3, 1),
                0b0010 => (1, 4, 1),
                0b1000 => (2, 2, 1),
                0b1001 => (2, 2, 2),
                0b0011 => (2, 4, 1),
                0b0100 => (3, 3, 1),
                0b0101 => (3, 3, 2),
                0b0000 => (4, 4, 1),
                0b0001 => (4, 4, 2),
                _ => return None,
            };
            (structures, registers, spacing, field(6, 2), Lanes::Whole)
        } else {
            let structures = field(8, 2) + 1;
            match field(10, 2) {
                // To all lanes: `T` doubles the count of a `vld1`, and spaces
                // the others.
                0b11 => {
                    let doubled = field(5, 1) == 1;
                    let (registers, spacing) = match (structures, doubled) {
                        (1, true) => (2, 1),
                        (_, true) => (structures, 2),
                        (_, false) => (structures, 1),
                    };
                    (structures, registers, spacing, field(6, 2), Lanes::All)
                }
                size => {
                    let index_align = field(4, 4);
                    let spacing = match size {
                        1 if index_align & 0b10 != 0 => 2,
                        2 if index_align & 0b100 != 0 => 2,
                        _ => 1,
                    };
                    let lane = index_align >> (size + 1);
                    (structures, structures, spacing, size, Lanes::One(lane))
                }
            }
        };
        Some(Self {
            load: field(21, 1) == 1,
            structures,
            first,
            count: registers,
            spacing,
            size,
            lanes,
            base: field(16, 4),
            index: field(0, 4),
            alignment: Self::alignment(word, structures, size, lanes),
        })
    }

    /// The alignment the `align` field of `word` asserts, in bits, by the
    /// tables of `VLD1` to `VLD4` in the Arm architecture manual.
    fn alignment(word: u32, structures: u32, size: u32, lanes: Lanes) -> Option<u32> {
        let field = |shift: u32, width: u32| word >> shift & ((1 << width) - 1);
        let bits = match lanes {
            Lanes::Whole => match field(4, 2) {
                0 => 0,
                align => 32 << align,
            },
            Lanes::All => match (field(4, 1), structures, size) {
                (0, ..) => 0,
                (_, 1, _) => 8 << size,
                (_, 2, _) => 16 << size,
                (_, 4, 0) => 32,
                (_, 4, 1 | 2) => 64,
                // A size of `11` moves words, aligned to 128 bits.
                (_, 4, _) => 128,
                _ => 0,
            },
            Lanes::One(_) => {
                let index_align = field(4, 4);
                match (structures, size, index_align & 0b11) {
                    (1, 1, align) if align & 1 == 1 => 16,
                    (1, 2, 0b11) => 32,
                    (2, size, align) if align & 1 == 1 => 16 << size,
                    (4, 0, align) if align & 1 == 1 => 32,
                    (4, 1, align) if align & 1 == 1 => 64,
                    (4, 2, 0b01) => 64,
                    (4, 2, 0b10) => 128,
                    _ => 0,
                }
            }
        };
        (bits != 0).then_some(bits)
    }

    /// The numbers of the `d` registers moved.
    fn registers(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.count).map(|index| self.first + index * self.spacing)
    }
}

/// Which lanes of its registers a NEON load or store moves.
#[derive(Clone, Copy)]
pub(crate) enum Lanes {
    /// Whole registers.
    Whole,
    /// One element, copied to every lane.
    All,
    /// The one lane given.
    One(u32),
}

/// Work out how an instruction moves control flow.
///
/// ARM has no single "return" opcode. A return is any write to the program
/// counter, so `pop {pc}` decodes as `LDR` and `mov pc, lr` as `MOV`. Reading
/// the opcode alone would miss both, so check the destination register too.
/// How `inst` moves control, where `target` is where a branch in it goes.
pub(crate) fn classify(inst: &Instruction, target: Option<u64>) -> InsnKind {
    let unconditional = inst.condition == ConditionCode::AL;

    match inst.opcode {
        Opcode::BL | Opcode::BLX => InsnKind::Call { target },

        // `bx lr` returns; `bx <other>` is an indirect jump. A conditional
        // one falls through when its condition fails, as `bxeq lr` does in
        // an early exit, so it is a branch and does not end the function.
        Opcode::BX if !unconditional => InsnKind::Branch { target: None },
        Opcode::BX => match inst.operands[0] {
            Operand::Reg(reg) if reg.number() as u16 == REG_LR => InsnKind::Return,
            _ => InsnKind::Jump { target: None },
        },

        Opcode::B => {
            if unconditional {
                InsnKind::Jump { target }
            } else {
                InsnKind::Branch { target }
            }
        }

        // Anything that writes the PC leaves the current block.
        _ if writes_pc(inst) => match (unconditional, returns(inst)) {
            (false, _) => InsnKind::Branch { target: None },
            (true, true) => InsnKind::Return,
            (true, false) => InsnKind::Jump { target: None },
        },

        _ => InsnKind::Normal,
    }
}

/// Resolve a PC-relative branch to a virtual address.
///
/// `yaxpeax` reports the offset in **words**, measured from the instruction
/// itself, and has already removed the 8-byte pipeline bias that the ARM
/// encoding carries. A branch to itself therefore reports offset 0. Adding the
/// bias again here would put every target 8 bytes too far.
pub(crate) fn branch_target(inst: &Instruction, address: u64) -> Option<u64> {
    match inst.operands[0] {
        Operand::BranchOffset(words) => {
            let byte_offset = (words as i64) * INSN_WIDTH as i64;
            u64::try_from(address as i64 + byte_offset).ok()
        }
        _ => None,
    }
}

/// Report whether a write of the program counter returns: it takes the PC
/// from the stack, as `pop {..., pc}` does, or from the link register.
///
/// Any other write is a computed jump. `add pc, r3, r2` jumps through a
/// table of cases, and the code after it is more of the same function.
pub fn returns(inst: &Instruction) -> bool {
    let is = |reg: &Reg, number: u16| reg.number() as u16 == number;
    let base_is_sp = |operand: &Operand| match operand {
        Operand::Reg(reg) | Operand::RegWBack(reg, _) | Operand::RegDeref(reg) => is(reg, REG_SP),
        Operand::RegDerefPostindexRegShift(reg, ..)
        | Operand::RegDerefPreindexRegShift(reg, ..)
        | Operand::RegDerefPostindexOffset(reg, ..)
        | Operand::RegDerefPreindexOffset(reg, ..)
        | Operand::RegDerefPostindexReg(reg, ..)
        | Operand::RegDerefPreindexReg(reg, ..) => is(reg, REG_SP),
        _ => false,
    };

    match inst.opcode {
        Opcode::POP => true,
        Opcode::LDM(..) => base_is_sp(&inst.operands[0]),
        Opcode::LDR => base_is_sp(&inst.operands[1]),
        Opcode::MOV => matches!(&inst.operands[1], Operand::Reg(reg) if is(reg, REG_LR)),
        _ => false,
    }
}

/// Report whether the instruction writes the program counter.
///
/// Only a destination counts. `add r1, pc, r1` reads the PC to form an
/// address, which PIC code does in every function that reaches a global, and
/// reading it as a write ended the function there.
pub(crate) fn writes_pc(inst: &Instruction) -> bool {
    let is_pc = |operand: &Operand| match operand {
        Operand::Reg(reg) | Operand::RegWBack(reg, _) => reg.number() as u16 == REG_PC,
        _ => false,
    };

    match inst.opcode {
        // A store or a comparison has no destination register.
        Opcode::CMP
        | Opcode::CMN
        | Opcode::TST
        | Opcode::TEQ
        | Opcode::PUSH
        | Opcode::STM(..)
        | Opcode::STR
        | Opcode::STRB
        | Opcode::STRH
        | Opcode::STRD
        | Opcode::STRT
        | Opcode::STRBT
        | Opcode::STRHT
        | Opcode::STREX
        | Opcode::STREXB
        | Opcode::STREXH
        | Opcode::STREXD => false,
        // `pop {..., pc}` carries the PC as a bit in a register-list mask.
        Opcode::LDM(..) | Opcode::POP => inst
            .operands
            .iter()
            .any(|operand| matches!(operand, Operand::RegList(mask) if mask & (1 << REG_PC) != 0)),
        _ => is_pc(&inst.operands[0]),
    }
}

#[cfg(test)]
mod unused_operand_tests {
    use super::*;

    #[test]
    fn a_compare_and_a_move_print_only_what_they_use() {
        let shown = |word: u32| {
            let code = word.to_le_bytes();
            let insn = Arm32.decode(&code, 0, 0).expect("decodes");
            insn.to_string()
        };
        // From `llvm-mc --triple=armv7`.
        assert_eq!(shown(0xe153_0002), "cmp r3, r2");
        assert_eq!(shown(0x1350_0007), "cmpne r0, 0x7");
        assert_eq!(shown(0xe311_0003), "tst r1, 0x3");
        assert_eq!(shown(0xe3e0_0000), "mvn r0, 0x0");
        assert_eq!(shown(0xe1a0_4201), "mov r4, r1, lsl 4");
        assert_eq!(shown(0xe1a0_7000), "mov r7, r0");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::DecodeError;
    use compact_str::CompactString;

    /// Decode one instruction from raw bytes at address 0.
    fn decode_one(bytes: [u8; 4]) -> Insn {
        Arm32.decode(&bytes, 0, 0).expect("bytes must decode")
    }

    /// Encodings from `llvm-mc --triple=armv7a --show-encoding`.
    mod words {
        pub const CMP_R0_1: [u8; 4] = [0x01, 0x00, 0x50, 0xe3];
        pub const BLT: [u8; 4] = [0x02, 0x00, 0x00, 0xba];
        pub const CMP_R0_0: [u8; 4] = [0x00, 0x00, 0x50, 0xe3];
        pub const BLE: [u8; 4] = [0x02, 0x00, 0x00, 0xda];
        pub const CMN_R1_1: [u8; 4] = [0x01, 0x00, 0x71, 0xe3];
        pub const BNE: [u8; 4] = [0x02, 0x00, 0x00, 0x1a];
        pub const TST_R2_4: [u8; 4] = [0x04, 0x00, 0x12, 0xe3];
        pub const BEQ: [u8; 4] = [0x02, 0x00, 0x00, 0x0a];
        pub const ADD_R0_R1_R2: [u8; 4] = [0x02, 0x00, 0x81, 0xe0];
        pub const LDR_R1_R2_8: [u8; 4] = [0x08, 0x10, 0x92, 0xe5];
        pub const LDR_R1_R2_POST: [u8; 4] = [0x04, 0x10, 0x92, 0xe4];
        pub const STR_R3_R4_R5: [u8; 4] = [0x05, 0x30, 0x84, 0xe7];
        pub const PUSH_R4_LR: [u8; 4] = [0x10, 0x40, 0x2d, 0xe9];
        pub const POP_R4_PC: [u8; 4] = [0x10, 0x80, 0xbd, 0xe8];
        pub const BL: [u8; 4] = [0x40, 0x00, 0x00, 0xeb];
        pub const STREX_R1_R2_R3: [u8; 4] = [0x92, 0x1f, 0x83, 0xe1];
        pub const UMULL: [u8; 4] = [0x92, 0x03, 0x81, 0xe0];
        pub const MOVT_R4: [u8; 4] = [0x34, 0x42, 0x41, 0xe3];
        pub const ADDEQ_R0: [u8; 4] = [0x01, 0x00, 0x80, 0x02];
        pub const LDRD_R2_R3_SP: [u8; 4] = [0xd8, 0x20, 0xcd, 0xe1];
    }

    fn lift_one(bytes: [u8; 4]) -> il::Lifted {
        Arm32.lift(&decode_one(bytes)).expect("the word must lift")
    }

    #[test]
    fn a_list_access_names_its_order() {
        let name = |word: u32| {
            let insn = decode_one(word.to_le_bytes());
            crate::arch::printed_name(&insn).to_string()
        };
        assert_eq!(name(0xe890_0006), "ldm", "increment after");
        assert_eq!(name(0xe990_0006), "ldmib");
        assert_eq!(name(0x1990_0006), "ldmibne");
        assert_eq!(name(0xe980_0006), "stmib");
        assert_eq!(name(0xe910_0006), "ldmdb");
        assert_eq!(name(0xe810_0006), "ldmda");
    }

    #[test]
    fn operands_come_in_printed_order() {
        use il::Operand::{Const, RegisterList, Target};
        let reg = |number| il::Operand::Reg(il::Reg::General(number));
        let operands = |bytes| lift_one(bytes).operands.into_vec();
        assert_eq!(operands(words::ADD_R0_R1_R2), [reg(0), reg(1), reg(2)]);
        assert_eq!(operands(words::CMP_R0_1), [reg(0), Const(1)], "no unused destination");
        let saved = [il::Reg::General(4), il::Reg::General(14)].into_iter().collect();
        let push = [il::Operand::Reg(il::Reg::Stack), RegisterList(saved)];
        assert_eq!(operands(words::PUSH_R4_LR), push, "the list names what it saves");
        assert!(
            matches!(operands(words::BL).as_slice(), [Target(Some(_))]),
            "a call names its distance"
        );
    }

    fn regs(numbers: &[u8]) -> il::RegSet {
        numbers
            .iter()
            .map(|&number| match number {
                13 => il::Reg::Stack,
                number => il::Reg::General(number),
            })
            .collect()
    }

    fn guard_of(words: &[[u8; 4]]) -> Option<il::Guard> {
        let lifted: Vec<Option<il::Lifted>> =
            words.iter().map(|&word| Some(lift_one(word))).collect();
        il::find_guards(&lifted).first().map(|found| found.guard)
    }

    /// Clang tests `x < 1` where GCC tests `x <= 0`, and both are one test.
    #[test]
    fn a_compare_and_its_branch_are_one_guard() {
        let clang = guard_of(&[words::CMP_R0_1, words::BLT]).unwrap();
        let gcc = guard_of(&[words::CMP_R0_0, words::BLE]).unwrap();
        assert_eq!(clang.cond, il::Cond::SignedLess);
        assert_eq!(clang.width, il::Width::Bits32);
        assert_eq!(clang.canonical(), gcc.canonical());
    }

    #[test]
    fn cmn_with_one_compares_with_minus_one() {
        let guard = guard_of(&[words::CMN_R1_1, words::BNE]).unwrap();
        assert_eq!(guard.right, il::Value::Const(0xffff_ffff));
    }

    #[test]
    fn tst_with_beq_tests_bits() {
        let guard = guard_of(&[words::TST_R2_4, words::BEQ]).unwrap();
        assert_eq!((guard.cond, guard.right), (il::Cond::BitsClear, il::Value::Const(4)));
    }

    #[test]
    fn a_conditional_instruction_reads_the_flags() {
        let lifted = lift_one(words::ADDEQ_R0);
        assert!(lifted.reads.contains(il::Reg::Flags));
        assert_eq!(lifted.test, None);
        assert_eq!(guard_of(&[words::CMP_R0_0, words::ADDEQ_R0, words::BEQ]), None);
    }

    #[test]
    fn registers_and_memory_are_named() {
        let add = lift_one(words::ADD_R0_R1_R2);
        assert_eq!((add.reads, add.writes), (regs(&[1, 2]), regs(&[0])));

        let load = lift_one(words::LDR_R1_R2_8);
        assert_eq!((load.reads, load.writes), (regs(&[2]), regs(&[1])));
        assert_eq!(load.memory.map(|access| access.kind), Some(il::AccessKind::Load));
        assert_eq!(lift_one(words::LDR_R1_R2_POST).writes, regs(&[1, 2]), "written back");

        let store = lift_one(words::STR_R3_R4_R5);
        assert_eq!((store.reads, store.writes), (regs(&[3, 4, 5]), il::RegSet::EMPTY));
        assert_eq!(store.memory.map(|access| access.kind), Some(il::AccessKind::Store));

        let push = lift_one(words::PUSH_R4_LR);
        assert_eq!((push.reads, push.writes), (regs(&[4, 13, 14]), regs(&[13])));
        let pop = lift_one(words::POP_R4_PC);
        assert_eq!((pop.reads, pop.writes), (regs(&[13]), regs(&[4, 13])), "the pc is no register");

        assert_eq!(lift_one(words::BL).writes, regs(&[14]));
        let exclusive = lift_one(words::STREX_R1_R2_R3);
        assert_eq!((exclusive.reads, exclusive.writes), (regs(&[2, 3]), regs(&[1])));
        let long = lift_one(words::UMULL);
        assert_eq!((long.reads, long.writes), (regs(&[2, 3]), regs(&[0, 1])));
        let movt = lift_one(words::MOVT_R4);
        assert_eq!((movt.reads, movt.writes), (regs(&[4]), regs(&[4])));
        let pair = lift_one(words::LDRD_R2_R3_SP);
        assert_eq!((pair.reads, pair.writes), (regs(&[13]), regs(&[2, 3])));
    }

    #[test]
    fn lifting_any_word_never_panics() {
        bolero::check!().with_type::<u32>().for_each(|&word| {
            let bytes = word.to_le_bytes();
            let insn = Arm32.decode(&bytes, 0, 0).expect("every word decodes or is unknown");
            if let Some(lifted) = Arm32.lift(&insn)
                && let Some(il::Test::Guard(_) | il::Test::OnFlags(_)) = lifted.test
            {
                assert!(
                    matches!(insn.kind, InsnKind::Branch { .. }),
                    "{insn}: a test that branches"
                );
            }
        });
    }

    /// The text of the A32 instruction `word`.
    fn text_of(word: u32) -> (String, String) {
        let insn = decode_one(word.to_le_bytes());
        (crate::arch::printed_name(&insn), crate::arch::printed_operands(&insn))
    }

    #[test]
    fn neon_loads_and_stores_of_whole_registers_read() {
        let cases = [
            (0xf420_070f, "vld1.8", "{d0}, [r0]"),
            (0xf441_0a8d, "vst1.32", "{d16, d17}, [r1]!"),
            (0xf422_0142, "vld4.16", "{d0, d2, d4, d6}, [r2], r2"),
        ];
        for (word, name, operands) in cases {
            assert_eq!(text_of(word), (name.into(), operands.into()), "{word:#010x}");
            assert_eq!(decode_one(word.to_le_bytes()).kind, InsnKind::Normal);
        }
    }

    #[test]
    fn neon_loads_of_lanes_read() {
        assert_eq!(text_of(0xf4a1_0c8f), ("vld1.32".into(), "{d0[]}, [r1]".into()), "all lanes");
        assert_eq!(
            text_of(0xf4a0_0762),
            ("vld4.16".into(), "{d0[1], d2[1], d4[1], d6[1]}, [r0], r2".into()),
            "one lane, every second register"
        );
    }

    #[test]
    fn decodes_simple_arithmetic() {
        let insn = decode_one([0x00, 0x00, 0x81, 0xe0]);
        assert_eq!(crate::arch::printed_name(&insn), "add");
        assert_eq!(crate::arch::printed_operands(&insn), "r0, r1, r0");
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

    /// `add r1, pc, r1` reads the PC to form an address. It does not leave.
    #[test]
    fn reading_the_pc_is_not_a_return() {
        let add = decode_one(0xe08f_1001_u32.to_le_bytes());
        assert_eq!(add.to_string(), "add r1, pc, r1");
        assert_eq!(add.kind, InsnKind::Normal);
    }

    /// `str pc, [sp]` and `cmp pc, r0` name the PC, but do not write it.
    #[test]
    fn a_store_or_compare_of_the_pc_is_not_a_return() {
        assert_eq!(decode_one(0xe58d_f000_u32.to_le_bytes()).kind, InsnKind::Normal);
        assert_eq!(decode_one(0xe15f_0000_u32.to_le_bytes()).kind, InsnKind::Normal);
        assert_eq!(
            decode_one(0xe92d_c000_u32.to_le_bytes()).kind,
            InsnKind::Normal,
            "push lr and pc"
        );
    }

    /// `add pc, pc, r0, lsl 2` and `ldr pc, [r1, r0, lsl 2]` jump through a
    /// table. They leave the block, but not the function.
    #[test]
    fn a_computed_write_of_the_pc_is_a_jump() {
        assert_eq!(decode_one(0xe08f_f100_u32.to_le_bytes()).kind, InsnKind::Jump { target: None });
        assert_eq!(decode_one(0xe791_f100_u32.to_le_bytes()).kind, InsnKind::Jump { target: None });
        assert_eq!(
            decode_one(0xe1a0_f003_u32.to_le_bytes()).kind,
            InsnKind::Jump { target: None },
            "mov pc, r3"
        );
    }

    /// `ldm sp!, {r4, pc}` returns, as `pop` does.
    #[test]
    fn a_load_multiple_from_the_stack_is_a_return() {
        assert_eq!(decode_one(0xe8bd_8010_u32.to_le_bytes()).kind, InsnKind::Return);
    }

    /// A conditional return falls through when the condition fails.
    #[test]
    fn a_conditional_bx_lr_is_a_branch() {
        assert_eq!(
            decode_one(0x012f_ff1e_u32.to_le_bytes()).kind,
            InsnKind::Branch { target: None }
        );
        assert_eq!(
            decode_one(0x012f_ff13_u32.to_le_bytes()).kind,
            InsnKind::Branch { target: None }
        ); // bxeq r3
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

    /// The usual ARM `nop` is one `yaxpeax` decodes "successfully" as
    /// `Opcode::Invalid`. The fallback reads it as `nop`, which moves nothing.
    #[test]
    fn nop_encoding_decodes_as_nop() {
        let insn = decode_one([0x00, 0xf0, 0x20, 0xe3]);
        assert_eq!(crate::arch::printed_name(&insn), "nop");
        assert_eq!(insn.kind, InsnKind::Normal);
    }

    /// NEON is outside what `yaxpeax-arm` 0.4 decodes. `vdup.32 q8, r2` must
    /// come back as opaque bytes, not as an error.
    #[test]
    fn neon_decodes_as_unknown() {
        let insn = decode_one([0x90, 0x2b, 0xa0, 0xee]);
        assert_eq!(insn.kind, InsnKind::Unknown);
        assert_eq!(insn.bytes_len, INSN_WIDTH);
    }

    /// The name of the operation of the A32 `word`.
    fn operation_of(word: u32) -> CompactString {
        Arm32.operation_name(&decode_one(word.to_le_bytes()))
    }

    #[test]
    fn distinct_operations_stay_distinct() {
        // ldr r0, [r1]; str r0, [r1]; push {r4, lr}; pop {r4, pc}.
        assert_ne!(operation_of(0xe591_0000), operation_of(0xe581_0000));
        assert_ne!(operation_of(0xe92d_4010), operation_of(0xe8bd_8010));
    }

    /// `yaxpeax` reads `mvn r0, #1` with an unused field, as
    /// `mvn r0, r0, 0x1`.
    #[test]
    fn a_not_of_a_constant_is_a_move_of_the_inverse() {
        let lifted = lift_one([0x01, 0x00, 0xe0, 0xe3]);
        assert_eq!(lifted.op, il::Op::Move);
        let inverse = il::Operand::Const(0xffff_fffe);
        assert_eq!(lifted.operands.as_slice(), [il::Operand::Reg(il::Reg::General(0)), inverse]);
        assert!(lifted.reads.is_empty(), "no register is read");
        // `mvn r1, r2` stays a not.
        assert_eq!(lift_one([0x02, 0x10, 0xe0, 0xe1]).op, il::Op::Not);
    }

    #[test]
    fn an_exclusive_access_is_atomic() {
        assert_eq!(lift_one(words::STREX_R1_R2_R3).op, il::Op::Atomic);
        // `ldrex r1, [r2]`
        assert_eq!(lift_one([0x9f, 0x1f, 0x92, 0xe1]).op, il::Op::Atomic);
        assert_eq!(lift_one(words::LDR_R1_R2_8).op, il::Op::Load);
    }

    /// `rsb` subtracts the other way round: `rsb r0, r1, #1` is `1 - r1`.
    #[test]
    fn a_reverse_subtract_names_its_values_in_order() {
        let general = |number| il::Operand::Reg(il::Reg::General(number));
        let lifted = lift_one([0x01, 0x00, 0x61, 0xe2]);
        assert_eq!(lifted.op, il::Op::Subtract);
        assert_eq!(lifted.operands.as_slice(), [general(0), il::Operand::Const(1), general(1)]);
    }

    /// `yaxpeax` reads no VFP or NEON load or store, so they lift from the
    /// fields [`decode_fallback`] reads.
    /// A register less or exclusive-or itself is zero, but not shifted:
    /// `eor r0, r1, r1, lsl #2` is `r1 ^ (r1 << 2)`. The lift once dropped
    /// the shift and read it as a move of zero.
    #[test]
    fn a_shifted_register_is_not_itself() {
        // eor r0, r1, r1, lsl #2 and eor r0, r1, r1.
        let shifted = lift_one(0xe021_0101_u32.to_le_bytes());
        let shift =
            il::Operand::Shifted { reg: il::Reg::General(1), shift: il::Shift::Left, amount: 2 };
        assert_eq!(shifted.operands[2], shift);
        assert_eq!(shifted.canonical().op, il::Op::Xor);
        assert_eq!(lift_one(0xe021_0001_u32.to_le_bytes()).canonical().op, il::Op::Move);
    }

    #[test]
    fn a_vfp_load_and_store_lift() {
        // `vldr d16, [pc, 0x90]`, as GCC loads a double from its pool.
        let load = lift_fallback(0xeddf_0b24, Encoding::A32).expect("vldr lifts");
        assert_eq!(load.op, il::Op::Load);
        assert_eq!(load.memory.and_then(|access| access.width), Some(il::Width::Bits64));
        let pool = il::Operand::memory(Some(il::Reg::ProgramCounter), Some(0x90));
        assert_eq!(load.operands.as_slice(), [il::Operand::Reg(il::Reg::Vector(16)), pool]);
        assert_eq!(load.writes, [il::Reg::Vector(16)].into_iter().collect());
        // `vstr s0, [sp, -0x4]`
        let store = lift_fallback(0xed0d_0a01, Encoding::A32).expect("vstr lifts");
        assert_eq!(store.op, il::Op::Store);
        let slot = il::Operand::memory(Some(il::Reg::Stack), Some(-4));
        assert_eq!(store.operands[1], slot);
        assert_eq!(store.reads, [il::Reg::Stack, il::Reg::Vector(0)].into_iter().collect());
        assert!(store.writes.is_empty());
    }

    /// A hint talks to the system: it reads no memory and names nothing.
    /// On a condition, it reads the flags.
    #[test]
    fn a_hint_lifts_to_the_system() {
        for (word, name) in [(0xe320_f000, "nop"), (0xe320_f004, "sev")] {
            let lifted = lift_fallback(word, Encoding::A32).expect(name);
            assert_eq!((lifted.op, lifted.memory), (il::Op::System, None), "{name}");
            assert!(lifted.operands.is_empty() && lifted.reads.is_empty(), "{name}");
        }
        let conditional = lift_fallback(0x0320_f004, Encoding::A32).expect("seveq");
        assert!(conditional.reads.contains(il::Reg::Flags));
    }

    #[test]
    fn what_the_fallback_lifts_it_decodes() {
        bolero::check!().with_type::<u32>().for_each(|&word| {
            if lift_fallback(word, Encoding::A32).is_some() {
                assert!(decode_fallback(word, Encoding::A32).is_some(), "{word:#010x}");
            }
        });
    }

    fn fallback_text(word: u32) -> Option<String> {
        decode_fallback(word, Encoding::A32).map(|(name, operands, _)| format!("{name} {operands}"))
    }

    /// Words `yaxpeax` 0.4 refuses, as `llvm-mc` reads them.
    #[test]
    fn reads_the_integer_words_the_decoder_refuses() {
        assert_eq!(fallback_text(0xe6ef_3073).as_deref(), Some("uxtb r3, r3"));
        assert_eq!(fallback_text(0xe6af_307e).as_deref(), Some("sxtb r3, lr"));
        assert_eq!(fallback_text(0xe6ff_0070).as_deref(), Some("uxth r0, r0"));
        assert_eq!(fallback_text(0xe7df_171f).as_deref(), Some("bfc r1, 0xe, 0x12"));
        assert_eq!(fallback_text(0xe7d6_3712).as_deref(), Some("bfi r3, r2, 0xe, 0x9"));
        assert_eq!(fallback_text(0xe7e8_0757).as_deref(), Some("ubfx r0, r7, 0xe, 0x9"));
        assert_eq!(fallback_text(0xe1a0_0011).as_deref(), Some("mov r0, r1, lsl r0"));
        assert_eq!(fallback_text(0xe1e0_a31c).as_deref(), Some("mvn sl, ip, lsl r3"));
        assert_eq!(fallback_text(0xe1d2_20d0).as_deref(), Some("ldrsb r2, [r2]"));
    }

    /// A wide T32 word is no A32 integer word, whatever its bits.
    #[test]
    fn a_t32_word_is_not_read_as_an_a32_integer_word() {
        assert!(decode_fallback(0xe6ef_3073, Encoding::T32).is_none());
        assert!(lift_fallback(0xe6ef_3073, Encoding::T32).is_none());
    }

    #[test]
    fn the_integer_words_lift() {
        let general = |number| il::Operand::Reg(il::Reg::General(number));
        let lift = |word| lift_fallback(word, Encoding::A32).expect("the word lifts");
        let extend = lift(0xe6ef_3073);
        assert_eq!(
            (extend.op, extend.operands.as_slice()),
            (il::Op::Extend, &[general(3), general(3)][..])
        );
        let insert = lift(0xe7d6_3712);
        assert_eq!(insert.op, il::Op::BitField);
        assert_eq!(insert.reads, [2, 3].map(il::Reg::General).into_iter().collect(), "keeps rd");
        let extract = lift(0xe7e8_0757);
        let field = [general(0), general(7), il::Operand::Const(14), il::Operand::Const(9)];
        assert_eq!(extract.operands.as_slice(), field);
        let shift = lift(0xe1a0_0011);
        assert_eq!(
            (shift.op, shift.operands.as_slice()),
            (il::Op::ShiftLeft, &[general(0), general(1), general(0)][..])
        );
        let load = lift(0xe1d2_20d0);
        assert_eq!(load.memory.and_then(|access| access.width), Some(il::Width::Bits8));
        let at = il::Operand::memory(Some(il::Reg::General(2)), Some(0));
        assert_eq!(load.operands.as_slice(), [general(2), at]);
    }

    /// A conditional word reads the flags.
    #[test]
    fn a_conditional_integer_word_reads_the_flags() {
        // `uxtbne r3, r3`
        let lifted = lift_fallback(0x16ef_3073, Encoding::A32).expect("the word lifts");
        assert!(lifted.reads.contains(il::Reg::Flags));
        assert_eq!(fallback_text(0x16ef_3073).as_deref(), Some("uxtbne r3, r3"));
    }

    /// `yaxpeax` swaps `bb` and `tt` of the multiplies of halfwords, and
    /// reads `smulwb` as `smlawb`; all 16 forms read as `llvm-mc` reads
    /// them.
    #[test]
    fn the_multiplies_of_halfwords_read_as_encoded() {
        let cases = [
            (0xe107_3182, "smlabb r7, r2, r1, r3"),
            (0xe107_31a2, "smlatb r7, r2, r1, r3"),
            (0xe107_31c2, "smlabt r7, r2, r1, r3"),
            (0xe107_31e2, "smlatt r7, r2, r1, r3"),
            (0xe127_3182, "smlawb r7, r2, r1, r3"),
            (0xe127_31a2, "smulwb r7, r2, r1"),
            (0xe127_31c2, "smlawt r7, r2, r1, r3"),
            (0xe127_31e2, "smulwt r7, r2, r1"),
            (0xe147_3182, "smlalbb r3, r7, r2, r1"),
            (0xe147_31a2, "smlaltb r3, r7, r2, r1"),
            (0xe147_31c2, "smlalbt r3, r7, r2, r1"),
            (0xe147_31e2, "smlaltt r3, r7, r2, r1"),
            (0xe167_3182, "smulbb r7, r2, r1"),
            (0xe167_31a2, "smultb r7, r2, r1"),
            (0xe167_31c2, "smulbt r7, r2, r1"),
            (0xe167_31e2, "smultt r7, r2, r1"),
        ];
        for (word, text) in cases {
            let insn = Arm32.decode(&u32::to_le_bytes(word), 0, 0).expect("the word reads");
            assert_eq!(insn.to_string(), text, "{word:#010x}");
        }
        let lift = |word: u32| {
            let bytes = word.to_le_bytes();
            Arm32.lift(&Arm32.decode(&bytes, 0, 0).unwrap()).expect("the word lifts")
        };
        let general = il::Reg::General;
        // `smulwb r7, r2, r1` multiplies and adds nothing.
        let word = lift(0xe127_31a2);
        assert_eq!(word.op, il::Op::Multiply);
        assert_eq!(word.reads, [general(2), general(1)].into_iter().collect());
        // `smlalbb r3, r7, r2, r1` adds to the pair, and writes both.
        let long = lift(0xe147_3182);
        assert_eq!(long.op, il::Op::MultiplyAdd);
        assert_eq!(long.writes, [general(3), general(7)].into_iter().collect());
        assert_eq!(
            long.reads,
            [general(1), general(2), general(3), general(7)].into_iter().collect()
        );
    }

    /// A NEON load names the alignment it asserts, as `llvm-mc` reads it:
    /// whole structures, all lanes and one lane. A sweep of 510 encodings
    /// agreed with `llvm-mc` when this was written.
    #[test]
    fn a_neon_load_names_its_alignment() {
        let cases = [
            (0xf423_0a0f, "vld1.8 {d0, d1}, [r3]"),
            (0xf423_0a1f, "vld1.8 {d0, d1}, [r3:64]"),
            (0xf423_0a2f, "vld1.8 {d0, d1}, [r3:128]"),
            (0xf423_023f, "vld1.8 {d0, d1, d2, d3}, [r3:256]"),
            (0xf4a3_0f9f, "vld4.32 {d0[], d1[], d2[], d3[]}, [r3:64]"),
            (0xf4a3_0c5f, "vld1.16 {d0[]}, [r3:16]"),
            (0xf4a3_041f, "vld1.16 {d0[0]}, [r3:16]"),
            (0xf4a3_0baf, "vld4.32 {d0[1], d1[1], d2[1], d3[1]}, [r3:128]"),
        ];
        for (word, text) in cases {
            assert_eq!(fallback_text(word).as_deref(), Some(text), "{word:#010x}");
        }
    }

    /// VFP words `yaxpeax` 0.4 refuses, as `llvm-mc` reads them.
    #[test]
    fn reads_the_vfp_words_the_decoder_refuses() {
        let cases = [
            (0xeebd_0be0, "vcvt.s32.f64 s0, d16"),
            (0xeef8_0bc0, "vcvt.f64.s32 d16, s0"),
            (0xeef8_0b40, "vcvt.f64.u32 d16, s0"),
            (0xeef5_0b40, "vcmp.f64 d16, 0x0"),
            (0xee40_1ba2, "vmla.f64 d17, d16, d18"),
            (0xec51_0b30, "vmov r0, r1, d16"),
            (0xec41_0b30, "vmov d16, r0, r1"),
            (0xee10_0a10, "vmov r0, s0"),
            (0xee00_1a10, "vmov s0, r1"),
            (0xeef1_fa10, "vmrs APSR_nzcv, fpscr"),
            (0xed2d_8b04, "vpush {d8, d9}"),
            (0xecbd_8b04, "vpop {d8, d9}"),
            (0xeef7_0a00, "vmov.f32 s1, #1.0"),
            (0xeeb8_0b00, "vmov.f64 d0, #-2.0"),
            (0xeef0_0b48, "vmov.f64 d16, d8"),
        ];
        for (word, text) in cases {
            assert_eq!(fallback_text(word).as_deref(), Some(text), "{word:#010x}");
        }
    }

    /// `yaxpeax` reads these words but drops an operand, so the decoder
    /// reads them itself, in A32 and in T32.
    #[test]
    fn the_vfp_words_the_decoder_misreads_keep_their_operands() {
        let cases = [
            (0xeef7_0a00_u32, "vmov.f32", "s1, #1.0"),
            (0xeef0_0b48, "vmov.f64", "d16, d8"),
            (0xeeb8_0b40, "vcvt.f64.u32", "d0, s0"),
            (0x1eb7_0b00, "vmov.f64ne", "d0, #1.0"),
        ];
        for (word, name, operands) in cases {
            let insn = Arm32.decode(&word.to_le_bytes(), 0, 0).expect("the word reads");
            assert_eq!(insn.to_string(), format!("{name} {operands}"));
            if word >> 28 == 0b1110 {
                let halves = [(word >> 16) as u16, word as u16];
                let bytes: Vec<u8> = halves.iter().flat_map(|half| half.to_le_bytes()).collect();
                let insn = super::super::thumb::Thumb2.decode(&bytes, 0, 0).expect("reads");
                assert_eq!(insn.to_string(), format!("{name} {operands}"));
            }
        }
        let constant = Arm32
            .lift(&Arm32.decode(&0xeef7_0a00_u32.to_le_bytes(), 0, 0).unwrap())
            .expect("the word lifts");
        assert_eq!(constant.op, il::Op::Move);
        assert_eq!(
            constant.operands.as_slice(),
            [il::Operand::Reg(il::Reg::Vector(1)), il::Operand::Const(0x3f80_0000)]
        );
        assert_eq!(constant.writes, [il::Reg::Vector(1)].into_iter().collect());
    }

    /// Each of the 256 constants of a VFP `vmov` stands for the same value
    /// as a single and as a double: a sign, then 16 to 31 sixteenths times
    /// a power of two from 2^-3 to 2^4.
    #[test]
    fn a_vfp_constant_is_the_same_value_at_both_sizes() {
        for constant in 0..=255 {
            let single = f64::from(f32::from_bits(expand_float_constant(constant, false) as u32));
            let double = f64::from_bits(expand_float_constant(constant, true));
            assert_eq!(single, double, "{constant:#x}");
            let exponent = (i32::from((constant >> 4 & 0b111) as u8) ^ 0b100) - 3;
            let sixteenths = f64::from(16 + (constant & 0b1111));
            let sign = if constant >> 7 == 1 { -1.0 } else { 1.0 };
            assert_eq!(double, sign * sixteenths / 16.0 * 2f64.powi(exponent), "{constant:#x}");
        }
    }

    /// T32 encodes the VFP as A32 does, so a T32 caller reads them too.
    #[test]
    fn a_t32_vfp_word_reads_as_its_a32_twin() {
        assert_eq!(
            decode_fallback(0xec51_0b30, Encoding::T32),
            decode_fallback(0xec51_0b30, Encoding::A32)
        );
        assert!(lift_fallback(0xec51_0b30, Encoding::T32).is_some());
    }

    #[test]
    fn a_vfp_operation_names_what_it_computes() {
        let op = |word| lift_fallback(word, Encoding::A32).expect("the word lifts").op;
        assert_eq!(op(0xee40_1ba2), il::Op::FloatMultiplyAdd, "vmla.f64");
        assert_eq!(op(0xeebd_0be0), il::Op::FloatRoundTowardZero, "vcvt.s32.f64");
        assert_eq!(op(0xeef8_0bc0), il::Op::FloatConvert, "vcvt.f64.s32");
        assert_eq!(op(0xeef5_0b40), il::Op::Float, "vcmp.f64");
    }
}
