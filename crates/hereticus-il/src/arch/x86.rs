//! The decoder and the lifter of x86, in 64-bit and 32-bit mode, which read
//! one instruction at a time and know nothing of the binary around it. The
//! rules that read x86 code, as which bytes pad and which instructions open
//! a function, are in `hereticus-recovery`, and the rules the matching reads
//! in `hereticus-arch`.
//!
//! `iced-x86` decodes, because it also says which registers and which memory
//! each instruction reads and writes. x86 hides much of that: `push` writes
//! the stack pointer, `div` reads `rdx`, and `rep movsb` reads three
//! registers it names nowhere.

use crate as il;
use crate::arch::{DecodeError, Decoder, Insn, InsnKind, InstructionSet, Printing};
use crate::{
    AccessKind, Comparison, Cond, Lifted, MemoryAccess, Op, Reg, RegSet, Test, Value, Width,
};
use compact_str::{CompactString, format_compact};
use iced_x86::{
    ConditionCode, DecoderError, DecoderOptions, FlowControl, Formatter as _, FormatterOutput,
    FormatterTextKind, InstructionInfoFactory, IntelFormatter, Mnemonic, OpAccess, OpKind,
    Register,
};

/// The longest x86 instruction, in bytes.
pub const MOST_BYTES: usize = 15;

/// The text of bytes the decoder cannot read.
const UNKNOWN_TEXT: &str = "(unknown)";

/// The mode an x86 processor decodes in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    /// 32-bit protected mode, as i386 code runs in.
    Bits32,
    /// 64-bit long mode, as x86-64 code runs in.
    Bits64,
}

impl Mode {
    /// The bitness `iced-x86` names the mode by.
    fn bitness(self) -> u32 {
        match self {
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }

    /// Bytes in one pointer.
    fn pointer_width(self) -> usize {
        match self {
            Self::Bits32 => 4,
            Self::Bits64 => 8,
        }
    }
}

/// x86, in one mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86 {
    mode: Mode,
}

/// The operation one x86 instruction encodes, as `iced-x86` names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decoded {
    /// The encoding, which also names the operand sizes.
    pub code: iced_x86::Code,
}

impl Decoded {
    /// The operation, with no operand size.
    pub fn mnemonic(self) -> Mnemonic {
        self.code.mnemonic()
    }
}

impl X86 {
    /// x86-64.
    pub const BITS64: Self = Self { mode: Mode::Bits64 };
    /// 32-bit x86.
    pub const BITS32: Self = Self { mode: Mode::Bits32 };

    /// The decoder of `mode`.
    pub const fn of(mode: Mode) -> Self {
        Self { mode }
    }

    /// The mode this decodes in.
    pub fn mode(self) -> Mode {
        self.mode
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
        let rest =
            code.get(offset..).filter(|rest| !rest.is_empty()).ok_or(DecodeError::Truncated)?;
        let insn_address = address + offset as u64;
        let inst = self.instruction_at(rest, insn_address);
        let unread = InstructionSet::X86(self.mode);
        if inst.is_invalid() {
            // A byte that opens no instruction stands alone, so the next
            // byte still starts one. Its value goes in the text, so that an
            // edit to it still shows.
            return Ok((
                Insn::new(
                    insn_address,
                    &rest[..1],
                    InsnKind::Unknown,
                    il::arch::Opcode::Unread(unread),
                ),
                printing.text(|| format!("{UNKNOWN_TEXT} {:#04x}", rest[0])),
            ));
        }
        let bytes = &rest[..inst.len()];
        let opcode = il::arch::Opcode::X86(Decoded { code: inst.code() }, self.mode);
        let insn = Insn::new(insn_address, bytes, classify(&inst), opcode);
        Ok((insn, printing.text(|| print(&inst))))
    }

    /// The instruction `bytes` open with, at `address`. An instruction cut
    /// short by the end of `bytes` is invalid.
    fn instruction_at(self, bytes: &[u8], address: u64) -> iced_x86::Instruction {
        let bytes = &bytes[..bytes.len().min(MOST_BYTES)];
        let mut decoder =
            iced_x86::Decoder::with_ip(self.mode.bitness(), bytes, address, DecoderOptions::NONE);
        let inst = decoder.decode();
        match decoder.last_error() {
            DecoderError::None => inst,
            _ => iced_x86::Instruction::default(),
        }
    }
}

impl Decoder for X86 {
    /// The condition of a jump, a move or a set is the test it applies, so
    /// `jne` and `je` stay apart. The operand size is left out: `add eax`
    /// and `add rax` are one operation on two widths.
    fn operation_name(&self, insn: &Insn) -> CompactString {
        let Some(decoded) = decoded(insn) else { return UNKNOWN_TEXT.into() };
        format_compact!("{:?}", decoded.mnemonic()).to_ascii_lowercase()
    }

    fn decode(&self, code: &[u8], offset: usize, address: u64) -> Result<Insn, DecodeError> {
        self.read(code, offset, address, Printing::Skip).map(|(insn, _)| insn)
    }

    fn triple(&self) -> &'static str {
        match self.mode {
            Mode::Bits32 => "i386-linux-gnu",
            Mode::Bits64 => "x86_64-linux-gnu",
        }
    }

    fn instruction_width(&self) -> usize {
        1
    }

    fn pointer_width(&self) -> usize {
        self.mode.pointer_width()
    }

    fn lift(&self, insn: &Insn) -> Option<Lifted> {
        Some(lift(&instruction(insn)?))
    }

    fn lift_named(&self, insn: &Insn) -> Option<il::Named> {
        let inst = instruction(insn)?;
        Some(il::Named { lifted: lift(&inst), names: names(&inst), write_back: None })
    }

    fn read_pointer(&self, bytes: &[u8]) -> u64 {
        let mut word = [0; 8];
        let width = self.mode.pointer_width();
        word[..width].copy_from_slice(&bytes[..width]);
        u64::from_le_bytes(word)
    }
}

/// What x86 `insn` encodes, where the x86 decoder read it.
pub fn decoded(insn: &Insn) -> Option<Decoded> {
    match insn.opcode {
        il::arch::Opcode::X86(decoded, _) => Some(decoded),
        _ => None,
    }
}

/// The mode x86 `insn` was read in, where the x86 decoder read it.
pub fn mode_of(insn: &Insn) -> Option<Mode> {
    match insn.opcode {
        il::arch::Opcode::X86(_, mode) | il::arch::Opcode::Unread(InstructionSet::X86(mode)) => {
            Some(mode)
        }
        _ => None,
    }
}

/// `insn` decoded again from its bytes, where the x86 decoder read it.
pub fn instruction(insn: &Insn) -> Option<iced_x86::Instruction> {
    let il::arch::Opcode::X86(_, mode) = insn.opcode else { return None };
    let inst = X86::of(mode).instruction_at(insn.bytes(), insn.address);
    (!inst.is_invalid()).then_some(inst)
}

/// How `inst` moves control.
fn classify(inst: &iced_x86::Instruction) -> InsnKind {
    let near_target = || match inst.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(inst.near_branch_target())
        }
        _ => None,
    };
    match inst.flow_control() {
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => {
            InsnKind::Jump { target: near_target() }
        }
        FlowControl::ConditionalBranch => InsnKind::Branch { target: near_target() },
        FlowControl::Return => InsnKind::Return,
        // `syscall` and `vmcall` call no function of the program.
        FlowControl::Call | FlowControl::IndirectCall if inst.mnemonic() == Mnemonic::Call => {
            InsnKind::Call { target: near_target() }
        }
        // `ud2` traps and never falls through, as a compiler puts after a
        // call that does not return.
        FlowControl::Exception => InsnKind::Return,
        FlowControl::Next
        | FlowControl::Call
        | FlowControl::IndirectCall
        | FlowControl::Interrupt
        | FlowControl::XbeginXabortXend => InsnKind::Normal,
    }
}

/// The formatter every text is printed with: lower case, `0x` numbers, the
/// size of each memory operand, and a `rip` operand as its distance, as
/// `llvm-objdump` prints them in Intel syntax.
fn formatter() -> IntelFormatter {
    let mut formatter = IntelFormatter::new();
    let options = formatter.options_mut();
    options.set_hex_prefix("0x");
    options.set_hex_suffix("");
    options.set_uppercase_hex(false);
    options.set_space_after_operand_separator(true);
    options.set_rip_relative_addresses(true);
    options.set_show_branch_size(false);
    options.set_branch_leading_zeros(false);
    options.set_space_between_memory_add_operators(true);
    options.set_scale_before_index(true);
    options.set_memory_size_options(iced_x86::MemorySizeOptions::Always);
    formatter
}

/// What a formatter writes, as one text.
struct Text(String);

impl FormatterOutput for Text {
    fn write(&mut self, text: &str, _kind: FormatterTextKind) {
        self.0.push_str(text);
    }
}

/// The text of `inst`, with a branch target as its distance from the
/// instruction, as `$+0x24`, as every decoder here names one.
fn print(inst: &iced_x86::Instruction) -> String {
    let mut formatter = formatter();
    let mut text = Text(String::new());
    formatter.format_mnemonic(inst, &mut text);
    let count = formatter.operand_count(inst);
    for operand in 0..count {
        text.0.push_str(if operand == 0 { " " } else { ", " });
        match formatter.get_instruction_operand(inst, operand) {
            Ok(Some(index)) if is_near_branch(inst.op_kind(index)) => {
                text.0.push_str(&il::target_name(distance(inst)));
            }
            _ => {
                // An operand index from the formatter itself is in range.
                let _ = formatter.format_operand(inst, &mut text, operand);
            }
        }
    }
    text.0
}

/// Whether `kind` is a branch target that the instruction names.
fn is_near_branch(kind: OpKind) -> bool {
    matches!(kind, OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64)
}

/// How far the branch target of `inst` is from the instruction.
fn distance(inst: &iced_x86::Instruction) -> i64 {
    inst.near_branch_target().wrapping_sub(inst.ip()) as i64
}

/// The register of the IL that `register` is part of, where the IL names
/// one: the 16 general registers by their encoding number, the stack
/// pointer, the vector registers, and the instruction pointer.
pub fn il_register(register: Register) -> Option<Reg> {
    if register == Register::None {
        return None;
    }
    if register.is_ip() {
        return Some(Reg::ProgramCounter);
    }
    let full = register.full_register();
    if full == Register::RSP {
        return Some(Reg::Stack);
    }
    if full.is_gpr() {
        return Some(Reg::General(full.number() as u8));
    }
    if full.is_vector_register() {
        return Some(Reg::Vector(full.number() as u8));
    }
    None
}

/// The width of a value of `bytes` bytes, where the IL names one.
fn width_of(bytes: usize) -> Option<Width> {
    match bytes {
        1 => Some(Width::Bits8),
        2 => Some(Width::Bits16),
        4 => Some(Width::Bits32),
        8 => Some(Width::Bits64),
        16 => Some(Width::Bits128),
        _ => None,
    }
}

/// The width of operand `index` of `inst`.
fn operand_width(inst: &iced_x86::Instruction, index: u32) -> Option<Width> {
    match inst.op_kind(index) {
        OpKind::Register => width_of(inst.op_register(index).size()),
        OpKind::Memory => width_of(inst.memory_size().size()),
        _ => None,
    }
}

/// How an operation reads its operands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    /// The first operand is both a source and the destination, as in
    /// `add rax, rbx`. The IL names it twice, as `rax = rax + rbx`, so it
    /// reads as a three-operand operation on every architecture.
    TwoAddress,
    /// As the instruction names them.
    AsNamed,
}

/// The operation `inst` does, and how it reads its operands.
fn op_of(inst: &iced_x86::Instruction) -> (Op, Form) {
    use Mnemonic as M;
    let mnemonic = inst.mnemonic();
    let with_memory = |load: Op, store: Op, plain: Op| match inst.op0_kind() {
        OpKind::Memory => store,
        _ if (0..inst.op_count()).any(|index| inst.op_kind(index) == OpKind::Memory) => load,
        _ => plain,
    };
    let two_address = |op| (op, Form::TwoAddress);
    let as_named = |op| (op, Form::AsNamed);
    // An operation with three operands names its destination apart, as
    // `imul eax, ebx, 3` and `andn eax, ebx, ecx` do.
    let arithmetic = |op| if inst.op_count() >= 3 { as_named(op) } else { two_address(op) };
    match mnemonic {
        M::Mov
        | M::Movd
        | M::Movq
        | M::Movss
        | M::Movsd
        | M::Movaps
        | M::Movapd
        | M::Movups
        | M::Movupd
        | M::Movdqa
        | M::Movdqu
        | M::Vmovss
        | M::Vmovsd
        | M::Vmovaps
        | M::Vmovapd
        | M::Vmovups
        | M::Vmovupd
        | M::Vmovdqa
        | M::Vmovdqu
        | M::Vmovd
        | M::Vmovq => as_named(with_memory(Op::Load, Op::Store, Op::Move)),
        M::Movzx | M::Movsx | M::Movsxd => as_named(with_memory(Op::Load, Op::Store, Op::Extend)),
        M::Cbw | M::Cwde | M::Cdqe | M::Cwd | M::Cdq | M::Cqo => as_named(Op::Extend),
        M::Lea if inst.is_ip_rel_memory_operand() => as_named(Op::Address),
        M::Lea => as_named(Op::Add),
        M::Push => as_named(Op::Store),
        M::Pop => as_named(Op::Load),
        M::Add | M::Adc | M::Inc => two_address(Op::Add),
        M::Sub | M::Sbb | M::Dec => two_address(Op::Subtract),
        M::Imul | M::Mul => arithmetic(Op::Multiply),
        M::Div | M::Idiv => as_named(Op::Divide),
        M::And => two_address(Op::And),
        M::Or => two_address(Op::Or),
        M::Xor => two_address(Op::Xor),
        M::Andn => as_named(Op::AndNot),
        M::Not => two_address(Op::Not),
        M::Neg => two_address(Op::Negate),
        M::Shl | M::Sal | M::Shlx => arithmetic(Op::ShiftLeft),
        M::Shr | M::Shrx => arithmetic(Op::ShiftRight),
        M::Sar | M::Sarx => arithmetic(Op::ShiftRightArithmetic),
        M::Rol | M::Ror | M::Rcl | M::Rcr | M::Rorx => arithmetic(Op::Rotate),
        M::Shld | M::Shrd | M::Bt | M::Bts | M::Btr | M::Btc | M::Bextr | M::Pdep | M::Pext => {
            as_named(Op::BitField)
        }
        M::Bsf | M::Bsr | M::Lzcnt | M::Tzcnt | M::Popcnt | M::Bswap => as_named(Op::Bits),
        M::Cmp | M::Test => as_named(Op::Compare),
        M::Cmove
        | M::Cmovne
        | M::Cmovb
        | M::Cmovae
        | M::Cmova
        | M::Cmovbe
        | M::Cmovl
        | M::Cmovge
        | M::Cmovg
        | M::Cmovle
        | M::Cmovs
        | M::Cmovns
        | M::Cmovo
        | M::Cmovno
        | M::Cmovp
        | M::Cmovnp
        | M::Sete
        | M::Setne
        | M::Setb
        | M::Setae
        | M::Seta
        | M::Setbe
        | M::Setl
        | M::Setge
        | M::Setg
        | M::Setle
        | M::Sets
        | M::Setns
        | M::Seto
        | M::Setno
        | M::Setp
        | M::Setnp => as_named(Op::Select),
        M::Xchg | M::Xadd | M::Cmpxchg | M::Cmpxchg8b | M::Cmpxchg16b
            if inst.has_lock_prefix() || inst.op0_kind() == OpKind::Memory =>
        {
            as_named(Op::Atomic)
        }
        M::Xchg => as_named(Op::Move),
        M::Call => as_named(Op::Call),
        M::Ret | M::Retf => as_named(Op::Return),
        M::Jmp => as_named(Op::Jump),
        _ if inst.flow_control() == FlowControl::ConditionalBranch => as_named(Op::Branch),
        M::Addss | M::Addsd | M::Vaddss | M::Vaddsd => arithmetic(Op::FloatAdd),
        M::Subss | M::Subsd | M::Vsubss | M::Vsubsd => arithmetic(Op::FloatSubtract),
        M::Mulss | M::Mulsd | M::Vmulss | M::Vmulsd => arithmetic(Op::FloatMultiply),
        M::Divss | M::Divsd | M::Vdivss | M::Vdivsd => arithmetic(Op::FloatDivide),
        M::Sqrtss | M::Sqrtsd | M::Vsqrtss | M::Vsqrtsd => as_named(Op::FloatSquareRoot),
        M::Minss
        | M::Minsd
        | M::Maxss
        | M::Maxsd
        | M::Vminss
        | M::Vminsd
        | M::Vmaxss
        | M::Vmaxsd => arithmetic(Op::FloatMinMax),
        M::Cvtsi2ss
        | M::Cvtsi2sd
        | M::Cvtss2sd
        | M::Cvtsd2ss
        | M::Cvtss2si
        | M::Cvtsd2si
        | M::Vcvtsi2ss
        | M::Vcvtsi2sd
        | M::Vcvtss2sd
        | M::Vcvtsd2ss
        | M::Vcvtss2si
        | M::Vcvtsd2si => as_named(Op::FloatConvert),
        M::Cvttss2si | M::Cvttsd2si | M::Vcvttss2si | M::Vcvttsd2si => {
            as_named(Op::FloatRoundTowardZero)
        }
        M::Ucomiss
        | M::Ucomisd
        | M::Comiss
        | M::Comisd
        | M::Vucomiss
        | M::Vucomisd
        | M::Vcomiss
        | M::Vcomisd => as_named(Op::Float),
        M::Syscall
        | M::Sysenter
        | M::Int
        | M::Int3
        | M::Int1
        | M::Into
        | M::Hlt
        | M::Ud2
        | M::Cpuid
        | M::Rdtsc
        | M::Rdtscp
        | M::Mfence
        | M::Lfence
        | M::Sfence
        | M::Pause
        | M::Endbr64
        | M::Endbr32 => as_named(Op::System),
        _ if is_vector(inst) => as_named(Op::Vector),
        _ => as_named(Op::Other),
    }
}

/// Whether `inst` works on a vector register.
fn is_vector(inst: &iced_x86::Instruction) -> bool {
    (0..inst.op_count()).any(|index| {
        inst.op_kind(index) == OpKind::Register && inst.op_register(index).is_vector_register()
    })
}

/// The condition `code` tests, as the IL names it after `cmp left, right`.
/// Parity tests no relation of the two, so the IL names none for it.
pub fn condition(code: ConditionCode) -> Option<Cond> {
    Some(match code {
        ConditionCode::o => Cond::Overflow,
        ConditionCode::no => Cond::NoOverflow,
        ConditionCode::b => Cond::UnsignedLess,
        ConditionCode::ae => Cond::UnsignedGreaterOrEqual,
        ConditionCode::e => Cond::Equal,
        ConditionCode::ne => Cond::NotEqual,
        ConditionCode::be => Cond::UnsignedLessOrEqual,
        ConditionCode::a => Cond::UnsignedGreater,
        ConditionCode::s => Cond::Negative,
        ConditionCode::ns => Cond::NotNegative,
        ConditionCode::l => Cond::SignedLess,
        ConditionCode::ge => Cond::SignedGreaterOrEqual,
        ConditionCode::le => Cond::SignedLessOrEqual,
        ConditionCode::g => Cond::SignedGreater,
        ConditionCode::None | ConditionCode::p | ConditionCode::np => return None,
    })
}

/// Operand `index` of `inst` as a value it reads.
fn value_of(inst: &iced_x86::Instruction, index: u32) -> Value {
    match il_operand(inst, index) {
        il::Operand::Reg(reg) => Value::Reg(reg),
        il::Operand::Const(value) => Value::Const(value),
        _ => Value::Other,
    }
}

/// What `inst` tests, where it tests anything.
fn test_of(inst: &iced_x86::Instruction) -> Option<Test> {
    match inst.mnemonic() {
        mnemonic @ (Mnemonic::Cmp | Mnemonic::Test) => {
            let (left, right) = (value_of(inst, 0), value_of(inst, 1));
            let comparison = match mnemonic {
                Mnemonic::Cmp => Comparison::Subtract { left, right },
                _ => Comparison::And { left, right },
            };
            Some(Test::Compare { comparison, width: operand_width(inst, 0)? })
        }
        _ if inst.flow_control() == FlowControl::ConditionalBranch => {
            Some(Test::OnFlags(condition(inst.condition_code())?))
        }
        _ => None,
    }
}

/// Operand `index` of `inst` as the IL names it.
fn il_operand(inst: &iced_x86::Instruction, index: u32) -> il::Operand {
    match inst.op_kind(index) {
        OpKind::Register => {
            il_register(inst.op_register(index)).map_or(il::Operand::Other, il::Operand::Reg)
        }
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            il::Operand::Target(Some(distance(inst)))
        }
        OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => il::Operand::Const(inst.immediate(index)),
        OpKind::Memory => {
            let base = il_register(inst.memory_base());
            // The distance from `rip` moves whenever the code does.
            let offset = (!inst.is_ip_rel_memory_operand())
                .then(|| inst.memory_displacement64() as i64)
                .filter(|&offset| offset != 0 || base.is_none());
            let index = il_register(inst.memory_index())
                .map(|reg| (reg, inst.memory_index_scale().trailing_zeros() as u8));
            il::Operand::Memory { base, offset, index, update: il::Update::None }
        }
        _ => il::Operand::Other,
    }
}

/// The IL of `inst`.
pub fn lift(inst: &iced_x86::Instruction) -> Lifted {
    let (op, form) = op_of(inst);
    let mut reads = RegSet::EMPTY;
    let mut writes = RegSet::EMPTY;
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(inst);
    for used in info.used_registers() {
        let Some(reg) = il_register(used.register()) else { continue };
        match used.access() {
            OpAccess::Read | OpAccess::CondRead => reads.insert(reg),
            OpAccess::Write | OpAccess::CondWrite => writes.insert(reg),
            OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                reads.insert(reg);
                writes.insert(reg);
            }
            OpAccess::None | OpAccess::NoMemAccess => {}
        }
    }
    let memory = memory_access(inst, info.used_memory());
    if inst.rflags_read() != 0 {
        reads.insert(Reg::Flags);
    }
    if inst.rflags_modified() != 0 {
        writes.insert(Reg::Flags);
    }
    let named = (0..inst.op_count()).map(|index| il_operand(inst, index));
    let operands = match form {
        Form::TwoAddress => {
            let destination = il_operand(inst, 0);
            core::iter::once(destination).chain(named).collect()
        }
        Form::AsNamed => named.collect(),
    };
    Lifted { op, reads, writes, memory, test: test_of(inst), operands }
}

/// How `inst` touches memory, from what `iced-x86` says it uses. A call and
/// a return touch the stack only to keep the return address, which no
/// function computes.
fn memory_access(
    inst: &iced_x86::Instruction,
    used: &[iced_x86::UsedMemory],
) -> Option<MemoryAccess> {
    if matches!(inst.mnemonic(), Mnemonic::Call | Mnemonic::Ret | Mnemonic::Lea | Mnemonic::Nop) {
        return None;
    }
    let (mut load, mut store) = (false, false);
    for access in used.iter().map(iced_x86::UsedMemory::access) {
        match access {
            OpAccess::Read | OpAccess::CondRead => load = true,
            OpAccess::Write | OpAccess::CondWrite => store = true,
            OpAccess::ReadWrite | OpAccess::ReadCondWrite => (load, store) = (true, true),
            OpAccess::None | OpAccess::NoMemAccess => {}
        }
    }
    let kind = match (load, store) {
        (true, true) => AccessKind::LoadStore,
        (true, false) => AccessKind::Load,
        (false, true) => AccessKind::Store,
        (false, false) => return None,
    };
    let width = used.first().and_then(|used| width_of(used.memory_size().size()));
    Some(MemoryAccess { kind, width })
}

/// The name of each operand of [`lift`], as a reader reads it.
pub fn names(inst: &iced_x86::Instruction) -> il::Names {
    let named = (0..inst.op_count()).map(|index| operand_name(inst, index));
    match op_of(inst).1 {
        Form::TwoAddress => core::iter::once(operand_name(inst, 0)).chain(named).collect(),
        Form::AsNamed => named.collect(),
    }
}

/// The name of a register, as `eax` or `xmm0`.
fn register_name(register: Register) -> CompactString {
    format_compact!("{register:?}").to_ascii_lowercase()
}

/// The name of operand `index` of `inst`.
fn operand_name(inst: &iced_x86::Instruction, index: u32) -> CompactString {
    match inst.op_kind(index) {
        OpKind::Register => register_name(inst.op_register(index)),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            il::target_name(distance(inst))
        }
        OpKind::Memory => {
            let index_name = (inst.memory_index() != Register::None).then(|| {
                let reg = register_name(inst.memory_index());
                match inst.memory_index_scale() {
                    1 => reg,
                    scale => format_compact!("{scale}*{reg}"),
                }
            });
            if inst.is_ip_rel_memory_operand() {
                let distance = inst.memory_displacement64().wrapping_sub(inst.next_ip()) as i64;
                return il::memory_name("rip", None, Some(distance));
            }
            let offset = Some(inst.memory_displacement64() as i64);
            match inst.memory_base() {
                Register::None => match index_name {
                    Some(index_name) => il::memory_name(&index_name, None, offset),
                    None => format_compact!("[{:#x}]", inst.memory_displacement64()),
                },
                base => {
                    let base = register_name(base);
                    match index_name {
                        // x86 adds an index and an offset in one operand, as
                        // an array in a structure needs.
                        Some(index_name) => {
                            let indexed = format_compact!("{base} + {index_name}");
                            il::memory_name(&indexed, None, offset)
                        }
                        None => il::memory_name(&base, None, offset),
                    }
                }
            }
        }
        _ => match il_operand(inst, index) {
            il::Operand::Const(value) => il::constant_name(value),
            _ => {
                let mut formatter = formatter();
                let mut text = Text(String::new());
                let _ = formatter.format_operand(inst, &mut text, index);
                text.0.into()
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn read(bytes: &[u8]) -> (Insn, String) {
        X86::BITS64.read(bytes, 0, 0x1000, Printing::Text).expect("the bytes must decode")
    }

    fn lift_one(bytes: &[u8]) -> Lifted {
        X86::BITS64.lift(&read(bytes).0).expect("the bytes must lift")
    }

    fn general(number: u8) -> Reg {
        Reg::General(number)
    }

    #[rstest]
    #[case::push(&[0x55], "push rbp", InsnKind::Normal)]
    #[case::ret(&[0xc3], "ret", InsnKind::Return)]
    #[case::call(&[0xe8, 0x10, 0x00, 0x00, 0x00], "call $+0x15", InsnKind::Call { target: Some(0x1015) })]
    #[case::jne(&[0x75, 0xfe], "jne $+0x0", InsnKind::Branch { target: Some(0x1000) })]
    #[case::jmp(&[0xe9, 0x00, 0x01, 0x00, 0x00], "jmp $+0x105", InsnKind::Jump { target: Some(0x1105) })]
    #[case::jmp_register(&[0xff, 0xe0], "jmp rax", InsnKind::Jump { target: None })]
    #[case::call_register(&[0xff, 0xd0], "call rax", InsnKind::Call { target: None })]
    #[case::syscall(&[0x0f, 0x05], "syscall", InsnKind::Normal)]
    #[case::ud2(&[0x0f, 0x0b], "ud2", InsnKind::Return)]
    #[case::rip_load(&[0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00], "mov rax, qword ptr [rip + 0x10]", InsnKind::Normal)]
    fn an_instruction_reads_its_length_kind_and_text(
        #[case] bytes: &[u8],
        #[case] text: &str,
        #[case] kind: InsnKind,
    ) {
        let (insn, printed) = read(bytes);
        assert_eq!(insn.bytes_len, bytes.len());
        assert_eq!(insn.kind, kind);
        assert_eq!(printed, text);
        assert_eq!(insn.to_string(), text);
    }

    #[test]
    fn a_byte_that_opens_no_instruction_stands_alone() {
        // `0x06` is `push es`, which 64-bit mode does not have.
        let (insn, text) = read(&[0x06, 0x90]);
        assert_eq!(insn.bytes_len, 1);
        assert_eq!(insn.kind, InsnKind::Unknown);
        assert_eq!(text, "(unknown) 0x06");
        assert_eq!(insn.to_string(), text);
    }

    #[test]
    fn an_instruction_cut_short_is_truncated() {
        // The end of the code cuts `call` short. It stands alone, as a byte
        // that opens no instruction does.
        let (insn, _) = read(&[0xe8, 0x10]);
        assert_eq!(insn.kind, InsnKind::Unknown);
        assert_eq!(X86::BITS64.decode(&[], 0, 0x1000), Err(DecodeError::Truncated));
    }

    #[test]
    fn thirty_two_bit_mode_reads_its_own_instructions() {
        // `0x40` is `inc eax` in 32-bit mode, and a prefix in 64-bit mode.
        let (insn, text) =
            X86::BITS32.read(&[0x40], 0, 0x1000, Printing::Text).expect("the byte must decode");
        assert_eq!((insn.bytes_len, text.as_str()), (1, "inc eax"));
        assert_eq!(X86::BITS32.pointer_width(), 4);
        assert_eq!(X86::BITS32.read_pointer(&[0x78, 0x56, 0x34, 0x12]), 0x1234_5678);
    }

    #[test]
    fn the_operation_name_keeps_the_condition_and_drops_the_size() {
        let name = |bytes: &[u8]| X86::BITS64.operation_name(&read(bytes).0);
        assert_eq!(name(&[0x48, 0x01, 0xd8]), "add"); // add rax, rbx
        assert_eq!(name(&[0x01, 0xd8]), "add"); // add eax, ebx
        assert_eq!(name(&[0x75, 0x00]), "jne");
        assert_eq!(name(&[0x74, 0x00]), "je");
    }

    #[test]
    fn a_two_address_operation_names_its_destination_twice() {
        // add rax, rbx
        let lifted = lift_one(&[0x48, 0x01, 0xd8]);
        assert_eq!(lifted.op, Op::Add);
        let rax = il::Operand::Reg(general(0));
        let rbx = il::Operand::Reg(general(3));
        assert_eq!(lifted.operands.as_slice(), [rax, rax, rbx]);
        assert!(lifted.reads.contains(general(0)) && lifted.reads.contains(general(3)));
        assert!(lifted.writes.contains(general(0)) && lifted.writes.contains(Reg::Flags));
    }

    #[test]
    fn a_register_exclusive_or_itself_is_a_move_of_zero() {
        // xor eax, eax
        let lifted = lift_one(&[0x31, 0xc0]).canonical();
        assert_eq!(lifted.op, Op::Move);
        assert_eq!(
            lifted.operands.as_slice(),
            [il::Operand::Reg(general(0)), il::Operand::Const(0)]
        );
    }

    #[test]
    fn push_stores_and_moves_the_stack_pointer() {
        let lifted = lift_one(&[0x55]);
        assert_eq!(lifted.op, Op::Store);
        assert_eq!(lifted.memory.map(|access| access.kind), Some(AccessKind::Store));
        assert!(lifted.reads.contains(general(5)));
        assert!(lifted.writes.contains(Reg::Stack));
    }

    #[test]
    fn a_memory_operand_names_its_base_index_and_offset() {
        // mov eax, [rbx+rcx*4+0x10]
        let lifted = lift_one(&[0x8b, 0x44, 0x8b, 0x10]);
        assert_eq!(lifted.op, Op::Load);
        assert_eq!(
            lifted.operands[1],
            il::Operand::Memory {
                base: Some(general(3)),
                offset: Some(0x10),
                index: Some((general(1), 2)),
                update: il::Update::None,
            }
        );
        let names = names(&instruction(&read(&[0x8b, 0x44, 0x8b, 0x10]).0).expect("decoded"));
        assert_eq!(names.as_slice(), ["eax", "[rbx + 4*rcx + 0x10]"]);
    }

    #[test]
    fn a_rip_relative_operand_names_no_offset() {
        // lea rdi, [rip+0x10]
        let lifted = lift_one(&[0x48, 0x8d, 0x3d, 0x10, 0x00, 0x00, 0x00]);
        assert_eq!(lifted.op, Op::Address);
        assert_eq!(lifted.operands[1], il::Operand::memory(Some(Reg::ProgramCounter), None));
    }

    #[rstest]
    #[case::cmp(&[0x48, 0x83, 0xf8, 0x05], Comparison::Subtract { left: Value::Reg(Reg::General(0)), right: Value::Const(5) })]
    #[case::test(&[0x85, 0xc0], Comparison::And { left: Value::Reg(Reg::General(0)), right: Value::Reg(Reg::General(0)) })]
    fn a_compare_names_what_it_compares(#[case] bytes: &[u8], #[case] comparison: Comparison) {
        let lifted = lift_one(bytes);
        assert_eq!(lifted.op, Op::Compare);
        assert!(
            matches!(lifted.test, Some(Test::Compare { comparison: found, .. }) if found == comparison)
        );
    }

    #[rstest]
    #[case::je(0x74, Cond::Equal)]
    #[case::jb(0x72, Cond::UnsignedLess)]
    #[case::ja(0x77, Cond::UnsignedGreater)]
    #[case::jl(0x7c, Cond::SignedLess)]
    #[case::jg(0x7f, Cond::SignedGreater)]
    fn a_conditional_jump_tests_the_flags(#[case] opcode: u8, #[case] cond: Cond) {
        let lifted = lift_one(&[opcode, 0x00]);
        assert_eq!(lifted.op, Op::Branch);
        assert_eq!(lifted.test, Some(Test::OnFlags(cond)));
        assert!(lifted.reads.contains(Reg::Flags));
    }

    #[test]
    fn a_parity_jump_tests_no_relation() {
        assert_eq!(lift_one(&[0x7a, 0x00]).test, None);
    }

    /// Every lift names each operand once, and whatever the bytes, a read
    /// never claims more bytes than the code holds.
    #[test]
    fn a_read_stays_inside_its_code() {
        bolero::check!().with_type::<[u8; 16]>().for_each(|code| {
            for x86 in [X86::BITS64, X86::BITS32] {
                let Ok((insn, text)) = x86.read(code, 0, 0x1000, Printing::Text) else {
                    panic!("16 bytes always hold an instruction or a byte")
                };
                assert!((1..=MOST_BYTES).contains(&insn.bytes_len));
                assert_eq!(insn.to_string(), crate::arch::one_space(&text));
                if let Some(inst) = instruction(&insn) {
                    assert_eq!(lift(&inst).operands.len(), names(&inst).len(), "{text}");
                }
            }
        });
    }
}
