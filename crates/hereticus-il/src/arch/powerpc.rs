//! The decoder and the lifter of PowerPC, 32-bit and 64-bit, in either
//! byte order, which read one word at a time and know nothing of the binary
//! around it. The rules that find
//! functions in PowerPC code are in `hereticus-recovery`, and the rules the
//! matching reads in `hereticus-arch`.
//!
//! `yaxpeax-power` reads each word as some version of the Power ISA defines
//! it: the PowerPC of the 603 and the 750, the Book E words of the e500 and
//! the 440, as `isel` and `wrteei`, and AltiVec. No version of it reads the
//! signal processing extension of the e500, as `evldd`, so such a word stays
//! unread. 32-bit firmware ships big endian, and 64-bit Linux little endian
//! since POWER8; both orders are read in both modes.
//!
//! The IL keeps the link register, the count register and the fixed-point
//! exception register, which holds the carry, after the 32 general
//! registers. The eight fields of the condition register are one
//! [`il::Reg::Flags`]: a compiler puts a compare and the branch that reads
//! it in one field, so one register is enough to pair them.

use crate as il;
use crate::arch::{DecodeError, Decoder, Insn, InsnKind, InstructionSet, Printing, split_printed};
use compact_str::{CompactString, format_compact};
use smallvec::SmallVec;
use yaxpeax_arch::{Decoder as _, U8Reader};
use yaxpeax_power::{AliasOp, InstDecoder, Instruction, IsaVersion, OpcodeAlias, Operand};

pub use yaxpeax_power::Opcode;

/// Every PowerPC instruction is 4 bytes wide.
pub const INSN_WIDTH: usize = 4;

/// The text of a word the decoder cannot read.
const UNKNOWN_TEXT: &str = "(unknown)";

/// The link register, which a call writes and a return reads.
pub const LINK: il::Reg = il::Reg::General(32);

/// The count register, which `bctr` jumps through and `bdnz` counts down.
pub const COUNT: il::Reg = il::Reg::General(33);

/// The fixed-point exception register, which holds the carry.
pub const CARRY: il::Reg = il::Reg::General(34);

/// The general register that holds the stack pointer.
pub const STACK: u8 = 1;

/// The width of a compare that does not set the L bit, which `cmpw` and
/// `cmplw` are in both modes.
const WIDTH: il::Width = il::Width::Bits32;

/// The number of the special-purpose register [`CARRY`] names.
const SPR_XER: u16 = 1;

/// The number of the special-purpose register [`LINK`] names.
pub const SPR_LR: u16 = 8;

/// The number of the special-purpose register [`COUNT`] names.
pub const SPR_CTR: u16 = 9;

/// How wide an address and a general register of PowerPC are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    /// 32 bits, as the 603, the 750 and the e500 run.
    Bits32,
    /// 64 bits, as POWER and the e5500 run.
    Bits64,
}

/// PowerPC, in one byte order and one mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowerPc {
    order: ByteOrder,
    mode: Mode,
}

pub use super::ByteOrder;

impl PowerPc {
    /// 32-bit, big endian, as most PowerPC firmware is.
    pub const BIG: Self = Self { order: ByteOrder::Big, mode: Mode::Bits32 };
    /// 32-bit, little endian.
    pub const LITTLE: Self = Self { order: ByteOrder::Little, mode: Mode::Bits32 };
    /// 64-bit, big endian, with the ELFv1 ABI as Linux built it before
    /// POWER8.
    pub const BIG64: Self = Self { order: ByteOrder::Big, mode: Mode::Bits64 };
    /// 64-bit, little endian, with the ELFv2 ABI, as Linux runs on POWER8
    /// and later.
    pub const LITTLE64: Self = Self { order: ByteOrder::Little, mode: Mode::Bits64 };

    /// The decoder of `order` and `mode`, which lives as long as the
    /// program, as [`crate::arch::reader_of`] needs.
    pub fn of(order: ByteOrder, mode: Mode) -> &'static Self {
        match (order, mode) {
            (ByteOrder::Big, Mode::Bits32) => &Self::BIG,
            (ByteOrder::Little, Mode::Bits32) => &Self::LITTLE,
            (ByteOrder::Big, Mode::Bits64) => &Self::BIG64,
            (ByteOrder::Little, Mode::Bits64) => &Self::LITTLE64,
        }
    }

    /// The byte order this decoder reads.
    pub fn order(self) -> ByteOrder {
        self.order
    }

    /// The width of an address and a general register.
    pub fn mode(self) -> Mode {
        self.mode
    }

    /// The word `bytes` hold, in this byte order.
    pub fn word(self, bytes: [u8; INSN_WIDTH]) -> u32 {
        self.order.read_word(bytes)
    }

    /// The decoder of every word some version of the Power ISA defines:
    /// see the module.
    fn decoder(self) -> InstDecoder {
        InstDecoder::for_cpu(IsaVersion::All).with_be(self.order == ByteOrder::Big)
    }
}

/// What [`Insn::opcode`] holds for PowerPC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decoded {
    /// The operation the decoder read. It leaves out the record and the
    /// overflow bits, so `add.` and `addo` are [`Opcode::ADD`].
    pub opcode: Opcode,
}

impl PowerPc {
    /// The instruction at `offset` of `code`, which starts at `address`,
    /// and its text where `printing` asks for it.
    pub fn read(
        self,
        code: &[u8],
        offset: usize,
        address: u64,
        printing: Printing,
    ) -> Result<(Insn, String), DecodeError> {
        let bytes = code
            .get(offset..)
            .and_then(|rest| rest.get(..INSN_WIDTH))
            .ok_or(DecodeError::Truncated)?;
        let insn_address = address + offset as u64;
        let word = self.word([bytes[0], bytes[1], bytes[2], bytes[3]]);

        let Ok(inst) = self.decoder().decode(&mut U8Reader::new(bytes)) else {
            // Every instruction is 4 bytes, so stepping over an unreadable
            // one keeps the rest aligned. Its word goes in the text, so
            // that an edit to it still shows.
            let insn = Insn::new(
                insn_address,
                bytes,
                InsnKind::Unknown,
                crate::arch::Opcode::Unread(InstructionSet::PowerPc(self)),
            );
            return Ok((insn, printing.text(|| format!("{UNKNOWN_TEXT} {word:#010x}"))));
        };

        let kind = classify(&inst, word, insn_address, self.mode);
        let text = printing.text(|| print(&inst, word));
        let opcode = crate::arch::Opcode::PowerPc(Decoded { opcode: inst.opcode() }, self);
        Ok((Insn::new(insn_address, bytes, kind, opcode), text))
    }
}

impl Decoder for PowerPc {
    /// A branch is named by the test it applies, so `beq` and `bne` stay
    /// apart, as on ARM. The CR field it reads is left out: which field a
    /// compiler picks is register allocation. An alias names the operation
    /// it stands for: `or r3, r4, r4` is `mr`, and `rlwinm` that only
    /// shifts is `slwi` or `srwi`.
    fn operation_name(&self, insn: &Insn) -> CompactString {
        let (Some(inst), Some(word)) = (instruction(insn), word_of(insn)) else {
            return UNKNOWN_TEXT.into();
        };
        let link = if inst.lk() { "l" } else { "" };
        let test = BranchTest::of(word);
        match inst.opcode() {
            Opcode::B | Opcode::BA => "b".into(),
            Opcode::BL | Opcode::BLA => "bl".into(),
            Opcode::BC | Opcode::BCA | Opcode::BCL | Opcode::BCLA => {
                format_compact!("b{}{link}", test.name())
            }
            Opcode::BCLR => format_compact!("b{}lr{link}", test.name()),
            Opcode::BCCTR => format_compact!("b{}ctr{link}", test.name()),
            _ => format_compact!("{}", inst.compute_alias().opcode()),
        }
    }

    fn decode(&self, code: &[u8], offset: usize, address: u64) -> Result<Insn, DecodeError> {
        self.read(code, offset, address, Printing::Skip).map(|(insn, _)| insn)
    }

    fn triple(&self) -> &'static str {
        match (self.order, self.mode) {
            (ByteOrder::Big, Mode::Bits32) => "powerpc",
            (ByteOrder::Little, Mode::Bits32) => "powerpcle",
            (ByteOrder::Big, Mode::Bits64) => "powerpc64",
            (ByteOrder::Little, Mode::Bits64) => "powerpc64le",
        }
    }

    fn instruction_width(&self) -> usize {
        INSN_WIDTH
    }

    fn pointer_width(&self) -> usize {
        match self.mode {
            Mode::Bits32 => 4,
            Mode::Bits64 => 8,
        }
    }

    fn read_pointer(&self, bytes: &[u8]) -> u64 {
        let width = self.pointer_width();
        let word = bytes[..width].iter().map(|&byte| u64::from(byte));
        match self.order {
            ByteOrder::Big => word.fold(0, |value, byte| value << 8 | byte),
            ByteOrder::Little => word.rev().fold(0, |value, byte| value << 8 | byte),
        }
    }

    fn data_order(&self) -> crate::arch::ByteOrder {
        self.order
    }

    fn lift(&self, insn: &Insn) -> Option<il::Lifted> {
        lifted(insn)
    }

    fn lift_named(&self, insn: &Insn) -> Option<il::Named> {
        let (inst, word) = (instruction(insn)?, word_of(insn)?);
        Some(il::Named { lifted: lift(&inst, word), names: names(&inst), write_back: None })
    }
}

/// What [`PowerPc`] read for `insn`, where it read PowerPC.
pub fn decoded(insn: &Insn) -> Option<Decoded> {
    match insn.opcode {
        crate::arch::Opcode::PowerPc(decoded, _) => Some(decoded),
        _ => None,
    }
}

/// The decoder that read `insn`, where it read PowerPC or found no
/// instruction there.
pub fn reader(insn: &Insn) -> Option<PowerPc> {
    match insn.opcode {
        crate::arch::Opcode::PowerPc(_, reader)
        | crate::arch::Opcode::Unread(InstructionSet::PowerPc(reader)) => Some(reader),
        _ => None,
    }
}

/// `insn` decoded again, where it is a PowerPC instruction.
pub fn instruction(insn: &Insn) -> Option<Instruction> {
    decoded(insn)?;
    reader(insn)?.decoder().decode(&mut U8Reader::new(insn.bytes())).ok()
}

/// The word of `insn`, in the byte order that read it, where it is a word
/// that PowerPC read.
pub fn word_of(insn: &Insn) -> Option<u32> {
    Some(reader(insn)?.word(insn.bytes().try_into().ok()?))
}

/// `insn` lifted, where it is a PowerPC instruction.
pub fn lifted(insn: &Insn) -> Option<il::Lifted> {
    Some(lift(&instruction(insn)?, word_of(insn)?))
}

/// The text of `inst`, which was read from `word`, as `yaxpeax-power`
/// prints it, with the target in the `$+0x24` form of every decoder.
///
/// `yaxpeax-power` names an always-taken `bcl 20, 31`, which PIC code runs
/// to read the program counter, as `bl` with a field of the condition
/// register. That reads as a call, so it prints as `llvm-objdump` does.
fn print(inst: &Instruction, word: u32) -> String {
    let printed = inst.to_string();
    let Some(distance) = distance(inst) else { return printed };
    let target = il::target_name(distance);
    if is_conditional_form(inst.opcode()) && BranchTest::of(word) == BranchTest::Always {
        let name = inst.opcode().name();
        let (bo, bi) = (word >> 21 & 0x1f, word >> 16 & 0x1f);
        return format!("{name} {bo}, {bi}, {target}");
    }
    let (name, operands) = split_printed(&printed);
    match operands.rsplit_once(',') {
        Some((head, _)) => format!("{name} {head}, {target}"),
        None => format!("{name} {target}"),
    }
}

/// Whether `opcode` is a `bc` with its target in the word.
fn is_conditional_form(opcode: Opcode) -> bool {
    matches!(opcode, Opcode::BC | Opcode::BCA | Opcode::BCL | Opcode::BCLA)
}

/// How far the target of a relative branch lies from the branch.
fn distance(inst: &Instruction) -> Option<i64> {
    operands(inst).iter().find_map(|operand| match *operand {
        Operand::BranchOffset16(distance) => Some(distance.into()),
        Operand::BranchOffset(distance) => Some(distance.into()),
        _ => None,
    })
}

/// Where a branch at `address` goes, where its word holds the target.
fn target_of(inst: &Instruction, address: u64, mode: Mode) -> Option<u64> {
    operands(inst).iter().find_map(|operand| match *operand {
        Operand::BranchOffset16(distance) => address.checked_add_signed(distance.into()),
        Operand::BranchOffset(distance) => address.checked_add_signed(distance.into()),
        // An absolute target is sign-extended to the width of the address.
        Operand::BranchAbs(target) => Some(match mode {
            Mode::Bits32 => u64::from(target as u32),
            Mode::Bits64 => target as i64 as u64,
        }),
        _ => None,
    })
}

/// The operands of `inst`, in the order of the hardware.
fn operands(inst: &Instruction) -> SmallVec<[Operand; 5]> {
    (0..inst.operand_count()).filter_map(|index| inst.operand(index as u8).copied()).collect()
}

/// Whether a conditional branch takes its target where a bit of the
/// condition register is set or where it is clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitValue {
    /// It branches where the bit is set.
    Set,
    /// It branches where the bit is clear.
    Clear,
}

/// What a branch that counts down the count register tests it for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CountTest {
    /// It branches where the count reaches zero, as `bdz` does.
    Zero,
    /// It branches where the count is not yet zero, as `bdnz` does.
    NotZero,
}

/// What a `bc`, `bclr` or `bcctr` tests, from its BO and BI fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BranchTest {
    /// It always branches.
    Always,
    /// It tests one bit of the condition register: bit `bit % 4` of field
    /// `bit / 4`, which says less, greater, equal or overflow.
    Bit {
        /// The bit, from 0 to 31.
        bit: u8,
        /// Whether it branches where the bit is set or clear.
        when: BitValue,
    },
    /// It counts the count register down and tests it, and tests a bit too
    /// where `bit` holds one.
    Count {
        /// What it tests the count for.
        until: CountTest,
        /// The bit it tests too, and how.
        bit: Option<(u8, BitValue)>,
    },
}

impl BranchTest {
    /// The test of the branch in `word`.
    ///
    /// Of the BO field, `0x10` says to test no bit, `0x08` which value of
    /// the bit branches, `0x04` to leave the count alone, and `0x02` which
    /// value of the count branches. The lowest bit and `0x01` of the old
    /// form are hints, which change nothing a branch does.
    pub fn of(word: u32) -> Self {
        let bo = word >> 21 & 0x1f;
        let bit = (word >> 16 & 0x1f) as u8;
        let when = if bo & 0x08 != 0 { BitValue::Set } else { BitValue::Clear };
        let tested = (bo & 0x10 == 0).then_some((bit, when));
        match (bo & 0x04 == 0, tested) {
            (false, None) => Self::Always,
            (false, Some((bit, when))) => Self::Bit { bit, when },
            (true, bit) => {
                let until = if bo & 0x02 != 0 { CountTest::Zero } else { CountTest::NotZero };
                Self::Count { until, bit }
            }
        }
    }

    /// The condition on the flags that the branch takes, where it tests
    /// only a bit. A less or greater bit counts as signed: see
    /// [`il::Comparison::Unsigned`] for the compares that set it unsigned.
    pub fn cond(self) -> Option<il::Cond> {
        match self {
            Self::Bit { bit, when } => Some(bit_cond(bit, when)),
            Self::Always | Self::Count { .. } => None,
        }
    }

    /// The part of the name of a branch that says its test, as `eq` in
    /// `beq` and `dnz` in `bdnz`.
    fn name(self) -> CompactString {
        match self {
            Self::Always => CompactString::default(),
            Self::Bit { bit, when } => bit_name(bit, when).into(),
            Self::Count { until, bit } => {
                let until = match until {
                    CountTest::Zero => "dz",
                    CountTest::NotZero => "dnz",
                };
                let bit = match bit {
                    Some((_, BitValue::Set)) => "t",
                    Some((_, BitValue::Clear)) => "f",
                    None => "",
                };
                format_compact!("{until}{bit}")
            }
        }
    }
}

/// The condition a branch on bit `bit` of the condition register tests,
/// where it branches as `when` says.
fn bit_cond(bit: u8, when: BitValue) -> il::Cond {
    let set = match bit % 4 {
        0 => il::Cond::SignedLess,
        1 => il::Cond::SignedGreater,
        2 => il::Cond::Equal,
        _ => il::Cond::Overflow,
    };
    match when {
        BitValue::Set => set,
        BitValue::Clear => set.opposite(),
    }
}

/// The name of the test of bit `bit`, as the extended mnemonics spell it.
fn bit_name(bit: u8, when: BitValue) -> &'static str {
    const SET: [&str; 4] = ["lt", "gt", "eq", "so"];
    const CLEAR: [&str; 4] = ["ge", "le", "ne", "ns"];
    let index = usize::from(bit % 4);
    match when {
        BitValue::Set => SET[index],
        BitValue::Clear => CLEAR[index],
    }
}

/// How `inst`, read from `word` at `address`, moves control.
pub(crate) fn classify(inst: &Instruction, word: u32, address: u64, mode: Mode) -> InsnKind {
    let target = target_of(inst, address, mode);
    let test = BranchTest::of(word);
    match (inst.opcode(), inst.lk(), test) {
        (Opcode::B | Opcode::BA, _, _) => InsnKind::Jump { target },
        (Opcode::BL | Opcode::BLA, _, _) => InsnKind::Call { target },
        (opcode, link, test) if is_conditional_form(opcode) => match (link, test) {
            // `bcl 20, 31` to the next word reads the program counter into
            // the link register, as PIC code does to find its table. It
            // calls nothing.
            (true, BranchTest::Always) if target == address.checked_add(4) => InsnKind::Normal,
            (true, BranchTest::Always) => InsnKind::Call { target },
            // A compiler calls on no condition, but data decodes as such
            // a call. It names no target, so it starts no function.
            (true, _) => InsnKind::Call { target: None },
            (false, BranchTest::Always) => InsnKind::Jump { target },
            (false, _) => InsnKind::Branch { target },
        },
        (Opcode::BCLR, false, BranchTest::Always) => InsnKind::Return,
        (Opcode::BCCTR, false, BranchTest::Always) => InsnKind::Jump { target: None },
        // A return or a jump on a condition, as `beqlr`, falls through
        // where the condition fails.
        (Opcode::BCLR | Opcode::BCCTR, false, _) => InsnKind::Branch { target: None },
        (Opcode::BCLR | Opcode::BCCTR, true, _) => InsnKind::Call { target: None },
        (Opcode::RFI | Opcode::RFID | Opcode::HRFID | Opcode::RFSVC, _, _) => InsnKind::Return,
        // `trap` stops the program, and control does not come back to the
        // next word, so it ends the code as a jump does.
        _ if is_trap(inst, word) => InsnKind::Jump { target: None },
        _ => InsnKind::Normal,
    }
}

/// Whether `inst` traps whatever its registers hold, as `trap` does: the
/// TO field asks for all five tests.
pub fn is_trap(inst: &Instruction, word: u32) -> bool {
    matches!(inst.opcode(), Opcode::TW | Opcode::TWI | Opcode::TD | Opcode::TDI)
        && word >> 21 & 0x1f == 0x1f
}

/// What an instruction does with its operands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// Writes its first operand from the others, as `add` does.
    Compute,
    /// Writes its first operand from the others and from itself, as
    /// `rlwimi` puts bits into it.
    Insert,
    /// Loads its first operand, or from it to `r31` for `lmw`.
    Load(Registers),
    /// Stores its first operand, or from it to `r31` for `stmw`.
    Store(Registers),
    /// Reads every operand and writes none, as `cmpw`, `tw` and `dcbz` do.
    ReadOnly,
    /// Moves control, as `b` and `bclr` do.
    Control,
}

/// How many registers a load or a store moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Registers {
    /// One, its first operand.
    One,
    /// Each from its first operand to `r31`, as `lmw` and `stmw` move.
    ToLast,
}

/// Whether a load or a store writes the address it formed back to its base.
fn updates(opcode: Opcode) -> bool {
    use Opcode::*;
    matches!(
        opcode,
        LBZU | LBZUX
            | LHZU
            | LHZUX
            | LHAU
            | LHAUX
            | LWZU
            | LWZUX
            | LWAUX
            | LDU
            | LDUX
            | LFSU
            | LFSUX
            | LFDU
            | LFDUX
            | STBU
            | STBUX
            | STHU
            | STHUX
            | STWU
            | STWUX
            | STDU
            | STDUX
            | STFSU
            | STFSUX
            | STFDU
            | STFDUX
            | PSQ_LU
            | PSQ_LUX
            | PSQ_STU
            | PSQ_STUX
    )
}

/// How `opcode` touches memory, and how wide each value it moves is, where
/// it touches memory.
fn access_of(opcode: Opcode) -> Option<(il::AccessKind, Option<il::Width>)> {
    use Opcode::*;
    use il::AccessKind::{Load, Store};
    use il::Width::{Bits8, Bits16, Bits32, Bits64, Bits128};
    Some(match opcode {
        LBZ | LBZU | LBZX | LBZUX => (Load, Some(Bits8)),
        LHZ | LHZU | LHZX | LHZUX | LHA | LHAU | LHAX | LHAUX | LHBRX => (Load, Some(Bits16)),
        LWZ | LWZU | LWZX | LWZUX | LWA | LWAX | LWAUX | LWBRX | LWARX | LMW | LFS | LFSU
        | LFSX | LFSUX => (Load, Some(Bits32)),
        LD | LDU | LDX | LDUX | LDBRX | LDARX | LFD | LFDU | LFDX | LFDUX => (Load, Some(Bits64)),
        LVX | LVXL | LVLX | LVRX | LVLXL | LVRXL | LVX128 | LVXL128 | LVLX128 | LVRX128
        | LVLXL128 | LVRXL128 => (Load, Some(Bits128)),
        LVEBX => (Load, Some(Bits8)),
        LVEHX => (Load, Some(Bits16)),
        LVEWX | LVEWX128 => (Load, Some(Bits32)),
        LSWI | LSWX | PSQ_L | PSQ_LU | PSQ_LX | PSQ_LUX => (Load, None),
        STB | STBU | STBX | STBUX => (Store, Some(Bits8)),
        STH | STHU | STHX | STHUX | STHBRX => (Store, Some(Bits16)),
        STW | STWU | STWX | STWUX | STWBRX | STWCX | STMW | STFS | STFSU | STFSX | STFSUX
        | STFIWX => (Store, Some(Bits32)),
        STD | STDU | STDX | STDUX | STDBRX | STDCX | STFD | STFDU | STFDX | STFDUX => {
            (Store, Some(Bits64))
        }
        STVX | STVXL | STVLX | STVRX | STVLXL | STVRXL | STVEPX | STVEPXL | STVX128 | STVXL128
        | STVLX128 | STVRX128 | STVLXL128 | STVRXL128 => (Store, Some(Bits128)),
        STVEBX => (Store, Some(Bits8)),
        STVEHX => (Store, Some(Bits16)),
        STVEWX | STVEWX128 => (Store, Some(Bits32)),
        STSWI | STSWX | PSQ_ST | PSQ_STU | PSQ_STX | PSQ_STUX => (Store, None),
        _ => return None,
    })
}

/// What `opcode`, read as `alias`, does with its operands.
fn role_of(opcode: Opcode, alias: OpcodeAlias) -> Role {
    use Opcode::*;
    if let Some((kind, _)) = access_of(opcode) {
        let registers = match opcode {
            LMW | STMW => Registers::ToLast,
            _ => Registers::One,
        };
        return match kind {
            il::AccessKind::Load => Role::Load(registers),
            _ => Role::Store(registers),
        };
    }
    match (opcode, alias) {
        (_, OpcodeAlias::Alias(AliasOp::NOP)) => Role::ReadOnly,
        (RLWIMI | RLDIMI | RLMI, _) => Role::Insert,
        (B | BA | BL | BLA | BC | BCA | BCL | BCLA | BCLR | BCCTR, _) => Role::Control,
        (
            CMP | CMPI | CMPL | CMPLI | FCMPU | FCMPO | TW | TWI | TD | TDI | SC | SYNC | ISYNC
            | EIEIO | MBAR | TLBSYNC | DCBA | DCBF | DCBI | DCBST | DCBT | DCBT_AS | DCBTST
            | DCBTLS | DCBZ | DCBZ_L | DCBZ128 | ICBI | TLBIA | TLBIE | TLBI | TLBWE | TLBSX
            | TLBIVAX | TLBRE | MTMSR | MTMSRD | MTMSRD_Xenon | WRTEE | WRTEEI | MTSR | MTSRIN
            | MTSRD | MTSRDIN | RFI | RFID | HRFID | RFSVC | DSS | DSSALL | DST | DSTT | DSTST
            | DSTSTT | MTVSCR,
            _,
        ) => Role::ReadOnly,
        _ => Role::Compute,
    }
}

/// What `inst` computes, named as on every architecture.
fn op_of(inst: &Instruction, alias: OpcodeAlias, test: BranchTest) -> il::Op {
    use il::Op;
    let opcode = inst.opcode();
    if let Some((kind, _)) = access_of(opcode) {
        return match (opcode, kind) {
            (Opcode::LWARX | Opcode::LDARX | Opcode::STWCX | Opcode::STDCX, _) => Op::Atomic,
            (_, il::AccessKind::Load) => Op::Load,
            _ => Op::Store,
        };
    }
    match alias {
        OpcodeAlias::Alias(alias) => {
            if let Some(op) = alias_op(alias) {
                return op;
            }
        }
        OpcodeAlias::Hardware(_) => {}
    }
    let link = inst.lk();
    match opcode {
        Opcode::B | Opcode::BA => Op::Jump,
        Opcode::BL | Opcode::BLA => Op::Call,
        // `bcl 20, 31` to the next word forms the address of that word.
        opcode if is_conditional_form(opcode) && link && distance(inst) == Some(4) => Op::Address,
        opcode if is_conditional_form(opcode) => match (link, test) {
            (true, _) => Op::Call,
            (false, BranchTest::Always) => Op::Jump,
            (false, _) => Op::Branch,
        },
        Opcode::BCLR if link => Op::Call,
        Opcode::BCLR => Op::Return,
        Opcode::BCCTR => match (link, test) {
            (true, _) => Op::Call,
            (false, BranchTest::Always) => Op::Jump,
            (false, _) => Op::Branch,
        },
        Opcode::RFI | Opcode::RFID | Opcode::HRFID | Opcode::RFSVC => Op::Return,
        opcode => plain_op(opcode),
    }
}

/// What an alias computes, where it names an operation of its own.
fn alias_op(alias: AliasOp) -> Option<il::Op> {
    use AliasOp::*;
    use il::Op;
    Some(match alias {
        MR | LI | MTLR | MFLR | MTCTR | MFCTR | MTXER | MFXER | MTCR => Op::Move,
        LIS => Op::Address,
        SUBI | SUBIS => Op::Subtract,
        NOT => Op::Not,
        NOP => Op::System,
        SLWI | SLDI => Op::ShiftLeft,
        SRWI | SRDI => Op::ShiftRight,
        ROTLWI | ROTLW => Op::Rotate,
        CLRLWI | CLRRWI | CLRLDI | CLRRDI => Op::And,
        EXTLWI | INSLWI => Op::BitField,
        _ => return None,
    })
}

/// What an instruction that is no alias computes.
fn plain_op(opcode: Opcode) -> il::Op {
    use Opcode::*;
    use il::Op;
    match opcode {
        ADD | ADDC | ADDE | ADDI | ADDIC | ADDIS | ADDZE | ADDME => Op::Add,
        SUBF | SUBFC | SUBFE | SUBFIC | SUBFZE | SUBFME => Op::Subtract,
        NEG => Op::Negate,
        MULLW | MULLI | MULHW | MULHWU | MULLD | MULHD | MULHDU | MUL => Op::Multiply,
        DIVW | DIVWU | DIVD | DIVDU | DIV | DIVS => Op::Divide,
        AND | ANDI | ANDIS => Op::And,
        ANDC => Op::AndNot,
        OR | ORI | ORIS => Op::Or,
        ORC => Op::OrNot,
        XOR | XORI | XORIS => Op::Xor,
        SLW | SLD => Op::ShiftLeft,
        SRW | SRD => Op::ShiftRight,
        SRAW | SRAWI | SRAD | SRADI => Op::ShiftRightArithmetic,
        RLWNM | RLDCL | RLDCR => Op::Rotate,
        RLWINM | RLWIMI | RLDIC | RLDICL | RLDICR | RLDIMI | RLMI => Op::BitField,
        EXTSB | EXTSH | EXTSW => Op::Extend,
        CNTLZW | CNTLZD => Op::Bits,
        ISEL | FSEL => Op::Select,
        CMP | CMPI | CMPL | CMPLI => Op::Compare,
        MFSPR | MTSPR | MFCR | MFOCRF | MTCRF | MTOCRF | MCRF | MCRXR | MFTB => Op::Move,
        FMR => Op::Move,
        FADD | FADDS => Op::FloatAdd,
        FSUB | FSUBS => Op::FloatSubtract,
        FMUL | FMULS => Op::FloatMultiply,
        FDIV | FDIVS => Op::FloatDivide,
        FMADD | FMADDS | FMSUB | FMSUBS | FNMADD | FNMADDS | FNMSUB | FNMSUBS => {
            Op::FloatMultiplyAdd
        }
        FNEG | FABS | FNABS | FCPSGN => Op::FloatSign,
        FSQRT | FSQRTS => Op::FloatSquareRoot,
        FRSP | FCFID | FCFIDU | FCFIDS | FCFIDUS | FCTIW | FCTID | FCTIWU | FCTIDU => {
            Op::FloatConvert
        }
        FCTIWZ | FCTIDZ | FCTIWUZ | FCTIDUZ | FRIZ => Op::FloatRoundTowardZero,
        FRIM => Op::FloatRoundDown,
        FRIP => Op::FloatRoundUp,
        FRIN => Op::FloatRoundNearest,
        FCMPU | FCMPO | FRE | FRES | FRSQRTE | FRSQRTES | MFFS | MTFSF | MTFSFI | MTFSB0
        | MTFSB1 | MCRFS | FTDIV | FTSQRT | DADD | DADDQ | DSUB | DSUBQ | DMUL | DMULQ | DDIV
        | DDIVQ | DCMPO | DCMPU | DCMPOQ | DCMPUQ => Op::Float,
        TW | TWI | TD | TDI | SC | SYNC | ISYNC | EIEIO | MBAR | TLBSYNC | DCBA | DCBF | DCBI
        | DCBST | DCBT | DCBT_AS | DCBTST | DCBTLS | DCBZ | DCBZ_L | DCBZ128 | ICBI | TLBIA
        | TLBIE | TLBI | TLBWE | TLBSX | TLBIVAX | TLBRE | MTMSR | MTMSRD | MTMSRD_Xenon
        | MFMSR | WRTEE | WRTEEI | MTSR | MTSRIN | MTSRD | MTSRDIN | MFSR | MFSRIN | MFSRI => {
            Op::System
        }
        opcode if is_vector(opcode) => Op::Vector,
        _ => Op::Other,
    }
}

/// Whether `opcode` is AltiVec, VMX128 or paired-single work.
fn is_vector(opcode: Opcode) -> bool {
    let name = opcode.name();
    name.starts_with('v') || name.starts_with("ps_") || name.starts_with("lvs")
}

/// The operands the IL lifts for `inst`: those its alias prints, as
/// `li r3, 5` prints two, and the target of a branch.
///
/// A move to or from a special-purpose register keeps the register the
/// alias leaves out, as `mtlr r0` leaves out `lr`, since it is what the
/// move writes or reads.
fn lifted_operands(inst: &Instruction, alias: &yaxpeax_power::InstructionAlias) -> Operands {
    match inst.opcode() {
        opcode if opcode.is_branch() => operands(inst)
            .into_iter()
            .filter(|operand| {
                matches!(
                    operand,
                    Operand::BranchOffset16(_) | Operand::BranchOffset(_) | Operand::BranchAbs(_)
                )
            })
            .collect(),
        Opcode::MTSPR | Opcode::MFSPR | Opcode::MTCRF | Opcode::MTOCRF | Opcode::MFOCRF => {
            operands(inst)
        }
        _ => (0..alias.operand_count())
            .filter_map(|index| alias.operand(index as u8).copied())
            .collect(),
    }
}

/// The operands of one instruction, held without a heap allocation.
type Operands = SmallVec<[Operand; 5]>;

/// The IL register of general register `number`: `r1` is the stack.
fn general(number: u8) -> il::Reg {
    match number {
        STACK => il::Reg::Stack,
        number => il::Reg::General(number),
    }
}

/// The IL register a special-purpose register is, where the IL names it.
fn special(number: u16) -> Option<il::Reg> {
    match number {
        SPR_LR => Some(LINK),
        SPR_CTR => Some(COUNT),
        SPR_XER => Some(CARRY),
        _ => None,
    }
}

/// The base of an access, which `r0` gives as no register: the address is
/// the offset alone.
fn base_of(base: yaxpeax_power::Register) -> Option<il::Reg> {
    (base.num() != 0).then(|| general(base.num()))
}

/// `operand` as the IL names it. A memory operand writes its address back
/// as `update` says.
fn il_operand(operand: Operand, update: il::Update) -> il::Operand {
    match operand {
        Operand::Register(reg) => il::Operand::Reg(general(reg.num())),
        Operand::RegisterOrZero(reg) if reg.num() == 0 => il::Operand::Zero,
        Operand::RegisterOrZero(reg) => il::Operand::Reg(general(reg.num())),
        Operand::MemoryDisp { base, disp } => il::Operand::Memory {
            base: base_of(base),
            offset: Some(disp.into()),
            index: None,
            update,
        },
        Operand::MemoryIndexed { base, index } => il::Operand::Memory {
            base: base_of(base),
            offset: None,
            index: Some((general(index.num()), 0)),
            update,
        },
        Operand::FPR(reg) => il::Operand::Reg(il::Reg::Vector(reg.num())),
        Operand::VR(reg) => il::Operand::Reg(il::Reg::Vector(reg.num())),
        Operand::VR128(reg) => il::Operand::Reg(il::Reg::Vector(reg.num() % 32)),
        Operand::SPR(spr) => special(spr.num()).map_or(il::Operand::Other, il::Operand::Reg),
        Operand::ImmExts16(value) => il::Operand::Const(i64::from(value) as u64),
        Operand::ImmU16(value) => il::Operand::Const(value.into()),
        Operand::ImmU32(value) => il::Operand::Const(value.into()),
        Operand::Imm8(value) => il::Operand::Const(value.into()),
        Operand::BranchOffset16(distance) => il::Operand::Target(Some(distance.into())),
        Operand::BranchOffset(distance) => il::Operand::Target(Some(distance.into())),
        Operand::BranchAbs(_) => il::Operand::Target(None),
        _ => il::Operand::Other,
    }
}

/// The name of a general register, as `r3`.
fn general_name(number: u8) -> CompactString {
    format_compact!("r{number}")
}

/// The name of the base of an access, where `r0` reads as 0.
fn base_name(base: yaxpeax_power::Register) -> CompactString {
    match base.num() {
        0 => "0".into(),
        number => general_name(number),
    }
}

/// The name of `operand`, as a reader of PowerPC code spells it.
fn operand_name(operand: Operand) -> CompactString {
    match operand {
        Operand::Register(reg) => general_name(reg.num()),
        Operand::RegisterOrZero(reg) => base_name(reg),
        Operand::MemoryDisp { base, disp } => {
            il::memory_name(&base_name(base), None, Some(disp.into()))
        }
        Operand::MemoryIndexed { base, index } => {
            il::memory_name(&base_name(base), Some(&general_name(index.num())), None)
        }
        Operand::FPR(reg) => format_compact!("f{}", reg.num()),
        Operand::VR(reg) => format_compact!("v{}", reg.num()),
        Operand::VR128(reg) => format_compact!("v{}", reg.num()),
        Operand::SPR(spr) => match spr.num() {
            SPR_LR => "lr".into(),
            SPR_CTR => "ctr".into(),
            SPR_XER => "xer".into(),
            number => format_compact!("spr{number}"),
        },
        Operand::ImmExts16(value) => il::constant_name(i64::from(value) as u64),
        Operand::ImmU16(value) => il::constant_name(value.into()),
        Operand::ImmU32(value) => il::constant_name(value.into()),
        Operand::Imm8(value) => il::constant_name(value.into()),
        Operand::BranchOffset16(distance) => il::target_name(distance.into()),
        Operand::BranchOffset(distance) => il::target_name(distance.into()),
        Operand::BranchAbs(target) => format_compact!("{:#x}", target as u32),
        Operand::CrField(field) => format_compact!("cr{field}"),
        Operand::CrBit(bit) => format_compact!("cr{}.{}", bit / 4, bit_name(bit, BitValue::Set)),
        Operand::CrMask(mask) => format_compact!("{mask:#x}"),
        Operand::FpscrField(field) => format_compact!("{field}"),
        Operand::GQR(reg) => format_compact!("qr{}", reg.num()),
        _ => "?".into(),
    }
}

/// The name of each operand that [`lift`] gives `inst`, in its order.
pub fn names(inst: &Instruction) -> il::Names {
    lifted_operands(inst, &inst.compute_alias()).into_iter().map(operand_name).collect()
}

/// The registers `operand` holds a value in: a register, or none.
fn value_register(operand: Operand) -> Option<il::Reg> {
    match il_operand(operand, il::Update::None) {
        il::Operand::Reg(reg) => Some(reg),
        _ => None,
    }
}

/// The registers an access through `operand` reads to form its address.
fn address_registers(operand: Operand) -> il::RegSet {
    match il_operand(operand, il::Update::None) {
        il::Operand::Memory { base, index, .. } => {
            base.into_iter().chain(index.map(|(index, _)| index)).collect()
        }
        _ => il::RegSet::EMPTY,
    }
}

/// The general registers from `first` to `r31`, as `lmw` and `stmw` move.
fn to_last(first: Option<il::Reg>) -> il::RegSet {
    let first = match first {
        Some(il::Reg::General(number)) => number,
        Some(il::Reg::Stack) => STACK,
        _ => return il::RegSet::EMPTY,
    };
    (first..32).map(general).collect()
}

/// The registers `inst` reads and writes beyond its operands: the flags,
/// the carry, the link and the count. `test` is its branch test.
fn implied_registers(inst: &Instruction, test: BranchTest) -> (il::RegSet, il::RegSet) {
    use Opcode::*;
    let (mut reads, mut writes) = (il::RegSet::EMPTY, il::RegSet::EMPTY);
    let opcode = inst.opcode();
    if inst.rc() || matches!(opcode, ANDI | ANDIS) {
        writes.insert(il::Reg::Flags);
    }
    match opcode {
        ADDC | ADDIC | SUBFC | SUBFIC | SRAW | SRAWI | SRAD | SRADI => writes.insert(CARRY),
        ADDE | ADDZE | ADDME | SUBFE | SUBFZE | SUBFME => {
            reads.insert(CARRY);
            writes.insert(CARRY);
        }
        _ => {}
    }
    if inst.oe() {
        writes.insert(CARRY);
    }
    match opcode {
        CMP | CMPI | CMPL | CMPLI | FCMPU | FCMPO | MTCRF | MTOCRF | MCRFS => {
            writes.insert(il::Reg::Flags);
        }
        MCRXR => {
            reads.insert(CARRY);
            writes.insert(il::Reg::Flags);
        }
        MFCR | MFOCRF | ISEL => reads.insert(il::Reg::Flags),
        MCRF | CRAND | CRANDC | CREQV | CRNAND | CRNOR | CROR | CRORC | CRXOR => {
            reads.insert(il::Reg::Flags);
            writes.insert(il::Reg::Flags);
        }
        _ => {}
    }
    if opcode.is_branch() {
        match test {
            BranchTest::Always => {}
            BranchTest::Bit { .. } => reads.insert(il::Reg::Flags),
            BranchTest::Count { bit, .. } => {
                reads.insert(COUNT);
                writes.insert(COUNT);
                if bit.is_some() {
                    reads.insert(il::Reg::Flags);
                }
            }
        }
        match opcode {
            BCLR => reads.insert(LINK),
            BCCTR => reads.insert(COUNT),
            _ => {}
        }
        if inst.lk() {
            writes.insert(LINK);
        }
    }
    (reads, writes)
}

/// What a compare puts in the flags, and in which width.
fn test_of(inst: &Instruction, operands: &[il::Operand], test: BranchTest) -> Option<il::Test> {
    let opcode = inst.opcode();
    match opcode {
        Opcode::CMP | Opcode::CMPI | Opcode::CMPL | Opcode::CMPLI => {
            // The L bit, the second operand of the hardware, compares
            // doublewords.
            let width = match inst.operand(1) {
                Some(Operand::Imm8(1)) => il::Width::Bits64,
                _ => WIDTH,
            };
            let value = |operand: &il::Operand| match *operand {
                il::Operand::Reg(reg) => il::Value::Reg(reg),
                il::Operand::Zero => il::Value::Const(0),
                il::Operand::Const(value) => il::Value::Const(value & width.mask()),
                _ => il::Value::Other,
            };
            let [.., left, right] = operands else { return None };
            let (left, right) = (value(left), value(right));
            let comparison = match opcode {
                Opcode::CMPL | Opcode::CMPLI => il::Comparison::Unsigned { left, right },
                _ => il::Comparison::Subtract { left, right },
            };
            Some(il::Test::Compare { comparison, width })
        }
        // A call on a condition tests nothing a guard reads.
        opcode if opcode.is_branch() && !inst.lk() => test.cond().map(il::Test::OnFlags),
        _ => None,
    }
}

/// Lift `inst`, read from `word`.
pub fn lift(inst: &Instruction, word: u32) -> il::Lifted {
    let alias = inst.compute_alias();
    let opcode = inst.opcode();
    let test = BranchTest::of(word);
    let role = role_of(opcode, alias.opcode());
    let update = if updates(opcode) { il::Update::Before } else { il::Update::None };
    let shown = lifted_operands(inst, &alias);

    let (mut reads, mut writes) = implied_registers(inst, test);
    for (index, operand) in shown.iter().copied().enumerate() {
        reads = union(reads, address_registers(operand));
        if update == il::Update::Before
            && let Some(base) = memory_base(il_operand(operand, update))
        {
            writes.insert(base);
        }
        let Some(reg) = value_register(operand) else { continue };
        match (role, index) {
            (Role::Compute, 0) => writes.insert(reg),
            (Role::Insert, 0) => {
                reads.insert(reg);
                writes.insert(reg);
            }
            (Role::Load(Registers::One), 0) => writes.insert(reg),
            (Role::Load(Registers::ToLast), 0) => writes = union(writes, to_last(Some(reg))),
            (Role::Store(Registers::ToLast), 0) => reads = union(reads, to_last(Some(reg))),
            _ => reads.insert(reg),
        }
    }

    let memory = access_of(opcode).map(|(kind, width)| il::MemoryAccess { kind, width });
    let operands: il::Operands = shown.iter().map(|&operand| il_operand(operand, update)).collect();
    il::Lifted {
        op: op_of(inst, alias.opcode(), test),
        reads,
        writes,
        memory,
        test: test_of(inst, &operands, test),
        operands,
    }
}

/// Every register in either set.
fn union(left: il::RegSet, right: il::RegSet) -> il::RegSet {
    left.iter().chain(right.iter()).collect()
}

/// The base register of a memory operand.
fn memory_base(operand: il::Operand) -> Option<il::Reg> {
    match operand {
        il::Operand::Memory { base, .. } => base,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccessKind, Comparison, Cond, Op, Reg, RegSet, Test, Update, Value, Width};
    use rstest::rstest;

    fn decode_one(word: u32) -> Insn {
        PowerPc::BIG.decode(&word.to_be_bytes(), 0, 0x1000).expect("4 bytes always decode")
    }

    fn lift_one(word: u32) -> il::Lifted {
        PowerPc::BIG.lift(&decode_one(word)).expect("the word must lift")
    }

    fn regs(regs: &[Reg]) -> RegSet {
        regs.iter().copied().collect()
    }

    fn r(number: u8) -> Reg {
        Reg::General(number)
    }

    #[rstest]
    #[case::mflr(0x7c08_02a6, "mflr r0")]
    #[case::stwu(0x9421_fff0, "stwu r1, -0x10(r1)")]
    #[case::li(0x3860_0005, "li r3, 5")]
    #[case::mr(0x7c83_2378, "mr r3, r4")]
    #[case::beq(0x4182_0010, "beq $+0x10")]
    #[case::bdnz_back(0x4200_fff0, "bdnz $-0x10")]
    #[case::bl_back(0x4bff_fff1, "bl $-0x10")]
    #[case::bcl_next(0x429f_0005, "bcl 20, 31, $+0x4")]
    #[case::blr(0x4e80_0020, "blr")]
    #[case::unread(0x0000_0000, "(unknown) 0x00000000")]
    fn prints_as_a_reader_expects(#[case] word: u32, #[case] text: &str) {
        let (_, printed) =
            PowerPc::BIG.read(&word.to_be_bytes(), 0, 0x1000, Printing::Text).expect("must read");
        assert_eq!(printed, text);
    }

    #[rstest]
    #[case::b(0x4800_0010, InsnKind::Jump { target: Some(0x1010) })]
    #[case::bl(0x4800_0011, InsnKind::Call { target: Some(0x1010) })]
    #[case::ba(0x4800_0012, InsnKind::Jump { target: Some(0x10) })]
    #[case::beq(0x4182_0010, InsnKind::Branch { target: Some(0x1010) })]
    #[case::bdnz(0x4200_fff0, InsnKind::Branch { target: Some(0x0ff0) })]
    #[case::bc_always(0x4280_0010, InsnKind::Jump { target: Some(0x1010) })]
    #[case::bcl_next(0x429f_0005, InsnKind::Normal)]
    #[case::bcl_far(0x429f_0011, InsnKind::Call { target: Some(0x1010) })]
    #[case::beql(0x4182_0011, InsnKind::Call { target: None })]
    #[case::blr(0x4e80_0020, InsnKind::Return)]
    #[case::beqlr(0x4d82_0020, InsnKind::Branch { target: None })]
    #[case::blrl(0x4e80_0021, InsnKind::Call { target: None })]
    #[case::bctr(0x4e80_0420, InsnKind::Jump { target: None })]
    #[case::bctrl(0x4e80_0421, InsnKind::Call { target: None })]
    #[case::rfi(0x4c00_0064, InsnKind::Return)]
    #[case::trap(0x7fe0_0008, InsnKind::Jump { target: None })]
    #[case::twi_on_condition(0x0c03_0000, InsnKind::Normal)]
    #[case::add(0x7c64_1a14, InsnKind::Normal)]
    #[case::unread(0x0000_0000, InsnKind::Unknown)]
    fn control_moves_as_the_instruction_says(#[case] word: u32, #[case] kind: InsnKind) {
        assert_eq!(decode_one(word).kind, kind);
    }

    #[rstest]
    #[case::beq(0x4182_0010, "beq")]
    #[case::bne_cr7(0x409e_0010, "bne")]
    #[case::bge(0x4080_0028, "bge")]
    #[case::bdnz(0x4200_fff0, "bdnz")]
    #[case::b(0x4800_0010, "b")]
    #[case::ba(0x4800_0012, "b")]
    #[case::bl(0x4800_0011, "bl")]
    #[case::blr(0x4e80_0020, "blr")]
    #[case::beqlr(0x4d82_0020, "beqlr")]
    #[case::bctrl(0x4e80_0421, "bctrl")]
    #[case::li(0x3860_0005, "li")]
    #[case::addi(0x3863_0005, "addi")]
    #[case::mr(0x7c83_2378, "mr")]
    #[case::or(0x7c83_2b78, "or")]
    #[case::add_record(0x7c64_1a15, "add")]
    #[case::srwi(0x5484_f0be, "srwi")]
    #[case::mtlr(0x7c08_03a6, "mtlr")]
    #[case::unread(0x0000_0000, "(unknown)")]
    fn names_the_operation(#[case] word: u32, #[case] name: &str) {
        assert_eq!(PowerPc::BIG.operation_name(&decode_one(word)), name);
    }

    #[test]
    fn a_compare_and_the_branch_after_it_are_one_guard() {
        // cmpwi cr7, r4, 4 ; blt cr7, $+0x10
        let body = [Some(lift_one(0x2f84_0004)), Some(lift_one(0x419c_0010))];
        let guards = il::find_guards(&body);
        assert_eq!(guards.len(), 1);
        let guard = guards[0].guard;
        assert_eq!(guard.cond, Cond::SignedLess);
        assert_eq!((guard.left, guard.right), (Value::Reg(r(4)), Value::Const(4)));
        assert_eq!(guard.width, Width::Bits32);
    }

    #[test]
    fn a_compare_without_sign_makes_an_unsigned_guard() {
        // cmplwi r4, 1 ; bgt $+0x10
        let body = [Some(lift_one(0x2804_0001)), Some(lift_one(0x4181_0010))];
        let guards = il::find_guards(&body);
        assert_eq!(guards.len(), 1);
        assert_eq!(guards[0].guard.cond, Cond::UnsignedGreater);
    }

    #[test]
    fn a_compare_writes_the_flags_and_names_both_sides() {
        let compare = lift_one(0x7c04_1800); // cmpw r4, r3
        assert_eq!(compare.op, Op::Compare);
        assert_eq!(compare.writes, regs(&[Reg::Flags]));
        assert_eq!(compare.reads, regs(&[r(3), r(4)]));
        let Some(Test::Compare { comparison, width }) = compare.test else {
            panic!("a compare must test");
        };
        assert_eq!(width, Width::Bits32);
        assert_eq!(
            comparison,
            Comparison::Subtract { left: Value::Reg(r(4)), right: Value::Reg(r(3)) }
        );
    }

    #[test]
    fn a_negative_bound_is_in_twos_complement_of_the_width() {
        let compare = lift_one(0x2c04_ffff); // cmpwi r4, -1
        let Some(Test::Compare { comparison: Comparison::Subtract { right, .. }, .. }) =
            compare.test
        else {
            panic!("a compare must test");
        };
        assert_eq!(right, Value::Const(0xffff_ffff));
    }

    #[test]
    fn a_store_with_update_writes_its_base() {
        let store = lift_one(0x9421_fff0); // stwu r1, -0x10(r1)
        assert_eq!(store.op, Op::Store);
        assert_eq!(
            store.memory,
            Some(il::MemoryAccess { kind: AccessKind::Store, width: Some(Width::Bits32) })
        );
        assert_eq!(store.reads, regs(&[Reg::Stack]));
        assert_eq!(store.writes, regs(&[Reg::Stack]));
        assert_eq!(
            store.operands[1],
            il::Operand::Memory {
                base: Some(Reg::Stack),
                offset: Some(-0x10),
                index: None,
                update: Update::Before
            }
        );
    }

    #[rstest]
    #[case::lbz(0x8864_0000, Width::Bits8, Reg::General(3))]
    #[case::lhz(0xa064_0000, Width::Bits16, Reg::General(3))]
    #[case::lwz(0x8064_0000, Width::Bits32, Reg::General(3))]
    #[case::lwzx(0x7c64_282e, Width::Bits32, Reg::General(3))]
    #[case::lfd(0xc803_0000, Width::Bits64, Reg::Vector(0))]
    fn a_load_writes_its_register_in_its_width(
        #[case] word: u32,
        #[case] width: Width,
        #[case] loaded: Reg,
    ) {
        let load = lift_one(word);
        assert_eq!(load.op, Op::Load);
        assert_eq!(
            load.memory,
            Some(il::MemoryAccess { kind: AccessKind::Load, width: Some(width) })
        );
        assert_eq!(load.writes, regs(&[loaded]));
    }

    #[test]
    fn a_load_through_r0_has_no_base() {
        let load = lift_one(0x8060_0010); // lwz r3, 0x10(0)
        assert_eq!(load.operands[1], il::Operand::memory(None, Some(0x10)));
        assert!(load.reads.is_empty());
    }

    #[test]
    fn a_load_of_many_writes_each_register_to_the_last() {
        let load = lift_one(0xbb61_000c); // lmw r27, 0xc(r1)
        assert_eq!(load.writes, regs(&[r(27), r(28), r(29), r(30), r(31)]));
        let store = lift_one(0xbf61_000c); // stmw r27, 0xc(r1)
        assert_eq!(store.reads, regs(&[r(27), r(28), r(29), r(30), r(31), Reg::Stack]));
    }

    #[test]
    fn calls_and_returns_use_the_link_register() {
        assert!(lift_one(0x4800_0011).writes.contains(LINK)); // bl
        assert!(lift_one(0x4e80_0020).reads.contains(LINK)); // blr
        assert_eq!(lift_one(0x4e80_0020).op, Op::Return);
        let call = lift_one(0x4e80_0421); // bctrl
        assert_eq!(call.op, Op::Call);
        assert!(call.reads.contains(COUNT));
        assert!(call.writes.contains(LINK));
    }

    #[test]
    fn a_move_of_the_link_register_names_it() {
        let save = lift_one(0x7c08_02a6); // mflr r0
        assert_eq!(save.op, Op::Move);
        assert_eq!((save.reads, save.writes), (regs(&[LINK]), regs(&[r(0)])));
        let restore = lift_one(0x7c08_03a6); // mtlr r0
        assert_eq!((restore.reads, restore.writes), (regs(&[r(0)]), regs(&[LINK])));
    }

    #[test]
    fn the_pc_read_of_pic_code_forms_an_address() {
        let read = lift_one(0x429f_0005); // bcl 20, 31, $+4
        assert_eq!(read.op, Op::Address);
        assert_eq!(read.writes, regs(&[LINK]));
    }

    #[test]
    fn a_count_loop_reads_and_writes_the_count() {
        let branch = lift_one(0x4200_fff0); // bdnz
        assert_eq!(branch.op, Op::Branch);
        assert_eq!((branch.reads, branch.writes), (regs(&[COUNT]), regs(&[COUNT])));
        assert_eq!(branch.test, None);
    }

    #[rstest]
    #[case::li(0x3860_0005, Op::Move)]
    #[case::lis(0x3c60_0001, Op::Address)]
    #[case::mr(0x7c83_2378, Op::Move)]
    #[case::nop(0x6000_0000, Op::System)]
    #[case::not(0x7c63_18f8, Op::Not)]
    #[case::subi(0x3863_ffff, Op::Subtract)]
    #[case::subf(0x7c63_2050, Op::Subtract)]
    #[case::neg(0x7c64_00d0, Op::Negate)]
    #[case::srwi(0x5484_f0be, Op::ShiftRight)]
    #[case::slwi(0x5484_103a, Op::ShiftLeft)]
    #[case::clrlwi(0x5484_063e, Op::And)]
    #[case::rlwimi(0x5083_402e, Op::BitField)]
    #[case::srawi(0x7c64_1670, Op::ShiftRightArithmetic)]
    #[case::divw(0x7c64_03d6, Op::Divide)]
    #[case::extsw(0x7c64_07b4, Op::Extend)]
    #[case::isel(0x7c64_289e, Op::Select)]
    #[case::fadd(0xfc21_102a, Op::FloatAdd)]
    #[case::fmadd(0xfc21_10ba, Op::FloatMultiplyAdd)]
    #[case::fmr(0xfc00_0890, Op::Move)]
    #[case::lwarx(0x7c60_1828, Op::Atomic)]
    #[case::stwcx(0x7c60_192d, Op::Atomic)]
    #[case::sync(0x7c00_04ac, Op::System)]
    #[case::vaddubm(0x1000_0000, Op::Vector)]
    fn an_operation_is_named_as_on_every_architecture(#[case] word: u32, #[case] op: Op) {
        assert_eq!(lift_one(word).op, op);
    }

    #[test]
    fn an_insert_reads_its_destination() {
        let insert = lift_one(0x5083_402e); // rlwimi r3, r4, 8, 0, 0x17
        assert_eq!(insert.reads, regs(&[r(3), r(4)]));
        assert_eq!(insert.writes, regs(&[r(3)]));
    }

    #[test]
    fn a_carry_flows_through_the_exception_register() {
        let first = lift_one(0x7c64_1814); // addc r3, r4, r3
        assert!(first.writes.contains(CARRY));
        let second = lift_one(0x7c64_1914); // adde r3, r4, r3
        assert!(second.reads.contains(CARRY));
    }

    #[test]
    fn a_record_form_writes_the_flags_and_tests_nothing() {
        let record = lift_one(0x7c64_1a15); // add. r3, r4, r3
        assert!(record.writes.contains(Reg::Flags));
        assert_eq!(record.test, None);
    }

    #[test]
    fn li_reads_no_register_and_its_canonical_form_is_a_move() {
        let li = lift_one(0x3860_0005);
        assert!(li.reads.is_empty());
        assert_eq!(li.operands.as_slice(), [il::Operand::Reg(r(3)), il::Operand::Const(5)]);
    }

    #[rstest]
    #[case::bit_set(0x4182_0010, BranchTest::Bit { bit: 2, when: BitValue::Set })]
    #[case::bit_clear(0x409e_0010, BranchTest::Bit { bit: 30, when: BitValue::Clear })]
    #[case::always(0x4e80_0020, BranchTest::Always)]
    #[case::bdnz(0x4200_fff0, BranchTest::Count { until: CountTest::NotZero, bit: None })]
    #[case::bdz(0x4240_fff0, BranchTest::Count { until: CountTest::Zero, bit: None })]
    #[case::bdnzt(0x4102_fff0, BranchTest::Count { until: CountTest::NotZero, bit: Some((2, BitValue::Set)) })]
    fn reads_the_test_of_a_branch(#[case] word: u32, #[case] test: BranchTest) {
        assert_eq!(BranchTest::of(word), test);
    }

    #[rstest]
    #[case(0, BitValue::Set, Cond::SignedLess)]
    #[case(0, BitValue::Clear, Cond::SignedGreaterOrEqual)]
    #[case(5, BitValue::Set, Cond::SignedGreater)]
    #[case(5, BitValue::Clear, Cond::SignedLessOrEqual)]
    #[case(30, BitValue::Set, Cond::Equal)]
    #[case(30, BitValue::Clear, Cond::NotEqual)]
    #[case(3, BitValue::Set, Cond::Overflow)]
    fn a_bit_of_a_field_is_its_condition(
        #[case] bit: u8,
        #[case] when: BitValue,
        #[case] cond: Cond,
    ) {
        assert_eq!(bit_cond(bit, when), cond);
    }

    #[test]
    fn the_names_name_each_operand_in_order() {
        let named = PowerPc::BIG.lift_named(&decode_one(0x9421_fff0)).expect("must lift");
        assert_eq!(named.names.as_slice(), ["r1", "[r1 - 0x10]"]);
        let named = PowerPc::BIG.lift_named(&decode_one(0x7c64_282e)).expect("must lift");
        assert_eq!(named.names.as_slice(), ["r3", "[r4 + r5]"]);
        let named = PowerPc::BIG.lift_named(&decode_one(0x7c08_03a6)).expect("must lift");
        assert_eq!(named.names.as_slice(), ["lr", "r0"]);
    }

    #[test]
    fn a_truncated_word_does_not_decode() {
        assert_eq!(PowerPc::BIG.decode(&[0x38, 0x60, 0x00], 0, 0), Err(DecodeError::Truncated));
        assert_eq!(
            PowerPc::BIG.decode(&[0x38, 0x60, 0x00, 0x05], 4, 0),
            Err(DecodeError::Truncated)
        );
    }

    #[test]
    fn a_pointer_is_a_word_or_a_doubleword_in_the_byte_order() {
        let bytes = [0x10, 0x00, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70];
        assert_eq!(PowerPc::BIG.read_pointer(&bytes), 0x1000_2030);
        assert_eq!(PowerPc::LITTLE.read_pointer(&bytes), 0x3020_0010);
        assert_eq!(PowerPc::BIG64.read_pointer(&bytes), 0x1000_2030_4050_6070);
        assert_eq!(PowerPc::LITTLE64.read_pointer(&bytes), 0x7060_5040_3020_0010);
        assert_eq!(PowerPc::BIG.pointer_width(), 4);
        assert_eq!(PowerPc::LITTLE64.pointer_width(), 8);
    }

    #[rstest]
    #[case(PowerPc::BIG, "powerpc")]
    #[case(PowerPc::LITTLE, "powerpcle")]
    #[case(PowerPc::BIG64, "powerpc64")]
    #[case(PowerPc::LITTLE64, "powerpc64le")]
    fn each_decoder_names_its_triple(#[case] decoder: PowerPc, #[case] triple: &str) {
        assert_eq!(decoder.triple(), triple);
        assert_eq!(PowerPc::of(decoder.order(), decoder.mode()), &decoder);
    }

    /// One instruction reads the same in either byte order, from bytes in
    /// that order, and lifts the same.
    #[test]
    fn little_endian_reads_the_word_from_its_bytes_reversed() {
        bolero::check!().with_type::<u32>().for_each(|&word| {
            let big = PowerPc::BIG.decode(&word.to_be_bytes(), 0, 0x1000).expect("decodes");
            let little = PowerPc::LITTLE.decode(&word.to_le_bytes(), 0, 0x1000).expect("decodes");
            assert_eq!(big.to_string(), little.to_string(), "{word:#010x}");
            assert_eq!(big.kind, little.kind);
            assert_eq!(PowerPc::BIG.lift(&big), PowerPc::LITTLE.lift(&little));
            assert_eq!(word_of(&little), Some(word));
        });
    }

    #[test]
    fn a_64_bit_absolute_target_extends_its_sign() {
        let word: u32 = 0x4bff_fff2; // ba -0x10
        let insn = PowerPc::BIG64.decode(&word.to_be_bytes(), 0, 0x1000).expect("decodes");
        assert_eq!(insn.kind, InsnKind::Jump { target: Some(0xffff_ffff_ffff_fff0) });
        let insn = PowerPc::BIG.decode(&word.to_be_bytes(), 0, 0x1000).expect("decodes");
        assert_eq!(insn.kind, InsnKind::Jump { target: Some(0xffff_fff0) });
    }

    #[rstest]
    #[case::stdu(0xf821_ffd1, Op::Store, Some(Width::Bits64))]
    #[case::ld(0xe862_8000, Op::Load, Some(Width::Bits64))]
    #[case::lwax(0x7d49_52aa, Op::Load, Some(Width::Bits32))]
    fn a_64_bit_access_names_its_width(
        #[case] word: u32,
        #[case] op: Op,
        #[case] width: Option<Width>,
    ) {
        let insn = PowerPc::BIG64.decode(&word.to_be_bytes(), 0, 0x1000).expect("decodes");
        let lifted = PowerPc::BIG64.lift(&insn).expect("lifts");
        assert_eq!((lifted.op, lifted.memory.and_then(|access| access.width)), (op, width));
    }

    /// Every word decodes to one instruction of 4 bytes, and lifts with a
    /// name for each operand, whatever its bits.
    #[test]
    fn any_word_decodes_and_lifts() {
        bolero::check!().with_type::<u32>().for_each(|&word| {
            let insn = decode_one(word);
            assert_eq!(insn.bytes_len, INSN_WIDTH);
            let _ = PowerPc::BIG.operation_name(&insn);
            let _ = insn.to_string();
            if let Some(named) = PowerPc::BIG.lift_named(&insn) {
                assert_eq!(named.names.len(), named.lifted.operands.len());
                assert_eq!(Some(named.lifted), PowerPc::BIG.lift(&insn));
            }
        });
    }
}
