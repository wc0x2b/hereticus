//! The MIPS32 and MIPS32 Release 2 instructions that `rabbitizer` refuses.
//!
//! `rabbitizer` reads the MIPS I to IV instruction sets, which is what old
//! game consoles use. Routers and set-top boxes run MIPS32, most of them
//! Release 2, which adds instructions in encodings MIPS II leaves reserved.
//! Measured on two OpenWrt kernels, about 25,000 words of real code in each
//! were unreadable for that reason alone.
//!
//! This module reads only those words, and only when `rabbitizer` has already
//! refused them, so nothing it reads changes. The text follows `rabbitizer`:
//! ABI register names, decimal shift and field widths.
//!
//! # The DSP ASE
//!
//! The DSP extension adds three accumulators, `ac1` to `ac3`, beside `hi` and
//! `lo`, which it calls `ac0`. A kernel built for a DSP core saves and
//! restores them on each task switch, so every such kernel holds a few dozen
//! words that name one. Only the words found in real firmware are read here:
//! measured on four OpenWrt MIPS kernels, the accumulator moves, the
//! accumulator multiplies, and `rddsp` and `wrdsp`. The packed arithmetic of
//! the extension, and `extr`, did not occur.

/// ABI names of the general registers, as `rabbitizer` prints them.
pub const REGISTERS: [&str; 32] = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
    "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "s8",
    "ra",
];

use super::InsnKind;
use crate as il;

/// The major opcodes this module reads under.
const SPECIAL: u32 = 0x00;
const REGIMM: u32 = 0x01;
const COP0: u32 = 0x10;
const COP1: u32 = 0x11;
const SPECIAL2: u32 = 0x1c;
const SPECIAL3: u32 = 0x1f;
const PREF: u32 = 0x33;

/// `rs` of the COP0 `mfmc0` group, which holds `di` and `ei`.
const MFMC0: u32 = 0x0b;

/// An operation this module reads, named as `rabbitizer` would print it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// `synci`: makes written code visible to the fetch of instructions.
    Synci,
    /// `sigrie`: traps, as a filler between functions.
    Sigrie,
    /// `pref`: fetches memory ahead of use.
    Pref,
    /// `eret`: returns from an exception.
    Eret,
    /// `deret`: returns from a debug exception.
    Deret,
    /// `jr.hb`: jumps through a register once hazards clear.
    JrHb,
    /// `jalr.hb`: calls through a register once hazards clear.
    JalrHb,
    /// `movz`: copies where a register is zero.
    Movz,
    /// `movn`: copies where a register is not zero.
    Movn,
    /// `rotr`: rotates right by a constant.
    Rotr,
    /// `rotrv`: rotates right by a register.
    Rotrv,
    /// `mfhi`: reads `hi`.
    Mfhi,
    /// `mflo`: reads `lo`.
    Mflo,
    /// `mthi`: writes `hi`.
    Mthi,
    /// `mtlo`: writes `lo`.
    Mtlo,
    /// `mult`: multiplies, signed, into `hi` and `lo`.
    Mult,
    /// `multu`: multiplies, unsigned, into `hi` and `lo`.
    Multu,
    /// `madd`: adds a signed product to `hi` and `lo`.
    Madd,
    /// `maddu`: adds an unsigned product to `hi` and `lo`.
    Maddu,
    /// `mul`: multiplies into a register.
    Mul,
    /// `msub`: subtracts a signed product from `hi` and `lo`.
    Msub,
    /// `msubu`: subtracts an unsigned product from `hi` and `lo`.
    Msubu,
    /// `clz`: counts the leading zeros.
    Clz,
    /// `clo`: counts the leading ones.
    Clo,
    /// `ext`: extracts a field of bits.
    Ext,
    /// `ins`: inserts a field of bits.
    Ins,
    /// `wsbh`: swaps the bytes of each halfword.
    Wsbh,
    /// `seb`: sign-extends a byte.
    Seb,
    /// `seh`: sign-extends a halfword.
    Seh,
    /// `rdhwr`: reads a hardware register.
    Rdhwr,
    /// `rddsp`: reads the DSP control register.
    Rddsp,
    /// `wrdsp`: writes the DSP control register.
    Wrdsp,
    /// `mfc0`: reads a register of coprocessor 0.
    Mfc0,
    /// `mtc0`: writes a register of coprocessor 0.
    Mtc0,
    /// `di`: turns interrupts off.
    Di,
    /// `ei`: turns interrupts on.
    Ei,
    /// `wait`: waits for an interrupt.
    Wait,
    /// `bc1f`, `bc1t`, `bc1fl` or `bc1tl` on a floating-point condition
    /// code other than 0, which MIPS IV added.
    FloatBranch(FloatBranch),
    /// `c.cond.fmt` into a floating-point condition code other than 0.
    FloatCompare(FloatCompare),
}

/// A branch on a floating-point condition code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloatBranch {
    /// `bc1f`: branches where the code is false.
    False,
    /// `bc1t`: branches where the code is true.
    True,
    /// `bc1fl`: as `bc1f`, and runs its delay slot only where taken.
    FalseLikely,
    /// `bc1tl`: as `bc1t`, and runs its delay slot only where taken.
    TrueLikely,
}

/// A compare of two floats into a condition code: which condition, by its
/// number in the encoding, and of which format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FloatCompare {
    /// The condition, from 0 (`f`) to 15 (`ngt`).
    pub condition: u8,
    /// The format of the floats.
    pub format: FloatFormat,
}

/// The format of a float.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloatFormat {
    /// Single precision, `.s`.
    Single,
    /// Double precision, `.d`.
    Double,
}

/// The name of each compare of single floats, by its condition.
const SINGLE_COMPARES: [&str; 16] = [
    "c.f.s", "c.un.s", "c.eq.s", "c.ueq.s", "c.olt.s", "c.ult.s", "c.ole.s", "c.ule.s", "c.sf.s",
    "c.ngle.s", "c.seq.s", "c.ngl.s", "c.lt.s", "c.nge.s", "c.le.s", "c.ngt.s",
];

/// The name of each compare of double floats, by its condition.
const DOUBLE_COMPARES: [&str; 16] = [
    "c.f.d", "c.un.d", "c.eq.d", "c.ueq.d", "c.olt.d", "c.ult.d", "c.ole.d", "c.ule.d", "c.sf.d",
    "c.ngle.d", "c.seq.d", "c.ngl.d", "c.lt.d", "c.nge.d", "c.le.d", "c.ngt.d",
];

/// The ABI names of the floating-point registers, as `rabbitizer` prints
/// them.
const FLOAT_REGISTERS: [&str; 32] = [
    "fv0", "fv0f", "fv1", "fv1f", "ft0", "ft0f", "ft1", "ft1f", "ft2", "ft2f", "ft3", "ft3f",
    "fa0", "fa0f", "fa1", "fa1f", "ft4", "ft4f", "ft5", "ft5f", "fs0", "fs0f", "fs1", "fs1f",
    "fs2", "fs2f", "fs3", "fs3f", "fs4", "fs4f", "fs5", "fs5f",
];

impl Op {
    /// The name `rabbitizer` would print it with, as `movz`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Synci => "synci",
            Self::Sigrie => "sigrie",
            Self::Pref => "pref",
            Self::Eret => "eret",
            Self::Deret => "deret",
            Self::JrHb => "jr.hb",
            Self::JalrHb => "jalr.hb",
            Self::Movz => "movz",
            Self::Movn => "movn",
            Self::Rotr => "rotr",
            Self::Rotrv => "rotrv",
            Self::Mfhi => "mfhi",
            Self::Mflo => "mflo",
            Self::Mthi => "mthi",
            Self::Mtlo => "mtlo",
            Self::Mult => "mult",
            Self::Multu => "multu",
            Self::Madd => "madd",
            Self::Maddu => "maddu",
            Self::Mul => "mul",
            Self::Msub => "msub",
            Self::Msubu => "msubu",
            Self::Clz => "clz",
            Self::Clo => "clo",
            Self::Ext => "ext",
            Self::Ins => "ins",
            Self::Wsbh => "wsbh",
            Self::Seb => "seb",
            Self::Seh => "seh",
            Self::Rdhwr => "rdhwr",
            Self::Rddsp => "rddsp",
            Self::Wrdsp => "wrdsp",
            Self::Mfc0 => "mfc0",
            Self::Mtc0 => "mtc0",
            Self::Di => "di",
            Self::Ei => "ei",
            Self::Wait => "wait",
            Self::FloatBranch(FloatBranch::False) => "bc1f",
            Self::FloatBranch(FloatBranch::True) => "bc1t",
            Self::FloatBranch(FloatBranch::FalseLikely) => "bc1fl",
            Self::FloatBranch(FloatBranch::TrueLikely) => "bc1tl",
            Self::FloatCompare(FloatCompare { condition, format }) => match format {
                FloatFormat::Single => SINGLE_COMPARES[usize::from(condition & 0xf)],
                FloatFormat::Double => DOUBLE_COMPARES[usize::from(condition & 0xf)],
            },
        }
    }

    /// The name of the operation, as `rabbitizer` names its own: a compare
    /// is `c_lt_d`, so that a compare into condition code 1 is the same
    /// operation as one into code 0, which `rabbitizer` reads.
    pub fn operation_name(self) -> compact_str::CompactString {
        self.name().replace('.', "_").into()
    }
}

/// One word this module reads.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Word {
    pub op: Op,
    pub operands: String,
    pub kind: InsnKind,
}

/// `eret` and `deret`, which return from an exception and from a debug
/// exception. Each is one fixed word.
const ERET: u32 = 0x4200_0018;
const DERET: u32 = 0x4200_001f;

/// Report whether `op` returns from an exception.
///
/// Unlike every other MIPS jump, such a return has no delay slot.
pub(crate) fn is_exception_return(op: Op) -> bool {
    matches!(op, Op::Eret | Op::Deret)
}

/// Read a MIPS32 or MIPS32r2 word.
///
/// Returns `None` for a word this module does not know, which leaves it
/// unreadable.
pub(crate) fn decode(word: u32) -> Option<Word> {
    let fields = Fields::of(word);
    if let Some(found) = control(word, &fields) {
        return Some(found);
    }

    let (op, operands) = match fields.opcode {
        SPECIAL => special(&fields),
        SPECIAL2 => special2(&fields),
        SPECIAL3 => special3(&fields),
        COP0 => cop0(&fields),
        COP1 => cop1(&fields),
        // `synci offset(base)` makes a written instruction visible. It sits
        // under REGIMM, in the `rt` MIPS II leaves reserved.
        REGIMM if fields.rt == 0x1f => {
            Some((Op::Synci, format!("{}({})", fields.offset(), fields.rs_name())))
        }
        // `sigrie code` traps. Release 6 defines it, and LLD fills the gaps
        // between functions with `sigrie 1` on every release.
        REGIMM if fields.rt == 0x17 && fields.rs == 0 => {
            Some((Op::Sigrie, format!("{:#x}", fields.immediate)))
        }
        PREF => {
            Some((Op::Pref, format!("{:#x}, {}({})", fields.rt, fields.offset(), fields.rs_name())))
        }
        _ => None,
    }?;
    // The target of a branch needs its address: see [`branch_distance`].
    let kind = match op {
        Op::FloatBranch(_) => InsnKind::Branch { target: None },
        _ => InsnKind::Normal,
    };
    Some(Word { op, operands, kind })
}

/// How far a branch this module reads goes, from the branch to its target,
/// or `None` for a word that is no such branch.
pub(crate) fn branch_distance(word: u32) -> Option<i64> {
    match decode(word)?.op {
        Op::FloatBranch(_) => Some(Fields::of(word).branch_distance()),
        _ => None,
    }
}

/// The floating-point condition code that a compare this module reads
/// writes, or that a branch it reads tests: 1 to 7. `None` for any other
/// word.
pub(crate) fn condition_code(word: u32) -> Option<u8> {
    let fields = Fields::of(word);
    match decode(word)?.op {
        Op::FloatBranch(_) => Some((fields.rt >> 2) as u8),
        Op::FloatCompare(_) => Some((fields.sa >> 2) as u8),
        _ => None,
    }
}

/// The words that move control: the exception returns, and `jr` and `jalr`
/// with the hazard barrier bit.
///
/// Release 2 marks the barrier with the top bit of the field `jr` leaves
/// zero. The jump itself is the same as without it, so it moves control the
/// same: `jr.hb ra` returns, and a kernel uses `jr.hb` through another
/// register to reach the next instruction once a hazard clears.
fn control(word: u32, fields: &Fields) -> Option<Word> {
    const JR: u32 = 0x08;
    const JALR: u32 = 0x09;
    const HAZARD_BARRIER: u32 = 0x10;
    const RA: u32 = 31;

    let (op, operands, kind) = match word {
        ERET => (Op::Eret, String::new(), InsnKind::Return),
        DERET => (Op::Deret, String::new(), InsnKind::Return),
        _ if fields.opcode != SPECIAL || fields.sa != HAZARD_BARRIER || fields.rt != 0 => {
            return None;
        }
        _ if fields.function == JR && fields.rd == 0 => {
            let kind =
                if fields.rs == RA { InsnKind::Return } else { InsnKind::Jump { target: None } };
            (Op::JrHb, fields.rs_name().to_string(), kind)
        }
        // `jalr` names its link register only when it is not `ra`, as
        // `rabbitizer` writes `jalr`.
        _ if fields.function == JALR => {
            let operands = if fields.rd == RA {
                fields.rs_name().to_string()
            } else {
                format!("{}, {}", fields.rd_name(), fields.rs_name())
            };
            (Op::JalrHb, operands, InsnKind::Call { target: None })
        }
        _ => return None,
    };
    Some(Word { op, operands, kind })
}

/// `rs` of the COP1 group of branches on a condition code.
const BC1: u32 = 0x08;
/// `rs` of the COP1 groups of single and double floats.
const FMT_S: u32 = 0x10;
const FMT_D: u32 = 0x11;
/// The top two bits of `function` of a compare, `c.cond.fmt`.
const COMPARE: u32 = 0x30;

/// The words of coprocessor 1 that use a condition code other than 0.
/// `rabbitizer` reads code 0, the only one MIPS I to III have.
fn cop1(fields: &Fields) -> Option<(Op, String)> {
    match fields.rs {
        BC1 => {
            let condition = fields.rt >> 2;
            let branch = match fields.rt & 0b11 {
                0 => FloatBranch::False,
                1 => FloatBranch::True,
                2 => FloatBranch::FalseLikely,
                _ => FloatBranch::TrueLikely,
            };
            let distance = fields.branch_distance();
            let target = super::mips::with_target("", distance);
            (condition != 0).then(|| (Op::FloatBranch(branch), format!("fcc{condition}, {target}")))
        }
        FMT_S | FMT_D => {
            // The condition code sits in the top three bits of `sa`; the
            // two below it are zero.
            let condition = fields.sa >> 2;
            if fields.function & 0x30 != COMPARE || fields.sa & 0b11 != 0 || condition == 0 {
                return None;
            }
            let format = if fields.rs == FMT_S { FloatFormat::Single } else { FloatFormat::Double };
            let compare = FloatCompare { condition: (fields.function & 0xf) as u8, format };
            let (fs, ft) =
                (FLOAT_REGISTERS[fields.rd as usize], FLOAT_REGISTERS[fields.rt as usize]);
            Some((Op::FloatCompare(compare), format!("fcc{condition}, {fs}, {ft}")))
        }
        _ => None,
    }
}

/// The fields of an instruction word.
struct Fields {
    opcode: u32,
    rs: u32,
    rt: u32,
    rd: u32,
    sa: u32,
    function: u32,
    immediate: u32,
}

impl Fields {
    fn of(word: u32) -> Self {
        Self {
            opcode: word >> 26,
            rs: (word >> 21) & 0x1f,
            rt: (word >> 16) & 0x1f,
            rd: (word >> 11) & 0x1f,
            sa: (word >> 6) & 0x1f,
            function: word & 0x3f,
            immediate: word & 0xffff,
        }
    }

    fn rs_name(&self) -> &'static str {
        REGISTERS[self.rs as usize]
    }

    fn rt_name(&self) -> &'static str {
        REGISTERS[self.rt as usize]
    }

    fn rd_name(&self) -> &'static str {
        REGISTERS[self.rd as usize]
    }

    /// How far a branch goes: from the branch, past its delay slot, by
    /// the signed offset in words.
    fn branch_distance(&self) -> i64 {
        4 + i64::from(self.immediate as u16 as i16) * 4
    }

    /// The signed 16-bit offset, written as `rabbitizer` writes one.
    fn offset(&self) -> String {
        let offset = self.immediate as u16 as i16;
        if offset < 0 {
            format!("-{:#X}", offset.unsigned_abs()).replace("0X", "0x")
        } else {
            format!("{offset:#X}").replace("0X", "0x")
        }
    }

    /// `rd, rs, rt`.
    fn three_registers(&self) -> String {
        format!("{}, {}, {}", self.rd_name(), self.rs_name(), self.rt_name())
    }

    /// `rs, rt`, for the operations that write `hi` and `lo`.
    fn two_sources(&self) -> String {
        format!("{}, {}", self.rs_name(), self.rt_name())
    }

    /// The accumulator an operation names in `rd`, or `None` when the bits
    /// above the two it uses are not zero.
    fn accumulator_in_rd(&self) -> Option<Accumulator> {
        (self.rd >> 2 == 0 && self.sa == 0).then_some(Accumulator(self.rd))
    }

    /// `rs, rt`, after the accumulator unless it is `ac0`.
    ///
    /// `ac0` is `hi` and `lo`, which the MIPS32 form names by leaving it
    /// out, so both spellings of one operation read alike.
    fn sources_into(&self, accumulator: Accumulator) -> String {
        if accumulator.is_hi_lo() {
            self.two_sources()
        } else {
            format!("{accumulator}, {}", self.two_sources())
        }
    }
}

/// One of the four DSP accumulators. `ac0` is `hi` and `lo`.
#[derive(Clone, Copy)]
struct Accumulator(u32);

impl Accumulator {
    fn is_hi_lo(self) -> bool {
        self.0 == 0
    }
}

impl core::fmt::Display for Accumulator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ac{}", self.0)
    }
}

/// `movz`, `movn`, `rotr`, `rotrv`, and the DSP accumulator forms.
fn special(fields: &Fields) -> Option<(Op, String)> {
    if let Some(found) = special_accumulator(fields) {
        return Some(found);
    }
    match (fields.function, fields.rs, fields.sa) {
        // MIPS IV and MIPS32: a move on a condition.
        (0x0a, _, 0) => Some((Op::Movz, fields.three_registers())),
        (0x0b, _, 0) => Some((Op::Movn, fields.three_registers())),
        // Release 2 marks a rotate with a 1 in the field `srl` leaves zero.
        (0x02, 1, _) => {
            Some((Op::Rotr, format!("{}, {}, {}", fields.rd_name(), fields.rt_name(), fields.sa)))
        }
        (0x06, _, 1) => Some((
            Op::Rotrv,
            format!("{}, {}, {}", fields.rd_name(), fields.rt_name(), fields.rs_name()),
        )),
        _ => None,
    }
}

/// The moves and multiplies that name a DSP accumulator other than `ac0`.
///
/// The `ac0` forms are MIPS II, which `rabbitizer` has already read. Each
/// form keeps the accumulator in a field MIPS II leaves zero, and the bits
/// around it must still be zero.
fn special_accumulator(fields: &Fields) -> Option<(Op, String)> {
    const MFHI: u32 = 0x10;
    const MTHI: u32 = 0x11;
    const MFLO: u32 = 0x12;
    const MTLO: u32 = 0x13;
    const MULT: u32 = 0x18;
    const MULTU: u32 = 0x19;

    match fields.function {
        // `mfhi rd, ac`: the accumulator is in the low two bits of `rs`.
        MFHI | MFLO if fields.rs >> 2 == 0 && fields.rt == 0 && fields.sa == 0 => {
            let op = if fields.function == MFHI { Op::Mfhi } else { Op::Mflo };
            Some((op, format!("{}, {}", fields.rd_name(), Accumulator(fields.rs))))
        }
        // `mthi rs, ac`: the accumulator is in the low two bits of `rd`.
        MTHI | MTLO if fields.rt == 0 => {
            let accumulator = fields.accumulator_in_rd()?;
            let op = if fields.function == MTHI { Op::Mthi } else { Op::Mtlo };
            Some((op, format!("{}, {accumulator}", fields.rs_name())))
        }
        MULT | MULTU => {
            let accumulator = fields.accumulator_in_rd()?;
            let op = if fields.function == MULT { Op::Mult } else { Op::Multu };
            Some((op, fields.sources_into(accumulator)))
        }
        _ => None,
    }
}

/// The MIPS32 multiply and count operations.
fn special2(fields: &Fields) -> Option<(Op, String)> {
    let op = match fields.function {
        0x00 => Op::Madd,
        0x01 => Op::Maddu,
        0x02 => Op::Mul,
        0x04 => Op::Msub,
        0x05 => Op::Msubu,
        0x20 => Op::Clz,
        0x21 => Op::Clo,
        _ => return None,
    };
    let operands = match op {
        Op::Mul => fields.three_registers(),
        Op::Clz | Op::Clo => format!("{}, {}", fields.rd_name(), fields.rs_name()),
        // The DSP ASE names an accumulator in `rd`, which MIPS32 leaves zero.
        _ => fields.sources_into(fields.accumulator_in_rd()?),
    };
    Some((op, operands))
}

/// The Release 2 bit field and byte operations.
fn special3(fields: &Fields) -> Option<(Op, String)> {
    match fields.function {
        // `ext rt, rs, pos, size`: `sa` holds the position and `rd` the size
        // less one.
        0x00 => Some((
            Op::Ext,
            format!("{}, {}, {}, {}", fields.rt_name(), fields.rs_name(), fields.sa, fields.rd + 1),
        )),
        // `ins rt, rs, pos, size`: `rd` holds the last bit, so the size is
        // what lies between it and the position.
        0x04 if fields.rd >= fields.sa => Some((
            Op::Ins,
            format!(
                "{}, {}, {}, {}",
                fields.rt_name(),
                fields.rs_name(),
                fields.sa,
                fields.rd - fields.sa + 1
            ),
        )),
        0x20 if fields.rs == 0 => {
            let op = match fields.sa {
                0x02 => Op::Wsbh,
                0x10 => Op::Seb,
                0x18 => Op::Seh,
                _ => return None,
            };
            Some((op, format!("{}, {}", fields.rd_name(), fields.rt_name())))
        }
        // GNU `as` writes the hardware register as `$29`, but a leading `$`
        // marks a branch target here, so it is named instead.
        0x3b if fields.rs == 0 => {
            Some((Op::Rdhwr, format!("{}, hwr{}", fields.rt_name(), fields.rd)))
        }
        0x38 => dsp_control(fields),
        _ => None,
    }
}

/// `rddsp` and `wrdsp`, which move the DSP control register.
///
/// The mask says which fields of the register move, one bit for each of six.
fn dsp_control(fields: &Fields) -> Option<(Op, String)> {
    const RDDSP: u32 = 0x12;
    const WRDSP: u32 = 0x13;

    match fields.sa {
        // `rddsp rd, mask`: the mask fills `rs` and `rt`.
        RDDSP => {
            let mask = (fields.rs << 5) | fields.rt;
            Some((Op::Rddsp, format!("{}, {mask:#x}", fields.rd_name())))
        }
        // `wrdsp rs, mask`: the mask fills `rt` and `rd`.
        WRDSP => {
            let mask = (fields.rt << 5) | fields.rd;
            Some((Op::Wrdsp, format!("{}, {mask:#x}", fields.rs_name())))
        }
        _ => None,
    }
}

/// `rs` of `mfc0` and `mtc0`.
const MFC0: u32 = 0x00;
const MTC0: u32 = 0x04;

/// `di`, `ei`, `wait`, and `mfc0` and `mtc0` with a select.
fn cop0(fields: &Fields) -> Option<(Op, String)> {
    // MIPS32 adds a select to the coprocessor 0 moves, in the low three bits.
    // `rabbitizer` reads only select 0, which it names, such as `Status`.
    // The others have no standard name, so the number and select are written.
    let select = fields.function & 0x7;
    if (fields.rs == MFC0 || fields.rs == MTC0) && fields.sa == 0 && fields.function & 0x38 == 0 {
        let op = if fields.rs == MFC0 { Op::Mfc0 } else { Op::Mtc0 };
        return Some((op, format!("{}, c0r{}, {select}", fields.rt_name(), fields.rd)));
    }
    // `mfmc0` names the status register, 12, and a fixed pattern below it.
    if fields.rs == MFMC0 && fields.rd == 12 && fields.sa == 0 && fields.function & 0x1f == 0 {
        let op = if fields.function & 0x20 == 0 { Op::Di } else { Op::Ei };
        let operands = if fields.rt == 0 { String::new() } else { fields.rt_name().to_string() };
        return Some((op, operands));
    }
    // `wait` sets the coprocessor-operation bit, and its code field is free.
    if fields.rs & 0x10 != 0 && fields.function == 0x20 {
        return Some((Op::Wait, String::new()));
    }
    None
}

/// Lift a word [`decode`] reads. A DSP accumulator other than `ac0`, which
/// is `hi` and `lo`, is a register the IL does not name: a move to or from
/// one names it as another operand, and a multiply into one lifts to
/// nothing.
pub(crate) fn lift(word: u32) -> Option<il::Lifted> {
    lift_named(word).map(|named| named.lifted)
}

/// [`lift`], with the name of each operand as [`decode`] writes it. An
/// operand it does not write, as the `hi` that `mthi` writes, has an empty
/// name.
pub(crate) fn lift_named(word: u32) -> Option<il::Named> {
    use compact_str::{CompactString, format_compact};
    use il::Op;
    let fields = Fields::of(word);
    let decoded = decode(word)?.op;
    type Named = (il::Operand, CompactString);
    let general = |number: u32| -> Named {
        let operand = match number {
            0 => il::Operand::Zero,
            number => il::Operand::Reg(il::Reg::General(number as u8)),
        };
        (operand, REGISTERS[number as usize].into())
    };
    let constant =
        |value: u32, name: CompactString| -> Named { (il::Operand::Const(value.into()), name) };
    let decimal = |value: u32| constant(value, format_compact!("{value}"));
    let hidden = |reg: il::Reg| -> Named { (il::Operand::Reg(reg), CompactString::default()) };
    let other = |name: CompactString| -> Named { (il::Operand::Other, name) };
    let (rs, rt, rd) = (general(fields.rs), general(fields.rt), general(fields.rd));
    let select = decimal(fields.function & 0x7);
    let base = match fields.rs {
        0 => None,
        number => Some(il::Reg::General(number as u8)),
    };
    let offset = fields.offset();
    let place = match offset.as_str() {
        "0x0" => format_compact!("[{}]", fields.rs_name()),
        _ => format_compact!("[{} + {offset}]", fields.rs_name()),
    };
    let memory: Named =
        (il::Operand::memory(base, Some(i64::from(fields.immediate as u16 as i16))), place);
    let accumulator = |number: u32| other(format_compact!("{}", Accumulator(number)));
    let (op, named, written): (Op, Vec<Named>, Option<il::Operand>) = match decoded {
        self::Op::Movz | self::Op::Movn => (Op::Select, vec![rd.clone(), rs, rt], Some(rd.0)),
        self::Op::Rotr => (Op::Rotate, vec![rd.clone(), rt, decimal(fields.sa)], Some(rd.0)),
        self::Op::Rotrv => (Op::Rotate, vec![rd.clone(), rt, rs], Some(rd.0)),
        self::Op::Mul => (Op::Multiply, vec![rd.clone(), rs, rt], Some(rd.0)),
        self::Op::Clz | self::Op::Clo => (Op::Bits, vec![rd.clone(), rs], Some(rd.0)),
        self::Op::Wsbh => (Op::Bits, vec![rd.clone(), rt], Some(rd.0)),
        self::Op::Seb | self::Op::Seh => (Op::Extend, vec![rd.clone(), rt], Some(rd.0)),
        self::Op::Ext => {
            let size = decimal(fields.rd + 1);
            (Op::BitField, vec![rt.clone(), rs, decimal(fields.sa), size], Some(rt.0))
        }
        self::Op::Ins => {
            let size = decimal(fields.rd - fields.sa + 1);
            (Op::BitField, vec![rt.clone(), rs, decimal(fields.sa), size], Some(rt.0))
        }
        // Only `ac0`, which is `hi` and `lo`, is a register the IL names.
        self::Op::Madd | self::Op::Maddu | self::Op::Msub | self::Op::Msubu if fields.rd == 0 => {
            (Op::MultiplyAdd, vec![rs, rt], None)
        }
        self::Op::Mult | self::Op::Multu if fields.rd == 0 => (Op::Multiply, vec![rs, rt], None),
        self::Op::Mfhi if fields.rs == 0 => {
            (Op::Move, vec![rd.clone(), (il::Operand::Reg(HI), "ac0".into())], Some(rd.0))
        }
        self::Op::Mflo if fields.rs == 0 => {
            (Op::Move, vec![rd.clone(), (il::Operand::Reg(LO), "ac0".into())], Some(rd.0))
        }
        self::Op::Mthi if fields.rd == 0 => {
            (Op::Move, vec![hidden(HI), rs], Some(il::Operand::Reg(HI)))
        }
        self::Op::Mtlo if fields.rd == 0 => {
            (Op::Move, vec![hidden(LO), rs], Some(il::Operand::Reg(LO)))
        }
        // An accumulator past `ac0` is no register the IL names.
        self::Op::Mfhi | self::Op::Mflo => {
            (Op::Move, vec![rd.clone(), accumulator(fields.rs)], Some(rd.0))
        }
        self::Op::Mthi | self::Op::Mtlo => (Op::Move, vec![accumulator(fields.rd), rs], None),
        // A move to or from coprocessor 0 names its register and select,
        // which the IL does not track.
        self::Op::Mfc0 | self::Op::Mtc0 => {
            let register = other(format_compact!("c0r{}", fields.rd));
            let written = (decoded == self::Op::Mfc0).then_some(rt.0);
            (Op::System, vec![rt, register, select], written)
        }
        // `di` and `ei` write the old status to `rt`, where it names one.
        self::Op::Di | self::Op::Ei if fields.rt == 0 => (Op::System, vec![], None),
        self::Op::Di | self::Op::Ei => (Op::System, vec![rt.clone()], Some(rt.0)),
        self::Op::Wait | self::Op::Eret | self::Op::Deret => (Op::System, vec![], None),
        self::Op::Sigrie => {
            let code = constant(fields.immediate, format_compact!("{:#x}", fields.immediate));
            (Op::System, vec![code], None)
        }
        self::Op::Pref => {
            let hint = constant(fields.rt, format_compact!("{:#x}", fields.rt));
            (Op::System, vec![hint, memory], None)
        }
        self::Op::Synci => (Op::System, vec![memory], None),
        self::Op::Rdhwr => {
            let register = other(format_compact!("hwr{}", fields.rd));
            (Op::Move, vec![rt.clone(), register], Some(rt.0))
        }
        self::Op::JrHb => (Op::Jump, vec![rs], None),
        self::Op::FloatBranch(_) => {
            let target = super::mips::with_target("", fields.branch_distance());
            (Op::Branch, vec![(il::Operand::Target(None), target.into())], None)
        }
        self::Op::FloatCompare(_) => {
            let float = |number: u32| -> Named {
                (
                    il::Operand::Reg(il::Reg::Vector(number as u8)),
                    FLOAT_REGISTERS[number as usize].into(),
                )
            };
            (Op::Float, vec![float(fields.rd), float(fields.rt)], None)
        }
        self::Op::JalrHb => {
            // `jalr` names its link register only when it is not `ra`.
            let link = match fields.rd {
                31 => (rd.0, CompactString::default()),
                _ => rd.clone(),
            };
            (Op::Call, vec![link, rs], Some(rd.0))
        }
        _ => return None,
    };
    let (operands, names): (il::Operands, il::Names) = named.into_iter().unzip();

    let register = |operand: &il::Operand| match operand {
        il::Operand::Reg(reg) => Some(*reg),
        _ => None,
    };
    let mut reads: il::RegSet =
        operands.iter().skip(usize::from(written.is_some())).filter_map(register).collect();
    let mut writes: il::RegSet = written.iter().filter_map(register).collect();
    match decoded {
        // A move on a condition keeps the destination where the condition
        // fails, and an insert keeps the bits around its field.
        self::Op::Movz | self::Op::Movn | self::Op::Ins => {
            writes.iter().for_each(|reg| reads.insert(reg))
        }
        self::Op::Madd | self::Op::Maddu | self::Op::Msub | self::Op::Msubu => {
            for accumulator in [HI, LO] {
                reads.insert(accumulator);
                writes.insert(accumulator);
            }
        }
        self::Op::Mult | self::Op::Multu => {
            writes.insert(HI);
            writes.insert(LO);
        }

        _ => {}
    }
    let lifted = il::Lifted { op, reads, writes, memory: None, test: None, operands };
    Some(il::Named { lifted, names, write_back: None })
}

/// Where the IL keeps `hi` and `lo`, as [`super::mips`] does.
const HI: il::Reg = il::Reg::General(32);
const LO: il::Reg = il::Reg::General(33);

#[cfg(test)]
mod tests {
    use super::*;

    fn text(word: u32) -> Option<String> {
        decode(word).map(|Word { op, operands, .. }| {
            let name = op.name();
            if operands.is_empty() { name.to_string() } else { format!("{name} {operands}") }
        })
    }

    fn kind(word: u32) -> Option<InsnKind> {
        decode(word).map(|word| word.kind)
    }

    /// The words a kernel holds lift with typed operands: what they write,
    /// and a coprocessor register or an accumulator past `ac0` as another
    /// operand.
    #[test]
    fn the_kernel_words_lift() {
        use il::{Op as IlOp, Operand, Reg};
        let t0 = Operand::Reg(Reg::General(8));
        let lifted = |word: u32| lift(word).unwrap_or_else(|| panic!("{word:#010x} lifts"));

        // mfc0 t0, c0r12, 0
        let mfc0 = lifted(0x4008_6000);
        assert_eq!(mfc0.op, IlOp::System);
        assert_eq!(mfc0.operands.as_slice(), [t0, Operand::Other, Operand::Const(0)]);
        assert!(mfc0.writes.contains(Reg::General(8)));

        // di t0 writes the old status; di alone writes nothing.
        assert!(lifted(0x4168_6000).writes.contains(Reg::General(8)));
        assert!(lifted(0x4160_6000).operands.is_empty());

        // mfhi v0, ac1 and mthi a0, ac1.
        let from = lifted(0x0020_1010);
        assert_eq!((from.op, from.operands[1]), (IlOp::Move, Operand::Other));
        assert!(from.writes.contains(Reg::General(2)));
        let to = lifted(0x0080_0811);
        assert!(to.reads.contains(Reg::General(4)) && to.writes.is_empty());

        // wait
        assert_eq!(lifted(0x4200_0020).op, IlOp::System);
    }

    /// `jr.hb $ra`, `jr.hb $3` and `jalr.hb $25`, as LLVM assembles them.
    /// A branch and a compare on a floating-point condition code other
    /// than 0, as GCC emits for a second compare, read and lift as the same
    /// words on code 0 do.
    #[test]
    fn reads_the_float_condition_codes() {
        // bc1t $fcc1, bc1fl $fcc7 and bc1tl $fcc1, each 0x28 ahead.
        assert_eq!(text(0x4505_0009).as_deref(), Some("bc1t fcc1, $+0x28"));
        assert_eq!(text(0x451e_0009).as_deref(), Some("bc1fl fcc7, $+0x28"));
        assert_eq!(text(0x4507_0009).as_deref(), Some("bc1tl fcc1, $+0x28"));
        assert_eq!(kind(0x4505_0009), Some(InsnKind::Branch { target: None }));
        assert_eq!(branch_distance(0x4505_0009), Some(0x28));
        // bc1t $fcc1 back by 4 words: 0x4505fffc.
        assert_eq!(branch_distance(0x4505_fffc), Some(-12));
        // c.lt.d $fcc1, $f2, $f0 and c.eq.s $fcc3, $f12, $f14.
        assert_eq!(text(0x4620_113c).as_deref(), Some("c.lt.d fcc1, fv1, fv0"));
        assert_eq!(text(0x460e_6332).as_deref(), Some("c.eq.s fcc3, fa0, fa1"));
        let compare = decode(0x4620_113c).expect("reads").op;
        assert_eq!(compare.operation_name(), "c_lt_d");
        let lifted = lift(0x4620_113c).expect("lifts");
        assert_eq!(lifted.op, il::Op::Float);
        assert_eq!(
            lifted.operands.as_slice(),
            [il::Operand::Reg(il::Reg::Vector(2)), il::Operand::Reg(il::Reg::Vector(0))]
        );
        assert_eq!(lift(0x4505_0009).expect("lifts").op, il::Op::Branch);
        // Code 0 is `rabbitizer`'s, and a compare with stray bits is no compare.
        assert_eq!(decode(0x4501_0009), None, "bc1t on code 0");
        assert_eq!(decode(0x4622_003e), None, "c.le.d on code 0");
        assert_eq!(decode(0x4620_117c), None, "a compare with stray bits");
    }

    #[test]
    fn reads_the_hazard_barrier_jumps() {
        assert_eq!(text(0x03e0_0408).as_deref(), Some("jr.hb ra"));
        assert_eq!(kind(0x03e0_0408), Some(InsnKind::Return));
        assert_eq!(text(0x0060_0408).as_deref(), Some("jr.hb v1"));
        assert_eq!(kind(0x0060_0408), Some(InsnKind::Jump { target: None }));
        assert_eq!(text(0x0320_fc09).as_deref(), Some("jalr.hb t9"));
        assert_eq!(text(0x0320_2409).as_deref(), Some("jalr.hb a0, t9"));
        assert_eq!(kind(0x0320_fc09), Some(InsnKind::Call { target: None }));
    }

    /// A `jr` with any other bit in the hint field is not `jr.hb`.
    #[test]
    fn a_jump_with_another_hint_is_refused() {
        assert_eq!(decode(0x03e0_0208), None, "hint 8");
        assert_eq!(decode(0x03e1_0408), None, "rt set");
        assert_eq!(decode(0x03e0_0c08), None, "rd set");
    }

    #[test]
    fn reads_the_exception_returns() {
        assert_eq!(text(0x4200_0018).as_deref(), Some("eret"));
        assert_eq!(text(0x4200_001f).as_deref(), Some("deret"));
        assert_eq!(kind(0x4200_0018), Some(InsnKind::Return));
        assert_eq!(kind(0x4200_001f), Some(InsnKind::Return));
        assert!(is_exception_return(Op::Eret) && is_exception_return(Op::Deret));
        assert!(!is_exception_return(Op::JrHb));
    }

    /// `sigrie 1`, as LLD pads with.
    #[test]
    fn reads_the_padding_trap() {
        assert_eq!(text(0x0417_0001).as_deref(), Some("sigrie 0x1"));
        assert_eq!(decode(0x0437_0001), None, "rs set");
    }

    /// `synci 0($4)` and `synci -16($13)`.
    #[test]
    fn reads_synci() {
        assert_eq!(text(0x049f_0000).as_deref(), Some("synci 0x0(a0)"));
        assert_eq!(text(0x05bf_fff0).as_deref(), Some("synci -0x10(t5)"));
        assert_eq!(kind(0x049f_0000), Some(InsnKind::Normal));
        assert_eq!(decode(0x049e_0000), None, "another REGIMM rt");
    }

    /// The encodings below come from the MIPS32 Release 2 manual, as GNU `as`
    /// assembles the instruction in the comment.
    #[test]
    fn reads_the_conditional_moves() {
        assert_eq!(text(0x0082_100a).as_deref(), Some("movz v0, a0, v0")); // movz $2,$4,$2
        assert_eq!(text(0x0082_100b).as_deref(), Some("movn v0, a0, v0")); // movn $2,$4,$2
    }

    #[test]
    fn reads_the_rotates() {
        assert_eq!(text(0x0022_1602).as_deref(), Some("rotr v0, v0, 24")); // rotr $2,$2,24
        assert_eq!(text(0x0082_1046).as_deref(), Some("rotrv v0, v0, a0")); // rotrv $2,$2,$4
    }

    /// `mfhi $3,$ac1` and friends, as LLVM assembles them with `-mattr=+dsp`.
    #[test]
    fn reads_the_accumulator_moves() {
        assert_eq!(text(0x0020_1810).as_deref(), Some("mfhi v1, ac1"));
        assert_eq!(text(0x0060_1812).as_deref(), Some("mflo v1, ac3"));
        assert_eq!(text(0x0080_0811).as_deref(), Some("mthi a0, ac1"));
        assert_eq!(text(0x00e0_0813).as_deref(), Some("mtlo a3, ac1"));
    }

    /// Bits beside the accumulator field are not an accumulator.
    #[test]
    fn a_move_with_stray_bits_is_refused() {
        assert_eq!(decode(0x0080_1810), None, "rs above the accumulator");
        assert_eq!(decode(0x0021_1810), None, "rt set");
        assert_eq!(decode(0x0080_2011), None, "rd above the accumulator");
        assert_eq!(decode(0x0080_0851), None, "sa set");
    }

    /// `mult $ac2,$zero,$8` and `madd $ac1,$4,$5`, with `ac0` left out as
    /// MIPS32 writes it.
    #[test]
    fn reads_the_accumulator_multiplies() {
        assert_eq!(text(0x0008_1018).as_deref(), Some("mult ac2, zero, t0"));
        assert_eq!(text(0x0085_1819).as_deref(), Some("multu ac3, a0, a1"));
        assert_eq!(text(0x7085_0800).as_deref(), Some("madd ac1, a0, a1"));
        assert_eq!(text(0x7085_1805).as_deref(), Some("msubu ac3, a0, a1"));
        assert_eq!(decode(0x0085_2018), None, "rd above the accumulator");
        assert_eq!(decode(0x7085_2000), None, "rd above the accumulator");
        assert_eq!(decode(0x7085_0040), None, "sa set");
    }

    /// `rddsp $2,0x1` and `wrdsp $4,0x3f`, as found in OpenWrt kernels.
    #[test]
    fn reads_the_dsp_control_moves() {
        assert_eq!(text(0x7c01_14b8).as_deref(), Some("rddsp v0, 0x1"));
        assert_eq!(text(0x7c3f_1cb8).as_deref(), Some("rddsp v1, 0x3f"));
        assert_eq!(text(0x7c81_fcf8).as_deref(), Some("wrdsp a0, 0x3f"));
        assert_eq!(decode(0x7c01_1478), None, "an operation of the group not read here");
    }

    /// `srl` and `srlv` share the encodings, told apart by one bit.
    #[test]
    fn a_plain_shift_is_not_a_rotate() {
        assert_eq!(decode(0x0002_1082), None, "srl v0, v0, 2 is MIPS II");
        assert_eq!(decode(0x0082_1006), None, "srlv v0, v0, a0 is MIPS II");
    }

    #[test]
    fn reads_the_multiply_and_count_operations() {
        assert_eq!(text(0x7085_1002).as_deref(), Some("mul v0, a0, a1")); // mul $2,$4,$5
        assert_eq!(text(0x7085_0000).as_deref(), Some("madd a0, a1"));
        assert_eq!(text(0x7085_0001).as_deref(), Some("maddu a0, a1"));
        assert_eq!(text(0x7085_0004).as_deref(), Some("msub a0, a1"));
        assert_eq!(text(0x7085_0005).as_deref(), Some("msubu a0, a1"));
        assert_eq!(text(0x7082_1020).as_deref(), Some("clz v0, a0")); // clz $2,$4
        assert_eq!(text(0x7082_1021).as_deref(), Some("clo v0, a0"));
        assert_eq!(decode(0x7085_0003), None, "function 3 is not defined");
    }

    #[test]
    fn reads_the_bit_fields() {
        // ext $2,$4,8,8 and ins $2,$4,8,8.
        assert_eq!(text(0x7c82_3a00).as_deref(), Some("ext v0, a0, 8, 8"));
        assert_eq!(text(0x7c82_7a04).as_deref(), Some("ins v0, a0, 8, 8"));
        // ext $2,$4,0,32 takes the whole word.
        assert_eq!(text(0x7c82_f800).as_deref(), Some("ext v0, a0, 0, 32"));
    }

    /// An `ins` whose last bit lies before its first is not an encoding.
    #[test]
    fn an_ins_that_ends_before_it_starts_is_refused() {
        assert_eq!(decode(0x7c82_3a04 & !(0x1f << 11) | (2 << 11)), None);
    }

    #[test]
    fn reads_the_byte_operations() {
        assert_eq!(text(0x7c02_10a0).as_deref(), Some("wsbh v0, v0")); // wsbh $2,$2
        assert_eq!(text(0x7c02_1420).as_deref(), Some("seb v0, v0")); // seb $2,$2
        assert_eq!(text(0x7c02_1620).as_deref(), Some("seh v0, v0")); // seh $2,$2
        assert_eq!(decode(0x7c02_1020), None, "sa 0 is not a byte operation");
    }

    #[test]
    fn reads_the_hardware_register_read() {
        assert_eq!(text(0x7c03_e83b).as_deref(), Some("rdhwr v1, hwr29")); // rdhwr $3,$29
    }

    #[test]
    fn reads_interrupt_control() {
        assert_eq!(text(0x4160_6000).as_deref(), Some("di")); // di
        assert_eq!(text(0x4162_6000).as_deref(), Some("di v0")); // di $2
        assert_eq!(text(0x4160_6020).as_deref(), Some("ei")); // ei
        assert_eq!(text(0x4200_0020).as_deref(), Some("wait"));
        assert_eq!(decode(0x4160_5000), None, "only the status register");
    }

    /// `mfc0 $2,$12,1` and `mtc0 $2,$16,7`.
    #[test]
    fn reads_the_coprocessor_moves_with_a_select() {
        assert_eq!(text(0x4002_6001).as_deref(), Some("mfc0 v0, c0r12, 1"));
        assert_eq!(text(0x4082_8007).as_deref(), Some("mtc0 v0, c0r16, 7"));
        assert_eq!(decode(0x4002_6009), None, "bits between rd and the select are zero");
    }

    /// No operand this module writes may start with `$`, which marks a branch
    /// target, so no instruction here reads as a branch to the matcher.
    #[test]
    fn no_operand_reads_as_a_branch_target() {
        for word in
            [0x7c03_e83b_u32, 0x4002_6001, 0x0022_1602, 0x7c82_3a00, 0xcc80_0010, 0x0060_0408]
        {
            let Word { operands, .. } = decode(word).expect("a known word");
            assert!(
                operands.split(',').all(|operand| !crate::arch::is_branch_target(operand.trim())),
                "{word:#010x}: {operands}"
            );
        }
    }

    #[test]
    fn reads_prefetch() {
        assert_eq!(text(0xcc80_0010).as_deref(), Some("pref 0x0, 0x10(a0)"));
        assert_eq!(text(0xcc81_fff0).as_deref(), Some("pref 0x1, -0x10(a0)"));
    }

    #[test]
    fn register_thirty_is_named_as_rabbitizer_names_it() {
        assert_eq!(REGISTERS[30], "s8");
        assert_eq!(REGISTERS.len(), 32);
    }

    /// A major opcode this module does not own is left alone.
    #[test]
    fn other_opcodes_are_refused() {
        assert_eq!(decode(0x2402_0001), None, "addiu");
        assert_eq!(decode(0xec00_0001), None, "a reserved opcode");
    }

    fn general(number: u8) -> il::Operand {
        il::Operand::Reg(il::Reg::General(number))
    }

    fn regs(numbers: &[u8]) -> il::RegSet {
        numbers.iter().map(|&number| il::Reg::General(number)).collect()
    }

    /// `movz v0, a1, at` keeps `v0` where `at` is not zero, so it reads it.
    #[test]
    fn a_move_on_a_condition_is_a_select() {
        let lifted = lift(0x00a1_100a).expect("movz lifts");
        assert_eq!(lifted.op, il::Op::Select);
        assert_eq!(lifted.operands.as_slice(), [general(2), general(5), general(1)]);
        assert_eq!((lifted.reads, lifted.writes), (regs(&[1, 2, 5]), regs(&[2])));
    }

    #[test]
    fn a_bit_field_names_its_position_and_size() {
        // `ext t0, a0, 3, 5`
        let lifted = lift(0x7c88_20c0).expect("ext lifts");
        assert_eq!(lifted.op, il::Op::BitField);
        let field = [il::Operand::Const(3), il::Operand::Const(5)];
        assert_eq!(lifted.operands[2..], field);
        assert_eq!((lifted.reads, lifted.writes), (regs(&[4]), regs(&[8])));
    }

    #[test]
    fn a_byte_extend_and_a_multiply_lift() {
        // `seb v0, a0`
        let seb = lift(0x7c04_1420).expect("seb lifts");
        assert_eq!(
            (seb.op, seb.operands.as_slice()),
            (il::Op::Extend, &[general(2), general(4)][..])
        );
        // `mul zero, a0, a1` writes nothing the IL keeps.
        let mul = lift(0x7085_0002).expect("mul lifts");
        assert_eq!(mul.operands[0], il::Operand::Zero);
        assert!(mul.writes.is_empty());
    }

    /// A multiply into `ac1` names an accumulator the IL has no register for.
    #[test]
    fn a_dsp_accumulator_lifts_to_nothing() {
        // `madd ac1, a0, a1`
        assert!(decode(0x7085_0800).is_some());
        assert_eq!(lift(0x7085_0800), None);
    }

    #[test]
    fn what_lifts_is_what_decodes() {
        bolero::check!().with_type::<u32>().for_each(|&word| {
            if let Some(lifted) = lift(word) {
                assert!(decode(word).is_some(), "{word:#010x}");
                assert!(lifted.operands.len() <= 4, "{word:#010x}");
            }
        });
    }
}
