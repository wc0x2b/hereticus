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
const REGISTERS: [&str; 32] = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
    "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "s8",
    "ra",
];

use super::InsnKind;

/// The major opcodes this module reads under.
const SPECIAL: u32 = 0x00;
const REGIMM: u32 = 0x01;
const COP0: u32 = 0x10;
const SPECIAL2: u32 = 0x1c;
const SPECIAL3: u32 = 0x1f;
const PREF: u32 = 0x33;

/// `rs` of the COP0 `mfmc0` group, which holds `di` and `ei`.
const MFMC0: u32 = 0x0b;

/// One word this module reads.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Word {
    pub(super) mnemonic: &'static str,
    pub(super) operands: String,
    pub(super) kind: InsnKind,
}

/// The mnemonic of the trap that LLD pads with.
pub(super) const SIGRIE: &str = "sigrie";

/// `eret` and `deret`, which return from an exception and from a debug
/// exception. Each is one fixed word.
const ERET: u32 = 0x4200_0018;
const DERET: u32 = 0x4200_001f;

/// Report whether a mnemonic returns from an exception.
///
/// Unlike every other MIPS jump, such a return has no delay slot.
pub(super) fn is_exception_return(mnemonic: &str) -> bool {
    matches!(mnemonic, "eret" | "deret")
}

/// Read a MIPS32 or MIPS32r2 word.
///
/// Returns `None` for a word this module does not know, which leaves it
/// unreadable.
pub(super) fn decode(word: u32) -> Option<Word> {
    let fields = Fields::of(word);
    if let Some(found) = control(word, &fields) {
        return Some(found);
    }

    let (mnemonic, operands) = match fields.opcode {
        SPECIAL => special(&fields),
        SPECIAL2 => special2(&fields),
        SPECIAL3 => special3(&fields),
        COP0 => cop0(&fields),
        // `synci offset(base)` makes a written instruction visible. It sits
        // under REGIMM, in the `rt` MIPS II leaves reserved.
        REGIMM if fields.rt == 0x1f => {
            Some(("synci", format!("{}({})", fields.offset(), fields.rs_name())))
        }
        // `sigrie code` traps. Release 6 defines it, and LLD fills the gaps
        // between functions with `sigrie 1` on every release.
        REGIMM if fields.rt == 0x17 && fields.rs == 0 => {
            Some((SIGRIE, format!("{:#x}", fields.immediate)))
        }
        PREF => {
            Some(("pref", format!("{:#x}, {}({})", fields.rt, fields.offset(), fields.rs_name())))
        }
        _ => None,
    }?;
    Some(Word { mnemonic, operands, kind: InsnKind::Normal })
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

    let (mnemonic, operands, kind) = match word {
        ERET => ("eret", String::new(), InsnKind::Return),
        DERET => ("deret", String::new(), InsnKind::Return),
        _ if fields.opcode != SPECIAL || fields.sa != HAZARD_BARRIER || fields.rt != 0 => {
            return None;
        }
        _ if fields.function == JR && fields.rd == 0 => {
            let kind =
                if fields.rs == RA { InsnKind::Return } else { InsnKind::Jump { target: None } };
            ("jr.hb", fields.rs_name().to_string(), kind)
        }
        // `jalr` names its link register only when it is not `ra`, as
        // `rabbitizer` writes `jalr`.
        _ if fields.function == JALR => {
            let operands = if fields.rd == RA {
                fields.rs_name().to_string()
            } else {
                format!("{}, {}", fields.rd_name(), fields.rs_name())
            };
            ("jalr.hb", operands, InsnKind::Call { target: None })
        }
        _ => return None,
    };
    Some(Word { mnemonic, operands, kind })
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
fn special(fields: &Fields) -> Option<(&'static str, String)> {
    if let Some(found) = special_accumulator(fields) {
        return Some(found);
    }
    match (fields.function, fields.rs, fields.sa) {
        // MIPS IV and MIPS32: a move on a condition.
        (0x0a, _, 0) => Some(("movz", fields.three_registers())),
        (0x0b, _, 0) => Some(("movn", fields.three_registers())),
        // Release 2 marks a rotate with a 1 in the field `srl` leaves zero.
        (0x02, 1, _) => {
            Some(("rotr", format!("{}, {}, {}", fields.rd_name(), fields.rt_name(), fields.sa)))
        }
        (0x06, _, 1) => Some((
            "rotrv",
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
fn special_accumulator(fields: &Fields) -> Option<(&'static str, String)> {
    const MFHI: u32 = 0x10;
    const MTHI: u32 = 0x11;
    const MFLO: u32 = 0x12;
    const MTLO: u32 = 0x13;
    const MULT: u32 = 0x18;
    const MULTU: u32 = 0x19;

    match fields.function {
        // `mfhi rd, ac`: the accumulator is in the low two bits of `rs`.
        MFHI | MFLO if fields.rs >> 2 == 0 && fields.rt == 0 && fields.sa == 0 => {
            let mnemonic = if fields.function == MFHI { "mfhi" } else { "mflo" };
            Some((mnemonic, format!("{}, {}", fields.rd_name(), Accumulator(fields.rs))))
        }
        // `mthi rs, ac`: the accumulator is in the low two bits of `rd`.
        MTHI | MTLO if fields.rt == 0 => {
            let accumulator = fields.accumulator_in_rd()?;
            let mnemonic = if fields.function == MTHI { "mthi" } else { "mtlo" };
            Some((mnemonic, format!("{}, {accumulator}", fields.rs_name())))
        }
        MULT | MULTU => {
            let accumulator = fields.accumulator_in_rd()?;
            let mnemonic = if fields.function == MULT { "mult" } else { "multu" };
            Some((mnemonic, fields.sources_into(accumulator)))
        }
        _ => None,
    }
}

/// The MIPS32 multiply and count operations.
fn special2(fields: &Fields) -> Option<(&'static str, String)> {
    let mnemonic = match fields.function {
        0x00 => "madd",
        0x01 => "maddu",
        0x02 => "mul",
        0x04 => "msub",
        0x05 => "msubu",
        0x20 => "clz",
        0x21 => "clo",
        _ => return None,
    };
    let operands = match mnemonic {
        "mul" => fields.three_registers(),
        "clz" | "clo" => format!("{}, {}", fields.rd_name(), fields.rs_name()),
        // The DSP ASE names an accumulator in `rd`, which MIPS32 leaves zero.
        _ => fields.sources_into(fields.accumulator_in_rd()?),
    };
    Some((mnemonic, operands))
}

/// The Release 2 bit field and byte operations.
fn special3(fields: &Fields) -> Option<(&'static str, String)> {
    match fields.function {
        // `ext rt, rs, pos, size`: `sa` holds the position and `rd` the size
        // less one.
        0x00 => Some((
            "ext",
            format!("{}, {}, {}, {}", fields.rt_name(), fields.rs_name(), fields.sa, fields.rd + 1),
        )),
        // `ins rt, rs, pos, size`: `rd` holds the last bit, so the size is
        // what lies between it and the position.
        0x04 if fields.rd >= fields.sa => Some((
            "ins",
            format!(
                "{}, {}, {}, {}",
                fields.rt_name(),
                fields.rs_name(),
                fields.sa,
                fields.rd - fields.sa + 1
            ),
        )),
        0x20 if fields.rs == 0 => {
            let mnemonic = match fields.sa {
                0x02 => "wsbh",
                0x10 => "seb",
                0x18 => "seh",
                _ => return None,
            };
            Some((mnemonic, format!("{}, {}", fields.rd_name(), fields.rt_name())))
        }
        // GNU `as` writes the hardware register as `$29`, but a leading `$`
        // marks a branch target here, so it is named instead.
        0x3b if fields.rs == 0 => {
            Some(("rdhwr", format!("{}, hwr{}", fields.rt_name(), fields.rd)))
        }
        0x38 => dsp_control(fields),
        _ => None,
    }
}

/// `rddsp` and `wrdsp`, which move the DSP control register.
///
/// The mask says which fields of the register move, one bit for each of six.
fn dsp_control(fields: &Fields) -> Option<(&'static str, String)> {
    const RDDSP: u32 = 0x12;
    const WRDSP: u32 = 0x13;

    match fields.sa {
        // `rddsp rd, mask`: the mask fills `rs` and `rt`.
        RDDSP => {
            let mask = (fields.rs << 5) | fields.rt;
            Some(("rddsp", format!("{}, {mask:#x}", fields.rd_name())))
        }
        // `wrdsp rs, mask`: the mask fills `rt` and `rd`.
        WRDSP => {
            let mask = (fields.rt << 5) | fields.rd;
            Some(("wrdsp", format!("{}, {mask:#x}", fields.rs_name())))
        }
        _ => None,
    }
}

/// `rs` of `mfc0` and `mtc0`.
const MFC0: u32 = 0x00;
const MTC0: u32 = 0x04;

/// `di`, `ei`, `wait`, and `mfc0` and `mtc0` with a select.
fn cop0(fields: &Fields) -> Option<(&'static str, String)> {
    // MIPS32 adds a select to the coprocessor 0 moves, in the low three bits.
    // `rabbitizer` reads only select 0, which it names, such as `Status`.
    // The others have no standard name, so the number and select are written.
    let select = fields.function & 0x7;
    if (fields.rs == MFC0 || fields.rs == MTC0) && fields.sa == 0 && fields.function & 0x38 == 0 {
        let mnemonic = if fields.rs == MFC0 { "mfc0" } else { "mtc0" };
        return Some((mnemonic, format!("{}, c0r{}, {select}", fields.rt_name(), fields.rd)));
    }
    // `mfmc0` names the status register, 12, and a fixed pattern below it.
    if fields.rs == MFMC0 && fields.rd == 12 && fields.sa == 0 && fields.function & 0x1f == 0 {
        let mnemonic = if fields.function & 0x20 == 0 { "di" } else { "ei" };
        let operands = if fields.rt == 0 { String::new() } else { fields.rt_name().to_string() };
        return Some((mnemonic, operands));
    }
    // `wait` sets the coprocessor-operation bit, and its code field is free.
    if fields.rs & 0x10 != 0 && fields.function == 0x20 {
        return Some(("wait", String::new()));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(word: u32) -> Option<String> {
        decode(word).map(|Word { mnemonic, operands, .. }| {
            if operands.is_empty() {
                mnemonic.to_string()
            } else {
                format!("{mnemonic} {operands}")
            }
        })
    }

    fn kind(word: u32) -> Option<InsnKind> {
        decode(word).map(|word| word.kind)
    }

    /// `jr.hb $ra`, `jr.hb $3` and `jalr.hb $25`, as LLVM assembles them.
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
        assert!(is_exception_return("eret") && is_exception_return("deret"));
        assert!(!is_exception_return("jr"));
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
}
