//! The decoder and the lifter of MIPS16e, which read one instruction at a
//! time, by the MIPS32 instruction it does where it has one. The rules that
//! read MIPS16e code, as its preamble of the global pointer and its jump
//! tables, are in `hereticus-recovery`, and the rules the matching reads in
//! `hereticus-arch`.

mod format;

use crate as il;
use crate::arch::mips::{Decoded as MipsDecoded, Mips32, decoded};
use crate::arch::{DecodeError, Decoder, Insn, InsnKind, Printing};
use compact_str::CompactString;
use deku::{DekuBitField, DekuRead};
use format::{
    DelaySlot, Encoded, ExtendAddiu, ExtendFrame, ExtendShift, I, I8, JumpMode, JumpRegister, Kept,
    Link, Prefix, Ri, Rr, Rri, RriA, Rrr, SaveRestore, Shift, Through,
};
use rabbitizer::opcodes::Opcode;

/// The width of one halfword, the unit of MIPS16e code.
pub const HALFWORD: usize = 2;

/// The general register of each 3-bit register field.
pub(crate) const REGISTERS: [u32; 8] = [16, 17, 2, 3, 4, 5, 6, 7];

/// The T register, which compares write, as MIPS32 numbers it.
pub const T: u32 = 24;

/// The stack pointer and the return address register.
pub(crate) const SP: u32 = 29;

pub(crate) const RA: u32 = 31;
pub(crate) const S0: u32 = 16;

pub(crate) const S2: u32 = 18;

pub(crate) const S8: u32 = 30;

/// The registers that `save` and `restore` name.
pub(crate) const A0: u32 = 4;

/// MIPS16e, in either byte order.
#[derive(Clone, Copy, Debug)]
pub struct Mips16 {
    /// The MIPS32 decoder of the same byte order, which reads what each
    /// instruction translates to.
    pub base: Mips32,
}

impl Mips16 {
    /// MIPS16e in the byte order of `base`.
    pub fn of(base: Mips32) -> Self {
        Self { base }
    }
}

impl Mips16 {
    /// The decoder for a little-endian image.
    pub const LITTLE: Self = Self { base: Mips32::LITTLE };
    /// The decoder for a big-endian image.
    pub const BIG: Self = Self { base: Mips32::BIG };
}

/// A MIPS16e instruction with no MIPS32 twin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// `jalx`, which calls and switches to MIPS32.
    Jalx,
    /// `jrc`, a `jr` with no delay slot.
    Jrc,
    /// `jalrc`, a `jalr` with no delay slot.
    Jalrc,
    /// `save`, which makes the frame.
    Save,
    /// `restore`, which drops it.
    Restore,
}

impl Op {
    /// The name the instruction prints with.
    pub fn name(self) -> &'static str {
        match self {
            Self::Jalx => "jalx",
            Self::Jrc => "jrc",
            Self::Jalrc => "jalrc",
            Self::Save => "save",
            Self::Restore => "restore",
        }
    }
}

/// The MIPS16e operation `insn` does, where it has no MIPS32 twin.
/// The frame that a `save` or `restore` makes or drops: whether it saves,
/// the arguments it stores into the frame of the caller, the size of the
/// frame, and the registers kept in it, lowest address first.
pub struct Frame {
    /// Whether the instruction is a `save`, not a `restore`.
    pub saves: bool,
    /// The arguments `save` stores into the frame of the caller.
    pub arguments: Vec<&'static str>,
    /// The size of the frame, in bytes.
    pub size: u32,
    /// The registers kept in the frame, lowest address first.
    pub kept: Vec<&'static str>,
}

/// The frame of `insn`, where it is a `save` or `restore`.
pub fn frame(insn: &Insn) -> Option<Frame> {
    let order = match insn.opcode {
        crate::arch::Opcode::Mips16(_, order) => order,
        _ => return None,
    };
    let decoded = Mips16::of(Mips32::of(order)).decoded(insn.bytes(), 0, insn.address)?;
    let Reading::Frame { step, size, registers } = decoded.reading else { return None };
    let name = |reg: u32| REGISTER_NAMES[reg as usize];
    Some(Frame {
        saves: step == FrameStep::Save,
        arguments: (A0..A0 + registers.arguments).map(name).collect(),
        size,
        kept: registers.kept.iter().copied().map(name).collect(),
    })
}

/// What one MIPS16e instruction reads as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reading {
    /// The MIPS32 instruction that does the same work.
    Word(u32),
    /// A transfer of control: its text, its kind, the register it goes
    /// through, where it goes through one, and the MIPS32 word that tests
    /// what it tests, where it tests anything.
    Control {
        /// The name it prints with, as `jalrc`.
        name: &'static str,
        /// The operation, as MIPS32 names it where it can.
        decoded: MipsDecoded,
        /// The operands as it prints them.
        operands: String,
        /// How it moves control.
        kind: InsnKind,
        /// The register it goes through, where it goes through one.
        through: Option<u32>,
        /// The MIPS32 word that tests what it tests, where it tests anything.
        test: Option<u32>,
    },
    /// A load of a word, or the forming of an address, relative to the
    /// program counter: `lw rx, imm(pc)` and `addiu rx, pc, imm`.
    PcRelative {
        /// Whether it loads the word, not only forms the address.
        load: bool,
        /// The register it writes.
        dest: u32,
        /// The address it forms.
        address: u64,
    },
    /// `save` or `restore` of the frame.
    Frame {
        /// Whether it makes the frame or drops it.
        step: FrameStep,
        /// The size of the frame, in bytes.
        size: u32,
        /// The registers it stores or loads.
        registers: FrameRegisters,
    },
}

/// Whether a frame instruction makes the frame or drops it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead, DekuBitField)]
#[deku(id_type = "u8", bits = 1, endian = "big", ctx = "_: deku::ctx::Endian")]
pub enum FrameStep {
    /// `save` makes the frame.
    #[deku(id = 1)]
    Save,
    /// `restore` drops it.
    #[deku(id = 0)]
    Restore,
}

/// The registers a `save` stores and a `restore` loads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameRegisters {
    /// How many arguments, from `a0`, a `save` stores into the frame of the
    /// caller. A `restore` loads none of them back.
    arguments: u32,
    /// The registers kept in the new frame, lowest address first. That is
    /// the order of their numbers: `a2`, `a3`, `s0` to `s8`, then `ra`.
    kept: Vec<u32>,
}

impl FrameRegisters {
    /// The registers that `insn` and the layout of its `extend` prefix
    /// name, or `None` for a reserved mix of arguments and statics.
    fn read(insn: SaveRestore, extend: Option<ExtendFrame>) -> Option<Self> {
        // `aregs` splits `a0` to `a3` into arguments, which come first, and
        // statics; two codes name all four of one kind.
        const ALL_ARGUMENTS: u8 = 0b1110;
        const ALL_STATICS: u8 = 0b1011;
        let (xsregs, aregs) =
            extend.map_or((0, 0), |prefix| (prefix.extra_statics, prefix.argument_registers));
        let (arguments, statics) = match aregs {
            ALL_ARGUMENTS => (4, 0),
            ALL_STATICS => (0, 4),
            _ => (u32::from(aregs >> 2), u32::from(aregs & 3)),
        };
        if arguments + statics > 4 {
            return None;
        }
        // `s2` to `s7` are numbered in a row, and the seventh is `s8`.
        let extra = (0..u32::from(xsregs)).map(|index| if index == 6 { S8 } else { S2 + index });
        let kept = (A0 + 4 - statics..A0 + 4)
            .chain(
                [(insn.s0, S0), (insn.s1, S0 + 1)]
                    .into_iter()
                    .filter(|&(kept, _)| kept == Kept::Yes)
                    .map(|(_, reg)| reg),
            )
            .chain(extra)
            .chain((insn.ra == Kept::Yes).then_some(RA))
            .collect();
        Some(Self { arguments, kept })
    }

    /// The operands `save` and `restore` print: the arguments, the size of
    /// the frame, then the registers kept, as `a0, 0x20, s0, s1, ra`.
    fn operands(&self, size: u32) -> String {
        (A0..A0 + self.arguments)
            .map(|reg| REGISTER_NAMES[reg as usize].to_string())
            .chain([format!("{size:#x}")])
            .chain(self.kept.iter().map(|&reg| REGISTER_NAMES[reg as usize].to_string()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The decoded fields of one instruction, and its width.
pub struct Read {
    /// What the instruction reads as.
    pub reading: Reading,
    width: usize,
}

/// One MIPS32 word of the I format.
pub(crate) fn immediate(op: u32, rs: u32, rt: u32, value: i64) -> u32 {
    op << 26 | rs << 21 | rt << 16 | (value as u32 & 0xffff)
}

/// One MIPS32 word of the R format.
pub fn register(rs: u32, rt: u32, rd: u32, sa: u32, funct: u32) -> u32 {
    rs << 21 | rt << 16 | rd << 11 | sa << 6 | funct
}

/// Sign-extend the low `bits` of `value`.
pub(crate) fn signed(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    (i64::from(value) << shift) >> shift
}

/// Decode the instruction `first`, with the halfword after it, `next`, at
/// `address`.
pub(crate) fn decode_halfwords(first: u16, next: Option<u16>, address: u64) -> Option<Read> {
    match Encoded::of(first, next)? {
        // `jal` and `jalx` take two halfwords: a 26-bit target, in words.
        Encoded::Jal(jal) => {
            let target = (address + 4) & !0x0fff_ffff | u64::from(jal.target()) << 2;
            let (name, decoded) = match jal.mode {
                JumpMode::Exchange => ("jalx", MipsDecoded::Mips16(Op::Jalx)),
                JumpMode::Stay => ("jal", MipsDecoded::Rabbitizer(Opcode::core_jal)),
            };
            let operands = format!("{target:#x}");
            let kind = InsnKind::Call { target: Some(target) };
            let reading =
                Reading::Control { name, decoded, operands, kind, through: None, test: None };
            Some(Read { reading, width: 4 })
        }
        Encoded::Extend(extend) => {
            let reading = read(extend.insn, Some(extend.prefix), address)?;
            Some(Read { reading, width: 4 })
        }
        encoded => Some(Read { reading: reading(encoded, first, None, address)?, width: HALFWORD }),
    }
}

/// Read one 16-bit instruction, widened by `extend` where an `extend`
/// prefix came first.
pub(crate) fn read(insn: u16, extend: Option<Prefix>, address: u64) -> Option<Reading> {
    let widened = extend.map(|prefix| (prefix, prefix.immediate(insn)));
    reading(Encoded::of(insn, None)?, insn, widened, address)
}

/// What the 16-bit instruction `encoded`, read from the halfword `insn`,
/// reads as, widened by `extend` where an `extend` prefix came first: the
/// prefix itself, and the 16-bit constant the two make.
#[allow(clippy::too_many_lines)]
fn reading(
    encoded: Encoded,
    insn: u16,
    extend: Option<(Prefix, u32)>,
    address: u64,
) -> Option<Reading> {
    let gpr = |index: u8| REGISTERS[usize::from(index)];
    let wide = extend.map(|(_, imm16)| signed(imm16, 16));
    let wide_unsigned = extend.map(|(_, imm16)| i64::from(imm16));
    // A branch counts from the instruction after it, which is 2 bytes on,
    // or 4 with an `extend`.
    let next = address + if extend.is_some() { 4 } else { 2 };
    let branch = |offset: i64, (name, opcode): (&'static str, Opcode), test: Option<u32>| {
        let conditional = test.is_some();
        let target = next.wrapping_add_signed(offset << 1);
        let distance = target.wrapping_sub(address) as i64;
        let place =
            if distance < 0 { format!("$-{:#x}", -distance) } else { format!("$+{distance:#x}") };
        let (operands, kind) = match test {
            Some(word) if conditional => {
                let tested = REGISTER_NAMES[(word >> 21 & 0x1f) as usize];
                (format!("{tested}, {place}"), InsnKind::Branch { target: Some(target) })
            }
            _ => (place, InsnKind::Jump { target: Some(target) }),
        };
        Reading::Control {
            name,
            decoded: MipsDecoded::Rabbitizer(opcode),
            operands,
            kind,
            through: None,
            test,
        }
    };
    // The 3-operand form of a 2-operand MIPS16e instruction.
    let word = |value: u32| Some(Reading::Word(value));
    // The constant of an instruction: the one `extend` widens it to, or its
    // own, in units of `scale` bytes.
    let constant = |imm: u8, scale: u32| wide.unwrap_or(i64::from(u32::from(imm) << scale));
    let load_store = |op: u32, Rri { rx, ry, imm }: Rri, scale: u32| {
        word(immediate(op, gpr(rx), gpr(ry), constant(imm, scale)))
    };
    let pc_relative = |load: bool, Ri { rx, imm }: Ri| {
        Some(Reading::PcRelative {
            load,
            dest: gpr(rx),
            address: (address & !3).wrapping_add_signed(constant(imm, 2)),
        })
    };

    match encoded {
        // `addiu rx, sp, imm`: a frame address.
        Encoded::AddiuSp(Ri { rx, imm }) => word(immediate(0x09, SP, gpr(rx), constant(imm, 2))),
        Encoded::AddiuPc(ri) => pc_relative(false, ri),
        Encoded::B(I { imm }) => {
            let offset = wide.unwrap_or_else(|| signed(u32::from(imm), 11));
            Some(branch(offset, ("b", Opcode::core_b), None))
        }
        Encoded::Beqz(Ri { rx, imm }) | Encoded::Bnez(Ri { rx, imm }) => {
            let offset = wide.unwrap_or_else(|| signed(u32::from(imm), 8));
            let (name, opcode) = if matches!(encoded, Encoded::Beqz(_)) {
                (("beqz", Opcode::core_beqz), 0x04)
            } else {
                (("bnez", Opcode::core_bnez), 0x05)
            };
            Some(branch(offset, name, Some(immediate(opcode, gpr(rx), 0, 0))))
        }
        Encoded::Shift(Shift { rx, ry, amount, function }) => {
            let sa = match extend {
                Some((prefix, _)) => u32::from(prefix.layout::<ExtendShift>().amount),
                None => match amount {
                    0 => 8,
                    amount => u32::from(amount),
                },
            };
            let funct = match function {
                0b00 => 0x00,
                0b10 => 0x02,
                0b11 => 0x03,
                _ => return None,
            };
            word(register(0, gpr(ry), gpr(rx), sa, funct))
        }
        // `addiu ry, rx, imm4`, or 15 bits extended.
        Encoded::RriA(RriA { rx, ry, function: 0, imm }) => {
            let value = match extend {
                Some((prefix, _)) => signed(prefix.layout::<ExtendAddiu>().immediate(imm), 15),
                None => signed(u32::from(imm), 4),
            };
            word(immediate(0x09, gpr(rx), gpr(ry), value))
        }
        Encoded::Addiu8(Ri { rx, imm }) => {
            let rx = gpr(rx);
            word(immediate(0x09, rx, rx, wide.unwrap_or_else(|| signed(u32::from(imm), 8))))
        }
        Encoded::Slti(Ri { rx, imm }) => word(immediate(0x0a, gpr(rx), T, constant(imm, 0))),
        Encoded::Sltiu(Ri { rx, imm }) => word(immediate(0x0b, gpr(rx), T, constant(imm, 0))),
        Encoded::I8(i8) => match i8 {
            I8::Bteqz(imm) | I8::Btnez(imm) => {
                let offset = wide.unwrap_or_else(|| signed(u32::from(imm), 8));
                let (name, opcode) = if matches!(i8, I8::Bteqz(_)) {
                    (("beqz", Opcode::core_beqz), 0x04)
                } else {
                    (("bnez", Opcode::core_bnez), 0x05)
                };
                Some(branch(offset, name, Some(immediate(opcode, T, 0, 0))))
            }
            I8::SwRaSp(imm) => word(immediate(0x2b, SP, RA, constant(imm, 2))),
            I8::AdjSp(imm) => word(immediate(
                0x09,
                SP,
                SP,
                wide.unwrap_or_else(|| signed(u32::from(imm), 8) << 3),
            )),
            I8::SaveRestore(frame) => {
                let low = u32::from(frame.frame_size);
                let size = match extend {
                    Some((prefix, _)) => {
                        (u32::from(prefix.layout::<ExtendFrame>().frame_size_7_4) << 4 | low) * 8
                    }
                    None if low == 0 => 128,
                    None => low * 8,
                };
                let registers =
                    FrameRegisters::read(frame, extend.map(|(prefix, _)| prefix.layout()))?;
                Some(Reading::Frame { step: frame.step, size, registers })
            }
            I8::Mov32R(mov) if extend.is_none() => {
                // `move r32, rz`, which MIPS32 spells `or r32, rz, zero`,
                // and `move zero, s0` is the `nop`.
                let r32 = mov.r32();
                if r32 == 0 && mov.rz == 0 {
                    return word(0);
                }
                word(register(gpr(mov.rz), 0, r32, 0, 0x25))
            }
            I8::MovR32(mov) if extend.is_none() => {
                word(register(u32::from(mov.r32), 0, gpr(mov.ry), 0, 0x25))
            }
            _ => None,
        },
        // `li rx, imm`, zero-extended.
        Encoded::Li(Ri { rx, imm }) => {
            word(immediate(0x0d, 0, gpr(rx), wide_unsigned.unwrap_or(i64::from(imm))))
        }
        // `cmpi rx, imm`: T is `rx ^ imm`.
        Encoded::Cmpi(Ri { rx, imm }) => {
            word(immediate(0x0e, gpr(rx), T, wide_unsigned.unwrap_or(i64::from(imm))))
        }
        Encoded::Lb(rri) => load_store(0x20, rri, 0),
        Encoded::Lh(rri) => load_store(0x21, rri, 1),
        Encoded::LwSp(Ri { rx, imm }) => word(immediate(0x23, SP, gpr(rx), constant(imm, 2))),
        Encoded::Lw(rri) => load_store(0x23, rri, 2),
        Encoded::Lbu(rri) => load_store(0x24, rri, 0),
        Encoded::Lhu(rri) => load_store(0x25, rri, 1),
        Encoded::LwPc(ri) => pc_relative(true, ri),
        Encoded::Sb(rri) => load_store(0x28, rri, 0),
        Encoded::Sh(rri) => load_store(0x29, rri, 1),
        Encoded::SwSp(Ri { rx, imm }) => word(immediate(0x2b, SP, gpr(rx), constant(imm, 2))),
        Encoded::Sw(rri) => load_store(0x2b, rri, 2),
        Encoded::Rrr(Rrr { rx, ry, rz, function }) if extend.is_none() => {
            let (rx, ry, rz) = (gpr(rx), gpr(ry), gpr(rz));
            match function {
                0b01 => word(register(rx, ry, rz, 0, 0x21)),
                0b11 => word(register(rx, ry, rz, 0, 0x23)),
                _ => None,
            }
        }
        Encoded::Rr(rr) if extend.is_none() => read_rr(rr, insn),
        _ => None,
    }
}

/// Read an instruction of the RR group, which names two registers, from
/// its fields `rr` and its halfword `insn`.
fn read_rr(rr: Rr, insn: u16) -> Option<Reading> {
    let word = |value: u32| Some(Reading::Word(value));
    let (rx, ry) = (REGISTERS[usize::from(rr.rx)], REGISTERS[usize::from(rr.ry)]);
    match rr.function {
        0b00000 => {
            // `jr`, `jalr` and their compact forms, which have no delay slot.
            let jump: JumpRegister = format::read(&insn.to_be_bytes())?;
            let target = match jump.through {
                Through::ReturnAddress => RA,
                Through::Rx => rx,
            };
            let name = REGISTER_NAMES[target as usize];
            let plain = match jump.slot {
                DelaySlot::Compact => ("jrc", MipsDecoded::Mips16(Op::Jrc)),
                DelaySlot::Filled => ("jr", MipsDecoded::Rabbitizer(Opcode::core_jr)),
            };
            let ((name, decoded), operands, kind) = match (jump.link, jump.through) {
                (Link::Jump, Through::ReturnAddress) => (plain, name.to_string(), InsnKind::Return),
                (Link::Jump, Through::Rx) => {
                    (plain, name.to_string(), InsnKind::Jump { target: None })
                }
                (Link::Call, Through::Rx) => {
                    let call = match jump.slot {
                        DelaySlot::Compact => ("jalrc", MipsDecoded::Mips16(Op::Jalrc)),
                        DelaySlot::Filled => ("jalr", MipsDecoded::Rabbitizer(Opcode::core_jalr)),
                    };
                    (call, format!("ra, {name}"), InsnKind::Call { target: None })
                }
                (Link::Call, Through::ReturnAddress) => return None,
            };
            Some(Reading::Control {
                name,
                decoded,
                operands,
                kind,
                through: Some(target),
                test: None,
            })
        }
        0b00001 => word(0x0000_000d),
        0b00010 => word(register(rx, ry, T, 0, 0x2a)),
        0b00011 => word(register(rx, ry, T, 0, 0x2b)),
        0b00100 => word(register(rx, ry, ry, 0, 0x04)),
        0b00101 => word(0x0000_000d),
        0b00110 => word(register(rx, ry, ry, 0, 0x06)),
        0b00111 => word(register(rx, ry, ry, 0, 0x07)),
        0b01010 => word(register(rx, ry, T, 0, 0x26)),
        0b01011 => word(register(0, ry, rx, 0, 0x23)),
        0b01100 => word(register(rx, ry, rx, 0, 0x24)),
        0b01101 => word(register(rx, ry, rx, 0, 0x25)),
        0b01110 => word(register(rx, ry, rx, 0, 0x26)),
        0b01111 => word(register(ry, 0, rx, 0, 0x27)),
        0b10000 => word(register(0, 0, rx, 0, 0x10)),
        0b10010 => word(register(0, 0, rx, 0, 0x12)),
        // `cnvt`, which names its operation in the second register field.
        0b10001 => match rr.ry {
            0b000 => word(immediate(0x0c, rx, rx, 0xff)),
            0b001 => word(immediate(0x0c, rx, rx, 0xffff)),
            0b100 => word(0x1f << 26 | rx << 16 | rx << 11 | 0x10 << 6 | 0x20),
            0b101 => word(0x1f << 26 | rx << 16 | rx << 11 | 0x18 << 6 | 0x20),
            _ => None,
        },
        0b11000 => word(register(rx, ry, 0, 0, 0x18)),
        0b11001 => word(register(rx, ry, 0, 0, 0x19)),
        0b11010 => word(register(rx, ry, 0, 0, 0x1a)),
        0b11011 => word(register(rx, ry, 0, 0, 0x1b)),
        _ => None,
    }
}

/// The ABI names of the general registers, as `rabbitizer` prints them.
pub(crate) const REGISTER_NAMES: [&str; 32] = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
    "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "s8",
    "ra",
];

impl Mips16 {
    /// The halfword at `offset` of `code`, in this byte order.
    pub fn halfword(self, code: &[u8], offset: usize) -> Option<u16> {
        let bytes: [u8; 2] = code.get(offset..offset + HALFWORD)?.try_into().ok()?;
        Some(self.base.read_halfword(bytes))
    }

    /// Decode at `offset`, with what it reads as.
    pub fn decoded(&self, code: &[u8], offset: usize, address: u64) -> Option<Read> {
        let first = self.halfword(code, offset)?;
        decode_halfwords(first, self.halfword(code, offset + HALFWORD), address)
    }

    /// The MIPS32 instruction a word translates to, at `address`.
    fn as_mips32(&self, word: u32, address: u64) -> Option<Insn> {
        self.base
            .read(&self.base.word_bytes(word), 0, address, Printing::Skip)
            .ok()
            .map(|(insn, _)| insn)
    }

    /// The instruction at `offset` of `code`, which starts at `address`,
    /// and its text where `printing` asks for it.
    pub fn read(
        &self,
        code: &[u8],
        offset: usize,
        address: u64,
        printing: Printing,
    ) -> Result<(Insn, String), DecodeError> {
        let first = self.halfword(code, offset).ok_or(DecodeError::Truncated)?;
        let insn_address = address + offset as u64;
        let unknown = |width: usize| {
            let bytes = &code[offset..offset + width];
            let insn = Insn::new(
                insn_address,
                bytes,
                InsnKind::Unknown,
                crate::arch::Opcode::Unread(crate::arch::InstructionSet::Mips16(self.base.order())),
            );
            let text = printing.text(|| {
                let raw: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
                format!("(unknown) {raw}")
            });
            (insn, text)
        };
        let Some(decoded) = self.decoded(code, offset, insn_address) else {
            // A prefix or a `jal` whose second halfword is cut off, or an
            // encoding MIPS16e leaves reserved, is stepped over whole.
            let wide =
                matches!(first >> 11, 0b00011 | 0b11110) && code.len() >= offset + 2 * HALFWORD;
            return Ok(unknown(if wide { 2 * HALFWORD } else { HALFWORD }));
        };
        let bytes = &code[offset..offset + decoded.width];
        let order = self.base.order();
        // Every instruction says MIPS16e decoded it, so a rule that MIPS32
        // shares lifts it as MIPS16e.
        let (kind, decoded, text) = match decoded.reading {
            Reading::Word(word) => {
                // The text and the opcode are those of the MIPS32 twin, and
                // the bytes are the MIPS16e ones, which the lift reads.
                let word = self.base.word_bytes(word);
                let (twin, text) = self.base.read(&word, 0, insn_address, printing)?;
                let crate::arch::Opcode::Mips(decoded, _) = twin.opcode else {
                    let opcode =
                        crate::arch::Opcode::Unread(crate::arch::InstructionSet::Mips16(order));
                    return Ok((Insn::new(insn_address, bytes, twin.kind, opcode), text));
                };
                (twin.kind, decoded, text)
            }
            Reading::Control { name, decoded, operands, kind, .. } => {
                (kind, decoded, printing.text(|| format!("{name} {operands}")))
            }
            Reading::PcRelative { load, dest, address: at } => {
                let text = printing.text(|| {
                    let register = REGISTER_NAMES[dest as usize];
                    match load {
                        true => format!("lw {register}, {at:#x}(pc)"),
                        false => format!("addiu {register}, pc, {at:#x}"),
                    }
                });
                // A load or an add from `pc` does what the MIPS32 one does
                // from another register.
                let opcode = if load { Opcode::core_lw } else { Opcode::core_addiu };
                (InsnKind::Normal, MipsDecoded::Rabbitizer(opcode), text)
            }
            Reading::Frame { step, size, registers } => {
                let op = match step {
                    FrameStep::Save => Op::Save,
                    FrameStep::Restore => Op::Restore,
                };
                let text = printing.text(|| format!("{} {}", op.name(), registers.operands(size)));
                (InsnKind::Normal, MipsDecoded::Mips16(op), text)
            }
        };
        let opcode = crate::arch::Opcode::Mips16(decoded, order);
        Ok((Insn::new(insn_address, bytes, kind, opcode), text))
    }
}

impl Decoder for Mips16 {
    fn operation_name(&self, insn: &Insn) -> CompactString {
        self.base.operation_name(insn)
    }

    fn decode(&self, code: &[u8], offset: usize, address: u64) -> Result<Insn, DecodeError> {
        self.read(code, offset, address, Printing::Skip).map(|(insn, _)| insn)
    }

    fn triple(&self) -> &'static str {
        self.base.triple()
    }

    fn instruction_width(&self) -> usize {
        HALFWORD
    }

    /// `jal`, `jalx`, `jr` and `jalr` run the instruction after them first;
    /// a branch and the compact jumps do not.
    fn delay_slots(&self, insn: &Insn) -> usize {
        let has_slot = matches!(
            decoded(insn),
            Some(
                MipsDecoded::Rabbitizer(Opcode::core_jal | Opcode::core_jr | Opcode::core_jalr)
                    | MipsDecoded::Mips16(Op::Jalx)
            )
        );
        usize::from(has_slot)
    }

    fn pointer_width(&self) -> usize {
        self.base.pointer_width()
    }

    fn read_pointer(&self, bytes: &[u8]) -> u64 {
        self.base.read_pointer(bytes)
    }

    fn lift(&self, insn: &Insn) -> Option<il::Lifted> {
        let word = insn.bytes();
        if insn.kind == InsnKind::Unknown {
            return None;
        }
        let decoded = self.decoded(word, 0, insn.address)?;
        match decoded.reading {
            Reading::Word(word) => {
                let translated = self.as_mips32(word, insn.address)?;
                self.base.lift(&translated)
            }
            Reading::Control { test: Some(word), .. } => {
                let translated = self.as_mips32(word, insn.address)?;
                self.base.lift(&translated)
            }
            Reading::Control { kind, through, .. } => {
                let op = match kind {
                    InsnKind::Call { .. } => il::Op::Call,
                    InsnKind::Return => il::Op::Return,
                    _ => il::Op::Jump,
                };
                let mut lifted = il::Lifted { op, ..Default::default() };
                if matches!(kind, InsnKind::Call { .. }) {
                    lifted.writes.insert(il::Reg::General(RA as u8));
                }
                // `jr`, `jalr` and their compact forms go through a register.
                let target = match through {
                    Some(number) => {
                        let reg = il::Reg::General(number as u8);
                        lifted.reads.insert(reg);
                        il::Operand::Reg(reg)
                    }
                    None => il::Operand::Target(None),
                };
                lifted.operands = [target].into_iter().collect();
                Some(lifted)
            }
            Reading::PcRelative { load, dest, address } => {
                let mut lifted = il::Lifted::default();
                let dest = il::Reg::General(dest as u8);
                lifted.writes.insert(dest);
                lifted.op = if load { il::Op::Load } else { il::Op::Address };
                let source = if load {
                    lifted.memory = Some(il::MemoryAccess {
                        kind: il::AccessKind::Load,
                        width: Some(il::Width::Bits32),
                    });
                    il::Operand::memory(Some(il::Reg::ProgramCounter), None)
                } else {
                    il::Operand::Target(Some(address.wrapping_sub(insn.address) as i64))
                };
                lifted.operands = [il::Operand::Reg(dest), source].into_iter().collect();
                Some(lifted)
            }
            Reading::Frame { .. } => None,
        }
    }

    /// The names are those of the MIPS32 twin, but for a target, which
    /// counts from the MIPS16e instruction, and the forms MIPS16e alone
    /// has.
    fn lift_named(&self, insn: &Insn) -> Option<il::Named> {
        use compact_str::{CompactString, format_compact};
        if insn.kind == InsnKind::Unknown {
            return None;
        }
        let lifted = self.lift(insn)?;
        let decoded = self.decoded(insn.bytes(), 0, insn.address)?;
        let target = match insn.kind {
            InsnKind::Call { target } | InsnKind::Jump { target } | InsnKind::Branch { target } => {
                target
            }
            _ => None,
        };
        let place = target.map(|target| il::target_name(target.wrapping_sub(insn.address) as i64));
        let names: il::Names = match decoded.reading {
            Reading::Word(word) | Reading::Control { test: Some(word), .. } => {
                let translated = self.as_mips32(word, insn.address)?;
                let twin = self.base.lift_named(&translated)?;
                twin.lifted
                    .operands
                    .iter()
                    .zip(twin.names)
                    .map(|(operand, name)| match (operand, &place) {
                        (il::Operand::Target(_), Some(place)) => place.clone(),
                        _ => name,
                    })
                    .collect()
            }
            Reading::Control { through: Some(number), .. } => {
                [CompactString::from(REGISTER_NAMES[number as usize])].into_iter().collect()
            }
            // `jal` and `jalx` print where they go; a branch prints how far.
            Reading::Control { kind: InsnKind::Call { target: Some(target) }, .. } => {
                [format_compact!("{target:#x}")].into_iter().collect()
            }
            Reading::Control { .. } => place.into_iter().collect(),
            Reading::PcRelative { load, dest, address } => {
                let source = match load {
                    true => format_compact!("[pc + {address:#x}]"),
                    false => format_compact!("{address:#x}"),
                };
                [CompactString::from(REGISTER_NAMES[dest as usize]), source].into_iter().collect()
            }
            Reading::Frame { .. } => return None,
        };
        Some(il::Named { lifted, names, write_back: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The text of the halfwords `values`, big endian, at `address`.
    fn text(values: &[u16], address: u64) -> String {
        let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
        let insn = Mips16::BIG.decode(&code, 0, address).expect("decodes");
        insn.to_string().trim_end().to_string()
    }

    /// Words from GCC 14 at `-mips16`, as `objdump` reads them.
    #[test]
    fn reads_as_the_mips32_instruction_of_the_same_work() {
        assert_eq!(text(&[0x3382], 0), "srl v1, a0, 8"); // srl v1,a0,8
        assert_eq!(text(&[0x3362], 0), "srl v1, v1, 8"); // srl v1,8
        assert_eq!(text(&[0x6744], 0), "or v0, a0, zero"); // move v0,a0
        assert_eq!(text(&[0x653b], 0), "or t9, v1, zero"); // move t9,v1
        assert_eq!(text(&[0xd303], 0), "sw v1, 0xC(sp)"); // sw v1,12(sp)
        assert_eq!(text(&[0xa460], 0), "lbu v1, 0x0(a0)"); // lbu v1,0(a0)
        assert_eq!(text(&[0x4c10], 0), "addiu a0, a0, 0x10"); // addiu a0,16
        assert_eq!(text(&[0xe34d], 0), "addu v1, v1, v0"); // addu v1,v0
        assert_eq!(text(&[0x6500], 0), "nop");
    }

    #[test]
    fn an_extend_widens_the_constant() {
        // addiu v1,a1,5552
        assert_eq!(text(&[0xf5b2, 0x4560], 0), "addiu v1, a1, 0x15B0");
        // lbu s1,-6(a0)
        assert_eq!(text(&[0xf7ff, 0xa43a], 0), "lbu s1, -0x6(a0)");
        // addiu a1,-5552
        assert_eq!(text(&[0xf25d, 0x4d10], 0), "addiu a1, a1, -0x15B0");
    }

    #[test]
    fn a_compare_writes_t8_and_a_branch_on_t_reads_it() {
        assert_eq!(text(&[0x7601], 0), "xori t8, a2, 0x1"); // cmpi a2,1
        assert_eq!(text(&[0x5e10], 0), "sltiu t8, a2, 0x10"); // sltiu a2,16
        // bteqz 198 at 0xe
        let code: Vec<u8> =
            [0xf0c0_u16, 0x6003].iter().flat_map(|value| value.to_be_bytes()).collect();
        let insn = Mips16::BIG.decode(&code, 0, 0xe).expect("decodes");
        assert_eq!(insn.kind, InsnKind::Branch { target: Some(0x198) });
        assert_eq!(crate::arch::printed_name(&insn), "beqz");
        assert!(crate::arch::printed_operands(&insn).starts_with("t8, "));
    }

    #[test]
    fn a_branch_counts_from_the_instruction_after_it() {
        // beqz a1,2fa at 0x12, extended
        let code: Vec<u8> =
            [0xf160_u16, 0x2512].iter().flat_map(|value| value.to_be_bytes()).collect();
        let insn = Mips16::BIG.decode(&code, 0, 0x12).expect("decodes");
        assert_eq!(insn.kind, InsnKind::Branch { target: Some(0x2fa) });
        assert_eq!(insn.bytes_len, 4);
    }

    /// Each encoding as GNU `as` 2.44 assembles the `binutils` text.
    #[test]
    fn save_and_restore_name_the_registers_they_move() {
        let cases: [(&[u16], &str, &str); 15] = [
            (&[0x64f4], "save 32,ra,s0-s1", "save 0x20, s0, s1, ra"),
            (&[0xf004, 0x64c4], "save a0,32,ra", "save a0, 0x20, ra"),
            (&[0xf001, 0x64c4], "save 32,ra,a3", "save 0x20, a3, ra"),
            (&[0xf005, 0x64c4], "save a0,32,ra,a3", "save a0, 0x20, a3, ra"),
            (&[0xf008, 0x64c4], "save a0-a1,32,ra", "save a0, a1, 0x20, ra"),
            (&[0xf009, 0x64c4], "save a0-a1,32,ra,a3", "save a0, a1, 0x20, a3, ra"),
            (&[0xf00c, 0x64c4], "save a0-a2,32,ra", "save a0, a1, a2, 0x20, ra"),
            (&[0xf00e, 0x64c4], "save a0-a3,32,ra", "save a0, a1, a2, a3, 0x20, ra"),
            (&[0xf00b, 0x64c4], "save 32,ra,a0-a3", "save 0x20, a0, a1, a2, a3, ra"),
            (&[0xf002, 0x64c4], "save 32,ra,a2-a3", "save 0x20, a2, a3, ra"),
            (&[0xf003, 0x64c4], "save 32,ra,a1-a3", "save 0x20, a1, a2, a3, ra"),
            (&[0xf006, 0x64c4], "save a0,32,ra,a2-a3", "save a0, 0x20, a2, a3, ra"),
            (
                &[0xf700, 0x64f4],
                "save 32,ra,s0-s8",
                "save 0x20, s0, s1, s2, s3, s4, s5, s6, s7, s8, ra",
            ),
            (&[0xf100, 0x64f4], "save 32,ra,s0-s2", "save 0x20, s0, s1, s2, ra"),
            (&[0xf002, 0x6474], "restore 32,ra,s0-s1,a2-a3", "restore 0x20, a2, a3, s0, s1, ra"),
        ];
        for (halfwords, binutils, shown) in cases {
            assert_eq!(text(halfwords, 0), shown, "{binutils}");
        }
    }

    #[test]
    fn a_reserved_mix_of_arguments_and_statics_is_no_save() {
        // `aregs` 0b1111 names three arguments and three statics of four.
        let code: Vec<u8> = [0xf00f_u16, 0x64c4].iter().flat_map(|h| h.to_be_bytes()).collect();
        assert_eq!(
            Mips16::BIG.decode(&code, 0, 0).map(|insn| insn.kind).ok(),
            Some(InsnKind::Unknown)
        );
    }

    #[test]
    fn a_return_and_a_call_move_control() {
        let decode = |values: &[u16]| {
            let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
            Mips16::BIG.decode(&code, 0, 0x400).expect("decodes")
        };
        let jr_ra = decode(&[0xe820]);
        assert_eq!(jr_ra.kind, InsnKind::Return);
        assert_eq!(Mips16::BIG.delay_slots(&jr_ra), 1);
        let jrc_ra = decode(&[0xe8a0]);
        assert_eq!(jrc_ra.kind, InsnKind::Return);
        assert_eq!(Mips16::BIG.delay_slots(&jrc_ra), 0);
        // jal to 0x1000, which stays MIPS16e
        let jal = decode(&[0x1800, 0x0400]);
        assert_eq!(jal.kind, InsnKind::Call { target: Some(0x1000) });
        assert_eq!(jal.bytes_len, 4);
    }

    #[test]
    fn a_compare_and_its_branch_lift_as_a_guard() {
        let lift = |values: &[u16], address: u64| {
            let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
            let insn = Mips16::BIG.decode(&code, 0, address).expect("decodes");
            Some(Mips16::BIG.lift(&insn).expect("lifts"))
        };
        // sltiu a2,16 then btnez
        let body = [lift(&[0x5e10], 0), lift(&[0x6105], 2)];
        let guards = il::find_guards(&body);
        assert_eq!(guards.len(), 1);
    }

    /// FNV-1a over the readings of every halfword, of every `extend` prefix
    /// before 256 halfwords of each major opcode, and of `jal` and `jalx`
    /// with four second halfwords: a fingerprint of what the decoder reads.
    fn fingerprint() -> u64 {
        const PATTERNS: [u16; 8] = [0, 0x7ff, 0x555, 0x2aa, 0x0f0, 0x70f, 0x123, 0x4ce];
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        let mut add = |read: Option<Read>| {
            let text = format!("{:?}", read.map(|read| (read.reading, read.width)));
            for byte in text.bytes() {
                hash = (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
            }
        };
        for first in 0..=u16::MAX {
            add(decode_halfwords(first, None, 0x1000));
        }
        for prefix in 0..0x800u16 {
            for op in 0..32u16 {
                for pattern in PATTERNS {
                    add(decode_halfwords(0xf000 | prefix, Some(op << 11 | pattern), 0x1000));
                }
            }
        }
        for target in 0..0x800u16 {
            for second in [0, 0xffff, 0x1234, 0x8001] {
                add(decode_halfwords(0x1800 | target, Some(second), 0x1000));
            }
        }
        hash
    }

    #[test]
    fn what_each_halfword_reads_as_is_locked() {
        assert_eq!(fingerprint(), 2_351_915_729_990_541_381);
    }

    #[test]
    fn decoding_any_halfwords_never_panics() {
        bolero::check!().with_type::<(u16, u16)>().for_each(|&(first, second)| {
            let code: Vec<u8> =
                [first, second].iter().flat_map(|value| value.to_be_bytes()).collect();
            for arch in [Mips16::BIG, Mips16::LITTLE] {
                let insn = arch.decode(&code, 0, 0x1000).expect("two halfwords decode");
                assert!(insn.bytes_len == 2 || insn.bytes_len == 4);
                let _ = arch.lift(&insn);
            }
        });
    }
}
