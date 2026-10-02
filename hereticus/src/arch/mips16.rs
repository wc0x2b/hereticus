//! MIPS16e, the compressed instruction set of MIPS32.
//!
//! OpenWrt builds much of its MIPS user space as MIPS16e: about half of the
//! binaries of the images the tests download hold such code. A function
//! runs in MIPS16e where bit 0 of its address is set, as a Thumb-2 function
//! does on ARM, and `jalx` switches between the two sets.
//!
//! An instruction is 16 bits, or 32 with an `extend` prefix that widens its
//! constant, or a `jal`. Each reads here as the MIPS32 instruction it does
//! the work of, so that the MIPS32 decoder names it and the MIPS32 lifter
//! lifts it: `addiu v0, 1` reads as `addiu v0, v0, 0x1`. MIPS16e keeps
//! the result of a compare in the T register, which is `t8`, so `slt a0, a1`
//! reads as `slt t8, a0, a1` and `bteqz` as `beqz t8`. What MIPS32 has no
//! instruction for keeps its own form: the branches, whose offsets differ,
//! the loads relative to the program counter, and `save` and `restore`.
//!
//! `rabbitizer` reads no MIPS16e, so this module decodes it from the
//! encodings of the MIPS16e ASE manual.

use super::mips::Mips32;
use super::{Arch, CallTarget, DecodeError, Insn, InsnKind, JumpTable, Memory};
use crate::address::{AddressSpace, ConstantKind, Contents};
use crate::il;
use compact_str::CompactString;

/// The width of one halfword, the unit of MIPS16e code.
const HALFWORD: usize = 2;

/// The general register of each 3-bit register field.
const REGISTERS: [u32; 8] = [16, 17, 2, 3, 4, 5, 6, 7];

/// The T register, which compares write, as MIPS32 numbers it.
const T: u32 = 24;
/// The stack pointer and the return address register.
const SP: u32 = 29;
const RA: u32 = 31;

/// MIPS16e, in either byte order.
#[derive(Clone, Copy, Debug)]
pub struct Mips16 {
    /// The MIPS32 decoder of the same byte order, which reads what each
    /// instruction translates to.
    base: Mips32,
}

impl Mips16 {
    /// The decoder for a little-endian image.
    pub const LITTLE: Self = Self { base: Mips32::LITTLE };
    /// The decoder for a big-endian image.
    pub const BIG: Self = Self { base: Mips32::BIG };
}

/// What one MIPS16e instruction reads as.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Reading {
    /// The MIPS32 instruction that does the same work.
    Word(u32),
    /// A transfer of control: its text, its kind, and the MIPS32 word that
    /// tests what it tests, where it tests anything.
    Control { mnemonic: &'static str, operands: String, kind: InsnKind, test: Option<u32> },
    /// A load of a word, or the forming of an address, relative to the
    /// program counter: `lw rx, imm(pc)` and `addiu rx, pc, imm`.
    PcRelative { load: bool, dest: u32, address: u64 },
    /// `save` or `restore` of the frame.
    Frame { save: bool, size: u32 },
}

/// The decoded fields of one instruction, and its width.
struct Decoded {
    reading: Reading,
    width: usize,
}

/// One MIPS32 word of the I format.
fn immediate(op: u32, rs: u32, rt: u32, value: i64) -> u32 {
    op << 26 | rs << 21 | rt << 16 | (value as u32 & 0xffff)
}

/// One MIPS32 word of the R format.
fn register(rs: u32, rt: u32, rd: u32, sa: u32, funct: u32) -> u32 {
    rs << 21 | rt << 16 | rd << 11 | sa << 6 | funct
}

/// Sign-extend the low `bits` of `value`.
fn signed(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    (i64::from(value) << shift) >> shift
}

/// Decode the instruction `first`, with the halfword after it, `next`, at
/// `address`.
fn decode_halfwords(first: u16, next: Option<u16>, address: u64) -> Option<Decoded> {
    let op = u32::from(first >> 11);
    // `jal` and `jalx` take two halfwords: a 26-bit target, in words.
    if op == 0b00011 {
        let second = u32::from(next?);
        let first = u32::from(first);
        let target26 = (first & 0x1f) << 21 | (first >> 5 & 0x1f) << 16 | second;
        let target = (address + 4) & !0x0fff_ffff | u64::from(target26) << 2;
        let exchange = first >> 10 & 1 == 1;
        let mnemonic = if exchange { "jalx" } else { "jal" };
        let operands = format!("{target:#x}");
        let kind = InsnKind::Call { target: Some(target) };
        return Some(Decoded {
            reading: Reading::Control { mnemonic, operands, kind, test: None },
            width: 4,
        });
    }
    if op == 0b11110 {
        let extend = u32::from(first);
        let insn = next?;
        let imm16 = (extend & 0x1f) << 11 | (extend >> 5 & 0x3f) << 5 | u32::from(insn) & 0x1f;
        let reading = read(insn, Some((extend, imm16)), address)?;
        return Some(Decoded { reading, width: 4 });
    }
    Some(Decoded { reading: read(first, None, address)?, width: HALFWORD })
}

/// Read one 16-bit instruction, widened by `extend` where an `extend`
/// prefix came first: the prefix itself, and the 16-bit constant the two
/// make.
#[allow(clippy::too_many_lines)]
fn read(insn: u16, extend: Option<(u32, u32)>, address: u64) -> Option<Reading> {
    let h = u32::from(insn);
    let op = h >> 11;
    let rx = REGISTERS[(h >> 8 & 7) as usize];
    let ry = REGISTERS[(h >> 5 & 7) as usize];
    let rz = REGISTERS[(h >> 2 & 7) as usize];
    let imm8 = h & 0xff;
    let imm5 = h & 0x1f;
    let wide = extend.map(|(_, imm16)| signed(imm16, 16));
    let wide_unsigned = extend.map(|(_, imm16)| i64::from(imm16));
    // A branch counts from the instruction after it, which is 2 bytes on,
    // or 4 with an `extend`.
    let next = address + if extend.is_some() { 4 } else { 2 };
    let branch = |offset: i64, mnemonic: &'static str, test: Option<u32>, conditional: bool| {
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
        Reading::Control { mnemonic, operands, kind, test }
    };
    // The 3-operand form of a 2-operand MIPS16e instruction.
    let word = |value: u32| Some(Reading::Word(value));

    match op {
        // `addiu rx, sp, imm`: a frame address.
        0b00000 => word(immediate(0x09, SP, rx, wide.unwrap_or(i64::from(imm8 << 2)))),
        0b00001 => Some(Reading::PcRelative {
            load: false,
            dest: rx,
            address: (address & !3).wrapping_add_signed(wide.unwrap_or(i64::from(imm8 << 2))),
        }),
        0b00010 => {
            let offset = wide.unwrap_or_else(|| signed(h & 0x7ff, 11));
            Some(branch(offset, "b", None, false))
        }
        0b00100 | 0b00101 => {
            let offset = wide.unwrap_or_else(|| signed(imm8, 8));
            let (mnemonic, opcode) = if op == 0b00100 { ("beqz", 0x04) } else { ("bnez", 0x05) };
            Some(branch(offset, mnemonic, Some(immediate(opcode, rx, 0, 0)), true))
        }
        0b00110 => {
            let sa = match extend {
                Some((prefix, _)) => prefix >> 6 & 0x1f,
                None => match h >> 2 & 7 {
                    0 => 8,
                    sa => sa,
                },
            };
            let funct = match h & 3 {
                0b00 => 0x00,
                0b10 => 0x02,
                0b11 => 0x03,
                _ => return None,
            };
            word(register(0, ry, rx, sa, funct))
        }
        // `addiu ry, rx, imm4`, or 15 bits extended.
        0b01000 if h >> 4 & 1 == 0 => {
            let value = match extend {
                Some((prefix, _)) => {
                    let imm15 = (prefix & 0xf) << 11 | (prefix >> 4 & 0x7f) << 4 | h & 0xf;
                    signed(imm15, 15)
                }
                None => signed(h & 0xf, 4),
            };
            word(immediate(0x09, rx, ry, value))
        }
        0b01001 => word(immediate(0x09, rx, rx, wide.unwrap_or_else(|| signed(imm8, 8)))),
        0b01010 => word(immediate(0x0a, rx, T, wide.unwrap_or(i64::from(imm8)))),
        0b01011 => word(immediate(0x0b, rx, T, wide.unwrap_or(i64::from(imm8)))),
        0b01100 => match h >> 8 & 7 {
            0b000 | 0b001 => {
                let offset = wide.unwrap_or_else(|| signed(imm8, 8));
                let (mnemonic, opcode) =
                    if h >> 8 & 7 == 0 { ("beqz", 0x04) } else { ("bnez", 0x05) };
                Some(branch(offset, mnemonic, Some(immediate(opcode, T, 0, 0)), true))
            }
            0b010 => word(immediate(0x2b, SP, RA, wide.unwrap_or(i64::from(imm8 << 2)))),
            0b011 => word(immediate(0x09, SP, SP, wide.unwrap_or_else(|| signed(imm8, 8) << 3))),
            0b100 => {
                let save = h >> 7 & 1 == 1;
                let low = h & 0xf;
                let size = match extend {
                    Some((prefix, _)) => ((prefix >> 4 & 0xf) << 4 | low) * 8,
                    None if low == 0 => 128,
                    None => low * 8,
                };
                Some(Reading::Frame { save, size })
            }
            0b101 if extend.is_none() => {
                // `move r32, rz`, which MIPS32 spells `or r32, rz, zero`,
                // and `move zero, s0` is the `nop`.
                let r32 = (h >> 5 & 7) | (h >> 3 & 3) << 3;
                if r32 == 0 && h & 7 == 0 {
                    return word(0);
                }
                word(register(REGISTERS[(h & 7) as usize], 0, r32, 0, 0x25))
            }
            0b111 if extend.is_none() => word(register(h & 0x1f, 0, ry, 0, 0x25)),
            _ => None,
        },
        // `li rx, imm`, zero-extended.
        0b01101 => word(immediate(0x0d, 0, rx, wide_unsigned.unwrap_or(i64::from(imm8)))),
        // `cmpi rx, imm`: T is `rx ^ imm`.
        0b01110 => word(immediate(0x0e, rx, T, wide_unsigned.unwrap_or(i64::from(imm8)))),
        0b10000 => word(immediate(0x20, rx, ry, wide.unwrap_or(i64::from(imm5)))),
        0b10001 => word(immediate(0x21, rx, ry, wide.unwrap_or(i64::from(imm5 << 1)))),
        0b10010 => word(immediate(0x23, SP, rx, wide.unwrap_or(i64::from(imm8 << 2)))),
        0b10011 => word(immediate(0x23, rx, ry, wide.unwrap_or(i64::from(imm5 << 2)))),
        0b10100 => word(immediate(0x24, rx, ry, wide.unwrap_or(i64::from(imm5)))),
        0b10101 => word(immediate(0x25, rx, ry, wide.unwrap_or(i64::from(imm5 << 1)))),
        0b10110 => Some(Reading::PcRelative {
            load: true,
            dest: rx,
            address: (address & !3).wrapping_add_signed(wide.unwrap_or(i64::from(imm8 << 2))),
        }),
        0b11000 => word(immediate(0x28, rx, ry, wide.unwrap_or(i64::from(imm5)))),
        0b11001 => word(immediate(0x29, rx, ry, wide.unwrap_or(i64::from(imm5 << 1)))),
        0b11010 => word(immediate(0x2b, SP, rx, wide.unwrap_or(i64::from(imm8 << 2)))),
        0b11011 => word(immediate(0x2b, rx, ry, wide.unwrap_or(i64::from(imm5 << 2)))),
        0b11100 if extend.is_none() => match h & 3 {
            0b01 => word(register(rx, ry, rz, 0, 0x21)),
            0b11 => word(register(rx, ry, rz, 0, 0x23)),
            _ => None,
        },
        0b11101 if extend.is_none() => read_rr(h, rx, ry),
        _ => None,
    }
}

/// Read an instruction of the RR group, which names two registers.
fn read_rr(h: u32, rx: u32, ry: u32) -> Option<Reading> {
    let word = |value: u32| Some(Reading::Word(value));
    match h & 0x1f {
        0b00000 => {
            // `jr`, `jalr` and their compact forms, which have no delay slot.
            let (compact, link, from_ra) = (h >> 7 & 1 == 1, h >> 6 & 1 == 1, h >> 5 & 1 == 1);
            let target = if from_ra { RA } else { rx };
            let name = REGISTER_NAMES[target as usize];
            let (mnemonic, operands, kind, test) = match (link, from_ra) {
                (false, true) => {
                    (if compact { "jrc" } else { "jr" }, name.to_string(), InsnKind::Return, None)
                }
                (false, false) => (
                    if compact { "jrc" } else { "jr" },
                    name.to_string(),
                    InsnKind::Jump { target: None },
                    None,
                ),
                (true, false) => (
                    if compact { "jalrc" } else { "jalr" },
                    format!("ra, {name}"),
                    InsnKind::Call { target: None },
                    None,
                ),
                (true, true) => return None,
            };
            Some(Reading::Control { mnemonic, operands, kind, test })
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
        0b10001 => match h >> 5 & 7 {
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
const REGISTER_NAMES: [&str; 32] = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
    "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "s8",
    "ra",
];

impl Mips16 {
    /// The halfword at `offset` of `code`, in this byte order.
    fn halfword(self, code: &[u8], offset: usize) -> Option<u16> {
        let bytes: [u8; 2] = code.get(offset..offset + HALFWORD)?.try_into().ok()?;
        Some(self.base.read_halfword(bytes))
    }

    /// Decode at `offset`, with what it reads as.
    fn decoded(&self, code: &[u8], offset: usize, address: u64) -> Option<Decoded> {
        let first = self.halfword(code, offset)?;
        decode_halfwords(first, self.halfword(code, offset + HALFWORD), address)
    }

    /// The MIPS32 instruction a word translates to, at `address`.
    fn as_mips32(&self, word: u32, address: u64) -> Option<Insn> {
        self.base.decode(&self.base.word_bytes(word), 0, address).ok()
    }
}

impl Arch for Mips16 {
    fn decode(&self, code: &[u8], offset: usize, address: u64) -> Result<Insn, DecodeError> {
        let first = self.halfword(code, offset).ok_or(DecodeError::Truncated)?;
        let insn_address = address + offset as u64;
        let unknown = |width: usize| {
            let raw: String =
                code[offset..offset + width].iter().map(|byte| format!("{byte:02x}")).collect();
            Insn {
                address: insn_address,
                bytes_len: width,
                mnemonic: "(unknown)".into(),
                operands: raw,
                kind: InsnKind::Unknown,
            }
        };
        let Some(decoded) = self.decoded(code, offset, insn_address) else {
            // A prefix or a `jal` whose second halfword is cut off, or an
            // encoding MIPS16e leaves reserved, is stepped over whole.
            let wide =
                matches!(first >> 11, 0b00011 | 0b11110) && code.len() >= offset + 2 * HALFWORD;
            return Ok(unknown(if wide { 2 * HALFWORD } else { HALFWORD }));
        };
        let width = decoded.width;
        let insn = match decoded.reading {
            Reading::Word(word) => {
                let mut insn = self.as_mips32(word, insn_address).ok_or(DecodeError::Truncated)?;
                insn.bytes_len = width;
                insn
            }
            Reading::Control { mnemonic, operands, kind, .. } => Insn {
                address: insn_address,
                bytes_len: width,
                mnemonic: mnemonic.into(),
                operands,
                kind,
            },
            Reading::PcRelative { load, dest, address: at } => Insn {
                address: insn_address,
                bytes_len: width,
                mnemonic: if load { "lw" } else { "addiu" }.into(),
                operands: if load {
                    format!("{}, {at:#x}(pc)", REGISTER_NAMES[dest as usize])
                } else {
                    format!("{}, pc, {at:#x}", REGISTER_NAMES[dest as usize])
                },
                kind: InsnKind::Normal,
            },
            Reading::Frame { save, size } => Insn {
                address: insn_address,
                bytes_len: width,
                mnemonic: if save { "save" } else { "restore" }.into(),
                operands: format!("{size:#x}"),
                kind: InsnKind::Normal,
            },
        };
        Ok(insn)
    }

    fn triple(&self) -> &'static str {
        self.base.triple()
    }

    fn instruction_width(&self) -> usize {
        HALFWORD
    }

    fn is_register(&self, operand: &str) -> bool {
        self.base.is_register(operand)
    }

    fn is_stack_register(&self, operand: &str) -> bool {
        self.base.is_stack_register(operand)
    }

    fn is_frame_register(&self, reg: il::Reg) -> bool {
        self.base.is_frame_register(reg)
    }

    fn mentions_stack_slot(&self, operands: &str) -> bool {
        self.base.mentions_stack_slot(operands)
    }

    fn constant_value(&self, operand: &str) -> Option<u64> {
        self.base.constant_value(operand)
    }

    fn normalize_operation(&self, mnemonic: &str) -> CompactString {
        self.base.normalize_operation(mnemonic)
    }

    /// `save` and `restore` make and drop the frame whole.
    fn is_frame_management(&self, insn: &Insn) -> bool {
        matches!(insn.mnemonic.as_str(), "save" | "restore") || self.base.is_frame_management(insn)
    }

    /// The text of each instruction is that of MIPS32, so MIPS32 follows
    /// the global pointer through the body. A load or address relative to
    /// the program counter moves with the code, and so does the upper half
    /// of `_gp_disp` that the preamble adds to it.
    fn constant_kinds(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
    ) -> Vec<ConstantKind> {
        // MIPS32 knows the global pointer as `_gp_disp` added to `t9`, the
        // address of the function. MIPS16e adds it to the program counter
        // instead, so its `addu` is given to MIPS32 in the form it knows.
        let preambles: Vec<usize> = (0..body.len())
            .filter(|&index| {
                body.get(index..index + GP_PREAMBLE_LENGTH).is_some_and(is_gp_preamble)
            })
            .collect();
        let mut as_mips32 = body.to_vec();
        for &index in &preambles {
            let add = &mut as_mips32[index + GP_PREAMBLE_LENGTH - 1];
            if let Some((destination, _)) = add.operands.split_once(',') {
                add.operands = format!("{destination}, {destination}, t9");
            }
        }

        let mut kinds = super::mips::constant_kinds_in(self, &as_mips32, space);
        for &index in &preambles {
            kinds[index] = ConstantKind::Address;
        }
        for (index, insn) in body.iter().enumerate() {
            if insn.operands.contains("(pc)") || insn.operands.contains(", pc,") {
                kinds[index] = ConstantKind::Address;
            }
        }
        kinds
    }

    fn contents(&self, _code: &[u8], _insns: &[Insn], _space: &AddressSpace) -> Contents {
        Contents::Code
    }

    fn jump_tables(
        &self,
        memory: &Memory<'_>,
        code: core::ops::Range<u64>,
        insns: &[Insn],
    ) -> Vec<JumpTable> {
        let entry = |address: u64| {
            let bytes = memory.bytes(address, HALFWORD)?;
            Some(self.base.read_halfword([bytes[0], bytes[1]]) as i16)
        };
        (0..insns.len())
            .filter_map(|index| {
                read_jump_table(insns, index, &code, &entry, |operand| self.constant_value(operand))
            })
            .collect()
    }

    /// An address taken from the program counter, or a lower half added to
    /// a page that PIC code read from the global offset table, through a
    /// copy of the global pointer:
    ///
    /// ```text
    /// la    a1, text               lw    a1, %got(text)(s0)
    ///                              addiu a1, %lo(text)
    /// ```
    fn data_addresses(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        memory: &Memory<'_>,
    ) -> Vec<u64> {
        let constant = |operand: &str| self.constant_value(operand);
        let page = |load_at: usize, load: &Insn| {
            let [_, reference] = two_operands(load)?;
            let (offset, base) = reference.strip_suffix(')')?.split_once('(')?;
            if load.mnemonic != "lw" || !holds_global_pointer(body, load_at, base) {
                return None;
            }
            let global_pointer = global_pointer_before(body, load_at, constant)?;
            let slot = (global_pointer as u32).wrapping_add(constant(offset)? as u32);
            let bytes = memory.bytes(u64::from(slot), 4)?;
            Some(self.read_pointer(bytes) as u32)
        };
        body.iter()
            .enumerate()
            .filter(|(_, insn)| insn.mnemonic == "addiu")
            .filter_map(|(index, insn)| match three_operands(insn)? {
                // `t9` receives a callee, not data.
                ["t9", ..] => None,
                // The preamble's is half of `_gp_disp`, a distance.
                [_, "pc", _] if index > 0 && is_gp_preamble_at(body, index - 1) => None,
                [_, "pc", address] => constant(address),
                // An address that is called is code, not data.
                [destination, ..] if is_called(body, index, destination) => None,
                [_, source, low] => {
                    let (at, written) = last_write(body, index, source)?;
                    let address = page(at, written)?.wrapping_add(constant(low)? as u32);
                    Some(u64::from(address))
                }
            })
            .filter(|&address| space.contains_formed(address))
            .collect()
    }

    /// PIC code calls a function it does not reach with `jal` through a
    /// slot of the global offset table, as MIPS32 does. It reaches the table
    /// through a copy of the global pointer, as `s0`:
    ///
    /// ```text
    /// lw   v0, %call16(callee)(s0)       lw    v0, %got(local)(s0)
    /// jalr v0                            addiu v0, %lo(local)
    /// move t9, v0                        jalr  v0
    /// ```
    ///
    /// A local function is reached as on the right: through a page that a
    /// slot holds, and its offset in that page.
    fn call_targets(&self, insns: &[Insn]) -> Vec<(usize, Option<CallTarget>)> {
        let slot_of = |load_at: usize, load: &Insn| {
            let [_, reference] = two_operands(load)?;
            let (offset, base) = reference.strip_suffix(')')?.split_once('(')?;
            let offset = self.constant_value(offset)?;
            if load.mnemonic != "lw" || !holds_global_pointer(insns, load_at, base) {
                return None;
            }
            let global_pointer =
                global_pointer_before(insns, load_at, |operand| self.constant_value(operand))?;
            Some(u64::from((global_pointer as u32).wrapping_add(offset as u32)))
        };
        let through_slot = |index: usize| {
            let register = insns[index].operands.rsplit(',').next()?.trim();
            let (written_at, written) = last_write(insns, index, register)?;
            match three_operands(written) {
                Some([_, source, low]) if written.mnemonic == "addiu" => {
                    let (load_at, load) = last_write(insns, written_at, source)?;
                    let slot = slot_of(load_at, load)?;
                    let offset = self.constant_value(low)?;
                    Some(CallTarget::PageOffset { slot, offset })
                }
                _ => slot_of(written_at, written).map(CallTarget::Slot),
            }
        };
        insns
            .iter()
            .enumerate()
            .filter_map(|(index, insn)| match insn.kind {
                InsnKind::Call { target: Some(target) } => {
                    Some((index, Some(CallTarget::Address(target))))
                }
                InsnKind::Call { target: None } => Some((index, through_slot(index))),
                InsnKind::Jump { target: Some(target) } if super::leaves(insns, target) => {
                    Some((index, Some(CallTarget::Address(target))))
                }
                _ => None,
            })
            .collect()
    }

    fn is_function_entry(&self, body: &[Insn]) -> bool {
        body.get(..GP_PREAMBLE_LENGTH).is_some_and(is_gp_preamble)
    }

    /// PIC computes the global pointer before `save`.
    fn preamble_before_prologue(&self, earlier: &[Insn]) -> usize {
        let start = earlier.len().saturating_sub(GP_PREAMBLE_LENGTH);
        if is_gp_preamble(&earlier[start..]) { GP_PREAMBLE_LENGTH } else { 0 }
    }

    /// A pointer to a MIPS16e function has bit 0 set, as on Thumb-2.
    fn tagged_function(&self, word: u64) -> Option<u64> {
        (word & 1 == 1).then_some(word & !1)
    }

    /// `save` makes the frame of almost every function that calls, and a
    /// leaf drops the stack pointer as MIPS32 does.
    fn is_prologue(&self, insn: &Insn) -> bool {
        insn.mnemonic == "save" || self.base.is_prologue(insn)
    }

    fn is_tail_call(&self, insn: &Insn) -> bool {
        matches!(insn.kind, InsnKind::Jump { target: None })
    }

    /// A zero halfword pads as `nop` does, and reads as this `addiu`. In
    /// the GCC builds of the tests, no instruction is a zero halfword: each
    /// is fill or a word of a literal pool.
    fn is_padding(&self, insn: &Insn) -> bool {
        insn.mnemonic == "nop" || (insn.mnemonic == "addiu" && insn.operands == "s0, sp, 0x0")
    }

    /// Only whole halfwords at the end are removed: the `nop` and zero fill.
    fn trim_padding<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        let mut end = bytes.len() - bytes.len() % HALFWORD;
        while end >= HALFWORD && matches!(self.halfword(bytes, end - HALFWORD), Some(0x6500 | 0)) {
            end -= HALFWORD;
        }
        &bytes[..end]
    }

    /// `jal`, `jalx`, `jr` and `jalr` run the instruction after them first;
    /// a branch and the compact jumps do not.
    fn delay_slots(&self, insn: &Insn) -> usize {
        usize::from(matches!(insn.mnemonic.as_str(), "jal" | "jalx" | "jr" | "jalr"))
    }

    fn pointer_width(&self) -> usize {
        self.base.pointer_width()
    }

    fn read_pointer(&self, bytes: &[u8]) -> u64 {
        self.base.read_pointer(bytes)
    }

    fn lift(&self, insn: &Insn, word: &[u8]) -> Option<il::Lifted> {
        if insn.kind == InsnKind::Unknown {
            return None;
        }
        let decoded = self.decoded(word, 0, insn.address)?;
        match decoded.reading {
            Reading::Word(word) => {
                let translated = self.as_mips32(word, insn.address)?;
                self.base.lift(&translated, &self.base.word_bytes(word))
            }
            Reading::Control { test: Some(word), .. } => {
                let translated = self.as_mips32(word, insn.address)?;
                self.base.lift(&translated, &self.base.word_bytes(word))
            }
            Reading::Control { kind, .. } => {
                let op = match kind {
                    InsnKind::Call { .. } => il::Op::Call,
                    InsnKind::Return => il::Op::Return,
                    _ => il::Op::Jump,
                };
                let mut lifted = il::Lifted { op, ..Default::default() };
                if matches!(kind, InsnKind::Call { .. }) {
                    lifted.writes.insert(il::Reg::General(RA as u8));
                }
                lifted.operands = [il::Operand::Target].into_iter().collect();
                Some(lifted)
            }
            Reading::PcRelative { load, dest, .. } => {
                let mut lifted = il::Lifted::default();
                let dest = il::Reg::General(dest as u8);
                lifted.writes.insert(dest);
                lifted.op = if load { il::Op::Load } else { il::Op::Address };
                let source = if load {
                    lifted.memory = Some(il::MemoryAccess {
                        kind: il::AccessKind::Load,
                        width: Some(il::Width::Bits32),
                    });
                    il::Operand::Memory { base: None, offset: None }
                } else {
                    il::Operand::Target
                };
                lifted.operands = [il::Operand::Reg(dest), source].into_iter().collect();
                Some(lifted)
            }
            Reading::Frame { .. } => None,
        }
    }

    fn stub_arch(&self) -> Option<&'static dyn Arch> {
        Some(if self.base.is_big() { &Mips32::BIG } else { &Mips32::LITTLE })
    }

    fn function_address(&self, pointer: u64) -> u64 {
        pointer & !1
    }
}

/// How far back the parts of a table jump may lie.
const TABLE_LOOK_BACK: usize = 16;

/// More cases than any `switch` a compiler turns into one table.
const MOST_CASES: usize = 1024;

/// Read the table behind the jump at `insns[index]`, as GCC writes it:
///
/// ```text
/// sltiu v0, 5            ; read as `sltiu t8, v0, 5`: the number of cases
/// btnez dispatch
/// ...
/// sll   v1, v0, 1
/// la    v0, table        ; read as `addiu v0, pc, table`
/// addu  v1, v0, v1
/// lh    v1, 0(v1)
/// addu  v0, v1           ; read as `addu v0, v0, v1`
/// jrc   v0
/// ```
///
/// Each halfword of the table is the distance from the table to a case,
/// with bit 0 set, as an address of MIPS16e code has. `entry` reads one,
/// and `constant` reads the bound.
fn read_jump_table(
    insns: &[Insn],
    index: usize,
    code: &core::ops::Range<u64>,
    entry: &dyn Fn(u64) -> Option<i16>,
    constant: impl Fn(&str) -> Option<u64>,
) -> Option<JumpTable> {
    let jump = &insns[index];
    if !matches!(jump.mnemonic.as_str(), "jr" | "jrc")
        || jump.kind != (InsnKind::Jump { target: None })
    {
        return None;
    }
    let (sum_at, sum) = last_write(insns, index, jump.operands.trim())?;
    let [_, left, right] = three_operands(sum)?;
    if sum.mnemonic != "addu" {
        return None;
    }
    let table = [(left, right), (right, left)].into_iter().find_map(|(base, offset)| {
        let (_, load) = last_write(insns, sum_at, offset)?;
        if load.mnemonic != "lh" {
            return None;
        }
        let (_, la) = last_write(insns, sum_at, base)?;
        match three_operands(la)? {
            [_, "pc", address] if la.mnemonic == "addiu" => constant(address),
            _ => None,
        }
    })?;

    // The bound comes before the jump, or before the branch to the block
    // that holds it: GCC can put the dispatch after the code of a case.
    let bound_before = |at: usize| {
        insns[at.saturating_sub(TABLE_LOOK_BACK)..at].iter().rev().find_map(|insn| {
            let [_, _, bound] = (insn.mnemonic == "sltiu").then(|| three_operands(insn))??;
            usize::try_from(constant(bound)?).ok().filter(|&cases| cases <= MOST_CASES)
        })
    };
    let block = insns[..index]
        .iter()
        .rposition(|insn| insn.kind != InsnKind::Normal)
        .map_or(0, |at| at + 1);
    let guard = insns
        .iter()
        .position(|insn| insn.kind == (InsnKind::Branch { target: Some(insns[block].address) }));
    let bound = bound_before(index).or_else(|| bound_before(guard?))?;
    let targets: Vec<u64> = (0..bound as u64)
        .map_while(|case| {
            let distance = entry(table + case * HALFWORD as u64)?;
            let target = table.wrapping_add_signed(i64::from(distance)) & !1;
            code.contains(&target).then_some(target)
        })
        .collect();
    let words = table..table + (targets.len() * HALFWORD) as u64;
    (targets.len() == bound).then_some(JumpTable { jump: jump.address, words, targets })
}

/// The last instruction before `insns[before]`, and its index, that writes
/// `register`.
fn last_write<'a>(insns: &'a [Insn], before: usize, register: &str) -> Option<(usize, &'a Insn)> {
    last_write_within(insns, before, register, TABLE_LOOK_BACK)
}

/// [`last_write`], within `distance` instructions.
fn last_write_within<'a>(
    insns: &'a [Insn],
    before: usize,
    register: &str,
    distance: usize,
) -> Option<(usize, &'a Insn)> {
    let from = before.saturating_sub(distance);
    (from..before).rev().map(|at| (at, &insns[at])).find(|(_, insn)| {
        insn.kind == InsnKind::Normal
            && !super::mips::is_store(&insn.mnemonic)
            && insn.operands.split(',').next().map(str::trim) == Some(register)
    })
}

/// The two operands of `op a, b`.
fn two_operands(insn: &Insn) -> Option<[&str; 2]> {
    let operands: Vec<&str> = insn.operands.split(',').map(str::trim).collect();
    operands.try_into().ok()
}

/// Report whether a call soon after `insns[index]` goes through `register`.
fn is_called(insns: &[Insn], index: usize, register: &str) -> bool {
    /// GCC puts the `jalr` right after the address it calls, or one
    /// instruction later.
    const MOST_INSTRUCTIONS_TO_CALL: usize = 3;

    insns.iter().skip(index + 1).take(MOST_INSTRUCTIONS_TO_CALL).any(|insn| {
        matches!(insn.kind, InsnKind::Call { target: None })
            && insn.operands.rsplit(',').next().map(str::trim) == Some(register)
    })
}

/// Report whether a preamble starts at `insns[at]`.
fn is_gp_preamble_at(insns: &[Insn], at: usize) -> bool {
    insns.get(at..at + GP_PREAMBLE_LENGTH).is_some_and(is_gp_preamble)
}

/// The global pointer that the last preamble before `insns[index]` makes:
/// the upper half it loads, shifted, plus the address it takes from the
/// program counter.
fn global_pointer_before(
    insns: &[Insn],
    index: usize,
    constant: impl Fn(&str) -> Option<u64>,
) -> Option<u64> {
    let start = (0..index.saturating_sub(GP_PREAMBLE_LENGTH - 1))
        .rev()
        .find(|&at| is_gp_preamble(&insns[at..at + GP_PREAMBLE_LENGTH]))?;
    let preamble = &insns[start..start + GP_PREAMBLE_LENGTH];
    let [_, _, high] = three_operands(&preamble[0])?;
    let [_, _, low] = three_operands(&preamble[1])?;
    let joined = (constant(high)? as u32).wrapping_shl(16).wrapping_add(constant(low)? as u32);
    Some(u64::from(joined))
}

/// Report whether `register` holds the global pointer at `insns[before]`:
/// it is `gp`, a copy of it, or what the preamble made.
fn holds_global_pointer(insns: &[Insn], before: usize, register: &str) -> bool {
    /// Copies of copies, as `move gp, v0` then `move s0, gp`.
    const MOST_COPIES: usize = 4;

    let (mut before, mut register) = (before, register);
    for _ in 0..=MOST_COPIES {
        if register == "gp" {
            return true;
        }
        let Some((at, write)) = last_write_within(insns, before, register, before) else {
            return false;
        };
        let preamble_start = (at + 1).checked_sub(GP_PREAMBLE_LENGTH);
        if preamble_start.is_some_and(|start| is_gp_preamble(&insns[start..=at])) {
            return true;
        }
        match three_operands(write) {
            Some([_, source, "zero"]) if write.mnemonic == "or" => {
                (before, register) = (at, source);
            }
            _ => return false,
        }
    }
    false
}

/// The three operands of `op a, b, c`.
fn three_operands(insn: &Insn) -> Option<[&str; 3]> {
    let operands: Vec<&str> = insn.operands.split(',').map(str::trim).collect();
    operands.try_into().ok()
}

/// The instructions of [`is_gp_preamble`].
const GP_PREAMBLE_LENGTH: usize = 4;

/// Report whether `body` is the sequence with which MIPS16e PIC computes
/// the global pointer. It has no `t9` to add `_gp_disp` to, as MIPS32 does,
/// so it adds the program counter:
///
/// ```text
/// li    v0, %hi(_gp_disp)       ; read here as `ori v0, zero, ...`
/// addiu v1, pc, %lo(_gp_disp)
/// sll   v0, v0, 16
/// addu  v0, v0, v1
/// ```
///
/// Only the entry of a function runs it.
fn is_gp_preamble(body: &[Insn]) -> bool {
    fn operands(insn: &Insn) -> Vec<&str> {
        insn.operands.split(',').map(str::trim).collect()
    }
    let [high, low, shift, add] = body else { return false };
    let (high_ops, low_ops, shift_ops, add_ops) =
        (operands(high), operands(low), operands(shift), operands(add));
    let (&[loaded, "zero", _], &[from_pc, "pc", _], &[shifted, source, "16"], &[_, left, right]) =
        (high_ops.as_slice(), low_ops.as_slice(), shift_ops.as_slice(), add_ops.as_slice())
    else {
        return false;
    };
    high.mnemonic == "ori"
        && low.mnemonic == "addiu"
        && shift.mnemonic == "sll"
        && add.mnemonic == "addu"
        && shifted == loaded
        && source == loaded
        && [left, right].contains(&loaded)
        && [left, right].contains(&from_pc)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The text of the halfwords `values`, big endian, at `address`.
    fn text(values: &[u16], address: u64) -> String {
        let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
        let insn = Mips16::BIG.decode(&code, 0, address).expect("decodes");
        format!("{} {}", insn.mnemonic, insn.operands).trim_end().to_string()
    }

    /// The opening of `adler32_combine_` in zlib, by GCC 14 at `-Os`.
    const GP_PREAMBLE: [u16; 7] = [0xf000, 0x6a02, 0xf0a8, 0x0b0c, 0xf400, 0x3240, 0xe269];

    fn decode_all_big(values: &[u16]) -> Vec<Insn> {
        let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
        crate::arch::decode_all(&Mips16::BIG, &code, 0x1540).0
    }

    /// A `switch` of five cases at 0x100, as GCC writes it, then its table
    /// at 0x110 with `entries`.
    fn switch(entries: [u16; 5]) -> Vec<u16> {
        let dispatch = [0x5a05, 0x3344, 0x0a03, 0xe26d, 0x8b60, 0xe269, 0xea80, 0x6500];
        dispatch.into_iter().chain(entries).chain([0x6500; 11]).collect()
    }

    fn tables(values: &[u16]) -> Vec<JumpTable> {
        let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
        let insns = crate::arch::decode_all(&Mips16::BIG, &code, 0x100).0;
        let regions = [(0x100, code.as_slice())];
        let end = 0x100 + code.len() as u64;
        Mips16::BIG.jump_tables(&Memory::new(&regions), 0x100..end, &insns)
    }

    #[test]
    fn a_switch_reads_each_case_from_its_table() {
        let found = tables(&switch([0x000b, 0x000d, 0xfff1, 0x0011, 0x0013]));
        assert_eq!(
            found,
            [JumpTable {
                jump: 0x10c,
                words: 0x110..0x11a,
                targets: vec![0x11a, 0x11c, 0x100, 0x120, 0x122],
            }]
        );
    }

    #[test]
    fn a_table_with_a_case_outside_the_code_is_not_read() {
        assert!(tables(&switch([0x000b, 0x000d, 0x7ff1, 0x0011, 0x0013])).is_empty());
    }

    #[test]
    fn a_table_with_no_bound_is_not_read() {
        let mut values = switch([0x000b, 0x000d, 0xfff1, 0x0011, 0x0013]);
        values[0] = 0x6500;
        assert!(tables(&values).is_empty());
    }

    /// The opening of `luaB_assert` in Lua 5.1, by GCC 14 at `-O2`, up to
    /// its first call, at 0x7de4.
    const CALL_THROUGH_SLOT: [u16; 18] = [
        0xf000, 0x6a03, 0xf0e3, 0x0b08, 0xf400, 0x3240, 0xe269, 0x659a, 0x64f5, 0x671c, 0x6d01,
        0xf450, 0x98ec, 0x6724, 0xd204, 0xef40, 0x653f, 0x6500,
    ];

    #[test]
    fn a_call_through_a_copy_of_gp_names_its_slot() {
        let code: Vec<u8> =
            CALL_THROUGH_SLOT.iter().flat_map(|value| value.to_be_bytes()).collect();
        let insns = crate::arch::decode_all(&Mips16::BIG, &code, 0x7de4).0;
        let global_pointer = 0x3_0000 + 0x96d0;
        let calls = Mips16::BIG.call_targets(&insns);
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert_eq!(calls[0].1, Some(CallTarget::Slot(global_pointer - 31668)));
    }

    #[test]
    fn an_address_from_the_global_offset_table_is_data() {
        // `lw a2, -32708(s0)`, `addiu a2, -5188`, `la a3, ...`, after the
        // preamble of `luaB_assert`.
        let mut values = CALL_THROUGH_SLOT[..11].to_vec();
        values.extend([0xf030, 0x98dc, 0xf3bd, 0x4e1c, 0x0f01]);
        let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
        let insns = crate::arch::decode_all(&Mips16::BIG, &code, 0x7de4).0;
        let slot = 0x3_96d0 - 32708;
        let page = 0x2_0000_u32.to_be_bytes();
        let regions = [(slot, page.as_slice())];
        let la = (insns.last().unwrap().address & !3) + 4;
        let space = AddressSpace::from_ranges([0x7000..0xa000, 0x1_0000..0x4_0000]);

        let found = Mips16::BIG.data_addresses(&code, &insns, &space, &Memory::new(&regions));
        assert_eq!(found, [0x2_0000 - 5188, la], "the preamble's `la` is not data");
    }

    #[test]
    fn a_call_to_a_local_function_names_its_page_and_offset() {
        // `lw v0, -0x7f0c(s0)`, `addiu v0, -0x393f`, `jalr v0`, `move t9, v0`,
        // after the preamble of `luaB_assert`.
        let mut values = CALL_THROUGH_SLOT[..11].to_vec();
        values.extend([0xf0f0, 0x9854, 0xf6d8, 0x4a01, 0xea40, 0x653a]);
        let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
        let insns = crate::arch::decode_all(&Mips16::BIG, &code, 0x7de4).0;
        let offset = (-0x393f_i64) as u64;
        let calls = Mips16::BIG.call_targets(&insns);
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert_eq!(calls[0].1, Some(CallTarget::PageOffset { slot: 0x3_96d0 - 0x7f0c, offset }));

        let space = AddressSpace::from_ranges([0x0..0x4_0000]);
        let page = 0x2_0000_u32.to_be_bytes();
        let regions = [(0x3_96d0 - 0x7f0c, page.as_slice())];
        let data = Mips16::BIG.data_addresses(&code, &insns, &space, &Memory::new(&regions));
        assert!(data.is_empty(), "a callee is not data: {data:#x?}");
    }

    #[test]
    fn a_call_through_a_register_from_elsewhere_names_nothing() {
        let mut values = CALL_THROUGH_SLOT;
        // `move s0, a0` in place of `move s0, gp`.
        values[9] = 0x6704;
        let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
        let insns = crate::arch::decode_all(&Mips16::BIG, &code, 0x7de4).0;
        let calls = Mips16::BIG.call_targets(&insns);
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert_eq!(calls[0].1, None);
    }

    #[test]
    fn the_gp_preamble_opens_a_function() {
        let insns = decode_all_big(&GP_PREAMBLE);
        assert_eq!(insns.len(), 4);
        assert!(Mips16::BIG.is_function_entry(&insns));
        assert_eq!(Mips16::BIG.preamble_before_prologue(&insns), 4);
        assert_eq!(Mips16::BIG.preamble_before_prologue(&insns[1..]), 0);
        assert!(!Mips16::BIG.is_function_entry(&insns[..3]));
        assert!(!Mips16::BIG.is_function_entry(&insns[1..]));
    }

    #[test]
    fn a_constant_built_elsewhere_is_no_gp_preamble() {
        // `li v0, 2`, `sll v0, v0, 16`: no program counter joins it.
        let insns = decode_all_big(&[0x6a02, 0x3240, 0x3240, 0xe269]);
        assert!(!Mips16::BIG.is_function_entry(&insns));
        assert_eq!(Mips16::BIG.preamble_before_prologue(&insns), 0);
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
        assert_eq!(insn.mnemonic, "beqz");
        assert!(insn.operands.starts_with("t8, "));
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

    #[test]
    fn save_and_restore_make_and_drop_the_frame() {
        assert_eq!(text(&[0x64b4], 0), "save 0x20"); // save 32,s0-s1
        let code = 0x64b4_u16.to_be_bytes();
        let insn = Mips16::BIG.decode(&code, 0, 0).expect("decodes");
        assert!(Mips16::BIG.is_frame_management(&insn));
        assert!(Mips16::BIG.is_prologue(&insn));
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
            Some(Mips16::BIG.lift(&insn, &code).expect("lifts"))
        };
        // sltiu a2,16 then btnez
        let body = [lift(&[0x5e10], 0), lift(&[0x6105], 2)];
        let guards = il::find_guards(&body);
        assert_eq!(guards.len(), 1);
    }

    #[test]
    fn decoding_any_halfwords_never_panics() {
        bolero::check!().with_type::<(u16, u16)>().for_each(|&(first, second)| {
            let code: Vec<u8> =
                [first, second].iter().flat_map(|value| value.to_be_bytes()).collect();
            for arch in [Mips16::BIG, Mips16::LITTLE] {
                let insn = arch.decode(&code, 0, 0x1000).expect("two halfwords decode");
                assert!(insn.bytes_len == 2 || insn.bytes_len == 4);
                let _ = arch.lift(&insn, &code[..insn.bytes_len]);
            }
        });
    }
}
