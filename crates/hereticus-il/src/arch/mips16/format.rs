//! The fields of each MIPS16e instruction format, as deku reads them from
//! the halfwords of an instruction, most significant bit first. The names
//! of the formats are those of the MIPS16e Application-Specific Extension
//! manual.
//!
//! A halfword is read in either byte order, so these types read it as
//! [`Encoded::of`] stores it: big endian.

use deku::prelude::*;

use super::FrameStep;

/// The major opcode of a halfword: its five high bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big")]
struct Major {
    #[deku(bits = 5)]
    opcode: u8,
    #[deku(bits = 11)]
    rest: u16,
}

/// One instruction, by its major opcode, which [`Major`] reads first. Each
/// format reads the whole halfword again, the opcode as padding, so that
/// all 16 bits are one read. `jal`, `jalx` and `extend` take the halfword
/// after it too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(ctx = "major: u8", id = "major", endian = "big")]
pub(crate) enum Encoded {
    #[deku(id = 0b00000)]
    AddiuSp(Ri),
    #[deku(id = 0b00001)]
    AddiuPc(Ri),
    #[deku(id = 0b00010)]
    B(I),
    #[deku(id = 0b00011)]
    Jal(#[deku(pad_bits_before = "5")] Jal),
    #[deku(id = 0b00100)]
    Beqz(Ri),
    #[deku(id = 0b00101)]
    Bnez(Ri),
    #[deku(id = 0b00110)]
    Shift(Shift),
    #[deku(id = 0b01000)]
    RriA(RriA),
    #[deku(id = 0b01001)]
    Addiu8(Ri),
    #[deku(id = 0b01010)]
    Slti(Ri),
    #[deku(id = 0b01011)]
    Sltiu(Ri),
    #[deku(id = 0b01100)]
    I8(#[deku(pad_bits_before = "5")] I8),
    #[deku(id = 0b01101)]
    Li(Ri),
    #[deku(id = 0b01110)]
    Cmpi(Ri),
    #[deku(id = 0b10000)]
    Lb(Rri),
    #[deku(id = 0b10001)]
    Lh(Rri),
    #[deku(id = 0b10010)]
    LwSp(Ri),
    #[deku(id = 0b10011)]
    Lw(Rri),
    #[deku(id = 0b10100)]
    Lbu(Rri),
    #[deku(id = 0b10101)]
    Lhu(Rri),
    #[deku(id = 0b10110)]
    LwPc(Ri),
    #[deku(id = 0b11000)]
    Sb(Rri),
    #[deku(id = 0b11001)]
    Sh(Rri),
    #[deku(id = 0b11010)]
    SwSp(Ri),
    #[deku(id = 0b11011)]
    Sw(Rri),
    #[deku(id = 0b11100)]
    Rrr(Rrr),
    #[deku(id = 0b11101)]
    Rr(Rr),
    #[deku(id = 0b11110)]
    Extend(#[deku(pad_bits_before = "5")] Extend),
    /// A major opcode that MIPS16e leaves reserved, or gives to MIPS64.
    #[deku(id_pat = "_")]
    Reserved,
}

impl Encoded {
    /// The instruction that `first`, then `next` where there is one, hold.
    /// `None` where the instruction needs a halfword that is not there.
    pub(crate) fn of(first: u16, next: Option<u16>) -> Option<Self> {
        let [a, b] = first.to_be_bytes();
        let major: Major = read(&[a, b])?;
        let read_with_major = |bytes: &[u8]| read_with(bytes, major.opcode);
        match next {
            Some(next) => {
                let [c, d] = next.to_be_bytes();
                read_with_major(&[a, b, c, d])
            }
            None => read_with_major(&[a, b]),
        }
    }
}

/// The `T` that `bytes` open with.
#[inline]
pub(crate) fn read<'a, T: DekuReader<'a>>(bytes: &'a [u8]) -> Option<T> {
    read_with(bytes, ())
}

/// The `T` that `bytes` open with, read in `ctx`.
///
/// This reads through a [`Slice`] of its own: `from_bytes` also works out
/// the bytes that are left, which no caller here reads.
#[inline]
fn read_with<'a, T: DekuReader<'a, Ctx>, Ctx>(bytes: &'a [u8], ctx: Ctx) -> Option<T> {
    let mut slice = Slice { rest: bytes };
    let mut reader = Reader::new(&mut slice);
    T::from_reader_with_ctx(&mut reader, ctx).ok()
}

/// The bytes a reader has yet to read.
///
/// `std::io::Cursor` copies through `memcpy` whatever the length, which a
/// read of two bytes calls for each halfword. This copy of a length known
/// at compile time is a load and a store.
struct Slice<'a> {
    rest: &'a [u8],
}

impl std::io::Read for Slice<'_> {
    #[inline(always)]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let length = buf.len().min(self.rest.len());
        let (head, tail) = self.rest.split_at(length);
        buf[..length].copy_from_slice(head);
        self.rest = tail;
        Ok(length)
    }

    #[inline(always)]
    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let (head, tail) =
            self.rest.split_at_checked(buf.len()).ok_or(std::io::ErrorKind::UnexpectedEof)?;
        buf.copy_from_slice(head);
        self.rest = tail;
        Ok(())
    }
}

/// Only a skip forward, as padding of whole bytes makes, is read here.
impl std::io::Seek for Slice<'_> {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        let std::io::SeekFrom::Current(by) = position else {
            return Err(std::io::ErrorKind::Unsupported.into());
        };
        let by = usize::try_from(by).map_err(|_| std::io::ErrorKind::Unsupported)?;
        self.rest = self.rest.get(by..).unwrap_or_default();
        Ok(0)
    }
}

/// A register and an 8-bit constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) struct Ri {
    #[deku(pad_bits_before = "5", bits = 3)]
    pub rx: u8,
    pub imm: u8,
}

/// An 11-bit constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) struct I {
    #[deku(pad_bits_before = "5", bits = 11)]
    pub imm: u16,
}

/// Two registers and a 5-bit constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) struct Rri {
    #[deku(pad_bits_before = "5", bits = 3)]
    pub rx: u8,
    #[deku(bits = 3)]
    pub ry: u8,
    #[deku(bits = 5)]
    pub imm: u8,
}

/// Three registers and a function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) struct Rrr {
    #[deku(pad_bits_before = "5", bits = 3)]
    pub rx: u8,
    #[deku(bits = 3)]
    pub ry: u8,
    #[deku(bits = 3)]
    pub rz: u8,
    #[deku(bits = 2)]
    pub function: u8,
}

/// A shift by a constant: `sll`, `srl` or `sra`. A shift of 0 means 8.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) struct Shift {
    #[deku(pad_bits_before = "5", bits = 3)]
    pub rx: u8,
    #[deku(bits = 3)]
    pub ry: u8,
    #[deku(bits = 3)]
    pub amount: u8,
    #[deku(bits = 2)]
    pub function: u8,
}

/// `addiu ry, rx, imm` with a 4-bit constant, where the function is 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) struct RriA {
    #[deku(pad_bits_before = "5", bits = 3)]
    pub rx: u8,
    #[deku(bits = 3)]
    pub ry: u8,
    #[deku(bits = 1)]
    pub function: u8,
    #[deku(bits = 4)]
    pub imm: u8,
}

/// Two registers and a function of five bits, which `jr` and `cnvt` read
/// on in the second register.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) struct Rr {
    #[deku(pad_bits_before = "5", bits = 3)]
    pub rx: u8,
    #[deku(bits = 3)]
    pub ry: u8,
    #[deku(bits = 5)]
    pub function: u8,
}

/// `jal` or `jalx`, with a 26-bit target in words.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) struct Jal {
    pub mode: JumpMode,
    #[deku(bits = 5)]
    target_20_16: u32,
    #[deku(bits = 5)]
    target_25_21: u32,
    target_15_0: u16,
}

impl Jal {
    /// The 26-bit target, in words.
    pub(crate) fn target(self) -> u32 {
        self.target_25_21 << 21 | self.target_20_16 << 16 | u32::from(self.target_15_0)
    }
}

/// Whether a `jal` stays in MIPS16e, or switches to MIPS32 as `jalx` does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(id_type = "u8", bits = 1, endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) enum JumpMode {
    #[deku(id = 0)]
    Stay,
    #[deku(id = 1)]
    Exchange,
}

/// The `extend` prefix, and the halfword it widens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) struct Extend {
    pub prefix: Prefix,
    pub insn: u16,
}

/// The 11 bits of an `extend` prefix. What they hold depends on the
/// instruction they widen, so each layout is read when the instruction is
/// known.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) struct Prefix {
    #[deku(bits = 11)]
    bits: u16,
}

impl Prefix {
    /// The prefix laid out as `T`, which reads the 11 bits after five bits
    /// of padding.
    pub(crate) fn layout<T: for<'a> DekuReader<'a>>(self) -> T {
        read(&self.bits.to_be_bytes()).expect("each layout reads 16 bits")
    }

    /// The 16-bit constant of the usual layout, with the five low bits that
    /// `insn` holds.
    pub(crate) fn immediate(self, insn: u16) -> u32 {
        let layout: ExtendImmediate = self.layout();
        u32::from(layout.imm_15_11) << 11 | u32::from(layout.imm_10_5) << 5 | u32::from(insn) & 0x1f
    }
}

/// The usual layout of a prefix: bits 10 to 5, then 15 to 11, of a 16-bit
/// constant whose low five bits the instruction holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big")]
pub(crate) struct ExtendImmediate {
    #[deku(pad_bits_before = "5", bits = 6)]
    imm_10_5: u8,
    #[deku(bits = 5)]
    imm_15_11: u8,
}

/// The layout of a prefix of a shift: the amount, up to 31.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big")]
pub(crate) struct ExtendShift {
    #[deku(pad_bits_before = "5", bits = 5)]
    pub amount: u8,
    #[deku(bits = 6)]
    zero: u8,
}

/// The layout of a prefix of `addiu ry, rx, imm`: bits 10 to 4, then 14 to
/// 11, of a 15-bit constant whose low four bits the instruction holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big")]
pub(crate) struct ExtendAddiu {
    #[deku(pad_bits_before = "5", bits = 7)]
    imm_10_4: u16,
    #[deku(bits = 4)]
    imm_14_11: u16,
}

impl ExtendAddiu {
    /// The 15-bit constant, with the four low bits that `low` holds.
    pub(crate) fn immediate(self, low: u8) -> u32 {
        u32::from(self.imm_14_11) << 11 | u32::from(self.imm_10_4) << 4 | u32::from(low)
    }
}

/// The layout of a prefix of `save` and `restore`: the statics from `s2`
/// on, the high bits of the frame size, and how `a0` to `a3` split into
/// arguments and statics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big")]
pub(crate) struct ExtendFrame {
    #[deku(pad_bits_before = "5", bits = 3)]
    pub extra_statics: u8,
    #[deku(bits = 4)]
    pub frame_size_7_4: u8,
    #[deku(bits = 4)]
    pub argument_registers: u8,
}

/// The `I8` group, by the function in bits 10 to 8.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(id_type = "u8", bits = 3, endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) enum I8 {
    /// `bteqz`: branch where T is zero.
    #[deku(id = 0b000)]
    Bteqz(u8),
    /// `btnez`: branch where T is not zero.
    #[deku(id = 0b001)]
    Btnez(u8),
    /// `sw ra, imm(sp)`.
    #[deku(id = 0b010)]
    SwRaSp(u8),
    /// `addiu sp, imm`, in units of 8 bytes.
    #[deku(id = 0b011)]
    AdjSp(u8),
    /// `save` or `restore`.
    #[deku(id = 0b100)]
    SaveRestore(SaveRestore),
    /// `move r32, rz`.
    #[deku(id = 0b101)]
    Mov32R(Mov32R),
    /// `move ry, r32`.
    #[deku(id = 0b111)]
    MovR32(MovR32),
    #[deku(id_pat = "_")]
    Reserved(u8),
}

/// `save` or `restore`: whether it saves, which of `ra`, `s0` and `s1` it
/// keeps, and the low bits of the frame size, in units of 8 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) struct SaveRestore {
    pub step: FrameStep,
    pub ra: Kept,
    pub s0: Kept,
    pub s1: Kept,
    #[deku(bits = 4)]
    pub frame_size: u8,
}

/// Whether `save` and `restore` keep a register in the frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(id_type = "u8", bits = 1, endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) enum Kept {
    #[deku(id = 0)]
    No,
    #[deku(id = 1)]
    Yes,
}

/// `move r32, rz`: any of the 32 registers from one of the eight. The
/// manual splits the number of `r32`, low bits first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) struct Mov32R {
    #[deku(bits = 3)]
    r32_2_0: u8,
    #[deku(bits = 2)]
    r32_4_3: u8,
    #[deku(bits = 3)]
    pub rz: u8,
}

impl Mov32R {
    /// The number of the register it writes.
    pub(crate) fn r32(self) -> u32 {
        u32::from(self.r32_4_3) << 3 | u32::from(self.r32_2_0)
    }
}

/// `move ry, r32`: one of the eight registers from any of the 32.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) struct MovR32 {
    #[deku(bits = 3)]
    pub ry: u8,
    #[deku(bits = 5)]
    pub r32: u8,
}

/// `jr`, `jalr` and their compact forms: the function 0 of the RR group,
/// which reads the second register field as three flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big")]
pub(crate) struct JumpRegister {
    #[deku(pad_bits_before = "5", bits = 3)]
    pub rx: u8,
    pub slot: DelaySlot,
    pub link: Link,
    pub through: Through,
    #[deku(bits = 5, assert_eq = "0")]
    function: u8,
}

/// Whether a jump through a register has a delay slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(id_type = "u8", bits = 1, endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) enum DelaySlot {
    #[deku(id = 0)]
    Filled,
    /// The compact forms, `jrc` and `jalrc`.
    #[deku(id = 1)]
    Compact,
}

/// Whether a jump through a register links, as a call does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(id_type = "u8", bits = 1, endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) enum Link {
    #[deku(id = 0)]
    Jump,
    #[deku(id = 1)]
    Call,
}

/// The register a jump goes through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(id_type = "u8", bits = 1, endian = "big", ctx = "_: deku::ctx::Endian")]
pub(crate) enum Through {
    /// The register `rx` names.
    #[deku(id = 0)]
    Rx,
    /// `ra`, as a return goes.
    #[deku(id = 1)]
    ReturnAddress,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_halfword_reads_by_its_major_opcode() {
        // `lw v1, 12(sp)`, as `lwsp` stores it.
        assert_eq!(Encoded::of(0x9303, None), Some(Encoded::LwSp(Ri { rx: 3, imm: 3 })));
        // `addu v1, v1, v0`.
        let addu = Rrr { rx: 3, ry: 2, rz: 3, function: 1 };
        assert_eq!(Encoded::of(0xe34d, None), Some(Encoded::Rrr(addu)));
        assert_eq!(Encoded::of(0x3800, None), Some(Encoded::Reserved));
    }

    #[test]
    fn jal_and_extend_need_the_halfword_after() {
        assert_eq!(Encoded::of(0x1c00, None), None);
        assert_eq!(Encoded::of(0xf000, None), None);
        let Some(Encoded::Jal(jal)) = Encoded::of(0x1c21, Some(0x1234)) else {
            panic!("jalx reads");
        };
        assert_eq!(jal.mode, JumpMode::Exchange);
        assert_eq!(jal.target(), 0x1 << 21 | 0x1 << 16 | 0x1234);
    }

    #[test]
    fn each_prefix_layout_reads_its_own_fields() {
        // `extend 0x25d`, as `addiu a1, -0x15b0` holds it.
        const BITS: u32 = 0x25d;
        let Some(Encoded::Extend(extend)) = Encoded::of(0xf25d, Some(0x4d10)) else {
            panic!("extend reads");
        };
        assert_eq!(extend.prefix.immediate(extend.insn), 0xea50);
        let shift: ExtendShift = extend.prefix.layout();
        assert_eq!(u32::from(shift.amount), BITS >> 6 & 0x1f);
        let addiu: ExtendAddiu = extend.prefix.layout();
        assert_eq!(addiu.immediate(0xf), (BITS & 0xf) << 11 | (BITS >> 4 & 0x7f) << 4 | 0xf);
        let frame: ExtendFrame = extend.prefix.layout();
        let fields = [frame.extra_statics, frame.frame_size_7_4, frame.argument_registers];
        assert_eq!(fields.map(u32::from), [BITS >> 8 & 7, BITS >> 4 & 0xf, BITS & 0xf]);
    }

    #[test]
    fn a_jump_register_reads_its_three_flags() {
        // `jrc ra`.
        let jump: JumpRegister = read(&0xe8a0_u16.to_be_bytes()).expect("jrc reads");
        assert_eq!(
            (jump.slot, jump.link, jump.through),
            (DelaySlot::Compact, Link::Jump, Through::ReturnAddress)
        );
        assert_eq!(read::<JumpRegister>(&0xe8a1_u16.to_be_bytes()), None, "another function");
    }
}
