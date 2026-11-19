//! The instruction forms of PowerPC, as the Power ISA names them and their
//! fields, which deku reads from a word most significant bit first.

use deku::{DekuRead, DekuReader};

/// The `T` that the 32 bits of `word` hold.
fn read<T: for<'a> DekuReader<'a>>(word: u32) -> T {
    let bytes = word.to_be_bytes();
    let mut cursor = deku::no_std_io::Cursor::new(&bytes[..]);
    let mut reader = deku::reader::Reader::new(&mut cursor);
    T::from_reader_with_ctx(&mut reader, ()).expect("a word holds each field of a form")
}

/// The D form: a register, a base and a 16-bit constant, as `addi`, `addis`
/// and `stwu` hold them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big")]
pub struct DForm {
    /// The primary opcode.
    #[deku(bits = 6)]
    pub opcode: u8,
    /// The target register.
    #[deku(bits = 5)]
    pub rt: u8,
    /// The base register, where 0 means the value 0 in a D form.
    #[deku(bits = 5)]
    pub ra: u8,
    #[deku(bits = 16)]
    d: u16,
}

impl DForm {
    /// The fields of `word`.
    pub fn of(word: u32) -> Self {
        read(word)
    }

    /// The constant, sign-extended.
    pub fn displacement(self) -> i16 {
        self.d as i16
    }
}

/// The DS form: a D form whose constant is in words, with two bits of
/// extended opcode, as `std` and `stdu` hold them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big")]
pub struct DsForm {
    /// The primary opcode.
    #[deku(bits = 6)]
    pub opcode: u8,
    /// The source register.
    #[deku(bits = 5)]
    pub rs: u8,
    /// The base register, where 0 means the value 0 in a D form.
    #[deku(bits = 5)]
    pub ra: u8,
    /// The constant, in words.
    #[deku(bits = 14)]
    pub ds: u16,
    /// The extended opcode.
    #[deku(bits = 2)]
    pub extended: u8,
}

impl DsForm {
    /// The fields of `word`.
    pub fn of(word: u32) -> Self {
        read(word)
    }
}

/// The X form: three registers and a 10-bit extended opcode, as `stwux`
/// and `tw` hold them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big")]
pub struct XForm {
    /// The primary opcode.
    #[deku(bits = 6)]
    pub opcode: u8,
    /// The target register, or the TO field of a trap.
    #[deku(bits = 5)]
    pub rt: u8,
    /// The base register, where 0 means the value 0 in a D form.
    #[deku(bits = 5)]
    pub ra: u8,
    /// The second source register.
    #[deku(bits = 5)]
    pub rb: u8,
    /// The extended opcode.
    #[deku(bits = 10)]
    pub extended: u16,
    /// The record bit, which writes CR0 too.
    #[deku(bits = 1)]
    pub rc: u8,
}

impl XForm {
    /// The fields of `word`.
    pub fn of(word: u32) -> Self {
        read(word)
    }
}

/// The XL form: three fields of the condition register, or the BO and BI
/// of a branch, and a 10-bit extended opcode, as `bclr` and `bcctr` hold
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big")]
pub struct XlForm {
    /// The primary opcode.
    #[deku(bits = 6)]
    pub opcode: u8,
    /// The options of a branch: see [`BranchOptions`].
    #[deku(bits = 5)]
    pub bo: u8,
    /// The bit of the condition register a branch tests.
    #[deku(bits = 5)]
    pub bi: u8,
    /// The third field of the condition register.
    #[deku(bits = 5)]
    pub bb: u8,
    /// The extended opcode.
    #[deku(bits = 10)]
    pub extended: u16,
    /// Whether it links, as a call does.
    #[deku(bits = 1)]
    pub lk: u8,
}

impl XlForm {
    /// The fields of `word`.
    pub fn of(word: u32) -> Self {
        read(word)
    }
}

/// The B form of a conditional branch, `bc`, whose BO and BI the XL forms
/// `bclr` and `bcctr` hold in the same place.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big")]
pub struct BForm {
    /// The primary opcode.
    #[deku(bits = 6)]
    pub opcode: u8,
    /// The options of the branch: see [`BranchOptions`].
    #[deku(bits = 5)]
    pub bo: u8,
    /// The bit of the condition register it tests.
    #[deku(bits = 5)]
    pub bi: u8,
    /// The distance to the target, in words.
    #[deku(bits = 14)]
    pub bd: u16,
    /// Whether the target is absolute, not relative.
    #[deku(bits = 1)]
    pub aa: u8,
    /// Whether it links, as a call does.
    #[deku(bits = 1)]
    pub lk: u8,
}

impl BForm {
    /// The fields of `word`.
    pub fn of(word: u32) -> Self {
        read(word)
    }
}

/// The five bits of the BO field of a branch, high bit first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big")]
pub struct BranchOptions {
    /// Whether it tests a bit.
    pub bit: BitUse,
    /// The value of the bit that branches.
    pub when: super::BitValue,
    /// Whether it counts down.
    pub count: CountUse,
    /// The value of the count that branches.
    pub until: super::CountTest,
    /// A hint, in the old form, which changes nothing a branch does.
    #[deku(bits = 1, pad_bits_after = "3")]
    pub hint: u8,
}

impl BranchOptions {
    /// The options that the five bits of `bo` give.
    pub fn of(bo: u8) -> Self {
        let bytes = [bo << 3];
        let mut cursor = deku::no_std_io::Cursor::new(&bytes[..]);
        let mut reader = deku::reader::Reader::new(&mut cursor);
        Self::from_reader_with_ctx(&mut reader, ()).expect("a byte holds each option")
    }
}

/// Whether a branch tests a bit of the condition register.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(id_type = "u8", bits = 1, endian = "big", ctx = "_: deku::ctx::Endian")]
pub enum BitUse {
    /// It tests the bit that BI names.
    #[deku(id = 0)]
    Test,
    /// It tests no bit.
    #[deku(id = 1)]
    Ignore,
}

/// Whether a branch counts the count register down and tests it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(id_type = "u8", bits = 1, endian = "big", ctx = "_: deku::ctx::Endian")]
pub enum CountUse {
    /// It counts the count register down, and tests it.
    #[deku(id = 0)]
    Decrement,
    /// It leaves the count register alone.
    #[deku(id = 1)]
    Keep,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_form_reads_its_fields() {
        // `addis r2, r12, 2`, then `addi r2, r2, -0x7f00`.
        let addis = DForm::of(0x3c4c_0002);
        assert_eq!((addis.opcode, addis.rt, addis.ra, addis.displacement()), (15, 2, 12, 2));
        assert_eq!(DForm::of(0x3842_8100).displacement(), -0x7f00);
        // `stdu r1, -0x70(r1)`.
        let stdu = DsForm::of(0xf821_ff91);
        assert_eq!((stdu.opcode, stdu.rs, stdu.ra, stdu.extended), (62, 1, 1, 1));
        // `stwux r1, r1, r0`.
        let stwux = XForm::of(0x7c21_016e);
        assert_eq!(
            (stwux.opcode, stwux.rt, stwux.ra, stwux.rb, stwux.extended),
            (31, 1, 1, 0, 183)
        );
        // `bcctr 20, 0`, which is `bctr`.
        let bctr = XlForm::of(0x4e80_0420);
        assert_eq!((bctr.opcode, bctr.bo, bctr.bi, bctr.extended, bctr.lk), (19, 20, 0, 528, 0));
        // `beq cr0, $+8`.
        let beq = BForm::of(0x4182_0008);
        assert_eq!((beq.opcode, beq.bo, beq.bi, beq.bd, beq.aa, beq.lk), (16, 12, 2, 2, 0, 0));
    }

    #[test]
    fn the_options_of_a_branch_read_high_bit_first() {
        let always = BranchOptions::of(0b10100);
        assert_eq!((always.bit, always.count), (BitUse::Ignore, CountUse::Keep));
        let bdnz = BranchOptions::of(0b10000);
        assert_eq!(
            (bdnz.count, bdnz.until),
            (CountUse::Decrement, super::super::CountTest::NotZero)
        );
    }
}
