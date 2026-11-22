//! The instruction forms of MIPS32 that a scan tests a word for, as deku
//! reads them from a word most significant bit first.

use deku::{DekuContainerRead, DekuRead};

/// The `T` that the 32 bits of `word` hold.
fn read<T: for<'a> DekuContainerRead<'a>>(word: u32) -> T {
    let (_, value) =
        T::from_bytes((&word.to_be_bytes(), 0)).expect("a word holds each field of a form");
    value
}

/// The I form: two registers and a 16-bit constant, as `addiu` and `sw`
/// hold them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big")]
pub struct IForm {
    /// The primary opcode.
    #[deku(bits = 6)]
    pub opcode: u8,
    /// The source or base register.
    #[deku(bits = 5)]
    pub rs: u8,
    /// The target register.
    #[deku(bits = 5)]
    pub rt: u8,
    /// The constant.
    #[deku(bits = 16)]
    pub immediate: u16,
}

impl IForm {
    /// The fields of `word`.
    pub fn of(word: u32) -> Self {
        read(word)
    }
}

/// The J form: a 26-bit target in words, as `j` and `jal` hold it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big")]
pub struct JForm {
    /// The primary opcode.
    #[deku(bits = 6)]
    pub opcode: u8,
    /// The target in words, within the 256 MiB region of the instruction.
    #[deku(bits = 26)]
    pub target: u32,
}

impl JForm {
    /// The fields of `word`.
    pub fn of(word: u32) -> Self {
        read(word)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_form_reads_its_fields() {
        // `addiu sp, sp, -32`.
        let addiu = IForm::of(0x27bd_ffe0);
        assert_eq!((addiu.opcode, addiu.rs, addiu.rt, addiu.immediate), (9, 29, 29, 0xffe0));
        // `jal 0x80012340`.
        let jal = JForm::of(0x0c00_48d0);
        assert_eq!((jal.opcode, jal.target << 2), (3, 0x0001_2340));
    }
}
