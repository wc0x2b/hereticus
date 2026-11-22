//! The instruction forms of AArch64 that a scan tests a word for, as deku
//! reads them from a word most significant bit first.

use deku::{DekuRead, DekuReader};

/// The fixed bits of `adr` and `adrp`, bits 28 to 24.
const PC_RELATIVE: u8 = 0b10000;

/// `adr` or `adrp`: a register, and an address relative to the program
/// counter, in bytes or in pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(endian = "big")]
pub struct PcRelative {
    /// Whether the address is in pages, as `adrp` gives it.
    pub unit: AddressUnit,
    #[deku(bits = 2)]
    immediate_low: u32,
    #[deku(bits = 5, assert_eq = "PC_RELATIVE")]
    fixed: u8,
    #[deku(bits = 19)]
    immediate_high: u32,
    /// The register it writes.
    #[deku(bits = 5)]
    pub rd: u8,
}

/// What an address relative to the program counter counts in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead)]
#[deku(id_type = "u8", bits = 1, endian = "big", ctx = "_: deku::ctx::Endian")]
pub enum AddressUnit {
    /// Bytes, as `adr` counts.
    #[deku(id = 0)]
    Byte,
    /// Pages of 4 KiB, as `adrp` counts.
    #[deku(id = 1)]
    Page,
}

impl PcRelative {
    /// The fields of `word`, where it is `adr` or `adrp`.
    pub fn of(word: u32) -> Option<Self> {
        let bytes = word.to_be_bytes();
        let mut cursor = deku::reader::SliceReader::new(&bytes);
        let mut reader = deku::reader::Reader::new(&mut cursor);
        Self::from_reader_with_ctx(&mut reader, ()).ok()
    }

    /// The 21-bit distance, in the unit of the instruction, unsigned.
    pub fn immediate(self) -> u32 {
        self.immediate_high << 2 | self.immediate_low
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adrp_and_adr_read_their_fields() {
        // `adrp x16, 0x11000` at 0, then `adr x1, 8`.
        let adrp = PcRelative::of(0xb000_0090).expect("adrp reads");
        assert_eq!((adrp.unit, adrp.immediate(), adrp.rd), (AddressUnit::Page, 0x11, 16));
        let adr = PcRelative::of(0x1000_0041).expect("adr reads");
        assert_eq!((adr.unit, adr.immediate(), adr.rd), (AddressUnit::Byte, 8, 1));
        assert_eq!(PcRelative::of(0xd61f_0220), None, "br x17");
    }
}
