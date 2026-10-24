//! The rules the matching reads in T32 code, as which registers hold the
//! frame and which constants are addresses. The rules that find
//! functions are in [`hereticus_recovery::arch::thumb`].

use super::{Arch, Insn, Memory};
use hereticus_il::arch::Decoder as _;
use hereticus_il::arch::arm32::Arm32;
use hereticus_il::arch::thumb::*;
use hereticus_memory::{AddressSpace, ConstantKind};
use hereticus_recovery::arch::arm32::{PcModel, track_pool_words};
use hereticus_recovery::arch::thumb::split_at_switch;

impl Arch for Thumb2 {
    fn is_frame_register(&self, reg: hereticus_il::Reg) -> bool {
        Arm32.is_frame_register(reg)
    }

    fn is_frame_management(&self, insn: &Insn) -> bool {
        Arm32.is_frame_management(insn)
    }

    fn constant_kinds(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
    ) -> Vec<ConstantKind> {
        match split_at_switch(code, body) {
            Some((offset, index)) => {
                let mut kinds = track_pool_words(
                    code,
                    &body[..index],
                    space,
                    PcModel::T32.with_data(self.data_order()),
                )
                .kinds;
                kinds.extend(Arm32.constant_kinds(&code[offset..], &body[index..], space));
                kinds
            }
            None => {
                track_pool_words(code, body, space, PcModel::T32.with_data(self.data_order())).kinds
            }
        }
    }

    fn formed_addresses(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        _memory: &Memory<'_>,
    ) -> Vec<Option<u64>> {
        track_pool_words(code, body, space, PcModel::T32.with_data(self.data_order())).formed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hereticus_recovery::arch::decode_all;

    /// T32 code from halfwords, little endian.
    fn halfwords(values: &[u16]) -> Vec<u8> {
        values.iter().flat_map(|value| value.to_le_bytes()).collect()
    }

    #[test]
    fn the_distance_a_veneer_adds_to_pc_is_a_stored_address() {
        let mut code = halfwords(&[0x4778, 0x46c0]);
        for word in [0xe59f_c000u32, 0xe08c_f00f, 0x0000_1000] {
            code.extend(word.to_le_bytes());
        }
        let (insns, _) = decode_all(&Thumb2, &code, 0x1000);
        let space = AddressSpace::of_raw_image(0x1000, 0x2000);
        let kinds = Thumb2.constant_kinds(&code, &insns, &space);
        // `pc` at the `add` is 0x1008 + 8, and the word adds 0x1000.
        assert_eq!(kinds.last(), Some(&ConstantKind::StoredAddress));
    }
}
