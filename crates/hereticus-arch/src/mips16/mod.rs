//! The rules the matching reads in MIPS16e code, as which registers hold the
//! frame and which constants are addresses. The rules that find
//! functions are in [`hereticus_recovery::arch::mips16`].

use super::mips::register_name;
use super::{Arch, Decoder, GlobalPointerSetup, Insn, Memory};
use hereticus_il as il;
use hereticus_il::arch::mips16::*;
use hereticus_memory::{AddressSpace, ConstantKind, Contents};
use hereticus_recovery::arch::mips::first_register;
use hereticus_recovery::arch::mips16::{
    AddressRules as _, GP_PREAMBLE_LENGTH, is_gp_preamble, mips16_op,
};

/// The function field of the MIPS32 `addu`.
const ADDU: u32 = 0x21;

impl Arch for Mips16 {
    fn is_frame_register(&self, reg: il::Reg) -> bool {
        self.base.is_frame_register(reg)
    }

    /// `save` and `restore` make and drop the frame whole.
    fn is_frame_management(&self, insn: &Insn) -> bool {
        matches!(mips16_op(insn), Some(Op::Save | Op::Restore))
            || self.base.is_frame_management(insn)
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
            let destination = self.lift(add).and_then(|lifted| match lifted.operands.first() {
                Some(il::Operand::Reg(il::Reg::General(number))) => Some(u32::from(*number)),
                _ => None,
            });
            // `addu rD, rD, t9`, the MIPS32 instruction that joins the
            // distance to the global pointer.
            let joined = destination.and_then(|rd| {
                // `t9` is register 25.
                let word = register(rd, 25, rd, 0, ADDU);
                self.base.decode(&self.base.word_bytes(word), 0, add.address).ok()
            });
            if let Some(joined) = joined {
                *add = joined;
            }
        }

        let mut kinds = super::mips::constant_kinds_in(self, &as_mips32, space);
        for &index in &preambles {
            kinds[index] = ConstantKind::Address;
        }
        for (index, insn) in body.iter().enumerate() {
            let reading = self.decoded(insn.bytes(), 0, insn.address).map(|found| found.reading);
            if matches!(reading, Some(Reading::PcRelative { .. })) {
                kinds[index] = ConstantKind::Address;
            }
        }
        kinds
    }

    fn contents(&self, _code: &[u8], _insns: &[Insn], _space: &AddressSpace) -> Contents {
        Contents::Code
    }

    /// What [`crate::Recovery::data_addresses`] finds, and also the slot of the
    /// global offset table each load through the global pointer reads.
    fn formed_addresses(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        memory: &Memory<'_>,
    ) -> Vec<Option<u64>> {
        let mut formed = vec![None; body.len()];
        for (index, address) in self.addresses_by_index(body, space, memory) {
            formed[index] = Some(address);
        }
        for (index, insn) in body.iter().enumerate() {
            if formed[index].is_none()
                && let Some(slot) = self.slot_of(body, index, insn)
            {
                formed[index] = Some(slot);
            }
        }
        formed
    }

    fn global_pointer_setup(&self, body: &[Insn]) -> Option<GlobalPointerSetup> {
        let preamble = body.get(..GP_PREAMBLE_LENGTH).filter(|run| is_gp_preamble(run))?;
        let register = register_name(first_register(preamble.last()?)?)?.to_string();
        Some(GlobalPointerSetup { parts: (0..GP_PREAMBLE_LENGTH).collect(), register })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Recovery as _;

    /// The text of the halfwords `values`, big endian, at `address`.
    fn text(values: &[u16], address: u64) -> String {
        let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
        let insn = Mips16::BIG.decode(&code, 0, address).expect("decodes");
        insn.to_string().trim_end().to_string()
    }

    #[test]
    fn save_and_restore_make_and_drop_the_frame() {
        assert_eq!(text(&[0x64b4], 0), "save 0x20, s0, s1"); // save 32,s0-s1
        let code = 0x64b4_u16.to_be_bytes();
        let insn = Mips16::BIG.decode(&code, 0, 0).expect("decodes");
        assert!(Mips16::BIG.is_frame_management(&insn));
        assert!(Mips16::BIG.is_prologue(&insn));
    }
}
