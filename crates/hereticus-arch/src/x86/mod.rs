//! The rules the matching reads in x86 code, as which registers hold the
//! frame and which constants are addresses. The rules that find functions
//! are in [`hereticus_recovery::arch::x86`].

use super::{Arch, Insn, Memory};
use hereticus_il::Reg;
use hereticus_il::arch::x86::{X86, il_register, instruction};
use hereticus_memory::{AddressSpace, ConstantKind};
use hereticus_recovery::arch::x86::{
    formed_address, global_offset_table_uses, is_branch_target_mark,
};
use iced_x86::{Mnemonic, OpKind};

/// The frame pointer, `rbp` or `ebp`, by its encoding number.
const FRAME: Reg = Reg::General(5);

impl Arch for X86 {
    fn is_frame_register(&self, reg: Reg) -> bool {
        matches!(reg, Reg::Stack | FRAME)
    }

    /// Pushing and popping a register, moving the stack pointer, making the
    /// frame pointer, and a spill to a frame slot.
    fn is_frame_management(&self, insn: &Insn) -> bool {
        if is_branch_target_mark(insn) {
            return true;
        }
        let Some(inst) = instruction(insn) else { return false };
        let is_frame =
            |register| il_register(register).is_some_and(|reg| self.is_frame_register(reg));
        let first_is_frame = inst.op0_kind() == OpKind::Register && is_frame(inst.op0_register());
        match inst.mnemonic() {
            Mnemonic::Push | Mnemonic::Pop => inst.op0_kind() == OpKind::Register,
            Mnemonic::Leave => true,
            Mnemonic::Sub | Mnemonic::Add | Mnemonic::Lea | Mnemonic::And => first_is_frame,
            Mnemonic::Mov => {
                first_is_frame
                    || (0..inst.op_count()).any(|index| {
                        inst.op_kind(index) == OpKind::Memory && is_frame(inst.memory_base())
                    })
            }
            _ => false,
        }
    }

    /// A distance from `rip` is part of an address, and so is a constant
    /// inside the image, as code that is not PIC holds, and a distance from
    /// the global offset table, as 32-bit PIC holds: see
    /// [`global_offset_table_uses`].
    fn constant_kinds(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
    ) -> Vec<ConstantKind> {
        let from_table = global_offset_table_uses(body);
        body.iter()
            .zip(from_table)
            .map(|(insn, from_table)| match from_table || formed_address(insn, space).is_some() {
                true => ConstantKind::Address,
                false => ConstantKind::Value,
            })
            .collect()
    }

    fn formed_addresses(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        _memory: &Memory<'_>,
    ) -> Vec<Option<u64>> {
        let from_table = global_offset_table_uses(body);
        body.iter()
            .zip(from_table)
            .map(|(insn, from_table)| (!from_table).then(|| formed_address(insn, space)).flatten())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hereticus_il::arch::Decoder as _;
    use hereticus_recovery::arch::decode_all;
    use rstest::rstest;

    fn one(bytes: &[u8]) -> Insn {
        X86::BITS64.decode(bytes, 0, 0x1000).expect("the bytes must decode")
    }

    #[test]
    fn the_frame_registers_are_rsp_and_rbp() {
        assert!(X86::BITS64.is_frame_register(Reg::Stack));
        assert!(X86::BITS64.is_frame_register(Reg::General(5)));
        assert!(!X86::BITS64.is_frame_register(Reg::General(0)));
    }

    #[rstest]
    #[case::endbr64(&[0xf3, 0x0f, 0x1e, 0xfa], true)]
    #[case::push_rbx(&[0x53], true)]
    #[case::pop_r15(&[0x41, 0x5f], true)]
    #[case::mov_rbp_rsp(&[0x48, 0x89, 0xe5], true)]
    #[case::sub_rsp(&[0x48, 0x83, 0xec, 0x10], true)]
    #[case::spill(&[0x89, 0x7d, 0xfc], true)]
    #[case::leave(&[0xc9], true)]
    #[case::push_constant(&[0x6a, 0x05], false)]
    #[case::add_rax(&[0x48, 0x83, 0xc0, 0x10], false)]
    #[case::load(&[0x8b, 0x07], false)]
    fn frame_management_keeps_the_stack(#[case] bytes: &[u8], #[case] frame: bool) {
        assert_eq!(X86::BITS64.is_frame_management(&one(bytes)), frame);
    }

    #[test]
    fn a_rip_distance_is_an_address() {
        let code = [
            0x48, 0x8d, 0x3d, 0xf9, 0x0f, 0x00, 0x00, // lea rdi, [rip + 0xff9]
            0x83, 0xf8, 0x05, //                         cmp eax, 5
        ];
        let (insns, _) = decode_all(&X86::BITS64, &code, 0x1000);
        let kinds = X86::BITS64.constant_kinds(&code, &insns, &AddressSpace::none());
        assert_eq!(kinds, [ConstantKind::Address, ConstantKind::Value]);
    }

    #[test]
    fn the_distance_to_the_global_offset_table_is_an_address() {
        let code = [
            0xe8, 0x10, 0x00, 0x00, 0x00, //       call __x86.get_pc_thunk.bx
            0x81, 0xc3, 0x5b, 0x2e, 0x00, 0x00, // add ebx, 0x2e5b
            0x81, 0xc3, 0x5b, 0x2e, 0x00, 0x00, // add ebx, 0x2e5b
        ];
        let (insns, _) = decode_all(&X86::BITS32, &code, 0x1000);
        let kinds = X86::BITS32.constant_kinds(&code, &insns, &AddressSpace::none());
        // A constant added to the table after it is a distance from it too.
        assert_eq!(kinds, [ConstantKind::Value, ConstantKind::Address, ConstantKind::Address]);
    }
}
