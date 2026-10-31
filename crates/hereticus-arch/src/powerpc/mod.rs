//! The rules the matching reads in PowerPC code, as which
//! instructions keep the frame and which constants are addresses. The rules
//! that find functions are in [`hereticus_recovery::arch::powerpc`].

use super::{Arch, Insn, Memory};
use hereticus_il::arch::Decoder as _;
use hereticus_il::arch::powerpc::{LINK, PowerPc};
use hereticus_il::{Op, Operand, Reg};
use hereticus_memory::{AddressSpace, ConstantKind};
use hereticus_recovery::arch::powerpc::track;

impl Arch for PowerPc {
    /// Making and freeing the frame, a load or a store of a frame slot, and
    /// the moves of the link register that save and restore it:
    ///
    /// ```text
    /// mflr r0                 lwz  r0, 0x24(r1)
    /// stwu r1, -0x20(r1)      mtlr r0
    /// stw  r0, 0x24(r1)       addi r1, r1, 0x20
    /// stmw r29, 0x14(r1)      blr
    /// ```
    fn is_frame_management(&self, insn: &Insn) -> bool {
        let Some(lifted) = self.lift(insn) else { return false };
        let reaches_frame = lifted.operands.iter().any(|operand| {
            matches!(operand, Operand::Memory { base: Some(Reg::Stack), index: None, .. })
        });
        match lifted.op {
            // `stwux r1, r1, r0` moves the stack pointer by a register.
            Op::Load | Op::Store => reaches_frame || lifted.writes.contains(Reg::Stack),
            // `mflr r0` and `mtlr r0`, and `mr r31, r1`, which makes a frame
            // pointer at `-O0`.
            Op::Move => {
                lifted.reads.contains(LINK)
                    || lifted.writes.contains(LINK)
                    || lifted.reads == [Reg::Stack].into_iter().collect()
            }
            // `addi r1, r1, N`, which frees the frame.
            Op::Add => lifted.writes.contains(Reg::Stack),
            _ => false,
        }
    }

    /// The parts of an address that `lis` and `addi` join, and every offset
    /// from the program counter that PIC code reads: see [`track`].
    fn constant_kinds(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
    ) -> Vec<ConstantKind> {
        track(*self, body, space, None).kinds
    }

    fn formed_addresses(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        memory: &Memory<'_>,
    ) -> Vec<Option<u64>> {
        track(*self, body, space, Some(memory)).formed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn one(word: u32) -> Insn {
        PowerPc::BIG.decode(&word.to_be_bytes(), 0, 0x1000).expect("4 bytes always decode")
    }

    #[rstest]
    #[case::mflr(0x7c08_02a6, true)]
    #[case::mtlr(0x7c08_03a6, true)]
    #[case::stwu(0x9421_fff0, true)]
    #[case::stwux(0x7c21_016e, true)]
    #[case::save(0x9001_0024, true)]
    #[case::restore(0x8001_0024, true)]
    #[case::stmw(0xbfa1_0014, true)]
    #[case::free(0x3821_0020, true)]
    #[case::frame_pointer(0x7c3f_0b78, true)]
    #[case::load(0x8063_0004, false)]
    #[case::add(0x7c63_2214, false)]
    #[case::mtctr(0x7c69_03a6, false)]
    #[case::li(0x3860_0005, false)]
    fn frame_management_keeps_the_stack(#[case] word: u32, #[case] frame: bool) {
        assert_eq!(PowerPc::BIG.is_frame_management(&one(word)), frame);
    }

    #[test]
    fn the_64_bit_frame_is_kept_as_the_32_bit_one() {
        let one =
            |word: u32| PowerPc::LITTLE64.decode(&word.to_le_bytes(), 0, 0x1000).expect("decodes");
        for word in [0xf821_ffd1, 0xfbc1_fff0, 0xebc1_fff0, 0xf801_0010, 0x3821_0030] {
            assert!(PowerPc::LITTLE64.is_frame_management(&one(word)), "{word:#010x}");
        }
        assert!(!PowerPc::LITTLE64.is_frame_management(&one(0xe863_0008)));
    }

    #[test]
    fn the_frame_register_is_the_stack() {
        assert!(PowerPc::BIG.is_frame_register(Reg::Stack));
        assert!(!PowerPc::BIG.is_frame_register(Reg::General(31)));
    }
}
