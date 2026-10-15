//! The rules the matching reads in A64 code, as which registers hold the
//! frame and which constants are addresses. The rules that find
//! functions are in [`hereticus_recovery::arch::aarch64`].

use super::{Arch, Insn, Memory};
use hereticus_il::Reg;
use hereticus_il::arch::aarch64::*;
use hereticus_memory::{AddressSpace, ConstantKind};
use hereticus_recovery::arch::aarch64::{SP, memory_base, operands_of, track_pages};
use yaxpeax_arm::armv8::a64::{Opcode, Operand, SizeCode};

impl Arch for Aarch64 {
    fn is_frame_register(&self, reg: Reg) -> bool {
        matches!(reg, Reg::Stack | FRAME)
    }

    fn is_frame_management(&self, insn: &Insn) -> bool {
        let Some(Decoded { opcode, alias }) = decoded(insn) else { return false };
        match (opcode, alias) {
            // Saving and restoring the frame and the registers it keeps.
            (Opcode::STP | Opcode::LDP | Opcode::STR | Opcode::LDR, _) => {
                operands_of(insn).iter().any(|&operand| reaches_frame(operand))
            }
            // Moving the stack pointer, or setting up the frame pointer.
            (_, Alias::Move)
            | (Opcode::SUB | Opcode::ADD | Opcode::MOVZ | Opcode::MOVN, Alias::None) => {
                operands_of(insn).first().is_some_and(|&operand| is_stack_or_frame(operand))
            }
            // Signing and checking the return address, and marking a branch
            // target, change nothing a function computes.
            (Opcode::PACIASP | Opcode::PACIBSP | Opcode::AUTIASP | Opcode::AUTIBSP, _)
            | (_, Alias::BranchTarget) => true,
            _ => false,
        }
    }

    /// The offset in a page that `add` or a load joins to an `adrp` is part
    /// of an address, and moves with the data it names.
    fn constant_kinds(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
    ) -> Vec<ConstantKind> {
        track_pages(code, body, space).kinds
    }

    fn formed_addresses(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        _memory: &Memory<'_>,
    ) -> Vec<Option<u64>> {
        track_pages(code, body, space).formed
    }
}

/// The frame pointer, as the A64 procedure call standard names it.
const FRAME: Reg = Reg::General(29);

/// The frame pointer, `x29`.
const X29_NUMBER: u16 = 29;

/// Whether `operand` reaches into the frame: an access through `sp` or
/// `x29`.
fn reaches_frame(operand: Operand) -> bool {
    matches!(memory_base(operand), Some(SP | X29_NUMBER))
}

/// Whether `operand` is `sp`, `wsp` or `x29`.
fn is_stack_or_frame(operand: Operand) -> bool {
    matches!(
        operand,
        Operand::RegisterOrSP(_, SP)
            | Operand::Register(SizeCode::X, X29_NUMBER)
            | Operand::RegisterOrSP(SizeCode::X, X29_NUMBER)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use hereticus_il::arch::Decoder as _;
    use hereticus_recovery::arch::Recovery as _;

    use hereticus_recovery::arch::decode_all;

    use hereticus_il::{self as il, Lifted};

    fn code(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn decode_one(word: u32) -> Insn {
        Aarch64.decode(&word.to_le_bytes(), 0, 0x1000).expect("the word must decode")
    }

    /// Encodings from `llvm-mc --triple=aarch64 -mattr=+lse --show-encoding`.
    mod words {
        pub const LDR_X1_X2_8: u32 = 0xf940_0441;
        pub const LDP_X29_X30_SP_POST: u32 = 0xa8c1_7bfd;
        pub const STR_W3_X4_X5: u32 = 0xb825_6883;
    }

    fn lift_one(word: u32) -> Lifted {
        Aarch64.lift(&decode_one(word)).expect("the word must lift")
    }

    fn x(number: u8) -> Reg {
        Reg::General(number)
    }

    #[test]
    fn a_memory_operand_names_its_base_and_offset() {
        let memory = |word| *lift_one(word).operands.last().expect("a memory operand");
        assert_eq!(memory(words::LDR_X1_X2_8), il::Operand::memory(Some(x(2)), Some(8)));
        assert_eq!(memory(words::STR_W3_X4_X5), il::Operand::memory(Some(x(4)), None));
        let written = |offset, update| il::Operand::Memory {
            base: Some(Reg::Stack),
            offset: Some(offset),
            index: None,
            update,
        };
        assert_eq!(memory(words::LDP_X29_X30_SP_POST), written(16, il::Update::After));
        // stp x29, x30, [sp, #-0x10]!
        assert_eq!(memory(0xa9bf_7bfd), written(-16, il::Update::Before));
    }

    #[test]
    fn the_frame_registers_are_sp_and_x29() {
        assert!(Aarch64.is_frame_register(Reg::Stack));
        assert!(Aarch64.is_frame_register(x(29)));
        assert!(!Aarch64.is_frame_register(x(28)));
        assert!(!Aarch64.is_frame_register(Reg::Vector(29)));
    }

    /// `adrp` and `add` form an address, and the offset in the page moves
    /// with it.
    #[test]
    fn a_page_and_an_offset_form_an_address() {
        let words = [
            0x9000_0080, // 0x1000 adrp x0, 0x11000
            0x9100_a000, // 0x1004 add x0, x0, #0x28
            0xd65f_03c0, // 0x1008 ret
        ];
        let (insns, _) = decode_all(&Aarch64, &code(&words), 0x1000);
        let space = AddressSpace::from_ranges(core::iter::once(0x1000..0x20000));
        assert_eq!(
            Aarch64.data_addresses(&code(&words), &insns, &space, &Memory::new(&[])),
            [0x11028]
        );
        let kinds = Aarch64.constant_kinds(&code(&words), &insns, &space);
        assert_eq!(kinds[..2], [ConstantKind::Address, ConstantKind::Address]);
    }

    /// A load from a page outside the image, as the GOT can be, still reads
    /// at an address that moves when the linker lays the image out again.
    #[test]
    fn a_load_from_any_page_reads_at_an_address() {
        let words = [
            0x9000_0080, // 0x1000 adrp x0, 0x11000
            0xf940_3408, // 0x1004 ldr x8, [x0, #0x68]
            0xf940_3428, // 0x1008 ldr x8, [x1, #0x68]
            0xd65f_03c0, // 0x100c ret
        ];
        let (insns, _) = decode_all(&Aarch64, &code(&words), 0x1000);
        let space = AddressSpace::from_ranges(core::iter::once(0x1000..0x2000));
        let kinds = Aarch64.constant_kinds(&code(&words), &insns, &space);
        assert_eq!(kinds[1], ConstantKind::Address, "through the page");
        assert_eq!(kinds[2], ConstantKind::Value, "through a register with no page");
    }

    /// `bti` marks where an indirect branch may land, and comes before the
    /// frame is made. `yaxpeax-arm` 0.4 prints it as `hint #0x22`.
    #[test]
    fn a_branch_target_mark_comes_before_the_prologue() {
        let bti_c = decode_one(0xd503_245f);
        assert_eq!(Aarch64.preamble_before_prologue(core::slice::from_ref(&bti_c)), 1);
        assert!(Aarch64.is_frame_management(&bti_c));
        let paciasp = decode_one(0xd503_233f);
        assert_eq!(Aarch64.preamble_before_prologue(&[paciasp]), 1);
        let nop = decode_one(0xd503_201f);
        assert_eq!(Aarch64.preamble_before_prologue(&[nop]), 0);
    }
}
