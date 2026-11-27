//! The rules the matching reads in PowerPC code, as which
//! instructions keep the frame and which constants are addresses. The rules
//! that find functions are in [`hereticus_recovery::arch::powerpc`].

use super::relocation::{DataReference, Part, RelocationType, Width, references_of};
use super::{Abi, Arch, CallingConvention, Insn, Memory, NamedReg};
use hereticus_il::arch::ByteOrder;
use hereticus_il::arch::Decoder as _;
use hereticus_il::arch::InsnKind;
use hereticus_il::arch::powerpc::{LINK, Opcode, PowerPc, decoded};
use hereticus_il::{Op, Operand, Reg};
use hereticus_memory::{AddressSpace, ConstantKind};
use hereticus_recovery::arch::Recovery as _;
use hereticus_recovery::arch::powerpc::{toc_from_global_entry, track};
use hereticus_recovery::dynamic::Dynamic;

/// The TOC of 64-bit code, which its call stubs reach their slots from:
/// where the first ELFv2 global entry in `regions` of little-endian code
/// makes it, or else 0x8000 past `got`, the start of `.got`, as GNU `ld`
/// and LLD put it. An ELFv1 function makes no TOC of its own, so only
/// `.got`, or a descriptor the dynamic segment names, gives it there.
fn toc(arch: PowerPc, regions: &[(u64, &[u8])], got: Option<u64>) -> Option<u64> {
    /// How far past the start of `.got` the TOC lies.
    const TOC_BIAS: u64 = 0x8000;
    let global_entry = || match arch.data_order() {
        ByteOrder::Little => {
            regions.iter().find_map(|&(base, data)| toc_from_global_entry(arch, data, base))
        }
        ByteOrder::Big => None,
    };
    global_entry().or_else(|| got.map(|got| got + TOC_BIAS))
}

/// The TOC of ELFv1 64-bit code, from the second doubleword of the
/// descriptor that an exported function names, as GNU `ld` writes it.
fn descriptor_toc(dynamic: &Dynamic<'_>) -> Option<u64> {
    dynamic
        .exports()
        .iter()
        .find_map(|export| dynamic.field(export.address + 8).filter(|&toc| toc != 0))
}

/// What a relocation of 32-bit PowerPC code names of the address of data.
fn part_of_32(r_type: RelocationType) -> Option<Part> {
    use object::elf::*;
    Some(match r_type {
        R_PPC_ADDR32 => Part::Word(Width::Four),
        R_PPC_ADDR16_HA | R_PPC_ADDR16_HI => Part::High,
        R_PPC_ADDR16_LO => Part::Low,
        _ => return None,
    })
}

/// What a relocation of 64-bit PowerPC code names of the address of data.
fn part_of_64(r_type: RelocationType) -> Option<Part> {
    use object::elf::*;
    Some(match r_type {
        R_PPC64_ADDR64 => Part::Word(Width::Eight),
        R_PPC64_ADDR16_HA | R_PPC64_ADDR16_HI => Part::High,
        R_PPC64_ADDR16_LO | R_PPC64_ADDR16_LO_DS => Part::Low,
        _ => return None,
    })
}

impl Arch for PowerPc {
    fn data_references(
        &self,
        relocations: &[(u64, object::Relocation)],
        word: &dyn Fn(u64) -> Option<u64>,
    ) -> Vec<DataReference> {
        match self.pointer_width() {
            8 => references_of(relocations, word, part_of_64),
            _ => references_of(relocations, word, part_of_32),
        }
    }

    fn address_relocations(&self) -> Option<[RelocationType; 2]> {
        use object::elf::{R_PPC_ADDR32, R_PPC_RELATIVE, R_PPC64_ADDR64, R_PPC64_RELATIVE};
        match self.pointer_width() {
            8 => Some([R_PPC64_ADDR64, R_PPC64_RELATIVE]),
            _ => Some([R_PPC_ADDR32, R_PPC_RELATIVE]),
        }
    }

    /// 32-bit PIC code holds the global offset table in `r30`, as
    /// `DT_PPC_GOT` gives it: `DT_PLTGOT` there gives the table of the PLT.
    /// 64-bit code reaches its slots from the TOC.
    fn global_table(
        &self,
        dynamic: Option<&Dynamic<'_>>,
        regions: &[(u64, &[u8])],
        got: Option<u64>,
    ) -> Option<u64> {
        /// `DT_PPC_GOT`, the first tag of the processor range.
        const DT_PPC_GOT: u64 = 0x7000_0000;
        match self.pointer_width() {
            8 => toc(*self, regions, got).or_else(|| descriptor_toc(dynamic?)),
            _ => dynamic?.value(DT_PPC_GOT),
        }
    }

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

    /// A jump over `nop`s to the word after them, which GCC puts in to align
    /// a loop, as `b $+0x18` and five `nop`s. It does nothing: the code
    /// runs on where it would run without it.
    fn idiom_length(&self, body: &[Insn]) -> usize {
        let Some((jump, rest)) = body.split_first() else { return 0 };
        let InsnKind::Jump { target: Some(target) } = jump.kind else { return 0 };
        let padding = rest.iter().take_while(|insn| self.is_padding(insn)).count();
        let lands =
            rest.get(padding).map_or(jump.address + 4 * (padding as u64 + 1), |insn| insn.address);
        match padding > 0
            && target == lands
            && decoded(jump).is_some_and(|decoded| decoded.opcode == Opcode::B)
        {
            true => 1 + padding,
            false => 0,
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

    /// The System V and ELFv2 ABIs: `r3` to `r10`, and `r3`.
    fn calling_convention(&self, _abi: Abi) -> Option<CallingConvention> {
        const SYSTEM_V: CallingConvention = CallingConvention {
            arguments: &[
                NamedReg::new(Reg::General(3), "r3"),
                NamedReg::new(Reg::General(4), "r4"),
                NamedReg::new(Reg::General(5), "r5"),
                NamedReg::new(Reg::General(6), "r6"),
                NamedReg::new(Reg::General(7), "r7"),
                NamedReg::new(Reg::General(8), "r8"),
                NamedReg::new(Reg::General(9), "r9"),
                NamedReg::new(Reg::General(10), "r10"),
            ],
            result: NamedReg::new(Reg::General(3), "r3"),
            stack: Reg::Stack,
            preserved: &[14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31],
            stack_arguments: None,
            link: Some(LINK),
        };
        Some(SYSTEM_V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn one(word: u32) -> Insn {
        PowerPc::BIG.decode(&word.to_be_bytes(), 0, 0x1000).expect("4 bytes always decode")
    }

    /// ELFv2 code makes its TOC at its first global entry, and ELFv1 code
    /// keeps it 0x8000 past the start of `.got`.
    #[test]
    fn the_toc_comes_from_a_global_entry_or_the_got() {
        let entry: Vec<u8> = [0x4e80_0020_u32, 0x3c4c_0002, 0x3842_2d28, 0x7c08_02a6]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let regions = [(0x2_1c9c, entry.as_slice())];
        assert_eq!(toc(PowerPc::LITTLE64, &regions, Some(0x1000)), Some(0x4_49c8));
        assert_eq!(toc(PowerPc::BIG64, &regions, Some(0x1000)), Some(0x9000));
        assert_eq!(toc(PowerPc::BIG64, &regions, None), None);
        assert_eq!(PowerPc::BIG64.global_table(None, &regions, Some(0x1000)), Some(0x9000));
        assert_eq!(PowerPc::BIG.global_table(None, &regions, Some(0x1000)), None, "no DT_PPC_GOT");
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
    fn a_jump_over_nops_is_an_idiom() {
        let code: Vec<u8> = [0x4800_000c_u32, 0x6000_0000, 0x6000_0000, 0x3860_0001]
            .iter()
            .flat_map(|word| word.to_be_bytes())
            .collect();
        let (insns, _) = hereticus_recovery::arch::decode_all(&PowerPc::BIG, &code, 0x1000);
        assert_eq!(PowerPc::BIG.idiom_length(&insns), 3);
        // A jump past the work after the `nop`s is work.
        let far: Vec<u8> = [0x4800_0010_u32, 0x6000_0000, 0x6000_0000, 0x3860_0001]
            .iter()
            .flat_map(|word| word.to_be_bytes())
            .collect();
        let (insns, _) = hereticus_recovery::arch::decode_all(&PowerPc::BIG, &far, 0x1000);
        assert_eq!(PowerPc::BIG.idiom_length(&insns), 0);
        assert_eq!(PowerPc::BIG.idiom_length(&insns[1..]), 0, "no jump");
    }

    #[test]
    fn the_frame_register_is_the_stack() {
        assert!(PowerPc::BIG.is_frame_register(Reg::Stack));
        assert!(!PowerPc::BIG.is_frame_register(Reg::General(31)));
    }
}
