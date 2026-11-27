//! The rules the matching reads in x86 code, as which registers hold the
//! frame and which constants are addresses. The rules that find functions
//! are in [`hereticus_recovery::arch::x86`].

use super::relocation::{DataReference, Part, RelocationType, Width, references_of};
use super::{
    Abi, Arch, CallingConvention, FramePointer, Insn, Memory, NamedReg, RegisterClass,
    StackArguments,
};
use hereticus_il::Reg;
use hereticus_il::arch::Decoder as _;
use hereticus_il::arch::x86::{Mode, X86, il_register, instruction};
use hereticus_memory::{AddressSpace, ConstantKind};
use hereticus_recovery::arch::x86::{
    formed_address, global_offset_table_uses, is_branch_target_mark,
};
use iced_x86::{Mnemonic, OpKind};

/// The frame pointer, `rbp` or `ebp`, by its encoding number.
const FRAME: Reg = Reg::General(5);

/// The class of an x86 register: `rax` holds 64 bits, `eax` 32, `ax` 16
/// and `al` 8, and so on for each.
fn register_class(name: &str) -> RegisterClass<'_> {
    const BITS_64: [&str; 8] = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"];
    const BITS_32: [&str; 8] = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];
    const BITS_16: [&str; 8] = ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"];
    const BITS_8: [&str; 12] =
        ["al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "sil", "dil", "bpl", "spl"];
    // `r8` to `r15`, with `d`, `w` or `b` for a part of 32, 16 or 8 bits.
    let numbered = name.strip_prefix('r').and_then(|rest| {
        let digits = rest.trim_end_matches(['d', 'w', 'b']);
        let number: u8 = digits.parse().ok()?;
        (8..=15).contains(&number).then_some(&rest[digits.len()..])
    });
    match (name, numbered) {
        (_, Some("")) => RegisterClass::General(64),
        (_, Some("d")) => RegisterClass::General(32),
        (_, Some("w")) => RegisterClass::General(16),
        (_, Some("b")) => RegisterClass::General(8),
        _ if BITS_64.contains(&name) => RegisterClass::General(64),
        _ if BITS_32.contains(&name) => RegisterClass::General(32),
        _ if BITS_16.contains(&name) => RegisterClass::General(16),
        _ if BITS_8.contains(&name) => RegisterClass::General(8),
        _ if name.starts_with("xmm") => RegisterClass::Vector('x'),
        _ if name.starts_with("ymm") => RegisterClass::Vector('y'),
        _ if name.starts_with("zmm") => RegisterClass::Vector('z'),
        _ => RegisterClass::Named(name),
    }
}

/// What a relocation of x86-64 code names of the address of data.
fn part_of_64(r_type: RelocationType) -> Option<Part> {
    use object::elf::*;
    Some(match r_type {
        R_X86_64_64 => Part::Word(Width::Eight),
        R_X86_64_32 | R_X86_64_32S => Part::Low,
        R_X86_64_PC32 => Part::FromEnd,
        _ => return None,
    })
}

/// What a relocation of 32-bit x86 code names of the address of data.
fn part_of_32(r_type: RelocationType) -> Option<Part> {
    (r_type == object::elf::R_386_32).then_some(Part::Low)
}

impl Arch for X86 {
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

    /// GNU `ld` writes the address of a `RELATIVE` relocation of x86-64
    /// into the file too, but zero for an `R_X86_64_64`, which fills the
    /// vtable of each class that a shared library exports.
    fn address_relocations(&self) -> Option<[RelocationType; 2]> {
        use object::elf::{R_386_32, R_386_RELATIVE, R_X86_64_64, R_X86_64_RELATIVE};
        match self.pointer_width() {
            8 => Some([R_X86_64_64, R_X86_64_RELATIVE]),
            _ => Some([R_386_32, R_386_RELATIVE]),
        }
    }

    fn register_class<'a>(&self, name: &'a str) -> RegisterClass<'a> {
        register_class(name)
    }

    /// Code built with `-O2` keeps a value of its own in `rbp`, and code
    /// that keeps a frame pointer there keeps its slots below it.
    fn frame_pointer(&self) -> FramePointer {
        FramePointer::FrameOrValue
    }

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

    /// The System V ABI of x86-64: `rdi`, `rsi`, `rdx`, `rcx`, `r8` and
    /// `r9`, and `rax`, or the x64 ABI of Windows. 32-bit code passes each
    /// argument on the stack.
    fn calling_convention(&self, abi: Abi) -> Option<CallingConvention> {
        const SYSTEM_V: CallingConvention = CallingConvention {
            arguments: &[
                NamedReg::new(Reg::General(7), "rdi"),
                NamedReg::new(Reg::General(6), "rsi"),
                NamedReg::new(Reg::General(2), "rdx"),
                NamedReg::new(Reg::General(1), "rcx"),
                NamedReg::new(Reg::General(8), "r8"),
                NamedReg::new(Reg::General(9), "r9"),
            ],
            result: NamedReg::new(Reg::General(0), "rax"),
            stack: Reg::Stack,
            // `rbx`, `rbp` and `r12` to `r15`.
            preserved: &[3, 5, 12, 13, 14, 15],
            stack_arguments: None,
            link: None,
        };
        /// cdecl: each argument on the stack, and the result in `eax`.
        const CDECL: CallingConvention = CallingConvention {
            arguments: &[],
            result: NamedReg::new(Reg::General(0), "eax"),
            stack: Reg::Stack,
            // `ebx`, `ebp`, `esi` and `edi`.
            preserved: &[3, 5, 6, 7],
            stack_arguments: Some(StackArguments { first: 4, width: 4 }),
            link: None,
        };
        /// The x64 ABI of Windows: `rcx`, `rdx`, `r8` and `r9`, and `rax`.
        /// It keeps `rdi` and `rsi`, which System V passes arguments in.
        const MICROSOFT_X64: CallingConvention = CallingConvention {
            arguments: &[
                NamedReg::new(Reg::General(1), "rcx"),
                NamedReg::new(Reg::General(2), "rdx"),
                NamedReg::new(Reg::General(8), "r8"),
                NamedReg::new(Reg::General(9), "r9"),
            ],
            result: NamedReg::new(Reg::General(0), "rax"),
            stack: Reg::Stack,
            // `rbx`, `rbp`, `rsi`, `rdi` and `r12` to `r15`.
            preserved: &[3, 5, 6, 7, 12, 13, 14, 15],
            stack_arguments: None,
            link: None,
        };
        Some(match (self.mode(), abi) {
            (Mode::Bits64, Abi::Unix) => SYSTEM_V,
            (Mode::Bits64, Abi::Windows) => MICROSOFT_X64,
            // cdecl and stdcall put the arguments in the same places.
            (Mode::Bits32, _) => CDECL,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
