//! The rules that find functions in x86 code, in 64-bit and 32-bit mode.
//!
//! An instruction is 1 to 15 bytes, so code is read from a known start and
//! never by fixed words. x86 keeps no data among its code: a `switch` jumps
//! through a table in `.rodata`, and x86-64 code forms an address as a
//! distance from the next instruction,
//!
//! ```text
//! lea rdi, [rip + 0x2f1a]   ; the data itself
//! mov rax, [rip + 0x2fe1]   ; a slot of the global offset table
//! ```
//!
//! so that distance moves with the data it names. 32-bit code that is not
//! PIC names the address whole, as an immediate or an absolute operand. The
//! unwind tables are `.eh_frame`, which the scan reads for any architecture.

use super::{CallTarget, Insn, InsnKind, Memory, Recovery, leaves};
use hereticus_il::arch::Decoder as _;
use hereticus_il::arch::x86::{MOST_BYTES, Mode, X86, instruction, mode_of};
use hereticus_memory::AddressSpace;
use iced_x86::{Mnemonic, OpKind, Register};

/// `endbr64`, which marks where an indirect branch may land.
const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];

/// `endbr32`, the same in 32-bit code.
const ENDBR32: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfb];

/// `int3`, which clang and MSVC pad between functions with.
const INT3: u8 = 0xcc;

impl Recovery for X86 {
    /// Code built with `-fcf-protection`, the default of most Linux
    /// distributions, opens each function that a pointer can reach with
    /// `endbr64`. `push rbp` is no such mark: optimized code pushes it among
    /// the other registers a call preserves, after the first of them.
    fn is_prologue(&self, insn: &Insn) -> bool {
        is_branch_target_mark(insn)
    }

    fn may_be_prologue(&self, word: &[u8]) -> bool {
        word.starts_with(&ENDBR64) || word.starts_with(&ENDBR32)
    }

    /// `nop` in each of its lengths, `int3`, and the forms that only move a
    /// register to itself, which old GNU `as` pads 32-bit code with.
    fn is_padding(&self, insn: &Insn) -> bool {
        let Some(inst) = instruction(insn) else { return false };
        match inst.mnemonic() {
            Mnemonic::Nop | Mnemonic::Int3 => true,
            // `lea esi, [esi + 0]`, with or without a zero index.
            Mnemonic::Lea => {
                inst.op0_register() == inst.memory_base()
                    && inst.memory_displacement64() == 0
                    && inst.memory_index() == Register::None
            }
            // `mov esi, esi` is padding only in 32-bit mode: in 64-bit mode
            // it clears the upper half of `rsi`.
            Mnemonic::Mov => {
                mode_of(insn) == Some(Mode::Bits32)
                    && inst.op_count() == 2
                    && inst.op0_kind() == OpKind::Register
                    && inst.op1_kind() == OpKind::Register
                    && inst.op0_register() == inst.op1_register()
            }
            _ => false,
        }
    }

    /// A variable width cannot be read backward, so this reads forward and
    /// ends after the last instruction that is not padding.
    fn trim_padding<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        let mut end = 0;
        let mut offset = 0;
        while offset < bytes.len() {
            let Ok(insn) = self.decode(bytes, offset, 0) else { break };
            offset += insn.bytes_len;
            if !self.is_padding(&insn) {
                end = offset;
            }
        }
        // A padding byte past the last instruction that decodes is padding
        // too; anything else stays, so that no code is lost.
        if offset < bytes.len() && bytes[offset..].iter().any(|&byte| byte != INT3) {
            return bytes;
        }
        &bytes[..end]
    }

    /// The addresses each instruction forms, and the pointers it loads from
    /// a slot where they point into the image: a text that only a table of
    /// pointers reaches is a text of the function too.
    fn data_addresses(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        memory: &Memory<'_>,
    ) -> Vec<u64> {
        let width = self.pointer_width();
        body.iter()
            .filter(|insn| !matches!(insn.kind, InsnKind::Call { .. } | InsnKind::Jump { .. }))
            .filter_map(|insn| formed_address(insn, space))
            .flat_map(|address| {
                let loaded = memory
                    .bytes(address, width)
                    .map(|bytes| self.read_pointer(bytes))
                    .filter(|&pointer| pointer != address && space.contains_formed(pointer));
                core::iter::once(address).chain(loaded)
            })
            .filter(|&address| space.contains_formed(address))
            .collect()
    }

    /// A call or a jump that names its target gives it. Code built with
    /// `-fno-plt` calls an import through its slot of the global offset
    /// table, as `call [rip + slot]`.
    fn call_targets(&self, insns: &[Insn]) -> Vec<(usize, Option<CallTarget>)> {
        insns
            .iter()
            .enumerate()
            .filter_map(|(index, insn)| match insn.kind {
                InsnKind::Call { target: Some(target) } => {
                    Some((index, Some(CallTarget::Address(target))))
                }
                InsnKind::Call { target: None } => {
                    Some((index, slot_of(insn).map(CallTarget::Slot)))
                }
                InsnKind::Jump { target: Some(target) } if leaves(insns, target) => {
                    Some((index, Some(CallTarget::Address(target))))
                }
                InsnKind::Jump { target: None } => {
                    slot_of(insn).map(|slot| (index, Some(CallTarget::Slot(slot))))
                }
                _ => None,
            })
            .collect()
    }

    /// The stubs GNU `ld` and LLD write for each PLT entry: a jump through
    /// a slot of the global offset table, after `endbr64` where the code
    /// is built for it.
    ///
    /// ```text
    /// endbr64                 ; .plt.sec, with -fcf-protection
    /// bnd jmp [rip + slot]
    /// ```
    ///
    /// 32-bit PIC jumps through `[ebx + offset]`, and the address in `ebx`
    /// is not in the stub, so only the absolute form is read there.
    fn stub_slot(&self, code: &[u8], address: u64) -> Option<u64> {
        // The scan asks at the target of every jump, so bytes that open no
        // stub end the question before anything decodes.
        let skip = if self.may_be_prologue(code) { ENDBR64.len() } else { 0 };
        let jump = code.get(skip..)?;
        let opens_a_jump = matches!(jump, [0xff, 0x25, ..] | [0xf2, 0xff, 0x25, ..]);
        if !opens_a_jump {
            return None;
        }
        let jump = &jump[..jump.len().min(MOST_BYTES)];
        let insn = self.decode(jump, 0, address + skip as u64).ok()?;
        slot_of(&insn)
    }

    /// A jump through a slot of the global offset table leaves the
    /// function. A `switch` jumps through a register or a table with an
    /// index, and stays.
    fn is_tail_call(&self, insn: &Insn) -> bool {
        slot_of(insn).is_some()
    }
}

/// Whether `insn` is `endbr64` or `endbr32`.
pub fn is_branch_target_mark(insn: &Insn) -> bool {
    instruction(insn)
        .is_some_and(|inst| matches!(inst.mnemonic(), Mnemonic::Endbr64 | Mnemonic::Endbr32))
}

/// The slot a call or a jump through memory reads its target from, where
/// the slot is a fixed address: `[rip + distance]`, or an absolute address
/// with no register in 32-bit code.
pub fn slot_of(insn: &Insn) -> Option<u64> {
    if !matches!(insn.kind, InsnKind::Call { target: None } | InsnKind::Jump { target: None }) {
        return None;
    }
    let inst = instruction(insn)?;
    if inst.op0_kind() != OpKind::Memory || inst.memory_index() != Register::None {
        return None;
    }
    match inst.memory_base() {
        base if base.is_ip() => Some(inst.ip_rel_memory_address()),
        Register::None => Some(inst.memory_displacement64()),
        _ => None,
    }
}

/// The address `insn` forms or reads at, where its code shows one: a
/// distance from `rip`, which is always an address, or a constant or an
/// absolute operand inside `space`, as code that is not PIC holds.
pub fn formed_address(insn: &Insn, space: &AddressSpace) -> Option<u64> {
    let inst = instruction(insn)?;
    if inst.is_ip_rel_memory_operand() {
        return Some(inst.ip_rel_memory_address());
    }
    (0..inst.op_count()).find_map(|index| {
        let value = match inst.op_kind(index) {
            OpKind::Memory if inst.memory_base() == Register::None => inst.memory_displacement64(),
            OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate64 => {
                inst.immediate(index)
            }
            _ => return None,
        };
        let value = match mode_of(insn) {
            Some(Mode::Bits32) => value & 0xffff_ffff,
            _ => value,
        };
        space.contains(value).then_some(value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::decode_all;
    use rstest::rstest;

    fn decode(bytes: &[u8], address: u64) -> Vec<Insn> {
        decode_all(&X86::BITS64, bytes, address).0
    }

    fn one(bytes: &[u8]) -> Insn {
        X86::BITS64.decode(bytes, 0, 0x1000).expect("the bytes must decode")
    }

    #[rstest]
    #[case::endbr64(&ENDBR64, true)]
    #[case::push_rbp(&[0x55], false)]
    #[case::nop(&[0x90], false)]
    fn only_a_branch_target_mark_opens_a_function(#[case] bytes: &[u8], #[case] opens: bool) {
        assert_eq!(X86::BITS64.is_prologue(&one(bytes)), opens);
        assert_eq!(X86::BITS64.may_be_prologue(bytes), opens);
    }

    #[rstest]
    #[case::nop(&[0x90], true)]
    #[case::long_nop(&[0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00], true)]
    #[case::int3(&[0xcc], true)]
    #[case::lea_to_itself(&[0x48, 0x8d, 0x76, 0x00], true)]
    #[case::mov_to_itself_in_64_bit_mode(&[0x89, 0xf6], false)]
    #[case::push(&[0x55], false)]
    fn padding_is_work_that_changes_nothing(#[case] bytes: &[u8], #[case] padding: bool) {
        assert_eq!(X86::BITS64.is_padding(&one(bytes)), padding);
    }

    #[test]
    fn a_register_moved_to_itself_pads_only_32_bit_code() {
        let insn = X86::BITS32.decode(&[0x89, 0xf6], 0, 0x1000).expect("the bytes must decode");
        assert!(X86::BITS32.is_padding(&insn));
    }

    #[rstest]
    #[case::int3_and_nops(&[0xc3, 0xcc, 0xcc, 0x90, 0x0f, 0x1f, 0x00], 1)]
    #[case::none(&[0x55, 0xc3], 2)]
    #[case::all_padding(&[0xcc, 0xcc], 0)]
    #[case::cut_short(&[0xc3, 0xe8, 0x00], 3)]
    #[case::empty(&[], 0)]
    fn trailing_padding_is_trimmed(#[case] bytes: &[u8], #[case] kept: usize) {
        assert_eq!(X86::BITS64.trim_padding(bytes).len(), kept);
    }

    #[test]
    fn a_plt_stub_names_its_slot() {
        // 0x1000 jmp [rip + 0x2fe2], to the slot at 0x1006 + 0x2fe2.
        let lazy = [0xff, 0x25, 0xe2, 0x2f, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(X86::BITS64.stub_slot(&lazy, 0x1000), Some(0x3fe8));
        // 0x1000 endbr64; 0x1004 bnd jmp [rip + 0x2fe2]
        let marked = [0xf3, 0x0f, 0x1e, 0xfa, 0xf2, 0xff, 0x25, 0xe2, 0x2f, 0x00, 0x00];
        assert_eq!(X86::BITS64.stub_slot(&marked, 0x1000), Some(0x1004 + 7 + 0x2fe2));
        // 32-bit, not PIC: jmp [0x804a00c]
        let absolute = [0xff, 0x25, 0x0c, 0xa0, 0x04, 0x08];
        assert_eq!(X86::BITS32.stub_slot(&absolute, 0x8049000), Some(0x804_a00c));
        assert_eq!(X86::BITS64.stub_slot(&[0x55, 0xc3], 0x1000), None);
    }

    #[test]
    fn a_call_through_a_slot_names_the_slot() {
        let insns = decode(
            &[
                0xff, 0x15, 0x10, 0x00, 0x00, 0x00, // 0x1000 call [rip + 0x10]
                0xe8, 0x00, 0x00, 0x00, 0x00, //       0x1006 call 0x100b
                0xff, 0xd0, //                         0x100b call rax
                0xff, 0x25, 0x10, 0x00, 0x00, 0x00, // 0x100d jmp [rip + 0x10]
            ],
            0x1000,
        );
        assert_eq!(
            X86::BITS64.call_targets(&insns),
            [
                (0, Some(CallTarget::Slot(0x1016))),
                (1, Some(CallTarget::Address(0x100b))),
                (2, None),
                (3, Some(CallTarget::Slot(0x1023))),
            ]
        );
        assert!(X86::BITS64.is_tail_call(&insns[3]));
        assert!(!X86::BITS64.is_tail_call(&one(&[0xff, 0xe0])), "jmp rax");
    }

    #[test]
    fn data_addresses_follow_rip_and_the_pointers_in_slots() {
        let code = [
            0x48, 0x8d, 0x3d, 0xf9, 0x0f, 0x00, 0x00, // 0x1000 lea rdi, [rip + 0xff9]: 0x2000
            0x48, 0x8b, 0x05, 0xfa, 0x0f, 0x00, 0x00, // 0x1007 mov rax, [rip + 0xffa]: 0x2008
            0xb8, 0x05, 0x00, 0x00, 0x00, //             0x100e mov eax, 5
            0xc3, //                                     0x1013 ret
        ];
        let insns = decode(&code, 0x1000);
        let space = AddressSpace::from_ranges(core::iter::once(0x1000..0x3000));
        let slot = 0x2100_u64.to_le_bytes();
        let regions = [(0x2008, &slot[..])];
        assert_eq!(
            X86::BITS64.data_addresses(&code, &insns, &space, &Memory::new(&regions)),
            [0x2000, 0x2008, 0x2100]
        );
    }

    #[test]
    fn a_constant_inside_the_image_is_an_address() {
        let space = AddressSpace::from_ranges(core::iter::once(0x804_8000..0x805_0000));
        let at = |bytes: &[u8]| {
            let insn = X86::BITS32.decode(bytes, 0, 0x804_8000).expect("the bytes must decode");
            formed_address(&insn, &space)
        };
        assert_eq!(at(&[0x68, 0x00, 0x90, 0x04, 0x08]), Some(0x804_9000), "push 0x8049000");
        assert_eq!(at(&[0xa1, 0x00, 0x90, 0x04, 0x08]), Some(0x804_9000), "mov eax, [0x8049000]");
        assert_eq!(at(&[0x68, 0x05, 0x00, 0x00, 0x00]), None, "push 5");
    }
}
