//! The boundary between `hereticus` and whichever crate decodes machine code.
//!
//! Everything above this module works on [`Insn`] and never sees a decoder
//! type. That keeps the decoder replaceable: the normalizer and the matcher
//! do not change when the decoder does.
//!
//! [`Arch`] carries more than decoding, because more than decoding is
//! architecture specific. Which register holds the frame, which instruction
//! only keeps it, which constant is an address: the crates above cannot
//! answer any of those without knowing the architecture, so they ask here.
//! [`Arch`] builds on [`Recovery`], which `hereticus-recovery` keeps with
//! the scan that finds functions. Adding an architecture means a decoder in
//! `hereticus-il`, a file of rules in `hereticus-recovery`, and one file in
//! this crate.
//!
//! # Why operands cross this boundary as text
//!
//! [`Insn`] holds the operands as one string, and several trait methods take
//! that string back to classify it. Typed operands would be cleaner, but the
//! decoder gives text cheaply and a parsed form costs memory on every
//! instruction — a whole kernel holds about two million an image, where the
//! cost decides whether the comparison runs at all. The text stays until a
//! second decoder shows what a shared operand type would have to be.

mod aarch64;
mod arm32;
mod mips;
mod mips16;
mod thumb;
mod x86;

use hereticus_il::arch::*;
use hereticus_recovery::arch::{Memory, Recovery};

use hereticus_memory::{AddressSpace, ConstantKind, Contents};

/// The instructions that make the global pointer: see
/// [`Arch::global_pointer_setup`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalPointerSetup {
    /// The index in the body of each part, in order. Other code can sit
    /// between them, as the prologue of a frame does on MIPS.
    pub parts: Vec<usize>,
    /// The register the last part leaves the pointer in.
    pub register: String,
}

/// An architecture that `hereticus` can compare code in: the rules of
/// [`Recovery`], and the rules the matching reads, as which registers hold
/// the frame and which constants are addresses.
pub trait Arch: Recovery {
    /// Report whether a lifted register is the stack or frame pointer.
    fn is_frame_register(&self, reg: hereticus_il::Reg) -> bool {
        reg == hereticus_il::Reg::Stack
    }

    /// Report whether an instruction only maintains the stack frame.
    ///
    /// Saving registers, moving the stack pointer and spilling to a frame slot
    /// are all bookkeeping a compiler adds or removes freely.
    fn is_frame_management(&self, insn: &Insn) -> bool;

    /// Say, for each instruction of `body`, whether its constants are an
    /// address inside `space` or a value.
    ///
    /// An address moves whenever the linker moves what it points at, so
    /// comparing it reports a change on every release. Where an architecture
    /// builds an address from several instructions, only the sequence shows
    /// which constants are parts of one, so the whole body is judged at once.
    ///
    /// `code` is the bytes `body` was decoded from, for a word whose value
    /// the decoded text does not show. The result holds one entry per
    /// instruction of `body`. Defaults to [`ConstantKind::Value`] for all.
    fn constant_kinds(
        &self,
        _code: &[u8],
        body: &[Insn],
        _space: &AddressSpace,
    ) -> Vec<ConstantKind> {
        vec![ConstantKind::Value; body.len()]
    }

    /// Say whether a recovered function holds code or data.
    ///
    /// A scan cannot see where code ends and data begins, so it reads a
    /// table after the last function as more of that function. Its words
    /// decode as nonsense instructions, and every release changes thousands
    /// of them, which puts the table at the top of any report.
    ///
    /// `code` is the bytes of the function, `insns` the same decoded.
    /// Defaults to [`Contents::Code`], for an architecture with no test that
    /// tells the two apart.
    fn contents(&self, _code: &[u8], _insns: &[Insn], _space: &AddressSpace) -> Contents {
        Contents::Code
    }

    /// The length of an ABI idiom starting at `body[0]`, or 0 for none.
    ///
    /// [`Arch::is_frame_management`] judges one instruction at a time, which
    /// cannot recognize bookkeeping whose shape lives in a *sequence*. The MIPS
    /// PIC preamble is the case: `lui rX, 0x0` followed by `addiu rX, rX, 0x0`
    /// loads one link-time constant, but either word alone is an ordinary
    /// operation that real code uses, so only the pair can be dropped safely.
    ///
    /// `body` begins at the instruction being judged and runs to the end of the
    /// function, so the return value can never exceed `body.len()`.
    ///
    /// Defaults to 0, for the architectures whose bookkeeping is all
    /// recognizable one instruction at a time.
    fn idiom_length(&self, _body: &[Insn]) -> usize {
        0
    }

    /// The instructions that make the global pointer from `body[0]` on, as
    /// the PIC preamble of MIPS does, which the IL view shows as one line.
    ///
    /// Defaults to `None`, for the architectures with no global pointer.
    fn global_pointer_setup(&self, _body: &[Insn]) -> Option<GlobalPointerSetup> {
        None
    }

    /// The address each instruction of `body` forms or reads, where the
    /// code shows it: a page and the offset joined to it, as `adrp` and
    /// `add` do. A page counts as the address of its instruction. An
    /// instruction that forms none is `None`. Defaults to none for each.
    fn formed_addresses(
        &self,
        _code: &[u8],
        body: &[Insn],
        _space: &AddressSpace,
        _memory: &Memory<'_>,
    ) -> Vec<Option<u64>> {
        vec![None; body.len()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hereticus_il::arch::aarch64::Aarch64;
    use hereticus_il::arch::arm32::Arm32;
    use hereticus_il::arch::mips::Mips32;
    use hereticus_il::arch::mips16::Mips16;
    use hereticus_il::arch::thumb::Thumb2;
    use hereticus_il::arch::x86::X86;
    use hereticus_recovery::arch::decode_all;

    /// Every architecture, by name.
    const ARCHES: [(&str, &dyn Arch); 9] = [
        ("A64", &Aarch64),
        ("A32", &Arm32),
        ("T32", &Thumb2),
        ("MIPS", &Mips32::BIG),
        ("MIPSel", &Mips32::LITTLE),
        ("MIPS16e", &Mips16::BIG),
        ("MIPS16el", &Mips16::LITTLE),
        ("x86-64", &X86::BITS64),
        ("x86", &X86::BITS32),
    ];

    /// The names stay in step with the operands: a lift with names lifts
    /// what the lift alone does, with one name for each operand, and the
    /// decoder of each instruction is the one that read it.
    #[test]
    fn a_lift_names_each_operand_it_lifts() {
        bolero::check!().with_type::<[u8; 4]>().for_each(|code| {
            for (name, arch) in ARCHES {
                let (insns, _) = decode_all(arch, code, 0x1000);
                for insn in &insns {
                    let named = lift_named(insn);
                    assert_eq!(
                        named.as_ref().map(|named| &named.lifted),
                        arch.lift(insn).as_ref(),
                        "{name}: {insn}: a name changed the lift"
                    );
                    if let Some(named) = named {
                        assert_eq!(
                            named.names.len(),
                            named.lifted.operands.len(),
                            "{name}: {insn}: {:?} for {:?}",
                            named.names,
                            named.lifted.operands
                        );
                    }
                    assert!(
                        reader_of(insn).is_some() || insn.kind == InsnKind::Unknown,
                        "{name}: {insn}: no decoder"
                    );
                }
            }
        });
    }
}
