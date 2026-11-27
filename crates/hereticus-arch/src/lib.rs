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
mod powerpc;
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

    /// The registers that the usual ABI of the architecture passes the
    /// arguments of a call in and gives its result in, which the high IL
    /// names by their roles.
    ///
    /// Defaults to `None`, for an architecture whose ABI the high IL does
    /// not read.
    fn calling_convention(&self, _abi: Abi) -> Option<CallingConvention> {
        None
    }

    /// The class of the register `name`: what its name says of the value
    /// it holds. Defaults to [`RegisterClass::Named`], for an architecture
    /// whose names the matching does not read.
    fn register_class<'a>(&self, name: &'a str) -> RegisterClass<'a> {
        RegisterClass::Named(name)
    }

    /// What the frame register holds. Defaults to
    /// [`FramePointer::FrameOnly`].
    fn frame_pointer(&self) -> FramePointer {
        FramePointer::FrameOnly
    }
}

/// What the name of a register says of the value it holds.
///
/// Two names of one class are a free choice of the compiler. Two of other
/// classes hold values of other widths: the fix of CVE-2021-30883 in the
/// iPhone kernel turns `mul w10, w10, w8` into `mul x10, x10, x8`, so a
/// product of 32 bits that overflowed is one of 64 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterClass<'a> {
    /// A general register of this many bits.
    General(u8),
    /// A floating point or vector register, by the letter of its kind, as
    /// `d` for a double of AArch64.
    Vector(char),
    /// A name of no class this knows, which matches only itself.
    Named(&'a str),
}

/// Whether `name` is one of the letters of `prefixes` and a number, as `x19`
/// is for the prefixes `"xw"`.
fn is_numbered(name: &str, prefixes: &str) -> bool {
    let mut characters = name.chars();
    characters.next().is_some_and(|first| prefixes.contains(first))
        && name.len() > 1
        && characters.all(|character| character.is_ascii_digit())
}

/// What the frame register of an architecture holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramePointer {
    /// Only the frame, so each place it addresses is a slot.
    FrameOnly,
    /// The frame where the code keeps one, and a value of its own where it
    /// does not, as `rbp` of x86 code built with `-O2`. Only a place below
    /// it is a slot of the frame.
    FrameOrValue,
}

/// The family of ABIs that a binary keeps, which its format tells: an x86-64
/// PE file passes its arguments as Windows does, in other registers than
/// an ELF file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Abi {
    /// The System V ABIs of ELF and Mach-O, and of a raw image.
    #[default]
    Unix,
    /// The ABIs of Windows, of a PE file.
    Windows,
}

/// A register of a [`CallingConvention`], with the name its architecture
/// gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamedReg {
    /// The register, as the lift names it.
    pub reg: hereticus_il::Reg,
    /// The name of the full register, as `x0` or `a0`.
    pub name: &'static str,
}

impl NamedReg {
    const fn new(reg: hereticus_il::Reg, name: &'static str) -> Self {
        Self { reg, name }
    }
}

/// Where the usual ABI of an architecture keeps the arguments of a call,
/// its result and the stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallingConvention {
    /// The registers of the first arguments, in order.
    pub arguments: &'static [NamedReg],
    /// The register of the result.
    pub result: NamedReg,
    /// The stack pointer, as the lift names it: MIPS lifts it as a general
    /// register.
    pub stack: hereticus_il::Reg,
    /// The numbers of the general registers that a call keeps. A call can
    /// change each other register.
    pub preserved: &'static [u8],
    /// Where the arguments that no register holds sit on the stack, where
    /// the ABI passes them there.
    pub stack_arguments: Option<StackArguments>,
    /// The register a call writes its return address to, as `lr` or `ra`,
    /// where a call writes one: a function saves it, as it saves a
    /// register that a call keeps.
    pub link: Option<hereticus_il::Reg>,
}

/// Where an ABI passes arguments on the stack: argument `n`, from 0, at
/// `first + n * width` bytes from the stack pointer at the entry, and at
/// `n * width` bytes from it at the call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackArguments {
    /// The distance of the first argument from the stack pointer at the
    /// entry, past the return address.
    pub first: i64,
    /// The bytes of each argument.
    pub width: i64,
}

impl CallingConvention {
    /// Report whether a call keeps the value of `reg`.
    pub fn preserves(&self, reg: hereticus_il::Reg) -> bool {
        match reg {
            hereticus_il::Reg::General(number) => self.preserved.contains(&number),
            hereticus_il::Reg::Stack => true,
            _ => reg == self.stack,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hereticus_il::arch::aarch64::Aarch64;
    use hereticus_il::arch::arm32::Arm32;
    use hereticus_il::arch::mips::Mips32;
    use hereticus_il::arch::mips16::Mips16;
    use hereticus_il::arch::powerpc::PowerPc;
    use hereticus_il::arch::thumb::Thumb2;
    use hereticus_il::arch::x86::X86;
    use hereticus_recovery::arch::decode_all;

    /// Every architecture, by name.
    const ARCHES: [(&str, &dyn Arch); 13] = [
        ("A64", &Aarch64),
        ("A32", &Arm32),
        ("T32", &Thumb2),
        ("MIPS", &Mips32::BIG),
        ("MIPSel", &Mips32::LITTLE),
        ("MIPS16e", &Mips16::BIG),
        ("MIPS16el", &Mips16::LITTLE),
        ("x86-64", &X86::BITS64),
        ("x86", &X86::BITS32),
        ("PowerPC", &PowerPc::BIG),
        ("PowerPCle", &PowerPc::LITTLE),
        ("PowerPC64", &PowerPc::BIG64),
        ("PowerPC64le", &PowerPc::LITTLE64),
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

    /// Each ABI passes its arguments in registers that a call can change,
    /// or on the stack, as 32-bit x86 does, and keeps the stack.
    #[test]
    fn a_calling_convention_keeps_the_stack_and_not_the_arguments() {
        for (name, arch) in ARCHES {
            let convention = arch.calling_convention(Abi::Unix).expect("each architecture has one");
            assert_eq!(
                convention.arguments.is_empty(),
                convention.stack_arguments.is_some(),
                "{name}"
            );
            let arguments: Vec<_> = convention.arguments.iter().map(|arg| arg.reg).collect();
            let distinct: std::collections::HashSet<_> = arguments.iter().collect();
            assert_eq!(distinct.len(), arguments.len(), "{name}");
            assert!(arguments.iter().all(|&reg| !convention.preserves(reg)), "{name}");
            assert!(!convention.preserves(convention.result.reg), "{name}");
            assert!(convention.preserves(convention.stack), "{name}");
            assert!(!arguments.contains(&convention.stack), "{name}");
        }
    }

    /// x86-64 code of Windows passes its arguments in `rcx`, `rdx`, `r8`
    /// and `r9`, and keeps `rdi` and `rsi`, which System V passes them in.
    #[test]
    fn x86_64_of_windows_passes_its_arguments_elsewhere() {
        let windows = X86::BITS64.calling_convention(Abi::Windows).expect("x64 has an ABI");
        let names: Vec<&str> = windows.arguments.iter().map(|arg| arg.name).collect();
        assert_eq!(names, ["rcx", "rdx", "r8", "r9"]);
        assert!(windows.preserves(hereticus_il::Reg::General(7)), "rdi");
        let unix = X86::BITS64.calling_convention(Abi::Unix).expect("x64 has an ABI");
        assert_eq!(unix.arguments[0].name, "rdi");
        assert_eq!(
            Aarch64.calling_convention(Abi::Windows),
            Aarch64.calling_convention(Abi::Unix),
            "ARM64 of Windows keeps the AAPCS64"
        );
    }

    #[test]
    fn a_register_name_tells_its_width_on_each_architecture() {
        use RegisterClass::{General, Named, Vector};
        let a64 = |name| Aarch64.register_class(name);
        assert_eq!(a64("x19"), General(64));
        assert_eq!(a64("w19"), General(32));
        assert_eq!(a64("xzr"), a64("x0"));
        assert_eq!(a64("wzr"), a64("w0"));
        assert_eq!(a64("d8"), Vector('d'));
        assert_ne!(a64("d8"), a64("s8"));
        let x64 = |name| X86::BITS64.register_class(name);
        assert_eq!(x64("rax"), x64("r12"));
        assert_eq!(x64("eax"), x64("r9d"));
        assert_ne!(x64("eax"), x64("rax"));
        assert_eq!(x64("al"), x64("r15b"));
        assert_eq!(x64("ax"), General(16));
        assert_eq!(x64("r16"), Named("r16"));
        assert_eq!(X86::BITS32.register_class("esi"), General(32));
        assert_eq!(Arm32.register_class("r4"), Thumb2.register_class("lr"));
        assert_eq!(Arm32.register_class("d16"), Vector('d'));
        assert_eq!(Mips32::LITTLE.register_class("s0"), Mips32::BIG.register_class("t9"));
        assert_eq!(Mips32::BIG.register_class("fp"), General(32));
        assert_eq!(Mips16::BIG.register_class("f12"), Vector('f'));
        assert_eq!(Mips32::BIG.register_class("hi"), Named("hi"));
        assert_eq!(
            PowerPc::BIG.register_class("r3"),
            Named("r3"),
            "names the matching does not read"
        );
    }

    #[test]
    fn only_the_frame_register_of_x86_can_hold_a_value() {
        for (name, arch) in ARCHES {
            let expected = match name {
                "x86-64" | "x86" => FramePointer::FrameOrValue,
                _ => FramePointer::FrameOnly,
            };
            assert_eq!(arch.frame_pointer(), expected, "{name}");
        }
    }
}
