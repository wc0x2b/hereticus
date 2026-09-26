//! The boundary between `hereticus` and whichever crate decodes machine code.
//!
//! Everything above this module works on [`Insn`] and never sees a decoder
//! type. That keeps the decoder replaceable: the normalizer and the matcher
//! do not change when the decoder does.
//!
//! [`Arch`] carries more than decoding, because more than decoding is
//! architecture specific. Which operand names a register, which mnemonic opens
//! a function, which word a linker pads with: the modules above cannot answer
//! any of those without knowing the architecture, so they ask here. Adding an
//! architecture means writing one file in this directory and nothing outside
//! it.
//!
//! # Why operands cross this boundary as text
//!
//! [`Insn`] holds the operands as one string, and several trait methods take
//! that string back to classify it. Typed operands would be cleaner, but the
//! decoder gives text cheaply and a parsed form costs memory on every
//! instruction — a whole kernel holds about two million an image, where the
//! cost decides whether the comparison runs at all. The text stays until a
//! second decoder shows what a shared operand type would have to be.

pub mod arm32;
pub mod mips;

use core::fmt;

use compact_str::CompactString;

use crate::address::{AddressSpace, ConstantKind};

/// An architecture that `hereticus` can decode.
///
/// The classifying methods take operands as printed, in the spelling this
/// architecture's own [`Arch::decode`] produces. An implementation answers for
/// its own output and never has to agree with another architecture's.
pub trait Arch {
    /// Decode one instruction at `offset` bytes into `code`.
    ///
    /// `address` is the virtual address of `code[0]`, so branch targets come
    /// out as virtual addresses instead of offsets into the slice.
    fn decode(&self, code: &[u8], offset: usize, address: u64) -> Result<Insn, DecodeError>;

    /// The name used to select the matching `llvm-objdump` triple in tests.
    fn triple(&self) -> &'static str;

    /// The shortest instruction, in bytes.
    ///
    /// Used to refuse an image too short to hold one. A fixed-width
    /// architecture reports its width; a variable-width one reports its
    /// minimum.
    fn instruction_width(&self) -> usize;

    /// Report whether an operand names a general register.
    fn is_register(&self, operand: &str) -> bool;

    /// Report whether an operand names the stack or frame pointer.
    ///
    /// Separate from [`Arch::is_register`] because frame work is what the
    /// normalizer drops, so the two must not be confused.
    fn is_stack_register(&self, operand: &str) -> bool;

    /// Report whether any operand reads or writes a frame slot.
    ///
    /// Takes the whole operand list, not one operand, because a frame
    /// reference is usually one bracketed group inside it.
    fn mentions_stack_slot(&self, operands: &str) -> bool;

    /// Report whether an operand is a list of registers.
    ///
    /// Defaults to `false`, for the architectures that have no such form.
    fn is_register_list(&self, _operand: &str) -> bool {
        false
    }

    /// Read a constant operand, or `None` when it is not one.
    ///
    /// Architecture specific because of the immediate sigil, which ARM prints
    /// as a leading `#`.
    fn constant_value(&self, operand: &str) -> Option<u64>;

    /// Strip whatever decorates a mnemonic without changing what it computes.
    ///
    /// A compiler picks between a flag-setting form and a plain one, or
    /// between a branch and a conditional move, for reasons that do not change
    /// the work. Reducing both to one name is what lets them compare equal.
    fn normalize_operation(&self, mnemonic: &str) -> CompactString;

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
    /// The result holds one entry per instruction of `body`. Defaults to
    /// [`ConstantKind::Value`] for all, for the architectures that reach their
    /// data through relative offsets, which normalizing already drops.
    fn constant_kinds(&self, body: &[Insn], _space: &AddressSpace) -> Vec<ConstantKind> {
        vec![ConstantKind::Value; body.len()]
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

    /// Report whether an instruction opens a function.
    ///
    /// Used to recover function starts from stripped code, so a false positive
    /// invents a function. Answer only for a shape that reliably begins one.
    fn is_prologue(&self, insn: &Insn) -> bool;

    /// How far back a function really starts, given its prologue.
    ///
    /// [`Arch::is_prologue`] names the instruction that opens a frame, but an
    /// ABI can oblige a few words before it. MIPS PIC computes the global
    /// pointer first, so the frame allocation is the second or third
    /// instruction of the function rather than the first.
    ///
    /// `earlier` holds the instructions before the prologue, closest last, so
    /// `earlier.last()` is the word immediately before it. Return how many of
    /// them belong to this function. Returning more than are there is not
    /// possible, because the slice is the bound.
    ///
    /// Defaults to 0: a prologue opens its function, which is true of every
    /// ABI that needs no preamble.
    fn preamble_before_prologue(&self, _earlier: &[Insn]) -> usize {
        0
    }

    /// Report whether an instruction is alignment padding rather than work.
    fn is_padding(&self, insn: &Insn) -> bool;

    /// Remove the alignment padding a linker put after a function.
    ///
    /// Only trailing padding is removed. Padding inside a function is not
    /// padding.
    fn trim_padding<'a>(&self, bytes: &'a [u8]) -> &'a [u8];

    /// The section holding an unwind table that lists function starts.
    ///
    /// Defaults to `None`, which skips the pass that reads it. An ABI without
    /// such a table loses only that source of function boundaries.
    fn unwind_section(&self) -> Option<&'static str> {
        None
    }

    /// Instructions after a branch that still belong to it.
    ///
    /// A delay slot runs whether or not the branch is taken, so it is part of
    /// the instruction before it rather than the start of whatever follows.
    /// Function recovery must step over it: MIPS ends a function with
    /// `jr ra` and then unwinds the frame in the slot, and treating that
    /// unwind as a new function invents one at the end of every function.
    ///
    /// Defaults to 0, for the architectures that have no such slot.
    fn delay_slots(&self) -> usize {
        0
    }

    /// Bytes in one stored pointer.
    fn pointer_width(&self) -> usize;

    /// Read one stored pointer, in this architecture's byte order.
    ///
    /// `bytes` is at least [`Arch::pointer_width`] long.
    fn read_pointer(&self, bytes: &[u8]) -> u64;
}

/// Report whether an operand is a branch target.
///
/// Not on [`Arch`]: the `$+0x24` form is how `hereticus` prints a target it has
/// resolved, not something an architecture chooses. Every decoder must produce
/// it, so every decoder can be asked about it the same way.
pub fn is_branch_target(operand: &str) -> bool {
    operand.starts_with('$')
}

/// One decoded instruction, in the only detail the rest of `hereticus` needs.
///
/// This deliberately holds the mnemonic as text and the operands as one
/// string. The normalizer works from [`Insn::kind`] and the operand text, not
/// from a full operand tree, because similarity scoring does not need exact
/// semantics. [`Insn::bytes_len`] must be right, though: a wrong length
/// desynchronizes every instruction that follows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Insn {
    /// Virtual address of this instruction.
    pub address: u64,
    /// Width in bytes. Fixed on some architectures, variable on others.
    pub bytes_len: usize,
    /// Mnemonic, lowercase, without operands. For example `ldr`.
    pub mnemonic: String,
    /// Operands as printed, for example `r0, [sp, 0x4]`. May be empty.
    pub operands: String,
    /// How this instruction moves control, which the CFG builder needs.
    pub kind: InsnKind,
}

impl fmt::Display for Insn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.operands.is_empty() {
            write!(f, "{}", self.mnemonic)
        } else {
            write!(f, "{} {}", self.mnemonic, self.operands)
        }
    }
}

/// How an instruction moves control flow.
///
/// The CFG builder ends a basic block on everything except [`InsnKind::Normal`]
/// and [`InsnKind::Unknown`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsnKind {
    /// Falls through to the next instruction.
    Normal,
    /// The decoder cannot read these bytes, so treat them as opaque.
    ///
    /// The bytes are still counted, which keeps the instructions after them
    /// aligned. Two causes look the same here: an extension the decoder does
    /// not implement, such as NEON, and data stored inside the code. Both are
    /// safer to step over than to stop on, so a diff of a function holding
    /// either still reports the parts that are readable.
    Unknown,
    /// Branches away and never falls through.
    Jump { target: Option<u64> },
    /// Branches one way or falls through the other.
    Branch { target: Option<u64> },
    /// Calls a subroutine and expects control back.
    Call { target: Option<u64> },
    /// Leaves the function.
    Return,
}

/// Why an instruction could not be decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The bytes are not a valid instruction.
    Invalid,
    /// The slice ends in the middle of an instruction.
    Truncated,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => write!(f, "invalid instruction"),
            Self::Truncated => write!(f, "truncated instruction"),
        }
    }
}

impl core::error::Error for DecodeError {}

/// Decode `code` from start to end, stopping at the first error.
///
/// Returns what it decoded and the error that stopped it, if any. Callers keep
/// the partial result because a function can end with data the decoder cannot
/// read.
pub fn decode_all(arch: &dyn Arch, code: &[u8], address: u64) -> (Vec<Insn>, Option<DecodeError>) {
    let mut out = Vec::new();
    let mut offset = 0;

    while offset < code.len() {
        match arch.decode(code, offset, address) {
            Ok(insn) => {
                // A zero width would loop forever. No decoder should report
                // one, so treat it as a decoder bug rather than bad input.
                debug_assert!(insn.bytes_len > 0, "decoder reported a zero-width instruction");
                if insn.bytes_len == 0 {
                    return (out, Some(DecodeError::Invalid));
                }
                offset += insn.bytes_len;
                out.push(insn);
            }
            Err(err) => return (out, Some(err)),
        }
    }

    (out, None)
}
