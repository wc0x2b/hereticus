//! The boundary between `tech-heresy` and whichever crate decodes machine code.
//!
//! Everything above this module works on [`Insn`] and never sees a decoder
//! type. That keeps the decoder replaceable: the normalizer and the matcher
//! do not change when the decoder does.

pub mod arm32;

use core::fmt;

/// An architecture that `tech-heresy` can decode.
pub trait Arch {
    /// Decode one instruction at `offset` bytes into `code`.
    ///
    /// `address` is the virtual address of `code[0]`, so branch targets come
    /// out as virtual addresses instead of offsets into the slice.
    fn decode(&self, code: &[u8], offset: usize, address: u64) -> Result<Insn, DecodeError>;

    /// The name used to select the matching `llvm-objdump` triple in tests.
    fn triple(&self) -> &'static str;
}

/// One decoded instruction, in the only detail the rest of `tech-heresy` needs.
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
    /// Width in bytes. ARM32 is always 4, but Thumb and x86 vary.
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
pub fn decode_all<A: Arch>(
    arch: &A,
    code: &[u8],
    address: u64,
) -> (Vec<Insn>, Option<DecodeError>) {
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
