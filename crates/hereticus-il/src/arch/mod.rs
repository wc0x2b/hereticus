//! What one instruction is, and the decoders that read it: A64, A32,
//! T32, MIPS32 and MIPS16e. A decoder reads one instruction at a time,
//! prints it on demand, and lifts it to the IL of this crate. It knows
//! nothing of the binary around the instruction.

pub mod aarch64;
pub mod arm32;
pub mod mips;
pub mod mips16;
pub mod mips32;
pub mod thumb;

use core::fmt;

use compact_str::CompactString;

/// What decodes and lifts the instructions of one instruction set, with
/// the facts of the set a decoder knows, as its pointer width.
pub trait Decoder {
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

    /// The name of the operation `insn` does, from its decoded opcode.
    ///
    /// What only decorates the work is left out: a compiler picks between a
    /// flag-setting form and a plain one, or puts a condition on an
    /// instruction, for reasons that do not change what it computes. One
    /// name for both is what lets them compare equal. Two names never
    /// meet across architectures, so each picks its own.
    fn operation_name(&self, insn: &Insn) -> CompactString;

    /// Lift `insn` to the intermediate language of [`crate`]. `word`
    /// holds its bytes.
    ///
    /// Defaults to `None`, for the architectures with no lifter yet. A
    /// caller treats `None` as "nothing known", never as "does nothing".
    fn lift(&self, _insn: &Insn) -> Option<crate::Lifted> {
        None
    }

    /// [`Decoder::lift`], with the name of each operand, for a reader: see
    /// [`crate::Named`].
    ///
    /// Defaults to `None`, as [`Decoder::lift`] does.
    fn lift_named(&self, _insn: &Insn) -> Option<crate::Named> {
        None
    }

    /// Adjust instructions that only their neighbours explain, once a run of
    /// them is decoded.
    ///
    /// T32 `it` makes up to four instructions after it conditional, and
    /// each of them, decoded alone, reads as if it ran always. Defaults to
    /// changing nothing.
    fn after_decoding(&self, _insns: &mut [Insn]) {}

    /// Instructions after a branch that still belong to it.
    ///
    /// A delay slot runs whether or not the branch is taken, so it is part of
    /// the instruction before it rather than the start of whatever follows.
    /// Function recovery must step over it: MIPS ends a function with
    /// `jr ra` and then unwinds the frame in the slot, and treating that
    /// unwind as a new function invents one at the end of every function.
    ///
    /// `insn` is the branch or return, because an architecture can have both
    /// kinds: MIPS `eret` leaves at once, with no slot.
    ///
    /// Defaults to 0, for the architectures that have no such slot.
    fn delay_slots(&self, _insn: &Insn) -> usize {
        0
    }

    /// Bytes in one stored pointer.
    fn pointer_width(&self) -> usize;

    /// Read one stored pointer, in this architecture's byte order.
    ///
    /// `bytes` is at least [`Decoder::pointer_width`] long.
    fn read_pointer(&self, bytes: &[u8]) -> u64;
}

/// Report whether an operand is a branch target.
///
/// Not on [`Decoder`]: the `$+0x24` form is how every decoder here names a
/// target it has resolved, not something an architecture chooses. Every
/// decoder must produce it, so every decoder can be asked about it the same
/// way.
pub fn is_branch_target(operand: &str) -> bool {
    operand.starts_with('$')
}

/// One decoded instruction, in the only detail the rest of `hereticus` needs.
///
/// [`Insn::opcode`] says what the instruction does, and everything that
/// decides by the operation reads it. `Display` prints the instruction as
/// its decoder does, for a reader: it reads the bytes again, so only the
/// diff and the IL view pay for the text. [`Insn::bytes_len`] must be
/// right: a wrong length desynchronizes every instruction that follows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Insn {
    /// Virtual address of this instruction.
    pub address: u64,
    /// Width in bytes. Fixed on some architectures, variable on others.
    pub bytes_len: usize,
    /// The bytes, in the order memory holds them, from the first:
    /// [`Insn::bytes`] gives the [`Insn::bytes_len`] of them. An
    /// instruction is four bytes at most, and a word of data among code
    /// eight.
    bytes: [u8; 8],
    /// How this instruction moves control, which the CFG builder needs.
    pub kind: InsnKind,
    /// The operation the decoder read.
    pub opcode: Opcode,
}

impl Insn {
    /// An instruction of `bytes`. Past eight bytes, only the first eight
    /// are kept.
    pub fn new(address: u64, bytes: &[u8], kind: InsnKind, opcode: Opcode) -> Self {
        let bytes_len = bytes.len();
        let mut kept = [0; 8];
        let held = bytes_len.min(kept.len());
        kept[..held].copy_from_slice(&bytes[..held]);
        Self { address, bytes_len, bytes: kept, kind, opcode }
    }

    /// The bytes of the instruction, in the order memory holds them.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.bytes_len.min(self.bytes.len())]
    }
}

/// The operation one instruction does, as its architecture names it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Opcode {
    /// No decoder named an operation: an instruction made by hand.
    #[default]
    None,
    /// Bytes the decoder of this instruction set cannot read.
    Unread(InstructionSet),
    /// A64.
    Aarch64(aarch64::Decoded),
    /// A word of data among code, as a literal pool holds, which no decoder
    /// reads as an instruction.
    Data,
    /// A32.
    Arm(arm32::Decoded),
    /// T32, which names its operations as A32 does.
    Thumb(arm32::Decoded),
    /// MIPS32, in the byte order its word was read in.
    Mips(mips::Decoded, mips::ByteOrder),
    /// MIPS16e, by the MIPS32 operation it does, or its own where it has
    /// none, in the byte order its halfwords were read in: see
    /// [`mips::Decoded`].
    Mips16(mips::Decoded, mips::ByteOrder),
}

/// The decoder that read `insn`, by its opcode, where one did.
///
/// A body can mix instruction sets, as a Thumb-2 function that goes on in
/// A32 after `bx pc`, so the decoder of the function may not be the one of
/// each instruction.
pub fn reader_of(insn: &Insn) -> Option<&'static dyn Decoder> {
    use InstructionSet as Set;
    use mips::ByteOrder;
    Some(match insn.opcode {
        Opcode::None | Opcode::Data => return None,
        Opcode::Aarch64(_) | Opcode::Unread(Set::Aarch64) => &aarch64::Aarch64,
        Opcode::Arm(_) | Opcode::Unread(Set::Arm) => &arm32::Arm32,
        Opcode::Thumb(_) | Opcode::Unread(Set::Thumb) => &thumb::Thumb2,
        Opcode::Mips(_, ByteOrder::Big) | Opcode::Unread(Set::Mips(ByteOrder::Big)) => {
            &mips::Mips32::BIG
        }
        Opcode::Mips(_, ByteOrder::Little) | Opcode::Unread(Set::Mips(ByteOrder::Little)) => {
            &mips::Mips32::LITTLE
        }
        Opcode::Mips16(_, ByteOrder::Big) | Opcode::Unread(Set::Mips16(ByteOrder::Big)) => {
            &mips16::Mips16::BIG
        }
        Opcode::Mips16(_, ByteOrder::Little) | Opcode::Unread(Set::Mips16(ByteOrder::Little)) => {
            &mips16::Mips16::LITTLE
        }
    })
}

/// [`Decoder::lift_named`] of `insn`, by the decoder that read it: see
/// [`reader_of`].
pub fn lift_named(insn: &Insn) -> Option<crate::Named> {
    reader_of(insn)?.lift_named(insn)
}

/// Whether a decoder prints what it reads. Printing costs more than
/// reading, and only a reader needs the text, so a decoder prints only on
/// demand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Printing {
    /// Read the instruction, and print nothing.
    Skip,
    /// Read the instruction, and print it too.
    Text,
}

impl Printing {
    /// The text that `print` makes, where this prints; else an empty text.
    pub fn text(self, print: impl FnOnce() -> String) -> String {
        match self {
            Self::Skip => String::new(),
            Self::Text => print(),
        }
    }
}

/// The instruction set a decoder reads, which prints what it read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstructionSet {
    /// A64.
    Aarch64,
    /// A32.
    Arm,
    /// T32.
    Thumb,
    /// MIPS32, in the byte order its words are read in.
    Mips(mips::ByteOrder),
    /// MIPS16e, in the byte order its halfwords are read in.
    Mips16(mips::ByteOrder),
}

impl Insn {
    /// The text of this instruction, read again from its bytes by the
    /// decoder that read it.
    fn printed(&self) -> String {
        use InstructionSet as Set;
        let printed = match self.opcode {
            Opcode::Data => Some(data_text(self.bytes())),
            Opcode::None => None,
            Opcode::Aarch64(_) | Opcode::Unread(Set::Aarch64) => aarch64::Aarch64
                .read(self.bytes(), 0, self.address, Printing::Text)
                .ok()
                .map(|read| read.1),
            Opcode::Arm(_) | Opcode::Unread(Set::Arm) => arm32::Arm32
                .read(self.bytes(), 0, self.address, Printing::Text)
                .ok()
                .map(|read| read.1),
            Opcode::Thumb(_) | Opcode::Unread(Set::Thumb) => thumb::print(self),
            Opcode::Mips(_, order) | Opcode::Unread(Set::Mips(order)) => mips::Mips32::of(order)
                .read(self.bytes(), 0, self.address, Printing::Text)
                .ok()
                .map(|read| read.1),
            Opcode::Mips16(_, order) | Opcode::Unread(Set::Mips16(order)) => {
                mips16::Mips16::of(mips::Mips32::of(order))
                    .read(self.bytes(), 0, self.address, Printing::Text)
                    .ok()
                    .map(|read| read.1)
            }
        };
        // An instruction made by hand has no decoder to print it.
        let printed =
            printed.unwrap_or_else(|| format!("{UNKNOWN_TEXT} {}", hex_word(self.bytes())));
        one_space(&printed)
    }
}

/// The text of bytes that no decoder reads.
const UNKNOWN_TEXT: &str = "(unknown)";

/// `text` with no space around it, and one space before the operands.
fn one_space(text: &str) -> String {
    let text = text.trim();
    match text.split_once(char::is_whitespace) {
        Some((head, tail)) if !tail.trim().is_empty() => format!("{head} {}", tail.trim()),
        Some((head, _)) => head.to_string(),
        None => text.to_string(),
    }
}

impl fmt::Display for Insn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.printed())
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
    Jump {
        /// Where it goes, where the decoder knows.
        target: Option<u64>,
    },
    /// Branches one way or falls through the other.
    Branch {
        /// Where it goes where taken, where the decoder knows.
        target: Option<u64>,
    },
    /// Calls a subroutine and expects control back.
    Call {
        /// The subroutine it calls, where the decoder knows.
        target: Option<u64>,
    },
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

/// The instructions of `code` as [`decode_all_but`] reads them, before
/// [`Decoder::after_decoding`], taking each one an earlier pass decoded at its
/// address in place of decoding it again. `earlier` holds that pass, sorted
/// by address, and the words it read as data, which decode nothing.
pub fn decode_raw(
    arch: &dyn Decoder,
    code: &[u8],
    address: u64,
    data: &std::collections::BTreeSet<u64>,
    earlier: (&[Insn], &std::collections::BTreeSet<u64>),
) -> (Vec<Insn>, Option<DecodeError>) {
    let (earlier, earlier_data) = earlier;
    let width = arch.pointer_width();
    let mut out = Vec::with_capacity(earlier.len());
    let mut offset = 0;
    let mut error = None;
    while offset < code.len() {
        let at = address + offset as u64;
        if data.contains(&at)
            && let Some(bytes) = code.get(offset..offset + width)
        {
            out.push(data_word(at, bytes));
            offset += width;
            continue;
        }
        let known = (!earlier_data.contains(&at))
            .then(|| earlier.binary_search_by_key(&at, |insn| insn.address).ok())
            .flatten()
            .map(|index| earlier[index].clone());
        match known.map_or_else(|| arch.decode(code, offset, address), Ok) {
            Ok(insn) if insn.bytes_len > 0 => {
                offset += insn.bytes_len;
                out.push(insn);
            }
            Ok(_) => {
                error = Some(DecodeError::Invalid);
                break;
            }
            Err(err) => {
                error = Some(err);
                break;
            }
        }
    }
    (out, error)
}

/// Printed text split at its first space, into the name and the operands.
///
/// Only to put text back together, as a decoder rewrites its operands:
/// nothing decides by the name.
pub(crate) fn split_printed(text: &str) -> (&str, &str) {
    match text.split_once(char::is_whitespace) {
        Some((head, tail)) => (head, tail.trim()),
        None => (text, ""),
    }
}

/// The name of `insn` as [`Insn`]'s `Display` prints it, as `ldr` or
/// `vsqrt.f64`: for a reader, as the IL view names an operation it has no
/// operator for.
pub fn printed_name(insn: &Insn) -> String {
    split_printed(&insn.to_string()).0.to_string()
}

/// The operands of `insn` as [`Insn`]'s `Display` prints them, as
/// `r0, [sp, 0x4]`. May be empty.
pub fn printed_operands(insn: &Insn) -> String {
    split_printed(&insn.to_string()).1.to_string()
}

/// A word of data among code, as one instruction no decoder reads.
pub fn data_word(at: u64, bytes: &[u8]) -> Insn {
    Insn::new(at, bytes, InsnKind::Unknown, Opcode::Data)
}

/// The text of a word of data among code, as `.word 00002000`.
fn data_text(bytes: &[u8]) -> String {
    format!(".word {}", hex_word(bytes))
}

/// `bytes`, which memory holds lowest first, as one hexadecimal number.
fn hex_word(bytes: &[u8]) -> String {
    bytes.iter().rev().map(|byte| format!("{byte:02x}")).collect()
}

/// Decode `code` one instruction after the next.
pub fn decode_linear(
    arch: &dyn Decoder,
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
            Err(err) => {
                arch.after_decoding(&mut out);
                return (out, Some(err));
            }
        }
    }

    arch.after_decoding(&mut out);
    (out, None)
}

/// [`decode_linear`], where each address in `data` holds a word of data rather
/// than an instruction.
///
/// T32 decodes by halfwords, so a literal pool word decoded as code can read
/// as a 32-bit instruction that runs into what follows, and every
/// instruction after it is then out of step. Measured on zlib for Thumb-2,
/// the upper half of a pool word joined the first halfword of the next
/// function. Such a word here is one [`InsnKind::Unknown`] as wide as a
/// pointer.
pub fn decode_all_but(
    arch: &dyn Decoder,
    code: &[u8],
    address: u64,
    data: &std::collections::BTreeSet<u64>,
) -> (Vec<Insn>, Option<DecodeError>) {
    let (mut out, error) = decode_raw(arch, code, address, data, (&[], data));
    arch.after_decoding(&mut out);
    (out, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::name_alone("nop", "nop")]
    #[case::trailing_space("ret ", "ret")]
    #[case::space_around(" add r0, r1 ", "add r0, r1")]
    #[case::many_spaces("ldr   r0, [sp]", "ldr r0, [sp]")]
    #[case::tab("mov\tr0, r1", "mov r0, r1")]
    #[case::empty("", "")]
    fn a_text_keeps_one_space_before_its_operands(#[case] text: &str, #[case] expected: &str) {
        assert_eq!(one_space(text), expected);
    }

    #[test]
    fn printing_runs_only_where_asked() {
        assert_eq!(Printing::Text.text(|| "add".to_string()), "add");
        let skipped = Printing::Skip.text(|| unreachable!("a skipped text is never made"));
        assert_eq!(skipped, "");
    }

    #[test]
    fn data_and_a_hand_made_instruction_print_their_bytes() {
        let data = data_word(0x100, &[0x00, 0x20, 0x00, 0x00]);
        assert_eq!(data.to_string(), ".word 00002000");
        let made = Insn::new(0, &[0x1f, 0x20, 0x03, 0xd5], InsnKind::Normal, Opcode::None);
        assert_eq!(made.to_string(), "(unknown) d503201f");
    }

    /// A decoder that reads at the start of its code, at a fixed address.
    type Read = fn(&[u8], Printing) -> Option<(Insn, String)>;

    /// Every decoder, by the instruction set it reads.
    const DECODERS: [(&str, Read); 7] = [
        ("A64", |code, printing| aarch64::Aarch64.read(code, 0, 0x1000, printing).ok()),
        ("A32", |code, printing| arm32::Arm32.read(code, 0, 0x1000, printing).ok()),
        ("T32", |code, printing| thumb::Thumb2.read(code, 0, 0x1000, printing).ok()),
        ("MIPS", |code, printing| mips::Mips32::BIG.read(code, 0, 0x1000, printing).ok()),
        ("MIPSel", |code, printing| mips::Mips32::LITTLE.read(code, 0, 0x1000, printing).ok()),
        ("MIPS16e", |code, printing| mips16::Mips16::BIG.read(code, 0, 0x1000, printing).ok()),
        ("MIPS16el", |code, printing| mips16::Mips16::LITTLE.read(code, 0, 0x1000, printing).ok()),
    ];

    /// Printing changes nothing a decoder reads, and `Display` prints from
    /// the bytes what the decoder printed as it read them.
    #[test]
    fn printing_changes_nothing_but_the_text() {
        bolero::check!().with_type::<[u8; 4]>().for_each(|code| {
            for (name, read) in DECODERS {
                let (Some((skipped, none)), Some((printed, text))) =
                    (read(code, Printing::Skip), read(code, Printing::Text))
                else {
                    continue;
                };
                assert_eq!(skipped, printed, "{name}: printing changed what was read");
                assert_eq!(none, "", "{name}: a skipped text was made");
                assert!(!text.trim().is_empty(), "{name}: no text for {code:02x?}");
                assert_eq!(printed.to_string(), one_space(&text), "{name}: Display differs");
            }
        });
    }
}
