//! MIPS32 decoding, little endian, on top of `rabbitizer`.
//!
//! Three details shape this module, and the rest of `hereticus` sees none of
//! them:
//!
//! 1. `rabbitizer` renders registers with a `$` sigil and pads the mnemonic
//!    to a column. Both are stripped here, because `hereticus` reserves a
//!    leading `$` for a branch target and compares operand text directly.
//! 2. MIPS ships in both byte orders and a whole image is one of them, so
//!    [`Mips32`] carries which. Reading at the wrong order does not fail:
//!    every word still decodes, into a different instruction. An ELF says
//!    which it is; a raw image is told by the caller.
//! 3. A MIPS branch counts its offset from the *delay slot*, and `j` and
//!    `jal` hold an address rather than a distance. `rabbitizer` resolves
//!    both, so neither correction is made here.

use compact_str::CompactString;
use rabbitizer::{
    Instruction, InstructionDisplayFlags, InstructionFlags, IsaVersion, Vram, opcodes::Opcode,
};

use super::{Arch, DecodeError, Insn, InsnKind};
use crate::address::{AddressSpace, ConstantKind, Contents};

/// Every MIPS32 instruction is 4 bytes wide.
const INSN_WIDTH: usize = 4;

/// Mnemonic reported for bytes the decoder cannot read.
const UNKNOWN_MNEMONIC: &str = "(unknown)";

/// The instruction set this decoder reads.
///
/// MIPS II covers most of what a compiler emits for a 32-bit target. The
/// MIPS32 and Release 2 words it refuses are read by [`super::mips32`]
/// instead, which leaves every word MIPS II reads as it was.
const ISA: IsaVersion = IsaVersion::MIPS_II;

/// The byte order a word is stored in.
///
/// MIPS ships in both, and a whole image is one or the other. Reading an
/// image at the wrong order does not fail: every word still decodes, into a
/// different instruction, so the order has to be known rather than guessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    /// `mipsel`, as a desktop-built object usually is.
    Little,
    /// `mips`, as most shipped firmware is.
    Big,
}

impl ByteOrder {
    /// Assemble one stored word.
    fn read_word(self, bytes: [u8; INSN_WIDTH]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }
}

/// MIPS32, in either byte order.
#[derive(Clone, Copy, Debug)]
pub struct Mips32 {
    order: ByteOrder,
}

impl Mips32 {
    /// The decoder for a little-endian image.
    pub const LITTLE: Self = Self { order: ByteOrder::Little };
    /// The decoder for a big-endian image, which most firmware is.
    pub const BIG: Self = Self { order: ByteOrder::Big };
}

impl Arch for Mips32 {
    fn decode(&self, code: &[u8], offset: usize, address: u64) -> Result<Insn, DecodeError> {
        let bytes = code.get(offset..).ok_or(DecodeError::Truncated)?;
        if bytes.len() < INSN_WIDTH {
            return Err(DecodeError::Truncated);
        }

        let insn_address = address + offset as u64;
        let word = &bytes[..INSN_WIDTH];
        let raw = self.order.read_word([word[0], word[1], word[2], word[3]]);

        // `new_checked` rejects a word it cannot read rather than reading it
        // as something else, which is what makes stepping over the word safe.
        let decoded = Instruction::new_checked(
            raw,
            Vram::new(insn_address as u32),
            InstructionFlags::new(ISA),
        );

        let Some(inst) = decoded else {
            // `rabbitizer` stops at MIPS IV, so a MIPS32 word it refuses may
            // still be one this crate reads. None of these move control.
            if let Some((mnemonic, operands)) = super::mips32::decode(raw) {
                return Ok(Insn {
                    address: insn_address,
                    bytes_len: INSN_WIDTH,
                    mnemonic: mnemonic.to_string(),
                    operands,
                    kind: InsnKind::Normal,
                });
            }

            // Stepping over an unreadable word keeps everything after it
            // aligned, because every instruction is the same width. The raw
            // word goes in the operand field so that two unreadable words
            // still compare as different.
            return Ok(Insn {
                address: insn_address,
                bytes_len: INSN_WIDTH,
                mnemonic: UNKNOWN_MNEMONIC.to_string(),
                operands: format!("{raw:#010x}"),
                kind: InsnKind::Unknown,
            });
        };

        let text =
            inst.display::<&str>(&InstructionDisplayFlags::new_gnu_as(), None, 0).to_string();
        let (mnemonic, mut operands) = split_mnemonic(&text);
        let kind = classify(&inst);

        // `rabbitizer` names a jump target as a label, such as
        // `func_80001000`, and a branch target as an expression, such as
        // `. + 4 + (0x7 << 2)`. Every decoder prints a resolved target in the
        // `$` form instead, which is how the rest of `hereticus` knows it
        // moves with the code rather than coming from the source.
        //
        // A branch is written from its offset rather than its target, which
        // cannot be resolved when it would lie below address zero.
        if let Some(offset) = inst.get_branch_offset() {
            operands = with_target(&operands, i64::from(offset.inner()));
        } else if let InsnKind::Call { target: Some(target) }
        | InsnKind::Jump { target: Some(target) } = kind
        {
            operands = with_target(&operands, target.wrapping_sub(insn_address) as i64);
        }

        Ok(Insn { address: insn_address, bytes_len: INSN_WIDTH, mnemonic, operands, kind })
    }

    fn triple(&self) -> &'static str {
        match self.order {
            ByteOrder::Little => "mipsel",
            ByteOrder::Big => "mips",
        }
    }

    fn instruction_width(&self) -> usize {
        INSN_WIDTH
    }

    fn is_register(&self, operand: &str) -> bool {
        is_register_name(operand)
    }

    fn is_stack_register(&self, operand: &str) -> bool {
        // `fp` is the frame pointer, which MIPS also calls `s8`.
        matches!(operand.trim(), "sp" | "fp" | "s8")
    }

    fn mentions_stack_slot(&self, operands: &str) -> bool {
        // A frame reference prints as `0x4(sp)`, so the register sits in
        // parentheses rather than in brackets as it does on ARM.
        operands.contains("(sp)") || operands.contains("(fp)") || operands.contains("(s8)")
    }

    fn constant_value(&self, operand: &str) -> Option<u64> {
        let text = operand.trim();
        if text.is_empty() {
            return None;
        }

        // A frame or object reference holds a constant, but that constant is
        // an offset that moves with unrelated edits. A branch target is not a
        // constant either.
        if text.contains('(') || text.contains(')') || text.starts_with('$') {
            return None;
        }

        // A negative immediate prints as `-0x1`.
        let (negative, digits) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text),
        };

        let value = match digits.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).ok()?,
            None => digits.parse::<u64>().ok()?,
        };

        // Negative immediates are compared as their two's complement form, so
        // that a constant keeps one spelling however it is printed.
        Some(if negative { (value as i64).wrapping_neg() as u64 } else { value })
    }

    /// MIPS mnemonics carry no condition or flag-setting suffix: the compare is
    /// part of the operation, as in `beq` against `bne`. So a name mostly passes
    /// through unchanged.
    ///
    /// The exception is the unconditional jump, which MIPS spells two ways. `j`
    /// holds an absolute address and `b` a distance from here, and a compiler
    /// picks between them on grounds that have nothing to do with the source: a
    /// PIC build must stay position independent, so it emits `b` where the same
    /// code built without PIC emits `j`. Measured on the PIC corpus the two
    /// account for six jumps each way, and they normalize alike in every other
    /// respect — one operand, `Jump` flow — so only the name kept them apart.
    ///
    /// A conditional branch is untouched. `beq` and `bne` differ in the test
    /// they apply, which is the source's decision and must keep them apart.
    fn normalize_operation(&self, mnemonic: &str) -> CompactString {
        match mnemonic.trim() {
            "j" | "b" => "jump".into(),
            other => other.into(),
        }
    }

    fn is_frame_management(&self, insn: &Insn) -> bool {
        // The PIC preamble is bookkeeping in the same sense frame work is: the
        // ABI obliges it, the source never asked for it, and it appears in
        // every function a PIC build compiles.
        if is_pic_setup(insn) {
            return true;
        }

        let operands = insn.operands.as_str();
        let first = operands.split(',').next().unwrap_or_default().trim();

        match insn.mnemonic.as_str() {
            // Moving the stack pointer, or setting up the frame pointer.
            // `or fp, sp, zero` is how a frame is established: this decoder
            // renders every register move as `or`, never as `move`.
            "addiu" | "addu" | "subu" | "or" => self.is_stack_register(first),

            // Spilling to and reloading from the frame.
            "sw" | "lw" | "swc1" | "lwc1" | "sd" | "ld" => self.mentions_stack_slot(operands),

            _ => false,
        }
    }

    /// The `_gp_disp` pair is the one piece of PIC scaffolding that needs two
    /// instructions to recognize.
    ///
    /// `lui rX, 0x0` on its own is how any relocated address load begins, and
    /// `addiu rX, rX, 0x0` on its own adds zero to a register. Dropping either
    /// alone would take real code with it, so only the pair comes out — and
    /// only where an `addu` against `t9` proves it is the PIC preamble rather
    /// than the address of a global.
    fn idiom_length(&self, body: &[Insn]) -> usize {
        if is_gp_disp_preamble(body) { 2 } else { 0 }
    }

    /// MIPS builds a 32-bit address in two halves: `lui rX, hi` loads the
    /// upper sixteen bits, and a later `addiu rY, rX, lo` or `ori` adds the
    /// lower sixteen. The two are often far apart, with other work between,
    /// so each register is followed from its `lui` to its uses.
    ///
    /// A `lui` whose upper half reaches into `space` is an address. So is a
    /// lower half that, joined to the address in its source register, lands in
    /// `space`, and so is a load or store whose offset is that lower half.
    ///
    /// Forward branches are followed, so code after a return that a branch
    /// reaches still knows what its registers hold. A loop is followed only on
    /// its way in.
    fn constant_kinds(&self, body: &[Insn], space: &AddressSpace) -> Vec<ConstantKind> {
        let mut kinds = vec![ConstantKind::Value; body.len()];
        if space.is_empty() {
            return kinds;
        }

        let mut upper = HeldAddresses::default();
        // What runs after the current delay slot, as the previous instruction
        // decided.
        let mut after_slot = AfterSlot::FallThrough;
        let mut reachable = Reach::FromAbove;
        // The addresses held on arrival at each forward branch target seen so
        // far.
        let mut at_target: Vec<(u64, HeldAddresses<'_>)> = Vec::new();

        for (index, insn) in body.iter().enumerate() {
            upper = arrive(upper, reachable, take_state(&mut at_target, insn.address));
            reachable = Reach::FromAbove;

            if let Some((register, high)) = upper_half(insn) {
                if space.overlaps(reach_of_upper_half(high)) {
                    kinds[index] = ConstantKind::Address;
                }
                upper.set(register, high);
            } else if let Some((destination, address)) = lower_half(insn, &upper) {
                // The destination now holds the whole address, and code
                // reaches the fields of a global through it as it would
                // through the upper half.
                if space.contains(address) {
                    kinds[index] = ConstantKind::Address;
                    upper.set(destination, address);
                } else {
                    upper.forget(destination);
                }
            } else if let Some((written, address)) = memory_reference(insn, &upper) {
                if space.contains(address) {
                    kinds[index] = ConstantKind::Address;
                }
                if let Some(written) = written {
                    upper.forget(written);
                }
            } else if !is_store(&insn.mnemonic)
                && let Some(written) = insn.operands.split(',').next()
            {
                upper.forget(written.trim());
            }

            // The delay slot runs before control moves, and compilers put the
            // lower half of an argument address there, so a transfer takes
            // effect only once its slot has run.
            match after_slot {
                AfterSlot::FallThrough => {}
                AfterSlot::Call => upper.keep_only(is_callee_saved),
                AfterSlot::Branch(target) => record_state(&mut at_target, target, &upper),
                AfterSlot::Leave(target) => {
                    if let Some(target) = target {
                        record_state(&mut at_target, target, &upper);
                    }
                    reachable = Reach::OnlyByBranch;
                }
            }
            after_slot = AfterSlot::of(insn);
        }

        kinds
    }

    /// A compiler keeps no data among MIPS instructions: constants are built
    /// with `lui` and literal pools do not exist. So a long function where
    /// many words are data is mostly not a function. Two shapes give it away:
    ///
    /// * Words that do not decode, or that hold an address inside the image.
    ///   A pointer inside a KSEG0 image reads as `lb rX, off(zero)`, which no
    ///   compiler emits. At least two words in five mark data.
    /// * Zero fill, which reads as `nop`. At least half the words mark data.
    ///
    /// Below 64 words a function is not judged: short code can look like
    /// anything, and every region of data measured was far longer. On two
    /// OpenWrt MIPS kernels, code of 64 words or more reaches at most 19% of
    /// the first and 25% of the second, and the regions of tables and zero
    /// fill after the code start at 44% and 67%. None of the compiled fixture
    /// functions is marked.
    fn contents(&self, code: &[u8], insns: &[Insn], space: &AddressSpace) -> Contents {
        const FEWEST_WORDS: usize = 64;

        let words = insns.len();
        if words < FEWEST_WORDS {
            return Contents::Code;
        }

        let unreadable = insns.iter().filter(|insn| insn.kind == InsnKind::Unknown).count();
        let pointers = code
            .chunks_exact(INSN_WIDTH)
            .filter(|word| space.contains(self.read_pointer(word)))
            .count();
        let zeros = insns.iter().filter(|insn| self.is_padding(insn)).count();

        if (unreadable + pointers) * 5 >= words * 2 || zeros * 2 >= words {
            Contents::Data
        } else {
            Contents::Code
        }
    }

    /// A function that needs a frame opens by making room for it, so
    /// `addiu sp, sp, -N` is the first instruction of almost every one.
    ///
    /// Saving the return address was tried first and reports the start late.
    /// A prologue saves several registers and `sw ra` can be any of them: on
    /// a stripped MIPS kernel, 2593 of 13362 saved return addresses follow
    /// another register save, so the function had already begun. Allocating
    /// the frame cannot be preceded that way, and it appears 13426 times
    /// against 13362, so it also catches a leaf that makes room without
    /// calling anything.
    fn is_prologue(&self, insn: &Insn) -> bool {
        if insn.mnemonic != "addiu" {
            return false;
        }

        // `addiu sp, sp, -N`: the stack pointer is both the destination and
        // the source, and the immediate is negative. A positive immediate is
        // the matching unwind at the end of a function.
        let mut operands = insn.operands.split(',').map(str::trim);
        let (Some("sp"), Some("sp"), Some(immediate)) =
            (operands.next(), operands.next(), operands.next())
        else {
            return false;
        };

        immediate.starts_with('-')
    }

    /// Under PIC the `_gp_disp` pair sits before the frame allocation, so the
    /// function starts two words earlier than its prologue.
    ///
    /// Measured on a stripped PIC object: without this, five of eight function
    /// starts land 8 bytes late, because `lui`/`addiu` open the function and
    /// the frame allocation follows them.
    ///
    /// The pair's shape is enough here, with no need to find the `addu` that
    /// [`is_gp_disp_preamble`] insists on. This is asked only about the two
    /// words immediately before a frame prologue, and code that loads the
    /// address of a global does so to use it, not to open a frame. Either
    /// reading also names a start inside the same function, so the cost of
    /// being wrong is a boundary 8 bytes out rather than a dropped
    /// instruction.
    fn preamble_before_prologue(&self, earlier: &[Insn]) -> usize {
        let [.., high, low] = earlier else { return 0 };

        if constant_pair_register(high, low).is_some() { 2 } else { 0 }
    }

    fn is_padding(&self, insn: &Insn) -> bool {
        // A zero word decodes as `nop` on MIPS, so unlike ARM one test covers
        // both the encoding a linker pads with and the named instruction.
        insn.mnemonic == "nop"
    }

    fn trim_padding<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        /// `nop` and zero are the same word on MIPS: `sll zero, zero, 0`. Zero
        /// reads the same in either byte order.
        const NOP: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

        let mut end = bytes.len();
        while end >= INSN_WIDTH {
            if bytes[end - INSN_WIDTH..end] == NOP {
                end -= INSN_WIDTH;
            } else {
                break;
            }
        }

        // A `nop` in the delay slot of the last branch is part of the
        // function, not padding. The symbol table includes it, so a scan must
        // too, or a scanned function differs from the same function read from
        // its symbol by one word.
        let trimmed_a_slot = end < bytes.len()
            && end >= INSN_WIDTH
            && self
                .decode(bytes, end - INSN_WIDTH, 0)
                .is_ok_and(|insn| insn.kind != InsnKind::Normal && insn.kind != InsnKind::Unknown);
        if trimmed_a_slot {
            end += INSN_WIDTH;
        }

        &bytes[..end]
    }

    /// MIPS runs the instruction after a branch whether or not the branch is
    /// taken, so that instruction belongs to the branch.
    fn delay_slots(&self) -> usize {
        1
    }

    fn pointer_width(&self) -> usize {
        INSN_WIDTH
    }

    fn read_pointer(&self, bytes: &[u8]) -> u64 {
        u64::from(self.order.read_word([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

/// Replace the last operand, which names the target, with the `$` form.
///
/// `distance` runs from the instruction to its target, which is how the ARM
/// decoder writes a target too.
fn with_target(operands: &str, distance: i64) -> String {
    let written = if distance < 0 {
        format!("$-{:#x}", distance.unsigned_abs())
    } else {
        format!("$+{distance:#x}")
    };
    match operands.rsplit_once(',') {
        Some((head, _)) => format!("{head}, {written}"),
        None => written,
    }
}

/// Split rendered instruction text into the mnemonic and the rest.
///
/// `rabbitizer` pads the mnemonic to a fixed column and writes every register
/// with a `$` sigil. The padding is noise, and the sigil would collide with
/// the `$+0x24` that `hereticus` reserves for a branch target, so both go.
fn split_mnemonic(text: &str) -> (String, String) {
    match text.split_once(char::is_whitespace) {
        Some((head, tail)) => (head.to_string(), tail.trim().replace('$', "")),
        None => (text.to_string(), String::new()),
    }
}

/// The register a `lui`/`addiu` pair builds a link-time constant in, if the two
/// instructions are such a pair.
///
/// ```text
/// lui   v0, 0x0
/// addiu v0, v0, 0x0
/// ```
///
/// Both immediates read as zero because the linker has yet to fill them in, and
/// both words name one register. That shape alone does **not** mean PIC: a
/// non-PIC build loads the address of a global exactly this way, so the caller
/// must confirm what consumes the result. See [`is_gp_disp_preamble`].
fn constant_pair_register<'a>(high: &'a Insn, low: &Insn) -> Option<&'a str> {
    if high.mnemonic != "lui" || low.mnemonic != "addiu" {
        return None;
    }

    let mut high_operands = high.operands.split(',').map(str::trim);
    let (Some(loaded), Some("0x0"), None) =
        (high_operands.next(), high_operands.next(), high_operands.next())
    else {
        return None;
    };

    // `addiu rX, rX, 0x0` must add into the very register `lui` just wrote,
    // or the two words are unrelated.
    let mut low_operands = low.operands.split(',').map(str::trim);
    let (Some(destination), Some(source), Some("0x0"), None) =
        (low_operands.next(), low_operands.next(), low_operands.next(), low_operands.next())
    else {
        return None;
    };

    (destination == loaded && source == loaded).then_some(loaded)
}

/// Report whether `body` opens with the `_gp_disp` preamble of a PIC function.
///
/// The `lui`/`addiu` pair by itself is ambiguous. Compiled without PIC,
///
/// ```c
/// extern int table[64];
/// int read_global(int i) { return table[i & 63]; }
/// ```
///
/// opens with `lui at, 0x0` then `addiu at, at, 0x0` — the same two words, the
/// same zero immediates, loading the address of `table`. Dropping the pair on
/// its shape alone therefore deletes a real memory reference from ordinary
/// code, and a function that reads one global would compare equal to one that
/// reads another.
///
/// What separates them is the consumer. A PIC preamble exists to be joined to
/// the callee address the ABI leaves in `t9`:
///
/// ```text
/// lui   v0, 0x0
/// addiu v0, v0, 0x0
/// addu  gp, v0, t9     ; only PIC does this
/// ```
///
/// A data load instead indexes or dereferences the address it built. So the
/// pair counts as PIC only when an `addu` that reads both the loaded register
/// and `t9` follows it. The two need not be adjacent: a compiler puts the frame
/// prologue between them, which is why a window is searched rather than the
/// next word alone.
fn is_gp_disp_preamble(body: &[Insn]) -> bool {
    /// How far to look for the `addu` that consumes the pair. Measured on the
    /// PIC fixtures the consumer is between zero and six instructions on,
    /// separated by the frame prologue; eight leaves margin without reaching
    /// into unrelated code.
    const MOST_WORDS_TO_CONSUMER: usize = 8;

    let [high, low, rest @ ..] = body else { return false };
    let Some(loaded) = constant_pair_register(high, low) else { return false };

    rest.iter().take(MOST_WORDS_TO_CONSUMER).any(|insn| joins_to_callee_address(insn, loaded))
}

/// What an instruction does to control flow once its delay slot has run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AfterSlot {
    /// Nothing: the next instruction runs next.
    FallThrough,
    /// A call returns here, with the argument and temporary registers
    /// clobbered and the saved ones restored.
    Call,
    /// A conditional branch goes forward to this address or falls through.
    Branch(u64),
    /// A jump or return: the next instruction runs only if a branch reaches
    /// it. A jump forward to a known address carries it.
    Leave(Option<u64>),
}

impl AfterSlot {
    fn of(insn: &Insn) -> Self {
        // A backward target is a loop, which is entered from above; its state
        // on the way back round is not followed.
        let forward = |target: Option<u64>| target.filter(|&target| target > insn.address);
        match insn.kind {
            InsnKind::Call { .. } => Self::Call,
            InsnKind::Branch { target } => match forward(target) {
                Some(target) => Self::Branch(target),
                None => Self::FallThrough,
            },
            InsnKind::Jump { target } => Self::Leave(forward(target)),
            InsnKind::Return => Self::Leave(None),
            InsnKind::Normal | InsnKind::Unknown => Self::FallThrough,
        }
    }
}

/// How control can reach an instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reach {
    /// The instruction before runs into it, and branches may join it too.
    FromAbove,
    /// The instruction before leaves, so only a branch reaches it.
    OnlyByBranch,
}

/// The addresses held on arrival at an instruction.
///
/// Where two paths join, only the addresses both agree on survive. Where only
/// a branch arrives, its addresses are the ones held. Where no branch is
/// known to arrive, as at a case of a jump table, nothing is held.
fn arrive<'a>(
    above: HeldAddresses<'a>,
    reach: Reach,
    branched: Option<HeldAddresses<'a>>,
) -> HeldAddresses<'a> {
    match (reach, branched) {
        (Reach::FromAbove, None) => above,
        (Reach::FromAbove, Some(branched)) => above.agreed_with(&branched),
        (Reach::OnlyByBranch, Some(branched)) => branched,
        (Reach::OnlyByBranch, None) => HeldAddresses::default(),
    }
}

/// Merge the addresses held on a branch to `target` into those recorded.
fn record_state<'a>(
    at_target: &mut Vec<(u64, HeldAddresses<'a>)>,
    target: u64,
    upper: &HeldAddresses<'a>,
) {
    match at_target.iter_mut().find(|(address, _)| *address == target) {
        Some((_, recorded)) => *recorded = recorded.agreed_with(upper),
        None => at_target.push((target, upper.clone())),
    }
}

/// Remove and return the addresses recorded for branches to `address`.
fn take_state<'a>(
    at_target: &mut Vec<(u64, HeldAddresses<'a>)>,
    address: u64,
) -> Option<HeldAddresses<'a>> {
    let position = at_target.iter().position(|(target, _)| *target == address)?;
    Some(at_target.swap_remove(position).1)
}

/// The registers that hold an address: an upper half loaded by `lui`, or a
/// whole address built from one.
///
/// A function holds a handful at a time, so a list beats a map.
#[derive(Clone, Debug, Default)]
struct HeldAddresses<'a> {
    held: Vec<(&'a str, u64)>,
}

impl<'a> HeldAddresses<'a> {
    fn set(&mut self, register: &'a str, value: u64) {
        self.forget(register);
        self.held.push((register, value));
    }

    fn get(&self, register: &str) -> Option<u64> {
        self.held.iter().find(|(held, _)| *held == register).map(|&(_, value)| value)
    }

    fn forget(&mut self, register: &str) {
        self.held.retain(|(held, _)| *held != register);
    }

    fn keep_only(&mut self, survives: fn(&str) -> bool) {
        self.held.retain(|(held, _)| survives(held));
    }

    /// The addresses this and `other` both hold, with the same value.
    fn agreed_with(&self, other: &Self) -> Self {
        let held = self
            .held
            .iter()
            .filter(|&&(register, value)| other.get(register) == Some(value))
            .copied()
            .collect();
        Self { held }
    }
}

/// Report whether the o32 ABI makes a callee restore a register.
fn is_callee_saved(register: &str) -> bool {
    matches!(
        register,
        "s0" | "s1" | "s2" | "s3" | "s4" | "s5" | "s6" | "s7" | "gp" | "sp" | "fp" | "s8"
    )
}

/// Read `lui rX, hi` as the register and the value it loads.
fn upper_half(insn: &Insn) -> Option<(&str, u64)> {
    if insn.mnemonic != "lui" {
        return None;
    }
    let mut operands = insn.operands.split(',').map(str::trim);
    let (Some(register), Some(immediate), None) =
        (operands.next(), operands.next(), operands.next())
    else {
        return None;
    };
    let high = Mips32::LITTLE.constant_value(immediate)?;
    Some((register, (high & 0xffff) << 16))
}

/// The addresses a `lui` can start, once any lower half is added.
///
/// `addiu` adds a signed lower half, so the address can sit up to 32 KiB
/// below the upper half as well as up to 32 KiB above it. `ori` reaches up to
/// 64 KiB above.
fn reach_of_upper_half(high: u64) -> core::ops::Range<u64> {
    high.saturating_sub(0x8000)..high + 0x1_0000
}

/// Read `addiu rY, rX, lo` or `ori rY, rX, lo`, where `rX` holds an
/// address, as the destination and the full address.
fn lower_half<'a>(insn: &'a Insn, upper: &HeldAddresses<'_>) -> Option<(&'a str, u64)> {
    if insn.mnemonic != "addiu" && insn.mnemonic != "ori" {
        return None;
    }
    let mut operands = insn.operands.split(',').map(str::trim);
    let (Some(destination), Some(source), Some(immediate), None) =
        (operands.next(), operands.next(), operands.next(), operands.next())
    else {
        return None;
    };
    let high = upper.get(source)?;
    let low = Mips32::LITTLE.constant_value(immediate)?;

    // A negative `addiu` immediate reads as a 64-bit two's complement, so
    // wrapping arithmetic on 32 bits gives the address the processor forms.
    let address = if insn.mnemonic == "ori" {
        high | (low & 0xffff)
    } else {
        u64::from((high as u32).wrapping_add(low as u32))
    };
    Some((destination, address))
}

/// Read a load or store through a register that holds an address, as the
/// register the load writes and the full address it reaches.
///
/// A store writes no register, so it gives `None` for the first.
fn memory_reference<'a>(
    insn: &'a Insn,
    upper: &HeldAddresses<'_>,
) -> Option<(Option<&'a str>, u64)> {
    let (first, reference) = insn.operands.split_once(',')?;
    let (offset, base) = reference.trim().strip_suffix(')')?.split_once('(')?;
    let high = upper.get(base.trim())?;
    let low = Mips32::LITTLE.constant_value(offset)?;

    let address = u64::from((high as u32).wrapping_add(low as u32));
    let written = (!is_store(&insn.mnemonic)).then(|| first.trim());
    Some((written, address))
}

/// Report whether an instruction stores, which reads its first operand
/// rather than writing it.
fn is_store(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "sb" | "sh"
            | "sw"
            | "swl"
            | "swr"
            | "sc"
            | "sd"
            | "sdl"
            | "sdr"
            | "scd"
            | "swc1"
            | "sdc1"
            | "swc2"
            | "sdc2"
    )
}

/// Report whether an instruction is `addu rD, loaded, t9` in either operand
/// order, which is what forms the PIC global pointer.
fn joins_to_callee_address(insn: &Insn, loaded: &str) -> bool {
    /// The register the ABI leaves the callee address in.
    const CALLEE_ADDRESS: &str = "t9";

    if insn.mnemonic != "addu" {
        return false;
    }

    let mut operands = insn.operands.split(',').map(str::trim);
    let (_destination, Some(left), Some(right), None) =
        (operands.next(), operands.next(), operands.next(), operands.next())
    else {
        return false;
    };

    (left == loaded && right == CALLEE_ADDRESS) || (left == CALLEE_ADDRESS && right == loaded)
}

/// Report whether an instruction only establishes the PIC global pointer.
///
/// MIPS ABI PIC opens every function that calls anything with a fixed
/// preamble, and restores the global pointer after every call:
///
/// ```text
/// lui   v0, 0x0        ; the halves of _gp_disp, which the linker fills in
/// addiu v0, v0, 0x0
/// addu  s0, v0, t9     ; joined to the callee address the ABI leaves in t9
/// ...
/// jalr  t9
/// or    gp, s0, zero   ; restore, usually in the delay slot
/// ```
///
/// None of it comes from the source, and all of it appears in every function,
/// so comparing it measures the ABI rather than the code. Left in, it raised
/// the mean similarity of *unrelated* functions from 0.34 to 0.44 on the PIC
/// corpus: noise that pushes decoys toward the true pairs.
///
/// The `jalr` is **not** matched here. That is the call itself, which is real
/// work: a non-PIC build spells the same call `jal`, and a source edit that adds
/// or removes a call must still show.
fn is_pic_setup(insn: &Insn) -> bool {
    /// The register the ABI leaves the callee address in.
    const CALLEE_ADDRESS: &str = "t9";
    /// The global pointer the preamble computes.
    const GLOBAL_POINTER: &str = "gp";

    let mut operands = insn.operands.split(',').map(str::trim);
    let (first, second, third) = (operands.next(), operands.next(), operands.next());

    match insn.mnemonic.as_str() {
        // `addu rX, rY, t9` folds the callee address into the global pointer.
        // Reading `t9` is what marks it: the ABI supplies that value on entry,
        // so no computation from the source starts there.
        "addu" => third == Some(CALLEE_ADDRESS) || second == Some(CALLEE_ADDRESS),

        // `lw t9, N(rX)` reads the callee address out of the GOT, which is how
        // PIC reaches a function a non-PIC build simply names in its `jal`. The
        // load exists only because the call is indirect, so it is scaffolding
        // around the call rather than work of its own.
        //
        // Writing `t9` is what marks it. The ABI reserves that register for the
        // address being called, and a compiler does not use it for anything
        // else: across the whole fixture corpus every one of the 48 writes to
        // `t9` is this load, and a non-PIC build has none at all. The `jalr`
        // that consumes it still reaches the comparison, so a call that is
        // added or removed is still visible.
        //
        // A reload of `t9` from the frame is frame work rather than a GOT read,
        // and the caller judges that on its own. Excluding it here keeps each
        // rule answering for what it actually recognizes.
        "lw" => first == Some(CALLEE_ADDRESS) && !insn.operands.contains("(sp)"),

        // A move to or from the global pointer, which this decoder renders as
        // `or rX, rY, zero`. Either direction is the same bookkeeping: the
        // preamble parks the value in a callee-saved register and puts it back
        // around each call.
        "or" if third == Some("zero") => {
            first == Some(GLOBAL_POINTER) || second == Some(GLOBAL_POINTER)
        }

        _ => false,
    }
}

/// Report whether an operand names a general register.
///
/// MIPS registers print by their ABI names, which are irregular enough to
/// list. `$4` style numbers do not appear in this decoder's output.
fn is_register_name(operand: &str) -> bool {
    matches!(
        operand.trim(),
        "zero"
            | "at"
            | "v0"
            | "v1"
            | "a0"
            | "a1"
            | "a2"
            | "a3"
            | "t0"
            | "t1"
            | "t2"
            | "t3"
            | "t4"
            | "t5"
            | "t6"
            | "t7"
            | "t8"
            | "t9"
            | "s0"
            | "s1"
            | "s2"
            | "s3"
            | "s4"
            | "s5"
            | "s6"
            | "s7"
            | "s8"
            | "k0"
            | "k1"
            | "gp"
            | "sp"
            | "fp"
            | "ra"
    )
}

/// Work out how an instruction moves control flow.
///
/// Read from the opcode rather than the printed text, so an alias or a
/// rendering change cannot alter the answer.
///
/// # Targets
///
/// `j` and `jal` hold an index that is shifted left two and joined to the top
/// bits of the program counter, so their target is an address inside the
/// region rather than a distance from here. A conditional branch holds a
/// signed offset counted from the delay slot, one instruction past itself.
/// `rabbitizer` resolves both forms, so neither correction is repeated here.
fn classify(inst: &Instruction) -> InsnKind {
    // A `jr` through the return-address register ends the function; through
    // any other register it is a tail call or a jump table.
    if inst.is_return() {
        return InsnKind::Return;
    }

    match inst.opcode() {
        // `jal` and `jalr` call. `bgezal` and friends also link, which
        // `is_function_call` already accounts for.
        Opcode::core_jalr => InsnKind::Call { target: None },
        Opcode::core_jal => InsnKind::Call { target: jump_target(inst) },
        Opcode::core_j => InsnKind::Jump { target: jump_target(inst) },
        Opcode::core_jr => InsnKind::Jump { target: None },

        _ if inst.is_function_call() => InsnKind::Call { target: branch_target(inst) },

        // An unconditional branch never falls through, so it is a jump
        // whatever it is spelled.
        _ if inst.is_unconditional_branch() => InsnKind::Jump { target: branch_target(inst) },

        // Anything else carrying a branch offset is conditional, and falls
        // through when it is not taken.
        _ if inst.get_branch_offset().is_some() => InsnKind::Branch { target: branch_target(inst) },

        _ => InsnKind::Normal,
    }
}

/// Resolve the absolute target of a `j` or `jal`.
fn jump_target(inst: &Instruction) -> Option<u64> {
    inst.get_instr_index_as_vram().map(|vram| u64::from(vram.inner()))
}

/// Resolve the target of a branch, which is relative to the delay slot.
fn branch_target(inst: &Instruction) -> Option<u64> {
    let offset = inst.get_branch_offset()?;
    let address = i64::from(inst.vram().inner());
    u64::try_from(address + i64::from(offset.inner())).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::decode_all;

    /// Decode one instruction from a little-endian word at address 0.
    fn decode_one(word: u32) -> Insn {
        Mips32::LITTLE.decode(&word.to_le_bytes(), 0, 0).expect("bytes must decode")
    }

    #[test]
    fn decodes_simple_arithmetic() {
        let insn = decode_one(0x0085_1021);
        assert_eq!(insn.mnemonic, "addu");
        assert_eq!(insn.operands, "v0, a0, a1");
        assert_eq!(insn.bytes_len, 4);
        assert_eq!(insn.kind, InsnKind::Normal);
    }

    #[test]
    fn jr_ra_is_a_return() {
        assert_eq!(decode_one(0x03e0_0008).kind, InsnKind::Return);
    }

    /// `jr` through any other register is a tail call or a switch, which
    /// leaves the block but does not end the function the way a return does.
    #[test]
    fn jr_through_another_register_is_an_indirect_jump() {
        assert_eq!(decode_one(0x0320_0008).kind, InsnKind::Jump { target: None });
    }

    #[test]
    fn jalr_is_a_call() {
        assert!(matches!(decode_one(0x0320_f809).kind, InsnKind::Call { .. }));
    }

    /// The J-type target is an address inside the region, not a distance from
    /// the instruction. The index `0x100` shifted left two is `0x400`, and
    /// that must be the answer whatever address the instruction sits at.
    #[test]
    fn a_jump_target_is_absolute_not_relative() {
        let at_zero = Mips32::LITTLE.decode(&0x0c00_0100u32.to_le_bytes(), 0, 0).unwrap();
        assert_eq!(at_zero.kind, InsnKind::Call { target: Some(0x400) });

        let moved = Mips32::LITTLE.decode(&0x0c00_0100u32.to_le_bytes(), 0, 0x1000).unwrap();
        assert_eq!(
            moved.kind,
            InsnKind::Call { target: Some(0x400) },
            "a region target must not move with the instruction address"
        );
    }

    #[test]
    fn j_is_an_unconditional_jump() {
        assert_eq!(decode_one(0x0800_0100).kind, InsnKind::Jump { target: Some(0x400) });
    }

    /// A branch offset counts from the delay slot, one instruction past the
    /// branch, so an offset of 5 from address 0 lands at `4 + (5 << 2)`.
    #[test]
    fn a_conditional_branch_can_fall_through() {
        assert_eq!(decode_one(0x1082_0005).kind, InsnKind::Branch { target: Some(24) });
        assert_eq!(decode_one(0x1482_0005).kind, InsnKind::Branch { target: Some(24) });
    }

    /// A backwards branch must resolve below the instruction, which catches a
    /// sign error that a forward-only test would miss.
    #[test]
    fn a_backwards_branch_resolves_below_itself() {
        let insn = Mips32::LITTLE.decode(&0x1082_fffeu32.to_le_bytes(), 0, 0x1000).unwrap();
        assert_eq!(insn.kind, InsnKind::Branch { target: Some(0x0ffc) });
    }

    /// A branch target moves with the instruction, unlike a jump target.
    #[test]
    fn a_branch_target_is_relative_to_the_instruction() {
        let insn = Mips32::LITTLE.decode(&0x1082_0005u32.to_le_bytes(), 0, 0x1000).unwrap();
        assert_eq!(insn.kind, InsnKind::Branch { target: Some(0x1018) });
    }

    /// `beq` of a register with itself renders as `b`, which never falls
    /// through.
    #[test]
    fn an_always_taken_branch_is_a_jump() {
        assert_eq!(decode_one(0x1000_0005).kind, InsnKind::Jump { target: Some(24) });
    }

    /// `break` begins with `b` but is not a branch.
    #[test]
    fn break_is_not_a_branch() {
        assert_eq!(decode_one(0x0000_000d).kind, InsnKind::Normal);
    }

    #[test]
    fn address_tracks_the_offset() {
        let mut code = Vec::new();
        code.extend_from_slice(&0x0085_1021u32.to_le_bytes());
        code.extend_from_slice(&0x03e0_0008u32.to_le_bytes());
        assert_eq!(Mips32::LITTLE.decode(&code, 4, 0x8000).unwrap().address, 0x8004);
    }

    #[test]
    fn rejects_truncated_input() {
        assert_eq!(Mips32::LITTLE.decode(&[0x00, 0x00], 0, 0), Err(DecodeError::Truncated));
        assert_eq!(Mips32::LITTLE.decode(&[], 0, 0), Err(DecodeError::Truncated));
    }

    #[test]
    fn rejects_offset_past_the_end() {
        assert_eq!(Mips32::LITTLE.decode(&[0x00; 4], 8, 0), Err(DecodeError::Truncated));
    }

    #[test]
    fn decode_all_advances_by_instruction_width() {
        let mut code = Vec::new();
        for word in [0x0085_1021u32, 0x03e0_0008, 0x0085_1021] {
            code.extend_from_slice(&word.to_le_bytes());
        }
        let (insns, err) = decode_all(&Mips32::LITTLE, &code, 0x1000);
        assert_eq!(err, None);
        let addresses: Vec<u64> = insns.iter().map(|insn| insn.address).collect();
        assert_eq!(addresses, vec![0x1000, 0x1004, 0x1008]);
    }

    #[test]
    fn decode_all_reports_trailing_partial_bytes() {
        let mut code = 0x0085_1021u32.to_le_bytes().to_vec();
        code.push(0xff);
        let (insns, err) = decode_all(&Mips32::LITTLE, &code, 0);
        assert_eq!(insns.len(), 1);
        assert_eq!(err, Some(DecodeError::Truncated));
    }

    #[test]
    fn decode_all_handles_empty_input() {
        let (insns, err) = decode_all(&Mips32::LITTLE, &[], 0);
        assert!(insns.is_empty());
        assert_eq!(err, None);
    }

    /// A zero word is `nop` on MIPS, so it is padding by name as well as by
    /// encoding.
    #[test]
    fn a_zero_word_is_padding() {
        let nop = decode_one(0x0000_0000);
        assert_eq!(nop.mnemonic, "nop");
        assert!(Mips32::LITTLE.is_padding(&nop));
        assert!(Mips32::LITTLE.trim_padding(&[0; 4]).is_empty());
    }

    #[test]
    fn trailing_padding_is_removed() {
        let mut code = 0x0085_1021u32.to_le_bytes().to_vec();
        code.extend_from_slice(&[0; 4]);
        assert_eq!(Mips32::LITTLE.trim_padding(&code), &code[..4]);
    }

    mod addresses {
        use super::*;
        use crate::address::{
            AddressSpace,
            ConstantKind::{Address, Value},
        };

        const V0: u32 = 2;
        const A0: u32 = 4;
        const A1: u32 = 5;
        const T0: u32 = 8;
        const S0: u32 = 16;
        const S1: u32 = 17;
        const SP: u32 = 29;

        fn lui(rt: u32, imm: u32) -> u32 {
            0x3c00_0000 | rt << 16 | imm
        }
        fn addiu(rt: u32, rs: u32, imm: u32) -> u32 {
            0x2400_0000 | rs << 21 | rt << 16 | (imm & 0xffff)
        }
        fn ori(rt: u32, rs: u32, imm: u32) -> u32 {
            0x3400_0000 | rs << 21 | rt << 16 | imm
        }
        fn lw(rt: u32, offset: u32, base: u32) -> u32 {
            0x8c00_0000 | base << 21 | rt << 16 | (offset & 0xffff)
        }
        fn sw(rt: u32, offset: u32, base: u32) -> u32 {
            0xac00_0000 | base << 21 | rt << 16 | (offset & 0xffff)
        }
        fn jal(target: u32) -> u32 {
            0x0c00_0000 | (target >> 2 & 0x03ff_ffff)
        }
        /// `beqz rs`, to `words` instructions past the delay slot.
        fn beqz(rs: u32, words: u32) -> u32 {
            0x1000_0000 | rs << 21 | words
        }
        const JR_RA: u32 = 0x03e0_0008;
        const NOP: u32 = 0;

        /// Where the code sits, and the space it refers to.
        const BASE: u64 = 0x8000_0000;

        fn space() -> AddressSpace {
            AddressSpace::of_raw_image(BASE, 0x10_0000)
        }

        fn kinds_in(words: &[u32], space: &AddressSpace) -> Vec<ConstantKind> {
            let code: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
            let (body, error) = decode_all(&Mips32::BIG, &code, BASE);
            assert_eq!(error, None);
            Mips32::BIG.constant_kinds(&body, space)
        }

        fn kinds(words: &[u32]) -> Vec<ConstantKind> {
            kinds_in(words, &space())
        }

        #[test]
        fn a_pair_that_builds_an_address_is_an_address() {
            assert_eq!(kinds(&[lui(V0, 0x8001), addiu(V0, V0, 0x51b8)]), [Address, Address]);
        }

        #[test]
        fn a_negative_lower_half_is_joined_as_the_processor_joins_it() {
            // 0x80010000 - 0x1d78 = 0x8000e288, inside the space.
            assert_eq!(kinds(&[lui(V0, 0x8001), addiu(V0, V0, 0xe288)]), [Address, Address]);
        }

        #[test]
        fn a_pair_joined_with_ori_is_an_address() {
            assert_eq!(kinds(&[lui(A0, 0x8001), ori(A0, A0, 0xca00)]), [Address, Address]);
        }

        /// 1,000,000,000 is built the same way, but is not an address here.
        #[test]
        fn a_pair_that_builds_a_number_is_a_value() {
            assert_eq!(kinds(&[lui(A0, 0x3b9a), ori(A0, A0, 0xca00)]), [Value, Value]);
        }

        /// The sign mask `0x80000000` is a number when the code is elsewhere.
        #[test]
        fn a_kseg_constant_outside_the_image_is_a_value() {
            let space = AddressSpace::of_raw_image(0x8040_0000, 0x1_0000);
            assert_eq!(kinds_in(&[lui(T0, 0x8000), NOP], &space), [Value, Value]);
        }

        #[test]
        fn nothing_is_an_address_without_a_space() {
            let words = [lui(V0, 0x8001), addiu(V0, V0, 0x51b8)];
            assert_eq!(kinds_in(&words, &AddressSpace::none()), [Value, Value]);
        }

        #[test]
        fn work_between_the_halves_does_not_break_the_pair() {
            let words = [lui(V0, 0x8001), addiu(T0, A0, 1), sw(T0, 0x10, SP), addiu(A0, V0, 0x20)];
            assert_eq!(kinds(&words), [Address, Value, Value, Address]);
        }

        #[test]
        fn a_register_written_between_the_halves_ends_the_pair() {
            let words = [lui(V0, 0x8001), addiu(V0, A0, 1), addiu(A0, V0, 0x20)];
            assert_eq!(kinds(&words), [Address, Value, Value]);
        }

        /// A load or store offset from an address register is its lower half.
        #[test]
        fn a_load_and_a_store_through_the_upper_half_are_addresses() {
            let words = [lui(S0, 0x8001), lw(A0, 0x1aa0, S0), sw(A1, 0x1aa4, S0)];
            assert_eq!(kinds(&words), [Address, Address, Address]);
        }

        /// A load writes its first operand, so it ends a pair on that register.
        #[test]
        fn a_load_into_the_register_ends_the_pair() {
            let words = [lui(S0, 0x8001), lw(S0, 0x10, SP), addiu(A0, S0, 0x20)];
            assert_eq!(kinds(&words), [Address, Value, Value]);
        }

        /// A store only reads its first operand, so the pair survives it.
        #[test]
        fn a_store_from_the_register_keeps_the_pair() {
            let words = [lui(S0, 0x8001), sw(S0, 0x10, SP), addiu(A0, S0, 0x20)];
            assert_eq!(kinds(&words), [Address, Value, Address]);
        }

        /// The whole address in a register reaches the fields of a global.
        #[test]
        fn a_whole_address_in_a_register_is_followed() {
            let words =
                [lui(S1, 0x8001), addiu(S1, S1, 0x0100), addiu(A0, S1, 0x10), lw(V0, 0x8, S1)];
            assert_eq!(kinds(&words), [Address, Address, Address, Address]);
        }

        /// The delay slot runs before the call, so a lower half there counts.
        #[test]
        fn a_lower_half_in_the_delay_slot_of_a_call_counts() {
            let words = [lui(A0, 0x8001), jal(0x8000_4000), addiu(A0, A0, 0x20)];
            assert_eq!(kinds(&words), [Address, Value, Address]);
        }

        #[test]
        fn a_call_clobbers_the_argument_registers() {
            let words = [lui(A0, 0x8001), jal(0x8000_4000), NOP, addiu(A0, A0, 0x20)];
            assert_eq!(kinds(&words), [Address, Value, Value, Value]);
        }

        #[test]
        fn a_call_keeps_the_saved_registers() {
            let words = [lui(S0, 0x8001), jal(0x8000_4000), NOP, addiu(A0, S0, 0x20)];
            assert_eq!(kinds(&words), [Address, Value, Value, Address]);
        }

        /// Code after a return runs only when a branch reaches it, holding what
        /// the branch held, even though the epilogue restored the register.
        #[test]
        fn a_block_after_a_return_holds_what_its_branch_held() {
            let words = [
                lui(S0, 0x8001),
                beqz(A0, 4), // to index 6
                NOP,
                lw(S0, 0x10, SP), // the epilogue restores s0
                JR_RA,
                NOP,
                addiu(A1, S0, 0x10),
            ];
            assert_eq!(kinds(&words)[6], Address);
        }

        /// With no branch to it, code after a return holds nothing known.
        #[test]
        fn a_block_no_branch_reaches_holds_nothing() {
            let words = [lui(S0, 0x8001), JR_RA, NOP, addiu(A1, S0, 0x10)];
            assert_eq!(kinds(&words)[3], Value);
        }

        #[test]
        fn paths_that_agree_keep_the_address() {
            let words = [
                lui(V0, 0x8001),
                beqz(A0, 3), // to index 5
                NOP,
                addiu(T0, A0, 1),
                NOP,
                addiu(A1, V0, 0x10),
            ];
            assert_eq!(kinds(&words)[5], Address);
        }

        #[test]
        fn paths_that_disagree_forget_the_address() {
            let words = [
                lui(V0, 0x8001),
                beqz(A0, 3), // to index 5
                NOP,
                lui(V0, 0x8002),
                NOP,
                addiu(A1, V0, 0x10),
            ];
            assert_eq!(kinds(&words)[5], Value);
        }

        #[test]
        fn there_is_one_kind_for_each_instruction() {
            let words = [lui(V0, 0x8001), JR_RA, addiu(V0, V0, 0x10), NOP, NOP];
            assert_eq!(kinds(&words).len(), words.len());
            assert!(kinds(&[]).is_empty());
        }

        /// The target of `jal` and `j` prints in the `$` form every decoder
        /// uses for a resolved target.
        #[test]
        fn a_jump_target_prints_as_a_resolved_target() {
            let code = jal(0x8000_4000).to_be_bytes();
            let insn = Mips32::BIG.decode(&code, 0, BASE).unwrap();
            assert_eq!(insn.operands, "$+0x4000");
            assert!(crate::arch::is_branch_target(&insn.operands));
        }

        fn contents_of(words: &[u32], space: &AddressSpace) -> crate::address::Contents {
            let code: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
            let (body, _) = decode_all(&Mips32::BIG, &code, BASE);
            Mips32::BIG.contents(&code, &body, space)
        }

        /// A long function of ordinary instructions is code.
        #[test]
        fn compiled_code_is_code() {
            use crate::address::Contents;
            let block = [
                addiu(SP, SP, 0xffe8),
                sw(S0, 0x10, SP),
                lui(V0, 0x8001),
                lw(A0, 0x20, V0),
                jal(0x8000_4000),
                addiu(A1, A0, 1),
                lw(S0, 0x10, SP),
                JR_RA,
                addiu(SP, SP, 0x18),
            ];
            let words = block.repeat(8);
            assert_eq!(contents_of(&words, &space()), Contents::Code);
        }

        /// A table of pointers into the image is data.
        #[test]
        fn a_table_of_pointers_is_data() {
            use crate::address::Contents;
            let mut words = vec![JR_RA, NOP];
            words.extend((0..64).map(|index| 0x8000_1000 + index * 0x40));
            assert_eq!(contents_of(&words, &space()), Contents::Data);
        }

        /// The same words are only numbers where the image is elsewhere.
        #[test]
        fn pointers_count_only_inside_the_space() {
            use crate::address::Contents;
            let mut words = vec![JR_RA, NOP];
            words.extend((0..64).map(|index| 0x8000_1000 + index * 0x40));
            let elsewhere = AddressSpace::of_raw_image(0x9000_0000, 0x1000);
            assert_eq!(contents_of(&words, &elsewhere), Contents::Code);
        }

        /// Zero fill after a return is data once it is half the words.
        #[test]
        fn zero_fill_is_data() {
            use crate::address::Contents;
            let mut words = vec![addiu(V0, V0, 1); 30];
            words.extend([JR_RA, NOP]);
            words.extend([0; 32]);
            assert_eq!(contents_of(&words, &space()), Contents::Data);
        }

        /// The `nop` in every delay slot of `-O0` code stays below half.
        #[test]
        fn delay_slot_nops_are_code() {
            use crate::address::Contents;
            let block = [
                addiu(V0, V0, 1),
                beqz(A0, 1),
                NOP,
                addiu(V0, V0, 2),
                jal(0x8000_4000),
                NOP,
                addiu(V0, V0, 3),
                addiu(V0, V0, 4),
                JR_RA,
                NOP,
            ];
            let words = block.repeat(7);
            assert_eq!(contents_of(&words, &space()), Contents::Code);
        }

        /// Opcode 0x3b is reserved in MIPS II, so these words do not decode.
        const UNREADABLE: u32 = 0xec00_0001;

        /// Mostly words that do not decode is data.
        #[test]
        fn unreadable_words_are_data() {
            use crate::address::Contents;
            let mut words = vec![addiu(V0, V0, 1); 38];
            words.extend([UNREADABLE; 26]);
            assert_eq!(contents_of(&words, &space()), Contents::Data);
        }

        /// A third of the words unreadable is below two in five, so it stays
        /// code.
        #[test]
        fn some_unreadable_words_are_code() {
            use crate::address::Contents;
            let mut words = vec![addiu(V0, V0, 1); 44];
            words.extend([UNREADABLE; 22]);
            assert_eq!(contents_of(&words, &space()), Contents::Code);
        }

        /// Too short to judge, so it stays code.
        #[test]
        fn a_short_function_is_code() {
            use crate::address::Contents;
            assert_eq!(contents_of(&[0; 63], &space()), Contents::Code);
            assert_eq!(contents_of(&[], &space()), Contents::Code);
        }

        /// Normalizing drops the constants of an address, and only those.
        #[test]
        fn normalizing_in_a_space_drops_only_the_address() {
            use crate::norm::{normalize_body, normalize_body_in};

            let words = [lui(V0, 0x8001), addiu(V0, V0, 0x51b8), addiu(A0, A0, 0x25)];
            let code: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
            let (body, _) = decode_all(&Mips32::BIG, &code, BASE);

            let plain = normalize_body(&Mips32::BIG, &body);
            let placed = normalize_body_in(&Mips32::BIG, &body, &space());

            assert_eq!(plain, placed, "the operations and shapes agree");
            assert_eq!(plain[0].constants.as_slice(), [0x8001]);
            assert!(placed[0].constants.is_empty() && placed[1].constants.is_empty());
            assert_eq!(placed[2].constants.as_slice(), [0x25], "a real constant stays");
        }
    }

    /// The `nop` in the delay slot of the last return belongs to the function.
    #[test]
    fn a_delay_slot_nop_is_kept() {
        // jr ra, nop in its slot, then two words of padding.
        let mut code = 0x03e0_0008u32.to_be_bytes().to_vec();
        code.extend_from_slice(&[0; 12]);
        assert_eq!(Mips32::BIG.trim_padding(&code), &code[..8]);
    }

    /// The same holds after a branch or a jump, and in either byte order.
    #[test]
    fn a_delay_slot_nop_is_kept_after_any_branch() {
        for word in [
            0x0800_0010u32, // j 0x40
            0x1000_ffff,    // b .
            0x1440_0003,    // bnez v0, . + 16
            0x0c00_0010,    // jal 0x40
            0x0320_f809,    // jalr t9
        ] {
            let mut little = word.to_le_bytes().to_vec();
            little.extend_from_slice(&[0; 8]);
            assert_eq!(Mips32::LITTLE.trim_padding(&little).len(), 8, "{word:#010x}");

            let mut big = word.to_be_bytes().to_vec();
            big.extend_from_slice(&[0; 8]);
            assert_eq!(Mips32::BIG.trim_padding(&big).len(), 8, "{word:#010x}");
        }
    }

    /// A branch whose slot holds real work loses only the padding after it.
    #[test]
    fn a_filled_delay_slot_is_not_padded_out() {
        let mut code = 0x03e0_0008u32.to_le_bytes().to_vec();
        code.extend_from_slice(&0x2402_0001u32.to_le_bytes()); // addiu v0, zero, 1
        code.extend_from_slice(&[0; 8]);
        assert_eq!(Mips32::LITTLE.trim_padding(&code), &code[..8]);
    }

    /// Code that ends without a branch keeps no `nop`.
    #[test]
    fn a_nop_after_plain_work_is_padding() {
        let mut code = 0x2402_0001u32.to_be_bytes().to_vec();
        code.extend_from_slice(&[0; 4]);
        assert_eq!(Mips32::BIG.trim_padding(&code), &code[..4]);
    }

    /// Padding inside a function is not padding, so it must stay.
    #[test]
    fn padding_before_real_code_is_kept() {
        let mut code = vec![0u8; 4];
        code.extend_from_slice(&0x0085_1021u32.to_le_bytes());
        assert_eq!(Mips32::LITTLE.trim_padding(&code), &code[..], "only the end is trimmed");
    }

    #[test]
    fn a_prologue_is_recognized_by_the_frame_it_makes() {
        // addiu sp, sp, -0x20
        let allocate = decode_one(0x27bd_ffe0);
        assert!(Mips32::LITTLE.is_prologue(&allocate));

        let add = decode_one(0x0085_1021);
        assert!(!Mips32::LITTLE.is_prologue(&add));
    }

    /// Releasing the frame ends a function; it must not be read as opening
    /// one, or every function start lands on the function before it.
    #[test]
    fn releasing_the_frame_is_not_a_prologue() {
        // addiu sp, sp, 0x28, the unwind that pairs with the allocation.
        let release = decode_one(0x27bd_0028);
        assert!(!Mips32::LITTLE.is_prologue(&release));
    }

    /// Saving the return address happens inside the prologue, not at its
    /// start, so it must not be taken for the start.
    #[test]
    fn saving_the_return_address_is_not_the_start() {
        // sw ra, 0x14(sp)
        let save_ra = decode_one(0xafbf_0014);
        assert_eq!(save_ra.to_string(), "sw ra, 0x14(sp)");
        assert!(!Mips32::LITTLE.is_prologue(&save_ra));
    }

    /// Adjusting another register, or adding to the stack pointer from
    /// somewhere else, is ordinary work.
    #[test]
    fn another_stack_adjustment_is_not_a_prologue() {
        // addiu a2, sp, 0x18, which takes the address of a frame slot.
        let address_of = decode_one(0x27a6_0018);
        assert!(!Mips32::LITTLE.is_prologue(&address_of));
    }

    #[test]
    fn frame_work_is_told_apart_from_real_work() {
        // addiu sp, sp, -0x20
        assert!(Mips32::LITTLE.is_frame_management(&decode_one(0x27bd_ffe0)));
        // sw ra, 0x14(sp)
        assert!(Mips32::LITTLE.is_frame_management(&decode_one(0xafbf_0014)));
        // addu v0, a0, a1 is the work itself
        assert!(!Mips32::LITTLE.is_frame_management(&decode_one(0x0085_1021)));
    }

    /// A load from an object is not a spill, even though both are `lw`.
    #[test]
    fn a_data_load_is_not_frame_work() {
        // lw v0, 0x0(a0)
        let load = decode_one(0x8c82_0000);
        assert!(!Mips32::LITTLE.is_frame_management(&load), "a load through a0 reads data");
    }

    /// This decoder renders a register move as `or rX, rY, zero`, never as
    /// `move`, so a frame pointer established that way must still be seen.
    #[test]
    fn a_frame_pointer_set_with_or_is_frame_work() {
        // or s8, sp, zero: establishing the frame pointer, which this decoder
        // names by its numbered form rather than as `fp`.
        assert!(Mips32::LITTLE.is_frame_management(&decode_one(0x03a0_f025)));
        // or v0, s2, zero: moving a computed value into the return register.
        assert!(!Mips32::LITTLE.is_frame_management(&decode_one(0x0240_1025)));
    }

    /// The PIC preamble is in every function a PIC build compiles, so
    /// comparing it measures the ABI rather than the code.
    #[test]
    fn the_pic_global_pointer_setup_is_not_real_work() {
        // addu s0, v0, t9: folding the callee address into the global pointer.
        assert!(Mips32::LITTLE.is_frame_management(&decode_one(0x0059_8021)));
        // addu gp, v0, t9: the same, straight into gp.
        assert!(Mips32::LITTLE.is_frame_management(&decode_one(0x0059_e021)));
        // or gp, s0, zero: the restore after a call, in the delay slot.
        assert!(Mips32::LITTLE.is_frame_management(&decode_one(0x0200_e025)));
    }

    /// The bookkeeping test keys on `t9` and `gp`, so an `addu` between other
    /// registers must stay. Taken from the same PIC function, where
    /// `addu s2, v0, s2` accumulates the running total.
    #[test]
    fn an_addu_that_is_not_pic_setup_stays() {
        assert!(
            !Mips32::LITTLE.is_frame_management(&decode_one(0x0052_9021)),
            "adding two ordinary registers is the work itself"
        );
    }

    /// The PIC preamble comes out of the comparison, but only as a pair and
    /// only where the `addu` against `t9` proves what it is.
    #[test]
    fn the_pic_preamble_is_dropped_as_a_pair() {
        let body = [
            decode_one(0x3c02_0000), // lui v0, 0x0
            decode_one(0x2442_0000), // addiu v0, v0, 0x0
            decode_one(0x0059_e021), // addu gp, v0, t9
        ];
        assert_eq!(Mips32::LITTLE.idiom_length(&body), 2);
    }

    /// The consumer need not follow the pair at once: a compiler puts the frame
    /// prologue between them.
    #[test]
    fn the_preamble_is_found_across_an_intervening_prologue() {
        let body = [
            decode_one(0x3c02_0000), // lui v0, 0x0
            decode_one(0x2442_0000), // addiu v0, v0, 0x0
            decode_one(0x27bd_ffd8), // addiu sp, sp, -0x28
            decode_one(0xafbf_0024), // sw ra, 0x24(sp)
            decode_one(0x0059_e021), // addu gp, v0, t9
        ];
        assert_eq!(Mips32::LITTLE.idiom_length(&body), 2);
    }

    /// A non-PIC build loads the address of a global with the very same two
    /// words, so the pair alone must not be dropped.
    ///
    /// From `int read_global(int i) { return table[i & 63]; }` built with
    /// `-fno-pic`: `lui at, 0x0` then `addiu at, at, 0x0` builds the address of
    /// `table`, and the `addu` that follows indexes it rather than joining it to
    /// `t9`. Dropping this pair would delete a real memory reference, and two
    /// functions reading different globals would compare equal.
    #[test]
    fn a_real_address_load_is_not_the_pic_preamble() {
        let body = [
            decode_one(0x3c01_0000), // lui at, 0x0
            decode_one(0x2421_0000), // addiu at, at, 0x0
            decode_one(0x3082_003f), // andi v0, a0, 0x3f
            decode_one(0x0002_1080), // sll v0, v0, 2
            decode_one(0x0022_0821), // addu at, at, v0, indexing, not PIC
            decode_one(0x8c22_0000), // lw v0, 0x0(at)
        ];
        assert_eq!(Mips32::LITTLE.idiom_length(&body), 0, "the address of a global is real work");
    }

    /// Without any consumer the pair is not a preamble either.
    #[test]
    fn a_pair_nothing_joins_to_t9_is_not_the_preamble() {
        let body = [
            decode_one(0x3c02_0000), // lui v0, 0x0
            decode_one(0x2442_0000), // addiu v0, v0, 0x0
            decode_one(0x8c42_0000), // lw v0, 0x0(v0), a plain dereference
        ];
        assert_eq!(Mips32::LITTLE.idiom_length(&body), 0);
    }

    /// A pair at the very end of a function has no consumer to find, and must
    /// not read past the body.
    #[test]
    fn a_pair_at_the_end_of_a_body_is_kept() {
        let body = [decode_one(0x3c02_0000), decode_one(0x2442_0000)];
        assert_eq!(Mips32::LITTLE.idiom_length(&body), 0);
        assert_eq!(Mips32::LITTLE.idiom_length(&body[..1]), 0);
        assert_eq!(Mips32::LITTLE.idiom_length(&[]), 0);
    }

    /// The `addu` must read the register the pair built, not merely any
    /// register alongside `t9`.
    #[test]
    fn an_addu_on_t9_and_another_register_is_not_the_consumer() {
        let body = [
            decode_one(0x3c02_0000), // lui v0, 0x0
            decode_one(0x2442_0000), // addiu v0, v0, 0x0
            decode_one(0x0079_8021), // addu s0, v1, t9: v1, not v0
        ];
        assert_eq!(Mips32::LITTLE.idiom_length(&body), 0);
    }

    /// The `_gp_disp` pair opens a PIC function, so the function starts two
    /// words before its prologue.
    #[test]
    fn the_global_pointer_pair_counts_as_a_preamble() {
        // lui v0, 0x0 then addiu v0, v0, 0x0.
        let pair = [decode_one(0x3c02_0000), decode_one(0x2442_0000)];
        assert_eq!(Mips32::LITTLE.preamble_before_prologue(&pair), 2);
    }

    /// The pair must share one register, or the two words are unrelated and
    /// the second is an ordinary add.
    #[test]
    fn a_pair_on_two_registers_is_not_a_preamble() {
        // lui v0, 0x0 then addiu v1, v1, 0x0: different registers.
        let pair = [decode_one(0x3c02_0000), decode_one(0x2463_0000)];
        assert_eq!(Mips32::LITTLE.preamble_before_prologue(&pair), 0);
    }

    /// A non-zero immediate means a real constant, which the linker has already
    /// filled in, so the words are not the `_gp_disp` pair.
    #[test]
    fn a_pair_holding_a_real_constant_is_not_a_preamble() {
        // lui v0, 0x1234 then addiu v0, v0, 0x0.
        let pair = [decode_one(0x3c02_1234), decode_one(0x2442_0000)];
        assert_eq!(Mips32::LITTLE.preamble_before_prologue(&pair), 0);
    }

    /// Ordinary work before a prologue belongs to the function before it.
    #[test]
    fn plain_instructions_are_not_a_preamble() {
        let pair = [decode_one(0x0085_1021), decode_one(0x0085_1021)];
        assert_eq!(Mips32::LITTLE.preamble_before_prologue(&pair), 0);
    }

    /// A function at the very start of an image has nothing before it, and the
    /// slice length is what stops the rule reading past the front.
    #[test]
    fn a_preamble_cannot_reach_past_the_start() {
        assert_eq!(Mips32::LITTLE.preamble_before_prologue(&[]), 0);
        assert_eq!(Mips32::LITTLE.preamble_before_prologue(&[decode_one(0x2442_0000)]), 0);
    }

    /// The call survives, but the GOT read that reaches it does not.
    ///
    /// A non-PIC build spells the same call `jal` and needs no load at all, so
    /// the load is scaffolding around the call. The `jalr` itself is the work:
    /// an edit that adds or removes a call must still show.
    #[test]
    fn the_call_is_kept_but_its_got_read_is_not() {
        // lw t9, 0x0(s0): reading the callee address out of the GOT.
        assert!(Mips32::LITTLE.is_frame_management(&decode_one(0x8e19_0000)));
        // lw t9, 0x0(gp): the same, indexed straight off the global pointer.
        assert!(Mips32::LITTLE.is_frame_management(&decode_one(0x8f99_0000)));
        // jalr t9: the call itself, which stays.
        assert!(!Mips32::LITTLE.is_frame_management(&decode_one(0x0320_f809)));
    }

    /// Only a load *into* `t9` is a GOT read. A load through `gp` into any other
    /// register reads a global, which is work the source asked for.
    #[test]
    fn a_global_read_through_gp_is_not_a_got_read() {
        // lw v0, 0x0(gp)
        assert!(
            !Mips32::LITTLE.is_frame_management(&decode_one(0x8f82_0000)),
            "reading a global is real work"
        );
    }

    /// A call that is added or removed must still be visible, or the report
    /// would call a new call site no change at all.
    #[test]
    fn an_added_call_still_shows_after_the_got_read_goes() {
        use crate::norm::normalize_body;

        let arch = &Mips32::LITTLE;
        let without = [decode_one(0x0085_1021)]; // addu v0, a0, a1
        let with = [
            decode_one(0x8f99_0000), // lw t9, 0x0(gp), dropped
            decode_one(0x0320_f809), // jalr t9, kept
            decode_one(0x0085_1021), // addu v0, a0, a1
        ];

        assert_eq!(normalize_body(arch, &without).len(), 1);
        assert_eq!(
            normalize_body(arch, &with).len(),
            2,
            "the call must remain once its GOT read is dropped"
        );
    }

    #[test]
    fn registers_are_recognized_by_their_abi_names() {
        for name in ["zero", "a0", "v0", "t9", "s8", "sp", "fp", "ra", "gp"] {
            assert!(Mips32::LITTLE.is_register(name), "{name} names a register");
        }
        for other in ["", "0x4", "0x4(sp)", "$+0x8", "r0", "x0"] {
            assert!(!Mips32::LITTLE.is_register(other), "{other} does not name a register");
        }
    }

    #[test]
    fn the_stack_and_frame_pointers_are_told_apart() {
        for name in ["sp", "fp", "s8"] {
            assert!(Mips32::LITTLE.is_stack_register(name));
        }
        assert!(!Mips32::LITTLE.is_stack_register("a0"));
        assert!(!Mips32::LITTLE.is_stack_register("ra"));
    }

    #[test]
    fn a_frame_reference_is_told_apart_from_another_memory_reference() {
        assert!(Mips32::LITTLE.mentions_stack_slot("ra, 0x14(sp)"));
        assert!(Mips32::LITTLE.mentions_stack_slot("v0, 0x0(fp)"));
        assert!(!Mips32::LITTLE.mentions_stack_slot("v0, 0x0(a0)"));
    }

    #[test]
    fn a_constant_reads_in_hex_and_decimal() {
        assert_eq!(Mips32::LITTLE.constant_value("0x25"), Some(0x25));
        assert_eq!(Mips32::LITTLE.constant_value("37"), Some(37));
    }

    /// A negative immediate must read back as one value, not as its digits.
    #[test]
    fn a_negative_constant_keeps_one_spelling() {
        assert_eq!(Mips32::LITTLE.constant_value("-0x20"), Some((-0x20i64) as u64));
        assert_ne!(Mips32::LITTLE.constant_value("-0x20"), Mips32::LITTLE.constant_value("0x20"));
    }

    #[test]
    fn what_is_not_a_constant_reads_as_none() {
        for operand in ["a0", "0x4(sp)", "$+0x400", "", "ra"] {
            assert_eq!(Mips32::LITTLE.constant_value(operand), None, "{operand} is not a constant");
        }
    }

    /// MIPS puts the comparison in the mnemonic, so nothing is stripped and
    /// two different branches must stay different.
    #[test]
    fn normalizing_an_operation_keeps_distinct_branches_apart() {
        assert_eq!(Mips32::LITTLE.normalize_operation("addu"), "addu");
        assert_ne!(
            Mips32::LITTLE.normalize_operation("beq"),
            Mips32::LITTLE.normalize_operation("bne")
        );
    }

    /// `b` and `j` are one jump spelled two ways, and which one a compiler picks
    /// follows from PIC rather than from the source.
    #[test]
    fn the_two_spellings_of_a_jump_normalize_alike() {
        assert_eq!(
            Mips32::LITTLE.normalize_operation("j"),
            Mips32::LITTLE.normalize_operation("b"),
            "a PIC build emits `b` where a non-PIC build emits `j`"
        );
    }

    /// Merging the jumps must not reach the conditional branches that start with
    /// the same letter, nor the calling forms.
    #[test]
    fn merging_the_jumps_leaves_everything_else_apart() {
        let jump = Mips32::LITTLE.normalize_operation("j");
        for other in ["beq", "bne", "bgez", "blez", "bltz", "jal", "jalr", "jr"] {
            assert_ne!(
                Mips32::LITTLE.normalize_operation(other),
                jump,
                "{other} is not a plain unconditional jump"
            );
        }
    }

    /// The whole instruction, not just the name, must come out alike: a `b` and
    /// a `j` to the same place are one operation.
    #[test]
    fn a_jump_normalizes_the_same_either_way() {
        use crate::norm::normalize;

        // b, which is `beq zero, zero, offset`, and j to an absolute address.
        let relative = decode_one(0x1000_0002);
        let absolute = decode_one(0x0800_0010);
        assert_eq!(relative.mnemonic, "b");
        assert_eq!(absolute.mnemonic, "j");

        let arch = &Mips32::LITTLE;
        assert_eq!(normalize(arch, &relative), normalize(arch, &absolute));
    }

    /// A conditional branch must still differ from an unconditional jump, or a
    /// new gate around some code would read as no change.
    #[test]
    fn a_conditional_branch_is_not_a_jump() {
        use crate::norm::normalize;

        let arch = &Mips32::LITTLE;
        // beq a0, v0, offset: a real test, not `b`.
        let conditional = decode_one(0x1082_0005);
        let unconditional = decode_one(0x1000_0002);
        assert_eq!(conditional.mnemonic, "beq");
        assert_ne!(
            normalize(arch, &conditional),
            normalize(arch, &unconditional),
            "a test that can fall through is not a jump"
        );
    }

    /// The trait's default says this architecture has no unwind index, which
    /// makes function recovery fall back to calls and returns.
    #[test]
    fn there_is_no_unwind_section() {
        assert_eq!(Mips32::LITTLE.unwind_section(), None);
    }

    /// MIPS runs the instruction after a branch either way, so recovery must
    /// not read it as the start of the next function.
    #[test]
    fn a_branch_has_one_delay_slot() {
        assert_eq!(Mips32::LITTLE.delay_slots(), 1);
        assert_eq!(Mips32::BIG.delay_slots(), 1);
    }

    /// The same bytes are two different instructions in the two byte orders,
    /// which is why the order cannot be guessed.
    #[test]
    fn byte_order_decides_what_a_word_means() {
        // `addu v0, a0, a1` stored big endian.
        let stored = 0x0085_1021u32.to_be_bytes();

        let big = Mips32::BIG.decode(&stored, 0, 0).unwrap();
        assert_eq!(big.mnemonic, "addu");

        let little = Mips32::LITTLE.decode(&stored, 0, 0).unwrap();
        assert_ne!(little.mnemonic, "addu", "the wrong order reads another instruction");
    }

    /// A big-endian image decodes exactly as a little-endian one does once
    /// the word is assembled, so the whole trait works either way.
    #[test]
    fn big_endian_classifies_control_flow_the_same() {
        let jr_ra = Mips32::BIG.decode(&0x03e0_0008u32.to_be_bytes(), 0, 0).unwrap();
        assert_eq!(jr_ra.kind, InsnKind::Return);

        let jal = Mips32::BIG.decode(&0x0c00_0100u32.to_be_bytes(), 0, 0).unwrap();
        assert_eq!(jal.kind, InsnKind::Call { target: Some(0x400) });
    }

    /// Each order names the triple the differential test disassembles with.
    #[test]
    fn each_order_names_its_own_triple() {
        assert_eq!(Mips32::LITTLE.triple(), "mipsel");
        assert_eq!(Mips32::BIG.triple(), "mips");
    }

    /// A stored pointer follows the image byte order, as an instruction does.
    #[test]
    fn a_pointer_reads_in_the_image_byte_order() {
        let stored = 0x8000_0000u32.to_be_bytes();
        assert_eq!(Mips32::BIG.read_pointer(&stored), 0x8000_0000);
        assert_ne!(Mips32::LITTLE.read_pointer(&stored), 0x8000_0000);
    }
}
