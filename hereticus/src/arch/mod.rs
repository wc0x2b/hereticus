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

pub mod aarch64;
pub mod arm32;
pub mod mips;
mod mips32;
pub mod thumb;

use core::fmt;
use std::collections::BTreeSet;

use compact_str::CompactString;

use crate::address::{AddressSpace, ConstantKind, Contents};

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

    /// Report whether a lifted register is the stack or frame pointer, as
    /// [`Arch::is_stack_register`] does for one printed.
    fn is_frame_register(&self, reg: crate::il::Reg) -> bool {
        reg == crate::il::Reg::Stack
    }

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

    /// The addresses inside `space` that `body` forms, in order, to read the
    /// data there.
    ///
    /// Two functions can differ only in the data they point at, as a call to
    /// `sscanf` with `"%d"` and one with `"%f"` do. Normalizing drops the
    /// addresses, which move on every release, so only the data tells such
    /// functions apart. `code` is as for [`Arch::constant_kinds`], and
    /// `memory` holds the global offset table for code that reads an address
    /// from it. Defaults to none.
    fn data_addresses(
        &self,
        _code: &[u8],
        _body: &[Insn],
        _space: &AddressSpace,
        _memory: &Memory<'_>,
    ) -> Vec<u64> {
        Vec::new()
    }

    /// The addresses of the words `insns` load from a literal pool.
    ///
    /// A pool word is data among the instructions. It decodes as whatever its
    /// bits spell, which can be a return or a prologue, and its value changes
    /// with every release, so a scan that read it as code would split a
    /// function at a different place in each. Defaults to none, for the
    /// architectures that keep no data among their instructions.
    fn literal_pool_words(&self, _insns: &[Insn]) -> Vec<u64> {
        Vec::new()
    }

    /// Each instruction of `insns` that loads from a literal pool, as its
    /// address and the address of a word it loads, where a compiler wrote
    /// the pool for the one function that loads it.
    ///
    /// Defaults to none. Hand-written A32, as the ARM kernel and its
    /// decompressor hold, shares one pool among many routines, so A32 keeps
    /// the default: measured on the OpenWrt ARM decompressors, a pool span
    /// merged 21 routines.
    fn literal_pool_loads(&self, _insns: &[Insn]) -> Vec<(u64, u64)> {
        Vec::new()
    }

    /// The instruction set a body that opens at `address` with `code` goes on
    /// in, and the address where it does, or `None` where it opens with no
    /// switch.
    ///
    /// Defaults to `None`, for the architectures with one set.
    fn switch_at_start(&self, _code: &[u8], _address: u64) -> Option<(&'static dyn Arch, u64)> {
        None
    }

    /// The table of handlers that `code`, loaded at `base`, opens with, as a
    /// Cortex-M image does, or `None`. Defaults to `None`.
    fn vector_table(&self, _code: &[u8], _base: u64) -> Option<VectorTable> {
        None
    }

    /// Whether `insn` is code of an extension the decoder does not read, as
    /// NEON on ARM, rather than bytes that are no instruction at all.
    ///
    /// Both stay opaque. Only a scan that tells code from data asks. Defaults
    /// to `false`.
    fn is_unread_extension(&self, _insn: &Insn) -> bool {
        false
    }

    /// Whether this architecture keeps data among its instructions.
    ///
    /// Where it does not, every word between the end of one function and the
    /// prologue of the next is code of the next: a compiler schedules work
    /// before the frame allocation, as MIPS `lui` often is. Where it does,
    /// those words can be the pool of the function before. Defaults to
    /// [`DataAmongCode::Never`].
    fn data_among_code(&self) -> DataAmongCode {
        DataAmongCode::Never
    }

    /// Whether a jump through a table of cases is an instruction of its own.
    /// Defaults to [`TableJumps::LikeOthers`].
    fn table_jumps(&self) -> TableJumps {
        TableJumps::LikeOthers
    }

    /// The jumps through a table of cases in `insns`, which were decoded
    /// from the code at `code` in `memory`.
    ///
    /// Such a jump names no target, so without the table a scan cannot see
    /// that the cases after it are more of the same function, and the words
    /// of the table decode as nonsense instructions. The table and what
    /// finds it can lie outside the code, in `.rodata` or the global offset
    /// table, so all of `memory` is there to read. Defaults to none.
    fn jump_tables(
        &self,
        _memory: &Memory<'_>,
        _code: core::ops::Range<u64>,
        _insns: &[Insn],
    ) -> Vec<JumpTable> {
        Vec::new()
    }

    /// Where each call in `insns` goes, as far as the code shows, with the
    /// index of the call.
    ///
    /// A call that names its target gives the address. PIC code on some
    /// architectures calls through a slot of the global offset table
    /// instead, and an architecture that can see which slot says so.
    /// A jump out of the function is a tail call, and counts too. Defaults to
    /// the targets the decoder resolved.
    fn call_targets(&self, insns: &[Insn]) -> Vec<(usize, Option<CallTarget>)> {
        insns
            .iter()
            .enumerate()
            .filter_map(|(index, insn)| match insn.kind {
                InsnKind::Call { target } => Some((index, target.map(CallTarget::Address))),
                InsnKind::Jump { target: Some(target) } if leaves(insns, target) => {
                    Some((index, Some(CallTarget::Address(target))))
                }
                _ => None,
            })
            .collect()
    }

    /// The slot of the global offset table that a PLT stub jumps through, or
    /// `None` when `code`, found at `address`, is no such stub.
    ///
    /// PIC code calls another library, and any function a library exports,
    /// through such a stub, so the stub stands between a call and its callee.
    /// Defaults to `None`, for the architectures that call through the global
    /// offset table directly.
    fn stub_slot(&self, _code: &[u8], _address: u64) -> Option<u64> {
        None
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

    /// Report whether an instruction opens a function.
    ///
    /// Used to recover function starts from stripped code, so a false positive
    /// invents a function. Answer only for a shape that reliably begins one.
    fn is_prologue(&self, insn: &Insn) -> bool;

    /// The operands before a reference to memory at a distance from the
    /// program counter, as a load from a literal pool makes, or `None` for
    /// operands with no such reference.
    ///
    /// The distance says only where the pool sits, which moves whenever code
    /// before it grows, and the words of the pool are compared on their own.
    /// Defaults to `None`, for the architectures with no such load.
    fn before_pc_reference<'a>(&self, _operands: &'a str) -> Option<&'a str> {
        None
    }

    /// Report whether a function can open with the instruction in `word`.
    ///
    /// Asked of the word after a return, where a guess would start a
    /// function. Defaults to `true`, for the architectures where any
    /// instruction can.
    fn may_open_function(&self, _word: &[u8]) -> bool {
        true
    }

    /// Report whether `body` opens with a sequence that only the entry of a
    /// function runs, as surely as a call to it would say.
    ///
    /// A prologue can be moved, or left out of a function that needs no
    /// frame. Some ABIs oblige an entry sequence that cannot. Defaults to
    /// `false`, for the ABIs with none.
    fn is_function_entry(&self, _body: &[Insn]) -> bool {
        false
    }

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

    /// Report whether a jump through a register is a tail call.
    ///
    /// Such a jump can also dispatch a `switch` through a table, which stays
    /// inside the function. Only an architecture knows the forms a compiler
    /// keeps for a tail call. Defaults to `false`.
    fn is_tail_call(&self, _insn: &Insn) -> bool {
        false
    }

    /// Lift `insn` to the intermediate language of [`crate::il`]. `word`
    /// holds its bytes.
    ///
    /// Defaults to `None`, for the architectures with no lifter yet. A
    /// caller treats `None` as "nothing known", never as "does nothing".
    fn lift(&self, _insn: &Insn, _word: &[u8]) -> Option<crate::il::Lifted> {
        None
    }

    /// The architecture the PLT stubs of a binary are in, where it is not
    /// this one.
    ///
    /// A Thumb-2 library calls through A32 stubs, and read as T32 their
    /// words split into pieces. Defaults to `None`: the stubs are in this
    /// architecture.
    fn stub_arch(&self) -> Option<&'static dyn Arch> {
        None
    }

    /// The address of the function a pointer to it holds.
    ///
    /// A pointer to a T32 function has bit 0 set, which only says the
    /// instruction set. Defaults to the pointer itself.
    fn function_address(&self, pointer: u64) -> u64 {
        pointer
    }

    /// The function a word of data points at, where the word itself says
    /// that it points at code.
    ///
    /// A pointer to a T32 function has bit 0 set, and no pointer to data or
    /// to an instruction of T32 has it. Defaults to `None`: a word does not
    /// say what it points at.
    fn tagged_function(&self, _word: u64) -> Option<u64> {
        None
    }

    /// The words among `insns` that hold a distance, not an address.
    ///
    /// PIC code on ARM loads a pool word and adds it to `pc`. Defaults to
    /// none.
    fn distance_words(&self, _code: &[u8], _insns: &[Insn]) -> BTreeSet<u64> {
        BTreeSet::new()
    }

    /// Adjust instructions that only their neighbours explain, once a run of
    /// them is decoded.
    ///
    /// T32 `it` makes up to four instructions after it conditional, and
    /// each of them, decoded alone, reads as if it ran always. Defaults to
    /// changing nothing.
    fn after_decoding(&self, _insns: &mut [Insn]) {}

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
    /// `bytes` is at least [`Arch::pointer_width`] long.
    fn read_pointer(&self, bytes: &[u8]) -> u64;

    /// Read a call that names its target by an absolute address.
    ///
    /// Such a target does not move with the base an image is read at, unlike
    /// a relative branch, so it can judge that base. `word` is
    /// [`Arch::instruction_width`] bytes long.
    ///
    /// Defaults to `None`, for the architectures whose calls are all
    /// relative.
    fn absolute_call(&self, _word: &[u8]) -> Option<AbsoluteCall> {
        None
    }
}

/// The bytes a binary loads, by address.
#[derive(Clone, Copy, Debug)]
pub struct Memory<'a> {
    regions: &'a [(u64, &'a [u8])],
}

impl<'a> Memory<'a> {
    /// Memory made of these regions, each an address and its bytes.
    pub fn new(regions: &'a [(u64, &'a [u8])]) -> Self {
        Self { regions }
    }

    /// The `length` bytes at `address`, if one region holds them all.
    pub fn bytes(&self, address: u64, length: usize) -> Option<&'a [u8]> {
        self.regions.iter().find_map(|&(start, data)| {
            let offset = usize::try_from(address.checked_sub(start)?).ok()?;
            data.get(offset..offset.checked_add(length)?)
        })
    }
}

/// The table of handlers an image opens with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VectorTable {
    /// The bytes of the table, which are data.
    pub words: core::ops::Range<u64>,
    /// The start of each handler the table names.
    pub handlers: Vec<u64>,
}

/// How a jump through a table of cases looks among other jumps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableJumps {
    /// It is an instruction of its own, as T32 `tbb` and `tbh` are. A table
    /// the scan cannot read still shows as such a jump.
    Distinct,
    /// It is a jump through a register, as a tail call can be, so a table
    /// the scan cannot read may go unseen.
    LikeOthers,
}

/// Whether an architecture keeps data among its instructions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataAmongCode {
    /// Constants sit in pools between functions, as on ARM.
    LiteralPools,
    /// Every word between functions is code or padding.
    Never,
}

/// Where a call goes, as far as its code shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallTarget {
    /// The address of the callee, or of a stub that stands for it.
    Address(u64),
    /// The address of a slot of the global offset table that holds the
    /// callee's address.
    Slot(u64),
}

/// A jump through a table of cases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JumpTable {
    /// The address of the jump.
    pub jump: u64,
    /// The addresses of the words of the table, which are data.
    pub words: core::ops::Range<u64>,
    /// Where each case starts, in table order.
    pub targets: Vec<u64>,
}

/// A call that holds the low bits of its target, and takes the high bits from
/// where it runs.
///
/// MIPS `jal` is the case: it holds 28 bits of the target, and the top 4 come
/// from the address of its delay slot. So a target is known only within one
/// aligned region, and the region is where the image loads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbsoluteCall {
    /// The target, as an offset into its region.
    pub offset: u64,
    /// The size of the region, a power of two.
    pub region: u64,
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

/// Report whether `target` lies outside the function `insns` make up, so a
/// jump there is a tail call.
///
/// A wrapper that only jumps to another function has the same shape as every
/// other such wrapper, and only the target tells them apart. Measured on zlib
/// 1.2.12 built by GCC, `crc32_combine_gen` paired with `gztell` that way,
/// and the new function went unreported.
pub fn leaves(insns: &[Insn], target: u64) -> bool {
    match (insns.first(), insns.last()) {
        (Some(first), Some(last)) => {
            target < first.address || target >= last.address + last.bytes_len as u64
        }
        _ => false,
    }
}

/// Decode `code` from start to end, stopping at the first error.
///
/// Returns what it decoded and the error that stopped it, if any. Callers keep
/// the partial result because a function can end with data the decoder cannot
/// read.
///
/// Where instructions are narrower than the words of a literal pool, as in
/// T32, the code is read twice: once to find the pool words, and again with
/// each kept whole. See [`decode_all_but`].
///
/// A body that [`Arch::switch_at_start`] says opens with a switch to another
/// instruction set is read in that set from where the switch lands.
pub fn decode_all(arch: &dyn Arch, code: &[u8], address: u64) -> (Vec<Insn>, Option<DecodeError>) {
    let switch = arch.switch_at_start(code, address).and_then(|(other, lands)| {
        let offset = usize::try_from(lands.checked_sub(address)?).ok()?;
        (offset > 0 && offset < code.len()).then_some((other, lands, offset))
    });
    let Some((other, lands, offset)) = switch else {
        return decode_in_one_set(arch, code, address);
    };
    let (mut insns, error) = decode_in_one_set(arch, &code[..offset], address);
    if error.is_some() {
        return (insns, error);
    }
    let (rest, error) = decode_all(other, &code[offset..], lands);
    insns.extend(rest);
    (insns, error)
}

/// [`decode_all`], in one instruction set throughout.
fn decode_in_one_set(
    arch: &dyn Arch,
    code: &[u8],
    address: u64,
) -> (Vec<Insn>, Option<DecodeError>) {
    let decoded = decode_linear(arch, code, address);
    if arch.data_among_code() == DataAmongCode::Never
        || arch.instruction_width() >= arch.pointer_width()
    {
        return decoded;
    }
    // Each pass reads the pool words from instructions in better step than
    // the pass before: a load read out of step names a word that is code.
    // Measured on Lua built by GCC for Thumb-2, one such word hid a `cbnz`
    // and split `setnodevector`. Two passes settle what is measured.
    const MOST_PASSES: usize = 3;
    let mut decoded = decoded;
    let mut pool = std::collections::BTreeSet::new();
    for _ in 0..MOST_PASSES {
        let named: std::collections::BTreeSet<u64> =
            arch.literal_pool_words(&decoded.0).into_iter().collect();
        if named == pool {
            break;
        }
        pool = named;
        decoded = decode_all_but(arch, code, address, &pool);
    }
    decoded
}

/// Decode `code` one instruction after the next.
fn decode_linear(arch: &dyn Arch, code: &[u8], address: u64) -> (Vec<Insn>, Option<DecodeError>) {
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

/// [`decode_all`], where each address in `data` holds a word of data rather
/// than an instruction.
///
/// T32 decodes by halfwords, so a literal pool word decoded as code can read
/// as a 32-bit instruction that runs into what follows, and every
/// instruction after it is then out of step. Measured on zlib for Thumb-2,
/// the upper half of a pool word joined the first halfword of the next
/// function. Such a word here is one [`InsnKind::Unknown`] as wide as a
/// pointer.
pub fn decode_all_but(
    arch: &dyn Arch,
    code: &[u8],
    address: u64,
    data: &std::collections::BTreeSet<u64>,
) -> (Vec<Insn>, Option<DecodeError>) {
    let width = arch.pointer_width();
    let mut out = Vec::new();
    let mut offset = 0;
    let mut error = None;
    while offset < code.len() {
        let at = address + offset as u64;
        if data.contains(&at)
            && let Some(bytes) = code.get(offset..offset + width)
        {
            let operands = bytes.iter().rev().map(|byte| format!("{byte:02x}")).collect();
            out.push(Insn {
                address: at,
                bytes_len: width,
                mnemonic: ".word".to_string(),
                operands,
                kind: InsnKind::Unknown,
            });
            offset += width;
            continue;
        }
        match arch.decode(code, offset, address) {
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
    arch.after_decoding(&mut out);
    (out, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// `count` four-byte instructions from `start` on.
    fn nops(start: u64, count: u64) -> Vec<Insn> {
        (0..count)
            .map(|index| Insn {
                address: start + 4 * index,
                bytes_len: 4,
                mnemonic: "nop".into(),
                operands: String::new(),
                kind: InsnKind::Normal,
            })
            .collect()
    }

    #[rstest]
    #[case::before_the_first(0xfc, true)]
    #[case::at_the_first(0x100, false)]
    #[case::inside(0x106, false)]
    #[case::at_the_last(0x108, false)]
    #[case::inside_the_last(0x10b, false)]
    #[case::just_past_the_end(0x10c, true)]
    #[case::far_away(0xdead_0000, true)]
    fn a_jump_leaves_only_past_the_ends(#[case] target: u64, #[case] expected: bool) {
        assert_eq!(leaves(&nops(0x100, 3), target), expected);
    }

    #[test]
    fn a_jump_leaves_no_empty_function() {
        assert!(!leaves(&[], 0x100));
    }

    #[test]
    fn a_jump_leaves_where_the_range_says() {
        bolero::check!().with_type::<(u32, u8, u64)>().for_each(|&(start, count, target)| {
            let insns = nops(u64::from(start), u64::from(count) + 1);
            let end = u64::from(start) + 4 * (u64::from(count) + 1);
            let outside = target < u64::from(start) || target >= end;
            assert_eq!(leaves(&insns, target), outside);
        });
    }
}
