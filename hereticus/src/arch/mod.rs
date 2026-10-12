//! The boundary between `hereticus` and whichever crate decodes machine code.
//!
//! Everything above this module works on [`Insn`] and never sees a decoder
//! type. That keeps the decoder replaceable: the normalizer and the matcher
//! do not change when the decoder does.
//!
//! [`Arch`] carries more than decoding, because more than decoding is
//! architecture specific. Which operand names a register, which instruction
//! opens a function, which word a linker pads with: the modules above cannot answer
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
pub mod mips16;
pub mod thumb;

/// The decoders, and what one instruction is: see [`hereticus_il::arch`].
pub use hereticus_il::arch::*;

use std::collections::BTreeSet;

use crate::address::{AddressSpace, ConstantKind, Contents};

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

/// An architecture that `hereticus` can decode, with the rules that read
/// its code: padding, prologues, tail calls, literal pools and jump tables.
/// An implementation answers for its own instructions and never has to
/// agree with another architecture's.
pub trait Arch: Decoder {
    /// Report whether a lifted register is the stack or frame pointer.
    fn is_frame_register(&self, reg: crate::il::Reg) -> bool {
        reg == crate::il::Reg::Stack
    }

    /// Report whether `bytes` can open a function, where an unwind index
    /// says one begins. A table of small numbers otherwise reads as an
    /// index. Defaults to `false`, for the architectures with no such index.
    fn can_open_function(&self, _bytes: &[u8]) -> bool {
        false
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

    /// The instructions that make the global pointer from `body[0]` on, as
    /// the PIC preamble of MIPS does, which the IL view shows as one line.
    ///
    /// Defaults to `None`, for the architectures with no global pointer.
    fn global_pointer_setup(&self, _body: &[Insn]) -> Option<GlobalPointerSetup> {
        None
    }

    /// Report whether an instruction opens a function.
    ///
    /// Used to recover function starts from stripped code, so a false positive
    /// invents a function. Answer only for a shape that reliably begins one.
    fn is_prologue(&self, insn: &Insn) -> bool;

    /// Report whether the instruction `word` starts with could be one
    /// [`Arch::is_prologue`] accepts, from its bits alone, so that a scan of
    /// every word decodes only those. `false` must mean it is none.
    fn may_be_prologue(&self, _word: &[u8]) -> bool {
        true
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

    /// Read a call that names its target by an absolute address.
    ///
    /// Such a target does not move with the base an image is read at, unlike
    /// a relative branch, so it can judge that base. `word` is
    /// [`Decoder::instruction_width`] bytes long.
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
    /// The address of a slot of the global offset table that holds a page,
    /// and the offset of the callee in that page. MIPS PIC reaches a local
    /// function so.
    PageOffset { slot: u64, offset: u64 },
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
    if arch.data_among_code() == DataAmongCode::Never
        || arch.instruction_width() >= arch.pointer_width()
    {
        return decode_linear(arch, code, address);
    }
    // Each pass reads the pool words from instructions in better step than
    // the pass before: a load read out of step names a word that is code.
    // Measured on Lua built by GCC for Thumb-2, one such word hid a `cbnz`
    // and split `setnodevector`. Two passes settle what is measured.
    //
    // An instruction decodes the same at an offset whatever the pool, so a
    // pass takes each one the pass before decoded there: decoding each pass
    // anew took a third of a comparison of libarchive for Thumb-2. What it
    // takes is the instruction as decoded, before `after_decoding`.
    const MOST_PASSES: usize = 3;
    let mut pool = std::collections::BTreeSet::new();
    let (mut raw, mut error) = decode_raw(arch, code, address, &pool, (&[], &pool));
    let finished = |raw: &[Insn]| {
        let mut insns = raw.to_vec();
        arch.after_decoding(&mut insns);
        insns
    };
    let mut decoded = finished(&raw);
    for _ in 0..MOST_PASSES {
        let named: std::collections::BTreeSet<u64> =
            arch.literal_pool_words(&decoded).into_iter().collect();
        if named == pool {
            break;
        }
        (raw, error) = decode_raw(arch, code, address, &named, (&raw, &pool));
        pool = named;
        decoded = finished(&raw);
    }
    (decoded, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// `count` four-byte instructions from `start` on.
    fn nops(start: u64, count: u64) -> Vec<Insn> {
        (0..count)
            .map(|index| {
                Insn::new(start + 4 * index, &[0; 4], InsnKind::Normal, crate::arch::Opcode::None)
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

    /// Every architecture, by name.
    const ARCHES: [(&str, &dyn Arch); 7] = [
        ("A64", &aarch64::Aarch64),
        ("A32", &arm32::Arm32),
        ("T32", &thumb::Thumb2),
        ("MIPS", &mips::Mips32::BIG),
        ("MIPSel", &mips::Mips32::LITTLE),
        ("MIPS16e", &mips16::Mips16::BIG),
        ("MIPS16el", &mips16::Mips16::LITTLE),
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
