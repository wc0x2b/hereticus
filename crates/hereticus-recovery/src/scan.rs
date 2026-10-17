//! Find functions in a binary that has no symbol table.
//!
//! A shipped firmware image is usually stripped, so the symbol table that
//! `hereticus_image::obj` reads is not there. This module recovers the function
//! boundaries from the code and from what the linker left behind.
//!
//! Four sources, strongest first:
//!
//! 1. **The dynamic symbol table.** A shared library keeps it after
//!    stripping, because the loader links through it. It names each
//!    exported function, with its start and its end. A raw image has none.
//! 2. **The unwind index.** Where the ABI has one — ARM keeps it in
//!    `.ARM.exidx` — it holds one entry per function, each pointing at where
//!    that function starts. It survives stripping, and when it is there it is
//!    exact. Not every architecture defines one, and a compiler can leave it
//!    out.
//! 3. **Call targets.** Anything a call instruction jumps to is the start of a
//!    function, and so is the address a slot of the global offset table holds
//!    where a call goes through it. This finds what is called but misses
//!    what is not. In an
//!    object file, whose code sections hold only code, so does an address
//!    the code takes, as it takes the address of a callback, and one that a
//!    relocated word of data holds, as a table of callbacks does.
//! 4. **What follows a return or a tail call, and what looks like a
//!    prologue.** Code after a function ends usually starts a new one, and
//!    the architecture says which instruction opens one. This is the weakest
//!    source, so it only fills gaps the others left.
//!
//! Which section holds the unwind index, which instruction is a prologue and
//! which word is padding are all architecture specific, so this module asks
//! [`Recovery`] rather than deciding for itself.
//!
//! Recovery is a guess wherever the first two sources are missing. [`Recovered`]
//! records which source found each function so a caller can tell an exact
//! answer from an inferred one.
//!
//! # Not every return ends a function
//!
//! The obvious rule — a function starts after every return — cuts functions
//! apart, because most of them return from more than one place. Two things
//! keep that in check, and together they took a stripped kernel object from
//! ten recovered functions to exactly the four it holds:
//!
//! * A return that a branch reaches across is inside a function, since control
//!   flows past it.
//! * A prologue starts a function whatever precedes it. An error path can jump
//!   backwards over the end of its own function, and without this the function
//!   after it is lost.

use std::collections::{BTreeMap, BTreeSet};

use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget, SectionKind, SymbolKind};

use crate::arch::{CallTarget, DataAmongCode, Memory, Recovery, TableJumps, decode_all};
use hereticus_il::arch::{Insn, InsnKind};
use hereticus_memory::AddressSpace;

/// Bytes in one ARM EHABI unwind entry: a function address and one word
/// that says how to unwind it.
const EXIDX_ENTRY_LEN: usize = 8;

/// The second word of an index entry for code that cannot be unwound.
const EXIDX_CANTUNWIND: u32 = 1;

/// One entry of an exception index: where a function starts, and whether the
/// entry describes it alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    pub address: u64,
    pub unwinding: Unwinding,
}

/// Whether an index entry describes how to unwind its function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unwinding {
    /// The entry describes one function, so the next entry starts the next.
    Described,
    /// The entry lists its function's start and end exactly, as call frame
    /// information does, so nothing but that function lies in its range.
    ///
    /// An unwind index lists only starts: code with no entry of its own,
    /// such as hand-written assembly in a kernel, runs on inside the range
    /// of the entry before.
    Listed,
    /// The code cannot be unwound. A linker merges neighbouring entries of
    /// this kind into one, so the entry can cover many functions. C built
    /// without unwind tables has only these.
    CannotUnwind,
}

/// How a function was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// The symbol table named it. Exact.
    Symbol,
    /// The unwind index listed it. Exact where it is present.
    ExceptionIndex,
    /// Something calls it, so it must be a function. Exact for what it finds.
    CallTarget,
    /// It opens with a sequence only a function entry runs. See
    /// [`Recovery::is_function_entry`].
    Entry,
    /// It follows the end of another function. A guess.
    AfterReturn,
    /// A vector table names it. Exact.
    Vector,
}

impl Source {
    /// Report whether this source states a fact rather than a guess.
    pub fn is_exact(self) -> bool {
        self != Self::AfterReturn
    }
}

/// A function found without help from the symbol table. It has no name: a
/// stripped binary has nothing to read one from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovered {
    /// The address of the first instruction.
    pub address: u64,
    /// The machine code, exactly the bytes of the function.
    pub code: Vec<u8>,
    /// What told the scan where the function starts.
    pub source: Source,
}

/// Find the functions in a binary with no usable symbol table.
///
/// Returns them in address order.
///
/// See RESEARCH.md, A16.
pub fn recover_functions(data: &[u8], arch: &dyn Recovery) -> Vec<Recovered> {
    let Ok(file) = object::File::parse(data) else { return Vec::new() };

    // Only executable sections hold functions. A binary can hold several, as
    // `.text.hot` and `.text.unlikely` show, so take them all. The PLT is
    // read apart where its stubs are in another architecture.
    let stub_arch = arch.stub_arch();
    let mut stubs: Vec<(u64, &[u8])> = Vec::new();
    let mut code_sections: Vec<(u64, &[u8])> = Vec::new();
    for section in file.sections() {
        if section.kind() != SectionKind::Text || section.size() == 0 {
            continue;
        }
        let Ok(data) = section.data() else { continue };
        let is_plt = stub_arch.is_some() && section.name() == Ok(".plt");
        if is_plt { &mut stubs } else { &mut code_sections }.push((section.address(), data));
    }

    // Where the ABI has no index of its own, as on MIPS, the call frame
    // information of C++ and of C built with unwind tables serves as one.
    let mut index = exception_index(&file, arch);
    if index.is_empty()
        && let Some(section) = file.section_by_name(".eh_frame")
        && let Ok(bytes) = section.data()
    {
        let order = if file.is_little_endian() {
            crate::unwind::ByteOrder::Little
        } else {
            crate::unwind::ByteOrder::Big
        };
        let ranges = crate::unwind::function_ranges(bytes, section.address(), order);
        index = index_from_ranges(&ranges, arch);
    }

    // Call frame information can list a whole PLT as one function, as it
    // does for i386, where each entry is a stub of its own.
    if let Some(size) = arch.plt_entry_size() {
        for section in file.sections() {
            let is_plt = section.name().is_ok_and(|name| name.starts_with(".plt"));
            if is_plt && section.kind() == SectionKind::Text {
                let range = section.address()..section.address() + section.size();
                index.extend(
                    range
                        .step_by(size as usize)
                        .map(|address| IndexEntry { address, unwinding: Unwinding::Listed }),
                );
            }
        }
        index.sort_by_key(|entry| entry.address);
    }

    // Tables that code reads, such as those a `switch` jumps through, can
    // lie in any section the binary loads.
    let loaded: Vec<(u64, &[u8])> = file
        .sections()
        .filter(|section| section.address() != 0)
        .filter_map(|section| section.data().ok().map(|data| (section.address(), data)))
        .collect();

    let memory = Memory::new(&loaded);
    let linked = Linked {
        exported: exported_functions(&file, arch),
        pointers: relocated_pointers(&file, arch, &memory),
        slot_names: crate::dynamic::slot_names(&file),
    };
    let mut found =
        recover_in_memory(&code_sections, &index, &linked, Regions::CodeOnly, arch, &memory);
    if let Some(stub_arch) = stub_arch
        && !stubs.is_empty()
    {
        let none = Linked::default();
        found.extend(recover_in_memory(&stubs, &[], &none, Regions::CodeOnly, stub_arch, &memory));
        found.sort_by_key(|recovered| recovered.address);
    }
    found
}

/// What a linked object file says about its functions, beyond its code.
#[derive(Clone, Debug, Default)]
pub struct Linked {
    /// Where each function the dynamic symbol table exports lies.
    pub exported: Vec<core::ops::Range<u64>>,
    /// The addresses the data holds, which the loader moves with the code,
    /// in runs of words that lie next to each other.
    pub pointers: Vec<Vec<u64>>,
    /// The symbol each slot of the global offset table holds, by the
    /// address of the slot.
    pub slot_names: BTreeMap<u64, String>,
}

/// The addresses the words that relative relocations name hold.
///
/// A shared library moves where it loads, so the loader adds the load address
/// to each word of data that holds an address: a relocation with no symbol.
/// Where such a word holds an address in the code, it points at a function,
/// as a table of callbacks does: Lua keeps `str_find` in one.
///
/// The words come in runs of neighbours, as a table holds them, because a
/// table of labels inside one function looks like a table of callbacks
/// word by word: see [`taken_addresses`].
fn relocated_pointers(
    file: &object::File<'_>,
    arch: &dyn Recovery,
    memory: &Memory<'_>,
) -> Vec<Vec<u64>> {
    let Some(relocations) = file.dynamic_relocations() else { return Vec::new() };
    let width = arch.pointer_width() as u64;
    // A REL relocation keeps the address in the word, as ARM and MIPS do,
    // and a RELA one in the relocation, as AArch64 does.
    let mut words: Vec<(u64, u64)> = relocations
        .filter(|(_, relocation)| relocation.target() == RelocationTarget::Absolute)
        .filter_map(|(offset, relocation)| {
            let pointer = match relocation.has_implicit_addend() {
                true => memory
                    .bytes(offset, arch.pointer_width())
                    .map(|bytes| arch.read_pointer(bytes))?,
                false => u64::try_from(relocation.addend()).ok()?,
            };
            Some((offset, pointer))
        })
        .collect();
    words.sort_unstable();
    words
        .chunk_by(|before, after| after.0 == before.0 + width)
        .map(|run| run.iter().map(|&(_, pointer)| pointer).collect())
        .collect()
}

/// Where each function the dynamic symbol table exports lies.
///
/// Stripping removes the symbol table but keeps the dynamic one, because the
/// loader needs it to link a shared library. So every exported function of a
/// stripped library is known, start and end. Measured on the releases built
/// for the tests, the scan alone missed the start of 843 of 27500 functions,
/// such as zlib's `crc32` after `crc32_z`, which ends with a jump back.
fn exported_functions(file: &object::File<'_>, arch: &dyn Recovery) -> Vec<core::ops::Range<u64>> {
    file.dynamic_symbols()
        .filter(|symbol| symbol.kind() == SymbolKind::Text && symbol.size() > 0)
        .filter(|symbol| symbol.section_index().is_some())
        .map(|symbol| symbol_range(arch, symbol.address(), symbol.size()))
        .collect()
}

/// The code a symbol of `size` bytes at `address` names.
///
/// ARM marks a Thumb function, and MIPS a MIPS16e one, by setting bit 0 of
/// its address. GCC can count that bit in the size of a MIPS16e function
/// too, as `XMLPrinter::Print` of tinyxml2 has 265 bytes of 264. Where an
/// instruction can be one byte, as on x86, a function can start and end at
/// any byte, and bit 0 marks nothing.
pub fn symbol_range(arch: &dyn Recovery, address: u64, size: u64) -> core::ops::Range<u64> {
    let start = symbol_address(arch, address);
    start..symbol_address(arch, start + size)
}

/// The address of the code a symbol at `address` names: see
/// [`symbol_range`].
pub fn symbol_address(arch: &dyn Recovery, address: u64) -> u64 {
    match arch.instruction_width() {
        1 => address,
        _ => address & !1,
    }
}

/// Turn the function ranges of call frame information into index entries.
///
/// Each range is described exactly. A gap after one holds code the table
/// does not list, such as hand-written assembly, so it is marked as an entry
/// that cannot unwind, which the scan searches as it would with no index.
///
/// A range of MIPS16e code starts at an address with bit 0 set, as a
/// pointer to such a function has it, so `arch` reads each end as one.
pub fn index_from_ranges(ranges: &[core::ops::Range<u64>], arch: &dyn Recovery) -> Vec<IndexEntry> {
    let ranges: Vec<core::ops::Range<u64>> = ranges
        .iter()
        .map(|range| arch.function_address(range.start)..arch.function_address(range.end))
        .collect();
    let mut entries = Vec::new();
    for (position, range) in ranges.iter().enumerate() {
        entries.push(IndexEntry { address: range.start, unwinding: Unwinding::Listed });
        let next = ranges.get(position + 1).map(|next| next.start);
        if next.is_none_or(|next| next > range.end) {
            entries.push(IndexEntry { address: range.end, unwinding: Unwinding::CannotUnwind });
        }
    }
    entries
}

/// Find the functions in code that is already located.
///
/// This is the part of recovery that needs no container format. A raw firmware
/// image is one region at whatever address it loads at, and has no exception
/// index, so it comes through here with an empty `exception_index`.
///
/// Each region is an address and the bytes stored there. Returns the functions
/// in address order, with empty names.
pub fn recover_from_regions(
    regions: &[(u64, &[u8])],
    exception_index: &[IndexEntry],
    arch: &dyn Recovery,
) -> Vec<Recovered> {
    let linked = Linked::default();
    recover_in_memory(
        regions,
        exception_index,
        &linked,
        Regions::CodeAndData,
        arch,
        &Memory::new(regions),
    )
}

/// What the regions given to the scan hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Regions {
    /// Only code, as the sections of an object file that it marks as code.
    CodeOnly,
    /// Code and data together, as a raw image holds them.
    CodeAndData,
}

/// A region of code, with its instructions decoded once for every pass of
/// the scan. A pass that decoded the region itself made the scan of a
/// library decode each instruction about eight times.
struct Region<'a> {
    base: u64,
    code: &'a [u8],
    insns: Vec<Insn>,
}

impl<'a> Region<'a> {
    fn decode(arch: &dyn Recovery, base: u64, code: &'a [u8]) -> Self {
        Self { base, code, insns: decode_all(arch, code, base).0 }
    }
}

/// Find the functions in code that is already located, where `memory` holds
/// everything else the binary loads, for the tables the code reads, and
/// `linked` what an object file says about its functions.
///
/// See RESEARCH.md, A16.
pub fn recover_in_memory(
    regions: &[(u64, &[u8])],
    exception_index: &[IndexEntry],
    linked: &Linked,
    contents: Regions,
    arch: &dyn Recovery,
    memory: &Memory<'_>,
) -> Vec<Recovered> {
    if regions.is_empty() {
        return Vec::new();
    }

    let mut starts: BTreeSet<(u64, Source)> = BTreeSet::new();
    // A vector table is data, and the code after it is read on its own, so
    // its words cannot put the decoder out of step. Each handler it names
    // starts a function.
    let mut split = Vec::with_capacity(regions.len());
    for &(base, code) in regions {
        let table =
            (contents == Regions::CodeAndData).then(|| arch.vector_table(code, base)).flatten();
        match table {
            Some(table) => {
                let length = (table.words.end - base) as usize;
                split.push((base, &code[..length]));
                split.push((table.words.end, &code[length..]));
                starts.extend(table.handlers.into_iter().map(|address| (address, Source::Vector)));
            }
            None => split.push((base, code)),
        }
    }
    let regions = split.as_slice();
    let decoded: Vec<Region<'_>> =
        regions.iter().map(|&(base, code)| Region::decode(arch, base, code)).collect();
    // An exported function is exact at both ends, and what follows it,
    // past the padding, starts another function.
    for range in &linked.exported {
        starts.insert((range.start, Source::Symbol));
        starts.insert((range.end, Source::AfterReturn));
        if let Some(next) = past_padding(regions, range.end, arch) {
            starts.insert((next, Source::AfterReturn));
        }
    }
    for entry in exception_index {
        starts.insert((entry.address, Source::ExceptionIndex));
    }

    // An entry that describes its function lists it alone, so between two
    // such entries the index is the whole answer. Guessing there only invents
    // boundaries: an internal `bx lr` would split one function into two.
    //
    // An entry that cannot unwind may cover many functions, merged by the
    // linker, so its range is scanned as if there were no index. Measured on
    // zlib built as an ARM shared library, five such entries covered all 123
    // functions, and trusting them found 27.
    if !exception_index.is_empty() {
        let mut blind = cannot_unwind_ranges(exception_index);
        let described = described_ranges(exception_index);
        for region in &decoded {
            let (base, code) = (&region.base, region.code);
            // Code before the first entry of a region is listed by nothing,
            // so it is searched as a region with no index.
            let end = base + code.len() as u64;
            let first = exception_index
                .iter()
                .map(|entry| entry.address)
                .filter(|address| (*base..end).contains(address))
                .min()
                .unwrap_or(end);
            if first > *base {
                starts.insert((*base, Source::AfterReturn));
                blind.push(*base..first);
            }
            // An entry that lists its function exactly covers it to the next
            // entry, so a "call" into the middle of it is data that decodes
            // as one, or a `bal` that only reads the program counter. An
            // unwind index lists only starts, so it proves no such thing.
            // Measured on tinyxml2 for MIPS at -O3 as a raw image, one cut a
            // template function short, and its caller then read as changed.
            let taken = taken_addresses(arch, regions, contents, &linked.pointers, region, memory);
            let local = slot_call_targets(arch, region, memory);
            for address in call_targets(arch, region).into_iter().chain(taken).chain(local) {
                if !described.iter().any(|range| range.start < address && range.contains(&address))
                {
                    starts.insert((address, Source::CallTarget));
                }
            }
            for address in starts_after_returns_in(arch, region, memory, linked) {
                if blind.iter().any(|range| range.contains(&address)) {
                    starts.insert((address, Source::AfterReturn));
                }
            }
            for address in function_entries(arch, &region.insns) {
                if blind.iter().any(|range| range.contains(&address)) {
                    starts.insert((address, Source::Entry));
                }
            }
        }
        let starts =
            outside_pool_spans(within_exports(starts, &linked.exported), arch, &decoded, memory);
        return build_functions(&starts, regions, arch);
    }

    for region in &decoded {
        let taken = taken_addresses(arch, regions, contents, &linked.pointers, region, memory);
        let local = slot_call_targets(arch, region, memory);
        for address in call_targets(arch, region).into_iter().chain(taken).chain(local) {
            starts.insert((address, Source::CallTarget));
        }
        for address in function_entries(arch, &region.insns) {
            starts.insert((address, Source::Entry));
        }
        for address in starts_after_returns_in(arch, region, memory, linked) {
            starts.insert((address, Source::AfterReturn));
        }
        // A region begins with a function unless something says otherwise.
        starts.insert((region.base, Source::AfterReturn));
    }

    let starts =
        outside_pool_spans(within_exports(starts, &linked.exported), arch, &decoded, memory);
    build_functions(&starts, regions, arch)
}

/// The first address from `address` on that holds no padding, in the
/// region that holds `address`, or `None` where padding runs to its end.
///
/// A linker pads after a function to align the next. GCC for Thumb-2 pads
/// with `nop` and zero halfwords, and `trim_padding` keeps zeros there, as
/// a pool can end with them. A start at the padding made a function of it,
/// and where the padding was `nop`s it took in the function after it too:
/// measured on zlib 1.2.11 by clang for Thumb-2, `crc32_combine_`. A word
/// of data that decodes as padding is not padding, but no start is guessed
/// inside a pool: see [`outside_pool_spans`].
fn past_padding(regions: &[(u64, &[u8])], address: u64, arch: &dyn Recovery) -> Option<u64> {
    let &(base, code) = regions
        .iter()
        .find(|&&(base, code)| (base..base + code.len() as u64).contains(&address))?;
    let mut offset = usize::try_from(address - base).ok()?;
    while offset < code.len() {
        match arch.decode(code, offset, base + offset as u64) {
            Ok(insn) if arch.is_padding(&insn) => offset += insn.bytes().len(),
            _ => return Some(base + offset as u64),
        }
    }
    None
}

/// The width of a word of a literal pool or of a jump table, the widest
/// data [`data_words`] lists.
const WORD_WIDTH: u64 = 4;

/// Drop the guessed starts that fall between a load from a literal pool and
/// the word it loads.
///
/// A compiler puts a function's pool after its code, so all between is the
/// same function. A guess there splits it, as at an exception landing pad
/// after the return: only the unwind tables reach it. The pool then goes with
/// the second piece, apart from the code that tells its words are distances,
/// and each release reads as a changed constant. Measured on tinyxml2 read
/// as a raw Thumb-2 image, `XMLElement::~XMLElement` split so at each level.
fn outside_pool_spans(
    starts: BTreeSet<(u64, Source)>,
    arch: &dyn Recovery,
    regions: &[Region<'_>],
    memory: &Memory<'_>,
) -> BTreeSet<(u64, Source)> {
    let mut spans: Vec<(u64, u64)> = regions
        .iter()
        .flat_map(|region| {
            let (base, code, insns) = (region.base, region.code, region.insns.as_slice());
            // A pool word or a jump table can decode as a load from a pool,
            // which reaches nothing.
            let data = data_words(arch, memory, base..base + code.len() as u64, insns);
            let is_data = |address: u64| {
                data.range(address.saturating_sub(WORD_WIDTH - 1)..=address).next().is_some()
            };
            // So can data outside the code, but there a word that does not
            // decode soon follows. Code up to its pool reads whole, but for
            // an extension the decoder does not read, as NEON.
            let unreadable: Vec<u64> = insns
                .iter()
                .filter(|insn| {
                    insn.kind == InsnKind::Unknown
                        && !arch.is_unread_extension(insn)
                        && !is_data(insn.address)
                })
                .map(|insn| insn.address)
                .collect();
            let reads_whole = |from: u64, to: u64| {
                let first = unreadable.partition_point(|&address| address <= from);
                unreadable.get(first).is_none_or(|&address| address >= to)
            };
            arch.literal_pool_loads(insns)
                .into_iter()
                .filter(|&(load, word)| load < word && !is_data(load) && reads_whole(load, word))
                .collect::<Vec<_>>()
        })
        .collect();
    if spans.is_empty() {
        return starts;
    }
    spans.sort_unstable();
    // The farthest word that any load at or before each one reaches.
    let reach: Vec<u64> = spans
        .iter()
        .scan(0, |farthest, &(_, word)| {
            *farthest = (*farthest).max(word);
            Some(*farthest)
        })
        .collect();
    let inside_a_span = |address: u64| {
        let loads_before = spans.partition_point(|&(load, _)| load < address);
        loads_before > 0 && reach[loads_before - 1] >= address
    };
    starts
        .into_iter()
        .filter(|&(address, source)| source.is_exact() || !inside_a_span(address))
        .collect()
}

/// Drop the starts that fall inside an exported function.
///
/// The dynamic symbol table gives such a function exactly, so what the scan
/// guessed inside it is wrong. Measured on Lua for Thumb-2, the doubles a
/// `vldr` loads after the return of `luaopen_math` started a function.
fn within_exports(
    starts: BTreeSet<(u64, Source)>,
    exported: &[core::ops::Range<u64>],
) -> BTreeSet<(u64, Source)> {
    starts
        .into_iter()
        .filter(|&(address, _)| {
            !exported.iter().any(|range| range.start < address && range.contains(&address))
        })
        .collect()
}

/// Functions of the C library and of the C++ runtime that never return.
const NEVER_RETURN: [&str; 16] = [
    "abort",
    "exit",
    "_exit",
    "_Exit",
    "quick_exit",
    "__assert_fail",
    "__assert",
    "__stack_chk_fail",
    "__fortify_fail",
    "longjmp",
    "siglongjmp",
    "pthread_exit",
    "err",
    "errx",
    "__cxa_throw",
    "_Unwind_Resume",
];

/// The addresses of the calls among `insns` whose callee never returns, as
/// the slot it goes through, or the slot of the PLT stub it reaches, names
/// it.
fn calls_that_never_return(
    arch: &dyn Recovery,
    insns: &[Insn],
    memory: &Memory<'_>,
    slot_names: &BTreeMap<u64, String>,
) -> BTreeSet<u64> {
    if slot_names.is_empty() {
        return BTreeSet::new();
    }
    let never_returns =
        |slot: u64| slot_names.get(&slot).is_some_and(|name| NEVER_RETURN.contains(&name.as_str()));
    /// More bytes than any PLT stub holds.
    const STUB_BYTES: usize = 16;
    arch.call_targets(insns)
        .into_iter()
        .filter(|&(index, _)| matches!(insns[index].kind, InsnKind::Call { .. }))
        .filter(|(_, target)| match *target {
            Some(CallTarget::Slot(slot)) => never_returns(slot),
            Some(CallTarget::Address(address)) => {
                let stub = (1..=STUB_BYTES).rev().find_map(|length| memory.bytes(address, length));
                stub.and_then(|code| arch.stub_slot(code, address)).is_some_and(never_returns)
            }
            _ => false,
        })
        .map(|(index, _)| insns[index].address)
        .collect()
}

/// The functions `code` calls through a slot of the global offset table
/// that holds an address in its own code.
///
/// MIPS PIC calls a function of its own this way, as it calls an import,
/// so no call names its target in its own bits and [`call_targets`] cannot
/// see it. The slot of an import holds no address in the code. Measured on
/// the releases built for the tests, Lua's `luaZ_init` is called only so,
/// after a function that ends with a jump back, and this found 12 more
/// function starts and invented none.
fn slot_call_targets(arch: &dyn Recovery, region: &Region<'_>, memory: &Memory<'_>) -> Vec<u64> {
    let (base, code, insns) = (region.base, region.code, region.insns.as_slice());
    let end = base + code.len() as u64;
    arch.call_targets(insns)
        .into_iter()
        .filter_map(|(_, target)| match target? {
            CallTarget::Slot(slot) => memory
                .bytes(slot, arch.pointer_width())
                .map(|bytes| arch.function_address(arch.read_pointer(bytes))),
            CallTarget::PageOffset { slot, offset } => {
                let page = arch.read_pointer(memory.bytes(slot, arch.pointer_width())?);
                let address = (page as u32).wrapping_add(offset as u32);
                Some(arch.function_address(u64::from(address)))
            }
            CallTarget::Address(_) => None,
        })
        .filter(|target| (base..end).contains(target))
        .collect()
}

/// The addresses in code that `code` forms, as a function pointer is.
///
/// Code passes a function it does not call by its address: a callback, or a
/// handler it stores for later. Nothing calls such a function directly, so
/// no call names its start, but the code that takes its address does.
/// Measured on the releases built for the tests, as Lua's `str_find` and
/// expat's `element4` are, this found 40 more function starts and invented
/// none.
///
/// Only where the regions hold nothing but code: in a raw image, the address
/// of a variable lands in the regions too. Measured on the OpenWrt MIPS
/// kernels, it cut hundreds of pieces out of their data.
/// A table this long, of words in a row, may hold the labels of one
/// function rather than functions.
const LEAST_LABELS: usize = 4;

fn taken_addresses(
    arch: &dyn Recovery,
    regions: &[(u64, &[u8])],
    contents: Regions,
    pointers: &[Vec<u64>],
    region: &Region<'_>,
    memory: &Memory<'_>,
) -> Vec<u64> {
    let (base, code, insns) = (region.base, region.code, region.insns.as_slice());
    let in_code = AddressSpace::from_ranges(
        regions.iter().map(|(start, bytes)| *start..*start + bytes.len() as u64),
    );
    let width = arch.instruction_width() as u64;
    let pool = data_words(arch, memory, base..base + code.len() as u64, insns);
    // A function starts where the one before it ended. A label inside a
    // function, or a constant that happens to fall in the code, follows code
    // that runs on into it.
    let ends_before = |address: u64| {
        let Ok(index) = insns.binary_search_by_key(&address, |insn| insn.address) else {
            return false;
        };
        let mut before = index;
        while before > 0
            && (arch.is_padding(&insns[before - 1]) || pool.contains(&insns[before - 1].address))
        {
            before -= 1;
        }
        // What ends a function ends it after its delay slots.
        let ends_at = |at: usize| {
            matches!(insns[at].kind, InsnKind::Return | InsnKind::Jump { .. })
                && at + 1 + arch.delay_slots(&insns[at]) == before
        };
        before == 0 || before < index || ends_at(before - 1) || (before >= 2 && ends_at(before - 2))
    };
    // Whether a jump through a register, not a return, ends the code right
    // before `address`, past padding and a pool.
    let follows_a_dispatch = |address: u64| {
        let Ok(index) = insns.binary_search_by_key(&address, |insn| insn.address) else {
            return false;
        };
        let mut before = index;
        while before > 0
            && (arch.is_padding(&insns[before - 1]) || pool.contains(&insns[before - 1].address))
        {
            before -= 1;
        }
        (1..=2).any(|back| {
            before.checked_sub(back).is_some_and(|at| {
                insns[at].kind == (InsnKind::Jump { target: None })
                    && at + 1 + arch.delay_slots(&insns[at]) == before
            })
        })
    };
    let end = base + code.len() as u64;
    let formed = match contents {
        Regions::CodeOnly => {
            let formed = arch.data_addresses(code, insns, &in_code, memory);
            // Where a pointer to code says that it is one, as on Thumb, an
            // address without the tag is a label inside a function: clang for
            // ARMv6-M, which has no `tbb`, loads the cases of a `switch` from
            // a pool. Measured on zlib for Cortex-M0, these cut `deflate`.
            match arch.tagged_function(1) {
                Some(_) => {
                    formed.into_iter().filter_map(|address| arch.tagged_function(address)).collect()
                }
                None => formed,
            }
        }
        Regions::CodeAndData => Vec::new(),
    };
    let tagged = match contents {
        Regions::CodeOnly => Vec::new(),
        Regions::CodeAndData => tagged_functions(arch, regions, &arch.distance_words(code, insns))
            .into_iter()
            .filter(|&address| {
                let opens_with_work = insns
                    .binary_search_by_key(&address, |insn| insn.address)
                    .is_ok_and(|index| !arch.is_padding(&insns[index]));
                opens_with_work
                    && !points_at_text(memory, address + 1)
                    && !lies_inside_a_body(insns, address)
            })
            .collect(),
    };
    // A relocated pointer to a T32 function has bit 0 set, as a word of a
    // table of callbacks does, and one without it is a label. GCC keeps the
    // labels of a computed `goto` so, and sets bit 0 before it jumps: the
    // `disptab` of Lua 5.4's `luaV_execute`.
    //
    // Where a pointer does not say, the table does. A function follows a
    // return or a tail call, but a label mostly follows the jump through a
    // register that ends the case before: in A32, each case of
    // `luaV_execute` ends with `mov pc, r3` to the next.
    // Measured on Lua 5.4 of Debian 13 for armel, the labels otherwise cut
    // `luaV_execute` in 90 pieces.
    let pointed = pointers
        .iter()
        .map(|run| -> Vec<u64> {
            match arch.tagged_function(1) {
                Some(_) => {
                    run.iter().filter_map(|&pointer| arch.tagged_function(pointer)).collect()
                }
                None => run.clone(),
            }
        })
        .filter(|run| {
            let here: Vec<u64> =
                run.iter().copied().filter(|address| (base..end).contains(address)).collect();
            let after_dispatch =
                here.iter().filter(|&&address| follows_a_dispatch(address)).count();
            here.len() < LEAST_LABELS || after_dispatch * 2 <= here.len()
        })
        .flatten();
    formed
        .into_iter()
        .chain(pointed)
        .chain(tagged)
        .filter(|address| (base..end).contains(address))
        .filter(|address| address % width == 0 && ends_before(*address))
        .collect()
}

/// The functions that the aligned words of `regions` point at, where a
/// word says that it points at code.
///
/// The words of `distances` are left out, as bit 0 of a distance says
/// nothing. So are the words that go on with a text: in an image loaded near
/// address 0, the tail `"ue"` of `"true"` reads as the address 0x6575.
fn tagged_functions(
    arch: &dyn Recovery,
    regions: &[(u64, &[u8])],
    distances: &BTreeSet<u64>,
) -> Vec<u64> {
    let width = arch.pointer_width();
    regions
        .iter()
        .flat_map(|&(start, bytes)| {
            let skip = (start.next_multiple_of(width as u64) - start) as usize;
            let words = bytes.get(skip..).unwrap_or_default().chunks_exact(width);
            let before = (skip..)
                .step_by(width)
                .map(|offset| offset.checked_sub(1).and_then(|at| bytes.get(at)).copied());
            words.zip(before).zip((start + skip as u64..).step_by(width))
        })
        .filter(|&((word, before), address)| {
            let goes_on_with_text = before.is_some_and(is_printable) && is_printable(word[0]);
            !distances.contains(&address) && !goes_on_with_text
        })
        .filter_map(|((word, _), _)| arch.tagged_function(arch.read_pointer(word)))
        .collect()
}

/// Whether local branches cross `address` both ways, as they cross a label
/// inside a loop or between the arms of an `if`.
///
/// A tail call is a jump, so the branch that crosses forward must be one that
/// can fall through. Then a short tail call between two small functions does
/// not count, and a start that a word in a byte table seems to point at, such
/// as the tail of Lua's `luaP_opmodes`, still does.
fn lies_inside_a_body(insns: &[Insn], address: u64) -> bool {
    /// Longer than this, a branch is likely a tail call, not a local one.
    const REACH: u64 = 256;
    let first = insns.partition_point(|insn| insn.address < address.saturating_sub(REACH));
    let last = insns.partition_point(|insn| insn.address <= address.saturating_add(REACH));
    let (mut forward, mut backward) = (false, false);
    for insn in &insns[first..last] {
        let source = insn.address;
        match insn.kind {
            InsnKind::Branch { target: Some(target) } if target.abs_diff(source) <= REACH => {
                forward |= source < address && address < target;
                backward |= target < address && address < source;
            }
            InsnKind::Jump { target: Some(target) } if target.abs_diff(source) <= REACH => {
                backward |= target < address && address < source;
            }
            _ => {}
        }
    }
    forward && backward
}

/// Whether `address` holds a text of two or more printable bytes up to a
/// NUL.
///
/// A pointer to a text at an odd address has bit 0 set too, as a pointer
/// to a T32 function has.
fn points_at_text(memory: &Memory<'_>, address: u64) -> bool {
    /// Longer than any format or message.
    const LONGEST: u64 = 256;
    let length = (0..=LONGEST)
        .map_while(|offset| memory.bytes(address + offset, 1).map(|byte| byte[0]))
        .take_while(|&byte| byte != 0 && (is_printable(byte) || b"\t\n\r".contains(&byte)))
        .count() as u64;
    (2..LONGEST).contains(&length)
        && memory.bytes(address + length, 1).is_some_and(|byte| byte[0] == 0)
}

fn is_printable(byte: u8) -> bool {
    byte.is_ascii_graphic() || byte == b' '
}

/// Turn a set of start addresses into functions that reach the next start.
fn build_functions(
    starts: &BTreeSet<(u64, Source)>,
    code_sections: &[(u64, &[u8])],
    arch: &dyn Recovery,
) -> Vec<Recovered> {
    // One address can come from several sources. Keep the strongest, which is
    // the first for a given address because `Source` sorts that way.
    let mut best: Vec<(u64, Source)> = Vec::new();
    for (address, source) in starts {
        if best.last().is_none_or(|(last, _)| last != address) {
            best.push((*address, *source));
        }
    }

    let mut out = Vec::new();
    for (index, (address, source)) in best.iter().enumerate() {
        let Some((base, code)) = code_sections
            .iter()
            .find(|(base, data)| *address >= *base && *address < *base + data.len() as u64)
        else {
            continue;
        };

        // A function runs to the next start in the same section, or to the
        // end of the section.
        let section_end = base + code.len() as u64;
        let end = best[index + 1..]
            .iter()
            .map(|(next, _)| *next)
            .find(|next| *next > *address && *next <= section_end)
            .unwrap_or(section_end);

        let start_offset = (address - base) as usize;
        let end_offset = (end - base) as usize;
        let Some(bytes) = code.get(start_offset..end_offset) else { continue };

        // A function runs to the next one, but the linker aligns functions,
        // so the gap between them holds padding. Keeping it would make a
        // function look changed when only its neighbour moved.
        let bytes = keep_loaded_words(arch, *address, bytes, arch.trim_padding(bytes).len());
        if bytes.is_empty() {
            continue;
        }
        // A guess that holds only padding is the gap between two functions.
        if *source == Source::AfterReturn
            && past_padding(&[(*address, bytes)], *address, arch).is_none()
        {
            continue;
        }

        out.push(Recovered { address: *address, code: bytes.to_vec(), source: *source });
    }

    out
}

/// The bytes of the function at `address`, cut at `trimmed` but for the
/// pool words its code loads.
///
/// A pool word can hold zero, as the offset of a thread local variable
/// does, and zero is also what a linker pads with. Measured on libjpeg-turbo
/// of Debian 13 for armel, each `jsimd_can_*` function lost its last pool
/// word so.
fn keep_loaded_words<'a>(
    arch: &dyn Recovery,
    address: u64,
    bytes: &'a [u8],
    trimmed: usize,
) -> &'a [u8] {
    if trimmed == bytes.len() {
        return bytes;
    }
    let (insns, _) = decode_all(arch, &bytes[..trimmed], address);
    let loaded_end = arch
        .literal_pool_words(&insns)
        .into_iter()
        .filter_map(|word| usize::try_from(word.checked_sub(address)?).ok())
        .map(|offset| offset + WORD_WIDTH as usize)
        .filter(|&end| end <= bytes.len())
        .max()
        .unwrap_or(0);
    &bytes[..trimmed.max(loaded_end)]
}

/// Find the unwind index in a raw image, which a flash dump copies along
/// with the code.
///
/// Nothing says where it is, but it is easy to recognize: entries of two
/// words, the first an offset from itself to a function of the image, in
/// rising order, and the second `EXIDX_CANTUNWIND`, an unwind description
/// held inline with its top bit set, or an offset to one elsewhere in the
/// image. A run of `FEWEST_INDEX_ENTRIES` such entries does not happen by
/// chance.
///
/// Measured on tinyxml2 for ARM as a raw image, the scan without it joined
/// destructors and short functions that follow a call that does not return.
pub fn find_exception_index(data: &[u8], base: u64, arch: &dyn Recovery) -> Vec<IndexEntry> {
    /// The fewest entries a run needs to be taken for an index.
    const FEWEST_INDEX_ENTRIES: usize = 16;
    /// The personalities an inline description can name: 0, 1 and 2.
    const INLINE_PERSONALITIES: core::ops::RangeInclusive<u32> = 0x80..=0x82;
    /// The most zero fill words to step over, enough to align to 64 bytes.
    const MOST_FILL_WORDS: usize = 15;

    if arch.unwind_section().is_none() {
        return Vec::new();
    }
    let end = base + data.len() as u64;
    let in_image = |address: u64| address >= base && address < end;
    let word = |offset: usize| {
        data.get(offset..offset + 4)
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    };
    let prel31 = |offset: usize, value: u32| {
        (value & 0x8000_0000 == 0)
            .then(|| (base + offset as u64).wrapping_add(sign_extend_31(value) as u64))
    };

    // The entry at `offset`, if it can be one.
    let entry = |offset: usize| -> Option<IndexEntry> {
        let (first, second) = (word(offset)?, word(offset + 4)?);
        let mut address = prel31(offset, first).filter(|&address| in_image(address))?;
        if !address.is_multiple_of(arch.instruction_width() as u64) {
            return None;
        }
        let unwinding = match second {
            EXIDX_CANTUNWIND => Unwinding::CannotUnwind,
            inline if INLINE_PERSONALITIES.contains(&(inline >> 24)) => Unwinding::Described,
            elsewhere => {
                prel31(offset + 4, elsewhere).filter(|&address| in_image(address))?;
                Unwinding::Described
            }
        };
        let word_at = |address: u64| word(usize::try_from(address - base).ok()?);
        let bytes_at = |address: u64| data.get(usize::try_from(address - base).ok()?..);
        // The last entry marks the end of `.text`, where the linker can put
        // zero fill before the next aligned section, as before `.plt`. What
        // follows the fill is code no entry lists.
        if unwinding == Unwinding::CannotUnwind {
            let mut skipped = 0;
            while skipped < MOST_FILL_WORDS && word_at(address) == Some(0) {
                address += 4;
                skipped += 1;
            }
        }
        // The entry names the first instruction of a function. A table of
        // small numbers otherwise reads as an index.
        if !arch.can_open_function(bytes_at(address)?) {
            return None;
        }
        Some(IndexEntry { address, unwinding })
    };

    let mut runs = Vec::new();
    let mut offset = 0;
    while offset + EXIDX_ENTRY_LEN <= data.len() {
        let run: Vec<IndexEntry> = (offset..data.len())
            .step_by(EXIDX_ENTRY_LEN)
            .map_while(entry)
            .scan(None, |previous: &mut Option<u64>, entry| {
                let rising = previous.is_none_or(|previous| entry.address > previous);
                *previous = Some(entry.address);
                rising.then_some(entry)
            })
            .collect();
        // An entry names a function, never the table itself. Zero fill
        // reads as a run of entries that each point at themselves.
        let span = base + offset as u64..base + (offset + run.len() * EXIDX_ENTRY_LEN) as u64;
        let outside = run.iter().all(|entry| !span.contains(&entry.address));
        // A table of one repeated number reads as entries whose targets rise
        // eight bytes at a time, in step with the entries: on Lua for ARM, 23
        // such pointed into the middle of `.text`. Functions of two
        // instructions are not that common.
        let in_step = run
            .windows(2)
            .filter(|pair| pair[1].address - pair[0].address == EXIDX_ENTRY_LEN as u64)
            .count();
        if run.len() >= FEWEST_INDEX_ENTRIES && outside && in_step * 2 <= run.len() {
            offset += run.len() * EXIDX_ENTRY_LEN;
            runs.push(run);
        } else {
            offset += 4;
        }
    }
    keep_whole_indexes(runs)
}

/// The runs that are whole indexes, longest first, their entries in one
/// list.
///
/// A table near the index can read as a shorter run whose functions fall
/// between those the index names: on tinyxml2 for Thumb-2, 17 such entries
/// came just before the index and split `XMLPrinter::PushAttribute`. A
/// second index, of another image, names functions of its own range, so a
/// run whose targets fall inside a longer run's range, but are not its
/// entries, is dropped.
fn keep_whole_indexes(mut runs: Vec<Vec<IndexEntry>>) -> Vec<IndexEntry> {
    runs.sort_by_key(|run| core::cmp::Reverse(run.len()));
    let mut kept: Vec<Vec<IndexEntry>> = Vec::new();
    for run in runs {
        let interleaves = kept.iter().any(|index| {
            let (first, last) = (index[0].address, index[index.len() - 1].address);
            run.iter().any(|entry| {
                (first..=last).contains(&entry.address)
                    && index.binary_search_by_key(&entry.address, |known| known.address).is_err()
            })
        });
        if !interleaves {
            kept.push(run);
        }
    }
    let mut found: Vec<IndexEntry> = kept.into_iter().flatten().collect();
    found.sort_by_key(|entry| entry.address);
    found
}

/// Read function addresses from the unwind index.
///
/// The architecture names the section, and reports `None` when its ABI has no
/// such table, which skips this source entirely.
///
/// The entry format read here is the one ARM EHABI defines: eight bytes, a
/// `PREL31` offset to the function then one word describing how to unwind it,
/// where `PREL31` is a signed 31-bit offset from the place the field itself
/// sits. An architecture whose table is laid out differently needs this parser
/// moved behind the trait as well; until one exists, the format stays here
/// with the rest of the scanning.
///
/// In a relocatable object the field holds the target directly, because the
/// relocation that would make it relative has not been applied. Both readings
/// are tried, and the one that lands inside a code section wins.
/// The address ranges that entries which list their function exactly cover:
/// from each such entry to the next entry.
fn described_ranges(index: &[IndexEntry]) -> Vec<core::ops::Range<u64>> {
    let mut sorted = index.to_vec();
    sorted.sort_by_key(|entry| entry.address);
    sorted
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.unwinding == Unwinding::Listed)
        .filter_map(|(position, entry)| {
            let end = sorted.get(position + 1)?.address;
            (end > entry.address).then_some(entry.address..end)
        })
        .collect()
}

/// The address ranges that entries which cannot unwind cover: from each such
/// entry to the next entry, or to the end of the address space.
fn cannot_unwind_ranges(index: &[IndexEntry]) -> Vec<core::ops::Range<u64>> {
    let mut sorted = index.to_vec();
    sorted.sort_by_key(|entry| entry.address);

    sorted
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.unwinding == Unwinding::CannotUnwind)
        .map(|(position, entry)| {
            let end = sorted.get(position + 1).map_or(u64::MAX, |next| next.address);
            entry.address..end
        })
        .collect()
}

fn exception_index(file: &object::File<'_>, arch: &dyn Recovery) -> Vec<IndexEntry> {
    let Some(name) = arch.unwind_section() else { return Vec::new() };
    let Some(section) = file.section_by_name(name) else { return Vec::new() };
    let Ok(data) = section.data() else { return Vec::new() };

    let code_ranges: Vec<(u64, u64)> = file
        .sections()
        .filter(|candidate| candidate.kind() == SectionKind::Text && candidate.size() > 0)
        .map(|candidate| (candidate.address(), candidate.address() + candidate.size()))
        .collect();

    let in_code = |address: u64| code_ranges.iter().any(|(lo, hi)| address >= *lo && address < *hi);

    // An executable or shared object has had its relocations applied. A
    // relocatable object has not, so its `PREL31` fields still hold targets.
    let relocated = !matches!(file.kind(), object::ObjectKind::Relocatable);

    let mut out = Vec::new();
    for (index, entry) in data.as_chunks::<EXIDX_ENTRY_LEN>().0.iter().enumerate() {
        let raw = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        let unwinding = match u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]) {
            EXIDX_CANTUNWIND => Unwinding::CannotUnwind,
            _ => Unwinding::Described,
        };

        // The top bit marks a "cannot unwind" entry, not part of the offset.
        let offset = sign_extend_31(raw & 0x7fff_ffff);
        let field_address = section.address() + (index * EXIDX_ENTRY_LEN) as u64;

        let relative = field_address.wrapping_add(offset as u64);
        let direct = u64::from(raw & 0x7fff_ffff);

        // A linked image holds a true `PREL31` offset, so the relative
        // reading is right, and it is the only one taken. A relocatable
        // object has not had its relocations applied, so the field still
        // holds the target itself, with the relative reading as a fallback
        // for an object that does not fit that pattern.
        //
        // A linked image gets no fallback because its last entry is a
        // sentinel the linker places at the end of the code, just outside
        // it. Read as a plain number instead, that field landed inside a
        // function of Lua built as an ARM shared library, and split it at a
        // different place in each release.
        let address = if relocated {
            in_code(relative).then_some(relative)
        } else if in_code(direct) {
            Some(direct)
        } else {
            in_code(relative).then_some(relative)
        };

        if let Some(address) = address {
            out.push(IndexEntry { address, unwinding });
        }
    }

    out
}

/// Sign extend a 31-bit value to a signed 64-bit one.
fn sign_extend_31(value: u32) -> i64 {
    const SIGN_BIT: u32 = 1 << 30;
    if value & SIGN_BIT != 0 { i64::from(value) - (1 << 31) } else { i64::from(value) }
}

/// Collect the addresses where a sequence opens that only a function entry
/// runs.
///
/// A function reached only through a pointer or the global offset table has
/// no call to name it, and one after a call that does not return, such as
/// `_Unwind_Resume`, follows no return. Measured on tinyxml2 for MIPS, both
/// joined two functions into one.
fn function_entries(arch: &dyn Recovery, insns: &[Insn]) -> Vec<u64> {
    (0..insns.len())
        .filter(|&index| arch.is_function_entry(&insns[index..]))
        .map(|index| insns[index].address)
        .collect()
}

/// Collect the addresses that calls jump to.
///
/// Anything called is a function. This misses a function nothing calls, such
/// as an entry point or a handler reached through a table.
///
/// A call that points at itself is discarded. In a relocatable object the
/// linker has not filled in the target yet, so every such call encodes the
/// placeholder `bl .-8`, which reads back as the call site. Believing those
/// would make a function start at every call.
fn call_targets(arch: &dyn Recovery, region: &Region<'_>) -> Vec<u64> {
    let (base, code, insns) = (region.base, region.code, region.insns.as_slice());
    let end = base + code.len() as u64;

    // A pool word that decodes as a call names a target made of data bits.
    let regions = [(base, code)];
    let pool = data_words(arch, &Memory::new(&regions), base..end, insns);

    // A string decodes as instructions too, and on ARM it often reads as a
    // conditional call: `blvs` is `k` in its top byte. Measured on Lua for
    // ARM as a raw image, the text "ON\0k" in `.rodata` "called" the middle
    // of `luaopen_base` and split it. A real call word is almost never text.
    let is_text = |insn: &Insn| {
        usize::try_from(insn.address - base)
            .ok()
            .and_then(|offset| code.get(offset..offset + insn.bytes_len))
            .is_some_and(crate::raw::is_text)
    };

    // A tail call jumps to a PLT stub that nothing may call, and a stub is
    // plain to see: measured on zlib 1.2.12 built by GCC for ARM as a raw
    // image, `crc32_combine_gen64@plt` was reached only by `b`, and joined the
    // stub before it.
    let is_stub = |target: u64| {
        usize::try_from(target.wrapping_sub(base))
            .ok()
            .and_then(|offset| code.get(offset..))
            .is_some_and(|stub| arch.stub_slot(stub, target).is_some())
    };

    insns
        .iter()
        .filter(|insn| !pool.contains(&insn.address) && !is_text(insn))
        .filter_map(|insn| match insn.kind {
            // A call to the next instruction only reads its own address, as
            // `call $+5` of 32-bit x86 PIC does: no function starts there.
            InsnKind::Call { target: Some(target) }
                if target == insn.address + insn.bytes_len as u64 =>
            {
                None
            }
            InsnKind::Call { target } => target.map(|target| (insn.address, target)),
            // An x86 compiler drops a jump to the next instruction, so only
            // the linker leaves one: a tail call to the function it put
            // next. Measured on a static musl build, `recv` ends with
            // `jmp recvfrom` and `recvfrom` follows it.
            InsnKind::Jump { target: Some(target) }
                if arch.instruction_width() == 1
                    && target == insn.address + insn.bytes_len as u64 =>
            {
                Some((insn.address, target))
            }
            InsnKind::Jump { target: Some(target) } if is_stub(target) => {
                Some((insn.address, target))
            }
            _ => None,
        })
        .filter(|(address, target)| target != address)
        .map(|(_, target)| target)
        // A call out of this section goes somewhere this pass cannot see.
        .filter(|target| *target >= base && *target < end)
        .filter(|&target| !pops_a_frame_it_did_not_make(arch, insns, target))
        .collect()
}

/// Whether the code at `target` reaches a return that pops `pc` before it
/// makes a frame of its own.
///
/// No function pops a frame it did not push, so such code is the epilogue
/// of the function around it. A `b` of ARMv6-M reaches only 2 KiB, so clang
/// jumps farther inside a function with `bl`, as to the shared epilogue of
/// `deflate` in zlib for Cortex-M0.
fn pops_a_frame_it_did_not_make(arch: &dyn Recovery, insns: &[Insn], target: u64) -> bool {
    /// Longer than any epilogue.
    const MOST_INSTRUCTIONS: usize = 16;
    let Ok(start) = insns.binary_search_by_key(&target, |insn| insn.address) else {
        return false;
    };
    for insn in insns[start..].iter().take(MOST_INSTRUCTIONS) {
        if arch.is_prologue(insn) {
            return false;
        }
        match insn.kind {
            InsnKind::Return => {
                return hereticus_il::arch::arm32::core_opcode(insn)
                    == Some(yaxpeax_arm::armv7::Opcode::POP)
                    && arch.lift(insn).is_some_and(|lifted| {
                        // `pop {pc}` alone lifts as the register, not a list.
                        lifted.operands.iter().any(|operand| match operand {
                            hereticus_il::Operand::RegisterList(list) => {
                                list.contains(hereticus_il::Reg::ProgramCounter)
                            }
                            hereticus_il::Operand::Reg(reg) => {
                                *reg == hereticus_il::Reg::ProgramCounter
                            }
                            _ => false,
                        })
                    });
            }
            InsnKind::Normal | InsnKind::Unknown => {}
            _ => return false,
        }
    }
    false
}

/// Guess that code following a return starts a new function.
///
/// The weakest source, and the one that invents boundaries. Two things keep it
/// from inventing too many.
///
/// Padding between functions is stepped over, so an address is only offered
/// when the bytes there decode into something real.
///
/// A return in the middle of a function is ignored. Most functions return from
/// more than one place — a guard clause, an early exit — and treating each as
/// the end of a function cuts one function into several. A branch that starts
/// at or before the return and lands after it proves control flows across it,
/// which marks it internal. Measured on a stripped kernel object, this drops
/// the count from ten recovered functions to the four that exist, missing
/// none. On a vendor firmware image it removes 104 of 144 candidate
/// boundaries.
#[cfg(test)]
fn starts_after_returns(arch: &dyn Recovery, code: &[u8], base: u64) -> Vec<u64> {
    let regions = [(base, code)];
    let region = Region::decode(arch, base, code);
    starts_after_returns_in(arch, &region, &Memory::new(&regions), &Linked::default())
}

/// `starts_after_returns`, where `memory` holds what else the binary loads.
fn starts_after_returns_in(
    arch: &dyn Recovery,
    region: &Region<'_>,
    memory: &Memory<'_>,
    linked: &Linked,
) -> Vec<u64> {
    let (base, code, insns) = (region.base, region.code, region.insns.as_slice());
    let never_returns = calls_that_never_return(arch, insns, memory, &linked.slot_names);
    let end = base + code.len() as u64;

    // Pool words are data. Read as code they are a random return or branch,
    // which moves with their values from one release to the next.
    let pool = data_words(arch, memory, base..end, insns);
    let is_code = |insn: &&Insn| !pool.contains(&insn.address);

    // Every branch, as (from, to, how). A jump through a table picks one
    // case by a value, as a conditional branch picks one of two ways, and
    // it never reaches another function either.
    let direct = insns.iter().filter(is_code).filter_map(|insn| match insn.kind {
        InsnKind::Branch { target: Some(target) } => {
            Some((insn.address, target, Transfer::Conditional))
        }
        InsnKind::Jump { target: Some(target) } => Some((insn.address, target, Transfer::Always)),
        _ => None,
    });
    let tables = arch.jump_tables(memory, base..end, insns);
    let table_jumps: BTreeSet<u64> = tables.iter().map(|table| table.jump).collect();
    let through_tables = tables.into_iter().flat_map(|table| {
        table.targets.into_iter().map(move |target| (table.jump, target, Transfer::Conditional))
    });
    let mut all_branches: Vec<(u64, u64, Transfer)> = direct.chain(through_tables).collect();
    all_branches.sort_unstable_by_key(|&(from, to, _)| (from, to));

    // Branches that stay inside this region, as (from, to), in order of
    // `from`. A function can return from several places — an early exit, a
    // guard clause — and each of those returns is followed by more of the
    // same function.
    let branches: Vec<(u64, u64)> = all_branches
        .iter()
        .filter(|&&(_, target, _)| target >= base && target < end)
        .map(|&(from, to, _)| (from, to))
        .collect();

    // Where each branch lands, and every place it comes from.
    let mut sources_of: BTreeMap<u64, Vec<(u64, Transfer)>> = BTreeMap::new();
    for &(from, to, transfer) in &all_branches {
        sources_of.entry(to).or_default().push((from, transfer));
    }

    // Addresses sure to start a function: what is called, what opens with an
    // entry sequence, and what opens a frame. A branch inside a function never crosses the start of another.
    //
    // A frame that a conditional branch runs into is made late, on the path
    // that needs it, as `luaC_linkupval` in Lua for MIPS does after its
    // early return. It is inside a function, so it is no sure start.
    let sure_starts: BTreeSet<u64> =
        call_targets(arch, region).into_iter().chain(function_entries(arch, insns)).collect();
    let is_sure_start = |address: u64| sure_starts.contains(&address);
    let may_open = |address: u64| {
        usize::try_from(address - base)
            .ok()
            .and_then(|offset| code.get(offset..))
            .is_some_and(|word| arch.may_open_function(word))
    };
    // The block a prologue sits in, and whether a conditional branch reaches
    // it. Code reaches another function only by a call or an unconditional
    // jump, so such a block is inside a function, and so is its frame: GCC
    // at `-Os` returns early with `bxle lr` and makes the frame after, in
    // `aux_upvalue` of Lua.
    //
    // Nor is a frame on one path of a conditional branch: walking back over
    // plain code and early returns, the first other control word is such a
    // branch, whose other path is the rest of the function. Clang does this
    // on MIPS in `lua_gettable`, after `bnez` and its delay slot.
    let is_inside_a_function = |index: usize| {
        let mut start = index;
        while start > 0 && is_code(&&insns[start - 1]) {
            match insns[start - 1].kind {
                InsnKind::Normal | InsnKind::Unknown | InsnKind::Branch { target: None } => {
                    start -= 1;
                }
                InsnKind::Branch { target: Some(_) } => return true,
                // The block starts after the delay slots of what ends the
                // one before it.
                _ => {
                    start = (start + arch.delay_slots(&insns[start - 1])).min(index);
                    break;
                }
            }
        }
        // A branch lands past the padding that can open a block, as GCC
        // puts one word after the jump through a table.
        while start < index && arch.is_padding(&insns[start]) {
            start += 1;
        }
        // No code runs into a frame made right after a pool, and a function
        // makes its frame first: a pool inside a function sits after a
        // jump, before more of the body. Clang for ARM puts `codebinexpval`
        // of Lua after the pool of `luaK_posfix`, which reaches it by a tail
        // call.
        // A conditional branch still never comes from another function: GCC
        // for Thumb-2 puts a pool after a call to `__assert_fail` in the
        // middle of libtiff's `TIFFWriteDirectorySec`, and a `bne.w` from
        // far before reaches the code after it.
        let after_pool = start == index && index > 0 && !is_code(&&insns[index - 1]);
        // A conditional branch never comes from another function, and nor
        // does any branch from after the last sure start: a tail call comes
        // from the function before. Clang on MIPS jumps with `b` to the late
        // frame of `lua_setmetatable`, which opens with an entry sequence.
        let block = insns[start].address;
        let last_sure_start = sure_starts.range(..=block).next_back().copied();
        sources_of.get(&block).is_some_and(|sources| {
            sources.iter().any(|&(from, transfer)| {
                transfer == Transfer::Conditional
                    || !after_pool
                        && last_sure_start.is_some_and(|start| from >= start && from < block)
            })
        })
    };
    let anchors: BTreeSet<u64> = insns
        .iter()
        .enumerate()
        .filter(|(index, insn)| {
            is_code(insn) && arch.is_prologue(insn) && !is_inside_a_function(*index)
        })
        .map(|(_, insn)| insn.address)
        .chain(sure_starts.iter().copied())
        .collect();

    // A branch that starts at or before a return and lands after it proves
    // control flows across that return, so the return is inside a function
    // rather than at the end of one. Only a branch from the same function
    // counts, which is one with no sure start between it and the return. In
    // a raw image, data before the code decodes as branches that cross
    // every return: measured on zlib for MIPS, these hid 48 of 123 functions.
    //
    // The same holds for where it lands: a branch to the next sure start or
    // past it leaves the function, as a tail call does. Measured on tinyxml2
    // for ARM as a raw image, `b` to a PLT stub past the end of `.text`
    // otherwise crossed the return of every function after it.
    let is_internal = |address: u64| {
        let function_start = anchors.range(..=address).next_back().copied().unwrap_or(base);
        let next_start = anchors.range(address + 1..).next().copied().unwrap_or(u64::MAX);
        let first = branches.partition_point(|&(from, _)| from < function_start);
        branches[first..]
            .iter()
            .take_while(|&&(from, _)| from <= address)
            .any(|&(_, to)| to > address && to < next_start)
    };

    // The jumps through a register that are neither a table the scan read
    // nor a tail call: what they reach is unknown.
    let unread_jumps: Vec<u64> = insns
        .iter()
        .filter(|insn| {
            is_code(insn)
                && insn.kind == (InsnKind::Jump { target: None })
                && !table_jumps.contains(&insn.address)
                && !arch.is_tail_call(insn)
        })
        .map(|insn| insn.address)
        .collect();
    let all_jumps_read = |start: Option<u64>, end: u64| {
        let Some(start) = start else { return false };
        let first = unread_jumps.partition_point(|&address| address < start);
        arch.table_jumps() == TableJumps::Distinct
            && unread_jumps.get(first).is_none_or(|&address| address >= end)
    };

    let mut out = Vec::new();
    // The last return before the current instruction. The code after it is
    // the function the current instruction is in, or the start of it.
    let mut previous_return = None;
    for (index, insn) in insns.iter().enumerate() {
        // A call that does not return, as to `exit`, is followed by the next
        // function, where its prologue comes next and no branch reaches it.
        // A call that returns is followed by more of its own function, which
        // does not open a frame. Measured on the releases built for the tests,
        // as Lua's `os_getenv` after `os_exit`, this found 8 more function
        // starts and invented none.
        if matches!(insn.kind, InsnKind::Call { .. }) && is_code(&insn) {
            // The pool of the function, or padding, can come between: clang
            // for ARM puts the pool word of the message after the call to
            // `luaG_typeerror` that ends `luaV_objlen`, before `luaV_div`.
            let after_call = index + 1 + arch.delay_slots(insn);
            let mut next = after_call;
            let mut past_pool = false;
            while insns.get(next).is_some_and(|insn| arch.is_padding(insn) || !is_code(&insn)) {
                past_pool |= !is_code(&&insns[next]);
                next += 1;
            }
            // A branch can reach it only where the call is followed by data,
            // which proves it does not return: then the branch is a tail
            // call from another function, as `b luaV_div` in Lua for ARM.
            // Measured on the OpenWrt MIPS kernels, allowing such a branch
            // after any call left 19 to 34 more changed bytes unreported.
            // A callee the linker names as one that never returns, as
            // `__assert_fail`, ends its caller even where a leaf with no
            // frame comes next, as `errorProcessor` of expat for MIPS does.
            // So does a jump from another function, past the data: GCC for
            // Thumb-2 tail calls libpng's `png_write_IEND` from far before,
            // after `png_error` and the pool that end `png_write_PLTE`, and
            // `png_write_IEND` loads from its pool before its frame.
            let tail_called = |following: &Insn| {
                let start = anchors.range(..=insn.address).next_back().copied().unwrap_or(base);
                let next_start =
                    anchors.range(following.address + 1..).next().copied().unwrap_or(u64::MAX);
                past_pool
                    && sources_of.get(&following.address).is_some_and(|sources| {
                        sources.iter().any(|&(from, transfer)| {
                            transfer == Transfer::Always && (from < start || from >= next_start)
                        })
                    })
            };
            let opens = |following: &Insn| {
                arch.is_prologue(following)
                    || never_returns.contains(&insn.address)
                    || tail_called(following)
            };
            if let Some(following) = insns.get(next)
                && opens(following)
                && (past_pool || !sources_of.contains_key(&following.address))
                && !is_inside_a_function(next)
            {
                out.push(start_of(insns, next, arch));
            }
        }
        // Only code that does not fall through can be followed by a new
        // function. Everything else continues the one it is in.
        if !matches!(insn.kind, InsnKind::Return | InsnKind::Jump { .. }) || !is_code(&insn) {
            continue;
        }
        let since = previous_return;
        let function_start = anchors.range(..=insn.address).next_back().copied();
        // A tail call ends a function as a return does: a jump to the start
        // of another function, or through a register the ABI calls through.
        // Measured on the releases built for the tests, where
        // `XMLText::Accept` for ARM ends with `bx r3` and `XMLUtil::ToStr`
        // with `b` to `snprintf`, this found 125 more function starts of
        // 27500 and invented 16.
        let ends = match insn.kind {
            InsnKind::Return => true,
            InsnKind::Jump { target: None } => {
                arch.is_tail_call(insn) && !table_jumps.contains(&insn.address)
            }
            // A jump out of the region leaves too, where it lands in what the
            // binary loads, as a jump to a PLT stub does. Data and bytes read
            // in the wrong order decode as jumps that land anywhere, mostly
            // where nothing is loaded.
            InsnKind::Jump { target: Some(target) } if target < base || target >= end => {
                memory.bytes(target, arch.instruction_width()).is_some()
            }
            // Inside it, only a jump to the start of another function is a
            // tail call. The kernel's exception fixups jump back into the
            // middle of the function they serve.
            //
            // A jump back into this function, after its start, closes a loop,
            // and nothing falls through it either. Where padding follows, the
            // function ends there: a compiler pads between functions. Where
            // a jump through a table is an instruction of its own, and the
            // scan read each in the function so far, it ends there too, as
            // the checks below ask whether a branch reaches what follows.
            // Else what follows may be reached only through an unread table,
            // as on MIPS. Measured on the stripped releases, where the cases
            // of a GCC `tbb` table for Thumb-2 each end with `b` back to the
            // loop, as in expat, this found 117 more function starts and
            // invented 1 more.
            InsnKind::Jump { target: Some(target) } => {
                let closes_a_loop =
                    function_start.is_some_and(|start| start <= target && target < insn.address);
                // The pool of a function sits at its end as padding does.
                // A pool in the middle, which branches jump over, still
                // stays inside by the checks below.
                let padded = insns
                    .get(index + 1 + arch.delay_slots(insn))
                    .is_some_and(|next| arch.is_padding(next) || !is_code(&next));
                (anchors.contains(&target) && Some(target) != function_start)
                    || (closes_a_loop && (padded || all_jumps_read(function_start, insn.address)))
            }
            _ => false,
        };
        if ends {
            previous_return = Some(insn.address);
        }

        // No branch lands on data, so a word that a branch from this
        // function reaches is code, and a literal pool cannot hold it. Only
        // a branch from after the last return counts: in a raw image, data
        // decodes as branches too, and these land anywhere. Measured on zlib
        // for MIPS, a word of `.rodata` "branched" to the start of
        // `inflateMark`, 126 KiB away.
        // A branch of this function comes from after its start, the last sure
        // start before here, or after the last return where no sure start is
        // known. A function can return more than once, so the last return
        // alone would miss a branch from before an early one.
        let reached_by = |address: u64, accepted: &[Transfer]| {
            sources_of.get(&address).is_some_and(|sources| {
                sources.iter().any(|&(from, transfer)| {
                    let of_this_function = match function_start {
                        Some(start) => from >= start,
                        None => since.is_none_or(|since| from > since),
                    };
                    // The terminator itself counts: a jump through a table
                    // can land right after itself, on its first case.
                    from <= insn.address && of_this_function && accepted.contains(&transfer)
                })
            })
        };
        let reached_here =
            |address: u64| reached_by(address, &[Transfer::Conditional, Transfer::Always]);

        // Step over the delay slot, which belongs to the terminator rather
        // than to what follows, and then over any padding the linker put
        // between functions and the pool the function ends with.
        let mut next = index + 1 + arch.delay_slots(insn);
        while insns.get(next).is_some_and(|insn| arch.is_padding(insn) || !is_code(&insn)) {
            next += 1;
        }
        // A linker fills the gap before an aligned section with zeros, which
        // ARM reads as `andeq r0, r0, r0`: measured on smallvec for ARM as a
        // raw image, one such word before `.plt` joined the PLT header to the
        // last function of `.text`. A zero word is also a constant in a pool
        // no load names, so only a prologue past the fill counts.
        let past_fill = next
            + insns[next.min(insns.len())..]
                .iter()
                .take_while(|insn| is_zero_fill(code, base, insn))
                .count();
        if past_fill > next && insns.get(past_fill).is_some_and(|insn| arch.is_prologue(insn)) {
            next = past_fill;
        }

        let Some(following) = insns.get(next) else { continue };

        // Code reaches another function by a call or by an unconditional
        // tail jump, never on a condition. So what a conditional branch of
        // this function reaches is more of it, even a prologue: a compiler
        // that returns early, before it makes a frame, puts the frame on the
        // path the branch takes, as `gzgetc` in zlib for ARM does after its
        // `bx lr`.
        if reached_by(following.address, &[Transfer::Conditional]) {
            continue;
        }
        // So is what a conditional branch from later in it reaches, as a
        // loop at the end of a function reaches back past an early return.
        // Later in it is before the next sure start.
        let next_start =
            sure_starts.range(following.address + 1..).next().copied().unwrap_or(u64::MAX);
        let reached_from_later = sources_of.get(&following.address).is_some_and(|sources| {
            sources.iter().any(|&(from, transfer)| {
                transfer == Transfer::Conditional && from > following.address && from < next_start
            })
        });
        if reached_from_later {
            continue;
        }

        // Otherwise a prologue is a function start whatever precedes it. This
        // is the stronger signal, so it is not subject to the spanning test:
        // an error path that jumps backwards over the end of its own function
        // would otherwise hide the function that follows.
        if arch.is_prologue(following) {
            out.push(start_of(insns, next, arch));
            continue;
        }

        // A compiler can drop a literal pool between two functions. Its words
        // are constants, but they still decode as instructions — often valid
        // ones — so the code right after a terminator is not the next
        // function's prologue. A prologue a few words past the pool is still a
        // function start, and a function reached only through a pointer has no
        // call or branch to name it, so this is the one source that can find
        // it. Look a short way ahead, stopping at any further terminator so the
        // scan cannot cross into real control flow.
        if let Some(prologue) = prologue_past_pool(
            insns,
            next,
            &reached_here,
            &|address| pool.contains(&address),
            &is_sure_start,
            &may_open,
            arch,
        ) {
            out.push(prologue);
            continue;
        }

        // A new function never starts by branching into the middle of the
        // one before: a tail call goes to a function's start. So a first
        // block that branches back past the start of this function, to no
        // known start, is more of it, reached through a table the scan did
        // not read. Measured on the stripped releases, the cases after the
        // early return of expat's `prologTok` for MIPS and the like read as
        // 24 invented functions, and none was missed for it.
        let branches_back = function_start.is_some_and(|start| {
            let mut block = insns[next..].iter();
            let mut ended = false;
            block
                .by_ref()
                .take_while(|insn| {
                    let go = !ended;
                    ended |= !matches!(insn.kind, InsnKind::Normal | InsnKind::Unknown);
                    go
                })
                .any(|insn| match insn.kind {
                    InsnKind::Branch { target: Some(target) }
                    | InsnKind::Jump { target: Some(target) } => {
                        start < target && target < following.address && !anchors.contains(&target)
                    }
                    _ => false,
                })
        });

        // Otherwise only a return that nothing branches across ends a
        // function. A jump without a prologue after it is a tail call or a
        // loop, which stays inside.
        let opens = may_open(following.address);
        if ends && !is_internal(insn.address) && opens && !branches_back {
            out.push(following.address);
        }
    }

    out
}

/// Report whether every byte of `insn` is zero.
fn is_zero_fill(code: &[u8], base: u64, insn: &Insn) -> bool {
    usize::try_from(insn.address - base)
        .ok()
        .and_then(|offset| code.get(offset..offset.checked_add(insn.bytes_len)?))
        .is_some_and(|bytes| bytes.iter().all(|&byte| byte == 0))
}

/// The words of a region that are data among the code: literal pools, and
/// the tables that jumps go through.
fn data_words(
    arch: &dyn Recovery,
    memory: &Memory<'_>,
    code: core::ops::Range<u64>,
    insns: &[Insn],
) -> BTreeSet<u64> {
    let tables = arch.jump_tables(memory, code, insns);
    let table_words =
        tables.iter().flat_map(|table| table.words.clone().step_by(arch.instruction_width()));
    arch.literal_pool_words(insns).into_iter().chain(table_words).collect()
}

/// Whether a branch always moves control, or only on a condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transfer {
    Conditional,
    Always,
}

/// The address a function really starts at, given where its prologue sits.
///
/// A prologue opens its function on most ABIs, but not all: MIPS PIC computes
/// the global pointer first, so the function begins a word or two before the
/// frame allocation. The architecture decides how far back to look, and the
/// instructions before `prologue` bound it, so a preamble can never reach past
/// the start of the slice.
fn start_of(insns: &[Insn], prologue: usize, arch: &dyn Recovery) -> u64 {
    // An architecture answers for its own ABI, and a wrong answer here would
    // move a boundary rather than fail. Clamping keeps a decoder bug from
    // reaching past the words this scan was given.
    let preamble = arch.preamble_before_prologue(&insns[..prologue]).min(prologue);
    insns[prologue - preamble].address
}

/// Find a prologue that begins just past an inline literal pool.
///
/// A terminator can be followed by a literal pool rather than by the next
/// function's first instruction. Pool words are constants, but they decode as
/// instructions — sometimes valid, sometimes `Unknown` — so the word right
/// after the terminator is not the prologue, and a scan that judged only that
/// word would miss the function behind the pool.
///
/// The scan steps over up to a short run of such words and takes a prologue
/// found within it. It stops at any further terminator: past a second `bx lr`
/// or branch the scan would be in real control flow, where a prologue is
/// inside a function rather than after a pool. The bound keeps a pool — a
/// handful of words — from being confused with the body of a function.
///
/// A word a branch lands on is code, not a pool, so the scan stops there too.
/// Without this, a compiler that moves the frame allocation down to the one
/// path that calls, as `-Os` does, splits the function at it: measured on
/// zlib for MIPS, `_tr_align` split in two after an internal `b`.
///
/// `reached` says whether a branch of the function lands on an address.
/// Returns the prologue address, or `None` when no prologue sits within the
/// window.
fn prologue_past_pool(
    insns: &[Insn],
    from: usize,
    reached: &dyn Fn(u64) -> bool,
    is_pool: &dyn Fn(u64) -> bool,
    is_sure_start: &dyn Fn(u64) -> bool,
    may_open: &dyn Fn(u64) -> bool,
    arch: &dyn Recovery,
) -> Option<u64> {
    /// The most words not known to be pool data to step over before a
    /// prologue. A literal pool between two functions holds a few constants;
    /// a longer run is a function body, not a pool, and its first
    /// prologue-shaped word is not a function start.
    const MOST_POOL_WORDS: usize = 8;

    let mut next = from;
    let mut guessed = 0;
    while guessed < MOST_POOL_WORDS {
        let insn = insns.get(next)?;
        // A word a load names is pool data for certain, so it does not count
        // against the limit. The words it cannot name, such as the doubles
        // that VFP `vldr` loads in Lua's `luaopen_math`, still do.
        if is_pool(insn.address) {
            next += 1;
            continue;
        }
        guessed += 1;
        // A call target or an entry sequence starts a function for certain,
        // pool or no pool.
        if is_sure_start(insn.address) {
            return Some(insn.address);
        }
        if arch.is_prologue(insn) {
            // Where no pool can sit between functions, every word before the
            // prologue is this function's: a compiler schedules work before
            // the frame allocation. Measured on the VR200 kernel, a `lui`
            // before `addiu sp, sp, -0x40` otherwise put the start one word
            // late and left that word a function of its own.
            //
            // Elsewhere, a preamble before this prologue belongs to the
            // function, but only as far back as the pool scan began: earlier
            // words are the pool, not this function's opening.
            return Some(match arch.data_among_code() {
                DataAmongCode::Never => insns[from].address,
                // The words just before the prologue that could open a
                // function, and are no known pool, are this function's: a
                // compiler schedules work before the frame, as GCC puts
                // `add ip, r0, 4096` before the `push` of `_tr_stored_block`.
                DataAmongCode::LiteralPools => {
                    let mut start = next;
                    while start > from
                        && !is_pool(insns[start - 1].address)
                        && may_open(insns[start - 1].address)
                    {
                        start -= 1;
                    }
                    if start == next {
                        start_of(&insns[from..], next - from, arch)
                    } else {
                        insns[start].address
                    }
                }
            });
        }
        // Only pool data may sit between the terminator and the prologue. A
        // pool word carries no control flow: it decodes as a plain `Normal`
        // instruction or as `Unknown`. Any branch, call, jump or return means
        // the scan has entered a function body, where a `push` is a mid-body
        // save rather than a prologue, so stop before claiming it.
        if !matches!(insn.kind, InsnKind::Normal | InsnKind::Unknown) || reached(insn.address) {
            return None;
        }
        next += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use hereticus_il::arch::Decoder as _;
    use hereticus_il::arch::arm32::Arm32;

    /// Thumb-2 halfwords as little-endian bytes.
    fn halfwords(halfwords: &[u16]) -> Vec<u8> {
        halfwords.iter().flat_map(|halfword| halfword.to_le_bytes()).collect()
    }

    /// The padding GCC puts after a Thumb-2 function, `nop` and zero
    /// halfwords, is stepped over to the next function.
    #[test]
    fn a_start_steps_past_padding() {
        use hereticus_il::arch::thumb::Thumb2;
        // bx lr, nop, two zero halfwords, then push {r4, lr}.
        let code = halfwords(&[0x4770, 0xbf00, 0x0000, 0x0000, 0xb510]);
        let regions = [(0x100, code.as_slice())];
        assert_eq!(past_padding(&regions, 0x102, &Thumb2), Some(0x108));
        assert_eq!(past_padding(&regions, 0x100, &Thumb2), Some(0x100), "no padding");
        assert_eq!(past_padding(&regions, 0x200, &Thumb2), None, "outside the region");
        let padding = halfwords(&[0xbf00, 0x0000]);
        assert_eq!(past_padding(&[(0x100, padding.as_slice())], 0x100, &Thumb2), None);
    }

    /// A guess that holds only padding makes no function; a fact does.
    #[test]
    fn a_guess_of_only_padding_makes_no_function() {
        use hereticus_il::arch::thumb::Thumb2;
        // bx lr, then a nop and two zero halfwords up to 0x108.
        let code = halfwords(&[0x4770, 0xbf00, 0x0000, 0x0000]);
        let regions = [(0x100, code.as_slice())];
        let starts = |source| BTreeSet::from([(0x100, Source::Symbol), (0x102, source)]);
        let found = build_functions(&starts(Source::AfterReturn), &regions, &Thumb2);
        assert_eq!(found.iter().map(|function| function.address).collect::<Vec<_>>(), [0x100]);
        let found = build_functions(&starts(Source::CallTarget), &regions, &Thumb2);
        assert_eq!(found.len(), 2, "something calls it");
    }

    /// A `pop` that loads `pc` returns from a frame, in its list form and
    /// alone; a `bx lr` pops no frame.
    #[test]
    fn a_pop_of_pc_in_either_form_pops_a_frame() {
        let pops = |word: u32| {
            let insns = crate::arch::decode_all(&Arm32, &word.to_le_bytes(), 0).0;
            pops_a_frame_it_did_not_make(&Arm32, &insns, 0)
        };
        assert!(pops(0xe8bd_8010), "pop {{r4, pc}}");
        assert!(pops(0xe49d_f004), "pop {{pc}}");
        assert!(!pops(0xe8bd_0010), "pop {{r4}}");
        assert!(!pops(0xe12f_ff1e), "bx lr");
    }

    /// A PIC call of MIPS32 through the slot at 0x10010, after the
    /// `_gp_disp` preamble.
    fn mips_call_through_slot() -> Vec<u8> {
        [
            0x3c1c_0002_u32, // lui gp, 0x2
            0x279c_8000,     // addiu gp, gp, -0x8000
            0x0399_e021,     // addu gp, gp, t9: gp is 0x18000
            0x8f99_8010,     // lw t9, -0x7ff0(gp)
            0x0320_f809,     // jalr t9
            0x0000_0000,     // nop
        ]
        .iter()
        .flat_map(|word| word.to_be_bytes())
        .collect()
    }

    #[test]
    fn a_call_to_a_callee_that_never_returns_is_found_by_its_slot() {
        let arch = &hereticus_il::arch::mips::Mips32::BIG;
        let code = mips_call_through_slot();
        let (insns, _) = decode_all(arch, &code, 0);
        let regions = [(0, code.as_slice())];
        let memory = Memory::new(&regions);
        let named = |name: &str| BTreeMap::from([(0x10010, name.to_string())]);

        let exit = calls_that_never_return(arch, &insns, &memory, &named("exit"));
        assert_eq!(exit, BTreeSet::from([0x10]));
        assert!(calls_that_never_return(arch, &insns, &memory, &named("puts")).is_empty());
        assert!(calls_that_never_return(arch, &insns, &memory, &BTreeMap::new()).is_empty());
    }

    #[test]
    fn call_frame_ranges_of_mips16_lose_bit_0() {
        let ranges = [0x6fd1..0x7095, 0x7095..0x70a1, 0x70b1..0x70c1];
        let entry = |address, unwinding| IndexEntry { address, unwinding };
        assert_eq!(
            index_from_ranges(&ranges, &hereticus_il::arch::mips16::Mips16::LITTLE),
            [
                entry(0x6fd0, Unwinding::Listed),
                entry(0x7094, Unwinding::Listed),
                entry(0x70a0, Unwinding::CannotUnwind),
                entry(0x70b0, Unwinding::Listed),
                entry(0x70c0, Unwinding::CannotUnwind),
            ]
        );
        let mips32 = index_from_ranges(
            core::slice::from_ref(&(0x100..0x110)),
            &hereticus_il::arch::mips::Mips32::LITTLE,
        );
        assert_eq!(
            mips32,
            [entry(0x100, Unwinding::Listed), entry(0x110, Unwinding::CannotUnwind)]
        );
    }

    /// A two-byte Thumb instruction at `address` that moves control as `kind`.
    fn thumb_insn(address: u64, kind: InsnKind) -> Insn {
        Insn::new(address, &[0; 2], kind, hereticus_il::arch::Opcode::None)
    }

    /// Instructions from 0x1000 up to 0x1100, all but `branches` plain.
    fn body_with(branches: &[(u64, InsnKind)]) -> Vec<Insn> {
        (0x1000..0x1100)
            .step_by(2)
            .map(|address| {
                let kind = branches
                    .iter()
                    .find(|(at, _)| *at == address)
                    .map_or(InsnKind::Normal, |&(_, kind)| kind);
                thumb_insn(address, kind)
            })
            .collect()
    }

    #[test]
    fn a_label_that_branches_cross_both_ways_lies_inside_a_body() {
        let insns = body_with(&[
            (0x1010, InsnKind::Branch { target: Some(0x1060) }),
            (0x1080, InsnKind::Jump { target: Some(0x1020) }),
        ]);
        assert!(lies_inside_a_body(&insns, 0x1050));
    }

    #[test]
    fn a_start_that_branches_cross_one_way_does_not_lie_inside_a_body() {
        let forward = body_with(&[(0x1010, InsnKind::Branch { target: Some(0x1060) })]);
        assert!(!lies_inside_a_body(&forward, 0x1050));
        let backward = body_with(&[(0x1080, InsnKind::Jump { target: Some(0x1020) })]);
        assert!(!lies_inside_a_body(&backward, 0x1050));
    }

    #[test]
    fn short_tail_calls_both_ways_do_not_make_a_body() {
        // Small functions that tail call their neighbours, as zlib's
        // `crc32_combine` and `crc32_combine64` do.
        let insns = body_with(&[
            (0x1010, InsnKind::Jump { target: Some(0x1060) }),
            (0x1080, InsnKind::Jump { target: Some(0x1020) }),
        ]);
        assert!(!lies_inside_a_body(&insns, 0x1050));
    }

    #[test]
    fn long_branches_do_not_make_a_body() {
        let mut insns = body_with(&[(0x1080, InsnKind::Jump { target: Some(0x1020) })]);
        insns.insert(0, thumb_insn(0x0e00, InsnKind::Branch { target: Some(0x1400) }));
        assert!(!lies_inside_a_body(&insns, 0x1050));
    }

    #[test]
    fn no_instructions_make_no_body() {
        assert!(!lies_inside_a_body(&[], 0x1050));
    }

    #[test]
    fn a_text_up_to_a_nul_is_text() {
        let bytes = b"xhello\0";
        let regions = [(0x100, &bytes[..])];
        assert!(points_at_text(&Memory::new(&regions), 0x101));
    }

    #[test]
    fn what_is_not_a_text_is_not_text() {
        let regions: [(u64, &[u8]); 4] =
            [(0x100, b"a\0"), (0x200, b"\x01\x02\0"), (0x300, b"no end"), (0x400, b"\0")];
        let memory = Memory::new(&regions);
        assert!(!points_at_text(&memory, 0x100), "one byte is too short");
        assert!(!points_at_text(&memory, 0x200), "control bytes are not printable");
        assert!(!points_at_text(&memory, 0x300), "a text ends with a NUL");
        assert!(!points_at_text(&memory, 0x400), "an empty text is not one");
        assert!(!points_at_text(&memory, 0x500), "nothing is loaded there");
    }

    #[test]
    fn a_text_too_long_for_a_message_is_not_text() {
        let mut bytes = vec![b'a'; 300];
        bytes.push(0);
        let regions = [(0x100, bytes.as_slice())];
        assert!(!points_at_text(&Memory::new(&regions), 0x100));
    }

    #[test]
    fn a_word_with_bit_0_set_tags_a_thumb_function() {
        let bytes = [0x01, 0x10, 0, 0, 0x00, 0x20, 0, 0];
        let regions = [(0x100, &bytes[..])];
        let tagged =
            tagged_functions(&hereticus_il::arch::thumb::Thumb2, &regions, &BTreeSet::new());
        assert_eq!(tagged, [0x1000]);
    }

    #[test]
    fn a_distance_word_tags_no_function() {
        let bytes = [0x01, 0x10, 0, 0];
        let regions = [(0x100, &bytes[..])];
        let distances = BTreeSet::from([0x100]);
        let tagged = tagged_functions(&hereticus_il::arch::thumb::Thumb2, &regions, &distances);
        assert!(tagged.is_empty());
    }

    #[test]
    fn the_tail_of_a_text_tags_no_function() {
        // `"ue"` of `"true"` reads as 0x6575, which has bit 0 set.
        let bytes = *b"\0\0tr\x75\x65\0\0";
        let regions = [(0x100, &bytes[..])];
        let tagged =
            tagged_functions(&hereticus_il::arch::thumb::Thumb2, &regions, &BTreeSet::new());
        assert!(tagged.is_empty());
    }

    /// Thumb code at 0x1000 that loads the pool word at 0x100c, returns,
    /// holds `between` up to the pool, then a second function at 0x1010.
    fn loads_over(between: &[u8]) -> Vec<u8> {
        let halfwords = |words: &[u16]| -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        };
        // ldr r0, [pc, 8]; bx lr
        let mut code = halfwords(&[0x4802, 0x4770]);
        code.extend_from_slice(between);
        assert_eq!(code.len(), 0xc, "the pool sits at 0x100c");
        code.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        // movs r0, 1; bx lr
        code.extend(halfwords(&[0x2001, 0x4770]));
        code
    }

    fn pool_span_survivors(code: &[u8], starts: &[(u64, Source)]) -> Vec<u64> {
        let regions = [(0x1000, code)];
        let arch = &hereticus_il::arch::thumb::Thumb2;
        let kept = outside_pool_spans(
            starts.iter().copied().collect(),
            arch,
            &[Region::decode(arch, 0x1000, code)],
            &Memory::new(&regions),
        );
        kept.into_iter().map(|(address, _)| address).collect()
    }

    /// movs r0, 0; bx lr; nop; nop
    const LANDING: [u8; 8] = [0x00, 0x20, 0x70, 0x47, 0x00, 0xbf, 0x00, 0xbf];

    #[test]
    fn a_guess_between_a_load_and_its_pool_is_dropped() {
        let code = loads_over(&LANDING);
        let starts = [
            (0x1000, Source::AfterReturn),
            (0x1004, Source::AfterReturn),
            (0x1010, Source::AfterReturn),
        ];
        assert_eq!(pool_span_survivors(&code, &starts), [0x1000, 0x1010]);
    }

    #[test]
    fn an_exact_start_between_a_load_and_its_pool_stays() {
        let code = loads_over(&LANDING);
        let starts = [(0x1004, Source::CallTarget)];
        assert_eq!(pool_span_survivors(&code, &starts), [0x1004]);
    }

    #[test]
    fn a_span_with_a_word_that_does_not_decode_drops_nothing() {
        // movs r0, 0; bx lr; then a word that is no T32 instruction.
        let code = loads_over(&[0x00, 0x20, 0x70, 0x47, 0xf0, 0xf7, 0x00, 0xa0]);
        let starts = [(0x1004, Source::AfterReturn)];
        assert_eq!(pool_span_survivors(&code, &starts), [0x1004]);
    }

    #[test]
    fn neon_between_a_load_and_its_pool_still_drops_the_guess() {
        // movs r0, 0; bx lr; then NEON `vmov.i32 q8, 0`, which stays opaque.
        let code = loads_over(&[0x00, 0x20, 0x70, 0x47, 0xc0, 0xef, 0x50, 0x00]);
        let starts = [(0x1004, Source::AfterReturn)];
        assert!(pool_span_survivors(&code, &starts).is_empty());
    }

    #[test]
    fn an_architecture_without_pool_loads_drops_nothing() {
        let code = loads_over(&LANDING);
        let regions = [(0x1000, code.as_slice())];
        let starts: BTreeSet<(u64, Source)> = [(0x1004, Source::AfterReturn)].into();
        let decoded = [Region::decode(&Arm32, 0x1000, &code)];
        let kept = outside_pool_spans(starts.clone(), &Arm32, &decoded, &Memory::new(&regions));
        assert_eq!(kept, starts);
    }

    /// A Thumb function at 0x1000 that ends with a loop, `b` back to
    /// 0x1004, then `between`, then a second function.
    fn loop_then(between: &[u16]) -> Vec<u8> {
        // push {r4, lr}; movs r0, 0; adds r0, 1; b 0x1004
        let mut halfwords = vec![0xb510, 0x2000, 0x3001, 0xe7fd];
        halfwords.extend_from_slice(between);
        // movs r0, 1; bx lr
        halfwords.extend([0x2001, 0x4770]);
        halfwords.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn padding_after_a_loop_back_ends_the_function() {
        let code = loop_then(&[0xbf00, 0xbf00]);
        let starts = starts_after_returns(&hereticus_il::arch::thumb::Thumb2, &code, 0x1000);
        assert!(starts.contains(&0x100c), "{starts:x?}");
    }

    #[test]
    fn where_no_jump_goes_unread_a_loop_back_ends_the_function() {
        let code = loop_then(&[]);
        let starts = starts_after_returns(&hereticus_il::arch::thumb::Thumb2, &code, 0x1000);
        assert!(starts.contains(&0x1008), "{starts:x?}");
    }

    /// An A32 function at 0x1000 that ends with a loop, `b` back to
    /// 0x1008, then `between`, then a second function.
    fn a32_loop_then(between: &[u32]) -> Vec<u8> {
        // push {r4, lr}; mov r0, 0; add r0, r0, 1; b 0x1008
        let mut words = vec![0xe92d_4010, 0xe3a0_0000, 0xe280_0001, 0xeaff_fffd];
        words.extend_from_slice(between);
        // mov r0, 1; bx lr
        words.extend([0xe3a0_0001, 0xe12f_ff1e]);
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn where_a_table_jump_looks_like_others_only_padding_ends_a_loop() {
        let bare = starts_after_returns(&Arm32, &a32_loop_then(&[]), 0x1000);
        assert!(!bare.contains(&0x1010), "{bare:x?}");
        let padded = starts_after_returns(&Arm32, &a32_loop_then(&[0xe320_f000]), 0x1000);
        assert!(padded.contains(&0x1014), "{padded:x?}");
    }

    #[test]
    fn after_an_unread_table_only_padding_ends_a_loop() {
        // push {r4, lr}; tbb [pc, r0] with no bound before it, then a loop.
        let code: Vec<u8> = [0xb510u16, 0xe8df, 0xf000, 0x2000, 0x3001, 0xe7fd, 0x2001, 0x4770]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let starts = starts_after_returns(&hereticus_il::arch::thumb::Thumb2, &code, 0x1000);
        assert!(!starts.contains(&0x100c), "{starts:x?}");
    }

    /// A32 code at 0x1000 that jumps through a table of byte offsets, as
    /// GCC does for ARMv5TE, whose first case makes a frame late, after a
    /// `mov r0, r0` filler.
    #[test]
    fn a_late_frame_on_the_first_case_of_a_table_starts_nothing() {
        let words = [
            0xe59f_2030u32, // ldr r2, [pc, 0x30]: the table, from 0x100c
            0xe08f_2002,    // add r2, pc, r2
            0xe353_0001,    // cmp r3, 1
            0x8a00_0007,    // bhi 0x1030
            0xe7d2_3003,    // ldrb r3, [r2, r3]
            0xe08f_f103,    // add pc, pc, r3, lsl 2
            0xe1a0_0000,    // mov r0, r0
            0xe92d_4010,    // case 0: push {r4, lr}
            0xebff_fff6,    // bl 0x1000
            0xe8bd_8010,    // pop {r4, pc}
            0xe3a0_0001,    // case 1: mov r0, 1
            0xe12f_ff1e,    // bx lr
            0xe3a0_0000,    // default: mov r0, 0
            0xe12f_ff1e,    // bx lr
            0x0000_0030,    // the pool word
            0x0000_0300,    // the table: case 0 at 0, case 1 at 3 words
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let starts = starts_after_returns(&Arm32, &code, 0x1000);
        for case in [0x1018, 0x101c, 0x1028, 0x1030] {
            assert!(!starts.contains(&case), "{case:x} in {starts:x?}");
        }
    }

    /// `bl` to a label inside a function, as ARMv6-M jumps far, calls
    /// nothing: the code there pops a frame it did not push.
    #[test]
    fn a_bl_to_an_epilogue_calls_nothing() {
        let halfwords = |words: &[u16]| -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        };
        // push {r4, lr}; bl 0x100c; bl 0x1010; movs r0, 0;
        // 0x100c: add sp, 8; pop {r4, pc};
        // 0x1010: push {r4, lr}; pop {r4, pc}
        let code = halfwords(&[
            0xb510, 0xf000, 0xf803, 0xf000, 0xf803, 0x2000, 0xb002, 0xbd10, 0xb510, 0xbd10,
        ]);
        let targets = call_targets(
            &hereticus_il::arch::thumb::Thumb2,
            &Region::decode(&hereticus_il::arch::thumb::Thumb2, 0x1000, &code),
        );
        assert_eq!(targets, [0x1010], "the epilogue at 0x100c is no function");
    }

    #[test]
    fn words_follow_the_alignment_of_the_address_not_of_the_region() {
        // The region starts two bytes before a word boundary.
        let bytes = [0xff, 0xff, 0x01, 0x10, 0, 0];
        let regions = [(0x102, &bytes[..])];
        let tagged =
            tagged_functions(&hereticus_il::arch::thumb::Thumb2, &regions, &BTreeSet::new());
        assert_eq!(tagged, [0x1000]);
    }

    #[test]
    fn sign_extension_keeps_small_offsets() {
        assert_eq!(sign_extend_31(0), 0);
        assert_eq!(sign_extend_31(8), 8);
        assert_eq!(sign_extend_31(0x100), 0x100);
    }

    #[test]
    fn sign_extension_handles_negative_offsets() {
        // The top bit of a 31-bit field marks a negative offset.
        assert_eq!(sign_extend_31(0x7fff_ffff), -1);
        assert_eq!(sign_extend_31(0x7fff_fffe), -2);
    }

    /// A raw ARM image to load at 0x1000: `functions` functions of four
    /// words from 0, then `tail` at 0x200, then an index at 0x400 with an
    /// inline entry for each function and a last entry that cannot unwind,
    /// which names 0x200.
    fn image_with_index(functions: usize, tail: &[u32]) -> Vec<u8> {
        const TAIL: usize = 0x200;
        const TABLE: usize = 0x400;
        let body = [0xe92d_4010_u32, 0xe1a0_0000, 0xe1a0_0000, 0xe8bd_8010];

        let mut words = vec![0_u32; 0x600 / 4];
        for function in 0..functions {
            words[function * 4..function * 4 + 4].copy_from_slice(&body);
        }
        words[TAIL / 4..TAIL / 4 + tail.len()].copy_from_slice(tail);
        let prel31 = |from: usize, to: usize| (to as u32).wrapping_sub(from as u32) & 0x7fff_ffff;
        let targets = (0..functions).map(|function| (function * 16, 0x80b0_b0b0));
        for (entry, (target, unwinding)) in
            targets.chain(core::iter::once((TAIL, EXIDX_CANTUNWIND))).enumerate()
        {
            let at = TABLE + entry * EXIDX_ENTRY_LEN;
            words[at / 4] = prel31(at, target);
            words[at / 4 + 1] = unwinding;
        }
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn reads_an_index_in_a_raw_image() {
        let image = image_with_index(20, &[0xe52d_e004]);
        let index = find_exception_index(&image, 0x1000, &Arm32);
        assert_eq!(index.len(), 21);
        assert_eq!(index[0], IndexEntry { address: 0x1000, unwinding: Unwinding::Described });
        assert_eq!(index[20], IndexEntry { address: 0x1200, unwinding: Unwinding::CannotUnwind });
    }

    /// The last entry names the end of `.text`, and zero fill can come
    /// before the section after it: the entry then names what follows.
    #[test]
    fn the_last_entry_steps_over_zero_fill() {
        let image = image_with_index(20, &[0, 0, 0xe52d_e004]);
        let index = find_exception_index(&image, 0x1000, &Arm32);
        assert_eq!(index.last().map(|entry| entry.address), Some(0x1208));

        // Past the fill there must be code, or the entry is no entry.
        let image = image_with_index(20, &[0, 0, 0x0000_0010]);
        let index = find_exception_index(&image, 0x1000, &Arm32);
        assert_eq!(index.len(), 20, "the run ends before it");
    }

    /// A few entries can occur by chance, so too short a run is no index.
    #[test]
    fn a_short_run_is_no_index() {
        let image = image_with_index(10, &[0xe52d_e004]);
        assert!(find_exception_index(&image, 0x1000, &Arm32).is_empty());
    }

    #[test]
    fn an_exact_source_is_told_from_a_guess() {
        assert!(Source::Symbol.is_exact());
        assert!(Source::ExceptionIndex.is_exact());
        assert!(Source::CallTarget.is_exact());
        assert!(!Source::AfterReturn.is_exact());
    }

    /// The strongest source must sort first, so it wins for a shared address.
    #[test]
    fn sources_rank_strongest_first() {
        let mut sources =
            vec![Source::AfterReturn, Source::CallTarget, Source::Symbol, Source::ExceptionIndex];
        sources.sort();
        assert_eq!(
            sources,
            [Source::Symbol, Source::ExceptionIndex, Source::CallTarget, Source::AfterReturn]
        );
    }

    #[test]
    fn finds_nothing_in_bytes_that_are_not_an_object() {
        assert!(recover_functions(b"not an object", &Arm32).is_empty());
    }

    #[test]
    fn finds_nothing_in_an_empty_input() {
        assert!(recover_functions(&[], &Arm32).is_empty());
    }

    #[test]
    fn a_call_to_itself_is_not_a_function_start() {
        // bl .-8, the placeholder a linker has yet to fill in.
        let code = [0xfe, 0xff, 0xff, 0xeb];
        assert!(call_targets(&Arm32, &Region::decode(&Arm32, 0x1000, &code)).is_empty());
    }

    #[test]
    fn a_real_call_target_is_a_function_start() {
        // `bl` to the third word, then `bx lr`, then the function called. An
        // assembler emits a placeholder and a relocation for this, so the
        // encoding is written out directly. A zero offset field means "two
        // words ahead", because the encoding carries the pipeline bias.
        let code = [0x00, 0x00, 0x00, 0xeb, 0x1e, 0xff, 0x2f, 0xe1, 0x00, 0x00, 0x81, 0xe0];
        assert_eq!(
            call_targets(&Arm32, &Region::decode(&Arm32, 0, &code)),
            vec![0x8],
            "the call target starts a function"
        );
    }

    #[test]
    fn a_return_followed_by_code_starts_a_function() {
        // add, bx lr, add
        let code = [0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1, 0x00, 0x00, 0x81, 0xe0];
        assert_eq!(starts_after_returns(&Arm32, &code, 0x1000), vec![0x1008]);
    }

    /// A return in the middle of a function must not start a new one.
    ///
    /// Most functions return from more than one place. Treating an early exit
    /// as the end of a function cut one function into several: a stripped
    /// kernel object recovered ten functions where four exist.
    #[test]
    fn a_return_branched_across_does_not_start_a_function() {
        // b +0x8 (past the return), bx lr, add
        let code = [
            0x00, 0x00, 0x00, 0xea, // b, two words forward
            0x1e, 0xff, 0x2f, 0xe1, // bx lr, inside the function
            0x00, 0x00, 0x81, 0xe0, // add, still the same function
        ];
        assert!(
            starts_after_returns(&Arm32, &code, 0).is_empty(),
            "a branch lands past this return, so control flows through it"
        );
    }

    /// A return nothing branches across still ends a function.
    #[test]
    fn a_return_nothing_crosses_starts_a_function() {
        // bx lr, add
        let code = [0x1e, 0xff, 0x2f, 0xe1, 0x00, 0x00, 0x81, 0xe0];
        assert_eq!(starts_after_returns(&Arm32, &code, 0), vec![0x4]);
    }

    /// Zero fill after a return is the linker's, and the code after it
    /// starts a function, as the PLT header does after `.text`.
    #[test]
    fn a_return_then_zero_fill_starts_a_function_after_the_fill() {
        let code = [
            0x1e, 0xff, 0x2f, 0xe1, // bx lr
            0x00, 0x00, 0x00, 0x00, // zero fill, `andeq r0, r0, r0`
            0x04, 0xe0, 0x2d, 0xe5, // str lr, [sp, -0x4]!: the PLT header
        ];
        assert_eq!(starts_after_returns(&Arm32, &code, 0x1000), vec![0x1008]);
    }

    /// A prologue starts a function whatever comes before it.
    ///
    /// An error path can jump backwards over the end of its own function, and
    /// that jump would otherwise hide the function that follows. Measured on a
    /// kernel object: `objpool_free` sits after `b` rather than after a
    /// return, and was lost until the prologue was trusted on its own.
    #[test]
    fn a_prologue_starts_a_function_after_a_jump() {
        // b backwards, then push {r4, lr}
        let code = [
            0xfe, 0xff, 0xff, 0xea, // b, to itself
            0x10, 0x40, 0x2d, 0xe9, // push {r4, lr}
        ];
        assert_eq!(
            starts_after_returns(&Arm32, &code, 0),
            vec![0x4],
            "a saved link register opens a function"
        );
    }

    #[test]
    fn a_return_at_the_end_starts_nothing() {
        let code = [0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
        assert!(starts_after_returns(&Arm32, &code, 0).is_empty());
    }

    /// A prologue behind a literal pool still starts a function.
    ///
    /// A compiler can place pool constants between two functions. Those words
    /// decode as `Unknown`, and a scan that stopped at the first one lost the
    /// prologue behind them. Measured on a kernel image: functions reached
    /// only through a pointer (`0x801df80c`, `0x80267d5c`) sit after their
    /// predecessor's pool, and were the two boundaries Ghidra found that this
    /// missed.
    /// A prologue behind a literal pool still starts a function.
    ///
    /// The three pool words here are real addresses taken from a firmware
    /// image at `0x801df800`; they decode as valid-looking instructions, not
    /// as `Unknown`, which is exactly why judging only the word after the
    /// terminator missed the prologue two words on. The `push` is the wide
    /// register save that opens `0x801df80c`, a function reached only through
    /// a pointer.
    #[test]
    fn a_prologue_behind_a_literal_pool_starts_a_function() {
        let code = [
            0xed, 0xff, 0xff, 0xea, // b, ends the function
            0x0a, 0x00, 0x70, 0x00, // 0x00700000, a pool constant, not code
            0xe8, 0xc0, 0xa1, 0x80, // 0x80a1c0e8, a stored address
            0x80, 0x04, 0xaa, 0x80, // 0x80aa0480, a stored address
            0xf0, 0x4f, 0x2d, 0xe9, // push {r4-r8, sb, sl, fp, lr}, the prologue
        ];
        assert_eq!(
            starts_after_returns(&Arm32, &code, 0),
            vec![0x10],
            "a prologue past the pool is a function start"
        );
    }

    /// A prologue far past a terminator is not read as a function start.
    ///
    /// Beyond a short pool the scan is in a function body, where a wide
    /// register save is not a prologue. The bound keeps the pool scan from
    /// walking that far.
    #[test]
    fn a_prologue_far_past_a_terminator_is_not_claimed() {
        let mut code = vec![0xed, 0xff, 0xff, 0xea]; // b, ends the function
        // Ten pool-looking words: longer than a real inter-function pool.
        for _ in 0..10 {
            code.extend_from_slice(&[0x80, 0x04, 0xaa, 0x80]);
        }
        code.extend_from_slice(&[0xf0, 0x4f, 0x2d, 0xe9]); // push, too far to be a start
        assert!(
            starts_after_returns(&Arm32, &code, 0).is_empty(),
            "a prologue past a long run is not claimed"
        );
    }

    /// A second terminator ends the pool scan before a later prologue.
    ///
    /// Past a return the scan is in real control flow, so a prologue there is
    /// inside a function, not after a pool.
    #[test]
    fn a_prologue_after_a_second_terminator_is_not_claimed() {
        let code = [
            0xed, 0xff, 0xff, 0xea, // b, ends the function
            0x80, 0x04, 0xaa, 0x80, // one pool word
            0x1e, 0xff, 0x2f, 0xe1, // bx lr, a second terminator: pool is over
            0xf0, 0x4f, 0x2d, 0xe9, // push, but now inside real code
        ];
        // The second terminator itself starts a scan, and the push right after
        // it is a genuine start; what must not happen is the FIRST scan
        // reaching across the bx lr to claim the push.
        assert_eq!(
            starts_after_returns(&Arm32, &code, 0),
            vec![0xc],
            "only the prologue right after the second terminator is a start"
        );
    }

    /// Code after a return that branches back into the middle of the
    /// function before is more of it, reached through a table not read.
    #[test]
    fn a_block_that_branches_back_continues_its_function() {
        let words = |last: u32| {
            arm_code(&[
                0xe92d_4010, // 0x00 push {r4, lr}
                0xe1a0_4000, // 0x04 mov r4, r0
                0xe354_0000, // 0x08 cmp r4, #0
                0xe8bd_8010, // 0x0c pop {r4, pc}
                0xe59d_0000, // 0x10 ldr r0, [sp]
                last,        // 0x14
            ])
        };
        let back = words(0xeaff_fffa); // b 0x04
        assert!(!starts_after_returns(&Arm32, &back, 0).contains(&0x10));
        let leaves = words(0xe12f_ff1e); // bx lr
        assert!(starts_after_returns(&Arm32, &leaves, 0).contains(&0x10));
    }

    /// A call that does not return can be followed by the pool word it
    /// loads, and then by the next function, which a tail jump from
    /// another function may reach, as `b luaV_div` does in Lua for ARM.
    #[test]
    fn a_prologue_past_the_pool_after_a_call_starts_a_function() {
        let code = arm_code(&[
            0xe92d_4010, // 0x00 push {r4, lr}
            0xe59f_0000, // 0x04 ldr r0, [pc]: the word at 0x0c
            0xeb00_003c, // 0x08 bl 0x100, which does not return
            0xfe8a_5c6a, // 0x0c pool word, `cdp2`
            0xe92d_4010, // 0x10 push {r4, lr}
            0xe8bd_8010, // 0x14 pop {r4, pc}
            0xe92d_4010, // 0x18 push {r4, lr}
            0xeaff_fffb, // 0x1c b 0x10, a tail call
        ]);
        assert!(starts_after_returns(&Arm32, &code, 0).contains(&0x10));
    }

    /// A leaf with no frame past the pool after such a call starts a
    /// function too, where a jump from another function reaches it.
    #[test]
    fn a_leaf_past_the_pool_that_a_tail_call_reaches_starts_a_function() {
        let code = arm_code(&[
            0xe92d_4010, // 0x00 push {r4, lr}
            0xe59f_0000, // 0x04 ldr r0, [pc]: the word at 0x0c
            0xeb00_003c, // 0x08 bl 0x100, which does not return
            0xfe8a_5c6a, // 0x0c pool word, `cdp2`
            0xe590_0000, // 0x10 ldr r0, [r0]
            0xe12f_ff1e, // 0x14 bx lr
            0xe92d_4010, // 0x18 push {r4, lr}
            0xeaff_fffb, // 0x1c b 0x10, a tail call
        ]);
        assert!(starts_after_returns(&Arm32, &code, 0).contains(&0x10));
    }

    /// What a conditional branch of the function reaches past the pool is
    /// more of the function, even where it makes a frame.
    #[test]
    fn a_frame_past_the_pool_that_a_conditional_branch_reaches_stays_inside() {
        let code = arm_code(&[
            0xe92d_4010, // 0x00 push {r4, lr}
            0xe350_0000, // 0x04 cmp r0, 0
            0x1a00_0002, // 0x08 bne 0x18
            0xe59f_0000, // 0x0c ldr r0, [pc]: the word at 0x14
            0xeb00_003a, // 0x10 bl 0x100, which does not return
            0xfe8a_5c6a, // 0x14 pool word, `cdp2`
            0xe92d_4010, // 0x18 push {r4, lr}
            0xe8bd_8010, // 0x1c pop {r4, pc}
        ]);
        assert!(!starts_after_returns(&Arm32, &code, 0).contains(&0x18));
    }

    /// Padding between functions must not be mistaken for their start.
    #[test]
    fn padding_after_a_return_is_stepped_over() {
        // bx lr, nop, add
        let code = [0x1e, 0xff, 0x2f, 0xe1, 0x00, 0xf0, 0x20, 0xe3, 0x00, 0x00, 0x81, 0xe0];
        assert_eq!(starts_after_returns(&Arm32, &code, 0), vec![0x8], "the nop is padding");
    }

    /// A function that nothing calls, whose address the code takes, starts
    /// where that address points, when the regions hold only code.
    #[test]
    fn a_function_whose_address_is_taken_starts_there() {
        let code = arm_code(&[
            0xe59f_0004, // 0x00 ldr r0, [pc, 0x4]: the word at 0x0c
            0xe08f_0000, // 0x04 add r0, pc, r0: 0x0c + 0x4
            0xeaff_fffc, // 0x08 b 0x0
            0x0000_0004, // 0x0c the distance to 0x10
            0xe3a0_0001, // 0x10 mov r0, 1
            0xe12f_ff1e, // 0x14 bx lr
        ]);
        let regions = [(0, code.as_slice())];
        let starts = |contents: Regions| -> Vec<u64> {
            recover_in_memory(
                &regions,
                &[],
                &Linked::default(),
                contents,
                &Arm32,
                &Memory::new(&regions),
            )
            .iter()
            .map(|found| found.address)
            .collect()
        };
        assert_eq!(starts(Regions::CodeOnly), [0x0, 0x10]);
        assert_eq!(starts(Regions::CodeAndData), [0x0], "an address in a raw image can be data");
    }

    /// A relocated pointer to a T32 function has bit 0 set, and still
    /// names where the function starts.
    #[test]
    fn a_relocated_pointer_to_a_t32_function_starts_it() {
        use hereticus_il::arch::thumb::Thumb2;

        let code: Vec<u8> = [
            0xb510_u16, // 0x00 push {r4, lr}
            0x4801,     // 0x02 ldr r0, [pc, 4]: the word at 0x08
            0xbd10,     // 0x04 pop {r4, pc}
            0xbf00,     // 0x06 nop
            0x0000,     // 0x08 the pool word
            0x0000, 0x6800, // 0x0c ldr r0, [r0]
            0x4770, // 0x0e bx lr
        ]
        .iter()
        .flat_map(|halfword| halfword.to_le_bytes())
        .collect();
        let regions = [(0x1000, code.as_slice())];
        // The code after the return starts a function anyway, but only as a
        // guess: the pointer makes it a fact.
        let starts = |pointers: Vec<u64>| -> Vec<(u64, Source)> {
            let linked = Linked { pointers: vec![pointers], ..Linked::default() };
            recover_in_memory(
                &regions,
                &[],
                &linked,
                Regions::CodeOnly,
                &Thumb2,
                &Memory::new(&regions),
            )
            .iter()
            .map(|found| (found.address, found.source))
            .collect()
        };
        assert_eq!(
            starts(vec![0x100d]),
            [(0x1000, Source::AfterReturn), (0x100c, Source::CallTarget)]
        );
        assert_eq!(starts(vec![]), [(0x1000, Source::AfterReturn), (0x100c, Source::AfterReturn)]);
    }

    /// An x86 jump to the next instruction is a tail call the linker
    /// resolved to the function it put next, in its long and short forms.
    #[rstest::rstest]
    #[case::long(&[0xe9, 0x00, 0x00, 0x00, 0x00])]
    #[case::short(&[0xeb, 0x00])]
    fn an_x86_jump_to_the_next_instruction_starts_a_function(#[case] jump: &[u8]) {
        use hereticus_il::arch::x86::X86;

        let mut code = vec![0x45, 0x31, 0xc9]; // xor r9d, r9d
        code.extend(jump);
        let next = 0x1000 + code.len() as u64;
        code.extend([0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]); // mov eax, 1; ret
        let found: Vec<u64> = recover_from_regions(&[(0x1000, code.as_slice())], &[], &X86::BITS64)
            .iter()
            .map(|found| found.address)
            .collect();
        assert_eq!(found, [0x1000, next]);
    }

    /// A zero word at the end of a function is padding, but for a pool word
    /// that its code loads.
    #[rstest::rstest]
    #[case::loaded(0xe59f_0000, 12)] // ldr r0, [pc]: the word at 0x08
    #[case::padding(0xe3a0_0000, 8)] // mov r0, 0
    fn a_zero_word_the_code_loads_stays(#[case] first: u32, #[case] length: usize) {
        let code = arm_code(&[
            first,       // 0x00
            0xe12f_ff1e, // 0x04 bx lr
            0x0000_0000, // 0x08
        ]);
        let found = recover_from_regions(&[(0, code.as_slice())], &[], &Arm32);
        assert_eq!(found.iter().map(|found| found.code.len()).collect::<Vec<_>>(), [length]);
    }

    /// A table of A32 labels, each after the jump that ends the case
    /// before, names no function. A table of functions, each after a
    /// return, names each.
    #[rstest::rstest]
    #[case::labels(0xe1a0_f003, &[])] // mov pc, r3
    #[case::functions(0xe12f_ff1e, &[0x0c, 0x14, 0x1c, 0x24])] // bx lr
    fn a_table_of_labels_names_no_function(#[case] end: u32, #[case] named: &[u64]) {
        let code = arm_code(&[
            0xe92d_4010, // 0x00 push {r4, lr}
            0xe792_3103, // 0x04 ldr r3, [r2, r3, lsl 2]
            end,         // 0x08
            0xe280_0001, // 0x0c add r0, r0, 1
            end,         // 0x10
            0xe280_0002, // 0x14 add r0, r0, 2
            end,         // 0x18
            0xe280_0003, // 0x1c add r0, r0, 3
            end,         // 0x20
            0xe280_0004, // 0x24 add r0, r0, 4
            0xe8bd_8010, // 0x28 pop {r4, pc}
        ]);
        let regions = [(0, code.as_slice())];
        let linked = Linked { pointers: vec![vec![0x0c, 0x14, 0x1c, 0x24]], ..Linked::default() };
        let found: Vec<u64> = recover_in_memory(
            &regions,
            &[],
            &linked,
            Regions::CodeOnly,
            &Arm32,
            &Memory::new(&regions),
        )
        .iter()
        .filter(|found| found.source == Source::CallTarget)
        .map(|found| found.address)
        .collect();
        assert_eq!(found, named);
    }

    /// MIPS PIC calls a function of its own through a slot of the global
    /// offset table, and the slot holds its address.
    #[test]
    fn a_function_called_through_a_slot_starts_there() {
        use hereticus_il::arch::mips::Mips32;

        let code: Vec<u8> = [
            0x3c02_0000_u32, // 0x00 lui v0, 0
            0x2442_7ff0,     // 0x04 addiu v0, v0, 0x7ff0: gp is 0x7ff0
            0x0059_8821,     // 0x08 addu s1, v0, t9
            0x8e39_9000,     // 0x0c lw t9, -0x7000(s1): the slot at 0xff0
            0x0320_f809,     // 0x10 jalr t9
            0x0000_0000,     // 0x14 nop
            0x1000_fff9,     // 0x18 b 0x0
            0x0000_0000,     // 0x1c nop
            0x03e0_0008,     // 0x20 jr ra: the callee
            0x0000_0000,     // 0x24 nop
        ]
        .iter()
        .flat_map(|word| word.to_be_bytes())
        .collect();
        let slot = 0x20_u32.to_be_bytes();
        let regions = [(0, code.as_slice())];
        let starts = |memory: &[(u64, &[u8])]| -> Vec<u64> {
            let memory = Memory::new(memory);
            recover_in_memory(
                &regions,
                &[],
                &Linked::default(),
                Regions::CodeAndData,
                &Mips32::BIG,
                &memory,
            )
            .iter()
            .map(|found| found.address)
            .collect()
        };
        assert_eq!(starts(&[(0, code.as_slice()), (0xff0, slot.as_slice())]), [0x0, 0x20]);
        assert_eq!(starts(&[(0, code.as_slice())]), [0x0], "the slot is not loaded");
    }

    /// Code after a return that a conditional branch from later in the
    /// function reaches is more of it, as a loop at its end reaches back.
    #[test]
    fn a_branch_back_past_a_return_keeps_the_function_whole() {
        let code = arm_code(&[
            0xe92d_4010, // 0x00 push {r4, lr}
            0xe8bd_8010, // 0x04 pop {r4, pc}
            0xe3a0_0001, // 0x08 mov r0, 1
            0xe251_1001, // 0x0c subs r1, r1, 1
            0x1aff_fffc, // 0x10 bne 0x08
            0xe8bd_8010, // 0x14 pop {r4, pc}
        ]);
        assert!(!starts_after_returns(&Arm32, &code, 0).contains(&0x8));
    }

    /// A call that does not return, as to `exit`, ends its function where a
    /// prologue follows it.
    #[test]
    fn a_prologue_after_a_call_starts_a_function() {
        let code = arm_code(&[
            0xe92d_4010, // 0x00 push {r4, lr}
            0xebff_fffe, // 0x04 bl 0x4: exit, which does not return
            0xe92d_4010, // 0x08 push {r4, lr}
            0xe8bd_8010, // 0x0c pop {r4, pc}
        ]);
        assert!(starts_after_returns(&Arm32, &code, 0).contains(&0x8));
    }

    /// `bx` through a register other than `lr` is a tail call, so a leaf
    /// with no prologue after it starts a function.
    #[test]
    fn an_indirect_tail_call_ends_a_function() {
        let code = arm_code(&[
            0xe1a0_3001, // 0x0 mov r3, r1
            0xe12f_ff13, // 0x4 bx r3
            0xe3a0_0001, // 0x8 mov r0, 1
            0xe12f_ff1e, // 0xc bx lr
        ]);
        assert_eq!(starts_after_returns(&Arm32, &code, 0), vec![0x8]);
    }

    /// A jump to the start of another function is a tail call. A jump into
    /// the middle of one is not, as an exception fixup of the kernel jumps
    /// back into the function it serves.
    #[test]
    fn only_a_jump_to_a_start_is_a_tail_call() {
        let with_jump = |jump: u32| {
            arm_code(&[
                0xe92d_4010, // 0x00 push {r4, lr}
                0xe3a0_0001, // 0x04 mov r0, 1
                0xe8bd_8010, // 0x08 pop {r4, pc}
                0xe3a0_0003, // 0x0c mov r0, 3
                0xe12f_ff1e, // 0x10 bx lr
                0xe92d_4010, // 0x14 push {r4, lr}
                0xe8bd_8010, // 0x18 pop {r4, pc}
                0xe3e0_000d, // 0x1c mvn r0, 13
                jump,        // 0x20 b
                0xe3a0_0002, // 0x24 mov r0, 2
                0xe12f_ff1e, // 0x28 bx lr
            ])
        };
        let to_a_start = starts_after_returns(&Arm32, &with_jump(0xeaff_fff6), 0); // b 0x0
        assert!(to_a_start.contains(&0x24), "{to_a_start:x?}");
        let to_a_middle = starts_after_returns(&Arm32, &with_jump(0xeaff_fff7), 0); // b 0x4
        assert!(!to_a_middle.contains(&0x24), "{to_a_middle:x?}");
    }

    /// Little-endian MIPS code from words.
    fn mips_code(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    /// `-Os` can make the frame only on the path that calls. The code
    /// between the jump and that frame is a branch target, so it is not a
    /// pool, and the frame does not start a function.
    #[test]
    fn a_frame_made_late_does_not_split_its_function() {
        use hereticus_il::arch::mips::Mips32;

        let with_first = |first: u32| {
            mips_code(&[
                first,           // 0x00
                0x0000_0000,     // 0x04 nop
                0x2402_0001,     // 0x08 addiu v0, zero, 1
                0x1000_0002,     // 0x0c b 0x18
                0x0000_0000,     // 0x10 nop
                0x2402_0002,     // 0x14 addiu v0, zero, 2
                0x27bd_fff8,     // 0x18 addiu sp, sp, -8
                0x03e0_0008,     // 0x1c jr ra
                0x27bd_0008_u32, // 0x20 addiu sp, sp, 8
            ])
        };

        // beq a0, zero, 0x14: the word after the jump is code.
        let branched = with_first(0x1080_0004);
        assert!(starts_after_returns(&Mips32::LITTLE, &branched, 0).is_empty());

        // addiu v0, zero, 3: nothing shows the word is code of this
        // function, and MIPS keeps no pool, so the function after the jump
        // starts right after its slot, with the word before its frame.
        let not_branched = with_first(0x2402_0003);
        assert_eq!(starts_after_returns(&Mips32::LITTLE, &not_branched, 0), vec![0x14]);
    }

    /// Little-endian ARM code from words.
    fn arm_code(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    /// An early `bx lr` before the frame is made, as `gzgetc` in zlib has.
    /// The frame after it is on the path of a conditional branch, so it is
    /// more of the same function.
    #[test]
    fn a_frame_after_an_early_return_does_not_start_a_function() {
        let with_second = |second: u32| {
            arm_code(&[
                0xe350_0000, // 0x00 cmp r0, 0
                second,      // 0x04
                0xe3a0_0001, // 0x08 mov r0, 1
                0xe12f_ff1e, // 0x0c bx lr
                0xe92d_4010, // 0x10 push {r4, lr}
                0xe8bd_8010, // 0x14 pop {r4, pc}
            ])
        };

        // beq 0x10
        assert!(starts_after_returns(&Arm32, &with_second(0x0a00_0001), 0).is_empty());
        // mov r1, r1: nothing of this function reaches the frame.
        assert_eq!(starts_after_returns(&Arm32, &with_second(0xe1a0_1001), 0), vec![0x10]);
    }

    /// Text decodes as a conditional call often enough to split functions.
    /// "ON\0k", from `_VERSION` in Lua, reads as `blvs` to 0x13948.
    #[test]
    fn a_call_that_is_text_names_no_function() {
        const MOV_R0_R0: u32 = 0xe1a0_0000;
        let with_word_at_4 = |word: u32| {
            let mut words = vec![MOV_R0_R0; 0x13950 / 4];
            words[1] = word;
            arm_code(&words)
        };

        let text = with_word_at_4(u32::from_le_bytes(*b"ON\0k"));
        assert_eq!(
            Arm32.decode(&text, 4, 0).map(|insn| insn.kind),
            Ok(InsnKind::Call { target: Some(0x13948) })
        );
        assert!(call_targets(&Arm32, &Region::decode(&Arm32, 0, &text)).is_empty());

        // bl 0x13948: the same target, from a word that is not text.
        let call = with_word_at_4(0xeb00_4e4f);
        assert_eq!(call_targets(&Arm32, &Region::decode(&Arm32, 0, &call)), vec![0x13948]);
    }

    /// A branch crosses a return inside its own function only. One from
    /// before a prologue is of another function, or is data, and it must
    /// not hide the leaf function after the return.
    #[test]
    fn a_branch_from_before_a_prologue_does_not_cross_a_return() {
        use hereticus_il::arch::mips::Mips32;

        // The branch is in the function before, which returns at 0x08.
        let with_frame = |frame: u32| {
            mips_code(&[
                0x1080_000a,     // 0x00 beq a0, zero, 0x2c
                0x0000_0000,     // 0x04 nop
                0x03e0_0008,     // 0x08 jr ra
                0x0000_0000,     // 0x0c nop
                frame,           // 0x10
                0x27bd_0008,     // 0x14 addiu sp, sp, 8
                0x03e0_0008,     // 0x18 jr ra
                0x0000_0000,     // 0x1c nop
                0x2402_0001,     // 0x20 addiu v0, zero, 1
                0x03e0_0008,     // 0x24 jr ra
                0x0000_0000,     // 0x28 nop
                0x0000_0000_u32, // 0x2c nop
            ])
        };

        // addiu sp, sp, -8: a function starts between the branch and the
        // return, so the branch does not cross it.
        assert_eq!(
            starts_after_returns(&Mips32::LITTLE, &with_frame(0x27bd_fff8), 0),
            vec![0x10, 0x20]
        );
        // addiu v0, zero, 2: the branch can be of this function.
        assert!(starts_after_returns(&Mips32::LITTLE, &with_frame(0x2402_0002), 0).is_empty());
    }

    /// The cases of a `switch` table each end with a return, and only the
    /// table reaches them. They are more of the function with the table.
    #[test]
    fn the_cases_of_a_jump_table_do_not_start_functions() {
        let code = arm_code(&[
            0xe92d_4010, // 0x00 push {r4, lr}
            0xe28f_1004, // 0x04 adr r1, pc, 0x4: the table is at 0x10
            0xe791_0100, // 0x08 ldr r0, [r1, r0, lsl 2]
            0xe081_f000, // 0x0c add pc, r1, r0
            0x0000_0008, // 0x10 case 0 at 0x18
            0x0000_0010, // 0x14 case 1 at 0x20
            0xe3a0_0001, // 0x18 mov r0, 1
            0xe8bd_8010, // 0x1c pop {r4, pc}
            0xe3a0_0002, // 0x20 mov r0, 2
            0xe8bd_8010, // 0x24 pop {r4, pc}
        ]);
        assert!(starts_after_returns(&Arm32, &code, 0).is_empty());
    }

    /// A frame made after a branch skips it is inside the function, as in
    /// `luaC_linkupval`, so the branch still crosses the return after it.
    #[test]
    fn a_frame_made_on_one_path_is_no_sure_start() {
        use hereticus_il::arch::mips::Mips32;

        let code = mips_code(&[
            0x1080_0006,     // 0x00 beq a0, zero, 0x1c
            0x0000_0000,     // 0x04 nop
            0x27bd_fff8,     // 0x08 addiu sp, sp, -8: runs on from the slot
            0x27bd_0008,     // 0x0c addiu sp, sp, 8
            0x03e0_0008,     // 0x10 jr ra
            0x0000_0000,     // 0x14 nop
            0x2402_0001,     // 0x18 addiu v0, zero, 1
            0x03e0_0008,     // 0x1c jr ra
            0x0000_0000_u32, // 0x20 nop
        ]);
        assert!(starts_after_returns(&Mips32::LITTLE, &code, 0).is_empty());
    }

    /// A called word is a function start, so the search for a prologue past
    /// a pool stops there rather than cutting that function short.
    #[test]
    fn the_search_for_a_prologue_stops_at_a_called_word() {
        let with_call = |call: u32| {
            arm_code(&[
                call,        // 0x00
                0xe12f_ff1e, // 0x04 bx lr
                0x0000_0010, // 0x08 a pool word
                0x11a0_1000, // 0x0c movne r1, r0
                0xe92d_4010, // 0x10 push {r4, lr}
                0xe8bd_8010, // 0x14 pop {r4, pc}
            ])
        };

        // bl 0x0c
        assert_eq!(starts_after_returns(&Arm32, &with_call(0xeb00_0001), 0), vec![0x0c]);
        // mov r0, r0: nothing calls 0x0c, and a conditional word cannot open
        // a function, so the prologue starts it.
        assert_eq!(starts_after_returns(&Arm32, &with_call(0xe1a0_0000), 0), vec![0x10]);
    }

    /// The `_gp_disp` preamble opens a function even after a call that does
    /// not return, and even with no frame.
    #[test]
    fn a_mips_entry_sequence_starts_a_function() {
        use hereticus_il::arch::mips::Mips32;

        let code = mips_code(&[
            0x0320_f809,     // 0x00 jalr t9, as to _Unwind_Resume
            0x0000_0000,     // 0x04 nop
            0x3c1c_0002,     // 0x08 lui gp, 0x2
            0x279c_8000,     // 0x0c addiu gp, gp, -0x8000
            0x0399_e021,     // 0x10 addu gp, gp, t9
            0x03e0_0008,     // 0x14 jr ra
            0x0000_0000_u32, // 0x18 nop
        ]);
        let (insns, _) = decode_all(&Mips32::LITTLE, &code, 0);
        assert_eq!(function_entries(&Mips32::LITTLE, &insns), vec![0x08]);
        let starts: Vec<u64> = recover_from_regions(&[(0, &code)], &[], &Mips32::LITTLE)
            .iter()
            .map(|found| found.address)
            .collect();
        assert_eq!(starts, [0x00, 0x08]);
    }

    /// GCC schedules work before the frame. The unconditional word before
    /// the `push` opens the function; the pool word before it does not.
    #[test]
    fn an_unconditional_word_before_a_frame_opens_the_function() {
        let code = arm_code(&[
            0xe12f_ff1e, // 0x00 bx lr
            0x0000_0010, // 0x04 a pool word
            0xe28d_c601, // 0x08 add ip, sp, 0x100000
            0xe92d_4010, // 0x0c push {r4, lr}
            0xe8bd_8010, // 0x10 pop {r4, pc}
        ]);
        assert_eq!(starts_after_returns(&Arm32, &code, 0), vec![0x08]);
    }

    /// A branch from before the last return is not of this function. In a
    /// raw image such a "branch" is often data, and it must not hide a
    /// function start.
    #[test]
    fn a_branch_from_an_earlier_function_does_not_block_a_start() {
        use hereticus_il::arch::mips::Mips32;

        let code = mips_code(&[
            0x1080_0006,     // 0x00 beq a0, zero, 0x1c
            0x0000_0000,     // 0x04 nop
            0x03e0_0008,     // 0x08 jr ra
            0x0000_0000,     // 0x0c nop
            0x2402_0001,     // 0x10 addiu v0, zero, 1
            0x03e0_0008,     // 0x14 jr ra
            0x0000_0000,     // 0x18 nop
            0x2402_0002,     // 0x1c addiu v0, zero, 2
            0x27bd_fff8_u32, // 0x20 addiu sp, sp, -8
        ]);
        assert_eq!(starts_after_returns(&Mips32::LITTLE, &code, 0), vec![0x1c]);
    }

    /// A delay slot belongs to the instruction before it, not to the function
    /// after it.
    ///
    /// MIPS unwinds the frame in the slot after `jr ra`, so reading that
    /// unwind as a function start invents a one-instruction function at the
    /// end of every real one. Measured on a stripped MIPS kernel, this cut
    /// nineteen recovered functions out of twenty-six, and the seven it
    /// removed were all the same stray `addiu sp, sp, N`.
    #[test]
    fn a_delay_slot_does_not_start_a_function() {
        use hereticus_il::arch::mips::Mips32;

        // jr ra, then the frame unwind in its delay slot, then a real
        // function that opens by saving the return address.
        let mut code = Vec::new();
        for word in [
            0x03e0_0008u32, // jr ra
            0x27bd_0028,    // addiu sp, sp, 0x28, in the delay slot
            0x27bd_ffd0,    // addiu sp, sp, -0x30, the next function's prologue
            0xafbf_002c,    // sw ra, 0x2c(sp)
        ] {
            code.extend_from_slice(&word.to_le_bytes());
        }

        // The delay slot holds `addiu sp, sp, 0x28`, which releases the frame
        // rather than making one, so it is not a prologue either. What matters
        // is that 0x4 is not offered at all.
        let starts = starts_after_returns(&Mips32::LITTLE, &code, 0);
        assert!(!starts.contains(&0x4), "the delay slot is part of the return, got {starts:?}");
        assert_eq!(starts, vec![0x8], "the function past the slot is the start");
    }

    /// A PIC function starts at its `_gp_disp` pair, not at its frame
    /// allocation.
    ///
    /// Measured on a stripped PIC object of eight functions, without this five
    /// starts landed 8 bytes late, because the two preamble words open the
    /// function and the prologue follows them.
    #[test]
    fn a_pic_function_starts_at_its_global_pointer_setup() {
        use hereticus_il::arch::mips::Mips32;

        let mut code = Vec::new();
        for word in [
            0x03e0_0008u32, // jr ra
            0x27bd_0028,    // addiu sp, sp, 0x28, in the delay slot
            0x3c02_0000,    // lui v0, 0x0, where the next function opens
            0x2442_0000,    // addiu v0, v0, 0x0
            0x27bd_ffd8,    // addiu sp, sp, -0x28, the prologue
            0xafbf_0024,    // sw ra, 0x24(sp)
        ] {
            code.extend_from_slice(&word.to_le_bytes());
        }

        assert_eq!(
            starts_after_returns(&Mips32::LITTLE, &code, 0),
            vec![0x8],
            "the function opens at the lui, two words before its prologue"
        );
    }

    /// The preamble rule must not reach back over words that are not one.
    ///
    /// Two ordinary instructions before a prologue belong to the function
    /// before it, so the start stays at the prologue itself.
    #[test]
    fn a_prologue_without_a_preamble_starts_where_it_sits() {
        use hereticus_il::arch::mips::Mips32;

        let mut code = Vec::new();
        for word in [
            0x03e0_0008u32, // jr ra
            0x27bd_0028,    // addiu sp, sp, 0x28, in the delay slot
            0x0085_1021,    // addu v0, a0, a1, not a preamble
            0x0085_1021,    // addu v0, a0, a1, nor this
            0x27bd_ffd8,    // addiu sp, sp, -0x28, the prologue
        ] {
            code.extend_from_slice(&word.to_le_bytes());
        }

        // The two `addu` words are a function of their own, found at 0x8 by the
        // return before them. What matters is that the prologue at 0x10 does
        // not drag the start back over them.
        let starts = starts_after_returns(&Mips32::LITTLE, &code, 0);
        assert!(!starts.contains(&0xc), "a plain instruction is not a preamble, got {starts:?}");
    }

    /// Without a prologue to point at, the start is the instruction after the
    /// delay slot rather than the slot itself.
    #[test]
    fn a_start_after_a_delay_slot_skips_the_slot() {
        use hereticus_il::arch::mips::Mips32;

        let mut code = Vec::new();
        for word in [
            0x03e0_0008u32, // jr ra
            0x27bd_0028,    // addiu sp, sp, 0x28, in the delay slot
            0x0085_1021,    // addu v0, a0, a1, the next function
        ] {
            code.extend_from_slice(&word.to_le_bytes());
        }

        assert_eq!(
            starts_after_returns(&Mips32::LITTLE, &code, 0),
            vec![0x8],
            "the start is past the slot, not at it"
        );
    }

    fn entries(addresses: &[u64]) -> Vec<IndexEntry> {
        addresses
            .iter()
            .map(|&address| IndexEntry { address, unwinding: Unwinding::Described })
            .collect()
    }

    /// A short run whose targets fall between those of the index is a
    /// table that reads as one; a run of its own range is another index.
    #[test]
    fn a_run_inside_the_range_of_an_index_is_dropped() {
        let index = entries(&[0x100, 0x140, 0x180, 0x1c0]);
        let between = entries(&[0x122, 0x162]);
        let elsewhere = entries(&[0x400, 0x440]);
        let found = keep_whole_indexes(vec![between, index.clone(), elsewhere.clone()]);
        let expected: Vec<IndexEntry> = index.into_iter().chain(elsewhere).collect();
        assert_eq!(found, expected);
        // An entry the index names too is no conflict.
        let repeated = entries(&[0x140, 0x180]);
        assert_eq!(keep_whole_indexes(vec![entries(&[0x100, 0x140, 0x180]), repeated]).len(), 5);
    }
}
