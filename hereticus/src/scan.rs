//! Find functions in a binary that has no symbol table.
//!
//! A shipped firmware image is usually stripped, so the symbol table that
//! [`crate::obj`] reads is not there. This module recovers the function
//! boundaries from the code and from what the linker left behind.
//!
//! Three sources, strongest first:
//!
//! 1. **The unwind index.** Where the ABI has one — ARM keeps it in
//!    `.ARM.exidx` — it holds one entry per function, each pointing at where
//!    that function starts. It survives stripping, and when it is there it is
//!    exact. Not every architecture defines one, and a compiler can leave it
//!    out.
//! 2. **Call targets.** Anything a call instruction jumps to is the start of a
//!    function. This finds what is called but misses what is not.
//! 3. **What follows a return, and what looks like a prologue.** Code after a
//!    function ends usually starts a new one, and the architecture says which
//!    instruction opens one. This is the weakest source, so it only fills gaps
//!    the other two left.
//!
//! Which section holds the unwind index, which instruction is a prologue and
//! which word is padding are all architecture specific, so this module asks
//! [`Arch`] rather than deciding for itself.
//!
//! Recovery is a guess wherever the first source is missing. [`Recovered`]
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

use object::{Object, ObjectSection, SectionKind};

use crate::arch::{Arch, DataAmongCode, Insn, InsnKind, Memory, decode_all};
use crate::obj::Function;

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
    /// [`Arch::is_function_entry`].
    Entry,
    /// It follows the end of another function. A guess.
    AfterReturn,
}

impl Source {
    /// Report whether this source states a fact rather than a guess.
    pub fn is_exact(self) -> bool {
        self != Self::AfterReturn
    }
}

/// A function found without help from the symbol table.
#[derive(Clone, Debug)]
pub struct Recovered {
    pub function: Function,
    pub source: Source,
}

/// Find the functions in a binary with no usable symbol table.
///
/// Returns them in address order. The name of each is empty, because there is
/// nothing to read a name from.
pub fn recover_functions(data: &[u8], arch: &dyn Arch) -> Vec<Recovered> {
    let Ok(file) = object::File::parse(data) else { return Vec::new() };

    // Only executable sections hold functions. A binary can hold several, as
    // `.text.hot` and `.text.unlikely` show, so take them all.
    let code_sections: Vec<(u64, &[u8])> = file
        .sections()
        .filter(|section| section.kind() == SectionKind::Text && section.size() > 0)
        .filter_map(|section| section.data().ok().map(|data| (section.address(), data)))
        .collect();

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
        index = index_from_ranges(&crate::unwind::function_ranges(bytes, section.address(), order));
    }

    // Tables that code reads, such as those a `switch` jumps through, can
    // lie in any section the binary loads.
    let loaded: Vec<(u64, &[u8])> = file
        .sections()
        .filter(|section| section.address() != 0)
        .filter_map(|section| section.data().ok().map(|data| (section.address(), data)))
        .collect();

    recover_in_memory(&code_sections, &index, arch, &Memory::new(&loaded))
}

/// Turn the function ranges of call frame information into index entries.
///
/// Each range is described exactly. A gap after one holds code the table
/// does not list, such as hand-written assembly, so it is marked as an entry
/// that cannot unwind, which the scan searches as it would with no index.
pub fn index_from_ranges(ranges: &[core::ops::Range<u64>]) -> Vec<IndexEntry> {
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
    arch: &dyn Arch,
) -> Vec<Recovered> {
    recover_in_memory(regions, exception_index, arch, &Memory::new(regions))
}

/// Find the functions in code that is already located, where `memory` holds
/// everything else the binary loads, for the tables the code reads.
pub fn recover_in_memory(
    regions: &[(u64, &[u8])],
    exception_index: &[IndexEntry],
    arch: &dyn Arch,
    memory: &Memory<'_>,
) -> Vec<Recovered> {
    if regions.is_empty() {
        return Vec::new();
    }

    let mut starts: BTreeSet<(u64, Source)> = BTreeSet::new();
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
        for (base, code) in regions {
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
            for address in call_targets(arch, code, *base) {
                if !described.iter().any(|range| range.start < address && range.contains(&address))
                {
                    starts.insert((address, Source::CallTarget));
                }
            }
            for address in starts_after_returns_in(arch, code, *base, memory) {
                if blind.iter().any(|range| range.contains(&address)) {
                    starts.insert((address, Source::AfterReturn));
                }
            }
        }
        return build_functions(&starts, regions, arch);
    }

    for (base, code) in regions {
        for address in call_targets(arch, code, *base) {
            starts.insert((address, Source::CallTarget));
        }
        for address in function_entries(arch, code, *base) {
            starts.insert((address, Source::Entry));
        }
        for address in starts_after_returns_in(arch, code, *base, memory) {
            starts.insert((address, Source::AfterReturn));
        }
        // A region begins with a function unless something says otherwise.
        starts.insert((*base, Source::AfterReturn));
    }

    build_functions(&starts, regions, arch)
}

/// Turn a set of start addresses into functions that reach the next start.
fn build_functions(
    starts: &BTreeSet<(u64, Source)>,
    code_sections: &[(u64, &[u8])],
    arch: &dyn Arch,
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
        let bytes = arch.trim_padding(bytes);
        if bytes.is_empty() {
            continue;
        }

        out.push(Recovered {
            function: Function { name: String::new(), address: *address, code: bytes.to_vec() },
            source: *source,
        });
    }

    out
}

/// Find the unwind index in a raw image, which a flash dump copies along
/// with the code.
///
/// Nothing says where it is, but it is easy to recognize: entries of two
/// words, the first an offset from itself to a function of the image, in
/// rising order, and the second `EXIDX_CANTUNWIND`, an unwind description
/// held inline with its top bit set, or an offset to one elsewhere in the
/// image. A run of [`FEWEST_INDEX_ENTRIES`] such entries does not happen by
/// chance.
///
/// Measured on tinyxml2 for ARM as a raw image, the scan without it joined
/// destructors and short functions that follow a call that does not return.
pub fn find_exception_index(data: &[u8], base: u64, arch: &dyn Arch) -> Vec<IndexEntry> {
    /// The fewest entries a run needs to be taken for an index.
    const FEWEST_INDEX_ENTRIES: usize = 16;
    /// The personalities an inline description can name: 0, 1 and 2.
    const INLINE_PERSONALITIES: core::ops::RangeInclusive<u32> = 0x80..=0x82;

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
        let address = prel31(offset, first).filter(|&address| in_image(address))?;
        if !address.is_multiple_of(4) {
            return None;
        }
        // The entry names the first instruction of a function, which runs
        // always, as almost every ARM instruction does: its top four bits
        // are `0xE`. A table of small numbers otherwise reads as an index.
        let first_instruction = word(usize::try_from(address - base).ok()?)?;
        if first_instruction >> 28 != 0xe {
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
        Some(IndexEntry { address, unwinding })
    };

    let mut found = Vec::new();
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
            found.extend(run);
        } else {
            offset += 4;
        }
    }
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

fn exception_index(file: &object::File<'_>, arch: &dyn Arch) -> Vec<IndexEntry> {
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
    for (index, entry) in data.chunks_exact(EXIDX_ENTRY_LEN).enumerate() {
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
fn function_entries(arch: &dyn Arch, code: &[u8], base: u64) -> Vec<u64> {
    let (insns, _) = decode_all(arch, code, base);
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
fn call_targets(arch: &dyn Arch, code: &[u8], base: u64) -> Vec<u64> {
    let (insns, _) = decode_all(arch, code, base);
    let end = base + code.len() as u64;

    // A pool word that decodes as a call names a target made of data bits.
    let regions = [(base, code)];
    let pool = data_words(arch, &Memory::new(&regions), base..end, &insns);

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

    insns
        .iter()
        .filter(|insn| !pool.contains(&insn.address) && !is_text(insn))
        .filter_map(|insn| match insn.kind {
            InsnKind::Call { target } => target.map(|target| (insn.address, target)),
            _ => None,
        })
        .filter(|(address, target)| target != address)
        .map(|(_, target)| target)
        // A call out of this section goes somewhere this pass cannot see.
        .filter(|target| *target >= base && *target < end)
        .collect()
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
fn starts_after_returns(arch: &dyn Arch, code: &[u8], base: u64) -> Vec<u64> {
    let regions = [(base, code)];
    starts_after_returns_in(arch, code, base, &Memory::new(&regions))
}

/// [`starts_after_returns`], where `memory` holds what else the binary loads.
fn starts_after_returns_in(
    arch: &dyn Arch,
    code: &[u8],
    base: u64,
    memory: &Memory<'_>,
) -> Vec<u64> {
    let (insns, _) = decode_all(arch, code, base);
    let end = base + code.len() as u64;

    // Pool words are data. Read as code they are a random return or branch,
    // which moves with their values from one release to the next.
    let pool = data_words(arch, memory, base..end, &insns);
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
    let through_tables =
        arch.jump_tables(memory, base..end, &insns).into_iter().flat_map(|table| {
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
    let sure_starts: BTreeSet<u64> = call_targets(arch, code, base)
        .into_iter()
        .chain(function_entries(arch, code, base))
        .collect();
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
        // A conditional branch never comes from another function, and nor
        // does any branch from after the last sure start: a tail call comes
        // from the function before. Clang on MIPS jumps with `b` to the late
        // frame of `lua_setmetatable`, which opens with an entry sequence.
        let block = insns[start].address;
        let last_sure_start = sure_starts.range(..=block).next_back().copied();
        sources_of.get(&block).is_some_and(|sources| {
            sources.iter().any(|&(from, transfer)| {
                transfer == Transfer::Conditional
                    || last_sure_start.is_some_and(|start| from >= start && from < block)
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

    let mut out = Vec::new();
    // The last return before the current instruction. The code after it is
    // the function the current instruction is in, or the start of it.
    let mut previous_return = None;
    for (index, insn) in insns.iter().enumerate() {
        // Only code that does not fall through can be followed by a new
        // function. Everything else continues the one it is in.
        if !matches!(insn.kind, InsnKind::Return | InsnKind::Jump { .. }) || !is_code(&insn) {
            continue;
        }
        let since = previous_return;
        if insn.kind == InsnKind::Return {
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
        let function_start = anchors.range(..=insn.address).next_back().copied();
        let reached_by = |address: u64, accepted: &[Transfer]| {
            sources_of.get(&address).is_some_and(|sources| {
                sources.iter().any(|&(from, transfer)| {
                    let of_this_function = match function_start {
                        Some(start) => from >= start,
                        None => since.is_none_or(|since| from > since),
                    };
                    from < insn.address && of_this_function && accepted.contains(&transfer)
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

        // Otherwise a prologue is a function start whatever precedes it. This
        // is the stronger signal, so it is not subject to the spanning test:
        // an error path that jumps backwards over the end of its own function
        // would otherwise hide the function that follows.
        if arch.is_prologue(following) {
            out.push(start_of(&insns, next, arch));
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
            &insns,
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

        // Otherwise only a return that nothing branches across ends a
        // function. A jump without a prologue after it is a tail call or a
        // loop, which stays inside.
        let opens = may_open(following.address);
        if insn.kind == InsnKind::Return && !is_internal(insn.address) && opens {
            out.push(following.address);
        }
    }

    out
}

/// The words of a region that are data among the code: literal pools, and
/// the tables that jumps go through.
fn data_words(
    arch: &dyn Arch,
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
fn start_of(insns: &[Insn], prologue: usize, arch: &dyn Arch) -> u64 {
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
    arch: &dyn Arch,
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
    use crate::arch::arm32::Arm32;

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
        assert!(call_targets(&Arm32, &code, 0x1000).is_empty());
    }

    #[test]
    fn a_real_call_target_is_a_function_start() {
        // `bl` to the third word, then `bx lr`, then the function called. An
        // assembler emits a placeholder and a relocation for this, so the
        // encoding is written out directly. A zero offset field means "two
        // words ahead", because the encoding carries the pipeline bias.
        let code = [0x00, 0x00, 0x00, 0xeb, 0x1e, 0xff, 0x2f, 0xe1, 0x00, 0x00, 0x81, 0xe0];
        assert_eq!(call_targets(&Arm32, &code, 0), vec![0x8], "the call target starts a function");
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

    /// Padding between functions must not be mistaken for their start.
    #[test]
    fn padding_after_a_return_is_stepped_over() {
        // bx lr, nop, add
        let code = [0x1e, 0xff, 0x2f, 0xe1, 0x00, 0xf0, 0x20, 0xe3, 0x00, 0x00, 0x81, 0xe0];
        assert_eq!(starts_after_returns(&Arm32, &code, 0), vec![0x8], "the nop is padding");
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
        use crate::arch::mips::Mips32;

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
        assert!(call_targets(&Arm32, &text, 0).is_empty());

        // bl 0x13948: the same target, from a word that is not text.
        let call = with_word_at_4(0xeb00_4e4f);
        assert_eq!(call_targets(&Arm32, &call, 0), vec![0x13948]);
    }

    /// A branch crosses a return inside its own function only. One from
    /// before a prologue is of another function, or is data, and it must
    /// not hide the leaf function after the return.
    #[test]
    fn a_branch_from_before_a_prologue_does_not_cross_a_return() {
        use crate::arch::mips::Mips32;

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
        use crate::arch::mips::Mips32;

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
        use crate::arch::mips::Mips32;

        let code = mips_code(&[
            0x0320_f809,     // 0x00 jalr t9, as to _Unwind_Resume
            0x0000_0000,     // 0x04 nop
            0x3c1c_0002,     // 0x08 lui gp, 0x2
            0x279c_8000,     // 0x0c addiu gp, gp, -0x8000
            0x0399_e021,     // 0x10 addu gp, gp, t9
            0x03e0_0008,     // 0x14 jr ra
            0x0000_0000_u32, // 0x18 nop
        ]);
        assert_eq!(function_entries(&Mips32::LITTLE, &code, 0), vec![0x08]);
        let starts: Vec<u64> = recover_from_regions(&[(0, &code)], &[], &Mips32::LITTLE)
            .iter()
            .map(|found| found.function.address)
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
        use crate::arch::mips::Mips32;

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
        use crate::arch::mips::Mips32;

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
        use crate::arch::mips::Mips32;

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
        use crate::arch::mips::Mips32;

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
        use crate::arch::mips::Mips32;

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
}
