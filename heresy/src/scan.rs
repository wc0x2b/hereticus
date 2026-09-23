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

use std::collections::BTreeSet;

use object::{Object, ObjectSection, SectionKind};

use crate::arch::{Arch, Insn, InsnKind, decode_all};
use crate::obj::Function;

/// Bytes in one ARM EHABI unwind entry: a function address and one word
/// that says how to unwind it.
const EXIDX_ENTRY_LEN: usize = 8;

/// How a function was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// The symbol table named it. Exact.
    Symbol,
    /// The unwind index listed it. Exact where it is present.
    ExceptionIndex,
    /// Something calls it, so it must be a function. Exact for what it finds.
    CallTarget,
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

    recover_from_regions(&code_sections, &exception_index_starts(&file, arch), arch)
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
    exception_index: &[u64],
    arch: &dyn Arch,
) -> Vec<Recovered> {
    if regions.is_empty() {
        return Vec::new();
    }

    let mut starts: BTreeSet<(u64, Source)> = BTreeSet::new();
    for address in exception_index {
        starts.insert((*address, Source::ExceptionIndex));
    }

    // The exception index lists every function, so when it is there it is the
    // whole answer. Guessing on top of it only invents boundaries: an
    // internal `bx lr` would split one function into two.
    if !exception_index.is_empty() {
        for (base, code) in regions {
            for address in call_targets(arch, code, *base) {
                starts.insert((address, Source::CallTarget));
            }
        }
        return build_functions(&starts, regions, arch);
    }

    for (base, code) in regions {
        for address in call_targets(arch, code, *base) {
            starts.insert((address, Source::CallTarget));
        }
        for address in starts_after_returns(arch, code, *base) {
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
fn exception_index_starts(file: &object::File<'_>, arch: &dyn Arch) -> Vec<u64> {
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

        // The top bit marks a "cannot unwind" entry, not part of the offset.
        let offset = sign_extend_31(raw & 0x7fff_ffff);
        let field_address = section.address() + (index * EXIDX_ENTRY_LEN) as u64;

        let relative = field_address.wrapping_add(offset as u64);
        let direct = u64::from(raw & 0x7fff_ffff);

        // A linked image holds a true `PREL31` offset, so the relative
        // reading is right. A relocatable object has not had its relocations
        // applied, so the field still holds the target itself.
        //
        // Both land inside code often enough that neither can be preferred
        // blindly, so `relocated` decides, and the other reading is only a
        // fallback for a file that does not fit either pattern.
        let (first, second) = if relocated { (relative, direct) } else { (direct, relative) };

        if in_code(first) {
            out.push(first);
        } else if in_code(second) {
            out.push(second);
        }
    }

    out
}

/// Sign extend a 31-bit value to a signed 64-bit one.
fn sign_extend_31(value: u32) -> i64 {
    const SIGN_BIT: u32 = 1 << 30;
    if value & SIGN_BIT != 0 { i64::from(value) - (1 << 31) } else { i64::from(value) }
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

    insns
        .iter()
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
fn starts_after_returns(arch: &dyn Arch, code: &[u8], base: u64) -> Vec<u64> {
    let (insns, _) = decode_all(arch, code, base);
    let end = base + code.len() as u64;

    // Branches that stay inside this region, as (from, to). A function can
    // return from several places — an early exit, a guard clause — and each
    // of those returns is followed by more of the same function.
    let branches: Vec<(u64, u64)> = insns
        .iter()
        .filter_map(|insn| match insn.kind {
            InsnKind::Branch { target: Some(target) } | InsnKind::Jump { target: Some(target) } => {
                Some((insn.address, target))
            }
            _ => None,
        })
        .filter(|(_, target)| *target >= base && *target < end)
        .collect();

    // A branch that starts at or before a return and lands after it proves
    // control flows across that return, so the return is inside a function
    // rather than at the end of one.
    let is_internal =
        |address: u64| branches.iter().any(|(from, to)| *from <= address && *to > address);

    let mut out = Vec::new();
    for (index, insn) in insns.iter().enumerate() {
        // Only code that does not fall through can be followed by a new
        // function. Everything else continues the one it is in.
        if !matches!(insn.kind, InsnKind::Return | InsnKind::Jump { .. }) {
            continue;
        }

        // Step over any padding the linker put between functions.
        let mut next = index + 1;
        while insns.get(next).is_some_and(|insn| arch.is_padding(insn)) {
            next += 1;
        }

        let Some(following) = insns.get(next) else { continue };

        // A prologue is a function start whatever precedes it. This is the
        // stronger signal, so it is not subject to the spanning test: an
        // error path that jumps backwards over the end of its own function
        // would otherwise hide the function that follows.
        if arch.is_prologue(following) {
            out.push(following.address);
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
        if let Some(prologue) = prologue_past_pool(&insns, next, arch) {
            out.push(prologue);
            continue;
        }

        // Otherwise only a return that nothing branches across ends a
        // function. A jump without a prologue after it is a tail call or a
        // loop, which stays inside.
        if insn.kind == InsnKind::Return && !is_internal(insn.address) {
            out.push(following.address);
        }
    }

    out
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
/// Returns the prologue address, or `None` when no prologue sits within the
/// window.
fn prologue_past_pool(insns: &[Insn], from: usize, arch: &dyn Arch) -> Option<u64> {
    /// The most words to step over before a prologue. A literal pool between
    /// two functions holds a few constants; a longer run is a function body,
    /// not a pool, and its first prologue-shaped word is not a function start.
    const MOST_POOL_WORDS: usize = 8;

    let mut next = from;
    for _ in 0..MOST_POOL_WORDS {
        let insn = insns.get(next)?;
        if arch.is_prologue(insn) {
            return Some(insn.address);
        }
        // Only pool data may sit between the terminator and the prologue. A
        // pool word carries no control flow: it decodes as a plain `Normal`
        // instruction or as `Unknown`. Any branch, call, jump or return means
        // the scan has entered a function body, where a `push` is a mid-body
        // save rather than a prologue, so stop before claiming it.
        if !matches!(insn.kind, InsnKind::Normal | InsnKind::Unknown) {
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
}
