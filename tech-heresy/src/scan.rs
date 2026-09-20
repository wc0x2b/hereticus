//! Find functions in a binary that has no symbol table.
//!
//! A shipped firmware image is usually stripped, so the symbol table that
//! [`crate::obj`] reads is not there. This module recovers the function
//! boundaries from the code and from what the linker left behind.
//!
//! Three sources, strongest first:
//!
//! 1. **The ARM exception index.** `.ARM.exidx` holds one entry per function,
//!    each pointing at where that function starts. It survives stripping, and
//!    when it is there it is exact. It is ARM specific, and a compiler can
//!    leave it out.
//! 2. **Call targets.** Anything a `bl` jumps to is the start of a function.
//!    This finds what is called but misses what is not.
//! 3. **What follows a return, and what looks like a prologue.** Code after a
//!    function ends usually starts a new one, and a `push` that saves the link
//!    register opens almost every non-leaf function. This is the weakest
//!    source, so it only fills gaps the other two left.
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

use crate::arch::{Arch, InsnKind, decode_all};
use crate::obj::Function;

/// Bytes in one ARM exception index entry: a function address and one word
/// that says how to unwind it.
const EXIDX_ENTRY_LEN: usize = 8;

/// How a function was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// The symbol table named it. Exact.
    Symbol,
    /// The ARM exception index listed it. Exact where it is present.
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
pub fn recover_functions<A: Arch>(data: &[u8], arch: &A) -> Vec<Recovered> {
    let Ok(file) = object::File::parse(data) else { return Vec::new() };

    // Only executable sections hold functions. A binary can hold several, as
    // `.text.hot` and `.text.unlikely` show, so take them all.
    let code_sections: Vec<(u64, &[u8])> = file
        .sections()
        .filter(|section| section.kind() == SectionKind::Text && section.size() > 0)
        .filter_map(|section| section.data().ok().map(|data| (section.address(), data)))
        .collect();

    recover_from_regions(&code_sections, &exception_index_starts(&file), arch)
}

/// Find the functions in code that is already located.
///
/// This is the part of recovery that needs no container format. A raw firmware
/// image is one region at whatever address it loads at, and has no exception
/// index, so it comes through here with an empty `exception_index`.
///
/// Each region is an address and the bytes stored there. Returns the functions
/// in address order, with empty names.
pub fn recover_from_regions<A: Arch>(
    regions: &[(u64, &[u8])],
    exception_index: &[u64],
    arch: &A,
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
        return build_functions(&starts, regions);
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

    build_functions(&starts, regions)
}

/// Turn a set of start addresses into functions that reach the next start.
fn build_functions(
    starts: &BTreeSet<(u64, Source)>,
    code_sections: &[(u64, &[u8])],
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
        let bytes = trim_padding(bytes);
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

/// Read function addresses from the ARM exception index.
///
/// Each entry is eight bytes: a `PREL31` offset to the function, then one word
/// describing how to unwind it. `PREL31` is a signed 31-bit offset from the
/// place the field itself sits.
///
/// In a relocatable object the field holds the target directly, because the
/// relocation that would make it relative has not been applied. Both readings
/// are tried, and the one that lands inside a code section wins.
fn exception_index_starts(file: &object::File<'_>) -> Vec<u64> {
    let Some(section) = file.section_by_name(".ARM.exidx") else { return Vec::new() };
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
fn call_targets<A: Arch>(arch: &A, code: &[u8], base: u64) -> Vec<u64> {
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
fn starts_after_returns<A: Arch>(arch: &A, code: &[u8], base: u64) -> Vec<u64> {
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
        while insns.get(next).is_some_and(is_padding) {
            next += 1;
        }

        let Some(following) = insns.get(next) else { continue };
        if following.kind == InsnKind::Unknown {
            continue;
        }

        // A prologue is a function start whatever precedes it. This is the
        // stronger signal, so it is not subject to the spanning test: an
        // error path that jumps backwards over the end of its own function
        // would otherwise hide the function that follows.
        if is_prologue(following) {
            out.push(following.address);
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

/// Report whether an instruction opens a function.
///
/// A function that calls anything must save the link register first, so
/// `push {..., lr}` is how almost every non-leaf ARM function begins. Measured
/// on a stripped kernel object, every real function start matched this and
/// nothing else did.
///
/// A leaf function has no prologue at all, which is why this adds to the
/// return-based rule rather than replacing it.
fn is_prologue(insn: &crate::arch::Insn) -> bool {
    (insn.mnemonic.starts_with("push") || insn.mnemonic.starts_with("stm"))
        && insn.operands.contains("lr")
}

/// Remove the alignment padding a linker put after a function.
///
/// Only whole words at the end are removed, and only the two encodings a
/// linker pads with. Padding in the middle of a function stays, because there
/// it is not padding.
fn trim_padding(bytes: &[u8]) -> &[u8] {
    /// The A32 `nop` encoding, little endian.
    const NOP: [u8; 4] = [0x00, 0xf0, 0x20, 0xe3];
    const ZERO: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

    let mut end = bytes.len();
    while end >= 4 {
        let word = &bytes[end - 4..end];
        if word == NOP || word == ZERO {
            end -= 4;
        } else {
            break;
        }
    }

    &bytes[..end]
}

/// Report whether an instruction is alignment padding rather than work.
///
/// A linker pads with `nop` or with zero words. `yaxpeax-arm` 0.4 does not
/// decode the usual ARM `nop` encoding `0xe320f000` and reports it as
/// unreadable, so the raw word is checked as well as the name.
fn is_padding(insn: &crate::arch::Insn) -> bool {
    /// The A32 hint encoding that means "no operation".
    const NOP: &str = "0xe320f000";
    /// Zero words, which some linkers use to pad instead.
    const ZERO: &str = "0x00000000";

    insn.mnemonic.starts_with("nop")
        || (insn.kind == InsnKind::Unknown && (insn.operands == NOP || insn.operands == ZERO))
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

    /// An unrelocated `bl` encodes `.-8`, which reads back as the call site.
    /// Treating that as a function start would split a function at every call.
    #[test]
    fn trailing_padding_is_removed() {
        // add, then a nop the linker used to align the next function.
        let code = [0x00, 0x00, 0x81, 0xe0, 0x00, 0xf0, 0x20, 0xe3];
        assert_eq!(trim_padding(&code), &code[..4]);
    }

    #[test]
    fn trailing_zero_words_are_removed() {
        let code = [0x00, 0x00, 0x81, 0xe0, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(trim_padding(&code), &code[..4]);
    }

    /// Padding inside a function is not padding, so it must stay.
    #[test]
    fn padding_before_real_code_is_kept() {
        let code = [0x00, 0xf0, 0x20, 0xe3, 0x00, 0x00, 0x81, 0xe0];
        assert_eq!(trim_padding(&code), &code[..], "only the end is trimmed");
    }

    #[test]
    fn trimming_leaves_a_function_of_only_padding_empty() {
        assert!(trim_padding(&[0x00, 0xf0, 0x20, 0xe3]).is_empty());
    }

    #[test]
    fn trimming_keeps_code_that_needs_no_trimming() {
        let code = [0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
        assert_eq!(trim_padding(&code), &code[..]);
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
    fn a_prologue_is_recognized_by_its_saved_link_register() {
        let push_lr = Arm32.decode(&[0x10, 0x40, 0x2d, 0xe9], 0, 0).unwrap();
        assert!(is_prologue(&push_lr), "push {{r4, lr}} opens a function");

        // `push {r4, r5}` saves no link register, so it calls nothing and is
        // not the start of a non-leaf function.
        let push_plain = Arm32.decode(&[0x30, 0x00, 0x2d, 0xe9], 0, 0).unwrap();
        assert!(!is_prologue(&push_plain));

        let add = Arm32.decode(&[0x00, 0x00, 0x81, 0xe0], 0, 0).unwrap();
        assert!(!is_prologue(&add));
    }

    #[test]
    fn a_return_at_the_end_starts_nothing() {
        let code = [0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
        assert!(starts_after_returns(&Arm32, &code, 0).is_empty());
    }

    /// Padding between functions must not be mistaken for their start.
    #[test]
    fn padding_after_a_return_is_stepped_over() {
        // bx lr, nop, add
        let code = [0x1e, 0xff, 0x2f, 0xe1, 0x00, 0xf0, 0x20, 0xe3, 0x00, 0x00, 0x81, 0xe0];
        assert_eq!(starts_after_returns(&Arm32, &code, 0), vec![0x8], "the nop is padding");
    }
}
