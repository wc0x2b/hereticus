//! The scores and the evidence by which the stages choose a pair.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::norm::NormInsn;
use hereticus_callees::Callee;
use hereticus_image::{RowText, VirtualSlot};

use super::{Confidence, Prepared, Symbol};

/// The `members` of one side that reach something, grouped by their shape and
/// by what they reach.
///
/// A member with a callee that is unknown or unpaired is left out: what it
/// reaches is only in part known, and the part can match a twin that
/// reaches less. Tinyxml2's `SetAttribute` for `int64_t` and for
/// `uint64_t` share one callee, and each has one of its own.
///
/// See RESEARCH.md, A6.
pub(super) fn group_by_shape_and_references<'a>(
    side: &'a [Prepared<'_>],
    keys: &'a [Vec<ReferenceKey>],
    members: impl Iterator<Item = usize>,
) -> HashMap<(&'a [Symbol], &'a [ReferenceKey]), Vec<usize>> {
    let reaches_all_known = |index: usize| {
        let prepared = &side[index];
        keys[index].len() == prepared.calls.len() + prepared.texts.len()
    };
    let mut groups: HashMap<_, Vec<usize>> = HashMap::new();
    for index in members.filter(|&index| !keys[index].is_empty() && reaches_all_known(index)) {
        groups
            .entry((side[index].ordered.as_slice(), keys[index].as_slice()))
            .or_default()
            .push(index);
    }
    groups
}

/// Texts shorter than this are reported only as [`short_texts_changed`]
/// says.
const SHORT_TEXT: usize = 4;

/// The texts of [`SHORT_TEXT`] bytes or more, in order.
pub(super) fn long_texts<'t>(texts: &[&'t str]) -> Vec<&'t str> {
    texts.iter().copied().filter(|text| text.len() >= SHORT_TEXT).collect()
}

/// How many short texts changed in place, as `"%d"` to `"%u"`.
///
/// A word of data can read as a short text by chance, so only a sure one
/// counts: see [`hereticus_image::Links::is_sure_text`]. And a short text
/// can come or go where no change is: a linker merges `"yes"` into the
/// tail of `"... yes"`, where no NUL comes before it, and measured on the
/// OpenWrt kernels, a pointer to such a tail read as a text on one side
/// only. So only as many as both sides lose and gain count.
///
/// Each side is its texts and its sure texts, both sorted.
pub(super) fn short_texts_changed(left: (&[&str], &[&str]), right: (&[&str], &[&str])) -> usize {
    let only = |sure: &[&str], other: &[&str]| {
        sure.iter()
            .filter(|text| text.len() < SHORT_TEXT && other.binary_search(text).is_err())
            .count()
    };
    only(left.1, right.0).min(only(right.1, left.0))
}

/// How many texts of one sorted list have no equal in the other, counted from
/// the side with more, so a text changed in place counts once.
///
/// A text that differs from one on the other side only by its build
/// directory counts as equal: see [`differ_only_by_build_path`].
pub(super) fn texts_that_differ(left: &[&str], right: &[&str]) -> usize {
    let (mut shared, mut l, mut r) = (0, 0, 0);
    let (mut left_only, mut right_only) = (Vec::new(), Vec::new());
    while l < left.len() && r < right.len() {
        match left[l].cmp(right[r]) {
            core::cmp::Ordering::Less => {
                left_only.push(left[l]);
                l += 1;
            }
            core::cmp::Ordering::Greater => {
                right_only.push(right[r]);
                r += 1;
            }
            core::cmp::Ordering::Equal => {
                shared += 1;
                l += 1;
                r += 1;
            }
        }
    }
    left_only.extend_from_slice(&left[l..]);
    right_only.extend_from_slice(&right[r..]);
    for text in left_only {
        if let Some(found) =
            right_only.iter().position(|other| differ_only_by_build_path(text, other))
        {
            right_only.swap_remove(found);
            shared += 1;
        }
    }
    left.len().max(right.len()) - shared
}

/// Report whether two texts are one path whose build directory alone
/// differs.
///
/// A build keeps the `__FILE__` path of each assert, and a build system
/// puts a random directory in it: Apple's kexts hold
/// `/AppleInternal/Library/BuildRoots/<random>/...`, and a Debian package
/// `/build/glibc-SzIz7B/...`. In iOS 27.0.1 all 28 changed kexts differed
/// in nothing else. Two texts are taken as one path where they hold the
/// same components but for those that look generated on both sides: the
/// same length, six or more bytes, no `.`, and digits with both upper and
/// lower case letters. A changed name of a file or a function is no such
/// component, so it still shows.
///
/// See RESEARCH.md, A11.
pub(super) fn differ_only_by_build_path(left: &str, right: &str) -> bool {
    let generated = |component: &str| {
        component.len() >= 6
            && !component.contains('.')
            && component.bytes().any(|byte| byte.is_ascii_digit())
            && component.bytes().any(|byte| byte.is_ascii_uppercase())
            && component.bytes().any(|byte| byte.is_ascii_lowercase())
    };
    if left == right || !left.contains('/') || !right.contains('/') {
        return false;
    }
    let (mut ours, mut theirs) = (left.split('/'), right.split('/'));
    loop {
        match (ours.next(), theirs.next()) {
            (None, None) => return true,
            (Some(one), Some(other)) if one == other => {}
            (Some(one), Some(other))
                if one.len() == other.len() && generated(one) && generated(other) => {}
            _ => return false,
        }
    }
}

/// How much what two functions call and point at weighs in the order the
/// similarity stage takes pairs in, against their code.
///
/// Two builds made another way, at `-Os` or by the other compiler, inline
/// and schedule differently, and the code alone then prefers the wrong
/// candidate by a few hundredths. What a function calls changes less. At
/// full agreement against none, the callees outweigh a difference of 0.2 in
/// the code. Measured on the backports built at other levels and by the
/// other compiler, stripped, this cut the wrong pairs by a quarter to a half,
/// and 0.05 or 0.2 did no better. The texts each function points at, added
/// later, cut them by a tenth more, with no comparison worse.
///
/// See RESEARCH.md, A8.
pub(super) const REFERENCE_WEIGHT: f64 = 0.1;

/// How deep the data-flow features go: an operation with what defines its
/// inputs, and what defines theirs. Measured over the cross builds, one
/// round paired 15 fewer right and 34 more wrong than two.
pub(super) const FLOW_DEPTH: usize = 2;

/// The floors at which data flow takes a pair the code alone would not.
pub(super) struct FlowRescue {
    /// The least similarity of the normalized instructions.
    pub(super) code: f64,
    /// The least similarity of the data-flow features.
    pub(super) flow: f64,
}

/// A true pair whose builds spell the work in other instructions scores
/// under the threshold, but its data flow can still agree, as data flow
/// knows an instruction by what feeds it. Measured over the cross builds,
/// 685 true pairs that clang and GCC built were missed with their partner
/// as the best candidate at 0.4 to 0.65. Taking those whose data flow
/// agrees at 0.7 or more paired 65 more right and 4 fewer wrong, and 7
/// more right and 2 more wrong across the releases. At 0.65 it paired 67
/// more right but 54 more wrong, and at 0.75, 17 more right and 4 more
/// wrong. The code floor matters little: 0.45 and 0.5 gave the same.
///
/// Data flow does not otherwise score a pair. Blended into the score, it
/// ran lower than the code alone and lost true pairs at the threshold: a
/// quarter of it paired 479 fewer right. As a part of the ranking, at 0.2,
/// it paired 21 more right and 18 fewer wrong over the cross builds, but 7
/// fewer right and 7 more wrong across the releases, all in tinyxml2.
///
/// See RESEARCH.md, A9.
pub(super) const FLOW_RESCUE: FlowRescue = FlowRescue { code: 0.5, flow: 0.7 };

/// How close in rank a free rival must come to stop the similarity stage
/// from taking a pair: see [`Cascade::match_by_similarity`]. The context
/// joins of [`Cascade::realign_by_context`] use it too, between two
/// candidates that share as many edges: there it paired 6 more right and
/// 11 fewer wrong over the backports, 96 fewer right and 145 fewer wrong
/// over the OpenWrt kernels, and 3 fewer right and 2 fewer wrong over the
/// Ubuntu updates.
///
/// Measured against no margin, 0.03 paired 24 fewer right and 159 fewer
/// wrong over the backports, and 223 fewer right and 2201 fewer wrong over
/// the OpenWrt kernels. Each step up to 0.03 was better on every set; 0.05
/// cost the backports 81 more right pairs for 16 fewer wrong. See
/// RESEARCH.md, entry 14.
///
/// [`Cascade::match_by_similarity`]: super::cascade::Cascade::match_by_similarity
/// [`Cascade::realign_by_context`]: super::cascade::Cascade::realign_by_context
pub(super) const RIVAL_MARGIN: f64 = 0.03;

/// The similarity at which the first pass of the similarity stage pairs.
///
/// The pairs it makes are the callees that tell the second pass's
/// candidates apart. Measured as for [`REFERENCE_WEIGHT`], 0.85 did best of
/// 0.75, 0.85 and 0.95.
///
/// See RESEARCH.md, A7.
pub(super) const CLOSE_SIMILARITY: f64 = 0.85;

/// A callee or a text, as both sides can name it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum ReferenceKey {
    /// A symbol the linker or the function names.
    Named(String),
    /// A function of the second binary, which a function of the first
    /// already paired with.
    Paired(usize),
    /// A text the function points at.
    Text(String),
}

/// How much the constants two functions share weigh in the order the
/// similarity stage takes pairs in, against their code.
///
/// See RESEARCH.md, entry 4 (PLocator): constants come from the source, so
/// another build keeps them where it rewrites the code around them. Pairing
/// on constants alone fails, as [`crate::norm::constant_signature`] says,
/// but as one part of the order they choose between close candidates.
/// Measured over the cross builds, 0.1 paired 94 more right and 77 fewer
/// wrong; 0.05 and 0.2 did less well.
pub(super) const CONSTANT_WEIGHT: f64 = 0.1;

/// The largest constant that names no function in particular, as a stack
/// offset, a field offset or a small count.
///
/// A shared constant above this counts as one edge in
/// [`Cascade::realign_by_context`]. Measured over the cross builds, this
/// paired 99 more right and 23 more wrong. Every shared constant, of any
/// size, paired 361 more right but 175 more wrong.
///
/// [`Cascade::realign_by_context`]: super::cascade::Cascade::realign_by_context
pub(super) const LARGEST_PLAIN_CONSTANT: u64 = 0xfff;

/// How well two sorted sets of constants agree, from -1.0 to 1.0, or 0.0
/// where neither holds any.
pub(super) fn constant_agreement(left: &[u64], right: &[u64]) -> f64 {
    if left.is_empty() && right.is_empty() {
        return 0.0;
    }
    2.0 * similarity_of_symbols(left, right) - 1.0
}

/// The lowest code similarity at which the layout alone pairs two
/// functions: see [`Cascade::pair_by_layout`].
///
/// Measured over the backports built two ways, 0.1 paired 1996 more right
/// and 59 more wrong; 0.2 paired 352 fewer right and 18 fewer wrong, and 0
/// paired 201 more right and 14 more wrong. A floor stays, so that a
/// function removed and another added in its place do not read as one.
/// Gaps whose counts differ, aligned by the scores, paired at 70%
/// precision at best, so they are left alone.
///
/// [`Cascade::pair_by_layout`]: super::cascade::Cascade::pair_by_layout
pub(super) const LOWEST_LAYOUT_SIMILARITY: f64 = 0.1;

/// How much more the pairs of a gap of equal counts must score, aligned in
/// order by their scores, than paired first with first, for
/// [`Cascade::pair_by_layout`] to take them.
///
/// Where a release deletes one function of a gap and adds another, the
/// functions after it pair one off, as `lockref_put_or_lock` with
/// `lockref_get`. Each pair counts its score less
/// [`LOWEST_LAYOUT_SIMILARITY`]. Measured against the symbols, this paired
/// 39 more right and 12 fewer wrong over the OpenWrt kernels, and 5 more
/// right over the backports built two ways, with every rank the same. At
/// 0.2 or less, the backports paired more wrong: between two compilers, the
/// first function of a gap is still most often the first one's partner.
///
/// [`Cascade::pair_by_layout`]: super::cascade::Cascade::pair_by_layout
pub(super) const SHIFTED_GAP_MARGIN: f64 = 0.3;

/// The lowest code similarity at which [`Cascade::pair_by_layout`] pairs
/// two functions in a gap whose counts differ.
///
/// Where a function went or came, nothing says which, but close code in
/// order still pairs: the similarity stage leaves it where a rival elsewhere
/// in the binary scores within [`RIVAL_MARGIN`], and the place tells the
/// two apart. No function of the gap that the alignment leaves out scores
/// within that margin of a pair, and the two call the same named
/// functions: five
/// hash wrappers of libssh, as `md5_update` and `md5_ctx_free`, score 1.00
/// and call other imports. Measured against the symbols, this paired 752
/// more right and 3 more wrong over the OpenWrt kernels, 10 more right over
/// the backports built two ways, and 4 more right over the Ubuntu updates,
/// with every rank the same. At 0.7 the backports paired 5 more wrong.
///
/// [`Cascade::pair_by_layout`]: super::cascade::Cascade::pair_by_layout
pub(super) const LOWEST_UNEVEN_GAP_SIMILARITY: f64 = 0.8;

/// Whether a pair sits between the pairs around it on both sides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Place {
    /// The second side sits between the partners of the pairs around the
    /// first, as code that stayed in its source file does.
    Kept,
    /// It sits elsewhere.
    Moved,
}

/// The callers and callees of the two sides of a pair.
pub(super) struct Context<'a> {
    /// The partners of the paired callers and callees of the first side.
    pub(super) partners_of_left: BTreeSet<usize>,
    /// The callers and callees of the second side.
    pub(super) right: &'a BTreeSet<usize>,
    /// How many of [`Self::right`] paired.
    pub(super) paired_right: usize,
}

/// Whether [`lacks_context`] judges a pair of `confidence`: a pair by
/// identical code, shape or name keeps itself whatever its callers and
/// callees say.
pub(super) fn is_judged_by_context(confidence: Confidence) -> bool {
    matches!(confidence, Confidence::SameCallers | Confidence::Similar | Confidence::SameLayout)
}

/// Whether the callers and callees of a pair say it is wrong: see
/// [`Cascade::unpair_without_context`].
///
/// [`Cascade::unpair_without_context`]: super::cascade::Cascade::unpair_without_context
pub(super) fn lacks_context(
    confidence: Confidence,
    score: f64,
    place: Place,
    context: &Context<'_>,
) -> bool {
    let Context { partners_of_left, right, paired_right } = context;
    let agreeing = partners_of_left.intersection(right).count();
    match confidence {
        Confidence::SameCallers => {
            let most = partners_of_left.len().max(*paired_right);
            place == Place::Moved
                && most > 0
                && (agreeing as f64) < LEAST_AGREEING_SHARE_OUT_OF_PLACE * most as f64
        }
        Confidence::Similar | Confidence::SameLayout => {
            let fewest = if score < WEAK_PAIR_SIMILARITY || place == Place::Moved {
                FEWEST_PAIRED_NEIGHBOURS_OF_A_WEAK_PAIR
            } else {
                FEWEST_PAIRED_NEIGHBOURS
            };
            partners_of_left.len() >= fewest && *paired_right >= fewest && agreeing == 0
        }
        _ => false,
    }
}

/// The least share of the paired callers and callees of a pair by callers
/// out of place that must agree, where [`Cascade::unpair_without_context`]
/// is to keep it.
///
/// Out of place, the pairs by callers where under 0.3 agree were right 20
/// times and wrong 156 over the kernels. Undoing them undid 17 right pairs
/// and 159 wrong there, and 2 right and 11 wrong over the backports, with
/// the fixes ranked a little higher. At 0.4 it ranked the backport fixes
/// lower; in place, no share told right from wrong.
///
/// [`Cascade::unpair_without_context`]: super::cascade::Cascade::unpair_without_context
pub(super) const LEAST_AGREEING_SHARE_OUT_OF_PLACE: f64 = 0.3;

/// How many callers and callees that paired each side of a pair needs for
/// [`Cascade::unpair_without_context`] to judge it.
///
/// [`Cascade::unpair_without_context`]: super::cascade::Cascade::unpair_without_context
pub(super) const FEWEST_PAIRED_NEIGHBOURS: usize = 2;

/// The code similarity under which a pair has little but its place for it,
/// so that [`FEWEST_PAIRED_NEIGHBOURS_OF_A_WEAK_PAIR`] applies.
///
/// Measured against the symbols and the source files in the DWARF, this
/// undid 16 right pairs and 103 wrong over the OpenWrt kernels, and 1 right
/// and 7 wrong over the backports built two ways, with the fixes ranked a
/// little higher. At 0.5 to 0.65 it undid more of both, and at 0.7 it
/// ranked the backport fixes lower.
pub(super) const WEAK_PAIR_SIMILARITY: f64 = 0.4;

/// See [`WEAK_PAIR_SIMILARITY`].
const FEWEST_PAIRED_NEIGHBOURS_OF_A_WEAK_PAIR: usize = 1;

/// The lowest code similarity at which a pair that [`Cascade::pair_by_layout`]
/// undid outranks a pair by place, where it also scores
/// [`MOVED_SIMILARITY_MARGIN`] more.
///
/// Across a kernel upgrade, code moves to another file or another place in
/// its file, and a pair of it breaks the order of the pairs around it. Undone
/// and paired by place, `put_mtd_device` lost its partner at 1.00 to
/// `mtd_read` at 0.35. Measured against the symbols, this paired 401 more
/// right and 160 fewer wrong over the OpenWrt kernels, and 26 more right and
/// 2 fewer wrong over the backports built two ways. A floor of 0.75 or 0.85,
/// or a margin of 0.1 to 0.4, did less on one of the two.
///
/// [`Cascade::pair_by_layout`]: super::cascade::Cascade::pair_by_layout
pub(super) const LOWEST_MOVED_SIMILARITY: f64 = 0.8;

/// See [`LOWEST_MOVED_SIMILARITY`].
pub(super) const MOVED_SIMILARITY_MARGIN: f64 = 0.2;

/// How many times [`Cascade::pair_by_unique_references_until_settled`]
/// runs the stage at most. Measured over the OpenWrt kernels, a second
/// round paired 7 more right and 7 fewer wrong, and the backports did not
/// change.
///
/// [`Cascade::pair_by_unique_references_until_settled`]: super::cascade::Cascade::pair_by_unique_references_until_settled
pub(super) const MOST_UNIQUE_REFERENCE_ROUNDS: usize = 4;

/// The lowest code similarity at which a text or a constant that only two
/// functions hold pairs them: see [`Cascade::pair_by_unique_references`].
///
/// Measured over the backports built two ways, 0.3 paired 304 more right
/// and 40 fewer wrong; 0.1 paired 328 more right and 31 fewer wrong, and
/// 0.4 paired 274 more right and 43 fewer wrong. A floor stays, so that a
/// text that moved to another function does not pair the two.
///
/// [`Cascade::pair_by_unique_references`]: super::cascade::Cascade::pair_by_unique_references
pub(super) const LOWEST_UNIQUE_REFERENCE_SIMILARITY: f64 = 0.3;

/// A reference that can tell one function from all others.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum UniqueReference<'a> {
    Text(&'a str),
    /// A function the linker names, as an import.
    Callee(&'a str),
    /// A function already paired, by its index in the second binary.
    Paired(usize),
    /// The set of functions already paired that a function calls, hashed,
    /// where it holds [`FEWEST_CALLEES_IN_A_SET`] or more.
    CalleeSet(u64),
    /// A constant above [`LARGEST_PLAIN_CONSTANT`].
    Constant(u64),
    /// A text beside the function in a record of the data, and how many
    /// words from the function it sits: see
    /// [`hereticus_image::Binary::row_texts`].
    Row(RowText<'a>),
    /// A slot of the vtable of a named class: see
    /// [`hereticus_image::Binary::virtual_slots`].
    ClassSlot(VirtualSlot<'a>),
}

/// Each text, large constant, named callee, row text and vtable slot that
/// exactly one function of `side` holds, and that function. `rows` holds
/// the row texts of each function of `side`, and `classes` its slots.
pub(super) fn unique_reference_holders<'a>(
    side: &'a [Prepared<'_>],
    rows: &'a [Vec<RowText<'a>>],
    classes: &'a [Vec<VirtualSlot<'a>>],
    paired: &dyn Fn(usize) -> Option<usize>,
) -> HashMap<UniqueReference<'a>, usize> {
    let mut holders: HashMap<UniqueReference<'a>, Option<usize>> = HashMap::new();
    for (index, prepared) in side.iter().enumerate() {
        let texts = prepared.texts.iter().map(|text| UniqueReference::Text(text));
        let constants = prepared.anchors().iter().map(|&value| UniqueReference::Constant(value));
        let calls = prepared.calls.iter().filter_map(|callee| match callee {
            Callee::Named(name) => Some(UniqueReference::Callee(name.as_str())),
            Callee::Function(callee) => paired(*callee).map(UniqueReference::Paired),
            _ => None,
        });
        let callee_set = paired_callee_set(prepared, paired);
        let row_texts = rows[index].iter().map(|&row| UniqueReference::Row(row));
        let class_slots = classes[index].iter().map(|&slot| UniqueReference::ClassSlot(slot));
        let keys = texts.chain(constants).chain(calls).chain(callee_set).chain(row_texts);
        for key in keys.chain(class_slots) {
            holders
                .entry(key)
                .and_modify(|holder| {
                    if *holder != Some(index) {
                        *holder = None;
                    }
                })
                .or_insert(Some(index));
        }
    }
    holders.into_iter().filter_map(|(key, holder)| Some((key, holder?))).collect()
}

/// The paired callees of `prepared` as one reference, where there are
/// [`FEWEST_CALLEES_IN_A_SET`] or more. `paired` names a callee by its
/// partner, so both sides hash alike.
fn paired_callee_set(
    prepared: &Prepared<'_>,
    paired: &dyn Fn(usize) -> Option<usize>,
) -> Option<UniqueReference<'static>> {
    use core::hash::{Hash, Hasher};
    let mut set: Vec<usize> = prepared
        .calls
        .iter()
        .filter_map(|callee| match callee {
            Callee::Function(callee) => paired(*callee),
            _ => None,
        })
        .collect();
    set.sort_unstable();
    set.dedup();
    if set.len() < FEWEST_CALLEES_IN_A_SET {
        return None;
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    set.hash(&mut hasher);
    Some(UniqueReference::CalleeSet(hasher.finish()))
}

/// The fewest paired callees whose set counts as a unique reference.
///
/// One function calls `kmalloc` among hundreds, but few call exactly the
/// same three functions. Measured over the OpenWrt kernels, sets of two or
/// more paired 283 more right and 244 fewer wrong; sets of three or more
/// 177 more right and 177 fewer wrong.
const FEWEST_CALLEES_IN_A_SET: usize = 2;

/// The largest gap, as the product of its free functions on the two sides,
/// that [`Cascade::same_places`] aligns.
///
/// The alignment keeps a table of this many scores. A gap this large holds
/// two unrelated runs of code, where a place means nothing.
///
/// [`Cascade::same_places`]: super::cascade::Cascade::same_places
pub(super) const MOST_PLACE_CELLS: usize = 1 << 20;

/// The least share of the functions of the smaller binary that must pair
/// in order before [`Cascade::pair_by_layout`] reads their places.
///
/// Two unrelated objects of eight functions each paired three by place
/// alone, with no pair around them. Measured over the backports built two
/// ways, 0.25 paired 4 fewer right than no floor, and 0.5 paired 167 fewer
/// right and 45 fewer wrong: another compiler pairs few functions in order.
///
/// [`Cascade::pair_by_layout`]: super::cascade::Cascade::pair_by_layout
pub(super) const LEAST_ANCHORED_SHARE: f64 = 0.25;

/// The keys that more than [`MOST_HOLDERS_OF_AN_EDGE`] of the functions
/// of `keys` hold.
pub(super) fn common_keys(keys: &[Vec<ReferenceKey>]) -> HashSet<ReferenceKey> {
    let mut holders: HashMap<&ReferenceKey, usize> = HashMap::new();
    for list in keys {
        // The keys are sorted, so a repeat sits next to its first.
        let mut distinct: Vec<&ReferenceKey> = list.iter().collect();
        distinct.dedup();
        for key in distinct {
            *holders.entry(key).or_default() += 1;
        }
    }
    holders
        .into_iter()
        .filter(|&(_, count)| count > MOST_HOLDERS_OF_AN_EDGE)
        .map(|(key, _)| key.clone())
        .collect()
}

/// The most functions an edge may join before
/// [`Cascade::realign_by_context`] counts it no more.
///
/// Measured over the OpenWrt kernels, where context joins were wrong 35%
/// of the time, 128 paired 390 fewer right and 918 fewer wrong; the
/// backports did not change, and the Ubuntu updates paired 1 fewer right.
/// 64 paired 113 fewer right for 74 fewer wrong than 128, and 256 paired
/// 85 more right for 141 more wrong.
///
/// [`Cascade::realign_by_context`]: super::cascade::Cascade::realign_by_context
pub(super) const MOST_HOLDERS_OF_AN_EDGE: usize = 128;

/// The fewest call edges and texts a pair must share before
/// [`Cascade::realign_by_context`] takes it.
///
/// [`Cascade::realign_by_context`]: super::cascade::Cascade::realign_by_context
pub(super) const FEWEST_SHARED_EDGES: usize = 3;

/// The lowest code similarity at which context alone pairs two functions.
pub(super) const LOWEST_CONTEXT_SIMILARITY: f64 = 0.3;

/// How much `count` copies of one added instruction weigh, from 1 for one
/// copy toward [`SATURATION`] + 1 for many.
///
/// The term frequency of BM25 (RESEARCH.md, entry 8): the first copies are
/// strong evidence, and each more copy adds less. A rewrite that adds forty
/// moves of one shape then weighs less than a fix that adds three rare
/// instructions.
pub(super) fn saturated(count: usize) -> f64 {
    let count = count as f64;
    count * (SATURATION + 1.0) / (count + SATURATION)
}

/// The `k1` of BM25. Measured on the backports built two ways and the
/// published fixes, 1.2 ranked the fixes higher than 0.5 or 3, and higher
/// than no saturation at all.
pub(super) const SATURATION: f64 = 1.2;

/// The items of the sorted list `left` that `right` lacks, counted as a
/// multiset, sorted.
pub(super) fn sorted_only_in<T: Ord + Copy>(left: &[T], right: &[T]) -> Vec<T> {
    let mut only = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < left.len() {
        if j == right.len() || left[i] < right[j] {
            only.push(left[i]);
            i += 1;
        } else if left[i] > right[j] {
            j += 1;
        } else {
            i += 1;
            j += 1;
        }
    }
    only
}

/// How many items two sorted lists share.
pub(super) fn sorted_shared<T: Ord>(left: &[T], right: &[T]) -> usize {
    let mut shared = 0usize;
    let (mut i, mut j) = (0usize, 0usize);
    while i < left.len() && j < right.len() {
        match left[i].cmp(&right[j]) {
            core::cmp::Ordering::Less => i += 1,
            core::cmp::Ordering::Greater => j += 1,
            core::cmp::Ordering::Equal => {
                shared += 1;
                i += 1;
                j += 1;
            }
        }
    }
    shared
}

/// How well two sorted lists of references agree, from -1.0 to 1.0, or 0.0
/// where neither names any.
///
/// See RESEARCH.md, A8.
pub(super) fn reference_agreement(left: &[ReferenceKey], right: &[ReferenceKey]) -> f64 {
    if left.is_empty() && right.is_empty() {
        return 0.0;
    }
    let shared = sorted_shared(left, right);
    let combined = left.len() + right.len() - shared;
    2.0 * shared as f64 / combined as f64 - 1.0
}

/// How many candidates one function keeps.
///
/// A function needs more than its single best candidate, because that one can
/// be claimed by a better pair and the function must then fall back rather
/// than go unmatched. It does not need all of them: a candidate is only ever
/// reached after every stronger one for the same function was taken by a
/// stronger pair, which the measurement below shows does not run deep.
///
/// Keeping every candidate is what made a whole kernel impossible to compare.
/// Two 11 MB images recover about 25000 functions each, and a kernel holds
/// thousands of near-identical wrappers, so the list grew to millions of
/// entries and the process was killed before it could report anything.
pub(super) const CANDIDATES_PER_FUNCTION: usize = 8;

/// Keep only the strongest candidates for one function.
///
/// Called with one new candidate appended, so at most one entry is over the
/// limit and a single pass finds the weakest.
///
/// See RESEARCH.md, A7.
pub(super) fn keep_best_candidates(candidates: &mut Vec<(f64, usize, usize)>) {
    if candidates.len() <= CANDIDATES_PER_FUNCTION {
        return;
    }

    // Drop the weakest. Ties break on the right-hand index, so the choice does
    // not depend on the order the scores arrived in.
    let weakest = candidates
        .iter()
        .enumerate()
        .min_by(|(_, a), (_, b)| {
            a.0.partial_cmp(&b.0).unwrap_or(core::cmp::Ordering::Equal).then_with(|| b.2.cmp(&a.2))
        })
        .map(|(position, _)| position);

    if let Some(position) = weakest {
        candidates.swap_remove(position);
    }
}

/// Similarity of two bodies already reduced to sorted symbols.
///
/// The same Jaccard similarity that [`similarity`] computes, over the same
/// multiset, but by walking two sorted lists rather than building a map. This
/// runs once per candidate pair in the scoring stage, so it allocates nothing.
///
/// See RESEARCH.md, A7.
pub(super) fn similarity_of_symbols<T: Ord>(left: &[T], right: &[T]) -> f64 {
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }

    let shared = sorted_shared(left, right);

    // |A ∪ B| = |A| + |B| − |A ∩ B| for multisets, so the union needs no walk.
    let combined = left.len() + right.len() - shared;
    if combined == 0 { 0.0 } else { shared as f64 / combined as f64 }
}

/// Similarity of two normalized bodies, from 0.0 to 1.0.
///
/// This is Jaccard similarity over the multiset of normalized instructions:
/// the shared count divided by the combined count. It ignores order, which
/// suits code the compiler reordered.
pub fn similarity(left: &[NormInsn], right: &[NormInsn]) -> f64 {
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }

    let mut counts: HashMap<&NormInsn, (usize, usize)> = HashMap::new();
    for insn in left {
        counts.entry(insn).or_default().0 += 1;
    }
    for insn in right {
        counts.entry(insn).or_default().1 += 1;
    }

    let mut shared = 0;
    let mut combined = 0;
    for (in_left, in_right) in counts.values() {
        shared += in_left.min(in_right);
        combined += in_left.max(in_right);
    }

    if combined == 0 { 0.0 } else { shared as f64 / combined as f64 }
}
