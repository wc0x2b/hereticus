//! Pair the functions of one binary with the functions of another.
//!
//! Matching runs as an ordered cascade. Each stage pairs the functions it is
//! sure about, removes them from the pool, and leaves the rest to the next
//! stage. Stages run from most reliable to least, so a confident answer is
//! never overruled by a guess.
//!
//! The order matters for cost as well as accuracy. Early stages are hashes and
//! run in linear time. Only what survives them reaches the scoring stage,
//! which compares every remaining pair.
//!
//! Matching says *which* function became which. It does not say whether the
//! function changed: two matched functions can still differ, and
//! [`Match::changed`] reports that.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub use crate::view::PairedLabels;

use rayon::prelude::*;

use crate::address::{AddressSpace, ConstantKind, Contents};

use crate::arch::{
    Arch, DataAmongCode, Insn, InsnKind, Memory, decode_all, is_branch_target, split_printed,
};
use crate::callee::{Callee, callees_in};
use crate::il;
use crate::norm::{
    FlowShape, NormInsn, OperandShape, constant_signature, flow_features, normalize_body_in,
};
use crate::obj::{Binary, FoundBy, Function, Isa};

/// How confident a pairing is, and what justified it.
///
/// The order of the variants is the order of the cascade, so a stronger reason
/// sorts before a weaker one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// The machine code is byte for byte the same.
    IdenticalCode,
    /// The normalized instructions agree exactly.
    IdenticalShape,
    /// The names agree, and no stronger reason applied.
    SameName,
    /// One of a group of functions with the same normalized instructions,
    /// paired with its counterpart by position. See
    /// [`Cascade::match_twins_in_order`].
    TwinInOrder,
    /// The two alone hold a text or a constant on both sides. See
    /// [`Cascade::pair_by_unique_references`].
    SameReferences,
    /// Calls from functions paired on firmer ground reach these two, where a
    /// weaker reason had paired each with another. See
    /// [`Cascade::pair_by_callers`].
    SameCallers,
    /// The two sit in the same place between pairs on both sides. See
    /// [`Cascade::pair_by_layout`].
    SameLayout,
    /// The normalized instructions are similar enough to pair.
    Similar,
}

impl Confidence {
    /// Report whether this pairing used the symbol name.
    ///
    /// A stripped binary has no names to use, so a caller that wants to know
    /// how it would do without them can ask.
    pub fn used_name(self) -> bool {
        self == Self::SameName
    }
}

/// One pair of functions, and what happened to it.
#[derive(Clone, Debug)]
pub struct Match {
    /// Index into the functions of the first binary.
    pub before: usize,
    /// Index into the functions of the second binary.
    pub after: usize,
    /// Why these two were paired.
    pub confidence: Confidence,
    /// Similarity of the normalized bodies, from 0.0 to 1.0.
    pub score: f64,
    /// Whether the pair differs in any way a reader would care about.
    pub changed: Changed,
    /// How many instructions the edit added, removed and rewrote.
    pub edits: Edits,
    /// What kind of code the edit touched.
    pub kinds: EditKinds,
    /// The instructions the later build added, with more weight where the
    /// addition is rare among the changed pairs.
    ///
    /// This is [`Edits::added`], plus ln((N + 1) / (n + 1)) for each
    /// instruction the later body holds more of, where N is the number of
    /// changed pairs and n the number of those that add the same
    /// instruction, with many copies of one instruction weighed as
    /// [`saturated`] says. Another compiler or another flag adds the same
    /// instructions to many functions, and a fix adds its own to few. Zero
    /// for a pair that did not change.
    ///
    /// Measured on four published fixes, this put the fix of
    /// CVE-2025-24257 at row 6 where [`Edits::added`] put it at row 19, and
    /// the others within one row of where they were. Over the backports
    /// built two ways, it lifts the fixes that rank worst, but some fall
    /// from row 1 to row 2.
    ///
    /// See RESEARCH.md, entry 6: this is the inverse document frequency of
    /// information retrieval, over the instructions each pair added.
    pub rarity: f64,
}

/// The size of an edit, in normalized instructions.
///
/// The score says how alike two functions are; this says how much work the
/// difference amounts to. A function at 0.98 that rewrote forty instructions
/// deserves a reader's attention before one at 0.98 that rewrote one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Edits {
    /// Instructions the later build has and the earlier one does not.
    pub added: usize,
    /// Instructions the earlier build has and the later one does not.
    pub removed: usize,
    /// Instructions present in both, in the same place, that differ.
    pub edited: usize,
}

impl Edits {
    /// Report whether the two bodies are the same size.
    ///
    /// A function that only rewrote instructions kept its length, which is a
    /// different kind of edit from one that grew or shrank.
    pub fn same_length(self) -> bool {
        self.added == 0 && self.removed == 0
    }

    /// How many instructions the edit touched in total.
    pub fn total(self) -> usize {
        self.added + self.removed + self.edited
    }
}

/// What kind of code an edit touched.
///
/// [`Edits`] says how much changed and [`Changed`] says how much to care. This
/// says *what*: a function that gained a branch reads differently from one
/// that moved a constant, even when both touched one instruction.
///
/// An instruction falls in exactly one kind, chosen by the order the variants
/// are declared, so the counts sum to the instructions the edit touched. The
/// order puts control flow first because it is what changes behavior.
///
/// See RESEARCH.md, A12.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EditKind {
    /// A conditional branch: a gate the code did not have, or lost.
    Branch,
    /// A call to another function.
    Call,
    /// A call kept in place that now reaches a different function.
    ///
    /// Reported on its own axis, as [`EditKind::Constant`] is: normalizing
    /// hides a call target on purpose, because a callee moves whenever code
    /// before it grows, so such a call is never added, removed or rewritten.
    /// See [`EditKinds::callees`].
    Callee,
    /// An unconditional jump or a return.
    Jump,
    /// A read or write through memory.
    Memory,
    /// A stored value, with the instructions around it untouched.
    ///
    /// Reported on its own axis from the rest: a changed threshold leaves
    /// every instruction in place, so it never reaches the counts in
    /// [`Edits`]. See [`EditKinds::constants`].
    Constant,
    /// A text the function points at, such as a format or a message.
    ///
    /// Reported on its own axis, as [`EditKind::Constant`] is: normalizing
    /// hides the address of the text, so no instruction changes. See
    /// [`EditKinds::texts`].
    Text,
    /// Anything the decoder could read that fits no other kind.
    Other,
    /// Bytes the decoder cannot read, which may be data rather than code.
    Opaque,
}

/// How many instructions of each kind an edit touched.
///
/// The first six counts partition the instructions [`Edits`] counted, so they
/// sum to `Edits::total`. The constant count stands apart: normalizing hides a
/// constant on purpose, so an instruction whose value changed stays in place
/// and is never added, removed or rewritten.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EditKinds {
    /// Conditional branches added, removed or rewritten.
    pub branches: usize,
    /// Calls added, removed or rewritten.
    pub calls: usize,
    /// Jumps and returns added, removed or rewritten.
    pub jumps: usize,
    /// Memory accesses added, removed or rewritten.
    pub memory: usize,
    /// Other readable instructions added, removed or rewritten.
    pub other: usize,
    /// Undecodable words added, removed or rewritten.
    pub opaque: usize,
    /// Instructions kept in place whose stored constants changed.
    ///
    /// Outside the sum above, because such an instruction did not move.
    pub constants: usize,
    /// Calls kept in place that reach a different function.
    ///
    /// Outside the sum above, for the same reason as `constants`.
    pub callees: usize,
    /// Texts the function points at that differ.
    ///
    /// Outside the sum above, for the same reason as `constants`.
    pub texts: usize,
}

impl EditKinds {
    /// Add one instruction of the given kind.
    fn add(&mut self, kind: EditKind) {
        let count = match kind {
            EditKind::Branch => &mut self.branches,
            EditKind::Call => &mut self.calls,
            EditKind::Callee => &mut self.callees,
            EditKind::Jump => &mut self.jumps,
            EditKind::Memory => &mut self.memory,
            EditKind::Constant => &mut self.constants,
            EditKind::Text => &mut self.texts,
            EditKind::Other => &mut self.other,
            EditKind::Opaque => &mut self.opaque,
        };
        *count += 1;
    }

    /// Every kind that appears, most telling first.
    ///
    /// The order follows [`EditKind`], so a reader sees control flow before
    /// bookkeeping.
    pub fn present(self) -> impl Iterator<Item = (EditKind, usize)> {
        [
            (EditKind::Branch, self.branches),
            (EditKind::Call, self.calls),
            (EditKind::Callee, self.callees),
            (EditKind::Jump, self.jumps),
            (EditKind::Memory, self.memory),
            (EditKind::Constant, self.constants),
            (EditKind::Text, self.texts),
            (EditKind::Other, self.other),
            (EditKind::Opaque, self.opaque),
        ]
        .into_iter()
        .filter(|(_, count)| *count > 0)
    }

    /// Report whether the edit touched control flow.
    ///
    /// A changed branch, call or jump can change what the function does for
    /// some input, which a changed constant or a moved load cannot.
    pub fn touches_control_flow(self) -> bool {
        self.branches > 0 || self.calls > 0 || self.callees > 0 || self.jumps > 0
    }
}

/// Work out which kind an instruction belongs to.
///
/// Control flow decides first, because it is what changes behavior. An
/// instruction that moves no control is classified by its operands, where a
/// memory reference outranks the rest.
fn kind_of(insn: &NormInsn) -> EditKind {
    match insn.flow {
        FlowShape::Branch => return EditKind::Branch,
        FlowShape::Call => return EditKind::Call,
        FlowShape::Jump | FlowShape::Return => return EditKind::Jump,
        FlowShape::Opaque => return EditKind::Opaque,
        FlowShape::Linear => {}
    }

    let touches_memory = insn
        .operands
        .iter()
        .any(|shape| matches!(shape, OperandShape::Memory | OperandShape::StackSlot));

    if touches_memory { EditKind::Memory } else { EditKind::Other }
}

/// Whether a matched pair differs, and how.
///
/// A pair can match and still differ. Normalizing hides the detail a compiler
/// picks freely, so two functions that normalize alike can still hold
/// different constants.
///
/// The variants rise in how much a reader should care, so
/// `Changed::No < Changed::Reordered < Changed::Data < Changed::InDetail <
/// Changed::Unreadable < Changed::Yes`.
///
/// See RESEARCH.md, A12.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Changed {
    /// Nothing a reader would call a change.
    ///
    /// Either the machine code is identical, or it differs only in what
    /// normalizing hides on purpose, such as which register holds a value.
    No,
    /// The same instructions in a different order.
    ///
    /// A compiler reorders freely, so this is usually not a real edit. It is
    /// reported separately rather than hidden, because a reordering can also
    /// come from an edit that moved code.
    Reordered,
    /// The pair looks like data rather than code, and its bytes differ.
    ///
    /// A scan reads the tables after the last function of a region as more of
    /// that function. Every release changes thousands of their words, which
    /// would put them above every real edit. See [`crate::arch::Arch::contents`].
    Data,
    /// The instructions agree but their constants do not.
    ///
    /// This is the shape a changed threshold or a changed magic number takes.
    InDetail,
    /// The difference sits in bytes the decoder cannot read.
    ///
    /// Two unrelated things produce this, and nothing local tells them apart:
    /// a word of **data** stored among the code, and an **instruction** from
    /// an extension the decoder does not implement. Measured on the test
    /// corpus, `array_max` rewritten as `array_min` differs in three opaque
    /// words of NEON, which is the same shape a changed table entry takes.
    ///
    /// So this variant claims only what it can prove: the bytes differ, and
    /// the tool cannot say what they mean. A reader who needs to know must
    /// open a disassembler. Saying that plainly is worth a variant, because
    /// 1039 of the 5650 differing functions in a measured kernel
    /// pair are in this position and were previously indistinguishable from
    /// the 1513 that hold a readable edit.
    Unreadable,
    /// The instructions themselves differ.
    Yes,
}

/// A function with no counterpart, and the closest thing to one.
///
/// A function can go unmatched because it really was removed or added, or
/// because the two builds compiled it too differently to recognize. Those need
/// different responses from a reader, and the score separates them: a near miss
/// at 0.38 is worth opening a disassembler for, one at 0.02 is not.
///
/// The same shape serves both directions. For a removed function the candidate
/// is in the second binary; for an added one it is in the first. Which binary
/// each index reads holds is fixed by the list the miss came from.
///
/// Reporting the score costs nothing. It was computed while matching and then
/// thrown away.
///
/// See RESEARCH.md, A14.
#[derive(Clone, Copy, Debug)]
pub struct NearMiss {
    /// The unmatched function this candidate is for, in its own binary.
    pub unmatched: usize,
    /// The closest candidate in the other binary, if any was scored.
    pub best: Option<usize>,
    /// How close that candidate came, from 0.0 to 1.0.
    pub score: f64,
    /// The unmatched function of the other binary that sits in the same
    /// place, between the same two pairs, if one does.
    ///
    /// A fix can rewrite a function so much that no score pairs it, or split
    /// it in two. Its place still shows where it went. This is a hint, not a
    /// pair: measured over the backports, 61% of these hints are right. See
    /// [`Cascade::same_places`] and RESEARCH.md, entry 7.
    pub in_place: Option<usize>,
}

/// The result of comparing two binaries.
#[derive(Clone, Debug)]
pub struct Diff {
    /// Pairs of functions, strongest reason first.
    pub matched: Vec<Match>,
    /// Functions of the first binary with no counterpart.
    pub removed: Vec<usize>,
    /// Functions of the second binary with no counterpart.
    pub added: Vec<usize>,
    /// Whether each removed function holds code or data, in the same order
    /// as [`Diff::removed`].
    ///
    /// A raw image holds its headers and read-only data among its code, and
    /// they move when the code before them grows, so data goes and comes as
    /// code does. See [`crate::arch::Arch::contents`].
    pub removed_contents: Vec<Contents>,
    /// Whether each added function holds code or data, in the same order as
    /// [`Diff::added`].
    pub added_contents: Vec<Contents>,
    /// For each removed function, the candidate that came closest.
    ///
    /// In the same order as [`Diff::removed`].
    pub near_misses: Vec<NearMiss>,
    /// For each added function, the candidate that came closest.
    ///
    /// The mirror of [`Diff::near_misses`]: the candidate is a function of the
    /// first binary. An added function with no close candidate is real new
    /// code; one with a close candidate is likely a function the cascade could
    /// not pair, not truly new. In the same order as [`Diff::added`].
    pub added_near_misses: Vec<NearMiss>,
}

impl Diff {
    /// Matched pairs that differ in any way.
    pub fn changed(&self) -> impl Iterator<Item = &Match> {
        self.matched.iter().filter(|pair| pair.changed != Changed::No)
    }

    /// The near miss for a removed function, if one was found.
    pub fn near_miss(&self, before: usize) -> Option<&NearMiss> {
        self.near_misses.iter().find(|miss| miss.unmatched == before)
    }

    /// The near miss for an added function, if one was found.
    pub fn added_near_miss(&self, after: usize) -> Option<&NearMiss> {
        self.added_near_misses.iter().find(|miss| miss.unmatched == after)
    }

    /// Removed functions, each with what it holds.
    pub fn removed_with_contents(&self) -> impl Iterator<Item = (usize, Contents)> + '_ {
        self.removed.iter().copied().zip(self.removed_contents.iter().copied())
    }

    /// Added functions, each with what it holds.
    pub fn added_with_contents(&self) -> impl Iterator<Item = (usize, Contents)> + '_ {
        self.added.iter().copied().zip(self.added_contents.iter().copied())
    }
}

/// How willing the cascade is to pair two functions on similarity alone.
///
/// Below this score a pair is left unmatched rather than guessed at. The
/// default separates the test corpus: functions that belong together score at
/// or near 1.00 there, and the closest unrelated pair scores 0.50.
const DEFAULT_THRESHOLD: f64 = 0.65;

/// The lowest score at which a caller alone pairs two unpaired functions.
///
/// A fix can rewrite a function past [`DEFAULT_THRESHOLD`], and a caller
/// whose code agrees then shows the two are one. Measured on smallvec built
/// by Rust for ARM at `-O1`, the edited `insert_many` for `u64` scored 0.54
/// against itself. This floor keeps a caller from pairing two functions that
/// share nothing.
const LOWEST_JOINED_SIMILARITY: f64 = 0.5;

/// Settings for a comparison.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Lowest similarity that still counts as a match.
    pub threshold: f64,
    /// Whether the cascade may pair functions by name.
    ///
    /// Turn this off to see how the cascade performs on a stripped binary
    /// while still having names available to check the answer.
    pub use_names: UseNames,
}

/// Whether symbol names may be used for matching.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UseNames {
    Yes,
    No,
}

impl Default for Options {
    fn default() -> Self {
        Self { threshold: DEFAULT_THRESHOLD, use_names: UseNames::Yes }
    }
}

/// A distinct normalized instruction, as a number.
///
/// Two instructions carry the same symbol exactly when they compare equal.
type Symbol = u32;

/// Give each distinct normalized instruction a number.
///
/// The scoring stage compares every remaining pair, and comparing two bodies
/// directly means hashing an operation name and an operand list once per
/// instruction per pair. The same few thousand instructions are hashed over and
/// over that way.
///
/// Numbering them once turns the comparison into counting over small integers.
/// Both binaries share one interner, so a symbol means the same thing on either
/// side.
#[derive(Default)]
struct Interner {
    symbols: HashMap<NormInsn, Symbol>,
}

impl Interner {
    /// The symbol for an instruction, assigning one when it is new.
    fn intern(&mut self, insn: &NormInsn) -> Symbol {
        let next = self.symbols.len() as Symbol;
        match self.symbols.get(insn) {
            Some(&symbol) => symbol,
            None => {
                self.symbols.insert(insn.clone(), next);
                next
            }
        }
    }

    /// How many distinct instructions have been numbered.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.symbols.len()
    }
}

/// A function together with the forms the cascade compares.
struct Prepared<'a> {
    function: &'a Function,
    /// The body as symbols, sorted.
    ///
    /// Sorted so that [`similarity`] can walk two bodies together instead of
    /// building a map for each comparison. Order is already irrelevant to the
    /// score, which counts shared instructions rather than matching positions.
    symbols: Vec<Symbol>,
    /// The same symbols in the order the instructions run.
    ///
    /// Two functions of identical shape carry identical sequences, because a
    /// symbol stands for one distinct normalized instruction. That answers the
    /// shape stage by comparing four bytes an instruction, where a `NormInsn`
    /// compares field by field.
    ordered: Vec<Symbol>,
    /// Which decoder read this function, so the printed form can be recovered.
    isa: Isa,
    /// Where the binary sits, so the body normalizes again the same way.
    addresses: &'a AddressSpace,
    /// Whether the function holds code or data.
    contents: Contents,
    /// The callee of each call, in order.
    calls: Vec<Callee>,
    /// The callee of each call as the binary names it, where that is not
    /// [`Self::calls`]: without names, a callee the symbol table names is
    /// known only as the function it is. See [`Self::linked_calls`].
    linked_calls: Option<Vec<Callee>>,
    /// The texts the function points at, sorted.
    texts: Vec<&'a str>,
    /// Those of [`Self::texts`] sure enough that a change to one is
    /// reported, sorted.
    sure_texts: Vec<&'a str>,
    /// The data-flow features of the body, sorted: see
    /// [`crate::il::flow_features`].
    flow: Vec<u64>,
    /// The distinct constants of the body, sorted: see
    /// [`crate::norm::constant_signature`].
    constants: Vec<u64>,
    /// The normalized body, kept so that a pair need not decode and
    /// normalize it again.
    body: Vec<NormInsn>,
}

/// What a function refers to that its normalized code does not show.
///
/// Twins of one shape that differ here are different functions: `ToInt` and
/// `ToFloat` in tinyxml2 differ only in the format they pass to `sscanf`, and
/// Lua's `math_exp` and `math_log10` only in the import they call.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Referents<'a> {
    /// The callees the linker or a symbol names, sorted.
    calls: Vec<&'a str>,
    /// See [`Prepared::texts`].
    texts: &'a [&'a str],
}

impl Prepared<'_> {
    /// See [`Referents`].
    fn referents(&self) -> Referents<'_> {
        Referents { calls: self.named_calls(), texts: &self.texts }
    }

    /// The callees the linker or a symbol names, sorted.
    fn named_calls(&self) -> Vec<&str> {
        let mut calls: Vec<&str> = self
            .calls
            .iter()
            .filter_map(|callee| match callee {
                Callee::Named(name) => Some(name.as_str()),
                _ => None,
            })
            .collect();
        calls.sort_unstable();
        calls
    }

    /// Normalize this function again.
    ///
    /// Kept out of [`Prepared`] for the same reason as [`Prepared::printed`],
    /// and it matters far more here. A whole kernel holds about two million
    /// instructions an image, so storing every normalized body costs over
    /// 160 MB a side and the pair could not be compared at all. Only a matched
    /// pair needs it, and matching itself reads nothing but the symbols.
    fn body(&self) -> &[NormInsn] {
        &self.body
    }

    /// Report whether the two functions share a constant too large to be
    /// an offset or a count, as a magic number or a mask.
    ///
    /// See RESEARCH.md, entry 4 (PLocator): such a constant comes from the
    /// source and survives another build.
    fn shares_an_anchor_with(&self, other: &Prepared<'_>) -> bool {
        sorted_shared(self.anchors(), other.anchors()) > 0
    }

    /// The constants above [`LARGEST_PLAIN_CONSTANT`], sorted.
    fn anchors(&self) -> &[u64] {
        let first = self.constants.partition_point(|&value| value <= LARGEST_PLAIN_CONSTANT);
        &self.constants[first..]
    }

    /// The callee of each call as the binary names it, as
    /// [`crate::callee::callees`] gives them.
    fn linked_calls(&self) -> &[Callee] {
        self.linked_calls.as_deref().unwrap_or(&self.calls)
    }

    /// How many functions this one calls, each once.
    fn distinct_callees(&self) -> usize {
        let mut callees: Vec<usize> = self
            .calls
            .iter()
            .filter_map(|callee| match callee {
                Callee::Function(callee) => Some(*callee),
                _ => None,
            })
            .collect();
        callees.sort_unstable();
        callees.dedup();
        callees.len()
    }

    /// Report whether this function normalized to nothing.
    ///
    /// The symbols carry one entry per normalized instruction, so they answer
    /// this without normalizing again.
    fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}

/// Report whether an instruction moves control to a target address.
///
/// Only these may have a `$...` operand that moves for free. A word of data
/// that happens to decode as a branch is excluded by the operation check that
/// runs first, which a changed data word almost always fails.
fn transfers_control(kind: InsnKind) -> bool {
    matches!(kind, InsnKind::Call { .. } | InsnKind::Jump { .. } | InsnKind::Branch { .. })
}

/// Report whether two normalized bodies hold the same constants.
///
/// Call this only on bodies that already compare equal, which fixes their
/// lengths as equal too.
fn same_detail(before: &[NormInsn], after: &[NormInsn]) -> bool {
    before.iter().zip(after).all(|(left, right)| !left.differs_in_detail(right))
}

/// Prepare every function of a binary for matching.
///
/// The interner is shared between the two binaries, so a symbol means the same
/// instruction on either side.
fn prepare<'a>(
    binary: &'a Binary,
    use_names: UseNames,
    interner: &mut Interner,
    progress: &dyn Progress,
) -> Vec<Prepared<'a>> {
    let regions = binary.links.regions();
    let memory = Memory::new(&regions);
    // Without names, a callee the symbol table names is known only as the
    // function it is, as in a stripped binary. What the linker names stays.
    // A stripped binary keeps the names of what it exports, and those stay.
    let own_names: HashMap<&str, usize> = match (use_names, binary.found_by) {
        (UseNames::Yes, _) | (UseNames::No, FoundBy::Scanning) => HashMap::new(),
        (UseNames::No, FoundBy::Symbols) => binary
            .functions
            .iter()
            .enumerate()
            .rev()
            .map(|(index, function)| (function.name.as_str(), index))
            .collect(),
    };
    binary
        .functions
        .iter()
        .map(|function| {
            progress.advance(1);
            let isa = binary.isa_of(function);
            let arch = isa.arch();
            let (insns, _) = decode_all(arch, &function.code, function.address);
            // The body is kept as well as interned. Each changed pair reads
            // both bodies; normalizing them again for it took a sixth of a
            // comparison of a kernel, and keeping them costs a twelfth of
            // its peak memory.
            let body = normalize_body_in(arch, &function.code, &insns, &binary.addresses);
            let flow = flow_features(arch, &insns, FLOW_DEPTH);
            let contents = arch.contents(&function.code, &insns, &binary.addresses);
            let linked_calls = callees_in(arch, &binary.links, &binary.functions, &insns);
            let calls: Vec<Callee> = linked_calls
                .iter()
                .cloned()
                .map(|callee| match callee {
                    Callee::Named(name) => match own_names.get(name.as_str()) {
                        Some(&index) => Callee::Function(index),
                        None => Callee::Named(name),
                    },
                    // A direct call to an exported function of a stripped
                    // binary names it, as a call through its PLT stub does.
                    Callee::Function(index)
                        if binary.found_by == FoundBy::Scanning
                            && !binary.functions[index].name.is_empty() =>
                    {
                        Callee::Named(binary.functions[index].name.clone())
                    }
                    other => other,
                })
                .collect();
            let linked_calls = (linked_calls != calls).then_some(linked_calls);

            let mut found: Vec<(&str, bool)> = arch
                .data_addresses(&function.code, &insns, &binary.addresses, &memory)
                .into_iter()
                .filter_map(|address| {
                    let text = binary.links.text_after_code(arch, address)?;
                    Some((text, binary.links.is_sure_text(address, text)))
                })
                .collect();
            found.sort_unstable();
            let texts: Vec<&str> = found.iter().map(|&(text, _)| text).collect();
            let sure_texts: Vec<&str> =
                found.iter().filter(|&&(_, sure)| sure).map(|&(text, _)| text).collect();

            let constants: Vec<u64> = constant_signature(&body).into_iter().collect();
            let ordered: Vec<Symbol> = body.iter().map(|insn| interner.intern(insn)).collect();
            let mut symbols = ordered.clone();
            symbols.sort_unstable();

            Prepared {
                function,
                symbols,
                ordered,
                isa,
                addresses: &binary.addresses,
                contents,
                calls,
                linked_calls,
                texts,
                sure_texts,
                flow,
                constants,
                body,
            }
        })
        .collect()
}

/// The steps of a comparison, in the order they run.
///
/// Reported so that a caller can say what the tool is doing. The names are for
/// a person to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Decoding and normalizing the functions of both binaries.
    Preparing,
    /// Pairing on identical machine code.
    IdenticalCode,
    /// Pairing on identical normalized instructions.
    IdenticalShape,
    /// Pairing on the symbol name.
    Names,
    /// Scoring every remaining pair.
    ///
    /// The long one. Its step count is the number of functions left to place.
    Similarity,
    /// Finding the closest candidate for each unmatched function.
    NearMisses,
}

impl Phase {
    /// A short description, for a progress display.
    pub fn label(self) -> &'static str {
        match self {
            Self::Preparing => "reading functions",
            Self::IdenticalCode => "matching identical code",
            Self::IdenticalShape => "matching identical shape",
            Self::Names => "matching names",
            Self::Similarity => "scoring pairs",
            Self::NearMisses => "finding near misses",
        }
    }
}

/// Somewhere to report how far a comparison has got.
///
/// A comparison of two large images runs for many seconds with nothing to show
/// for it. Implement this to display progress. The library reports; it does not
/// draw, so nothing here dictates a display or pulls in a dependency.
///
/// Every method takes `&self`, so an implementation holds its own state behind
/// whatever it needs.
///
/// The scoring stages run on several threads, so an implementation must be
/// safe to call from all of them, and must not assume steps arrive in order.
pub trait Progress: Sync {
    /// A phase is starting, and will report `total` steps.
    fn start(&self, phase: Phase, total: usize);

    /// Some steps of the current phase are done.
    fn advance(&self, steps: usize);

    /// The current phase is done.
    fn finish(&self);
}

/// A [`Progress`] that discards everything, for callers that want no display.
pub struct NoProgress;

impl Progress for NoProgress {
    fn start(&self, _phase: Phase, _total: usize) {}
    fn advance(&self, _steps: usize) {}
    fn finish(&self) {}
}

/// Compare two binaries with the default settings.
pub fn diff(before: &Binary, after: &Binary) -> Diff {
    diff_with(before, after, Options::default())
}

/// Compare two binaries.
pub fn diff_with(before: &Binary, after: &Binary, options: Options) -> Diff {
    diff_reporting(before, after, options, &NoProgress)
}

/// Compare two binaries, reporting progress as each phase runs.
pub fn diff_reporting(
    before: &Binary,
    after: &Binary,
    options: Options,
    progress: &dyn Progress,
) -> Diff {
    progress.start(Phase::Preparing, before.functions.len() + after.functions.len());
    let mut interner = Interner::default();
    let left = prepare(before, options.use_names, &mut interner, progress);
    let right = prepare(after, options.use_names, &mut interner, progress);
    progress.finish();

    let mut cascade = Cascade {
        left,
        right,
        left_free: vec![true; before.functions.len()],
        right_free: vec![true; after.functions.len()],
        matched: Vec::new(),
        options,
    };

    cascade.match_identical_code(progress);
    cascade.match_identical_shape(progress);
    if options.use_names == UseNames::Yes {
        cascade.match_by_name(progress);
    }
    cascade.match_twins_in_order();
    // The stubs first too, so the similarity stage knows which import each
    // call reaches.
    cascade.align_stubs();
    // Twins that differ in a constant, before similarity pairs them in the
    // order it finds them, and again once their callees are known.
    cascade.pair_leftover_twins();
    // The close pairs first, so their callees tell the rest apart.
    let threshold = cascade.options.threshold;
    cascade.options.threshold = threshold.max(CLOSE_SIMILARITY);
    cascade.match_by_similarity(progress);
    cascade.options.threshold = threshold;
    cascade.match_by_similarity(progress);

    cascade.align_stubs();
    cascade.repair_twins_by_callees();
    cascade.uncross_by_callees();
    cascade.pair_by_unique_references_until_settled();
    cascade.pair_by_callers();
    cascade.realign_by_context();
    cascade.pair_by_layout();
    // Again, now that the callers and the order paired more of the callees
    // that tell two callers apart.
    cascade.pair_by_unique_references_until_settled();
    cascade.pair_leftover_twins();
    // Last, so that every pair that can serve as context has paired.
    cascade.unpair_without_context();
    cascade.compare_callees();
    cascade.compare_texts();
    cascade.finish(progress)
}

/// Which functions a question covers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Only {
    /// The functions still unpaired.
    Free,
    /// Every function.
    Any,
}

/// Which binary of a comparison.
#[derive(Clone, Copy)]
enum Side {
    Before,
    After,
}

/// The functions still to pair, and the pairs found so far.
///
/// Holding the pool in one place keeps each stage to the same short shape:
/// look for pairs, and call [`Cascade::take_pair`] for each one found.
struct Cascade<'a> {
    left: Vec<Prepared<'a>>,
    right: Vec<Prepared<'a>>,
    /// Whether each function of the first binary is still unpaired.
    left_free: Vec<bool>,
    /// Whether each function of the second binary is still unpaired.
    right_free: Vec<bool>,
    matched: Vec<Match>,
    options: Options,
}

impl Cascade<'_> {
    /// Record a pair and take both functions out of the pool.
    fn take_pair(&mut self, before: usize, after: usize, confidence: Confidence, score: f64) {
        self.left_free[before] = false;
        self.right_free[after] = false;
        let pair = self.assess(before, after, confidence, score);
        self.matched.push(pair);
    }

    /// What each free function calls and points at, as keys both sides
    /// share, sorted.
    ///
    /// A callee counts where the linker names it, or where it is a function
    /// already paired. Others say nothing yet. Every text counts.
    fn reference_keys(&self) -> (Vec<Vec<ReferenceKey>>, Vec<Vec<ReferenceKey>>) {
        self.reference_keys_where(Only::Free)
    }

    /// Undo a pair by similarity or by place where its callers and callees
    /// that paired all paired with functions its partner has no call edge
    /// with.
    ///
    /// A function deleted in a release often pairs with a new one of
    /// similar code, as `cpuidle_enter_state` with `skb_expand_head`. The
    /// code of the two agrees, but nothing around them does. A pair is
    /// undone where each side has [`FEWEST_PAIRED_NEIGHBOURS`] or more
    /// callers and callees that paired, and no two of them are a pair. One
    /// each is enough for a pair that scores under
    /// [`WEAK_PAIR_SIMILARITY`], and for one out of place: its sides do not
    /// sit between the same pairs, as code that stayed in its source file
    /// does. Out of place, 83% of the pairs by similarity with one paired
    /// neighbour that disagrees were wrong over the kernels; undoing them
    /// undid 57 right pairs and 269 wrong there, and 5 wrong over the
    /// backports. A pair by callers out of place is undone where less than
    /// [`LEAST_AGREEING_SHARE_OUT_OF_PLACE`] of its paired callers and
    /// callees agree.
    /// Stronger reasons stand, and a pair by callers or by references has
    /// its context already.
    ///
    /// Measured against the symbols, this undid 25 right pairs and 482
    /// wrong over the OpenWrt kernels, and 1 right and 1 wrong over the
    /// backports built two ways, with the fixes ranked as before. With one
    /// neighbour each, it undid 276 right and 919 wrong over the kernels,
    /// and ranked the fixes of the backports lower.
    ///
    /// See RESEARCH.md, entry 1: the callers and callees are the context of
    /// a function.
    fn unpair_without_context(&mut self) {
        // The functions each function calls or is called by, itself left
        // out.
        let neighbours = |side: &[Prepared<'_>]| {
            let mut sets = vec![BTreeSet::new(); side.len()];
            for (caller, prepared) in side.iter().enumerate() {
                for callee in &prepared.calls {
                    if let Callee::Function(callee) = *callee
                        && callee != caller
                        && callee < side.len()
                    {
                        sets[caller].insert(callee);
                        sets[callee].insert(caller);
                    }
                }
            }
            sets
        };
        let (left, right) = (neighbours(&self.left), neighbours(&self.right));
        let partner: HashMap<usize, usize> =
            self.matched.iter().map(|pair| (pair.before, pair.after)).collect();
        let layout = self.layout();
        // The place of each pair on the second side, by its place on the
        // first.
        let places: BTreeMap<usize, usize> = self
            .matched
            .iter()
            .map(|pair| (layout.left_place[pair.before], layout.right_place[pair.after]))
            .collect();
        // Whether a pair sits between the pairs that sit around it on the
        // first side, as code that stayed in its source file does.
        let in_place = |pair: &Match| {
            if layout.is_unanchored() {
                return true;
            }
            let (left, right) = (layout.left_place[pair.before], layout.right_place[pair.after]);
            let previous = places.range(..left).next_back().map(|(_, &place)| place);
            let next = places.range(left + 1..).next().map(|(_, &place)| place);
            match (previous, next) {
                (Some(previous), Some(next)) => previous < right && right < next,
                _ => true,
            }
        };
        let undone: Vec<bool> = self
            .matched
            .iter()
            .map(|pair| {
                let context = Context {
                    partners_of_left: left[pair.before]
                        .iter()
                        .filter_map(|neighbour| partner.get(neighbour).copied())
                        .collect(),
                    right: &right[pair.after],
                    paired_right: right[pair.after]
                        .iter()
                        .filter(|&&neighbour| !self.right_free[neighbour])
                        .count(),
                };
                let place = if in_place(pair) { Place::Kept } else { Place::Moved };
                lacks_context(pair.confidence, pair.score, place, &context)
            })
            .collect();
        let mut index = 0;
        self.matched.retain(|pair| {
            let keep = !undone[index];
            index += 1;
            if !keep {
                self.left_free[pair.before] = true;
                self.right_free[pair.after] = true;
            }
            keep
        });
    }

    /// The callers of each function that already paired, as indices into
    /// the second binary, sorted and without repeats.
    ///
    /// A caller of the first binary is known by its partner, so two lists
    /// compare directly.
    ///
    /// See RESEARCH.md, entry 1: the callers are the context of a function.
    fn paired_callers(&self) -> (Vec<Vec<usize>>, Vec<Vec<usize>>) {
        let partner: HashMap<usize, usize> =
            self.matched.iter().map(|pair| (pair.before, pair.after)).collect();
        let callers = |side: &[Prepared<'_>], key: &dyn Fn(usize) -> Option<usize>| {
            let mut callers = vec![Vec::new(); side.len()];
            for (caller, prepared) in side.iter().enumerate() {
                let Some(key) = key(caller) else { continue };
                for callee in &prepared.calls {
                    if let Callee::Function(callee) = callee
                        && let Some(list) = callers.get_mut(*callee)
                    {
                        list.push(key);
                    }
                }
            }
            for list in &mut callers {
                list.sort_unstable();
                list.dedup();
            }
            callers
        };
        (
            callers(&self.left, &|caller| partner.get(&caller).copied()),
            callers(&self.right, &|caller| (!self.right_free[caller]).then_some(caller)),
        )
    }

    /// Move a pairing by similarity to a free function that keeps more of
    /// its call edges, and pair two free functions whose call edges agree.
    ///
    /// Two builds made another way rewrite a function past what its code
    /// can show: measured over the cross builds, 572 wrong pairs had their
    /// true partner left free, and 358 of those partners scored under 0.5.
    /// Their context still agrees: the functions they call, the functions
    /// that call them, and the texts they point at. The code then only has
    /// to clear [`LOWEST_CONTEXT_SIMILARITY`].
    ///
    /// An edge that many functions share says little: most of a kernel
    /// calls `kfree` and `mutex_lock`, so two unrelated functions share
    /// three edges by chance. A callee or a text that more than
    /// [`MOST_HOLDERS_OF_AN_EDGE`] functions hold, and a caller that calls
    /// more than that many, do not count.
    ///
    /// See RESEARCH.md, entry 1 (contextual diffing, ASIA CCS 2025), which
    /// matches through the neighbors of matched functions, and entry 2
    /// (network alignment, QBinDiff), which scores a pair by the call edges
    /// it keeps together with its code.
    fn realign_by_context(&mut self) {
        /// Each round lets the new pairs serve as context for the next.
        const MOST_ROUNDS: usize = 4;

        for _ in 0..MOST_ROUNDS {
            if self.realign_by_context_once() == Repaired::Nothing {
                break;
            }
        }
    }

    /// One round of [`Self::realign_by_context`].
    fn realign_by_context_once(&mut self) -> Repaired {
        let (mut left_keys, mut right_keys) = self.reference_keys_of_all();
        let (mut left_callers, mut right_callers) = self.paired_callers();
        let common = common_keys(&right_keys);
        for keys in left_keys.iter_mut().chain(right_keys.iter_mut()) {
            keys.retain(|key| !common.contains(key));
        }
        let fanout: Vec<usize> = self.right.iter().map(Prepared::distinct_callees).collect();
        for callers in left_callers.iter_mut().chain(right_callers.iter_mut()) {
            callers.retain(|&caller| fanout[caller] <= MOST_HOLDERS_OF_AN_EDGE);
        }
        let context = |x: usize, y: usize| {
            sorted_shared(&left_keys[x], &right_keys[y])
                + sorted_shared(&left_callers[x], &right_callers[y])
                + usize::from(self.left[x].shares_an_anchor_with(&self.right[y]))
        };

        // The free functions of the second binary that a paired caller of
        // `x` calls, or that call a paired callee of `x`.
        let mut right_callers_of: Vec<Vec<usize>> = vec![Vec::new(); self.right.len()];
        for (caller, prepared) in self.right.iter().enumerate() {
            for callee in &prepared.calls {
                if let Callee::Function(callee) = callee
                    && let Some(list) = right_callers_of.get_mut(*callee)
                {
                    list.push(caller);
                }
            }
        }
        let neighbors = |x: usize| -> BTreeSet<usize> {
            let mut found = BTreeSet::new();
            for &caller in &left_callers[x] {
                for callee in &self.right[caller].calls {
                    if let Callee::Function(callee) = callee {
                        found.insert(*callee);
                    }
                }
            }
            for key in &left_keys[x] {
                if let ReferenceKey::Paired(callee) = key {
                    found.extend(right_callers_of[*callee].iter().copied());
                }
            }
            found.retain(|&y| y < self.right.len() && self.right_free[y]);
            found
        };

        let weak_partner: HashMap<usize, (usize, usize)> = self
            .matched
            .iter()
            .enumerate()
            .filter(|(_, pair)| pair.confidence == Confidence::Similar)
            .map(|(index, pair)| (pair.before, (index, pair.after)))
            .collect();

        // (context, score, x, y): the best free partner of each function of
        // the first binary that is free or paired by similarity alone.
        let mut proposals: Vec<(usize, f64, usize, usize)> = (0..self.left.len())
            .into_par_iter()
            .filter(|&x| self.left_free[x] || weak_partner.contains_key(&x))
            .filter_map(|x| {
                let now = weak_partner.get(&x).map_or(0, |&(_, y)| context(x, y));
                let mut found: Vec<(usize, f64, usize, usize)> = neighbors(x)
                    .into_iter()
                    .filter_map(|y| {
                        let shared = context(x, y);
                        let score =
                            similarity_of_symbols(&self.left[x].symbols, &self.right[y].symbols);
                        (shared >= FEWEST_SHARED_EDGES
                            && shared > now
                            && score >= LOWEST_CONTEXT_SIMILARITY)
                            .then_some((shared, score, x, y))
                    })
                    .collect();
                found.sort_by(|a, b| {
                    b.0.cmp(&a.0)
                        .then_with(|| b.1.partial_cmp(&a.1).unwrap_or(core::cmp::Ordering::Equal))
                        .then_with(|| a.3.cmp(&b.3))
                });
                // Two candidates alike in context and code: see
                // `RIVAL_MARGIN`.
                match found.as_slice() {
                    [best, second, ..]
                        if second.0 == best.0 && second.1 >= best.1 - RIVAL_MARGIN =>
                    {
                        None
                    }
                    found => found.first().copied(),
                }
            })
            .collect();
        // A free function of the second binary that two functions propose
        // alike goes to neither, unless a third shares more with it.
        let mut by_after: HashMap<usize, Vec<(usize, f64)>> = HashMap::new();
        for &(shared, score, _, y) in &proposals {
            by_after.entry(y).or_default().push((shared, score));
        }
        proposals.retain(|&(shared, score, _, y)| {
            let rivals = &by_after[&y];
            let alike = rivals
                .iter()
                .filter(|&&(other, other_score)| {
                    other == shared && (other_score - score).abs() <= RIVAL_MARGIN
                })
                .count();
            alike <= 1 || rivals.iter().any(|&(other, _)| other > shared)
        });
        proposals.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| b.1.partial_cmp(&a.1).unwrap_or(core::cmp::Ordering::Equal))
                .then_with(|| a.2.cmp(&b.2))
                .then_with(|| a.3.cmp(&b.3))
        });

        let mut taken = BTreeSet::new();
        let mut moves = Vec::new();
        let mut joins = Vec::new();
        for (_, score, x, y) in proposals {
            if !taken.insert(y) {
                continue;
            }
            match weak_partner.get(&x) {
                Some(&(index, _)) => moves.push((index, x, y, score)),
                None => joins.push((x, y, score)),
            }
        }
        if moves.is_empty() && joins.is_empty() {
            return Repaired::Nothing;
        }
        for (index, x, y, score) in moves {
            let old = self.matched[index].after;
            self.right_free[old] = true;
            self.right_free[y] = false;
            self.matched[index] = self.assess(x, y, Confidence::Similar, score);
        }
        for (x, y, score) in joins {
            self.take_pair(x, y, Confidence::SameCallers, score);
        }
        Repaired::Some
    }

    /// Pair the free functions that sit between two pairs in the same
    /// place on both sides, in order.
    ///
    /// A linker places the functions of one object in source order, and a
    /// new release keeps most of that order. Where two pairs `a`–`a′` and
    /// `b`–`b′` keep their order, and as many free functions sit between
    /// `a` and `b` as between `a′` and `b′`, the first pairs with the first,
    /// and so on, where each pair scores [`LOWEST_LAYOUT_SIMILARITY`] or
    /// more.
    ///
    /// A weak pair that breaks the order is undone first, so that its
    /// functions can pair by place, and comes back where neither does.
    /// Measured over the backports built two ways, this paired 504 more
    /// right and 242 fewer wrong. An undone pair whose code is close comes
    /// back in place of a pair by place that scores well below it: see
    /// [`LOWEST_MOVED_SIMILARITY`].
    ///
    /// See RESEARCH.md, entry 7: genome comparison calls this synteny, and
    /// uses conserved gene order to tell orthologs from look-alikes.
    fn pair_by_layout(&mut self) {
        let layout = self.layout();
        if layout.is_unanchored() {
            return;
        }
        let Layout { left_place, right_place, chain, .. } = &layout;

        // A weak pair off the chain breaks the order of the pairs around
        // it, which a wrong pair does more often than a right one. Its
        // functions are freed, so that each can pair by place, and the pair
        // comes back where neither does.
        let on_chain: BTreeSet<(usize, usize)> = chain.iter().copied().collect();
        let (kept, released): (Vec<Match>, Vec<Match>) =
            core::mem::take(&mut self.matched).into_iter().partition(|pair| {
                !matches!(
                    pair.confidence,
                    Confidence::Similar
                        | Confidence::SameReferences
                        | Confidence::SameCallers
                        | Confidence::TwinInOrder
                ) || on_chain.contains(&(left_place[pair.before], right_place[pair.after]))
            });
        self.matched = kept;
        for pair in &released {
            self.left_free[pair.before] = true;
            self.right_free[pair.after] = true;
        }

        let mut pairs = Vec::new();
        for (lefts, rights) in layout.gaps(&self.left_free, &self.right_free) {
            // Where the counts differ, a function went or came, and nothing
            // says which.
            if lefts.is_empty() || lefts.len() != rights.len() {
                continue;
            }
            for (&x, &y) in lefts.iter().zip(&rights) {
                let score = similarity_of_symbols(&self.left[x].symbols, &self.right[y].symbols);
                if score >= LOWEST_LAYOUT_SIMILARITY {
                    pairs.push((x, y, score));
                }
            }
        }
        // A pair undone above can be close code that moved: its functions
        // left the order when a release moved the code to another place.
        // Such a pair outranks a pair by place that would take one of its
        // functions.
        let mut undone_score: (HashMap<usize, f64>, HashMap<usize, f64>) = Default::default();
        for pair in &released {
            undone_score.0.insert(pair.before, pair.score);
            undone_score.1.insert(pair.after, pair.score);
        }
        let outranks = |undone: Option<&f64>, score: f64| {
            undone.is_some_and(|&undone| {
                undone >= LOWEST_MOVED_SIMILARITY && undone > score + MOVED_SIMILARITY_MARGIN
            })
        };
        pairs.retain(|&(x, y, score)| {
            !outranks(undone_score.0.get(&x), score) && !outranks(undone_score.1.get(&y), score)
        });
        for (x, y, score) in pairs {
            self.take_pair(x, y, Confidence::SameLayout, score);
        }
        for pair in released {
            if self.left_free[pair.before] && self.right_free[pair.after] {
                self.left_free[pair.before] = false;
                self.right_free[pair.after] = false;
                self.matched.push(pair);
            }
        }
    }

    /// Run [`Self::pair_by_unique_references`] until it pairs nothing more,
    /// or [`MOST_UNIQUE_REFERENCE_ROUNDS`] times: each new pair is a callee
    /// that can tell its callers apart.
    fn pair_by_unique_references_until_settled(&mut self) {
        for _ in 0..MOST_UNIQUE_REFERENCE_ROUNDS {
            if self.pair_by_unique_references() == Repaired::Nothing {
                break;
            }
        }
    }

    /// Pair two functions that hold a text, a constant or a call that no
    /// other function of either binary holds.
    ///
    /// A message, a magic number or the one call to an import comes from
    /// the source, and a function that alone holds it on both sides is one
    /// function, however its code changed. So is the one caller of a
    /// function already paired, as BinDiff's call graph propagation
    /// assumes where one caller is left, and the one function that calls
    /// a given set of paired functions. Such a pair is taken where its code scores
    /// [`LOWEST_UNIQUE_REFERENCE_SIMILARITY`] or more and the pairs it
    /// breaks share fewer such references: a pair by identical code, by
    /// identical shape or by name is never broken, and nor is one that
    /// scores [`CLOSE_SIMILARITY`] or more and more than the new pair. A
    /// constant can be a line number that a patch moved to the next
    /// function: libexpat's `storeEntityValue`, at 0.92 against itself, lost
    /// its partner to `appendAttributeValue` at 0.73 that way. Such a pair is still weak:
    /// [`Self::pair_by_layout`] undoes it where it breaks the order of the
    /// pairs around it.
    ///
    /// Measured over the backports built two ways, this paired 547 more
    /// right and 135 fewer wrong, and every fix now shows on a changed row,
    /// where 18 did not. Over the OpenWrt kernels it paired 704 more right
    /// and 575 fewer wrong.
    ///
    /// See RESEARCH.md, entry 13: BinDiff matches on string references,
    /// and Diaphora on a rare constant.
    fn pair_by_unique_references(&mut self) -> Repaired {
        let mut repaired = Repaired::Nothing;
        let partner: HashMap<usize, usize> =
            self.matched.iter().map(|pair| (pair.before, pair.after)).collect();
        let left_keys =
            unique_reference_holders(&self.left, &|callee| partner.get(&callee).copied());
        let right_keys = unique_reference_holders(&self.right, &|callee| {
            self.right_free.get(callee).is_some_and(|free| !free).then_some(callee)
        });
        let mut shared: HashMap<(usize, usize), usize> = HashMap::new();
        for (key, &x) in &left_keys {
            if let Some(&y) = right_keys.get(key) {
                *shared.entry((x, y)).or_default() += 1;
            }
        }
        let shared_by = |x: usize, y: usize| shared.get(&(x, y)).copied().unwrap_or(0);

        // (shared references, score, x, y): most shared first, then the
        // best code, then the index, so the order does not depend on the
        // map.
        let mut candidates: Vec<(usize, f64, usize, usize)> = shared
            .iter()
            .map(|(&(x, y), &count)| {
                (count, similarity_of_symbols(&self.left[x].symbols, &self.right[y].symbols), x, y)
            })
            .filter(|&(_, score, _, _)| score >= LOWEST_UNIQUE_REFERENCE_SIMILARITY)
            .collect();
        candidates.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| b.1.partial_cmp(&a.1).unwrap_or(core::cmp::Ordering::Equal))
                .then_with(|| a.2.cmp(&b.2))
                .then_with(|| a.3.cmp(&b.3))
        });

        for (count, score, x, y) in candidates {
            let pair_of_x = self.matched.iter().position(|pair| pair.before == x);
            let pair_of_y = self.matched.iter().position(|pair| pair.after == y);
            if pair_of_x.is_some() && pair_of_x == pair_of_y {
                continue;
            }
            let mut broken: Vec<usize> = [pair_of_x, pair_of_y].into_iter().flatten().collect();
            let outweighs = broken.iter().all(|&index| {
                let pair = &self.matched[index];
                !matches!(
                    pair.confidence,
                    Confidence::IdenticalCode | Confidence::IdenticalShape | Confidence::SameName
                ) && shared_by(pair.before, pair.after) < count
                    && (pair.score < CLOSE_SIMILARITY || score >= pair.score)
            });
            if !outweighs {
                continue;
            }
            // Highest first, so that removing one does not move the other.
            broken.sort_unstable_by(|a, b| b.cmp(a));
            for index in broken {
                let pair = self.matched.swap_remove(index);
                self.left_free[pair.before] = true;
                self.right_free[pair.after] = true;
            }
            self.take_pair(x, y, Confidence::SameReferences, score);
            repaired = Repaired::Some;
        }
        repaired
    }

    /// The functions of each side in address order, and the longest chain
    /// of pairs that keep that order on both sides.
    fn layout(&self) -> Layout {
        let order = |side: &[Prepared<'_>]| -> Vec<usize> {
            let mut order: Vec<usize> = (0..side.len()).collect();
            order.sort_by_key(|&index| side[index].function.address);
            order
        };
        let place_of = |order: &[usize]| -> Vec<usize> {
            let mut place = vec![0; order.len()];
            for (at, &index) in order.iter().enumerate() {
                place[index] = at;
            }
            place
        };
        let (left_order, right_order) = (order(&self.left), order(&self.right));
        let (left_place, right_place) = (place_of(&left_order), place_of(&right_order));

        let mut anchors: Vec<(usize, usize)> = self
            .matched
            .iter()
            .map(|pair| (left_place[pair.before], right_place[pair.after]))
            .collect();
        anchors.sort_unstable();
        let chain = longest_increasing_chain(&anchors);
        Layout { left_order, right_order, left_place, right_place, chain }
    }

    /// For each unpaired function, the unpaired function of the other side
    /// that sits in the same place, as two maps: first to second binary,
    /// and second to first.
    ///
    /// Where a gap between two pairs holds as many free functions on both
    /// sides, the first sits in the place of the first, and so on. Where
    /// the counts differ, a function went or came, and the gap aligns by
    /// the scores of its functions, in order, so that the sum of the scores
    /// is highest; a function that shares nothing with its partner in such
    /// an alignment has no place.
    ///
    /// Measured over the backports built two ways, 888 of these hints are
    /// right and 564 wrong. Of the 18 comparisons where no changed pair holds
    /// the fix, because it went and came as two functions, 13 name a
    /// function of the fix in its place. Zipping a gap with equal counts
    /// named 38 more right and 5 more wrong than aligning it by scores, and
    /// a floor on the scores of 0.1 to 0.3 lost more right than wrong. See
    /// RESEARCH.md, entry 7.
    fn same_places(&self) -> (HashMap<usize, usize>, HashMap<usize, usize>) {
        let mut places = (HashMap::new(), HashMap::new());
        let layout = self.layout();
        if layout.is_unanchored() {
            return places;
        }
        for (lefts, rights) in layout.gaps(&self.left_free, &self.right_free) {
            let cells = lefts.len().saturating_mul(rights.len());
            if cells == 0 || cells > MOST_PLACE_CELLS {
                continue;
            }
            let aligned = if lefts.len() == rights.len() {
                lefts.iter().copied().zip(rights.iter().copied()).collect()
            } else {
                let score = |x: usize, y: usize| {
                    similarity_of_symbols(
                        &self.left[lefts[x]].symbols,
                        &self.right[rights[y]].symbols,
                    )
                };
                align_by_scores(lefts.len(), rights.len(), score)
                    .into_iter()
                    .map(|(x, y)| (lefts[x], rights[y]))
                    .collect::<Vec<_>>()
            };
            for (x, y) in aligned {
                places.0.insert(x, y);
                places.1.insert(y, x);
            }
        }
        places
    }

    /// [`Self::reference_keys`], for every function.
    fn reference_keys_of_all(&self) -> (Vec<Vec<ReferenceKey>>, Vec<Vec<ReferenceKey>>) {
        self.reference_keys_where(Only::Any)
    }

    fn reference_keys_where(&self, only: Only) -> (Vec<Vec<ReferenceKey>>, Vec<Vec<ReferenceKey>>) {
        let partner: HashMap<usize, usize> =
            self.matched.iter().map(|pair| (pair.before, pair.after)).collect();
        let keys = |side: &[Prepared<'_>], free: &[bool], which: Side| -> Vec<Vec<ReferenceKey>> {
            side.iter()
                .enumerate()
                .map(|(index, prepared)| {
                    if only == Only::Free && !free[index] {
                        return Vec::new();
                    }
                    let mut keys: Vec<ReferenceKey> = prepared
                        .calls
                        .iter()
                        .filter_map(|callee| match callee {
                            Callee::Named(name) => Some(ReferenceKey::Named(name.clone())),
                            Callee::Function(callee) => match which {
                                Side::Before => partner.get(callee).copied(),
                                Side::After => (!self.right_free[*callee]).then_some(*callee),
                            }
                            .map(ReferenceKey::Paired),
                            Callee::Unknown => None,
                        })
                        .collect();
                    keys.extend(
                        prepared.texts.iter().map(|text| ReferenceKey::Text((*text).to_string())),
                    );
                    keys.sort_unstable();
                    keys
                })
                .collect()
        };
        (
            keys(&self.left, &self.left_free, Side::Before),
            keys(&self.right, &self.right_free, Side::After),
        )
    }

    /// Compare two functions as a pair.
    fn assess(&self, before: usize, after: usize, confidence: Confidence, score: f64) -> Match {
        let (left, right) = (&self.left[before], &self.right[after]);
        // The same bytes edit nothing. Most pairs of a release are such, and
        // normalizing their bodies again cost a quarter of a comparison.
        if left.function.code == right.function.code {
            return Match {
                before,
                after,
                confidence,
                score,
                changed: Changed::No,
                edits: Edits::default(),
                kinds: EditKinds::default(),
                rarity: 0.0,
            };
        }
        let (left_body, right_body) = (left.body(), right.body());
        let (edits, kinds) = count_edits(left_body, right_body);
        Match {
            before,
            after,
            confidence,
            score,
            changed: classify_change(left, right, left_body, right_body),
            edits,
            kinds,
            rarity: 0.0,
        }
    }

    /// The callees of each pair whose code agrees, so that its calls line up
    /// one for one, by the index of the pair.
    fn aligned_callees(&self) -> Vec<(usize, Vec<Callee>, Vec<Callee>)> {
        self.matched
            .iter()
            .enumerate()
            .filter(|(_, pair)| matches!(pair.changed, Changed::No | Changed::InDetail))
            .filter_map(|(index, pair)| {
                let left = self.left[pair.before].linked_calls();
                let right = self.right[pair.after].linked_calls();
                (left.len() == right.len()).then(|| (index, left.to_vec(), right.to_vec()))
            })
            .collect()
    }

    /// Pair the PLT stubs of the two binaries as two ordered lists.
    ///
    /// Every stub is the same code but for the slot it jumps through, and
    /// where no relocation names the slots, as in a raw image, nothing else
    /// tells them apart. The linker writes one stub for each import, in
    /// order, so an import added inserts a stub and moves every stub after
    /// it by one place. Measured on tinyxml2 for ARM as a raw image, the fix
    /// adds one, and `vsnprintf` then paired with the stub before its own.
    ///
    /// So the stubs are aligned in order, as a diff aligns lines. Each pair
    /// the alignment makes counts one, and each caller whose code agrees
    /// counts [`CALLER_WEIGHT`] more for the stubs its calls line up. Every
    /// place a gap can go keeps as many pairs, so a caller decides where the
    /// gap goes. It cannot pull a stub out of order, which would cost more
    /// pairs than it weighs: an edited caller calls a new stub, and that must
    /// not undo the order that shows the edit. A stub the alignment leaves
    /// out went or came.
    ///
    /// See RESEARCH.md, A5.
    fn align_stubs(&mut self) {
        /// What one caller weighs against one pair kept in order.
        const CALLER_WEIGHT: usize = 2;

        // A stub named for its callee pairs by that name, and one with no
        // partner of its name went or came, as a new import does.
        let use_names = self.options.use_names;
        let stubs = |side: &[Prepared<'_>]| -> Vec<usize> {
            (0..side.len())
                .filter(|&index| {
                    let function = side[index].function;
                    side[index].isa.arch().stub_slot(&function.code, function.address).is_some()
                        && (use_names == UseNames::No || function.name.is_empty())
                })
                .collect()
        };
        let (left, right) = (stubs(&self.left), stubs(&self.right));
        if left.is_empty() || right.is_empty() {
            return;
        }

        let mut voters: BTreeSet<(usize, usize, usize)> = BTreeSet::new();
        for (caller, calls_before, calls_after) in self.aligned_callees() {
            for pair in calls_before.iter().zip(&calls_after) {
                if let (Callee::Function(x), Callee::Function(y)) = pair {
                    voters.insert((*x, *y, caller));
                }
            }
        }
        let mut votes: HashMap<(usize, usize), usize> = HashMap::new();
        for &(x, y, _) in &voters {
            *votes.entry((x, y)).or_default() += 1;
        }
        let weight =
            |x: usize, y: usize| votes.get(&(x, y)).copied().unwrap_or(0) * CALLER_WEIGHT + 1;

        // The heaviest alignment that keeps both orders.
        let (rows, columns) = (left.len(), right.len());
        let mut best = vec![vec![0usize; columns + 1]; rows + 1];
        for row in 1..=rows {
            for column in 1..=columns {
                let paired = best[row - 1][column - 1] + weight(left[row - 1], right[column - 1]);
                best[row][column] = paired.max(best[row - 1][column]).max(best[row][column - 1]);
            }
        }
        let mut aligned = Vec::new();
        let (mut row, mut column) = (rows, columns);
        while row > 0 && column > 0 {
            let paired = best[row - 1][column - 1] + weight(left[row - 1], right[column - 1]);
            if best[row][column] == paired {
                aligned.push((left[row - 1], right[column - 1]));
                row -= 1;
                column -= 1;
            } else if best[row][column] == best[row - 1][column] {
                row -= 1;
            } else {
                column -= 1;
            }
        }

        // Replace every pair that holds a stub with the alignment.
        let is_stub_pair = |pair: &Match| {
            left.binary_search(&pair.before).is_ok() || right.binary_search(&pair.after).is_ok()
        };
        // A pair can hold a stub on one side only, so free both sides of it.
        let (dropped, kept) =
            core::mem::take(&mut self.matched).into_iter().partition(is_stub_pair);
        self.matched = kept;
        for pair in dropped {
            self.left_free[pair.before] = true;
            self.right_free[pair.after] = true;
        }
        for (x, y) in aligned.into_iter().rev() {
            if !self.left_free[x] || !self.right_free[y] {
                continue;
            }
            let score = similarity_of_symbols(&self.left[x].symbols, &self.right[y].symbols);
            self.take_pair(x, y, Confidence::SameCallers, score);
        }
    }

    /// Pair, or pair again, the functions the calls say are one.
    ///
    /// A small function has many twins, and similarity pairs them by chance:
    /// on the VR200 kernel, an eight-byte function paired by similarity with
    /// one of its twins while forty callers called another. Each call of a
    /// pair whose code agrees votes that its two callees are one function.
    /// Two pairs `x`–`y′` and `x′`–`y` swap to `x`–`y` and `x′`–`y′` when the
    /// votes for the swap outnumber those against it.
    ///
    /// Only pairings by similarity or by twin order swap, because a stronger
    /// reason outweighs a vote. A swap never leaves a function unpaired.
    /// Where one callee is unpaired, the weak pairing of the other moves to
    /// it, and where both are, they pair if they score at least
    /// [`LOWEST_JOINED_SIMILARITY`].
    ///
    /// A caller votes once for each pair of callees, however often it calls
    /// them, and a swap needs [`FEWEST_VOTERS`] callers for it. Otherwise one
    /// edited caller outvotes the rest and hides its own edit: the tinyxml2
    /// fix makes three calls to a new PLT stub, whose twins pair by order.
    /// Where similarity cannot choose, one caller is enough; see
    /// [`Self::is_near_tie`].
    ///
    /// See RESEARCH.md, A10.
    fn pair_by_callers(&mut self) {
        /// Each round moves a pairing that is off by one along a run of
        /// twins by one place: a new PLT stub puts every stub after it one
        /// place off. Rounds cost only the votes, so a long run can settle.
        const MOST_ROUNDS: usize = 4096;
        /// The fewest callers that must agree before a swap.
        const FEWEST_VOTERS: usize = 2;

        // Which callees a call reaches does not depend on the pairing, so the
        // votes are counted once. A swapped pair is a callee, and hardly
        // ever a caller whose code agrees, so its own vote stays as it was.
        let mut voters: BTreeSet<(usize, usize, usize)> = BTreeSet::new();
        for (caller, left, right) in self.aligned_callees() {
            for pair in left.iter().zip(&right) {
                if let (Callee::Function(x), Callee::Function(y)) = pair {
                    voters.insert((*x, *y, caller));
                }
            }
        }
        let mut votes: BTreeMap<(usize, usize), usize> = BTreeMap::new();
        for &(x, y, _) in &voters {
            *votes.entry((x, y)).or_default() += 1;
        }

        for _ in 0..MOST_ROUNDS {
            let vote = |x: usize, y: usize| votes.get(&(x, y)).copied().unwrap_or(0);

            let pair_of_before: HashMap<usize, usize> =
                self.matched.iter().enumerate().map(|(index, pair)| (pair.before, index)).collect();
            let pair_of_after: HashMap<usize, usize> =
                self.matched.iter().enumerate().map(|(index, pair)| (pair.after, index)).collect();
            let is_weak = |pair: &Match| {
                matches!(pair.confidence, Confidence::Similar | Confidence::TwinInOrder)
            };

            let mut touched = BTreeSet::new();
            let mut swaps = Vec::new();
            let mut moves = Vec::new();
            let mut joins = Vec::new();
            // The free functions a join or a move takes this round, so that
            // no two take the same one.
            let (mut claimed_before, mut claimed_after) = (BTreeSet::new(), BTreeSet::new());
            for (&(x, y), &for_swap) in &votes {
                // Both unpaired: a caller whose code agrees says they are
                // one function, which the fix rewrote past the threshold.
                // Measured on smallvec for ARM, the edited `insert_many`
                // for `u8` scored 0.62 against itself.
                let both_free = !pair_of_before.contains_key(&x)
                    && !pair_of_after.contains_key(&y)
                    && self.left_free[x]
                    && self.right_free[y];
                if both_free {
                    let score =
                        similarity_of_symbols(&self.left[x].symbols, &self.right[y].symbols);
                    if score >= LOWEST_JOINED_SIMILARITY
                        && !claimed_before.contains(&x)
                        && !claimed_after.contains(&y)
                    {
                        claimed_before.insert(x);
                        claimed_after.insert(y);
                        joins.push((x, y, score));
                    }
                    continue;
                }

                // One side unpaired: move the weak pairing of the other to
                // it, and free its old partner. Similarity pairs a template
                // instance with the wrong twin this way, as
                // `CreateUnlinkedNode<XMLElement, 60>` in tinyxml2 at -O3.
                let (paired, moved) = match (pair_of_before.get(&x), pair_of_after.get(&y)) {
                    (Some(&first), None) if self.right_free[y] && !claimed_after.contains(&y) => {
                        (first, vote(x, self.matched[first].after))
                    }
                    (None, Some(&second)) if self.left_free[x] && !claimed_before.contains(&x) => {
                        (second, vote(self.matched[second].before, y))
                    }
                    _ => (usize::MAX, usize::MAX),
                };
                if paired != usize::MAX
                    && !touched.contains(&paired)
                    && (for_swap >= FEWEST_VOTERS
                        || (for_swap > 0 && self.is_near_tie(&[&self.matched[paired]], &[(x, y)])))
                    && for_swap > moved
                    && is_weak(&self.matched[paired])
                {
                    touched.insert(paired);
                    claimed_before.insert(x);
                    claimed_after.insert(y);
                    moves.push((paired, x, y));
                    continue;
                }

                let (Some(&first), Some(&second)) = (pair_of_before.get(&x), pair_of_after.get(&y))
                else {
                    continue;
                };
                if first == second || touched.contains(&first) || touched.contains(&second) {
                    continue;
                }
                let (y_other, x_other) = (self.matched[first].after, self.matched[second].before);
                let enough_voters = for_swap >= FEWEST_VOTERS
                    || (for_swap > 0
                        && self.is_near_tie(
                            &[&self.matched[first], &self.matched[second]],
                            &[(x, y), (x_other, y_other)],
                        ));
                let wins = enough_voters
                    && for_swap + vote(x_other, y_other) > vote(x, y_other) + vote(x_other, y);
                if wins && is_weak(&self.matched[first]) && is_weak(&self.matched[second]) {
                    touched.extend([first, second]);
                    swaps.push((first, second));
                }
            }
            if swaps.is_empty() && moves.is_empty() && joins.is_empty() {
                break;
            }

            for (x, y, score) in joins {
                self.take_pair(x, y, Confidence::SameCallers, score);
            }

            for (index, x, y) in moves {
                let (old_before, old_after) =
                    (self.matched[index].before, self.matched[index].after);
                self.left_free[old_before] = true;
                self.right_free[old_after] = true;
                self.left_free[x] = false;
                self.right_free[y] = false;
                let score = similarity_of_symbols(&self.left[x].symbols, &self.right[y].symbols);
                self.matched[index] = self.assess(x, y, Confidence::SameCallers, score);
            }

            for (first, second) in swaps {
                let (x, y_other) = (self.matched[first].before, self.matched[first].after);
                let (x_other, y) = (self.matched[second].before, self.matched[second].after);
                for (index, (left, right)) in [(first, (x, y)), (second, (x_other, y_other))] {
                    let score =
                        similarity_of_symbols(&self.left[left].symbols, &self.right[right].symbols);
                    self.matched[index] = self.assess(left, right, Confidence::SameCallers, score);
                }
            }
        }
    }

    /// Report whether similarity cannot choose between the `current`
    /// pairings and the `proposed` ones, so that one caller may.
    ///
    /// Every current pairing must be by similarity, and the proposed ones
    /// must score within [`NEAR_TIE`] of them on average. Measured on
    /// smallvec built by Rust for MIPS at `-O2`, the edited `insert_many` for
    /// `u32` paired with the one for `u64` at 0.82 and 0.82, against 0.82 and
    /// 0.81 the right way, and one caller each called them. A pairing by
    /// twin order is left to `FEWEST_VOTERS`: twins score the same, so any
    /// one caller would win.
    fn is_near_tie(&self, current: &[&Match], proposed: &[(usize, usize)]) -> bool {
        /// How far below the current pairings the proposed ones may score,
        /// on average, and still count as a tie.
        const NEAR_TIE: f64 = 0.02;

        if !current.iter().all(|pair| pair.confidence == Confidence::Similar) {
            return false;
        }
        let current_score: f64 = current.iter().map(|pair| pair.score).sum();
        let proposed_score: f64 = proposed
            .iter()
            .map(|&(before, after)| {
                similarity_of_symbols(&self.left[before].symbols, &self.right[after].symbols)
            })
            .sum();
        proposed_score >= current_score - NEAR_TIE * current.len() as f64
    }

    /// Mark each pair whose code agrees but whose calls reach different
    /// functions.
    ///
    /// Run once every function has paired, because a callee is the same
    /// function on both sides exactly when the two pair. A pair whose code
    /// already differs keeps its verdict: its calls cannot be lined up one
    /// for one.
    ///
    /// See RESEARCH.md, A11.
    fn compare_callees(&mut self) {
        let partner_of_before: HashMap<usize, usize> =
            self.matched.iter().map(|pair| (pair.before, pair.after)).collect();
        let partner_of_after: HashMap<usize, usize> =
            self.matched.iter().map(|pair| (pair.after, pair.before)).collect();

        // A callee pair is different only when the matching says so: one of
        // them paired, and not with the other. A call that now reaches a new
        // function is a change, as the tinyxml2 fix calls a new PLT stub. A
        // callee the code or the linker does not name says nothing, and nor
        // do two that both paired with nothing. A call to code that
        // normalizes the same is the
        // same call, whichever twin the matching picked, if its constants
        // agree too. A PLT stub is the exception: every stub is the same code
        // but for the slot it jumps through, and the slot is the callee.
        let (left_side, right_side) = (&self.left, &self.right);
        let is_stub = |side: &Prepared<'_>| {
            side.isa.arch().stub_slot(&side.function.code, side.function.address).is_some()
        };
        let same_code = |left: usize, right: usize| {
            let (left, right) = (&left_side[left], &right_side[right]);
            if is_stub(left) || is_stub(right) {
                return false;
            }
            left.function.code == right.function.code
                || (left.ordered == right.ordered && same_detail(left.body(), right.body()))
        };
        //
        // A forwarder, whose whole body is one call or jump, is the
        // exception to the rule for two callees that paired with nothing:
        // what it reaches is all it does. zlib 1.2.12 turned `crc32_combine`
        // from a jump to `crc32_combine_` into one to `crc32_combine64`, and
        // neither callee paired. In larger code, two such callees are most
        // often one function that changed too much to pair: measured on the
        // OpenWrt kernels, counting them as a change reported hundreds more
        // functions.
        let differ = |left: &Callee, right: &Callee, unpaired: Unpaired| match (left, right) {
            (Callee::Named(left), Callee::Named(right)) => left != right,
            (Callee::Function(left), Callee::Function(right)) => {
                let crossed = match (partner_of_before.get(left), partner_of_after.get(right)) {
                    (Some(partner), _) => partner != right,
                    (None, Some(partner)) => partner != left,
                    (None, None) => unpaired == Unpaired::Differ,
                };
                crossed && !same_code(*left, *right)
            }
            _ => false,
        };

        for pair in &mut self.matched {
            if !matches!(pair.changed, Changed::No | Changed::InDetail) {
                continue;
            }
            let forwards = |side: &Prepared<'_>| side.ordered.len() == 1;
            let unpaired = if forwards(&left_side[pair.before]) && forwards(&right_side[pair.after])
            {
                Unpaired::Differ
            } else {
                Unpaired::SayNothing
            };
            let (left, right) =
                (left_side[pair.before].linked_calls(), right_side[pair.after].linked_calls());
            if left.len() != right.len() {
                continue;
            }
            let changed = left
                .iter()
                .zip(right)
                .filter(|(left, right)| differ(left, right, unpaired))
                .count();
            if changed > 0 {
                pair.changed = Changed::Yes;
                pair.kinds.callees += changed;
            }
        }
    }

    /// Mark each pair whose code agrees but whose texts differ.
    ///
    /// A fix can change only a format, as `"%s"` to `"%.*s"`, and leave the
    /// code around it as it was. A changed text counts as a changed value.
    ///
    /// A short text counts only as [`short_texts_changed`] says.
    ///
    /// See RESEARCH.md, A11.
    fn compare_texts(&mut self) {
        for pair in &mut self.matched {
            if !matches!(pair.changed, Changed::No | Changed::Reordered | Changed::InDetail) {
                continue;
            }
            let (left, right) = (&self.left[pair.before], &self.right[pair.after]);
            let differ = texts_that_differ(&long_texts(&left.texts), &long_texts(&right.texts))
                + short_texts_changed(
                    (&left.texts, &left.sure_texts),
                    (&right.texts, &right.sure_texts),
                );
            if differ > 0 {
                pair.changed = Changed::InDetail;
                pair.kinds.texts += differ;
            }
        }
    }

    /// Weigh what each changed pair added by how rare it is: see
    /// [`Match::rarity`].
    fn weigh_additions(&mut self) {
        // A pair that changed only a value adds no instruction, and counting
        // it would make every addition look rarer than it is.
        let is_edit = |pair: &Match| {
            !matches!(pair.changed, Changed::No | Changed::Data) && pair.edits.total() > 0
        };
        let added: Vec<Vec<Symbol>> = self
            .matched
            .iter()
            .map(|pair| {
                if !is_edit(pair) {
                    return Vec::new();
                }
                sorted_only_in(&self.right[pair.after].symbols, &self.left[pair.before].symbols)
            })
            .collect();
        let edited = self.matched.iter().filter(|pair| is_edit(pair)).count();

        // In how many changed pairs each instruction was added.
        let mut pairs_adding: HashMap<Symbol, usize> = HashMap::new();
        for symbols in &added {
            let mut distinct = symbols.clone();
            distinct.dedup();
            for symbol in distinct {
                *pairs_adding.entry(symbol).or_default() += 1;
            }
        }
        let rarity_of =
            |symbol: Symbol| ((edited as f64 + 1.0) / (pairs_adding[&symbol] as f64 + 1.0)).ln();
        for (pair, symbols) in self.matched.iter_mut().zip(&added) {
            if is_edit(pair) {
                let weighted: f64 = symbols
                    .chunk_by(|a, b| a == b)
                    .map(|run| rarity_of(run[0]) * saturated(run.len()))
                    .sum();
                pair.rarity = pair.edits.added as f64 + weighted;
            }
        }
    }

    /// Sort the pairs and collect what stayed unmatched.
    fn finish(mut self, progress: &dyn Progress) -> Diff {
        self.weigh_additions();

        // Strongest reason first, then highest score, so the rows a reader
        // should trust sit at the top of a report.
        self.matched.sort_by(|a, b| {
            a.confidence
                .cmp(&b.confidence)
                .then_with(|| b.score.partial_cmp(&a.score).unwrap_or(core::cmp::Ordering::Equal))
        });

        let unpaired = |free: &[bool]| -> Vec<usize> {
            free.iter().enumerate().filter(|(_, free)| **free).map(|(index, _)| index).collect()
        };

        let removed = unpaired(&self.left_free);
        let added = unpaired(&self.right_free);

        // Each unmatched function looks for its closest candidate on the other
        // side. The two passes together score every unmatched function against
        // every one on the far side, so the phase counts both.
        progress.start(Phase::NearMisses, removed.len() + added.len());
        let (left_places, right_places) = self.same_places();
        let near_misses =
            self.near_misses(&removed, &self.left, &added, &self.right, &left_places, progress);
        let added_near_misses =
            self.near_misses(&added, &self.right, &removed, &self.left, &right_places, progress);
        progress.finish();

        let removed_contents = removed.iter().map(|&index| self.left[index].contents).collect();
        let added_contents = added.iter().map(|&index| self.right[index].contents).collect();

        Diff {
            removed,
            added,
            removed_contents,
            added_contents,
            near_misses,
            added_near_misses,
            matched: self.matched,
        }
    }

    /// Find the closest candidate for each function that stayed unmatched.
    ///
    /// This compares only the functions no stage could place, against only the
    /// functions still free to take. Both sets are small by the time the
    /// cascade is done, so the cost is a fraction of the matching pass that
    /// preceded it.
    ///
    /// The direction is a parameter, so one body serves both removed against
    /// added and added against removed. Each `NearMiss` reads its `unmatched`
    /// index in `theirs` and its `best` index in `others`.
    ///
    /// See RESEARCH.md, A14.
    fn near_misses(
        &self,
        unmatched: &[usize],
        theirs: &[Prepared<'_>],
        others: &[usize],
        others_side: &[Prepared<'_>],
        places: &HashMap<usize, usize>,
        progress: &dyn Progress,
    ) -> Vec<NearMiss> {
        // Read-only, like the scoring stage, and the same shape of work. The
        // output keeps the order of `unmatched`, which `Diff` documents.
        unmatched
            .par_iter()
            .map(|one| {
                progress.advance(1);
                let best = others
                    .iter()
                    .map(|other| {
                        (
                            similarity_of_symbols(
                                &theirs[*one].symbols,
                                &others_side[*other].symbols,
                            ),
                            *other,
                        )
                    })
                    .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(core::cmp::Ordering::Equal));

                let in_place = places.get(one).copied();
                match best {
                    Some((score, other)) => {
                        NearMiss { unmatched: *one, best: Some(other), score, in_place }
                    }
                    None => NearMiss { unmatched: *one, best: None, score: 0.0, in_place },
                }
            })
            .collect()
    }
}

/// Report whether two bodies differ only in choices the compiler makes freely.
///
/// Both sides already normalize alike, so this decides whether the bytes
/// behind them differ for a reason a reader should hear about. It compares the
/// instructions as printed, and allows two kinds of difference that carry no
/// meaning: which register holds a value, and where a branch goes.
///
/// A branch target moves whenever anything before it changes size. In a whole
/// kernel almost every function calls something that moved, so counting a
/// moved target as an edit reports the entire image as changed. Measured on
/// a whole-kernel pair, 6899 functions of otherwise identical
/// shape differ in nothing but their targets.
///
/// A word of data among the instructions still fails this check, which is the
/// point. It decodes as some instruction, and when its bits change it usually
/// becomes a *different* instruction rather than the same one with another
/// register or target.
fn differs_only_in_free_choices(before: &Prepared<'_>, after: &Prepared<'_>) -> bool {
    // Decoded rather than stored, and walked in step rather than collected:
    // a function of twenty thousand instructions would otherwise hold two
    // heap strings apiece on both sides at once, which is what exhausted
    // memory on a whole kernel.
    let before_arch = before.isa.arch();
    let after_arch = after.isa.arch();
    let (before_insns, _) = decode_all(before_arch, &before.function.code, before.function.address);
    let (after_insns, _) = decode_all(after_arch, &after.function.code, after.function.address);
    let before_kinds =
        before_arch.constant_kinds(&before.function.code, &before_insns, before.addresses);
    let after_kinds =
        after_arch.constant_kinds(&after.function.code, &after_insns, after.addresses);

    // Padding does nothing, and alignment puts it where it likes: GCC pads
    // a pool of doubles to eight bytes, so one more `nop` came before it.
    let work =
        |arch: &dyn Arch, insns: &[Insn], kinds: &[ConstantKind]| -> Vec<(Insn, ConstantKind)> {
            insns
                .iter()
                .zip(kinds)
                .filter(|(insn, _)| !arch.is_padding(insn))
                .map(|(insn, kind)| (insn.clone(), *kind))
                .collect()
        };
    let before_work = work(before_arch, &before_insns, &before_kinds);
    let after_work = work(after_arch, &after_insns, &after_kinds);
    if before_work.len() != after_work.len() {
        return false;
    }

    before_work.iter().zip(&after_work).all(|((left, left_kind), (right, right_kind))| {
        let kinds = (left_kind, right_kind);
        // A stored address on both sides is data the linker chose, so it may
        // hold anything and decode as anything.
        if kinds == (&ConstantKind::StoredAddress, &ConstantKind::StoredAddress) {
            return true;
        }
        // Compare the operation the way the normalizer does, so a condition
        // code the compiler chose differently, as `movwlt` against
        // `movwlo`, stays the free choice it is rather than reading as an
        // edit.
        if before_arch.operation_name(left) != after_arch.operation_name(right) {
            return false;
        }
        // What no lift reads is compared by its bytes.
        let (Some(left_lift), Some(right_lift)) = (before_arch.lift(left), after_arch.lift(right))
        else {
            return left.bytes() == right.bytes();
        };
        let (mut left_operands, mut right_operands) =
            (left_lift.operands.as_slice(), right_lift.operands.as_slice());
        // A load from a pool reads at a distance that says only where the
        // pool sits, so what comes before the reference is all to compare.
        if before_arch.data_among_code() == DataAmongCode::LiteralPools
            && let (Some(left_at), Some(right_at)) =
                (pool_reference(left_operands), pool_reference(right_operands))
        {
            (left_operands, right_operands) =
                (&left_operands[..left_at], &right_operands[..right_at]);
        }
        operands_are_interchangeable(
            left_operands,
            right_operands,
            // A moved target is a free choice only on an instruction that
            // truly branches. Both sides agree on the operation by now, so
            // either one answers.
            TargetMoves::from(transfers_control(left.kind) && transfers_control(right.kind)),
            AddressMoves::from(kinds),
        )
    })
}

/// Where the reference to memory at a distance from the program counter
/// sits among `operands`, as a load from a literal pool makes.
fn pool_reference(operands: &[il::Operand]) -> Option<usize> {
    operands.iter().position(|operand| {
        matches!(operand, il::Operand::Memory { base: Some(il::Reg::ProgramCounter), .. })
    })
}

/// Whether a differing constant counts as a free choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddressMoves {
    /// The constant is part of an address on both sides, so the linker chose
    /// it, not the source.
    Freely,
    /// The constant is a value on at least one side.
    Never,
}

impl From<(&ConstantKind, &ConstantKind)> for AddressMoves {
    fn from(kinds: (&ConstantKind, &ConstantKind)) -> Self {
        match kinds {
            (ConstantKind::Address, ConstantKind::Address) => Self::Freely,
            (_, _) => Self::Never,
        }
    }
}

/// Whether a differing branch target counts as a free choice.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetMoves {
    /// The instruction branches, so a moved target means nothing.
    Freely,
    /// The instruction does not branch, so a `$...` operand is data.
    Never,
}

impl From<bool> for TargetMoves {
    fn from(transfers_control: bool) -> Self {
        if transfers_control { Self::Freely } else { Self::Never }
    }
}

/// Compare two operand lists, allowing the differences that carry no meaning.
///
/// A register is a free choice, but not where it is the base of an access:
/// an address may move, but not the register it is read through. A shift
/// is no free choice either: a word of data that decodes as `eoreq r0, fp,
/// r8, lsr 17` changed when its shift did.
fn operands_are_interchangeable(
    left: &[il::Operand],
    right: &[il::Operand],
    targets: TargetMoves,
    addresses: AddressMoves,
) -> bool {
    use il::Operand::{Const, Memory, Reg, RegisterList, Shifted, Target, Zero};
    let moves = addresses == AddressMoves::Freely;
    left.len() == right.len()
        && left.iter().zip(right).all(|(a, b)| {
            a == b
                || match (a, b) {
                    (Reg(_) | Zero, Reg(_) | Zero) => true,
                    (
                        Shifted { shift: left_shift, amount: left_amount, .. },
                        Shifted { shift: right_shift, amount: right_amount, .. },
                    ) => left_shift == right_shift && left_amount == right_amount,
                    // Which registers a `push` saves is the allocator's
                    // choice, but not whether a `pop` loads the program
                    // counter, as that returns.
                    (RegisterList(left_list), RegisterList(right_list)) => {
                        left_list.len() == right_list.len()
                            && special_registers(*left_list) == special_registers(*right_list)
                    }
                    (Target(_), Target(_)) => targets == TargetMoves::Freely || moves,
                    (Const(_), Const(_)) => moves,
                    // The offset an address adds to its base, as A64 adds
                    // the part of an address in a page: `[x22, #0x608]`.
                    (
                        Memory { base: left_base, index: left_index, update: left_update, .. },
                        Memory {
                            base: right_base, index: right_index, update: right_update, ..
                        },
                    ) => {
                        moves
                            && left_base == right_base
                            && left_index == right_index
                            && left_update == right_update
                    }
                    _ => false,
                }
        })
}

/// How two instructions differ, for a diff to show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Difference {
    /// Only in what the compiler or the linker chose freely: a register, a
    /// branch target, or where a literal pool sits.
    FreeChoices,
    /// In a constant or the offset of an access too, but not in shape: the
    /// same instruction with another value.
    Values,
    /// In the operation or the shape of its operands: other work.
    Shape,
}

/// Whether the offset of a slot of the frame is a free choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameSlots {
    /// A slot moves when the frame grows, which the compiler decides, as
    /// the IL view reads it.
    Move,
    /// A slot is where the instruction prints it, as the assembly view
    /// reads it.
    Stay,
}

/// How `before` differs from `after`, read from their lifts.
///
/// What no lift reads differs in shape unless its bytes agree.
fn difference(
    before_arch: &dyn Arch,
    before: &Insn,
    after_arch: &dyn Arch,
    after: &Insn,
    frame_slots: FrameSlots,
) -> Difference {
    if before_arch.operation_name(before) != after_arch.operation_name(after) {
        return Difference::Shape;
    }
    let (Some(before_lift), Some(after_lift)) = (before_arch.lift(before), after_arch.lift(after))
    else {
        return if before.bytes() == after.bytes() {
            Difference::FreeChoices
        } else {
            Difference::Shape
        };
    };
    let without_frame_offsets = |arch: &dyn Arch, operands: &[il::Operand]| -> Vec<il::Operand> {
        operands
            .iter()
            .map(|operand| match *operand {
                il::Operand::Memory { base: Some(base), index, update, .. }
                    if frame_slots == FrameSlots::Move && arch.is_frame_register(base) =>
                {
                    il::Operand::Memory { base: Some(base), offset: None, index, update }
                }
                other => other,
            })
            .collect()
    };
    let before_operands = without_frame_offsets(before_arch, &before_lift.operands);
    let after_operands = without_frame_offsets(after_arch, &after_lift.operands);
    let (before_operands, after_operands) = (&before_operands[..], &after_operands[..]);
    // The distance to a literal pool says only where the pool sits.
    let free = match (pool_reference(before_operands), pool_reference(after_operands)) {
        (Some(before_at), Some(after_at)) => {
            (&before_operands[..before_at], &after_operands[..after_at])
        }
        _ => (before_operands, after_operands),
    };
    if operands_are_interchangeable(free.0, free.1, TargetMoves::Freely, AddressMoves::Never) {
        Difference::FreeChoices
    } else if operands_are_interchangeable(
        before_operands,
        after_operands,
        TargetMoves::Freely,
        AddressMoves::Freely,
    ) {
        Difference::Values
    } else {
        Difference::Shape
    }
}

/// The registers in `list` that are no general register.
fn special_registers(list: il::RegSet) -> il::RegSet {
    list.iter().filter(|reg| !matches!(reg, il::Reg::General(_))).collect()
}

/// Work out whether a matched pair differs.
///
/// The order of these checks runs from cheapest and most certain to least.
///
/// See RESEARCH.md, A12.
fn classify_change(
    before: &Prepared<'_>,
    after: &Prepared<'_>,
    before_body: &[NormInsn],
    after_body: &[NormInsn],
) -> Changed {
    if before.function.code == after.function.code {
        return Changed::No;
    }

    // Data decodes as nonsense instructions, so comparing them says nothing.
    // The bytes differ, and that is all that can be said.
    if before.contents == Contents::Data || after.contents == Contents::Data {
        return Changed::Data;
    }

    if before_body == after_body {
        if !same_detail(before_body, after_body) {
            return Changed::InDetail;
        }

        // The instructions and their constants agree, yet the bytes do not.
        // Two very different things look like this:
        //
        // * A register or a branch address changed, which normalizing hides
        //   on purpose because a compiler picks those freely.
        // * A word of **data** changed. Data stored among instructions
        //   decodes as one, and normalizing then buckets its operands and
        //   loses the difference. Measured on a vendor kernel image, the
        //   stored kernel size `0x2b08a8` decoded as `eoreq r0, fp, r8, lsr
        //   17` and its change to `0x2b3c48` vanished entirely.
        //
        // Saying "unchanged" about bytes that differ is the one answer this
        // tool must never give, so the second case is reported.
        return if differs_only_in_free_choices(before, after) {
            Changed::No
        } else {
            Changed::InDetail
        };
    }

    // The instructions differ in position. They may still be the same
    // instructions, moved, which the sorted symbols already answer: a symbol
    // stands for one distinct normalized instruction, so two functions hold
    // the same multiset exactly when their sorted symbols agree. Comparing
    // those rather than sorting two copies of the instructions keeps a
    // twenty-thousand-instruction function from allocating twice its own size
    // here, which is what exhausted memory on a whole kernel.
    if before.symbols == after.symbols {
        return Changed::Reordered;
    }

    if differs_only_where_unreadable(before_body, after_body) {
        Changed::Unreadable
    } else {
        Changed::Yes
    }
}

/// Report whether every difference sits in bytes the decoder cannot read.
///
/// Such a difference is real — the bytes differ — but the tool cannot say
/// whether it edited an instruction or a word of data stored among the code.
/// Separating it from a readable edit lets a reader spend attention where the
/// tool has something to show.
///
/// Bodies of different length never qualify. An edit that added or removed an
/// instruction changed the code, whatever else it touched.
fn differs_only_where_unreadable(before: &[NormInsn], after: &[NormInsn]) -> bool {
    if before.len() != after.len() {
        return false;
    }

    let mut differs = false;
    for (left, right) in before.iter().zip(after) {
        if left == right {
            continue;
        }
        differs = true;
        if left.flow != FlowShape::Opaque && right.flow != FlowShape::Opaque {
            return false;
        }
    }

    differs
}

/// Count how many instructions an edit added, removed and rewrote.
///
/// The two bodies are aligned with the same longest-common-subsequence walk
/// that [`instruction_diff`] uses, so an instruction inserted near the top
/// costs one addition rather than making every instruction after it look
/// rewritten.
///
/// An instruction counts as rewritten when the alignment dropped it from both
/// sides, such as an `add` that became a `sub`. Those arrive as a removal next
/// to an addition and are folded back into one rewrite, the same way
/// [`lines_from_alignment`] folds them for display. What is left on one
/// side alone is a true addition or removal.
///
/// A pair the alignment kept is not a rewrite even when its constants differ.
/// Normalizing hides a constant on purpose, and [`Changed::InDetail`] already
/// reports that case; counting it here as well would say a threshold that went
/// from 100 to 50 rewrote an instruction, when the code around it is
/// untouched. A reader sorting by this count wants the functions whose
/// instructions moved.
///
/// A pair too large for the table aligns by anchors: see [`align`].
///
/// See RESEARCH.md, A12 and A13.
fn count_edits(left: &[NormInsn], right: &[NormInsn]) -> (Edits, EditKinds) {
    let mut edits = Edits::default();
    let mut kinds = EditKinds::default();
    // Instructions removed since the last kept one, still free to pair with an
    // addition. The alignment emits a run of removals before the additions that
    // replace them, so the two need not be strictly adjacent. Their indexes are
    // kept so that an unpaired one can still be classified.
    let mut unpaired_removals: Vec<usize> = Vec::new();

    let (mut i, mut j) = (0, 0);
    for step in align(left, right) {
        match step {
            Step::Both => {
                // A kept pair agrees in shape, so only its constants can
                // differ. That is a change in value, not in instructions.
                if left[i].differs_in_detail(&right[j]) {
                    kinds.add(EditKind::Constant);
                }
                edits.removed += unpaired_removals.len();
                for index in unpaired_removals.drain(..) {
                    kinds.add(kind_of(&left[index]));
                }
                i += 1;
                j += 1;
            }
            Step::Left => {
                unpaired_removals.push(i);
                i += 1;
            }
            Step::Right => {
                // A removal waiting next to this addition means one instruction
                // took another's place, which is a rewrite rather than a pair
                // of length changes. The later build's instruction names the
                // kind, because that is the code the reader now has.
                if unpaired_removals.pop().is_some() {
                    edits.edited += 1;
                } else {
                    edits.added += 1;
                }
                kinds.add(kind_of(&right[j]));
                j += 1;
            }
        }
    }

    edits.removed += unpaired_removals.len();
    for index in unpaired_removals {
        kinds.add(kind_of(&left[index]));
    }

    (edits, kinds)
}

impl Cascade<'_> {
    /// Stage one: identical machine code.
    ///
    /// The strongest evidence there is, and the cheapest to find. A function
    /// that was not touched and did not move lands here.
    ///
    /// See RESEARCH.md, A1.
    fn match_identical_code(&mut self, progress: &dyn Progress) {
        progress.start(Phase::IdenticalCode, self.left.len());
        let mut by_code: HashMap<&[u8], Vec<usize>> = HashMap::new();
        for (index, prepared) in self.right.iter().enumerate() {
            by_code.entry(prepared.function.code.as_slice()).or_default().push(index);
        }
        let mut twins_of: HashMap<&[u8], Vec<usize>> = HashMap::new();
        for (index, prepared) in self.left.iter().enumerate() {
            twins_of.entry(prepared.function.code.as_slice()).or_default().push(index);
        }

        // Where names are known, a function named on both sides is its own
        // partner's, as in the shape stage.
        let left_names: HashSet<&str> = match self.options.use_names {
            UseNames::Yes => {
                self.left.iter().map(|prepared| prepared.function.name.as_str()).collect()
            }
            UseNames::No => HashSet::new(),
        };

        let mut pairs = Vec::new();
        for (index, prepared) in self.left.iter().enumerate() {
            progress.advance(1);
            let Some(candidates) = by_code.get(prepared.function.code.as_slice()) else { continue };
            // Code that holds a distance, as a T32 range extension thunk
            // does, reaches another target from another address. So bytes
            // alike are one function only where what they reach is alike
            // too: LLD's thunks for `gzclose_r` and `gzclose_w` in zlib were
            // byte for byte the same across two builds.
            let name = prepared.function.name.as_str();
            let referents = prepared.referents();
            let free: Vec<usize> = candidates
                .iter()
                .copied()
                .filter(|&other| self.right_free[other])
                .filter(|&other| {
                    let other_name = self.right[other].function.name.as_str();
                    other_name == name || other_name.is_empty() || !left_names.contains(other_name)
                })
                .collect();
            // What the twins refer to decides only where no twin on this side
            // refers to the same, as in the shape stage.
            let shared = twins_of[prepared.function.code.as_slice()].iter().any(|&other| {
                other != index && self.left_free[other] && self.left[other].referents() == referents
            });
            let free: Vec<usize> = match shared {
                true => free,
                false => free
                    .into_iter()
                    .filter(|&other| self.right[other].referents() == referents)
                    .collect(),
            };
            // Only pair when the answer is unambiguous. Several functions can
            // share a body, and guessing between them helps nobody.
            if let [only] = free[..] {
                pairs.push((index, only));
            }
        }

        for (index, other) in pairs {
            if self.left_free[index] && self.right_free[other] {
                self.take_pair(index, other, Confidence::IdenticalCode, 1.0);
            }
        }
        progress.finish();
    }

    /// Stage two: identical normalized instructions.
    ///
    /// This is the stage that survives recompilation. Two builds of one
    /// function differ in register choice and branch addresses, which
    /// normalizing removes, so what remains agrees exactly.
    ///
    /// See RESEARCH.md, A2.
    fn match_identical_shape(&mut self, progress: &dyn Progress) {
        progress.start(Phase::IdenticalShape, self.left.len());
        // Where names are known, a function named on both sides is its own
        // partner's, so no other function takes it by shape. Measured on
        // zlib for ARM, `crc32_combine`, one tail jump, took `gzseek`, which
        // is one too.
        let left_names: HashSet<&str> = match self.options.use_names {
            UseNames::Yes => {
                self.left.iter().map(|prepared| prepared.function.name.as_str()).collect()
            }
            UseNames::No => HashSet::new(),
        };
        for index in 0..self.left.len() {
            progress.advance(1);
            // An empty body carries no evidence, so pairing on it would be a
            // guess dressed up as a certainty.
            if !self.left_free[index] || self.left[index].is_empty() {
                continue;
            }

            let mut candidates: Vec<usize> = (0..self.right.len())
                .filter(|other| {
                    self.right_free[*other]
                        && self.left[index].ordered == self.right[*other].ordered
                })
                .collect();
            let name = self.left[index].function.name.as_str();
            candidates.retain(|&other| {
                let other_name = self.right[other].function.name.as_str();
                other_name == name || other_name.is_empty() || !left_names.contains(other_name)
            });
            // Where names are known, the twin of the same name is the one.
            // Measured on expat for ARM, `big2_charRefNumber` otherwise
            // paired with `little2_charRefNumber` at 1.00.
            if candidates.len() > 1 && self.options.use_names == UseNames::Yes {
                let name = &self.left[index].function.name;
                let named: Vec<usize> = candidates
                    .iter()
                    .copied()
                    .filter(|&other| !name.is_empty() && self.right[other].function.name == *name)
                    .collect();
                if named.len() == 1 {
                    candidates = named;
                }
            }
            // Twins that refer to different things are told apart, but only
            // where no twin on this side refers to the same. Otherwise what
            // they refer to cannot tell them apart, and a text read by chance
            // on the other side would decide: expat for ARM points into a
            // table of short strings at an offset that changes each release.
            if candidates.len() > 1 {
                let referents = self.left[index].referents();
                let shared = (0..self.left.len()).any(|other| {
                    other != index
                        && self.left_free[other]
                        && self.left[other].ordered == self.left[index].ordered
                        && self.left[other].referents() == referents
                });
                // A twin whose texts were edited agrees with none, and then
                // they say nothing.
                let agreeing: Vec<usize> = candidates
                    .iter()
                    .copied()
                    .filter(|&other| self.right[other].referents() == referents)
                    .collect();
                if !shared && !agreeing.is_empty() {
                    candidates = agreeing;
                }
            }

            if let [only] = candidates[..] {
                self.take_pair(index, only, Confidence::IdenticalShape, 1.0);
            }
        }
        progress.finish();
    }

    /// Stage three and a half: twins, in the order they sit.
    ///
    /// Several functions can share one normalized body: small wrappers that
    /// differ only in the function they call, such as Lua's `math_sin` and
    /// `math_sinh`. The shape stage cannot choose between them, and without
    /// names they would all read as removed and added. Measured on Lua built
    /// as a stripped shared library, six such wrappers did.
    ///
    /// A linker keeps the functions of one object in source order, so when
    /// both sides hold the same number of free functions of one shape, the
    /// first pairs with the first, and so on. A group of unequal size is left
    /// alone, because then an order is no evidence of which pairs with which.
    ///
    /// See RESEARCH.md, A4.
    fn match_twins_in_order(&mut self) {
        // A group holds one shape that calls the same named functions: order
        // is no evidence across compilers, and GCC places functions in
        // another order than clang does. Texts do not split a group, because
        // a release edits messages, and a group of unequal sides pairs none.
        type Group<'a> = (&'a [Symbol], Vec<&'a str>);
        let mut groups: HashMap<Group<'_>, (Vec<usize>, Vec<usize>)> = HashMap::new();
        for (index, prepared) in self.left.iter().enumerate() {
            if self.left_free[index] && !prepared.is_empty() {
                let key = (prepared.ordered.as_slice(), prepared.named_calls());
                groups.entry(key).or_default().0.push(index);
            }
        }
        for (index, prepared) in self.right.iter().enumerate() {
            if self.right_free[index]
                && let Some((_, right)) =
                    groups.get_mut(&(prepared.ordered.as_slice(), prepared.named_calls()))
            {
                right.push(index);
            }
        }

        let mut pairs: Vec<(usize, usize)> = Vec::new();
        for (mut left, mut right) in groups.into_values() {
            if left.len() < 2 || left.len() != right.len() {
                continue;
            }
            left.sort_by_key(|&index| self.left[index].function.address);
            right.sort_by_key(|&index| self.right[index].function.address);
            pairs.extend(left.into_iter().zip(right));
        }

        // Pairing in a fixed order keeps the result independent of the order
        // the map yields its groups in.
        pairs.sort_unstable();
        for (before, after) in pairs {
            self.take_pair(before, after, Confidence::TwinInOrder, 1.0);
        }
    }

    /// Stage three: the same symbol name.
    ///
    /// Weaker than it looks. A name is reliable when it is present, but a
    /// stripped binary has none, and a renamed function keeps its behavior. It
    /// runs after the two code-based stages so that evidence from the code
    /// always wins.
    ///
    /// See RESEARCH.md, A3.
    fn match_by_name(&mut self, progress: &dyn Progress) {
        progress.start(Phase::Names, self.left.len());
        let mut by_name: HashMap<String, usize> = HashMap::new();
        for (index, prepared) in self.right.iter().enumerate() {
            if self.right_free[index] && !prepared.function.name.is_empty() {
                by_name.insert(prepared.function.name.clone(), index);
            }
        }

        for index in 0..self.left.len() {
            progress.advance(1);
            if !self.left_free[index] || self.left[index].function.name.is_empty() {
                continue;
            }
            let Some(&other) = by_name.get(&self.left[index].function.name) else { continue };
            if !self.right_free[other] {
                continue;
            }

            let score =
                similarity_of_symbols(&self.left[index].symbols, &self.right[other].symbols);
            self.take_pair(index, other, Confidence::SameName, score);
        }
        progress.finish();
    }
}

/// Stage four: the best remaining pair, above the threshold.
///
/// This stage compares every remaining pair, so it is the expensive one. It
/// runs last, on the few functions the cheaper stages could not place.
///
/// Pairs are taken best first, rather than in the order the functions appear.
/// Taking them in order would let a mediocre pair claim a function that a
/// later, better pair needed.
///
/// A pair is not taken where either function has a free rival that ranks
/// within [`RIVAL_MARGIN`] of it: the code cannot choose between the two,
/// and a later stage, by place, references or callers, can. A kernel holds
/// many small functions alike in shape, as `return 2;`, and best first
/// paired them by index.
impl Cascade<'_> {
    /// See RESEARCH.md, A7, and entry 14 (the ratio test).
    fn match_by_similarity(&mut self, progress: &dyn Progress) {
        // Only the functions still free reach the inner loop, so counting them
        // gives a total the bar can actually reach.
        let remaining = self.left_free.iter().filter(|free| **free).count();
        progress.start(Phase::Similarity, remaining);

        // Scoring only reads, so the rows run in parallel. Each row keeps its
        // own results, and the sort below decides the order, so the answer does
        // not depend on the order the rows finished in.
        let threshold = self.options.threshold;
        let (left_calls, right_calls) = self.reference_keys();
        let candidates: Vec<(f64, usize, usize)> = (0..self.left.len())
            .into_par_iter()
            .filter(|index| self.left_free[*index])
            .map(|index| {
                progress.advance(1);
                if self.left[index].is_empty() {
                    return Vec::new();
                }

                let mut best: Vec<(f64, usize, usize)> = Vec::new();
                for other in 0..self.right.len() {
                    if !self.right_free[other] || self.right[other].is_empty() {
                        continue;
                    }
                    let (left, right) = (&self.left[index], &self.right[other]);
                    let score = similarity_of_symbols(&left.symbols, &right.symbols);
                    let flows_alike = || {
                        score >= FLOW_RESCUE.code
                            && similarity_of_symbols(&left.flow, &right.flow) >= FLOW_RESCUE.flow
                    };
                    if score >= threshold || flows_alike() {
                        best.push((score, index, other));
                        keep_best_candidates(&mut best);
                    }
                }
                best
            })
            .flatten()
            .collect();

        // Best first. Ties break on index so the answer does not depend on
        // the order two equal scores happened to be found in.
        let rank = |&(score, index, other): &(f64, usize, usize)| {
            let (left, right) = (&self.left[index], &self.right[other]);
            score
                + REFERENCE_WEIGHT * reference_agreement(&left_calls[index], &right_calls[other])
                + CONSTANT_WEIGHT * constant_agreement(&left.constants, &right.constants)
        };
        let mut ranked: Vec<(f64, (f64, usize, usize))> =
            candidates.into_iter().map(|candidate| (rank(&candidate), candidate)).collect();
        ranked.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(core::cmp::Ordering::Equal)
                .then_with(|| a.1.1.cmp(&b.1.1))
                .then_with(|| a.1.2.cmp(&b.1.2))
        });

        // The candidates of each function, to find a rival of a pair.
        let mut of_left: HashMap<usize, Vec<(f64, usize)>> = HashMap::new();
        let mut of_right: HashMap<usize, Vec<(f64, usize)>> = HashMap::new();
        for &(rank, (_, index, other)) in &ranked {
            of_left.entry(index).or_default().push((rank, other));
            of_right.entry(other).or_default().push((rank, index));
        }
        for (rank, (score, index, other)) in ranked {
            if !(self.left_free[index] && self.right_free[other]) {
                continue;
            }
            let close = |rival: f64| rival >= rank - RIVAL_MARGIN;
            let rival_after = of_left[&index]
                .iter()
                .any(|&(rival, y)| y != other && self.right_free[y] && close(rival));
            let rival_before = of_right[&other]
                .iter()
                .any(|&(rival, x)| x != index && self.left_free[x] && close(rival));
            if !(rival_after || rival_before) {
                self.take_pair(index, other, Confidence::Similar, score);
            }
        }
        progress.finish();
    }
}

impl Cascade<'_> {
    /// Pair the twins still free where their constants and what they reach
    /// tell them apart.
    ///
    /// A wrapper that passes a constant on to another function, as
    /// `j target` with `addiu a1, zero, 0x71` in its delay slot, has the
    /// shape of every such wrapper, and the stages before cannot choose. The
    /// constant can, and so can the callee once it has paired: a free
    /// function pairs with the one free twin that agrees on both, where that
    /// twin agrees with no other. Measured on the OpenWrt MIPS kernels, once
    /// tail calls end functions, hundreds of such wrappers were left free,
    /// because each keeps only [`CANDIDATES_PER_FUNCTION`] candidates by
    /// similarity, and those went to its twins.
    ///
    /// See RESEARCH.md, A6.
    fn pair_leftover_twins(&mut self) {
        let (left_keys, right_keys) = self.reference_keys();
        let group = |side: &[Prepared<'_>], free: &[bool]| {
            let mut groups: HashMap<Vec<Symbol>, Vec<usize>> = HashMap::new();
            for (index, prepared) in side.iter().enumerate() {
                if free[index] && !prepared.is_empty() {
                    groups.entry(prepared.ordered.clone()).or_default().push(index);
                }
            }
            groups
        };
        let left_groups = group(&self.left, &self.left_free);
        let right_groups = group(&self.right, &self.right_free);

        let mut pairs = Vec::new();
        for (shape, lefts) in &left_groups {
            let Some(rights) = right_groups.get(shape) else { continue };
            let left_bodies: Vec<&[NormInsn]> =
                lefts.iter().map(|&index| self.left[index].body()).collect();
            let right_bodies: Vec<&[NormInsn]> =
                rights.iter().map(|&index| self.right[index].body()).collect();
            let agree = |l: usize, r: usize| {
                left_keys[lefts[l]] == right_keys[rights[r]]
                    && same_detail(left_bodies[l], right_bodies[r])
            };
            for l in 0..lefts.len() {
                let mut agreeing = (0..rights.len()).filter(|&r| agree(l, r));
                let (Some(r), None) = (agreeing.next(), agreeing.next()) else { continue };
                if (0..lefts.len()).filter(|&other| agree(other, r)).count() == 1 {
                    pairs.push((lefts[l], rights[r]));
                }
            }
        }
        // Pairing in a fixed order keeps the result independent of the order
        // the maps yield their groups in.
        pairs.sort_unstable();
        for (before, after) in pairs {
            self.take_pair(before, after, Confidence::IdenticalShape, 1.0);
        }
    }

    /// Pair again, by what they reach, the twins that paired by code but
    /// reach different functions.
    ///
    /// The bytes of a T32 range extension thunk hold only a distance, so all
    /// thunks have one shape, and in a raw image nothing names what they
    /// reach. The code stages pair them before the PLT stubs they reach have
    /// paired, and one thunk more on one side shifts every pair after it.
    /// Measured on Lua built for Thumb-2 by clang at `-O1`, eight thunks had
    /// paired with the next one's partner. A swap of two pairs cannot undo
    /// such a shift, so each such pair is undone, and its function pairs with
    /// the one function of its shape that reaches what it reaches, where no
    /// other function of that shape reaches the same.
    ///
    /// A pair waits while what it reaches is itself crossed: Tinyxml2's
    /// `XMLComment::ShallowClone` and `XMLUnknown::ShallowClone` differ only
    /// in the thunk they call, so they can be told apart only once the
    /// thunks have paired again.
    ///
    /// See RESEARCH.md, A6.
    fn repair_twins_by_callees(&mut self) {
        /// Each round settles one more level of callers.
        const MOST_ROUNDS: usize = 4;

        for _ in 0..MOST_ROUNDS {
            if self.repair_settled_twins() == Repaired::Nothing {
                break;
            }
        }
    }

    /// One round of [`Self::repair_twins_by_callees`].
    fn repair_settled_twins(&mut self) -> Repaired {
        let (left_keys, right_keys) = self.reference_keys_of_all();
        let all_crossed: Vec<usize> = self
            .matched
            .iter()
            .enumerate()
            .filter(|(_, pair)| {
                matches!(
                    pair.confidence,
                    Confidence::IdenticalCode
                        | Confidence::IdenticalShape
                        | Confidence::TwinInOrder
                ) && left_keys[pair.before] != right_keys[pair.after]
            })
            .map(|(index, _)| index)
            .collect();
        let crossed_rights: HashSet<usize> =
            all_crossed.iter().map(|&index| self.matched[index].after).collect();
        let reaches_crossed = |keys: &[ReferenceKey]| {
            keys.iter().any(
                |key| matches!(key, ReferenceKey::Paired(after) if crossed_rights.contains(after)),
            )
        };
        let crossed: Vec<usize> = all_crossed
            .into_iter()
            .filter(|&index| {
                let pair = &self.matched[index];
                !reaches_crossed(&left_keys[pair.before])
                    && !reaches_crossed(&right_keys[pair.after])
            })
            .collect();
        if crossed.is_empty() {
            return Repaired::Nothing;
        }

        // Only the functions of the crossed pairs take part. A free function
        // of the same shape that reaches the same is no evidence: in a
        // kernel, many wrappers stay free for good reason.
        let lefts = crossed.iter().map(|&index| self.matched[index].before);
        let rights = crossed.iter().map(|&index| self.matched[index].after);
        let left_groups = group_by_shape_and_references(&self.left, &left_keys, lefts);
        let right_groups = group_by_shape_and_references(&self.right, &right_keys, rights);

        let mut pairs: Vec<(usize, usize)> = left_groups
            .iter()
            .filter_map(|(key, lefts)| {
                match (lefts.as_slice(), right_groups.get(key)?.as_slice()) {
                    (&[before], &[after]) => Some((before, after)),
                    _ => None,
                }
            })
            .collect();
        // Pairing in a fixed order keeps the result independent of the order
        // the maps yield their groups in.
        pairs.sort_unstable();

        let (new_lefts, new_rights): (HashSet<usize>, HashSet<usize>) =
            pairs.iter().copied().unzip();
        let undone: HashSet<usize> = crossed
            .into_iter()
            .filter(|&index| {
                let pair = &self.matched[index];
                new_lefts.contains(&pair.before) || new_rights.contains(&pair.after)
            })
            .collect();
        let mut index = 0;
        self.matched.retain(|pair| {
            let keep = !undone.contains(&index);
            index += 1;
            if !keep {
                self.left_free[pair.before] = true;
                self.right_free[pair.after] = true;
            }
            keep
        });
        if pairs.is_empty() {
            return Repaired::Nothing;
        }
        for (before, after) in pairs {
            self.take_pair(before, after, Confidence::IdenticalShape, 1.0);
        }
        Repaired::Some
    }

    /// Swap two pairings by similarity where each function calls and points
    /// at exactly what the other's partner does, and the code cannot choose. Where the
    /// function that calls the same is unpaired, the pairing moves to it.
    ///
    /// A wrapper that only calls another function has the shape of every
    /// such wrapper. The similarity stage ranks candidates by their callees,
    /// but a callee pairs in that same stage, often after its caller. Once
    /// every stage has run, the callees are known. Measured on zlib 1.2.12
    /// built by GCC for MIPS as a raw image, `gzgetc_` and `crc32_combine`,
    /// one tail call each, had paired crossed.
    ///
    /// See RESEARCH.md, A10.
    fn uncross_by_callees(&mut self) {
        /// A swap moves the callees of its callers, so a chain of wrappers
        /// settles in a few rounds.
        const MOST_ROUNDS: usize = 4;

        for _ in 0..MOST_ROUNDS {
            let (left_calls, right_calls) = self.reference_keys_of_all();
            let mut by_calls: HashMap<&[ReferenceKey], Vec<usize>> = HashMap::new();
            for (index, keys) in right_calls.iter().enumerate() {
                if !keys.is_empty() {
                    by_calls.entry(keys.as_slice()).or_default().push(index);
                }
            }
            let pair_of_after: HashMap<usize, usize> =
                self.matched.iter().enumerate().map(|(index, pair)| (pair.after, index)).collect();

            let mut touched = BTreeSet::new();
            let mut swaps = Vec::new();
            let mut moves = Vec::new();
            let mut moved_to = BTreeSet::new();
            for (first, pair) in self.matched.iter().enumerate() {
                let (x, y_other) = (pair.before, pair.after);
                let wanted = left_calls[x].as_slice();
                if pair.confidence != Confidence::Similar
                    || wanted.is_empty()
                    || wanted == right_calls[y_other].as_slice()
                    || touched.contains(&first)
                {
                    continue;
                }
                // A free function that calls what `x` calls takes its place.
                let free = by_calls.get(wanted).into_iter().flatten().copied().find(|&y| {
                    self.right_free[y] && self.is_near_tie(&[&self.matched[first]], &[(x, y)])
                });
                if let Some(y) = free.filter(|y| moved_to.insert(*y)) {
                    touched.insert(first);
                    moves.push((first, y));
                    continue;
                }
                let crossed = by_calls.get(wanted).into_iter().flatten().find_map(|&y| {
                    let second = *pair_of_after.get(&y)?;
                    let x_other = self.matched[second].before;
                    let fits = left_calls[x_other] == right_calls[y_other]
                        && !touched.contains(&second)
                        && self.is_near_tie(
                            &[&self.matched[first], &self.matched[second]],
                            &[(x, y), (x_other, y_other)],
                        );
                    fits.then_some(second)
                });
                if let Some(second) = crossed {
                    touched.extend([first, second]);
                    swaps.push((first, second));
                }
            }
            if swaps.is_empty() && moves.is_empty() {
                break;
            }
            for (index, y) in moves {
                let (x, old) = (self.matched[index].before, self.matched[index].after);
                self.right_free[old] = true;
                self.right_free[y] = false;
                let score = similarity_of_symbols(&self.left[x].symbols, &self.right[y].symbols);
                self.matched[index] = self.assess(x, y, Confidence::Similar, score);
            }
            for (first, second) in swaps {
                let (x, y_other) = (self.matched[first].before, self.matched[first].after);
                let (x_other, y) = (self.matched[second].before, self.matched[second].after);
                for (index, (left, right)) in [(first, (x, y)), (second, (x_other, y_other))] {
                    let score =
                        similarity_of_symbols(&self.left[left].symbols, &self.right[right].symbols);
                    self.matched[index] = self.assess(left, right, Confidence::Similar, score);
                }
            }
        }
    }
}

/// Whether a round of [`Cascade::repair_twins_by_callees`] paired anything
/// again.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Repaired {
    Nothing,
    Some,
}

/// What two callees that each paired with nothing say about a call.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Unpaired {
    /// They are different functions.
    Differ,
    /// Nothing: they may be one function that changed too much to pair.
    SayNothing,
}

/// The `members` of one side that reach something, grouped by their shape and
/// by what they reach.
///
/// A member with a callee that is unknown or unpaired is left out: what it
/// reaches is only in part known, and the part can match a twin that
/// reaches less. Tinyxml2's `SetAttribute` for `int64_t` and for
/// `uint64_t` share one callee, and each has one of its own.
///
/// See RESEARCH.md, A6.
fn group_by_shape_and_references<'a>(
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
fn long_texts<'t>(texts: &[&'t str]) -> Vec<&'t str> {
    texts.iter().copied().filter(|text| text.len() >= SHORT_TEXT).collect()
}

/// How many short texts changed in place, as `"%d"` to `"%u"`.
///
/// A word of data can read as a short text by chance, so only a sure one
/// counts: see [`crate::callee::Links::is_sure_text`]. And a short text
/// can come or go where no change is: a linker merges `"yes"` into the
/// tail of `"... yes"`, where no NUL comes before it, and measured on the
/// OpenWrt kernels, a pointer to such a tail read as a text on one side
/// only. So only as many as both sides lose and gain count.
///
/// Each side is its texts and its sure texts, both sorted.
fn short_texts_changed(left: (&[&str], &[&str]), right: (&[&str], &[&str])) -> usize {
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
fn texts_that_differ(left: &[&str], right: &[&str]) -> usize {
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
fn differ_only_by_build_path(left: &str, right: &str) -> bool {
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
const REFERENCE_WEIGHT: f64 = 0.1;

/// How deep the data-flow features go: an operation with what defines its
/// inputs, and what defines theirs. Measured over the cross builds, one
/// round paired 15 fewer right and 34 more wrong than two.
const FLOW_DEPTH: usize = 2;

/// The floors at which data flow takes a pair the code alone would not.
struct FlowRescue {
    /// The least similarity of the normalized instructions.
    code: f64,
    /// The least similarity of the data-flow features.
    flow: f64,
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
const FLOW_RESCUE: FlowRescue = FlowRescue { code: 0.5, flow: 0.7 };

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
const RIVAL_MARGIN: f64 = 0.03;

/// The similarity at which the first pass of the similarity stage pairs.
///
/// The pairs it makes are the callees that tell the second pass's
/// candidates apart. Measured as for [`REFERENCE_WEIGHT`], 0.85 did best of
/// 0.75, 0.85 and 0.95.
///
/// See RESEARCH.md, A7.
const CLOSE_SIMILARITY: f64 = 0.85;

/// A callee or a text, as both sides can name it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ReferenceKey {
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
const CONSTANT_WEIGHT: f64 = 0.1;

/// The largest constant that names no function in particular, as a stack
/// offset, a field offset or a small count.
///
/// A shared constant above this counts as one edge in
/// [`Cascade::realign_by_context`]. Measured over the cross builds, this
/// paired 99 more right and 23 more wrong. Every shared constant, of any
/// size, paired 361 more right but 175 more wrong.
const LARGEST_PLAIN_CONSTANT: u64 = 0xfff;

/// How well two sorted sets of constants agree, from -1.0 to 1.0, or 0.0
/// where neither holds any.
fn constant_agreement(left: &[u64], right: &[u64]) -> f64 {
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
const LOWEST_LAYOUT_SIMILARITY: f64 = 0.1;

/// Whether a pair sits between the pairs around it on both sides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place {
    /// The second side sits between the partners of the pairs around the
    /// first, as code that stayed in its source file does.
    Kept,
    /// It sits elsewhere.
    Moved,
}

/// The callers and callees of the two sides of a pair.
struct Context<'a> {
    /// The partners of the paired callers and callees of the first side.
    partners_of_left: BTreeSet<usize>,
    /// The callers and callees of the second side.
    right: &'a BTreeSet<usize>,
    /// How many of [`Self::right`] paired.
    paired_right: usize,
}

/// Whether the callers and callees of a pair say it is wrong: see
/// [`Cascade::unpair_without_context`].
fn lacks_context(confidence: Confidence, score: f64, place: Place, context: &Context<'_>) -> bool {
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
const LEAST_AGREEING_SHARE_OUT_OF_PLACE: f64 = 0.3;

/// How many callers and callees that paired each side of a pair needs for
/// [`Cascade::unpair_without_context`] to judge it.
const FEWEST_PAIRED_NEIGHBOURS: usize = 2;

/// The code similarity under which a pair has little but its place for it,
/// so that [`FEWEST_PAIRED_NEIGHBOURS_OF_A_WEAK_PAIR`] applies.
///
/// Measured against the symbols and the source files in the DWARF, this
/// undid 16 right pairs and 103 wrong over the OpenWrt kernels, and 1 right
/// and 7 wrong over the backports built two ways, with the fixes ranked a
/// little higher. At 0.5 to 0.65 it undid more of both, and at 0.7 it
/// ranked the backport fixes lower.
const WEAK_PAIR_SIMILARITY: f64 = 0.4;

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
const LOWEST_MOVED_SIMILARITY: f64 = 0.8;

/// See [`LOWEST_MOVED_SIMILARITY`].
const MOVED_SIMILARITY_MARGIN: f64 = 0.2;

/// How many times [`Cascade::pair_by_unique_references_until_settled`]
/// runs the stage at most. Measured over the OpenWrt kernels, a second
/// round paired 7 more right and 7 fewer wrong, and the backports did not
/// change.
const MOST_UNIQUE_REFERENCE_ROUNDS: usize = 4;

/// The lowest code similarity at which a text or a constant that only two
/// functions hold pairs them: see [`Cascade::pair_by_unique_references`].
///
/// Measured over the backports built two ways, 0.3 paired 304 more right
/// and 40 fewer wrong; 0.1 paired 328 more right and 31 fewer wrong, and
/// 0.4 paired 274 more right and 43 fewer wrong. A floor stays, so that a
/// text that moved to another function does not pair the two.
const LOWEST_UNIQUE_REFERENCE_SIMILARITY: f64 = 0.3;

/// A reference that can tell one function from all others.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum UniqueReference<'a> {
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
}

/// Each text, large constant and named callee that exactly one function
/// of `side` holds, and that function.
fn unique_reference_holders<'a>(
    side: &'a [Prepared<'_>],
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
        for key in texts.chain(constants).chain(calls).chain(callee_set) {
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
const MOST_PLACE_CELLS: usize = 1 << 20;

/// The least share of the functions of the smaller binary that must pair
/// in order before [`Cascade::pair_by_layout`] reads their places.
///
/// Two unrelated objects of eight functions each paired three by place
/// alone, with no pair around them. Measured over the backports built two
/// ways, 0.25 paired 4 fewer right than no floor, and 0.5 paired 167 fewer
/// right and 45 fewer wrong: another compiler pairs few functions in order.
const LEAST_ANCHORED_SHARE: f64 = 0.25;

/// The keys that more than [`MOST_HOLDERS_OF_AN_EDGE`] of the functions
/// of `keys` hold.
fn common_keys(keys: &[Vec<ReferenceKey>]) -> HashSet<ReferenceKey> {
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
const MOST_HOLDERS_OF_AN_EDGE: usize = 128;

/// The fewest call edges and texts a pair must share before
/// [`Cascade::realign_by_context`] takes it.
const FEWEST_SHARED_EDGES: usize = 3;

/// The lowest code similarity at which context alone pairs two functions.
const LOWEST_CONTEXT_SIMILARITY: f64 = 0.3;

/// How much `count` copies of one added instruction weigh, from 1 for one
/// copy toward [`SATURATION`] + 1 for many.
///
/// The term frequency of BM25 (RESEARCH.md, entry 8): the first copies are
/// strong evidence, and each more copy adds less. A rewrite that adds forty
/// moves of one shape then weighs less than a fix that adds three rare
/// instructions.
fn saturated(count: usize) -> f64 {
    let count = count as f64;
    count * (SATURATION + 1.0) / (count + SATURATION)
}

/// The `k1` of BM25. Measured on the backports built two ways and the
/// published fixes, 1.2 ranked the fixes higher than 0.5 or 3, and higher
/// than no saturation at all.
const SATURATION: f64 = 1.2;

/// The items of the sorted list `left` that `right` lacks, counted as a
/// multiset, sorted.
fn sorted_only_in<T: Ord + Copy>(left: &[T], right: &[T]) -> Vec<T> {
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
fn sorted_shared<T: Ord>(left: &[T], right: &[T]) -> usize {
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
fn reference_agreement(left: &[ReferenceKey], right: &[ReferenceKey]) -> f64 {
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
const CANDIDATES_PER_FUNCTION: usize = 8;

/// Keep only the strongest candidates for one function.
///
/// Called with one new candidate appended, so at most one entry is over the
/// limit and a single pass finds the weakest.
///
/// See RESEARCH.md, A7.
fn keep_best_candidates(candidates: &mut Vec<(f64, usize, usize)>) {
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
fn similarity_of_symbols<T: Ord>(left: &[T], right: &[T]) -> f64 {
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

/// One line of an instruction-level diff between two matched functions.
///
/// The counts in [`Match::edits`] say *how much* changed; this says *what*.
/// The text is the instruction as the decoder printed it, so a reader sees the
/// real instruction, not the normalized form the matcher compares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiffLine {
    /// The same instruction on both sides.
    Same(String),
    /// An instruction the later build added.
    Added(String),
    /// An instruction the later build removed.
    Removed(String),
    /// An instruction kept in place but with a changed constant.
    ///
    /// The operation and operand shapes agree, so the matcher aligns the two,
    /// but a stored value differs. This is the shape a changed threshold or
    /// magic number takes.
    Changed { before: String, after: String },
}

/// How `--diff` shows each instruction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum View {
    /// As the decoder printed it.
    #[default]
    Assembly,
    /// As the IL reads it: see [`crate::view`].
    Il,
}

/// The address of each line `view` shows of the function `index` of
/// `binary`, in order: the IL view shows some idioms of several
/// instructions as one line.
pub fn line_addresses(view: View, binary: &Binary, index: usize) -> Vec<u64> {
    let function = &binary.functions[index];
    let arch = binary.isa_of(function).arch();
    let insns = decode_all(arch, &function.code, function.address).0;
    match view {
        View::Assembly => insns.iter().map(|insn| insn.address).collect(),
        View::Il => crate::view::il_line_addresses(arch, &insns),
    }
}

/// [`instruction_diff`], or the same diff with each instruction shown as
/// `view` says.
///
/// The IL view aligns on the IL statements, so two spellings of one
/// operation, as `eor r0, r0, r0` and `mov r0, #0`, are the same line. With
/// `paired`, a call to a stripped function of `after` names the function as
/// its pair in `before` is named.
pub fn instruction_diff_in(
    view: View,
    paired: Option<&PairedLabels>,
    before: &Binary,
    before_index: usize,
    after: &Binary,
    after_index: usize,
) -> Vec<DiffLine> {
    let (left, right) = (&before.functions[before_index], &after.functions[after_index]);
    let (before_isa, after_isa) = (before.isa_of(left), after.isa_of(right));
    if view == View::Assembly {
        return instruction_diff(left, before_isa, right, after_isa);
    }
    let side = |binary: &Binary, function: &Function, isa: Isa, paired| {
        let arch = isa.arch();
        let insns = decode_all(arch, &function.code, function.address).0;
        let context = crate::view::Context {
            links: &binary.links,
            space: &binary.addresses,
            functions: &binary.functions,
            paired,
        };
        IlSide::new(arch, &function.code, insns, Some(context))
    };
    let before_side = side(before, left, before_isa, None);
    let after_side = side(after, right, after_isa, paired);
    let keys = |side: &IlSide| -> Vec<String> {
        side.statements.iter().map(|statement| il_key(&statement.text)).collect()
    };
    let steps = align(&keys(&before_side), &keys(&after_side));
    fold_il_runs(&steps, &before_side, &after_side)
}

/// The IL statements of one side of a diff, with the instructions they show.
struct IlSide<'a> {
    arch: &'a dyn Arch,
    insns: Vec<Insn>,
    statements: Vec<crate::view::Statement>,
    /// The words the instructions print, as their registers.
    printed: HashSet<String>,
}

impl<'a> IlSide<'a> {
    fn new(
        arch: &'a dyn Arch,
        code: &[u8],
        insns: Vec<Insn>,
        context: Option<crate::view::Context<'_>>,
    ) -> Self {
        let statements = crate::view::il_statements_in(arch, code, &insns, context);
        let printed = insns.iter().flat_map(|insn| words_of(&insn.to_string())).collect();
        Self { arch, insns, statements, printed }
    }

    /// The instruction that `statement` shows.
    fn insn_of(&self, statement: &crate::view::Statement) -> Option<&Insn> {
        let index =
            self.insns.binary_search_by_key(&statement.address, |insn| insn.address).ok()?;
        Some(&self.insns[index])
    }
}

/// Pair a run of removed statements with the run of added ones right after
/// it, one for one where the two runs are as long.
///
/// Each pair of the same shape is one statement: the same, where only a
/// register differs, as a register is the compiler's free choice, and else
/// with another constant. A compare and its branch move together, so their
/// two statements come as a run of two.
fn fold_il_runs(steps: &[Step], before: &IlSide<'_>, after: &IlSide<'_>) -> Vec<DiffLine> {
    let mut folded: Vec<DiffLine> = Vec::with_capacity(steps.len());
    let (mut i, mut j) = (0, 0);
    let mut index = 0;
    while index < steps.len() {
        let removed = steps[index..].iter().take_while(|step| **step == Step::Left).count();
        let added =
            steps[index + removed..].iter().take_while(|step| **step == Step::Right).count();
        if removed == 0 || added == 0 {
            folded.push(match steps[index] {
                Step::Both => DiffLine::Same(after.statements[j].text.clone()),
                Step::Left => DiffLine::Removed(before.statements[i].text.clone()),
                Step::Right => DiffLine::Added(after.statements[j].text.clone()),
            });
            (i, j) = match steps[index] {
                Step::Both => (i + 1, j + 1),
                Step::Left => (i + 1, j),
                Step::Right => (i, j + 1),
            };
            index += 1;
            continue;
        }
        let run = IlRun { before, before_at: i..i + removed, after, after_at: j..j + added };
        let pairs: Option<Vec<DiffLine>> =
            (removed == added).then(|| (0..removed).map(|at| run.fold(at, at)).collect()).flatten();
        match pairs {
            Some(pairs) => folded.extend(pairs),
            // Runs of other lengths fold only where they meet.
            None => {
                folded.extend(
                    (0..removed - 1).map(|at| DiffLine::Removed(run.before_text(at).to_string())),
                );
                match run.fold(removed - 1, 0) {
                    Some(line) => folded.push(line),
                    None => folded.extend([
                        DiffLine::Removed(run.before_text(removed - 1).to_string()),
                        DiffLine::Added(run.after_text(0).to_string()),
                    ]),
                }
                folded.extend((1..added).map(|at| DiffLine::Added(run.after_text(at).to_string())));
            }
        }
        (i, j) = (i + removed, j + added);
        index += removed + added;
    }
    folded
}

/// A run of removed IL statements and the run of added ones after it.
struct IlRun<'a> {
    before: &'a IlSide<'a>,
    before_at: core::ops::Range<usize>,
    after: &'a IlSide<'a>,
    after_at: core::ops::Range<usize>,
}

impl IlRun<'_> {
    fn before_text(&self, at: usize) -> &str {
        &self.before.statements[self.before_at.start + at].text
    }

    fn after_text(&self, at: usize) -> &str {
        &self.after.statements[self.after_at.start + at].text
    }

    /// The statement `before_at` of the run against `after_at`, as one line
    /// where the two are of one shape.
    fn fold(&self, before_at: usize, after_at: usize) -> Option<DiffLine> {
        let before_statement = &self.before.statements[self.before_at.start + before_at];
        let after_statement = &self.after.statements[self.after_at.start + after_at];
        let (before_text, after_text) = (&before_statement.text, &after_statement.text);
        let difference =
            match (self.before.insn_of(before_statement), self.after.insn_of(after_statement)) {
                (Some(left), Some(right)) => {
                    difference(self.before.arch, left, self.after.arch, right, FrameSlots::Move)
                }
                _ => Difference::Shape,
            };
        if difference == Difference::FreeChoices
            && self.only_printed_words_differ(before_at, after_at)
        {
            Some(DiffLine::Same(after_text.clone()))
        } else if il_shape(before_text) == il_shape(after_text) {
            Some(DiffLine::Changed { before: before_text.clone(), after: after_text.clone() })
        } else {
            None
        }
    }

    /// Whether each word in which the two statements differ is one that the
    /// instructions of its side print, as a register is.
    ///
    /// A name the IL view gives, as of a callee or a string, is no word of
    /// an instruction. It changes where the target or the pool the
    /// instruction reads changed, which [`difference`] lets move.
    fn only_printed_words_differ(&self, before_at: usize, after_at: usize) -> bool {
        let before = words_of(&il_key(self.before_text(before_at)));
        let after = words_of(&il_key(self.after_text(after_at)));
        before.len() == after.len()
            && before.iter().zip(&after).all(|(a, b)| {
                a == b || (self.before.printed.contains(a) && self.after.printed.contains(b))
            })
    }
}

/// The words of `line`: its runs of letters, digits and `_`.
fn words_of(line: &str) -> Vec<String> {
    line.split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|word| !word.is_empty())
        .map(str::to_string)
        .collect()
}

/// The text two IL statements must share to align: the statement with
/// each target collapsed, as [`diff_key`] does for an instruction.
fn il_key(line: &str) -> String {
    let words: Vec<&str> =
        line.split(' ').map(|word| if is_branch_target(word) { "$" } else { word }).collect();
    // An address the code formed, as `@0x57c6`, moves as a target does,
    // and so does the distance from `pc` to a literal pool. A slot of the
    // stack frame moves when the frame grows, which the compiler decides:
    // the matcher reads every frame slot as one kind too. The size of the
    // frame stays, as `sp = sp - 0x40`, since a stack buffer can grow.
    let mut key = words.join(" ");
    for marker in [
        "@0x",
        "[pc + 0x",
        "[pc - 0x",
        "[sp + 0x",
        "[sp - 0x",
        "[x29 + 0x",
        "[x29 - 0x",
        "[fp + 0x",
        "[fp - 0x",
        "[r7 + 0x",
        "[s8 + 0x",
    ] {
        let mut collapsed = String::with_capacity(key.len());
        let mut rest = key.as_str();
        while let Some(at) = rest.find(marker) {
            collapsed.push_str(&rest[..at + marker.len() - 2]);
            rest = rest[at + marker.len()..]
                .trim_start_matches(|character: char| character.is_ascii_hexdigit());
        }
        collapsed.push_str(rest);
        key = collapsed;
    }
    key
}

/// An IL statement with every number collapsed, so two that differ only in
/// a constant share it.
fn il_shape(line: &str) -> String {
    let key = il_key(line);
    let mut shape = String::with_capacity(key.len());
    let mut in_number = false;
    let mut previous = ' ';
    for character in key.chars() {
        let starts_number = character.is_ascii_digit() && !previous.is_ascii_alphanumeric();
        if starts_number
            || (in_number && character.is_ascii_hexdigit())
            || (in_number && character == 'x')
        {
            if !in_number {
                shape.push('#');
            }
            in_number = true;
        } else {
            in_number = false;
            shape.push(character);
        }
        previous = character;
    }
    shape
}

/// Align two matched functions instruction by instruction.
///
/// The alignment keys on the normalized form, so a branch whose target only
/// moved reads as [`DiffLine::Same`], the same choice the matcher makes
/// everywhere else. A longest-common-subsequence walk keeps an inserted
/// instruction from making every line after it look changed, which a plain
/// position-by-position compare cannot do.
///
/// The printed text carries the true disassembly. Where two aligned
/// instructions agree in shape but differ in a constant, the line is
/// [`DiffLine::Changed`] rather than [`DiffLine::Same`], so a changed value is
/// never reported as no change.
///
/// See RESEARCH.md, A13.
pub fn instruction_diff(
    before: &Function,
    before_isa: Isa,
    after: &Function,
    after_isa: Isa,
) -> Vec<DiffLine> {
    let before_arch = before_isa.arch();
    let after_arch = after_isa.arch();
    let before_insns = decode_all(before_arch, &before.code, before.address).0;
    let after_insns = decode_all(after_arch, &after.code, after.address).0;

    // Align on the printed text, but with branch targets collapsed. Keeping the
    // constant in the key is what lets a new `tst r5, #4` stand apart from an
    // existing `tst r5, #8`: the matcher's normalized form drops both to one
    // shape and would pair them, hiding the new gate. Collapsing the target
    // still folds a call whose callee only moved.
    let before_keys: Vec<String> = before_insns.iter().map(diff_key).collect();
    let after_keys: Vec<String> = after_insns.iter().map(diff_key).collect();

    let steps = align(&before_keys, &after_keys);
    lines_from_alignment(&steps, (before_arch, &before_insns), (after_arch, &after_insns))
}

/// The text two instructions must share to align, with targets removed.
///
/// A branch or a `[pc, #imm]` load prints its target as `$+0x24`; the target
/// moves whenever anything before it changes size, so it must not decide the
/// alignment. Everything else, the constant included, stays: a changed value is
/// a real difference the reader came to see.
fn diff_key(insn: &Insn) -> String {
    let printed = insn.to_string();
    let (name, operands) = split_printed(&printed);
    let operands = operands
        .split(',')
        .map(str::trim)
        .map(|operand| if is_branch_target(operand) { "$" } else { operand })
        .collect::<Vec<_>>()
        .join(", ");
    format!("{name} {operands}")
}

/// A move through the alignment grid: keep both sides, or drop one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// The instruction is on both sides; advance both.
    Both,
    /// The instruction is only on the left; advance the left.
    Left,
    /// The instruction is only on the right; advance the right.
    Right,
}

/// Largest alignment table worth building, in cells.
///
/// The table holds one `usize` a cell, so this caps it at about 128 MB. Most
/// functions are a few hundred instructions and never come close. A whole
/// kernel holds a few that do: measured on a vendor image, one pair of 19926
/// and 19872 instructions asks for 3.2 GB and the process is killed before it
/// can report anything.
const LARGEST_ALIGNMENT: usize = 16 * 1024 * 1024;

/// Align two sequences: exactly where the table fits, and by anchors where
/// it does not.
///
/// The exact walk is [`longest_common_subsequence`], which is quadratic in
/// memory. For a pair whose table passes [`LARGEST_ALIGNMENT`] cells, this
/// follows the seed, chain and extend of genome alignment (RESEARCH.md,
/// entry 3, minimap2), as patience diff does:
///
/// 1. **Seed**: the common head and tail, and the items that occur once on
///    each side, are anchors.
/// 2. **Chain**: the longest run of anchors in the same order on both
///    sides, found as a longest increasing subsequence.
/// 3. **Extend**: each gap between two anchors aligns the same way.
///
/// A gap with no anchor and too large to align is compared position by
/// position. An insertion near the top of a large function then costs one
/// addition, where comparing the whole function by position made every
/// instruction after it look rewritten.
fn align<T: Eq + core::hash::Hash>(left: &[T], right: &[T]) -> Vec<Step> {
    align_within(left, right, LARGEST_ALIGNMENT)
}

/// [`align`], with the largest table to build given, so a test can reach
/// the anchors with short sequences.
fn align_within<T: Eq + core::hash::Hash>(left: &[T], right: &[T], largest: usize) -> Vec<Step> {
    // Each item as a number, equal where the items are: the table compares
    // up to every pair, and two numbers compare at once where two normalized
    // instructions do not.
    let mut ids: HashMap<&T, u32> = HashMap::with_capacity(left.len() + right.len());
    let mut id_of = |item| {
        let next = ids.len() as u32;
        *ids.entry(item).or_insert(next)
    };
    let left: Vec<u32> = left.iter().map(&mut id_of).collect();
    let right: Vec<u32> = right.iter().map(&mut id_of).collect();
    let count = ids.len();
    let mut steps = Vec::with_capacity(left.len().max(right.len()));
    align_into(&left, &right, count, largest, &mut steps);
    steps
}

/// [`align_within`], appending to `steps`.
fn align_into(left: &[u32], right: &[u32], count: usize, largest: usize, steps: &mut Vec<Step>) {
    // A pair that fits takes the exact walk unchanged, so that its ties
    // break as they always have.
    let fits = |left: usize, right: usize| {
        left.saturating_add(1).saturating_mul(right.saturating_add(1)) <= largest
    };
    if fits(left.len(), right.len()) {
        steps.extend(longest_common_subsequence_of_numbers(left, right, count));
        return;
    }
    let head = left.iter().zip(right).take_while(|(a, b)| a == b).count();
    let tail = left[head..]
        .iter()
        .rev()
        .zip(right[head..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    steps.extend(core::iter::repeat_n(Step::Both, head));
    let (left_gap, right_gap) = (&left[head..left.len() - tail], &right[head..right.len() - tail]);

    if fits(left_gap.len(), right_gap.len()) {
        steps.extend(longest_common_subsequence_of_numbers(left_gap, right_gap, count));
    } else {
        let anchors = chain_of_unique_items(left_gap, right_gap);
        if anchors.is_empty() {
            steps.extend(steps_by_position(left_gap, right_gap));
        } else {
            let (mut i, mut j) = (0, 0);
            for (x, y) in anchors {
                align_into(&left_gap[i..x], &right_gap[j..y], count, largest, steps);
                steps.push(Step::Both);
                (i, j) = (x + 1, y + 1);
            }
            align_into(&left_gap[i..], &right_gap[j..], count, largest, steps);
        }
    }
    steps.extend(core::iter::repeat_n(Step::Both, tail));
}

/// The positions of the items that occur once on each side, as `(left,
/// right)`, keeping the longest run in the same order on both sides.
fn chain_of_unique_items<T: Eq + core::hash::Hash>(left: &[T], right: &[T]) -> Vec<(usize, usize)> {
    /// Where an item sits on each side, and how often it occurs there.
    #[derive(Default)]
    struct Seen {
        left: (usize, usize),
        right: (usize, usize),
    }
    let mut seen: HashMap<&T, Seen> = HashMap::new();
    for (index, item) in left.iter().enumerate() {
        let entry = seen.entry(item).or_default();
        entry.left = (entry.left.0 + 1, index);
    }
    for (index, item) in right.iter().enumerate() {
        if let Some(entry) = seen.get_mut(item) {
            entry.right = (entry.right.0 + 1, index);
        }
    }
    let mut seeds: Vec<(usize, usize)> = seen
        .into_values()
        .filter(|entry| entry.left.0 == 1 && entry.right.0 == 1)
        .map(|entry| (entry.left.1, entry.right.1))
        .collect();
    seeds.sort_unstable();
    longest_increasing_chain(&seeds)
}

/// The functions of two binaries in address order, and the pairs that keep
/// that order: see [`Cascade::layout`].
struct Layout {
    /// The functions of the first binary, by address.
    left_order: Vec<usize>,
    /// The functions of the second binary, by address.
    right_order: Vec<usize>,
    /// The place of each function of the first binary in `left_order`.
    left_place: Vec<usize>,
    /// The place of each function of the second binary in `right_order`.
    right_place: Vec<usize>,
    /// The longest chain of pairs in the same order on both sides, as
    /// places.
    chain: Vec<(usize, usize)>,
}

impl Layout {
    /// Whether too few pairs keep their order for a place to mean anything.
    ///
    /// Two unrelated binaries pair few functions, and the place of one there
    /// means nothing: see [`LEAST_ANCHORED_SHARE`].
    fn is_unanchored(&self) -> bool {
        let smaller = self.left_order.len().min(self.right_order.len());
        (self.chain.len() as f64) < LEAST_ANCHORED_SHARE * smaller as f64
    }

    /// The free functions of each gap between two pairs of the chain, in
    /// address order, on the first and the second binary.
    ///
    /// Each gap runs from just after one pair to just before the next, and
    /// the ends of the binaries bound the first and the last.
    fn gaps<'a>(
        &'a self,
        left_free: &'a [bool],
        right_free: &'a [bool],
    ) -> impl Iterator<Item = (Vec<usize>, Vec<usize>)> + 'a {
        let free_in = |order: &[usize], free: &[bool], places: core::ops::Range<usize>| {
            order[places].iter().copied().filter(|&index| free[index]).collect::<Vec<_>>()
        };
        let ends =
            self.chain.iter().copied().chain([(self.left_order.len(), self.right_order.len())]);
        let starts = [(0, 0)].into_iter().chain(self.chain.iter().map(|&(x, y)| (x + 1, y + 1)));
        starts.zip(ends).map(move |(start, end)| {
            (
                free_in(&self.left_order, left_free, start.0..end.0),
                free_in(&self.right_order, right_free, start.1..end.1),
            )
        })
    }
}

/// Align two runs in order so that the sum of the scores of the aligned
/// items is highest, and return the aligned items that score above zero.
///
/// The dynamic program of Needleman and Wunsch, with no cost for a gap.
/// `score(x, y)` scores item `x` of the first run against item `y` of the
/// second.
fn align_by_scores(
    left_len: usize,
    right_len: usize,
    score: impl Fn(usize, usize) -> f64,
) -> Vec<(usize, usize)> {
    let width = right_len + 1;
    let mut scores = vec![0.0; left_len * right_len];
    // `best[x * width + y]` is the highest sum over the first `x` and `y`
    // items.
    let mut best = vec![0.0_f64; (left_len + 1) * width];
    for x in 1..=left_len {
        for y in 1..=right_len {
            let here = score(x - 1, y - 1);
            scores[(x - 1) * right_len + (y - 1)] = here;
            best[x * width + y] = (best[(x - 1) * width + (y - 1)] + here)
                .max(best[(x - 1) * width + y])
                .max(best[x * width + y - 1]);
        }
    }
    let mut aligned = Vec::new();
    let (mut x, mut y) = (left_len, right_len);
    while x > 0 && y > 0 {
        let here = scores[(x - 1) * right_len + (y - 1)];
        if here > 0.0 && best[x * width + y] == best[(x - 1) * width + (y - 1)] + here {
            aligned.push((x - 1, y - 1));
            (x, y) = (x - 1, y - 1);
        } else if best[x * width + y] == best[(x - 1) * width + y] {
            x -= 1;
        } else {
            y -= 1;
        }
    }
    aligned.reverse();
    aligned
}

/// The longest subsequence of `seeds`, sorted by their left position, whose
/// right positions increase too.
///
/// Patience sorting: `ends[k]` is the seed that ends the best chain of
/// length `k + 1` found so far, with the smallest right position.
fn longest_increasing_chain(seeds: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut ends: Vec<usize> = Vec::new();
    let mut previous: Vec<Option<usize>> = vec![None; seeds.len()];
    for (index, &(_, right)) in seeds.iter().enumerate() {
        let length = ends.partition_point(|&end| seeds[end].1 < right);
        previous[index] = length.checked_sub(1).map(|before| ends[before]);
        if length == ends.len() {
            ends.push(index);
        } else {
            ends[length] = index;
        }
    }
    let mut chain = Vec::with_capacity(ends.len());
    let mut at = ends.last().copied();
    while let Some(index) = at {
        chain.push(seeds[index]);
        at = previous[index];
    }
    chain.reverse();
    chain
}

/// Compare two sequences position by position, for a gap with no anchor
/// that is too large to align.
fn steps_by_position<T: PartialEq>(left: &[T], right: &[T]) -> Vec<Step> {
    let mut steps = Vec::with_capacity(left.len() + right.len());
    for (a, b) in left.iter().zip(right) {
        if a == b {
            steps.push(Step::Both);
        } else {
            steps.extend([Step::Left, Step::Right]);
        }
    }
    let overlap = left.len().min(right.len());
    steps.extend(core::iter::repeat_n(Step::Left, left.len() - overlap));
    steps.extend(core::iter::repeat_n(Step::Right, right.len() - overlap));
    steps
}

/// Table of the classic longest-common-subsequence dynamic program, the
/// model [`longest_common_subsequence_of_numbers`] is tested against.
///
/// `len[i][j]` is the length of the longest run of instructions shared by the
/// tails `left[i..]` and `right[j..]`. Reading it back from the top left gives
/// the alignment.
///
/// The caller must check the size first, as [`align`] does. The table is
/// quadratic, and on the largest functions of a whole kernel it would ask
/// for more memory than the machine has.
///
/// See RESEARCH.md, A13.
#[cfg(test)]
fn longest_common_subsequence<T: PartialEq>(left: &[T], right: &[T]) -> Vec<Step> {
    // A shared head aligns with itself: the walk below takes each equal
    // pair as it meets it. Most changed functions share a long head, and the
    // table is quadratic in what is left.
    let head = left.iter().zip(right).take_while(|(a, b)| a == b).count();
    let mut steps = vec![Step::Both; head];
    let (left, right) = (&left[head..], &right[head..]);

    // `len[i * cols + j]`, in one allocation. A length is at most that of
    // the shorter side, which the size of the table keeps far below 2^32,
    // and a narrow cell halves the memory the table reads.
    let cols = right.len() + 1;
    let mut len = vec![0u32; (left.len() + 1) * cols];
    for i in (0..left.len()).rev() {
        for j in (0..right.len()).rev() {
            len[i * cols + j] = if left[i] == right[j] {
                len[(i + 1) * cols + j + 1] + 1
            } else {
                len[(i + 1) * cols + j].max(len[i * cols + j + 1])
            };
        }
    }

    let (mut i, mut j) = (0, 0);
    while i < left.len() && j < right.len() {
        if left[i] == right[j] {
            steps.push(Step::Both);
            i += 1;
            j += 1;
        } else if len[(i + 1) * cols + j] >= len[i * cols + j + 1] {
            steps.push(Step::Left);
            i += 1;
        } else {
            steps.push(Step::Right);
            j += 1;
        }
    }
    steps.extend(core::iter::repeat_n(Step::Left, left.len() - i));
    steps.extend(core::iter::repeat_n(Step::Right, right.len() - j));
    steps
}

/// [`longest_common_subsequence`] of two runs of numbers below `count`,
/// with each row of the table held as bits.
///
/// The walk of the table reads only whether `len[i + 1][j]` is at least
/// `len[i][j + 1]`, so the same walk on the same lengths gives the same
/// steps. The lengths come from the bit-parallel program of Hyyrö (2004),
/// on both runs reversed, as `len` is of tails: after `k` items of the
/// reversed left run, bit `b` of the row is clear where the length grows
/// at item `b` of the reversed right run. A row is `right.len() / 64`
/// words where the table row was `right.len()` cells, and each step of the
/// program handles 64 cells at once.
fn longest_common_subsequence_of_numbers(left: &[u32], right: &[u32], count: usize) -> Vec<Step> {
    let head = left.iter().zip(right).take_while(|(a, b)| a == b).count();
    let mut steps = vec![Step::Both; head];
    let (left, right) = (&left[head..], &right[head..]);
    let (rows, columns) = (left.len(), right.len());
    let words = columns.div_ceil(64).max(1);

    // Where each number sits in the reversed right run.
    let mut matches = vec![0u64; count * words];
    for (bit, &item) in right.iter().rev().enumerate() {
        matches[item as usize * words + bit / 64] |= 1 << (bit % 64);
    }
    // `table[k]`: the row after `k` items of the reversed left run.
    let mut table = vec![u64::MAX; (rows + 1) * words];
    for (k, &item) in left.iter().rev().enumerate() {
        let (done, next) = table.split_at_mut((k + 1) * words);
        let (row, next) = (&done[k * words..], &mut next[..words]);
        let mask = &matches[item as usize * words..][..words];
        let (mut carry, mut borrow) = (false, false);
        for word in 0..words {
            let (v, u) = (row[word], row[word] & mask[word]);
            let (sum, c1) = v.overflowing_add(u);
            let (sum, c2) = sum.overflowing_add(u64::from(carry));
            carry = c1 || c2;
            let (difference, b1) = v.overflowing_sub(u);
            let (difference, b2) = difference.overflowing_sub(u64::from(borrow));
            borrow = b1 || b2;
            next[word] = sum | difference;
        }
    }
    // `len[i][j]`: the clear bits of the first `columns - j` of row
    // `rows - i`.
    let len = |i: usize, j: usize| {
        let row = &table[(rows - i) * words..][..words];
        let width = columns - j;
        let (whole, rest) = (width / 64, width % 64);
        let set: u32 = row[..whole].iter().map(|word| word.count_ones()).sum::<u32>()
            + if rest == 0 { 0 } else { (row[whole] & ((1 << rest) - 1)).count_ones() };
        width - set as usize
    };

    let (mut i, mut j) = (0, 0);
    while i < rows && j < columns {
        if left[i] == right[j] {
            steps.push(Step::Both);
            i += 1;
            j += 1;
        } else if len(i + 1, j) >= len(i, j + 1) {
            steps.push(Step::Left);
            i += 1;
        } else {
            steps.push(Step::Right);
            j += 1;
        }
    }
    steps.extend(core::iter::repeat_n(Step::Left, rows - i));
    steps.extend(core::iter::repeat_n(Step::Right, columns - j));
    steps
}

/// Turn an alignment of `before` against `after` into diff lines.
///
/// Aligning on the printed text splits a changed constant into a removal
/// and an addition, as the two print differently, and can so split a line
/// whose target only moved. A removal right before an addition of the same
/// operation and shape is one line: [`DiffLine::Same`] where only a free
/// choice differs, and [`DiffLine::Changed`] where a value does.
///
/// See RESEARCH.md, A13.
fn lines_from_alignment(
    steps: &[Step],
    (before_arch, before_insns): (&dyn Arch, &[Insn]),
    (after_arch, after_insns): (&dyn Arch, &[Insn]),
) -> Vec<DiffLine> {
    let mut lines = Vec::with_capacity(steps.len());
    let (mut i, mut j) = (0, 0);
    // The instruction of the last line, where that line is a removal.
    let mut removed: Option<&Insn> = None;
    for step in steps {
        match step {
            Step::Both => {
                lines.push(DiffLine::Same(after_insns[j].to_string()));
                removed = None;
                i += 1;
                j += 1;
            }
            Step::Left => {
                lines.push(DiffLine::Removed(before_insns[i].to_string()));
                removed = Some(&before_insns[i]);
                i += 1;
            }
            Step::Right => {
                let added = &after_insns[j];
                let difference = removed
                    .take()
                    .map(|left| difference(before_arch, left, after_arch, added, FrameSlots::Stay));
                let line = match (difference, lines.pop()) {
                    (Some(Difference::FreeChoices), Some(DiffLine::Removed(_))) => {
                        DiffLine::Same(added.to_string())
                    }
                    (Some(Difference::Values), Some(DiffLine::Removed(before))) => {
                        DiffLine::Changed { before, after: added.to_string() }
                    }
                    (_, last) => {
                        lines.extend(last);
                        DiffLine::Added(added.to_string())
                    }
                };
                lines.push(line);
                j += 1;
            }
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bit-parallel table walks as the table of cells does, ties and
    /// all, on runs of every length across the edges of a word.
    #[test]
    fn the_bit_table_walks_as_the_cell_table() {
        bolero::check!().with_type::<(Vec<u8>, Vec<u8>)>().for_each(|(left, right)| {
            // Few distinct items, so that ties are many.
            let left: Vec<u32> = left.iter().map(|&item| u32::from(item % 5)).collect();
            let right: Vec<u32> = right.iter().map(|&item| u32::from(item % 5)).collect();
            assert_eq!(
                longest_common_subsequence_of_numbers(&left, &right, 5),
                longest_common_subsequence(&left, &right),
                "{left:?} {right:?}"
            );
        });
        // Runs of up to 300 items, which span several words.
        let mut seed = 0x9e37_79b9_u32;
        let mut next = |below: u32| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed % below
        };
        for _ in 0..200 {
            let (left_len, right_len) = (next(300), next(300));
            let left: Vec<u32> = (0..left_len).map(|_| next(6)).collect();
            let right: Vec<u32> = (0..right_len).map(|_| next(6)).collect();
            assert_eq!(
                longest_common_subsequence_of_numbers(&left, &right, 6),
                longest_common_subsequence(&left, &right)
            );
        }
        let long: Vec<u32> = (0..200).map(|index| index % 7).collect();
        let other: Vec<u32> = (0..190).map(|index| (index * 3) % 7).collect();
        assert_eq!(
            longest_common_subsequence_of_numbers(&long, &other, 7),
            longest_common_subsequence(&long, &other)
        );
    }
    use crate::arch::InsnKind;
    use crate::arch::arm32::Arm32;
    use crate::norm::normalize;

    /// Instructions written by hand, by name, with no bytes: each
    /// normalizes by its opcode alone, which is all these tests compare.
    fn body(names: &[&str]) -> Vec<NormInsn> {
        names
            .iter()
            .map(|name| normalize(&Arm32, &crate::arch::arm32::test_insn(name, InsnKind::Normal)))
            .collect()
    }

    #[test]
    fn a_body_is_identical_to_itself() {
        let only = body(&["add", "mul"]);
        assert_eq!(similarity(&only, &only), 1.0);
    }

    #[test]
    fn two_empty_bodies_are_identical() {
        assert_eq!(similarity(&[], &[]), 1.0);
    }

    #[test]
    fn an_empty_body_shares_nothing_with_a_full_one() {
        assert_eq!(similarity(&[], &body(&["add"])), 0.0);
    }

    #[test]
    fn similarity_does_not_depend_on_the_order_of_its_arguments() {
        let left = body(&["add", "mul"]);
        let right = body(&["add", "sub"]);
        assert_eq!(similarity(&left, &right), similarity(&right, &left));
    }

    /// Reordering the same instructions is not the same as editing them.
    #[test]
    fn reordering_is_told_apart_from_editing() {
        let original = body(&["mov", "mvn", "cmp"]);
        let moved = body(&["mvn", "cmp", "mov"]);
        let edited = body(&["mov", "ldr", "cmp"]);

        let mut original_sorted = original.clone();
        let mut moved_sorted = moved.clone();
        let mut edited_sorted = edited;
        original_sorted.sort();
        moved_sorted.sort();
        edited_sorted.sort();

        assert_eq!(original_sorted, moved_sorted, "the same instructions, moved");
        assert_ne!(original_sorted, edited_sorted, "a replaced instruction is a real change");
    }

    /// A changed word of data must not be reported as unchanged.
    ///
    /// Data stored among instructions decodes as one, so normalizing buckets
    /// its operands and loses the difference. Measured on a vendor kernel
    /// image: the stored kernel size `0x2b08a8` decoded as
    /// `eoreq r0, fp, r8, lsr 17`, and when the next release changed it to
    /// `0x2b3c48` the function was called unchanged. Three of eleven real
    /// changes were missed that way.
    #[test]
    fn a_changed_data_word_is_not_called_unchanged() {
        // The two encodings of that kernel size field, as they lift:
        // `eoreq r0, fp, r8, lsr 17` and `eoreq r3, fp, r8, asr 24`.
        let lift = |word: u32| {
            Arm32.lift(&Arm32.decode(&word.to_le_bytes(), 0, 0).expect("decodes")).expect("lifts")
        };
        let (before, after) = (lift(0x002b_08a8), lift(0x002b_3c48));
        assert!(
            !operands_are_interchangeable(
                &before.operands,
                &after.operands,
                TargetMoves::Never,
                AddressMoves::Never
            ),
            "a shift that changed is not a register that changed"
        );
    }

    fn r(number: u8) -> il::Operand {
        il::Operand::Reg(il::Reg::General(number))
    }

    /// A register the compiler picked differently is not an edit.
    #[test]
    fn a_changed_register_is_not_a_change() {
        assert!(operands_are_interchangeable(
            &[r(0), r(1), r(2)],
            &[r(4), r(5), r(6)],
            TargetMoves::Never,
            AddressMoves::Never
        ));
    }

    /// A call whose callee moved is not an edit.
    ///
    /// Anything that changes size shifts every target after it, so a whole
    /// image of unedited functions would otherwise read as changed.
    #[test]
    fn a_moved_branch_target_is_not_a_change() {
        assert!(operands_are_interchangeable(
            &[il::Operand::Target(Some(0x50_a734))],
            &[il::Operand::Target(Some(0x50_b2d4))],
            TargetMoves::Freely,
            AddressMoves::Never
        ));
    }

    /// A target on an instruction that does not branch is data, as an
    /// address `adr` forms, and a changed one must stay visible.
    #[test]
    fn a_target_that_is_not_a_branch_stays_a_change() {
        assert!(!operands_are_interchangeable(
            &[il::Operand::Target(Some(0x50_a734))],
            &[il::Operand::Target(Some(0x50_b2d4))],
            TargetMoves::Never,
            AddressMoves::Never
        ));
    }

    /// Allowing targets to move must not let anything else move with them.
    #[test]
    fn a_branch_still_reports_its_other_operands() {
        assert!(!operands_are_interchangeable(
            &[r(0), il::Operand::Const(0x10)],
            &[r(0), il::Operand::Const(0x20)],
            TargetMoves::Freely,
            AddressMoves::Never
        ));
    }

    /// An access through `base` plus `offset`.
    fn at(base: u8, offset: i64) -> il::Operand {
        il::Operand::memory(Some(il::Reg::General(base)), Some(offset))
    }

    /// A constant that is part of an address on both sides moves with the
    /// linker, so it is not an edit.
    #[test]
    fn a_moved_address_is_not_a_change() {
        assert!(operands_are_interchangeable(
            &[r(2), il::Operand::Const(0x806f)],
            &[r(2), il::Operand::Const(0x8070)],
            TargetMoves::Never,
            AddressMoves::Freely
        ));
        assert!(operands_are_interchangeable(
            &[r(7), at(16, 0x1aa0)],
            &[r(7), at(16, -0x4560)],
            TargetMoves::Never,
            AddressMoves::Freely
        ));
    }

    /// The same constants, when either side is a value, stay a change.
    #[test]
    fn a_changed_value_is_still_a_change() {
        assert!(!operands_are_interchangeable(
            &[r(2), il::Operand::Const(0x806f)],
            &[r(2), il::Operand::Const(0x8070)],
            TargetMoves::Never,
            AddressMoves::Never
        ));
        assert!(!operands_are_interchangeable(
            &[r(2), at(2, 0x3c0)],
            &[r(2), at(2, 0x3c8)],
            TargetMoves::Never,
            AddressMoves::Never
        ));
    }

    /// An address may move, but not the register it is read through.
    #[test]
    fn a_moved_address_through_another_register_is_a_change() {
        assert!(!operands_are_interchangeable(
            &[r(7), at(16, 0x1aa0)],
            &[r(7), at(17, 0x1aa0)],
            TargetMoves::Never,
            AddressMoves::Freely
        ));
    }

    /// Two lists of operands of different lengths are different work.
    #[test]
    fn a_changed_count_of_operands_is_a_change() {
        assert!(!operands_are_interchangeable(
            &[r(0), r(1)],
            &[r(0), r(1), r(2)],
            TargetMoves::Freely,
            AddressMoves::Freely
        ));
    }

    /// A list the allocator filled with other registers is the same work,
    /// but a list that now loads the program counter returns.
    #[test]
    fn a_register_list_is_a_free_choice_but_not_its_return() {
        let list = |regs: &[il::Reg]| il::Operand::RegisterList(regs.iter().copied().collect());
        let (r4, r5, r6, r7) =
            (il::Reg::General(4), il::Reg::General(5), il::Reg::General(6), il::Reg::General(7));
        let pc = il::Reg::ProgramCounter;
        let interchangeable = |left: &[il::Reg], right: &[il::Reg]| {
            operands_are_interchangeable(
                &[list(left)],
                &[list(right)],
                TargetMoves::Never,
                AddressMoves::Never,
            )
        };
        assert!(interchangeable(&[r4, r6, r7, pc], &[r4, r5, r6, pc]));
        assert!(!interchangeable(&[r4, r6, r7, pc], &[r4, r5, r6, r7]));
        assert!(!interchangeable(&[r4, r6, pc], &[r4, r5, r6, pc]));
    }

    /// Only one side being an address is not enough to let it move.
    #[test]
    fn an_address_on_one_side_only_does_not_move() {
        assert_eq!(
            AddressMoves::from((&ConstantKind::Address, &ConstantKind::Value)),
            AddressMoves::Never
        );
        assert_eq!(
            AddressMoves::from((&ConstantKind::Value, &ConstantKind::Address)),
            AddressMoves::Never
        );
        assert_eq!(
            AddressMoves::from((&ConstantKind::Address, &ConstantKind::Address)),
            AddressMoves::Freely
        );
    }

    /// A condition code is the compiler's choice, not an edit.
    ///
    /// `movwlt` against `movwlo` is signed against unsigned less-than. Both
    /// appear for the same source at different optimization levels, and
    /// reporting it as a change cried wolf on the test corpus.
    #[test]
    fn a_changed_condition_is_not_a_change() {
        let decode = |word: u32| Arm32.decode(&word.to_le_bytes(), 0, 0).expect("decodes");
        // movwlt r0, #1 and movwlo r0, #1.
        let (signed, unsigned) = (decode(0xb300_0001), decode(0x3300_0001));
        assert_ne!(signed.to_string(), unsigned.to_string());
        assert_eq!(Arm32.operation_name(&signed), Arm32.operation_name(&unsigned));
    }

    #[test]
    fn a_reordering_still_counts_as_a_change_to_report() {
        assert!(Changed::Reordered > Changed::No);
        assert!(Changed::Yes > Changed::InDetail);
        assert!(Changed::Unreadable > Changed::InDetail);
        assert!(Changed::Yes > Changed::Unreadable);
    }

    /// `(unknown) 0xf26206e0` then `bx lr`, as NEON decodes.
    const OPAQUE_WORD: &[u8] = &[0xe0, 0x06, 0x62, 0xf2, 0x1e, 0xff, 0x2f, 0xe1];
    /// The same word changed: `(unknown) 0xf26206f0`.
    const OPAQUE_WORD_EDITED: &[u8] = &[0xf0, 0x06, 0x62, 0xf2, 0x1e, 0xff, 0x2f, 0xe1];
    /// `sub r0, r1, r0` then `bx lr`, which the decoder reads.
    const SUB_THEN_RETURN: &[u8] = &[0x00, 0x00, 0x41, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];

    /// A difference the decoder cannot read is reported as exactly that.
    ///
    /// Two opaque words that differ share no instruction but the return, so
    /// pairing them needs a permissive threshold. What the pair is called
    /// once it exists is the point here.
    #[test]
    fn an_unreadable_difference_is_told_apart_from_an_edit() {
        let before = binary_of(&[("f", OPAQUE_WORD)]);
        let after = binary_of(&[("f", OPAQUE_WORD_EDITED)]);
        let diff = diff_with(&before, &after, Options { threshold: 0.0, use_names: UseNames::No });
        let pair = diff.matched.first().expect("a threshold of zero pairs anything");
        assert_eq!(pair.changed, Changed::Unreadable);
    }

    /// A difference in readable code stays a plain change, so the new variant
    /// does not swallow the edits a reader came for.
    ///
    /// These two share only their return, so pairing them needs a threshold
    /// low enough to accept a weak match. The classification under test runs
    /// once a pair exists, whatever justified it.
    #[test]
    fn a_readable_edit_is_not_called_unreadable() {
        let before = binary_of(&[("f", ADD_THEN_RETURN)]);
        let after = binary_of(&[("f", SUB_THEN_RETURN)]);
        let diff = diff_with(&before, &after, Options { threshold: 0.0, use_names: UseNames::No });
        let pair = diff.matched.first().expect("a threshold of zero pairs anything");
        assert_eq!(pair.changed, Changed::Yes);
    }

    /// Counting an edit that rewrote one instruction in place.
    #[test]
    fn an_edit_counts_the_instructions_it_rewrote() {
        let edits = edits_between(ADD_THEN_RETURN, SUB_THEN_RETURN);
        assert_eq!(edits, Edits { added: 0, removed: 0, edited: 1 });
        assert!(edits.same_length(), "nothing was added or removed");
        assert_eq!(edits.total(), 1);
    }

    /// An edit that grew the function counts what it added.
    #[test]
    fn an_edit_counts_the_instructions_it_added() {
        // `add` then `add` then `bx lr`, against `add` then `bx lr`.
        let longer: &[u8] =
            &[0x00, 0x00, 0x81, 0xe0, 0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
        let edits = edits_between(ADD_THEN_RETURN, longer);
        assert_eq!(edits.added, 1, "one instruction appeared");
        assert_eq!(edits.removed, 0);
        assert!(!edits.same_length());
    }

    /// The same comparison reversed must report a removal, not an addition.
    #[test]
    fn an_edit_counts_the_instructions_it_removed() {
        let longer: &[u8] =
            &[0x00, 0x00, 0x81, 0xe0, 0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
        let edits = edits_between(longer, ADD_THEN_RETURN);
        assert_eq!(edits.removed, 1, "one instruction went away");
        assert_eq!(edits.added, 0);
    }

    /// An instruction inserted near the top must cost one addition, not a
    /// rewrite of everything after it.
    ///
    /// Counting position by position made the insertion shift every later
    /// instruction against a different one, so a one-line edit was reported as
    /// a wholly rewritten body. Aligning the two bodies first is what keeps the
    /// count honest.
    #[test]
    fn an_insertion_does_not_make_the_rest_look_rewritten() {
        // `add`, `mul`, `sub`, `bx lr`, against the same with a `mov` in front.
        let before: &[u8] = &[
            0x00, 0x00, 0x81, 0xe0, // add r0, r1, r0
            0x91, 0x00, 0x00, 0xe0, // mul r0, r1, r0
            0x00, 0x00, 0x41, 0xe0, // sub r0, r1, r0
            0x1e, 0xff, 0x2f, 0xe1, // bx lr
        ];
        let after: &[u8] = &[
            0x01, 0x00, 0xa0, 0xe3, // mov r0, 1
            0x00, 0x00, 0x81, 0xe0, // add r0, r1, r0
            0x91, 0x00, 0x00, 0xe0, // mul r0, r1, r0
            0x00, 0x00, 0x41, 0xe0, // sub r0, r1, r0
            0x1e, 0xff, 0x2f, 0xe1, // bx lr
        ];

        let edits = edits_between(before, after);
        assert_eq!(edits, Edits { added: 1, removed: 0, edited: 0 });
        assert_eq!(edits.total(), 1, "one instruction appeared, none was rewritten");
    }

    /// A moved instruction costs one addition and one removal.
    ///
    /// Measured on the test corpus: `switch_dense` moves a single `mov` three
    /// places down between `-O1` and `-O2`, which the position-by-position
    /// count reported as three rewritten instructions.
    #[test]
    fn a_moved_instruction_is_not_counted_as_three_rewrites() {
        let before: &[u8] = &[
            0x01, 0x30, 0xa0, 0xe3, // mov r3, 1
            0x00, 0x00, 0x81, 0xe0, // add r0, r1, r0
            0x91, 0x00, 0x00, 0xe0, // mul r0, r1, r0
            0x1e, 0xff, 0x2f, 0xe1, // bx lr
        ];
        let after: &[u8] = &[
            0x00, 0x00, 0x81, 0xe0, // add r0, r1, r0
            0x91, 0x00, 0x00, 0xe0, // mul r0, r1, r0
            0x01, 0x30, 0xa0, 0xe3, // mov r3, 1
            0x1e, 0xff, 0x2f, 0xe1, // bx lr
        ];

        let edits = edits_between(before, after);
        assert_eq!(edits.edited, 0, "nothing was rewritten, one instruction moved");
        assert_eq!(edits.added, 1);
        assert_eq!(edits.removed, 1);
    }

    /// A changed constant is reported by `Changed::InDetail`, not by the edit
    /// counts.
    ///
    /// The `+/-/~` column counts instructions whose shape moved. Normalizing
    /// hides a constant on purpose, so a threshold that changed value leaves
    /// every instruction in place and the counts stay clean. The CLI relies on
    /// this to hide such a pair unless asked for it.
    #[test]
    fn a_changed_constant_touches_no_instruction() {
        // `mov r0, 1` then `bx lr`, against `mov r0, 2` then `bx lr`.
        let before: &[u8] = &[0x01, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1];
        let after: &[u8] = &[0x02, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1];

        assert_eq!(edits_between(before, after), Edits::default());
    }

    /// `cmp r0, 0` then `bx lr`, the body the kind tests start from.
    const COMPARE_THEN_RETURN: &[u8] = &[0x00, 0x00, 0x50, 0xe3, 0x1e, 0xff, 0x2f, 0xe1];

    /// A gate the later build added is reported as a branch.
    #[test]
    fn an_added_branch_is_classified_as_control_flow() {
        // The same body with a `beq` after the compare.
        let with_branch: &[u8] = &[
            0x00, 0x00, 0x50, 0xe3, // cmp r0, 0
            0x02, 0x00, 0x00, 0x0a, // beq
            0x1e, 0xff, 0x2f, 0xe1, // bx lr
        ];

        let kinds = kinds_between(COMPARE_THEN_RETURN, with_branch);
        assert_eq!(kinds.branches, 1, "the added instruction was a branch");
        assert_eq!(kinds.constants, 0, "no stored value changed");
        assert!(kinds.touches_control_flow());
    }

    /// A call the later build added is told apart from a branch.
    #[test]
    fn an_added_call_is_classified_as_a_call() {
        let with_call: &[u8] = &[
            0x00, 0x00, 0x50, 0xe3, // cmp r0, 0
            0x03, 0x00, 0x00, 0xeb, // bl
            0x1e, 0xff, 0x2f, 0xe1, // bx lr
        ];

        let kinds = kinds_between(COMPARE_THEN_RETURN, with_call);
        assert_eq!(kinds.calls, 1);
        assert_eq!(kinds.branches, 0, "a call is not a branch");
    }

    /// A load the later build added is reported as memory, not control flow.
    #[test]
    fn an_added_load_is_classified_as_memory() {
        let with_load: &[u8] = &[
            0x00, 0x00, 0x50, 0xe3, // cmp r0, 0
            0x00, 0x10, 0x90, 0xe5, // ldr r1, [r0]
            0x1e, 0xff, 0x2f, 0xe1, // bx lr
        ];

        let kinds = kinds_between(COMPARE_THEN_RETURN, with_load);
        assert_eq!(kinds.memory, 1);
        assert!(!kinds.touches_control_flow(), "a load changes no control flow");
    }

    /// A changed constant is reported on its own, with no instruction touched.
    ///
    /// This is the case the edit counts deliberately leave out, so the kinds
    /// are the only place it appears.
    #[test]
    fn a_changed_constant_is_classified_as_a_constant() {
        // `mov r0, 1` then `bx lr`, against `mov r0, 2` then `bx lr`.
        let before: &[u8] = &[0x01, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1];
        let after: &[u8] = &[0x02, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1];

        let kinds = kinds_between(before, after);
        assert_eq!(kinds.constants, 1);
        assert_eq!(edits_between(before, after), Edits::default(), "no instruction moved");
        assert!(!kinds.touches_control_flow());
    }

    /// An edit that both adds a branch and changes a constant reports both.
    ///
    /// This is what the severity axis cannot say: [`Changed::Yes`] covers the
    /// whole edit, and the constant change disappears into it.
    #[test]
    fn an_edit_that_adds_code_and_changes_a_value_reports_both() {
        // `mov r0, 1` then `bx lr`.
        let before: &[u8] = &[0x01, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1];
        // `mov r0, 2`, a `beq`, then `bx lr`.
        let after: &[u8] = &[
            0x02, 0x00, 0xa0, 0xe3, // mov r0, 2
            0x02, 0x00, 0x00, 0x0a, // beq
            0x1e, 0xff, 0x2f, 0xe1, // bx lr
        ];

        let kinds = kinds_between(before, after);
        assert_eq!(kinds.branches, 1, "the added branch is visible");
        assert_eq!(kinds.constants, 1, "and so is the changed value");
    }

    /// The kinds of the moved instructions sum to what the counts reported.
    ///
    /// Constants stand outside that sum, because such an instruction stayed in
    /// place.
    #[test]
    fn the_kinds_account_for_every_instruction_counted() {
        let with_branch: &[u8] = &[
            0x00, 0x00, 0x50, 0xe3, // cmp r0, 0
            0x02, 0x00, 0x00, 0x0a, // beq
            0x00, 0x10, 0x90, 0xe5, // ldr r1, [r0]
            0x1e, 0xff, 0x2f, 0xe1, // bx lr
        ];

        let edits = edits_between(COMPARE_THEN_RETURN, with_branch);
        let kinds = kinds_between(COMPARE_THEN_RETURN, with_branch);
        let counted: usize =
            kinds.present().filter(|(kind, _)| *kind != EditKind::Constant).map(|(_, n)| n).sum();

        assert_eq!(counted, edits.total(), "every touched instruction has a kind");
    }

    /// A pair too large to align is still counted, without the table.
    ///
    /// The alignment table is quadratic. A vendor kernel holds functions of
    /// about twenty thousand instructions, where the table asks for over
    /// three gigabytes and the process is killed. Such a pair must fall back
    /// rather than bring the run down.
    #[test]
    fn a_pair_too_large_to_align_is_still_counted() {
        let cells = |left: usize, right: usize| (left + 1) * (right + 1);
        assert!(cells(19926, 19872) > LARGEST_ALIGNMENT, "a whole-kernel pair is over the limit");
        assert!(cells(500, 500) <= LARGEST_ALIGNMENT, "an ordinary function is well under it");

        // One instruction rewritten, in bodies past the alignment limit.
        let left = vec![body(&["add"])[0].clone(); 5000];
        let mut right = left.clone();
        right[0] = body(&["sub"])[0].clone();
        assert!(
            cells(left.len(), right.len()) > LARGEST_ALIGNMENT,
            "the test bodies are over the limit"
        );

        let (edits, kinds) = count_edits(&left, &right);
        assert_eq!(edits, Edits { added: 0, removed: 0, edited: 1 });
        assert_eq!(kinds.other, 1, "the rewritten instruction is classified");
    }

    /// Check that `steps` is an alignment of the two sequences: it walks
    /// both to the end and keeps only equal items. Return how many it kept.
    fn kept_by<T: PartialEq + core::fmt::Debug>(left: &[T], right: &[T], steps: &[Step]) -> usize {
        let (mut i, mut j, mut kept) = (0, 0, 0);
        for step in steps {
            match step {
                Step::Both => {
                    assert_eq!(left[i], right[j], "a kept pair must be equal");
                    (i, j, kept) = (i + 1, j + 1, kept + 1);
                }
                Step::Left => i += 1,
                Step::Right => j += 1,
            }
        }
        assert_eq!((i, j), (left.len(), right.len()), "the alignment must walk both sides");
        kept
    }

    /// The table without its shared head gives the same walk as the full
    /// table, step for step.
    #[test]
    fn a_shared_head_aligns_as_the_full_table_does() {
        fn full_table(left: &[u64], right: &[u64]) -> Vec<Step> {
            let mut len = vec![vec![0usize; right.len() + 1]; left.len() + 1];
            for i in (0..left.len()).rev() {
                for j in (0..right.len()).rev() {
                    len[i][j] = if left[i] == right[j] {
                        len[i + 1][j + 1] + 1
                    } else {
                        len[i + 1][j].max(len[i][j + 1])
                    };
                }
            }
            let (mut steps, mut i, mut j) = (Vec::new(), 0, 0);
            while i < left.len() && j < right.len() {
                if left[i] == right[j] {
                    steps.push(Step::Both);
                    (i, j) = (i + 1, j + 1);
                } else if len[i + 1][j] >= len[i][j + 1] {
                    steps.push(Step::Left);
                    i += 1;
                } else {
                    steps.push(Step::Right);
                    j += 1;
                }
            }
            steps.extend(core::iter::repeat_n(Step::Left, left.len() - i));
            steps.extend(core::iter::repeat_n(Step::Right, right.len() - j));
            steps
        }

        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = |limit: u64| {
            state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            (state >> 33) % limit
        };
        for _ in 0..2000 {
            let alphabet = 1 + next(6);
            let head: Vec<u64> = (0..next(8)).map(|_| next(alphabet)).collect();
            let left: Vec<u64> =
                head.iter().copied().chain((0..next(12)).map(|_| next(alphabet))).collect();
            let right: Vec<u64> =
                head.iter().copied().chain((0..next(12)).map(|_| next(alphabet))).collect();
            assert_eq!(
                longest_common_subsequence(&left, &right),
                full_table(&left, &right),
                "{left:?} {right:?}"
            );
        }
    }

    /// Any two sequences align validly by anchors, and never keep more
    /// than the exact alignment does.
    #[test]
    fn anchors_align_any_two_sequences() {
        // A small linear congruential generator keeps the test repeatable.
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = |limit: u64| {
            state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            (state >> 33) % limit
        };
        for _ in 0..500 {
            let alphabet = 1 + next(40);
            let left: Vec<u64> = (0..next(60)).map(|_| next(alphabet)).collect();
            let right: Vec<u64> = (0..next(60)).map(|_| next(alphabet)).collect();
            let exact = kept_by(&left, &right, &longest_common_subsequence(&left, &right));
            for largest in [0, 16, 200] {
                let kept = kept_by(&left, &right, &align_within(&left, &right, largest));
                assert!(kept <= exact, "{left:?} {right:?}");
            }
        }
    }

    /// An instruction inserted at the top of a function too large for the
    /// table costs one addition, not a rewrite of every one after it.
    #[test]
    fn an_insertion_into_a_large_body_costs_one_addition() {
        let left: Vec<u32> = (0..1000).collect();
        let right: Vec<u32> = core::iter::once(5000).chain(0..1000).collect();
        let steps = align_within(&left, &right, 100);
        assert_eq!(kept_by(&left, &right, &steps), 1000);
        assert_eq!(steps.iter().filter(|step| **step == Step::Right).count(), 1);
    }

    #[test]
    fn the_chain_keeps_the_longest_run_in_order() {
        let seeds = [(0, 3), (1, 0), (2, 1), (3, 4), (4, 2), (5, 5)];
        assert_eq!(longest_increasing_chain(&seeds), vec![(1, 0), (2, 1), (4, 2), (5, 5)]);
        assert_eq!(longest_increasing_chain(&[]), vec![]);
    }

    /// A function compared with itself has nothing to count.
    #[test]
    fn an_unedited_function_counts_no_edits() {
        let edits = edits_between(ADD_THEN_RETURN, ADD_THEN_RETURN);
        assert_eq!(edits, Edits::default());
        assert_eq!(edits.total(), 0);
    }

    /// Count the edits between two one-function images.
    ///
    /// A threshold of zero pairs the two whatever they score, so a test can
    /// measure the count without first arguing that the pair is a good one.
    fn edits_between(before: &[u8], after: &[u8]) -> Edits {
        let before = binary_of(&[("f", before)]);
        let after = binary_of(&[("f", after)]);
        let diff = diff_with(&before, &after, Options { threshold: 0.0, use_names: UseNames::No });
        diff.matched.first().expect("a threshold of zero pairs anything").edits
    }

    /// Classify the edits between two one-function images.
    fn kinds_between(before: &[u8], after: &[u8]) -> EditKinds {
        let before = binary_of(&[("f", before)]);
        let after = binary_of(&[("f", after)]);
        let diff = diff_with(&before, &after, Options { threshold: 0.0, use_names: UseNames::No });
        diff.matched.first().expect("a threshold of zero pairs anything").kinds
    }

    /// Building a `Binary` by hand keeps these tests free of fixture files.
    fn binary_of(functions: &[(&str, &[u8])]) -> crate::obj::Binary {
        crate::obj::Binary {
            isa: Isa::Arm32,
            found_by: crate::obj::FoundBy::Symbols,
            addresses: crate::address::AddressSpace::none(),
            links: crate::callee::Links::default(),
            other_set: std::collections::BTreeSet::new(),
            functions: functions
                .iter()
                .enumerate()
                .map(|(index, (name, code))| Function {
                    name: (*name).to_string(),
                    address: index as u64 * 0x100,
                    code: code.to_vec(),
                })
                .collect(),
        }
    }

    /// Two twins that each call one import through a PLT stub, the import
    /// that `names` gives for the stub at 0x200 and the one at 0x300, and
    /// placed at 0x0 and 0x100 in that order.
    fn twins_calling(names: [&str; 2]) -> crate::obj::Binary {
        /// The distance from an LLD PLT stub to the slot it jumps through.
        const TO_SLOT: u64 = 0x3ea34 - 0x1dd60;
        let bl = |from: u32, to: u32| 0xeb00_0000 | ((to.wrapping_sub(from + 8) / 4) & 0x00ff_ffff);
        let words = |words: &[u32]| -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        };
        let stub = words(&[0xe28f_c600, 0xe28c_ca20, 0xe5bc_fccc]);
        let codes = [
            words(&[0xe92d_4010, bl(0x4, 0x200), 0xe8bd_8010]),
            words(&[0xe92d_4010, bl(0x104, 0x300), 0xe8bd_8010]),
            stub.clone(),
            stub,
        ];
        let mut binary =
            binary_of(&[("", &codes[0]), ("", &codes[1]), ("", &codes[2]), ("", &codes[3])]);
        let memory = binary
            .functions
            .iter()
            .map(|function| (function.address, function.code.clone()))
            .collect();
        let slots = BTreeMap::from([
            (0x200 + TO_SLOT, names[0].to_string()),
            (0x300 + TO_SLOT, names[1].to_string()),
        ]);
        binary.links = crate::callee::Links::of_parts(memory, slots);
        binary
    }

    /// Twins in another order, as another compiler places them, pair by the
    /// import each calls rather than by their order.
    #[test]
    fn twins_pair_by_what_they_call() {
        let before = twins_calling(["exp", "log10"]);
        let after = twins_calling(["log10", "exp"]);
        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        let partner = |index: usize| {
            diff.matched.iter().find(|pair| pair.before == index).map(|pair| pair.after)
        };
        assert_eq!(partner(0), Some(1), "exp");
        assert_eq!(partner(1), Some(0), "log10");
        assert_eq!(diff.changed().count(), 0);
    }

    /// Where names are known, twins of one shape pair by name, however
    /// the other side orders them.
    #[test]
    fn twins_pair_by_name_where_names_are_known() {
        let returns = |value: u32| -> Vec<u8> {
            [0xe3a0_0000 | value, 0xe12f_ff1e].iter().flat_map(|word| word.to_le_bytes()).collect()
        };
        let before = binary_of(&[("first", &returns(1)), ("second", &returns(2))]);
        let after = binary_of(&[("second", &returns(4)), ("first", &returns(3))]);
        let diff = diff_with(&before, &after, Options::default());
        let partner = |index: usize| {
            diff.matched.iter().find(|pair| pair.before == index).map(|pair| pair.after)
        };
        assert_eq!(partner(0), Some(1), "first");
        assert_eq!(partner(1), Some(0), "second");
    }

    /// Twins that call the same import cannot be told apart by it, so the
    /// shape stage does not pair one of them with the only twin on the other
    /// side that calls it.
    #[test]
    fn a_callee_twins_share_does_not_pair_them() {
        let before = twins_calling(["exp", "exp"]);
        let after = twins_calling(["log10", "exp"]);
        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        let by_shape = diff
            .matched
            .iter()
            .filter(|pair| pair.before < 2 && pair.confidence == Confidence::IdenticalShape)
            .count();
        assert_eq!(by_shape, 0);
    }

    /// Twins that differ only in a constant pair by it, even where there
    /// are more twins than similarity keeps candidates for, and one side has
    /// one more.
    #[test]
    fn twins_pair_by_their_constants() {
        let returns = |value: u32| -> Vec<u8> {
            [0xe3a0_0000 | value, 0xe12f_ff1e].iter().flat_map(|word| word.to_le_bytes()).collect()
        };
        let before: Vec<Vec<u8>> = (1..=12).map(returns).collect();
        let after: Vec<Vec<u8>> = (1..=13).rev().map(returns).collect();
        let unnamed_before: Vec<(&str, &[u8])> =
            before.iter().map(|code| ("", code.as_slice())).collect();
        let unnamed_after: Vec<(&str, &[u8])> =
            after.iter().map(|code| ("", code.as_slice())).collect();
        let diff = diff_with(
            &binary_of(&unnamed_before),
            &binary_of(&unnamed_after),
            Options { use_names: UseNames::No, ..Default::default() },
        );
        for index in 0..12 {
            let partner = diff.matched.iter().find(|pair| pair.before == index).map(|p| p.after);
            assert_eq!(partner, Some(12 - index), "the function that returns {}", index + 1);
        }
        assert_eq!(diff.added, [0], "the one that returns 13");
    }

    #[test]
    fn a_short_text_counts_where_it_changed_in_place() {
        // Sorted, as a function holds them.
        let changed = short_texts_changed((&["%d", "no"], &["%d", "no"]), (&["%u", "no"], &["%u"]));
        assert_eq!(changed, 1, "`%d` became `%u`");
        let came = short_texts_changed((&["no"], &["no"]), (&["no", "yes"], &["no", "yes"]));
        assert_eq!(came, 0, "a text that came alone can be a merged tail");
        let unsure = short_texts_changed((&["!e"], &[]), (&["!f"], &[]));
        assert_eq!(unsure, 0, "neither is sure");
        let one_sure = short_texts_changed((&["%d"], &["%d"]), (&["!f"], &[]));
        assert_eq!(one_sure, 0, "the other side's is not sure");
    }

    #[test]
    fn an_il_shape_collapses_numbers_but_not_names() {
        assert_eq!(il_shape("w0 = w1 + 0x10"), il_shape("w0 = w1 + 0x20"));
        assert_eq!(il_shape("x0 = load.32 [x1 + 8]"), "x0 = load.# [x1 + #]");
        assert_eq!(il_key("if (w0 <= 3) goto $+0x40"), "if (w0 <= 3) goto $");
        assert_eq!(il_key("x8 = load.64 [@0x57c6]"), "x8 = load.64 [@]");
        assert_eq!(il_key("r2 = load.32 [pc + 0x5c]"), "r2 = load.32 [pc + ]");
        assert_eq!(il_key("store.64 [sp + 0x20] = x22, x21"), "store.64 [sp + ] = x22, x21");
        assert_eq!(il_key("sp = sp - 0x40"), "sp = sp - 0x40", "the frame size stays");
        assert_eq!(il_key("x1 = &\"usage\""), "x1 = &\"usage\"");
        assert_ne!(il_shape("w0 = w1 + 1"), il_shape("w0 = w1 - 1"));
    }

    /// The IL statements of the AArch64 `words`, with their instructions.
    fn il_side(words: &[u32]) -> IlSide<'static> {
        let arch: &dyn Arch = &crate::arch::aarch64::Aarch64;
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let insns = decode_all(arch, &code, 0x1000).0;
        IlSide::new(arch, &code, insns, None)
    }

    /// Fold the IL statements of `before` against those of `after`.
    fn fold_il(before: &[u32], after: &[u32], steps: &[Step]) -> Vec<DiffLine> {
        fold_il_runs(steps, &il_side(before), &il_side(after))
    }

    /// A statement where only a register changed is the same, and one where
    /// a constant changed is changed. A compare and its branch fold as a run.
    #[test]
    fn an_il_statement_folds_on_its_instruction() {
        const ADD_X3_X20_4: u32 = 0x9100_1283;
        const ADD_X3_X19_4: u32 = 0x9100_1263;
        const ADD_X3_X20_8: u32 = 0x9100_2283;
        let one_pair = [Step::Left, Step::Right];
        assert!(matches!(
            fold_il(&[ADD_X3_X20_4], &[ADD_X3_X19_4], &one_pair)[..],
            [DiffLine::Same(_)]
        ));
        assert!(matches!(
            fold_il(&[ADD_X3_X20_4], &[ADD_X3_X20_8], &one_pair)[..],
            [DiffLine::Changed { .. }]
        ));

        // `cmp x23, x0; b.ne` against `cmp x20, x0; b.ne`.
        const B_NE: u32 = 0x54ff_ff21;
        let folded = fold_il(
            &[0xeb00_02ff, B_NE],
            &[0xeb00_029f, B_NE],
            &[Step::Left, Step::Left, Step::Right, Step::Right],
        );
        assert!(folded.iter().all(|line| matches!(line, DiffLine::Same(_))), "{folded:?}");

        // `add w0, w1, 1` against `add w0, w1, 2; blr x1`.
        let grew = fold_il(
            &[0x1100_0420],
            &[0x1100_0820, 0xd63f_0020],
            &[Step::Left, Step::Right, Step::Right],
        );
        assert!(matches!(grew[..], [DiffLine::Changed { .. }, DiffLine::Added(_)]), "{grew:?}");
    }

    /// A call whose target moved is a free choice, but not where the IL
    /// view names another callee: the name is no word of the instruction.
    #[test]
    fn an_il_statement_with_another_callee_is_no_same_line() {
        let side = |word: u32, text: &str| {
            let mut side = il_side(&[word]);
            side.statements[0].text = text.to_string();
            side
        };
        // `bl` to two places.
        let (before, after) = (side(0x9400_0010, "call foo"), side(0x9400_0020, "call bar"));
        let folded = fold_il_runs(&[Step::Left, Step::Right], &before, &after);
        assert!(matches!(folded[..], [DiffLine::Removed(_), DiffLine::Added(_)]), "{folded:?}");
        let renamed = side(0x9400_0020, "call foo");
        let folded = fold_il_runs(&[Step::Left, Step::Right], &before, &renamed);
        assert!(matches!(folded[..], [DiffLine::Same(_)]), "{folded:?}");
    }

    #[test]
    fn texts_differ_by_what_they_do_not_share() {
        assert_eq!(texts_that_differ(&[], &[]), 0);
        assert_eq!(texts_that_differ(&["a", "b"], &["a", "b"]), 0);
        assert_eq!(texts_that_differ(&["a", "b"], &["a", "c"]), 1, "one changed in place");
        assert_eq!(texts_that_differ(&["a"], &["a", "b"]), 1, "one added");
        assert_eq!(texts_that_differ(&["a", "a"], &["a"]), 1, "a repeat counts");
        assert_eq!(texts_that_differ(&["a", "b"], &["c"]), 2);
    }

    #[test]
    fn a_text_that_differs_only_by_its_build_directory_is_no_change() {
        let apple = |root: &str| {
            format!(
                "/AppleInternal/Library/BuildRoots/{root}/Library/Sources/AppleHIDTransport/hid.cpp"
            )
        };
        let (old, new) = (apple("4~Bq7XzA9kLm2"), apple("7~Cv3YwD1nPo8"));
        assert!(differ_only_by_build_path(&old, &new));
        assert_eq!(texts_that_differ(&[old.as_str(), "x"], &[new.as_str(), "x"]), 0);
        assert!(differ_only_by_build_path(
            "/build/glibc-SzIz7B/malloc/malloc.c",
            "/build/glibc-Ab1cDe/malloc/malloc.c"
        ));
    }

    #[test]
    fn a_changed_file_or_message_still_shows() {
        let differ = differ_only_by_build_path;
        assert!(!differ("/src/file12.c", "/src/file34.c"), "a file name");
        assert!(!differ("/build/glibc-SzIz7B/a.c", "/build/glibc-Ab1cDe/b.c"), "another file too");
        assert!(!differ("/build/glibc-SzIz7B/a.c", "/build/glibc-Ab1cD/a.c"), "another length");
        assert!(!differ("bad length %d", "bad size %d"), "no path");
        assert!(!differ("/a/b", "/a/b"), "no difference");
        assert!(!differ("/a/b/c", "/a/b"), "another depth");
        assert_eq!(texts_that_differ(&["/src/file12.c"], &["/src/file34.c"]), 1);
    }

    /// One ARM function at 0x8000 that passes the text at 0x9001 on, with
    /// that text after a NUL.
    fn passes_text(text: &str) -> crate::obj::Binary {
        let words = [
            0xe59f_0004_u32, // 0x8000 ldr r0, [pc, 0x4]: the word at 0x800c
            0xe08f_0000,     // 0x8004 add r0, pc, r0
            0xe12f_ff1e,     // 0x8008 bx lr
            0x9001 - 0x800c, // 0x800c the distance to the text
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let data = [&[0], text.as_bytes(), &[0]].concat();
        crate::obj::Binary {
            isa: Isa::Arm32,
            found_by: crate::obj::FoundBy::Symbols,
            addresses: crate::address::AddressSpace::of_raw_image(0x8000, 0x880),
            other_set: std::collections::BTreeSet::new(),
            links: crate::callee::Links::of_parts(
                vec![(0x8000, code.clone()), (0x9000, data)],
                BTreeMap::new(),
            ),
            functions: vec![Function { name: "f".to_string(), address: 0x8000, code }],
        }
    }

    /// Code that stayed the same around a changed text changed in detail.
    #[test]
    fn a_changed_text_is_a_change() {
        let diff = diff_with(&passes_text("hello"), &passes_text("howdy"), Options::default());
        let pair = &diff.matched[0];
        assert_eq!(pair.changed, Changed::InDetail);
        assert_eq!(pair.kinds.texts, 1);

        let same = diff_with(&passes_text("hello"), &passes_text("hello"), Options::default());
        assert_eq!(same.matched[0].changed, Changed::No);
    }

    /// A text shorter than a word can be a pointer or a number by chance.
    #[test]
    fn a_changed_short_text_is_no_change() {
        let diff = diff_with(&passes_text("ab"), &passes_text("cd"), Options::default());
        assert_eq!(diff.matched[0].changed, Changed::No);
        assert_eq!(diff.matched[0].kinds.texts, 0);
    }

    /// A key counts as common where more than `MOST_HOLDERS_OF_AN_EDGE`
    /// functions hold it, and a repeat within one function counts once.
    #[test]
    fn a_key_is_common_past_the_most_holders() {
        let key = |name: &str| ReferenceKey::Named(name.to_string());
        let mut keys = vec![vec![key("kfree"), key("kfree"), key("rare")]];
        keys.extend((0..MOST_HOLDERS_OF_AN_EDGE - 1).map(|_| vec![key("kfree"), key("often")]));
        assert!(common_keys(&keys).is_empty(), "{} holders is not too many", keys.len());

        keys.push(vec![key("kfree")]);
        let common = common_keys(&keys);
        assert!(common.contains(&key("kfree")));
        assert!(!common.contains(&key("often")) && !common.contains(&key("rare")));
    }

    #[test]
    fn references_agree_by_what_they_share() {
        let key = |name: &str| ReferenceKey::Named(name.to_string());
        let (exp, log) = (key("exp"), key("log10"));
        assert_eq!(reference_agreement(&[], &[]), 0.0, "nothing to say");
        let (only_exp, only_log) = (core::slice::from_ref(&exp), core::slice::from_ref(&log));
        assert_eq!(reference_agreement(only_exp, only_exp), 1.0);
        assert_eq!(reference_agreement(only_exp, only_log), -1.0);
        assert_eq!(reference_agreement(only_exp, &[]), -1.0, "one calls, one does not");
        let (mut both, one) = (vec![exp.clone(), log], vec![exp]);
        both.sort();
        assert_eq!(reference_agreement(&both, &one), 0.0, "half shared");
        assert_eq!(
            reference_agreement(&[ReferenceKey::Paired(3)], &[ReferenceKey::Paired(3)]),
            1.0
        );
        let text = |text: &str| ReferenceKey::Text(text.to_string());
        assert_eq!(reference_agreement(&[text("<!--")], &[text("<!--")]), 1.0);
        assert_eq!(reference_agreement(&[text("<!--")], &[text("=\"")]), -1.0);
    }

    /// A MIPS table of pointers into its own image, after a `jr ra`.
    fn pointer_table(first: u32) -> Vec<u8> {
        let mut words = vec![0x03e0_0008u32, 0];
        words.extend((0..64).map(|index| first + index * 0x40));
        words.iter().flat_map(|word| word.to_be_bytes()).collect()
    }

    fn raw_mips(code: &[u8]) -> crate::obj::Binary {
        crate::obj::Binary {
            isa: Isa::Mips32Be,
            found_by: crate::obj::FoundBy::Scanning,
            addresses: AddressSpace::of_raw_image(0x8000_0000, 0x10_0000),
            links: crate::callee::Links::default(),
            other_set: std::collections::BTreeSet::new(),
            functions: vec![Function {
                name: String::new(),
                address: 0x8000_0000,
                code: code.to_vec(),
            }],
        }
    }

    /// A function that returns 1, at 0x80002000, big endian.
    fn returns_one() -> Function {
        let words = [0x2402_0001u32, 0x03e0_0008, 0];
        Function {
            name: String::new(),
            address: 0x8000_2000,
            code: words.iter().flat_map(|word| word.to_be_bytes()).collect(),
        }
    }

    /// `bl target` from `from`, little endian.
    fn bl(from: u64, target: u64) -> [u8; 4] {
        let offset = (target.wrapping_sub(from).wrapping_sub(8) as u32 >> 2) & 0x00ff_ffff;
        (0xeb00_0000 | offset).to_le_bytes()
    }

    /// `mov r0, value; bx lr`, little endian.
    fn returns(value: u8) -> Vec<u8> {
        [[value, 0x00, 0xa0, 0xe3], [0x1e, 0xff, 0x2f, 0xe1]].concat()
    }

    /// A caller at 0x0 that calls the function at `callee`, then returns.
    fn caller_of(callee: u64) -> Vec<u8> {
        [bl(0, callee).as_slice(), &[0x1e, 0xff, 0x2f, 0xe1]].concat()
    }

    /// Code that calls a different function changed, though normalizing
    /// alone reads it as the same, with or without names.
    #[test]
    fn a_call_to_a_different_function_is_a_change() {
        for names in [["caller", "one", "two"], ["", "", ""]] {
            let before = binary_of(&[
                (names[0], &caller_of(0x100)),
                (names[1], &returns(1)),
                (names[2], &returns(2)),
            ]);
            let after = binary_of(&[
                (names[0], &caller_of(0x200)),
                (names[1], &returns(1)),
                (names[2], &returns(2)),
            ]);
            let diff = diff_with(&before, &after, Options { threshold: 0.0, ..Options::default() });

            let caller = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
            assert_eq!(caller.changed, Changed::Yes, "names {names:?}");
            assert_eq!(caller.kinds.callees, 1, "names {names:?}");
            assert!(caller.kinds.touches_control_flow());
        }
    }

    /// Four leaves at 0x0 to 0x300 that pair by their bytes, and at 0x400 a
    /// function that calls the two at `callees`, then runs `work`.
    fn calling_two_leaves(callees: [u64; 2], work: &[u32]) -> crate::obj::Binary {
        let caller: Vec<u8> = [bl(0x400, callees[0]), bl(0x404, callees[1])]
            .into_iter()
            .flatten()
            .chain(work.iter().flat_map(|word| word.to_le_bytes()))
            .collect();
        let leaves = [returns(1), returns(2), returns(3), returns(4)];
        let [one, two, three, four] = &leaves;
        binary_of(&[("", one), ("", two), ("", three), ("", four), ("", &caller)])
    }

    /// A function whose callees all paired with what its look-alike does not
    /// call pairs with nothing; one that calls their partners pairs.
    #[test]
    fn a_pair_whose_paired_neighbours_disagree_is_undone() {
        let blind = Options { use_names: UseNames::No, ..Default::default() };
        let before = calling_two_leaves([0x000, 0x100], &[ADD, SUB, ORR, EOR, AND, BX_LR]);
        let edited = [ADD, SUB, ORR, EOR, BIC, BX_LR];

        let elsewhere = calling_two_leaves([0x200, 0x300], &edited);
        let diff = diff_with(&before, &elsewhere, blind);
        assert_eq!(
            (diff.removed.as_slice(), diff.added.as_slice()),
            ([4].as_slice(), [4].as_slice())
        );

        let same_callees = calling_two_leaves([0x000, 0x100], &edited);
        let diff = diff_with(&before, &same_callees, blind);
        let pair = diff.matched.iter().find(|pair| pair.before == 4).expect("paired");
        assert_eq!((pair.after, pair.confidence), (4, Confidence::Similar));
    }

    /// Two leaves at 0x0 and 0x100, three anchors from 0x200, and at 0x500,
    /// between the second and the third anchor, a function that calls the
    /// leaf at `callee`, then runs `work`.
    fn weak_pair_calling(callee: u64, work: &[u32]) -> crate::obj::Binary {
        let caller: Vec<u8> = bl(0x500, callee)
            .into_iter()
            .chain(work.iter().flat_map(|word| word.to_le_bytes()))
            .collect();
        let functions = [
            returns(1),
            returns(2),
            arm(&[ADC, SBC, RSB, BX_LR]),
            arm(&[MUL, MUL, ADC, BX_LR]),
            arm(&[RSB, RSB, BX_LR]),
            caller,
            arm(&[SBC, SBC, SBC, BX_LR]),
        ];
        let named: Vec<(&str, &[u8])> =
            functions.iter().map(|code| ("", code.as_slice())).collect();
        binary_of(&named)
    }

    /// A pair by place that scores low, whose one paired callee pairs with
    /// what its partner does not call, pairs with nothing.
    #[test]
    fn a_weak_pair_whose_one_paired_neighbour_disagrees_is_undone() {
        let blind = Options { use_names: UseNames::No, ..Default::default() };
        let before = weak_pair_calling(0x000, &[ADD, SUB, ORR, EOR, AND, BIC, BX_LR]);
        let rewritten = [ADD, MUL, MUL, MUL, MUL, MUL, BX_LR];

        let same_callee = weak_pair_calling(0x000, &rewritten);
        let diff = diff_with(&before, &same_callee, blind);
        let pair = diff.matched.iter().find(|pair| pair.before == 5).expect("paired");
        assert_eq!((pair.after, pair.confidence), (5, Confidence::SameLayout));
        assert!(pair.score < WEAK_PAIR_SIMILARITY, "{pair:?}");

        let other_callee = weak_pair_calling(0x100, &rewritten);
        let diff = diff_with(&before, &other_callee, blind);
        assert_eq!(
            (diff.removed.as_slice(), diff.added.as_slice()),
            ([5].as_slice(), [5].as_slice())
        );
    }

    /// Two leaves at 0x0 and 0x100, four anchors, and a function that calls
    /// the leaf at `callee`, then runs `work`: after the first anchor where
    /// `moved` is false, and after the last where it is true.
    fn similar_pair_calling(callee: u64, work: &[u32], moved: bool) -> crate::obj::Binary {
        let place: u64 = if moved { 6 } else { 3 };
        let caller: Vec<u8> = bl(place * 0x100, callee)
            .into_iter()
            .chain(work.iter().flat_map(|word| word.to_le_bytes()))
            .collect();
        let mut functions = vec![
            returns(1),
            returns(2),
            arm(&[ADC, SBC, RSB, BX_LR]),
            arm(&[MUL, MUL, ADC, BX_LR]),
            arm(&[RSB, RSB, BX_LR]),
            arm(&[SBC, SBC, SBC, BX_LR]),
        ];
        functions.insert(place as usize, caller);
        let named: Vec<(&str, &[u8])> =
            functions.iter().map(|code| ("", code.as_slice())).collect();
        binary_of(&named)
    }

    /// A pair by similarity whose sides sit in different places, and whose
    /// one paired callee pairs with what its partner does not call, pairs
    /// with nothing. In its place, or with the callee agreeing, it pairs.
    #[test]
    fn a_pair_out_of_place_whose_one_paired_neighbour_disagrees_is_undone() {
        let blind = Options { use_names: UseNames::No, ..Default::default() };
        let before = similar_pair_calling(0x000, &[ADD, SUB, ORR, EOR, AND, BX_LR], false);
        let edited = [ADD, SUB, ORR, EOR, BIC, BX_LR];
        let pair_of_caller = |after: &crate::obj::Binary| {
            let diff = diff_with(&before, after, blind);
            diff.matched
                .iter()
                .find(|pair| pair.before == 3)
                .map(|pair| (pair.after, pair.confidence))
        };

        assert_eq!(pair_of_caller(&similar_pair_calling(0x100, &edited, true)), None);
        assert_eq!(
            pair_of_caller(&similar_pair_calling(0x000, &edited, true)),
            Some((6, Confidence::Similar))
        );
        assert_eq!(
            pair_of_caller(&similar_pair_calling(0x100, &edited, false)),
            Some((3, Confidence::Similar))
        );
    }

    /// Each rule of `lacks_context`, on both sides of its bound.
    #[test]
    fn context_decides_by_stage_place_and_share() {
        use Confidence::{IdenticalShape, SameCallers, SameLayout, Similar};
        use Place::{Kept, Moved};
        // (stage, score, place, partners of the first side's neighbours,
        // the second side's neighbours, how many of those paired, undone)
        type Case = (Confidence, f64, Place, &'static [usize], &'static [usize], usize, bool);
        let cases: &[Case] = &[
            // Two disagreeing neighbours undo a pair by similarity anywhere.
            (Similar, 0.9, Kept, &[1, 2], &[3, 4], 2, true),
            // One is not enough in place, at a firm score.
            (Similar, 0.9, Kept, &[1], &[3], 1, false),
            // One is enough out of place, or at a weak score.
            (Similar, 0.9, Moved, &[1], &[3], 1, true),
            (SameLayout, 0.2, Kept, &[1], &[3], 1, true),
            // One that agrees keeps it.
            (Similar, 0.9, Moved, &[1, 2], &[2, 3], 2, false),
            // With no paired neighbour, nothing is said.
            (Similar, 0.2, Moved, &[], &[3], 0, false),
            // A pair by callers out of place goes under the share.
            (SameCallers, 0.5, Moved, &[1, 2, 3, 4], &[1, 5, 6, 7], 4, true),
            (SameCallers, 0.5, Moved, &[1, 2, 3], &[1, 5, 6], 3, false),
            (SameCallers, 0.5, Kept, &[1, 2, 3, 4], &[1, 5, 6, 7], 4, false),
            // A stronger stage stands.
            (IdenticalShape, 1.0, Moved, &[1, 2], &[3, 4], 2, false),
        ];
        for &(stage, score, place, left, right, paired_right, undone) in cases {
            let right: BTreeSet<usize> = right.iter().copied().collect();
            let context = Context {
                partners_of_left: left.iter().copied().collect(),
                right: &right,
                paired_right,
            };
            assert_eq!(
                lacks_context(stage, score, place, &context),
                undone,
                "{stage:?} {score} {place:?} {left:?} {right:?}"
            );
        }
    }

    /// `b target` from `from`, little endian.
    fn b(from: u64, target: u64) -> [u8; 4] {
        let offset = (target.wrapping_sub(from).wrapping_sub(8) as u32 >> 2) & 0x00ff_ffff;
        (0xea00_0000 | offset).to_le_bytes()
    }

    /// Two images where the function at 0x0 is `prefix` and then reaches
    /// the function at `callee` with `b`, and the callees share no code, so
    /// neither pairs.
    fn forwarding_to_unpaired(prefix: &[u8]) -> Diff {
        let reaching = |callee: u64| [prefix, &b(prefix.len() as u64, callee)].concat();
        // mov r0, 1; bx lr
        let one = returns(1);
        // add r0, r0, r1; mul r0, r1, r0; eor r0, r0, r1; sub r0, r0, r1:
        // nothing in common with `one`, so not even its place pairs it.
        let other: Vec<u8> = [0xe080_0001u32, 0xe000_0091, 0xe020_0001, 0xe040_0001]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let before = binary_of(&[("", &reaching(0x100)), ("", &one)]);
        let after = binary_of(&[("", &reaching(0x100)), ("", &other)]);
        diff_with(&before, &after, Options { threshold: 0.9, use_names: UseNames::No })
    }

    /// A forwarder that reaches a different function changed, even where
    /// neither callee pairs: what it reaches is all it does.
    #[test]
    fn a_forwarder_to_an_unpaired_callee_changed() {
        let diff = forwarding_to_unpaired(&[]);
        assert!(diff.removed.contains(&1) && diff.added.contains(&1), "neither callee pairs");
        let forwarder = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
        assert_eq!(forwarder.changed, Changed::Yes);
        assert_eq!(forwarder.kinds.callees, 1);
    }

    /// Larger code that reaches an unpaired callee says nothing about it:
    /// the callee may be one function that changed too much to pair.
    #[test]
    fn more_than_a_forwarder_says_nothing_of_an_unpaired_callee() {
        // add r2, r2, 1
        let diff = forwarding_to_unpaired(&0xe282_2001u32.to_le_bytes());
        let caller = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
        assert_eq!(caller.changed, Changed::No);
    }

    /// A callee that only moved is the same callee.
    #[test]
    fn a_call_to_a_moved_function_is_no_change() {
        for names in [["caller", "pad", "one"], ["", "", ""]] {
            let before = binary_of(&[(names[0], &caller_of(0x100)), (names[2], &returns(1))]);
            let after = binary_of(&[
                (names[0], &caller_of(0x200)),
                (names[1], &returns(7)),
                (names[2], &returns(1)),
            ]);
            let diff = diff_with(&before, &after, Options { threshold: 0.0, ..Options::default() });

            let caller = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
            assert_eq!(caller.changed, Changed::No, "names {names:?}");
            assert_eq!(caller.kinds.callees, 0, "names {names:?}");
        }
    }

    /// ARM words, little endian.
    fn arm(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    const ADD: u32 = 0xe080_0001;
    const SUB: u32 = 0xe040_0001;
    const ORR: u32 = 0xe180_0001;
    const EOR: u32 = 0xe020_0001;
    const AND: u32 = 0xe000_0001;
    const BIC: u32 = 0xe1c0_0001;
    const ADC: u32 = 0xe0a0_0001;
    const SBC: u32 = 0xe0c0_0001;
    const RSB: u32 = 0xe060_0001;
    const MUL: u32 = 0xe000_0091;
    const BX_LR: u32 = 0xe12f_ff1e;

    /// A function at 0x0 that calls the three at 0x100, 0x200 and 0x300,
    /// then runs `rest`.
    fn calls_three_then(rest: &[u32]) -> Vec<u8> {
        let calls: Vec<u32> = [0x100, 0x200, 0x300]
            .iter()
            .enumerate()
            .map(|(slot, &target)| u32::from_le_bytes(bl(slot as u64 * 4, target)))
            .collect();
        arm(&[calls.as_slice(), rest].concat())
    }

    /// Code at `base` that calls the functions at 0x100, 0x200 and 0x300,
    /// then runs `rest`.
    fn calls_three_from(base: u64, rest: &[u32]) -> Vec<u8> {
        let calls: Vec<u32> = [0x100, 0x200, 0x300]
            .iter()
            .enumerate()
            .map(|(slot, &target)| u32::from_le_bytes(bl(base + slot as u64 * 4, target)))
            .collect();
        arm(&[calls.as_slice(), rest].concat())
    }

    /// Of two free candidates with the same context and the same code,
    /// context joins neither; the function then pairs by its place.
    #[test]
    fn context_joins_neither_of_two_alike() {
        let before_code = calls_three_from(0, &[ADD, SUB, ORR, EOR, AND, BIC, ADC, SBC, BX_LR]);
        let after_code = |base| calls_three_from(base, &[ADD, SUB, MUL, BX_LR]);
        let [one, two, three] = [returns(1), returns(2), returns(3)];
        let before = binary_of(&[("", &before_code), ("", &one), ("", &two), ("", &three)]);
        let after = binary_of(&[
            ("", &after_code(0)),
            ("", &one),
            ("", &two),
            ("", &three),
            ("", &after_code(0x400)),
        ]);

        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        let pair = diff.matched.iter().find(|pair| pair.before == 0);
        assert_eq!(
            pair.map(|pair| (pair.after, pair.confidence)),
            Some((0, Confidence::SameLayout))
        );
    }

    /// A function rewritten past the threshold pairs with itself by the
    /// functions it calls, and not with a free look-alike that calls none.
    #[test]
    fn a_rewritten_function_pairs_by_its_context() {
        let before_code = calls_three_then(&[ADD, SUB, ORR, EOR, AND, BIC, ADC, SBC, BX_LR]);
        let after_code = calls_three_then(&[ADD, SUB, MUL, BX_LR]);
        let look_alike = arm(&[ADD, SUB, ORR, EOR, AND, BIC, ADC, SBC, BX_LR, RSB]);
        let [one, two, three] = [returns(1), returns(2), returns(3)];
        let before = binary_of(&[("", &before_code), ("", &one), ("", &two), ("", &three)]);
        let after = binary_of(&[
            ("", &after_code),
            ("", &one),
            ("", &two),
            ("", &three),
            ("", &look_alike),
        ]);

        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        let partner = diff.matched.iter().find(|pair| pair.before == 0).map(|pair| pair.after);
        assert_eq!(partner, Some(0));
        assert_eq!(diff.added, vec![4]);
    }

    /// A function rewritten past the threshold pairs with the one function
    /// that holds its constant, and not with a look-alike that lacks it.
    #[test]
    fn a_unique_constant_pairs_a_rewritten_function() {
        const MOVW_1234: u32 = 0xe301_0234;
        let before = binary_of(&[("", &arm(&[MOVW_1234, ADD, SUB, ORR, EOR, BX_LR]))]);
        let after = binary_of(&[
            ("", &arm(&[ADD, SUB, ORR, EOR, AND, BX_LR])),
            ("", &arm(&[MOVW_1234, ADD, MUL, MUL, MUL, BX_LR])),
        ]);

        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        let pair = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
        assert_eq!((pair.after, pair.confidence), (1, Confidence::SameReferences));
        assert_eq!(diff.added, vec![0]);
    }

    /// The one caller of a function already paired pairs with its one
    /// caller on the other side, though a look-alike scores higher.
    #[test]
    fn the_one_caller_of_a_paired_function_pairs() {
        let call = u32::from_le_bytes(bl(0, 0x100));
        let before =
            binary_of(&[("", &arm(&[call, ADD, SUB, ORR, EOR, BX_LR])), ("", &returns(1))]);
        let after = binary_of(&[
            ("", &arm(&[call, ADD, MUL, MUL, MUL, BX_LR])),
            ("", &returns(1)),
            ("", &arm(&[ADD, SUB, ORR, EOR, AND, BX_LR])),
        ]);

        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        let pair = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
        assert_eq!((pair.after, pair.confidence), (0, Confidence::SameReferences));
        assert_eq!(diff.added, vec![2]);
    }

    /// The one function that calls both of two paired functions pairs, where
    /// other functions call each of them alone.
    #[test]
    fn the_one_caller_of_a_set_of_paired_functions_pairs() {
        let call = |from: u64, to: u64| u32::from_le_bytes(bl(from, to));
        let calls_both = |rest: &[u32]| arm(&[&[call(0, 0x300), call(4, 0x400)], rest].concat());
        let calls_a = arm(&[call(0x100, 0x300), RSB, RSB, BX_LR]);
        let calls_b = arm(&[call(0x200, 0x400), BIC, BIC, BX_LR]);
        let [a, b] = [returns(1), returns(2)];
        let before = binary_of(&[
            ("", &calls_both(&[ADD, SUB, ORR, EOR, BX_LR])),
            ("", &calls_a),
            ("", &calls_b),
            ("", &a),
            ("", &b),
        ]);
        let after = binary_of(&[
            ("", &calls_both(&[ADD, MUL, MUL, MUL, BX_LR])),
            ("", &calls_a),
            ("", &calls_b),
            ("", &a),
            ("", &b),
            ("", &arm(&[ADD, SUB, ORR, EOR, AND, BX_LR])),
        ]);

        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        let pair = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
        assert_eq!((pair.after, pair.confidence), (0, Confidence::SameReferences));
        assert_eq!(diff.added, vec![5]);
    }

    /// A pair by name stays, though its constant moved to another function.
    #[test]
    fn a_unique_constant_does_not_break_a_pair_by_name() {
        const MOVW_1234: u32 = 0xe301_0234;
        let before = binary_of(&[("foo", &arm(&[MOVW_1234, ADD, SUB, ORR, EOR, BX_LR]))]);
        let after = binary_of(&[
            ("foo", &arm(&[ADD, SUB, ORR, EOR, AND, BX_LR])),
            ("bar", &arm(&[MOVW_1234, ADD, MUL, MUL, MUL, BX_LR])),
        ]);

        let diff = diff_with(&before, &after, Options::default());
        let pair = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
        assert_eq!((pair.after, pair.confidence), (0, Confidence::SameName));
        assert_eq!(diff.added, vec![1]);
    }

    /// A constant that two functions of one side hold tells neither apart.
    #[test]
    fn a_constant_held_twice_pairs_nothing() {
        const MOVW_1234: u32 = 0xe301_0234;
        let before = binary_of(&[
            ("", &arm(&[MOVW_1234, ADD, SUB, ORR, EOR, BX_LR])),
            ("", &arm(&[MOVW_1234, RSB, RSB, RSB, BX_LR])),
        ]);
        let after = binary_of(&[
            ("", &arm(&[ADD, SUB, ORR, EOR, AND, BX_LR])),
            ("", &arm(&[MOVW_1234, ADD, MUL, MUL, MUL, BX_LR])),
        ]);

        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        assert!(diff.matched.iter().all(|pair| pair.confidence != Confidence::SameReferences));
    }

    /// Code too far apart does not pair, whatever constant it shares.
    #[test]
    fn a_unique_constant_needs_some_code_in_common() {
        const MOVW_1234: u32 = 0xe301_0234;
        let before = binary_of(&[("", &arm(&[MOVW_1234, ADD, SUB, ORR, EOR, AND, BIC, BX_LR]))]);
        let after = binary_of(&[("", &arm(&[MOVW_1234, MUL, MUL, MUL, MUL, RSB, RSB, RSB]))]);

        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        assert!(diff.matched.iter().all(|pair| pair.confidence != Confidence::SameReferences));
    }

    /// Of two candidates that score the same, the one that keeps the
    /// constants pairs.
    #[test]
    fn a_shared_constant_breaks_a_tie() {
        const MOVW_1234: u32 = 0xe301_0234;
        const MOVW_5678: u32 = 0xe305_0678;
        let before = binary_of(&[("", &arm(&[MOVW_1234, ADD, SUB, BX_LR]))]);
        let after = binary_of(&[
            ("", &arm(&[MOVW_5678, ADD, SUB, ORR, BX_LR])),
            ("", &arm(&[MOVW_1234, ADD, SUB, EOR, BX_LR])),
        ]);

        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        assert_eq!(diff.matched.len(), 1);
        assert_eq!(diff.matched[0].after, 1);
    }

    #[test]
    fn constants_agree_by_what_they_share() {
        assert_eq!(constant_agreement(&[], &[]), 0.0);
        assert_eq!(constant_agreement(&[5, 9], &[5, 9]), 1.0);
        assert_eq!(constant_agreement(&[5], &[9]), -1.0);
        assert_eq!(constant_agreement(&[], &[9]), -1.0);
    }

    /// An addition few pairs share weighs more than one many pairs share,
    /// and an unchanged pair weighs nothing.
    #[test]
    fn a_rare_addition_weighs_more() {
        let before = binary_of(&[
            ("a", &arm(&[ADD, ORR, BX_LR])),
            ("b", &arm(&[ADD, EOR, BX_LR])),
            ("c", &arm(&[ADD, AND, BX_LR])),
            ("d", &arm(&[ADC, SBC, BX_LR])),
        ]);
        let after = binary_of(&[
            ("a", &arm(&[ADD, ORR, SUB, BX_LR])),
            ("b", &arm(&[ADD, EOR, SUB, BX_LR])),
            ("c", &arm(&[ADD, AND, MUL, BX_LR])),
            ("d", &arm(&[ADC, SBC, BX_LR])),
        ]);

        let diff = diff(&before, &after);
        let rarity = |index: usize| {
            diff.matched.iter().find(|pair| pair.before == index).map(|pair| pair.rarity)
        };
        // Three pairs changed. Two add `sub` and one adds `mul`.
        let close =
            |found: Option<f64>, expected: f64| (found.expect("paired") - expected).abs() < 1e-9;
        assert!(close(rarity(0), 1.0 + (4.0f64 / 3.0).ln()), "{:?}", rarity(0));
        assert!(close(rarity(1), 1.0 + (4.0f64 / 3.0).ln()));
        assert!(close(rarity(2), 1.0 + 2.0f64.ln()));
        assert_eq!(rarity(3), Some(0.0));
    }

    /// One copy weighs one, each more copy weighs less than the last, and
    /// no count passes `SATURATION + 1`.
    #[test]
    fn copies_of_an_addition_saturate() {
        assert!((saturated(1) - 1.0).abs() < 1e-12);
        let weights: Vec<f64> = (1..200).map(saturated).collect();
        for step in weights.windows(3) {
            assert!(step[1] > step[0], "more copies weigh more");
            assert!(step[2] - step[1] < step[1] - step[0], "each copy adds less");
        }
        assert!(weights.iter().all(|&weight| weight < SATURATION + 1.0));
    }

    #[test]
    fn only_in_counts_a_multiset() {
        assert_eq!(sorted_only_in(&[1, 2, 2, 3], &[2, 3, 4]), vec![1, 2]);
        assert_eq!(sorted_only_in::<u32>(&[], &[1]), Vec::<u32>::new());
        assert_eq!(sorted_only_in(&[5, 5], &[]), vec![5, 5]);
    }

    /// Of two candidates that rank the same, the similarity stage takes
    /// neither; with one clearly better, it takes that one.
    #[test]
    fn a_tie_between_candidates_pairs_neither() {
        let before = binary_of(&[("", &arm(&[ADD, SUB, ORR, EOR, BX_LR]))]);
        let tie = binary_of(&[
            ("", &arm(&[ADD, SUB, ORR, EOR, AND, BX_LR])),
            ("", &arm(&[ADD, SUB, ORR, EOR, BIC, BX_LR])),
        ]);
        let blind = Options { use_names: UseNames::No, ..Default::default() };
        let diff = diff_with(&before, &tie, blind);
        assert!(diff.matched.is_empty(), "{:?}", diff.matched);

        let clear = binary_of(&[
            ("", &arm(&[ADD, SUB, ORR, EOR, AND, BX_LR])),
            ("", &arm(&[ADD, SUB, MUL, MUL, BIC, BX_LR])),
        ]);
        let diff = diff_with(&before, &clear, blind);
        let pair = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
        assert_eq!((pair.after, pair.confidence), (0, Confidence::Similar));
    }

    /// A function rewritten past the threshold pairs by its place between
    /// two pairs, where as many free functions sit there on both sides.
    #[test]
    fn a_rewritten_function_pairs_by_its_place() {
        let first = arm(&[ADC, SBC, RSB, BX_LR]);
        let last = arm(&[MUL, MUL, ADC, BX_LR]);
        let before_code = arm(&[ADD, SUB, ORR, EOR, AND, BIC, BX_LR]);
        let after_code = arm(&[ADD, MUL, MUL, MUL, MUL, MUL, BX_LR]);
        let before = binary_of(&[("", &first), ("", &before_code), ("", &last)]);
        let after = binary_of(&[("", &first), ("", &after_code), ("", &last)]);

        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        let pair = diff.matched.iter().find(|pair| pair.before == 1).expect("paired by place");
        assert_eq!((pair.after, pair.confidence), (1, Confidence::SameLayout));
    }

    /// A function that paired by similarity with a look-alike out of
    /// order pairs again by its place, where the look-alike is not close.
    #[test]
    fn a_pair_out_of_order_pairs_again_by_place() {
        let anchors =
            [arm(&[ADC, SBC, RSB, BX_LR]), arm(&[MUL, MUL, ADC, BX_LR]), arm(&[RSB, RSB, BX_LR])];
        let before_code = arm(&[ADD, SUB, ORR, EOR, AND, BIC, BX_LR]);
        let rewritten = arm(&[ADD, MUL, MUL, MUL, MUL, MUL, BX_LR]);
        // Scores 0.78, below `LOWEST_MOVED_SIMILARITY`.
        let look_alike = arm(&[ADD, SUB, ORR, EOR, AND, BIC, ADC, SBC, BX_LR]);
        let [first, second, third] = &anchors;
        let before = binary_of(&[("", first), ("", &before_code), ("", second), ("", third)]);
        let after = binary_of(&[
            ("", first),
            ("", &rewritten),
            ("", second),
            ("", third),
            ("", &look_alike),
        ]);

        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        let pair = diff.matched.iter().find(|pair| pair.before == 1).expect("paired");
        assert_eq!((pair.after, pair.confidence), (1, Confidence::SameLayout));
        assert_eq!(diff.added, vec![4]);
    }

    /// A function whose close code moved to another place keeps its
    /// partner there, over a function that scores well below in its old
    /// place.
    #[test]
    fn close_code_that_moved_keeps_its_partner_over_its_place() {
        let anchors = [
            arm(&[ADC, SBC, RSB, BX_LR]),
            arm(&[MUL, MUL, ADC, BX_LR]),
            arm(&[RSB, RSB, BX_LR]),
            arm(&[SBC, SBC, SBC, BX_LR]),
        ];
        let moved = arm(&[ADD, SUB, ORR, EOR, AND, BIC, ADC, SBC, RSB, BX_LR]);
        let moved_and_edited = arm(&[ADD, SUB, ORR, EOR, AND, BIC, ADC, SBC, MUL, BX_LR]);
        let in_its_place = arm(&[ADD, MUL, MUL, MUL, MUL, MUL, MUL, MUL, MUL, BX_LR]);
        let [first, second, third, fourth] = &anchors;
        let before =
            binary_of(&[("", first), ("", &moved), ("", second), ("", third), ("", fourth)]);
        let after = binary_of(&[
            ("", first),
            ("", &in_its_place),
            ("", second),
            ("", third),
            ("", fourth),
            ("", &moved_and_edited),
        ]);

        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        let pair = diff.matched.iter().find(|pair| pair.before == 1).expect("paired");
        assert!(pair.score >= LOWEST_MOVED_SIMILARITY, "{pair:?}");
        assert_eq!((pair.after, pair.confidence), (5, Confidence::Similar));
        assert_eq!(diff.added, vec![1]);
    }

    /// Two unrelated binaries pair nothing by place, though each function
    /// has one opposite it.
    #[test]
    fn unrelated_binaries_pair_nothing_by_place() {
        let before = binary_of(&[
            ("", &arm(&[ADD, SUB, BX_LR])),
            ("", &arm(&[ORR, EOR, BX_LR])),
            ("", &arm(&[AND, BIC, BX_LR])),
        ]);
        let after = binary_of(&[
            ("", &arm(&[MUL, ADC, BX_LR])),
            ("", &arm(&[SBC, RSB, BX_LR])),
            ("", &arm(&[MUL, SBC, BX_LR])),
        ]);

        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        assert!(diff.matched.is_empty(), "{:?}", diff.matched);
    }

    /// Where one side holds more free functions between two pairs, one
    /// went or came, and the place says nothing of which.
    #[test]
    fn a_gap_of_unequal_counts_pairs_nothing() {
        let first = arm(&[ADC, SBC, RSB, BX_LR]);
        let last = arm(&[MUL, MUL, ADC, BX_LR]);
        let before_code = arm(&[ADD, SUB, ORR, EOR, AND, BIC, BX_LR]);
        let after_code = arm(&[ADD, MUL, MUL, MUL, MUL, MUL, BX_LR]);
        let other = arm(&[EOR, EOR, EOR, EOR, EOR, EOR, BX_LR]);
        let before = binary_of(&[("", &first), ("", &before_code), ("", &last)]);
        let after = binary_of(&[("", &first), ("", &after_code), ("", &other), ("", &last)]);

        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        assert_eq!(diff.removed, vec![1]);
    }

    /// Where a gap holds one more function on one side, the function gone
    /// names the new one that scores closest as in its place, and the
    /// other new one has no place.
    #[test]
    fn a_gap_of_unequal_counts_names_the_function_in_place() {
        let first = arm(&[ADC, SBC, RSB, BX_LR]);
        let last = arm(&[MUL, MUL, ADC, BX_LR]);
        let before_code = arm(&[ADD, SUB, ORR, EOR, AND, BIC, BX_LR]);
        let after_code = arm(&[ADD, SUB, ORR, MUL, MUL, MUL, BX_LR]);
        let other = arm(&[EOR, EOR, EOR, EOR, EOR, EOR, BX_LR]);
        let before = binary_of(&[("", &first), ("", &before_code), ("", &last)]);
        let after = binary_of(&[("", &first), ("", &other), ("", &after_code), ("", &last)]);

        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        assert_eq!(diff.removed, vec![1]);
        assert_eq!(diff.near_miss(1).and_then(|miss| miss.in_place), Some(2));
        assert_eq!(diff.added_near_miss(2).and_then(|miss| miss.in_place), Some(1));
        assert_eq!(diff.added_near_miss(1).and_then(|miss| miss.in_place), None);
    }

    /// A function that shares too little with the one in its place to pair
    /// by place still names it.
    #[test]
    fn a_replaced_function_names_the_one_in_its_place() {
        let first = arm(&[ADC, SBC, RSB, BX_LR]);
        let last = arm(&[MUL, MUL, ADC, BX_LR]);
        let before_code = arm(&[ADD, SUB, ORR, EOR, AND, BIC, ADD, SUB, ORR, EOR, BX_LR]);
        let after_code = arm(&[[MUL; 40].as_slice(), &[BX_LR]].concat());
        let before = binary_of(&[("", &first), ("", &before_code), ("", &last)]);
        let after = binary_of(&[("", &first), ("", &after_code), ("", &last)]);

        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        assert_eq!(
            (diff.removed.as_slice(), diff.added.as_slice()),
            ([1].as_slice(), [1].as_slice())
        );
        assert_eq!(diff.near_miss(1).and_then(|miss| miss.in_place), Some(1));
        assert_eq!(diff.added_near_miss(1).and_then(|miss| miss.in_place), Some(1));
    }

    /// Two unrelated binaries name no function in place.
    #[test]
    fn unrelated_binaries_name_nothing_in_place() {
        let before = binary_of(&[
            ("", &arm(&[ADD, SUB, BX_LR])),
            ("", &arm(&[ORR, EOR, BX_LR])),
            ("", &arm(&[AND, BIC, BX_LR])),
        ]);
        let after = binary_of(&[
            ("", &arm(&[MUL, ADC, BX_LR])),
            ("", &arm(&[SBC, RSB, BX_LR])),
            ("", &arm(&[MUL, SBC, BX_LR])),
        ]);

        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        let misses = diff.near_misses.iter().chain(&diff.added_near_misses);
        assert!(misses.clone().count() == 6, "{diff:?}");
        assert!(misses.into_iter().all(|miss| miss.in_place.is_none()), "{diff:?}");
    }

    #[test]
    fn alignment_by_scores_takes_the_highest_sum_in_order() {
        let table = [[0.9, 0.0, 0.0], [0.0, 0.2, 0.8]];
        assert_eq!(align_by_scores(2, 3, |x, y| table[x][y]), vec![(0, 0), (1, 2)]);
        // Crossing pairs score more, but break the order.
        let table = [[0.0, 0.9], [0.9, 0.0]];
        assert_eq!(align_by_scores(2, 2, |x, y| table[x][y]).len(), 1);
        assert!(align_by_scores(2, 2, |_, _| 0.0).is_empty(), "nothing shared");
        assert!(align_by_scores(0, 3, |_, _| 1.0).is_empty());
        assert!(align_by_scores(3, 0, |_, _| 1.0).is_empty());
    }

    /// The highest sum of scores of any alignment in order, by trying
    /// every one.
    fn best_alignment_sum(left: usize, right: usize, score: &dyn Fn(usize, usize) -> f64) -> f64 {
        if left == 0 || right == 0 {
            return 0.0;
        }
        let both = best_alignment_sum(left - 1, right - 1, score) + score(left - 1, right - 1);
        both.max(best_alignment_sum(left - 1, right, score)).max(best_alignment_sum(
            left,
            right - 1,
            score,
        ))
    }

    /// Any alignment by scores keeps the order on both sides, takes only
    /// items that share something, and reaches the highest sum.
    #[test]
    fn alignment_by_scores_is_ordered_and_best() {
        bolero::check!().with_type::<(u8, u8, [u8; 25])>().for_each(|&(left, right, cells)| {
            let (left, right) = (usize::from(left % 6), usize::from(right % 6));
            let score = |x: usize, y: usize| f64::from(cells[(x * 5 + y) % 25] % 4) / 4.0;
            let aligned = align_by_scores(left, right, score);
            for step in aligned.windows(2) {
                assert!(step[0].0 < step[1].0 && step[0].1 < step[1].1, "{aligned:?}");
            }
            assert!(aligned.iter().all(|&(x, y)| x < left && y < right && score(x, y) > 0.0));
            let sum: f64 = aligned.iter().map(|&(x, y)| score(x, y)).sum();
            assert!((sum - best_alignment_sum(left, right, &score)).abs() < 1e-9);
        });
    }

    /// Context alone does not pair two functions whose code shares too
    /// little: see [`LOWEST_CONTEXT_SIMILARITY`].
    #[test]
    fn context_does_not_pair_unrelated_code() {
        let before_code = calls_three_then(&[ADD, SUB, ORR, EOR, AND, BIC, ADC, SBC, BX_LR]);
        let after_code = calls_three_then(&[MUL, MUL, MUL, MUL, MUL, MUL, MUL, MUL, MUL, BX_LR]);
        let [one, two, three] = [returns(1), returns(2), returns(3)];
        let before = binary_of(&[("", &before_code), ("", &one), ("", &two), ("", &three)]);
        let after = binary_of(&[("", &after_code), ("", &one), ("", &two), ("", &three)]);

        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        // Its place alone may pair it, as the only function before the
        // three; its context does not.
        let pair = diff.matched.iter().find(|pair| pair.before == 0);
        assert!(pair.is_none_or(|pair| pair.confidence != Confidence::SameCallers), "{pair:?}");
    }

    /// Twins that paired in order, each with the next one's partner, pair
    /// again by what they call, however long the chain.
    #[test]
    fn twins_paired_crossed_in_a_chain_pair_by_what_they_call() {
        let calls = |from: u64, callee: u64| -> Vec<u8> {
            [bl(from, callee).as_slice(), &[0x1e, 0xff, 0x2f, 0xe1]].concat()
        };
        let callees = [returns(1), returns(2), returns(3)];
        let image = |targets: [u64; 3]| {
            let wrappers: Vec<Vec<u8>> = targets
                .iter()
                .enumerate()
                .map(|(index, &target)| calls(index as u64 * 0x100, target))
                .collect();
            let functions: Vec<(&str, &[u8])> =
                wrappers.iter().chain(&callees).map(|code| ("", code.as_slice())).collect();
            binary_of(&functions)
        };
        let before = image([0x300, 0x400, 0x500]);
        let after = image([0x500, 0x300, 0x400]);
        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });

        let partner = |index: usize| {
            diff.matched.iter().find(|pair| pair.before == index).map(|pair| pair.after)
        };
        assert_eq!([partner(0), partner(1), partner(2)], [Some(1), Some(2), Some(0)]);
        assert_eq!(diff.changed().count(), 0);
    }

    /// A table that went or came says it is data, and code says it is code.
    #[test]
    fn a_table_that_goes_or_comes_is_data() {
        let with_table = {
            let mut binary = raw_mips(&pointer_table(0x8000_1000));
            binary.functions.push(returns_one());
            binary
        };
        let without = crate::obj::Binary { functions: vec![returns_one()], ..raw_mips(&[]) };
        let options = Options { threshold: 0.0, use_names: UseNames::No };

        let gone = diff_with(&with_table, &without, options);
        assert_eq!(gone.removed_with_contents().collect::<Vec<_>>(), [(0, Contents::Data)]);
        assert!(gone.added.is_empty() && gone.added_contents.is_empty());

        let new = diff_with(&without, &with_table, options);
        assert_eq!(new.added_with_contents().collect::<Vec<_>>(), [(0, Contents::Data)]);
        assert!(new.removed.is_empty() && new.removed_contents.is_empty());

        // Code that goes is code.
        let only_table = raw_mips(&pointer_table(0x8000_1000));
        let code_gone = diff_with(&with_table, &only_table, options);
        assert_eq!(code_gone.removed_with_contents().collect::<Vec<_>>(), [(1, Contents::Code)]);
    }

    /// A table whose pointers moved is reported as changed data, not as a
    /// rewritten function.
    #[test]
    fn a_changed_table_is_changed_data() {
        let before = raw_mips(&pointer_table(0x8000_1000));
        let after = raw_mips(&pointer_table(0x8000_2000));
        let diff = diff_with(&before, &after, Options { threshold: 0.0, use_names: UseNames::No });

        assert_eq!(diff.matched.len(), 1);
        assert_eq!(diff.matched[0].changed, Changed::Data);
    }

    /// The same table on both sides is not a change at all.
    #[test]
    fn an_unchanged_table_is_no_change() {
        let table = raw_mips(&pointer_table(0x8000_1000));
        let diff = diff_with(&table, &table, Options { threshold: 0.0, use_names: UseNames::No });

        assert_eq!(diff.matched[0].changed, Changed::No);
    }

    /// Data counts for less than a changed constant, and for more than none.
    #[test]
    fn data_ranks_between_a_reorder_and_a_changed_value() {
        assert!(Changed::Data > Changed::Reordered);
        assert!(Changed::Data < Changed::InDetail);
    }

    /// `add r0, r1, r0` then `bx lr`.
    const ADD_THEN_RETURN: &[u8] = &[0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
    /// `mul r0, r0, r1` then `bx lr`, which shares no operation with the above.
    const MUL_THEN_RETURN: &[u8] = &[0x91, 0x00, 0x00, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];

    /// `bl $+0x20` then `bx lr`.
    const CALL_NEAR: &[u8] = &[0x06, 0x00, 0x00, 0xeb, 0x1e, 0xff, 0x2f, 0xe1];
    /// The same call after its callee moved: `bl $+0x40` then `bx lr`.
    const CALL_FAR: &[u8] = &[0x0e, 0x00, 0x00, 0xeb, 0x1e, 0xff, 0x2f, 0xe1];

    /// The kernel size `0x2b08a8` stored among code, then `bx lr`.
    ///
    /// The word decodes as `eoreq r0, fp, r8, lsr 17`.
    const DATA_WORD: &[u8] = &[0xa8, 0x08, 0x2b, 0x00, 0x1e, 0xff, 0x2f, 0xe1];
    /// The same field changed to `0x2b3c48`: `eoreq r3, fp, r8, asr 24`.
    const DATA_WORD_EDITED: &[u8] = &[0x48, 0x3c, 0x2b, 0x00, 0x1e, 0xff, 0x2f, 0xe1];

    /// Compare two one-function images and report what happened to the pair.
    fn change_between(before: &[u8], after: &[u8]) -> Changed {
        let before = binary_of(&[("f", before)]);
        let after = binary_of(&[("f", after)]);
        let diff =
            diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
        diff.matched.first().expect("the pair must match").changed
    }

    /// A call whose callee moved must reach the report as no change at all.
    ///
    /// The unit tests above cover the operand rule directly. This one runs the
    /// whole pipeline, so it still fails if the instruction kind stops
    /// reaching the comparison and every target starts counting as data.
    #[test]
    fn a_moved_call_target_reports_no_change() {
        assert_eq!(change_between(CALL_NEAR, CALL_FAR), Changed::No);
    }

    /// The same difference in a word of data must stay visible.
    ///
    /// Both cases change four bytes of an otherwise identical function. Only
    /// the kind of the instruction tells them apart, which is why the pair of
    /// tests belongs together.
    #[test]
    fn a_changed_data_word_still_reports_a_change() {
        assert_ne!(change_between(DATA_WORD, DATA_WORD_EDITED), Changed::No);
    }

    /// Identical code stays unchanged, so the tests above measure the edit
    /// rather than a comparison that reports everything.
    #[test]
    fn an_unedited_function_reports_no_change() {
        assert_eq!(change_between(CALL_NEAR, CALL_NEAR), Changed::No);
        assert_eq!(change_between(DATA_WORD, DATA_WORD), Changed::No);
    }

    #[test]
    fn an_unmatched_function_reports_its_closest_candidate() {
        let before = binary_of(&[("only", ADD_THEN_RETURN)]);
        // A second function that shares nothing keeps the two from
        // pairing by their place: see `Cascade::pair_by_layout`.
        let unrelated = arm(&[SUB, SUB]);
        let after = binary_of(&[("other", MUL_THEN_RETURN), ("unrelated", &unrelated)]);

        // A threshold of 1.0 refuses everything below an exact match, so the
        // pair is left for the near-miss report.
        let diff = diff_with(&before, &after, Options { threshold: 1.0, use_names: UseNames::No });

        assert_eq!(diff.removed, vec![0], "nothing could be paired");
        let miss = diff.near_miss(0).expect("the removed function needs a near miss");
        assert_eq!(miss.best, Some(0), "the only candidate is the closest one");
        assert!(miss.score > 0.0, "the two share a return, so they are not unrelated");
        assert!(miss.score < 1.0, "they are not the same function either");
    }

    /// With nothing to compare against, a near miss names no candidate rather
    /// than inventing one.
    #[test]
    fn a_near_miss_without_candidates_names_none() {
        let before = binary_of(&[("gone", ADD_THEN_RETURN)]);
        let after = binary_of(&[]);

        let diff = diff_with(&before, &after, Options::default());

        let miss = diff.near_miss(0).expect("the removed function needs a near miss");
        assert_eq!(miss.best, None);
        assert_eq!(miss.score, 0.0);
    }

    /// Diff two one-function images at instruction level.
    fn diff_lines(before: &[u8], after: &[u8]) -> Vec<DiffLine> {
        let before = binary_of(&[("f", before)]);
        let after = binary_of(&[("f", after)]);
        instruction_diff(&before.functions[0], Isa::Arm32, &after.functions[0], Isa::Arm32)
    }

    /// A function diffed with itself is every line unchanged.
    #[test]
    fn an_unedited_function_diffs_to_all_same() {
        let lines = diff_lines(ADD_THEN_RETURN, ADD_THEN_RETURN);
        assert!(lines.iter().all(|line| matches!(line, DiffLine::Same(_))));
        assert_eq!(lines.len(), 2, "add then bx lr");
    }

    /// A moved branch target is a free choice, so the diff shows no change.
    #[test]
    fn a_moved_target_diffs_to_all_same() {
        let lines = diff_lines(CALL_NEAR, CALL_FAR);
        assert!(
            lines.iter().all(|line| matches!(line, DiffLine::Same(_))),
            "only the branch target moved"
        );
    }

    /// An added instruction shows as one added line, the rest unchanged.
    #[test]
    fn an_added_instruction_shows_as_added() {
        // `add` then `add` then `bx lr`, against `add` then `bx lr`.
        let longer: &[u8] =
            &[0x00, 0x00, 0x81, 0xe0, 0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
        let lines = diff_lines(ADD_THEN_RETURN, longer);
        assert_eq!(lines.iter().filter(|line| matches!(line, DiffLine::Added(_))).count(), 1);
        assert_eq!(lines.iter().filter(|line| matches!(line, DiffLine::Removed(_))).count(), 0);
    }

    /// The same comparison reversed shows a removal, not an addition.
    #[test]
    fn a_removed_instruction_shows_as_removed() {
        let longer: &[u8] =
            &[0x00, 0x00, 0x81, 0xe0, 0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
        let lines = diff_lines(longer, ADD_THEN_RETURN);
        assert_eq!(lines.iter().filter(|line| matches!(line, DiffLine::Removed(_))).count(), 1);
        assert_eq!(lines.iter().filter(|line| matches!(line, DiffLine::Added(_))).count(), 0);
    }

    /// A changed constant shows as one changed line, with both forms.
    ///
    /// The two `mov` share every shape a compiler picks freely, so they align;
    /// only the constant differs, which is the line the reader came for.
    #[test]
    fn a_changed_constant_shows_both_forms() {
        // `mov r1, 0x25` then `mul` then `bx lr`, against `mov r1, 0x29`.
        let before: &[u8] =
            &[0x25, 0x10, 0xa0, 0xe3, 0x91, 0x00, 0x00, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
        let after: &[u8] =
            &[0x29, 0x10, 0xa0, 0xe3, 0x91, 0x00, 0x00, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
        let lines = diff_lines(before, after);

        let changed: Vec<_> =
            lines.iter().filter(|line| matches!(line, DiffLine::Changed { .. })).collect();
        assert_eq!(changed.len(), 1, "only the constant changed");
        let DiffLine::Changed { before, after } = changed[0] else { unreachable!() };
        assert!(before.contains("0x25") && after.contains("0x29"), "both values shown");
    }

    /// A remove-then-add of the same instruction folds by shape.
    ///
    /// Aligning on the printed text splits a changed constant, and can split a
    /// line whose target only moved, into a removal beside an addition. The fold
    /// puts them back: a moved target is no change, a changed value is one
    /// [`DiffLine::Changed`], and an unrelated pair is left apart.
    #[test]
    fn an_adjacent_remove_and_add_fold_by_shape() {
        let insns = |words: &[u32]| {
            let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            decode_all(&Arm32, &code, 0).0
        };
        // `bl`, `mov r1, 0x25`, `push {lr}`, against `bl` farther, `mov r1,
        // 0x29`, `mul r0, r0, r1`.
        let before = insns(&[0xeb00_0006, 0xe3a0_1025, 0xe52d_e004]);
        let after = insns(&[0xeb00_000e, 0xe3a0_1029, 0xe000_0190]);
        let steps = [Step::Left, Step::Right, Step::Left, Step::Right, Step::Left, Step::Right];
        let folded = lines_from_alignment(&steps, (&Arm32, &before), (&Arm32, &after));
        assert_eq!(
            folded,
            vec![
                DiffLine::Same(after[0].to_string()),
                DiffLine::Changed { before: before[1].to_string(), after: after[1].to_string() },
                DiffLine::Removed(before[2].to_string()),
                DiffLine::Added(after[2].to_string()),
            ]
        );
    }

    /// A register or a slot of the frame is a free choice, a constant or the
    /// offset of another access is a value, and the base of an access or the
    /// operation is the shape.
    #[test]
    fn two_instructions_differ_in_choices_values_or_shape() {
        let insn = |word: u32| decode_all(&Arm32, &word.to_le_bytes(), 0).0.remove(0);
        let difference = |left: u32, right: u32| {
            difference(&Arm32, &insn(left), &Arm32, &insn(right), FrameSlots::Move)
        };
        const MOV_R1_0X25: u32 = 0xe3a0_1025;
        const LDR_R0_R1_8: u32 = 0xe591_0008;
        assert_eq!(difference(MOV_R1_0X25, MOV_R1_0X25), Difference::FreeChoices);
        assert_eq!(difference(MOV_R1_0X25, 0xe3a0_2025), Difference::FreeChoices, "mov r2");
        assert_eq!(difference(MOV_R1_0X25, 0xe3a0_1029), Difference::Values, "mov r1, 0x29");
        assert_eq!(difference(LDR_R0_R1_8, 0xe591_000c), Difference::Values, "[r1, 0xc]");
        assert_eq!(difference(LDR_R0_R1_8, 0xe592_0008), Difference::Shape, "[r2, 8]");
        assert_eq!(difference(MOV_R1_0X25, 0xe000_0190), Difference::Shape, "mul");
        // `str r4, [sp]` against `str r4, [sp, 4]`: the frame grew, which
        // the assembly view shows.
        assert_eq!(difference(0xe58d_4000, 0xe58d_4004), Difference::FreeChoices);
        let (store, store_farther) = (insn(0xe58d_4000), insn(0xe58d_4004));
        assert_eq!(
            super::difference(&Arm32, &store, &Arm32, &store_farther, FrameSlots::Stay),
            Difference::Values
        );
        // `ldr r0, [pc, 8]` against `ldr r0, [pc, 0x10]`: the pool moved.
        assert_eq!(difference(0xe59f_0008, 0xe59f_0010), Difference::FreeChoices);
    }

    /// A matched function is not a near miss, so the report stays short.
    #[test]
    fn matched_functions_are_not_reported_as_near_misses() {
        let before = binary_of(&[("same", ADD_THEN_RETURN)]);
        let after = binary_of(&[("same", ADD_THEN_RETURN)]);

        let diff = diff_with(&before, &after, Options::default());

        assert_eq!(diff.matched.len(), 1);
        assert!(diff.near_misses.is_empty(), "nothing went unmatched");
        assert!(diff.added_near_misses.is_empty(), "nothing went unmatched");
    }

    /// An added function names its closest candidate on the first binary, the
    /// mirror of the removed-side near miss.
    #[test]
    fn an_added_function_reports_its_closest_candidate() {
        let before = binary_of(&[("only", ADD_THEN_RETURN)]);
        // A second function that shares nothing keeps the two from
        // pairing by their place: see `Cascade::pair_by_layout`.
        let unrelated = arm(&[SUB, SUB]);
        let after = binary_of(&[("other", MUL_THEN_RETURN), ("unrelated", &unrelated)]);

        // A threshold of 1.0 refuses everything below an exact match, so both
        // sides are left for the near-miss report.
        let diff = diff_with(&before, &after, Options { threshold: 1.0, use_names: UseNames::No });

        assert_eq!(diff.added, vec![0, 1], "nothing could be paired");
        let miss = diff.added_near_miss(0).expect("the added function needs a near miss");
        assert_eq!(miss.best, Some(0), "the only candidate is the closest one");
        assert!(miss.score > 0.0, "the two share a return, so they are not unrelated");
        assert!(miss.score < 1.0, "they are not the same function either");
    }

    /// Reduce bodies to sorted symbols the way `prepare` does.
    fn symbols_of(bodies: &[&[NormInsn]]) -> Vec<Vec<Symbol>> {
        let mut interner = Interner::default();
        bodies
            .iter()
            .map(|body| {
                let mut symbols: Vec<Symbol> =
                    body.iter().map(|insn| interner.intern(insn)).collect();
                symbols.sort_unstable();
                symbols
            })
            .collect()
    }

    /// The fast path must agree with the one it replaced.
    ///
    /// `similarity` stays the public, obviously-correct definition. The scoring
    /// stage uses `similarity_of_symbols` instead, for speed. Nothing in the
    /// types stops those two drifting apart, so this checks them together.
    #[test]
    fn scoring_by_symbol_agrees_with_scoring_by_body() {
        let cases: Vec<(Vec<NormInsn>, Vec<NormInsn>)> = vec![
            // Identical.
            (body(&["add"]), body(&["add"])),
            // Nothing shared.
            (body(&["ldr"]), body(&["mul"])),
            // Partly shared.
            (body(&["add", "mul"]), body(&["add", "sub"])),
            // One side empty.
            (Vec::new(), body(&["add"])),
            // Both empty.
            (Vec::new(), Vec::new()),
            // Repeats, where the multiset matters rather than the set.
            (body(&["add", "add", "add"]), body(&["add"])),
            // The same instructions in a different order.
            (body(&["add", "mul"]), body(&["mul", "add"])),
        ];

        for (left, right) in &cases {
            let symbols = symbols_of(&[left, right]);
            let by_body = similarity(left, right);
            let by_symbol = similarity_of_symbols(&symbols[0], &symbols[1]);
            assert!(
                (by_body - by_symbol).abs() < 1e-12,
                "{left:?} against {right:?}: body gives {by_body}, symbols give {by_symbol}"
            );
        }
    }

    /// Two equal instructions must get one symbol, and unequal ones must not.
    ///
    /// Equality ignores constants on purpose, so the interner has to as well.
    #[test]
    fn equal_instructions_share_a_symbol() {
        let mut interner = Interner::default();

        let decoded = |word: u32| {
            let insn = Arm32.decode(&word.to_le_bytes(), 0, 0).expect("the word decodes");
            normalize(&Arm32, &insn)
        };
        let first = interner.intern(&decoded(0xe3a0_0001)); // mov r0, #1
        let second = interner.intern(&decoded(0xe3a0_0002)); // mov r0, #2
        assert_eq!(first, second, "constants stay out of equality, so out of the symbol");

        let third = interner.intern(&decoded(0xe591_0000)); // ldr r0, [r1]
        assert_ne!(first, third, "a different operation needs a different symbol");
        assert_eq!(interner.len(), 2, "two distinct instructions were seen");
    }

    /// Record what a comparison reports, to check the reporting itself.
    ///
    /// Behind a lock because the scoring stages report from several threads.
    #[derive(Default)]
    struct Recorder {
        events: std::sync::Mutex<Vec<Event>>,
    }

    #[derive(Debug, PartialEq)]
    enum Event {
        Start(Phase, usize),
        Advance(usize),
        Finish,
    }

    impl Recorder {
        fn events(&self) -> std::sync::MutexGuard<'_, Vec<Event>> {
            self.events.lock().expect("no test panics while holding the lock")
        }
    }

    impl Progress for Recorder {
        fn start(&self, phase: Phase, total: usize) {
            self.events().push(Event::Start(phase, total));
        }
        fn advance(&self, steps: usize) {
            self.events().push(Event::Advance(steps));
        }
        fn finish(&self) {
            self.events().push(Event::Finish);
        }
    }

    /// A bar that runs past its own total, or never ends, reads as a fault in
    /// the tool. Every phase must announce a total it then reaches exactly, and
    /// must close before the next one opens.
    #[test]
    fn every_phase_reports_a_total_it_reaches() {
        let before = binary_of(&[("same", ADD_THEN_RETURN), ("gone", MUL_THEN_RETURN)]);
        let after = binary_of(&[("same", ADD_THEN_RETURN), ("new", &[0x00, 0x00, 0xa0, 0xe1])]);

        let recorder = Recorder::default();
        diff_reporting(&before, &after, Options::default(), &recorder);

        let events = recorder.events();
        let mut open: Option<(Phase, usize)> = None;
        let mut seen = 0usize;
        let mut phases = Vec::new();

        for event in events.iter() {
            match event {
                Event::Start(phase, total) => {
                    assert!(open.is_none(), "{phase:?} started while another phase was open");
                    open = Some((*phase, *total));
                    seen = 0;
                    phases.push(*phase);
                }
                Event::Advance(steps) => {
                    let (phase, total) = open.expect("a step was reported outside a phase");
                    seen += steps;
                    assert!(seen <= total, "{phase:?} passed its total of {total} at {seen}");
                }
                Event::Finish => {
                    let (phase, total) = open.take().expect("a phase ended without starting");
                    assert_eq!(seen, total, "{phase:?} ended at {seen} of {total}");
                }
            }
        }

        assert!(open.is_none(), "a phase was left open");
        assert!(phases.contains(&Phase::Preparing), "preparing is always reported");
        assert!(phases.contains(&Phase::Similarity), "the long phase is always reported");
    }

    /// Every phase needs something to show, or a bar displays an empty label.
    #[test]
    fn every_phase_has_a_label() {
        for phase in [
            Phase::Preparing,
            Phase::IdenticalCode,
            Phase::IdenticalShape,
            Phase::Names,
            Phase::Similarity,
            Phase::NearMisses,
        ] {
            assert!(!phase.label().is_empty(), "{phase:?} needs a label");
        }
    }

    /// Reporting progress must not change the answer.
    #[test]
    fn reporting_progress_does_not_change_the_result() {
        let before = binary_of(&[("same", ADD_THEN_RETURN), ("gone", MUL_THEN_RETURN)]);
        let after = binary_of(&[("same", ADD_THEN_RETURN), ("new", &[0x00, 0x00, 0xa0, 0xe1])]);

        let quiet = diff_with(&before, &after, Options::default());
        let loud = diff_reporting(&before, &after, Options::default(), &Recorder::default());

        assert_eq!(quiet.matched.len(), loud.matched.len());
        assert_eq!(quiet.removed, loud.removed);
        assert_eq!(quiet.added, loud.added);
    }

    /// The answer must not depend on how the work was spread over threads.
    ///
    /// The scoring stages run in parallel, so rows finish in whatever order the
    /// threads happen to take. Sorting the candidates is what makes the result
    /// repeatable, and this checks that it does.
    #[test]
    fn the_result_does_not_depend_on_thread_order() {
        // Bodies close enough to score above the threshold against several
        // candidates, so the order pairs are taken in decides the answer.
        let before = binary_of(&[
            ("a", ADD_THEN_RETURN),
            ("b", MUL_THEN_RETURN),
            ("c", ADD_THEN_RETURN),
            ("d", MUL_THEN_RETURN),
            ("e", ADD_THEN_RETURN),
        ]);
        let after = binary_of(&[
            ("v", MUL_THEN_RETURN),
            ("w", ADD_THEN_RETURN),
            ("x", MUL_THEN_RETURN),
            ("y", ADD_THEN_RETURN),
            ("z", MUL_THEN_RETURN),
        ]);

        let options = Options { threshold: 0.3, use_names: UseNames::No };
        let first = diff_with(&before, &after, options);

        let pairs = |diff: &Diff| -> Vec<(usize, usize, Confidence)> {
            diff.matched.iter().map(|m| (m.before, m.after, m.confidence)).collect()
        };

        for run in 0..16 {
            let again = diff_with(&before, &after, options);
            assert_eq!(pairs(&first), pairs(&again), "run {run} paired differently");
            assert_eq!(first.removed, again.removed, "run {run} removed differently");
            assert_eq!(first.added, again.added, "run {run} added differently");
        }
    }

    #[test]
    fn similarity_falls_as_bodies_diverge() {
        let base = body(&["add", "mul"]);
        let half = body(&["add", "sub"]);
        let none = body(&["ldr", "str"]);

        assert!(similarity(&base, &half) > similarity(&base, &none));
        assert_eq!(similarity(&base, &none), 0.0);
    }
}
