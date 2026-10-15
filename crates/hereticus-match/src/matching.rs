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
//!
//! The cascade and its stages are in `cascade`, and the scores they choose
//! by in `score`. `change` tells how a pair differs, `near_miss` finds the
//! closest candidate of a function left unpaired, `align` aligns two bodies,
//! and `lines` shows the diff of a pair.

use std::collections::HashMap;

use hereticus_memory::{AddressSpace, Contents};

use crate::norm::{
    FlowShape, NormInsn, OperandShape, constant_signature, flow_features, normalize_body_in,
};
use hereticus_callees::{Callee, callees_in};
use hereticus_il::arch::InsnKind;
use hereticus_image::{Binary, FoundBy, Function, Isa};
use hereticus_recovery::arch::{Memory, decode_all};
pub use hereticus_view::PairedLabels;

mod align;
mod cascade;
mod change;
mod lines;
mod near_miss;
mod score;
mod tables;

use cascade::Cascade;
pub use lines::{DiffLine, View, instruction_diff, instruction_diff_in, line_addresses};
pub use score::similarity;
use score::{CLOSE_SIMILARITY, FLOW_DEPTH, LARGEST_PLAIN_CONSTANT, sorted_shared};

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
    /// `Cascade::match_twins_in_order`.
    TwinInOrder,
    /// Twins in the same slot of two tables of functions that firmer pairs
    /// join, as a vtable. See `Cascade::pair_by_tables`.
    SameTable,
    /// The two alone hold a text or a constant on both sides. See
    /// `Cascade::pair_by_unique_references`.
    SameReferences,
    /// Calls from functions paired on firmer ground reach these two, where a
    /// weaker reason had paired each with another. See
    /// `Cascade::pair_by_callers`.
    SameCallers,
    /// The two sit in the same place between pairs on both sides. See
    /// `Cascade::pair_by_layout`.
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
    /// `saturated` says. Another compiler or another flag adds the same
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
    /// would put them above every real edit. See [`hereticus_arch::Arch::contents`].
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
    /// `Cascade::same_places` and RESEARCH.md, entry 7.
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
    /// code does. See [`hereticus_arch::Arch::contents`].
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
    /// The label of each stripped function of `after`, as its pair in
    /// `before` names it.
    pub fn paired_labels(&self, before: &Binary, after: &Binary) -> PairedLabels {
        PairedLabels::of_pairs(
            self.matched
                .iter()
                .map(|pair| (&before.functions[pair.before], &after.functions[pair.after])),
        )
    }

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
    /// [`hereticus_il::flow_features`].
    flow: Vec<u64>,
    /// The distinct constants of the body, sorted: see
    /// [`crate::norm::constant_signature`].
    constants: Vec<u64>,
    /// The normalized body, kept so that a pair need not decode and
    /// normalize it again.
    body: Vec<NormInsn>,
    /// The import this function jumps to, where it is a PLT stub whose
    /// slot the linker names.
    stub_of: Option<&'a str>,
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

    /// The normalized body.
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
    /// [`hereticus_callees::callees`] gives them.
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

            // Only a stub is named `free@plt`: by its slot, or on MIPS by
            // the symbol its lazy binding stub resolves.
            let stub_of = binary
                .links
                .stub_callee(arch, function.address)
                .or_else(|| function.name.strip_suffix("@plt"));
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
                stub_of,
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
        left_tables: before.function_tables(),
        right_tables: after.function_tables(),
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
    // Once the similarity stage has paired the functions that tell two
    // tables apart.
    cascade.pair_by_tables();
    cascade.uncross_by_callees();
    cascade.pair_by_unique_references_until_settled();
    cascade.pair_by_callers();
    cascade.realign_by_context();
    cascade.pair_by_layout();
    // Again, now that the callers and the order paired more of the callees
    // that tell two callers apart.
    cascade.pair_by_unique_references_until_settled();
    cascade.pair_leftover_twins();
    // Again, now that the callers and the order paired more of each table.
    cascade.pair_by_tables();
    // Last, so that every pair that can serve as context has paired.
    cascade.unpair_without_context();
    cascade.compare_callees();
    cascade.compare_texts();
    cascade.finish(progress)
}

#[cfg(test)]
mod tests;
