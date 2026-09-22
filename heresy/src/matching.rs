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

use std::collections::HashMap;

use rayon::prelude::*;

use crate::arch::{Insn, InsnKind, decode_all};
use crate::norm::{FlowShape, NormInsn, normalize_body, normalize_operation};
use crate::obj::{Binary, Function, Isa};

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

/// Whether a matched pair differs, and how.
///
/// A pair can match and still differ. Normalizing hides the detail a compiler
/// picks freely, so two functions that normalize alike can still hold
/// different constants.
///
/// The variants rise in how much a reader should care, so
/// `Changed::No < Changed::Reordered < Changed::InDetail < Changed::Unreadable
/// < Changed::Yes`.
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
#[derive(Clone, Copy, Debug)]
pub struct NearMiss {
    /// The unmatched function this candidate is for, in its own binary.
    pub unmatched: usize,
    /// The closest candidate in the other binary, if any was scored.
    pub best: Option<usize>,
    /// How close that candidate came, from 0.0 to 1.0.
    pub score: f64,
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
}

/// How willing the cascade is to pair two functions on similarity alone.
///
/// Below this score a pair is left unmatched rather than guessed at. The
/// default separates the test corpus: functions that belong together score at
/// or near 1.00 there, and the closest unrelated pair scores 0.50.
const DEFAULT_THRESHOLD: f64 = 0.65;

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
    fn intern(&mut self, insn: NormInsn) -> Symbol {
        let next = self.symbols.len() as Symbol;
        *self.symbols.entry(insn).or_insert(next)
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
    body: Vec<NormInsn>,
    /// The body as symbols, sorted.
    ///
    /// Sorted so that [`similarity`] can walk two bodies together instead of
    /// building a map for each comparison. Order is already irrelevant to the
    /// score, which counts shared instructions rather than matching positions.
    symbols: Vec<Symbol>,
    /// Each instruction as decoded, before normalizing: the operation, its
    /// operands, and how it moves control.
    ///
    /// Normalizing throws away detail on purpose, which is what lets a
    /// function match itself across builds. Telling a changed register from a
    /// changed word of data needs that detail back, so it is kept here. The
    /// kind comes along because a branch target is only a free choice when the
    /// instruction really does branch.
    printed: Vec<PrintedInsn>,
}

/// One instruction as the decoder printed it, kept for the detail comparison.
struct PrintedInsn {
    mnemonic: String,
    operands: String,
    kind: InsnKind,
}

impl PrintedInsn {
    /// Report whether this instruction moves control to a target address.
    ///
    /// Only these may have a `$...` operand that moves for free. A word of
    /// data that happens to decode as a branch is excluded by the operation
    /// check that runs first, which a changed data word almost always fails.
    fn transfers_control(&self) -> bool {
        matches!(self.kind, InsnKind::Call { .. } | InsnKind::Jump { .. } | InsnKind::Branch { .. })
    }
}

impl Prepared<'_> {
    /// Report whether the normalized instructions agree, constants aside.
    fn same_shape_as(&self, other: &Self) -> bool {
        self.body == other.body
    }

    /// Report whether two bodies that match also hold the same constants.
    fn same_detail_as(&self, other: &Self) -> bool {
        self.body.len() == other.body.len()
            && self.body.iter().zip(&other.body).all(|(left, right)| !left.differs_in_detail(right))
    }
}

/// Prepare every function of a binary for matching.
///
/// The interner is shared between the two binaries, so a symbol means the same
/// instruction on either side.
fn prepare<'a>(
    binary: &'a Binary,
    interner: &mut Interner,
    progress: &dyn Progress,
) -> Vec<Prepared<'a>> {
    let arch = binary.isa.arch();
    binary
        .functions
        .iter()
        .map(|function| {
            progress.advance(1);
            let (insns, _) = decode_all(&arch, &function.code, function.address);
            let printed = insns
                .iter()
                .map(|insn| PrintedInsn {
                    mnemonic: insn.mnemonic.clone(),
                    operands: insn.operands.clone(),
                    kind: insn.kind,
                })
                .collect();
            let body = normalize_body(&insns);

            let mut symbols: Vec<Symbol> =
                body.iter().map(|insn| interner.intern(insn.clone())).collect();
            symbols.sort_unstable();

            Prepared { function, body, symbols, printed }
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
    let left = prepare(before, &mut interner, progress);
    let right = prepare(after, &mut interner, progress);
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
    cascade.match_by_similarity(progress);

    cascade.finish(progress)
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
        let (left, right) = (&self.left[before], &self.right[after]);
        self.matched.push(Match {
            before,
            after,
            confidence,
            score,
            changed: classify_change(left, right),
            edits: count_edits(left, right),
        });
    }

    /// Sort the pairs and collect what stayed unmatched.
    fn finish(mut self, progress: &dyn Progress) -> Diff {
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
        let near_misses = self.near_misses(&removed, &self.left, &added, &self.right, progress);
        let added_near_misses =
            self.near_misses(&added, &self.right, &removed, &self.left, progress);
        progress.finish();

        Diff { removed, added, near_misses, added_near_misses, matched: self.matched }
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
    fn near_misses(
        &self,
        unmatched: &[usize],
        theirs: &[Prepared<'_>],
        others: &[usize],
        others_side: &[Prepared<'_>],
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

                match best {
                    Some((score, other)) => NearMiss { unmatched: *one, best: Some(other), score },
                    None => NearMiss { unmatched: *one, best: None, score: 0.0 },
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
    if before.printed.len() != after.printed.len() {
        return false;
    }

    before.printed.iter().zip(&after.printed).all(|(left, right)| {
        // Compare the operation the way the normalizer does, so a condition
        // code the compiler chose differently — `movwlt` against `movwlo` —
        // stays the free choice it is rather than reading as an edit.
        normalize_operation(&left.mnemonic) == normalize_operation(&right.mnemonic)
            && operands_are_interchangeable(
                &left.operands,
                &right.operands,
                // A `$...` operand is a free choice only on an instruction
                // that truly branches. Both sides agree on the operation by
                // now, so either one answers.
                TargetMoves::from(left.transfers_control() && right.transfers_control()),
            )
    })
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
fn operands_are_interchangeable(left: &str, right: &str, targets: TargetMoves) -> bool {
    let left = left.split(',').map(str::trim);
    let right = right.split(',').map(str::trim);

    left.zip(right).all(|(a, b)| {
        a == b
            || (is_register_name(a) && is_register_name(b))
            || (targets == TargetMoves::Freely && is_branch_target(a) && is_branch_target(b))
    })
}

/// Report whether an operand is a branch target, which prints as `$+0x24`.
fn is_branch_target(operand: &str) -> bool {
    operand.starts_with('$')
}

/// Report whether an operand is a bare register name.
fn is_register_name(operand: &str) -> bool {
    matches!(operand, "sp" | "lr" | "pc" | "fp" | "ip" | "sl")
        || operand
            .strip_prefix('r')
            .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
}

/// Work out whether a matched pair differs.
///
/// The order of these checks runs from cheapest and most certain to least.
fn classify_change(before: &Prepared<'_>, after: &Prepared<'_>) -> Changed {
    if before.function.code == after.function.code {
        return Changed::No;
    }

    if before.same_shape_as(after) {
        if !before.same_detail_as(after) {
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
    // instructions, moved. Sorting both sides answers that.
    let mut before_sorted = before.body.clone();
    let mut after_sorted = after.body.clone();
    before_sorted.sort();
    after_sorted.sort();

    if before_sorted == after_sorted {
        return Changed::Reordered;
    }

    if differs_only_where_unreadable(before, after) { Changed::Unreadable } else { Changed::Yes }
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
fn differs_only_where_unreadable(before: &Prepared<'_>, after: &Prepared<'_>) -> bool {
    if before.body.len() != after.body.len() {
        return false;
    }

    let mut differs = false;
    for (left, right) in before.body.iter().zip(&after.body) {
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
/// [`coalesce_changed_constants`] folds them for display. What is left on one
/// side alone is a true addition or removal.
///
/// A pair the alignment kept is not a rewrite even when its constants differ.
/// Normalizing hides a constant on purpose, and [`Changed::InDetail`] already
/// reports that case; counting it here as well would say a threshold that went
/// from 100 to 50 rewrote an instruction, when the code around it is
/// untouched. A reader sorting by this count wants the functions whose
/// instructions moved.
fn count_edits(before: &Prepared<'_>, after: &Prepared<'_>) -> Edits {
    let (left, right) = (&before.body, &after.body);
    let mut edits = Edits::default();
    // Removals seen since the last kept instruction, still free to pair with an
    // addition. The alignment emits a run of removals before the additions that
    // replace them, so the two need not be strictly adjacent.
    let mut unpaired_removals = 0usize;

    for step in longest_common_subsequence(left, right) {
        match step {
            Step::Both => {
                edits.removed += unpaired_removals;
                unpaired_removals = 0;
            }
            Step::Left => unpaired_removals += 1,
            Step::Right => {
                // A removal waiting next to this addition means one instruction
                // took another's place, which is a rewrite rather than a pair
                // of length changes.
                if unpaired_removals > 0 {
                    unpaired_removals -= 1;
                    edits.edited += 1;
                } else {
                    edits.added += 1;
                }
            }
        }
    }
    edits.removed += unpaired_removals;

    edits
}

impl Cascade<'_> {
    /// Stage one: identical machine code.
    ///
    /// The strongest evidence there is, and the cheapest to find. A function
    /// that was not touched and did not move lands here.
    fn match_identical_code(&mut self, progress: &dyn Progress) {
        progress.start(Phase::IdenticalCode, self.left.len());
        let mut by_code: HashMap<&[u8], Vec<usize>> = HashMap::new();
        for (index, prepared) in self.right.iter().enumerate() {
            by_code.entry(prepared.function.code.as_slice()).or_default().push(index);
        }

        let mut pairs = Vec::new();
        for (index, prepared) in self.left.iter().enumerate() {
            progress.advance(1);
            let Some(candidates) = by_code.get(prepared.function.code.as_slice()) else { continue };
            // Only pair when the answer is unambiguous. Several functions can
            // share a body, and guessing between them helps nobody.
            let free: Vec<usize> =
                candidates.iter().copied().filter(|other| self.right_free[*other]).collect();
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
    fn match_identical_shape(&mut self, progress: &dyn Progress) {
        progress.start(Phase::IdenticalShape, self.left.len());
        for index in 0..self.left.len() {
            progress.advance(1);
            // An empty body carries no evidence, so pairing on it would be a
            // guess dressed up as a certainty.
            if !self.left_free[index] || self.left[index].body.is_empty() {
                continue;
            }

            let candidates: Vec<usize> = (0..self.right.len())
                .filter(|other| {
                    self.right_free[*other] && self.left[index].same_shape_as(&self.right[*other])
                })
                .collect();

            if let [only] = candidates[..] {
                self.take_pair(index, only, Confidence::IdenticalShape, 1.0);
            }
        }
        progress.finish();
    }

    /// Stage three: the same symbol name.
    ///
    /// Weaker than it looks. A name is reliable when it is present, but a
    /// stripped binary has none, and a renamed function keeps its behavior. It
    /// runs after the two code-based stages so that evidence from the code
    /// always wins.
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
impl Cascade<'_> {
    fn match_by_similarity(&mut self, progress: &dyn Progress) {
        // Only the functions still free reach the inner loop, so counting them
        // gives a total the bar can actually reach.
        let remaining = self.left_free.iter().filter(|free| **free).count();
        progress.start(Phase::Similarity, remaining);

        // Scoring only reads, so the rows run in parallel. Each row keeps its
        // own results, and the sort below decides the order, so the answer does
        // not depend on the order the rows finished in.
        let threshold = self.options.threshold;
        let mut candidates: Vec<(f64, usize, usize)> = (0..self.left.len())
            .into_par_iter()
            .filter(|index| self.left_free[*index])
            .map(|index| {
                progress.advance(1);
                if self.left[index].body.is_empty() {
                    return Vec::new();
                }

                (0..self.right.len())
                    .filter(|other| self.right_free[*other] && !self.right[*other].body.is_empty())
                    .filter_map(|other| {
                        let score = similarity_of_symbols(
                            &self.left[index].symbols,
                            &self.right[other].symbols,
                        );
                        (score >= threshold).then_some((score, index, other))
                    })
                    .collect()
            })
            .flatten()
            .collect();

        // Best first. Ties break on index so the answer does not depend on
        // the order two equal scores happened to be found in.
        candidates.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(core::cmp::Ordering::Equal)
                .then_with(|| a.1.cmp(&b.1))
                .then_with(|| a.2.cmp(&b.2))
        });

        for (score, index, other) in candidates {
            if self.left_free[index] && self.right_free[other] {
                self.take_pair(index, other, Confidence::Similar, score);
            }
        }
        progress.finish();
    }
}

/// Similarity of two bodies already reduced to sorted symbols.
///
/// The same Jaccard similarity that [`similarity`] computes, over the same
/// multiset, but by walking two sorted lists rather than building a map. This
/// runs once per candidate pair in the scoring stage, so it allocates nothing.
fn similarity_of_symbols(left: &[Symbol], right: &[Symbol]) -> f64 {
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }

    // Both sides are sorted, so one pass counts the shared instructions. Every
    // instruction counts toward the combined total either way, so the combined
    // count needs no separate walk.
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
/// real mnemonic and operands, not the normalized form the matcher compares.
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
pub fn instruction_diff(
    before: &Function,
    before_isa: Isa,
    after: &Function,
    after_isa: Isa,
) -> Vec<DiffLine> {
    let before_insns = decode_all(&before_isa.arch(), &before.code, before.address).0;
    let after_insns = decode_all(&after_isa.arch(), &after.code, after.address).0;

    // Align on the printed text, but with branch targets collapsed. Keeping the
    // constant in the key is what lets a new `tst r5, #4` stand apart from an
    // existing `tst r5, #8`: the matcher's normalized form drops both to one
    // shape and would pair them, hiding the new gate. Collapsing the target
    // still folds a call whose callee only moved.
    let before_keys: Vec<String> = before_insns.iter().map(diff_key).collect();
    let after_keys: Vec<String> = after_insns.iter().map(diff_key).collect();

    let steps = longest_common_subsequence(&before_keys, &after_keys);
    let lines = lines_from_alignment(&steps, &before_insns, &after_insns);
    coalesce_changed_constants(lines)
}

/// The text two instructions must share to align, with targets removed.
///
/// A branch or a `[pc, #imm]` load prints its target as `$+0x24`; the target
/// moves whenever anything before it changes size, so it must not decide the
/// alignment. Everything else, the constant included, stays: a changed value is
/// a real difference the reader came to see.
fn diff_key(insn: &Insn) -> String {
    let operands = insn
        .operands
        .split(',')
        .map(str::trim)
        .map(|operand| if operand.starts_with('$') { "$" } else { operand })
        .collect::<Vec<_>>()
        .join(", ");
    format!("{} {operands}", insn.mnemonic)
}

/// Fold an adjacent remove-then-add of the same instruction into one line.
///
/// Aligning on the printed text splits a changed constant into a removal and an
/// addition, because the two print differently. They are the same instruction
/// with another value, so they belong on one [`DiffLine::Changed`]. When the
/// two are identical bar their targets they are no change at all. The pair is
/// always adjacent, because the alignment keeps the order.
fn coalesce_changed_constants(lines: Vec<DiffLine>) -> Vec<DiffLine> {
    let mut folded: Vec<DiffLine> = Vec::with_capacity(lines.len());
    for line in lines {
        let pair = match (folded.last(), &line) {
            (Some(DiffLine::Removed(before)), DiffLine::Added(after)) => {
                Some((before.clone(), after.clone()))
            }
            _ => None,
        };

        match pair {
            // The two share the operation and operand shapes, so they are the
            // same instruction. A moved register or branch target is a free
            // choice, so that is no change; a changed constant is a real one.
            Some((before, after)) if same_operation(&before, &after) => {
                folded.pop();
                folded.push(if only_free_choices_differ(&before, &after) {
                    DiffLine::Same(after)
                } else {
                    DiffLine::Changed { before, after }
                });
            }
            _ => folded.push(line),
        }
    }
    folded
}

/// Report whether two same-shape instructions differ in nothing but a register
/// or a branch target.
///
/// Both are free choices the compiler makes, so an instruction that differs
/// only in them did not really change. A differing literal, by contrast, is a
/// changed value the reader must see. Call this only on a pair that already
/// shares its operation.
fn only_free_choices_differ(before: &str, after: &str) -> bool {
    let (_, before_args) = before.split_once(' ').unwrap_or((before, ""));
    let (_, after_args) = after.split_once(' ').unwrap_or((after, ""));

    before_args.split(',').map(str::trim).zip(after_args.split(',').map(str::trim)).all(|(a, b)| {
        a == b
            || (is_register_name(a) && is_register_name(b))
            || (a.starts_with('$') && b.starts_with('$'))
    })
}

/// Report whether two printed instructions share operation and operand shapes.
///
/// This is the printed-text mirror of what the matcher normalizes to: the two
/// agree once a register name or a branch target is allowed to differ. It tells
/// a changed constant, which keeps the same shape, from an unrelated pairing.
fn same_operation(before: &str, after: &str) -> bool {
    let (before_op, before_args) = before.split_once(' ').unwrap_or((before, ""));
    let (after_op, after_args) = after.split_once(' ').unwrap_or((after, ""));
    if normalize_operation(before_op) != normalize_operation(after_op) {
        return false;
    }

    let mut before = before_args.split(',').map(str::trim);
    let mut after = after_args.split(',').map(str::trim);
    loop {
        match (before.next(), after.next()) {
            (None, None) => return true,
            (Some(a), Some(b)) => {
                // A changed constant keeps the same shape, so two literals are
                // interchangeable here: it is the case this fold exists for.
                let interchangeable = a == b
                    || (is_register_name(a) && is_register_name(b))
                    || (a.starts_with('$') && b.starts_with('$'))
                    || (is_literal(a) && is_literal(b));
                if !interchangeable {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

/// Report whether an operand is a numeric literal, which prints as `0x1c` or a
/// bare number.
fn is_literal(operand: &str) -> bool {
    let digits = operand.strip_prefix("0x").unwrap_or(operand);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A move through the alignment grid: keep both sides, or drop one.
#[derive(Clone, Copy)]
enum Step {
    /// The instruction is on both sides; advance both.
    Both,
    /// The instruction is only on the left; advance the left.
    Left,
    /// The instruction is only on the right; advance the right.
    Right,
}

/// Table of the classic longest-common-subsequence dynamic program.
///
/// `len[i][j]` is the length of the longest run of instructions shared by the
/// tails `left[i..]` and `right[j..]`. Reading it back from the top left gives
/// the alignment. Both sides are function bodies, small enough that the
/// quadratic table costs nothing worth avoiding.
fn longest_common_subsequence<T: PartialEq>(left: &[T], right: &[T]) -> Vec<Step> {
    let (rows, cols) = (left.len() + 1, right.len() + 1);
    let mut len = vec![vec![0usize; cols]; rows];

    for i in (0..left.len()).rev() {
        for j in (0..right.len()).rev() {
            len[i][j] = if left[i] == right[j] {
                len[i + 1][j + 1] + 1
            } else {
                len[i + 1][j].max(len[i][j + 1])
            };
        }
    }

    let mut steps = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < left.len() && j < right.len() {
        if left[i] == right[j] {
            steps.push(Step::Both);
            i += 1;
            j += 1;
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

/// Turn an alignment into diff lines, reading the printed text for each side.
///
/// A line the alignment kept on both sides is unchanged, targets aside.
/// A changed constant reaches here as a removal next to an addition;
/// [`coalesce_changed_constants`] folds that pair back into one line.
fn lines_from_alignment(
    steps: &[Step],
    before_insns: &[Insn],
    after_insns: &[Insn],
) -> Vec<DiffLine> {
    let mut lines = Vec::with_capacity(steps.len());
    let (mut i, mut j) = (0, 0);
    for step in steps {
        match step {
            Step::Both => {
                lines.push(DiffLine::Same(after_insns[j].to_string()));
                i += 1;
                j += 1;
            }
            Step::Left => {
                lines.push(DiffLine::Removed(before_insns[i].to_string()));
                i += 1;
            }
            Step::Right => {
                lines.push(DiffLine::Added(after_insns[j].to_string()));
                j += 1;
            }
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::{Insn, InsnKind};
    use crate::norm::normalize;

    fn body(operations: &[(&str, &str)]) -> Vec<NormInsn> {
        operations
            .iter()
            .map(|(mnemonic, operands)| {
                normalize(&Insn {
                    address: 0,
                    bytes_len: 4,
                    mnemonic: mnemonic.to_string(),
                    operands: operands.to_string(),
                    kind: InsnKind::Normal,
                })
            })
            .collect()
    }

    #[test]
    fn a_body_is_identical_to_itself() {
        let only = body(&[("add", "r0, r1, r2"), ("mul", "r0, r0, r1")]);
        assert_eq!(similarity(&only, &only), 1.0);
    }

    #[test]
    fn two_empty_bodies_are_identical() {
        assert_eq!(similarity(&[], &[]), 1.0);
    }

    #[test]
    fn an_empty_body_shares_nothing_with_a_full_one() {
        assert_eq!(similarity(&[], &body(&[("add", "r0, r1, r2")])), 0.0);
    }

    #[test]
    fn similarity_does_not_depend_on_the_order_of_its_arguments() {
        let left = body(&[("add", "r0, r1, r2"), ("mul", "r0, r0, r1")]);
        let right = body(&[("add", "r0, r1, r2"), ("sub", "r0, r0, r1")]);
        assert_eq!(similarity(&left, &right), similarity(&right, &left));
    }

    /// Reordering the same instructions is not the same as editing them.
    #[test]
    fn reordering_is_told_apart_from_editing() {
        let original = body(&[("mov", "r0, 0x1"), ("mvn", "r1, 0x2"), ("cmp", "r0, r1")]);
        let moved = body(&[("mvn", "r1, 0x2"), ("cmp", "r0, r1"), ("mov", "r0, 0x1")]);
        let edited = body(&[("mov", "r0, 0x1"), ("ldr", "r1, [r2]"), ("cmp", "r0, r1")]);

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
        // The two encodings of that kernel size field, as they decode.
        let before = [("eoreq".to_string(), "r0, fp, r8, lsr 17".to_string())];
        let after = [("eoreq".to_string(), "r3, fp, r8, asr 24".to_string())];

        assert!(
            !operands_are_interchangeable(&before[0].1, &after[0].1, TargetMoves::Never),
            "a shift that changed is not a register that changed"
        );
    }

    /// A register the compiler picked differently is not an edit.
    #[test]
    fn a_changed_register_is_not_a_change() {
        assert!(operands_are_interchangeable("r0, r1, r2", "r4, r5, r6", TargetMoves::Never));
        assert!(operands_are_interchangeable("r0, fp, r8", "r3, fp, r8", TargetMoves::Never));
    }

    /// A call whose callee moved is not an edit.
    ///
    /// Anything that changes size shifts every target after it, so a whole
    /// image of unedited functions would otherwise read as changed.
    #[test]
    fn a_moved_branch_target_is_not_a_change() {
        assert!(operands_are_interchangeable("$+0x50a734", "$+0x50b2d4", TargetMoves::Freely));
    }

    /// A `$...` operand on an instruction that does not branch is data, and a
    /// changed data word must stay visible.
    #[test]
    fn a_target_that_is_not_a_branch_stays_a_change() {
        assert!(!operands_are_interchangeable("$+0x50a734", "$+0x50b2d4", TargetMoves::Never));
    }

    /// Allowing targets to move must not let anything else move with them.
    #[test]
    fn a_branch_still_reports_its_other_operands() {
        assert!(!operands_are_interchangeable("r0, 0x10", "r0, 0x20", TargetMoves::Freely));
    }

    /// A condition code is the compiler's choice, not an edit.
    ///
    /// `movwlt` against `movwlo` is signed against unsigned less-than. Both
    /// appear for the same source at different optimization levels, and
    /// reporting it as a change cried wolf on the test corpus.
    #[test]
    fn a_changed_condition_is_not_a_change() {
        assert_eq!(normalize_operation("movwlt"), normalize_operation("movwlo"));
    }

    #[test]
    fn a_register_name_is_recognized() {
        for name in ["r0", "r12", "sp", "lr", "pc", "fp"] {
            assert!(is_register_name(name), "{name} is a register");
        }
        for other in ["0x1c", "[sp, 0x4]", "{r4, lr}", "lsr 17", ""] {
            assert!(!is_register_name(other), "{other} is not a register");
        }
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

    /// Building a `Binary` by hand keeps these tests free of fixture files.
    fn binary_of(functions: &[(&str, &[u8])]) -> crate::obj::Binary {
        crate::obj::Binary {
            isa: Isa::Arm32,
            found_by: crate::obj::FoundBy::Symbols,
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
        let after = binary_of(&[("other", MUL_THEN_RETURN)]);

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
    /// puts them back: same text is no change, a changed value is one
    /// [`DiffLine::Changed`], and an unrelated pair is left apart.
    #[test]
    fn an_adjacent_remove_and_add_fold_by_shape() {
        let lines = vec![
            // Identical bar the target: no change.
            DiffLine::Removed("bl $+0x40".to_string()),
            DiffLine::Added("bl $+0x80".to_string()),
            // Same operation, changed value: one changed line.
            DiffLine::Removed("mov r1, 0x25".to_string()),
            DiffLine::Added("mov r1, 0x29".to_string()),
            // Unrelated: stays two lines.
            DiffLine::Removed("push {lr}".to_string()),
            DiffLine::Added("mul r0, r0, r1".to_string()),
        ];
        let folded = coalesce_changed_constants(lines);
        assert_eq!(
            folded,
            vec![
                DiffLine::Same("bl $+0x80".to_string()),
                DiffLine::Changed {
                    before: "mov r1, 0x25".to_string(),
                    after: "mov r1, 0x29".to_string(),
                },
                DiffLine::Removed("push {lr}".to_string()),
                DiffLine::Added("mul r0, r0, r1".to_string()),
            ]
        );
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
        let after = binary_of(&[("other", MUL_THEN_RETURN)]);

        // A threshold of 1.0 refuses everything below an exact match, so both
        // sides are left for the near-miss report.
        let diff = diff_with(&before, &after, Options { threshold: 1.0, use_names: UseNames::No });

        assert_eq!(diff.added, vec![0], "nothing could be paired");
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
                    body.iter().map(|insn| interner.intern(insn.clone())).collect();
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
            (body(&[("add", "r0, r1, r2")]), body(&[("add", "r0, r1, r2")])),
            // Nothing shared.
            (body(&[("ldr", "r0, [r1]")]), body(&[("mul", "r0, r0, r1")])),
            // Partly shared.
            (
                body(&[("add", "r0, r1, r2"), ("mul", "r0, r0, r1")]),
                body(&[("add", "r0, r1, r2"), ("sub", "r0, r0, r1")]),
            ),
            // One side empty.
            (Vec::new(), body(&[("add", "r0, r1, r2")])),
            // Both empty.
            (Vec::new(), Vec::new()),
            // Repeats, where the multiset matters rather than the set.
            (
                body(&[("add", "r0, r1, r2"), ("add", "r0, r1, r2"), ("add", "r0, r1, r2")]),
                body(&[("add", "r0, r1, r2")]),
            ),
            // The same instructions in a different order.
            (
                body(&[("add", "r0, r1, r2"), ("mul", "r0, r0, r1")]),
                body(&[("mul", "r0, r0, r1"), ("add", "r0, r1, r2")]),
            ),
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

        let same_shape_other_constant = body(&[("mov", "r0, 0x1"), ("mov", "r0, 0x2")]);
        let first = interner.intern(same_shape_other_constant[0].clone());
        let second = interner.intern(same_shape_other_constant[1].clone());
        assert_eq!(first, second, "constants stay out of equality, so out of the symbol");

        let different = body(&[("ldr", "r0, [r1]")]);
        let third = interner.intern(different[0].clone());
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
        let base = body(&[("add", "r0, r1, r2"), ("mul", "r0, r0, r1")]);
        let half = body(&[("add", "r0, r1, r2"), ("sub", "r0, r0, r1")]);
        let none = body(&[("ldr", "r0, [r1]"), ("str", "r0, [r2]")]);

        assert!(similarity(&base, &half) > similarity(&base, &none));
        assert_eq!(similarity(&base, &none), 0.0);
    }
}
