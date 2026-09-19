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

use crate::arch::decode_all;
use crate::norm::{NormInsn, normalize_body, normalize_operation};
use crate::obj::{Binary, Function};

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
}

/// Whether a matched pair differs, and how.
///
/// A pair can match and still differ. Normalizing hides the detail a compiler
/// picks freely, so two functions that normalize alike can still hold
/// different constants.
///
/// The variants rise in how much a reader should care, so
/// `Changed::No < Changed::Reordered < Changed::InDetail < Changed::Yes`.
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
    /// The instructions themselves differ.
    Yes,
}

/// A function with no counterpart, and the closest thing to one.
///
/// A function can go unmatched because it really was removed, or because the
/// two builds compiled it too differently to recognize. Those need different
/// responses from a reader, and the score separates them: a near miss at 0.38
/// is worth opening a disassembler for, one at 0.02 is not.
///
/// Reporting the score costs nothing. It was computed while matching and then
/// thrown away.
#[derive(Clone, Copy, Debug)]
pub struct NearMiss {
    /// Index into the functions of the first binary.
    pub before: usize,
    /// The closest candidate in the second binary, if any was scored.
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
}

impl Diff {
    /// Matched pairs that differ in any way.
    pub fn changed(&self) -> impl Iterator<Item = &Match> {
        self.matched.iter().filter(|pair| pair.changed != Changed::No)
    }

    /// The near miss for a removed function, if one was found.
    pub fn near_miss(&self, before: usize) -> Option<&NearMiss> {
        self.near_misses.iter().find(|miss| miss.before == before)
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

/// A function together with the forms the cascade compares.
struct Prepared<'a> {
    function: &'a Function,
    body: Vec<NormInsn>,
    /// Each instruction as decoded, before normalizing: the operation and its
    /// operands.
    ///
    /// Normalizing throws away detail on purpose, which is what lets a
    /// function match itself across builds. Telling a changed register from a
    /// changed word of data needs that detail back, so it is kept here.
    printed: Vec<(String, String)>,
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
fn prepare(binary: &Binary) -> Vec<Prepared<'_>> {
    let arch = binary.isa.arch();
    binary
        .functions
        .iter()
        .map(|function| {
            let (insns, _) = decode_all(&arch, &function.code, function.address);
            let printed =
                insns.iter().map(|insn| (insn.mnemonic.clone(), insn.operands.clone())).collect();
            Prepared { function, body: normalize_body(&insns), printed }
        })
        .collect()
}

/// Compare two binaries with the default settings.
pub fn diff(before: &Binary, after: &Binary) -> Diff {
    diff_with(before, after, Options::default())
}

/// Compare two binaries.
pub fn diff_with(before: &Binary, after: &Binary, options: Options) -> Diff {
    let mut cascade = Cascade {
        left: prepare(before),
        right: prepare(after),
        left_free: vec![true; before.functions.len()],
        right_free: vec![true; after.functions.len()],
        matched: Vec::new(),
        options,
    };

    cascade.match_identical_code();
    cascade.match_identical_shape();
    if options.use_names == UseNames::Yes {
        cascade.match_by_name();
    }
    cascade.match_by_similarity();

    cascade.finish()
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
        self.matched.push(Match {
            before,
            after,
            confidence,
            score,
            changed: classify_change(&self.left[before], &self.right[after]),
        });
    }

    /// Sort the pairs and collect what stayed unmatched.
    fn finish(mut self) -> Diff {
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
        let near_misses = self.near_misses(&removed, &added);

        Diff { removed, added, near_misses, matched: self.matched }
    }

    /// Find the closest candidate for each function that stayed unmatched.
    ///
    /// This compares only the functions no stage could place, against only the
    /// functions still free to take. Both sets are small by the time the
    /// cascade is done, so the cost is a fraction of the matching pass that
    /// preceded it.
    fn near_misses(&self, removed: &[usize], added: &[usize]) -> Vec<NearMiss> {
        removed
            .iter()
            .map(|before| {
                let best = added
                    .iter()
                    .map(|after| {
                        (similarity(&self.left[*before].body, &self.right[*after].body), *after)
                    })
                    .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(core::cmp::Ordering::Equal));

                match best {
                    Some((score, after)) => NearMiss { before: *before, best: Some(after), score },
                    None => NearMiss { before: *before, best: None, score: 0.0 },
                }
            })
            .collect()
    }
}

/// Report whether two bodies differ only in which registers they name.
///
/// Both sides already normalize alike, so this decides whether the bytes
/// behind them differ for a reason a reader should hear about. It compares the
/// instructions as printed: register names are allowed to differ, anything
/// else is a real difference.
///
/// A word of data among the instructions fails this check, which is the point.
/// It decodes as some instruction, and when its bits change it usually becomes
/// a *different* instruction rather than the same one with another register.
fn differs_only_in_registers(before: &Prepared<'_>, after: &Prepared<'_>) -> bool {
    if before.printed.len() != after.printed.len() {
        return false;
    }

    before.printed.iter().zip(&after.printed).all(|(left, right)| {
        // Compare the operation the way the normalizer does, so a condition
        // code the compiler chose differently — `movwlt` against `movwlo` —
        // stays the free choice it is rather than reading as an edit.
        normalize_operation(&left.0) == normalize_operation(&right.0)
            && operands_differ_only_by_register(&left.1, &right.1)
    })
}

/// Compare two operand lists, allowing register names to differ.
fn operands_differ_only_by_register(left: &str, right: &str) -> bool {
    let left = left.split(',').map(str::trim);
    let right = right.split(',').map(str::trim);

    left.zip(right).all(|(a, b)| a == b || (is_register_name(a) && is_register_name(b)))
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
        return if differs_only_in_registers(before, after) {
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

    if before_sorted == after_sorted { Changed::Reordered } else { Changed::Yes }
}

impl Cascade<'_> {
    /// Stage one: identical machine code.
    ///
    /// The strongest evidence there is, and the cheapest to find. A function
    /// that was not touched and did not move lands here.
    fn match_identical_code(&mut self) {
        let mut by_code: HashMap<&[u8], Vec<usize>> = HashMap::new();
        for (index, prepared) in self.right.iter().enumerate() {
            by_code.entry(prepared.function.code.as_slice()).or_default().push(index);
        }

        let mut pairs = Vec::new();
        for (index, prepared) in self.left.iter().enumerate() {
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
    }

    /// Stage two: identical normalized instructions.
    ///
    /// This is the stage that survives recompilation. Two builds of one
    /// function differ in register choice and branch addresses, which
    /// normalizing removes, so what remains agrees exactly.
    fn match_identical_shape(&mut self) {
        for index in 0..self.left.len() {
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
    }

    /// Stage three: the same symbol name.
    ///
    /// Weaker than it looks. A name is reliable when it is present, but a
    /// stripped binary has none, and a renamed function keeps its behavior. It
    /// runs after the two code-based stages so that evidence from the code
    /// always wins.
    fn match_by_name(&mut self) {
        let mut by_name: HashMap<String, usize> = HashMap::new();
        for (index, prepared) in self.right.iter().enumerate() {
            if self.right_free[index] && !prepared.function.name.is_empty() {
                by_name.insert(prepared.function.name.clone(), index);
            }
        }

        for index in 0..self.left.len() {
            if !self.left_free[index] || self.left[index].function.name.is_empty() {
                continue;
            }
            let Some(&other) = by_name.get(&self.left[index].function.name) else { continue };
            if !self.right_free[other] {
                continue;
            }

            let score = similarity(&self.left[index].body, &self.right[other].body);
            self.take_pair(index, other, Confidence::SameName, score);
        }
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
    fn match_by_similarity(&mut self) {
        let mut candidates: Vec<(f64, usize, usize)> = Vec::new();
        for index in 0..self.left.len() {
            if !self.left_free[index] || self.left[index].body.is_empty() {
                continue;
            }
            for other in 0..self.right.len() {
                if !self.right_free[other] || self.right[other].body.is_empty() {
                    continue;
                }
                let score = similarity(&self.left[index].body, &self.right[other].body);
                if score >= self.options.threshold {
                    candidates.push((score, index, other));
                }
            }
        }

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
    }
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
            !operands_differ_only_by_register(&before[0].1, &after[0].1),
            "a shift that changed is not a register that changed"
        );
    }

    /// A register the compiler picked differently is not an edit.
    #[test]
    fn a_changed_register_is_not_a_change() {
        assert!(operands_differ_only_by_register("r0, r1, r2", "r4, r5, r6"));
        assert!(operands_differ_only_by_register("r0, fp, r8", "r3, fp, r8"));
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
    }

    /// Building a `Binary` by hand keeps these tests free of fixture files.
    fn binary_of(functions: &[(&str, &[u8])]) -> crate::obj::Binary {
        crate::obj::Binary {
            isa: crate::obj::Isa::Arm32,
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

    /// A matched function is not a near miss, so the report stays short.
    #[test]
    fn matched_functions_are_not_reported_as_near_misses() {
        let before = binary_of(&[("same", ADD_THEN_RETURN)]);
        let after = binary_of(&[("same", ADD_THEN_RETURN)]);

        let diff = diff_with(&before, &after, Options::default());

        assert_eq!(diff.matched.len(), 1);
        assert!(diff.near_misses.is_empty(), "nothing went unmatched");
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
