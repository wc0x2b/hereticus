//! Code that moved between a function and a function it calls.
//!
//! A release can move the body of a function into a new callee and leave a
//! wrapper with the old name, or inline a callee into its caller. The code
//! of the old function then matches the new callee, or the old callee the
//! new caller, and a stage pairs those. The two functions of one side, read
//! as one, match better.
//!
//! See RESEARCH.md, entry 17.

use std::collections::{BTreeSet, HashMap};

use hereticus_callees::Callee;

use super::cascade::Cascade;
use super::score::similarity_of_symbols;
use super::{Prepared, Symbol};

/// How much more than the pair alone the two functions of one side, read as
/// one, must score before [`Cascade::pair_moved_code`] moves the pair.
///
/// Measured against the symbols, once [`Cascade::unpair_across_files`] ran,
/// 0.1 paired 114 more right and 112 fewer wrong over the OpenWrt kernels,
/// and 2 more right and 2 fewer wrong over the Ubuntu updates. 0.2 paired 62
/// more right and 61 fewer wrong.
///
/// [`Cascade::unpair_across_files`]: super::cascade::Cascade::unpair_across_files
pub(super) const MOVED_CODE_MARGIN: f64 = 0.1;

/// The callers of each function of `side`, itself left out.
fn callers_of(side: &[Prepared<'_>]) -> Vec<BTreeSet<usize>> {
    let mut callers = vec![BTreeSet::new(); side.len()];
    for (caller, prepared) in side.iter().enumerate() {
        for callee in &prepared.calls {
            if let Callee::Function(callee) = *callee
                && callee != caller
                && let Some(set) = callers.get_mut(callee)
            {
                set.insert(caller);
            }
        }
    }
    callers
}

/// The symbols of two functions as the body of one, sorted.
pub(super) fn joined(first: &[Symbol], second: &[Symbol]) -> Vec<Symbol> {
    let mut all = [first, second].concat();
    all.sort_unstable();
    all
}

/// Whether a caller in `mine` has its partner, by `partner`, in `theirs`.
fn share_a_caller(
    mine: &BTreeSet<usize>,
    theirs: &BTreeSet<usize>,
    partner: &HashMap<usize, usize>,
) -> bool {
    mine.iter().filter_map(|caller| partner.get(caller)).any(|caller| theirs.contains(caller))
}

/// A better pair for a pair, by its index in [`Cascade::matched`].
struct Move {
    index: usize,
    before: usize,
    after: usize,
}

impl Cascade<'_> {
    /// Move a weak pair to the free caller that, read with its callee, matches
    /// better: the wrapper that kept the place of the old function, or the
    /// caller that inlined the old callee.
    ///
    /// The free caller must share a paired caller with the other side, so a
    /// function that merely calls the moved code does not take its place.
    /// The moved code stays free, as the new function or the deleted one
    /// that it is.
    ///
    /// See RESEARCH.md, entry 17 (O2NMatcher and N2NMatcher), which match one
    /// function with a function and its inlined callees.
    pub(super) fn pair_moved_code(&mut self) {
        let (left_callers, right_callers) = (callers_of(&self.left), callers_of(&self.right));
        let partner: HashMap<usize, usize> =
            self.matched.iter().map(|pair| (pair.before, pair.after)).collect();
        let back: HashMap<usize, usize> =
            self.matched.iter().map(|pair| (pair.after, pair.before)).collect();
        let moves: Vec<Move> = self
            .matched
            .iter()
            .enumerate()
            .filter(|(_, pair)| pair.confidence.is_weak())
            .filter_map(|(index, pair)| {
                let (old, new) = (pair.before, pair.after);
                let (old_symbols, new_symbols) =
                    (&self.left[old].symbols, &self.right[new].symbols);
                let alone = similarity_of_symbols(old_symbols, new_symbols);
                let wrappers = right_callers[new]
                    .iter()
                    .filter(|&&wrapper| {
                        self.right_free[wrapper]
                            && share_a_caller(&left_callers[old], &right_callers[wrapper], &partner)
                    })
                    .map(|&wrapper| {
                        let read_as_one = joined(&self.right[wrapper].symbols, new_symbols);
                        (similarity_of_symbols(old_symbols, &read_as_one), old, wrapper)
                    });
                let inliners = left_callers[old]
                    .iter()
                    .filter(|&&inliner| {
                        self.left_free[inliner]
                            && share_a_caller(&right_callers[new], &left_callers[inliner], &back)
                    })
                    .map(|&inliner| {
                        let read_as_one = joined(&self.left[inliner].symbols, old_symbols);
                        (similarity_of_symbols(&read_as_one, new_symbols), inliner, new)
                    });
                // The first of the best, so the answer does not depend on how
                // `max_by` breaks a tie.
                wrappers
                    .chain(inliners)
                    .filter(|&(score, _, _)| score > alone + MOVED_CODE_MARGIN)
                    .reduce(|best, next| if next.0 > best.0 { next } else { best })
                    .map(|(_, before, after)| Move { index, before, after })
            })
            .collect();

        let mut undone = vec![false; self.matched.len()];
        let mut taken = Vec::new();
        let (mut taken_left, mut taken_right) = (BTreeSet::new(), BTreeSet::new());
        for Move { index, before, after } in moves {
            if taken_left.insert(before) && taken_right.insert(after) {
                undone[index] = true;
                taken.push((before, after, self.matched[index].confidence));
            }
        }
        self.unpair(&undone);
        for (before, after, confidence) in taken {
            if self.left_free[before] && self.right_free[after] {
                let score =
                    similarity_of_symbols(&self.left[before].symbols, &self.right[after].symbols);
                self.take_pair(before, after, confidence, score);
            }
        }
    }
}
