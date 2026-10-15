//! The cascade: the stages that pair functions, strongest first.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::norm::NormInsn;
use hereticus_callees::Callee;
use rayon::prelude::*;

use super::align::{Layout, align_by_scores, longest_increasing_chain};
use super::change::{classify_change, count_edits};
use super::score::{
    CLOSE_SIMILARITY, CONSTANT_WEIGHT, Context, FEWEST_SHARED_EDGES, FLOW_RESCUE,
    LOWEST_CONTEXT_SIMILARITY, LOWEST_LAYOUT_SIMILARITY, LOWEST_MOVED_SIMILARITY,
    LOWEST_UNIQUE_REFERENCE_SIMILARITY, MOST_HOLDERS_OF_AN_EDGE, MOST_PLACE_CELLS,
    MOST_UNIQUE_REFERENCE_ROUNDS, MOVED_SIMILARITY_MARGIN, Place, REFERENCE_WEIGHT, RIVAL_MARGIN,
    ReferenceKey, common_keys, constant_agreement, group_by_shape_and_references,
    keep_best_candidates, lacks_context, long_texts, reference_agreement, saturated,
    short_texts_changed, similarity_of_symbols, sorted_only_in, sorted_shared, texts_that_differ,
    unique_reference_holders,
};
use super::{
    Changed, Confidence, Diff, EditKinds, Edits, LOWEST_JOINED_SIMILARITY, Match, Options, Phase,
    Prepared, Progress, Symbol, UseNames, same_detail,
};

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
pub(super) struct Cascade<'a> {
    pub(super) left: Vec<Prepared<'a>>,
    pub(super) right: Vec<Prepared<'a>>,
    /// Whether each function of the first binary is still unpaired.
    pub(super) left_free: Vec<bool>,
    /// Whether each function of the second binary is still unpaired.
    pub(super) right_free: Vec<bool>,
    pub(super) matched: Vec<Match>,
    pub(super) options: Options,
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
    ///
    /// [`FEWEST_PAIRED_NEIGHBOURS`]: super::score::FEWEST_PAIRED_NEIGHBOURS
    /// [`WEAK_PAIR_SIMILARITY`]: super::score::WEAK_PAIR_SIMILARITY
    /// [`LEAST_AGREEING_SHARE_OUT_OF_PLACE`]: super::score::LEAST_AGREEING_SHARE_OUT_OF_PLACE
    pub(super) fn unpair_without_context(&mut self) {
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
    pub(super) fn realign_by_context(&mut self) {
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
    pub(super) fn pair_by_layout(&mut self) {
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
    pub(super) fn pair_by_unique_references_until_settled(&mut self) {
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
    /// counts `CALLER_WEIGHT` more for the stubs its calls line up. Every
    /// place a gap can go keeps as many pairs, so a caller decides where the
    /// gap goes. It cannot pull a stub out of order, which would cost more
    /// pairs than it weighs: an edited caller calls a new stub, and that must
    /// not undo the order that shows the edit. A stub the alignment leaves
    /// out went or came.
    ///
    /// See RESEARCH.md, A5.
    pub(super) fn align_stubs(&mut self) {
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
    /// them, and a swap needs `FEWEST_VOTERS` callers for it. Otherwise one
    /// edited caller outvotes the rest and hides its own edit: the tinyxml2
    /// fix makes three calls to a new PLT stub, whose twins pair by order.
    /// Where similarity cannot choose, one caller is enough; see
    /// [`Self::is_near_tie`].
    ///
    /// See RESEARCH.md, A10.
    pub(super) fn pair_by_callers(&mut self) {
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
    /// must score within `NEAR_TIE` of them on average. Measured on
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
    pub(super) fn compare_callees(&mut self) {
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
    pub(super) fn compare_texts(&mut self) {
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
    pub(super) fn finish(mut self, progress: &dyn Progress) -> Diff {
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
}

impl Cascade<'_> {
    /// Stage one: identical machine code.
    ///
    /// The strongest evidence there is, and the cheapest to find. A function
    /// that was not touched and did not move lands here.
    ///
    /// See RESEARCH.md, A1.
    pub(super) fn match_identical_code(&mut self, progress: &dyn Progress) {
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
    pub(super) fn match_identical_shape(&mut self, progress: &dyn Progress) {
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
    pub(super) fn match_twins_in_order(&mut self) {
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
    pub(super) fn match_by_name(&mut self, progress: &dyn Progress) {
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
    pub(super) fn match_by_similarity(&mut self, progress: &dyn Progress) {
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
    ///
    /// [`CANDIDATES_PER_FUNCTION`]: super::score::CANDIDATES_PER_FUNCTION
    pub(super) fn pair_leftover_twins(&mut self) {
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
    pub(super) fn repair_twins_by_callees(&mut self) {
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
    pub(super) fn uncross_by_callees(&mut self) {
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
