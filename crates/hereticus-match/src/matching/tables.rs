//! Pair functions by their slot in a table of functions.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::Confidence;
use super::cascade::Cascade;
use super::score::similarity_of_symbols;

/// The lowest similarity at which two free functions pair by their slot.
///
/// Measured against the symbols: at 0.5 the backports paired 102 fewer
/// right and the kernels 84 fewer right and 5 more wrong; at 0.1 the
/// backports paired 5 more wrong and the kernels 12 more wrong.
const LOWEST_SLOT_SIMILARITY: f64 = 0.3;

impl Cascade<'_> {
    /// Pair two functions that sit in the same slot of two tables of
    /// functions that firmer pairs already join.
    ///
    /// A C++ vtable lists the virtual functions of a class in the order the
    /// source declares them, whatever the compiler, and a C table of
    /// handlers keeps the order of its fields. Measured on tinyxml2 between
    /// clang and GCC, the twins left wrong were all virtual:
    /// `XMLNode::ToComment` and `XMLNode::ToText` both return null, and
    /// `MemPoolT<52>::Free` and `MemPoolT<60>::Free` are the same code. A
    /// vtable also holds functions that differ, as `MemPoolT<52>::ItemSize`,
    /// which returns 52, and those say which tables are one.
    ///
    /// Two tables are one where each is the other's best match by the
    /// slots that firm pairs join, with no tie, and where no firm pair joins
    /// a function of one to another slot of the other, as where a release
    /// added a virtual function and moved the slots. A function pairs by its slot
    /// only where every such table agrees on its partner, and then only
    /// with a twin, or with a free function of similar code where it is
    /// free too. A pair this breaks is one the code could not choose: twins
    /// in order, or a pair by similarity or by place.
    ///
    /// See RESEARCH.md, entry 15.
    pub(super) fn pair_by_tables(&mut self) {
        let pair_of_before: HashMap<usize, usize> =
            self.matched.iter().enumerate().map(|(index, pair)| (pair.before, index)).collect();
        let pair_of_after: HashMap<usize, usize> =
            self.matched.iter().enumerate().map(|(index, pair)| (pair.after, index)).collect();
        let firm = |index: Option<&usize>| {
            index.is_some_and(|&index| !is_breakable(self.matched[index].confidence))
        };
        let slot = |before: usize, after: usize| match (
            pair_of_before.get(&before),
            pair_of_after.get(&after),
        ) {
            // Twins in order may be the very pairs this stage corrects.
            (Some(&left), Some(&right)) if left == right => match self.matched[left].confidence {
                Confidence::TwinInOrder => Slot::Open,
                _ => Slot::Joined,
            },
            (left, right) if firm(left) || firm(right) => Slot::Crossed,
            _ => Slot::Open,
        };

        let mut votes_before: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        let mut votes_after: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        for (left, right) in self.same_tables(slot) {
            for (&before, &after) in self.left_tables[left].iter().zip(&self.right_tables[right]) {
                votes_before.entry(before).or_default().insert(after);
                votes_after.entry(after).or_default().insert(before);
            }
        }

        let breakable = |index: Option<&usize>| {
            index.is_none_or(|&index| is_breakable(self.matched[index].confidence))
        };
        let pairs: Vec<(usize, usize)> = votes_before
            .iter()
            .filter_map(|(&before, afters)| {
                let &after = only(afters)?;
                (only(votes_after.get(&after)?) == Some(&before)).then_some((before, after))
            })
            .filter(|&(before, after)| {
                let (pair_before, pair_after) =
                    (pair_of_before.get(&before), pair_of_after.get(&after));
                let paired_already = pair_before.is_some() && pair_before == pair_after;
                let twins = self.left[before].ordered == self.right[after].ordered;
                let both_free = pair_before.is_none() && pair_after.is_none();
                let fits = twins
                    || (both_free && self.similarity_of(before, after) >= LOWEST_SLOT_SIMILARITY);
                !paired_already && fits && breakable(pair_before) && breakable(pair_after)
            })
            .collect();
        if pairs.is_empty() {
            return;
        }

        let undone: BTreeSet<usize> = pairs
            .iter()
            .flat_map(|(before, after)| [pair_of_before.get(before), pair_of_after.get(after)])
            .flatten()
            .copied()
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
        for (before, after) in pairs {
            let score = self.similarity_of(before, after);
            self.take_pair(before, after, Confidence::SameTable, score);
        }
    }

    /// The similarity of the code of `before` and `after`.
    fn similarity_of(&self, before: usize, after: usize) -> f64 {
        similarity_of_symbols(&self.left[before].symbols, &self.right[after].symbols)
    }

    /// The tables of the two sides that are one, by their indices: each the
    /// other's best match by the slots `joins` accepts, with no tie.
    fn same_tables(&self, slot: impl Fn(usize, usize) -> Slot) -> Vec<(usize, usize)> {
        let mut by_length: HashMap<usize, Vec<usize>> = HashMap::new();
        for (index, table) in self.right_tables.iter().enumerate() {
            by_length.entry(table.len()).or_default().push(index);
        }
        // The slots each pair of tables of one length shares, where any.
        let mut shared: Vec<(usize, usize, usize)> = Vec::new();
        for (left, table) in self.left_tables.iter().enumerate() {
            for &right in by_length.get(&table.len()).into_iter().flatten() {
                let slots: Vec<Slot> = table
                    .iter()
                    .zip(&self.right_tables[right])
                    .map(|(&before, &after)| slot(before, after))
                    .collect();
                let count = slots.iter().filter(|&&slot| slot == Slot::Joined).count();
                if count > 0 && !slots.contains(&Slot::Crossed) {
                    shared.push((left, right, count));
                }
            }
        }
        let best_of_left =
            best_matches(shared.iter().map(|&(left, right, count)| (left, right, count)));
        let best_of_right =
            best_matches(shared.iter().map(|&(left, right, count)| (right, left, count)));
        let mut tables: Vec<(usize, usize)> = best_of_left
            .iter()
            .filter_map(|(&left, best)| Some((left, best.alone()?)))
            .filter(|&(left, right)| best_of_right.get(&right).and_then(Best::alone) == Some(left))
            .collect();
        tables.sort_unstable();
        tables
    }
}

/// What the pairs so far say of two functions in one slot of two tables.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    /// A firm pair joins the two.
    Joined,
    /// A firm pair joins one of them to another function.
    Crossed,
    /// Neither: they are free, or paired on ground this stage may break.
    Open,
}

/// Report whether a pair of `confidence` is one the code could not choose,
/// which a slot may break.
fn is_breakable(confidence: Confidence) -> bool {
    matches!(confidence, Confidence::TwinInOrder | Confidence::Similar | Confidence::SameLayout)
}

/// The one member of `set`, or `None` where it holds none or more.
fn only(set: &BTreeSet<usize>) -> Option<&usize> {
    set.first().filter(|_| set.len() == 1)
}

/// The best match of a table so far.
#[derive(Clone, Copy)]
struct Best {
    /// The table on the other side.
    other: usize,
    /// The slots the two share.
    count: usize,
    /// Whether another table shares as many.
    rival: Rival,
}

/// Whether a best match has a rival.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Rival {
    /// No other table shares as many slots.
    None,
    /// Another table shares as many slots.
    Tied,
}

impl Best {
    /// The other table, where none ties with it.
    fn alone(&self) -> Option<usize> {
        (self.rival == Rival::None).then_some(self.other)
    }
}

/// The best match of each table by its count of shared slots, from
/// `(table, other, count)`.
fn best_matches(shared: impl Iterator<Item = (usize, usize, usize)>) -> HashMap<usize, Best> {
    let mut best: HashMap<usize, Best> = HashMap::new();
    for (table, other, count) in shared {
        let candidate = Best { other, count, rival: Rival::None };
        best.entry(table)
            .and_modify(|best| {
                if count > best.count {
                    *best = candidate;
                } else if count == best.count {
                    best.rival = Rival::Tied;
                }
            })
            .or_insert(candidate);
    }
    best
}
