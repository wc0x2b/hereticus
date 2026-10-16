//! The alignment of two bodies, item by item.

use std::collections::HashMap;

use hereticus_arch::Arch;

use hereticus_il::arch::Insn;

use super::change::{Difference, FrameSlots, difference};
use super::lines::DiffLine;
use super::score::LEAST_ANCHORED_SHARE;

/// A move through the alignment grid: keep both sides, or drop one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
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
pub(super) const LARGEST_ALIGNMENT: usize = 16 * 1024 * 1024;

/// Align two sequences: exactly where the table fits, and by anchors where
/// it does not.
///
/// The exact walk is `longest_common_subsequence`, which is quadratic in
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
pub(super) fn align<T: Eq + core::hash::Hash>(left: &[T], right: &[T]) -> Vec<Step> {
    align_within(left, right, LARGEST_ALIGNMENT)
}

/// [`align`], with the largest table to build given, so a test can reach
/// the anchors with short sequences.
pub(super) fn align_within<T: Eq + core::hash::Hash>(
    left: &[T],
    right: &[T],
    largest: usize,
) -> Vec<Step> {
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
///
/// [`Cascade::layout`]: super::cascade::Cascade::layout
pub(super) struct Layout {
    /// The functions of the first binary, by address.
    pub(super) left_order: Vec<usize>,
    /// The functions of the second binary, by address.
    pub(super) right_order: Vec<usize>,
    /// The place of each function of the first binary in `left_order`.
    pub(super) left_place: Vec<usize>,
    /// The place of each function of the second binary in `right_order`.
    pub(super) right_place: Vec<usize>,
    /// The longest chain of pairs in the same order on both sides, as
    /// places.
    pub(super) chain: Vec<(usize, usize)>,
}

impl Layout {
    /// Whether too few pairs keep their order for a place to mean anything.
    ///
    /// Two unrelated binaries pair few functions, and the place of one there
    /// means nothing: see [`LEAST_ANCHORED_SHARE`].
    pub(super) fn is_unanchored(&self) -> bool {
        let smaller = self.left_order.len().min(self.right_order.len());
        (self.chain.len() as f64) < LEAST_ANCHORED_SHARE * smaller as f64
    }

    /// The free functions of each gap between two pairs of the chain, in
    /// address order, on the first and the second binary.
    ///
    /// Each gap runs from just after one pair to just before the next, and
    /// the ends of the binaries bound the first and the last.
    pub(super) fn gaps<'a>(
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
pub(super) fn align_by_scores(
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

/// Align a gap of as many items on each side, as `scores[x][y]` scores
/// item `x` of the first side against item `y` of the second.
///
/// The first pairs with the first, and so on, unless [`align_by_scores`],
/// with each score less `floor`, sums `margin` more.
pub(super) fn align_gap(scores: &[Vec<f64>], floor: f64, margin: f64) -> Vec<(usize, usize)> {
    let in_order: Vec<(usize, usize)> = (0..scores.len()).map(|place| (place, place)).collect();
    let sum = |pairs: &[(usize, usize)]| -> f64 {
        pairs.iter().map(|&(x, y)| (scores[x][y] - floor).max(0.0)).sum()
    };
    let by_score = align_by_scores(scores.len(), scores.len(), |x, y| scores[x][y] - floor);
    if sum(&by_score) > sum(&in_order) + margin { by_score } else { in_order }
}

/// The longest subsequence of `seeds`, sorted by their left position, whose
/// right positions increase too.
///
/// Patience sorting: `ends[k]` is the seed that ends the best chain of
/// length `k + 1` found so far, with the smallest right position.
pub(super) fn longest_increasing_chain(seeds: &[(usize, usize)]) -> Vec<(usize, usize)> {
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
pub(super) fn longest_common_subsequence<T: PartialEq>(left: &[T], right: &[T]) -> Vec<Step> {
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

/// `longest_common_subsequence` of two runs of numbers below `count`,
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
pub(super) fn longest_common_subsequence_of_numbers(
    left: &[u32],
    right: &[u32],
    count: usize,
) -> Vec<Step> {
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
pub(super) fn lines_from_alignment(
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
