//! How deep in the jumps of its function each instruction sits, so that a
//! view can indent it as the source indents the body of an `if` or a loop.
//!
//! A compiler does not keep the order of the source. It moves a path that
//! seldom runs, as the handling of an error, after the return, and jumps
//! there and back. A jump that steps over the lines to such a path does not
//! guard all of them: the path comes back into the middle. So the lines a
//! forward jump steps over stop where another path comes in, and a jump
//! back is a loop only where its target can run again.

use core::ops::Range;

use hereticus_il::arch::{Insn, InsnKind};
use hereticus_il::flow::successors;

/// The depth of each instruction of `insns`, which are one function.
///
/// A forward jump puts the lines after it one level deeper, up to its
/// target or up to the first line that another path comes into, of the
/// two the first. A jump on no condition starts the `else` of an `if`, so
/// it lets in the paths that come from the `if`. A jump back puts the lines
/// from its target up to it one level deeper, where the target leads to the
/// jump again. A jump through a register, or out of the function, adds no
/// level.
///
/// A branch and its delay slots move as one: a jump forward steps over
/// what comes after the last slot, and a jump back stops before the branch.
pub(crate) fn nesting_depths(insns: &[Insn], delay_slots: impl Fn(&Insn) -> usize) -> Vec<usize> {
    let next = successors(insns, &delay_slots);
    let entries = Entries::of(&next);
    let component = components(&next);
    let index_of = |target: u64| insns.binary_search_by_key(&target, |insn| insn.address).ok();
    // How many spans start at each instruction, and how many end before it.
    let mut starts = vec![0_usize; insns.len()];
    let mut ends = vec![0_usize; insns.len() + 1];
    for (index, insn) in insns.iter().enumerate() {
        let (InsnKind::Branch { target: Some(target) } | InsnKind::Jump { target: Some(target) }) =
            insn.kind
        else {
            continue;
        };
        let Some(target) = index_of(target) else { continue };
        let span = if target > index {
            let start = index + delay_slots(insn) + 1;
            let from = match insn.kind {
                InsnKind::Jump { .. } => entries.lowest_at(start).unwrap_or(index).min(index),
                _ => index,
            };
            let end = entries.first_entered_from_outside(start..target, from..target);
            start..end.unwrap_or(target)
        } else if component[target] == component[index] {
            target..index
        } else {
            continue;
        };
        if span.is_empty() {
            continue;
        }
        starts[span.start] += 1;
        ends[span.end] += 1;
    }
    starts
        .iter()
        .zip(&ends)
        .scan(0, |depth, (started, ended)| {
            // Each span ends after it starts, so the depth never drops
            // below zero.
            *depth = *depth + started - ended;
            Some(*depth)
        })
        .collect()
}

/// The lowest and the highest instruction that leads to each instruction,
/// in a tree of ranges, so that a query finds the first instruction that a
/// path from outside a range comes into in a time that grows as the log of
/// the count of instructions.
struct Entries {
    /// How many leaves the tree has: a power of two, at least one.
    leaves: usize,
    /// The lowest instruction that leads into each node, with `usize::MAX`
    /// where none does. Node 1 is the root, and node `n` has `2n` and
    /// `2n + 1` below it.
    lowest: Vec<usize>,
    /// The highest instruction that leads into each node, with zero where
    /// none does.
    highest: Vec<usize>,
}

impl Entries {
    fn of(next: &[Vec<usize>]) -> Self {
        let leaves = next.len().next_power_of_two();
        let mut lowest = vec![usize::MAX; 2 * leaves];
        let mut highest = vec![0; 2 * leaves];
        for (from, successors) in next.iter().enumerate() {
            for &to in successors {
                lowest[leaves + to] = lowest[leaves + to].min(from);
                highest[leaves + to] = highest[leaves + to].max(from);
            }
        }
        for node in (1..leaves).rev() {
            lowest[node] = lowest[2 * node].min(lowest[2 * node + 1]);
            highest[node] = highest[2 * node].max(highest[2 * node + 1]);
        }
        Self { leaves, lowest, highest }
    }

    /// The lowest instruction that leads to `index`, where one does.
    fn lowest_at(&self, index: usize) -> Option<usize> {
        let lowest = *self.lowest.get(self.leaves + index)?;
        (lowest != usize::MAX).then_some(lowest)
    }

    /// The first instruction of `lines` that an instruction out of
    /// `inside` leads to.
    fn first_entered_from_outside(
        &self,
        lines: Range<usize>,
        inside: Range<usize>,
    ) -> Option<usize> {
        self.descend(1, 0..self.leaves, &lines, &inside)
    }

    fn descend(
        &self,
        node: usize,
        covers: Range<usize>,
        lines: &Range<usize>,
        inside: &Range<usize>,
    ) -> Option<usize> {
        let apart = covers.end <= lines.start || lines.end <= covers.start;
        // The highest is below `inside.end` too where nothing leads in.
        let all_inside = inside.start <= self.lowest[node] && self.highest[node] < inside.end;
        if apart || all_inside {
            return None;
        }
        if covers.len() == 1 {
            return Some(covers.start);
        }
        let middle = covers.start + covers.len() / 2;
        self.descend(2 * node, covers.start..middle, lines, inside)
            .or_else(|| self.descend(2 * node + 1, middle..covers.end, lines, inside))
    }
}

/// The strongly connected component of each instruction, by number: two
/// instructions share one where each leads to the other.
///
/// This is the algorithm of Tarjan, with a stack of its own in place of
/// recursion, as a function of a kernel holds tens of thousands of
/// instructions.
fn components(next: &[Vec<usize>]) -> Vec<usize> {
    const UNSEEN: usize = usize::MAX;
    let count = next.len();
    let mut seen_at = vec![UNSEEN; count];
    let mut lowest_reached = vec![0; count];
    let mut component = vec![UNSEEN; count];
    let mut open: Vec<usize> = Vec::new();
    let mut is_open = vec![false; count];
    let mut seen = 0;
    let mut found = 0;
    for root in 0..count {
        if seen_at[root] != UNSEEN {
            continue;
        }
        // Each instruction on the path from the root, with how many of its
        // successors it has visited.
        let mut path = vec![(root, 0)];
        seen_at[root] = seen;
        lowest_reached[root] = seen;
        seen += 1;
        open.push(root);
        is_open[root] = true;
        while let Some(top) = path.last_mut() {
            let node = top.0;
            if let Some(&successor) = next[node].get(top.1) {
                top.1 += 1;
                if seen_at[successor] == UNSEEN {
                    seen_at[successor] = seen;
                    lowest_reached[successor] = seen;
                    seen += 1;
                    open.push(successor);
                    is_open[successor] = true;
                    path.push((successor, 0));
                } else if is_open[successor] {
                    lowest_reached[node] = lowest_reached[node].min(seen_at[successor]);
                }
                continue;
            }
            path.pop();
            if let Some(&(parent, _)) = path.last() {
                lowest_reached[parent] = lowest_reached[parent].min(lowest_reached[node]);
            }
            if lowest_reached[node] == seen_at[node] {
                while let Some(member) = open.pop() {
                    is_open[member] = false;
                    component[member] = found;
                    if member == node {
                        break;
                    }
                }
                found += 1;
            }
        }
    }
    component
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An instruction at `0x1000 + 4 * index`, of `kind`.
    fn flow(index: u64, kind: InsnKind) -> Insn {
        Insn::new(0x1000 + 4 * index, &[0; 4], kind, hereticus_il::arch::Opcode::None)
    }

    /// A branch from instruction `from` to instruction `to`.
    fn branch(from: u64, to: u64) -> Insn {
        flow(from, InsnKind::Branch { target: Some(0x1000 + 4 * to) })
    }

    /// A jump on no condition from instruction `from` to instruction `to`.
    fn jump(from: u64, to: u64) -> Insn {
        flow(from, InsnKind::Jump { target: Some(0x1000 + 4 * to) })
    }

    fn straight(index: u64) -> Insn {
        flow(index, InsnKind::Normal)
    }

    fn ret(index: u64) -> Insn {
        flow(index, InsnKind::Return)
    }

    #[test]
    fn the_body_of_an_if_sits_one_level_deeper() {
        let insns = [branch(0, 3), straight(1), straight(2), straight(3)];
        assert_eq!(nesting_depths(&insns, |_| 0), [0, 1, 1, 0]);
    }

    #[test]
    fn the_two_arms_of_an_if_and_else_sit_at_one_level() {
        let insns = [branch(0, 3), straight(1), jump(2, 5), straight(3), straight(4), straight(5)];
        assert_eq!(nesting_depths(&insns, |_| 0), [0, 1, 1, 1, 1, 0]);
    }

    #[test]
    fn the_body_of_a_loop_sits_one_level_deeper() {
        let insns = [straight(0), straight(1), straight(2), branch(3, 1), straight(4)];
        assert_eq!(nesting_depths(&insns, |_| 0), [0, 1, 1, 0, 0]);
    }

    #[test]
    fn a_loop_in_an_if_sits_two_levels_deeper() {
        let insns = [branch(0, 4), straight(1), straight(2), branch(3, 1), straight(4)];
        assert_eq!(nesting_depths(&insns, |_| 0), [0, 2, 2, 1, 0]);
    }

    #[test]
    fn a_delay_slot_sits_with_its_branch() {
        let insns = [branch(0, 3), straight(1), straight(2), straight(3)];
        let slots = |insn: &Insn| usize::from(matches!(insn.kind, InsnKind::Branch { .. }));
        assert_eq!(nesting_depths(&insns, slots), [0, 0, 1, 0]);
    }

    #[test]
    fn a_jump_with_no_target_in_the_function_adds_no_level() {
        let insns = [
            flow(0, InsnKind::Jump { target: None }),
            flow(1, InsnKind::Branch { target: Some(0x8000) }),
            branch(2, 2),
            branch(3, 4),
            straight(4),
        ];
        assert_eq!(nesting_depths(&insns, |_| 0), [0; 5]);
        assert!(nesting_depths(&[], |_| 0).is_empty());
    }

    /// A compiler puts the rare path after the return, and jumps back
    /// from it: only the lines before the path comes back are guarded.
    #[test]
    fn a_path_moved_after_the_return_guards_only_the_lines_before_it_comes_back() {
        let insns = [
            branch(0, 5), // if (rare) goto 5
            straight(1),
            straight(2), // 5 comes back here
            straight(3),
            ret(4),
            straight(5), // the rare path
            jump(6, 2),
        ];
        assert_eq!(nesting_depths(&insns, |_| 0), [0, 1, 0, 0, 0, 0, 0]);
    }

    /// A jump back that does not run again is no loop.
    #[test]
    fn a_jump_back_that_runs_once_adds_no_level() {
        let insns = [branch(0, 4), straight(1), straight(2), ret(3), jump(4, 1)];
        let depths = nesting_depths(&insns, |_| 0);
        assert_eq!(depths[1..4], [0, 0, 0], "{depths:?}");
    }

    /// A loop that starts at its test, as a compiler rotates it: the jump
    /// into the test does not stop the body.
    #[test]
    fn a_loop_entered_at_its_test_sits_one_level_deeper() {
        let insns = [jump(0, 3), straight(1), straight(2), branch(3, 1), ret(4)];
        assert_eq!(nesting_depths(&insns, |_| 0), [0, 1, 1, 0, 0]);
    }

    /// A line that two paths come into ends the `if` before it. So the
    /// body of `if (a || !b)` shows at the level of its test: it is not
    /// all of one branch.
    #[test]
    fn a_line_two_paths_come_into_ends_the_if() {
        let insns = [branch(0, 2), branch(1, 4), straight(2), straight(3), ret(4)];
        assert_eq!(nesting_depths(&insns, |_| 0), [0, 1, 0, 0, 0]);
        let crossed = [branch(0, 3), straight(1), straight(2), straight(3), branch(4, 2)];
        let depths = nesting_depths(&crossed, |_| 0);
        assert_eq!(depths[1], 1, "2 is the head of the loop, which ends the if");
        assert_eq!(depths[2..4], [1, 1], "the body of the loop: {depths:?}");
    }

    #[test]
    fn instructions_that_lead_to_each_other_share_a_component() {
        let next = vec![vec![1], vec![2], vec![1, 3], vec![]];
        let component = components(&next);
        assert_eq!(component[1], component[2]);
        assert_ne!(component[0], component[1]);
        assert_ne!(component[3], component[1]);
        assert!(components(&[]).is_empty());
    }

    /// Whether `from` leads to `to`, by a search of every path.
    fn leads_to(next: &[Vec<usize>], from: usize, to: usize) -> bool {
        let mut seen = vec![false; next.len()];
        let mut open = vec![from];
        while let Some(node) = open.pop() {
            if node == to {
                return true;
            }
            if !core::mem::replace(&mut seen[node], true) {
                open.extend(&next[node]);
            }
        }
        false
    }

    #[test]
    fn the_depth_of_an_instruction_counts_the_spans_around_it() {
        // Each instruction branches, jumps or returns, to an index below
        // 24, which can be past the end of the function.
        bolero::check!().with_type::<(Vec<(u8, u8)>, bool)>().for_each(|(shapes, slot)| {
            let slots = usize::from(*slot);
            let insns: Vec<Insn> = (0..)
                .zip(shapes)
                .map(|(index, &(shape, to))| match shape % 4 {
                    0 => straight(index),
                    1 => branch(index, u64::from(to % 24)),
                    2 => jump(index, u64::from(to % 24)),
                    _ => ret(index),
                })
                .collect();
            let has_slots = |insn: &Insn| match insn.kind {
                InsnKind::Branch { .. } | InsnKind::Jump { .. } => slots,
                _ => 0,
            };
            let next = successors(&insns, has_slots);
            let comes_from = |line: usize| -> Vec<usize> {
                (0..next.len()).filter(|&from| next[from].contains(&line)).collect()
            };
            let spans: Vec<Range<usize>> = shapes
                .iter()
                .enumerate()
                .filter(|(_, (shape, _))| shape % 4 == 1 || shape % 4 == 2)
                .filter_map(|(index, &(shape, to))| {
                    let target = usize::from(to % 24);
                    if target >= insns.len() {
                        return None;
                    }
                    if target <= index {
                        // A branch whose delay slot is past the end
                        // leads nowhere.
                        let looped =
                            leads_to(&next, target, index) && leads_to(&next, index, target);
                        return looped.then_some(target..index);
                    }
                    let start = index + slots + 1;
                    let from = match shape % 4 {
                        2 => comes_from(start).into_iter().min().unwrap_or(index).min(index),
                        _ => index,
                    };
                    let end = (start..target)
                        .find(|&line| {
                            comes_from(line).iter().any(|&k| !(from..target).contains(&k))
                        })
                        .unwrap_or(target);
                    Some(start..end)
                })
                .collect();
            let model: Vec<usize> = (0..insns.len())
                .map(|index| spans.iter().filter(|span| span.contains(&index)).count())
                .collect();
            assert_eq!(nesting_depths(&insns, has_slots), model);
        });
    }
}
