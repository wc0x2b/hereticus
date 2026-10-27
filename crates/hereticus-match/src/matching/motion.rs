//! Which removed and added lines of a diff are one block of code that
//! moved, as `git diff --color-moved` shows them.
//!
//! A compiler moves a block of code where an edit changes what comes
//! before it, or where it schedules the code otherwise: the same lines
//! leave one place and come back in another. The diff aligns the lines in
//! order, so it shows such a block as removed and added.
//!
//! A fix can be a move too: a check put before the use it guards, or a
//! call of `free` put after the last use. So a block that holds a branch, a
//! call or a return is no moved block, and only the IL view, which names
//! each of those one way on every architecture, finds blocks.

use std::collections::HashMap;

use super::lines::{DiffLine, View};

/// The fewest lines that a block holds to read as moved. A line alone, as
/// `x0 = x19`, comes and goes in many places by chance.
pub const FEWEST_MOVED_LINES: usize = 3;

/// The most lines of the other side that one removed line is tried
/// against, so that a function of a kernel with many equal lines takes a
/// time in step with its length.
const MOST_CANDIDATES: usize = 64;

/// Whether a line of a diff is in a block of code that moved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Motion {
    /// The line is where the diff shows it, or is no removed or added line.
    #[default]
    Stayed,
    /// The line is in a block of at least [`FEWEST_MOVED_LINES`] that the
    /// other side holds whole in another place.
    Moved,
}

/// Whether the IL statement `text` moves control: a branch, a jump, a
/// call or a return.
fn moves_control(text: &str) -> bool {
    text.starts_with("if (")
        || text.starts_with("goto ")
        || text.starts_with("call ")
        || text == "return"
}

/// The motion of each line of `lines`, which `view` shows.
///
/// A block is a run of removed lines that follow one another in the diff,
/// and the same run of added lines in another place. Each removed line
/// starts a block where it can, with the longest block that it starts, and
/// an added line is in one block at most. In the assembly view, each line
/// stays.
pub fn motions(lines: &[DiffLine], view: View) -> Vec<Motion> {
    let mut motion = vec![Motion::Stayed; lines.len()];
    if view == View::Assembly {
        return motion;
    }
    let removed: Vec<(usize, &str)> = lines
        .iter()
        .enumerate()
        .filter_map(|(at, line)| match line {
            DiffLine::Removed(text) => Some((at, text.as_str())),
            _ => None,
        })
        .collect();
    let added: Vec<(usize, &str)> = lines
        .iter()
        .enumerate()
        .filter_map(|(at, line)| match line {
            DiffLine::Added(text) => Some((at, text.as_str())),
            _ => None,
        })
        .collect();
    let mut by_text: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, (_, text)) in added.iter().enumerate() {
        by_text.entry(text).or_default().push(index);
    }
    let mut taken = vec![false; added.len()];
    // How many lines from `removed[from]` and `added[to]` on match, each
    // right after the one before in the diff.
    let block = |from: usize, to: usize, taken: &[bool]| -> usize {
        let follows = |pairs: &[(usize, &str)], at: usize| pairs[at].0 == pairs[at - 1].0 + 1;
        (0..)
            .take_while(|&length| {
                let (r, a) = (from + length, to + length);
                r < removed.len()
                    && a < added.len()
                    && !taken[a]
                    && removed[r].1 == added[a].1
                    && !moves_control(removed[r].1)
                    && (length == 0 || (follows(&removed, r) && follows(&added, a)))
            })
            .count()
    };
    let mut from = 0;
    while from < removed.len() {
        let candidates = by_text.get(removed[from].1).map_or(&[][..], Vec::as_slice);
        let best = candidates
            .iter()
            .take(MOST_CANDIDATES)
            .map(|&to| (block(from, to, &taken), to))
            .max_by_key(|&(length, to)| (length, core::cmp::Reverse(to)));
        match best {
            Some((length, to)) if length >= FEWEST_MOVED_LINES => {
                for offset in 0..length {
                    taken[to + offset] = true;
                    motion[removed[from + offset].0] = Motion::Moved;
                    motion[added[to + offset].0] = Motion::Moved;
                }
                from += length;
            }
            _ => from += 1,
        }
    }
    motion
}

#[cfg(test)]
mod tests {
    use super::*;

    fn moved_of(lines: &[DiffLine]) -> Vec<bool> {
        motions(lines, View::Il).into_iter().map(|motion| motion == Motion::Moved).collect()
    }

    fn removed(text: &str) -> DiffLine {
        DiffLine::Removed(text.into())
    }

    fn added(text: &str) -> DiffLine {
        DiffLine::Added(text.into())
    }

    fn same(text: &str) -> DiffLine {
        DiffLine::Same(text.into())
    }

    #[test]
    fn a_block_that_moved_down_is_moved_on_both_sides() {
        let lines = [
            removed("a"),
            removed("b"),
            removed("c"),
            same("x"),
            added("a"),
            added("b"),
            added("c"),
        ];
        assert_eq!(moved_of(&lines), [true, true, true, false, true, true, true]);
    }

    #[test]
    fn a_block_shorter_than_three_lines_stays() {
        let lines = [removed("a"), removed("b"), same("x"), added("a"), added("b")];
        assert!(moved_of(&lines).iter().all(|moved| !moved));
        assert!(motions(&[], View::Il).is_empty());
    }

    /// The lines of a block follow one another on each side: a line both
    /// sides hold between two of them splits the block.
    #[test]
    fn a_block_is_lines_that_follow_one_another() {
        let lines = [
            removed("a"),
            removed("b"),
            same("x"),
            removed("c"),
            same("y"),
            added("a"),
            added("b"),
            added("c"),
        ];
        assert!(moved_of(&lines).iter().all(|moved| !moved), "{:?}", moved_of(&lines));
    }

    /// A line of the other side is in one block at most, and a changed line
    /// is no part of a block.
    #[test]
    fn an_added_line_is_in_one_block_at_most() {
        let lines = [
            removed("a"),
            removed("b"),
            removed("c"),
            same("x"),
            removed("a"),
            removed("b"),
            removed("c"),
            same("y"),
            added("a"),
            added("b"),
            added("c"),
            DiffLine::Changed { before: "d".into(), after: "e".into() },
        ];
        let moved = moved_of(&lines);
        assert_eq!(moved.iter().filter(|moved| **moved).count(), 6, "{moved:?}");
        assert!(!moved[11], "a changed line");
    }

    /// A check moved before the use it guards is how a fix can look, so a
    /// block with a branch, a call or a return stays red and green.
    #[test]
    fn a_block_that_moves_control_stays() {
        for control in ["if (x0 == 0) goto $+0x8", "goto $-0x4", "call free", "return"] {
            let lines = [
                removed("a"),
                removed(control),
                removed("c"),
                same("x"),
                added("a"),
                added(control),
                added("c"),
            ];
            assert!(moved_of(&lines).iter().all(|moved| !moved), "{control}");
        }
    }

    #[test]
    fn the_assembly_view_finds_no_block() {
        let lines = [
            removed("a"),
            removed("b"),
            removed("c"),
            same("x"),
            added("a"),
            added("b"),
            added("c"),
        ];
        assert!(motions(&lines, View::Assembly).iter().all(|motion| *motion == Motion::Stayed));
    }

    #[test]
    fn any_motion_pairs_as_many_removed_as_added_lines() {
        bolero::check!().with_type::<Vec<(u8, u8)>>().for_each(|picks| {
            let lines: Vec<DiffLine> = picks
                .iter()
                .take(60)
                .map(|&(kind, text)| {
                    let text = ((b'a' + text % 4) as char).to_string();
                    match kind % 3 {
                        0 => DiffLine::Removed(text),
                        1 => DiffLine::Added(text),
                        _ => DiffLine::Same(text),
                    }
                })
                .collect();
            let motion = motions(&lines, View::Il);
            assert_eq!(motion.len(), lines.len());
            let count = |wanted: fn(&DiffLine) -> bool| {
                lines
                    .iter()
                    .zip(&motion)
                    .filter(|(line, motion)| wanted(line) && **motion == Motion::Moved)
                    .count()
            };
            let moved_removed = count(|line| matches!(line, DiffLine::Removed(_)));
            let moved_added = count(|line| matches!(line, DiffLine::Added(_)));
            assert_eq!(moved_removed, moved_added);
            assert_eq!(count(|line| matches!(line, DiffLine::Same(_))), 0);
            assert!(moved_removed == 0 || moved_removed >= FEWEST_MOVED_LINES);
        });
    }
}
