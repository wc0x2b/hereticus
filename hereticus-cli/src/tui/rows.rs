//! Lay the lines of a diff out in rows, each with the address of the
//! instruction it shows and its depth in the jumps of the function.

use hereticus::matching::{DiffLine, LinePlace};

/// What one half of a row shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side<'l> {
    /// Nothing, across from a line the other side alone has.
    Empty,
    Same(&'l str),
    Removed(&'l str),
    Added(&'l str),
    /// A line kept in place with a changed constant, as `~` names it in the
    /// `+/-/~` column.
    Changed(&'l str),
}

/// One half of a row: a line, the address of its instruction, and how
/// many levels deep the line sits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Half<'l> {
    pub side: Side<'l>,
    pub address: Option<u64>,
    pub depth: usize,
}

impl<'l> Half<'l> {
    const EMPTY: Self = Self { side: Side::Empty, address: None, depth: 0 };

    /// The half that shows `side` at `place`.
    fn at(side: Side<'l>, place: Option<LinePlace>) -> Self {
        Self {
            side,
            address: place.map(|place| place.address),
            depth: place.map_or(0, |place| place.depth),
        }
    }

    /// Report whether the half shows a change, not a line both sides hold.
    pub fn is_change(self) -> bool {
        !matches!(self.side, Side::Same(_))
    }
}

/// One row of a diff laid side by side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SideRow<'l> {
    pub left: Half<'l>,
    pub right: Half<'l>,
}

/// Where each line of the two functions a diff compares sits, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Places {
    pub before: Vec<LinePlace>,
    pub after: Vec<LinePlace>,
}

/// Each line of a diff, with where it sits on each side.
///
/// A diff holds one line for each line the view shows of a side, in
/// order: a line
/// both hold, or a changed one, takes the next of each side, a removed line
/// the next of the earlier function, and an added one the next of the later.
fn locate<'l>(
    lines: &'l [DiffLine],
    places: &Places,
) -> impl Iterator<Item = (&'l DiffLine, Option<LinePlace>, Option<LinePlace>)> {
    let (mut before, mut after) = (places.before.iter().copied(), places.after.iter().copied());
    lines.iter().map(move |line| match line {
        DiffLine::Same(_) | DiffLine::Changed { .. } => (line, before.next(), after.next()),
        DiffLine::Removed(_) => (line, before.next(), None),
        DiffLine::Added(_) => (line, None, after.next()),
    })
}

/// Lay a diff side by side. A run of removed lines and the run of added
/// lines next to it share rows, so a rewritten block reads across.
pub fn side_by_side<'l>(lines: &'l [DiffLine], places: &Places) -> Vec<SideRow<'l>> {
    let mut rows = Vec::with_capacity(lines.len());
    let mut removed: Vec<Half<'l>> = Vec::new();
    let mut added: Vec<Half<'l>> = Vec::new();
    for (line, before, after) in locate(lines, places) {
        match line {
            DiffLine::Removed(text) => removed.push(Half::at(Side::Removed(text), before)),
            DiffLine::Added(text) => added.push(Half::at(Side::Added(text), after)),
            DiffLine::Same(text) => {
                flush_runs(&mut rows, &mut removed, &mut added);
                rows.push(SideRow {
                    left: Half::at(Side::Same(text), before),
                    right: Half::at(Side::Same(text), after),
                });
            }
            DiffLine::Changed { before: old, after: new } => {
                flush_runs(&mut rows, &mut removed, &mut added);
                rows.push(SideRow {
                    left: Half::at(Side::Changed(old), before),
                    right: Half::at(Side::Changed(new), after),
                });
            }
        }
    }
    flush_runs(&mut rows, &mut removed, &mut added);
    rows
}

/// Put a run of removed lines and a run of added lines on shared rows.
fn flush_runs<'l>(
    rows: &mut Vec<SideRow<'l>>,
    removed: &mut Vec<Half<'l>>,
    added: &mut Vec<Half<'l>>,
) {
    let longest = removed.len().max(added.len());
    let left = removed.drain(..).chain(core::iter::repeat(Half::EMPTY));
    let right = added.drain(..).chain(core::iter::repeat(Half::EMPTY));
    rows.extend(left.zip(right).take(longest).map(|(left, right)| SideRow { left, right }));
}

/// Lay a diff in one column, as a patch reads. A line both sides hold
/// shows the address of the later function.
pub fn unified<'l>(lines: &'l [DiffLine], places: &Places) -> Vec<Half<'l>> {
    locate(lines, places)
        .flat_map(|(line, before, after)| match line {
            DiffLine::Same(text) => [Half::at(Side::Same(text), after), Half::EMPTY],
            DiffLine::Removed(text) => [Half::at(Side::Removed(text), before), Half::EMPTY],
            DiffLine::Added(text) => [Half::at(Side::Added(text), after), Half::EMPTY],
            DiffLine::Changed { before: old, after: new } => {
                [Half::at(Side::Removed(old), before), Half::at(Side::Added(new), after)]
            }
        })
        .filter(|half| half.side != Side::Empty)
        .collect()
}

/// Where each run of changed rows starts.
pub fn change_starts(changes: impl IntoIterator<Item = bool>) -> Vec<usize> {
    let mut before = false;
    changes
        .into_iter()
        .enumerate()
        .filter_map(|(index, change)| {
            let starts = change && !before;
            before = change;
            starts.then_some(index)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same(text: &str) -> DiffLine {
        DiffLine::Same(text.into())
    }

    fn half(side: Side<'_>, address: Option<u64>) -> Half<'_> {
        Half { side, address, depth: 0 }
    }

    /// The places of lines at `before` and `after`, each at no depth.
    fn places(before: &[u64], after: &[u64]) -> Places {
        let at = |addresses: &[u64]| {
            addresses.iter().map(|&address| LinePlace { address, depth: 0 }).collect()
        };
        Places { before: at(before), after: at(after) }
    }

    #[test]
    fn a_removed_run_and_an_added_run_share_rows() {
        let lines = [
            same("a"),
            DiffLine::Removed("b".into()),
            DiffLine::Removed("c".into()),
            DiffLine::Added("d".into()),
            same("e"),
            DiffLine::Changed { before: "f".into(), after: "g".into() },
            DiffLine::Added("h".into()),
        ];
        let addresses = places(&[0, 4, 8, 12, 16], &[0, 4, 8, 12, 16]);
        let row = |left, right| SideRow { left, right };
        assert_eq!(
            side_by_side(&lines, &addresses),
            [
                row(half(Side::Same("a"), Some(0)), half(Side::Same("a"), Some(0))),
                row(half(Side::Removed("b"), Some(4)), half(Side::Added("d"), Some(4))),
                row(half(Side::Removed("c"), Some(8)), Half::EMPTY),
                row(half(Side::Same("e"), Some(12)), half(Side::Same("e"), Some(8))),
                row(half(Side::Changed("f"), Some(16)), half(Side::Changed("g"), Some(12))),
                row(Half::EMPTY, half(Side::Added("h"), Some(16))),
            ]
        );
        assert!(side_by_side(&[], &addresses).is_empty());
    }

    #[test]
    fn a_line_past_the_addresses_has_none() {
        let lines = [same("a"), same("b")];
        let addresses = places(&[0x10], &[]);
        let rows = side_by_side(&lines, &addresses);
        assert_eq!(rows[0].left.address, Some(0x10));
        assert_eq!(rows[1].left.address, None);
        assert_eq!(rows[0].right.address, None);
    }

    #[test]
    fn a_unified_diff_puts_a_changed_line_on_two_rows() {
        let lines = [same("a"), DiffLine::Changed { before: "b".into(), after: "c".into() }];
        let addresses = places(&[0x100, 0x104], &[0x200, 0x204]);
        assert_eq!(
            unified(&lines, &addresses),
            [
                half(Side::Same("a"), Some(0x200)),
                half(Side::Removed("b"), Some(0x104)),
                half(Side::Added("c"), Some(0x204)),
            ]
        );
    }

    #[test]
    fn each_half_keeps_the_depth_of_its_side() {
        let lines = [same("a"), DiffLine::Changed { before: "b".into(), after: "c".into() }];
        let place = |address, depth| LinePlace { address, depth };
        let places = Places {
            before: vec![place(0x100, 0), place(0x104, 2)],
            after: vec![place(0x200, 1), place(0x204, 3)],
        };
        let depths = |row: &SideRow<'_>| (row.left.depth, row.right.depth);
        let rows = side_by_side(&lines, &places);
        assert_eq!(rows.iter().map(depths).collect::<Vec<_>>(), [(0, 1), (2, 3)]);
        let halves = unified(&lines, &places);
        assert_eq!(halves.iter().map(|half| half.depth).collect::<Vec<_>>(), [1, 2, 3]);
    }

    #[test]
    fn a_change_starts_where_a_run_of_changes_does() {
        assert_eq!(change_starts([true, true, false, true, false, false, true]), [0, 3, 6]);
        assert_eq!(change_starts([false, false]), Vec::<usize>::new());
        assert_eq!(change_starts([]), Vec::<usize>::new());
    }
}
