//! Lay the lines of a diff out in rows, each with the address of the
//! instruction it shows.

use hereticus::matching::DiffLine;

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

/// One half of a row: a line, and the address of its instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Half<'l> {
    pub side: Side<'l>,
    pub address: Option<u64>,
}

impl Half<'_> {
    const EMPTY: Self = Self { side: Side::Empty, address: None };

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

/// The address of each instruction of the two functions a diff compares,
/// in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Addresses {
    pub before: Vec<u64>,
    pub after: Vec<u64>,
}

/// Each line of a diff, with the address of its instruction on each side.
///
/// A diff holds one line for each instruction of a side, in order: a line
/// both hold, or a changed one, takes the next of each side, a removed line
/// the next of the earlier function, and an added one the next of the later.
fn locate<'l>(
    lines: &'l [DiffLine],
    addresses: &Addresses,
) -> impl Iterator<Item = (&'l DiffLine, Option<u64>, Option<u64>)> {
    let (mut before, mut after) =
        (addresses.before.iter().copied(), addresses.after.iter().copied());
    lines.iter().map(move |line| match line {
        DiffLine::Same(_) | DiffLine::Changed { .. } => (line, before.next(), after.next()),
        DiffLine::Removed(_) => (line, before.next(), None),
        DiffLine::Added(_) => (line, None, after.next()),
    })
}

/// Lay a diff side by side. A run of removed lines and the run of added
/// lines next to it share rows, so a rewritten block reads across.
pub fn side_by_side<'l>(lines: &'l [DiffLine], addresses: &Addresses) -> Vec<SideRow<'l>> {
    let mut rows = Vec::with_capacity(lines.len());
    let mut removed: Vec<Half<'l>> = Vec::new();
    let mut added: Vec<Half<'l>> = Vec::new();
    for (line, before, after) in locate(lines, addresses) {
        match line {
            DiffLine::Removed(text) => {
                removed.push(Half { side: Side::Removed(text), address: before })
            }
            DiffLine::Added(text) => added.push(Half { side: Side::Added(text), address: after }),
            DiffLine::Same(text) => {
                flush_runs(&mut rows, &mut removed, &mut added);
                rows.push(SideRow {
                    left: Half { side: Side::Same(text), address: before },
                    right: Half { side: Side::Same(text), address: after },
                });
            }
            DiffLine::Changed { before: old, after: new } => {
                flush_runs(&mut rows, &mut removed, &mut added);
                rows.push(SideRow {
                    left: Half { side: Side::Changed(old), address: before },
                    right: Half { side: Side::Changed(new), address: after },
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
pub fn unified<'l>(lines: &'l [DiffLine], addresses: &Addresses) -> Vec<Half<'l>> {
    locate(lines, addresses)
        .flat_map(|(line, before, after)| match line {
            DiffLine::Same(text) => [Half { side: Side::Same(text), address: after }, Half::EMPTY],
            DiffLine::Removed(text) => {
                [Half { side: Side::Removed(text), address: before }, Half::EMPTY]
            }
            DiffLine::Added(text) => {
                [Half { side: Side::Added(text), address: after }, Half::EMPTY]
            }
            DiffLine::Changed { before: old, after: new } => [
                Half { side: Side::Removed(old), address: before },
                Half { side: Side::Added(new), address: after },
            ],
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
        Half { side, address }
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
        let addresses = Addresses { before: vec![0, 4, 8, 12, 16], after: vec![0, 4, 8, 12, 16] };
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
        let addresses = Addresses { before: vec![0x10], after: vec![] };
        let rows = side_by_side(&lines, &addresses);
        assert_eq!(rows[0].left.address, Some(0x10));
        assert_eq!(rows[1].left.address, None);
        assert_eq!(rows[0].right.address, None);
    }

    #[test]
    fn a_unified_diff_puts_a_changed_line_on_two_rows() {
        let lines = [same("a"), DiffLine::Changed { before: "b".into(), after: "c".into() }];
        let addresses = Addresses { before: vec![0x100, 0x104], after: vec![0x200, 0x204] };
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
    fn a_change_starts_where_a_run_of_changes_does() {
        assert_eq!(change_starts([true, true, false, true, false, false, true]), [0, 3, 6]);
        assert_eq!(change_starts([false, false]), Vec::<usize>::new());
        assert_eq!(change_starts([]), Vec::<usize>::new());
    }
}
