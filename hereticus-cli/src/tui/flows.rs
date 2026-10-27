//! The jumps of a column of a diff, drawn as lines in a gutter at the left
//! of the code, as `radare2` and Binary Ninja draw them.
//!
//! Each jump takes a lane: a column of the gutter that it holds from its
//! line to its target. The longest jumps take the lanes at the left, so a
//! loop in a loop reads from the outside in. A jump that finds no free lane
//! is not drawn, as the code must stay in sight.
//!
//! A jump takes the color of its line, so a jump that a change adds or
//! removes stands out from the jumps both sides hold.

use super::rows::{Half, Side};

/// How many jumps can pass one row.
pub const LANES: usize = 4;

/// The columns of the gutter: one for each lane, then one for the head of
/// the arrow.
pub const WIDTH: usize = LANES + 1;

/// What one cell of the gutter shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Glyph {
    #[default]
    Blank,
    /// A jump passes the row.
    Vertical,
    /// A jump goes to or from its lane on this row.
    Horizontal,
    /// One jump passes the row where another goes to or from its lane.
    Cross,
    /// The first row of a jump, at its lane.
    Top,
    /// The last row of a jump, at its lane.
    Bottom,
    /// The first row of a jump, where another goes across it.
    TopCrossed,
    /// The last row of a jump, where another goes across it.
    BottomCrossed,
    /// The line the jump leaves from.
    Source,
    /// The line the jump goes to.
    Target,
}

impl Glyph {
    pub fn symbol(self) -> char {
        match self {
            Self::Blank => ' ',
            Self::Vertical => '│',
            Self::Horizontal => '─',
            Self::Cross => '┼',
            Self::Top => '┌',
            Self::Bottom => '└',
            Self::TopCrossed => '┬',
            Self::BottomCrossed => '┴',
            Self::Source => '<',
            Self::Target => '>',
        }
    }

    /// The glyph where a line across the row meets this one.
    fn crossed(self) -> Self {
        match self {
            Self::Vertical | Self::Cross => Self::Cross,
            Self::Top | Self::TopCrossed => Self::TopCrossed,
            Self::Bottom | Self::BottomCrossed => Self::BottomCrossed,
            _ => Self::Horizontal,
        }
    }
}

/// The color a jump takes from its line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Tint {
    /// A line both sides hold.
    #[default]
    Same,
    Removed,
    Added,
    Changed,
}

/// One cell of the gutter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cell {
    pub glyph: Glyph,
    pub tint: Tint,
}

/// The gutter of a column of halves, row by row.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Gutter {
    /// [`WIDTH`] cells for each row.
    cells: Vec<Cell>,
}

impl Gutter {
    /// The cells of row `row`, blank past the last row.
    pub fn row(&self, row: usize) -> [Cell; WIDTH] {
        let start = row * WIDTH;
        self.cells
            .get(start..start + WIDTH)
            .and_then(|cells| cells.try_into().ok())
            .unwrap_or_default()
    }

    /// The gutter of the jumps of `halves`, which are one column of a diff
    /// from its top.
    pub fn of(halves: &[Half<'_>]) -> Self {
        let mut gutter = Self { cells: vec![Cell::default(); halves.len() * WIDTH] };
        let mut jumps = jumps_of(halves);
        // The outermost jump first, so it takes the lane at the left.
        jumps.sort_by_key(|jump| (jump.top(), core::cmp::Reverse(jump.bottom())));
        // The last row each lane holds.
        let mut held: [Option<usize>; LANES] = [None; LANES];
        let mut placed: Vec<(Jump, usize)> = Vec::with_capacity(jumps.len());
        for jump in jumps {
            let free = held.iter().position(|last| last.is_none_or(|last| last < jump.top()));
            if let Some(lane) = free {
                held[lane] = Some(jump.bottom());
                placed.push((jump, lane));
            }
        }
        // A change draws over the jumps both sides hold.
        placed.sort_by_key(|(jump, _)| jump.tint != Tint::Same);
        for (jump, lane) in placed {
            gutter.draw(jump, lane);
        }
        gutter
    }

    fn draw(&mut self, jump: Jump, lane: usize) {
        let tint = jump.tint;
        for row in jump.top() + 1..jump.bottom() {
            let cell = &mut self.cells[row * WIDTH + lane];
            let glyph = match cell.glyph {
                Glyph::Horizontal | Glyph::Cross => Glyph::Cross,
                _ => Glyph::Vertical,
            };
            *cell = Cell { glyph, tint };
        }
        for (row, corner) in [(jump.top(), Glyph::Top), (jump.bottom(), Glyph::Bottom)] {
            let cells = &mut self.cells[row * WIDTH..(row + 1) * WIDTH];
            let corner = match cells[lane].glyph {
                Glyph::Horizontal | Glyph::Cross => match corner {
                    Glyph::Top => Glyph::TopCrossed,
                    _ => Glyph::BottomCrossed,
                },
                _ => corner,
            };
            cells[lane] = Cell { glyph: corner, tint };
            for cell in &mut cells[lane + 1..LANES] {
                *cell = Cell { glyph: cell.glyph.crossed(), tint };
            }
            // A line that one jump leaves and another comes to shows the
            // jump it makes.
            let head = if row == jump.from { Glyph::Source } else { Glyph::Target };
            if cells[LANES].glyph != Glyph::Source {
                cells[LANES] = Cell { glyph: head, tint };
            }
        }
    }
}

/// A jump from one row of a column to another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Jump {
    from: usize,
    to: usize,
    tint: Tint,
}

impl Jump {
    fn top(self) -> usize {
        self.from.min(self.to)
    }

    fn bottom(self) -> usize {
        self.from.max(self.to)
    }
}

/// The jumps of `halves` from row to row, of each side they show.
///
/// A row of one column shows one side, or both where a unified diff shows
/// a line both sides hold. A jump goes to the first row of its side at or
/// after its target, as the IL view shows some instructions in the line of
/// another. A jump both sides hold on one row is one jump.
fn jumps_of(halves: &[Half<'_>]) -> Vec<Jump> {
    let mut jumps = Vec::new();
    for side in 0..2 {
        // The address of each row that shows this side, in order.
        let rows: Vec<(u64, usize)> = halves
            .iter()
            .enumerate()
            .filter_map(|(row, half)| Some((half.places[side]?.address, row)))
            .collect();
        for (row, half) in halves.iter().enumerate() {
            let Some(target) = half.places[side].and_then(|place| place.jump) else { continue };
            let at = rows.partition_point(|&(address, _)| address < target);
            let Some(&(_, to)) = rows.get(at) else { continue };
            if to != row {
                jumps.push(Jump { from: row, to, tint: tint_of(half.side) });
            }
        }
    }
    jumps.sort_by_key(|jump| (jump.from, jump.to));
    jumps.dedup_by_key(|jump| (jump.from, jump.to));
    jumps
}

fn tint_of(side: Side<'_>) -> Tint {
    match side {
        Side::Empty | Side::Same(_) => Tint::Same,
        Side::Removed(_) => Tint::Removed,
        Side::Added(_) => Tint::Added,
        Side::Changed(_) => Tint::Changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hereticus::matching::LinePlace;

    /// A line both sides hold at `address`, of the later side, that jumps
    /// to `jump`.
    fn line(address: u64, jump: Option<u64>) -> Half<'static> {
        Half::shown(Side::Same("x"), [None, Some(LinePlace { address, depth: 0, jump })])
    }

    /// The gutter of `halves` as text, a row for each line.
    fn drawn(halves: &[Half<'_>]) -> Vec<String> {
        let gutter = Gutter::of(halves);
        (0..halves.len())
            .map(|row| gutter.row(row).iter().map(|cell| cell.glyph.symbol()).collect())
            .collect()
    }

    #[test]
    fn a_jump_forward_goes_from_its_line_to_its_target() {
        let halves = [line(0, Some(8)), line(4, None), line(8, None), line(12, None)];
        assert_eq!(drawn(&halves), ["┌───<", "│    ", "└───>", "     "]);
    }

    #[test]
    fn a_jump_back_points_up_to_its_target() {
        let halves = [line(0, None), line(4, None), line(8, Some(0))];
        assert_eq!(drawn(&halves), ["┌───>", "│    ", "└───<"]);
    }

    #[test]
    fn an_outer_jump_takes_the_lane_at_the_left() {
        let halves = [
            line(0, Some(16)), // outer
            line(4, None),
            line(8, Some(4)), // inner loop
            line(12, None),
            line(16, None),
        ];
        assert_eq!(drawn(&halves), ["┌───<", "│┌──>", "│└──<", "│    ", "└───>"]);
    }

    #[test]
    fn a_jump_that_crosses_a_lane_draws_a_cross() {
        let halves = [line(0, Some(8)), line(4, Some(12)), line(8, None), line(12, None)];
        assert_eq!(drawn(&halves), ["┌───<", "│┌──<", "└┼──>", " └──>"]);
    }

    /// A jump that ends on the row where the next starts goes across its
    /// corner, in either order of drawing.
    #[test]
    fn a_jump_across_a_corner_keeps_the_corner() {
        let halves = [line(0, Some(8)), line(4, None), line(8, Some(12)), line(12, None)];
        assert_eq!(drawn(&halves), ["┌───<", "│    ", "└┬──<", " └──>"]);
        let back = [line(0, None), line(4, Some(0)), line(8, Some(4))];
        assert_eq!(drawn(&back), ["┌───>", "└┬──<", " └──<"]);
    }

    #[test]
    fn a_jump_with_no_row_at_its_target_is_not_drawn() {
        let halves = [line(0, Some(0x100)), line(4, Some(4)), line(8, None)];
        assert!(drawn(&halves).iter().all(|row| row.trim().is_empty()));
        assert!(drawn(&[]).is_empty());
    }

    /// The IL view shows the making of the global pointer as one line, so
    /// a jump into it goes to the next line shown.
    #[test]
    fn a_jump_into_a_folded_line_goes_to_the_next_line() {
        let halves = [line(0, Some(6)), line(4, None), line(8, None)];
        assert_eq!(drawn(&halves), ["┌───<", "│    ", "└───>"]);
    }

    #[test]
    fn more_jumps_than_lanes_drop_the_innermost() {
        let halves: Vec<Half<'_>> = (0..12)
            .map(|index| {
                let jump = (index < 6).then(|| 4 * (11 - index));
                line(4 * index, jump)
            })
            .collect();
        let gutter = Gutter::of(&halves);
        let lanes_used = (0..LANES).filter(|&lane| gutter.row(5)[lane].glyph != Glyph::Blank);
        assert_eq!(lanes_used.count(), LANES);
        assert_eq!(gutter.row(4)[LANES].glyph, Glyph::Blank, "the fifth jump has no lane");
    }

    #[test]
    fn a_jump_takes_the_color_of_its_line_and_draws_over_the_rest() {
        let place = |address, jump| Some(LinePlace { address, depth: 0, jump });
        let halves = [
            Half::shown(Side::Same("a"), [None, place(0, Some(8))]),
            Half::shown(Side::Added("b"), [None, place(4, Some(8))]),
            Half::shown(Side::Same("c"), [None, place(8, None)]),
        ];
        let gutter = Gutter::of(&halves);
        assert_eq!(gutter.row(0)[0].tint, Tint::Same);
        assert_eq!(gutter.row(1)[LANES].tint, Tint::Added);
        assert_eq!(gutter.row(2)[LANES].tint, Tint::Added, "the added jump draws last");
    }

    /// A unified diff shows a line both sides hold once: its jump on each
    /// side is one jump where both go to one row.
    #[test]
    fn a_jump_both_sides_hold_is_drawn_once() {
        let place = |address, jump| Some(LinePlace { address, depth: 0, jump });
        let halves = [
            Half::shown(Side::Same("a"), [place(0x100, Some(0x108)), place(0, Some(8))]),
            Half::shown(Side::Removed("b"), [place(0x104, None), None]),
            Half::shown(Side::Same("c"), [place(0x108, None), place(8, None)]),
        ];
        assert_eq!(jumps_of(&halves).len(), 1);
        assert_eq!(drawn(&halves), ["┌───<", "│    ", "└───>"]);
    }

    #[test]
    fn any_jumps_draw_inside_the_gutter() {
        bolero::check!().with_type::<Vec<Option<u8>>>().for_each(|targets| {
            let halves: Vec<Half<'_>> = (0..)
                .zip(targets)
                .map(|(index, target)| line(4 * index, target.map(|to| 4 * u64::from(to))))
                .collect();
            let gutter = Gutter::of(&halves);
            let heads = (0..halves.len())
                .filter(|&row| gutter.row(row)[LANES].glyph != Glyph::Blank)
                .count();
            assert!(heads <= halves.len());
            for row in 0..halves.len() {
                let cells = gutter.row(row);
                // A head shows where a lane turns toward the code.
                let turns = cells[..LANES].iter().any(|cell| {
                    matches!(
                        cell.glyph,
                        Glyph::Top | Glyph::Bottom | Glyph::TopCrossed | Glyph::BottomCrossed
                    )
                });
                assert_eq!(turns, cells[LANES].glyph != Glyph::Blank, "row {row}: {cells:?}");
            }
            assert_eq!(gutter.row(halves.len()), [Cell::default(); WIDTH]);
        });
    }
}
