//! The lines of the jumps at the left of a diff, read back from the text
//! that `hereticus` prints, and cut down to the jumps a snippet shows.
//!
//! A snippet of a diff shows some runs of its lines, with the lines
//! between the runs left out. A jump that leaves its run shows a line to
//! nowhere: the line it goes to is out of sight, and `goto $-0x40` already
//! names where it goes. [`Gutter::keep_whole_jumps`] removes each such
//! jump, and [`Gutter::drop_empty_columns`] then removes the columns that
//! hold no jump.
//!
//! Each jump holds one lane, a column, from its first row to its last. A
//! corner on each of the two rows turns it to the right, and a horizontal
//! line goes on to the head of the arrow in the last column: `<` where the
//! jump leaves, `>` where it arrives.

/// The directions a cell of the gutter joins, as bits.
type Links = u8;

const UP: Links = 1;
const DOWN: Links = 2;
const LEFT: Links = 4;
const RIGHT: Links = 8;

/// The head of an arrow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Head {
    /// `<`: the jump leaves from this row.
    Source,
    /// `>`: the jump arrives at this row.
    Target,
}

/// One cell of the gutter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Cell {
    links: Links,
    /// The head this cell shows while a line joins it from the left.
    head: Option<Head>,
}

impl Cell {
    /// The cell `glyph` draws, or none for a character that is no part of
    /// a gutter.
    fn of(glyph: char) -> Option<Self> {
        let line = |links| Some(Self { links, head: None });
        let head = |head| Some(Self { links: LEFT, head: Some(head) });
        match glyph {
            ' ' => line(0),
            '│' => line(UP | DOWN),
            '─' => line(LEFT | RIGHT),
            '┼' => line(UP | DOWN | LEFT | RIGHT),
            '┌' => line(DOWN | RIGHT),
            '└' => line(UP | RIGHT),
            '┬' => line(DOWN | LEFT | RIGHT),
            '┴' => line(UP | LEFT | RIGHT),
            '<' => head(Head::Source),
            '>' => head(Head::Target),
            _ => None,
        }
    }

    fn glyph(self) -> char {
        if let Some(head) = self.head {
            return match (self.links & LEFT, head) {
                (0, _) => ' ',
                (_, Head::Source) => '<',
                (_, Head::Target) => '>',
            };
        }
        let vertical = self.links & (UP | DOWN);
        let horizontal = self.links & (LEFT | RIGHT);
        match (vertical, horizontal) {
            (0, 0) => ' ',
            (0, _) => '─',
            (_, 0) => '│',
            (_, LEFT) => '┼',
            (DOWN, RIGHT) => '┌',
            (UP, RIGHT) => '└',
            (DOWN, _) => '┬',
            (UP, _) => '┴',
            _ => '┼',
        }
    }

    fn has(self, links: Links) -> bool {
        self.links & links != 0
    }

    fn is_blank(self) -> bool {
        self.links == 0
    }

    /// Whether the cell only carries a horizontal line through, which a
    /// shorter line draws as well.
    fn is_pass_through(self) -> bool {
        self.head.is_none() && self.links & !(LEFT | RIGHT) == 0
    }
}

/// The gutters of the lines of a snippet, each row as wide as the others.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gutter {
    rows: Vec<Vec<Cell>>,
}

impl Gutter {
    /// The gutter of `rows`, each the text of the gutter of one line, or
    /// none where a character is no part of a gutter.
    pub fn parse<'r>(rows: impl IntoIterator<Item = &'r str>) -> Option<Self> {
        let rows = rows
            .into_iter()
            .map(|row| row.chars().map(Cell::of).collect::<Option<Vec<_>>>())
            .collect::<Option<Vec<_>>>()?;
        let width = rows.iter().map(Vec::len).max().unwrap_or(0);
        let rows = rows
            .into_iter()
            .map(|mut row| {
                row.resize(width, Cell::default());
                row
            })
            .collect();
        Some(Self { rows })
    }

    /// The text of each row.
    pub fn rows(&self) -> impl Iterator<Item = String> + '_ {
        self.rows.iter().map(|row| row.iter().map(|cell| cell.glyph()).collect())
    }

    fn width(&self) -> usize {
        self.rows.first().map_or(0, Vec::len)
    }

    /// Remove each jump that does not start and end in the run of rows
    /// `run`, which the snippet shows with no line left out.
    pub fn keep_whole_jumps(&mut self, run: core::ops::Range<usize>) {
        for lane in 0..self.width() {
            let mut row = run.start;
            while row < run.end {
                if !self.rows[row][lane].has(UP | DOWN) {
                    row += 1;
                    continue;
                }
                let first = row;
                while row + 1 < run.end
                    && self.rows[row][lane].has(DOWN)
                    && self.rows[row + 1][lane].has(UP)
                {
                    row += 1;
                }
                let last = row;
                let cut_above = self.rows[first][lane].has(UP);
                let cut_below = self.rows[last][lane].has(DOWN);
                if cut_above || cut_below {
                    self.remove_jump(lane, first..=last, [!cut_above, !cut_below]);
                }
                row += 1;
            }
        }
    }

    /// Remove the jump in `lane` on `rows`, and the lines from its corners
    /// to its heads. `corners` tells whether the first and the last row
    /// show a corner, where the snippet shows that end of the jump.
    fn remove_jump(
        &mut self,
        lane: usize,
        rows: core::ops::RangeInclusive<usize>,
        corners: [bool; 2],
    ) {
        let ends = [*rows.start(), *rows.end()];
        for row in rows {
            self.rows[row][lane].links &= !(UP | DOWN);
        }
        for (row, corner) in ends.into_iter().zip(corners) {
            // A line from another jump that goes across the corner also
            // carries the line to the head, so it stays.
            if corner && !self.rows[row][lane].has(LEFT) {
                self.remove_line_right_of(row, lane);
            }
        }
    }

    /// Remove the horizontal line that starts at `lane` of `row`, up to
    /// its head or to the corner of another jump that it joins.
    fn remove_line_right_of(&mut self, row: usize, lane: usize) {
        let cells = &mut self.rows[row];
        cells[lane].links &= !RIGHT;
        for cell in &mut cells[lane + 1..] {
            cell.links &= !LEFT;
            let vertical = cell.links & (UP | DOWN);
            if cell.head.is_some() || vertical == UP || vertical == DOWN {
                break;
            }
            cell.links &= !RIGHT;
        }
    }

    /// Remove each column that holds no jump on any row, and the column of
    /// the heads where it holds no head.
    pub fn drop_empty_columns(&mut self) {
        let width = self.width();
        let kept: Vec<bool> = (0..width)
            .map(|column| {
                !self.rows.iter().all(|row| {
                    let cell = row[column];
                    cell.is_blank() || cell.is_pass_through()
                })
            })
            .collect();
        for row in &mut self.rows {
            let mut column = 0;
            row.retain(|_| {
                column += 1;
                kept[column - 1]
            });
        }
    }

    /// Whether no row draws anything.
    pub fn is_empty(&self) -> bool {
        self.rows.iter().flatten().all(|cell| cell.is_blank())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gutter(rows: &[&str]) -> Gutter {
        Gutter::parse(rows.iter().copied()).expect("a gutter")
    }

    fn texts(gutter: &Gutter) -> Vec<String> {
        gutter.rows().collect()
    }

    fn pruned(rows: &[&str]) -> Vec<String> {
        let mut gutter = gutter(rows);
        gutter.keep_whole_jumps(0..rows.len());
        gutter.drop_empty_columns();
        texts(&gutter)
    }

    #[test]
    fn each_glyph_reads_back_as_itself() {
        let row = " │─┼┌└┬┴<>";
        assert_eq!(texts(&gutter(&[row])), [row]);
    }

    #[test]
    fn a_character_out_of_a_gutter_is_no_gutter() {
        assert_eq!(Gutter::parse(["│ a"]), None);
    }

    #[test]
    fn a_jump_that_starts_and_ends_in_sight_stays() {
        assert_eq!(pruned(&["┌─<", "│  ", "└─>"]), ["┌<", "│ ", "└>"]);
    }

    #[test]
    fn a_jump_cut_at_either_end_goes() {
        assert_eq!(pruned(&["┌─<", "│  "]), ["", ""]);
        assert_eq!(pruned(&["│  ", "└─>"]), ["", ""]);
        assert_eq!(pruned(&["│  ", "│  "]), ["", ""]);
    }

    #[test]
    fn a_jump_that_goes_across_a_removed_one_stays() {
        // Lane 1 runs from the top out of sight; lane 0 is whole.
        let rows = ["┌┼─<", "││  ", "└┼─>"];
        assert_eq!(pruned(&rows), ["┌<", "│ ", "└>"]);
    }

    #[test]
    fn a_removed_line_stops_at_the_corner_of_another_jump() {
        // Both jumps arrive at the last row. Lane 1 is whole, lane 0 is not.
        let rows = ["│┌─<", "││  ", "└┴─>"];
        assert_eq!(pruned(&rows), ["┌<", "│ ", "└>"]);
    }

    #[test]
    fn a_crossed_corner_keeps_the_line_of_the_other_jump() {
        // Lane 1 starts in sight and is cut below; lane 0 is whole and
        // goes across the corner of lane 1.
        let rows = ["┌┬─<", "││  ", "└┼─>", " │  "];
        assert_eq!(pruned(&rows), ["┌<", "│ ", "└>", "  "]);
    }

    #[test]
    fn a_run_cuts_a_jump_that_goes_on_past_it() {
        let mut both = gutter(&["┌─<", "│  ", "└─>"]);
        both.keep_whole_jumps(0..2);
        both.keep_whole_jumps(2..3);
        both.drop_empty_columns();
        assert!(both.is_empty(), "{:?}", texts(&both));
    }

    #[test]
    fn two_jumps_in_one_lane_are_two_jumps() {
        let rows = ["┌─<", "└─>", "┌─<", "│  "];
        assert_eq!(pruned(&rows), ["┌<", "└>", "  ", "  "]);
    }

    /// A row of up to six cells of glyphs.
    fn row_of(seed: u64, width: usize) -> String {
        const GLYPHS: [char; 10] = [' ', '│', '─', '┼', '┌', '└', '┬', '┴', '<', '>'];
        (0..width).map(|at| GLYPHS[((seed >> (at * 4)) % 10) as usize]).collect()
    }

    #[test]
    fn pruning_any_gutter_leaves_no_line_to_nowhere_and_keeps_the_rows() {
        bolero::check!().with_type::<(Vec<u64>, u8)>().for_each(|(seeds, width)| {
            let width = usize::from(width % 6);
            let rows: Vec<String> = seeds.iter().take(12).map(|&s| row_of(s, width)).collect();
            let mut gutter = Gutter::parse(rows.iter().map(String::as_str)).expect("glyphs");
            gutter.keep_whole_jumps(0..rows.len());
            gutter.drop_empty_columns();
            assert_eq!(gutter.rows.len(), rows.len(), "each row stays");
            let width = gutter.width();
            assert!(gutter.rows.iter().all(|row| row.len() == width), "the rows stay even");
            // No vertical line runs off the top or the bottom.
            for lane in 0..width {
                assert!(!gutter.rows.first().is_some_and(|row| row[lane].has(UP)));
                assert!(!gutter.rows.last().is_some_and(|row| row[lane].has(DOWN)));
            }
            let again = texts(&gutter);
            gutter.keep_whole_jumps(0..rows.len());
            gutter.drop_empty_columns();
            assert_eq!(texts(&gutter), again, "a second pass changes nothing");
        });
    }
}
