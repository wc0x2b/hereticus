//! Fit the columns of the table of functions to the width of the terminal.
//!
//! Each column takes the width of its widest cell. Where the terminal is too
//! narrow for that, the columns a reader needs least give up their width
//! first, and a cell cut short ends in `…`.

use ratatui::text::{Line, Span};
use unicode_width::UnicodeWidthStr;

/// A column of the table, in the order it shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Column {
    Rank,
    Function,
    Change,
    Score,
    Edits,
    Touched,
    MatchedBy,
}

impl Column {
    pub const ALL: [Self; 7] = [
        Self::Rank,
        Self::Function,
        Self::Change,
        Self::Score,
        Self::Edits,
        Self::Touched,
        Self::MatchedBy,
    ];

    pub fn heading(self) -> &'static str {
        match self {
            Self::Rank => "#",
            Self::Function => "FUNCTION",
            Self::Change => "CHANGE",
            Self::Score => "SCORE",
            Self::Edits => "+/-/~",
            Self::Touched => "TOUCHED",
            Self::MatchedBy => "MATCHED BY",
        }
    }

    pub fn index(self) -> usize {
        self as usize
    }
}

/// The width of each column, by [`Column::ALL`].
pub type Widths = [u16; Column::ALL.len()];

/// The order in which the columns give up their width, and how narrow each
/// step leaves the column. The kinds touched and how a pair matched are
/// read last, so they shrink first, then the names down to what still
/// tells most of them apart. Past that, the two columns go.
const SHRINK: [(Column, u16); 6] = [
    (Column::Touched, 12),
    (Column::MatchedBy, 10),
    (Column::Function, 16),
    (Column::MatchedBy, 0),
    (Column::Touched, 0),
    (Column::Function, 8),
];

/// The widths of the headings, which each column holds at least.
pub fn heading_widths() -> Widths {
    Column::ALL.map(|column| column.heading().len() as u16)
}

/// The width of each column, from the width of its widest cell, `natural`,
/// and the width the table has for its cells, `available`.
///
/// Width left over goes to the names. Where the cells do not fit, the
/// columns shrink in the order of [`SHRINK`].
pub fn allocate(natural: Widths, available: u16) -> Widths {
    let mut widths = natural;
    let total: u16 = widths.iter().fold(0, |sum, &width| sum.saturating_add(width));
    if total <= available {
        widths[Column::Function.index()] += available - total;
        return widths;
    }
    let mut over = total - available;
    for (column, floor) in SHRINK {
        let width = &mut widths[column.index()];
        let cut = over.min(width.saturating_sub(floor));
        *width -= cut;
        over -= cut;
    }
    widths
}

/// `line`, cut to `width` columns of the terminal, with `…` as its last
/// character where it was cut.
pub fn fit(line: Line<'static>, width: u16) -> Line<'static> {
    let width = usize::from(width);
    if line.width() <= width {
        return line;
    }
    let Some(room) = width.checked_sub(1) else {
        return Line { spans: Vec::new(), ..line };
    };
    // The width of a text is not always the sum of the widths of its
    // characters, as where a mark joins the letter before it, so each step
    // measures all that is kept.
    let mut used = 0;
    let mut spans = Vec::new();
    let mut last_style = line.style;
    'spans: for span in &line.spans {
        last_style = span.style;
        let mut kept = String::new();
        for character in span.content.chars() {
            kept.push(character);
            if used + kept.width() > room {
                kept.pop();
                if !kept.is_empty() {
                    spans.push(Span::styled(kept, span.style));
                }
                break 'spans;
            }
        }
        used += kept.width();
        spans.push(Span::styled(kept, span.style));
    }
    spans.push(Span::styled("…", last_style));
    Line { spans, ..line }
}

/// `text`, cut at its start to `width` columns of the terminal, with `…` as
/// its first character where it was cut. The end of a path names the file,
/// so a path keeps its end.
pub fn fit_start(text: &str, width: usize) -> String {
    if text.width() <= width {
        return text.to_string();
    }
    let Some(room) = width.checked_sub(1) else {
        return String::new();
    };
    // See `fit` for why each step measures all that is kept.
    let mut kept_from = text.len();
    for (index, _) in text.char_indices().rev() {
        if text[index..].width() > room {
            break;
        }
        kept_from = index;
    }
    format!("…{}", &text[kept_from..])
}

#[cfg(test)]
mod tests {
    use super::*;

    const NATURAL: Widths = [3, 20, 14, 5, 7, 30, 32];

    fn sum(widths: Widths) -> u16 {
        widths.iter().sum()
    }

    #[test]
    fn a_wide_table_gives_each_column_its_cells_and_the_rest_to_the_names() {
        let widths = allocate(NATURAL, 200);
        let function = Column::Function.index();
        assert_eq!(widths[..function], NATURAL[..function]);
        assert_eq!(widths[function + 1..], NATURAL[function + 1..]);
        assert_eq!(sum(widths), 200);
    }

    #[test]
    fn a_narrow_table_shrinks_the_kinds_touched_first() {
        let widths = allocate(NATURAL, sum(NATURAL) - 10);
        assert_eq!(widths[Column::Touched.index()], 20);
        assert_eq!(widths[Column::MatchedBy.index()], 32, "not yet");
        assert_eq!(widths[Column::Function.index()], 20, "not yet");
    }

    #[test]
    fn a_very_narrow_table_drops_the_last_two_columns_before_the_names() {
        let widths = allocate(NATURAL, 50);
        assert_eq!(widths[Column::MatchedBy.index()], 0);
        assert_eq!(widths[Column::Function.index()], 16);
        assert_eq!(widths[Column::Change.index()], 14, "the kind of change stays");
        assert_eq!(widths[Column::Rank.index()], 3, "the rank stays");
        assert_eq!(sum(widths), 50);
    }

    /// Any widths fit where the columns that never shrink fit, and a column
    /// never grows past its cells but for the names.
    #[test]
    fn any_widths_fit_and_never_grow() {
        bolero::check!().with_type::<(Widths, u16)>().for_each(|&(natural, available)| {
            let natural = natural.map(|width| width % 300);
            let widths = allocate(natural, available);
            for column in Column::ALL.into_iter().filter(|&column| column != Column::Function) {
                assert!(widths[column.index()] <= natural[column.index()], "{column:?}");
            }
            let fixed: u16 = [Column::Rank, Column::Change, Column::Score, Column::Edits]
                .map(|column| natural[column.index()])
                .iter()
                .sum::<u16>()
                + natural[Column::Function.index()].min(8);
            if fixed <= available {
                assert!(sum(widths) <= available, "{widths:?} in {available}");
            }
        });
    }

    #[test]
    fn a_line_that_fits_is_kept() {
        let line = Line::from("check_header");
        assert_eq!(fit(line.clone(), 12), line);
    }

    #[test]
    fn a_line_cut_short_ends_in_an_ellipsis_and_keeps_its_styles() {
        use ratatui::style::{Color, Style};
        let red = Style::new().fg(Color::Red);
        let line = Line::from(vec![Span::raw("check"), Span::styled("_header", red)]);
        let cut = fit(line, 8);
        assert_eq!(cut.width(), 8);
        assert_eq!(cut.to_string(), "check_h…");
        assert_eq!(cut.spans.last().unwrap().style, red);
        assert_eq!(fit(Line::from("abc"), 0).width(), 0);
        assert_eq!(fit(Line::from("abc"), 1).to_string(), "…");
    }

    #[test]
    fn a_wide_character_is_not_split() {
        assert_eq!(fit(Line::from("名前名前"), 4).to_string(), "名…");
    }

    #[test]
    fn any_line_fits_its_width() {
        bolero::check!().with_type::<(String, u8)>().for_each(|(text, width)| {
            let cut = fit(Line::from(text.clone()), u16::from(*width));
            assert!(cut.width() <= usize::from(*width), "{text:?} in {width}");
        });
    }

    #[test]
    fn a_path_cut_short_keeps_its_end() {
        let path = "/home/reader/firmware/before.bin";
        assert_eq!(fit_start(path, 40), path);
        assert_eq!(fit_start(path, path.len()), path);
        assert_eq!(fit_start(path, 12), "…/before.bin");
        assert_eq!(fit_start(path, 1), "…");
        assert_eq!(fit_start(path, 0), "");
        assert_eq!(fit_start("", 0), "");
    }

    #[test]
    fn a_path_is_not_cut_inside_a_wide_character() {
        assert_eq!(fit_start("名前名前", 4), "…前");
    }

    #[test]
    fn any_path_fits_its_width_and_keeps_its_end() {
        bolero::check!().with_type::<(String, u8)>().for_each(|(text, width)| {
            let width = usize::from(*width);
            let cut = fit_start(text, width);
            assert!(cut.width() <= width, "{text:?} in {width}");
            let kept = cut.strip_prefix('…').unwrap_or(&cut);
            assert!(text.ends_with(kept), "{text:?} in {width}: {cut:?}");
        });
    }
}
