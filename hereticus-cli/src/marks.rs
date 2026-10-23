//! The functions a project marked, as each report shows them.
//!
//! A reader marks a function in the browser and gives it a label: see
//! [`crate::tui::Mark`]. Each report of an opened project lists the marked
//! functions first, whatever would hide them, with the label beside the
//! name, as the browser does.

use hereticus::address::Contents;
use hereticus::matching::Match;

use crate::tui::{Key, Mark};

/// What leads the name of a marked function, in the browser too.
pub const MARK_SIGN: &str = "◆ ";

/// The label of each marked function, by the row it marks, in the order
/// of the project.
#[derive(Clone, Debug, Default)]
pub struct Marks {
    labels: Vec<(Key, String)>,
}

impl Marks {
    pub fn new(marks: &[Mark]) -> Self {
        Self { labels: marks.iter().map(|mark| (mark.row, mark.label.clone())).collect() }
    }

    /// The label of a pair, where it is marked.
    pub fn of_pair(&self, pair: &Match) -> Option<&str> {
        self.of(Key::Pair { before: pair.before, after: pair.after })
    }

    /// The label of a function gone or new, by its index in its binary.
    pub fn of_unmatched(&self, side: Side, function: usize) -> Option<&str> {
        self.of(match side {
            Side::Gone => Key::Gone { function },
            Side::New => Key::New { function },
        })
    }

    fn of(&self, key: Key) -> Option<&str> {
        self.labels.iter().find(|(marked, _)| *marked == key).map(|(_, label)| label.as_str())
    }

    /// The row whose label is `label`, for `--diff` to find.
    pub fn find(&self, label: &str) -> Option<Key> {
        // A label is a name the reader gave, so an empty one names nothing.
        self.labels.iter().find(|(_, text)| !text.is_empty() && text == label).map(|&(key, _)| key)
    }

    /// Order the pairs the marked ones first, and keep the order within
    /// each part.
    pub fn first_pairs(&self, pairs: &mut [&Match]) {
        pairs.sort_by_key(|pair| self.of_pair(pair).is_none());
    }

    /// Order the functions gone or new the marked ones first, and keep the
    /// order within each part.
    pub fn first_unmatched(&self, side: Side, functions: &mut [(usize, Contents)]) {
        functions.sort_by_key(|&(function, _)| self.of_unmatched(side, function).is_none());
    }
}

/// Which list of functions with no counterpart a function is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// In the earlier binary only.
    Gone,
    /// In the later binary only.
    New,
}

/// `name` with the sign and the label of its mark, as `◆ handle [fix]`.
pub fn marked(name: String, label: Option<&str>) -> String {
    match label {
        None => name,
        Some("") => format!("{MARK_SIGN}{name}"),
        Some(label) => format!("{MARK_SIGN}{name} [{label}]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mark(row: Key, label: &str) -> Mark {
        Mark { row, label: label.to_string() }
    }

    #[test]
    fn a_marked_name_shows_its_sign_and_label() {
        assert_eq!(marked("handle".to_string(), None), "handle");
        assert_eq!(marked("handle".to_string(), Some("")), "◆ handle");
        assert_eq!(marked("handle".to_string(), Some("fix")), "◆ handle [fix]");
    }

    #[test]
    fn each_kind_of_row_has_its_own_marks() {
        let marks = Marks::new(&[
            mark(Key::Pair { before: 1, after: 2 }, "pair"),
            mark(Key::Gone { function: 1 }, "gone"),
            mark(Key::New { function: 1 }, "new"),
        ]);
        let pair = |before, after| Match { before, after, ..plain_pair() };
        assert_eq!(marks.of_pair(&pair(1, 2)), Some("pair"));
        assert_eq!(marks.of_pair(&pair(2, 1)), None);
        assert_eq!(marks.of_unmatched(Side::Gone, 1), Some("gone"));
        assert_eq!(marks.of_unmatched(Side::New, 1), Some("new"));
        assert_eq!(marks.of_unmatched(Side::New, 2), None);
    }

    #[test]
    fn a_label_finds_the_first_row_it_marks_and_an_empty_one_none() {
        let marks = Marks::new(&[
            mark(Key::Gone { function: 3 }, ""),
            mark(Key::Gone { function: 4 }, "twice"),
            mark(Key::New { function: 5 }, "twice"),
        ]);
        assert_eq!(marks.find("twice"), Some(Key::Gone { function: 4 }));
        assert_eq!(marks.find(""), None);
        assert_eq!(marks.find("other"), None);
    }

    #[test]
    fn the_marked_rows_go_first_and_each_part_keeps_its_order() {
        let marks =
            Marks::new(&[mark(Key::New { function: 3 }, ""), mark(Key::New { function: 1 }, "x")]);
        let mut functions: Vec<(usize, Contents)> =
            (0..5).map(|function| (function, Contents::Code)).collect();
        marks.first_unmatched(Side::New, &mut functions);
        let order: Vec<usize> = functions.iter().map(|&(function, _)| function).collect();
        assert_eq!(order, [1, 3, 0, 2, 4]);

        // A mark on the other side moves nothing.
        marks.first_unmatched(Side::Gone, &mut functions);
        let again: Vec<usize> = functions.iter().map(|&(function, _)| function).collect();
        assert_eq!(again, order);
    }

    /// A pair with no edit, for the fields a test does not set.
    fn plain_pair() -> Match {
        use hereticus::matching::{Changed, Confidence, EditKinds, Edits};
        Match {
            before: 0,
            after: 0,
            confidence: Confidence::SameName,
            score: 1.0,
            changed: Changed::No,
            edits: Edits::default(),
            kinds: EditKinds::default(),
            rarity: 0.0,
            bounded_calls: 0,
            early_exits: 0,
        }
    }
}
