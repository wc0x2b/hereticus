//! The report as markdown, to paste into a document, and as JSON, for other
//! tools to read.
//!
//! Both list what the text report lists, chosen and ordered the same way.

use core::fmt::Write as _;

use hereticus::address::Contents;
use hereticus::matching::{Diff, Match, NearMiss};
use hereticus::obj::Binary;
use tabled::Table;
use tabled::settings::Style;

use super::marks::{Side, marked};
use super::{
    Feature, Listing, Paint, Row, describe, describe_confidence, describe_edits, describe_kinds,
    name_of, name_of_kind, summary_lines, unmatched_word,
};

/// A name in code spans, so markdown reads `__init` as a name and not as
/// bold text.
fn code(name: &str) -> String {
    // A span that holds a backtick needs a longer fence, which no symbol
    // name calls for; a backtick reads as a quote instead.
    format!("`{}`", name.replace('`', "'"))
}

/// The closest function on the other side, as the text report names it,
/// where it scores `floor` or more.
fn closest_note(miss: Option<&NearMiss>, other: &Binary, floor: f64) -> Option<String> {
    let miss = miss.filter(|miss| miss.score >= floor)?;
    Some(format!("closest {} at {:.2}", code(&name_of(other, miss.best?)), miss.score))
}

/// The function on the other side in the same place, as the text report
/// names it.
fn place_note(miss: Option<&NearMiss>, other: &Binary) -> Option<String> {
    Some(format!("same place as {}", code(&name_of(other, miss?.in_place?))))
}

/// A name in code spans, with the sign and the label of its mark, as
/// ``◆ `handle` [fix]``.
fn marked_code(name: String, label: Option<&str>) -> String {
    // A `|` would end the cell of a table.
    marked(name, label.map(|label| label.replace('|', "\\|")).as_deref())
}

/// The notes that are present, each after a comma.
fn joined_notes(notes: impl IntoIterator<Item = Option<String>>) -> String {
    notes.into_iter().flatten().map(|note| format!(", {note}")).collect()
}

/// Print the report as a markdown table, the functions that went or came as
/// a list, and the summary.
pub(crate) fn print_markdown(
    diff: &Diff,
    before: &Binary,
    after: &Binary,
    listing: Listing<'_>,
    near_miss_floor: f64,
) {
    let marks = listing.marks;
    let shown = listing.pairs(diff);
    if !shown.is_empty() {
        let rows = shown.iter().map(|pair| {
            let name = name_of(before, pair.before);
            let renamed = name_of(after, pair.after);
            let function = if name == renamed {
                code(&name)
            } else {
                format!("{} -> {}", code(&name), code(&renamed))
            };
            Row {
                function: marked_code(function, marks.of_pair(pair)),
                change: describe(pair.changed),
                score: format!("{:.2}", pair.score),
                edits: describe_edits(pair.edits, Paint::Off),
                kinds: describe_kinds(pair.kinds, pair.changed),
                matched_by: describe_confidence(pair.confidence),
            }
        });
        let mut table = Table::new(rows);
        table.with(Style::markdown());
        println!("{table}");
    }

    let mut unmatched = Vec::new();
    for (index, contents) in listing.unmatched(diff, Side::Gone) {
        let miss = diff.near_miss(index);
        let notes = [closest_note(miss, after, near_miss_floor), place_note(miss, after)];
        unmatched.push(format!(
            "- {}: {}{}",
            marked_code(code(&name_of(before, index)), marks.of_unmatched(Side::Gone, index)),
            unmatched_word("gone", contents),
            joined_notes(notes)
        ));
    }
    for (index, contents) in listing.unmatched(diff, Side::New) {
        let miss = diff.added_near_miss(index);
        let notes = [closest_note(miss, before, near_miss_floor), place_note(miss, before)];
        unmatched.push(format!(
            "- {}: {}{}",
            marked_code(code(&name_of(after, index)), marks.of_unmatched(Side::New, index)),
            unmatched_word("new", contents),
            joined_notes(notes)
        ));
    }
    // Each part is a block of its own: markdown joins lines that touch.
    let mut blocks = Vec::new();
    if !unmatched.is_empty() {
        blocks.push(unmatched.join("\n"));
    }
    blocks.extend(summary_lines(diff, listing.hidden, listing.only));
    if !shown.is_empty() {
        println!();
    }
    println!("{}", blocks.join("\n\n"));
}

/// Text as a JSON string, quoted, with what JSON needs escaped.
pub(crate) fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if u32::from(control) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(control));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// The function at `index`, as a JSON object of its name and address.
fn json_function(binary: &Binary, index: usize) -> String {
    let function = &binary.functions[index];
    format!(
        "{{\"name\":{},\"address\":{}}}",
        json_string(&name_of(binary, index)),
        function.address
    )
}

/// The `mark` member of an object, where the function is marked: the label,
/// which can be empty.
fn json_mark(label: Option<&str>) -> String {
    label.map_or_else(String::new, |label| format!(",\"mark\":{}", json_string(label)))
}

/// One pair, as a JSON object.
fn json_pair(pair: &Match, before: &Binary, after: &Binary, mark: Option<&str>) -> String {
    let touched: Vec<String> = pair
        .kinds
        .present()
        .map(|(kind, count)| format!("{}:{count}", json_string(name_of_kind(kind))))
        .collect();
    let features: Vec<String> = Feature::ALL
        .into_iter()
        .filter(|&feature| crate::has_feature(pair, feature))
        .map(|feature| json_string(feature.name()))
        .collect();
    format!(
        "{{\"before\":{},\"after\":{},\"change\":{},\"score\":{:.4},\
         \"added\":{},\"removed\":{},\"edited\":{},\"touched\":{{{}}},\"features\":[{}],\
         \"matched_by\":{}{}}}",
        json_function(before, pair.before),
        json_function(after, pair.after),
        json_string(describe(pair.changed)),
        pair.score,
        pair.edits.added,
        pair.edits.removed,
        pair.edits.edited,
        touched.join(","),
        features.join(","),
        json_string(describe_confidence(pair.confidence)),
        json_mark(mark),
    )
}

/// A function that went or came, as a JSON object, with the closest one on
/// the other side where there is one.
fn json_unmatched(
    binary: &Binary,
    index: usize,
    contents: Contents,
    other: &Binary,
    miss: Option<&NearMiss>,
    mark: Option<&str>,
) -> String {
    let holds = match contents {
        Contents::Code => "code",
        Contents::Data => "data",
    };
    let closest = match miss.and_then(|miss| Some((miss.best?, miss.score))) {
        Some((best, score)) => {
            format!("{{\"function\":{},\"score\":{score:.4}}}", json_function(other, best))
        }
        None => "null".to_string(),
    };
    let in_place = match miss.and_then(|miss| miss.in_place) {
        Some(place) => json_function(other, place),
        None => "null".to_string(),
    };
    format!(
        "{{\"function\":{},\"holds\":\"{holds}\",\"closest\":{closest},\
         \"in_place\":{in_place}{}}}",
        json_function(binary, index),
        json_mark(mark),
    )
}

/// Print the report as one JSON object.
///
/// Every address is a number, not a string, so a tool can compare it. The
/// totals count every function, whatever the report lists.
pub(crate) fn print_json(diff: &Diff, before: &Binary, after: &Binary, listing: Listing<'_>) {
    let marks = listing.marks;
    let pairs: Vec<String> = listing
        .pairs(diff)
        .into_iter()
        .map(|pair| json_pair(pair, before, after, marks.of_pair(pair)))
        .collect();
    let gone: Vec<String> = listing
        .unmatched(diff, Side::Gone)
        .into_iter()
        .map(|(index, contents)| {
            let mark = marks.of_unmatched(Side::Gone, index);
            json_unmatched(before, index, contents, after, diff.near_miss(index), mark)
        })
        .collect();
    let new: Vec<String> = listing
        .unmatched(diff, Side::New)
        .into_iter()
        .map(|(index, contents)| {
            let mark = marks.of_unmatched(Side::New, index);
            json_unmatched(after, index, contents, before, diff.added_near_miss(index), mark)
        })
        .collect();
    let changed = diff.changed().count();
    println!(
        "{{\"pairs\":[{}],\"gone\":[{}],\"new\":[{}],\"totals\":{{\"matched\":{},\
         \"unchanged\":{},\"changed\":{changed},\"gone\":{},\"new\":{}}}}}",
        pairs.join(","),
        gone.join(","),
        new.join(","),
        diff.matched.len(),
        diff.matched.len() - changed,
        diff.removed.len(),
        diff.added.len(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_json_string_escapes_what_json_needs() {
        assert_eq!(json_string("plain"), "\"plain\"");
        assert_eq!(json_string("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(json_string("line\nnext\ttab"), "\"line\\nnext\\ttab\"");
        assert_eq!(json_string("\u{1}"), "\"\\u0001\"");
        assert_eq!(json_string("ü"), "\"ü\"");
    }

    #[test]
    fn a_name_in_markdown_is_code() {
        assert_eq!(code("__init"), "`__init`");
        assert_eq!(code("a`b"), "`a'b`");
    }
}
