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

use super::{
    Hidden, Paint, Row, Sort, describe, describe_confidence, describe_edits, describe_kinds,
    is_interesting, is_shown_unmatched, name_of, name_of_kind, sort_shown, summary_lines,
    unmatched_word,
};

/// The pairs a report lists, in its order.
fn shown_pairs(diff: &Diff, show_all: bool, hidden: Hidden, sort: Sort) -> Vec<&Match> {
    let mut shown: Vec<&Match> =
        diff.matched.iter().filter(|pair| show_all || is_interesting(pair, hidden)).collect();
    sort_shown(&mut shown, sort);
    shown
}

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

/// Print the report as a markdown table, the functions that went or came as
/// a list, and the summary.
pub(crate) fn print_markdown(
    diff: &Diff,
    before: &Binary,
    after: &Binary,
    show_all: bool,
    hidden: Hidden,
    sort: Sort,
    near_miss_floor: f64,
) {
    let shown = shown_pairs(diff, show_all, hidden, sort);
    if !shown.is_empty() {
        let rows = shown.iter().map(|pair| {
            let name = name_of(before, pair.before);
            let renamed = name_of(after, pair.after);
            Row {
                function: if name == renamed {
                    code(&name)
                } else {
                    format!("{} -> {}", code(&name), code(&renamed))
                },
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
    for (index, contents) in diff.removed_with_contents() {
        if show_all || is_shown_unmatched(contents, hidden) {
            let note = closest_note(diff.near_miss(index), after, near_miss_floor);
            unmatched.push(format!(
                "- {}: {}{}",
                code(&name_of(before, index)),
                unmatched_word("gone", contents),
                note.map(|note| format!(", {note}")).unwrap_or_default()
            ));
        }
    }
    for (index, contents) in diff.added_with_contents() {
        if show_all || is_shown_unmatched(contents, hidden) {
            let note = closest_note(diff.added_near_miss(index), before, near_miss_floor);
            unmatched.push(format!(
                "- {}: {}{}",
                code(&name_of(after, index)),
                unmatched_word("new", contents),
                note.map(|note| format!(", {note}")).unwrap_or_default()
            ));
        }
    }
    // Each part is a block of its own: markdown joins lines that touch.
    let mut blocks = Vec::new();
    if !unmatched.is_empty() {
        blocks.push(unmatched.join("\n"));
    }
    blocks.extend(summary_lines(diff, hidden));
    if !shown.is_empty() {
        println!();
    }
    println!("{}", blocks.join("\n\n"));
}

/// Text as a JSON string, quoted, with what JSON needs escaped.
fn json_string(text: &str) -> String {
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

/// One pair, as a JSON object.
fn json_pair(pair: &Match, before: &Binary, after: &Binary) -> String {
    let touched: Vec<String> = pair
        .kinds
        .present()
        .map(|(kind, count)| format!("{}:{count}", json_string(name_of_kind(kind))))
        .collect();
    format!(
        "{{\"before\":{},\"after\":{},\"change\":{},\"score\":{:.4},\
         \"added\":{},\"removed\":{},\"edited\":{},\"touched\":{{{}}},\"matched_by\":{}}}",
        json_function(before, pair.before),
        json_function(after, pair.after),
        json_string(describe(pair.changed)),
        pair.score,
        pair.edits.added,
        pair.edits.removed,
        pair.edits.edited,
        touched.join(","),
        json_string(describe_confidence(pair.confidence)),
    )
}

/// A function that went or came, as a JSON object, with the closest one on
/// the other side where there is one.
fn json_unmatched(
    binary: &Binary,
    index: usize,
    contents: Contents,
    closest: Option<(&Binary, usize, f64)>,
) -> String {
    let holds = match contents {
        Contents::Code => "code",
        Contents::Data => "data",
    };
    let closest = match closest {
        Some((other, best, score)) => {
            format!("{{\"function\":{},\"score\":{score:.4}}}", json_function(other, best))
        }
        None => "null".to_string(),
    };
    format!(
        "{{\"function\":{},\"holds\":\"{holds}\",\"closest\":{closest}}}",
        json_function(binary, index)
    )
}

/// Print the report as one JSON object.
///
/// Every address is a number, not a string, so a tool can compare it. The
/// totals count every function, whatever the report lists.
pub(crate) fn print_json(
    diff: &Diff,
    before: &Binary,
    after: &Binary,
    show_all: bool,
    hidden: Hidden,
    sort: Sort,
) {
    let pairs: Vec<String> = shown_pairs(diff, show_all, hidden, sort)
        .into_iter()
        .map(|pair| json_pair(pair, before, after))
        .collect();
    let gone: Vec<String> = diff
        .removed_with_contents()
        .filter(|&(_, contents)| show_all || is_shown_unmatched(contents, hidden))
        .map(|(index, contents)| {
            let miss = diff.near_miss(index);
            let closest = miss.and_then(|miss| Some((after, miss.best?, miss.score)));
            json_unmatched(before, index, contents, closest)
        })
        .collect();
    let new: Vec<String> = diff
        .added_with_contents()
        .filter(|&(_, contents)| show_all || is_shown_unmatched(contents, hidden))
        .map(|(index, contents)| {
            let miss = diff.added_near_miss(index);
            let closest = miss.and_then(|miss| Some((before, miss.best?, miss.score)));
            json_unmatched(after, index, contents, closest)
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
