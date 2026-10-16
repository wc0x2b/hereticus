//! Keep the numbers the docs quote in step with the tests that lock them.
//!
//! A number in a doc names its source in a comment right after it:
//!
//! ```text
//! 0.95%<!-- from truth_kernels: all / wrong% -->
//! 45937<!-- from boundaries.rs: exact -->
//! ```
//!
//! A source without `.rs` is the one snapshot of `tests/snapshots` whose
//! name starts with it, and the key is a row and a column of a table in
//! it. A source with `.rs` is a test of `tests`, and the key is a field
//! that it sets once, as `exact: 45937`. The doc may round the number.
//!
//! When a snapshot or a test changes, this test fails until the docs
//! quote the new numbers. It reads only the files of the tree, so it runs
//! in `just quick-test` though the `truth_*` tests do not.

use std::path::{Path, PathBuf};

const MARKER_START: &str = "<!-- from ";
const MARKER_END: &str = "-->";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn tests_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

/// The docs that can quote a number: the Markdown files at the root, and
/// in the book and the report folders.
fn docs() -> Vec<PathBuf> {
    fn markdown_in(dir: &Path, recurse: bool, found: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("a docs folder").flatten() {
            let path = entry.path();
            if path.is_dir() {
                if recurse {
                    markdown_in(&path, recurse, found);
                }
            } else if path.extension().is_some_and(|extension| extension == "md") {
                found.push(path);
            }
        }
    }
    let root = root();
    let mut found = Vec::new();
    markdown_in(&root, false, &mut found);
    for dir in ["book/src", "real-life-reports", "malware-reports"] {
        markdown_in(&root.join(dir), true, &mut found);
    }
    found.sort();
    found
}

/// A number a doc quotes, and where it says the number comes from.
#[derive(Debug, PartialEq)]
struct Quote<'a> {
    line: usize,
    number: &'a str,
    source: &'a str,
    key: &'a str,
}

/// Whether `at` is inside a fenced code block of `text`, which shows a
/// marker and does not use it.
fn in_code_block(text: &str, at: usize) -> bool {
    text[..at].lines().filter(|line| line.trim_start().starts_with("```")).count() % 2 == 1
}

/// Every marked number of `text`, or the first marker that is malformed.
fn quotes(text: &str) -> Result<Vec<Quote<'_>>, String> {
    let mut found = Vec::new();
    for (start, _) in text.match_indices(MARKER_START) {
        if in_code_block(text, start) {
            continue;
        }
        let line = text[..start].matches('\n').count() + 1;
        let body_start = start + MARKER_START.len();
        let body_len = text[body_start..]
            .find(MARKER_END)
            .ok_or_else(|| format!("line {line}: the marker has no `{MARKER_END}`"))?;
        let body = text[body_start..body_start + body_len].trim();
        let (source, key) = body
            .split_once(": ")
            .ok_or_else(|| format!("line {line}: `{body}` is not `source: key`"))?;
        let before = &text[..start];
        let number_start = before
            .rfind(|c: char| !(c.is_ascii_digit() || matches!(c, '.' | ',' | '%')))
            .map_or(0, |at| at + 1);
        let number = before[number_start..].trim_end_matches(['.', ',']);
        if !number.bytes().any(|byte| byte.is_ascii_digit()) {
            return Err(format!("line {line}: no number comes right before `{body}`"));
        }
        found.push(Quote { line, number, source: source.trim(), key: key.trim() });
    }
    Ok(found)
}

/// The value at `row` and `column` of the tables of a snapshot.
///
/// The values of a table are right-aligned under their headings. A heading
/// can be wider than its column, as `in lib`, and push the headings after
/// it out of line, so each word of the heading line goes to the value whose
/// end is closest to its own.
fn table_cell(snapshot: &str, row: &str, column: &str) -> Result<String, String> {
    let mut found = Vec::new();
    let mut heading: Option<&str> = None;
    for line in snapshot.lines() {
        if line.trim().is_empty() || line.starts_with("---") {
            heading = None;
            continue;
        }
        let Some(heading) = heading else {
            heading = Some(line);
            continue;
        };
        let values = values_of(line);
        let name_end = values.first().map_or(line.len(), |&(start, _)| start);
        if values.is_empty() || line[..name_end].trim() != row {
            continue;
        }
        let labels = labels_of(heading, &values);
        found.extend(
            labels
                .iter()
                .zip(&values)
                .filter(|(label, _)| *label == column)
                .map(|(_, &(start, end))| line[start..end].to_owned()),
        );
    }
    match found.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(format!("no table has row `{row}` and column `{column}`")),
        _ => Err(format!("{} tables have row `{row}` and column `{column}`", found.len())),
    }
}

/// The heading of each of `values`, from the words of the `heading` line.
///
/// Each heading is one word or more, right-aligned over its values, but a
/// heading wider than its column, as `in lib`, pushes the headings after it
/// out of line. So the words split into one run for each value, in order,
/// where the ends of the runs come closest to the ends of the values.
fn labels_of(heading: &str, values: &[(usize, usize)]) -> Vec<String> {
    // The first word names the column of the row names.
    let words: Vec<(usize, usize)> = words_of(heading)
        .into_iter()
        .skip(1)
        .filter(|&(start, end)| &heading[start..end] != "|")
        .collect();
    if values.is_empty() || words.len() < values.len() {
        return vec![String::new(); values.len()];
    }
    // `cost[w][v]`: the least distance over the splits of the first `w`
    // words into runs for the first `v` values, and where its last run starts.
    let mut cost = vec![vec![(usize::MAX, 0); values.len() + 1]; words.len() + 1];
    cost[0][0] = (0, 0);
    for v in 1..=values.len() {
        for w in v..=words.len() {
            let distance = words[w - 1].1.abs_diff(values[v - 1].1);
            cost[w][v] = (v - 1..w)
                .filter(|&run_start| cost[run_start][v - 1].0 != usize::MAX)
                .map(|run_start| (cost[run_start][v - 1].0 + distance, run_start))
                .min()
                .unwrap_or((usize::MAX, 0));
        }
    }
    let mut labels = vec![String::new(); values.len()];
    let mut run_end = words.len();
    for v in (1..=values.len()).rev() {
        let run_start = cost[run_end][v].1;
        labels[v - 1] = words[run_start..run_end]
            .iter()
            .map(|&(start, end)| &heading[start..end])
            .collect::<Vec<_>>()
            .join(" ");
        run_end = run_start;
    }
    labels
}

/// The byte ranges of the words of a line.
fn words_of(line: &str) -> Vec<(usize, usize)> {
    let mut words = Vec::new();
    let mut start = None;
    for (at, c) in line.char_indices().chain([(line.len(), ' ')]) {
        match (start, c.is_whitespace()) {
            (None, false) => start = Some(at),
            (Some(word_start), true) => {
                words.push((word_start, at));
                start = None;
            }
            _ => {}
        }
    }
    words
}

/// The byte ranges of the values at the end of a table row: the numbers
/// after its name, with the `|` that splits a table into groups skipped.
fn values_of(line: &str) -> Vec<(usize, usize)> {
    let words = words_of(line);
    let is_value = |&(start, end): &(usize, usize)| {
        let word = line[start..end].trim_end_matches('%');
        word == "|" || word.parse::<f64>().is_ok()
    };
    let first_value = words.iter().rposition(|word| !is_value(word)).map_or(0, |at| at + 1);
    words[first_value..].iter().copied().filter(|&(start, end)| &line[start..end] != "|").collect()
}

/// The value that a test sets once as `field: value`.
fn field(source: &str, field: &str) -> Result<String, String> {
    let pattern = format!("{field}: ");
    let found: Vec<&str> = source
        .match_indices(&pattern)
        .map(|(at, _)| {
            let rest = &source[at + pattern.len()..];
            let end = rest.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(rest.len());
            &rest[..end]
        })
        .filter(|value| !value.is_empty())
        .collect();
    match found.as_slice() {
        [one] => Ok((*one).to_owned()),
        [] => Err(format!("no `{field}: <number>`")),
        _ => Err(format!("{} times `{field}: <number>`", found.len())),
    }
}

/// The text of the source a quote names.
fn source_text(source: &str) -> Result<String, String> {
    let path = if source.ends_with(".rs") {
        tests_dir().join(source)
    } else {
        let prefix = format!("{source}__");
        let mut matching: Vec<PathBuf> = std::fs::read_dir(tests_dir().join("snapshots"))
            .expect("the snapshots folder")
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(&prefix))
            })
            .collect();
        match matching.len() {
            1 => matching.remove(0),
            count => return Err(format!("{count} snapshots start with `{prefix}`, not one")),
        }
    };
    std::fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))
}

/// The value a quote names in the text of its source.
fn value_in(source: &str, text: &str, key: &str) -> Result<String, String> {
    if source.ends_with(".rs") {
        field(text, key)
    } else {
        let (row, column) =
            key.split_once(" / ").ok_or_else(|| format!("`{key}` is not `row / column`"))?;
        table_cell(text, row.trim(), column.trim())
    }
}

/// Whether `quoted` is `actual`, rounded to the digits that `quoted` gives.
fn agrees(quoted: &str, actual: &str) -> bool {
    let quoted = quoted.replace(',', "");
    let quoted = quoted.trim_end_matches('%');
    let Ok(actual) = actual.trim_end_matches('%').parse::<f64>() else {
        return false;
    };
    let digits = quoted.split_once('.').map_or(0, |(_, fraction)| fraction.len());
    format!("{actual:.digits$}") == quoted
}

#[test]
fn every_number_the_docs_quote_agrees_with_its_source() {
    let mut problems = Vec::new();
    let mut checked = 0;
    for doc in docs() {
        let text = std::fs::read_to_string(&doc).expect("a doc");
        let name = doc.strip_prefix(root()).unwrap_or(&doc).display().to_string();
        let found = match quotes(&text) {
            Ok(found) => found,
            Err(problem) => {
                problems.push(format!("{name}: {problem}"));
                continue;
            }
        };
        for quote in found {
            checked += 1;
            let actual =
                source_text(quote.source).and_then(|text| value_in(quote.source, &text, quote.key));
            match actual {
                Ok(actual) if agrees(quote.number, &actual) => {}
                Ok(actual) => problems.push(format!(
                    "{name}:{}: says {} but {} gives {actual} for `{}`",
                    quote.line, quote.number, quote.source, quote.key
                )),
                Err(problem) => problems.push(format!(
                    "{name}:{}: {} for `{}`: {problem}",
                    quote.line, quote.source, quote.key
                )),
            }
        }
    }
    assert!(problems.is_empty(), "numbers in the docs do not agree:\n{}", problems.join("\n"));
    assert!(checked > 0, "no doc quotes a number with a `{MARKER_START}` marker");
}

/// Lines of the locked snapshots, as they stood when this test was written.
const TABLES: &str = "\
---
source: hereticus/tests/truth_ubuntu.rs
expression: out
---
library                cases  right homo wrong  gone   new | in lib found inline ranks top1 top5
zlib1g arm64               1    118    0     0     0     0 |     1     1      0     1    1    1
all                      218 264955    0   129   240   313 |   193   193     52   365  163  187

kernel                                 right renamed unproven  twin homonym  wrong  wrong% at most
arm-ex6100v2 22.03.2/22.03.5           23009      10        2     7       0     23   0.10%   0.11%

releases                               right renamed unproven  twin homonym  wrong  wrong% at most
all                                   243104     960      518   698      64   2278   0.95%   1.15%

stage                                  right renamed unproven  twin homonym  wrong  wrong% at most
Similar                                59923     621      221     8      30    962   1.61%   1.96%
";

#[test]
fn a_cell_is_found_by_its_row_and_its_heading() {
    assert_eq!(table_cell(TABLES, "zlib1g arm64", "right"), Ok("118".to_owned()));
    assert_eq!(table_cell(TABLES, "all", "in lib"), Ok("193".to_owned()));
    assert_eq!(table_cell(TABLES, "all", "top1"), Ok("163".to_owned()));
    assert_eq!(table_cell(TABLES, "Similar", "wrong%"), Ok("1.61%".to_owned()));
    assert_eq!(
        table_cell(TABLES, "arm-ex6100v2 22.03.2/22.03.5", "at most"),
        Ok("0.11%".to_owned())
    );
    assert_eq!(table_cell(TABLES, "all", "cases"), Ok("218".to_owned()));
}

#[test]
fn each_value_of_the_locked_tables_has_its_own_heading() {
    for source in ["truth_kernels", "truth_ubuntu"] {
        let text = source_text(source).expect("a locked snapshot");
        let mut heading: Option<&str> = None;
        for line in text
            .lines()
            .skip_while(|line| *line != "---")
            .skip(1)
            .skip_while(|line| *line != "---")
            .skip(1)
        {
            if line.trim().is_empty() {
                heading = None;
                continue;
            }
            let Some(heading) = heading else {
                heading = Some(line);
                continue;
            };
            let labels = labels_of(heading, &values_of(line));
            let mut distinct = labels.clone();
            distinct.sort();
            distinct.dedup();
            assert!(
                !labels.iter().any(String::is_empty) && distinct.len() == labels.len(),
                "{source}: `{line}` gets the headings {labels:?}"
            );
        }
    }
}

#[test]
fn a_cell_that_is_missing_or_in_two_tables_is_an_error() {
    assert!(table_cell(TABLES, "zlib1g armhf", "right").is_err());
    assert!(table_cell(TABLES, "all", "lost").is_err());
    // The libraries and the releases both have a row `all` with a column `wrong`.
    assert!(table_cell(TABLES, "all", "wrong").is_err());
}

#[test]
fn a_field_must_be_set_once() {
    let source = "Recovery { functions: 46006, exact: 45937 }; let exact: u64 = 1;";
    assert_eq!(field(source, "functions"), Ok("46006".to_owned()));
    assert_eq!(field(source, "exact"), Ok("45937".to_owned()));
    assert!(field(source, "missed").is_err());
    assert!(field("a: 1, a: 2", "a").is_err());
}

#[test]
fn a_quote_takes_the_number_right_before_its_marker() {
    let text = "Wrong:\n0.95%<!-- from truth_kernels: all / wrong% --> and\n\
                45,937<!-- from boundaries.rs: exact -->.";
    assert_eq!(
        quotes(text),
        Ok(vec![
            Quote { line: 2, number: "0.95%", source: "truth_kernels", key: "all / wrong%" },
            Quote { line: 3, number: "45,937", source: "boundaries.rs", key: "exact" },
        ])
    );
    assert_eq!(quotes("No markers here. <!-- a plain comment -->"), Ok(Vec::new()));
    let example = "```markdown\n1<!-- from truth_kernels: all / wrong% -->\n```\n";
    assert_eq!(quotes(example), Ok(Vec::new()));
}

#[test]
fn a_malformed_quote_is_an_error() {
    assert!(quotes("word<!-- from truth_kernels: all / wrong% -->").is_err());
    assert!(quotes("1<!-- from truth_kernels all -->").is_err());
    assert!(quotes("1<!-- from truth_kernels: all / wrong%").is_err());
}

#[test]
fn a_quote_may_round_its_source() {
    assert!(agrees("7%", "6.98%"));
    assert!(agrees("1.4%", "1.39%"));
    assert!(agrees("0.95%", "0.95%"));
    assert!(agrees("45,937", "45937"));
    assert!(!agrees("151", "129"));
    assert!(!agrees("1.5%", "1.39%"));
    assert!(!agrees("7%", "not a number"));
}
