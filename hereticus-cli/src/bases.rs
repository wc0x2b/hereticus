//! The bases a raw image could load at, as `--find-base` lists them.
//!
//! A raw image holds the full addresses of its own strings and functions.
//! At the right base, many words point at the start of one; at any other,
//! few do. The table gives the evidence for each base, so a reader can see
//! how clearly the best one stands out, and the line after it gives the
//! base where one does.

use hereticus::obj::Isa;
use hereticus::raw::{BaseCandidate, rank_bases, suggest_base};
use tabled::settings::object::Columns;
use tabled::settings::style::HorizontalLine;
use tabled::settings::{Alignment, Style};
use tabled::{Table, Tabled};

use super::Format;

#[derive(Tabled)]
struct Row {
    #[tabled(rename = "BASE")]
    base: String,
    #[tabled(rename = "STRINGS")]
    strings: usize,
    #[tabled(rename = "FUNCTIONS")]
    functions: usize,
    #[tabled(rename = "BY CHANCE")]
    chance: String,
    #[tabled(rename = "EVIDENCE")]
    evidence: String,
}

impl From<&BaseCandidate> for Row {
    fn from(candidate: &BaseCandidate) -> Self {
        Self {
            base: format!("{:#x}", candidate.base),
            strings: candidate.strings,
            functions: candidate.functions,
            chance: format!("{:.0}", candidate.expected),
            evidence: evidence_of(candidate),
        }
    }
}

/// The hits above chance, or why a base has no evidence at all.
fn evidence_of(candidate: &BaseCandidate) -> String {
    if candidate.confined { "halves".to_string() } else { format!("{:.0}", candidate.excess()) }
}

/// The columns that hold numbers, which read better against the right edge.
const NUMBER_COLUMNS: core::ops::RangeInclusive<usize> = 1..=4;

/// Print the bases `data` could load at, the best first, and the base it
/// loads at where one stands out.
pub(crate) fn print_bases(data: &[u8], isa: Isa, format: Format) {
    let ranked = rank_bases(data, isa.arch());
    let found = suggest_base(data, isa.arch());
    match format {
        Format::Text => {
            if !ranked.is_empty() {
                let mut table = Table::new(ranked.iter().map(Row::from));
                table
                    .with(
                        Style::rounded()
                            .horizontals([(1, HorizontalLine::inherit(Style::modern_rounded()))]),
                    )
                    .with(Alignment::left())
                    .modify(Columns::new(NUMBER_COLUMNS), Alignment::right());
                println!("{table}");
                println!();
            }
            println!("{}", verdict(found));
        }
        Format::Compact => {
            for candidate in &ranked {
                let row = Row::from(candidate);
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    row.base, row.strings, row.functions, row.chance, row.evidence
                );
            }
        }
        Format::Markdown => {
            if !ranked.is_empty() {
                let mut table = Table::new(ranked.iter().map(Row::from));
                table.with(Style::markdown());
                println!("{table}");
                println!();
            }
            println!("{}", verdict(found));
        }
        Format::Json => println!("{}", json_bases(&ranked, found)),
    }
}

/// The line under the table: the base, or what to do where none stands out.
fn verdict(found: Option<u64>) -> String {
    match found {
        Some(base) => {
            format!("The image loads at {base:#x}. Give --base {base:#x} or --base auto.")
        }
        None => {
            "No base stands out, so give --base. See \"Find the Base\" in the book.".to_string()
        }
    }
}

/// The bases as one JSON object: the base where one stands out, else
/// `null`, and the evidence for each candidate.
fn json_bases(ranked: &[BaseCandidate], found: Option<u64>) -> String {
    let candidates: Vec<String> = ranked
        .iter()
        .map(|candidate| {
            format!(
                "{{\"base\":{},\"strings\":{},\"functions\":{},\"by_chance\":{:.1},\
                 \"evidence\":{:.1},\"halves\":{}}}",
                candidate.base,
                candidate.strings,
                candidate.functions,
                candidate.expected,
                candidate.excess(),
                candidate.confined,
            )
        })
        .collect();
    let base = found.map_or_else(|| "null".to_string(), |base| base.to_string());
    format!("{{\"base\":{base},\"candidates\":[{}]}}", candidates.join(","))
}
