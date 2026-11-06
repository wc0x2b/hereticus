//! Compare where radiff2, Ghidra and this tool show the function that each
//! published fix of `real-life-reports/` edits, and lock the ranks.
//!
//! `just rivals-cves` gives the binaries of each fix of
//! `fixtures/rivals/cves.txt` to radiff2 and to Ghidra Version Tracking, as
//! `fixtures/rivals_cves.sh` says. This test runs this tool on the same
//! binaries, as a user runs it. The fixes and the function each edits are
//! those of `truth_cves.rs`, which this test reads, so the two cannot
//! disagree. A report shows the fix on the first row, in the order a reader
//! reads them, whose function of the earlier binary starts where the fixed
//! function does.
//!
//! The binaries of Apple come from IPSW files, and Ghidra takes about half
//! an hour over every fix, so `just quick-test` skips this test.

mod rivals;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use hereticus::obj::Binary;
use rivals::{Order, Report, reading_order};

/// A rank this low or lower puts the fix on the first screen of a report.
const FIRST_SCREEN: usize = 10;

/// A tool whose report this test scores.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Tool {
    Hereticus,
    Radare2,
    Ghidra,
}

impl Tool {
    const ALL: [Tool; 3] = [Tool::Hereticus, Tool::Radare2, Tool::Ghidra];

    fn name(self) -> &'static str {
        match self {
            Self::Hereticus => "hereticus",
            Self::Radare2 => "radare2",
            Self::Ghidra => "ghidra",
        }
    }

    fn order(self) -> Order {
        match self {
            Self::Hereticus => Order::AsListed,
            Self::Radare2 | Self::Ghidra => Order::ByScore,
        }
    }
}

/// A published fix, as `truth_cves.rs` lists it.
#[derive(Debug, PartialEq, Eq)]
struct Fix {
    name: String,
    before: String,
    after: String,
    /// The function of the earlier binary that the fix edits, as this tool
    /// names it: a name of a symbol, or `sub_` and its address.
    function: String,
}

/// The fixes of `truth_cves.rs`, read from its source: each `Fix` there
/// sets `name`, `before`, `after` and `function` on lines of their own.
fn fixes(source: &str) -> Vec<Fix> {
    let mut fields: BTreeMap<&str, String> = BTreeMap::new();
    let mut found = Vec::new();
    for line in source.lines().map(str::trim) {
        let Some((key, rest)) = line.split_once(": \"") else { continue };
        if !["name", "before", "after", "function"].contains(&key) {
            continue;
        }
        let value = rest.strip_suffix("\",").expect("a field ends with `\",`");
        fields.insert(key, value.to_owned());
        if key == "function" {
            let mut take = |key: &str| fields.remove(key).expect("each field of a fix is set");
            found.push(Fix {
                name: take("name"),
                before: take("before"),
                after: take("after"),
                function: take("function"),
            });
        }
    }
    found
}

fn cache() -> PathBuf {
    Path::new(&std::env::var("HOME").expect("HOME is set")).join(".cache")
}

/// The name `fixtures/rivals_cves.sh` gives the file of a fix: each run of
/// characters other than letters and digits as one `-`.
fn file_name(fix: &str) -> String {
    let mut name = String::new();
    for character in fix.chars() {
        match character.is_ascii_alphanumeric() {
            true => name.push(character),
            false if !name.ends_with('-') => name.push('-'),
            false => {}
        }
    }
    name
}

/// Where the function that `fix` edits starts in the earlier binary.
fn fixed_address(fix: &Fix) -> u64 {
    if let Some(hex) = fix.function.strip_prefix("sub_") {
        return u64::from_str_radix(hex, 16).expect("`sub_` and an address");
    }
    let data = std::fs::read(cache().join(&fix.before)).expect("the binary is cached");
    let binary = Binary::parse(&data).expect("the binary parses");
    let function = binary.functions.iter().find(|function| function.name == fix.function);
    function.unwrap_or_else(|| panic!("{}: no `{}`", fix.name, fix.function)).address
}

fn report(tool: Tool, fix: &Fix) -> Report {
    match tool {
        Tool::Hereticus => {
            rivals::hereticus_rows(&cache().join(&fix.before), &cache().join(&fix.after))
        }
        Tool::Radare2 | Tool::Ghidra => {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../fixtures/build/rivals")
                .join(format!("{}-cves", tool.name()))
                .join(format!("{}.json", file_name(&fix.name)));
            rivals::rows_in(&path, "just rivals-cves")
        }
    }
}

/// The score of one report of one fix.
#[derive(Clone, Copy, Debug, Default)]
struct Score {
    rank: Option<usize>,
    rows: usize,
}

fn score(report: &Report, address: u64, order: Order) -> Score {
    // A MIPS16e or a Thumb function starts at an address with bit 0 set.
    let fix: Vec<bool> = report
        .rows
        .iter()
        .map(|row| row.before.is_some_and(|at| at & !1 == address & !1))
        .collect();
    let scores: Vec<Option<f64>> = report.rows.iter().map(|row| row.score).collect();
    let rank = reading_order(&scores, &fix, order).into_iter().position(|at| fix[at]);
    Score { rank: rank.map(|place| place + 1), rows: report.rows.len() }
}

/// The sums of the scores of one tool over the fixes.
#[derive(Clone, Copy, Debug, Default)]
struct Tally {
    fixes: usize,
    found: usize,
    first: usize,
    first_screen: usize,
    rows: usize,
}

impl Tally {
    fn add(&mut self, score: Score) {
        self.fixes += 1;
        self.found += usize::from(score.rank.is_some());
        self.first += usize::from(score.rank == Some(1));
        self.first_screen += usize::from(score.rank.is_some_and(|rank| rank <= FIRST_SCREEN));
        self.rows += score.rows;
    }
}

fn rank_text(rank: Option<usize>) -> String {
    rank.map_or_else(|| "-".to_owned(), |rank| rank.to_string())
}

#[test]
fn the_rank_of_each_published_fix_in_each_tool_is_locked() {
    let listed: Vec<String> = include_str!("../../fixtures/rivals/cves.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split('|').next().map(str::to_owned))
        .collect();
    let fixes: Vec<Fix> = fixes(include_str!("truth_cves.rs"))
        .into_iter()
        .filter(|fix| listed.contains(&fix.name))
        .collect();
    assert_eq!(fixes.len(), listed.len(), "each fix of cves.txt is a fix of truth_cves.rs");

    let columns: String =
        Tool::ALL.iter().map(|tool| format!(" {:>14}", format!("rank:{}", tool.name()))).collect();
    let mut ranks = format!("{:40}{columns}\n", "fix");
    let mut all: BTreeMap<Tool, Tally> = BTreeMap::new();
    for fix in &fixes {
        let address = fixed_address(fix);
        write!(ranks, "{:40}", fix.name).unwrap();
        for tool in Tool::ALL {
            let score = score(&report(tool, fix), address, tool.order());
            write!(ranks, " {:>14}", rank_text(score.rank)).unwrap();
            all.entry(tool).or_default().add(score);
        }
        ranks.push('\n');
    }
    let mut totals = format!(
        "{:20} {:>5} {:>5} {:>5} {:>6} {:>7}\n",
        "tool", "fixes", "found", "first", "top10", "rows"
    );
    for (tool, tally) in &all {
        let Tally { fixes, found, first, first_screen, rows } = *tally;
        writeln!(
            totals,
            "{:20} {fixes:>5} {found:>5} {first:>5} {first_screen:>6} {rows:>7}",
            format!("all {}", tool.name())
        )
        .unwrap();
    }
    insta::assert_snapshot!(format!("{totals}\n{ranks}"));
}

#[test]
fn the_fixes_are_read_from_their_fields() {
    let source = r#"
        Fix {
            name: "CVE-1 a",
            before: "x/1",
            after: "x/2",
            function: "sub_10",
        },
        Fix {
            name: "CVE-2 b",
            before: "y/1",
            after: "y/2",
            function: "main",
        },
    "#;
    let found = fixes(source);
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].function, "sub_10");
    assert_eq!(found[1].name, "CVE-2 b");
    assert_eq!(found[1].after, "y/2");
}

#[test]
fn a_file_name_joins_each_run_of_other_characters_into_one_dash() {
    assert_eq!(file_name("CVE-2025-62526 ubusd MIPS16e BE"), "CVE-2025-62526-ubusd-MIPS16e-BE");
    assert_eq!(file_name("CVE-2020-7248 libubox A64"), "CVE-2020-7248-libubox-A64");
    assert_eq!(file_name(""), "");
}
