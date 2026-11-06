//! Compare the reports of radiff2, Ghidra and this tool on the Ubuntu
//! security updates of `fixtures/ubuntu_cases.json`, and lock the scores.
//!
//! Each case is a pair of consecutive security releases of a C library for
//! Ubuntu 22.04, arm64 or armhf, with a published fix in between, as
//! `hereticus/tests/truth_ubuntu.rs` reads them. `just rivals-ubuntu` gives
//! each pair to radiff2 and to Ghidra, as `fixtures/rivals_ubuntu.sh` says,
//! and this test runs this tool on the same pairs, as a user runs it. All
//! three read the libraries as Ubuntu ships them, with the names of the
//! functions they export.
//!
//! The `-dbgsym` debug files name each row by the symbols that its function
//! starts in, each by the function it holds code of, as [`function_name`]
//! says. A function of the fix is one that the patches of the update
//! touched, a symbol of which both libraries hold, and whose normalized
//! instructions differ there, as an address in them does not count. A case counts where it
//! has a function of the fix. A patch can touch only a tool of the same
//! source, or change a function only where another inlines it, and then
//! the case does not count. For each tool and case:
//!
//! * the **rank** is the first row, in the order a reader reads them, that
//!   names a function of the fix, or whose function holds a copy of one
//!   that the compiler inlined, as the DWARF says, or none;
//! * the **rows** are how many rows the report holds.
//!
//! The other tools sort by a score, and a reader of such a tool reads the
//! rows of the fix first among those of their score, as `rivals/mod.rs`
//! says. A real update can change more than the fix: other patches, or code
//! that the fix inlines. So no count of rows the fix did not touch is
//! given.
//!
//! The inputs are about 800 MB, and Ghidra takes hours over every case, so
//! `just quick-test` skips this test.

#[path = "../../hereticus/tests/common/inlined.rs"]
mod inlined;
mod rivals;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use hereticus::norm::{NormInsn, normalize_body_in};
use hereticus::obj::Binary;
use hereticus::recovery::arch::decode_all;
use rivals::{Order, Report, Row, reading_order};

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

/// A function symbol of a debug file: start, end and name.
type Symbol = (u64, u64, String);

/// One security update, as `fixtures/ubuntu_cases.json` pins it.
struct Case {
    name: String,
    library: String,
    /// The library and its debug file, before and after.
    files: [[PathBuf; 2]; 2],
    /// The functions the patches of the update touched.
    fixes: BTreeSet<String>,
}

fn cache() -> PathBuf {
    Path::new(&std::env::var("HOME").expect("HOME is set")).join(".cache/hereticus-ubuntu-cve")
}

fn cases() -> Vec<Case> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/ubuntu_cases.json");
    let text = std::fs::read_to_string(&path).expect("the cases are in the tree");
    let cases: Vec<serde_json::Value> = serde_json::from_str(&text).expect("the cases are JSON");
    let string = |value: &serde_json::Value| value.as_str().expect("a string").to_owned();
    cases
        .iter()
        .map(|case| {
            let file = |side: usize, which: usize| {
                cache().join(string(&case["files"][side][which]["path"]))
            };
            let name = ["library", "arch", "before", "after"].map(|key| string(&case[key]));
            Case {
                name: name.join("-"),
                library: string(&case["library"]),
                files: [[file(0, 0), file(0, 1)], [file(1, 0), file(1, 1)]],
                fixes: case["fixes"].as_array().expect("a list").iter().map(string).collect(),
            }
        })
        .collect()
}

/// The function symbols of a debug file, sorted by their start. A Thumb
/// symbol has bit 0 set, which is no part of where its code lies.
fn debug_symbols(path: &Path) -> Vec<Symbol> {
    use object::{Object, ObjectSymbol, SymbolKind};
    let data = std::fs::read(path)
        .unwrap_or_else(|err| panic!("{}: {err}; run `just truth`", path.display()));
    let file = object::File::parse(&*data).expect("the debug file parses");
    let mut symbols: Vec<Symbol> = file
        .symbols()
        .filter(|symbol| symbol.kind() == SymbolKind::Text && symbol.size() > 0)
        .filter_map(|symbol| {
            let name = symbol.name().ok()?;
            // GNU ld names each veneer of the Cortex-A53 erratum 843419 by
            // where it sits, so one veneer has another name in each build.
            if name.starts_with("e843419@") {
                return None;
            }
            let start = symbol.address() & !1;
            Some((start, start + symbol.size(), name.to_owned()))
        })
        .collect();
    symbols.sort();
    symbols
}

/// The name of the function that a symbol holds code of. GCC names a part
/// or a copy of a function by a suffix, as `xmlXPathEvalExpr.part.0`, and
/// libxml2 names the copy it calls itself by `__internal_alias`.
fn function_name(symbol: &str) -> &str {
    [".part.", ".isra.", ".constprop.", ".lto_priv.", ".cold", "__internal_alias"]
        .iter()
        .filter_map(|suffix| symbol.find(suffix))
        .min()
        .map_or(symbol, |end| &symbol[..end])
}

/// The names of the functions that the symbols `address` lies in hold.
fn names_at(symbols: &[Symbol], address: Option<u64>) -> BTreeSet<&str> {
    let Some(address) = address.map(|address| address & !1) else { return BTreeSet::new() };
    symbols
        .iter()
        .take_while(|symbol| symbol.0 <= address)
        .filter(|symbol| address < symbol.1)
        .map(|symbol| function_name(&symbol.2))
        .collect()
}

/// The normalized instructions of the code of `binary` that `symbol`
/// covers, where one function of the scan holds them all.
fn body(binary: &Binary, symbol: &Symbol) -> Option<Vec<NormInsn>> {
    let function = binary.functions.iter().find(|function| {
        let start = function.address & !1;
        start <= symbol.0 && symbol.1 <= start + function.code.len() as u64
    })?;
    let from = usize::try_from(symbol.0 - (function.address & !1)).ok()?;
    let to = usize::try_from(symbol.1 - (function.address & !1)).ok()?;
    let code = &function.code[from..to];
    let arch = binary.isa_of(function).arch();
    let (insns, _) = decode_all(arch, code, symbol.0);
    Some(normalize_body_in(arch, code, &insns, &binary.addresses))
}

/// The functions the patches touched whose code changed: see the comment
/// of this file.
fn changed_fixes(case: &Case, symbols: &[Vec<Symbol>; 2]) -> BTreeSet<String> {
    let binaries = case.files.each_ref().map(|[library, _]| {
        let data = std::fs::read(library)
            .unwrap_or_else(|err| panic!("{}: {err}; run `just truth`", library.display()));
        Binary::parse(&data).expect("the library parses")
    });
    // Each symbol of a function, as a part and a copy of it each have one,
    // by the name of the symbol. A name that two symbols of one side hold,
    // as two static functions can, says nothing.
    let unique = |side: usize, fix: &str| -> BTreeMap<&str, &Symbol> {
        let mut named: BTreeMap<&str, Vec<&Symbol>> = BTreeMap::new();
        for symbol in symbols[side].iter().filter(|symbol| function_name(&symbol.2) == fix) {
            named.entry(symbol.2.as_str()).or_default().push(symbol);
        }
        named
            .into_iter()
            .filter(|(_, all)| all.len() == 1)
            .map(|(name, all)| (name, all[0]))
            .collect()
    };
    case.fixes
        .iter()
        .filter(|&fix| {
            let [before, after] = [0, 1].map(|side| unique(side, fix));
            before.iter().any(|(name, symbol)| {
                after
                    .get(name)
                    .is_some_and(|other| body(&binaries[0], symbol) != body(&binaries[1], other))
            })
        })
        .cloned()
        .collect()
}

/// The score of one report of one case.
#[derive(Clone, Copy, Debug, Default)]
struct Score {
    rank: Option<usize>,
    rows: usize,
}

/// What the debug files of one case say: the symbols of each side, and the
/// inlined copies of functions; and the functions the patches touched.
struct Answer {
    symbols: [Vec<Symbol>; 2],
    copies: [Vec<Symbol>; 2],
    /// A function that the compiler inlined into every caller keeps no
    /// symbol of its own, so its code can change only in its callers, as
    /// `Curl_http_cookies` of libcurl does inside `Curl_http`. A copy of any
    /// function the patches touched thus counts.
    touched: BTreeSet<String>,
}

impl Answer {
    /// Whether the function that `address` lies in on `side` is a function
    /// of the fix, or holds an inlined copy of a function the patches
    /// touched.
    fn holds_fix(&self, side: usize, address: Option<u64>, fixes: &BTreeSet<String>) -> bool {
        let Some(address) = address.map(|address| address & !1) else { return false };
        let containing = self.symbols[side]
            .iter()
            .take_while(|symbol| symbol.0 <= address)
            .filter(|symbol| address < symbol.1);
        containing.into_iter().any(|symbol| {
            fixes.contains(function_name(&symbol.2))
                || self.copies[side].iter().any(|copy| {
                    copy.0 < symbol.1
                        && symbol.0 < copy.1
                        && self.touched.contains(function_name(&copy.2))
                })
        })
    }
}

fn score(rows: &[Row], answer: &Answer, fixes: &BTreeSet<String>, order: Order) -> Score {
    let fix: Vec<bool> = rows
        .iter()
        .map(|row| answer.holds_fix(0, row.before, fixes) || answer.holds_fix(1, row.after, fixes))
        .collect();
    let scores: Vec<Option<f64>> = rows.iter().map(|row| row.score).collect();
    let rank = reading_order(&scores, &fix, order)
        .into_iter()
        .position(|at| fix[at])
        .map(|place| place + 1);
    Score { rank, rows: rows.len() }
}

fn report(tool: Tool, case: &Case) -> Report {
    match tool {
        Tool::Hereticus => rivals::hereticus_rows(&case.files[0][0], &case.files[1][0]),
        Tool::Radare2 | Tool::Ghidra => {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../fixtures/build/rivals")
                .join(format!("{}-ubuntu", tool.name()))
                .join(format!("{}.json", case.name));
            rivals::rows_in(&path, "just rivals-ubuntu")
        }
    }
}

/// The sums of the scores of one tool over some cases.
#[derive(Clone, Copy, Debug, Default)]
struct Tally {
    cases: usize,
    found: usize,
    first: usize,
    first_screen: usize,
    rows: usize,
}

impl Tally {
    fn add(&mut self, score: Score) {
        self.cases += 1;
        self.found += usize::from(score.rank.is_some());
        self.first += usize::from(score.rank == Some(1));
        self.first_screen += usize::from(score.rank.is_some_and(|rank| rank <= FIRST_SCREEN));
        self.rows += score.rows;
    }
}

fn row(out: &mut String, label: &str, tally: Tally) {
    let Tally { cases, found, first, first_screen, rows } = tally;
    writeln!(out, "{label:26} {cases:>5} {found:>5} {first:>5} {first_screen:>6} {rows:>7}")
        .unwrap();
}

fn heading(out: &mut String, label: &str) {
    writeln!(
        out,
        "{label:26} {:>5} {:>5} {:>5} {:>6} {:>7}",
        "cases", "found", "first", "top10", "rows"
    )
    .unwrap();
}

#[test]
fn the_scores_on_the_ubuntu_updates_are_locked() {
    let mut by_library: BTreeMap<(String, Tool), Tally> = BTreeMap::new();
    let mut all: BTreeMap<Tool, Tally> = BTreeMap::new();
    let mut found_by_none = 0;
    // The cases where another tool shows the fix on an earlier row than
    // this tool, or shows it where this tool does not.
    let mut earlier: BTreeMap<Tool, usize> = BTreeMap::new();
    // The rank of each tool in each case where another tool shows the fix
    // earlier than this tool.
    let mut behind: Vec<(String, Vec<Option<usize>>)> = Vec::new();
    // The cases where this tool shows the fix earlier than another tool.
    let mut ours_earlier: BTreeMap<Tool, usize> = BTreeMap::new();
    for case in cases() {
        let symbols = [debug_symbols(&case.files[0][1]), debug_symbols(&case.files[1][1])];
        let fixes = changed_fixes(&case, &symbols);
        if fixes.is_empty() {
            continue;
        }
        let copies = case.files.each_ref().map(|[_, debug]| inlined::inlined_copies(debug));
        let answer = Answer { symbols, copies, touched: case.fixes.clone() };
        let scores: Vec<(Tool, Score)> = Tool::ALL
            .into_iter()
            .map(|tool| {
                let rows = report(tool, &case).rows;
                (tool, score(&rows, &answer, &fixes, tool.order()))
            })
            .collect();
        found_by_none += usize::from(scores.iter().all(|(_, score)| score.rank.is_none()));
        let ours = scores[0].1.rank;
        for &(tool, score) in &scores[1..] {
            let better = match (score.rank, ours) {
                (Some(theirs), Some(ours)) => theirs < ours,
                (Some(_), None) => true,
                (None, _) => false,
            };
            let worse = match (score.rank, ours) {
                (Some(theirs), Some(ours)) => ours < theirs,
                (None, Some(_)) => true,
                (_, None) => false,
            };
            *ours_earlier.entry(tool).or_default() += usize::from(worse);
            *earlier.entry(tool).or_default() += usize::from(better);
            if better && behind.last().is_none_or(|(name, _)| *name != case.name) {
                behind.push((
                    case.name.clone(),
                    scores.iter().map(|(_, score)| score.rank).collect(),
                ));
            }
        }
        for (tool, score) in scores {
            by_library.entry((case.library.clone(), tool)).or_default().add(score);
            all.entry(tool).or_default().add(score);
        }
    }

    let mut out = String::new();
    heading(&mut out, "library");
    for ((library, tool), tally) in &by_library {
        row(&mut out, &format!("{library} {}", tool.name()), *tally);
    }
    out += "\n";
    heading(&mut out, "tool");
    for (tool, tally) in &all {
        row(&mut out, &format!("all {}", tool.name()), *tally);
    }
    // How often each tool shows the fix on an earlier row than the other.
    writeln!(out, "\n{:26} {:>17} {:>13}", "rival", "hereticus-earlier", "rival-earlier").unwrap();
    for (tool, &ours) in &ours_earlier {
        let theirs = earlier.get(tool).copied().unwrap_or(0);
        writeln!(out, "{:26} {ours:>17} {theirs:>13}", tool.name()).unwrap();
    }
    writeln!(out, "\nfound by none: {found_by_none}").unwrap();
    // The cases where another tool shows the fix earlier, to look at.
    let columns: String =
        Tool::ALL.iter().map(|tool| format!(" {:>14}", format!("rank:{}", tool.name()))).collect();
    writeln!(out, "\n{:64}{columns}", "behind").unwrap();
    for (name, ranks) in &behind {
        let ranks: String = ranks
            .iter()
            .map(|rank| format!(" {:>14}", rank.map_or("-".to_owned(), |rank| rank.to_string())))
            .collect();
        writeln!(out, "{name:64}{ranks}").unwrap();
    }
    insta::assert_snapshot!(out);
}

#[test]
fn a_row_names_the_symbols_its_address_lies_in() {
    let symbols = vec![(0x100, 0x140, "a".to_owned()), (0x140, 0x150, "b".to_owned())];
    assert_eq!(names_at(&symbols, Some(0x120)), BTreeSet::from(["a"]));
    assert_eq!(names_at(&symbols, Some(0x141)), BTreeSet::from(["b"]));
    assert_eq!(names_at(&symbols, Some(0x150)), BTreeSet::new());
    assert_eq!(names_at(&symbols, None), BTreeSet::new());
}

#[test]
fn the_rank_is_the_first_row_of_a_fix_as_read() {
    let side = vec![(0x100, 0x110, "fix".to_owned()), (0x200, 0x210, "other".to_owned())];
    let symbols = Answer {
        symbols: [side.clone(), side.clone()],
        copies: [vec![], vec![]],
        touched: BTreeSet::new(),
    };
    let fixes = BTreeSet::from(["fix".to_owned()]);
    let rows = [
        Row { before: Some(0x200), after: Some(0x200), score: Some(0.5) },
        Row { before: Some(0x100), after: Some(0x100), score: Some(0.9) },
    ];
    assert_eq!(score(&rows, &symbols, &fixes, Order::AsListed).rank, Some(2));
    assert_eq!(score(&rows, &symbols, &fixes, Order::ByScore).rank, Some(2));
    let gone = [Row { before: Some(0x100), after: None, score: None }];
    assert_eq!(score(&gone, &symbols, &fixes, Order::ByScore).rank, Some(1));
    assert_eq!(score(&[], &symbols, &fixes, Order::AsListed).rank, None);

    // A function that holds an inlined copy of the fix shows it too.
    let copies = vec![(0x204, 0x208, "fix.part.0".to_owned())];
    let inlined = Answer {
        symbols: [side.clone(), side],
        copies: [copies.clone(), copies],
        touched: fixes.clone(),
    };
    assert_eq!(score(&rows, &inlined, &fixes, Order::AsListed).rank, Some(1));
}
