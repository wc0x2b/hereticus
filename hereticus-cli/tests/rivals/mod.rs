//! Score the report of this tool and of another diff tool on the same
//! backport pairs, against the functions each fix touched.
//!
//! `fixtures/rivals.sh` gives each stripped build of
//! `fixtures/rivals/builds.txt` to the other tool, and writes the rows that
//! tool reports, the lowest score first. This module runs `hereticus` on the
//! same pairs, as a user runs it, and names each row of each report by the
//! symbols of the unstripped build: a row names the symbol its function
//! starts in.
//!
//! Three numbers score one report of one build:
//!
//! * the **rank**: the last row a reader must read to see every function
//!   the fix edits, or none when a function the fix edits is not reported;
//! * the **rows**: how many rows the report holds;
//! * the **extras**: how many rows name no function that the fix edits or
//!   that may change with it.
//!
//! The other tools sort by a score, and rows with the same score have no
//! order, so such a row ranks as the first of its score. That favours the
//! other tool. This tool sorts its rows itself, so a row ranks where it is.
//!
//! The functions that must and may change are those of
//! `hereticus/tests/backports.rs`, which says why.

// Each test file compares with one tool, and thus uses one part of this.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use hereticus::obj::Binary;

/// A diff tool whose rows `fixtures/rivals.sh` writes.
#[derive(Clone, Copy, Debug)]
pub enum Rival {
    Radare2,
    Ghidra,
}

impl Rival {
    fn directory(self) -> &'static str {
        match self {
            Self::Radare2 => "radare2",
            Self::Ghidra => "ghidra",
        }
    }

    fn recipe(self) -> &'static str {
        match self {
            Self::Radare2 => "just rivals",
            Self::Ghidra => "just rivals-ghidra",
        }
    }
}

/// One backport build: the directories of `fixtures/build/backports`.
#[derive(Clone, Debug)]
pub struct Build {
    pub project: String,
    pub arch: String,
    pub level: String,
}

impl Build {
    pub fn name(&self) -> String {
        format!("{}-{}-{}", self.project, self.arch, self.level)
    }

    fn file(&self, variant: Variant, file: &str) -> PathBuf {
        fixtures()
            .join("build/backports")
            .join(format!("{}-{}", self.project, variant.directory()))
            .join(format!("{}-{}", self.arch, self.level))
            .join(file)
    }
}

/// Which side of the fix a build is.
#[derive(Clone, Copy, Debug)]
enum Variant {
    Before,
    After,
}

impl Variant {
    fn directory(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
        }
    }
}

/// Which symbols a name in a list stands for.
#[derive(Clone, Copy, Debug)]
enum Name {
    /// The symbol with this name.
    Exact(&'static str),
    /// Every symbol whose name holds this. A Rust symbol holds a hash of its
    /// crate, which differs for each target.
    Containing(&'static str),
}

impl Name {
    fn matches(self, symbol: &str) -> bool {
        match self {
            Self::Exact(name) => symbol == name,
            Self::Containing(part) => symbol.contains(part),
        }
    }
}

/// The functions each fix edits, as `hereticus/tests/backports.rs` lists
/// them.
fn must_change(project: &str) -> &'static [Name] {
    match project {
        "zlib" => &[Name::Exact("inflate")],
        "lua" => &[Name::Exact("luaZ_fill"), Name::Exact("luaZ_init")],
        "tinyxml2" => &[Name::Exact("_ZN8tinyxml27XMLNode9ParseDeepEPcPNS_7StrPairEPi")],
        "smallvec" => &[Name::Containing("E11insert_many")],
        _ => panic!("{project} is not a backport"),
    }
}

/// The functions that may change without being edited, or be new.
fn may_change(project: &str) -> &'static [Name] {
    match project {
        "zlib" | "tinyxml2" => &[],
        "lua" => {
            &[Name::Exact("lua_load"), Name::Exact("luaZ_read"), Name::Exact("luaZ_lookahead")]
        }
        "smallvec" => &[Name::Containing("E6insert")],
        _ => panic!("{project} is not a backport"),
    }
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures")
}

/// The builds of `fixtures/rivals/builds.txt`.
pub fn builds() -> Vec<Build> {
    include_str!("../../../fixtures/rivals/builds.txt")
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [project, arch, level] = fields[..] else {
                panic!("builds.txt: {line:?} is not a project, an arch and a level");
            };
            Build { project: project.to_owned(), arch: arch.to_owned(), level: level.to_owned() }
        })
        .collect()
}

/// One row of a report: the function before and after, where each side
/// links it. A gone function has no after, and a new one no before.
#[derive(Clone, Copy, Debug)]
struct Row {
    before: Option<u64>,
    after: Option<u64>,
    /// The score the other tool sorts by. This tool's rows have none, as
    /// their place is their rank.
    score: Option<f64>,
}

/// How a report places its rows.
#[derive(Clone, Copy, Debug)]
enum Order {
    /// Each row ranks where it is.
    AsListed,
    /// The rows are sorted by score, so a row ranks as the first of its
    /// score, and a row with no score as the first after every scored row.
    ByScore,
}

fn read_json(path: &Path, recipe: &str) -> serde_json::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("{}: {err}, run `{recipe}` first", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

fn address(value: &serde_json::Value) -> Option<u64> {
    value.as_u64()
}

/// The rows the other tool reports for `build`.
fn rival_rows(rival: Rival, build: &Build) -> Vec<Row> {
    let path = fixtures().join("build/rivals").join(rival.directory()).join(build.name() + ".json");
    let report = read_json(&path, rival.recipe());
    report["rows"]
        .as_array()
        .expect("the rows are a list")
        .iter()
        .map(|row| Row {
            before: address(&row["before"]),
            after: address(&row["after"]),
            score: row["score"].as_f64(),
        })
        .collect()
}

/// The rows this tool reports for `build`, run as a user runs it.
fn hereticus_rows(build: &Build) -> Vec<Row> {
    let output = Command::new(env!("CARGO_BIN_EXE_hereticus"))
        .args(["--progress", "never", "--format", "json"])
        .arg(build.file(Variant::Before, "lib-stripped.so"))
        .arg(build.file(Variant::After, "lib-stripped.so"))
        .output()
        .expect("the tool runs");
    assert!(
        output.status.success(),
        "{}: {}",
        build.name(),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the report is JSON");
    let list = |key: &str| report[key].as_array().expect("a list of the report").clone();

    let pairs = list("pairs").into_iter().map(|pair| Row {
        before: address(&pair["before"]["address"]),
        after: address(&pair["after"]["address"]),
        score: None,
    });
    let gone = list("gone").into_iter().map(|function| Row {
        before: address(&function["address"]),
        after: None,
        score: None,
    });
    let new = list("new").into_iter().map(|function| Row {
        before: None,
        after: address(&function["address"]),
        score: None,
    });
    pairs.chain(gone).chain(new).collect()
}

/// The symbols of each side of a build, which name the rows.
struct Symbols {
    before: Binary,
    after: Binary,
}

impl Symbols {
    fn of(build: &Build) -> Self {
        let parse = |variant| {
            let path = build.file(variant, "lib.so");
            let bytes = std::fs::read(&path).unwrap_or_else(|err| {
                panic!("{}: {err}, run `just backports` first", path.display())
            });
            Binary::parse(&bytes).expect("a fixture library must parse")
        };
        Self { before: parse(Variant::Before), after: parse(Variant::After) }
    }

    /// The symbols the function of a row starts in, on either side.
    fn names(&self, row: Row) -> BTreeSet<String> {
        fn starting_in(binary: &Binary, address: Option<u64>) -> impl Iterator<Item = String> {
            // A Thumb or MIPS16e entry can carry bit 0, which is no part of
            // where the code lies.
            let address = address.map(|address| address & !1);
            binary
                .functions
                .iter()
                .filter(move |symbol| {
                    address.is_some_and(|address| {
                        symbol.address <= address
                            && address < symbol.address + symbol.code.len() as u64
                    })
                })
                .map(|symbol| symbol.name.clone())
        }
        starting_in(&self.before, row.before).chain(starting_in(&self.after, row.after)).collect()
    }

    /// Every symbol of either side that one of `names` stands for.
    fn named(&self, names: &[Name], side: Side) -> BTreeSet<String> {
        let binaries = match side {
            Side::Before => vec![&self.before],
            Side::Either => vec![&self.before, &self.after],
        };
        binaries
            .into_iter()
            .flat_map(|binary| &binary.functions)
            .filter(|function| names.iter().any(|name| name.matches(&function.name)))
            .map(|function| function.name.clone())
            .collect()
    }
}

#[derive(Clone, Copy, Debug)]
enum Side {
    Before,
    Either,
}

/// The score of one report of one build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Score {
    /// None when a function the fix edits is not reported.
    pub rank: Option<usize>,
    pub rows: usize,
    pub extras: usize,
}

fn score(build: &Build, symbols: &Symbols, rows: &[Row], order: Order) -> Score {
    let must = symbols.named(must_change(&build.project), Side::Before);
    assert!(!must.is_empty(), "{}: no symbol is named as the fix", build.name());
    let allowed: BTreeSet<String> = symbols
        .named(must_change(&build.project), Side::Either)
        .union(&symbols.named(may_change(&build.project), Side::Either))
        .cloned()
        .collect();

    let names: Vec<BTreeSet<String>> = rows.iter().map(|&row| symbols.names(row)).collect();
    let rank_of = |at: usize| match order {
        Order::AsListed => at + 1,
        Order::ByScore => {
            let lower = |other: &Row| match (other.score, rows[at].score) {
                (Some(other), Some(this)) => other < this,
                (Some(_), None) => true,
                (None, _) => false,
            };
            1 + rows.iter().filter(|other| lower(other)).count()
        }
    };
    let rank = must
        .iter()
        .map(|function| names.iter().position(|row| row.contains(function)).map(rank_of))
        .collect::<Option<Vec<usize>>>()
        .map(|ranks| ranks.into_iter().max().expect("the fix names a function"));
    let extras = names.iter().filter(|row| row.is_disjoint(&allowed)).count();
    Score { rank, rows: rows.len(), extras }
}

/// The score of this tool and of the other tool on one build.
pub struct Contest {
    pub build: Build,
    pub hereticus: Score,
    pub rival: Score,
}

/// Score both tools on every build.
pub fn contests(rival: Rival) -> Vec<Contest> {
    builds()
        .into_iter()
        .map(|build| {
            let symbols = Symbols::of(&build);
            let hereticus = score(&build, &symbols, &hereticus_rows(&build), Order::AsListed);
            let rival = score(&build, &symbols, &rival_rows(rival, &build), Order::ByScore);
            Contest { build, hereticus, rival }
        })
        .collect()
}

/// Where this tool does worse than the other tool, one line each.
///
/// This tool must report every fix, rank it no lower than the other tool
/// does, and report no more extras.
pub fn losses(contests: &[Contest]) -> Vec<String> {
    let mut losses = Vec::new();
    for contest in contests {
        let name = contest.build.name();
        let (ours, theirs) = (contest.hereticus, contest.rival);
        match (ours.rank, theirs.rank) {
            (None, _) => losses.push(format!("{name}: hereticus misses the fix")),
            (Some(ours), Some(theirs)) if ours > theirs => {
                losses.push(format!("{name}: hereticus ranks the fix {ours}, the other {theirs}"))
            }
            _ => {}
        }
        if ours.extras > theirs.extras {
            losses.push(format!(
                "{name}: hereticus reports {} extras, the other {}",
                ours.extras, theirs.extras
            ));
        }
    }
    losses
}

fn rank_text(rank: Option<usize>) -> String {
    rank.map_or_else(|| "-".to_owned(), |rank| rank.to_string())
}

/// The totals of both tools, and then the scores of each build, as tables.
pub fn table(rival: Rival, contests: &[Contest]) -> String {
    let other = rival.directory();
    let mut totals =
        format!("{:10} {:>5} {:>5} {:>6} {:>6}\n", "tool", "found", "first", "rows", "extras");
    let total = |pick: fn(&Contest) -> Score| {
        let scores: Vec<Score> = contests.iter().map(pick).collect();
        let found = scores.iter().filter(|score| score.rank.is_some()).count();
        let first = scores.iter().filter(|score| score.rank == Some(1)).count();
        let rows: usize = scores.iter().map(|score| score.rows).sum();
        let extras: usize = scores.iter().map(|score| score.extras).sum();
        (found, first, rows, extras)
    };
    for (tool, pick) in [
        ("hereticus", (|contest: &Contest| contest.hereticus) as fn(&Contest) -> Score),
        (other, |contest: &Contest| contest.rival),
    ] {
        let (found, first, rows, extras) = total(pick);
        writeln!(totals, "{tool:10} {found:>5} {first:>5} {rows:>6} {extras:>6}").unwrap();
    }
    writeln!(totals, "{:10} {:>5}", "builds", contests.len()).unwrap();

    let columns = ["rank", "rows", "extras"]
        .map(|column| {
            format!(" {:>16} {:>16}", format!("{column}:hereticus"), format!("{column}:{other}"))
        })
        .concat();
    let mut builds = format!("\n{:24}{columns}\n", "build");
    for contest in contests {
        let (ours, theirs) = (contest.hereticus, contest.rival);
        writeln!(
            builds,
            "{:24} {:>16} {:>16} {:>16} {:>16} {:>16} {:>16}",
            contest.build.name(),
            rank_text(ours.rank),
            rank_text(theirs.rank),
            ours.rows,
            theirs.rows,
            ours.extras,
            theirs.extras
        )
        .unwrap();
    }
    totals + &builds
}
