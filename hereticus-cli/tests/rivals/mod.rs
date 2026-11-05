//! Score the report of this tool and of another diff tool on the same
//! backport pairs, against the functions each fix touched.
//!
//! `fixtures/rivals.sh` gives each stripped build of
//! `fixtures/rivals/builds.txt` to the other tool, and writes the rows that
//! tool reports, the lowest score first. This module runs `hereticus` on the
//! same pairs, as a user runs it, and names each row of each report by the
//! symbols of the unstripped build: a row names the symbol its function
//! starts in. A [`Setup`] says how the other tool ran, and on which copy of
//! the libraries.
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
//! order, so a reader of such a tool reads the rows of the fix first among
//! those of their score. That favours the other tool. This tool sorts its
//! rows itself, so a reader reads them as listed.
//!
//! The functions that must and may change are those of
//! `hereticus/tests/backports.rs`, which says why.

// Each test file compares with one tool, and thus uses one part of this.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

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

/// How the other tool ran, and on what, as the setups of
/// `fixtures/rivals.sh` say.
#[derive(Clone, Copy, Debug)]
pub enum Setup {
    /// Its default analysis, on the stripped libraries.
    Default,
    /// Its deepest analysis, on the stripped libraries.
    Deeper,
    /// Its default analysis, on copies of the stripped libraries with no
    /// symbol that the library defines. `hereticus` reads the same copies.
    Unnamed,
    /// Its default analysis, on the builds of
    /// `fixtures/rivals/crossed-builds.txt`, whose two sides are built by
    /// other compilers or at other levels.
    Crossed,
}

impl Setup {
    /// The part that `fixtures/rivals.sh` adds to the name of the folder of
    /// the other tool.
    fn suffix(self) -> &'static str {
        match self {
            Self::Default => "",
            Self::Deeper => "-deeper",
            Self::Unnamed => "-unnamed",
            Self::Crossed => "-crossed",
        }
    }
}

/// The other tool and its setup.
#[derive(Clone, Copy, Debug)]
pub struct Contender {
    pub rival: Rival,
    pub setup: Setup,
}

impl Contender {
    /// The folder of `fixtures/build/rivals` with its rows, which also names
    /// the tool in a table.
    fn directory(self) -> String {
        format!("{}{}", self.rival.directory(), self.setup.suffix())
    }
}

/// One backport build: the directories of `fixtures/build/backports`.
#[derive(Clone, Debug)]
pub struct Build {
    pub project: String,
    pub arch: String,
    /// The level of the build before the fix.
    pub level: String,
    /// The level of the build after the fix, where it is another: another
    /// compiler or optimization, as a vendor's next release can have.
    pub after_level: Option<String>,
}

impl Build {
    pub fn name(&self) -> String {
        let name = format!("{}-{}-{}", self.project, self.arch, self.level);
        match &self.after_level {
            Some(after) => format!("{name}-to-{after}"),
            None => name,
        }
    }

    pub fn file(&self, variant: Variant, file: &str) -> PathBuf {
        let level = match (variant, &self.after_level) {
            (Variant::After, Some(after)) => after,
            _ => &self.level,
        };
        fixtures()
            .join("build/backports")
            .join(format!("{}-{}", self.project, variant.directory()))
            .join(format!("{}-{level}", self.arch))
            .join(file)
    }

    /// The library of one side that both tools read in `setup`.
    pub fn library(&self, variant: Variant, setup: Setup) -> PathBuf {
        match setup {
            Setup::Default | Setup::Deeper | Setup::Crossed => {
                self.file(variant, "lib-stripped.so")
            }
            Setup::Unnamed => fixtures()
                .join("build/rivals/unnamed")
                .join(self.name())
                .join(format!("{}.so", variant.directory())),
        }
    }
}

/// Which side of the fix a build is.
#[derive(Clone, Copy, Debug)]
pub enum Variant {
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

/// The builds that `setup` reads: those of
/// `fixtures/rivals/crossed-builds.txt` for [`Setup::Crossed`], and those of
/// `fixtures/rivals/builds.txt` for the others.
pub fn builds(setup: Setup) -> Vec<Build> {
    let list = match setup {
        Setup::Crossed => include_str!("../../../fixtures/rivals/crossed-builds.txt"),
        Setup::Default | Setup::Deeper | Setup::Unnamed => {
            include_str!("../../../fixtures/rivals/builds.txt")
        }
    };
    list.lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (project, arch, level, after_level) = match fields[..] {
                [project, arch, level] => (project, arch, level, None),
                [project, arch, level, after] => (project, arch, level, Some(after.to_owned())),
                _ => panic!(
                    "builds.txt: {line:?} is not a project, an arch, a level and maybe the \
                     level after the fix"
                ),
            };
            Build {
                project: project.to_owned(),
                arch: arch.to_owned(),
                level: level.to_owned(),
                after_level,
            }
        })
        .collect()
}

/// One row of a report: the function before and after, where each side
/// links it. A gone function has no after, and a new one no before.
#[derive(Clone, Copy, Debug)]
pub struct Row {
    pub before: Option<u64>,
    pub after: Option<u64>,
    /// The score the other tool sorts by. This tool's rows have none, as
    /// their place is their rank.
    pub score: Option<f64>,
}

/// How a report places its rows.
#[derive(Clone, Copy, Debug)]
pub enum Order {
    /// The rows are read as listed.
    AsListed,
    /// The rows are read the lowest score first, and the rows with no score
    /// last. Among the rows of one score, the rows of the fix come first.
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

/// What one tool reports for one build, and how long it took.
pub struct Report {
    pub rows: Vec<Row>,
    pub seconds: f64,
}

/// What the other tool reports for `build`.
fn rival_report(contender: Contender, build: &Build) -> Report {
    let path =
        fixtures().join("build/rivals").join(contender.directory()).join(build.name() + ".json");
    rows_in(&path, contender.rival.recipe())
}

/// The rows that `fixtures/rivals.sh`, or a script like it, wrote to `path`.
/// `recipe` is the command that writes them.
pub fn rows_in(path: &Path, recipe: &str) -> Report {
    let report = read_json(path, recipe);
    let seconds = report["seconds"]
        .as_f64()
        .unwrap_or_else(|| panic!("{}: no seconds, run `{recipe}` again", path.display()));
    let rows = report["rows"]
        .as_array()
        .expect("the rows are a list")
        .iter()
        .map(|row| Row {
            before: address(&row["before"]),
            after: address(&row["after"]),
            score: row["score"].as_f64(),
        })
        .collect();
    Report { rows, seconds }
}

/// What this tool reports for `build`, run as a user runs it, on the
/// libraries of `setup`.
fn hereticus_report(build: &Build, setup: Setup) -> Report {
    hereticus_rows(&build.library(Variant::Before, setup), &build.library(Variant::After, setup))
}

/// What this tool reports for two files, run as a user runs it.
pub fn hereticus_rows(before: &Path, after: &Path) -> Report {
    let start = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_hereticus"))
        .args(["--progress", "never", "--format", "json"])
        .arg(before)
        .arg(after)
        .output()
        .expect("the tool runs");
    let seconds = start.elapsed().as_secs_f64();
    assert!(
        output.status.success(),
        "{} {}: {}",
        before.display(),
        after.display(),
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
    // A gone or a new row holds its function, with what else the report
    // says of it.
    let gone = list("gone").into_iter().map(|row| Row {
        before: address(&row["function"]["address"]),
        after: None,
        score: None,
    });
    let new = list("new").into_iter().map(|row| Row {
        before: None,
        after: address(&row["function"]["address"]),
        score: None,
    });
    Report { rows: pairs.chain(gone).chain(new).collect(), seconds }
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

/// The rows in the order a reader reads them: their index in `scores`.
/// `fix[at]` tells if the row `at` names a function the fix edits.
pub fn reading_order(scores: &[Option<f64>], fix: &[bool], order: Order) -> Vec<usize> {
    let mut rows: Vec<usize> = (0..scores.len()).collect();
    if let Order::ByScore = order {
        rows.sort_by(|&a, &b| {
            let unscored = |at: usize| scores[at].is_none();
            unscored(a)
                .cmp(&unscored(b))
                .then(scores[a].unwrap_or(0.0).total_cmp(&scores[b].unwrap_or(0.0)))
                .then(fix[b].cmp(&fix[a]))
                .then(a.cmp(&b))
        });
    }
    rows
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
    let scores: Vec<Option<f64>> = rows.iter().map(|row| row.score).collect();
    let fix: Vec<bool> = names.iter().map(|row| !row.is_disjoint(&must)).collect();
    let read: Vec<&BTreeSet<String>> =
        reading_order(&scores, &fix, order).into_iter().map(|at| &names[at]).collect();
    let rank = must
        .iter()
        .map(|function| read.iter().position(|row| row.contains(function)).map(|at| at + 1))
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
    /// The wall time of this tool on the build, in seconds.
    pub hereticus_seconds: f64,
    /// The wall time of the other tool, as `fixtures/rivals.sh` measured it.
    pub rival_seconds: f64,
}

/// Score both tools on every build.
pub fn contests(contender: Contender) -> Vec<Contest> {
    builds(contender.setup)
        .into_iter()
        .map(|build| {
            let symbols = Symbols::of(&build);
            let ours = hereticus_report(&build, contender.setup);
            let theirs = rival_report(contender, &build);
            Contest {
                hereticus: score(&build, &symbols, &ours.rows, Order::AsListed),
                rival: score(&build, &symbols, &theirs.rows, Order::ByScore),
                hereticus_seconds: ours.seconds,
                rival_seconds: theirs.seconds,
                build,
            }
        })
        .collect()
}

/// Whether [`losses`] counts a fix that the other tool ranks higher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ranks {
    /// This tool must rank each fix no lower than the other tool does.
    Checked,
    /// The snapshot locks the ranks, and a test does not check them, as
    /// where the other tool ranks some fixes higher.
    Locked,
}

/// Whether [`losses`] counts a build where this tool reports more extras.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Extras {
    /// This tool must report no more extras than the other tool does.
    Checked,
    /// The snapshot locks the extras, and a test does not check them, as
    /// where the copies of a setup give this tool rows that a real build
    /// would not.
    Locked,
}

/// Where this tool does worse than the other tool, one line each.
///
/// This tool must report every fix, rank it no lower than the other tool
/// does where `ranks` says so, and report no more extras where `extras`
/// says so.
pub fn losses(contests: &[Contest], ranks: Ranks, extras: Extras) -> Vec<String> {
    let mut losses = Vec::new();
    for contest in contests {
        let name = contest.build.name();
        let (ours, theirs) = (contest.hereticus, contest.rival);
        match (ours.rank, theirs.rank) {
            (None, _) => losses.push(format!("{name}: hereticus misses the fix")),
            (Some(ours), Some(theirs)) if ours > theirs && ranks == Ranks::Checked => {
                losses.push(format!("{name}: hereticus ranks the fix {ours}, the other {theirs}"))
            }
            _ => {}
        }
        if ours.extras > theirs.extras && extras == Extras::Checked {
            losses.push(format!(
                "{name}: hereticus reports {} extras, the other {}",
                ours.extras, theirs.extras
            ));
        }
    }
    losses
}

/// The builds where this tool does not report the fix, one line each.
pub fn misses(contests: &[Contest]) -> Vec<String> {
    contests
        .iter()
        .filter(|contest| contest.hereticus.rank.is_none())
        .map(|contest| format!("{}: hereticus misses the fix", contest.build.name()))
        .collect()
}

fn rank_text(rank: Option<usize>) -> String {
    rank.map_or_else(|| "-".to_owned(), |rank| rank.to_string())
}

/// The totals of both tools, and then the scores of each build, as tables.
pub fn table(contender: Contender, contests: &[Contest]) -> String {
    let other = contender.directory();
    let mut totals = format!(
        "{:16} {:>6} {:>5} {:>5} {:>6} {:>6}\n",
        "tool", "builds", "found", "first", "rows", "extras"
    );
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
        (other.as_str(), |contest: &Contest| contest.rival),
    ] {
        let (found, first, rows, extras) = total(pick);
        let builds = contests.len();
        writeln!(totals, "{tool:16} {builds:>6} {found:>5} {first:>5} {rows:>6} {extras:>6}")
            .unwrap();
    }

    let columns = ["rank", "rows", "extras"]
        .map(|column| {
            format!(" {:>22} {:>22}", format!("{column}:hereticus"), format!("{column}:{other}"))
        })
        .concat();
    let mut builds = format!("\n{:32}{columns}\n", "build");
    for contest in contests {
        let (ours, theirs) = (contest.hereticus, contest.rival);
        writeln!(
            builds,
            "{:32} {:>22} {:>22} {:>22} {:>22} {:>22} {:>22}",
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

/// The wall time of both tools on each build, and in all, as a table.
///
/// A time depends on the machine and on what else runs on it, so no
/// snapshot locks it. This tool runs in the test, while other tests run;
/// the other tool ran alone, in `fixtures/rivals.sh`.
pub fn times(contender: Contender, contests: &[Contest]) -> String {
    let other = contender.directory();
    let mut table = format!("{:32} {:>12} {:>12}\n", "build", "hereticus s", format!("{other} s"));
    for contest in contests {
        writeln!(
            table,
            "{:32} {:>12.3} {:>12.3}",
            contest.build.name(),
            contest.hereticus_seconds,
            contest.rival_seconds
        )
        .unwrap();
    }
    let ours: f64 = contests.iter().map(|contest| contest.hereticus_seconds).sum();
    let theirs: f64 = contests.iter().map(|contest| contest.rival_seconds).sum();
    writeln!(table, "{:32} {ours:>12.3} {theirs:>12.3}", "all").unwrap();
    table
}
