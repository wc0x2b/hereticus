//! Check the pairs of radiff2, Ghidra and this tool on the two garbled
//! releases of the Go fixture against the names that `garble reverse` gives
//! back, and lock the counts.
//!
//! `just rivals-go-pairs` runs `fixtures/rivals_go_pairs.sh`, which gives
//! shfmt 3.11.0 and 3.12.0, both garbled, of each build to radiff2 and to
//! Ghidra Version Tracking, and writes every pair of functions each makes.
//! This test pairs the same builds with this tool, as `tests/go_garbled.rs`
//! does, and judges every pair of each tool by the same rule: see
//! [`Verdict`].
//!
//! garble names each function anew in each release, so no tool can pair by
//! a name. Ghidra takes about half an hour over every build, so
//! `just quick-test` skips this test.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use hereticus::matching::{Options, UseNames, diff_with};
use hereticus::obj::Binary;
use rayon::prelude::*;

#[path = "common/garbled.rs"]
mod garbled;
use garbled::{Answer, NEWER, OLDER, Verdict, file, read};

/// The builds of `fixtures/go.sh`.
const BUILDS: [&str; 7] =
    ["amd64", "386", "arm64", "arm-7", "arm-5", "mips-softfloat", "mipsle-softfloat"];

/// A tool whose pairs this test judges.
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
}

/// The verdicts of the pairs of one tool on one build.
#[derive(Clone, Copy, Debug, Default)]
struct Tally {
    pairs: usize,
    right: usize,
    unproven: usize,
    wrong: usize,
}

impl Tally {
    fn add(&mut self, verdict: Verdict) {
        self.pairs += 1;
        match verdict {
            Verdict::Right => self.right += 1,
            Verdict::Unproven => self.unproven += 1,
            Verdict::Wrong => self.wrong += 1,
            Verdict::Unknown => {}
        }
    }
}

impl core::ops::AddAssign for Tally {
    fn add_assign(&mut self, other: Tally) {
        self.pairs += other.pairs;
        self.right += other.right;
        self.unproven += other.unproven;
        self.wrong += other.wrong;
    }
}

/// The starts of each pair of this tool, run as `tests/go_garbled.rs` runs
/// it.
fn hereticus_pairs(arch: &str) -> Vec<(u64, u64)> {
    let read_release = |release: &str| {
        let data = read(&file(release, arch, "bin"))
            .unwrap_or_else(|| panic!("{arch}: run `just fixtures` first"));
        Binary::parse(&data).expect("the build parses")
    };
    let (before, after) = (read_release(OLDER), read_release(NEWER));
    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    diff.matched
        .iter()
        .map(|pair| (before.functions[pair.before].address, after.functions[pair.after].address))
        .collect()
}

/// The pairs that `fixtures/rivals_go_pairs.sh` wrote for `tool`.
fn rival_pairs(tool: Tool, arch: &str) -> Vec<(u64, u64)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/build/rivals")
        .join(format!("{}-go-pairs", tool.name()))
        .join(format!("{arch}.json"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("{}: {err}, run `just rivals-go-pairs` first", path.display())
    });
    let report: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    report["pairs"]
        .as_array()
        .expect("the pairs are a list")
        .iter()
        .map(|pair| {
            let address = |at: usize| pair[at].as_u64().expect("an address");
            (address(0), address(1))
        })
        .collect()
}

fn measure(arch: &&str) -> BTreeMap<Tool, Tally> {
    let answer = Answer::of(arch);
    Tool::ALL
        .into_iter()
        .map(|tool| {
            let pairs = match tool {
                Tool::Hereticus => hereticus_pairs(arch),
                Tool::Radare2 | Tool::Ghidra => rival_pairs(tool, arch),
            };
            let mut tally = Tally::default();
            // A pointer to a Thumb function carries bit 0, though no build
            // here is Thumb; it is no part of where the code lies.
            pairs.into_iter().for_each(|(before, after)| {
                tally.add(answer.judge(before & !1, after & !1));
            });
            (tool, tally)
        })
        .collect()
}

fn row(out: &mut String, label: &str, tally: Tally) {
    let Tally { pairs, right, unproven, wrong } = tally;
    writeln!(out, "{label:28} {pairs:>6} {right:>6} {unproven:>8} {wrong:>6}").unwrap();
}

fn heading(out: &mut String, label: &str) {
    writeln!(out, "{label:28} {:>6} {:>6} {:>8} {:>6}", "pairs", "right", "unproven", "wrong")
        .unwrap();
}

#[test]
fn the_pairs_of_each_tool_on_garbled_go_are_locked() {
    let tallies: Vec<BTreeMap<Tool, Tally>> = BUILDS.par_iter().map(measure).collect();
    let mut out = String::new();
    heading(&mut out, "build");
    let mut all: BTreeMap<Tool, Tally> = BTreeMap::new();
    for (arch, tallies) in BUILDS.iter().zip(&tallies) {
        for (&tool, &tally) in tallies {
            row(&mut out, &format!("{arch} {}", tool.name()), tally);
            *all.entry(tool).or_default() += tally;
        }
    }
    out += "\n";
    heading(&mut out, "tool");
    for (tool, tally) in &all {
        row(&mut out, &format!("all {}", tool.name()), *tally);
    }
    insta::assert_snapshot!(out);
}
