//! The answer for the garbled builds of the Go fixture: the function table
//! of each build, with the names that `garble reverse` gives back, as
//! `fixtures/go.sh` writes it beside the build.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The release that the recovery and Ghidra counts read.
pub const NEWER: &str = "3.12.0";
/// The release before it, which the pairs compare with.
pub const OLDER: &str = "3.11.0";

pub fn build(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/go").join(name)
}

pub fn read(name: &str) -> Option<Vec<u8>> {
    std::fs::read(build(name)).ok()
}

/// The file of `release` built for `arch`, with `extension`.
pub fn file(release: &str, arch: &str, extension: &str) -> String {
    format!("shfmt-{release}-{arch}.{extension}")
}

/// Each function of the table of `release` for `arch`, by its start: its
/// end and its name.
pub fn table(release: &str, arch: &str) -> BTreeMap<u64, (u64, String)> {
    let text = std::fs::read_to_string(build(&file(release, arch, "truth")))
        .expect("`just fixtures` writes the truth beside each build");
    text.lines()
        .map(|line| {
            // A name can hold spaces, as a generic type does.
            let mut fields = line.splitn(3, ' ');
            let mut hex = || u64::from_str_radix(fields.next().expect("a field"), 16).unwrap();
            let (start, end) = (hex(), hex());
            (start, (end, fields.next().expect("a name").to_owned()))
        })
        .collect()
}

/// What the names say of one pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The two functions have the same name in the two tables.
    Right,
    /// The names cannot judge the pair, as a name that only one of the two
    /// tables holds: `garble reverse` gives back no name of some methods of
    /// `main`, and those differ in each release.
    Unproven,
    /// The two functions have different names, each of which the other
    /// release holds too.
    Wrong,
    /// Code that the table lists for no function has no answer.
    Unknown,
}

/// The tables of the two releases of one build.
pub struct Answer {
    tables: [BTreeMap<u64, (u64, String)>; 2],
    names: [BTreeSet<String>; 2],
}

impl Answer {
    pub fn of(arch: &str) -> Self {
        let tables = [table(OLDER, arch), table(NEWER, arch)];
        let names = tables.each_ref().map(|table| table.values().map(|(_, name)| name.clone()).collect());
        Self { tables, names }
    }

    /// The name of the function of the table of `side` that holds `address`.
    fn name_at(&self, side: usize, address: u64) -> Option<&str> {
        self.tables[side]
            .range(..=address)
            .next_back()
            .filter(|(_, (end, _))| address < *end)
            .map(|(_, (_, name))| name.as_str())
    }

    /// Judge the pair of the functions that hold `before` and `after`.
    pub fn judge(&self, before: u64, after: u64) -> Verdict {
        match (self.name_at(0, before), self.name_at(1, after)) {
            (Some(left), Some(right)) if left == right => Verdict::Right,
            (Some(left), Some(right))
                if !self.names[1].contains(left) || !self.names[0].contains(right) =>
            {
                Verdict::Unproven
            }
            (Some(_), Some(_)) => Verdict::Wrong,
            _ => Verdict::Unknown,
        }
    }
}
