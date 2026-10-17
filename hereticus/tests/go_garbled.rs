//! Measure how well the functions of garbled Go are recovered and paired,
//! with the function table of each build as the answer.
//!
//! Go malware is obfuscated, mostly with garble, so every Go fixture is
//! built so too: `fixtures/go.sh` builds two releases of shfmt for each
//! architecture. garble strips the symbols, scrambles the names, and hides
//! the function table of Go behind a magic number of its own, so Ghidra
//! reads none of it and the scan reads the code alone. The table itself is
//! still the one the runtime reads, so `fixtures/go/pcln` reads it with the
//! usual magic put back, `garble reverse` gives back its names, and the
//! answer is written beside each build.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hereticus::matching::{Options, UseNames, diff_with};
use hereticus::obj::Binary;
use object::{Object, ObjectSection};

/// The magic number of the function table of Go 1.20 and later.
const PCLNTAB_MAGIC: u32 = 0xffff_fff1;

/// What recovery found in one build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Recovery {
    /// Functions of the function table.
    functions: usize,
    /// Functions found with the same start and end, padding left out.
    exact: usize,
    /// Starts found where no function of the table starts.
    invented: usize,
    /// Starts of the table not found.
    missed: usize,
}

fn build(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/go").join(name)
}

fn read(name: &str) -> Option<Vec<u8>> {
    std::fs::read(build(name)).ok()
}

/// The release that the recovery and Ghidra counts read.
const NEWER: &str = "3.12.0";
/// The release before it, which the pairs compare with.
const OLDER: &str = "3.11.0";

/// The file of `release` built for `arch`, with `extension`.
fn file(release: &str, arch: &str, extension: &str) -> String {
    format!("shfmt-{release}-{arch}.{extension}")
}

/// Each function of the table of `release` for `arch`, by its start: its
/// end and its name.
fn table(release: &str, arch: &str) -> BTreeMap<u64, (u64, String)> {
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

/// Each function of the table of the newer release, by its start, to its
/// end.
fn truth(arch: &str) -> BTreeMap<u64, u64> {
    table(NEWER, arch).into_iter().map(|(start, (end, _))| (start, end)).collect()
}

fn recovery_of(arch: &str) -> Recovery {
    let data = read(&file(NEWER, arch, "bin")).expect("the build exists");
    let binary = Binary::parse(&data).expect("the build parses");
    let file = object::File::parse(data.as_slice()).expect("the build parses");
    let truth = truth(arch);
    let (low, high) =
        (*truth.keys().next().expect("a function"), *truth.values().max().expect("a function"));

    // Go counts the padding after a function in its end, and the scan
    // leaves padding out, so the true end is read without it.
    let text = file.section_by_name(".text").expect("Go code has .text");
    let code = text.data().expect("the code reads");
    let middle = &binary.functions[binary.functions.len() / 2];
    let arch_rules = binary.isa_of(middle).arch();
    let true_end = |start: u64, end: u64| {
        let offset = |address: u64| (address - text.address()) as usize;
        start + arch_rules.trim_padding(&code[offset(start)..offset(end)]).len() as u64
    };

    let found: BTreeMap<u64, u64> = binary
        .functions
        .iter()
        .filter(|function| (low..high).contains(&function.address))
        .map(|function| (function.address, function.address + function.code.len() as u64))
        .collect();
    Recovery {
        functions: truth.len(),
        exact: truth
            .iter()
            .filter(|&(start, end)| found.get(start) == Some(&true_end(*start, *end)))
            .count(),
        invented: found.keys().filter(|start| !truth.contains_key(start)).count(),
        missed: truth.keys().filter(|start| !found.contains_key(start)).count(),
    }
}

/// Each build is garbled: no symbol table, and a function table that the
/// usual magic does not open.
#[rstest::rstest]
fn each_build_is_garbled(
    #[values("amd64", "386", "arm64", "arm-7", "arm-5", "mips-softfloat", "mipsle-softfloat")]
    arch: &str,
) {
    let Some(data) = read(&file(NEWER, arch, "bin")) else {
        eprintln!("skipped: run `just fixtures` first");
        return;
    };
    let file = object::File::parse(data.as_slice()).expect("the build parses");
    assert!(file.section_by_name(".symtab").is_none(), "{arch} keeps its symbols");
    let table = file.section_by_name(".gopclntab").expect("Go keeps its function table");
    let bytes: [u8; 4] = table.data().unwrap()[..4].try_into().unwrap();
    let magic = match file.is_little_endian() {
        true => u32::from_le_bytes(bytes),
        false => u32::from_be_bytes(bytes),
    };
    assert_ne!(magic, PCLNTAB_MAGIC, "{arch} shows the usual magic");
}

#[rstest::rstest]
#[case::amd64("amd64", Recovery { functions: 3635, exact: 3572, invented: 51, missed: 11 })]
#[case::i386("386", Recovery { functions: 3679, exact: 3669, invented: 49, missed: 5 })]
#[case::arm64("arm64", Recovery { functions: 3594, exact: 3511, invented: 21, missed: 40 })]
#[case::armv7("arm-7", Recovery { functions: 3672, exact: 3521, invented: 51, missed: 75 })]
#[case::armv5("arm-5", Recovery { functions: 3703, exact: 3558, invented: 54, missed: 71 })]
#[case::mips("mips-softfloat", Recovery { functions: 3579, exact: 3391, invented: 57, missed: 88 })]
#[case::mipsle("mipsle-softfloat", Recovery { functions: 3579, exact: 3390, invented: 58, missed: 88 })]
fn garbled_go_functions_are_recovered(#[case] arch: &str, #[case] expected: Recovery) {
    if read(&file(NEWER, arch, "bin")).is_none() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }
    assert_eq!(recovery_of(arch), expected, "{arch}");
}

/// The garbled builds, as `fixtures/go.sh` names them.
const BUILDS: &[&str] =
    &["amd64", "386", "arm64", "arm-7", "arm-5", "mips-softfloat", "mipsle-softfloat"];

/// The starts that this tool and Ghidra find in each garbled build, against
/// the function table: found, real, not real, and real ones missed.
///
/// `just rivals-go` lets Ghidra analyse each build with its default
/// analyzers. Its Go analyzer reads no table it cannot find, so Ghidra
/// reads the code alone too. Ghidra loads the little-endian MIPS build as
/// 64-bit MIPS32r6, which its ELF header does not say, and so finds little
/// there.
#[test]
fn the_starts_against_ghidra_are_locked() {
    use std::collections::BTreeSet;
    use std::fmt::Write as _;

    let ghidra = |name: &str| {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/build/rivals/ghidra-go")
            .join(file(NEWER, name, "txt"));
        std::fs::read_to_string(path).ok()
    };
    if BUILDS.iter().any(|name| read(&file(NEWER, name, "bin")).is_none() || ghidra(name).is_none())
    {
        eprintln!("skipped: run `just rivals-go` first");
        return;
    }
    // A row is named `<build> <tool>`, as the docs quote it.
    let mut out = format!(
        "{:26} {:>6} {:>6} {:>8} {:>6}\n",
        "build and tool", "found", "real", "not real", "missed"
    );
    for name in BUILDS {
        let truth = truth(name);
        let real: BTreeSet<u64> = truth.keys().copied().collect();
        let range = *truth.keys().next().unwrap()..*truth.values().max().unwrap();
        let data = read(&file(NEWER, name, "bin")).unwrap();
        let binary = Binary::parse(&data).expect("the build parses");
        let ours: BTreeSet<u64> = binary
            .functions
            .iter()
            .map(|function| function.address)
            .filter(|address| range.contains(address))
            .collect();
        let theirs: BTreeSet<u64> = ghidra(name)
            .unwrap()
            .lines()
            .map(|line| u64::from_str_radix(line, 16).expect("a hexadecimal entry"))
            .filter(|address| range.contains(address))
            .collect();
        for (tool, starts) in [("hereticus", &ours), ("ghidra", &theirs)] {
            writeln!(
                out,
                "{:26} {:>6} {:>6} {:>8} {:>6}",
                format!("{name} {tool}"),
                starts.len(),
                starts.intersection(&real).count(),
                starts.difference(&real).count(),
                real.difference(starts).count()
            )
            .unwrap();
        }
    }
    insta::assert_snapshot!(out);
}

/// What comparing the two releases of one build counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pairs {
    /// Pairs whose functions have the same name in the two tables.
    right: usize,
    /// Pairs whose names cannot judge them, as a name that only one of the
    /// two tables holds: `garble reverse` gives back no name of some
    /// methods of `main`, and those differ in each release.
    unproven: usize,
    /// Pairs whose functions have different names, each of which the other
    /// release holds too.
    wrong: usize,
    /// Functions of the older release left unpaired.
    gone: usize,
    /// Functions of the newer release left unpaired.
    new: usize,
}

fn pairs_of(arch: &str) -> Pairs {
    let read_release = |release: &str| {
        let data = read(&file(release, arch, "bin")).expect("the build exists");
        Binary::parse(&data).expect("the build parses")
    };
    let (before, after) = (read_release(OLDER), read_release(NEWER));
    let (old_table, new_table) = (table(OLDER, arch), table(NEWER, arch));
    // The name of the function of `table` that holds `address`.
    let name_at = |table: &BTreeMap<u64, (u64, String)>, address: u64| {
        table
            .range(..=address)
            .next_back()
            .filter(|(_, (end, _))| address < *end)
            .map(|(_, (_, name))| name.clone())
    };
    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    let names = |table: &BTreeMap<u64, (u64, String)>| -> std::collections::BTreeSet<String> {
        table.values().map(|(_, name)| name.clone()).collect()
    };
    let (old_names, new_names) = (names(&old_table), names(&new_table));
    let mut pairs =
        Pairs { right: 0, unproven: 0, wrong: 0, gone: diff.removed.len(), new: diff.added.len() };
    for pair in &diff.matched {
        let names = (
            name_at(&old_table, before.functions[pair.before].address),
            name_at(&new_table, after.functions[pair.after].address),
        );
        match names {
            (Some(left), Some(right)) if left == right => pairs.right += 1,
            (Some(left), Some(right))
                if !new_names.contains(&left) || !old_names.contains(&right) =>
            {
                pairs.unproven += 1
            }
            (Some(_), Some(_)) => pairs.wrong += 1,
            // Code that the table lists for no function has no answer.
            _ => {}
        }
    }
    pairs
}

/// Two releases of garbled shfmt pair by their code alone: garble names
/// each function anew in each release, so no name is the same.
#[rstest::rstest]
#[case::amd64("amd64", Pairs { right: 3668, unproven: 4, wrong: 2, gone: 2, new: 1 })]
#[case::i386("386", Pairs { right: 3717, unproven: 4, wrong: 2, gone: 0, new: 0 })]
#[case::arm64("arm64", Pairs { right: 3569, unproven: 4, wrong: 1, gone: 1, new: 1 })]
#[case::armv7("arm-7", Pairs { right: 3640, unproven: 4, wrong: 4, gone: 0, new: 0 })]
#[case::armv5("arm-5", Pairs { right: 3682, unproven: 4, wrong: 0, gone: 0, new: 0 })]
#[case::mips("mips-softfloat", Pairs { right: 3541, unproven: 4, wrong: 3, gone: 0, new: 0 })]
#[case::mipsle("mipsle-softfloat", Pairs { right: 3544, unproven: 4, wrong: 0, gone: 0, new: 1 })]
fn garbled_go_releases_pair(#[case] arch: &str, #[case] expected: Pairs) {
    if read(&file(OLDER, arch, "bin")).is_none() || read(&file(NEWER, arch, "bin")).is_none() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }
    assert_eq!(pairs_of(arch), expected, "{arch}");
}
