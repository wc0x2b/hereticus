//! Measure how well stripped and raw functions pair across releases, and
//! whether every changed function is reported, with the symbols as the
//! answer.
//!
//! `just backports` also builds consecutive releases of zlib, Lua, expat
//! and tinyxml2, each with clang and with GCC at `-O2`, into
//! `fixtures/build/versions`. A new release changes many functions at once,
//! as a firmware update does, where a backport changes one.
//!
//! Each comparison counts, over the three architectures and both compilers:
//!
//! * `right` and `wrong`: pairs whose functions share a symbol, or not.
//! * `gone` and `new`: functions the matcher left unpaired.
//! * `missed`: functions that changed, as the comparison with symbols says,
//!   which no reported function covers. This is the count that matters most:
//!   a change the tool does not show is a change a reader never checks.
//!
//! The tallies are locked, so a change that moves them must update them here.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hereticus::matching::{Changed, Diff, Options, UseNames, diff_with};
use hereticus::obj::{Binary, Isa};
use object::{Object, ObjectSection};
use rstest::rstest;

/// How a build is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reading {
    Stripped,
    Raw,
}

/// What one comparison counts, summed over its builds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Tally {
    right: usize,
    wrong: usize,
    gone: usize,
    new: usize,
    missed: usize,
}

impl core::ops::AddAssign for Tally {
    fn add_assign(&mut self, other: Self) {
        self.right += other.right;
        self.wrong += other.wrong;
        self.gone += other.gone;
        self.new += other.new;
        self.missed += other.missed;
    }
}

fn versions() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/versions")
}

fn read_file(project: &str, version: &str, build: &str, file: &str) -> Vec<u8> {
    let path = versions().join(format!("{project}-{version}/{build}/{file}"));
    std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{}: {err}, run `just backports` first", path.display()))
}

fn parse(data: &[u8]) -> Binary {
    Binary::parse(data).expect("a fixture library must parse")
}

/// The raw image of a build, read at the address its first loaded section
/// sits at, as `llvm-objcopy -O binary` wrote it.
fn parse_raw(library: &[u8], image: &[u8], arch: &str) -> Binary {
    let file = object::File::parse(library).expect("a fixture library must parse");
    let base = file
        .sections()
        .filter(|section| {
            section.address() != 0
                && section.size() != 0
                && section.kind() != object::SectionKind::UninitializedData
        })
        .map(|section| section.address())
        .min()
        .expect("a library loads something");
    let isa = match arch {
        "arm" => Isa::Arm32,
        "thumb" => Isa::Thumb2,
        "aarch64" => Isa::Aarch64,
        "mips" => Isa::Mips32Be,
        _ => Isa::Mips32,
    };
    Binary::parse_raw(image, base, isa).expect("a raw image must read")
}

/// A symbol name without the suffix GCC gives a copy it specialized, as
/// `g_iofile.isra.0`: the copy is still that function.
fn function_name(symbol: &str) -> &str {
    [".isra.", ".constprop.", ".part.", ".cold"]
        .iter()
        .filter_map(|suffix| symbol.find(suffix))
        .min()
        .map_or(symbol, |end| &symbol[..end])
}

/// The functions whose symbols overlap function `index` of `binary`.
fn names_of(symbols: &Binary, binary: &Binary, index: usize) -> BTreeSet<String> {
    let function = &binary.functions[index];
    let range = function.address..function.address + function.code.len() as u64;
    symbols
        .functions
        .iter()
        .filter(|symbol| {
            symbol.address < range.end && symbol.address + symbol.code.len() as u64 > range.start
        })
        .map(|symbol| function_name(&symbol.name).to_owned())
        .collect()
}

/// The functions that changed, went or came, by the comparison with symbols.
fn changed_names(diff: &Diff, before: &Binary, after: &Binary) -> BTreeSet<String> {
    let name =
        |binary: &Binary, index: usize| function_name(&binary.functions[index].name).to_owned();
    diff.changed()
        .map(|pair| name(before, pair.before))
        .chain(diff.removed.iter().map(|&index| name(before, index)))
        .chain(diff.added.iter().map(|&index| name(after, index)))
        .collect()
}

/// Compare two releases of one build, read as `reading`, and count.
fn tally(project: &str, versions: [&str; 2], build: &str, reading: Reading) -> Tally {
    let arch = build.split('-').next().expect("a build names its architecture");
    let libraries = versions.map(|version| read_file(project, version, build, "lib.so"));
    let symbols = [parse(&libraries[0]), parse(&libraries[1])];
    let [before, after] = [0, 1].map(|side| match reading {
        Reading::Stripped => parse(&read_file(project, versions[side], build, "lib-stripped.so")),
        Reading::Raw => {
            parse_raw(&libraries[side], &read_file(project, versions[side], build, "lib.bin"), arch)
        }
    });

    let answer = diff_with(&symbols[0], &symbols[1], Options::default());
    let must_show = changed_names(&answer, &symbols[0], &symbols[1]);

    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    let mut tally = Tally { gone: diff.removed.len(), new: diff.added.len(), ..Tally::default() };
    for pair in &diff.matched {
        let (left, right) = (
            names_of(&symbols[0], &before, pair.before),
            names_of(&symbols[1], &after, pair.after),
        );
        // Code that no symbol covers, as a PLT stub, has no answer.
        if left.is_empty() || right.is_empty() {
            continue;
        }
        if left.is_disjoint(&right) {
            tally.wrong += 1;
        } else {
            tally.right += 1;
        }
    }

    let shown: BTreeSet<String> = diff
        .matched
        .iter()
        .filter(|pair| pair.changed != Changed::No)
        .flat_map(|pair| {
            names_of(&symbols[0], &before, pair.before).into_iter().chain(names_of(
                &symbols[1],
                &after,
                pair.after,
            ))
        })
        .chain(diff.removed.iter().flat_map(|&index| names_of(&symbols[0], &before, index)))
        .chain(diff.added.iter().flat_map(|&index| names_of(&symbols[1], &after, index)))
        .collect();
    tally.missed = must_show.difference(&shown).count();
    tally
}

/// Every architecture and compiler of one comparison, summed.
fn tally_all(project: &str, versions: [&str; 2], reading: Reading) -> Tally {
    let mut total = Tally::default();
    for arch in ["arm", "thumb", "aarch64", "mips", "mipsel"] {
        for level in ["O2", "gcc-O2"] {
            total += tally(project, versions, &format!("{arch}-{level}"), reading);
        }
    }
    total
}

#[rstest]
#[case::zlib_1_2_11("zlib", ["1.2.11", "1.2.12"], Tally { right: 1199, wrong: 5, gone: 47, new: 68, missed: 3 },
        Tally { right: 1176, wrong: 4, gone: 105, new: 124, missed: 0 })]
#[case::zlib_1_2_12("zlib", ["1.2.12", "1.2.13"], Tally { right: 1266, wrong: 0, gone: 3, new: 2, missed: 0 }, Tally { right: 1240, wrong: 3, gone: 9, new: 10, missed: 0 })]
#[case::zlib_1_2_13("zlib", ["1.2.13", "1.3"], Tally { right: 1268, wrong: 0, gone: 0, new: 0, missed: 0 }, Tally { right: 1244, wrong: 0, gone: 8, new: 11, missed: 0 })]
#[case::lua_5_1("lua", ["5.1.4", "5.1.5"], Tally { right: 4914, wrong: 0, gone: 10, new: 10, missed: 0 }, Tally { right: 4883, wrong: 0, gone: 14, new: 13, missed: 0 })]
#[case::lua_5_3("lua", ["5.3.5", "5.3.6"], Tally { right: 5693, wrong: 0, gone: 21, new: 22, missed: 0 },
        Tally { right: 5657, wrong: 2, gone: 71, new: 92, missed: 0 })]
#[case::tinyxml2_8("tinyxml2", ["8.0.0", "9.0.0"], Tally { right: 2294, wrong: 8, gone: 308, new: 346, missed: 0 },
        Tally { right: 2229, wrong: 6, gone: 429, new: 452, missed: 1 })]
#[case::tinyxml2_9("tinyxml2", ["9.0.0", "10.0.0"], Tally { right: 2622, wrong: 22, gone: 1, new: 26, missed: 0 }, Tally { right: 2546, wrong: 26, gone: 91, new: 109, missed: 0 })]
#[case::expat_2_4_4("expat", ["2.4.4", "2.4.5"], Tally { right: 2925, wrong: 0, gone: 14, new: 4, missed: 0 },
        Tally { right: 2857, wrong: 0, gone: 45, new: 37, missed: 0 })]
#[case::expat_2_4_8("expat", ["2.4.8", "2.4.9"], Tally { right: 2927, wrong: 2, gone: 0, new: 0, missed: 0 },
        Tally { right: 2859, wrong: 3, gone: 7, new: 10, missed: 0 })]
fn releases_pair_and_show_their_changes(
    #[case] project: &str,
    #[case] versions: [&str; 2],
    #[case] stripped: Tally,
    #[case] raw: Tally,
) {
    assert_eq!(
        [
            tally_all(project, versions, Reading::Stripped),
            tally_all(project, versions, Reading::Raw)
        ],
        [stripped, raw],
        "{project} {versions:?}, stripped then raw"
    );
}
