//! Check the comparison against the functions a real fix touched.
//!
//! `just backports` builds each project twice, from the pristine release and
//! with one upstream fix on top, as a vendor ships a backport. Unlike the
//! OpenWrt tests, these know the right answer: the functions the fix edits.
//!
//! | Project | Fix | Must change | May change |
//! |---|---|---|---|
//! | zlib 1.2.12 | CVE-2022-37434 | `inflate` | none |
//! | Lua 5.1.5 | bug 2 | `luaZ_fill`, `luaZ_init` | `lua_load`, `luaZ_read`, `luaZ_lookahead` |
//! | tinyxml2 9.0.0 | `ParseDeep` frees a node by its document | `XMLNode::ParseDeep` | none |
//! | smallvec 1.6.0 | CVE-2021-25900 | every `insert_many` | a new `insert` |
//!
//! Lua's fix adds a field to `ZIO`, which `lua_load` holds on its stack, and
//! at `-O2` the compiler inlines `luaZ_fill` into `luaZ_read` and
//! `luaZ_lookahead`, so those may change without being edited.
//!
//! smallvec is a generic Rust library, so the harness in
//! `fixtures/smallvec-harness` uses it with three element types and two
//! iterators, and the fix edits six copies of `insert_many`. The fix calls
//! `insert`, which `-Os` does not inline, so there it is a new function. Rust
//! is built by clang's backend alone, so it has no GCC levels.
//!
//! Each build is read three ways: with its symbols, stripped, and as the raw
//! image a flash dump holds. Every reading must name every function that must
//! change, and nothing outside the two lists.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hereticus::matching::{Changed, Diff, Options, UseNames, diff_with};
use hereticus::obj::{Binary, Isa};
use object::{Object, ObjectSection};
use rstest::rstest;

/// One fixed build: which project, and how it was built.
#[derive(Clone, Copy, Debug)]
struct Build {
    project: Project,
    arch: &'static str,
    level: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Project {
    Zlib,
    Lua,
    Tinyxml2,
    Smallvec,
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

/// Every symbol of `binary` that one of `names` stands for.
fn named(binary: &Binary, names: &[Name]) -> BTreeSet<String> {
    binary
        .functions
        .iter()
        .filter(|function| names.iter().any(|name| name.matches(&function.name)))
        .map(|function| function.name.clone())
        .collect()
}

impl Project {
    fn name(self) -> &'static str {
        match self {
            Self::Zlib => "zlib",
            Self::Lua => "lua",
            Self::Tinyxml2 => "tinyxml2",
            Self::Smallvec => "smallvec",
        }
    }

    /// The functions the fix edits.
    fn must_change(self) -> &'static [Name] {
        match self {
            Self::Zlib => &[Name::Exact("inflate")],
            Self::Lua => &[Name::Exact("luaZ_fill"), Name::Exact("luaZ_init")],
            Self::Tinyxml2 => &[Name::Exact("_ZN8tinyxml27XMLNode9ParseDeepEPcPNS_7StrPairEPi")],
            Self::Smallvec => &[Name::Containing("E11insert_many")],
        }
    }

    /// The functions that may change without being edited, or be new.
    fn may_change(self) -> &'static [Name] {
        match self {
            Self::Zlib | Self::Tinyxml2 => &[],
            Self::Lua => {
                &[Name::Exact("lua_load"), Name::Exact("luaZ_read"), Name::Exact("luaZ_lookahead")]
            }
            Self::Smallvec => &[Name::Containing("E6insert")],
        }
    }
}

/// How a build is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reading {
    Stripped,
    Raw,
}

/// Functions a scan reports although the fix did not touch them, one per
/// line with the reason. A test fails if any other appears, and also if one
/// of these stops appearing, so the list stays true.
///
/// All are `XMLDocument::~XMLDocument` of tinyxml2 read as a raw Thumb-2
/// image. The scan cuts it at an exception landing pad after its return, and
/// the tail, with the pool after it, reads as a changed constant. Its NEON
/// words do not decode, so the rule that keeps a pool with its loads does
/// not apply. See `TODO.md`.
const KNOWN_EXTRAS: &[(Reading, &str, &str, &str, &str)] = &[
    (Reading::Raw, "tinyxml2", "thumb", "O1", "_ZN8tinyxml211XMLDocumentD1Ev"),
    (Reading::Raw, "tinyxml2", "thumb", "O1", "_ZN8tinyxml211XMLDocumentD2Ev"),
    (Reading::Raw, "tinyxml2", "thumb", "O3", "_ZN8tinyxml211XMLDocumentD1Ev"),
    (Reading::Raw, "tinyxml2", "thumb", "O3", "_ZN8tinyxml211XMLDocumentD2Ev"),
];

fn backports() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/backports")
}

fn read(build: Build, variant: &str, file: &str) -> Vec<u8> {
    let path = backports()
        .join(format!("{}-{variant}", build.project.name()))
        .join(format!("{}-{}", build.arch, build.level))
        .join(file);
    std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{}: {err}, run `just backports` first", path.display()))
}

fn parse(build: Build, variant: &str, file: &str) -> Binary {
    Binary::parse(&read(build, variant, file)).expect("a fixture library must parse")
}

/// The raw image of a build, read at the address it loads at.
///
/// `llvm-objcopy -O binary` writes every loaded section that holds bytes,
/// from the lowest address up, so that address is the base. A section that
/// is not loaded has address zero.
fn parse_raw(build: Build, variant: &str) -> Binary {
    let library = read(build, variant, "lib.so");
    let file = object::File::parse(library.as_slice()).expect("a fixture library must parse");
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
    let isa = match build.arch {
        "arm" => Isa::Arm32,
        "thumb" => Isa::Thumb2,
        "aarch64" => Isa::Aarch64,
        "mips" => Isa::Mips32Be,
        _ => Isa::Mips32,
    };
    Binary::parse_raw(&read(build, variant, "lib.bin"), base, isa).expect("a raw image must read")
}

/// One function the comparison reports, named by the symbols it overlaps.
#[derive(Debug)]
struct Region {
    names: BTreeSet<String>,
    what: Holds,
}

/// Whether a reported function holds code the fix could have touched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Holds {
    Code,
    /// The tool classed it as data, or it lies outside `.text` altogether.
    /// A raw image holds the global offset table and the read-only data, and
    /// both move when code before them grows.
    Data,
}

/// The address range of `.text` in a build.
fn text_range(build: Build, variant: &str) -> core::ops::Range<u64> {
    let library = read(build, variant, "lib.so");
    let file = object::File::parse(library.as_slice()).expect("a fixture library must parse");
    let text = file.section_by_name(".text").expect("a library has code");
    text.address()..text.address() + text.size()
}

/// The functions a build reports, named by the symbols of each side.
///
/// A stripped or raw function has no name, so each is named by the symbols
/// its bytes overlap. One recovered function can overlap several.
fn regions(build: Build, diff: &Diff, before: &Binary, after: &Binary) -> Vec<Region> {
    let symbols = [parse(build, "before", "lib.so"), parse(build, "after", "lib.so")];
    let texts = [text_range(build, "before"), text_range(build, "after")];

    let region = |binary: &Binary, index: usize, side: usize, data: bool| {
        let function = &binary.functions[index];
        let range = function.address..function.address + function.code.len() as u64;
        let names = symbols[side]
            .functions
            .iter()
            .filter(|symbol| {
                symbol.address < range.end
                    && symbol.address + symbol.code.len() as u64 > range.start
            })
            .map(|symbol| symbol.name.clone())
            .collect();
        let in_text = range.start < texts[side].end && texts[side].start < range.end;
        let what = if data || !in_text { Holds::Data } else { Holds::Code };
        Region { names, what }
    };

    let changed =
        diff.changed().map(|pair| region(before, pair.before, 0, pair.changed == Changed::Data));
    let gone = diff.removed.iter().map(|&index| region(before, index, 0, false));
    let new = diff.added.iter().map(|&index| region(after, index, 1, false));
    changed.chain(gone).chain(new).collect()
}

/// Check that the reported code covers what must change, and strays nowhere
/// else but the known extras.
fn check_regions(build: Build, reading: Reading, regions: &[Region]) {
    let project = build.project;
    let symbols = [parse(build, "before", "lib.so"), parse(build, "after", "lib.so")];
    let must = named(&symbols[0], project.must_change());
    let allowed: BTreeSet<String> = symbols
        .iter()
        .flat_map(|binary| {
            named(binary, project.must_change())
                .into_iter()
                .chain(named(binary, project.may_change()))
        })
        .collect();
    let extras: BTreeSet<&str> = KNOWN_EXTRAS
        .iter()
        .filter(|(how, name, arch, level, _)| {
            *how == reading
                && *name == project.name()
                && *arch == build.arch
                && *level == build.level
        })
        .map(|&(.., function)| function)
        .collect();

    let code: Vec<&Region> = regions.iter().filter(|region| region.what == Holds::Code).collect();

    let mut extras_seen = BTreeSet::new();
    for region in &code {
        if region.names.iter().any(|name| allowed.contains(name)) {
            continue;
        }
        assert!(
            region.names.iter().all(|name| extras.contains(name.as_str())),
            "{build:?} {reading:?}: code over {:?} was reported, which the fix did not touch",
            region.names
        );
        extras_seen.extend(region.names.iter().cloned());
    }

    // Data does not count here: a changed function hidden inside a region
    // classed as data would be a change the reader never sees.
    for must in &must {
        assert!(
            code.iter().any(|region| region.names.contains(must)),
            "{build:?} {reading:?}: {must} changed, but no reported code covers it"
        );
    }

    let expected: BTreeSet<String> = extras.iter().map(|name| (*name).to_owned()).collect();
    assert_eq!(
        extras_seen, expected,
        "{build:?} {reading:?}: the known extras changed, update KNOWN_EXTRAS"
    );
}

fn build(project: Project, arch: &'static str, level: &'static str) -> Build {
    Build { project, arch, level }
}

/// With symbols, the report names exactly the functions the fix touched.
#[rstest]
fn with_symbols_the_fix_is_named_exactly(
    #[values(Project::Zlib, Project::Lua, Project::Tinyxml2)] project: Project,
    #[values("arm", "thumb", "aarch64", "mips", "mipsel")] arch: &'static str,
    #[values("O1", "O2", "O3", "Os", "gcc-O2", "gcc-Os")] level: &'static str,
) {
    check_with_symbols(build(project, arch, level));
}

/// The same for the Rust project, which has no GCC levels.
#[rstest]
fn with_symbols_the_rust_fix_is_named_exactly(
    #[values("arm", "mips", "mipsel")] arch: &'static str,
    #[values("O1", "O2", "O3", "Os")] level: &'static str,
) {
    check_with_symbols(build(Project::Smallvec, arch, level));
}

fn check_with_symbols(build: Build) {
    let project = build.project;
    let before = parse(build, "before", "lib.so");
    let after = parse(build, "after", "lib.so");
    let diff = diff_with(&before, &after, Options::default());

    let changed: BTreeSet<String> =
        diff.changed().map(|pair| before.functions[pair.before].name.clone()).collect();
    let must = named(&before, project.must_change());
    let allowed: BTreeSet<String> =
        named(&before, project.may_change()).union(&must).cloned().collect();
    let new: BTreeSet<String> =
        diff.added.iter().map(|&index| after.functions[index].name.clone()).collect();

    assert!(!must.is_empty(), "{build:?}: no symbol is named as the fix");
    assert!(must.is_subset(&changed), "{build:?}: {must:?} must be reported, got {changed:?}");
    assert!(changed.is_subset(&allowed), "{build:?}: {changed:?} reaches past {allowed:?}");
    assert!(diff.removed.is_empty(), "{build:?}: nothing is gone");
    assert!(
        new.is_subset(&named(&after, project.may_change())),
        "{build:?}: {new:?} is new, which the fix did not add"
    );
}

/// Stripped, the report covers the fix and strays nowhere else.
#[rstest]
fn stripped_the_fix_is_covered_and_nothing_else(
    #[values(Project::Zlib, Project::Lua, Project::Tinyxml2)] project: Project,
    #[values("arm", "thumb", "aarch64", "mips", "mipsel")] arch: &'static str,
    #[values("O1", "O2", "O3", "Os", "gcc-O2", "gcc-Os")] level: &'static str,
) {
    check_stripped(build(project, arch, level));
}

/// The same for the Rust project.
#[rstest]
fn stripped_the_rust_fix_is_covered_and_nothing_else(
    #[values("arm", "mips", "mipsel")] arch: &'static str,
    #[values("O1", "O2", "O3", "Os")] level: &'static str,
) {
    check_stripped(build(Project::Smallvec, arch, level));
}

fn check_stripped(build: Build) {
    let before = parse(build, "before", "lib-stripped.so");
    let after = parse(build, "after", "lib-stripped.so");
    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });

    check_regions(build, Reading::Stripped, &regions(build, &diff, &before, &after));
}

/// As a raw image, with no container at all, the same holds.
#[rstest]
fn as_a_raw_image_the_fix_is_covered_and_nothing_else(
    #[values(Project::Zlib, Project::Lua, Project::Tinyxml2)] project: Project,
    #[values("arm", "thumb", "aarch64", "mips", "mipsel")] arch: &'static str,
    #[values("O1", "O2", "O3", "Os", "gcc-O2", "gcc-Os")] level: &'static str,
) {
    check_raw(build(project, arch, level));
}

/// The same for the Rust project.
#[rstest]
fn as_a_raw_image_the_rust_fix_is_covered_and_nothing_else(
    #[values("arm", "mips", "mipsel")] arch: &'static str,
    #[values("O1", "O2", "O3", "Os")] level: &'static str,
) {
    check_raw(build(Project::Smallvec, arch, level));
}

fn check_raw(build: Build) {
    let before = parse_raw(build, "before");
    let after = parse_raw(build, "after");
    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });

    check_regions(build, Reading::Raw, &regions(build, &diff, &before, &after));
}

/// Each build compared with itself reports nothing, in every reading.
#[rstest]
fn a_build_compared_with_itself_reports_nothing(
    #[values(Project::Zlib, Project::Lua, Project::Tinyxml2, Project::Smallvec)] project: Project,
    #[values("arm", "thumb", "aarch64", "mips", "mipsel")] arch: &'static str,
    #[values("before", "after")] variant: &str,
) {
    // The Rust harness is built for 32-bit ARM and MIPS only.
    if project == Project::Smallvec && matches!(arch, "thumb" | "aarch64") {
        return;
    }
    let build = build(project, arch, "O2");
    for binary in [
        parse(build, variant, "lib.so"),
        parse(build, variant, "lib-stripped.so"),
        parse_raw(build, variant),
    ] {
        let diff = diff_with(&binary, &binary, Options::default());
        assert_eq!(diff.changed().count(), 0, "{build:?} {variant}");
        assert!(diff.removed.is_empty() && diff.added.is_empty());
    }
}
