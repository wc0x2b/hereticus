//! Check the comparison against the functions a real fix touched.
//!
//! `just backports` builds zlib and Lua twice each, from the pristine release
//! and with one upstream fix on top, as a vendor ships a backport. Unlike the
//! OpenWrt tests, these know the right answer: the functions the fix edits.
//!
//! | Project | Fix | Must change | May change |
//! |---|---|---|---|
//! | zlib 1.2.12 | CVE-2022-37434 | `inflate` | none |
//! | Lua 5.1.5 | bug 2 | `luaZ_fill`, `luaZ_init` | `lua_load`, `luaZ_read`, `luaZ_lookahead` |
//!
//! Lua's fix adds a field to `ZIO`, which `lua_load` holds on its stack, and
//! at `-O2` the compiler inlines `luaZ_fill` into `luaZ_read` and
//! `luaZ_lookahead`, so those may change without being edited.
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
}

impl Project {
    fn name(self) -> &'static str {
        match self {
            Self::Zlib => "zlib",
            Self::Lua => "lua",
        }
    }

    /// The functions the fix edits.
    fn must_change(self) -> &'static [&'static str] {
        match self {
            Self::Zlib => &["inflate"],
            Self::Lua => &["luaZ_fill", "luaZ_init"],
        }
    }

    /// The functions that may change without being edited.
    fn may_change(self) -> &'static [&'static str] {
        match self {
            Self::Zlib => &[],
            Self::Lua => &["lua_load", "luaZ_read", "luaZ_lookahead"],
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
/// Each is a function a scan splits, whose later piece reaches the global
/// offset table through a register the earlier piece set. The scan cannot
/// see that register, so a table offset reads as a changed constant.
const KNOWN_EXTRAS: &[(Reading, &str, &str, &str, &str)] = &[
    // A word of `.rodata` in the raw image decodes as `blvs` into the middle
    // of `luaopen_base`, so it reads as a call target and splits it.
    (Reading::Raw, "lua", "arm", "Os", "luaopen_base"),
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
    let allowed: BTreeSet<&str> =
        project.must_change().iter().chain(project.may_change()).copied().collect();
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
        if region.names.iter().any(|name| allowed.contains(name.as_str())) {
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
    for must in project.must_change() {
        assert!(
            code.iter().any(|region| region.names.contains(*must)),
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
    #[values(Project::Zlib, Project::Lua)] project: Project,
    #[values("arm", "mips", "mipsel")] arch: &'static str,
    #[values("O2", "Os")] level: &'static str,
) {
    let build = build(project, arch, level);
    let before = parse(build, "before", "lib.so");
    let after = parse(build, "after", "lib.so");
    let diff = diff_with(&before, &after, Options::default());

    let changed: BTreeSet<&str> =
        diff.changed().map(|pair| before.functions[pair.before].name.as_str()).collect();
    let allowed: BTreeSet<&str> =
        project.must_change().iter().chain(project.may_change()).copied().collect();

    for must in project.must_change() {
        assert!(changed.contains(must), "{build:?}: {must} must be reported, got {changed:?}");
    }
    assert!(changed.is_subset(&allowed), "{build:?}: {changed:?} reaches past {allowed:?}");
    assert!(diff.removed.is_empty() && diff.added.is_empty(), "{build:?}: nothing is gone or new");
}

/// Stripped, the report covers the fix and strays nowhere else.
#[rstest]
fn stripped_the_fix_is_covered_and_nothing_else(
    #[values(Project::Zlib, Project::Lua)] project: Project,
    #[values("arm", "mips", "mipsel")] arch: &'static str,
    #[values("O2", "Os")] level: &'static str,
) {
    let build = build(project, arch, level);
    let before = parse(build, "before", "lib-stripped.so");
    let after = parse(build, "after", "lib-stripped.so");
    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });

    check_regions(build, Reading::Stripped, &regions(build, &diff, &before, &after));
}

/// As a raw image, with no container at all, the same holds.
#[rstest]
fn as_a_raw_image_the_fix_is_covered_and_nothing_else(
    #[values(Project::Zlib, Project::Lua)] project: Project,
    #[values("arm", "mips", "mipsel")] arch: &'static str,
    #[values("O2", "Os")] level: &'static str,
) {
    let build = build(project, arch, level);
    let before = parse_raw(build, "before");
    let after = parse_raw(build, "after");
    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });

    check_regions(build, Reading::Raw, &regions(build, &diff, &before, &after));
}

/// Each build compared with itself reports nothing, in every reading.
#[rstest]
fn a_build_compared_with_itself_reports_nothing(
    #[values(Project::Zlib, Project::Lua)] project: Project,
    #[values("arm", "mips", "mipsel")] arch: &'static str,
    #[values("before", "after")] variant: &str,
) {
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
