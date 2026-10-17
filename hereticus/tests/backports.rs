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
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};
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
            // Rust packs its strings with no NUL between them, so a text
            // runs on to the next NUL. The fix adds an assertion message to
            // the run that holds `"capacity overflow"`, which `extend`
            // reads, so on x86-64, where the reader follows the address, that
            // text differs.
            Self::Smallvec => &[Name::Containing("E6insert"), Name::Containing("E6extend")],
        }
    }
}

/// How a build is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reading {
    Stripped,
    /// Stripped of the section headers too, as `sstrip` leaves a file.
    Sstripped,
    Raw,
}

/// Functions a scan reports although the fix did not touch them, one per
/// line with the reason. A test fails if any other appears, and also if one
/// of these stops appearing, so the list stays true.
///
/// Both are Lua built by GCC for ARMv5TE, read as a raw image. A raw image
/// holds `.rodata` right after `.text`, so its first words join the last
/// function, `luaZ_openspace`. One build pads `.rodata` with a zero word and
/// the other does not, and a zero word reads as `andeq r0, r0, r0`, which
/// cannot count as padding, since a literal pool word can hold zero. See
/// `TODO.md`.
///
/// The others are tinyxml2 built as MIPS16e at `-Os`, read as a raw image.
/// GCC puts a MIPS32 stub before each MIPS16e function that takes a float
/// argument, as `XMLUtil::ToStr` for `float` and `double`. A raw image is
/// read in one set, so each stub reads as MIPS16e, and the address of the
/// function it jumps to, which moves, reads as a value.
const KNOWN_EXTRAS: &[(Reading, &str, &str, &str, &str)] = &[
    (Reading::Raw, "lua", "armv5", "gcc-O2", "luaZ_openspace"),
    (Reading::Raw, "lua", "armv5", "gcc-Os", "luaZ_openspace"),
    (Reading::Raw, "tinyxml2", "mips16", "gcc-Os", "_ZN8tinyxml27XMLUtil5ToStrEdPci"),
    (Reading::Raw, "tinyxml2", "mips16", "gcc-Os", "_ZN8tinyxml27XMLUtil5ToStrEfPci"),
    (Reading::Raw, "tinyxml2", "mips16", "gcc-Os", "__fn_stub__ZN8tinyxml27XMLUtil5ToStrEdPci"),
    (Reading::Raw, "tinyxml2", "mips16", "gcc-Os", "__fn_stub__ZN8tinyxml27XMLUtil5ToStrEfPci"),
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
        "arm" | "armv5" | "armv6" | "armhf" => Isa::Arm32,
        "thumb" | "cortex-m0" | "cortex-m3" => Isa::Thumb2,
        "aarch64" => Isa::Aarch64,
        "x86_64" => Isa::X86_64,
        "i686" => Isa::X86,
        "mips" => Isa::Mips32Be,
        "mips16" => Isa::Mips16,
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
    #[values(
        "arm", "armv5", "armv6", "armhf", "thumb", "mixed", "aarch64", "mips", "mipsel", "x86_64",
        "i686"
    )]
    arch: &'static str,
    #[values("O1", "O2", "O3", "Os", "gcc-O2", "gcc-Os")] level: &'static str,
) {
    check_with_symbols(build(project, arch, level));
}

/// The same for the Rust project, which has no GCC levels.
#[rstest]
fn with_symbols_the_rust_fix_is_named_exactly(
    #[values("arm", "thumb", "aarch64", "mips", "mipsel", "x86_64", "i686")] arch: &'static str,
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
    #[values(
        "arm", "armv5", "armv6", "armhf", "thumb", "aarch64", "mips", "mipsel", "x86_64", "i686"
    )]
    arch: &'static str,
    #[values("O1", "O2", "O3", "Os", "gcc-O2", "gcc-Os")] level: &'static str,
) {
    check_stripped(build(project, arch, level));
}

/// The same for the Rust project.
#[rstest]
fn stripped_the_rust_fix_is_covered_and_nothing_else(
    #[values("arm", "thumb", "aarch64", "mips", "mipsel", "x86_64", "i686")] arch: &'static str,
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

/// The library as `sstrip` leaves it: with no section headers, so only the
/// segments say what loads where.
fn parse_sstripped(build: Build, variant: &str) -> Binary {
    Binary::parse(&sstrip(read(build, variant, "lib-stripped.so")))
        .expect("an ELF file with no section headers must read")
}

/// Remove the section headers of an ELF file, as `sstrip` does: the header
/// no longer says where they are or how many there are.
fn sstrip(mut elf: Vec<u8>) -> Vec<u8> {
    const CLASS_64: u8 = 2;
    let (offset, count) = match elf[4] {
        CLASS_64 => (0x28..0x30, 0x3c..0x40),
        _ => (0x20..0x24, 0x30..0x34),
    };
    elf[offset].fill(0);
    // `e_shnum` and `e_shstrndx`.
    elf[count].fill(0);
    elf
}

/// With no section headers, the report covers the fix and strays nowhere
/// else.
#[rstest]
fn sstripped_the_fix_is_covered_and_nothing_else(
    #[values(Project::Zlib, Project::Lua, Project::Tinyxml2)] project: Project,
    #[values("arm", "thumb", "aarch64", "mips", "mipsel", "x86_64", "i686", "mips16")]
    arch: &'static str,
    #[values("O2", "gcc-O2", "gcc-Os")] level: &'static str,
) {
    // GCC alone builds MIPS16e.
    if arch == "mips16" && !level.starts_with("gcc") {
        return;
    }
    let build = build(project, arch, level);
    let before = parse_sstripped(build, "before");
    let after = parse_sstripped(build, "after");
    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });

    check_regions(build, Reading::Sstripped, &regions(build, &diff, &before, &after));
}

/// As a raw image, with no container at all, the same holds.
#[rstest]
fn as_a_raw_image_the_fix_is_covered_and_nothing_else(
    #[values(Project::Zlib, Project::Lua, Project::Tinyxml2)] project: Project,
    #[values(
        "arm", "armv5", "armv6", "armhf", "thumb", "aarch64", "mips", "mipsel", "x86_64", "i686"
    )]
    arch: &'static str,
    #[values("O1", "O2", "O3", "Os", "gcc-O2", "gcc-Os")] level: &'static str,
) {
    check_raw(build(project, arch, level));
}

/// The same for the Rust project.
#[rstest]
fn as_a_raw_image_the_rust_fix_is_covered_and_nothing_else(
    #[values("arm", "thumb", "aarch64", "mips", "mipsel", "x86_64", "i686")] arch: &'static str,
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

/// MIPS16e, which GCC alone builds, read every way.
#[rstest]
fn mips16_shows_the_fix_and_nothing_else(
    #[values(Project::Zlib, Project::Lua, Project::Tinyxml2)] project: Project,
    #[values("gcc-O2", "gcc-Os")] level: &'static str,
) {
    let build = build(project, "mips16", level);
    check_with_symbols(build);
    check_stripped(build);
    check_raw(build);
}

/// Cortex-M firmware, bare metal behind a vector table, read every way:
/// zlib only, built by clang only, as `fixtures/backports.sh` says.
#[rstest]
fn cortex_m_firmware_shows_the_fix_and_nothing_else(
    #[values("cortex-m0", "cortex-m3")] arch: &'static str,
    #[values("O1", "O2", "O3", "Os")] level: &'static str,
) {
    let build = build(Project::Zlib, arch, level);
    check_with_symbols(build);
    check_stripped(build);
    check_raw(build);
}

/// The vector table names the reset handler, which a raw image shows.
#[rstest]
fn a_cortex_m_image_starts_its_reset_handler_where_the_table_says(
    #[values("cortex-m0", "cortex-m3")] arch: &'static str,
) {
    let build = build(Project::Zlib, arch, "O2");
    let image = read(build, "before", "lib.bin");
    let reset = u32::from_le_bytes([image[4], image[5], image[6], image[7]]);
    assert_eq!(reset & 1, 1, "a Cortex-M handler is Thumb code");
    let raw = parse_raw(build, "before");
    assert!(
        raw.functions.iter().any(|function| function.address == u64::from(reset & !1)),
        "{build:?}: the reset handler at {reset:#x} starts a function"
    );
}

/// A library that mixes A32 and Thumb-2 reads each function in the set bit 0
/// of its symbol names, and compared with itself reports nothing.
#[rstest]
fn a_mixed_library_reads_each_function_in_its_own_set(
    #[values(Project::Zlib, Project::Lua)] project: Project,
    #[values("O2", "gcc-O2")] level: &'static str,
) {
    let build = build(project, "mixed", level);
    let library = read(build, "before", "lib.so");
    let file = object::File::parse(library.as_slice()).expect("a fixture library must parse");
    let binary = parse(build, "before", "lib.so");

    let mut sets = BTreeSet::new();
    for symbol in file.symbols() {
        if symbol.kind() != SymbolKind::Text || symbol.size() == 0 {
            continue;
        }
        let address = symbol.address() & !1;
        let expected = if symbol.address() & 1 == 1 { Isa::Thumb2 } else { Isa::Arm32 };
        let function = binary
            .functions
            .iter()
            .find(|function| function.address == address)
            .expect("each symbol is a function");
        assert_eq!(binary.isa_of(function), expected, "{build:?} {}", function.name);
        sets.insert(format!("{expected:?}"));
    }
    assert_eq!(sets.len(), 2, "{build:?} mixes both sets");

    let diff = diff_with(&binary, &binary, Options::default());
    assert_eq!(diff.changed().count(), 0, "{build:?}");
}

/// Each build compared with itself reports nothing, in every reading.
#[rstest]
fn a_build_compared_with_itself_reports_nothing(
    #[values(Project::Zlib, Project::Lua, Project::Tinyxml2, Project::Smallvec)] project: Project,
    #[values(
        "arm", "armv5", "armv6", "armhf", "thumb", "aarch64", "mips", "mipsel", "x86_64", "i686"
    )]
    arch: &'static str,
    #[values("before", "after")] variant: &str,
) {
    // The Rust harness is built for soft-float ARMv7 and later, not
    // ARMv5TE, ARMv6 or the hard-float ABI.
    if project == Project::Smallvec && matches!(arch, "armv5" | "armv6" | "armhf") {
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
