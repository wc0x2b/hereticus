//! Measure how well a stripped library's functions are recovered, with the
//! symbols as the answer.
//!
//! Every comparison of a stripped binary starts from the functions the scan
//! finds, so a function split in two or merged into its neighbour is wrong
//! in every report that follows. This reads each release that
//! `just backports` builds into `fixtures/build/versions`, stripped, and
//! compares the functions found against the symbol table of the same build.
//! The counts are locked, so a change to the scan shows what it gains and
//! what it costs.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hereticus::obj::{Binary, Isa};
use object::{Object, ObjectSection};

/// What recovery found, summed over every build.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Recovery {
    /// Functions of the symbol table.
    functions: usize,
    /// Functions found with the same start and end as a symbol.
    exact: usize,
    /// Starts found where no symbol starts: a function split in two.
    invented: usize,
    /// Symbol starts not found: a function merged into the one before.
    missed: usize,
}

fn builds() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/versions");
    let mut builds: Vec<PathBuf> = std::fs::read_dir(&root)
        .expect("run `just backports` first")
        .flatten()
        .flat_map(|release| std::fs::read_dir(release.path()).into_iter().flatten().flatten())
        .map(|build| build.path())
        .filter(|build| build.join("lib-stripped.so").exists())
        .collect();
    builds.sort();
    builds
}

/// The start and end of each function.
fn spans(binary: &Binary) -> BTreeSet<(u64, u64)> {
    binary
        .functions
        .iter()
        .map(|function| (function.address, function.address + function.code.len() as u64))
        .collect()
}

fn recovery_of(build: &Path) -> Recovery {
    let read = |file: &str| {
        let data = std::fs::read(build.join(file)).expect("the build exists");
        Binary::parse(&data).expect("the build parses")
    };
    // The PLT, and the lazy binding stubs of MIPS, are code no symbol
    // names, so the stubs the scan finds there are no error, and are left
    // out.
    let library = std::fs::read(build.join("lib.so")).expect("the build exists");
    let file = object::File::parse(library.as_slice()).expect("the build parses");
    let plt: Vec<core::ops::Range<u64>> = file
        .sections()
        .filter(|section| {
            section.name().is_ok_and(|name| name.starts_with(".plt") || name == ".MIPS.stubs")
        })
        .map(|section| section.address()..section.address() + section.size())
        .collect();
    let outside_plt = |&(start, _): &(u64, u64)| !plt.iter().any(|range| range.contains(&start));
    let (truth, found) = (spans(&read("lib.so")), spans(&read("lib-stripped.so")));
    let found: BTreeSet<(u64, u64)> = found.into_iter().filter(outside_plt).collect();
    let starts = |spans: &BTreeSet<(u64, u64)>| -> BTreeSet<u64> {
        spans.iter().map(|&(start, _)| start).collect()
    };
    let (true_starts, found_starts) = (starts(&truth), starts(&found));
    Recovery {
        functions: truth.len(),
        exact: truth.intersection(&found).count(),
        invented: found_starts.difference(&true_starts).count(),
        missed: true_starts.difference(&found_starts).count(),
    }
}

#[test]
fn stripped_functions_are_recovered() {
    let builds = builds();
    assert!(!builds.is_empty(), "run `just backports` first");
    let total =
        builds.iter().map(|build| recovery_of(build)).fold(Recovery::default(), |sum, one| {
            Recovery {
                functions: sum.functions + one.functions,
                exact: sum.exact + one.exact,
                invented: sum.invented + one.invented,
                missed: sum.missed + one.missed,
            }
        });
    assert_eq!(
        total,
        Recovery { functions: 64551, exact: 64488, invented: 3, missed: 9 },
        "over {} builds",
        builds.len()
    );
}

/// A stripped library keeps its dynamic symbol table, so each function it
/// exports keeps its name, its start and its end.
#[test]
fn exported_functions_keep_their_names() {
    let build =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/versions/zlib-1.2.13/arm-O2");
    let read = |file: &str| {
        let data = std::fs::read(build.join(file)).expect("run `just backports` first");
        Binary::parse(&data).expect("the build parses")
    };
    let (symbols, stripped) = (read("lib.so"), read("lib-stripped.so"));
    for name in ["crc32", "crc32_z", "inflateEnd", "gzseek"] {
        let span_of = |binary: &Binary| {
            binary
                .functions
                .iter()
                .find(|function| function.name == name)
                .map(|function| (function.address, function.code.len()))
        };
        assert!(span_of(&symbols).is_some(), "{name} is in the symbol table");
        assert_eq!(span_of(&stripped), span_of(&symbols), "{name}");
    }
}

/// A static function that only a table of callbacks points at is found
/// through the relocation that the table's word holds.
#[test]
fn a_function_only_a_table_points_at_is_found() {
    let build = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/build/versions/lua-5.1.4/arm-gcc-O2");
    let read = |file: &str| {
        let data = std::fs::read(build.join(file)).expect("run `just backports` first");
        Binary::parse(&data).expect("the build parses")
    };
    let (symbols, stripped) = (read("lib.so"), read("lib-stripped.so"));
    let str_find = symbols
        .functions
        .iter()
        .find(|function| function.name == "str_find")
        .expect("str_find is in the symbol table");
    let found = stripped
        .functions
        .iter()
        .find(|function| function.address == str_find.address)
        .expect("str_find is found");
    assert_eq!(found.code.len(), str_find.code.len());
}

/// GCC links the thunks of 32-bit PIC with no size, and each is still a
/// function of its own, with symbols as without.
#[test]
fn an_x86_thunk_with_no_size_is_a_function() {
    let build = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/build/versions/zlib-1.2.13/i686-gcc-O2");
    let read = |file: &str| {
        let data = std::fs::read(build.join(file)).expect("run `just backports` first");
        Binary::parse(&data).expect("the build parses")
    };
    let (symbols, stripped) = (read("lib.so"), read("lib-stripped.so"));
    let thunk = symbols
        .functions
        .iter()
        .find(|function| function.name == "__x86.get_pc_thunk.bx")
        .expect("the thunk is a function");
    // mov ebx, [esp]; ret
    assert_eq!(thunk.code, [0x8b, 0x1c, 0x24, 0xc3]);
    assert!(
        stripped
            .functions
            .iter()
            .any(|function| function.address == thunk.address && function.code == thunk.code),
        "the scan finds the same thunk"
    );
}

/// Each entry of the PLT of a stripped ARM library is a function of its
/// own, named for its import, in the instruction set it is in, and so is
/// each entry of the raw image of the same build. GNU `ld` puts a T32
/// prefix that switches to A32 before each stub that T32 code calls, and
/// LLD writes A32 stubs alone.
#[rstest::rstest]
#[case::gnu_arm("arm-gcc-O2", Isa::Arm32, 57, 0)]
#[case::lld_arm("arm-O2", Isa::Arm32, 49, 0)]
#[case::gnu_thumb("thumb-gcc-O2", Isa::Thumb2, 57, 17)]
#[case::lld_thumb("thumb-O2", Isa::Thumb2, 49, 0)]
fn each_plt_entry_is_a_function(
    #[case] build: &str,
    #[case] isa: Isa,
    #[case] entries: usize,
    #[case] prefixed: usize,
) {
    let build = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/build/versions/zlib-1.2.13")
        .join(build);
    let read = |file: &str| std::fs::read(build.join(file)).expect("run `just backports` first");
    let (stripped, image) = (read("lib-stripped.so"), read("lib.bin"));
    let file = object::File::parse(stripped.as_slice()).expect("the build parses");
    let plt = file.section_by_name(".plt").expect("a library calls through its PLT");
    let range = plt.address()..plt.address() + plt.size();
    // `llvm-objcopy -O binary` starts the image at the first section that
    // loads.
    let base = file
        .sections()
        .filter(|section| section.address() != 0 && section.size() != 0)
        .filter(|section| section.kind() != object::SectionKind::UninitializedData)
        .map(|section| section.address())
        .min()
        .expect("a library loads something");
    let readings = [
        ("stripped", Binary::parse(&stripped).expect("the build parses")),
        ("raw", Binary::parse_raw(&image, base, isa).expect("the image reads")),
    ];
    for (reading, binary) in &readings {
        check_plt(binary, range.clone(), entries, prefixed, reading);
    }
}

/// Check that the functions of `binary` in the PLT at `range` are its
/// `entries`, of which `prefixed` open with the T32 prefix.
fn check_plt(
    binary: &Binary,
    range: core::ops::Range<u64>,
    entries: usize,
    prefixed: usize,
    reading: &str,
) {
    /// `bx pc`, little endian.
    const BX_PC: [u8; 2] = [0x78, 0x47];

    let in_plt: Vec<_> =
        binary.functions.iter().filter(|function| range.contains(&function.address)).collect();
    assert_eq!(in_plt.len(), entries, "{reading}: the first entry and each stub");

    let (first, stubs) = in_plt.split_first().expect("the PLT holds functions");
    assert_eq!(first.address, range.start, "{reading}");
    assert!(first.name.is_empty(), "{reading}: the first entry calls the lazy resolver");
    assert_eq!(binary.isa_of(first), Isa::Arm32, "{reading}");
    assert!(
        stubs.iter().all(|stub| stub.name.ends_with("@plt")),
        "{reading}: each stub has its import"
    );
    let opens_in_t32 = |code: &[u8]| code.starts_with(&BX_PC);
    let prefixes = stubs.iter().filter(|stub| opens_in_t32(&stub.code)).count();
    assert_eq!(prefixes, prefixed, "{reading}");
    for stub in stubs {
        let set = if opens_in_t32(&stub.code) { Isa::Thumb2 } else { Isa::Arm32 };
        assert_eq!(binary.isa_of(stub), set, "{reading}: {}", stub.name);
    }
    // A raw Thumb-2 image is read as T32, which trims the word that traps
    // after a stub of LLD as padding.
    const TRAP_WORD: u64 = 4;
    let end = in_plt.iter().map(|function| function.address + function.code.len() as u64).max();
    let covers = end.is_some_and(|end| end == range.end || end + TRAP_WORD == range.end);
    assert!(covers, "{reading}: the stubs cover the PLT, to {end:x?}");
}
