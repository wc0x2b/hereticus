//! Measure how well the functions of x86 code that is not PIC are found and
//! paired, with the symbols as the answer.
//!
//! Firmware for x86, and executables of older distributions, are built with
//! `-fno-pic`, and there a `switch` jumps through a table of whole
//! addresses, as `jmp qword ptr [8*rax + table]`, which no PIC build holds.
//! `just backports` builds each release of zlib and Lua so, with clang and
//! with GCC, for x86-64 and i686, into `fixtures/build/versions`. Each build
//! is read stripped and as a raw image, and the counts are locked.

/// See `ALLOCATOR` in `hereticus-cli/src/main.rs`.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hereticus::matching::{Options, UseNames, diff_with};
use hereticus::obj::{Binary, Isa};
use object::{Object, ObjectSection};

/// How a build is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reading {
    Stripped,
    Raw,
}

/// The releases built so, in order, by project.
const RELEASES: [(&str, &[&str]); 3] = [
    ("zlib", &["1.2.11", "1.2.12", "1.2.13", "1.3"]),
    ("lua", &["5.1.4", "5.1.5"]),
    ("lua", &["5.3.5", "5.3.6"]),
];

/// The builds of each release.
const BUILDS: [&str; 4] =
    ["x86_64-nopic-O2", "x86_64-nopic-gcc-O2", "i686-nopic-O2", "i686-nopic-gcc-O2"];

fn build_dir(project: &str, version: &str, build: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/build/versions")
        .join(format!("{project}-{version}"))
        .join(build)
}

fn read_file(project: &str, version: &str, build: &str, file: &str) -> Vec<u8> {
    let path = build_dir(project, version, build).join(file);
    std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{}: {err}, run `just backports` first", path.display()))
}

/// The build of `project` at `version`, read as `reading`.
fn read(project: &str, version: &str, build: &str, reading: Reading) -> Binary {
    match reading {
        Reading::Stripped => {
            let data = read_file(project, version, build, "lib-stripped.so");
            Binary::parse(&data).expect("a fixture executable must parse")
        }
        Reading::Raw => {
            let executable = read_file(project, version, build, "lib.so");
            let image = read_file(project, version, build, "lib.bin");
            let isa = if build.starts_with("x86_64") { Isa::X86_64 } else { Isa::X86 };
            Binary::parse_raw(&image, base_of(&executable), isa).expect("a raw image must read")
        }
    }
}

/// The address of the first section that loads, where `llvm-objcopy -O
/// binary` starts the image.
fn base_of(executable: &[u8]) -> u64 {
    let file = object::File::parse(executable).expect("a fixture executable must parse");
    file.sections()
        .filter(|section| section.address() != 0 && section.size() != 0)
        .filter(|section| section.kind() != object::SectionKind::UninitializedData)
        .map(|section| section.address())
        .min()
        .expect("an executable loads something")
}

/// The symbols of a build, which are the answer.
fn symbols(project: &str, version: &str, build: &str) -> Binary {
    let data = read_file(project, version, build, "lib.so");
    Binary::parse(&data).expect("a fixture executable must parse")
}

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

/// The start and end of each function of `binary` that lies in the code
/// the symbols cover.
fn spans(binary: &Binary, code: &core::ops::Range<u64>) -> BTreeSet<(u64, u64)> {
    binary
        .functions
        .iter()
        .filter(|function| code.contains(&function.address))
        .map(|function| (function.address, function.address + function.code.len() as u64))
        .collect()
}

fn recovery_of(project: &str, version: &str, build: &str, reading: Reading) -> Recovery {
    let truth = symbols(project, version, build);
    // The PLT, `.init` and `.fini` hold code no symbol of the project
    // names, so only the code between the first and the last symbol counts.
    let starts = truth.functions.iter().map(|function| function.address);
    let ends = truth.functions.iter().map(|function| function.address + function.code.len() as u64);
    let code = starts.min().unwrap_or(0)..ends.max().unwrap_or(0);
    let (truth, found) =
        (spans(&truth, &code), spans(&read(project, version, build, reading), &code));
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

/// Every release and build, read as `reading`, summed.
fn recovery_all(reading: Reading) -> Recovery {
    let mut total = Recovery::default();
    for (project, versions) in RELEASES {
        for version in versions {
            for build in BUILDS {
                let one = recovery_of(project, version, build, reading);
                total.functions += one.functions;
                total.exact += one.exact;
                total.invented += one.invented;
                total.missed += one.missed;
            }
        }
    }
    total
}

/// The builds keep no unwind tables, as firmware does, so only the code
/// bounds their functions, and a `switch` whose cases each return reads as
/// one function only where its table is read. With no table read, 304
/// starts were invented and 100 fewer functions found exact.
#[test]
fn functions_that_are_not_pic_are_recovered_stripped() {
    assert_eq!(
        recovery_all(Reading::Stripped),
        Recovery { functions: 10512, exact: 10212, invented: 8, missed: 175 }
    );
}

/// A raw image keeps no dynamic symbol table either. With no table read,
/// 305 starts were invented and 101 fewer functions found exact.
#[test]
fn functions_that_are_not_pic_are_recovered_raw() {
    assert_eq!(
        recovery_all(Reading::Raw),
        Recovery { functions: 10512, exact: 10140, invented: 8, missed: 225 }
    );
}

/// What a comparison of two releases counts, summed over its builds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Tally {
    /// Pairs whose two functions share a symbol.
    right: usize,
    /// Pairs whose two functions share none.
    wrong: usize,
    /// Functions of the first release that paired with nothing.
    gone: usize,
    /// Functions of the second release that paired with nothing.
    new: usize,
}

/// The names of the symbols that overlap function `index` of `binary`.
fn names_of(symbols: &Binary, binary: &Binary, index: usize) -> BTreeSet<String> {
    let function = &binary.functions[index];
    let range = function.address..function.address + function.code.len() as u64;
    symbols
        .functions
        .iter()
        .filter(|symbol| {
            symbol.address < range.end && symbol.address + symbol.code.len() as u64 > range.start
        })
        .map(|symbol| symbol.name.clone())
        .collect()
}

/// Each consecutive pair of releases, compared with no names, as `reading`.
fn tally_all(reading: Reading) -> Tally {
    let mut total = Tally::default();
    for (project, versions) in RELEASES {
        for pair in versions.windows(2) {
            for build in BUILDS {
                let answer = [symbols(project, pair[0], build), symbols(project, pair[1], build)];
                let read = [
                    read(project, pair[0], build, reading),
                    read(project, pair[1], build, reading),
                ];
                let diff = diff_with(
                    &read[0],
                    &read[1],
                    Options { use_names: UseNames::No, ..Default::default() },
                );
                total.gone += diff.removed.len();
                total.new += diff.added.len();
                for found in &diff.matched {
                    let left = names_of(&answer[0], &read[0], found.before);
                    let right = names_of(&answer[1], &read[1], found.after);
                    // Code that no symbol covers, as a PLT stub, has no answer.
                    if left.is_empty() || right.is_empty() {
                        continue;
                    }
                    if left.is_disjoint(&right) {
                        total.wrong += 1;
                    } else {
                        total.right += 1;
                    }
                }
            }
        }
    }
    total
}

/// A function cut in pieces pairs each piece with a piece of the same
/// function, so with no table read, more pairs count as right: 5771 raw, and
/// 249 functions gone and 218 new, where the whole functions leave 119 and
/// 99.
#[test]
fn releases_that_are_not_pic_pair() {
    assert_eq!(
        [tally_all(Reading::Stripped), tally_all(Reading::Raw)],
        [
            Tally { right: 5639, wrong: 4, gone: 24, new: 30 },
            Tally { right: 5624, wrong: 4, gone: 119, new: 99 }
        ],
        "stripped then raw"
    );
}
