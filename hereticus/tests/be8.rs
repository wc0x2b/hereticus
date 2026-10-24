//! Measure how well the functions of big-endian ARM are found and paired,
//! with the symbols as the answer.
//!
//! Some networking parts run ARM big endian. In a BE8 image, as `ld.lld
//! --be8` links it, each instruction is stored little endian and the data
//! stays big endian: the literal pools, the unwind index, the global offset
//! table and every pointer. `just backports` builds each release of zlib,
//! Lua, expat and tinyxml2 so with clang, as A32 and as Thumb-2, into
//! `fixtures/build/versions`. Each build is read stripped and as a raw
//! image, and the counts are locked beside those of the little-endian
//! builds of the same releases.

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

/// The byte order of the data of a build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Order {
    /// BE8: the data big endian, the code little endian.
    Big,
    /// The same releases built little endian, to compare with.
    Little,
}

/// The releases of each project, in order, and the pairs of them compared.
const RELEASES: [(&str, &[&str]); 5] = [
    ("zlib", &["1.2.11", "1.2.12", "1.2.13", "1.3"]),
    ("lua", &["5.1.4", "5.1.5"]),
    ("lua", &["5.3.5", "5.3.6"]),
    ("expat", &["2.4.8", "2.4.9"]),
    ("tinyxml2", &["8.0.0", "9.0.0", "10.0.0"]),
];

/// The builds of each release in each byte order, and the instruction set
/// a raw image of each is read in.
fn builds(order: Order) -> [(&'static str, Isa); 2] {
    match order {
        Order::Big => [("armbe8-O2", Isa::Arm32Be8), ("thumbbe8-O2", Isa::Thumb2Be8)],
        Order::Little => [("arm-O2", Isa::Arm32), ("thumb-O2", Isa::Thumb2)],
    }
}

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
fn read(project: &str, version: &str, (build, isa): (&str, Isa), reading: Reading) -> Binary {
    match reading {
        Reading::Stripped => {
            let data = read_file(project, version, build, "lib-stripped.so");
            Binary::parse(&data).expect("a fixture library must parse")
        }
        Reading::Raw => {
            let library = read_file(project, version, build, "lib.so");
            let image = read_file(project, version, build, "lib.bin");
            Binary::parse_raw(&image, base_of(&library), isa).expect("a raw image must read")
        }
    }
}

/// The address of the first section that loads, where `llvm-objcopy -O
/// binary` starts the image.
fn base_of(library: &[u8]) -> u64 {
    let file = object::File::parse(library).expect("a fixture library must parse");
    file.sections()
        .filter(|section| section.address() != 0 && section.size() != 0)
        .filter(|section| section.kind() != object::SectionKind::UninitializedData)
        .map(|section| section.address())
        .min()
        .expect("a library loads something")
}

/// The symbols of a build, which are the answer.
fn symbols(project: &str, version: &str, build: &str) -> Binary {
    let data = read_file(project, version, build, "lib.so");
    Binary::parse(&data).expect("a fixture library must parse")
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

/// The start and end of each function of `binary` in `code`.
fn spans(binary: &Binary, code: &core::ops::Range<u64>) -> BTreeSet<(u64, u64)> {
    binary
        .functions
        .iter()
        .filter(|function| code.contains(&function.address))
        .map(|function| (function.address, function.address + function.code.len() as u64))
        .collect()
}

fn recovery_of(project: &str, version: &str, build: (&str, Isa), reading: Reading) -> Recovery {
    let truth = symbols(project, version, build.0);
    // The PLT holds code no symbol names, so only the code between the
    // first and the last symbol counts.
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

/// Every release and build in `order`, read as `reading`, summed.
fn recovery_all(order: Order, reading: Reading) -> Recovery {
    let mut total = Recovery::default();
    for (project, versions) in RELEASES {
        for version in versions {
            for build in builds(order) {
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

/// Each consecutive pair of releases in `order`, compared with no names,
/// as `reading`.
fn tally_all(order: Order, reading: Reading) -> Tally {
    let mut total = Tally::default();
    for (project, versions) in RELEASES {
        for pair in versions.windows(2) {
            for build in builds(order) {
                let answer =
                    [symbols(project, pair[0], build.0), symbols(project, pair[1], build.0)];
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

/// Read stripped, BE8 finds its functions as well as little endian does.
/// With the data read little endian, as before, the unwind index read as
/// noise: 7945 exact, 73 invented and 18 missed.
#[test]
fn be8_functions_are_recovered_stripped() {
    assert_eq!(
        [
            recovery_all(Order::Big, Reading::Stripped),
            recovery_all(Order::Little, Reading::Stripped)
        ],
        [
            Recovery { functions: 8024, exact: 7997, invented: 1, missed: 4 },
            Recovery { functions: 8024, exact: 7993, invented: 1, missed: 4 }
        ],
        "big then little"
    );
}

/// Read raw, as `--arch arm32-be8` and `thumb2-be8` read an image. With the
/// data read little endian, as before: 7788 exact, 93 invented and 102
/// missed.
#[test]
fn be8_functions_are_recovered_raw() {
    assert_eq!(
        [recovery_all(Order::Big, Reading::Raw), recovery_all(Order::Little, Reading::Raw)],
        [
            Recovery { functions: 8024, exact: 7931, invented: 5, missed: 37 },
            Recovery { functions: 8024, exact: 7925, invented: 7, missed: 41 }
        ],
        "big then little"
    );
}

/// The releases pair as well in BE8 as little endian, where before 18
/// pairs were wrong stripped and 29 raw. A raw image holds the dynamic
/// symbol and string tables before the code, which read as code in BE8 more
/// often, and go or come: so more functions are gone and new there.
#[test]
fn be8_releases_pair() {
    assert_eq!(
        [
            tally_all(Order::Big, Reading::Stripped),
            tally_all(Order::Little, Reading::Stripped),
            tally_all(Order::Big, Reading::Raw),
            tally_all(Order::Little, Reading::Raw),
        ],
        [
            Tally { right: 4464, wrong: 6, gone: 72, new: 93 },
            Tally { right: 4464, wrong: 6, gone: 72, new: 93 },
            Tally { right: 4448, wrong: 6, gone: 196, new: 239 },
            Tally { right: 4446, wrong: 7, gone: 146, new: 158 },
        ],
        "big then little, stripped then raw"
    );
}
