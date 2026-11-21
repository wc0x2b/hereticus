//! Measure how well the functions of ARM big endian, BE32, are found and
//! paired, with the symbols as the answer.
//!
//! Cores before ARMv6 run big endian as BE32, where the instructions are
//! stored big endian, as the data is. `just backports` builds each release
//! of zlib, Lua, expat and tinyxml2 so with clang for ARMv5TE, as A32 and
//! as Thumb, into `fixtures/build/versions`. It builds them little endian
//! with the same flags too, so the two differ in the byte order alone.
//! Each build is read stripped and as a raw image, and the counts are
//! locked beside those of the little-endian builds.

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
    /// BE32: the code and the data big endian.
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
        Order::Big => [("armbe32-O2", Isa::Arm32Be32), ("thumbbe32-O2", Isa::Thumb2Be32)],
        Order::Little => [("armv5-O2", Isa::Arm32), ("thumbv5-O2", Isa::Thumb2)],
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

/// Read stripped, BE32 finds its functions as well as little endian does.
#[test]
fn be32_functions_are_recovered_stripped() {
    assert_eq!(
        [
            recovery_all(Order::Big, Reading::Stripped),
            recovery_all(Order::Little, Reading::Stripped)
        ],
        [
            Recovery { functions: 7862, exact: 7821, invented: 399, missed: 4 },
            Recovery { functions: 7862, exact: 7822, invented: 408, missed: 4 }
        ],
        "big then little"
    );
}

/// Read raw, as `--arch arm32-be32` and `thumb2-be32` read an image. With
/// the instructions read little endian, as before, 249 were exact and 7326
/// missed. With them read big endian but the raw words that the scan
/// reads before it decodes still little endian, 6587 were exact and 907
/// missed.
#[test]
fn be32_functions_are_recovered_raw() {
    assert_eq!(
        [recovery_all(Order::Big, Reading::Raw), recovery_all(Order::Little, Reading::Raw)],
        [
            Recovery { functions: 7862, exact: 7734, invented: 686, missed: 37 },
            Recovery { functions: 7862, exact: 7726, invented: 717, missed: 39 }
        ],
        "big then little"
    );
}

/// The releases pair as well in BE32 as little endian. As for BE8, a raw
/// image holds the dynamic symbol and string tables before the code, which
/// read as different code in each byte order, and go or come: so more
/// functions are gone and new there.
#[test]
fn be32_releases_pair() {
    assert_eq!(
        [
            tally_all(Order::Big, Reading::Stripped),
            tally_all(Order::Little, Reading::Stripped),
            tally_all(Order::Big, Reading::Raw),
            tally_all(Order::Little, Reading::Raw),
        ],
        [
            Tally { right: 4565, wrong: 6, gone: 69, new: 93 },
            Tally { right: 4569, wrong: 6, gone: 70, new: 93 },
            Tally { right: 4663, wrong: 6, gone: 234, new: 260 },
            Tally { right: 4727, wrong: 6, gone: 180, new: 193 },
        ],
        "big then little, stripped then raw"
    );
}
