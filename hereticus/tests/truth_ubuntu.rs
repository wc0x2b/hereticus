//! Check the pairs of Ubuntu security updates against their debug symbols,
//! and lock the counts and the rank of each fix.
//!
//! Each case is a pair of consecutive security releases of a C library for
//! Ubuntu 22.04, arm64 or armhf: the same compiler and flags on both sides,
//! and a published fix in between. `fixtures/ubuntu_cves.py` fetches the
//! cases that `fixtures/ubuntu_cases.json` pins, each file by its SHA-256.
//!
//! A pair is right when the two functions overlap a symbol of the same
//! name in the `-dbgsym` debug files, and wrong when they share no name.
//! The pairing does not use the names the libraries export, as for a
//! stripped binary. The rank is the row of the first function the patches
//! of the update touched, in the order `--sort added` shows, where any
//! such function is in the library, as its own function or inlined into
//! another.
//!
//! The inputs are about 800 MB, so `just quick-test` skips this test.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use hereticus::matching::{Changed, Diff, Match, Options, UseNames, diff_with};
use hereticus::obj::Binary;
use rayon::prelude::*;

/// See `ALLOCATOR` in `hereticus-cli/src/main.rs`.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// A function symbol of a debug file: start, end and name.
type Symbol = (u64, u64, String);

/// One security update, as `fixtures/ubuntu_cases.json` pins it.
struct Case {
    library: String,
    arch: String,
    /// The library and its debug file, before and after.
    files: [[PathBuf; 2]; 2],
    /// The functions the patches of the update touched.
    fixes: BTreeSet<String>,
}

/// The counts of one library on one architecture, summed over its cases.
#[derive(Default)]
struct Tally {
    cases: usize,
    right: usize,
    wrong: usize,
    gone: usize,
    new: usize,
    /// Cases where a function the fix touched is in the library at all.
    /// A patch can touch only a tool or a test of the same source, as
    /// `tiffcrop` of libtiff, which no row can show.
    in_library: usize,
    /// Cases where a changed row holds a function the fix touched.
    found: usize,
    /// Of [`Tally::found`], those where the first such row holds the
    /// function only as an inlined copy.
    by_inlining: usize,
    /// Over the found cases: the sum of the rank of the fix, from 1, and
    /// how often it is first and in the first five.
    rank_sum: usize,
    top1: usize,
    top5: usize,
}

impl core::ops::AddAssign<&Tally> for Tally {
    fn add_assign(&mut self, other: &Tally) {
        self.cases += other.cases;
        self.right += other.right;
        self.wrong += other.wrong;
        self.gone += other.gone;
        self.new += other.new;
        self.in_library += other.in_library;
        self.found += other.found;
        self.by_inlining += other.by_inlining;
        self.rank_sum += other.rank_sum;
        self.top1 += other.top1;
        self.top5 += other.top5;
    }
}

fn cache() -> PathBuf {
    Path::new(&std::env::var("HOME").expect("HOME is set")).join(".cache/hereticus-ubuntu-cve")
}

fn cases() -> Vec<Case> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/ubuntu_cases.json");
    let text = std::fs::read_to_string(&path).expect("the pinned cases are in the repository");
    let pinned: serde_json::Value = serde_json::from_str(&text).expect("the pinned cases parse");
    let string = |value: &serde_json::Value| value.as_str().expect("a string").to_owned();
    pinned
        .as_array()
        .expect("a list of cases")
        .iter()
        .map(|case| {
            let file = |side: usize, which: usize| {
                cache().join(string(&case["files"][side][which]["path"]))
            };
            Case {
                library: string(&case["library"]),
                arch: string(&case["arch"]),
                files: [[file(0, 0), file(0, 1)], [file(1, 0), file(1, 1)]],
                fixes: case["fixes"]
                    .as_array()
                    .expect("a list of names")
                    .iter()
                    .map(string)
                    .collect(),
            }
        })
        .collect()
}

/// The name of a function without the suffix of a GCC clone.
fn function_name(symbol: &str) -> &str {
    // GCC names a local function `.lto_priv.N` where it built with LTO,
    // as Ubuntu does for arm64 and not for armhf.
    [".isra.", ".constprop.", ".part.", ".cold", ".lto_priv."]
        .iter()
        .filter_map(|suffix| symbol.find(suffix))
        .min()
        .map_or(symbol, |end| &symbol[..end])
}

/// The function symbols of a debug file.
fn debug_symbols(path: &Path) -> Vec<Symbol> {
    use object::{Object, ObjectSymbol, SymbolKind};
    let data = std::fs::read(path)
        .unwrap_or_else(|err| panic!("{}: {err}; run `just test`", path.display()));
    let file = object::File::parse(&*data).expect("the debug file parses");
    file.symbols()
        .filter(|symbol| symbol.kind() == SymbolKind::Text && symbol.size() > 0)
        .filter_map(|symbol| {
            let name = symbol.name().ok()?;
            // GNU ld names each veneer of the Cortex-A53 erratum 843419 by
            // where it sits, so one veneer has another name in each build.
            if name.starts_with("e843419@") {
                return None;
            }
            let name = function_name(name).to_owned();
            // A Thumb symbol has its low bit set.
            let start = symbol.address() & !1;
            Some((start, start + symbol.size(), name))
        })
        .collect()
}

/// Where the compiler inlined a function, from the DWARF of a debug file:
/// start, end and the name of the inlined function.
///
/// Under LTO a patched function can live only inside its callers, as
/// liblzma's `lzma_index_prealloc` inside `index_decode` on arm64, so the
/// row that shows the fix carries another name.
fn inlined_copies(path: &Path) -> Vec<Symbol> {
    use gimli::{AttributeValue, DebugInfoOffset, constants};
    use object::{Object, ObjectSection};
    use std::borrow::Cow;

    let data = std::fs::read(path).expect("the debug file is cached");
    let file = object::File::parse(&*data).expect("the debug file parses");
    let endian = if file.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    let sections = gimli::DwarfSections::load(|id| -> Result<Cow<'_, [u8]>, gimli::Error> {
        Ok(file
            .section_by_name(id.name())
            .and_then(|section| section.uncompressed_data().ok())
            .unwrap_or(Cow::Borrowed(&[])))
    })
    .expect("the DWARF sections load");
    let dwarf = sections.borrow(|section| gimli::EndianSlice::new(section, endian));

    // Each entry by its offset in `.debug_info`: its name, or the entry
    // it takes its name from.
    let reference = |unit: &gimli::Unit<_>, value| match value {
        AttributeValue::UnitRef(offset) => offset.to_debug_info_offset(&unit.header),
        AttributeValue::DebugInfoRef(offset) => Some(offset),
        _ => None,
    };
    let mut origins: BTreeMap<DebugInfoOffset, (Option<String>, Option<DebugInfoOffset>)> =
        BTreeMap::new();
    let mut copies: Vec<(u64, u64, DebugInfoOffset)> = Vec::new();
    let mut headers = dwarf.units();
    while let Ok(Some(header)) = headers.next() {
        let Ok(unit) = dwarf.unit(header) else { continue };
        let mut entries = unit.entries();
        while let Ok(Some(entry)) = entries.next_dfs() {
            let Some(offset) = entry.offset().to_debug_info_offset(&unit.header) else { continue };
            let name =
                [constants::DW_AT_linkage_name, constants::DW_AT_name].iter().find_map(|&at| {
                    let value = entry.attr_value(at)?;
                    let text = dwarf.attr_string(&unit, value).ok()?;
                    Some(text.to_string_lossy().into_owned())
                });
            let origin = [constants::DW_AT_abstract_origin, constants::DW_AT_specification]
                .iter()
                .find_map(|&at| reference(&unit, entry.attr_value(at)?));
            if name.is_some() || origin.is_some() {
                origins.insert(offset, (name, origin));
            }
            if entry.tag() == constants::DW_TAG_inlined_subroutine
                && let Some(origin) = origin
                && let Ok(mut ranges) = dwarf.die_ranges(&unit, entry)
            {
                while let Ok(Some(range)) = ranges.next() {
                    copies.push((range.begin, range.end, origin));
                }
            }
        }
    }

    let name_of = |mut offset: DebugInfoOffset| {
        // An inlined copy names its function through a chain of origins.
        for _ in 0..4 {
            match origins.get(&offset)? {
                (Some(name), _) => return Some(function_name(name).to_owned()),
                (None, Some(next)) => offset = *next,
                (None, None) => return None,
            }
        }
        None
    };
    copies
        .into_iter()
        .filter_map(|(start, end, origin)| Some((start & !1, end & !1, name_of(origin)?)))
        .collect()
}

/// The rows the report shows by default, in the order of `--sort added`:
/// a rescheduled pair last, then most instructions added first, then the
/// lowest score. See `is_rescheduled` in `hereticus-cli/src/main.rs`.
fn rows(diff: &Diff) -> Vec<&Match> {
    let mut shown: Vec<&Match> = diff
        .changed()
        .filter(|pair| pair.changed != Changed::Data)
        .filter(|pair| {
            !(pair.edits.total() == 0
                && pair.kinds.callees == 0
                && pair.kinds.texts == 0
                && pair.score >= 1.0)
        })
        .collect();
    let rescheduled =
        |pair: &Match| pair.changed == Changed::Reordered && !pair.kinds.touches_control_flow();
    shown.sort_by(|a, b| {
        rescheduled(a)
            .cmp(&rescheduled(b))
            .then_with(|| b.edits.added.cmp(&a.edits.added))
            .then_with(|| a.score.partial_cmp(&b.score).unwrap_or(core::cmp::Ordering::Equal))
    });
    shown
}

fn measure(case: &Case) -> Tally {
    let binaries = case.files.each_ref().map(|[library, _]| {
        let data = std::fs::read(library)
            .unwrap_or_else(|err| panic!("{}: {err}; run `just test`", library.display()));
        Binary::parse(&data).expect("the library parses")
    });
    let symbols = case.files.each_ref().map(|[_, debug]| debug_symbols(debug));
    let diff = diff_with(
        &binaries[0],
        &binaries[1],
        Options { use_names: UseNames::No, ..Default::default() },
    );
    let names = |side: usize, index: usize| -> BTreeSet<&str> {
        let function = &binaries[side].functions[index];
        let start = function.address & !1;
        let end = start + function.code.len() as u64;
        symbols[side]
            .iter()
            .filter(|(low, high, _)| *low < end && *high > start)
            .map(|(_, _, name)| name.as_str())
            .collect()
    };

    let mut tally =
        Tally { cases: 1, gone: diff.removed.len(), new: diff.added.len(), ..Tally::default() };
    for pair in &diff.matched {
        let (before, after) = (names(0, pair.before), names(1, pair.after));
        if before.is_empty() || after.is_empty() {
            continue;
        }
        if before.is_disjoint(&after) {
            tally.wrong += 1;
        } else {
            tally.right += 1;
        }
    }

    // A fix counts in a function that holds an inlined copy of it too.
    let copies = case.files.each_ref().map(|[_, debug]| inlined_copies(debug));
    let holds_fix_in = |side: usize, index: usize, found: &[Symbol]| {
        let function = &binaries[side].functions[index];
        let start = function.address & !1;
        let end = start + function.code.len() as u64;
        found
            .iter()
            .any(|(low, high, name)| *low < end && *high > start && case.fixes.contains(name))
    };
    let holds_fix = |side: usize, index: usize| {
        holds_fix_in(side, index, &symbols[side]) || holds_fix_in(side, index, &copies[side])
    };
    let in_library =
        symbols.iter().chain(&copies).flatten().any(|(_, _, name)| case.fixes.contains(name));
    tally.in_library = usize::from(in_library);
    let is_fix = |pair: &&Match| holds_fix(0, pair.before) || holds_fix(1, pair.after);
    let shown = rows(&diff);
    if let Some(rank) = shown.iter().position(is_fix) {
        let first = shown[rank];
        let by_name =
            holds_fix_in(0, first.before, &symbols[0]) || holds_fix_in(1, first.after, &symbols[1]);
        tally.by_inlining = usize::from(!by_name);
        tally.found = 1;
        tally.rank_sum = rank + 1;
        tally.top1 = usize::from(rank == 0);
        tally.top5 = usize::from(rank < 5);
    }
    tally
}

#[test]
fn the_ubuntu_updates_checked_against_their_symbols_are_locked() {
    let cases = cases();
    let tallies: Vec<Tally> = cases.par_iter().map(measure).collect();

    let mut libraries: BTreeMap<String, Tally> = BTreeMap::new();
    for (case, tally) in cases.iter().zip(&tallies) {
        *libraries.entry(format!("{} {}", case.library, case.arch)).or_default() += tally;
    }
    let mut all = Tally::default();
    for tally in libraries.values() {
        all += tally;
    }
    let mut out = String::new();
    writeln!(
        out,
        "{:22} {:>5} {:>6} {:>5} {:>5} {:>5} | {:>5} {:>5} {:>6} {:>5} {:>4} {:>4}",
        "library",
        "cases",
        "right",
        "wrong",
        "gone",
        "new",
        "in lib",
        "found",
        "inline",
        "ranks",
        "top1",
        "top5"
    )
    .unwrap();
    for (library, tally) in libraries.iter().chain([(&"all".to_owned(), &all)]) {
        writeln!(
            out,
            "{library:22} {:>5} {:>6} {:>5} {:>5} {:>5} | {:>5} {:>5} {:>6} {:>5} {:>4} {:>4}",
            tally.cases,
            tally.right,
            tally.wrong,
            tally.gone,
            tally.new,
            tally.in_library,
            tally.found,
            tally.by_inlining,
            tally.rank_sum,
            tally.top1,
            tally.top5
        )
        .unwrap();
    }
    insta::assert_snapshot!(out);
}
