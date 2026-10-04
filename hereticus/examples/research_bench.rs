//! Measure the matching and the ranking on the backport fixtures.
//!
//! Matching: the pairs of stripped builds, checked against the symbols, as
//! `tests/cross_build.rs` counts them. Ranking: where the first function of
//! the upstream fix sits among the changed rows, in the order the library
//! ranks them.
//!
//! Run with `cargo run --release --example research_bench -p hereticus`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hereticus::matching::{Changed, Diff, Match, Options, UseNames, diff_with};
use hereticus::obj::Binary;

const ARCHES: &[&str] = &["arm", "thumb", "aarch64", "mips", "mipsel"];
const LEVELS: &[(&str, &str)] = &[
    ("O2", "O2"),
    ("O1", "O2"),
    ("O2", "O3"),
    ("O2", "Os"),
    ("O3", "Os"),
    ("gcc-O2", "gcc-Os"),
    ("O2", "gcc-O2"),
];

fn backports() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/backports")
}

fn read(project: &str, variant: &str, arch: &str, level: &str, file: &str) -> Binary {
    let path = backports().join(format!("{project}-{variant}/{arch}-{level}/{file}"));
    let data = std::fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    Binary::parse(&data).expect("a fixture library must parse")
}

fn function_name(symbol: &str) -> &str {
    [".isra.", ".constprop.", ".part.", ".cold"]
        .iter()
        .filter_map(|suffix| symbol.find(suffix))
        .min()
        .map_or(symbol, |end| &symbol[..end])
}

fn names_over(symbols: &Binary, range: core::ops::Range<u64>) -> BTreeSet<String> {
    symbols
        .functions
        .iter()
        .filter(|symbol| {
            symbol.address < range.end && symbol.address + symbol.code.len() as u64 > range.start
        })
        .map(|symbol| function_name(&symbol.name).to_owned())
        .collect()
}

fn is_fix(project: &str, name: &str) -> bool {
    match project {
        "zlib" => name == "inflate",
        "lua" => name == "luaZ_fill" || name == "luaZ_init",
        "tinyxml2" => name == "_ZN8tinyxml27XMLNode9ParseDeepEPcPNS_7StrPairEPi",
        "smallvec" => name.contains("E11insert_many"),
        _ => unreachable!(),
    }
}

#[derive(Default)]
struct Totals {
    right: usize,
    wrong: usize,
    gone: usize,
    new: usize,
    /// Sum over the comparisons of the rank of the fix, from 1.
    rank_sum: usize,
    top1: usize,
    top5: usize,
    /// Comparisons where no changed row holds the fix.
    missed: usize,
    cases: usize,
}

fn measure(project: &str, arch: &str, first: &str, second: &str, totals: &mut Totals) {
    let symbols = [
        read(project, "before", arch, first, "lib.so"),
        read(project, "after", arch, second, "lib.so"),
    ];
    let stripped = [
        read(project, "before", arch, first, "lib-stripped.so"),
        read(project, "after", arch, second, "lib-stripped.so"),
    ];
    let diff: Diff = diff_with(
        &stripped[0],
        &stripped[1],
        Options { use_names: UseNames::No, ..Default::default() },
    );
    let names = |side: usize, index: usize| {
        let function = &stripped[side].functions[index];
        names_over(&symbols[side], function.address..function.address + function.code.len() as u64)
    };
    totals.gone += diff.removed.len();
    totals.new += diff.added.len();
    for pair in &diff.matched {
        let (left, right) = (names(0, pair.before), names(1, pair.after));
        if left.is_empty() || right.is_empty() {
            continue;
        }
        if left.is_disjoint(&right) {
            totals.wrong += 1;
            if std::env::var_os("BENCH_WHERE").is_some() {
                let truth =
                    (0..stripped[1].functions.len()).find(|&y| !names(1, y).is_disjoint(&left));
                let state = match truth {
                    None => "absent",
                    Some(y) if diff.added.contains(&y) => "free",
                    Some(y) => match diff.matched.iter().find(|p| p.after == y) {
                        Some(p) if !names(0, p.before).is_disjoint(&names(1, y)) => "paired-right",
                        Some(_) => "paired-wrong",
                        None => "?",
                    },
                };
                let body = |side: usize, index: usize| {
                    let binary = &stripped[side];
                    let function = &binary.functions[index];
                    let arch = binary.isa_of(function).arch();
                    let (insns, _) =
                        hereticus::arch::decode_all(arch, &function.code, function.address);
                    hereticus::norm::normalize_body_in(
                        arch,
                        &function.code,
                        &insns,
                        &binary.addresses,
                    )
                };
                let x = body(0, pair.before);
                let wrong = hereticus::matching::similarity(&x, &body(1, pair.after));
                let right =
                    truth.map_or(-1.0, |y| hereticus::matching::similarity(&x, &body(1, y)));
                println!(
                    "WHERE {:?} {state} wrong {wrong:.2} truth {right:.2} len {}",
                    pair.confidence,
                    x.len()
                );
            }
            if std::env::var_os("BENCH_WRONG").is_some() {
                println!(
                    "WRONG {:?} {:.2} {:?} {left:?} {right:?}",
                    pair.confidence, pair.score, pair.changed
                );
            }
        } else {
            totals.right += 1;
        }
    }

    totals.cases += 1;
    let ranked = rows(&diff);
    let rank = ranked.iter().position(|pair| {
        names(1, pair.after).iter().any(|name| is_fix(project, name))
            || names(0, pair.before).iter().any(|name| is_fix(project, name))
    });
    match rank {
        Some(rank) => {
            totals.rank_sum += rank + 1;
            totals.top1 += usize::from(rank == 0);
            totals.top5 += usize::from(rank < 5);
        }
        None => totals.missed += 1,
    }
    if std::env::var_os("BENCH_VERBOSE").is_some() {
        println!(
            "{project:9} {arch:8} {first:7} {second:7} rank {:>5} of {}",
            rank.map_or("-".to_owned(), |rank| (rank + 1).to_string()),
            ranked.len()
        );
    }
}

/// The rows the report shows by default, in its default order: most
/// instructions added first, then the lowest score.
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
    shown.sort_by(|a, b| {
        b.edits
            .added
            .cmp(&a.edits.added)
            .then_with(|| a.score.partial_cmp(&b.score).unwrap_or(core::cmp::Ordering::Equal))
    });
    shown
}

fn main() {
    println!(
        "{:16} {:>6} {:>6} {:>6} {:>6} | {:>5} {:>4} {:>4} {:>6}",
        "levels", "right", "wrong", "gone", "new", "ranks", "top1", "top5", "missed"
    );
    let mut all = Totals::default();
    for &(first, second) in LEVELS {
        let built_by_gcc = first.starts_with("gcc") || second.starts_with("gcc");
        let projects: &[&str] = if built_by_gcc {
            &["zlib", "lua", "tinyxml2"]
        } else {
            &["zlib", "lua", "tinyxml2", "smallvec"]
        };
        let mut totals = Totals::default();
        for project in projects {
            for arch in ARCHES {
                measure(project, arch, first, second, &mut totals);
            }
        }
        println!(
            "{:16} {:>6} {:>6} {:>6} {:>6} | {:>5} {:>4} {:>4} {:>6}",
            format!("{first}/{second}"),
            totals.right,
            totals.wrong,
            totals.gone,
            totals.new,
            totals.rank_sum,
            totals.top1,
            totals.top5,
            totals.missed
        );
        all.right += totals.right;
        all.wrong += totals.wrong;
        all.gone += totals.gone;
        all.new += totals.new;
        all.rank_sum += totals.rank_sum;
        all.top1 += totals.top1;
        all.top5 += totals.top5;
        all.missed += totals.missed;
        all.cases += totals.cases;
    }
    println!(
        "{:16} {:>6} {:>6} {:>6} {:>6} | {:>5} {:>4} {:>4} {:>6}  ({} cases)",
        "all",
        all.right,
        all.wrong,
        all.gone,
        all.new,
        all.rank_sum,
        all.top1,
        all.top5,
        all.missed,
        all.cases
    );
}
