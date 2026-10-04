//! Measure the matching and the ranking on the backport fixtures.
//!
//! Matching: the pairs of stripped builds, checked against the symbols, as
//! `tests/cross_build.rs` counts them. Ranking: where the first function of
//! the upstream fix sits among the changed rows, in the order the library
//! ranks them.
//!
//! Run with `cargo run --release --example research_bench -p hereticus`.

use std::collections::{BTreeSet, HashMap};
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
    /// For each order of [`ORDERS`]: the rank sum, top 1 and top 5.
    orders: Vec<(usize, usize, usize, f64)>,
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
    let is_fix_row = |pair: &Match| {
        names(1, pair.after).iter().any(|name| is_fix(project, name))
            || names(0, pair.before).iter().any(|name| is_fix(project, name))
    };
    let rank = ranked.iter().position(|pair| is_fix_row(pair));
    match rank {
        Some(rank) => {
            totals.rank_sum += rank + 1;
            totals.top1 += usize::from(rank == 0);
            totals.top5 += usize::from(rank < 5);
        }
        None => totals.missed += 1,
    }

    // Each other order, over the same rows.
    let features = features_of(&ranked, &stripped);
    if totals.orders.is_empty() {
        totals.orders = vec![(0, 0, 0, 0.0); ORDERS.len()];
    }
    for (slot, (_, order)) in ORDERS.iter().enumerate() {
        let mut keyed: Vec<(f64, usize)> =
            features.iter().enumerate().map(|(row, f)| (order(f), row)).collect();
        keyed.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap().then(a.1.cmp(&b.1)));
        if let Some(rank) = keyed.iter().position(|&(_, row)| is_fix_row(ranked[row])) {
            totals.orders[slot].0 += rank + 1;
            totals.orders[slot].1 += usize::from(rank == 0);
            totals.orders[slot].2 += usize::from(rank < 5);
            totals.orders[slot].3 += 1.0 / (rank + 1) as f64;
            if std::env::var_os("BENCH_VERBOSE").is_some() && slot == 2 {
                println!("  a+1idf: rank {}", rank + 1);
            }
        }
    }
    if std::env::var_os("BENCH_VERBOSE").is_some() {
        println!(
            "{project:9} {arch:8} {first:7} {second:7} rank {:>5} of {}",
            rank.map_or("-".to_owned(), |rank| (rank + 1).to_string()),
            ranked.len()
        );
    }
}

/// What an order may read of one row.
struct Features {
    edits: hereticus::matching::Edits,
    kinds: hereticus::matching::EditKinds,
    score: f64,
    rarity: f64,
    /// Instructions in the longer body.
    length: usize,
    /// IDF of each token added or removed, summed.
    idf_sum: f64,
    idf_max: f64,
    /// IDF of each token added, summed.
    idf_added: f64,
    idf2_added: f64,
    /// IDF of each pair of neighbors added or removed, summed.
    idf2_sum: f64,
    /// Count of added conditional branches, by bag.
    added_branches: usize,
    added_calls: usize,
    added_returns: usize,
}

type Order = fn(&Features) -> f64;

fn guards(f: &Features) -> f64 {
    (f.added_branches.min(3) + f.added_returns.min(2) + f.added_calls.min(2)) as f64
}

const ORDERS: &[(&str, Order)] = &[
    ("added", |f| f.edits.added as f64 - f.score * 1e-3),
    ("a+0.5idf", |f| f.edits.added as f64 + 0.5 * f.idf_added),
    ("a+1idf", |f| f.edits.added as f64 + f.idf_added),
    ("rarity", |f| f.rarity),
    ("a+2idf", |f| f.edits.added as f64 + 2.0 * f.idf_added),
    ("idf-added", |f| f.idf_added),
    ("a+1idf+2g", |f| f.edits.added as f64 + f.idf_added + 2.0 * guards(f)),
    ("a+1idf+5g", |f| f.edits.added as f64 + f.idf_added + 5.0 * guards(f)),
    ("a+2g", |f| f.edits.added as f64 + 2.0 * guards(f)),
    ("ln(a+idf)+g", |f| (1.0 + f.edits.added as f64 + f.idf_added).ln() + 0.5 * guards(f)),
    ("ln(a+idf)+.25g", |f| (1.0 + f.edits.added as f64 + f.idf_added).ln() + 0.25 * guards(f)),
];

fn body_tokens(binary: &Binary, index: usize) -> Vec<(u64, hereticus::norm::FlowShape)> {
    use core::hash::{Hash, Hasher};
    let function = &binary.functions[index];
    let arch = binary.isa_of(function).arch();
    let (insns, _) = hereticus::arch::decode_all(arch, &function.code, function.address);
    hereticus::norm::normalize_body_in(arch, &function.code, &insns, &binary.addresses)
        .into_iter()
        .map(|insn| {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            insn.hash(&mut hasher);
            (hasher.finish(), insn.flow)
        })
        .collect()
}

/// The items of `after` that `before` lacks, and those of `before` that
/// `after` lacks, each counted as a bag.
fn bag_difference<T: Ord + Clone>(before: &[T], after: &[T]) -> (Vec<T>, Vec<T>) {
    let mut counts: std::collections::BTreeMap<T, isize> = std::collections::BTreeMap::new();
    for item in after {
        *counts.entry(item.clone()).or_default() += 1;
    }
    for item in before {
        *counts.entry(item.clone()).or_default() -= 1;
    }
    let (mut added, mut removed) = (Vec::new(), Vec::new());
    for (item, count) in counts {
        for _ in 0..count.max(0) {
            added.push(item.clone());
        }
        for _ in 0..(-count).max(0) {
            removed.push(item.clone());
        }
    }
    (added, removed)
}

fn features_of(rows: &[&Match], stripped: &[Binary; 2]) -> Vec<Features> {
    use hereticus::norm::FlowShape;
    // (sign, token) so an added and a removed instruction differ.
    let mut edits: Vec<(Vec<(bool, u64)>, Vec<(bool, u64, u64)>, usize, [usize; 3])> = Vec::new();
    for pair in rows {
        let before = body_tokens(&stripped[0], pair.before);
        let after = body_tokens(&stripped[1], pair.after);
        let (added, removed) = bag_difference(&before, &after);
        let count = |list: &[(u64, FlowShape)], flow: FlowShape| {
            list.iter().filter(|t| t.1 == flow).count()
        };
        let guards = [
            count(&added, FlowShape::Branch),
            count(&added, FlowShape::Call),
            count(&added, FlowShape::Return) + count(&added, FlowShape::Jump),
        ];
        let mut tokens: Vec<(bool, u64)> = added.iter().map(|t| (true, t.0)).collect();
        tokens.extend(removed.iter().map(|t| (false, t.0)));
        let grams = |body: &[(u64, FlowShape)]| -> Vec<(u64, u64)> {
            body.windows(2).map(|w| (w[0].0, w[1].0)).collect()
        };
        let (added2, removed2) = bag_difference(&grams(&before), &grams(&after));
        let mut tokens2: Vec<(bool, u64, u64)> = added2.iter().map(|t| (true, t.0, t.1)).collect();
        tokens2.extend(removed2.iter().map(|t| (false, t.0, t.1)));
        edits.push((tokens, tokens2, before.len().max(after.len()), guards));
    }
    let rows_count = edits.len() as f64;
    let mut df1: HashMap<(bool, u64), usize> = HashMap::new();
    let mut df2: HashMap<(bool, u64, u64), usize> = HashMap::new();
    for (tokens, tokens2, _, _) in &edits {
        for token in tokens.iter().collect::<BTreeSet<_>>() {
            *df1.entry(*token).or_default() += 1;
        }
        for token in tokens2.iter().collect::<BTreeSet<_>>() {
            *df2.entry(*token).or_default() += 1;
        }
    }
    let idf = |df: usize| ((rows_count + 1.0) / (df as f64 + 1.0)).ln();
    rows.iter()
        .zip(&edits)
        .map(|(pair, (tokens, tokens2, length, guards))| {
            let weights: Vec<f64> = tokens.iter().map(|t| idf(df1[t])).collect();
            Features {
                edits: pair.edits,
                kinds: pair.kinds,
                score: pair.score,
                rarity: pair.rarity,
                length: *length,
                idf_sum: weights.iter().sum(),
                idf_max: weights.iter().copied().fold(0.0, f64::max),
                idf_added: tokens.iter().zip(&weights).filter(|(t, _)| t.0).map(|(_, w)| w).sum(),
                idf2_sum: tokens2.iter().map(|t| idf(df2[t])).sum(),
                idf2_added: tokens2.iter().filter(|t| t.0).map(|t| idf(df2[t])).sum(),
                added_branches: guards[0],
                added_calls: guards[1],
                added_returns: guards[2],
            }
        })
        .collect()
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

/// A published fix in two shipped releases: the files, and the function of
/// the first release that the fix edits, by address or by name.
const CVES: &[(&str, &str, &str, &str)] = &[
    (
        "CVE-2025-24257",
        "hereticus-apple/cve/18.3.2/com.apple.iokit.IOGPUFamily",
        "hereticus-apple/cve/18.4/com.apple.iokit.IOGPUFamily",
        "0xfffffff009a765c0",
    ),
    (
        "CVE-2026-28825",
        "hereticus-apple/cve/26.3.1/com.apple.filesystems.smbfs",
        "hereticus-apple/cve/25E246/com.apple.filesystems.smbfs",
        "_smb2_rq_decompress_read",
    ),
    (
        "CVE-2025-62526",
        "hereticus-openwrt-cve/24.10.3/armsr-armv8/sbin/ubusd",
        "hereticus-openwrt-cve/24.10.4/armsr-armv8/sbin/ubusd",
        "0x4a3c",
    ),
    (
        "CVE-2021-30883",
        "hereticus-apple/cve/15.0.1/19A348__iPhone12,1/kernelcache.release.iPhone12,1",
        "hereticus-apple/cve/15.0.2/19A404__iPhone12,1/kernelcache.release.iPhone12,1",
        "0xfffffff009c0b13c",
    ),
];

/// Rank each published fix under each order, with names as the tool uses
/// them by default.
fn measure_cves() {
    let cache = Path::new(&std::env::var("HOME").expect("a home")).join(".cache");
    for &(cve, before, after, fix) in CVES {
        let parse = |path: &str| {
            let data = std::fs::read(cache.join(path)).expect("the binary is cached");
            Binary::parse(&data).expect("the binary parses")
        };
        let stripped = [parse(before), parse(after)];
        let diff = hereticus::matching::diff(&stripped[0], &stripped[1]);
        let ranked = rows(&diff);
        let is_fix = |pair: &Match| {
            let function = &stripped[0].functions[pair.before];
            match fix.strip_prefix("0x") {
                Some(hex) => function.address == u64::from_str_radix(hex, 16).expect("hex"),
                None => function.name == fix,
            }
        };
        let features = features_of(&ranked, &stripped);
        let mut line = format!("{cve} ({} rows):", ranked.len());
        for (name, order) in ORDERS {
            let mut keyed: Vec<(f64, usize)> =
                features.iter().enumerate().map(|(row, f)| (order(f), row)).collect();
            keyed.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap().then(a.1.cmp(&b.1)));
            let rank = keyed.iter().position(|&(_, row)| is_fix(ranked[row]));
            line +=
                &format!(" {name}={}", rank.map_or("-".to_owned(), |rank| (rank + 1).to_string()));
        }
        println!("{line}");
    }
}

fn main() {
    if std::env::args().any(|arg| arg == "--cves") {
        measure_cves();
        return;
    }
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
        if all.orders.is_empty() {
            all.orders = vec![(0, 0, 0, 0.0); ORDERS.len()];
        }
        for (sum, one) in all.orders.iter_mut().zip(&totals.orders) {
            sum.0 += one.0;
            sum.1 += one.1;
            sum.2 += one.2;
            sum.3 += one.3;
        }
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
    for ((name, _), (ranks, top1, top5, mrr)) in ORDERS.iter().zip(&all.orders) {
        println!(
            "order {name:16} ranks {ranks:>5} top1 {top1:>3} top5 {top5:>3} mrr {:.3}",
            mrr / all.cases as f64
        );
    }
}
