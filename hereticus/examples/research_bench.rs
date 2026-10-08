//! Measure the matching and the ranking on the backport fixtures.
//!
//! Matching: the pairs of stripped builds, checked against the symbols, as
//! `tests/cross_build.rs` counts them. Ranking: where the first function of
//! the upstream fix sits among the changed rows, in the order the library
//! ranks them.
//!
//! Run with `cargo run --release --example research_bench -p hereticus`.
//! `--cves` ranks published fixes, `--ubuntu` measures Ubuntu security
//! updates, and `--kernels` checks the pairs of the OpenWrt kernels against
//! their symbols.

/// See `ALLOCATOR` in `hereticus-cli/src/main.rs`.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

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
    // GCC names a local function `.lto_priv.N` where it built with LTO,
    // as Ubuntu does for arm64 and not for armhf.
    [".isra.", ".constprop.", ".part.", ".cold", ".lto_priv."]
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
    /// Comparisons that [`Totals::missed`] counts, where a function of the
    /// fix gone or new names a function of the fix as in its place.
    found_in_place: usize,
    /// Hints of a place, `NearMiss::in_place`, right and wrong by the
    /// symbols.
    places_right: usize,
    places_wrong: usize,
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

    // The hints of a place, on the rows of functions gone and new.
    let hints = diff
        .near_misses
        .iter()
        .filter_map(|miss| Some((miss.unmatched, miss.in_place?)))
        .chain(
            diff.added_near_misses.iter().filter_map(|miss| Some((miss.in_place?, miss.unmatched))),
        )
        .collect::<BTreeSet<_>>();
    let mut fix_in_place = false;
    for &(x, y) in &hints {
        let (left, right) = (names(0, x), names(1, y));
        if left.is_empty() || right.is_empty() {
            continue;
        }
        if left.is_disjoint(&right) {
            totals.places_wrong += 1;
        } else {
            totals.places_right += 1;
        }
        let holds_fix = |side: &BTreeSet<String>| side.iter().any(|name| is_fix(project, name));
        fix_in_place |= holds_fix(&left) && holds_fix(&right);
    }
    totals.found_in_place += usize::from(rank.is_none() && fix_in_place);

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
    score: f64,
    /// See `Match::rarity`.
    rarity: f64,
    /// IDF of each instruction added, summed, by bag.
    idf_added: f64,
    /// One minus the cosine of the added instructions, as a vector of
    /// counts, against the sum of all the rows' vectors.
    outlier: f64,
    /// BM25 of the added instructions at k1 = 0.5, 1.2 and 3: each distinct
    /// instruction counts its IDF times a count that saturates.
    bm25: [f64; 3],
    /// Conditional branches added, by bag.
    added_branches: usize,
    /// Calls added, by bag.
    added_calls: usize,
    /// Jumps and returns added, by bag.
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
    ("bm25 k0.5", |f| f.bm25[0]),
    ("bm25 k1.2", |f| f.bm25[1]),
    ("bm25 k3", |f| f.bm25[2]),
    ("a+bm25 k1.2", |f| f.edits.added as f64 + f.bm25[1]),
    ("a*outlier", |f| f.edits.added as f64 * f.outlier),
    ("rarity*outlier", |f| f.rarity * f.outlier),
    ("rarity*(0.5+outlier)", |f| f.rarity * (0.5 + f.outlier)),
    ("a+2bm25 k1.2", |f| f.edits.added as f64 + 2.0 * f.bm25[1]),
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

/// The features of each row. The IDF counts over the rows, as
/// `Match::rarity` counts over the changed pairs.
fn features_of(rows: &[&Match], stripped: &[Binary; 2]) -> Vec<Features> {
    use hereticus::norm::FlowShape;
    let added: Vec<Vec<(u64, FlowShape)>> = rows
        .iter()
        .map(|pair| {
            let before = body_tokens(&stripped[0], pair.before);
            let after = body_tokens(&stripped[1], pair.after);
            bag_difference(&before, &after).0
        })
        .collect();
    let mut df: HashMap<u64, usize> = HashMap::new();
    for tokens in &added {
        for token in tokens.iter().map(|t| t.0).collect::<BTreeSet<_>>() {
            *df.entry(token).or_default() += 1;
        }
    }
    let idf = |df: usize| ((rows.len() as f64 + 1.0) / (df as f64 + 1.0)).ln();
    let mut centroid: HashMap<u64, f64> = HashMap::new();
    for tokens in &added {
        for token in tokens {
            *centroid.entry(token.0).or_default() += 1.0;
        }
    }
    let centroid_norm = centroid.values().map(|v| v * v).sum::<f64>().sqrt();
    let outlier = |tokens: &[(u64, FlowShape)]| {
        let mut counts: HashMap<u64, f64> = HashMap::new();
        for token in tokens {
            *counts.entry(token.0).or_default() += 1.0;
        }
        let norm = counts.values().map(|v| v * v).sum::<f64>().sqrt();
        if norm == 0.0 || centroid_norm == 0.0 {
            return 0.0;
        }
        let dot: f64 = counts.iter().map(|(t, c)| c * centroid[t]).sum();
        1.0 - dot / (norm * centroid_norm)
    };
    rows.iter()
        .zip(&added)
        .map(|(pair, tokens)| {
            let count = |flow: FlowShape| tokens.iter().filter(|t| t.1 == flow).count();
            Features {
                edits: pair.edits,
                score: pair.score,
                rarity: pair.rarity,
                idf_added: tokens.iter().map(|t| idf(df[&t.0])).sum(),
                outlier: outlier(tokens),
                bm25: [0.5, 1.2, 3.0].map(|k1| {
                    let mut counts: HashMap<u64, f64> = HashMap::new();
                    for token in tokens {
                        *counts.entry(token.0).or_default() += 1.0;
                    }
                    counts
                        .iter()
                        .map(|(token, &tf)| idf(df[token]) * tf * (k1 + 1.0) / (tf + k1))
                        .sum()
                }),
                added_branches: count(FlowShape::Branch),
                added_calls: count(FlowShape::Call),
                added_returns: count(FlowShape::Return) + count(FlowShape::Jump),
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
        "CVE-2024-23265",
        "hereticus-apple/cve/17.3.1/com.apple.driver.AppleDiskImages2",
        "hereticus-apple/cve/17.4/com.apple.driver.AppleDiskImages2",
        "0xfffffff028a156c8",
    ),
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
        "CVE-2025-62526 A32",
        "hereticus-openwrt-cve/24.10.3/armsr-armv7/sbin/ubusd",
        "hereticus-openwrt-cve/24.10.4/armsr-armv7/sbin/ubusd",
        "0x3e34",
    ),
    (
        "CVE-2025-62526 MIPS16e BE",
        "hereticus-openwrt-cve/24.10.3/malta-be/sbin/ubusd",
        "hereticus-openwrt-cve/24.10.4/malta-be/sbin/ubusd",
        "0x39e0",
    ),
    (
        "CVE-2025-62526 MIPS16e LE",
        "hereticus-openwrt-cve/24.10.3/malta-le/sbin/ubusd",
        "hereticus-openwrt-cve/24.10.4/malta-le/sbin/ubusd",
        "0x3b0c",
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

/// A board of `tests/openwrt.rs`: the name its files carry, the target
/// whose kernel it runs, how its code reads, and where its kernel is linked.
const BOARDS: &[(&str, &str, hereticus::obj::Isa, u64)] = {
    use hereticus::obj::Isa;
    &[
        ("arm-ex6100v2", "ipq40xx-generic", Isa::Arm32, 0xc020_8000),
        ("mipsbe-eap245v3", "ath79-generic", Isa::Mips32Be, 0x8006_0000),
        ("mipsel-r6220", "ramips-mt7621", Isa::Mips32, 0x8000_1000),
        ("arm-a385dbap", "mvebu-cortexa9", Isa::Arm32, 0xc000_8000),
        ("mipsbe-vr200", "lantiq-xrx200", Isa::Mips32Be, 0x8000_2000),
        ("mipsel-mt300nv2", "ramips-mt76x8", Isa::Mips32, 0x8000_0000),
    ]
};

/// The releases `tests/openwrt.rs` compares, and the boards it compares
/// them on: the point release on all, the two kernel upgrades on three.
const KERNEL_RELEASES: &[(&str, &str, usize)] =
    &[("22.03.2", "22.03.5", 6), ("21.02.7", "22.03.2", 3), ("22.03.5", "23.05.5", 3)];

/// The names of the symbols that overlap `range`, from symbols sorted by
/// their start.
fn names_in(symbols: &[(u64, u64, String)], range: core::ops::Range<u64>) -> BTreeSet<String> {
    let first = symbols.partition_point(|symbol| symbol.0 <= range.start).saturating_sub(1);
    symbols[first..]
        .iter()
        .take_while(|symbol| symbol.0 < range.end)
        .filter(|symbol| symbol.1 > range.start)
        .map(|symbol| symbol.2.clone())
        .collect()
}

/// Check the pairs of each OpenWrt kernel of `tests/openwrt.rs` against the
/// symbols of its build, which `fixtures/openwrt_debug.py` fetched, by the
/// stage that paired them.
///
/// A wrong pair counts as proven where its true partner exists by name;
/// the others can be one function renamed. `BENCH_WHERE=1` shows where
/// the true partner of each wrong pair went: absent, free, or paired.
fn measure_kernels() {
    use std::collections::BTreeMap;
    let firmware = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/openwrt");
    let debug =
        Path::new(&std::env::var("HOME").expect("a home")).join(".cache/hereticus-openwrt-debug");
    let mut stages: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    println!(
        "{:36} {:>7} {:>7} {:>6} {:>6} {:>6} {:>6}",
        "kernel", "starts", "right", "wrong", "proven", "gone", "new"
    );
    let only = std::env::var("BENCH_ONLY").ok();
    for &(first, second, boards) in KERNEL_RELEASES {
        for &(board, target, isa, base) in &BOARDS[..boards] {
            if only.as_deref().is_some_and(|only| !format!("{board} {first}").contains(only)) {
                continue;
            }
            let read = |release: &str| {
                let path = firmware.join(format!("{board}-kernel-{release}.bin"));
                let data = std::fs::read(&path).expect("run `just firmware`");
                Binary::parse_raw(&data, base, isa).expect("the kernel reads")
            };
            let symbols = |release: &str| {
                let path = debug.join(release).join(target).join("vmlinux");
                debug_symbols(path.to_str().expect("a path"))
            };
            let kernels = [read(first), read(second)];
            let answers = [symbols(first), symbols(second)];
            // How many recovered functions start where a symbol does: the
            // debug file belongs to the same build only where most do.
            let starts: usize = (0..2)
                .map(|side| {
                    let known: BTreeSet<u64> =
                        answers[side].iter().map(|symbol| symbol.0).collect();
                    kernels[side].functions.iter().filter(|f| known.contains(&f.address)).count()
                })
                .sum();
            let functions = kernels[0].functions.len() + kernels[1].functions.len();
            let diff = diff_with(
                &kernels[0],
                &kernels[1],
                Options { use_names: UseNames::No, ..Default::default() },
            );
            let names = |side: usize, index: usize| {
                let function = &kernels[side].functions[index];
                names_in(
                    &answers[side],
                    function.address..function.address + function.code.len() as u64,
                )
            };
            // A wrong pair is proven wrong where a name of one side lives on
            // in the other build: the true partner exists. Otherwise it can
            // be one function renamed.
            let all_names: [BTreeSet<&str>; 2] =
                [0, 1].map(|side| answers[side].iter().map(|symbol| symbol.2.as_str()).collect());
            let mut proven = 0;
            // Where the true partner of each wrong pair is.
            let after_of_name: HashMap<String, usize> = (0..kernels[1].functions.len())
                .flat_map(|y| names(1, y).into_iter().map(move |name| (name, y)))
                .collect();
            let partner_of_after: HashMap<usize, usize> =
                diff.matched.iter().map(|pair| (pair.after, pair.before)).collect();
            let (mut right, mut wrong) = (0, 0);
            for pair in &diff.matched {
                let (left, right_names) = (names(0, pair.before), names(1, pair.after));
                if left.is_empty() || right_names.is_empty() {
                    continue;
                }
                let stage = stages.entry(format!("{:?}", pair.confidence)).or_default();
                if left.is_disjoint(&right_names) {
                    wrong += 1;
                    stage.1 += 1;
                    let is_proven = left.iter().any(|name| all_names[1].contains(name.as_str()))
                        || right_names.iter().any(|name| all_names[0].contains(name.as_str()));
                    proven += usize::from(is_proven);
                    stage.2 += usize::from(is_proven);
                    let truth = left.iter().find_map(|name| after_of_name.get(name)).copied();
                    let place = match truth {
                        None => "absent",
                        Some(y) => match partner_of_after.get(&y) {
                            None => "free",
                            Some(&x) if !names(0, x).is_disjoint(&names(1, y)) => "paired-right",
                            Some(_) => "paired-wrong",
                        },
                    };
                    if std::env::var_os("BENCH_WHERE").is_some() {
                        println!("WHERE {:?} {place}", pair.confidence);
                    }
                    if std::env::var_os("BENCH_WRONG").is_some() {
                        println!(
                            "WRONG {:?} {:.2} {} {} {is_proven} {left:?} {right_names:?}",
                            pair.confidence,
                            pair.score,
                            kernels[0].functions[pair.before].code.len(),
                            kernels[1].functions[pair.after].code.len(),
                        );
                    }
                } else {
                    right += 1;
                    stage.0 += 1;
                    if std::env::var_os("BENCH_RIGHT").is_some() {
                        println!(
                            "RIGHT {:?} {:.2} {} {}",
                            pair.confidence,
                            pair.score,
                            kernels[0].functions[pair.before].code.len(),
                            kernels[1].functions[pair.after].code.len(),
                        );
                    }
                }
            }
            println!(
                "{:36} {:>6.1}% {right:>7} {wrong:>6} {proven:>6} {:>6} {:>6}",
                format!("{board} {first}/{second}"),
                100.0 * starts as f64 / functions as f64,
                diff.removed.len(),
                diff.added.len()
            );
        }
    }
    for (stage, (right, wrong, proven)) in &stages {
        println!("stage {stage:16} right {right:>7} wrong {wrong:>5} proven {proven:>5}");
    }
}

/// The functions of a debug file: start, end and name.
fn debug_symbols(path: &str) -> Vec<(u64, u64, String)> {
    use object::{Object, ObjectSymbol, SymbolKind};
    let data = std::fs::read(path).expect("the debug file is cached");
    let file = object::File::parse(&*data).expect("the debug file parses");
    let mut symbols: Vec<(u64, u64, String)> = file
        .symbols()
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
        .collect();
    symbols.sort();
    symbols
}

/// Measure each Ubuntu security update that `fixtures/ubuntu_cves.py`
/// fetched: the pairs of the stripped libraries, checked against the debug
/// symbols, and the rank of the first function the update's patches touch.
fn measure_ubuntu() {
    let cache =
        Path::new(&std::env::var("HOME").expect("a home")).join(".cache/hereticus-ubuntu-cve");
    let text =
        std::fs::read_to_string(cache.join("cases.json")).expect("run fixtures/ubuntu_cves.py");
    let cases = parse_cases(&text);
    let use_names = match std::env::var("NAMES").as_deref() {
        Ok("yes") => UseNames::Yes,
        _ => UseNames::No,
    };
    use rayon::prelude::*;
    let mut all = Totals::default();
    let mut libraries: std::collections::BTreeMap<String, Totals> = Default::default();
    let results: Vec<(String, Totals, String)> =
        cases.par_iter().map(|case| measure_ubuntu_case(case, use_names)).collect();
    for (key, one, line) in results {
        if std::env::var_os("BENCH_VERBOSE").is_some() {
            println!("{line}");
        }
        add(libraries.entry(key).or_default(), &one);
    }
    println!(
        "{:28} {:>6} {:>6} {:>6} {:>6} {:>6}",
        "library", "right", "wrong", "gone", "new", "cases"
    );
    for (library, totals) in &libraries {
        println!(
            "{library:28} {:>6} {:>6} {:>6} {:>6} {:>6}",
            totals.right, totals.wrong, totals.gone, totals.new, totals.cases
        );
        add(&mut all, totals);
    }
    println!(
        "{:28} {:>6} {:>6} {:>6} {:>6} {:>6}  (fix found in {} of {})",
        "all",
        all.right,
        all.wrong,
        all.gone,
        all.new,
        all.cases,
        all.cases - all.missed,
        all.cases
    );
    let ranked_cases = (all.cases - all.missed) as f64;
    for ((name, _), (ranks, top1, top5, mrr)) in ORDERS.iter().zip(&all.orders) {
        println!(
            "order {name:16} ranks {ranks:>5} top1 {top1:>3} top5 {top5:>3} mrr {:.3}",
            mrr / ranked_cases
        );
    }
}

/// One case of [`measure_ubuntu`]: its library, its counts and its line.
fn measure_ubuntu_case(case: &Case, use_names: UseNames) -> (String, Totals, String) {
    let binaries = [0, 1].map(|side| {
        let data = std::fs::read(&case.files[side].0).expect("cached");
        Binary::parse(&data).expect("the library parses")
    });
    let symbols = [0, 1].map(|side| debug_symbols(&case.files[side].1));
    let diff = diff_with(&binaries[0], &binaries[1], Options { use_names, ..Default::default() });
    let names = |side: usize, index: usize| -> BTreeSet<String> {
        let function = &binaries[side].functions[index];
        let (start, end) =
            (function.address & !1, (function.address & !1) + function.code.len() as u64);
        symbols[side]
            .iter()
            .filter(|(low, high, _)| *low < end && *high > start)
            .map(|(_, _, name)| name.clone())
            .collect()
    };
    let mut one = Totals::default();
    let totals = &mut one;
    totals.gone += diff.removed.len();
    totals.new += diff.added.len();
    for pair in &diff.matched {
        let (left, right) = (names(0, pair.before), names(1, pair.after));
        if left.is_empty() || right.is_empty() {
            continue;
        }
        if left.is_disjoint(&right) {
            totals.wrong += 1;
            if std::env::var_os("BENCH_WRONG").is_some() {
                println!(
                    "WRONG {} {} {:?} {:.2} {left:?} {right:?}",
                    case.library, case.arch, pair.confidence, pair.score
                );
            }
        } else {
            totals.right += 1;
        }
    }

    totals.cases += 1;
    let ranked = rows(&diff);
    let is_fix_row = |pair: &Match| {
        names(0, pair.before)
            .iter()
            .chain(&names(1, pair.after))
            .any(|name| case.fixes.contains(name))
    };
    let features = features_of(&ranked, &binaries);
    if totals.orders.is_empty() {
        totals.orders = vec![(0, 0, 0, 0.0); ORDERS.len()];
    }
    let mut line = format!(
        "{} {} {} -> {} ({} rows):",
        case.library,
        case.arch,
        case.before,
        case.after,
        ranked.len()
    );
    let mut any = false;
    for (slot, (name, order)) in ORDERS.iter().enumerate() {
        let mut keyed: Vec<(f64, usize)> =
            features.iter().enumerate().map(|(row, f)| (order(f), row)).collect();
        keyed.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap().then(a.1.cmp(&b.1)));
        let rank = keyed.iter().position(|&(_, row)| is_fix_row(ranked[row]));
        if let Some(rank) = rank {
            any = true;
            totals.orders[slot].0 += rank + 1;
            totals.orders[slot].1 += usize::from(rank == 0);
            totals.orders[slot].2 += usize::from(rank < 5);
            totals.orders[slot].3 += 1.0 / (rank + 1) as f64;
        }
        line += &format!(" {name}={}", rank.map_or("-".to_owned(), |rank| (rank + 1).to_string()));
    }
    if !any {
        totals.missed += 1;
    }
    (format!("{} {}", case.library, case.arch), one, line)
}

fn add(all: &mut Totals, one: &Totals) {
    all.right += one.right;
    all.wrong += one.wrong;
    all.gone += one.gone;
    all.new += one.new;
    all.missed += one.missed;
    all.cases += one.cases;
    if all.orders.is_empty() {
        all.orders = vec![(0, 0, 0, 0.0); ORDERS.len()];
    }
    for (sum, one) in all.orders.iter_mut().zip(&one.orders) {
        sum.0 += one.0;
        sum.1 += one.1;
        sum.2 += one.2;
        sum.3 += one.3;
    }
}

struct Case {
    library: String,
    arch: String,
    before: String,
    after: String,
    /// The library and its debug file, before and after.
    files: [(String, String); 2],
    fixes: BTreeSet<String>,
}

/// Read `cases.json` without a JSON crate: each field is a string or a
/// list of strings.
fn parse_cases(text: &str) -> Vec<Case> {
    let strings = |object: &str, key: &str| -> Vec<String> {
        let start = object.find(&format!("\"{key}\":")).expect(key) + key.len() + 3;
        let rest = &object[start..];
        let end = if rest.trim_start().starts_with('[') {
            let mut depth = 0;
            rest.char_indices()
                .find(|&(_, c)| {
                    depth += match c {
                        '[' => 1,
                        ']' => -1,
                        _ => 0,
                    };
                    c == ']' && depth == 0
                })
                .map_or(rest.len(), |(at, _)| at + 1)
        } else {
            rest.find(['\n', ',']).unwrap_or(rest.len())
        };
        rest[..end].split('"').skip(1).step_by(2).map(str::to_owned).collect()
    };
    text.split("\n {")
        .skip(1)
        .map(|object| {
            let files = strings(object, "files");
            Case {
                library: strings(object, "library").remove(0),
                arch: strings(object, "arch").remove(0),
                before: strings(object, "before").remove(0),
                after: strings(object, "after").remove(0),
                files: [(files[0].clone(), files[1].clone()), (files[2].clone(), files[3].clone())],
                fixes: strings(object, "fixes").into_iter().collect(),
            }
        })
        .collect()
}

fn main() {
    if std::env::args().any(|arg| arg == "--ubuntu") {
        measure_ubuntu();
        return;
    }
    if std::env::args().any(|arg| arg == "--kernels") {
        measure_kernels();
        return;
    }
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
        all.found_in_place += totals.found_in_place;
        all.places_right += totals.places_right;
        all.places_wrong += totals.places_wrong;
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
    println!(
        "in place: {} right, {} wrong; the fix found in place in {} of {} missed",
        all.places_right, all.places_wrong, all.found_in_place, all.missed
    );
    for ((name, _), (ranks, top1, top5, mrr)) in ORDERS.iter().zip(&all.orders) {
        println!(
            "order {name:16} ranks {ranks:>5} top1 {top1:>3} top5 {top5:>3} mrr {:.3}",
            mrr / all.cases as f64
        );
    }
}
