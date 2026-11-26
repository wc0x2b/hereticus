//! Scratch: count the lines that the IL and the high IL show as removed,
//! added or rewritten, on the same changed pairs, to measure how much of a
//! diff each view leaves for a reader.
//!
//! `BACKPORTS=1` reads the backports of `fixtures/build/backports`, where
//! each pair holds one fix; else `PAIRS` pairs of Assemblage.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use hereticus::matching::{Changed, DiffLine, Options, View, diff_with, instruction_diff_in};
use hereticus::obj::Binary;
use rayon::prelude::*;

/// The lines of the diffs of one view.
#[derive(Clone, Copy, Default)]
struct Counts {
    /// Every line.
    lines: usize,
    /// The lines that differ: removed, added, or rewritten.
    changed: usize,
}

impl Counts {
    fn of(lines: &[DiffLine]) -> Self {
        let changed = lines.iter().filter(|line| !matches!(line, DiffLine::Same(_))).count();
        Self { lines: lines.len(), changed }
    }

    fn add(&mut self, other: Self) {
        self.lines += other.lines;
        self.changed += other.changed;
    }
}

/// The cases to compare, each the paths of two binaries.
fn cases() -> Vec<(String, String)> {
    if std::env::var_os("BACKPORTS").is_some() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/backports");
        let mut cases = Vec::new();
        for entry in std::fs::read_dir(&root).unwrap().flatten() {
            let name = entry.file_name().into_string().unwrap();
            let Some(project) = name.strip_suffix("-before") else { continue };
            for config in std::fs::read_dir(entry.path()).unwrap().flatten() {
                let config = config.file_name().into_string().unwrap();
                let side = |which: &str| {
                    root.join(format!("{project}-{which}/{config}/lib.so")).display().to_string()
                };
                cases.push((side("before"), side("after")));
            }
        }
        return cases;
    }
    let home = std::env::var("HOME").unwrap();
    let text =
        std::fs::read_to_string(format!("{home}/.cache/hereticus-assemblage/cases.json")).unwrap();
    let cases: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();
    let count: usize = std::env::var("PAIRS").ok().and_then(|n| n.parse().ok()).unwrap_or(300);
    let stride = (cases.len() / count).max(1);
    cases
        .iter()
        .step_by(stride)
        .take(count)
        .filter_map(|case| {
            let files = case["files"].as_array()?;
            let path = |side: usize| Some(files[side][0].as_str()?.to_string());
            Some((path(0)?, path(1)?))
        })
        .collect()
}

fn main() {
    let results: Vec<(Counts, Counts, usize)> = cases()
        .par_iter()
        .filter_map(|(before, after)| {
            let read = |path: &str| Binary::parse(&std::fs::read(path).ok()?).ok();
            let (before, after) = (read(before)?, read(after)?);
            let diff = diff_with(&before, &after, Options::default());
            let paired = diff.paired_labels(&before, &after);
            let (mut il, mut high, mut pairs) = (Counts::default(), Counts::default(), 0);
            for pair in diff.matched.iter().filter(|pair| pair.changed != Changed::No) {
                let lines = |view| {
                    instruction_diff_in(
                        view,
                        Some(&paired),
                        &before,
                        pair.before,
                        &after,
                        pair.after,
                    )
                };
                il.add(Counts::of(&lines(View::Il)));
                high.add(Counts::of(&lines(View::Hil)));
                pairs += 1;
            }
            Some((il, high, pairs))
        })
        .collect();
    let (mut il, mut high, mut pairs) = (Counts::default(), Counts::default(), 0);
    for (one_il, one_high, one_pairs) in &results {
        il.add(*one_il);
        high.add(*one_high);
        pairs += one_pairs;
    }
    let share = |part: usize, whole: usize| 100.0 * part as f64 / whole.max(1) as f64;
    println!("binaries {}, changed pairs {pairs}", results.len());
    println!("view      lines  changed  changed%");
    for (name, counts) in [("IL", il), ("high IL", high)] {
        println!(
            "{name:8} {:>7} {:>8} {:>8.1}%",
            counts.lines,
            counts.changed,
            share(counts.changed, counts.lines)
        );
    }
    println!(
        "the high IL shows {:.1}% fewer lines and {:.1}% fewer changed lines",
        100.0 - share(high.lines, il.lines),
        100.0 - share(high.changed, il.changed)
    );
}
