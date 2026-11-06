//! Scratch: rank the lines that IL diffs show as removed or added, on a
//! sample of the pairs of Assemblage.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::{BTreeMap, HashMap};

use hereticus::matching::{
    Changed, DiffLine, Motion, Options, View, diff_with, instruction_diff_in, motions,
};
use hereticus::obj::Binary;
use rayon::prelude::*;

fn is_word(word: &str) -> bool {
    !word.is_empty()
        && word.starts_with(|c: char| c.is_ascii_lowercase())
        && word.chars().all(|c| c.is_ascii_alphanumeric())
}

fn kind(text: &str) -> &'static str {
    let (left, right) = text.split_once(" = ").unwrap_or((text, ""));
    match () {
        _ if text.starts_with("if (") => "branch",
        _ if text.starts_with("goto ") => "goto",
        _ if text.starts_with("call ") => "call",
        _ if text == "return" => "return",
        _ if text.starts_with("push") || text.starts_with("pop") => "push/pop",
        _ if text.starts_with("store") => "store",
        _ if text.starts_with("flags = ") => "compare",
        _ if text == "endbr64" => "endbr64",
        _ if matches!(left, "rsp" | "esp" | "sp") => "stack pointer",
        _ if right.starts_with("load") => "load",
        _ if right.starts_with('&') || right.starts_with('@') => "address",
        _ if is_word(left) && is_word(right) => "move register",
        _ if is_word(left)
            && (right.starts_with("0x")
                || right.starts_with("-0x")
                || right.chars().all(|c| c.is_ascii_digit() || c == '-')) =>
        {
            "move constant"
        }
        _ if !right.is_empty() => "operation",
        _ => "other",
    }
}

/// The text with each word that looks like a register written `R` and
/// each number written `#`.
fn shape(text: &str) -> String {
    let mut out = String::new();
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        if word.starts_with(|c: char| c.is_ascii_digit()) {
            out.push('#');
        } else if is_word(word)
            && word.len() <= 5
            && word.chars().any(|c| c.is_ascii_digit() || "aeiou".contains(c))
        {
            out.push('R');
        } else {
            out.push_str(word);
        }
        word.clear();
    };
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            word.push(c);
        } else {
            flush(&mut word, &mut out);
            out.push(c);
        }
    }
    flush(&mut word, &mut out);
    out
}

#[derive(Default)]
struct Counts {
    shown: usize,
    changed: usize,
    by_kind: BTreeMap<&'static str, usize>,
    /// Lines whose text the other side of the same hunk holds too.
    same_text_in_hunk: usize,
    /// Lines whose shape the other side of the same hunk holds too.
    same_shape_in_hunk: usize,
    /// Lines whose text the other side holds unpaired somewhere in the function.
    same_text_in_function: usize,
    /// Lines in hunks of one side only.
    one_sided_hunk: usize,
    /// Lines already gray as a moved block.
    moved: usize,
    /// Unpaired lines, not gray, whose twin is at most this many diff lines away.
    near: [usize; 6],
    /// Moved lines under other rules: (fewest, control).
    variants: [usize; 10],
    /// Lines with the same text elsewhere and not gray, by kind.
    elsewhere_by_kind: BTreeMap<&'static str, usize>,
}

fn add(into: &mut Counts, from: &Counts) {
    into.shown += from.shown;
    into.changed += from.changed;
    into.same_text_in_hunk += from.same_text_in_hunk;
    into.same_shape_in_hunk += from.same_shape_in_hunk;
    into.same_text_in_function += from.same_text_in_function;
    into.one_sided_hunk += from.one_sided_hunk;
    into.moved += from.moved;
    for i in 0..6 {
        into.near[i] += from.near[i];
    }
    for i in 0..10 {
        into.variants[i] += from.variants[i];
    }
    for (k, v) in &from.elsewhere_by_kind {
        *into.elsewhere_by_kind.entry(k).or_default() += v;
    }
    for (k, v) in &from.by_kind {
        *into.by_kind.entry(k).or_default() += v;
    }
}

fn count(diff: &[DiffLine], counts: &mut Counts) {
    let mut removed_texts: HashMap<&str, usize> = HashMap::new();
    let mut added_texts: HashMap<&str, usize> = HashMap::new();
    for line in diff {
        match line {
            DiffLine::Removed(t) => *removed_texts.entry(t).or_default() += 1,
            DiffLine::Added(t) => *added_texts.entry(t).or_default() += 1,
            DiffLine::Changed { before, after } => {
                counts.changed += 1;
                if std::env::var_os("CHANGED").is_some() {
                    eprintln!("CHANGED {} || {} || {}", kind(after), before, after);
                }
            }
            DiffLine::Same(_) => {}
        }
    }
    let motion = motions(diff, View::Il);
    // Twins: a removed line and an added line of one text, both not gray,
    // paired greedily by nearest distance.
    {
        let mut free_added: HashMap<String, Vec<usize>> = HashMap::new();
        for (at, line) in diff.iter().enumerate() {
            if let (DiffLine::Added(t), Motion::Stayed) = (line, motion[at]) {
                free_added.entry(targetless(t)).or_default().push(at);
            }
        }
        for (at, line) in diff.iter().enumerate() {
            let DiffLine::Removed(t) = line else { continue };
            if motion[at] != Motion::Stayed {
                continue;
            }
            let Some(list) = free_added.get_mut(&targetless(t)) else { continue };
            let Some((k, &other)) = list.iter().enumerate().min_by_key(|(_, o)| o.abs_diff(at))
            else {
                continue;
            };
            let distance = other.abs_diff(at);
            for (i, limit) in [1usize, 2, 3, 5, 8, 16].iter().enumerate() {
                if distance <= *limit {
                    counts.near[i] += 2;
                }
            }
            list.swap_remove(k);
        }
    }
    for (i, (fewest, control)) in
        [(3, 0u8), (3, 1), (3, 2), (3, 3), (4, 3), (5, 3), (6, 3), (8, 3), (4, 2), (3, 4)]
            .into_iter()
            .enumerate()
    {
        counts.variants[i] += moved_lines(diff, fewest, control);
    }
    for (line, motion) in diff.iter().zip(&motion) {
        let (text, other) = match line {
            DiffLine::Removed(t) => (t, &added_texts),
            DiffLine::Added(t) => (t, &removed_texts),
            _ => continue,
        };
        counts.shown += 1;
        *counts.by_kind.entry(kind(text)).or_default() += 1;
        if *motion == Motion::Moved {
            counts.moved += 1;
        } else if other.contains_key(text.as_str()) {
            counts.same_text_in_function += 1;
            *counts.elsewhere_by_kind.entry(kind(text)).or_default() += 1;
        }
    }
    // Hunks: runs of lines that are not the same.
    let mut at = 0;
    while at < diff.len() {
        if matches!(diff[at], DiffLine::Same(_)) {
            at += 1;
            continue;
        }
        let end =
            (at..diff.len()).find(|&i| matches!(diff[i], DiffLine::Same(_))).unwrap_or(diff.len());
        let hunk = &diff[at..end];
        let removed: Vec<&str> = hunk
            .iter()
            .filter_map(|l| match l {
                DiffLine::Removed(t) => Some(t.as_str()),
                _ => None,
            })
            .collect();
        let added: Vec<&str> = hunk
            .iter()
            .filter_map(|l| match l {
                DiffLine::Added(t) => Some(t.as_str()),
                _ => None,
            })
            .collect();
        if removed.is_empty() || added.is_empty() {
            counts.one_sided_hunk += removed.len() + added.len();
        }
        let shapes = |lines: &[&str]| -> Vec<String> { lines.iter().map(|t| shape(t)).collect() };
        let (removed_shapes, added_shapes) = (shapes(&removed), shapes(&added));
        for t in &removed {
            counts.same_text_in_hunk += added.contains(t) as usize;
            counts.same_shape_in_hunk += added_shapes.contains(&shape(t)) as usize;
        }
        for t in &added {
            counts.same_text_in_hunk += removed.contains(t) as usize;
            counts.same_shape_in_hunk += removed_shapes.contains(&shape(t)) as usize;
        }
        at = end;
    }
}

/// How many removed and added lines are in moved blocks of at least
/// `fewest` lines, where `control` says whether a block may hold a line
/// that moves control.
/// `text` with each branch target written `$`.
fn targetless(text: &str) -> String {
    text.split(' ')
        .map(|w| if w.starts_with("$+0x") || w.starts_with("$-0x") { "$" } else { w })
        .collect::<Vec<_>>()
        .join(" ")
}

fn moved_lines(lines: &[DiffLine], fewest: usize, control: u8) -> usize {
    // 0: no control; 1: calls only; 2: all but branches; 3: all
    let moves_control = |t: &str| match control {
        4 => false,
        0 => {
            t.starts_with("if (")
                || t.starts_with("goto ")
                || t.starts_with("call ")
                || t == "return"
        }
        1 => t.starts_with("if (") || t.starts_with("goto ") || t == "return",
        2 => t.starts_with("if ("),
        _ => false,
    };
    let keys: Vec<String> = lines
        .iter()
        .map(|l| match l {
            DiffLine::Removed(t) | DiffLine::Added(t) => targetless(t),
            _ => String::new(),
        })
        .collect();
    let pick = |want_removed: bool| -> Vec<(usize, &str)> {
        lines
            .iter()
            .enumerate()
            .filter_map(|(at, l)| match (l, want_removed) {
                (DiffLine::Removed(_), true) | (DiffLine::Added(_), false) => {
                    Some((at, keys[at].as_str()))
                }
                _ => None,
            })
            .collect()
    };
    let (removed, added) = (pick(true), pick(false));
    let mut by_text: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, (_, t)) in added.iter().enumerate() {
        by_text.entry(t).or_default().push(i);
    }
    let ends = |t: &str| t.starts_with("goto ") || t == "return";
    let ends_flow = |t: &str| ends(t) || t.starts_with("if (");
    // The line of the same side before diff line `at`.
    let before_on_side = |at: usize, removed_side: bool| -> Option<&str> {
        lines[..at].iter().rev().find_map(|l| match (l, removed_side) {
            (DiffLine::Same(t), _) => Some(t.as_str()),
            (DiffLine::Changed { before, .. }, true) => Some(before.as_str()),
            (DiffLine::Changed { after, .. }, false) => Some(after.as_str()),
            (DiffLine::Removed(t), true) | (DiffLine::Added(t), false) => Some(t.as_str()),
            _ => None,
        })
    };
    let whole = |from: usize, to: usize, n: usize| -> bool {
        let starts = |at: usize, side: bool| {
            before_on_side(at, side).is_none_or(|t| {
                if std::env::var_os("STRICT").is_some() { ends(t) } else { ends_flow(t) }
            })
        };
        ends(removed[from + n - 1].1) && starts(removed[from].0, true) && starts(added[to].0, false)
    };
    let has_control = |from: usize, n: usize| {
        removed[from..from + n].iter().any(|(_, t)| {
            t.starts_with("if (")
                || t.starts_with("goto ")
                || t.starts_with("call ")
                || *t == "return"
        })
    };
    let mut taken = vec![false; added.len()];
    let block = |from: usize, to: usize, taken: &[bool]| -> usize {
        let follows = |p: &[(usize, &str)], at: usize| p[at].0 == p[at - 1].0 + 1;
        (0..)
            .take_while(|&n| {
                let (r, a) = (from + n, to + n);
                r < removed.len()
                    && a < added.len()
                    && !taken[a]
                    && removed[r].1 == added[a].1
                    && !moves_control(removed[r].1)
                    && (n == 0 || (follows(&removed, r) && follows(&added, a)))
            })
            .count()
    };
    let (mut from, mut moved) = (0, 0);
    while from < removed.len() {
        let best = by_text
            .get(removed[from].1)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .take(64)
            .map(|&to| (block(from, to, &taken), to))
            .max_by_key(|&(n, to)| (n, core::cmp::Reverse(to)));
        match best {
            Some((n, to))
                if n >= fewest && control == 4 && has_control(from, n) && !whole(from, to, n) =>
            {
                let plain = (fewest..n)
                    .rev()
                    .find(|&k| whole(from, to, k))
                    .unwrap_or_else(|| (0..n).take_while(|&k| !has_control(from + k, 1)).count());
                if plain >= fewest {
                    (to..to + plain).for_each(|a| taken[a] = true);
                    moved += 2 * plain;
                    from += plain;
                } else {
                    from += 1;
                }
            }
            Some((n, to)) if n >= fewest => {
                if control == 1
                    && has_control(from, n)
                    && std::env::var_os("SHOWCALLS").is_some()
                    && (removed[from].0 * 31) % 97 == 0
                {
                    let text = |l: &DiffLine| match l {
                        DiffLine::Same(t) => format!("    {t}"),
                        DiffLine::Removed(t) => format!("  - {t}"),
                        DiffLine::Added(t) => format!("  + {t}"),
                        DiffLine::Changed { before, after } => format!("  ~ {before} => {after}"),
                    };
                    let (a, b) = (
                        removed[from].0.min(added[to].0),
                        removed[from + n - 1].0.max(added[to + n - 1].0),
                    );
                    if b - a < 40 {
                        eprintln!(
                            "BLOCK\n{}\nBEND",
                            lines[a.saturating_sub(2)..(b + 3).min(lines.len())]
                                .iter()
                                .map(text)
                                .collect::<Vec<_>>()
                                .join("\n")
                        );
                    }
                }
                (to..to + n).for_each(|a| taken[a] = true);
                moved += 2 * n;
                from += n;
            }
            _ => from += 1,
        }
    }
    moved
}

fn main() {
    let home = std::env::var("HOME").unwrap();
    let text =
        std::fs::read_to_string(format!("{home}/.cache/hereticus-assemblage/cases.json")).unwrap();
    let cases: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();
    let count_of: usize = std::env::var("PAIRS").ok().and_then(|n| n.parse().ok()).unwrap_or(300);
    let stride = (cases.len() / count_of).max(1);
    let mut picked: Vec<serde_json::Value> =
        cases.iter().step_by(stride).take(count_of).cloned().collect();
    if std::env::var_os("BACKPORTS").is_some() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/backports");
        picked.clear();
        for entry in std::fs::read_dir(&root).unwrap().flatten() {
            let name = entry.file_name().into_string().unwrap();
            let Some(project) = name.strip_suffix("-before") else { continue };
            for config in std::fs::read_dir(entry.path()).unwrap().flatten() {
                let config = config.file_name().into_string().unwrap();
                let side = |which: &str| {
                    root.join(format!("{project}-{which}/{config}/lib.so")).display().to_string()
                };
                picked.push(serde_json::json!({"files": [[side("before")], [side("after")]]}));
            }
        }
    }
    let results: Vec<Counts> = picked
        .par_iter()
        .filter_map(|case| {
            let files = case["files"].as_array()?;
            let read = |side: usize| {
                let path = files[side][0].as_str()?;
                Binary::parse(&std::fs::read(path).ok()?).ok()
            };
            let (before, after) = (read(0)?, read(1)?);
            let diff = diff_with(&before, &after, Options::default());
            let mut counts = Counts::default();
            for pair in diff.matched.iter().filter(|pair| pair.changed != Changed::No) {
                let lines =
                    instruction_diff_in(View::Il, None, &before, pair.before, &after, pair.after);
                count(&lines, &mut counts);
            }
            Some(counts)
        })
        .collect();
    let mut all = Counts::default();
    for one in &results {
        add(&mut all, one);
    }
    let share = |n: usize| 100.0 * n as f64 / all.shown as f64;
    println!("pairs {} removed+added {} changed {}", results.len(), all.shown, all.changed);
    let mut kinds: Vec<_> = all.by_kind.iter().collect();
    kinds.sort_by_key(|(_, n)| core::cmp::Reverse(**n));
    for (k, n) in kinds {
        println!("{k:16} {n:>8} {:>5.1}%", share(*n));
    }
    println!(
        "same text in hunk      {:>8} {:>5.1}%",
        all.same_text_in_hunk,
        share(all.same_text_in_hunk)
    );
    println!(
        "same shape in hunk     {:>8} {:>5.1}%",
        all.same_shape_in_hunk,
        share(all.same_shape_in_hunk)
    );
    println!(
        "same text in function  {:>8} {:>5.1}%",
        all.same_text_in_function,
        share(all.same_text_in_function)
    );
    println!("moved (gray)           {:>8} {:>5.1}%", all.moved, share(all.moved));
    for (k, n) in &all.elsewhere_by_kind {
        println!("  elsewhere {k:16} {n:>8} {:>5.1}%", share(*n));
    }
    for (i, name) in [
        "3 none",
        "3 calls",
        "3 no branch",
        "3 all",
        "4 all",
        "5 all",
        "6 all",
        "8 all",
        "4 no branch",
        "3 whole",
    ]
    .iter()
    .enumerate()
    {
        println!("variant {name:14} {:>8} {:>5.1}%", all.variants[i], share(all.variants[i]));
    }
    for (i, limit) in [1, 2, 3, 5, 8, 16].iter().enumerate() {
        println!("twin within {limit:>2}          {:>8} {:>5.1}%", all.near[i], share(all.near[i]));
    }
    println!(
        "one-sided hunk         {:>8} {:>5.1}%",
        all.one_sided_hunk,
        share(all.one_sided_hunk)
    );
}
