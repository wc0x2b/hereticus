//! Scratch: check the high IL of every function of the binaries named on the
//! command line, or of the backports, for what must hold of any function:
//! no panic, the same lines on each run, no line that differs in a diff of
//! the function with itself, one place for each line, and a line for each
//! of its own instructions at most once.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::HashSet;
use std::time::Instant;

use hereticus::matching::{DiffLine, View, instruction_diff_in, line_places};
use hereticus::obj::Binary;
use rayon::prelude::*;

fn paths() -> Vec<String> {
    let named: Vec<String> = std::env::args().skip(1).collect();
    if !named.is_empty() {
        return named;
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/backports");
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(&root).unwrap().flatten() {
        let Ok(configs) = std::fs::read_dir(entry.path()) else { continue };
        for config in configs.flatten() {
            let path = config.path().join("lib.so");
            if path.exists() {
                paths.push(path.display().to_string());
            }
        }
    }
    paths.sort();
    paths
}

fn main() {
    let results: Vec<(String, usize, Vec<String>, f64, String)> = paths()
        .par_iter()
        .filter_map(|path| {
            let binary = Binary::parse(&std::fs::read(path).ok()?).ok()?;
            let mut problems = Vec::new();
            let mut slowest = (0.0, String::new());
            for index in 0..binary.functions.len() {
                let label = binary.functions[index].label();
                let started = Instant::now();
                let run = || instruction_diff_in(View::Hil, None, &binary, index, &binary, index);
                let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run));
                let Ok(first) = first else {
                    problems.push(format!("{label}: panic"));
                    continue;
                };
                let seconds = started.elapsed().as_secs_f64();
                if seconds > slowest.0 {
                    slowest = (seconds, label.clone());
                }
                if first.iter().any(|line| !matches!(line, DiffLine::Same(_))) {
                    problems.push(format!("{label}: differs from itself"));
                }
                if run() != first {
                    problems.push(format!("{label}: not the same on a second run"));
                }
                let places = line_places(View::Hil, &binary, index);
                if places.len() != first.len() {
                    problems.push(format!(
                        "{label}: {} lines, {} places",
                        first.len(),
                        places.len()
                    ));
                }
                let addresses: HashSet<u64> = places.iter().map(|place| place.address).collect();
                if addresses.len() != places.len() {
                    problems.push(format!("{label}: two lines at one address"));
                }
            }
            Some((path.clone(), binary.functions.len(), problems, slowest.0, slowest.1))
        })
        .collect();
    let (mut functions, mut failed) = (0, 0);
    for (path, count, problems, seconds, slowest) in &results {
        functions += count;
        if !problems.is_empty() || *seconds > 1.0 {
            println!("{path}: {} problems, slowest {slowest} {seconds:.2}s", problems.len());
            for problem in problems.iter().take(5) {
                println!("  {problem}");
            }
            failed += problems.len();
        }
    }
    println!("binaries {}, functions {functions}, problems {failed}", results.len());
}
