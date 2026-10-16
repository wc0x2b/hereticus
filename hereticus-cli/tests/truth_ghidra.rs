//! Check the comparison against Ghidra Version Tracking on the backport
//! pairs.
//!
//! `just rivals-ghidra` runs Auto Version Tracking on each stripped pair of
//! `fixtures/rivals/builds.txt`, through
//! `fixtures/rivals/HereticusVersionTracking.java`, which says which pairs
//! count as changed. On every build, this tool must report the fix, rank it
//! no lower than Ghidra does, and report no more functions that the fix did
//! not touch. `rivals/mod.rs` says how each report is scored. The snapshot
//! locks the scores of both tools.
//!
//! Ghidra takes about a hundred times as long as this tool, so a check of
//! the total time stays true on a busy machine. `just rival-times` shows
//! the times.
//!
//! The Ghidra image is about 2 GB and the first run takes about ten
//! minutes, so `just quick-test` skips this test.

mod rivals;

use rivals::Rival;

#[test]
fn hereticus_does_no_worse_than_ghidra() {
    let contests = rivals::contests(Rival::Ghidra);
    let losses = rivals::losses(&contests);
    assert!(losses.is_empty(), "hereticus does worse than Ghidra:\n{}", losses.join("\n"));
}

#[test]
fn the_scores_against_ghidra_are_locked() {
    let contests = rivals::contests(Rival::Ghidra);
    insta::assert_snapshot!(rivals::table(Rival::Ghidra, &contests));
}

#[test]
fn hereticus_takes_less_time_than_ghidra() {
    let contests = rivals::contests(Rival::Ghidra);
    let table = rivals::times(Rival::Ghidra, &contests);
    println!("{table}");
    let ours: f64 = contests.iter().map(|contest| contest.hereticus_seconds).sum();
    let theirs: f64 = contests.iter().map(|contest| contest.rival_seconds).sum();
    assert!(ours < theirs, "hereticus took longer than Ghidra:\n{table}");
}
