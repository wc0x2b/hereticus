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
