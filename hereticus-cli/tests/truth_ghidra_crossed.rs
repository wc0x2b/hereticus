//! Check the comparison against Ghidra Version Tracking on backport pairs
//! built two ways.
//!
//! As `rivals_radare2_crossed.rs`, with Auto Version Tracking, as
//! `just rivals-ghidra` runs it on `fixtures/rivals/crossed-builds.txt`.
//!
//! The Ghidra image is about 2 GB, so `just quick-test` skips this test.

mod rivals;

use rivals::{Contender, Rival, Setup};

const GHIDRA: Contender = Contender { rival: Rival::Ghidra, setup: Setup::Crossed };

#[test]
fn hereticus_finds_each_fix_across_builds() {
    let contests = rivals::contests(GHIDRA);
    let misses = rivals::misses(&contests);
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}

#[test]
fn the_scores_against_ghidra_across_builds_are_locked() {
    let contests = rivals::contests(GHIDRA);
    insta::assert_snapshot!(rivals::table(GHIDRA, &contests));
}
