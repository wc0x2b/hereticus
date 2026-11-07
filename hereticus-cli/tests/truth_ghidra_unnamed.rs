//! Check the comparison against Ghidra Version Tracking on backport pairs
//! with no names.
//!
//! `fixtures/rivals/unname.py` writes a copy of each stripped library of
//! `fixtures/rivals/builds.txt` with no symbol that the library defines, and
//! `just rivals-ghidra` runs Auto Version Tracking on the copies. With no
//! names, the Exact Symbol Name correlator pairs no function. `hereticus`
//! reads the same copies. The snapshot locks the scores of both tools.
//!
//! The Ghidra image is about 2 GB, so `just quick-test` skips this test.

mod rivals;

use rivals::{Contender, Ranks, Rival, Setup};

const GHIDRA: Contender = Contender { rival: Rival::Ghidra, setup: Setup::Unnamed };

#[test]
fn hereticus_does_no_worse_than_ghidra_with_no_names() {
    let contests = rivals::contests(GHIDRA);
    let losses = rivals::losses(&contests, Ranks::Checked);
    assert!(losses.is_empty(), "hereticus does worse than Ghidra:\n{}", losses.join("\n"));
}

#[test]
fn the_scores_against_ghidra_with_no_names_are_locked() {
    let contests = rivals::contests(GHIDRA);
    insta::assert_snapshot!(rivals::table(GHIDRA, &contests));
}
