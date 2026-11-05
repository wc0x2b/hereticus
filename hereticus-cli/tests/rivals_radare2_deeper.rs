//! Check the comparison against radiff2 with its deepest analysis, `aaaa`,
//! on the backport pairs.
//!
//! `just rivals` runs `radiff2 -AA -C` on each stripped pair of
//! `fixtures/rivals/builds.txt`. `rivals_radare2.rs` runs it with `-A`, as
//! its manual shows. `hereticus` runs with no options in both. The snapshot
//! locks the scores of both tools.

mod rivals;

use rivals::{Contender, Ranks, Rival, Setup};

const RADIFF2: Contender = Contender { rival: Rival::Radare2, setup: Setup::Deeper };

#[test]
fn hereticus_does_no_worse_than_deeper_radiff2() {
    let contests = rivals::contests(RADIFF2);
    let losses = rivals::losses(&contests, Ranks::Checked);
    assert!(losses.is_empty(), "hereticus does worse than radiff2 -AA:\n{}", losses.join("\n"));
}

#[test]
fn the_scores_against_deeper_radiff2_are_locked() {
    let contests = rivals::contests(RADIFF2);
    insta::assert_snapshot!(rivals::table(RADIFF2, &contests));
}
