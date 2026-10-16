//! Check the comparison against radiff2 of radare2 on the backport pairs.
//!
//! `just rivals` runs `radiff2 -A -C` on each stripped pair of
//! `fixtures/rivals/builds.txt`. On every build, this tool must report the
//! fix, rank it no lower than radiff2 does, and report no more functions
//! that the fix did not touch. `rivals/mod.rs` says how each report is
//! scored. The snapshot locks the scores of both tools.

mod rivals;

use rivals::Rival;

#[test]
fn hereticus_does_no_worse_than_radiff2() {
    let contests = rivals::contests(Rival::Radare2);
    let losses = rivals::losses(&contests);
    assert!(losses.is_empty(), "hereticus does worse than radiff2:\n{}", losses.join("\n"));
}

#[test]
fn the_scores_against_radiff2_are_locked() {
    let contests = rivals::contests(Rival::Radare2);
    insta::assert_snapshot!(rivals::table(Rival::Radare2, &contests));
}
