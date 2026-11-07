//! Check the comparison against radiff2 on backport pairs built two ways.
//!
//! Each build of `fixtures/rivals/crossed-builds.txt` has its two sides
//! built by other compilers, clang and GCC, or at other levels, `-Os` and
//! `-O3`, as a vendor's next release can be. Then most functions change, not
//! only those of the fix. `just rivals` runs `radiff2 -A -C` on each pair,
//! and `hereticus` runs with no options. On these pairs `hereticus` can show
//! more rows than radiff2, and rank a small fix low, so the test checks only
//! that it finds each fix. The snapshot locks the scores of both tools.

mod rivals;

use rivals::{Contender, Rival, Setup};

const RADIFF2: Contender = Contender { rival: Rival::Radare2, setup: Setup::Crossed };

#[test]
fn hereticus_finds_each_fix_across_builds() {
    let contests = rivals::contests(RADIFF2);
    let misses = rivals::misses(&contests);
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}

#[test]
fn the_scores_against_radiff2_across_builds_are_locked() {
    let contests = rivals::contests(RADIFF2);
    insta::assert_snapshot!(rivals::table(RADIFF2, &contests));
}
