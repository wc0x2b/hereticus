//! Check the comparison against radiff2 with its deepest analysis, `aaaa`,
//! on the backport pairs.
//!
//! `just rivals` runs `radiff2 -AA -C` on each stripped pair of
//! `fixtures/rivals/builds.txt`. `rivals_radare2.rs` runs it with `-A`, as
//! its manual shows. `hereticus` runs with no options in both. The snapshot
//! locks the scores of both tools.
//!
//! On Lua for 64-bit PowerPC, radiff2 scores `luaZ_init` 0 and lists it
//! first, where this tool lists `luaZ_lookahead` and `luaZ_read`, which
//! change with the fix, above it, as more of their code changed. So the
//! test checks the fixes found and the extras, and the snapshot locks the
//! ranks.

mod rivals;

use rivals::{Contender, Extras, Ranks, Rival, Setup};

const RADIFF2: Contender = Contender { rival: Rival::Radare2, setup: Setup::Deeper };

#[test]
fn hereticus_finds_as_much_as_deeper_radiff2_with_fewer_extras() {
    let contests = rivals::contests(RADIFF2);
    let losses = rivals::losses(&contests, Ranks::Locked, Extras::Checked);
    assert!(losses.is_empty(), "hereticus does worse than radiff2 -AA:\n{}", losses.join("\n"));
}

#[test]
fn the_scores_against_deeper_radiff2_are_locked() {
    let contests = rivals::contests(RADIFF2);
    insta::assert_snapshot!(rivals::table(RADIFF2, &contests));
}
