//! Check the comparison against Ghidra Version Tracking on backport pairs
//! with no names.
//!
//! `fixtures/rivals/unname.py` writes a copy of each stripped library of
//! `fixtures/rivals/builds.txt` with no symbol that the library defines, and
//! `just rivals-ghidra` runs Auto Version Tracking on the copies. With no
//! names, the Exact Symbol Name correlator pairs no function. `hereticus`
//! reads the same copies. The snapshot locks the scores of both tools.
//!
//! On Lua for 32-bit PowerPC, Ghidra lists `luaZ_init` of the fix before
//! `luaZ_read`, which changes with it, and this tool after, as more of the
//! code of `luaZ_read` changed. So the test checks the fixes found and the
//! extras, and the snapshot locks the ranks.
//!
//! The Ghidra image is about 2 GB, so `just quick-test` skips this test.

mod rivals;

use rivals::{Contender, Extras, Ranks, Rival, Setup};

const GHIDRA: Contender = Contender { rival: Rival::Ghidra, setup: Setup::Unnamed };

#[test]
fn hereticus_finds_as_much_as_ghidra_with_no_names_with_fewer_extras() {
    let contests = rivals::contests(GHIDRA);
    let losses = rivals::losses(&contests, Ranks::Locked, Extras::Checked);
    assert!(losses.is_empty(), "hereticus does worse than Ghidra:\n{}", losses.join("\n"));
}

#[test]
fn the_scores_against_ghidra_with_no_names_are_locked() {
    let contests = rivals::contests(GHIDRA);
    insta::assert_snapshot!(rivals::table(GHIDRA, &contests));
}
