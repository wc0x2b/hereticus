//! Check the comparison against Ghidra Version Tracking with more
//! correlators, on the backport pairs.
//!
//! Auto Version Tracking runs only the correlators that find exact matches
//! and those that follow references. With `deeper`,
//! `fixtures/rivals/HereticusVersionTracking.java` then runs the BSim,
//! Exact Function Mnemonics and Combined Function and Data Reference
//! correlators, and accepts the best match of each function that is not
//! paired yet. `hereticus` runs with no options. The snapshot locks the
//! scores of both tools.
//!
//! On five builds of Lua, Ghidra puts the fix one or two rows higher. A
//! reference correlator gives `luaZ_read`, which changes with the fix, a
//! score of 1, so Ghidra lists it last, and `luaZ_init` comes up. This tool
//! lists `luaZ_read` above `luaZ_init`, as more of its code changed. So the
//! test checks the fixes found and the extras, and the snapshot locks the
//! ranks.
//!
//! The Ghidra image is about 2 GB, so `just quick-test` skips this test.

mod rivals;

use rivals::{Contender, Ranks, Rival, Setup};

const GHIDRA: Contender = Contender { rival: Rival::Ghidra, setup: Setup::Deeper };

#[test]
fn hereticus_finds_as_much_as_deeper_ghidra_with_fewer_extras() {
    let contests = rivals::contests(GHIDRA);
    let losses = rivals::losses(&contests, Ranks::Locked);
    assert!(
        losses.is_empty(),
        "hereticus does worse than Ghidra with more correlators:\n{}",
        losses.join("\n")
    );
}

#[test]
fn the_scores_against_deeper_ghidra_are_locked() {
    let contests = rivals::contests(GHIDRA);
    insta::assert_snapshot!(rivals::table(GHIDRA, &contests));
}
