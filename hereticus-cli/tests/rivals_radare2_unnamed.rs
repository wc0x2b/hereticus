//! Check the comparison against radiff2 on backport pairs with no names.
//!
//! A shared library keeps the symbols of the functions it exports, which
//! name them and say where they start. `fixtures/rivals/unname.py` writes a
//! copy of each stripped library of `fixtures/rivals/builds.txt` with none,
//! and `just rivals` runs `radiff2 -A -C` on the copies. `hereticus` reads
//! the same copies. The snapshot locks the scores of both tools.
//!
//! On x86-64, a copy keeps the PLT stubs of the functions that the library
//! exported, which a linker does not write for a library that exports
//! nothing. Such stubs move between the two builds, and show as gone and
//! new, so the test checks the fixes and their ranks, not the extras.

mod rivals;

use hereticus::obj::Binary;
use rivals::{Contender, Extras, Ranks, Rival, Setup, Variant};

const RADIFF2: Contender = Contender { rival: Rival::Radare2, setup: Setup::Unnamed };

#[test]
fn hereticus_finds_and_ranks_as_well_as_radiff2_with_no_names() {
    let contests = rivals::contests(RADIFF2);
    let losses = rivals::losses(&contests, Ranks::Checked, Extras::Locked);
    assert!(losses.is_empty(), "hereticus does worse than radiff2:\n{}", losses.join("\n"));
}

#[test]
fn the_scores_against_radiff2_with_no_names_are_locked() {
    let contests = rivals::contests(RADIFF2);
    insta::assert_snapshot!(rivals::table(RADIFF2, &contests));
}

/// With no symbols, the addresses of functions that relocations store say
/// whether an ARM library is A32 or Thumb-2 code.
#[test]
fn a_library_with_no_names_reads_in_the_set_its_symbols_say() {
    let isa = |path: std::path::PathBuf| {
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|err| panic!("{}: {err}, run `just rivals` first", path.display()));
        Binary::parse(&bytes).expect("a fixture library must parse").isa
    };
    for build in rivals::builds(Setup::Unnamed) {
        for variant in [Variant::Before, Variant::After] {
            assert_eq!(
                isa(build.library(variant, Setup::Unnamed)),
                isa(build.file(variant, "lib.so")),
                "{} {variant:?}",
                build.name()
            );
        }
    }
}
