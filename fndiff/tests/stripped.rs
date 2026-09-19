//! Measure function recovery on binaries with no symbol table.
//!
//! Every fixture exists twice: once with symbols and once stripped. The
//! symbol table of the first is the answer for the second, so these tests can
//! state what recovery got right rather than only that it ran.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use fndiff::matching::{Changed, Options, UseNames, diff_with};
use fndiff::obj::{Binary, FoundBy};

fn object_path(directory: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/build")
        .join(directory)
        .join(format!("{name}.o"))
}

fn read(directory: &str, name: &str) -> Option<Binary> {
    let data = std::fs::read(object_path(directory, name)).ok()?;
    Binary::parse(&data).ok()
}

/// Where each function starts, and how long it is.
fn extents(binary: &Binary) -> BTreeSet<(u64, usize)> {
    binary.functions.iter().map(|function| (function.address, function.code.len())).collect()
}

fn fixtures_present() -> bool {
    object_path("O2-stripped", "basic").exists()
}

/// Recovery must find every function, at the right place and the right size.
///
/// The fixtures carry an ARM exception index, which lists one entry per
/// function and survives stripping. Where that is present the answer should
/// be exact, so this test demands exactness rather than a ratio.
#[test]
fn recovers_every_function_from_a_stripped_object() {
    assert!(fixtures_present(), "run `just fixtures` first");

    for level in ["O0", "O1", "O2", "Os"] {
        let (Some(truth), Some(stripped)) =
            (read(level, "basic"), read(&format!("{level}-stripped"), "basic"))
        else {
            continue;
        };

        assert_eq!(truth.found_by, FoundBy::Symbols, "{level}: the original keeps its symbols");
        assert_eq!(stripped.found_by, FoundBy::Scanning, "{level}: the copy has none");

        assert_eq!(
            extents(&stripped),
            extents(&truth),
            "{level}: recovered functions must match the symbol table exactly"
        );
    }
}

/// A recovered function has no name, so one is made from its address.
#[test]
fn recovered_functions_have_no_names() {
    assert!(fixtures_present(), "run `just fixtures` first");
    let Some(stripped) = read("O2-stripped", "basic") else { return };

    assert!(
        stripped.functions.iter().all(|function| function.name.is_empty()),
        "a stripped object holds no names to read"
    );
}

/// Comparing two stripped binaries must give the same answer as comparing the
/// two originals.
///
/// This is the property that matters. Firmware ships stripped, so a result
/// that needs symbols is of no use.
#[test]
fn a_stripped_comparison_agrees_with_an_unstripped_one() {
    assert!(fixtures_present(), "run `just fixtures` first");

    let (Some(before), Some(after)) = (read("O2", "basic"), read("O2", "basic_v2")) else {
        panic!("fixtures are missing");
    };
    let (Some(stripped_before), Some(stripped_after)) =
        (read("O2-stripped", "basic"), read("O2-stripped", "basic_v2"))
    else {
        panic!("stripped fixtures are missing");
    };

    let options = Options { use_names: UseNames::No, ..Default::default() };
    let with_symbols = diff_with(&before, &after, options);
    let without = diff_with(&stripped_before, &stripped_after, options);

    assert_eq!(
        without.matched.len(),
        with_symbols.matched.len(),
        "the same functions must be paired either way"
    );
    assert_eq!(
        without.changed().count(),
        with_symbols.changed().count(),
        "the same functions must be reported as changed either way"
    );

    // Compare by address, which is the one name both sides share.
    let changed_addresses = |diff: &fndiff::matching::Diff, binary: &Binary| -> BTreeSet<u64> {
        diff.changed().map(|pair| binary.functions[pair.before].address).collect()
    };

    assert_eq!(
        changed_addresses(&without, &stripped_before),
        changed_addresses(&with_symbols, &before),
        "the same addresses must be reported as changed"
    );
}

/// The three planned edits must still be found without symbols.
#[test]
fn finds_the_planned_edits_in_stripped_objects() {
    assert!(fixtures_present(), "run `just fixtures` first");

    let (Some(before), Some(after)) =
        (read("O2-stripped", "basic"), read("O2-stripped", "basic_v2"))
    else {
        panic!("stripped fixtures are missing");
    };

    let diff = diff_with(&before, &after, Options::default());

    // From the symbol table of the unstripped originals: mul_by_constant at
    // 0x8, classify at 0x3c, array_max at 0x90, and call_chain at 0x80, which
    // inlined the edited constant.
    let changed: BTreeSet<u64> =
        diff.changed().map(|pair| before.functions[pair.before].address).collect();

    assert_eq!(
        changed,
        BTreeSet::from([0x8, 0x3c, 0x80, 0x90]),
        "the edits must be found at the same addresses as with symbols"
    );
}

/// Recovery must still work when the exception index is gone too.
///
/// Then nothing is left but the code, so the boundaries come from call
/// targets and from what follows a return. That is a guess, and this test
/// states how good a guess it is rather than assuming it is perfect.
#[test]
fn recovers_functions_with_nothing_but_the_code() {
    let bare = object_path("bare", "basic");
    if !bare.exists() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    let data = std::fs::read(&bare).expect("the fixture must be readable");
    let recovered = Binary::parse(&data).expect("a bare object must still yield functions");
    assert_eq!(recovered.found_by, FoundBy::Scanning);

    let Some(truth) = read("O2", "basic") else { return };
    let real_starts: BTreeSet<u64> =
        truth.functions.iter().map(|function| function.address).collect();
    let found: BTreeSet<u64> =
        recovered.functions.iter().map(|function| function.address).collect();

    // Every real function must be found. Without the exception index the scan
    // also splits functions at internal returns, so it finds more than there
    // are; those extra boundaries are the known cost of guessing.
    let missed: Vec<&u64> = real_starts.difference(&found).collect();
    assert!(missed.is_empty(), "every real function must be found, but missed {missed:?}");
}

/// A file with code but no recoverable function must say so.
///
/// Returning an empty result would read as "nothing changed", which is the
/// opposite of the truth.
#[test]
fn reports_a_binary_it_cannot_analyze() {
    // An ELF header for ARM with a `.text` section holding one unreadable
    // word is hard to build by hand, so this checks the simpler promise: a
    // file that is not an object at all is refused rather than accepted as
    // empty.
    assert!(Binary::parse(b"not an object at all").is_err());
    assert!(Binary::parse(&[]).is_err());
}

/// Matching a stripped binary against an unstripped one must still work.
///
/// This is the patch-checking case: a vendor image against a reference build.
#[test]
fn matches_a_stripped_binary_against_an_unstripped_one() {
    assert!(fixtures_present(), "run `just fixtures` first");

    let (Some(reference), Some(shipped)) = (read("O2", "basic"), read("O2-stripped", "basic"))
    else {
        panic!("fixtures are missing");
    };

    let diff = diff_with(&reference, &shipped, Options::default());

    assert_eq!(diff.matched.len(), reference.functions.len(), "every function must be paired");
    assert!(
        diff.matched.iter().all(|pair| pair.changed == Changed::No),
        "stripping changes no code, so nothing must be reported as changed"
    );
}
