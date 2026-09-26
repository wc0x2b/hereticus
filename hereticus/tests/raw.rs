//! Compare firmware images that carry no container format.
//!
//! A flash dump is bytes and a load address. These tests check that reading
//! one finds the same functions and reports the same changes as reading the
//! object file it came from, which is the only ground truth available.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hereticus::arch::arm32::Arm32;
use hereticus::matching::{Options, UseNames, diff_with};
use hereticus::obj::{Binary, FoundBy, Isa};
use hereticus::raw::{BaseFit, check_base};

/// Where the vector-table fixture is linked. Must agree with
/// `fixtures/build.sh`.
const VECTOR_BASE: u64 = 0x0800_0000;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build")
}

fn read_raw(name: &str) -> Option<Vec<u8>> {
    std::fs::read(fixtures().join("raw").join(name)).ok()
}

fn read_object(level: &str, name: &str) -> Option<Binary> {
    let data = std::fs::read(fixtures().join(level).join(format!("{name}.o"))).ok()?;
    Binary::parse(&data).ok()
}

fn fixtures_present() -> bool {
    fixtures().join("raw/O2-basic.bin").exists()
}

/// A raw image gives up the functions the object file it came from holds.
///
/// The blob is the `.text` of a known object, so its symbol table says what
/// should be found. Recovery over-splits without an exception index, so the
/// test requires every real function to be present rather than requiring the
/// counts to agree.
#[test]
fn recovers_the_functions_of_the_object_it_came_from() {
    assert!(fixtures_present(), "run `just fixtures` first");

    let (Some(blob), Some(object)) = (read_raw("O2-basic.bin"), read_object("O2", "basic")) else {
        panic!("fixtures are missing");
    };

    // The blob is the `.text` section, which the object loads at zero.
    let raw = Binary::parse_raw(&blob, 0, Isa::Arm32).expect("a raw image must yield functions");
    assert_eq!(raw.found_by, FoundBy::Scanning);

    let found: BTreeSet<u64> = raw.functions.iter().map(|function| function.address).collect();
    for real in &object.functions {
        assert!(
            found.contains(&real.address),
            "{} at {:#x} must be found in the raw image",
            real.name,
            real.address
        );
    }
}

/// Reading a raw image reports the same changes as reading the objects.
///
/// This is the property that matters. A firmware image with no symbols and no
/// sections must still answer the question the tool exists for.
#[test]
fn a_raw_comparison_finds_the_same_changes() {
    assert!(fixtures_present(), "run `just fixtures` first");

    let (Some(before_blob), Some(after_blob)) =
        (read_raw("O2-basic.bin"), read_raw("O2-basic_v2.bin"))
    else {
        panic!("fixtures are missing");
    };
    let (Some(before_object), Some(after_object)) =
        (read_object("O2", "basic"), read_object("O2", "basic_v2"))
    else {
        panic!("fixtures are missing");
    };

    let options = Options { use_names: UseNames::No, ..Default::default() };

    let raw_before = Binary::parse_raw(&before_blob, 0, Isa::Arm32).unwrap();
    let raw_after = Binary::parse_raw(&after_blob, 0, Isa::Arm32).unwrap();
    let raw_diff = diff_with(&raw_before, &raw_after, options);
    let object_diff = diff_with(&before_object, &after_object, options);

    assert_eq!(
        raw_diff.changed().count(),
        object_diff.changed().count(),
        "a raw image must find as many changed functions as the object does"
    );

    // Three of the four edits sit at the start of a function, so their
    // addresses survive the over-splitting. The fourth lands inside a
    // function that recovery split, so its address moves.
    let raw_changed: BTreeSet<u64> =
        raw_diff.changed().map(|pair| raw_before.functions[pair.before].address).collect();
    for expected in [0x8, 0x80, 0x90] {
        assert!(
            raw_changed.contains(&expected),
            "the edit at {expected:#x} must be reported, found {raw_changed:x?}"
        );
    }
}

/// Where an image loads must not change what the matcher sees.
///
/// Addresses are dropped by normalizing, so the same blob at two bases must
/// compare as unchanged against itself.
#[test]
fn the_load_address_does_not_change_the_comparison() {
    assert!(fixtures_present(), "run `just fixtures` first");
    let Some(blob) = read_raw("O2-basic.bin") else { return };

    let low = Binary::parse_raw(&blob, 0, Isa::Arm32).unwrap();
    let high = Binary::parse_raw(&blob, 0x0800_0000, Isa::Arm32).unwrap();

    assert_eq!(low.functions.len(), high.functions.len(), "the same functions must be found");

    let diff = diff_with(&low, &high, Options { use_names: UseNames::No, ..Default::default() });
    assert_eq!(diff.changed().count(), 0, "only the addresses differ, not the code");
    assert!(diff.removed.is_empty() && diff.added.is_empty());
}

/// Addresses are reported relative to the base the caller gave.
#[test]
fn reported_addresses_follow_the_base() {
    assert!(fixtures_present(), "run `just fixtures` first");
    let Some(blob) = read_raw("O2-basic.bin") else { return };

    let base = 0x0800_0000;
    let raw = Binary::parse_raw(&blob, base, Isa::Arm32).unwrap();

    assert!(
        raw.functions.iter().all(|function| function.address >= base),
        "every function must sit at or after the base"
    );
    assert_eq!(raw.functions[0].address, base, "the image starts with a function");
}

/// The load-address check finds a base that is wrong by a little.
#[test]
fn the_base_check_catches_a_nearly_right_base() {
    let Some(vectors) = read_raw("vectors.bin") else {
        eprintln!("skipped: no vector table fixture, run `just fixtures`");
        return;
    };

    assert!(
        matches!(check_base(&vectors, VECTOR_BASE, &Arm32), BaseFit::Plausible { .. }),
        "the base it was linked at must look right, got {:?}",
        check_base(&vectors, VECTOR_BASE, &Arm32)
    );

    // Wrong by a page or less, which is the mistake people make.
    for wrong in [VECTOR_BASE + 0x100, VECTOR_BASE + 0x400, VECTOR_BASE + 0x1000] {
        assert!(
            check_base(&vectors, wrong, &Arm32).is_suspect(),
            "{wrong:#x} must be suspect, got {:?}",
            check_base(&vectors, wrong, &Arm32)
        );
    }
}

/// Code holding no stored addresses cannot judge a base either way.
///
/// The compiled fixtures are position-independent, so this is the normal case
/// and must not produce a warning.
#[test]
fn the_base_check_stays_quiet_without_evidence() {
    assert!(fixtures_present(), "run `just fixtures` first");
    let Some(blob) = read_raw("O2-basic.bin") else { return };

    for base in [0, 0x0800_0000, 0x2000_0000] {
        let fit = check_base(&blob, base, &Arm32);
        assert!(
            !fit.is_suspect(),
            "position-independent code must not accuse a base, got {fit:?} at {base:#x}"
        );
    }
}

/// An empty image is refused rather than read as holding nothing.
#[test]
fn an_empty_image_is_refused() {
    assert!(Binary::parse_raw(&[], 0, Isa::Arm32).is_err());
}

/// Too few bytes to hold one instruction is refused too.
#[test]
fn an_image_shorter_than_an_instruction_is_refused() {
    assert!(Binary::parse_raw(&[0x00, 0x01], 0, Isa::Arm32).is_err());
}
