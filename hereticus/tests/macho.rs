//! Read AArch64 Mach-O dylibs, as macOS and iOS ship them.
//!
//! `just fixtures` links each fixture as an arm64 and an arm64e dylib, and
//! strips a copy of each. The unstripped dylib names every function, so it is
//! the answer for the stripped copy.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hereticus::matching::{Diff, Options, UseNames, diff_with};
use hereticus::obj::{Binary, FoundBy, Isa, ObjError};
use object::{Object, ObjectSection};
use rstest::rstest;

fn path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/macho").join(name)
}

fn read_bytes(name: &str) -> Vec<u8> {
    let path = path(name);
    std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{}: {err}, run `just fixtures` first", path.display()))
}

fn read(name: &str) -> Binary {
    Binary::parse(&read_bytes(name)).unwrap_or_else(|err| panic!("{name}: {err}"))
}

/// Where each function starts, and how long it is.
fn extents(binary: &Binary) -> BTreeSet<(u64, usize)> {
    binary.functions.iter().map(|function| (function.address, function.code.len())).collect()
}

fn names(binary: &Binary) -> BTreeSet<&str> {
    binary.functions.iter().map(|function| function.name.as_str()).collect()
}

/// The names of the functions `diff` reports as changed.
fn changed<'a>(diff: &Diff, before: &'a Binary) -> BTreeSet<&'a str> {
    diff.changed().map(|pair| before.functions[pair.before].name.as_str()).collect()
}

/// The span of `__text`, where every function of a fixture is.
fn text_section(name: &str) -> core::ops::Range<u64> {
    let data = read_bytes(name);
    let file = object::File::parse(&*data).expect("a fixture must parse");
    let text = file.section_by_name("__text").expect("a dylib has __text");
    text.address()..text.address() + text.size()
}

/// The symbols name every function, and `__text` holds them end to end,
/// with nothing from the stubs.
#[rstest]
fn a_dylib_names_each_function_and_bounds_it(#[values("arm64", "arm64e")] arch: &str) {
    let name = format!("{arch}-callee.dylib");
    let binary = read(&name);

    assert_eq!(binary.isa, Isa::Aarch64);
    assert_eq!(binary.found_by, FoundBy::Symbols);
    assert_eq!(names(&binary), BTreeSet::from(["_keep", "_pick", "_scale"]));

    let text = text_section(&name);
    let mut next = text.start;
    for function in &binary.functions {
        assert_eq!(function.address, next, "{}: a gap or an overlap", function.name);
        next += function.code.len() as u64;
    }
    assert_eq!(next, text.end, "the last function ends with __text");
}

/// Stripping removes the names of local functions, but not where they start.
#[rstest]
fn a_stripped_dylib_keeps_its_bounds_and_its_exports(
    #[values("arm64", "arm64e")] arch: &str,
    #[values("basic", "firmware", "callee")] fixture: &str,
) {
    let truth = read(&format!("{arch}-{fixture}.dylib"));
    let stripped = read(&format!("{arch}-{fixture}-stripped.dylib"));

    assert_eq!(extents(&stripped), extents(&truth));
    for (kept, original) in stripped.functions.iter().zip(&truth.functions) {
        let exported = !original.name.is_empty() && original.name != "_scale";
        let expected = if exported { original.name.as_str() } else { "" };
        assert_eq!(kept.name, expected, "at {:#x}", original.address);
    }
}

/// Only `_scale` is local, so only the stripped callee fixture lacks a name.
#[test]
fn a_dylib_with_an_unnamed_function_reads_as_scanned() {
    assert_eq!(read("arm64-callee-stripped.dylib").found_by, FoundBy::Scanning);
    assert_eq!(read("arm64-firmware-stripped.dylib").found_by, FoundBy::Symbols);
}

/// An unlinked object has no function starts, so its symbols bound its
/// functions, and they agree with the linked dylib.
#[rstest]
fn an_object_agrees_with_its_dylib(#[values("arm64", "arm64e")] arch: &str) {
    let object = read(&format!("{arch}-firmware.o"));
    let dylib = read(&format!("{arch}-firmware.dylib"));

    assert_eq!(names(&object), names(&dylib));
    let lengths = |binary: &Binary| -> BTreeSet<(String, usize)> {
        binary.functions.iter().map(|f| (f.name.clone(), f.code.len())).collect()
    };
    assert_eq!(lengths(&object), lengths(&dylib));
}

/// Without `LC_FUNCTION_STARTS`, the symbol table bounds the functions where
/// it names them all, and a stripped copy falls back to a scan.
#[test]
fn a_dylib_with_no_function_starts_reads_from_its_symbols() {
    // The missing load command moves `__text`, so compare without addresses.
    let lengths = |binary: &Binary| -> Vec<(String, usize)> {
        binary.functions.iter().map(|f| (f.name.clone(), f.code.len())).collect()
    };
    let truth = read("arm64-callee.dylib");
    let nostarts = read("arm64-callee-nostarts.dylib");
    assert_eq!(lengths(&nostarts), lengths(&truth));

    let stripped = read("arm64-callee-nostarts-stripped.dylib");
    assert!(!stripped.functions.is_empty(), "a scan still finds functions");
}

/// The firmware fixture edits `handle`, `dispatch` and `check_header`.
///
/// Without names, `check_header` changes too much to pair, at a score of
/// 0.29, as it does in the ELF build. It is reported as gone and new.
#[rstest]
fn finds_the_planned_edits(
    #[values("arm64", "arm64e")] arch: &str,
    #[values("", "-stripped")] strip: &str,
    #[values(UseNames::Yes, UseNames::No)] use_names: UseNames,
) {
    let before = read(&format!("{arch}-firmware{strip}.dylib"));
    let after = read(&format!("{arch}-firmware_v2{strip}.dylib"));
    let diff = diff_with(&before, &after, Options { use_names, ..Default::default() });

    assert_eq!(diff.removed.len(), diff.added.len());
    let gone = diff.removed.iter().map(|&index| before.functions[index].name.as_str());
    let reported: BTreeSet<&str> = changed(&diff, &before)
        .into_iter()
        .chain(gone)
        .filter(|name| !["_checksum", "_validate_length"].contains(name))
        .collect();
    assert_eq!(reported, BTreeSet::from(["_check_header", "_dispatch", "_handle"]));
}

/// `pick` calls `beta` in place of `alpha`, through a stub, and nothing else
/// changes. Only the indirect symbol table tells the two stubs apart.
#[rstest]
fn a_call_through_a_stub_to_another_symbol_is_reported(
    #[values("arm64", "arm64e")] arch: &str,
    #[values("", "-stripped")] strip: &str,
    #[values(UseNames::Yes, UseNames::No)] use_names: UseNames,
) {
    let before = read(&format!("{arch}-callee{strip}.dylib"));
    let after = read(&format!("{arch}-callee_v2{strip}.dylib"));
    let diff = diff_with(&before, &after, Options { use_names, ..Default::default() });

    let reported: Vec<_> = diff.changed().collect();
    assert_eq!(reported.len(), 1, "only `pick` changed");
    assert_eq!(before.functions[reported[0].before].name, "_pick");
    assert_eq!(reported[0].kinds.callees, 1);
}

/// A universal binary is read as its AArch64 slice.
#[test]
fn a_universal_binary_reads_as_its_aarch64_slice() {
    let universal = read("universal-firmware.dylib");
    let slice = read("arm64e-firmware.dylib");

    assert_eq!(universal.isa, Isa::Aarch64);
    assert_eq!(extents(&universal), extents(&slice));
    assert_eq!(names(&universal), names(&slice));
}

/// A universal binary with no AArch64 slice says why it cannot be read.
#[test]
fn a_universal_binary_with_no_aarch64_slice_is_refused() {
    let data = read_bytes("universal-x86_64-firmware.dylib");
    assert!(matches!(Binary::parse(&data), Err(ObjError::Parse(_))));
}

/// A kernelcache of iOS 15 and later is a fileset, read kext by kext.
///
/// Apple's kernelcaches are 66 MB each, too large to keep with the tests,
/// so this runs where `HERETICUS_KERNELCACHE` names the directories
/// `ipsw download ipsw --device iPhone15,2 --kernel` makes for iOS 27.0,
/// build 24A437, and iOS 27.0.1, build 24A446, separated by a colon.
#[test]
fn a_kernelcache_reads_every_kext_and_its_update_changes_only_values() {
    let Some(dirs) = std::env::var_os("HERETICUS_KERNELCACHE") else {
        eprintln!("skipped: set HERETICUS_KERNELCACHE to the two kernelcache directories");
        return;
    };
    let dirs = dirs.to_string_lossy().into_owned();
    let read = |dir: &str| {
        let data = std::fs::read(format!("{dir}/kernelcache.release.iPhone15,2"))
            .expect("the kernelcache");
        hereticus::obj::Binary::parse(&data).expect("the kernelcache parses")
    };
    let (old, new) = dirs.split_once(':').expect("two directories");
    let (before, after) = (read(old), read(new));
    // Read whole, the fileset gave 648 functions.
    assert_eq!((before.functions.len(), after.functions.len()), (175_109, 175_109));
    // A pointer of `__DATA_CONST` is a link of a chain until its fixup is
    // applied: `ipsw macho info --fixups` reads this one as a rebase to
    // 0xfffffff00a17b878.
    let regions = after.links.regions();
    let memory = hereticus::recovery::arch::Memory::new(&regions);
    let pointer = memory.bytes(0xffff_fff0_07bb_0018, 8).expect("the slot is loaded");
    assert_eq!(u64::from_le_bytes(pointer.try_into().expect("8 bytes")), 0xffff_fff0_0a17_b878);
    let diff = hereticus::matching::diff(&before, &after);
    assert!(diff.removed.is_empty() && diff.added.is_empty());
    // The update changed constants and the build paths in texts, not code.
    assert!(diff.changed().all(|pair| pair.changed == hereticus::matching::Changed::InDetail));
}
