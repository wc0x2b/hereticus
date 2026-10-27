//! Read Windows PE files for x86-64, 32-bit x86 and ARM64.
//!
//! `just fixtures` links each fixture as a DLL that exports one function and
//! imports the rest from `host.dll`, and strips a copy of each. The symbol
//! table of the DLL names every function, so it is the answer for the
//! stripped copy. For x86-64 it also links the firmware fixture as an
//! executable, as a DLL that imports by ordinal, and as one that loads
//! `host.dll` on its first call.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hereticus::matching::{Options, UseNames, diff_with};
use hereticus::obj::{Binary, FoundBy, Isa};
use rstest::rstest;

fn path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/pe").join(name)
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

/// The name of the function of `binary` that starts at `address`.
fn name_at(binary: &Binary, address: u64) -> &str {
    let function = binary.functions.iter().find(|function| function.address == address);
    function.map_or("", |function| function.name.as_str())
}

/// The entry point of the PE file `name`.
fn entry_point(name: &str) -> Option<u64> {
    let data = read_bytes(name);
    let file = object::File::parse(&*data).expect("a fixture parses");
    hereticus::recovery::pe::entry_point(&file)
}

/// The functions that the fixtures import from `host.dll`.
const IMPORTS: [&str; 6] = ["alpha", "beta", "gamma_", "sink", "log_event", "crypto_verify"];

/// The symbol table names each function, and each import thunk by its
/// import.
#[rstest]
#[case::x86_64("x86_64", Isa::X86_64)]
#[case::i686("i686", Isa::X86)]
#[case::arm64("arm64", Isa::Aarch64)]
fn a_dll_names_each_function_and_each_import(#[case] arch: &str, #[case] isa: Isa) {
    let binary = read(&format!("{arch}-firmware.dll"));

    assert_eq!(binary.isa, isa);
    assert_eq!(binary.found_by, FoundBy::Symbols);
    let expected =
        ["check_header", "checksum", "dispatch", "handle", "log_event", "validate_length"];
    assert_eq!(names(&binary), BTreeSet::from(expected));
}

/// Stripping removes the names of the functions the DLL does not export,
/// but not where they start and end. The exception directory bounds the
/// functions that change the stack, and the scan finds the leaf functions
/// between them. 32-bit x86 has no exception directory, so the scan finds
/// all of them.
#[rstest]
fn a_stripped_dll_keeps_its_bounds_its_export_and_its_imports(
    #[values("x86_64", "i686", "arm64")] arch: &str,
    #[values("basic", "basic_v2", "firmware", "firmware_v2", "calls")] fixture: &str,
) {
    let truth = read(&format!("{arch}-{fixture}.dll"));
    let stripped = read(&format!("{arch}-{fixture}-stripped.dll"));

    assert_eq!(stripped.found_by, FoundBy::Scanning);
    assert_eq!(extents(&stripped), extents(&truth));
    let export = match fixture {
        "basic" | "basic_v2" => "call_chain",
        "calls" => "nested",
        _ => "handle",
    };
    for (kept, original) in stripped.functions.iter().zip(&truth.functions) {
        let named = original.name == export || IMPORTS.contains(&original.name.as_str());
        let expected = if named { original.name.as_str() } else { "" };
        assert_eq!(kept.name, expected, "at {:#x}", original.address);
    }
}

/// Each range of the exception directory is one function the symbol table
/// bounds, exactly. The basic fixture for ARM64 holds only leaf functions,
/// so it has no exception directory.
#[rstest]
fn the_exception_directory_bounds_functions_exactly(
    #[values("x86_64", "arm64")] arch: &str,
    #[values("firmware", "calls")] fixture: &str,
) {
    let name = format!("{arch}-{fixture}-stripped.dll");
    let data = read_bytes(&name);
    let file = object::File::parse(&*data).expect("a fixture parses");
    let ranges = hereticus::recovery::pe::function_ranges(&file);
    let truth = extents(&read(&format!("{arch}-{fixture}.dll")));

    assert!(!ranges.is_empty(), "{name}: an exception directory");
    for range in ranges {
        let extent = (range.start, (range.end - range.start) as usize);
        assert!(truth.contains(&extent), "{name}: {range:#x?} bounds no function");
    }
}

/// The firmware fixture edits `handle`, `dispatch` and `check_header`, and
/// the new version calls `crypto_verify`, a new import.
///
/// A stripped DLL starts each function where the DLL with symbols does, so
/// that DLL names what the diff of the stripped ones reports.
#[rstest]
fn finds_the_planned_edits(
    #[values("x86_64", "i686", "arm64")] arch: &str,
    #[values("", "-stripped")] strip: &str,
    #[values(UseNames::Yes, UseNames::No)] use_names: UseNames,
) {
    let truth = (read(&format!("{arch}-firmware.dll")), read(&format!("{arch}-firmware_v2.dll")));
    let before = read(&format!("{arch}-firmware{strip}.dll"));
    let after = read(&format!("{arch}-firmware_v2{strip}.dll"));
    let diff = diff_with(&before, &after, Options { use_names, ..Default::default() });

    let gone = diff.removed.iter().map(|&index| before.functions[index].address);
    let reported: BTreeSet<&str> = diff
        .changed()
        .map(|pair| before.functions[pair.before].address)
        .chain(gone)
        .map(|address| name_at(&truth.0, address))
        .filter(|name| !["checksum", "validate_length"].contains(name))
        .collect();
    assert_eq!(reported, BTreeSet::from(["check_header", "dispatch", "handle"]));
    let added: Vec<&str> =
        diff.added.iter().map(|&index| name_at(&truth.1, after.functions[index].address)).collect();
    assert_eq!(added, ["crypto_verify"]);
}

/// An executable exports nothing, but its entry point starts a function.
/// A DLL linked with `/noentry` has no entry point.
#[test]
fn a_stripped_executable_keeps_its_bounds_and_its_imports() {
    let truth = read("x86_64-firmware.exe");
    let stripped = read("x86_64-firmware-stripped.exe");

    assert_eq!(extents(&stripped), extents(&truth));
    let entry = entry_point("x86_64-firmware-stripped.exe").expect("an entry point");
    assert_eq!(name_at(&truth, entry), "handle");
    assert!(names(&stripped).contains("log_event"));
    assert_eq!(entry_point("x86_64-firmware-stripped.dll"), None);
}

/// An import by ordinal has no name, so the thunk of a stripped DLL takes
/// the DLL and the ordinal.
#[test]
fn an_import_by_ordinal_reads_as_its_dll_and_ordinal() {
    let before = read("x86_64-firmware-ordinals-stripped.dll");
    let after = read("x86_64-firmware_v2-ordinals-stripped.dll");

    assert!(names(&before).contains("host.dll#1"));
    assert!(names(&after).is_superset(&BTreeSet::from(["host.dll#1", "host.dll#2"])));
    assert_eq!(extents(&before), extents(&read("x86_64-firmware-ordinals.dll")));
}

/// A DLL that loads `host.dll` on its first call jumps through a slot of
/// the delay-load directory, which names each thunk.
///
/// LLD writes the code that loads the DLL after the thunks, with no
/// symbol, so the thunks end where the scan finds that code starts, and
/// the DLL with symbols reads as scanned.
#[rstest]
fn a_thunk_of_the_delay_load_directory_takes_its_import(
    #[values("firmware", "firmware_v2")] fixture: &str,
) {
    let truth = read(&format!("x86_64-{fixture}-delayed.dll"));
    let stripped = read(&format!("x86_64-{fixture}-delayed-stripped.dll"));

    assert_eq!(extents(&stripped), extents(&truth));
    assert_eq!(truth.found_by, FoundBy::Scanning);
    /// `jmp [rip + slot]`.
    const THUNK_BYTES: usize = 6;
    let imports = match fixture {
        "firmware" => &["log_event"][..],
        _ => &["crypto_verify", "log_event"],
    };
    for import in imports {
        let thunk = stripped.functions.iter().find(|function| function.name == *import);
        let thunk = thunk.unwrap_or_else(|| panic!("{import}: a thunk"));
        assert_eq!(thunk.code.len(), THUNK_BYTES, "{import}");
        assert_eq!(name_at(&truth, thunk.address), *import);
    }
}
