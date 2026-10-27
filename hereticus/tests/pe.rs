//! Read x86-64 Windows DLLs.
//!
//! `just fixtures` links each fixture as a DLL that exports one function and
//! imports the rest from `host.dll`, and strips a copy of each. The symbol
//! table of the DLL names every function, so it is the answer for the
//! stripped copy.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hereticus::matching::{Options, UseNames, diff_with};
use hereticus::obj::{Binary, FoundBy, Isa};
use rstest::rstest;

fn path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/pe").join(name)
}

fn read(name: &str) -> Binary {
    let path = path(name);
    let data = std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{}: {err}, run `just fixtures` first", path.display()));
    Binary::parse(&data).unwrap_or_else(|err| panic!("{name}: {err}"))
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

/// The symbol table names each function, and each import thunk by its
/// import.
#[test]
fn a_dll_names_each_function_and_each_import() {
    let binary = read("firmware.dll");

    assert_eq!(binary.isa, Isa::X86_64);
    assert_eq!(binary.found_by, FoundBy::Symbols);
    assert_eq!(
        names(&binary),
        BTreeSet::from([
            "check_header",
            "checksum",
            "dispatch",
            "handle",
            "log_event",
            "validate_length"
        ])
    );
}

/// Stripping removes the names of the functions the DLL does not export,
/// but not where they start and end. The exception directory bounds the
/// functions that change the stack, and the scan finds the leaf functions
/// between them.
#[rstest]
fn a_stripped_dll_keeps_its_bounds_its_export_and_its_imports(
    #[values("basic", "basic_v2", "firmware", "firmware_v2", "calls")] fixture: &str,
) {
    let truth = read(&format!("{fixture}.dll"));
    let stripped = read(&format!("{fixture}-stripped.dll"));

    assert_eq!(stripped.found_by, FoundBy::Scanning);
    assert_eq!(extents(&stripped), extents(&truth));
    let export = match fixture {
        "basic" | "basic_v2" => "call_chain",
        "calls" => "nested",
        _ => "handle",
    };
    let imports = ["alpha", "beta", "gamma_", "sink", "log_event", "crypto_verify"];
    for (kept, original) in stripped.functions.iter().zip(&truth.functions) {
        let named = original.name == export || imports.contains(&original.name.as_str());
        let expected = if named { original.name.as_str() } else { "" };
        assert_eq!(kept.name, expected, "at {:#x}", original.address);
    }
}

/// The firmware fixture edits `handle`, `dispatch` and `check_header`, and
/// the new version calls `crypto_verify`, a new import.
///
/// A stripped DLL starts each function where the DLL with symbols does, so
/// that DLL names what the diff of the stripped ones reports.
#[rstest]
fn finds_the_planned_edits(
    #[values("", "-stripped")] strip: &str,
    #[values(UseNames::Yes, UseNames::No)] use_names: UseNames,
) {
    let truth = (read("firmware.dll"), read("firmware_v2.dll"));
    let before = read(&format!("firmware{strip}.dll"));
    let after = read(&format!("firmware_v2{strip}.dll"));
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
