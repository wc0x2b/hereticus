//! The dynamic segment, read through the program headers, says what the
//! section headers say, and a damaged one reads without a panic.

use std::collections::BTreeSet;
use std::path::Path;

use hereticus::dynamic::Dynamic;
use hereticus::obj::Binary;
use object::{Object, ObjectSymbol, SymbolKind};
use rstest::rstest;

fn library(arch: &str, level: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/build/backports/zlib-before")
        .join(format!("{arch}-{level}"))
        .join("lib.so");
    std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{}: {err}, run `just backports` first", path.display()))
}

/// GNU ld writes only a GNU hash table, and lld writes both kinds.
#[rstest]
fn the_exports_are_the_functions_of_the_dynamic_symbol_table(
    #[values("arm", "thumb", "aarch64", "mips", "mipsel", "mips16")] arch: &str,
    #[values("O2", "gcc-O2")] level: &str,
) {
    if arch == "mips16" && level == "O2" {
        return;
    }
    let data = library(arch, level);
    let file = object::File::parse(data.as_slice()).expect("a fixture library parses");
    let expected: BTreeSet<(String, u64)> = file
        .dynamic_symbols()
        .filter(|symbol| symbol.kind() == SymbolKind::Text && symbol.size() > 0)
        .filter(|symbol| symbol.section_index().is_some())
        .map(|symbol| (symbol.name().unwrap().to_string(), symbol.address()))
        .collect();

    let dynamic = Dynamic::of(&file).expect("a shared library has a dynamic segment");
    let found: BTreeSet<(String, u64)> =
        dynamic.exports().iter().map(|export| (export.name.to_string(), export.address)).collect();

    assert!(!expected.is_empty());
    assert_eq!(found, expected, "{arch} {level}");
}

/// Each slot the dynamic segment names holds a symbol the library imports
/// or exports.
#[rstest]
fn the_slots_are_named_for_dynamic_symbols(
    #[values("arm", "thumb", "aarch64", "mips", "mipsel")] arch: &str,
) {
    let data = library(arch, "gcc-O2");
    let file = object::File::parse(data.as_slice()).expect("a fixture library parses");
    let names: BTreeSet<String> =
        file.dynamic_symbols().map(|symbol| symbol.name().unwrap().to_string()).collect();

    let slots = Dynamic::of(&file).expect("a dynamic segment").slot_names();
    assert!(!slots.is_empty(), "{arch}");
    for (slot, name) in &slots {
        assert!(names.contains(name), "{arch}: slot {slot:#x} names {name}");
    }
}

/// A shared library fills its vtables through dynamic relocations, so
/// the tables of functions of tinyxml2 read the same on x86 as on ARM of
/// the same word size, by the names of their functions. GNU `ld` leaves
/// zero in each word that an absolute relocation of x86 fills.
#[rstest]
#[case::x86_64("x86_64", "aarch64")]
#[case::x86("i686", "arm")]
fn the_vtables_read_the_same_on_x86_as_on_arm(#[case] arch: &str, #[case] same_width: &str) {
    let tables = |arch: &str| -> Vec<Vec<String>> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/build/backports/tinyxml2-before")
            .join(format!("{arch}-O2"))
            .join("lib.so");
        let data = std::fs::read(&path)
            .unwrap_or_else(|err| panic!("{}: {err}, run `just backports` first", path.display()));
        let binary = Binary::parse(&data).expect("a fixture library parses");
        let mut tables: Vec<Vec<String>> = binary
            .function_tables()
            .iter()
            .map(|table| table.iter().map(|&index| binary.functions[index].name.clone()).collect())
            .collect();
        tables.sort_unstable();
        tables
    };
    let expected = tables(same_width);
    assert!(expected.len() > 10, "tinyxml2 holds a vtable for each kind of node");
    assert_eq!(tables(arch), expected, "{arch}");
}

/// Any bytes written over the dynamic segment and the tables it names read
/// without a panic.
#[test]
fn a_damaged_dynamic_segment_reads_without_a_panic() {
    let pristine = library("mipsel", "gcc-O2");
    bolero::check!().with_type::<Vec<(u16, u8)>>().for_each(|writes| {
        let mut data = pristine.clone();
        for &(at, value) in writes {
            // The dynamic segment and the tables lie in the first pages.
            if let Some(byte) = data.get_mut(usize::from(at)) {
                *byte = value;
            }
        }
        let Ok(file) = object::File::parse(data.as_slice()) else { return };
        if let Some(dynamic) = Dynamic::of(&file) {
            let _ = dynamic.exports();
            let _ = dynamic.slot_names();
        }
    });
}
