//! Read what a Windows PE file says about its functions and its calls.
//!
//! An x86-64 or ARM64 PE file holds an exception directory, the `.pdata`
//! section, with the start and the length of each function that changes
//! the stack. Windows unwinds through it, so stripping keeps it. A leaf
//! function that does not change the stack needs no entry, so the code
//! between two entries is scanned as code with no index. 32-bit x86 has no
//! such directory.
//!
//! A call to another DLL goes through a slot of the import address table,
//! and the import directory names the symbol each slot holds. A DLL that
//! loads on its first call has a slot in the delay-load directory instead.
//! The export directory names each function the DLL exports, by its start
//! only.

use core::ops::Range;
use std::collections::BTreeMap;

use object::pe;
use object::read::pe::{ExportTarget, ImageNtHeaders, Import, ImportThunkList, PeFile};
use object::{LittleEndian as LE, Object, ObjectSection, SectionKind};

/// The flag of unwind information that says the entry continues the
/// function of another entry, as the code after a shrink-wrapped prologue
/// does.
const UNW_FLAG_CHAININFO: u8 = 0x4;

/// The bits of an ARM64 entry that say where its length is.
const ARM64_FLAG: u32 = 0b11;
/// The flag of an ARM64 entry whose unwind information lies in `.xdata`.
const ARM64_XDATA: u32 = 0;
/// The flag of an ARM64 entry that packs its unwind information.
const ARM64_PACKED: u32 = 1;
/// The flag of an ARM64 entry that packs the unwind information of a
/// fragment of a function, with no prologue.
const ARM64_PACKED_FRAGMENT: u32 = 2;
/// The bits of the length, in words, of the function of an ARM64 entry,
/// past the flag where the entry packs it, and at bit 0 of `.xdata`.
const ARM64_PACKED_LENGTH: u32 = 0x7ff;
const ARM64_XDATA_LENGTH: u32 = 0x3_ffff;
/// An ARM64 instruction is one word.
const ARM64_WORD: u64 = 4;

/// Where each function that the exception directory of `file` lists starts
/// and ends, in address order. Empty where `file` is no x86-64 or ARM64 PE
/// file.
///
/// An entry with chained unwind information, or an ARM64 fragment, that
/// starts where the entry before it ends is one function with that entry,
/// so the two are joined. A chained entry elsewhere, as a block that the
/// compiler moved away from its function, is a range of its own.
pub fn function_ranges(file: &object::File<'_>) -> Vec<Range<u64>> {
    let object::File::Pe64(pe) = file else { return Vec::new() };
    let data = pe.data();
    let sections = pe.section_table();
    let Some(directory) = pe.data_directory(pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION) else {
        return Vec::new();
    };
    let Ok(table) = directory.data(data, &sections) else { return Vec::new() };
    let base = pe.relative_address_base();
    let at = |rva: u32| sections.pe_data_at(data, rva);
    match pe.nt_headers().file_header.machine.get(LE) {
        pe::IMAGE_FILE_MACHINE_AMD64 => x64_ranges(table, base, at),
        pe::IMAGE_FILE_MACHINE_ARM64 => arm64_ranges(table, base, at),
        _ => Vec::new(),
    }
}

/// The ranges of the x86-64 exception directory `table`, of an image at
/// `base`, where `at` gives the bytes at an address relative to `base`.
fn x64_ranges<'data>(
    table: &[u8],
    base: u64,
    at: impl Fn(u32) -> Option<&'data [u8]>,
) -> Vec<Range<u64>> {
    let Ok(entries) = object::pod::slice_from_all_bytes::<pe::ImageRuntimeFunctionEntry>(table)
    else {
        return Vec::new();
    };
    let unwind_of = |unwind_info: u32| {
        let flags = at(unwind_info).and_then(|info| info.first());
        match flags
            .is_some_and(|&version_and_flags| (version_and_flags >> 3) & UNW_FLAG_CHAININFO != 0)
        {
            true => Unwind::Chained,
            false => Unwind::Own,
        }
    };
    joined(entries.iter().map(|entry| {
        let start = base + u64::from(entry.begin_address.get(LE));
        let end = base + u64::from(entry.end_address.get(LE));
        (start..end, unwind_of(entry.unwind_info_address_or_data.get(LE)))
    }))
}

/// The ranges of the ARM64 exception directory `table`, as
/// [`x64_ranges`] reads one of x86-64.
///
/// An ARM64 entry gives the start of its function and the length, in
/// words, either packed in the entry or at the start of its `.xdata`. An
/// entry whose flag is reserved, or whose `.xdata` is not there, is left
/// out.
fn arm64_ranges<'data>(
    table: &[u8],
    base: u64,
    at: impl Fn(u32) -> Option<&'data [u8]>,
) -> Vec<Range<u64>> {
    let Ok(entries) =
        object::pod::slice_from_all_bytes::<pe::ImageArm64RuntimeFunctionEntry>(table)
    else {
        return Vec::new();
    };
    let packed_length = |unwind: u32| (unwind >> 2) & ARM64_PACKED_LENGTH;
    let length_and_unwind = |unwind: u32| match unwind & ARM64_FLAG {
        ARM64_XDATA => {
            let header = at(unwind)?.first_chunk::<4>()?;
            Some((u32::from_le_bytes(*header) & ARM64_XDATA_LENGTH, Unwind::Own))
        }
        ARM64_PACKED => Some((packed_length(unwind), Unwind::Own)),
        ARM64_PACKED_FRAGMENT => Some((packed_length(unwind), Unwind::Chained)),
        _ => None,
    };
    joined(entries.iter().filter_map(|entry| {
        let (words, unwind) = length_and_unwind(entry.unwind_data.get(LE))?;
        let start = base + u64::from(entry.begin_address.get(LE));
        Some((start..start + u64::from(words) * ARM64_WORD, unwind))
    }))
}

/// Whether an entry of the exception directory unwinds on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unwind {
    /// The entry describes its own frame.
    Own,
    /// The entry continues the unwind information of another entry.
    Chained,
}

/// The ranges of the functions that `entries` list, in address order, with
/// each chained entry joined to the one before it where it starts at its
/// end. An empty or reversed range is dropped.
fn joined(entries: impl IntoIterator<Item = (Range<u64>, Unwind)>) -> Vec<Range<u64>> {
    let mut ranges: Vec<Range<u64>> = Vec::new();
    for (range, unwind) in entries {
        if range.is_empty() {
            continue;
        }
        match ranges.last_mut() {
            Some(last) if last.end == range.start && unwind == Unwind::Chained => {
                last.end = range.end;
            }
            _ => ranges.push(range),
        }
    }
    ranges.sort_by_key(|range| range.start);
    ranges
}

/// Where each function that `file` exports starts, and its name, in address
/// order. Empty where `file` is no PE file.
///
/// The export directory gives no size. An export that forwards to another
/// DLL, or that names data, is left out.
pub fn exports<'data>(file: &object::File<'data>) -> Vec<(u64, &'data str)> {
    let mut named = match file {
        object::File::Pe32(pe) => exports_of(pe),
        object::File::Pe64(pe) => exports_of(pe),
        _ => return Vec::new(),
    };
    let code: Vec<Range<u64>> = file
        .sections()
        .filter(|section| section.kind() == SectionKind::Text)
        .map(|section| section.address()..section.address() + section.size())
        .collect();
    named.retain(|(address, _)| code.iter().any(|range| range.contains(address)));
    named.sort_unstable();
    named
}

fn exports_of<'data, Pe: ImageNtHeaders>(pe: &PeFile<'data, Pe>) -> Vec<(u64, &'data str)> {
    let Ok(Some(table)) = pe.export_table() else { return Vec::new() };
    let Ok(exports) = table.exports() else { return Vec::new() };
    let base = pe.relative_address_base();
    exports
        .into_iter()
        .filter_map(|export| {
            let ExportTarget::Address(address) = export.target else { return None };
            let name = core::str::from_utf8(export.name?).ok()?;
            Some((base + u64::from(address), name))
        })
        .collect()
}

/// The symbol each slot of the import address table of `file` holds, and
/// each slot of its delay-load directory, by the address of the slot.
/// Empty where `file` is no PE file.
///
/// An import by ordinal has no name, so it reads as the DLL and the
/// ordinal, as `ws2_32.dll#23`.
pub fn import_slot_names(file: &object::File<'_>) -> BTreeMap<u64, String> {
    match file {
        object::File::Pe32(pe) => slot_names_of(pe),
        object::File::Pe64(pe) => slot_names_of(pe),
        _ => BTreeMap::new(),
    }
}

fn slot_names_of<Pe: ImageNtHeaders>(pe: &PeFile<'_, Pe>) -> BTreeMap<u64, String> {
    let mut names = bound_slot_names_of(pe);
    // A DLL can import only through the delay-load directory, with no
    // import directory at all.
    names.extend(delayed_slot_names_of(pe));
    names
}

/// The symbol each slot of the import directory of `pe` holds.
fn bound_slot_names_of<Pe: ImageNtHeaders>(pe: &PeFile<'_, Pe>) -> BTreeMap<u64, String> {
    let mut names = BTreeMap::new();
    let Ok(Some(table)) = pe.import_table() else { return names };
    let Ok(mut descriptors) = table.descriptors() else { return names };
    let base = pe.relative_address_base();
    while let Ok(Some(descriptor)) = descriptors.next() {
        let Ok(library) = table.name(descriptor.name.get(LE)) else { continue };
        let library = String::from_utf8_lossy(library);
        let slots = descriptor.first_thunk.get(LE);
        // The lookup table names what the address table holds before the
        // loader binds it. An old linker leaves out the lookup table, and
        // the address table names the imports itself.
        let lookup = match descriptor.original_first_thunk.get(LE) {
            0 => slots,
            lookup => lookup,
        };
        let Ok(thunks) = table.thunks(lookup) else { continue };
        let first_slot = base + u64::from(slots);
        name_slots::<Pe>(&mut names, thunks, first_slot, &library, |thunk| {
            table.import::<Pe>(thunk)
        });
    }
    names
}

/// The symbol each slot of the delay-load directory of `pe` holds.
///
/// A slot holds a thunk that loads the DLL, until the first call binds it.
/// Only a directory that gives addresses relative to the image is read, as
/// every linker since Visual C++ 7 writes it.
fn delayed_slot_names_of<Pe: ImageNtHeaders>(pe: &PeFile<'_, Pe>) -> BTreeMap<u64, String> {
    /// The attribute that says the directory gives relative addresses.
    const RELATIVE_ADDRESSES: u32 = 1;

    let mut names = BTreeMap::new();
    let Ok(Some(table)) = pe.delay_load_import_table() else { return names };
    let Ok(mut descriptors) = table.descriptors() else { return names };
    let base = pe.relative_address_base();
    while let Ok(Some(descriptor)) = descriptors.next() {
        if descriptor.attributes.get(LE) & RELATIVE_ADDRESSES == 0 {
            continue;
        }
        let Ok(library) = table.name(descriptor.dll_name_rva.get(LE)) else { continue };
        let library = String::from_utf8_lossy(library);
        let Ok(thunks) = table.thunks(descriptor.import_name_table_rva.get(LE)) else {
            continue;
        };
        let first_slot = base + u64::from(descriptor.import_address_table_rva.get(LE));
        name_slots::<Pe>(&mut names, thunks, first_slot, &library, |thunk| {
            table.import::<Pe>(thunk)
        });
    }
    names
}

/// Name the slots from `first_slot` on, one for each of `thunks`, which
/// `import` reads, in `names`. An import by ordinal reads as `library` and
/// the ordinal. A thunk that does not read ends the list.
fn name_slots<'data, Pe: ImageNtHeaders>(
    names: &mut BTreeMap<u64, String>,
    mut thunks: ImportThunkList<'data>,
    first_slot: u64,
    library: &str,
    import: impl Fn(Pe::ImageThunkData) -> object::Result<Import<'data>>,
) {
    let slot_width = core::mem::size_of::<Pe::ImageThunkData>() as u64;
    let mut slot = first_slot;
    while let Ok(Some(thunk)) = thunks.next::<Pe>() {
        let name = match import(thunk) {
            Ok(Import::Name(_, name)) => String::from_utf8_lossy(name).into_owned(),
            Ok(Import::Ordinal(ordinal)) => format!("{library}#{ordinal}"),
            Err(_) => break,
        };
        names.insert(slot, name);
        slot += slot_width;
    }
}

/// Where each function the symbols of `file` name starts, where `file` is
/// a PE file that keeps its symbols, as one linked with `/debug:symtab`.
pub fn symbol_starts(file: &object::File<'_>) -> Vec<u64> {
    use object::ObjectSymbol;

    if !matches!(file, object::File::Pe32(_) | object::File::Pe64(_)) {
        return Vec::new();
    }
    file.symbols()
        .filter(|symbol| symbol.kind() == object::SymbolKind::Text)
        .map(|symbol| symbol.address())
        .collect()
}

/// Where the entry point of `file` is, where it is a PE file that has one.
/// A DLL linked with `/noentry` has none.
pub fn entry_point(file: &object::File<'_>) -> Option<u64> {
    use object::read::pe::ImageOptionalHeader;

    let (base, rva) = match file {
        object::File::Pe32(pe) => {
            (pe.relative_address_base(), pe.nt_headers().optional_header.address_of_entry_point())
        }
        object::File::Pe64(pe) => {
            (pe.relative_address_base(), pe.nt_headers().optional_header.address_of_entry_point())
        }
        _ => return None,
    };
    (rva != 0).then(|| base + u64::from(rva))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chained_entry_joins_the_one_it_follows() {
        let entries = [
            (0x1000..0x1010, Unwind::Own),
            (0x1010..0x1020, Unwind::Chained),
            (0x1020..0x1030, Unwind::Own),
        ];
        assert_eq!(joined(entries), [0x1000..0x1020, 0x1020..0x1030]);
    }

    /// A block that the compiler moved away from its function is chained,
    /// but lies apart, so it stays a range of its own.
    #[test]
    fn a_chained_entry_apart_from_the_one_before_stays_apart() {
        let entries = [(0x1000..0x1010, Unwind::Own), (0x2000..0x2008, Unwind::Chained)];
        assert_eq!(joined(entries), [0x1000..0x1010, 0x2000..0x2008]);
    }

    #[test]
    fn an_empty_or_reversed_entry_is_dropped() {
        // A broken directory can hold an end before its start.
        let (start, end) = (0x1010, 0x1000);
        let entries = [(start..end, Unwind::Own), (0x1000..0x1000, Unwind::Own)];
        assert!(joined(entries).is_empty());
    }

    /// An ARM64 entry: the start of its function, relative to the image,
    /// and its unwind word.
    fn arm64_entry(start: u32, unwind: u32) -> [u8; 8] {
        let mut entry = [0; 8];
        entry[..4].copy_from_slice(&start.to_le_bytes());
        entry[4..].copy_from_slice(&unwind.to_le_bytes());
        entry
    }

    /// The unwind word of an ARM64 entry that packs a function of `words`.
    fn packed(flag: u32, words: u32) -> u32 {
        flag | (words << 2)
    }

    #[test]
    fn an_arm64_entry_gives_its_length_packed_or_in_xdata() {
        const BASE: u64 = 0x1_8000_0000;
        let xdata_at = 0x3000;
        let table: Vec<u8> = [
            arm64_entry(0x1000, packed(ARM64_PACKED, 4)),
            arm64_entry(0x1010, packed(ARM64_PACKED_FRAGMENT, 2)),
            arm64_entry(0x1100, xdata_at),
            arm64_entry(0x1200, 0b11),
        ]
        .concat();
        let xdata = 8u32.to_le_bytes();
        let at = |rva: u32| (rva == xdata_at).then_some(&xdata[..]);
        assert_eq!(
            arm64_ranges(&table, BASE, at),
            [BASE + 0x1000..BASE + 0x1018, BASE + 0x1100..BASE + 0x1120],
            "the fragment joins the entry before it, and the reserved flag is left out"
        );
    }

    #[test]
    fn an_arm64_entry_with_no_xdata_is_left_out() {
        let table = arm64_entry(0x1000, 0x3000);
        assert!(arm64_ranges(&table, 0, |_| None).is_empty());
        assert!(arm64_ranges(&table[..7], 0, |_| None).is_empty(), "a broken table");
    }

    #[test]
    fn an_x64_entry_reads_chained_from_its_unwind_information() {
        let entry = |start: u32, end: u32, unwind: u32| {
            [start, end, unwind].iter().flat_map(|word| word.to_le_bytes()).collect::<Vec<u8>>()
        };
        let table = [entry(0x1000, 0x1010, 0x3000), entry(0x1010, 0x1020, 0x3010)].concat();
        let own = [1u8];
        let chained = [1 | (UNW_FLAG_CHAININFO << 3)];
        let at = |rva: u32| match rva {
            0x3000 => Some(&own[..]),
            0x3010 => Some(&chained[..]),
            _ => None,
        };
        assert_eq!(x64_ranges(&table, 0, at), vec![(0x1000..0x1020)]);
        assert_eq!(x64_ranges(&table, 0, |_| Some(&own[..])), [0x1000..0x1010, 0x1010..0x1020]);
    }

    #[test]
    fn a_file_that_is_no_pe_file_has_no_index_exports_or_imports() {
        use object::write::Object as Writer;
        let writer = Writer::new(
            object::BinaryFormat::Elf,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let data = writer.write().expect("an empty object writes");
        let file = object::File::parse(&*data).expect("it parses");
        assert!(function_ranges(&file).is_empty());
        assert!(exports(&file).is_empty());
        assert!(import_slot_names(&file).is_empty());
        assert_eq!(entry_point(&file), None);
        assert!(symbol_starts(&file).is_empty());
    }

    /// Each joined range is in order and apart from the next, and covers
    /// what the entries do.
    #[test]
    fn joined_ranges_are_ordered_and_cover_the_entries() {
        bolero::check!().with_type::<Vec<(u16, u8, bool)>>().for_each(|entries| {
            let entries: Vec<(Range<u64>, Unwind)> = entries
                .iter()
                .map(|&(start, length, chained)| {
                    let start = u64::from(start);
                    let unwind = if chained { Unwind::Chained } else { Unwind::Own };
                    (start..start + u64::from(length), unwind)
                })
                .collect();
            let ranges = joined(entries.clone());
            assert!(ranges.windows(2).all(|pair| pair[0].start <= pair[1].start));
            for (range, _) in entries.iter().filter(|(range, _)| !range.is_empty()) {
                assert!(
                    ranges
                        .iter()
                        .any(|joined| joined.start <= range.start && range.end <= joined.end),
                    "{range:?} is in no range of {ranges:?}"
                );
            }
        });
    }

    /// A broken file must not panic any reader.
    #[test]
    fn arbitrary_bytes_do_not_panic() {
        bolero::check!().for_each(|data: &[u8]| {
            if let Ok(file) = object::File::parse(data) {
                let _ = function_ranges(&file);
                let _ = exports(&file);
                let _ = import_slot_names(&file);
                let _ = entry_point(&file);
                let _ = symbol_starts(&file);
            }
        });
    }
}
