//! Read what a Windows PE file says about its functions and its calls.
//!
//! An x86-64 PE file holds an exception directory, the `.pdata` section,
//! with the start and the end of each function that changes the stack.
//! Windows unwinds through it, so stripping keeps it. A leaf function that
//! does not change the stack needs no entry, so the code between two entries
//! is scanned as code with no index.
//!
//! A call to another DLL goes through a slot of the import address table,
//! and the import directory names the symbol each slot holds. The export
//! directory names each function the DLL exports, by its start only.

use core::ops::Range;
use std::collections::BTreeMap;

use object::pe;
use object::read::pe::{ExportTarget, ImageNtHeaders, Import, PeFile};
use object::{LittleEndian as LE, Object, ObjectSection, SectionKind};

/// The flag of unwind information that says the entry continues the
/// function of another entry, as the code after a shrink-wrapped prologue
/// does.
const UNW_FLAG_CHAININFO: u8 = 0x4;

/// Where each function that the exception directory of `file` lists starts
/// and ends, in address order. Empty where `file` is no x86-64 PE file.
///
/// An entry with chained unwind information that starts where the entry
/// before it ends is one function with that entry, so the two are joined.
/// A chained entry elsewhere, as a block that the compiler moved away from
/// its function, is a range of its own.
pub fn function_ranges(file: &object::File<'_>) -> Vec<Range<u64>> {
    let object::File::Pe64(pe) = file else { return Vec::new() };
    if pe.nt_headers().file_header.machine.get(LE) != pe::IMAGE_FILE_MACHINE_AMD64 {
        return Vec::new();
    }
    let data = pe.data();
    let sections = pe.section_table();
    let Some(directory) = pe.data_directory(pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION) else {
        return Vec::new();
    };
    let Ok(table) = directory.data(data, &sections) else { return Vec::new() };
    let Ok(entries) = object::pod::slice_from_all_bytes::<pe::ImageRuntimeFunctionEntry>(table)
    else {
        return Vec::new();
    };

    let base = pe.relative_address_base();
    let unwind_of = |unwind_info: u32| {
        let flags = sections.pe_data_at(data, unwind_info).and_then(|info| info.first());
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

/// The symbol each slot of the import address table of `file` holds, by the
/// address of the slot. Empty where `file` is no PE file.
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
    let mut names = BTreeMap::new();
    let Ok(Some(table)) = pe.import_table() else { return names };
    let Ok(mut descriptors) = table.descriptors() else { return names };
    let base = pe.relative_address_base();
    let slot_width = core::mem::size_of::<Pe::ImageThunkData>() as u64;
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
        let Ok(mut thunks) = table.thunks(lookup) else { continue };
        let mut slot = base + u64::from(slots);
        while let Ok(Some(thunk)) = thunks.next::<Pe>() {
            let name = match table.import::<Pe>(thunk) {
                Ok(Import::Name(_, name)) => String::from_utf8_lossy(name).into_owned(),
                Ok(Import::Ordinal(ordinal)) => format!("{library}#{ordinal}"),
                Err(_) => break,
            };
            names.insert(slot, name);
            slot += slot_width;
        }
    }
    names
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
            }
        });
    }
}
