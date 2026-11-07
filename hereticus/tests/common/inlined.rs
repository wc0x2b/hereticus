//! The inlined copies of each function, from the DWARF of a debug file.

use std::collections::BTreeMap;
use std::path::Path;

/// A range of code and a name: start, end and the name.
pub type Symbol = (u64, u64, String);

/// Where the compiler inlined a function, from the DWARF of a debug file:
/// start, end and the name of the inlined function, as its symbol has it.
///
/// Under LTO a patched function can live only inside its callers, as
/// liblzma's `lzma_index_prealloc` inside `index_decode` on arm64, so the
/// row that shows the fix carries another name.
pub fn inlined_copies(path: &Path) -> Vec<Symbol> {
    use gimli::{AttributeValue, DebugInfoOffset, constants};
    use object::{Object, ObjectSection};
    use std::borrow::Cow;

    let data = std::fs::read(path).expect("the debug file is cached");
    let file = object::File::parse(&*data).expect("the debug file parses");
    let endian = if file.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    let sections = gimli::DwarfSections::load(|id| -> Result<Cow<'_, [u8]>, gimli::Error> {
        Ok(file
            .section_by_name(id.name())
            .and_then(|section| section.uncompressed_data().ok())
            .unwrap_or(Cow::Borrowed(&[])))
    })
    .expect("the DWARF sections load");
    let dwarf = sections.borrow(|section| gimli::EndianSlice::new(section, endian));

    // Each entry by its offset in `.debug_info`: its name, or the entry
    // it takes its name from.
    let reference = |unit: &gimli::Unit<_>, value| match value {
        AttributeValue::UnitRef(offset) => offset.to_debug_info_offset(&unit.header),
        AttributeValue::DebugInfoRef(offset) => Some(offset),
        _ => None,
    };
    let mut origins: BTreeMap<DebugInfoOffset, (Option<String>, Option<DebugInfoOffset>)> =
        BTreeMap::new();
    let mut copies: Vec<(u64, u64, DebugInfoOffset)> = Vec::new();
    let mut headers = dwarf.units();
    while let Ok(Some(header)) = headers.next() {
        let Ok(unit) = dwarf.unit(header) else { continue };
        let mut entries = unit.entries();
        while let Ok(Some(entry)) = entries.next_dfs() {
            let Some(offset) = entry.offset().to_debug_info_offset(&unit.header) else { continue };
            let name =
                [constants::DW_AT_linkage_name, constants::DW_AT_name].iter().find_map(|&at| {
                    let value = entry.attr_value(at)?;
                    let text = dwarf.attr_string(&unit, value).ok()?;
                    Some(text.to_string_lossy().into_owned())
                });
            let origin = [constants::DW_AT_abstract_origin, constants::DW_AT_specification]
                .iter()
                .find_map(|&at| reference(&unit, entry.attr_value(at)?));
            if name.is_some() || origin.is_some() {
                origins.insert(offset, (name, origin));
            }
            if entry.tag() == constants::DW_TAG_inlined_subroutine
                && let Some(origin) = origin
                && let Ok(mut ranges) = dwarf.die_ranges(&unit, entry)
            {
                while let Ok(Some(range)) = ranges.next() {
                    copies.push((range.begin, range.end, origin));
                }
            }
        }
    }

    let name_of = |mut offset: DebugInfoOffset| {
        // An inlined copy names its function through a chain of origins.
        for _ in 0..4 {
            match origins.get(&offset)? {
                (Some(name), _) => return Some(name.clone()),
                (None, Some(next)) => offset = *next,
                (None, None) => return None,
            }
        }
        None
    };
    copies
        .into_iter()
        .filter_map(|(start, end, origin)| Some((start & !1, end & !1, name_of(origin)?)))
        .collect()
}
