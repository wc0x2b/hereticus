//! Read the function ranges that DWARF call frame information lists.
//!
//! Code built with unwind tables, which is all C++ and all Rust and any C
//! built with `-funwind-tables`, holds `.eh_frame`: one FDE for each function,
//! with its start and its length. It survives stripping, because the unwinder
//! needs it at run time, and a raw image copies it with the code.
//!
//! It is the exact answer a scan otherwise guesses at. It matters most where
//! the guess is worst: a C++ landing pad follows the function's return and is
//! reached by no branch, only by the unwinder, so a scan cuts it off as a
//! function of its own. Measured on tinyxml2 for MIPS, three such pieces lost
//! the global pointer of their function, and their table offsets then read as
//! changed values.

use core::ops::Range;

use gimli::{BaseAddresses, CieOrFde, EhFrame, RunTimeEndian, UnwindSection};

/// The byte order of the words the tables hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    Little,
    Big,
}

impl From<ByteOrder> for RunTimeEndian {
    fn from(order: ByteOrder) -> Self {
        match order {
            ByteOrder::Little => Self::Little,
            ByteOrder::Big => Self::Big,
        }
    }
}

/// The function ranges the FDEs of an `.eh_frame` section list, sorted.
///
/// `data` is the section and `address` where it loads. An FDE that does not
/// parse, or that covers nothing, is left out rather than failing the rest.
///
/// See RESEARCH.md, A16.
pub fn function_ranges(data: &[u8], address: u64, order: ByteOrder) -> Vec<Range<u64>> {
    let section = EhFrame::new(data, RunTimeEndian::from(order));
    let bases = BaseAddresses::default().set_eh_frame(address);

    let mut ranges = Vec::new();
    let mut entries = section.entries(&bases);
    while let Ok(Some(entry)) = entries.next() {
        let CieOrFde::Fde(partial) = entry else { continue };
        let Ok(fde) =
            partial.parse(|section, bases, offset| section.cie_from_offset(bases, offset))
        else {
            continue;
        };
        if fde.len() > 0 {
            let start = fde.initial_address();
            ranges.push(start..start.saturating_add(fde.len()));
        }
    }
    ranges.sort_by_key(|range| range.start);
    ranges.dedup_by_key(|range| range.start);
    ranges
}

/// Find `.eh_frame` in a raw image, and read its function ranges.
///
/// Nothing says where the section is, but it opens with a CIE, which is easy
/// to recognize: a length, an id of zero, version 1 or 3, and an augmentation
/// string that starts with `z`. The section is taken where one parses to at
/// least [`FEWEST_FUNCTIONS`] functions, each inside the image, and the start
/// that parses to the most wins.
pub fn find_function_ranges(image: &[u8], base: u64, order: ByteOrder) -> Vec<Range<u64>> {
    /// The fewest functions a candidate must list to be taken for the
    /// section. A few words that happen to parse list one or two at most.
    const FEWEST_FUNCTIONS: usize = 8;

    let end = base + image.len() as u64;
    let word = |offset: usize| {
        let bytes: [u8; 4] = image.get(offset..offset + 4)?.try_into().ok()?;
        Some(match order {
            ByteOrder::Little => u32::from_le_bytes(bytes),
            ByteOrder::Big => u32::from_be_bytes(bytes),
        })
    };
    let opens_a_cie = |offset: usize| {
        let (Some(length), Some(id)) = (word(offset), word(offset + 4)) else { return false };
        let version = image.get(offset + 8).copied();
        let augmentation = image.get(offset + 9).copied();
        (8..0x1000).contains(&length)
            && id == 0
            && matches!(version, Some(1 | 3))
            && augmentation == Some(b'z')
    };

    let mut best: Vec<Range<u64>> = Vec::new();
    let mut offset = 0;
    while offset + 12 <= image.len() {
        if !opens_a_cie(offset) {
            offset += 4;
            continue;
        }
        let ranges: Vec<Range<u64>> =
            function_ranges(&image[offset..], base + offset as u64, order)
                .into_iter()
                .filter(|range| range.start >= base && range.end <= end)
                .collect();
        if ranges.len() >= FEWEST_FUNCTIONS && ranges.len() > best.len() {
            best = ranges;
        }
        offset += 4;
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A CIE with augmentation `zR`, pointers `pcrel | sdata4`, then one FDE
    /// for each of `functions`, as (start, length), little endian, as it
    /// would load at `address`.
    fn eh_frame(address: u64, functions: &[(u64, u32)]) -> Vec<u8> {
        let mut data = vec![
            0x10, 0, 0, 0, // length
            0, 0, 0, 0, // CIE id
            1, // version
            b'z', b'R', 0,    // augmentation
            4,    // code alignment
            0x7c, // data alignment, -4
            31,   // return address register
            1,    // augmentation data length
            0x1b, // FDE pointers: pcrel | sdata4
            0, 0, 0, // padding to the length
        ];
        for &(start, length) in functions {
            let at = data.len();
            let pc_begin = start.wrapping_sub(address + at as u64 + 8) as u32;
            data.extend_from_slice(&16_u32.to_le_bytes()); // length
            data.extend_from_slice(&((at + 4) as u32).to_le_bytes()); // back to the CIE
            data.extend_from_slice(&pc_begin.to_le_bytes());
            data.extend_from_slice(&length.to_le_bytes());
            data.extend_from_slice(&[0, 0, 0, 0]); // augmentation length and padding
        }
        data.extend_from_slice(&[0, 0, 0, 0]); // the terminator
        data
    }

    #[test]
    fn reads_the_range_of_each_function() {
        let data = eh_frame(0x1000, &[(0x2000, 0x40), (0x2040, 0x10)]);
        assert_eq!(
            function_ranges(&data, 0x1000, ByteOrder::Little),
            [0x2000..0x2040, 0x2040..0x2050]
        );
    }

    #[test]
    fn nothing_that_parses_lists_nothing() {
        assert!(function_ranges(&[0xff; 64], 0x1000, ByteOrder::Little).is_empty());
        assert!(function_ranges(&[], 0x1000, ByteOrder::Little).is_empty());
    }

    /// In a raw image the section is found by its CIE, among code and data.
    #[test]
    fn finds_the_section_in_an_image() {
        let functions: Vec<(u64, u32)> =
            (0..10).map(|index| (0x520 + index * 0x20, 0x20)).collect();
        let mut image = vec![0xe1_u8; 0x400];
        let table = eh_frame(0x800, &functions);
        image[0x300..0x300 + table.len()].copy_from_slice(&table);

        let found = find_function_ranges(&image, 0x500, ByteOrder::Little);
        assert_eq!(found.len(), 10);
        assert_eq!(found[0], 0x520..0x540);
    }

    /// Too few functions is no table: a few words can parse by chance.
    #[test]
    fn a_short_table_is_not_taken() {
        let mut image = vec![0xe1_u8; 0x400];
        let table = eh_frame(0x800, &[(0x600, 0x20)]);
        image[0x300..0x300 + table.len()].copy_from_slice(&table);
        assert!(find_function_ranges(&image, 0x500, ByteOrder::Little).is_empty());
    }
}
