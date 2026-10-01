//! Read what a Mach-O file says about its functions and its calls.
//!
//! A Mach-O symbol has an address but no size, so the symbol table alone
//! cannot bound a function. The linker records every function start in
//! `LC_FUNCTION_STARTS`, and stripping keeps it, so each function here ends
//! where the next one starts, or where its section ends.
//!
//! A call to another image goes through a stub in `__stubs`, or in
//! `__auth_stubs` on arm64e, and the stub jumps through a pointer slot. The
//! indirect symbol table names the symbol of each stub and each slot, and
//! stripping keeps that table too.

use std::collections::{BTreeMap, BTreeSet};

use object::macho;
use object::read::macho::{
    FatArch, LoadCommandVariant, MachOFatFile32, MachOFatFile64, MachOFile64, Nlist, Section,
};
use object::{Endianness, Object, ObjectSection, ObjectSegment, ObjectSymbol, SymbolKind};

use crate::obj::{FoundBy, Function, stable_name};

/// A 64-bit Mach-O file, read from a slice.
pub(crate) type MachO<'data> = MachOFile64<'data, Endianness, &'data [u8]>;

/// The AArch64 slice of a universal ("fat") binary, or `data` itself where it
/// is no fat binary.
///
/// macOS ships most of its binaries with an x86-64 slice and an arm64e
/// slice in one file. Only AArch64 is decoded, so that slice is the one read.
/// A fat binary with no AArch64 slice is returned whole, so the parse that
/// follows reports why it cannot read it.
pub(crate) fn aarch64_slice(data: &[u8]) -> &[u8] {
    fn find<'data, Fat: FatArch>(data: &'data [u8], arches: &[Fat]) -> Option<&'data [u8]> {
        arches
            .iter()
            .find(|arch| arch.cputype() == macho::CPU_TYPE_ARM64)
            .and_then(|arch| arch.data(data).ok())
    }

    let slice = match object::FileKind::parse(data) {
        Ok(object::FileKind::MachOFat32) => {
            MachOFatFile32::parse(data).ok().and_then(|fat| find(data, fat.arches()))
        }
        Ok(object::FileKind::MachOFat64) => {
            MachOFatFile64::parse(data).ok().and_then(|fat| find(data, fat.arches()))
        }
        _ => None,
    };
    slice.unwrap_or(data)
}

/// The functions of a Mach-O file, and where their names came from, or
/// `None` where the file records no function start and no symbol names one.
///
/// A start comes from `LC_FUNCTION_STARTS` or from a symbol, since an
/// unlinked object has no such command. Where several symbols name one
/// start, the first in sorted order names it, the same in both binaries.
///
/// Where a symbol names every start, the result reads as [`FoundBy::Symbols`].
/// A stripped file keeps only the symbols it exports, so some starts have no
/// name, and the result reads as [`FoundBy::Scanning`], as the exported names
/// of a stripped ELF file do.
pub(crate) fn functions(file: &MachO<'_>) -> Option<(Vec<Function>, FoundBy)> {
    let mut names: BTreeMap<u64, &str> = BTreeMap::new();
    for symbol in file.symbols().filter(|symbol| symbol.kind() == SymbolKind::Text) {
        let Ok(name) = symbol.name() else { continue };
        if name.is_empty() || is_assembler_private(name) {
            continue;
        }
        let name_of = names.entry(symbol.address()).or_insert(name);
        *name_of = (*name_of).min(name);
    }

    let starts: BTreeSet<u64> =
        function_starts(file).into_iter().chain(names.keys().copied()).collect();
    let sections: Vec<(u64, &[u8])> = file
        .sections()
        .filter(|section| section.kind() == object::SectionKind::Text)
        .filter_map(|section| Some((section.address(), section.data().ok()?)))
        .collect();

    let ends = starts.iter().skip(1).map(Some).chain(core::iter::once(None));
    let functions: Vec<Function> = starts
        .iter()
        .zip(ends)
        .filter_map(|(&address, next)| {
            let code = code_at(&sections, address, next.copied())?;
            let name = names.get(&address).map(|name| stable_name(name).to_string());
            Some(Function { name: name.unwrap_or_default(), address, code })
        })
        .collect();

    let found_by = if functions.iter().all(|function| !function.name.is_empty()) {
        FoundBy::Symbols
    } else {
        FoundBy::Scanning
    };
    (!functions.is_empty()).then_some((functions, found_by))
}

/// The bytes from `address` up to `next`, or to the end of the section of
/// code that holds `address`.
fn code_at(sections: &[(u64, &[u8])], address: u64, next: Option<u64>) -> Option<Vec<u8>> {
    sections.iter().find_map(|&(start, data)| {
        let offset = usize::try_from(address.checked_sub(start)?).ok()?;
        let rest = data.get(offset..).filter(|rest| !rest.is_empty())?;
        let length = next
            .and_then(|next| usize::try_from(next - address).ok())
            .map_or(rest.len(), |length| length.min(rest.len()));
        Some(rest[..length].to_vec())
    })
}

/// Report whether `name` is a label the assembler keeps to itself, as the
/// `ltmp0` that clang puts at the start of each section of an object. Such a
/// label names no function.
fn is_assembler_private(name: &str) -> bool {
    name.starts_with('l') || name.starts_with('L')
}

/// The addresses `LC_FUNCTION_STARTS` records, which are offsets from the
/// start of the `__TEXT` segment.
fn function_starts(file: &MachO<'_>) -> Vec<u64> {
    let endian = file.endian();
    let Some(text) = file
        .segments()
        .find(|segment| segment.name().ok().flatten() == Some("__TEXT"))
        .map(|segment| segment.address())
    else {
        return Vec::new();
    };
    let Ok(mut commands) = file.macho_load_commands() else { return Vec::new() };

    let mut starts = Vec::new();
    while let Ok(Some(command)) = commands.next() {
        if command.cmd() != macho::LC_FUNCTION_STARTS {
            continue;
        }
        let Ok(LoadCommandVariant::LinkeditData(data)) = command.variant() else { continue };
        let Ok(mut iter) = data.function_starts(endian, file.data(), text) else { continue };
        // A bad entry ends the list; the starts before it still hold.
        while let Ok(Some(start)) = iter.next() {
            starts.push(start);
        }
    }
    starts
}

/// The symbol that each stub and each pointer slot stands for, by address,
/// as the indirect symbol table names them: `(stubs, slots)`.
pub(crate) fn indirect_names(file: &MachO<'_>) -> (BTreeMap<u64, String>, BTreeMap<u64, String>) {
    let endian = file.endian();
    let mut stubs = BTreeMap::new();
    let mut slots = BTreeMap::new();
    let Some(indirect) = indirect_symbol_table(file) else { return (stubs, slots) };
    let symbols = file.macho_symbol_table();

    for section in file.sections() {
        let header = section.macho_section();
        let Ok(entries) = header.indirect_symbols(endian, indirect) else { continue };
        let (width, names) = match header.symbol_stub_size(endian) {
            0 => (size_of::<u64>() as u64, &mut slots),
            stub => (u64::from(stub), &mut stubs),
        };
        for (address, entry) in (section.address()..).step_by(width as usize).zip(entries) {
            // An entry the linker bound to a local or an absolute address
            // has no index, and names nothing.
            let Some(index) = entry.get(endian).index() else { continue };
            let name = symbols
                .symbol(object::SymbolIndex(index as usize))
                .ok()
                .and_then(|nlist| nlist.name(endian, symbols.strings()).ok())
                .and_then(|name| core::str::from_utf8(name).ok())
                .filter(|name| !name.is_empty());
            if let Some(name) = name {
                names.insert(address, stable_name(name).to_string());
            }
        }
    }
    (stubs, slots)
}

/// The indirect symbol table of `LC_DYSYMTAB`.
fn indirect_symbol_table<'data>(
    file: &MachO<'data>,
) -> Option<&'data [object::U32<Endianness, macho::IndirectSymbol>]> {
    let endian = file.endian();
    let mut commands = file.macho_load_commands().ok()?;
    while let Ok(Some(command)) = commands.next() {
        if let Ok(LoadCommandVariant::Dysymtab(dysymtab)) = command.variant() {
            return dysymtab.indirect_symbols(endian, file.data()).ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A universal binary of 32-bit headers, with one four-byte slice per
    /// CPU type in `slices`, in order.
    fn universal(slices: &[(macho::CpuType, &[u8; 4])]) -> Vec<u8> {
        const HEADER: usize = 8;
        const ARCH: usize = 20;
        let mut data = macho::FAT_MAGIC.to_be_bytes().to_vec();
        data.extend((slices.len() as u32).to_be_bytes());
        let first = HEADER + ARCH * slices.len();
        for (index, (cputype, _)) in slices.iter().enumerate() {
            let offset = (first + 4 * index) as u32;
            for field in [cputype.0, 0, offset, 4, 0] {
                data.extend(field.to_be_bytes());
            }
        }
        for (_, bytes) in slices {
            data.extend(*bytes);
        }
        data
    }

    #[test]
    fn a_universal_binary_gives_its_aarch64_slice() {
        let data =
            universal(&[(macho::CPU_TYPE_X86_64, b"x86!"), (macho::CPU_TYPE_ARM64, b"arm!")]);
        assert_eq!(aarch64_slice(&data), b"arm!");
    }

    #[test]
    fn a_universal_binary_with_no_aarch64_slice_stays_whole() {
        let data = universal(&[(macho::CPU_TYPE_X86_64, b"x86!")]);
        assert_eq!(aarch64_slice(&data), data.as_slice());
    }

    #[test]
    fn a_slice_past_the_end_leaves_the_file_whole() {
        let mut data = universal(&[(macho::CPU_TYPE_ARM64, b"arm!")]);
        data.truncate(data.len() - 1);
        assert_eq!(aarch64_slice(&data), data.as_slice());
    }

    #[test]
    fn a_thin_file_stays_whole() {
        assert_eq!(aarch64_slice(b"not a universal binary"), b"not a universal binary");
        assert_eq!(aarch64_slice(&[]), &[] as &[u8]);
    }

    #[test]
    fn code_runs_to_the_next_start_or_the_section_end() {
        let sections: [(u64, &[u8]); 2] = [(0x100, &[1, 2, 3, 4, 5, 6, 7, 8]), (0x200, &[9; 4])];
        assert_eq!(code_at(&sections, 0x100, Some(0x104)), Some(vec![1, 2, 3, 4]));
        assert_eq!(code_at(&sections, 0x104, Some(0x200)), Some(vec![5, 6, 7, 8]));
        assert_eq!(code_at(&sections, 0x200, None), Some(vec![9; 4]));
    }

    #[test]
    fn a_start_outside_every_section_has_no_code() {
        let sections: [(u64, &[u8]); 1] = [(0x100, &[1, 2, 3, 4])];
        assert_eq!(code_at(&sections, 0xfc, Some(0x100)), None, "before the section");
        assert_eq!(code_at(&sections, 0x104, None), None, "at its end");
        assert_eq!(code_at(&[], 0x100, None), None, "no section at all");
    }

    #[test]
    fn code_never_passes_the_next_start_or_its_section() {
        bolero::check!().with_type::<(u8, u8, u8, u8)>().for_each(|&(size, start, gap, at)| {
            let data = vec![0; usize::from(size)];
            let sections = [(u64::from(start), data.as_slice())];
            let address = u64::from(at);
            let next = address + u64::from(gap) + 1;
            if let Some(code) = code_at(&sections, address, Some(next)) {
                assert!(!code.is_empty());
                assert!(address + code.len() as u64 <= next);
                assert!(address + code.len() as u64 <= u64::from(start) + u64::from(size));
            }
        });
    }

    #[test]
    fn assembler_labels_name_no_function() {
        assert!(is_assembler_private("ltmp0"));
        assert!(is_assembler_private("LBB0_1"));
        assert!(!is_assembler_private("_main"));
        assert!(!is_assembler_private("__ZN4core3fmt5write17h"));
    }
}
