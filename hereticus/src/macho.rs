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

/// The functions of a fileset, as the kernelcache of iOS 15 and later is,
/// or `None` where `file` is no fileset.
///
/// A fileset holds each kext as a Mach-O of its own, which an
/// `LC_FILESET_ENTRY` names, and each records its own function starts and
/// symbols. Read whole, the file gives only the starts the fileset records
/// for itself: 648 functions of an iOS 27 kernelcache. The code of every
/// entry lies in the executable segments of the fileset, which carry no
/// sections, so the functions are cut from those.
pub(crate) fn fileset_functions(file: &MachO<'_>) -> Option<(Vec<Function>, FoundBy)> {
    use object::read::macho::{MachHeader as _, Segment as _};

    let endian = file.endian();
    let data = file.data();
    if file.macho_header().filetype(endian) != macho::MH_FILESET {
        return None;
    }
    let mut starts = BTreeSet::new();
    let mut names: BTreeMap<u64, String> = BTreeMap::new();
    let mut commands = file.macho_load_commands().ok()?;
    while let Ok(Some(command)) = commands.next() {
        let Ok(LoadCommandVariant::FilesetEntry(entry)) = command.variant() else { continue };
        let Ok(offset) = usize::try_from(entry.fileoff.get(endian)) else { continue };
        let Ok(header) = macho::MachHeader64::<Endianness>::parse(data, offset as u64) else {
            continue;
        };
        entry_functions(header, endian, data, offset as u64, &mut starts, &mut names);
    }

    let code: Vec<(u64, &[u8])> = file
        .segments()
        .filter(|segment| {
            segment.macho_segment().initprot(endian).0 & macho::VM_PROT_EXECUTE.0 != 0
        })
        .filter_map(|segment| Some((segment.address(), segment.data().ok()?)))
        .collect();
    let ends = starts.iter().skip(1).map(Some).chain(core::iter::once(None));
    let functions: Vec<Function> = starts
        .iter()
        .zip(ends)
        .filter_map(|(&address, next)| {
            let code = code_at(&code, address, next.copied())?;
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

/// Add the function starts and the names of code of one fileset entry,
/// whose header is at `offset` of the fileset.
fn entry_functions(
    header: &macho::MachHeader64<Endianness>,
    endian: Endianness,
    data: &[u8],
    offset: u64,
    starts: &mut BTreeSet<u64>,
    names: &mut BTreeMap<u64, String>,
) {
    use object::read::macho::{MachHeader as _, Segment as _};

    let Ok(mut commands) = header.load_commands(endian, data, offset) else { return };
    let mut text = None;
    let mut function_starts = None;
    let mut symtab = None;
    while let Ok(Some(command)) = commands.next() {
        match command.variant() {
            Ok(LoadCommandVariant::Segment64(segment, _)) if segment.name() == b"__TEXT" => {
                text = Some(segment.vmaddr(endian));
            }
            Ok(LoadCommandVariant::LinkeditData(linkedit))
                if command.cmd() == macho::LC_FUNCTION_STARTS =>
            {
                function_starts = Some(linkedit);
            }
            Ok(LoadCommandVariant::Symtab(table)) => symtab = Some(table),
            _ => {}
        }
    }
    if let (Some(text), Some(linkedit)) = (text, function_starts)
        && let Ok(mut iter) = linkedit.function_starts(endian, data, text)
    {
        // A bad entry ends the list; the starts before it still hold.
        while let Ok(Some(start)) = iter.next() {
            starts.insert(start);
        }
    }
    let Some(symtab) = symtab else { return };
    let Ok(symbols) = symtab.symbols::<macho::MachHeader64<Endianness>, _>(endian, data) else {
        return;
    };
    for symbol in symbols.iter() {
        if !symbol.is_definition() {
            continue;
        }
        let Ok(name) = symbol.name(endian, symbols.strings()) else { continue };
        let Ok(name) = core::str::from_utf8(name) else { continue };
        let address = symbol.n_value(endian);
        if name.is_empty() || is_assembler_private(name) || !starts.contains(&address) {
            continue;
        }
        let name_of = names.entry(address).or_insert_with(|| name.to_string());
        if name < name_of.as_str() {
            *name_of = name.to_string();
        }
    }
}

/// Write the address each chained fixup of `file` rebases to over the
/// fixup, in `memory`, the segments as loaded.
///
/// An arm64e file, and a kernelcache, stores each pointer of its data as a
/// link of a chain: the target as an offset, the distance to the next link,
/// and the bits of pointer authentication. Read as it is stored, no such
/// pointer is an address, so a text that only a pointer reaches was not
/// found. A bind, to another image, is left as it is.
pub(crate) fn apply_chained_fixups(file: &MachO<'_>, memory: &mut [(u64, Vec<u8>)]) {
    use object::read::macho::{Fixup, Segment as _};

    let endian = file.endian();
    let data = file.data();
    let segments: Vec<(u64, &[u8])> = file
        .segments()
        .map(|segment| (segment.macho_segment().vmaddr(endian), segment.data().unwrap_or_default()))
        .collect();
    let Some(text) = file
        .segments()
        .find(|segment| segment.name().ok().flatten() == Some("__TEXT"))
        .map(|segment| segment.address())
    else {
        return;
    };
    let Ok(mut commands) = file.macho_load_commands() else { return };
    while let Ok(Some(command)) = commands.next() {
        let Ok(Some(linkedit)) = command.dyld_chained_fixups() else { continue };
        let Ok(fixups) = linkedit.chained_fixups(endian, data) else { continue };
        let Ok(mut chained) = fixups.segments(endian) else { continue };
        while let Ok(Some(segment)) = chained.next() {
            let Some(&(address, bytes)) = segments.get(segment.index() as usize) else { continue };
            let mut links = segment.fixups(endian, text, bytes);
            while let Ok(Some((offset, fixup))) = links.next() {
                let target = match fixup {
                    Fixup::Rebase(rebase) => text.wrapping_add(rebase.target_offset),
                    Fixup::KernelCacheRebase(rebase) => text.wrapping_add(rebase.target_offset),
                    Fixup::SegmentedRebase(rebase) => {
                        let Some(&(base, _)) =
                            segments.get(usize::from(rebase.target_segment_index))
                        else {
                            continue;
                        };
                        base.wrapping_add(rebase.target_segment_offset)
                    }
                    Fixup::Bind(_) => continue,
                };
                write_pointer(memory, address.wrapping_add(offset), target);
            }
        }
    }
}

/// Write `value` as a little-endian pointer at `address` of `memory`.
fn write_pointer(memory: &mut [(u64, Vec<u8>)], address: u64, value: u64) {
    for (start, bytes) in memory.iter_mut() {
        let Some(offset) =
            address.checked_sub(*start).and_then(|offset| usize::try_from(offset).ok())
        else {
            continue;
        };
        if let Some(slot) = bytes.get_mut(offset..offset.saturating_add(8)) {
            slot.copy_from_slice(&value.to_le_bytes());
            return;
        }
    }
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

    /// A fileset of one kext, as a kernelcache is built: the outer header
    /// maps the code in one executable segment with no sections, and the
    /// kext's own header records where its two functions start.
    fn fileset() -> Vec<u8> {
        let word = |data: &mut Vec<u8>, value: u32| data.extend(value.to_le_bytes());
        let quad = |data: &mut Vec<u8>, value: u64| data.extend(value.to_le_bytes());
        let name = |data: &mut Vec<u8>, name: &str| {
            let mut field = [0u8; 16];
            field[..name.len()].copy_from_slice(name.as_bytes());
            data.extend(field);
        };
        let segment = |data: &mut Vec<u8>, segname: &str, address: u64, offset: u64, size: u64| {
            word(data, macho::LC_SEGMENT_64.0);
            word(data, 72);
            name(data, segname);
            for value in [address, size, offset, size] {
                quad(data, value);
            }
            for value in [5, 5, 0, 0] {
                word(data, value); // r-x, r-x, no section, no flag
            }
        };
        let header = |data: &mut Vec<u8>, filetype: u32, commands: u32, size: u32| {
            for value in
                [macho::MH_MAGIC_64, macho::CPU_TYPE_ARM64.0, 0, filetype, commands, size, 0, 0]
            {
                word(data, value);
            }
        };

        let id = b"com.example.kext\0\0\0\0\0\0\0";
        let mut data = Vec::new();
        header(&mut data, macho::MH_FILESET.0, 2, 72 + 32 + id.len() as u32);
        segment(&mut data, "__TEXT_EXEC", 0x1000, 0x400, 0x100);
        word(&mut data, macho::LC_FILESET_ENTRY.0);
        word(&mut data, 32 + id.len() as u32);
        quad(&mut data, 0x1000);
        quad(&mut data, 0x200);
        word(&mut data, 32);
        word(&mut data, 0);
        data.extend(id);
        data.resize(0x200, 0);

        header(&mut data, macho::MH_KEXT_BUNDLE.0, 2, 72 + 16);
        segment(&mut data, "__TEXT", 0xf00, 0, 0);
        word(&mut data, macho::LC_FUNCTION_STARTS.0);
        word(&mut data, 16);
        word(&mut data, 0x300);
        word(&mut data, 8);
        data.resize(0x300, 0);
        // From `__TEXT` at 0xf00: 0x100 to the first, 0x40 to the second.
        data.extend([0x80, 0x02, 0x40, 0x00]);
        data.resize(0x400, 0);
        for _ in 0..0x40 {
            word(&mut data, 0xd65f_03c0); // ret
        }
        data
    }

    /// Each kext of a fileset records its own function starts, which the
    /// fileset as a whole does not.
    #[test]
    fn a_fileset_reads_the_functions_of_each_entry() {
        let binary = crate::obj::Binary::parse(&fileset()).expect("the fileset parses");
        let spans: Vec<(u64, usize)> = binary
            .functions
            .iter()
            .map(|function| (function.address, function.code.len()))
            .collect();
        assert_eq!(spans, [(0x1000, 0x40), (0x1040, 0xc0)]);
    }

    #[test]
    fn a_file_that_is_no_fileset_reads_as_before() {
        let data = fileset();
        let mut plain = data.clone();
        plain[12..16].copy_from_slice(&macho::MH_EXECUTE.0.to_le_bytes());
        let object::File::MachO64(file) = object::File::parse(plain.as_slice()).expect("parses")
        else {
            panic!("a 64-bit Mach-O");
        };
        assert!(fileset_functions(&file).is_none());
    }

    #[test]
    fn a_pointer_is_written_where_its_region_holds_it() {
        let mut memory = vec![(0x1000, vec![0u8; 16]), (0x2000, vec![0u8; 4])];
        write_pointer(&mut memory, 0x1008, 0x1122_3344_5566_7788);
        assert_eq!(memory[0].1[8..], 0x1122_3344_5566_7788_u64.to_le_bytes());
        // A slot that no region holds whole is left alone.
        write_pointer(&mut memory, 0x2000, 1);
        write_pointer(&mut memory, 0x3000, 1);
        assert_eq!(memory[1].1, [0; 4]);
    }
}
