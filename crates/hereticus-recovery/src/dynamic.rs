//! Read the dynamic segment of an ELF file through its program headers.
//!
//! `sstrip`, which OpenWrt runs on every binary it ships, removes the section
//! headers. The loader does not need them: the dynamic segment gives the
//! dynamic symbol table, its strings and the relocations by address. So the
//! names a stripped file keeps, of what it exports and of the slots its
//! calls go through, are still there to read, though not through sections.

use std::collections::BTreeMap;

use object::read::elf::{Dyn, ElfFile, FileHeader, ProgramHeader};
use object::{Endianness, Object, ObjectSection, ObjectSegment, ObjectSymbol, ObjectSymbolTable};

/// The tags of the dynamic segment read here.
const DT_NULL: u64 = 0;
const DT_PLTRELSZ: u64 = 2;
const DT_PLTGOT: u64 = 3;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_STRSZ: u64 = 10;
const DT_REL: u64 = 17;
const DT_RELSZ: u64 = 18;
const DT_PLTREL: u64 = 20;
const DT_JMPREL: u64 = 23;
const DT_GNU_HASH: u64 = 0x6fff_fef5;
const DT_MIPS_LOCAL_GOTNO: u64 = 0x7000_000a;
const DT_MIPS_SYMTABNO: u64 = 0x7000_0011;
const DT_MIPS_GOTSYM: u64 = 0x7000_0013;

/// The type of a symbol that names a function.
const STT_FUNC: u8 = 2;

/// The dynamic segment of one ELF file, and the memory its addresses name.
pub struct Dynamic<'data> {
    entries: Vec<(u64, u64)>,
    /// Each loaded segment: its address and the bytes the file holds for it.
    loaded: Vec<(u64, &'data [u8])>,
    order: Endianness,
    width: Width,
}

/// The size of an address, and so of each field the tables hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Width {
    Bits32,
    Bits64,
}

/// A function the dynamic symbol table names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export<'data> {
    pub name: &'data str,
    pub address: u64,
    pub size: u64,
    /// The `st_other` field, where MIPS marks a MIPS16e function.
    pub other: u8,
}

impl<'data> Dynamic<'data> {
    /// The dynamic segment of `file`, or `None` where it has none.
    pub fn of(file: &object::File<'data>) -> Option<Self> {
        let entries = match file {
            object::File::Elf32(elf) => entries_of(elf)?,
            object::File::Elf64(elf) => entries_of(elf)?,
            _ => return None,
        };
        let loaded = file
            .segments()
            .filter_map(|segment| Some((segment.address(), segment.data().ok()?)))
            .collect();
        let order = if file.is_little_endian() { Endianness::Little } else { Endianness::Big };
        let width = if file.is_64() { Width::Bits64 } else { Width::Bits32 };
        Some(Self { entries, loaded, order, width })
    }

    /// The value of the first entry with `tag`.
    pub fn value(&self, tag: u64) -> Option<u64> {
        self.entries.iter().find_map(|&(entry_tag, value)| (entry_tag == tag).then_some(value))
    }

    /// The symbol each slot of the global offset table is written with: by a
    /// relocation that names a symbol, and on MIPS by the order of the
    /// global slots.
    pub fn slot_names(&self) -> BTreeMap<u64, String> {
        let mut names = self.relocated_slot_names();
        names.extend(self.mips_global_slot_names());
        names
    }

    /// The name of dynamic symbol number `index`.
    pub fn symbol_name(&self, index: u64) -> Option<&'data str> {
        let name = self.name(self.symbol(index)?.name)?;
        (!name.is_empty()).then_some(name)
    }

    /// The functions the dynamic symbol table names, as many as a hash
    /// table, or on MIPS `DT_MIPS_SYMTABNO`, says it holds.
    pub fn exports(&self) -> Vec<Export<'data>> {
        let count = self
            .value(DT_MIPS_SYMTABNO)
            .or_else(|| self.word(self.value(DT_HASH)? + 4, 4))
            .or_else(|| self.gnu_hash_symbol_count())
            .unwrap_or(0)
            .min(self.symbols_held());
        (1..count)
            .filter_map(|index| self.symbol(index))
            .filter(|symbol| symbol.kind == STT_FUNC && symbol.address != 0 && symbol.size != 0)
            .filter_map(|symbol| {
                let name = self.name(symbol.name)?;
                let (address, size, other) = (symbol.address, symbol.size, symbol.other);
                (!name.is_empty()).then_some(Export { name, address, size, other })
            })
            .collect()
    }

    /// The number of dynamic symbols, from the GNU hash table, which has no
    /// field for it.
    ///
    /// The table lists, for each bucket, its first symbol, and then a chain
    /// word for each symbol from `symoffset` on, with bit 0 set on the last
    /// of a bucket. So the symbols end where the chain of the bucket with
    /// the highest first symbol ends.
    fn gnu_hash_symbol_count(&self) -> Option<u64> {
        /// More symbols than any binary holds, which bounds a walk of a
        /// table that is not one.
        const MOST_SYMBOLS: u64 = 1 << 20;

        let table = self.value(DT_GNU_HASH)?;
        let buckets = self.word(table, 4)?;
        let first_hashed = self.word(table + 4, 4)?;
        let bloom_words = self.word(table + 8, 4)?;
        let bucket_start = table + 16 + bloom_words * self.field_width();
        let chain_start = bucket_start + buckets * 4;
        let highest =
            (0..buckets).filter_map(|bucket| self.word(bucket_start + bucket * 4, 4)).max()?;
        if highest < first_hashed {
            return Some(first_hashed);
        }
        (highest..MOST_SYMBOLS)
            .find(|&symbol| {
                self.word(chain_start + (symbol - first_hashed) * 4, 4)
                    .is_none_or(|chain| chain & 1 == 1)
            })
            .map(|last| last + 1)
    }

    /// The slots that a relocation with a symbol writes: `JUMP_SLOT` and
    /// `GLOB_DAT` ones, as the PLT and the GOT of ARM and AArch64 use.
    fn relocated_slot_names(&self) -> BTreeMap<u64, String> {
        let explicit = self.value(DT_PLTREL) == Some(DT_RELA);
        let tables = [
            (self.value(DT_JMPREL), self.value(DT_PLTRELSZ), explicit),
            (self.value(DT_REL), self.value(DT_RELSZ), false),
            (self.value(DT_RELA), self.value(DT_RELASZ), true),
        ];
        tables
            .into_iter()
            .filter_map(|(start, size, explicit)| Some((start?, size?, explicit)))
            .flat_map(|(start, size, explicit)| self.relocations(start, size, explicit))
            .filter(|&(_, symbol)| symbol != 0)
            .filter_map(|(slot, symbol)| {
                let name = self.name(self.symbol(symbol)?.name)?;
                (!name.is_empty()).then(|| (slot, name.to_string()))
            })
            .collect()
    }

    /// The slots after the first `DT_MIPS_LOCAL_GOTNO` hold the dynamic
    /// symbols from `DT_MIPS_GOTSYM` on, one each, in order.
    fn mips_global_slot_names(&self) -> BTreeMap<u64, String> {
        let (Some(got), Some(local), Some(first), Some(count)) = (
            self.value(DT_PLTGOT),
            self.value(DT_MIPS_LOCAL_GOTNO),
            self.value(DT_MIPS_GOTSYM),
            self.value(DT_MIPS_SYMTABNO),
        ) else {
            return BTreeMap::new();
        };
        let slot_width = self.field_width();
        (first..count.min(self.symbols_held()))
            .filter_map(|index| {
                let name = self.name(self.symbol(index)?.name)?;
                let slot = got + (local + index - first) * slot_width;
                (!name.is_empty()).then(|| (slot, name.to_string()))
            })
            .collect()
    }

    /// Each relocation of the table at `start`, of `size` bytes: the slot it
    /// writes, and the index of its symbol.
    fn relocations(&self, start: u64, size: u64, explicit: bool) -> Vec<(u64, u64)> {
        let field = self.field_width();
        let entry = if explicit { 3 * field } else { 2 * field };
        let symbol_shift = match self.width {
            Width::Bits32 => 8,
            Width::Bits64 => 32,
        };
        // A size past the end of the file is no table.
        let held = self.bytes_from(start).map_or(0, |bytes| bytes.len() as u64);
        let count = size.min(held) / entry;
        (0..count)
            .filter_map(|index| {
                let at = start + index * entry;
                let slot = self.word(at, field)?;
                let info = self.word(at + field, field)?;
                Some((slot, info >> symbol_shift))
            })
            .collect()
    }

    /// How many symbols the bytes from the start of the symbol table could
    /// hold, which bounds any count a damaged file gives.
    fn symbols_held(&self) -> u64 {
        let size = match self.width {
            Width::Bits32 => 16,
            Width::Bits64 => 24,
        };
        let held = self.value(DT_SYMTAB).and_then(|table| self.bytes_from(table));
        held.map_or(0, |bytes| bytes.len() as u64 / size)
    }

    /// The fields of symbol number `index` that are read here.
    fn symbol(&self, index: u64) -> Option<Symbol> {
        let table = self.value(DT_SYMTAB)?;
        match self.width {
            // st_name, st_value, st_size, st_info, st_other, st_shndx
            Width::Bits32 => {
                let at = table + index * 16;
                Some(Symbol {
                    name: self.word(at, 4)?,
                    address: self.word(at + 4, 4)?,
                    size: self.word(at + 8, 4)?,
                    kind: self.bytes(at + 12, 1)?[0] & 0xf,
                    other: self.bytes(at + 13, 1)?[0],
                })
            }
            // st_name, st_info, st_other, st_shndx, st_value, st_size
            Width::Bits64 => {
                let at = table + index * 24;
                Some(Symbol {
                    name: self.word(at, 4)?,
                    kind: self.bytes(at + 4, 1)?[0] & 0xf,
                    other: self.bytes(at + 5, 1)?[0],
                    address: self.word(at + 8, 8)?,
                    size: self.word(at + 16, 8)?,
                })
            }
        }
    }

    /// The string at `offset` into the string table.
    fn name(&self, offset: u64) -> Option<&'data str> {
        let table = self.value(DT_STRTAB)?;
        if offset >= self.value(DT_STRSZ)? {
            return None;
        }
        let bytes = self.bytes_from(table + offset)?;
        let end = bytes.iter().position(|&byte| byte == 0)?;
        core::str::from_utf8(&bytes[..end]).ok()
    }

    fn field_width(&self) -> u64 {
        match self.width {
            Width::Bits32 => 4,
            Width::Bits64 => 8,
        }
    }

    /// The unsigned number of `length` bytes at `address`.
    fn word(&self, address: u64, length: u64) -> Option<u64> {
        let bytes = self.bytes(address, length)?;
        let mut word = [0u8; 8];
        let length = bytes.len();
        Some(match self.order {
            Endianness::Little => {
                word[..length].copy_from_slice(bytes);
                u64::from_le_bytes(word)
            }
            Endianness::Big => {
                word[8 - length..].copy_from_slice(bytes);
                u64::from_be_bytes(word)
            }
        })
    }

    fn bytes(&self, address: u64, length: u64) -> Option<&'data [u8]> {
        self.bytes_from(address)?.get(..usize::try_from(length).ok()?)
    }

    /// The bytes the file holds from `address` to the end of its segment.
    fn bytes_from(&self, address: u64) -> Option<&'data [u8]> {
        self.loaded.iter().find_map(|&(start, data)| {
            let offset = usize::try_from(address.checked_sub(start)?).ok()?;
            data.get(offset..)
        })
    }
}

/// The fields of a symbol that are read here.
struct Symbol {
    name: u64,
    address: u64,
    size: u64,
    kind: u8,
    other: u8,
}

/// The entries of the dynamic segment, up to `DT_NULL`.
fn entries_of<'data, Elf>(elf: &ElfFile<'data, Elf>) -> Option<Vec<(u64, u64)>>
where
    Elf: FileHeader<Endian = Endianness>,
{
    let endian = elf.endian();
    let entries = elf
        .elf_program_headers()
        .iter()
        .find_map(|header| header.dynamic(endian, elf.data()).ok().flatten())?;
    Some(
        entries
            .iter()
            // A tag is signed; the ones read here are all positive.
            .map(|entry| (entry.d_tag(endian).0 as u64, entry.d_val(endian).into()))
            .take_while(|&(tag, _)| tag != DT_NULL)
            .collect(),
    )
}

/// The symbol each slot of the global offset table holds, where a
/// relocation or the order of the MIPS global slots names it.
pub fn slot_names(file: &object::File<'_>) -> BTreeMap<u64, String> {
    let mut slots = jump_slot_names(file);
    slots.extend(mips_global_slot_names(file));
    // A file with no section headers names its slots only through the
    // dynamic segment.
    if file.sections().next().is_none()
        && let Some(dynamic) = Dynamic::of(file)
    {
        slots.extend(dynamic.slot_names());
    }
    slots
}

/// The symbol that each `JUMP_SLOT` or `GLOB_DAT` relocation writes into a
/// slot of the global offset table.
fn jump_slot_names(file: &object::File<'_>) -> BTreeMap<u64, String> {
    let Some(symbols) = file.dynamic_symbol_table() else { return BTreeMap::new() };
    let Some(relocations) = file.dynamic_relocations() else { return BTreeMap::new() };
    relocations
        .filter_map(|(slot, relocation)| match relocation.target() {
            object::RelocationTarget::Symbol(index) => {
                let name = symbols.symbol_by_index(index).ok()?.name().ok()?;
                (!name.is_empty()).then(|| (slot, name.to_string()))
            }
            _ => None,
        })
        .collect()
}

/// The symbol each global slot of a MIPS global offset table holds.
///
/// The slots after the first `DT_MIPS_LOCAL_GOTNO` hold the dynamic symbols
/// from `DT_MIPS_GOTSYM` on, one each, in order.
fn mips_global_slot_names(file: &object::File<'_>) -> BTreeMap<u64, String> {
    const DT_PLTGOT: u32 = 3;
    const DT_MIPS_LOCAL_GOTNO: u32 = 0x7000_000a;
    const DT_MIPS_GOTSYM: u32 = 0x7000_0013;
    /// A MIPS32 slot holds one 32-bit address.
    const SLOT_WIDTH: u64 = 4;

    if file.architecture() != object::Architecture::Mips {
        return BTreeMap::new();
    }
    let (Some(dynamic), Some(symbols)) =
        (file.section_by_name(".dynamic"), file.dynamic_symbol_table())
    else {
        return BTreeMap::new();
    };
    let Ok(data) = dynamic.data() else { return BTreeMap::new() };

    let word = |bytes: &[u8]| {
        let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if file.is_little_endian() { u32::from_le_bytes(bytes) } else { u32::from_be_bytes(bytes) }
    };
    let tag = |wanted: u32| {
        data.as_chunks::<8>()
            .0
            .iter()
            .map(|entry| (word(&entry[..4]), word(&entry[4..])))
            .find(|&(tag, _)| tag == wanted)
            .map(|(_, value)| u64::from(value))
    };
    let (Some(got), Some(local), Some(first_symbol)) =
        (tag(DT_PLTGOT), tag(DT_MIPS_LOCAL_GOTNO), tag(DT_MIPS_GOTSYM))
    else {
        return BTreeMap::new();
    };

    symbols
        .symbols()
        .filter(|symbol| symbol.index().0 as u64 >= first_symbol)
        .filter_map(|symbol| {
            let name = symbol.name().ok().filter(|name| !name.is_empty())?;
            let slot = got + (local + symbol.index().0 as u64 - first_symbol) * SLOT_WIDTH;
            Some((slot, name.to_string()))
        })
        .collect()
}
