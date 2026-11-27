//! Where a view places the sections of an unlinked object, as a linker
//! would, and what each relocation in its code points at there.
//!
//! An unlinked object, as a kernel module, holds zero where its code forms
//! the address of data: the relocation at the instruction names the symbol.
//! So `lui a0, %hi(text)` and `addiu a0, a0, %lo(text)` read as `a0 = 0`. Each
//! data section here gets an address of its own, and each undefined symbol
//! one in an area for them, so the address a relocation names reads as the
//! text or the symbol there. The matching reads none of this: the addresses
//! are made up, and change with each build.

use std::collections::BTreeMap;

use hereticus_arch::Arch;
use hereticus_arch::relocation::DataReference;
pub use hereticus_arch::relocation::{Part, Width};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolSection};

use crate::Links;
use crate::links::{ByteOrder, is_renamed_local};
use crate::obj::stable_name;

/// Where the first data section goes: above the code of any module, which
/// starts at zero. A word of a 32-bit pool must hold each placed address,
/// and the data and the undefined symbols after it stay within 32 bits for
/// any real module: for `amdgpu.ko`, they end at 0x760a_1ed4. A word that
/// cannot hold its address names nothing.
const PLACED_BASE: u64 = 0x7000_0000;

/// The byte that starts the level of a message of the Linux kernel.
const KERN_SOH: u8 = 0x01;

/// Whether `name` is a label the compiler or assembler makes, which names
/// nothing a reader knows: a constant, as `$LC7` and `.LC0`, which it
/// numbers anew in each build, or a mapping symbol of ARM, as `$d` and
/// `$x`, which marks where code or data starts.
fn is_compiler_label(name: &str) -> bool {
    let mapping = name.strip_prefix('$').is_some_and(|rest| {
        let kind = rest.split('.').next().unwrap_or(rest);
        matches!(kind, "a" | "d" | "t" | "x")
    });
    mapping || name.starts_with("$L") || name.starts_with(".L")
}

/// The room each undefined symbol takes, so an offset into it, as
/// `table + 0x44`, keeps its name.
const EXTERN_ROOM: u64 = 0x1_0000;

/// The sections of an unlinked object as a view places them, and what each
/// relocation in its code points at.
#[derive(Clone, Debug, Default)]
pub struct Unlinked {
    /// The data sections, each at the address it is placed at, to read the
    /// texts in them.
    data: Links,
    /// Each named symbol: its end and its name, by its start.
    symbols: BTreeMap<u64, (u64, String)>,
    /// Each placed data section: its end and its name, by its start.
    sections: BTreeMap<u64, (u64, String)>,
    /// What each relocation in code points at, by the address it writes.
    references: BTreeMap<u64, Reference>,
}

/// What a relocation in code points at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reference {
    /// The address it points at, as this places the sections.
    pub target: u64,
    /// What the instruction or word at the relocation holds of the address.
    pub part: Part,
}

impl Unlinked {
    /// The sections of `file`, an unlinked object whose code sections lie
    /// at the addresses `base_of` gives, as a view places them. `None` where
    /// no relocation in its code points at data.
    pub(crate) fn of(
        file: &object::File<'_>,
        arch: &dyn Arch,
        base_of: impl Fn(&object::Section<'_, '_>) -> Option<u64>,
    ) -> Option<Self> {
        let order = if file.is_little_endian() { ByteOrder::Little } else { ByteOrder::Big };
        let code = |section: &object::Section<'_, '_>| section.kind() == SectionKind::Text;
        // Each section that code can point at, at its address.
        let mut placed: BTreeMap<usize, u64> = BTreeMap::new();
        let mut data: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut read_only = Vec::new();
        let mut sections = BTreeMap::new();
        let mut next = PLACED_BASE;
        for section in file.sections() {
            if code(&section) {
                if let Some(base) = base_of(&section) {
                    placed.insert(section.index().0, base);
                }
                continue;
            }
            let loaded = matches!(
                section.kind(),
                SectionKind::Data
                    | SectionKind::ReadOnlyData
                    | SectionKind::ReadOnlyString
                    | SectionKind::ReadOnlyDataWithRel
                    | SectionKind::UninitializedData
            );
            if !loaded || section.size() == 0 {
                continue;
            }
            let start = next.next_multiple_of(section.align().max(16));
            next = start + section.size();
            placed.insert(section.index().0, start);
            if let Ok(name) = section.name() {
                sections.insert(start, (next, name.to_string()));
            }
            if matches!(section.kind(), SectionKind::ReadOnlyData | SectionKind::ReadOnlyString) {
                read_only.push(start);
            }
            if section.kind() != SectionKind::UninitializedData
                && let Ok(bytes) = section.data()
            {
                data.push((start, bytes.to_vec()));
            }
        }
        // Each undefined symbol, at an address of its own past the data.
        let mut externs: BTreeMap<String, u64> = BTreeMap::new();
        let mut symbols = BTreeMap::new();
        let mut extern_next = next.next_multiple_of(EXTERN_ROOM) + EXTERN_ROOM;
        for symbol in file.symbols() {
            let Ok(name) = symbol.name() else { continue };
            let name = stable_name(name).to_string();
            if name.is_empty() || is_renamed_local(&name) || is_compiler_label(&name) {
                continue;
            }
            match symbol.section() {
                SymbolSection::Undefined | SymbolSection::Common => {
                    externs.entry(name.clone()).or_insert_with(|| {
                        let start = extern_next;
                        extern_next += EXTERN_ROOM;
                        symbols.insert(start, (start + EXTERN_ROOM, name));
                        start
                    });
                }
                SymbolSection::Section(index) if symbol.kind() != object::SymbolKind::Section => {
                    let Some(&base) = placed.get(&index.0) else { continue };
                    let start = base + symbol.address();
                    symbols.insert(start, (start + symbol.size().max(1), name));
                }
                _ => {}
            }
        }
        let address_of = |index: object::SymbolIndex| -> Option<u64> {
            let symbol = file.symbol_by_index(index).ok()?;
            match symbol.section() {
                SymbolSection::Section(section) => Some(placed.get(&section.0)? + symbol.address()),
                SymbolSection::Undefined | SymbolSection::Common => {
                    externs.get(stable_name(symbol.name().ok()?)).copied()
                }
                SymbolSection::Absolute => Some(symbol.address()),
                _ => None,
            }
        };
        // Each relocation of code, by section and offset: two code sections
        // of an object can share an address, and such a site names nothing.
        let mut references: BTreeMap<u64, Option<Reference>> = BTreeMap::new();
        for section in file.sections().filter(|section| code(section)) {
            let Some(base) = base_of(&section) else { continue };
            let bytes = section.data().unwrap_or_default();
            let relocations: Vec<(u64, object::Relocation)> = section.relocations().collect();
            let word = |offset: u64| -> Option<u64> {
                let offset = usize::try_from(offset).ok()?;
                Some(order.read(bytes.get(offset..offset + 4)?))
            };
            for reference in arch.data_references(&relocations, &word) {
                let DataReference { offset, symbol, addend, part } = reference;
                let Some(symbol) = address_of(symbol) else { continue };
                let target = symbol.wrapping_add_signed(addend);
                if let Part::Word(width) = part
                    && !width.holds(target)
                {
                    continue;
                }
                let reference = Reference { target, part };
                references
                    .entry(base + offset)
                    .and_modify(|known| {
                        if *known != Some(reference) {
                            *known = None;
                        }
                    })
                    .or_insert(Some(reference));
            }
        }
        let references: BTreeMap<u64, Reference> = references
            .into_iter()
            .filter_map(|(site, reference)| Some((site, reference?)))
            .collect();
        if references.is_empty() {
            return None;
        }
        let data = Links::of_parts(data, BTreeMap::new()).with_read_only_starts(read_only);
        Some(Self { data, symbols, sections, references })
    }

    /// The first relocation of code within `start..end`, as a view looks
    /// one up for the instruction there, with its address.
    pub fn reference_in(&self, start: u64, end: u64) -> Option<(u64, Reference)> {
        self.references.range(start..end).next().map(|(&site, &reference)| (site, reference))
    }

    /// Each relocation whose word holds an address, as a literal pool
    /// word does, by its address: the address and the width of the word.
    pub fn words(&self) -> impl Iterator<Item = (u64, u64, Width)> + '_ {
        self.references.iter().filter_map(|(&site, reference)| match reference.part {
            Part::Word(width) => Some((site, reference.target, width)),
            _ => None,
        })
    }

    /// The text that holds `address`, in a placed section of read-only
    /// data, and how far into it the address is.
    ///
    /// A message of the Linux kernel starts with its level, as `\x014` for
    /// a warning, which no printable text holds: the text holds the level
    /// too.
    pub fn text_holding(&self, address: u64) -> Option<(String, u64)> {
        let sure = |address: u64| {
            self.data
                .text_holding(address)
                .filter(|(text, offset)| self.data.is_sure_text(address - offset, text))
        };
        if let Some((text, offset)) = sure(address) {
            return Some((text.to_string(), offset));
        }
        let level = self.data.bytes_at(address)?.get(..2)?;
        match level {
            [KERN_SOH, level] if level.is_ascii_alphanumeric() => {
                let text = self.data.printable_text(address + 2)?;
                Some((format!("{}{}{text}", char::from(KERN_SOH), char::from(*level)), 0))
            }
            _ => None,
        }
    }

    /// The symbol, or else the placed data section, that holds `address`,
    /// and how far into it the address is.
    pub fn name_holding(&self, address: u64) -> Option<(&str, u64)> {
        holding(&self.symbols, address).or_else(|| holding(&self.sections, address))
    }
}

/// The name in `names` that holds `address`, and how far into it the
/// address is.
fn holding(names: &BTreeMap<u64, (u64, String)>, address: u64) -> Option<(&str, u64)> {
    let (&start, (end, name)) = names.range(..=address).next_back()?;
    (address < *end).then(|| (name.as_str(), address - start))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The placed data of one section of read-only data at `PLACED_BASE`,
    /// with no relocations.
    fn placed(bytes: &[u8]) -> Unlinked {
        let data = Links::of_parts(vec![(PLACED_BASE, bytes.to_vec())], BTreeMap::new())
            .with_read_only_starts(vec![PLACED_BASE]);
        let symbols = BTreeMap::from([(PLACED_BASE + 0x40, (PLACED_BASE + 0x48, "seen".into()))]);
        let sections = BTreeMap::from([(PLACED_BASE, (PLACED_BASE + 0x100, ".rodata".into()))]);
        Unlinked { data, symbols, sections, references: BTreeMap::new() }
    }

    #[test]
    fn a_kernel_message_reads_as_a_text_with_its_level() {
        let unlinked = placed(b"\x013usage: ptm\0plain text\0");
        let (text, offset) = unlinked.text_holding(PLACED_BASE).expect("a message");
        assert_eq!((text.as_str(), offset), ("\u{1}3usage: ptm", 0));
        let (text, offset) = unlinked.text_holding(PLACED_BASE + 13).expect("a text");
        assert_eq!((text.as_str(), offset), ("plain text", 0));
    }

    #[test]
    fn an_address_reads_as_the_symbol_or_the_section_that_holds_it() {
        let unlinked = placed(&[0; 0x100]);
        assert_eq!(unlinked.name_holding(PLACED_BASE + 0x44), Some(("seen", 4)));
        assert_eq!(unlinked.name_holding(PLACED_BASE + 0x48), Some((".rodata", 0x48)));
        assert_eq!(unlinked.name_holding(PLACED_BASE + 0x100), None);
    }

    #[test]
    fn a_label_of_the_compiler_names_nothing() {
        for label in ["$LC7", ".LC0", ".L.str", "$d", "$x", "$a.1", "$t"] {
            assert!(is_compiler_label(label), "{label}");
        }
        for name in ["counter", "$data", "table", "_7"] {
            assert!(!is_compiler_label(name), "{name}");
        }
    }

    #[test]
    fn a_word_holds_an_address_only_where_it_fits() {
        assert!(Width::Four.holds(u64::from(u32::MAX)));
        assert!(!Width::Four.holds(u64::from(u32::MAX) + 1));
        assert!(Width::Eight.holds(u64::MAX));
        assert_eq!((Width::Four.bytes(), Width::Eight.bytes()), (4, 8));
    }

    /// The words of AArch64 code that relocations fill keep the width the
    /// relocation gives, and a word of 4 bytes that cannot hold its address
    /// names nothing.
    #[test]
    fn each_word_has_the_width_of_its_relocation() {
        use object::elf::{R_AARCH64_ABS32, R_AARCH64_ABS64};
        use object::write::{Object as Written, Relocation, StandardSection};
        let mut written = Written::new(
            object::BinaryFormat::Elf,
            object::Architecture::Aarch64,
            object::Endianness::Little,
        );
        let text = written.section_id(StandardSection::Text);
        written.append_section_data(text, &[0; 24], 8);
        let rodata = written.section_id(StandardSection::ReadOnlyData);
        written.append_section_data(rodata, &[0; 16], 8);
        let symbol = written.section_symbol(rodata);
        let beyond = i64::from(u32::MAX);
        for (offset, r_type, addend) in
            [(0, R_AARCH64_ABS32, 4), (8, R_AARCH64_ABS64, 8), (16, R_AARCH64_ABS32, beyond)]
        {
            let flags = object::RelocationFlags::Elf { r_type };
            let relocation = Relocation { offset, symbol, addend, flags };
            written.add_relocation(text, relocation).expect("the relocation adds");
        }
        let bytes = written.write().expect("the object writes");
        let file = object::File::parse(bytes.as_slice()).expect("parses");
        let arch = &hereticus_il::arch::aarch64::Aarch64;
        let unlinked = Unlinked::of(&file, arch, |section| Some(section.address())).expect("words");
        let words: Vec<(u64, u64, Width)> = unlinked.words().collect();
        assert_eq!(words, [(0, PLACED_BASE + 4, Width::Four), (8, PLACED_BASE + 8, Width::Eight)],);
    }
}
