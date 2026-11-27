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

use object::elf::RelocationType;
use object::{
    Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget, SectionKind,
    SymbolSection,
};

use crate::Links;
use crate::links::{ByteOrder, is_renamed_local};
use crate::obj::stable_name;

/// Where the first data section goes: above the code of any module, which
/// starts at zero, and within 32 bits, so a word of a 32-bit pool holds it.
const PLACED_BASE: u64 = 0x7000_0000;

/// The byte that starts the level of a message of the Linux kernel.
const KERN_SOH: u8 = 0x01;

/// Whether `name` is a label the compiler makes for a constant, as `$LC7`
/// and `.LC0`: it numbers them anew in each build.
fn is_compiler_label(name: &str) -> bool {
    name.starts_with("$L") || name.starts_with(".L")
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

/// What an instruction or a word holds of the address its relocation names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    /// The word holds the address, as a word of a literal pool does.
    Word,
    /// The instruction forms the upper part of the address, as `adrp` and
    /// `addis` do, and another completes it.
    High,
    /// The instruction completes the address, or reads or writes the place
    /// there, as the `add` and `ldr` of AArch64 do after `adrp`.
    Low,
    /// The instruction forms the upper half of an address whose lower half
    /// another adds as its immediate, as a MIPS `lui` does: the relocations
    /// keep their addend in those immediates. So a view shows the whole
    /// address at the `lui`, and no immediate at the instruction that adds
    /// the lower half, with whatever the code adds between.
    UpperOfPair,
    /// The instruction adds the lower half of an [`Part::UpperOfPair`], as
    /// `addiu` and `lw` do.
    LowerOfPair,
    /// The instruction holds the distance to the address from its own end,
    /// as the x86-64 `lea rdi, [rip + x]` does. The target is the address
    /// less the distance from the relocation to the end of the instruction.
    FromEnd,
}

impl Unlinked {
    /// The sections of `file`, an unlinked object whose code sections lie
    /// at the addresses `base_of` gives, as a view places them. `None` where
    /// no relocation in its code points at data.
    pub(crate) fn of(
        file: &object::File<'_>,
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
            let pairs = match file.architecture() {
                object::Architecture::Mips => mips_pairs(&relocations, word),
                _ => BTreeMap::new(),
            };
            for (offset, relocation) in &relocations {
                let RelocationTarget::Symbol(index) = relocation.target() else { continue };
                let RelocationFlags::Elf { r_type } = relocation.flags() else { continue };
                let Some(kind) = kind_of(file.architecture(), r_type) else { continue };
                let Some(symbol) = address_of(index) else { continue };
                let (addend, part) = match (relocation.has_implicit_addend(), kind) {
                    (false, _) => (relocation.addend(), kind.part()),
                    (true, Kind::MipsHigh | Kind::MipsLow) => match pairs.get(offset) {
                        Some(pair) => (pair.addend, pair.part(kind)),
                        None => continue,
                    },
                    (true, _) => (i64::from(word(*offset).unwrap_or(0) as u32 as i32), kind.part()),
                };
                let reference = Reference { target: symbol.wrapping_add_signed(addend), part };
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
    /// word does, by its address.
    pub fn words(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.references
            .iter()
            .filter(|(_, reference)| reference.part == Part::Word)
            .map(|(&site, reference)| (site, reference.target))
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

/// What a relocation of code of the architecture `architecture` names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// A whole address in a word.
    Word,
    /// The upper half of an address, as `R_MIPS_HI16` gives it.
    MipsHigh,
    /// The lower half, as `R_MIPS_LO16` gives it.
    MipsLow,
    /// The upper part of an address, with the addend in the relocation.
    High,
    /// The lower part, or a whole address in an instruction.
    Low,
    /// A distance from the instruction, as `R_X86_64_PC32` gives it.
    FromEnd,
}

impl Kind {
    fn part(self) -> Part {
        match self {
            Self::Word => Part::Word,
            Self::High => Part::High,
            Self::Low => Part::Low,
            Self::MipsHigh => Part::UpperOfPair,
            Self::MipsLow => Part::LowerOfPair,
            Self::FromEnd => Part::FromEnd,
        }
    }
}

/// What the relocation of type `r_type` of `architecture` names, where it
/// names the address of data that code forms or reads.
fn kind_of(architecture: object::Architecture, r_type: RelocationType) -> Option<Kind> {
    use object::Architecture;
    use object::elf::*;
    Some(match architecture {
        Architecture::Mips => match r_type {
            R_MIPS_32 => Kind::Word,
            R_MIPS_HI16 => Kind::MipsHigh,
            R_MIPS_LO16 => Kind::MipsLow,
            _ => return None,
        },
        Architecture::Arm => match r_type {
            R_ARM_ABS32 => Kind::Word,
            _ => return None,
        },
        Architecture::Aarch64 => match r_type {
            R_AARCH64_ABS64 | R_AARCH64_ABS32 => Kind::Word,
            R_AARCH64_ADR_PREL_PG_HI21 | R_AARCH64_ADR_PREL_PG_HI21_NC => Kind::High,
            R_AARCH64_ADD_ABS_LO12_NC
            | R_AARCH64_LDST8_ABS_LO12_NC
            | R_AARCH64_LDST16_ABS_LO12_NC
            | R_AARCH64_LDST32_ABS_LO12_NC
            | R_AARCH64_LDST64_ABS_LO12_NC
            | R_AARCH64_LDST128_ABS_LO12_NC => Kind::Low,
            _ => return None,
        },
        Architecture::X86_64 => match r_type {
            R_X86_64_64 => Kind::Word,
            R_X86_64_32 | R_X86_64_32S => Kind::Low,
            R_X86_64_PC32 => Kind::FromEnd,
            _ => return None,
        },
        Architecture::I386 => match r_type {
            R_386_32 => Kind::Low,
            _ => return None,
        },
        Architecture::PowerPc => match r_type {
            R_PPC_ADDR32 => Kind::Word,
            R_PPC_ADDR16_HA | R_PPC_ADDR16_HI => Kind::High,
            R_PPC_ADDR16_LO => Kind::Low,
            _ => return None,
        },
        Architecture::PowerPc64 => match r_type {
            R_PPC64_ADDR64 => Kind::Word,
            R_PPC64_ADDR16_HA | R_PPC64_ADDR16_HI => Kind::High,
            R_PPC64_ADDR16_LO | R_PPC64_ADDR16_LO_DS => Kind::Low,
            _ => return None,
        },
        _ => return None,
    })
}

/// A pair of `R_MIPS_HI16` and `R_MIPS_LO16` relocations, as [`mips_pair`]
/// reads it.
struct MipsPair {
    /// The addend the pair holds in the immediates of its two instructions.
    addend: i64,
    /// Whether the instruction of the relocation adds the lower half, as
    /// `addiu` does, where a load or a store, as `lw`, reads or writes at
    /// the address. For a `lui`, whether each instruction that adds a lower
    /// half to it does.
    adds: bool,
}

impl MipsPair {
    /// What the instruction of `kind`, one of the pair, holds of the
    /// address. An `addiu` shows the whole address, as on any architecture,
    /// and the `lui` of only such adds a page. A load or a store, which can
    /// add an index between, shows no offset, and its `lui` the whole
    /// address.
    fn part(&self, kind: Kind) -> Part {
        match (kind, self.adds) {
            (Kind::MipsHigh, true) => Part::High,
            (Kind::MipsHigh, false) => Part::UpperOfPair,
            (_, true) => Part::Low,
            (_, false) => Part::LowerOfPair,
        }
    }
}

/// The pair of `R_MIPS_HI16` and `R_MIPS_LO16` relocations that each of
/// them in `relocations`, of one code section, is part of, by its offset.
/// `word` reads the instruction at an offset.
///
/// An `R_MIPS_LO16` pairs with the last `lui` before it, in the code, of
/// its symbol and into the register its instruction adds to or reads at.
/// The relocation table need not list them in pairs: in a module of
/// OpenWrt, a `lui` comes after the lower halves it pairs with.
fn mips_pairs(
    relocations: &[(u64, object::Relocation)],
    word: impl Fn(u64) -> Option<u64>,
) -> BTreeMap<u64, MipsPair> {
    /// The opcodes of `addiu` and `addi`, in the top six bits of a word.
    const ADDS: [u64; 2] = [0x09, 0x08];
    let of_type = |relocation: &object::Relocation, r_type: RelocationType| {
        relocation.flags() == RelocationFlags::Elf { r_type }
    };
    // Each half, in the order of the code: its offset, its symbol, the
    // register it writes or reads, and its word.
    let mut halves: Vec<(u64, RelocationTarget, u64, u64, bool)> = relocations
        .iter()
        .filter_map(|(offset, relocation)| {
            let high = of_type(relocation, object::elf::R_MIPS_HI16);
            if !high && !of_type(relocation, object::elf::R_MIPS_LO16) {
                return None;
            }
            let word = word(*offset)?;
            // A `lui` writes `rt`; an `addiu` and a load read `rs`.
            let register = if high { word >> 16 & 0x1f } else { word >> 21 & 0x1f };
            Some((*offset, relocation.target(), register, word, high))
        })
        .collect();
    halves.sort_by_key(|half| half.0);
    // The `lui` of each lower half.
    let mut high_of: BTreeMap<u64, u64> = BTreeMap::new();
    for (at, &(offset, target, register, _, high)) in halves.iter().enumerate() {
        if high {
            continue;
        }
        let lui = halves[..at].iter().rev().find(|&&(_, other, written, _, is_high)| {
            is_high && other == target && written == register
        });
        if let Some(&(lui, ..)) = lui {
            high_of.insert(offset, lui);
        }
    }
    let word_at: BTreeMap<u64, u64> = halves.iter().map(|half| (half.0, half.3)).collect();
    let adds = |offset: u64| word_at.get(&offset).is_some_and(|word| ADDS.contains(&(word >> 26)));
    // The halves add in 32 bits: `lui 0xffff` is the upper half of -0x10000.
    let addend = |high: Option<u64>, low: Option<u64>| {
        let upper = high
            .and_then(|high| word_at.get(&high))
            .map_or(0, |&word| (word as u32 & 0xffff) << 16);
        let lower = low
            .and_then(|low| word_at.get(&low))
            .map_or(0, |&word| word as u16 as i16 as i32 as u32);
        i64::from(upper.wrapping_add(lower) as i32)
    };
    let mut pairs = BTreeMap::new();
    for &(offset, _, _, _, high) in &halves {
        let pair = match high {
            true => {
                let lows: Vec<u64> = high_of
                    .iter()
                    .filter(|&(_, &lui)| lui == offset)
                    .map(|(&low, _)| low)
                    .collect();
                MipsPair {
                    addend: addend(Some(offset), lows.first().copied()),
                    adds: !lows.is_empty() && lows.iter().all(|&low| adds(low)),
                }
            }
            false => MipsPair {
                addend: addend(high_of.get(&offset).copied(), Some(offset)),
                adds: adds(offset),
            },
        };
        pairs.insert(offset, pair);
    }
    pairs
}
