//! What the linker left in a binary: the texts, the slots of the global
//! offset table, and the stubs that jump through them.

use std::collections::{BTreeMap, BTreeSet};

use object::{
    Object, ObjectKind, ObjectSection, ObjectSegment, ObjectSymbol, ObjectSymbolTable, SectionKind,
};

use crate::obj::stable_name;
use hereticus_arch::Arch;
use hereticus_il::arch::InsnKind;
use hereticus_recovery::dynamic::slot_names;

/// What the linker left that names the callees of a binary.
#[derive(Clone, Debug, Default)]
pub struct Links {
    /// The bytes the binary loads, by address, to read a stub or a slot.
    memory: Vec<(u64, Vec<u8>)>,
    /// The symbol each named slot of the global offset table holds.
    slots: BTreeMap<u64, String>,
    /// The symbol each Mach-O stub stands for, by the address of the stub.
    stubs: BTreeMap<u64, String>,
    /// The address of the global offset table, from which a stub of 32-bit
    /// x86 PIC finds its slot.
    table: Option<u64>,
    /// The symbol a relocation at a call names, by the address of the call.
    sites: BTreeMap<u64, String>,
    /// Where each section of read-only data starts, whose first string
    /// follows whatever the section before it ends with.
    read_only_starts: BTreeSet<u64>,
    /// The address each dynamic relocation stores, by the address of the
    /// word it writes. A shared library fills its vtables this way, so
    /// the file holds zero or an addend where the loader puts a function.
    relocated: BTreeMap<u64, u64>,
}

impl Links {
    /// Links for a raw image: its bytes, and the names of the slots the
    /// relocations of its dynamic segment write, where the image holds one,
    /// as an image of a whole shared library does. `pointer_width` and
    /// `order` are those of its words.
    pub fn of_raw_image(base: u64, data: &[u8], pointer_width: usize, order: ByteOrder) -> Self {
        let order = match order {
            ByteOrder::Little => object::Endianness::Little,
            ByteOrder::Big => object::Endianness::Big,
        };
        let dynamic =
            hereticus_recovery::dynamic::Dynamic::find_in_raw(base, data, pointer_width, order);
        let slots = dynamic.as_ref().map(|dynamic| dynamic.slot_names()).unwrap_or_default();
        let table = dynamic.and_then(|dynamic| dynamic.global_offset_table());
        Self { memory: vec![(base, data.to_vec())], slots, table, ..Self::default() }
    }

    /// Read what an object file says about its calls.
    pub fn of_object(file: &object::File<'_>) -> Self {
        if file.kind() == ObjectKind::Relocatable {
            return Self { sites: call_site_names(file), ..Self::default() };
        }

        // The segments, as the loader maps them, so that the bytes around a
        // section are there as in a raw image of the same file.
        let mut memory: Vec<(u64, Vec<u8>)> = file
            .segments()
            .filter_map(|segment| Some((segment.address(), segment.data().ok()?.to_vec())))
            .filter(|(_, data)| !data.is_empty())
            .collect();
        if memory.is_empty() {
            memory = file
                .sections()
                .filter(|section| section.address() != 0)
                .filter_map(|section| Some((section.address(), section.data().ok()?.to_vec())))
                .filter(|(_, data)| !data.is_empty())
                .collect();
        }

        let mut slots = slot_names(file);
        let mut stubs = BTreeMap::new();
        if let object::File::MachO64(macho) = file {
            crate::apply_chained_fixups(macho, &mut memory);
            let (macho_stubs, macho_slots) = crate::indirect_names(macho);
            stubs = macho_stubs;
            slots.extend(macho_slots);
        }
        let read_only_starts = file
            .sections()
            .filter(|section| {
                matches!(section.kind(), SectionKind::ReadOnlyData | SectionKind::ReadOnlyString)
            })
            .map(|section| section.address())
            .filter(|&address| address != 0)
            .collect();
        let relocated = relocated_addresses(file, &memory);
        let table = hereticus_recovery::dynamic::Dynamic::of(file)
            .and_then(|dynamic| dynamic.global_offset_table());
        Self { memory, slots, stubs, table, sites: BTreeMap::new(), read_only_starts, relocated }
    }

    /// Links for a kernel module, or another unlinked object, whose code
    /// sections lie at the addresses `bases` gives, by section index: the
    /// symbol each call relocation names, and the code as memory.
    pub fn of_module(file: &object::File<'_>, bases: &BTreeMap<usize, u64>) -> Self {
        let base_of = |section: &object::Section<'_, '_>| bases.get(&section.index().0).copied();
        let memory = file
            .sections()
            .filter_map(|section| Some((base_of(&section)?, section.data().ok()?.to_vec())))
            .collect();
        Self { memory, sites: call_site_names_at(file, base_of), ..Self::default() }
    }

    /// The symbol whose stub is at `address`: a Mach-O stub, or a PLT stub
    /// whose slot a relocation names.
    pub fn stub_callee(&self, arch: &dyn Arch, address: u64) -> Option<&str> {
        if let Some(name) = self.stubs.get(&address) {
            return Some(name);
        }
        let slot = self.stub_slot(arch, self.bytes_at(address)?, address)?;
        self.slot_name(slot)
    }

    /// The symbol a relocation at the call at `address` names.
    pub fn site_name(&self, address: u64) -> Option<&str> {
        self.sites.get(&address).map(String::as_str)
    }

    /// The symbol a relocation writes into the slot at `address`.
    pub fn slot_name(&self, address: u64) -> Option<&str> {
        self.slots.get(&address).map(String::as_str)
    }

    /// The name of the function whose PLT stub `function` is, as
    /// `getpwnam@plt`, where a relocation names the slot it jumps through.
    pub fn stub_name(
        &self,
        arch: &dyn Arch,
        function: &hereticus_memory::Function,
    ) -> Option<String> {
        let slot = self.stub_slot(arch, &function.code, function.address)?;
        self.slots.get(&slot).map(|name| format!("{name}@plt"))
    }

    /// The slot the PLT stub `code` at `address` jumps through: the one it
    /// names, or the one at its distance from the global offset table.
    fn stub_slot(&self, arch: &dyn Arch, code: &[u8], address: u64) -> Option<u64> {
        arch.stub_slot(code, address)
            .or_else(|| Some(self.table?.wrapping_add(arch.stub_table_offset(code)?)))
    }

    /// These links, with `sites` as the symbol each relocation at a call or
    /// at an address names, for a test to build.
    pub fn with_sites(self, sites: BTreeMap<u64, String>) -> Self {
        Self { sites, ..self }
    }

    /// Links from loaded bytes and named slots, for a test to build.
    pub fn of_parts(memory: Vec<(u64, Vec<u8>)>, slots: BTreeMap<u64, String>) -> Self {
        Self {
            memory,
            slots,
            stubs: BTreeMap::new(),
            table: None,
            sites: BTreeMap::new(),
            read_only_starts: BTreeSet::new(),
            relocated: BTreeMap::new(),
        }
    }

    /// The loaded bytes, each section at its address, as [`Memory`] reads
    /// them.
    ///
    /// [`Memory`]: hereticus_recovery::arch::Memory
    pub fn regions(&self) -> Vec<(u64, &[u8])> {
        self.memory.iter().map(|(start, data)| (*start, data.as_slice())).collect()
    }

    /// The text that starts at `address`: printable ASCII up to a NUL, just
    /// after the NUL of the text before it.
    ///
    /// Anything else is not text as far as this can tell, such as a table,
    /// a word of code, or a string too long to be a message or a format. A
    /// compiler packs C strings end to end, so a string starts after a NUL
    /// or zero fill. A table of pointers, where the pointer bytes can spell
    /// `"!e"` by chance, and Rust strings, which have no NUL, do not. Nor
    /// does the first byte of a section that can be written: tinyxml2 for
    /// MIPS points at the start of `.data.rel.ro`, a table. A section of
    /// read-only data can start with a string right after code, as GCC puts
    /// `.rodata` after `.text` in Lua for Thumb-2.
    pub fn text_at(&self, address: u64) -> Option<&str> {
        let after_a_nul = address
            .checked_sub(1)
            .and_then(|before| self.bytes_at(before))
            .is_some_and(|before| before[0] == 0);
        if !after_a_nul && !self.read_only_starts.contains(&address) {
            return None;
        }
        self.printable_at(address)
    }

    /// The text that holds `address`, and how far into it `address` is.
    ///
    /// A linker merges a text that ends another into it: GNU `ld` keeps one
    /// `"DEVPATH"` for `procd` of OpenWrt, and a pointer 3 into it for
    /// `"PATH"`. GCC also reaches a text from the address of another, as
    /// `"Unexpected character\n"` from 10 bytes on in `jsonfilter`, so a
    /// pointer into a text is no text of its own. Only the view asks for
    /// one, to show the text it is in.
    pub fn text_holding(&self, address: u64) -> Option<(&str, u64)> {
        if let Some(text) = self.text_at(address) {
            return Some((text, 0));
        }
        let is_text_at = |at: u64| self.bytes_at(at).is_some_and(|bytes| is_text_byte(bytes[0]));
        let start = (1..=LONGEST as u64)
            .map_while(|back| address.checked_sub(back))
            .take_while(|&at| is_text_at(at))
            .last()?;
        let whole = self.text_at(start)?;
        let offset = address - start;
        let inside = (offset as usize) < whole.len();
        (inside && self.is_sure_text(start, whole)).then_some((whole, offset))
    }

    /// [`Self::text_at`], or the text right after an instruction of `arch`
    /// that ends a function, a return or a jump, or after padding.
    ///
    /// That is where `.rodata` starts when a linker puts it right after
    /// `.text`, as GNU `ld` does, and a raw image has no section to say so.
    /// Measured on Lua built by GCC for AArch64 as a raw image, the first
    /// string of `.rodata` otherwise read as text in one release and not in
    /// the next, and `lua_replace` read as changed.
    pub fn text_after_code(&self, arch: &dyn Arch, address: u64) -> Option<&str> {
        self.text_at(address).or_else(|| {
            let width = arch.instruction_width();
            let start = address.checked_sub(width as u64)?;
            let word = self.bytes_at(start)?.get(..width)?;
            let before = arch.decode(word, 0, start).ok()?;
            let ends = matches!(before.kind, InsnKind::Return | InsnKind::Jump { .. })
                || arch.is_padding(&before);
            ends.then(|| self.printable_at(address)).flatten()
        })
    }

    /// Printable ASCII from `address` up to a NUL.
    fn printable_at(&self, address: u64) -> Option<&str> {
        let rest = self.bytes_at(address)?;
        let rest = &rest[..rest.len().min(LONGEST + 1)];
        let end = rest.iter().position(|&byte| byte == 0)?;
        let text = &rest[..end];
        let printable =
            text.iter().all(|&byte| byte.is_ascii_graphic() || b" \t\n\r".contains(&byte));
        if text.len() < SHORTEST || !printable {
            return None;
        }
        core::str::from_utf8(text).ok()
    }

    /// Report whether a change to `text`, read at `address`, is sure enough
    /// to report.
    ///
    /// A text shorter than `SURE_LENGTH` can be a word of data by chance:
    /// a panic location of Rust for ARM read as `"!\t"`, and a table of
    /// tinyxml2 for MIPS as `"!e"`, and both changed with the pointers they
    /// hold. Their section does not settle it, as both are read-only data.
    /// So a short text is sure only where another text follows it, as in
    /// the pool a compiler packs C strings into. A text that is not sure
    /// still tells twins apart.
    pub fn is_sure_text(&self, address: u64, text: &str) -> bool {
        text.len() >= SURE_LENGTH || self.text_follows(address + text.len() as u64 + 1)
    }

    /// Report whether a text of [`SHORTEST`] bytes or more starts at
    /// `address`, after zero fill a compiler aligns texts with.
    fn text_follows(&self, address: u64) -> bool {
        /// More fill than any alignment of a text needs.
        const MOST_FILL: usize = 7;
        let Some(rest) = self.bytes_at(address) else { return false };
        let fill = rest.iter().take(MOST_FILL + 1).take_while(|&&byte| byte == 0).count();
        let rest = &rest[fill.min(rest.len())..];
        let length = rest.iter().take_while(|&&byte| is_text_byte(byte)).count();
        length >= SHORTEST && rest.get(length) == Some(&0)
    }

    /// Each word of `width` bytes the loaded bytes hold, by its address,
    /// as the loader leaves it: the address a dynamic relocation stores
    /// where one writes the word, else the stored value.
    pub fn words(&self, width: Width, order: ByteOrder) -> impl Iterator<Item = (u64, u64)> + '_ {
        let size = width.bytes();
        self.memory.iter().flat_map(move |(start, data)| {
            // A word of a table is aligned to its width.
            let skip = (size - (*start % size as u64) as usize) % size;
            data.get(skip..).unwrap_or_default().chunks_exact(size).enumerate().map(
                move |(index, bytes)| {
                    let address = start + (skip + index * size) as u64;
                    let value =
                        self.relocated.get(&address).copied().unwrap_or_else(|| order.read(bytes));
                    (address, value)
                },
            )
        })
    }

    /// The loaded bytes from `address` to the end of their section.
    pub fn bytes_at(&self, address: u64) -> Option<&[u8]> {
        self.memory.iter().find_map(|(start, data)| {
            let offset = usize::try_from(address.checked_sub(*start)?).ok()?;
            data.get(offset..).filter(|rest| !rest.is_empty())
        })
    }
}

/// Report whether `name` is a local symbol that OpenWrt's
/// `strip-kmod.sh` renamed to a number, as `_7`, which names nothing from
/// one build to the next.
pub fn is_renamed_local(name: &str) -> bool {
    name.strip_prefix('_').is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

/// The width of an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    /// Four bytes, as on ARM32 and MIPS32.
    Bits32,
    /// Eight bytes, as on AArch64.
    Bits64,
}

impl Width {
    /// The number of bytes.
    pub fn bytes(self) -> usize {
        match self {
            Self::Bits32 => 4,
            Self::Bits64 => 8,
        }
    }
}

/// The order of the bytes of a word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    /// Least significant byte first.
    Little,
    /// Most significant byte first.
    Big,
}

impl ByteOrder {
    /// The value of `bytes`, four or eight of them.
    pub fn read(self, bytes: &[u8]) -> u64 {
        let fold = |value: u64, &byte: &u8| (value << 8) | u64::from(byte);
        match self {
            Self::Little => bytes.iter().rev().fold(0, fold),
            Self::Big => bytes.iter().fold(0, fold),
        }
    }
}

/// The address each dynamic relocation of `file` stores in a word, by the
/// address of the word: see [`Links::words`].
///
/// Only the relocations that store an address are read: an absolute one,
/// which adds the address of a symbol, and a relative one, which adds the
/// load address, zero as the file is linked.
fn relocated_addresses(file: &object::File<'_>, memory: &[(u64, Vec<u8>)]) -> BTreeMap<u64, u64> {
    use object::elf::{R_AARCH64_ABS64, R_AARCH64_RELATIVE, R_ARM_ABS32, R_ARM_RELATIVE};
    use object::elf::{R_MIPS_32, R_MIPS_REL32};
    let Some(relocations) = file.dynamic_relocations() else { return BTreeMap::new() };
    let symbols = file.dynamic_symbol_table();
    let order = if file.is_little_endian() { ByteOrder::Little } else { ByteOrder::Big };
    let width = if file.is_64() { Width::Bits64 } else { Width::Bits32 };
    let stored = |address: u64| -> Option<u64> {
        memory.iter().find_map(|(start, data)| {
            let offset = usize::try_from(address.checked_sub(*start)?).ok()?;
            Some(order.read(data.get(offset..offset + width.bytes())?))
        })
    };
    relocations
        .filter_map(|(address, relocation)| {
            let object::RelocationFlags::Elf { r_type } = relocation.flags() else { return None };
            if ![
                R_AARCH64_ABS64,
                R_AARCH64_RELATIVE,
                R_ARM_ABS32,
                R_ARM_RELATIVE,
                R_MIPS_32,
                R_MIPS_REL32,
            ]
            .contains(&r_type)
            {
                return None;
            }
            let base = match relocation.target() {
                object::RelocationTarget::Symbol(index) => {
                    symbols.as_ref()?.symbol_by_index(index).ok()?.address()
                }
                object::RelocationTarget::Absolute => 0,
                _ => return None,
            };
            let addend = if relocation.has_implicit_addend() {
                stored(address)?
            } else {
                relocation.addend() as u64
            };
            Some((address, base.wrapping_add(addend)))
        })
        .collect()
}

/// Fewer bytes than this are as likely a small number as text: the word
/// 0x41 reads `"A"` in little-endian order.
const SHORTEST: usize = 2;
/// Longer than any format or message, and it keeps a stray pointer into a
/// large table cheap.
const LONGEST: usize = 256;
/// Texts this long or longer are reported wherever they are; see
/// [`Links::is_sure_text`].
const SURE_LENGTH: usize = 4;

/// Report whether `byte` can be part of a text.
fn is_text_byte(byte: u8) -> bool {
    byte.is_ascii_graphic() || b" \t\n\r".contains(&byte)
}

/// The symbol a relocation at each call of an unlinked object names.
///
/// Every section of an unlinked object starts at zero, so two sections can
/// put a call at the same offset. Such an offset names no callee.
fn call_site_names(file: &object::File<'_>) -> BTreeMap<u64, String> {
    call_site_names_at(file, |section| Some(section.address()))
}

/// [`call_site_names`], with each code section at the address `base_of`
/// gives it, where it gives one.
fn call_site_names_at(
    file: &object::File<'_>,
    base_of: impl Fn(&object::Section<'_, '_>) -> Option<u64>,
) -> BTreeMap<u64, String> {
    let mut names: BTreeMap<u64, Option<String>> = BTreeMap::new();
    for section in file.sections().filter(|section| section.kind() == object::SectionKind::Text) {
        let Some(base) = base_of(&section) else { continue };
        for (offset, relocation) in section.relocations() {
            let object::RelocationTarget::Symbol(index) = relocation.target() else { continue };
            let Some(name) = file
                .symbol_by_index(index)
                .ok()
                .and_then(|symbol| symbol.name().ok().map(|name| stable_name(name).to_string()))
                .filter(|name| !name.is_empty() && !is_renamed_local(name))
            else {
                continue;
            };
            let site = base + offset;
            names
                .entry(site)
                .and_modify(|known| {
                    if known.as_deref() != Some(name.as_str()) {
                        *known = None;
                    }
                })
                .or_insert(Some(name));
        }
    }
    names.into_iter().filter_map(|(site, name)| Some((site, name?))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use hereticus_il::arch::aarch64::Aarch64;

    /// A word is read at its alignment, in its byte order, and where a
    /// relocation writes it, as the address the relocation stores.
    #[test]
    fn a_word_reads_as_the_loader_leaves_it() {
        // Two bytes before the first aligned word, and one after the last.
        let data = vec![0xaa, 0xbb, 1, 2, 3, 4, 0, 0, 0, 0, 5];
        let links = Links {
            relocated: BTreeMap::from([(0x108, 0x4000)]),
            ..Links::of_parts(vec![(0x102, data)], BTreeMap::new())
        };
        let words = |order| links.words(Width::Bits32, order).collect::<Vec<_>>();
        assert_eq!(words(ByteOrder::Little), [(0x104, 0x0403_0201), (0x108, 0x4000)]);
        assert_eq!(words(ByteOrder::Big), [(0x104, 0x0102_0304), (0x108, 0x4000)]);
        let wide = Links::of_parts(vec![(0x100, (1..=9).collect())], BTreeMap::new());
        let words: Vec<_> = wide.words(Width::Bits64, ByteOrder::Little).collect();
        assert_eq!(words, [(0x100, 0x0807_0605_0403_0201)]);
        assert_eq!(Links::default().words(Width::Bits64, ByteOrder::Big).count(), 0);
    }

    #[test]
    fn a_local_renamed_to_a_number_names_nothing() {
        assert!(is_renamed_local("_0"));
        assert!(is_renamed_local("_17"));
        assert!(!is_renamed_local("_"));
        assert!(!is_renamed_local("_init"));
        assert!(!is_renamed_local("ptm_ioctl"));
    }

    #[test]
    fn text_is_printable_up_to_a_nul() {
        // 0x100 "%d", 0x103 "x", 0x105 two unprintable bytes, 0x108 "no end",
        // each after a NUL.
        let data = b"\0%d\0x\0\x01\x02\0no end\0".to_vec();
        let links = Links::of_parts(
            vec![(0xff, data), (0x1000, vec![b'a'; 300]), (0x2000, b"at start\0".to_vec())],
            BTreeMap::new(),
        );
        assert_eq!(links.text_at(0x100), Some("%d"));
        assert_eq!(links.text_at(0x103), None, "one byte is no text");
        assert_eq!(links.text_at(0x105), None, "not printable");
        assert_eq!(links.text_at(0x108), Some("no end"));
        assert_eq!(links.text_at(0x109), None, "not after a NUL");
        assert_eq!(links.text_holding(0x109), Some(("no end", 1)), "inside a text");
        assert_eq!(links.text_holding(0x10d), Some(("no end", 5)), "its last byte");
        assert_eq!(links.text_holding(0x100), Some(("%d", 0)), "a whole text");
        assert_eq!(links.text_holding(0x10e), None, "the NUL that ends it");
        assert_eq!(links.text_holding(0x1010), None, "no NUL near enough");
        assert_eq!(links.text_at(0x2000), None, "nothing before it says it starts");
        let read_only = Links { read_only_starts: BTreeSet::from([0x2000]), ..links.clone() };
        assert_eq!(read_only.text_at(0x2000), Some("at start"), "read-only data starts there");
        assert_eq!(links.text_at(0x1000), None, "no NUL near enough");
        assert_eq!(links.text_at(0x50), None, "not loaded");
    }

    /// A short text is sure where another text follows it, after fill.
    #[test]
    fn a_short_text_is_sure_only_in_a_pool() {
        // 0x100 "%d" then "%u"; 0x103 "%u" then fill and "%ld"; 0x10e "!e"
        // then a word that is no text; 0x114 "%s" at the end.
        let data = b"\0%d\0%u\0\0\0\0%ld\0\0!e\0\x01\x02\0%s\0".to_vec();
        let links = Links::of_parts(vec![(0xff, data)], BTreeMap::new());
        let sure = |address: u64| {
            let text = links.text_at(address).expect("a text");
            links.is_sure_text(address, text)
        };
        assert!(sure(0x100), "another text follows");
        assert!(sure(0x103), "a text follows the fill");
        assert!(sure(0x109), "long enough");
        assert!(!sure(0x10e), "a word of data follows");
        assert!(!sure(0x114), "nothing follows");
    }

    /// A raw image has no section to say where `.rodata` starts, so a text
    /// right after the last instruction of a function reads as a text.
    #[test]
    fn text_after_code_follows_an_end_of_function() {
        let after = |word: u32| {
            let mut data = word.to_le_bytes().to_vec();
            data.extend_from_slice(b"text\0");
            Links::of_parts(vec![(0x1000, data)], BTreeMap::new())
        };
        let (ret, nop, add) = (0xd65f_03c0, 0xd503_201f, 0x9100_0400);
        assert_eq!(after(ret).text_after_code(&Aarch64, 0x1004), Some("text"), "after a return");
        assert_eq!(after(nop).text_after_code(&Aarch64, 0x1004), Some("text"), "after padding");
        assert_eq!(after(add).text_after_code(&Aarch64, 0x1004), None, "inside a function");
        assert_eq!(after(ret).text_after_code(&Aarch64, 0x1005), None, "not after a NUL");
        assert_eq!(after(ret).text_after_code(&Aarch64, 0x1002), None, "no whole word before");
    }
}
