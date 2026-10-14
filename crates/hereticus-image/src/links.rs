//! What the linker left in a binary: the texts, the slots of the global
//! offset table, and the stubs that jump through them.

use std::collections::{BTreeMap, BTreeSet};

use object::{Object, ObjectKind, ObjectSection, ObjectSegment, ObjectSymbol, SectionKind};

use crate::obj::stable_name;
use hereticus_arch::{Arch, InsnKind};
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
    /// The symbol a relocation at a call names, by the address of the call.
    sites: BTreeMap<u64, String>,
    /// Where each section of read-only data starts, whose first string
    /// follows whatever the section before it ends with.
    read_only_starts: BTreeSet<u64>,
}

impl Links {
    /// Links for a raw image: its bytes, and no names.
    pub fn of_raw_image(base: u64, data: &[u8]) -> Self {
        Self { memory: vec![(base, data.to_vec())], ..Self::default() }
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
        Self { memory, slots, stubs, sites: BTreeMap::new(), read_only_starts }
    }

    /// The symbol whose stub is at `address`: a Mach-O stub, or a PLT stub
    /// whose slot a relocation names.
    pub fn stub_callee(&self, arch: &dyn Arch, address: u64) -> Option<&str> {
        if let Some(name) = self.stubs.get(&address) {
            return Some(name);
        }
        let slot = arch.stub_slot(self.bytes_at(address)?, address)?;
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
        let slot = arch.stub_slot(&function.code, function.address)?;
        self.slots.get(&slot).map(|name| format!("{name}@plt"))
    }

    /// Links from loaded bytes and named slots, for a test to build.
    pub fn of_parts(memory: Vec<(u64, Vec<u8>)>, slots: BTreeMap<u64, String>) -> Self {
        Self {
            memory,
            slots,
            stubs: BTreeMap::new(),
            sites: BTreeMap::new(),
            read_only_starts: BTreeSet::new(),
        }
    }

    /// The loaded bytes, each section at its address, as [`Memory`] reads
    /// them.
    ///
    /// [`Memory`]: hereticus_arch::Memory
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

    /// The loaded bytes from `address` to the end of their section.
    pub fn bytes_at(&self, address: u64) -> Option<&[u8]> {
        self.memory.iter().find_map(|(start, data)| {
            let offset = usize::try_from(address.checked_sub(*start)?).ok()?;
            data.get(offset..).filter(|rest| !rest.is_empty())
        })
    }
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
    let mut names: BTreeMap<u64, Option<String>> = BTreeMap::new();
    for section in file.sections().filter(|section| section.kind() == object::SectionKind::Text) {
        for (offset, relocation) in section.relocations() {
            let object::RelocationTarget::Symbol(index) = relocation.target() else { continue };
            let Some(name) = file
                .symbol_by_index(index)
                .ok()
                .and_then(|symbol| symbol.name().ok().map(|name| stable_name(name).to_string()))
                .filter(|name| !name.is_empty())
            else {
                continue;
            };
            let site = section.address() + offset;
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

    use hereticus_arch::aarch64::Aarch64;

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
