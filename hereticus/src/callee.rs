//! Name the function each call reaches.
//!
//! Normalizing replaces a call target with a placeholder, because a callee
//! moves whenever code before it grows, and a moved callee is no change. That
//! also hides a call to a *different* function, which is the most common shape
//! a security fix takes: `strcpy` becomes `strlcpy`, or a node is freed by its
//! document rather than by itself. So each call is resolved to its callee
//! here, and the matcher compares callees once it knows which functions pair.
//!
//! # Where a callee is named
//!
//! * **A call that holds its target**, as `bl` and `jal` do. The target is the
//!   start of a function of the same binary.
//! * **A PLT stub.** PIC code on ARM calls another library, and any function
//!   its own library exports, through a stub that jumps through a slot of the
//!   global offset table. A `R_ARM_JUMP_SLOT` relocation names that slot, and
//!   it survives stripping.
//! * **A Mach-O stub.** A call to another image reaches a stub in `__stubs`
//!   or `__auth_stubs`, and the indirect symbol table names the symbol of
//!   each stub and of each pointer slot. It survives stripping.
//! * **A slot of the global offset table.** PIC code on MIPS loads the callee
//!   from the slot itself. The dynamic symbol table names the global slots in
//!   order, from `DT_MIPS_GOTSYM`, and a local slot holds the callee's address.
//! * **A relocation at the call.** An unlinked object holds no targets yet,
//!   only a relocation that names the callee.
//!
//! A raw image has no relocations, so only the first source and the address a
//! slot holds are left there.

use std::collections::{BTreeMap, BTreeSet};

use object::{
    Object, ObjectKind, ObjectSection, ObjectSegment, ObjectSymbol, ObjectSymbolTable,
    RelocationTarget, SectionKind,
};

use crate::arch::{Arch, CallTarget, Insn, InsnKind, decode_all};
use crate::obj::{Function, stable_name};

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

/// The function a call reaches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Callee {
    /// A function of the same binary, by its index.
    Function(usize),
    /// A symbol, named by the linker or by the function's own symbol.
    Named(String),
    /// Nothing the code or the linker shows.
    Unknown,
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
            crate::macho::apply_chained_fixups(macho, &mut memory);
            let (macho_stubs, macho_slots) = crate::macho::indirect_names(macho);
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

    /// The name of the function whose PLT stub `function` is, as
    /// `getpwnam@plt`, where a relocation names the slot it jumps through.
    pub(crate) fn stub_name(&self, arch: &dyn Arch, function: &Function) -> Option<String> {
        let slot = arch.stub_slot(&function.code, function.address)?;
        self.slots.get(&slot).map(|name| format!("{name}@plt"))
    }

    /// Links from loaded bytes and named slots, for a test to build.
    #[cfg(test)]
    pub(crate) fn of_parts(memory: Vec<(u64, Vec<u8>)>, slots: BTreeMap<u64, String>) -> Self {
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
    /// [`Memory`]: crate::arch::Memory
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
    /// A text shorter than [`SURE_LENGTH`] can be a word of data by chance:
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
    fn bytes_at(&self, address: u64) -> Option<&[u8]> {
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

/// The callee of every call in `function`, in order, as `binary` names them.
///
/// `functions` are the functions of the binary, sorted by address.
pub fn callees(
    arch: &dyn Arch,
    links: &Links,
    functions: &[Function],
    function: &Function,
) -> Vec<Callee> {
    let (insns, _) = decode_all(arch, &function.code, function.address);
    callees_in(arch, links, functions, &insns)
}

/// [`callees`], for a function already decoded to `insns`.
pub fn callees_in(
    arch: &dyn Arch,
    links: &Links,
    functions: &[Function],
    insns: &[Insn],
) -> Vec<Callee> {
    arch.call_targets(insns)
        .into_iter()
        .map(|(index, target)| match links.sites.get(&insns[index].address) {
            Some(name) => Callee::Named(name.clone()),
            None => {
                target.map_or(Callee::Unknown, |target| resolve(arch, links, functions, target))
            }
        })
        .collect()
}

/// Resolve where a call goes to the function there.
fn resolve(arch: &dyn Arch, links: &Links, functions: &[Function], target: CallTarget) -> Callee {
    match target {
        CallTarget::Address(address) => {
            if let Some(name) = links.stubs.get(&address) {
                return Callee::Named(name.clone());
            }
            let stub = links.bytes_at(address).and_then(|code| arch.stub_slot(code, address));
            // A stub's slot holds the address of the PLT header until the
            // dynamic linker binds it, the same for every callee. So where
            // no relocation names the slot, as in a raw image, the stub
            // itself stands for its callee: each callee has one.
            match stub.and_then(|slot| links.slots.get(&slot)) {
                Some(name) => Callee::Named(name.clone()),
                None => function_at(functions, address),
            }
        }
        CallTarget::Slot(slot) => resolve_slot(arch, links, functions, slot),
        CallTarget::PageOffset { slot, offset } => match slot_value(arch, links, slot) {
            Some(page) => {
                let address = (page as u32).wrapping_add(offset as u32);
                function_at(functions, u64::from(address & !1))
            }
            None => Callee::Unknown,
        },
    }
}

/// The address a slot of the global offset table holds.
fn slot_value(arch: &dyn Arch, links: &Links, slot: u64) -> Option<u64> {
    let bytes = links.bytes_at(slot)?;
    (bytes.len() >= arch.pointer_width()).then(|| arch.read_pointer(bytes))
}

/// The callee a slot of the global offset table holds.
fn resolve_slot(arch: &dyn Arch, links: &Links, functions: &[Function], slot: u64) -> Callee {
    if let Some(name) = links.slots.get(&slot) {
        return Callee::Named(name.clone());
    }
    // A pointer to a Thumb-2 or MIPS16e function has bit 0 set. Code of
    // every set starts at an even address, so it can be cleared for all.
    match slot_value(arch, links, slot) {
        Some(address) => function_at(functions, address & !1),
        None => Callee::Unknown,
    }
}

/// The function that starts at `address`, by its name where it has one.
///
/// C++ gives one function several names, as a constructor's `C1` and `C2`,
/// so the first in sorted order stands for all, the same in both binaries.
fn function_at(functions: &[Function], address: u64) -> Callee {
    let index = functions.partition_point(|function| function.address < address);
    match functions.get(index) {
        Some(function) if function.address != address => Callee::Unknown,
        Some(function) if function.name.is_empty() => Callee::Function(index),
        Some(function) => Callee::Named(function.name.clone()),
        None => Callee::Unknown,
    }
}

/// The symbol each slot of the global offset table holds, where a
/// relocation or the order of the MIPS global slots names it.
pub(crate) fn slot_names(file: &object::File<'_>) -> BTreeMap<u64, String> {
    let mut slots = jump_slot_names(file);
    slots.extend(mips_global_slot_names(file));
    // A file with no section headers names its slots only through the
    // dynamic segment.
    if file.sections().next().is_none()
        && let Some(dynamic) = crate::dynamic::Dynamic::of(file)
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
            RelocationTarget::Symbol(index) => {
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
        data.chunks_exact(8)
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

/// The symbol a relocation at each call of an unlinked object names.
///
/// Every section of an unlinked object starts at zero, so two sections can
/// put a call at the same offset. Such an offset names no callee.
fn call_site_names(file: &object::File<'_>) -> BTreeMap<u64, String> {
    let mut names: BTreeMap<u64, Option<String>> = BTreeMap::new();
    for section in file.sections().filter(|section| section.kind() == object::SectionKind::Text) {
        for (offset, relocation) in section.relocations() {
            let RelocationTarget::Symbol(index) = relocation.target() else { continue };
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
        use crate::arch::aarch64::Aarch64;
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
    use crate::arch::arm32::Arm32;

    fn function(name: &str, address: u64) -> Function {
        Function { name: name.to_string(), address, code: vec![0; 4] }
    }

    /// A function with several names reads as the first, whichever the
    /// call reached it by.
    #[test]
    fn a_function_is_named_by_its_first_name() {
        let functions = [function("_ZC1", 0x10), function("_ZC2", 0x10), function("other", 0x20)];
        assert_eq!(function_at(&functions, 0x10), Callee::Named("_ZC1".to_string()));
        assert_eq!(function_at(&functions, 0x14), Callee::Unknown, "inside a function");
        assert_eq!(function_at(&functions, 0x40), Callee::Unknown, "past the last");
        assert_eq!(function_at(&[function("", 0x20)], 0x20), Callee::Function(0));
    }

    /// A call to a PLT stub reaches the symbol its slot is named for, and a
    /// slot with no name reaches the function whose address it holds.
    #[test]
    fn a_stub_and_a_slot_name_their_callee() {
        let stub: Vec<u8> = [0xe28f_c600_u32, 0xe28c_ca20, 0xe5bc_fccc]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let links = Links {
            memory: vec![(0x1dd60, stub), (0x3ea38, 0x20_u32.to_le_bytes().to_vec())],
            slots: BTreeMap::from([(0x3ea34, "_ZN8tinyxml27StrPair5ResetEv".to_string())]),
            stubs: BTreeMap::new(),
            sites: BTreeMap::new(),
            read_only_starts: BTreeSet::new(),
        };
        let functions = [function("", 0x20)];

        let via_stub = resolve(&Arm32, &links, &functions, CallTarget::Address(0x1dd60));
        assert_eq!(via_stub, Callee::Named("_ZN8tinyxml27StrPair5ResetEv".to_string()));
        let via_slot = resolve(&Arm32, &links, &functions, CallTarget::Slot(0x3ea38));
        assert_eq!(via_slot, Callee::Function(0));
        let nowhere = resolve(&Arm32, &links, &functions, CallTarget::Slot(0x9000));
        assert_eq!(nowhere, Callee::Unknown);

        let stub = Function {
            name: String::new(),
            address: 0x1dd60,
            code: links.bytes_at(0x1dd60).unwrap()[..12].to_vec(),
        };
        let stub_name = links.stub_name(&Arm32, &stub);
        assert_eq!(stub_name.as_deref(), Some("_ZN8tinyxml27StrPair5ResetEv@plt"));
        assert_eq!(links.stub_name(&Arm32, &function("", 0x20)), None, "no stub");

        let in_page = CallTarget::PageOffset { slot: 0x3ea38, offset: 0x11 };
        let functions = [function("", 0x20), function("", 0x30)];
        assert_eq!(resolve(&Arm32, &links, &functions, in_page), Callee::Function(1));
        let in_no_page = CallTarget::PageOffset { slot: 0x9000, offset: 0x11 };
        assert_eq!(resolve(&Arm32, &links, &functions, in_no_page), Callee::Unknown);
    }
}
