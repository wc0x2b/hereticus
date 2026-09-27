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
//! * **A slot of the global offset table.** PIC code on MIPS loads the callee
//!   from the slot itself. The dynamic symbol table names the global slots in
//!   order, from `DT_MIPS_GOTSYM`, and a local slot holds the callee's address.
//! * **A relocation at the call.** An unlinked object holds no targets yet,
//!   only a relocation that names the callee.
//!
//! A raw image has no relocations, so only the first source and the address a
//! slot holds are left there.

use std::collections::BTreeMap;

use object::{
    Object, ObjectKind, ObjectSection, ObjectSymbol, ObjectSymbolTable, RelocationTarget,
};

use crate::arch::{Arch, CallTarget, Insn, decode_all};
use crate::obj::{Function, stable_name};

/// What the linker left that names the callees of a binary.
#[derive(Clone, Debug, Default)]
pub struct Links {
    /// The bytes the binary loads, by address, to read a stub or a slot.
    memory: Vec<(u64, Vec<u8>)>,
    /// The symbol each named slot of the global offset table holds.
    slots: BTreeMap<u64, String>,
    /// The symbol a relocation at a call names, by the address of the call.
    sites: BTreeMap<u64, String>,
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

        let memory = file
            .sections()
            .filter(|section| section.address() != 0)
            .filter_map(|section| Some((section.address(), section.data().ok()?.to_vec())))
            .filter(|(_, data)| !data.is_empty())
            .collect();

        let mut slots = jump_slot_names(file);
        slots.extend(mips_global_slot_names(file));
        Self { memory, slots, sites: BTreeMap::new() }
    }

    /// Links from loaded bytes and named slots, for a test to build.
    #[cfg(test)]
    pub(crate) fn of_parts(memory: Vec<(u64, Vec<u8>)>, slots: BTreeMap<u64, String>) -> Self {
        Self { memory, slots, sites: BTreeMap::new() }
    }

    /// The loaded bytes from `address` to the end of their section.
    fn bytes_at(&self, address: u64) -> Option<&[u8]> {
        self.memory.iter().find_map(|(start, data)| {
            let offset = usize::try_from(address.checked_sub(*start)?).ok()?;
            data.get(offset..).filter(|rest| !rest.is_empty())
        })
    }
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
    }
}

/// The callee a slot of the global offset table holds.
fn resolve_slot(arch: &dyn Arch, links: &Links, functions: &[Function], slot: u64) -> Callee {
    if let Some(name) = links.slots.get(&slot) {
        return Callee::Named(name.clone());
    }
    let width = arch.pointer_width();
    match links.bytes_at(slot).filter(|bytes| bytes.len() >= width) {
        Some(bytes) => function_at(functions, arch.read_pointer(bytes)),
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
            sites: BTreeMap::new(),
        };
        let functions = [function("", 0x20)];

        let via_stub = resolve(&Arm32, &links, &functions, CallTarget::Address(0x1dd60));
        assert_eq!(via_stub, Callee::Named("_ZN8tinyxml27StrPair5ResetEv".to_string()));
        let via_slot = resolve(&Arm32, &links, &functions, CallTarget::Slot(0x3ea38));
        assert_eq!(via_slot, Callee::Function(0));
        let nowhere = resolve(&Arm32, &links, &functions, CallTarget::Slot(0x9000));
        assert_eq!(nowhere, Callee::Unknown);
    }
}
