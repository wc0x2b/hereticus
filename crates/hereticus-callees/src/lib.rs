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

use hereticus_arch::Arch;

use hereticus_recovery::arch::{CallTarget, decode_all};

use hereticus_il::arch::Insn;
use hereticus_image::Links;
use hereticus_memory::Function;

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
///
/// See RESEARCH.md, A11.
pub fn callees_in(
    arch: &dyn Arch,
    links: &Links,
    functions: &[Function],
    insns: &[Insn],
) -> Vec<Callee> {
    arch.call_targets(insns)
        .into_iter()
        .map(|(index, target)| match links.site_name(insns[index].address) {
            Some(name) => Callee::Named(name.to_string()),
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
            // A stub's slot holds the address of the PLT header until the
            // dynamic linker binds it, the same for every callee. So where
            // no relocation names the slot, as in a raw image, the stub
            // itself stands for its callee: each callee has one.
            match links.stub_callee(arch, address) {
                Some(name) => Callee::Named(name.to_string()),
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
    if let Some(name) = links.slot_name(slot) {
        return Callee::Named(name.to_string());
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use hereticus_il::arch::arm32::Arm32;

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
        let links = Links::of_parts(
            vec![(0x1dd60, stub), (0x3ea38, 0x20_u32.to_le_bytes().to_vec())],
            BTreeMap::from([(0x3ea34, "_ZN8tinyxml27StrPair5ResetEv".to_string())]),
        );
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
