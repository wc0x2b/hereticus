//! Read binaries and find the functions in them.

use std::collections::{BTreeMap, BTreeSet};

use object::{Object, ObjectKind, ObjectSection, ObjectSymbol, SymbolKind};

use crate::address::AddressSpace;
use crate::arch::Arch;
use crate::arch::aarch64::Aarch64;
use crate::arch::arm32::Arm32;
use crate::arch::mips::Mips32;
use crate::arch::thumb::Thumb2;
use crate::callee::Links;

/// Why a binary could not be read.
#[derive(Debug)]
pub enum ObjError {
    /// The bytes are not an object file this crate can read.
    Parse(object::Error),
    /// The file is a valid object, but not for an architecture `hereticus` knows.
    UnsupportedArch(object::Architecture),
    /// The file holds no executable code.
    NoCode,
    /// The file holds code, but no function could be found in it.
    ///
    /// Reported rather than returning nothing, because an empty result would
    /// read as "nothing changed" when the truth is "nothing was examined".
    NoFunctions,
}

impl core::fmt::Display for ObjError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parse(err) => write!(f, "cannot parse object: {err}"),
            Self::UnsupportedArch(arch) => write!(f, "unsupported architecture: {arch:?}"),
            Self::NoCode => write!(f, "object has no executable code"),
            Self::NoFunctions => {
                write!(f, "object has code, but no function could be found in it")
            }
        }
    }
}

impl core::error::Error for ObjError {}

impl From<object::Error> for ObjError {
    fn from(err: object::Error) -> Self {
        Self::Parse(err)
    }
}

/// The architectures `hereticus` can decode.
///
/// More variants arrive as more decoders do. Keeping this an enum rather than
/// a boxed trait object lets the matcher check that two binaries agree on
/// architecture before it compares them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Isa {
    Arm32,
    /// ARM32 in Thumb-2 mode, as most Cortex-M firmware and much ARM user
    /// space is built.
    Thumb2,
    /// ARMv8-A in AArch64 mode, 64-bit.
    Aarch64,
    /// MIPS32, little endian, as a desktop-built object usually is.
    Mips32,
    /// MIPS32, big endian, as most shipped firmware is.
    Mips32Be,
    /// MIPS16e, little endian, which much MIPS user space is built as.
    Mips16,
    /// MIPS16e, big endian.
    Mips16Be,
}

impl Isa {
    /// The decoder for this architecture.
    ///
    /// Returned behind the trait so that everything above [`crate::arch`]
    /// works on any architecture. Adding a variant here must not oblige a
    /// caller to change.
    pub fn arch(self) -> &'static dyn Arch {
        match self {
            Self::Arm32 => &Arm32,
            Self::Thumb2 => &Thumb2,
            Self::Aarch64 => &Aarch64,
            Self::Mips32 => &Mips32::LITTLE,
            Self::Mips32Be => &Mips32::BIG,
            Self::Mips16 => &crate::arch::mips16::Mips16::LITTLE,
            Self::Mips16Be => &crate::arch::mips16::Mips16::BIG,
        }
    }

    /// The other instruction set of a core that runs two, as ARM runs A32 and
    /// Thumb-2, or `None`.
    pub fn other_set(self) -> Option<Self> {
        match self {
            Self::Arm32 => Some(Self::Thumb2),
            Self::Thumb2 => Some(Self::Arm32),
            Self::Mips32 => Some(Self::Mips16),
            Self::Mips16 => Some(Self::Mips32),
            Self::Mips32Be => Some(Self::Mips16Be),
            Self::Mips16Be => Some(Self::Mips32Be),
            Self::Aarch64 => None,
        }
    }

    /// Choose a decoder for what an object file says it holds.
    ///
    /// `little_endian` decides nothing for ARM, which is only read in that
    /// order anyway, and decides which decoder for MIPS, which ships in both.
    fn from_object(arch: object::Architecture, little_endian: bool) -> Result<Self, ObjError> {
        match arch {
            object::Architecture::Arm => Ok(Self::Arm32),
            object::Architecture::Aarch64 => Ok(Self::Aarch64),
            object::Architecture::Mips if little_endian => Ok(Self::Mips32),
            object::Architecture::Mips => Ok(Self::Mips32Be),
            _ => Err(ObjError::UnsupportedArch(arch)),
        }
    }
}

/// One function found in a binary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    /// Symbol name. Empty when the binary is stripped.
    pub name: String,
    /// Virtual address of the first instruction.
    pub address: u64,
    /// Machine code, exactly the bytes of this function.
    pub code: Vec<u8>,
}

/// Where the functions of a binary came from.
///
/// A caller should treat a scanned binary more carefully than one read from a
/// symbol table: boundaries found by scanning can be wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoundBy {
    /// The symbol table named every function.
    Symbols,
    /// The binary is stripped, so the functions were recovered from the code,
    /// or from what the linker left, as the `LC_FUNCTION_STARTS` of Mach-O.
    /// Only the names of what the binary exports are left.
    Scanning,
}

/// A binary, with the functions found in it.
#[derive(Clone, Debug)]
pub struct Binary {
    pub isa: Isa,
    pub functions: Vec<Function>,
    /// How the functions were found.
    pub found_by: FoundBy,
    /// Where the binary sits in memory, which tells an address from a number.
    pub addresses: AddressSpace,
    /// What the linker left that names the callee of each call.
    pub links: Links,
    /// The addresses of the functions in [`Isa::other_set`] of `isa`.
    ///
    /// An ARM library can mix A32 and Thumb-2 functions, and bit 0 of each
    /// symbol says which a function is. `isa` is the set most of them are
    /// in. Empty where the binary holds one set, or where nothing says.
    pub other_set: BTreeSet<u64>,
}

impl Binary {
    /// The instruction set `function`, one of this binary's, is in.
    pub fn isa_of(&self, function: &Function) -> Isa {
        match self.isa.other_set() {
            Some(other) if self.other_set.contains(&function.address) => other,
            _ => self.isa,
        }
    }

    /// Read a binary and find the functions in it.
    ///
    /// The symbol table comes first, because a name is exact. A stripped
    /// binary has none, so the functions are recovered from the code instead.
    /// See [`crate::scan`] for how, and for what that costs in accuracy.
    pub fn parse(data: &[u8]) -> Result<Self, ObjError> {
        let data = crate::macho::aarch64_slice(data);
        let file = object::File::parse(data)?;
        let isa = match Isa::from_object(file.architecture(), file.is_little_endian())? {
            isa @ (Isa::Arm32 | Isa::Mips32 | Isa::Mips32Be) => {
                set_of_symbol(isa, most_functions_encoded(&file))
            }
            isa => isa,
        };

        if let object::File::MachO64(macho) = &file
            && let Some((functions, found_by)) =
                crate::macho::fileset_functions(macho).or_else(|| crate::macho::functions(macho))
        {
            return Ok(Self {
                isa,
                functions,
                found_by,
                addresses: address_space(&file),
                links: Links::of_object(&file),
                other_set: BTreeSet::new(),
            });
        }

        let mut functions = Vec::new();
        let mut other_set = BTreeSet::new();
        for symbol in file.symbols() {
            if symbol.kind() != SymbolKind::Text || symbol.size() == 0 {
                continue;
            }

            let own = set_of_symbol(isa, encoding_of(&symbol));
            let address = own.arch().function_address(symbol.address());
            if own != isa {
                other_set.insert(address);
            }
            let Some(code) = symbol_code(&file, &symbol, address) else { continue };
            functions.push(Function {
                name: stable_name(symbol.name().unwrap_or_default()).to_string(),
                address,
                code,
            });
        }

        if !functions.is_empty() {
            // A stable order keeps output and snapshots reproducible; the
            // symbol table order is not guaranteed.
            functions.sort_by_key(|function| (function.address, function.name.clone()));
            let addresses = address_space(&file);
            let links = Links::of_object(&file);
            return Ok(Self {
                isa,
                functions,
                found_by: FoundBy::Symbols,
                addresses,
                links,
                other_set,
            });
        }

        if !has_code_section(&file) {
            return Err(ObjError::NoCode);
        }

        // Stripping keeps the dynamic symbol table, which names what the
        // library exports, so those functions keep their names, and their
        // instruction sets.
        let mut exported: BTreeMap<u64, &str> = BTreeMap::new();
        let mut other_set = BTreeSet::new();
        for symbol in file.dynamic_symbols() {
            if symbol.kind() == SymbolKind::Text
                && symbol.size() > 0
                && let Ok(name) = symbol.name()
            {
                // ARM marks a Thumb function by setting bit 0 of its address.
                let address = symbol.address() & !1;
                if set_of_symbol(isa, encoding_of(&symbol)) != isa {
                    other_set.insert(address);
                }
                let name_of = exported.entry(address).or_insert(name);
                // Aliases share an address. The first by name keeps the
                // result the same whatever order the table lists them in.
                *name_of = (*name_of).min(name);
            }
        }
        let scanned: Vec<Function> = crate::scan::recover_functions(data, isa.arch())
            .into_iter()
            .map(|found| found.function)
            .map(|function| match exported.get(&function.address) {
                Some(name) => Function { name: stable_name(name).to_string(), ..function },
                None => function,
            })
            .collect();

        // Code that yields no functions means the scan failed, not that the
        // binary is empty. Saying so beats reporting that nothing changed.
        if scanned.is_empty() {
            return Err(ObjError::NoFunctions);
        }

        Ok(Self {
            isa,
            functions: scanned,
            found_by: FoundBy::Scanning,
            addresses: address_space(&file),
            links: Links::of_object(&file),
            other_set,
        })
    }

    /// Read a blob that carries no container format.
    ///
    /// A flash dump is bytes and nothing else. There is no header to say what
    /// architecture the code is for, and no section table to say where it
    /// loads, so the caller states both.
    ///
    /// The whole blob is treated as code. Data mixed into it decodes as
    /// instructions, which is wrong but harmless: those words become opaque or
    /// meaningless entries that the matcher compares by content, so they
    /// affect one function's score rather than derailing the comparison.
    ///
    /// Boundaries are less reliable than in an object file. A raw image has no
    /// exception index, so recovery falls back to call targets and to the code
    /// after a return, which splits some functions at an internal return. See
    /// [`crate::scan`].
    pub fn parse_raw(data: &[u8], base: u64, isa: Isa) -> Result<Self, ObjError> {
        // Too short to hold one instruction. Without this the scanner reports
        // a "function" of two or three bytes that can never decode.
        if data.len() < isa.arch().instruction_width() {
            return Err(ObjError::NoCode);
        }

        let regions = [(base, data)];
        let mut index = crate::scan::find_exception_index(data, base, isa.arch());
        if index.is_empty() {
            let order = match isa {
                Isa::Mips32Be | Isa::Mips16Be => crate::unwind::ByteOrder::Big,
                Isa::Arm32 | Isa::Thumb2 | Isa::Aarch64 | Isa::Mips32 | Isa::Mips16 => {
                    crate::unwind::ByteOrder::Little
                }
            };
            let ranges = crate::unwind::find_function_ranges(data, base, order);
            index = crate::scan::index_from_ranges(&ranges, isa.arch());
        }
        let functions: Vec<Function> =
            crate::scan::recover_from_regions(&regions, &index, isa.arch())
                .into_iter()
                .map(|found| found.function)
                .collect();

        if functions.is_empty() {
            return Err(ObjError::NoFunctions);
        }

        let addresses = AddressSpace::of_raw_image(base, data.len() as u64);
        let links = Links::of_raw_image(base, data);
        Ok(Self {
            isa,
            functions,
            found_by: FoundBy::Scanning,
            addresses,
            links,
            other_set: BTreeSet::new(),
        })
    }
}

/// Copy out the bytes a symbol covers.
/// A symbol name without the part that changes when unrelated code does.
///
/// LLVM gives a local function it makes visible across a module a suffix
/// `.llvm.` and a hash of the module, so any edit to the module renames all
/// of them. Measured on smallvec built by Rust for ARM at `-Os`, the fix
/// renamed `SmallVec::reserve`, and each unedited caller of it read as calling
/// a different function. GCC's `.constprop.0` and `.isra.0` count clones in
/// order, so they stay.
pub(crate) fn stable_name(name: &str) -> &str {
    match name.rsplit_once(".llvm.") {
        Some((stem, hash))
            if !hash.is_empty() && hash.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            stem
        }
        _ => name,
    }
}

fn symbol_code(
    file: &object::File<'_>,
    symbol: &object::Symbol<'_, '_>,
    address: u64,
) -> Option<Vec<u8>> {
    let section = file.section_by_index(symbol.section_index()?).ok()?;
    let data = section.data().ok()?;

    // Symbol addresses are absolute; section data starts at the section
    // address, so rebase before slicing.
    let start = address.checked_sub(section.address())? as usize;
    let end = start.checked_add(symbol.size() as usize)?;
    data.get(start..end).map(<[u8]>::to_vec)
}

/// How a function's instructions are encoded, where an architecture has a
/// compact set beside its full one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Encoding {
    /// A32, or MIPS32.
    Full,
    /// Thumb-2, or MIPS16e.
    Compact,
}

/// The `st_other` value of an ELF symbol that names a MIPS16e function.
const STO_MIPS16: u8 = 0xf0;

/// The encoding of the function a symbol names.
///
/// A linked file sets bit 0 of a Thumb-2 or MIPS16e function's address. An
/// unlinked MIPS object does not: it marks the symbol in `st_other` instead.
fn encoding_of(symbol: &object::Symbol<'_, '_>) -> Encoding {
    let marked = match symbol.flags() {
        object::SymbolFlags::Elf { st_other, .. } => st_other.0 & STO_MIPS16 == STO_MIPS16,
        _ => false,
    };
    match symbol.address() & 1 == 1 || marked {
        true => Encoding::Compact,
        false => Encoding::Full,
    }
}

/// The instruction set of a function in `encoding`, in a binary read as
/// `isa`.
fn set_of_symbol(isa: Isa, encoding: Encoding) -> Isa {
    match (isa, encoding) {
        (Isa::Arm32 | Isa::Thumb2, Encoding::Compact) => Isa::Thumb2,
        (Isa::Arm32 | Isa::Thumb2, Encoding::Full) => Isa::Arm32,
        (Isa::Mips32 | Isa::Mips16, Encoding::Compact) => Isa::Mips16,
        (Isa::Mips32 | Isa::Mips16, Encoding::Full) => Isa::Mips32,
        (Isa::Mips32Be | Isa::Mips16Be, Encoding::Compact) => Isa::Mips16Be,
        (Isa::Mips32Be | Isa::Mips16Be, Encoding::Full) => Isa::Mips32Be,
        (Isa::Aarch64, _) => isa,
    }
}

/// The encoding of most functions of a file, as their symbols say.
///
/// The symbol table says it where there is one, and the dynamic symbol
/// table where it was stripped. Where neither is left, as in stripped
/// firmware, bit 0 of the entry point says which set the code runs in.
fn most_functions_encoded(file: &object::File<'_>) -> Encoding {
    let count = |symbols: &mut dyn Iterator<Item = object::Symbol<'_, '_>>| {
        symbols
            .filter(|symbol| symbol.kind() == SymbolKind::Text && symbol.size() > 0)
            .fold((0usize, 0usize), |(compact, all), symbol| {
                let found = usize::from(encoding_of(&symbol) == Encoding::Compact);
                (compact + found, all + 1)
            })
    };
    let (compact, all) = match count(&mut file.symbols()) {
        (_, 0) => count(&mut file.dynamic_symbols()),
        counted => counted,
    };
    let most = match all {
        0 => file.entry() & 1 == 1,
        _ => compact * 2 > all,
    };
    match most {
        true => Encoding::Compact,
        false => Encoding::Full,
    }
}

/// The addresses a linked file occupies: each section it loads, `.bss`
/// included.
///
/// An unlinked object gets none. Its sections all start at zero, and the code
/// holds zeros where the linker will write addresses, so nothing in it is an
/// address yet.
fn address_space(file: &object::File<'_>) -> AddressSpace {
    if file.kind() == ObjectKind::Relocatable {
        return AddressSpace::none();
    }
    AddressSpace::from_ranges(
        file.sections()
            .filter(|section| section.address() != 0)
            .map(|section| section.address()..section.address().saturating_add(section.size())),
    )
}

fn has_code_section(file: &object::File<'_>) -> bool {
    file.sections().any(|section| section.kind() == object::SectionKind::Text && section.size() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bytes_that_are_not_an_object() {
        assert!(matches!(Binary::parse(b"not an elf"), Err(ObjError::Parse(_))));
    }

    #[test]
    fn rejects_empty_input() {
        assert!(Binary::parse(&[]).is_err());
    }

    #[test]
    fn a_name_loses_the_hash_of_its_module() {
        assert_eq!(stable_name("_RNvMs_reserve.llvm.17076722752549331491"), "_RNvMs_reserve");
        assert_eq!(stable_name("inflate"), "inflate");
        assert_eq!(stable_name("deflate.constprop.0"), "deflate.constprop.0");
        assert_eq!(stable_name("odd.llvm."), "odd.llvm.", "no hash");
        assert_eq!(stable_name("odd.llvm.12a"), "odd.llvm.12a", "not a hash");
        assert_eq!(stable_name(""), "");
    }

    const EVERY_ISA: [Isa; 7] = [
        Isa::Arm32,
        Isa::Thumb2,
        Isa::Aarch64,
        Isa::Mips32,
        Isa::Mips32Be,
        Isa::Mips16,
        Isa::Mips16Be,
    ];

    #[test]
    fn the_other_set_of_the_other_set_is_the_set() {
        for isa in EVERY_ISA {
            if let Some(other) = isa.other_set() {
                assert_ne!(other, isa);
                assert_eq!(other.other_set(), Some(isa), "{isa:?}");
            }
        }
    }

    #[test]
    fn a_symbol_keeps_to_the_sets_of_its_binary() {
        for isa in EVERY_ISA {
            for encoding in [Encoding::Full, Encoding::Compact] {
                let own = set_of_symbol(isa, encoding);
                assert!(own == isa || isa.other_set() == Some(own), "{isa:?} {encoding:?}");
                assert_eq!(set_of_symbol(own, encoding), own, "{isa:?} {encoding:?}");
            }
        }
        assert_eq!(set_of_symbol(Isa::Mips32, Encoding::Compact), Isa::Mips16);
        assert_eq!(set_of_symbol(Isa::Mips16Be, Encoding::Full), Isa::Mips32Be);
        assert_eq!(set_of_symbol(Isa::Arm32, Encoding::Compact), Isa::Thumb2);
        assert_eq!(set_of_symbol(Isa::Aarch64, Encoding::Compact), Isa::Aarch64);
    }

    /// How a MIPS object marks a MIPS16e function.
    #[derive(Clone, Copy, Debug)]
    enum Marking {
        /// As an unlinked object does.
        StOther,
        /// As a linked file does.
        Bit0,
    }

    /// A MIPS object with one function in each set: `full` at 0, and
    /// `compact` at 8, marked as `marking` says.
    fn mips_object(marking: Marking) -> Vec<u8> {
        use object::write::{Object, Symbol, SymbolSection};
        let mut object = Object::new(
            object::BinaryFormat::Elf,
            object::Architecture::Mips,
            object::Endianness::Little,
        );
        let text = object.section_id(object::write::StandardSection::Text);
        // `jr ra` and its delay slot, then MIPS16e `jrc ra`, `nop`, padded.
        let code = [
            0x08, 0x00, 0xe0, 0x03, 0, 0, 0, 0, 0xa0, 0xe8, 0x00, 0x65, 0x00, 0x65, 0x00, 0x65,
        ];
        object.append_section_data(text, &code, 4);
        let mut add = |name: &str, value: u64, size: u64, st_other: u8| {
            object.add_symbol(Symbol {
                name: name.as_bytes().to_vec(),
                value,
                size,
                kind: object::SymbolKind::Text,
                scope: object::SymbolScope::Linkage,
                weak: false,
                section: SymbolSection::Section(text),
                flags: object::SymbolFlags::Elf {
                    st_info: object::elf::SymbolInfo::new(object::elf::STB_GLOBAL, object::elf::STT_FUNC),
                    st_other: object::elf::SymbolOther(st_other),
                },
            });
        };
        add("full", 0, 8, 0);
        match marking {
            Marking::StOther => add("compact", 8, 4, STO_MIPS16),
            Marking::Bit0 => add("compact", 9, 4, 0),
        }
        object.write().expect("a small object writes")
    }

    #[test]
    fn a_mips16_function_is_found_by_st_other_or_by_bit_0() {
        for marking in [Marking::StOther, Marking::Bit0] {
            let binary = Binary::parse(&mips_object(marking)).expect("the object parses");
            let set = |name: &str| {
                let function =
                    binary.functions.iter().find(|function| function.name == name).unwrap();
                binary.isa_of(function)
            };
            assert_eq!(set("full"), Isa::Mips32, "{marking:?}");
            assert_eq!(set("compact"), Isa::Mips16, "{marking:?}");
            let compact = binary.functions.iter().find(|function| function.name == "compact");
            assert_eq!(compact.map(|function| function.address), Some(8), "{marking:?}");
        }
    }
}
