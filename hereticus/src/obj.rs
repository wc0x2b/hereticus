//! Read binaries and find the functions in them.

use object::{Object, ObjectKind, ObjectSection, ObjectSymbol, SymbolKind};

use crate::address::AddressSpace;
use crate::arch::Arch;
use crate::arch::arm32::Arm32;
use crate::arch::mips::Mips32;

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
    /// MIPS32, little endian, as a desktop-built object usually is.
    Mips32,
    /// MIPS32, big endian, as most shipped firmware is.
    Mips32Be,
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
            Self::Mips32 => &Mips32::LITTLE,
            Self::Mips32Be => &Mips32::BIG,
        }
    }

    /// Choose a decoder for what an object file says it holds.
    ///
    /// `little_endian` decides nothing for ARM, which is only read in that
    /// order anyway, and decides which decoder for MIPS, which ships in both.
    fn from_object(arch: object::Architecture, little_endian: bool) -> Result<Self, ObjError> {
        match arch {
            object::Architecture::Arm => Ok(Self::Arm32),
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
    /// The binary is stripped, so the functions were recovered from the code.
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
}

impl Binary {
    /// Read a binary and find the functions in it.
    ///
    /// The symbol table comes first, because a name is exact. A stripped
    /// binary has none, so the functions are recovered from the code instead.
    /// See [`crate::scan`] for how, and for what that costs in accuracy.
    pub fn parse(data: &[u8]) -> Result<Self, ObjError> {
        let file = object::File::parse(data)?;
        let isa = Isa::from_object(file.architecture(), file.is_little_endian())?;

        let mut functions = Vec::new();
        for symbol in file.symbols() {
            if symbol.kind() != SymbolKind::Text || symbol.size() == 0 {
                continue;
            }

            let Some(code) = symbol_code(&file, &symbol) else { continue };
            functions.push(Function {
                name: symbol.name().unwrap_or_default().to_string(),
                address: symbol.address(),
                code,
            });
        }

        if !functions.is_empty() {
            // A stable order keeps output and snapshots reproducible; the
            // symbol table order is not guaranteed.
            functions.sort_by_key(|function| (function.address, function.name.clone()));
            let addresses = address_space(&file);
            return Ok(Self { isa, functions, found_by: FoundBy::Symbols, addresses });
        }

        if !has_code_section(&file) {
            return Err(ObjError::NoCode);
        }

        let scanned: Vec<Function> = crate::scan::recover_functions(data, isa.arch())
            .into_iter()
            .map(|found| found.function)
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
        let functions: Vec<Function> = crate::scan::recover_from_regions(&regions, &[], isa.arch())
            .into_iter()
            .map(|found| found.function)
            .collect();

        if functions.is_empty() {
            return Err(ObjError::NoFunctions);
        }

        let addresses = AddressSpace::of_raw_image(base, data.len() as u64);
        Ok(Self { isa, functions, found_by: FoundBy::Scanning, addresses })
    }
}

/// Copy out the bytes a symbol covers.
fn symbol_code(file: &object::File<'_>, symbol: &object::Symbol<'_, '_>) -> Option<Vec<u8>> {
    let section = file.section_by_index(symbol.section_index()?).ok()?;
    let data = section.data().ok()?;

    // Symbol addresses are absolute; section data starts at the section
    // address, so rebase before slicing.
    let start = symbol.address().checked_sub(section.address())? as usize;
    let end = start.checked_add(symbol.size() as usize)?;
    data.get(start..end).map(<[u8]>::to_vec)
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
}
