//! Read binaries and find the functions in them.

use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

use crate::arch::arm32::Arm32;

/// Why a binary could not be read.
#[derive(Debug)]
pub enum ObjError {
    /// The bytes are not an object file this crate can read.
    Parse(object::Error),
    /// The file is a valid object, but not for an architecture `fndiff` knows.
    UnsupportedArch(object::Architecture),
    /// The file holds no executable code.
    NoCode,
}

impl core::fmt::Display for ObjError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parse(err) => write!(f, "cannot parse object: {err}"),
            Self::UnsupportedArch(arch) => write!(f, "unsupported architecture: {arch:?}"),
            Self::NoCode => write!(f, "object has no executable code"),
        }
    }
}

impl core::error::Error for ObjError {}

impl From<object::Error> for ObjError {
    fn from(err: object::Error) -> Self {
        Self::Parse(err)
    }
}

/// The architectures `fndiff` can decode.
///
/// More variants arrive as more decoders do. Keeping this an enum rather than
/// a boxed trait object lets the matcher check that two binaries agree on
/// architecture before it compares them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Isa {
    Arm32,
}

impl Isa {
    /// The decoder for this architecture.
    pub fn arch(self) -> Arm32 {
        match self {
            Self::Arm32 => Arm32,
        }
    }

    fn from_object(arch: object::Architecture) -> Option<Self> {
        match arch {
            object::Architecture::Arm => Some(Self::Arm32),
            _ => None,
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

/// A binary, with the functions found in it.
#[derive(Clone, Debug)]
pub struct Binary {
    pub isa: Isa,
    pub functions: Vec<Function>,
}

impl Binary {
    /// Read a binary and recover its functions from the symbol table.
    ///
    /// Only symbols marked as functions with a known size are recovered. A
    /// stripped binary therefore yields nothing here; finding functions
    /// without symbols needs scanning, which is separate work.
    pub fn parse(data: &[u8]) -> Result<Self, ObjError> {
        let file = object::File::parse(data)?;
        let isa = Isa::from_object(file.architecture())
            .ok_or_else(|| ObjError::UnsupportedArch(file.architecture()))?;

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

        if functions.is_empty() && !has_code_section(&file) {
            return Err(ObjError::NoCode);
        }

        // A stable order keeps output and snapshots reproducible; the symbol
        // table order is not guaranteed.
        functions.sort_by_key(|function| (function.address, function.name.clone()));
        Ok(Self { isa, functions })
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
