//! Read a binary: an ELF or Mach-O file, or a raw image, and the functions
//! in it.
//!
//! [`Binary::parse`] takes the functions from the symbols where the binary
//! has them, and from a scan of the code where it is stripped. [`Links`]
//! reads what the linker left: the texts, the slots of the global offset
//! table, and the stubs that jump through them.

pub mod links;
mod macho;
pub mod obj;

use macho::{apply_chained_fixups, indirect_names};

pub use links::Links;
pub use obj::{Binary, FoundBy, Function, Isa, ObjError, ROW_REACH, RowText, stable_name};
