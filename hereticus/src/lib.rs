//! Compare functions between two binaries.
//!
//! Two builds of the same source can produce very different machine code. The
//! same function at `-O0` and `-O2` shares almost no bytes. `hereticus` finds the
//! functions that changed in behavior, and ignores the ones that only changed
//! in compilation.

pub mod address;
pub mod arch;
pub mod callee;
pub mod dynamic;
pub mod il;
mod macho;
pub mod matching;
pub mod norm;
pub mod obj;
pub mod raw;
pub mod scan;
pub mod unpack;
pub mod unwind;
pub mod view;
