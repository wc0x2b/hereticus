//! Compare functions between two binaries.
//!
//! Two builds of the same source can produce very different machine code. The
//! same function at `-O0` and `-O2` shares almost no bytes. `fndiff` finds the
//! functions that changed in behavior, and ignores the ones that only changed
//! in compilation.

pub mod arch;
pub mod norm;
pub mod obj;
