//! Compare functions between two binaries.
//!
//! Two builds of the same source can produce very different machine code. The
//! same function at `-O0` and `-O2` shares almost no bytes. `hereticus` finds the
//! functions that changed in behavior, and ignores the ones that only changed
//! in compilation.

pub use hereticus_arch as arch;
/// The callee of each call, and what the linker left to name it.
pub mod callee {
    pub use hereticus_callees::*;
    pub use hereticus_image::Links;
}
/// The IL each architecture lifts to: see [`hereticus_il`].
pub use hereticus_il as il;
pub use hereticus_image::obj;
pub use hereticus_match::{matching, norm};
/// Where each address of a binary leads: see [`hereticus_memory`].
pub mod address {
    pub use hereticus_memory::{AddressSpace, ConstantKind, Contents};
}
pub use hereticus_recovery::{dynamic, raw, scan, unwind};
pub use hereticus_unpack as unpack;
pub use hereticus_view as view;
