//! Recover function boundaries from stripped binaries.
//!
//! The instructions that make up a function, and the addresses they refer to,
//! are what `hereticus` compares between two builds. When a binary has no
//! symbol table, the only way to find those functions is to read the code and
//! look for the patterns that only a function starts: prologues, calls, and
//! the words that follow a return.
//!
//! This crate defines the [`Recovery`] trait, which an architecture implements
//! to answer the questions a scan needs. Each architecture module in the
//! `arch` subdirectory provides an implementation.

pub mod address;
pub mod arch;

pub use address::{AddressSpace, ConstantKind, Contents};
pub use arch::{
    AbsoluteCall, CallTarget, DataAmongCode, Decoder, GlobalPointerSetup, Insn, InsnKind,
    JumpTable, Memory, Recovery, TableJumps, VectorTable, decode_all, leaves,
};
pub use hereticus_il::arch::Opcode;
pub use hereticus_il::Operand;
