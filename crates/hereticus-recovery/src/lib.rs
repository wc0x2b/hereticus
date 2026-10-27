//! Recover function boundaries from stripped binaries.
//!
//! The instructions that make up a function, and the addresses they refer to,
//! are what `hereticus` compares between two builds. When a binary has no
//! symbol table, the only way to find those functions is to read the code and
//! look for the patterns that only a function starts: prologues, calls, and
//! the words that follow a return.
//!
//! A scan asks an architecture through the [`arch::Recovery`] trait, which
//! [`arch`] implements for each instruction set.

pub mod arch;
pub mod dynamic;
pub mod mips_stubs;
pub mod pe;
pub mod raw;
pub mod scan;
pub mod unwind;
