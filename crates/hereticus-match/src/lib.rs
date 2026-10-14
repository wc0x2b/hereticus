//! Pair the functions of two binaries, and say which changed in behavior.
//!
//! [`norm`] rewrites each instruction to what a rebuild cannot change.
//! [`matching`] pairs the functions of two binaries on those forms, and
//! reports what changed in each pair.

pub mod matching;
pub mod norm;

pub use hereticus_view::PairedLabels;
