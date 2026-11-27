//! The rules of the IL view of PowerPC code.

use hereticus_il::arch::{Insn, powerpc};

use super::Rules;

/// The rules of PowerPC code, of 32 and 64 bits.
pub(super) struct PowerPc;

impl Rules for PowerPc {
    fn reads_as_printed(&self, insn: &Insn) -> bool {
        powerpc::reads_as_printed(insn)
    }

    /// `lis` puts its constant in the upper half, which the IL holds
    /// shifted.
    fn upper_half_shift(&self, _insn: &Insn) -> Option<u32> {
        Some(0)
    }
}
