//! The rules of the IL view of x86 code.

use hereticus_il::arch::Insn;

use super::Rules;
use crate::CarryFlag;

/// The rules of x86 code, of 32 and 64 bits.
pub(super) struct X86;

impl Rules for X86 {
    fn carry_flag(&self) -> CarryFlag {
        CarryFlag::SetBelow
    }

    /// `inc` and `dec` keep the carry flag of the code before them.
    fn keeps_carry(&self, insn: &Insn) -> bool {
        let text = insn.to_string();
        text.starts_with("inc ") || text.starts_with("dec ")
    }

    fn names_field(&self) -> bool {
        true
    }
}
