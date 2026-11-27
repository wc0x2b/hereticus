//! The rules of the IL view of A64 code.

use hereticus_il::arch::{Insn, aarch64};
use yaxpeax_arm::armv8::a64::Opcode as A64Opcode;

use super::Rules;
use crate::{Compared, constant_text};

/// The rules of A64 code.
pub(super) struct Aarch64;

impl Rules for Aarch64 {
    fn is_named_load(&self, insn: &Insn) -> bool {
        aarch64::decoded(insn).is_some_and(aarch64::is_named_load)
    }

    fn operand_statement(
        &self,
        insn: &Insn,
        tokens: &[&str],
        last_compare: &mut Option<Compared>,
    ) -> Option<String> {
        aarch64_statement(insn, tokens, last_compare)
    }

    /// `brk` traps.
    fn traps(&self, insn: &Insn) -> bool {
        aarch64_opcode(insn) == Some(A64Opcode::BRK)
    }

    fn forms_page(&self, insn: &Insn) -> bool {
        aarch64_opcode(insn) == Some(A64Opcode::ADRP)
    }

    /// `mneg` is a multiply-subtract of zero.
    fn subtracts_product(&self, insn: &Insn) -> bool {
        matches!(
            aarch64_opcode(insn),
            Some(A64Opcode::MSUB | A64Opcode::UMSUBL | A64Opcode::SMSUBL)
        )
    }

    fn compares_by_adding(&self, insn: &Insn) -> bool {
        aarch64_opcode(insn) == Some(A64Opcode::ADDS)
    }

    /// `csetm` is a `csinv` of the zero register, and `cset` a `csinc`.
    fn select_constant(&self, insn: &Insn) -> &'static str {
        match aarch64_opcode(insn) {
            Some(A64Opcode::CSINV) => "-1",
            _ => "1",
        }
    }

    fn select_statement(
        &self,
        insn: &Insn,
        [dest, chosen, other, cond]: [&str; 4],
        other_is_zero: bool,
    ) -> String {
        let printed = hereticus_il::arch::printed_name(insn);
        match (aarch64_opcode(insn), printed.as_str()) {
            // `cinc x0, x1, ne` is `csinc x0, x1, x1, eq`: it prints the
            // condition of the change.
            (Some(A64Opcode::CSINC), "cinc") => {
                format!("{dest} = {cond} ? {chosen} + 1 : {chosen}")
            }
            (Some(A64Opcode::CSINV), "cinv") => format!("{dest} = {cond} ? ~{chosen} : {chosen}"),
            (Some(A64Opcode::CSNEG), "cneg") => format!("{dest} = {cond} ? -{chosen} : {chosen}"),
            // Else `csinc` adds 1 to what it picks where the condition
            // fails, `csinv` inverts it and `csneg` negates it.
            (Some(A64Opcode::CSINC), _) if other_is_zero => {
                format!("{dest} = {cond} ? {chosen} : 1")
            }
            (Some(A64Opcode::CSINC), _) => format!("{dest} = {cond} ? {chosen} : {other} + 1"),
            (Some(A64Opcode::CSINV), _) if other_is_zero => {
                format!("{dest} = {cond} ? {chosen} : -1")
            }
            (Some(A64Opcode::CSINV), _) => format!("{dest} = {cond} ? {chosen} : ~{other}"),
            (Some(A64Opcode::CSNEG), _) if other_is_zero => {
                format!("{dest} = {cond} ? {chosen} : 0")
            }
            (Some(A64Opcode::CSNEG), _) => format!("{dest} = {cond} ? {chosen} : -{other}"),
            _ => format!("{dest} = {cond} ? {chosen} : {other}"),
        }
    }
}

/// The statement of an AArch64 instruction whose operands the IL does not
/// read as an operator does: a conditional compare, a vector constant, and
/// a move between a general register and a lane of a vector.
fn aarch64_statement(
    insn: &Insn,
    tokens: &[&str],
    last_compare: &mut Option<Compared>,
) -> Option<String> {
    let opcode = aarch64::decoded(insn)?.opcode;
    let immediate = |token: &str| {
        let token = token.trim_start_matches('#');
        token
            .strip_prefix("0x")
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            .map_or_else(|| token.to_string(), constant_text)
    };
    let is_lane = |token: &str| token.contains('.') && token.ends_with(']');
    let line = match (opcode, tokens) {
        // `ccmp x1, x2, #4, eq` compares where its condition holds, and
        // else sets the flags to the constant it names. A branch after it
        // tests the flags, not one compare.
        (
            A64Opcode::CCMP | A64Opcode::CCMN | A64Opcode::FCCMP | A64Opcode::FCCMPE,
            [left, right, flags, cond],
        ) => {
            *last_compare = None;
            let right = immediate(right);
            let right = if opcode == A64Opcode::CCMN { format!("-{right}") } else { right };
            format!("flags = {cond} ? compare({left}, {right}) : nzcv({})", immediate(flags))
        }
        (A64Opcode::MOVI, [dest, value]) => format!("{dest} = {}", immediate(value)),
        // A shifted value is named as one, as `3 msl 16`.
        (A64Opcode::MVNI, [dest, value]) if value.contains(' ') => format!("{dest} = ~({value})"),
        (A64Opcode::MVNI, [dest, value]) => format!("{dest} = ~{}", immediate(value)),
        // `ins`, `umov` and `dup` of a lane print as `mov`.
        (A64Opcode::INS | A64Opcode::UMOV | A64Opcode::DUP, [dest, source])
            if is_lane(dest) || is_lane(source) =>
        {
            format!("{dest} = {source}")
        }
        (A64Opcode::SMOV | A64Opcode::DUP, [dest, source]) => {
            format!("{dest} = {}({source})", hereticus_il::arch::printed_name(insn))
        }
        _ => return None,
    };
    Some(line)
}

/// The opcode of `insn`, where it is A64.
fn aarch64_opcode(insn: &Insn) -> Option<A64Opcode> {
    aarch64::decoded(insn).map(|decoded| decoded.opcode)
}
