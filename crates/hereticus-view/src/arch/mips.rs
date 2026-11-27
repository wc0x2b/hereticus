//! The rules of the IL view of MIPS32 and MIPS16e code.

use hereticus_il::Reg;
use hereticus_il::arch::Insn;
use hereticus_il::arch::mips::{self, Decoded as MipsDecoded};
use hereticus_il::arch::mips16::Op as Mips16Op;
use hereticus_il::arch::mips32::Op as Mips32Op;
use rabbitizer::opcodes::Opcode as MipsOpcode;

use super::{FrameStep, Reading, Rules, WholeFrame};
use crate::constant_text;

/// The rules of MIPS32 and MIPS16e code.
pub(super) struct Mips;

impl Rules for Mips {
    /// A load of a double from a slot prints with `ld` first.
    fn is_named_load(&self, insn: &Insn) -> bool {
        matches!(
            mips::decoded(insn),
            Some(MipsDecoded::Rabbitizer(MipsOpcode::core_ldc1 | MipsOpcode::core_ldc2))
        )
    }

    fn reads_as_printed(&self, insn: &Insn) -> bool {
        mips::moves_part_of_a_word(insn)
    }

    fn own_statement(&self, insn: &Insn, shown: &[&str], reading: &mut Reading) -> Option<String> {
        mips_statement(insn, shown, &mut reading.float_conditions)
    }

    /// `lui` puts its constant in the upper half.
    fn upper_half_shift(&self, insn: &Insn) -> Option<u32> {
        mips::is(insn, MipsOpcode::core_lui).then_some(16)
    }

    fn joins_page_offset(&self, insn: &Insn) -> bool {
        mips::is(insn, MipsOpcode::core_addiu) || mips::is(insn, MipsOpcode::core_ori)
    }

    fn loads_page(&self, insn: &Insn) -> bool {
        mips::is(insn, MipsOpcode::core_lw)
    }

    fn whole_frame(&self, insn: &Insn) -> Option<WholeFrame> {
        let frame = hereticus_il::arch::mips16::frame(insn)?;
        let reg = |name: &&str| {
            let number =
                hereticus_il::arch::mips32::REGISTERS.iter().position(|known| known == name)?;
            Some(Reg::General(u8::try_from(number).ok()?))
        };
        Some(WholeFrame {
            step: if frame.saves { FrameStep::Makes } else { FrameStep::Drops },
            size: i64::from(frame.size),
            kept: frame.kept.iter().map(reg).collect(),
        })
    }
}

/// The test of the last float compare into each of the eight condition
/// codes, so a branch on a code reads as `if (fv0 < fv1) goto $+0xc`.
#[derive(Default)]
pub(super) struct FloatConditions([Option<String>; 8]);

impl FloatConditions {
    /// The name of condition code `code`. Code 0 is the only one MIPS I
    /// has, and most code uses no other, so it keeps the short name.
    fn name(code: u8) -> String {
        match code {
            0 => "fcc".to_string(),
            code => format!("fcc{code}"),
        }
    }

    /// Keep `test` as what code `code` holds, and give the statement that
    /// sets it.
    fn set(&mut self, code: u8, test: String) -> String {
        let line = format!("{} = {test}", Self::name(code));
        self.0[usize::from(code & 7)] = Some(test);
        line
    }

    /// The statement of a branch to `target` where code `code` is `when`.
    fn branch(&self, code: u8, when: Truth, target: &str) -> String {
        let test = self.0[usize::from(code & 7)].as_deref();
        match (when, test) {
            (Truth::True, Some(test)) => format!("if ({test}) goto {target}"),
            (Truth::True, None) => format!("if ({}) goto {target}", Self::name(code)),
            (Truth::False, Some(test)) if test.starts_with("!(") => {
                format!("if ({}) goto {target}", &test[2..test.len() - 1])
            }
            (Truth::False, Some(test)) => format!("if (!({test})) goto {target}"),
            (Truth::False, None) => format!("if (!{}) goto {target}", Self::name(code)),
        }
    }
}

/// Which value of a condition code a branch takes.
#[derive(Clone, Copy)]
enum Truth {
    True,
    False,
}

/// The statement of a MIPS instruction whose operands the code does not
/// print: the `hi` and `lo` that a multiply or divide writes, the
/// condition code that a float compare sets and `bc1t` and `bc1f` test,
/// and the stores and loads of the MIPS16e `save` and `restore`.
fn mips_statement(
    insn: &Insn,
    operands: &[&str],
    float_conditions: &mut FloatConditions,
) -> Option<String> {
    use MipsDecoded::{Mips16, Mips32, Rabbitizer};
    use hereticus_il::arch::mips32::{FloatBranch, FloatCompare};
    let decoded = mips::decoded(insn)?;
    // `multu` and `divu` read their operands unsigned, as `u>>` does.
    let unsigned = matches!(
        decoded,
        Rabbitizer(MipsOpcode::core_multu | MipsOpcode::core_divu)
            | Mips32(Mips32Op::Multu | Mips32Op::Maddu | Mips32Op::Msubu)
    );
    let sign = if unsigned { "u" } else { "" };
    let line = match (decoded, operands) {
        (
            Rabbitizer(MipsOpcode::core_mult | MipsOpcode::core_multu)
            | Mips32(Mips32Op::Mult | Mips32Op::Multu),
            [left, right],
        ) => format!("hi:lo = {left} {sign}* {right}"),
        (Mips32(Mips32Op::Madd | Mips32Op::Maddu), [left, right]) => {
            format!("hi:lo = hi:lo + {left} {sign}* {right}")
        }
        (Mips32(Mips32Op::Msub | Mips32Op::Msubu), [left, right]) => {
            format!("hi:lo = hi:lo - {left} {sign}* {right}")
        }
        // The assembler prints the `zero` that the encoding holds first.
        (
            Rabbitizer(MipsOpcode::core_div | MipsOpcode::core_divu),
            [left, right] | ["zero", left, right],
        ) => format!("lo = {left} {sign}/ {right}; hi = {left} {sign}% {right}"),
        (Mips16(Mips16Op::Save | Mips16Op::Restore), _) => {
            return frame_statement(&hereticus_il::arch::mips16::frame(insn)?);
        }
        (Rabbitizer(MipsOpcode::core_mfhi) | Mips32(Mips32Op::Mfhi), [dest]) => {
            format!("{dest} = hi")
        }
        (Rabbitizer(MipsOpcode::core_mflo) | Mips32(Mips32Op::Mflo), [dest]) => {
            format!("{dest} = lo")
        }
        (Rabbitizer(MipsOpcode::core_mthi) | Mips32(Mips32Op::Mthi), [source]) => {
            format!("hi = {source}")
        }
        (Rabbitizer(MipsOpcode::core_mtlo) | Mips32(Mips32Op::Mtlo), [source]) => {
            format!("lo = {source}")
        }
        (
            Rabbitizer(MipsOpcode::core_bc1t) | Mips32(Mips32Op::FloatBranch(FloatBranch::True)),
            [target],
        ) => float_conditions.branch(mips::float_condition_code(insn)?, Truth::True, target),
        (
            Rabbitizer(MipsOpcode::core_bc1f) | Mips32(Mips32Op::FloatBranch(FloatBranch::False)),
            [target],
        ) => float_conditions.branch(mips::float_condition_code(insn)?, Truth::False, target),
        (Rabbitizer(opcode), [left, right]) => {
            let test = float_test(compare_condition(opcode)?, left, right);
            float_conditions.set(0, test)
        }
        (Mips32(Mips32Op::FloatCompare(FloatCompare { condition, .. })), [left, right]) => {
            let test = float_test(condition, left, right);
            float_conditions.set(mips::float_condition_code(insn)?, test)
        }
        _ => return None,
    };
    Some(line)
}

/// The condition of a MIPS float compare that `rabbitizer` reads, by its
/// number in the encoding: from 0 (`c.f`) to 15 (`c.ngt`). `rabbitizer`
/// spells `c.sf.d` as `c.df.d`.
fn compare_condition(opcode: MipsOpcode) -> Option<u8> {
    use MipsOpcode as O;
    const COMPARES: [(MipsOpcode, MipsOpcode); 16] = [
        (O::core_c_f_s, O::core_c_f_d),
        (O::core_c_un_s, O::core_c_un_d),
        (O::core_c_eq_s, O::core_c_eq_d),
        (O::core_c_ueq_s, O::core_c_ueq_d),
        (O::core_c_olt_s, O::core_c_olt_d),
        (O::core_c_ult_s, O::core_c_ult_d),
        (O::core_c_ole_s, O::core_c_ole_d),
        (O::core_c_ule_s, O::core_c_ule_d),
        (O::core_c_sf_s, O::core_c_df_d),
        (O::core_c_ngle_s, O::core_c_ngle_d),
        (O::core_c_seq_s, O::core_c_seq_d),
        (O::core_c_ngl_s, O::core_c_ngl_d),
        (O::core_c_lt_s, O::core_c_lt_d),
        (O::core_c_nge_s, O::core_c_nge_d),
        (O::core_c_le_s, O::core_c_le_d),
        (O::core_c_ngt_s, O::core_c_ngt_d),
    ];
    let found =
        COMPARES.iter().position(|&(single, double)| opcode == single || opcode == double)?;
    u8::try_from(found).ok()
}

/// What a MIPS float compare of condition `condition` tests, as an
/// expression of `left` and `right`. Each operator is false on a NaN, so a
/// compare that is true on one reads as the negation of its opposite:
/// `c.ult` is `!(a >= b)`. The signaling eight, 8 to 15, test as the quiet
/// eight do.
fn float_test(condition: u8, left: &str, right: &str) -> String {
    match condition & 7 {
        0 => "0".to_string(),
        1 => format!("unordered({left}, {right})"),
        2 => format!("{left} == {right}"),
        3 => format!("!({left} < {right} || {left} > {right})"),
        4 => format!("{left} < {right}"),
        5 => format!("!({left} >= {right})"),
        6 => format!("{left} <= {right}"),
        _ => format!("!({left} > {right})"),
    }
}

/// The statement of a MIPS16e `save` or `restore`: the arguments `save`
/// stores into the frame of the caller, the size of the frame, then the
/// registers kept in the frame, lowest address first:
///
/// ```text
/// save    a0, 0x20, s0, ra   store.32 [sp] = a0; store.32 [sp - 8] = s0, ra; sp = sp - 0x20
/// restore 0x20, s0, ra       s0, ra = load.32 [sp + 0x18]; sp = sp + 0x20
/// ```
fn frame_statement(frame: &hereticus_il::arch::mips16::Frame) -> Option<String> {
    let (arguments, kept) = (&frame.arguments, &frame.kept);
    let size = u64::from(frame.size);
    let kept_size = 4 * kept.len() as u64;
    let mut parts = Vec::new();
    match frame.saves {
        true => {
            if !arguments.is_empty() {
                parts.push(format!("store.32 [sp] = {}", arguments.join(", ")));
            }
            if !kept.is_empty() {
                let offset = constant_text(kept_size);
                parts.push(format!("store.32 [sp - {offset}] = {}", kept.join(", ")));
            }
            parts.push(format!("sp = sp - {}", constant_text(size)));
        }
        _ => {
            if !kept.is_empty() {
                let base = match size.checked_sub(kept_size)? {
                    0 => "sp".to_string(),
                    offset => format!("sp + {}", constant_text(offset)),
                };
                parts.push(format!("{} = load.32 [{base}]", kept.join(", ")));
            }
            parts.push(format!("sp = sp + {}", constant_text(size)));
        }
    }
    Some(parts.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_too_small_for_its_registers_has_no_statement() {
        let too_small = hereticus_il::arch::mips16::Frame {
            saves: false,
            arguments: Vec::new(),
            size: 4,
            kept: vec!["s0", "ra"],
        };
        assert_eq!(frame_statement(&too_small), None, "a frame too small");
    }
}
