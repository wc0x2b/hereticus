//! Show code as the IL reads it, one statement per instruction.
//!
//! The IL names what an instruction computes the same way on every
//! architecture, as p-code and the IL of Binary Ninja do, so `--diff` can
//! show `w0 = w1 + 0x10` where the code says `add w0, w1, #0x10` on one
//! architecture and `addiu a0, a1, 0x10` on another. A branch on the flags
//! names the compare before it, as `if (w0 <= 0x3f) goto $+0x40`.
//!
//! The IL keeps no register names and no targets, so each statement takes
//! them from the operands the decoder printed. An instruction the IL does
//! not name shows as the decoder printed it.

use std::collections::HashMap;

use crate::arch::{Arch, Insn, is_branch_target};
use crate::il::{AccessKind, Comparison, Cond, Lifted, Op, Operand, Reg, Test};

/// The IL statement of each instruction of `insns`, which were decoded from
/// `code`.
pub fn il_lines(arch: &dyn Arch, code: &[u8], insns: &[Insn]) -> Vec<String> {
    let Some(first) = insns.first() else { return Vec::new() };
    let mut last_compare: Option<Compared> = None;
    insns
        .iter()
        .map(|insn| {
            let word = usize::try_from(insn.address - first.address)
                .ok()
                .and_then(|offset| code.get(offset..offset.checked_add(insn.bytes_len)?));
            let lifted = word.and_then(|word| arch.lift(insn, word));
            match lifted.and_then(|lifted| statement(insn, &lifted, &mut last_compare)) {
                Some(text) => match a32_condition(arch, insn) {
                    Some(cond) => format!("if ({cond}) {text}"),
                    None => text,
                },
                None => insn.to_string(),
            }
        })
        .collect()
}

/// The condition an A32 instruction runs on, as the `ne` of `addne`.
///
/// The IL holds no such condition, so it is read from the mnemonic. A
/// branch names its own, and `teq` is no conditional `t`.
fn a32_condition<'i>(arch: &dyn Arch, insn: &'i Insn) -> Option<&'i str> {
    const CONDITIONS: [&str; 16] = [
        "eq", "ne", "hs", "cs", "lo", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt",
        "le",
    ];
    if !arch.triple().starts_with("arm")
        || matches!(insn.kind, crate::arch::InsnKind::Branch { .. })
    {
        return None;
    }
    let mnemonic = insn.mnemonic.as_str();
    let cond = CONDITIONS.iter().find(|cond| mnemonic.ends_with(*cond))?;
    let base = &mnemonic[..mnemonic.len() - cond.len()];
    (!base.is_empty() && base != "t").then(|| &mnemonic[base.len()..])
}

/// What the last compare compared, for the branches that follow it.
#[derive(Clone, Debug)]
struct Compared {
    left: String,
    right: String,
    kind: CompareKind,
}

/// How a compare combined its two values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompareKind {
    Subtract,
    Add,
    And,
}

/// The operands as the decoder printed them, split at the commas that are
/// not inside brackets, braces or parentheses.
fn split_operands(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0i32, 0);
    for (index, character) in text.char_indices() {
        match character {
            '[' | '{' | '(' => depth += 1,
            ']' | '}' | ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(text[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    let last = text[start..].trim();
    if !last.is_empty() {
        parts.push(last);
    }
    parts
}

/// A memory operand as `[base + offset]`, from `[x1, #0x10]` or
/// `0x10(sp)`.
fn memory_text(token: &str) -> String {
    let inner = if let Some(inner) = token.strip_prefix('[') {
        inner.trim_end_matches('!').trim_end_matches(']')
    } else if let Some((offset, base)) = token.split_once('(') {
        let base = base.trim_end_matches(')');
        return match offset.trim() {
            "" | "0" | "0x0" => format!("[{base}]"),
            offset => format!("[{base} + {offset}]"),
        };
    } else {
        return token.to_string();
    };
    // A shift applies to the index before it, as `[r3, r1, lsl 2]` does.
    let mut parts: Vec<String> = Vec::new();
    for part in inner.split(',').map(|part| part.trim().trim_start_matches('#')) {
        let is_shift =
            ["lsl", "lsr", "asr", "ror", "uxt", "sxt"].iter().any(|word| part.starts_with(word));
        match parts.last_mut() {
            Some(index) if is_shift => *index = format!("({index} {})", part.replace('#', "")),
            _ => parts.push(part.to_string()),
        }
    }
    format!("[{}]", parts.join(" + ").replace("+ -", "- "))
}

/// A constant as code reads it: small ones in decimal, a negative one with
/// its sign.
fn constant_text(value: u64) -> String {
    let signed = value as i64;
    if (-0x1_0000..0).contains(&signed) {
        return format!("-{:#x}", signed.unsigned_abs());
    }
    if value < 10 { value.to_string() } else { format!("{value:#x}") }
}

/// The relation a condition tests, as an operator.
fn relation(cond: Cond) -> Option<&'static str> {
    Some(match cond {
        Cond::Equal => "==",
        Cond::NotEqual => "!=",
        Cond::UnsignedGreaterOrEqual => "u>=",
        Cond::UnsignedLess => "u<",
        Cond::UnsignedGreater => "u>",
        Cond::UnsignedLessOrEqual => "u<=",
        Cond::SignedGreaterOrEqual => ">=",
        Cond::SignedLess => "<",
        Cond::SignedGreater => ">",
        Cond::SignedLessOrEqual => "<=",
        _ => return None,
    })
}

/// The test of a condition on what a compare compared.
fn condition_text(cond: Cond, compared: Option<&Compared>) -> String {
    let Some(compared) = compared else { return format!("flags.{cond:?}") };
    let (left, right) = (&compared.left, &compared.right);
    match (compared.kind, cond) {
        (CompareKind::And, Cond::Equal | Cond::BitsClear) => format!("({left} & {right}) == 0"),
        (CompareKind::And, Cond::NotEqual | Cond::BitsSet) => format!("({left} & {right}) != 0"),
        (CompareKind::Subtract, Cond::Negative) => format!("{left} - {right} < 0"),
        (CompareKind::Subtract, Cond::NotNegative) => format!("{left} - {right} >= 0"),
        (CompareKind::Subtract, cond) => match relation(cond) {
            Some(operator) => format!("{left} {operator} {right}"),
            None => format!("flags.{cond:?}"),
        },
        (CompareKind::Add, cond) => match relation(cond) {
            Some(operator) => format!("{left} {operator} -{right}"),
            None => format!("flags.{cond:?}"),
        },
        (CompareKind::And, cond) => format!("flags.{cond:?}"),
    }
}

/// Report whether an operand reads as zero.
fn is_zero(operand: &Operand) -> bool {
    matches!(operand, Operand::Zero | Operand::Const(0))
}

/// The width a memory access names, as `.32`.
fn width_text(lifted: &Lifted) -> String {
    lifted
        .memory
        .and_then(|memory| memory.width)
        .map(|width| format!(".{}", width.bits()))
        .unwrap_or_default()
}

/// What a lifted operand was paired with among the printed ones.
enum Pairing {
    /// A printed operand.
    Printed(String),
    /// Nothing printed, as the zero register of `cmp`: what it reads as.
    Implied(String),
    /// The printed operands left over after the last lifted one, as the
    /// `#0x20` of a post-index access.
    Extra(String),
}

impl Pairing {
    fn into_text(self) -> String {
        match self {
            Self::Printed(text) | Self::Implied(text) | Self::Extra(text) => text,
        }
    }
}

/// Pair each lifted operand with the printed operand it stands for.
///
/// An alias prints fewer operands than the IL holds: `cmp` leaves out the
/// zero register it writes, `mov x0, x1` is `orr x0, xzr, x1`, `mov x29,
/// sp` adds 0, and the Thumb-2 `adds r0, 0x18` names `r0` once for two
/// operands. A shifted register prints as two, as `r1, lsl 4`, which pair
/// with one lifted operand as `(r1 lsl 4)`. `None` where the two do not
/// pair.
fn pair_operands(lifted: &[Operand], tokens: &[&str]) -> Option<Vec<Pairing>> {
    let mut missing = lifted.len().saturating_sub(tokens.len());
    let mut printed = tokens.iter();
    let mut paired: Vec<Pairing> = Vec::with_capacity(lifted.len());
    for (index, operand) in lifted.iter().enumerate() {
        let repeats = index > 0
            && matches!(operand, Operand::Reg(_))
            && lifted.get(index - 1) == Some(operand);
        if missing > 0 && matches!(operand, Operand::Zero | Operand::Const(0)) {
            missing -= 1;
            paired.push(Pairing::Implied("0".to_string()));
            continue;
        }
        if missing > 0 && repeats {
            missing -= 1;
            let text = paired.last().map(|last| match last {
                Pairing::Printed(text) | Pairing::Implied(text) | Pairing::Extra(text) => {
                    text.clone()
                }
            })?;
            paired.push(Pairing::Implied(text));
            continue;
        }
        paired.push(Pairing::Printed((*printed.next()?).to_string()));
    }
    if missing > 0 {
        return None;
    }
    let rest: Vec<&str> = printed.copied().collect();
    if !rest.is_empty() {
        // A post-index offset follows the memory operand; a shift follows
        // the register it shifts.
        let after_memory = matches!(lifted.last(), Some(Operand::Memory { .. }));
        let is_shift = |token: &str| {
            ["lsl", "lsr", "asr", "ror", "rrx", "uxt", "sxt"]
                .iter()
                .any(|word| token.starts_with(word))
        };
        if after_memory {
            paired.push(Pairing::Extra(rest.join(", ")));
        } else if rest.iter().all(|token| is_shift(token)) {
            let Some(Pairing::Printed(last)) = paired.pop() else { return None };
            let shift = rest.join(" ").replace('#', "");
            paired.push(Pairing::Printed(format!("({last} {shift})")));
        } else {
            return None;
        }
    }
    Some(paired)
}

/// The statement of one instruction, or `None` where the IL does not name
/// it well enough to show.
fn statement(insn: &Insn, lifted: &Lifted, last_compare: &mut Option<Compared>) -> Option<String> {
    let mut tokens = split_operands(&insn.operands);
    // The A32 decoder prints a register before the two a compare compares,
    // as `cmps r0, r3, 0x0`, which is no operand of it.
    if lifted.op == Op::Compare && tokens.len() == lifted.operands.len() + 1 {
        tokens.remove(0);
    }
    let target = tokens.iter().rev().find(|token| is_branch_target(token)).copied();
    // A call or jump through a register names it last, as `blr x1` and the
    // MIPS16e `jalr ra, v0` do.
    match lifted.op {
        Op::Return => return Some("return".to_string()),
        Op::Call => return Some(format!("call {}", target.or(tokens.last().copied())?)),
        Op::Jump => return Some(format!("goto {}", target.or(tokens.last().copied())?)),
        _ => {}
    }
    // `lsl` and `lsr` of AArch64 are aliases of a field move, which the IL
    // holds with the two field bounds; the printed amount is the shift.
    let shift = match lifted.op {
        Op::ShiftLeft => Some("<<"),
        Op::ShiftRight => Some("u>>"),
        Op::ShiftRightArithmetic => Some(">>"),
        _ => None,
    };
    if let (Some(operator), [dest, source, amount], 4) =
        (shift, tokens.as_slice(), lifted.operands.len())
    {
        return Some(format!("{dest} = {source} {operator} {}", amount.trim_start_matches('#')));
    }
    let mut paired = pair_operands(&lifted.operands, &tokens)?;
    // A post-index access writes its base after it, as `ldp x29, x30, [sp],
    // #0x20` does.
    let mut after = String::new();
    if let Some(Pairing::Extra(rest)) = paired.last()
        && let Some(base) = tokens.iter().find(|token| token.starts_with('['))
    {
        let base = base.trim_start_matches('[').trim_end_matches(']');
        after = format!("; {base} = {base} + {}", rest.trim_start_matches('#'));
        paired.pop();
    }
    let paired: Vec<String> = paired.into_iter().map(Pairing::into_text).collect();

    // The idioms `canonical` reads plainly rewrite the operands, so their
    // registers are named by what each was paired with.
    let names: HashMap<Reg, &str> = lifted
        .operands
        .iter()
        .zip(&paired)
        .filter_map(|(operand, text)| match operand {
            Operand::Reg(reg) => Some((*reg, text.as_str())),
            _ => None,
        })
        .collect();
    let memory = tokens.iter().find(|token| token.starts_with('[') || token.contains('('));
    let canonical = lifted.clone().canonical();
    let operands: Vec<String> = if canonical.operands == lifted.operands {
        lifted
            .operands
            .iter()
            .zip(paired)
            .map(|(operand, text)| match operand {
                Operand::Memory { .. } => memory_text(&text),
                Operand::Const(value) => constant_text(*value),
                _ => text,
            })
            .collect()
    } else {
        let text = |operand: &Operand| -> Option<String> {
            Some(match operand {
                Operand::Reg(reg) => (*names.get(reg)?).to_string(),
                Operand::Zero => "0".to_string(),
                Operand::Const(value) => constant_text(*value),
                Operand::Memory { .. } => memory_text(memory?),
                Operand::Target => target?.to_string(),
                Operand::RegisterList | Operand::Other => return None,
            })
        };
        canonical.operands.iter().map(text).collect::<Option<_>>()?
    };

    let binary = |operator: &str| match operands.as_slice() {
        [dest, left, right] => Some(format!("{dest} = {left} {operator} {right}")),
        [dest, right] => Some(format!("{dest} = {dest} {operator} {right}")),
        _ => None,
    };

    let line = match canonical.op {
        // A move can hold a zero it does not use, as `mov x0, x1` is
        // `orr x0, xzr, x1` and `mov x29, sp` adds 0.
        Op::Move => match operands.as_slice() {
            [dest, source] | [dest, source, _]
                if canonical.operands.get(2).is_some_and(is_zero) =>
            {
                format!("{dest} = {source}")
            }
            [dest, _, source] if canonical.operands.get(1).is_some_and(is_zero) => {
                format!("{dest} = {source}")
            }
            [dest, source] => format!("{dest} = {source}"),
            _ => return None,
        },
        Op::Address => match operands.as_slice() {
            [dest, source] => format!("{dest} = &{source}"),
            _ => return None,
        },
        Op::Add => binary("+")?,
        Op::Subtract => binary("-")?,
        Op::Multiply => binary("*")?,
        Op::Divide => binary("/")?,
        Op::And => binary("&")?,
        Op::Or => binary("|")?,
        Op::Xor => binary("^")?,
        Op::AndNot => binary("& ~")?.replace("& ~ ", "& ~"),
        Op::OrNot => binary("| ~")?.replace("| ~ ", "| ~"),
        Op::ShiftLeft => binary("<<")?,
        Op::ShiftRight => binary("u>>")?,
        Op::ShiftRightArithmetic => binary(">>")?,
        // `csel x0, x1, x2, ls` picks on the condition it names last.
        Op::Select => match operands.as_slice() {
            [dest, chosen, other, cond]
                if !canonical.operands.get(1).is_some_and(is_zero)
                    || !canonical.operands.get(2).is_some_and(is_zero) =>
            {
                format!("{dest} = {cond} ? {chosen} : {other}")
            }
            _ => return None,
        },
        Op::Rotate => binary("ror")?,
        Op::MultiplyAdd => match operands.as_slice() {
            [dest, left, right, add] => format!("{dest} = {left} * {right} + {add}"),
            _ => return None,
        },
        Op::Not => match operands.as_slice() {
            [dest, source] => format!("{dest} = ~{source}"),
            _ => return None,
        },
        Op::Negate => match operands.as_slice() {
            [dest, source] => format!("{dest} = -{source}"),
            _ => return None,
        },
        Op::Load | Op::Store | Op::Atomic => {
            let access = canonical.memory?;
            let place = memory_text(memory?);
            let values: Vec<&String> =
                operands.iter().filter(|operand| !operand.starts_with('[')).collect();
            let values = values.iter().map(|value| value.as_str()).collect::<Vec<_>>().join(", ");
            match access.kind {
                AccessKind::Load => {
                    format!("{values} = load{} {place}{after}", width_text(&canonical))
                }
                AccessKind::Store => {
                    format!("store{} {place} = {values}{after}", width_text(&canonical))
                }
                AccessKind::LoadStore => return None,
            }
        }
        Op::Compare => match canonical.test {
            Some(Test::Compare { comparison, .. }) => {
                let kind = match comparison {
                    Comparison::Subtract { .. } => CompareKind::Subtract,
                    Comparison::Add { .. } => CompareKind::Add,
                    Comparison::And { .. } => CompareKind::And,
                };
                // `cmp` writes the zero register, which comes first.
                let [.., left, right] = operands.as_slice() else { return None };
                *last_compare = Some(Compared { left: left.clone(), right: right.clone(), kind });
                match kind {
                    CompareKind::And => format!("flags = {left} & {right}"),
                    CompareKind::Subtract | CompareKind::Add => {
                        format!("flags = compare({left}, {right})")
                    }
                }
            }
            Some(Test::SetOnCompare { cond, .. }) => {
                let [dest, left, right] = operands.as_slice() else { return None };
                format!("{dest} = {left} {} {right}", relation(cond)?)
            }
            _ => return None,
        },
        Op::Branch => {
            let target = target?;
            match canonical.test {
                Some(Test::OnFlags(cond)) => {
                    format!("if ({}) goto {target}", condition_text(cond, last_compare.as_ref()))
                }
                Some(Test::Guard(guard)) => {
                    let left = operands.first()?;
                    let right = match operands.as_slice() {
                        [_, right, _] => right.clone(),
                        _ => match guard.right {
                            crate::il::Value::Const(value) => constant_text(value),
                            _ => return None,
                        },
                    };
                    let test = match (guard.cond, relation(guard.cond)) {
                        (Cond::BitsClear, _) => format!("({left} & {right}) == 0"),
                        (Cond::BitsSet, _) => format!("({left} & {right}) != 0"),
                        (_, Some(operator)) => format!("{left} {operator} {right}"),
                        (_, None) => return None,
                    };
                    format!("if ({test}) goto {target}")
                }
                _ => return None,
            }
        }
        _ => return None,
    };
    Some(line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::aarch64::Aarch64;
    use crate::arch::decode_all;

    fn lines(words: &[u32]) -> Vec<String> {
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = decode_all(&Aarch64, &code, 0x1000);
        il_lines(&Aarch64, &code, &insns)
    }

    #[test]
    fn operands_split_outside_brackets() {
        assert_eq!(split_operands("x0, [x1, #0x10]"), ["x0", "[x1, #0x10]"]);
        assert_eq!(split_operands("a0, 0x10(sp)"), ["a0", "0x10(sp)"]);
        assert_eq!(split_operands(""), Vec::<&str>::new());
    }

    #[test]
    fn a_memory_operand_reads_as_base_plus_offset() {
        assert_eq!(memory_text("[x1, #0x10]"), "[x1 + 0x10]");
        assert_eq!(memory_text("[sp, #-0x10]!"), "[sp - 0x10]");
        assert_eq!(memory_text("[x0]"), "[x0]");
        assert_eq!(memory_text("0x10(sp)"), "[sp + 0x10]");
        assert_eq!(memory_text("0x0(v0)"), "[v0]");
        assert_eq!(memory_text("[r3, r1, lsl 2]"), "[r3 + (r1 lsl 2)]");
        assert_eq!(memory_text("[x1, x2, lsl #3]"), "[x1 + (x2 lsl 3)]");
    }

    #[test]
    fn a_compare_and_its_branch_read_as_one_test() {
        let shown = lines(&[
            0x7100_fc5f, // cmp w2, #0x3f
            0x5400_0208, // b.hi $+0x40
            0x8b02_0020, // add x0, x1, x2
            0xb940_1020, // ldr w0, [x1, #0x10]
            0xd65f_03c0, // ret
        ]);
        assert_eq!(
            shown,
            [
                "flags = compare(w2, 0x3f)",
                "if (w2 u> 0x3f) goto $+0x40",
                "x0 = x1 + x2",
                "w0 = load.32 [x1 + 0x10]",
                "return",
            ]
        );
    }

    #[test]
    fn aliases_and_forms_of_aarch64_read_plainly() {
        let shown = lines(&[
            0xa8c2_7bfd, // ldp x29, x30, [sp], #0x20
            0x9a80_9020, // csel x0, x1, x0, ls
            0x531c_6c23, // lsl w3, w1, #4
            0xd63f_0020, // blr x1
        ]);
        assert_eq!(
            shown,
            [
                "x29, x30 = load.64 [sp]; sp = sp + 0x20",
                "x0 = ls ? x1 : x0",
                "w3 = w1 << 0x4",
                "call x1",
            ]
        );
    }

    #[test]
    fn a_shifted_register_reads_as_one_operand() {
        use crate::arch::arm32::Arm32;
        let code = 0xe081_3204_u32.to_le_bytes(); // add r3, r1, r4, lsl #4
        let (insns, _) = decode_all(&Arm32, &code, 0x1000);
        assert_eq!(il_lines(&Arm32, &code, &insns), ["r3 = r1 + (r4 lsl 4)"]);
    }

    #[test]
    fn a_conditional_a32_instruction_names_its_condition() {
        use crate::arch::arm32::Arm32;
        // cmp r2, r3; addne r6, r4, #1
        let code: Vec<u8> =
            [0xe152_0003_u32, 0x1284_6001].iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = decode_all(&Arm32, &code, 0x1000);
        let shown = il_lines(&Arm32, &code, &insns);
        assert_eq!(shown[1], "if (ne) r6 = r4 + 1");
        assert_eq!(a32_condition(&Arm32, &insns[0]), None, "a compare that always runs");
    }

    #[test]
    fn any_code_shows_without_a_panic() {
        use crate::arch::{arm32::Arm32, mips::Mips32, mips16::Mips16, thumb::Thumb2};
        bolero::check!().with_type::<Vec<u8>>().for_each(|code| {
            let arches: [&dyn Arch; 6] =
                [&Aarch64, &Arm32, &Thumb2, &Mips32::BIG, &Mips16::LITTLE, &Mips16::BIG];
            for arch in arches {
                let (insns, _) = decode_all(arch, code, 0x1000);
                assert_eq!(il_lines(arch, code, &insns).len(), insns.len());
            }
        });
    }

    #[test]
    fn what_the_il_does_not_name_reads_as_the_decoder_printed_it() {
        let shown = lines(&[0xd503_201f]); // nop
        assert_eq!(shown, ["nop"]);
    }
}
