//! The rules of the IL view of A32 and T32 code.

use hereticus_il::arch::Insn;
use hereticus_il::arch::arm32::{self, Step, Vfp};
use hereticus_il::arch::neon::NeonOperation;
use hereticus_il::{AccessKind, Lifted, Named, Op, Operand, Reg};
use yaxpeax_arm::armv7::{ConditionCode, Opcode as ArmOpcode};

use super::Rules;
use crate::{Compared, constant_text};

/// The rules of A32 code.
pub(super) struct Arm32;

/// The rules of T32 code.
pub(super) struct Thumb2;

impl Rules for Arm32 {
    fn condition(&self, insn: &Insn, op: Option<Op>) -> Option<&'static str> {
        a32_condition(insn, op)
    }

    fn without_condition<'a>(&self, name: &'a str) -> &'a str {
        without_condition(name)
    }

    fn is_named_load(&self, insn: &Insn) -> bool {
        is_named_load(insn)
    }

    fn list_statement(&self, insn: &Insn, tokens: &[&str], lifted: &Lifted) -> Option<String> {
        list_statement(insn, tokens, lifted)
    }

    fn list_offsets(&self, insn: &Insn, lifted: &Lifted, count: usize) -> Option<(i64, i64)> {
        list_offsets(insn, lifted, count)
    }

    fn operand_statement(
        &self,
        insn: &Insn,
        tokens: &[&str],
        last_compare: &mut Option<Compared>,
    ) -> Option<String> {
        vfp_statement(insn, tokens, last_compare).or_else(|| lane_move_statement(insn, tokens))
    }

    fn subtracts_product(&self, insn: &Insn) -> bool {
        arm32::core_opcode(insn) == Some(ArmOpcode::MLS)
    }

    fn compares_by_adding(&self, insn: &Insn) -> bool {
        arm32::core_opcode(insn) == Some(ArmOpcode::CMN)
    }

    fn conditional_compare(&self, insn: &Insn, left: &str, right: &str) -> String {
        match arm32::core_opcode(insn) {
            Some(ArmOpcode::CMN) => format!("flags = compare({left}, {})", crate::negated(right)),
            Some(ArmOpcode::TST) => format!("flags = {left} & {right}"),
            Some(ArmOpcode::TEQ) => format!("flags = {left} ^ {right}"),
            _ => format!("flags = compare({left}, {right})"),
        }
    }

    fn sets_upper_half(&self, insn: &Insn) -> bool {
        arm32::core_opcode(insn) == Some(ArmOpcode::MOVT)
    }

    fn loads_pool_word(&self, insn: &Insn, named: &Named) -> bool {
        arm32::core_opcode(insn).is_some() && is_literal_load(named)
    }

    /// The program counter reads 8 bytes past an A32 instruction.
    fn pool_address(&self, insn: &Insn, offset: i64) -> Option<u64> {
        Some((insn.address + 8).wrapping_add_signed(offset))
    }
}

/// T32 keeps the rules of A32 but for its `it` and its program counter.
impl Rules for Thumb2 {
    fn hides(&self, insn: &Insn) -> bool {
        hereticus_il::arch::thumb::is_it(insn)
    }

    /// The program counter reads 4 bytes past a T32 instruction, to a word.
    fn pool_address(&self, insn: &Insn, offset: i64) -> Option<u64> {
        Some(((insn.address + 4) & !3).wrapping_add_signed(offset))
    }

    fn condition(&self, insn: &Insn, op: Option<Op>) -> Option<&'static str> {
        Arm32.condition(insn, op)
    }

    fn without_condition<'a>(&self, name: &'a str) -> &'a str {
        Arm32.without_condition(name)
    }

    fn is_named_load(&self, insn: &Insn) -> bool {
        Arm32.is_named_load(insn)
    }

    fn list_statement(&self, insn: &Insn, tokens: &[&str], lifted: &Lifted) -> Option<String> {
        Arm32.list_statement(insn, tokens, lifted)
    }

    fn list_offsets(&self, insn: &Insn, lifted: &Lifted, count: usize) -> Option<(i64, i64)> {
        Arm32.list_offsets(insn, lifted, count)
    }

    fn operand_statement(
        &self,
        insn: &Insn,
        tokens: &[&str],
        last_compare: &mut Option<Compared>,
    ) -> Option<String> {
        Arm32.operand_statement(insn, tokens, last_compare)
    }

    fn subtracts_product(&self, insn: &Insn) -> bool {
        Arm32.subtracts_product(insn)
    }

    fn compares_by_adding(&self, insn: &Insn) -> bool {
        Arm32.compares_by_adding(insn)
    }

    fn conditional_compare(&self, insn: &Insn, left: &str, right: &str) -> String {
        Arm32.conditional_compare(insn, left, right)
    }

    fn sets_upper_half(&self, insn: &Insn) -> bool {
        Arm32.sets_upper_half(insn)
    }

    fn loads_pool_word(&self, insn: &Insn, named: &Named) -> bool {
        Arm32.loads_pool_word(insn, named)
    }
}

/// Whether the decoder prints `insn` with `ld` first, as a load of a GOT
/// slot is.
fn is_named_load(insn: &Insn) -> bool {
    matches!(
        arm32::core_opcode(insn),
        Some(
            ArmOpcode::LDR
                | ArmOpcode::LDRB
                | ArmOpcode::LDRH
                | ArmOpcode::LDRSB
                | ArmOpcode::LDRSH
                | ArmOpcode::LDRSBT
                | ArmOpcode::LDRSHT
                | ArmOpcode::LDRD
                | ArmOpcode::LDRT
                | ArmOpcode::LDRBT
                | ArmOpcode::LDRHT
                | ArmOpcode::LDREX
                | ArmOpcode::LDREXB
                | ArmOpcode::LDREXH
                | ArmOpcode::LDREXD
                | ArmOpcode::LDM(..)
                | ArmOpcode::LDC(_)
                | ArmOpcode::LDCL(_)
                | ArmOpcode::LDC2(_)
                | ArmOpcode::LDC2L(_)
        )
    )
}

/// The condition an A32 instruction runs on, as the `ne` of `addne`, or a
/// Thumb-2 one in an `it` block.
///
/// The IL holds no such condition, so it is read from the decoded
/// instruction. A branch names its own. A conditional return or jump, as
/// `bxne lr`, decodes as a branch too, but names no condition, so `op`,
/// where the lift names one, and not the kind of `insn` decides.
fn a32_condition(insn: &Insn, op: Option<Op>) -> Option<&'static str> {
    if op == Some(Op::Branch) {
        return None;
    }
    let condition = arm32::condition(insn).filter(|&condition| condition != ConditionCode::AL)?;
    Some(arm32::condition_name(condition))
}

/// The statement of a NEON move to or from one lane, as `r1 = d16[1]`. The
/// IL holds the lane as an operand of its own, which the text names with
/// its register.
fn lane_move_statement(insn: &Insn, tokens: &[&str]) -> Option<String> {
    let Some(arm32::Decoded::Neon(neon)) = arm32::decoded(insn) else { return None };
    match (neon.operation, tokens) {
        (NeonOperation::Vmov, [dest, source]) if dest.contains('[') || source.contains('[') => {
            Some(format!("{dest} = {source}"))
        }
        _ => None,
    }
}

/// The statement of an A32 or T32 VFP instruction that the IL names only
/// `Float`: a compare, the move of its result to the flags, and a move of a
/// double between two general registers, low half first.
fn vfp_statement(
    insn: &Insn,
    tokens: &[&str],
    last_compare: &mut Option<Compared>,
) -> Option<String> {
    let Some(arm32::Decoded::Vfp { vfp, .. }) = arm32::decoded(insn) else { return None };
    let line = match (vfp, tokens) {
        // A branch after it tests the flags, not the operands: the flags of
        // a float compare mean other things than those of an integer one.
        (Vfp::Compare { .. }, [left, right]) => {
            *last_compare = None;
            let right = if *right == "0x0" { "0" } else { right };
            format!("fpscr = compare({left}, {right})")
        }
        (Vfp::Status, ["APSR_nzcv"]) => {
            *last_compare = None;
            "flags = fpscr".to_string()
        }
        (Vfp::MoveDouble, [low, high, double]) if double.starts_with('d') => {
            format!("{high}:{low} = {double}")
        }
        (Vfp::MoveDouble, [double, low, high]) if double.starts_with('d') => {
            format!("{double} = {high}:{low}")
        }
        _ => return None,
    };
    Some(line)
}

/// The name of an A32 instruction without the condition it ends with, as
/// `clz` of `clzeq` and `uxtah` of `uxtahcc`.
fn without_condition(name: &str) -> &str {
    const CONDITIONS: [&str; 16] = [
        "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt",
        "le",
    ];
    match name.len().checked_sub(2).map(|at| name.split_at(at)) {
        Some((base, condition)) if !base.is_empty() && CONDITIONS.contains(&condition) => base,
        _ => name,
    }
}

/// Where an ARM access to a list of registers starts, relative to its base,
/// and in which direction it moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ListOrder {
    IncrementAfter,
    IncrementBefore,
    DecrementAfter,
    DecrementBefore,
}

/// Whether an access to a list of registers writes its last address back to
/// its base, as the `!` of `ldm r0!, {r1}` and every `push` do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteBack {
    Yes,
    No,
}

impl ListOrder {
    /// The order an access to a list goes in, as `ia` of `ldmia`, or
    /// `None` for an instruction that accesses no list.
    fn of(insn: &Insn) -> Option<(Self, WriteBack)> {
        use arm32::Decoded::{Core, Vfp as VfpWord};
        Some(match arm32::decoded(insn)? {
            Core { opcode: ArmOpcode::PUSH, .. } | VfpWord { vfp: Vfp::Push, .. } => {
                (Self::DecrementBefore, WriteBack::Yes)
            }
            Core { opcode: ArmOpcode::POP, .. } | VfpWord { vfp: Vfp::Pop, .. } => {
                (Self::IncrementAfter, WriteBack::Yes)
            }
            Core {
                opcode: ArmOpcode::LDM(up, before, ..) | ArmOpcode::STM(up, before, ..),
                ..
            } => {
                let order = match (up, before) {
                    (true, false) => Self::IncrementAfter,
                    (true, true) => Self::IncrementBefore,
                    (false, false) => Self::DecrementAfter,
                    (false, true) => Self::DecrementBefore,
                };
                (order, WriteBack::No)
            }
            VfpWord { vfp: Vfp::Multiple(Step::IncrementAfter, _), .. } => {
                (Self::IncrementAfter, WriteBack::No)
            }
            VfpWord { vfp: Vfp::Multiple(Step::DecrementBefore, _), .. } => {
                (Self::DecrementBefore, WriteBack::No)
            }
            _ => return None,
        })
    }

    /// The offset of the first register from the base, and the change of
    /// the base after it, for `size` bytes in all.
    fn offsets(self, size: u64, slot: u64) -> (i64, i64) {
        let size = size as i64;
        match self {
            Self::IncrementAfter => (0, size),
            Self::IncrementBefore => (slot as i64, size),
            Self::DecrementAfter => (slot as i64 - size, -size),
            Self::DecrementBefore => (-size, -size),
        }
    }
}

/// Where an A32 or T32 access to a list of `count` registers puts the
/// first, from its base, and how far it moves the base where it writes it
/// back: `(-0x8, -0x8)` for `push {r4, lr}`.
fn list_offsets(insn: &Insn, lifted: &Lifted, count: usize) -> Option<(i64, i64)> {
    let (order, _) = ListOrder::of(insn)?;
    let bits = lifted.memory.and_then(|memory| memory.width).map_or(32, |width| width.bits());
    let slot = u64::from(bits / 8);
    Some(order.offsets(slot * count as u64, slot))
}

/// An ARM access to a list of registers as one load or store, as
/// `store.32 [sp - 0x8] = r4, lr; sp = sp - 0x8` for `push {r4, lr}`.
///
/// It is read from the printed text, as the IL holds no list.
fn list_statement(insn: &Insn, tokens: &[&str], lifted: &Lifted) -> Option<String> {
    let (order, mut write_back) = ListOrder::of(insn)?;
    let list = tokens.iter().find(|token| token.starts_with('{'))?;
    let registers: Vec<&str> =
        list.trim_end().strip_suffix('}')?[1..].split(',').map(str::trim).collect();
    if registers.iter().any(|register| register.is_empty() || register.contains('-')) {
        return None;
    }
    // The base, where the access names one: `push` and `pop` go through
    // `sp`.
    let base = tokens.iter().find(|token| !token.starts_with('{')).copied().unwrap_or("");
    let base = match base {
        "" => "sp",
        base => match base.strip_suffix('!') {
            Some(base) => {
                write_back = WriteBack::Yes;
                base
            }
            None => base,
        },
    };
    let bits = lifted.memory.and_then(|memory| memory.width).map_or(32, |width| width.bits());
    let slot = u64::from(bits / 8);
    let (start, change) = order.offsets(slot * registers.len() as u64, slot);
    let place = match start {
        0 => format!("[{base}]"),
        start if start < 0 => format!("[{base} - {}]", constant_text(start.unsigned_abs())),
        start => format!("[{base} + {}]", constant_text(start as u64)),
    };
    let values = registers.join(", ");
    let mut line = match lifted.memory?.kind {
        AccessKind::Load => format!("{values} = load.{bits} {place}"),
        AccessKind::Store => format!("store.{bits} {place} = {values}"),
        AccessKind::LoadStore => return None,
    };
    // A load into the base leaves the loaded value there, not the address.
    let loads_base = lifted.memory?.kind == AccessKind::Load && registers.contains(&base);
    if write_back == WriteBack::Yes && !loads_base {
        let operator = if change < 0 { "-" } else { "+" };
        let amount = constant_text(change.unsigned_abs());
        line.push_str(&format!("; {base} = {base} {operator} {amount}"));
    }
    Some(line)
}

/// Whether `named` loads one word at a distance from `pc`, as
/// `ldr r1, [pc, #0x4c]` reads a word of a literal pool.
fn is_literal_load(named: &Named) -> bool {
    named.lifted.op == Op::Load
        && matches!(
            named.lifted.operands.as_slice(),
            [Operand::Reg(_), Operand::Memory { base: Some(Reg::ProgramCounter), index: None, .. }]
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hereticus_il::arch::Decoder as _;

    #[test]
    fn the_name_of_a_conditional_instruction_drops_the_condition() {
        assert_eq!(without_condition("uxtahcc"), "uxtah");
        assert_eq!(without_condition("smlawbmi"), "smlawb");
        assert_eq!(without_condition("eq"), "eq");
    }

    #[test]
    fn a_list_order_names_where_the_access_starts() {
        use hereticus_il::arch::arm32::Arm32;
        use hereticus_il::arch::thumb::Thumb2;
        let a32 = |word: u32| Arm32.decode(&word.to_le_bytes(), 0, 0).expect("the word decodes");
        // push.w {r4, lr}
        let push = Thumb2.decode(&[0x2d, 0xe9, 0x10, 0x40], 0, 0).expect("the word decodes");
        assert_eq!(hereticus_il::arch::printed_name(&push), "push");
        assert_eq!(ListOrder::of(&push), Some((ListOrder::DecrementBefore, WriteBack::Yes)));
        let vpop = a32(0xecbd_8b02); // vpop {d8}
        assert_eq!(hereticus_il::arch::printed_name(&vpop), "vpop");
        assert_eq!(ListOrder::of(&vpop), Some((ListOrder::IncrementAfter, WriteBack::Yes)));
        let stmdb = a32(0xe900_0002); // stmdb r0, {r1}
        assert_eq!(ListOrder::of(&stmdb), Some((ListOrder::DecrementBefore, WriteBack::No)));
        let ldmne = a32(0x1890_0002); // ldmne r0, {r1}
        assert_eq!(ListOrder::of(&ldmne), Some((ListOrder::IncrementAfter, WriteBack::No)));
        assert_eq!(ListOrder::of(&a32(0xe591_0000)), None, "ldr r0, [r1]");
        assert_eq!(ListOrder::IncrementAfter.offsets(8, 4), (0, 8));
        assert_eq!(ListOrder::IncrementBefore.offsets(8, 4), (4, 8));
        assert_eq!(ListOrder::DecrementAfter.offsets(8, 4), (-4, -8));
        assert_eq!(ListOrder::DecrementBefore.offsets(8, 4), (-8, -8));
    }
}
