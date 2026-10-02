//! Reduce instructions to the part that survives recompilation.
//!
//! Two builds of one function differ in the details a compiler is free to
//! choose: which register holds a value, where a spill lands in the frame,
//! what address a branch goes to. Comparing those details finds differences
//! that do not matter. This module removes them and keeps the shape of the
//! work: which operation runs, on how many operands, of which kinds.
//!
//! # Scope
//!
//! Normalizing closes the gap between `-O1`, `-O2` and `-Os`, where the
//! compiler makes the same decisions in a different order. It does **not**
//! close the gap to `-O0`. Measured on the test corpus, an unoptimized build
//! shares about 0.31 of its normalized instructions with the same function at
//! `-O2`, while unrelated functions share about 0.21 — too close to separate.
//! The cause is not spelling but algorithm: at `-O2` the compiler replaces
//! `sum_to`'s loop with the closed form `n(n+1)/2`, and turns `classify`'s ten
//! basic blocks into one with conditional execution. No amount of renaming
//! bridges that. Matching an unoptimized build against an optimized one needs
//! semantic comparison, which is separate work.

use std::collections::BTreeSet;

use compact_str::{CompactString, format_compact};
use smallvec::SmallVec;

use crate::address::{AddressSpace, ConstantKind};
use crate::arch::{Arch, Insn, InsnKind, is_branch_target};
use crate::il::{self, Comparison, Cond, Guard, Lifted, Reg, Value, find_guards};

/// Operands held without a heap allocation.
///
/// Measured across the corpus, an instruction carries up to four operands,
/// bar a handful of register lists that reach six. Four inline covers all but
/// those, which spill to the heap and still work.
pub type Operands = SmallVec<[OperandShape; 4]>;

/// Constants held without a heap allocation.
///
/// The same measurement: an instruction holds no constant or one, and never
/// more than two.
pub type Constants = SmallVec<[u64; 2]>;

/// An instruction with the build-specific detail removed.
///
/// Equality ignores [`NormInsn::constants`], so two instructions that do the
/// same work with different constants compare equal. That is what makes
/// matching survive recompilation. Reporting *what changed* needs the exact
/// values, so they are carried here and compared by
/// [`NormInsn::differs_in_detail`].
#[derive(Clone, Debug, Eq)]
pub struct NormInsn {
    /// Operation name, with the flag-setting suffix and condition removed.
    ///
    /// A mnemonic is two or three characters, so it sits inline. An
    /// unreadable word carries its raw bits in the name instead and can reach
    /// twenty, which still fits the inline limit.
    pub operation: CompactString,
    /// Shape of each operand, in order.
    pub operands: Operands,
    /// How the instruction moves control.
    pub flow: FlowShape,
    /// Exact constants, in the order they appear.
    ///
    /// Kept out of equality on purpose: a threshold that changes from 100 to
    /// 50 must still match the function it came from, and must still show up
    /// as a difference once matched.
    pub constants: Constants,
}

impl NormInsn {
    /// Report whether two matched instructions differ in their exact values.
    ///
    /// Call this only on instructions that already compare equal. Equality
    /// answers "is this the same operation"; this answers "did the values
    /// change".
    pub fn differs_in_detail(&self, other: &Self) -> bool {
        self.constants != other.constants
    }
}

impl PartialEq for NormInsn {
    fn eq(&self, other: &Self) -> bool {
        self.operation == other.operation
            && self.operands == other.operands
            && self.flow == other.flow
    }
}

impl core::hash::Hash for NormInsn {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        // Must agree with `PartialEq`, so constants stay out.
        self.operation.hash(state);
        self.operands.hash(state);
        self.flow.hash(state);
    }
}

impl PartialOrd for NormInsn {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NormInsn {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.operation
            .cmp(&other.operation)
            .then_with(|| self.operands.cmp(&other.operands))
            .then_with(|| self.flow.cmp(&other.flow))
    }
}

/// What an operand is, without saying which one.
///
/// A register number and an exact constant both change between builds, so
/// neither is kept. Which *kind* of operand appears, and how many, stays
/// stable and still separates one operation from another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OperandShape {
    /// A general register.
    Register,
    /// The stack or frame pointer, which marks frame work.
    StackPointer,
    /// A constant, bucketed by size.
    Immediate(Magnitude),
    /// A memory reference through a register.
    Memory,
    /// A memory reference relative to the stack or frame pointer.
    StackSlot,
    /// A branch or load target, never the address itself.
    Target,
    /// A list of registers, as `push` and `pop` take.
    RegisterList,
    /// Anything not recognized.
    Other,
}

/// Rough size of a constant.
///
/// Exact values change with unrelated edits, but the difference between zero,
/// a small count and a wide constant reflects what the code does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Magnitude {
    Zero,
    /// Fits in a byte: loop counts, small offsets, field indexes.
    Small,
    /// Wider than a byte: masks, addresses, scaled constants.
    Large,
}

impl Magnitude {
    fn of(value: u64) -> Self {
        match value {
            0 => Self::Zero,
            1..=0xff => Self::Small,
            _ => Self::Large,
        }
    }
}

/// Control flow, without the target address.
///
/// Addresses move whenever anything before them changes size, so only the kind
/// of transfer is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FlowShape {
    Linear,
    Call,
    Jump,
    Branch,
    Return,
    Opaque,
}

impl From<InsnKind> for FlowShape {
    fn from(kind: InsnKind) -> Self {
        match kind {
            InsnKind::Normal => Self::Linear,
            InsnKind::Unknown => Self::Opaque,
            InsnKind::Call { .. } => Self::Call,
            InsnKind::Jump { .. } => Self::Jump,
            InsnKind::Branch { .. } => Self::Branch,
            InsnKind::Return => Self::Return,
        }
    }
}

/// Normalize one instruction.
pub fn normalize(arch: &dyn Arch, insn: &Insn) -> NormInsn {
    // Bytes the decoder cannot read carry their raw word as the operand.
    // Keeping that word in the operation name is what separates one
    // unreadable instruction from another: without it, a NEON `vmax` and a
    // NEON `vmin` would normalize alike and an edit between them would be
    // reported as no change.
    if insn.kind == InsnKind::Unknown {
        return NormInsn {
            operation: format_compact!("{}{}", insn.mnemonic, insn.operands),
            operands: Operands::new(),
            flow: FlowShape::Opaque,
            constants: Constants::new(),
        };
    }

    let fields = insn.operands.split(',');
    NormInsn {
        operation: arch.normalize_operation(&insn.mnemonic),
        operands: fields.clone().filter_map(|field| shape_of(arch, field)).collect(),
        flow: insn.kind.into(),
        constants: fields.filter_map(|field| arch.constant_value(field)).collect(),
    }
}

/// Normalize a function body, dropping the instructions that only manage the
/// stack frame or satisfy the ABI.
///
/// Frame work is the largest single difference between builds: an unoptimized
/// build spills every value to the stack, and an optimized one keeps them in
/// registers. Removing that traffic raised same-function similarity from 0.13
/// to 0.31 on the test corpus, and left unrelated functions unchanged at 0.21,
/// so it removes noise rather than signal.
///
/// Two kinds of bookkeeping come out. Most is recognizable one instruction at
/// a time, which [`Arch::is_frame_management`] answers for. The rest has a
/// shape only a sequence shows: the MIPS PIC preamble is two ordinary
/// instructions that are scaffolding *together* and real work apart, so
/// [`Arch::idiom_length`] is asked about each remaining position and the whole
/// run it reports is skipped.
pub fn normalize_body(arch: &dyn Arch, insns: &[Insn]) -> Vec<NormInsn> {
    normalize_body_in(arch, &[], insns, &AddressSpace::none())
}

/// Normalize a function body that lives in `space`.
///
/// As [`normalize_body`], and in addition the constants that are addresses
/// inside `space` are dropped, as branch targets are. They move whenever the
/// linker moves what they point at, so keeping them would report every
/// function that refers to moved data as changed. See
/// [`Arch::constant_kinds`].
pub fn normalize_body_in(
    arch: &dyn Arch,
    code: &[u8],
    insns: &[Insn],
    space: &AddressSpace,
) -> Vec<NormInsn> {
    let kinds = arch.constant_kinds(code, insns, space);
    let lifted = lift_all(arch, code, insns);
    let guards = find_guards(&lifted);
    let is_address = |at: usize| {
        matches!(kinds.get(at), Some(ConstantKind::Address | ConstantKind::StoredAddress))
    };
    let mut out = Vec::with_capacity(insns.len());
    let mut index = 0;

    while index < insns.len() {
        // A multi-instruction idiom is tested first: its words can each look
        // like work on their own, so judging them singly would keep them. The
        // remaining length bounds the answer, so a decoder that overstates one
        // drops the rest of the body rather than reading past it.
        let idiom = arch.idiom_length(&insns[index..]).min(insns.len() - index);
        if idiom > 0 {
            index += idiom;
            continue;
        }

        // A guard reads as two: the test, where the compare is, and a plain
        // branch. `cbz` thus reads as `cmp` with `b.eq` does, and a guard
        // weighs as much in a score as the two instructions it most often is.
        if let Some(found) =
            guards.iter().find(|found| found.compare.unwrap_or(found.branch) == index)
        {
            let address = [found.compare, Some(found.branch)].into_iter().flatten().any(is_address);
            let guard = found.guard.canonical();
            out.push(normalize_test(&Test::of_guard(guard), address));
            if found.compare.is_none() {
                out.push(guard_branch(guard.cond));
            }
            index += 1;
            continue;
        }
        if let Some(found) =
            guards.iter().find(|found| found.compare.is_some() && found.branch == index)
        {
            out.push(guard_branch(found.guard.canonical().cond));
            index += 1;
            continue;
        }
        // A compare that no branch reads, as before a conditional move,
        // reads as the test of a guard does, so the two still match.
        if let Some(Some(Lifted { test: Some(il::Test::Compare { comparison, .. }), .. })) =
            lifted.get(index)
        {
            out.push(normalize_test(&Test::of_comparison(*comparison), is_address(index)));
            index += 1;
            continue;
        }

        match kinds.get(index) {
            // A stored address is data, not an instruction: comparing what it
            // happens to decode as would report every move of its target.
            Some(ConstantKind::StoredAddress) => {}
            _ if arch.is_frame_management(&insns[index]) => {}
            // A `nop` does nothing, and a compiler puts one where alignment
            // asks, as before a pool of doubles.
            _ if arch.is_padding(&insns[index]) => {}
            // The address moves, so its size says nothing either: an A64
            // offset in a page went from 0xf8 to 0x108 when data before it
            // grew, and crossed from one size to the next.
            Some(ConstantKind::Address) => {
                let mut normalized = normalize(arch, &insns[index]);
                normalized.constants.clear();
                for shape in &mut normalized.operands {
                    if matches!(shape, OperandShape::Immediate(_)) {
                        *shape = OperandShape::Target;
                    }
                }
                out.push(named_by_op(normalized, lifted.get(index)));
            }
            Some(ConstantKind::Value) | None => {
                out.push(named_by_op(normalize(arch, &insns[index]), lifted.get(index)));
            }
        }
        index += 1;
    }

    out
}

/// The distinct constants a function uses.
///
/// A constant comes from the source, not from the compiler, so it survives a
/// change of optimization level that rewrites everything around it. Measured
/// on the test corpus, the set is **identical** across `-O1`, `-O2` and `-Os`
/// for every function the compiler did not vectorize: `mul_by_constant` keeps
/// `{37}`, `classify` keeps `{2, 100}`, `switch_dense` keeps `{2, 6, 10}`.
///
/// # Do not match on this
///
/// This is for **reporting**, not for pairing functions. Matching on it was
/// tried and measured, and it is worse than the instruction comparison it
/// would have joined:
///
/// * **False pairs at 1.00.** `mul_by_constant` and `call_chain` both reduce
///   to `{37}`, because the compiler inlined the first into the second. A
///   stage that paired on equal sets would confidently pair the wrong two
///   functions.
/// * **Half the true pairs missed.** Four of eight fixtures score below the
///   match threshold: `add` and `sum_to` hold no distinctive constants at all,
///   and `array_max` and `factorial` are vectorized.
/// * **Worst where it was wanted.** For the case it was meant to rescue — a
///   reference build against a differently optimized one — the true pair
///   scores 0.40 while a decoy scores 1.00, because four of five functions
///   there share the same uninformative set.
///
/// Vectorizing is what breaks it. At `-O2` the compiler rewrites `array_max`
/// with NEON and adds vector widths, alignment masks and unrolled offsets,
/// taking the set from four values to ten. `yaxpeax-arm` 0.4 cannot decode
/// NEON either, so those instructions contribute no constants at all. An empty
/// set therefore does not mean "the source used no constants".
pub fn constant_signature(body: &[NormInsn]) -> BTreeSet<u64> {
    // Values so common that they name no function in particular. Measured
    // across the corpus: `1` appears in five of eight functions and `0` in
    // four, while nothing else appears in more than two. Keep this list at
    // the values the measurement justifies, because every entry here is
    // signal thrown away.
    const TOO_COMMON: [u64; 2] = [0, 1];

    body.iter()
        .flat_map(|insn| insn.constants.iter().copied())
        .filter(|value| !TOO_COMMON.contains(value))
        .collect()
}

/// Classify one operand from its printed form.
///
/// The architecture answers what each form means; the ordering of the
/// questions is the same whatever answers them, because a memory reference
/// must be recognized before the constant inside it, and a frame slot before
/// a plain memory reference.
fn shape_of(arch: &dyn Arch, operand: &str) -> Option<OperandShape> {
    let operand = operand.trim();
    if operand.is_empty() {
        return None;
    }

    if arch.is_register_list(operand) {
        return Some(OperandShape::RegisterList);
    }

    // Memory references print inside brackets.
    if operand.contains('[') || operand.contains(']') {
        return Some(if arch.mentions_stack_slot(operand) {
            OperandShape::StackSlot
        } else {
            OperandShape::Memory
        });
    }

    if is_branch_target(operand) {
        return Some(OperandShape::Target);
    }

    if let Some(value) = arch.constant_value(operand) {
        return Some(OperandShape::Immediate(Magnitude::of(value)));
    }

    Some(if arch.is_stack_register(operand) {
        OperandShape::StackPointer
    } else if arch.is_register(operand) {
        OperandShape::Register
    } else {
        OperandShape::Other
    })
}

/// `normalized`, named by the operation its lifted form computes, where the
/// lifter names one. `add`, `adds` and `addu` then compare equal, and so do
/// `ldr` and `lw` of one width.
fn named_by_op(mut normalized: NormInsn, lifted: Option<&Option<Lifted>>) -> NormInsn {
    let Some(Some(lifted)) = lifted else { return normalized };
    if lifted.op == il::Op::Other || normalized.flow == FlowShape::Opaque {
        return normalized;
    }
    let width = lifted.memory.and_then(|access| access.width);
    normalized.operation = match (lifted.op, width) {
        (il::Op::Load | il::Op::Store | il::Op::Atomic, Some(width)) => {
            format_compact!("{}.{}", lifted.op.name(), width.bits())
        }
        (op, _) => op.name().into(),
    };
    normalized
}

/// Lift each instruction of `insns`, which `code` holds from its first
/// byte. Without the code, nothing is lifted.
fn lift_all(arch: &dyn Arch, code: &[u8], insns: &[Insn]) -> Vec<Option<Lifted>> {
    let Some(first) = insns.first() else { return Vec::new() };
    insns
        .iter()
        .map(|insn| {
            let offset = usize::try_from(insn.address.checked_sub(first.address)?).ok()?;
            let word = code.get(offset..offset.checked_add(insn.bytes_len)?)?;
            arch.lift(insn, word)
        })
        .collect()
}

/// The branch of a guard, with its condition either way: a compiler can
/// branch on the opposite condition and swap the code after it.
fn guard_branch(cond: Cond) -> NormInsn {
    let operation = match cond.either_way() {
        Cond::Equal => "b.eq",
        Cond::UnsignedGreaterOrEqual => "b.hs",
        Cond::Negative => "b.mi",
        Cond::Overflow => "b.vs",
        Cond::UnsignedGreater => "b.hi",
        Cond::SignedGreaterOrEqual => "b.ge",
        Cond::SignedGreater => "b.gt",
        Cond::BitsClear => "b.bits",
        _ => "b",
    };
    NormInsn {
        operation: operation.into(),
        operands: [OperandShape::Target].into_iter().collect(),
        flow: FlowShape::Branch,
        constants: Constants::new(),
    }
}

/// What a compare computes, named as the ARM compares are, whatever the
/// architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Test {
    operation: &'static str,
    left: Value,
    right: Value,
}

impl Test {
    fn of_comparison(comparison: Comparison) -> Self {
        match comparison {
            Comparison::Subtract { left, right } => Self { operation: "cmp", left, right },
            Comparison::And { left, right } => Self { operation: "tst", left, right },
            Comparison::Add { left, right } => Self { operation: "cmn", left, right },
        }
    }

    /// The test of a guard. Its condition is not kept: a compare that no
    /// branch reads has none, and a compiler can branch on the opposite
    /// condition and swap the code after it.
    fn of_guard(guard: Guard) -> Self {
        let operation = match guard.cond {
            Cond::BitsClear | Cond::BitsSet => "tst",
            _ => "cmp",
        };
        Self { operation, left: guard.left, right: guard.right }
    }
}

/// The test of a guard, or a lone compare, whatever the spelling, so that
/// `cbnz x8` and `cmp x8, #0` with `b.ne` compare equal.
///
/// The constant compared with stays, to report a changed bound. Where it
/// is an address, it moves with unrelated edits, so it is a target, as in
/// [`normalize_body_in`].
fn normalize_test(test: &Test, address: bool) -> NormInsn {
    let shape = |value: Value| match value {
        Value::Reg(Reg::Stack) => OperandShape::StackPointer,
        Value::Reg(_) => OperandShape::Register,
        Value::Const(_) if address => OperandShape::Target,
        Value::Const(constant) => OperandShape::Immediate(Magnitude::of(constant)),
        Value::Other => OperandShape::Other,
    };
    let constants = [test.left, test.right]
        .into_iter()
        .filter_map(|value| match value {
            Value::Const(constant) if !address => Some(constant),
            _ => None,
        })
        .collect();
    NormInsn {
        operation: test.operation.into(),
        operands: [shape(test.left), shape(test.right)].into_iter().collect(),
        flow: FlowShape::Linear,
        constants,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::arm32::Arm32;

    fn insn(mnemonic: &str, operands: &str, kind: InsnKind) -> Insn {
        Insn {
            address: 0,
            bytes_len: 4,
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            kind,
        }
    }

    #[test]
    fn register_choice_does_not_change_the_result() {
        let first = normalize(&Arm32, &insn("add", "r0, r1, r2", InsnKind::Normal));
        let second = normalize(&Arm32, &insn("add", "r4, r5, r6", InsnKind::Normal));
        assert_eq!(first, second, "a compiler picks registers freely");
    }

    #[test]
    fn small_constants_group_together() {
        let first = normalize(&Arm32, &insn("add", "r0, r0, 0x1", InsnKind::Normal));
        let second = normalize(&Arm32, &insn("add", "r0, r0, 0x4", InsnKind::Normal));
        assert_eq!(first, second);
    }

    /// Bucketing must not merge every constant, or a changed mask would hide.
    #[test]
    fn wide_constants_stay_apart_from_small_ones() {
        let small = normalize(&Arm32, &insn("mov", "r0, 0x4", InsnKind::Normal));
        let large = normalize(&Arm32, &insn("mov", "r0, 0xdeadbeef", InsnKind::Normal));
        assert_ne!(small, large);

        let zero = normalize(&Arm32, &insn("mov", "r0, 0x0", InsnKind::Normal));
        assert_ne!(zero, small);
    }

    /// Equality must ignore constants so matching survives an edited value,
    /// and the values must still be there to report the edit.
    #[test]
    fn constants_stay_available_but_out_of_equality() {
        let original = normalize(&Arm32, &insn("mov", "r1, 0x25", InsnKind::Normal));
        let edited = normalize(&Arm32, &insn("mov", "r1, 0x29", InsnKind::Normal));

        assert_eq!(original, edited, "the same work with a different constant still matches");
        assert!(original.differs_in_detail(&edited), "the changed value must be visible");
        assert_eq!(original.constants.as_slice(), [0x25]);
        assert_eq!(edited.constants.as_slice(), [0x29]);
    }

    #[test]
    fn identical_instructions_do_not_differ_in_detail() {
        let first = normalize(&Arm32, &insn("mov", "r1, 0x25", InsnKind::Normal));
        let second = normalize(&Arm32, &insn("mov", "r2, 0x25", InsnKind::Normal));
        assert!(!first.differs_in_detail(&second));
    }

    /// `Hash` must agree with `PartialEq`, or lookups break.
    #[test]
    fn hash_ignores_constants_like_equality() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let hash_of = |insn: &NormInsn| {
            let mut hasher = DefaultHasher::new();
            insn.hash(&mut hasher);
            hasher.finish()
        };

        let original = normalize(&Arm32, &insn("mov", "r1, 0x25", InsnKind::Normal));
        let edited = normalize(&Arm32, &insn("mov", "r1, 0x29", InsnKind::Normal));
        assert_eq!(hash_of(&original), hash_of(&edited));
    }

    /// An offset into a frame moves with unrelated edits, so it is not a
    /// constant worth reporting.
    #[test]
    fn frame_offsets_are_not_recorded_as_constants() {
        let load = normalize(&Arm32, &insn("ldr", "r0, [sp, 0x4]", InsnKind::Normal));
        assert!(load.constants.is_empty());
    }

    #[test]
    fn branch_addresses_do_not_change_the_result() {
        let near = insn("b", "$+0x8", InsnKind::Jump { target: Some(0x100) });
        let far = insn("b", "$+0x400", InsnKind::Jump { target: Some(0x9000) });
        assert_eq!(
            normalize(&Arm32, &near),
            normalize(&Arm32, &far),
            "addresses move with unrelated edits"
        );
    }

    #[test]
    fn separates_stack_references_from_other_memory() {
        let spill = normalize(&Arm32, &insn("ldr", "r0, [sp, 0x4]", InsnKind::Normal));
        let load = normalize(&Arm32, &insn("ldr", "r0, [r1]", InsnKind::Normal));
        assert_ne!(spill, load, "a frame slot is not the same as a data load");
    }

    #[test]
    fn drops_frame_management() {
        let body = [
            insn("push", "{fp, lr}", InsnKind::Normal),
            insn("mov", "fp, sp", InsnKind::Normal),
            insn("sub", "sp, sp, 0xc", InsnKind::Normal),
            insn("str", "r0, [fp, -0x4]", InsnKind::Normal),
            insn("add", "r0, r0, r1", InsnKind::Normal),
            insn("bx", "lr", InsnKind::Return),
        ];
        let normalized = normalize_body(&Arm32, &body);

        assert_eq!(normalized.len(), 2, "only the real work must remain");
        assert_eq!(normalized[0].operation, "add");
        assert_eq!(normalized[1].flow, FlowShape::Return);
    }

    /// `pop {fp, pc}` both restores the frame and returns, so it must stay.
    #[test]
    fn keeps_a_pop_that_returns() {
        let body = [insn("pop", "{fp, pc}", InsnKind::Return)];
        assert_eq!(normalize_body(&Arm32, &body).len(), 1);
    }

    #[test]
    fn keeps_loads_that_are_not_spills() {
        let body = [insn("ldr", "r0, [r1, 0x8]", InsnKind::Normal)];
        assert_eq!(normalize_body(&Arm32, &body).len(), 1, "a data load is real work");
    }

    /// An architecture can name a run of instructions as one idiom, and the
    /// whole run comes out rather than the first word of it.
    ///
    /// This is what per-instruction filtering cannot do: the MIPS PIC preamble
    /// is two words that are scaffolding together and real work apart.
    #[test]
    fn drops_a_whole_idiom_rather_than_one_word_of_it() {
        use crate::arch::mips::Mips32;

        let mips = |mnemonic: &str, operands: &str| Insn {
            address: 0,
            bytes_len: 4,
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            kind: InsnKind::Normal,
        };

        let body = [
            mips("lui", "v0, 0x0"),
            mips("addiu", "v0, v0, 0x0"),
            mips("addu", "gp, v0, t9"),
            mips("addu", "v0, a0, a1"),
        ];
        let normalized = normalize_body(&Mips32::LITTLE, &body);

        // The pair goes as an idiom and the `addu` into `gp` as frame work,
        // leaving only the arithmetic.
        assert_eq!(normalized.len(), 1, "got {normalized:?}");
        assert_eq!(normalized[0].operation, "addu");
    }

    /// An idiom the architecture does not confirm stays whole.
    #[test]
    fn keeps_a_sequence_that_is_not_an_idiom() {
        use crate::arch::mips::Mips32;

        let mips = |mnemonic: &str, operands: &str| Insn {
            address: 0,
            bytes_len: 4,
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            kind: InsnKind::Normal,
        };

        // The same two opening words, but nothing joins the result to `t9`, so
        // this builds the address of a global rather than the global pointer.
        let body =
            [mips("lui", "at, 0x0"), mips("addiu", "at, at, 0x0"), mips("lw", "v0, 0x0(at)")];

        assert_eq!(
            normalize_body(&Mips32::LITTLE, &body).len(),
            3,
            "a real address load is work, not scaffolding"
        );
    }

    #[test]
    fn a_constant_signature_holds_the_values_a_function_uses() {
        let body = normalize_body(
            &Arm32,
            &[insn("mov", "r1, 0x25", InsnKind::Normal), insn("cmp", "r0, 0x64", InsnKind::Normal)],
        );
        assert_eq!(constant_signature(&body), BTreeSet::from([0x25, 0x64]));
    }

    /// Values in almost every function cannot identify one, so they go.
    #[test]
    fn a_constant_signature_drops_the_common_values() {
        let body = normalize_body(
            &Arm32,
            &[
                insn("mov", "r0, 0x0", InsnKind::Normal),
                insn("add", "r0, r0, 0x1", InsnKind::Normal),
                insn("cmp", "r0, 0x25", InsnKind::Normal),
            ],
        );
        assert_eq!(constant_signature(&body), BTreeSet::from([0x25]), "only 37 identifies this");
    }

    #[test]
    fn a_constant_signature_is_empty_without_constants() {
        let body = normalize_body(&Arm32, &[insn("bx", "lr", InsnKind::Return)]);
        assert!(constant_signature(&body).is_empty());
    }

    /// The same value used twice is one entry, so the set does not depend on
    /// how many times the compiler happened to materialize it.
    #[test]
    fn a_constant_signature_counts_each_value_once() {
        let body = normalize_body(
            &Arm32,
            &[insn("mov", "r0, 0x25", InsnKind::Normal), insn("mov", "r1, 0x25", InsnKind::Normal)],
        );
        assert_eq!(constant_signature(&body), BTreeSet::from([0x25]));
    }

    /// Frame offsets move with unrelated edits, so they are not part of the
    /// signature. This follows from `constant_value`, and is checked here so
    /// a change there cannot quietly widen the signature.
    #[test]
    fn a_constant_signature_ignores_frame_offsets() {
        let body = normalize_body(&Arm32, &[insn("ldr", "r0, [r1, 0x25]", InsnKind::Normal)]);
        assert!(constant_signature(&body).is_empty());
    }

    /// Two different functions can share a constant set, which is why this
    /// must not be used to pair them.
    ///
    /// Measured on the corpus: inlining `mul_by_constant` into `call_chain`
    /// leaves both holding `{37}` and nothing else. The signature cannot tell
    /// them apart, so a matching stage built on it would pair the wrong two.
    #[test]
    fn different_functions_can_share_a_constant_signature() {
        let caller = normalize_body(
            &Arm32,
            &[
                insn("mov", "r1, 0x25", InsnKind::Normal),
                insn("mul", "r0, r0, r1", InsnKind::Normal),
                insn("add", "r0, r0, 0x1", InsnKind::Normal),
                insn("bx", "lr", InsnKind::Return),
            ],
        );
        let callee = normalize_body(
            &Arm32,
            &[
                insn("mov", "r1, 0x25", InsnKind::Normal),
                insn("mul", "r0, r0, r1", InsnKind::Normal),
                insn("bx", "lr", InsnKind::Return),
            ],
        );

        assert_eq!(
            constant_signature(&caller),
            constant_signature(&callee),
            "one inlined into the other leaves the same constants"
        );
        assert_ne!(caller, callee, "the instructions still tell them apart");
    }

    /// A function whose constants are all common has no signature at all.
    ///
    /// Most code that copies or parses is in this position, so an empty set is
    /// the normal case rather than an unusual one.
    #[test]
    fn a_function_of_common_constants_has_no_signature() {
        let body = normalize_body(
            &Arm32,
            &[
                insn("cmp", "r0, 0x0", InsnKind::Normal),
                insn("add", "r0, r0, 0x1", InsnKind::Normal),
                insn("bx", "lr", InsnKind::Return),
            ],
        );
        assert!(constant_signature(&body).is_empty());
    }

    #[test]
    fn opaque_bytes_stay_opaque() {
        let body = [insn("(unknown)", "0xf2600680", InsnKind::Unknown)];
        assert_eq!(normalize_body(&Arm32, &body)[0].flow, FlowShape::Opaque);
    }

    /// Two unreadable instructions must stay apart when their bytes differ.
    ///
    /// The compiler turns `vmax.s32` into `vmin.s32` when a comparison flips.
    /// Both are NEON, which the decoder cannot read. If they normalized alike
    /// the change would be reported as no change at all.
    #[test]
    fn different_opaque_words_do_not_normalize_alike() {
        let first = normalize(&Arm32, &insn("(unknown)", "0xf2600680", InsnKind::Unknown));
        let second = normalize(&Arm32, &insn("(unknown)", "0xf2200680", InsnKind::Unknown));
        assert_ne!(first, second, "an edit inside unreadable bytes must stay visible");
    }

    #[test]
    fn matching_opaque_words_normalize_alike() {
        let first = normalize(&Arm32, &insn("(unknown)", "0xf2600680", InsnKind::Unknown));
        let second = normalize(&Arm32, &insn("(unknown)", "0xf2600680", InsnKind::Unknown));
        assert_eq!(first, second);
    }

    #[test]
    fn handles_instructions_without_operands() {
        let normalized = normalize(&Arm32, &insn("nop", "", InsnKind::Normal));
        assert!(normalized.operands.is_empty());
    }
}
