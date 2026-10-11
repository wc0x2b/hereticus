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

use smallvec::SmallVec;

use crate::address::{AddressSpace, ConstantKind};
use crate::arch::{Arch, Insn, InsnKind};
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

/// The operation a normalized instruction does.
///
/// Two spellings of one operation get one value: `add`, `adds` and `addu`
/// are all [`il::Op::Add`], and `cbz x8` tests as `cmp x8, #0` does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Operation {
    /// What the lifter names, with the width of a memory access.
    Lifted { op: il::Op, width: Option<u8> },
    /// The test of a guard, or a lone compare.
    Test(TestKind),
    /// The branch of a guard, by its condition either way: a compiler can
    /// branch on the opposite condition and swap the code after it.
    GuardBranch(Cond),
    /// An instruction the lifter names no operation for, by a key of the
    /// operation its opcode does: see [`Arch::operation_name`].
    Decoded(u64),
    /// Bytes no decoder reads, by the bytes. Without them, a NEON `vmax`
    /// and a NEON `vmin` would normalize alike, and an edit between them
    /// would read as no change.
    Unreadable(u64),
}

/// What a test computes, as the ARM compares name it on every
/// architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TestKind {
    /// `left - right`, as `cmp` computes.
    Compare,
    /// `left & right`, as `tst` computes.
    BitTest,
    /// `left + right`, as `cmn` computes.
    CompareNegative,
}

/// An instruction with the build-specific detail removed.
///
/// Equality ignores [`NormInsn::constants`], so two instructions that do the
/// same work with different constants compare equal. That is what makes
/// matching survive recompilation. Reporting *what changed* needs the exact
/// values, so they are carried here and compared by
/// [`NormInsn::differs_in_detail`].
#[derive(Clone, Debug, Eq)]
pub struct NormInsn {
    /// The operation.
    pub operation: Operation,
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
    /// A floating point or vector register. Kept apart from a general
    /// register, so a float compare or load reads apart from an integer
    /// one: measured over the cross builds, this paired 15 fewer wrong and
    /// 5 fewer right.
    VectorRegister,
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
    let lifted = arch.lift(insn).map(|lifted| frame_addressed(arch, lifted.canonical()));
    named_by_op(normalize_lifted(arch, insn, lifted.as_ref()), lifted.as_ref())
}

/// The bytes of `word` as one number, for [`Operation::Unreadable`]. An
/// instruction holds eight bytes at most.
fn bytes_key(word: &[u8]) -> u64 {
    word.iter().take(8).fold(0, |key, &byte| key << 8 | u64::from(byte))
}

/// A 64-bit FNV-1a hash of `text`, as a key that does not change from run
/// to run.
fn text_key(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
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
///
/// See RESEARCH.md, A2.
pub fn normalize_body_in(
    arch: &dyn Arch,
    code: &[u8],
    insns: &[Insn],
    space: &AddressSpace,
) -> Vec<NormInsn> {
    let kinds = arch.constant_kinds(code, insns, space);
    let lifted = lift_all(arch, insns);
    let guards = find_guards(&lifted);
    // The first guard that starts at each index, and the first whose branch
    // after a compare sits there. A search of every guard at each index
    // took a third of a comparison of a MIPS kernel, whose functions are
    // long.
    let mut starting: Vec<Option<usize>> = vec![None; insns.len()];
    let mut branching: Vec<Option<usize>> = vec![None; insns.len()];
    for (at, found) in guards.iter().enumerate() {
        if let Some(slot) = starting.get_mut(found.compare.unwrap_or(found.branch)) {
            slot.get_or_insert(at);
        }
        if found.compare.is_some()
            && let Some(slot) = branching.get_mut(found.branch)
        {
            slot.get_or_insert(at);
        }
    }
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
        if let Some(found) = starting[index].map(|at| &guards[at]) {
            let address = [found.compare, Some(found.branch)].into_iter().flatten().any(is_address);
            let guard = found.guard.canonical();
            out.push(normalize_test(&Test::of_guard(guard), address));
            if found.compare.is_none() {
                out.push(guard_branch(guard.cond));
            }
            index += 1;
            continue;
        }
        if let Some(found) = branching[index].map(|at| &guards[at]) {
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
                let lifted = lifted.get(index).and_then(Option::as_ref);
                let mut normalized = normalize_lifted(arch, &insns[index], lifted);
                normalized.constants.clear();
                for shape in &mut normalized.operands {
                    if matches!(shape, OperandShape::Immediate(_)) {
                        *shape = OperandShape::Target;
                    }
                }
                out.push(named_by_op(normalized, lifted));
            }
            Some(ConstantKind::Value) | None => {
                let lifted = lifted.get(index).and_then(Option::as_ref);
                let normalized = normalize_lifted(arch, &insns[index], lifted);
                out.push(named_by_op(normalized, lifted));
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
/// # Do not pair on this alone
///
/// The matcher uses it only to choose between candidates the instructions
/// already found, and as one edge of context: see `CONSTANT_WEIGHT` and
/// `LARGEST_PLAIN_CONSTANT` in `matching.rs`. Pairing on it alone was
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

/// Normalize one instruction, with its operands read from `lifted`. An
/// instruction the lifter does not read has none.
fn normalize_lifted(arch: &dyn Arch, insn: &Insn, lifted: Option<&Lifted>) -> NormInsn {
    if insn.kind == InsnKind::Unknown {
        return NormInsn {
            operation: Operation::Unreadable(bytes_key(insn.bytes())),
            operands: Operands::new(),
            flow: FlowShape::Opaque,
            constants: Constants::new(),
        };
    }
    let operands = lifted.map_or(&[][..], |lifted| lifted.operands.as_slice());
    // [`named_by_op`] names what the lifter names; only the rest needs the
    // name of its opcode.
    let operation = match lifted {
        Some(lifted) if lifted.op != il::Op::Other => {
            Operation::Lifted { op: lifted.op, width: None }
        }
        _ => Operation::Decoded(text_key(&arch.operation_name(insn))),
    };
    NormInsn {
        operation,
        operands: operands.iter().flat_map(|operand| lifted_shapes(arch, *operand)).collect(),
        flow: insn.kind.into(),
        constants: operands
            .iter()
            .filter_map(|operand| match operand {
                il::Operand::Const(value) => Some(*value),
                _ => None,
            })
            .collect(),
    }
}

/// The shapes of a lifted operand.
///
/// A memory reference outside the frame also gives the size of its offset:
/// a field at 4 and one at 0x400 are different work. Measured over the
/// cross builds, this paired 62 fewer functions wrong. A frame offset moves
/// with every spill, so it gives none.
fn lifted_shapes(arch: &dyn Arch, operand: il::Operand) -> impl Iterator<Item = OperandShape> {
    let in_frame = |reg: Option<Reg>| reg.is_some_and(|reg| arch.is_frame_register(reg));
    let (shape, offset) = match operand {
        il::Operand::Reg(Reg::ProgramCounter) => (OperandShape::Other, None),
        il::Operand::Reg(reg) | il::Operand::Shifted { reg, .. } if in_frame(Some(reg)) => {
            (OperandShape::StackPointer, None)
        }
        il::Operand::Reg(Reg::Vector(_)) | il::Operand::Shifted { reg: Reg::Vector(_), .. } => {
            (OperandShape::VectorRegister, None)
        }
        il::Operand::Reg(_) | il::Operand::Shifted { .. } | il::Operand::Zero => {
            (OperandShape::Register, None)
        }
        il::Operand::Const(value) => (OperandShape::Immediate(Magnitude::of(value)), None),
        il::Operand::Memory { base, .. } if in_frame(base) => (OperandShape::StackSlot, None),
        il::Operand::Memory { offset, .. } => (
            OperandShape::Memory,
            offset.map(|offset| OperandShape::Immediate(Magnitude::of(offset.unsigned_abs()))),
        ),
        il::Operand::Target => (OperandShape::Target, None),
        il::Operand::RegisterList(_) => (OperandShape::RegisterList, None),
        il::Operand::Other => (OperandShape::Other, None),
    };
    core::iter::once(shape).chain(offset)
}

/// `normalized`, named by the operation its lifted form computes, where the
/// lifter names one. `add`, `adds` and `addu` then compare equal, and so do
/// `ldr` and `lw` of one width.
fn named_by_op(mut normalized: NormInsn, lifted: Option<&Lifted>) -> NormInsn {
    let Some(lifted) = lifted else { return normalized };
    if lifted.op == il::Op::Other || normalized.flow == FlowShape::Opaque {
        return normalized;
    }
    let width = lifted.memory.and_then(|access| access.width);
    normalized.operation = match (lifted.op, width) {
        // A compare and a branch no guard took read as a guard's do: A32
        // predicates a chain of compares, as `cmp` then `cmpne` then `bne`,
        // where another build branches after each.
        (il::Op::Compare, _) => Operation::Test(TestKind::Compare),
        (il::Op::Branch, _) => match lifted.test {
            Some(il::Test::OnFlags(cond)) => guard_branch(cond).operation,
            _ => Operation::Lifted { op: lifted.op, width: None },
        },
        (op @ (il::Op::Load | il::Op::Store | il::Op::Atomic), Some(width)) => {
            Operation::Lifted { op, width: Some(width.bits() as u8) }
        }
        (op, _) => Operation::Lifted { op, width: None },
    };
    normalized
}

/// The data-flow features of a body: see [`il::flow_features`]. Frame work
/// and idioms stay in, as a value can pass through them.
pub fn flow_features(arch: &dyn Arch, insns: &[Insn], depth: usize) -> Vec<u64> {
    il::flow_features(&lift_all(arch, insns), depth)
}

/// Lift each instruction of `insns`.
fn lift_all(arch: &dyn Arch, insns: &[Insn]) -> Vec<Option<Lifted>> {
    insns
        .iter()
        .map(|insn| arch.lift(insn).map(|lifted| frame_addressed(arch, lifted.canonical())))
        .collect()
}

/// `lifted`, with an add or subtract of a constant to the stack or frame
/// pointer read as the address of a frame slot. Compilers reach one slot
/// from either register: clang takes `sub x1, x29, #0x4` where GCC takes
/// `add x1, sp, #0x1c`.
fn frame_addressed(arch: &dyn Arch, mut lifted: Lifted) -> Lifted {
    let (il::Op::Add | il::Op::Subtract) = lifted.op else { return lifted };
    let [dest, il::Operand::Reg(base), il::Operand::Const(offset)] = lifted.operands.as_slice()
    else {
        return lifted;
    };
    if !arch.is_frame_register(*base) {
        return lifted;
    }
    let offset = *offset as i64;
    let offset = if lifted.op == il::Op::Subtract { offset.wrapping_neg() } else { offset };
    lifted.operands = [*dest, il::Operand::memory(Some(*base), Some(offset))].into_iter().collect();
    lifted.op = il::Op::Address;
    lifted
}

/// The branch of a guard, with its condition either way: a compiler can
/// branch on the opposite condition and swap the code after it.
fn guard_branch(cond: Cond) -> NormInsn {
    let operation = Operation::GuardBranch(cond.either_way());
    NormInsn {
        operation,
        operands: [OperandShape::Target].into_iter().collect(),
        flow: FlowShape::Branch,
        constants: Constants::new(),
    }
}

/// What a compare computes, named as the ARM compares are, whatever the
/// architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Test {
    operation: TestKind,
    left: Value,
    right: Value,
}

impl Test {
    fn of_comparison(comparison: Comparison) -> Self {
        match comparison {
            Comparison::Subtract { left, right } => {
                Self { operation: TestKind::Compare, left, right }
            }
            Comparison::And { left, right } => Self { operation: TestKind::BitTest, left, right },
            Comparison::Add { left, right } => {
                Self { operation: TestKind::CompareNegative, left, right }
            }
        }
    }

    /// The test of a guard. Its condition is not kept: a compare that no
    /// branch reads has none, and a compiler can branch on the opposite
    /// condition and swap the code after it.
    fn of_guard(guard: Guard) -> Self {
        let operation = match guard.cond {
            Cond::BitsClear | Cond::BitsSet => TestKind::BitTest,
            _ => TestKind::Compare,
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
        Value::Reg(Reg::Vector(_)) => OperandShape::VectorRegister,
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
        operation: Operation::Test(test.operation),
        operands: [shape(test.left), shape(test.right)].into_iter().collect(),
        flow: FlowShape::Linear,
        constants,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::aarch64::Aarch64;
    use crate::arch::arm32::Arm32;

    /// One A32 word, as the decoder reads it.
    fn a32(word: u32) -> Insn {
        Arm32.decode(&word.to_le_bytes(), 0, 0).expect("the word must decode")
    }

    /// One A32 word, normalized.
    fn word(word: u32) -> NormInsn {
        normalize(&Arm32, &a32(word))
    }

    /// A body of A32 words, normalized.
    fn body(words: &[u32]) -> Vec<NormInsn> {
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0);
        normalize_body(&Arm32, &insns)
    }

    const ADD: Operation = Operation::Lifted { op: il::Op::Add, width: None };

    #[test]
    fn register_choice_does_not_change_the_result() {
        // add r0, r1, r2 and add r4, r5, r6.
        assert_eq!(word(0xe081_0002), word(0xe085_4006), "a compiler picks registers freely");
    }

    #[test]
    fn small_constants_group_together() {
        // add r0, r0, #1 and add r0, r0, #4.
        assert_eq!(word(0xe280_0001), word(0xe280_0004));
    }

    /// Bucketing must not merge every constant, or a changed mask would hide.
    #[test]
    fn wide_constants_stay_apart_from_small_ones() {
        // mov r0, #4; mov r0, #0x400; mov r0, #0.
        let (small, large, zero) = (word(0xe3a0_0004), word(0xe3a0_0b01), word(0xe3a0_0000));
        assert_ne!(small, large);
        assert_ne!(zero, small);
    }

    /// Equality must ignore constants so matching survives an edited value,
    /// and the values must still be there to report the edit.
    #[test]
    fn constants_stay_available_but_out_of_equality() {
        // mov r1, #0x25 and mov r1, #0x29.
        let (original, edited) = (word(0xe3a0_1025), word(0xe3a0_1029));
        assert_eq!(original, edited, "the same work with a different constant still matches");
        assert!(original.differs_in_detail(&edited), "the changed value must be visible");
        assert_eq!(original.constants.as_slice(), [0x25]);
        assert_eq!(edited.constants.as_slice(), [0x29]);
    }

    #[test]
    fn identical_instructions_do_not_differ_in_detail() {
        // mov r1, #0x25 and mov r2, #0x25.
        assert!(!word(0xe3a0_1025).differs_in_detail(&word(0xe3a0_2025)));
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
        assert_eq!(hash_of(&word(0xe3a0_1025)), hash_of(&word(0xe3a0_1029)));
    }

    /// An offset into a frame moves with unrelated edits, so it is not a
    /// constant worth reporting.
    #[test]
    fn frame_offsets_are_not_recorded_as_constants() {
        // ldr r0, [sp, #4].
        assert!(word(0xe59d_0004).constants.is_empty());
    }

    #[test]
    fn branch_addresses_do_not_change_the_result() {
        // b to the next word but one, and b far ahead.
        assert_eq!(word(0xea00_0000), word(0xea00_00ff), "addresses move with unrelated edits");
    }

    #[test]
    fn separates_stack_references_from_other_memory() {
        // ldr r0, [sp, #4] and ldr r0, [r1].
        assert_ne!(word(0xe59d_0004), word(0xe591_0000), "a frame slot is not a data load");
    }

    #[test]
    fn drops_frame_management() {
        let normalized = body(&[
            0xe92d_4800, // push {fp, lr}
            0xe1a0_b00d, // mov fp, sp
            0xe24d_d00c, // sub sp, sp, 0xc
            0xe50b_0004, // str r0, [fp, -0x4]
            0xe080_0001, // add r0, r0, r1
            0xe12f_ff1e, // bx lr
        ]);
        assert_eq!(normalized.len(), 2, "only the real work must remain");
        assert_eq!(normalized[0].operation, ADD);
        assert_eq!(normalized[1].flow, FlowShape::Return);
    }

    /// `pop {fp, pc}` both restores the frame and returns, so it must stay.
    #[test]
    fn keeps_a_pop_that_returns() {
        assert_eq!(a32(0xe8bd_8800).kind, InsnKind::Return);
        assert_eq!(body(&[0xe8bd_8800]).len(), 1);
    }

    #[test]
    fn keeps_loads_that_are_not_spills() {
        // ldr r0, [r1, 0x8]
        assert_eq!(body(&[0xe591_0008]).len(), 1, "a data load is real work");
    }

    /// The body of MIPS32 little-endian `words`, decoded and normalized.
    fn mips_body(words: &[u32]) -> (Vec<String>, Vec<NormInsn>) {
        use crate::arch::mips::Mips32;
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = crate::arch::decode_all(&Mips32::LITTLE, &code, 0);
        let text = insns.iter().map(ToString::to_string).collect();
        (text, normalize_body(&Mips32::LITTLE, &insns))
    }

    /// An architecture can name a run of instructions as one idiom, and the
    /// whole run comes out rather than the first word of it.
    ///
    /// This is what per-instruction filtering cannot do: the MIPS PIC preamble
    /// is two words that are scaffolding together and real work apart.
    #[test]
    fn drops_a_whole_idiom_rather_than_one_word_of_it() {
        let (text, normalized) = mips_body(&[
            0x3c02_0000, // lui v0, 0x0
            0x2442_0000, // addiu v0, v0, 0x0
            0x0059_e021, // addu gp, v0, t9
            0x0085_1021, // addu v0, a0, a1
        ]);
        assert_eq!(
            text,
            ["lui v0, 0x0", "addiu v0, v0, 0x0", "addu gp, v0, t9", "addu v0, a0, a1"]
        );
        // The pair goes as an idiom and the `addu` into `gp` as frame work,
        // leaving only the arithmetic.
        assert_eq!(normalized.len(), 1, "got {normalized:?}");
        assert_eq!(normalized[0].operation, ADD);
    }

    /// An idiom the architecture does not confirm stays whole.
    #[test]
    fn keeps_a_sequence_that_is_not_an_idiom() {
        // The same two opening words, but nothing joins the result to `t9`, so
        // this builds the address of a global rather than the global pointer.
        let (text, normalized) = mips_body(&[
            0x3c01_0000, // lui at, 0x0
            0x2421_0000, // addiu at, at, 0x0
            0x8c22_0000, // lw v0, 0x0(at)
        ]);
        assert_eq!(text, ["lui at, 0x0", "addiu at, at, 0x0", "lw v0, 0x0(at)"]);
        assert_eq!(normalized.len(), 3, "a real address load is work, not scaffolding");
    }

    #[test]
    fn a_constant_signature_holds_the_values_a_function_uses() {
        // mov r1, #0x25; cmp r0, #0x64.
        let normalized = body(&[0xe3a0_1025, 0xe350_0064]);
        assert_eq!(constant_signature(&normalized), BTreeSet::from([0x25, 0x64]));
    }

    /// Values in almost every function cannot identify one, so they go.
    #[test]
    fn a_constant_signature_drops_the_common_values() {
        // mov r0, #0; add r0, r0, #1; cmp r0, #0x25.
        let normalized = body(&[0xe3a0_0000, 0xe280_0001, 0xe350_0025]);
        assert_eq!(constant_signature(&normalized), BTreeSet::from([0x25]), "only 37 tells");
    }

    #[test]
    fn a_constant_signature_is_empty_without_constants() {
        // bx lr.
        assert!(constant_signature(&body(&[0xe12f_ff1e])).is_empty());
    }

    /// The same value used twice is one entry, so the set does not depend on
    /// how many times the compiler happened to materialize it.
    #[test]
    fn a_constant_signature_counts_each_value_once() {
        // mov r0, #0x25; mov r1, #0x25.
        let normalized = body(&[0xe3a0_0025, 0xe3a0_1025]);
        assert_eq!(constant_signature(&normalized), BTreeSet::from([0x25]));
    }

    /// The offset of a memory reference is no constant of the signature.
    #[test]
    fn a_constant_signature_ignores_memory_offsets() {
        // ldr r0, [r1, #0x25].
        assert!(constant_signature(&body(&[0xe591_0025])).is_empty());
    }

    /// Two different functions can share a constant set, which is why this
    /// must not be used to pair them.
    ///
    /// Measured on the corpus: inlining `mul_by_constant` into `call_chain`
    /// leaves both holding `{37}` and nothing else. The signature cannot tell
    /// them apart, so a matching stage built on it would pair the wrong two.
    #[test]
    fn different_functions_can_share_a_constant_signature() {
        // mov r1, #0x25; mul r0, r0, r1; add r0, r0, #1; bx lr.
        let caller = body(&[0xe3a0_1025, 0xe000_0190, 0xe280_0001, 0xe12f_ff1e]);
        let callee = body(&[0xe3a0_1025, 0xe000_0190, 0xe12f_ff1e]);
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
        // cmp r0, #0; add r0, r0, #1; bx lr.
        assert!(constant_signature(&body(&[0xe350_0000, 0xe280_0001, 0xe12f_ff1e])).is_empty());
    }

    #[test]
    fn opaque_bytes_stay_opaque() {
        assert_eq!(body(&[0xf260_0680])[0].flow, FlowShape::Opaque);
    }

    /// Two unreadable instructions must stay apart when their bytes differ.
    ///
    /// The compiler turns `vmax.s32` into `vmin.s32` when a comparison flips.
    /// Both are NEON, which the decoder cannot read. If they normalized alike
    /// the change would be reported as no change at all.
    #[test]
    fn different_opaque_words_do_not_normalize_alike() {
        assert_ne!(word(0xf260_0680), word(0xf220_0680), "an edit there must stay visible");
    }

    #[test]
    fn matching_opaque_words_normalize_alike() {
        assert_eq!(word(0xf260_0680), word(0xf260_0680));
    }

    #[test]
    fn handles_instructions_without_operands() {
        // nop.
        assert!(word(0xe320_f000).operands.is_empty());
    }

    fn shapes(operand: il::Operand) -> Vec<OperandShape> {
        lifted_shapes(&Aarch64, operand).collect()
    }

    #[test]
    fn a_lifted_register_reads_as_its_kind() {
        use il::Operand::{Reg as R, Zero};
        assert_eq!(shapes(R(Reg::General(3))), [OperandShape::Register]);
        assert_eq!(shapes(Zero), [OperandShape::Register]);
        assert_eq!(shapes(R(Reg::Stack)), [OperandShape::StackPointer]);
        assert_eq!(shapes(R(Reg::General(29))), [OperandShape::StackPointer], "x29");
    }

    /// A frame slot moves with every spill, so its offset says nothing.
    #[test]
    fn a_frame_slot_gives_no_offset() {
        let slot = il::Operand::memory(Some(Reg::Stack), Some(0x400));
        assert_eq!(shapes(slot), [OperandShape::StackSlot]);
    }

    #[test]
    fn a_memory_reference_gives_the_size_of_its_offset() {
        let at = |offset| il::Operand::memory(Some(Reg::General(2)), offset);
        let sized = |magnitude| [OperandShape::Memory, OperandShape::Immediate(magnitude)];
        assert_eq!(shapes(at(Some(0))), sized(Magnitude::Zero));
        assert_eq!(shapes(at(Some(8))), sized(Magnitude::Small));
        assert_eq!(shapes(at(Some(-8))), sized(Magnitude::Small), "sized as its distance");
        assert_eq!(shapes(at(Some(0x400))), sized(Magnitude::Large));
        assert_eq!(shapes(at(Some(i64::MIN))), sized(Magnitude::Large));
        assert_eq!(shapes(at(None)), [OperandShape::Memory], "an offset in a register");
        let unnamed = il::Operand::memory(None, Some(8));
        assert_eq!(shapes(unnamed), sized(Magnitude::Small), "a literal pool load");
    }

    #[test]
    fn a_lifted_body_reads_its_operands_from_the_il() {
        // `ldr x1, [x2, #8]` and `ldr x1, [x2, #0x400]`: a near field and a
        // far one.
        let body = |word: u32| {
            let code = word.to_le_bytes();
            let (insns, _) = crate::arch::decode_all(&Aarch64, &code, 0x1000);
            normalize_body_in(&Aarch64, &code, &insns, &AddressSpace::none())
        };
        let (near, far) = (body(0xf940_0441), body(0xf942_0041));
        assert_ne!(near, far);
        assert_eq!(
            near[0].operands.as_slice(),
            [
                OperandShape::Register,
                OperandShape::Memory,
                OperandShape::Immediate(Magnitude::Small)
            ]
        );
        assert!(near[0].constants.is_empty(), "an offset is no constant");
    }

    fn body_of(arch: &dyn Arch, code: &[u8]) -> Vec<NormInsn> {
        let (insns, _) = crate::arch::decode_all(arch, code, 0x1000);
        normalize_body_in(arch, code, &insns, &AddressSpace::none())
    }

    /// A32 predicates a chain of compares, where another build branches
    /// after each. The compare and branch no guard takes read as a guard's.
    #[test]
    fn a_predicated_compare_reads_as_a_guard_does() {
        const CMP_R0_0: [u8; 4] = [0x00, 0x00, 0x50, 0xe3];
        const CMPNE_R1_0: [u8; 4] = [0x00, 0x00, 0x51, 0x13];
        const CMP_R1_0: [u8; 4] = [0x00, 0x00, 0x51, 0xe3];
        const BEQ: [u8; 4] = [0x02, 0x00, 0x00, 0x0a];
        let chained = body_of(&Arm32, &[CMP_R0_0, CMPNE_R1_0, BEQ].concat());
        let alone = body_of(&Arm32, &[CMP_R1_0, BEQ].concat());
        assert_eq!(chained[1..], alone[..], "cmpne and beq read as cmp and beq");
    }

    /// clang takes a local's address from the frame pointer, and GCC from
    /// the stack pointer.
    #[test]
    fn the_address_of_a_frame_slot_reads_alike_from_either_register() {
        // `sub x1, x29, #0x4` and `add x1, sp, #0x1c`
        let from_frame = body_of(&Aarch64, &0xd100_13a1_u32.to_le_bytes());
        let from_stack = body_of(&Aarch64, &0x9100_73e1_u32.to_le_bytes());
        assert_eq!(from_frame, from_stack);
        assert_eq!(from_frame[0].operation, Operation::Lifted { op: il::Op::Address, width: None });
        assert_eq!(
            from_frame[0].operands.as_slice(),
            [OperandShape::Register, OperandShape::StackSlot]
        );
        // `add x1, x2, #0x1c` is no frame slot.
        assert_eq!(body_of(&Aarch64, &0x9100_7041_u32.to_le_bytes())[0].operation, ADD);
    }

    #[test]
    fn flow_features_of_any_code_never_panic() {
        bolero::check!().with_type::<Vec<u32>>().for_each(|words| {
            let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            let (insns, _) = crate::arch::decode_all(&Aarch64, &code, 0x1000);
            for depth in 0..4 {
                let features = flow_features(&Aarch64, &insns, depth);
                assert!(features.len() <= insns.len());
                assert!(features.is_sorted());
            }
        });
    }

    #[test]
    fn a_vector_register_is_no_general_register() {
        use il::Operand::Reg as R;
        assert_eq!(shapes(R(Reg::Vector(1))), [OperandShape::VectorRegister]);
        assert_ne!(shapes(R(Reg::Vector(1))), shapes(R(Reg::General(1))));
    }
}
