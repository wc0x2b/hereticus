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

use crate::arch::{Insn, InsnKind};

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
    pub operation: String,
    /// Shape of each operand, in order.
    pub operands: Vec<OperandShape>,
    /// How the instruction moves control.
    pub flow: FlowShape,
    /// Exact constants, in the order they appear.
    ///
    /// Kept out of equality on purpose: a threshold that changes from 100 to
    /// 50 must still match the function it came from, and must still show up
    /// as a difference once matched.
    pub constants: Vec<u64>,
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
pub fn normalize(insn: &Insn) -> NormInsn {
    // Bytes the decoder cannot read carry their raw word as the operand.
    // Keeping that word in the operation name is what separates one
    // unreadable instruction from another: without it, a NEON `vmax` and a
    // NEON `vmin` would normalize alike and an edit between them would be
    // reported as no change.
    if insn.kind == InsnKind::Unknown {
        return NormInsn {
            operation: format!("{}{}", insn.mnemonic, insn.operands),
            operands: Vec::new(),
            flow: FlowShape::Opaque,
            constants: Vec::new(),
        };
    }

    let fields = insn.operands.split(',');
    NormInsn {
        operation: normalize_operation(&insn.mnemonic),
        operands: fields.clone().filter_map(shape_of).collect(),
        flow: insn.kind.into(),
        constants: fields.filter_map(constant_value).collect(),
    }
}

/// Normalize a function body, dropping the instructions that only manage the
/// stack frame.
///
/// Frame work is the largest single difference between builds: an unoptimized
/// build spills every value to the stack, and an optimized one keeps them in
/// registers. Removing that traffic raised same-function similarity from 0.13
/// to 0.31 on the test corpus, and left unrelated functions unchanged at 0.21,
/// so it removes noise rather than signal.
pub fn normalize_body<'a, I>(insns: I) -> Vec<NormInsn>
where
    I: IntoIterator<Item = &'a Insn>,
{
    insns.into_iter().filter(|insn| !is_frame_management(insn)).map(normalize).collect()
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

/// Report whether an instruction only maintains the stack frame.
///
/// Saving registers, moving the stack pointer and spilling to a frame slot are
/// all bookkeeping that the compiler adds or removes freely.
fn is_frame_management(insn: &Insn) -> bool {
    let operation = normalize_operation(&insn.mnemonic);
    let operands = insn.operands.as_str();

    match operation.as_str() {
        // Saving and restoring registers. A `pop` that loads the program
        // counter also returns, so it must stay.
        "push" => true,
        "pop" => insn.kind != InsnKind::Return,

        // Moving the stack pointer, or setting up the frame pointer.
        "sub" | "add" | "mov" => starts_with_stack_register(operands),

        // Spilling to and reloading from the frame.
        "ldr" | "str" | "ldm" | "stm" => mentions_stack_slot(operands),

        _ => false,
    }
}

/// Report whether the first operand is the stack or frame pointer.
fn starts_with_stack_register(operands: &str) -> bool {
    let first = operands.split(',').next().unwrap_or_default().trim();
    matches!(first, "sp" | "fp" | "r13" | "r11")
}

/// Report whether any operand reads or writes a frame slot.
fn mentions_stack_slot(operands: &str) -> bool {
    operands.contains("[sp") || operands.contains("[fp") || operands.contains("[r13")
}

/// Strip the flag-setting suffix and the condition from a mnemonic.
///
/// A compiler picks between `add` and `adds`, and between a branch and a
/// conditional move, for reasons that do not change what the code computes.
fn normalize_operation(mnemonic: &str) -> String {
    const CONDITIONS: [&str; 17] = [
        "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al",
        "lo", "hs",
    ];

    // Mnemonics that end in condition letters but carry no condition.
    const NOT_CONDITIONAL: [&str; 6] = ["b", "bl", "ble", "bls", "movs", "cmps"];

    let mnemonic = mnemonic.trim();
    if NOT_CONDITIONAL.contains(&mnemonic) {
        // `movs` and `cmps` still carry a flag-setting suffix to remove.
        return mnemonic.trim_end_matches('s').to_string();
    }

    let without_condition = CONDITIONS
        .iter()
        .find_map(|suffix| mnemonic.strip_suffix(suffix).filter(|stem| stem.len() >= 2))
        .unwrap_or(mnemonic);

    // Keep a trailing `s` that belongs to the name, as in `bics` versus `bic`.
    match without_condition.strip_suffix('s') {
        Some(stem) if stem.len() >= 2 => stem.to_string(),
        _ => without_condition.to_string(),
    }
}

/// Classify one operand from its printed form.
fn shape_of(operand: &str) -> Option<OperandShape> {
    let operand = operand.trim();
    if operand.is_empty() {
        return None;
    }

    // Register lists print as `{r4, lr}`. Splitting on commas breaks them
    // apart, so the fragments are recognized by their braces.
    if operand.starts_with('{') || operand.ends_with('}') {
        return Some(OperandShape::RegisterList);
    }

    // Memory references print inside brackets.
    if operand.contains('[') || operand.contains(']') {
        return Some(if mentions_stack_slot(operand) {
            OperandShape::StackSlot
        } else {
            OperandShape::Memory
        });
    }

    // Branch targets print as `$+0x24`.
    if operand.starts_with('$') {
        return Some(OperandShape::Target);
    }

    if let Some(value) = constant_value(operand) {
        return Some(OperandShape::Immediate(Magnitude::of(value)));
    }

    Some(match operand {
        "sp" | "fp" | "r13" | "r11" => OperandShape::StackPointer,
        _ if is_register(operand) => OperandShape::Register,
        _ => OperandShape::Other,
    })
}

/// Read a constant operand, in hex or decimal.
///
/// Returns `None` for anything that is not a plain constant, including
/// registers, memory references and branch targets.
fn constant_value(operand: &str) -> Option<u64> {
    let text = operand.trim().trim_start_matches('#');
    if text.is_empty() {
        return None;
    }

    // A memory reference can hold a constant, but that constant is an offset
    // into a frame or object and moves with unrelated edits.
    if text.contains('[') || text.contains(']') || text.starts_with('$') {
        return None;
    }

    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse::<u64>().ok(),
    }
}

/// Report whether an operand names a general register.
fn is_register(operand: &str) -> bool {
    matches!(operand, "lr" | "pc" | "ip" | "sl")
        || operand
            .strip_prefix('r')
            .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn strips_flag_suffix_and_condition() {
        assert_eq!(normalize_operation("adds"), "add");
        assert_eq!(normalize_operation("movlt"), "mov");
        assert_eq!(normalize_operation("bxeq"), "bx");
        assert_eq!(normalize_operation("movs"), "mov");
    }

    /// A mnemonic that merely ends in condition letters must survive.
    #[test]
    fn keeps_operations_that_look_conditional() {
        for operation in ["b", "bl", "ble", "mov", "mul", "push", "pop"] {
            assert_eq!(normalize_operation(operation), operation);
        }
    }

    /// Distinct operations must stay distinct, or matching means nothing.
    #[test]
    fn keeps_distinct_operations_apart() {
        assert_ne!(normalize_operation("add"), normalize_operation("sub"));
        assert_ne!(normalize_operation("ldr"), normalize_operation("str"));
        assert_ne!(normalize_operation("push"), normalize_operation("pop"));
    }

    #[test]
    fn register_choice_does_not_change_the_result() {
        let first = normalize(&insn("add", "r0, r1, r2", InsnKind::Normal));
        let second = normalize(&insn("add", "r4, r5, r6", InsnKind::Normal));
        assert_eq!(first, second, "a compiler picks registers freely");
    }

    #[test]
    fn small_constants_group_together() {
        let first = normalize(&insn("add", "r0, r0, 0x1", InsnKind::Normal));
        let second = normalize(&insn("add", "r0, r0, 0x4", InsnKind::Normal));
        assert_eq!(first, second);
    }

    /// Bucketing must not merge every constant, or a changed mask would hide.
    #[test]
    fn wide_constants_stay_apart_from_small_ones() {
        let small = normalize(&insn("mov", "r0, 0x4", InsnKind::Normal));
        let large = normalize(&insn("mov", "r0, 0xdeadbeef", InsnKind::Normal));
        assert_ne!(small, large);

        let zero = normalize(&insn("mov", "r0, 0x0", InsnKind::Normal));
        assert_ne!(zero, small);
    }

    /// Equality must ignore constants so matching survives an edited value,
    /// and the values must still be there to report the edit.
    #[test]
    fn constants_stay_available_but_out_of_equality() {
        let original = normalize(&insn("mov", "r1, 0x25", InsnKind::Normal));
        let edited = normalize(&insn("mov", "r1, 0x29", InsnKind::Normal));

        assert_eq!(original, edited, "the same work with a different constant still matches");
        assert!(original.differs_in_detail(&edited), "the changed value must be visible");
        assert_eq!(original.constants, vec![0x25]);
        assert_eq!(edited.constants, vec![0x29]);
    }

    #[test]
    fn identical_instructions_do_not_differ_in_detail() {
        let first = normalize(&insn("mov", "r1, 0x25", InsnKind::Normal));
        let second = normalize(&insn("mov", "r2, 0x25", InsnKind::Normal));
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

        let original = normalize(&insn("mov", "r1, 0x25", InsnKind::Normal));
        let edited = normalize(&insn("mov", "r1, 0x29", InsnKind::Normal));
        assert_eq!(hash_of(&original), hash_of(&edited));
    }

    /// An offset into a frame moves with unrelated edits, so it is not a
    /// constant worth reporting.
    #[test]
    fn frame_offsets_are_not_recorded_as_constants() {
        let load = normalize(&insn("ldr", "r0, [sp, 0x4]", InsnKind::Normal));
        assert!(load.constants.is_empty());
    }

    #[test]
    fn branch_addresses_do_not_change_the_result() {
        let near = insn("b", "$+0x8", InsnKind::Jump { target: Some(0x100) });
        let far = insn("b", "$+0x400", InsnKind::Jump { target: Some(0x9000) });
        assert_eq!(normalize(&near), normalize(&far), "addresses move with unrelated edits");
    }

    #[test]
    fn separates_stack_references_from_other_memory() {
        let spill = normalize(&insn("ldr", "r0, [sp, 0x4]", InsnKind::Normal));
        let load = normalize(&insn("ldr", "r0, [r1]", InsnKind::Normal));
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
        let normalized = normalize_body(&body);

        assert_eq!(normalized.len(), 2, "only the real work must remain");
        assert_eq!(normalized[0].operation, "add");
        assert_eq!(normalized[1].flow, FlowShape::Return);
    }

    /// `pop {fp, pc}` both restores the frame and returns, so it must stay.
    #[test]
    fn keeps_a_pop_that_returns() {
        let body = [insn("pop", "{fp, pc}", InsnKind::Return)];
        assert_eq!(normalize_body(&body).len(), 1);
    }

    #[test]
    fn keeps_loads_that_are_not_spills() {
        let body = [insn("ldr", "r0, [r1, 0x8]", InsnKind::Normal)];
        assert_eq!(normalize_body(&body).len(), 1, "a data load is real work");
    }

    #[test]
    fn a_constant_signature_holds_the_values_a_function_uses() {
        let body = normalize_body(&[
            insn("mov", "r1, 0x25", InsnKind::Normal),
            insn("cmp", "r0, 0x64", InsnKind::Normal),
        ]);
        assert_eq!(constant_signature(&body), BTreeSet::from([0x25, 0x64]));
    }

    /// Values in almost every function cannot identify one, so they go.
    #[test]
    fn a_constant_signature_drops_the_common_values() {
        let body = normalize_body(&[
            insn("mov", "r0, 0x0", InsnKind::Normal),
            insn("add", "r0, r0, 0x1", InsnKind::Normal),
            insn("cmp", "r0, 0x25", InsnKind::Normal),
        ]);
        assert_eq!(constant_signature(&body), BTreeSet::from([0x25]), "only 37 identifies this");
    }

    #[test]
    fn a_constant_signature_is_empty_without_constants() {
        let body = normalize_body(&[insn("bx", "lr", InsnKind::Return)]);
        assert!(constant_signature(&body).is_empty());
    }

    /// The same value used twice is one entry, so the set does not depend on
    /// how many times the compiler happened to materialize it.
    #[test]
    fn a_constant_signature_counts_each_value_once() {
        let body = normalize_body(&[
            insn("mov", "r0, 0x25", InsnKind::Normal),
            insn("mov", "r1, 0x25", InsnKind::Normal),
        ]);
        assert_eq!(constant_signature(&body), BTreeSet::from([0x25]));
    }

    /// Frame offsets move with unrelated edits, so they are not part of the
    /// signature. This follows from `constant_value`, and is checked here so
    /// a change there cannot quietly widen the signature.
    #[test]
    fn a_constant_signature_ignores_frame_offsets() {
        let body = normalize_body(&[insn("ldr", "r0, [r1, 0x25]", InsnKind::Normal)]);
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
        let caller = normalize_body(&[
            insn("mov", "r1, 0x25", InsnKind::Normal),
            insn("mul", "r0, r0, r1", InsnKind::Normal),
            insn("add", "r0, r0, 0x1", InsnKind::Normal),
            insn("bx", "lr", InsnKind::Return),
        ]);
        let callee = normalize_body(&[
            insn("mov", "r1, 0x25", InsnKind::Normal),
            insn("mul", "r0, r0, r1", InsnKind::Normal),
            insn("bx", "lr", InsnKind::Return),
        ]);

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
        let body = normalize_body(&[
            insn("cmp", "r0, 0x0", InsnKind::Normal),
            insn("add", "r0, r0, 0x1", InsnKind::Normal),
            insn("bx", "lr", InsnKind::Return),
        ]);
        assert!(constant_signature(&body).is_empty());
    }

    #[test]
    fn opaque_bytes_stay_opaque() {
        let body = [insn("(unknown)", "0x00000000", InsnKind::Unknown)];
        assert_eq!(normalize_body(&body)[0].flow, FlowShape::Opaque);
    }

    /// Two unreadable instructions must stay apart when their bytes differ.
    ///
    /// The compiler turns `vmax.s32` into `vmin.s32` when a comparison flips.
    /// Both are NEON, which the decoder cannot read. If they normalized alike
    /// the change would be reported as no change at all.
    #[test]
    fn different_opaque_words_do_not_normalize_alike() {
        let first = normalize(&insn("(unknown)", "0xf2600680", InsnKind::Unknown));
        let second = normalize(&insn("(unknown)", "0xf2200680", InsnKind::Unknown));
        assert_ne!(first, second, "an edit inside unreadable bytes must stay visible");
    }

    #[test]
    fn matching_opaque_words_normalize_alike() {
        let first = normalize(&insn("(unknown)", "0xf2600680", InsnKind::Unknown));
        let second = normalize(&insn("(unknown)", "0xf2600680", InsnKind::Unknown));
        assert_eq!(first, second);
    }

    #[test]
    fn handles_instructions_without_operands() {
        let normalized = normalize(&insn("nop", "", InsnKind::Normal));
        assert!(normalized.operands.is_empty());
    }
}
