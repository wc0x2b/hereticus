use std::collections::{BTreeMap, BTreeSet};

use super::align::*;
use super::change::*;
use super::lines::*;
use super::score::*;
use super::*;
use hereticus_arch::Arch;
use hereticus_il as il;
use hereticus_il::arch::Decoder as _;
use hereticus_memory::ConstantKind;

/// The bit-parallel table walks as the table of cells does, ties and
/// all, on runs of every length across the edges of a word.
#[test]
fn the_bit_table_walks_as_the_cell_table() {
    bolero::check!().with_type::<(Vec<u8>, Vec<u8>)>().for_each(|(left, right)| {
        // Few distinct items, so that ties are many.
        let left: Vec<u32> = left.iter().map(|&item| u32::from(item % 5)).collect();
        let right: Vec<u32> = right.iter().map(|&item| u32::from(item % 5)).collect();
        assert_eq!(
            longest_common_subsequence_of_numbers(&left, &right, 5),
            longest_common_subsequence(&left, &right),
            "{left:?} {right:?}"
        );
    });
    // Runs of up to 300 items, which span several words.
    let mut seed = 0x9e37_79b9_u32;
    let mut next = |below: u32| {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed % below
    };
    for _ in 0..200 {
        let (left_len, right_len) = (next(300), next(300));
        let left: Vec<u32> = (0..left_len).map(|_| next(6)).collect();
        let right: Vec<u32> = (0..right_len).map(|_| next(6)).collect();
        assert_eq!(
            longest_common_subsequence_of_numbers(&left, &right, 6),
            longest_common_subsequence(&left, &right)
        );
    }
    let long: Vec<u32> = (0..200).map(|index| index % 7).collect();
    let other: Vec<u32> = (0..190).map(|index| (index * 3) % 7).collect();
    assert_eq!(
        longest_common_subsequence_of_numbers(&long, &other, 7),
        longest_common_subsequence(&long, &other)
    );
}
/// Two instructions align on the operation and the names of the lift,
/// with targets left out, and what no lift reads aligns by its bytes.
#[test]
fn a_diff_aligns_on_the_names_of_the_lift() {
    use hereticus_il::arch::aarch64::Aarch64;
    let a32 = |word: u32, at: u64| Arm32.decode(&word.to_le_bytes(), 0, at).expect("decodes");
    let a64 = |word: u32, at: u64| Aarch64.decode(&word.to_le_bytes(), 0, at).expect("decodes");
    // bl $+0x100 and bl $+0x200, at two places: the target moves.
    assert_eq!(diff_key(&a64(0x9400_0040, 0x1000)), diff_key(&a64(0x9400_0080, 0x2000)));
    // The post-index register.
    let (by_r2, by_r3) = (a32(0xe691_0002, 0), a32(0xe691_0003, 0));
    assert_eq!(by_r2.to_string(), "ldr r0, [r1],  r2", "as yaxpeax-arm prints it");
    assert_eq!(by_r3.to_string(), "ldr r0, [r1],  r3");
    assert_ne!(diff_key(&by_r2), diff_key(&by_r3));
    // cmp r0, #1 against cmp r0, #2: the constant.
    assert_ne!(diff_key(&a32(0xe350_0001, 0)), diff_key(&a32(0xe350_0002, 0)));
    // add w0, w1, w2 against add x0, x1, x2: the width.
    assert_ne!(diff_key(&a64(0x0b02_0020, 0)), diff_key(&a64(0x8b02_0020, 0)));
    // Two words no decoder reads, by their bytes.
    let unread = |word: u32| a64(word, 0);
    assert_eq!(diff_key(&unread(0)), diff_key(&unread(0)));
    assert_ne!(diff_key(&unread(0)), diff_key(&unread(1)));
}

use crate::norm::normalize;
use hereticus_il::arch::arm32::Arm32;

/// One A32 instruction for each name, normalized. Each has the same
/// registers as every other of its name, so only the names differ.
fn body(names: &[&str]) -> Vec<NormInsn> {
    names
        .iter()
        .map(|name| {
            let word: u32 = match *name {
                "add" => 0xe081_0002, // add r0, r1, r2
                "sub" => 0xe041_0002, // sub r0, r1, r2
                "mul" => 0xe000_0291, // mul r0, r1, r2
                "mov" => 0xe1a0_0001, // mov r0, r1
                "mvn" => 0xe1e0_0001, // mvn r0, r1
                "cmp" => 0xe150_0001, // cmp r0, r1
                "ldr" => 0xe591_0000, // ldr r0, [r1]
                "str" => 0xe581_0000, // str r0, [r1]
                other => panic!("no word for {other}"),
            };
            let insn = Arm32.decode(&word.to_le_bytes(), 0, 0).expect("the word must decode");
            normalize(&Arm32, &insn)
        })
        .collect()
}

#[test]
fn a_body_is_identical_to_itself() {
    let only = body(&["add", "mul"]);
    assert_eq!(similarity(&only, &only), 1.0);
}

#[test]
fn two_empty_bodies_are_identical() {
    assert_eq!(similarity(&[], &[]), 1.0);
}

#[test]
fn an_empty_body_shares_nothing_with_a_full_one() {
    assert_eq!(similarity(&[], &body(&["add"])), 0.0);
}

#[test]
fn similarity_does_not_depend_on_the_order_of_its_arguments() {
    let left = body(&["add", "mul"]);
    let right = body(&["add", "sub"]);
    assert_eq!(similarity(&left, &right), similarity(&right, &left));
}

/// Reordering the same instructions is not the same as editing them.
#[test]
fn reordering_is_told_apart_from_editing() {
    let original = body(&["mov", "mvn", "cmp"]);
    let moved = body(&["mvn", "cmp", "mov"]);
    let edited = body(&["mov", "ldr", "cmp"]);

    let mut original_sorted = original.clone();
    let mut moved_sorted = moved.clone();
    let mut edited_sorted = edited;
    original_sorted.sort();
    moved_sorted.sort();
    edited_sorted.sort();

    assert_eq!(original_sorted, moved_sorted, "the same instructions, moved");
    assert_ne!(original_sorted, edited_sorted, "a replaced instruction is a real change");
}

/// A changed word of data must not be reported as unchanged.
///
/// Data stored among instructions decodes as one, so normalizing buckets
/// its operands and loses the difference. Measured on a vendor kernel
/// image: the stored kernel size `0x2b08a8` decoded as
/// `eoreq r0, fp, r8, lsr 17`, and when the next release changed it to
/// `0x2b3c48` the function was called unchanged. Three of eleven real
/// changes were missed that way.
#[test]
fn a_changed_data_word_is_not_called_unchanged() {
    // The two encodings of that kernel size field, as they lift:
    // `eoreq r0, fp, r8, lsr 17` and `eoreq r3, fp, r8, asr 24`.
    let lift = |word: u32| {
        Arm32.lift(&Arm32.decode(&word.to_le_bytes(), 0, 0).expect("decodes")).expect("lifts")
    };
    let (before, after) = (lift(0x002b_08a8), lift(0x002b_3c48));
    assert!(
        !operands_are_interchangeable(
            &before.operands,
            &after.operands,
            TargetMoves::Never,
            AddressMoves::Never
        ),
        "a shift that changed is not a register that changed"
    );
}

fn r(number: u8) -> il::Operand {
    il::Operand::Reg(il::Reg::General(number))
}

/// A register the compiler picked differently is not an edit.
#[test]
fn a_changed_register_is_not_a_change() {
    assert!(operands_are_interchangeable(
        &[r(0), r(1), r(2)],
        &[r(4), r(5), r(6)],
        TargetMoves::Never,
        AddressMoves::Never
    ));
}

/// A call whose callee moved is not an edit.
///
/// Anything that changes size shifts every target after it, so a whole
/// image of unedited functions would otherwise read as changed.
#[test]
fn a_moved_branch_target_is_not_a_change() {
    assert!(operands_are_interchangeable(
        &[il::Operand::Target(Some(0x50_a734))],
        &[il::Operand::Target(Some(0x50_b2d4))],
        TargetMoves::Freely,
        AddressMoves::Never
    ));
}

/// A target on an instruction that does not branch is data, as an
/// address `adr` forms, and a changed one must stay visible.
#[test]
fn a_target_that_is_not_a_branch_stays_a_change() {
    assert!(!operands_are_interchangeable(
        &[il::Operand::Target(Some(0x50_a734))],
        &[il::Operand::Target(Some(0x50_b2d4))],
        TargetMoves::Never,
        AddressMoves::Never
    ));
}

/// Allowing targets to move must not let anything else move with them.
#[test]
fn a_branch_still_reports_its_other_operands() {
    assert!(!operands_are_interchangeable(
        &[r(0), il::Operand::Const(0x10)],
        &[r(0), il::Operand::Const(0x20)],
        TargetMoves::Freely,
        AddressMoves::Never
    ));
}

/// An access through `base` plus `offset`.
fn at(base: u8, offset: i64) -> il::Operand {
    il::Operand::memory(Some(il::Reg::General(base)), Some(offset))
}

/// A constant that is part of an address on both sides moves with the
/// linker, so it is not an edit.
#[test]
fn a_moved_address_is_not_a_change() {
    assert!(operands_are_interchangeable(
        &[r(2), il::Operand::Const(0x806f)],
        &[r(2), il::Operand::Const(0x8070)],
        TargetMoves::Never,
        AddressMoves::Freely
    ));
    assert!(operands_are_interchangeable(
        &[r(7), at(16, 0x1aa0)],
        &[r(7), at(16, -0x4560)],
        TargetMoves::Never,
        AddressMoves::Freely
    ));
}

/// The same constants, when either side is a value, stay a change.
#[test]
fn a_changed_value_is_still_a_change() {
    assert!(!operands_are_interchangeable(
        &[r(2), il::Operand::Const(0x806f)],
        &[r(2), il::Operand::Const(0x8070)],
        TargetMoves::Never,
        AddressMoves::Never
    ));
    assert!(!operands_are_interchangeable(
        &[r(2), at(2, 0x3c0)],
        &[r(2), at(2, 0x3c8)],
        TargetMoves::Never,
        AddressMoves::Never
    ));
}

/// An address may move, but not the register it is read through.
#[test]
fn a_moved_address_through_another_register_is_a_change() {
    assert!(!operands_are_interchangeable(
        &[r(7), at(16, 0x1aa0)],
        &[r(7), at(17, 0x1aa0)],
        TargetMoves::Never,
        AddressMoves::Freely
    ));
}

/// Two lists of operands of different lengths are different work.
#[test]
fn a_changed_count_of_operands_is_a_change() {
    assert!(!operands_are_interchangeable(
        &[r(0), r(1)],
        &[r(0), r(1), r(2)],
        TargetMoves::Freely,
        AddressMoves::Freely
    ));
}

/// A list the allocator filled with other registers is the same work,
/// but a list that now loads the program counter returns.
#[test]
fn a_register_list_is_a_free_choice_but_not_its_return() {
    let list = |regs: &[il::Reg]| il::Operand::RegisterList(regs.iter().copied().collect());
    let (r4, r5, r6, r7) =
        (il::Reg::General(4), il::Reg::General(5), il::Reg::General(6), il::Reg::General(7));
    let pc = il::Reg::ProgramCounter;
    let interchangeable = |left: &[il::Reg], right: &[il::Reg]| {
        operands_are_interchangeable(
            &[list(left)],
            &[list(right)],
            TargetMoves::Never,
            AddressMoves::Never,
        )
    };
    assert!(interchangeable(&[r4, r6, r7, pc], &[r4, r5, r6, pc]));
    assert!(!interchangeable(&[r4, r6, r7, pc], &[r4, r5, r6, r7]));
    assert!(!interchangeable(&[r4, r6, pc], &[r4, r5, r6, pc]));
}

/// Only one side being an address is not enough to let it move.
#[test]
fn an_address_on_one_side_only_does_not_move() {
    assert_eq!(
        AddressMoves::from((&ConstantKind::Address, &ConstantKind::Value)),
        AddressMoves::Never
    );
    assert_eq!(
        AddressMoves::from((&ConstantKind::Value, &ConstantKind::Address)),
        AddressMoves::Never
    );
    assert_eq!(
        AddressMoves::from((&ConstantKind::Address, &ConstantKind::Address)),
        AddressMoves::Freely
    );
}

/// A condition code is the compiler's choice, not an edit.
///
/// `movwlt` against `movwlo` is signed against unsigned less-than. Both
/// appear for the same source at different optimization levels, and
/// reporting it as a change cried wolf on the test corpus.
#[test]
fn a_changed_condition_is_not_a_change() {
    let decode = |word: u32| Arm32.decode(&word.to_le_bytes(), 0, 0).expect("decodes");
    // movwlt r0, #1 and movwlo r0, #1.
    let (signed, unsigned) = (decode(0xb300_0001), decode(0x3300_0001));
    assert_ne!(signed.to_string(), unsigned.to_string());
    assert_eq!(Arm32.operation_name(&signed), Arm32.operation_name(&unsigned));
}

#[test]
fn a_reordering_still_counts_as_a_change_to_report() {
    assert!(Changed::Reordered > Changed::No);
    assert!(Changed::Yes > Changed::InDetail);
    assert!(Changed::Unreadable > Changed::InDetail);
    assert!(Changed::Yes > Changed::Unreadable);
}

/// `(neon) 0xf2601844`, a NEON word no instruction encodes, then `bx lr`.
const OPAQUE_WORD: &[u8] = &[0x44, 0x18, 0x60, 0xf2, 0x1e, 0xff, 0x2f, 0xe1];
/// The same word changed: `(neon) 0xf2601846`.
const OPAQUE_WORD_EDITED: &[u8] = &[0x46, 0x18, 0x60, 0xf2, 0x1e, 0xff, 0x2f, 0xe1];
/// `sub r0, r1, r0` then `bx lr`, which the decoder reads.
const SUB_THEN_RETURN: &[u8] = &[0x00, 0x00, 0x41, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];

/// A difference the decoder cannot read is reported as exactly that.
///
/// Two opaque words that differ share no instruction but the return, so
/// pairing them needs a permissive threshold. What the pair is called
/// once it exists is the point here.
#[test]
fn an_unreadable_difference_is_told_apart_from_an_edit() {
    let before = binary_of(&[("f", OPAQUE_WORD)]);
    let after = binary_of(&[("f", OPAQUE_WORD_EDITED)]);
    let diff = diff_with(&before, &after, Options { threshold: 0.0, use_names: UseNames::No });
    let pair = diff.matched.first().expect("a threshold of zero pairs anything");
    assert_eq!(pair.changed, Changed::Unreadable);
}

/// A difference in readable code stays a plain change, so the new variant
/// does not swallow the edits a reader came for.
///
/// These two share only their return, so pairing them needs a threshold
/// low enough to accept a weak match. The classification under test runs
/// once a pair exists, whatever justified it.
#[test]
fn a_readable_edit_is_not_called_unreadable() {
    let before = binary_of(&[("f", ADD_THEN_RETURN)]);
    let after = binary_of(&[("f", SUB_THEN_RETURN)]);
    let diff = diff_with(&before, &after, Options { threshold: 0.0, use_names: UseNames::No });
    let pair = diff.matched.first().expect("a threshold of zero pairs anything");
    assert_eq!(pair.changed, Changed::Yes);
}

/// Counting an edit that rewrote one instruction in place.
#[test]
fn an_edit_counts_the_instructions_it_rewrote() {
    let edits = edits_between(ADD_THEN_RETURN, SUB_THEN_RETURN);
    assert_eq!(edits, Edits { added: 0, removed: 0, edited: 1 });
    assert!(edits.same_length(), "nothing was added or removed");
    assert_eq!(edits.total(), 1);
}

/// An edit that grew the function counts what it added.
#[test]
fn an_edit_counts_the_instructions_it_added() {
    // `add` then `add` then `bx lr`, against `add` then `bx lr`.
    let longer: &[u8] = &[0x00, 0x00, 0x81, 0xe0, 0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
    let edits = edits_between(ADD_THEN_RETURN, longer);
    assert_eq!(edits.added, 1, "one instruction appeared");
    assert_eq!(edits.removed, 0);
    assert!(!edits.same_length());
}

/// The same comparison reversed must report a removal, not an addition.
#[test]
fn an_edit_counts_the_instructions_it_removed() {
    let longer: &[u8] = &[0x00, 0x00, 0x81, 0xe0, 0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
    let edits = edits_between(longer, ADD_THEN_RETURN);
    assert_eq!(edits.removed, 1, "one instruction went away");
    assert_eq!(edits.added, 0);
}

/// An instruction inserted near the top must cost one addition, not a
/// rewrite of everything after it.
///
/// Counting position by position made the insertion shift every later
/// instruction against a different one, so a one-line edit was reported as
/// a wholly rewritten body. Aligning the two bodies first is what keeps the
/// count honest.
#[test]
fn an_insertion_does_not_make_the_rest_look_rewritten() {
    // `add`, `mul`, `sub`, `bx lr`, against the same with a `mov` in front.
    let before: &[u8] = &[
        0x00, 0x00, 0x81, 0xe0, // add r0, r1, r0
        0x91, 0x00, 0x00, 0xe0, // mul r0, r1, r0
        0x00, 0x00, 0x41, 0xe0, // sub r0, r1, r0
        0x1e, 0xff, 0x2f, 0xe1, // bx lr
    ];
    let after: &[u8] = &[
        0x01, 0x00, 0xa0, 0xe3, // mov r0, 1
        0x00, 0x00, 0x81, 0xe0, // add r0, r1, r0
        0x91, 0x00, 0x00, 0xe0, // mul r0, r1, r0
        0x00, 0x00, 0x41, 0xe0, // sub r0, r1, r0
        0x1e, 0xff, 0x2f, 0xe1, // bx lr
    ];

    let edits = edits_between(before, after);
    assert_eq!(edits, Edits { added: 1, removed: 0, edited: 0 });
    assert_eq!(edits.total(), 1, "one instruction appeared, none was rewritten");
}

/// A moved instruction costs one addition and one removal.
///
/// Measured on the test corpus: `switch_dense` moves a single `mov` three
/// places down between `-O1` and `-O2`, which the position-by-position
/// count reported as three rewritten instructions.
#[test]
fn a_moved_instruction_is_not_counted_as_three_rewrites() {
    let before: &[u8] = &[
        0x01, 0x30, 0xa0, 0xe3, // mov r3, 1
        0x00, 0x00, 0x81, 0xe0, // add r0, r1, r0
        0x91, 0x00, 0x00, 0xe0, // mul r0, r1, r0
        0x1e, 0xff, 0x2f, 0xe1, // bx lr
    ];
    let after: &[u8] = &[
        0x00, 0x00, 0x81, 0xe0, // add r0, r1, r0
        0x91, 0x00, 0x00, 0xe0, // mul r0, r1, r0
        0x01, 0x30, 0xa0, 0xe3, // mov r3, 1
        0x1e, 0xff, 0x2f, 0xe1, // bx lr
    ];

    let edits = edits_between(before, after);
    assert_eq!(edits.edited, 0, "nothing was rewritten, one instruction moved");
    assert_eq!(edits.added, 1);
    assert_eq!(edits.removed, 1);
}

/// A changed constant is reported by `Changed::InDetail`, not by the edit
/// counts.
///
/// The `+/-/~` column counts instructions whose shape moved. Normalizing
/// hides a constant on purpose, so a threshold that changed value leaves
/// every instruction in place and the counts stay clean. The CLI relies on
/// this to hide such a pair unless asked for it.
#[test]
fn a_changed_constant_touches_no_instruction() {
    // `mov r0, 1` then `bx lr`, against `mov r0, 2` then `bx lr`.
    let before: &[u8] = &[0x01, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1];
    let after: &[u8] = &[0x02, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1];

    assert_eq!(edits_between(before, after), Edits::default());
}

/// `cmp r0, 0` then `bx lr`, the body the kind tests start from.
const COMPARE_THEN_RETURN: &[u8] = &[0x00, 0x00, 0x50, 0xe3, 0x1e, 0xff, 0x2f, 0xe1];

/// A gate the later build added is reported as a branch.
#[test]
fn an_added_branch_is_classified_as_control_flow() {
    // The same body with a `beq` after the compare.
    let with_branch: &[u8] = &[
        0x00, 0x00, 0x50, 0xe3, // cmp r0, 0
        0x02, 0x00, 0x00, 0x0a, // beq
        0x1e, 0xff, 0x2f, 0xe1, // bx lr
    ];

    let kinds = kinds_between(COMPARE_THEN_RETURN, with_branch);
    assert_eq!(kinds.branches, 1, "the added instruction was a branch");
    assert_eq!(kinds.constants, 0, "no stored value changed");
    assert!(kinds.touches_control_flow());
}

/// A call the later build added is told apart from a branch.
#[test]
fn an_added_call_is_classified_as_a_call() {
    let with_call: &[u8] = &[
        0x00, 0x00, 0x50, 0xe3, // cmp r0, 0
        0x03, 0x00, 0x00, 0xeb, // bl
        0x1e, 0xff, 0x2f, 0xe1, // bx lr
    ];

    let kinds = kinds_between(COMPARE_THEN_RETURN, with_call);
    assert_eq!(kinds.calls, 1);
    assert_eq!(kinds.branches, 0, "a call is not a branch");
}

/// A load the later build added is reported as memory, not control flow.
#[test]
fn an_added_load_is_classified_as_memory() {
    let with_load: &[u8] = &[
        0x00, 0x00, 0x50, 0xe3, // cmp r0, 0
        0x00, 0x10, 0x90, 0xe5, // ldr r1, [r0]
        0x1e, 0xff, 0x2f, 0xe1, // bx lr
    ];

    let kinds = kinds_between(COMPARE_THEN_RETURN, with_load);
    assert_eq!(kinds.memory, 1);
    assert!(!kinds.touches_control_flow(), "a load changes no control flow");
}

/// A changed constant is reported on its own, with no instruction touched.
///
/// This is the case the edit counts deliberately leave out, so the kinds
/// are the only place it appears.
#[test]
fn a_changed_constant_is_classified_as_a_constant() {
    // `mov r0, 1` then `bx lr`, against `mov r0, 2` then `bx lr`.
    let before: &[u8] = &[0x01, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1];
    let after: &[u8] = &[0x02, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1];

    let kinds = kinds_between(before, after);
    assert_eq!(kinds.constants, 1);
    assert_eq!(edits_between(before, after), Edits::default(), "no instruction moved");
    assert!(!kinds.touches_control_flow());
}

/// An edit that both adds a branch and changes a constant reports both.
///
/// This is what the severity axis cannot say: [`Changed::Yes`] covers the
/// whole edit, and the constant change disappears into it.
#[test]
fn an_edit_that_adds_code_and_changes_a_value_reports_both() {
    // `mov r0, 1` then `bx lr`.
    let before: &[u8] = &[0x01, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1];
    // `mov r0, 2`, a `beq`, then `bx lr`.
    let after: &[u8] = &[
        0x02, 0x00, 0xa0, 0xe3, // mov r0, 2
        0x02, 0x00, 0x00, 0x0a, // beq
        0x1e, 0xff, 0x2f, 0xe1, // bx lr
    ];

    let kinds = kinds_between(before, after);
    assert_eq!(kinds.branches, 1, "the added branch is visible");
    assert_eq!(kinds.constants, 1, "and so is the changed value");
}

/// The kinds of the moved instructions sum to what the counts reported.
///
/// Constants stand outside that sum, because such an instruction stayed in
/// place.
#[test]
fn the_kinds_account_for_every_instruction_counted() {
    let with_branch: &[u8] = &[
        0x00, 0x00, 0x50, 0xe3, // cmp r0, 0
        0x02, 0x00, 0x00, 0x0a, // beq
        0x00, 0x10, 0x90, 0xe5, // ldr r1, [r0]
        0x1e, 0xff, 0x2f, 0xe1, // bx lr
    ];

    let edits = edits_between(COMPARE_THEN_RETURN, with_branch);
    let kinds = kinds_between(COMPARE_THEN_RETURN, with_branch);
    let counted: usize =
        kinds.present().filter(|(kind, _)| *kind != EditKind::Constant).map(|(_, n)| n).sum();

    assert_eq!(counted, edits.total(), "every touched instruction has a kind");
}

/// A pair too large to align is still counted, without the table.
///
/// The alignment table is quadratic. A vendor kernel holds functions of
/// about twenty thousand instructions, where the table asks for over
/// three gigabytes and the process is killed. Such a pair must fall back
/// rather than bring the run down.
#[test]
fn a_pair_too_large_to_align_is_still_counted() {
    let cells = |left: usize, right: usize| (left + 1) * (right + 1);
    assert!(cells(19926, 19872) > LARGEST_ALIGNMENT, "a whole-kernel pair is over the limit");
    assert!(cells(500, 500) <= LARGEST_ALIGNMENT, "an ordinary function is well under it");

    // One instruction rewritten, in bodies past the alignment limit.
    let left = vec![body(&["add"])[0].clone(); 5000];
    let mut right = left.clone();
    right[0] = body(&["sub"])[0].clone();
    assert!(
        cells(left.len(), right.len()) > LARGEST_ALIGNMENT,
        "the test bodies are over the limit"
    );

    let (edits, kinds) = count_edits(&left, &right);
    assert_eq!(edits, Edits { added: 0, removed: 0, edited: 1 });
    assert_eq!(kinds.other, 1, "the rewritten instruction is classified");
}

/// Check that `steps` is an alignment of the two sequences: it walks
/// both to the end and keeps only equal items. Return how many it kept.
fn kept_by<T: PartialEq + core::fmt::Debug>(left: &[T], right: &[T], steps: &[Step]) -> usize {
    let (mut i, mut j, mut kept) = (0, 0, 0);
    for step in steps {
        match step {
            Step::Both => {
                assert_eq!(left[i], right[j], "a kept pair must be equal");
                (i, j, kept) = (i + 1, j + 1, kept + 1);
            }
            Step::Left => i += 1,
            Step::Right => j += 1,
        }
    }
    assert_eq!((i, j), (left.len(), right.len()), "the alignment must walk both sides");
    kept
}

/// The table without its shared head gives the same walk as the full
/// table, step for step.
#[test]
fn a_shared_head_aligns_as_the_full_table_does() {
    fn full_table(left: &[u64], right: &[u64]) -> Vec<Step> {
        let mut len = vec![vec![0usize; right.len() + 1]; left.len() + 1];
        for i in (0..left.len()).rev() {
            for j in (0..right.len()).rev() {
                len[i][j] = if left[i] == right[j] {
                    len[i + 1][j + 1] + 1
                } else {
                    len[i + 1][j].max(len[i][j + 1])
                };
            }
        }
        let (mut steps, mut i, mut j) = (Vec::new(), 0, 0);
        while i < left.len() && j < right.len() {
            if left[i] == right[j] {
                steps.push(Step::Both);
                (i, j) = (i + 1, j + 1);
            } else if len[i + 1][j] >= len[i][j + 1] {
                steps.push(Step::Left);
                i += 1;
            } else {
                steps.push(Step::Right);
                j += 1;
            }
        }
        steps.extend(core::iter::repeat_n(Step::Left, left.len() - i));
        steps.extend(core::iter::repeat_n(Step::Right, right.len() - j));
        steps
    }

    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = |limit: u64| {
        state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        (state >> 33) % limit
    };
    for _ in 0..2000 {
        let alphabet = 1 + next(6);
        let head: Vec<u64> = (0..next(8)).map(|_| next(alphabet)).collect();
        let left: Vec<u64> =
            head.iter().copied().chain((0..next(12)).map(|_| next(alphabet))).collect();
        let right: Vec<u64> =
            head.iter().copied().chain((0..next(12)).map(|_| next(alphabet))).collect();
        assert_eq!(
            longest_common_subsequence(&left, &right),
            full_table(&left, &right),
            "{left:?} {right:?}"
        );
    }
}

/// Any two sequences align validly by anchors, and never keep more
/// than the exact alignment does.
#[test]
fn anchors_align_any_two_sequences() {
    // A small linear congruential generator keeps the test repeatable.
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = |limit: u64| {
        state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        (state >> 33) % limit
    };
    for _ in 0..500 {
        let alphabet = 1 + next(40);
        let left: Vec<u64> = (0..next(60)).map(|_| next(alphabet)).collect();
        let right: Vec<u64> = (0..next(60)).map(|_| next(alphabet)).collect();
        let exact = kept_by(&left, &right, &longest_common_subsequence(&left, &right));
        for largest in [0, 16, 200] {
            let kept = kept_by(&left, &right, &align_within(&left, &right, largest));
            assert!(kept <= exact, "{left:?} {right:?}");
        }
    }
}

/// An instruction inserted at the top of a function too large for the
/// table costs one addition, not a rewrite of every one after it.
#[test]
fn an_insertion_into_a_large_body_costs_one_addition() {
    let left: Vec<u32> = (0..1000).collect();
    let right: Vec<u32> = core::iter::once(5000).chain(0..1000).collect();
    let steps = align_within(&left, &right, 100);
    assert_eq!(kept_by(&left, &right, &steps), 1000);
    assert_eq!(steps.iter().filter(|step| **step == Step::Right).count(), 1);
}

#[test]
fn the_chain_keeps_the_longest_run_in_order() {
    let seeds = [(0, 3), (1, 0), (2, 1), (3, 4), (4, 2), (5, 5)];
    assert_eq!(longest_increasing_chain(&seeds), vec![(1, 0), (2, 1), (4, 2), (5, 5)]);
    assert_eq!(longest_increasing_chain(&[]), vec![]);
}

/// A function compared with itself has nothing to count.
#[test]
fn an_unedited_function_counts_no_edits() {
    let edits = edits_between(ADD_THEN_RETURN, ADD_THEN_RETURN);
    assert_eq!(edits, Edits::default());
    assert_eq!(edits.total(), 0);
}

/// Count the edits between two one-function images.
///
/// A threshold of zero pairs the two whatever they score, so a test can
/// measure the count without first arguing that the pair is a good one.
fn edits_between(before: &[u8], after: &[u8]) -> Edits {
    let before = binary_of(&[("f", before)]);
    let after = binary_of(&[("f", after)]);
    let diff = diff_with(&before, &after, Options { threshold: 0.0, use_names: UseNames::No });
    diff.matched.first().expect("a threshold of zero pairs anything").edits
}

/// Classify the edits between two one-function images.
fn kinds_between(before: &[u8], after: &[u8]) -> EditKinds {
    let before = binary_of(&[("f", before)]);
    let after = binary_of(&[("f", after)]);
    let diff = diff_with(&before, &after, Options { threshold: 0.0, use_names: UseNames::No });
    diff.matched.first().expect("a threshold of zero pairs anything").kinds
}

/// Building a `Binary` by hand keeps these tests free of fixture files.
fn binary_of(functions: &[(&str, &[u8])]) -> hereticus_image::Binary {
    hereticus_image::Binary {
        isa: Isa::Arm32,
        found_by: hereticus_image::FoundBy::Symbols,
        addresses: hereticus_memory::AddressSpace::none(),
        links: hereticus_image::Links::default(),
        other_set: std::collections::BTreeSet::new(),
        functions: functions
            .iter()
            .enumerate()
            .map(|(index, (name, code))| Function {
                name: (*name).to_string(),
                address: index as u64 * 0x100,
                code: code.to_vec(),
            })
            .collect(),
    }
}

/// Two twins that each call one import through a PLT stub, the import
/// that `names` gives for the stub at 0x200 and the one at 0x300, and
/// placed at 0x0 and 0x100 in that order.
fn twins_calling(names: [&str; 2]) -> hereticus_image::Binary {
    /// The distance from an LLD PLT stub to the slot it jumps through.
    const TO_SLOT: u64 = 0x3ea34 - 0x1dd60;
    let bl = |from: u32, to: u32| 0xeb00_0000 | ((to.wrapping_sub(from + 8) / 4) & 0x00ff_ffff);
    let words =
        |words: &[u32]| -> Vec<u8> { words.iter().flat_map(|word| word.to_le_bytes()).collect() };
    let stub = words(&[0xe28f_c600, 0xe28c_ca20, 0xe5bc_fccc]);
    let codes = [
        words(&[0xe92d_4010, bl(0x4, 0x200), 0xe8bd_8010]),
        words(&[0xe92d_4010, bl(0x104, 0x300), 0xe8bd_8010]),
        stub.clone(),
        stub,
    ];
    let mut binary =
        binary_of(&[("", &codes[0]), ("", &codes[1]), ("", &codes[2]), ("", &codes[3])]);
    let memory =
        binary.functions.iter().map(|function| (function.address, function.code.clone())).collect();
    let slots = BTreeMap::from([
        (0x200 + TO_SLOT, names[0].to_string()),
        (0x300 + TO_SLOT, names[1].to_string()),
    ]);
    binary.links = hereticus_image::Links::of_parts(memory, slots);
    binary
}

/// Twins in another order, as another compiler places them, pair by the
/// import each calls rather than by their order.
#[test]
fn twins_pair_by_what_they_call() {
    let before = twins_calling(["exp", "log10"]);
    let after = twins_calling(["log10", "exp"]);
    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    let partner =
        |index: usize| diff.matched.iter().find(|pair| pair.before == index).map(|pair| pair.after);
    assert_eq!(partner(0), Some(1), "exp");
    assert_eq!(partner(1), Some(0), "log10");
    assert_eq!(diff.changed().count(), 0);
}

/// Where names are known, twins of one shape pair by name, however
/// the other side orders them.
#[test]
fn twins_pair_by_name_where_names_are_known() {
    let returns = |value: u32| -> Vec<u8> {
        [0xe3a0_0000 | value, 0xe12f_ff1e].iter().flat_map(|word| word.to_le_bytes()).collect()
    };
    let before = binary_of(&[("first", &returns(1)), ("second", &returns(2))]);
    let after = binary_of(&[("second", &returns(4)), ("first", &returns(3))]);
    let diff = diff_with(&before, &after, Options::default());
    let partner =
        |index: usize| diff.matched.iter().find(|pair| pair.before == index).map(|pair| pair.after);
    assert_eq!(partner(0), Some(1), "first");
    assert_eq!(partner(1), Some(0), "second");
}

/// Twins that call the same import cannot be told apart by it, so the
/// shape stage does not pair one of them with the only twin on the other
/// side that calls it.
#[test]
fn a_callee_twins_share_does_not_pair_them() {
    let before = twins_calling(["exp", "exp"]);
    let after = twins_calling(["log10", "exp"]);
    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    let by_shape = diff
        .matched
        .iter()
        .filter(|pair| pair.before < 2 && pair.confidence == Confidence::IdenticalShape)
        .count();
    assert_eq!(by_shape, 0);
}

/// Where a release deletes one of two twins, the twin that comes first
/// does not take the one left by its shape alone: the constant decides.
#[test]
fn a_deleted_twin_does_not_take_the_one_left() {
    // `mov` the value into `register`, then return.
    let moves = |register: u32, value: u32| -> Vec<u8> {
        [0xe3a0_0000 | register << 12 | value, 0xe12f_ff1e]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect()
    };
    let before = binary_of(&[("", &moves(0, 1)), ("", &moves(0, 2))]);
    // Another register, so that no byte agrees and only the shape does.
    let after = binary_of(&[("", &moves(1, 2))]);
    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    let partner =
        |index: usize| diff.matched.iter().find(|pair| pair.before == index).map(|pair| pair.after);
    assert_eq!(partner(1), Some(0), "the function that returns 2");
    assert_eq!(diff.removed, [0], "the function that returns 1");
}

/// Twins that differ only in a constant pair by it, even where there
/// are more twins than similarity keeps candidates for, and one side has
/// one more.
#[test]
fn twins_pair_by_their_constants() {
    let returns = |value: u32| -> Vec<u8> {
        [0xe3a0_0000 | value, 0xe12f_ff1e].iter().flat_map(|word| word.to_le_bytes()).collect()
    };
    let before: Vec<Vec<u8>> = (1..=12).map(returns).collect();
    let after: Vec<Vec<u8>> = (1..=13).rev().map(returns).collect();
    let unnamed_before: Vec<(&str, &[u8])> =
        before.iter().map(|code| ("", code.as_slice())).collect();
    let unnamed_after: Vec<(&str, &[u8])> =
        after.iter().map(|code| ("", code.as_slice())).collect();
    let diff = diff_with(
        &binary_of(&unnamed_before),
        &binary_of(&unnamed_after),
        Options { use_names: UseNames::No, ..Default::default() },
    );
    for index in 0..12 {
        let partner = diff.matched.iter().find(|pair| pair.before == index).map(|p| p.after);
        assert_eq!(partner, Some(12 - index), "the function that returns {}", index + 1);
    }
    assert_eq!(diff.added, [0], "the one that returns 13");
}

#[test]
fn a_short_text_counts_where_it_changed_in_place() {
    // Sorted, as a function holds them.
    let changed = short_texts_changed((&["%d", "no"], &["%d", "no"]), (&["%u", "no"], &["%u"]));
    assert_eq!(changed, 1, "`%d` became `%u`");
    let came = short_texts_changed((&["no"], &["no"]), (&["no", "yes"], &["no", "yes"]));
    assert_eq!(came, 0, "a text that came alone can be a merged tail");
    let unsure = short_texts_changed((&["!e"], &[]), (&["!f"], &[]));
    assert_eq!(unsure, 0, "neither is sure");
    let one_sure = short_texts_changed((&["%d"], &["%d"]), (&["!f"], &[]));
    assert_eq!(one_sure, 0, "the other side's is not sure");
}

#[test]
fn an_il_shape_collapses_numbers_but_not_names() {
    assert_eq!(il_shape("w0 = w1 + 0x10"), il_shape("w0 = w1 + 0x20"));
    assert_eq!(il_shape("x0 = load.32 [x1 + 8]"), "x0 = load.# [x1 + #]");
    assert_eq!(il_key("if (w0 <= 3) goto $+0x40"), "if (w0 <= 3) goto $");
    assert_eq!(il_key("x8 = load.64 [@0x57c6]"), "x8 = load.64 [@]");
    assert_eq!(il_key("r2 = load.32 [pc + 0x5c]"), "r2 = load.32 [pc + ]");
    assert_eq!(il_key("store.64 [sp + 0x20] = x22, x21"), "store.64 [sp + ] = x22, x21");
    assert_eq!(il_key("sp = sp - 0x40"), "sp = sp - 0x40", "the frame size stays");
    assert_eq!(il_key("x1 = &\"usage\""), "x1 = &\"usage\"");
    assert_eq!(il_key("x1 = &\"DEVPATH\"[3]"), "x1 = &@", "a pointer into a text moves");
    assert_eq!(il_key("x1 = load.64 [\"a\\\"b\"[1]]"), "x1 = load.64 [@]", "past an escaped quote");
    assert_eq!(il_key("x1 = &\"[2]\""), "x1 = &\"[2]\"", "a text that holds brackets");
    assert_eq!(il_key("x = \"a\"[x]"), "x = \"a\"[x]", "no number in the brackets");
    assert_eq!(il_key("x = \"open"), "x = \"open", "a text with no end");
    assert_ne!(il_shape("w0 = w1 + 1"), il_shape("w0 = w1 - 1"));
}

/// The IL statements of the AArch64 `words`, with their instructions.
fn il_side(words: &[u32]) -> IlSide<'static> {
    let arch: &dyn Arch = &hereticus_il::arch::aarch64::Aarch64;
    let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let insns = decode_all(arch, &code, 0x1000).0;
    IlSide::new(arch, &code, insns, None)
}

/// Fold the IL statements of `before` against those of `after`.
fn fold_il(before: &[u32], after: &[u32], steps: &[Step]) -> Vec<DiffLine> {
    fold_il_runs(steps, &il_side(before), &il_side(after))
}

/// A statement where only a register changed is the same, and one where
/// a constant changed is changed. A compare and its branch fold as a run.
#[test]
fn an_il_statement_folds_on_its_instruction() {
    const ADD_X3_X20_4: u32 = 0x9100_1283;
    const ADD_X3_X19_4: u32 = 0x9100_1263;
    const ADD_X3_X20_8: u32 = 0x9100_2283;
    let one_pair = [Step::Left, Step::Right];
    assert!(matches!(
        fold_il(&[ADD_X3_X20_4], &[ADD_X3_X19_4], &one_pair)[..],
        [DiffLine::Same(_)]
    ));
    assert!(matches!(
        fold_il(&[ADD_X3_X20_4], &[ADD_X3_X20_8], &one_pair)[..],
        [DiffLine::Changed { .. }]
    ));

    // `cmp x23, x0; b.ne` against `cmp x20, x0; b.ne`.
    const B_NE: u32 = 0x54ff_ff21;
    let folded = fold_il(
        &[0xeb00_02ff, B_NE],
        &[0xeb00_029f, B_NE],
        &[Step::Left, Step::Left, Step::Right, Step::Right],
    );
    assert!(folded.iter().all(|line| matches!(line, DiffLine::Same(_))), "{folded:?}");

    // `add w0, w1, 1` against `add w0, w1, 2; blr x1`.
    let grew = fold_il(
        &[0x1100_0420],
        &[0x1100_0820, 0xd63f_0020],
        &[Step::Left, Step::Right, Step::Right],
    );
    assert!(matches!(grew[..], [DiffLine::Changed { .. }, DiffLine::Added(_)]), "{grew:?}");
}

/// A call whose target moved is a free choice, but not where the IL
/// view names another callee: the name is no word of the instruction.
#[test]
fn an_il_statement_with_another_callee_is_no_same_line() {
    let side = |word: u32, text: &str| {
        let mut side = il_side(&[word]);
        side.statements[0].text = text.to_string();
        side
    };
    // `bl` to two places.
    let (before, after) = (side(0x9400_0010, "call foo"), side(0x9400_0020, "call bar"));
    let folded = fold_il_runs(&[Step::Left, Step::Right], &before, &after);
    assert!(matches!(folded[..], [DiffLine::Removed(_), DiffLine::Added(_)]), "{folded:?}");
    let renamed = side(0x9400_0020, "call foo");
    let folded = fold_il_runs(&[Step::Left, Step::Right], &before, &renamed);
    assert!(matches!(folded[..], [DiffLine::Same(_)]), "{folded:?}");
}

/// A text that changed only in a mark, as `"PATH"` to `"PATH="` in the
/// `procd` fix of CVE-2026-30874, is no same line, though its words agree.
#[test]
fn an_il_statement_with_another_text_is_no_same_line() {
    let side = |text: &str| {
        // `adr x3, $+0x40`, so the instruction is the same on both sides.
        let mut side = il_side(&[0x1000_0203]);
        side.statements[0].text = text.to_string();
        side
    };
    let steps = [Step::Left, Step::Right];
    let folded = fold_il_runs(&steps, &side("x3 = &\"PATH\""), &side("x3 = &\"PATH=\""));
    assert!(!matches!(folded[..], [DiffLine::Same(_)]), "{folded:?}");
    let folded = fold_il_runs(&steps, &side("x3 = &\"PATH\""), &side("x3 = &\"PATH\""));
    assert!(matches!(folded[..], [DiffLine::Same(_)]), "{folded:?}");
}

#[test]
fn texts_differ_by_what_they_do_not_share() {
    assert_eq!(texts_that_differ(&[], &[]), 0);
    assert_eq!(texts_that_differ(&["a", "b"], &["a", "b"]), 0);
    assert_eq!(texts_that_differ(&["a", "b"], &["a", "c"]), 1, "one changed in place");
    assert_eq!(texts_that_differ(&["a"], &["a", "b"]), 1, "one added");
    assert_eq!(texts_that_differ(&["a", "a"], &["a"]), 1, "a repeat counts");
    assert_eq!(texts_that_differ(&["a", "b"], &["c"]), 2);
}

#[test]
fn a_text_that_differs_only_by_its_build_directory_is_no_change() {
    let apple = |root: &str| {
        format!(
            "/AppleInternal/Library/BuildRoots/{root}/Library/Sources/AppleHIDTransport/hid.cpp"
        )
    };
    let (old, new) = (apple("4~Bq7XzA9kLm2"), apple("7~Cv3YwD1nPo8"));
    assert!(differ_only_by_build_path(&old, &new));
    assert_eq!(texts_that_differ(&[old.as_str(), "x"], &[new.as_str(), "x"]), 0);
    assert!(differ_only_by_build_path(
        "/build/glibc-SzIz7B/malloc/malloc.c",
        "/build/glibc-Ab1cDe/malloc/malloc.c"
    ));
}

#[test]
fn a_changed_file_or_message_still_shows() {
    let differ = differ_only_by_build_path;
    assert!(!differ("/src/file12.c", "/src/file34.c"), "a file name");
    assert!(!differ("/build/glibc-SzIz7B/a.c", "/build/glibc-Ab1cDe/b.c"), "another file too");
    assert!(!differ("/build/glibc-SzIz7B/a.c", "/build/glibc-Ab1cD/a.c"), "another length");
    assert!(!differ("bad length %d", "bad size %d"), "no path");
    assert!(!differ("/a/b", "/a/b"), "no difference");
    assert!(!differ("/a/b/c", "/a/b"), "another depth");
    assert_eq!(texts_that_differ(&["/src/file12.c"], &["/src/file34.c"]), 1);
}

/// One ARM function at 0x8000 that passes the text at 0x9001 on, with
/// that text after a NUL.
fn passes_text(text: &str) -> hereticus_image::Binary {
    let words = [
        0xe59f_0004_u32, // 0x8000 ldr r0, [pc, 0x4]: the word at 0x800c
        0xe08f_0000,     // 0x8004 add r0, pc, r0
        0xe12f_ff1e,     // 0x8008 bx lr
        0x9001 - 0x800c, // 0x800c the distance to the text
    ];
    let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let data = [&[0], text.as_bytes(), &[0]].concat();
    hereticus_image::Binary {
        isa: Isa::Arm32,
        found_by: hereticus_image::FoundBy::Symbols,
        addresses: hereticus_memory::AddressSpace::of_raw_image(0x8000, 0x880),
        other_set: std::collections::BTreeSet::new(),
        links: hereticus_image::Links::of_parts(
            vec![(0x8000, code.clone()), (0x9000, data)],
            BTreeMap::new(),
        ),
        functions: vec![Function { name: "f".to_string(), address: 0x8000, code }],
    }
}

/// Code that stayed the same around a changed text changed in detail.
#[test]
fn a_changed_text_is_a_change() {
    let diff = diff_with(&passes_text("hello"), &passes_text("howdy"), Options::default());
    let pair = &diff.matched[0];
    assert_eq!(pair.changed, Changed::InDetail);
    assert_eq!(pair.kinds.texts, 1);

    let same = diff_with(&passes_text("hello"), &passes_text("hello"), Options::default());
    assert_eq!(same.matched[0].changed, Changed::No);
}

/// [`passes_text`], with `sub r0, r0, r1` added before the return.
fn passes_text_and_subtracts(text: &str) -> hereticus_image::Binary {
    let words = [
        0xe59f_0008_u32, // 0x8000 ldr r0, [pc, 0x8]: the word at 0x8010
        0xe08f_0000,     // 0x8004 add r0, pc, r0
        SUB,             // 0x8008
        0xe12f_ff1e,     // 0x800c bx lr
        0x9001 - 0x800c, // 0x8010 the distance to the text
    ];
    let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let mut binary = passes_text(text);
    binary.links = hereticus_image::Links::of_parts(
        vec![(0x8000, code.clone()), (0x9000, [&[0], text.as_bytes(), &[0]].concat())],
        BTreeMap::new(),
    );
    binary.functions[0].code = code;
    binary
}

/// A text that changes in a pair whose code changed too counts, and the
/// pair keeps its verdict.
#[test]
fn a_changed_text_counts_in_a_changed_pair() {
    let diff =
        diff_with(&passes_text("hello"), &passes_text_and_subtracts("howdy"), Options::default());
    let pair = &diff.matched[0];
    assert_eq!(pair.changed, Changed::Yes);
    assert_eq!(pair.kinds.texts, 1);

    let same =
        diff_with(&passes_text("hello"), &passes_text_and_subtracts("hello"), Options::default());
    assert_eq!(same.matched[0].changed, Changed::Yes);
    assert_eq!(same.matched[0].kinds.texts, 0);
}

/// A text shorter than a word can be a pointer or a number by chance.
#[test]
fn a_changed_short_text_is_no_change() {
    let diff = diff_with(&passes_text("ab"), &passes_text("cd"), Options::default());
    assert_eq!(diff.matched[0].changed, Changed::No);
    assert_eq!(diff.matched[0].kinds.texts, 0);
}

/// A key counts as common where more than `MOST_HOLDERS_OF_AN_EDGE`
/// functions hold it, and a repeat within one function counts once.
#[test]
fn a_key_is_common_past_the_most_holders() {
    let key = |name: &str| ReferenceKey::Named(name.to_string());
    let mut keys = vec![vec![key("kfree"), key("kfree"), key("rare")]];
    keys.extend((0..MOST_HOLDERS_OF_AN_EDGE - 1).map(|_| vec![key("kfree"), key("often")]));
    assert!(common_keys(&keys).is_empty(), "{} holders is not too many", keys.len());

    keys.push(vec![key("kfree")]);
    let common = common_keys(&keys);
    assert!(common.contains(&key("kfree")));
    assert!(!common.contains(&key("often")) && !common.contains(&key("rare")));
}

#[test]
fn references_agree_by_what_they_share() {
    let key = |name: &str| ReferenceKey::Named(name.to_string());
    let (exp, log) = (key("exp"), key("log10"));
    assert_eq!(reference_agreement(&[], &[]), 0.0, "nothing to say");
    let (only_exp, only_log) = (core::slice::from_ref(&exp), core::slice::from_ref(&log));
    assert_eq!(reference_agreement(only_exp, only_exp), 1.0);
    assert_eq!(reference_agreement(only_exp, only_log), -1.0);
    assert_eq!(reference_agreement(only_exp, &[]), -1.0, "one calls, one does not");
    let (mut both, one) = (vec![exp.clone(), log], vec![exp]);
    both.sort();
    assert_eq!(reference_agreement(&both, &one), 0.0, "half shared");
    assert_eq!(reference_agreement(&[ReferenceKey::Paired(3)], &[ReferenceKey::Paired(3)]), 1.0);
    let text = |text: &str| ReferenceKey::Text(text.to_string());
    assert_eq!(reference_agreement(&[text("<!--")], &[text("<!--")]), 1.0);
    assert_eq!(reference_agreement(&[text("<!--")], &[text("=\"")]), -1.0);
}

/// A MIPS table of pointers into its own image, after a `jr ra`.
fn pointer_table(first: u32) -> Vec<u8> {
    let mut words = vec![0x03e0_0008u32, 0];
    words.extend((0..64).map(|index| first + index * 0x40));
    words.iter().flat_map(|word| word.to_be_bytes()).collect()
}

fn raw_mips(code: &[u8]) -> hereticus_image::Binary {
    hereticus_image::Binary {
        isa: Isa::Mips32Be,
        found_by: hereticus_image::FoundBy::Scanning,
        addresses: AddressSpace::of_raw_image(0x8000_0000, 0x10_0000),
        links: hereticus_image::Links::default(),
        other_set: std::collections::BTreeSet::new(),
        functions: vec![Function {
            name: String::new(),
            address: 0x8000_0000,
            code: code.to_vec(),
        }],
    }
}

/// A function that returns 1, at 0x80002000, big endian.
fn returns_one() -> Function {
    let words = [0x2402_0001u32, 0x03e0_0008, 0];
    Function {
        name: String::new(),
        address: 0x8000_2000,
        code: words.iter().flat_map(|word| word.to_be_bytes()).collect(),
    }
}

/// `bl target` from `from`, little endian.
fn bl(from: u64, target: u64) -> [u8; 4] {
    let offset = (target.wrapping_sub(from).wrapping_sub(8) as u32 >> 2) & 0x00ff_ffff;
    (0xeb00_0000 | offset).to_le_bytes()
}

/// `mov r0, value; bx lr`, little endian.
fn returns(value: u8) -> Vec<u8> {
    [[value, 0x00, 0xa0, 0xe3], [0x1e, 0xff, 0x2f, 0xe1]].concat()
}

/// A caller at 0x0 that calls the function at `callee`, then returns.
fn caller_of(callee: u64) -> Vec<u8> {
    [bl(0, callee).as_slice(), &[0x1e, 0xff, 0x2f, 0xe1]].concat()
}

/// Code that calls a different function changed, though normalizing
/// alone reads it as the same, with or without names.
#[test]
fn a_call_to_a_different_function_is_a_change() {
    for names in [["caller", "one", "two"], ["", "", ""]] {
        let before = binary_of(&[
            (names[0], &caller_of(0x100)),
            (names[1], &returns(1)),
            (names[2], &returns(2)),
        ]);
        let after = binary_of(&[
            (names[0], &caller_of(0x200)),
            (names[1], &returns(1)),
            (names[2], &returns(2)),
        ]);
        let diff = diff_with(&before, &after, Options { threshold: 0.0, ..Options::default() });

        let caller = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
        assert_eq!(caller.changed, Changed::Yes, "names {names:?}");
        assert_eq!(caller.kinds.callees, 1, "names {names:?}");
        assert!(caller.kinds.touches_control_flow());
    }
}

/// A caller at 0x0 that calls the function at `callee`, then runs `work`.
fn caller_running(callee: u64, work: &[u32]) -> Vec<u8> {
    bl(0, callee).into_iter().chain(work.iter().flat_map(|word| word.to_le_bytes())).collect()
}

/// Code that adds an instruction and calls a different function in the
/// same place counts the callee too, as the `procd` fix of CVE-2026-30874
/// does: the diff lines up the two calls.
#[test]
fn a_changed_pair_counts_a_call_kept_in_place_to_another_function() {
    let options = Options { threshold: 0.0, ..Options::default() };
    let before_work = [ADD, ADD, ADD, BX_LR];
    let after_work = [ADD, ADD, SUB, ADD, BX_LR];
    for names in [["caller", "one", "two"], ["", "", ""]] {
        let side = |callee: u64, work: &[u32]| {
            binary_of(&[
                (names[0], &caller_running(callee, work)),
                (names[1], &returns(1)),
                (names[2], &returns(2)),
            ])
        };
        let before = side(0x100, &before_work);

        let diff = diff_with(&before, &side(0x200, &after_work), options);
        let caller = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
        assert_eq!(caller.changed, Changed::Yes, "names {names:?}");
        assert_eq!(caller.edits.added, 1, "names {names:?}");
        assert_eq!(caller.kinds.callees, 1, "names {names:?}");

        let diff = diff_with(&before, &side(0x100, &after_work), options);
        let caller = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
        assert_eq!(caller.kinds.callees, 0, "the same callee, names {names:?}");
    }
}

/// A call that turns from `strcmp` into `strncmp` counts as bounded, in a
/// pair whose code changed and in one whose code agrees; a call that turns
/// into `memcmp` does not.
#[test]
fn a_call_turned_into_its_bounded_form_counts() {
    let options = Options { threshold: 0.0, ..Options::default() };
    let side = |callee: u64, work: &[u32]| {
        binary_of(&[
            ("caller", &caller_running(callee, work)),
            ("strcmp", &returns(1)),
            ("strncmp", &returns(2)),
            ("memcmp", &returns(3)),
        ])
    };
    let before = side(0x100, &[ADD, ADD, ADD, BX_LR]);
    for (after_work, changed) in
        [(&[ADD, ADD, SUB, ADD, BX_LR][..], "code changed"), (&[ADD, ADD, ADD, BX_LR], "same code")]
    {
        let diff = diff_with(&before, &side(0x200, after_work), options);
        let caller = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
        assert_eq!((caller.kinds.callees, caller.bounded_calls), (1, 1), "{changed}");

        let diff = diff_with(&before, &side(0x300, after_work), options);
        let caller = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
        assert_eq!((caller.kinds.callees, caller.bounded_calls), (1, 0), "memcmp, {changed}");
    }
}

/// An edit that adds a test and a return where it fails counts one check
/// before an early exit; one that adds a test before more work does not.
#[test]
fn a_check_before_an_early_return_counts() {
    const CMP_R0_0: u32 = 0xe350_0000;
    const BNE_OVER_TWO: u32 = 0x1a00_0000;
    const MVN_R0_0: u32 = 0xe3e0_0000;
    let options = Options { threshold: 0.0, ..Options::default() };
    let before = binary_of(&[("f", &arm(&[ADD, ADD, ADD, BX_LR]))]);

    let checked = [CMP_R0_0, BNE_OVER_TWO, MVN_R0_0, BX_LR, ADD, ADD, ADD, BX_LR];
    let diff = diff_with(&before, &binary_of(&[("f", &arm(&checked))]), options);
    assert_eq!(diff.matched[0].changed, Changed::Yes);
    assert_eq!(diff.matched[0].early_exits, 1);

    let mut longer = vec![CMP_R0_0, 0x1a00_0001]; // bne into the work
    longer.extend([SUB; 10]);
    longer.extend([ADD, ADD, ADD, BX_LR]);
    let diff = diff_with(&before, &binary_of(&[("f", &arm(&longer))]), options);
    assert_eq!(diff.matched[0].early_exits, 0, "the branch leads to more work");

    let diff = diff_with(&before, &before, options);
    assert_eq!(diff.matched[0].early_exits, 0, "no edit");
}

/// A call the edit removes lines up with no call, so its callee counts
/// as no changed callee.
#[test]
fn a_call_the_edit_removes_counts_no_changed_callee() {
    let options = Options { threshold: 0.0, ..Options::default() };
    let before = binary_of(&[
        ("caller", &caller_running(0x100, &[ADD, ADD, ADD, BX_LR])),
        ("one", &returns(1)),
        ("two", &returns(2)),
    ]);
    let after = binary_of(&[
        ("caller", &arm(&[ADD, ADD, ADD, SUB, BX_LR])),
        ("one", &returns(1)),
        ("two", &returns(2)),
    ]);
    let diff = diff_with(&before, &after, options);
    let caller = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
    assert_eq!(caller.changed, Changed::Yes);
    assert_eq!(caller.kinds.callees, 0);
}

/// Four leaves at 0x0 to 0x300 that pair by their bytes, and at 0x400 a
/// function that calls the two at `callees`, then runs `work`.
fn calling_two_leaves(callees: [u64; 2], work: &[u32]) -> hereticus_image::Binary {
    let caller: Vec<u8> = [bl(0x400, callees[0]), bl(0x404, callees[1])]
        .into_iter()
        .flatten()
        .chain(work.iter().flat_map(|word| word.to_le_bytes()))
        .collect();
    let leaves = [returns(1), returns(2), returns(3), returns(4)];
    let [one, two, three, four] = &leaves;
    binary_of(&[("", one), ("", two), ("", three), ("", four), ("", &caller)])
}

/// A function whose callees all paired with what its look-alike does not
/// call pairs with nothing; one that calls their partners pairs.
#[test]
fn a_pair_whose_paired_neighbours_disagree_is_undone() {
    let blind = Options { use_names: UseNames::No, ..Default::default() };
    let before = calling_two_leaves([0x000, 0x100], &[ADD, SUB, ORR, EOR, AND, BX_LR]);
    let edited = [ADD, SUB, ORR, EOR, BIC, BX_LR];

    let elsewhere = calling_two_leaves([0x200, 0x300], &edited);
    let diff = diff_with(&before, &elsewhere, blind);
    assert_eq!((diff.removed.as_slice(), diff.added.as_slice()), ([4].as_slice(), [4].as_slice()));

    let same_callees = calling_two_leaves([0x000, 0x100], &edited);
    let diff = diff_with(&before, &same_callees, blind);
    let pair = diff.matched.iter().find(|pair| pair.before == 4).expect("paired");
    assert_eq!((pair.after, pair.confidence), (4, Confidence::Similar));
}

/// Two leaves at 0x0 and 0x100, three anchors from 0x200, and at 0x500,
/// between the second and the third anchor, a function that calls the
/// leaf at `callee`, then runs `work`.
fn weak_pair_calling(callee: u64, work: &[u32]) -> hereticus_image::Binary {
    let caller: Vec<u8> = bl(0x500, callee)
        .into_iter()
        .chain(work.iter().flat_map(|word| word.to_le_bytes()))
        .collect();
    let functions = [
        returns(1),
        returns(2),
        arm(&[ADC, SBC, RSB, BX_LR]),
        arm(&[MUL, MUL, ADC, BX_LR]),
        arm(&[RSB, RSB, BX_LR]),
        caller,
        arm(&[SBC, SBC, SBC, BX_LR]),
    ];
    let named: Vec<(&str, &[u8])> = functions.iter().map(|code| ("", code.as_slice())).collect();
    binary_of(&named)
}

/// A pair by place that scores low, whose one paired callee pairs with
/// what its partner does not call, pairs with nothing.
#[test]
fn a_weak_pair_whose_one_paired_neighbour_disagrees_is_undone() {
    let blind = Options { use_names: UseNames::No, ..Default::default() };
    let before = weak_pair_calling(0x000, &[ADD, SUB, ORR, EOR, AND, BIC, BX_LR]);
    let rewritten = [ADD, MUL, MUL, MUL, MUL, MUL, BX_LR];

    let same_callee = weak_pair_calling(0x000, &rewritten);
    let diff = diff_with(&before, &same_callee, blind);
    let pair = diff.matched.iter().find(|pair| pair.before == 5).expect("paired");
    assert_eq!((pair.after, pair.confidence), (5, Confidence::SameLayout));
    assert!(pair.score < WEAK_PAIR_SIMILARITY, "{pair:?}");

    let other_callee = weak_pair_calling(0x100, &rewritten);
    let diff = diff_with(&before, &other_callee, blind);
    assert_eq!((diff.removed.as_slice(), diff.added.as_slice()), ([5].as_slice(), [5].as_slice()));
}

/// Two leaves at 0x0 and 0x100, four anchors, and a function that calls
/// the leaf at `callee`, then runs `work`: after the first anchor where
/// `moved` is false, and after the last where it is true.
fn similar_pair_calling(callee: u64, work: &[u32], moved: bool) -> hereticus_image::Binary {
    let place: u64 = if moved { 6 } else { 3 };
    let caller: Vec<u8> = bl(place * 0x100, callee)
        .into_iter()
        .chain(work.iter().flat_map(|word| word.to_le_bytes()))
        .collect();
    let mut functions = vec![
        returns(1),
        returns(2),
        arm(&[ADC, SBC, RSB, BX_LR]),
        arm(&[MUL, MUL, ADC, BX_LR]),
        arm(&[RSB, RSB, BX_LR]),
        arm(&[SBC, SBC, SBC, BX_LR]),
    ];
    functions.insert(place as usize, caller);
    let named: Vec<(&str, &[u8])> = functions.iter().map(|code| ("", code.as_slice())).collect();
    binary_of(&named)
}

/// A pair by similarity whose sides sit in different places, and whose
/// one paired callee pairs with what its partner does not call, pairs
/// with nothing. In its place, or with the callee agreeing, it pairs.
#[test]
fn a_pair_out_of_place_whose_one_paired_neighbour_disagrees_is_undone() {
    let blind = Options { use_names: UseNames::No, ..Default::default() };
    let before = similar_pair_calling(0x000, &[ADD, SUB, ORR, EOR, AND, BX_LR], false);
    let edited = [ADD, SUB, ORR, EOR, BIC, BX_LR];
    let pair_of_caller = |after: &hereticus_image::Binary| {
        let diff = diff_with(&before, after, blind);
        diff.matched.iter().find(|pair| pair.before == 3).map(|pair| (pair.after, pair.confidence))
    };

    assert_eq!(pair_of_caller(&similar_pair_calling(0x100, &edited, true)), None);
    assert_eq!(
        pair_of_caller(&similar_pair_calling(0x000, &edited, true)),
        Some((6, Confidence::Similar))
    );
    assert_eq!(
        pair_of_caller(&similar_pair_calling(0x100, &edited, false)),
        Some((3, Confidence::Similar))
    );
}

/// Each rule of `lacks_context`, on both sides of its bound.
#[test]
fn context_decides_by_stage_place_and_share() {
    use Confidence::{IdenticalShape, SameCallers, SameLayout, Similar};
    use Place::{Kept, Moved};
    // (stage, score, place, partners of the first side's neighbours,
    // the second side's neighbours, how many of those paired, undone)
    type Case = (Confidence, f64, Place, &'static [usize], &'static [usize], usize, bool);
    let cases: &[Case] = &[
        // Two disagreeing neighbours undo a pair by similarity anywhere.
        (Similar, 0.9, Kept, &[1, 2], &[3, 4], 2, true),
        // One is not enough in place, at a firm score.
        (Similar, 0.9, Kept, &[1], &[3], 1, false),
        // One is enough out of place, or at a weak score.
        (Similar, 0.9, Moved, &[1], &[3], 1, true),
        (SameLayout, 0.2, Kept, &[1], &[3], 1, true),
        // One that agrees keeps it.
        (Similar, 0.9, Moved, &[1, 2], &[2, 3], 2, false),
        // With no paired neighbour, nothing is said.
        (Similar, 0.2, Moved, &[], &[3], 0, false),
        // A pair by callers out of place goes under the share.
        (SameCallers, 0.5, Moved, &[1, 2, 3, 4], &[1, 5, 6, 7], 4, true),
        (SameCallers, 0.5, Moved, &[1, 2, 3], &[1, 5, 6], 3, false),
        (SameCallers, 0.5, Kept, &[1, 2, 3, 4], &[1, 5, 6, 7], 4, false),
        // A stronger stage stands.
        (IdenticalShape, 1.0, Moved, &[1, 2], &[3, 4], 2, false),
    ];
    for &(stage, score, place, left, right, paired_right, undone) in cases {
        let right: BTreeSet<usize> = right.iter().copied().collect();
        let context = Context {
            partners_of_left: left.iter().copied().collect(),
            right: &right,
            paired_right,
        };
        assert_eq!(
            lacks_context(stage, score, place, &context),
            undone,
            "{stage:?} {score} {place:?} {left:?} {right:?}"
        );
    }
}

/// `b target` from `from`, little endian.
fn b(from: u64, target: u64) -> [u8; 4] {
    let offset = (target.wrapping_sub(from).wrapping_sub(8) as u32 >> 2) & 0x00ff_ffff;
    (0xea00_0000 | offset).to_le_bytes()
}

/// Two images where the function at 0x0 is `prefix` and then reaches
/// the function at `callee` with `b`, and the callees share no code, so
/// neither pairs.
fn forwarding_to_unpaired(prefix: &[u8]) -> Diff {
    let reaching = |callee: u64| [prefix, &b(prefix.len() as u64, callee)].concat();
    // mov r0, 1; bx lr
    let one = returns(1);
    // add r0, r0, r1; mul r0, r1, r0; eor r0, r0, r1; sub r0, r0, r1:
    // nothing in common with `one`, so not even its place pairs it.
    let other: Vec<u8> = [0xe080_0001u32, 0xe000_0091, 0xe020_0001, 0xe040_0001]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    let before = binary_of(&[("", &reaching(0x100)), ("", &one)]);
    let after = binary_of(&[("", &reaching(0x100)), ("", &other)]);
    diff_with(&before, &after, Options { threshold: 0.9, use_names: UseNames::No })
}

/// A forwarder that reaches a different function changed, even where
/// neither callee pairs: what it reaches is all it does.
#[test]
fn a_forwarder_to_an_unpaired_callee_changed() {
    let diff = forwarding_to_unpaired(&[]);
    assert!(diff.removed.contains(&1) && diff.added.contains(&1), "neither callee pairs");
    let forwarder = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
    assert_eq!(forwarder.changed, Changed::Yes);
    assert_eq!(forwarder.kinds.callees, 1);
}

/// Larger code that reaches an unpaired callee says nothing about it:
/// the callee may be one function that changed too much to pair.
#[test]
fn more_than_a_forwarder_says_nothing_of_an_unpaired_callee() {
    // add r2, r2, 1
    let diff = forwarding_to_unpaired(&0xe282_2001u32.to_le_bytes());
    let caller = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
    assert_eq!(caller.changed, Changed::No);
}

/// A callee that only moved is the same callee.
#[test]
fn a_call_to_a_moved_function_is_no_change() {
    for names in [["caller", "pad", "one"], ["", "", ""]] {
        let before = binary_of(&[(names[0], &caller_of(0x100)), (names[2], &returns(1))]);
        let after = binary_of(&[
            (names[0], &caller_of(0x200)),
            (names[1], &returns(7)),
            (names[2], &returns(1)),
        ]);
        let diff = diff_with(&before, &after, Options { threshold: 0.0, ..Options::default() });

        let caller = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
        assert_eq!(caller.changed, Changed::No, "names {names:?}");
        assert_eq!(caller.kinds.callees, 0, "names {names:?}");
    }
}

/// ARM words, little endian.
fn arm(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

const ADD: u32 = 0xe080_0001;
const SUB: u32 = 0xe040_0001;
const ORR: u32 = 0xe180_0001;
const EOR: u32 = 0xe020_0001;
const AND: u32 = 0xe000_0001;
const BIC: u32 = 0xe1c0_0001;
const ADC: u32 = 0xe0a0_0001;
const SBC: u32 = 0xe0c0_0001;
const RSB: u32 = 0xe060_0001;
const MUL: u32 = 0xe000_0091;
const BX_LR: u32 = 0xe12f_ff1e;

/// A function at 0x0 that calls the three at 0x100, 0x200 and 0x300,
/// then runs `rest`.
fn calls_three_then(rest: &[u32]) -> Vec<u8> {
    let calls: Vec<u32> = [0x100, 0x200, 0x300]
        .iter()
        .enumerate()
        .map(|(slot, &target)| u32::from_le_bytes(bl(slot as u64 * 4, target)))
        .collect();
    arm(&[calls.as_slice(), rest].concat())
}

/// Code at `base` that calls the functions at 0x100, 0x200 and 0x300,
/// then runs `rest`.
fn calls_three_from(base: u64, rest: &[u32]) -> Vec<u8> {
    let calls: Vec<u32> = [0x100, 0x200, 0x300]
        .iter()
        .enumerate()
        .map(|(slot, &target)| u32::from_le_bytes(bl(base + slot as u64 * 4, target)))
        .collect();
    arm(&[calls.as_slice(), rest].concat())
}

/// Of two free candidates with the same context and the same code,
/// context joins neither; the function then pairs by its place.
#[test]
fn context_joins_neither_of_two_alike() {
    let before_code = calls_three_from(0, &[ADD, SUB, ORR, EOR, AND, BIC, ADC, SBC, BX_LR]);
    let after_code = |base| calls_three_from(base, &[ADD, SUB, MUL, BX_LR]);
    let [one, two, three] = [returns(1), returns(2), returns(3)];
    let before = binary_of(&[("", &before_code), ("", &one), ("", &two), ("", &three)]);
    let after = binary_of(&[
        ("", &after_code(0)),
        ("", &one),
        ("", &two),
        ("", &three),
        ("", &after_code(0x400)),
    ]);

    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    let pair = diff.matched.iter().find(|pair| pair.before == 0);
    assert_eq!(pair.map(|pair| (pair.after, pair.confidence)), Some((0, Confidence::SameLayout)));
}

/// A function rewritten past the threshold pairs with itself by the
/// functions it calls, and not with a free look-alike that calls none.
#[test]
fn a_rewritten_function_pairs_by_its_context() {
    let before_code = calls_three_then(&[ADD, SUB, ORR, EOR, AND, BIC, ADC, SBC, BX_LR]);
    let after_code = calls_three_then(&[ADD, SUB, MUL, BX_LR]);
    let look_alike = arm(&[ADD, SUB, ORR, EOR, AND, BIC, ADC, SBC, BX_LR, RSB]);
    let [one, two, three] = [returns(1), returns(2), returns(3)];
    let before = binary_of(&[("", &before_code), ("", &one), ("", &two), ("", &three)]);
    let after =
        binary_of(&[("", &after_code), ("", &one), ("", &two), ("", &three), ("", &look_alike)]);

    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    let partner = diff.matched.iter().find(|pair| pair.before == 0).map(|pair| pair.after);
    assert_eq!(partner, Some(0));
    assert_eq!(diff.added, vec![4]);
}

/// A function rewritten past the threshold pairs with the one function
/// that holds its constant, and not with a look-alike that lacks it.
#[test]
fn a_unique_constant_pairs_a_rewritten_function() {
    const MOVW_1234: u32 = 0xe301_0234;
    let before = binary_of(&[("", &arm(&[MOVW_1234, ADD, SUB, ORR, EOR, BX_LR]))]);
    let after = binary_of(&[
        ("", &arm(&[ADD, SUB, ORR, EOR, AND, BX_LR])),
        ("", &arm(&[MOVW_1234, ADD, MUL, MUL, MUL, BX_LR])),
    ]);

    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    let pair = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
    assert_eq!((pair.after, pair.confidence), (1, Confidence::SameReferences));
    assert_eq!(diff.added, vec![0]);
}

/// The one caller of a function already paired pairs with its one
/// caller on the other side, though a look-alike scores higher.
#[test]
fn the_one_caller_of_a_paired_function_pairs() {
    let call = u32::from_le_bytes(bl(0, 0x100));
    let before = binary_of(&[("", &arm(&[call, ADD, SUB, ORR, EOR, BX_LR])), ("", &returns(1))]);
    let after = binary_of(&[
        ("", &arm(&[call, ADD, MUL, MUL, MUL, BX_LR])),
        ("", &returns(1)),
        ("", &arm(&[ADD, SUB, ORR, EOR, AND, BX_LR])),
    ]);

    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    let pair = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
    assert_eq!((pair.after, pair.confidence), (0, Confidence::SameReferences));
    assert_eq!(diff.added, vec![2]);
}

/// The one function that calls both of two paired functions pairs, where
/// other functions call each of them alone.
#[test]
fn the_one_caller_of_a_set_of_paired_functions_pairs() {
    let call = |from: u64, to: u64| u32::from_le_bytes(bl(from, to));
    let calls_both = |rest: &[u32]| arm(&[&[call(0, 0x300), call(4, 0x400)], rest].concat());
    let calls_a = arm(&[call(0x100, 0x300), RSB, RSB, BX_LR]);
    let calls_b = arm(&[call(0x200, 0x400), BIC, BIC, BX_LR]);
    let [a, b] = [returns(1), returns(2)];
    let before = binary_of(&[
        ("", &calls_both(&[ADD, SUB, ORR, EOR, BX_LR])),
        ("", &calls_a),
        ("", &calls_b),
        ("", &a),
        ("", &b),
    ]);
    let after = binary_of(&[
        ("", &calls_both(&[ADD, MUL, MUL, MUL, BX_LR])),
        ("", &calls_a),
        ("", &calls_b),
        ("", &a),
        ("", &b),
        ("", &arm(&[ADD, SUB, ORR, EOR, AND, BX_LR])),
    ]);

    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    let pair = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
    assert_eq!((pair.after, pair.confidence), (0, Confidence::SameReferences));
    assert_eq!(diff.added, vec![5]);
}

/// A pair by name stays, though its constant moved to another function.
#[test]
fn a_unique_constant_does_not_break_a_pair_by_name() {
    const MOVW_1234: u32 = 0xe301_0234;
    let before = binary_of(&[("foo", &arm(&[MOVW_1234, ADD, SUB, ORR, EOR, BX_LR]))]);
    let after = binary_of(&[
        ("foo", &arm(&[ADD, SUB, ORR, EOR, AND, BX_LR])),
        ("bar", &arm(&[MOVW_1234, ADD, MUL, MUL, MUL, BX_LR])),
    ]);

    let diff = diff_with(&before, &after, Options::default());
    let pair = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
    assert_eq!((pair.after, pair.confidence), (0, Confidence::SameName));
    assert_eq!(diff.added, vec![1]);
}

/// A constant that two functions of one side hold tells neither apart.
#[test]
fn a_constant_held_twice_pairs_nothing() {
    const MOVW_1234: u32 = 0xe301_0234;
    let before = binary_of(&[
        ("", &arm(&[MOVW_1234, ADD, SUB, ORR, EOR, BX_LR])),
        ("", &arm(&[MOVW_1234, RSB, RSB, RSB, BX_LR])),
    ]);
    let after = binary_of(&[
        ("", &arm(&[ADD, SUB, ORR, EOR, AND, BX_LR])),
        ("", &arm(&[MOVW_1234, ADD, MUL, MUL, MUL, BX_LR])),
    ]);

    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    assert!(diff.matched.iter().all(|pair| pair.confidence != Confidence::SameReferences));
}

/// Code too far apart does not pair, whatever constant it shares.
#[test]
fn a_unique_constant_needs_some_code_in_common() {
    const MOVW_1234: u32 = 0xe301_0234;
    let before = binary_of(&[("", &arm(&[MOVW_1234, ADD, SUB, ORR, EOR, AND, BIC, BX_LR]))]);
    let after = binary_of(&[("", &arm(&[MOVW_1234, MUL, MUL, MUL, MUL, RSB, RSB, RSB]))]);

    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    assert!(diff.matched.iter().all(|pair| pair.confidence != Confidence::SameReferences));
}

/// Of two candidates that score the same, the one that keeps the
/// constants pairs.
#[test]
fn a_shared_constant_breaks_a_tie() {
    const MOVW_1234: u32 = 0xe301_0234;
    const MOVW_5678: u32 = 0xe305_0678;
    let before = binary_of(&[("", &arm(&[MOVW_1234, ADD, SUB, BX_LR]))]);
    let after = binary_of(&[
        ("", &arm(&[MOVW_5678, ADD, SUB, ORR, BX_LR])),
        ("", &arm(&[MOVW_1234, ADD, SUB, EOR, BX_LR])),
    ]);

    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    assert_eq!(diff.matched.len(), 1);
    assert_eq!(diff.matched[0].after, 1);
}

#[test]
fn constants_agree_by_what_they_share() {
    assert_eq!(constant_agreement(&[], &[]), 0.0);
    assert_eq!(constant_agreement(&[5, 9], &[5, 9]), 1.0);
    assert_eq!(constant_agreement(&[5], &[9]), -1.0);
    assert_eq!(constant_agreement(&[], &[9]), -1.0);
}

/// An addition few pairs share weighs more than one many pairs share,
/// and an unchanged pair weighs nothing.
#[test]
fn a_rare_addition_weighs_more() {
    let before = binary_of(&[
        ("a", &arm(&[ADD, ORR, BX_LR])),
        ("b", &arm(&[ADD, EOR, BX_LR])),
        ("c", &arm(&[ADD, AND, BX_LR])),
        ("d", &arm(&[ADC, SBC, BX_LR])),
    ]);
    let after = binary_of(&[
        ("a", &arm(&[ADD, ORR, SUB, BX_LR])),
        ("b", &arm(&[ADD, EOR, SUB, BX_LR])),
        ("c", &arm(&[ADD, AND, MUL, BX_LR])),
        ("d", &arm(&[ADC, SBC, BX_LR])),
    ]);

    let diff = diff(&before, &after);
    let rarity = |index: usize| {
        diff.matched.iter().find(|pair| pair.before == index).map(|pair| pair.rarity)
    };
    // Three pairs changed. Two add `sub` and one adds `mul`.
    let close =
        |found: Option<f64>, expected: f64| (found.expect("paired") - expected).abs() < 1e-9;
    assert!(close(rarity(0), 1.0 + (4.0f64 / 3.0).ln()), "{:?}", rarity(0));
    assert!(close(rarity(1), 1.0 + (4.0f64 / 3.0).ln()));
    assert!(close(rarity(2), 1.0 + 2.0f64.ln()));
    assert_eq!(rarity(3), Some(0.0));
}

/// One copy weighs one, each more copy weighs less than the last, and
/// no count passes `SATURATION + 1`.
#[test]
fn copies_of_an_addition_saturate() {
    assert!((saturated(1) - 1.0).abs() < 1e-12);
    let weights: Vec<f64> = (1..200).map(saturated).collect();
    for step in weights.windows(3) {
        assert!(step[1] > step[0], "more copies weigh more");
        assert!(step[2] - step[1] < step[1] - step[0], "each copy adds less");
    }
    assert!(weights.iter().all(|&weight| weight < SATURATION + 1.0));
}

#[test]
fn only_in_counts_a_multiset() {
    assert_eq!(sorted_only_in(&[1, 2, 2, 3], &[2, 3, 4]), vec![1, 2]);
    assert_eq!(sorted_only_in::<u32>(&[], &[1]), Vec::<u32>::new());
    assert_eq!(sorted_only_in(&[5, 5], &[]), vec![5, 5]);
}

/// Of two candidates that rank the same, the similarity stage takes
/// neither; with one clearly better, it takes that one.
#[test]
fn a_tie_between_candidates_pairs_neither() {
    let before = binary_of(&[("", &arm(&[ADD, SUB, ORR, EOR, BX_LR]))]);
    let tie = binary_of(&[
        ("", &arm(&[ADD, SUB, ORR, EOR, AND, BX_LR])),
        ("", &arm(&[ADD, SUB, ORR, EOR, BIC, BX_LR])),
    ]);
    let blind = Options { use_names: UseNames::No, ..Default::default() };
    let diff = diff_with(&before, &tie, blind);
    assert!(diff.matched.is_empty(), "{:?}", diff.matched);

    let clear = binary_of(&[
        ("", &arm(&[ADD, SUB, ORR, EOR, AND, BX_LR])),
        ("", &arm(&[ADD, SUB, MUL, MUL, BIC, BX_LR])),
    ]);
    let diff = diff_with(&before, &clear, blind);
    let pair = diff.matched.iter().find(|pair| pair.before == 0).expect("paired");
    assert_eq!((pair.after, pair.confidence), (0, Confidence::Similar));
}

/// A function rewritten past the threshold pairs by its place between
/// two pairs, where as many free functions sit there on both sides.
#[test]
fn a_rewritten_function_pairs_by_its_place() {
    let first = arm(&[ADC, SBC, RSB, BX_LR]);
    let last = arm(&[MUL, MUL, ADC, BX_LR]);
    let before_code = arm(&[ADD, SUB, ORR, EOR, AND, BIC, BX_LR]);
    let after_code = arm(&[ADD, MUL, MUL, MUL, MUL, MUL, BX_LR]);
    let before = binary_of(&[("", &first), ("", &before_code), ("", &last)]);
    let after = binary_of(&[("", &first), ("", &after_code), ("", &last)]);

    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    let pair = diff.matched.iter().find(|pair| pair.before == 1).expect("paired by place");
    assert_eq!((pair.after, pair.confidence), (1, Confidence::SameLayout));
}

/// A function that paired by similarity with a look-alike out of
/// order pairs again by its place, where the look-alike is not close.
#[test]
fn a_pair_out_of_order_pairs_again_by_place() {
    let anchors =
        [arm(&[ADC, SBC, RSB, BX_LR]), arm(&[MUL, MUL, ADC, BX_LR]), arm(&[RSB, RSB, BX_LR])];
    let before_code = arm(&[ADD, SUB, ORR, EOR, AND, BIC, BX_LR]);
    let rewritten = arm(&[ADD, MUL, MUL, MUL, MUL, MUL, BX_LR]);
    // Scores 0.78, below `LOWEST_MOVED_SIMILARITY`.
    let look_alike = arm(&[ADD, SUB, ORR, EOR, AND, BIC, ADC, SBC, BX_LR]);
    let [first, second, third] = &anchors;
    let before = binary_of(&[("", first), ("", &before_code), ("", second), ("", third)]);
    let after =
        binary_of(&[("", first), ("", &rewritten), ("", second), ("", third), ("", &look_alike)]);

    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    let pair = diff.matched.iter().find(|pair| pair.before == 1).expect("paired");
    assert_eq!((pair.after, pair.confidence), (1, Confidence::SameLayout));
    assert_eq!(diff.added, vec![4]);
}

/// A function whose close code moved to another place keeps its
/// partner there, over a function that scores well below in its old
/// place.
#[test]
fn close_code_that_moved_keeps_its_partner_over_its_place() {
    let anchors = [
        arm(&[ADC, SBC, RSB, BX_LR]),
        arm(&[MUL, MUL, ADC, BX_LR]),
        arm(&[RSB, RSB, BX_LR]),
        arm(&[SBC, SBC, SBC, BX_LR]),
    ];
    let moved = arm(&[ADD, SUB, ORR, EOR, AND, BIC, ADC, SBC, RSB, BX_LR]);
    let moved_and_edited = arm(&[ADD, SUB, ORR, EOR, AND, BIC, ADC, SBC, MUL, BX_LR]);
    let in_its_place = arm(&[ADD, MUL, MUL, MUL, MUL, MUL, MUL, MUL, MUL, BX_LR]);
    let [first, second, third, fourth] = &anchors;
    let before = binary_of(&[("", first), ("", &moved), ("", second), ("", third), ("", fourth)]);
    let after = binary_of(&[
        ("", first),
        ("", &in_its_place),
        ("", second),
        ("", third),
        ("", fourth),
        ("", &moved_and_edited),
    ]);

    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    let pair = diff.matched.iter().find(|pair| pair.before == 1).expect("paired");
    assert!(pair.score >= LOWEST_MOVED_SIMILARITY, "{pair:?}");
    assert_eq!((pair.after, pair.confidence), (5, Confidence::Similar));
    assert_eq!(diff.added, vec![1]);
}

/// Two unrelated binaries pair nothing by place, though each function
/// has one opposite it.
#[test]
fn unrelated_binaries_pair_nothing_by_place() {
    let before = binary_of(&[
        ("", &arm(&[ADD, SUB, BX_LR])),
        ("", &arm(&[ORR, EOR, BX_LR])),
        ("", &arm(&[AND, BIC, BX_LR])),
    ]);
    let after = binary_of(&[
        ("", &arm(&[MUL, ADC, BX_LR])),
        ("", &arm(&[SBC, RSB, BX_LR])),
        ("", &arm(&[MUL, SBC, BX_LR])),
    ]);

    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    assert!(diff.matched.is_empty(), "{:?}", diff.matched);
}

/// Where one side holds more free functions between two pairs, one
/// went or came, and the place says nothing of which: code that is not
/// close does not pair by it.
#[test]
fn a_gap_of_unequal_counts_pairs_no_distant_code() {
    let first = arm(&[ADC, SBC, RSB, BX_LR]);
    let last = arm(&[MUL, MUL, ADC, BX_LR]);
    let before_code = arm(&[ADD, SUB, ORR, EOR, AND, BIC, BX_LR]);
    let after_code = arm(&[ADD, MUL, MUL, MUL, MUL, MUL, BX_LR]);
    let other = arm(&[EOR, EOR, EOR, EOR, EOR, EOR, BX_LR]);
    let before = binary_of(&[("", &first), ("", &before_code), ("", &last)]);
    let after = binary_of(&[("", &first), ("", &after_code), ("", &other), ("", &last)]);

    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    assert_eq!(diff.removed, vec![1]);
}

/// Where a gap holds one more function on one side, the function gone
/// names the new one that scores closest as in its place, and the
/// other new one has no place.
#[test]
fn a_gap_of_unequal_counts_names_the_function_in_place() {
    let first = arm(&[ADC, SBC, RSB, BX_LR]);
    let last = arm(&[MUL, MUL, ADC, BX_LR]);
    let before_code = arm(&[ADD, SUB, ORR, EOR, AND, BIC, BX_LR]);
    let after_code = arm(&[ADD, SUB, ORR, MUL, MUL, MUL, BX_LR]);
    let other = arm(&[EOR, EOR, EOR, EOR, EOR, EOR, BX_LR]);
    let before = binary_of(&[("", &first), ("", &before_code), ("", &last)]);
    let after = binary_of(&[("", &first), ("", &other), ("", &after_code), ("", &last)]);

    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    assert_eq!(diff.removed, vec![1]);
    assert_eq!(diff.near_miss(1).and_then(|miss| miss.in_place), Some(2));
    assert_eq!(diff.added_near_miss(2).and_then(|miss| miss.in_place), Some(1));
    assert_eq!(diff.added_near_miss(1).and_then(|miss| miss.in_place), None);
}

/// A function that shares too little with the one in its place to pair
/// by place still names it.
#[test]
fn a_replaced_function_names_the_one_in_its_place() {
    let first = arm(&[ADC, SBC, RSB, BX_LR]);
    let last = arm(&[MUL, MUL, ADC, BX_LR]);
    let before_code = arm(&[ADD, SUB, ORR, EOR, AND, BIC, ADD, SUB, ORR, EOR, BX_LR]);
    let after_code = arm(&[[MUL; 40].as_slice(), &[BX_LR]].concat());
    let before = binary_of(&[("", &first), ("", &before_code), ("", &last)]);
    let after = binary_of(&[("", &first), ("", &after_code), ("", &last)]);

    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    assert_eq!((diff.removed.as_slice(), diff.added.as_slice()), ([1].as_slice(), [1].as_slice()));
    assert_eq!(diff.near_miss(1).and_then(|miss| miss.in_place), Some(1));
    assert_eq!(diff.added_near_miss(1).and_then(|miss| miss.in_place), Some(1));
}

/// Two unrelated binaries name no function in place.
#[test]
fn unrelated_binaries_name_nothing_in_place() {
    let before = binary_of(&[
        ("", &arm(&[ADD, SUB, BX_LR])),
        ("", &arm(&[ORR, EOR, BX_LR])),
        ("", &arm(&[AND, BIC, BX_LR])),
    ]);
    let after = binary_of(&[
        ("", &arm(&[MUL, ADC, BX_LR])),
        ("", &arm(&[SBC, RSB, BX_LR])),
        ("", &arm(&[MUL, SBC, BX_LR])),
    ]);

    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    let misses = diff.near_misses.iter().chain(&diff.added_near_misses);
    assert!(misses.clone().count() == 6, "{diff:?}");
    assert!(misses.into_iter().all(|miss| miss.in_place.is_none()), "{diff:?}");
}

#[test]
fn alignment_by_scores_takes_the_highest_sum_in_order() {
    let table = [[0.9, 0.0, 0.0], [0.0, 0.2, 0.8]];
    assert_eq!(align_by_scores(2, 3, |x, y| table[x][y]), vec![(0, 0), (1, 2)]);
    // Crossing pairs score more, but break the order.
    let table = [[0.0, 0.9], [0.9, 0.0]];
    assert_eq!(align_by_scores(2, 2, |x, y| table[x][y]).len(), 1);
    assert!(align_by_scores(2, 2, |_, _| 0.0).is_empty(), "nothing shared");
    assert!(align_by_scores(0, 3, |_, _| 1.0).is_empty());
    assert!(align_by_scores(3, 0, |_, _| 1.0).is_empty());
}

/// A gap where one function went and another came pairs the rest by
/// score, one place off.
#[test]
fn a_gap_with_one_function_gone_and_one_new_pairs_by_score() {
    // `a b c` became `b c d`.
    let scores = vec![vec![0.2, 0.1, 0.1], vec![0.9, 0.2, 0.1], vec![0.1, 0.9, 0.2]];
    assert_eq!(align_gap(&scores, 0.1, 0.3), vec![(1, 0), (2, 1)]);
}

/// A gap pairs first with first where scores in another order sum
/// little more, as two builds of one source often do.
#[test]
fn a_gap_pairs_in_order_unless_scores_say_clearly_otherwise() {
    let scores = vec![vec![0.5, 0.1], vec![0.6, 0.4]];
    assert_eq!(align_gap(&scores, 0.1, 0.3), vec![(0, 0), (1, 1)]);
    assert!(align_gap(&[], 0.1, 0.3).is_empty());
}

/// A gap where a function came pairs the close code around it in order.
#[test]
fn an_uneven_gap_pairs_close_code_in_order() {
    // `a b` became `a n b`.
    let scores = vec![vec![0.95, 0.2, 0.1], vec![0.1, 0.3, 0.9]];
    assert_eq!(align_uneven_gap(&scores, 0.8, 0.03), vec![(0, 0), (1, 2)]);
}

/// A pair with a rival in its gap, or under the floor, does not pair.
#[test]
fn an_uneven_gap_leaves_a_pair_with_a_close_rival() {
    let scores = vec![vec![0.9, 0.89, 0.1], vec![0.1, 0.1, 0.7]];
    assert!(align_uneven_gap(&scores, 0.8, 0.03).is_empty());
    assert!(align_uneven_gap(&[], 0.8, 0.03).is_empty());
}

/// Twins that an uneven gap aligns in order pair, where a twin left out
/// of the alignment would make the one it rivals stay free.
#[test]
fn an_uneven_gap_pairs_twins_in_order() {
    // `add sub` became `add sub new`.
    let scores = vec![vec![1.0, 1.0, 0.1], vec![1.0, 1.0, 0.1]];
    assert_eq!(align_uneven_gap(&scores, 0.8, 0.03), vec![(0, 0), (1, 1)]);
    // `add sub` became `add sub add`: which `add` is the old one?
    let scores = vec![vec![1.0, 0.5, 1.0], vec![0.5, 1.0, 0.5]];
    assert_eq!(align_uneven_gap(&scores, 0.8, 0.03), vec![(1, 1)]);
}

/// An uneven gap pairs a subset of its alignment by score, each pair at
/// the floor or more and with no rival left out of that alignment within
/// the margin.
#[test]
fn an_aligned_uneven_gap_is_ordered_and_without_rivals() {
    bolero::check!().with_type::<(u8, u8, [u8; 25])>().for_each(|&(left, right, cells)| {
        let (left, right) = (usize::from(left % 6), usize::from(right % 6));
        let scores: Vec<Vec<f64>> = (0..left)
            .map(|x| (0..right).map(|y| f64::from(cells[x * 5 + y] % 5) / 4.0).collect())
            .collect();
        let aligned = align_uneven_gap(&scores, 0.5, 0.1);
        for step in aligned.windows(2) {
            assert!(step[0].0 < step[1].0 && step[0].1 < step[1].1, "{aligned:?}");
        }
        let by_score = align_by_scores(left, right, |x, y| scores[x][y] - 0.5);
        assert!(aligned.iter().all(|pair| by_score.contains(pair)), "{aligned:?}");
        let left_out_x = |x: usize| by_score.iter().all(|pair| pair.0 != x);
        let left_out_y = |y: usize| by_score.iter().all(|pair| pair.1 != y);
        for &(x, y) in &aligned {
            let score = scores[x][y];
            assert!(score >= 0.5);
            assert!((0..right).all(|other| !left_out_y(other) || scores[x][other] < score - 0.1));
            assert!((0..left).all(|other| !left_out_x(other) || scores[other][y] < score - 0.1));
        }
    });
}

/// An aligned gap keeps the order on both sides, and sums no less than
/// first with first.
#[test]
fn an_aligned_gap_is_ordered_and_no_worse_than_in_order() {
    bolero::check!().with_type::<(u8, [u8; 25])>().for_each(|&(size, cells)| {
        let size = usize::from(size % 6);
        let scores: Vec<Vec<f64>> = (0..size)
            .map(|x| (0..size).map(|y| f64::from(cells[x * 5 + y] % 5) / 4.0).collect())
            .collect();
        let aligned = align_gap(&scores, 0.1, 0.3);
        for step in aligned.windows(2) {
            assert!(step[0].0 < step[1].0 && step[0].1 < step[1].1, "{aligned:?}");
        }
        let sum = |pairs: &[(usize, usize)]| -> f64 {
            pairs.iter().map(|&(x, y)| (scores[x][y] - 0.1).max(0.0)).sum()
        };
        let in_order: Vec<(usize, usize)> = (0..size).map(|place| (place, place)).collect();
        assert!(sum(&aligned) >= sum(&in_order));
    });
}

/// The highest sum of scores of any alignment in order, by trying
/// every one.
fn best_alignment_sum(left: usize, right: usize, score: &dyn Fn(usize, usize) -> f64) -> f64 {
    if left == 0 || right == 0 {
        return 0.0;
    }
    let both = best_alignment_sum(left - 1, right - 1, score) + score(left - 1, right - 1);
    both.max(best_alignment_sum(left - 1, right, score)).max(best_alignment_sum(
        left,
        right - 1,
        score,
    ))
}

/// Any alignment by scores keeps the order on both sides, takes only
/// items that share something, and reaches the highest sum.
#[test]
fn alignment_by_scores_is_ordered_and_best() {
    bolero::check!().with_type::<(u8, u8, [u8; 25])>().for_each(|&(left, right, cells)| {
        let (left, right) = (usize::from(left % 6), usize::from(right % 6));
        let score = |x: usize, y: usize| f64::from(cells[(x * 5 + y) % 25] % 4) / 4.0;
        let aligned = align_by_scores(left, right, score);
        for step in aligned.windows(2) {
            assert!(step[0].0 < step[1].0 && step[0].1 < step[1].1, "{aligned:?}");
        }
        assert!(aligned.iter().all(|&(x, y)| x < left && y < right && score(x, y) > 0.0));
        let sum: f64 = aligned.iter().map(|&(x, y)| score(x, y)).sum();
        assert!((sum - best_alignment_sum(left, right, &score)).abs() < 1e-9);
    });
}

/// Context alone does not pair two functions whose code shares too
/// little: see [`LOWEST_CONTEXT_SIMILARITY`].
#[test]
fn context_does_not_pair_unrelated_code() {
    let before_code = calls_three_then(&[ADD, SUB, ORR, EOR, AND, BIC, ADC, SBC, BX_LR]);
    let after_code = calls_three_then(&[MUL, MUL, MUL, MUL, MUL, MUL, MUL, MUL, MUL, BX_LR]);
    let [one, two, three] = [returns(1), returns(2), returns(3)];
    let before = binary_of(&[("", &before_code), ("", &one), ("", &two), ("", &three)]);
    let after = binary_of(&[("", &after_code), ("", &one), ("", &two), ("", &three)]);

    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    // Its place alone may pair it, as the only function before the
    // three; its context does not.
    let pair = diff.matched.iter().find(|pair| pair.before == 0);
    assert!(pair.is_none_or(|pair| pair.confidence != Confidence::SameCallers), "{pair:?}");
}

/// Twins that paired in order, each with the next one's partner, pair
/// again by what they call, however long the chain.
#[test]
fn twins_paired_crossed_in_a_chain_pair_by_what_they_call() {
    let calls = |from: u64, callee: u64| -> Vec<u8> {
        [bl(from, callee).as_slice(), &[0x1e, 0xff, 0x2f, 0xe1]].concat()
    };
    let callees = [returns(1), returns(2), returns(3)];
    let image = |targets: [u64; 3]| {
        let wrappers: Vec<Vec<u8>> = targets
            .iter()
            .enumerate()
            .map(|(index, &target)| calls(index as u64 * 0x100, target))
            .collect();
        let functions: Vec<(&str, &[u8])> =
            wrappers.iter().chain(&callees).map(|code| ("", code.as_slice())).collect();
        binary_of(&functions)
    };
    let before = image([0x300, 0x400, 0x500]);
    let after = image([0x500, 0x300, 0x400]);
    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });

    let partner =
        |index: usize| diff.matched.iter().find(|pair| pair.before == index).map(|pair| pair.after);
    assert_eq!([partner(0), partner(1), partner(2)], [Some(1), Some(2), Some(0)]);
    assert_eq!(diff.changed().count(), 0);
}

/// A table that went or came says it is data, and code says it is code.
#[test]
fn a_table_that_goes_or_comes_is_data() {
    let with_table = {
        let mut binary = raw_mips(&pointer_table(0x8000_1000));
        binary.functions.push(returns_one());
        binary
    };
    let without = hereticus_image::Binary { functions: vec![returns_one()], ..raw_mips(&[]) };
    let options = Options { threshold: 0.0, use_names: UseNames::No };

    let gone = diff_with(&with_table, &without, options);
    assert_eq!(gone.removed_with_contents().collect::<Vec<_>>(), [(0, Contents::Data)]);
    assert!(gone.added.is_empty() && gone.added_contents.is_empty());

    let new = diff_with(&without, &with_table, options);
    assert_eq!(new.added_with_contents().collect::<Vec<_>>(), [(0, Contents::Data)]);
    assert!(new.removed.is_empty() && new.removed_contents.is_empty());

    // Code that goes is code.
    let only_table = raw_mips(&pointer_table(0x8000_1000));
    let code_gone = diff_with(&with_table, &only_table, options);
    assert_eq!(code_gone.removed_with_contents().collect::<Vec<_>>(), [(1, Contents::Code)]);
}

/// One binary read alone tells its table from its code, as a comparison does.
#[test]
fn contents_of_tells_a_table_from_code() {
    let mut binary = raw_mips(&pointer_table(0x8000_1000));
    binary.functions.push(returns_one());

    let found: Vec<Contents> =
        binary.functions.iter().map(|function| contents_of(&binary, function)).collect();
    assert_eq!(found, [Contents::Data, Contents::Code]);
}

/// A table whose pointers moved is reported as changed data, not as a
/// rewritten function.
#[test]
fn a_changed_table_is_changed_data() {
    let before = raw_mips(&pointer_table(0x8000_1000));
    let after = raw_mips(&pointer_table(0x8000_2000));
    let diff = diff_with(&before, &after, Options { threshold: 0.0, use_names: UseNames::No });

    assert_eq!(diff.matched.len(), 1);
    assert_eq!(diff.matched[0].changed, Changed::Data);
}

/// The same table on both sides is not a change at all.
#[test]
fn an_unchanged_table_is_no_change() {
    let table = raw_mips(&pointer_table(0x8000_1000));
    let diff = diff_with(&table, &table, Options { threshold: 0.0, use_names: UseNames::No });

    assert_eq!(diff.matched[0].changed, Changed::No);
}

/// Data counts for less than a changed constant, and for more than none.
#[test]
fn data_ranks_between_a_reorder_and_a_changed_value() {
    assert!(Changed::Data > Changed::Reordered);
    assert!(Changed::Data < Changed::InDetail);
}

/// `add r0, r1, r0` then `bx lr`.
const ADD_THEN_RETURN: &[u8] = &[0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
/// `mul r0, r0, r1` then `bx lr`, which shares no operation with the above.
const MUL_THEN_RETURN: &[u8] = &[0x91, 0x00, 0x00, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];

/// `bl $+0x20` then `bx lr`.
const CALL_NEAR: &[u8] = &[0x06, 0x00, 0x00, 0xeb, 0x1e, 0xff, 0x2f, 0xe1];
/// The same call after its callee moved: `bl $+0x40` then `bx lr`.
const CALL_FAR: &[u8] = &[0x0e, 0x00, 0x00, 0xeb, 0x1e, 0xff, 0x2f, 0xe1];

/// The kernel size `0x2b08a8` stored among code, then `bx lr`.
///
/// The word decodes as `eoreq r0, fp, r8, lsr 17`.
const DATA_WORD: &[u8] = &[0xa8, 0x08, 0x2b, 0x00, 0x1e, 0xff, 0x2f, 0xe1];
/// The same field changed to `0x2b3c48`: `eoreq r3, fp, r8, asr 24`.
const DATA_WORD_EDITED: &[u8] = &[0x48, 0x3c, 0x2b, 0x00, 0x1e, 0xff, 0x2f, 0xe1];

/// Compare two one-function images and report what happened to the pair.
fn change_between(before: &[u8], after: &[u8]) -> Changed {
    let before = binary_of(&[("f", before)]);
    let after = binary_of(&[("f", after)]);
    let diff =
        diff_with(&before, &after, Options { use_names: UseNames::No, ..Default::default() });
    diff.matched.first().expect("the pair must match").changed
}

/// A call whose callee moved must reach the report as no change at all.
///
/// The unit tests above cover the operand rule directly. This one runs the
/// whole pipeline, so it still fails if the instruction kind stops
/// reaching the comparison and every target starts counting as data.
#[test]
fn a_moved_call_target_reports_no_change() {
    assert_eq!(change_between(CALL_NEAR, CALL_FAR), Changed::No);
}

/// The same difference in a word of data must stay visible.
///
/// Both cases change four bytes of an otherwise identical function. Only
/// the kind of the instruction tells them apart, which is why the pair of
/// tests belongs together.
#[test]
fn a_changed_data_word_still_reports_a_change() {
    assert_ne!(change_between(DATA_WORD, DATA_WORD_EDITED), Changed::No);
}

/// Identical code stays unchanged, so the tests above measure the edit
/// rather than a comparison that reports everything.
#[test]
fn an_unedited_function_reports_no_change() {
    assert_eq!(change_between(CALL_NEAR, CALL_NEAR), Changed::No);
    assert_eq!(change_between(DATA_WORD, DATA_WORD), Changed::No);
}

#[test]
fn an_unmatched_function_reports_its_closest_candidate() {
    let before = binary_of(&[("only", ADD_THEN_RETURN)]);
    // A second function that shares nothing keeps the two from
    // pairing by their place: see `Cascade::pair_by_layout`.
    let unrelated = arm(&[SUB, SUB]);
    let after = binary_of(&[("other", MUL_THEN_RETURN), ("unrelated", &unrelated)]);

    // A threshold of 1.0 refuses everything below an exact match, so the
    // pair is left for the near-miss report.
    let diff = diff_with(&before, &after, Options { threshold: 1.0, use_names: UseNames::No });

    assert_eq!(diff.removed, vec![0], "nothing could be paired");
    let miss = diff.near_miss(0).expect("the removed function needs a near miss");
    assert_eq!(miss.best, Some(0), "the only candidate is the closest one");
    assert!(miss.score > 0.0, "the two share a return, so they are not unrelated");
    assert!(miss.score < 1.0, "they are not the same function either");
}

/// With nothing to compare against, a near miss names no candidate rather
/// than inventing one.
#[test]
fn a_near_miss_without_candidates_names_none() {
    let before = binary_of(&[("gone", ADD_THEN_RETURN)]);
    let after = binary_of(&[]);

    let diff = diff_with(&before, &after, Options::default());

    let miss = diff.near_miss(0).expect("the removed function needs a near miss");
    assert_eq!(miss.best, None);
    assert_eq!(miss.score, 0.0);
}

/// Diff two one-function images at instruction level.
fn diff_lines(before: &[u8], after: &[u8]) -> Vec<DiffLine> {
    let before = binary_of(&[("f", before)]);
    let after = binary_of(&[("f", after)]);
    instruction_diff(&before.functions[0], Isa::Arm32, &after.functions[0], Isa::Arm32)
}

/// A function diffed with itself is every line unchanged.
#[test]
fn an_unedited_function_diffs_to_all_same() {
    let lines = diff_lines(ADD_THEN_RETURN, ADD_THEN_RETURN);
    assert!(lines.iter().all(|line| matches!(line, DiffLine::Same(_))));
    assert_eq!(lines.len(), 2, "add then bx lr");
}

/// A moved branch target is a free choice, so the diff shows no change.
#[test]
fn a_moved_target_diffs_to_all_same() {
    let lines = diff_lines(CALL_NEAR, CALL_FAR);
    assert!(
        lines.iter().all(|line| matches!(line, DiffLine::Same(_))),
        "only the branch target moved"
    );
}

/// An added instruction shows as one added line, the rest unchanged.
#[test]
fn an_added_instruction_shows_as_added() {
    // `add` then `add` then `bx lr`, against `add` then `bx lr`.
    let longer: &[u8] = &[0x00, 0x00, 0x81, 0xe0, 0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
    let lines = diff_lines(ADD_THEN_RETURN, longer);
    assert_eq!(lines.iter().filter(|line| matches!(line, DiffLine::Added(_))).count(), 1);
    assert_eq!(lines.iter().filter(|line| matches!(line, DiffLine::Removed(_))).count(), 0);
}

/// The same comparison reversed shows a removal, not an addition.
#[test]
fn a_removed_instruction_shows_as_removed() {
    let longer: &[u8] = &[0x00, 0x00, 0x81, 0xe0, 0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
    let lines = diff_lines(longer, ADD_THEN_RETURN);
    assert_eq!(lines.iter().filter(|line| matches!(line, DiffLine::Removed(_))).count(), 1);
    assert_eq!(lines.iter().filter(|line| matches!(line, DiffLine::Added(_))).count(), 0);
}

/// A changed constant shows as one changed line, with both forms.
///
/// The two `mov` share every shape a compiler picks freely, so they align;
/// only the constant differs, which is the line the reader came for.
#[test]
fn a_changed_constant_shows_both_forms() {
    // `mov r1, 0x25` then `mul` then `bx lr`, against `mov r1, 0x29`.
    let before: &[u8] = &[0x25, 0x10, 0xa0, 0xe3, 0x91, 0x00, 0x00, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
    let after: &[u8] = &[0x29, 0x10, 0xa0, 0xe3, 0x91, 0x00, 0x00, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
    let lines = diff_lines(before, after);

    let changed: Vec<_> =
        lines.iter().filter(|line| matches!(line, DiffLine::Changed { .. })).collect();
    assert_eq!(changed.len(), 1, "only the constant changed");
    let DiffLine::Changed { before, after } = changed[0] else { unreachable!() };
    assert!(before.contains("0x25") && after.contains("0x29"), "both values shown");
}

/// A remove-then-add of the same instruction folds by shape.
///
/// Aligning on the printed text splits a changed constant, and can split a
/// line whose target only moved, into a removal beside an addition. The fold
/// puts them back: a moved target is no change, a changed value is one
/// [`DiffLine::Changed`], and an unrelated pair is left apart.
#[test]
fn an_adjacent_remove_and_add_fold_by_shape() {
    let insns = |words: &[u32]| {
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        decode_all(&Arm32, &code, 0).0
    };
    // `bl`, `mov r1, 0x25`, `push {lr}`, against `bl` farther, `mov r1,
    // 0x29`, `mul r0, r0, r1`.
    let before = insns(&[0xeb00_0006, 0xe3a0_1025, 0xe52d_e004]);
    let after = insns(&[0xeb00_000e, 0xe3a0_1029, 0xe000_0190]);
    let steps = [Step::Left, Step::Right, Step::Left, Step::Right, Step::Left, Step::Right];
    let folded = lines_from_alignment(&steps, (&Arm32, &before), (&Arm32, &after));
    assert_eq!(
        folded,
        vec![
            DiffLine::Same(after[0].to_string()),
            DiffLine::Changed { before: before[1].to_string(), after: after[1].to_string() },
            DiffLine::Removed(before[2].to_string()),
            DiffLine::Added(after[2].to_string()),
        ]
    );
}

/// A register or a slot of the frame is a free choice, a constant or the
/// offset of another access is a value, and the base of an access or the
/// operation is the shape.
#[test]
fn two_instructions_differ_in_choices_values_or_shape() {
    let insn = |word: u32| decode_all(&Arm32, &word.to_le_bytes(), 0).0.remove(0);
    let difference = |left: u32, right: u32| {
        difference(&Arm32, &insn(left), &Arm32, &insn(right), FrameSlots::Move)
    };
    const MOV_R1_0X25: u32 = 0xe3a0_1025;
    const LDR_R0_R1_8: u32 = 0xe591_0008;
    assert_eq!(difference(MOV_R1_0X25, MOV_R1_0X25), Difference::FreeChoices);
    assert_eq!(difference(MOV_R1_0X25, 0xe3a0_2025), Difference::FreeChoices, "mov r2");
    assert_eq!(difference(MOV_R1_0X25, 0xe3a0_1029), Difference::Values, "mov r1, 0x29");
    assert_eq!(difference(LDR_R0_R1_8, 0xe591_000c), Difference::Values, "[r1, 0xc]");
    assert_eq!(difference(LDR_R0_R1_8, 0xe592_0008), Difference::Shape, "[r2, 8]");
    assert_eq!(difference(MOV_R1_0X25, 0xe000_0190), Difference::Shape, "mul");
    // `str r4, [sp]` against `str r4, [sp, 4]`: the frame grew, which
    // the assembly view shows.
    assert_eq!(difference(0xe58d_4000, 0xe58d_4004), Difference::FreeChoices);
    let (store, store_farther) = (insn(0xe58d_4000), insn(0xe58d_4004));
    assert_eq!(
        super::change::difference(&Arm32, &store, &Arm32, &store_farther, FrameSlots::Stay),
        Difference::Values
    );
    // `ldr r0, [pc, 8]` against `ldr r0, [pc, 0x10]`: the pool moved.
    assert_eq!(difference(0xe59f_0008, 0xe59f_0010), Difference::FreeChoices);
}

/// A matched function is not a near miss, so the report stays short.
#[test]
fn matched_functions_are_not_reported_as_near_misses() {
    let before = binary_of(&[("same", ADD_THEN_RETURN)]);
    let after = binary_of(&[("same", ADD_THEN_RETURN)]);

    let diff = diff_with(&before, &after, Options::default());

    assert_eq!(diff.matched.len(), 1);
    assert!(diff.near_misses.is_empty(), "nothing went unmatched");
    assert!(diff.added_near_misses.is_empty(), "nothing went unmatched");
}

/// An added function names its closest candidate on the first binary, the
/// mirror of the removed-side near miss.
#[test]
fn an_added_function_reports_its_closest_candidate() {
    let before = binary_of(&[("only", ADD_THEN_RETURN)]);
    // A second function that shares nothing keeps the two from
    // pairing by their place: see `Cascade::pair_by_layout`.
    let unrelated = arm(&[SUB, SUB]);
    let after = binary_of(&[("other", MUL_THEN_RETURN), ("unrelated", &unrelated)]);

    // A threshold of 1.0 refuses everything below an exact match, so both
    // sides are left for the near-miss report.
    let diff = diff_with(&before, &after, Options { threshold: 1.0, use_names: UseNames::No });

    assert_eq!(diff.added, vec![0, 1], "nothing could be paired");
    let miss = diff.added_near_miss(0).expect("the added function needs a near miss");
    assert_eq!(miss.best, Some(0), "the only candidate is the closest one");
    assert!(miss.score > 0.0, "the two share a return, so they are not unrelated");
    assert!(miss.score < 1.0, "they are not the same function either");
}

/// Reduce bodies to sorted symbols the way `prepare` does.
fn symbols_of(bodies: &[&[NormInsn]]) -> Vec<Vec<Symbol>> {
    let mut interner = Interner::default();
    bodies
        .iter()
        .map(|body| {
            let mut symbols: Vec<Symbol> = body.iter().map(|insn| interner.intern(insn)).collect();
            symbols.sort_unstable();
            symbols
        })
        .collect()
}

/// The fast path must agree with the one it replaced.
///
/// `similarity` stays the public, obviously-correct definition. The scoring
/// stage uses `similarity_of_symbols` instead, for speed. Nothing in the
/// types stops those two drifting apart, so this checks them together.
#[test]
fn scoring_by_symbol_agrees_with_scoring_by_body() {
    let cases: Vec<(Vec<NormInsn>, Vec<NormInsn>)> = vec![
        // Identical.
        (body(&["add"]), body(&["add"])),
        // Nothing shared.
        (body(&["ldr"]), body(&["mul"])),
        // Partly shared.
        (body(&["add", "mul"]), body(&["add", "sub"])),
        // One side empty.
        (Vec::new(), body(&["add"])),
        // Both empty.
        (Vec::new(), Vec::new()),
        // Repeats, where the multiset matters rather than the set.
        (body(&["add", "add", "add"]), body(&["add"])),
        // The same instructions in a different order.
        (body(&["add", "mul"]), body(&["mul", "add"])),
    ];

    for (left, right) in &cases {
        let symbols = symbols_of(&[left, right]);
        let by_body = similarity(left, right);
        let by_symbol = similarity_of_symbols(&symbols[0], &symbols[1]);
        assert!(
            (by_body - by_symbol).abs() < 1e-12,
            "{left:?} against {right:?}: body gives {by_body}, symbols give {by_symbol}"
        );
    }
}

/// Two equal instructions must get one symbol, and unequal ones must not.
///
/// Equality ignores constants on purpose, so the interner has to as well.
#[test]
fn equal_instructions_share_a_symbol() {
    let mut interner = Interner::default();

    let decoded = |word: u32| {
        let insn = Arm32.decode(&word.to_le_bytes(), 0, 0).expect("the word decodes");
        normalize(&Arm32, &insn)
    };
    let first = interner.intern(&decoded(0xe3a0_0001)); // mov r0, #1
    let second = interner.intern(&decoded(0xe3a0_0002)); // mov r0, #2
    assert_eq!(first, second, "constants stay out of equality, so out of the symbol");

    let third = interner.intern(&decoded(0xe591_0000)); // ldr r0, [r1]
    assert_ne!(first, third, "a different operation needs a different symbol");
    assert_eq!(interner.len(), 2, "two distinct instructions were seen");
}

/// Record what a comparison reports, to check the reporting itself.
///
/// Behind a lock because the scoring stages report from several threads.
#[derive(Default)]
struct Recorder {
    events: std::sync::Mutex<Vec<Event>>,
}

#[derive(Debug, PartialEq)]
enum Event {
    Start(Phase, usize),
    Advance(usize),
    Finish,
}

impl Recorder {
    fn events(&self) -> std::sync::MutexGuard<'_, Vec<Event>> {
        self.events.lock().expect("no test panics while holding the lock")
    }
}

impl Progress for Recorder {
    fn start(&self, phase: Phase, total: usize) {
        self.events().push(Event::Start(phase, total));
    }
    fn advance(&self, steps: usize) {
        self.events().push(Event::Advance(steps));
    }
    fn finish(&self) {
        self.events().push(Event::Finish);
    }
}

/// A bar that runs past its own total, or never ends, reads as a fault in
/// the tool. Every phase must announce a total it then reaches exactly, and
/// must close before the next one opens.
#[test]
fn every_phase_reports_a_total_it_reaches() {
    let before = binary_of(&[("same", ADD_THEN_RETURN), ("gone", MUL_THEN_RETURN)]);
    let after = binary_of(&[("same", ADD_THEN_RETURN), ("new", &[0x00, 0x00, 0xa0, 0xe1])]);

    let recorder = Recorder::default();
    diff_reporting(&before, &after, Options::default(), &recorder);

    let events = recorder.events();
    let mut open: Option<(Phase, usize)> = None;
    let mut seen = 0usize;
    let mut phases = Vec::new();

    for event in events.iter() {
        match event {
            Event::Start(phase, total) => {
                assert!(open.is_none(), "{phase:?} started while another phase was open");
                open = Some((*phase, *total));
                seen = 0;
                phases.push(*phase);
            }
            Event::Advance(steps) => {
                let (phase, total) = open.expect("a step was reported outside a phase");
                seen += steps;
                assert!(seen <= total, "{phase:?} passed its total of {total} at {seen}");
            }
            Event::Finish => {
                let (phase, total) = open.take().expect("a phase ended without starting");
                assert_eq!(seen, total, "{phase:?} ended at {seen} of {total}");
            }
        }
    }

    assert!(open.is_none(), "a phase was left open");
    assert!(phases.contains(&Phase::Preparing), "preparing is always reported");
    assert!(phases.contains(&Phase::Similarity), "the long phase is always reported");
}

/// Every phase needs something to show, or a bar displays an empty label.
#[test]
fn every_phase_has_a_label() {
    for phase in [
        Phase::Preparing,
        Phase::IdenticalCode,
        Phase::IdenticalShape,
        Phase::Names,
        Phase::Similarity,
        Phase::NearMisses,
    ] {
        assert!(!phase.label().is_empty(), "{phase:?} needs a label");
    }
}

/// Reporting progress must not change the answer.
#[test]
fn reporting_progress_does_not_change_the_result() {
    let before = binary_of(&[("same", ADD_THEN_RETURN), ("gone", MUL_THEN_RETURN)]);
    let after = binary_of(&[("same", ADD_THEN_RETURN), ("new", &[0x00, 0x00, 0xa0, 0xe1])]);

    let quiet = diff_with(&before, &after, Options::default());
    let loud = diff_reporting(&before, &after, Options::default(), &Recorder::default());

    assert_eq!(quiet.matched.len(), loud.matched.len());
    assert_eq!(quiet.removed, loud.removed);
    assert_eq!(quiet.added, loud.added);
}

/// The answer must not depend on how the work was spread over threads.
///
/// The scoring stages run in parallel, so rows finish in whatever order the
/// threads happen to take. Sorting the candidates is what makes the result
/// repeatable, and this checks that it does.
#[test]
fn the_result_does_not_depend_on_thread_order() {
    // Bodies close enough to score above the threshold against several
    // candidates, so the order pairs are taken in decides the answer.
    let before = binary_of(&[
        ("a", ADD_THEN_RETURN),
        ("b", MUL_THEN_RETURN),
        ("c", ADD_THEN_RETURN),
        ("d", MUL_THEN_RETURN),
        ("e", ADD_THEN_RETURN),
    ]);
    let after = binary_of(&[
        ("v", MUL_THEN_RETURN),
        ("w", ADD_THEN_RETURN),
        ("x", MUL_THEN_RETURN),
        ("y", ADD_THEN_RETURN),
        ("z", MUL_THEN_RETURN),
    ]);

    let options = Options { threshold: 0.3, use_names: UseNames::No };
    let first = diff_with(&before, &after, options);

    let pairs = |diff: &Diff| -> Vec<(usize, usize, Confidence)> {
        diff.matched.iter().map(|m| (m.before, m.after, m.confidence)).collect()
    };

    for run in 0..16 {
        let again = diff_with(&before, &after, options);
        assert_eq!(pairs(&first), pairs(&again), "run {run} paired differently");
        assert_eq!(first.removed, again.removed, "run {run} removed differently");
        assert_eq!(first.added, again.added, "run {run} added differently");
    }
}

#[test]
fn similarity_falls_as_bodies_diverge() {
    let base = body(&["add", "mul"]);
    let half = body(&["add", "sub"]);
    let none = body(&["ldr", "str"]);

    assert!(similarity(&base, &half) > similarity(&base, &none));
    assert_eq!(similarity(&base, &none), 0.0);
}

/// A branch on the opposite condition is shown but counts no edit, since
/// a compiler may flip it and swap the code after it; a branch on another
/// condition, as `lt` against `le`, is an edit. A32 and A64 agree.
#[test]
fn a_flipped_branch_reads_alike_on_a32_and_a64() {
    const RETURN_A32: u32 = 0xe12f_ff1e; // bx lr
    const RETURN_A64: u32 = 0xd65f_03c0; // ret
    const CMP_A32: u32 = 0xe350_0000; // cmp r0, #0
    const CMP_A64: u32 = 0xf100_001f; // cmp x0, #0
    let changed = |isa: Isa, branches: [u32; 2], compare: u32, ret: u32| {
        let binary = |branch: u32| {
            let code: Vec<u8> =
                [compare, branch, ret, ret].iter().flat_map(|word| word.to_le_bytes()).collect();
            hereticus_image::Binary { isa, ..binary_of(&[("f", &code)]) }
        };
        let options = Options { threshold: 0.0, use_names: UseNames::No };
        let diff = diff_with(&binary(branches[0]), &binary(branches[1]), options);
        diff.matched.first().expect("a threshold of zero pairs anything").changed
    };
    // bne and beq, then blt and ble, each to the next instruction but one.
    let a32 = |branches| changed(Isa::Arm32, branches, CMP_A32, RETURN_A32);
    assert_eq!(a32([0x1a00_0000, 0x0a00_0000]), Changed::InDetail);
    assert_eq!(a32([0xba00_0000, 0xda00_0000]), Changed::Yes);
    // b.ne and b.eq, then b.lt and b.le, the same way.
    let a64 = |branches| changed(Isa::Aarch64, branches, CMP_A64, RETURN_A64);
    assert_eq!(a64([0x5400_0041, 0x5400_0040]), Changed::InDetail);
    assert_eq!(a64([0x5400_004b, 0x5400_004d]), Changed::Yes);
}

/// A binary of ARM functions placed from 0x1000, each named for what it
/// returns, as `"52"` or `"0 again"`, and a table at 0x4000 of the
/// addresses of `table`, by name.
fn binary_with_table(names: &[&str], table: &[&str]) -> hereticus_image::Binary {
    let words = |words: &[u32]| -> Vec<u8> { words.iter().flat_map(|w| w.to_le_bytes()).collect() };
    let codes: Vec<Vec<u8>> = names
        .iter()
        .map(|name| {
            let value: u32 = name.split(' ').next().and_then(|n| n.parse().ok()).expect("a value");
            // mov r0, #value then bx lr
            words(&[0xe3a0_0000 | value, 0xe12f_ff1e])
        })
        .collect();
    let functions: Vec<(&str, &[u8])> =
        names.iter().zip(&codes).map(|(name, code)| (*name, code.as_slice())).collect();
    let mut binary = binary_of(&functions);
    for function in &mut binary.functions {
        function.address += 0x1000;
    }
    let address_of = |name: &&str| {
        let index = names.iter().position(|other| other == name).expect("a function");
        0x1000 + 0x100 * index as u32
    };
    let addresses: Vec<u32> = table.iter().map(address_of).collect();
    binary.links =
        hereticus_image::Links::of_parts(vec![(0x4000, words(&addresses))], BTreeMap::new());
    binary
}

/// Twins pair by their slot in a table that a firmer pair joins, not in
/// the order of their addresses.
#[test]
fn twins_pair_by_their_slot_in_a_table() {
    // `52` tells the tables apart; `0` and `0 again` are twins, placed the
    // other way round in the second binary.
    let before = binary_with_table(&["52", "0", "0 again"], &["52", "0", "0 again"]);
    let after = binary_with_table(&["52", "0 again", "0"], &["52", "0", "0 again"]);
    let diff = diff_with(&before, &after, Options { threshold: 0.0, use_names: UseNames::No });
    for pair in &diff.matched {
        assert_eq!(
            before.functions[pair.before].name, after.functions[pair.after].name,
            "{:?}",
            pair.confidence
        );
    }
    assert_eq!(diff.matched.len(), 3);
    assert!(diff.matched.iter().any(|pair| pair.confidence == Confidence::SameTable));
}

/// Two tables are not one where a firm pair joins a function of one to
/// another slot of the other: an edit moved the slots.
#[test]
fn a_crossed_slot_keeps_two_tables_apart() {
    let names = ["52", "7", "0", "0 again"];
    let before = binary_with_table(&names, &["52", "7", "0", "0 again"]);
    let after = binary_with_table(&names, &["52", "0 again", "7", "0"]);
    let diff = diff_with(&before, &after, Options { threshold: 0.0, use_names: UseNames::No });
    assert!(diff.matched.iter().all(|pair| pair.confidence != Confidence::SameTable));
}

/// Two PLT stubs of one import edit nothing where only their slot moved.
#[test]
fn a_stub_whose_slot_moved_is_unchanged() {
    // adr ip, pc, 0; add ip, ip, 0x13000; ldr pc, [ip, 0x144]! and 0xe4.
    let stub = |offset: u32| -> Vec<u8> {
        [0xe28f_c600_u32, 0xe28c_ca13, 0xe5bc_f000 | offset]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect()
    };
    let (before, after) = (stub(0x144), stub(0xe4));
    let options = Options { threshold: 0.0, use_names: UseNames::No };
    let changed = |names: [&str; 2]| {
        let diff = diff_with(
            &binary_of(&[(names[0], &before)]),
            &binary_of(&[(names[1], &after)]),
            options,
        );
        diff.matched.first().expect("a threshold of zero pairs anything").changed
    };
    assert_eq!(changed(["free@plt", "free@plt"]), Changed::No);
    assert_ne!(changed(["free@plt", "malloc@plt"]), Changed::No, "another import");
    assert_ne!(changed(["", ""]), Changed::No, "no stub known");
}

/// MIPS loads an address from the slot of its page with a low half added,
/// or from a slot of its own: the linker's choice, and no edit.
#[test]
fn a_mips_address_from_a_slot_of_its_own_edits_nothing() {
    let words = |words: &[u32]| -> Vec<u8> { words.iter().flat_map(|w| w.to_be_bytes()).collect() };
    let page = words(&[
        0x8f82_8024, // lw v0, -0x7fdc(gp)
        0x2442_1080, // addiu v0, v0, 0x1080
        0x8c43_0024, // lw v1, 0x24(v0)
        0x03e0_0008, // jr ra
        0x0000_0000, // nop
    ]);
    let own = words(&[
        0x8f82_830c, // lw v0, -0x7cf4(gp)
        0x8c43_0024, // lw v1, 0x24(v0)
        0x03e0_0008, // jr ra
        0x0000_0000, // nop
    ]);
    let binary =
        |code: &[u8]| hereticus_image::Binary { isa: Isa::Mips32Be, ..binary_of(&[("f", code)]) };
    let options = Options { threshold: 0.0, use_names: UseNames::No };
    let diff = diff_with(&binary(&page), &binary(&own), options);
    let pair = diff.matched.first().expect("a threshold of zero pairs anything");
    assert_eq!(pair.edits, Edits::default());
    assert_ne!(pair.changed, Changed::Yes);
}

/// Two stubs of one import pair by its name, though each has the bytes of
/// the other's stub: a lazy binding stub holds the number of its symbol.
#[test]
fn stubs_pair_by_their_import_before_their_bytes() {
    let (first, second) = ([0xe3a0_0001_u32, 0xe12f_ff1e], [0xe3a0_0002_u32, 0xe12f_ff1e]);
    let bytes =
        |words: [u32; 2]| -> Vec<u8> { words.iter().flat_map(|w| w.to_le_bytes()).collect() };
    let (first, second) = (bytes(first), bytes(second));
    let before = binary_of(&[("a@plt", &first), ("b@plt", &second)]);
    let after = binary_of(&[("a@plt", &second), ("b@plt", &first)]);
    let options = Options { threshold: 0.0, use_names: UseNames::No };
    let diff = diff_with(&before, &after, options);
    for pair in &diff.matched {
        assert_eq!(before.functions[pair.before].name, after.functions[pair.after].name);
        assert_eq!(pair.confidence, Confidence::SameImport);
    }
    assert_eq!(diff.matched.len(), 2);
}

mod files {
    use super::super::files::*;

    /// Functions 0 to `count` in address order: each sits at its own index.
    fn in_order(count: usize) -> (Vec<usize>, Vec<usize>) {
        ((0..count).collect(), (0..count).collect())
    }

    #[test]
    fn a_call_holds_the_functions_between_its_ends_in_one_file() {
        let (order, place) = in_order(6);
        let files = source_files(&order, &place, [(1, 3), (4, 5)]);
        assert_eq!(files[1], files[2], "between the ends");
        assert_eq!(files[2], files[3]);
        assert_eq!(files[4], files[5]);
        assert_ne!(files[0], files[1], "nothing joins 0 to 1");
        assert_ne!(files[3], files[4], "nothing spans 3 to 4");
    }

    #[test]
    fn functions_with_no_edge_each_sit_alone() {
        let (order, place) = in_order(4);
        assert_eq!(source_files(&order, &place, []), [0, 1, 2, 3]);
    }

    #[test]
    fn an_edge_past_the_most_span_joins_nothing() {
        let (order, place) = in_order(MOST_FILE_SPAN + 2);
        let files = source_files(&order, &place, [(0, MOST_FILE_SPAN + 1)]);
        assert_ne!(files[0], files[MOST_FILE_SPAN + 1]);
        let files = source_files(&order, &place, [(0, MOST_FILE_SPAN)]);
        assert_eq!(files[0], files[MOST_FILE_SPAN]);
    }

    #[test]
    fn the_files_follow_the_address_order_not_the_index() {
        // Function 2 sits first, then 0, then 1.
        let (order, place) = (vec![2, 0, 1], vec![1, 2, 0]);
        let files = source_files(&order, &place, [(2, 0)]);
        assert_eq!(files[2], files[0]);
        assert!(files[1] > files[0]);
    }

    /// Whatever the order and the edges, the files grow along the address
    /// order, and the two ends of an edge within the span share a file.
    #[test]
    fn any_edges_give_files_in_address_order() {
        bolero::check!().with_type::<(Vec<u8>, Vec<(u8, u8)>)>().for_each(|(keys, edges)| {
            let count = keys.len();
            if count == 0 {
                return;
            }
            let mut order: Vec<usize> = (0..count).collect();
            order.sort_by_key(|&index| (keys[index], index));
            let mut place = vec![0; count];
            for (at, &function) in order.iter().enumerate() {
                place[function] = at;
            }
            let edges: Vec<(usize, usize)> = edges
                .iter()
                .map(|&(one, other)| (usize::from(one) % count, usize::from(other) % count))
                .collect();
            let files = source_files(&order, &place, edges.iter().copied());
            assert!(order.windows(2).all(|pair| files[pair[0]] <= files[pair[1]]));
            for &(one, other) in &edges {
                if place[one].abs_diff(place[other]) <= MOST_FILE_SPAN {
                    assert_eq!(files[one], files[other]);
                }
            }
        });
    }

    #[test]
    fn files_disagree_where_their_other_pairs_go_elsewhere() {
        // Files 1 and 2 hold two more pairs each, all to other files.
        let votes = FileVotes::new([(1, 2), (1, 7), (1, 7), (8, 2), (9, 2)]);
        assert!(votes.disagree(1, 2));
    }

    #[test]
    fn files_agree_where_another_pair_joins_them() {
        let votes = FileVotes::new([(1, 2), (1, 2), (1, 7), (8, 2), (9, 2)]);
        assert!(!votes.disagree(1, 2));
    }

    #[test]
    fn files_with_too_few_other_pairs_are_not_judged() {
        let votes = FileVotes::new([(1, 2), (1, 7), (8, 2), (9, 2)]);
        assert!(!votes.disagree(1, 2), "file 1 holds one other pair");
        let votes = FileVotes::new([(1, 2)]);
        assert!(!votes.disagree(1, 2));
        assert!(!FileVotes::new([]).disagree(1, 2), "a pair not counted");
    }
}

/// `push {r4, lr}`, then `kept`, `bl target` from `from` and
/// `pop {r4, pc}`, little endian.
fn wrapper_of(from: u64, kept: &[u32], target: u64) -> Vec<u8> {
    let call_at = from + 4 * (1 + kept.len() as u64);
    [
        code(&[[0xe92d_4010].as_slice(), kept].concat()),
        bl(call_at, target).to_vec(),
        code(&[0xe8bd_8010]),
    ]
    .concat()
}

/// `words` as little-endian code.
fn code(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// A function whose work moved to a new callee pairs with the wrapper
/// that kept its place, not with the new callee its code matches; the
/// reverse, a callee inlined into its caller, pairs with the caller.
#[test]
fn moved_code_pairs_with_the_function_that_kept_its_place() {
    const KEPT: [u32; 3] = [ADC, SBC, RSB];
    const MOVED: [u32; 6] = [ADD, SUB, ORR, EOR, AND, MUL];
    let whole = code(&[[0xe92d_4010].as_slice(), &KEPT, &MOVED, &[0xe8bd_8010]].concat());
    let moved = code(&[MOVED.as_slice(), &[BX_LR]].concat());
    // The moved work alone scores 0.55 against the whole, and the wrapper
    // alone 0.36, so the similarity stage pairs the moved work.
    let options = Options { use_names: UseNames::No, threshold: 0.5 };
    let before = binary_of(&[("", &caller_of(0x100)), ("", &whole)]);
    let after =
        binary_of(&[("", &caller_of(0x100)), ("", &wrapper_of(0x100, &KEPT, 0x200)), ("", &moved)]);
    let partner = |diff: &Diff, index: usize| {
        diff.matched.iter().find(|pair| pair.before == index).map(|pair| pair.after)
    };

    let diff = diff_with(&before, &after, options);
    assert_eq!(partner(&diff, 1), Some(1), "the wrapper");
    assert_eq!(diff.added, [2], "the moved work is new");

    let diff = diff_with(&after, &before, options);
    assert_eq!(partner(&diff, 1), Some(1), "the caller that inlined it");
    assert_eq!(diff.removed, [2], "the inlined callee is gone");
}

#[test]
fn two_functions_read_as_one_hold_the_symbols_of_both() {
    use super::moved::joined;
    assert_eq!(joined(&[3, 1], &[2, 1]), [1, 1, 2, 3]);
    assert_eq!(joined(&[], &[]), Vec::<Symbol>::new());
}
