//! How two paired functions differ, and what kind of change that is.

use crate::norm::{FlowShape, NormInsn};
use hereticus_arch::Arch;
use hereticus_il as il;
use hereticus_il::arch::Insn;
use hereticus_memory::{ConstantKind, Contents};
use hereticus_recovery::arch::{DataAmongCode, decode_all};

use super::align::{Step, align};
use super::{
    Changed, EditKind, EditKinds, Edits, Prepared, kind_of, same_detail, transfers_control,
};

/// Report whether two bodies differ only in choices the compiler makes freely.
///
/// Both sides already normalize alike, so this decides whether the bytes
/// behind them differ for a reason a reader should hear about. It compares the
/// instructions as printed, and allows two kinds of difference that carry no
/// meaning: which register holds a value, and where a branch goes.
///
/// A branch target moves whenever anything before it changes size. In a whole
/// kernel almost every function calls something that moved, so counting a
/// moved target as an edit reports the entire image as changed. Measured on
/// a whole-kernel pair, 6899 functions of otherwise identical
/// shape differ in nothing but their targets.
///
/// A word of data among the instructions still fails this check, which is the
/// point. It decodes as some instruction, and when its bits change it usually
/// becomes a *different* instruction rather than the same one with another
/// register or target.
fn differs_only_in_free_choices(before: &Prepared<'_>, after: &Prepared<'_>) -> bool {
    // Decoded rather than stored, and walked in step rather than collected:
    // a function of twenty thousand instructions would otherwise hold two
    // heap strings apiece on both sides at once, which is what exhausted
    // memory on a whole kernel.
    let before_arch = before.isa.arch();
    let after_arch = after.isa.arch();
    let (before_insns, _) = decode_all(before_arch, &before.function.code, before.function.address);
    let (after_insns, _) = decode_all(after_arch, &after.function.code, after.function.address);
    let before_kinds =
        before_arch.constant_kinds(&before.function.code, &before_insns, before.addresses);
    let after_kinds =
        after_arch.constant_kinds(&after.function.code, &after_insns, after.addresses);

    // Padding does nothing, and alignment puts it where it likes: GCC pads
    // a pool of doubles to eight bytes, so one more `nop` came before it.
    let work =
        |arch: &dyn Arch, insns: &[Insn], kinds: &[ConstantKind]| -> Vec<(Insn, ConstantKind)> {
            insns
                .iter()
                .zip(kinds)
                .filter(|(insn, _)| !arch.is_padding(insn))
                .map(|(insn, kind)| (insn.clone(), *kind))
                .collect()
        };
    let before_work = work(before_arch, &before_insns, &before_kinds);
    let after_work = work(after_arch, &after_insns, &after_kinds);
    if before_work.len() != after_work.len() {
        return false;
    }

    before_work.iter().zip(&after_work).all(|((left, left_kind), (right, right_kind))| {
        let kinds = (left_kind, right_kind);
        // A stored address on both sides is data the linker chose, so it may
        // hold anything and decode as anything.
        if kinds == (&ConstantKind::StoredAddress, &ConstantKind::StoredAddress) {
            return true;
        }
        // Compare the operation the way the normalizer does, so a condition
        // code the compiler chose differently, as `movwlt` against
        // `movwlo`, stays the free choice it is rather than reading as an
        // edit.
        if before_arch.operation_name(left) != after_arch.operation_name(right) {
            return false;
        }
        // What no lift reads is compared by its bytes.
        let (Some(left_lift), Some(right_lift)) = (before_arch.lift(left), after_arch.lift(right))
        else {
            return left.bytes() == right.bytes();
        };
        let (mut left_operands, mut right_operands) =
            (left_lift.operands.as_slice(), right_lift.operands.as_slice());
        // A load from a pool reads at a distance that says only where the
        // pool sits, so what comes before the reference is all to compare.
        if before_arch.data_among_code() == DataAmongCode::LiteralPools
            && let (Some(left_at), Some(right_at)) =
                (pool_reference(left_operands), pool_reference(right_operands))
        {
            (left_operands, right_operands) =
                (&left_operands[..left_at], &right_operands[..right_at]);
        }
        operands_are_interchangeable(
            left_operands,
            right_operands,
            // A moved target is a free choice only on an instruction that
            // truly branches. Both sides agree on the operation by now, so
            // either one answers.
            TargetMoves::from(transfers_control(left.kind) && transfers_control(right.kind)),
            AddressMoves::from(kinds),
        )
    })
}

/// Where the reference to memory at a distance from the program counter
/// sits among `operands`, as a load from a literal pool makes.
fn pool_reference(operands: &[il::Operand]) -> Option<usize> {
    operands.iter().position(|operand| {
        matches!(operand, il::Operand::Memory { base: Some(il::Reg::ProgramCounter), .. })
    })
}

/// Whether a differing constant counts as a free choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AddressMoves {
    /// The constant is part of an address on both sides, so the linker chose
    /// it, not the source.
    Freely,
    /// The constant is a value on at least one side.
    Never,
}

impl From<(&ConstantKind, &ConstantKind)> for AddressMoves {
    fn from(kinds: (&ConstantKind, &ConstantKind)) -> Self {
        match kinds {
            (ConstantKind::Address, ConstantKind::Address) => Self::Freely,
            (_, _) => Self::Never,
        }
    }
}

/// Whether a differing branch target counts as a free choice.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TargetMoves {
    /// The instruction branches, so a moved target means nothing.
    Freely,
    /// The instruction does not branch, so a `$...` operand is data.
    Never,
}

impl From<bool> for TargetMoves {
    fn from(transfers_control: bool) -> Self {
        if transfers_control { Self::Freely } else { Self::Never }
    }
}

/// Compare two operand lists, allowing the differences that carry no meaning.
///
/// A register is a free choice, but not where it is the base of an access:
/// an address may move, but not the register it is read through. A shift
/// is no free choice either: a word of data that decodes as `eoreq r0, fp,
/// r8, lsr 17` changed when its shift did.
pub(super) fn operands_are_interchangeable(
    left: &[il::Operand],
    right: &[il::Operand],
    targets: TargetMoves,
    addresses: AddressMoves,
) -> bool {
    use hereticus_il::Operand::{Const, Memory, Reg, RegisterList, Shifted, Target, Zero};
    let moves = addresses == AddressMoves::Freely;
    left.len() == right.len()
        && left.iter().zip(right).all(|(a, b)| {
            a == b
                || match (a, b) {
                    (Reg(_) | Zero, Reg(_) | Zero) => true,
                    (
                        Shifted { shift: left_shift, amount: left_amount, .. },
                        Shifted { shift: right_shift, amount: right_amount, .. },
                    ) => left_shift == right_shift && left_amount == right_amount,
                    // Which registers a `push` saves is the allocator's
                    // choice, but not whether a `pop` loads the program
                    // counter, as that returns.
                    (RegisterList(left_list), RegisterList(right_list)) => {
                        left_list.len() == right_list.len()
                            && special_registers(*left_list) == special_registers(*right_list)
                    }
                    (Target(_), Target(_)) => targets == TargetMoves::Freely || moves,
                    (Const(_), Const(_)) => moves,
                    // The offset an address adds to its base, as A64 adds
                    // the part of an address in a page: `[x22, #0x608]`.
                    (
                        Memory { base: left_base, index: left_index, update: left_update, .. },
                        Memory {
                            base: right_base, index: right_index, update: right_update, ..
                        },
                    ) => {
                        moves
                            && left_base == right_base
                            && left_index == right_index
                            && left_update == right_update
                    }
                    _ => false,
                }
        })
}

/// How two instructions differ, for a diff to show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Difference {
    /// Only in what the compiler or the linker chose freely: a register, a
    /// branch target, or where a literal pool sits.
    FreeChoices,
    /// In a constant or the offset of an access too, but not in shape: the
    /// same instruction with another value.
    Values,
    /// In the operation or the shape of its operands: other work.
    Shape,
}

/// Whether the offset of a slot of the frame is a free choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FrameSlots {
    /// A slot moves when the frame grows, which the compiler decides, as
    /// the IL view reads it.
    Move,
    /// A slot is where the instruction prints it, as the assembly view
    /// reads it.
    Stay,
}

/// How `before` differs from `after`, read from their lifts.
///
/// What no lift reads differs in shape unless its bytes agree.
pub(super) fn difference(
    before_arch: &dyn Arch,
    before: &Insn,
    after_arch: &dyn Arch,
    after: &Insn,
    frame_slots: FrameSlots,
) -> Difference {
    if before_arch.operation_name(before) != after_arch.operation_name(after) {
        return Difference::Shape;
    }
    let (Some(before_lift), Some(after_lift)) = (before_arch.lift(before), after_arch.lift(after))
    else {
        return if before.bytes() == after.bytes() {
            Difference::FreeChoices
        } else {
            Difference::Shape
        };
    };
    let without_frame_offsets = |arch: &dyn Arch, operands: &[il::Operand]| -> Vec<il::Operand> {
        operands
            .iter()
            .map(|operand| match *operand {
                il::Operand::Memory { base: Some(base), index, update, .. }
                    if frame_slots == FrameSlots::Move && arch.is_frame_register(base) =>
                {
                    il::Operand::Memory { base: Some(base), offset: None, index, update }
                }
                other => other,
            })
            .collect()
    };
    let before_operands = without_frame_offsets(before_arch, &before_lift.operands);
    let after_operands = without_frame_offsets(after_arch, &after_lift.operands);
    let (before_operands, after_operands) = (&before_operands[..], &after_operands[..]);
    // The distance to a literal pool says only where the pool sits.
    let free = match (pool_reference(before_operands), pool_reference(after_operands)) {
        (Some(before_at), Some(after_at)) => {
            (&before_operands[..before_at], &after_operands[..after_at])
        }
        _ => (before_operands, after_operands),
    };
    if operands_are_interchangeable(free.0, free.1, TargetMoves::Freely, AddressMoves::Never) {
        Difference::FreeChoices
    } else if operands_are_interchangeable(
        before_operands,
        after_operands,
        TargetMoves::Freely,
        AddressMoves::Freely,
    ) {
        Difference::Values
    } else {
        Difference::Shape
    }
}

/// The registers in `list` that are no general register.
fn special_registers(list: il::RegSet) -> il::RegSet {
    list.iter().filter(|reg| !matches!(reg, il::Reg::General(_))).collect()
}

/// Work out whether a matched pair differs.
///
/// The order of these checks runs from cheapest and most certain to least.
///
/// See RESEARCH.md, A12.
pub(super) fn classify_change(
    before: &Prepared<'_>,
    after: &Prepared<'_>,
    before_body: &[NormInsn],
    after_body: &[NormInsn],
) -> Changed {
    if before.function.code == after.function.code {
        return Changed::No;
    }

    // Data decodes as nonsense instructions, so comparing them says nothing.
    // The bytes differ, and that is all that can be said.
    if before.contents == Contents::Data || after.contents == Contents::Data {
        return Changed::Data;
    }

    if before_body == after_body {
        if !same_detail(before_body, after_body) {
            return Changed::InDetail;
        }

        // The instructions and their constants agree, yet the bytes do not.
        // Two very different things look like this:
        //
        // * A register or a branch address changed, which normalizing hides
        //   on purpose because a compiler picks those freely.
        // * A word of **data** changed. Data stored among instructions
        //   decodes as one, and normalizing then buckets its operands and
        //   loses the difference. Measured on a vendor kernel image, the
        //   stored kernel size `0x2b08a8` decoded as `eoreq r0, fp, r8, lsr
        //   17` and its change to `0x2b3c48` vanished entirely.
        //
        // Saying "unchanged" about bytes that differ is the one answer this
        // tool must never give, so the second case is reported.
        return if differs_only_in_free_choices(before, after) {
            Changed::No
        } else {
            Changed::InDetail
        };
    }

    // The instructions differ in position. They may still be the same
    // instructions, moved, which the sorted symbols already answer: a symbol
    // stands for one distinct normalized instruction, so two functions hold
    // the same multiset exactly when their sorted symbols agree. Comparing
    // those rather than sorting two copies of the instructions keeps a
    // twenty-thousand-instruction function from allocating twice its own size
    // here, which is what exhausted memory on a whole kernel.
    if before.symbols == after.symbols {
        return Changed::Reordered;
    }

    if differs_only_where_unreadable(before_body, after_body) {
        Changed::Unreadable
    } else {
        Changed::Yes
    }
}

/// Report whether every difference sits in bytes the decoder cannot read.
///
/// Such a difference is real — the bytes differ — but the tool cannot say
/// whether it edited an instruction or a word of data stored among the code.
/// Separating it from a readable edit lets a reader spend attention where the
/// tool has something to show.
///
/// Bodies of different length never qualify. An edit that added or removed an
/// instruction changed the code, whatever else it touched.
fn differs_only_where_unreadable(before: &[NormInsn], after: &[NormInsn]) -> bool {
    if before.len() != after.len() {
        return false;
    }

    let mut differs = false;
    for (left, right) in before.iter().zip(after) {
        if left == right {
            continue;
        }
        differs = true;
        if left.flow != FlowShape::Opaque && right.flow != FlowShape::Opaque {
            return false;
        }
    }

    differs
}

/// Count how many instructions an edit added, removed and rewrote.
///
/// The two bodies are aligned with the same longest-common-subsequence walk
/// that [`instruction_diff`] uses, so an instruction inserted near the top
/// costs one addition rather than making every instruction after it look
/// rewritten.
///
/// An instruction counts as rewritten when the alignment dropped it from both
/// sides, such as an `add` that became a `sub`. Those arrive as a removal next
/// to an addition and are folded back into one rewrite, the same way
/// [`lines_from_alignment`] folds them for display. What is left on one
/// side alone is a true addition or removal.
///
/// A pair the alignment kept is not a rewrite even when its constants differ.
/// Normalizing hides a constant on purpose, and [`Changed::InDetail`] already
/// reports that case; counting it here as well would say a threshold that went
/// from 100 to 50 rewrote an instruction, when the code around it is
/// untouched. A reader sorting by this count wants the functions whose
/// instructions moved.
///
/// A pair too large for the table aligns by anchors: see [`align`].
///
/// See RESEARCH.md, A12 and A13.
///
/// [`instruction_diff`]: super::instruction_diff
/// [`lines_from_alignment`]: super::align::lines_from_alignment
pub(super) fn count_edits(left: &[NormInsn], right: &[NormInsn]) -> (Edits, EditKinds) {
    let mut edits = Edits::default();
    let mut kinds = EditKinds::default();
    // Instructions removed since the last kept one, still free to pair with an
    // addition. The alignment emits a run of removals before the additions that
    // replace them, so the two need not be strictly adjacent. Their indexes are
    // kept so that an unpaired one can still be classified.
    let mut unpaired_removals: Vec<usize> = Vec::new();

    let (mut i, mut j) = (0, 0);
    for step in align(left, right) {
        match step {
            Step::Both => {
                // A kept pair agrees in shape, so only its constants can
                // differ. That is a change in value, not in instructions.
                if left[i].differs_in_detail(&right[j]) {
                    kinds.add(EditKind::Constant);
                }
                edits.removed += unpaired_removals.len();
                for index in unpaired_removals.drain(..) {
                    kinds.add(kind_of(&left[index]));
                }
                i += 1;
                j += 1;
            }
            Step::Left => {
                unpaired_removals.push(i);
                i += 1;
            }
            Step::Right => {
                // A removal waiting next to this addition means one instruction
                // took another's place, which is a rewrite rather than a pair
                // of length changes. The later build's instruction names the
                // kind, because that is the code the reader now has.
                if unpaired_removals.pop().is_some() {
                    edits.edited += 1;
                } else {
                    edits.added += 1;
                }
                kinds.add(kind_of(&right[j]));
                j += 1;
            }
        }
    }

    edits.removed += unpaired_removals.len();
    for index in unpaired_removals {
        kinds.add(kind_of(&left[index]));
    }

    (edits, kinds)
}
