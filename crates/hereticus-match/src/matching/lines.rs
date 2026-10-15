//! The diff of two paired functions, one line per instruction or IL statement.

use std::collections::HashSet;

use hereticus_arch::Arch;

use hereticus_il::arch::{Insn, is_branch_target};

use hereticus_image::{Binary, Function, Isa};
use hereticus_recovery::arch::decode_all;
use hereticus_view::PairedLabels;

use super::align::{Step, align, lines_from_alignment};
use super::change::{Difference, FrameSlots, difference};

/// One line of an instruction-level diff between two matched functions.
///
/// The counts in [`Match::edits`] say *how much* changed; this says *what*.
/// The text is the instruction as the decoder printed it, so a reader sees the
/// real instruction, not the normalized form the matcher compares.
///
/// [`Match::edits`]: super::Match::edits
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiffLine {
    /// The same instruction on both sides.
    Same(String),
    /// An instruction the later build added.
    Added(String),
    /// An instruction the later build removed.
    Removed(String),
    /// An instruction kept in place but with a changed constant.
    ///
    /// The operation and operand shapes agree, so the matcher aligns the two,
    /// but a stored value differs. This is the shape a changed threshold or
    /// magic number takes.
    Changed { before: String, after: String },
}

/// How `--diff` shows each instruction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum View {
    /// As the decoder printed it.
    #[default]
    Assembly,
    /// As the IL reads it: see [`hereticus_view`].
    Il,
}

/// The address of each line `view` shows of the function `index` of
/// `binary`, in order: the IL view shows some idioms of several
/// instructions as one line.
pub fn line_addresses(view: View, binary: &Binary, index: usize) -> Vec<u64> {
    let function = &binary.functions[index];
    let arch = binary.isa_of(function).arch();
    let insns = decode_all(arch, &function.code, function.address).0;
    match view {
        View::Assembly => insns.iter().map(|insn| insn.address).collect(),
        View::Il => hereticus_view::il_line_addresses(arch, &insns),
    }
}

/// [`instruction_diff`], or the same diff with each instruction shown as
/// `view` says.
///
/// The IL view aligns on the IL statements, so two spellings of one
/// operation, as `eor r0, r0, r0` and `mov r0, #0`, are the same line. With
/// `paired`, a call to a stripped function of `after` names the function as
/// its pair in `before` is named.
pub fn instruction_diff_in(
    view: View,
    paired: Option<&PairedLabels>,
    before: &Binary,
    before_index: usize,
    after: &Binary,
    after_index: usize,
) -> Vec<DiffLine> {
    let (left, right) = (&before.functions[before_index], &after.functions[after_index]);
    let (before_isa, after_isa) = (before.isa_of(left), after.isa_of(right));
    if view == View::Assembly {
        return instruction_diff(left, before_isa, right, after_isa);
    }
    let side = |binary: &Binary, function: &Function, isa: Isa, paired| {
        let arch = isa.arch();
        let insns = decode_all(arch, &function.code, function.address).0;
        let context = hereticus_view::Context {
            links: &binary.links,
            space: &binary.addresses,
            functions: &binary.functions,
            paired,
        };
        IlSide::new(arch, &function.code, insns, Some(context))
    };
    let before_side = side(before, left, before_isa, None);
    let after_side = side(after, right, after_isa, paired);
    let keys = |side: &IlSide| -> Vec<String> {
        side.statements.iter().map(|statement| il_key(&statement.text)).collect()
    };
    let steps = align(&keys(&before_side), &keys(&after_side));
    fold_il_runs(&steps, &before_side, &after_side)
}

/// The IL statements of one side of a diff, with the instructions they show.
pub(super) struct IlSide<'a> {
    arch: &'a dyn Arch,
    insns: Vec<Insn>,
    pub(super) statements: Vec<hereticus_view::Statement>,
    /// The words the operands of the instructions name, as their registers.
    printed: HashSet<String>,
}

impl<'a> IlSide<'a> {
    pub(super) fn new(
        arch: &'a dyn Arch,
        code: &[u8],
        insns: Vec<Insn>,
        context: Option<hereticus_view::Context<'_>>,
    ) -> Self {
        let statements = hereticus_view::il_statements_in(arch, code, &insns, context);
        let printed = insns
            .iter()
            .filter_map(hereticus_il::arch::lift_named)
            .flat_map(|named| named.names)
            .flat_map(|name| words_of(&name))
            .collect();
        Self { arch, insns, statements, printed }
    }

    /// The instruction that `statement` shows.
    fn insn_of(&self, statement: &hereticus_view::Statement) -> Option<&Insn> {
        let index =
            self.insns.binary_search_by_key(&statement.address, |insn| insn.address).ok()?;
        Some(&self.insns[index])
    }
}

/// Pair a run of removed statements with the run of added ones right after
/// it, one for one where the two runs are as long.
///
/// Each pair of the same shape is one statement: the same, where only a
/// register differs, as a register is the compiler's free choice, and else
/// with another constant. A compare and its branch move together, so their
/// two statements come as a run of two.
pub(super) fn fold_il_runs(
    steps: &[Step],
    before: &IlSide<'_>,
    after: &IlSide<'_>,
) -> Vec<DiffLine> {
    let mut folded: Vec<DiffLine> = Vec::with_capacity(steps.len());
    let (mut i, mut j) = (0, 0);
    let mut index = 0;
    while index < steps.len() {
        let removed = steps[index..].iter().take_while(|step| **step == Step::Left).count();
        let added =
            steps[index + removed..].iter().take_while(|step| **step == Step::Right).count();
        if removed == 0 || added == 0 {
            folded.push(match steps[index] {
                Step::Both => DiffLine::Same(after.statements[j].text.clone()),
                Step::Left => DiffLine::Removed(before.statements[i].text.clone()),
                Step::Right => DiffLine::Added(after.statements[j].text.clone()),
            });
            (i, j) = match steps[index] {
                Step::Both => (i + 1, j + 1),
                Step::Left => (i + 1, j),
                Step::Right => (i, j + 1),
            };
            index += 1;
            continue;
        }
        let run = IlRun { before, before_at: i..i + removed, after, after_at: j..j + added };
        let pairs: Option<Vec<DiffLine>> =
            (removed == added).then(|| (0..removed).map(|at| run.fold(at, at)).collect()).flatten();
        match pairs {
            Some(pairs) => folded.extend(pairs),
            // Runs of other lengths fold only where they meet.
            None => {
                folded.extend(
                    (0..removed - 1).map(|at| DiffLine::Removed(run.before_text(at).to_string())),
                );
                match run.fold(removed - 1, 0) {
                    Some(line) => folded.push(line),
                    None => folded.extend([
                        DiffLine::Removed(run.before_text(removed - 1).to_string()),
                        DiffLine::Added(run.after_text(0).to_string()),
                    ]),
                }
                folded.extend((1..added).map(|at| DiffLine::Added(run.after_text(at).to_string())));
            }
        }
        (i, j) = (i + removed, j + added);
        index += removed + added;
    }
    folded
}

/// A run of removed IL statements and the run of added ones after it.
struct IlRun<'a> {
    before: &'a IlSide<'a>,
    before_at: core::ops::Range<usize>,
    after: &'a IlSide<'a>,
    after_at: core::ops::Range<usize>,
}

impl IlRun<'_> {
    fn before_text(&self, at: usize) -> &str {
        &self.before.statements[self.before_at.start + at].text
    }

    fn after_text(&self, at: usize) -> &str {
        &self.after.statements[self.after_at.start + at].text
    }

    /// The statement `before_at` of the run against `after_at`, as one line
    /// where the two are of one shape.
    fn fold(&self, before_at: usize, after_at: usize) -> Option<DiffLine> {
        let before_statement = &self.before.statements[self.before_at.start + before_at];
        let after_statement = &self.after.statements[self.after_at.start + after_at];
        let (before_text, after_text) = (&before_statement.text, &after_statement.text);
        let difference =
            match (self.before.insn_of(before_statement), self.after.insn_of(after_statement)) {
                (Some(left), Some(right)) => {
                    difference(self.before.arch, left, self.after.arch, right, FrameSlots::Move)
                }
                _ => Difference::Shape,
            };
        if difference == Difference::FreeChoices
            && self.only_printed_words_differ(before_at, after_at)
        {
            Some(DiffLine::Same(after_text.clone()))
        } else if il_shape(before_text) == il_shape(after_text) {
            Some(DiffLine::Changed { before: before_text.clone(), after: after_text.clone() })
        } else {
            None
        }
    }

    /// Whether each word in which the two statements differ is one that the
    /// instructions of its side print, as a register is.
    ///
    /// A name the IL view gives, as of a callee or a string, is no word of
    /// an instruction. It changes where the target or the pool the
    /// instruction reads changed, which [`difference`] lets move.
    fn only_printed_words_differ(&self, before_at: usize, after_at: usize) -> bool {
        let before = words_of(&il_key(self.before_text(before_at)));
        let after = words_of(&il_key(self.after_text(after_at)));
        before.len() == after.len()
            && before.iter().zip(&after).all(|(a, b)| {
                a == b || (self.before.printed.contains(a) && self.after.printed.contains(b))
            })
    }
}

/// The words of `line`: its runs of letters, digits and `_`.
fn words_of(line: &str) -> Vec<String> {
    line.split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|word| !word.is_empty())
        .map(str::to_string)
        .collect()
}

/// The text two IL statements must share to align: the statement with
/// each target collapsed, as [`diff_key`] does for an instruction.
pub(super) fn il_key(line: &str) -> String {
    let words: Vec<&str> =
        line.split(' ').map(|word| if is_branch_target(word) { "$" } else { word }).collect();
    // An address the code formed, as `@0x57c6`, moves as a target does,
    // and so does the distance from `pc` to a literal pool. A slot of the
    // stack frame moves when the frame grows, which the compiler decides:
    // the matcher reads every frame slot as one kind too. The size of the
    // frame stays, as `sp = sp - 0x40`, since a stack buffer can grow.
    let mut key = words.join(" ");
    for marker in [
        "@0x",
        "[pc + 0x",
        "[pc - 0x",
        "[sp + 0x",
        "[sp - 0x",
        "[x29 + 0x",
        "[x29 - 0x",
        "[fp + 0x",
        "[fp - 0x",
        "[r7 + 0x",
        "[s8 + 0x",
    ] {
        let mut collapsed = String::with_capacity(key.len());
        let mut rest = key.as_str();
        while let Some(at) = rest.find(marker) {
            collapsed.push_str(&rest[..at + marker.len() - 2]);
            rest = rest[at + marker.len()..]
                .trim_start_matches(|character: char| character.is_ascii_hexdigit());
        }
        collapsed.push_str(rest);
        key = collapsed;
    }
    key
}

/// An IL statement with every number collapsed, so two that differ only in
/// a constant share it.
pub(super) fn il_shape(line: &str) -> String {
    let key = il_key(line);
    let mut shape = String::with_capacity(key.len());
    let mut in_number = false;
    let mut previous = ' ';
    for character in key.chars() {
        let starts_number = character.is_ascii_digit() && !previous.is_ascii_alphanumeric();
        if starts_number
            || (in_number && character.is_ascii_hexdigit())
            || (in_number && character == 'x')
        {
            if !in_number {
                shape.push('#');
            }
            in_number = true;
        } else {
            in_number = false;
            shape.push(character);
        }
        previous = character;
    }
    shape
}

/// Align two matched functions instruction by instruction.
///
/// The alignment keys on the normalized form, so a branch whose target only
/// moved reads as [`DiffLine::Same`], the same choice the matcher makes
/// everywhere else. A longest-common-subsequence walk keeps an inserted
/// instruction from making every line after it look changed, which a plain
/// position-by-position compare cannot do.
///
/// The printed text carries the true disassembly. Where two aligned
/// instructions agree in shape but differ in a constant, the line is
/// [`DiffLine::Changed`] rather than [`DiffLine::Same`], so a changed value is
/// never reported as no change.
///
/// See RESEARCH.md, A13.
pub fn instruction_diff(
    before: &Function,
    before_isa: Isa,
    after: &Function,
    after_isa: Isa,
) -> Vec<DiffLine> {
    let before_arch = before_isa.arch();
    let after_arch = after_isa.arch();
    let before_insns = decode_all(before_arch, &before.code, before.address).0;
    let after_insns = decode_all(after_arch, &after.code, after.address).0;

    // Align on the printed text, but with branch targets collapsed. Keeping the
    // constant in the key is what lets a new `tst r5, #4` stand apart from an
    // existing `tst r5, #8`: the matcher's normalized form drops both to one
    // shape and would pair them, hiding the new gate. Collapsing the target
    // still folds a call whose callee only moved.
    let before_keys: Vec<String> = before_insns.iter().map(diff_key).collect();
    let after_keys: Vec<String> = after_insns.iter().map(diff_key).collect();

    let steps = align(&before_keys, &after_keys);
    lines_from_alignment(&steps, (before_arch, &before_insns), (after_arch, &after_insns))
}

/// What two instructions must share to align: the operation, and the name
/// of each operand from the lift, with targets removed. What no lift reads
/// aligns by its bytes.
///
/// A branch or a load from a literal pool names its target as `$+0x24`; the
/// target moves whenever anything before it changes size, so it must not
/// decide the alignment. Everything else, the constant included, stays: a
/// changed value is a real difference the reader came to see.
pub(super) fn diff_key(insn: &Insn) -> String {
    match hereticus_il::arch::lift_named(insn) {
        Some(named) => {
            let names = named.names.iter().map(|name| match is_branch_target(name) {
                true => "$",
                false => name.as_str(),
            });
            // What a post-index access adds to its base is no operand name.
            let write_back = named.write_back.as_deref().unwrap_or_default();
            format!("{:?} {} {write_back}", insn.opcode, names.collect::<Vec<_>>().join(", "))
        }
        None => format!("{:?} {:02x?}", insn.opcode, insn.bytes()),
    }
}
