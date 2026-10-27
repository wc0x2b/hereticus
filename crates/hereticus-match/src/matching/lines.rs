//! The diff of two paired functions, one line per instruction or IL statement.

use std::collections::{HashMap, HashSet};

use hereticus_arch::Arch;

use hereticus_il::arch::{Insn, InsnKind, is_branch_target};

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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum View {
    /// As the decoder printed it.
    #[default]
    Assembly,
    /// As the IL reads it: see [`hereticus_view`].
    Il,
}

/// Where a line of a view sits in its function.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinePlace {
    /// The address of the instruction the line shows.
    pub address: u64,
    /// How deep in the jumps of the function the line is, as
    /// [`hereticus_view::il_line_depths`] gives it. The assembly view keeps
    /// each line at zero, as the decoder prints it.
    pub depth: usize,
    /// Where the line jumps or branches to, where that is an instruction
    /// of its function.
    pub jump: Option<u64>,
}

/// Where each line `view` shows of the function `index` of `binary` sits,
/// in order: the IL view shows some idioms of several instructions as one
/// line.
pub fn line_places(view: View, binary: &Binary, index: usize) -> Vec<LinePlace> {
    let function = &binary.functions[index];
    let arch = binary.isa_of(function).arch();
    let insns = decode_shown(arch, function);
    let jump_of = |address: u64| {
        let at = insns.binary_search_by_key(&address, |insn| insn.address).ok()?;
        let (InsnKind::Branch { target: Some(target) } | InsnKind::Jump { target: Some(target) }) =
            insns[at].kind
        else {
            return None;
        };
        insns.binary_search_by_key(&target, |insn| insn.address).is_ok().then_some(target)
    };
    let place = |address, depth| LinePlace { address, depth, jump: jump_of(address) };
    match view {
        View::Assembly => insns.iter().map(|insn| place(insn.address, 0)).collect(),
        View::Il => hereticus_view::il_line_addresses(arch, &insns)
            .into_iter()
            .zip(hereticus_view::il_line_depths(arch, &insns))
            .map(|(address, depth)| place(address, depth))
            .collect(),
    }
}

/// The instructions of `function` as a diff shows them, with each word of
/// a literal pool as data.
///
/// A32 keeps its pool words as wide as its instructions, so the decoder
/// reads them as whatever their bits spell, as `mrc2` or `andeq`. Their
/// values move with each release, which put ten lines of noise after the
/// `procd` fix of CVE-2026-30874.
fn decode_shown(arch: &dyn Arch, function: &Function) -> Vec<Insn> {
    let mut insns = decode_all(arch, &function.code, function.address).0;
    let pool: HashSet<u64> = arch.literal_pool_words(&insns).into_iter().collect();
    for insn in insns.iter_mut().filter(|insn| pool.contains(&insn.address)) {
        *insn = hereticus_il::arch::data_word(insn.address, insn.bytes());
    }
    insns
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
        let insns = decode_shown(arch, function);
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

    /// The key of `line` to align on, with each word that an instruction of
    /// this side prints as a register written `R`. A number stays, as two
    /// statements that differ in a constant can differ in what they do.
    fn without_registers(&self, line: &str) -> String {
        let key = il_key(line);
        let mut out = String::with_capacity(key.len());
        let mut word = String::new();
        let flush = |word: &mut String, out: &mut String| {
            let register = !word.starts_with(|c: char| c.is_ascii_digit())
                && self.printed.contains(word.as_str());
            out.push_str(if register { "R" } else { word });
            word.clear();
        };
        for character in key.chars() {
            if character.is_ascii_alphanumeric() || character == '_' {
                word.push(character);
            } else {
                flush(&mut word, &mut out);
                out.push(character);
            }
        }
        flush(&mut word, &mut out);
        out
    }

    /// The instruction that `statement` shows.
    fn insn_of(&self, statement: &hereticus_view::Statement) -> Option<&Insn> {
        let index =
            self.insns.binary_search_by_key(&statement.address, |insn| insn.address).ok()?;
        Some(&self.insns[index])
    }
}

/// Pair a run of removed statements with the run of added ones right after
/// it, where they align as [`IlRun::fold_aligned`] says.
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
        match run.fold_aligned(&kept_around(steps, index, removed + added, before, i)) {
            Some(lines) => folded.extend(lines),
            // Runs that share no statement but for their registers fold
            // only where they meet.
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

/// How many statements on each side of a run say which registers keep
/// their names around it.
const KEPT_AROUND: usize = 3;

/// The registers of the statements that both sides hold around the run of
/// `length` steps at `index` of `steps`, which starts at statement `at` of
/// `before`: up to [`KEPT_AROUND`] before the run and after it. The two
/// sides name each of them alike.
fn kept_around(
    steps: &[Step],
    index: usize,
    length: usize,
    before: &IlSide<'_>,
    at: usize,
) -> HashSet<String> {
    let registers = |statement: usize| -> Vec<String> {
        words_of(&il_key(&before.statements[statement].text))
            .into_iter()
            .filter(|word| {
                !word.starts_with(|c: char| c.is_ascii_digit()) && before.printed.contains(word)
            })
            .collect()
    };
    let shared_before = steps[..index].iter().rev().take_while(|step| **step == Step::Both).count();
    let earlier = (at - shared_before.min(KEPT_AROUND).min(at))..at;
    let removed = steps[index..index + length].iter().filter(|step| **step == Step::Left).count();
    let shared_after =
        steps[index + length..].iter().take_while(|step| **step == Step::Both).count();
    let later = (at + removed)..(at + removed + shared_after.min(KEPT_AROUND));
    earlier.chain(later).flat_map(registers).collect()
}

/// The registers that the folded pairs of a run rename, from the name on
/// the earlier side to the name on the later, which must be one to one.
#[derive(Default)]
pub(super) struct Renaming {
    to_after: HashMap<String, String>,
    to_before: HashMap<String, String>,
}

impl Renaming {
    /// Take the renaming of a pair whose registers are `before` and
    /// `after`, in order, where it agrees with the pairs taken so far and
    /// renames no register of `kept`. Report whether it did.
    pub(super) fn take(
        &mut self,
        before: &[String],
        after: &[String],
        kept: &HashSet<String>,
    ) -> bool {
        if before.len() != after.len() {
            return false;
        }
        let agrees = before.iter().zip(after).all(|(old, new)| {
            let renamed = old != new && (kept.contains(old) || kept.contains(new));
            !renamed
                && self.to_after.get(old).is_none_or(|known| known == new)
                && self.to_before.get(new).is_none_or(|known| known == old)
        });
        if agrees {
            for (old, new) in before.iter().zip(after) {
                self.to_after.insert(old.clone(), new.clone());
                self.to_before.insert(new.clone(), old.clone());
            }
        }
        agrees
    }
}

/// The pairs of indices that `steps` align, in order.
fn aligned_pairs(steps: &[Step]) -> impl Iterator<Item = (usize, usize)> + '_ {
    let (mut i, mut j) = (0, 0);
    steps.iter().filter_map(move |step| {
        let pair = (*step == Step::Both).then_some((i, j));
        match step {
            Step::Both => (i, j) = (i + 1, j + 1),
            Step::Left => i += 1,
            Step::Right => j += 1,
        }
        pair
    })
}

/// A run of removed IL statements and the run of added ones after it.
struct IlRun<'a> {
    before: &'a IlSide<'a>,
    before_at: core::ops::Range<usize>,
    after: &'a IlSide<'a>,
    after_at: core::ops::Range<usize>,
}

impl IlRun<'_> {
    /// The lines of the run, where the statements of the two runs align on
    /// their text with each register left out, and each aligned pair folds
    /// as [`IlRun::fold`] allows. `None` where no two statements align.
    ///
    /// A compiler picks the registers freely, and one more register in
    /// use moves the rest: `x2 = x1 + 1` in one release is `x3 = x1 + 1`
    /// in the next, a line below, so the runs differ in length and do not
    /// fold pair by pair. The statements that do not align so align again
    /// with each number left out too, between the pairs found, so that a
    /// statement with another constant pairs only where no statement with
    /// the same one does.
    ///
    /// Two names are one register renamed only where the renaming is one
    /// to one over the run: a register the statements around the run keep
    /// under its own name, which `kept` holds, is no other register. The fix
    /// of CVE-2025-14282 in `dropbear` turns `if (w1 != 0)`, a test of a
    /// global that `w1` loaded, into `if (w0 != 0)`, a test of what
    /// `getuid` returned, right after `w0 = 1`.
    fn fold_aligned(&self, kept: &HashSet<String>) -> Option<Vec<DiffLine>> {
        let keys = |side: &IlSide<'_>, at: &core::ops::Range<usize>, shape: bool| -> Vec<String> {
            at.clone()
                .map(|index| {
                    let key = side.without_registers(&side.statements[index].text);
                    if shape { il_shape(&key) } else { key }
                })
                .collect()
        };
        let pairs =
            |shape: bool, before: core::ops::Range<usize>, after: core::ops::Range<usize>| {
                let before_keys = keys(
                    self.before,
                    &(self.before_at.start + before.start..self.before_at.start + before.end),
                    shape,
                );
                let after_keys = keys(
                    self.after,
                    &(self.after_at.start + after.start..self.after_at.start + after.end),
                    shape,
                );
                aligned_pairs(&align(&before_keys, &after_keys))
                    .map(|(i, j)| (before.start + i, after.start + j))
                    .collect::<Vec<_>>()
            };
        let exact = pairs(false, 0..self.before_at.len(), 0..self.after_at.len());
        // The gaps between the exact pairs, and after the last.
        let ends = exact.iter().copied().chain([(self.before_at.len(), self.after_at.len())]);
        let mut all = Vec::new();
        let (mut i, mut j) = (0, 0);
        for (next_i, next_j) in ends {
            all.extend(pairs(true, i..next_i, j..next_j));
            if next_i < self.before_at.len() {
                all.push((next_i, next_j));
            }
            (i, j) = (next_i + 1, next_j + 1);
        }
        if all.is_empty() {
            return None;
        }
        let mut lines = Vec::with_capacity(self.before_at.len() + self.after_at.len());
        let mut renaming = Renaming::default();
        let (mut i, mut j) = (0, 0);
        let ends = all.into_iter().chain([(self.before_at.len(), self.after_at.len())]);
        for (pair_i, pair_j) in ends {
            lines.extend((i..pair_i).map(|at| DiffLine::Removed(self.before_text(at).to_string())));
            lines.extend((j..pair_j).map(|at| DiffLine::Added(self.after_text(at).to_string())));
            if pair_i == self.before_at.len() {
                break;
            }
            let folded = self.fold(pair_i, pair_j).filter(|line| match line {
                DiffLine::Same(_) => renaming.take(
                    &self.registers_of(self.before, self.before_text(pair_i)),
                    &self.registers_of(self.after, self.after_text(pair_j)),
                    kept,
                ),
                _ => true,
            });
            match folded {
                Some(line) => lines.push(line),
                None => lines.extend([
                    DiffLine::Removed(self.before_text(pair_i).to_string()),
                    DiffLine::Added(self.after_text(pair_j).to_string()),
                ]),
            }
            (i, j) = (pair_i + 1, pair_j + 1);
        }
        Some(lines)
    }

    /// The words of `line` that the instructions of `side` print as
    /// registers, in order.
    fn registers_of(&self, side: &IlSide<'_>, line: &str) -> Vec<String> {
        words_of(&il_key(line))
            .into_iter()
            .filter(|word| {
                !word.starts_with(|c: char| c.is_ascii_digit()) && side.printed.contains(word)
            })
            .collect()
    }

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
    ///
    /// A text is compared whole, as its words alone read `"PATH"` and
    /// `"PATH="` as one: the fix of CVE-2026-30874 in `procd`.
    fn only_printed_words_differ(&self, before_at: usize, after_at: usize) -> bool {
        let (before_key, after_key) =
            (il_key(self.before_text(before_at)), il_key(self.after_text(after_at)));
        let texts = |key: &str| -> Vec<String> {
            key.split('"').skip(1).step_by(2).map(str::to_string).collect()
        };
        if texts(&before_key) != texts(&after_key) {
            return false;
        }
        let before = words_of(&before_key);
        let after = words_of(&after_key);
        let (before_triple, after_triple) = (self.before.arch.triple(), self.after.arch.triple());
        before.len() == after.len()
            && before.iter().zip(&after).all(|(a, b)| {
                let number = a.starts_with(|c: char| c.is_ascii_digit());
                a == b
                    || (self.before.printed.contains(a)
                        && self.after.printed.contains(b)
                        && (number
                            || register_class(before_triple, a) == register_class(after_triple, b)))
            })
    }
}

/// What the name of a register says of the value it holds, on the
/// architecture of `triple`.
///
/// Two names of one class are a free choice of the compiler. Two of other
/// classes hold values of other widths: the fix of CVE-2021-30883 in the
/// iPhone kernel turns `mul w10, w10, w8` into `mul x10, x10, x8`, so a
/// product of 32 bits that overflowed is one of 64 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RegisterClass<'a> {
    /// A general register of this many bits.
    General(u8),
    /// A floating point or vector register, by the letter of its kind, as
    /// `d` for a double of AArch64.
    Vector(char),
    /// A name of no class this knows, which matches only itself.
    Named(&'a str),
}

/// The class of the register `name` on the architecture of `triple`.
pub(super) fn register_class<'a>(triple: &str, name: &'a str) -> RegisterClass<'a> {
    let numbered = |prefixes: &str| {
        let mut characters = name.chars();
        characters.next().is_some_and(|first| prefixes.contains(first))
            && name.len() > 1
            && characters.all(|character| character.is_ascii_digit())
    };
    let first = name.chars().next().unwrap_or(' ');
    if triple.starts_with("aarch64") {
        return match name {
            "sp" | "xzr" => RegisterClass::General(64),
            "wsp" | "wzr" => RegisterClass::General(32),
            _ if numbered("x") => RegisterClass::General(64),
            _ if numbered("w") => RegisterClass::General(32),
            _ if numbered("bhsdqv") => RegisterClass::Vector(first),
            _ => RegisterClass::Named(name),
        };
    }
    if triple.starts_with("x86_64") || triple.starts_with("i386") || triple.starts_with("i686") {
        return x86_register_class(name);
    }
    if triple.starts_with("arm") || triple.starts_with("thumb") {
        return match name {
            "sb" | "sl" | "fp" | "ip" | "sp" | "lr" | "pc" => RegisterClass::General(32),
            _ if numbered("r") => RegisterClass::General(32),
            _ if numbered("sdq") => RegisterClass::Vector(first),
            _ => RegisterClass::Named(name),
        };
    }
    if triple.starts_with("mips") {
        const GENERAL: [&str; 32] = [
            "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5",
            "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1",
            "gp", "sp", "fp", "ra",
        ];
        return match name {
            _ if GENERAL.contains(&name) || name == "s8" => RegisterClass::General(32),
            _ if numbered("f") => RegisterClass::Vector('f'),
            _ => RegisterClass::Named(name),
        };
    }
    RegisterClass::Named(name)
}

/// The class of an x86 register: `rax` holds 64 bits, `eax` 32, `ax` 16
/// and `al` 8, and so on for each.
fn x86_register_class(name: &str) -> RegisterClass<'_> {
    const BITS_64: [&str; 8] = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"];
    const BITS_32: [&str; 8] = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];
    const BITS_16: [&str; 8] = ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"];
    const BITS_8: [&str; 12] =
        ["al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "sil", "dil", "bpl", "spl"];
    // `r8` to `r15`, with `d`, `w` or `b` for a part of 32, 16 or 8 bits.
    let numbered = name.strip_prefix('r').and_then(|rest| {
        let digits = rest.trim_end_matches(['d', 'w', 'b']);
        let number: u8 = digits.parse().ok()?;
        (8..=15).contains(&number).then_some(&rest[digits.len()..])
    });
    match (name, numbered) {
        (_, Some("")) => RegisterClass::General(64),
        (_, Some("d")) => RegisterClass::General(32),
        (_, Some("w")) => RegisterClass::General(16),
        (_, Some("b")) => RegisterClass::General(8),
        _ if BITS_64.contains(&name) => RegisterClass::General(64),
        _ if BITS_32.contains(&name) => RegisterClass::General(32),
        _ if BITS_16.contains(&name) => RegisterClass::General(16),
        _ if BITS_8.contains(&name) => RegisterClass::General(8),
        _ if name.starts_with("xmm") => RegisterClass::Vector('x'),
        _ if name.starts_with("ymm") => RegisterClass::Vector('y'),
        _ if name.starts_with("zmm") => RegisterClass::Vector('z'),
        _ => RegisterClass::Named(name),
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
    // frame stays, as `sp = sp - 0x40`, since a stack buffer can grow. On
    // x86 only the stack pointer marks a slot: code built with `-O2` keeps
    // a value of its own in `rbp` or `ebp`, so `[rbp + 0x10]` can be a
    // field of a struct.
    let mut key = words.join(" ");
    for marker in [
        "@0x",
        "[pc + 0x",
        "[pc - 0x",
        "[sp + 0x",
        "[sp - 0x",
        "[rsp + 0x",
        "[esp + 0x",
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
    collapse_into_texts(&key)
}

/// `line` with each pointer into a text, as `"Unexpected character\n"[10]`,
/// collapsed to `@`: the code reaches some other data from the text's
/// address, and the distance moves as an address does.
fn collapse_into_texts(line: &str) -> String {
    let mut collapsed = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(open) = rest.find('"') {
        // The text ends at the next quote that no backslash escapes.
        let after_open = &rest[open + 1..];
        let mut escaped = false;
        let Some(close) = after_open.find(|character: char| {
            let ends = character == '"' && !escaped;
            escaped = character == '\\' && !escaped;
            ends
        }) else {
            break;
        };
        let text_end = open + 1 + close + 1;
        let index = rest[text_end..].strip_prefix('[').and_then(|inside| {
            let digits =
                inside.len() - inside.trim_start_matches(|c: char| c.is_ascii_digit()).len();
            (digits > 0 && inside[digits..].starts_with(']')).then_some(digits + 2)
        });
        match index {
            Some(length) => {
                collapsed.push_str(&rest[..open]);
                collapsed.push('@');
                rest = &rest[text_end + length..];
            }
            None => {
                collapsed.push_str(&rest[..text_end]);
                rest = &rest[text_end..];
            }
        }
    }
    collapsed.push_str(rest);
    collapsed
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
    let before_insns = decode_shown(before_arch, before);
    let after_insns = decode_shown(after_arch, after);

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
