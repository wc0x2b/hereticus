//! The high IL: the IL view, with each call shown with what it passes and
//! what it gives back, each register named for what it holds, and the
//! upkeep of the frame left out.
//!
//! The IL shows one statement for each instruction, which is what the
//! matching compares. A reader wants less. On MIPS, `a1 = s0`, `call
//! strcmp` and the `a0 = &"admin"` in its delay slot are one call,
//! `strcmp("admin", s0)`. This layer reads the IL statements and the lifted
//! instructions under them, and changes nothing below it.
//!
//! The roles come from the usual ABI of the architecture, as
//! [`Arch::calling_convention`] gives it. A register shows as `arg1` where
//! it holds the first argument of the function, as it came in, on every
//! path. It shows as `ret` where it holds what the last call gave back on
//! every path. A place on the stack shows as `var_1c` where it is 0x1c
//! bytes below the stack pointer of the entry, and as `arg_10` where it is
//! 0x10 bytes above it, in the frame of the caller.
//!
//! A call shows the arguments that the code before it sets, in its block
//! and in the one block before that leads only to it, up to the last one
//! set. The code does not say how many arguments the callee reads, so an
//! argument counts only where nothing but a test reads it before the call.
//! A setting of an argument folds into the call where nothing between them
//! reads the register or changes what the setting reads, and no other path
//! from a branch between them reads it.
//!
//! The statements that only keep the frame do not show: a save of a
//! register that the function must give back as it came, its restore, a
//! move of the stack pointer, and the making of the frame pointer.

use std::collections::{HashMap, HashSet};

use hereticus_arch::{Arch, CallingConvention, NamedReg};
use hereticus_il::arch::{Insn, InsnKind};
use hereticus_il::flow::{held_on_every_path_of, successors};
use hereticus_il::{AccessKind, Lifted, Named, Op, Operand, Reg, RegSet, Update, Width};

use crate::arity::{self, Arity};
use crate::{Context, Fold, Statement, folds, instruction_lines};

/// What a register holds, where the high IL knows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Held {
    /// Argument `n` of the function, counted from 1, as it came in.
    Argument(usize),
    /// What the last call gave back.
    Result,
    /// The stack pointer of the entry, plus this many bytes.
    Stack(i64),
    /// What this register held at the entry, which is no argument.
    Entry(Reg),
    /// The address of a function, by its index in [`Body::callees`].
    Callee(usize),
}

impl Held {
    /// Whether a call or a store through an unknown address leaves the
    /// value in a place on the stack: a pointer to the place can escape,
    /// but code writes a saved register or the address of a function there
    /// only itself.
    fn outlives_unknown_stores(self) -> bool {
        matches!(self, Self::Entry(_) | Self::Callee(_))
    }
}

/// A register, or a place on the stack by its distance from the stack
/// pointer at the entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Place {
    Reg(Reg),
    Slot(i64),
}

/// What each register and place on the stack that the high IL knows holds
/// before one instruction.
type Holding = HashMap<Place, Held>;

/// The registers of a [`Holding`].
trait Registers {
    fn reg(&self, reg: Reg) -> Option<&Held>;
    fn set(&mut self, reg: Reg, held: Held);
    fn unset(&mut self, reg: Reg);
}

impl Registers for Holding {
    fn reg(&self, reg: Reg) -> Option<&Held> {
        self.get(&Place::Reg(reg))
    }

    fn set(&mut self, reg: Reg, held: Held) {
        self.insert(Place::Reg(reg), held);
    }

    fn unset(&mut self, reg: Reg) {
        self.remove(&Place::Reg(reg));
    }
}

/// The most instructions a call looks back over for its arguments.
const MOST_LOOKED_BACK: usize = 64;

/// The most arguments on the stack that a call shows.
const MOST_STACK_ARGUMENTS: usize = 12;

/// The registers GCC passes the first arguments of a local function in on
/// 32-bit x86, in order, where cdecl passes each on the stack.
const LOCAL_REGISTERS: [NamedReg; 3] = [
    NamedReg { reg: Reg::General(0), name: "eax" },
    NamedReg { reg: Reg::General(2), name: "edx" },
    NamedReg { reg: Reg::General(1), name: "ecx" },
];

/// How many arguments a callee reads, and how many of them come first in
/// [`LOCAL_REGISTERS`], on an ABI that passes them on the stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Takes {
    arity: Arity,
    in_registers: usize,
}

impl From<Arity> for Takes {
    fn from(arity: Arity) -> Self {
        Self { arity, in_registers: 0 }
    }
}

/// The most instructions of a callee that the high IL reads for its count
/// of arguments: a larger one costs more than the count is worth.
const MOST_READ_OF_A_CALLEE: usize = 4096;

/// What the liveness of a body takes an unknown read to be: an
/// instruction that does not lift, a call that shows no arguments, or a
/// jump out of the function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unknown {
    /// Each argument: the body shows, and must not hide a setting that
    /// code may read.
    ReadsArguments,
    /// Nothing: the body is a callee, whose count of arguments a guess
    /// must not grow.
    ReadsNothing,
}

/// The general registers that hold their own value at the entry: more than
/// any architecture here has.
const GENERAL_REGISTERS: u8 = 35;

/// The high IL statements of `insns`, which were decoded from `code`, as
/// [`crate::il_statements_in`] gives the IL statements. An architecture
/// with no [`Arch::calling_convention`] shows the IL statements.
pub fn hil_statements_in(
    arch: &dyn Arch,
    code: &[u8],
    insns: &[Insn],
    context: Option<Context<'_>>,
) -> Vec<Statement> {
    let abi = context.map_or(hereticus_arch::Abi::Unix, |context| context.abi);
    let Some(convention) = arch.calling_convention(abi).filter(|_| !insns.is_empty()) else {
        return crate::il_statements_in(arch, code, insns, context);
    };
    let folds = folds(arch, insns);
    let printed = instruction_lines(arch, code, insns, context);
    let body = Body::new(arch, convention, insns, &printed);
    let lines: Vec<String> =
        printed.iter().enumerate().map(|(index, line)| body.rename(index, line)).collect();
    let mut hidden = body.upkeep.clone();
    for index in body.page_feeders(&lines) {
        hidden[index] = true;
    }
    let mut sites: Vec<CallSite> = (0..insns.len())
        .filter_map(|index| body.call_site(index, &printed, &lines, &folds))
        .collect();
    let mut arities: HashMap<String, Option<Takes>> = HashMap::new();
    for site in &mut sites {
        let arity = *arities
            .entry(site.callee.clone())
            .or_insert_with(|| arity_of(arch, convention, context, &site.callee));
        if let Some(Takes { arity, in_registers }) = arity {
            let most = match convention.stack_arguments {
                Some(_) => MOST_STACK_ARGUMENTS,
                None => convention.arguments.len(),
            };
            site.count = arity.shown(site.count, most);
            site.counted = Counted::ByCallee;
            site.in_registers = in_registers;
        }
    }
    let live = body.live_in(&sites);
    let calls: Vec<Call> = sites
        .into_iter()
        .map(|site| Block::new(&body, &lines, &folds, site).into_call(&live))
        .collect();
    for call in &calls {
        for &index in &call.hidden {
            hidden[index] = true;
        }
    }
    let by_index: HashMap<usize, &Call> = calls.iter().map(|call| (call.index, call)).collect();
    let mut texts: Vec<Option<String>> = (0..insns.len())
        .map(|index| match (&folds[index], by_index.get(&index)) {
            (Fold::Hidden, _) => None,
            _ if hidden[index] || does_nothing(&lines[index]) => None,
            (Fold::GlobalPointer(register), _) => Some(format!("{register} = _gp")),
            (Fold::Own, Some(call)) => Some(call.text()),
            (Fold::Own, None) => Some(lines[index].clone()),
        })
        .collect();
    // An instruction the IL does not name shows as the decoder prints it,
    // with no value to fold into.
    let raw: Vec<bool> =
        insns.iter().zip(&printed).map(|(insn, line)| *line == insn.to_string()).collect();
    Values { body: &body, live: &live, calls: &by_index, folds: &folds, raw: &raw }
        .fold(&mut texts);
    let statement = |index: usize| -> Option<Statement> {
        let text = texts[index].clone()?;
        Some(Statement { address: insns[index].address, text })
    };
    let mut statements = Vec::with_capacity(insns.len());
    let mut index = 0;
    while index < insns.len() {
        // A delay slot runs before its call, branch or return goes, so it
        // shows before it, where it writes nothing the branch reads.
        let last =
            by_index.get(&index).map_or_else(|| body.slot_first(index), |call| Some(call.last));
        match last {
            Some(last) => {
                statements.extend((index + 1..=last).chain([index]).filter_map(statement));
                index = last + 1;
            }
            None => {
                statements.extend(statement(index));
                index += 1;
            }
        }
    }
    statements
}

/// A call that the IL names as `call <callee>`, and the instructions before
/// it that can set its arguments.
#[derive(Debug)]
struct CallSite {
    /// The index of the call.
    index: usize,
    /// The index of the last instruction of the call: its last delay slot,
    /// or the call itself.
    last: usize,
    /// The name of the callee.
    callee: String,
    /// The instructions before the call, by index, in the order they run:
    /// the block of the call, the one block before that leads only to it,
    /// and the delay slots of the call.
    order: Vec<usize>,
    /// How many arguments the call shows.
    count: usize,
    /// Where the count comes from.
    counted: Counted,
    /// How many arguments come first in [`LOCAL_REGISTERS`].
    in_registers: usize,
}

/// Where the count of arguments of a call comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Counted {
    /// The prototype or the code of the callee.
    ByCallee,
    /// The code before the call, which can set a register for another use
    /// or leave one set from before.
    ByCaller,
}

/// A MIPS16e `save` or `restore`, read for the high IL.
struct Frame {
    /// Whether it is a `save`.
    saves: bool,
    /// The place on the stack of each register it keeps.
    places: Vec<(i64, Reg)>,
    /// What the stack pointer holds after it.
    stack: i64,
}

/// The values that one statement sets and one later statement reads, to
/// fold into the one that reads them.
struct Values<'v, 'a> {
    body: &'v Body<'a>,
    live: &'v [RegSet],
    calls: &'v HashMap<usize, &'v Call>,
    folds: &'v [Fold],
    /// Whether each instruction shows as the decoder prints it.
    raw: &'v [bool],
}

/// The longest statement that folding makes: a longer one is harder to
/// read than the two it joins.
const LONGEST_FOLDED: usize = 120;

impl Values<'_, '_> {
    /// Fold each value of `texts`, the text each instruction shows, into
    /// the statement that reads it: hide a compare that only its branch
    /// reads, a copy of an argument, and each value that one statement of
    /// the same straight run reads and nothing reads after.
    fn fold(&self, texts: &mut [Option<String>]) {
        let compares = self.hide_compares(texts);
        self.hide_argument_copies(texts);
        for index in 0..texts.len() {
            if let Some((user, text)) = self.folded(index, texts, &compares) {
                texts[index] = None;
                texts[user] = Some(text);
            }
        }
    }

    fn lifted(&self, index: usize) -> Option<&Lifted> {
        Some(&self.body.lifts[index].as_ref()?.lifted)
    }

    /// The instructions after `index` on its one straight path.
    fn straight_after(&self, index: usize) -> impl Iterator<Item = usize> + '_ {
        let body = self.body;
        (index + 1..body.insns.len())
            .take_while(move |&at| body.next[at - 1] == [at] && body.entries[at] == 1)
    }

    /// The instructions after `index` on the path a value of `reg` can fold
    /// along: the straight path, and past a branch where the other path
    /// does not read `reg`, as a MIPS delay slot sets a value that only the
    /// code the branch falls into reads. A call keeps its place, so its
    /// result takes the straight path alone.
    fn path_after(&self, index: usize, reg: Reg, source: Source) -> Vec<usize> {
        let body = self.body;
        let mut path = Vec::new();
        let mut at = index;
        while at + 1 < body.insns.len() && body.entries[at + 1] == 1 {
            let next = &body.next[at];
            let falls_through = next.contains(&(at + 1));
            let others_read = next
                .iter()
                .filter(|&&successor| successor != at + 1)
                .any(|&successor| self.live[successor].contains(reg));
            let crosses = next.len() > 1;
            if !falls_through || others_read || (crosses && source == Source::Call) {
                break;
            }
            at += 1;
            path.push(at);
        }
        path
    }

    /// Hide each compare whose flags only the branch after it reads: the
    /// branch names what the compare compared, as `if (r1 == 2) goto …`.
    fn hide_compares(&self, texts: &mut [Option<String>]) -> HashSet<usize> {
        let mut hidden = HashSet::new();
        for index in 0..texts.len() {
            let Some(lifted) = self.lifted(index) else { continue };
            let is_compare = lifted.writes == RegSet::from_iter([Reg::Flags])
                && lifted.memory.is_none()
                && texts[index].as_deref().is_some_and(|text| text.starts_with("flags = "))
                && !self.body.is_conditional(index);
            if !is_compare {
                continue;
            }
            let reader = self.straight_after(index).find(|&at| {
                self.lifted(at).is_none_or(|lifted| {
                    lifted.reads.contains(Reg::Flags) || lifted.writes.contains(Reg::Flags)
                })
            });
            let Some(branch) = reader else { continue };
            let names_the_test = texts[branch].as_deref().is_some_and(names_its_test);
            let reads_flags =
                self.lifted(branch).is_some_and(|lifted| lifted.reads.contains(Reg::Flags));
            if matches!(self.body.insns[branch].kind, InsnKind::Branch { .. })
                && names_the_test
                && reads_flags
                && !self.body.live_after(self.live, branch).contains(Reg::Flags)
            {
                texts[index] = None;
                hidden.insert(index);
            }
        }
        hidden
    }

    /// Hide each copy of an argument, as `x19 = arg1`, or load of one from
    /// the place on the stack that holds it, where each statement that
    /// reads the register shows it as the argument.
    fn hide_argument_copies(&self, texts: &mut [Option<String>]) {
        for (index, text) in texts.iter_mut().enumerate() {
            let Some((dest, n)) = self.argument_copied(index) else { continue };
            let is_copy = text.as_deref().is_some_and(|text| text.contains(" = "));
            if is_copy && self.reads_show_argument(index, dest, n) {
                *text = None;
            }
        }
    }

    /// Whether each statement that reads `dest` as instruction `index` sets
    /// it shows it as argument `n`: on the straight path after it, up to a
    /// write of `dest` or a point where nothing reads it any more, or else
    /// in the whole function.
    fn reads_show_argument(&self, index: usize, dest: Reg, n: usize) -> bool {
        let body = self.body;
        let shows = |at: usize| {
            !self.uses(at).contains(dest) || body.holding[at].reg(dest) == Some(&Held::Argument(n))
        };
        let mut last = index;
        for at in self.straight_after(index) {
            if !shows(at) {
                return false;
            }
            let writes = self.lifted(at).is_none_or(|lifted| lifted.writes.contains(dest));
            if writes && !body.is_conditional(at) {
                return true;
            }
            last = at;
        }
        !body.live_after(self.live, last).contains(dest)
            || (0..body.insns.len()).all(|at| at == index || shows(at))
    }

    /// The register that instruction `index` copies argument `n` into, as a
    /// copy of a register or a load from the stack, and `n`.
    fn argument_copied(&self, index: usize) -> Option<(Reg, usize)> {
        let body = self.body;
        let lifted = body.canonical(index)?;
        let holding = &body.holding[index];
        let held = match copy_of(&lifted) {
            Some((dest, source)) => (dest, *holding.reg(source)?),
            None => {
                let [(at, dest)] = body.stack_places(index, &lifted, holding)?[..] else {
                    return None;
                };
                let loads = lifted.memory.is_some_and(|access| access.kind == AccessKind::Load);
                if !loads || lifted.writes != RegSet::from_iter([dest]) {
                    return None;
                }
                (dest, *holding.get(&Place::Slot(at))?)
            }
        };
        match held {
            (dest, Held::Argument(n)) => Some((dest, n)),
            _ => None,
        }
    }

    /// The registers that instruction `index` reads, with the arguments
    /// of the call it makes.
    fn uses(&self, index: usize) -> RegSet {
        let own = self.lifted(index).map_or(RegSet::ALL, |lifted| lifted.reads);
        match self.calls.get(&index) {
            Some(call) => own.union(call.reads),
            None => own,
        }
    }

    /// The value that instruction `index` sets, where it sets one register
    /// and does nothing else: the register, its name, the value, and
    /// whether the value comes from a call.
    fn value_of(&self, index: usize, text: &str) -> Option<(Reg, String, String, Source)> {
        let body = self.body;
        if let Some(call) = self.calls.get(&index) {
            let value = text.strip_prefix("ret = ")?;
            return call.gives.then(|| {
                (body.convention.result.reg, "ret".to_string(), value.to_string(), Source::Call)
            });
        }
        let lifted = self.lifted(index)?;
        let (name, value) = text.split_once(" = ")?;
        let reg = *body.registers.get(name)?;
        let pure = lifted.writes == RegSet::from_iter([reg])
            && lifted.memory.is_none_or(|access| access.kind == AccessKind::Load)
            && self.folds[index] == Fold::Own
            && !body.is_conditional(index)
            && !matches!(body.insns[index].kind, InsnKind::Call { .. })
            && !value.contains(';');
        let source = if lifted.memory.is_some() { Source::Memory } else { Source::Registers };
        pure.then(|| (reg, name.to_string(), value.to_string(), source))
    }

    /// The statement that the value of instruction `index` folds into, and
    /// its text with the value in place of the register.
    fn folded(
        &self,
        index: usize,
        texts: &[Option<String>],
        compares: &HashSet<usize>,
    ) -> Option<(usize, String)> {
        let body = self.body;
        let (reg, name, value, source) = self.value_of(index, texts[index].as_deref()?)?;
        let start = self.calls.get(&index).map_or(index, |call| call.last);
        // The registers the value reads that a later write would change.
        let holding = &body.holding[index];
        let inputs: RegSet = match source {
            Source::Call => RegSet::EMPTY,
            _ => self
                .lifted(index)?
                .reads
                .iter()
                .filter(|reg| {
                    !matches!(holding.reg(*reg), Some(Held::Argument(_) | Held::Stack(_)))
                })
                .collect(),
        };
        let mut user = None;
        // A compare that shows no line passes the value on to its branch.
        let mut compared = false;
        for at in self.path_after(start, reg, source) {
            let uses = self.uses(at);
            if compares.contains(&at) {
                compared |= uses.contains(reg);
            } else if uses.contains(reg) || (compared && uses.contains(Reg::Flags)) {
                user = Some(at);
                break;
            }
            let lifted = self.lifted(at)?;
            // A save of a register to the new frame stores nowhere that a
            // load can read.
            let stores = !body.upkeep[at]
                && lifted.memory.is_some_and(|access| access.kind != AccessKind::Load);
            let changes =
                lifted.writes.iter().any(|written| written == reg || inputs.contains(written));
            let moves_past = match source {
                // A call keeps its place among the statements that show.
                Source::Call => texts[at].is_some() || stores,
                Source::Memory => stores,
                Source::Registers => false,
            };
            // A call can change the registers and memory the value reads,
            // whether the high IL shows it as a call or not.
            let calls = matches!(body.insns[at].kind, InsnKind::Call { .. });
            if changes || moves_past || calls {
                return None;
            }
        }
        let user = user?;
        if self.raw[user] || self.raw[index] {
            return None;
        }
        let text = texts[user].as_deref()?;
        // A copy of the result keeps the name `ret` where code reads it, so
        // the line that names it stays.
        if source == Source::Call
            && let Some((copy, _)) = body.canonical(user).as_ref().and_then(copy_of)
            && (0..body.insns.len()).any(|at| {
                at != user
                    && self.uses(at).contains(copy)
                    && body.holding[at].reg(copy) == Some(&Held::Result)
            })
        {
            return None;
        }
        let rewrites = self.lifted(user).is_some_and(|lifted| lifted.writes.contains(reg))
            && !body.is_conditional(user);
        if body.live_after(self.live, user).contains(reg) && !rewrites {
            return None;
        }
        // A value that is the whole right side needs no parentheses.
        let operand =
            if text.ends_with(&format!(" = {name}")) { value } else { operand_of(&value) };
        let folded = simplified(&replace_read_once(text, &name, &operand)?);
        (folded.len() <= LONGEST_FOLDED).then_some((user, folded))
    }
}

/// Whether `insn` is a MIPS branch likely, whose delay slot runs only where
/// it branches.
fn is_branch_likely(insn: &Insn) -> bool {
    const LIKELY: [&str; 12] = [
        "beql", "bnel", "blezl", "bgtzl", "bltzl", "bgezl", "bltzall", "bgezall", "bc1fl", "bc1tl",
        "beqzl", "bnezl",
    ];
    LIKELY.contains(&hereticus_il::arch::printed_name(insn).as_str())
}

/// Whether the statement `text` leaves each register as it was, as
/// `esi = &[esi]`, which x86 code pads with.
fn does_nothing(text: &str) -> bool {
    text.split_once(" = &[").is_some_and(|(dest, rest)| rest.strip_suffix(']') == Some(dest))
}

/// Whether the branch `text` names what it tests, as `if (r1 == 2) goto`,
/// where `if (ne) return` names a condition of the flags alone.
fn names_its_test(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("if (") else { return false };
    let mut depth = 1;
    let condition = rest
        .char_indices()
        .find_map(|(at, c)| {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            (depth == 0).then(|| &rest[..at])
        })
        .unwrap_or(rest);
    condition.contains(' ') && !condition.contains("flags")
}

/// `text` with each operation on two constants in parentheses or
/// brackets worked out, as MIPS builds a constant in two halves:
/// `(0x7fff0000 | 0xfff1)` is `0x7ffffff1`.
fn simplified(text: &str) -> String {
    let mut text = text.to_string();
    // Each pass works out the innermost operations, which can leave an
    // operation on two constants one level out.
    for _ in 0..4 {
        let next = simplify_once(&text);
        if next == text {
            break;
        }
        text = next;
    }
    text
}

fn simplify_once(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = opening_outside_strings(rest) {
        let close_char = if rest[open..].starts_with('(') { ')' } else { ']' };
        let Some(length) = rest[open + 1..].find(close_char) else { break };
        let inner = &rest[open + 1..open + 1 + length];
        out.push_str(&rest[..open]);
        match worked_out(inner) {
            Some(value) if close_char == ')' => out.push_str(&value),
            Some(value) => {
                out.push('[');
                out.push_str(&value);
                out.push(']');
            }
            None => out.push_str(&rest[open..open + 1]),
        }
        rest = match worked_out(inner) {
            Some(_) => &rest[open + 2 + length..],
            None => &rest[open + 1..],
        };
    }
    out.push_str(rest);
    out
}

/// Where the first `(` or `[` of `text` outside a string is.
fn opening_outside_strings(text: &str) -> Option<usize> {
    let mut quoted = false;
    let mut escaped = false;
    for (at, c) in text.char_indices() {
        match c {
            '"' if !escaped => quoted = !quoted,
            '(' | '[' if !quoted => return Some(at),
            _ => {}
        }
        escaped = quoted && c == '\\' && !escaped;
    }
    None
}

/// The value of `inner`, where it is one operation on two constants.
fn worked_out(inner: &str) -> Option<String> {
    let mut parts = inner.split(' ');
    let (left, op, right) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    // An address the code formed, plus a distance, is another address.
    if let Some(address) = left.strip_prefix('@')
        && let (Some(address), Some(distance)) = (parse_constant(address), parse_constant(right))
    {
        let address = match op {
            "+" => address.checked_add(distance)?,
            "-" => address.checked_sub(distance)?,
            _ => return None,
        };
        return (address >= 0).then(|| format!("@{address:#x}"));
    }
    let (left, right) = (parse_constant(left)?, parse_constant(right)?);
    let value = match op {
        "+" => left.checked_add(right)?,
        "-" => left.checked_sub(right)?,
        "|" => left | right,
        "&" => left & right,
        "^" => left ^ right,
        "<<" => left.checked_shl(u32::try_from(right).ok()?)?,
        _ => return None,
    };
    Some(if value < 0 {
        format!("-{:#x}", value.unsigned_abs())
    } else {
        hereticus_il::constant_name(value as u64).to_string()
    })
}

/// Where a folded value comes from, which says what it can move past.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    /// A call: it keeps its place among the statements that show.
    Call,
    /// A load: no store can come between.
    Memory,
    /// Registers alone.
    Registers,
}

/// `value` as one operand of another statement: in parentheses where it
/// holds a space outside of brackets, parentheses and strings.
fn operand_of(value: &str) -> String {
    let mut depth = 0_i32;
    let mut quoted = false;
    let mut escaped = false;
    let mut spaced = false;
    for c in value.chars() {
        match c {
            '"' if !escaped => quoted = !quoted,
            '(' | '[' if !quoted => depth += 1,
            ')' | ']' if !quoted => depth -= 1,
            ' ' if !quoted && depth == 0 => spaced = true,
            _ => {}
        }
        escaped = quoted && c == '\\' && !escaped;
    }
    if spaced { format!("({value})") } else { value.to_string() }
}

/// `text` with the one read of the register `name` replaced by `value`,
/// where `text` reads it once, outside strings and addresses, and to the
/// right of a ` = `.
fn replace_read_once(text: &str, name: &str, value: &str) -> Option<String> {
    let reads = std::cell::Cell::new(0);
    let replaced = rename_registers(text, |word| {
        (word == name).then(|| {
            reads.set(reads.get() + 1);
            value.to_string()
        })
    });
    (reads.get() == 1).then_some(replaced)
}

/// A call, as the high IL shows it.
#[derive(Debug)]
struct Call {
    index: usize,
    last: usize,
    callee: String,
    /// Each argument, as it shows.
    arguments: Vec<String>,
    /// The instructions that fold into the call.
    hidden: Vec<usize>,
    /// Whether code after the call reads what it gives back.
    gives: bool,
    /// The registers of the arguments it shows.
    reads: RegSet,
}

/// Functions of the C library that never return. The flow of the code
/// does not say so: the instruction after a call to one reads as the code
/// that runs after it.
const NO_RETURN: [&str; 14] = [
    "exit",
    "_exit",
    "_Exit",
    "abort",
    "err",
    "errx",
    "verr",
    "verrx",
    "longjmp",
    "siglongjmp",
    "pthread_exit",
    "__assert_fail",
    "__stack_chk_fail",
    "__fortify_fail",
];

impl Call {
    fn text(&self) -> String {
        let call = format!("{}({})", self.callee, self.arguments.join(", "));
        let returns = !NO_RETURN.contains(&self.callee.as_str());
        if self.gives && returns { format!("ret = {call}") } else { call }
    }
}

/// The instructions of one function, with what the high IL knows of each.
struct Body<'a> {
    arch: &'a dyn Arch,
    convention: CallingConvention,
    insns: &'a [Insn],
    lifts: Vec<Option<Named>>,
    /// The instructions that can run right after each one.
    next: Vec<Vec<usize>>,
    /// How many edges reach each instruction.
    entries: Vec<usize>,
    /// For the last delay slot of a call, the index of the call.
    call_of_slot: Vec<Option<usize>>,
    /// Whether each instruction is in the delay slot of a call.
    in_call_slot: Vec<bool>,
    /// What each register holds before each instruction.
    holding: Vec<Holding>,
    /// Whether each instruction only keeps the frame.
    upkeep: Vec<bool>,
    /// The register whose value at the entry each place on the stack holds,
    /// where a save put it there, by the place.
    save_slots: HashMap<i64, Reg>,
    /// What the liveness takes an unknown read to be.
    unknown: Unknown,
    /// The register each name of an operand names.
    registers: HashMap<String, Reg>,
    /// The functions whose addresses the code loads, by name.
    callees: Vec<String>,
    /// The places on the stack that the code loads from, by their distance
    /// from the stack pointer at the entry.
    loaded_places: HashSet<i64>,
    /// The registers a call writes the return address to, as `lr` or `ra`:
    /// a function saves one, as it saves a register that a call keeps.
    links: RegSet,
    /// For each instruction that loads the address of a function from a
    /// slot of the global offset table, as `x26 = load.64 [@strcmp]`, the
    /// index of the function in [`Body::callees`].
    callee_loads: Vec<Option<usize>>,
}

impl<'a> Body<'a> {
    /// The body of `insns`, which the IL shows as `printed`.
    fn new(
        arch: &'a dyn Arch,
        convention: CallingConvention,
        insns: &'a [Insn],
        printed: &[String],
    ) -> Self {
        let mut callees: Vec<String> = Vec::new();
        let callee_loads = printed
            .iter()
            .map(|line| {
                let name = loaded_function(line)?;
                let index = callees.iter().position(|known| known == name).unwrap_or_else(|| {
                    callees.push(name.to_string());
                    callees.len() - 1
                });
                Some(index)
            })
            .collect();
        let lifts: Vec<Option<Named>> = insns.iter().map(hereticus_il::arch::lift_named).collect();
        let mut next = successors(insns, |insn| arch.delay_slots(insn));
        // A word of data among the code never runs, though a jump through a
        // register can seem to reach it: it leads nowhere.
        let is_data = |insn: &Insn| insn.opcode == hereticus_il::arch::Opcode::Data;
        for (edges, insn) in next.iter_mut().zip(insns) {
            if is_data(insn) {
                edges.clear();
            }
        }
        // What only a word of data led to, a jump through a register can
        // reach, as `successors` lets it reach each other unreached one.
        let mut reached = vec![false; insns.len()];
        for &successor in next.iter().flatten() {
            reached[successor] = true;
        }
        let unreached: Vec<usize> =
            (1..insns.len()).filter(|&index| !reached[index] && !is_data(&insns[index])).collect();
        for (index, insn) in insns.iter().enumerate() {
            if matches!(insn.kind, InsnKind::Jump { target: None }) {
                let last = (index + arch.delay_slots(insn)).min(insns.len() - 1);
                for &target in &unreached {
                    if !next[last].contains(&target) {
                        next[last].push(target);
                    }
                }
            }
        }
        let mut entries = vec![0; insns.len()];
        for &successor in next.iter().flatten() {
            entries[successor] += 1;
        }
        let mut call_of_slot = vec![None; insns.len()];
        let mut in_call_slot = vec![false; insns.len()];
        for (index, insn) in insns.iter().enumerate() {
            let slots = arch.delay_slots(insn);
            if slots > 0 && matches!(insn.kind, InsnKind::Call { .. }) {
                let end = (index + slots).min(insns.len() - 1);
                in_call_slot[index + 1..=end].fill(true);
                call_of_slot[end] = Some(index);
            }
        }
        let registers = registers_named(&lifts, convention);
        let mut body = Self {
            arch,
            convention,
            insns,
            lifts,
            next,
            entries,
            call_of_slot,
            in_call_slot,
            holding: Vec::new(),
            upkeep: Vec::new(),
            save_slots: HashMap::new(),
            unknown: Unknown::ReadsArguments,
            registers,
            callees,
            callee_loads,
            links: RegSet::EMPTY,
            loaded_places: HashSet::new(),
        };
        body.links = convention.link.into_iter().collect();
        body.holding = body.held();
        // A load from a place that a save filled gives back the value it
        // saved, so the restore shows as such: PowerPC saves `lr` through
        // `r0`.
        body.save_slots = body.save_slots();
        if !body.save_slots.is_empty() {
            body.holding = body.held();
        }
        body.upkeep = body.frame_upkeep();
        body.loaded_places = (0..insns.len())
            .filter_map(|index| {
                let lifted = body.canonical(index)?;
                if lifted.memory?.kind == AccessKind::Store {
                    return None;
                }
                Some(body.stack_addresses(index, &lifted, &body.holding[index]))
            })
            .flatten()
            .collect();
        body
    }

    /// What each register holds before each instruction.
    fn held(&self) -> Vec<Holding> {
        let mut holding =
            held_on_every_path_of(&self.next, |index, holding| self.step(index, holding));
        if let Some(entry) = self.entry()
            && let Some(first) = holding.first_mut()
        {
            *first = entry;
        }
        holding
    }

    /// The MIPS16e `save` or `restore` at `index`, where the stack pointer
    /// holds a known place before it, which no lift reads.
    fn frame(&self, index: usize, holding: &Holding) -> Option<Frame> {
        let frame = hereticus_il::arch::mips16::frame(&self.insns[index])?;
        let Some(&Held::Stack(at)) = holding.reg(self.convention.stack) else { return None };
        let reg = |name: &str| {
            let number =
                hereticus_il::arch::mips32::REGISTERS.iter().position(|known| *known == name)?;
            Some(Reg::General(number as u8))
        };
        let kept: Option<Vec<Reg>> = frame.kept.iter().map(|name| reg(name)).collect();
        let size = i64::from(frame.size);
        // The kept registers sit at the top of the new frame, the lowest
        // first.
        let top = if frame.saves { at } else { at + size };
        let kept = kept?;
        let first = top - 4 * kept.len() as i64;
        let places =
            kept.into_iter().enumerate().map(|(k, reg)| (first + 4 * k as i64, reg)).collect();
        let moved = if frame.saves { -size } else { size };
        Some(Frame { saves: frame.saves, places, stack: at + moved })
    }

    /// Apply a MIPS16e `save` or `restore`.
    fn apply_frame(&self, frame: &Frame, holding: &mut Holding) {
        if !frame.saves {
            for &(at, reg) in &frame.places {
                match self.save_slots.get(&at) {
                    Some(&saved) => holding.set(reg, Held::Entry(saved)),
                    None => holding.unset(reg),
                };
            }
        }
        holding.set(self.convention.stack, Held::Stack(frame.stack));
    }

    /// The places on the stack where a store puts the value that a register
    /// held at the entry, with that register.
    fn save_slots(&self) -> HashMap<i64, Reg> {
        let mut slots = HashMap::new();
        for index in 0..self.insns.len() {
            let holding = &self.holding[index];
            if let Some(frame) = self.frame(index, holding).filter(|frame| frame.saves) {
                for &(at, reg) in &frame.places {
                    if let Some(&Held::Entry(saved)) = holding.reg(reg)
                        && self.is_saved_by_frame(saved)
                    {
                        slots.insert(at, saved);
                    }
                }
            }
            let Some(lifted) = self.canonical(index) else { continue };
            if lifted.memory.is_none_or(|access| access.kind != AccessKind::Store) {
                continue;
            }
            let holding = &self.holding[index];
            for (at, reg) in self.stack_places(index, &lifted, holding).into_iter().flatten() {
                if let Some(&Held::Entry(saved)) = holding.reg(reg)
                    && self.is_saved_by_frame(saved)
                {
                    slots.insert(at, saved);
                }
            }
        }
        slots
    }

    /// What the registers hold at the entry, where no edge comes back to
    /// it.
    fn entry(&self) -> Option<Holding> {
        if self.entries.first().is_none_or(|&count| count > 0) {
            return None;
        }
        let convention = self.convention;
        let own = (0..GENERAL_REGISTERS).map(Reg::General).map(|reg| (reg, Held::Entry(reg)));
        let arguments = convention
            .arguments
            .iter()
            .enumerate()
            .map(|(n, arg)| (arg.reg, Held::Argument(n + 1)));
        // A later entry takes the place of an earlier one: the result
        // register can be the first argument too.
        let mut entry: Holding = own
            .chain(arguments)
            .chain([(convention.stack, Held::Stack(0))])
            .map(|(reg, held)| (Place::Reg(reg), held))
            .collect();
        // An ABI that passes the arguments on the stack holds each in its
        // place there.
        if let Some(stack) = convention.stack_arguments {
            entry.extend((0..MOST_STACK_ARGUMENTS).map(|n| {
                (Place::Slot(stack.first + n as i64 * stack.width), Held::Argument(n + 1))
            }));
        }
        Some(entry)
    }

    /// The last delay slot of the branch, jump or return at `index`, where
    /// its slots can show before it: they write nothing it reads.
    fn slot_first(&self, index: usize) -> Option<usize> {
        let insn = &self.insns[index];
        if matches!(insn.kind, InsnKind::Normal | InsnKind::Unknown | InsnKind::Call { .. }) {
            return None;
        }
        let slots = self.arch.delay_slots(insn);
        let last = index + slots;
        if slots == 0 || last >= self.insns.len() || is_branch_likely(insn) {
            return None;
        }
        let reads = self.lifts[index].as_ref()?.lifted.reads;
        let writes_read = (index + 1..=last).any(|slot| {
            self.lifts[slot]
                .as_ref()
                .is_none_or(|named| named.lifted.writes.iter().any(|reg| reads.contains(reg)))
        });
        (!writes_read).then_some(last)
    }

    /// The registers instruction `index` reads, where it lifts. An idiom
    /// that sets a constant, as `xor eax, eax`, reads none.
    fn reads_of(&self, index: usize) -> RegSet {
        let Some(named) = &self.lifts[index] else { return RegSet::ALL };
        match self.canonical(index).as_ref().map(|lifted| (lifted.op, lifted.operands.as_slice())) {
            Some((Op::Move, [Operand::Reg(_), Operand::Const(_)])) => {
                named.lifted.reads.difference(named.lifted.writes)
            }
            _ => named.lifted.reads,
        }
    }

    /// Whether a save of the value `reg` held at the entry keeps the frame:
    /// a call keeps `reg`, or writes its return address there.
    fn is_saved_by_frame(&self, reg: Reg) -> bool {
        self.convention.preserves(reg) || self.links.contains(reg)
    }

    fn is_call(&self, index: usize) -> bool {
        matches!(self.insns[index].kind, InsnKind::Call { .. })
    }

    fn has_slots(&self, index: usize) -> bool {
        self.arch.delay_slots(&self.insns[index]) > 0
    }

    /// Instruction `index` with its idioms read as the operations they are,
    /// where it lifts.
    fn canonical(&self, index: usize) -> Option<Lifted> {
        Some(self.lifts[index].as_ref()?.lifted.clone().canonical())
    }

    /// Apply instruction `index` to what the registers hold. A delay slot
    /// runs before its call, so the call applies after its last slot.
    fn step(&self, index: usize, holding: &mut Holding) {
        if index == 0
            && let Some(entry) = self.entry()
        {
            *holding = entry;
        }
        if self.call_of_slot[index].is_some() {
            self.apply(index, holding);
            self.apply_call(holding);
        } else if self.is_call(index) {
            if !self.has_slots(index) {
                self.apply_call(holding);
            }
        } else {
            self.apply(index, holding);
        }
    }

    /// Apply a call: the result register holds what it gives back, and each
    /// register that the call does not keep holds nothing known. A copy of
    /// what an earlier call gave back is no longer `ret`.
    fn apply_call(&self, holding: &mut Holding) {
        holding.retain(|place, held| match place {
            Place::Reg(reg) => self.convention.preserves(*reg) && *held != Held::Result,
            Place::Slot(_) => held.outlives_unknown_stores(),
        });
        holding.set(self.convention.result.reg, Held::Result);
    }

    /// Apply an instruction that is no call.
    fn apply(&self, index: usize, holding: &mut Holding) {
        if let Some(frame) = self.frame(index, holding) {
            self.apply_frame(&frame, holding);
            return;
        }
        let Some(lifted) = self.canonical(index) else {
            holding.clear();
            return;
        };
        let mut gained: Vec<(Reg, Held)> = Vec::new();
        if let Some((dest, source)) = copy_of(&lifted)
            && let Some(&held) = holding.reg(source)
        {
            gained.push((dest, held));
        }
        if let Some((dest, at)) = stack_arithmetic(&lifted, holding) {
            gained.push((dest, Held::Stack(at)));
        }
        let write_back = self.lifts[index].as_ref().and_then(|named| named.write_back.as_deref());
        for operand in &lifted.operands {
            let Operand::Memory { base: Some(base), offset, update, .. } = *operand else {
                continue;
            };
            let Some(&Held::Stack(at)) = holding.reg(base) else { continue };
            let moved = match update {
                Update::None => None,
                Update::Before => Some(displacement(offset)),
                Update::After => write_back.and_then(parse_constant),
            };
            if let Some(moved) = moved {
                gained.push((base, Held::Stack(at + moved)));
            }
        }
        let stack = self.convention.stack;
        let moved = match lifted.operands.as_slice() {
            // An A32 or T32 `push` or `pop` names its list and its base
            // alone.
            // T32 `push` and `pop` name the list alone.
            [Operand::Reg(base), Operand::RegisterList(list)] if *base == stack => {
                crate::list_offsets(&self.insns[index], &lifted, list.len()).map(|(_, moved)| moved)
            }
            [Operand::RegisterList(list)] if lifted.writes.contains(stack) => {
                crate::list_offsets(&self.insns[index], &lifted, list.len()).map(|(_, moved)| moved)
            }
            // An x86 `push` or `pop` names its value alone, as a register,
            // a constant, or a place in memory.
            [Operand::Reg(_) | Operand::Const(_) | Operand::Memory { .. }]
                if lifted.writes.contains(stack) =>
            {
                match lifted.op {
                    Op::Store => Some(-self.width(&lifted)),
                    Op::Load => Some(self.width(&lifted)),
                    _ => None,
                }
            }
            _ => None,
        };
        if let Some(moved) = moved
            && let Some(&Held::Stack(at)) = holding.reg(stack)
        {
            gained.push((stack, Held::Stack(at + moved)));
        }
        if let Some(callee) = self.callee_loads[index]
            && let Some(dest) = lifted.writes.iter().next()
        {
            gained.push((dest, Held::Callee(callee)));
        }
        let places = self.stack_places(index, &lifted, holding);
        let mut stored: Vec<(i64, Option<Held>)> = Vec::new();
        match (lifted.memory.map(|access| access.kind), &places) {
            (Some(AccessKind::Load), Some(places)) => {
                for &(at, reg) in places {
                    let held = holding.get(&Place::Slot(at)).copied();
                    let saved = self.save_slots.get(&at).map(|&saved| Held::Entry(saved));
                    if let Some(held) = held.or(saved) {
                        gained.push((reg, held));
                    }
                }
            }
            (Some(AccessKind::Store), Some(places)) => {
                stored = places.iter().map(|&(at, reg)| (at, holding.reg(reg).copied())).collect();
            }
            // An operation that writes a place it names, as `add [esp], eax`,
            // leaves it holding a new value. A store through an address the
            // high IL does not know can reach a place on the stack whose
            // address escaped.
            (Some(AccessKind::Store | AccessKind::LoadStore), None) => {
                let written = self.stack_addresses(index, &lifted, holding);
                match written.is_empty() {
                    false => written.iter().for_each(|&at| {
                        holding.remove(&Place::Slot(at));
                    }),
                    true => holding.retain(|place, held| {
                        matches!(place, Place::Reg(_)) || held.outlives_unknown_stores()
                    }),
                }
            }
            _ => {}
        }
        // An instruction that runs only on a condition leaves each place it
        // writes holding one of two values, which the high IL does not name.
        if self.is_conditional(index) {
            gained.clear();
            stored.iter_mut().for_each(|(_, held)| *held = None);
        }
        for reg in lifted.writes.iter() {
            holding.unset(reg);
        }
        // A store also changes each place it overlaps.
        let width = self.width(&lifted);
        for &(at, _) in &stored {
            holding.retain(|place, _| match *place {
                Place::Slot(other) => other == at || other + 8 <= at || other >= at + width,
                Place::Reg(_) => true,
            });
        }
        for (at, held) in stored {
            match held {
                Some(held) => holding.insert(Place::Slot(at), held),
                None => holding.remove(&Place::Slot(at)),
            };
        }
        holding.extend(gained.into_iter().map(|(reg, held)| (Place::Reg(reg), held)));
    }

    /// `line`, the IL statement of instruction `index`, with each place on
    /// the stack and each register named for what it holds before the
    /// instruction.
    fn rename(&self, index: usize, line: &str) -> String {
        let Some(named) = &self.lifts[index] else { return line.to_string() };
        // An instruction the IL does not name shows as the decoder prints
        // it, with no ` = ` that says which register it writes.
        if line == self.insns[index].to_string() {
            return line.to_string();
        }
        let holding = &self.holding[index];
        let mut text = line.to_string();
        for (operand, name) in named.lifted.operands.iter().zip(&named.names) {
            let Operand::Memory { base: Some(base), offset, index: None, update } = *operand else {
                continue;
            };
            let Some(&Held::Stack(at)) = holding.reg(base) else { continue };
            let at = if update == Update::After { at } else { at + displacement(offset) };
            if !name.is_empty()
                && let Some(start) = text.find(name.as_str())
            {
                text.replace_range(start..start + name.len(), &self.place_name(at));
            }
        }
        if let Some(lifted) = self.canonical(index)
            && let Some((dest, at)) = stack_arithmetic(&lifted, holding)
            && dest != self.convention.stack
            && !self.arch.is_frame_register(dest)
            && let Some(name) = named.names.first()
            && text.starts_with(&format!("{name} = "))
        {
            text = format!("{name} = &{}", self.place_name(at));
        }
        let text = plain_slot_access(&text);
        self.renamed(index, &text)
    }

    /// `text` with each register named for its role before instruction
    /// `index`, as `arg1` or `ret`.
    fn renamed(&self, index: usize, text: &str) -> String {
        let holding = &self.holding[index];
        rename_registers(text, |word| {
            let reg = self.registers.get(word)?;
            match holding.reg(*reg)? {
                Held::Argument(n) => Some(format!("arg{n}")),
                Held::Result => Some("ret".to_string()),
                Held::Stack(_) | Held::Entry(_) | Held::Callee(_) => None,
            }
        })
    }

    /// Whether each instruction only keeps the frame: it saves a register
    /// that holds what it held at the entry, restores a register saved so,
    /// moves the stack pointer, or makes the frame pointer from it.
    fn frame_upkeep(&self) -> Vec<bool> {
        let stack = self.convention.stack;
        let mut upkeep = vec![false; self.insns.len()];
        for (index, keeps) in upkeep.iter_mut().enumerate() {
            // A MIPS16e `save` or `restore` makes or drops the frame whole.
            if hereticus_il::arch::mips16::frame(&self.insns[index]).is_some() {
                *keeps = self.frame(index, &self.holding[index]).is_some();
                continue;
            }
            let Some(lifted) = self.canonical(index) else { continue };
            let holding = &self.holding[index];
            let places =
                self.stack_places(index, &lifted, holding).filter(|places| !places.is_empty());
            *keeps = match (lifted.memory.map(|access| access.kind), places) {
                // A save, or the link of a PowerPC frame to the one before.
                (Some(AccessKind::Store), Some(places)) => places.iter().all(|(_, reg)| {
                    *reg == stack
                        || matches!(holding.reg(*reg), Some(&Held::Entry(saved)) if self.is_saved_by_frame(saved))
                }),
                // A restore, into the register saved there, or a return
                // address into a register that passes it on, as PowerPC
                // restores `lr` through `r0`. A `pop` into the program
                // counter is the return.
                (Some(AccessKind::Load), Some(places)) => {
                    self.insns[index].kind == InsnKind::Normal
                        && places.iter().all(|(at, reg)| match self.save_slots.get(at) {
                            Some(&saved) => saved == *reg || self.links.contains(saved),
                            None => false,
                        })
                }
                (None, _) => {
                    self.moves_frame(&lifted, holding)
                        || copy_of(&lifted).is_some_and(|(dest, source)| {
                            dest != source && holding.reg(source) == Some(&Held::Entry(dest))
                        })
                }
                _ => false,
            };
        }
        // A copy of what a register held at the entry that only a save
        // reads, as `r0 = lr` before PowerPC saves `r0`.
        for index in 0..self.insns.len() {
            if let Some((dest, source)) = self.canonical(index).as_ref().and_then(copy_of)
                && self.holding[index].reg(source) == Some(&Held::Entry(source))
                && self.next_reader(index, dest).is_some_and(|reader| upkeep[reader])
            {
                upkeep[index] = true;
            }
        }
        upkeep
    }

    /// The next instruction after `index` on its one path that reads `reg`,
    /// where nothing before it writes `reg`.
    fn next_reader(&self, index: usize, reg: Reg) -> Option<usize> {
        let mut at = index;
        while self.next[at] == [at + 1] && self.entries[at + 1] == 1 {
            at += 1;
            let lifted = &self.lifts[at].as_ref()?.lifted;
            if lifted.reads.contains(reg) {
                return Some(at);
            }
            if lifted.writes.contains(reg) {
                return None;
            }
        }
        None
    }

    /// The bytes of each value that `lifted` stores or loads.
    fn width(&self, lifted: &Lifted) -> i64 {
        let bits = lifted.memory.and_then(|access| access.width).map(Width::bits);
        bits.map_or(self.arch.pointer_width() as i64, |bits| i64::from(bits / 8))
    }

    /// How many arguments come before the `...` of the function, where it
    /// takes more: `va_start` needs the arguments in memory, so the function
    /// stores each argument register from the first it does not name to
    /// the last, as it came in. A function that names each argument stores
    /// no more than it names.
    fn variadic_from(&self) -> Option<usize> {
        let count = self.convention.arguments.len();
        let mut stored = vec![false; count];
        for index in 0..self.insns.len() {
            let Some(lifted) = self.canonical(index) else { continue };
            if lifted.memory.is_none_or(|access| access.kind != AccessKind::Store) {
                continue;
            }
            let holding = &self.holding[index];
            for (_, reg) in self.stack_places(index, &lifted, holding).into_iter().flatten() {
                if let Some(&Held::Argument(n)) = holding.reg(reg) {
                    stored[n - 1] = true;
                }
            }
        }
        let fixed = stored.iter().rposition(|stored| !stored).map_or(0, |last| last + 1);
        (fixed < count && count > 1).then_some(fixed)
    }

    /// The places on the stack that instruction `index` reads or writes,
    /// with no regard to which register a value comes from or goes to, as
    /// `add eax, [esp + 4]` reads `arg1`.
    fn stack_addresses(&self, index: usize, lifted: &Lifted, holding: &Holding) -> Vec<i64> {
        if let Some(places) = self.stack_places(index, lifted, holding) {
            return places.into_iter().map(|(at, _)| at).collect();
        }
        lifted
            .operands
            .iter()
            .filter_map(|operand| match *operand {
                Operand::Memory { base: Some(base), offset, index: None, update: Update::None } => {
                    match holding.reg(base) {
                        Some(&Held::Stack(at)) => Some(at + displacement(offset)),
                        _ => None,
                    }
                }
                _ => None,
            })
            .collect()
    }

    /// The places on the stack that instruction `index` stores to or loads
    /// from, each with the register it stores or loads there, where every
    /// place it reaches is on the stack.
    fn stack_places(
        &self,
        index: usize,
        lifted: &Lifted,
        holding: &Holding,
    ) -> Option<Vec<(i64, Reg)>> {
        let access = lifted.memory?;
        let stack = self.convention.stack;
        let at_of = |reg: Reg| match holding.reg(reg) {
            Some(&Held::Stack(at)) => Some(at),
            _ => None,
        };
        let width = self.width(lifted);
        let memory: Vec<&Operand> = lifted
            .operands
            .iter()
            .filter(|operand| matches!(operand, Operand::Memory { .. }))
            .collect();
        let (start, values): (i64, Vec<Reg>) = match (memory.as_slice(), lifted.operands.as_slice())
        {
            // Only a load or a store moves values between registers and the
            // place: `add eax, [esp + 4]` reads `eax` and the place.
            ([Operand::Memory { base: Some(base), offset, index: None, update }], operands)
                if matches!(lifted.op, Op::Load | Op::Store) =>
            {
                let at = at_of(*base)?;
                let start = if *update == Update::After { at } else { at + displacement(*offset) };
                let values = operands
                    .iter()
                    .filter_map(|operand| match operand {
                        Operand::Reg(reg) => Some(*reg),
                        _ => None,
                    })
                    .collect();
                (start, values)
            }
            ([], [Operand::Reg(base), Operand::RegisterList(list)]) => {
                let (start, _) = crate::list_offsets(&self.insns[index], lifted, list.len())?;
                (at_of(*base)? + start, list.iter().collect())
            }
            ([], [Operand::RegisterList(list)]) if lifted.writes.contains(stack) => {
                let (start, _) = crate::list_offsets(&self.insns[index], lifted, list.len())?;
                (at_of(stack)? + start, list.iter().collect())
            }
            ([], [Operand::Reg(value)]) if lifted.writes.contains(stack) => {
                let at = at_of(stack)?;
                let start = if access.kind == AccessKind::Store { at - width } else { at };
                (start, vec![*value])
            }
            _ => return None,
        };
        let places = values.into_iter().enumerate();
        Some(places.map(|(k, reg)| (start + k as i64 * width, reg)).collect())
    }

    /// Whether `lifted` moves the stack pointer by a constant, makes a frame
    /// pointer from it, or puts it back from the frame pointer.
    fn moves_frame(&self, lifted: &Lifted, holding: &Holding) -> bool {
        let stack = self.convention.stack;
        let is_frame = |reg: Reg| reg == stack || self.arch.is_frame_register(reg);
        if let Some((dest, _)) = stack_arithmetic(lifted, holding) {
            return is_frame(dest);
        }
        copy_of(lifted).is_some_and(|(dest, source)| is_frame(dest) && is_frame(source))
    }

    /// The instructions that put a page in a register for the next one to
    /// add its offset to, as `x0 = &page` before `x0 = &"usage"`. The next
    /// one names the whole address.
    fn page_feeders(&self, lines: &[String]) -> Vec<usize> {
        let mut feeders = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            let Some(name) = line.strip_suffix(" = &page") else { continue };
            let Some(&reg) = self.registers.get(name) else { continue };
            let mut at = index;
            while self.next[at] == [at + 1] && self.entries[at + 1] == 1 {
                at += 1;
                let Some(named) = &self.lifts[at] else { break };
                let lifted = &named.lifted;
                if lifted.reads.contains(reg) {
                    if lifted.writes == RegSet::from_iter([reg]) && lines[at] != *line {
                        feeders.push(index);
                    }
                    break;
                }
                if lifted.writes.contains(reg) {
                    break;
                }
            }
        }
        feeders
    }

    /// The call at `index`, where the IL names it as `call <callee>`, with
    /// the instructions before it.
    fn call_site(
        &self,
        index: usize,
        printed: &[String],
        lines: &[String],
        folds: &[Fold],
    ) -> Option<CallSite> {
        if !self.is_call(index) || folds[index] != Fold::Own {
            return None;
        }
        let callee = self.callee(index, &printed[index], &lines[index])?;
        let slots = self.arch.delay_slots(&self.insns[index]);
        let last = (index + slots).min(self.insns.len() - 1);
        if self.lifts[index + 1..=last].iter().any(Option::is_none) {
            return None;
        }
        let mut start = index;
        while let Some(previous) = start.checked_sub(1)
            && index - previous <= MOST_LOOKED_BACK
            && self.entries[start] == 1
            && self.next[previous].contains(&start)
            && self.lifts[previous].is_some()
            && !self.is_call(previous)
            && !self.in_call_slot[previous]
            && self.insns[previous].kind != InsnKind::Return
        {
            start = previous;
        }
        let mut site = CallSite {
            index,
            last,
            callee,
            order: (start..index).chain(index + 1..=last).collect(),
            count: 0,
            counted: Counted::ByCaller,
            in_registers: 0,
        };
        site.count = match self.convention.stack_arguments {
            Some(_) => self.stack_argument_count(&site),
            None => self.argument_count(&site),
        };
        Some(site)
    }

    /// The callee of the call at `index`, whose IL statement is `printed`,
    /// and `line` with its registers named for what they hold: the name the
    /// IL gives it, or the one register the call goes through, as the `ctr`
    /// of PowerPC `bctrl`. A register keeps its name here, so that the call
    /// reads as one through a register. A callee in memory shows as the
    /// load of it, as `(load.64 [arg1 + 0x10])`.
    fn callee(&self, index: usize, printed: &str, line: &str) -> Option<String> {
        if let Some(callee) = printed.strip_prefix("call ")
            && let Some(&target) = self.registers.get(callee)
        {
            // A register that holds the address of one function on every
            // path, as one loaded from the stack where the code kept it,
            // names that function.
            return match self.holding[index].reg(target) {
                Some(&Held::Callee(function)) => Some(self.callees[function].clone()),
                _ => Some(callee.to_string()),
            };
        }
        let Some(callee) = line.strip_prefix("call ") else {
            let mut targets = self.targets(index).iter();
            let (Some(target), None) = (targets.next(), targets.next()) else { return None };
            let names = self.registers.iter().filter(|(_, reg)| **reg == target);
            return names.map(|(name, _)| name.clone()).min();
        };
        if callee.starts_with('[') && callee.ends_with(']') {
            let bits = self.arch.pointer_width() * 8;
            return Some(format!("(load.{bits} {callee})"));
        }
        Some(callee.to_string())
    }

    /// The registers that the call at `index` goes through, where its
    /// target is in a register.
    fn targets(&self, index: usize) -> RegSet {
        let mut targets =
            self.lifts[index].as_ref().map_or(RegSet::EMPTY, |named| named.lifted.reads);
        for reg in [Reg::Stack, Reg::Flags, Reg::ProgramCounter, self.convention.stack] {
            targets.remove(reg);
        }
        targets
    }

    /// How many arguments the call of `site` shows: up to the last one that
    /// the code before it sets and nothing but a test or a copy reads. A
    /// call right before the site sets the result register.
    fn argument_count(&self, site: &CallSite) -> usize {
        let targets = self.targets(site.index);
        let lifted = |index: usize| &self.lifts[index].as_ref().expect("a site holds lifts").lifted;
        let start = site.order.first().copied().unwrap_or(site.index).min(site.index);
        let after_call = start.checked_sub(1).is_some_and(|previous| {
            self.entries[start] == 1
                && self.next[previous] == [start]
                && (self.call_of_slot[previous].is_some()
                    || (self.is_call(previous) && !self.has_slots(previous)))
        });
        let passed = |reg: Reg| {
            let from =
                match site.order.iter().rposition(|&index| lifted(index).writes.contains(reg)) {
                    Some(position) => position + 1,
                    None if after_call && reg == self.convention.result.reg => 0,
                    None => return false,
                };
            site.order[from..].iter().all(|&later| {
                let later = lifted(later);
                let is_test = later.memory.is_none()
                    && later.writes.difference(RegSet::from_iter([Reg::Flags])).is_empty();
                let copies = copy_of(&later.clone().canonical())
                    .is_some_and(|(dest, source)| source == reg && dest != reg);
                !later.reads.contains(reg) || is_test || copies
            })
        };
        self.convention
            .arguments
            .iter()
            .rposition(|arg| !targets.contains(arg.reg) && passed(arg.reg))
            .map_or(0, |position| position + 1)
    }

    /// What instruction `index` reads and writes, for the registers that
    /// can be live after it, with a call after its delay slot.
    fn effects(&self, index: usize, reads_of_call: &HashMap<usize, RegSet>) -> (RegSet, RegSet) {
        let convention = self.convention;
        let all_arguments: RegSet = convention.arguments.iter().map(|arg| arg.reg).collect();
        let result = RegSet::from_iter([convention.result.reg]);
        let (unknown_reads, all_arguments) = match self.unknown {
            Unknown::ReadsArguments => (RegSet::ALL, all_arguments),
            Unknown::ReadsNothing => (RegSet::EMPTY, RegSet::EMPTY),
        };
        let own = || match &self.lifts[index] {
            None => (unknown_reads, RegSet::EMPTY),
            Some(named) if self.is_conditional(index) => (self.reads_of(index), RegSet::EMPTY),
            Some(named) => (self.reads_of(index), named.lifted.writes),
        };
        // A call can change each register that it does not keep.
        let changed: RegSet = (0..GENERAL_REGISTERS)
            .map(Reg::General)
            .filter(|reg| !convention.preserves(*reg))
            .chain([convention.result.reg])
            .collect();
        let call = |call: usize| {
            // A call the high IL does not show may read any argument.
            let arguments = reads_of_call.get(&call).copied().unwrap_or(all_arguments);
            (arguments.union(self.targets(call)), changed)
        };
        if let Some(at) = self.call_of_slot[index] {
            let ((slot_reads, slot_writes), (call_reads, call_writes)) = (own(), call(at));
            let reads = slot_reads.union(call_reads.difference(slot_writes));
            return (reads, slot_writes.union(call_writes));
        }
        match self.insns[index].kind {
            InsnKind::Call { .. } if self.has_slots(index) => (RegSet::EMPTY, RegSet::EMPTY),
            InsnKind::Call { .. } => call(index),
            InsnKind::Return => (own().0.union(result), RegSet::EMPTY),
            // A jump out of the function is a call that returns for it.
            InsnKind::Jump { .. } if self.next[index].is_empty() => {
                (own().0.union(all_arguments).union(result), RegSet::EMPTY)
            }
            _ => own(),
        }
    }

    /// The registers that code from each instruction on can read before
    /// it writes them, on some path.
    fn live_in(&self, sites: &[CallSite]) -> Vec<RegSet> {
        let reads_of_call: HashMap<usize, RegSet> = sites
            .iter()
            .map(|site| {
                // A guessed count can leave out an argument the callee reads.
                let count = match (site.counted, self.unknown) {
                    (Counted::ByCaller, Unknown::ReadsArguments) => self.convention.arguments.len(),
                    _ => site.count,
                };
                let registers = &self.convention.arguments;
                let read = registers[..count.min(registers.len())].iter().map(|arg| arg.reg);
                // A local function of 32-bit x86 can take registers, which a
                // guessed count does not say.
                let in_registers =
                    match (site.counted, self.unknown, self.convention.stack_arguments) {
                        (Counted::ByCaller, Unknown::ReadsArguments, Some(_)) => {
                            LOCAL_REGISTERS.len()
                        }
                        _ => site.in_registers,
                    };
                let local = LOCAL_REGISTERS[..in_registers].iter().map(|arg| arg.reg);
                (site.index, read.chain(local).collect())
            })
            .collect();
        let effects: Vec<(RegSet, RegSet)> =
            (0..self.insns.len()).map(|index| self.effects(index, &reads_of_call)).collect();
        let mut live = vec![RegSet::EMPTY; self.insns.len()];
        let mut changed = true;
        while changed {
            changed = false;
            for index in (0..self.insns.len()).rev() {
                let (reads, writes) = effects[index];
                let before = reads.union(self.live_after(&live, index).difference(writes));
                if before != live[index] {
                    live[index] = before;
                    changed = true;
                }
            }
        }
        live
    }

    fn live_after(&self, live_in: &[RegSet], index: usize) -> RegSet {
        self.next[index]
            .iter()
            .fold(RegSet::EMPTY, |live, &successor| live.union(live_in[successor]))
    }

    /// Whether instruction `index` runs only on a condition, as A32 code
    /// can.
    fn is_conditional(&self, index: usize) -> bool {
        crate::a32_condition(&self.insns[index], None).is_some()
    }

    /// The name of the place on the stack `at` bytes from the stack pointer
    /// at the entry: an argument where the ABI passes one there, as `arg1`,
    /// or else as [`slot_name`] names it.
    fn place_name(&self, at: i64) -> String {
        match self.convention.stack_arguments {
            Some(stack) if at >= stack.first && (at - stack.first) % stack.width == 0 => {
                format!("arg{}", (at - stack.first) / stack.width + 1)
            }
            _ => slot_name(at),
        }
    }

    /// The place on the stack that instruction `index` stores one value to,
    /// and the value, as `push esi` and `store.32 [esp + 0x8] = 3` do.
    fn stack_store(&self, index: usize) -> Option<(i64, String)> {
        let named = self.lifts[index].as_ref()?;
        let lifted = &named.lifted;
        // A push of a place in memory loads and stores at once.
        if lifted.memory?.kind == AccessKind::Load {
            return None;
        }
        let holding = &self.holding[index];
        let stack = self.convention.stack;
        let at_of = |reg: Reg| match holding.reg(reg) {
            Some(&Held::Stack(at)) => Some(at),
            _ => None,
        };
        let (at, value) = match lifted.operands.as_slice() {
            // A push stores below the stack pointer, and moves it there.
            [value @ (Operand::Reg(_) | Operand::Const(_) | Operand::Memory { .. })]
                if lifted.writes.contains(stack) && lifted.op == Op::Store =>
            {
                (at_of(stack)? - self.width(lifted), (value, named.names.first()?))
            }
            [
                Operand::Memory { base: Some(base), offset, index: None, update: Update::None },
                value,
            ] if matches!(value, Operand::Reg(_) | Operand::Const(_)) => {
                (at_of(*base)? + displacement(*offset), (value, named.names.get(1)?))
            }
            _ => return None,
        };
        let shown = match value {
            (Operand::Reg(reg), name) => self.held_name(index, *reg, name),
            // A push of a place in memory passes what the place holds.
            (Operand::Memory { base: Some(base), offset, index: None, .. }, _)
                if matches!(holding.reg(*base), Some(Held::Stack(_))) =>
            {
                let Some(&Held::Stack(base_at)) = holding.reg(*base) else { return None };
                self.place_name(base_at + displacement(*offset))
            }
            (Operand::Memory { .. }, name) => {
                let bits = self.width(lifted) * 8;
                format!("load.{bits} {}", self.renamed(index, name))
            }
            (_, name) => name.to_string(),
        };
        Some((at, shown))
    }

    /// The argument that the store at `index` sets for a call at whose entry
    /// the stack pointer holds `at_call`, counted from 0.
    fn stack_argument_of(&self, index: usize, at_call: i64) -> Option<(usize, String)> {
        let stack = self.convention.stack_arguments?;
        // A save of a register is no argument.
        if self.upkeep.get(index).copied().unwrap_or(false) {
            return None;
        }
        let (at, value) = self.stack_store(index)?;
        let distance = at - at_call;
        let argument = (distance >= 0 && distance % stack.width == 0)
            .then(|| (distance / stack.width) as usize)
            .filter(|&argument| argument < MOST_STACK_ARGUMENTS)?;
        Some((argument, value))
    }

    /// What the stack pointer holds at the call at `index`.
    fn stack_at(&self, index: usize) -> Option<i64> {
        match self.holding[index].reg(self.convention.stack) {
            Some(&Held::Stack(at)) => Some(at),
            _ => None,
        }
    }

    /// How many arguments on the stack the code before the call of `site`
    /// sets, each from the first, with none left out.
    fn stack_argument_count(&self, site: &CallSite) -> usize {
        let Some(at_call) = self.stack_at(site.index) else { return 0 };
        let mut set = [false; MOST_STACK_ARGUMENTS];
        for &index in site.order.iter().filter(|&&index| index < site.index) {
            if let Some((argument, _)) = self.stack_argument_of(index, at_call) {
                set[argument] = true;
            }
        }
        set.iter().take_while(|&&set| set).count()
    }

    /// The name that argument `reg` shows as where the code before the call
    /// at `index` does not set it, by what it holds there.
    fn held_name(&self, index: usize, reg: Reg, name: &str) -> String {
        match self.holding[index].reg(reg) {
            Some(Held::Argument(n)) => format!("arg{n}"),
            Some(Held::Result) => "ret".to_string(),
            Some(Held::Stack(at)) => format!("&{}", self.place_name(*at)),
            Some(Held::Callee(callee)) => format!("&{}", self.callees[*callee]),
            Some(Held::Entry(_)) | None => name.to_string(),
        }
    }
}

/// A call site, with what folds into the call.
struct Block<'b, 'a> {
    body: &'b Body<'a>,
    lines: &'b [String],
    folds: &'b [Fold],
    site: CallSite,
    /// The instructions that fold into the call.
    hidden: HashSet<usize>,
}

impl<'b, 'a> Block<'b, 'a> {
    fn new(body: &'b Body<'a>, lines: &'b [String], folds: &'b [Fold], site: CallSite) -> Self {
        Self { body, lines, folds, site, hidden: HashSet::new() }
    }

    fn lifted(&self, index: usize) -> &'b Lifted {
        // A call site holds only lifted instructions.
        &self.body.lifts[index].as_ref().expect("a site holds lifts").lifted
    }

    /// The position in the order of the site of the last instruction before
    /// position `end` that writes `reg`.
    fn last_setting(&self, reg: Reg, end: usize) -> Option<usize> {
        self.site.order[..end].iter().rposition(|&index| self.lifted(index).writes.contains(reg))
    }

    fn read_between(&self, reg: Reg, positions: core::ops::Range<usize>) -> bool {
        self.site.order[positions].iter().any(|&index| self.lifted(index).reads.contains(reg))
    }

    /// The value that instruction `index` puts in `reg`, where it does
    /// nothing else, as the text after `a0 = `.
    fn only_sets(&self, index: usize, reg: Reg) -> Option<&'b str> {
        let lifted = self.lifted(index);
        let pure = lifted.writes == RegSet::from_iter([reg])
            && lifted.memory.is_none_or(|access| access.kind == AccessKind::Load)
            && self.folds[index] == Fold::Own
            && !self.body.is_conditional(index);
        if !pure {
            return None;
        }
        let (dest, value) = self.lines[index].split_once(" = ")?;
        let names_reg = self.body.registers.get(dest) == Some(&reg);
        (names_reg && !value.contains(';')).then_some(value)
    }

    /// Whether no path that leaves the site after position `position` reads
    /// `reg` before it writes it.
    fn stays_inside(&self, reg: Reg, position: usize, live: &[RegSet]) -> bool {
        self.site.order[position..].iter().filter(|&&index| index < self.site.index).all(|&index| {
            self.body.next[index]
                .iter()
                .filter(|&&successor| successor != index + 1)
                .all(|&successor| !live[successor].contains(reg))
        })
    }

    /// Whether the setting at `position` can move into the call: nothing
    /// after it reads `reg`, changes a value it reads, or stores where it
    /// loads, and no path that leaves reads `reg`. A save of a register to
    /// the new frame stores nowhere that a load can read. A register that shows
    /// by its role, as `arg1`, or as a place on the stack, names a value
    /// that a later write to the register does not change.
    fn can_move(&self, position: usize, reg: Reg, live: &[RegSet]) -> bool {
        let setter = self.site.order[position];
        let lifted = self.lifted(setter);
        let loads = lifted.memory.is_some();
        let holding = &self.body.holding[setter];
        let inputs: RegSet = lifted
            .reads
            .iter()
            .filter(|reg| !matches!(holding.reg(*reg), Some(Held::Argument(_) | Held::Stack(_))))
            .collect();
        !self.read_between(reg, position + 1..self.site.order.len())
            && self.stays_inside(reg, position, live)
            && self.site.order[position + 1..].iter().all(|&index| {
                let later = self.lifted(index);
                let changes_input = later.writes.iter().any(|written| inputs.contains(written));
                let stores = !self.body.upkeep[index]
                    && later.memory.is_some_and(|access| {
                        matches!(access.kind, AccessKind::Store | AccessKind::LoadStore)
                    });
                !changes_input && !(loads && stores)
            })
    }

    /// Hide the page that the setting at `position` adds its offset to, as
    /// `x1 = &page` before `x1 = load.64 [@setgid]`: the setting names the
    /// whole address. Any other value that it reads stays.
    fn hide_feeders(&mut self, reg: Reg, mut position: usize, live: &[RegSet]) {
        while self.lifted(self.site.order[position]).reads.contains(reg)
            && let Some(earlier) = self.last_setting(reg, position)
            && self.only_sets(self.site.order[earlier], reg) == Some("&page")
            && !self.read_between(reg, earlier + 1..position)
            && self.stays_inside(reg, earlier, live)
        {
            self.hidden.insert(self.site.order[earlier]);
            position = earlier;
        }
    }

    fn into_call(mut self, live: &[RegSet]) -> Call {
        let body = self.body;
        let index = self.site.index;
        let end = self.site.order.len();
        let targets = body.targets(index);
        // A callee the IL names takes the place of the register the call
        // goes through, so the setting of that register folds away.
        // A call reads its target before its delay slot runs.
        let before_call = self.site.order.iter().take_while(|&&at| at < index).count();
        // A register that keeps its value over the call, as `x21`, can take
        // a callee that a later call reads again. Code after the call can
        // read no other register before it sets it.
        let live_after_call = body.live_after(live, self.site.last);
        let convention_keeps = |reg: Reg| body.convention.preserves(reg);
        let dead_after =
            |target: Reg| !convention_keeps(target) || !live_after_call.contains(target);
        let mut callee = core::mem::take(&mut self.site.callee);
        match body.registers.get(&callee) {
            None => {
                for target in targets.iter() {
                    if let Some(position) = self.last_setting(target, before_call)
                        && self.only_sets(self.site.order[position], target).is_some()
                        && !self.read_between(target, position + 1..end)
                        && self.stays_inside(target, position, live)
                        && dead_after(target)
                    {
                        self.hidden.insert(self.site.order[position]);
                        self.hide_feeders(target, position, live);
                    }
                }
            }
            // A call through a register that the code before it loads shows
            // the load, as `(load.32 [arg1 + 0x8])(…)`. A call that reads a
            // second register, as the modifier of an AArch64 `blraa`, keeps
            // the name of the register, and so does a register that holds a
            // constant: the IL names a call to a known address.
            Some(&target) => {
                callee = body.held_name(index, target, &callee);
                if targets.len() == 1
                    && let Some(position) = self.last_setting(target, before_call)
                    && let Some(value) = self.only_sets(self.site.order[position], target)
                    && !value.starts_with(|c: char| c.is_ascii_digit() || c == '-')
                    && self.can_move(position, target, live)
                    && dead_after(target)
                {
                    callee = format!("({value})");
                    self.hidden.insert(self.site.order[position]);
                    self.hide_feeders(target, position, live);
                }
            }
        }
        let (arguments, registers) = match body.convention.stack_arguments {
            // The registers of a local function come first, then the stack.
            Some(_) => {
                let registers = &LOCAL_REGISTERS[..self.site.in_registers];
                let mut arguments = self.register_arguments(registers, targets, live);
                arguments.extend(self.stack_arguments());
                (arguments, registers)
            }
            None => {
                let registers = &body.convention.arguments[..self.site.count];
                (self.register_arguments(registers, targets, live), registers)
            }
        };
        let reads = registers.iter().map(|arg| arg.reg).collect();
        let gives = body.live_after(live, self.site.last).contains(body.convention.result.reg);
        let mut hidden: Vec<usize> = self.hidden.into_iter().collect();
        hidden.sort_unstable();
        Call { index, last: self.site.last, callee, arguments, hidden, gives, reads }
    }

    /// The arguments of the call that `registers` pass: each the value its
    /// setting puts there, which folds into the call where it can move, or
    /// else the register.
    fn register_arguments(
        &mut self,
        registers: &[NamedReg],
        targets: RegSet,
        live: &[RegSet],
    ) -> Vec<String> {
        let body = self.body;
        let index = self.site.index;
        let end = self.site.order.len();
        let mut arguments = Vec::with_capacity(registers.len());
        for arg in registers {
            let setting = self.last_setting(arg.reg, end).filter(|_| !targets.contains(arg.reg));
            let shown = match setting {
                Some(position) => {
                    let setter = self.site.order[position];
                    match self.only_sets(setter, arg.reg) {
                        Some(value) if self.can_move(position, arg.reg, live) => {
                            self.hidden.insert(setter);
                            self.hide_feeders(arg.reg, position, live);
                            value.to_string()
                        }
                        // The setting stays, so the argument shows as the
                        // register it names, as `x1` of `x3, x1 = …`, or
                        // as what it holds.
                        _ => {
                            let name = self.lines[setter]
                                .split_once(" = ")
                                .and_then(|(dest, _)| {
                                    dest.split(", ")
                                        .find(|word| body.registers.get(*word) == Some(&arg.reg))
                                })
                                .unwrap_or(arg.name);
                            body.held_name(index, arg.reg, name)
                        }
                    }
                }
                None => body.held_name(index, arg.reg, arg.name),
            };
            arguments.push(shown);
        }
        arguments
    }
}

/// How many arguments the callee `name` reads: by its prototype, where the
/// table of [`arity`] holds it, or else by its code, where `context` holds
/// a function of that name.
fn arity_of(
    arch: &dyn Arch,
    convention: CallingConvention,
    context: Option<Context<'_>>,
    name: &str,
) -> Option<Takes> {
    if let Some(arity) = arity::known(name) {
        return Some(arity.into());
    }
    let context = context?;
    let label = |function: &hereticus_image::Function| {
        let paired = context.paired.and_then(|paired| paired.0.get(&function.address));
        paired.cloned().unwrap_or_else(|| function.label())
    };
    let function = context.functions.iter().find(|function| label(function) == name)?;
    arity_of_code(arch, convention, &function.code, function.address)
}

/// How many arguments the function of `code`, at `address`, reads before it
/// writes them. A function that jumps out to another reads at least as
/// many as it reads itself, as the other can read more.
fn arity_of_code(
    arch: &dyn Arch,
    convention: CallingConvention,
    code: &[u8],
    address: u64,
) -> Option<Takes> {
    let (insns, _) = hereticus_recovery::arch::decode_all(arch, code, address);
    if insns.is_empty() || insns.len() > MOST_READ_OF_A_CALLEE {
        return None;
    }
    let printed = instruction_lines(arch, code, &insns, None);
    let mut body = Body::new(arch, convention, &insns, &printed);
    body.unknown = Unknown::ReadsNothing;
    let folds = folds(arch, &insns);
    let sites: Vec<CallSite> = (0..insns.len())
        .filter_map(|index| body.call_site(index, &printed, &printed, &folds))
        .collect();
    let live = body.live_in(&sites);
    let read = *live.first()?;
    let count = convention
        .arguments
        .iter()
        .rposition(|arg| read.contains(arg.reg))
        .map_or(0, |position| position + 1);
    // An ABI that passes the arguments on the stack: the callee reads them
    // from the places above the stack pointer at its entry.
    if let Some(stack) = convention.stack_arguments {
        let read = (0..insns.len())
            .filter_map(|index| {
                let lifted = body.canonical(index)?;
                if lifted.memory?.kind == AccessKind::Store {
                    return None;
                }
                Some(body.stack_addresses(index, &lifted, &body.holding[index]))
            })
            .flatten()
            .filter(|&at| at >= stack.first && (at - stack.first) % stack.width == 0)
            .map(|at| ((at - stack.first) / stack.width) as usize + 1)
            .max()
            .unwrap_or(0)
            .min(MOST_STACK_ARGUMENTS);
        let jumps_out = insns
            .iter()
            .zip(&body.next)
            .any(|(insn, next)| matches!(insn.kind, InsnKind::Jump { .. }) && next.is_empty());
        // GCC can pass the first arguments of a local function in
        // registers: the callee reads them before it writes them.
        let at_entry = live.first().copied().unwrap_or(RegSet::EMPTY);
        let in_registers = LOCAL_REGISTERS
            .iter()
            .rposition(|arg| at_entry.contains(arg.reg))
            .map_or(0, |position| position + 1);
        let arity = if jumps_out { Arity::AtLeast(read) } else { Arity::Exact(read) };
        return Some(Takes { arity, in_registers });
    }
    if let Some(fixed) = body.variadic_from() {
        return Some(Arity::AtLeast(fixed).into());
    }
    let jumps_out = insns
        .iter()
        .zip(&body.next)
        .any(|(insn, next)| matches!(insn.kind, InsnKind::Jump { .. }) && next.is_empty());
    Some(if jumps_out { Arity::AtLeast(count) } else { Arity::Exact(count) }.into())
}

impl Block<'_, '_> {
    /// The arguments of a call that the ABI passes on the stack: each the
    /// value the code before the call stores where the argument sits, which
    /// folds into the call, or else the place, by its name.
    fn stack_arguments(&mut self) -> Vec<String> {
        let body = self.body;
        let index = self.site.index;
        let Some(stack) = body.convention.stack_arguments else { return Vec::new() };
        let Some(at_call) = body.stack_at(index) else { return Vec::new() };
        let before: Vec<usize> = self.site.order.iter().copied().filter(|&at| at < index).collect();
        (0..self.site.count)
            .map(|argument| {
                let place = at_call + argument as i64 * stack.width;
                let setting = before.iter().rposition(|&at| {
                    body.stack_argument_of(at, at_call).is_some_and(|(set, _)| set == argument)
                });
                let Some(position) = setting else { return body.place_name(place) };
                let setter = before[position];
                let Some((_, value)) = body.stack_argument_of(setter, at_call) else {
                    return body.place_name(place);
                };
                // The value folds where nothing after its store changes a
                // register it reads.
                let lifted = self.lifted(setter);
                let inputs = lifted.reads.difference(RegSet::from_iter([body.convention.stack]));
                let changed = before[position + 1..].iter().any(|&later| {
                    self.lifted(later)
                        .writes
                        .iter()
                        .any(|written| inputs.contains(written) && written != body.convention.stack)
                });
                // A place the code loads from again holds a value of its
                // own, as GCC keeps locals right above the arguments on
                // 32-bit x86: its store stays.
                if changed || body.loaded_places.contains(&place) {
                    return body.place_name(place);
                }
                self.hidden.insert(setter);
                value
            })
            .collect()
    }
}

/// Where `lifted` adds a constant to a register that holds a place on the
/// stack, or copies one, the register it writes and the place it then
/// holds.
fn stack_arithmetic(lifted: &Lifted, holding: &Holding) -> Option<(Reg, i64)> {
    let (dest, source, value) = match (lifted.op, lifted.operands.as_slice()) {
        (
            Op::Add | Op::Subtract,
            [Operand::Reg(dest), Operand::Reg(source), Operand::Const(value)],
        )
        | (Op::Add, [Operand::Reg(dest), Operand::Const(value), Operand::Reg(source)]) => {
            (*dest, *source, signed(*value))
        }
        // An x86 `lea` forms the address of a place.
        (
            Op::Add,
            [
                Operand::Reg(dest),
                Operand::Memory { base: Some(source), offset, index: None, update: Update::None },
            ],
        ) => (*dest, *source, displacement(*offset)),
        _ => {
            let (dest, source) = copy_of(lifted)?;
            (dest, source, 0)
        }
    };
    let Held::Stack(at) = *holding.reg(source)? else { return None };
    Some((dest, if lifted.op == Op::Subtract { at - value } else { at + value }))
}

/// Where `lifted` copies one register to another, the register it writes
/// and the one it reads. AArch64 lifts `mov x29, sp` and `mov x19, x0`
/// with a zero operand.
fn copy_of(lifted: &Lifted) -> Option<(Reg, Reg)> {
    let zero = |operand: &Operand| matches!(operand, Operand::Zero | Operand::Const(0));
    match (lifted.op, lifted.operands.as_slice()) {
        (Op::Move, [Operand::Reg(dest), Operand::Reg(source)]) => Some((*dest, *source)),
        (Op::Move, [Operand::Reg(dest), Operand::Reg(source), other])
        | (Op::Move, [Operand::Reg(dest), other, Operand::Reg(source)])
            if zero(other) =>
        {
            Some((*dest, *source))
        }
        _ => None,
    }
}

/// The function whose address the IL statement `line` loads from a slot of
/// the global offset table, as `strcmp` of `x26 = load.64 [@strcmp]`.
fn loaded_function(line: &str) -> Option<&str> {
    let (_, value) = line.split_once(" = load.")?;
    let name = value.split_once(" [@")?.1.strip_suffix(']')?;
    let is_name = name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@'));
    is_name.then_some(name)
}

/// The register that each name of an operand of `lifts` names, with the
/// names of the registers of `convention`.
fn registers_named(lifts: &[Option<Named>], convention: CallingConvention) -> HashMap<String, Reg> {
    let mut registers: HashMap<String, Reg> = convention
        .arguments
        .iter()
        .chain([&convention.result])
        .map(|arg| (arg.name.to_string(), arg.reg))
        .collect();
    for named in lifts.iter().flatten() {
        for (operand, name) in named.lifted.operands.iter().zip(&named.names) {
            let mut words = register_words(name);
            match *operand {
                Operand::Reg(reg) if !name.is_empty() => {
                    registers.insert(name.to_string(), reg);
                }
                Operand::Shifted { reg, .. } => {
                    if let Some(word) = words.next() {
                        registers.insert(word.to_string(), reg);
                    }
                }
                Operand::Memory { base, index, .. } => {
                    for reg in base.into_iter().chain(index.map(|(reg, _)| reg)) {
                        if let Some(word) = words.next() {
                            registers.insert(word.to_string(), reg);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    registers
}

/// The words of `name` that can name a register: no number and no address.
fn register_words(name: &str) -> impl Iterator<Item = &str> {
    name.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '@' || c == '$'))
        .filter(|word| word.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'))
}

/// `text` with each word that `role` names replaced, outside strings and
/// addresses. The registers to the left of ` = ` keep their names, where
/// no memory operand is there: what they hold after the statement is
/// another value.
fn rename_registers(text: &str, role: impl Fn(&str) -> Option<String>) -> String {
    statements_of(text).map(|statement| rename_in(statement, &role)).collect::<Vec<_>>().join("; ")
}

/// The statements of `text` that `; ` joins, as a write-back joins its
/// access, outside strings.
fn statements_of(text: &str) -> impl Iterator<Item = &str> {
    let mut quoted = false;
    let mut escaped = false;
    let mut starts = vec![0];
    for (at, c) in text.char_indices() {
        match c {
            '"' if !escaped => quoted = !quoted,
            ';' if !quoted && text[at..].starts_with("; ") => starts.push(at + 2),
            _ => {}
        }
        escaped = quoted && c == '\\' && !escaped;
    }
    let ends: Vec<usize> = starts[1..].iter().map(|start| start - 2).chain([text.len()]).collect();
    starts.into_iter().zip(ends).map(move |(start, end)| &text[start..end])
}

/// [`rename_registers`] of one statement.
fn rename_in(text: &str, role: &impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    if let Some((dest, value)) = text.split_once(" = ")
        && !dest.contains('[')
    {
        out.push_str(dest);
        out.push_str(" = ");
        rest = value;
    }
    let mut quoted = false;
    let mut escaped = false;
    let mut word = String::new();
    let mut previous = ' ';
    let mut before_word = ' ';
    let flush = |word: &mut String, out: &mut String, before: char| {
        let is_symbol = matches!(before, '@' | '$' | '.');
        match role(word).filter(|_| !is_symbol) {
            Some(name) => out.push_str(&name),
            None => out.push_str(word),
        }
        word.clear();
    };
    for c in rest.chars() {
        if quoted {
            out.push(c);
            match c {
                '"' if !escaped => quoted = false,
                '\\' => escaped = !escaped,
                _ => escaped = false,
            }
        } else if c.is_ascii_alphanumeric() || c == '_' {
            if word.is_empty() {
                before_word = previous;
            }
            word.push(c);
        } else {
            flush(&mut word, &mut out, before_word);
            out.push(c);
            quoted = c == '"';
            escaped = false;
        }
        previous = c;
    }
    flush(&mut word, &mut out, before_word);
    out
}

/// `text` with a load or a store of one value at a place on the stack
/// written as the place alone: `v0 = load.32 var_1c` is `v0 = var_1c`, and
/// `store.32 var_1c = a0` is `var_1c = a0`.
fn plain_slot_access(text: &str) -> String {
    let without_width = |rest: &str| -> Option<String> {
        let rest = rest.trim_start_matches(|c: char| c.is_ascii_digit()).strip_prefix(' ')?;
        Some(rest.to_string())
    };
    if let Some((dest, value)) = text.split_once(" = load.")
        && let Some(place) = without_width(value)
        && is_slot(&place)
    {
        return format!("{dest} = {place}");
    }
    if let Some(rest) = text.strip_prefix("store.")
        && let Some(rest) = without_width(rest)
        && let Some((place, value)) = rest.split_once(" = ")
        && is_slot(place)
        && !value.contains([',', ';'])
    {
        return format!("{place} = {value}");
    }
    text.to_string()
}

/// Whether `word` names a place on the stack, as `var_1c` or `arg_10`.
fn is_slot(word: &str) -> bool {
    let named = word
        .strip_prefix("var_")
        .or_else(|| word.strip_prefix("arg_"))
        .is_some_and(|hex| !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()));
    // An argument that the ABI passes on the stack, as `arg1`.
    let argument = word
        .strip_prefix("arg")
        .is_some_and(|digits| !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()));
    named || argument
}

/// The name of the place on the stack `at` bytes from the stack pointer of
/// the entry.
fn slot_name(at: i64) -> String {
    if at < 0 { format!("var_{:x}", at.unsigned_abs()) } else { format!("arg_{at:x}") }
}

/// The displacement of a memory operand as a signed number: 32-bit x86
/// lifts `[ebp - 8]` with `0xfffffff8`.
fn displacement(offset: Option<i64>) -> i64 {
    signed(offset.unwrap_or(0) as u64)
}

/// A constant of the IL as a signed number. A 32-bit architecture can hold
/// a negative one in the low word alone, as `0xffffffb8`.
fn signed(value: u64) -> i64 {
    if (0xffff_0000..=0xffff_ffff).contains(&value) {
        value as i64 - 0x1_0000_0000
    } else {
        value as i64
    }
}

/// A constant as the IL names it, as `0x20`, `-0x10` or `8`.
fn parse_constant(text: &str) -> Option<i64> {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => (false, text),
    };
    let value = match digits.strip_prefix("0x") {
        Some(hex) => i64::from_str_radix(hex, 16).ok()?,
        None => digits.parse().ok()?,
    };
    Some(if negative { -value } else { value })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hereticus_il::arch::aarch64::Aarch64;
    use hereticus_il::arch::arm32::Arm32;
    use hereticus_il::arch::mips::Mips32;
    use hereticus_image::Links;
    use hereticus_recovery::arch::decode_all;

    fn aarch64(words: &[u32]) -> Vec<String> {
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = decode_all(&Aarch64, &code, 0x1000);
        hil_statements_in(&Aarch64, &code, &insns, None).into_iter().map(|line| line.text).collect()
    }

    fn mips(words: &[u32]) -> Vec<String> {
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
        let (insns, _) = decode_all(&Mips32::BIG, &code, 0x1000);
        hil_statements_in(&Mips32::BIG, &code, &insns, None)
            .into_iter()
            .map(|line| line.text)
            .collect()
    }

    /// The settings of the arguments fold into the call, and a return
    /// that reads the result names it.
    #[test]
    fn a_call_shows_its_arguments_and_its_result() {
        let shown = aarch64(&[
            0x5280_0020, // mov w0, #1
            0x5280_00a1, // mov w1, #5
            0x9400_0040, // bl $+0x100
            0xd65f_03c0, // ret
        ]);
        assert_eq!(shown, ["ret = $+0x100(1, 5)", "return"]);
    }

    /// A store reads `w0` before the call, so the call may read no
    /// argument: it shows none. A callee of no known count can still read
    /// `w0`, so its setting stays.
    #[test]
    fn a_register_that_other_code_reads_is_no_argument() {
        let shown = aarch64(&[
            0x5280_0020, // mov w0, #1
            0xb900_0020, // str w0, [x1]
            0x9400_0040, // bl $+0x100
            0xd65f_03c0, // ret
        ]);
        assert_eq!(shown, ["w0 = 1", "store.32 [arg2] = w0", "ret = $+0x100()", "return"]);
    }

    /// A test does not stop a register from being an argument, but the
    /// other path of the branch reads it, so its setting stays.
    #[test]
    fn a_setting_that_another_path_reads_stays() {
        let shown = aarch64(&[
            0x5280_0020, // mov w0, #1
            0x3400_0041, // cbz w1, $+0x8
            0x9400_0040, // bl $+0x100
            0xd65f_03c0, // ret
        ]);
        assert_eq!(shown, ["w0 = 1", "if (arg2 == 0) goto $+0x8", "ret = $+0x100(w0)", "return"]);
    }

    /// The save and restore of the frame and the making of the frame
    /// pointer do not show, and an argument shows by its role.
    #[test]
    fn the_upkeep_of_the_frame_does_not_show() {
        let shown = aarch64(&[
            0xa9bf_7bfd, // stp x29, x30, [sp, #-0x10]!
            0x9100_03fd, // mov x29, sp
            0xb940_1000, // ldr w0, [x0, #0x10]
            0xa8c1_7bfd, // ldp x29, x30, [sp], #0x10
            0xd65f_03c0, // ret
        ]);
        assert_eq!(shown, ["w0 = load.32 [arg1 + 0x10]", "return"]);
    }

    /// A place on the stack shows by its distance below the stack pointer
    /// of the entry, and its address as `&` and its name.
    #[test]
    fn a_place_on_the_stack_shows_by_name() {
        let shown = aarch64(&[
            0xd100_83ff, // sub sp, sp, #0x20
            0xb900_0fe0, // str w0, [sp, #0xc]
            0x9100_23e1, // add x1, sp, #0x8
            0x9400_0040, // bl $+0x100
            0x9100_83ff, // add sp, sp, #0x20
            0xd65f_03c0, // ret
        ]);
        assert_eq!(shown, ["var_14 = arg1", "ret = $+0x100(arg1, &var_18)", "return"]);
    }

    /// A `push` and a `sub` of the stack move it, so a place on it shows
    /// by name, and the `pop` that returns shows as the return.
    #[test]
    fn a_push_moves_the_stack_and_its_pop_returns() {
        let code: Vec<u8> = [
            0xe92d_4010_u32, // push {r4, lr}
            0xe24d_d008,     // sub sp, sp, #8
            0xe28d_1004,     // add r1, sp, #4
            0xeb00_0040,     // bl $+0x108
            0xe28d_d008,     // add sp, sp, #8
            0xe8bd_8010,     // pop {r4, pc}
        ]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
        let (insns, _) = decode_all(&Arm32, &code, 0x1000);
        let shown: Vec<String> = hil_statements_in(&Arm32, &code, &insns, None)
            .into_iter()
            .map(|line| line.text)
            .collect();
        assert_eq!(shown.len(), 2, "{shown:?}");
        assert_eq!(shown[0], "ret = $+0x108(arg1, &var_c)");
    }

    /// A load of two registers stays, and each argument it sets shows as
    /// its own register. `x2` is no setting of the code, so it shows as the
    /// argument it holds.
    #[test]
    fn an_argument_that_a_load_of_two_sets_shows_as_its_register() {
        let shown = aarch64(&[
            0xa940_8403, // ldp x3, x1, [x0, #0x8]
            0x9400_0040, // bl $+0x100
            0xd65f_03c0, // ret
        ]);
        assert_eq!(
            shown,
            ["x3, x1 = load.64 [arg1 + 0x8]", "ret = $+0x100(arg1, x1, arg3, x3)", "return"]
        );
    }

    /// A MIPS16e `save` and `restore` make and drop the frame, so they show
    /// no line, and a place in the frame shows by name.
    #[test]
    fn a_mips16e_save_and_restore_keep_the_frame() {
        use hereticus_il::arch::mips16::Mips16;
        // save 0x20, s0, ra; addiu a1, sp, 4; restore 0x20, s0, ra; jrc ra
        let halfwords: [u16; 4] = [0x64e4, 0x0501, 0x6464, 0xe8a0];
        let code: Vec<u8> = halfwords.iter().flat_map(|half| half.to_be_bytes()).collect();
        let (insns, _) = decode_all(&Mips16::BIG, &code, 0x1000);
        let shown: Vec<String> = hil_statements_in(&Mips16::BIG, &code, &insns, None)
            .into_iter()
            .map(|line| line.text)
            .collect();
        assert_eq!(shown, ["a1 = &var_1c", "return"]);
    }

    /// A T32 `push` names its list alone, and moves the stack all the same.
    #[test]
    fn a_t32_push_moves_the_stack() {
        use hereticus_il::arch::thumb::Thumb2;
        // push {r4, lr}; sub sp, #8; add r1, sp, #4; add sp, #8; pop {r4, pc}
        let halfwords: [u16; 5] = [0xb510, 0xb082, 0xa901, 0xb002, 0xbd10];
        let code: Vec<u8> = halfwords.iter().flat_map(|half| half.to_le_bytes()).collect();
        let (insns, _) = decode_all(&Thumb2, &code, 0x1000);
        let shown: Vec<String> = hil_statements_in(&Thumb2, &code, &insns, None)
            .into_iter()
            .map(|line| line.text)
            .collect();
        assert_eq!(shown, ["r1 = &var_c", "return"]);
    }

    /// A word of data that a jump through a register seems to reach leaves
    /// what the code after it holds as the jump left it.
    #[test]
    fn a_word_of_data_leads_nowhere() {
        use hereticus_il::arch::arm32::Arm32;
        let words: [u32; 5] = [
            0xe92d_4010, // push {r4, lr}
            0xe12f_ff13, // bx r3
            0x0000_493c, // a word of a table
            0xe28d_1004, // add r1, sp, #4, which only the jump reaches
            0xe8bd_8010, // pop {r4, pc}
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (mut insns, _) = decode_all(&Arm32, &code, 0x1000);
        insns[2] = hereticus_il::arch::data_word(insns[2].address, insns[2].bytes());
        let shown: Vec<String> = hil_statements_in(&Arm32, &code, &insns, None)
            .into_iter()
            .map(|line| line.text)
            .collect();
        assert!(shown.contains(&"r1 = &var_4".to_string()), "{shown:?}");
    }

    /// x86-64 `push` and `pop` move the stack, and they save and restore
    /// `rbx`.
    #[test]
    fn a_push_and_a_pop_of_x86_keep_the_frame() {
        use hereticus_il::arch::x86::X86;
        let code = [
            0x53, // push rbx
            0x48, 0x83, 0xec, 0x10, // sub rsp, 0x10
            0x48, 0x8d, 0x74, 0x24, 0x08, // lea rsi, [rsp + 8]
            0xe8, 0x00, 0x01, 0x00, 0x00, // call $+0x105
            0x48, 0x83, 0xc4, 0x10, // add rsp, 0x10
            0x5b, // pop rbx
            0xc3, // ret
        ];
        let (insns, _) = decode_all(&X86::BITS64, &code, 0x1000);
        let shown: Vec<String> = hil_statements_in(&X86::BITS64, &code, &insns, None)
            .into_iter()
            .map(|line| line.text)
            .collect();
        assert_eq!(shown.len(), 2, "{shown:?}");
        assert!(shown[0].ends_with("(arg1, &var_10)"), "{shown:?}");
    }

    /// PowerPC links its frame with `stwu` and saves `lr` through `r0`:
    /// none of it shows.
    #[test]
    fn the_link_register_of_powerpc_saves_through_r0() {
        use hereticus_il::arch::powerpc::PowerPc;
        let code: Vec<u8> = [
            0x9421_ffe0_u32, // stwu r1, -0x20(r1)
            0x7c08_02a6,     // mflr r0
            0x9001_0024,     // stw r0, 0x24(r1)
            0x3881_0008,     // addi r4, r1, 8
            0x4800_0101,     // bl $+0x100
            0x8001_0024,     // lwz r0, 0x24(r1)
            0x3821_0020,     // addi r1, r1, 0x20
            0x7c08_03a6,     // mtlr r0
            0x4e80_0020,     // blr
        ]
        .iter()
        .flat_map(|word| word.to_be_bytes())
        .collect();
        let (insns, _) = decode_all(&PowerPc::BIG, &code, 0x1000);
        let shown: Vec<String> = hil_statements_in(&PowerPc::BIG, &code, &insns, None)
            .into_iter()
            .map(|line| line.text)
            .collect();
        assert_eq!(shown.len(), 2, "{shown:?}");
        assert!(shown[0].ends_with("(arg1, &var_18)"), "{shown:?}");
    }

    /// PowerPC calls through `ctr`, which the IL prints as `bctrl`: the call
    /// shows what the code put in `ctr`, here the seventh argument, `r9`.
    #[test]
    fn a_call_through_ctr_shows_the_register() {
        use hereticus_il::arch::powerpc::PowerPc;
        let code: Vec<u8> = [
            0x7d29_03a6_u32, // mtctr r9
            0x4e80_0421,     // bctrl
            0x4e80_0020,     // blr
        ]
        .iter()
        .flat_map(|word| word.to_be_bytes())
        .collect();
        let (insns, _) = decode_all(&PowerPc::BIG, &code, 0x1000);
        let shown: Vec<String> = hil_statements_in(&PowerPc::BIG, &code, &insns, None)
            .into_iter()
            .map(|line| line.text)
            .collect();
        assert_eq!(shown, ["ret = (arg7)()", "return"]);
    }

    /// A call through a register that the code just loaded shows the load
    /// as its callee.
    #[test]
    fn a_call_through_a_loaded_register_shows_the_load() {
        let shown = aarch64(&[
            0xf940_0408, // ldr x8, [x0, #0x8]
            0xd63f_0100, // blr x8
            0xd65f_03c0, // ret
        ]);
        assert_eq!(shown, ["ret = (load.64 [arg1 + 0x8])()", "return"]);
    }

    /// A setting that reads a value set before it folds, and the value
    /// stays.
    #[test]
    fn a_value_that_a_folded_setting_reads_stays() {
        let shown = aarch64(&[
            0x5280_3701, // mov w1, #0x1b8
            0x1100_0c21, // add w1, w1, #3
            0x9400_0040, // bl $+0x100
            0xd65f_03c0, // ret
        ]);
        assert_eq!(shown, ["w1 = 0x1b8", "ret = $+0x100(arg1, w1 + 3)", "return"]);
    }

    /// A copy of what a call gave back is no `ret` after the next call.
    #[test]
    fn a_copy_of_a_result_is_no_result_after_the_next_call() {
        let shown = aarch64(&[
            0x9400_0040, // bl $+0x100
            0xaa00_03f3, // mov x19, x0
            0x9400_0040, // bl $+0x100
            0xaa13_03e0, // mov x0, x19
            0x9400_0040, // bl $+0x100
            0xd65f_03c0, // ret
        ]);
        assert_eq!(shown[1], "x19 = ret");
        assert_eq!(shown[3], "ret = $+0x100(x19)", "{shown:?}");
    }

    /// `blraa` reads its target and a modifier, so the callee stays the
    /// register it names.
    #[test]
    fn a_call_with_a_modifier_keeps_its_register() {
        let shown = aarch64(&[
            0xf940_0008, // ldr x8, [x0]
            0xf2ed_8451, // movk x17, #0x6c22, lsl #48
            0xd73f_0911, // blraa x8, x17
            0xd65f_03c0, // ret
        ]);
        assert!(shown.iter().any(|line| line.starts_with("x8 = ")), "{shown:?}");
        assert!(!shown.iter().any(|line| line.contains("(0x")), "{shown:?}");
    }

    /// What a call gave back passes on to the next call, though the code
    /// copies it first.
    #[test]
    fn a_result_passes_on_to_the_next_call() {
        let shown = aarch64(&[
            0x9400_0040, // bl $+0x100
            0xaa00_03f6, // mov x22, x0
            0x9400_0040, // bl $+0x100
            0xd65f_03c0, // ret
        ]);
        assert_eq!(shown, ["ret = $+0x100()", "x22 = ret", "ret = $+0x100(ret)", "return"]);
    }

    /// The setting of a register that a later call goes through again
    /// stays.
    #[test]
    fn a_target_that_a_later_call_reads_stays() {
        let shown = aarch64(&[
            0xf940_0015, // ldr x21, [x0]
            0xd63f_02a0, // blr x21
            0xd63f_02a0, // blr x21
            0xd65f_03c0, // ret
        ]);
        assert_eq!(shown[0], "x21 = load.64 [arg1]", "{shown:?}");
    }

    /// A call changes the argument registers, so the target of the call
    /// before it is no longer read and folds away.
    #[test]
    fn a_call_ends_the_life_of_an_argument_register() {
        let shown = aarch64(&[
            0xf940_0002, // ldr x2, [x0]
            0xd63f_0040, // blr x2
            0x9400_0040, // bl $+0x100
            0xd65f_03c0, // ret
        ]);
        assert_eq!(shown[0], "ret = (load.64 [arg1])()", "{shown:?}");
    }

    /// A callee of the binary reads as many arguments as its code reads
    /// before it writes them, whatever the caller sets.
    #[test]
    fn a_callee_of_the_binary_takes_the_arguments_its_code_reads() {
        let words: [u32; 6] = [
            0x5280_0020, // 0x1000 mov w0, #1
            0x5280_0041, // 0x1004 mov w1, #2
            0x5280_0062, // 0x1008 mov w2, #3
            0x9400_0002, // 0x100c bl 0x1014
            0xd65f_03c0, // 0x1010 ret
            0x8b01_0000, // 0x1014 add x0, x0, x1, the callee
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let callee = hereticus_image::Function {
            name: "add".into(),
            address: 0x1014,
            code: code[0x14..].to_vec(),
        };
        let functions = [callee];
        let (links, space) = (Links::default(), hereticus_memory::AddressSpace::default());
        let context = Context {
            links: &links,
            space: &space,
            functions: &functions,
            paired: None,
            abi: hereticus_arch::Abi::Unix,
        };
        let (insns, _) = decode_all(&Aarch64, &code[..0x14], 0x1000);
        let shown: Vec<String> = hil_statements_in(&Aarch64, &code[..0x14], &insns, Some(context))
            .into_iter()
            .map(|line| line.text)
            .collect();
        assert_eq!(shown, ["w2 = 3", "ret = add(1, 2)", "return"]);
        let convention = Aarch64
            .calling_convention(hereticus_arch::Abi::Unix)
            .expect("AArch64 has a convention");
        assert_eq!(
            arity_of_code(&Aarch64, convention, &code[0x14..], 0x1014),
            Some(Arity::Exact(2).into())
        );
    }

    /// A function that stores each argument register from the second on,
    /// as `va_start` needs, takes a format and more.
    #[test]
    fn a_callee_that_stores_its_last_arguments_is_variadic() {
        let convention = Aarch64
            .calling_convention(hereticus_arch::Abi::Unix)
            .expect("AArch64 has a convention");
        let words: [u32; 6] = [
            0xa9bf_8be1, // stp x1, x2, [sp, #-0x8]!, as the top of a frame
            0xa9bf_93e3, // stp x3, x4, [sp, #-0x8]!
            0xa9bf_9be5, // stp x5, x6, [sp, #-0x8]!
            0xf81f_8fe7, // str x7, [sp, #-0x8]!
            0x9400_0040, // bl $+0x100
            0xd65f_03c0, // ret
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        assert_eq!(
            arity_of_code(&Aarch64, convention, &code, 0x1000),
            Some(Arity::AtLeast(1).into())
        );
        // A function that stores the one argument it names takes one.
        let one: Vec<u8> = [0xf81f_0fe0_u32, 0xd65f_03c0] // str x0, [sp, #-0x10]!; ret
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        assert_eq!(arity_of_code(&Aarch64, convention, &one, 0x1000), Some(Arity::Exact(1).into()));
    }

    /// The address of a function that the code keeps on the stack over a
    /// call names the call through the register it loads it back into.
    #[test]
    fn a_callee_kept_on_the_stack_names_its_call() {
        let words: [u32; 8] = [
            0xf000_001a, // 0x1000 adrp x26, 0x4000
            0xf940_075a, // 0x1004 ldr x26, [x26, #8]: strcmp
            0xd100_43ff, // 0x1008 sub sp, sp, #0x10
            0xf900_07fa, // 0x100c str x26, [sp, #8]
            0x9400_0040, // 0x1010 bl $+0x100
            0xf940_07e8, // 0x1014 ldr x8, [sp, #8]
            0xd63f_0100, // 0x1018 blr x8
            0xd65f_03c0, // 0x101c ret
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let links = Links::of_parts(
            vec![(0x4000, vec![0; 0x18])],
            std::collections::BTreeMap::from([(0x4008, "strcmp".to_string())]),
        );
        let space = hereticus_memory::AddressSpace::default();
        let context = Context {
            links: &links,
            space: &space,
            functions: &[],
            paired: None,
            abi: hereticus_arch::Abi::Unix,
        };
        let (insns, _) = decode_all(&Aarch64, &code, 0x1000);
        let shown: Vec<String> = hil_statements_in(&Aarch64, &code, &insns, Some(context))
            .into_iter()
            .map(|line| line.text)
            .collect();
        assert!(shown.iter().any(|line| line.starts_with("ret = strcmp(ret, x1)")), "{shown:?}");
    }

    #[test]
    fn a_load_from_a_named_slot_loads_a_function() {
        assert_eq!(loaded_function("x26 = load.64 [@strcmp]"), Some("strcmp"));
        assert_eq!(loaded_function("x0 = load.64 [@0x50990]"), None, "an address");
        assert_eq!(loaded_function("x0 = load.64 [x1 + 0x8]"), None);
        assert_eq!(loaded_function("store.64 [@strcmp] = x0"), None);
        assert_eq!(loaded_function("x0 = load.64 [@strcmp] + 1"), None);
    }

    /// A value that a compare reads folds into the branch that shows the
    /// compare.
    #[test]
    fn a_compared_value_folds_into_its_branch() {
        use hereticus_il::arch::arm32::Arm32;
        let code: Vec<u8> = [
            0xe590_3014_u32, // ldr r3, [r0, #0x14]
            0xe353_0000,     // cmp r3, #0
            0x1a00_0000,     // bne $+0x8
            0xe12f_ff1e,     // bx lr
            0xe350_0000,     // cmp r0, #0
            0x0a00_0000,     // beq $+0x8
            0xe12f_ff1e,     // bx lr
        ]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
        let (insns, _) = decode_all(&Arm32, &code, 0x1000);
        let shown: Vec<String> = hil_statements_in(&Arm32, &code, &insns, None)
            .into_iter()
            .map(|line| line.text)
            .collect();
        assert_eq!(shown[0], "if ((load.32 [arg1 + 0x14]) != 0) goto $+0x8", "{shown:?}");
        assert_eq!(shown[2], "if (arg1 == 0) goto $+0x8", "the return reads no `r0` there");
    }

    #[test]
    fn an_operation_on_two_constants_is_worked_out() {
        assert_eq!(
            simplified("if ((arg3 u< (0x7fff0000 | 0xfff1)) == 0) goto $+0x8"),
            "if ((arg3 u< 0x7ffffff1) == 0) goto $+0x8"
        );
        assert_eq!(simplified("a3 = arg4 + (-0x10000 + 0x760f)"), "a3 = arg4 + -0x89f1");
        assert_eq!(simplified("v0 = load.32 [0 + 0x20]"), "v0 = load.32 [0x20]");
        assert_eq!(
            simplified("s1 = load.32 [@0x440000 + -0x38C0]"),
            "s1 = load.32 [@0x43c740]",
            "an address and a distance"
        );
        assert_eq!(simplified("x = [@strcmp + 4]"), "x = [@strcmp + 4]", "a name stays");
        assert_eq!(simplified("x0 = (x1 + 2)"), "x0 = (x1 + 2)");
        assert_eq!(simplified("w0 = ((1 << 4) | 3)"), "w0 = 0x13");
        assert_eq!(simplified(r#"x0 = &"(1 + 2)""#), r#"x0 = &"(1 + 2)""#, "a string stays");
    }

    #[test]
    fn padding_that_does_nothing_shows_no_line() {
        assert!(does_nothing("esi = &[esi]"));
        assert!(!does_nothing("esi = &[esi + 0x4]"));
        assert!(!does_nothing("esi = &[edi]"));
    }

    #[test]
    fn a_branch_names_its_test_where_it_shows_the_operands() {
        assert!(names_its_test("if (r1 == 2) goto $+0x8"));
        assert!(names_its_test("if ((w0 & 0x80000000) == 0) goto $+0x10"));
        assert!(!names_its_test("if (ne) return"));
        assert!(!names_its_test("if (flags.Equal) goto $+0x8"));
        assert!(!names_its_test("return"));
    }

    /// A copy of a result that a later statement reads as `ret` keeps the
    /// call that names `ret`.
    #[test]
    fn a_result_that_a_copy_keeps_stays_named() {
        let shown = aarch64(&[
            0x9400_0040, // bl $+0x100
            0xaa00_03e2, // mov x2, x0
            0xb900_0022, // str w2, [x1]
            0xd65f_03c0, // ret
        ]);
        assert_eq!(shown[..2], ["ret = $+0x100()", "x2 = ret"], "{shown:?}");
    }

    /// A load of an argument from the place the code stored it shows no
    /// line: each read of the register shows the argument.
    #[test]
    fn a_load_of_a_stored_argument_shows_no_line() {
        let shown = aarch64(&[
            0xf81f_0fe1, // str x1, [sp, #-0x10]!
            0xf940_03e2, // ldr x2, [sp]
            0xb940_0440, // ldr w0, [x2, #4]
            0x9100_43ff, // add sp, sp, #0x10
            0xd65f_03c0, // ret
        ]);
        assert_eq!(shown, ["var_10 = arg2", "w0 = load.32 [arg2 + 0x4]", "return"]);
    }

    /// A copy that runs on a condition leaves the register holding one of
    /// two values, so no read of it shows the argument.
    #[test]
    fn a_conditional_copy_names_no_role() {
        use hereticus_il::arch::arm32::Arm32;
        let code: Vec<u8> = [
            0xe350_0000_u32, // cmp r0, #0
            0x01a0_4001,     // moveq r4, r1
            0xe594_0000,     // ldr r0, [r4]
            0xe12f_ff1e,     // bx lr
        ]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
        let (insns, _) = decode_all(&Arm32, &code, 0x1000);
        let shown: Vec<String> = hil_statements_in(&Arm32, &code, &insns, None)
            .into_iter()
            .map(|line| line.text)
            .collect();
        assert!(shown.contains(&"if (eq) r4 = arg2".to_string()), "{shown:?}");
        assert!(shown.contains(&"r0 = load.32 [r4]".to_string()), "{shown:?}");
    }

    /// A value does not fold past a call that the high IL shows as none,
    /// as one that runs on a condition: the call can change what it reads.
    #[test]
    fn a_value_does_not_fold_past_a_conditional_call() {
        use hereticus_il::arch::arm32::Arm32;
        let code: Vec<u8> = [
            0xe591_3000_u32, // ldr r3, [r1]
            0xe350_0000,     // cmp r0, #0
            0x1b00_0040,     // blne $+0x108
            0xe583_5000,     // str r5, [r3]
            0xe12f_ff1e,     // bx lr
        ]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
        let (insns, _) = decode_all(&Arm32, &code, 0x1000);
        let shown: Vec<String> = hil_statements_in(&Arm32, &code, &insns, None)
            .into_iter()
            .map(|line| line.text)
            .collect();
        assert!(shown.contains(&"r3 = load.32 [arg2]".to_string()), "{shown:?}");
    }

    /// A push of a register that no call keeps is no save: on 32-bit x86
    /// it passes an argument.
    #[test]
    fn a_push_of_a_register_no_call_keeps_is_an_argument() {
        use hereticus_il::arch::x86::X86;
        let code = [
            0x50, // push eax, as it came in
            0xe8, 0x00, 0x00, 0x00, 0x00, // call $+0x5
            0x83, 0xc4, 0x04, // add esp, 4
            0xc3, // ret
        ];
        let (insns, _) = decode_all(&X86::BITS32, &code, 0x1000);
        let shown: Vec<String> = hil_statements_in(&X86::BITS32, &code, &insns, None)
            .into_iter()
            .map(|line| line.text)
            .collect();
        assert_eq!(shown, ["ret = $+0x5(eax)", "return"]);
    }

    /// A load of a saved register into another register reads it: it is no
    /// restore.
    #[test]
    fn a_load_of_a_saved_value_into_another_register_shows() {
        let shown = aarch64(&[
            0xf81f_0ff3, // str x19, [sp, #-0x10]!
            0xf940_03e0, // ldr x0, [sp]
            0xf841_07f3, // ldr x19, [sp], #0x10
            0xd65f_03c0, // ret
        ]);
        assert_eq!(shown, ["x0 = var_10", "return"]);
    }

    /// A wide store changes the narrow places inside it.
    #[test]
    fn a_wide_store_changes_the_places_inside_it() {
        let shown = aarch64(&[
            0xd100_43ff, // sub sp, sp, #0x10
            0xb900_0fe0, // str w0, [sp, #0xc]
            0xf900_07e1, // str x1, [sp, #0x8]
            0xb940_0fe2, // ldr w2, [sp, #0xc]
            0xb940_0440, // ldr w0, [x2, #4]
            0x9100_43ff, // add sp, sp, #0x10
            0xd65f_03c0, // ret
        ]);
        assert!(!shown.iter().any(|line| line.contains("[arg1 + 0x4]")), "{shown:?}");
    }

    /// A store to a place above the stack pointer that the code loads from
    /// again keeps its line, though the call may take it as an argument.
    #[test]
    fn a_store_to_a_local_that_is_read_again_stays() {
        use hereticus_il::arch::x86::X86;
        let code = [
            0x83, 0xec, 0x08, // sub esp, 8
            0xc7, 0x44, 0x24, 0x04, 0x07, 0x00, 0x00, 0x00, // mov dword [esp + 4], 7
            0xc7, 0x04, 0x24, 0x05, 0x00, 0x00, 0x00, // mov dword [esp], 5
            0xe8, 0x00, 0x00, 0x00, 0x00, // call $+0x5
            0x8b, 0x44, 0x24, 0x04, // mov eax, [esp + 4]
            0x83, 0xc4, 0x08, // add esp, 8
            0xc3, // ret
        ];
        let (insns, _) = decode_all(&X86::BITS32, &code, 0x1000);
        let shown: Vec<String> = hil_statements_in(&X86::BITS32, &code, &insns, None)
            .into_iter()
            .map(|line| line.text)
            .collect();
        assert!(shown.contains(&"var_4 = 7".to_string()), "{shown:?}");
        assert!(shown.iter().any(|line| line.contains("(5, var_4)")), "{shown:?}");
    }

    /// x86-64 code of Windows takes its first argument in `rcx`, where
    /// System V passes the fourth.
    #[test]
    fn x86_64_of_windows_names_its_arguments_by_its_abi() {
        use hereticus_il::arch::x86::X86;
        let code = [0x8b, 0x41, 0x10, 0xc3]; // mov eax, [rcx + 0x10]; ret
        let (insns, _) = decode_all(&X86::BITS64, &code, 0x1000);
        let (links, space) = (Links::default(), hereticus_memory::AddressSpace::default());
        let context =
            |abi| Context { links: &links, space: &space, functions: &[], paired: None, abi };
        let shown = |abi| -> Vec<String> {
            hil_statements_in(&X86::BITS64, &code, &insns, Some(context(abi)))
                .into_iter()
                .map(|line| line.text)
                .collect()
        };
        assert_eq!(shown(hereticus_arch::Abi::Windows)[0], "eax = load.32 [arg1 + 0x10]");
        assert_eq!(shown(hereticus_arch::Abi::Unix)[0], "eax = load.32 [arg4 + 0x10]");
    }

    /// GCC passes the first arguments of a local function in `eax`, `edx`
    /// and `ecx` on 32-bit x86: the callee reads them before it writes
    /// them, so the call shows them first.
    #[test]
    fn a_local_function_of_x86_takes_registers() {
        use hereticus_il::arch::x86::X86;
        let code = [
            0xb8, 0x05, 0x00, 0x00, 0x00, // 0x1000 mov eax, 5
            0xba, 0x07, 0x00, 0x00, 0x00, // 0x1005 mov edx, 7
            0x6a, 0x09, // 0x100a push 9
            0xe8, 0x04, 0x00, 0x00, 0x00, // 0x100c call 0x1015
            0x83, 0xc4, 0x04, // 0x1011 add esp, 4
            0xc3, // 0x1014 ret
            0x01, 0xd0, // 0x1015 add eax, edx: the callee
            0x03, 0x44, 0x24, 0x04, // 0x1017 add eax, [esp + 4]
            0xc3, // 0x101b ret
        ];
        let callee = hereticus_image::Function {
            name: "local".into(),
            address: 0x1015,
            code: code[0x15..].to_vec(),
        };
        let functions = [callee];
        let (links, space) = (Links::default(), hereticus_memory::AddressSpace::default());
        let context = Context {
            links: &links,
            space: &space,
            functions: &functions,
            paired: None,
            abi: hereticus_arch::Abi::Unix,
        };
        let (insns, _) = decode_all(&X86::BITS32, &code[..0x15], 0x1000);
        let shown: Vec<String> =
            hil_statements_in(&X86::BITS32, &code[..0x15], &insns, Some(context))
                .into_iter()
                .map(|line| line.text)
                .collect();
        assert_eq!(shown, ["ret = local(5, 7, 9)", "return"]);
        // `xor eax, eax` sets `eax` and reads nothing of it.
        let zeroing = [0x31, 0xc0, 0xc3]; // xor eax, eax; ret
        let convention =
            X86::BITS32.calling_convention(hereticus_arch::Abi::Unix).expect("x86 has an ABI");
        let takes = arity_of_code(&X86::BITS32, convention, &zeroing, 0x2000);
        assert_eq!(takes, Some(Takes { arity: Arity::Exact(0), in_registers: 0 }));
    }

    /// An operation on a place in memory reads the place: it moves no value
    /// between a register and the place, as a load or a store does.
    #[test]
    fn an_operation_on_a_place_moves_no_value_into_it() {
        use hereticus_il::arch::x86::X86;
        let code = [
            0x83, 0xec, 0x08, // sub esp, 8
            0x89, 0x04, 0x24, // mov [esp], eax
            0x01, 0x04, 0x24, // add [esp], eax
            0x8b, 0x0c, 0x24, // mov ecx, [esp]
            0x8b, 0x01, // mov eax, [ecx]
            0x83, 0xc4, 0x08, // add esp, 8
            0xc3, // ret
        ];
        let (insns, _) = decode_all(&X86::BITS32, &code, 0x1000);
        let printed = instruction_lines(&X86::BITS32, &code, &insns, None);
        let convention =
            X86::BITS32.calling_convention(hereticus_arch::Abi::Unix).expect("x86 has an ABI");
        let body = Body::new(&X86::BITS32, convention, &insns, &printed);
        // After the add, the place holds no copy of what `eax` held.
        assert_ne!(body.holding[3].get(&Place::Slot(-8)), body.holding[1].reg(Reg::General(0)));
    }

    /// A call to a function that never returns gives nothing back.
    #[test]
    fn a_call_that_never_returns_gives_nothing() {
        let call = |callee: &str| Call {
            index: 0,
            last: 0,
            callee: callee.to_string(),
            arguments: vec!["1".to_string()],
            hidden: Vec::new(),
            gives: true,
            reads: RegSet::EMPTY,
        };
        assert_eq!(call("exit").text(), "exit(1)");
        assert_eq!(call("strlen").text(), "ret = strlen(1)");
    }

    /// The setting of `a0` in the delay slot runs before the call, so it
    /// folds into it.
    #[test]
    fn a_setting_in_the_delay_slot_of_a_call_folds_into_it() {
        let shown = mips(&[
            0x2405_0005, // addiu a1, zero, 5
            0x0c00_0800, // jal 0x2000
            0x0200_2025, // or a0, s0, zero
            0x03e0_0008, // jr ra
            0x0000_0000, // nop
        ]);
        assert_eq!(shown, ["ret = $+0xffc(s0, 5)", "return"]);
    }

    /// `jalr` reads its target before the delay slot runs, so a setting
    /// of the same register in the slot is no setting of the target, and
    /// it stays.
    #[test]
    fn a_setting_of_the_target_in_the_delay_slot_stays() {
        let shown = mips(&[
            0x3c01_0000, // lui at, 0x0
            0x2421_0000, // addiu at, at, 0x0
            0x0020_f809, // jalr at
            0x00a6_0821, // addu at, a1, a2
            0x03e0_0008, // jr ra
            0x0000_0000, // nop
        ]);
        assert!(shown.contains(&"at = arg2 + arg3".to_string()), "{shown:?}");
    }

    /// A loop back to the first instruction leaves what the registers
    /// hold at the entry unknown, so no register shows by its role.
    #[test]
    fn a_loop_to_the_entry_names_no_role() {
        let shown = aarch64(&[
            0xb940_1000, // ldr w0, [x0, #0x10]
            0x35ff_ffe0, // cbnz w0, $-0x4
            0xd65f_03c0, // ret
        ]);
        assert_eq!(shown[0], "w0 = load.32 [x0 + 0x10]");
    }

    /// 32-bit x86 passes each argument on the stack: a place above the
    /// stack pointer at the entry is an argument, and the pushes and stores
    /// before a call are its arguments.
    #[test]
    fn x86_passes_the_arguments_on_the_stack() {
        use hereticus_il::arch::x86::X86;
        let code = [
            0x55, // push ebp
            0x89, 0xe5, // mov ebp, esp
            0x8b, 0x45, 0x08, // mov eax, [ebp + 8]
            0x8d, 0x55, 0xf8, // lea edx, [ebp - 8]
            0x52, // push edx
            0x6a, 0x10, // push 0x10
            0x50, // push eax
            0xe8, 0x00, 0x00, 0x00, 0x00, // call $+0x5
            0x83, 0xc4, 0x0c, // add esp, 0xc
            0x5d, // pop ebp
            0xc3, // ret
        ];
        let (insns, _) = decode_all(&X86::BITS32, &code, 0x1000);
        let shown: Vec<String> = hil_statements_in(&X86::BITS32, &code, &insns, None)
            .into_iter()
            .map(|line| line.text)
            .collect();
        assert_eq!(shown, ["edx = &var_c", "ret = $+0x5(arg1, 0x10, &var_c)", "return"]);
        // A push of a place in memory passes what it holds, and moves the
        // stack as the others do.
        let code = [
            0x8b, 0x5c, 0x24, 0x04, // mov ebx, [esp + 4]
            0xff, 0x73, 0x0c, // push dword ptr [ebx + 0xc]
            0xe8, 0x00, 0x00, 0x00, 0x00, // call $+0x5
            0x83, 0xc4, 0x04, // add esp, 4
            0x8b, 0x44, 0x24, 0x08, // mov eax, [esp + 8]
            0xc3, // ret
        ];
        let (insns, _) = decode_all(&X86::BITS32, &code, 0x1000);
        let shown: Vec<String> = hil_statements_in(&X86::BITS32, &code, &insns, None)
            .into_iter()
            .map(|line| line.text)
            .collect();
        assert_eq!(shown, ["$+0x5(load.32 [arg1 + 0xc])", "eax = arg2", "return"]);
        assert!(hil_statements_in(&Aarch64, &[], &[], None).is_empty());
    }

    #[test]
    fn a_role_renames_no_string_address_or_left_side() {
        let role = |word: &str| (word == "a0").then(|| "arg1".to_string());
        assert_eq!(rename_registers("a0 = a0 + 1", role), "a0 = arg1 + 1");
        assert_eq!(rename_registers("x3, a0 = load.64 [a0]", role), "x3, a0 = load.64 [arg1]");
        assert_eq!(rename_registers("if (eq) a0 = a0", role), "if (eq) a0 = arg1");
        assert_eq!(rename_registers(r#"v0 = &"a0 \"a0\" a0""#, role), r#"v0 = &"a0 \"a0\" a0""#);
        assert_eq!(rename_registers("store.32 [a0] = @a0", role), "store.32 [arg1] = @a0");
        assert_eq!(rename_registers("if (a0 != 0) goto $+0x8", role), "if (arg1 != 0) goto $+0x8");
        assert_eq!(rename_registers("", role), "");
        assert_eq!(
            rename_registers("r1 = load.32 [a0]; a0 = a0 - 4", role),
            "r1 = load.32 [arg1]; a0 = arg1 - 4"
        );
        assert_eq!(rename_registers(r#"v0 = &"a0; a0""#, role), r#"v0 = &"a0; a0""#);
    }

    /// With no role, a statement stays as it is, whatever it holds.
    #[test]
    fn no_role_changes_no_statement() {
        bolero::check!().with_type::<String>().for_each(|text| {
            assert_eq!(&rename_registers(text, |_| None), text);
        });
    }

    #[test]
    fn a_load_or_store_of_one_place_reads_as_the_place() {
        assert_eq!(plain_slot_access("v0 = load.32 var_1c"), "v0 = var_1c");
        assert_eq!(plain_slot_access("store.32 var_1c = a0"), "var_1c = a0");
        assert_eq!(plain_slot_access("store.64 var_10 = x29, x30"), "store.64 var_10 = x29, x30");
        assert_eq!(plain_slot_access("v0 = load.32 [a0]"), "v0 = load.32 [a0]");
        assert_eq!(plain_slot_access("v0 = load.32 var_"), "v0 = load.32 var_");
        assert_eq!(plain_slot_access("store.8 arg_10 = 0"), "arg_10 = 0");
    }

    #[test]
    fn a_place_is_named_by_its_side_of_the_entry() {
        assert_eq!(slot_name(-0x1c), "var_1c");
        assert_eq!(slot_name(0x10), "arg_10");
        assert_eq!(slot_name(0), "arg_0");
        assert!(is_slot("var_1c") && is_slot("arg_0"));
        assert!(is_slot("arg1"), "an argument on the stack");
        assert!(!is_slot("var_") && !is_slot("var_xy") && !is_slot("arg"));
    }

    #[test]
    fn constants_read_with_their_sign() {
        assert_eq!(signed(0xffff_ffb8), -0x48);
        assert_eq!(signed(u64::MAX), -1);
        assert_eq!(signed(0x20), 0x20);
        assert_eq!(parse_constant("0x20"), Some(0x20));
        assert_eq!(parse_constant("-0x10"), Some(-0x10));
        assert_eq!(parse_constant("8"), Some(8));
        assert_eq!(parse_constant("x8"), None);
        assert_eq!(parse_constant(""), None);
    }

    /// The statements of any code come in the order of the code, but for a
    /// delay slot before its call, and each shows an instruction of the
    /// code.
    #[test]
    fn any_code_gives_statements_of_its_own_instructions() {
        bolero::check!().with_type::<Vec<u32>>().for_each(|words| {
            for (arch, code) in [
                (
                    &Aarch64 as &dyn Arch,
                    words.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>(),
                ),
                (&Mips32::BIG as &dyn Arch, words.iter().flat_map(|w| w.to_be_bytes()).collect()),
            ] {
                let (insns, _) = decode_all(arch, &code, 0x1000);
                let addresses: HashSet<u64> = insns.iter().map(|insn| insn.address).collect();
                let shown = hil_statements_in(arch, &code, &insns, None);
                assert!(shown.len() <= insns.len());
                assert!(shown.iter().all(|line| addresses.contains(&line.address)));
            }
        });
    }
}
