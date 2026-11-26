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

use hereticus_arch::{Arch, CallingConvention};
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
}

/// What each register that the high IL knows holds before one instruction.
type Holding = HashMap<Reg, Held>;

/// The most instructions a call looks back over for its arguments.
const MOST_LOOKED_BACK: usize = 64;

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
    let Some(convention) = arch.calling_convention().filter(|_| !insns.is_empty()) else {
        return crate::il_statements_in(arch, code, insns, context);
    };
    let folds = folds(arch, insns);
    let body = Body::new(arch, convention, insns);
    let printed = instruction_lines(arch, code, insns, context);
    let lines: Vec<String> =
        printed.iter().enumerate().map(|(index, line)| body.rename(index, line)).collect();
    let mut hidden = body.upkeep.clone();
    for index in body.page_feeders(&lines) {
        hidden[index] = true;
    }
    let mut sites: Vec<CallSite> = (0..insns.len())
        .filter_map(|index| body.call_site(index, &printed, &lines, &folds))
        .collect();
    let mut arities: HashMap<String, Option<Arity>> = HashMap::new();
    for site in &mut sites {
        let arity = *arities
            .entry(site.callee.clone())
            .or_insert_with(|| arity_of(arch, convention, context, &site.callee));
        if let Some(arity) = arity {
            site.count = arity.shown(site.count, convention.arguments.len());
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
    let statement = |index: usize| -> Option<Statement> {
        let text = match (&folds[index], by_index.get(&index)) {
            (Fold::Hidden, _) => return None,
            _ if hidden[index] => return None,
            (Fold::GlobalPointer(register), _) => format!("{register} = _gp"),
            (Fold::Own, Some(call)) => call.text(),
            (Fold::Own, None) => lines[index].clone(),
        };
        Some(Statement { address: insns[index].address, text })
    };
    let mut statements = Vec::with_capacity(insns.len());
    let mut index = 0;
    while index < insns.len() {
        // A delay slot runs before its call, so it shows before it.
        let last = by_index.get(&index).map_or(index, |call| call.last);
        statements.extend((index + 1..=last).chain([index]).filter_map(statement));
        index = last + 1;
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
}

impl<'a> Body<'a> {
    fn new(arch: &'a dyn Arch, convention: CallingConvention, insns: &'a [Insn]) -> Self {
        let lifts: Vec<Option<Named>> = insns.iter().map(hereticus_il::arch::lift_named).collect();
        let next = successors(insns, |insn| arch.delay_slots(insn));
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
        };
        body.holding = body.held();
        // A load from a place that a save filled gives back the value it
        // saved, so the restore shows as such: PowerPC saves `lr` through
        // `r0`.
        body.save_slots = body.save_slots();
        if !body.save_slots.is_empty() {
            body.holding = body.held();
        }
        body.upkeep = body.frame_upkeep();
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
        let Some(&Held::Stack(at)) = holding.get(&self.convention.stack) else { return None };
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
                    Some(&saved) => holding.insert(reg, Held::Entry(saved)),
                    None => holding.remove(&reg),
                };
            }
        }
        holding.insert(self.convention.stack, Held::Stack(frame.stack));
    }

    /// The places on the stack where a store puts the value that a register
    /// held at the entry, with that register.
    fn save_slots(&self) -> HashMap<i64, Reg> {
        let mut slots = HashMap::new();
        for index in 0..self.insns.len() {
            let holding = &self.holding[index];
            if let Some(frame) = self.frame(index, holding).filter(|frame| frame.saves) {
                for &(at, reg) in &frame.places {
                    if let Some(&Held::Entry(saved)) = holding.get(&reg) {
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
                if let Some(&Held::Entry(saved)) = holding.get(&reg) {
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
        let entry = own.chain(arguments).chain([(convention.stack, Held::Stack(0))]).collect();
        Some(entry)
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
        holding.retain(|reg, held| self.convention.preserves(*reg) && *held != Held::Result);
        holding.insert(self.convention.result.reg, Held::Result);
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
            && let Some(&held) = holding.get(&source)
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
            let Some(&Held::Stack(at)) = holding.get(&base) else { continue };
            let moved = match update {
                Update::None => None,
                Update::Before => offset,
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
            [Operand::Reg(base), Operand::RegisterList(list)] if *base == stack => {
                crate::list_offsets(&self.insns[index], &lifted, list.len()).map(|(_, moved)| moved)
            }
            // An x86 `push` or `pop` names its value alone.
            [Operand::Reg(_)] if lifted.writes.contains(stack) => {
                lifted.memory.map(|access| match access.kind {
                    AccessKind::Store => -self.width(&lifted),
                    _ => self.width(&lifted),
                })
            }
            _ => None,
        };
        if let Some(moved) = moved
            && let Some(&Held::Stack(at)) = holding.get(&stack)
        {
            gained.push((stack, Held::Stack(at + moved)));
        }
        if lifted.memory.is_some_and(|access| access.kind == AccessKind::Load) {
            for (at, reg) in self.stack_places(index, &lifted, holding).into_iter().flatten() {
                if let Some(&saved) = self.save_slots.get(&at) {
                    gained.push((reg, Held::Entry(saved)));
                }
            }
        }
        for reg in lifted.writes.iter() {
            holding.remove(&reg);
        }
        holding.extend(gained);
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
            let Some(&Held::Stack(at)) = holding.get(&base) else { continue };
            let at = if update == Update::After { at } else { at + offset.unwrap_or(0) };
            if !name.is_empty()
                && let Some(start) = text.find(name.as_str())
            {
                text.replace_range(start..start + name.len(), &slot_name(at));
            }
        }
        if let Some(lifted) = self.canonical(index)
            && let Some((dest, at)) = stack_arithmetic(&lifted, holding)
            && dest != self.convention.stack
            && !self.arch.is_frame_register(dest)
            && let Some(name) = named.names.first()
            && text.starts_with(&format!("{name} = "))
        {
            text = format!("{name} = &{}", slot_name(at));
        }
        let text = plain_slot_access(&text);
        rename_registers(&text, |word| {
            let reg = self.registers.get(word)?;
            match holding.get(reg)? {
                Held::Argument(n) => Some(format!("arg{n}")),
                Held::Result => Some("ret".to_string()),
                Held::Stack(_) | Held::Entry(_) => None,
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
                    *reg == stack || matches!(holding.get(reg), Some(Held::Entry(_)))
                }),
                // A restore. A `pop` into the program counter is the return.
                (Some(AccessKind::Load), Some(places)) => {
                    self.insns[index].kind == InsnKind::Normal
                        && places.iter().all(|(at, _)| self.save_slots.contains_key(at))
                }
                (None, _) => {
                    self.moves_frame(&lifted, holding)
                        || copy_of(&lifted).is_some_and(|(dest, source)| {
                            dest != source && holding.get(&source) == Some(&Held::Entry(dest))
                        })
                }
                _ => false,
            };
        }
        // A copy of what a register held at the entry that only a save
        // reads, as `r0 = lr` before PowerPC saves `r0`.
        for index in 0..self.insns.len() {
            if let Some((dest, source)) = self.canonical(index).as_ref().and_then(copy_of)
                && self.holding[index].get(&source) == Some(&Held::Entry(source))
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
                if let Some(&Held::Argument(n)) = holding.get(&reg) {
                    stored[n - 1] = true;
                }
            }
        }
        let fixed = stored.iter().rposition(|stored| !stored).map_or(0, |last| last + 1);
        (fixed < count && count > 1).then_some(fixed)
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
        let at_of = |reg: Reg| match holding.get(&reg) {
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
            ([Operand::Memory { base: Some(base), offset, index: None, update }], operands) => {
                let at = at_of(*base)?;
                let start = if *update == Update::After { at } else { at + offset.unwrap_or(0) };
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
        };
        site.count = self.argument_count(&site);
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
            && self.registers.contains_key(callee)
        {
            return Some(callee.to_string());
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
            Some(named) if self.is_conditional(index) => (named.lifted.reads, RegSet::EMPTY),
            Some(named) => (named.lifted.reads, named.lifted.writes),
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
                let shown = self.convention.arguments[..site.count].iter().map(|arg| arg.reg);
                (site.index, shown.collect())
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

    /// The name that argument `reg` shows as where the code before the call
    /// at `index` does not set it, by what it holds there.
    fn held_name(&self, index: usize, reg: Reg, name: &str) -> String {
        match self.holding[index].get(&reg) {
            Some(Held::Argument(n)) => format!("arg{n}"),
            Some(Held::Result) => "ret".to_string(),
            Some(Held::Stack(at)) => format!("&{}", slot_name(*at)),
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
            .filter(|reg| !matches!(holding.get(reg), Some(Held::Argument(_) | Held::Stack(_))))
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
        let mut arguments = Vec::with_capacity(self.site.count);
        for arg in &body.convention.arguments[..self.site.count] {
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
                        // register it names, as `x1` of `x3, x1 = …`.
                        _ => self.lines[setter]
                            .split_once(" = ")
                            .and_then(|(dest, _)| {
                                dest.split(", ")
                                    .find(|word| body.registers.get(*word) == Some(&arg.reg))
                            })
                            .unwrap_or(arg.name)
                            .to_string(),
                    }
                }
                None => body.held_name(index, arg.reg, arg.name),
            };
            arguments.push(shown);
        }
        let gives = body.live_after(live, self.site.last).contains(body.convention.result.reg);
        let mut hidden: Vec<usize> = self.hidden.into_iter().collect();
        hidden.sort_unstable();
        Call { index, last: self.site.last, callee, arguments, hidden, gives }
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
) -> Option<Arity> {
    if let Some(arity) = arity::known(name) {
        return Some(arity);
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
) -> Option<Arity> {
    let (insns, _) = hereticus_recovery::arch::decode_all(arch, code, address);
    if insns.is_empty() || insns.len() > MOST_READ_OF_A_CALLEE {
        return None;
    }
    let mut body = Body::new(arch, convention, &insns);
    body.unknown = Unknown::ReadsNothing;
    let printed = instruction_lines(arch, code, &insns, None);
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
    if let Some(fixed) = body.variadic_from() {
        return Some(Arity::AtLeast(fixed));
    }
    let jumps_out = insns
        .iter()
        .zip(&body.next)
        .any(|(insn, next)| matches!(insn.kind, InsnKind::Jump { .. }) && next.is_empty());
    Some(if jumps_out { Arity::AtLeast(count) } else { Arity::Exact(count) })
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
        _ => {
            let (dest, source) = copy_of(lifted)?;
            (dest, source, 0)
        }
    };
    let Held::Stack(at) = *holding.get(&source)? else { return None };
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
    word.strip_prefix("var_")
        .or_else(|| word.strip_prefix("arg_"))
        .is_some_and(|hex| !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()))
}

/// The name of the place on the stack `at` bytes from the stack pointer of
/// the entry.
fn slot_name(at: i64) -> String {
    if at < 0 { format!("var_{:x}", at.unsigned_abs()) } else { format!("arg_{at:x}") }
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
    /// argument: it shows none, and the setting stays.
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
        let context = Context { links: &links, space: &space, functions: &functions, paired: None };
        let (insns, _) = decode_all(&Aarch64, &code[..0x14], 0x1000);
        let shown: Vec<String> = hil_statements_in(&Aarch64, &code[..0x14], &insns, Some(context))
            .into_iter()
            .map(|line| line.text)
            .collect();
        assert_eq!(shown, ["w2 = 3", "ret = add(1, 2)", "return"]);
        let convention = Aarch64.calling_convention().expect("AArch64 has a convention");
        assert_eq!(
            arity_of_code(&Aarch64, convention, &code[0x14..], 0x1014),
            Some(Arity::Exact(2))
        );
    }

    /// A function that stores each argument register from the second on,
    /// as `va_start` needs, takes a format and more.
    #[test]
    fn a_callee_that_stores_its_last_arguments_is_variadic() {
        let convention = Aarch64.calling_convention().expect("AArch64 has a convention");
        let words: [u32; 6] = [
            0xa9bf_8be1, // stp x1, x2, [sp, #-0x8]!, as the top of a frame
            0xa9bf_93e3, // stp x3, x4, [sp, #-0x8]!
            0xa9bf_9be5, // stp x5, x6, [sp, #-0x8]!
            0xf81f_8fe7, // str x7, [sp, #-0x8]!
            0x9400_0040, // bl $+0x100
            0xd65f_03c0, // ret
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        assert_eq!(arity_of_code(&Aarch64, convention, &code, 0x1000), Some(Arity::AtLeast(1)));
        // A function that stores the one argument it names takes one.
        let one: Vec<u8> = [0xf81f_0fe0_u32, 0xd65f_03c0] // str x0, [sp, #-0x10]!; ret
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        assert_eq!(arity_of_code(&Aarch64, convention, &one, 0x1000), Some(Arity::Exact(1)));
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

    /// An architecture with no calling convention shows the IL.
    #[test]
    fn code_with_no_calling_convention_shows_the_il() {
        use hereticus_il::arch::x86::X86;
        let code = [0x55, 0x89, 0xe5, 0x5d, 0xc3]; // push ebp; mov ebp, esp; pop ebp; ret
        let (insns, _) = decode_all(&X86::BITS32, &code, 0x1000);
        assert_eq!(
            hil_statements_in(&X86::BITS32, &code, &insns, None),
            crate::il_statements_in(&X86::BITS32, &code, &insns, None)
        );
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
        assert!(!is_slot("arg1") && !is_slot("var_") && !is_slot("var_xy"));
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
