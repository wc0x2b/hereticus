//! Show code as the IL reads it, one statement per instruction.
//!
//! The IL names what an instruction computes the same way on every
//! architecture, as p-code and the IL of Binary Ninja do, so `--diff` can
//! show `w0 = w1 + 0x10` where the code says `add w0, w1, #0x10` on one
//! architecture and `addiu a0, a1, 0x10` on another. A branch on the flags
//! names the compare before it, as `if (w0 <= 0x3f) goto $+0x40`.
//!
//! The IL keeps no register names and no targets, so each statement takes
//! them from the operands the decoder printed. An instruction the IL does
//! not name shows as the decoder printed it.

use std::collections::HashMap;

use crate::address::AddressSpace;
use crate::arch::{Arch, Insn, is_branch_target};
use crate::callee::Links;
use crate::il::{AccessKind, Comparison, Cond, Lifted, Op, Operand, Reg, Test};

/// What the binary around the code says, to name what the code points at.
#[derive(Clone, Copy)]
pub struct Context<'a> {
    pub links: &'a Links,
    pub space: &'a AddressSpace,
    /// The functions of the binary, sorted by address, to name a callee.
    pub functions: &'a [crate::obj::Function],
}

impl Context<'_> {
    /// The name of the function at `address`: its symbol, or the callee of
    /// the PLT stub there. A function with no name has none here, as its
    /// address moves.
    fn callee_at(&self, arch: &dyn Arch, address: u64) -> Option<String> {
        if let Some(name) = self.links.stub_callee(arch, address) {
            return Some(name.to_string());
        }
        let index =
            self.functions.binary_search_by_key(&address, |function| function.address).ok()?;
        let name = &self.functions[index].name;
        (!name.is_empty()).then(|| name.clone())
    }

    /// The name of the callee a call target reaches.
    fn callee_of(&self, arch: &dyn Arch, target: crate::arch::CallTarget) -> Option<String> {
        use crate::arch::CallTarget;
        match target {
            CallTarget::Address(address) => self.callee_at(arch, address),
            CallTarget::Slot(slot) => self.links.slot_name(slot).map(str::to_string),
            CallTarget::PageOffset { .. } => None,
        }
    }
}

/// The IL statement of each instruction of `insns`, which were decoded from
/// `code`.
pub fn il_lines(arch: &dyn Arch, code: &[u8], insns: &[Insn]) -> Vec<String> {
    il_lines_in(arch, code, insns, None)
}

/// [`il_lines`], where `context` names the addresses the code forms: a text
/// as `&"usage"`, a slot of the global offset table by its symbol, as
/// `@malloc`, and any other address as `@0x57c6`. An address moves when
/// code or data before it grows, so a diff aligns on `@` alone.
pub fn il_lines_in(
    arch: &dyn Arch,
    code: &[u8],
    insns: &[Insn],
    context: Option<Context<'_>>,
) -> Vec<String> {
    let Some(first) = insns.first() else { return Vec::new() };
    // The constants that are part of an address, which move with what
    // they reach.
    let moving: Vec<bool> = match context {
        Some(context) => arch
            .constant_kinds(code, insns, context.space)
            .into_iter()
            .map(|kind| kind != crate::address::ConstantKind::Value)
            .collect(),
        None => vec![false; insns.len()],
    };
    let formed = match context {
        Some(context) => {
            let regions = context.links.regions();
            let memory = crate::arch::Memory::new(&regions);
            arch.formed_addresses(code, insns, context.space, &memory)
        }
        None => vec![None; insns.len()],
    };
    let mut last_compare: Option<Compared> = None;
    // The callee each register holds, from a load of a GOT slot.
    let mut callees: HashMap<String, String> = HashMap::new();
    // The callee of each call, as the architecture follows it, as through
    // a slot on MIPS.
    let named_calls: HashMap<usize, String> = match context {
        Some(context) => arch
            .call_targets(insns)
            .into_iter()
            .filter_map(|(index, target)| Some((index, context.callee_of(arch, target?)?)))
            .collect(),
        None => HashMap::new(),
    };
    insns
        .iter()
        .zip(formed)
        .enumerate()
        .map(|(index, (insn, formed))| {
            if let Some(name) = named_calls.get(&index)
                && matches!(insn.kind, crate::arch::InsnKind::Call { .. })
            {
                return format!("call {name}");
            }
            let address =
                formed.zip(context).map(|(address, context)| Pointed::of(address, context));
            let text = named_line(arch, insn, &address, context, &mut callees);
            if let Some(text) = text {
                return text;
            }
            let word = usize::try_from(insn.address - first.address)
                .ok()
                .and_then(|offset| code.get(offset..offset.checked_add(insn.bytes_len)?));
            let lifted = word.and_then(|word| arch.lift(insn, word));
            let moves = moving.get(index).copied().unwrap_or(false);
            let shown = lifted
                .and_then(|lifted| statement(insn, &lifted, address, moves, &mut last_compare));
            match shown {
                Some(text) => match a32_condition(arch, insn) {
                    Some(cond) => format!("if ({cond}) {text}"),
                    None => text,
                },
                None => insn.to_string(),
            }
        })
        .collect()
}

/// The line of a call that a name can say better than an address, and
/// what a load of a GOT slot leaves in its register for one.
fn named_line(
    arch: &dyn Arch,
    insn: &Insn,
    address: &Option<Pointed>,
    context: Option<Context<'_>>,
    callees: &mut HashMap<String, String>,
) -> Option<String> {
    let written = split_operands(&insn.operands).first().map(|first| first.to_string());
    match insn.kind {
        crate::arch::InsnKind::Call { target: Some(target) } => {
            Some(format!("call {}", context?.callee_at(arch, target)?))
        }
        // A jump to a function is a tail call.
        crate::arch::InsnKind::Jump { target: Some(target) } => {
            Some(format!("goto {}", context?.callee_at(arch, target)?))
        }
        crate::arch::InsnKind::Call { target: None } => {
            let register = split_operands(&insn.operands).last()?.to_string();
            Some(format!("call {}", callees.get(&register)?))
        }
        _ => {
            if let Some(written) = written {
                match address {
                    Some(Pointed::Slot(name)) if insn.mnemonic.starts_with("ld") => {
                        callees.insert(written, name.clone());
                    }
                    _ => {
                        callees.remove(&written);
                    }
                }
            }
            None
        }
    }
}

/// What an address the code forms points at.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Pointed {
    /// A text, which it shows in quotes.
    Text(String),
    /// A slot of the global offset table, by the symbol it holds.
    Slot(String),
    /// Anything else, by its address.
    Address(u64),
}

impl Pointed {
    fn of(address: u64, context: Context<'_>) -> Self {
        /// More of a text than a line shows.
        const LONGEST: usize = 40;
        if let Some(text) =
            context.links.text_at(address).filter(|text| context.links.is_sure_text(address, text))
        {
            let mut shown: String = text.chars().take(LONGEST).collect();
            if text.len() > LONGEST {
                shown.push_str("...");
            }
            return Self::Text(shown.escape_debug().to_string());
        }
        match context.links.slot_name(address) {
            Some(name) => Self::Slot(name.to_string()),
            None => Self::Address(address),
        }
    }

    /// As a value an instruction forms: `&"text"` or `@name`.
    fn as_value(&self) -> String {
        match self {
            Self::Text(text) => format!("&\"{text}\""),
            Self::Slot(name) => format!("&@{name}"),
            Self::Address(address) => format!("@{address:#x}"),
        }
    }

    /// As a place an instruction reads or writes: `[@name]`.
    fn as_place(&self) -> String {
        match self {
            Self::Text(text) => format!("[\"{text}\"]"),
            Self::Slot(name) => format!("[@{name}]"),
            Self::Address(address) => format!("[@{address:#x}]"),
        }
    }
}

/// The condition an A32 instruction runs on, as the `ne` of `addne`, or a
/// Thumb-2 one in an `it` block.
///
/// The IL holds no such condition, so it is read from the mnemonic. A
/// branch names its own, and `teq` is no conditional `t`.
fn a32_condition<'i>(arch: &dyn Arch, insn: &'i Insn) -> Option<&'i str> {
    const CONDITIONS: [&str; 16] = [
        "eq", "ne", "hs", "cs", "lo", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt",
        "le",
    ];
    // Thumb-2 names the condition so inside an `it` block.
    let triple = arch.triple();
    let is_arm = triple.starts_with("arm") || triple.starts_with("thumb");
    if !is_arm || matches!(insn.kind, crate::arch::InsnKind::Branch { .. }) {
        return None;
    }
    let mnemonic = insn.mnemonic.as_str();
    // These end in the letters of a condition and name none.
    const UNCONDITIONAL: [&str; 4] = ["mls", "vmls", "vnmls", "teq"];
    if UNCONDITIONAL.contains(&mnemonic) || mnemonic.contains('.') {
        return None;
    }
    let cond = CONDITIONS.iter().find(|cond| mnemonic.ends_with(*cond))?;
    let base = &mnemonic[..mnemonic.len() - cond.len()];
    (!base.is_empty() && base != "t").then(|| &mnemonic[base.len()..])
}

/// What the last compare compared, for the branches that follow it.
#[derive(Clone, Debug)]
struct Compared {
    left: String,
    right: String,
    kind: CompareKind,
}

/// How a compare combined its two values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompareKind {
    Subtract,
    Add,
    And,
}

/// The operands as the decoder printed them, split at the commas that are
/// not inside brackets, braces or parentheses.
fn split_operands(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0i32, 0);
    for (index, character) in text.char_indices() {
        match character {
            '[' | '{' | '(' => depth += 1,
            ']' | '}' | ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(text[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    let last = text[start..].trim();
    if !last.is_empty() {
        parts.push(last);
    }
    parts
}

/// A memory operand as `[base + offset]`, from `[x1, #0x10]` or
/// `0x10(sp)`.
fn memory_text(token: &str) -> String {
    let inner = if let Some(inner) = token.strip_prefix('[') {
        inner.trim_end_matches('!').trim_end_matches(']')
    } else if let Some((offset, base)) = token.split_once('(') {
        let base = base.trim_end_matches(')');
        return match offset.trim() {
            "" | "0" | "0x0" => format!("[{base}]"),
            offset => format!("[{base} + {offset}]"),
        };
    } else {
        return token.to_string();
    };
    // A shift applies to the index before it, as `[r3, r1, lsl 2]` does.
    let mut parts: Vec<String> = Vec::new();
    for part in inner.split(',').map(|part| part.trim().trim_start_matches('#')) {
        let is_shift =
            ["lsl", "lsr", "asr", "ror", "uxt", "sxt"].iter().any(|word| part.starts_with(word));
        match parts.last_mut() {
            Some(index) if is_shift => *index = format!("({index} {})", part.replace('#', "")),
            _ => parts.push(part.to_string()),
        }
    }
    format!("[{}]", parts.join(" + ").replace("+ -", "- "))
}

/// A constant as code reads it: small ones in decimal, a negative one with
/// its sign.
fn constant_text(value: u64) -> String {
    let signed = value as i64;
    if (-0x1_0000..0).contains(&signed) {
        return format!("-{:#x}", signed.unsigned_abs());
    }
    // A small negative number in a 32-bit register, as `mvn r0, #0` makes.
    if (0xffff_0000..=0xffff_ffff).contains(&value) {
        return format!("-{:#x}", 0x1_0000_0000 - value);
    }
    if value < 10 { value.to_string() } else { format!("{value:#x}") }
}

/// The relation a condition tests, as an operator.
fn relation(cond: Cond) -> Option<&'static str> {
    Some(match cond {
        Cond::Equal => "==",
        Cond::NotEqual => "!=",
        Cond::UnsignedGreaterOrEqual => "u>=",
        Cond::UnsignedLess => "u<",
        Cond::UnsignedGreater => "u>",
        Cond::UnsignedLessOrEqual => "u<=",
        Cond::SignedGreaterOrEqual => ">=",
        Cond::SignedLess => "<",
        Cond::SignedGreater => ">",
        Cond::SignedLessOrEqual => "<=",
        _ => return None,
    })
}

/// The test of a condition on what a compare compared.
fn condition_text(cond: Cond, compared: Option<&Compared>) -> String {
    let Some(compared) = compared else { return format!("flags.{cond:?}") };
    let (left, right) = (&compared.left, &compared.right);
    match (compared.kind, cond) {
        (CompareKind::And, Cond::Equal | Cond::BitsClear) => format!("({left} & {right}) == 0"),
        (CompareKind::And, Cond::NotEqual | Cond::BitsSet) => format!("({left} & {right}) != 0"),
        (CompareKind::Subtract, Cond::Negative) => format!("{left} - {right} < 0"),
        (CompareKind::Subtract, Cond::NotNegative) => format!("{left} - {right} >= 0"),
        (CompareKind::Subtract, cond) => match relation(cond) {
            Some(operator) => format!("{left} {operator} {right}"),
            None => format!("flags.{cond:?}"),
        },
        (CompareKind::Add, cond) => match relation(cond) {
            Some(operator) => format!("{left} {operator} -{right}"),
            None => format!("flags.{cond:?}"),
        },
        (CompareKind::And, cond) => format!("flags.{cond:?}"),
    }
}

/// Report whether an operand reads as zero.
fn is_zero(operand: &Operand) -> bool {
    matches!(operand, Operand::Zero | Operand::Const(0))
}

/// The width a memory access names, as `.32`.
fn width_text(lifted: &Lifted) -> String {
    lifted
        .memory
        .and_then(|memory| memory.width)
        .map(|width| format!(".{}", width.bits()))
        .unwrap_or_default()
}

/// What a lifted operand was paired with among the printed ones.
enum Pairing {
    /// A printed operand.
    Printed(String),
    /// Nothing printed, as the zero register of `cmp`: what it reads as.
    Implied(String),
    /// The printed operands left over after the last lifted one, as the
    /// `#0x20` of a post-index access.
    Extra(String),
}

impl Pairing {
    fn into_text(self) -> String {
        match self {
            Self::Printed(text) | Self::Implied(text) | Self::Extra(text) => text,
        }
    }
}

/// Pair each lifted operand with the printed operand it stands for.
///
/// An alias prints fewer operands than the IL holds: `cmp` leaves out the
/// zero register it writes, `mov x0, x1` is `orr x0, xzr, x1`, `mov x29,
/// sp` adds 0, and the Thumb-2 `adds r0, 0x18` names `r0` once for two
/// operands. A shifted register prints as two, as `r1, lsl 4`, which pair
/// with one lifted operand as `(r1 lsl 4)`. `None` where the two do not
/// pair.
fn pair_operands(lifted: &[Operand], tokens: &[&str]) -> Option<Vec<Pairing>> {
    let mut missing = lifted.len().saturating_sub(tokens.len());
    let mut printed = tokens.iter();
    let mut paired: Vec<Pairing> = Vec::with_capacity(lifted.len());
    for (index, operand) in lifted.iter().enumerate() {
        let repeats = index > 0
            && matches!(operand, Operand::Reg(_))
            && lifted.get(index - 1) == Some(operand);
        if missing > 0 && matches!(operand, Operand::Zero | Operand::Const(0)) {
            missing -= 1;
            paired.push(Pairing::Implied("0".to_string()));
            continue;
        }
        if missing > 0 && repeats {
            missing -= 1;
            let text = paired.last().map(|last| match last {
                Pairing::Printed(text) | Pairing::Implied(text) | Pairing::Extra(text) => {
                    text.clone()
                }
            })?;
            paired.push(Pairing::Implied(text));
            continue;
        }
        paired.push(Pairing::Printed((*printed.next()?).to_string()));
    }
    if missing > 0 {
        return None;
    }
    let rest: Vec<&str> = printed.copied().collect();
    if !rest.is_empty() {
        // A post-index offset follows the memory operand; a shift follows
        // the register it shifts.
        let after_memory = matches!(lifted.last(), Some(Operand::Memory { .. }));
        let is_shift = |token: &str| {
            ["lsl", "lsr", "asr", "ror", "rrx", "uxt", "sxt"]
                .iter()
                .any(|word| token.starts_with(word))
        };
        if after_memory {
            paired.push(Pairing::Extra(rest.join(", ")));
        } else if rest.iter().all(|token| is_shift(token)) {
            let Some(Pairing::Printed(last)) = paired.pop() else { return None };
            let shift = rest.join(" ").replace('#', "");
            paired.push(Pairing::Printed(format!("({last} {shift})")));
        } else {
            return None;
        }
    }
    Some(paired)
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
    /// The order a mnemonic names, as `ia` of `ldmia`, or `None` for one
    /// that does not access a list. A condition can follow, as in `ldmne`.
    fn of(mnemonic: &str) -> Option<(Self, WriteBack)> {
        let mnemonic = mnemonic.strip_prefix('v').unwrap_or(mnemonic);
        let mnemonic = mnemonic.split('.').next().unwrap_or(mnemonic);
        if mnemonic.starts_with("push") {
            return Some((Self::DecrementBefore, WriteBack::Yes));
        }
        if mnemonic.starts_with("pop") {
            return Some((Self::IncrementAfter, WriteBack::Yes));
        }
        let suffix = mnemonic.strip_prefix("ldm").or_else(|| mnemonic.strip_prefix("stm"))?;
        // `stmfd` and the other stack names are never printed.
        let order = match suffix.get(..2) {
            Some("ib") => Self::IncrementBefore,
            Some("da") => Self::DecrementAfter,
            Some("db") => Self::DecrementBefore,
            _ => Self::IncrementAfter,
        };
        Some((order, WriteBack::No))
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

/// An ARM access to a list of registers as one load or store, as
/// `store.32 [sp - 0x8] = r4, lr; sp = sp - 0x8` for `push {r4, lr}`.
///
/// It is read from the printed text, as the IL holds no list.
fn list_statement(insn: &Insn, lifted: &Lifted) -> Option<String> {
    let (order, mut write_back) = ListOrder::of(&insn.mnemonic)?;
    let (before, list) = insn.operands.split_once('{')?;
    let registers: Vec<&str> =
        list.trim_end().strip_suffix('}')?.split(',').map(str::trim).collect();
    if registers.iter().any(|register| register.is_empty() || register.contains('-')) {
        return None;
    }
    let base = match before.trim().trim_end_matches(',').trim() {
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

/// The statement of one instruction, or `None` where the IL does not name
/// it well enough to show.
fn statement(
    insn: &Insn,
    lifted: &Lifted,
    address: Option<Pointed>,
    moves: bool,
    last_compare: &mut Option<Compared>,
) -> Option<String> {
    // A constant that is part of an address shows as one, as `@0x20000`.
    let constant = |value: u64| {
        if moves { format!("@{value:#x}") } else { constant_text(value) }
    };
    let mut tokens = split_operands(&insn.operands);
    // The A32 decoder prints a register before the two a compare compares,
    // as `cmps r0, r3, 0x0`, which is no operand of it.
    if lifted.op == Op::Compare && tokens.len() == lifted.operands.len() + 1 {
        tokens.remove(0);
    }
    // The MIPS16e `la` prints the `pc` it reads, as `addiu v1, pc, 0x7340`,
    // and already adds it into the address it prints.
    if lifted.op == Op::Address
        && tokens.len() == lifted.operands.len() + 1
        && tokens.get(1) == Some(&"pc")
    {
        tokens.remove(1);
    }
    let target = tokens.iter().rev().find(|token| is_branch_target(token)).copied();
    // A call or jump through a register names it last, as `blr x1` and the
    // MIPS16e `jalr ra, v0` do.
    match lifted.op {
        Op::Return => return Some("return".to_string()),
        Op::Load | Op::Store => {
            if let Some(line) = list_statement(insn, lifted) {
                return Some(line);
            }
        }
        Op::Call => return Some(format!("call {}", target.or(tokens.last().copied())?)),
        Op::Jump => return Some(format!("goto {}", target.or(tokens.last().copied())?)),
        _ => {}
    }
    // `lsl` and `lsr` of AArch64 are aliases of a field move, which the IL
    // holds with the two field bounds; the printed amount is the shift.
    let shift = match lifted.op {
        Op::ShiftLeft => Some("<<"),
        Op::ShiftRight => Some("u>>"),
        Op::ShiftRightArithmetic => Some(">>"),
        _ => None,
    };
    if let (Some(operator), [dest, source, amount], 4) =
        (shift, tokens.as_slice(), lifted.operands.len())
    {
        return Some(format!("{dest} = {source} {operator} {}", amount.trim_start_matches('#')));
    }
    // What the IL names but has no operator for reads as a function of its
    // sources, named and spelled as the code prints them: `x1 = sxtw(w1)`.
    // Many are aliases, whose IL operands do not pair with the printed ones.
    let functional = matches!(
        lifted.op,
        Op::Extend
            | Op::BitField
            | Op::Bits
            | Op::FloatConvert
            | Op::FloatRoundDown
            | Op::FloatRoundUp
            | Op::FloatRoundNearest
            | Op::FloatRoundTowardZero
            | Op::FloatSign
            | Op::FloatSquareRoot
            | Op::FloatMinMax
            | Op::FloatMultiplyAdd
    ) && !insn.mnemonic.starts_with("movt");
    if functional
        && !lifted.writes.is_empty()
        && let Some((dest, sources)) = tokens.split_first()
        && !sources.is_empty()
    {
        let name = insn.mnemonic.split('.').next().unwrap_or(&insn.mnemonic);
        let sources: Vec<String> =
            sources.iter().map(|source| source.trim_start_matches('#').to_string()).collect();
        return Some(format!("{dest} = {name}({})", sources.join(", ")));
    }
    let mut paired = pair_operands(&lifted.operands, &tokens)?;
    // A post-index access writes its base after it, as `ldp x29, x30, [sp],
    // #0x20` does.
    let mut after = String::new();
    if let Some(Pairing::Extra(rest)) = paired.last()
        && let Some(base) = tokens.iter().find(|token| token.starts_with('['))
    {
        let base = base.trim_start_matches('[').trim_end_matches(']');
        after = format!("; {base} = {base} + {}", rest.trim_start_matches('#'));
        paired.pop();
    }
    let paired: Vec<String> = paired.into_iter().map(Pairing::into_text).collect();

    // The idioms `canonical` reads plainly rewrite the operands, so their
    // registers are named by what each was paired with.
    let names: HashMap<Reg, &str> = lifted
        .operands
        .iter()
        .zip(&paired)
        .filter_map(|(operand, text)| match operand {
            Operand::Reg(reg) => Some((*reg, text.as_str())),
            _ => None,
        })
        .collect();
    let memory = tokens.iter().find(|token| token.starts_with('[') || token.contains('('));
    let canonical = lifted.clone().canonical();
    let operands: Vec<String> = if canonical.operands == lifted.operands {
        lifted
            .operands
            .iter()
            .zip(paired)
            .map(|(operand, text)| match operand {
                Operand::Memory { .. } => memory_text(&text),
                Operand::Const(value) => constant(*value),
                _ => text,
            })
            .collect()
    } else {
        let text = |operand: &Operand| -> Option<String> {
            Some(match operand {
                Operand::Reg(reg) => (*names.get(reg)?).to_string(),
                Operand::Zero => "0".to_string(),
                Operand::Const(value) => constant(*value),
                Operand::Memory { .. } => memory_text(memory?),
                Operand::Target => target?.to_string(),
                Operand::RegisterList | Operand::Other => return None,
            })
        };
        canonical.operands.iter().map(text).collect::<Option<_>>()?
    };

    let binary = |operator: &str| match operands.as_slice() {
        [dest, left, right] => Some(format!("{dest} = {left} {operator} {right}")),
        [dest, right] => Some(format!("{dest} = {dest} {operator} {right}")),
        _ => None,
    };

    let line = match canonical.op {
        // A move can hold a zero it does not use, as `mov x0, x1` is
        // `orr x0, xzr, x1` and `mov x29, sp` adds 0.
        Op::Move => match operands.as_slice() {
            [dest, source] | [dest, source, _]
                if canonical.operands.get(2).is_some_and(is_zero) =>
            {
                format!("{dest} = {source}")
            }
            [dest, _, source] if canonical.operands.get(1).is_some_and(is_zero) => {
                format!("{dest} = {source}")
            }
            [dest, source] => format!("{dest} = {source}"),
            _ => return None,
        },
        // A page is half an address: the instruction that joins the offset
        // to it names what the two point at.
        Op::Address => match (operands.as_slice(), &address) {
            ([dest, _], Some(_)) if insn.mnemonic == "adrp" => format!("{dest} = &page"),
            // `lui` puts its constant in the upper half.
            ([dest, _], None) if insn.mnemonic == "lui" => match canonical.operands.get(1) {
                Some(Operand::Const(high)) => format!("{dest} = {}", constant(high << 16)),
                _ => return None,
            },
            ([dest, _], Some(pointed)) => format!("{dest} = {}", pointed.as_value()),
            // A distance that moves, as half of `_gp_disp`.
            ([dest, source], None) if moves => format!("{dest} = @{source}"),
            ([dest, source], None) => format!("{dest} = &{source}"),
            _ => return None,
        },
        Op::Add => match (operands.first(), &address) {
            (Some(dest), Some(pointed)) => format!("{dest} = {}", pointed.as_value()),
            _ => binary("+")?,
        },
        Op::Subtract => binary("-")?,
        // `mul` is a multiply-add of zero on AArch64.
        Op::Multiply | Op::MultiplyAdd
            if operands.len() == 4 && canonical.operands.get(3).is_some_and(is_zero) =>
        {
            format!("{} = {} * {}", operands[0], operands[1], operands[2])
        }
        Op::Multiply => binary("*")?,
        Op::FloatAdd => binary("+")?,
        Op::FloatSubtract => binary("-")?,
        Op::FloatMultiply => binary("*")?,
        Op::FloatDivide => binary("/")?,
        Op::Divide => binary("/")?,
        Op::And => binary("&")?,
        Op::Or => binary("|")?,
        Op::Xor => binary("^")?,
        Op::AndNot => binary("& ~")?.replace("& ~ ", "& ~"),
        Op::OrNot => binary("| ~")?.replace("| ~ ", "| ~"),
        Op::ShiftLeft => binary("<<")?,
        Op::ShiftRight => binary("u>>")?,
        Op::ShiftRightArithmetic => binary(">>")?,
        // `cset w0, ne` picks 1 or 0, and `csetm` all ones or 0.
        Op::Select
            if operands.len() == 4
                && canonical.operands.get(1).is_some_and(is_zero)
                && canonical.operands.get(2).is_some_and(is_zero) =>
        {
            let one = if insn.mnemonic == "csetm" { "-1" } else { "1" };
            format!("{} = {} ? {one} : 0", operands[0], operands[3])
        }
        // `csel x0, x1, x2, ls` picks on the condition it names last.
        Op::Select => match operands.as_slice() {
            [dest, chosen, other, cond]
                if !canonical.operands.get(1).is_some_and(is_zero)
                    || !canonical.operands.get(2).is_some_and(is_zero) =>
            {
                format!("{dest} = {cond} ? {chosen} : {other}")
            }
            _ => return None,
        },
        Op::Rotate => binary("ror")?,
        Op::MultiplyAdd => match operands.as_slice() {
            [dest, left, right, add] => format!("{dest} = {left} * {right} + {add}"),
            _ => return None,
        },
        // `mvn` of AArch64 is `orn` with the zero register.
        Op::Not => match operands.as_slice() {
            [dest, source] => format!("{dest} = ~{source}"),
            [dest, _, source] if canonical.operands.get(1).is_some_and(is_zero) => {
                format!("{dest} = ~{source}")
            }
            _ => return None,
        },
        Op::Negate => match operands.as_slice() {
            [dest, source] => format!("{dest} = -{source}"),
            _ => return None,
        },
        Op::Load | Op::Store | Op::Atomic => {
            let access = canonical.memory?;
            let place = match &address {
                Some(pointed) => pointed.as_place(),
                None => memory_text(memory?),
            };
            let values: Vec<&String> =
                operands.iter().filter(|operand| !operand.starts_with('[')).collect();
            let values = values.iter().map(|value| value.as_str()).collect::<Vec<_>>().join(", ");
            match access.kind {
                AccessKind::Load => {
                    format!("{values} = load{} {place}{after}", width_text(&canonical))
                }
                AccessKind::Store => {
                    format!("store{} {place} = {values}{after}", width_text(&canonical))
                }
                AccessKind::LoadStore => return None,
            }
        }
        Op::Compare => match canonical.test {
            Some(Test::Compare { comparison, .. }) => {
                let kind = match comparison {
                    Comparison::Subtract { .. } => CompareKind::Subtract,
                    Comparison::Add { .. } => CompareKind::Add,
                    Comparison::And { .. } => CompareKind::And,
                };
                // `cmp` writes the zero register, which comes first.
                let [.., left, right] = operands.as_slice() else { return None };
                *last_compare = Some(Compared { left: left.clone(), right: right.clone(), kind });
                match kind {
                    CompareKind::And => format!("flags = {left} & {right}"),
                    CompareKind::Subtract | CompareKind::Add => {
                        format!("flags = compare({left}, {right})")
                    }
                }
            }
            Some(Test::SetOnCompare { cond, .. }) => {
                let [dest, left, right] = operands.as_slice() else { return None };
                format!("{dest} = {left} {} {right}", relation(cond)?)
            }
            // A conditional compare, as `cmpne`, leaves the flags of the
            // compare before it where its condition fails, so a branch after
            // it tests the flags, not one compare.
            None => {
                *last_compare = None;
                let [left, right] = operands.as_slice() else { return None };
                match insn.mnemonic.starts_with("cmn") {
                    true => format!("flags = compare({left}, -{right})"),
                    false => format!("flags = compare({left}, {right})"),
                }
            }
            _ => return None,
        },
        Op::Branch => {
            let target = target?;
            match canonical.test {
                Some(Test::OnFlags(cond)) => {
                    format!("if ({}) goto {target}", condition_text(cond, last_compare.as_ref()))
                }
                Some(Test::Guard(guard)) => {
                    let left = operands.first()?;
                    let right = match operands.as_slice() {
                        [_, right, _] => right.clone(),
                        _ => match guard.right {
                            crate::il::Value::Const(value) => constant_text(value),
                            _ => return None,
                        },
                    };
                    let test = match (guard.cond, relation(guard.cond)) {
                        (Cond::BitsClear, _) => format!("({left} & {right}) == 0"),
                        (Cond::BitsSet, _) => format!("({left} & {right}) != 0"),
                        (_, Some(operator)) => format!("{left} {operator} {right}"),
                        (_, None) => return None,
                    };
                    format!("if ({test}) goto {target}")
                }
                _ => return None,
            }
        }
        // `movt` sets the upper half and keeps the lower.
        Op::BitField if insn.mnemonic.starts_with("movt") => match operands.as_slice() {
            [dest, high] => format!("{dest} = {dest} & 0xffff | {high} << 16"),
            _ => return None,
        },
        _ => return None,
    };
    Some(line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::aarch64::Aarch64;
    use crate::arch::decode_all;

    fn lines(words: &[u32]) -> Vec<String> {
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = decode_all(&Aarch64, &code, 0x1000);
        il_lines(&Aarch64, &code, &insns)
    }

    #[test]
    fn a_constant_reads_as_code_writes_it() {
        assert_eq!(constant_text(3), "3");
        assert_eq!(constant_text(0x40), "0x40");
        assert_eq!(constant_text(u64::MAX), "-0x1");
        assert_eq!(constant_text(0xffff_fffc), "-0x4", "in a 32-bit register");
        assert_eq!(constant_text(0x8000_0000), "0x80000000");
    }

    #[test]
    fn operands_split_outside_brackets() {
        assert_eq!(split_operands("x0, [x1, #0x10]"), ["x0", "[x1, #0x10]"]);
        assert_eq!(split_operands("a0, 0x10(sp)"), ["a0", "0x10(sp)"]);
        assert_eq!(split_operands(""), Vec::<&str>::new());
    }

    #[test]
    fn a_memory_operand_reads_as_base_plus_offset() {
        assert_eq!(memory_text("[x1, #0x10]"), "[x1 + 0x10]");
        assert_eq!(memory_text("[sp, #-0x10]!"), "[sp - 0x10]");
        assert_eq!(memory_text("[x0]"), "[x0]");
        assert_eq!(memory_text("0x10(sp)"), "[sp + 0x10]");
        assert_eq!(memory_text("0x0(v0)"), "[v0]");
        assert_eq!(memory_text("[r3, r1, lsl 2]"), "[r3 + (r1 lsl 2)]");
        assert_eq!(memory_text("[x1, x2, lsl #3]"), "[x1 + (x2 lsl 3)]");
    }

    #[test]
    fn a_compare_and_its_branch_read_as_one_test() {
        let shown = lines(&[
            0x7100_fc5f, // cmp w2, #0x3f
            0x5400_0208, // b.hi $+0x40
            0x8b02_0020, // add x0, x1, x2
            0xb940_1020, // ldr w0, [x1, #0x10]
            0xd65f_03c0, // ret
        ]);
        assert_eq!(
            shown,
            [
                "flags = compare(w2, 0x3f)",
                "if (w2 u> 0x3f) goto $+0x40",
                "x0 = x1 + x2",
                "w0 = load.32 [x1 + 0x10]",
                "return",
            ]
        );
    }

    #[test]
    fn aliases_and_forms_of_aarch64_read_plainly() {
        let shown = lines(&[
            0xa8c2_7bfd, // ldp x29, x30, [sp], #0x20
            0x9a80_9020, // csel x0, x1, x0, ls
            0x531c_6c23, // lsl w3, w1, #4
            0xd63f_0020, // blr x1
        ]);
        assert_eq!(
            shown,
            [
                "x29, x30 = load.64 [sp]; sp = sp + 0x20",
                "x0 = ls ? x1 : x0",
                "w3 = w1 << 0x4",
                "call x1",
            ]
        );
    }

    #[test]
    fn more_forms_of_aarch64_read_as_statements() {
        let shown = lines(&[
            0x1a9f_07e0, // cset w0, ne
            0x2a33_03e1, // mvn w1, w19
            0x9b02_7c20, // mul x0, x1, x2
            0x9340_7c21, // sxtw x1, w1
            0x5ac0_1020, // clz w0, w1
        ]);
        assert_eq!(
            shown,
            ["w0 = ne ? 1 : 0", "w1 = ~w19", "x0 = x1 * x2", "x1 = sxtw(w1)", "w0 = clz(w1)"]
        );
    }

    #[test]
    fn a_shifted_register_reads_as_one_operand() {
        use crate::arch::arm32::Arm32;
        let code = 0xe081_3204_u32.to_le_bytes(); // add r3, r1, r4, lsl #4
        let (insns, _) = decode_all(&Arm32, &code, 0x1000);
        assert_eq!(il_lines(&Arm32, &code, &insns), ["r3 = r1 + (r4 lsl 4)"]);
    }

    #[test]
    fn a_list_of_registers_reads_as_one_access() {
        use crate::arch::arm32::Arm32;
        let words = [
            0xe92d_4010_u32, // push {r4, lr}
            0xe890_0006,     // ldm r0, {r1, r2}
            0xe830_0002,     // ldmda r0!, {r1}
            0xe990_0006,     // ldmib r0, {r1, r2}
            0x1890_0002,     // ldmne r0, {r1}
            0xed2d_8b02,     // vpush {d8}
            0xecb0_8b04,     // vldmia r0!, {d8, d9}
            0xe49d_0004,     // pop {r0}
            0xe8b0_0001,     // ldm r0!, {r0}
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = decode_all(&Arm32, &code, 0x1000);
        assert_eq!(
            il_lines(&Arm32, &code, &insns),
            [
                "store.32 [sp - 8] = r4, lr; sp = sp - 8",
                "r1, r2 = load.32 [r0]",
                "r1 = load.32 [r0]; r0 = r0 - 4",
                "r1, r2 = load.32 [r0 + 4]",
                "if (ne) r1 = load.32 [r0]",
                "store.64 [sp - 8] = d8; sp = sp - 8",
                "d8, d9 = load.64 [r0]; r0 = r0 + 0x10",
                "r0 = load.32 [sp]; sp = sp + 4",
                "r0 = load.32 [r0]",
            ]
        );
    }

    #[test]
    fn a_list_order_names_where_the_access_starts() {
        assert_eq!(ListOrder::of("push.w"), Some((ListOrder::DecrementBefore, WriteBack::Yes)));
        assert_eq!(ListOrder::of("vpop"), Some((ListOrder::IncrementAfter, WriteBack::Yes)));
        assert_eq!(ListOrder::of("stmdb"), Some((ListOrder::DecrementBefore, WriteBack::No)));
        assert_eq!(ListOrder::of("ldmne"), Some((ListOrder::IncrementAfter, WriteBack::No)));
        assert_eq!(ListOrder::of("ldr"), None);
        assert_eq!(ListOrder::IncrementAfter.offsets(8, 4), (0, 8));
        assert_eq!(ListOrder::IncrementBefore.offsets(8, 4), (4, 8));
        assert_eq!(ListOrder::DecrementAfter.offsets(8, 4), (-4, -8));
        assert_eq!(ListOrder::DecrementBefore.offsets(8, 4), (-8, -8));
    }

    #[test]
    fn a_conditional_compare_leaves_the_branch_on_the_flags() {
        use crate::arch::arm32::Arm32;
        // cmp r2, r3; cmpne r6, r3; beq
        let code: Vec<u8> = [0xe152_0003_u32, 0x1156_0003, 0x0a00_0002]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let (insns, _) = decode_all(&Arm32, &code, 0x1000);
        let shown = il_lines(&Arm32, &code, &insns);
        assert_eq!(shown[1], "if (ne) flags = compare(r6, r3)");
        assert!(shown[2].starts_with("if (flags.Equal) goto"), "{shown:?}");
    }

    #[test]
    fn a_conditional_a32_instruction_names_its_condition() {
        use crate::arch::arm32::Arm32;
        // cmp r2, r3; addne r6, r4, #1
        let code: Vec<u8> =
            [0xe152_0003_u32, 0x1284_6001].iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = decode_all(&Arm32, &code, 0x1000);
        let shown = il_lines(&Arm32, &code, &insns);
        assert_eq!(shown[1], "if (ne) r6 = r4 + 1");
        assert_eq!(a32_condition(&Arm32, &insns[0]), None, "a compare that always runs");
        let mls = Insn {
            address: 0,
            bytes_len: 4,
            mnemonic: "mls".into(),
            operands: "r0, r1, r2, r3".into(),
            kind: crate::arch::InsnKind::Normal,
        };
        assert_eq!(a32_condition(&Arm32, &mls), None, "a multiply-subtract");
    }

    #[test]
    fn any_code_shows_without_a_panic() {
        use crate::arch::{arm32::Arm32, mips::Mips32, mips16::Mips16, thumb::Thumb2};
        bolero::check!().with_type::<Vec<u8>>().for_each(|code| {
            let arches: [&dyn Arch; 6] =
                [&Aarch64, &Arm32, &Thumb2, &Mips32::BIG, &Mips16::LITTLE, &Mips16::BIG];
            for arch in arches {
                let (insns, _) = decode_all(arch, code, 0x1000);
                assert_eq!(il_lines(arch, code, &insns).len(), insns.len());
            }
        });
    }

    #[test]
    fn what_the_il_does_not_name_reads_as_the_decoder_printed_it() {
        let shown = lines(&[0xd503_201f]); // nop
        assert_eq!(shown, ["nop"]);
    }
}
