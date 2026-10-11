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

use std::collections::{HashMap, HashSet};

use crate::address::AddressSpace;
use crate::arch::arm32::{self, Step, Vfp};
use crate::arch::mips::{self, Decoded as MipsDecoded};
use crate::arch::mips16::Op as Mips16Op;
use crate::arch::mips32::Op as Mips32Op;
use crate::arch::{Arch, Insn, aarch64, is_branch_target, split_printed};
use crate::callee::Links;
use crate::il::{AccessKind, Comparison, Cond, Lifted, Op, Operand, Reg, Test};
use rabbitizer::opcodes::Opcode as MipsOpcode;
use yaxpeax_arm::armv7::{ConditionCode, Opcode as ArmOpcode};
use yaxpeax_arm::armv8::a64::Opcode as A64Opcode;

/// What the binary around the code says, to name what the code points at.
#[derive(Clone, Copy)]
pub struct Context<'a> {
    pub links: &'a Links,
    pub space: &'a AddressSpace,
    /// The functions of the binary, sorted by address, to name a callee.
    pub functions: &'a [crate::obj::Function],
    /// The labels the functions take from their pairs in the other binary
    /// of a diff.
    pub paired: Option<&'a PairedLabels>,
}

/// The label of each stripped function of the later binary of a diff, by
/// address, as its pair in the earlier binary names it.
///
/// The address of a stripped function moves, so where each side names a
/// callee by its own `sub_<hex>`, every call to it reads as a change.
#[derive(Clone, Debug, Default)]
pub struct PairedLabels(HashMap<u64, String>);

impl PairedLabels {
    pub fn new(
        diff: &crate::matching::Diff,
        before: &crate::obj::Binary,
        after: &crate::obj::Binary,
    ) -> Self {
        let labels = diff
            .matched
            .iter()
            .map(|pair| (&before.functions[pair.before], &after.functions[pair.after]))
            .filter(|(_, later)| later.name.is_empty())
            .map(|(earlier, later)| (later.address, earlier.label()))
            .collect();
        Self(labels)
    }
}

impl Context<'_> {
    /// The name of the function at `address`: the callee of the PLT stub
    /// there, its symbol, the label of its pair, or `sub_<hex>`.
    fn callee_at(&self, arch: &dyn Arch, address: u64) -> Option<String> {
        if let Some(name) = self.links.stub_callee(arch, address) {
            return Some(name.to_string());
        }
        let index =
            self.functions.binary_search_by_key(&address, |function| function.address).ok()?;
        let function = &self.functions[index];
        let paired = self.paired.and_then(|paired| paired.0.get(&address));
        Some(paired.cloned().unwrap_or_else(|| function.label()))
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

/// One line of the IL view, and the address of the instruction it shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub address: u64,
    pub text: String,
}

/// The IL statements of `insns`, which were decoded from `code`: one for
/// each instruction, but where an idiom of several instructions shows as
/// one, as the making of the global pointer on MIPS, and an `it`, whose
/// condition sits on each instruction it covers, shows as none.
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
    il_statements_in(arch, code, insns, context).into_iter().map(|line| line.text).collect()
}

/// [`il_lines_in`], with the address of each line.
pub fn il_statements_in(
    arch: &dyn Arch,
    code: &[u8],
    insns: &[Insn],
    context: Option<Context<'_>>,
) -> Vec<Statement> {
    insns
        .iter()
        .zip(instruction_lines(arch, code, insns, context))
        .zip(folds(arch, insns))
        .filter_map(|((insn, text), fold)| {
            let text = match fold {
                Fold::Own => text,
                Fold::Hidden => return None,
                Fold::GlobalPointer(register) => format!("{register} = _gp"),
            };
            Some(Statement { address: insn.address, text })
        })
        .collect()
}

/// The address of each line of [`il_statements_in`], which needs only the
/// instructions.
pub fn il_line_addresses(arch: &dyn Arch, insns: &[Insn]) -> Vec<u64> {
    insns
        .iter()
        .zip(folds(arch, insns))
        .filter(|(_, fold)| *fold != Fold::Hidden)
        .map(|(insn, _)| insn.address)
        .collect()
}

/// How the IL view shows an instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Fold {
    /// On a line of its own.
    Own,
    /// Not at all: another line shows what it does.
    Hidden,
    /// As the last part of the making of the global pointer, which it
    /// leaves in this register.
    GlobalPointer(String),
}

/// How the IL view shows each instruction of `insns`.
fn folds(arch: &dyn Arch, insns: &[Insn]) -> Vec<Fold> {
    let mut folds = vec![Fold::Own; insns.len()];
    for index in 0..insns.len() {
        if crate::arch::thumb::is_it(&insns[index]) {
            folds[index] = Fold::Hidden;
        }
        let Some(setup) = arch.global_pointer_setup(&insns[index..]) else { continue };
        let Some((last, earlier)) = setup.parts.split_last() else { continue };
        for part in earlier {
            folds[index + part] = Fold::Hidden;
        }
        folds[index + last] = Fold::GlobalPointer(setup.register);
    }
    folds
}

/// The IL statement of each instruction of `insns`, one to one.
fn instruction_lines(
    arch: &dyn Arch,
    code: &[u8],
    insns: &[Insn],
    context: Option<Context<'_>>,
) -> Vec<String> {
    if insns.is_empty() {
        return Vec::new();
    }
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
    let pages = page_loads(insns, &formed);
    let mut last_compare: Option<Compared> = None;
    let is_mips = arch.triple().starts_with("mips");
    let mut float_condition: Option<String> = None;
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
            // A call can run on a condition, as `blne` does.
            let conditional = |text: String, op| match a32_condition(insn, op) {
                Some(cond) => format!("if ({cond}) {text}"),
                None => text,
            };
            if let Some(name) = named_calls.get(&index)
                && matches!(insn.kind, crate::arch::InsnKind::Call { .. })
            {
                return conditional(format!("call {name}"), None);
            }
            let address =
                formed.zip(context).map(|(address, context)| Pointed::of(address, context));
            let text = named_line(arch, insn, &address, context, &mut callees);
            if let Some(text) = text {
                return conditional(text, None);
            }
            if pages.contains(&index)
                && matches!(address, Some(Pointed::Address(_)))
                && let Some(dest) = split_operands(insn.operands()).first()
            {
                return format!("{dest} = &page");
            }
            if is_mips && let Some(text) = mips_statement(insn, &mut float_condition) {
                return text;
            }
            let lifted = arch.lift(insn);
            let moves = moving.get(index).copied().unwrap_or(false);
            let shown = lifted.and_then(|lifted| {
                let text = statement(insn, &lifted, address, moves, &mut last_compare)?;
                Some((lifted.op, text))
            });
            match shown {
                Some((op, text)) => conditional(text, Some(op)),
                None => insn.to_string(),
            }
        })
        .collect()
}

/// The MIPS loads of a page from the global offset table: each `lw` whose
/// register an `addiu` or `ori` after it joins the low half to, to form an
/// address, as
///
/// ```text
/// lw    v0, %got(local)(gp)
/// addiu v0, v0, %lo(local)
/// ```
///
/// The slot the `lw` reads moves with the table, but the `addiu` names what
/// the two point at, as the `add` after `adrp` does.
fn page_loads(insns: &[Insn], formed: &[Option<u64>]) -> HashSet<usize> {
    /// How far back the `lw` can be, as a compiler schedules others between.
    const LOOK_BACK: usize = 16;
    insns
        .iter()
        .enumerate()
        .filter(|&(index, insn)| {
            let opcode = mips::rabbitizer_opcode(insn);
            matches!(opcode, Some(MipsOpcode::core_addiu | MipsOpcode::core_ori))
                && formed[index].is_some()
        })
        .filter_map(|(index, insn)| {
            // The MIPS16e `addiu v0, 0x10` adds to the register it writes.
            let source = match split_operands(insn.operands()).as_slice() {
                [_, source, _] => *source,
                [dest, _] => *dest,
                _ => return None,
            };
            let at = (index.saturating_sub(LOOK_BACK)..index).rev().find(|&at| {
                let earlier = &insns[at];
                matches!(earlier.kind, crate::arch::InsnKind::Call { .. })
                    || split_operands(earlier.operands()).first() == Some(&source)
            })?;
            let loads = mips::rabbitizer_opcode(&insns[at]) == Some(MipsOpcode::core_lw);
            (loads && formed[at].is_some()).then_some(at)
        })
        .collect()
}

/// The statement of a MIPS instruction whose operands the code does not
/// print: the `hi` and `lo` that a multiply or divide writes, the
/// condition bit that a float compare sets and `bc1t` and `bc1f` test, and
/// the stores and loads of the MIPS16e `save` and `restore`.
///
/// `float_condition` keeps the test of the last float compare, so a branch
/// on it reads as `if (fv0 < fv1) goto $+0xc`.
fn mips_statement(insn: &Insn, float_condition: &mut Option<String>) -> Option<String> {
    use MipsDecoded::{Mips16, Mips32, Rabbitizer};
    let operands = split_operands(insn.operands());
    let decoded = mips::decoded(insn)?;
    // `multu` and `divu` read their operands unsigned, as `u>>` does.
    let unsigned = matches!(
        decoded,
        Rabbitizer(MipsOpcode::core_multu | MipsOpcode::core_divu)
            | Mips32(Mips32Op::Multu | Mips32Op::Maddu | Mips32Op::Msubu)
    );
    let sign = if unsigned { "u" } else { "" };
    let line = match (decoded, operands.as_slice()) {
        (
            Rabbitizer(MipsOpcode::core_mult | MipsOpcode::core_multu)
            | Mips32(Mips32Op::Mult | Mips32Op::Multu),
            [left, right],
        ) => format!("hi:lo = {left} {sign}* {right}"),
        (Mips32(Mips32Op::Madd | Mips32Op::Maddu), [left, right]) => {
            format!("hi:lo = hi:lo + {left} {sign}* {right}")
        }
        (Mips32(Mips32Op::Msub | Mips32Op::Msubu), [left, right]) => {
            format!("hi:lo = hi:lo - {left} {sign}* {right}")
        }
        // The assembler prints the `zero` that the encoding holds first.
        (
            Rabbitizer(MipsOpcode::core_div | MipsOpcode::core_divu),
            [left, right] | ["zero", left, right],
        ) => format!("lo = {left} {sign}/ {right}; hi = {left} {sign}% {right}"),
        (Mips16(step @ (Mips16Op::Save | Mips16Op::Restore)), _) => {
            return frame_statement(step, &operands);
        }
        (Rabbitizer(MipsOpcode::core_mfhi) | Mips32(Mips32Op::Mfhi), [dest]) => {
            format!("{dest} = hi")
        }
        (Rabbitizer(MipsOpcode::core_mflo) | Mips32(Mips32Op::Mflo), [dest]) => {
            format!("{dest} = lo")
        }
        (Rabbitizer(MipsOpcode::core_mthi) | Mips32(Mips32Op::Mthi), [source]) => {
            format!("hi = {source}")
        }
        (Rabbitizer(MipsOpcode::core_mtlo) | Mips32(Mips32Op::Mtlo), [source]) => {
            format!("lo = {source}")
        }
        (Rabbitizer(MipsOpcode::core_bc1t), [target]) => {
            let test = float_condition.as_deref().unwrap_or("fcc");
            format!("if ({test}) goto {target}")
        }
        (Rabbitizer(MipsOpcode::core_bc1f), [target]) => match float_condition.as_deref() {
            Some(test) if test.starts_with("!(") => {
                format!("if ({}) goto {target}", &test[2..test.len() - 1])
            }
            Some(test) => format!("if (!({test})) goto {target}"),
            None => format!("if (!fcc) goto {target}"),
        },
        (Rabbitizer(opcode), [left, right]) if float_test(opcode, left, right).is_some() => {
            let test = float_test(opcode, left, right)?;
            *float_condition = Some(test.clone());
            format!("fcc = {test}")
        }
        _ => return None,
    };
    Some(line)
}

/// What a MIPS float compare tests, as an expression of `left` and
/// `right`. Each operator is false on a NaN, so a compare that is true on
/// one reads as the negation of its opposite: `c.ult` is `!(a >= b)`. The
/// signaling forms test the same; `rabbitizer` spells `c.sf.d` as `c.df.d`.
fn float_test(opcode: MipsOpcode, left: &str, right: &str) -> Option<String> {
    Some(match opcode {
        MipsOpcode::core_c_f_s
        | MipsOpcode::core_c_f_d
        | MipsOpcode::core_c_sf_s
        | MipsOpcode::core_c_df_d => "0".to_string(),
        MipsOpcode::core_c_un_s
        | MipsOpcode::core_c_un_d
        | MipsOpcode::core_c_ngle_s
        | MipsOpcode::core_c_ngle_d => format!("unordered({left}, {right})"),
        MipsOpcode::core_c_eq_s
        | MipsOpcode::core_c_eq_d
        | MipsOpcode::core_c_seq_s
        | MipsOpcode::core_c_seq_d => format!("{left} == {right}"),
        MipsOpcode::core_c_ueq_s
        | MipsOpcode::core_c_ueq_d
        | MipsOpcode::core_c_ngl_s
        | MipsOpcode::core_c_ngl_d => {
            format!("!({left} < {right} || {left} > {right})")
        }
        MipsOpcode::core_c_olt_s
        | MipsOpcode::core_c_olt_d
        | MipsOpcode::core_c_lt_s
        | MipsOpcode::core_c_lt_d => format!("{left} < {right}"),
        MipsOpcode::core_c_ult_s
        | MipsOpcode::core_c_ult_d
        | MipsOpcode::core_c_nge_s
        | MipsOpcode::core_c_nge_d => format!("!({left} >= {right})"),
        MipsOpcode::core_c_ole_s
        | MipsOpcode::core_c_ole_d
        | MipsOpcode::core_c_le_s
        | MipsOpcode::core_c_le_d => format!("{left} <= {right}"),
        MipsOpcode::core_c_ule_s
        | MipsOpcode::core_c_ule_d
        | MipsOpcode::core_c_ngt_s
        | MipsOpcode::core_c_ngt_d => format!("!({left} > {right})"),
        _ => return None,
    })
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
    let written = split_operands(insn.operands()).first().map(|first| first.to_string());
    match insn.kind {
        crate::arch::InsnKind::Call { target: Some(target) } => {
            Some(format!("call {}", context?.callee_at(arch, target)?))
        }
        // A jump to a function is a tail call.
        crate::arch::InsnKind::Jump { target: Some(target) } => {
            Some(format!("goto {}", context?.callee_at(arch, target)?))
        }
        crate::arch::InsnKind::Call { target: None } => {
            let register = split_operands(insn.operands()).last()?.to_string();
            Some(format!("call {}", callees.get(&register)?))
        }
        _ => {
            if let Some(written) = written {
                match address {
                    Some(Pointed::Slot(name)) if is_named_load(insn) => {
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

/// Whether the decoder prints `insn` with `ld` first, as a load of a GOT
/// slot is on AArch64 and A32.
fn is_named_load(insn: &Insn) -> bool {
    if let Some(decoded) = aarch64::decoded(insn) {
        return aarch64::is_named_load(decoded);
    }
    if let Some(decoded) = mips::decoded(insn) {
        return matches!(
            decoded,
            MipsDecoded::Rabbitizer(MipsOpcode::core_ldc1 | MipsOpcode::core_ldc2)
        );
    }
    matches!(
        arm32::core_opcode(insn),
        Some(
            ArmOpcode::LDR
                | ArmOpcode::LDRB
                | ArmOpcode::LDRH
                | ArmOpcode::LDRSB
                | ArmOpcode::LDRSH
                | ArmOpcode::LDRSBT
                | ArmOpcode::LDRSHT
                | ArmOpcode::LDRD
                | ArmOpcode::LDRT
                | ArmOpcode::LDRBT
                | ArmOpcode::LDRHT
                | ArmOpcode::LDREX
                | ArmOpcode::LDREXB
                | ArmOpcode::LDREXH
                | ArmOpcode::LDREXD
                | ArmOpcode::LDM(..)
                | ArmOpcode::LDC(_)
                | ArmOpcode::LDCL(_)
                | ArmOpcode::LDC2(_)
                | ArmOpcode::LDC2L(_)
        )
    )
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
/// The IL holds no such condition, so it is read from the decoded
/// instruction. A branch names its own. A conditional return or jump, as
/// `bxne lr`, decodes as a branch too, but names no condition, so `op`,
/// where the lift names one, and not the kind of `insn` decides.
fn a32_condition(insn: &Insn, op: Option<Op>) -> Option<&'static str> {
    if op == Some(Op::Branch) {
        return None;
    }
    let condition = arm32::condition(insn).filter(|&condition| condition != ConditionCode::AL)?;
    Some(arm32::condition_name(condition))
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

/// The statement of a MIPS16e `save` or `restore`, whose operands are the
/// arguments `save` stores into the frame of the caller, the size of the
/// frame, then the registers kept in the frame, lowest address first:
///
/// ```text
/// save    a0, 0x20, s0, ra   store.32 [sp] = a0; store.32 [sp - 8] = s0, ra; sp = sp - 0x20
/// restore 0x20, s0, ra       s0, ra = load.32 [sp + 0x18]; sp = sp + 0x20
/// ```
fn frame_statement(step: Mips16Op, operands: &[&str]) -> Option<String> {
    let at = operands.iter().position(|operand| operand.starts_with("0x"))?;
    let (arguments, [size, kept @ ..]) = operands.split_at(at) else { return None };
    let size = u64::from_str_radix(size.strip_prefix("0x")?, 16).ok()?;
    let kept_size = 4 * kept.len() as u64;
    let mut parts = Vec::new();
    match step {
        Mips16Op::Save => {
            if !arguments.is_empty() {
                parts.push(format!("store.32 [sp] = {}", arguments.join(", ")));
            }
            if !kept.is_empty() {
                let offset = constant_text(kept_size);
                parts.push(format!("store.32 [sp - {offset}] = {}", kept.join(", ")));
            }
            parts.push(format!("sp = sp - {}", constant_text(size)));
        }
        _ => {
            if !kept.is_empty() {
                let base = match size.checked_sub(kept_size)? {
                    0 => "sp".to_string(),
                    offset => format!("sp + {}", constant_text(offset)),
                };
                parts.push(format!("{} = load.32 [{base}]", kept.join(", ")));
            }
            parts.push(format!("sp = sp + {}", constant_text(size)));
        }
    }
    Some(parts.join("; "))
}

/// The statement of an AArch64 instruction whose operands the IL does not
/// pair with the printed ones: a conditional compare, a vector constant,
/// and a move between a general register and a lane of a vector.
fn aarch64_statement(
    insn: &Insn,
    tokens: &[&str],
    last_compare: &mut Option<Compared>,
) -> Option<String> {
    let opcode = aarch64::decoded(insn)?.opcode;
    // As printed, for the reader.
    let (printed_name, _) = split_printed(&insn.text);
    let immediate = |token: &str| {
        let token = token.trim_start_matches('#');
        token
            .strip_prefix("0x")
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            .map_or_else(|| token.to_string(), constant_text)
    };
    let is_lane = |token: &str| token.contains('.') && token.ends_with(']');
    let line = match (opcode, tokens) {
        // `ccmp x1, x2, #4, eq` compares where its condition holds, and
        // else sets the flags to the constant it names. A branch after it
        // tests the flags, not one compare.
        (
            A64Opcode::CCMP | A64Opcode::CCMN | A64Opcode::FCCMP | A64Opcode::FCCMPE,
            [left, right, flags, cond],
        ) => {
            *last_compare = None;
            let right = immediate(right);
            let right = if opcode == A64Opcode::CCMN { format!("-{right}") } else { right };
            format!("flags = {cond} ? compare({left}, {right}) : nzcv({})", immediate(flags))
        }
        (A64Opcode::MOVI, [dest, value]) => format!("{dest} = {}", immediate(value)),
        (A64Opcode::MVNI, [dest, value]) => format!("{dest} = ~{}", immediate(value)),
        (A64Opcode::MOVI | A64Opcode::MVNI, [dest, value, shift]) => {
            let (kind, amount) = shift.split_once(' ')?;
            let operator = match kind {
                "lsl" => "<<",
                // `msl` shifts ones in.
                "msl" => "msl",
                _ => return None,
            };
            let shifted = format!("{} {operator} {}", immediate(value), immediate(amount));
            match opcode {
                A64Opcode::MVNI => format!("{dest} = ~({shifted})"),
                _ => format!("{dest} = {shifted}"),
            }
        }
        // `ins`, `umov` and `dup` of a lane print as `mov`.
        (A64Opcode::INS | A64Opcode::UMOV | A64Opcode::DUP, [dest, source])
            if is_lane(dest) || is_lane(source) =>
        {
            format!("{dest} = {source}")
        }
        (A64Opcode::SMOV | A64Opcode::DUP, [dest, source]) => {
            format!("{dest} = {printed_name}({source})")
        }
        _ => return None,
    };
    Some(line)
}

/// The statement of an A32 or T32 VFP instruction that the IL names only
/// `Float`: a compare, the move of its result to the flags, and a move of a
/// double between two general registers, low half first.
fn vfp_statement(
    insn: &Insn,
    tokens: &[&str],
    last_compare: &mut Option<Compared>,
) -> Option<String> {
    let Some(arm32::Decoded::Vfp { vfp, .. }) = arm32::decoded(insn) else { return None };
    let line = match (vfp, tokens) {
        // A branch after it tests the flags, not the operands: the flags of
        // a float compare mean other things than those of an integer one.
        (Vfp::Compare { .. }, [left, right]) => {
            *last_compare = None;
            let right = if *right == "0x0" { "0" } else { right };
            format!("fpscr = compare({left}, {right})")
        }
        (Vfp::Status, ["APSR_nzcv", "fpscr"]) => {
            *last_compare = None;
            "flags = fpscr".to_string()
        }
        (Vfp::MoveDouble, [low, high, double]) if double.starts_with('d') => {
            format!("{high}:{low} = {double}")
        }
        (Vfp::MoveDouble, [double, low, high]) if double.starts_with('d') => {
            format!("{double} = {high}:{low}")
        }
        _ => return None,
    };
    Some(line)
}

/// The opcode of `insn`, where it is A64.
fn aarch64_opcode(insn: &Insn) -> Option<A64Opcode> {
    aarch64::decoded(insn).map(|decoded| decoded.opcode)
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
    /// The order an access to a list goes in, as `ia` of `ldmia`, or
    /// `None` for an instruction that accesses no list.
    fn of(insn: &Insn) -> Option<(Self, WriteBack)> {
        use arm32::Decoded::{Core, Vfp as VfpWord};
        Some(match arm32::decoded(insn)? {
            Core { opcode: ArmOpcode::PUSH, .. } | VfpWord { vfp: Vfp::Push, .. } => {
                (Self::DecrementBefore, WriteBack::Yes)
            }
            Core { opcode: ArmOpcode::POP, .. } | VfpWord { vfp: Vfp::Pop, .. } => {
                (Self::IncrementAfter, WriteBack::Yes)
            }
            Core {
                opcode: ArmOpcode::LDM(up, before, ..) | ArmOpcode::STM(up, before, ..),
                ..
            } => {
                let order = match (up, before) {
                    (true, false) => Self::IncrementAfter,
                    (true, true) => Self::IncrementBefore,
                    (false, false) => Self::DecrementAfter,
                    (false, true) => Self::DecrementBefore,
                };
                (order, WriteBack::No)
            }
            VfpWord { vfp: Vfp::Multiple(Step::IncrementAfter, _), .. } => {
                (Self::IncrementAfter, WriteBack::No)
            }
            VfpWord { vfp: Vfp::Multiple(Step::DecrementBefore, _), .. } => {
                (Self::DecrementBefore, WriteBack::No)
            }
            _ => return None,
        })
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
    let (order, mut write_back) = ListOrder::of(insn)?;
    let (before, list) = insn.operands().split_once('{')?;
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
    let mut tokens = split_operands(insn.operands());
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
    if let Some(line) = aarch64_statement(insn, &tokens, last_compare) {
        return Some(line);
    }
    if let Some(line) = vfp_statement(insn, &tokens, last_compare) {
        return Some(line);
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
    ) && arm32::core_opcode(insn) != Some(ArmOpcode::MOVT);
    if functional
        && !lifted.writes.is_empty()
        && let Some((dest, sources)) = tokens.split_first()
        && !sources.is_empty()
    {
        // As printed, for the reader, without the size: `vsqrt` of
        // `vsqrt.f64`.
        let (printed_name, _) = split_printed(&insn.text);
        let name = printed_name.split('.').next().unwrap_or(printed_name);
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
            ([dest, _], Some(_)) if aarch64_opcode(insn) == Some(A64Opcode::ADRP) => {
                format!("{dest} = &page")
            }
            // `lui` puts its constant in the upper half.
            ([dest, _], None) if mips::rabbitizer_opcode(insn) == Some(MipsOpcode::core_lui) => {
                match canonical.operands.get(1) {
                    Some(Operand::Const(high)) => format!("{dest} = {}", constant(high << 16)),
                    _ => return None,
                }
            }
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
            // `csetm` is a `csinv` of the zero register, and `cset` a `csinc`.
            let one = if aarch64_opcode(insn) == Some(A64Opcode::CSINV) { "-1" } else { "1" };
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
                match arm32::core_opcode(insn) == Some(ArmOpcode::CMN) {
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
        Op::BitField if arm32::core_opcode(insn) == Some(ArmOpcode::MOVT) => {
            match operands.as_slice() {
                [dest, high] => format!("{dest} = {dest} & 0xffff | {high} << 16"),
                _ => return None,
            }
        }
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
        use crate::arch::arm32::Arm32;
        use crate::arch::thumb::Thumb2;
        let a32 = |word: u32| Arm32.decode(&word.to_le_bytes(), 0, 0).expect("the word decodes");
        // push.w {r4, lr}
        let push = Thumb2.decode(&[0x2d, 0xe9, 0x10, 0x40], 0, 0).expect("the word decodes");
        assert_eq!(crate::arch::split_printed(&push.text).0, "push");
        assert_eq!(ListOrder::of(&push), Some((ListOrder::DecrementBefore, WriteBack::Yes)));
        let vpop = a32(0xecbd_8b02); // vpop {d8}
        assert_eq!(crate::arch::split_printed(&vpop.text).0, "vpop");
        assert_eq!(ListOrder::of(&vpop), Some((ListOrder::IncrementAfter, WriteBack::Yes)));
        let stmdb = a32(0xe900_0002); // stmdb r0, {r1}
        assert_eq!(ListOrder::of(&stmdb), Some((ListOrder::DecrementBefore, WriteBack::No)));
        let ldmne = a32(0x1890_0002); // ldmne r0, {r1}
        assert_eq!(ListOrder::of(&ldmne), Some((ListOrder::IncrementAfter, WriteBack::No)));
        assert_eq!(ListOrder::of(&a32(0xe591_0000)), None, "ldr r0, [r1]");
        assert_eq!(ListOrder::IncrementAfter.offsets(8, 4), (0, 8));
        assert_eq!(ListOrder::IncrementBefore.offsets(8, 4), (4, 8));
        assert_eq!(ListOrder::DecrementAfter.offsets(8, 4), (-4, -8));
        assert_eq!(ListOrder::DecrementBefore.offsets(8, 4), (-8, -8));
    }

    /// A MIPS instruction as the decoder would give it. MIPS16e prints an
    /// `addiu` with two operands, which no MIPS32 word decodes to.
    fn mips(name: &str, operands: &str, kind: crate::arch::InsnKind) -> Insn {
        let opcode = match name {
            "lw" => MipsOpcode::core_lw,
            "addiu" => MipsOpcode::core_addiu,
            "jalr" => MipsOpcode::core_jalr,
            _ => MipsOpcode::core_or,
        };
        Insn::new(
            0,
            &[0; 4],
            &format!("{name} {operands}"),
            kind,
            crate::arch::Opcode::Mips(MipsDecoded::Rabbitizer(opcode)),
        )
    }

    #[test]
    fn a_load_of_a_page_is_found_by_the_addiu_after_it() {
        use crate::arch::InsnKind::{Call, Normal};
        let insns = [
            mips("lw", "v0, -0x7fe0(gp)", Normal),
            mips("lw", "a2, -0x7fe0(gp)", Normal),
            mips("lw", "t9, -0x7f00(gp)", Normal),
            mips("addiu", "v0, v0, 0x10", Normal),
            mips("addiu", "a2, a2, 0x20", Normal),
        ];
        let formed = [Some(0x1000), Some(0x1000), Some(0x1004), Some(0x2010), Some(0x2020)];
        assert_eq!(page_loads(&insns, &formed), HashSet::from([0, 1]));

        // MIPS16e adds to the register it writes.
        let insns = [mips("lw", "v0, 0x10(s0)", Normal), mips("addiu", "v0, 0x10", Normal)];
        assert_eq!(page_loads(&insns, &[Some(0x1000), Some(0x2010)]), HashSet::from([0]));

        // A write or a call between them leaves the register holding
        // something else.
        let insns = [
            mips("lw", "v0, -0x7fe0(gp)", Normal),
            mips("or", "v0, a0, zero", Normal),
            mips("addiu", "v0, v0, 0x10", Normal),
        ];
        assert!(page_loads(&insns, &[Some(0x1000), None, Some(0x2010)]).is_empty());
        let insns = [
            mips("lw", "v0, -0x7fe0(gp)", Normal),
            mips("jalr", "t9", Call { target: None }),
            mips("addiu", "v0, v0, 0x10", Normal),
        ];
        assert!(page_loads(&insns, &[Some(0x1000), None, Some(0x2010)]).is_empty());

        // An `addiu` that forms no address joins no page.
        let insns = [mips("lw", "v0, -0x7fe0(gp)", Normal), mips("addiu", "v0, v0, 1", Normal)];
        assert!(page_loads(&insns, &[Some(0x1000), None]).is_empty());
    }

    #[test]
    fn mips_hi_and_lo_read_as_registers() {
        use crate::arch::mips::Mips32;
        let words: [u32; 7] = [
            0x0085_0018, // mult a0, a1
            0x0000_1012, // mflo v0
            0x0085_001b, // divu zero, a0, a1
            0x0000_1810, // mfhi v1
            0x0080_0013, // mtlo a0
            0x7085_0000, // madd a0, a1
            0x7085_1002, // mul v0, a0, a1
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
        let (insns, _) = decode_all(&Mips32::BIG, &code, 0x1000);
        assert_eq!(
            il_lines(&Mips32::BIG, &code, &insns),
            [
                "hi:lo = a0 * a1",
                "v0 = lo",
                "lo = a0 u/ a1; hi = a0 u% a1",
                "v1 = hi",
                "lo = a0",
                "hi:lo = hi:lo + a0 * a1",
                "v0 = a0 * a1",
            ]
        );
    }

    #[test]
    fn a_mips_float_compare_and_its_branch_read_as_one_test() {
        use crate::arch::mips::Mips32;
        let words: [u32; 6] = [
            0x4622_003c, // c.lt.d fv0, fv1
            0x4501_0002, // bc1t $+0xc
            0x4500_0002, // bc1f $+0xc
            0x4622_0035, // c.ult.d fv0, fv1
            0x4501_0002, // bc1t $+0xc
            0x0000_0000, // nop
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
        let (insns, _) = decode_all(&Mips32::BIG, &code, 0x1000);
        let shown = il_lines(&Mips32::BIG, &code, &insns);
        assert_eq!(
            shown[..3],
            ["fcc = fv0 < fv1", "if (fv0 < fv1) goto $+0xc", "if (!(fv0 < fv1)) goto $+0xc"]
        );
        assert_eq!(shown[3], "fcc = !(fv0 >= fv1)", "true on a NaN");
        assert_eq!(shown[4], "if (!(fv0 >= fv1)) goto $+0xc");
    }

    #[test]
    fn every_mips_float_compare_reads_as_a_test() {
        use crate::arch::mips::Mips32;
        let expected = [
            "fcc = 0",
            "fcc = unordered(fv0, fv1)",
            "fcc = fv0 == fv1",
            "fcc = !(fv0 < fv1 || fv0 > fv1)",
            "fcc = fv0 < fv1",
            "fcc = !(fv0 >= fv1)",
            "fcc = fv0 <= fv1",
            "fcc = !(fv0 > fv1)",
        ];
        // c.f.d to c.ngt.d: the signaling eight test as the quiet eight do.
        let words: Vec<u32> = (0..16).map(|cond| 0x4622_0030 | cond).collect();
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
        let (insns, _) = decode_all(&Mips32::BIG, &code, 0x1000);
        let shown = il_lines(&Mips32::BIG, &code, &insns);
        assert_eq!(shown[..8], expected);
        assert_eq!(shown[8..], expected);
    }

    #[test]
    fn a_branch_on_false_negates_the_float_compare() {
        use crate::arch::mips::Mips32;
        let words: [u32; 3] = [
            0x4622_0035, // c.ult.d fv0, fv1
            0x4500_0002, // bc1f $+0xc
            0x0000_0000, // nop
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
        let (insns, _) = decode_all(&Mips32::BIG, &code, 0x1000);
        let shown = il_lines(&Mips32::BIG, &code, &insns);
        assert_eq!(shown[1], "if (fv0 >= fv1) goto $+0xc");
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
        assert_eq!(a32_condition(&insns[0], Some(Op::Compare)), None, "a compare that always runs");
        assert_eq!(a32_condition(&insns[1], Some(Op::Add)), Some("ne"));
        // mls r0, r1, r2, r3 ends in the letters of a condition.
        let mls = Arm32.decode(&0xe060_3291_u32.to_le_bytes(), 0, 0).expect("the word decodes");
        assert_eq!(crate::arch::split_printed(&mls.text).0, "mls");
        assert_eq!(a32_condition(&mls, Some(Op::MultiplyAdd)), None, "a multiply-subtract");
        // adcs r0, r0, r1 ends in `cs` too, and runs always.
        let adcs = Arm32.decode(&0xe0b0_0001_u32.to_le_bytes(), 0, 0).expect("the word decodes");
        assert_eq!(crate::arch::split_printed(&adcs.text).0, "adcs");
        assert_eq!(a32_condition(&adcs, Some(Op::Add)), None, "an add with carry");
    }

    #[test]
    fn conditional_compares_and_vector_moves_read_plainly() {
        let shown = lines(&[
            0x7a43_1800, // ccmp w0, #3, #0, ne
            0x5400_0040, // b.eq $+0x8
            0x3a41_b862, // ccmn w3, #1, #2, lt
            0x1e21_1400, // fccmp s0, s1, #0, ne
            0x6f00_e400, // movi v0.2d, #0
            0x4f00_2600, // movi v0.4s, #16, lsl #8
            0x6f00_8441, // mvni v1.8h, #2
            0x6f00_d462, // mvni v2.4s, #3, msl #16
            0x0e0c_3c20, // mov w0, v1.s[1]
            0x0e07_3ca4, // umov w4, v5.b[3]
            0x4e0a_2ce6, // smov x6, v7.h[2]
            0x4e0c_1c83, // mov v3.s[1], w4
            0x4e04_0d07, // dup v7.4s, w8
        ]);
        assert_eq!(
            shown,
            [
                "flags = ne ? compare(w0, 3) : nzcv(0)",
                "if (flags.Equal) goto $+0x8",
                "flags = lt ? compare(w3, -1) : nzcv(2)",
                "flags = ne ? compare(s0, s1) : nzcv(0)",
                "v0.2d = 0",
                "v0.4s = 0x10 << 8",
                "v1.8h = ~2",
                "v2.4s = ~(3 msl 16)",
                "w0 = v1.s[1]",
                "w4 = v5.b[3]",
                "x6 = smov(v7.h[2])",
                "v3.s[1] = w4",
                "v7.4s = dup(w8)",
            ]
        );
    }

    #[test]
    fn a_vfp_compare_and_its_moves_read_plainly() {
        use crate::arch::arm32::Arm32;
        let words: [u32; 8] = [
            0xe150_0001, // cmp r0, r1
            0xeeb4_0b41, // vcmp.f64 d0, d1
            0xeeb5_0ac0, // vcmpe.f32 s0, #0
            0xeef1_fa10, // vmrs APSR_nzcv, fpscr
            0xca00_0000, // bgt $+0x8
            0xec51_0b12, // vmov r0, r1, d2
            0xec43_2b13, // vmov d3, r2, r3
            0xee02_5a10, // vmov s4, r5
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = decode_all(&Arm32, &code, 0x1000);
        assert_eq!(
            il_lines(&Arm32, &code, &insns)[1..],
            [
                "fpscr = compare(d0, d1)",
                "fpscr = compare(s0, 0)",
                "flags = fpscr",
                "if (flags.SignedGreater) goto $+0x8",
                "r1:r0 = d2",
                "d3 = r3:r2",
                "s4 = r5",
            ]
        );
    }

    #[test]
    fn a_mips16e_frame_reads_as_its_stores_and_loads() {
        use crate::arch::mips16::Mips16;
        // save a0,32,ra,s0; restore 32,ra,s0; save 128; restore 32,ra,s0-s1,a2-a3
        let halfwords: [u16; 7] = [0xf004, 0x64e4, 0x6464, 0x6480, 0xf002, 0x6474, 0x6500];
        let code: Vec<u8> = halfwords.iter().flat_map(|half| half.to_be_bytes()).collect();
        let (insns, _) = decode_all(&Mips16::BIG, &code, 0x1000);
        assert_eq!(
            il_lines(&Mips16::BIG, &code, &insns)[..4],
            [
                "store.32 [sp] = a0; store.32 [sp - 8] = s0, ra; sp = sp - 0x20",
                "s0, ra = load.32 [sp + 0x18]; sp = sp + 0x20",
                "sp = sp - 0x80",
                "a2, a3, s0, s1, ra = load.32 [sp + 0xc]; sp = sp + 0x20",
            ]
        );
        assert_eq!(frame_statement(Mips16Op::Save, &["s0"]), None, "no size");
        assert_eq!(
            frame_statement(Mips16Op::Restore, &["0x4", "s0", "ra"]),
            None,
            "a frame too small"
        );
    }

    #[test]
    fn a_callee_takes_its_symbol_its_pair_or_its_address() {
        let function = |name: &str, address| crate::obj::Function {
            name: name.into(),
            address,
            code: Vec::new(),
        };
        let functions = [function("main", 0x100), function("", 0x200), function("", 0x300)];
        let paired = PairedLabels([(0x200, "sub_1f0".to_string())].into_iter().collect());
        let (links, space) = (Links::default(), AddressSpace::default());
        let context =
            |paired| Context { links: &links, space: &space, functions: &functions, paired };
        let arch = &crate::arch::aarch64::Aarch64;
        let named = |paired, address| context(paired).callee_at(arch, address);
        assert_eq!(named(None, 0x100).as_deref(), Some("main"));
        assert_eq!(named(None, 0x200).as_deref(), Some("sub_200"));
        assert_eq!(named(Some(&paired), 0x200).as_deref(), Some("sub_1f0"));
        assert_eq!(named(Some(&paired), 0x300).as_deref(), Some("sub_300"), "with no pair");
        assert_eq!(named(Some(&paired), 0x204), None, "inside a function");
    }

    #[test]
    fn a_conditional_return_names_its_condition() {
        use crate::arch::arm32::Arm32;
        // cmp r1, r3; bxne lr; popne {r11, pc}; bxne r3; bne $+0x8
        let code: Vec<u8> = [0xe151_0003_u32, 0x112f_ff1e, 0x18bd_8800, 0x112f_ff13, 0x1a00_0000]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let (insns, _) = decode_all(&Arm32, &code, 0x1000);
        let shown = il_lines(&Arm32, &code, &insns);
        assert_eq!(shown[1], "if (ne) return");
        assert!(shown[2].starts_with("if (ne) "), "{shown:?}");
        assert!(shown[2].ends_with("return"), "{shown:?}");
        assert_eq!(shown[3], "if (ne) goto r3");
        assert!(shown[4].starts_with("if (r1 != r3) goto"), "{shown:?}");
    }

    /// A function that calls a named one, `foo`, at `foo` from its start.
    fn calling_foo(arch: &dyn Arch, code: &[u8], foo: u64) -> Vec<String> {
        let functions =
            [crate::obj::Function { name: "foo".into(), address: 0x1000 + foo, code: Vec::new() }];
        let (links, space) = (Links::default(), AddressSpace::default());
        let context = Context { links: &links, space: &space, functions: &functions, paired: None };
        let (insns, _) = decode_all(arch, code, 0x1000);
        il_lines_in(arch, code, &insns, Some(context))
    }

    #[test]
    fn an_it_shows_no_line_and_its_call_keeps_the_condition() {
        use crate::arch::thumb::Thumb2;
        // cmp r0, #0; it ne; blne foo; bx lr; foo: bx lr
        let halfwords: [u16; 6] = [0x2800, 0xbf18, 0xf000, 0xf801, 0x4770, 0x4770];
        let code: Vec<u8> = halfwords.iter().flat_map(|half| half.to_le_bytes()).collect();
        assert_eq!(
            calling_foo(&Thumb2, &code, 0xa),
            ["flags = compare(r0, 0)", "if (ne) call foo", "return", "return"]
        );
    }

    #[test]
    fn a_conditional_a32_call_keeps_its_condition() {
        use crate::arch::arm32::Arm32;
        // cmp r0, #0; blne foo; bx lr; foo: bx lr
        let words: [u32; 4] = [0xe350_0000, 0x1b00_0000, 0xe12f_ff1e, 0xe12f_ff1e];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        assert_eq!(calling_foo(&Arm32, &code, 0xc)[1], "if (ne) call foo");
    }

    #[test]
    fn the_making_of_the_global_pointer_reads_as_one_line() {
        use crate::arch::mips::Mips32;
        let words: [u32; 5] = [
            0x3c1c_0002, // lui gp, 0x2
            0x279c_59ec, // addiu gp, gp, 0x59ec
            0x27bd_ffc8, // addiu sp, sp, -0x38
            0x0399_e021, // addu gp, gp, t9
            0x0000_0000, // nop
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
        let (insns, _) = decode_all(&Mips32::BIG, &code, 0x1000);
        let statements = il_statements_in(&Mips32::BIG, &code, &insns, None);
        let shown: Vec<(u64, &str)> =
            statements.iter().map(|line| (line.address, line.text.as_str())).collect();
        assert_eq!(shown, [(0x1008, "sp = sp + -0x38"), (0x100c, "gp = _gp"), (0x1010, "nop")]);
        assert_eq!(il_line_addresses(&Mips32::BIG, &insns), [0x1008, 0x100c, 0x1010]);
    }

    #[test]
    fn the_mips16e_global_pointer_reads_as_one_line() {
        use crate::arch::mips16::Mips16;
        // The opening of `adler32_combine_` in zlib, by GCC 14 at `-Os`.
        let halfwords: [u16; 7] = [0xf000, 0x6a02, 0xf0a8, 0x0b0c, 0xf400, 0x3240, 0xe269];
        let code: Vec<u8> = halfwords.iter().flat_map(|half| half.to_be_bytes()).collect();
        let (insns, _) = decode_all(&Mips16::BIG, &code, 0x1000);
        assert_eq!(il_lines(&Mips16::BIG, &code, &insns), ["v0 = _gp"]);
    }

    #[test]
    fn a_constant_built_alone_is_no_global_pointer() {
        use crate::arch::mips::Mips32;
        // lui gp, 0x2; addiu gp, gp, 0x59ec; with no `addu` of `t9`
        let words: [u32; 2] = [0x3c1c_0002, 0x279c_59ec];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
        let (insns, _) = decode_all(&Mips32::BIG, &code, 0x1000);
        assert_eq!(il_lines(&Mips32::BIG, &code, &insns).len(), 2);
    }

    #[test]
    fn any_code_shows_without_a_panic() {
        use crate::arch::{arm32::Arm32, mips::Mips32, mips16::Mips16, thumb::Thumb2};
        bolero::check!().with_type::<Vec<u8>>().for_each(|code| {
            let arches: [&dyn Arch; 6] =
                [&Aarch64, &Arm32, &Thumb2, &Mips32::BIG, &Mips16::LITTLE, &Mips16::BIG];
            for arch in arches {
                let (insns, _) = decode_all(arch, code, 0x1000);
                let statements = il_statements_in(arch, code, &insns, None);
                let addresses: Vec<u64> = statements.iter().map(|line| line.address).collect();
                assert_eq!(il_line_addresses(arch, &insns), addresses);
                assert!(addresses.is_sorted_by(|earlier, later| earlier < later));
            }
        });
    }

    #[test]
    fn what_the_il_does_not_name_reads_as_the_decoder_printed_it() {
        let shown = lines(&[0xd503_201f]); // nop
        assert_eq!(shown, ["nop"]);
    }
}
