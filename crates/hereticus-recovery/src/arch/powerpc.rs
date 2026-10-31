//! The rules that find functions in 32-bit PowerPC code.
//!
//! Every instruction is 4 bytes, and a pointer 4. A function that makes a
//! frame opens with `stwu r1, -N(r1)`, which stores the back chain and
//! moves the stack pointer in one. A call returns through the link
//! register, which a function that calls saves first:
//!
//! ```text
//! mflr r0
//! stwu r1, -0x20(r1)
//! stw  r0, 0x24(r1)
//! ```
//!
//! Code that is not PIC forms an address from two halves, as MIPS does:
//! `lis r9, hi` and `addi r9, r9, lo`, or `lis` and the offset of a load.
//! PIC code reads the program counter with `bcl 20, 31` and `mflr`, and
//! reaches its data from there. GCC adds the distance to the global offset
//! table with `addis` and `addi`; clang loads it from a word just before
//! the function, which is data among the code.

use super::{Insn, InsnKind, JumpTable, Memory, Recovery};
use core::ops::Range;
use hereticus_il::arch::Decoder as _;
use hereticus_il::arch::powerpc::*;
use hereticus_memory::{AddressSpace, ConstantKind};
use yaxpeax_power::{Instruction, Operand};

/// `nop`, which is `ori r0, r0, 0`.
const NOP: u32 = 0x6000_0000;

/// The volatile general registers, which a call does not keep: `r0` and
/// `r3` to `r12`.
const VOLATILE: [u8; 11] = [0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

/// How far back the parts of a table jump may lie.
const TABLE_LOOK_BACK: usize = 16;

/// More cases than any `switch` a compiler turns into one table.
const MOST_CASES: usize = 4096;

/// How far from its jump a case may lie when no bound gives the number of
/// cases. A table is followed by other data, which this keeps from reading
/// as more cases.
const MOST_CASE_DISTANCE: u64 = 0x1_0000;

/// The word at the start of `bytes`, where it holds one.
fn word_at(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(..INSN_WIDTH)?.try_into().ok()?))
}

/// The operands of `inst`, in the order of the hardware.
pub fn hardware_operands(inst: &Instruction) -> Vec<Operand> {
    (0..inst.operand_count()).filter_map(|index| inst.operand(index as u8).copied()).collect()
}

/// `insn` decoded again, with its operands, where it is PowerPC.
fn read(insn: &Insn) -> Option<(Instruction, Vec<Operand>)> {
    let inst = instruction(insn)?;
    let operands = hardware_operands(&inst);
    Some((inst, operands))
}

impl Recovery for PowerPc {
    /// `stwu r1, -N(r1)`, and `stwux r1, r1, rN` for a frame larger than a
    /// displacement holds. Only a function that needs no frame lacks one.
    fn is_prologue(&self, insn: &Insn) -> bool {
        let Some((inst, operands)) = read(insn) else { return false };
        match (inst.opcode(), operands.as_slice()) {
            (Opcode::STWU, [Operand::Register(stored), Operand::MemoryDisp { base, disp }]) => {
                stored.num() == STACK && base.num() == STACK && *disp < 0
            }
            (Opcode::STWUX, [Operand::Register(stored), Operand::MemoryIndexed { base, .. }]) => {
                stored.num() == STACK && base.num() == STACK
            }
            _ => false,
        }
    }

    /// `stwu r1, d(r1)` is primary opcode 37 with `r1` in both register
    /// fields, and `stwux r1, r1, rB` opcode 31 with extended opcode 183.
    fn may_be_prologue(&self, word: &[u8]) -> bool {
        const STWU_R1_R1: u32 = 0x9421_0000;
        const STWUX_R1_R1: u32 = 0x7c21_016e;
        word_at(word).is_some_and(|word| {
            word & 0xffff_0000 == STWU_R1_R1 || word & 0xffff_07ff == STWUX_R1_R1
        })
    }

    /// A function that calls saves the link register, and a compiler can
    /// read it before it makes the frame: clang writes `mflr r0` first.
    fn preamble_before_prologue(&self, earlier: &[Insn]) -> usize {
        let reads_link = |insn: &Insn| {
            read(insn).is_some_and(|(inst, operands)| {
                inst.opcode() == Opcode::MFSPR
                    && matches!(operands.as_slice(), [_, Operand::SPR(spr)] if spr.num() == SPR_LR)
            })
        };
        usize::from(earlier.last().is_some_and(reads_link))
    }

    /// GNU `as` aligns code with `nop`, and a linker pads with zero words,
    /// which are no instruction.
    fn is_padding(&self, insn: &Insn) -> bool {
        matches!(word_of(insn), Some(NOP | 0))
    }

    /// A zero word is no instruction, so it traps where it runs.
    fn is_trap_fill(&self, insn: &Insn) -> bool {
        word_of(insn) == Some(0)
    }

    /// Only whole words at the end are removed, and only the two a linker
    /// pads with.
    fn trim_padding<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        let mut end = bytes.len() - bytes.len() % INSN_WIDTH;
        while end >= INSN_WIDTH && matches!(word_at(&bytes[end - INSN_WIDTH..]), Some(NOP | 0)) {
            end -= INSN_WIDTH;
        }
        &bytes[..end]
    }

    /// Clang keeps the distance to the global offset table in a word just
    /// before a PIC function: see the module.
    fn data_among_code(&self) -> super::DataAmongCode {
        super::DataAmongCode::LiteralPools
    }

    /// The words that PIC code loads from the program counter, where they
    /// lie among the code: the word before a function that clang reads.
    fn literal_pool_words(&self, insns: &[Insn]) -> Vec<u64> {
        let (Some(first), Some(last)) = (insns.first(), insns.last()) else {
            return Vec::new();
        };
        let span = first.address.saturating_sub(2 * INSN_WIDTH as u64)
            ..last.address + last.bytes_len as u64;
        let mut tracker = Tracker::default();
        let mut words = Vec::new();
        for (index, insn) in insns.iter().enumerate() {
            let step = tracker.step(index, insn, None);
            if let Some(Access { address, origin: Origin::Counter, kind: AccessKind::Load }) =
                step.access
                && span.contains(&address)
            {
                words.push(address);
            }
        }
        words.sort_unstable();
        words.dedup();
        words
    }

    /// A `switch` compiles to a load from a table and `bctr`. GCC holds the
    /// distance from the table to each case, and adds the table to it:
    ///
    /// ```text
    /// lis   r9, table@ha
    /// slwi  r3, r3, 2
    /// addi  r9, r9, table@l
    /// lwzx  r3, r9, r3
    /// add   r3, r3, r9
    /// mtctr r3
    /// bctr
    /// ```
    ///
    /// A table of addresses leaves out the `add`. A `cmplwi` of the case
    /// number before it bounds the table.
    fn jump_tables(&self, memory: &Memory<'_>, code: Range<u64>, insns: &[Insn]) -> Vec<JumpTable> {
        let shapes: Vec<TableShape> =
            (0..insns.len()).filter_map(|index| table_shape(insns, index)).collect();
        if shapes.is_empty() {
            return Vec::new();
        }
        let mut bases = vec![None; shapes.len()];
        let mut tracker = Tracker::default();
        let mut next = 0;
        for (index, insn) in insns.iter().enumerate() {
            while let Some(shape) = shapes.get(next).filter(|shape| shape.load <= index) {
                if shape.load == index {
                    bases[next] = tracker.whole(shape.base);
                }
                next += 1;
            }
            if next == shapes.len() {
                break;
            }
            tracker.step(index, insn, Some(memory));
        }
        shapes
            .iter()
            .zip(bases)
            .filter_map(|(shape, base)| read_table(memory, &code, insns, shape, base?))
            .collect()
    }

    /// The stub GNU `ld` writes for a call from code that is not PIC, which
    /// jumps through a slot whose address it forms whole:
    ///
    /// ```text
    /// lis   r11, slot@ha
    /// lwz   r11, slot@l(r11)
    /// mtctr r11
    /// bctr
    /// ```
    fn stub_slot(&self, code: &[u8], address: u64) -> Option<u64> {
        let length = code.len().min(4 * INSN_WIDTH) / INSN_WIDTH * INSN_WIDTH;
        if length < 4 * INSN_WIDTH {
            return None;
        }
        let (insns, _) = super::decode_all(self, &code[..length], address);
        let [high, load, move_count, jump] = insns.as_slice() else { return None };
        if jump.kind != (InsnKind::Jump { target: None }) || !moves_to_count(move_count) {
            return None;
        }
        let mut tracker = Tracker::default();
        tracker.step(0, high, None);
        let access = tracker.step(1, load, None).access?;
        (access.kind == AccessKind::Load && access.origin == Origin::Constant)
            .then_some(access.address)
    }

    /// The addresses a function forms whole, from two halves or from the
    /// program counter.
    fn data_addresses(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        memory: &Memory<'_>,
    ) -> Vec<u64> {
        let tracked = track(body, space, Some(memory));
        let mut addresses: Vec<u64> = tracked
            .joins
            .iter()
            .flatten()
            .copied()
            .filter(|&address| space.contains_formed(address))
            .collect();
        addresses.dedup();
        addresses
    }
}

/// Whether `insn` is `mtctr`, which a jump through the count register
/// needs first.
fn moves_to_count(insn: &Insn) -> bool {
    read(insn).is_some_and(|(inst, operands)| {
        inst.opcode() == Opcode::MTSPR
            && matches!(operands.first(), Some(Operand::SPR(spr)) if spr.num() == SPR_CTR)
    })
}

/// What a word of a jump table holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Entries {
    /// The address of each case.
    Addresses,
    /// The distance from the table to each case.
    FromTable,
}

/// The parts of a jump through a table, as [`table_shape`] reads them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TableShape {
    /// The index of the `bctr`.
    jump: usize,
    /// The index of the load from the table.
    load: usize,
    /// The general register that holds the table at the load.
    base: u8,
    /// What the table holds.
    entries: Entries,
}

/// The general register `operand` names, by number.
fn general(operand: &Operand) -> Option<u8> {
    match operand {
        Operand::Register(reg) => Some(reg.num()),
        Operand::RegisterOrZero(reg) if reg.num() != 0 => Some(reg.num()),
        _ => None,
    }
}

/// The last instruction before `insns[before]` that writes general register
/// `register`, with its index, within [`TABLE_LOOK_BACK`] instructions.
fn last_write(insns: &[Insn], before: usize, register: u8) -> Option<(usize, Instruction)> {
    let written = if register == STACK {
        hereticus_il::Reg::Stack
    } else {
        hereticus_il::Reg::General(register)
    };
    let from = before.saturating_sub(TABLE_LOOK_BACK);
    (from..before).rev().find_map(|at| {
        let insn = &insns[at];
        let writes = PowerPc.lift(insn).is_some_and(|lifted| lifted.writes.contains(written));
        writes.then(|| instruction(insn).map(|inst| (at, inst))).flatten()
    })
}

/// The table load of `lwzx rD, rA, rB` or `lwz rD, 0(rA)`, as the register
/// that holds the table: `rA` of the indexed form, where `rB` is the case.
fn table_load(inst: &Instruction) -> Option<u8> {
    match (inst.opcode(), hardware_operands(inst).as_slice()) {
        (Opcode::LWZX, [_, Operand::MemoryIndexed { base, .. }]) if base.num() != 0 => {
            Some(base.num())
        }
        _ => None,
    }
}

/// Read the parts of a jump through a table at `insns[index]`, where it is
/// one.
fn table_shape(insns: &[Insn], index: usize) -> Option<TableShape> {
    let jump = &insns[index];
    if jump.kind != (InsnKind::Jump { target: None }) || decoded(jump)?.opcode != Opcode::BCCTR {
        return None;
    }
    let from = index.saturating_sub(TABLE_LOOK_BACK);
    let move_at = (from..index).rev().find(|&at| moves_to_count(&insns[at]))?;
    let (_, moved) = read(&insns[move_at])?;
    let target = general(moved.get(1)?)?;
    let (at, def) = last_write(insns, move_at, target)?;
    if let Some(base) = table_load(&def) {
        return Some(TableShape { jump: index, load: at, base, entries: Entries::Addresses });
    }
    if def.opcode() != Opcode::ADD {
        return None;
    }
    let operands = hardware_operands(&def);
    let [_, left, right] = operands.as_slice() else { return None };
    let (left, right) = (general(left)?, general(right)?);
    [(left, right), (right, left)].into_iter().find_map(|(loaded, table)| {
        let (load, inst) = last_write(insns, at, loaded)?;
        (table_load(&inst)? == table).then_some(TableShape {
            jump: index,
            load,
            base: table,
            entries: Entries::FromTable,
        })
    })
}

/// The number of cases, from the `cmplwi rN, n` and the branch past the
/// table that guard it, as `n + 1`.
fn case_count(insns: &[Insn], index: usize) -> Option<usize> {
    let from = index.saturating_sub(TABLE_LOOK_BACK);
    insns[from..index].iter().rev().find_map(|insn| {
        let (inst, operands) = read(insn)?;
        if inst.opcode() != Opcode::CMPLI {
            return None;
        }
        match operands.as_slice() {
            [.., Operand::ImmU16(bound)] => {
                usize::from(*bound).checked_add(1).filter(|&count| count <= MOST_CASES)
            }
            _ => None,
        }
    })
}

/// Read the cases of the table `shape` names, which lies at `table`.
fn read_table(
    memory: &Memory<'_>,
    code: &Range<u64>,
    insns: &[Insn],
    shape: &TableShape,
    table: u64,
) -> Option<JumpTable> {
    let jump = &insns[shape.jump];
    let bound = case_count(insns, shape.jump);
    let mut targets = Vec::new();
    let mut word = table;
    for _ in 0..bound.unwrap_or(MOST_CASES) {
        let Some(value) = memory.bytes(word, INSN_WIDTH).and_then(word_at) else { break };
        let target = match shape.entries {
            Entries::Addresses => u64::from(value),
            Entries::FromTable => u64::from((table as u32).wrapping_add(value)),
        };
        let holds_code = target.is_multiple_of(INSN_WIDTH as u64) && code.contains(&target);
        let near = target.abs_diff(jump.address) < MOST_CASE_DISTANCE;
        if !holds_code || (bound.is_none() && !near) {
            break;
        }
        targets.push(target);
        word += INSN_WIDTH as u64;
    }
    (!targets.is_empty()).then_some(JumpTable { jump: jump.address, words: table..word, targets })
}

/// Where an address the code holds comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// From constants in the code, as `lis` and `addi` give it. It is an
    /// address only where it lies inside the image.
    Constant,
    /// From the program counter, as PIC code reads it. It is an address
    /// wherever it lies.
    Counter,
}

/// What a general register holds, as far as the code before shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Held {
    /// The upper half of a value, from the `lis` or `addis` at `from`.
    Upper { value: u64, from: usize, origin: Origin },
    /// A value whole.
    Whole { value: u64, origin: Origin },
    /// A word loaded from memory, which PIC code adds to the program
    /// counter.
    Loaded(u64),
    /// An address formed from the program counter, whose value the code
    /// alone does not show.
    FromCounter,
}

/// How an instruction touches memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccessKind {
    Load,
    Store,
}

/// An access at an address the code formed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Access {
    address: u64,
    origin: Origin,
    kind: AccessKind,
}

/// What one instruction formed, as [`Tracker::step`] tells.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Step {
    /// The address it joined from an upper half, and the index of the
    /// instruction that made that half.
    join: Option<(u64, Origin, Option<usize>)>,
    /// Whether a constant of it is a distance from the program counter.
    from_counter: bool,
    /// The access it made at a known address.
    access: Option<Access>,
}

/// What the general registers hold, one instruction after the next.
///
/// Branches are stepped over, as if the code ran straight down: a compiler
/// forms an address next to where it uses it.
#[derive(Clone, Debug, Default)]
struct Tracker {
    held: [Option<Held>; 32],
    /// The address that `bcl 20, 31` to the next word put in the link
    /// register, where nothing wrote it since.
    link: Option<u64>,
}

/// A 32-bit value.
fn word(value: u64) -> u64 {
    value & 0xffff_ffff
}

impl Tracker {
    /// The value general register `register` holds whole, where known.
    fn whole(&self, register: u8) -> Option<u64> {
        match self.held.get(usize::from(register))? {
            Some(Held::Whole { value, .. }) => Some(*value),
            _ => None,
        }
    }

    fn get(&self, register: u8) -> Option<Held> {
        *self.held.get(usize::from(register))?
    }

    fn set(&mut self, register: u8, held: Option<Held>) {
        if let Some(slot) = self.held.get_mut(usize::from(register)) {
            *slot = held;
        }
    }

    /// The address an offset from what `base` holds forms, and from where.
    fn offset_from(&self, base: u8, offset: i64) -> Option<(u64, Origin, Option<usize>)> {
        match self.get(base)? {
            Held::Upper { value, from, origin } => {
                Some((word(value.wrapping_add_signed(offset)), origin, Some(from)))
            }
            Held::Whole { value, origin: Origin::Counter } => {
                Some((word(value.wrapping_add_signed(offset)), Origin::Counter, None))
            }
            _ => None,
        }
    }

    /// Step over `insn`, the instruction at `index`, and say what it
    /// formed. `memory`, where given, gives the words PIC code loads.
    fn step(&mut self, index: usize, insn: &Insn, memory: Option<&Memory<'_>>) -> Step {
        let mut step = Step::default();
        if let InsnKind::Call { .. } = insn.kind {
            VOLATILE.iter().for_each(|&register| self.set(register, None));
            self.link = None;
            return step;
        }
        if insn.kind == InsnKind::Normal
            && decoded(insn).is_some_and(|decoded| decoded.opcode == Opcode::BCL)
        {
            self.link = insn.address.checked_add(INSN_WIDTH as u64);
            return step;
        }
        let Some((inst, operands)) = read(insn) else { return step };
        let held = match (inst.opcode(), operands.as_slice()) {
            (
                Opcode::ADDIS,
                [Operand::Register(dest), Operand::RegisterOrZero(source), Operand::ImmExts16(imm)],
            ) => {
                let high = word((i64::from(*imm) << 16) as u64);
                match (source.num(), self.get(source.num())) {
                    (0, _) => {
                        Some(Held::Upper { value: high, from: index, origin: Origin::Constant })
                    }
                    (
                        _,
                        Some(Held::Whole { value, origin } | Held::Upper { value, origin, .. }),
                    ) => {
                        step.from_counter = origin == Origin::Counter;
                        Some(Held::Upper { value: word(value + high), from: index, origin })
                    }
                    (_, Some(Held::FromCounter)) => {
                        step.from_counter = true;
                        Some(Held::FromCounter)
                    }
                    _ => None,
                }
                .map(|held| (dest.num(), Some(held)))
            }
            (
                Opcode::ADDI | Opcode::ADDIC,
                [Operand::Register(dest), Operand::RegisterOrZero(source), Operand::ImmExts16(imm)],
            ) => {
                let joined = self.offset_from(source.num(), (*imm).into());
                step.join = joined;
                step.from_counter = matches!(self.get(source.num()), Some(Held::FromCounter))
                    || joined.is_some_and(|(_, origin, _)| origin == Origin::Counter);
                let held = match joined {
                    Some((value, origin, _)) => Some(Held::Whole { value, origin }),
                    None if step.from_counter => Some(Held::FromCounter),
                    None => None,
                };
                Some((dest.num(), held))
            }
            (
                Opcode::ORI,
                [Operand::Register(dest), Operand::Register(source), Operand::ImmU16(imm)],
            ) => {
                let held = match self.get(source.num()) {
                    Some(Held::Upper { value, from, origin }) => {
                        let value = value | u64::from(*imm);
                        step.join = Some((value, origin, Some(from)));
                        Some(Held::Whole { value, origin })
                    }
                    _ => None,
                };
                Some((dest.num(), held))
            }
            // `mr`, which is `or rD, rS, rS`.
            (
                Opcode::OR,
                [Operand::Register(dest), Operand::Register(left), Operand::Register(right)],
            ) if left == right => Some((dest.num(), self.get(left.num()))),
            (
                Opcode::ADD,
                [Operand::Register(dest), Operand::Register(left), Operand::Register(right)],
            ) => {
                let held = match (self.get(left.num()), self.get(right.num())) {
                    (
                        Some(Held::Whole { value, origin: Origin::Counter }),
                        Some(Held::Loaded(distance)),
                    )
                    | (
                        Some(Held::Loaded(distance)),
                        Some(Held::Whole { value, origin: Origin::Counter }),
                    ) => {
                        Some(Held::Whole { value: word(value + distance), origin: Origin::Counter })
                    }
                    (Some(Held::Whole { origin: Origin::Counter, .. } | Held::FromCounter), _)
                    | (_, Some(Held::Whole { origin: Origin::Counter, .. } | Held::FromCounter)) => {
                        Some(Held::FromCounter)
                    }
                    _ => None,
                };
                Some((dest.num(), held))
            }
            (Opcode::MFSPR, [Operand::Register(dest), Operand::SPR(spr)])
                if spr.num() == SPR_LR =>
            {
                let held = self.link.map(|value| Held::Whole { value, origin: Origin::Counter });
                Some((dest.num(), held))
            }
            _ => None,
        };
        if let Some((dest, held)) = held {
            self.set(dest, held);
            return step;
        }

        // A load or a store through a base whose value is known.
        let access = operands.iter().find_map(|operand| match *operand {
            Operand::MemoryDisp { base, disp } if base.num() != 0 => Some((base.num(), disp)),
            _ => None,
        });
        if let Some((base, disp)) = access
            && let Some(kind) = access_kind(insn)
        {
            step.from_counter = matches!(self.get(base), Some(Held::FromCounter));
            if let Some((address, origin, from)) = self.offset_from(base, disp.into()) {
                step.join = Some((address, origin, from));
                step.from_counter |= origin == Origin::Counter;
                step.access = Some(Access { address, origin, kind });
            }
        }
        let lifted = PowerPc.lift(insn);
        let loaded = step
            .access
            .filter(|access| access.kind == AccessKind::Load && access.origin == Origin::Counter);
        for reg in lifted.iter().flat_map(|lifted| lifted.writes.iter()) {
            let register = match reg {
                hereticus_il::Reg::General(number) if number < 32 => number,
                hereticus_il::Reg::Stack => STACK,
                LINK => {
                    self.link = None;
                    continue;
                }
                _ => continue,
            };
            let value = loaded
                .and_then(|access| memory?.bytes(access.address, INSN_WIDTH).and_then(word_at))
                .map(|value| Held::Loaded(value.into()));
            self.set(register, value);
        }
        step
    }
}

/// Whether `insn` loads or stores, where it touches memory.
fn access_kind(insn: &Insn) -> Option<AccessKind> {
    match PowerPc.lift(insn)?.memory?.kind {
        hereticus_il::AccessKind::Load => Some(AccessKind::Load),
        hereticus_il::AccessKind::Store => Some(AccessKind::Store),
        hereticus_il::AccessKind::LoadStore => None,
    }
}

/// What [`track`] found in a body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tracked {
    /// For each instruction, whether its constant is an address.
    pub kinds: Vec<ConstantKind>,
    /// For each instruction, the address it forms whole, where it forms
    /// one: the join of two halves, or an offset from the program counter.
    pub joins: Vec<Option<u64>>,
}

/// The constants of `body` that are parts of an address inside `space`,
/// and the addresses they form.
///
/// An upper half from `lis` is an address only where the half joined to it
/// gives one: `lis` and `ori` also build a large constant, as the magic
/// number of a division is. Any offset from the program counter is an
/// address, as is the `addis` and `addi` that reach the global offset table
/// from it. `memory`, where given, gives the word clang loads to reach it.
pub fn track(body: &[Insn], space: &AddressSpace, memory: Option<&Memory<'_>>) -> Tracked {
    let mut tracked =
        Tracked { kinds: vec![ConstantKind::Value; body.len()], joins: vec![None; body.len()] };
    let mut tracker = Tracker::default();
    for (index, insn) in body.iter().enumerate() {
        let step = tracker.step(index, insn, memory);
        if step.from_counter {
            tracked.kinds[index] = ConstantKind::Address;
        }
        let Some((address, origin, from)) = step.join else { continue };
        if origin == Origin::Counter || space.contains_formed(address) {
            tracked.kinds[index] = ConstantKind::Address;
            tracked.joins[index] = Some(address);
            if let Some(from) = from {
                tracked.kinds[from] = ConstantKind::Address;
            }
        }
    }
    tracked
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn code(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_be_bytes()).collect()
    }

    fn decode_one(word: u32) -> Insn {
        PowerPc.decode(&word.to_be_bytes(), 0, 0x1000).expect("4 bytes always decode")
    }

    fn decode_at(words: &[u32], address: u64) -> Vec<Insn> {
        super::super::decode_all(&PowerPc, &code(words), address).0
    }

    #[rstest]
    #[case::stwu(0x9421_fff0, true)]
    #[case::stwu_up(0x9421_0010, false)]
    #[case::stwu_other_base(0x9423_fff0, false)]
    #[case::stwux(0x7c21_016e, true)]
    #[case::stw(0x9001_0014, false)]
    #[case::mflr(0x7c08_02a6, false)]
    fn the_frame_allocation_opens_a_function(#[case] word: u32, #[case] opens: bool) {
        assert_eq!(PowerPc.is_prologue(&decode_one(word)), opens);
        if opens {
            assert!(PowerPc.may_be_prologue(&word.to_be_bytes()));
        }
    }

    /// The quick test of the bits never refuses a word the full test takes.
    #[test]
    fn the_bits_of_a_prologue_admit_every_prologue() {
        bolero::check!().with_type::<u32>().for_each(|&word| {
            if PowerPc.is_prologue(&decode_one(word)) {
                assert!(PowerPc.may_be_prologue(&word.to_be_bytes()), "{word:#010x}");
            }
        });
    }

    #[test]
    fn mflr_before_the_frame_belongs_to_the_function() {
        let earlier = decode_at(&[0x3860_0000, 0x7c08_02a6], 0x1000);
        assert_eq!(PowerPc.preamble_before_prologue(&earlier), 1);
        let earlier = decode_at(&[0x7c08_02a6, 0x3860_0000], 0x1000);
        assert_eq!(PowerPc.preamble_before_prologue(&earlier), 0);
    }

    #[rstest]
    #[case::nops(&[0x4e80_0020, NOP, NOP], 4)]
    #[case::zeros(&[0x4e80_0020, 0, 0], 4)]
    #[case::none(&[0x3860_0000, 0x4e80_0020], 8)]
    #[case::all(&[NOP, 0], 0)]
    fn padding_is_nops_and_zeros(#[case] words: &[u32], #[case] kept: usize) {
        assert_eq!(PowerPc.trim_padding(&code(words)).len(), kept);
    }

    #[test]
    fn a_partial_word_at_the_end_is_dropped() {
        assert_eq!(PowerPc.trim_padding(&[0x4e, 0x80, 0x00, 0x20, 0x60]).len(), 4);
    }

    /// GCC's table of distances from the table, guarded by `cmplwi`.
    #[test]
    fn reads_a_table_of_distances_from_the_table() {
        let words = [
            0x2803_0002, // cmplwi r3, 2
            0x4181_0024, // bgt $+0x24
            0x3d20_0000, // lis r9, 0
            0x5463_103a, // slwi r3, r3, 2
            0x3929_2000, // addi r9, r9, 0x2000
            0x7c69_182e, // lwzx r3, r9, r3
            0x7c63_4a14, // add r3, r3, r9
            0x7c69_03a6, // mtctr r3
            0x4e80_0420, // bctr
            0x3860_0001, // li r3, 1        ; 0x1024, a case
            0x4e80_0020, // blr
        ];
        let insns = decode_at(&words, 0x1000);
        let text = code(&words);
        let table = code(&[0xffff_f024, 0xffff_f028, 0xffff_f024, 0x1234_5678]);
        let regions = [(0x1000, text.as_slice()), (0x2000, table.as_slice())];
        let memory = Memory::new(&regions);
        let tables = PowerPc.jump_tables(&memory, 0x1000..0x102c, &insns);
        assert_eq!(
            tables,
            [JumpTable {
                jump: 0x1020,
                words: 0x2000..0x200c,
                targets: vec![0x1024, 0x1028, 0x1024]
            }]
        );
    }

    #[test]
    fn a_jump_through_a_pointer_is_no_table() {
        let words = [
            0x8129_0000, // lwz r9, 0(r9)
            0x7d29_03a6, // mtctr r9
            0x4e80_0420, // bctr
        ];
        let insns = decode_at(&words, 0x1000);
        let text = code(&words);
        let regions = [(0x1000, text.as_slice())];
        assert!(PowerPc.jump_tables(&Memory::new(&regions), 0x1000..0x100c, &insns).is_empty());
    }

    #[test]
    fn reads_the_slot_a_plt_stub_jumps_through() {
        let stub = code(&[
            0x3d60_1002, // lis r11, 0x1002
            0x816b_8010, // lwz r11, -0x7ff0(r11)
            0x7d69_03a6, // mtctr r11
            0x4e80_0420, // bctr
        ]);
        assert_eq!(PowerPc.stub_slot(&stub, 0x1000), Some(0x1001_8010));
        assert_eq!(PowerPc.stub_slot(&stub[..12], 0x1000), None);
    }

    #[test]
    fn lis_and_addi_form_an_address_inside_the_image() {
        let body = decode_at(
            &[
                0x3c60_1000, // lis r3, 0x1000
                0x3863_0040, // addi r3, r3, 0x40
                0x3c80_2492, // lis r4, 0x2492
                0x6084_4925, // ori r4, r4, 0x4925   ; a divisor, no address
            ],
            0x1000,
        );
        let space = AddressSpace::from_ranges(core::iter::once(0x1000_0000..0x1001_0000));
        let tracked = track(&body, &space, None);
        use ConstantKind::{Address, Value};
        assert_eq!(tracked.kinds, [Address, Address, Value, Value]);
        assert_eq!(tracked.joins, [None, Some(0x1000_0040), None, None]);
    }

    #[test]
    fn a_load_through_an_upper_half_forms_its_address() {
        let body = decode_at(
            &[
                0x3d20_1001, // lis r9, 0x1001
                0x8069_fff0, // lwz r3, -0x10(r9)
            ],
            0x1000,
        );
        let space = AddressSpace::from_ranges(core::iter::once(0x1000_0000..0x1002_0000));
        assert_eq!(track(&body, &space, None).joins, [None, Some(0x1000_fff0)]);
    }

    /// GCC PIC: the program counter, then the distance to the table.
    #[test]
    fn an_offset_from_the_program_counter_is_an_address() {
        let body = decode_at(
            &[
                0x429f_0005, // bcl 20, 31, $+4
                0x7fc8_02a6, // mflr r30
                0x3fde_0001, // addis r30, r30, 1
                0x3bde_0010, // addi r30, r30, 0x10
                0x813e_fff8, // lwz r9, -8(r30)
                0x3860_0005, // li r3, 5
            ],
            0x1000,
        );
        let tracked = track(&body, &AddressSpace::none(), None);
        use ConstantKind::{Address, Value};
        assert_eq!(tracked.kinds, [Value, Value, Address, Address, Address, Value]);
        assert_eq!(tracked.joins[3], Some(0x1_1014));
        assert_eq!(tracked.joins[4], Some(0x1_100c));
    }

    /// Clang PIC: the distance to the table is a word before the function.
    #[test]
    fn the_word_clang_loads_before_a_function_is_data() {
        let words = [
            0x0001_0000, // .long table - .L0
            0x7c08_02a6, // mflr r0
            0x9421_fff0, // stwu r1, -0x10(r1)
            0x429f_0005, // bcl 20, 31, $+4
            0x7fc8_02a6, // mflr r30
            0x80be_fff0, // lwz r5, -0x10(r30)   ; the word at 0x1000
            0x7fc5_f214, // add r30, r5, r30
            0x807e_0008, // lwz r3, 8(r30)
        ];
        let insns = decode_at(&words, 0x1000);
        assert_eq!(PowerPc.literal_pool_words(&insns[1..]), [0x1000]);
        let text = code(&words);
        let regions = [(0x1000, text.as_slice())];
        let memory = Memory::new(&regions);
        let tracked = track(&insns, &AddressSpace::none(), Some(&memory));
        assert_eq!(tracked.kinds[7], ConstantKind::Address);
        assert_eq!(tracked.joins[7], Some(0x1_1018));
    }

    #[test]
    fn a_call_forgets_what_volatile_registers_held() {
        let body = decode_at(
            &[
                0x3c60_1000, // lis r3, 0x1000
                0x4800_0011, // bl $+0x10
                0x3863_0040, // addi r3, r3, 0x40
            ],
            0x1000,
        );
        let space = AddressSpace::from_ranges(core::iter::once(0x1000_0000..0x1001_0000));
        assert_eq!(track(&body, &space, None).joins, [None, None, None]);
    }

    #[test]
    fn padding_is_a_nop_or_a_zero_word() {
        assert!(PowerPc.is_padding(&decode_one(NOP)));
        assert!(PowerPc.is_padding(&decode_one(0)));
        assert!(PowerPc.is_trap_fill(&decode_one(0)));
        assert!(!PowerPc.is_trap_fill(&decode_one(NOP)));
        assert!(!PowerPc.is_padding(&decode_one(0x3860_0000)));
    }
}
