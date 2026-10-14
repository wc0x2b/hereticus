//! MIPS16e, the compressed instruction set of MIPS32.
//!
//! OpenWrt builds much of its MIPS user space as MIPS16e: about half of the
//! binaries of the images the tests download hold such code. A function
//! runs in MIPS16e where bit 0 of its address is set, as a Thumb-2 function
//! does on ARM, and `jalx` switches between the two sets.
//!
//! An instruction is 16 bits, or 32 with an `extend` prefix that widens its
//! constant, or a `jal`. Each reads here as the MIPS32 instruction it does
//! the work of, so that the MIPS32 decoder names it and the MIPS32 lifter
//! lifts it: `addiu v0, 1` reads as `addiu v0, v0, 0x1`. MIPS16e keeps
//! the result of a compare in the T register, which is `t8`, so `slt a0, a1`
//! reads as `slt t8, a0, a1` and `bteqz` as `beqz t8`. What MIPS32 has no
//! instruction for keeps its own form: the branches, whose offsets differ,
//! the loads relative to the program counter, and `save` and `restore`.
//!
//! `rabbitizer` reads no MIPS16e, so this module decodes it from the
//! encodings of the MIPS16e ASE manual.

pub use hereticus_il::arch::mips16::*;

use super::mips::{
    Decoded as MipsDecoded, GP, Mips32, SP_REG, T9, access, constant, decoded, first_register, is,
    operands_of, register_name,
};
use super::{
    CallTarget, Decoder, GlobalPointerSetup, Insn, InsnKind, JumpTable, Memory, Recovery,
};
use crate::address::{AddressSpace, ConstantKind, Contents};
use hereticus_il as il;
use rabbitizer::opcodes::Opcode;

/// The function field of the MIPS32 `addu`.
const ADDU: u32 = 0x21;

fn mips16_op(insn: &Insn) -> Option<Op> {
    match decoded(insn)? {
        MipsDecoded::Mips16(op) => Some(op),
        _ => None,
    }
}

impl Recovery for Mips16 {
    fn jump_tables(
        &self,
        memory: &Memory<'_>,
        code: core::ops::Range<u64>,
        insns: &[Insn],
    ) -> Vec<JumpTable> {
        let entry = |address: u64| {
            let bytes = memory.bytes(address, HALFWORD)?;
            Some(self.base.read_halfword([bytes[0], bytes[1]]) as i16)
        };
        (0..insns.len())
            .filter_map(|index| read_jump_table(self, insns, index, &code, &entry))
            .collect()
    }

    /// An address taken from the program counter, or a lower half added to
    /// a page that PIC code read from the global offset table, through a
    /// copy of the global pointer:
    ///
    /// ```text
    /// la    a1, text               lw    a1, %got(text)(s0)
    ///                              addiu a1, %lo(text)
    /// ```
    fn data_addresses(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        memory: &Memory<'_>,
    ) -> Vec<u64> {
        self.addresses_by_index(body, space, memory)
            .into_iter()
            .map(|(_, address)| address)
            .collect()
    }

    /// PIC code calls a function it does not reach with `jal` through a
    /// slot of the global offset table, as MIPS32 does. It reaches the table
    /// through a copy of the global pointer, as `s0`:
    ///
    /// ```text
    /// lw   v0, %call16(callee)(s0)       lw    v0, %got(local)(s0)
    /// jalr v0                            addiu v0, %lo(local)
    /// move t9, v0                        jalr  v0
    /// ```
    ///
    /// A local function is reached as on the right: through a page that a
    /// slot holds, and its offset in that page.
    fn call_targets(&self, insns: &[Insn]) -> Vec<(usize, Option<CallTarget>)> {
        let slot_of = |load_at: usize, load: &Insn| {
            let (offset, base) = load_reference(load)?;
            if !is(load, Opcode::core_lw) || !holds_global_pointer(insns, load_at, base) {
                return None;
            }
            let global_pointer = global_pointer_before(self, insns, load_at)?;
            Some(u64::from((global_pointer as u32).wrapping_add(offset as u32)))
        };
        let through_slot = |index: usize| {
            let register = operands_of(&insns[index]).last().and_then(super::mips::register)?;
            let (written_at, written) = last_write(insns, index, register)?;
            let operands = operands_of(written);
            match operands.as_slice() {
                [_, il::Operand::Reg(source), low] if is(written, Opcode::core_addiu) => {
                    let (load_at, load) = last_write(insns, written_at, *source)?;
                    let slot = slot_of(load_at, load)?;
                    Some(CallTarget::PageOffset { slot, offset: constant(low)? })
                }
                _ => slot_of(written_at, written).map(CallTarget::Slot),
            }
        };
        insns
            .iter()
            .enumerate()
            .filter_map(|(index, insn)| match insn.kind {
                InsnKind::Call { target: Some(target) } => {
                    Some((index, Some(CallTarget::Address(target))))
                }
                InsnKind::Call { target: None } => Some((index, through_slot(index))),
                InsnKind::Jump { target: Some(target) } if super::leaves(insns, target) => {
                    Some((index, Some(CallTarget::Address(target))))
                }
                _ => None,
            })
            .collect()
    }

    fn is_function_entry(&self, body: &[Insn]) -> bool {
        body.get(..GP_PREAMBLE_LENGTH).is_some_and(is_gp_preamble)
    }

    /// PIC computes the global pointer before `save`.
    fn preamble_before_prologue(&self, earlier: &[Insn]) -> usize {
        let start = earlier.len().saturating_sub(GP_PREAMBLE_LENGTH);
        if is_gp_preamble(&earlier[start..]) { GP_PREAMBLE_LENGTH } else { 0 }
    }

    /// A pointer to a MIPS16e function has bit 0 set, as on Thumb-2.
    fn tagged_function(&self, word: u64) -> Option<u64> {
        (word & 1 == 1).then_some(word & !1)
    }

    /// `save` makes the frame of almost every function that calls, and a
    /// leaf drops the stack pointer as MIPS32 does.
    fn is_prologue(&self, insn: &Insn) -> bool {
        mips16_op(insn) == Some(Op::Save) || self.base.is_prologue(insn)
    }

    fn is_tail_call(&self, insn: &Insn) -> bool {
        matches!(insn.kind, InsnKind::Jump { target: None })
    }

    /// A zero halfword pads as `nop` does, and reads as this `addiu`. In
    /// the GCC builds of the tests, no instruction is a zero halfword: each
    /// is fill or a word of a literal pool.
    fn is_padding(&self, insn: &Insn) -> bool {
        is(insn, Opcode::core_nop)
            || (is(insn, Opcode::core_addiu)
                && operands_of(insn).as_slice()
                    == [
                        il::Operand::Reg(il::Reg::General(16)),
                        il::Operand::Reg(SP_REG),
                        il::Operand::Const(0),
                    ])
    }

    /// Only whole halfwords at the end are removed: the `nop` and zero fill.
    fn trim_padding<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        let mut end = bytes.len() - bytes.len() % HALFWORD;
        while end >= HALFWORD && matches!(self.halfword(bytes, end - HALFWORD), Some(0x6500 | 0)) {
            end -= HALFWORD;
        }
        &bytes[..end]
    }

    fn stub_arch(&self) -> Option<&'static dyn Recovery> {
        Some(if self.base.is_big() { &Mips32::BIG } else { &Mips32::LITTLE })
    }

    fn function_address(&self, pointer: u64) -> u64 {
        pointer & !1
    }
}


/// How far back

/// How far back the parts of a table jump may lie.
const TABLE_LOOK_BACK: usize = 16;

/// More cases than any `switch` a compiler turns into one table.
const MOST_CASES: usize = 1024;

/// Read the table behind the jump at `insns[index]`, as GCC writes it:
///
/// ```text
/// sltiu v0, 5            ; read as `sltiu t8, v0, 5`: the number of cases
/// btnez dispatch
/// ...
/// sll   v1, v0, 1
/// la    v0, table        ; read as `addiu v0, pc, table`
/// addu  v1, v0, v1
/// lh    v1, 0(v1)
/// addu  v0, v1           ; read as `addu v0, v0, v1`
/// jrc   v0
/// ```
///
/// Each halfword of the table is the distance from the table to a case,
/// with bit 0 set, as an address of MIPS16e code has. `entry` reads one,
/// and `constant` reads the bound.
fn read_jump_table(
    arch: &Mips16,
    insns: &[Insn],
    index: usize,
    code: &core::ops::Range<u64>,
    entry: &dyn Fn(u64) -> Option<i16>,
) -> Option<JumpTable> {
    let jump = &insns[index];
    if !(is(jump, Opcode::core_jr) || mips16_op(jump) == Some(Op::Jrc))
        || jump.kind != (InsnKind::Jump { target: None })
    {
        return None;
    }
    let target = match operands_of(jump).as_slice() {
        [il::Operand::Reg(target)] => *target,
        _ => return None,
    };
    let (sum_at, sum) = last_write(insns, index, target)?;
    let (left, right) = match operands_of(sum).as_slice() {
        [_, il::Operand::Reg(left), il::Operand::Reg(right)] => (*left, *right),
        _ => return None,
    };
    if !is(sum, Opcode::core_addu) {
        return None;
    }
    let table = [(left, right), (right, left)].into_iter().find_map(|(base, offset)| {
        let (_, load) = last_write(insns, sum_at, offset)?;
        if !is(load, Opcode::core_lh) {
            return None;
        }
        let (_, la) = last_write(insns, sum_at, base)?;
        is(la, Opcode::core_addiu).then(|| arch.address_from_pc(la)).flatten()
    })?;

    // The bound comes before the jump, or before the branch to the block
    // that holds it: GCC can put the dispatch after the code of a case.
    let bound_before = |at: usize| {
        insns[at.saturating_sub(TABLE_LOOK_BACK)..at].iter().rev().find_map(|insn| {
            if !is(insn, Opcode::core_sltiu) {
                return None;
            }
            let bound = match operands_of(insn).as_slice() {
                [_, _, bound] => constant(bound)?,
                _ => return None,
            };
            usize::try_from(bound).ok().filter(|&cases| cases <= MOST_CASES)
        })
    };
    let block = insns[..index]
        .iter()
        .rposition(|insn| insn.kind != InsnKind::Normal)
        .map_or(0, |at| at + 1);
    let guard = insns
        .iter()
        .position(|insn| insn.kind == (InsnKind::Branch { target: Some(insns[block].address) }));
    let bound = bound_before(index).or_else(|| bound_before(guard?))?;
    let targets: Vec<u64> = (0..bound as u64)
        .map_while(|case| {
            let distance = entry(table + case * HALFWORD as u64)?;
            let target = table.wrapping_add_signed(i64::from(distance)) & !1;
            code.contains(&target).then_some(target)
        })
        .collect();
    let words = table..table + (targets.len() * HALFWORD) as u64;
    (targets.len() == bound).then_some(JumpTable { jump: jump.address, words, targets })
}

/// The last instruction before `insns[before]`, and its index, that writes
/// `register`.
fn last_write(insns: &[Insn], before: usize, register: il::Reg) -> Option<(usize, &Insn)> {
    last_write_within(insns, before, register, TABLE_LOOK_BACK)
}

/// [`last_write`], within `distance` instructions.
fn last_write_within(
    insns: &[Insn],
    before: usize,
    register: il::Reg,
    distance: usize,
) -> Option<(usize, &Insn)> {
    let from = before.saturating_sub(distance);
    (from..before).rev().map(|at| (at, &insns[at])).find(|(_, insn)| {
        insn.kind == InsnKind::Normal
            && !super::mips::is_store(insn)
            && first_register(insn) == Some(register)
    })
}

/// The offset and the base of `lw rX, offset(rA)`.
fn load_reference(insn: &Insn) -> Option<(u64, il::Reg)> {
    match operands_of(insn).as_slice() {
        [_, reference] => match access(reference)? {
            (Some(base), offset) => Some((offset, base)),
            _ => None,
        },
        _ => None,
    }
}

/// Report whether a call soon after `insns[index]` goes through `register`.
fn is_called(insns: &[Insn], index: usize, register: il::Reg) -> bool {
    /// GCC puts the `jalr` right after the address it calls, or one
    /// instruction later.
    const MOST_INSTRUCTIONS_TO_CALL: usize = 3;

    insns.iter().skip(index + 1).take(MOST_INSTRUCTIONS_TO_CALL).any(|insn| {
        matches!(insn.kind, InsnKind::Call { target: None })
            && operands_of(insn).last().and_then(super::mips::register) == Some(register)
    })
}

/// Report whether a preamble starts at `insns[at]`.
fn is_gp_preamble_at(insns: &[Insn], at: usize) -> bool {
    insns.get(at..at + GP_PREAMBLE_LENGTH).is_some_and(is_gp_preamble)
}

/// The global pointer that the last preamble before `insns[index]` makes:
/// the upper half it loads, shifted, plus the address it takes from the
/// program counter.
fn global_pointer_before(arch: &Mips16, insns: &[Insn], index: usize) -> Option<u64> {
    let start = (0..index.saturating_sub(GP_PREAMBLE_LENGTH - 1))
        .rev()
        .find(|&at| is_gp_preamble(&insns[at..at + GP_PREAMBLE_LENGTH]))?;
    let preamble = &insns[start..start + GP_PREAMBLE_LENGTH];
    let high = match operands_of(&preamble[0]).as_slice() {
        [_, _, high] => constant(high)?,
        _ => return None,
    };
    let low = arch.address_from_pc(&preamble[1])?;
    let joined = (high as u32).wrapping_shl(16).wrapping_add(low as u32);
    Some(u64::from(joined))
}

/// Report whether `register` holds the global pointer at `insns[before]`:
/// it is `gp`, a copy of it, or what the preamble made.
fn holds_global_pointer(insns: &[Insn], before: usize, register: il::Reg) -> bool {
    /// Copies of copies, as `move gp, v0` then `move s0, gp`.
    const MOST_COPIES: usize = 4;

    let (mut before, mut register) = (before, register);
    for _ in 0..=MOST_COPIES {
        if register == GP {
            return true;
        }
        let Some((at, write)) = last_write_within(insns, before, register, before) else {
            return false;
        };
        let preamble_start = (at + 1).checked_sub(GP_PREAMBLE_LENGTH);
        if preamble_start.is_some_and(|start| is_gp_preamble(&insns[start..=at])) {
            return true;
        }
        match operands_of(write).as_slice() {
            [_, il::Operand::Reg(source), il::Operand::Zero] if is(write, Opcode::core_or) => {
                (before, register) = (at, *source);
            }
            _ => return false,
        }
    }
    false
}

/// The byte order an instruction of MIPS16e was read in.
fn order_of(insn: &Insn) -> super::mips::ByteOrder {
    match insn.opcode {
        super::Opcode::Mips16(_, order) | super::Opcode::Mips(_, order) => order,
        _ => super::mips::ByteOrder::Big,
    }
}

/// The rules that read the addresses MIPS16e forms from `pc` and through
/// the global offset table.
trait AddressRules {
    fn address_from_pc(&self, insn: &Insn) -> Option<u64>;
    fn slot_of(&self, body: &[Insn], load_index: usize, load: &Insn) -> Option<u64>;
    fn addresses_by_index(
        &self,
        body: &[Insn],
        space: &AddressSpace,
        memory: &Memory<'_>,
    ) -> Vec<(usize, u64)>;
}

impl AddressRules for Mips16 {
    /// The address an `addiu rX, pc, imm` forms, from where `insn` is.
    fn address_from_pc(&self, insn: &Insn) -> Option<u64> {
        match self.decoded(insn.bytes(), 0, insn.address)?.reading {
            Reading::PcRelative { load: false, address, .. } => Some(address),
            _ => None,
        }
    }

    /// The slot of the global offset table that the `lw` at `load_index`
    /// of `body` reads through the global pointer or a copy of it.
    fn slot_of(&self, body: &[Insn], load_index: usize, load: &Insn) -> Option<u64> {
        let (offset, base) = load_reference(load)?;
        if !is(load, Opcode::core_lw) || !holds_global_pointer(body, load_index, base) {
            return None;
        }
        let global_pointer = global_pointer_before(self, body, load_index)?;
        Some(u64::from((global_pointer as u32).wrapping_add(offset as u32)))
    }

    /// Each address `body` forms, with the index of the instruction that
    /// forms it: see [`Recovery::data_addresses`].
    fn addresses_by_index(
        &self,
        body: &[Insn],
        space: &AddressSpace,
        memory: &Memory<'_>,
    ) -> Vec<(usize, u64)> {
        let page = |load_at: usize, load: &Insn| {
            let slot = self.slot_of(body, load_at, load)?;
            let bytes = memory.bytes(slot, 4)?;
            Some(self.read_pointer(bytes) as u32)
        };
        body.iter()
            .enumerate()
            .filter(|(_, insn)| is(insn, Opcode::core_addiu))
            .filter_map(|(index, insn)| {
                let operands = operands_of(insn);
                let destination = operands.first().and_then(super::mips::register)?;
                let from_pc = self.address_from_pc(insn);
                let address = match (from_pc, operands.as_slice()) {
                    // `t9` receives a callee, not data.
                    _ if destination == T9 => None,
                    // The preamble's is half of `_gp_disp`, a distance.
                    (Some(_), _) if index > 0 && is_gp_preamble_at(body, index - 1) => None,
                    (Some(address), _) => Some(address),
                    // An address that is called is code, not data.
                    _ if is_called(body, index, destination) => None,
                    (None, [_, il::Operand::Reg(source), low]) => {
                        let (at, written) = last_write(body, index, *source)?;
                        let address = page(at, written)?.wrapping_add(constant(low)? as u32);
                        Some(u64::from(address))
                    }
                    _ => None,
                }?;
                Some((index, address))
            })
            .filter(|&(_, address)| space.contains_formed(address))
            .collect()
    }
}

/// The instructions of [`is_gp_preamble`].
const GP_PREAMBLE_LENGTH: usize = 4;

/// Report whether `body` is the sequence with which MIPS16e PIC computes
/// the global pointer. It has no `t9` to add `_gp_disp` to, as MIPS32 does,
/// so it adds the program counter:
///
/// ```text
/// li    v0, %hi(_gp_disp)       ; read here as `ori v0, zero, ...`
/// addiu v1, pc, %lo(_gp_disp)
/// sll   v0, v0, 16
/// addu  v0, v0, v1
/// ```
///
/// Only the entry of a function runs it.
fn is_gp_preamble(body: &[Insn]) -> bool {
    use il::Operand::{Const, Reg, Zero};
    let [high, low, shift, add] = body else { return false };
    let (Some(loaded), Some(from_pc)) = (first_register(high), first_register(low)) else {
        return false;
    };
    let shape = matches!(operands_of(high).as_slice(), [_, Zero, Const(_)])
        && matches!(operands_of(shift).as_slice(), [Reg(shifted), Reg(source), Const(16)]
            if *shifted == loaded && *source == loaded)
        && matches!(operands_of(add).as_slice(), [_, Reg(left), Reg(right)]
            if [*left, *right].contains(&loaded) && [*left, *right].contains(&from_pc));
    // The `addiu` from the program counter reads as an address, which only
    // the reading tells apart from another `addiu`.
    let low_from_pc = matches!(
        Mips16::of(super::mips::Mips32::of(order_of(low))).decoded(low.bytes(), 0, low.address),
        Some(Read { reading: Reading::PcRelative { load: false, .. }, .. })
    );
    is(high, Opcode::core_ori)
        && is(low, Opcode::core_addiu)
        && is(shift, Opcode::core_sll)
        && is(add, Opcode::core_addu)
        && shape
        && low_from_pc
}

