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

mod decode;
pub use decode::*;

use super::mips::{
    Decoded as MipsDecoded, GP, Mips32, SP_REG, T9, access, constant, decoded, first_register, is,
    operands_of, register_name,
};
use super::{Arch, CallTarget, Decoder, GlobalPointerSetup, Insn, InsnKind, JumpTable, Memory};
use crate::address::{AddressSpace, ConstantKind, Contents};
use crate::il;
use rabbitizer::opcodes::Opcode;

/// The function field of the MIPS32 `addu`.
const ADDU: u32 = 0x21;

fn mips16_op(insn: &Insn) -> Option<Op> {
    match decoded(insn)? {
        MipsDecoded::Mips16(op) => Some(op),
        _ => None,
    }
}

impl Arch for Mips16 {
    fn is_frame_register(&self, reg: il::Reg) -> bool {
        self.base.is_frame_register(reg)
    }

    /// `save` and `restore` make and drop the frame whole.
    fn is_frame_management(&self, insn: &Insn) -> bool {
        matches!(mips16_op(insn), Some(Op::Save | Op::Restore))
            || self.base.is_frame_management(insn)
    }

    /// The text of each instruction is that of MIPS32, so MIPS32 follows
    /// the global pointer through the body. A load or address relative to
    /// the program counter moves with the code, and so does the upper half
    /// of `_gp_disp` that the preamble adds to it.
    fn constant_kinds(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
    ) -> Vec<ConstantKind> {
        // MIPS32 knows the global pointer as `_gp_disp` added to `t9`, the
        // address of the function. MIPS16e adds it to the program counter
        // instead, so its `addu` is given to MIPS32 in the form it knows.
        let preambles: Vec<usize> = (0..body.len())
            .filter(|&index| {
                body.get(index..index + GP_PREAMBLE_LENGTH).is_some_and(is_gp_preamble)
            })
            .collect();
        let mut as_mips32 = body.to_vec();
        for &index in &preambles {
            let add = &mut as_mips32[index + GP_PREAMBLE_LENGTH - 1];
            let destination = self.lift(add).and_then(|lifted| match lifted.operands.first() {
                Some(il::Operand::Reg(il::Reg::General(number))) => Some(u32::from(*number)),
                _ => None,
            });
            // `addu rD, rD, t9`, the MIPS32 instruction that joins the
            // distance to the global pointer.
            let joined = destination.and_then(|rd| {
                // `t9` is register 25.
                let word = register(rd, 25, rd, 0, ADDU);
                self.base.decode(&self.base.word_bytes(word), 0, add.address).ok()
            });
            if let Some(joined) = joined {
                *add = joined;
            }
        }

        let mut kinds = super::mips::constant_kinds_in(self, &as_mips32, space);
        for &index in &preambles {
            kinds[index] = ConstantKind::Address;
        }
        for (index, insn) in body.iter().enumerate() {
            let reading = self.decoded(insn.bytes(), 0, insn.address).map(|found| found.reading);
            if matches!(reading, Some(Reading::PcRelative { .. })) {
                kinds[index] = ConstantKind::Address;
            }
        }
        kinds
    }

    fn contents(&self, _code: &[u8], _insns: &[Insn], _space: &AddressSpace) -> Contents {
        Contents::Code
    }

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

    /// What [`Arch::data_addresses`] finds, and also the slot of the
    /// global offset table each load through the global pointer reads.
    fn formed_addresses(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        memory: &Memory<'_>,
    ) -> Vec<Option<u64>> {
        let mut formed = vec![None; body.len()];
        for (index, address) in self.addresses_by_index(body, space, memory) {
            formed[index] = Some(address);
        }
        for (index, insn) in body.iter().enumerate() {
            if formed[index].is_none()
                && let Some(slot) = self.slot_of(body, index, insn)
            {
                formed[index] = Some(slot);
            }
        }
        formed
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

    fn global_pointer_setup(&self, body: &[Insn]) -> Option<GlobalPointerSetup> {
        let preamble = body.get(..GP_PREAMBLE_LENGTH).filter(|run| is_gp_preamble(run))?;
        let register = register_name(first_register(preamble.last()?)?)?.to_string();
        Some(GlobalPointerSetup { parts: (0..GP_PREAMBLE_LENGTH).collect(), register })
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

    fn stub_arch(&self) -> Option<&'static dyn Arch> {
        Some(if self.base.is_big() { &Mips32::BIG } else { &Mips32::LITTLE })
    }

    fn function_address(&self, pointer: u64) -> u64 {
        pointer & !1
    }
}

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

impl Mips16 {
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
    /// forms it: see [`Arch::data_addresses`].
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The text of the halfwords `values`, big endian, at `address`.
    fn text(values: &[u16], address: u64) -> String {
        let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
        let insn = Mips16::BIG.decode(&code, 0, address).expect("decodes");
        insn.to_string().trim_end().to_string()
    }

    /// The opening of `adler32_combine_` in zlib, by GCC 14 at `-Os`.
    const GP_PREAMBLE: [u16; 7] = [0xf000, 0x6a02, 0xf0a8, 0x0b0c, 0xf400, 0x3240, 0xe269];

    fn decode_all_big(values: &[u16]) -> Vec<Insn> {
        let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
        crate::arch::decode_all(&Mips16::BIG, &code, 0x1540).0
    }

    /// A `switch` of five cases at 0x100, as GCC writes it, then its table
    /// at 0x110 with `entries`.
    fn switch(entries: [u16; 5]) -> Vec<u16> {
        let dispatch = [0x5a05, 0x3344, 0x0a03, 0xe26d, 0x8b60, 0xe269, 0xea80, 0x6500];
        dispatch.into_iter().chain(entries).chain([0x6500; 11]).collect()
    }

    fn tables(values: &[u16]) -> Vec<JumpTable> {
        let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
        let insns = crate::arch::decode_all(&Mips16::BIG, &code, 0x100).0;
        let regions = [(0x100, code.as_slice())];
        let end = 0x100 + code.len() as u64;
        Mips16::BIG.jump_tables(&Memory::new(&regions), 0x100..end, &insns)
    }

    #[test]
    fn a_switch_reads_each_case_from_its_table() {
        let found = tables(&switch([0x000b, 0x000d, 0xfff1, 0x0011, 0x0013]));
        assert_eq!(
            found,
            [JumpTable {
                jump: 0x10c,
                words: 0x110..0x11a,
                targets: vec![0x11a, 0x11c, 0x100, 0x120, 0x122],
            }]
        );
    }

    #[test]
    fn a_table_with_a_case_outside_the_code_is_not_read() {
        assert!(tables(&switch([0x000b, 0x000d, 0x7ff1, 0x0011, 0x0013])).is_empty());
    }

    #[test]
    fn a_table_with_no_bound_is_not_read() {
        let mut values = switch([0x000b, 0x000d, 0xfff1, 0x0011, 0x0013]);
        values[0] = 0x6500;
        assert!(tables(&values).is_empty());
    }

    /// The opening of `luaB_assert` in Lua 5.1, by GCC 14 at `-O2`, up to
    /// its first call, at 0x7de4.
    const CALL_THROUGH_SLOT: [u16; 18] = [
        0xf000, 0x6a03, 0xf0e3, 0x0b08, 0xf400, 0x3240, 0xe269, 0x659a, 0x64f5, 0x671c, 0x6d01,
        0xf450, 0x98ec, 0x6724, 0xd204, 0xef40, 0x653f, 0x6500,
    ];

    #[test]
    fn a_call_through_a_copy_of_gp_names_its_slot() {
        let code: Vec<u8> =
            CALL_THROUGH_SLOT.iter().flat_map(|value| value.to_be_bytes()).collect();
        let insns = crate::arch::decode_all(&Mips16::BIG, &code, 0x7de4).0;
        let global_pointer = 0x3_0000 + 0x96d0;
        let calls = Mips16::BIG.call_targets(&insns);
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert_eq!(calls[0].1, Some(CallTarget::Slot(global_pointer - 31668)));
    }

    #[test]
    fn an_address_from_the_global_offset_table_is_data() {
        // `lw a2, -32708(s0)`, `addiu a2, -5188`, `la a3, ...`, after the
        // preamble of `luaB_assert`.
        let mut values = CALL_THROUGH_SLOT[..11].to_vec();
        values.extend([0xf030, 0x98dc, 0xf3bd, 0x4e1c, 0x0f01]);
        let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
        let insns = crate::arch::decode_all(&Mips16::BIG, &code, 0x7de4).0;
        let slot = 0x3_96d0 - 32708;
        let page = 0x2_0000_u32.to_be_bytes();
        let regions = [(slot, page.as_slice())];
        let la = (insns.last().unwrap().address & !3) + 4;
        let space = AddressSpace::from_ranges([0x7000..0xa000, 0x1_0000..0x4_0000]);

        let found = Mips16::BIG.data_addresses(&code, &insns, &space, &Memory::new(&regions));
        assert_eq!(found, [0x2_0000 - 5188, la], "the preamble's `la` is not data");
    }

    #[test]
    fn a_call_to_a_local_function_names_its_page_and_offset() {
        // `lw v0, -0x7f0c(s0)`, `addiu v0, -0x393f`, `jalr v0`, `move t9, v0`,
        // after the preamble of `luaB_assert`.
        let mut values = CALL_THROUGH_SLOT[..11].to_vec();
        values.extend([0xf0f0, 0x9854, 0xf6d8, 0x4a01, 0xea40, 0x653a]);
        let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
        let insns = crate::arch::decode_all(&Mips16::BIG, &code, 0x7de4).0;
        let offset = (-0x393f_i64) as u64;
        let calls = Mips16::BIG.call_targets(&insns);
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert_eq!(calls[0].1, Some(CallTarget::PageOffset { slot: 0x3_96d0 - 0x7f0c, offset }));

        let space = AddressSpace::from_ranges(core::iter::once(0x0..0x4_0000));
        let page = 0x2_0000_u32.to_be_bytes();
        let regions = [(0x3_96d0 - 0x7f0c, page.as_slice())];
        let data = Mips16::BIG.data_addresses(&code, &insns, &space, &Memory::new(&regions));
        assert!(data.is_empty(), "a callee is not data: {data:#x?}");
    }

    #[test]
    fn a_call_through_a_register_from_elsewhere_names_nothing() {
        let mut values = CALL_THROUGH_SLOT;
        // `move s0, a0` in place of `move s0, gp`.
        values[9] = 0x6704;
        let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
        let insns = crate::arch::decode_all(&Mips16::BIG, &code, 0x7de4).0;
        let calls = Mips16::BIG.call_targets(&insns);
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert_eq!(calls[0].1, None);
    }

    #[test]
    fn the_gp_preamble_opens_a_function() {
        let insns = decode_all_big(&GP_PREAMBLE);
        assert_eq!(insns.len(), 4);
        assert!(Mips16::BIG.is_function_entry(&insns));
        assert_eq!(Mips16::BIG.preamble_before_prologue(&insns), 4);
        assert_eq!(Mips16::BIG.preamble_before_prologue(&insns[1..]), 0);
        assert!(!Mips16::BIG.is_function_entry(&insns[..3]));
        assert!(!Mips16::BIG.is_function_entry(&insns[1..]));
    }

    #[test]
    fn a_constant_built_elsewhere_is_no_gp_preamble() {
        // `li v0, 2`, `sll v0, v0, 16`: no program counter joins it.
        let insns = decode_all_big(&[0x6a02, 0x3240, 0x3240, 0xe269]);
        assert!(!Mips16::BIG.is_function_entry(&insns));
        assert_eq!(Mips16::BIG.preamble_before_prologue(&insns), 0);
    }

    /// Words from GCC 14 at `-mips16`, as `objdump` reads them.
    #[test]
    fn reads_as_the_mips32_instruction_of_the_same_work() {
        assert_eq!(text(&[0x3382], 0), "srl v1, a0, 8"); // srl v1,a0,8
        assert_eq!(text(&[0x3362], 0), "srl v1, v1, 8"); // srl v1,8
        assert_eq!(text(&[0x6744], 0), "or v0, a0, zero"); // move v0,a0
        assert_eq!(text(&[0x653b], 0), "or t9, v1, zero"); // move t9,v1
        assert_eq!(text(&[0xd303], 0), "sw v1, 0xC(sp)"); // sw v1,12(sp)
        assert_eq!(text(&[0xa460], 0), "lbu v1, 0x0(a0)"); // lbu v1,0(a0)
        assert_eq!(text(&[0x4c10], 0), "addiu a0, a0, 0x10"); // addiu a0,16
        assert_eq!(text(&[0xe34d], 0), "addu v1, v1, v0"); // addu v1,v0
        assert_eq!(text(&[0x6500], 0), "nop");
    }

    #[test]
    fn an_extend_widens_the_constant() {
        // addiu v1,a1,5552
        assert_eq!(text(&[0xf5b2, 0x4560], 0), "addiu v1, a1, 0x15B0");
        // lbu s1,-6(a0)
        assert_eq!(text(&[0xf7ff, 0xa43a], 0), "lbu s1, -0x6(a0)");
        // addiu a1,-5552
        assert_eq!(text(&[0xf25d, 0x4d10], 0), "addiu a1, a1, -0x15B0");
    }

    #[test]
    fn a_compare_writes_t8_and_a_branch_on_t_reads_it() {
        assert_eq!(text(&[0x7601], 0), "xori t8, a2, 0x1"); // cmpi a2,1
        assert_eq!(text(&[0x5e10], 0), "sltiu t8, a2, 0x10"); // sltiu a2,16
        // bteqz 198 at 0xe
        let code: Vec<u8> =
            [0xf0c0_u16, 0x6003].iter().flat_map(|value| value.to_be_bytes()).collect();
        let insn = Mips16::BIG.decode(&code, 0, 0xe).expect("decodes");
        assert_eq!(insn.kind, InsnKind::Branch { target: Some(0x198) });
        assert_eq!(crate::arch::printed_name(&insn), "beqz");
        assert!(crate::arch::printed_operands(&insn).starts_with("t8, "));
    }

    #[test]
    fn a_branch_counts_from_the_instruction_after_it() {
        // beqz a1,2fa at 0x12, extended
        let code: Vec<u8> =
            [0xf160_u16, 0x2512].iter().flat_map(|value| value.to_be_bytes()).collect();
        let insn = Mips16::BIG.decode(&code, 0, 0x12).expect("decodes");
        assert_eq!(insn.kind, InsnKind::Branch { target: Some(0x2fa) });
        assert_eq!(insn.bytes_len, 4);
    }

    #[test]
    fn save_and_restore_make_and_drop_the_frame() {
        assert_eq!(text(&[0x64b4], 0), "save 0x20, s0, s1"); // save 32,s0-s1
        let code = 0x64b4_u16.to_be_bytes();
        let insn = Mips16::BIG.decode(&code, 0, 0).expect("decodes");
        assert!(Mips16::BIG.is_frame_management(&insn));
        assert!(Mips16::BIG.is_prologue(&insn));
    }

    /// Each encoding as GNU `as` 2.44 assembles the `binutils` text.
    #[test]
    fn save_and_restore_name_the_registers_they_move() {
        let cases: [(&[u16], &str, &str); 15] = [
            (&[0x64f4], "save 32,ra,s0-s1", "save 0x20, s0, s1, ra"),
            (&[0xf004, 0x64c4], "save a0,32,ra", "save a0, 0x20, ra"),
            (&[0xf001, 0x64c4], "save 32,ra,a3", "save 0x20, a3, ra"),
            (&[0xf005, 0x64c4], "save a0,32,ra,a3", "save a0, 0x20, a3, ra"),
            (&[0xf008, 0x64c4], "save a0-a1,32,ra", "save a0, a1, 0x20, ra"),
            (&[0xf009, 0x64c4], "save a0-a1,32,ra,a3", "save a0, a1, 0x20, a3, ra"),
            (&[0xf00c, 0x64c4], "save a0-a2,32,ra", "save a0, a1, a2, 0x20, ra"),
            (&[0xf00e, 0x64c4], "save a0-a3,32,ra", "save a0, a1, a2, a3, 0x20, ra"),
            (&[0xf00b, 0x64c4], "save 32,ra,a0-a3", "save 0x20, a0, a1, a2, a3, ra"),
            (&[0xf002, 0x64c4], "save 32,ra,a2-a3", "save 0x20, a2, a3, ra"),
            (&[0xf003, 0x64c4], "save 32,ra,a1-a3", "save 0x20, a1, a2, a3, ra"),
            (&[0xf006, 0x64c4], "save a0,32,ra,a2-a3", "save a0, 0x20, a2, a3, ra"),
            (
                &[0xf700, 0x64f4],
                "save 32,ra,s0-s8",
                "save 0x20, s0, s1, s2, s3, s4, s5, s6, s7, s8, ra",
            ),
            (&[0xf100, 0x64f4], "save 32,ra,s0-s2", "save 0x20, s0, s1, s2, ra"),
            (&[0xf002, 0x6474], "restore 32,ra,s0-s1,a2-a3", "restore 0x20, a2, a3, s0, s1, ra"),
        ];
        for (halfwords, binutils, shown) in cases {
            assert_eq!(text(halfwords, 0), shown, "{binutils}");
        }
    }

    #[test]
    fn a_reserved_mix_of_arguments_and_statics_is_no_save() {
        // `aregs` 0b1111 names three arguments and three statics of four.
        let code: Vec<u8> = [0xf00f_u16, 0x64c4].iter().flat_map(|h| h.to_be_bytes()).collect();
        assert_eq!(
            Mips16::BIG.decode(&code, 0, 0).map(|insn| insn.kind).ok(),
            Some(InsnKind::Unknown)
        );
    }

    #[test]
    fn a_return_and_a_call_move_control() {
        let decode = |values: &[u16]| {
            let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
            Mips16::BIG.decode(&code, 0, 0x400).expect("decodes")
        };
        let jr_ra = decode(&[0xe820]);
        assert_eq!(jr_ra.kind, InsnKind::Return);
        assert_eq!(Mips16::BIG.delay_slots(&jr_ra), 1);
        let jrc_ra = decode(&[0xe8a0]);
        assert_eq!(jrc_ra.kind, InsnKind::Return);
        assert_eq!(Mips16::BIG.delay_slots(&jrc_ra), 0);
        // jal to 0x1000, which stays MIPS16e
        let jal = decode(&[0x1800, 0x0400]);
        assert_eq!(jal.kind, InsnKind::Call { target: Some(0x1000) });
        assert_eq!(jal.bytes_len, 4);
    }

    #[test]
    fn a_compare_and_its_branch_lift_as_a_guard() {
        let lift = |values: &[u16], address: u64| {
            let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
            let insn = Mips16::BIG.decode(&code, 0, address).expect("decodes");
            Some(Mips16::BIG.lift(&insn).expect("lifts"))
        };
        // sltiu a2,16 then btnez
        let body = [lift(&[0x5e10], 0), lift(&[0x6105], 2)];
        let guards = il::find_guards(&body);
        assert_eq!(guards.len(), 1);
    }

    #[test]
    fn decoding_any_halfwords_never_panics() {
        bolero::check!().with_type::<(u16, u16)>().for_each(|&(first, second)| {
            let code: Vec<u8> =
                [first, second].iter().flat_map(|value| value.to_be_bytes()).collect();
            for arch in [Mips16::BIG, Mips16::LITTLE] {
                let insn = arch.decode(&code, 0, 0x1000).expect("two halfwords decode");
                assert!(insn.bytes_len == 2 || insn.bytes_len == 4);
                let _ = arch.lift(&insn);
            }
        });
    }
}
