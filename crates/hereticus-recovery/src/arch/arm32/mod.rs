//! ARM32 (A32) decoding, on top of `yaxpeax-arm`.
//!
//! Two details of the `yaxpeax` API are easy to get wrong, so this module
//! handles both and the rest of `hereticus` never sees them:
//!
//! 1. `U8Reader` implements `Reader<u32, U32le>`, not `Reader<u32, u32>`.
//! 2. `total_offset()` counts **words**, not bytes. Multiplying by the
//!    instruction width is what makes reported addresses right.

pub use hereticus_il::arch::arm32::*;

use super::{DataAmongCode, Decoder, Insn, InsnKind, JumpTable, Memory, Recovery};
use crate::address::{AddressSpace, ConstantKind, Contents};
use hereticus_il as il;
use core::ops::Range;
use std::collections::BTreeSet;
use yaxpeax_arm::armv7::{ConditionCode, Opcode};

/// A pool word, or a pointer, is 4 bytes wide.
const WORD_WIDTH: usize = 4;

/// The section holding the ARM exception index.
///
/// One entry a function, each naming where that function starts. It survives
/// stripping, so it is the strongest source of function boundaries there is.
pub(super) const UNWIND_SECTION: &str = ".ARM.exidx";

/// The A32 `nop` encoding, little endian.
const NOP_BYTES: [u8; 4] = [0x00, 0xf0, 0x20, 0xe3];

/// Zero words, which some linkers pad with instead.
const ZERO_BYTES: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

/// The frame pointer, as the A32 procedure call standard names it.
const FRAME: il::Reg = il::Reg::General(11);

/// An A32 instruction with the opcode `name` has, for a test that writes
/// instructions by hand. It holds no bytes, so it lifts to nothing.

/// The program counter, as an operand names it.
const PC_OPERAND: il::Operand = il::Operand::Reg(il::Reg::ProgramCounter);

/// The link register, which a function that calls another saves first.
const LR: il::Reg = il::Reg::General(14);

/// Whether `insn` does `opcode` always and keeps the flags: the plain form,
/// as `add` and not `addeq` or `adds`.
pub(super) fn is_plain(insn: &Insn, opcode: Opcode) -> bool {
    decoded(insn)
        == Some(Decoded::Core { opcode, condition: ConditionCode::AL, flags: Flags::Kept })
}

impl Recovery for Arm32 {
    /// The first instruction of a function runs always, as almost every
    /// A32 instruction does: its top four bits are `0xE`.
    fn can_open_function(&self, bytes: &[u8]) -> bool {
        bytes.get(..INSN_WIDTH).is_some_and(|word| word[3] >> 4 == 0xe)
    }

    /// A function that calls anything must save the link register first, so
    /// `push {..., lr}` is how almost every non-leaf ARM function begins.
    /// Measured on a stripped kernel object, every real function start matched
    /// this and nothing else did.
    ///
    /// A leaf function has no prologue at all, which is why the scanner treats
    /// this as one source among several.
    fn is_prologue(&self, insn: &Insn) -> bool {
        matches!(core_opcode(insn), Some(Opcode::PUSH | Opcode::STM(..)))
            && lifted(insn).is_some_and(|lifted| {
                // `push {lr}` alone is `str lr, [sp, #-4]!`, which names it
                // as one register.
                lifted.operands.iter().any(|operand| match operand {
                    il::Operand::RegisterList(list) => list.contains(LR),
                    il::Operand::Reg(reg) => *reg == LR,
                    _ => false,
                })
            })
    }

    /// The `nop` hint, which [`decode_fallback`] reads where `yaxpeax-arm`
    /// 0.4 does not, or the word of it or of zeros that no decoder reads. A
    /// core before ARMv6K has no such hint, so GCC pads with `mov r0, r0`
    /// there. A word of data that holds zero is no padding.
    fn is_padding(&self, insn: &Insn) -> bool {
        const R0: il::Operand = il::Operand::Reg(il::Reg::General(0));
        let moves_r0_to_itself =
            || lifted(insn).is_some_and(|lifted| lifted.operands.as_slice() == [R0, R0]);
        core_opcode(insn) == Some(Opcode::NOP)
            || (is_plain(insn, Opcode::MOV) && moves_r0_to_itself())
            || (insn.kind == InsnKind::Unknown
                && insn.opcode != super::Opcode::Data
                && (insn.bytes() == NOP_BYTES || insn.bytes() == ZERO_BYTES))
    }

    /// Only whole words at the end are removed, and only the two encodings a
    /// linker pads with.
    fn trim_padding<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        let mut end = bytes.len();
        while end >= INSN_WIDTH {
            let word = &bytes[end - INSN_WIDTH..end];
            if word == NOP_BYTES || word == ZERO_BYTES {
                end -= INSN_WIDTH;
            } else {
                break;
            }
        }

        &bytes[..end]
    }

    /// The addresses [`Recovery::constant_kinds`] finds formed, and the pool
    /// words that hold an address whole, as non-PIC code keeps them.
    fn data_addresses(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        _memory: &Memory<'_>,
    ) -> Vec<u64> {
        track_pool_words(code, body, space, PcModel::A32).addresses
    }

    /// `bx` through a register other than `lr`. A `switch` jumps with `add pc`
    /// or `ldr pc` instead.
    fn is_tail_call(&self, insn: &Insn) -> bool {
        is_plain(insn, Opcode::BX) && insn.kind == (InsnKind::Jump { target: None })
    }

    /// A variadic function reserves room for its register arguments before it
    /// saves anything, so `sub sp, sp, #N` opens it one word before the
    /// `push`. Measured on Lua built as an ARM shared library: without this,
    /// `lua_pushfstring`, `luaG_runerror` and `luaO_pushfstring` each left a
    /// one-word fragment that no release could pair.
    fn preamble_before_prologue(&self, earlier: &[Insn]) -> usize {
        let Some(last) = earlier.last() else { return 0 };
        const SP: il::Operand = il::Operand::Reg(il::Reg::Stack);
        let reserves_stack = core_opcode(last) == Some(Opcode::SUB)
            && lifted(last).is_some_and(|lifted| lifted.operands.starts_with(&[SP, SP]));
        usize::from(reserves_stack)
    }

    /// A function opens unconditionally: nothing has set the flags a
    /// condition would test. Words of a pool mostly decode as conditional
    /// instructions, `0x00000000` as `andeq`. Measured on `factorial` in the
    /// `-O2` fixture, the constants `vld1` loads after the return otherwise
    /// started a function.
    fn may_open_function(&self, word: &[u8]) -> bool {
        word.get(3).is_some_and(|&top| top >= 0xe0)
    }

    fn data_among_code(&self) -> DataAmongCode {
        DataAmongCode::LiteralPools
    }

    /// `ldr rX, [pc, imm]` loads one pool word, and `ldrd` and `vldr` two.
    fn literal_pool_words(&self, insns: &[Insn]) -> Vec<u64> {
        pool_words_loaded(insns, PcModel::A32)
    }

    fn is_unread_extension(&self, insn: &Insn) -> bool {
        decoded(insn) == Some(Decoded::NeonData)
    }

    /// See [`is_long_thunk`].
    fn is_function_entry(&self, body: &[Insn]) -> bool {
        is_long_thunk(body)
    }

    fn call_targets(&self, insns: &[Insn]) -> Vec<(usize, Option<super::CallTarget>)> {
        call_targets_through_thunks(insns, PcModel::A32)
    }

    /// The table GCC emits for a `switch` in PIC code:
    ///
    /// ```text
    /// adr  r1, table             ; r1 = the address of the table
    /// ldr  r0, [r1, r0, lsl 2]   ; an offset from the table to one case
    /// add  pc, r1, r0
    /// ```
    ///
    /// The cases follow the table, so it ends where the first case starts.
    fn jump_tables(&self, memory: &Memory<'_>, code: Range<u64>, insns: &[Insn]) -> Vec<JumpTable> {
        insns
            .iter()
            .enumerate()
            .filter_map(|(index, jump)| read_jump_table(memory, &code, &insns[..index], jump))
            .collect()
    }

    /// The stub LLD and GNU `ld` write for each PLT entry:
    ///
    /// ```text
    /// add ip, pc, imm        ; the decoder writes `adr ip, pc, imm`
    /// add ip, ip, imm
    /// ldr pc, [ip, imm]!
    /// ```
    ///
    /// The slot is the sum, from `pc`, which reads two words ahead.
    fn stub_slot(&self, code: &[u8], address: u64) -> Option<u64> {
        const PC_AHEAD: u64 = 8;

        // The scan asks at the target of every jump, so a first word that is
        // no `adr` ends the question before the rest decode.
        if !is_plain(&self.decode(code, 0, address).ok()?, Opcode::ADR) {
            return None;
        }
        let (insns, _) = super::decode_all(self, code.get(..3 * INSN_WIDTH)?, address);
        let [first, second, third] = insns.as_slice() else { return None };
        const IP: il::Operand = il::Operand::Reg(il::Reg::General(12));
        const PC: il::Operand = il::Operand::Reg(il::Reg::ProgramCounter);
        let operands = |insn: &Insn| self.lift(insn).map(|lifted| lifted.operands);
        // `add ip, pc, #high`; `add ip, ip, #middle`; `ldr pc, [ip, #low]!`.
        let high = match operands(first)?.as_slice() {
            [IP, PC, il::Operand::Const(high)] => *high,
            _ => return None,
        };
        let middle = match operands(second)?.as_slice() {
            [IP, IP, il::Operand::Const(middle)] => *middle,
            _ => return None,
        };
        let low = match operands(third)?.as_slice() {
            [
                PC,
                il::Operand::Memory {
                    base: Some(il::Reg::General(12)),
                    offset: Some(low @ 0..),
                    index: None,
                    update: il::Update::Before,
                },
            ] => *low as u64,
            _ => return None,
        };
        let shape = is_plain(first, Opcode::ADR)
            && is_plain(second, Opcode::ADD)
            && is_plain(third, Opcode::LDR);
        shape.then(|| address + PC_AHEAD + high + middle + low)
    }

    fn unwind_section(&self) -> Option<&'static str> {
        Some(UNWIND_SECTION)
    }
}


/// Read the table behind

/// Read the table behind `add pc, rB, rX`, where `earlier` holds the
/// instructions before the jump.
fn read_jump_table(
    memory: &Memory<'_>,
    code: &Range<u64>,
    earlier: &[Insn],
    jump: &Insn,
) -> Option<JumpTable> {
    /// How far back the load of the table and its address may be. GCC puts
    /// them right before the jump, but can move other work between.
    const LOOK_BACK: usize = 16;
    /// More cases than any `switch` a compiler turns into one table.
    const MOST_CASES: usize = 1024;

    if let Some(table) = read_branch_table(memory, code, jump) {
        return Some(table);
    }
    if let Some(table) = read_offset_table(memory, code, earlier, jump) {
        return Some(table);
    }
    if !is_plain(jump, Opcode::ADD) || jump.kind != (InsnKind::Jump { target: None }) {
        return None;
    }
    let operands = |insn: &Insn| lifted(insn).map(|lifted| lifted.operands).unwrap_or_default();
    // `add pc, rB, rX`.
    let (table_register, offset_register) = match operands(jump).as_slice() {
        [
            il::Operand::Reg(il::Reg::ProgramCounter),
            il::Operand::Reg(table),
            il::Operand::Reg(offset),
        ] => (*table, *offset),
        _ => return None,
    };

    // The last instruction to write a register, or `None` past the window.
    let last_write = |register: il::Reg| {
        earlier
            .iter()
            .rev()
            .take(LOOK_BACK)
            .find(|insn| operands(insn).first() == Some(&il::Operand::Reg(register)))
    };

    // `ldr rX, [rB, rI, lsl 2]`: one word of the table.
    let load = last_write(offset_register)?;
    let reads_the_table = matches!(
        operands(load).as_slice(),
        [_, il::Operand::Memory { base: Some(base), offset: None, index: Some((_, 2)), update: il::Update::None }]
            if *base == table_register
    );
    if !is_plain(load, Opcode::LDR) || !reads_the_table {
        return None;
    }

    // `adr rB, pc, imm`: the address of the table.
    let address = last_write(table_register)?;
    let immediate = match operands(address).as_slice() {
        [_, il::Operand::Reg(il::Reg::ProgramCounter), il::Operand::Const(immediate)] => *immediate,
        _ => return None,
    };
    if !is_plain(address, Opcode::ADR) {
        return None;
    }
    let table = address.address.checked_add(8)?.checked_add(immediate)?;

    let (base, end) = (code.start, code.end);
    let mut targets = Vec::new();
    let mut first_case = end;
    let mut word = table;
    while word < first_case && targets.len() < MOST_CASES {
        // The end of the section ends the table.
        let Some(bytes) = memory.bytes(word, INSN_WIDTH) else { break };
        let delta = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let target = table.checked_add_signed(i64::from(delta))?;
        // A case lies inside the code, on a whole word, and outside the
        // table. It can lie before the table: GCC sends a case with no code
        // of its own back to the shared exit before the jump.
        let in_table = (table..word + INSN_WIDTH as u64).contains(&target);
        if in_table || target < base || target >= end || !target.is_multiple_of(INSN_WIDTH as u64) {
            break;
        }
        if target > word {
            first_case = first_case.min(target);
        }
        targets.push(target);
        word += INSN_WIDTH as u64;
    }

    (!targets.is_empty()).then_some(JumpTable { jump: jump.address, words: table..word, targets })
}

/// Read the table GCC emits for a `switch`: the jump adds the case number,
/// times four, to `pc`, which reads two words ahead, so it lands on one of
/// the `b` instructions that follow it.
///
/// ```text
/// cmp    r3, 5
/// addls  pc, pc, r3, lsl 2
/// b      default
/// b      case_0
/// b      case_1
/// ```
///
/// The table is code, so it names no data words.
fn read_branch_table(memory: &Memory<'_>, code: &Range<u64>, jump: &Insn) -> Option<JumpTable> {
    /// More cases than any `switch` a compiler turns into one table.
    const MOST_CASES: usize = 1024;

    let is_jump =
        matches!(jump.kind, InsnKind::Jump { target: None } | InsnKind::Branch { target: None });
    // `add pc, pc, rX, lsl #2`.
    let shape = lifted(jump).is_some_and(|lifted| {
        matches!(
            lifted.operands.as_slice(),
            [
                PC_OPERAND,
                PC_OPERAND,
                il::Operand::Shifted { shift: il::Shift::Left, amount: 2, .. }
            ]
        )
    });
    if core_opcode(jump) != Some(Opcode::ADD) || !is_jump || !shape {
        return None;
    }

    let mut targets = Vec::new();
    let mut entry = jump.address + INSN_WIDTH as u64;
    while targets.len() < MOST_CASES && code.contains(&entry) {
        let Some(bytes) = memory.bytes(entry, INSN_WIDTH) else { break };
        let Ok(insn) = Arm32.decode(bytes, 0, entry) else { break };
        match insn.kind {
            InsnKind::Jump { target: Some(target) } if code.contains(&target) => {
                targets.push(target)
            }
            _ => break,
        }
        entry += INSN_WIDTH as u64;
    }

    (!targets.is_empty()).then_some(JumpTable { jump: jump.address, words: entry..entry, targets })
}

/// Read the compressed table GCC emits for a `switch`: each case is a byte,
/// or a halfword, that says how many words past the jump it starts.
///
/// ```text
/// ldr    ip, [pc, imm]     ; the table, from here
/// add    ip, pc, ip
/// cmp    r3, 3             ; four cases
/// bhi    default
/// ldrb   r3, [ip, r3]
/// add    pc, pc, r3, lsl 2
/// ```
///
/// Measured on Lua built by GCC for ARM, `luaK_storevar` jumps this way, and
/// its cases after the first return read as functions of their own.
fn read_offset_table(
    memory: &Memory<'_>,
    code: &Range<u64>,
    earlier: &[Insn],
    jump: &Insn,
) -> Option<JumpTable> {
    const LOOK_BACK: usize = 16;
    /// How far back the table's address may be made. A `switch` in a loop
    /// has it made once, before the loop: Lua's `sweeplist` for ARM makes it
    /// 24 instructions before the jump.
    const TABLE_LOOK_BACK: usize = 128;
    const PC_AHEAD: u64 = 8;

    let is_jump =
        matches!(jump.kind, InsnKind::Jump { target: None } | InsnKind::Branch { target: None });
    if core_opcode(jump) != Some(Opcode::ADD) || !is_jump {
        return None;
    }
    let operands = |insn: &Insn| lifted(insn).map(|lifted| lifted.operands).unwrap_or_default();
    // `add pc, pc, rX, lsl #2`.
    let offset_register = match operands(jump).as_slice() {
        [
            PC_OPERAND,
            PC_OPERAND,
            il::Operand::Shifted { reg, shift: il::Shift::Left, amount: 2 },
        ] => *reg,
        _ => return None,
    };

    let window = || earlier.iter().rev().take(LOOK_BACK);
    // A compare names `r0` first but writes nothing, so it is no write.
    let writes = |insn: &Insn, register: il::Reg| {
        writes_first_operand(insn) && operands(insn).first() == Some(&il::Operand::Reg(register))
    };
    let last_write = |register: il::Reg| window().find(|insn| writes(insn, register));

    // `ldrb rX, [rB, rI]`: one entry of the table.
    let load = last_write(offset_register)?;
    let width = match core_opcode(load)? {
        Opcode::LDRB => 1,
        Opcode::LDRH => 2,
        _ => return None,
    };
    let (table_register, index_register) = match operands(load).as_slice() {
        [
            _,
            il::Operand::Memory {
                base: Some(base),
                offset: None,
                index: Some((index, 0)),
                update: il::Update::None,
            },
        ] => (*base, *index),
        _ => return None,
    };

    // The table's address: `ldr rB, [pc, imm]` then `add rB, pc, rB`.
    // It is made before the load, which can write the same register, as
    // `ldrb lr, [lr, r1]` in Lua's `intarith` for ARM does.
    let add = earlier
        .iter()
        .rev()
        .skip_while(|insn| insn.address >= load.address)
        .take(TABLE_LOOK_BACK)
        .find(|insn| writes(insn, table_register))?;
    let table_operand = il::Operand::Reg(table_register);
    if core_opcode(add) != Some(Opcode::ADD)
        || operands(add).as_slice() != [table_operand, PC_OPERAND, table_operand]
    {
        return None;
    }
    let pool_load = earlier
        .iter()
        .rev()
        .skip_while(|insn| insn.address >= add.address)
        .take(LOOK_BACK)
        .find(|insn| writes(insn, table_register))?;
    let pool_offset = match operands(pool_load).as_slice() {
        [
            _,
            il::Operand::Memory {
                base: Some(il::Reg::ProgramCounter),
                offset: Some(offset),
                index: None,
                update: il::Update::None,
            },
        ] => *offset,
        _ => return None,
    };
    let pool = pool_load.address.checked_add(PC_AHEAD)?.checked_add_signed(pool_offset)?;
    let pool_word = memory.bytes(pool, INSN_WIDTH)?;
    let distance = u32::from_le_bytes([pool_word[0], pool_word[1], pool_word[2], pool_word[3]]);
    let table = (add.address + PC_AHEAD).wrapping_add(u64::from(distance)) & 0xffff_ffff;

    // `cmp rI, n` bounds the case number, so there are n + 1 cases.
    let compare = window()
        .filter(|insn| core_opcode(insn) == Some(Opcode::CMP))
        .map(operands)
        .find(|compared| compared.first() == Some(&il::Operand::Reg(index_register)))?;
    let [_, il::Operand::Const(last_case)] = compare.as_slice() else { return None };
    let last_case = *last_case;
    let cases = usize::try_from(last_case).ok()?.checked_add(1).filter(|&cases| cases <= 1024)?;

    let base = jump.address + PC_AHEAD;
    let mut targets = Vec::with_capacity(cases);
    for case in 0..cases {
        let bytes = memory.bytes(table + (case * width) as u64, width)?;
        let entry = if width == 1 {
            u64::from(bytes[0])
        } else {
            u64::from(u16::from_le_bytes([bytes[0], bytes[1]]))
        };
        let target = base + entry * INSN_WIDTH as u64;
        if !code.contains(&target) {
            return None;
        }
        targets.push(target);
    }
    let words = table..table + (cases * width) as u64;
    Some(JumpTable { jump: jump.address, words, targets })
}

/// How `pc` reads in one instruction set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PcModel {
    /// How far past an instruction `pc` reads.
    ahead: u64,
    /// Whether a load from `[pc, imm]` rounds `pc` down to a word first.
    aligns_literal_loads: Alignment,
}

/// Whether an address rounds down to a word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Alignment {
    AsIs,
    ToWord,
}

impl PcModel {
    /// A32: `pc` reads two instructions, 8 bytes, ahead.
    pub(super) const A32: Self = Self { ahead: 8, aligns_literal_loads: Alignment::AsIs };
    /// T32: `pc` reads 4 bytes ahead, and a literal load rounds it down to a
    /// word.
    pub(super) const T32: Self = Self { ahead: 4, aligns_literal_loads: Alignment::ToWord };

    /// What `pc` reads in the instruction at `address`.
    pub(super) fn of(self, address: u64) -> u64 {
        address.wrapping_add(self.ahead)
    }

    /// What `pc` reads in a load from `[pc, imm]` at `address`.
    pub(super) fn of_literal_load(self, address: u64) -> u64 {
        match self.aligns_literal_loads {
            Alignment::AsIs => self.of(address),
            Alignment::ToWord => self.of(address) & !3,
        }
    }
}

/// Whether `body` opens with LLD's range extension thunk, a function by
/// itself:
///
/// ```text
/// movw ip, lo
/// movt ip, hi
/// add  ip, pc         ; A32 writes `add ip, ip, pc`
/// bx   ip
/// ```
///
/// A thunk that nothing in this build calls still starts there, and a run of
/// them otherwise reads as one function. A library that mixes A32 and
/// Thumb-2 holds both kinds.
pub(super) fn is_long_thunk(body: &[Insn]) -> bool {
    long_thunk_halves(body).is_some()
}

/// The two halves a long thunk moves into `ip`: `movw ip, #low`, `movt ip,
/// #high`, `add ip, pc` or `add ip, ip, pc`, then `bx ip`.
fn long_thunk_halves(body: &[Insn]) -> Option<(u64, u64)> {
    const IP: il::Operand = il::Operand::Reg(il::Reg::General(12));
    let [movw, movt, add, bx, ..] = body else { return None };
    let operands = |insn: &Insn| lifted(insn).map(|lifted| lifted.operands).unwrap_or_default();
    let shape = is_plain(movw, Opcode::MOV)
        && is_plain(movt, Opcode::MOVT)
        && is_plain(add, Opcode::ADD)
        && matches!(operands(add).as_slice(), [IP, PC_OPERAND] | [IP, IP, PC_OPERAND])
        && is_plain(bx, Opcode::BX)
        && operands(bx).as_slice() == [IP];
    match (shape, operands(movw).as_slice(), operands(movt).as_slice()) {
        (true, [IP, il::Operand::Const(low)], [IP, il::Operand::Const(high)]) => {
            Some((*low, *high))
        }
        _ => None,
    }
}

fn long_thunk_target(body: &[Insn], pc: PcModel) -> Option<u64> {
    let (low, high) = long_thunk_halves(body)?;
    let distance = (high << 16 | low) as u32;
    let pc = pc.of(body[2].address) as u32;
    Some(u64::from(pc.wrapping_add(distance) & !1))
}

/// The calls of `insns`, the tail calls, and the jump of a range extension
/// thunk to where it formed. See [`super::Recovery::call_targets`].
pub(super) fn call_targets_through_thunks(
    insns: &[Insn],
    pc: PcModel,
) -> Vec<(usize, Option<super::CallTarget>)> {
    insns
        .iter()
        .enumerate()
        .filter_map(|(index, insn)| match insn.kind {
            InsnKind::Call { target } => Some((index, target.map(super::CallTarget::Address))),
            InsnKind::Jump { target: Some(target) } if super::leaves(insns, target) => {
                Some((index, Some(super::CallTarget::Address(target))))
            }
            InsnKind::Jump { target: None } if index >= 3 => {
                long_thunk_target(&insns[index - 3..], pc)
                    .map(|target| (index, Some(super::CallTarget::Address(target))))
            }
            _ => None,
        })
        .collect()
}

/// The addresses of the pool words `insns` load, where `pc` reads as `pc` says.
pub(super) fn pool_words_loaded(insns: &[Insn], pc: PcModel) -> Vec<u64> {
    pool_loads(insns, pc).into_iter().map(|(_, word)| word).collect()
}

/// Each instruction of `insns` that loads from a literal pool, as its
/// address and the address of a word it loads.
pub(super) fn pool_loads(insns: &[Insn], pc: PcModel) -> Vec<(u64, u64)> {
    let mut loads = Vec::new();
    for insn in insns {
        let is_load = matches!(
            decoded(insn),
            Some(
                Decoded::Core { opcode: Opcode::LDR | Opcode::LDRD, .. }
                    | Decoded::Vfp { vfp: Vfp::Load, .. }
            )
        );
        let Some(lifted) = is_load.then(|| lifted(insn)).flatten() else { continue };
        // `ldr` and a `vldr` of a single read one word, and `ldrd` and a
        // `vldr` of a double two.
        let count = match decoded(insn) {
            Some(Decoded::Core { opcode: Opcode::LDRD, .. }) => 2,
            Some(Decoded::Vfp { .. }) => {
                let width = lifted.memory.and_then(|access| access.width);
                if width == Some(il::Width::Bits64) { 2 } else { 1 }
            }
            _ => 1,
        };
        let Some(offset) = lifted.operands.iter().rev().find_map(|operand| match operand {
            il::Operand::Memory {
                base: Some(il::Reg::ProgramCounter),
                offset: Some(offset),
                index: None,
                ..
            } => Some(*offset),
            _ => None,
        }) else {
            continue;
        };
        let pool = pc.of_literal_load(insn.address).wrapping_add(offset as u64);
        loads.extend(
            (0..count).map(|word| (insn.address, pool.wrapping_add(word * WORD_WIDTH as u64))),
        );
    }
    loads
}

/// What reading a function for its pool words found.
pub(super) struct PoolWords {
    /// See [`Recovery::constant_kinds`].
    pub(super) kinds: Vec<ConstantKind>,
    /// The addresses inside the image the function forms or loads whole.
    pub(super) addresses: Vec<u64>,
    /// The address each instruction forms or reads, where one does.
    pub(super) formed: Vec<Option<u64>>,
    /// The pool words the function adds to a base, as PIC code adds one to
    /// `pc`: each holds a distance, not an address.
    pub(super) distances: BTreeSet<u64>,
}

/// Read `body` for the pool words that make addresses. See
/// [`Arm32::constant_kinds`].
pub(super) fn track_pool_words(
    code: &[u8],
    body: &[Insn],
    space: &AddressSpace,
    pc_model: PcModel,
) -> PoolWords {
    let mut kinds = vec![ConstantKind::Value; body.len()];
    let mut formed = vec![None; body.len()];
    let mut addresses = Vec::new();
    // Pool words whose value lies in the image, by where they sit. PIC code
    // adds such a word to `pc`, and then the value is only a distance.
    let mut whole: Vec<(u64, u64)> = Vec::new();
    let mut distances: BTreeSet<u64> = BTreeSet::new();
    let Some(start) = body.first().map(|insn| insn.address) else {
        return PoolWords { kinds, addresses, formed, distances };
    };

    // Registers holding a pool word: where the word sits, and its value.
    let mut literal: Vec<(il::Reg, u64, u32)> = Vec::new();
    // Registers holding an address built from `pc` and a pool word.
    let mut relative: Vec<(il::Reg, u64)> = Vec::new();
    // Registers holding a value built by `movw` and `movt`, with where the
    // two are. LLD's range extension thunks for T32 add such a value to `pc`:
    // `movw ip, lo; movt ip, hi; add ip, pc; bx ip`.
    let mut halves: Vec<(il::Reg, [usize; 2], u32)> = Vec::new();

    let word_at = |pool: u64| -> Option<u32> {
        let offset = usize::try_from(pool.checked_sub(start)?).ok()?;
        let bytes = code.get(offset..offset.checked_add(WORD_WIDTH)?)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    };

    for (index, insn) in body.iter().enumerate() {
        let opcode = core_opcode(insn);
        let Some(lifted) = lifted(insn) else { continue };
        let [il::Operand::Reg(destination), rest @ ..] = lifted.operands.as_slice() else {
            continue;
        };
        let destination = *destination;
        if rest.is_empty() {
            continue;
        }
        let pc = pc_model.of(insn.address);

        // `movw rX, lo` then `movt rX, hi`: a 32-bit value in two halves.
        // Any other write ends it, but for the `add rX, pc` that uses it.
        let builds_halves = matches!(opcode, Some(Opcode::MOV | Opcode::MOVT));
        // T32 writes `add rX, pc`, and A32 `add rX, rX, pc`.
        let adds_pc = opcode == Some(Opcode::ADD)
            && (rest == [PC_OPERAND] || rest == [il::Operand::Reg(destination), PC_OPERAND]);
        if writes_first_operand(insn) && !builds_halves && !adds_pc {
            halves.retain(|(held, ..)| *held != destination);
        }
        match (opcode, rest) {
            (Some(Opcode::MOV), [source]) => {
                halves.retain(|(held, ..)| *held != destination);
                if let il::Operand::Const(low @ 0..=0xffff) = source {
                    halves.push((destination, [index, index], *low as u32));
                }
            }
            (Some(Opcode::MOVT), _) => {
                let high = match rest {
                    [il::Operand::Const(high @ 0..=0xffff)] => Some(*high),
                    _ => None,
                };
                match (high, halves.iter_mut().find(|(held, ..)| *held == destination)) {
                    (Some(high), Some((_, at, value))) => {
                        at[1] = index;
                        *value = (*value & 0xffff) | ((high as u32) << 16);
                        // Code that is not PIC builds an address whole, as
                        // Cortex-M firmware does for its globals. A value in
                        // the image is one, as a word in a pool is.
                        if at[0] != at[1] && space.contains(u64::from(*value)) {
                            addresses.push(u64::from(*value));
                            formed[index] = Some(u64::from(*value));
                            for at in *at {
                                kinds[at] = ConstantKind::Address;
                            }
                        }
                    }
                    _ => halves.retain(|(held, ..)| *held != destination),
                }
                continue;
            }
            // `add rX, pc` of a value in both halves forms an address.
            (Some(Opcode::ADD), _) if adds_pc => {
                let whole =
                    halves.iter().find(|(held, at, _)| *held == destination && at[0] != at[1]);
                if let Some(&(_, at, value)) = whole {
                    let address = pc.wrapping_add(i64::from(value as i32) as u64) & 0xffff_ffff;
                    if space.contains_formed(address) {
                        addresses.push(address);
                        formed[index] = Some(address);
                        for at in at {
                            kinds[at] = ConstantKind::Address;
                        }
                    }
                    halves.retain(|(held, ..)| *held != destination);
                    forget(&mut literal, &mut relative, destination);
                    relative.push((destination, address));
                    continue;
                }
            }
            _ => {}
        }
        let literal_of = |register: il::Reg| {
            literal
                .iter()
                .find(|(held, ..)| *held == register)
                .map(|&(_, pool, value)| (pool, value))
        };
        let base_of = |register: il::Reg| match register {
            il::Reg::ProgramCounter => Some(pc),
            _ => relative.iter().find(|(held, _)| *held == register).map(|&(_, at)| at),
        };
        // The address a base and a pool word form, when it lies in the
        // image, marks the word as a stored address.
        let mut join = |base: u64, (pool, value): (u64, u32)| {
            let address = base.wrapping_add(i64::from(value as i32) as u64);
            distances.insert(pool);
            if space.contains_formed(address) {
                addresses.push(address);
                formed[index] = Some(address);
                if let Ok(index) = body.binary_search_by_key(&pool, |insn| insn.address) {
                    kinds[index] = ConstantKind::StoredAddress;
                }
            }
            address
        };

        // The two registers an `add` reads: T32 writes `add rX, rY` for
        // `add rX, rX, rY`.
        let sources = match (opcode, rest) {
            (Some(Opcode::ADD), [il::Operand::Reg(right)]) => Some((destination, *right)),
            (Some(Opcode::ADD), [il::Operand::Reg(left), il::Operand::Reg(right)]) => {
                Some((*left, *right))
            }
            _ => None,
        };
        // A plain access: through a base, plus a constant or a register.
        let reference = match (opcode, rest) {
            (
                Some(Opcode::LDR),
                [
                    il::Operand::Memory {
                        base: Some(base),
                        offset,
                        index,
                        update: il::Update::None,
                    },
                ],
            ) => match (offset, index) {
                (Some(offset), None) => Some((*base, Ok(*offset))),
                (None, Some((index, 0))) => Some((*base, Err(*index))),
                _ => None,
            },
            _ => None,
        };
        match (opcode, rest, reference, sources) {
            // `ldr rX, [pc, imm]`: load a pool word.
            (Some(Opcode::LDR), _, Some((il::Reg::ProgramCounter, Ok(offset))), _) => {
                let pool = pc_model.of_literal_load(insn.address).wrapping_add(offset as u64);
                forget(&mut literal, &mut relative, destination);
                if let Some(value) = word_at(pool) {
                    if space.contains(u64::from(value)) {
                        whole.push((pool, u64::from(value)));
                    }
                    literal.push((destination, pool, value));
                }
                continue;
            }
            // `mov rY, rX`: a copy holds what its source holds. GCC
            // copies the address of the global offset table so before it
            // reads a slot through it.
            (Some(Opcode::MOV), [il::Operand::Reg(source)], ..) => {
                let copied_address =
                    base_of(*source).filter(|_| *source != il::Reg::ProgramCounter);
                let copied_word = literal_of(*source);
                forget(&mut literal, &mut relative, destination);
                if let Some(address) = copied_address {
                    relative.push((destination, address));
                }
                if let Some((pool, value)) = copied_word {
                    literal.push((destination, pool, value));
                }
                continue;
            }
            // `ldr rY, [base, rX]`: read at a distance from a base.
            (Some(Opcode::LDR), _, Some((base, Err(index))), _) => {
                if let (Some(base), Some(word)) = (base_of(base), literal_of(index)) {
                    join(base, word);
                }
            }
            // `add rY, base, rX`, either order: build an address.
            (Some(Opcode::ADD), _, _, Some((left, right))) => {
                let joined =
                    match (base_of(left), literal_of(right), base_of(right), literal_of(left)) {
                        (Some(base), Some(word), ..) | (.., Some(base), Some(word)) => {
                            Some((base, word))
                        }
                        _ => None,
                    };
                if let Some((base, word)) = joined {
                    let address = join(base, word);
                    forget(&mut literal, &mut relative, destination);
                    relative.push((destination, address));
                    continue;
                }
            }
            _ => {}
        }

        if writes_first_operand(insn) {
            forget(&mut literal, &mut relative, destination);
        }
    }

    let stored: Vec<(u64, u64)> =
        whole.into_iter().filter(|(pool, _)| !distances.contains(pool)).collect();
    // In an image linked high, a pool word that holds an address in it is
    // that address, as Cortex-M firmware loads its globals. In a PIC library
    // linked at zero, such a word is more likely a number.
    if space.starts_high() {
        for &(pool, _) in &stored {
            if let Ok(index) = body.binary_search_by_key(&pool, |insn| insn.address) {
                kinds[index] = ConstantKind::StoredAddress;
            }
        }
    }
    addresses.extend(stored.into_iter().map(|(_, value)| value));
    PoolWords { kinds, addresses, formed, distances }
}

/// Stop following a register the instruction writes.
fn forget(
    literal: &mut Vec<(il::Reg, u64, u32)>,
    relative: &mut Vec<(il::Reg, u64)>,
    register: il::Reg,
) {
    literal.retain(|(held, ..)| *held != register);
    relative.retain(|(held, _)| *held != register);
}

/// Report whether `insn` writes its first operand. Stores, compares and
/// branches read it.
fn writes_first_operand(insn: &Insn) -> bool {
    !matches!(
        core_opcode(insn),
        Some(
            Opcode::STR
                | Opcode::STRB
                | Opcode::STRH
                | Opcode::STRD
                | Opcode::PUSH
                | Opcode::STM(true, false, ..)
                | Opcode::STM(false, true, ..)
                | Opcode::CMP
                | Opcode::CMN
                | Opcode::TST
                | Opcode::TEQ
                | Opcode::B
                | Opcode::BL
                | Opcode::BX
                | Opcode::BLX
        )
    )
}

