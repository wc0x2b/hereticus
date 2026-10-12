//! ARM32 (A32) decoding, on top of `yaxpeax-arm`.
//!
//! Two details of the `yaxpeax` API are easy to get wrong, so this module
//! handles both and the rest of `hereticus` never sees them:
//!
//! 1. `U8Reader` implements `Reader<u32, U32le>`, not `Reader<u32, u32>`.
//! 2. `total_offset()` counts **words**, not bytes. Multiplying by the
//!    instruction width is what makes reported addresses right.

pub use hereticus_il::arch::arm32::*;

use super::{Arch, DataAmongCode, Decoder, Insn, InsnKind, JumpTable, Memory};
use crate::address::{AddressSpace, ConstantKind, Contents};
use crate::il;
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
#[cfg(test)]
pub(crate) fn test_insn(name: &str, kind: InsnKind) -> Insn {
    let opcode = match name {
        "add" => Opcode::ADD,
        "sub" => Opcode::SUB,
        "mul" => Opcode::MUL,
        "mov" => Opcode::MOV,
        "mvn" => Opcode::MVN,
        "cmp" => Opcode::CMP,
        "ldr" => Opcode::LDR,
        "str" => Opcode::STR,
        "b" => Opcode::B,
        "bx" => Opcode::BX,
        "nop" => Opcode::NOP,
        other => panic!("no opcode for {other}"),
    };
    let decoded = Decoded::Core { opcode, condition: ConditionCode::AL, flags: Flags::Kept };
    Insn::new(0, &[], kind, super::Opcode::Arm(decoded))
}

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

impl Arch for Arm32 {
    fn is_frame_register(&self, reg: il::Reg) -> bool {
        matches!(reg, il::Reg::Stack | FRAME)
    }

    /// The first instruction of a function runs always, as almost every
    /// A32 instruction does: its top four bits are `0xE`.
    fn can_open_function(&self, bytes: &[u8]) -> bool {
        bytes.get(..INSN_WIDTH).is_some_and(|word| word[3] >> 4 == 0xe)
    }

    fn is_frame_management(&self, insn: &Insn) -> bool {
        let Some(opcode) = core_opcode(insn) else { return false };
        let operands = || lifted(insn).map(|lifted| lifted.operands).unwrap_or_default();

        match opcode {
            // Saving and restoring registers. A `pop` that loads the program
            // counter also returns, so it must stay.
            Opcode::PUSH => true,
            Opcode::POP => insn.kind != InsnKind::Return,

            // Moving the stack pointer, or setting up the frame pointer.
            Opcode::SUB | Opcode::ADD | Opcode::MOV => {
                matches!(operands().first(), Some(il::Operand::Reg(reg)) if self.is_frame_register(*reg))
            }

            // Spilling to and reloading from the frame, by `ldr`, `str`,
            // `ldm` and `stm`, which go up from the base.
            Opcode::LDR
            | Opcode::STR
            | Opcode::LDM(true, false, ..)
            | Opcode::STM(true, false, ..) => operands().iter().any(|operand| {
                matches!(operand, il::Operand::Memory { base: Some(base), .. } if self.is_frame_register(*base))
            }),

            _ => false,
        }
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

    /// ARM code reaches its data through literal pool words, and PIC code
    /// stores a *distance* there rather than an address: the word is added to
    /// `pc`, or used as an offset from a base built that way.
    ///
    /// ```text
    /// ldr r0, [pc, 0x4]     ; load the pool word
    /// add r0, pc, r0        ; add it to pc: the word is a distance
    /// ...
    /// ldr r3, [pc, 0xa0]
    /// ldr r3, [pc, r3]      ; read a GOT entry at that distance
    /// ```
    ///
    /// Such a word changes whenever the linker moves the data it reaches,
    /// which is every release, so it is marked as a stored address, but only
    /// when the address it forms lies inside `space`. A distance to something
    /// outside the image, such as the kernel a decompressor stub unpacks,
    /// stays a value: it changes because the thing it measures changed. A
    /// pool word used any other way, such as a size or a mask, stays a value.
    /// Measured on zlib built as an ARM shared library, these words alone made
    /// 18 unedited functions read as changed.
    fn constant_kinds(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
    ) -> Vec<ConstantKind> {
        track_pool_words(code, body, space, PcModel::A32).kinds
    }

    /// The addresses [`Arch::constant_kinds`] finds formed, and the pool
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

    fn formed_addresses(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        _memory: &Memory<'_>,
    ) -> Vec<Option<u64>> {
        track_pool_words(code, body, space, PcModel::A32).formed
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

    /// Almost every ARM instruction runs always: its top four bits are
    /// `0xE`, or `0xF` for the few with no condition. Data has no such
    /// bias. Measured on zlib, Lua and tinyxml2 for ARM, at least 40% of the
    /// words of every function of 16 words or more are such, and 65% for all
    /// but one in twenty. Their symbol tables, strings, `.rodata`, relocations
    /// and unwind tables reach at most 6%. So a quarter is the line.
    ///
    /// Below 16 words a function is not judged: a stub can look like
    /// anything.
    fn contents(&self, code: &[u8], _insns: &[Insn], _space: &AddressSpace) -> Contents {
        const FEWEST_WORDS: usize = 16;

        let words: Vec<u32> = code
            .as_chunks::<INSN_WIDTH>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
            .collect();
        if words.len() < FEWEST_WORDS {
            return Contents::Code;
        }
        let always = words.iter().filter(|&&word| word >> 28 >= 0xe).count();
        if always * 4 < words.len() { Contents::Data } else { Contents::Code }
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
/// thunk to where it formed. See [`super::Arch::call_targets`].
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
    /// See [`Arch::constant_kinds`].
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

#[cfg(test)]
mod unused_operand_tests {
    use super::*;

    #[test]
    fn a_compare_and_a_move_print_only_what_they_use() {
        let shown = |word: u32| {
            let code = word.to_le_bytes();
            let insn = Arm32.decode(&code, 0, 0).expect("decodes");
            insn.to_string()
        };
        // From `llvm-mc --triple=armv7`.
        assert_eq!(shown(0xe153_0002), "cmp r3, r2");
        assert_eq!(shown(0x1350_0007), "cmpne r0, 0x7");
        assert_eq!(shown(0xe311_0003), "tst r1, 0x3");
        assert_eq!(shown(0xe3e0_0000), "mvn r0, 0x0");
        assert_eq!(shown(0xe1a0_4201), "mov r4, r1, lsl 4");
        assert_eq!(shown(0xe1a0_7000), "mov r7, r0");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::{DecodeError, decode_all};
    use compact_str::CompactString;

    /// Decode one instruction from raw bytes at address 0.
    fn decode_one(bytes: [u8; 4]) -> Insn {
        Arm32.decode(&bytes, 0, 0).expect("bytes must decode")
    }

    /// Encodings from `llvm-mc --triple=armv7a --show-encoding`.
    mod words {
        pub const CMP_R0_1: [u8; 4] = [0x01, 0x00, 0x50, 0xe3];
        pub const BLT: [u8; 4] = [0x02, 0x00, 0x00, 0xba];
        pub const CMP_R0_0: [u8; 4] = [0x00, 0x00, 0x50, 0xe3];
        pub const BLE: [u8; 4] = [0x02, 0x00, 0x00, 0xda];
        pub const CMN_R1_1: [u8; 4] = [0x01, 0x00, 0x71, 0xe3];
        pub const BNE: [u8; 4] = [0x02, 0x00, 0x00, 0x1a];
        pub const TST_R2_4: [u8; 4] = [0x04, 0x00, 0x12, 0xe3];
        pub const BEQ: [u8; 4] = [0x02, 0x00, 0x00, 0x0a];
        pub const ADD_R0_R1_R2: [u8; 4] = [0x02, 0x00, 0x81, 0xe0];
        pub const LDR_R1_R2_8: [u8; 4] = [0x08, 0x10, 0x92, 0xe5];
        pub const LDR_R1_R2_POST: [u8; 4] = [0x04, 0x10, 0x92, 0xe4];
        pub const STR_R3_R4_R5: [u8; 4] = [0x05, 0x30, 0x84, 0xe7];
        pub const PUSH_R4_LR: [u8; 4] = [0x10, 0x40, 0x2d, 0xe9];
        pub const POP_R4_PC: [u8; 4] = [0x10, 0x80, 0xbd, 0xe8];
        pub const BL: [u8; 4] = [0x40, 0x00, 0x00, 0xeb];
        pub const STREX_R1_R2_R3: [u8; 4] = [0x92, 0x1f, 0x83, 0xe1];
        pub const UMULL: [u8; 4] = [0x92, 0x03, 0x81, 0xe0];
        pub const MOVT_R4: [u8; 4] = [0x34, 0x42, 0x41, 0xe3];
        pub const ADDEQ_R0: [u8; 4] = [0x01, 0x00, 0x80, 0x02];
        pub const LDRD_R2_R3_SP: [u8; 4] = [0xd8, 0x20, 0xcd, 0xe1];
    }

    fn lift_one(bytes: [u8; 4]) -> il::Lifted {
        Arm32.lift(&decode_one(bytes)).expect("the word must lift")
    }

    #[test]
    fn a_list_access_names_its_order() {
        let name = |word: u32| {
            let insn = decode_one(word.to_le_bytes());
            crate::arch::printed_name(&insn).to_string()
        };
        assert_eq!(name(0xe890_0006), "ldm", "increment after");
        assert_eq!(name(0xe990_0006), "ldmib");
        assert_eq!(name(0x1990_0006), "ldmibne");
        assert_eq!(name(0xe980_0006), "stmib");
        assert_eq!(name(0xe910_0006), "ldmdb");
        assert_eq!(name(0xe810_0006), "ldmda");
    }

    #[test]
    fn operands_come_in_printed_order() {
        use il::Operand::{Const, RegisterList, Target};
        let reg = |number| il::Operand::Reg(il::Reg::General(number));
        let operands = |bytes| lift_one(bytes).operands.into_vec();
        assert_eq!(operands(words::ADD_R0_R1_R2), [reg(0), reg(1), reg(2)]);
        assert_eq!(operands(words::CMP_R0_1), [reg(0), Const(1)], "no unused destination");
        let saved = [il::Reg::General(4), il::Reg::General(14)].into_iter().collect();
        let push = [il::Operand::Reg(il::Reg::Stack), RegisterList(saved)];
        assert_eq!(operands(words::PUSH_R4_LR), push, "the list names what it saves");
        assert!(
            matches!(operands(words::BL).as_slice(), [Target(Some(_))]),
            "a call names its distance"
        );
    }

    #[test]
    fn a_memory_operand_names_its_base_and_offset() {
        let general = |number| Some(il::Reg::General(number));
        let memory = |bytes| *lift_one(bytes).operands.last().expect("a memory operand");
        // `ldr r1, [r2, #-8]`
        const LDR_R1_R2_MINUS_8: [u8; 4] = [0x08, 0x10, 0x12, 0xe5];
        assert_eq!(memory(words::LDR_R1_R2_8), il::Operand::memory(general(2), Some(8)));
        assert_eq!(memory(LDR_R1_R2_MINUS_8), il::Operand::memory(general(2), Some(-8)));
        let indexed = il::Operand::Memory {
            base: general(4),
            offset: None,
            index: Some((il::Reg::General(5), 0)),
            update: il::Update::None,
        };
        assert_eq!(memory(words::STR_R3_R4_R5), indexed, "the index names its register");
        assert_eq!(
            memory(words::LDRD_R2_R3_SP),
            il::Operand::memory(Some(il::Reg::Stack), Some(8))
        );
    }

    #[test]
    fn the_frame_registers_are_sp_and_r11() {
        assert!(Arm32.is_frame_register(il::Reg::Stack));
        assert!(Arm32.is_frame_register(il::Reg::General(11)));
        assert!(!Arm32.is_frame_register(il::Reg::General(7)));
    }

    fn regs(numbers: &[u8]) -> il::RegSet {
        numbers
            .iter()
            .map(|&number| match number {
                13 => il::Reg::Stack,
                number => il::Reg::General(number),
            })
            .collect()
    }

    fn guard_of(words: &[[u8; 4]]) -> Option<il::Guard> {
        let lifted: Vec<Option<il::Lifted>> =
            words.iter().map(|&word| Some(lift_one(word))).collect();
        il::find_guards(&lifted).first().map(|found| found.guard)
    }

    /// Clang tests `x < 1` where GCC tests `x <= 0`, and both are one test.
    #[test]
    fn a_compare_and_its_branch_are_one_guard() {
        let clang = guard_of(&[words::CMP_R0_1, words::BLT]).unwrap();
        let gcc = guard_of(&[words::CMP_R0_0, words::BLE]).unwrap();
        assert_eq!(clang.cond, il::Cond::SignedLess);
        assert_eq!(clang.width, il::Width::Bits32);
        assert_eq!(clang.canonical(), gcc.canonical());
    }

    #[test]
    fn cmn_with_one_compares_with_minus_one() {
        let guard = guard_of(&[words::CMN_R1_1, words::BNE]).unwrap();
        assert_eq!(guard.right, il::Value::Const(0xffff_ffff));
    }

    #[test]
    fn tst_with_beq_tests_bits() {
        let guard = guard_of(&[words::TST_R2_4, words::BEQ]).unwrap();
        assert_eq!((guard.cond, guard.right), (il::Cond::BitsClear, il::Value::Const(4)));
    }

    #[test]
    fn a_conditional_instruction_reads_the_flags() {
        let lifted = lift_one(words::ADDEQ_R0);
        assert!(lifted.reads.contains(il::Reg::Flags));
        assert_eq!(lifted.test, None);
        assert_eq!(guard_of(&[words::CMP_R0_0, words::ADDEQ_R0, words::BEQ]), None);
    }

    #[test]
    fn registers_and_memory_are_named() {
        let add = lift_one(words::ADD_R0_R1_R2);
        assert_eq!((add.reads, add.writes), (regs(&[1, 2]), regs(&[0])));

        let load = lift_one(words::LDR_R1_R2_8);
        assert_eq!((load.reads, load.writes), (regs(&[2]), regs(&[1])));
        assert_eq!(load.memory.map(|access| access.kind), Some(il::AccessKind::Load));
        assert_eq!(lift_one(words::LDR_R1_R2_POST).writes, regs(&[1, 2]), "written back");

        let store = lift_one(words::STR_R3_R4_R5);
        assert_eq!((store.reads, store.writes), (regs(&[3, 4, 5]), il::RegSet::EMPTY));
        assert_eq!(store.memory.map(|access| access.kind), Some(il::AccessKind::Store));

        let push = lift_one(words::PUSH_R4_LR);
        assert_eq!((push.reads, push.writes), (regs(&[4, 13, 14]), regs(&[13])));
        let pop = lift_one(words::POP_R4_PC);
        assert_eq!((pop.reads, pop.writes), (regs(&[13]), regs(&[4, 13])), "the pc is no register");

        assert_eq!(lift_one(words::BL).writes, regs(&[14]));
        let exclusive = lift_one(words::STREX_R1_R2_R3);
        assert_eq!((exclusive.reads, exclusive.writes), (regs(&[2, 3]), regs(&[1])));
        let long = lift_one(words::UMULL);
        assert_eq!((long.reads, long.writes), (regs(&[2, 3]), regs(&[0, 1])));
        let movt = lift_one(words::MOVT_R4);
        assert_eq!((movt.reads, movt.writes), (regs(&[4]), regs(&[4])));
        let pair = lift_one(words::LDRD_R2_R3_SP);
        assert_eq!((pair.reads, pair.writes), (regs(&[13]), regs(&[2, 3])));
    }

    #[test]
    fn lifting_any_word_never_panics() {
        bolero::check!().with_type::<u32>().for_each(|&word| {
            let bytes = word.to_le_bytes();
            let insn = Arm32.decode(&bytes, 0, 0).expect("every word decodes or is unknown");
            if let Some(lifted) = Arm32.lift(&insn)
                && let Some(il::Test::Guard(_) | il::Test::OnFlags(_)) = lifted.test
            {
                assert!(
                    matches!(insn.kind, InsnKind::Branch { .. }),
                    "{insn}: a test that branches"
                );
            }
        });
    }

    /// The text of the A32 instruction `word`.
    fn text_of(word: u32) -> (String, String) {
        let insn = decode_one(word.to_le_bytes());
        (crate::arch::printed_name(&insn), crate::arch::printed_operands(&insn))
    }

    #[test]
    fn mov_r0_r0_is_padding_as_a_core_before_armv6k_pads() {
        let filler = decode_one(0xe1a0_0000u32.to_le_bytes());
        assert_eq!(filler.to_string(), "mov r0, r0");
        assert!(Arm32.is_padding(&filler));
        let copy = decode_one(0xe1a0_0001u32.to_le_bytes());
        assert!(!Arm32.is_padding(&copy), "mov r0, r1 does work");
    }

    #[test]
    fn an_a32_thunk_is_an_entry_and_names_where_it_jumps() {
        // movw ip, 0xb3b; movt ip, 0xffff; add ip, ip, pc; bx ip
        let words = [0xe300_cb3bu32, 0xe34f_cfff, 0xe08c_c00f, 0xe12f_ff1c];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = decode_all(&Arm32, &code, 0x2f6c8);
        assert!(Arm32.is_function_entry(&insns));
        // `pc` at the `add` is 0x2f6d0 + 8, and 0xffff_0b3b, without the
        // T32 bit, takes it back before the thunk.
        let target = 0x2f6d8u32.wrapping_add(0xffff_0b3b) & !1;
        assert_eq!(
            Arm32.call_targets(&insns),
            [(3, Some(crate::arch::CallTarget::Address(u64::from(target))))]
        );
    }

    #[test]
    fn neon_loads_and_stores_of_whole_registers_read() {
        let cases = [
            (0xf420_070f, "vld1.8", "{d0}, [r0]"),
            (0xf441_0a8d, "vst1.32", "{d16, d17}, [r1]!"),
            (0xf422_0142, "vld4.16", "{d0, d2, d4, d6}, [r2], r2"),
        ];
        for (word, name, operands) in cases {
            assert_eq!(text_of(word), (name.into(), operands.into()), "{word:#010x}");
            assert_eq!(decode_one(word.to_le_bytes()).kind, InsnKind::Normal);
        }
    }

    #[test]
    fn neon_loads_of_lanes_read() {
        assert_eq!(text_of(0xf4a1_0c8f), ("vld1.32".into(), "{d0[]}, [r1]".into()), "all lanes");
        assert_eq!(
            text_of(0xf4a0_0762),
            ("vld4.16".into(), "{d0[1], d2[1], d4[1], d6[1]}, [r0], r2".into()),
            "one lane, every second register"
        );
    }

    #[test]
    fn an_undefined_neon_load_stays_unknown() {
        let insn = decode_one(0xf420_0b0fu32.to_le_bytes());
        assert_eq!(
            (crate::arch::printed_name(&insn).as_str(), insn.kind),
            (UNKNOWN_TEXT, InsnKind::Unknown)
        );
        assert!(!Arm32.is_unread_extension(&insn));
    }

    #[test]
    fn neon_data_processing_stays_opaque_but_is_code() {
        let insn = decode_one(0xf260_0680u32.to_le_bytes());
        assert_eq!(
            (crate::arch::printed_name(&insn).as_str(), insn.kind),
            (NEON_TEXT, InsnKind::Unknown)
        );
        assert_eq!(
            crate::arch::printed_operands(&insn),
            "0xf2600680",
            "the word keeps an edit visible"
        );
        assert!(Arm32.is_unread_extension(&insn));
    }

    #[test]
    fn decodes_simple_arithmetic() {
        let insn = decode_one([0x00, 0x00, 0x81, 0xe0]);
        assert_eq!(crate::arch::printed_name(&insn), "add");
        assert_eq!(crate::arch::printed_operands(&insn), "r0, r1, r0");
        assert_eq!(insn.bytes_len, 4);
        assert_eq!(insn.kind, InsnKind::Normal);
    }

    #[test]
    fn bx_lr_is_a_return() {
        assert_eq!(decode_one([0x1e, 0xff, 0x2f, 0xe1]).kind, InsnKind::Return);
    }

    /// `pop {pc}` decodes with opcode `LDR`, so only the PC check finds it.
    #[test]
    fn pop_pc_is_a_return() {
        assert_eq!(decode_one([0x04, 0xf0, 0x9d, 0xe4]).kind, InsnKind::Return);
    }

    /// `pop {fp, pc}` carries the PC in a register-list bitmask.
    #[test]
    fn pop_reglist_with_pc_is_a_return() {
        assert_eq!(decode_one([0x00, 0x88, 0xbd, 0xe8]).kind, InsnKind::Return);
    }

    /// `mov pc, lr` decodes with opcode `MOV`.
    #[test]
    fn mov_pc_lr_is_a_return() {
        assert_eq!(decode_one([0x0e, 0xf0, 0xa0, 0xe1]).kind, InsnKind::Return);
    }

    /// `add r1, pc, r1` reads the PC to form an address. It does not leave.
    #[test]
    fn reading_the_pc_is_not_a_return() {
        let add = decode_one(0xe08f_1001_u32.to_le_bytes());
        assert_eq!(add.to_string(), "add r1, pc, r1");
        assert_eq!(add.kind, InsnKind::Normal);
    }

    /// `str pc, [sp]` and `cmp pc, r0` name the PC, but do not write it.
    #[test]
    fn a_store_or_compare_of_the_pc_is_not_a_return() {
        assert_eq!(decode_one(0xe58d_f000_u32.to_le_bytes()).kind, InsnKind::Normal);
        assert_eq!(decode_one(0xe15f_0000_u32.to_le_bytes()).kind, InsnKind::Normal);
        assert_eq!(
            decode_one(0xe92d_c000_u32.to_le_bytes()).kind,
            InsnKind::Normal,
            "push lr and pc"
        );
    }

    /// `bx` through a register other than `lr` is a tail call. A write of the
    /// pc through a table is not.
    #[test]
    fn only_bx_is_a_tail_call() {
        assert!(Arm32.is_tail_call(&decode_one(0xe12f_ff13_u32.to_le_bytes())), "bx r3");
        assert!(!Arm32.is_tail_call(&decode_one(0xe12f_ff1e_u32.to_le_bytes())), "bx lr");
        assert!(!Arm32.is_tail_call(&decode_one(0xe08f_f100_u32.to_le_bytes())), "add pc");
    }

    /// `add pc, pc, r0, lsl 2` and `ldr pc, [r1, r0, lsl 2]` jump through a
    /// table. They leave the block, but not the function.
    #[test]
    fn a_computed_write_of_the_pc_is_a_jump() {
        assert_eq!(decode_one(0xe08f_f100_u32.to_le_bytes()).kind, InsnKind::Jump { target: None });
        assert_eq!(decode_one(0xe791_f100_u32.to_le_bytes()).kind, InsnKind::Jump { target: None });
        assert_eq!(
            decode_one(0xe1a0_f003_u32.to_le_bytes()).kind,
            InsnKind::Jump { target: None },
            "mov pc, r3"
        );
    }

    /// Code with a `switch` table as GCC emits it, at address 0: `adr`,
    /// `ldr`, `add pc`, then the table, then the cases.
    fn switch_code(entries: &[i32]) -> Vec<u8> {
        let mut words = vec![
            0xe28f_1004_u32, // 0x00 adr r1, pc, 0x4: the table is at 0x0c
            0xe791_0100,     // 0x04 ldr r0, [r1, r0, lsl 2]
            0xe081_f000,     // 0x08 add pc, r1, r0
        ];
        words.extend(entries.iter().map(|&entry| entry as u32));
        words.extend([0xe3a0_0001, 0xe12f_ff1e, 0xe3a0_0002, 0xe12f_ff1e]); // mov r0, n; bx lr
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn tables_of(code: &[u8]) -> Vec<JumpTable> {
        let (insns, _) = crate::arch::decode_all(&Arm32, code, 0);
        let regions = [(0, code)];
        Arm32.jump_tables(&Memory::new(&regions), 0..code.len() as u64, &insns)
    }

    /// Each entry is an offset from the table, and the cases follow it.
    #[test]
    fn reads_a_switch_table() {
        // Two entries end at 0x14, where the first case starts.
        let code = switch_code(&[0x08, 0x10]);
        assert_eq!(
            tables_of(&code),
            [JumpTable { jump: 0x08, words: 0x0c..0x14, targets: vec![0x14, 0x1c] }]
        );
    }

    /// A case can lead back before the table, to a shared exit.
    #[test]
    fn a_case_can_lie_before_the_table() {
        // Three entries end at 0x18, and the second leads back to 0x00.
        let code = switch_code(&[0x0c, -0x0c, 0x10]);
        assert_eq!(tables_of(&code)[0].targets, [0x18, 0x00, 0x1c]);
    }

    /// An entry that points into the table, or past the code, ends it.
    #[test]
    fn an_entry_that_is_no_case_ends_the_table() {
        assert_eq!(tables_of(&switch_code(&[0x10, 0x04]))[0].targets, [0x1c]);
        assert_eq!(tables_of(&switch_code(&[0x10, 0x1000]))[0].targets, [0x1c]);
        assert_eq!(tables_of(&switch_code(&[0x11]))[..], [], "not on a whole word");
    }

    /// GCC's table is a run of `b` after `add pc, pc, rX, lsl 2`.
    #[test]
    fn reads_a_table_of_branches() {
        let words = [
            0xe353_0002_u32, // 0x00 cmp r3, 2
            0x908f_f103,     // 0x04 addls pc, pc, r3, lsl 2
            0xea00_0003,     // 0x08 b 0x1c: the default
            0xea00_0002,     // 0x0c b 0x1c
            0xea00_0002,     // 0x10 b 0x20
            0xea00_0002,     // 0x14 b 0x24
            0xe12f_ff1e,     // 0x18 bx lr
            0xe3a0_0000,     // 0x1c mov r0, 0
            0xe3a0_0001,     // 0x20 mov r0, 1
            0xe3a0_0002,     // 0x24 mov r0, 2
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let tables = tables_of(&code);
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].jump, 0x04);
        assert_eq!(tables[0].targets, [0x1c, 0x1c, 0x20, 0x24]);
        assert!(tables[0].words.is_empty(), "the table is code");
    }

    /// GCC's compressed table: a byte for each case, in `.rodata`.
    #[test]
    fn reads_a_table_of_byte_offsets() {
        let words = [
            0xe59f_c010_u32, // 0x00 ldr ip, [pc, 0x10]: the word at 0x18
            0xe08f_c00c,     // 0x04 add ip, pc, ip: ip = 0x0c + 0x14 = 0x20
            0xe353_0002,     // 0x08 cmp r3, 2
            0xe7dc_3003,     // 0x0c ldrb r3, [ip, r3]
            0xe08f_f103,     // 0x10 add pc, pc, r3, lsl 2
            0xe12f_ff1e,     // 0x14 bx lr
            0x0000_0014,     // 0x18 the distance to the table
            0xe12f_ff1e,     // 0x1c bx lr
            0x0001_0100,     // 0x20 the table: cases at +0, +1, +1 words
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let tables = tables_of(&code);
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].targets, [0x18, 0x1c, 0x1c]);
        assert_eq!(tables[0].words, 0x20..0x23);
    }

    /// Without the `adr` and the scaled `ldr`, the jump is not through a
    /// table this can read.
    #[test]
    fn a_computed_jump_without_its_table_is_left_alone() {
        let mut code = switch_code(&[0x08, 0x10]);
        code[..4].copy_from_slice(&0xe1a0_1000_u32.to_le_bytes()); // mov r1, r0
        assert!(tables_of(&code).is_empty());

        let mut code = switch_code(&[0x08, 0x10]);
        code[4..8].copy_from_slice(&0xe591_0000_u32.to_le_bytes()); // ldr r0, [r1]
        assert!(tables_of(&code).is_empty());
    }

    /// `vldr d16, [pc, 0x90]`, as GCC loads a double from its pool, and the
    /// hints `yaxpeax` leaves unread.
    #[test]
    fn reads_vfp_loads_and_hints() {
        let text = |word: u32| decode_one(word.to_le_bytes()).to_string();
        assert_eq!(text(0xeddf_0b24), "vldr d16, [pc, 0x90]");
        assert_eq!(text(0xed1f_0a01), "vldr s0, [pc, -0x4]");
        assert_eq!(text(0x0d8d_1b00), "vstreq d1, [sp]");
        assert_eq!(text(0xe320_f000), "nop");
        assert_eq!(text(0xe320_f003), "wfi");
        assert_eq!(decode_one(0xeddf_0b24_u32.to_le_bytes()).kind, InsnKind::Normal);
    }

    /// A pool a VFP load reads is data, one word for a single and two for a
    /// double.
    #[test]
    fn a_vfp_load_names_its_pool_words() {
        let words = [0xeddf_0b00_u32, 0xed9f_0a00]; // vldr d16, [pc]; vldr s0, [pc]
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0);
        assert_eq!(Arm32.literal_pool_words(&insns), [0x08, 0x0c, 0x0c]);
    }

    /// Code that is not PIC builds an address whole with `movw` and `movt`.
    #[test]
    fn a_whole_address_built_in_two_halves_is_an_address() {
        // movw r2, 0x9de8; movt r2, 0x800
        let words = [0xe309_2de8_u32, 0xe340_2800];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0x0800_0000);
        let space = AddressSpace::of_raw_image(0x0800_0000, 0x1_0000);
        let kinds = Arm32.constant_kinds(&code, &insns, &space);
        assert_eq!(kinds, [ConstantKind::Address, ConstantKind::Address]);
        let number = AddressSpace::of_raw_image(0x0900_0000, 0x1_0000);
        assert_eq!(Arm32.constant_kinds(&code, &insns, &number)[0], ConstantKind::Value);
    }

    /// In an image linked high, a pool word that holds an address in it is
    /// that address; in one linked at zero, it may be a number.
    #[test]
    fn a_pool_word_holds_an_address_only_in_an_image_linked_high() {
        let pool_word_at = |base: u64| {
            // ldr r0, [pc, -0x4]: the word right after it, which holds an
            // address 0x100 into the image.
            let words = [0xe51f_0004_u32, (base + 0x100) as u32];
            let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            let (insns, _) = crate::arch::decode_all(&Arm32, &code, base);
            let space = AddressSpace::of_raw_image(base, 0x2000);
            Arm32.constant_kinds(&code, &insns, &space)[1]
        };
        assert_eq!(pool_word_at(0x0800_0000), ConstantKind::StoredAddress);
        assert_eq!(pool_word_at(0), ConstantKind::Value);
    }

    /// A double load just after address 0 reaches back past it, as
    /// random bytes read at base 0 can. The pool address wraps and does not
    /// overflow.
    #[test]
    fn a_pool_before_address_zero_wraps() {
        let code = 0xed5f_0b03_u32.to_le_bytes(); // vldr d16, [pc, -0xc]
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0);
        assert_eq!(Arm32.literal_pool_words(&insns), [u64::MAX - 3, 0]);
    }

    /// GCC copies the address of the global offset table with `mov` before
    /// it reads a slot through it. The pool word that holds the slot's
    /// offset is then chosen by the linker, as the address itself is.
    #[test]
    fn a_copied_table_address_marks_its_slot_offset() {
        let words = [
            0xe59f_c00c_u32, // 0x00 ldr ip, [pc, 0xc]: the word at 0x14
            0xe08f_c00c,     // 0x04 add ip, pc, ip: the table at 0x14 + 0xc
            0xe1a0_000c,     // 0x08 mov r0, ip
            0xe59f_c004,     // 0x0c ldr ip, [pc, 0x4]: the word at 0x18
            0xe790_000c,     // 0x10 ldr r0, [r0, ip]
            0x0000_0014,     // 0x14 the distance to the table
            0x0000_0008,     // 0x18 the slot's offset in the table
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        // Numbers below a page are never addresses, so the code sits higher.
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0x8000);
        let space = AddressSpace::of_raw_image(0x8000, 0x100);
        let kinds = Arm32.constant_kinds(&code, &insns, &space);
        assert_eq!(kinds[5], ConstantKind::StoredAddress, "the table's distance");
        assert_eq!(kinds[6], ConstantKind::StoredAddress, "the slot's offset");
    }

    /// `lld` puts the read-only data of a small library below the first
    /// page, and code reaches it by a negative distance from `pc`. Measured
    /// on a Rust library for ARM, the message a panic prints sat at 0xbc8.
    #[test]
    fn a_distance_to_low_data_marks_its_pool_word() {
        let words = [
            0xe59f_0000_u32,                // 0x10000 ldr r0, [pc]: the word at 0x10008
            0xe08f_0000,                    // 0x10004 add r0, pc, r0
            (0x0bc8_i32 - 0x1_000c) as u32, // 0x10008 the distance to 0xbc8
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0x1_0000);
        let space = AddressSpace::from_ranges([0x870..0xd40, 0x1_0000..0x1_0100]);
        let kinds = Arm32.constant_kinds(&code, &insns, &space);
        assert_eq!(kinds[2], ConstantKind::StoredAddress);
    }

    /// PIC code adds a pool word to `pc`, and other code keeps the whole
    /// address in the pool. Both are data the function points at.
    #[test]
    fn data_addresses_are_formed_or_loaded_whole() {
        let words = [
            0xe59f_0004_u32, // 0x8000 ldr r0, [pc, 0x4]: the word at 0x800c
            0xe08f_0000,     // 0x8004 add r0, pc, r0: 0x800c + 0x40
            0xe59f_1000,     // 0x8008 ldr r1, [pc]: the word at 0x8010
            0x0000_0040,     // 0x800c a distance
            0x0000_8080,     // 0x8010 an address
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0x8000);
        let space = AddressSpace::of_raw_image(0x8000, 0x100);
        let memory = Memory::new(&[]);
        assert_eq!(Arm32.data_addresses(&code, &insns, &space, &memory), [0x804c, 0x8080]);
        let outside = AddressSpace::of_raw_image(0x9000, 0x100);
        assert!(Arm32.data_addresses(&code, &insns, &outside, &memory).is_empty());
    }

    /// A pool word that `pc` is added to is a distance, even where its
    /// value happens to lie in the image as well.
    #[test]
    fn a_distance_is_no_whole_address() {
        let words = [
            0xe59f_0000_u32, // 0x8000 ldr r0, [pc]: the word at 0x8008
            0xe08f_0000,     // 0x8004 add r0, pc, r0: 0x8008 + 0x8040, outside
            0x0000_8040,     // 0x8008 a distance that reads as an address
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0x8000);
        let space = AddressSpace::of_raw_image(0x8000, 0x100);
        assert!(Arm32.data_addresses(&code, &insns, &space, &Memory::new(&[])).is_empty());
    }

    /// GCC for PIC reads a byte table in `.rodata` and adds it to `pc`. The
    /// table's address can be made long before the jump, before a loop, and
    /// the load can write the register that held it.
    #[test]
    fn reads_a_byte_table_whose_address_was_made_long_before() {
        let mut words = vec![
            0xe59f_e070_u32, // 0x1000 ldr lr, [pc, 0x70]: the word at 0x1078
            0xe08f_e00e,     // 0x1004 add lr, pc, lr: the table at 0x2000
        ];
        words.extend([0xe1a0_0000; 20]); // 0x1008 mov r0, r0, twenty times
        words.extend([
            0xe351_0002, // 0x1058 cmp r1, 2
            0x8a00_0003, // 0x105c bhi 0x1070
            0xe7de_e001, // 0x1060 ldrb lr, [lr, r1]
            0xe08f_f10e, // 0x1064 add pc, pc, lr, lsl 2
            0xe1a0_0000, // 0x1068 nop
            0xe12f_ff1e, // 0x106c case 0: bx lr
            0xe12f_ff1e, // 0x1070 case 1: bx lr
            0xe12f_ff1e, // 0x1074 case 2: bx lr
            0x0000_0ff4, // 0x1078 the distance from 0x100c to the table
        ]);
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0x1000);
        let table = [0_u8, 1, 2];
        let regions = [(0x1000, code.as_slice()), (0x2000, table.as_slice())];
        assert_eq!(
            Arm32.jump_tables(&Memory::new(&regions), 0x1000..0x107c, &insns),
            [JumpTable {
                jump: 0x1064,
                words: 0x2000..0x2003,
                targets: vec![0x106c, 0x1070, 0x1074]
            }]
        );
    }

    /// A compare prints `r0` first but writes nothing, so it does not hide
    /// where a table in `r0` was made.
    #[test]
    fn a_compare_does_not_hide_a_table_in_r0() {
        let words = [
            0xe59f_0020_u32, // 0x1000 ldr r0, [pc, 0x20]: the word at 0x1028
            0xe08f_0000,     // 0x1004 add r0, pc, r0: the table at 0x2000
            0xe351_0002,     // 0x1008 cmp r1, 2
            0x8a00_0004,     // 0x100c bhi 0x1024
            0xe7d0_1001,     // 0x1010 ldrb r1, [r0, r1]
            0xe08f_f101,     // 0x1014 add pc, pc, r1, lsl 2
            0xe1a0_0000,     // 0x1018 nop
            0xe12f_ff1e,     // 0x101c case 0: bx lr
            0xe12f_ff1e,     // 0x1020 case 1: bx lr
            0xe12f_ff1e,     // 0x1024 case 2: bx lr
            0x0000_0ff4,     // 0x1028 the distance from 0x100c to the table
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0x1000);
        let table = [0_u8, 1, 2];
        let regions = [(0x1000, code.as_slice()), (0x2000, table.as_slice())];
        assert_eq!(
            Arm32.jump_tables(&Memory::new(&regions), 0x1000..0x102c, &insns),
            [JumpTable {
                jump: 0x1014,
                words: 0x2000..0x2003,
                targets: vec![0x101c, 0x1020, 0x1024]
            }]
        );
    }

    /// Code runs always; text and tables do not.
    #[test]
    fn tells_code_from_data() {
        let space = AddressSpace::none();
        let judge = |words: &[u32]| {
            let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0);
            Arm32.contents(&code, &insns, &space)
        };
        let code = [0xe92d_4010_u32, 0xe1a0_4000, 0x0a00_0002, 0xe594_0000, 0xe8bd_8010];
        let text = u32::from_le_bytes(*b"text");
        assert_eq!(judge(&code.repeat(4)), Contents::Code);
        assert_eq!(judge(&[text; 16]), Contents::Data);
        assert_eq!(judge(&[0x0000_0010; 16]), Contents::Data, "a table of small offsets");
        assert_eq!(judge(&[text; 15]), Contents::Code, "too short to judge");
    }

    /// The PLT stub of `StrPair::Reset` in tinyxml2 for ARM, as LLD wrote
    /// it, jumps through the slot at 0x3ea34.
    #[test]
    fn reads_the_slot_a_plt_stub_jumps_through() {
        let stub: Vec<u8> = [0xe28f_c600_u32, 0xe28c_ca20, 0xe5bc_fccc]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        assert_eq!(Arm32.stub_slot(&stub, 0x1dd60), Some(0x3ea34));
        assert_eq!(Arm32.stub_slot(&stub[..8], 0x1dd60), None, "too short");

        let mut other = stub.clone();
        other[8..].copy_from_slice(&0xe59c_f000_u32.to_le_bytes()); // ldr pc, [ip]
        assert_eq!(Arm32.stub_slot(&other, 0x1dd60), None);

        // `ldr pc, [ip]!`: a slot at the offset of zero prints no offset,
        // as Lua's stub of `lua_setupvalue` for ARM does.
        let mut zero = stub.clone();
        zero[8..].copy_from_slice(&0xe5bc_f000_u32.to_le_bytes());
        assert_eq!(Arm32.stub_slot(&zero, 0x1dd60), Some(0x3dd68));
    }

    /// `ldm sp!, {r4, pc}` returns, as `pop` does.
    #[test]
    fn a_load_multiple_from_the_stack_is_a_return() {
        assert_eq!(decode_one(0xe8bd_8010_u32.to_le_bytes()).kind, InsnKind::Return);
    }

    /// A conditional return falls through when the condition fails.
    #[test]
    fn a_conditional_bx_lr_is_a_branch() {
        assert_eq!(
            decode_one(0x012f_ff1e_u32.to_le_bytes()).kind,
            InsnKind::Branch { target: None }
        );
        assert_eq!(
            decode_one(0x012f_ff13_u32.to_le_bytes()).kind,
            InsnKind::Branch { target: None }
        ); // bxeq r3
    }

    #[test]
    fn push_is_not_a_return() {
        assert_eq!(decode_one([0x00, 0x48, 0x2d, 0xe9]).kind, InsnKind::Normal);
    }

    /// `sub sp, sp, 0xc` before a `push` opens a variadic function.
    #[test]
    fn a_stack_reservation_before_the_prologue_opens_the_function() {
        let reserve = decode_one(0xe24d_d00c_u32.to_le_bytes()); // sub sp, sp, 0xc
        let work = decode_one(0xe080_0001_u32.to_le_bytes()); // add r0, r0, r1
        assert_eq!(Arm32.preamble_before_prologue(&[work.clone(), reserve]), 1);
        assert_eq!(Arm32.preamble_before_prologue(&[work]), 0);
        assert_eq!(Arm32.preamble_before_prologue(&[]), 0);
    }

    #[test]
    fn bl_is_a_call() {
        let insn = decode_one([0xfe, 0xff, 0xff, 0xeb]);
        assert!(matches!(insn.kind, InsnKind::Call { .. }));
    }

    /// `b` and `beq` share opcode `B`; only the condition separates them.
    #[test]
    fn unconditional_branch_is_a_jump() {
        assert!(matches!(decode_one([0xfe, 0xff, 0xff, 0xea]).kind, InsnKind::Jump { .. }));
    }

    #[test]
    fn conditional_branch_can_fall_through() {
        assert!(matches!(decode_one([0xfe, 0xff, 0xff, 0x0a]).kind, InsnKind::Branch { .. }));
    }

    /// `yaxpeax` removes the pipeline bias, so a branch to self is offset 0.
    #[test]
    fn branch_to_self_resolves_to_its_own_address() {
        let insn = Arm32.decode(&[0xfe, 0xff, 0xff, 0xea], 0, 0x1000).unwrap();
        assert_eq!(insn.kind, InsnKind::Jump { target: Some(0x1000) });
    }

    /// Branching to itself cannot catch a wrong scale or sign, so check a
    /// forward and a backward branch too.
    #[test]
    fn branch_targets_scale_by_instruction_width() {
        let forward = Arm32.decode(&[0xff, 0xff, 0xff, 0xea], 0, 0x1000).unwrap();
        assert_eq!(forward.kind, InsnKind::Jump { target: Some(0x1004) });

        let backward = Arm32.decode(&[0xfd, 0xff, 0xff, 0xea], 0, 0x1000).unwrap();
        assert_eq!(backward.kind, InsnKind::Jump { target: Some(0x0ffc) });
    }

    #[test]
    fn address_tracks_the_offset() {
        let code = [0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
        assert_eq!(Arm32.decode(&code, 4, 0x8000).unwrap().address, 0x8004);
    }

    #[test]
    fn rejects_truncated_input() {
        assert_eq!(Arm32.decode(&[0x00, 0x00], 0, 0), Err(DecodeError::Truncated));
        assert_eq!(Arm32.decode(&[], 0, 0), Err(DecodeError::Truncated));
    }

    #[test]
    fn rejects_offset_past_the_end() {
        assert_eq!(Arm32.decode(&[0x00; 4], 8, 0), Err(DecodeError::Truncated));
    }

    /// Addresses must advance by 4 per instruction, not by 1. This is the
    /// regression test for the word-versus-byte offset trap.
    #[test]
    fn decode_all_advances_by_instruction_width() {
        // add, bx lr, add
        let code = [0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1, 0x00, 0x00, 0x81, 0xe0];
        let (insns, err) = decode_all(&Arm32, &code, 0x1000);
        assert_eq!(err, None);
        let addresses: Vec<u64> = insns.iter().map(|i| i.address).collect();
        assert_eq!(addresses, vec![0x1000, 0x1004, 0x1008]);
    }

    /// The usual ARM `nop` is one `yaxpeax` decodes "successfully" as
    /// `Opcode::Invalid`. The fallback reads it as `nop`, which moves nothing.
    #[test]
    fn nop_encoding_decodes_as_nop() {
        let insn = decode_one([0x00, 0xf0, 0x20, 0xe3]);
        assert_eq!(crate::arch::printed_name(&insn), "nop");
        assert_eq!(insn.kind, InsnKind::Normal);
    }

    /// NEON is outside what `yaxpeax-arm` 0.4 decodes. `vdup.32 q8, r2` must
    /// come back as opaque bytes, not as an error.
    #[test]
    fn neon_decodes_as_unknown() {
        let insn = decode_one([0x90, 0x2b, 0xa0, 0xee]);
        assert_eq!(insn.kind, InsnKind::Unknown);
        assert_eq!(insn.bytes_len, INSN_WIDTH);
    }

    /// Stepping over an unreadable word must keep the instructions after it
    /// aligned, which is the whole reason for the opaque kind.
    #[test]
    fn decoding_continues_past_unknown_bytes() {
        // add, vdup.32 (NEON), bx lr
        let code = [0x00, 0x00, 0x81, 0xe0, 0x90, 0x2b, 0xa0, 0xee, 0x1e, 0xff, 0x2f, 0xe1];
        let (insns, err) = decode_all(&Arm32, &code, 0x1000);

        assert_eq!(err, None, "unreadable bytes must not stop the decode");
        assert_eq!(insns.len(), 3);
        assert_eq!(insns[1].kind, InsnKind::Unknown);

        // The instruction after the opaque word must still be read correctly.
        assert_eq!(insns[2].kind, InsnKind::Return);
        assert_eq!(insns[2].address, 0x1008);
    }

    #[test]
    fn decode_all_reports_trailing_partial_bytes() {
        let code = [0x00, 0x00, 0x81, 0xe0, 0xff];
        let (insns, err) = decode_all(&Arm32, &code, 0);
        assert_eq!(insns.len(), 1);
        assert_eq!(err, Some(DecodeError::Truncated));
    }

    #[test]
    fn decode_all_handles_empty_input() {
        let (insns, err) = decode_all(&Arm32, &[], 0);
        assert!(insns.is_empty());
        assert_eq!(err, None);
    }

    #[test]
    fn trailing_padding_is_removed() {
        // add, then a nop the linker used to align the next function.
        let code = [0x00, 0x00, 0x81, 0xe0, 0x00, 0xf0, 0x20, 0xe3];
        assert_eq!(Arm32.trim_padding(&code), &code[..4]);
    }

    #[test]
    fn trailing_zero_words_are_removed() {
        let code = [0x00, 0x00, 0x81, 0xe0, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(Arm32.trim_padding(&code), &code[..4]);
    }

    /// Padding inside a function is not padding, so it must stay.
    #[test]
    fn padding_before_real_code_is_kept() {
        let code = [0x00, 0xf0, 0x20, 0xe3, 0x00, 0x00, 0x81, 0xe0];
        assert_eq!(Arm32.trim_padding(&code), &code[..], "only the end is trimmed");
    }

    #[test]
    fn trimming_leaves_a_function_of_only_padding_empty() {
        assert!(Arm32.trim_padding(&[0x00, 0xf0, 0x20, 0xe3]).is_empty());
    }

    #[test]
    fn trimming_keeps_code_that_needs_no_trimming() {
        let code = [0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
        assert_eq!(Arm32.trim_padding(&code), &code[..]);
    }

    #[test]
    fn a_prologue_is_recognized_by_its_saved_link_register() {
        let push_lr = Arm32.decode(&[0x10, 0x40, 0x2d, 0xe9], 0, 0).unwrap();
        assert!(Arm32.is_prologue(&push_lr), "push {{r4, lr}} opens a function");

        // `push {r4, r5}` saves no link register, so it calls nothing and is
        // not the start of a non-leaf function.
        let push_plain = Arm32.decode(&[0x30, 0x00, 0x2d, 0xe9], 0, 0).unwrap();
        assert!(!Arm32.is_prologue(&push_plain));

        let add = Arm32.decode(&[0x00, 0x00, 0x81, 0xe0], 0, 0).unwrap();
        assert!(!Arm32.is_prologue(&add));
    }

    /// The `nop` the linker pads with is padding, by its name now that the
    /// fallback reads it.
    #[test]
    fn the_nop_encoding_is_padding() {
        let nop = decode_one(NOP_BYTES);
        assert!(Arm32.is_padding(&nop), "the A32 nop encoding is padding");

        let add = decode_one([0x00, 0x00, 0x81, 0xe0]);
        assert!(!Arm32.is_padding(&add), "real work is not padding");
    }

    /// A zero word decodes as `andeq r0, r0, r0`, a real instruction, so the
    /// instruction-level test does not claim it. Only [`Arch::trim_padding`],
    /// which reads the bytes, removes a run of zeros from the end of a
    /// function. The two tests differ on purpose: mistaking a zero word inside
    /// a function for padding would drop real code.
    #[test]
    fn a_zero_word_is_padding_only_to_the_byte_level_test() {
        let zero = decode_one(ZERO_BYTES);
        assert_eq!(zero.kind, InsnKind::Normal, "a zero word decodes as andeq");
        assert!(!Arm32.is_padding(&zero));
        assert!(Arm32.trim_padding(&ZERO_BYTES).is_empty());
    }

    /// The name of the operation of the A32 `word`.
    fn operation_of(word: u32) -> CompactString {
        Arm32.operation_name(&decode_one(word.to_le_bytes()))
    }

    /// A condition and a flag-setting `s` say when the work runs and what
    /// it leaves in the flags, not what it computes. Text that ends in
    /// condition letters cannot fool the opcode: `adcs` is `adc`, though
    /// `cs` is a condition, and `bls` is a branch, not a call. A branch keeps
    /// its condition, which is its test.
    #[test]
    fn a_condition_and_the_flags_do_not_change_the_operation() {
        // mov r0, r1; movlt r0, r1; movs r0, r1.
        assert_eq!(operation_of(0xe1a0_0001), operation_of(0xb1a0_0001));
        assert_eq!(operation_of(0xe1a0_0001), operation_of(0xe1b0_0001));
        // bx lr; bxeq lr.
        assert_eq!(operation_of(0xe12f_ff1e), operation_of(0x012f_ff1e));
        // adc r0, r0, r1; adcs r0, r0, r1.
        assert_eq!(operation_of(0xe0a0_0001), operation_of(0xe0b0_0001));
        // bls is a branch on a test, not a call.
        assert_ne!(operation_of(0x9a00_0000), operation_of(0xeb00_0000));
        // bne and beq apply different tests.
        assert_ne!(operation_of(0x1a00_0000), operation_of(0x0a00_0000));
    }

    #[test]
    fn distinct_operations_stay_distinct() {
        // ldr r0, [r1]; str r0, [r1]; push {r4, lr}; pop {r4, pc}.
        assert_ne!(operation_of(0xe591_0000), operation_of(0xe581_0000));
        assert_ne!(operation_of(0xe92d_4010), operation_of(0xe8bd_8010));
    }

    #[test]
    fn frame_work_is_told_apart_from_real_work() {
        let push = decode_one([0x10, 0x40, 0x2d, 0xe9]);
        assert!(Arm32.is_frame_management(&push));

        let add = decode_one([0x00, 0x00, 0x81, 0xe0]);
        assert!(!Arm32.is_frame_management(&add), "arithmetic is the work itself");
    }

    /// A `pop` that loads the program counter returns, so it is not mere
    /// bookkeeping and must survive normalization.
    #[test]
    fn a_pop_that_returns_is_not_frame_work() {
        let pop_pc = decode_one([0x00, 0x88, 0xbd, 0xe8]);
        assert_eq!(pop_pc.kind, InsnKind::Return);
        assert!(!Arm32.is_frame_management(&pop_pc));
    }

    /// `yaxpeax` reads `mvn r0, #1` with an unused field, as
    /// `mvn r0, r0, 0x1`.
    #[test]
    fn a_not_of_a_constant_is_a_move_of_the_inverse() {
        let lifted = lift_one([0x01, 0x00, 0xe0, 0xe3]);
        assert_eq!(lifted.op, il::Op::Move);
        let inverse = il::Operand::Const(0xffff_fffe);
        assert_eq!(lifted.operands.as_slice(), [il::Operand::Reg(il::Reg::General(0)), inverse]);
        assert!(lifted.reads.is_empty(), "no register is read");
        // `mvn r1, r2` stays a not.
        assert_eq!(lift_one([0x02, 0x10, 0xe0, 0xe1]).op, il::Op::Not);
    }

    #[test]
    fn an_exclusive_access_is_atomic() {
        assert_eq!(lift_one(words::STREX_R1_R2_R3).op, il::Op::Atomic);
        // `ldrex r1, [r2]`
        assert_eq!(lift_one([0x9f, 0x1f, 0x92, 0xe1]).op, il::Op::Atomic);
        assert_eq!(lift_one(words::LDR_R1_R2_8).op, il::Op::Load);
    }

    /// `rsb` subtracts the other way round: `rsb r0, r1, #1` is `1 - r1`.
    #[test]
    fn a_reverse_subtract_names_its_values_in_order() {
        let general = |number| il::Operand::Reg(il::Reg::General(number));
        let lifted = lift_one([0x01, 0x00, 0x61, 0xe2]);
        assert_eq!(lifted.op, il::Op::Subtract);
        assert_eq!(lifted.operands.as_slice(), [general(0), il::Operand::Const(1), general(1)]);
    }

    /// `yaxpeax` reads no VFP or NEON load or store, so they lift from the
    /// fields [`decode_fallback`] reads.
    /// A register less or exclusive-or itself is zero, but not shifted:
    /// `eor r0, r1, r1, lsl #2` is `r1 ^ (r1 << 2)`. The lift once dropped
    /// the shift and read it as a move of zero.
    #[test]
    fn a_shifted_register_is_not_itself() {
        // eor r0, r1, r1, lsl #2 and eor r0, r1, r1.
        let shifted = lift_one(0xe021_0101_u32.to_le_bytes());
        let shift =
            il::Operand::Shifted { reg: il::Reg::General(1), shift: il::Shift::Left, amount: 2 };
        assert_eq!(shifted.operands[2], shift);
        assert_eq!(shifted.canonical().op, il::Op::Xor);
        assert_eq!(lift_one(0xe021_0001_u32.to_le_bytes()).canonical().op, il::Op::Move);
    }

    #[test]
    fn a_vfp_load_and_store_lift() {
        // `vldr d16, [pc, 0x90]`, as GCC loads a double from its pool.
        let load = lift_fallback(0xeddf_0b24, Encoding::A32).expect("vldr lifts");
        assert_eq!(load.op, il::Op::Load);
        assert_eq!(load.memory.and_then(|access| access.width), Some(il::Width::Bits64));
        let pool = il::Operand::memory(Some(il::Reg::ProgramCounter), Some(0x90));
        assert_eq!(load.operands.as_slice(), [il::Operand::Reg(il::Reg::Vector(16)), pool]);
        assert_eq!(load.writes, [il::Reg::Vector(16)].into_iter().collect());
        // `vstr s0, [sp, -0x4]`
        let store = lift_fallback(0xed0d_0a01, Encoding::A32).expect("vstr lifts");
        assert_eq!(store.op, il::Op::Store);
        let slot = il::Operand::memory(Some(il::Reg::Stack), Some(-4));
        assert_eq!(store.operands[1], slot);
        assert_eq!(store.reads, [il::Reg::Stack, il::Reg::Vector(0)].into_iter().collect());
        assert!(store.writes.is_empty());
    }

    #[test]
    fn a_neon_load_writes_its_list_and_steps_its_base() {
        // `vld1.8 {d16, d17}, [r0]!`
        let load = lift_fallback(0xf460_0a0d, Encoding::A32).expect("vld1 lifts");
        assert_eq!(load.op, il::Op::Load);
        assert_eq!(load.memory.and_then(|access| access.width), Some(il::Width::Bits8));
        let base = il::Operand::Memory {
            base: Some(il::Reg::General(0)),
            offset: Some(0),
            index: None,
            update: il::Update::After,
        };
        let list = [il::Reg::Vector(16), il::Reg::Vector(17)].into_iter().collect();
        assert_eq!(load.operands.as_slice(), [il::Operand::RegisterList(list), base]);
        let written = [il::Reg::General(0), il::Reg::Vector(16), il::Reg::Vector(17)];
        assert_eq!(load.writes, written.into_iter().collect());
    }

    /// A hint talks to the system: it reads no memory and names nothing.
    /// On a condition, it reads the flags.
    #[test]
    fn a_hint_lifts_to_the_system() {
        for (word, name) in [(0xe320_f000, "nop"), (0xe320_f004, "sev")] {
            let lifted = lift_fallback(word, Encoding::A32).expect(name);
            assert_eq!((lifted.op, lifted.memory), (il::Op::System, None), "{name}");
            assert!(lifted.operands.is_empty() && lifted.reads.is_empty(), "{name}");
        }
        let conditional = lift_fallback(0x0320_f004, Encoding::A32).expect("seveq");
        assert!(conditional.reads.contains(il::Reg::Flags));
    }

    #[test]
    fn what_the_fallback_lifts_it_decodes() {
        bolero::check!().with_type::<u32>().for_each(|&word| {
            if lift_fallback(word, Encoding::A32).is_some() {
                assert!(decode_fallback(word, Encoding::A32).is_some(), "{word:#010x}");
            }
        });
    }

    fn fallback_text(word: u32) -> Option<String> {
        decode_fallback(word, Encoding::A32).map(|(name, operands, _)| format!("{name} {operands}"))
    }

    /// Words `yaxpeax` 0.4 refuses, as `llvm-mc` reads them.
    #[test]
    fn reads_the_integer_words_the_decoder_refuses() {
        assert_eq!(fallback_text(0xe6ef_3073).as_deref(), Some("uxtb r3, r3"));
        assert_eq!(fallback_text(0xe6af_307e).as_deref(), Some("sxtb r3, lr"));
        assert_eq!(fallback_text(0xe6ff_0070).as_deref(), Some("uxth r0, r0"));
        assert_eq!(fallback_text(0xe7df_171f).as_deref(), Some("bfc r1, 0xe, 0x12"));
        assert_eq!(fallback_text(0xe7d6_3712).as_deref(), Some("bfi r3, r2, 0xe, 0x9"));
        assert_eq!(fallback_text(0xe7e8_0757).as_deref(), Some("ubfx r0, r7, 0xe, 0x9"));
        assert_eq!(fallback_text(0xe1a0_0011).as_deref(), Some("mov r0, r1, lsl r0"));
        assert_eq!(fallback_text(0xe1e0_a31c).as_deref(), Some("mvn sl, ip, lsl r3"));
        assert_eq!(fallback_text(0xe1d2_20d0).as_deref(), Some("ldrsb r2, [r2]"));
    }

    /// A wide T32 word is no A32 integer word, whatever its bits.
    #[test]
    fn a_t32_word_is_not_read_as_an_a32_integer_word() {
        assert!(decode_fallback(0xe6ef_3073, Encoding::T32).is_none());
        assert!(lift_fallback(0xe6ef_3073, Encoding::T32).is_none());
    }

    #[test]
    fn the_integer_words_lift() {
        let general = |number| il::Operand::Reg(il::Reg::General(number));
        let lift = |word| lift_fallback(word, Encoding::A32).expect("the word lifts");
        let extend = lift(0xe6ef_3073);
        assert_eq!(
            (extend.op, extend.operands.as_slice()),
            (il::Op::Extend, &[general(3), general(3)][..])
        );
        let insert = lift(0xe7d6_3712);
        assert_eq!(insert.op, il::Op::BitField);
        assert_eq!(insert.reads, [2, 3].map(il::Reg::General).into_iter().collect(), "keeps rd");
        let extract = lift(0xe7e8_0757);
        let field = [general(0), general(7), il::Operand::Const(14), il::Operand::Const(9)];
        assert_eq!(extract.operands.as_slice(), field);
        let shift = lift(0xe1a0_0011);
        assert_eq!(
            (shift.op, shift.operands.as_slice()),
            (il::Op::ShiftLeft, &[general(0), general(1), general(0)][..])
        );
        let load = lift(0xe1d2_20d0);
        assert_eq!(load.memory.and_then(|access| access.width), Some(il::Width::Bits8));
        let at = il::Operand::memory(Some(il::Reg::General(2)), Some(0));
        assert_eq!(load.operands.as_slice(), [general(2), at]);
    }

    /// A conditional word reads the flags.
    #[test]
    fn a_conditional_integer_word_reads_the_flags() {
        // `uxtbne r3, r3`
        let lifted = lift_fallback(0x16ef_3073, Encoding::A32).expect("the word lifts");
        assert!(lifted.reads.contains(il::Reg::Flags));
        assert_eq!(fallback_text(0x16ef_3073).as_deref(), Some("uxtbne r3, r3"));
    }

    /// `yaxpeax` swaps `bb` and `tt` of the multiplies of halfwords, and
    /// reads `smulwb` as `smlawb`; all 16 forms read as `llvm-mc` reads
    /// them.
    #[test]
    fn the_multiplies_of_halfwords_read_as_encoded() {
        let cases = [
            (0xe107_3182, "smlabb r7, r2, r1, r3"),
            (0xe107_31a2, "smlatb r7, r2, r1, r3"),
            (0xe107_31c2, "smlabt r7, r2, r1, r3"),
            (0xe107_31e2, "smlatt r7, r2, r1, r3"),
            (0xe127_3182, "smlawb r7, r2, r1, r3"),
            (0xe127_31a2, "smulwb r7, r2, r1"),
            (0xe127_31c2, "smlawt r7, r2, r1, r3"),
            (0xe127_31e2, "smulwt r7, r2, r1"),
            (0xe147_3182, "smlalbb r3, r7, r2, r1"),
            (0xe147_31a2, "smlaltb r3, r7, r2, r1"),
            (0xe147_31c2, "smlalbt r3, r7, r2, r1"),
            (0xe147_31e2, "smlaltt r3, r7, r2, r1"),
            (0xe167_3182, "smulbb r7, r2, r1"),
            (0xe167_31a2, "smultb r7, r2, r1"),
            (0xe167_31c2, "smulbt r7, r2, r1"),
            (0xe167_31e2, "smultt r7, r2, r1"),
        ];
        for (word, text) in cases {
            let insn = Arm32.decode(&u32::to_le_bytes(word), 0, 0).expect("the word reads");
            assert_eq!(insn.to_string(), text, "{word:#010x}");
        }
        let lift = |word: u32| {
            let bytes = word.to_le_bytes();
            Arm32.lift(&Arm32.decode(&bytes, 0, 0).unwrap()).expect("the word lifts")
        };
        let general = il::Reg::General;
        // `smulwb r7, r2, r1` multiplies and adds nothing.
        let word = lift(0xe127_31a2);
        assert_eq!(word.op, il::Op::Multiply);
        assert_eq!(word.reads, [general(2), general(1)].into_iter().collect());
        // `smlalbb r3, r7, r2, r1` adds to the pair, and writes both.
        let long = lift(0xe147_3182);
        assert_eq!(long.op, il::Op::MultiplyAdd);
        assert_eq!(long.writes, [general(3), general(7)].into_iter().collect());
        assert_eq!(
            long.reads,
            [general(1), general(2), general(3), general(7)].into_iter().collect()
        );
    }

    /// A NEON load names the alignment it asserts, as `llvm-mc` reads it:
    /// whole structures, all lanes and one lane. A sweep of 510 encodings
    /// agreed with `llvm-mc` when this was written.
    #[test]
    fn a_neon_load_names_its_alignment() {
        let cases = [
            (0xf423_0a0f, "vld1.8 {d0, d1}, [r3]"),
            (0xf423_0a1f, "vld1.8 {d0, d1}, [r3:64]"),
            (0xf423_0a2f, "vld1.8 {d0, d1}, [r3:128]"),
            (0xf423_023f, "vld1.8 {d0, d1, d2, d3}, [r3:256]"),
            (0xf4a3_0f9f, "vld4.32 {d0[], d1[], d2[], d3[]}, [r3:64]"),
            (0xf4a3_0c5f, "vld1.16 {d0[]}, [r3:16]"),
            (0xf4a3_041f, "vld1.16 {d0[0]}, [r3:16]"),
            (0xf4a3_0baf, "vld4.32 {d0[1], d1[1], d2[1], d3[1]}, [r3:128]"),
        ];
        for (word, text) in cases {
            assert_eq!(fallback_text(word).as_deref(), Some(text), "{word:#010x}");
        }
    }

    /// VFP words `yaxpeax` 0.4 refuses, as `llvm-mc` reads them.
    #[test]
    fn reads_the_vfp_words_the_decoder_refuses() {
        let cases = [
            (0xeebd_0be0, "vcvt.s32.f64 s0, d16"),
            (0xeef8_0bc0, "vcvt.f64.s32 d16, s0"),
            (0xeef8_0b40, "vcvt.f64.u32 d16, s0"),
            (0xeef5_0b40, "vcmp.f64 d16, 0x0"),
            (0xee40_1ba2, "vmla.f64 d17, d16, d18"),
            (0xec51_0b30, "vmov r0, r1, d16"),
            (0xec41_0b30, "vmov d16, r0, r1"),
            (0xee10_0a10, "vmov r0, s0"),
            (0xee00_1a10, "vmov s0, r1"),
            (0xeef1_fa10, "vmrs APSR_nzcv, fpscr"),
            (0xed2d_8b04, "vpush {d8, d9}"),
            (0xecbd_8b04, "vpop {d8, d9}"),
            (0xeef7_0a00, "vmov.f32 s1, #1.0"),
            (0xeeb8_0b00, "vmov.f64 d0, #-2.0"),
            (0xeef0_0b48, "vmov.f64 d16, d8"),
        ];
        for (word, text) in cases {
            assert_eq!(fallback_text(word).as_deref(), Some(text), "{word:#010x}");
        }
    }

    /// `yaxpeax` reads these words but drops an operand, so the decoder
    /// reads them itself, in A32 and in T32.
    #[test]
    fn the_vfp_words_the_decoder_misreads_keep_their_operands() {
        let cases = [
            (0xeef7_0a00_u32, "vmov.f32", "s1, #1.0"),
            (0xeef0_0b48, "vmov.f64", "d16, d8"),
            (0xeeb8_0b40, "vcvt.f64.u32", "d0, s0"),
            (0x1eb7_0b00, "vmov.f64ne", "d0, #1.0"),
        ];
        for (word, name, operands) in cases {
            let insn = Arm32.decode(&word.to_le_bytes(), 0, 0).expect("the word reads");
            assert_eq!(insn.to_string(), format!("{name} {operands}"));
            if word >> 28 == 0b1110 {
                let halves = [(word >> 16) as u16, word as u16];
                let bytes: Vec<u8> = halves.iter().flat_map(|half| half.to_le_bytes()).collect();
                let insn = super::super::thumb::Thumb2.decode(&bytes, 0, 0).expect("reads");
                assert_eq!(insn.to_string(), format!("{name} {operands}"));
            }
        }
        let constant = Arm32
            .lift(&Arm32.decode(&0xeef7_0a00_u32.to_le_bytes(), 0, 0).unwrap())
            .expect("the word lifts");
        assert_eq!(constant.op, il::Op::Move);
        assert_eq!(
            constant.operands.as_slice(),
            [il::Operand::Reg(il::Reg::Vector(1)), il::Operand::Const(0x3f80_0000)]
        );
        assert_eq!(constant.writes, [il::Reg::Vector(1)].into_iter().collect());
    }

    /// Each of the 256 constants of a VFP `vmov` stands for the same value
    /// as a single and as a double: a sign, then 16 to 31 sixteenths times
    /// a power of two from 2^-3 to 2^4.
    #[test]
    fn a_vfp_constant_is_the_same_value_at_both_sizes() {
        for constant in 0..=255 {
            let single = f64::from(f32::from_bits(expand_float_constant(constant, false) as u32));
            let double = f64::from_bits(expand_float_constant(constant, true));
            assert_eq!(single, double, "{constant:#x}");
            let exponent = (i32::from((constant >> 4 & 0b111) as u8) ^ 0b100) - 3;
            let sixteenths = f64::from(16 + (constant & 0b1111));
            let sign = if constant >> 7 == 1 { -1.0 } else { 1.0 };
            assert_eq!(double, sign * sixteenths / 16.0 * 2f64.powi(exponent), "{constant:#x}");
        }
    }

    /// T32 encodes the VFP as A32 does, so a T32 caller reads them too.
    #[test]
    fn a_t32_vfp_word_reads_as_its_a32_twin() {
        assert_eq!(
            decode_fallback(0xec51_0b30, Encoding::T32),
            decode_fallback(0xec51_0b30, Encoding::A32)
        );
        assert!(lift_fallback(0xec51_0b30, Encoding::T32).is_some());
    }

    #[test]
    fn the_vfp_words_lift() {
        let core = |number| il::Reg::General(number);
        let vector = il::Reg::Vector;
        let regs = |regs: &[il::Reg]| -> il::RegSet { regs.iter().copied().collect() };
        let lift = |word| lift_fallback(word, Encoding::A32).expect("the word lifts");
        // `vmov d16, r0, r1` writes the double from the pair.
        let to_double = lift(0xec41_0b30);
        assert_eq!(to_double.op, il::Op::Move);
        assert_eq!(
            (to_double.reads, to_double.writes),
            (regs(&[core(0), core(1)]), regs(&[vector(16)]))
        );
        // `vmov r0, r1, d16` writes the pair.
        let to_core = lift(0xec51_0b30);
        assert_eq!(
            (to_core.reads, to_core.writes),
            (regs(&[vector(16)]), regs(&[core(0), core(1)]))
        );
        // `vcmp.f64 d16, #0` writes only the VFP flags, and `vmrs` moves them.
        let compare = lift(0xeef5_0b40);
        assert_eq!(compare.op, il::Op::Float, "never an integer compare");
        assert_eq!((compare.reads, compare.writes), (regs(&[vector(16)]), il::RegSet::EMPTY));
        assert!(lift(0xeef1_fa10).writes.contains(il::Reg::Flags));
        // `vpush {d8, d9}` stores below `sp` and moves it.
        let push = lift(0xed2d_8b04);
        assert_eq!(push.op, il::Op::Store);
        let below = il::Operand::Memory {
            base: Some(il::Reg::Stack),
            offset: Some(-16),
            index: None,
            update: il::Update::Before,
        };
        let list = regs(&[vector(8), vector(9)]);
        assert_eq!(push.operands.as_slice(), [il::Operand::RegisterList(list), below]);
        assert_eq!(push.reads, regs(&[il::Reg::Stack, vector(8), vector(9)]));
        assert_eq!(push.writes, regs(&[il::Reg::Stack]));
        // `vcvt.s32.f64 s0, d16` converts into the single register.
        let convert = lift(0xeebd_0be0);
        assert_eq!(
            convert.operands.as_slice(),
            [il::Operand::Reg(vector(0)), il::Operand::Reg(vector(16))]
        );
    }

    #[test]
    fn a_vfp_operation_names_what_it_computes() {
        let op = |word| lift_fallback(word, Encoding::A32).expect("the word lifts").op;
        assert_eq!(op(0xee40_1ba2), il::Op::FloatMultiplyAdd, "vmla.f64");
        assert_eq!(op(0xeebd_0be0), il::Op::FloatRoundTowardZero, "vcvt.s32.f64");
        assert_eq!(op(0xeef8_0bc0), il::Op::FloatConvert, "vcvt.f64.s32");
        assert_eq!(op(0xeef5_0b40), il::Op::Float, "vcmp.f64");
    }

    #[test]
    fn a_function_opens_with_a_word_that_runs_always() {
        assert!(Arm32.can_open_function(&words::PUSH_R4_LR));
        assert!(!Arm32.can_open_function(&words::ADDEQ_R0), "conditional");
        assert!(!Arm32.can_open_function(&[0, 0]), "short");
    }
}
