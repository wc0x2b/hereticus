//! The rules that find functions in x86 code, in 64-bit and 32-bit mode.
//!
//! An instruction is 1 to 15 bytes, so code is read from a known start and
//! never by fixed words. x86 keeps no data among its code: a `switch` jumps
//! through a table in `.rodata`, and x86-64 code forms an address as a
//! distance from the next instruction,
//!
//! ```text
//! lea rdi, [rip + 0x2f1a]   ; the data itself
//! mov rax, [rip + 0x2fe1]   ; a slot of the global offset table
//! ```
//!
//! so that distance moves with the data it names. 32-bit code that is not
//! PIC names the address whole, as an immediate or an absolute operand. The
//! unwind tables are `.eh_frame`, which the scan reads for any architecture.

use super::{CallTarget, Insn, InsnKind, JumpTable, Memory, Recovery, leaves};
use core::ops::Range;
use hereticus_il::arch::Decoder as _;
use hereticus_il::arch::x86::{
    MOST_BYTES, Mode, X86, il_register, instruction, lift as x86_lift, mode_of,
};
use hereticus_il::{Reg, RegSet};
use hereticus_memory::AddressSpace;
use iced_x86::{ConditionCode, Mnemonic, OpKind, Register};

/// `endbr64`, which marks where an indirect branch may land.
const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];

/// `endbr32`, the same in 32-bit code.
const ENDBR32: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfb];

/// `int3`, which clang and MSVC pad between functions with.
const INT3: u8 = 0xcc;

/// How far back the parts of a table jump may lie.
const TABLE_LOOK_BACK: usize = 16;

/// More cases than any `switch` a compiler turns into one table.
const MOST_CASES: u64 = 4096;

/// How far back the parts of the setup of the global offset table may lie.
const SETUP_LOOK_BACK: usize = 8;

/// The bytes of an entry of the PLT.
const PLT_ENTRY: u64 = 16;

/// The width of an entry of a table of distances.
const ENTRY_WIDTH: u64 = 4;

impl Recovery for X86 {
    /// Code built with `-fcf-protection`, the default of most Linux
    /// distributions, opens each function that a pointer can reach with
    /// `endbr64`. `push rbp` is no such mark: optimized code pushes it among
    /// the other registers a call preserves, after the first of them.
    fn is_prologue(&self, insn: &Insn) -> bool {
        is_branch_target_mark(insn)
    }

    fn may_be_prologue(&self, word: &[u8]) -> bool {
        word.starts_with(&ENDBR64) || word.starts_with(&ENDBR32)
    }

    /// `nop` in each of its lengths, `int3`, and the forms that only move a
    /// register to itself, which old GNU `as` pads 32-bit code with.
    fn is_padding(&self, insn: &Insn) -> bool {
        let Some(inst) = instruction(insn) else { return false };
        match inst.mnemonic() {
            Mnemonic::Nop | Mnemonic::Int3 => true,
            // `66 90`, the two-byte `nop`, reads as `xchg ax, ax`.
            Mnemonic::Xchg => {
                inst.op_count() == 2
                    && inst.op0_kind() == OpKind::Register
                    && inst.op1_kind() == OpKind::Register
                    && inst.op0_register() == Register::AX
                    && inst.op1_register() == Register::AX
            }
            // `lea esi, [esi + 0]`, with or without a zero index.
            Mnemonic::Lea => {
                inst.op0_register() == inst.memory_base()
                    && inst.memory_displacement64() == 0
                    && inst.memory_index() == Register::None
            }
            // `mov esi, esi` is padding only in 32-bit mode: in 64-bit mode
            // it clears the upper half of `rsi`.
            Mnemonic::Mov => {
                mode_of(insn) == Some(Mode::Bits32)
                    && inst.op_count() == 2
                    && inst.op0_kind() == OpKind::Register
                    && inst.op1_kind() == OpKind::Register
                    && inst.op0_register() == inst.op1_register()
            }
            _ => false,
        }
    }

    /// A variable width cannot be read backward, so this reads forward and
    /// ends after the last instruction that is not padding.
    fn trim_padding<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        let mut end = 0;
        let mut offset = 0;
        while offset < bytes.len() {
            let Ok(insn) = self.decode(bytes, offset, 0) else { break };
            offset += insn.bytes_len;
            if !self.is_padding(&insn) {
                end = offset;
            }
        }
        // A padding byte past the last instruction that decodes is padding
        // too; anything else stays, so that no code is lost.
        if offset < bytes.len() && bytes[offset..].iter().any(|&byte| byte != INT3) {
            return bytes;
        }
        &bytes[..end]
    }

    /// The addresses each instruction forms, and the pointers it loads from
    /// a slot where they point into the image: a text that only a table of
    /// pointers reaches is a text of the function too. A table of cases is
    /// no text: its distances move whenever the code does.
    fn data_addresses(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        memory: &Memory<'_>,
    ) -> Vec<u64> {
        let width = self.pointer_width();
        let tables: Vec<u64> = match (body.first(), body.last()) {
            (Some(first), Some(last)) => {
                let code = first.address..last.address + last.bytes_len as u64;
                self.jump_tables(memory, code, body).iter().map(|table| table.words.start).collect()
            }
            _ => Vec::new(),
        };
        // A distance from the global offset table is no address alone.
        let from_table = global_offset_table_uses(body);
        body.iter()
            .zip(from_table)
            .filter(|&(_, from_table)| !from_table)
            .map(|(insn, _)| insn)
            .filter(|insn| !matches!(insn.kind, InsnKind::Call { .. } | InsnKind::Jump { .. }))
            .filter_map(|insn| formed_address(insn, space))
            .filter(|address| !tables.contains(address))
            .flat_map(|address| {
                let loaded = memory
                    .bytes(address, width)
                    .map(|bytes| self.read_pointer(bytes))
                    .filter(|&pointer| pointer != address && space.contains_formed(pointer));
                core::iter::once(address).chain(loaded)
            })
            .filter(|&address| space.contains_formed(address))
            .collect()
    }

    /// A call or a jump that names its target gives it. Code built with
    /// `-fno-plt` calls an import through its slot of the global offset
    /// table, as `call [rip + slot]`. `call $+5` of 32-bit PIC only reads
    /// its own address, and calls no function.
    fn call_targets(&self, insns: &[Insn]) -> Vec<(usize, Option<CallTarget>)> {
        insns
            .iter()
            .enumerate()
            .filter(|(_, insn)| !reads_its_address(insn))
            .filter_map(|(index, insn)| match insn.kind {
                InsnKind::Call { target: Some(target) } => {
                    Some((index, Some(CallTarget::Address(target))))
                }
                InsnKind::Call { target: None } => {
                    Some((index, slot_of(insn).map(CallTarget::Slot)))
                }
                InsnKind::Jump { target: Some(target) } if leaves(insns, target) => {
                    Some((index, Some(CallTarget::Address(target))))
                }
                InsnKind::Jump { target: None } => {
                    slot_of(insn).map(|slot| (index, Some(CallTarget::Slot(slot))))
                }
                _ => None,
            })
            .collect()
    }

    /// The stubs GNU `ld` and LLD write for each PLT entry: a jump through
    /// a slot of the global offset table, after `endbr64` where the code
    /// is built for it.
    ///
    /// ```text
    /// endbr64                 ; .plt.sec, with -fcf-protection
    /// bnd jmp [rip + slot]
    /// ```
    ///
    /// 32-bit PIC jumps through `[ebx + offset]`, and the address in `ebx`
    /// is not in the stub, so only the absolute form is read there.
    fn stub_slot(&self, code: &[u8], address: u64) -> Option<u64> {
        // The scan asks at the target of every jump, so bytes that open no
        // stub end the question before anything decodes.
        let skip = if self.may_be_prologue(code) { ENDBR64.len() } else { 0 };
        let jump = code.get(skip..)?;
        let opens_a_jump = matches!(jump, [0xff, 0x25, ..] | [0xf2, 0xff, 0x25, ..]);
        if !opens_a_jump {
            return None;
        }
        let jump = &jump[..jump.len().min(MOST_BYTES)];
        let insn = self.decode(jump, 0, address + skip as u64).ok()?;
        slot_of(&insn)
    }

    /// Clang and GCC jump through a table of distances from the table
    /// itself, in `.rodata`, where they build for PIC:
    ///
    /// ```text
    /// cmp    edi, 5                     ; the last case
    /// ja     default
    /// lea    rcx, [rip + table]
    /// movsxd rax, dword ptr [rcx + 4*rax]
    /// add    rax, rcx
    /// jmp    rax
    /// ```
    fn jump_tables(&self, memory: &Memory<'_>, code: Range<u64>, insns: &[Insn]) -> Vec<JumpTable> {
        (0..insns.len()).filter_map(|index| read_jump_table(memory, &code, insns, index)).collect()
    }

    /// GNU `ld` and LLD write each entry of `.plt`, `.plt.sec` and
    /// `.plt.got` in 16 bytes, the first of `.plt` too.
    fn plt_entry_size(&self) -> Option<u64> {
        Some(PLT_ENTRY)
    }

    /// 32-bit PIC finds the table in `ebx`, which the caller set:
    ///
    /// ```text
    /// endbr32                  ; with -fcf-protection
    /// jmp  [ebx + 0xc]
    /// ```
    fn stub_table_offset(&self, code: &[u8]) -> Option<u64> {
        let (insns, _) = super::decode_all(self, &code[..code.len().min(2 * MOST_BYTES)], 0);
        let jump_at = usize::from(insns.first().is_some_and(is_branch_target_mark));
        let jump = insns.get(jump_at)?;
        let inst = instruction(jump)?;
        let through_the_table = mode_of(jump) == Some(Mode::Bits32)
            && jump.kind == (InsnKind::Jump { target: None })
            && inst.op0_kind() == OpKind::Memory
            && inst.memory_base() == Register::EBX
            && inst.memory_index() == Register::None;
        through_the_table.then(|| inst.memory_displacement64() & 0xffff_ffff)
    }

    /// A jump through a slot of the global offset table leaves the
    /// function. A `switch` jumps through a register or a table with an
    /// index, and stays.
    fn is_tail_call(&self, insn: &Insn) -> bool {
        slot_of(insn).is_some()
    }
}

/// The table that the jump at `index` of `insns` goes through, where it is
/// one: see [`Recovery::jump_tables`].
fn read_jump_table(
    memory: &Memory<'_>,
    code: &Range<u64>,
    insns: &[Insn],
    index: usize,
) -> Option<JumpTable> {
    let jump = &insns[index];
    if jump.kind != (InsnKind::Jump { target: None }) {
        return None;
    }
    let jump_inst = instruction(jump)?;
    if jump_inst.op0_kind() != OpKind::Register {
        return None;
    }
    let earlier = &insns[index.saturating_sub(TABLE_LOOK_BACK)..index];
    let decoded: Vec<iced_x86::Instruction> = earlier.iter().filter_map(instruction).collect();
    if decoded.len() != earlier.len() {
        return None;
    }
    let target = jump_inst.op0_register().full_register();
    let writes = |inst: &iced_x86::Instruction, register: Register| {
        inst.op_count() >= 1
            && inst.op0_kind() == OpKind::Register
            && inst.op0_register().full_register() == register
    };
    // The last write of each register before `before`, by position.
    let last_write = |register: Register, before: usize| {
        (0..before).rev().find(|&at| writes(&decoded[at], register))
    };
    // `add rax, rcx`: the entry and the table.
    let add_at = last_write(target, decoded.len())?;
    let add = &decoded[add_at];
    if add.mnemonic() != Mnemonic::Add || add.op1_kind() != OpKind::Register {
        return None;
    }
    let table_register = add.op1_register().full_register();
    // `movsxd rax, dword ptr [rcx + 4*rax]`, or in 32-bit PIC
    // `mov eax, dword ptr [ebx + 4*eax - 0x31e88]`: one entry.
    let load_at = last_write(target, add_at)?;
    let load = &decoded[load_at];
    let loads_an_entry = matches!(load.mnemonic(), Mnemonic::Movsxd | Mnemonic::Mov)
        && load.op1_kind() == OpKind::Memory
        && load.memory_base().full_register() == table_register
        && load.memory_index_scale() == ENTRY_WIDTH as u32;
    if !loads_an_entry {
        return None;
    }
    // Where the table lies, and what each distance in it is from.
    let (table, from) = match load.mnemonic() {
        // `lea rcx, [rip + table]`, and distances from the table.
        Mnemonic::Movsxd if load.memory_displacement64() == 0 => {
            let lea = &decoded[last_write(table_register, load_at)?];
            if lea.mnemonic() != Mnemonic::Lea || !lea.is_ip_rel_memory_operand() {
                return None;
            }
            let table = lea.ip_rel_memory_address();
            (table, table)
        }
        // The register holds the global offset table, and the distances
        // are from it.
        Mnemonic::Mov if mode_of(jump) == Some(Mode::Bits32) => {
            let global = table_before(insns, index)?;
            (global.wrapping_add(load.memory_displacement64()) & 0xffff_ffff, global)
        }
        _ => return None,
    };
    let index_register = load.memory_index().full_register();
    let masked = last_write(index_register, load_at)
        .map(|at| &decoded[at])
        .filter(|inst| inst.mnemonic() == Mnemonic::And)
        .and_then(constant_operand)
        .filter(|mask| (mask + 1).is_power_of_two());
    let cases = match masked {
        // `and eax, 3`: the cases run from 0 to the mask.
        Some(mask) => mask + 1,
        None => cases_before(&earlier[..load_at], &decoded[..load_at])?,
    };
    if !(1..=MOST_CASES).contains(&cases) {
        return None;
    }

    let mut targets = Vec::new();
    for case in 0..cases {
        let bytes = memory.bytes(table + case * ENTRY_WIDTH, ENTRY_WIDTH as usize)?;
        let distance = i32::from_le_bytes(bytes.try_into().ok()?);
        let target = from.checked_add_signed(i64::from(distance))?;
        if !code.contains(&target) {
            return None;
        }
        targets.push(target);
    }
    Some(JumpTable { jump: jump.address, words: table..table + cases * ENTRY_WIDTH, targets })
}

/// How many cases the last bound before a table jump admits: a `cmp` of a
/// constant, and an unsigned branch on it.
fn cases_before(earlier: &[Insn], decoded: &[iced_x86::Instruction]) -> Option<u64> {
    let branch_at =
        earlier.iter().rposition(|insn| matches!(insn.kind, InsnKind::Branch { .. }))?;
    let compare =
        decoded[..branch_at].iter().rev().find(|inst| inst.mnemonic() == Mnemonic::Cmp)?;
    let bound = constant_operand(compare)?;
    // The jump over the table, or to it.
    let cases = match decoded[branch_at].condition_code() {
        ConditionCode::a | ConditionCode::be => bound.checked_add(1)?,
        ConditionCode::ae | ConditionCode::b => bound,
        _ => return None,
    };
    Some(cases)
}

/// The constant that the second operand of `inst` is, where it is one.
fn constant_operand(inst: &iced_x86::Instruction) -> Option<u64> {
    match inst.op1_kind() {
        OpKind::Immediate8
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32
        | OpKind::Immediate32to64 => Some(inst.immediate(1) & 0xffff_ffff),
        _ => None,
    }
}

/// Whether `insn` is `call $+5`, which pushes the address after it for a
/// `pop` to read.
fn reads_its_address(insn: &Insn) -> bool {
    insn.kind == (InsnKind::Call { target: Some(insn.address + insn.bytes_len as u64) })
}

/// Whether `insn` is `endbr64` or `endbr32`.
pub fn is_branch_target_mark(insn: &Insn) -> bool {
    instruction(insn)
        .is_some_and(|inst| matches!(inst.mnemonic(), Mnemonic::Endbr64 | Mnemonic::Endbr32))
}

/// The slot a call or a jump through memory reads its target from, where
/// the slot is a fixed address: `[rip + distance]`, or an absolute address
/// with no register in 32-bit code.
pub fn slot_of(insn: &Insn) -> Option<u64> {
    if !matches!(insn.kind, InsnKind::Call { target: None } | InsnKind::Jump { target: None }) {
        return None;
    }
    let inst = instruction(insn)?;
    if inst.op0_kind() != OpKind::Memory || inst.memory_index() != Register::None {
        return None;
    }
    match inst.memory_base() {
        base if base.is_ip() => Some(inst.ip_rel_memory_address()),
        Register::None => Some(inst.memory_displacement64()),
        _ => None,
    }
}

/// The address `insn` forms or reads at, where its code shows one: a
/// distance from `rip`, which is always an address, or a constant or an
/// absolute operand inside `space`, as code that is not PIC holds.
pub fn formed_address(insn: &Insn, space: &AddressSpace) -> Option<u64> {
    let inst = instruction(insn)?;
    if inst.is_ip_rel_memory_operand() {
        return Some(inst.ip_rel_memory_address());
    }
    (0..inst.op_count()).find_map(|index| {
        let value = match inst.op_kind(index) {
            OpKind::Memory if inst.memory_base() == Register::None => inst.memory_displacement64(),
            OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate64 => {
                inst.immediate(index)
            }
            _ => return None,
        };
        let value = match mode_of(insn) {
            Some(Mode::Bits32) => value & 0xffff_ffff,
            _ => value,
        };
        space.contains(value).then_some(value)
    })
}

/// For each instruction of `body`, whether its constant is a distance from
/// the global offset table, which moves whenever the data it reaches does.
///
/// 32-bit PIC has no `rip` to reach data from, so a function reads its own
/// address and adds the distance to the table, in one of two forms:
///
/// ```text
/// call __x86.get_pc_thunk.bx      ; GCC
/// add  ebx, 0x2e5b
///
/// call $+5                        ; clang
/// pop  ebx
/// add  ebx, 0x106ac
/// ```
///
/// The add is part of the address, and so is each offset from a register
/// that holds the table, as `lea eax, [ebx - 0x18768]`.
///
/// A register or a slot of the frame holds the table before an instruction
/// where every path to it put the table there: GCC keeps it in `ebx` for the
/// whole function, and clang spills it to a slot that later holds other
/// values, and loads it back just before it uses it.
pub fn global_offset_table_uses(body: &[Insn]) -> Vec<bool> {
    let steps: Vec<Step> = steps_of(body);
    if !steps.iter().any(|step| step.setup.is_some()) {
        return vec![false; body.len()];
    }
    // Code that nothing reaches opens a path of its own where it is a
    // function that a scan with no unwind table merged into the one before.
    let next = nearest_cases(body);
    let mut reached = vec![false; body.len()];
    next.iter().flatten().for_each(|&successor| reached[successor] = true);
    // Only code that makes the table in its first block is a function: a
    // case laid out before the jump that dispatches it is reached too, by a
    // path this walk cannot see.
    let sets_up_first = |index: usize| {
        let block_end = (index..body.len())
            .find(|&at| !matches!(body[at].kind, InsnKind::Normal | InsnKind::Call { .. }))
            .unwrap_or(body.len());
        steps[index..block_end].iter().any(|step| step.setup.is_some())
    };
    let entries: Vec<usize> = (0..body.len())
        .filter(|&index| index == 0 || (!reached[index] && sets_up_first(index)))
        .collect();
    let held = hereticus_il::flow::held_on_every_path_from(&next, &entries, |index, held| {
        step_holders(&steps[index], held);
    });
    steps
        .iter()
        .zip(&held)
        .map(|(step, held)| {
            step.setup.is_some()
                || step.base.is_some_and(|base| held.contains_key(&Holder::Register(base)))
        })
        .collect()
}

/// What [`global_offset_table_uses`] reads of one instruction.
struct Step {
    /// The register the instruction leaves the table in, where it ends the
    /// setup.
    setup: Option<Reg>,
    /// The register it forms an address from: the base of its memory
    /// operand, or the register it adds a constant to, as
    /// `add edi, 0xfffe9dde` does to a copy of the table.
    base: Option<Reg>,
    /// Where it moves a value to, and from where.
    to: Holder,
    from: Holder,
    /// The registers it writes, with those a call may change.
    writes: RegSet,
    /// Whether what it writes counts against a holder of the table.
    writes_count: WritesCount,
    /// The register it writes and the one it reads, where it adds a scaled
    /// index to a register and nothing else, as `lea edi, [edx + 2*ecx]`
    /// does. From the table, that leaves the distance still to add.
    indexed: Option<(Reg, Reg)>,
}

/// Whether what an instruction writes counts against a holder of the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WritesCount {
    /// It counts.
    Yes,
    /// It does not: a `pop` in an epilogue gives the caller back its own
    /// value, which no code of the function reads after it, and the `pop`
    /// of clang's setup is the first half of the table.
    No,
}

/// Read each instruction of `body` once.
fn steps_of(body: &[Insn]) -> Vec<Step> {
    let moved = stack_offsets(body);
    body.iter()
        .enumerate()
        .map(|(index, insn)| {
            let setup = table_setup(&body[..=index]).map(|(register, _)| register);
            let Some(inst) = instruction(insn) else {
                return Step {
                    setup,
                    base: None,
                    to: Holder::None,
                    from: Holder::None,
                    writes: RegSet::EMPTY,
                    writes_count: WritesCount::Yes,
                    indexed: None,
                };
            };
            let slot = frame_slot(&inst, moved[index]);
            let register_of = |operand| match inst.op_kind(operand) {
                OpKind::Register => {
                    il_register(inst.op_register(operand)).map_or(Holder::None, Holder::Register)
                }
                OpKind::Memory => slot.map_or(Holder::None, Holder::Slot),
                _ => Holder::None,
            };
            let pushed = moved[index]
                .map(|moved| (Reg::Stack, moved + i64::from(inst.stack_pointer_increment())));
            let (to, from) = match inst.mnemonic() {
                Mnemonic::Mov => (register_of(0), register_of(1)),
                Mnemonic::Push => (pushed.map_or(Holder::None, Holder::Slot), register_of(0)),
                Mnemonic::Pop => {
                    let popped = moved[index].map(|moved| (Reg::Stack, moved));
                    (register_of(0), popped.map_or(Holder::None, Holder::Slot))
                }
                _ => (Holder::None, Holder::None),
            };
            let mut writes = x86_lift(&inst).writes;
            if matches!(insn.kind, InsnKind::Call { .. }) {
                // A callee may change the registers the ABI does not keep.
                (0..8)
                    .map(Reg::General)
                    .filter(|&reg| !is_preserved_by_a_call(reg))
                    .for_each(|reg| writes.insert(reg));
            }
            // `pop` after `call $+5`, the first half of clang's setup.
            let opens_setup = inst.mnemonic() == Mnemonic::Pop
                && index.checked_sub(1).is_some_and(|before| {
                    body[before].kind == (InsnKind::Call { target: Some(insn.address) })
                });
            let writes_count = match is_epilogue(&body[index..]) || opens_setup {
                true => WritesCount::No,
                false => WritesCount::Yes,
            };
            let indexed = (inst.mnemonic() == Mnemonic::Lea
                && inst.memory_index() != Register::None
                && inst.memory_displacement64() == 0)
                .then(|| {
                    Some((il_register(inst.op0_register())?, il_register(inst.memory_base())?))
                })
                .flatten();
            Step { setup, base: address_base(&inst), to, from, writes, writes_count, indexed }
        })
        .collect()
}

/// The successors of each instruction of `body`, as
/// [`hereticus_il::flow::successors`] gives them, with each instruction
/// that only a jump through a table reaches taken as a case of the nearest
/// such jump before it, as a compiler lays out a `switch`.
///
/// Taken as a case of every such jump, a case after the second `switch` of
/// `newkey` in Lua reads as reached before the code that spills the table,
/// and every use of the spill is lost.
fn nearest_cases(body: &[Insn]) -> Vec<Vec<usize>> {
    let mut next = hereticus_il::flow::successors(body, |_| 0);
    let mut nearest = None;
    let mut dispatch: Vec<Option<usize>> = Vec::with_capacity(body.len());
    for (index, insn) in body.iter().enumerate() {
        dispatch.push(nearest);
        if insn.kind == (InsnKind::Jump { target: None }) {
            nearest = Some(index);
        }
    }
    // How many edges reach each instruction from code that is no padding.
    let mut reached = vec![0usize; body.len()];
    for (from, edges) in next.iter().enumerate() {
        if !is_nop(&body[from]) {
            edges.iter().for_each(|&to| reached[to] += 1);
        }
    }
    // Padding is a case only where the code after it has no other way in:
    // before a loop it aligns the loop, which its branches reach.
    let opens_a_case = |case: usize| {
        let after = (case..body.len()).find(|&at| !is_nop(&body[at]));
        !is_nop(&body[case]) || after.is_none_or(|after| reached[after] == 0)
    };
    for (index, insn) in body.iter().enumerate() {
        if insn.kind == (InsnKind::Jump { target: None }) {
            next[index].retain(|&case| dispatch[case] == Some(index) && opens_a_case(case));
        }
    }
    next
}

/// Whether `insn` pads code: see [`Recovery::is_padding`].
fn is_nop(insn: &Insn) -> bool {
    mode_of(insn).is_some_and(|mode| X86::of(mode).is_padding(insn))
}

/// What holds the table after `step`, from what `held` held before it.
fn step_holders(step: &Step, held: &mut std::collections::HashMap<Holder, ()>) {
    if let Some(register) = step.setup {
        held.insert(Holder::Register(register), ());
        return;
    }
    // The code after a return runs as the code before the epilogue left it,
    // so an epilogue changes nothing.
    if step.writes_count == WritesCount::No {
        return;
    }
    let holds = |holder: Holder| held.contains_key(&holder);
    let moves_the_table = step.from != Holder::None && holds(step.from);
    let indexed_from_table =
        step.indexed.filter(|&(_, read)| holds(Holder::Register(read))).map(|(written, _)| written);
    for written in step.writes.iter() {
        held.remove(&Holder::Register(written));
    }
    if step.to != Holder::None {
        match moves_the_table {
            true => held.insert(step.to, ()),
            false => held.remove(&step.to),
        };
    }
    if let Some(written) = indexed_from_table {
        held.insert(Holder::Register(written), ());
    }
}

/// The register `inst` forms an address from: see [`Step::base`].
fn address_base(inst: &iced_x86::Instruction) -> Option<Reg> {
    let adds_a_constant = matches!(inst.mnemonic(), Mnemonic::Add | Mnemonic::Sub)
        && inst.op0_kind() == OpKind::Register
        && matches!(inst.op1_kind(), OpKind::Immediate32 | OpKind::Immediate8to32);
    match adds_a_constant {
        true => il_register(inst.op0_register()),
        false => il_register(inst.memory_base()),
    }
}

/// Whether `rest` opens with a `pop` or a `leave` that only more of them,
/// or a constant add to the stack pointer, separate from a return.
fn is_epilogue(rest: &[Insn]) -> bool {
    let restores = |insn: &Insn| {
        instruction(insn)
            .is_some_and(|inst| matches!(inst.mnemonic(), Mnemonic::Pop | Mnemonic::Leave))
    };
    if !rest.first().is_some_and(restores) {
        return false;
    }
    for insn in rest {
        if insn.kind == InsnKind::Return {
            return true;
        }
        let frees_the_frame = instruction(insn)
            .is_some_and(|inst| inst.mnemonic() == Mnemonic::Add)
            && stack_change(insn).is_some_and(|change| change > 0);
        if !(restores(insn) || frees_the_frame) {
            return false;
        }
    }
    false
}

/// The slot of the frame the memory operand of `inst` names, where it names
/// one: through the stack pointer, by its offset from the stack pointer at
/// the entry, where `moved` says how far that is, or through `ebp`.
fn frame_slot(inst: &iced_x86::Instruction, moved: Option<i64>) -> Option<(Reg, i64)> {
    let has_memory = (0..inst.op_count()).any(|operand| inst.op_kind(operand) == OpKind::Memory);
    if !has_memory || inst.memory_index() != Register::None {
        return None;
    }
    let offset = inst.memory_displacement64() as i64;
    match il_register(inst.memory_base())? {
        Reg::Stack => Some((Reg::Stack, moved? + offset)),
        frame @ Reg::General(5) => Some((frame, offset)),
        _ => None,
    }
}

/// How far the stack pointer has moved from the entry before each
/// instruction of `body`, where pushes, pops and constant adds say, and
/// the paths to the instruction agree.
///
/// A call to a function that never returns, as a panic of Rust, leaves its
/// arguments on the stack, and the code after it is another block that a
/// branch reaches. So where the way on from a call disagrees with a branch,
/// the branch is right.
fn stack_offsets(body: &[Insn]) -> Vec<Option<i64>> {
    let next = hereticus_il::flow::successors(body, |_| 0);
    let mut height = vec![Height::Unreached; body.len()];
    let Some(entry) = height.first_mut() else { return Vec::new() };
    *entry = Height::Known(0, Edge::Branch);
    let mut work = vec![0];
    while let Some(index) = work.pop() {
        let out = match height[index] {
            Height::Known(moved, edge) => match stack_change(&body[index]) {
                Some(change) => Height::Known(moved + change, edge),
                None => Height::Unknown,
            },
            other => other,
        };
        // `call $+5` reads its own address, and always goes on.
        let insn = &body[index];
        let after_call = match insn.kind {
            InsnKind::Call { target } => target != Some(insn.address + insn.bytes_len as u64),
            _ => false,
        };
        for &successor in &next[index] {
            // What a path after a call reaches stays as weak as the call.
            let arrives = match out {
                Height::Known(moved, _) if after_call && successor == index + 1 => {
                    Height::Known(moved, Edge::AfterCall)
                }
                other => other,
            };
            let joined = height[successor].join(arrives);
            if joined != height[successor] {
                height[successor] = joined;
                work.push(successor);
            }
        }
    }
    height
        .into_iter()
        .map(|height| match height {
            Height::Known(moved, _) => Some(moved),
            Height::Unreached | Height::Unknown => None,
        })
        .collect()
}

/// How an edge reaches an instruction, for [`stack_offsets`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Edge {
    /// The way on after a call, which may never return.
    AfterCall,
    /// A branch, a jump or the way on after another instruction.
    Branch,
}

/// What [`stack_offsets`] knows of the stack pointer before one
/// instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Height {
    /// No path reaches the instruction yet.
    Unreached,
    /// It has moved this far, as the strongest edge that reaches says.
    Known(i64, Edge),
    /// Branches disagree, or an instruction moved it by an amount the code
    /// does not show.
    Unknown,
}

impl Height {
    /// What is known where `self` and `other` meet.
    fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unreached, other) | (other, Self::Unreached) => other,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Known(left, left_edge), Self::Known(right, right_edge)) => {
                match (left == right, left_edge.cmp(&right_edge), left_edge) {
                    (true, ..) => Self::Known(left, left_edge.max(right_edge)),
                    (false, core::cmp::Ordering::Less, _) => Self::Known(right, right_edge),
                    (false, core::cmp::Ordering::Greater, _) => Self::Known(left, left_edge),
                    // Two ways on after calls disagree: a branch, which can
                    // still come, settles which is right.
                    (false, core::cmp::Ordering::Equal, Edge::AfterCall) => self,
                    (false, core::cmp::Ordering::Equal, Edge::Branch) => Self::Unknown,
                }
            }
        }
    }
}

/// How far `insn` moves the stack pointer, where it says.
fn stack_change(insn: &Insn) -> Option<i64> {
    let inst = instruction(insn)?;
    let moves_stack = inst.op_count() >= 1
        && inst.op0_kind() == OpKind::Register
        && il_register(inst.op0_register()) == Some(Reg::Stack);
    let constant = (moves_stack && inst.op_count() == 2)
        .then(|| match inst.op1_kind() {
            OpKind::Immediate8to32
            | OpKind::Immediate32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => Some(inst.immediate(1) as i64),
            _ => None,
        })
        .flatten();
    match (inst.mnemonic(), constant) {
        (Mnemonic::Sub, Some(amount)) => Some(-amount),
        (Mnemonic::Add, Some(amount)) => Some(amount),
        // `call` pushes the return address, and the callee pops it, but
        // `call $+5` only pushes its own address, for a `pop` to read.
        (Mnemonic::Call, _) if inst.near_branch_target() == inst.next_ip() => Some(-4),
        (Mnemonic::Call, _) => Some(0),
        _ if moves_stack => None,
        _ => Some(i64::from(inst.stack_pointer_increment())),
    }
}

/// What an instruction moves the table from or to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Holder {
    /// A register.
    Register(Reg),
    /// A slot of the frame.
    Slot((Reg, i64)),
    /// Nothing that can hold it, or a slot the walk cannot name.
    None,
}

/// The register the last instruction of `body` leaves the global offset
/// table in, where it is the add that ends the setup.
fn table_setup(body: &[Insn]) -> Option<(Reg, u64)> {
    let (add, before) = body.split_last()?;
    if mode_of(add) != Some(Mode::Bits32) {
        return None;
    }
    let inst = instruction(add)?;
    let adds_a_constant = inst.mnemonic() == Mnemonic::Add
        && inst.op0_kind() == OpKind::Register
        && inst.op1_kind() == OpKind::Immediate32;
    if !adds_a_constant {
        return None;
    }
    let register = il_register(inst.op0_register())?;
    // Both forms leave the address after the call in the register, and the
    // add makes the table of it.
    let table = |call: &Insn| {
        (call.address + call.bytes_len as u64).wrapping_add(inst.immediate(1)) & 0xffff_ffff
    };
    // Code that writes something else can lie between the parts, as Rust
    // schedules it.
    for (at, insn) in before.iter().enumerate().rev().take(SETUP_LOOK_BACK) {
        if let InsnKind::Call { target: Some(_) } = insn.kind {
            // A call to the next instruction pops its address into a
            // register other than this one; any other call is to a thunk.
            return (!reads_its_address(insn)).then(|| (register, table(insn)));
        }
        if x86_lift(&instruction(insn)?).writes.contains(register) {
            let call = before.get(..at).and_then(<[Insn]>::last)?;
            let popped = call.kind == (InsnKind::Call { target: Some(insn.address) })
                && instruction(insn).is_some_and(|pop| pop.mnemonic() == Mnemonic::Pop);
            return popped.then(|| (register, table(call)));
        }
    }
    None
}

/// The address of the global offset table, as the last setup of it in
/// `body` before `before` makes it, where one does.
fn table_before(body: &[Insn], before: usize) -> Option<u64> {
    /// Farther back than the setup of any function lies from its switch.
    const LOOK_BACK: usize = 4096;
    let end = before.min(body.len());
    (end.saturating_sub(LOOK_BACK) + 1..=end)
        .rev()
        .find_map(|end| table_setup(&body[..end]))
        .map(|(_, table)| table)
}

/// Whether a callee keeps `reg` as it found it, by the System V ABI for
/// i386: `ebx`, `esi`, `edi`, `ebp` and the stack pointer.
fn is_preserved_by_a_call(reg: Reg) -> bool {
    matches!(reg, Reg::Stack | Reg::General(3 | 5 | 6 | 7))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::decode_all;
    use rstest::rstest;

    fn decode(bytes: &[u8], address: u64) -> Vec<Insn> {
        decode_all(&X86::BITS64, bytes, address).0
    }

    fn one(bytes: &[u8]) -> Insn {
        X86::BITS64.decode(bytes, 0, 0x1000).expect("the bytes must decode")
    }

    #[rstest]
    #[case::endbr64(&ENDBR64, true)]
    #[case::push_rbp(&[0x55], false)]
    #[case::nop(&[0x90], false)]
    fn only_a_branch_target_mark_opens_a_function(#[case] bytes: &[u8], #[case] opens: bool) {
        assert_eq!(X86::BITS64.is_prologue(&one(bytes)), opens);
        assert_eq!(X86::BITS64.may_be_prologue(bytes), opens);
    }

    #[rstest]
    #[case::nop(&[0x90], true)]
    #[case::long_nop(&[0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00], true)]
    #[case::int3(&[0xcc], true)]
    #[case::lea_to_itself(&[0x48, 0x8d, 0x76, 0x00], true)]
    #[case::two_byte_nop(&[0x66, 0x90], true)]
    #[case::xchg_eax_eax(&[0x87, 0xc0], false)]
    #[case::mov_to_itself_in_64_bit_mode(&[0x89, 0xf6], false)]
    #[case::push(&[0x55], false)]
    fn padding_is_work_that_changes_nothing(#[case] bytes: &[u8], #[case] padding: bool) {
        assert_eq!(X86::BITS64.is_padding(&one(bytes)), padding);
    }

    #[test]
    fn a_register_moved_to_itself_pads_only_32_bit_code() {
        let insn = X86::BITS32.decode(&[0x89, 0xf6], 0, 0x1000).expect("the bytes must decode");
        assert!(X86::BITS32.is_padding(&insn));
    }

    #[rstest]
    #[case::int3_and_nops(&[0xc3, 0xcc, 0xcc, 0x90, 0x0f, 0x1f, 0x00], 1)]
    #[case::none(&[0x55, 0xc3], 2)]
    #[case::all_padding(&[0xcc, 0xcc], 0)]
    #[case::cut_short(&[0xc3, 0xe8, 0x00], 3)]
    #[case::empty(&[], 0)]
    fn trailing_padding_is_trimmed(#[case] bytes: &[u8], #[case] kept: usize) {
        assert_eq!(X86::BITS64.trim_padding(bytes).len(), kept);
    }

    #[test]
    fn a_plt_stub_names_its_slot() {
        // 0x1000 jmp [rip + 0x2fe2], to the slot at 0x1006 + 0x2fe2.
        let lazy = [0xff, 0x25, 0xe2, 0x2f, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(X86::BITS64.stub_slot(&lazy, 0x1000), Some(0x3fe8));
        // 0x1000 endbr64; 0x1004 bnd jmp [rip + 0x2fe2]
        let marked = [0xf3, 0x0f, 0x1e, 0xfa, 0xf2, 0xff, 0x25, 0xe2, 0x2f, 0x00, 0x00];
        assert_eq!(X86::BITS64.stub_slot(&marked, 0x1000), Some(0x1004 + 7 + 0x2fe2));
        // 32-bit, not PIC: jmp [0x804a00c]
        let absolute = [0xff, 0x25, 0x0c, 0xa0, 0x04, 0x08];
        assert_eq!(X86::BITS32.stub_slot(&absolute, 0x8049000), Some(0x804_a00c));
        assert_eq!(X86::BITS64.stub_slot(&[0x55, 0xc3], 0x1000), None);
    }

    #[test]
    fn a_32_bit_pic_stub_names_its_distance_from_the_table() {
        // jmp [ebx + 0xc]; push 0; jmp .plt
        let stub = [0xff, 0xa3, 0x0c, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(X86::BITS32.stub_table_offset(&stub), Some(0xc));
        // endbr32; jmp [ebx + 0x10]
        let marked = [0xf3, 0x0f, 0x1e, 0xfb, 0xff, 0xa3, 0x10, 0x00, 0x00, 0x00];
        assert_eq!(X86::BITS32.stub_table_offset(&marked), Some(0x10));
        // jmp [eax + 0xc] reads no table, and 64-bit code names its slot.
        assert_eq!(X86::BITS32.stub_table_offset(&[0xff, 0xa0, 0x0c, 0, 0, 0]), None);
        assert_eq!(X86::BITS64.stub_table_offset(&stub), None);
    }

    #[test]
    fn a_call_that_reads_its_own_address_calls_nothing() {
        // call $+5; pop ebx
        let insns = decode_all(&X86::BITS32, &[0xe8, 0x00, 0x00, 0x00, 0x00, 0x5b], 0x1000).0;
        assert!(X86::BITS32.call_targets(&insns).is_empty());
    }

    #[test]
    fn a_call_through_a_slot_names_the_slot() {
        let insns = decode(
            &[
                0xff, 0x15, 0x10, 0x00, 0x00, 0x00, // 0x1000 call [rip + 0x10]
                0xe8, 0x10, 0x00, 0x00, 0x00, //       0x1006 call 0x101b
                0xff, 0xd0, //                         0x100b call rax
                0xff, 0x25, 0x10, 0x00, 0x00, 0x00, // 0x100d jmp [rip + 0x10]
            ],
            0x1000,
        );
        assert_eq!(
            X86::BITS64.call_targets(&insns),
            [
                (0, Some(CallTarget::Slot(0x1016))),
                (1, Some(CallTarget::Address(0x101b))),
                (2, None),
                (3, Some(CallTarget::Slot(0x1023))),
            ]
        );
        assert!(X86::BITS64.is_tail_call(&insns[3]));
        assert!(!X86::BITS64.is_tail_call(&one(&[0xff, 0xe0])), "jmp rax");
    }

    #[test]
    fn data_addresses_follow_rip_and_the_pointers_in_slots() {
        let code = [
            0x48, 0x8d, 0x3d, 0xf9, 0x0f, 0x00, 0x00, // 0x1000 lea rdi, [rip + 0xff9]: 0x2000
            0x48, 0x8b, 0x05, 0xfa, 0x0f, 0x00, 0x00, // 0x1007 mov rax, [rip + 0xffa]: 0x2008
            0xb8, 0x05, 0x00, 0x00, 0x00, //             0x100e mov eax, 5
            0xc3, //                                     0x1013 ret
        ];
        let insns = decode(&code, 0x1000);
        let space = AddressSpace::from_ranges(core::iter::once(0x1000..0x3000));
        let slot = 0x2100_u64.to_le_bytes();
        let regions = [(0x2008, &slot[..])];
        assert_eq!(
            X86::BITS64.data_addresses(&code, &insns, &space, &Memory::new(&regions)),
            [0x2000, 0x2008, 0x2100]
        );
    }

    #[test]
    fn a_distance_from_the_global_offset_table_moves_with_the_data() {
        let code = [
            0xe8, 0x00, 0x00, 0x00, 0x00, //       0x1000 call 0x1005
            0x5b, //                               0x1005 pop ebx
            0x81, 0xc3, 0xac, 0x06, 0x01, 0x00, // 0x1006 add ebx, 0x106ac
            0x8d, 0x83, 0x98, 0x87, 0xfe, 0xff, // 0x100c lea eax, [ebx - 0x18768]
            0x89, 0xde, //                         0x1012 mov esi, ebx
            0x8b, 0x46, 0x10, //                   0x1014 mov eax, [esi + 0x10]
            0x8b, 0x41, 0x10, //                   0x1017 mov eax, [ecx + 0x10]
            0xbb, 0x00, 0x00, 0x00, 0x00, //       0x101a mov ebx, 0
            0x8b, 0x43, 0x10, //                   0x101f mov eax, [ebx + 0x10]
        ];
        let insns = decode_all(&X86::BITS32, &code, 0x1000).0;
        assert_eq!(
            global_offset_table_uses(&insns),
            [false, false, true, true, false, true, false, false, false]
        );
    }

    #[test]
    fn the_table_spilled_to_the_frame_comes_back_from_it() {
        let code = [
            0xe8, 0x00, 0x00, 0x00, 0x00, //       call 0x1005
            0x58, //                               pop eax
            0x05, 0xdc, 0xfe, 0x00, 0x00, //       add eax, 0xfedc
            0x89, 0x04, 0x24, //                   mov [esp], eax
            0x51, //                               push ecx
            0x58, //                               pop eax
            0x31, 0xc0, //                         xor eax, eax
            0x8b, 0x0c, 0x24, //                   mov ecx, [esp]
            0x8b, 0x6c, 0x81, 0x10, //             mov ebp, [ecx + 4*eax + 0x10]
            0x83, 0xec, 0x04, //                   sub esp, 4
            0x8b, 0x14, 0x24, //                   mov edx, [esp]
            0x8b, 0x72, 0x10, //                   mov esi, [edx + 0x10]
            0x8b, 0x54, 0x24, 0x04, //             mov edx, [esp + 4]
            0x8b, 0x72, 0x10, //                   mov esi, [edx + 0x10]
        ];
        let insns = decode_all(&X86::BITS32, &code, 0x1000).0;
        assert_eq!(
            global_offset_table_uses(&insns),
            [
                false, false, true, false, false, false, false, false, true, false, false, false,
                false, true
            ]
        );
    }

    #[test]
    fn an_epilogue_that_gives_the_caller_back_ebx_keeps_the_table() {
        let code = [
            0x53, //                               push ebx
            0xe8, 0x00, 0x00, 0x00, 0x00, //       call $+5
            0x5b, //                               pop ebx
            0x81, 0xc3, 0xac, 0x06, 0x01, 0x00, // add ebx, 0x106ac
            0x75, 0x02, //                         jne past the return
            0x5b, //                               pop ebx
            0xc3, //                               ret
            0x8b, 0x43, 0x10, //                   mov eax, [ebx + 0x10]
        ];
        let insns = decode_all(&X86::BITS32, &code, 0x1000).0;
        assert_eq!(
            global_offset_table_uses(&insns),
            [false, false, false, true, false, false, false, true]
        );
        // A `pop` with no return after it writes something else.
        let code = [&code[..], &[0x5b, 0x8b, 0x43, 0x10]].concat();
        let insns = decode_all(&X86::BITS32, &code, 0x1000).0;
        assert_eq!(global_offset_table_uses(&insns)[8..], [false, false]);
    }

    #[test]
    fn the_code_after_an_early_return_keeps_the_table() {
        let code = [
            0x56, //                               push esi
            0xe8, 0x00, 0x00, 0x00, 0x00, //       call $+5
            0x59, //                               pop ecx
            0x81, 0xc1, 0x02, 0xb6, 0x00, 0x00, // add ecx, 0xb602
            0x75, 0x02, //                         jne $+4
            0x5e, //                               pop esi
            0xc3, //                               ret
            0x8d, 0x81, 0xac, 0x7b, 0xfe, 0xff, // lea eax, [ecx - 0x18454]
            0x5e, //                               pop esi
            0xc3, //                               ret
            0x31, 0xc9, //                         xor ecx, ecx
        ];
        let insns = decode_all(&X86::BITS32, &code, 0x1000).0;
        assert_eq!(
            global_offset_table_uses(&insns),
            [false, false, false, true, false, false, false, true, false, false, false]
        );
    }

    #[test]
    fn a_constant_added_to_the_table_is_a_distance() {
        let code = [
            0xe8, 0x00, 0x00, 0x00, 0x00, //       call $+5
            0x5b, //                               pop ebx
            0x81, 0xc3, 0xac, 0x06, 0x01, 0x00, // add ebx, 0x106ac
            0x89, 0xdf, //                         mov edi, ebx
            0x81, 0xc7, 0xde, 0x9d, 0xfe, 0xff, // add edi, 0xfffe9dde
            0x83, 0xc0, 0x04, //                   add eax, 4
        ];
        let insns = decode_all(&X86::BITS32, &code, 0x1000).0;
        assert_eq!(global_offset_table_uses(&insns), [false, false, true, false, true, false]);
    }

    #[test]
    fn an_index_added_to_the_table_leaves_the_distance_to_add() {
        let code = [
            0xe8, 0x00, 0x00, 0x00, 0x00, //       call $+5
            0x5b, //                               pop ebx
            0x81, 0xc3, 0xac, 0x06, 0x01, 0x00, // add ebx, 0x106ac
            0x8d, 0x3c, 0x4b, //                   lea edi, [ebx + 2*ecx]
            0x81, 0xc7, 0xde, 0x9d, 0xfe, 0xff, // add edi, 0xfffe9dde
            0x8d, 0x43, 0x10, //                   lea eax, [ebx + 0x10]
            0x8b, 0x48, 0x04, //                   mov ecx, [eax + 4]
        ];
        let insns = decode_all(&X86::BITS32, &code, 0x1000).0;
        assert_eq!(global_offset_table_uses(&insns), [false, false, true, true, true, true, false]);
    }

    #[test]
    fn other_code_can_lie_between_the_parts_of_the_setup() {
        let code = [
            0xe8, 0x00, 0x00, 0x00, 0x00, //       call $+5
            0x5b, //                               pop ebx
            0x8b, 0x74, 0x24, 0x38, //             mov esi, [esp + 0x38]
            0x81, 0xc3, 0xa8, 0x2c, 0x00, 0x00, // add ebx, 0x2ca8
            0xe8, 0x00, 0x00, 0x00, 0x00, //       call $+5
            0x5b, //                               pop ebx
            0x31, 0xdb, //                         xor ebx, ebx
            0x81, 0xc3, 0xa8, 0x2c, 0x00, 0x00, // add ebx, 0x2ca8
        ];
        let insns = decode_all(&X86::BITS32, &code, 0x1000).0;
        assert_eq!(
            global_offset_table_uses(&insns),
            [false, false, false, true, false, false, false, false]
        );
    }

    #[test]
    fn a_call_that_never_returns_leaves_no_stack_offset() {
        let code = [
            0x83, 0xec, 0x10, //       0x1000 sub esp, 0x10
            0x74, 0x06, //             0x1003 je 0x100b
            0x50, //                   0x1005 push eax
            0xe8, 0x00, 0x10, 0x00, 0x00, // 0x1006 call a panic
            0x8b, 0x1c, 0x24, //       0x100b mov ebx, [esp]
            0xc3, //                   0x100e ret
        ];
        let insns = decode_all(&X86::BITS32, &code, 0x1000).0;
        assert_eq!(
            stack_offsets(&insns),
            [Some(0), Some(-0x10), Some(-0x10), Some(-0x14), Some(-0x10), Some(-0x10)]
        );
    }

    #[test]
    fn a_case_is_the_nearest_table_jump_and_no_padding() {
        let code = [
            0xff, 0xe0, // 0x1000 jmp eax
            0xc3, //       0x1002 ret, a case
            0xff, 0xe1, // 0x1003 jmp ecx, which nothing else reaches
            0xc3, //       0x1005 ret, a case of the nearer jump
            0x90, //       0x1006 nop, before a case that nothing else reaches
            0xc3, //       0x1007 ret
        ];
        let insns = decode_all(&X86::BITS32, &code, 0x1000).0;
        let next = nearest_cases(&insns);
        assert_eq!(next[0], [1, 2]);
        assert_eq!(next[2], [3, 4]);
        // Padding that runs into a loop its branches reach is no case.
        let code = [
            0xff, 0xe0, // 0x1000 jmp eax
            0x90, //       0x1002 nop
            0x40, //       0x1003 inc eax
            0x75, 0xfd, // 0x1004 jne 0x1003
            0xc3, //       0x1006 ret
        ];
        let insns = decode_all(&X86::BITS32, &code, 0x1000).0;
        assert!(nearest_cases(&insns)[0].is_empty());
    }

    #[test]
    fn a_function_merged_after_another_makes_its_own_table() {
        let code = [
            0xc3, //                               ret, the end of a function
            0xe8, 0x00, 0x00, 0x00, 0x00, //       call $+5, which nothing reaches
            0x5b, //                               pop ebx
            0x81, 0xc3, 0xac, 0x06, 0x01, 0x00, // add ebx, 0x106ac
            0x8b, 0x43, 0x10, //                   mov eax, [ebx + 0x10]
            0xc3, //                               ret
        ];
        let insns = decode_all(&X86::BITS32, &code, 0x1000).0;
        assert_eq!(global_offset_table_uses(&insns), [false, false, false, true, true, false]);
    }

    #[test]
    fn a_thunk_call_and_an_add_find_the_table() {
        let code = [
            0xe8, 0x10, 0x00, 0x00, 0x00, //       call __x86.get_pc_thunk.bx
            0x81, 0xc3, 0x5b, 0x2e, 0x00, 0x00, // add ebx, 0x2e5b
            0xe8, 0x10, 0x00, 0x00, 0x00, //       call elsewhere
            0x8b, 0x43, 0x10, //                   mov eax, [ebx + 0x10]
            0x8b, 0x48, 0x10, //                   mov ecx, [eax + 0x10]
        ];
        let insns = decode_all(&X86::BITS32, &code, 0x1000).0;
        assert_eq!(global_offset_table_uses(&insns), [false, true, false, true, false]);
        // 64-bit code reaches its data from `rip`, and adds no such distance.
        let insns = decode_all(&X86::BITS64, &code[..11], 0x1000).0;
        assert_eq!(global_offset_table_uses(&insns), [false, false]);
    }

    #[test]
    fn a_jump_through_a_table_of_distances_names_its_cases() {
        let code = [
            0x83, 0xff, 0x02, //                         0x1000 cmp edi, 2
            0x77, 0x13, //                               0x1003 ja 0x1018
            0x89, 0xf8, //                               0x1005 mov eax, edi
            0x48, 0x8d, 0x0d, 0xf2, 0x0f, 0x00, 0x00, // 0x1007 lea rcx, [rip + 0xff2]: 0x2000
            0x48, 0x63, 0x04,
            0x81, //                   0x100e movsxd rax, dword ptr [rcx + 4*rax]
            0x48, 0x01, 0xc8, //                         0x1012 add rax, rcx
            0xff, 0xe0, //                               0x1015 jmp rax
            0xc3, //                                     0x1017 ret
            0xc3, //                                     0x1018 ret
        ];
        let insns = decode(&code, 0x1000);
        let table: Vec<u8> =
            [-0x0fe9_i32, -0x0fe8, -0x0fe9].iter().flat_map(|entry| entry.to_le_bytes()).collect();
        let regions = [(0x2000, &table[..])];
        let tables = X86::BITS64.jump_tables(&Memory::new(&regions), 0x1000..0x1019, &insns);
        assert_eq!(
            tables,
            [JumpTable {
                jump: 0x1015,
                words: 0x2000..0x200c,
                targets: vec![0x1017, 0x1018, 0x1017]
            }]
        );
        let space = AddressSpace::from_ranges(core::iter::once(0x1000..0x3000));
        let read = X86::BITS64.data_addresses(&code, &insns, &space, &Memory::new(&regions));
        assert!(read.is_empty(), "a table is no text: {read:x?}");
        // `and eax, 1` bounds the cases as a compare does.
        let masked = [&[0x83, 0xe0, 0x01, 0x90, 0x90][..], &code[7..]].concat();
        let insns = decode(&masked, 0x1002);
        let tables = X86::BITS64.jump_tables(&Memory::new(&regions), 0x1000..0x1019, &insns);
        assert_eq!(tables.first().map(|table| table.targets.len()), Some(2));
        // A case outside the code is no table.
        let tables = X86::BITS64.jump_tables(&Memory::new(&regions), 0x1000..0x1018, &insns);
        assert!(tables.is_empty());
    }

    #[test]
    fn a_32_bit_pic_switch_names_its_cases_from_the_table() {
        let code = [
            0xe8, 0x00, 0x00, 0x00, 0x00, //             0x1000 call $+5
            0x5b, //                                     0x1005 pop ebx
            0x81, 0xc3, 0xfb, 0x0f, 0x00, 0x00, //       0x1006 add ebx, 0xffb: 0x2000
            0x83, 0xf8, 0x01, //                         0x100c cmp eax, 1
            0x77, 0x0a, //                               0x100f ja 0x101b
            0x8b, 0x84, 0x83, 0x00, 0x01, 0x00, 0x00, // 0x1011 mov eax, [ebx + 4*eax + 0x100]
            0x01, 0xd8, //                               0x1018 add eax, ebx
            0xff, 0xe0, //                               0x101a jmp eax
            0xc3, //                                     0x101c ret
        ];
        let insns = decode_all(&X86::BITS32, &code, 0x1000).0;
        let table: Vec<u8> =
            [-0x0fe4_i32, -0x0fe4].iter().flat_map(|entry| entry.to_le_bytes()).collect();
        let regions = [(0x2100, &table[..])];
        let tables = X86::BITS32.jump_tables(&Memory::new(&regions), 0x1000..0x101d, &insns);
        assert_eq!(
            tables,
            [JumpTable { jump: 0x101a, words: 0x2100..0x2108, targets: vec![0x101c, 0x101c] }]
        );
    }

    #[test]
    fn a_constant_inside_the_image_is_an_address() {
        let space = AddressSpace::from_ranges(core::iter::once(0x804_8000..0x805_0000));
        let at = |bytes: &[u8]| {
            let insn = X86::BITS32.decode(bytes, 0, 0x804_8000).expect("the bytes must decode");
            formed_address(&insn, &space)
        };
        assert_eq!(at(&[0x68, 0x00, 0x90, 0x04, 0x08]), Some(0x804_9000), "push 0x8049000");
        assert_eq!(at(&[0xa1, 0x00, 0x90, 0x04, 0x08]), Some(0x804_9000), "mov eax, [0x8049000]");
        assert_eq!(at(&[0x68, 0x05, 0x00, 0x00, 0x00]), None, "push 5");
    }
}
