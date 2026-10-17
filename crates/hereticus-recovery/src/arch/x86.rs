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

use super::{CallTarget, Insn, InsnKind, Memory, Recovery, leaves};
use hereticus_il::arch::Decoder as _;
use hereticus_il::arch::x86::{
    MOST_BYTES, Mode, X86, il_register, instruction, lift as x86_lift, mode_of,
};
use hereticus_il::{Reg, RegSet};
use hereticus_memory::AddressSpace;
use iced_x86::{Mnemonic, OpKind, Register};

/// `endbr64`, which marks where an indirect branch may land.
const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];

/// `endbr32`, the same in 32-bit code.
const ENDBR32: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfb];

/// `int3`, which clang and MSVC pad between functions with.
const INT3: u8 = 0xcc;

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
    /// pointers reaches is a text of the function too.
    fn data_addresses(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        memory: &Memory<'_>,
    ) -> Vec<u64> {
        let width = self.pointer_width();
        body.iter()
            .filter(|insn| !matches!(insn.kind, InsnKind::Call { .. } | InsnKind::Jump { .. }))
            .filter_map(|insn| formed_address(insn, space))
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
    /// table, as `call [rip + slot]`.
    fn call_targets(&self, insns: &[Insn]) -> Vec<(usize, Option<CallTarget>)> {
        insns
            .iter()
            .enumerate()
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

    /// A jump through a slot of the global offset table leaves the
    /// function. A `switch` jumps through a register or a table with an
    /// index, and stays.
    fn is_tail_call(&self, insn: &Insn) -> bool {
        slot_of(insn).is_some()
    }
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
/// A register or a slot of the frame holds the table everywhere when each
/// write to it puts the table there, as GCC keeps it in `ebx` for the whole
/// function. That needs no order of the code, which a compiler lays out
/// freely. Each other register holds it from a write of the table to the
/// next write of something else, as clang loads it from a slot just before
/// it uses it.
pub fn global_offset_table_uses(body: &[Insn]) -> Vec<bool> {
    let steps: Vec<Step> = steps_of(body);
    if !steps.iter().any(|step| step.setup.is_some()) {
        return vec![false; body.len()];
    }
    // Start from every register and slot, and take away each that some
    // write fills with anything else, until none changes.
    let mut holders = Holders {
        registers: (0..8).map(Reg::General).filter(|&reg| reg != Reg::General(4)).collect(),
        slots: steps.iter().filter_map(|step| step.slot).collect(),
    };
    loop {
        let (uses, refuted) = walk(&steps, &holders);
        if refuted.registers.is_empty() && refuted.slots.is_empty() {
            return uses;
        }
        holders.registers =
            holders.registers.iter().filter(|&reg| !refuted.registers.contains(reg)).collect();
        holders.slots.retain(|slot| !refuted.slots.contains(slot));
    }
}

/// What [`global_offset_table_uses`] reads of one instruction.
struct Step {
    /// The register the instruction leaves the table in, where it ends the
    /// setup.
    setup: Option<Reg>,
    /// The register its memory operand starts from.
    base: Option<Reg>,
    /// Where it moves a value to, and from where.
    to: Holder,
    from: Holder,
    /// The slot of the frame it names, where it names one.
    slot: Option<(Reg, i64)>,
    /// The registers it writes, with those a call may change.
    writes: RegSet,
}

/// The registers and the slots that hold the table everywhere they are
/// read.
#[derive(Clone, Debug, Default)]
struct Holders {
    registers: RegSet,
    slots: Vec<(Reg, i64)>,
}

/// Read each instruction of `body` once.
fn steps_of(body: &[Insn]) -> Vec<Step> {
    let moved = stack_offsets(body);
    body.iter()
        .enumerate()
        .map(|(index, insn)| {
            let setup = table_setup(&body[..=index]);
            let Some(inst) = instruction(insn) else {
                return Step {
                    setup,
                    base: None,
                    to: Holder::None,
                    from: Holder::None,
                    slot: None,
                    writes: RegSet::EMPTY,
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
            Step { setup, base: il_register(inst.memory_base()), to, from, slot, writes }
        })
        .collect()
}

/// Walk `steps` with `holders` taken to hold the table, and give whether
/// each step reaches memory from it, and the holders some write refutes.
fn walk(steps: &[Step], holders: &Holders) -> (Vec<bool>, Holders) {
    let mut uses = vec![false; steps.len()];
    let mut refuted = Holders::default();
    let mut local = RegSet::EMPTY;
    for (index, step) in steps.iter().enumerate() {
        if let Some(register) = step.setup {
            uses[index] = true;
            local.insert(register);
            continue;
        }
        let holds = |reg: Reg| local.contains(reg) || holders.registers.contains(reg);
        uses[index] = step.base.is_some_and(holds);
        let moves_the_table = match step.from {
            Holder::Register(reg) => holds(reg),
            Holder::Slot(slot) => holders.slots.contains(&slot),
            Holder::None => false,
        };
        for written in step.writes.iter() {
            if !(moves_the_table && step.to == Holder::Register(written)) {
                if holders.registers.contains(written) {
                    refuted.registers.insert(written);
                }
                local = local.iter().filter(|&reg| reg != written).collect();
            }
        }
        match step.to {
            Holder::Register(reg) if moves_the_table => local.insert(reg),
            Holder::Slot(slot) if !moves_the_table && holders.slots.contains(&slot) => {
                refuted.slots.push(slot);
            }
            _ => {}
        }
    }
    (uses, refuted)
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
/// instruction of `body`, where pushes, pops and constant adds say.
///
/// After a jump or a return, the code goes on at the offset the branches to
/// it had, or the offset of the last branch: the code after an epilogue
/// runs with the frame still made.
fn stack_offsets(body: &[Insn]) -> Vec<Option<i64>> {
    let mut at_targets: std::collections::HashMap<u64, Option<i64>> = Default::default();
    let mut moved = Some(0);
    let mut at_last_branch = Some(0);
    let mut ended = false;
    body.iter()
        .map(|insn| {
            if ended {
                moved = at_targets.get(&insn.address).copied().unwrap_or(at_last_branch);
            }
            let before = moved;
            match insn.kind {
                InsnKind::Branch { target } | InsnKind::Jump { target } => {
                    at_last_branch = before;
                    if let Some(target) = target {
                        at_targets.entry(target).or_insert(before);
                    }
                }
                _ => {}
            }
            ended = matches!(insn.kind, InsnKind::Return | InsnKind::Jump { .. });
            moved = moved.and_then(|moved| Some(moved + stack_change(insn)?));
            before
        })
        .collect()
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
        // `call` pushes the return address, and the callee pops it.
        (Mnemonic::Call, _) => Some(0),
        _ if moves_stack => None,
        _ => Some(i64::from(inst.stack_pointer_increment())),
    }
}

/// What an instruction moves the table from or to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
fn table_setup(body: &[Insn]) -> Option<Reg> {
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
    let follows_a_call = |insn: &Insn| matches!(insn.kind, InsnKind::Call { target: Some(_) });
    let set_up = match before {
        [.., call, pop] => {
            follows_a_call(pop)
                || (call.kind == InsnKind::Call { target: Some(pop.address) }
                    && instruction(pop).is_some_and(|pop| {
                        pop.mnemonic() == Mnemonic::Pop
                            && il_register(pop.op0_register()) == Some(register)
                    }))
        }
        [call] => follows_a_call(call),
        [] => false,
    };
    set_up.then_some(register)
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
    fn a_call_through_a_slot_names_the_slot() {
        let insns = decode(
            &[
                0xff, 0x15, 0x10, 0x00, 0x00, 0x00, // 0x1000 call [rip + 0x10]
                0xe8, 0x00, 0x00, 0x00, 0x00, //       0x1006 call 0x100b
                0xff, 0xd0, //                         0x100b call rax
                0xff, 0x25, 0x10, 0x00, 0x00, 0x00, // 0x100d jmp [rip + 0x10]
            ],
            0x1000,
        );
        assert_eq!(
            X86::BITS64.call_targets(&insns),
            [
                (0, Some(CallTarget::Slot(0x1016))),
                (1, Some(CallTarget::Address(0x100b))),
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
