//! The rules the matching reads in MIPS32 code, as which registers hold the
//! frame and which constants are addresses. The rules that find
//! functions are in [`hereticus_recovery::arch::mips`].

use super::{Arch, Decoder, GlobalPointerSetup, Insn, InsnKind, Memory, Recovery};
use hereticus_il as il;
use hereticus_il::arch::mips::*;
use hereticus_memory::{AddressSpace, ConstantKind, Contents};
use hereticus_recovery::arch::mips::{
    GP, LowerHalf, SP, SP_REG, T9, TableRules as _, first_register, gp_disp_consumer,
    is_gp_disp_preamble, is_store, join_halves, operands_of, three_registers, upper_half,
};
use rabbitizer::opcodes::Opcode;
use std::collections::BTreeMap;

/// The name the ABI gives a general register, as `gp` for 28.
pub(super) fn register_name(register: il::Reg) -> Option<&'static str> {
    match register {
        il::Reg::General(number) => super::mips32::REGISTERS.get(usize::from(number)).copied(),
        _ => None,
    }
}

impl Arch for Mips32 {
    fn is_frame_register(&self, reg: il::Reg) -> bool {
        matches!(reg, il::Reg::General(SP | FP))
    }

    fn is_frame_management(&self, insn: &Insn) -> bool {
        // The PIC preamble is bookkeeping in the same sense frame work is: the
        // ABI obliges it, the source never asked for it, and it appears in
        // every function a PIC build compiles.
        if is_pic_setup(insn) {
            return true;
        }

        let operands = operands_of(insn);
        match rabbitizer_opcode(insn) {
            // Moving the stack pointer, or setting up the frame pointer.
            // `or fp, sp, zero` is how a frame is established: this decoder
            // renders every register move as `or`, never as `move`.
            Some(Opcode::core_addiu | Opcode::core_addu | Opcode::core_subu | Opcode::core_or) => {
                operands.first().and_then(register).is_some_and(|reg| self.is_frame_register(reg))
            }

            // Spilling to and reloading from the frame.
            Some(Opcode::core_sw | Opcode::core_lw | Opcode::core_swc1 | Opcode::core_lwc1) => {
                operands
                    .iter()
                    .filter_map(access)
                    .any(|(base, _)| base.is_some_and(|base| self.is_frame_register(base)))
            }

            _ => false,
        }
    }

    /// The `_gp_disp` pair is the one piece of PIC scaffolding that needs two
    /// instructions to recognize.
    ///
    /// `lui rX, 0x0` on its own is how any relocated address load begins, and
    /// `addiu rX, rX, 0x0` on its own adds zero to a register. Dropping either
    /// alone would take real code with it, so only the pair comes out — and
    /// only where an `addu` against `t9` proves it is the PIC preamble rather
    /// than the address of a global.
    fn idiom_length(&self, body: &[Insn]) -> usize {
        if is_gp_disp_preamble(body) { 2 } else { 0 }
    }

    fn global_pointer_setup(&self, body: &[Insn]) -> Option<GlobalPointerSetup> {
        let consumer = gp_disp_consumer(body)?;
        let register = register_name(first_register(&body[consumer])?)?.to_string();
        Some(GlobalPointerSetup { parts: vec![0, 1, consumer], register })
    }

    /// MIPS builds a 32-bit address in two halves: `lui rX, hi` loads the
    /// upper sixteen bits, and a later `addiu rY, rX, lo` or `ori` adds the
    /// lower sixteen. The two are often far apart, with other work between,
    /// so each register is followed from its `lui` to its uses.
    ///
    /// A `lui` whose upper half reaches into `space` is an address. So is a
    /// lower half that, joined to the address in its source register, lands in
    /// `space`, and so is a load or store whose offset is that lower half.
    ///
    /// Forward branches are followed, so code after a return that a branch
    /// reaches still knows what its registers hold. A loop is followed only on
    /// its way in.
    fn constant_kinds(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
    ) -> Vec<ConstantKind> {
        // Code that no known branch reaches, as a loop body entered from
        // below or a landing pad the unwinder enters, still holds what the
        // function keeps in a saved register throughout. Which registers
        // those are is known only once the whole function has been read.
        constant_kinds_in(self, body, space)
    }

    /// A compiler keeps no data among MIPS instructions: constants are built
    /// with `lui` and literal pools do not exist. So a long function where
    /// many words are data is mostly not a function. Two shapes give it away:
    ///
    /// * Words that do not decode, or that hold an address inside the image.
    ///   A pointer inside a KSEG0 image reads as `lb rX, off(zero)`, which no
    ///   compiler emits. At least two words in five mark data.
    /// * Zero fill, which reads as `nop`. At least half the words mark data.
    ///
    /// Below 64 words a function is not judged: short code can look like
    /// anything, and every region of data measured was far longer. On two
    /// OpenWrt MIPS kernels, code of 64 words or more reaches at most 19% of
    /// the first and 25% of the second, and the regions of tables and zero
    /// fill after the code start at 44% and 67%. None of the compiled fixture
    /// functions is marked.
    fn contents(&self, code: &[u8], insns: &[Insn], space: &AddressSpace) -> Contents {
        const FEWEST_WORDS: usize = 64;

        let words = insns.len();
        if words < FEWEST_WORDS {
            return Contents::Code;
        }

        let unreadable = insns.iter().filter(|insn| insn.kind == InsnKind::Unknown).count();
        let pointers = code
            .as_chunks::<INSN_WIDTH>()
            .0
            .iter()
            .filter(|word| space.contains(self.read_pointer(*word)))
            .count();
        let zeros = insns.iter().filter(|insn| self.is_padding(insn)).count();

        if (unreadable + pointers) * 5 >= words * 2 || zeros * 2 >= words {
            Contents::Data
        } else {
            Contents::Code
        }
    }

    /// What [`Recovery::data_addresses`] finds, and also the slot of the
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
            if is(insn, Opcode::core_lw)
                && formed[index].is_none()
                && let Some(slot) = self.slot_of(body, index, insn)
            {
                formed[index] = Some(slot);
            }
        }
        formed
    }
}

/// What reading a function for its addresses found.
struct Tracked {
    kinds: Vec<ConstantKind>,
    /// How many instructions no known branch reached.
    unreached_arrivals: usize,
    /// The saved registers that hold one address throughout the function.
    invariant: HeldAddresses,
}

/// Read `body` for the constants that are parts of addresses.
///
/// `invariant` holds what the saved registers keep throughout, to assume
/// where no known branch arrives.
/// [`Arch::constant_kinds`] of MIPS32 text, where `arch` says which
/// transfers have a delay slot. MIPS16e reads as MIPS32 text, but most of
/// its branches have none.
pub(super) fn constant_kinds_in(
    arch: &dyn Arch,
    body: &[Insn],
    space: &AddressSpace,
) -> Vec<ConstantKind> {
    // Code that no known branch reaches, as a loop body entered from
    // below or a landing pad the unwinder enters, still holds what the
    // function keeps in a saved register throughout. Which registers
    // those are is known only once the whole function has been read.
    let first = track_addresses(arch, body, space, &HeldAddresses::default());
    if first.unreached_arrivals == 0 || first.invariant.is_empty() {
        return first.kinds;
    }
    track_addresses(arch, body, space, &first.invariant).kinds
}

fn track_addresses(
    arch: &dyn Arch,
    body: &[Insn],
    space: &AddressSpace,
    invariant: &HeldAddresses,
) -> Tracked {
    let mut kinds = vec![ConstantKind::Value; body.len()];

    // The `_gp_disp` halves are the distance from the function to its
    // global offset table, which moves with every function before it.
    for index in 0..body.len() {
        if is_gp_disp_preamble(&body[index..]) {
            kinds[index] = ConstantKind::Address;
            kinds[index + 1] = ConstantKind::Address;
        }
    }

    // `gp` holds the global pointer on entry: the caller's in non-PIC
    // code, where it reaches the small data, and the one the preamble
    // rebuilds in PIC code.
    let mut upper = HeldAddresses::default();
    upper.set(GP, Held::GlobalPointer);
    // What runs after the current delay slot, as the previous instruction
    // decided.
    let mut after_slot = AfterSlot::FallThrough;
    let mut reachable = Reach::FromAbove;
    // The addresses held on arrival at each forward branch target seen so
    // far.
    let mut at_target: BTreeMap<u64, HeldAddresses> = BTreeMap::new();
    let mut unreached_arrivals = 0;
    let mut saved = SavedRegisters::default();
    // What was held at the last computed jump, which the cases of a jump
    // table start from.
    let mut dispatched: Option<HeldAddresses> = None;
    // What each stack slot holds, where a register that held an address was
    // stored there. GCC stores the global pointer after its preamble, as
    // `.cprestore` asks, and loads it back after every call.
    let mut slots: Vec<(u64, Held)> = Vec::new();

    for (index, insn) in body.iter().enumerate() {
        let branched = take_state(&mut at_target, insn.address);
        if reachable == Reach::OnlyByBranch && branched.is_none() {
            unreached_arrivals += 1;
        }
        upper = arrive(upper, reachable, branched, dispatched.as_ref(), invariant);
        reachable = Reach::FromAbove;

        if let Some((register, high)) = upper_half(insn) {
            if space.overlaps(reach_of_upper_half(high)) {
                kinds[index] = ConstantKind::Address;
            }
            upper.set(register, Held::At(high));
        } else if let Some(destination) = global_pointer_formed(insn) {
            upper.set(destination, Held::GlobalPointer);
        } else if let Some((destination, source)) = register_copy(insn) {
            match upper.get(source) {
                Some(held) => upper.set(destination, held),
                None => upper.forget(destination),
            }
        } else if let Some((destination, source, low)) = lower_half(insn, &upper) {
            match source {
                // The destination now holds the whole address, and code
                // reaches the fields of a global through it as it would
                // through the upper half.
                Held::At(high) => {
                    let address = join_halves(LowerHalf::of(insn), high, low);
                    if space.contains(address) {
                        kinds[index] = ConstantKind::Address;
                        upper.set(destination, Held::At(address));
                    } else {
                        upper.forget(destination);
                    }
                }
                // An offset from the global pointer is the linker's.
                Held::GlobalPointer => {
                    kinds[index] = ConstantKind::Address;
                    upper.set(destination, Held::Somewhere);
                }
                // So is the low half added to an address read out of the
                // global offset table, and the linker may give the object a
                // slot of its own, which needs none.
                Held::Somewhere => {
                    kinds[index] = ConstantKind::AddressTail;
                    upper.set(destination, Held::Somewhere);
                }
                Held::PerhapsGlobalPointer => upper.forget(destination),
            }
        } else if let Some((register, slot, access)) = stack_slot(insn) {
            match access {
                SlotAccess::Store => {
                    slots.retain(|&(held_slot, _)| held_slot != slot);
                    if let Some(held) = upper.get(register) {
                        slots.push((slot, held));
                    }
                }
                SlotAccess::Load => match slots.iter().find(|&&(held_slot, _)| held_slot == slot) {
                    Some(&(_, held)) => upper.set(register, held),
                    None => upper.forget(register),
                },
            }
        } else if let Some((written, base, offset)) = memory_reference(insn, &upper) {
            let loaded = match base {
                Held::At(high) => {
                    if space.contains(join_halves(LowerHalf::Added, high, offset)) {
                        kinds[index] = ConstantKind::Address;
                    }
                    None
                }
                // A slot of the global offset table, which holds an
                // address the code then reaches data or a callee through.
                Held::GlobalPointer => {
                    kinds[index] = ConstantKind::Address;
                    Some(Held::Somewhere)
                }
                Held::Somewhere => {
                    kinds[index] = ConstantKind::Address;
                    None
                }
                Held::PerhapsGlobalPointer if is_table_slot_offset(offset) => {
                    kinds[index] = ConstantKind::Address;
                    Some(Held::Somewhere)
                }
                Held::PerhapsGlobalPointer => None,
            };
            if let Some(written) = written {
                match loaded {
                    Some(held) => upper.set(written, held),
                    None => upper.forget(written),
                }
            }
        } else if let Some((destination, held)) = indexed_address(insn, &upper) {
            upper.set(destination, held);
        } else if !is_store(insn)
            && let Some(written) = first_register(insn)
        {
            upper.forget(written);
        }

        // The delay slot runs before control moves, and compilers put the
        // lower half of an argument address there, so a transfer takes
        // effect only once its slot has run.
        let mut flow = Flow { upper, at_target, reachable, dispatched };
        flow.transfer(after_slot);
        saved.record(insn, &flow.upper);
        after_slot = AfterSlot::of(insn);
        if arch.delay_slots(insn) == 0 {
            flow.transfer(after_slot);
            after_slot = AfterSlot::FallThrough;
        }
        Flow { upper, at_target, reachable, dispatched } = flow;
    }

    Tracked { kinds, unreached_arrivals, invariant: saved.invariant() }
}

/// What each saved register is set to across a function.
#[derive(Default)]
struct SavedRegisters {
    /// Each value a saved register was set to, `None` for a value that is no
    /// address, apart from the restores of an epilogue.
    assigned: Vec<(il::Reg, Option<Held>)>,
    /// The saved registers an epilogue restores from the stack.
    restored: Vec<il::Reg>,
}

impl SavedRegisters {
    /// Note what `insn` wrote to a saved register, as `upper` holds it now.
    ///
    /// An epilogue restores each saved register from the stack before it
    /// returns. That only undoes the function's own use of the register, so
    /// it is not counted.
    fn record(&mut self, insn: &Insn, upper: &HeldAddresses) {
        if insn.kind != InsnKind::Normal || is_store(insn) {
            return;
        }
        let operands = operands_of(insn);
        let Some(written) = operands.first().and_then(register) else { return };
        if !is_callee_saved(written) || written == SP_REG {
            return;
        }
        let restores = is(insn, Opcode::core_lw)
            && operands.last().and_then(access).is_some_and(|(base, _)| base == Some(SP_REG));
        if restores {
            self.restored.push(written);
        } else {
            self.assigned.push((written, upper.get(written)));
        }
    }

    /// The saved registers this function keeps and sets to one address, and
    /// to nothing else.
    ///
    /// A register counts only if an epilogue restores it, which the ABI
    /// obliges of a function that uses it. Without that, code a scan glued
    /// on after the return can be another function, where the register
    /// holds the caller's value.
    fn invariant(&self) -> HeldAddresses {
        let mut invariant = HeldAddresses::default();
        for &(register, held) in &self.assigned {
            if !self.restored.contains(&register) {
                continue;
            }
            let all_alike = self
                .assigned
                .iter()
                .filter(|(other, _)| *other == register)
                .all(|(_, other)| *other == held);
            if let (Some(held), true) = (held, all_alike) {
                invariant.set(register, held);
            }
        }
        invariant
    }
}

/// What an instruction does to control flow once its delay slot has run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AfterSlot {
    /// Nothing: the next instruction runs next.
    FallThrough,
    /// A call returns here, with the argument and temporary registers
    /// clobbered and the saved ones restored.
    Call,
    /// A conditional branch goes forward to this address or falls through.
    Branch(u64),
    /// A jump or return: the next instruction runs only if a branch reaches
    /// it. A jump forward to a known address carries it.
    Leave(Option<u64>),
    /// A jump to a computed address, as through a jump table. The next
    /// instruction runs only if a branch reaches it, or if it is a case.
    Dispatch,
}

impl AfterSlot {
    fn of(insn: &Insn) -> Self {
        // A backward target is a loop, which is entered from above; its state
        // on the way back round is not followed.
        let forward = |target: Option<u64>| target.filter(|&target| target > insn.address);
        match insn.kind {
            InsnKind::Call { .. } => Self::Call,
            InsnKind::Branch { target } => match forward(target) {
                Some(target) => Self::Branch(target),
                None => Self::FallThrough,
            },
            InsnKind::Jump { target: None } => Self::Dispatch,
            InsnKind::Jump { target } => Self::Leave(forward(target)),
            InsnKind::Return => Self::Leave(None),
            InsnKind::Normal | InsnKind::Unknown => Self::FallThrough,
        }
    }
}

/// What [`track_addresses`] knows of control flow at one instruction.
struct Flow {
    upper: HeldAddresses,
    at_target: BTreeMap<u64, HeldAddresses>,
    reachable: Reach,
    dispatched: Option<HeldAddresses>,
}

impl Flow {
    /// Move control as `after_slot` says.
    fn transfer(&mut self, after_slot: AfterSlot) {
        match after_slot {
            AfterSlot::FallThrough => {}
            AfterSlot::Call => self.upper.keep_only(is_callee_saved),
            AfterSlot::Branch(target) => record_state(&mut self.at_target, target, &self.upper),
            AfterSlot::Leave(target) => {
                if let Some(target) = target {
                    record_state(&mut self.at_target, target, &self.upper);
                }
                self.reachable = Reach::OnlyByBranch;
            }
            AfterSlot::Dispatch => {
                self.dispatched = Some(self.upper.clone());
                self.reachable = Reach::OnlyByBranch;
            }
        }
    }
}

/// How control can reach an instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reach {
    /// The instruction before runs into it, and branches may join it too.
    FromAbove,
    /// The instruction before leaves, so only a branch reaches it.
    OnlyByBranch,
}

/// The addresses held on arrival at an instruction.
///
/// Where two paths join, only the addresses both agree on survive. Where only
/// a branch arrives, its addresses are the ones held. Where no branch is
/// known to arrive, as at a case of a jump table, only the global pointer and
/// `invariant` are held: what a function sets once and keeps in a saved
/// register throughout. On MIPS -Os tinyxml2, a C++ landing pad, entered by
/// the unwinder, reached the global offset table through `s0` that way.
///
/// The global pointer is taken both from above and from `dispatched`, the
/// last computed jump, which is where a case of a jump table comes from. One
/// case can reuse the register that holds the pointer, and the case after it
/// in the code still has it. Measured on `core::fmt::Formatter::pad_integral`
/// built by Rust for MIPS at `-O2`, a case loaded `s2` and the cases after it
/// lost the global pointer.
fn arrive(
    above: HeldAddresses,
    reach: Reach,
    branched: Option<HeldAddresses>,
    dispatched: Option<&HeldAddresses>,
    invariant: &HeldAddresses,
) -> HeldAddresses {
    match (reach, branched) {
        (Reach::FromAbove, None) => above,
        (Reach::FromAbove, Some(branched)) => above.agreed_with(&branched),
        (Reach::OnlyByBranch, Some(branched)) => branched,
        (Reach::OnlyByBranch, None) => {
            let mut held = above.global_pointers_only();
            for &(register, value) in dispatched.map_or(&[][..], |at| &at.held[..]) {
                if value.may_be_global_pointer() && held.get(register).is_none() {
                    held.set(register, value);
                }
            }
            for &(register, value) in &invariant.held {
                held.set(register, value);
            }
            held
        }
    }
}

/// Merge the addresses held on a branch to `target` into those recorded.
fn record_state(at_target: &mut BTreeMap<u64, HeldAddresses>, target: u64, upper: &HeldAddresses) {
    match at_target.get_mut(&target) {
        Some(recorded) => *recorded = recorded.agreed_with(upper),
        None => {
            at_target.insert(target, upper.clone());
        }
    }
}

/// Remove and return the addresses recorded for branches to `address`.
fn take_state(at_target: &mut BTreeMap<u64, HeldAddresses>, address: u64) -> Option<HeldAddresses> {
    at_target.remove(&address)
}

impl Held {
    fn may_be_global_pointer(self) -> bool {
        matches!(self, Self::GlobalPointer | Self::PerhapsGlobalPointer)
    }
}

/// Report whether an offset from the global pointer can only reach a slot
/// of the global offset table.
///
/// The table starts `0x7ff0` below the pointer, so the first 4096 slots lie
/// below `-0x4000`, and no field of a structure lies that far below the
/// structure.
fn is_table_slot_offset(offset: u64) -> bool {
    const HIGHEST_SLOT_OFFSET: i64 = -0x4000;
    (offset as i64) < HIGHEST_SLOT_OFFSET
}

/// What a register holds, as far as addresses go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Held {
    /// A known address: an upper half loaded by `lui`, or a whole address
    /// built from one.
    At(u64),
    /// An address whose value the code does not show, read out of the global
    /// offset table or formed from the global pointer.
    Somewhere,
    /// The global pointer, which reaches the global offset table in PIC code
    /// and the small data in non-PIC code.
    GlobalPointer,
    /// The global pointer on one path here, and no known address on another.
    ///
    /// A call that never returns, as a Rust panic does, ends the other path,
    /// but nothing in the code says so. Measured on `SmallVec::extend` built
    /// by Rust for MIPS at `-O2`, `s0` held a byte before such a call and the
    /// global pointer after it, and the table slots read through it looked
    /// like changed values. A small offset from such a register can be a
    /// field of whatever the other path left there, so only an offset that
    /// only a slot of the table has counts. See [`is_table_slot_offset`].
    PerhapsGlobalPointer,
}

/// The registers that hold an address, and what each holds.
///
/// A function holds a handful at a time, so a list beats a map.
#[derive(Clone, Debug, Default)]
struct HeldAddresses {
    held: Vec<(il::Reg, Held)>,
}

impl HeldAddresses {
    fn set(&mut self, register: il::Reg, value: Held) {
        self.forget(register);
        self.held.push((register, value));
    }

    fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    fn get(&self, register: il::Reg) -> Option<Held> {
        self.held.iter().find(|(held, _)| *held == register).map(|&(_, value)| value)
    }

    fn forget(&mut self, register: il::Reg) {
        self.held.retain(|(held, _)| *held != register);
    }

    fn keep_only(&mut self, survives: fn(il::Reg) -> bool) {
        self.held.retain(|&(held, _)| survives(held));
    }

    fn global_pointers_only(mut self) -> Self {
        self.held.retain(|&(_, held)| held.may_be_global_pointer());
        self
    }

    /// The addresses this and `other` both hold, with the same value.
    ///
    /// A global pointer that only one side holds is kept as
    /// [`Held::PerhapsGlobalPointer`].
    fn agreed_with(&self, other: &Self) -> Self {
        let mut agreed = Self::default();
        let registers = self.held.iter().chain(&other.held).map(|&(register, _)| register);
        for register in registers {
            if agreed.get(register).is_some() {
                continue;
            }
            match (self.get(register), other.get(register)) {
                (Some(left), Some(right)) if left == right => agreed.set(register, left),
                (left, right)
                    if left.is_some_and(Held::may_be_global_pointer)
                        || right.is_some_and(Held::may_be_global_pointer) =>
                {
                    agreed.set(register, Held::PerhapsGlobalPointer);
                }
                _ => {}
            }
        }
        agreed
    }
}

/// Report whether the o32 ABI makes a callee restore a register.
fn is_callee_saved(register: il::Reg) -> bool {
    // `s0` to `s7`, `gp`, `sp` and `fp`, which is also `s8`.
    matches!(register, il::Reg::General(16..=23 | 28 | 29 | 30))
}

/// The addresses a `lui` can start, once any lower half is added.
///
/// `addiu` adds a signed lower half, so the address can sit up to 32 KiB
/// below the upper half as well as up to 32 KiB above it. `ori` reaches up to
/// 64 KiB above.
fn reach_of_upper_half(high: u64) -> core::ops::Range<u64> {
    high.saturating_sub(0x8000)..high + 0x1_0000
}

/// Read `addiu rY, rX, lo` or `ori rY, rX, lo`, where `rX` holds an
/// address, as the destination, what `rX` holds, and the lower half.
fn lower_half(insn: &Insn, upper: &HeldAddresses) -> Option<(il::Reg, Held, u64)> {
    if !is(insn, Opcode::core_addiu) && !is(insn, Opcode::core_ori) {
        return None;
    }
    match operands_of(insn).as_slice() {
        [il::Operand::Reg(destination), il::Operand::Reg(source), low] => {
            Some((*destination, upper.get(*source)?, constant(low)?))
        }
        _ => None,
    }
}

/// Read a load or store through a register that holds an address, as the
/// register the load writes, what the base register holds, and the offset.
///
/// A store writes no register, so it gives `None` for the first.
fn memory_reference(insn: &Insn, upper: &HeldAddresses) -> Option<(Option<il::Reg>, Held, u64)> {
    let operands = operands_of(insn);
    let [first, reference] = operands.as_slice() else { return None };
    let (base, offset) = access(reference)?;
    let held = upper.get(base?)?;
    let written = if is_store(insn) { None } else { register(first) };
    Some((written, held, offset))
}

/// Whether an instruction saves a register to the stack or loads one back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotAccess {
    Store,
    Load,
}

/// Read `sw rX, off(sp)` or `lw rX, off(sp)` as the register, the offset of
/// the slot, and which way the word moves.
fn stack_slot(insn: &Insn) -> Option<(il::Reg, u64, SlotAccess)> {
    let access_kind = match rabbitizer_opcode(insn)? {
        Opcode::core_sw => SlotAccess::Store,
        Opcode::core_lw => SlotAccess::Load,
        _ => return None,
    };
    match operands_of(insn).as_slice() {
        [il::Operand::Reg(register), reference] => match access(reference)? {
            (Some(SP_REG), offset) => Some((*register, offset, access_kind)),
            _ => None,
        },
        _ => None,
    }
}

/// Read `addu rD, rX, rY`, where one source holds an address and the other
/// does not, as the destination and what it holds.
///
/// That is an address plus an index, as a table or an array is reached:
/// `lui v0, %hi(table); addu v0, v0, s1; lw v0, %lo(table)(v0)`. The upper
/// half still names the table, so a lower half joined to it later is still
/// part of an address. An address from the global offset table, or the global
/// pointer, plus an index is an address the code does not show.
///
/// Two addresses added make no address, and nor does a sum of two values.
fn indexed_address(insn: &Insn, upper: &HeldAddresses) -> Option<(il::Reg, Held)> {
    if !is(insn, Opcode::core_addu) {
        return None;
    }
    let (destination, left, right) = three_registers(insn)?;
    let held = match (upper.get(left), upper.get(right)) {
        (Some(held), None) | (None, Some(held)) => held,
        _ => return None,
    };
    Some(match held {
        Held::At(high) => (destination, Held::At(high)),
        Held::Somewhere | Held::GlobalPointer => (destination, Held::Somewhere),
        Held::PerhapsGlobalPointer => return None,
    })
}

/// Read `addu rD, rX, t9`, which forms the PIC global pointer, as `rD`.
fn global_pointer_formed(insn: &Insn) -> Option<il::Reg> {
    if !is(insn, Opcode::core_addu) {
        return None;
    }
    let operands = operands_of(insn);
    let (destination, sources) = operands.split_first()?;
    sources.contains(&il::Operand::Reg(T9)).then(|| register(destination)).flatten()
}

/// Read a register copy, `or rD, rS, zero` or `addu rD, rS, zero`, as `rD`
/// and `rS`. The global pointer is restored after a call this way.
fn register_copy(insn: &Insn) -> Option<(il::Reg, il::Reg)> {
    if !is(insn, Opcode::core_or) && !is(insn, Opcode::core_addu) {
        return None;
    }
    use il::Operand::{Reg, Zero};
    match operands_of(insn).as_slice() {
        [Reg(destination), Reg(source)]
        | [Reg(destination), Reg(source), Zero]
        | [Reg(destination), Zero, Reg(source)] => Some((*destination, *source)),
        _ => None,
    }
}

/// Report whether an instruction only establishes the PIC global pointer.
///
/// MIPS ABI PIC opens every function that calls anything with a fixed
/// preamble, and restores the global pointer after every call:
///
/// ```text
/// lui   v0, 0x0        ; the halves of _gp_disp, which the linker fills in
/// addiu v0, v0, 0x0
/// addu  s0, v0, t9     ; joined to the callee address the ABI leaves in t9
/// ...
/// jalr  t9
/// or    gp, s0, zero   ; restore, usually in the delay slot
/// ```
///
/// None of it comes from the source, and all of it appears in every function,
/// so comparing it measures the ABI rather than the code. Left in, it raised
/// the mean similarity of *unrelated* functions from 0.34 to 0.44 on the PIC
/// corpus: noise that pushes decoys toward the true pairs.
///
/// The `jalr` is **not** matched here. That is the call itself, which is real
/// work: a non-PIC build spells the same call `jal`, and a source edit that adds
/// or removes a call must still show.
fn is_pic_setup(insn: &Insn) -> bool {
    let operands = operands_of(insn);
    let at = |index: usize| operands.get(index).and_then(register);

    match rabbitizer_opcode(insn) {
        // `addu rX, rY, t9` folds the callee address into the global pointer.
        // Reading `t9` is what marks it: the ABI supplies that value on entry,
        // so no computation from the source starts there.
        Some(Opcode::core_addu) => at(2) == Some(T9) || at(1) == Some(T9),

        // `lw t9, N(rX)` reads the callee address out of the GOT, which is how
        // PIC reaches a function a non-PIC build simply names in its `jal`. The
        // load exists only because the call is indirect, so it is scaffolding
        // around the call rather than work of its own.
        //
        // Writing `t9` is what marks it. The ABI reserves that register for the
        // address being called, and a compiler does not use it for anything
        // else: across the whole fixture corpus every one of the 48 writes to
        // `t9` is this load, and a non-PIC build has none at all. The `jalr`
        // that consumes it still reaches the comparison, so a call that is
        // added or removed is still visible.
        //
        // A reload of `t9` from the frame is frame work rather than a GOT read,
        // and the caller judges that on its own. Excluding it here keeps each
        // rule answering for what it actually recognizes.
        Some(Opcode::core_lw) => {
            at(0) == Some(T9)
                && operands.last().and_then(access).is_some_and(|(base, _)| base != Some(SP_REG))
        }

        // A move to or from the global pointer, which this decoder renders as
        // `or rX, rY, zero`. Either direction is the same bookkeeping: the
        // preamble parks the value in a callee-saved register and puts it back
        // around each call.
        Some(Opcode::core_or) if operands.get(2) == Some(&il::Operand::Zero) => {
            at(0) == Some(GP) || at(1) == Some(GP)
        }

        _ => false,
    }
}

const FP: u8 = 30;

#[cfg(test)]
mod tests {
    use super::*;

    use hereticus_recovery::arch::decode_all;

    /// Decode one instruction from a little-endian word at address 0.
    fn decode_one(word: u32) -> Insn {
        Mips32::LITTLE.decode(&word.to_le_bytes(), 0, 0).expect("bytes must decode")
    }

    /// Encodings from `llvm-mc --triple=mips --show-encoding`, as words.
    mod words {}

    #[test]
    fn the_frame_registers_are_sp_and_fp() {
        assert!(Mips32::BIG.is_frame_register(il::Reg::General(29)));
        assert!(Mips32::BIG.is_frame_register(il::Reg::General(30)));
        assert!(!Mips32::BIG.is_frame_register(il::Reg::General(31)));
        assert!(!Mips32::BIG.is_frame_register(il::Reg::Stack), "MIPS names sp by number");
    }

    mod addresses {
        use super::*;
        use hereticus_memory::{
            AddressSpace,
            ConstantKind::{Address, AddressTail, Value},
        };

        const V0: u32 = 2;
        const A0: u32 = 4;
        const A1: u32 = 5;
        const T0: u32 = 8;
        const S0: u32 = 16;
        const S1: u32 = 17;
        const SP: u32 = 29;

        fn lui(rt: u32, imm: u32) -> u32 {
            0x3c00_0000 | rt << 16 | imm
        }
        fn addiu(rt: u32, rs: u32, imm: u32) -> u32 {
            0x2400_0000 | rs << 21 | rt << 16 | (imm & 0xffff)
        }
        fn ori(rt: u32, rs: u32, imm: u32) -> u32 {
            0x3400_0000 | rs << 21 | rt << 16 | imm
        }
        fn lw(rt: u32, offset: u32, base: u32) -> u32 {
            0x8c00_0000 | base << 21 | rt << 16 | (offset & 0xffff)
        }
        fn sw(rt: u32, offset: u32, base: u32) -> u32 {
            0xac00_0000 | base << 21 | rt << 16 | (offset & 0xffff)
        }
        fn jal(target: u32) -> u32 {
            0x0c00_0000 | (target >> 2 & 0x03ff_ffff)
        }
        fn addu(rd: u32, rs: u32, rt: u32) -> u32 {
            rs << 21 | rt << 16 | rd << 11 | 0x21
        }
        /// `beqz rs`, to `words` instructions past the delay slot.
        fn beqz(rs: u32, words: u32) -> u32 {
            0x1000_0000 | rs << 21 | words
        }
        const JR_RA: u32 = 0x03e0_0008;
        const NOP: u32 = 0;

        /// Where the code sits, and the space it refers to.
        const BASE: u64 = 0x8000_0000;

        fn space() -> AddressSpace {
            AddressSpace::of_raw_image(BASE, 0x10_0000)
        }

        fn kinds_in(words: &[u32], space: &AddressSpace) -> Vec<ConstantKind> {
            let code: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
            let (body, error) = decode_all(&Mips32::BIG, &code, BASE);
            assert_eq!(error, None);
            Mips32::BIG.constant_kinds(&code, &body, space)
        }

        fn kinds(words: &[u32]) -> Vec<ConstantKind> {
            kinds_in(words, &space())
        }

        #[test]
        fn a_pair_that_builds_an_address_is_an_address() {
            assert_eq!(kinds(&[lui(V0, 0x8001), addiu(V0, V0, 0x51b8)]), [Address, Address]);
        }

        #[test]
        fn a_negative_lower_half_is_joined_as_the_processor_joins_it() {
            // 0x80010000 - 0x1d78 = 0x8000e288, inside the space.
            assert_eq!(kinds(&[lui(V0, 0x8001), addiu(V0, V0, 0xe288)]), [Address, Address]);
        }

        #[test]
        fn a_pair_joined_with_ori_is_an_address() {
            assert_eq!(kinds(&[lui(A0, 0x8001), ori(A0, A0, 0xca00)]), [Address, Address]);
        }

        /// 1,000,000,000 is built the same way, but is not an address here.
        #[test]
        fn a_pair_that_builds_a_number_is_a_value() {
            assert_eq!(kinds(&[lui(A0, 0x3b9a), ori(A0, A0, 0xca00)]), [Value, Value]);
        }

        /// The sign mask `0x80000000` is a number when the code is elsewhere.
        #[test]
        fn a_kseg_constant_outside_the_image_is_a_value() {
            let space = AddressSpace::of_raw_image(0x8040_0000, 0x1_0000);
            assert_eq!(kinds_in(&[lui(T0, 0x8000), NOP], &space), [Value, Value]);
        }

        #[test]
        fn nothing_is_an_address_without_a_space() {
            let words = [lui(V0, 0x8001), addiu(V0, V0, 0x51b8)];
            assert_eq!(kinds_in(&words, &AddressSpace::none()), [Value, Value]);
        }

        #[test]
        fn work_between_the_halves_does_not_break_the_pair() {
            let words = [lui(V0, 0x8001), addiu(T0, A0, 1), sw(T0, 0x10, SP), addiu(A0, V0, 0x20)];
            assert_eq!(kinds(&words), [Address, Value, Value, Address]);
        }

        #[test]
        fn a_register_written_between_the_halves_ends_the_pair() {
            let words = [lui(V0, 0x8001), addiu(V0, A0, 1), addiu(A0, V0, 0x20)];
            assert_eq!(kinds(&words), [Address, Value, Value]);
        }

        /// A load or store offset from an address register is its lower half.
        #[test]
        fn a_load_and_a_store_through_the_upper_half_are_addresses() {
            let words = [lui(S0, 0x8001), lw(A0, 0x1aa0, S0), sw(A1, 0x1aa4, S0)];
            assert_eq!(kinds(&words), [Address, Address, Address]);
        }

        /// A load writes its first operand, so it ends a pair on that register.
        #[test]
        fn a_load_into_the_register_ends_the_pair() {
            let words = [lui(S0, 0x8001), lw(S0, 0x10, SP), addiu(A0, S0, 0x20)];
            assert_eq!(kinds(&words), [Address, Value, Value]);
        }

        /// A store only reads its first operand, so the pair survives it.
        #[test]
        fn a_store_from_the_register_keeps_the_pair() {
            let words = [lui(S0, 0x8001), sw(S0, 0x10, SP), addiu(A0, S0, 0x20)];
            assert_eq!(kinds(&words), [Address, Value, Address]);
        }

        /// The whole address in a register reaches the fields of a global.
        #[test]
        fn a_whole_address_in_a_register_is_followed() {
            let words =
                [lui(S1, 0x8001), addiu(S1, S1, 0x0100), addiu(A0, S1, 0x10), lw(V0, 0x8, S1)];
            assert_eq!(kinds(&words), [Address, Address, Address, Address]);
        }

        /// The delay slot runs before the call, so a lower half there counts.
        #[test]
        fn a_lower_half_in_the_delay_slot_of_a_call_counts() {
            let words = [lui(A0, 0x8001), jal(0x8000_4000), addiu(A0, A0, 0x20)];
            assert_eq!(kinds(&words), [Address, Value, Address]);
        }

        #[test]
        fn a_call_clobbers_the_argument_registers() {
            let words = [lui(A0, 0x8001), jal(0x8000_4000), NOP, addiu(A0, A0, 0x20)];
            assert_eq!(kinds(&words), [Address, Value, Value, Value]);
        }

        #[test]
        fn a_call_keeps_the_saved_registers() {
            let words = [lui(S0, 0x8001), jal(0x8000_4000), NOP, addiu(A0, S0, 0x20)];
            assert_eq!(kinds(&words), [Address, Value, Value, Address]);
        }

        /// Code after a return runs only when a branch reaches it, holding what
        /// the branch held, even though the epilogue restored the register.
        #[test]
        fn a_block_after_a_return_holds_what_its_branch_held() {
            let words = [
                lui(S0, 0x8001),
                beqz(A0, 4), // to index 6
                NOP,
                lw(S0, 0x10, SP), // the epilogue restores s0
                JR_RA,
                NOP,
                addiu(A1, S0, 0x10),
            ];
            assert_eq!(kinds(&words)[6], Address);
        }

        /// With no branch to it, code after a return holds nothing known.
        #[test]
        fn a_block_no_branch_reaches_holds_nothing() {
            let words = [lui(S0, 0x8001), JR_RA, NOP, addiu(A1, S0, 0x10)];
            assert_eq!(kinds(&words)[3], Value);
        }

        /// A table address plus an index is still that table: the lower
        /// half of the load is part of an address.
        #[test]
        fn an_indexed_address_keeps_its_upper_half() {
            let words = [lui(V0, 0x8001), addu(V0, V0, S1), lw(V0, 0x10, V0)];
            assert_eq!(kinds(&words)[2], Address);

            // Two values added make no address.
            let words = [addu(V0, A0, S1), lw(V0, 0x10, V0)];
            assert_eq!(kinds(&words)[1], Value);

            // Nor do two addresses.
            let words = [lui(V0, 0x8001), lui(S1, 0x8002), addu(V0, V0, S1), lw(V0, 0x10, V0)];
            assert_eq!(kinds(&words)[3], Value);
        }

        /// The low half added to an address read out of the global offset
        /// table is a tail the linker's choice adds, not an address of its
        /// own: an object with a slot of its own needs none.
        #[test]
        fn the_low_half_after_a_table_slot_is_an_address_tail() {
            const GP: u32 = 28;
            let words = [lw(V0, 0x8024, GP), addiu(V0, V0, 0x1080), lw(A0, 0x8, V0)];
            assert_eq!(kinds(&words), [Address, AddressTail, Address]);
        }

        /// GCC stores the global pointer in a stack slot and loads it back
        /// after each call, as `.cprestore` asks. A slot of the global offset
        /// table read through the reloaded pointer is still an address.
        #[test]
        fn a_register_loaded_back_from_the_stack_holds_what_was_stored() {
            const GP: u32 = 28;
            let words = [
                sw(GP, 0x10, SP),
                jal(0x8000_4000),
                NOP,
                lw(GP, 0x10, SP), // the pointer comes back
                lw(A0, 0x8010, GP),
            ];
            assert_eq!(kinds(&words)[4], Address);

            // A slot that held no address gives none back.
            let words = [sw(A1, 0x10, SP), lw(GP, 0x10, SP), lw(A0, 0x8010, GP)];
            assert_eq!(kinds(&words)[2], Value);
        }

        /// A saved register the function sets once, and restores in its
        /// epilogue, holds that address where no branch arrives, as in a
        /// landing pad the unwinder enters.
        #[test]
        fn a_kept_register_holds_its_address_where_no_branch_arrives() {
            let words = [
                lui(S0, 0x8001),
                lw(S0, 0x10, SP), // the epilogue restores s0
                JR_RA,
                NOP,
                addiu(A1, S0, 0x10),
            ];
            assert_eq!(kinds(&words)[4], Address);
        }

        /// A case of a jump table starts from what the jump held. A case
        /// before it in the code can load the register that holds the global
        /// pointer, and the next case still has the pointer.
        #[test]
        fn a_case_holds_the_global_pointer_the_jump_held() {
            const T9: u32 = 25;
            const JR_T0: u32 = (T0 << 21) | 0x08;
            let words = [
                addu(S1, V0, T9), // the global pointer, in s1
                lw(T0, 0x10, A1),
                JR_T0,
                NOP,
                lw(S1, 0x0, A0), // one case reuses s1
                beqz(0, 8),      // b: to the end of the switch
                NOP,
                lw(A1, 0x8010, S1), // the next case reads a slot
            ];
            assert_eq!(kinds(&words)[7], Address);

            // After a return, with no computed jump before it, nothing is
            // held but what `gp` holds.
            let words = [addu(S1, V0, T9), lw(S1, 0x0, A0), JR_RA, NOP, lw(A1, 0x8010, S1)];
            assert_eq!(kinds(&words)[4], Value);
        }

        /// Where one path holds the global pointer and the other a value, a
        /// slot of the table read through the register is still an address,
        /// but a small offset is a field and stays a value.
        #[test]
        fn a_global_pointer_one_path_lost_still_reaches_the_table() {
            const T9: u32 = 25;
            let join = |read: u32| {
                let words = [
                    addu(S0, V0, T9), // the global pointer, in s0
                    beqz(A0, 3),      // to index 5, holding it
                    NOP,
                    lw(S0, 0x0, A1), // a value in s0 on this path
                    NOP,
                    read,
                ];
                kinds(&words)[5]
            };
            assert_eq!(join(lw(T0, 0x8020, S0)), Address, "-0x7fe0, a slot");
            assert_eq!(join(lw(T0, 0x10, S0)), Value, "a field");
            assert_eq!(join(addiu(T0, S0, 0x8020)), Value, "no load, no slot");
        }

        #[test]
        fn paths_that_agree_keep_the_address() {
            let words = [
                lui(V0, 0x8001),
                beqz(A0, 3), // to index 5
                NOP,
                addiu(T0, A0, 1),
                NOP,
                addiu(A1, V0, 0x10),
            ];
            assert_eq!(kinds(&words)[5], Address);
        }

        #[test]
        fn paths_that_disagree_forget_the_address() {
            let words = [
                lui(V0, 0x8001),
                beqz(A0, 3), // to index 5
                NOP,
                lui(V0, 0x8002),
                NOP,
                addiu(A1, V0, 0x10),
            ];
            assert_eq!(kinds(&words)[5], Value);
        }

        #[test]
        fn there_is_one_kind_for_each_instruction() {
            let words = [lui(V0, 0x8001), JR_RA, addiu(V0, V0, 0x10), NOP, NOP];
            assert_eq!(kinds(&words).len(), words.len());
            assert!(kinds(&[]).is_empty());
        }

        /// The target of `jal` and `j` prints in the `$` form every decoder
        /// uses for a resolved target.
        #[test]
        fn a_jump_target_prints_as_a_resolved_target() {
            let code = jal(0x8000_4000).to_be_bytes();
            let insn = Mips32::BIG.decode(&code, 0, BASE).unwrap();
            assert_eq!(crate::printed_operands(&insn), "$+0x4000");
            assert!(crate::is_branch_target(&crate::printed_operands(&insn)));
        }

        fn contents_of(words: &[u32], space: &AddressSpace) -> hereticus_memory::Contents {
            let code: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
            let (body, _) = decode_all(&Mips32::BIG, &code, BASE);
            Mips32::BIG.contents(&code, &body, space)
        }

        /// A long function of ordinary instructions is code.
        #[test]
        fn compiled_code_is_code() {
            use hereticus_memory::Contents;
            let block = [
                addiu(SP, SP, 0xffe8),
                sw(S0, 0x10, SP),
                lui(V0, 0x8001),
                lw(A0, 0x20, V0),
                jal(0x8000_4000),
                addiu(A1, A0, 1),
                lw(S0, 0x10, SP),
                JR_RA,
                addiu(SP, SP, 0x18),
            ];
            let words = block.repeat(8);
            assert_eq!(contents_of(&words, &space()), Contents::Code);
        }

        /// A table of pointers into the image is data.
        #[test]
        fn a_table_of_pointers_is_data() {
            use hereticus_memory::Contents;
            let mut words = vec![JR_RA, NOP];
            words.extend((0..64).map(|index| 0x8000_1000 + index * 0x40));
            assert_eq!(contents_of(&words, &space()), Contents::Data);
        }

        /// The same words are only numbers where the image is elsewhere.
        #[test]
        fn pointers_count_only_inside_the_space() {
            use hereticus_memory::Contents;
            let mut words = vec![JR_RA, NOP];
            words.extend((0..64).map(|index| 0x8000_1000 + index * 0x40));
            let elsewhere = AddressSpace::of_raw_image(0x9000_0000, 0x1000);
            assert_eq!(contents_of(&words, &elsewhere), Contents::Code);
        }

        /// Zero fill after a return is data once it is half the words.
        #[test]
        fn zero_fill_is_data() {
            use hereticus_memory::Contents;
            let mut words = vec![addiu(V0, V0, 1); 30];
            words.extend([JR_RA, NOP]);
            words.extend([0; 32]);
            assert_eq!(contents_of(&words, &space()), Contents::Data);
        }

        /// The `nop` in every delay slot of `-O0` code stays below half.
        #[test]
        fn delay_slot_nops_are_code() {
            use hereticus_memory::Contents;
            let block = [
                addiu(V0, V0, 1),
                beqz(A0, 1),
                NOP,
                addiu(V0, V0, 2),
                jal(0x8000_4000),
                NOP,
                addiu(V0, V0, 3),
                addiu(V0, V0, 4),
                JR_RA,
                NOP,
            ];
            let words = block.repeat(7);
            assert_eq!(contents_of(&words, &space()), Contents::Code);
        }

        /// Opcode 0x3b is reserved in MIPS II, so these words do not decode.
        const UNREADABLE: u32 = 0xec00_0001;

        /// Mostly words that do not decode is data.
        #[test]
        fn unreadable_words_are_data() {
            use hereticus_memory::Contents;
            let mut words = vec![addiu(V0, V0, 1); 38];
            words.extend([UNREADABLE; 26]);
            assert_eq!(contents_of(&words, &space()), Contents::Data);
        }

        /// A third of the words unreadable is below two in five, so it stays
        /// code.
        #[test]
        fn some_unreadable_words_are_code() {
            use hereticus_memory::Contents;
            let mut words = vec![addiu(V0, V0, 1); 44];
            words.extend([UNREADABLE; 22]);
            assert_eq!(contents_of(&words, &space()), Contents::Code);
        }

        /// Too short to judge, so it stays code.
        #[test]
        fn a_short_function_is_code() {
            use hereticus_memory::Contents;
            assert_eq!(contents_of(&[0; 63], &space()), Contents::Code);
            assert_eq!(contents_of(&[], &space()), Contents::Code);
        }
    }

    #[test]
    fn frame_work_is_told_apart_from_real_work() {
        // addiu sp, sp, -0x20
        assert!(Mips32::LITTLE.is_frame_management(&decode_one(0x27bd_ffe0)));
        // sw ra, 0x14(sp)
        assert!(Mips32::LITTLE.is_frame_management(&decode_one(0xafbf_0014)));
        // addu v0, a0, a1 is the work itself
        assert!(!Mips32::LITTLE.is_frame_management(&decode_one(0x0085_1021)));
    }

    /// A load from an object is not a spill, even though both are `lw`.
    #[test]
    fn a_data_load_is_not_frame_work() {
        // lw v0, 0x0(a0)
        let load = decode_one(0x8c82_0000);
        assert!(!Mips32::LITTLE.is_frame_management(&load), "a load through a0 reads data");
    }

    /// This decoder renders a register move as `or rX, rY, zero`, never as
    /// `move`, so a frame pointer established that way must still be seen.
    #[test]
    fn a_frame_pointer_set_with_or_is_frame_work() {
        // or s8, sp, zero: establishing the frame pointer, which this decoder
        // names by its numbered form rather than as `fp`.
        assert!(Mips32::LITTLE.is_frame_management(&decode_one(0x03a0_f025)));
        // or v0, s2, zero: moving a computed value into the return register.
        assert!(!Mips32::LITTLE.is_frame_management(&decode_one(0x0240_1025)));
    }

    /// The PIC preamble is in every function a PIC build compiles, so
    /// comparing it measures the ABI rather than the code.
    #[test]
    fn the_pic_global_pointer_setup_is_not_real_work() {
        // addu s0, v0, t9: folding the callee address into the global pointer.
        assert!(Mips32::LITTLE.is_frame_management(&decode_one(0x0059_8021)));
        // addu gp, v0, t9: the same, straight into gp.
        assert!(Mips32::LITTLE.is_frame_management(&decode_one(0x0059_e021)));
        // or gp, s0, zero: the restore after a call, in the delay slot.
        assert!(Mips32::LITTLE.is_frame_management(&decode_one(0x0200_e025)));
    }

    /// The bookkeeping test keys on `t9` and `gp`, so an `addu` between other
    /// registers must stay. Taken from the same PIC function, where
    /// `addu s2, v0, s2` accumulates the running total.
    #[test]
    fn an_addu_that_is_not_pic_setup_stays() {
        assert!(
            !Mips32::LITTLE.is_frame_management(&decode_one(0x0052_9021)),
            "adding two ordinary registers is the work itself"
        );
    }

    /// The PIC preamble comes out of the comparison, but only as a pair and
    /// only where the `addu` against `t9` proves what it is.
    #[test]
    fn the_pic_preamble_is_dropped_as_a_pair() {
        let body = [
            decode_one(0x3c02_0000), // lui v0, 0x0
            decode_one(0x2442_0000), // addiu v0, v0, 0x0
            decode_one(0x0059_e021), // addu gp, v0, t9
        ];
        assert_eq!(Mips32::LITTLE.idiom_length(&body), 2);
    }

    /// The consumer need not follow the pair at once: a compiler puts the frame
    /// prologue between them.
    #[test]
    fn the_preamble_is_found_across_an_intervening_prologue() {
        let body = [
            decode_one(0x3c02_0000), // lui v0, 0x0
            decode_one(0x2442_0000), // addiu v0, v0, 0x0
            decode_one(0x27bd_ffd8), // addiu sp, sp, -0x28
            decode_one(0xafbf_0024), // sw ra, 0x24(sp)
            decode_one(0x0059_e021), // addu gp, v0, t9
        ];
        assert_eq!(Mips32::LITTLE.idiom_length(&body), 2);
    }

    /// A non-PIC build loads the address of a global with the very same two
    /// words, so the pair alone must not be dropped.
    ///
    /// From `int read_global(int i) { return table[i & 63]; }` built with
    /// `-fno-pic`: `lui at, 0x0` then `addiu at, at, 0x0` builds the address of
    /// `table`, and the `addu` that follows indexes it rather than joining it to
    /// `t9`. Dropping this pair would delete a real memory reference, and two
    /// functions reading different globals would compare equal.
    #[test]
    fn a_real_address_load_is_not_the_pic_preamble() {
        let body = [
            decode_one(0x3c01_0000), // lui at, 0x0
            decode_one(0x2421_0000), // addiu at, at, 0x0
            decode_one(0x3082_003f), // andi v0, a0, 0x3f
            decode_one(0x0002_1080), // sll v0, v0, 2
            decode_one(0x0022_0821), // addu at, at, v0, indexing, not PIC
            decode_one(0x8c22_0000), // lw v0, 0x0(at)
        ];
        assert_eq!(Mips32::LITTLE.idiom_length(&body), 0, "the address of a global is real work");
    }

    /// A large frame puts many register saves between the pair and its
    /// consumer, as `compress2` in zlib does.
    #[test]
    fn the_consumer_is_found_past_a_large_prologue() {
        let mut body = vec![
            decode_one(0x3c02_0004), // lui v0, 0x4
            decode_one(0x2442_8e10), // addiu v0, v0, -0x71f0
            decode_one(0x27bd_ff98), // addiu sp, sp, -0x68
        ];
        body.extend((0..9).map(|slot| decode_one(0xafbf_0064 - slot * 4))); // sw ..., 0x64(sp)
        body.push(decode_one(0x0059_8021)); // addu s0, v0, t9
        assert_eq!(Mips32::LITTLE.idiom_length(&body), 2);
    }

    /// An early return before the consumer does not hide it, as in `gzclose`.
    #[test]
    fn the_consumer_is_found_past_an_early_return_test() {
        let body = [
            decode_one(0x3c02_0003), // lui v0, 0x3
            decode_one(0x2442_2e00), // addiu v0, v0, 0x2e00
            decode_one(0x1080_0003), // beqz a0, ...
            decode_one(0x0000_0000), // nop
            decode_one(0x0059_8021), // addu s0, v0, t9
        ];
        assert_eq!(Mips32::LITTLE.idiom_length(&body), 2);
    }

    /// Writing the loaded register ends the search too.
    #[test]
    fn overwriting_the_pair_ends_the_search_for_the_consumer() {
        let body = [
            decode_one(0x3c02_0004), // lui v0, 0x4
            decode_one(0x2442_8e10), // addiu v0, v0, -0x71f0
            decode_one(0x8c82_0000), // lw v0, 0x0(a0)
            decode_one(0x0059_8021), // addu s0, v0, t9
        ];
        assert_eq!(Mips32::LITTLE.idiom_length(&body), 0);
    }

    /// Without any consumer the pair is not a preamble either.
    #[test]
    fn a_pair_nothing_joins_to_t9_is_not_the_preamble() {
        let body = [
            decode_one(0x3c02_0000), // lui v0, 0x0
            decode_one(0x2442_0000), // addiu v0, v0, 0x0
            decode_one(0x8c42_0000), // lw v0, 0x0(v0), a plain dereference
        ];
        assert_eq!(Mips32::LITTLE.idiom_length(&body), 0);
    }

    /// A pair at the very end of a function has no consumer to find, and must
    /// not read past the body.
    #[test]
    fn a_pair_at_the_end_of_a_body_is_kept() {
        let body = [decode_one(0x3c02_0000), decode_one(0x2442_0000)];
        assert_eq!(Mips32::LITTLE.idiom_length(&body), 0);
        assert_eq!(Mips32::LITTLE.idiom_length(&body[..1]), 0);
        assert_eq!(Mips32::LITTLE.idiom_length(&[]), 0);
    }

    /// The `addu` must read the register the pair built, not merely any
    /// register alongside `t9`.
    #[test]
    fn an_addu_on_t9_and_another_register_is_not_the_consumer() {
        let body = [
            decode_one(0x3c02_0000), // lui v0, 0x0
            decode_one(0x2442_0000), // addiu v0, v0, 0x0
            decode_one(0x0079_8021), // addu s0, v1, t9: v1, not v0
        ];
        assert_eq!(Mips32::LITTLE.idiom_length(&body), 0);
    }

    /// The linked preamble is dropped as a pair, as the unlinked one is.
    #[test]
    fn a_linked_preamble_is_dropped_as_a_pair() {
        let body = [
            decode_one(0x3c02_0004), // lui v0, 0x4
            decode_one(0x2442_9008), // addiu v0, v0, -0x6ff8
            decode_one(0x0059_e021), // addu gp, v0, t9
        ];
        assert_eq!(Mips32::LITTLE.idiom_length(&body), 2);
    }

    /// A linked pair that indexes a table is still the address of a global.
    #[test]
    fn a_linked_address_load_is_not_the_pic_preamble() {
        let body = [
            decode_one(0x3c01_8001), // lui at, 0x8001
            decode_one(0x2421_1000), // addiu at, at, 0x1000
            decode_one(0x0022_0821), // addu at, at, v0, indexing, not PIC
        ];
        assert_eq!(Mips32::LITTLE.idiom_length(&body), 0);
    }

    /// The call survives, but the GOT read that reaches it does not.
    ///
    /// A non-PIC build spells the same call `jal` and needs no load at all, so
    /// the load is scaffolding around the call. The `jalr` itself is the work:
    /// an edit that adds or removes a call must still show.
    #[test]
    fn the_call_is_kept_but_its_got_read_is_not() {
        // lw t9, 0x0(s0): reading the callee address out of the GOT.
        assert!(Mips32::LITTLE.is_frame_management(&decode_one(0x8e19_0000)));
        // lw t9, 0x0(gp): the same, indexed straight off the global pointer.
        assert!(Mips32::LITTLE.is_frame_management(&decode_one(0x8f99_0000)));
        // jalr t9: the call itself, which stays.
        assert!(!Mips32::LITTLE.is_frame_management(&decode_one(0x0320_f809)));
    }

    /// Only a load *into* `t9` is a GOT read. A load through `gp` into any other
    /// register reads a global, which is work the source asked for.
    #[test]
    fn a_global_read_through_gp_is_not_a_got_read() {
        // lw v0, 0x0(gp)
        assert!(
            !Mips32::LITTLE.is_frame_management(&decode_one(0x8f82_0000)),
            "reading a global is real work"
        );
    }
}
