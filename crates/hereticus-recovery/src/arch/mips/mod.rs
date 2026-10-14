//! MIPS32 decoding, little endian, on top of `rabbitizer`.
//!
//! Three details shape this module, and the rest of `hereticus` sees none of
//! them:
//!
//! 1. `rabbitizer` renders registers with a `$` sigil and pads the name of
//!    the operation to a column. Both are stripped here, because `hereticus` reserves a
//!    leading `$` for a branch target and compares operand text directly.
//! 2. MIPS ships in both byte orders and a whole image is one of them, so
//!    [`Mips32`] carries which. Reading at the wrong order does not fail:
//!    every word still decodes, into a different instruction. An ELF says
//!    which it is; a raw image is told by the caller.
//! 3. A MIPS branch counts its offset from the *delay slot*, and `j` and
//!    `jal` hold an address rather than a distance. `rabbitizer` resolves
//!    both, so neither correction is made here.

pub use hereticus_il::arch::mips::*;

use super::{
    AbsoluteCall, CallTarget, Decoder, GlobalPointerSetup, Insn, InsnKind, JumpTable, Memory,
    Recovery,
};
use crate::address::{AddressSpace, ConstantKind, Contents};
use hereticus_il as il;
use rabbitizer::opcodes::Opcode;
use std::collections::BTreeMap;

/// The operands of `insn`, lifted: see [`lifted`].
pub(super) fn operands_of(insn: &Insn) -> il::Operands {
    lifted(insn).map(|lifted| lifted.operands).unwrap_or_default()
}

/// The register the ABI calls through, `t9`.
pub(super) const T9: il::Reg = il::Reg::General(25);

/// The global pointer, `gp`.
pub(super) const GP: il::Reg = il::Reg::General(28);

/// The stack pointer, `sp`.
pub(super) const SP_REG: il::Reg = il::Reg::General(SP);

/// The name the ABI gives a general register, as `gp` for 28.
pub(super) fn register_name(register: il::Reg) -> Option<&'static str> {
    match register {
        il::Reg::General(number) => super::mips32::REGISTERS.get(usize::from(number)).copied(),
        _ => None,
    }
}

/// The register the first operand of `insn` names.
pub(super) fn first_register(insn: &Insn) -> Option<il::Reg> {
    operands_of(insn).first().and_then(register)
}

/// The rules that read data through the global offset table.
trait TableRules {
    fn slot_of(&self, body: &[Insn], load_index: usize, load: &Insn) -> Option<u64>;
    fn addresses_by_index(
        &self,
        body: &[Insn],
        space: &AddressSpace,
        memory: &Memory<'_>,
    ) -> Vec<(usize, u64)>;
}

impl TableRules for Mips32 {
    /// The slot of the global offset table that `load`, at `load_index` of
    /// `body`, reads through the global pointer.
    fn slot_of(&self, body: &[Insn], load_index: usize, load: &Insn) -> Option<u64> {
        let (offset, base) = load_operands(load)?;
        let (global_pointer, register) = global_pointer_before(body, load_index)?;
        if base != register && base != GP {
            return None;
        }
        Some(u64::from((global_pointer as u32).wrapping_add(offset as u32)))
    }

    /// Each address `body` forms, with the index of the instruction that
    /// joins its lower half: see [`Recovery::data_addresses`].
    fn addresses_by_index(
        &self,
        body: &[Insn],
        space: &AddressSpace,
        memory: &Memory<'_>,
    ) -> Vec<(usize, u64)> {
        let slot_value = |load_index: usize, load: &Insn| {
            let slot = self.slot_of(body, load_index, load)?;
            Some(self.read_pointer(memory.bytes(slot, INSN_WIDTH)?))
        };

        body.iter()
            .enumerate()
            .filter(|(_, insn)| is(insn, Opcode::core_addiu) || is(insn, Opcode::core_ori))
            .filter_map(|(index, insn)| {
                let operands = operands_of(insn);
                let [destination, il::Operand::Reg(source), low] = operands.as_slice() else {
                    return None;
                };
                // `t9` receives a callee, not data.
                if register(destination) == Some(T9) {
                    return None;
                }
                let (source, low) = (*source, constant(low)?);
                let (at, written) = last_write(body, index, source)?;
                let high = match rabbitizer_opcode(written)? {
                    // The `_gp_disp` halves are a distance, not an address.
                    Opcode::core_lui if is_gp_disp_preamble(&body[at..]) => return None,
                    Opcode::core_lui => upper_half(written)?.1,
                    Opcode::core_lw => slot_value(at, written)?,
                    _ => return None,
                };
                Some((index, join_halves(LowerHalf::of(insn), high, low)))
            })
            .filter(|&(_, address)| space.contains_formed(address))
            .collect()
    }
}

impl Recovery for Mips32 {
    /// `jr t9`: the ABI calls through `t9`, and a `switch` jumps through
    /// another register.
    fn is_tail_call(&self, insn: &Insn) -> bool {
        is(insn, Opcode::core_jr) && operands_of(insn).as_slice() == [il::Operand::Reg(T9)]
    }

    /// A function that needs a frame opens by making room for it, so
    /// `addiu sp, sp, -N` is the first instruction of almost every one.
    ///
    /// Saving the return address was tried first and reports the start late.
    /// A prologue saves several registers and `sw ra` can be any of them: on
    /// a stripped MIPS kernel, 2593 of 13362 saved return addresses follow
    /// another register save, so the function had already begun. Allocating
    /// the frame cannot be preceded that way, and it appears 13426 times
    /// against 13362, so it also catches a leaf that makes room without
    /// calling anything.
    /// `addiu sp, sp, imm`: opcode 9, with `sp`, 29, in both `rs` and `rt`.
    fn may_be_prologue(&self, word: &[u8]) -> bool {
        const ADDIU_SP_SP: u32 = 0x27bd_0000;
        let Some(&[a, b, c, d]) = word.get(..INSN_WIDTH) else { return false };
        self.order().read_word([a, b, c, d]) & 0xffff_0000 == ADDIU_SP_SP
    }

    fn is_prologue(&self, insn: &Insn) -> bool {
        if !is(insn, Opcode::core_addiu) {
            return false;
        }

        // `addiu sp, sp, -N`: the stack pointer is both the destination and
        // the source, and the immediate is negative. A positive immediate is
        // the matching unwind at the end of a function.
        matches!(
            operands_of(insn).as_slice(),
            [il::Operand::Reg(SP_REG), il::Operand::Reg(SP_REG), il::Operand::Const(immediate)]
                if (*immediate as i64) < 0
        )
    }

    /// PIC code forms the global pointer from `t9`, which holds the address
    /// of the function only on entry. So the `_gp_disp` preamble opens a
    /// function whether or not the function has a frame, and wherever the
    /// code before it ends.
    fn is_function_entry(&self, body: &[Insn]) -> bool {
        is_gp_disp_preamble(body)
    }

    /// Under PIC the `_gp_disp` pair sits before the frame allocation, so the
    /// function starts two words earlier than its prologue.
    ///
    /// Measured on a stripped PIC object: without this, five of eight function
    /// starts land 8 bytes late, because `lui`/`addiu` open the function and
    /// the frame allocation follows them.
    ///
    /// The pair's shape is enough here, with no need to find the `addu` that
    /// [`is_gp_disp_preamble`] insists on. This is asked only about the two
    /// words immediately before a frame prologue, and code that loads the
    /// address of a global does so to use it, not to open a frame. Either
    /// reading also names a start inside the same function, so the cost of
    /// being wrong is a boundary 8 bytes out rather than a dropped
    /// instruction.
    fn preamble_before_prologue(&self, earlier: &[Insn]) -> usize {
        let [.., high, low] = earlier else { return 0 };

        if constant_pair_register(high, low).is_some() { 2 } else { 0 }
    }

    fn is_padding(&self, insn: &Insn) -> bool {
        // A zero word decodes as `nop` on MIPS, so unlike ARM one test covers
        // both the encoding a linker pads with and the named instruction.
        // LLD pads with a trap instead.
        is(insn, Opcode::core_nop)
            || decoded(insn) == Some(Decoded::Mips32(super::mips32::Op::Sigrie))
    }

    fn trim_padding<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        /// `nop` and zero are the same word on MIPS: `sll zero, zero, 0`. Zero
        /// reads the same in either byte order.
        const NOP: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

        // A word that does not decode is not code either. MIPS keeps no data
        // among its instructions, so after a function's last instruction it
        // is the gap before the next, which moves when a function before it
        // grows. Measured on zlib built as a shared library, such a word made
        // an unedited `inflateCodesUsed` read as changed.
        //
        // Only whole words are decoded. With a partial word at the end, the
        // last four bytes straddle two words and read differently in each
        // byte order, which moved a boundary under the fuzzer.
        let aligned = bytes.len().is_multiple_of(INSN_WIDTH);
        let is_filler = |end: usize| {
            bytes[end - INSN_WIDTH..end] == NOP
                || (aligned
                    && self
                        .decode(bytes, end - INSN_WIDTH, 0)
                        .is_ok_and(|insn| insn.kind == InsnKind::Unknown || self.is_padding(&insn)))
        };

        let mut end = bytes.len();
        while end >= INSN_WIDTH && is_filler(end) {
            end -= INSN_WIDTH;
        }

        // The word in the delay slot of the last branch is part of the
        // function, not padding. The symbol table includes it, so a scan must
        // too, or a scanned function differs from the same function read from
        // its symbol by one word.
        let trimmed_a_slot = end < bytes.len()
            && end >= INSN_WIDTH
            && self.decode(bytes, end - INSN_WIDTH, 0).is_ok_and(|insn| {
                insn.kind != InsnKind::Normal
                    && insn.kind != InsnKind::Unknown
                    && self.delay_slots(&insn) > 0
            });
        if trimmed_a_slot {
            end += INSN_WIDTH;
        }

        &bytes[..end]
    }

    /// A `switch` compiles to a load from a table and a `jr`, in one of two
    /// shapes. Code that is not PIC holds the address of each case:
    ///
    /// ```text
    /// lui   v0, %hi(table)
    /// addiu v0, v0, %lo(table)
    /// addu  v0, v0, s1          ; s1 = the case number times four
    /// lw    v0, 0(v0)
    /// jr    v0
    /// ```
    ///
    /// PIC code finds the table through the global offset table, and holds
    /// the distance from the global pointer to each case:
    ///
    /// ```text
    /// lw    v0, %got(table)(gp)
    /// addu  at, at, v0          ; at = the case number times four
    /// lw    at, %lo(table)(at)
    /// addu  at, gp, at
    /// jr    at
    /// ```
    ///
    /// Only a raw image holds the global offset table among its code, so only
    /// there is the second shape read.
    fn jump_tables(
        &self,
        memory: &Memory<'_>,
        code: core::ops::Range<u64>,
        insns: &[Insn],
    ) -> Vec<JumpTable> {
        let image = Image { memory, code, order: self.order() };
        (0..insns.len()).filter_map(|index| read_jump_table(&image, insns, index)).collect()
    }

    /// PIC code calls a function it does not reach with `bal` through a slot
    /// of the global offset table:
    ///
    /// ```text
    /// lw   t9, %call16(callee)(gp)
    /// jalr t9
    /// ```
    ///
    /// The global pointer comes from the `_gp_disp` preamble of the function,
    /// so `insns` must be one whole function for a slot to be found.
    fn call_targets(&self, insns: &[Insn]) -> Vec<(usize, Option<CallTarget>)> {
        let through_slot = |index: usize| {
            let (_, load) = last_write(insns, index, T9)?;
            if !is(load, Opcode::core_lw) {
                return None;
            }
            let (offset, base) = load_operands(load)?;
            let (global_pointer, register) = global_pointer_before(insns, index)?;
            (base == register || base == GP)
                .then(|| u64::from((global_pointer as u32).wrapping_add(offset as u32)))
        };
        let calls_through_t9 =
            |insn: &Insn| operands_of(insn).last().and_then(register) == Some(T9);

        insns
            .iter()
            .enumerate()
            .filter_map(|(index, insn)| match insn.kind {
                InsnKind::Call { target: Some(target) } => {
                    Some((index, Some(CallTarget::Address(target))))
                }
                InsnKind::Call { target: None } if calls_through_t9(insn) => {
                    Some((index, through_slot(index).map(CallTarget::Slot)))
                }
                InsnKind::Call { target: None } => Some((index, None)),
                // A tail call jumps through `t9` as a call does.
                InsnKind::Jump { target: None }
                    if operands_of(insn).as_slice() == [il::Operand::Reg(T9)] =>
                {
                    Some((index, through_slot(index).map(CallTarget::Slot)))
                }
                InsnKind::Jump { target: Some(target) } if super::leaves(insns, target) => {
                    Some((index, Some(CallTarget::Address(target))))
                }
                _ => None,
            })
            .collect()
    }

    /// A lower half joined to what its source register holds, where that
    /// is an upper half, or an address PIC code read from the global offset
    /// table:
    ///
    /// ```text
    /// lui   a1, %hi(text)          lw    a1, %got(text)(gp)
    /// addiu a1, a1, %lo(text)      addiu a1, a1, %lo(text)
    /// ```
    ///
    /// Only these two shapes are read. Unlike [`Recovery::constant_kinds`], this
    /// asks for the data, and a pair far apart is rare where a function
    /// passes a string on.
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

    fn absolute_call(&self, word: &[u8]) -> Option<AbsoluteCall> {
        /// The primary opcode of `jal`, in the top 6 bits.
        const JAL: u32 = 0b00_0011;
        /// `jal` holds a word index, so the region is 2^26 words.
        const JAL_REGION: u64 = 1 << 28;

        let raw = self.order().read_word([word[0], word[1], word[2], word[3]]);
        (raw >> 26 == JAL)
            .then(|| AbsoluteCall { offset: u64::from(raw & 0x03ff_ffff) << 2, region: JAL_REGION })
    }
}


/// The register a

/// The register a `lui`/`addiu` pair builds a link-time constant in, if the two
/// instructions are such a pair.
///
/// ```text
/// lui   v0, 0x4          ; 0x0 in an object the linker has not seen yet
/// addiu v0, v0, -0x6ff8
/// ```
///
/// Both words name one register. The immediates are the distance from the
/// function to its global offset table, which a linked file holds and an
/// unlinked object leaves as zero, so they say nothing either way. Measured
/// on zlib and Lua built as MIPS shared libraries: requiring zero missed every
/// preamble, and every function that moved read as changed.
///
/// That shape alone does **not** mean PIC: a non-PIC build loads the address
/// of a global exactly this way, so the caller must confirm what consumes the
/// result. See [`is_gp_disp_preamble`].
fn constant_pair_register(high: &Insn, low: &Insn) -> Option<il::Reg> {
    if !is(high, Opcode::core_lui) || !is(low, Opcode::core_addiu) {
        return None;
    }
    let loaded = match operands_of(high).as_slice() {
        [il::Operand::Reg(loaded), _] => *loaded,
        _ => return None,
    };
    // `addiu rX, rX, lo` must add into the very register `lui` just wrote,
    // or the two words are unrelated.
    match operands_of(low).as_slice() {
        [il::Operand::Reg(destination), il::Operand::Reg(source), _]
            if *destination == loaded && *source == loaded =>
        {
            Some(loaded)
        }
        _ => None,
    }
}

/// Report whether `body` opens with the `_gp_disp` preamble of a PIC function.
///
/// The `lui`/`addiu` pair by itself is ambiguous. Compiled without PIC,
///
/// ```c
/// extern int table[64];
/// int read_global(int i) { return table[i & 63]; }
/// ```
///
/// opens with `lui at, 0x0` then `addiu at, at, 0x0` — the same two words, the
/// same zero immediates, loading the address of `table`. Dropping the pair on
/// its shape alone therefore deletes a real memory reference from ordinary
/// code, and a function that reads one global would compare equal to one that
/// reads another.
///
/// What separates them is the consumer. A PIC preamble exists to be joined to
/// the callee address the ABI leaves in `t9`:
///
/// ```text
/// lui   v0, 0x0
/// addiu v0, v0, 0x0
/// addu  gp, v0, t9     ; only PIC does this
/// ```
///
/// A data load instead indexes or dereferences the address it built. So the
/// pair counts as PIC only when an `addu` that reads both the loaded register
/// and `t9` follows it. The two need not be adjacent: a compiler puts the frame
/// prologue between them, which is why a window is searched rather than the
/// next word alone.
fn is_gp_disp_preamble(body: &[Insn]) -> bool {
    gp_disp_consumer(body).is_some()
}

/// The index in `body` of the `addu` that joins the pair of
/// [`is_gp_disp_preamble`] to `t9`.
fn gp_disp_consumer(body: &[Insn]) -> Option<usize> {
    /// How far to look for the `addu` that consumes the pair. The frame
    /// prologue sits between them: an allocation and up to eleven register
    /// saves. Measured on zlib linked as a shared library, `compress2` puts
    /// ten words between them, so the eight first measured on the fixtures
    /// missed it.
    const MOST_WORDS_TO_CONSUMER: usize = 16;

    let [high, low, rest @ ..] = body else { return None };
    let loaded = constant_pair_register(high, low)?;

    // A write to the loaded register ends the search: past it an `addu`
    // with `t9` joins some other value. A branch does not, because a function
    // can test an argument and return early before it needs the pointer, as
    // `gzclose` does.
    for (index, insn) in rest.iter().enumerate().take(MOST_WORDS_TO_CONSUMER) {
        if joins_to_callee_address(insn, loaded) {
            return Some(index + 2);
        }
        let writes_loaded = !is_store(insn) && first_register(insn) == Some(loaded);
        if writes_loaded {
            return None;
        }
    }
    None
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
/// [`Recovery::constant_kinds`] of MIPS32 text, where `decoder` says which
/// transfers have a delay slot. MIPS16e reads as MIPS32 text, but most of
/// its branches have none.
pub(super) fn constant_kinds_in(
    decoder: &dyn Decoder,
    body: &[Insn],
    space: &AddressSpace,
) -> Vec<ConstantKind> {
    // Code that no known branch reaches, as a loop body entered from
    // below or a landing pad the unwinder enters, still holds what the
    // function keeps in a saved register throughout. Which registers
    // those are is known only once the whole function has been read.
    let first = track_addresses(decoder, body, space, &HeldAddresses::default());
    if first.unreached_arrivals == 0 || first.invariant.is_empty() {
        return first.kinds;
    }
    track_addresses(decoder, body, space, &first.invariant).kinds
}

fn track_addresses(
    decoder: &dyn Decoder,
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
                // An offset from the global pointer, or from an address
                // read out of the global offset table, is the linker's.
                Held::GlobalPointer | Held::Somewhere => {
                    kinds[index] = ConstantKind::Address;
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
        if decoder.delay_slots(insn) == 0 {
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

/// Code and where it lies, to read the words a table holds.
struct Image<'a> {
    memory: &'a Memory<'a>,
    code: core::ops::Range<u64>,
    order: ByteOrder,
}

impl Image<'_> {
    /// The word at `address`, or `None` where nothing loads.
    fn word(&self, address: u64) -> Option<u32> {
        let bytes = self.memory.bytes(address, INSN_WIDTH)?;
        Some(self.order.read_word([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Report whether a case can start at `address`.
    fn holds_code_at(&self, address: u64) -> bool {
        address.is_multiple_of(INSN_WIDTH as u64) && self.code.contains(&address)
    }
}

/// What the words of a jump table hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Entries {
    /// The address of each case.
    Addresses,
    /// The distance from the global pointer to each case.
    FromGlobalPointer { global_pointer: u64 },
}

/// How far back the parts of a table jump may lie. GCC puts them together
/// before the `jr`, but can move other work between them.
const TABLE_LOOK_BACK: usize = 16;

/// More cases than any `switch` a compiler turns into one table.
const MOST_CASES: usize = 1024;

/// How far from its jump a case may lie when no bound gives the number of
/// cases. A table is followed by other data, which this keeps from reading
/// as more cases.
const MOST_CASE_DISTANCE: u64 = 0x1_0000;

/// Read the table behind the `jr` at `insns[index]`.
fn read_jump_table(image: &Image<'_>, insns: &[Insn], index: usize) -> Option<JumpTable> {
    let jump = &insns[index];
    if !is(jump, Opcode::core_jr) || jump.kind != (InsnKind::Jump { target: None }) {
        return None;
    }
    let target_register = match operands_of(jump).as_slice() {
        [il::Operand::Reg(target)] => *target,
        _ => return None,
    };

    // The PIC shape adds the global pointer after the load.
    let (load_at, entries) = match last_write(insns, index, target_register)? {
        (at, insn) if is(insn, Opcode::core_lw) => (at, Entries::Addresses),
        (at, insn) if is(insn, Opcode::core_addu) => {
            let (global_pointer, pointer_register) = global_pointer_before(insns, index)?;
            let (_, left, right) = three_registers(insn)?;
            let entry_register = match (left, right) {
                (left, entry) if left == pointer_register => entry,
                (entry, right) if right == pointer_register => entry,
                _ => return None,
            };
            let (load_at, load) = last_write(insns, at, entry_register)?;
            is(load, Opcode::core_lw).then_some(())?;
            (load_at, Entries::FromGlobalPointer { global_pointer })
        }
        _ => return None,
    };

    // `lw rX, lo(rA)`, where `rA` is the table plus the case number.
    let (offset, indexed) = load_operands(&insns[load_at])?;
    let (sum_at, sum) = last_write(insns, load_at, indexed)?;
    if !is(sum, Opcode::core_addu) {
        return None;
    }
    let (_, left, right) = three_registers(sum)?;
    let table_base = table_address(image, insns, sum_at, left, entries)
        .or_else(|| table_address(image, insns, sum_at, right, entries))?;
    let table = u64::from((table_base as u32).wrapping_add(offset as u32));

    let bound = case_count(insns, index);
    let mut targets = Vec::new();
    let mut word = table;
    for _ in 0..bound.unwrap_or(MOST_CASES) {
        // The end of the section ends the table, as `Arith` in Lua for MIPS
        // ends `.rodata`.
        let Some(value) = image.word(word) else { break };
        let target = match entries {
            Entries::Addresses => u64::from(value),
            Entries::FromGlobalPointer { global_pointer } => {
                u64::from((global_pointer as u32).wrapping_add(value))
            }
        };
        let near = target.abs_diff(jump.address) < MOST_CASE_DISTANCE;
        if !image.holds_code_at(target) || (bound.is_none() && !near) {
            break;
        }
        targets.push(target);
        word += INSN_WIDTH as u64;
    }

    (!targets.is_empty()).then_some(JumpTable { jump: jump.address, words: table..word, targets })
}

/// The address a register holds at `insns[before]`, when it is the base of
/// a table: a `lui` and `addiu` pair, a `lui` alone, or, in PIC code, a word
/// of the global offset table.
fn table_address(
    image: &Image<'_>,
    insns: &[Insn],
    before: usize,
    register: il::Reg,
    entries: Entries,
) -> Option<u64> {
    /// How far back the table's address may be made. A `switch` in a loop
    /// has it made once, before the loop: expat's `big2_attributeValueTok`
    /// for MIPS makes it 27 instructions before the jump.
    const BASE_LOOK_BACK: usize = 128;

    let (at, insn) = last_write_within(insns, before, register, BASE_LOOK_BACK)?;
    if let Some((_, high)) = upper_half(insn) {
        return Some(high);
    }
    match (rabbitizer_opcode(insn)?, entries) {
        // The upper half from `lui`, or, as GCC writes PIC code, the page
        // from a slot of the global offset table.
        (Opcode::core_addiu, _) => {
            let operands = operands_of(insn);
            let [_, il::Operand::Reg(source), immediate] = operands.as_slice() else {
                return None;
            };
            let (source, low) = (*source, constant(immediate)?);
            let (source_at, _) = last_write(insns, at, source)?;
            let high = table_address(image, insns, source_at + 1, source, entries)?;
            Some(join_halves(LowerHalf::Added, high, low))
        }
        (Opcode::core_lw, Entries::FromGlobalPointer { global_pointer }) => {
            let (offset, _) = load_operands(insn)?;
            let slot = u64::from((global_pointer as u32).wrapping_add(offset as u32));
            image.word(slot).map(u64::from)
        }
        _ => None,
    }
}

/// The last instruction before `insns[before]` that writes `register`, with
/// its index, within [`TABLE_LOOK_BACK`] instructions.
///
/// A branch names a register it only reads, so it is stepped over.
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
        insn.kind == InsnKind::Normal && !is_store(insn) && first_register(insn) == Some(register)
    })
}

/// Read `op rD, rS, rT` as its three registers.
fn three_registers(insn: &Insn) -> Option<(il::Reg, il::Reg, il::Reg)> {
    match operands_of(insn).as_slice() {
        [first, second, third] => Some((register(first)?, register(second)?, register(third)?)),
        _ => None,
    }
}

/// Read `lw rX, offset(rA)` as the offset and `rA`.
fn load_operands(insn: &Insn) -> Option<(u64, il::Reg)> {
    match operands_of(insn).as_slice() {
        [_, reference] => match access(reference)? {
            (Some(base), offset) => Some((offset, base)),
            _ => None,
        },
        _ => None,
    }
}

/// The number of cases, from the `sltiu rT, rX, n` that guards the table.
fn case_count(insns: &[Insn], index: usize) -> Option<usize> {
    insns[index.saturating_sub(TABLE_LOOK_BACK)..index].iter().rev().find_map(|insn| {
        if !is(insn, Opcode::core_sltiu) {
            return None;
        }
        let bound = match operands_of(insn).as_slice() {
            [_, _, bound] => constant(bound)?,
            _ => return None,
        };
        usize::try_from(bound).ok().filter(|&n| n <= MOST_CASES)
    })
}

/// The global pointer of the function that holds `insns[index]`, and the
/// register it is in, from the `_gp_disp` preamble at its start.
///
/// The preamble adds the distance to the global pointer to `t9`, which holds
/// the address of the function, and that is the address of its `lui`.
fn global_pointer_before(insns: &[Insn], index: usize) -> Option<(u64, il::Reg)> {
    /// How far back the start of a function may lie. A `switch` sits deep in
    /// a long function more often than not.
    const MOST_WORDS_TO_START: usize = 4096;

    let from = index.saturating_sub(MOST_WORDS_TO_START);
    (from..index).rev().find_map(|at| {
        if !is_gp_disp_preamble(&insns[at..]) {
            return None;
        }
        let (high, low) = (&insns[at], &insns[at + 1]);
        let loaded = constant_pair_register(high, low)?;
        let (_, upper) = upper_half(high)?;
        let immediate = match operands_of(low).as_slice() {
            [_, _, immediate] => constant(immediate)?,
            _ => return None,
        };
        let distance = join_halves(LowerHalf::Added, upper, immediate);
        let global_pointer = u64::from((high.address as u32).wrapping_add(distance as u32));
        let register = insns[at + 2..]
            .iter()
            .take(TABLE_LOOK_BACK)
            .find(|insn| joins_to_callee_address(insn, loaded))
            .and_then(first_register)?;
        Some((global_pointer, register))
    })
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

/// Read `lui rX, hi` as the register and the value it loads.
fn upper_half(insn: &Insn) -> Option<(il::Reg, u64)> {
    if !is(insn, Opcode::core_lui) {
        return None;
    }
    match operands_of(insn).as_slice() {
        [il::Operand::Reg(register), high] => Some((*register, (constant(high)? & 0xffff) << 16)),
        _ => None,
    }
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

/// How a lower half joins an upper half.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LowerHalf {
    /// By `addiu`, which adds it signed.
    Added,
    /// By `ori`, which puts it in the low 16 bits.
    Ored,
}

impl LowerHalf {
    /// How `insn` joins its lower half: an `ori` puts it in, and anything
    /// else adds it.
    fn of(insn: &Insn) -> Self {
        if is(insn, Opcode::core_ori) { Self::Ored } else { Self::Added }
    }
}

/// Join an upper half and a lower half as `joined` says.
///
/// A negative `addiu` immediate reads as a 64-bit two's complement, so
/// wrapping arithmetic on 32 bits gives the address the processor forms.
fn join_halves(joined: LowerHalf, high: u64, low: u64) -> u64 {
    match joined {
        LowerHalf::Ored => high | (low & 0xffff),
        LowerHalf::Added => u64::from((high as u32).wrapping_add(low as u32)),
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

/// Report whether an instruction stores, which reads its first operand
/// rather than writing it.
pub(super) fn is_store(insn: &Insn) -> bool {
    matches!(
        rabbitizer_opcode(insn),
        Some(
            Opcode::core_sb
                | Opcode::core_sh
                | Opcode::core_sw
                | Opcode::core_swl
                | Opcode::core_swr
                | Opcode::core_sc
                | Opcode::core_swc1
                | Opcode::core_sdc1
                | Opcode::core_swc2
                | Opcode::core_sdc2
        )
    )
}

/// The opcode `rabbitizer` read for `insn`, where it read it.
pub(crate) fn rabbitizer_opcode(insn: &Insn) -> Option<Opcode> {
    match decoded(insn)? {
        Decoded::Rabbitizer(opcode) => Some(opcode),
        _ => None,
    }
}

/// Report whether an instruction is `addu rD, loaded, t9` in either operand
/// order, which is what forms the PIC global pointer.
fn joins_to_callee_address(insn: &Insn, loaded: il::Reg) -> bool {
    if !is(insn, Opcode::core_addu) {
        return false;
    }
    matches!(
        three_registers(insn),
        Some((_, left, right)) if (left == loaded && right == T9) || (left == T9 && right == loaded)
    )
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

/// The stack and frame pointers.
const SP: u8 = 29;

const FP: u8 = 30;

