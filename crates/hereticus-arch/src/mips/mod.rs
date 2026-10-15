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
    AbsoluteCall, Arch, CallTarget, Decoder, GlobalPointerSetup, Insn, InsnKind, JumpTable, Memory,
    Recovery,
};
use hereticus_il as il;
use hereticus_memory::{AddressSpace, ConstantKind, Contents};
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
    /// `is_gp_disp_preamble` insists on. This is asked only about the two
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
    /// Only these two shapes are read. Unlike [`Arch::constant_kinds`], this
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DecodeError, decode_all};

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

    /// `jr` through any other register is a tail call or a switch, which
    /// leaves the block but does not end the function the way a return does.
    #[test]
    fn jr_through_another_register_is_an_indirect_jump() {
        assert_eq!(decode_one(0x0320_0008).kind, InsnKind::Jump { target: None });
    }

    /// The ABI calls through `t9`, so `jr t9` is a tail call, and `jr` through
    /// another register dispatches a `switch`.
    #[test]
    fn only_jr_t9_is_a_tail_call() {
        assert!(Mips32::LITTLE.is_tail_call(&decode_one(0x0320_0008)), "jr t9");
        assert!(!Mips32::LITTLE.is_tail_call(&decode_one(0x0040_0008)), "jr v0");
        assert!(!Mips32::LITTLE.is_tail_call(&decode_one(0x03e0_0008)), "jr ra");
    }

    /// Read the jump tables of big-endian code at `base`.
    fn tables_in(words: &[u32], base: u64) -> Vec<JumpTable> {
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
        let (insns, _) = decode_all(&Mips32::BIG, &code, base);
        let regions = [(base, code.as_slice())];
        Mips32::BIG.jump_tables(&Memory::new(&regions), base..base + code.len() as u64, &insns)
    }

    /// Code that is not PIC holds the address of each case. The `sltiu`
    /// bound says how many there are.
    fn absolute_switch(bound: u32) -> Vec<u32> {
        vec![
            0x2c83_0000 | bound, // 0x00 sltiu v1, a0, bound
            0x1060_000a,         // 0x04 beqz v1, 0x30
            0x0004_1880,         // 0x08 sll v1, a0, 2
            0x3c02_8000,         // 0x0c lui v0, 0x8000
            0x2442_0040,         // 0x10 addiu v0, v0, 0x40
            0x0043_1021,         // 0x14 addu v0, v0, v1
            0x8c42_0000,         // 0x18 lw v0, 0(v0)
            0x0040_0008,         // 0x1c jr v0
            0,                   // 0x20 nop
            0x03e0_0008,         // 0x24 case 0: jr ra
            0,                   // 0x28 nop
            0x03e0_0008,         // 0x2c case 1: jr ra
            0,                   // 0x30 nop
            0x03e0_0008,         // 0x34 jr ra
            0,                   // 0x38 nop
            0,                   // 0x3c nop
            0x8000_0024,         // 0x40 the table
            0x8000_002c,         // 0x44
            0x8000_0030,         // 0x48
            0x8000_0024,         // 0x4c past the bound
        ]
    }

    #[test]
    fn reads_a_table_of_case_addresses() {
        assert_eq!(
            tables_in(&absolute_switch(3), 0x8000_0000),
            [JumpTable {
                jump: 0x8000_001c,
                words: 0x8000_0040..0x8000_004c,
                targets: vec![0x8000_0024, 0x8000_002c, 0x8000_0030],
            }]
        );
    }

    /// The end of what loads ends a table, even before its bound.
    #[test]
    fn the_end_of_memory_ends_the_table() {
        let words = absolute_switch(4);
        assert_eq!(
            tables_in(&words[..19], 0x8000_0000)[0].targets,
            [0x8000_0024, 0x8000_002c, 0x8000_0030]
        );
    }

    /// GCC's PIC table: the page from a GOT slot, plus a low half.
    #[test]
    fn reads_a_table_on_a_page_from_the_global_offset_table() {
        let words = [
            0x3c1c_0000_u32, // 0x00 lui gp, 0
            0x279c_7ff0,     // 0x04 addiu gp, gp, 0x7ff0: gp is 0x7ff0
            0x0399_e021,     // 0x08 addu gp, gp, t9
            0x2c62_0002,     // 0x0c sltiu v0, v1, 2
            0x0003_2080,     // 0x10 sll a0, v1, 2
            0x8f82_8050,     // 0x14 lw v0, -0x7fb0(gp): the slot at 0x40
            0x2442_0010,     // 0x18 addiu v0, v0, 0x10: the table at 0x58
            0x0044_1021,     // 0x1c addu v0, v0, a0
            0x8c42_0000,     // 0x20 lw v0, 0(v0)
            0x005c_1021,     // 0x24 addu v0, v0, gp
            0x0040_0008,     // 0x28 jr v0
            0,               // 0x2c nop
            0x03e0_0008,     // 0x30 case 0: jr ra
            0,               // 0x34 nop
            0x03e0_0008,     // 0x38 case 1: jr ra
            0,               // 0x3c nop
            0x0000_0048,     // 0x40 the slot: the page is 0x48
            0,               // 0x44
            0,               // 0x48
            0,               // 0x4c
            0,               // 0x50
            0,               // 0x54
            0xffff_8040,     // 0x58 the table: 0x30 - gp
            0xffff_8048,     // 0x5c 0x38 - gp
        ];
        assert_eq!(
            tables_in(&words, 0),
            [JumpTable { jump: 0x28, words: 0x58..0x60, targets: vec![0x30, 0x38] }]
        );
    }

    /// A word that is no address of code ends the table early.
    #[test]
    fn a_word_that_is_no_case_ends_the_table() {
        let mut words = absolute_switch(4);
        words[17] = 0x1234_5678;
        assert_eq!(tables_in(&words, 0x8000_0000)[0].targets, [0x8000_0024]);
    }

    /// A `jr` whose register is not loaded from a table is left alone.
    #[test]
    fn a_jump_through_a_pointer_is_no_table() {
        let mut words = absolute_switch(3);
        words[6] = 0x0080_1021; // addu v0, a0, zero
        assert!(tables_in(&words, 0x8000_0000).is_empty());
        let mut words = absolute_switch(3);
        words[7] = 0x03e0_0008; // jr ra
        assert!(tables_in(&words, 0x8000_0000).is_empty());
    }

    /// A `switch` in a loop has its table's page loaded once, before the
    /// loop, far from the jump.
    #[test]
    fn reads_a_table_whose_page_was_loaded_long_before() {
        let mut words = vec![
            0x3c02_0000_u32, // 0x00 lui v0, 0
            0x2442_7ff0,     // 0x04 addiu v0, v0, 0x7ff0: gp is 0x7ff0
            0x0059_0821,     // 0x08 addu at, v0, t9
            0x8c22_8098,     // 0x0c lw v0, -0x7f68(at): the slot at 0x88
        ];
        words.extend([0x0100_4025; 20]); // 0x10 or t0, t0, zero, twenty times
        words.extend([
            0x0004_1880, // 0x60 sll v1, a0, 2
            0x0062_1821, // 0x64 addu v1, v1, v0
            0x8c63_0010, // 0x68 lw v1, 0x10(v1)
            0x0023_1821, // 0x6c addu v1, at, v1
            0x0060_0008, // 0x70 jr v1
            0,           // 0x74 nop
            0x03e0_0008, // 0x78 case 0: jr ra
            0,           // 0x7c nop
            0x03e0_0008, // 0x80 case 1: jr ra
            0,           // 0x84 nop
            0x0000_0080, // 0x88 the slot: the table's page
            0,           // 0x8c
            0xffff_8088, // 0x90 the table: 0x78 - gp
            0xffff_8090, // 0x94 0x80 - gp
            0x1000_0000, // 0x98 no case
        ]);
        assert_eq!(
            tables_in(&words, 0),
            [JumpTable { jump: 0x70, words: 0x90..0x98, targets: vec![0x78, 0x80] }]
        );
    }

    /// PIC code finds the table through the global offset table, and holds
    /// the distance from the global pointer to each case. With no bound, the
    /// table ends at the first word that is not a case.
    #[test]
    fn reads_a_table_of_distances_from_the_global_pointer() {
        let words = [
            0x3c02_0000, // 0x00 lui v0, 0
            0x2442_7ff0, // 0x04 addiu v0, v0, 0x7ff0: gp is 0x7ff0
            0x0059_0821, // 0x08 addu at, v0, t9
            0x0004_1880, // 0x0c sll v1, a0, 2
            0x8c22_8050, // 0x10 lw v0, -0x7fb0(at): the slot at 0x40
            0x0062_1821, // 0x14 addu v1, v1, v0
            0x8c63_0010, // 0x18 lw v1, 0x10(v1)
            0x0023_1821, // 0x1c addu v1, at, v1
            0x0060_0008, // 0x20 jr v1
            0,           // 0x24 nop
            0x03e0_0008, // 0x28 case 0: jr ra
            0,           // 0x2c nop
            0x03e0_0008, // 0x30 case 1: jr ra
            0,           // 0x34 nop
            0,           // 0x38
            0,           // 0x3c
            0x0000_0048, // 0x40 the slot: the table's page
            0,           // 0x44
            0,           // 0x48
            0,           // 0x4c
            0,           // 0x50
            0,           // 0x54
            0xffff_8038, // 0x58 the table: 0x28 - gp
            0xffff_8040, // 0x5c 0x30 - gp
            0x1000_0000, // 0x60 no case
        ];
        assert_eq!(
            tables_in(&words, 0),
            [JumpTable { jump: 0x20, words: 0x58..0x60, targets: vec![0x28, 0x30] }]
        );
    }

    /// PIC code calls through a slot at the global pointer plus an offset,
    /// and the preamble gives the global pointer.
    #[test]
    fn a_call_through_the_global_offset_table_names_its_slot() {
        use crate::CallTarget;

        let words = [
            0x3c02_0000_u32, // 0x00 lui v0, 0
            0x2442_7ff0,     // 0x04 addiu v0, v0, 0x7ff0: gp is 0x7ff0
            0x0059_8821,     // 0x08 addu s1, v0, t9
            0x8e39_8010,     // 0x0c lw t9, -0x7ff0(s1): the slot at 0x0
            0x0320_f809,     // 0x10 jalr t9
            0,               // 0x14 nop
            0x0c00_0010,     // 0x18 jal 0x40
            0,               // 0x1c nop
            0x0320_f809,     // 0x20 jalr t9: t9 still holds the slot's callee
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
        let (insns, _) = decode_all(&Mips32::BIG, &code, 0);
        assert_eq!(
            Mips32::BIG.call_targets(&insns),
            [
                (4, Some(CallTarget::Slot(0))),
                (6, Some(CallTarget::Address(0x40))),
                (8, Some(CallTarget::Slot(0))),
            ]
        );
    }

    /// PIC code reads a local address from the global offset table and adds
    /// its lower half. Other code joins two halves. The `_gp_disp` pair and
    /// an address bound for `t9` are no data.
    #[test]
    fn data_addresses_come_from_the_table_or_from_two_halves() {
        let words = [
            0x3c02_0000_u32, // 0x00 lui v0, 0
            0x2442_7ff0,     // 0x04 addiu v0, v0, 0x7ff0: gp is 0x7ff0
            0x0059_8821,     // 0x08 addu s1, v0, t9
            0x8e25_9000,     // 0x0c lw a1, -0x7000(s1): the slot at 0xff0
            0x24a5_0010,     // 0x10 addiu a1, a1, 0x10
            0x3c04_8000,     // 0x14 lui a0, 0x8000
            0x2484_0040,     // 0x18 addiu a0, a0, 0x40
            0x2499_0008,     // 0x1c addiu t9, a0, 0x8
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
        let (insns, _) = decode_all(&Mips32::BIG, &code, 0);
        let table = 0x2000_u32.to_be_bytes();
        let regions = [(0xff0, table.as_slice())];
        let space = AddressSpace::from_ranges([0x0..0x1_0000, 0x8000_0000..0x8000_1000]);
        assert_eq!(
            Mips32::BIG.data_addresses(&code, &insns, &space, &Memory::new(&regions)),
            [0x2010, 0x8000_0040]
        );
        assert_eq!(
            Mips32::BIG.data_addresses(&code, &insns, &space, &Memory::new(&[])),
            [0x8000_0040],
            "an unread slot gives no address"
        );
    }

    /// `jal` holds the target's word index, which the region completes.
    #[test]
    fn jal_is_an_absolute_call_in_either_order() {
        let jal = 0x0c00_0800u32; // jal 0x2000
        let expected = Some(AbsoluteCall { offset: 0x2000, region: 1 << 28 });
        assert_eq!(Mips32::LITTLE.absolute_call(&jal.to_le_bytes()), expected);
        assert_eq!(Mips32::BIG.absolute_call(&jal.to_be_bytes()), expected);
    }

    /// Only `jal` names an absolute target of a call. `j` jumps, and `jalr`
    /// and `bal` do not hold one.
    #[test]
    fn other_words_are_not_absolute_calls() {
        for word in [0x0800_0800u32, 0x0320_f809, 0x0411_0004, 0x27bd_ffe8, 0] {
            assert_eq!(Mips32::LITTLE.absolute_call(&word.to_le_bytes()), None, "{word:#010x}");
        }
    }

    #[test]
    fn decode_all_advances_by_instruction_width() {
        let mut code = Vec::new();
        for word in [0x0085_1021u32, 0x03e0_0008, 0x0085_1021] {
            code.extend_from_slice(&word.to_le_bytes());
        }
        let (insns, err) = decode_all(&Mips32::LITTLE, &code, 0x1000);
        assert_eq!(err, None);
        let addresses: Vec<u64> = insns.iter().map(|insn| insn.address).collect();
        assert_eq!(addresses, vec![0x1000, 0x1004, 0x1008]);
    }

    #[test]
    fn decode_all_reports_trailing_partial_bytes() {
        let mut code = 0x0085_1021u32.to_le_bytes().to_vec();
        code.push(0xff);
        let (insns, err) = decode_all(&Mips32::LITTLE, &code, 0);
        assert_eq!(insns.len(), 1);
        assert_eq!(err, Some(DecodeError::Truncated));
    }

    #[test]
    fn decode_all_handles_empty_input() {
        let (insns, err) = decode_all(&Mips32::LITTLE, &[], 0);
        assert!(insns.is_empty());
        assert_eq!(err, None);
    }

    /// A zero word is `nop` on MIPS, so it is padding by name as well as by
    /// encoding.
    #[test]
    fn a_zero_word_is_padding() {
        let nop = decode_one(0x0000_0000);
        assert_eq!(crate::printed_name(&nop), "nop");
        assert!(Mips32::LITTLE.is_padding(&nop));
        assert!(Mips32::LITTLE.trim_padding(&[0; 4]).is_empty());
    }

    #[test]
    fn trailing_padding_is_removed() {
        let mut code = 0x0085_1021u32.to_le_bytes().to_vec();
        code.extend_from_slice(&[0; 4]);
        assert_eq!(Mips32::LITTLE.trim_padding(&code), &code[..4]);
    }

    mod addresses {
        use super::*;
        use hereticus_memory::{
            AddressSpace,
            ConstantKind::{Address, Value},
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

    /// The `nop` in the delay slot of the last return belongs to the function.
    #[test]
    fn a_delay_slot_nop_is_kept() {
        // jr ra, nop in its slot, then two words of padding.
        let mut code = 0x03e0_0008u32.to_be_bytes().to_vec();
        code.extend_from_slice(&[0; 12]);
        assert_eq!(Mips32::BIG.trim_padding(&code), &code[..8]);
    }

    /// The same holds after a branch or a jump, and in either byte order.
    #[test]
    fn a_delay_slot_nop_is_kept_after_any_branch() {
        for word in [
            0x0800_0010u32, // j 0x40
            0x1000_ffff,    // b .
            0x1440_0003,    // bnez v0, . + 16
            0x0c00_0010,    // jal 0x40
            0x0320_f809,    // jalr t9
        ] {
            let mut little = word.to_le_bytes().to_vec();
            little.extend_from_slice(&[0; 8]);
            assert_eq!(Mips32::LITTLE.trim_padding(&little).len(), 8, "{word:#010x}");

            let mut big = word.to_be_bytes().to_vec();
            big.extend_from_slice(&[0; 8]);
            assert_eq!(Mips32::BIG.trim_padding(&big).len(), 8, "{word:#010x}");
        }
    }

    /// A branch whose slot holds real work loses only the padding after it.
    #[test]
    fn a_filled_delay_slot_is_not_padded_out() {
        let mut code = 0x03e0_0008u32.to_le_bytes().to_vec();
        code.extend_from_slice(&0x2402_0001u32.to_le_bytes()); // addiu v0, zero, 1
        code.extend_from_slice(&[0; 8]);
        assert_eq!(Mips32::LITTLE.trim_padding(&code), &code[..8]);
    }

    /// A word that does not decode after the last return is the gap before
    /// the next function, as the `nop` padding is.
    #[test]
    fn an_unreadable_word_after_the_return_is_trimmed() {
        let mut code = 0x03e0_0008u32.to_be_bytes().to_vec(); // jr ra
        code.extend_from_slice(&[0; 4]); // nop, in the delay slot
        code.extend_from_slice(&0xec00_0001u32.to_be_bytes()); // a reserved opcode
        assert_eq!(Mips32::BIG.trim_padding(&code), &code[..8]);
    }

    /// LLD fills the gap after a function with `sigrie 1`, which traps.
    #[test]
    fn the_padding_trap_after_the_return_is_trimmed() {
        let mut code = 0x03e0_0008u32.to_be_bytes().to_vec(); // jr ra
        code.extend_from_slice(&[0; 4]); // nop, in the delay slot
        code.extend_from_slice(&0x0417_0001u32.to_be_bytes());
        code.extend_from_slice(&0x0417_0001u32.to_be_bytes());
        assert_eq!(Mips32::BIG.trim_padding(&code), &code[..8]);
    }

    /// An unreadable word before real code is kept: only the end is trimmed.
    #[test]
    fn an_unreadable_word_inside_a_function_is_kept() {
        let mut code = 0xec00_0001u32.to_be_bytes().to_vec(); // a reserved opcode
        code.extend_from_slice(&0x2402_0001u32.to_be_bytes()); // addiu v0, zero, 1
        assert_eq!(Mips32::BIG.trim_padding(&code), &code[..]);
    }

    /// Code that ends without a branch keeps no `nop`.
    #[test]
    fn a_nop_after_plain_work_is_padding() {
        let mut code = 0x2402_0001u32.to_be_bytes().to_vec();
        code.extend_from_slice(&[0; 4]);
        assert_eq!(Mips32::BIG.trim_padding(&code), &code[..4]);
    }

    /// Padding inside a function is not padding, so it must stay.
    #[test]
    fn padding_before_real_code_is_kept() {
        let mut code = vec![0u8; 4];
        code.extend_from_slice(&0x0085_1021u32.to_le_bytes());
        assert_eq!(Mips32::LITTLE.trim_padding(&code), &code[..], "only the end is trimmed");
    }

    #[test]
    fn a_prologue_is_recognized_by_the_frame_it_makes() {
        // addiu sp, sp, -0x20
        let allocate = decode_one(0x27bd_ffe0);
        assert!(Mips32::LITTLE.is_prologue(&allocate));

        let add = decode_one(0x0085_1021);
        assert!(!Mips32::LITTLE.is_prologue(&add));
    }

    /// Releasing the frame ends a function; it must not be read as opening
    /// one, or every function start lands on the function before it.
    #[test]
    fn releasing_the_frame_is_not_a_prologue() {
        // addiu sp, sp, 0x28, the unwind that pairs with the allocation.
        let release = decode_one(0x27bd_0028);
        assert!(!Mips32::LITTLE.is_prologue(&release));
    }

    /// Saving the return address happens inside the prologue, not at its
    /// start, so it must not be taken for the start.
    #[test]
    fn saving_the_return_address_is_not_the_start() {
        // sw ra, 0x14(sp)
        let save_ra = decode_one(0xafbf_0014);
        assert_eq!(save_ra.to_string(), "sw ra, 0x14(sp)");
        assert!(!Mips32::LITTLE.is_prologue(&save_ra));
    }

    /// Adjusting another register, or adding to the stack pointer from
    /// somewhere else, is ordinary work.
    #[test]
    fn another_stack_adjustment_is_not_a_prologue() {
        // addiu a2, sp, 0x18, which takes the address of a frame slot.
        let address_of = decode_one(0x27a6_0018);
        assert!(!Mips32::LITTLE.is_prologue(&address_of));
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

    /// The `_gp_disp` pair opens a PIC function, so the function starts two
    /// words before its prologue.
    #[test]
    fn the_global_pointer_pair_counts_as_a_preamble() {
        // lui v0, 0x0 then addiu v0, v0, 0x0.
        let pair = [decode_one(0x3c02_0000), decode_one(0x2442_0000)];
        assert_eq!(Mips32::LITTLE.preamble_before_prologue(&pair), 2);
    }

    /// The pair must share one register, or the two words are unrelated and
    /// the second is an ordinary add.
    #[test]
    fn a_pair_on_two_registers_is_not_a_preamble() {
        // lui v0, 0x0 then addiu v1, v1, 0x0: different registers.
        let pair = [decode_one(0x3c02_0000), decode_one(0x2463_0000)];
        assert_eq!(Mips32::LITTLE.preamble_before_prologue(&pair), 0);
    }

    /// A linked file holds the real distance to the global offset table, so
    /// the pair opens the function whatever its values.
    #[test]
    fn a_linked_pair_counts_as_a_preamble() {
        // lui v0, 0x4 then addiu v0, v0, -0x6ff8, as ld.lld links zlib.
        let pair = [decode_one(0x3c02_0004), decode_one(0x2442_9008)];
        assert_eq!(Mips32::LITTLE.preamble_before_prologue(&pair), 2);
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

    /// Ordinary work before a prologue belongs to the function before it.
    #[test]
    fn plain_instructions_are_not_a_preamble() {
        let pair = [decode_one(0x0085_1021), decode_one(0x0085_1021)];
        assert_eq!(Mips32::LITTLE.preamble_before_prologue(&pair), 0);
    }

    /// A function at the very start of an image has nothing before it, and the
    /// slice length is what stops the rule reading past the front.
    #[test]
    fn a_preamble_cannot_reach_past_the_start() {
        assert_eq!(Mips32::LITTLE.preamble_before_prologue(&[]), 0);
        assert_eq!(Mips32::LITTLE.preamble_before_prologue(&[decode_one(0x2442_0000)]), 0);
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

    /// The trait's default says this architecture has no unwind index, which
    /// makes function recovery fall back to calls and returns.
    #[test]
    fn there_is_no_unwind_section() {
        assert_eq!(Mips32::LITTLE.unwind_section(), None);
    }

    /// Padding after an `eret` is padding, not the slot of a branch.
    #[test]
    fn padding_after_an_exception_return_is_trimmed() {
        let code: Vec<u8> =
            [0x2402_0001u32, 0x4200_0018, 0, 0].into_iter().flat_map(u32::to_le_bytes).collect();
        assert_eq!(Mips32::LITTLE.trim_padding(&code).len(), 8);
    }

    /// The bits `may_be_prologue` tests reject no word that opens a frame.
    #[test]
    fn a_word_the_bits_reject_opens_no_frame() {
        bolero::check!().with_type::<u32>().for_each(|&word| {
            for arch in [Mips32::LITTLE, Mips32::BIG] {
                let bytes = match arch.order() {
                    ByteOrder::Little => word.to_le_bytes(),
                    ByteOrder::Big => word.to_be_bytes(),
                };
                if !arch.may_be_prologue(&bytes)
                    && let Ok(insn) = arch.decode(&bytes, 0, 0)
                {
                    assert!(!arch.is_prologue(&insn), "{insn}");
                }
            }
        });
        let addiu = 0x27bd_ffe0_u32.to_be_bytes(); // addiu sp, sp, -0x20
        assert!(Mips32::BIG.may_be_prologue(&addiu));
        assert!(Mips32::BIG.is_prologue(&Mips32::BIG.decode(&addiu, 0, 0).unwrap()));
    }
}
