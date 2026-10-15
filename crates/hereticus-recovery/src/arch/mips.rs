//! The rules that find functions in MIPS32 code.
//!
//! Position-independent MIPS code reaches its data and its callees through
//! the global offset table, by the global pointer `gp` that each function
//! sets up from `t9`. A `switch` jumps by `jr` through a table of addresses,
//! or of offsets from `gp`. A branch has a delay slot, so the word after a
//! return still belongs to the function.

use super::{AbsoluteCall, CallTarget, Decoder, Insn, InsnKind, JumpTable, Memory, Recovery};
use hereticus_il as il;
use hereticus_il::arch::mips::*;
use hereticus_memory::AddressSpace;
use rabbitizer::opcodes::Opcode;

/// The operands of `insn`, lifted: see [`lifted`].
pub fn operands_of(insn: &Insn) -> il::Operands {
    lifted(insn).map(|lifted| lifted.operands).unwrap_or_default()
}

/// The register the ABI calls through, `t9`.
pub const T9: il::Reg = il::Reg::General(25);

/// The global pointer, `gp`.
pub const GP: il::Reg = il::Reg::General(28);

/// The stack pointer, `sp`.
pub const SP_REG: il::Reg = il::Reg::General(SP);

/// The register the first operand of `insn` names.
pub fn first_register(insn: &Insn) -> Option<il::Reg> {
    operands_of(insn).first().and_then(register)
}

/// The rules that read data through the global offset table.
pub trait TableRules {
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
    /// Only these two shapes are read. Unlike `Arch::constant_kinds` of
    /// `hereticus-arch`, this asks for the data, and a pair far apart is
    /// rare where a function passes a string on.
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
pub fn is_gp_disp_preamble(body: &[Insn]) -> bool {
    gp_disp_consumer(body).is_some()
}

/// The index in `body` of the `addu` that joins the pair of
/// [`is_gp_disp_preamble`] to `t9`.
pub fn gp_disp_consumer(body: &[Insn]) -> Option<usize> {
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
pub fn three_registers(insn: &Insn) -> Option<(il::Reg, il::Reg, il::Reg)> {
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

/// Read `lui rX, hi` as the register and the value it loads.
pub fn upper_half(insn: &Insn) -> Option<(il::Reg, u64)> {
    if !is(insn, Opcode::core_lui) {
        return None;
    }
    match operands_of(insn).as_slice() {
        [il::Operand::Reg(register), high] => Some((*register, (constant(high)? & 0xffff) << 16)),
        _ => None,
    }
}

/// How a lower half joins an upper half.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LowerHalf {
    /// By `addiu`, which adds it signed.
    Added,
    /// By `ori`, which puts it in the low 16 bits.
    Ored,
}

impl LowerHalf {
    /// How `insn` joins its lower half: an `ori` puts it in, and anything
    /// else adds it.
    pub fn of(insn: &Insn) -> Self {
        if is(insn, Opcode::core_ori) { Self::Ored } else { Self::Added }
    }
}

/// Join an upper half and a lower half as `joined` says.
///
/// A negative `addiu` immediate reads as a 64-bit two's complement, so
/// wrapping arithmetic on 32 bits gives the address the processor forms.
pub fn join_halves(joined: LowerHalf, high: u64, low: u64) -> u64 {
    match joined {
        LowerHalf::Ored => high | (low & 0xffff),
        LowerHalf::Added => u64::from((high as u32).wrapping_add(low as u32)),
    }
}

/// Report whether an instruction stores, which reads its first operand
/// rather than writing it.
pub fn is_store(insn: &Insn) -> bool {
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

/// The stack and frame pointers.
pub const SP: u8 = 29;

#[cfg(test)]
mod tests {
    use super::*;

    use crate::arch::decode_all;
    use hereticus_il::arch::DecodeError;

    /// Decode one instruction from a little-endian word at address 0.
    fn decode_one(word: u32) -> Insn {
        Mips32::LITTLE.decode(&word.to_le_bytes(), 0, 0).expect("bytes must decode")
    }

    /// Encodings from `llvm-mc --triple=mips --show-encoding`, as words.
    mod words {}

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
        use crate::arch::CallTarget;

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
        assert_eq!(hereticus_il::arch::printed_name(&nop), "nop");
        assert!(Mips32::LITTLE.is_padding(&nop));
        assert!(Mips32::LITTLE.trim_padding(&[0; 4]).is_empty());
    }

    #[test]
    fn trailing_padding_is_removed() {
        let mut code = 0x0085_1021u32.to_le_bytes().to_vec();
        code.extend_from_slice(&[0; 4]);
        assert_eq!(Mips32::LITTLE.trim_padding(&code), &code[..4]);
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
