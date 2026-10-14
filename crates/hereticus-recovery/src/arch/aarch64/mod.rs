//! AArch64 (A64) decoding, on top of `yaxpeax-arm`.
//!
//! Every instruction is 4 bytes, and a pointer 8. A64 keeps no literal pool
//! among its code where a compiler builds for PIC: it forms an address from
//! the page of `pc` and an offset in that page,
//!
//! ```text
//! adrp x0, page       ; the 4 KiB page of the data, relative to pc
//! add  x0, x0, #lo12  ; the data itself, or `ldr x1, [x0, #lo12]`
//! ```
//!
//! so the offset in the page is part of an address, and moves with it. The
//! unwind tables are `.eh_frame`, which the scan reads for any architecture,
//! and a `switch` jumps through a table of distances in `.rodata`.

pub use hereticus_il::arch::aarch64::*;

use super::{Insn, InsnKind, JumpTable, Memory, Recovery};
use crate::address::{AddressSpace, ConstantKind};
use hereticus_il::Reg;
use core::ops::Range;
use yaxpeax_arch::{Decoder as _, U8Reader};
use yaxpeax_arm::armv8::a64::{InstDecoder, Instruction, Opcode, Operand, ShiftStyle, SizeCode};

/// A page, as `adrp` counts them.
const PAGE: u64 = 0x1000;

/// The bits that make a word `adr` or `adrp`: `x 0 0 1 0 0 0 0` at the top,
/// where `x` tells them apart.
const ADR_MASK: u32 = 0x1f00_0000;

const ADR_BITS: u32 = 0x1000_0000;

/// The A64 `nop` encoding, little endian.
const NOP_BYTES: [u8; 4] = [0x1f, 0x20, 0x03, 0xd5];

/// Zero words, which some linkers pad with instead.
const ZERO_BYTES: [u8; 4] = [0; 4];

/// How far back the parts of a table jump may lie.
const TABLE_LOOK_BACK: usize = 32;

/// More cases than any `switch` a compiler turns into one table.
const MOST_CASES: usize = 4096;

impl Recovery for Aarch64 {
    /// Almost every function that calls another saves the frame pointer and
    /// the link register first, as `stp x29, x30, [sp, #-N]!`. A leaf that
    /// needs no frame has no prologue, which is why the scan treats this as
    /// one source among several.
    fn is_prologue(&self, insn: &Insn) -> bool {
        const X29: Operand = Operand::Register(SizeCode::X, 29);
        const X30: Operand = Operand::Register(SizeCode::X, 30);
        let operands = operands_of(insn);
        match (opcode_of(insn), operands.as_slice()) {
            (Some(Opcode::STP), [X29, X30, slot, ..]) => memory_base(*slot) == Some(SP),
            // Only the form that moves `sp` first, as `str x30, [sp, #-16]!`.
            (Some(Opcode::STR), [X30, Operand::RegPreIndex(SP, _, true), ..]) => true,
            _ => false,
        }
    }

    /// A signed return address, or a branch target mark, can come before
    /// the frame is made.
    fn preamble_before_prologue(&self, earlier: &[Insn]) -> usize {
        let Some(last) = earlier.last().and_then(decoded) else { return 0 };
        usize::from(matches!(
            (last.opcode, last.alias),
            (Opcode::PACIASP | Opcode::PACIBSP, _) | (_, Alias::BranchTarget)
        ))
    }

    fn is_padding(&self, insn: &Insn) -> bool {
        decoded(insn).is_some_and(|decoded| decoded.alias == Alias::Nop)
            || (insn.kind == InsnKind::Unknown && insn.bytes() == [0; INSN_WIDTH])
    }

    /// Only whole words at the end are removed, and only the two encodings a
    /// linker pads with.
    fn trim_padding<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        let mut end = bytes.len() - bytes.len() % INSN_WIDTH;
        while end >= INSN_WIDTH
            && (bytes[end - INSN_WIDTH..end] == NOP_BYTES
                || bytes[end - INSN_WIDTH..end] == ZERO_BYTES)
        {
            end -= INSN_WIDTH;
        }
        &bytes[..end]
    }

    /// The addresses a function forms from a page, and the pointers it
    /// loads from one where they point into the image: a text that only a
    /// table of pointers reaches is a text of the function too. A pointer
    /// of a Mach-O file reads as an address once its chained fixups are
    /// applied, as [`crate::callee::Links`] does.
    fn data_addresses(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        memory: &Memory<'_>,
    ) -> Vec<u64> {
        let pages = track_pages(code, body, space);
        let loaded = pages.pointer_loads.iter().filter_map(|&address| {
            let pointer = u64::from_le_bytes(memory.bytes(address, 8)?.try_into().ok()?);
            (pointer != address && space.contains_formed(pointer)).then_some(pointer)
        });
        pages.addresses.iter().copied().chain(loaded).collect()
    }

    /// Clang and GCC jump through a table of distances in `.rodata`:
    ///
    /// ```text
    /// adr  x28, table              ; or adrp and add
    /// ldrh w10, [x28, x9, lsl #1]  ; one entry, a count of instructions
    /// adr  x8, base
    /// add  x8, x8, x10, lsl #2     ; GCC: add x3, x3, w0, sxth #2
    /// br   x8
    /// ```
    ///
    /// A `cmp` of the case number before it bounds the table.
    fn jump_tables(&self, memory: &Memory<'_>, code: Range<u64>, insns: &[Insn]) -> Vec<JumpTable> {
        (0..insns.len()).filter_map(|index| read_jump_table(memory, &code, insns, index)).collect()
    }

    /// The stub LLD and GNU `ld` write for each PLT entry:
    ///
    /// ```text
    /// adrp x16, page
    /// ldr  x17, [x16, #lo12]
    /// add  x16, x16, #lo12
    /// br   x17
    /// ```
    fn stub_slot(&self, code: &[u8], address: u64) -> Option<u64> {
        // The scan asks at the target of every jump, so a word that is no
        // `adrp` or `adr` ends the question before anything decodes.
        let first = u32::from_le_bytes(code.get(..INSN_WIDTH)?.try_into().ok()?);
        if first & ADR_MASK != ADR_BITS {
            return None;
        }
        let (insns, _) = super::decode_all(self, code.get(..4 * INSN_WIDTH)?, address);
        let [adrp, load, add, jump] = insns.as_slice() else { return None };
        let page = page_of(adrp)?;
        let low = match operands_of(load).as_slice() {
            [x17, Operand::RegPreIndex(16, offset, false)] if is_x(*x17, 17) => {
                i64::from(*offset) as u64
            }
            _ => return None,
        };
        let adds_to_x16 = matches!(
            operands_of(add).as_slice(),
            [dest, source, ..] if is_x(*dest, 16) && is_x(*source, 16)
        );
        let jumps_through_x17 =
            matches!(operands_of(jump).as_slice(), [target] if is_x(*target, 17));
        let shape = opcode_of(load) == Some(Opcode::LDR)
            && opcode_of(add) == Some(Opcode::ADD)
            && adds_to_x16
            && opcode_of(jump) == Some(Opcode::BR)
            && jumps_through_x17;
        shape.then_some(page + low)
    }

    /// `br x16` and `br x17`: the ABI keeps these two for a jump the linker
    /// adds, a PLT stub or a veneer. A `switch` jumps through another.
    fn is_tail_call(&self, insn: &Insn) -> bool {
        opcode_of(insn) == Some(Opcode::BR)
            && matches!(operands_of(insn).as_slice(), [target] if is_x(*target, 16) || is_x(*target, 17))
    }
}


/// The frame pointer

/// The frame pointer, as the A64 procedure call standard names it.
const FRAME: Reg = Reg::General(29);

/// The operands of `insn`, as the decoder reads them from its bytes.
fn operands_of(insn: &Insn) -> Vec<Operand> {
    let mut inst = Instruction::default();
    if InstDecoder::default().decode_into(&mut inst, &mut U8Reader::new(insn.bytes())).is_err() {
        return Vec::new();
    }
    inst.operands.into_iter().take_while(|operand| *operand != Operand::Nothing).collect()
}

/// The number the A64 encodings give the stack pointer where it is the base
/// of an access, or the destination of `add` and `mov`.
const SP: u16 = 31;

/// The frame pointer, `x29`.
const X29_NUMBER: u16 = 29;

/// The base register of an access, by number, where `operand` is one.
fn memory_base(operand: Operand) -> Option<u16> {
    match operand {
        Operand::RegPreIndex(base, ..)
        | Operand::RegPostIndex(base, _)
        | Operand::RegPostIndexReg(base, _)
        | Operand::RegRegOffset(base, ..) => Some(base),
        _ => None,
    }
}

/// Whether `operand` reaches into the frame: an access through `sp` or
/// `x29`.
fn reaches_frame(operand: Operand) -> bool {
    matches!(memory_base(operand), Some(SP | X29_NUMBER))
}

/// A general register by its width and number, as `w8` is `(W, 8)`.
type Named = (SizeCode, u16);

/// The general register `operand` names.
fn named(operand: Operand) -> Option<Named> {
    match operand {
        Operand::Register(size, number) | Operand::RegisterOrSP(size, number) => {
            Some((size, number))
        }
        _ => None,
    }
}

/// The value of a constant operand, shifted where it names a shift.
fn immediate(operand: Operand) -> Option<u64> {
    match operand {
        Operand::Immediate(value) => Some(value.into()),
        Operand::ImmShift(value, shift) => Some(u64::from(value) << shift),
        _ => None,
    }
}

/// Whether `operand` is the 64-bit register `number`, as `x16`.
fn is_x(operand: Operand, number: u16) -> bool {
    matches!(operand, Operand::Register(SizeCode::X, n) | Operand::RegisterOrSP(SizeCode::X, n) if n == number)
}

/// Whether `operand` is `sp`, `wsp` or `x29`.
fn is_stack_or_frame(operand: Operand) -> bool {
    matches!(
        operand,
        Operand::RegisterOrSP(_, SP)
            | Operand::Register(SizeCode::X, X29_NUMBER)
            | Operand::RegisterOrSP(SizeCode::X, X29_NUMBER)
    )
}

fn opcode_of(insn: &Insn) -> Option<Opcode> {
    decoded(insn).map(|decoded| decoded.opcode)
}

/// A load, or an atomic access that `yaxpeax-arm` names as one: every
/// instruction it prints with `ld` first.
pub(crate) fn is_named_load(decoded: Decoded) -> bool {
    match role_of(decoded.opcode, decoded.alias) {
        Role::Load { .. } => true,
        Role::Atomic => !matches!(
            decoded.opcode,
            Opcode::CAS(_)
                | Opcode::CASB(_)
                | Opcode::CASH(_)
                | Opcode::CASP(_)
                | Opcode::SWP(_)
                | Opcode::SWPB(_)
                | Opcode::SWPH(_)
        ),
        _ => false,
    }
}

/// A load, a store or an atomic access of memory.
fn accesses_memory(decoded: Decoded) -> bool {
    !matches!(role_of(decoded.opcode, decoded.alias), Role::Compute | Role::ReadOnly)
}

/// Whether `insn` may write the register its operands name first. A store
/// names first a register it reads, and a compare the value it compares.
fn may_write_first(insn: &Insn) -> bool {
    decoded(insn).is_none_or(|decoded| {
        decoded.alias != Alias::Compare
            && !matches!(role_of(decoded.opcode, decoded.alias), Role::Store | Role::StoreExclusive)
    })
}

/// The page an `adrp` names, or the address an `adr` does.
fn page_of(insn: &Insn) -> Option<u64> {
    let Some(&Operand::PCOffset(offset)) = operands_of(insn).get(1) else { return None };
    let base = match opcode_of(insn)? {
        Opcode::ADRP => insn.address & !(PAGE - 1),
        Opcode::ADR => insn.address,
        _ => return None,
    };
    Some(base.wrapping_add(offset as u64))
}

/// What reading a function for its pages found.
struct Pages {
    kinds: Vec<ConstantKind>,
    /// The address each instruction forms or reads, or the page it takes.
    formed: Vec<Option<u64>>,
    addresses: Vec<u64>,
    /// Where a load of a whole pointer reads, from an address the page
    /// forms.
    pointer_loads: Vec<u64>,
}

/// Follow each register that holds a page from `adrp`, or an address from
/// `adr`, to the `add` or the load that joins an offset to it.
fn track_pages(code: &[u8], body: &[Insn], space: &AddressSpace) -> Pages {
    let mut kinds = vec![ConstantKind::Value; body.len()];
    let mut formed_at = vec![None; body.len()];
    let mut addresses = Vec::new();
    let mut pointer_loads = Vec::new();
    let Some(start) = body.first().map(|insn| insn.address) else {
        return Pages { kinds, formed: formed_at, addresses, pointer_loads };
    };
    // Registers holding a page, or an address.
    let mut held: Vec<(Tracked, u64)> = Vec::new();
    // The page each register last took from `adrp`. An `add` to itself
    // keeps it: on another path through the function, the register still
    // holds the page. GCC's `inflate_table` for AArch64 at `-Os` adds the
    // same offset to one page register on two paths.
    let mut pages = PageRegisters::default();
    fn values_of(list: &[(Tracked, u64)], register: Tracked) -> impl Iterator<Item = u64> + '_ {
        list.iter().filter(move |(held, _)| *held == register).map(|&(_, value)| value)
    }
    // The address a base register and an offset form, if what the register
    // holds, or a page it may hold, lands in the image.
    let formed = |held: &[(Tracked, u64)], pages: &PageRegisters, base: Tracked, low: u64| {
        values_of(held, base)
            .chain(pages.values(base).iter().copied())
            .map(|value| value.wrapping_add(low))
            .find(|&address| space.contains_formed(address))
    };

    for (index, insn) in body.iter().enumerate() {
        let after_an_end =
            index > 0 && matches!(body[index - 1].kind, InsnKind::Jump { .. } | InsnKind::Return);
        if after_an_end {
            pages.after_an_end();
        }
        // The operands as the decoder read them, from the word itself: the
        // text would have to be split and parsed again for each.
        let Some(decoded) = decoded(insn) else { continue };
        let Some(inst) = usize::try_from(insn.address - start)
            .ok()
            .and_then(|offset| code.get(offset..offset + INSN_WIDTH))
            .and_then(|word| {
                let mut inst = Instruction::default();
                InstDecoder::default().decode_into(&mut inst, &mut U8Reader::new(word)).ok()?;
                Some(inst)
            })
        else {
            continue;
        };
        let operands = &inst.operands;
        let destination = Tracked::of(operands[0]);
        match (decoded.opcode, decoded.alias, operands) {
            // The distance from `pc` to a page or to data moves whenever the
            // code or the data does.
            (Opcode::ADRP | Opcode::ADR, ..) => {
                kinds[index] = ConstantKind::Address;
                let Some(destination) = destination else { continue };
                held.retain(|(held, _)| *held != destination);
                pages.forget(destination);
                if let Some(value) = page_of(insn) {
                    formed_at[index] = Some(value);
                    if decoded.opcode == Opcode::ADR && space.contains_formed(value) {
                        addresses.push(value);
                    }
                    held.push((destination, value));
                    if decoded.opcode == Opcode::ADRP {
                        pages.take(destination, value);
                    }
                }
                continue;
            }
            // `add xD, xP, #lo12`: the address on the page.
            // A 32-bit add, as `add w20, w20, #0x1`, counts: it forms no
            // address, though it writes the register.
            (
                Opcode::ADD,
                Alias::None,
                [
                    Operand::RegisterOrSP(SizeCode::X, _),
                    source @ Operand::RegisterOrSP(SizeCode::X, _),
                    Operand::Immediate(low),
                    Operand::Nothing,
                ],
            ) => {
                let (Some(destination), Some(source)) = (destination, Tracked::of(*source)) else {
                    continue;
                };
                let low = u64::from(*low);
                let address = formed(&held, &pages, source, low);
                // An address outside what the image holds, as the data of a
                // kext linked apart, is still one to show.
                if address.is_none() {
                    formed_at[index] =
                        pages.values(source).first().map(|page| page.wrapping_add(low));
                }
                if let Some(address) = address {
                    kinds[index] = ConstantKind::Address;
                    formed_at[index] = Some(address);
                    addresses.push(address);
                    held.retain(|(held, _)| *held != destination);
                    held.push((destination, address));
                    if destination != source {
                        pages.forget(destination);
                    }
                    continue;
                }
            }
            // `ldr xD, [xP, #lo12]` and stores: data on the page. An index
            // register names no offset, but the page still moves.
            _ if accesses_memory(decoded) => {
                if let Some((base, low)) = operands.iter().find_map(|&operand| page_offset(operand))
                {
                    // A page outside the image, as the GOT can be, still moves.
                    let on_a_page = !pages.values(base).is_empty();
                    let address = low.and_then(|low| formed(&held, &pages, base, low));
                    if on_a_page || address.is_some() {
                        kinds[index] = ConstantKind::Address;
                    }
                    // A page outside the image, as the GOT of a kext can be,
                    // still names a slot.
                    formed_at[index] = address.or_else(|| {
                        let low = low?;
                        pages.values(base).first().map(|page| page.wrapping_add(low))
                    });
                    // `ldr x0, [x8, #lo12]` reads a whole pointer, as from a
                    // slot of the GOT or a table of texts.
                    if let Some(address) = address
                        && decoded.opcode == Opcode::LDR
                        && matches!(operands[0], Operand::Register(SizeCode::X, _))
                    {
                        pointer_loads.push(address);
                    }
                }
            }
            _ => {}
        }
        // Any other write of the register ends what it held. A write of
        // the low half, as `mov w24, w0`, clears the high half too, so it
        // ends it as well in truth; the text this replaced read `w24` and
        // `x24` as two registers, and that is kept until a measure says
        // which reads better (TODO.md).
        let writes_whole = matches!(
            operands[0],
            Operand::Register(SizeCode::X, _) | Operand::RegisterOrSP(SizeCode::X, _)
        );
        if let Some(destination) = destination
            && writes_whole
            && may_write_first(insn)
        {
            held.retain(|(held, _)| *held != destination);
            pages.forget(destination);
        }
    }
    Pages { kinds, formed: formed_at, addresses, pointer_loads }
}

/// A register [`track_pages`] follows: a general register by its number,
/// whichever width names it, or the stack pointer, as 31. The zero
/// register holds nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Tracked(u8);

impl Tracked {
    /// How many registers there are to follow.
    const COUNT: usize = 32;

    fn of(operand: Operand) -> Option<Self> {
        match operand {
            Operand::Register(_, 31) => None,
            Operand::Register(_, number) | Operand::RegisterOrSP(_, number) => {
                Some(Self(number.min(31) as u8))
            }
            _ => None,
        }
    }

    fn index(self) -> usize {
        usize::from(self.0)
    }
}

/// The base register of a memory operand that names an offset in a page,
/// and the offset, `None` for an index register. An offset of zero, as in
/// `[x8]`, joins no page. Nor does a load that writes its base back, as
/// `ldr w2, [x3, #0x48]!`: on libgnutls for arm64 that is a field of a
/// structure, and reading it as an address reported texts that are none.
fn page_offset(operand: Operand) -> Option<(Tracked, Option<u64>)> {
    let base = |number: u16| Tracked(number.min(31) as u8);
    match operand {
        Operand::RegPreIndex(number, offset, false) if offset != 0 => {
            Some((base(number), Some(i64::from(offset) as u64)))
        }
        // `[x1, x2]`. One that shifts or extends the index, as
        // `[x1, x14, lsl #2]`, indexes a table of its own.
        Operand::RegRegOffset(number, _, SizeCode::X, ShiftStyle::LSL, 0) => {
            Some((base(number), None))
        }
        _ => None,
    }
}

/// The pages each register may hold, as [`track_pages`] reads on.
///
/// Code that only a branch reaches, after a jump or a return, can find a
/// register as any path left it, and the path the page came by is not always
/// the one above: `inflate_table` copies over the page register just before
/// it jumps away. So each register keeps every page it ever took, and after
/// an end may hold any of them.
///
/// `track_pages` reads a whole region of a stripped library as one body, and
/// a library of 300000 instructions takes thousands of pages. A copy of every
/// page after each end then took 9.5 seconds on `libgnutls` for AArch64, so
/// a register after an end holds a count of its pages, not a copy. Only the
/// first page of a register that forms an address counts, so each page is
/// kept once, in the order it came.
struct PageRegisters {
    /// Every page each register took, each once, the first first.
    ever: [Vec<u64>; Tracked::COUNT],
    /// What each register holds on the path read now. `None` holds no page.
    now: [Option<MayHold>; Tracked::COUNT],
}

impl Default for PageRegisters {
    fn default() -> Self {
        Self { ever: core::array::from_fn(|_| Vec::new()), now: [None; Tracked::COUNT] }
    }
}

/// The pages a register may hold.
#[derive(Clone, Copy)]
enum MayHold {
    /// The first so many pages the register ever took.
    AnyOf(usize),
    /// The page it took last, on this path.
    One(u64),
}

impl PageRegisters {
    /// The pages `register` may hold, the most likely first.
    fn values(&self, register: Tracked) -> &[u64] {
        match &self.now[register.index()] {
            Some(MayHold::AnyOf(count)) => &self.ever[register.index()][..*count],
            Some(MayHold::One(page)) => core::slice::from_ref(page),
            None => &[],
        }
    }

    /// `register` takes `page` from `adrp`.
    fn take(&mut self, register: Tracked, page: u64) {
        self.now[register.index()] = Some(MayHold::One(page));
        let taken = &mut self.ever[register.index()];
        if !taken.contains(&page) {
            taken.push(page);
        }
    }

    /// `register` holds no page any more.
    fn forget(&mut self, register: Tracked) {
        self.now[register.index()] = None;
    }

    /// Past a jump or a return, each register may hold any page it took.
    fn after_an_end(&mut self) {
        for (now, taken) in self.now.iter_mut().zip(&self.ever) {
            *now = (!taken.is_empty()).then_some(MayHold::AnyOf(taken.len()));
        }
    }
}

/// Read the table a `br` at `insns[index]` jumps through.
fn read_jump_table(
    memory: &Memory<'_>,
    code: &Range<u64>,
    insns: &[Insn],
    index: usize,
) -> Option<JumpTable> {
    let jump = &insns[index];
    if opcode_of(jump) != Some(Opcode::BR) {
        return None;
    }
    let earlier = &insns[index.saturating_sub(TABLE_LOOK_BACK)..index];
    let last_write = |register: Named, before: u64| {
        earlier.iter().rev().filter(|insn| insn.address < before).find(|insn| {
            may_write_first(insn)
                && operands_of(insn).first().and_then(|&op| named(op)) == Some(register)
        })
    };
    // `add xT, xB, xE, lsl #2`, or GCC's `add xT, xB, wE, sxth #2`.
    let target = operands_of(jump).first().and_then(|&op| named(op))?;
    let add = last_write(target, jump.address)?;
    let (base_register, entry, style) = match operands_of(add).as_slice() {
        [_, base, Operand::RegShift(style, 2, _, entry)] => (named(*base)?, *entry, *style),
        _ => return None,
    };
    if opcode_of(add) != Some(Opcode::ADD) {
        return None;
    }
    let signed =
        matches!(style, ShiftStyle::SXTB | ShiftStyle::SXTH | ShiftStyle::SXTW | ShiftStyle::SXTX);
    let base = page_of(last_write(base_register, add.address)?)?;

    // `ldrb wE, [xTab, xI, lsl #1]` and the like: one entry.
    let load = last_write((SizeCode::W, entry), add.address)?;
    let width = match opcode_of(load)? {
        Opcode::LDRB | Opcode::LDRSB => 1,
        Opcode::LDRH | Opcode::LDRSH => 2,
        Opcode::LDR | Opcode::LDRSW => 4,
        _ => return None,
    };
    let (table_number, index_number) = match operands_of(load).as_slice() {
        [_, Operand::RegRegOffset(table, index, ..)] => (*table, *index),
        _ => return None,
    };
    let table_insn = last_write((SizeCode::X, table_number), load.address)?;
    let table = match opcode_of(table_insn)? {
        Opcode::ADR => page_of(table_insn)?,
        Opcode::ADD => {
            let (page_register, low) = match operands_of(table_insn).as_slice() {
                [_, page, low] => (named(*page)?, immediate(*low)?),
                _ => return None,
            };
            let page = page_of(last_write(page_register, table_insn.address)?)?;
            page.wrapping_add(low)
        }
        _ => return None,
    };

    // `cmp wI, #n`: the cases run from 0 to n.
    let bound = earlier.iter().rev().find_map(|insn| {
        let is_cmp = decoded(insn).is_some_and(|decoded| {
            decoded.opcode == Opcode::SUBS && decoded.alias == Alias::Compare
        });
        match operands_of(insn).as_slice() {
            [_, register, bound]
                if is_cmp && named(*register).map(|(_, n)| n) == Some(index_number) =>
            {
                immediate(*bound)
            }
            _ => None,
        }
    })?;
    let cases = usize::try_from(bound).ok()?.checked_add(1).filter(|&cases| cases <= MOST_CASES)?;

    let mut targets = Vec::with_capacity(cases);
    for case in 0..cases {
        let bytes = memory.bytes(table + (case * width) as u64, width)?;
        let entry = match (bytes, signed) {
            ([byte], false) => i64::from(*byte),
            ([byte], true) => i64::from(*byte as i8),
            ([low, high], false) => i64::from(u16::from_le_bytes([*low, *high])),
            ([low, high], true) => i64::from(i16::from_le_bytes([*low, *high])),
            ([a, b, c, d], _) => i64::from(i32::from_le_bytes([*a, *b, *c, *d])),
            _ => return None,
        };
        let target = base.checked_add_signed(entry * INSN_WIDTH as i64)?;
        if !code.contains(&target) {
            return None;
        }
        targets.push(target);
    }
    Some(JumpTable { jump: jump.address, words: table..table + (cases * width) as u64, targets })
}

