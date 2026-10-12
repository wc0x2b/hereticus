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

mod decode;
pub use decode::*;

use super::{Arch, Insn, InsnKind, JumpTable, Memory};
use crate::address::{AddressSpace, ConstantKind};
use crate::il::Reg;
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

impl Arch for Aarch64 {
    fn is_frame_register(&self, reg: Reg) -> bool {
        matches!(reg, Reg::Stack | FRAME)
    }

    fn is_frame_management(&self, insn: &Insn) -> bool {
        let Some(Decoded { opcode, alias }) = decoded(insn) else { return false };
        match (opcode, alias) {
            // Saving and restoring the frame and the registers it keeps.
            (Opcode::STP | Opcode::LDP | Opcode::STR | Opcode::LDR, _) => {
                operands_of(insn).iter().any(|&operand| reaches_frame(operand))
            }
            // Moving the stack pointer, or setting up the frame pointer.
            (_, Alias::Move)
            | (Opcode::SUB | Opcode::ADD | Opcode::MOVZ | Opcode::MOVN, Alias::None) => {
                operands_of(insn).first().is_some_and(|&operand| is_stack_or_frame(operand))
            }
            // Signing and checking the return address, and marking a branch
            // target, change nothing a function computes.
            (Opcode::PACIASP | Opcode::PACIBSP | Opcode::AUTIASP | Opcode::AUTIBSP, _)
            | (_, Alias::BranchTarget) => true,
            _ => false,
        }
    }

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

    /// The offset in a page that `add` or a load joins to an `adrp` is part
    /// of an address, and moves with the data it names.
    fn constant_kinds(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
    ) -> Vec<ConstantKind> {
        track_pages(code, body, space).kinds
    }

    fn formed_addresses(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        _memory: &Memory<'_>,
    ) -> Vec<Option<u64>> {
        track_pages(code, body, space).formed
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

#[cfg(test)]
mod extend_tests {
    use super::*;
    use crate::arch::Decoder as _;

    #[test]
    fn a_32_bit_register_in_a_64_bit_add_is_zero_extended() {
        let shown = |words: u32| {
            let code = words.to_le_bytes();
            let insn = Aarch64.decode(&code, 0, 0).expect("decodes");
            insn.to_string()
        };
        // From `llvm-mc --triple=aarch64`.
        assert_eq!(shown(0x8b21_5061), "add x1, x3, w1, uxtw #4");
        // `add x23, x10, w8, uxtw`, `sub x29, x6, w30, uxtw` and
        // `cmp x12, w11, uxtw`, as `llvm-mc` reads them.
        assert_eq!(shown(0x8b28_4157), "add x23, x10, w8, uxtw");
        assert_eq!(shown(0xcb3e_40dd), "sub x29, x6, w30, uxtw");
        assert_eq!(shown(0xeb2b_419f), "cmp x12, w11, uxtw");
        assert_eq!(shown(0x9b22_7c20), "smull x0, w1, w2");
        let extended = |opcode, operands: &str| extended_register(opcode, operands.into());
        assert_eq!(extended(Opcode::ADD, "x0, x1, x2, lsl #3"), "x0, x1, x2, lsl #3");
        assert_eq!(extended(Opcode::ADD, "w0, w1, w2, lsl #3"), "w0, w1, w2, lsl #3");
        assert_eq!(extended(Opcode::SMADDL, "x0, w1, w2"), "x0, w1, w2");
        assert_eq!(extended(Opcode::ADD, "x0, x1, w2, sxtw"), "x0, x1, w2, sxtw");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::Decoder as _;
    use crate::arch::decode_all;
    use crate::il::{
        self, AccessKind, Cond, Guard, Lifted, MemoryAccess, Op, RegSet, Test, Value, Width,
    };

    /// After an end, a register may hold any page it took, each once and
    /// the first first; a new page on the path read now replaces them.
    #[test]
    fn a_register_after_an_end_may_hold_any_page_it_took() {
        let mut pages = PageRegisters::default();
        pages.take(Tracked(8), 0x1000);
        pages.take(Tracked(8), 0x2000);
        pages.take(Tracked(8), 0x1000);
        pages.take(Tracked(9), 0x3000);
        assert_eq!(pages.values(Tracked(8)), [0x1000]);
        pages.forget(Tracked(9));
        assert!(pages.values(Tracked(9)).is_empty());

        pages.after_an_end();
        assert_eq!(pages.values(Tracked(8)), [0x1000, 0x2000]);
        assert_eq!(pages.values(Tracked(9)), [0x3000]);
        assert!(pages.values(Tracked(10)).is_empty());

        // A page taken later is not one this path may hold.
        pages.take(Tracked(9), 0x4000);
        pages.forget(Tracked(9));
        assert_eq!(pages.values(Tracked(8)), [0x1000, 0x2000]);
        pages.after_an_end();
        assert_eq!(pages.values(Tracked(9)), [0x3000, 0x4000]);
    }

    fn code(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn decode_one(word: u32) -> Insn {
        Aarch64.decode(&word.to_le_bytes(), 0, 0x1000).expect("the word must decode")
    }

    /// Encodings from `llvm-mc --triple=aarch64 -mattr=+lse --show-encoding`.
    mod words {
        pub const CBNZ_X8: u32 = 0xb500_00e8;
        pub const CBZ_X8: u32 = 0xb400_0068;
        pub const CMN_X8_1: u32 = 0xb100_051f;
        pub const B_NE: u32 = 0x5400_0121;
        pub const CMP_X8_0: u32 = 0xf100_011f;
        pub const CMP_W2_63: u32 = 0x7100_fc5f;
        pub const B_HI: u32 = 0x5400_0208;
        pub const TST_W0_4: u32 = 0x721e_001f;
        pub const B_EQ: u32 = 0x5400_0080;
        pub const TBZ_W0_2: u32 = 0x3610_0080;
        pub const ADD_X0_X1_X2: u32 = 0x8b02_0020;
        pub const LDR_X1_X2_8: u32 = 0xf940_0441;
        pub const LDP_X29_X30_SP_POST: u32 = 0xa8c1_7bfd;
        pub const STR_W3_X4_X5: u32 = 0xb825_6883;
        pub const STXR_W1_X2_X3: u32 = 0xc801_7c62;
        pub const BL: u32 = 0x9400_0040;
        pub const BLR_X8: u32 = 0xd63f_0100;
        pub const RET: u32 = 0xd65f_03c0;
        pub const CSEL_X8_XZR_X8_EQ: u32 = 0x9a88_03e8;
        pub const MOVK_X23: u32 = 0xf2e3_05d7;
        pub const SUBS_X0_X0_1: u32 = 0xf100_0400;
        pub const LDADD_W1_W2_X3: u32 = 0xb821_0062;
        pub const CMP_X1_X2: u32 = 0xeb02_003f;
    }

    fn lift_one(word: u32) -> Lifted {
        Aarch64.lift(&decode_one(word)).expect("the word must lift")
    }

    fn regs(regs: &[Reg]) -> RegSet {
        regs.iter().copied().collect()
    }

    fn x(number: u8) -> Reg {
        Reg::General(number)
    }

    /// The first guard that `words` make, and how many words it takes.
    fn guard_of(words: &[u32]) -> Option<(usize, Guard)> {
        let lifted: Vec<Option<Lifted>> = words.iter().map(|&word| Some(lift_one(word))).collect();
        let found = *crate::il::find_guards(&lifted).first()?;
        Some((found.branch + 1 - found.compare.unwrap_or(found.branch), found.guard))
    }

    #[test]
    fn cbnz_and_cmp_with_b_ne_are_one_guard() {
        let (taken, fused) = guard_of(&[words::CMP_X8_0, words::B_NE]).unwrap();
        assert_eq!(taken, 2);
        assert_eq!(guard_of(&[words::CBNZ_X8]), Some((1, fused)));
        assert_eq!(fused.cond, Cond::NotEqual);
        assert_eq!(fused.left, Value::Reg(x(8)));
        assert_eq!(fused.right, Value::Const(0));
    }

    #[test]
    fn cbz_tests_for_zero() {
        let (_, guard) = guard_of(&[words::CBZ_X8]).unwrap();
        assert_eq!(guard.cond, Cond::Equal);
        assert_eq!(guard.width, Width::Bits64);
    }

    /// The check of CVE-2024-23265: `x8 != -1`.
    #[test]
    fn cmn_with_one_compares_with_minus_one() {
        let (_, guard) = guard_of(&[words::CMN_X8_1, words::B_NE]).unwrap();
        assert_eq!(guard.cond, Cond::NotEqual);
        assert_eq!(guard.right, Value::Const(u64::MAX));
    }

    /// The check of CVE-2025-24257: a size above 63.
    #[test]
    fn a_32_bit_bound_keeps_its_width() {
        let (_, guard) = guard_of(&[words::CMP_W2_63, words::B_HI]).unwrap();
        assert_eq!(guard.cond, Cond::UnsignedGreater);
        assert_eq!(guard.left, Value::Reg(x(2)));
        assert_eq!(guard.right, Value::Const(63));
        assert_eq!(guard.width, Width::Bits32);
    }

    #[test]
    fn tst_with_b_eq_and_tbz_are_one_guard() {
        let (_, tst) = guard_of(&[words::TST_W0_4, words::B_EQ]).unwrap();
        let (_, tbz) = guard_of(&[words::TBZ_W0_2]).unwrap();
        assert_eq!(tst, tbz);
        assert_eq!(tbz.cond, Cond::BitsClear);
        assert_eq!(tbz.right, Value::Const(4));
    }

    #[test]
    fn a_compare_of_two_registers_reads_both() {
        let lifted = lift_one(words::CMP_X1_X2);
        assert_eq!(lifted.reads, regs(&[x(1), x(2)]));
        assert_eq!(lifted.writes, regs(&[Reg::Flags]), "the zero register is no destination");
    }

    #[test]
    fn arithmetic_that_sets_flags_is_no_compare() {
        let lifted = lift_one(words::SUBS_X0_X0_1);
        assert_eq!(lifted.writes, regs(&[x(0), Reg::Flags]));
        assert_eq!(lifted.test, None, "a loop count is work, not a check");
    }

    #[test]
    fn computing_writes_the_first_operand() {
        let lifted = lift_one(words::ADD_X0_X1_X2);
        assert_eq!(lifted.writes, regs(&[x(0)]));
        assert_eq!(lifted.reads, regs(&[x(1), x(2)]));
        assert_eq!(lifted.memory, None);
    }

    #[test]
    fn loads_and_stores_name_their_registers_and_width() {
        let load = lift_one(words::LDR_X1_X2_8);
        assert_eq!((load.reads, load.writes), (regs(&[x(2)]), regs(&[x(1)])));
        assert_eq!(
            load.memory,
            Some(MemoryAccess { kind: AccessKind::Load, width: Some(Width::Bits64) })
        );

        let pair = lift_one(words::LDP_X29_X30_SP_POST);
        assert_eq!(pair.writes, regs(&[x(29), x(30), Reg::Stack]), "the base is written back");
        assert_eq!(pair.reads, regs(&[Reg::Stack]));

        let store = lift_one(words::STR_W3_X4_X5);
        assert_eq!(store.reads, regs(&[x(3), x(4), x(5)]));
        assert!(store.writes.is_empty());
        assert_eq!(
            store.memory,
            Some(MemoryAccess { kind: AccessKind::Store, width: Some(Width::Bits32) })
        );

        let exclusive = lift_one(words::STXR_W1_X2_X3);
        assert_eq!(exclusive.writes, regs(&[x(1)]), "the status");
        assert_eq!(exclusive.reads, regs(&[x(2), x(3)]));

        let atomic = lift_one(words::LDADD_W1_W2_X3);
        assert_eq!((atomic.reads, atomic.writes), (regs(&[x(1), x(3)]), regs(&[x(2)])));
        assert_eq!(atomic.memory.map(|access| access.kind), Some(AccessKind::LoadStore));
    }

    #[test]
    fn calls_and_returns_use_the_link_register() {
        assert_eq!(lift_one(words::BL).writes, regs(&[x(30)]));
        let indirect = lift_one(words::BLR_X8);
        assert_eq!((indirect.reads, indirect.writes), (regs(&[x(8)]), regs(&[x(30)])));
        assert!(lift_one(words::RET).reads.contains(x(30)));
    }

    #[test]
    fn a_select_reads_the_flags_and_a_movk_its_destination() {
        let select = lift_one(words::CSEL_X8_XZR_X8_EQ);
        assert_eq!(select.reads, regs(&[x(8), Reg::Flags]));
        assert_eq!(select.writes, regs(&[x(8)]));
        let movk = lift_one(words::MOVK_X23);
        assert_eq!((movk.reads, movk.writes), (regs(&[x(23)]), regs(&[x(23)])));
    }

    #[test]
    fn operands_come_in_printed_order() {
        use il::Operand::{Const, Other, Target, Zero};
        let reg = |number| il::Operand::Reg(x(number));
        let operands = |word| lift_one(word).operands.into_vec();
        assert_eq!(operands(words::SUBS_X0_X0_1), [reg(0), reg(0), Const(1)]);
        assert_eq!(operands(words::CSEL_X8_XZR_X8_EQ), [reg(8), Zero, reg(8), Other]);
        assert!(
            matches!(operands(words::BL).as_slice(), [Target(Some(_))]),
            "a call names its distance"
        );
        assert_eq!(operands(words::RET), [reg(30)], "the link register");
    }

    #[test]
    fn a_memory_operand_names_its_base_and_offset() {
        let memory = |word| *lift_one(word).operands.last().expect("a memory operand");
        assert_eq!(memory(words::LDR_X1_X2_8), il::Operand::memory(Some(x(2)), Some(8)));
        assert_eq!(memory(words::STR_W3_X4_X5), il::Operand::memory(Some(x(4)), None));
        let written = |offset, update| il::Operand::Memory {
            base: Some(Reg::Stack),
            offset: Some(offset),
            index: None,
            update,
        };
        assert_eq!(memory(words::LDP_X29_X30_SP_POST), written(16, il::Update::After));
        // stp x29, x30, [sp, #-0x10]!
        assert_eq!(memory(0xa9bf_7bfd), written(-16, il::Update::Before));
    }

    #[test]
    fn the_frame_registers_are_sp_and_x29() {
        assert!(Aarch64.is_frame_register(Reg::Stack));
        assert!(Aarch64.is_frame_register(x(29)));
        assert!(!Aarch64.is_frame_register(x(28)));
        assert!(!Aarch64.is_frame_register(Reg::Vector(29)));
    }

    #[test]
    fn lifting_any_word_never_panics() {
        bolero::check!().with_type::<u32>().for_each(|&word| {
            let bytes = word.to_le_bytes();
            let insn = Aarch64.decode(&bytes, 0, 0x1000).expect("every word decodes or is unknown");
            if let Some(lifted) = Aarch64.lift(&insn)
                && let Some(Test::Guard(_) | Test::OnFlags(_)) = lifted.test
            {
                assert!(
                    matches!(insn.kind, InsnKind::Branch { .. }),
                    "{insn}: a test that branches"
                );
            }
        });
    }

    #[test]
    fn control_moves_as_the_instruction_says() {
        assert_eq!(decode_one(0xd65f_03c0).kind, InsnKind::Return); // ret
        assert_eq!(decode_one(0x9400_0004).kind, InsnKind::Call { target: Some(0x1010) }); // bl
        assert_eq!(decode_one(0x1400_0002).kind, InsnKind::Jump { target: Some(0x1008) }); // b
        assert_eq!(decode_one(0x5400_0041).kind, InsnKind::Branch { target: Some(0x1008) }); // b.ne
        assert_eq!(decode_one(0xb400_0060).kind, InsnKind::Branch { target: Some(0x100c) }); // cbz x0
        assert_eq!(decode_one(0xd61f_0220).kind, InsnKind::Jump { target: None }); // br x17
        assert_eq!(decode_one(0xd63f_0100).kind, InsnKind::Call { target: None }); // blr x8
    }

    #[test]
    fn the_frame_record_opens_a_function() {
        assert!(Aarch64.is_prologue(&decode_one(0xa9bd_7bfd))); // stp x29, x30, [sp, #-0x30]!
        assert!(!Aarch64.is_prologue(&decode_one(0xa901_57f6))); // stp x22, x21, [sp, #0x10]
        assert!(Aarch64.is_tail_call(&decode_one(0xd61f_0220))); // br x17
        assert!(!Aarch64.is_tail_call(&decode_one(0xd61f_0100))); // br x8
    }

    /// `adrp` and `add` form an address, and the offset in the page moves
    /// with it.
    #[test]
    fn a_page_and_an_offset_form_an_address() {
        let words = [
            0x9000_0080, // 0x1000 adrp x0, 0x11000
            0x9100_a000, // 0x1004 add x0, x0, #0x28
            0xd65f_03c0, // 0x1008 ret
        ];
        let (insns, _) = decode_all(&Aarch64, &code(&words), 0x1000);
        let space = AddressSpace::from_ranges(core::iter::once(0x1000..0x20000));
        assert_eq!(
            Aarch64.data_addresses(&code(&words), &insns, &space, &Memory::new(&[])),
            [0x11028]
        );
        let kinds = Aarch64.constant_kinds(&code(&words), &insns, &space);
        assert_eq!(kinds[..2], [ConstantKind::Address, ConstantKind::Address]);
    }

    /// A load from a page outside the image, as the GOT can be, still reads
    /// at an address that moves when the linker lays the image out again.
    #[test]
    fn a_load_from_any_page_reads_at_an_address() {
        let words = [
            0x9000_0080, // 0x1000 adrp x0, 0x11000
            0xf940_3408, // 0x1004 ldr x8, [x0, #0x68]
            0xf940_3428, // 0x1008 ldr x8, [x1, #0x68]
            0xd65f_03c0, // 0x100c ret
        ];
        let (insns, _) = decode_all(&Aarch64, &code(&words), 0x1000);
        let space = AddressSpace::from_ranges(core::iter::once(0x1000..0x2000));
        let kinds = Aarch64.constant_kinds(&code(&words), &insns, &space);
        assert_eq!(kinds[1], ConstantKind::Address, "through the page");
        assert_eq!(kinds[2], ConstantKind::Value, "through a register with no page");
    }

    /// The bits `stub_slot` tests first are those of `adr` and `adrp`.
    #[test]
    fn the_address_bits_are_adr_and_adrp() {
        bolero::check!().with_type::<u32>().for_each(|&word| {
            let opcode = opcode_of(&decode_one(word));
            let is_address = matches!(opcode, Some(Opcode::ADR | Opcode::ADRP));
            assert_eq!(word & ADR_MASK == ADR_BITS, is_address, "{word:#010x}");
        });
    }

    /// The PLT stub of LLD for AArch64, from zlib.
    #[test]
    fn reads_the_slot_a_plt_stub_jumps_through() {
        let stub = code(&[0x9000_0110, 0xf942_3e11, 0x9111_e210, 0xd61f_0220]);
        assert_eq!(Aarch64.stub_slot(&stub, 0x1a210), Some(0x3a478));
        assert_eq!(Aarch64.stub_slot(&stub[..8], 0x1a210), None, "too short");
        // The stub of `lua_settable` in Lua for AArch64 at `-Os`, whose slot
        // starts its page: `ldr x17, [x16]`.
        let at_page = code(&[0xd000_0110, 0xf940_0211, 0x9100_0210, 0xd61f_0220]);
        assert_eq!(Aarch64.stub_slot(&at_page, 0x36710), Some(0x58000));
    }

    /// `bti` marks where an indirect branch may land, and comes before the
    /// frame is made. `yaxpeax-arm` 0.4 prints it as `hint #0x22`.
    #[test]
    fn a_branch_target_mark_comes_before_the_prologue() {
        let bti_c = decode_one(0xd503_245f);
        assert_eq!(Aarch64.preamble_before_prologue(core::slice::from_ref(&bti_c)), 1);
        assert!(Aarch64.is_frame_management(&bti_c));
        let paciasp = decode_one(0xd503_233f);
        assert_eq!(Aarch64.preamble_before_prologue(&[paciasp]), 1);
        let nop = decode_one(0xd503_201f);
        assert_eq!(Aarch64.preamble_before_prologue(&[nop]), 0);
    }

    #[test]
    fn padding_is_nops_and_zeros() {
        let bytes = code(&[0xd65f_03c0, 0xd503_201f, 0]);
        assert_eq!(Aarch64.trim_padding(&bytes), &bytes[..4]);
        assert!(Aarch64.is_padding(&decode_one(0xd503_201f)));
    }

    /// An exclusive access is one step of an atomic sequence, never a plain
    /// load or store that a pair could stand for.
    #[test]
    fn an_exclusive_access_is_atomic() {
        assert_eq!(lift_one(words::STXR_W1_X2_X3).op, Op::Atomic);
        // `ldxp x1, x2, [x0]`
        assert_eq!(lift_one(0xc87f_0801).op, Op::Atomic);
        assert_eq!(lift_one(words::LDR_X1_X2_8).op, Op::Load);
    }

    /// `floor` and `ceil` inline as `frintm` and `frintp`, and Lua's
    /// `math_floor` and `math_ceil` are twins but for them.
    #[test]
    fn a_float_operation_names_what_it_computes() {
        let cases = [
            (0x1e61_0800_u32, Op::FloatMultiply),    // fmul d0, d0, d1
            (0x1e61_1800, Op::FloatDivide),          // fdiv d0, d0, d1
            (0x1e65_4000, Op::FloatRoundDown),       // frintm d0, d0
            (0x1e64_c000, Op::FloatRoundUp),         // frintp d0, d0
            (0x1e78_0000, Op::FloatRoundTowardZero), // fcvtzs w0, d0
            (0x1e62_0000, Op::FloatConvert),         // scvtf d0, w0
        ];
        for (word, op) in cases {
            assert_eq!(lift_one(word).op, op, "{word:#010x}");
        }
    }

    /// The decoder prints an alias in place of the instruction it stands
    /// for, and the alias names what the instruction computes.
    #[test]
    fn an_alias_computes_what_it_names() {
        let cases = [
            (0x2a01_03e0_u32, Op::Move),             // mov w0, w1 (orr)
            (0x9100_03e0, Op::Move),                 // mov x0, sp (add)
            (0x4b01_03e0, Op::Negate),               // neg w0, w1 (sub)
            (0xeb01_03e0, Op::Negate),               // negs x0, x1 (subs)
            (0xda01_03e0, Op::Negate),               // ngc x0, x1 (sbc)
            (0x2a21_03e0, Op::Not),                  // mvn w0, w1 (orn)
            (0x9b02_7c20, Op::Multiply),             // mul x0, x1, x2 (madd)
            (0x9b22_fc20, Op::Multiply),             // smnegl x0, w1, w2 (smsubl)
            (0xd37f_f800, Op::ShiftLeft),            // lsl x0, x0, #1 (ubfm)
            (0xd341_fc00, Op::ShiftRight),           // lsr x0, x0, #1 (ubfm)
            (0x5300_1c00, Op::Extend),               // uxtb w0, w0 (ubfm)
            (0xd344_1c00, Op::BitField),             // ubfx x0, x0, #4, #4 (ubfm)
            (0x1300_1c00, Op::Extend),               // sxtb w0, w0 (sbfm)
            (0x9340_7c00, Op::Extend),               // sxtw x0, w0 (sbfm)
            (0x9340_fc00, Op::ShiftRightArithmetic), // asr x0, x0, #0 (sbfm)
            (words::CMP_X1_X2, Op::Compare),         // cmp x1, x2 (subs)
            (words::TST_W0_4, Op::Compare),          // tst w0, #4 (ands)
            (words::SUBS_X0_X0_1, Op::Subtract),     // subs x0, x0, #1
        ];
        for (word, op) in cases {
            assert_eq!(lift_one(word).op, op, "{word:#010x}");
        }
    }

    /// `ldadd w1, wzr, [x0]` keeps no old value, and prints as `stadd`. An
    /// acquiring form has no such alias, as it orders what comes after it.
    #[test]
    fn an_atomic_that_keeps_no_value_is_a_store() {
        let store = lift_one(0xb821_001f); // stadd w1, [x0]
        assert_eq!(store.op, Op::Store);
        assert_eq!(store.memory.map(|access| access.kind), Some(AccessKind::Store));
        assert!(store.writes.is_empty());
        assert_eq!(lift_one(0xb8a1_001f).op, Op::Atomic); // ldadda w1, wzr, [x0]
    }

    /// Instructions that keep part of their destination read it.
    #[test]
    fn an_insert_reads_its_destination() {
        let insert = lift_one(0x4e0c_1c20); // mov v0.s[1], w1 (ins)
        assert!(insert.reads.contains(Reg::Vector(0)));
        assert!(insert.writes.contains(Reg::Vector(0)));
        let select = lift_one(0x6e62_1c20); // bsl v0.16b, v1.16b, v2.16b
        assert!(select.reads.contains(Reg::Vector(0)));
        assert!(select.writes.contains(Reg::Vector(0)));
    }

    /// `ldrab` loads a whole pointer, though its name ends in `b`.
    #[test]
    fn a_signed_pointer_load_moves_a_pointer() {
        let load = lift_one(0xf8bf_0c20); // ldrab x0, [x1, #0xf80]!
        assert_eq!(load.memory.and_then(|access| access.width), Some(Width::Bits64));
    }

    /// `bc.eq` branches as `b.eq` does, and `eret` returns.
    #[test]
    fn a_hinted_branch_and_an_exception_return_move_control() {
        let branch = decode_one(0x5400_0010); // bc.eq
        assert_eq!(branch.kind, InsnKind::Branch { target: Some(0x1000) });
        let lifted = lift_one(0x5400_0010);
        assert_eq!(lifted.test, Some(Test::OnFlags(Cond::Equal)));
        assert!(lifted.reads.contains(Reg::Flags));
        assert_eq!(decode_one(0xd69f_03e0).kind, InsnKind::Return);
        assert_eq!(lift_one(0xd69f_03e0).op, Op::Return);
        assert_eq!(lift_one(0xd503_229f).op, Op::System, "csdb");
    }

    /// A function that loads a pointer from a table points at what the
    /// pointer does, where it lands in the image.
    #[test]
    fn a_pointer_loaded_from_a_page_is_an_address_of_the_function() {
        let words = [
            0x9000_0088, // 0x1000 adrp x8, 0x11000
            0xf940_0900, // 0x1004 ldr x0, [x8, #0x10]
            0xd65f_03c0, // 0x1008 ret
        ];
        let (insns, _) = decode_all(&Aarch64, &code(&words), 0x1000);
        let space = AddressSpace::from_ranges(core::iter::once(0x1000..0x20000));
        let addresses = |pointer: u64| {
            let mut data = vec![0u8; 0x20];
            data[0x10..0x18].copy_from_slice(&pointer.to_le_bytes());
            let regions = [(0x11000, data.as_slice())];
            Aarch64.data_addresses(&code(&words), &insns, &space, &Memory::new(&regions))
        };
        assert!(addresses(0x12345).contains(&0x12345), "a pointer into the image");
        assert!(!addresses(0).contains(&0), "an unrelocated slot holds nothing");
        assert!(!addresses(0x9999_0000).contains(&0x9999_0000), "a pointer out of the image");
    }
}
