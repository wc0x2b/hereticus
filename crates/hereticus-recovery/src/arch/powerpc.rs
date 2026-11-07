//! The rules that find functions in PowerPC code, 32-bit and 64-bit.
//!
//! Every instruction is 4 bytes, and a pointer 4 or 8. A function that makes a
//! frame opens with `stwu r1, -N(r1)`, which stores the back chain and
//! moves the stack pointer in one. A call returns through the link
//! register, which a function that calls saves first:
//!
//! ```text
//! mflr r0
//! stwu r1, -0x20(r1)
//! stw  r0, 0x24(r1)
//! ```
//!
//! Code that is not PIC forms an address from two halves, as MIPS does:
//! `lis r9, hi` and `addi r9, r9, lo`, or `lis` and the offset of a load.
//! PIC code reads the program counter with `bcl 20, 31` and `mflr`, and
//! reaches its data from there. GCC adds the distance to the global offset
//! table with `addis` and `addi`; clang loads it from a word just before
//! the function, which is data among the code.
//!
//! 64-bit code makes its frame with `stdu r1, -N(r1)`, and reaches its data
//! through the TOC that `r2` holds. An ELFv2 function that reads the TOC
//! makes it first from `r12`, which holds the address of the function on
//! entry:
//!
//! ```text
//! addis r2, r12, hi
//! addi  r2, r2, lo
//! ```

use super::{Insn, InsnKind, JumpTable, Memory, Recovery};
use core::ops::Range;
use hereticus_il::arch::Decoder as _;
use hereticus_il::arch::powerpc::*;
use hereticus_memory::{AddressSpace, ConstantKind};
use yaxpeax_power::{Instruction, Operand};

/// `nop`, which is `ori r0, r0, 0`.
const NOP: u32 = 0x6000_0000;

/// `ori r2, r2, 0`, the `nop` that ends a dispatch group, which GCC pads
/// a loop of 64-bit code with.
const GROUP_NOP: u32 = 0x6042_0000;

/// `trap`, which LLD fills the gaps between 64-bit functions with.
const TRAP: u32 = 0x7fe0_0008;

/// The volatile general registers, which a call does not keep: `r0` and
/// `r3` to `r12`.
const VOLATILE: [u8; 11] = [0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

/// The register that holds the global offset table in PIC code, by the
/// SVR4 ABI.
const PIC_BASE: u8 = 30;

/// The register that holds the TOC in 64-bit code.
const TOC: u8 = 2;

/// The register that holds the address of an ELFv2 function on entry.
const ENTRY: u8 = 12;

/// The register through which code reaches its table, in `mode`.
fn table_register(mode: Mode) -> u8 {
    match mode {
        Mode::Bits32 => PIC_BASE,
        Mode::Bits64 => TOC,
    }
}

/// The value `mode` holds of `value`: its low 32 bits, or all of it.
fn in_mode(mode: Mode, value: u64) -> u64 {
    match mode {
        Mode::Bits32 => value & 0xffff_ffff,
        Mode::Bits64 => value,
    }
}

/// How far back the parts of a table jump may lie.
const TABLE_LOOK_BACK: usize = 16;

/// More cases than any `switch` a compiler turns into one table.
const MOST_CASES: usize = 4096;

/// How far from its jump a case may lie when no bound gives the number of
/// cases. A table is followed by other data, which this keeps from reading
/// as more cases.
const MOST_CASE_DISTANCE: u64 = 0x1_0000;

/// The word at the start of `bytes`, in the byte order of `arch`, where
/// `bytes` hold one.
fn word_at(arch: PowerPc, bytes: &[u8]) -> Option<u32> {
    Some(arch.word(bytes.get(..INSN_WIDTH)?.try_into().ok()?))
}

/// The operands of `inst`, in the order of the hardware.
pub fn hardware_operands(inst: &Instruction) -> Vec<Operand> {
    (0..inst.operand_count()).filter_map(|index| inst.operand(index as u8).copied()).collect()
}

/// `insn` decoded again, with its operands, where it is PowerPC.
fn read(insn: &Insn) -> Option<(Instruction, Vec<Operand>)> {
    let inst = instruction(insn)?;
    let operands = hardware_operands(&inst);
    Some((inst, operands))
}

impl Recovery for PowerPc {
    /// `stwu r1, -N(r1)`, and `stwux r1, r1, rN` for a frame larger than a
    /// displacement holds; `stdu` and `stdux` in 64-bit code. Only a
    /// function that needs no frame lacks one.
    fn is_prologue(&self, insn: &Insn) -> bool {
        let Some((inst, operands)) = read(insn) else { return false };
        match (inst.opcode(), operands.as_slice()) {
            (Opcode::STWU, [Operand::Register(stored), Operand::MemoryDisp { base, disp }]) => {
                stored.num() == STACK && base.num() == STACK && *disp < 0
            }
            (Opcode::STDU, [Operand::Register(stored), Operand::MemoryDisp { base, disp }]) => {
                self.mode() == Mode::Bits64
                    && stored.num() == STACK
                    && base.num() == STACK
                    && *disp < 0
            }
            (Opcode::STWUX, [Operand::Register(stored), Operand::MemoryIndexed { base, .. }]) => {
                stored.num() == STACK && base.num() == STACK
            }
            (Opcode::STDUX, [Operand::Register(stored), Operand::MemoryIndexed { base, .. }]) => {
                self.mode() == Mode::Bits64 && stored.num() == STACK && base.num() == STACK
            }
            _ => false,
        }
    }

    /// `stwu r1, d(r1)` is primary opcode 37 with `r1` in both register
    /// fields, and `stwux r1, r1, rB` opcode 31 with extended opcode 183.
    /// `stdu` is opcode 62 with 1 in the two lowest bits, and `stdux`
    /// extended opcode 181. The decoder reads the two indexed forms whatever
    /// their lowest bit, the record bit, holds, as `0x7c21016f`.
    fn may_be_prologue(&self, word: &[u8]) -> bool {
        const STWU_R1_R1: u32 = 0x9421_0000;
        const STWUX_R1_R1: u32 = 0x7c21_016e;
        const STDU_R1_R1: u32 = 0xf821_0001;
        const STDUX_R1_R1: u32 = 0x7c21_016a;
        /// The two register fields and the extended opcode, without the
        /// record bit.
        const INDEXED: u32 = 0xffff_07fe;
        word_at(*self, word).is_some_and(|word| {
            word & 0xffff_0000 == STWU_R1_R1
                || word & INDEXED == STWUX_R1_R1
                || word & 0xffff_0003 == STDU_R1_R1
                || word & INDEXED == STDUX_R1_R1
        })
    }

    /// A function that calls saves the link register, and a compiler can
    /// read it before it makes the frame: clang writes `mflr r0` first.
    ///
    /// 64-bit code saves registers below the stack pointer before it moves
    /// it, as `std r30, -16(r1)`, and an ELFv2 function makes its TOC
    /// before all of it.
    fn preamble_before_prologue(&self, earlier: &[Insn]) -> usize {
        /// The most instructions of a 64-bit function before its frame.
        const MOST_BEFORE: usize = 24;
        let reads_link = |insn: &Insn| {
            read(insn).is_some_and(|(inst, operands)| {
                inst.opcode() == Opcode::MFSPR
                    && matches!(operands.as_slice(), [_, Operand::SPR(spr)] if spr.num() == SPR_LR)
            })
        };
        if self.mode() == Mode::Bits32 {
            return usize::from(earlier.last().is_some_and(reads_link));
        }
        let saves = |insn: &Insn| {
            lifted(insn).is_some_and(|lifted| {
                lifted.op == hereticus_il::Op::Store
                    && lifted.operands.iter().any(|operand| {
                        matches!(
                            operand,
                            hereticus_il::Operand::Memory {
                                base: Some(hereticus_il::Reg::Stack),
                                ..
                            }
                        )
                    })
            })
        };
        let before = earlier
            .iter()
            .rev()
            .take(MOST_BEFORE)
            .take_while(|insn| reads_link(insn) || saves(insn))
            .count();
        let entry = earlier.len() - before;
        match entry.checked_sub(2).map(|at| &earlier[at..entry]) {
            Some(pair) if is_global_entry(pair) => before + 2,
            _ => before,
        }
    }

    /// The global entry of an ELFv2 function, which makes the TOC from the
    /// address of the function: only a call runs it.
    fn is_function_entry(&self, body: &[Insn]) -> bool {
        self.mode() == Mode::Bits64 && is_global_entry(body)
    }

    /// A word of primary opcode 0 is no instruction a function runs. Such a
    /// word after a return is the distance clang keeps before a PIC
    /// function: a positive distance below 64 MiB has its top 6 bits clear.
    fn may_open_function(&self, word: &[u8]) -> bool {
        word_at(*self, word).is_some_and(|word| word >> 26 != 0)
    }

    /// GNU `as` aligns code with `nop`, and with `ori r2, r2, 0` in a
    /// 64-bit loop. GNU `ld` pads with zero words, which are no
    /// instruction, and LLD 64-bit code with `trap`. In 32-bit code `trap`
    /// is work: a deleted destructor is one `trap`.
    fn is_padding(&self, insn: &Insn) -> bool {
        matches!(
            (self.mode(), word_of(insn)),
            (_, Some(NOP | GROUP_NOP | 0)) | (Mode::Bits64, Some(TRAP))
        )
    }

    /// A zero word is no instruction, so it traps where it runs, as the
    /// `trap` that LLD fills 64-bit code with does.
    fn is_trap_fill(&self, insn: &Insn) -> bool {
        matches!((self.mode(), word_of(insn)), (_, Some(0)) | (Mode::Bits64, Some(TRAP)))
    }

    /// Only whole words at the end are removed: `nop`, `ori r2, r2, 0`, the
    /// `trap` that LLD fills 64-bit code with,
    /// and in 32-bit code the words of primary opcode 0, which no function
    /// runs. Those are zero fill, and the distance clang keeps before the
    /// next function, where nothing says where this one ends. GCC puts a
    /// traceback table of such words after each 64-bit function, and its
    /// symbol counts it, so there they stay.
    fn trim_padding<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        let pads = |word: u32| match self.mode() {
            Mode::Bits32 => matches!(word, NOP | GROUP_NOP) || word >> 26 == 0,
            Mode::Bits64 => matches!(word, NOP | GROUP_NOP | TRAP),
        };
        let mut end = bytes.len() - bytes.len() % INSN_WIDTH;
        while end >= INSN_WIDTH && word_at(*self, &bytes[end - INSN_WIDTH..]).is_some_and(pads) {
            end -= INSN_WIDTH;
        }
        &bytes[..end]
    }

    /// Clang keeps the distance to the global offset table in a word just
    /// before a 32-bit PIC function: see the module. 64-bit code keeps its
    /// data in the TOC.
    fn data_among_code(&self) -> super::DataAmongCode {
        match self.mode() {
            Mode::Bits32 => super::DataAmongCode::LiteralPools,
            Mode::Bits64 => super::DataAmongCode::Never,
        }
    }

    /// The words that PIC code loads from the program counter, where they
    /// lie among the code: the word before a function that clang reads.
    fn literal_pool_words(&self, insns: &[Insn]) -> Vec<u64> {
        let (Some(first), Some(last)) = (insns.first(), insns.last()) else {
            return Vec::new();
        };
        let span = first.address.saturating_sub(2 * INSN_WIDTH as u64)
            ..last.address + last.bytes_len as u64;
        let mut tracker = Tracker::of(*self);
        let mut words = Vec::new();
        for (index, insn) in insns.iter().enumerate() {
            let step = tracker.step(index, insn, None);
            if let Some(Access { address, origin: Origin::Counter, kind: AccessKind::Load, .. }) =
                step.access
                && span.contains(&address)
            {
                words.push(address);
            }
        }
        words.sort_unstable();
        words.dedup();
        words
    }

    /// A `switch` compiles to a load from a table and `bctr`. GCC holds the
    /// distance from the table to each case, and adds the table to it:
    ///
    /// ```text
    /// lis   r9, table@ha
    /// slwi  r3, r3, 2
    /// addi  r9, r9, table@l
    /// lwzx  r3, r9, r3
    /// add   r3, r3, r9
    /// mtctr r3
    /// bctr
    /// ```
    ///
    /// A table of addresses leaves out the `add`. A `cmplwi` of the case
    /// number before it bounds the table.
    fn jump_tables(&self, memory: &Memory<'_>, code: Range<u64>, insns: &[Insn]) -> Vec<JumpTable> {
        let shapes: Vec<TableShape> =
            (0..insns.len()).filter_map(|index| table_shape(insns, index)).collect();
        if shapes.is_empty() {
            return Vec::new();
        }
        let mut bases = vec![None; shapes.len()];
        let mut tracker = Tracker::of(*self);
        let mut next = 0;
        for (index, insn) in insns.iter().enumerate() {
            while let Some(shape) = shapes.get(next).filter(|shape| shape.load <= index) {
                if shape.load == index {
                    bases[next] = tracker.whole(shape.base);
                }
                next += 1;
            }
            if next == shapes.len() {
                break;
            }
            tracker.step(index, insn, Some(memory));
        }
        shapes
            .iter()
            .zip(bases)
            .filter_map(|(shape, base)| read_table(*self, memory, &code, insns, shape, base?))
            .collect()
    }

    /// The stub GNU `ld` writes for a call from code that is not PIC, which
    /// jumps through a slot whose address it forms whole:
    ///
    /// ```text
    /// lis   r11, slot@ha
    /// lwz   r11, slot@l(r11)
    /// mtctr r11
    /// bctr
    /// ```
    fn stub_slot(&self, code: &[u8], address: u64) -> Option<u64> {
        let length = code.len().min(4 * INSN_WIDTH) / INSN_WIDTH * INSN_WIDTH;
        if length < 4 * INSN_WIDTH {
            return None;
        }
        let (insns, _) = super::decode_all(self, &code[..length], address);
        let [high, load, move_count, jump] = insns.as_slice() else { return None };
        if jump.kind != (InsnKind::Jump { target: None }) || !moves_to_count(move_count) {
            return None;
        }
        let mut tracker = Tracker::of(*self);
        tracker.step(0, high, None);
        let access = tracker.step(1, load, None).access?;
        (access.kind == AccessKind::Load && access.origin == Origin::Constant)
            .then_some(access.address)
    }

    /// LLD and GNU `ld` write a call stub for each library a PowerPC object
    /// calls, among the code.
    fn stub_place(&self) -> super::StubPlace {
        super::StubPlace::AmongCode
    }

    /// Each call stub in `code`, by its shape: the load of the slot, then
    /// `mtctr r11` and `bctr`. See [`PowerPc::stub_slot`] and
    /// [`stub_through_table`].
    fn plt_entries(&self, code: &[u8], base: u64) -> Vec<Range<u64>> {
        /// `bctr`, which ends a stub, or a `b` after `bcctr` on a condition,
        /// which ends an ELFv1 stub of GNU `ld`.
        const BCTR: u32 = 0x4e80_0420;
        let ends = |at: usize, words: &[u32]| {
            words[at] == BCTR
                || (words[at] >> 26 == 18
                    && at > 0
                    && words[at - 1] & 0xfc00_ffff == 0x4c00_0420
                    && words[at - 1] != BCTR)
        };
        /// The most words of a stub before its `bctr`.
        const MOST_BEFORE: usize = 7;
        /// The most words of padding after a stub.
        const MOST_PADDING: usize = 8;
        let words: Vec<u32> =
            code.as_chunks::<INSN_WIDTH>().0.iter().map(|word| self.word(*word)).collect();
        let mut stubs: Vec<Range<u64>> = Vec::new();
        for jump in (0..words.len()).filter(|&at| ends(at, &words)) {
            let end = (jump + 1) * INSN_WIDTH;
            // The earliest start whose stub ends at this `bctr` and holds
            // no other jump.
            let start = (2..=MOST_BEFORE).rev().find_map(|back| {
                let start = jump.checked_sub(back)?;
                let at = start * INSN_WIDTH;
                let address = base + at as u64;
                let (insns, _) = super::decode_all(self, &code[at..end], address);
                let jumps =
                    insns.iter().filter(|insn| matches!(insn.kind, InsnKind::Jump { .. })).count();
                let is_stub = stub_through_table(&insns).is_some()
                    || (back == 3 && self.stub_slot(&code[at..end], address).is_some());
                (jumps == 1 && is_stub).then_some(start)
            });
            if let Some(start) = start {
                let start = base + (start * INSN_WIDTH) as u64;
                // GNU `ld` pads each stub to 16 bytes with a `nop` in 32-bit
                // code, and to 32 bytes with zero words in 64-bit code.
                let pad = words[jump + 1..]
                    .iter()
                    .take(MOST_PADDING)
                    .take_while(|word| matches!(**word, NOP | GROUP_NOP | 0))
                    .count()
                    * INSN_WIDTH;
                if stubs.last().is_none_or(|last| last.end <= start) {
                    stubs.push(start..base + (end + pad) as u64);
                }
            }
        }
        stubs
    }

    /// The call stub LLD writes for PIC code, which reaches its slot from
    /// the table that `r30` of the caller holds: see [`stub_through_table`].
    fn stub_table_offset(&self, code: &[u8]) -> Option<u64> {
        /// The most words of a stub, as an ELFv1 stub of 64-bit code takes.
        const MOST_WORDS: usize = 8;
        let length = code.len().min(MOST_WORDS * INSN_WIDTH) / INSN_WIDTH * INSN_WIDTH;
        let (insns, _) = super::decode_all(self, &code[..length], 0);
        stub_through_table(&insns).map(|(offset, _)| offset)
    }

    /// The addresses a function forms whole, from two halves or from the
    /// program counter.
    fn data_addresses(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        memory: &Memory<'_>,
    ) -> Vec<u64> {
        let tracked = track(*self, body, space, Some(memory));
        let mut addresses: Vec<u64> = tracked
            .joins
            .iter()
            .flatten()
            .copied()
            .filter(|&address| space.contains_formed(address))
            .collect();
        addresses.dedup();
        addresses
    }
}

/// The distance from the table register of the slot the call stub that
/// `insns` opens with jumps through, and which of its instructions hold a
/// part of that distance. The table register is `r30` in 32-bit code and
/// the TOC, `r2`, in 64-bit code:
///
/// ```text
/// addis r11, r30, hi       lwz   r11, lo(r30)      std   r2, 24(r1)
/// lwz   r11, lo(r11)       mtctr r11               addis r12, r2, hi
/// mtctr r11                bctr                    ld    r12, lo(r12)
/// bctr                                             mtctr r12
///                                                  bctr
/// ```
///
/// A 64-bit stub saves the TOC of its caller first, and an ELFv1 stub
/// loads the TOC and the environment of its callee after `mtctr`. The stub
/// runs with the table register of its caller, which the stub alone does
/// not show.
pub fn stub_through_table(insns: &[Insn]) -> Option<(u64, Range<usize>)> {
    /// The most instructions between `mtctr` and `bctr`.
    const MOST_AFTER_MOVE: usize = 3;
    let arch = reader(insns.first()?)?;
    let base = table_register(arch.mode());
    let operands_of = |insn: &Insn| read(insn).map(|(inst, operands)| (inst.opcode(), operands));
    let load_from = |insn: &Insn, from: u8| {
        let (opcode, operands) = operands_of(insn)?;
        let loads = match arch.mode() {
            Mode::Bits32 => opcode == Opcode::LWZ,
            Mode::Bits64 => opcode == Opcode::LD,
        };
        match operands.as_slice() {
            [Operand::Register(dest), Operand::MemoryDisp { base, disp }]
                if loads && base.num() == from =>
            {
                Some((dest.num(), i64::from(*disp)))
            }
            _ => None,
        }
    };
    let saves_toc = arch.mode() == Mode::Bits64
        && operands_of(insns.first()?).is_some_and(|(opcode, operands)| {
            opcode == Opcode::STD
                && matches!(
                    operands.as_slice(),
                    [Operand::Register(saved), Operand::MemoryDisp { base, .. }]
                        if saved.num() == TOC && base.num() == STACK
                )
        });
    let first = usize::from(saves_toc);
    let high = match operands_of(insns.get(first)?)? {
        (Opcode::ADDIS, operands) => match operands.as_slice() {
            [Operand::Register(dest), Operand::RegisterOrZero(from), Operand::ImmExts16(high)]
                if from.num() == base =>
            {
                Some((dest.num(), i64::from(*high) << 16))
            }
            _ => None,
        },
        _ => None,
    };
    let (parts, offset, loaded) = match high {
        Some((dest, high)) => {
            let (loaded, low) = load_from(insns.get(first + 1)?, dest)?;
            (first..first + 2, high + low, loaded)
        }
        None => {
            let (loaded, low) = load_from(insns.get(first)?, base)?;
            (first..first + 1, low, loaded)
        }
    };
    let move_count = insns.get(parts.end)?;
    let moved = read(move_count).is_some_and(|(_, operands)| {
        moves_to_count(move_count) && operands.get(1).and_then(general) == Some(loaded)
    });
    // GNU `ld` checks the TOC of an ELFv1 callee and jumps on to the lazy
    // resolver where it is 0: `bnectr`, then `b`.
    let jumps = insns
        .iter()
        .skip(parts.end + 1)
        .take(MOST_AFTER_MOVE + 2)
        .take_while(|insn| {
            matches!(
                insn.kind,
                InsnKind::Normal | InsnKind::Branch { target: None } | InsnKind::Jump { .. }
            )
        })
        .any(|insn| matches!(insn.kind, InsnKind::Jump { .. }));
    (moved && jumps).then_some((in_mode(arch.mode(), offset as u64), parts))
}

/// Whether `body` opens with the global entry of an ELFv2 function:
///
/// ```text
/// addis r2, r12, hi
/// addi  r2, r2, lo
/// ```
pub fn is_global_entry(body: &[Insn]) -> bool {
    let [high, low, ..] = body else { return false };
    let shape = |insn: &Insn, opcode: Opcode, source: u8| {
        read(insn).is_some_and(|(inst, operands)| {
            inst.opcode() == opcode
                && matches!(
                    operands.as_slice(),
                    [Operand::Register(dest), Operand::RegisterOrZero(from), _]
                        if dest.num() == TOC && from.num() == source
                )
        })
    };
    shape(high, Opcode::ADDIS, ENTRY) && shape(low, Opcode::ADDI, TOC)
}

/// The TOC that 64-bit code in `code`, loaded at `base`, reaches its data
/// through, as the first ELFv2 global entry in it makes it: see
/// [`is_global_entry`]. A module has one TOC, unless it is too large for
/// one, which no library of the tests is.
pub fn toc_from_global_entry(arch: PowerPc, code: &[u8], base: u64) -> Option<u64> {
    let words: Vec<u32> =
        code.as_chunks::<INSN_WIDTH>().0.iter().map(|word| arch.word(*word)).collect();
    words.windows(2).enumerate().find_map(|(at, pair)| {
        // `addis r2, r12, hi`, then `addi r2, r2, lo`.
        let [high, low] = *pair else { return None };
        (high >> 16 == 0x3c4c && low >> 16 == 0x3842).then(|| {
            let address = base + (at * INSN_WIDTH) as u64;
            let high = i64::from(high as u16 as i16) << 16;
            let low = i64::from(low as u16 as i16);
            address.wrapping_add_signed(high + low)
        })
    })
}

/// Whether `insn` is `mtctr`, which a jump through the count register
/// needs first.
fn moves_to_count(insn: &Insn) -> bool {
    read(insn).is_some_and(|(inst, operands)| {
        inst.opcode() == Opcode::MTSPR
            && matches!(operands.first(), Some(Operand::SPR(spr)) if spr.num() == SPR_CTR)
    })
}

/// What a word of a jump table holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Entries {
    /// The address of each case.
    Addresses,
    /// The distance from the table to each case.
    FromTable,
}

/// The parts of a jump through a table, as [`table_shape`] reads them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TableShape {
    /// The index of the `bctr`.
    jump: usize,
    /// The index of the load from the table.
    load: usize,
    /// The general register that holds the table at the load.
    base: u8,
    /// What the table holds.
    entries: Entries,
}

/// The general register `operand` names, by number.
fn general(operand: &Operand) -> Option<u8> {
    match operand {
        Operand::Register(reg) => Some(reg.num()),
        Operand::RegisterOrZero(reg) if reg.num() != 0 => Some(reg.num()),
        _ => None,
    }
}

/// The last instruction before `insns[before]` that writes general register
/// `register`, with its index, within [`TABLE_LOOK_BACK`] instructions.
fn last_write(insns: &[Insn], before: usize, register: u8) -> Option<(usize, Instruction)> {
    let written = if register == STACK {
        hereticus_il::Reg::Stack
    } else {
        hereticus_il::Reg::General(register)
    };
    let from = before.saturating_sub(TABLE_LOOK_BACK);
    (from..before).rev().find_map(|at| {
        let insn = &insns[at];
        let writes = lifted(insn).is_some_and(|lifted| lifted.writes.contains(written));
        writes.then(|| instruction(insn).map(|inst| (at, inst))).flatten()
    })
}

/// The table load of `lwzx rD, rA, rB` or `lwz rD, 0(rA)`, as the register
/// that holds the table: `rA` of the indexed form, where `rB` is the case.
fn table_load(inst: &Instruction) -> Option<u8> {
    match (inst.opcode(), hardware_operands(inst).as_slice()) {
        (Opcode::LWZX, [_, Operand::MemoryIndexed { base, .. }]) if base.num() != 0 => {
            Some(base.num())
        }
        _ => None,
    }
}

/// Read the parts of a jump through a table at `insns[index]`, where it is
/// one.
fn table_shape(insns: &[Insn], index: usize) -> Option<TableShape> {
    let jump = &insns[index];
    if jump.kind != (InsnKind::Jump { target: None }) || decoded(jump)?.opcode != Opcode::BCCTR {
        return None;
    }
    let from = index.saturating_sub(TABLE_LOOK_BACK);
    let move_at = (from..index).rev().find(|&at| moves_to_count(&insns[at]))?;
    let (_, moved) = read(&insns[move_at])?;
    let target = general(moved.get(1)?)?;
    let (at, def) = last_write(insns, move_at, target)?;
    if let Some(base) = table_load(&def) {
        return Some(TableShape { jump: index, load: at, base, entries: Entries::Addresses });
    }
    if def.opcode() != Opcode::ADD {
        return None;
    }
    let operands = hardware_operands(&def);
    let [_, left, right] = operands.as_slice() else { return None };
    let (left, right) = (general(left)?, general(right)?);
    [(left, right), (right, left)].into_iter().find_map(|(loaded, table)| {
        let (load, inst) = last_write(insns, at, loaded)?;
        (table_load(&inst)? == table).then_some(TableShape {
            jump: index,
            load,
            base: table,
            entries: Entries::FromTable,
        })
    })
}

/// The number of cases, from the `cmplwi rN, n` and the branch past the
/// table that guard it, as `n + 1`.
fn case_count(insns: &[Insn], index: usize) -> Option<usize> {
    let from = index.saturating_sub(TABLE_LOOK_BACK);
    insns[from..index].iter().rev().find_map(|insn| {
        let (inst, operands) = read(insn)?;
        if inst.opcode() != Opcode::CMPLI {
            return None;
        }
        match operands.as_slice() {
            [.., Operand::ImmU16(bound)] => {
                usize::from(*bound).checked_add(1).filter(|&count| count <= MOST_CASES)
            }
            _ => None,
        }
    })
}

/// Read the cases of the table `shape` names, which lies at `table`.
fn read_table(
    arch: PowerPc,
    memory: &Memory<'_>,
    code: &Range<u64>,
    insns: &[Insn],
    shape: &TableShape,
    table: u64,
) -> Option<JumpTable> {
    let jump = &insns[shape.jump];
    let bound = case_count(insns, shape.jump);
    let mut targets = Vec::new();
    let mut word = table;
    for _ in 0..bound.unwrap_or(MOST_CASES) {
        let Some(value) = memory.bytes(word, INSN_WIDTH).and_then(|bytes| word_at(arch, bytes))
        else {
            break;
        };
        let target = match shape.entries {
            Entries::Addresses => u64::from(value),
            Entries::FromTable => {
                in_mode(arch.mode(), table.wrapping_add_signed(i64::from(value as i32)))
            }
        };
        let holds_code = target.is_multiple_of(INSN_WIDTH as u64) && code.contains(&target);
        let near = target.abs_diff(jump.address) < MOST_CASE_DISTANCE;
        if !holds_code || (bound.is_none() && !near) {
            break;
        }
        targets.push(target);
        word += INSN_WIDTH as u64;
    }
    (!targets.is_empty()).then_some(JumpTable { jump: jump.address, words: table..word, targets })
}

/// Where an address the code holds comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// From constants in the code, as `lis` and `addi` give it. It is an
    /// address only where it lies inside the image.
    Constant,
    /// From the program counter, as PIC code reads it. It is an address
    /// wherever it lies.
    Counter,
}

/// What a general register holds, as far as the code before shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Held {
    /// The upper half of a value, from the `lis` or `addis` at `from`.
    Upper { value: u64, from: usize, origin: Origin },
    /// A value whole.
    Whole { value: u64, origin: Origin },
    /// A word loaded from memory, which PIC code adds to the program
    /// counter.
    Loaded(u64),
    /// An address formed from the program counter, whose value the code
    /// alone does not show.
    FromCounter,
}

/// How an instruction touches memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccessKind {
    Load,
    Store,
}

/// An access at an address the code formed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Access {
    address: u64,
    origin: Origin,
    kind: AccessKind,
    width: Option<hereticus_il::Width>,
}

/// What one instruction formed, as [`Tracker::step`] tells.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Step {
    /// The address it joined from an upper half, and the index of the
    /// instruction that made that half.
    join: Option<(u64, Origin, Option<usize>)>,
    /// Whether a constant of it is a distance from the program counter.
    from_counter: bool,
    /// The upper half it made, as `lis` and `addis` do.
    upper: Option<u64>,
    /// The access it made at a known address.
    access: Option<Access>,
}

/// What each general register holds.
type Registers = [Option<Held>; 32];

/// What the registers hold where two paths meet: what both paths agree
/// on, and an address from the program counter where both hold one,
/// though not the same.
fn merged(left: &Registers, right: &Registers) -> Registers {
    let from_counter = |held: &Option<Held>| {
        matches!(
            held,
            Some(
                Held::FromCounter
                    | Held::Whole { origin: Origin::Counter, .. }
                    | Held::Upper { origin: Origin::Counter, .. }
            )
        )
    };
    core::array::from_fn(|register| match (&left[register], &right[register]) {
        (left, right) if left == right => *left,
        (left, right) if from_counter(left) && from_counter(right) => Some(Held::FromCounter),
        _ => None,
    })
}

/// What the general registers hold, one instruction after the next.
///
/// Branches are stepped over, as if the code ran straight down: a compiler
/// forms an address next to where it uses it.
#[derive(Clone, Debug)]
struct Tracker {
    arch: PowerPc,
    held: Registers,
    /// The address that `bcl 20, 31` to the next word put in the link
    /// register, where nothing wrote it since.
    link: Option<u64>,
}

impl Tracker {
    /// A tracker of `arch` code that knows nothing yet, but that 64-bit
    /// code holds the TOC in `r2` throughout.
    fn of(arch: PowerPc) -> Self {
        let mut held = [None; 32];
        if arch.mode() == Mode::Bits64 {
            held[usize::from(TOC)] = Some(Held::FromCounter);
        }
        Self { arch, held, link: None }
    }

    /// `value`, in the width of an address.
    fn word(&self, value: u64) -> u64 {
        in_mode(self.arch.mode(), value)
    }

    /// The value general register `register` holds whole, where known.
    fn whole(&self, register: u8) -> Option<u64> {
        match self.held.get(usize::from(register))? {
            Some(Held::Whole { value, .. }) => Some(*value),
            _ => None,
        }
    }

    fn get(&self, register: u8) -> Option<Held> {
        *self.held.get(usize::from(register))?
    }

    /// Say what general register `register` holds. In 64-bit code `r2`
    /// holds the TOC by the ABI, whatever writes it, as `ld r2, 24(r1)`
    /// after a call and the `ori r2, r2, 0` that GCC puts in to end a
    /// dispatch group.
    fn set(&mut self, register: u8, held: Option<Held>) {
        let held = match (self.arch.mode(), register, held) {
            (Mode::Bits64, TOC, None) => Some(Held::FromCounter),
            (_, _, held) => held,
        };
        if let Some(slot) = self.held.get_mut(usize::from(register)) {
            *slot = held;
        }
    }

    /// The address an offset from what `base` holds forms, and from where.
    fn offset_from(&self, base: u8, offset: i64) -> Option<(u64, Origin, Option<usize>)> {
        match self.get(base)? {
            Held::Upper { value, from, origin } => {
                Some((self.word(value.wrapping_add_signed(offset)), origin, Some(from)))
            }
            Held::Whole { value, origin: Origin::Counter } => {
                Some((self.word(value.wrapping_add_signed(offset)), Origin::Counter, None))
            }
            _ => None,
        }
    }

    /// Step over `insn`, the instruction at `index`, and say what it
    /// formed. `memory`, where given, gives the words PIC code loads.
    fn step(&mut self, index: usize, insn: &Insn, memory: Option<&Memory<'_>>) -> Step {
        let mut step = Step::default();
        if let InsnKind::Call { .. } = insn.kind {
            VOLATILE.iter().for_each(|&register| self.set(register, None));
            self.link = None;
            return step;
        }
        if insn.kind == InsnKind::Normal
            && decoded(insn).is_some_and(|decoded| decoded.opcode == Opcode::BCL)
        {
            self.link = insn.address.checked_add(INSN_WIDTH as u64);
            return step;
        }
        let Some((inst, operands)) = read(insn) else { return step };
        let held = match (inst.opcode(), operands.as_slice()) {
            (
                Opcode::ADDIS,
                [Operand::Register(dest), Operand::RegisterOrZero(source), Operand::ImmExts16(imm)],
            ) => {
                // ELFv2 makes the TOC from `r12`, which holds the address of
                // this instruction on entry.
                if dest.num() == TOC && source.num() == ENTRY {
                    let entry = Held::Whole { value: insn.address, origin: Origin::Counter };
                    self.set(ENTRY, Some(entry));
                }
                let high = self.word((i64::from(*imm) << 16) as u64);
                match (source.num(), self.get(source.num())) {
                    (0, _) => {
                        Some(Held::Upper { value: high, from: index, origin: Origin::Constant })
                    }
                    (
                        _,
                        Some(Held::Whole { value, origin } | Held::Upper { value, origin, .. }),
                    ) => {
                        step.from_counter = origin == Origin::Counter;
                        Some(Held::Upper {
                            value: self.word(value.wrapping_add(high)),
                            from: index,
                            origin,
                        })
                    }
                    (_, Some(Held::FromCounter)) => {
                        step.from_counter = true;
                        Some(Held::FromCounter)
                    }
                    _ => None,
                }
                .inspect(|held| {
                    if let Held::Upper { value, .. } = held {
                        step.upper = Some(*value);
                    }
                })
                .map(|held| (dest.num(), Some(held)))
            }
            (
                Opcode::ADDI | Opcode::ADDIC,
                [Operand::Register(dest), Operand::RegisterOrZero(source), Operand::ImmExts16(imm)],
            ) => {
                let joined = self.offset_from(source.num(), (*imm).into());
                step.join = joined;
                step.from_counter = matches!(self.get(source.num()), Some(Held::FromCounter))
                    || joined.is_some_and(|(_, origin, _)| origin == Origin::Counter);
                let held = match joined {
                    Some((value, origin, _)) => Some(Held::Whole { value, origin }),
                    None if step.from_counter => Some(Held::FromCounter),
                    None => None,
                };
                Some((dest.num(), held))
            }
            (
                Opcode::ORI,
                [Operand::Register(dest), Operand::Register(source), Operand::ImmU16(imm)],
            ) => {
                let held = match self.get(source.num()) {
                    Some(Held::Upper { value, from, origin }) => {
                        let value = value | u64::from(*imm);
                        step.join = Some((value, origin, Some(from)));
                        Some(Held::Whole { value, origin })
                    }
                    _ => None,
                };
                Some((dest.num(), held))
            }
            // `mr`, which is `or rD, rS, rS`.
            (
                Opcode::OR,
                [Operand::Register(dest), Operand::Register(left), Operand::Register(right)],
            ) if left == right => Some((dest.num(), self.get(left.num()))),
            (
                Opcode::ADD,
                [Operand::Register(dest), Operand::Register(left), Operand::Register(right)],
            ) => {
                let held = match (self.get(left.num()), self.get(right.num())) {
                    (
                        Some(Held::Whole { value, origin: Origin::Counter }),
                        Some(Held::Loaded(distance)),
                    )
                    | (
                        Some(Held::Loaded(distance)),
                        Some(Held::Whole { value, origin: Origin::Counter }),
                    ) => Some(Held::Whole {
                        value: self.word(value.wrapping_add(distance)),
                        origin: Origin::Counter,
                    }),
                    (Some(Held::Whole { origin: Origin::Counter, .. } | Held::FromCounter), _)
                    | (_, Some(Held::Whole { origin: Origin::Counter, .. } | Held::FromCounter)) => {
                        Some(Held::FromCounter)
                    }
                    _ => None,
                };
                Some((dest.num(), held))
            }
            (Opcode::MFSPR, [Operand::Register(dest), Operand::SPR(spr)])
                if spr.num() == SPR_LR =>
            {
                let held = self.link.map(|value| Held::Whole { value, origin: Origin::Counter });
                Some((dest.num(), held))
            }
            _ => None,
        };
        if let Some((dest, held)) = held {
            self.set(dest, held);
            return step;
        }

        // A load or a store through a base whose value is known.
        let access = operands.iter().find_map(|operand| match *operand {
            Operand::MemoryDisp { base, disp } if base.num() != 0 => Some((base.num(), disp)),
            _ => None,
        });
        if let Some((base, disp)) = access
            && let Some((kind, width)) = access_kind(insn)
        {
            step.from_counter = matches!(self.get(base), Some(Held::FromCounter));
            if let Some((address, origin, from)) = self.offset_from(base, disp.into()) {
                step.join = Some((address, origin, from));
                step.from_counter |= origin == Origin::Counter;
                step.access = Some(Access { address, origin, kind, width });
            }
        }
        let lifted = lifted(insn);
        let loaded = step
            .access
            .filter(|access| access.kind == AccessKind::Load && access.origin == Origin::Counter);
        for reg in lifted.iter().flat_map(|lifted| lifted.writes.iter()) {
            let register = match reg {
                hereticus_il::Reg::General(number) if number < 32 => number,
                hereticus_il::Reg::Stack => STACK,
                LINK => {
                    self.link = None;
                    continue;
                }
                _ => continue,
            };
            let value = loaded
                .and_then(|access| {
                    let width = match access.width {
                        Some(hereticus_il::Width::Bits64) => 8,
                        _ => INSN_WIDTH,
                    };
                    let bytes = memory?.bytes(access.address, width)?;
                    Some(match width {
                        INSN_WIDTH => u64::from(word_at(self.arch, bytes)?),
                        _ => self.arch.read_pointer(bytes),
                    })
                })
                .map(Held::Loaded);
            self.set(register, value);
        }
        step
    }
}

/// Whether `insn` loads or stores, and how wide a value it moves, where
/// it touches memory.
fn access_kind(insn: &Insn) -> Option<(AccessKind, Option<hereticus_il::Width>)> {
    let memory = lifted(insn)?.memory?;
    let kind = match memory.kind {
        hereticus_il::AccessKind::Load => AccessKind::Load,
        hereticus_il::AccessKind::Store => AccessKind::Store,
        hereticus_il::AccessKind::LoadStore => return None,
    };
    Some((kind, memory.width))
}

/// What [`track`] found in a body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tracked {
    /// For each instruction, whether its constant is an address.
    pub kinds: Vec<ConstantKind>,
    /// For each instruction, the address it forms whole, where it forms
    /// one: the join of two halves, or an offset from the program counter.
    pub joins: Vec<Option<u64>>,
    /// [`Tracked::joins`], and the upper half of each join at the `lis` or
    /// `addis` that made it, as the page of an `adrp` is.
    pub formed: Vec<Option<u64>>,
}

/// The constants of `body` that are parts of an address inside `space`,
/// and the addresses they form.
///
/// An upper half from `lis` is an address only where the half joined to it
/// gives one: `lis` and `ori` also build a large constant, as the magic
/// number of a division is. Any offset from the program counter is an
/// address, as is the `addis` and `addi` that reach the global offset table
/// from it. `memory`, where given, gives the word clang loads to reach it.
pub fn track(
    arch: PowerPc,
    body: &[Insn],
    space: &AddressSpace,
    memory: Option<&Memory<'_>>,
) -> Tracked {
    let mut tracked = Tracked {
        kinds: vec![ConstantKind::Value; body.len()],
        joins: vec![None; body.len()],
        formed: vec![None; body.len()],
    };
    let mut uppers = vec![None; body.len()];
    if let Some((_, parts)) = stub_through_table(body) {
        tracked.kinds[parts].fill(ConstantKind::Address);
    }
    // What the registers hold where a forward branch lands, from each branch
    // that reaches there, merged.
    let index_of: std::collections::HashMap<u64, usize> =
        body.iter().enumerate().map(|(index, insn)| (insn.address, index)).collect();
    let mut landing: std::collections::HashMap<usize, Registers> = Default::default();
    let mut tracker = Tracker::of(arch);
    for (index, insn) in body.iter().enumerate() {
        if let Some(reached) = landing.remove(&index) {
            let falls_in = index.checked_sub(1).is_some_and(|before| {
                !matches!(body[before].kind, InsnKind::Jump { .. } | InsnKind::Return)
            });
            tracker.held = match falls_in {
                true => merged(&tracker.held, &reached),
                false => reached,
            };
        }
        let step = tracker.step(index, insn, memory);
        if let InsnKind::Branch { target: Some(target) } | InsnKind::Jump { target: Some(target) } =
            insn.kind
            && let Some(&at) = index_of.get(&target)
            && at > index
        {
            let held = tracker.held;
            landing
                .entry(at)
                .and_modify(|reached| *reached = merged(reached, &held))
                .or_insert(held);
        }
        uppers[index] = step.upper;
        if step.from_counter {
            tracked.kinds[index] = ConstantKind::Address;
        }
        let Some((address, origin, from)) = step.join else { continue };
        if origin == Origin::Counter || space.contains_formed(address) {
            tracked.kinds[index] = ConstantKind::Address;
            tracked.joins[index] = Some(address);
            tracked.formed[index] = Some(address);
            if let Some(from) = from {
                tracked.kinds[from] = ConstantKind::Address;
                tracked.formed[from] = uppers[from];
            }
        }
    }
    tracked
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn code(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_be_bytes()).collect()
    }

    fn decode_one(word: u32) -> Insn {
        PowerPc::BIG.decode(&word.to_be_bytes(), 0, 0x1000).expect("4 bytes always decode")
    }

    fn decode_at(words: &[u32], address: u64) -> Vec<Insn> {
        super::super::decode_all(&PowerPc::BIG, &code(words), address).0
    }

    #[rstest]
    #[case::stwu(0x9421_fff0, true)]
    #[case::stwu_up(0x9421_0010, false)]
    #[case::stwu_other_base(0x9423_fff0, false)]
    #[case::stwux(0x7c21_016e, true)]
    #[case::stwux_with_the_record_bit(0x7c21_016f, true)]
    #[case::stw(0x9001_0014, false)]
    #[case::mflr(0x7c08_02a6, false)]
    fn the_frame_allocation_opens_a_function(#[case] word: u32, #[case] opens: bool) {
        assert_eq!(PowerPc::BIG.is_prologue(&decode_one(word)), opens);
        if opens {
            assert!(PowerPc::BIG.may_be_prologue(&word.to_be_bytes()));
        }
    }

    /// The quick test of the bits never refuses a word the full test takes.
    #[test]
    fn the_bits_of_a_prologue_admit_every_prologue() {
        bolero::check!().with_type::<u32>().for_each(|&word| {
            if PowerPc::BIG.is_prologue(&decode_one(word)) {
                assert!(PowerPc::BIG.may_be_prologue(&word.to_be_bytes()), "{word:#010x}");
            }
        });
    }

    #[rstest]
    #[case::distance(0x0002_05f4, false)]
    #[case::zero(0, false)]
    #[case::mflr(0x7c08_02a6, true)]
    #[case::li(0x3860_0000, true)]
    fn a_word_of_opcode_0_opens_no_function(#[case] word: u32, #[case] opens: bool) {
        assert_eq!(PowerPc::BIG.may_open_function(&word.to_be_bytes()), opens);
        assert!(!PowerPc::BIG.may_open_function(&word.to_be_bytes()[..3]), "a partial word");
    }

    fn decode_64(words: &[u32]) -> Vec<Insn> {
        let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        super::super::decode_all(&PowerPc::LITTLE64, &bytes, 0x1000).0
    }

    #[rstest]
    #[case::stdu(0xf821_ffd1, true)]
    #[case::stdu_up(0xf821_0031, false)]
    #[case::std(0xf821_ffd0, false)]
    #[case::stdux(0x7c21_016a, true)]
    #[case::stwu(0x9421_fff0, true)]
    fn the_64_bit_frame_allocation_opens_a_function(#[case] word: u32, #[case] opens: bool) {
        let insns = decode_64(&[word]);
        assert_eq!(PowerPc::LITTLE64.is_prologue(&insns[0]), opens, "{word:#010x}");
        if opens {
            assert!(PowerPc::LITTLE64.may_be_prologue(&word.to_le_bytes()));
        }
        // 32-bit code has no `stdu`.
        if word >> 26 == 62 {
            assert!(!PowerPc::BIG.is_prologue(&decode_one(word)));
        }
    }

    #[test]
    fn the_global_entry_and_the_saves_open_a_64_bit_function() {
        let insns = decode_64(&[
            0x4e80_0020, // blr                 ; the function before
            0x3c4c_0002, // addis r2, r12, 2
            0x3842_8000, // addi r2, r2, -0x8000
            0x7c08_02a6, // mflr r0
            0xfbc1_fff0, // std r30, -16(r1)
            0xf821_ffd1, // stdu r1, -48(r1)
        ]);
        assert!(PowerPc::LITTLE64.is_function_entry(&insns[1..]));
        assert!(!PowerPc::LITTLE64.is_function_entry(&insns[2..]));
        assert!(!PowerPc::LITTLE.is_function_entry(&insns[1..]), "32-bit has no TOC");
        assert_eq!(PowerPc::LITTLE64.preamble_before_prologue(&insns[..5]), 4);
        assert_eq!(PowerPc::LITTLE64.preamble_before_prologue(&insns[3..5]), 2);
    }

    /// The TOC that the global entry makes from `r12` is known, and an
    /// offset from `r2` is an address however it was made.
    #[test]
    fn an_offset_from_the_toc_is_an_address() {
        let insns = decode_64(&[
            0x3c4c_0002, // addis r2, r12, 2
            0x3842_8000, // addi r2, r2, -0x8000
            0x3c82_0000, // addis r4, r2, 0
            0xe884_0010, // ld r4, 0x10(r4)
            0x4800_0011, // bl $+0x10
            0xe841_0018, // ld r2, 24(r1)
            0xe862_0020, // ld r3, 0x20(r2)
            0x6042_0000, // ori r2, r2, 0
            0xe862_0028, // ld r3, 0x28(r2)
        ]);
        let tracked = track(PowerPc::LITTLE64, &insns, &AddressSpace::none(), None);
        use ConstantKind::{Address, Value};
        assert_eq!(
            tracked.kinds,
            [Address, Address, Address, Address, Value, Value, Address, Value, Address]
        );
        assert_eq!(tracked.joins[1], Some(0x1_9000));
        assert_eq!(tracked.joins[3], Some(0x1_9010));
    }

    /// An upper half made before a branch reaches the code the branch
    /// lands on, where the straight code before it wrote the register.
    #[test]
    fn an_upper_half_reaches_where_a_branch_lands() {
        let insns = decode_64(&[
            0x3c62_fffa, // subis r3, r2, 6
            0x4182_000c, // beq $+0xc
            0x4800_0011, // bl $+0x10             ; r3 is its result
            0x4800_0008, // b $+8
            0x3863_4890, // addi r3, r3, 0x4890   ; reached by beq alone
        ]);
        let kinds = track(PowerPc::LITTLE64, &insns, &AddressSpace::none(), None).kinds;
        assert_eq!(kinds[4], ConstantKind::Address);
    }

    #[test]
    fn where_two_paths_disagree_nothing_is_known() {
        let insns = decode_64(&[
            0x3c62_fffa, // subis r3, r2, 6
            0x4182_0008, // beq $+8
            0x3860_0010, // li r3, 0x10
            0x3863_4890, // addi r3, r3, 0x4890   ; r3 is 0x10 or a half
        ]);
        let kinds = track(PowerPc::LITTLE64, &insns, &AddressSpace::none(), None).kinds;
        assert_eq!(kinds[3], ConstantKind::Value);
    }

    #[test]
    fn two_toc_offsets_merge_into_one_from_the_toc() {
        let insns = decode_64(&[
            0x3c62_fffa, // subis r3, r2, 6
            0x4182_0008, // beq $+8
            0x3c62_fff9, // subis r3, r2, 7
            0x3863_4890, // addi r3, r3, 0x4890
        ]);
        let kinds = track(PowerPc::LITTLE64, &insns, &AddressSpace::none(), None).kinds;
        assert_eq!(kinds[3], ConstantKind::Address);
    }

    #[test]
    fn the_first_global_entry_gives_the_toc() {
        let bytes: Vec<u8> = [0x4e80_0020_u32, 0x3c4c_0002, 0x3842_2d28, 0x7c08_02a6]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        assert_eq!(toc_from_global_entry(PowerPc::LITTLE64, &bytes, 0x2_1c9c), Some(0x4_49c8));
        assert_eq!(toc_from_global_entry(PowerPc::LITTLE64, &bytes[..8], 0x2_1c9c), None);
    }

    #[test]
    fn a_64_bit_stub_saves_the_toc_of_its_caller() {
        let insns = decode_64(&[
            0xf841_0018, // std r2, 24(r1)
            0x3d82_0001, // addis r12, r2, 1
            0xe98c_8018, // ld r12, -0x7fe8(r12)
            0x7d89_03a6, // mtctr r12
            0x4e80_0420, // bctr
        ]);
        assert_eq!(stub_through_table(&insns), Some((0x8018, 1..3)));
        let bytes: Vec<u8> =
            [0x4e80_0020u32, 0xf841_0018, 0x3d82_0001, 0xe98c_8018, 0x7d89_03a6, 0x4e80_0420]
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect();
        assert_eq!(PowerPc::LITTLE64.plt_entries(&bytes, 0x1000), vec![0x1004..0x1018]);
    }

    #[test]
    fn mflr_before_the_frame_belongs_to_the_function() {
        let earlier = decode_at(&[0x3860_0000, 0x7c08_02a6], 0x1000);
        assert_eq!(PowerPc::BIG.preamble_before_prologue(&earlier), 1);
        let earlier = decode_at(&[0x7c08_02a6, 0x3860_0000], 0x1000);
        assert_eq!(PowerPc::BIG.preamble_before_prologue(&earlier), 0);
    }

    #[rstest]
    #[case::nops(&[0x4e80_0020, NOP, NOP], 4)]
    #[case::zeros(&[0x4e80_0020, 0, 0], 4)]
    #[case::none(&[0x3860_0000, 0x4e80_0020], 8)]
    #[case::all(&[NOP, 0], 0)]
    #[case::distance_before_the_next(&[0x4e80_0020, 0x0002_05f4], 4)]
    fn padding_is_nops_zeros_and_words_of_opcode_0(#[case] words: &[u32], #[case] kept: usize) {
        assert_eq!(PowerPc::BIG.trim_padding(&code(words)).len(), kept);
    }

    #[test]
    fn a_partial_word_at_the_end_is_dropped() {
        assert_eq!(PowerPc::BIG.trim_padding(&[0x4e, 0x80, 0x00, 0x20, 0x60]).len(), 4);
    }

    /// GCC's table of distances from the table, guarded by `cmplwi`.
    #[test]
    fn reads_a_table_of_distances_from_the_table() {
        let words = [
            0x2803_0002, // cmplwi r3, 2
            0x4181_0024, // bgt $+0x24
            0x3d20_0000, // lis r9, 0
            0x5463_103a, // slwi r3, r3, 2
            0x3929_2000, // addi r9, r9, 0x2000
            0x7c69_182e, // lwzx r3, r9, r3
            0x7c63_4a14, // add r3, r3, r9
            0x7c69_03a6, // mtctr r3
            0x4e80_0420, // bctr
            0x3860_0001, // li r3, 1        ; 0x1024, a case
            0x4e80_0020, // blr
        ];
        let insns = decode_at(&words, 0x1000);
        let text = code(&words);
        let table = code(&[0xffff_f024, 0xffff_f028, 0xffff_f024, 0x1234_5678]);
        let regions = [(0x1000, text.as_slice()), (0x2000, table.as_slice())];
        let memory = Memory::new(&regions);
        let tables = PowerPc::BIG.jump_tables(&memory, 0x1000..0x102c, &insns);
        assert_eq!(
            tables,
            [JumpTable {
                jump: 0x1020,
                words: 0x2000..0x200c,
                targets: vec![0x1024, 0x1028, 0x1024]
            }]
        );
    }

    #[test]
    fn a_jump_through_a_pointer_is_no_table() {
        let words = [
            0x8129_0000, // lwz r9, 0(r9)
            0x7d29_03a6, // mtctr r9
            0x4e80_0420, // bctr
        ];
        let insns = decode_at(&words, 0x1000);
        let text = code(&words);
        let regions = [(0x1000, text.as_slice())];
        assert!(
            PowerPc::BIG.jump_tables(&Memory::new(&regions), 0x1000..0x100c, &insns).is_empty()
        );
    }

    #[test]
    fn reads_the_slot_a_plt_stub_jumps_through() {
        let stub = code(&[
            0x3d60_1002, // lis r11, 0x1002
            0x816b_8010, // lwz r11, -0x7ff0(r11)
            0x7d69_03a6, // mtctr r11
            0x4e80_0420, // bctr
        ]);
        assert_eq!(PowerPc::BIG.stub_slot(&stub, 0x1000), Some(0x1001_8010));
        assert_eq!(PowerPc::BIG.stub_slot(&stub[..12], 0x1000), None);
    }

    #[rstest]
    #[case::far(&[0x3d7e_0001, 0x816b_0078, 0x7d69_03a6, 0x4e80_0420], Some((0x1_0078, 0..2)))]
    #[case::near(&[0x817e_fff8, 0x7d69_03a6, 0x4e80_0420], Some((0xffff_fff8, 0..1)))]
    #[case::other_base(&[0x3d7f_0001, 0x816b_0078, 0x7d69_03a6, 0x4e80_0420], None)]
    #[case::other_register(&[0x817e_fff8, 0x7d89_03a6, 0x4e80_0420], None)]
    #[case::no_jump(&[0x817e_fff8, 0x7d69_03a6, 0x4e80_0020], None)]
    fn reads_the_distance_a_pic_stub_reaches_its_slot_from(
        #[case] words: &[u32],
        #[case] expected: Option<(u64, Range<usize>)>,
    ) {
        let insns = decode_at(words, 0x1000);
        assert_eq!(stub_through_table(&insns), expected);
        assert_eq!(
            PowerPc::BIG.stub_table_offset(&code(words)),
            expected.as_ref().map(|(offset, _)| *offset)
        );
        if let Some((_, parts)) = expected {
            let kinds = track(PowerPc::BIG, &insns, &AddressSpace::none(), None).kinds;
            assert!(kinds[parts].iter().all(|&kind| kind == ConstantKind::Address));
        }
    }

    #[test]
    fn finds_each_call_stub_among_the_code() {
        let words = [
            0x4e80_0020, // blr
            0x3d7e_0001, // addis r11, r30, 1
            0x816b_0078, // lwz r11, 0x78(r11)
            0x7d69_03a6, // mtctr r11
            0x4e80_0420, // bctr
            0x817e_fff8, // lwz r11, -8(r30)
            0x7d69_03a6, // mtctr r11
            0x4e80_0420, // bctr
            NOP,         // nop, which pads the stub of GNU `ld`
            0x3d60_1002, // lis r11, 0x1002
            0x816b_8010, // lwz r11, -0x7ff0(r11)
            0x7d69_03a6, // mtctr r11
            0x4e80_0420, // bctr
            0x8129_0000, // lwz r9, 0(r9)        ; a jump through a pointer
            0x7d69_03a6, // mtctr r11
            0x4e80_0420, // bctr
        ];
        assert_eq!(PowerPc::BIG.stub_place(), super::super::StubPlace::AmongCode);
        assert_eq!(
            PowerPc::BIG.plt_entries(&code(&words), 0x1000),
            [0x1004..0x1014, 0x1014..0x1024, 0x1024..0x1034]
        );
    }

    #[test]
    fn lis_and_addi_form_an_address_inside_the_image() {
        let body = decode_at(
            &[
                0x3c60_1000, // lis r3, 0x1000
                0x3863_0040, // addi r3, r3, 0x40
                0x3c80_2492, // lis r4, 0x2492
                0x6084_4925, // ori r4, r4, 0x4925   ; a divisor, no address
            ],
            0x1000,
        );
        let space = AddressSpace::from_ranges(core::iter::once(0x1000_0000..0x1001_0000));
        let tracked = track(PowerPc::BIG, &body, &space, None);
        use ConstantKind::{Address, Value};
        assert_eq!(tracked.kinds, [Address, Address, Value, Value]);
        assert_eq!(tracked.joins, [None, Some(0x1000_0040), None, None]);
        assert_eq!(tracked.formed, [Some(0x1000_0000), Some(0x1000_0040), None, None]);
    }

    #[test]
    fn a_load_through_an_upper_half_forms_its_address() {
        let body = decode_at(
            &[
                0x3d20_1001, // lis r9, 0x1001
                0x8069_fff0, // lwz r3, -0x10(r9)
            ],
            0x1000,
        );
        let space = AddressSpace::from_ranges(core::iter::once(0x1000_0000..0x1002_0000));
        assert_eq!(track(PowerPc::BIG, &body, &space, None).joins, [None, Some(0x1000_fff0)]);
    }

    /// GCC PIC: the program counter, then the distance to the table.
    #[test]
    fn an_offset_from_the_program_counter_is_an_address() {
        let body = decode_at(
            &[
                0x429f_0005, // bcl 20, 31, $+4
                0x7fc8_02a6, // mflr r30
                0x3fde_0001, // addis r30, r30, 1
                0x3bde_0010, // addi r30, r30, 0x10
                0x813e_fff8, // lwz r9, -8(r30)
                0x3860_0005, // li r3, 5
            ],
            0x1000,
        );
        let tracked = track(PowerPc::BIG, &body, &AddressSpace::none(), None);
        use ConstantKind::{Address, Value};
        assert_eq!(tracked.kinds, [Value, Value, Address, Address, Address, Value]);
        assert_eq!(tracked.joins[3], Some(0x1_1014));
        assert_eq!(tracked.joins[4], Some(0x1_100c));
    }

    /// Clang PIC: the distance to the table is a word before the function.
    #[test]
    fn the_word_clang_loads_before_a_function_is_data() {
        let words = [
            0x0001_0000, // .long table - .L0
            0x7c08_02a6, // mflr r0
            0x9421_fff0, // stwu r1, -0x10(r1)
            0x429f_0005, // bcl 20, 31, $+4
            0x7fc8_02a6, // mflr r30
            0x80be_fff0, // lwz r5, -0x10(r30)   ; the word at 0x1000
            0x7fc5_f214, // add r30, r5, r30
            0x807e_0008, // lwz r3, 8(r30)
        ];
        let insns = decode_at(&words, 0x1000);
        assert_eq!(PowerPc::BIG.literal_pool_words(&insns[1..]), [0x1000]);
        let text = code(&words);
        let regions = [(0x1000, text.as_slice())];
        let memory = Memory::new(&regions);
        let tracked = track(PowerPc::BIG, &insns, &AddressSpace::none(), Some(&memory));
        assert_eq!(tracked.kinds[7], ConstantKind::Address);
        assert_eq!(tracked.joins[7], Some(0x1_1018));
    }

    #[test]
    fn a_call_forgets_what_volatile_registers_held() {
        let body = decode_at(
            &[
                0x3c60_1000, // lis r3, 0x1000
                0x4800_0011, // bl $+0x10
                0x3863_0040, // addi r3, r3, 0x40
            ],
            0x1000,
        );
        let space = AddressSpace::from_ranges(core::iter::once(0x1000_0000..0x1001_0000));
        assert_eq!(track(PowerPc::BIG, &body, &space, None).joins, [None, None, None]);
    }

    #[test]
    fn padding_is_a_nop_or_a_zero_word() {
        assert!(PowerPc::BIG.is_padding(&decode_one(NOP)));
        assert!(PowerPc::BIG.is_padding(&decode_one(0)));
        assert!(PowerPc::BIG.is_padding(&decode_one(GROUP_NOP)));
        assert!(!PowerPc::BIG.is_padding(&decode_one(TRAP)), "32-bit work");
        let trap = PowerPc::BIG64.decode(&TRAP.to_be_bytes(), 0, 0x1000).expect("decodes");
        assert!(PowerPc::BIG64.is_padding(&trap));
        assert!(PowerPc::BIG64.is_trap_fill(&trap));
        assert!(PowerPc::BIG.is_trap_fill(&decode_one(0)));
        assert!(!PowerPc::BIG.is_trap_fill(&decode_one(NOP)));
        assert!(!PowerPc::BIG.is_padding(&decode_one(0x3860_0000)));
    }
}
