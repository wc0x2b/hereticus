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

use core::ops::Range;

use compact_str::CompactString;
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{InstDecoder, Instruction, Opcode, Operand};

use super::arm32::split_mnemonic;
use super::{Arch, DecodeError, Insn, InsnKind, JumpTable, Memory};
use crate::address::{AddressSpace, ConstantKind};

/// Every A64 instruction is 4 bytes wide.
const INSN_WIDTH: usize = 4;

/// A pointer is 8 bytes wide.
const POINTER_WIDTH: usize = 8;

/// A page, as `adrp` counts them.
const PAGE: u64 = 0x1000;

/// Mnemonic reported for bytes the decoder cannot read.
const UNKNOWN_MNEMONIC: &str = "(unknown)";

/// The A64 `nop` encoding, little endian.
const NOP_BYTES: [u8; 4] = [0x1f, 0x20, 0x03, 0xd5];

/// Zero words, which some linkers pad with instead.
const ZERO_BYTES: [u8; 4] = [0; 4];

/// How far back the parts of a table jump may lie.
const TABLE_LOOK_BACK: usize = 32;

/// More cases than any `switch` a compiler turns into one table.
const MOST_CASES: usize = 4096;

/// ARMv8-A in A64 (AArch64) mode.
#[derive(Clone, Copy, Debug, Default)]
pub struct Aarch64;

impl Arch for Aarch64 {
    fn decode(&self, code: &[u8], offset: usize, address: u64) -> Result<Insn, DecodeError> {
        let bytes = code.get(offset..offset + INSN_WIDTH).ok_or(DecodeError::Truncated)?;
        let insn_address = address + offset as u64;

        let mut reader = U8Reader::new(bytes);
        let mut inst = Instruction::default();
        if InstDecoder::default().decode_into(&mut inst, &mut reader).is_err() {
            // Every instruction is 4 bytes, so stepping over an unreadable
            // one keeps the rest aligned. Its word goes in the operands, so
            // that an edit to it still shows.
            let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            return Ok(Insn {
                address: insn_address,
                bytes_len: INSN_WIDTH,
                mnemonic: UNKNOWN_MNEMONIC.to_string(),
                operands: format!("{word:#010x}"),
                kind: InsnKind::Unknown,
            });
        }

        let text = inst.to_string();
        let (mnemonic, operands) = split_mnemonic(&text);
        let kind = classify(&inst, &mnemonic, insn_address);
        Ok(Insn { address: insn_address, bytes_len: INSN_WIDTH, mnemonic, operands, kind })
    }

    fn triple(&self) -> &'static str {
        "aarch64-linux-gnu"
    }

    fn instruction_width(&self) -> usize {
        INSN_WIDTH
    }

    fn is_register(&self, operand: &str) -> bool {
        let operand = operand.trim();
        matches!(operand, "sp" | "wsp" | "xzr" | "wzr" | "lr")
            || ["x", "w", "d", "s", "q", "h", "b", "v"].iter().any(|prefix| {
                operand.strip_prefix(prefix).is_some_and(|number| {
                    let number = number.split('.').next().unwrap_or_default();
                    !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
                })
            })
    }

    fn is_stack_register(&self, operand: &str) -> bool {
        matches!(operand.trim(), "sp" | "wsp" | "x29")
    }

    fn mentions_stack_slot(&self, operands: &str) -> bool {
        operands.contains("[sp") || operands.contains("[x29")
    }

    fn constant_value(&self, operand: &str) -> Option<u64> {
        let text = operand.trim().trim_start_matches('#');
        if text.is_empty() || text.contains(['[', ']']) || text.starts_with('$') {
            return None;
        }
        let (negative, text) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let value = match text.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).ok()?,
            None => text.parse::<u64>().ok()?,
        };
        Some(if negative { value.wrapping_neg() } else { value })
    }

    /// The condition of `b.ne` is dropped, as A32 drops it from `bne`.
    fn normalize_operation(&self, mnemonic: &str) -> CompactString {
        let mnemonic = mnemonic.trim();
        match mnemonic.split_once('.') {
            Some((stem, _)) if stem == "b" => stem.into(),
            _ => mnemonic.into(),
        }
    }

    fn is_frame_management(&self, insn: &Insn) -> bool {
        let operation = self.normalize_operation(&insn.mnemonic);
        let operands = insn.operands.as_str();
        let first = operands.split(',').next().unwrap_or_default();
        match operation.as_str() {
            // Saving and restoring the frame and the registers it keeps.
            "stp" | "ldp" | "str" | "ldr" => self.mentions_stack_slot(operands),
            // Moving the stack pointer, or setting up the frame pointer.
            "sub" | "add" | "mov" => self.is_stack_register(first),
            // Signing and checking the return address, and marking a branch
            // target, change nothing a function computes.
            "paciasp" | "pacibsp" | "autiasp" | "autibsp" | "bti" => true,
            _ => false,
        }
    }

    /// Almost every function that calls another saves the frame pointer and
    /// the link register first, as `stp x29, x30, [sp, #-N]!`. A leaf that
    /// needs no frame has no prologue, which is why the scan treats this as
    /// one source among several.
    fn is_prologue(&self, insn: &Insn) -> bool {
        (insn.mnemonic == "stp" && insn.operands.starts_with("x29, x30, [sp"))
            || (insn.mnemonic == "str"
                && insn.operands.starts_with("x30, [sp")
                && insn.operands.ends_with('!'))
    }

    /// A signed return address, or a branch target mark, can come before
    /// the frame is made.
    fn preamble_before_prologue(&self, earlier: &[Insn]) -> usize {
        let Some(last) = earlier.last() else { return 0 };
        usize::from(matches!(last.mnemonic.as_str(), "paciasp" | "pacibsp" | "bti"))
    }

    fn is_padding(&self, insn: &Insn) -> bool {
        insn.mnemonic == "nop" || (insn.kind == InsnKind::Unknown && insn.operands == "0x00000000")
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
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
    ) -> Vec<ConstantKind> {
        track_pages(body, space).kinds
    }

    fn data_addresses(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        _memory: &Memory<'_>,
    ) -> Vec<u64> {
        track_pages(body, space).addresses
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
        let (insns, _) = super::decode_all(self, code.get(..4 * INSN_WIDTH)?, address);
        let [adrp, load, add, jump] = insns.as_slice() else { return None };
        let page = page_of(adrp)?;
        let low =
            self.constant_value(load.operands.strip_prefix("x17, [x16, ")?.strip_suffix(']')?)?;
        let shape = load.mnemonic == "ldr"
            && add.operands.starts_with("x16, x16, ")
            && jump.mnemonic == "br"
            && jump.operands == "x17";
        shape.then_some(page + low)
    }

    /// `br x16` and `br x17`: the ABI keeps these two for a jump the linker
    /// adds, a PLT stub or a veneer. A `switch` jumps through another.
    fn is_tail_call(&self, insn: &Insn) -> bool {
        insn.mnemonic == "br" && matches!(insn.operands.as_str(), "x16" | "x17")
    }

    fn pointer_width(&self) -> usize {
        POINTER_WIDTH
    }

    fn read_pointer(&self, bytes: &[u8]) -> u64 {
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }
}

/// How an instruction moves control. The pointer authentication forms of a
/// return, a jump and a call, as `retaa`, `braa` and `blraa`, move it as the
/// plain ones do.
fn classify(inst: &Instruction, mnemonic: &str, address: u64) -> InsnKind {
    let target = inst.operands.iter().find_map(|operand| match operand {
        Operand::PCOffset(offset) => address.checked_add_signed(*offset),
        _ => None,
    });
    match inst.opcode {
        Opcode::BL => InsnKind::Call { target },
        Opcode::B => InsnKind::Jump { target },
        Opcode::Bcc(_) | Opcode::CBZ | Opcode::CBNZ | Opcode::TBZ | Opcode::TBNZ => {
            InsnKind::Branch { target }
        }
        _ if mnemonic.starts_with("ret") || mnemonic.starts_with("eret") => InsnKind::Return,
        _ if mnemonic.starts_with("blr") => InsnKind::Call { target: None },
        _ if mnemonic.starts_with("br") => InsnKind::Jump { target: None },
        _ => InsnKind::Normal,
    }
}

/// The page an `adrp` names, or the address an `adr` does.
fn page_of(insn: &Insn) -> Option<u64> {
    let distance = insn.operands.split_once(", $")?.1;
    let (negative, digits) = match distance.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, distance.strip_prefix('+')?),
    };
    let offset = u64::from_str_radix(digits.strip_prefix("0x")?, 16).ok()?;
    let base = match insn.mnemonic.as_str() {
        "adrp" => insn.address & !(PAGE - 1),
        "adr" => insn.address,
        _ => return None,
    };
    Some(if negative { base.wrapping_sub(offset) } else { base.wrapping_add(offset) })
}

/// What reading a function for its pages found.
struct Pages {
    kinds: Vec<ConstantKind>,
    addresses: Vec<u64>,
}

/// Follow each register that holds a page from `adrp`, or an address from
/// `adr`, to the `add` or the load that joins an offset to it.
fn track_pages(body: &[Insn], space: &AddressSpace) -> Pages {
    let mut kinds = vec![ConstantKind::Value; body.len()];
    let mut addresses = Vec::new();
    // Registers holding a page, or an address.
    let mut held: Vec<(&str, u64)> = Vec::new();
    // The page each register last took from `adrp`. An `add` to itself
    // keeps it: on another path through the function, the register still
    // holds the page. GCC's `inflate_table` for AArch64 at `-Os` adds the
    // same offset to one page register on two paths.
    let mut pages: Vec<(&str, u64)> = Vec::new();
    // Every page each register took. Code that only a branch reaches, after
    // a jump or a return, can find a register as any path left it, and the
    // path the page came by is not always the one above: `inflate_table`
    // copies over the page register just before it jumps away.
    let mut ever: Vec<(&str, u64)> = Vec::new();
    let values_of = |list: &[(&str, u64)], register: &str| -> Vec<u64> {
        list.iter().filter(|(name, _)| *name == register).map(|&(_, value)| value).collect()
    };
    // The address a base register and an offset form, if what the register
    // holds, or a page it may hold, lands in the image.
    let formed = |held: &[(&str, u64)], pages: &[(&str, u64)], base: &str, low: u64| {
        values_of(held, base)
            .into_iter()
            .chain(values_of(pages, base))
            .map(|value| value.wrapping_add(low))
            .find(|&address| space.contains_formed(address))
    };

    for (index, insn) in body.iter().enumerate() {
        let after_an_end =
            index > 0 && matches!(body[index - 1].kind, InsnKind::Jump { .. } | InsnKind::Return);
        if after_an_end {
            pages = ever.clone();
        }
        let operands: Vec<&str> = insn.operands.split(',').map(str::trim).collect();
        let Some(&destination) = operands.first() else { continue };
        match (insn.mnemonic.as_str(), operands.as_slice()) {
            // The distance from `pc` to a page or to data moves whenever the
            // code or the data does.
            ("adrp" | "adr", _) => {
                kinds[index] = ConstantKind::Address;
                held.retain(|(name, _)| *name != destination);
                pages.retain(|(name, _)| *name != destination);
                if let Some(value) = page_of(insn) {
                    if insn.mnemonic == "adr" && space.contains_formed(value) {
                        addresses.push(value);
                    }
                    held.push((destination, value));
                    if insn.mnemonic == "adrp" {
                        pages.push((destination, value));
                        ever.push((destination, value));
                    }
                }
                continue;
            }
            // `add xD, xP, #lo12`: the address on the page.
            ("add", [_, source, low]) if low.starts_with('#') => {
                let address =
                    Aarch64.constant_value(low).and_then(|low| formed(&held, &pages, source, low));
                if let Some(address) = address {
                    kinds[index] = ConstantKind::Address;
                    addresses.push(address);
                    held.retain(|(name, _)| *name != destination);
                    held.push((destination, address));
                    if destination != *source {
                        pages.retain(|(name, _)| *name != destination);
                    }
                    continue;
                }
            }
            // `ldr xD, [xP, #lo12]` and stores: data on the page.
            (mnemonic, [.., reference, low])
                if (mnemonic.starts_with("ld") || mnemonic.starts_with("st"))
                    && reference.starts_with('[')
                    && low.ends_with(']') =>
            {
                let base = reference.trim_start_matches('[');
                let low = low.trim_end_matches(']').trim_end_matches('!');
                if Aarch64
                    .constant_value(low)
                    .and_then(|low| formed(&held, &pages, base, low))
                    .is_some()
                {
                    kinds[index] = ConstantKind::Address;
                }
            }
            _ => {}
        }
        // Any other write of the register ends what it held. A store names
        // the register it reads first.
        if !insn.mnemonic.starts_with("st") && !insn.mnemonic.starts_with("cmp") {
            held.retain(|(name, _)| *name != destination);
            pages.retain(|(name, _)| *name != destination);
        }
    }
    Pages { kinds, addresses }
}

/// Read the table a `br` at `insns[index]` jumps through.
fn read_jump_table(
    memory: &Memory<'_>,
    code: &Range<u64>,
    insns: &[Insn],
    index: usize,
) -> Option<JumpTable> {
    let jump = &insns[index];
    if jump.mnemonic != "br" {
        return None;
    }
    let earlier = &insns[index.saturating_sub(TABLE_LOOK_BACK)..index];
    let last_write = |register: &str, before: u64| {
        earlier.iter().rev().filter(|insn| insn.address < before).find(|insn| {
            !insn.mnemonic.starts_with("st")
                && !insn.mnemonic.starts_with("cmp")
                && insn.operands.split(',').next().map(str::trim) == Some(register)
        })
    };
    // `add xT, xB, xE, lsl #2`, or GCC's `add xT, xB, wE, sxth #2`.
    let add = last_write(jump.operands.trim(), jump.address)?;
    let parts: Vec<&str> = add.operands.split(',').map(str::trim).collect();
    let [_, base_register, entry_register, extend] = parts.as_slice() else { return None };
    let signed = extend.starts_with("sxt");
    if add.mnemonic != "add" || !extend.ends_with("#2") {
        return None;
    }
    let base = page_of(last_write(base_register, add.address)?)?;

    // `ldrb wE, [xTab, xI, lsl #1]` and the like: one entry.
    let entry_name = format!("w{}", &entry_register[1..]);
    let load = last_write(&entry_name, add.address)?;
    let width = match load.mnemonic.as_str() {
        "ldrb" | "ldrsb" => 1,
        "ldrh" | "ldrsh" => 2,
        "ldr" | "ldrsw" => 4,
        _ => return None,
    };
    let reference = load.operands.split_once('[')?.1;
    let mut fields = reference.split([',', ']']).map(str::trim);
    let (table_register, index_register) = (fields.next()?, fields.next()?);
    let table_insn = last_write(table_register, load.address)?;
    let table = match table_insn.mnemonic.as_str() {
        "adr" => page_of(table_insn)?,
        "add" => {
            let parts: Vec<&str> = table_insn.operands.split(',').map(str::trim).collect();
            let [_, page_register, low] = parts.as_slice() else { return None };
            let page = page_of(last_write(page_register, table_insn.address)?)?;
            page.wrapping_add(Aarch64.constant_value(low)?)
        }
        _ => return None,
    };

    // `cmp wI, #n`: the cases run from 0 to n.
    let index_number = &index_register[1..];
    let bound = earlier.iter().rev().find_map(|insn| {
        let parts: Vec<&str> = insn.operands.split(',').map(str::trim).collect();
        match (insn.mnemonic.as_str(), parts.as_slice()) {
            ("cmp", [register, bound]) if register.get(1..) == Some(index_number) => {
                Aarch64.constant_value(bound)
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
mod tests {
    use super::*;
    use crate::arch::decode_all;

    fn code(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn decode_one(word: u32) -> Insn {
        Aarch64.decode(&word.to_le_bytes(), 0, 0x1000).expect("the word must decode")
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
        assert_eq!(Aarch64.data_addresses(&[], &insns, &space, &Memory::new(&[])), [0x11028]);
        let kinds = Aarch64.constant_kinds(&[], &insns, &space);
        assert_eq!(kinds[..2], [ConstantKind::Address, ConstantKind::Address]);
    }

    /// The PLT stub of LLD for AArch64, from zlib.
    #[test]
    fn reads_the_slot_a_plt_stub_jumps_through() {
        let stub = code(&[0x9000_0110, 0xf942_3e11, 0x9111_e210, 0xd61f_0220]);
        assert_eq!(Aarch64.stub_slot(&stub, 0x1a210), Some(0x3a478));
        assert_eq!(Aarch64.stub_slot(&stub[..8], 0x1a210), None, "too short");
    }

    #[test]
    fn padding_is_nops_and_zeros() {
        let bytes = code(&[0xd65f_03c0, 0xd503_201f, 0]);
        assert_eq!(Aarch64.trim_padding(&bytes), &bytes[..4]);
        assert!(Aarch64.is_padding(&decode_one(0xd503_201f)));
    }

    #[test]
    fn constants_read_with_their_sign() {
        assert_eq!(Aarch64.constant_value("#0x30"), Some(0x30));
        assert_eq!(Aarch64.constant_value("#-0x30"), Some(0x30_u64.wrapping_neg()));
        assert_eq!(Aarch64.constant_value("[sp, #0x10]"), None);
    }
}
