//! ARM32 (A32) decoding, on top of `yaxpeax-arm`.
//!
//! Two details of the `yaxpeax` API are easy to get wrong, so this module
//! handles both and the rest of `hereticus` never sees them:
//!
//! 1. `U8Reader` implements `Reader<u32, U32le>`, not `Reader<u32, u32>`.
//! 2. `total_offset()` counts **words**, not bytes. Multiplying by the
//!    instruction width is what makes reported addresses right.

use compact_str::CompactString;
use yaxpeax_arch::{Decoder, Reader, U8Reader, U32le};
use yaxpeax_arm::armv7::{ConditionCode, InstDecoder, Instruction, Opcode, Operand};

use super::{Arch, DecodeError, Insn, InsnKind};
use crate::address::{AddressSpace, ConstantKind};

/// Every A32 instruction is 4 bytes wide.
const INSN_WIDTH: usize = 4;

/// The section holding the ARM exception index.
///
/// One entry a function, each naming where that function starts. It survives
/// stripping, so it is the strongest source of function boundaries there is.
const UNWIND_SECTION: &str = ".ARM.exidx";

/// The A32 `nop` encoding, little endian.
const NOP_BYTES: [u8; 4] = [0x00, 0xf0, 0x20, 0xe3];

/// Zero words, which some linkers pad with instead.
const ZERO_BYTES: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

/// Mnemonic reported for bytes the decoder cannot read.
///
/// `yaxpeax-arm` 0.4 has no NEON or SIMD support and answers "incomplete
/// decoder" for those encodings. `clang` vectorizes automatically at `-O2`,
/// so real code reaches this path.
const UNKNOWN_MNEMONIC: &str = "(unknown)";

/// Register number of the program counter.
const REG_PC: u16 = 15;
/// Register number of the link register.
const REG_LR: u16 = 14;

/// ARM32 in A32 (not Thumb) mode.
#[derive(Clone, Copy, Debug, Default)]
pub struct Arm32;

impl Arch for Arm32 {
    fn decode(&self, code: &[u8], offset: usize, address: u64) -> Result<Insn, DecodeError> {
        let bytes = code.get(offset..).ok_or(DecodeError::Truncated)?;
        if bytes.len() < INSN_WIDTH {
            return Err(DecodeError::Truncated);
        }

        let insn_address = address + offset as u64;

        let mut reader = U8Reader::new(bytes);
        let mut inst = Instruction::default();

        // `yaxpeax` rejects a word it cannot read in two different ways: it
        // returns an error, or it succeeds and sets `Opcode::Invalid`. The
        // standard ARM `nop`, `0xe320f000`, takes the second path. Both mean
        // the same thing here.
        let failed = InstDecoder::default().decode_into(&mut inst, &mut reader).is_err();
        if failed || inst.opcode == Opcode::Invalid {
            // A32 instructions are all 4 bytes, so stepping over an
            // unreadable word keeps everything after it aligned. Reporting an
            // error instead would throw away the rest of the function.
            //
            // The raw word goes in the operand field. Without it every
            // unreadable instruction would look like every other one, and an
            // edit inside a NEON loop would be reported as no change at all.
            let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            return Ok(Insn {
                address: insn_address,
                bytes_len: INSN_WIDTH,
                mnemonic: UNKNOWN_MNEMONIC.to_string(),
                operands: format!("{word:#010x}"),
                kind: InsnKind::Unknown,
            });
        }

        // `total_offset` is in words; convert so the assertion below compares
        // like with like.
        let words = <U8Reader<'_> as Reader<u32, U32le>>::total_offset(&mut reader);
        let consumed = words as usize * INSN_WIDTH;
        debug_assert_eq!(consumed, INSN_WIDTH, "A32 instructions are always 4 bytes");

        let text = inst.to_string();
        let (mnemonic, operands) = split_mnemonic(&text);

        Ok(Insn {
            address: insn_address,
            bytes_len: INSN_WIDTH,
            mnemonic,
            operands,
            kind: classify(&inst, insn_address),
        })
    }

    fn triple(&self) -> &'static str {
        "arm-linux-gnueabi"
    }

    fn instruction_width(&self) -> usize {
        INSN_WIDTH
    }

    fn is_register(&self, operand: &str) -> bool {
        // `ip`, `sl` and `fp` are the AAPCS names for r12, r10 and r11.
        matches!(operand, "sp" | "lr" | "pc" | "ip" | "sl" | "fp")
            || operand.strip_prefix('r').is_some_and(|number| {
                !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit())
            })
    }

    fn is_stack_register(&self, operand: &str) -> bool {
        matches!(operand.trim(), "sp" | "fp" | "r13" | "r11")
    }

    fn mentions_stack_slot(&self, operands: &str) -> bool {
        operands.contains("[sp") || operands.contains("[fp") || operands.contains("[r13")
    }

    /// Register lists print as `{r4, lr}`. Splitting the operand list on
    /// commas breaks them apart, so a fragment is recognized by its braces
    /// rather than by holding both.
    fn is_register_list(&self, operand: &str) -> bool {
        operand.starts_with('{') || operand.ends_with('}')
    }

    fn constant_value(&self, operand: &str) -> Option<u64> {
        let text = operand.trim().trim_start_matches('#');
        if text.is_empty() {
            return None;
        }

        // A memory reference can hold a constant, but that constant is an
        // offset into a frame or object and moves with unrelated edits.
        if text.contains('[') || text.contains(']') || text.starts_with('$') {
            return None;
        }

        match text.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).ok(),
            None => text.parse::<u64>().ok(),
        }
    }

    /// A compiler picks between `add` and `adds`, and between a branch and a
    /// conditional move, for reasons that do not change what the code
    /// computes.
    fn normalize_operation(&self, mnemonic: &str) -> CompactString {
        const CONDITIONS: [&str; 17] = [
            "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
            "al", "lo", "hs",
        ];

        // Mnemonics that end in condition letters but carry no condition.
        const NOT_CONDITIONAL: [&str; 6] = ["b", "bl", "ble", "bls", "movs", "cmps"];

        let mnemonic = mnemonic.trim();
        if NOT_CONDITIONAL.contains(&mnemonic) {
            // `movs` and `cmps` still carry a flag-setting suffix to remove.
            return mnemonic.trim_end_matches('s').into();
        }

        let without_condition = CONDITIONS
            .iter()
            .find_map(|suffix| mnemonic.strip_suffix(suffix).filter(|stem| stem.len() >= 2))
            .unwrap_or(mnemonic);

        // Keep a trailing `s` that belongs to the name, as in `bics` versus
        // `bic`.
        match without_condition.strip_suffix('s') {
            Some(stem) if stem.len() >= 2 => stem.into(),
            _ => without_condition.into(),
        }
    }

    fn is_frame_management(&self, insn: &Insn) -> bool {
        let operation = self.normalize_operation(&insn.mnemonic);
        let operands = insn.operands.as_str();
        let first = operands.split(',').next().unwrap_or_default();

        match operation.as_str() {
            // Saving and restoring registers. A `pop` that loads the program
            // counter also returns, so it must stay.
            "push" => true,
            "pop" => insn.kind != InsnKind::Return,

            // Moving the stack pointer, or setting up the frame pointer.
            "sub" | "add" | "mov" => self.is_stack_register(first),

            // Spilling to and reloading from the frame.
            "ldr" | "str" | "ldm" | "stm" => self.mentions_stack_slot(operands),

            _ => false,
        }
    }

    /// A function that calls anything must save the link register first, so
    /// `push {..., lr}` is how almost every non-leaf ARM function begins.
    /// Measured on a stripped kernel object, every real function start matched
    /// this and nothing else did.
    ///
    /// A leaf function has no prologue at all, which is why the scanner treats
    /// this as one source among several.
    fn is_prologue(&self, insn: &Insn) -> bool {
        (insn.mnemonic.starts_with("push") || insn.mnemonic.starts_with("stm"))
            && insn.operands.contains("lr")
    }

    /// `yaxpeax-arm` 0.4 does not decode the usual ARM `nop` encoding
    /// `0xe320f000` and reports it as unreadable, so the raw word is checked
    /// as well as the name.
    fn is_padding(&self, insn: &Insn) -> bool {
        /// The A32 hint encoding that means "no operation", as printed.
        const NOP: &str = "0xe320f000";
        /// Zero words, which some linkers use to pad instead.
        const ZERO: &str = "0x00000000";

        insn.mnemonic.starts_with("nop")
            || (insn.kind == InsnKind::Unknown && (insn.operands == NOP || insn.operands == ZERO))
    }

    /// Only whole words at the end are removed, and only the two encodings a
    /// linker pads with.
    fn trim_padding<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        let mut end = bytes.len();
        while end >= INSN_WIDTH {
            let word = &bytes[end - INSN_WIDTH..end];
            if word == NOP_BYTES || word == ZERO_BYTES {
                end -= INSN_WIDTH;
            } else {
                break;
            }
        }

        &bytes[..end]
    }

    /// ARM code reaches its data through literal pool words, and PIC code
    /// stores a *distance* there rather than an address: the word is added to
    /// `pc`, or used as an offset from a base built that way.
    ///
    /// ```text
    /// ldr r0, [pc, 0x4]     ; load the pool word
    /// add r0, pc, r0        ; add it to pc: the word is a distance
    /// ...
    /// ldr r3, [pc, 0xa0]
    /// ldr r3, [pc, r3]      ; read a GOT entry at that distance
    /// ```
    ///
    /// Such a word changes whenever the linker moves the data it reaches,
    /// which is every release, so it is marked as a stored address, but only
    /// when the address it forms lies inside `space`. A distance to something
    /// outside the image, such as the kernel a decompressor stub unpacks,
    /// stays a value: it changes because the thing it measures changed. A
    /// pool word used any other way, such as a size or a mask, stays a value.
    /// Measured on zlib built as an ARM shared library, these words alone made
    /// 18 unedited functions read as changed.
    fn constant_kinds(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
    ) -> Vec<ConstantKind> {
        /// `pc` reads two instructions ahead of the one that uses it.
        const PC_AHEAD: u64 = 8;

        let mut kinds = vec![ConstantKind::Value; body.len()];
        let Some(start) = body.first().map(|insn| insn.address) else { return kinds };

        // Registers holding a pool word: where the word sits, and its value.
        let mut literal: Vec<(&str, u64, u32)> = Vec::new();
        // Registers holding an address built from `pc` and a pool word.
        let mut relative: Vec<(&str, u64)> = Vec::new();

        let word_at = |pool: u64| -> Option<u32> {
            let offset = usize::try_from(pool.checked_sub(start)?).ok()?;
            let bytes = code.get(offset..offset.checked_add(INSN_WIDTH)?)?;
            Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        };

        for insn in body {
            let operation = self.normalize_operation(&insn.mnemonic);
            let Some((destination, rest)) = insn.operands.split_once(',') else { continue };
            let (destination, rest) = (destination.trim(), rest.trim());
            let pc = insn.address.wrapping_add(PC_AHEAD);
            let literal_of = |register: &str| {
                literal
                    .iter()
                    .find(|(held, ..)| *held == register)
                    .map(|&(_, pool, value)| (pool, value))
            };
            let base_of = |register: &str| match register {
                "pc" => Some(pc),
                _ => relative.iter().find(|(held, _)| *held == register).map(|&(_, at)| at),
            };
            // The address a base and a pool word form, when it lies in the
            // image, marks the word as a stored address.
            let mut formed = |base: u64, (pool, value): (u64, u32)| {
                let address = base.wrapping_add(i64::from(value as i32) as u64);
                if space.contains(address)
                    && let Ok(index) = body.binary_search_by_key(&pool, |insn| insn.address)
                {
                    kinds[index] = ConstantKind::StoredAddress;
                }
                address
            };

            match (operation.as_str(), parse_reference(rest), parse_three(rest)) {
                // `ldr rX, [pc, imm]`: load a pool word.
                ("ldr", Some(("pc", Offset::Immediate(offset))), _) => {
                    let pool = pc.wrapping_add(offset as u64);
                    forget(&mut literal, &mut relative, destination);
                    if let Some(value) = word_at(pool) {
                        literal.push((destination, pool, value));
                    }
                    continue;
                }
                // `ldr rY, [base, rX]`: read at a distance from a base.
                ("ldr", Some((base, Offset::Register(index))), _) => {
                    if let (Some(base), Some(word)) = (base_of(base), literal_of(index)) {
                        formed(base, word);
                    }
                }
                // `add rY, base, rX`, either order: build an address.
                ("add", _, Some((left, right))) => {
                    let joined = match (
                        base_of(left),
                        literal_of(right),
                        base_of(right),
                        literal_of(left),
                    ) {
                        (Some(base), Some(word), ..) | (.., Some(base), Some(word)) => {
                            Some((base, word))
                        }
                        _ => None,
                    };
                    if let Some((base, word)) = joined {
                        let address = formed(base, word);
                        forget(&mut literal, &mut relative, destination);
                        relative.push((destination, address));
                        continue;
                    }
                }
                _ => {}
            }

            if writes_first_operand(&operation) {
                forget(&mut literal, &mut relative, destination);
            }
        }

        kinds
    }

    /// A variadic function reserves room for its register arguments before it
    /// saves anything, so `sub sp, sp, #N` opens it one word before the
    /// `push`. Measured on Lua built as an ARM shared library: without this,
    /// `lua_pushfstring`, `luaG_runerror` and `luaO_pushfstring` each left a
    /// one-word fragment that no release could pair.
    fn preamble_before_prologue(&self, earlier: &[Insn]) -> usize {
        let Some(last) = earlier.last() else { return 0 };
        let reserves_stack = self.normalize_operation(&last.mnemonic) == "sub"
            && last.operands.starts_with("sp, sp, ");
        usize::from(reserves_stack)
    }

    /// `ldr rX, [pc, imm]` loads one pool word, and `ldrd` and `vldr` two.
    fn literal_pool_words(&self, insns: &[Insn]) -> Vec<u64> {
        /// `pc` reads two instructions ahead of the one that uses it.
        const PC_AHEAD: u64 = 8;

        let mut words = Vec::new();
        for insn in insns {
            let operation = self.normalize_operation(&insn.mnemonic);
            let count = match operation.as_str() {
                "ldr" => 1,
                "ldrd" | "vldr" => 2,
                _ => continue,
            };
            let Some((_, reference)) = insn.operands.rsplit_once('[') else { continue };
            let Some(("pc", Offset::Immediate(offset))) = parse_reference(&format!("[{reference}"))
            else {
                continue;
            };
            let pool = insn.address.wrapping_add(PC_AHEAD).wrapping_add(offset as u64);
            words.extend((0..count).map(|word| pool + word * INSN_WIDTH as u64));
        }
        words
    }

    fn unwind_section(&self) -> Option<&'static str> {
        Some(UNWIND_SECTION)
    }

    fn pointer_width(&self) -> usize {
        INSN_WIDTH
    }

    fn read_pointer(&self, bytes: &[u8]) -> u64 {
        u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

/// The offset in a memory reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Offset<'a> {
    Immediate(i64),
    Register(&'a str),
}

/// Read `[base, offset]` as the base register and the offset.
fn parse_reference(text: &str) -> Option<(&str, Offset<'_>)> {
    let inner = text.strip_prefix('[')?.strip_suffix(']')?;
    let (base, offset) = inner.split_once(',')?;
    let offset = offset.trim();
    let parsed = match offset.strip_prefix('-') {
        Some(digits) => Offset::Immediate(-parse_number(digits)?),
        None if offset.starts_with("0x") || offset.starts_with(|c: char| c.is_ascii_digit()) => {
            Offset::Immediate(parse_number(offset)?)
        }
        None => Offset::Register(offset),
    };
    Some((base.trim(), parsed))
}

fn parse_number(text: &str) -> Option<i64> {
    match text.strip_prefix("0x") {
        Some(hex) => i64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// Read `rA, rB`, the two sources of a three-register operation.
fn parse_three(text: &str) -> Option<(&str, &str)> {
    let (left, right) = text.split_once(',')?;
    let right = right.trim();
    (!right.contains(',')).then(|| (left.trim(), right))
}

/// Stop following a register the instruction writes.
fn forget(literal: &mut Vec<(&str, u64, u32)>, relative: &mut Vec<(&str, u64)>, register: &str) {
    literal.retain(|(held, ..)| *held != register);
    relative.retain(|(held, _)| *held != register);
}

/// Report whether an operation writes its first operand. Stores, compares
/// and branches read it.
fn writes_first_operand(operation: &str) -> bool {
    !matches!(
        operation,
        "str"
            | "strb"
            | "strh"
            | "strd"
            | "push"
            | "stm"
            | "stmdb"
            | "cmp"
            | "cmn"
            | "tst"
            | "teq"
            | "b"
            | "bl"
            | "bx"
            | "blx"
    )
}

/// Split rendered instruction text into the mnemonic and the rest.
fn split_mnemonic(text: &str) -> (String, String) {
    match text.split_once(char::is_whitespace) {
        Some((head, tail)) => (head.to_string(), tail.trim().to_string()),
        None => (text.to_string(), String::new()),
    }
}

/// Work out how an instruction moves control flow.
///
/// ARM has no single "return" opcode. A return is any write to the program
/// counter, so `pop {pc}` decodes as `LDR` and `mov pc, lr` as `MOV`. Reading
/// the opcode alone would miss both, so check the destination register too.
fn classify(inst: &Instruction, address: u64) -> InsnKind {
    let unconditional = inst.condition == ConditionCode::AL;

    match inst.opcode {
        Opcode::BL | Opcode::BLX => InsnKind::Call { target: branch_target(inst, address) },

        // `bx lr` returns; `bx <other>` is an indirect jump.
        Opcode::BX => match inst.operands[0] {
            Operand::Reg(reg) if reg.number() as u16 == REG_LR => InsnKind::Return,
            _ => InsnKind::Jump { target: None },
        },

        Opcode::B => {
            let target = branch_target(inst, address);
            if unconditional { InsnKind::Jump { target } } else { InsnKind::Branch { target } }
        }

        // Anything that writes the PC leaves the current block.
        _ if writes_pc(inst) => {
            if unconditional {
                InsnKind::Return
            } else {
                InsnKind::Branch { target: None }
            }
        }

        _ => InsnKind::Normal,
    }
}

/// Resolve a PC-relative branch to a virtual address.
///
/// `yaxpeax` reports the offset in **words**, measured from the instruction
/// itself, and has already removed the 8-byte pipeline bias that the ARM
/// encoding carries. A branch to itself therefore reports offset 0. Adding the
/// bias again here would put every target 8 bytes too far.
fn branch_target(inst: &Instruction, address: u64) -> Option<u64> {
    match inst.operands[0] {
        Operand::BranchOffset(words) => {
            let byte_offset = (words as i64) * INSN_WIDTH as i64;
            u64::try_from(address as i64 + byte_offset).ok()
        }
        _ => None,
    }
}

/// Report whether the instruction writes the program counter.
fn writes_pc(inst: &Instruction) -> bool {
    inst.operands.iter().any(|operand| match operand {
        Operand::Reg(reg) => reg.number() as u16 == REG_PC,
        Operand::RegWBack(reg, _) => reg.number() as u16 == REG_PC,
        // `pop {..., pc}` carries the PC as a bit in a register-list mask.
        Operand::RegList(mask) => mask & (1 << REG_PC) != 0,
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::decode_all;

    /// Decode one instruction from raw bytes at address 0.
    fn decode_one(bytes: [u8; 4]) -> Insn {
        Arm32.decode(&bytes, 0, 0).expect("bytes must decode")
    }

    #[test]
    fn decodes_simple_arithmetic() {
        let insn = decode_one([0x00, 0x00, 0x81, 0xe0]);
        assert_eq!(insn.mnemonic, "add");
        assert_eq!(insn.operands, "r0, r1, r0");
        assert_eq!(insn.bytes_len, 4);
        assert_eq!(insn.kind, InsnKind::Normal);
    }

    #[test]
    fn bx_lr_is_a_return() {
        assert_eq!(decode_one([0x1e, 0xff, 0x2f, 0xe1]).kind, InsnKind::Return);
    }

    /// `pop {pc}` decodes with opcode `LDR`, so only the PC check finds it.
    #[test]
    fn pop_pc_is_a_return() {
        assert_eq!(decode_one([0x04, 0xf0, 0x9d, 0xe4]).kind, InsnKind::Return);
    }

    /// `pop {fp, pc}` carries the PC in a register-list bitmask.
    #[test]
    fn pop_reglist_with_pc_is_a_return() {
        assert_eq!(decode_one([0x00, 0x88, 0xbd, 0xe8]).kind, InsnKind::Return);
    }

    /// `mov pc, lr` decodes with opcode `MOV`.
    #[test]
    fn mov_pc_lr_is_a_return() {
        assert_eq!(decode_one([0x0e, 0xf0, 0xa0, 0xe1]).kind, InsnKind::Return);
    }

    #[test]
    fn push_is_not_a_return() {
        assert_eq!(decode_one([0x00, 0x48, 0x2d, 0xe9]).kind, InsnKind::Normal);
    }

    /// `sub sp, sp, 0xc` before a `push` opens a variadic function.
    #[test]
    fn a_stack_reservation_before_the_prologue_opens_the_function() {
        let reserve = decode_one(0xe24d_d00c_u32.to_le_bytes()); // sub sp, sp, 0xc
        let work = decode_one(0xe080_0001_u32.to_le_bytes()); // add r0, r0, r1
        assert_eq!(Arm32.preamble_before_prologue(&[work.clone(), reserve]), 1);
        assert_eq!(Arm32.preamble_before_prologue(&[work]), 0);
        assert_eq!(Arm32.preamble_before_prologue(&[]), 0);
    }

    #[test]
    fn bl_is_a_call() {
        let insn = decode_one([0xfe, 0xff, 0xff, 0xeb]);
        assert!(matches!(insn.kind, InsnKind::Call { .. }));
    }

    /// `b` and `beq` share opcode `B`; only the condition separates them.
    #[test]
    fn unconditional_branch_is_a_jump() {
        assert!(matches!(decode_one([0xfe, 0xff, 0xff, 0xea]).kind, InsnKind::Jump { .. }));
    }

    #[test]
    fn conditional_branch_can_fall_through() {
        assert!(matches!(decode_one([0xfe, 0xff, 0xff, 0x0a]).kind, InsnKind::Branch { .. }));
    }

    /// `yaxpeax` removes the pipeline bias, so a branch to self is offset 0.
    #[test]
    fn branch_to_self_resolves_to_its_own_address() {
        let insn = Arm32.decode(&[0xfe, 0xff, 0xff, 0xea], 0, 0x1000).unwrap();
        assert_eq!(insn.kind, InsnKind::Jump { target: Some(0x1000) });
    }

    /// Branching to itself cannot catch a wrong scale or sign, so check a
    /// forward and a backward branch too.
    #[test]
    fn branch_targets_scale_by_instruction_width() {
        let forward = Arm32.decode(&[0xff, 0xff, 0xff, 0xea], 0, 0x1000).unwrap();
        assert_eq!(forward.kind, InsnKind::Jump { target: Some(0x1004) });

        let backward = Arm32.decode(&[0xfd, 0xff, 0xff, 0xea], 0, 0x1000).unwrap();
        assert_eq!(backward.kind, InsnKind::Jump { target: Some(0x0ffc) });
    }

    #[test]
    fn address_tracks_the_offset() {
        let code = [0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
        assert_eq!(Arm32.decode(&code, 4, 0x8000).unwrap().address, 0x8004);
    }

    #[test]
    fn rejects_truncated_input() {
        assert_eq!(Arm32.decode(&[0x00, 0x00], 0, 0), Err(DecodeError::Truncated));
        assert_eq!(Arm32.decode(&[], 0, 0), Err(DecodeError::Truncated));
    }

    #[test]
    fn rejects_offset_past_the_end() {
        assert_eq!(Arm32.decode(&[0x00; 4], 8, 0), Err(DecodeError::Truncated));
    }

    /// Addresses must advance by 4 per instruction, not by 1. This is the
    /// regression test for the word-versus-byte offset trap.
    #[test]
    fn decode_all_advances_by_instruction_width() {
        // add, bx lr, add
        let code = [0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1, 0x00, 0x00, 0x81, 0xe0];
        let (insns, err) = decode_all(&Arm32, &code, 0x1000);
        assert_eq!(err, None);
        let addresses: Vec<u64> = insns.iter().map(|i| i.address).collect();
        assert_eq!(addresses, vec![0x1000, 0x1004, 0x1008]);
    }

    /// The usual ARM `nop` is one `yaxpeax` decodes "successfully" as
    /// `Opcode::Invalid`. It must still come back as unreadable, or a linker's
    /// padding looks like a real instruction.
    #[test]
    fn nop_encoding_decodes_as_unknown() {
        let insn = decode_one([0x00, 0xf0, 0x20, 0xe3]);
        assert_eq!(insn.kind, InsnKind::Unknown);
        assert_eq!(insn.operands, "0xe320f000", "the raw word must be kept");
    }

    /// NEON is outside what `yaxpeax-arm` 0.4 decodes. `vdup.32 q8, r2` must
    /// come back as opaque bytes, not as an error.
    #[test]
    fn neon_decodes_as_unknown() {
        let insn = decode_one([0x90, 0x2b, 0xa0, 0xee]);
        assert_eq!(insn.kind, InsnKind::Unknown);
        assert_eq!(insn.bytes_len, INSN_WIDTH);
    }

    /// Stepping over an unreadable word must keep the instructions after it
    /// aligned, which is the whole reason for the opaque kind.
    #[test]
    fn decoding_continues_past_unknown_bytes() {
        // add, vdup.32 (NEON), bx lr
        let code = [0x00, 0x00, 0x81, 0xe0, 0x90, 0x2b, 0xa0, 0xee, 0x1e, 0xff, 0x2f, 0xe1];
        let (insns, err) = decode_all(&Arm32, &code, 0x1000);

        assert_eq!(err, None, "unreadable bytes must not stop the decode");
        assert_eq!(insns.len(), 3);
        assert_eq!(insns[1].kind, InsnKind::Unknown);

        // The instruction after the opaque word must still be read correctly.
        assert_eq!(insns[2].kind, InsnKind::Return);
        assert_eq!(insns[2].address, 0x1008);
    }

    #[test]
    fn decode_all_reports_trailing_partial_bytes() {
        let code = [0x00, 0x00, 0x81, 0xe0, 0xff];
        let (insns, err) = decode_all(&Arm32, &code, 0);
        assert_eq!(insns.len(), 1);
        assert_eq!(err, Some(DecodeError::Truncated));
    }

    #[test]
    fn decode_all_handles_empty_input() {
        let (insns, err) = decode_all(&Arm32, &[], 0);
        assert!(insns.is_empty());
        assert_eq!(err, None);
    }

    #[test]
    fn trailing_padding_is_removed() {
        // add, then a nop the linker used to align the next function.
        let code = [0x00, 0x00, 0x81, 0xe0, 0x00, 0xf0, 0x20, 0xe3];
        assert_eq!(Arm32.trim_padding(&code), &code[..4]);
    }

    #[test]
    fn trailing_zero_words_are_removed() {
        let code = [0x00, 0x00, 0x81, 0xe0, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(Arm32.trim_padding(&code), &code[..4]);
    }

    /// Padding inside a function is not padding, so it must stay.
    #[test]
    fn padding_before_real_code_is_kept() {
        let code = [0x00, 0xf0, 0x20, 0xe3, 0x00, 0x00, 0x81, 0xe0];
        assert_eq!(Arm32.trim_padding(&code), &code[..], "only the end is trimmed");
    }

    #[test]
    fn trimming_leaves_a_function_of_only_padding_empty() {
        assert!(Arm32.trim_padding(&[0x00, 0xf0, 0x20, 0xe3]).is_empty());
    }

    #[test]
    fn trimming_keeps_code_that_needs_no_trimming() {
        let code = [0x00, 0x00, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
        assert_eq!(Arm32.trim_padding(&code), &code[..]);
    }

    #[test]
    fn a_prologue_is_recognized_by_its_saved_link_register() {
        let push_lr = Arm32.decode(&[0x10, 0x40, 0x2d, 0xe9], 0, 0).unwrap();
        assert!(Arm32.is_prologue(&push_lr), "push {{r4, lr}} opens a function");

        // `push {r4, r5}` saves no link register, so it calls nothing and is
        // not the start of a non-leaf function.
        let push_plain = Arm32.decode(&[0x30, 0x00, 0x2d, 0xe9], 0, 0).unwrap();
        assert!(!Arm32.is_prologue(&push_plain));

        let add = Arm32.decode(&[0x00, 0x00, 0x81, 0xe0], 0, 0).unwrap();
        assert!(!Arm32.is_prologue(&add));
    }

    /// The `nop` the linker pads with is one `yaxpeax` reports as unreadable,
    /// so it must be recognized by its raw word and not only by its name.
    #[test]
    fn padding_is_recognized_by_its_raw_word() {
        let nop = decode_one(NOP_BYTES);
        assert_eq!(nop.kind, InsnKind::Unknown, "the decoder cannot read this nop");
        assert!(Arm32.is_padding(&nop), "the A32 nop encoding is padding");

        let add = decode_one([0x00, 0x00, 0x81, 0xe0]);
        assert!(!Arm32.is_padding(&add), "real work is not padding");
    }

    /// A zero word decodes as `andeq r0, r0, r0`, a real instruction, so the
    /// instruction-level test does not claim it. Only [`Arch::trim_padding`],
    /// which reads the bytes, removes a run of zeros from the end of a
    /// function. The two tests differ on purpose: mistaking a zero word inside
    /// a function for padding would drop real code.
    #[test]
    fn a_zero_word_is_padding_only_to_the_byte_level_test() {
        let zero = decode_one(ZERO_BYTES);
        assert_eq!(zero.kind, InsnKind::Normal, "a zero word decodes as andeq");
        assert!(!Arm32.is_padding(&zero));
        assert!(Arm32.trim_padding(&ZERO_BYTES).is_empty());
    }

    #[test]
    fn conditions_are_stripped_from_a_mnemonic() {
        assert_eq!(Arm32.normalize_operation("movlt"), "mov");
        assert_eq!(Arm32.normalize_operation("bxeq"), "bx");
        assert_eq!(Arm32.normalize_operation("movs"), "mov");
    }

    /// A mnemonic that only looks conditional must survive intact.
    #[test]
    fn a_mnemonic_that_is_not_conditional_is_left_alone() {
        for operation in ["b", "bl", "ble", "mov", "mul", "push", "pop"] {
            assert_eq!(Arm32.normalize_operation(operation), operation);
        }
    }

    #[test]
    fn distinct_operations_stay_distinct() {
        assert_ne!(Arm32.normalize_operation("ldr"), Arm32.normalize_operation("str"));
        assert_ne!(Arm32.normalize_operation("push"), Arm32.normalize_operation("pop"));
    }

    #[test]
    fn registers_are_recognized_by_name_and_by_number() {
        for name in ["r0", "r13", "sp", "lr", "pc", "ip", "sl", "fp"] {
            assert!(Arm32.is_register(name), "{name} names a register");
        }
        for other in ["", "0x4", "[sp", "r", "rx", "$+0x8"] {
            assert!(!Arm32.is_register(other), "{other} does not name a register");
        }
    }

    #[test]
    fn the_stack_and_frame_pointers_are_told_apart_from_other_registers() {
        for name in ["sp", "fp", "r13", "r11"] {
            assert!(Arm32.is_stack_register(name));
        }
        assert!(!Arm32.is_stack_register("r0"));
        assert!(!Arm32.is_stack_register("lr"));
    }

    #[test]
    fn a_frame_reference_is_told_apart_from_another_memory_reference() {
        assert!(Arm32.mentions_stack_slot("r0, [sp, 0x4]"));
        assert!(Arm32.mentions_stack_slot("r0, [fp, -0x4]"));
        assert!(!Arm32.mentions_stack_slot("r0, [r1, 0x8]"));
    }

    #[test]
    fn a_constant_reads_in_hex_and_decimal_and_past_the_immediate_sigil() {
        assert_eq!(Arm32.constant_value("0x25"), Some(0x25));
        assert_eq!(Arm32.constant_value("37"), Some(37));
        assert_eq!(Arm32.constant_value("#4"), Some(4));
    }

    /// A register, a frame reference and a branch target are not constants,
    /// even though each holds digits.
    #[test]
    fn what_is_not_a_constant_reads_as_none() {
        for operand in ["r0", "[sp, 0x4]", "$+0x24", "", "lr"] {
            assert_eq!(Arm32.constant_value(operand), None, "{operand} is not a constant");
        }
    }

    #[test]
    fn frame_work_is_told_apart_from_real_work() {
        let push = decode_one([0x10, 0x40, 0x2d, 0xe9]);
        assert!(Arm32.is_frame_management(&push));

        let add = decode_one([0x00, 0x00, 0x81, 0xe0]);
        assert!(!Arm32.is_frame_management(&add), "arithmetic is the work itself");
    }

    /// A `pop` that loads the program counter returns, so it is not mere
    /// bookkeeping and must survive normalization.
    #[test]
    fn a_pop_that_returns_is_not_frame_work() {
        let pop_pc = decode_one([0x00, 0x88, 0xbd, 0xe8]);
        assert_eq!(pop_pc.kind, InsnKind::Return);
        assert!(!Arm32.is_frame_management(&pop_pc));
    }
}
