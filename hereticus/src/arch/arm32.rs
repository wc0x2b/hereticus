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
use yaxpeax_arm::armv7::{ConditionCode, InstDecoder, Instruction, Opcode, Operand, Reg};

use core::ops::Range;
use std::collections::BTreeSet;

use super::{Arch, DataAmongCode, DecodeError, Insn, InsnKind, JumpTable, Memory};
use crate::address::{AddressSpace, ConstantKind, Contents};

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

/// Register number of the stack pointer.
const REG_SP: u16 = 13;

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
            if let Some((mnemonic, operands)) = decode_fallback(word) {
                return Ok(Insn {
                    address: insn_address,
                    bytes_len: INSN_WIDTH,
                    mnemonic,
                    operands,
                    kind: InsnKind::Normal,
                });
            }
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
        track_pool_words(code, body, space).kinds
    }

    /// The addresses [`Arch::constant_kinds`] finds formed, and the pool
    /// words that hold an address whole, as non-PIC code keeps them.
    fn data_addresses(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        _memory: &Memory<'_>,
    ) -> Vec<u64> {
        track_pool_words(code, body, space).addresses
    }

    /// `bx` through a register other than `lr`. A `switch` jumps with `add pc`
    /// or `ldr pc` instead.
    fn is_tail_call(&self, insn: &Insn) -> bool {
        insn.mnemonic == "bx" && insn.kind == (InsnKind::Jump { target: None })
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

    /// Almost every ARM instruction runs always: its top four bits are
    /// `0xE`, or `0xF` for the few with no condition. Data has no such
    /// bias. Measured on zlib, Lua and tinyxml2 for ARM, at least 40% of the
    /// words of every function of 16 words or more are such, and 65% for all
    /// but one in twenty. Their symbol tables, strings, `.rodata`, relocations
    /// and unwind tables reach at most 6%. So a quarter is the line.
    ///
    /// Below 16 words a function is not judged: a stub can look like
    /// anything.
    fn contents(&self, code: &[u8], _insns: &[Insn], _space: &AddressSpace) -> Contents {
        const FEWEST_WORDS: usize = 16;

        let words: Vec<u32> = code
            .chunks_exact(INSN_WIDTH)
            .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
            .collect();
        if words.len() < FEWEST_WORDS {
            return Contents::Code;
        }
        let always = words.iter().filter(|&&word| word >> 28 >= 0xe).count();
        if always * 4 < words.len() { Contents::Data } else { Contents::Code }
    }

    /// A function opens unconditionally: nothing has set the flags a
    /// condition would test. Words of a pool mostly decode as conditional
    /// instructions, `0x00000000` as `andeq`. Measured on `factorial` in the
    /// `-O2` fixture, the constants `vld1` loads after the return otherwise
    /// started a function.
    fn may_open_function(&self, word: &[u8]) -> bool {
        word.get(3).is_some_and(|&top| top >= 0xe0)
    }

    fn before_pc_reference<'a>(&self, operands: &'a str) -> Option<&'a str> {
        operands.split_once("[pc").map(|(before, _)| before.trim_end_matches([',', ' ']))
    }

    fn data_among_code(&self) -> DataAmongCode {
        DataAmongCode::LiteralPools
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
                "vldr" if insn.operands.starts_with('s') => 1,
                "ldrd" | "vldr" => 2,
                _ => continue,
            };
            let Some((_, reference)) = insn.operands.rsplit_once('[') else { continue };
            let Some(("pc", Offset::Immediate(offset))) = parse_reference(&format!("[{reference}"))
            else {
                continue;
            };
            let pool = insn.address.wrapping_add(PC_AHEAD).wrapping_add(offset as u64);
            words.extend((0..count).map(|word| pool.wrapping_add(word * INSN_WIDTH as u64)));
        }
        words
    }

    /// The table GCC emits for a `switch` in PIC code:
    ///
    /// ```text
    /// adr  r1, table             ; r1 = the address of the table
    /// ldr  r0, [r1, r0, lsl 2]   ; an offset from the table to one case
    /// add  pc, r1, r0
    /// ```
    ///
    /// The cases follow the table, so it ends where the first case starts.
    fn jump_tables(&self, memory: &Memory<'_>, code: Range<u64>, insns: &[Insn]) -> Vec<JumpTable> {
        insns
            .iter()
            .enumerate()
            .filter_map(|(index, jump)| read_jump_table(memory, &code, &insns[..index], jump))
            .collect()
    }

    /// The stub LLD and GNU `ld` write for each PLT entry:
    ///
    /// ```text
    /// add ip, pc, imm        ; the decoder writes `adr ip, pc, imm`
    /// add ip, ip, imm
    /// ldr pc, [ip, imm]!
    /// ```
    ///
    /// The slot is the sum, from `pc`, which reads two words ahead.
    fn stub_slot(&self, code: &[u8], address: u64) -> Option<u64> {
        const PC_AHEAD: u64 = 8;

        let (insns, _) = super::decode_all(self, code.get(..3 * INSN_WIDTH)?, address);
        let [first, second, third] = insns.as_slice() else { return None };
        let high = parse_hex(first.operands.strip_prefix("ip, pc, ")?)?;
        let middle = parse_hex(second.operands.strip_prefix("ip, ip, ")?)?;
        let low = parse_hex(third.operands.strip_prefix("pc, [ip, ")?.strip_suffix("]!")?)?;
        let shape = first.mnemonic == "adr" && second.mnemonic == "add" && third.mnemonic == "ldr";
        shape.then(|| address + PC_AHEAD + high + middle + low)
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

/// Read the table behind `add pc, rB, rX`, where `earlier` holds the
/// instructions before the jump.
fn read_jump_table(
    memory: &Memory<'_>,
    code: &Range<u64>,
    earlier: &[Insn],
    jump: &Insn,
) -> Option<JumpTable> {
    /// How far back the load of the table and its address may be. GCC puts
    /// them right before the jump, but can move other work between.
    const LOOK_BACK: usize = 16;
    /// More cases than any `switch` a compiler turns into one table.
    const MOST_CASES: usize = 1024;

    if let Some(table) = read_branch_table(memory, code, jump) {
        return Some(table);
    }
    if let Some(table) = read_offset_table(memory, code, earlier, jump) {
        return Some(table);
    }
    if jump.mnemonic != "add" || jump.kind != (InsnKind::Jump { target: None }) {
        return None;
    }
    let mut operands = jump.operands.split(',').map(str::trim);
    let (Some("pc"), Some(table_register), Some(offset_register), None) =
        (operands.next(), operands.next(), operands.next(), operands.next())
    else {
        return None;
    };

    // The last instruction to write a register, or `None` past the window.
    let last_write = |register: &str| {
        earlier
            .iter()
            .rev()
            .take(LOOK_BACK)
            .find(|insn| insn.operands.split(',').next().map(str::trim) == Some(register))
    };

    // `ldr rX, [rB, rI, lsl 2]`: one word of the table.
    let load = last_write(offset_register)?;
    let expected = format!("{offset_register}, [{table_register}, ");
    if load.mnemonic != "ldr"
        || !load.operands.starts_with(&expected)
        || !load.operands.ends_with(", lsl 2]")
    {
        return None;
    }

    // `adr rB, pc, imm`: the address of the table.
    let address = last_write(table_register)?;
    let immediate = address.operands.strip_prefix(&format!("{table_register}, pc, "))?;
    if address.mnemonic != "adr" {
        return None;
    }
    let table = address.address.checked_add(8)?.checked_add(parse_hex(immediate)?)?;

    let (base, end) = (code.start, code.end);
    let mut targets = Vec::new();
    let mut first_case = end;
    let mut word = table;
    while word < first_case && targets.len() < MOST_CASES {
        // The end of the section ends the table.
        let Some(bytes) = memory.bytes(word, INSN_WIDTH) else { break };
        let delta = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let target = table.checked_add_signed(i64::from(delta))?;
        // A case lies inside the code, on a whole word, and outside the
        // table. It can lie before the table: GCC sends a case with no code
        // of its own back to the shared exit before the jump.
        let in_table = (table..word + INSN_WIDTH as u64).contains(&target);
        if in_table || target < base || target >= end || !target.is_multiple_of(INSN_WIDTH as u64) {
            break;
        }
        if target > word {
            first_case = first_case.min(target);
        }
        targets.push(target);
        word += INSN_WIDTH as u64;
    }

    (!targets.is_empty()).then_some(JumpTable { jump: jump.address, words: table..word, targets })
}

/// Read the table GCC emits for a `switch`: the jump adds the case number,
/// times four, to `pc`, which reads two words ahead, so it lands on one of
/// the `b` instructions that follow it.
///
/// ```text
/// cmp    r3, 5
/// addls  pc, pc, r3, lsl 2
/// b      default
/// b      case_0
/// b      case_1
/// ```
///
/// The table is code, so it names no data words.
fn read_branch_table(memory: &Memory<'_>, code: &Range<u64>, jump: &Insn) -> Option<JumpTable> {
    /// More cases than any `switch` a compiler turns into one table.
    const MOST_CASES: usize = 1024;

    let is_jump =
        matches!(jump.kind, InsnKind::Jump { target: None } | InsnKind::Branch { target: None });
    let operation = Arm32.normalize_operation(&jump.mnemonic);
    let shape = jump.operands.starts_with("pc, pc, ") && jump.operands.ends_with(", lsl 2");
    if operation != "add" || !is_jump || !shape {
        return None;
    }

    let mut targets = Vec::new();
    let mut entry = jump.address + INSN_WIDTH as u64;
    while targets.len() < MOST_CASES && code.contains(&entry) {
        let Some(bytes) = memory.bytes(entry, INSN_WIDTH) else { break };
        let Ok(insn) = Arm32.decode(bytes, 0, entry) else { break };
        match insn.kind {
            InsnKind::Jump { target: Some(target) } if code.contains(&target) => {
                targets.push(target)
            }
            _ => break,
        }
        entry += INSN_WIDTH as u64;
    }

    (!targets.is_empty()).then_some(JumpTable { jump: jump.address, words: entry..entry, targets })
}

/// Read the compressed table GCC emits for a `switch`: each case is a byte,
/// or a halfword, that says how many words past the jump it starts.
///
/// ```text
/// ldr    ip, [pc, imm]     ; the table, from here
/// add    ip, pc, ip
/// cmp    r3, 3             ; four cases
/// bhi    default
/// ldrb   r3, [ip, r3]
/// add    pc, pc, r3, lsl 2
/// ```
///
/// Measured on Lua built by GCC for ARM, `luaK_storevar` jumps this way, and
/// its cases after the first return read as functions of their own.
fn read_offset_table(
    memory: &Memory<'_>,
    code: &Range<u64>,
    earlier: &[Insn],
    jump: &Insn,
) -> Option<JumpTable> {
    const LOOK_BACK: usize = 16;
    /// How far back the table's address may be made. A `switch` in a loop
    /// has it made once, before the loop: Lua's `sweeplist` for ARM makes it
    /// 24 instructions before the jump.
    const TABLE_LOOK_BACK: usize = 128;
    const PC_AHEAD: u64 = 8;

    let is_jump =
        matches!(jump.kind, InsnKind::Jump { target: None } | InsnKind::Branch { target: None });
    if Arm32.normalize_operation(&jump.mnemonic) != "add" || !is_jump {
        return None;
    }
    let offset_register = jump.operands.strip_prefix("pc, pc, ")?.strip_suffix(", lsl 2")?;

    let window = || earlier.iter().rev().take(LOOK_BACK);
    // A compare names `r0` first but writes nothing, so it is no write.
    let writes = |insn: &Insn, register: &str| {
        writes_first_operand(&Arm32.normalize_operation(&insn.mnemonic))
            && insn.operands.split(',').next().map(str::trim) == Some(register)
    };
    let last_write = |register: &str| window().find(|insn| writes(insn, register));

    // `ldrb rX, [rB, rI]`: one entry of the table.
    let load = last_write(offset_register)?;
    let width = match Arm32.normalize_operation(&load.mnemonic).as_str() {
        "ldrb" => 1,
        "ldrh" => 2,
        _ => return None,
    };
    let (_, reference) = load.operands.split_once(',')?;
    let (table_register, Offset::Register(index_register)) = parse_reference(reference.trim())?
    else {
        return None;
    };

    // The table's address: `ldr rB, [pc, imm]` then `add rB, pc, rB`.
    // It is made before the load, which can write the same register, as
    // `ldrb lr, [lr, r1]` in Lua's `intarith` for ARM does.
    let add = earlier
        .iter()
        .rev()
        .skip_while(|insn| insn.address >= load.address)
        .take(TABLE_LOOK_BACK)
        .find(|insn| writes(insn, table_register))?;
    let expected = format!("{table_register}, pc, {table_register}");
    if Arm32.normalize_operation(&add.mnemonic) != "add" || add.operands != expected {
        return None;
    }
    let pool_load = earlier
        .iter()
        .rev()
        .skip_while(|insn| insn.address >= add.address)
        .take(LOOK_BACK)
        .find(|insn| writes(insn, table_register))?;
    let (_, pool_reference) = pool_load.operands.split_once(',')?;
    let ("pc", Offset::Immediate(pool_offset)) = parse_reference(pool_reference.trim())? else {
        return None;
    };
    let pool = pool_load.address.checked_add(PC_AHEAD)?.checked_add_signed(pool_offset)?;
    let pool_word = memory.bytes(pool, INSN_WIDTH)?;
    let distance = u32::from_le_bytes([pool_word[0], pool_word[1], pool_word[2], pool_word[3]]);
    let table = (add.address + PC_AHEAD).wrapping_add(u64::from(distance)) & 0xffff_ffff;

    // `cmp rI, n` bounds the case number, so there are n + 1 cases. The
    // decoder writes it as `cmps r0, rI, n`, so the last two operands count.
    fn compared(insn: &Insn) -> Option<(&str, &str)> {
        let operands: Vec<&str> = insn.operands.split(',').map(str::trim).collect();
        match operands.as_slice() {
            [.., register, bound] => Some((*register, *bound)),
            _ => None,
        }
    }
    let (_, bound) = window()
        .filter(|insn| Arm32.normalize_operation(&insn.mnemonic) == "cmp")
        .filter_map(compared)
        .find(|&(register, _)| register == index_register)?;
    let last_case = parse_hex(bound)?;
    let cases = usize::try_from(last_case).ok()?.checked_add(1).filter(|&cases| cases <= 1024)?;

    let base = jump.address + PC_AHEAD;
    let mut targets = Vec::with_capacity(cases);
    for case in 0..cases {
        let bytes = memory.bytes(table + (case * width) as u64, width)?;
        let entry = if width == 1 {
            u64::from(bytes[0])
        } else {
            u64::from(u16::from_le_bytes([bytes[0], bytes[1]]))
        };
        let target = base + entry * INSN_WIDTH as u64;
        if !code.contains(&target) {
            return None;
        }
        targets.push(target);
    }
    let words = table..table + (cases * width) as u64;
    Some(JumpTable { jump: jump.address, words, targets })
}

/// Read a hexadecimal immediate as the decoder prints it, such as `0x4`.
fn parse_hex(text: &str) -> Option<u64> {
    u64::from_str_radix(text.strip_prefix("0x")?, 16).ok()
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
    // `[rX]` is an offset of zero.
    let Some((base, offset)) = inner.split_once(',') else {
        return Some((inner.trim(), Offset::Immediate(0)));
    };
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

/// Read the words `yaxpeax` refuses that this crate knows: the hints, and
/// the VFP loads and stores.
///
/// A VFP load reads a constant pool as `ldr` does, so a scan must see it to
/// know the pool is data. Measured on tinyxml2 built by GCC for ARM,
/// `vldr d16, [pc, 0x90]` did not decode, its offset changed whenever an
/// alignment `nop` moved the pool, and that read as an edit.
fn decode_fallback(word: u32) -> Option<(String, String)> {
    const CONDITIONS: [&str; 15] =
        ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", ""];
    const REGISTERS: [&str; 16] = [
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "sb", "sl", "fp", "ip", "sp", "lr",
        "pc",
    ];

    let condition = *CONDITIONS.get((word >> 28) as usize)?;

    // The hints: `nop`, `yield`, `wfe`, `wfi` and `sev`.
    if word & 0x0fff_ff00 == 0x0320_f000 {
        let hint = ["nop", "yield", "wfe", "wfi", "sev"].get((word & 0xff) as usize)?;
        return Some((format!("{hint}{condition}"), String::new()));
    }

    // `vldr` and `vstr`: 1101 U D 0 L Rn Vd 101 sz imm8.
    if word >> 24 & 0xf == 0b1101 && word >> 21 & 1 == 0 && word >> 9 & 0b111 == 0b101 {
        let load = word >> 20 & 1 == 1;
        let up = word >> 23 & 1 == 1;
        let (d, vd) = (word >> 22 & 1, word >> 12 & 0xf);
        let register = if word >> 8 & 1 == 1 {
            format!("d{}", d << 4 | vd)
        } else {
            format!("s{}", vd << 1 | d)
        };
        let base = REGISTERS[(word >> 16 & 0xf) as usize];
        let offset = (word & 0xff) * 4;
        let reference = match (offset, up) {
            (0, _) => format!("[{base}]"),
            (_, true) => format!("[{base}, {offset:#x}]"),
            (_, false) => format!("[{base}, -{offset:#x}]"),
        };
        let operation = if load { "vldr" } else { "vstr" };
        return Some((format!("{operation}{condition}"), format!("{register}, {reference}")));
    }
    None
}

/// Read `rA, rB`, the two sources of a three-register operation.
fn parse_three(text: &str) -> Option<(&str, &str)> {
    let (left, right) = text.split_once(',')?;
    let right = right.trim();
    (!right.contains(',')).then(|| (left.trim(), right))
}

/// What reading a function for its pool words found.
struct PoolWords {
    /// See [`Arch::constant_kinds`].
    kinds: Vec<ConstantKind>,
    /// The addresses inside the image the function forms or loads whole.
    addresses: Vec<u64>,
}

/// Read `body` for the pool words that make addresses. See
/// [`Arm32::constant_kinds`].
fn track_pool_words(code: &[u8], body: &[Insn], space: &AddressSpace) -> PoolWords {
    /// `pc` reads two instructions ahead of the one that uses it.
    const PC_AHEAD: u64 = 8;

    let mut kinds = vec![ConstantKind::Value; body.len()];
    let mut addresses = Vec::new();
    // Pool words whose value lies in the image, by where they sit. PIC code
    // adds such a word to `pc`, and then the value is only a distance.
    let mut whole: Vec<(u64, u64)> = Vec::new();
    let mut distances: BTreeSet<u64> = BTreeSet::new();
    let Some(start) = body.first().map(|insn| insn.address) else {
        return PoolWords { kinds, addresses };
    };

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
        let operation = Arm32.normalize_operation(&insn.mnemonic);
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
            distances.insert(pool);
            if space.contains_formed(address) {
                addresses.push(address);
                if let Ok(index) = body.binary_search_by_key(&pool, |insn| insn.address) {
                    kinds[index] = ConstantKind::StoredAddress;
                }
            }
            address
        };

        match (operation.as_str(), parse_reference(rest), parse_three(rest)) {
            // `ldr rX, [pc, imm]`: load a pool word.
            ("ldr", Some(("pc", Offset::Immediate(offset))), _) => {
                let pool = pc.wrapping_add(offset as u64);
                forget(&mut literal, &mut relative, destination);
                if let Some(value) = word_at(pool) {
                    if space.contains(u64::from(value)) {
                        whole.push((pool, u64::from(value)));
                    }
                    literal.push((destination, pool, value));
                }
                continue;
            }
            // `mov rY, rX`: a copy holds what its source holds. GCC
            // copies the address of the global offset table so before it
            // reads a slot through it.
            ("mov", _, _) if !rest.contains(',') => {
                let copied_address = base_of(rest).filter(|_| rest != "pc");
                let copied_word = literal_of(rest);
                forget(&mut literal, &mut relative, destination);
                if let Some(address) = copied_address {
                    relative.push((destination, address));
                }
                if let Some((pool, value)) = copied_word {
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
                let joined =
                    match (base_of(left), literal_of(right), base_of(right), literal_of(left)) {
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

    addresses.extend(
        whole.into_iter().filter(|(pool, _)| !distances.contains(pool)).map(|(_, value)| value),
    );
    PoolWords { kinds, addresses }
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

        // `bx lr` returns; `bx <other>` is an indirect jump. A conditional
        // one falls through when its condition fails, as `bxeq lr` does in
        // an early exit, so it is a branch and does not end the function.
        Opcode::BX if !unconditional => InsnKind::Branch { target: None },
        Opcode::BX => match inst.operands[0] {
            Operand::Reg(reg) if reg.number() as u16 == REG_LR => InsnKind::Return,
            _ => InsnKind::Jump { target: None },
        },

        Opcode::B => {
            let target = branch_target(inst, address);
            if unconditional { InsnKind::Jump { target } } else { InsnKind::Branch { target } }
        }

        // Anything that writes the PC leaves the current block.
        _ if writes_pc(inst) => match (unconditional, returns(inst)) {
            (false, _) => InsnKind::Branch { target: None },
            (true, true) => InsnKind::Return,
            (true, false) => InsnKind::Jump { target: None },
        },

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

/// Report whether a write of the program counter returns: it takes the PC
/// from the stack, as `pop {..., pc}` does, or from the link register.
///
/// Any other write is a computed jump. `add pc, r3, r2` jumps through a
/// table of cases, and the code after it is more of the same function.
fn returns(inst: &Instruction) -> bool {
    let is = |reg: &Reg, number: u16| reg.number() as u16 == number;
    let base_is_sp = |operand: &Operand| match operand {
        Operand::Reg(reg) | Operand::RegWBack(reg, _) | Operand::RegDeref(reg) => is(reg, REG_SP),
        Operand::RegDerefPostindexRegShift(reg, ..)
        | Operand::RegDerefPreindexRegShift(reg, ..)
        | Operand::RegDerefPostindexOffset(reg, ..)
        | Operand::RegDerefPreindexOffset(reg, ..)
        | Operand::RegDerefPostindexReg(reg, ..)
        | Operand::RegDerefPreindexReg(reg, ..) => is(reg, REG_SP),
        _ => false,
    };

    match inst.opcode {
        Opcode::POP => true,
        Opcode::LDM(..) => base_is_sp(&inst.operands[0]),
        Opcode::LDR => base_is_sp(&inst.operands[1]),
        Opcode::MOV => matches!(&inst.operands[1], Operand::Reg(reg) if is(reg, REG_LR)),
        _ => false,
    }
}

/// Report whether the instruction writes the program counter.
///
/// Only a destination counts. `add r1, pc, r1` reads the PC to form an
/// address, which PIC code does in every function that reaches a global, and
/// reading it as a write ended the function there.
fn writes_pc(inst: &Instruction) -> bool {
    let is_pc = |operand: &Operand| match operand {
        Operand::Reg(reg) | Operand::RegWBack(reg, _) => reg.number() as u16 == REG_PC,
        _ => false,
    };

    match inst.opcode {
        // A store or a comparison has no destination register.
        Opcode::CMP
        | Opcode::CMN
        | Opcode::TST
        | Opcode::TEQ
        | Opcode::PUSH
        | Opcode::STM(..)
        | Opcode::STR
        | Opcode::STRB
        | Opcode::STRH
        | Opcode::STRD
        | Opcode::STRT
        | Opcode::STRBT
        | Opcode::STRHT
        | Opcode::STREX
        | Opcode::STREXB
        | Opcode::STREXH
        | Opcode::STREXD => false,
        // `pop {..., pc}` carries the PC as a bit in a register-list mask.
        Opcode::LDM(..) | Opcode::POP => inst
            .operands
            .iter()
            .any(|operand| matches!(operand, Operand::RegList(mask) if mask & (1 << REG_PC) != 0)),
        _ => is_pc(&inst.operands[0]),
    }
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

    /// `add r1, pc, r1` reads the PC to form an address. It does not leave.
    #[test]
    fn reading_the_pc_is_not_a_return() {
        let add = decode_one(0xe08f_1001_u32.to_le_bytes());
        assert_eq!(add.to_string(), "add r1, pc, r1");
        assert_eq!(add.kind, InsnKind::Normal);
    }

    /// `str pc, [sp]` and `cmp pc, r0` name the PC, but do not write it.
    #[test]
    fn a_store_or_compare_of_the_pc_is_not_a_return() {
        assert_eq!(decode_one(0xe58d_f000_u32.to_le_bytes()).kind, InsnKind::Normal);
        assert_eq!(decode_one(0xe15f_0000_u32.to_le_bytes()).kind, InsnKind::Normal);
        assert_eq!(
            decode_one(0xe92d_c000_u32.to_le_bytes()).kind,
            InsnKind::Normal,
            "push lr and pc"
        );
    }

    /// `bx` through a register other than `lr` is a tail call. A write of the
    /// pc through a table is not.
    #[test]
    fn only_bx_is_a_tail_call() {
        assert!(Arm32.is_tail_call(&decode_one(0xe12f_ff13_u32.to_le_bytes())), "bx r3");
        assert!(!Arm32.is_tail_call(&decode_one(0xe12f_ff1e_u32.to_le_bytes())), "bx lr");
        assert!(!Arm32.is_tail_call(&decode_one(0xe08f_f100_u32.to_le_bytes())), "add pc");
    }

    /// `add pc, pc, r0, lsl 2` and `ldr pc, [r1, r0, lsl 2]` jump through a
    /// table. They leave the block, but not the function.
    #[test]
    fn a_computed_write_of_the_pc_is_a_jump() {
        assert_eq!(decode_one(0xe08f_f100_u32.to_le_bytes()).kind, InsnKind::Jump { target: None });
        assert_eq!(decode_one(0xe791_f100_u32.to_le_bytes()).kind, InsnKind::Jump { target: None });
        assert_eq!(
            decode_one(0xe1a0_f003_u32.to_le_bytes()).kind,
            InsnKind::Jump { target: None },
            "mov pc, r3"
        );
    }

    /// Code with a `switch` table as GCC emits it, at address 0: `adr`,
    /// `ldr`, `add pc`, then the table, then the cases.
    fn switch_code(entries: &[i32]) -> Vec<u8> {
        let mut words = vec![
            0xe28f_1004_u32, // 0x00 adr r1, pc, 0x4: the table is at 0x0c
            0xe791_0100,     // 0x04 ldr r0, [r1, r0, lsl 2]
            0xe081_f000,     // 0x08 add pc, r1, r0
        ];
        words.extend(entries.iter().map(|&entry| entry as u32));
        words.extend([0xe3a0_0001, 0xe12f_ff1e, 0xe3a0_0002, 0xe12f_ff1e]); // mov r0, n; bx lr
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn tables_of(code: &[u8]) -> Vec<JumpTable> {
        let (insns, _) = crate::arch::decode_all(&Arm32, code, 0);
        let regions = [(0, code)];
        Arm32.jump_tables(&Memory::new(&regions), 0..code.len() as u64, &insns)
    }

    /// Each entry is an offset from the table, and the cases follow it.
    #[test]
    fn reads_a_switch_table() {
        // Two entries end at 0x14, where the first case starts.
        let code = switch_code(&[0x08, 0x10]);
        assert_eq!(
            tables_of(&code),
            [JumpTable { jump: 0x08, words: 0x0c..0x14, targets: vec![0x14, 0x1c] }]
        );
    }

    /// A case can lead back before the table, to a shared exit.
    #[test]
    fn a_case_can_lie_before_the_table() {
        // Three entries end at 0x18, and the second leads back to 0x00.
        let code = switch_code(&[0x0c, -0x0c, 0x10]);
        assert_eq!(tables_of(&code)[0].targets, [0x18, 0x00, 0x1c]);
    }

    /// An entry that points into the table, or past the code, ends it.
    #[test]
    fn an_entry_that_is_no_case_ends_the_table() {
        assert_eq!(tables_of(&switch_code(&[0x10, 0x04]))[0].targets, [0x1c]);
        assert_eq!(tables_of(&switch_code(&[0x10, 0x1000]))[0].targets, [0x1c]);
        assert_eq!(tables_of(&switch_code(&[0x11]))[..], [], "not on a whole word");
    }

    /// GCC's table is a run of `b` after `add pc, pc, rX, lsl 2`.
    #[test]
    fn reads_a_table_of_branches() {
        let words = [
            0xe353_0002_u32, // 0x00 cmp r3, 2
            0x908f_f103,     // 0x04 addls pc, pc, r3, lsl 2
            0xea00_0003,     // 0x08 b 0x1c: the default
            0xea00_0002,     // 0x0c b 0x1c
            0xea00_0002,     // 0x10 b 0x20
            0xea00_0002,     // 0x14 b 0x24
            0xe12f_ff1e,     // 0x18 bx lr
            0xe3a0_0000,     // 0x1c mov r0, 0
            0xe3a0_0001,     // 0x20 mov r0, 1
            0xe3a0_0002,     // 0x24 mov r0, 2
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let tables = tables_of(&code);
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].jump, 0x04);
        assert_eq!(tables[0].targets, [0x1c, 0x1c, 0x20, 0x24]);
        assert!(tables[0].words.is_empty(), "the table is code");
    }

    /// GCC's compressed table: a byte for each case, in `.rodata`.
    #[test]
    fn reads_a_table_of_byte_offsets() {
        let words = [
            0xe59f_c010_u32, // 0x00 ldr ip, [pc, 0x10]: the word at 0x18
            0xe08f_c00c,     // 0x04 add ip, pc, ip: ip = 0x0c + 0x14 = 0x20
            0xe353_0002,     // 0x08 cmp r3, 2
            0xe7dc_3003,     // 0x0c ldrb r3, [ip, r3]
            0xe08f_f103,     // 0x10 add pc, pc, r3, lsl 2
            0xe12f_ff1e,     // 0x14 bx lr
            0x0000_0014,     // 0x18 the distance to the table
            0xe12f_ff1e,     // 0x1c bx lr
            0x0001_0100,     // 0x20 the table: cases at +0, +1, +1 words
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let tables = tables_of(&code);
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].targets, [0x18, 0x1c, 0x1c]);
        assert_eq!(tables[0].words, 0x20..0x23);
    }

    /// Without the `adr` and the scaled `ldr`, the jump is not through a
    /// table this can read.
    #[test]
    fn a_computed_jump_without_its_table_is_left_alone() {
        let mut code = switch_code(&[0x08, 0x10]);
        code[..4].copy_from_slice(&0xe1a0_1000_u32.to_le_bytes()); // mov r1, r0
        assert!(tables_of(&code).is_empty());

        let mut code = switch_code(&[0x08, 0x10]);
        code[4..8].copy_from_slice(&0xe591_0000_u32.to_le_bytes()); // ldr r0, [r1]
        assert!(tables_of(&code).is_empty());
    }

    /// `vldr d16, [pc, 0x90]`, as GCC loads a double from its pool, and the
    /// hints `yaxpeax` leaves unread.
    #[test]
    fn reads_vfp_loads_and_hints() {
        let text = |word: u32| decode_one(word.to_le_bytes()).to_string();
        assert_eq!(text(0xeddf_0b24), "vldr d16, [pc, 0x90]");
        assert_eq!(text(0xed1f_0a01), "vldr s0, [pc, -0x4]");
        assert_eq!(text(0x0d8d_1b00), "vstreq d1, [sp]");
        assert_eq!(text(0xe320_f000), "nop");
        assert_eq!(text(0xe320_f003), "wfi");
        assert_eq!(decode_one(0xeddf_0b24_u32.to_le_bytes()).kind, InsnKind::Normal);
    }

    /// A pool a VFP load reads is data, one word for a single and two for a
    /// double.
    #[test]
    fn a_vfp_load_names_its_pool_words() {
        let words = [0xeddf_0b00_u32, 0xed9f_0a00]; // vldr d16, [pc]; vldr s0, [pc]
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0);
        assert_eq!(Arm32.literal_pool_words(&insns), [0x08, 0x0c, 0x0c]);
    }

    /// A double load just after address 0 reaches back past it, as
    /// random bytes read at base 0 can. The pool address wraps and does not
    /// overflow.
    #[test]
    fn a_pool_before_address_zero_wraps() {
        let code = 0xed5f_0b03_u32.to_le_bytes(); // vldr d16, [pc, -0xc]
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0);
        assert_eq!(Arm32.literal_pool_words(&insns), [u64::MAX - 3, 0]);
    }

    /// GCC copies the address of the global offset table with `mov` before
    /// it reads a slot through it. The pool word that holds the slot's
    /// offset is then chosen by the linker, as the address itself is.
    #[test]
    fn a_copied_table_address_marks_its_slot_offset() {
        let words = [
            0xe59f_c00c_u32, // 0x00 ldr ip, [pc, 0xc]: the word at 0x14
            0xe08f_c00c,     // 0x04 add ip, pc, ip: the table at 0x14 + 0xc
            0xe1a0_000c,     // 0x08 mov r0, ip
            0xe59f_c004,     // 0x0c ldr ip, [pc, 0x4]: the word at 0x18
            0xe790_000c,     // 0x10 ldr r0, [r0, ip]
            0x0000_0014,     // 0x14 the distance to the table
            0x0000_0008,     // 0x18 the slot's offset in the table
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        // Numbers below a page are never addresses, so the code sits higher.
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0x8000);
        let space = AddressSpace::of_raw_image(0x8000, 0x100);
        let kinds = Arm32.constant_kinds(&code, &insns, &space);
        assert_eq!(kinds[5], ConstantKind::StoredAddress, "the table's distance");
        assert_eq!(kinds[6], ConstantKind::StoredAddress, "the slot's offset");
    }

    /// `lld` puts the read-only data of a small library below the first
    /// page, and code reaches it by a negative distance from `pc`. Measured
    /// on a Rust library for ARM, the message a panic prints sat at 0xbc8.
    #[test]
    fn a_distance_to_low_data_marks_its_pool_word() {
        let words = [
            0xe59f_0000_u32,                // 0x10000 ldr r0, [pc]: the word at 0x10008
            0xe08f_0000,                    // 0x10004 add r0, pc, r0
            (0x0bc8_i32 - 0x1_000c) as u32, // 0x10008 the distance to 0xbc8
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0x1_0000);
        let space = AddressSpace::from_ranges([0x870..0xd40, 0x1_0000..0x1_0100]);
        let kinds = Arm32.constant_kinds(&code, &insns, &space);
        assert_eq!(kinds[2], ConstantKind::StoredAddress);
    }

    /// PIC code adds a pool word to `pc`, and other code keeps the whole
    /// address in the pool. Both are data the function points at.
    #[test]
    fn data_addresses_are_formed_or_loaded_whole() {
        let words = [
            0xe59f_0004_u32, // 0x8000 ldr r0, [pc, 0x4]: the word at 0x800c
            0xe08f_0000,     // 0x8004 add r0, pc, r0: 0x800c + 0x40
            0xe59f_1000,     // 0x8008 ldr r1, [pc]: the word at 0x8010
            0x0000_0040,     // 0x800c a distance
            0x0000_8080,     // 0x8010 an address
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0x8000);
        let space = AddressSpace::of_raw_image(0x8000, 0x100);
        let memory = Memory::new(&[]);
        assert_eq!(Arm32.data_addresses(&code, &insns, &space, &memory), [0x804c, 0x8080]);
        let outside = AddressSpace::of_raw_image(0x9000, 0x100);
        assert!(Arm32.data_addresses(&code, &insns, &outside, &memory).is_empty());
    }

    /// A pool word that `pc` is added to is a distance, even where its
    /// value happens to lie in the image as well.
    #[test]
    fn a_distance_is_no_whole_address() {
        let words = [
            0xe59f_0000_u32, // 0x8000 ldr r0, [pc]: the word at 0x8008
            0xe08f_0000,     // 0x8004 add r0, pc, r0: 0x8008 + 0x8040, outside
            0x0000_8040,     // 0x8008 a distance that reads as an address
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0x8000);
        let space = AddressSpace::of_raw_image(0x8000, 0x100);
        assert!(Arm32.data_addresses(&code, &insns, &space, &Memory::new(&[])).is_empty());
    }

    /// GCC for PIC reads a byte table in `.rodata` and adds it to `pc`. The
    /// table's address can be made long before the jump, before a loop, and
    /// the load can write the register that held it.
    #[test]
    fn reads_a_byte_table_whose_address_was_made_long_before() {
        let mut words = vec![
            0xe59f_e070_u32, // 0x1000 ldr lr, [pc, 0x70]: the word at 0x1078
            0xe08f_e00e,     // 0x1004 add lr, pc, lr: the table at 0x2000
        ];
        words.extend([0xe1a0_0000; 20]); // 0x1008 mov r0, r0, twenty times
        words.extend([
            0xe351_0002, // 0x1058 cmp r1, 2
            0x8a00_0003, // 0x105c bhi 0x1070
            0xe7de_e001, // 0x1060 ldrb lr, [lr, r1]
            0xe08f_f10e, // 0x1064 add pc, pc, lr, lsl 2
            0xe1a0_0000, // 0x1068 nop
            0xe12f_ff1e, // 0x106c case 0: bx lr
            0xe12f_ff1e, // 0x1070 case 1: bx lr
            0xe12f_ff1e, // 0x1074 case 2: bx lr
            0x0000_0ff4, // 0x1078 the distance from 0x100c to the table
        ]);
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0x1000);
        let table = [0_u8, 1, 2];
        let regions = [(0x1000, code.as_slice()), (0x2000, table.as_slice())];
        assert_eq!(
            Arm32.jump_tables(&Memory::new(&regions), 0x1000..0x107c, &insns),
            [JumpTable {
                jump: 0x1064,
                words: 0x2000..0x2003,
                targets: vec![0x106c, 0x1070, 0x1074]
            }]
        );
    }

    /// A compare prints `r0` first but writes nothing, so it does not hide
    /// where a table in `r0` was made.
    #[test]
    fn a_compare_does_not_hide_a_table_in_r0() {
        let words = [
            0xe59f_0020_u32, // 0x1000 ldr r0, [pc, 0x20]: the word at 0x1028
            0xe08f_0000,     // 0x1004 add r0, pc, r0: the table at 0x2000
            0xe351_0002,     // 0x1008 cmp r1, 2
            0x8a00_0004,     // 0x100c bhi 0x1024
            0xe7d0_1001,     // 0x1010 ldrb r1, [r0, r1]
            0xe08f_f101,     // 0x1014 add pc, pc, r1, lsl 2
            0xe1a0_0000,     // 0x1018 nop
            0xe12f_ff1e,     // 0x101c case 0: bx lr
            0xe12f_ff1e,     // 0x1020 case 1: bx lr
            0xe12f_ff1e,     // 0x1024 case 2: bx lr
            0x0000_0ff4,     // 0x1028 the distance from 0x100c to the table
        ];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0x1000);
        let table = [0_u8, 1, 2];
        let regions = [(0x1000, code.as_slice()), (0x2000, table.as_slice())];
        assert_eq!(
            Arm32.jump_tables(&Memory::new(&regions), 0x1000..0x102c, &insns),
            [JumpTable {
                jump: 0x1014,
                words: 0x2000..0x2003,
                targets: vec![0x101c, 0x1020, 0x1024]
            }]
        );
    }

    /// Code runs always; text and tables do not.
    #[test]
    fn tells_code_from_data() {
        let space = AddressSpace::none();
        let judge = |words: &[u32]| {
            let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0);
            Arm32.contents(&code, &insns, &space)
        };
        let code = [0xe92d_4010_u32, 0xe1a0_4000, 0x0a00_0002, 0xe594_0000, 0xe8bd_8010];
        let text = u32::from_le_bytes(*b"text");
        assert_eq!(judge(&code.repeat(4)), Contents::Code);
        assert_eq!(judge(&[text; 16]), Contents::Data);
        assert_eq!(judge(&[0x0000_0010; 16]), Contents::Data, "a table of small offsets");
        assert_eq!(judge(&[text; 15]), Contents::Code, "too short to judge");
    }

    /// The PLT stub of `StrPair::Reset` in tinyxml2 for ARM, as LLD wrote
    /// it, jumps through the slot at 0x3ea34.
    #[test]
    fn reads_the_slot_a_plt_stub_jumps_through() {
        let stub: Vec<u8> = [0xe28f_c600_u32, 0xe28c_ca20, 0xe5bc_fccc]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        assert_eq!(Arm32.stub_slot(&stub, 0x1dd60), Some(0x3ea34));
        assert_eq!(Arm32.stub_slot(&stub[..8], 0x1dd60), None, "too short");

        let mut other = stub.clone();
        other[8..].copy_from_slice(&0xe59c_f000_u32.to_le_bytes()); // ldr pc, [ip]
        assert_eq!(Arm32.stub_slot(&other, 0x1dd60), None);
    }

    /// `ldm sp!, {r4, pc}` returns, as `pop` does.
    #[test]
    fn a_load_multiple_from_the_stack_is_a_return() {
        assert_eq!(decode_one(0xe8bd_8010_u32.to_le_bytes()).kind, InsnKind::Return);
    }

    /// A conditional return falls through when the condition fails.
    #[test]
    fn a_conditional_bx_lr_is_a_branch() {
        assert_eq!(
            decode_one(0x012f_ff1e_u32.to_le_bytes()).kind,
            InsnKind::Branch { target: None }
        );
        assert_eq!(
            decode_one(0x012f_ff13_u32.to_le_bytes()).kind,
            InsnKind::Branch { target: None }
        ); // bxeq r3
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
    /// `Opcode::Invalid`. The fallback reads it as `nop`, which moves nothing.
    #[test]
    fn nop_encoding_decodes_as_nop() {
        let insn = decode_one([0x00, 0xf0, 0x20, 0xe3]);
        assert_eq!(insn.mnemonic, "nop");
        assert_eq!(insn.kind, InsnKind::Normal);
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

    /// The `nop` the linker pads with is padding, by its name now that the
    /// fallback reads it.
    #[test]
    fn the_nop_encoding_is_padding() {
        let nop = decode_one(NOP_BYTES);
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
