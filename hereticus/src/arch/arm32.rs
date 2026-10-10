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
use yaxpeax_arm::armv7::{
    ConditionCode, InstDecoder, Instruction, Opcode, Operand, Reg, RegShiftStyle, ShiftStyle,
};

use core::ops::Range;
use std::collections::BTreeSet;

use super::{Arch, DataAmongCode, DecodeError, Insn, InsnKind, JumpTable, Memory};
use crate::address::{AddressSpace, ConstantKind, Contents};
use crate::il;

/// Every A32 instruction is 4 bytes wide.
const INSN_WIDTH: usize = 4;

/// A pool word, or a pointer, is 4 bytes wide.
const WORD_WIDTH: usize = 4;

/// The section holding the ARM exception index.
///
/// One entry a function, each naming where that function starts. It survives
/// stripping, so it is the strongest source of function boundaries there is.
pub(super) const UNWIND_SECTION: &str = ".ARM.exidx";

/// The A32 `nop` encoding, little endian.
const NOP_BYTES: [u8; 4] = [0x00, 0xf0, 0x20, 0xe3];

/// Zero words, which some linkers pad with instead.
const ZERO_BYTES: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

/// Mnemonic reported for bytes the decoder cannot read.
///
/// `yaxpeax-arm` 0.4 has no NEON or SIMD support and answers "incomplete
/// decoder" for those encodings. `clang` vectorizes automatically at `-O2`,
/// so real code reaches this path.
pub(super) const UNKNOWN_MNEMONIC: &str = "(unknown)";

/// The mnemonic of a NEON data-processing instruction, which the decoder
/// cannot read either. It stays opaque, as an unreadable word does, but the
/// name says that it is code. See [`super::Arch::is_unread_extension`].
pub(super) const NEON_MNEMONIC: &str = "(neon)";

/// Register number of the program counter.
const REG_PC: u16 = 15;
/// Register number of the link register.
const REG_LR: u16 = 14;

/// Register number of the stack pointer.
const REG_SP: u16 = 13;

/// The frame pointer, as the A32 procedure call standard names it.
const FRAME: il::Reg = il::Reg::General(11);

/// What [`Insn::opcode`] holds for A32 and T32.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decoded {
    /// An integer instruction, by the opcode `yaxpeax-arm` names, whether it
    /// or this module reads the word. A store or a load of the stack that
    /// it prints as `push` or `pop` has that opcode.
    Core { opcode: Opcode, condition: ConditionCode, flags: Flags },
    /// `it`, which makes up to four instructions after it conditional: the
    /// condition of the first, and the mask that says the rest.
    It { condition: u8, mask: u8 },
    /// A VFP instruction this module reads, and its condition.
    Vfp { vfp: Vfp, condition: ConditionCode },
    /// A NEON load or store this module reads.
    NeonAccess,
    /// NEON data processing, which nothing here reads.
    NeonData,
}

/// Whether an instruction sets the flags, as the `s` of `adds` says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flags {
    Kept,
    Set,
}

impl Flags {
    pub(super) fn of(sets_flags: bool) -> Self {
        if sets_flags { Self::Set } else { Self::Kept }
    }
}

/// Which VFP instruction this module read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vfp {
    /// `vldr`.
    Load,
    /// `vstr`.
    Store,
    /// `vmov` between a core register and a single.
    Move,
    /// `vmov` between two core registers and a double.
    MoveDouble,
    /// `vmrs`, which moves the status register to a core register.
    Status,
    /// `vpush`.
    Push,
    /// `vpop`.
    Pop,
    /// `vldm` and `vstm`, which step through memory as `step` says.
    Multiple(Step),
    /// `vcmp` and `vcmpe`.
    Compare,
    /// The arithmetic, the conversions and `vmov` of a constant.
    Compute,
}

/// Which way a load or store of a list steps through memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// From the base up: `ia`.
    IncrementAfter,
    /// From below the base up to it: `db`.
    DecrementBefore,
}

/// The conditions of A32, by the top four bits of a word.
const CONDITION_CODES: [ConditionCode; 15] = [
    ConditionCode::EQ,
    ConditionCode::NE,
    ConditionCode::HS,
    ConditionCode::LO,
    ConditionCode::MI,
    ConditionCode::PL,
    ConditionCode::VS,
    ConditionCode::VC,
    ConditionCode::HI,
    ConditionCode::LS,
    ConditionCode::GE,
    ConditionCode::LT,
    ConditionCode::GT,
    ConditionCode::LE,
    ConditionCode::AL,
];

/// The condition the top four bits of an A32 `word` name, or `None` for the
/// words that have none.
pub(super) fn condition_of(word: u32) -> Option<ConditionCode> {
    CONDITION_CODES.get((word >> 28) as usize).copied()
}

/// What `inst` holds, as [`Insn::opcode`] keeps it.
pub(super) fn decoded_of(inst: &Instruction) -> Decoded {
    if inst.opcode == Opcode::IT
        && let [Operand::Imm32(condition), Operand::Imm32(mask), ..] = inst.operands
    {
        return Decoded::It { condition: condition as u8, mask: mask as u8 };
    }
    Decoded::Core {
        opcode: printed_opcode(inst),
        condition: inst.condition,
        flags: Flags::of(inst.s()),
    }
}

/// The opcode of `inst`, or `push` or `pop` where `yaxpeax-arm` 0.4 prints
/// it so: a store of one register before `sp` that moves `sp`, a load of
/// one after it, and a store or a load of a list on `sp` that moves it.
fn printed_opcode(inst: &Instruction) -> Opcode {
    let is_sp = |reg: Reg| u16::from(reg.number()) == REG_SP;
    match (inst.opcode, inst.operands) {
        (
            Opcode::LDR,
            [
                Operand::Reg(_),
                Operand::RegDerefPostindexOffset(base, 4, true, false),
                Operand::Nothing,
                Operand::Nothing,
            ],
        ) if is_sp(base) => Opcode::POP,
        (
            Opcode::STR,
            [
                Operand::Reg(_),
                Operand::RegDerefPreindexOffset(base, 4, false, true),
                Operand::Nothing,
                Operand::Nothing,
            ],
        ) if is_sp(base) => Opcode::PUSH,
        (
            Opcode::LDM(true, false, false, _),
            [
                Operand::RegWBack(base, true),
                Operand::RegList(_),
                Operand::Nothing,
                Operand::Nothing,
            ],
        ) if is_sp(base) => Opcode::POP,
        (
            Opcode::STM(false, true, false, _),
            [
                Operand::RegWBack(base, true),
                Operand::RegList(_),
                Operand::Nothing,
                Operand::Nothing,
            ],
        ) if is_sp(base) => Opcode::PUSH,
        (opcode, _) => opcode,
    }
}

/// What the decoder read for `insn`, where it read A32 or T32.
pub(crate) fn decoded(insn: &Insn) -> Option<Decoded> {
    match insn.opcode {
        super::Opcode::Arm(decoded) => Some(decoded),
        _ => None,
    }
}

/// The condition `insn` runs on, where it names one.
pub(crate) fn condition(insn: &Insn) -> Option<ConditionCode> {
    match decoded(insn)? {
        Decoded::Core { condition, .. } | Decoded::Vfp { condition, .. } => Some(condition),
        _ => None,
    }
}

/// The suffix a mnemonic takes for `condition`.
pub(crate) fn condition_name(condition: ConditionCode) -> &'static str {
    match condition {
        ConditionCode::EQ => "eq",
        ConditionCode::NE => "ne",
        ConditionCode::HS => "hs",
        ConditionCode::LO => "lo",
        ConditionCode::MI => "mi",
        ConditionCode::PL => "pl",
        ConditionCode::VS => "vs",
        ConditionCode::VC => "vc",
        ConditionCode::HI => "hi",
        ConditionCode::LS => "ls",
        ConditionCode::GE => "ge",
        ConditionCode::LT => "lt",
        ConditionCode::GT => "gt",
        ConditionCode::LE => "le",
        ConditionCode::AL => "",
    }
}

/// The integer operation `insn` does, whatever its condition and flags.
pub(crate) fn core_opcode(insn: &Insn) -> Option<Opcode> {
    match decoded(insn)? {
        Decoded::Core { opcode, .. } => Some(opcode),
        _ => None,
    }
}

/// Whether `insn` does `opcode` always and keeps the flags: the form its
/// plain mnemonic names, as `add` and not `addeq` or `adds`.
pub(super) fn is_plain(insn: &Insn, opcode: Opcode) -> bool {
    decoded(insn)
        == Some(Decoded::Core { opcode, condition: ConditionCode::AL, flags: Flags::Kept })
}

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
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let failed = InstDecoder::default().decode_into(&mut inst, &mut reader).is_err();
        if failed || inst.opcode == Opcode::Invalid || decoder_misreads(word, Encoding::A32) {
            // A32 instructions are all 4 bytes, so stepping over an
            // unreadable word keeps everything after it aligned. Reporting an
            // error instead would throw away the rest of the function.
            //
            // The raw word goes in the operand field. Without it every
            // unreadable instruction would look like every other one, and an
            // edit inside a NEON loop would be reported as no change at all.
            if let Some((mnemonic, operands, decoded)) = decode_fallback(word, Encoding::A32) {
                return Ok(Insn {
                    address: insn_address,
                    bytes_len: INSN_WIDTH,
                    mnemonic,
                    operands,
                    kind: InsnKind::Normal,
                    opcode: super::Opcode::Arm(decoded),
                });
            }
            return Ok(Insn {
                address: insn_address,
                bytes_len: INSN_WIDTH,
                mnemonic: unread_mnemonic(word).to_string(),
                operands: format!("{word:#010x}"),
                kind: InsnKind::Unknown,
                opcode: unread_opcode(word),
            });
        }

        // `total_offset` is in words; convert so the assertion below compares
        // like with like.
        let words = <U8Reader<'_> as Reader<u32, U32le>>::total_offset(&mut reader);
        let consumed = words as usize * INSN_WIDTH;
        debug_assert_eq!(consumed, INSN_WIDTH, "A32 instructions are always 4 bytes");

        let text = inst.to_string();
        let (mnemonic, operands) = split_mnemonic(&text);
        let (mnemonic, operands) = without_unused_operand(mnemonic, operands);
        let mnemonic = with_list_order(&inst.opcode, mnemonic);

        Ok(Insn {
            address: insn_address,
            bytes_len: INSN_WIDTH,
            mnemonic,
            operands,
            kind: classify(&inst, branch_target(&inst, insn_address)),
            opcode: super::Opcode::Arm(decoded_of(&inst)),
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

    fn is_frame_register(&self, reg: il::Reg) -> bool {
        matches!(reg, il::Reg::Stack | FRAME)
    }

    /// The first instruction of a function runs always, as almost every
    /// A32 instruction does: its top four bits are `0xE`.
    fn can_open_function(&self, bytes: &[u8]) -> bool {
        bytes.get(..INSN_WIDTH).is_some_and(|word| word[3] >> 4 == 0xe)
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
        let Some(opcode) = core_opcode(insn) else { return false };
        let operands = insn.operands.as_str();
        let first = operands.split(',').next().unwrap_or_default();

        match opcode {
            // Saving and restoring registers. A `pop` that loads the program
            // counter also returns, so it must stay.
            Opcode::PUSH => true,
            Opcode::POP => insn.kind != InsnKind::Return,

            // Moving the stack pointer, or setting up the frame pointer.
            Opcode::SUB | Opcode::ADD | Opcode::MOV => self.is_stack_register(first),

            // Spilling to and reloading from the frame, by `ldr`, `str`,
            // `ldm` and `stm`, which go up from the base.
            Opcode::LDR
            | Opcode::STR
            | Opcode::LDM(true, false, ..)
            | Opcode::STM(true, false, ..) => self.mentions_stack_slot(operands),

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
        matches!(core_opcode(insn), Some(Opcode::PUSH | Opcode::STM(..)))
            && insn.operands.contains("lr")
    }

    /// `yaxpeax-arm` 0.4 does not decode the usual ARM `nop` encoding
    /// `0xe320f000` and reports it as unreadable, so the raw word is checked
    /// as well as the name. A core before ARMv6K has no such hint, so GCC
    /// pads with `mov r0, r0` there.
    fn is_padding(&self, insn: &Insn) -> bool {
        /// The A32 hint encoding that means "no operation", as printed.
        const NOP: &str = "0xe320f000";
        /// Zero words, which some linkers use to pad instead.
        const ZERO: &str = "0x00000000";

        core_opcode(insn) == Some(Opcode::NOP)
            || (is_plain(insn, Opcode::MOV) && insn.operands == "r0, r0")
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
        track_pool_words(code, body, space, PcModel::A32).kinds
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
        track_pool_words(code, body, space, PcModel::A32).addresses
    }

    fn formed_addresses(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        _memory: &Memory<'_>,
    ) -> Vec<Option<u64>> {
        track_pool_words(code, body, space, PcModel::A32).formed
    }

    /// `bx` through a register other than `lr`. A `switch` jumps with `add pc`
    /// or `ldr pc` instead.
    fn is_tail_call(&self, insn: &Insn) -> bool {
        is_plain(insn, Opcode::BX) && insn.kind == (InsnKind::Jump { target: None })
    }

    /// A variadic function reserves room for its register arguments before it
    /// saves anything, so `sub sp, sp, #N` opens it one word before the
    /// `push`. Measured on Lua built as an ARM shared library: without this,
    /// `lua_pushfstring`, `luaG_runerror` and `luaO_pushfstring` each left a
    /// one-word fragment that no release could pair.
    fn preamble_before_prologue(&self, earlier: &[Insn]) -> usize {
        let Some(last) = earlier.last() else { return 0 };
        let reserves_stack =
            core_opcode(last) == Some(Opcode::SUB) && last.operands.starts_with("sp, sp, ");
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
            .as_chunks::<INSN_WIDTH>()
            .0
            .iter()
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
        pool_words_loaded(insns, PcModel::A32)
    }

    fn is_unread_extension(&self, insn: &Insn) -> bool {
        decoded(insn) == Some(Decoded::NeonData)
    }

    /// See [`is_long_thunk`].
    fn is_function_entry(&self, body: &[Insn]) -> bool {
        is_long_thunk(body)
    }

    fn call_targets(&self, insns: &[Insn]) -> Vec<(usize, Option<super::CallTarget>)> {
        call_targets_through_thunks(insns, PcModel::A32)
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

        // The scan asks at the target of every jump, so a first word that is
        // no `adr` ends the question before the rest decode.
        if !is_plain(&self.decode(code, 0, address).ok()?, Opcode::ADR) {
            return None;
        }
        let (insns, _) = super::decode_all(self, code.get(..3 * INSN_WIDTH)?, address);
        let [first, second, third] = insns.as_slice() else { return None };
        let high = parse_hex(first.operands.strip_prefix("ip, pc, ")?)?;
        let middle = parse_hex(second.operands.strip_prefix("ip, ip, ")?)?;
        let low = parse_hex(third.operands.strip_prefix("pc, [ip, ")?.strip_suffix("]!")?)?;
        let shape = is_plain(first, Opcode::ADR)
            && is_plain(second, Opcode::ADD)
            && is_plain(third, Opcode::LDR);
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

    fn lift(&self, insn: &Insn, word: &[u8]) -> Option<il::Lifted> {
        let a32 = word.try_into().ok().map(u32::from_le_bytes);
        lift_with(InstDecoder::default(), insn, word, a32.map(|a32| (a32, Encoding::A32)))
    }
}

/// Decode `word` again with `decoder` and lift it. A word the decoder
/// refuses, or reads only through the fallback, lifts to nothing.
///
/// A word the decoder refuses lifts from `fallback`, its A32 form and the
/// encoding it came in, where [`lift_fallback`] reads it.
pub(super) fn lift_with(
    decoder: InstDecoder,
    insn: &Insn,
    word: &[u8],
    fallback: Option<(u32, Encoding)>,
) -> Option<il::Lifted> {
    if insn.kind == InsnKind::Unknown {
        return None;
    }
    let mut inst = Instruction::default();
    let decoded = decoder.decode_into(&mut inst, &mut U8Reader::new(word)).is_ok();
    let misread = fallback.is_some_and(|(a32, encoding)| decoder_misreads(a32, encoding));
    if decoded && inst.opcode != Opcode::Invalid && !misread {
        Some(lift(&inst))
    } else {
        let (a32, encoding) = fallback?;
        lift_fallback(a32, encoding)
    }
}

/// What an ARM instruction does with its first operands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// Writes its first `count` operands from the others, as `add` writes
    /// one and `umull` two.
    Compute { count: usize },
    /// Reads every operand and writes none, as `str`, `cmp` and `b` do.
    ReadOnly,
    /// Loads its first `count` operands, or the registers of its list.
    Load { count: usize },
    /// An exclusive store, which writes its status to the first operand.
    StoreExclusive,
}

/// Lift one decoded A32 or T32 instruction.
fn lift(inst: &Instruction) -> il::Lifted {
    let mut operands: Vec<Operand> =
        inst.operands.iter().copied().take_while(|operand| *operand != Operand::Nothing).collect();
    // `yaxpeax` gives an A32 compare the unused destination field first, as
    // in `cmps r0, r0, 0x1`. T32 gives only the two values.
    if is_compare(inst.opcode) && operands.len() == 3 {
        operands.remove(0);
    }
    // It gives an A32 `mvn` of a constant the unused first value field too,
    // as in `mvn r0, r0, 0x1`.
    if matches!(inst.opcode, Opcode::MVN | Opcode::MOV) && operands.len() == 3 {
        operands.remove(1);
    }
    let mut reads = il::RegSet::EMPTY;
    let mut writes = il::RegSet::EMPTY;
    for operand in &operands {
        address_registers(*operand, &mut reads, &mut writes);
    }

    let role = role_of(inst.opcode);
    for (index, operand) in operands.iter().enumerate() {
        let regs = value_registers(*operand);
        let written = match role {
            Role::Compute { count } | Role::Load { count } => index < count,
            Role::StoreExclusive => index == 0,
            Role::ReadOnly => false,
        };
        let list_loaded =
            matches!(role, Role::Load { .. }) && matches!(operand, Operand::RegList(_));
        if written || list_loaded {
            regs.iter().for_each(|reg| writes.insert(reg));
            if reads_destination(inst.opcode) {
                regs.iter().for_each(|reg| reads.insert(reg));
            }
        } else {
            regs.iter().for_each(|reg| reads.insert(reg));
        }
    }

    match inst.opcode {
        Opcode::BL | Opcode::BLX => writes.insert(il::Reg::General(REG_LR as u8)),
        Opcode::PUSH | Opcode::POP => {
            reads.insert(il::Reg::Stack);
            writes.insert(il::Reg::Stack);
        }
        _ => {}
    }
    if inst.condition != ConditionCode::AL || matches!(inst.opcode, Opcode::IT) {
        reads.insert(il::Reg::Flags);
    }
    if inst.s() || is_compare(inst.opcode) {
        writes.insert(il::Reg::Flags);
    }

    let mut lifted = il::Lifted {
        op: op_of(inst, &operands),
        reads,
        writes,
        memory: memory_access(inst.opcode, &operands),
        test: test_of(inst, &operands),
        operands: operands.iter().map(|operand| il_operand(*operand)).collect(),
    };
    // A 16-bit Thumb form names its destination once, as `adds r0, #1`,
    // where the 32-bit form names it twice, as `add r0, r0, #1`.
    if is_binary(lifted.op) && lifted.operands.len() == 2 {
        let destination = lifted.operands[0];
        lifted.operands.insert(1, destination);
    }
    // `rsb` subtracts the other way round, so its values swap to read as
    // `sub` does: `rsb r0, r1, #0` is `0 - r1`.
    if matches!(inst.opcode, Opcode::RSB | Opcode::RSC) && lifted.operands.len() == 3 {
        lifted.operands.swap(1, 2);
    }
    // `mov r4, r1, lsl #4` is the shift `lsl r4, r1, #4`.
    if let (Opcode::MOV, [_, Operand::RegShift(shift)]) = (inst.opcode, operands.as_slice()) {
        let op_of_style = |style: ShiftStyle| match style {
            ShiftStyle::LSL => il::Op::ShiftLeft,
            ShiftStyle::LSR => il::Op::ShiftRight,
            ShiftStyle::ASR => il::Op::ShiftRightArithmetic,
            ShiftStyle::ROR => il::Op::Rotate,
        };
        let shifted = match shift.into_shift() {
            // A shift right of 0 encodes one of 32; a rotate of 0 is `rrx`,
            // and a shift left of 0 is no shift.
            RegShiftStyle::RegImm(shift) => match (shift.stype(), shift.imm()) {
                (ShiftStyle::LSL, 0) | (ShiftStyle::ROR, 0) => None,
                (style, 0) => Some((op_of_style(style), shift.shiftee(), il::Operand::Const(32))),
                (style, amount) => {
                    Some((op_of_style(style), shift.shiftee(), il::Operand::Const(amount.into())))
                }
            },
            RegShiftStyle::RegReg(shift) => il_reg(shift.shifter())
                .map(|by| (op_of_style(shift.stype()), shift.shiftee(), il::Operand::Reg(by))),
        };
        if let Some((op, source, amount)) = shifted
            && let Some(source) = il_reg(source)
        {
            lifted.op = op;
            lifted.operands =
                [lifted.operands[0], il::Operand::Reg(source), amount].into_iter().collect();
        }
    }
    // `mvn r0, #1` puts the constant `~1` in `r0`, as `mov` would.
    if let (Opcode::MVN, [dest, il::Operand::Const(constant)]) =
        (inst.opcode, lifted.operands.as_slice())
    {
        let inverted = il::Operand::Const(u64::from(!(*constant as u32)));
        lifted.operands = [*dest, inverted].into_iter().collect();
        lifted.op = il::Op::Move;
    }
    lifted
}

/// Report whether `op` computes its result from two values.
fn is_binary(op: il::Op) -> bool {
    use il::Op;
    matches!(
        op,
        Op::Add
            | Op::Subtract
            | Op::Multiply
            | Op::And
            | Op::Or
            | Op::Xor
            | Op::AndNot
            | Op::OrNot
            | Op::ShiftLeft
            | Op::ShiftRight
            | Op::ShiftRightArithmetic
            | Op::Rotate
    )
}

/// An operand as the IL names it.
fn il_operand(operand: Operand) -> il::Operand {
    let register = |reg: Reg| il_reg(reg).map_or(il::Operand::Other, il::Operand::Reg);
    match operand {
        Operand::Reg(reg) | Operand::RegWBack(reg, _) => register(reg),
        Operand::RegShift(shift) => match shift.into_shift() {
            RegShiftStyle::RegImm(shift) => register(shift.shiftee()),
            RegShiftStyle::RegReg(shift) => register(shift.shiftee()),
        },
        Operand::RegList(_) => il::Operand::RegisterList,
        Operand::RegDeref(base) => il::Operand::Memory { base: il_reg(base), offset: Some(0) },
        Operand::RegDerefPostindexOffset(base, offset, add, _)
        | Operand::RegDerefPreindexOffset(base, offset, add, _) => {
            let offset = i64::from(offset);
            il::Operand::Memory {
                base: il_reg(base),
                offset: Some(if add { offset } else { -offset }),
            }
        }
        Operand::RegDerefPostindexRegShift(base, ..)
        | Operand::RegDerefPreindexRegShift(base, ..)
        | Operand::RegDerefPostindexReg(base, ..)
        | Operand::RegDerefPreindexReg(base, ..) => {
            il::Operand::Memory { base: il_reg(base), offset: None }
        }
        Operand::Imm12(value) => il::Operand::Const(value.into()),
        Operand::Imm32(value) => il::Operand::Const(value.into()),
        Operand::BranchOffset(_) | Operand::BranchThumbOffset(_) => il::Operand::Target,
        _ => il::Operand::Other,
    }
}

/// What an A32 or T32 instruction computes.
fn op_of(inst: &Instruction, operands: &[Operand]) -> il::Op {
    use il::Op;
    let unconditional = inst.condition == ConditionCode::AL;
    let loads_pc = operands.iter().any(|operand| {
        matches!(operand, Operand::RegList(list) if list & (1 << REG_PC) != 0)
            || matches!(operand, Operand::Reg(reg) if u16::from(reg.number()) == REG_PC)
    });
    match inst.opcode {
        Opcode::B if unconditional => Op::Jump,
        Opcode::B | Opcode::CBZ | Opcode::CBNZ => Op::Branch,
        Opcode::BL | Opcode::BLX => Op::Call,
        Opcode::BX | Opcode::BXJ => match operands.first() {
            Some(Operand::Reg(reg)) if u16::from(reg.number()) == REG_LR => Op::Return,
            _ => Op::Jump,
        },
        Opcode::TBB | Opcode::TBH => Op::Jump,
        // `pop {r4, pc}` loads the return address into the program counter.
        Opcode::POP | Opcode::LDM(..) if loads_pc => Op::Return,
        Opcode::MOV => Op::Move,
        Opcode::MVN => Op::Not,
        Opcode::MOVT | Opcode::UBFX | Opcode::SBFX | Opcode::BFI | Opcode::BFC => Op::BitField,
        Opcode::ADR => Op::Address,
        Opcode::ADD | Opcode::ADC => Op::Add,
        Opcode::SUB | Opcode::SBC | Opcode::RSB | Opcode::RSC => Op::Subtract,
        Opcode::MUL
        | Opcode::UMULL
        | Opcode::SMULL
        | Opcode::SMUL(..)
        | Opcode::SMULW(_)
        | Opcode::SMMUL
        | Opcode::SMUAD
        | Opcode::SMUSD => Op::Multiply,
        Opcode::MLA
        | Opcode::MLS
        | Opcode::UMLAL
        | Opcode::SMLAL
        | Opcode::SMLAL_halfword(..)
        | Opcode::UMAAL
        | Opcode::SMLA(..)
        | Opcode::SMLAW(_)
        | Opcode::SMLALD(_)
        | Opcode::SMLSLD(_)
        | Opcode::SMLAD
        | Opcode::SMLSD
        | Opcode::SMMLA
        | Opcode::SMMLS
        | Opcode::SMAL(..)
        | Opcode::USADA8 => Op::MultiplyAdd,
        Opcode::SDIV | Opcode::UDIV => Op::Divide,
        Opcode::AND => Op::And,
        Opcode::ORR => Op::Or,
        Opcode::EOR => Op::Xor,
        Opcode::BIC => Op::AndNot,
        Opcode::ORN => Op::OrNot,
        Opcode::LSL => Op::ShiftLeft,
        Opcode::LSR => Op::ShiftRight,
        Opcode::ASR => Op::ShiftRightArithmetic,
        Opcode::ROR | Opcode::RRX => Op::Rotate,
        Opcode::SXTB
        | Opcode::SXTH
        | Opcode::UXTB
        | Opcode::UXTH
        | Opcode::SXTAB
        | Opcode::SXTAH
        | Opcode::UXTAB
        | Opcode::UXTAH
        | Opcode::SXTB16
        | Opcode::UXTB16
        | Opcode::SXTAB16
        | Opcode::UXTAB16 => Op::Extend,
        Opcode::CLZ | Opcode::RBIT | Opcode::REV | Opcode::REV16 | Opcode::REVSH => Op::Bits,
        Opcode::SEL => Op::Select,
        Opcode::CMP | Opcode::CMN | Opcode::TST | Opcode::TEQ => Op::Compare,
        Opcode::SWP | Opcode::SWPB => Op::Atomic,
        Opcode::IT
        | Opcode::NOP
        | Opcode::HINT
        | Opcode::YIELD
        | Opcode::WFE
        | Opcode::WFI
        | Opcode::SEV
        | Opcode::CSDB
        | Opcode::DMB
        | Opcode::DSB
        | Opcode::ISB
        | Opcode::SVC
        | Opcode::BKPT
        | Opcode::MSR
        | Opcode::MRS
        | Opcode::CPS(_)
        | Opcode::CPS_modeonly
        | Opcode::SETEND
        | Opcode::CLREX
        | Opcode::UDF
        | Opcode::DBG
        | Opcode::PLD
        | Opcode::PLI
        | Opcode::HVC
        | Opcode::SMC
        | Opcode::ERET
        | Opcode::LDC(_)
        | Opcode::LDCL(_)
        | Opcode::LDC2(_)
        | Opcode::LDC2L(_)
        | Opcode::STC(_)
        | Opcode::STCL(_)
        | Opcode::STC2(_)
        | Opcode::STC2L(_)
        | Opcode::MCR2(..)
        | Opcode::MCRR2(..)
        | Opcode::MRC2(..)
        | Opcode::MRRC2(..)
        | Opcode::MCRR(..)
        | Opcode::MRRC(..)
        | Opcode::CDP2(..) => Op::System,
        Opcode::LDREX | Opcode::LDREXB | Opcode::LDREXH | Opcode::LDREXD => Op::Atomic,
        opcode => match role_of(opcode) {
            Role::Load { .. } => Op::Load,
            Role::StoreExclusive => Op::Atomic,
            Role::ReadOnly if matches!(opcode, Opcode::STM(..) | Opcode::PUSH) => Op::Store,
            Role::ReadOnly if memory_access(opcode, operands).is_some() => Op::Store,
            Role::ReadOnly | Role::Compute { .. } => Op::Other,
        },
    }
}

fn is_compare(opcode: Opcode) -> bool {
    matches!(opcode, Opcode::CMP | Opcode::CMN | Opcode::TST | Opcode::TEQ)
}

/// Instructions that keep part of their destination, so read it too.
fn reads_destination(opcode: Opcode) -> bool {
    matches!(
        opcode,
        Opcode::MOVT | Opcode::BFI | Opcode::BFC | Opcode::UMLAL | Opcode::SMLAL | Opcode::UMAAL
    )
}

fn role_of(opcode: Opcode) -> Role {
    match opcode {
        Opcode::LDR
        | Opcode::LDRB
        | Opcode::LDRH
        | Opcode::LDRSB
        | Opcode::LDRSH
        | Opcode::LDRT
        | Opcode::LDRBT
        | Opcode::LDRHT
        | Opcode::LDRSBT
        | Opcode::LDRSHT
        | Opcode::LDREX
        | Opcode::LDREXB
        | Opcode::LDREXH
        | Opcode::SWP
        | Opcode::SWPB => Role::Load { count: 1 },
        Opcode::LDRD | Opcode::LDREXD => Role::Load { count: 2 },
        Opcode::LDM(..) | Opcode::POP => Role::Load { count: 0 },
        Opcode::STREX | Opcode::STREXB | Opcode::STREXH | Opcode::STREXD => Role::StoreExclusive,
        Opcode::STR
        | Opcode::STRB
        | Opcode::STRH
        | Opcode::STRD
        | Opcode::STRT
        | Opcode::STRBT
        | Opcode::STRHT
        | Opcode::STM(..)
        | Opcode::PUSH
        | Opcode::CMP
        | Opcode::CMN
        | Opcode::TST
        | Opcode::TEQ
        | Opcode::B
        | Opcode::BL
        | Opcode::BLX
        | Opcode::BX
        | Opcode::BXJ
        | Opcode::CBZ
        | Opcode::CBNZ
        | Opcode::TBB
        | Opcode::TBH
        | Opcode::IT
        | Opcode::MSR
        | Opcode::PLD
        | Opcode::PLI
        | Opcode::SVC
        | Opcode::BKPT
        | Opcode::NOP
        | Opcode::HINT
        | Opcode::DMB
        | Opcode::DSB
        | Opcode::ISB => Role::ReadOnly,
        Opcode::UMULL | Opcode::SMULL | Opcode::UMLAL | Opcode::SMLAL | Opcode::UMAAL => {
            Role::Compute { count: 2 }
        }
        _ => Role::Compute { count: 1 },
    }
}

/// The text of an A32 instruction without the register its encoding holds
/// but does not use.
///
/// `yaxpeax-arm` 0.4 prints the first source of a compare, which a compare
/// has none of, and a flag-setting `s` it always has: `cmp r3, r2` reads
/// `cmps r0, r3, r2`. It prints the first source of `mov` and `mvn` too,
/// which they do not read: `mvn r0, #0` reads `mvn r0, r0, 0x0`. Measured on
/// Lua by GCC, 2601 of 28304 instructions printed so.
fn without_unused_operand(mnemonic: String, operands: String) -> (String, String) {
    const CONDITIONS: [&str; 15] =
        ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al"];
    let condition =
        CONDITIONS.iter().find(|cond| mnemonic.len() > 4 && mnemonic.ends_with(*cond)).copied();
    let base = &mnemonic[..mnemonic.len() - condition.map_or(0, str::len)];
    let is_shift =
        |part: &str| ["lsl", "lsr", "asr", "ror", "rrx"].iter().any(|s| part.starts_with(s));
    let parts: Vec<&str> = operands.split(", ").collect();
    match base {
        "cmps" | "cmns" | "tsts" | "teqs" if parts.len() >= 3 => {
            let name = format!("{}{}", &base[..3], condition.unwrap_or_default());
            (name, parts[1..].join(", "))
        }
        "mov" | "movs" | "mvn" | "mvns" => {
            let values = parts.iter().filter(|part| !is_shift(part)).count();
            if values > 2 {
                let kept: Vec<&str> =
                    parts.iter().enumerate().filter(|&(i, _)| i != 1).map(|(_, p)| *p).collect();
                (mnemonic, kept.join(", "))
            } else {
                (mnemonic, operands)
            }
        }
        _ => (mnemonic, operands),
    }
}

/// The name of an A32 access to a list of registers with the order it has.
///
/// `yaxpeax-arm` 0.4 prints the increment-before form as `ldmia` and
/// `stmia`, the name of increment-after, which it prints as `ldm` and `stm`.
/// So `ldmib r0, {r1, r2}`, which loads from `r0 + 4`, read as a load from
/// `r0`.
fn with_list_order(opcode: &Opcode, mnemonic: String) -> String {
    match opcode {
        Opcode::LDM(true, true, ..) | Opcode::STM(true, true, ..) => match mnemonic.get(..5) {
            Some(stem @ ("ldmia" | "stmia")) => format!("{}ib{}", &stem[..3], &mnemonic[5..]),
            _ => mnemonic,
        },
        _ => mnemonic,
    }
}

/// The register `reg` names, where it is one the IL tracks: the program
/// counter is not.
fn il_reg(reg: Reg) -> Option<il::Reg> {
    match u16::from(reg.number()) {
        REG_PC => None,
        REG_SP => Some(il::Reg::Stack),
        number => Some(il::Reg::General(number as u8)),
    }
}

/// The registers an operand that is a value names.
fn value_registers(operand: Operand) -> il::RegSet {
    match operand {
        Operand::Reg(reg) | Operand::RegWBack(reg, _) => il_reg(reg).into_iter().collect(),
        Operand::RegShift(shift) => match shift.into_shift() {
            RegShiftStyle::RegImm(shift) => il_reg(shift.shiftee()).into_iter().collect(),
            RegShiftStyle::RegReg(shift) => {
                [il_reg(shift.shiftee()), il_reg(shift.shifter())].into_iter().flatten().collect()
            }
        },
        Operand::RegList(list) => (0..16_u8)
            .filter(|bit| list & (1 << bit) != 0)
            .filter_map(|bit| il_reg(Reg::from_u8(bit)))
            .collect(),
        _ => il::RegSet::EMPTY,
    }
}

/// The registers a memory operand reads to form its address, and the base
/// it writes back. A base in the list of `ldm` or `stm` is a value, and its
/// write back is read from the operand.
fn address_registers(operand: Operand, reads: &mut il::RegSet, writes: &mut il::RegSet) {
    let mut base = |reg: Reg, write_back: bool| {
        if let Some(reg) = il_reg(reg) {
            reads.insert(reg);
            if write_back {
                writes.insert(reg);
            }
        }
    };
    match operand {
        Operand::RegDeref(reg) => base(reg, false),
        Operand::RegWBack(reg, true) => base(reg, true),
        Operand::RegDerefPreindexOffset(reg, _, _, write_back) => base(reg, write_back),
        Operand::RegDerefPostindexOffset(reg, ..) => base(reg, true),
        Operand::RegDerefPreindexReg(reg, index, _, write_back) => {
            base(reg, write_back);
            il_reg(index).into_iter().for_each(|reg| reads.insert(reg));
        }
        Operand::RegDerefPostindexReg(reg, index, ..) => {
            base(reg, true);
            il_reg(index).into_iter().for_each(|reg| reads.insert(reg));
        }
        Operand::RegDerefPreindexRegShift(reg, shift, _, write_back) => {
            base(reg, write_back);
            value_registers(Operand::RegShift(shift)).iter().for_each(|reg| reads.insert(reg));
        }
        Operand::RegDerefPostindexRegShift(reg, shift, ..) => {
            base(reg, true);
            value_registers(Operand::RegShift(shift)).iter().for_each(|reg| reads.insert(reg));
        }
        _ => {}
    }
}

fn memory_access(opcode: Opcode, operands: &[Operand]) -> Option<il::MemoryAccess> {
    let kind = match role_of(opcode) {
        Role::Load { .. } if matches!(opcode, Opcode::SWP | Opcode::SWPB) => {
            il::AccessKind::LoadStore
        }
        Role::Load { .. } => il::AccessKind::Load,
        Role::StoreExclusive => il::AccessKind::Store,
        Role::ReadOnly if matches!(opcode, Opcode::STM(..) | Opcode::PUSH) => il::AccessKind::Store,
        Role::ReadOnly
            if operands.iter().any(|operand| {
                matches!(
                    operand,
                    Operand::RegDeref(_)
                        | Operand::RegDerefPreindexOffset(..)
                        | Operand::RegDerefPostindexOffset(..)
                        | Operand::RegDerefPreindexReg(..)
                        | Operand::RegDerefPostindexReg(..)
                        | Operand::RegDerefPreindexRegShift(..)
                        | Operand::RegDerefPostindexRegShift(..)
                )
            }) && !matches!(opcode, Opcode::PLD | Opcode::PLI | Opcode::TBB | Opcode::TBH) =>
        {
            il::AccessKind::Store
        }
        _ => return None,
    };
    let width = match opcode {
        Opcode::LDRB
        | Opcode::STRB
        | Opcode::LDRSB
        | Opcode::LDRBT
        | Opcode::STRBT
        | Opcode::LDRSBT
        | Opcode::LDREXB
        | Opcode::STREXB
        | Opcode::SWPB => Some(il::Width::Bits8),
        Opcode::LDRH
        | Opcode::STRH
        | Opcode::LDRSH
        | Opcode::LDRHT
        | Opcode::STRHT
        | Opcode::LDRSHT
        | Opcode::LDREXH
        | Opcode::STREXH => Some(il::Width::Bits16),
        Opcode::LDM(..) | Opcode::STM(..) | Opcode::PUSH | Opcode::POP => None,
        _ => Some(il::Width::Bits32),
    };
    Some(il::MemoryAccess { kind, width })
}

/// What an operand gives as a value. The program counter, and a register
/// shifted by something, are no one value.
fn value_of(operand: Operand) -> il::Value {
    match operand {
        Operand::Reg(reg) => il_reg(reg).map_or(il::Value::Other, il::Value::Reg),
        Operand::Imm32(value) => il::Value::Const(u64::from(value)),
        Operand::Imm12(value) => il::Value::Const(u64::from(value)),
        Operand::RegShift(shift) => match shift.into_shift() {
            RegShiftStyle::RegImm(shift)
                if shift.imm() == 0 && shift.stype() == ShiftStyle::LSL =>
            {
                il_reg(shift.shiftee()).map_or(il::Value::Other, il::Value::Reg)
            }
            _ => il::Value::Other,
        },
        _ => il::Value::Other,
    }
}

fn test_of(inst: &Instruction, operands: &[Operand]) -> Option<il::Test> {
    /// Every ARM general register is 32 bits wide.
    const WIDTH: il::Width = il::Width::Bits32;
    let value = |index: usize| operands.get(index).map_or(il::Value::Other, |op| value_of(*op));
    let guard = |cond| {
        Some(il::Test::Guard(il::Guard {
            cond,
            left: value(0),
            right: il::Value::Const(0),
            width: WIDTH,
        }))
    };
    let (left, right) = (value(0), value(1));
    let comparison = match inst.opcode {
        Opcode::B if inst.condition != ConditionCode::AL => {
            return Some(il::Test::OnFlags(il::Cond::from_arm(inst.condition as u8)));
        }
        Opcode::CBZ => return guard(il::Cond::Equal),
        Opcode::CBNZ => return guard(il::Cond::NotEqual),
        // A compare that only runs on a condition tests nothing on its own.
        _ if inst.condition != ConditionCode::AL => return None,
        Opcode::CMP => il::Comparison::Subtract { left, right },
        Opcode::TST => il::Comparison::And { left, right },
        // `cmn r, #k` sets the flags as `cmp r, #-k` does, for any `k` but zero.
        Opcode::CMN => match right {
            il::Value::Const(constant) if constant != 0 => il::Comparison::Subtract {
                left,
                right: il::Value::Const(constant.wrapping_neg() & WIDTH.mask()),
            },
            _ => il::Comparison::Add { left, right },
        },
        _ => return None,
    };
    Some(il::Test::Compare { comparison, width: WIDTH })
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
    if !is_plain(jump, Opcode::ADD) || jump.kind != (InsnKind::Jump { target: None }) {
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
    if !is_plain(load, Opcode::LDR)
        || !load.operands.starts_with(&expected)
        || !load.operands.ends_with(", lsl 2]")
    {
        return None;
    }

    // `adr rB, pc, imm`: the address of the table.
    let address = last_write(table_register)?;
    let immediate = address.operands.strip_prefix(&format!("{table_register}, pc, "))?;
    if !is_plain(address, Opcode::ADR) {
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
    let shape = jump.operands.starts_with("pc, pc, ") && jump.operands.ends_with(", lsl 2");
    if core_opcode(jump) != Some(Opcode::ADD) || !is_jump || !shape {
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
    if core_opcode(jump) != Some(Opcode::ADD) || !is_jump {
        return None;
    }
    let offset_register = jump.operands.strip_prefix("pc, pc, ")?.strip_suffix(", lsl 2")?;

    let window = || earlier.iter().rev().take(LOOK_BACK);
    // A compare names `r0` first but writes nothing, so it is no write.
    let writes = |insn: &Insn, register: &str| {
        writes_first_operand(insn)
            && insn.operands.split(',').next().map(str::trim) == Some(register)
    };
    let last_write = |register: &str| window().find(|insn| writes(insn, register));

    // `ldrb rX, [rB, rI]`: one entry of the table.
    let load = last_write(offset_register)?;
    let width = match core_opcode(load)? {
        Opcode::LDRB => 1,
        Opcode::LDRH => 2,
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
    if core_opcode(add) != Some(Opcode::ADD) || add.operands != expected {
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
        .filter(|insn| core_opcode(insn) == Some(Opcode::CMP))
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
pub(super) fn parse_hex(text: &str) -> Option<u64> {
    u64::from_str_radix(text.strip_prefix("0x")?, 16).ok()
}

/// The offset in a memory reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Offset<'a> {
    Immediate(i64),
    Register(&'a str),
}

/// Read `[base, offset]` as the base register and the offset.
pub(super) fn parse_reference(text: &str) -> Option<(&str, Offset<'_>)> {
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
pub(super) fn decode_fallback(word: u32, encoding: Encoding) -> Option<(String, String, Decoded)> {
    const CONDITIONS: [&str; 15] =
        ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", ""];
    if word >> 24 == NEON_LOAD_STORE {
        let (mnemonic, operands) = decode_neon_load_store(word)?;
        return Some((mnemonic, operands, Decoded::NeonAccess));
    }

    let condition = *CONDITIONS.get((word >> 28) as usize)?;
    let condition_code = condition_of(word)?;
    let core = |opcode, flags| Decoded::Core { opcode, condition: condition_code, flags };

    // The hints: `nop`, `yield`, `wfe`, `wfi` and `sev`.
    if word & 0x0fff_ff00 == 0x0320_f000 {
        const HINTS: [(&str, Opcode); 5] = [
            ("nop", Opcode::NOP),
            ("yield", Opcode::YIELD),
            ("wfe", Opcode::WFE),
            ("wfi", Opcode::WFI),
            ("sev", Opcode::SEV),
        ];
        let (hint, opcode) = HINTS.get((word & 0xff) as usize)?;
        return Some((format!("{hint}{condition}"), String::new(), core(*opcode, Flags::Kept)));
    }

    if let Some(word) = IntegerWord::of(word).filter(|_| encoding == Encoding::A32) {
        let decoded = core(word.opcode(), word.flags());
        return Some((format!("{}{condition}", word.mnemonic()), word.operands(), decoded));
    }
    if let Some(word) = VfpWord::of(word) {
        let (mnemonic, operands) = word.text();
        let decoded = Decoded::Vfp { vfp: word.kind(), condition: condition_code };
        return Some((format!("{mnemonic}{condition}"), operands, decoded));
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
        let base = ARM_REGISTERS[(word >> 16 & 0xf) as usize];
        let offset = (word & 0xff) * 4;
        let reference = match (offset, up) {
            (0, _) => format!("[{base}]"),
            (_, true) => format!("[{base}, {offset:#x}]"),
            (_, false) => format!("[{base}, -{offset:#x}]"),
        };
        let (operation, vfp) = if load { ("vldr", Vfp::Load) } else { ("vstr", Vfp::Store) };
        return Some((
            format!("{operation}{condition}"),
            format!("{register}, {reference}"),
            Decoded::Vfp { vfp, condition: condition_code },
        ));
    }
    None
}

/// An A32 integer word `yaxpeax` 0.4 refuses, though ARMv7 defines it.
///
/// Measured on the backport fixtures built for A32 by clang and GCC at
/// `-O2`, these made 520 of the 1,690 words it could not read: the byte and
/// halfword extends, the bit field operations, `mov` and `mvn` of a register
/// shifted by a register, and a halfword or signed byte load with no offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IntegerWord {
    /// `uxtb rd, rm` and kin, which may add `rn` and rotate `rm` first.
    Extend { kind: Extend, rd: u32, rn: Option<u32>, rm: u32, rotation: u32 },
    /// `bfi rd, rn, lsb, width`, or `bfc` with no `rn`.
    Insert { rd: u32, rn: Option<u32>, lsb: u32, width: u32 },
    /// `ubfx rd, rn, lsb, width` and `sbfx`.
    Extract { signed: bool, rd: u32, rn: u32, lsb: u32, width: u32 },
    /// `mov rd, rm, lsl rs` and kin, or `mvn` of the same.
    ShiftByRegister { not: bool, sets_flags: bool, rd: u32, rm: u32, kind: u32, rs: u32 },
    /// `smulbb rd, rn, rm` and kin. `top_n` and `top_m` take the top
    /// halfword of `rn` and of `rm`. A long form names `rdlo` as `ra`.
    HalfwordMultiply {
        kind: HalfwordMultiply,
        top_n: bool,
        top_m: bool,
        rd: u32,
        ra: u32,
        rn: u32,
        rm: u32,
    },
    /// `ldrsb rt, [rn, imm]` and the other loads and stores of a halfword,
    /// a signed byte or a pair.
    Halfword { access: HalfwordAccess, rt: u32, rn: u32, offset: i64, index: Indexing },
}

/// Which extend an [`IntegerWord::Extend`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Extend {
    Sxtb16,
    Sxtb,
    Sxth,
    Uxtb16,
    Uxtb,
    Uxth,
}

impl Extend {
    fn name(self) -> &'static str {
        match self {
            Self::Sxtb16 => "sxtb16",
            Self::Sxtb => "sxtb",
            Self::Sxth => "sxth",
            Self::Uxtb16 => "uxtb16",
            Self::Uxtb => "uxtb",
            Self::Uxth => "uxth",
        }
    }

    /// The opcode, or the one that adds `rn` after the extend, as `uxtab`.
    fn opcode(self, adds: bool) -> Opcode {
        match (self, adds) {
            (Self::Sxtb16, false) => Opcode::SXTB16,
            (Self::Sxtb16, true) => Opcode::SXTAB16,
            (Self::Uxtb16, false) => Opcode::UXTB16,
            (Self::Uxtb16, true) => Opcode::UXTAB16,
            (Self::Sxtb, false) => Opcode::SXTB,
            (Self::Sxtb, true) => Opcode::SXTAB,
            (Self::Sxth, false) => Opcode::SXTH,
            (Self::Sxth, true) => Opcode::SXTAH,
            (Self::Uxtb, false) => Opcode::UXTB,
            (Self::Uxtb, true) => Opcode::UXTAB,
            (Self::Uxth, false) => Opcode::UXTH,
            (Self::Uxth, true) => Opcode::UXTAH,
        }
    }
}

/// Which load or store an [`IntegerWord::Halfword`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HalfwordAccess {
    Ldrh,
    Ldrsb,
    Ldrsh,
    Strh,
    Ldrd,
    Strd,
}

impl HalfwordAccess {
    fn name(self) -> &'static str {
        match self {
            Self::Ldrh => "ldrh",
            Self::Ldrsb => "ldrsb",
            Self::Ldrsh => "ldrsh",
            Self::Strh => "strh",
            Self::Ldrd => "ldrd",
            Self::Strd => "strd",
        }
    }

    fn opcode(self) -> Opcode {
        match self {
            Self::Ldrh => Opcode::LDRH,
            Self::Ldrsb => Opcode::LDRSB,
            Self::Ldrsh => Opcode::LDRSH,
            Self::Strh => Opcode::STRH,
            Self::Ldrd => Opcode::LDRD,
            Self::Strd => Opcode::STRD,
        }
    }

    fn is_load(self) -> bool {
        !matches!(self, Self::Strh | Self::Strd)
    }

    /// `ldrd` and `strd`, which move two registers.
    fn is_pair(self) -> bool {
        matches!(self, Self::Ldrd | Self::Strd)
    }

    fn width(self) -> il::Width {
        match self {
            Self::Ldrsb => il::Width::Bits8,
            Self::Ldrh | Self::Ldrsh | Self::Strh => il::Width::Bits16,
            Self::Ldrd | Self::Strd => il::Width::Bits32,
        }
    }
}

/// How a load or store forms its address and moves its base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Indexing {
    /// `[rn, imm]`: the base stays.
    Offset,
    /// `[rn, imm]!`: the base moves first.
    PreIndex,
    /// `[rn], imm`: the base moves after.
    PostIndex,
}

impl IntegerWord {
    fn of(word: u32) -> Option<Self> {
        let field = |shift: u32, width: u32| word >> shift & ((1 << width) - 1);
        let (rn, rd, rm) = (field(16, 4), field(12, 4), field(0, 4));
        // cond 0001 0 op 0 Rd Ra Rm 1 y x 0 Rn
        if field(23, 5) == 0b00010 && field(20, 1) == 0 && field(7, 1) == 1 && field(4, 1) == 0 {
            let (top_n, top_m) = (field(5, 1) == 1, field(6, 1) == 1);
            let kind = match (field(21, 2), top_n) {
                (0b00, _) => HalfwordMultiply::MultiplyAdd,
                // In the word forms, `x` chooses the form, not a halfword.
                (0b01, false) => HalfwordMultiply::WordMultiplyAdd,
                (0b01, true) => HalfwordMultiply::WordMultiply,
                (0b10, _) => HalfwordMultiply::LongMultiplyAdd,
                _ => HalfwordMultiply::Multiply,
            };
            let top_n = top_n && !matches!(field(21, 2), 0b01);
            return Some(Self::HalfwordMultiply {
                kind,
                top_n,
                top_m,
                rd: field(16, 4),
                ra: field(12, 4),
                rn: field(0, 4),
                rm: field(8, 4),
            });
        }
        if field(23, 5) == 0b01101 && field(4, 4) == 0b0111 && field(8, 2) == 0 {
            let kind = match field(20, 3) {
                0b000 => Extend::Sxtb16,
                0b010 => Extend::Sxtb,
                0b011 => Extend::Sxth,
                0b100 => Extend::Uxtb16,
                0b110 => Extend::Uxtb,
                0b111 => Extend::Uxth,
                _ => return None,
            };
            let rn = (rn != 15).then_some(rn);
            return Some(Self::Extend { kind, rd, rn, rm, rotation: field(10, 2) * 8 });
        }
        if field(21, 7) == 0b011_1110 && field(4, 3) == 0b001 {
            let (msb, lsb) = (field(16, 5), field(7, 5));
            let width = msb.checked_sub(lsb)? + 1;
            return Some(Self::Insert { rd, rn: (rm != 15).then_some(rm), lsb, width });
        }
        if field(23, 5) == 0b01111 && field(21, 1) == 1 && field(4, 3) == 0b101 {
            let (lsb, width) = (field(7, 5), field(16, 5) + 1);
            return Some(Self::Extract { signed: field(22, 1) == 0, rd, rn: rm, lsb, width });
        }
        let move_op = field(21, 4);
        if field(25, 3) == 0
            && matches!(move_op, 0b1101 | 0b1111)
            && field(7, 1) == 0
            && field(4, 1) == 1
            && rn == 0
        {
            return Some(Self::ShiftByRegister {
                not: move_op == 0b1111,
                sets_flags: field(20, 1) == 1,
                rd,
                rm,
                kind: field(5, 2),
                rs: field(8, 4),
            });
        }
        if field(25, 3) == 0 && field(22, 1) == 1 && field(7, 1) == 1 && field(4, 1) == 1 {
            let access = match (field(20, 1), field(5, 2)) {
                (1, 0b01) => HalfwordAccess::Ldrh,
                (1, 0b10) => HalfwordAccess::Ldrsb,
                (1, 0b11) => HalfwordAccess::Ldrsh,
                (0, 0b01) => HalfwordAccess::Strh,
                (0, 0b10) => HalfwordAccess::Ldrd,
                (0, 0b11) => HalfwordAccess::Strd,
                _ => return None,
            };
            let magnitude = i64::from(field(8, 4) << 4 | field(0, 4));
            let offset = if field(23, 1) == 1 { magnitude } else { -magnitude };
            let index = match (field(24, 1), field(21, 1)) {
                (1, 0) => Indexing::Offset,
                (1, 1) => Indexing::PreIndex,
                (0, 0) => Indexing::PostIndex,
                _ => return None,
            };
            return Some(Self::Halfword { access, rt: rd, rn, offset, index });
        }
        None
    }

    /// The opcode `yaxpeax-arm` names this operation by.
    pub(super) fn opcode(self) -> Opcode {
        match self {
            Self::Extend { kind, rn, .. } => kind.opcode(rn.is_some()),
            Self::Insert { rn: Some(_), .. } => Opcode::BFI,
            Self::Insert { rn: None, .. } => Opcode::BFC,
            Self::Extract { signed: true, .. } => Opcode::SBFX,
            Self::Extract { signed: false, .. } => Opcode::UBFX,
            Self::ShiftByRegister { not: true, .. } => Opcode::MVN,
            Self::ShiftByRegister { not: false, .. } => Opcode::MOV,
            Self::HalfwordMultiply { kind, top_n, top_m, .. } => match kind {
                HalfwordMultiply::Multiply => Opcode::SMUL(top_n, top_m),
                HalfwordMultiply::MultiplyAdd => Opcode::SMLA(top_n, top_m),
                HalfwordMultiply::WordMultiply => Opcode::SMULW(top_m),
                HalfwordMultiply::WordMultiplyAdd => Opcode::SMLAW(top_m),
                HalfwordMultiply::LongMultiplyAdd => Opcode::SMLAL_halfword(top_n, top_m),
            },
            Self::Halfword { access, .. } => access.opcode(),
        }
    }

    pub(super) fn flags(self) -> Flags {
        match self {
            Self::ShiftByRegister { sets_flags, .. } => Flags::of(sets_flags),
            _ => Flags::Kept,
        }
    }

    pub(super) fn mnemonic(self) -> String {
        match self {
            Self::Extend { kind, rn: None, .. } => kind.name().to_string(),
            // `uxtab` adds the extended value to `rn`.
            Self::Extend { kind, rn: Some(_), .. } => {
                let name = kind.name();
                format!("{}a{}", &name[..3], &name[3..])
            }
            Self::Insert { rn: Some(_), .. } => "bfi".into(),
            Self::Insert { rn: None, .. } => "bfc".into(),
            Self::Extract { signed: true, .. } => "sbfx".into(),
            Self::Extract { signed: false, .. } => "ubfx".into(),
            Self::ShiftByRegister { not, sets_flags, .. } => {
                format!("{}{}", if not { "mvn" } else { "mov" }, if sets_flags { "s" } else { "" })
            }
            Self::HalfwordMultiply { kind, top_n, top_m, .. } => {
                let half = |top: bool| if top { 't' } else { 'b' };
                match kind {
                    HalfwordMultiply::Multiply => format!("smul{}{}", half(top_n), half(top_m)),
                    HalfwordMultiply::MultiplyAdd => format!("smla{}{}", half(top_n), half(top_m)),
                    HalfwordMultiply::WordMultiply => format!("smulw{}", half(top_m)),
                    HalfwordMultiply::WordMultiplyAdd => format!("smlaw{}", half(top_m)),
                    HalfwordMultiply::LongMultiplyAdd => {
                        format!("smlal{}{}", half(top_n), half(top_m))
                    }
                }
            }
            Self::Halfword { access, .. } => access.name().into(),
        }
    }

    pub(super) fn operands(self) -> String {
        let name = |number: u32| ARM_REGISTERS[number as usize];
        match self {
            Self::Extend { rd, rn, rm, rotation, .. } => {
                let added = rn.map(|rn| format!("{}, ", name(rn))).unwrap_or_default();
                let rotated =
                    if rotation == 0 { String::new() } else { format!(", ror {rotation:#x}") };
                format!("{}, {added}{}{rotated}", name(rd), name(rm))
            }
            Self::Insert { rd, rn, lsb, width } => {
                let source = rn.map(|rn| format!("{}, ", name(rn))).unwrap_or_default();
                format!("{}, {source}{lsb:#x}, {width:#x}", name(rd))
            }
            Self::Extract { rd, rn, lsb, width, .. } => {
                format!("{}, {}, {lsb:#x}, {width:#x}", name(rd), name(rn))
            }
            Self::ShiftByRegister { rd, rm, kind, rs, .. } => {
                let shift = ["lsl", "lsr", "asr", "ror"][kind as usize];
                format!("{}, {}, {shift} {}", name(rd), name(rm), name(rs))
            }
            Self::HalfwordMultiply { kind, rd, ra, rn, rm, .. } => {
                let (rd, ra, rn, rm) = (name(rd), name(ra), name(rn), name(rm));
                match kind {
                    HalfwordMultiply::Multiply | HalfwordMultiply::WordMultiply => {
                        format!("{rd}, {rn}, {rm}")
                    }
                    HalfwordMultiply::MultiplyAdd | HalfwordMultiply::WordMultiplyAdd => {
                        format!("{rd}, {rn}, {rm}, {ra}")
                    }
                    HalfwordMultiply::LongMultiplyAdd => format!("{ra}, {rd}, {rn}, {rm}"),
                }
            }
            Self::Halfword { access, rt, rn, offset, index } => {
                let pair = if access.is_pair() {
                    format!("{}, ", name((rt + 1) & 15))
                } else {
                    String::new()
                };
                let amount = if offset < 0 {
                    format!("-{:#x}", offset.unsigned_abs())
                } else {
                    format!("{offset:#x}")
                };
                let base = name(rn);
                let address = match (index, offset) {
                    (Indexing::Offset, 0) => format!("[{base}]"),
                    (Indexing::Offset, _) => format!("[{base}, {amount}]"),
                    (Indexing::PreIndex, _) => format!("[{base}, {amount}]!"),
                    (Indexing::PostIndex, _) => format!("[{base}], {amount}"),
                };
                format!("{}, {pair}{address}", name(rt))
            }
        }
    }

    /// The IL form of this word, as [`lift`] gives for the words `yaxpeax`
    /// reads.
    pub(super) fn lift(self) -> il::Lifted {
        use il::Op;
        let general = |number: u32| il_reg(Reg::from_u8(number as u8));
        let value = |number: u32| general(number).map_or(il::Operand::Other, il::Operand::Reg);
        let constant = |value: u32| il::Operand::Const(value.into());
        let mut lifted = il::Lifted::default();
        let read = |lifted: &mut il::Lifted, number: u32| {
            general(number).into_iter().for_each(|reg| lifted.reads.insert(reg));
        };
        let write = |lifted: &mut il::Lifted, number: u32| {
            general(number).into_iter().for_each(|reg| lifted.writes.insert(reg));
        };
        match self {
            Self::Extend { rd, rn, rm, .. } => {
                lifted.op = Op::Extend;
                lifted.operands = [Some(value(rd)), rn.map(value), Some(value(rm))]
                    .into_iter()
                    .flatten()
                    .collect();
                rn.into_iter().chain([rm]).for_each(|number| read(&mut lifted, number));
                write(&mut lifted, rd);
            }
            Self::Insert { rd, rn, lsb, width } => {
                lifted.op = Op::BitField;
                lifted.operands =
                    [Some(value(rd)), rn.map(value), Some(constant(lsb)), Some(constant(width))]
                        .into_iter()
                        .flatten()
                        .collect();
                // An insert keeps the bits around its field.
                rn.into_iter().chain([rd]).for_each(|number| read(&mut lifted, number));
                write(&mut lifted, rd);
            }
            Self::Extract { rd, rn, lsb, width, .. } => {
                lifted.op = Op::BitField;
                lifted.operands =
                    [value(rd), value(rn), constant(lsb), constant(width)].into_iter().collect();
                read(&mut lifted, rn);
                write(&mut lifted, rd);
            }
            Self::ShiftByRegister { not, sets_flags, rd, rm, kind, rs } => {
                lifted.op = match (not, kind) {
                    (true, _) => Op::Not,
                    (false, 0) => Op::ShiftLeft,
                    (false, 1) => Op::ShiftRight,
                    (false, 2) => Op::ShiftRightArithmetic,
                    (false, _) => Op::Rotate,
                };
                lifted.operands = [value(rd), value(rm), value(rs)].into_iter().collect();
                [rm, rs].into_iter().for_each(|number| read(&mut lifted, number));
                write(&mut lifted, rd);
                if sets_flags {
                    lifted.writes.insert(il::Reg::Flags);
                }
            }
            Self::HalfwordMultiply { kind, rd, ra, rn, rm, .. } => {
                // Written first, then read, as the operands list them.
                let (written, read_too): (&[u32], &[u32]) = match kind {
                    HalfwordMultiply::Multiply | HalfwordMultiply::WordMultiply => {
                        lifted.op = Op::Multiply;
                        (&[rd], &[rn, rm])
                    }
                    HalfwordMultiply::MultiplyAdd | HalfwordMultiply::WordMultiplyAdd => {
                        lifted.op = Op::MultiplyAdd;
                        (&[rd], &[rn, rm, ra])
                    }
                    // The sum is in the pair it adds to, low then high.
                    HalfwordMultiply::LongMultiplyAdd => {
                        lifted.op = Op::MultiplyAdd;
                        (&[ra, rd], &[ra, rd, rn, rm])
                    }
                };
                let listed = written.iter().chain(read_too.iter().filter(|r| !written.contains(r)));
                lifted.operands = listed.map(|&number| value(number)).collect();
                read_too.iter().for_each(|&number| read(&mut lifted, number));
                written.iter().for_each(|&number| write(&mut lifted, number));
            }
            Self::Halfword { access, rt, rn, offset, index } => {
                let load = access.is_load();
                let pair = access.is_pair();
                let width = access.width();
                let values: Vec<u32> = if pair { vec![rt, (rt + 1) & 15] } else { vec![rt] };
                let at = match index {
                    Indexing::PostIndex => 0,
                    Indexing::Offset | Indexing::PreIndex => offset,
                };
                let memory = il::Operand::Memory { base: general(rn), offset: Some(at) };
                lifted.op = if load { Op::Load } else { Op::Store };
                lifted.operands =
                    values.iter().map(|&number| value(number)).chain([memory]).collect();
                read(&mut lifted, rn);
                for &number in &values {
                    if load { write(&mut lifted, number) } else { read(&mut lifted, number) }
                }
                if index != Indexing::Offset {
                    write(&mut lifted, rn);
                }
                let kind = if load { il::AccessKind::Load } else { il::AccessKind::Store };
                lifted.memory = Some(il::MemoryAccess { kind, width: Some(width) });
            }
        }
        lifted
    }
}

/// Whether `yaxpeax` 0.4 reads the A32 `word` but prints it wrong, so that
/// [`decode_fallback`] and [`lift_fallback`] read it instead.
///
/// It reads the VFP data processing words, but loses operands: `vmov.f32 s1,
/// #1.0` prints as `vmov.f32 s1`, `vmov.f64 d16, d8` as `vmov.f64 d16`, and
/// `vcvt.f64.u32 d0, s0` as `vmov.f64 d0`. An edit to what they read then
/// shows as no change.
///
/// In A32 it swaps `bb` and `tt` of the multiplies of halfwords, so that
/// `smulbb` reads as `smultt`, and reads `smulwb` as `smlawb`.
pub(super) fn decoder_misreads(word: u32, encoding: Encoding) -> bool {
    let vfp =
        matches!(VfpWord::of(word), Some(VfpWord::Compute { .. } | VfpWord::MoveConstant { .. }));
    let multiply = encoding == Encoding::A32
        && matches!(IntegerWord::of(word), Some(IntegerWord::HalfwordMultiply { .. }));
    word >> 28 != 0b1111 && (vfp || multiply)
}

/// Which multiply of halfwords an A32 word is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HalfwordMultiply {
    /// `smulbb rd, rn, rm`: a halfword of each.
    Multiply,
    /// `smlabb rd, rn, rm, ra`: the product, plus `ra`.
    MultiplyAdd,
    /// `smulwb rd, rn, rm`: all of `rn` by a halfword of `rm`, the top 32
    /// bits of the 48.
    WordMultiply,
    /// `smlawb rd, rn, rm, ra`: the same, plus `ra`.
    WordMultiplyAdd,
    /// `smlalbb rdlo, rdhi, rn, rm`: the product, added to a 64-bit value.
    LongMultiplyAdd,
}

/// A VFP word `yaxpeax` 0.4 refuses: the moves between core and VFP
/// registers, the multiple loads and stores, and the data processing.
///
/// Measured on the backport fixtures built for A32 by clang and GCC at
/// `-O2`, these made 620 of the 1,690 words it could not read. A
/// `-mfloat-abi=softfp` build moves every double argument and result
/// through core registers, so `vmov d16, r0, r1` is common.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VfpWord {
    /// `vmov s0, r1` or `vmov r0, s0`.
    MoveSingle { to_core: bool, core: u32, single: u32 },
    /// `vmov d16, r0, r1` or `vmov r0, r1, d16`.
    MoveDouble { to_core: bool, low: u32, high: u32, double: u32 },
    /// `vmrs rt, fpscr`. `rt` 15 moves the compare flags to the core flags.
    StatusToCore { core: u32 },
    /// `vldmia rn!, {d8, d9}` and kin. `vpush` and `vpop` are the forms
    /// on `sp` that `push` and `pop` are.
    Multiple {
        load: bool,
        base: u32,
        write_back: bool,
        before: bool,
        first: u32,
        count: u32,
        double: bool,
    },
    /// The arithmetic, compares and conversions. A conversion names its
    /// sizes in `name`, as `vcvt.s32.f64`; the rest take `size`.
    Compute {
        operation: VfpOperation,
        size: &'static str,
        dest: Vector,
        sources: [Option<Vector>; 2],
    },
    /// `vmov.f32 s0, #1.0`: a constant of 8 bits, which a few floats fit.
    MoveConstant { dest: Vector, bits: u64 },
}

/// What a VFP data processing word computes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VfpOperation {
    Vmla,
    Vmls,
    Vnmls,
    Vnmla,
    Vmul,
    Vnmul,
    Vadd,
    Vsub,
    Vdiv,
    Vmov,
    Vabs,
    Vneg,
    Vsqrt,
    Vcmp,
    Vcmpe,
    /// `vcvt` and `vcvtr`. The name holds the sizes, as `vcvt.s32.f64`.
    Convert {
        name: &'static str,
        rounding: Rounding,
    },
}

/// How a VFP conversion rounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rounding {
    /// Between `f32` and `f64`, or from an integer.
    Exact,
    /// To an integer, toward zero: `vcvt`.
    TowardZero,
    /// To an integer, as the status register says: `vcvtr`.
    AsStatus,
}

impl VfpOperation {
    fn name(self) -> &'static str {
        match self {
            Self::Vmla => "vmla",
            Self::Vmls => "vmls",
            Self::Vnmls => "vnmls",
            Self::Vnmla => "vnmla",
            Self::Vmul => "vmul",
            Self::Vnmul => "vnmul",
            Self::Vadd => "vadd",
            Self::Vsub => "vsub",
            Self::Vdiv => "vdiv",
            Self::Vmov => "vmov",
            Self::Vabs => "vabs",
            Self::Vneg => "vneg",
            Self::Vsqrt => "vsqrt",
            Self::Vcmp => "vcmp",
            Self::Vcmpe => "vcmpe",
            Self::Convert { name, .. } => name,
        }
    }

    fn is_compare(self) -> bool {
        matches!(self, Self::Vcmp | Self::Vcmpe)
    }

    /// `vmla` and kin, which add to their destination.
    fn adds_to_destination(self) -> bool {
        matches!(self, Self::Vmla | Self::Vmls | Self::Vnmla | Self::Vnmls)
    }

    /// What this computes. `vcvt` to an integer rounds toward zero, and
    /// `vcvtr` as the status register says.
    fn op(self) -> il::Op {
        use il::Op;
        match self {
            Self::Vmov => Op::Move,
            Self::Vadd => Op::FloatAdd,
            Self::Vsub => Op::FloatSubtract,
            Self::Vmul | Self::Vnmul => Op::FloatMultiply,
            Self::Vmla | Self::Vmls | Self::Vnmla | Self::Vnmls => Op::FloatMultiplyAdd,
            Self::Vdiv => Op::FloatDivide,
            Self::Vneg | Self::Vabs => Op::FloatSign,
            Self::Vsqrt => Op::FloatSquareRoot,
            Self::Vcmp | Self::Vcmpe => Op::Float,
            Self::Convert { rounding: Rounding::AsStatus, .. } => Op::FloatRoundNearest,
            Self::Convert { rounding: Rounding::TowardZero, .. } => Op::FloatRoundTowardZero,
            Self::Convert { rounding: Rounding::Exact, .. } => Op::FloatConvert,
        }
    }
}

/// A VFP register: `d` where `double`, else `s`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Vector {
    double: bool,
    number: u32,
}

impl Vector {
    fn text(self) -> String {
        format!("{}{}", if self.double { 'd' } else { 's' }, self.number)
    }
}

impl VfpWord {
    fn of(word: u32) -> Option<Self> {
        let field = |shift: u32, width: u32| word >> shift & ((1 << width) - 1);
        let single = |high: u32, low: u32| high << 1 | low;
        let double = |high: u32, low: u32| low << 4 | high;
        let is_double = field(8, 1) == 1;
        let register =
            |four: u32, one: u32| if is_double { double(four, one) } else { single(four, one) };
        if field(21, 7) == 0b111_0000 && field(8, 4) == 0b1010 && field(0, 7) == 0b001_0000 {
            let to_core = field(20, 1) == 1;
            return Some(Self::MoveSingle {
                to_core,
                core: field(12, 4),
                single: single(field(16, 4), field(7, 1)),
            });
        }
        if field(21, 7) == 0b110_0010
            && field(8, 4) == 0b1011
            && field(6, 2) == 0
            && field(4, 1) == 1
        {
            return Some(Self::MoveDouble {
                to_core: field(20, 1) == 1,
                low: field(12, 4),
                high: field(16, 4),
                double: double(field(0, 4), field(5, 1)),
            });
        }
        if word & 0x0fff_0fff == 0x0ef1_0a10 {
            return Some(Self::StatusToCore { core: field(12, 4) });
        }
        if field(25, 3) == 0b110 && field(9, 3) == 0b101 {
            let (before, up, write_back) =
                (field(24, 1) == 1, field(23, 1) == 1, field(21, 1) == 1);
            // `before` without write back is `vldr` or `vstr`, and the rest
            // of the pairs are no access.
            if before == up || (before && !write_back) {
                return None;
            }
            let count = if is_double { field(1, 7) } else { field(0, 8) };
            if count == 0 {
                return None;
            }
            return Some(Self::Multiple {
                load: field(20, 1) == 1,
                base: field(16, 4),
                write_back,
                before,
                first: register(field(12, 4), field(22, 1)),
                count,
                double: is_double,
            });
        }
        if field(24, 4) == 0b1110 && field(4, 1) == 0 && field(9, 3) == 0b101 {
            let sized = |four: u32, one: u32, double: bool| Vector {
                double,
                number: if double { one << 4 | four } else { four << 1 | one },
            };
            let (vd, d, vn, n, vm, m) =
                (field(12, 4), field(22, 1), field(16, 4), field(7, 1), field(0, 4), field(5, 1));
            let dest = sized(vd, d, is_double);
            let both = [Some(sized(vn, n, is_double)), Some(sized(vm, m, is_double))];
            let one = [Some(sized(vm, m, is_double)), None];
            let size = if is_double { "f64" } else { "f32" };
            let float = |operation, sources| Some(Self::Compute { operation, size, dest, sources });
            let convert = |name, rounding| VfpOperation::Convert { name, rounding };
            return match (field(23, 1) << 2 | field(20, 2), field(6, 1)) {
                (0b000, 0) => float(VfpOperation::Vmla, both),
                (0b000, _) => float(VfpOperation::Vmls, both),
                (0b001, 0) => float(VfpOperation::Vnmls, both),
                (0b001, _) => float(VfpOperation::Vnmla, both),
                (0b010, 0) => float(VfpOperation::Vmul, both),
                (0b010, _) => float(VfpOperation::Vnmul, both),
                (0b011, 0) => float(VfpOperation::Vadd, both),
                (0b011, _) => float(VfpOperation::Vsub, both),
                (0b100, 0) => float(VfpOperation::Vdiv, both),
                (0b111, 0) => {
                    let constant = field(16, 4) << 4 | field(0, 4);
                    Some(Self::MoveConstant {
                        dest,
                        bits: expand_float_constant(constant, is_double),
                    })
                }
                (0b111, _) => match (field(16, 4), field(7, 1)) {
                    (0b0000, 0) => float(VfpOperation::Vmov, one),
                    (0b0000, _) => float(VfpOperation::Vabs, one),
                    (0b0001, 0) => float(VfpOperation::Vneg, one),
                    (0b0001, _) => float(VfpOperation::Vsqrt, one),
                    (0b0100, 0) => float(VfpOperation::Vcmp, one),
                    (0b0100, _) => float(VfpOperation::Vcmpe, one),
                    (0b0101, 0) => float(VfpOperation::Vcmp, [None, None]),
                    (0b0101, _) => float(VfpOperation::Vcmpe, [None, None]),
                    // Between `f32` and `f64`: the result is the other size.
                    (0b0111, 1) => {
                        let name = if is_double { "vcvt.f32.f64" } else { "vcvt.f64.f32" };
                        Some(Self::Compute {
                            operation: convert(name, Rounding::Exact),
                            size: "",
                            dest: sized(vd, d, !is_double),
                            sources: one,
                        })
                    }
                    // From a 32-bit integer in an `s` register.
                    (0b1000, signed) => {
                        let name = match (is_double, signed) {
                            (true, 1) => "vcvt.f64.s32",
                            (true, _) => "vcvt.f64.u32",
                            (false, 1) => "vcvt.f32.s32",
                            (false, _) => "vcvt.f32.u32",
                        };
                        let source = [Some(sized(vm, m, false)), None];
                        let operation = convert(name, Rounding::Exact);
                        Some(Self::Compute { operation, size: "", dest, sources: source })
                    }
                    // To a 32-bit integer in an `s` register. A clear bit 7
                    // rounds as the status register says, which `vcvtr` names.
                    (opc2 @ (0b1100 | 0b1101), toward_zero) => {
                        let name = match (opc2, toward_zero, is_double) {
                            (0b1101, 1, true) => "vcvt.s32.f64",
                            (0b1101, 1, false) => "vcvt.s32.f32",
                            (0b1101, _, true) => "vcvtr.s32.f64",
                            (0b1101, _, false) => "vcvtr.s32.f32",
                            (_, 1, true) => "vcvt.u32.f64",
                            (_, 1, false) => "vcvt.u32.f32",
                            (_, _, true) => "vcvtr.u32.f64",
                            (_, _, false) => "vcvtr.u32.f32",
                        };
                        let rounding = if toward_zero == 1 {
                            Rounding::TowardZero
                        } else {
                            Rounding::AsStatus
                        };
                        Some(Self::Compute {
                            operation: convert(name, rounding),
                            size: "",
                            dest: sized(vd, d, false),
                            sources: one,
                        })
                    }
                    _ => None,
                },
                _ => None,
            };
        }
        None
    }

    fn kind(self) -> Vfp {
        match self {
            Self::MoveSingle { .. } => Vfp::Move,
            Self::MoveDouble { .. } => Vfp::MoveDouble,
            Self::StatusToCore { .. } => Vfp::Status,
            // As `text` names them.
            Self::Multiple { load: false, base: 13, write_back: true, before: true, .. } => {
                Vfp::Push
            }
            Self::Multiple { load: true, base: 13, write_back: true, before: false, .. } => {
                Vfp::Pop
            }
            Self::Multiple { before: true, .. } => Vfp::Multiple(Step::DecrementBefore),
            Self::Multiple { before: false, .. } => Vfp::Multiple(Step::IncrementAfter),
            Self::Compute { operation, .. } if operation.is_compare() => Vfp::Compare,
            Self::Compute { .. } | Self::MoveConstant { .. } => Vfp::Compute,
        }
    }

    fn text(self) -> (String, String) {
        let vector = |double: bool, number: u32| {
            if double { format!("d{number}") } else { format!("s{number}") }
        };
        let core = |number: u32| ARM_REGISTERS[number as usize];
        match self {
            Self::MoveSingle { to_core: true, core: rt, single } => {
                ("vmov".into(), format!("{}, s{single}", core(rt)))
            }
            Self::MoveSingle { to_core: false, core: rt, single } => {
                ("vmov".into(), format!("s{single}, {}", core(rt)))
            }
            Self::MoveDouble { to_core: true, low, high, double } => {
                ("vmov".into(), format!("{}, {}, d{double}", core(low), core(high)))
            }
            Self::MoveDouble { to_core: false, low, high, double } => {
                ("vmov".into(), format!("d{double}, {}, {}", core(low), core(high)))
            }
            Self::StatusToCore { core: 15 } => ("vmrs".into(), "APSR_nzcv, fpscr".into()),
            Self::StatusToCore { core: rt } => ("vmrs".into(), format!("{}, fpscr", core(rt))),
            Self::Multiple { load, base, write_back, before, first, count, double } => {
                let list: Vec<String> =
                    (first..first + count).map(|number| vector(double, number)).collect();
                let list = format!("{{{}}}", list.join(", "));
                match (load, base, write_back, before) {
                    (false, 13, true, true) => ("vpush".into(), list),
                    (true, 13, true, false) => ("vpop".into(), list),
                    _ => {
                        let name = format!(
                            "v{}m{}",
                            if load { "ld" } else { "st" },
                            if before { "db" } else { "ia" }
                        );
                        let bang = if write_back { "!" } else { "" };
                        (name, format!("{}{bang}, {list}", core(base)))
                    }
                }
            }
            Self::MoveConstant { dest, bits } => {
                let value = if dest.double {
                    f64::from_bits(bits)
                } else {
                    f64::from(f32::from_bits(bits as u32))
                };
                let size = if dest.double { "f64" } else { "f32" };
                (format!("vmov.{size}"), format!("{}, #{value:?}", dest.text()))
            }
            Self::Compute { operation, size, dest, sources } => {
                let mut operands = vec![dest.text()];
                operands.extend(sources.iter().flatten().map(|source| source.text()));
                if operation.is_compare() && sources == [None, None] {
                    operands.push("0x0".into());
                }
                let name = operation.name();
                let name =
                    if size.is_empty() { name.to_string() } else { format!("{name}.{size}") };
                (name, operands.join(", "))
            }
        }
    }

    /// The IL form of this word. The VFP registers are [`il::Reg::Vector`]
    /// by number, `s` and `d` alike.
    fn lift(self) -> il::Lifted {
        use il::Op;
        let general = |number: u32| il_reg(Reg::from_u8(number as u8));
        let core = |number: u32| general(number).map_or(il::Operand::Other, il::Operand::Reg);
        let vector = |number: u32| il::Reg::Vector(number as u8);
        let mut lifted = il::Lifted::default();
        match self {
            Self::MoveSingle { to_core, core: rt, single } => {
                lifted.op = Op::Move;
                let (dest, source) = if to_core {
                    (core(rt), il::Operand::Reg(vector(single)))
                } else {
                    (il::Operand::Reg(vector(single)), core(rt))
                };
                lifted.operands = [dest, source].into_iter().collect();
            }
            Self::MoveDouble { to_core, low, high, double } => {
                lifted.op = Op::Move;
                let pair = [core(low), core(high)];
                let vector = il::Operand::Reg(vector(double));
                lifted.operands = if to_core {
                    pair.into_iter().chain([vector]).collect()
                } else {
                    [vector].into_iter().chain(pair).collect()
                };
            }
            Self::StatusToCore { core: rt } => {
                lifted.op = Op::Move;
                lifted.operands = [core(rt)].into_iter().collect();
                if rt == 15 {
                    lifted.writes.insert(il::Reg::Flags);
                }
            }
            Self::Multiple { load, base, write_back, before, first, count, double } => {
                lifted.op = if load { Op::Load } else { Op::Store };
                let offset =
                    if before { -i64::from(count * if double { 8 } else { 4 }) } else { 0 };
                let memory = il::Operand::Memory { base: general(base), offset: Some(offset) };
                lifted.operands = [il::Operand::RegisterList, memory].into_iter().collect();
                let kind = if load { il::AccessKind::Load } else { il::AccessKind::Store };
                let width = if double { il::Width::Bits64 } else { il::Width::Bits32 };
                lifted.memory = Some(il::MemoryAccess { kind, width: Some(width) });
                let moved = if load { &mut lifted.writes } else { &mut lifted.reads };
                (first..first + count).for_each(|number| moved.insert(vector(number)));
                if write_back {
                    general(base).into_iter().for_each(|reg| lifted.writes.insert(reg));
                }
                general(base).into_iter().for_each(|reg| lifted.reads.insert(reg));
                return lifted;
            }
            Self::MoveConstant { dest, bits } => {
                lifted.op = Op::Move;
                let dest = il::Operand::Reg(vector(dest.number));
                lifted.operands = [dest, il::Operand::Const(bits)].into_iter().collect();
            }
            Self::Compute { dest, sources, operation, .. } => {
                lifted.op = operation.op();
                let vector = |register: Vector| il::Operand::Reg(vector(register.number));
                let values = sources.iter().flatten().map(|&source| vector(source));
                lifted.operands = [vector(dest)].into_iter().chain(values).collect();
                if operation.is_compare() {
                    if sources == [None, None] {
                        lifted.operands.push(il::Operand::Const(0));
                    }
                    // A compare writes only the VFP flags, which `vmrs`
                    // moves on: it reads every value it names.
                    for operand in lifted.operands.clone() {
                        if let il::Operand::Reg(reg) = operand {
                            lifted.reads.insert(reg);
                        }
                    }
                    return lifted;
                }
                // `vmla` and kin add to their destination.
                if operation.adds_to_destination() {
                    lifted.reads.insert(il::Reg::Vector(dest.number as u8));
                }
            }
        }
        // A move or computation reads every operand but the first, and
        // writes the first: two for a move of a double to core registers.
        let written = match self {
            Self::MoveDouble { to_core: true, .. } => 2,
            _ => 1,
        };
        for (index, operand) in lifted.operands.clone().iter().enumerate() {
            if let il::Operand::Reg(reg) = operand {
                if index < written { lifted.writes.insert(*reg) } else { lifted.reads.insert(*reg) }
            }
        }
        lifted
    }
}

/// The bits of the float that the 8-bit constant of a VFP `vmov` stands
/// for: `VFPExpandImm` of the Arm architecture manual. The constant holds a
/// sign, three bits of exponent and four of fraction.
fn expand_float_constant(constant: u32, double: bool) -> u64 {
    let constant = u64::from(constant);
    let sign = constant >> 7;
    let b = constant >> 6 & 1;
    let low_exponent = constant >> 4 & 0b11;
    let fraction = constant & 0b1111;
    // The exponent is NOT(b), then b again and again, then the two bits.
    let (repeats, width, fraction_shift) = if double { (8, 64, 48) } else { (5, 32, 19) };
    let copies = if b == 1 { (1 << repeats) - 1 } else { 0 };
    let exponent = (b ^ 1) << (repeats + 2) | copies << 2 | low_exponent;
    sign << (width - 1) | exponent << (width - 1 - (repeats + 3)) | fraction << fraction_shift
}

/// Which instruction set a word given as A32 came in. A T32 VFP or NEON
/// word reads as its A32 twin, but no other T32 word does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Encoding {
    A32,
    /// A wide T32 word, its halfwords swapped and its NEON prefix made A32.
    T32,
}

/// The names of the general registers, as the decoder prints them.
const ARM_REGISTERS: [&str; 16] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "sb", "sl", "fp", "ip", "sp", "lr", "pc",
];

/// The top byte of an A32 NEON element or structure load or store.
pub(super) const NEON_LOAD_STORE: u32 = 0xf4;

/// The name for an A32 `word` the decoder cannot read: [`NEON_MNEMONIC`]
/// for NEON data processing, `1111 001U`, else [`UNKNOWN_MNEMONIC`].
pub(super) fn unread_mnemonic(word: u32) -> &'static str {
    if is_neon_data(word) { NEON_MNEMONIC } else { UNKNOWN_MNEMONIC }
}

/// What [`Insn::opcode`] holds for an A32 `word` the decoder cannot read.
fn unread_opcode(word: u32) -> super::Opcode {
    if is_neon_data(word) { super::Opcode::Arm(Decoded::NeonData) } else { super::Opcode::None }
}

/// NEON data processing, `1111 001U`.
fn is_neon_data(word: u32) -> bool {
    word >> 25 == 0b111_1001
}

/// Read an A32 NEON element or structure load or store:
///
/// ```text
/// 1111 0100 A D L 0 Rn Vd type size align Rm
/// ```
///
/// `A` clear moves whole structures, set moves one lane or all lanes. `Rm`
/// says how the base moves after: 15 not at all, 13 by the size moved, any
/// other by that register.
fn decode_neon_load_store(word: u32) -> Option<(String, String)> {
    let access = NeonAccess::of(word)?;
    let lane = match access.lanes {
        Lanes::Whole => String::new(),
        Lanes::All => "[]".to_string(),
        Lanes::One(lane) => format!("[{lane}]"),
    };
    let list: Vec<String> =
        access.registers().map(|register| format!("d{register}{lane}")).collect();
    let alignment = access.alignment.map(|bits| format!(":{bits}")).unwrap_or_default();
    let base = format!("[{}{alignment}]", ARM_REGISTERS[access.base as usize]);
    let address = match access.index {
        0b1111 => base,
        0b1101 => format!("{base}!"),
        index => format!("{base}, {}", ARM_REGISTERS[index as usize]),
    };
    let operation = if access.load { "vld" } else { "vst" };
    Some((
        format!("{operation}{}.{}", access.structures, 8 << access.size),
        format!("{{{}}}, {address}", list.join(", ")),
    ))
}

/// Lift an A32 `word` the decoder refuses but [`decode_fallback`] reads,
/// where it moves data: the VFP and NEON loads and stores. A T32 caller
/// gives the A32 form of its word.
pub(super) fn lift_fallback(word: u32, encoding: Encoding) -> Option<il::Lifted> {
    let field = |shift: u32, width: u32| word >> shift & ((1 << width) - 1);
    if encoding == Encoding::A32
        && word >> 28 != 0b1111
        && let Some(integer) = IntegerWord::of(word)
    {
        let mut lifted = integer.lift();
        if word >> 28 != 0b1110 {
            lifted.reads.insert(il::Reg::Flags);
        }
        return Some(lifted);
    }
    if word >> 28 != 0b1111
        && let Some(vfp) = VfpWord::of(word)
    {
        let mut lifted = vfp.lift();
        if word >> 28 != 0b1110 {
            lifted.reads.insert(il::Reg::Flags);
        }
        return Some(lifted);
    }
    let general = |number: u32| il_reg(Reg::from_u8(number as u8));
    let mut reads = il::RegSet::EMPTY;
    let mut writes = il::RegSet::EMPTY;

    let (load, width, values, memory): (bool, il::Width, il::Operand, il::Operand) =
        if word >> 24 == NEON_LOAD_STORE {
            let access = NeonAccess::of(word)?;
            let base = general(access.base);
            base.into_iter().for_each(|reg| reads.insert(reg));
            // `Rm` 15 leaves the base, 13 steps it by the size moved, and any
            // other register steps it by that register.
            let offset = match access.index {
                0b1111 => Some(0),
                0b1101 => {
                    base.into_iter().for_each(|reg| writes.insert(reg));
                    Some(0)
                }
                index => {
                    base.into_iter().for_each(|reg| writes.insert(reg));
                    general(index).into_iter().for_each(|reg| reads.insert(reg));
                    None
                }
            };
            let moved = if access.load { &mut writes } else { &mut reads };
            access.registers().for_each(|number| moved.insert(il::Reg::Vector(number as u8)));
            let width = match access.size {
                0 => il::Width::Bits8,
                1 => il::Width::Bits16,
                2 => il::Width::Bits32,
                _ => il::Width::Bits64,
            };
            let memory = il::Operand::Memory { base, offset };
            (access.load, width, il::Operand::RegisterList, memory)
        } else {
            // `vldr` and `vstr`: 1101 U D 0 L Rn Vd 101 sz imm8.
            let (_, _, decoded) = decode_fallback(word, encoding)?;
            if !matches!(decoded, Decoded::Vfp { vfp: Vfp::Load | Vfp::Store, .. }) {
                return None;
            }
            let double = field(8, 1) == 1;
            let (d, vd) = (field(22, 1), field(12, 4));
            let register = il::Reg::Vector(if double { d << 4 | vd } else { vd << 1 | d } as u8);
            let base = general(field(16, 4));
            base.into_iter().for_each(|reg| reads.insert(reg));
            let load = field(20, 1) == 1;
            if load {
                writes.insert(register)
            } else {
                reads.insert(register)
            }
            let offset = i64::from(field(0, 8) * 4);
            let offset = if field(23, 1) == 1 { offset } else { -offset };
            let width = if double { il::Width::Bits64 } else { il::Width::Bits32 };
            let memory = il::Operand::Memory { base, offset: Some(offset) };
            (load, width, il::Operand::Reg(register), memory)
        };
    if word >> 28 != 0b1110 && word >> 24 != NEON_LOAD_STORE {
        reads.insert(il::Reg::Flags);
    }
    let (op, kind) = if load {
        (il::Op::Load, il::AccessKind::Load)
    } else {
        (il::Op::Store, il::AccessKind::Store)
    };
    Some(il::Lifted {
        op,
        reads,
        writes,
        memory: Some(il::MemoryAccess { kind, width: Some(width) }),
        test: None,
        operands: [values, memory].into_iter().collect(),
    })
}

/// The fields of an A32 NEON element or structure load or store.
struct NeonAccess {
    load: bool,
    structures: u32,
    /// The first `d` register, and how many follow it, how far apart.
    first: u32,
    count: u32,
    spacing: u32,
    /// The element size, as a power of two of bytes.
    size: u32,
    lanes: Lanes,
    /// The base register, and `Rm`, which says how the base moves after.
    base: u32,
    index: u32,
    /// The alignment the access asserts, in bits, as `[r3:64]` prints it.
    alignment: Option<u32>,
}

impl NeonAccess {
    fn of(word: u32) -> Option<Self> {
        let field = |shift: u32, width: u32| word >> shift & ((1 << width) - 1);
        let first = field(22, 1) << 4 | field(12, 4);
        let (structures, registers, spacing, size, lanes) = if field(23, 1) == 0 {
            let (structures, registers, spacing) = match field(8, 4) {
                0b0111 => (1, 1, 1),
                0b1010 => (1, 2, 1),
                0b0110 => (1, 3, 1),
                0b0010 => (1, 4, 1),
                0b1000 => (2, 2, 1),
                0b1001 => (2, 2, 2),
                0b0011 => (2, 4, 1),
                0b0100 => (3, 3, 1),
                0b0101 => (3, 3, 2),
                0b0000 => (4, 4, 1),
                0b0001 => (4, 4, 2),
                _ => return None,
            };
            (structures, registers, spacing, field(6, 2), Lanes::Whole)
        } else {
            let structures = field(8, 2) + 1;
            match field(10, 2) {
                // To all lanes: `T` doubles the count of a `vld1`, and spaces
                // the others.
                0b11 => {
                    let doubled = field(5, 1) == 1;
                    let (registers, spacing) = match (structures, doubled) {
                        (1, true) => (2, 1),
                        (_, true) => (structures, 2),
                        (_, false) => (structures, 1),
                    };
                    (structures, registers, spacing, field(6, 2), Lanes::All)
                }
                size => {
                    let index_align = field(4, 4);
                    let spacing = match size {
                        1 if index_align & 0b10 != 0 => 2,
                        2 if index_align & 0b100 != 0 => 2,
                        _ => 1,
                    };
                    let lane = index_align >> (size + 1);
                    (structures, structures, spacing, size, Lanes::One(lane))
                }
            }
        };
        Some(Self {
            load: field(21, 1) == 1,
            structures,
            first,
            count: registers,
            spacing,
            size,
            lanes,
            base: field(16, 4),
            index: field(0, 4),
            alignment: Self::alignment(word, structures, size, lanes),
        })
    }

    /// The alignment the `align` field of `word` asserts, in bits, by the
    /// tables of `VLD1` to `VLD4` in the Arm architecture manual.
    fn alignment(word: u32, structures: u32, size: u32, lanes: Lanes) -> Option<u32> {
        let field = |shift: u32, width: u32| word >> shift & ((1 << width) - 1);
        let bits = match lanes {
            Lanes::Whole => match field(4, 2) {
                0 => 0,
                align => 32 << align,
            },
            Lanes::All => match (field(4, 1), structures, size) {
                (0, ..) => 0,
                (_, 1, _) => 8 << size,
                (_, 2, _) => 16 << size,
                (_, 4, 0) => 32,
                (_, 4, 1 | 2) => 64,
                // A size of `11` moves words, aligned to 128 bits.
                (_, 4, _) => 128,
                _ => 0,
            },
            Lanes::One(_) => {
                let index_align = field(4, 4);
                match (structures, size, index_align & 0b11) {
                    (1, 1, align) if align & 1 == 1 => 16,
                    (1, 2, 0b11) => 32,
                    (2, size, align) if align & 1 == 1 => 16 << size,
                    (4, 0, align) if align & 1 == 1 => 32,
                    (4, 1, align) if align & 1 == 1 => 64,
                    (4, 2, 0b01) => 64,
                    (4, 2, 0b10) => 128,
                    _ => 0,
                }
            }
        };
        (bits != 0).then_some(bits)
    }

    /// The numbers of the `d` registers moved.
    fn registers(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.count).map(|index| self.first + index * self.spacing)
    }
}

/// Which lanes of its registers a NEON load or store moves.
#[derive(Clone, Copy)]
enum Lanes {
    /// Whole registers.
    Whole,
    /// One element, copied to every lane.
    All,
    /// The one lane given.
    One(u32),
}

/// Read `rA, rB`, the two sources of a three-register operation.
fn parse_three(text: &str) -> Option<(&str, &str)> {
    let (left, right) = text.split_once(',')?;
    let right = right.trim();
    (!right.contains(',')).then(|| (left.trim(), right))
}

/// How `pc` reads in one instruction set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PcModel {
    /// How far past an instruction `pc` reads.
    ahead: u64,
    /// Whether a load from `[pc, imm]` rounds `pc` down to a word first.
    aligns_literal_loads: Alignment,
}

/// Whether an address rounds down to a word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Alignment {
    AsIs,
    ToWord,
}

impl PcModel {
    /// A32: `pc` reads two instructions, 8 bytes, ahead.
    pub(super) const A32: Self = Self { ahead: 8, aligns_literal_loads: Alignment::AsIs };
    /// T32: `pc` reads 4 bytes ahead, and a literal load rounds it down to a
    /// word.
    pub(super) const T32: Self = Self { ahead: 4, aligns_literal_loads: Alignment::ToWord };

    /// What `pc` reads in the instruction at `address`.
    pub(super) fn of(self, address: u64) -> u64 {
        address.wrapping_add(self.ahead)
    }

    /// What `pc` reads in a load from `[pc, imm]` at `address`.
    pub(super) fn of_literal_load(self, address: u64) -> u64 {
        match self.aligns_literal_loads {
            Alignment::AsIs => self.of(address),
            Alignment::ToWord => self.of(address) & !3,
        }
    }
}

/// Whether `body` opens with LLD's range extension thunk, a function by
/// itself:
///
/// ```text
/// movw ip, lo
/// movt ip, hi
/// add  ip, pc         ; A32 writes `add ip, ip, pc`
/// bx   ip
/// ```
///
/// A thunk that nothing in this build calls still starts there, and a run of
/// them otherwise reads as one function. A library that mixes A32 and
/// Thumb-2 holds both kinds.
pub(super) fn is_long_thunk(body: &[Insn]) -> bool {
    let [movw, movt, add, bx, ..] = body else { return false };
    is_plain(movw, Opcode::MOV)
        && movw.operands.starts_with("ip, 0x")
        && is_plain(movt, Opcode::MOVT)
        && movt.operands.starts_with("ip, ")
        && is_plain(add, Opcode::ADD)
        && matches!(add.operands.as_str(), "ip, pc" | "ip, ip, pc")
        && is_plain(bx, Opcode::BX)
        && bx.operands == "ip"
}

/// Where the range extension thunk that `body` opens with jumps: the value
/// `movw` and `movt` build, plus `pc` at the `add`, without the T32 bit.
fn long_thunk_target(body: &[Insn], pc: PcModel) -> Option<u64> {
    if !is_long_thunk(body) {
        return None;
    }
    let low = parse_hex(body[0].operands.strip_prefix("ip, ")?)?;
    let high = parse_hex(body[1].operands.strip_prefix("ip, ")?)?;
    let distance = (high << 16 | low) as u32;
    let pc = pc.of(body[2].address) as u32;
    Some(u64::from(pc.wrapping_add(distance) & !1))
}

/// The calls of `insns`, the tail calls, and the jump of a range extension
/// thunk to where it formed. See [`super::Arch::call_targets`].
pub(super) fn call_targets_through_thunks(
    insns: &[Insn],
    pc: PcModel,
) -> Vec<(usize, Option<super::CallTarget>)> {
    insns
        .iter()
        .enumerate()
        .filter_map(|(index, insn)| match insn.kind {
            InsnKind::Call { target } => Some((index, target.map(super::CallTarget::Address))),
            InsnKind::Jump { target: Some(target) } if super::leaves(insns, target) => {
                Some((index, Some(super::CallTarget::Address(target))))
            }
            InsnKind::Jump { target: None } if index >= 3 => {
                long_thunk_target(&insns[index - 3..], pc)
                    .map(|target| (index, Some(super::CallTarget::Address(target))))
            }
            _ => None,
        })
        .collect()
}

/// The addresses of the pool words `insns` load, where `pc` reads as `pc` says.
pub(super) fn pool_words_loaded(insns: &[Insn], pc: PcModel) -> Vec<u64> {
    pool_loads(insns, pc).into_iter().map(|(_, word)| word).collect()
}

/// Each instruction of `insns` that loads from a literal pool, as its
/// address and the address of a word it loads.
pub(super) fn pool_loads(insns: &[Insn], pc: PcModel) -> Vec<(u64, u64)> {
    let mut loads = Vec::new();
    for insn in insns {
        let count = match decoded(insn) {
            Some(Decoded::Core { opcode: Opcode::LDR, .. }) => 1,
            Some(Decoded::Vfp { vfp: Vfp::Load, .. }) if insn.operands.starts_with('s') => 1,
            Some(
                Decoded::Core { opcode: Opcode::LDRD, .. } | Decoded::Vfp { vfp: Vfp::Load, .. },
            ) => 2,
            _ => continue,
        };
        let Some((_, reference)) = insn.operands.rsplit_once('[') else { continue };
        let Some(("pc", Offset::Immediate(offset))) = parse_reference(&format!("[{reference}"))
        else {
            continue;
        };
        let pool = pc.of_literal_load(insn.address).wrapping_add(offset as u64);
        loads.extend(
            (0..count).map(|word| (insn.address, pool.wrapping_add(word * WORD_WIDTH as u64))),
        );
    }
    loads
}

/// What reading a function for its pool words found.
pub(super) struct PoolWords {
    /// See [`Arch::constant_kinds`].
    pub(super) kinds: Vec<ConstantKind>,
    /// The addresses inside the image the function forms or loads whole.
    pub(super) addresses: Vec<u64>,
    /// The address each instruction forms or reads, where one does.
    pub(super) formed: Vec<Option<u64>>,
    /// The pool words the function adds to a base, as PIC code adds one to
    /// `pc`: each holds a distance, not an address.
    pub(super) distances: BTreeSet<u64>,
}

/// Read `body` for the pool words that make addresses. See
/// [`Arm32::constant_kinds`].
pub(super) fn track_pool_words(
    code: &[u8],
    body: &[Insn],
    space: &AddressSpace,
    pc_model: PcModel,
) -> PoolWords {
    let mut kinds = vec![ConstantKind::Value; body.len()];
    let mut formed = vec![None; body.len()];
    let mut addresses = Vec::new();
    // Pool words whose value lies in the image, by where they sit. PIC code
    // adds such a word to `pc`, and then the value is only a distance.
    let mut whole: Vec<(u64, u64)> = Vec::new();
    let mut distances: BTreeSet<u64> = BTreeSet::new();
    let Some(start) = body.first().map(|insn| insn.address) else {
        return PoolWords { kinds, addresses, formed, distances };
    };

    // Registers holding a pool word: where the word sits, and its value.
    let mut literal: Vec<(&str, u64, u32)> = Vec::new();
    // Registers holding an address built from `pc` and a pool word.
    let mut relative: Vec<(&str, u64)> = Vec::new();
    // Registers holding a value built by `movw` and `movt`, with where the
    // two are. LLD's range extension thunks for T32 add such a value to `pc`:
    // `movw ip, lo; movt ip, hi; add ip, pc; bx ip`.
    let mut halves: Vec<(&str, [usize; 2], u32)> = Vec::new();

    let word_at = |pool: u64| -> Option<u32> {
        let offset = usize::try_from(pool.checked_sub(start)?).ok()?;
        let bytes = code.get(offset..offset.checked_add(WORD_WIDTH)?)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    };

    for (index, insn) in body.iter().enumerate() {
        let opcode = core_opcode(insn);
        let Some((destination, rest)) = insn.operands.split_once(',') else { continue };
        let (destination, rest) = (destination.trim(), rest.trim());
        let pc = pc_model.of(insn.address);

        // `movw rX, lo` then `movt rX, hi`: a 32-bit value in two halves.
        // Any other write ends it, but for the `add rX, pc` that uses it.
        let builds_halves = matches!(opcode, Some(Opcode::MOV | Opcode::MOVT));
        // A32 writes the `add` with three operands.
        let adds_pc = opcode == Some(Opcode::ADD)
            && (rest == "pc"
                || rest.strip_prefix(destination).and_then(|rest| rest.strip_prefix(", "))
                    == Some("pc"));
        let uses_halves = adds_pc;
        if writes_first_operand(insn) && !builds_halves && !uses_halves {
            halves.retain(|(held, ..)| *held != destination);
        }
        match opcode {
            Some(Opcode::MOV) if !rest.contains(',') => {
                halves.retain(|(held, ..)| *held != destination);
                if let Some(low) = parse_hex(rest).filter(|&low| low <= 0xffff) {
                    halves.push((destination, [index, index], low as u32));
                }
            }
            Some(Opcode::MOVT) => {
                let high = parse_hex(rest).filter(|&high| high <= 0xffff);
                match (high, halves.iter_mut().find(|(held, ..)| *held == destination)) {
                    (Some(high), Some((_, at, value))) => {
                        at[1] = index;
                        *value = (*value & 0xffff) | ((high as u32) << 16);
                        // Code that is not PIC builds an address whole, as
                        // Cortex-M firmware does for its globals. A value in
                        // the image is one, as a word in a pool is.
                        if at[0] != at[1] && space.contains(u64::from(*value)) {
                            addresses.push(u64::from(*value));
                            formed[index] = Some(u64::from(*value));
                            for at in *at {
                                kinds[at] = ConstantKind::Address;
                            }
                        }
                    }
                    _ => halves.retain(|(held, ..)| *held != destination),
                }
                continue;
            }
            // `add rX, pc` of a value in both halves forms an address.
            Some(Opcode::ADD) if adds_pc => {
                let whole =
                    halves.iter().find(|(held, at, _)| *held == destination && at[0] != at[1]);
                if let Some(&(_, at, value)) = whole {
                    let address = pc.wrapping_add(i64::from(value as i32) as u64) & 0xffff_ffff;
                    if space.contains_formed(address) {
                        addresses.push(address);
                        formed[index] = Some(address);
                        for at in at {
                            kinds[at] = ConstantKind::Address;
                        }
                    }
                    halves.retain(|(held, ..)| *held != destination);
                    forget(&mut literal, &mut relative, destination);
                    relative.push((destination, address));
                    continue;
                }
            }
            _ => {}
        }
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
        let mut join = |base: u64, (pool, value): (u64, u32)| {
            let address = base.wrapping_add(i64::from(value as i32) as u64);
            distances.insert(pool);
            if space.contains_formed(address) {
                addresses.push(address);
                formed[index] = Some(address);
                if let Ok(index) = body.binary_search_by_key(&pool, |insn| insn.address) {
                    kinds[index] = ConstantKind::StoredAddress;
                }
            }
            address
        };

        // T32 writes `add rX, pc` for `add rX, rX, pc`. Only an `add` reads
        // three operands, so only it parses them.
        let two_operand_add;
        let three = match opcode {
            Some(Opcode::ADD) if !rest.contains(',') => {
                two_operand_add = format!("{destination}, {rest}");
                parse_three(&two_operand_add)
            }
            Some(Opcode::ADD) => parse_three(rest),
            _ => None,
        };
        let reference = match opcode {
            Some(Opcode::LDR) => parse_reference(rest),
            _ => None,
        };
        match (opcode, reference, three) {
            // `ldr rX, [pc, imm]`: load a pool word.
            (Some(Opcode::LDR), Some(("pc", Offset::Immediate(offset))), _) => {
                let pool = pc_model.of_literal_load(insn.address).wrapping_add(offset as u64);
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
            (Some(Opcode::MOV), _, _) if !rest.contains(',') => {
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
            (Some(Opcode::LDR), Some((base, Offset::Register(index))), _) => {
                if let (Some(base), Some(word)) = (base_of(base), literal_of(index)) {
                    join(base, word);
                }
            }
            // `add rY, base, rX`, either order: build an address.
            (Some(Opcode::ADD), _, Some((left, right))) => {
                let joined =
                    match (base_of(left), literal_of(right), base_of(right), literal_of(left)) {
                        (Some(base), Some(word), ..) | (.., Some(base), Some(word)) => {
                            Some((base, word))
                        }
                        _ => None,
                    };
                if let Some((base, word)) = joined {
                    let address = join(base, word);
                    forget(&mut literal, &mut relative, destination);
                    relative.push((destination, address));
                    continue;
                }
            }
            _ => {}
        }

        if writes_first_operand(insn) {
            forget(&mut literal, &mut relative, destination);
        }
    }

    let stored: Vec<(u64, u64)> =
        whole.into_iter().filter(|(pool, _)| !distances.contains(pool)).collect();
    // In an image linked high, a pool word that holds an address in it is
    // that address, as Cortex-M firmware loads its globals. In a PIC library
    // linked at zero, such a word is more likely a number.
    if space.starts_high() {
        for &(pool, _) in &stored {
            if let Ok(index) = body.binary_search_by_key(&pool, |insn| insn.address) {
                kinds[index] = ConstantKind::StoredAddress;
            }
        }
    }
    addresses.extend(stored.into_iter().map(|(_, value)| value));
    PoolWords { kinds, addresses, formed, distances }
}

/// Stop following a register the instruction writes.
fn forget(literal: &mut Vec<(&str, u64, u32)>, relative: &mut Vec<(&str, u64)>, register: &str) {
    literal.retain(|(held, ..)| *held != register);
    relative.retain(|(held, _)| *held != register);
}

/// Report whether `insn` writes its first operand. Stores, compares and
/// branches read it.
fn writes_first_operand(insn: &Insn) -> bool {
    !matches!(
        core_opcode(insn),
        Some(
            Opcode::STR
                | Opcode::STRB
                | Opcode::STRH
                | Opcode::STRD
                | Opcode::PUSH
                | Opcode::STM(true, false, ..)
                | Opcode::STM(false, true, ..)
                | Opcode::CMP
                | Opcode::CMN
                | Opcode::TST
                | Opcode::TEQ
                | Opcode::B
                | Opcode::BL
                | Opcode::BX
                | Opcode::BLX
        )
    )
}

/// Split rendered instruction text into the mnemonic and the rest.
pub(super) fn split_mnemonic(text: &str) -> (String, String) {
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
/// How `inst` moves control, where `target` is where a branch in it goes.
pub(super) fn classify(inst: &Instruction, target: Option<u64>) -> InsnKind {
    let unconditional = inst.condition == ConditionCode::AL;

    match inst.opcode {
        Opcode::BL | Opcode::BLX => InsnKind::Call { target },

        // `bx lr` returns; `bx <other>` is an indirect jump. A conditional
        // one falls through when its condition fails, as `bxeq lr` does in
        // an early exit, so it is a branch and does not end the function.
        Opcode::BX if !unconditional => InsnKind::Branch { target: None },
        Opcode::BX => match inst.operands[0] {
            Operand::Reg(reg) if reg.number() as u16 == REG_LR => InsnKind::Return,
            _ => InsnKind::Jump { target: None },
        },

        Opcode::B => {
            if unconditional {
                InsnKind::Jump { target }
            } else {
                InsnKind::Branch { target }
            }
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
mod unused_operand_tests {
    use super::*;

    #[test]
    fn a_compare_and_a_move_print_only_what_they_use() {
        let shown = |word: u32| {
            let code = word.to_le_bytes();
            let insn = Arm32.decode(&code, 0, 0).expect("decodes");
            format!("{} {}", insn.mnemonic, insn.operands)
        };
        // From `llvm-mc --triple=armv7`.
        assert_eq!(shown(0xe153_0002), "cmp r3, r2");
        assert_eq!(shown(0x1350_0007), "cmpne r0, 0x7");
        assert_eq!(shown(0xe311_0003), "tst r1, 0x3");
        assert_eq!(shown(0xe3e0_0000), "mvn r0, 0x0");
        assert_eq!(shown(0xe1a0_4201), "mov r4, r1, lsl 4");
        assert_eq!(shown(0xe1a0_7000), "mov r7, r0");
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

    /// Encodings from `llvm-mc --triple=armv7a --show-encoding`.
    mod words {
        pub const CMP_R0_1: [u8; 4] = [0x01, 0x00, 0x50, 0xe3];
        pub const BLT: [u8; 4] = [0x02, 0x00, 0x00, 0xba];
        pub const CMP_R0_0: [u8; 4] = [0x00, 0x00, 0x50, 0xe3];
        pub const BLE: [u8; 4] = [0x02, 0x00, 0x00, 0xda];
        pub const CMN_R1_1: [u8; 4] = [0x01, 0x00, 0x71, 0xe3];
        pub const BNE: [u8; 4] = [0x02, 0x00, 0x00, 0x1a];
        pub const TST_R2_4: [u8; 4] = [0x04, 0x00, 0x12, 0xe3];
        pub const BEQ: [u8; 4] = [0x02, 0x00, 0x00, 0x0a];
        pub const ADD_R0_R1_R2: [u8; 4] = [0x02, 0x00, 0x81, 0xe0];
        pub const LDR_R1_R2_8: [u8; 4] = [0x08, 0x10, 0x92, 0xe5];
        pub const LDR_R1_R2_POST: [u8; 4] = [0x04, 0x10, 0x92, 0xe4];
        pub const STR_R3_R4_R5: [u8; 4] = [0x05, 0x30, 0x84, 0xe7];
        pub const PUSH_R4_LR: [u8; 4] = [0x10, 0x40, 0x2d, 0xe9];
        pub const POP_R4_PC: [u8; 4] = [0x10, 0x80, 0xbd, 0xe8];
        pub const BL: [u8; 4] = [0x40, 0x00, 0x00, 0xeb];
        pub const STREX_R1_R2_R3: [u8; 4] = [0x92, 0x1f, 0x83, 0xe1];
        pub const UMULL: [u8; 4] = [0x92, 0x03, 0x81, 0xe0];
        pub const MOVT_R4: [u8; 4] = [0x34, 0x42, 0x41, 0xe3];
        pub const ADDEQ_R0: [u8; 4] = [0x01, 0x00, 0x80, 0x02];
        pub const LDRD_R2_R3_SP: [u8; 4] = [0xd8, 0x20, 0xcd, 0xe1];
    }

    fn lift_one(bytes: [u8; 4]) -> il::Lifted {
        Arm32.lift(&decode_one(bytes), &bytes).expect("the word must lift")
    }

    #[test]
    fn a_list_access_names_its_order() {
        let name = |word: u32| decode_one(word.to_le_bytes()).mnemonic;
        assert_eq!(name(0xe890_0006), "ldm", "increment after");
        assert_eq!(name(0xe990_0006), "ldmib");
        assert_eq!(name(0x1990_0006), "ldmibne");
        assert_eq!(name(0xe980_0006), "stmib");
        assert_eq!(name(0xe910_0006), "ldmdb");
        assert_eq!(name(0xe810_0006), "ldmda");
    }

    #[test]
    fn operands_come_in_printed_order() {
        use il::Operand::{Const, RegisterList, Target};
        let reg = |number| il::Operand::Reg(il::Reg::General(number));
        let operands = |bytes| lift_one(bytes).operands.into_vec();
        assert_eq!(operands(words::ADD_R0_R1_R2), [reg(0), reg(1), reg(2)]);
        assert_eq!(operands(words::CMP_R0_1), [reg(0), Const(1)], "no unused destination");
        assert_eq!(operands(words::PUSH_R4_LR), [il::Operand::Reg(il::Reg::Stack), RegisterList]);
        assert_eq!(operands(words::BL), [Target]);
    }

    #[test]
    fn a_memory_operand_names_its_base_and_offset() {
        use il::Operand::Memory;
        let general = |number| Some(il::Reg::General(number));
        let memory = |bytes| *lift_one(bytes).operands.last().expect("a memory operand");
        // `ldr r1, [r2, #-8]`
        const LDR_R1_R2_MINUS_8: [u8; 4] = [0x08, 0x10, 0x12, 0xe5];
        assert_eq!(memory(words::LDR_R1_R2_8), Memory { base: general(2), offset: Some(8) });
        assert_eq!(memory(LDR_R1_R2_MINUS_8), Memory { base: general(2), offset: Some(-8) });
        assert_eq!(memory(words::STR_R3_R4_R5), Memory { base: general(4), offset: None });
        assert_eq!(
            memory(words::LDRD_R2_R3_SP),
            Memory { base: Some(il::Reg::Stack), offset: Some(8) }
        );
    }

    #[test]
    fn the_frame_registers_are_sp_and_r11() {
        assert!(Arm32.is_frame_register(il::Reg::Stack));
        assert!(Arm32.is_frame_register(il::Reg::General(11)));
        assert!(!Arm32.is_frame_register(il::Reg::General(7)));
    }

    fn regs(numbers: &[u8]) -> il::RegSet {
        numbers
            .iter()
            .map(|&number| match number {
                13 => il::Reg::Stack,
                number => il::Reg::General(number),
            })
            .collect()
    }

    fn guard_of(words: &[[u8; 4]]) -> Option<il::Guard> {
        let lifted: Vec<Option<il::Lifted>> =
            words.iter().map(|&word| Some(lift_one(word))).collect();
        il::find_guards(&lifted).first().map(|found| found.guard)
    }

    /// Clang tests `x < 1` where GCC tests `x <= 0`, and both are one test.
    #[test]
    fn a_compare_and_its_branch_are_one_guard() {
        let clang = guard_of(&[words::CMP_R0_1, words::BLT]).unwrap();
        let gcc = guard_of(&[words::CMP_R0_0, words::BLE]).unwrap();
        assert_eq!(clang.cond, il::Cond::SignedLess);
        assert_eq!(clang.width, il::Width::Bits32);
        assert_eq!(clang.canonical(), gcc.canonical());
    }

    #[test]
    fn cmn_with_one_compares_with_minus_one() {
        let guard = guard_of(&[words::CMN_R1_1, words::BNE]).unwrap();
        assert_eq!(guard.right, il::Value::Const(0xffff_ffff));
    }

    #[test]
    fn tst_with_beq_tests_bits() {
        let guard = guard_of(&[words::TST_R2_4, words::BEQ]).unwrap();
        assert_eq!((guard.cond, guard.right), (il::Cond::BitsClear, il::Value::Const(4)));
    }

    #[test]
    fn a_conditional_instruction_reads_the_flags() {
        let lifted = lift_one(words::ADDEQ_R0);
        assert!(lifted.reads.contains(il::Reg::Flags));
        assert_eq!(lifted.test, None);
        assert_eq!(guard_of(&[words::CMP_R0_0, words::ADDEQ_R0, words::BEQ]), None);
    }

    #[test]
    fn registers_and_memory_are_named() {
        let add = lift_one(words::ADD_R0_R1_R2);
        assert_eq!((add.reads, add.writes), (regs(&[1, 2]), regs(&[0])));

        let load = lift_one(words::LDR_R1_R2_8);
        assert_eq!((load.reads, load.writes), (regs(&[2]), regs(&[1])));
        assert_eq!(load.memory.map(|access| access.kind), Some(il::AccessKind::Load));
        assert_eq!(lift_one(words::LDR_R1_R2_POST).writes, regs(&[1, 2]), "written back");

        let store = lift_one(words::STR_R3_R4_R5);
        assert_eq!((store.reads, store.writes), (regs(&[3, 4, 5]), il::RegSet::EMPTY));
        assert_eq!(store.memory.map(|access| access.kind), Some(il::AccessKind::Store));

        let push = lift_one(words::PUSH_R4_LR);
        assert_eq!((push.reads, push.writes), (regs(&[4, 13, 14]), regs(&[13])));
        let pop = lift_one(words::POP_R4_PC);
        assert_eq!((pop.reads, pop.writes), (regs(&[13]), regs(&[4, 13])), "the pc is no register");

        assert_eq!(lift_one(words::BL).writes, regs(&[14]));
        let exclusive = lift_one(words::STREX_R1_R2_R3);
        assert_eq!((exclusive.reads, exclusive.writes), (regs(&[2, 3]), regs(&[1])));
        let long = lift_one(words::UMULL);
        assert_eq!((long.reads, long.writes), (regs(&[2, 3]), regs(&[0, 1])));
        let movt = lift_one(words::MOVT_R4);
        assert_eq!((movt.reads, movt.writes), (regs(&[4]), regs(&[4])));
        let pair = lift_one(words::LDRD_R2_R3_SP);
        assert_eq!((pair.reads, pair.writes), (regs(&[13]), regs(&[2, 3])));
    }

    #[test]
    fn lifting_any_word_never_panics() {
        bolero::check!().with_type::<u32>().for_each(|&word| {
            let bytes = word.to_le_bytes();
            let insn = Arm32.decode(&bytes, 0, 0).expect("every word decodes or is unknown");
            if let Some(lifted) = Arm32.lift(&insn, &bytes)
                && let Some(il::Test::Guard(_) | il::Test::OnFlags(_)) = lifted.test
            {
                assert!(
                    matches!(insn.kind, InsnKind::Branch { .. }),
                    "{insn}: a test that branches"
                );
            }
        });
    }

    /// The text of the A32 instruction `word`.
    fn text_of(word: u32) -> (String, String) {
        let insn = decode_one(word.to_le_bytes());
        (insn.mnemonic, insn.operands)
    }

    #[test]
    fn mov_r0_r0_is_padding_as_a_core_before_armv6k_pads() {
        let filler = decode_one(0xe1a0_0000u32.to_le_bytes());
        assert_eq!((filler.mnemonic.as_str(), filler.operands.as_str()), ("mov", "r0, r0"));
        assert!(Arm32.is_padding(&filler));
        let copy = decode_one(0xe1a0_0001u32.to_le_bytes());
        assert!(!Arm32.is_padding(&copy), "mov r0, r1 does work");
    }

    #[test]
    fn an_a32_thunk_is_an_entry_and_names_where_it_jumps() {
        // movw ip, 0xb3b; movt ip, 0xffff; add ip, ip, pc; bx ip
        let words = [0xe300_cb3bu32, 0xe34f_cfff, 0xe08c_c00f, 0xe12f_ff1c];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = decode_all(&Arm32, &code, 0x2f6c8);
        assert!(Arm32.is_function_entry(&insns));
        // `pc` at the `add` is 0x2f6d0 + 8, and 0xffff_0b3b, without the
        // T32 bit, takes it back before the thunk.
        let target = 0x2f6d8u32.wrapping_add(0xffff_0b3b) & !1;
        assert_eq!(
            Arm32.call_targets(&insns),
            [(3, Some(crate::arch::CallTarget::Address(u64::from(target))))]
        );
    }

    #[test]
    fn neon_loads_and_stores_of_whole_registers_read() {
        let cases = [
            (0xf420_070f, "vld1.8", "{d0}, [r0]"),
            (0xf441_0a8d, "vst1.32", "{d16, d17}, [r1]!"),
            (0xf422_0142, "vld4.16", "{d0, d2, d4, d6}, [r2], r2"),
        ];
        for (word, mnemonic, operands) in cases {
            assert_eq!(text_of(word), (mnemonic.into(), operands.into()), "{word:#010x}");
            assert_eq!(decode_one(word.to_le_bytes()).kind, InsnKind::Normal);
        }
    }

    #[test]
    fn neon_loads_of_lanes_read() {
        assert_eq!(text_of(0xf4a1_0c8f), ("vld1.32".into(), "{d0[]}, [r1]".into()), "all lanes");
        assert_eq!(
            text_of(0xf4a0_0762),
            ("vld4.16".into(), "{d0[1], d2[1], d4[1], d6[1]}, [r0], r2".into()),
            "one lane, every second register"
        );
    }

    #[test]
    fn an_undefined_neon_load_stays_unknown() {
        let insn = decode_one(0xf420_0b0fu32.to_le_bytes());
        assert_eq!((insn.mnemonic.as_str(), insn.kind), (UNKNOWN_MNEMONIC, InsnKind::Unknown));
        assert!(!Arm32.is_unread_extension(&insn));
    }

    #[test]
    fn neon_data_processing_stays_opaque_but_is_code() {
        let insn = decode_one(0xf260_0680u32.to_le_bytes());
        assert_eq!((insn.mnemonic.as_str(), insn.kind), (NEON_MNEMONIC, InsnKind::Unknown));
        assert_eq!(insn.operands, "0xf2600680", "the word keeps an edit visible");
        assert!(Arm32.is_unread_extension(&insn));
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

    /// Code that is not PIC builds an address whole with `movw` and `movt`.
    #[test]
    fn a_whole_address_built_in_two_halves_is_an_address() {
        // movw r2, 0x9de8; movt r2, 0x800
        let words = [0xe309_2de8_u32, 0xe340_2800];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = crate::arch::decode_all(&Arm32, &code, 0x0800_0000);
        let space = AddressSpace::of_raw_image(0x0800_0000, 0x1_0000);
        let kinds = Arm32.constant_kinds(&code, &insns, &space);
        assert_eq!(kinds, [ConstantKind::Address, ConstantKind::Address]);
        let number = AddressSpace::of_raw_image(0x0900_0000, 0x1_0000);
        assert_eq!(Arm32.constant_kinds(&code, &insns, &number)[0], ConstantKind::Value);
    }

    /// In an image linked high, a pool word that holds an address in it is
    /// that address; in one linked at zero, it may be a number.
    #[test]
    fn a_pool_word_holds_an_address_only_in_an_image_linked_high() {
        let pool_word_at = |base: u64| {
            // ldr r0, [pc, -0x4]: the word right after it, which holds an
            // address 0x100 into the image.
            let words = [0xe51f_0004_u32, (base + 0x100) as u32];
            let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            let (insns, _) = crate::arch::decode_all(&Arm32, &code, base);
            let space = AddressSpace::of_raw_image(base, 0x2000);
            Arm32.constant_kinds(&code, &insns, &space)[1]
        };
        assert_eq!(pool_word_at(0x0800_0000), ConstantKind::StoredAddress);
        assert_eq!(pool_word_at(0), ConstantKind::Value);
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

    /// `yaxpeax` reads `mvn r0, #1` with an unused field, as
    /// `mvn r0, r0, 0x1`.
    #[test]
    fn a_not_of_a_constant_is_a_move_of_the_inverse() {
        let lifted = lift_one([0x01, 0x00, 0xe0, 0xe3]);
        assert_eq!(lifted.op, il::Op::Move);
        let inverse = il::Operand::Const(0xffff_fffe);
        assert_eq!(lifted.operands.as_slice(), [il::Operand::Reg(il::Reg::General(0)), inverse]);
        assert!(lifted.reads.is_empty(), "no register is read");
        // `mvn r1, r2` stays a not.
        assert_eq!(lift_one([0x02, 0x10, 0xe0, 0xe1]).op, il::Op::Not);
    }

    #[test]
    fn an_exclusive_access_is_atomic() {
        assert_eq!(lift_one(words::STREX_R1_R2_R3).op, il::Op::Atomic);
        // `ldrex r1, [r2]`
        assert_eq!(lift_one([0x9f, 0x1f, 0x92, 0xe1]).op, il::Op::Atomic);
        assert_eq!(lift_one(words::LDR_R1_R2_8).op, il::Op::Load);
    }

    /// `rsb` subtracts the other way round: `rsb r0, r1, #1` is `1 - r1`.
    #[test]
    fn a_reverse_subtract_names_its_values_in_order() {
        let general = |number| il::Operand::Reg(il::Reg::General(number));
        let lifted = lift_one([0x01, 0x00, 0x61, 0xe2]);
        assert_eq!(lifted.op, il::Op::Subtract);
        assert_eq!(lifted.operands.as_slice(), [general(0), il::Operand::Const(1), general(1)]);
    }

    /// `yaxpeax` reads no VFP or NEON load or store, so they lift from the
    /// fields [`decode_fallback`] reads.
    #[test]
    fn a_vfp_load_and_store_lift() {
        // `vldr d16, [pc, 0x90]`, as GCC loads a double from its pool.
        let load = lift_fallback(0xeddf_0b24, Encoding::A32).expect("vldr lifts");
        assert_eq!(load.op, il::Op::Load);
        assert_eq!(load.memory.and_then(|access| access.width), Some(il::Width::Bits64));
        let pool = il::Operand::Memory { base: None, offset: Some(0x90) };
        assert_eq!(load.operands.as_slice(), [il::Operand::Reg(il::Reg::Vector(16)), pool]);
        assert_eq!(load.writes, [il::Reg::Vector(16)].into_iter().collect());
        // `vstr s0, [sp, -0x4]`
        let store = lift_fallback(0xed0d_0a01, Encoding::A32).expect("vstr lifts");
        assert_eq!(store.op, il::Op::Store);
        let slot = il::Operand::Memory { base: Some(il::Reg::Stack), offset: Some(-4) };
        assert_eq!(store.operands[1], slot);
        assert_eq!(store.reads, [il::Reg::Stack, il::Reg::Vector(0)].into_iter().collect());
        assert!(store.writes.is_empty());
    }

    #[test]
    fn a_neon_load_writes_its_list_and_steps_its_base() {
        // `vld1.8 {d16, d17}, [r0]!`
        let load = lift_fallback(0xf460_0a0d, Encoding::A32).expect("vld1 lifts");
        assert_eq!(load.op, il::Op::Load);
        assert_eq!(load.memory.and_then(|access| access.width), Some(il::Width::Bits8));
        let base = il::Operand::Memory { base: Some(il::Reg::General(0)), offset: Some(0) };
        assert_eq!(load.operands.as_slice(), [il::Operand::RegisterList, base]);
        let written = [il::Reg::General(0), il::Reg::Vector(16), il::Reg::Vector(17)];
        assert_eq!(load.writes, written.into_iter().collect());
    }

    /// A hint is no access, and lifts to nothing.
    #[test]
    fn a_hint_lifts_to_nothing() {
        assert_eq!(lift_fallback(0xe320_f000, Encoding::A32), None, "nop");
    }

    #[test]
    fn what_the_fallback_lifts_it_decodes() {
        bolero::check!().with_type::<u32>().for_each(|&word| {
            if lift_fallback(word, Encoding::A32).is_some() {
                assert!(decode_fallback(word, Encoding::A32).is_some(), "{word:#010x}");
            }
        });
    }

    fn fallback_text(word: u32) -> Option<String> {
        decode_fallback(word, Encoding::A32).map(|(name, operands, _)| format!("{name} {operands}"))
    }

    /// Words `yaxpeax` 0.4 refuses, as `llvm-mc` reads them.
    #[test]
    fn reads_the_integer_words_the_decoder_refuses() {
        assert_eq!(fallback_text(0xe6ef_3073).as_deref(), Some("uxtb r3, r3"));
        assert_eq!(fallback_text(0xe6af_307e).as_deref(), Some("sxtb r3, lr"));
        assert_eq!(fallback_text(0xe6ff_0070).as_deref(), Some("uxth r0, r0"));
        assert_eq!(fallback_text(0xe7df_171f).as_deref(), Some("bfc r1, 0xe, 0x12"));
        assert_eq!(fallback_text(0xe7d6_3712).as_deref(), Some("bfi r3, r2, 0xe, 0x9"));
        assert_eq!(fallback_text(0xe7e8_0757).as_deref(), Some("ubfx r0, r7, 0xe, 0x9"));
        assert_eq!(fallback_text(0xe1a0_0011).as_deref(), Some("mov r0, r1, lsl r0"));
        assert_eq!(fallback_text(0xe1e0_a31c).as_deref(), Some("mvn sl, ip, lsl r3"));
        assert_eq!(fallback_text(0xe1d2_20d0).as_deref(), Some("ldrsb r2, [r2]"));
    }

    /// A wide T32 word is no A32 integer word, whatever its bits.
    #[test]
    fn a_t32_word_is_not_read_as_an_a32_integer_word() {
        assert!(decode_fallback(0xe6ef_3073, Encoding::T32).is_none());
        assert!(lift_fallback(0xe6ef_3073, Encoding::T32).is_none());
    }

    #[test]
    fn the_integer_words_lift() {
        let general = |number| il::Operand::Reg(il::Reg::General(number));
        let lift = |word| lift_fallback(word, Encoding::A32).expect("the word lifts");
        let extend = lift(0xe6ef_3073);
        assert_eq!(
            (extend.op, extend.operands.as_slice()),
            (il::Op::Extend, &[general(3), general(3)][..])
        );
        let insert = lift(0xe7d6_3712);
        assert_eq!(insert.op, il::Op::BitField);
        assert_eq!(insert.reads, [2, 3].map(il::Reg::General).into_iter().collect(), "keeps rd");
        let extract = lift(0xe7e8_0757);
        let field = [general(0), general(7), il::Operand::Const(14), il::Operand::Const(9)];
        assert_eq!(extract.operands.as_slice(), field);
        let shift = lift(0xe1a0_0011);
        assert_eq!(
            (shift.op, shift.operands.as_slice()),
            (il::Op::ShiftLeft, &[general(0), general(1), general(0)][..])
        );
        let load = lift(0xe1d2_20d0);
        assert_eq!(load.memory.and_then(|access| access.width), Some(il::Width::Bits8));
        let at = il::Operand::Memory { base: Some(il::Reg::General(2)), offset: Some(0) };
        assert_eq!(load.operands.as_slice(), [general(2), at]);
    }

    /// A conditional word reads the flags.
    #[test]
    fn a_conditional_integer_word_reads_the_flags() {
        // `uxtbne r3, r3`
        let lifted = lift_fallback(0x16ef_3073, Encoding::A32).expect("the word lifts");
        assert!(lifted.reads.contains(il::Reg::Flags));
        assert_eq!(fallback_text(0x16ef_3073).as_deref(), Some("uxtbne r3, r3"));
    }

    /// `yaxpeax` swaps `bb` and `tt` of the multiplies of halfwords, and
    /// reads `smulwb` as `smlawb`; all 16 forms read as `llvm-mc` reads
    /// them.
    #[test]
    fn the_multiplies_of_halfwords_read_as_encoded() {
        let cases = [
            (0xe107_3182, "smlabb r7, r2, r1, r3"),
            (0xe107_31a2, "smlatb r7, r2, r1, r3"),
            (0xe107_31c2, "smlabt r7, r2, r1, r3"),
            (0xe107_31e2, "smlatt r7, r2, r1, r3"),
            (0xe127_3182, "smlawb r7, r2, r1, r3"),
            (0xe127_31a2, "smulwb r7, r2, r1"),
            (0xe127_31c2, "smlawt r7, r2, r1, r3"),
            (0xe127_31e2, "smulwt r7, r2, r1"),
            (0xe147_3182, "smlalbb r3, r7, r2, r1"),
            (0xe147_31a2, "smlaltb r3, r7, r2, r1"),
            (0xe147_31c2, "smlalbt r3, r7, r2, r1"),
            (0xe147_31e2, "smlaltt r3, r7, r2, r1"),
            (0xe167_3182, "smulbb r7, r2, r1"),
            (0xe167_31a2, "smultb r7, r2, r1"),
            (0xe167_31c2, "smulbt r7, r2, r1"),
            (0xe167_31e2, "smultt r7, r2, r1"),
        ];
        for (word, text) in cases {
            let insn = Arm32.decode(&u32::to_le_bytes(word), 0, 0).expect("the word reads");
            assert_eq!(format!("{} {}", insn.mnemonic, insn.operands), text, "{word:#010x}");
        }
        let lift = |word: u32| {
            let bytes = word.to_le_bytes();
            Arm32.lift(&Arm32.decode(&bytes, 0, 0).unwrap(), &bytes).expect("the word lifts")
        };
        let general = il::Reg::General;
        // `smulwb r7, r2, r1` multiplies and adds nothing.
        let word = lift(0xe127_31a2);
        assert_eq!(word.op, il::Op::Multiply);
        assert_eq!(word.reads, [general(2), general(1)].into_iter().collect());
        // `smlalbb r3, r7, r2, r1` adds to the pair, and writes both.
        let long = lift(0xe147_3182);
        assert_eq!(long.op, il::Op::MultiplyAdd);
        assert_eq!(long.writes, [general(3), general(7)].into_iter().collect());
        assert_eq!(
            long.reads,
            [general(1), general(2), general(3), general(7)].into_iter().collect()
        );
    }

    /// A NEON load names the alignment it asserts, as `llvm-mc` reads it:
    /// whole structures, all lanes and one lane. A sweep of 510 encodings
    /// agreed with `llvm-mc` when this was written.
    #[test]
    fn a_neon_load_names_its_alignment() {
        let cases = [
            (0xf423_0a0f, "vld1.8 {d0, d1}, [r3]"),
            (0xf423_0a1f, "vld1.8 {d0, d1}, [r3:64]"),
            (0xf423_0a2f, "vld1.8 {d0, d1}, [r3:128]"),
            (0xf423_023f, "vld1.8 {d0, d1, d2, d3}, [r3:256]"),
            (0xf4a3_0f9f, "vld4.32 {d0[], d1[], d2[], d3[]}, [r3:64]"),
            (0xf4a3_0c5f, "vld1.16 {d0[]}, [r3:16]"),
            (0xf4a3_041f, "vld1.16 {d0[0]}, [r3:16]"),
            (0xf4a3_0baf, "vld4.32 {d0[1], d1[1], d2[1], d3[1]}, [r3:128]"),
        ];
        for (word, text) in cases {
            assert_eq!(fallback_text(word).as_deref(), Some(text), "{word:#010x}");
        }
    }

    /// VFP words `yaxpeax` 0.4 refuses, as `llvm-mc` reads them.
    #[test]
    fn reads_the_vfp_words_the_decoder_refuses() {
        let cases = [
            (0xeebd_0be0, "vcvt.s32.f64 s0, d16"),
            (0xeef8_0bc0, "vcvt.f64.s32 d16, s0"),
            (0xeef8_0b40, "vcvt.f64.u32 d16, s0"),
            (0xeef5_0b40, "vcmp.f64 d16, 0x0"),
            (0xee40_1ba2, "vmla.f64 d17, d16, d18"),
            (0xec51_0b30, "vmov r0, r1, d16"),
            (0xec41_0b30, "vmov d16, r0, r1"),
            (0xee10_0a10, "vmov r0, s0"),
            (0xee00_1a10, "vmov s0, r1"),
            (0xeef1_fa10, "vmrs APSR_nzcv, fpscr"),
            (0xed2d_8b04, "vpush {d8, d9}"),
            (0xecbd_8b04, "vpop {d8, d9}"),
            (0xeef7_0a00, "vmov.f32 s1, #1.0"),
            (0xeeb8_0b00, "vmov.f64 d0, #-2.0"),
            (0xeef0_0b48, "vmov.f64 d16, d8"),
        ];
        for (word, text) in cases {
            assert_eq!(fallback_text(word).as_deref(), Some(text), "{word:#010x}");
        }
    }

    /// `yaxpeax` reads these words but drops an operand, so the decoder
    /// reads them itself, in A32 and in T32.
    #[test]
    fn the_vfp_words_the_decoder_misreads_keep_their_operands() {
        let cases = [
            (0xeef7_0a00_u32, "vmov.f32", "s1, #1.0"),
            (0xeef0_0b48, "vmov.f64", "d16, d8"),
            (0xeeb8_0b40, "vcvt.f64.u32", "d0, s0"),
            (0x1eb7_0b00, "vmov.f64ne", "d0, #1.0"),
        ];
        for (word, mnemonic, operands) in cases {
            let insn = Arm32.decode(&word.to_le_bytes(), 0, 0).expect("the word reads");
            assert_eq!((insn.mnemonic.as_str(), insn.operands.as_str()), (mnemonic, operands));
            if word >> 28 == 0b1110 {
                let halves = [(word >> 16) as u16, word as u16];
                let bytes: Vec<u8> = halves.iter().flat_map(|half| half.to_le_bytes()).collect();
                let insn = super::super::thumb::Thumb2.decode(&bytes, 0, 0).expect("reads");
                assert_eq!((insn.mnemonic.as_str(), insn.operands.as_str()), (mnemonic, operands));
            }
        }
        let constant = Arm32
            .lift(
                &Arm32.decode(&0xeef7_0a00_u32.to_le_bytes(), 0, 0).unwrap(),
                &0xeef7_0a00_u32.to_le_bytes(),
            )
            .expect("the word lifts");
        assert_eq!(constant.op, il::Op::Move);
        assert_eq!(
            constant.operands.as_slice(),
            [il::Operand::Reg(il::Reg::Vector(1)), il::Operand::Const(0x3f80_0000)]
        );
        assert_eq!(constant.writes, [il::Reg::Vector(1)].into_iter().collect());
    }

    /// Each of the 256 constants of a VFP `vmov` stands for the same value
    /// as a single and as a double: a sign, then 16 to 31 sixteenths times
    /// a power of two from 2^-3 to 2^4.
    #[test]
    fn a_vfp_constant_is_the_same_value_at_both_sizes() {
        for constant in 0..=255 {
            let single = f64::from(f32::from_bits(expand_float_constant(constant, false) as u32));
            let double = f64::from_bits(expand_float_constant(constant, true));
            assert_eq!(single, double, "{constant:#x}");
            let exponent = (i32::from((constant >> 4 & 0b111) as u8) ^ 0b100) - 3;
            let sixteenths = f64::from(16 + (constant & 0b1111));
            let sign = if constant >> 7 == 1 { -1.0 } else { 1.0 };
            assert_eq!(double, sign * sixteenths / 16.0 * 2f64.powi(exponent), "{constant:#x}");
        }
    }

    /// T32 encodes the VFP as A32 does, so a T32 caller reads them too.
    #[test]
    fn a_t32_vfp_word_reads_as_its_a32_twin() {
        assert_eq!(
            decode_fallback(0xec51_0b30, Encoding::T32),
            decode_fallback(0xec51_0b30, Encoding::A32)
        );
        assert!(lift_fallback(0xec51_0b30, Encoding::T32).is_some());
    }

    #[test]
    fn the_vfp_words_lift() {
        let core = |number| il::Reg::General(number);
        let vector = il::Reg::Vector;
        let regs = |regs: &[il::Reg]| -> il::RegSet { regs.iter().copied().collect() };
        let lift = |word| lift_fallback(word, Encoding::A32).expect("the word lifts");
        // `vmov d16, r0, r1` writes the double from the pair.
        let to_double = lift(0xec41_0b30);
        assert_eq!(to_double.op, il::Op::Move);
        assert_eq!(
            (to_double.reads, to_double.writes),
            (regs(&[core(0), core(1)]), regs(&[vector(16)]))
        );
        // `vmov r0, r1, d16` writes the pair.
        let to_core = lift(0xec51_0b30);
        assert_eq!(
            (to_core.reads, to_core.writes),
            (regs(&[vector(16)]), regs(&[core(0), core(1)]))
        );
        // `vcmp.f64 d16, #0` writes only the VFP flags, and `vmrs` moves them.
        let compare = lift(0xeef5_0b40);
        assert_eq!(compare.op, il::Op::Float, "never an integer compare");
        assert_eq!((compare.reads, compare.writes), (regs(&[vector(16)]), il::RegSet::EMPTY));
        assert!(lift(0xeef1_fa10).writes.contains(il::Reg::Flags));
        // `vpush {d8, d9}` stores below `sp` and moves it.
        let push = lift(0xed2d_8b04);
        assert_eq!(push.op, il::Op::Store);
        let below = il::Operand::Memory { base: Some(il::Reg::Stack), offset: Some(-16) };
        assert_eq!(push.operands.as_slice(), [il::Operand::RegisterList, below]);
        assert_eq!(push.reads, regs(&[il::Reg::Stack, vector(8), vector(9)]));
        assert_eq!(push.writes, regs(&[il::Reg::Stack]));
        // `vcvt.s32.f64 s0, d16` converts into the single register.
        let convert = lift(0xeebd_0be0);
        assert_eq!(
            convert.operands.as_slice(),
            [il::Operand::Reg(vector(0)), il::Operand::Reg(vector(16))]
        );
    }

    #[test]
    fn a_vfp_operation_names_what_it_computes() {
        let op = |word| lift_fallback(word, Encoding::A32).expect("the word lifts").op;
        assert_eq!(op(0xee40_1ba2), il::Op::FloatMultiplyAdd, "vmla.f64");
        assert_eq!(op(0xeebd_0be0), il::Op::FloatRoundTowardZero, "vcvt.s32.f64");
        assert_eq!(op(0xeef8_0bc0), il::Op::FloatConvert, "vcvt.f64.s32");
        assert_eq!(op(0xeef5_0b40), il::Op::Float, "vcmp.f64");
    }

    #[test]
    fn a_function_opens_with_a_word_that_runs_always() {
        assert!(Arm32.can_open_function(&words::PUSH_R4_LR));
        assert!(!Arm32.can_open_function(&words::ADDEQ_R0), "conditional");
        assert!(!Arm32.can_open_function(&[0, 0]), "short");
    }
}
