//! The decoder and the lifter of T32, which read one instruction at a
//! time, with the condition of the `it` that covers it, and know nothing
//! of the binary around it. The rules that read Thumb-2 code, as table
//! branches and the switch to A32 after `bx pc`, are in `hereticus`.

use crate::arch::arm32::{
    Arm32, Decoded, Encoding, Extend, Flags, IntegerWord, NEON_LOAD_STORE, NEON_TEXT, UNKNOWN_TEXT,
    classify, condition_name, decode_fallback, decoded_of, decoder_misreads, lift_named_with,
};
use crate::arch::{DecodeError, Decoder, Insn, InsnKind, Printing, split_printed};
use compact_str::CompactString;
use yaxpeax_arch::{Decoder as _, U8Reader};
use yaxpeax_arm::armv7::{ConditionCode, InstDecoder, Instruction, Opcode, Operand};

/// The text of `insn`, read again from its bytes, with the condition of
/// the `it` that covers it.
pub fn print(insn: &Insn) -> Option<String> {
    let (alone, text) = Thumb2.read(insn.bytes(), 0, insn.address, Printing::Text).ok()?;
    // [`Decoder::after_decoding`] writes the condition of an `it` into the
    // opcode, so an opcode that differs from the one read alone holds it.
    let covered = match insn.opcode {
        crate::arch::Opcode::Thumb(
            Decoded::Core { condition, .. } | Decoded::Vfp { condition, .. },
        ) if alone.opcode != insn.opcode => Some(condition),
        _ => None,
    };
    Some(match covered {
        Some(condition) => conditional_text(&text, insn.bytes_len, condition),
        None => text,
    })
}

/// `text`, of an instruction `width` bytes wide, as it prints where an
/// `it` makes it run on `code`.
///
/// `yaxpeax-arm` prints no condition inside the block, so `movgt r0, #0`
/// reads as `movs r0, 0x0`. A 16-bit form that sets the flags outside a
/// block does not inside one.
pub(crate) fn conditional_text(text: &str, width: usize, code: ConditionCode) -> String {
    let condition = condition_name(code);
    let (name, operands) = split_printed(text);
    let base = match width == HALFWORD && name.len() > 2 {
        true => name.strip_suffix('s').unwrap_or(name),
        false => name,
    };
    match base.ends_with(condition) {
        true => text.to_string(),
        false => format!("{base}{condition} {operands}"),
    }
}

/// The narrow T32 instruction, and the alignment of every one.
pub const HALFWORD: usize = 2;

/// The wide T32 instruction.
pub const WORD: usize = 4;

/// ARM32 in T32 (Thumb-2) mode.
#[derive(Clone, Copy, Debug, Default)]
pub struct Thumb2;

impl Thumb2 {
    /// Lift `insn`, with the name of each operand where `printing` asks for
    /// them, as [`Thumb2::read`] prints them.
    fn lift_as(self, insn: &Insn, printing: Printing) -> Option<crate::Named> {
        use crate::{Named, Names, Operand};
        use compact_str::format_compact;
        let word = insn.bytes();
        let halves = match *word {
            [low, high, second_low, second_high] => Some((
                u16::from_le_bytes([low, high]),
                u16::from_le_bytes([second_low, second_high]),
            )),
            _ => None,
        };
        let named = |names: &dyn Fn() -> Names| match printing {
            Printing::Skip => Names::new(),
            Printing::Text => names(),
        };
        if let Some(store) = halves.and_then(|(first, second)| wide_store(first, second)) {
            let names = named(&|| store.names());
            return Some(Named { lifted: store.lifted(), names, write_back: None });
        }
        if let Some(wide) = halves.and_then(|(first, second)| WideWord::of(first, second)) {
            let names = named(&|| wide.names());
            return Some(Named { lifted: wide.lifted(), names, write_back: None });
        }
        let a32 = match *word {
            [low, high, second_low, second_high] => {
                Some(as_a32(u32::from_le_bytes([second_low, second_high, low, high])))
            }
            _ => None,
        };
        let fallback = a32.map(|a32| (a32, Encoding::T32));
        let mut named =
            lift_named_with(InstDecoder::default_thumb(), insn, word, fallback, printing)?;
        // `yaxpeax-arm` misplaces `imm4` of `movw` and `movt`, so the
        // constant is read again from the encoding, as the text is.
        if let Some((first, second)) = halves
            && let Some(value) = wide_move_value(first, second)
            && let Some(at) = named
                .lifted
                .operands
                .iter()
                .rposition(|operand| matches!(operand, Operand::Const(_)))
        {
            named.lifted.operands[at] = Operand::Const(u64::from(value));
            if let Some(name) = named.names.get_mut(at) {
                *name = format_compact!("{value:#x}");
            }
            if let Some(name) = named.names.first_mut() {
                *name = REGISTER_NAMES[usize::from(second >> 8 & 0xf)].into();
            }
        }
        if printing == Printing::Skip {
            return Some(named);
        }
        // A target counts from this instruction, as [`with_target_text`]
        // prints it.
        let target = match insn.kind {
            InsnKind::Branch { target } | InsnKind::Jump { target } | InsnKind::Call { target } => {
                target
            }
            _ => None,
        };
        // A shift right by 32 encodes as one by 0: see [`shift_of_32`].
        let shifts_by_32 = halves.is_some_and(|(first, second)| {
            let amount = (second >> 12 & 0b111) << 2 | (second >> 6 & 0b11);
            first & 0xfe00 == 0xea00 && amount == 0 && matches!(second >> 4 & 0b11, 0b01 | 0b10)
        });
        // `tbb` and `tbh` index a table at `pc`; `yaxpeax-arm` 0.4 reads the
        // shift of `tbh` as one by a register: see [`table_branch`].
        let table = halves.and_then(|(first, second)| {
            let (_, _, opcode) = table_branch(first, second)?;
            let base = REGISTER_NAMES[usize::from(first & 0xf)];
            let index = REGISTER_NAMES[usize::from(second & 0xf)];
            Some(match opcode {
                Opcode::TBH => format_compact!("[{base} + ({index} lsl 1)]"),
                _ => format_compact!("[{base} + {index}]"),
            })
        });
        for (operand, name) in named.lifted.operands.iter().zip(named.names.iter_mut()) {
            match operand {
                Operand::Memory { .. } if table.is_some() => {
                    *name = table.clone().unwrap_or_default();
                }
                Operand::Target(_) => {
                    if let Some(target) = target {
                        *name = crate::target_name(target.wrapping_sub(insn.address) as i64);
                    }
                }
                Operand::Shifted { .. } if shifts_by_32 => {
                    if let Some(shifted) = name.strip_suffix(" 0)") {
                        *name = format_compact!("{shifted} 0x20)");
                    }
                }
                _ => {}
            }
        }
        Some(named)
    }

    /// The instruction at `offset` of `code`, which starts at `address`,
    /// and its text where `printing` asks for it. An instruction that an
    /// `it` covers reads as if it ran always: see [`Decoder::after_decoding`].
    pub fn read(
        self,
        code: &[u8],
        offset: usize,
        address: u64,
        printing: Printing,
    ) -> Result<(Insn, String), DecodeError> {
        let bytes = code.get(offset..).ok_or(DecodeError::Truncated)?;
        let first = bytes.get(..HALFWORD).ok_or(DecodeError::Truncated)?;
        let width = if is_wide(u16::from_le_bytes([first[0], first[1]])) { WORD } else { HALFWORD };
        let bytes = bytes.get(..width).ok_or(DecodeError::Truncated)?;
        let insn_address = address + offset as u64;

        let mut reader = U8Reader::new(bytes);
        let mut inst = Instruction::default();
        let failed = InstDecoder::default_thumb().decode_into(&mut inst, &mut reader).is_err();
        let misread = match *bytes {
            [low, high, second_low, second_high] => decoder_misreads(
                as_a32(u32::from_le_bytes([second_low, second_high, low, high])),
                Encoding::T32,
            ),
            _ => false,
        };
        if failed || inst.opcode == Opcode::Invalid || misread {
            // `yaxpeax-arm` 0.4 reads no VFP in T32 either. A wide T32 `vldr`
            // is the A32 word with the condition that means always, so the
            // A32 reading serves: without it, the doubles a `vldr` loads
            // after a return read as code, as in Lua's `os_clock`.
            let word = match *bytes {
                [low, high, second_low, second_high] => {
                    Some(u32::from_le_bytes([second_low, second_high, low, high]))
                }
                _ => None,
            };
            let fallback = word.and_then(|word| decode_fallback(as_a32(word), Encoding::T32));
            if let Some((name, operands, decoded)) = fallback {
                let opcode = crate::arch::Opcode::Thumb(decoded);
                let insn = Insn::new(insn_address, bytes, InsnKind::Normal, opcode);
                return Ok((insn, printing.text(|| format!("{name} {operands}"))));
            }
            // The width comes from the first halfword, so stepping over an
            // unreadable instruction keeps the rest aligned. Its bytes go in
            // the operands, so that an edit to it still shows.
            let is_neon = word.is_some_and(|word| matches!(word >> 24, 0xef | 0xff));
            let (name, opcode) = if is_neon {
                (NEON_TEXT, crate::arch::Opcode::Thumb(Decoded::NeonData))
            } else {
                (UNKNOWN_TEXT, crate::arch::Opcode::Unread(crate::arch::InstructionSet::Thumb))
            };
            let insn = Insn::new(insn_address, bytes, InsnKind::Unknown, opcode);
            let text = printing.text(|| {
                let operands: String =
                    bytes.iter().rev().map(|byte| format!("{byte:02x}")).collect();
                format!("{name} {operands}")
            });
            return Ok((insn, text));
        }

        // A wide instruction that this module reads in place of
        // `yaxpeax-arm`, as its halfwords.
        let halves = match *bytes {
            [low, high, second_low, second_high] => Some((
                u16::from_le_bytes([low, high]),
                u16::from_le_bytes([second_low, second_high]),
            )),
            _ => None,
        };
        let table = halves.and_then(|(first, second)| table_branch(first, second));
        let word = halves.and_then(|(first, second)| WideWord::of(first, second));
        let moves = halves.is_some_and(|(first, second)| wide_move_value(first, second).is_some());
        let store = halves.and_then(|(first, second)| wide_store(first, second));
        let decoded = match (&table, &word, moves, &store) {
            (Some((_, _, opcode)), ..) => always(*opcode, Flags::Kept),
            (None, Some(word), ..) => word.decoded(),
            (None, None, false, Some(store)) => store.decoded(),
            _ => decoded_of(&inst),
        };
        let target = branch_target(&inst, insn_address, width);
        let kind = match inst.opcode {
            Opcode::CBZ | Opcode::CBNZ => InsnKind::Branch { target },
            Opcode::TBB | Opcode::TBH => InsnKind::Jump { target: None },
            Opcode::IT => InsnKind::Normal,
            _ => classify(&inst, target),
        };
        let text = printing.text(|| {
            let printed = inst.to_string();
            let (name, operands) = split_printed(&printed);
            // `.w` only says the encoding is wide, which the length already
            // does, so the text leaves it out, as A32 does. A condition can
            // follow it, as in `b.wne`.
            let name = if name.contains('.') {
                without_suffix(&without_suffix(name, b'w'), b'n')
            } else {
                name.to_string()
            };
            let (name, operands) = match (table, word, halves) {
                (Some((table, operands, _)), ..) => (table.to_string(), operands),
                (None, Some(word), _) => word.text(),
                (None, None, Some((first, second))) => {
                    match (wide_move_operands(first, second), store) {
                        (Some(moved), _) => (name, moved),
                        (None, Some(store)) => (store.printed_name().to_string(), store.operands()),
                        (None, None) => (name, shift_of_32(first, second, operands.to_string())),
                    }
                }
                (None, None, None) => (name, operands.to_string()),
            };
            let operands = match target {
                Some(target) => with_target_text(&operands, insn_address, target),
                None => operands,
            };
            format!("{name} {operands}")
        });

        let insn = Insn::new(insn_address, bytes, kind, crate::arch::Opcode::Thumb(decoded));
        Ok((insn, text))
    }
}

impl Decoder for Thumb2 {
    fn operation_name(&self, insn: &Insn) -> CompactString {
        Arm32.operation_name(insn)
    }

    fn decode(&self, code: &[u8], offset: usize, address: u64) -> Result<Insn, DecodeError> {
        self.read(code, offset, address, Printing::Skip).map(|(insn, _)| insn)
    }

    fn triple(&self) -> &'static str {
        "thumbv7-linux-gnueabi"
    }

    /// The narrow width, which every instruction is a multiple of and is
    /// aligned to.
    fn instruction_width(&self) -> usize {
        HALFWORD
    }

    /// An `it` makes the next one to four instructions conditional: `itt`
    /// two, `itete` four. A return or a jump among them falls through when
    /// its condition fails, so it is a branch.
    fn after_decoding(&self, insns: &mut [Insn]) {
        // The conditions of the instructions an `it` covers, next first.
        let mut conditions: Vec<ConditionCode> = Vec::new();
        for insn in insns {
            if !conditions.is_empty() {
                let code = conditions.remove(0);
                insn.kind = match insn.kind {
                    InsnKind::Return => InsnKind::Branch { target: None },
                    InsnKind::Jump { target } => InsnKind::Branch { target },
                    kind => kind,
                };
                // A 16-bit form that sets the flags outside a block does
                // not inside one. [`print`] reads both from the opcode.
                let narrow = insn.bytes_len == HALFWORD;
                match &mut insn.opcode {
                    crate::arch::Opcode::Thumb(Decoded::Core { condition, flags, .. }) => {
                        *condition = code;
                        if narrow {
                            *flags = Flags::Kept;
                        }
                    }
                    crate::arch::Opcode::Thumb(Decoded::Vfp { condition, .. }) => *condition = code,
                    _ => {}
                }
            } else if let crate::arch::Opcode::Thumb(Decoded::It { condition, mask }) = insn.opcode
            {
                conditions = it_conditions(condition, mask).unwrap_or_default();
            }
        }
    }

    fn pointer_width(&self) -> usize {
        WORD
    }

    fn lift(&self, insn: &Insn) -> Option<crate::Lifted> {
        self.lift_as(insn, Printing::Skip).map(|named| named.lifted)
    }

    fn lift_named(&self, insn: &Insn) -> Option<crate::Named> {
        self.lift_as(insn, Printing::Text)
    }

    fn read_pointer(&self, bytes: &[u8]) -> u64 {
        u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

/// The operands of a T32 `movw` or `movt`, read from the encoding:
///
/// ```text
/// 11110 i 10 0 1 0 0 imm4 | 0 imm3 Rd imm8      movw
/// 11110 i 10 1 1 0 0 imm4 | 0 imm3 Rd imm8      movt
/// ```
///
/// The value is `imm4:i:imm3:imm8`. `yaxpeax-arm` 0.4 puts `imm4` four bits
/// too high, so `movw ip, 0xfaac` reads as `0xf0aac`. Most values a thunk
/// builds have `imm4` clear, so only a far jump, as from T32 to an A32
/// function, showed it.
pub(crate) fn wide_move_operands(first: u16, second: u16) -> Option<String> {
    let value = wide_move_value(first, second)?;
    let register = REGISTER_NAMES[usize::from(second >> 8 & 0xf)];
    Some(format!("{register}, {value:#x}"))
}

/// A T32 store of a register at an offset from a base, read from the
/// encoding:
///
/// ```text
/// 1111 1000 1 sz 0 Rn | Rt imm12      str.w, strh.w, strb.w
/// ```
///
/// `yaxpeax-arm` 0.4 reads these as the store at an offset in a register,
/// so `str.w r8, [sp, #0x1c]` read as `str r8, [sp, ip, lsl 1]`. The loads
/// of the same form read right.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WideStore {
    value: u16,
    base: u16,
    offset: u16,
    width: crate::Width,
}

impl WideStore {
    /// The name it prints with, by the width stored. `yaxpeax-arm` 0.4 names a store
    /// whose offset has the bits `1110` at 8 to 11 `strt`: `str.w r1, [r8,
    /// #0xec4]` read as `strt`.
    fn printed_name(self) -> &'static str {
        match self.width {
            crate::Width::Bits8 => "strb",
            crate::Width::Bits16 => "strh",
            _ => "str",
        }
    }

    fn decoded(self) -> Decoded {
        let opcode = match self.width {
            crate::Width::Bits8 => Opcode::STRB,
            crate::Width::Bits16 => Opcode::STRH,
            _ => Opcode::STR,
        };
        always(opcode, Flags::Kept)
    }

    /// The operands as the decoder prints those of a load.
    fn operands(self) -> String {
        let (value, base) =
            (REGISTER_NAMES[usize::from(self.value)], REGISTER_NAMES[usize::from(self.base)]);
        match self.offset {
            0 => format!("{value}, [{base}]"),
            offset => format!("{value}, [{base}, {offset:#x}]"),
        }
    }

    /// The name of each operand of [`WideStore::lifted`], as
    /// [`WideStore::operands`] prints it.
    fn names(self) -> crate::Names {
        use compact_str::format_compact;
        let (value, base) =
            (REGISTER_NAMES[usize::from(self.value)], REGISTER_NAMES[usize::from(self.base)]);
        let place = match self.offset {
            0 => format_compact!("[{base}]"),
            offset => format_compact!("[{base} + {offset:#x}]"),
        };
        [value.into(), place].into_iter().collect()
    }

    /// The store as the IL reads it.
    fn lifted(self) -> crate::Lifted {
        use crate::{AccessKind, Lifted, MemoryAccess, Op, Operand, Reg};
        let reg = |number: u16| match number {
            13 => Reg::Stack,
            number => Reg::General(number as u8),
        };
        let mut lifted = Lifted {
            op: Op::Store,
            memory: Some(MemoryAccess { kind: AccessKind::Store, width: Some(self.width) }),
            ..Lifted::default()
        };
        lifted.reads.insert(reg(self.value));
        lifted.reads.insert(reg(self.base));
        lifted.operands = [
            Operand::Reg(reg(self.value)),
            Operand::memory(Some(reg(self.base)), Some(i64::from(self.offset))),
        ]
        .into_iter()
        .collect();
        lifted
    }
}

/// The wide store at an offset that `first` and `second` encode, if they
/// encode one: see [`WideStore`].
pub(crate) fn wide_store(first: u16, second: u16) -> Option<WideStore> {
    use crate::Width;
    let width = match first & 0xfff0 {
        0xf8c0 => Width::Bits32,
        0xf8a0 => Width::Bits16,
        0xf880 => Width::Bits8,
        _ => return None,
    };
    let (value, base) = (second >> 12, first & 0xf);
    // `pc` as either is another encoding, or none.
    (value != 15 && base != 15).then_some(WideStore { value, base, offset: second & 0xfff, width })
}

/// The 16-bit value of a T32 `movw` or `movt`: see [`wide_move_operands`].
pub(crate) fn wide_move_value(first: u16, second: u16) -> Option<u32> {
    const MOVW: u16 = 0xf240;
    const MOVT: u16 = 0xf2c0;
    const OPCODE_MASK: u16 = 0xfbf0;
    if !matches!(first & OPCODE_MASK, MOVW | MOVT) || second & 0x8000 != 0 {
        return None;
    }
    let imm4 = u32::from(first & 0xf);
    let i = u32::from(first >> 10 & 1);
    let imm3 = u32::from(second >> 12 & 0b111);
    let imm8 = u32::from(second & 0xff);
    Some(imm4 << 12 | i << 11 | imm3 << 8 | imm8)
}

/// A wide T32 word that `yaxpeax-arm` 0.4 reads wrong, read from the
/// encoding. `tests/differential.rs` found each against `llvm-objdump`:
///
/// ```text
/// 1111 0i00 011S 1111 | 0 imm3 Rd imm8          mvn rd, #const
/// 1111 1010 0 ty S Rn | 1111 Rd 0000 Rm         lsl rd, rn, rm, and kin
/// 1111 1010 0 op Rn   | 1111 Rd 10 rot Rm       uxtb rd, rm, ror #8, and kin
/// 1111 0011 0110 Rn   | 0 imm3 Rd imm2 0 msb    bfi rd, rn, #lsb, #width
/// ```
///
/// It read `mvn` as `mov`, every shift by a register as `lsl`, the
/// rotation of an extend from the wrong bits, and `bfi` with its last bit
/// for its width. The shift, the extend and the insert are the operations
/// A32 encodes too, so they read and lift as [`IntegerWord`] does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WideWord {
    /// `mvn rd, #value`, or `mvns`.
    NotConstant { rd: u32, value: u32, sets_flags: bool },
    /// `lsl rd, rn, rm` and kin, or `lsls`.
    Shift { kind: u32, sets_flags: bool, rd: u32, rn: u32, rm: u32 },
    /// An extend or a bit field insert.
    Integer(IntegerWord),
}

impl WideWord {
    fn of(first: u16, second: u16) -> Option<Self> {
        let (first, second) = (u32::from(first), u32::from(second));
        let field = |half: u32, shift: u32, width: u32| half >> shift & ((1 << width) - 1);
        let rd = field(second, 8, 4);
        let rn = field(first, 0, 4);
        let rm = field(second, 0, 4);
        if first & 0xfbef == 0xf06f && second & 0x8000 == 0 {
            let constant =
                field(first, 10, 1) << 11 | field(second, 12, 3) << 8 | field(second, 0, 8);
            return Some(Self::NotConstant {
                rd,
                value: thumb_expand_constant(constant),
                sets_flags: field(first, 4, 1) == 1,
            });
        }
        if first & 0xff80 == 0xfa00 && second & 0xf0f0 == 0xf000 {
            let (kind, sets_flags) = (field(first, 5, 2), field(first, 4, 1) == 1);
            return Some(Self::Shift { kind, sets_flags, rd, rn, rm });
        }
        if first & 0xff80 == 0xfa00 && second & 0xf0c0 == 0xf080 {
            let kind = match field(first, 4, 3) {
                0b000 => Extend::Sxth,
                0b001 => Extend::Uxth,
                0b010 => Extend::Sxtb16,
                0b011 => Extend::Uxtb16,
                0b100 => Extend::Sxtb,
                0b101 => Extend::Uxtb,
                _ => return None,
            };
            let rn = (rn != 15).then_some(rn);
            let rotation = field(second, 4, 2) * 8;
            return Some(Self::Integer(IntegerWord::Extend { kind, rd, rn, rm, rotation }));
        }
        if first & 0xfff0 == 0xf360 && second & 0x8020 == 0 {
            let lsb = field(second, 12, 3) << 2 | field(second, 6, 2);
            let width = field(second, 0, 5).checked_sub(lsb)? + 1;
            let rn = (rn != 15).then_some(rn);
            return Some(Self::Integer(IntegerWord::Insert { rd, rn, lsb, width }));
        }
        None
    }

    fn decoded(self) -> Decoded {
        match self {
            Self::NotConstant { sets_flags, .. } => always(Opcode::MVN, Flags::of(sets_flags)),
            Self::Shift { kind, sets_flags, .. } => {
                let opcode = [Opcode::LSL, Opcode::LSR, Opcode::ASR, Opcode::ROR][kind as usize];
                always(opcode, Flags::of(sets_flags))
            }
            Self::Integer(word) => always(word.opcode(), word.flags()),
        }
    }

    /// The name and the operands, as the decoder prints them.
    fn text(self) -> (String, String) {
        let name = |number: u32| REGISTER_NAMES[number as usize];
        let flags = |sets_flags: bool| if sets_flags { "s" } else { "" };
        match self {
            Self::NotConstant { rd, value, sets_flags } => {
                (format!("mvn{}", flags(sets_flags)), format!("{}, {value:#x}", name(rd)))
            }
            Self::Shift { kind, sets_flags, rd, rn, rm } => {
                let shift = ["lsl", "lsr", "asr", "ror"][kind as usize];
                (
                    format!("{shift}{}", flags(sets_flags)),
                    format!("{}, {}, {}", name(rd), name(rn), name(rm)),
                )
            }
            Self::Integer(word) => (word.printed_name(), word.operands()),
        }
    }

    /// The name of each operand of [`WideWord::lifted`], as
    /// [`WideWord::text`] prints it.
    fn names(self) -> crate::Names {
        use compact_str::{CompactString, format_compact};
        let name = |number: u32| CompactString::from(REGISTER_NAMES[number as usize]);
        match self {
            Self::NotConstant { rd, value, .. } => {
                [name(rd), format_compact!("{value:#x}")].into_iter().collect()
            }
            Self::Shift { rd, rn, rm, .. } => [name(rd), name(rn), name(rm)].into_iter().collect(),
            Self::Integer(word) => word.names(),
        }
    }

    /// The IL form, as A32 lifts the same operation.
    fn lifted(self) -> crate::Lifted {
        use crate::{Lifted, Op, Operand, Reg};
        match self {
            // `mvn r0, #1` puts the constant `~1` in `r0`.
            Self::NotConstant { rd, value, sets_flags } => {
                let mut lifted = Lifted { op: Op::Move, ..Lifted::default() };
                let dest = match rd {
                    13 => Reg::Stack,
                    number => Reg::General(number as u8),
                };
                lifted.operands =
                    [Operand::Reg(dest), Operand::Const(u64::from(!value))].into_iter().collect();
                lifted.writes.insert(dest);
                if sets_flags {
                    lifted.writes.insert(Reg::Flags);
                }
                lifted
            }
            Self::Shift { kind, sets_flags, rd, rn, rm } => {
                IntegerWord::ShiftByRegister { not: false, sets_flags, rd, rm: rn, kind, rs: rm }
                    .lift()
            }
            Self::Integer(word) => word.lift(),
        }
    }
}

/// The 32-bit constant that the 12 bits of a T32 data processing word
/// stand for: `ThumbExpandImm` of the Arm architecture manual. A byte
/// repeated in a pattern, or a byte with its top bit set, rotated.
pub fn thumb_expand_constant(constant: u32) -> u32 {
    let byte = constant & 0xff;
    if constant >> 10 == 0 {
        return match constant >> 8 & 0b11 {
            0b00 => byte,
            0b01 => byte << 16 | byte,
            0b10 => byte << 24 | byte << 8,
            _ => byte * 0x0101_0101,
        };
    }
    (0x80 | constant & 0x7f).rotate_right(constant >> 7)
}

/// `operands` of a wide data processing word whose second value is
/// shifted, with a shift right of 0 put right: the encoding means 32.
///
/// ```text
/// 1110 101x xxxx Rn | 0 imm3 Rd imm2 type Rm
/// ```
///
/// `yaxpeax-arm` 0.4 prints the field, so `ands.w r3, r3, r1, asr #32`
/// read as `asr 0`.
pub(crate) fn shift_of_32(first: u16, second: u16, operands: String) -> String {
    let amount = (second >> 12 & 0b111) << 2 | (second >> 6 & 0b11);
    let kind = second >> 4 & 0b11;
    if first & 0xfe00 != 0xea00 || amount != 0 || !matches!(kind, 0b01 | 0b10) {
        return operands;
    }
    match operands.strip_suffix(" 0x0").or_else(|| operands.strip_suffix(" 0")) {
        Some(rest) => format!("{rest} 0x20"),
        None => operands,
    }
}

/// The T32 `tbb` or `tbh`, read from the encoding:
///
/// ```text
/// 1110 1000 1101 Rn | 1111 0000 000 H Rm
/// ```
///
/// `yaxpeax-arm` 0.4 reads `tbh [pc, r2, lsl 1]` as `tbb [pc, r2, lsl r0]`,
/// so a table of halfwords read as one of bytes. Measured on Lua built by GCC
/// at `-Os` for Thumb-2, the `tbh` of `luaV_execute` cut it in 19 pieces.
pub(crate) fn table_branch(first: u16, second: u16) -> Option<(&'static str, String, Opcode)> {
    const TABLE_BRANCH: u16 = 0xe8d0;
    if first & 0xfff0 != TABLE_BRANCH || second & 0xffe0 != 0xf000 {
        return None;
    }
    let base = REGISTER_NAMES[usize::from(first & 0xf)];
    let index = REGISTER_NAMES[usize::from(second & 0xf)];
    Some(match second >> 4 & 1 {
        0 => ("tbb", format!("[{base}, {index}]"), Opcode::TBB),
        _ => ("tbh", format!("[{base}, {index}, lsl 0x1]"), Opcode::TBH),
    })
}

/// `opcode`, with no condition: an `it` before it gives one later.
pub(crate) fn always(opcode: Opcode, flags: Flags) -> Decoded {
    Decoded::Core { opcode, condition: ConditionCode::AL, flags }
}

/// The names of the general registers, as `yaxpeax-arm` prints them.
pub(crate) const REGISTER_NAMES: [&str; 16] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "sb", "sl", "fp", "ip", "sp", "lr", "pc",
];

/// The A32 word for the wide T32 `word`, first halfword high, where the two
/// sets encode one instruction alike but for the top bits.
///
/// NEON data processing is `111U 1111` in T32 and `1111 001U` in A32, and a
/// NEON element or structure load or store is `1111 1001` in T32 and
/// `1111 0100` in A32. VFP is the same word in both, with the A32 condition
/// that means always.
pub(crate) fn as_a32(word: u32) -> u32 {
    const LOW: u32 = 0x00ff_ffff;
    match word >> 24 {
        0xef => 0xf200_0000 | word & LOW,
        0xff => 0xf300_0000 | word & LOW,
        0xf9 => NEON_LOAD_STORE << 24 | word & LOW,
        _ => word,
    }
}

/// Report whether the halfword `first` opens a 32-bit instruction.
pub(crate) fn is_wide(first: u16) -> bool {
    matches!(first >> 11, 0b11101..=0b11111)
}

/// Where a branch goes: `pc`, 4 bytes past the branch, plus twice the
/// offset it holds.
///
/// `yaxpeax` reports one more than the encoding holds for a narrow `cbz`,
/// `cbnz` and conditional `b`, and the encoding itself for the rest. A call
/// that switches to A32 goes to a word, so its target rounds down.
pub(crate) fn branch_target(inst: &Instruction, address: u64, width: usize) -> Option<u64> {
    let reported = inst.operands.iter().find_map(|operand| match operand {
        Operand::BranchThumbOffset(halfwords) => Some(i64::from(*halfwords)),
        _ => None,
    })?;
    let conditional = inst.condition != ConditionCode::AL;
    let biased = width == HALFWORD
        && (matches!(inst.opcode, Opcode::CBZ | Opcode::CBNZ)
            || (inst.opcode == Opcode::B && conditional));
    let halfwords = if biased { reported - 1 } else { reported };
    let pc = address as i64 + WORD as i64;
    let target = u64::try_from(pc + halfwords * HALFWORD as i64).ok()?;
    Some(if inst.opcode == Opcode::BLX { target & !3 } else { target })
}

/// `operands` with the distance `yaxpeax` prints, `$+0x2e`, put right: the
/// distance from the instruction to `target`.
///
/// `yaxpeax` 0.4 prints the offset of the encoding, which counts from the
/// program counter, 4 bytes on, and for a narrow conditional branch is one
/// halfword off besides: `bne $+0x2e` went to the instruction 0x30 on.
/// A32 prints the distance from the instruction, and so does this.
/// `name` with every `.` followed by `letter` taken out, as
/// `str::replace` would, but by a scan of bytes: a search for a string on
/// every instruction cost a sixth of a whole comparison.
pub fn without_suffix(name: &str, letter: u8) -> String {
    let bytes = name.as_bytes();
    let mut kept = String::with_capacity(name.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'.' && bytes.get(at + 1) == Some(&letter) {
            at += 2;
        } else {
            let next = name[at + 1..].find('.').map_or(bytes.len(), |dot| at + 1 + dot);
            kept.push_str(&name[at..next]);
            at = next;
        }
    }
    kept
}

/// `operands`, with the target they print named by its distance from
/// `address`, as `$+0x24`.
pub fn with_target_text(operands: &str, address: u64, target: u64) -> String {
    // A search for a byte, not for `"$+"`: this runs on every branch.
    let after_dollar = |sign: u8| {
        operands
            .match_indices('$')
            .map(|(at, _)| at)
            .find(|&at| operands.as_bytes().get(at + 1) == Some(&sign))
    };
    let Some(start) = after_dollar(b'+').or_else(|| after_dollar(b'-')) else {
        return operands.to_string();
    };
    let end = operands[start..].find(',').map_or(operands.len(), |at| start + at);
    let distance = target as i64 - address as i64;
    let sign = if distance < 0 { '-' } else { '+' };
    format!("{}${sign}{:#x}{}", &operands[..start], distance.unsigned_abs(), &operands[end..])
}

/// The condition of each instruction an `it` covers, in order, from the
/// condition of the first and the mask of the rest. Each bit of the mask
/// above its lowest set bit covers one more: as bit 0 of the condition,
/// `t`, it takes the condition, and else its opposite, `e`. `None` where
/// the condition has no opposite.
pub fn it_conditions(condition: u8, mask: u8) -> Option<Vec<ConditionCode>> {
    /// The conditions by number. 14 is always, and has no opposite.
    const CODES: [ConditionCode; 14] = [
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
    ];
    let then = *CODES.get(usize::from(condition))?;
    let otherwise = CODES[usize::from(condition ^ 1)];
    let mask = mask & 0xf;
    if mask == 0 {
        return None;
    }
    let covered = 4 - mask.trailing_zeros();
    let rest = (1..covered).map(|slot| {
        let bit = mask >> (4 - slot) & 1;
        if bit == condition & 1 { then } else { otherwise }
    });
    Some(core::iter::once(then).chain(rest).collect())
}

/// Whether `insn` is an `it`.
pub fn is_it(insn: &Insn) -> bool {
    matches!(insn.opcode, crate::arch::Opcode::Thumb(Decoded::It { .. }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::arm32::condition_name;

    /// Taking out a suffix by bytes gives what `str::replace` gives, for
    /// any text of dots, the two letters and others.
    #[test]
    fn a_suffix_comes_out_as_replace_takes_it() {
        bolero::check!().with_type::<Vec<u8>>().for_each(|picks| {
            let text: String =
                picks.iter().map(|pick| ['.', 'w', 'n', 'b', 'e'][*pick as usize % 5]).collect();
            for letter in *b"wn" {
                let pattern = format!(".{}", letter as char);
                assert_eq!(without_suffix(&text, letter), text.replace(&pattern, ""), "{text:?}");
            }
        });
    }

    /// The target of a branch replaces the first `$+` offset, or else the
    /// first `$-` one.
    #[test]
    fn a_branch_names_the_distance_to_its_target() {
        assert_eq!(with_target_text("$+0x2e", 0x100, 0x130), "$+0x30");
        assert_eq!(with_target_text("r0, $-0x4", 0x100, 0xf0), "r0, $-0x10");
        assert_eq!(with_target_text("r1, r2", 0x100, 0x130), "r1, r2");
        assert_eq!(with_target_text("$5, $+0x2", 0x100, 0x108), "$5, $+0x8");
    }

    /// The wide words `yaxpeax` misreads, against `llvm-mc`.
    #[test]
    fn reads_the_wide_words_the_decoder_misreads() {
        let cases: [(u16, u16, &str, &str); 9] = [
            (0xf06f, 0x0002, "mvn", "r0, 0x2"),
            (0xf07f, 0x4300, "mvns", "r3, 0x80000000"),
            (0xfa0c, 0xfc00, "lsl", "ip, ip, r0"),
            (0xfa2c, 0xfc00, "lsr", "ip, ip, r0"),
            (0xfa4c, 0xfc00, "asr", "ip, ip, r0"),
            (0xfa6c, 0xfc00, "ror", "ip, ip, r0"),
            (0xfa1f, 0xf29b, "uxth", "r2, fp, ror 0x8"),
            (0xf362, 0x3596, "bfi", "r5, r2, 0xe, 0x9"),
            (0xf36f, 0x209f, "bfc", "r0, 0xa, 0x16"),
        ];
        for (first, second, name, operands) in cases {
            let bytes = halfwords(&[first, second]);
            let insn = Thumb2.decode(&bytes, 0, 0).expect("the word reads");
            assert_eq!(insn.to_string(), format!("{name} {operands}"));
        }
        let lift = |first, second| {
            let bytes = halfwords(&[first, second]);
            Thumb2.lift(&Thumb2.decode(&bytes, 0, 0).unwrap()).expect("the word lifts")
        };
        // `mvn r0, #2` puts `~2` in `r0`.
        let not = lift(0xf06f, 0x0002);
        assert_eq!(not.op, crate::Op::Move);
        assert_eq!(not.operands[1], crate::Operand::Const(u64::from(!2u32)));
        assert_eq!(lift(0xfa4c, 0xfc00).op, crate::Op::ShiftRightArithmetic);
        assert_eq!(lift(0xfa6c, 0xfc00).op, crate::Op::Rotate);
        // `asr #32` is encoded as a shift of 0.
        let shifted = Thumb2.decode(&halfwords(&[0xea13, 0x0321]), 0, 0).unwrap();
        assert_eq!(crate::arch::printed_operands(&shifted), "r3, r3, r1, asr 0x20");
        let plain = Thumb2.decode(&halfwords(&[0xea13, 0x0301]), 0, 0).unwrap();
        assert_eq!(crate::arch::printed_operands(&plain), "r3, r3, r1");
    }

    /// Each pattern of `ThumbExpandImm`, and a rotated byte.
    #[test]
    fn a_t32_constant_expands() {
        assert_eq!(thumb_expand_constant(0x0ab), 0xab);
        assert_eq!(thumb_expand_constant(0x1ab), 0x00ab_00ab);
        assert_eq!(thumb_expand_constant(0x2ab), 0xab00_ab00);
        assert_eq!(thumb_expand_constant(0x3ab), 0xabab_abab);
        assert_eq!(thumb_expand_constant(0x400), 0x8000_0000);
        // A rotation of 31 puts the byte `0xff` at bits 1 to 8.
        assert_eq!(thumb_expand_constant(0xfff), 0x1fe);
    }

    /// A branch prints the distance from itself to where it goes, as
    /// `llvm-objdump` resolves it: `bne` at 0x14cf6 goes to 0x14d26.
    #[test]
    fn a_branch_prints_the_distance_to_its_target() {
        let cases: [(&[u8], &str, &str); 4] = [
            // `bne`, narrow and conditional.
            (&[0x16, 0xd1], "bne", "$+0x30"),
            // `cbz r1`, narrow.
            (&[0xd1, 0xb1], "cbz", "r1, $+0x38"),
            // `b.w`, wide.
            (&[0x00, 0xf0, 0x10, 0xb8], "b", "$+0x24"),
            // LLD's fill, a branch back.
            (&[0xd4, 0xd4], "bmi", "$-0x54"),
        ];
        for (bytes, name, operands) in cases {
            let insn = Thumb2.decode(bytes, 0, 0x1000).expect("the branch reads");
            assert_eq!(insn.to_string(), format!("{name} {operands}"));
            let (InsnKind::Branch { target: Some(target) }
            | InsnKind::Jump { target: Some(target) }) = insn.kind
            else {
                panic!("{bytes:x?} is a branch")
            };
            let distance = operands.rsplit('$').next().expect("a distance");
            let distance = i64::from_str_radix(&distance[3..], 16).expect("hex")
                * if distance.starts_with('-') { -1 } else { 1 };
            assert_eq!(target as i64 - 0x1000, distance, "{bytes:x?}");
        }
        assert_eq!(with_target_text("r1, $+0x2", 0x10, 0x8), "r1, $-0x8");
        assert_eq!(with_target_text("r1", 0x10, 0x8), "r1", "no distance to put right");
    }

    /// T32 code from halfwords, little endian.
    fn halfwords(values: &[u16]) -> Vec<u8> {
        values.iter().flat_map(|value| value.to_le_bytes()).collect()
    }

    fn decode_one(values: &[u16]) -> Insn {
        Thumb2.decode(&halfwords(values), 0, 0x1000).expect("bytes must decode")
    }

    fn lift_one(values: &[u16]) -> crate::Lifted {
        Thumb2.lift(&decode_one(values)).expect("the halfwords must lift")
    }

    fn guard_of(code: &[&[u16]]) -> Option<crate::Guard> {
        let lifted: Vec<_> = code.iter().map(|values| Some(lift_one(values))).collect();
        crate::find_guards(&lifted).first().map(|found| found.guard)
    }

    /// Encodings from `llvm-mc --triple=thumbv7m --show-encoding`.
    #[test]
    fn cbz_and_cmp_with_beq_are_one_guard() {
        use crate::{Cond, Reg, Value};
        const CBZ_R0: &[u16] = &[0xb120];
        const CMP_R0_0: &[u16] = &[0x2800];
        const BEQ: &[u16] = &[0xd004];
        const CBNZ_R1: &[u16] = &[0xb921];
        let cbz = guard_of(&[CBZ_R0]).unwrap();
        assert_eq!(guard_of(&[CMP_R0_0, BEQ]), Some(cbz));
        assert_eq!((cbz.cond, cbz.left), (Cond::Equal, Value::Reg(Reg::General(0))));
        assert_eq!(guard_of(&[CBNZ_R1]).unwrap().cond, Cond::NotEqual);
    }

    #[test]
    fn a_wide_compare_and_branch_are_one_guard() {
        use crate::{Cond, Reg, Value};
        const CMP_W_R8_256: &[u16] = &[0xf5b8, 0x7f80];
        const BHS_W: &[u16] = &[0xf080, 0x8020];
        let guard = guard_of(&[CMP_W_R8_256, BHS_W]).unwrap();
        assert_eq!(guard.cond, Cond::UnsignedGreaterOrEqual);
        assert_eq!((guard.left, guard.right), (Value::Reg(Reg::General(8)), Value::Const(256)));
    }

    #[test]
    fn an_it_block_reads_the_flags_and_ends_a_guard() {
        const CMP_R0_0: &[u16] = &[0x2800];
        const IT_EQ: &[u16] = &[0xbf08];
        const BEQ: &[u16] = &[0xd004];
        assert!(lift_one(IT_EQ).reads.contains(crate::Reg::Flags));
        assert_eq!(guard_of(&[CMP_R0_0, IT_EQ, BEQ]), None);
    }

    #[test]
    fn a_narrow_load_names_its_width() {
        const LDRB_R0_R1_3: &[u16] = &[0x78c8];
        let load = lift_one(LDRB_R0_R1_3);
        assert_eq!(load.memory.and_then(|access| access.width), Some(crate::Width::Bits8));
        assert!(load.writes.contains(crate::Reg::General(0)));
    }

    #[test]
    fn lifting_any_halfwords_never_panics() {
        bolero::check!().with_type::<(u16, u16)>().for_each(|&(first, second)| {
            let bytes = halfwords(&[first, second]);
            let Ok(insn) = Thumb2.decode(&bytes, 0, 0x1000) else { return };
            let _ = Thumb2.lift(&insn);
        });
    }

    #[test]
    fn tbb_and_tbh_read_as_themselves() {
        let tbb = decode_one(&[0xe8df, 0xf002]);
        assert_eq!(tbb.to_string(), "tbb [pc, r2]");
        let tbh = decode_one(&[0xe8df, 0xf012]);
        assert_eq!(tbh.to_string(), "tbh [pc, r2, lsl 0x1]");
        assert_eq!(tbh.kind, InsnKind::Jump { target: None });
    }

    #[test]
    fn a_wide_store_at_an_offset_reads_as_one() {
        // From `llvm-mc --triple=thumbv7`.
        let shown = |values: &[u16]| {
            let insn = decode_one(values);
            insn.to_string()
        };
        assert_eq!(shown(&[0xf8cd, 0x801c]), "str r8, [sp, 0x1c]");
        assert_eq!(shown(&[0xf8ad, 0x801c]), "strh r8, [sp, 0x1c]");
        assert_eq!(shown(&[0xf88d, 0x801c]), "strb r8, [sp, 0x1c]");
        assert_eq!(shown(&[0xf8cd, 0x8000]), "str r8, [sp]");
        assert_eq!(shown(&[0xf840, 0x8001]), "str r8, [r0, r1]", "the register form stays");
        let lifted = lift_one(&[0xf8c5, 0x8004]);
        assert_eq!(lifted.op, crate::Op::Store);
        assert_eq!(
            lifted.operands.last(),
            Some(&crate::Operand::memory(Some(crate::Reg::General(5)), Some(4)))
        );
    }

    #[test]
    fn a_wide_move_keeps_every_bit_of_its_value() {
        // movw ip, 0xfaac; movt ip, 0xfffe: imm4 is set in both.
        let low = decode_one(&[0xf64f, 0x2cac]);
        assert_eq!(low.to_string(), "mov ip, 0xfaac");
        let high = decode_one(&[0xf6cf, 0x7cfe]);
        assert_eq!(high.to_string(), "movt ip, 0xfffe");
        // The lift holds the same values the text shows.
        let constant = |values: &[u16]| lift_one(values).operands.last().copied();
        assert_eq!(constant(&[0xf64f, 0x2cac]), Some(crate::Operand::Const(0xfaac)));
        assert_eq!(constant(&[0xf6cf, 0x7cfe]), Some(crate::Operand::Const(0xfffe)));
    }

    #[test]
    fn a_t32_neon_store_reads_as_its_a32_twin() {
        let insn = decode_one(&[0xf941, 0x0a8d]);
        assert_eq!(crate::arch::printed_name(&insn), "vst1.32");
        assert_eq!(crate::arch::printed_operands(&insn), "{d16, d17}, [r1]!");
        assert_eq!((insn.bytes_len, insn.kind), (4, InsnKind::Normal));
    }

    #[test]
    fn narrow_and_wide_instructions_have_their_width() {
        let narrow = decode_one(&[0x4770]); // bx lr
        assert_eq!((crate::arch::printed_name(&narrow).as_str(), narrow.bytes_len), ("bx", 2));
        assert_eq!(narrow.kind, InsnKind::Return);
        let wide = decode_one(&[0xf04f, 0x0001]); // mov.w r0, 1
        assert_eq!(
            (crate::arch::printed_name(&wide).as_str(), wide.bytes_len),
            ("mov", 4),
            "no .w"
        );
    }

    /// Every branch form goes to `pc`, 4 bytes past it, plus twice its
    /// offset.
    #[test]
    fn branches_reach_their_targets() {
        // b.n with an offset of 1: 0x1004 + 2.
        assert_eq!(decode_one(&[0xe001]).kind, InsnKind::Jump { target: Some(0x1006) });
        // bne.n with an offset of 2: 0x1004 + 4.
        assert_eq!(decode_one(&[0xd102]).kind, InsnKind::Branch { target: Some(0x1008) });
        // cbz r0 with an offset of 6: 0x1004 + 12.
        assert_eq!(decode_one(&[0xb130]).kind, InsnKind::Branch { target: Some(0x1010) });
        // b.w with an offset of 0x7fe: 0x1004 + 0xffc.
        assert_eq!(decode_one(&[0xf000, 0xbffe]).kind, InsnKind::Jump { target: Some(0x2000) });
        // bl with an offset of 0x7fe: 0x1004 + 0xffc.
        assert_eq!(decode_one(&[0xf000, 0xfffe]).kind, InsnKind::Call { target: Some(0x2000) });
    }

    /// Each `it` covers the conditions its name and its operand print:
    /// `t` the condition, and `e` its opposite.
    #[test]
    fn it_blocks_cover_what_they_print() {
        for condition in 0..14_u16 {
            for mask in 1..16_u16 {
                let insn = decode_one(&[0xbf00 | condition << 4 | mask]);
                assert!(is_it(&insn), "{insn}");
                let then = crate::arch::printed_operands(&insn);
                let names: Vec<&str> = it_conditions(condition as u8, mask as u8)
                    .expect("a condition with an opposite")
                    .into_iter()
                    .map(condition_name)
                    .collect();
                let pattern = &crate::arch::printed_name(&insn)[2..];
                assert_eq!(names.len(), pattern.len() + 1, "{insn}");
                assert_eq!(names[0], then, "{insn}");
                for (name, letter) in names[1..].iter().zip(pattern.chars()) {
                    assert_eq!(letter == 't', *name == then, "{insn}");
                }
            }
        }
        assert!(!is_it(&decode_one(&[0xbf00])), "nop");
    }

    fn reg(number: u8) -> crate::Operand {
        crate::Operand::Reg(crate::Reg::General(number))
    }

    /// A 16-bit form names its destination once, and lifts as the 32-bit
    /// form that names it twice.
    #[test]
    fn a_two_address_form_names_its_destination_twice() {
        use crate::{Op, Operand};
        // `adds r0, #1` and `ands r0, r1`
        let add = lift_one(&[0x3001]);
        assert_eq!(
            (add.op, add.operands.as_slice()),
            (Op::Add, &[reg(0), reg(0), Operand::Const(1)][..])
        );
        let and = lift_one(&[0x4008]);
        assert_eq!((and.op, and.operands.as_slice()), (Op::And, &[reg(0), reg(0), reg(1)][..]));
        // `lsls r0, r1, #2` names three already.
        assert_eq!(lift_one(&[0x0088]).operands.len(), 3);
    }

    /// `negs r0, r1` is `rsbs r0, r1, #0`, which is `0 - r1`.
    #[test]
    fn a_reverse_subtract_from_zero_is_a_negate() {
        let negate = lift_one(&[0x4248]).canonical();
        assert_eq!(negate.op, crate::Op::Negate);
        assert_eq!(negate.operands.as_slice(), [reg(0), reg(1)]);
    }
}
