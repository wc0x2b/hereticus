//! The rules the matching reads in A32 code, as which registers hold the
//! frame and which constants are addresses. The rules that find
//! functions are in [`hereticus_recovery::arch::arm32`].

use super::{Arch, Insn, InsnKind, Memory};
use hereticus_il as il;
pub use hereticus_il::arch::arm32::*;
use hereticus_memory::{AddressSpace, ConstantKind, Contents};
use hereticus_recovery::arch::arm32::{PcModel, track_pool_words};
use yaxpeax_arm::armv7::Opcode;

/// The frame pointer, as the A32 procedure call standard names it.
const FRAME: il::Reg = il::Reg::General(11);

impl Arch for Arm32 {
    fn is_frame_register(&self, reg: il::Reg) -> bool {
        matches!(reg, il::Reg::Stack | FRAME)
    }

    fn is_frame_management(&self, insn: &Insn) -> bool {
        let Some(opcode) = core_opcode(insn) else { return false };
        let operands = || lifted(insn).map(|lifted| lifted.operands).unwrap_or_default();

        match opcode {
            // Saving and restoring registers. A `pop` that loads the program
            // counter also returns, so it must stay.
            Opcode::PUSH => true,
            Opcode::POP => insn.kind != InsnKind::Return,

            // Moving the stack pointer, or setting up the frame pointer.
            Opcode::SUB | Opcode::ADD | Opcode::MOV => {
                matches!(operands().first(), Some(il::Operand::Reg(reg)) if self.is_frame_register(*reg))
            }

            // Spilling to and reloading from the frame, by `ldr`, `str`,
            // `ldm` and `stm`, which go up from the base.
            Opcode::LDR
            | Opcode::STR
            | Opcode::LDM(true, false, ..)
            | Opcode::STM(true, false, ..) => operands().iter().any(|operand| {
                matches!(operand, il::Operand::Memory { base: Some(base), .. } if self.is_frame_register(*base))
            }),

            _ => false,
        }
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

    fn formed_addresses(
        &self,
        code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        _memory: &Memory<'_>,
    ) -> Vec<Option<u64>> {
        track_pool_words(code, body, space, PcModel::A32).formed
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
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::Decoder as _;

    use compact_str::CompactString;

    /// Decode one instruction from raw bytes at address 0.
    fn decode_one(bytes: [u8; 4]) -> Insn {
        Arm32.decode(&bytes, 0, 0).expect("bytes must decode")
    }

    /// Encodings from `llvm-mc --triple=armv7a --show-encoding`.
    mod words {
        pub const LDR_R1_R2_8: [u8; 4] = [0x08, 0x10, 0x92, 0xe5];
        pub const STR_R3_R4_R5: [u8; 4] = [0x05, 0x30, 0x84, 0xe7];
        pub const LDRD_R2_R3_SP: [u8; 4] = [0xd8, 0x20, 0xcd, 0xe1];
    }

    fn lift_one(bytes: [u8; 4]) -> il::Lifted {
        Arm32.lift(&decode_one(bytes)).expect("the word must lift")
    }

    #[test]
    fn a_memory_operand_names_its_base_and_offset() {
        let general = |number| Some(il::Reg::General(number));
        let memory = |bytes| *lift_one(bytes).operands.last().expect("a memory operand");
        // `ldr r1, [r2, #-8]`
        const LDR_R1_R2_MINUS_8: [u8; 4] = [0x08, 0x10, 0x12, 0xe5];
        assert_eq!(memory(words::LDR_R1_R2_8), il::Operand::memory(general(2), Some(8)));
        assert_eq!(memory(LDR_R1_R2_MINUS_8), il::Operand::memory(general(2), Some(-8)));
        let indexed = il::Operand::Memory {
            base: general(4),
            offset: None,
            index: Some((il::Reg::General(5), 0)),
            update: il::Update::None,
        };
        assert_eq!(memory(words::STR_R3_R4_R5), indexed, "the index names its register");
        assert_eq!(
            memory(words::LDRD_R2_R3_SP),
            il::Operand::memory(Some(il::Reg::Stack), Some(8))
        );
    }

    #[test]
    fn the_frame_registers_are_sp_and_r11() {
        assert!(Arm32.is_frame_register(il::Reg::Stack));
        assert!(Arm32.is_frame_register(il::Reg::General(11)));
        assert!(!Arm32.is_frame_register(il::Reg::General(7)));
    }

    /// Code that is not PIC builds an address whole with `movw` and `movt`.
    #[test]
    fn a_whole_address_built_in_two_halves_is_an_address() {
        // movw r2, 0x9de8; movt r2, 0x800
        let words = [0xe309_2de8_u32, 0xe340_2800];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (insns, _) = crate::decode_all(&Arm32, &code, 0x0800_0000);
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
            let (insns, _) = crate::decode_all(&Arm32, &code, base);
            let space = AddressSpace::of_raw_image(base, 0x2000);
            Arm32.constant_kinds(&code, &insns, &space)[1]
        };
        assert_eq!(pool_word_at(0x0800_0000), ConstantKind::StoredAddress);
        assert_eq!(pool_word_at(0), ConstantKind::Value);
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
        let (insns, _) = crate::decode_all(&Arm32, &code, 0x8000);
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
        let (insns, _) = crate::decode_all(&Arm32, &code, 0x1_0000);
        let space = AddressSpace::from_ranges([0x870..0xd40, 0x1_0000..0x1_0100]);
        let kinds = Arm32.constant_kinds(&code, &insns, &space);
        assert_eq!(kinds[2], ConstantKind::StoredAddress);
    }

    /// Code runs always; text and tables do not.
    #[test]
    fn tells_code_from_data() {
        let space = AddressSpace::none();
        let judge = |words: &[u32]| {
            let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            let (insns, _) = crate::decode_all(&Arm32, &code, 0);
            Arm32.contents(&code, &insns, &space)
        };
        let code = [0xe92d_4010_u32, 0xe1a0_4000, 0x0a00_0002, 0xe594_0000, 0xe8bd_8010];
        let text = u32::from_le_bytes(*b"text");
        assert_eq!(judge(&code.repeat(4)), Contents::Code);
        assert_eq!(judge(&[text; 16]), Contents::Data);
        assert_eq!(judge(&[0x0000_0010; 16]), Contents::Data, "a table of small offsets");
        assert_eq!(judge(&[text; 15]), Contents::Code, "too short to judge");
    }

    /// The name of the operation of the A32 `word`.
    fn operation_of(word: u32) -> CompactString {
        Arm32.operation_name(&decode_one(word.to_le_bytes()))
    }

    /// A condition and a flag-setting `s` say when the work runs and what
    /// it leaves in the flags, not what it computes. Text that ends in
    /// condition letters cannot fool the opcode: `adcs` is `adc`, though
    /// `cs` is a condition, and `bls` is a branch, not a call. A branch keeps
    /// its condition, which is its test.
    #[test]
    fn a_condition_and_the_flags_do_not_change_the_operation() {
        // mov r0, r1; movlt r0, r1; movs r0, r1.
        assert_eq!(operation_of(0xe1a0_0001), operation_of(0xb1a0_0001));
        assert_eq!(operation_of(0xe1a0_0001), operation_of(0xe1b0_0001));
        // bx lr; bxeq lr.
        assert_eq!(operation_of(0xe12f_ff1e), operation_of(0x012f_ff1e));
        // adc r0, r0, r1; adcs r0, r0, r1.
        assert_eq!(operation_of(0xe0a0_0001), operation_of(0xe0b0_0001));
        // bls is a branch on a test, not a call.
        assert_ne!(operation_of(0x9a00_0000), operation_of(0xeb00_0000));
        // bne and beq apply different tests.
        assert_ne!(operation_of(0x1a00_0000), operation_of(0x0a00_0000));
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
        let below = il::Operand::Memory {
            base: Some(il::Reg::Stack),
            offset: Some(-16),
            index: None,
            update: il::Update::Before,
        };
        let list = regs(&[vector(8), vector(9)]);
        assert_eq!(push.operands.as_slice(), [il::Operand::RegisterList(list), below]);
        assert_eq!(push.reads, regs(&[il::Reg::Stack, vector(8), vector(9)]));
        assert_eq!(push.writes, regs(&[il::Reg::Stack]));
        // `vcvt.s32.f64 s0, d16` converts into the single register.
        let convert = lift(0xeebd_0be0);
        assert_eq!(
            convert.operands.as_slice(),
            [il::Operand::Reg(vector(0)), il::Operand::Reg(vector(16))]
        );
    }
}
