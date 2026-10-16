//! The rules the matching reads in MIPS16e code, as which registers hold the
//! frame and which constants are addresses. The rules that find
//! functions are in [`hereticus_recovery::arch::mips16`].

use super::mips::register_name;
use super::{Arch, Decoder, GlobalPointerSetup, Insn, Memory};
use hereticus_il as il;
use hereticus_il::arch::mips16::*;
use hereticus_memory::{AddressSpace, ConstantKind, Contents};
use hereticus_recovery::arch::mips::first_register;
use hereticus_recovery::arch::mips16::{
    AddressRules as _, GP_PREAMBLE_LENGTH, is_gp_preamble, mips16_op,
};

/// The function field of the MIPS32 `addu`.
const ADDU: u32 = 0x21;

impl Arch for Mips16 {
    fn is_frame_register(&self, reg: il::Reg) -> bool {
        self.base.is_frame_register(reg)
    }

    /// `save` and `restore` make and drop the frame whole.
    fn is_frame_management(&self, insn: &Insn) -> bool {
        matches!(mips16_op(insn), Some(Op::Save | Op::Restore))
            || self.base.is_frame_management(insn)
    }

    /// The text of each instruction is that of MIPS32, so MIPS32 follows
    /// the global pointer through the body. A load or address relative to
    /// the program counter moves with the code, and so does the upper half
    /// of `_gp_disp` that the preamble adds to it.
    fn constant_kinds(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
    ) -> Vec<ConstantKind> {
        // MIPS32 knows the global pointer as `_gp_disp` added to `t9`, the
        // address of the function. MIPS16e adds it to the program counter
        // instead, so its `addu` is given to MIPS32 in the form it knows.
        let preambles: Vec<usize> = (0..body.len())
            .filter(|&index| {
                body.get(index..index + GP_PREAMBLE_LENGTH).is_some_and(is_gp_preamble)
            })
            .collect();
        let mut as_mips32 = body.to_vec();
        for &index in &preambles {
            let add = &mut as_mips32[index + GP_PREAMBLE_LENGTH - 1];
            let destination = self.lift(add).and_then(|lifted| match lifted.operands.first() {
                Some(il::Operand::Reg(il::Reg::General(number))) => Some(u32::from(*number)),
                _ => None,
            });
            // `addu rD, rD, t9`, the MIPS32 instruction that joins the
            // distance to the global pointer.
            let joined = destination.and_then(|rd| {
                // `t9` is register 25.
                let word = register(rd, 25, rd, 0, ADDU);
                self.base.decode(&self.base.word_bytes(word), 0, add.address).ok()
            });
            if let Some(joined) = joined {
                *add = joined;
            }
        }

        let mut kinds = super::mips::constant_kinds_in(self, &as_mips32, space);
        for &index in &preambles {
            kinds[index] = ConstantKind::Address;
        }
        for (index, insn) in body.iter().enumerate() {
            let reading = self.decoded(insn.bytes(), 0, insn.address).map(|found| found.reading);
            if matches!(reading, Some(Reading::PcRelative { .. })) {
                kinds[index] = ConstantKind::Address;
            }
        }
        kinds
    }

    /// GCC puts the table of each `switch` after its function in MIPS16e
    /// code, as the absolute addresses of its cases where the code is not
    /// PIC, and a scan reads such a table as a function of its own. Its
    /// addresses move with each release. So a function whose aligned words
    /// are at least half addresses inside the image is data.
    ///
    /// A function's literal pool holds addresses too. Measured on the
    /// MIPS16e builds of `uhttpd`, `ubusd`, `odhcpd`, `jsonfilter` and
    /// `libblobmsg_json` of OpenWrt, code of 8 words or more reaches at
    /// most 40%, and the tables of `uhttpd` of 18.06 at least 70%.
    ///
    /// A shorter run is data only where every word is an address: the scan
    /// splits a literal pool of addresses off the function it ends, as one
    /// of 5 words in that `uhttpd`. A word of MIPS16e code whose top
    /// halfword is the top of an address, as `addiu s0, sp, 0x100` for
    /// `0x0040`, is rare, and every word of a run of such is rarer.
    fn contents(&self, code: &[u8], insns: &[Insn], space: &AddressSpace) -> Contents {
        const FEWEST_WORDS: usize = 8;
        const FEWEST_POOL_WORDS: usize = 2;
        const WORD: usize = 4;

        let Some(first) = insns.first() else { return Contents::Code };
        // The words of a table start on a word, and a function on a
        // halfword.
        let skip =
            usize::try_from((WORD as u64 - first.address % WORD as u64) % WORD as u64).unwrap_or(0);
        let words = code.get(skip..).unwrap_or_default().as_chunks::<WORD>().0;
        // A pointer to a MIPS16e function has bit 0 set.
        let addresses =
            words.iter().filter(|word| space.contains(self.read_pointer(*word) & !1)).count();
        let is_table = words.len() >= FEWEST_WORDS && addresses * 2 >= words.len();
        let is_pool =
            (FEWEST_POOL_WORDS..FEWEST_WORDS).contains(&words.len()) && addresses == words.len();
        if is_table || is_pool { Contents::Data } else { Contents::Code }
    }

    /// What [`crate::Recovery::data_addresses`] finds, and also the slot of the
    /// global offset table each load through the global pointer reads.
    fn formed_addresses(
        &self,
        _code: &[u8],
        body: &[Insn],
        space: &AddressSpace,
        memory: &Memory<'_>,
    ) -> Vec<Option<u64>> {
        let mut formed = vec![None; body.len()];
        for (index, address) in self.addresses_by_index(body, space, memory) {
            formed[index] = Some(address);
        }
        for (index, insn) in body.iter().enumerate() {
            if formed[index].is_none()
                && let Some(slot) = self.slot_of(body, index, insn)
            {
                formed[index] = Some(slot);
            }
        }
        formed
    }

    fn global_pointer_setup(&self, body: &[Insn]) -> Option<GlobalPointerSetup> {
        let preamble = body.get(..GP_PREAMBLE_LENGTH).filter(|run| is_gp_preamble(run))?;
        let register = register_name(first_register(preamble.last()?)?)?.to_string();
        Some(GlobalPointerSetup { parts: (0..GP_PREAMBLE_LENGTH).collect(), register })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Recovery as _;

    /// The text of the halfwords `values`, big endian, at `address`.
    fn text(values: &[u16], address: u64) -> String {
        let code: Vec<u8> = values.iter().flat_map(|value| value.to_be_bytes()).collect();
        let insn = Mips16::BIG.decode(&code, 0, address).expect("decodes");
        insn.to_string().trim_end().to_string()
    }

    #[test]
    fn save_and_restore_make_and_drop_the_frame() {
        assert_eq!(text(&[0x64b4], 0), "save 0x20, s0, s1"); // save 32,s0-s1
        let code = 0x64b4_u16.to_be_bytes();
        let insn = Mips16::BIG.decode(&code, 0, 0).expect("decodes");
        assert!(Mips16::BIG.is_frame_management(&insn));
        assert!(Mips16::BIG.is_prologue(&insn));
    }

    /// The contents of the words `words`, big endian, at `address`, in an
    /// image from 0x400000 to 0x420000.
    fn contents_of(words: &[u32], address: u64) -> Contents {
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
        let (insns, _) = hereticus_recovery::arch::decode_all(&Mips16::BIG, &code, address);
        let space = AddressSpace::of_raw_image(0x40_0000, 0x2_0000);
        Mips16::BIG.contents(&code, &insns, &space)
    }

    /// The pool that ends a function of `uhttpd` of OpenWrt 18.06.5.
    const POOL: [u32; 5] = [0x0041_81b0, 0x0040_663c, 0x0040_65a8, 0x0040_6648, 0x0040_665c];
    /// The function after it: `save`, and on.
    const CODE: [u32; 8] = [
        0x64e4_6d0c,
        0x6704_1a00,
        0x1e14_6c01,
        0xb305_da02,
        0x9b81_da60,
        0xda81_db41,
        0xdc40_6464,
        0xe8a0_6500,
    ];

    #[test]
    fn a_table_of_addresses_is_data() {
        let table: Vec<u32> = (0..8).map(|at| 0x0040_6600 + at * 0x10 + 1).collect();
        assert_eq!(contents_of(&table, 0x40_4250), Contents::Data);
        let mut half = table.clone();
        half[..4].copy_from_slice(&CODE[..4]);
        assert_eq!(contents_of(&half, 0x40_4250), Contents::Data, "half addresses");
        half[4] = CODE[4];
        assert_eq!(contents_of(&half, 0x40_4250), Contents::Code, "fewer than half");
    }

    #[test]
    fn a_pool_of_addresses_alone_is_data() {
        assert_eq!(contents_of(&POOL, 0x40_3ad0), Contents::Data);
        let mut mixed = POOL;
        mixed[2] = CODE[0];
        assert_eq!(contents_of(&mixed, 0x40_3ad0), Contents::Code, "one word of code");
        assert_eq!(contents_of(&POOL[..1], 0x40_3ad0), Contents::Code, "one word");
    }

    #[test]
    fn code_with_its_pool_is_code() {
        let function: Vec<u32> = CODE.iter().chain(&POOL[..2]).copied().collect();
        assert_eq!(contents_of(&function, 0x40_3ae4), Contents::Code);
        assert_eq!(contents_of(&CODE, 0x40_3ae4), Contents::Code);
        assert_eq!(contents_of(&[], 0x40_3ae4), Contents::Code);
    }

    /// A function on a halfword reads its words from the next word.
    #[test]
    fn the_words_start_on_a_word() {
        let mut code = 0x6500_u16.to_be_bytes().to_vec();
        code.extend(POOL.iter().flat_map(|word| word.to_be_bytes()));
        let (insns, _) = hereticus_recovery::arch::decode_all(&Mips16::BIG, &code, 0x40_3ace);
        let space = AddressSpace::of_raw_image(0x40_0000, 0x2_0000);
        assert_eq!(Mips16::BIG.contents(&code, &insns, &space), Contents::Data);
    }
}
