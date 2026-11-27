//! What the relocations in the code of an unlinked object name, as a
//! kernel module holds them: the part of an address that each instruction
//! or word at a relocation holds. Each architecture reads its own types of
//! relocation in [`crate::Arch::data_references`].

pub use object::elf::RelocationType;
use object::{RelocationFlags, RelocationTarget, SymbolIndex};

/// A relocation in code that names the address of data, as an architecture
/// reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataReference {
    /// Where the relocation writes, from the start of its section.
    pub offset: u64,
    /// The symbol whose address it names.
    pub symbol: SymbolIndex,
    /// What it adds to the address of the symbol.
    pub addend: i64,
    /// What the instruction or word at the relocation holds of the address.
    pub part: Part,
}

/// How many bytes a word that holds an address takes. A relocation gives
/// it, as `R_AARCH64_ABS32` names a word of 4 bytes in code of 64 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    /// 32 bits.
    Four,
    /// 64 bits.
    Eight,
}

impl Width {
    /// The number of bytes of the word.
    pub fn bytes(self) -> usize {
        match self {
            Self::Four => 4,
            Self::Eight => 8,
        }
    }

    /// Whether a word of this width holds `address` whole.
    pub fn holds(self, address: u64) -> bool {
        match self {
            Self::Four => u32::try_from(address).is_ok(),
            Self::Eight => true,
        }
    }
}

/// What an instruction or a word holds of the address its relocation names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    /// The word holds the address, as a word of a literal pool does.
    Word(Width),
    /// The instruction forms the upper part of the address, as `adrp` and
    /// `addis` do, and another completes it.
    High,
    /// The instruction completes the address, or reads or writes the place
    /// there, as the `add` and `ldr` of AArch64 do after `adrp`.
    Low,
    /// The instruction forms the upper half of an address whose lower half
    /// another adds as its immediate, as a MIPS `lui` does: the relocations
    /// keep their addend in those immediates. So a view shows the whole
    /// address at the `lui`, and no immediate at the instruction that adds
    /// the lower half, with whatever the code adds between.
    UpperOfPair,
    /// The instruction adds the lower half of an [`Part::UpperOfPair`], as
    /// `addiu` and `lw` do.
    LowerOfPair,
    /// The instruction holds the distance to the address from its own end,
    /// as the x86-64 `lea rdi, [rip + x]` does. The target is the address
    /// less the distance from the relocation to the end of the instruction.
    FromEnd,
}

/// The reference of each relocation in `relocations` whose type `part_of`
/// gives a part. Its addend is the one the relocation holds, or else the
/// word of 32 bits that `word` reads at its offset.
pub(crate) fn references_of(
    relocations: &[(u64, object::Relocation)],
    word: &dyn Fn(u64) -> Option<u64>,
    part_of: impl Fn(RelocationType) -> Option<Part>,
) -> Vec<DataReference> {
    relocations
        .iter()
        .filter_map(|(offset, relocation)| {
            let RelocationTarget::Symbol(symbol) = relocation.target() else { return None };
            let RelocationFlags::Elf { r_type } = relocation.flags() else { return None };
            let part = part_of(r_type)?;
            let addend = match relocation.has_implicit_addend() {
                true => implicit_addend(word, *offset),
                false => relocation.addend(),
            };
            Some(DataReference { offset: *offset, symbol, addend, part })
        })
        .collect()
}

/// The addend that the word of 32 bits at `offset` holds, as a relocation
/// with no addend of its own keeps it.
pub(crate) fn implicit_addend(word: &dyn Fn(u64) -> Option<u64>, offset: u64) -> i64 {
    i64::from(word(offset).unwrap_or(0) as u32 as i32)
}
