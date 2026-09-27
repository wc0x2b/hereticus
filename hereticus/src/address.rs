//! The addresses a binary can refer to.
//!
//! A constant that is an address changes whenever the linker moves what it
//! points at, which happens on every release, whether or not the code that
//! holds it changed. Comparing such a constant finds a difference that does not
//! matter, so the normalizer must tell an address from a number. Where the
//! binary lives in memory is what tells them apart: a value inside that space
//! is taken as an address.

use core::ops::Range;

/// Below this, a value is a small number rather than an address.
///
/// The same floor [`crate::raw::check_base`] uses. Without it, a binary
/// loaded at zero would read every small constant as an address.
const SMALLEST_ADDRESS: u64 = 0x1000;

/// The address ranges a binary occupies.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddressSpace {
    ranges: Vec<Range<u64>>,
}

impl AddressSpace {
    /// A space holding no address, for code whose addresses are not final.
    ///
    /// An unlinked object is the case: every section starts at zero, and the
    /// linker has yet to fill in the addresses the code refers to.
    pub fn none() -> Self {
        Self::default()
    }

    /// The space of a raw image loaded at `base`.
    ///
    /// A raw image holds only what is stored. The zero-filled data after it,
    /// `.bss`, takes no room in the image but is still referred to, so the
    /// space reaches one image length past the end. Measured on two OpenWrt
    /// MIPS kernels, one `lui` in ten points into that gap.
    pub fn of_raw_image(base: u64, length: u64) -> Self {
        let end = base.saturating_add(length.saturating_mul(2));
        Self::from_ranges(core::iter::once(base..end))
    }

    /// The space made of the given ranges. Empty ranges are dropped.
    pub fn from_ranges(ranges: impl IntoIterator<Item = Range<u64>>) -> Self {
        let mut ranges: Vec<Range<u64>> =
            ranges.into_iter().filter(|range| !range.is_empty()).collect();
        ranges.sort_unstable_by_key(|range| range.start);
        Self { ranges }
    }

    /// Report whether a value is an address inside this space.
    pub fn contains(&self, value: u64) -> bool {
        value >= SMALLEST_ADDRESS && self.contains_formed(value)
    }

    /// Report whether an address the code formed lies inside this space.
    ///
    /// Unlike [`Self::contains`], no floor applies. A distance added to `pc`
    /// forms an address, however small, and `lld` puts the read-only data
    /// of a small shared library below [`SMALLEST_ADDRESS`].
    pub fn contains_formed(&self, address: u64) -> bool {
        self.ranges.iter().any(|range| range.contains(&address))
    }

    /// Report whether any address in `values` lies inside this space.
    pub fn overlaps(&self, values: Range<u64>) -> bool {
        let values = values.start.max(SMALLEST_ADDRESS)..values.end;
        self.ranges.iter().any(|range| range.start < values.end && values.start < range.end)
    }

    /// Report whether this space holds no address a value can name.
    pub fn is_empty(&self) -> bool {
        self.ranges.iter().all(|range| range.end <= SMALLEST_ADDRESS)
    }
}

/// What a constant in an instruction stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConstantKind {
    /// A number from the source, such as a bound or a mask.
    Value,
    /// Part of an address, which moves when the linker moves its target.
    Address,
    /// The whole word is data holding an address, such as a literal pool
    /// entry, and decodes as an instruction only by accident.
    StoredAddress,
}

/// What a stretch of bytes holds, as far as its words show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Contents {
    /// Instructions a compiler emitted.
    Code,
    /// Tables, pointers, strings or zero fill, which decode as instructions
    /// only because every word decodes as something.
    Data,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_raw_image_covers_itself_and_the_gap_after_it() {
        let space = AddressSpace::of_raw_image(0x8000_1000, 0x1000);

        assert!(space.contains(0x8000_1000), "the first byte");
        assert!(space.contains(0x8000_1fff), "the last byte");
        assert!(space.contains(0x8000_2000), "just past the end, where .bss sits");
        assert!(space.contains(0x8000_2fff), "one image length past the end");
        assert!(!space.contains(0x8000_3000), "further out is not the image");
        assert!(!space.contains(0x8000_0fff), "before the base is not the image");
    }

    #[test]
    fn small_numbers_are_never_addresses() {
        let space = AddressSpace::of_raw_image(0, 0x10_0000);

        assert!(!space.contains(0), "zero");
        assert!(!space.contains(0xfff), "a small count");
        assert!(space.contains(0x1000), "the floor is an address");
    }

    /// Code that adds a distance to `pc` forms an address, and small ones
    /// count: `lld` loads the read-only data of a small library there.
    #[test]
    fn a_formed_address_below_the_floor_counts() {
        let space = AddressSpace::from_ranges([0x870..0xd40, 0x1_0d40..0x1_6c20]);

        assert!(space.contains_formed(0xbc8), "read-only data");
        assert!(!space.contains(0xbc8), "the same number as a value");
        assert!(!space.contains_formed(0x800), "before the data");
        assert!(space.contains(0x1_0d40), "code, either way");
        assert!(!space.overlaps(0x800..0x900), "values below the floor");
    }

    #[test]
    fn nothing_is_an_address_in_an_empty_space() {
        let space = AddressSpace::none();

        assert!(space.is_empty());
        assert!(!space.contains(0x8000_0000));
        assert!(!space.overlaps(0..u64::MAX));
    }

    #[test]
    fn overlap_is_checked_at_both_ends() {
        let space = AddressSpace::from_ranges(core::iter::once(0x8000_0000..0x8001_0000));

        assert!(space.overlaps(0x7fff_8000..0x8000_8000), "reaches in from below");
        assert!(space.overlaps(0x8000_8000..0x8001_8000), "reaches out above");
        assert!(space.overlaps(0x7000_0000..0x9000_0000), "covers it");
        assert!(!space.overlaps(0x7fff_0000..0x8000_0000), "ends at the start");
        assert!(!space.overlaps(0x8001_0000..0x8002_0000), "starts at the end");
    }

    #[test]
    fn several_ranges_each_count() {
        let space = AddressSpace::from_ranges([0x9000_0000..0x9000_1000, 0x8000_0000..0x8000_1000]);

        assert!(space.contains(0x8000_0800));
        assert!(space.contains(0x9000_0800));
        assert!(!space.contains(0x8800_0000), "the gap between them");
    }

    #[test]
    fn empty_ranges_are_dropped() {
        assert!(AddressSpace::from_ranges(core::iter::once(0x8000_0000..0x8000_0000)).is_empty());
        assert!(
            AddressSpace::from_ranges(core::iter::once(0..0x800)).is_empty(),
            "below the floor"
        );
    }

    #[test]
    fn a_base_near_the_top_does_not_overflow() {
        let space = AddressSpace::of_raw_image(u64::MAX - 0x10, 0x100);
        assert!(space.contains(u64::MAX - 1));
    }
}
