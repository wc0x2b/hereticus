//! Read the deku types of this crate from bytes.
//!
//! The scans call these at each word of an image, so each is inlined: a
//! call that returns its `Option` through memory took more instructions
//! than the read itself.

use deku::prelude::*;

/// The `T` that `bytes` open with, or `None` where they do not hold one.
#[inline]
pub(crate) fn parse<'a, T: DekuReader<'a>>(bytes: &'a [u8]) -> Option<T> {
    parse_with(bytes, ())
}

/// The `T` that `bytes` open with, read in `ctx`, as a byte order.
#[inline]
pub(crate) fn parse_with<'a, T: DekuReader<'a, Ctx>, Ctx>(bytes: &'a [u8], ctx: Ctx) -> Option<T> {
    let mut cursor = deku::reader::SliceReader::new(bytes);
    let mut reader = Reader::new(&mut cursor);
    T::from_reader_with_ctx(&mut reader, ctx).ok()
}

/// Each `T` that `bytes` hold, one after the other, or `None` where the
/// bytes do not end with a whole one.
#[inline]
pub(crate) fn parse_all<'a, T: DekuReader<'a>>(bytes: &'a [u8]) -> Option<Vec<T>> {
    let mut cursor = deku::reader::SliceReader::new(bytes);
    let mut reader = Reader::new(&mut cursor);
    let mut values = Vec::new();
    while !reader.try_end().ok()? {
        values.push(T::from_reader_with_ctx(&mut reader, ()).ok()?);
    }
    Some(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, DekuRead)]
    #[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
    struct Word(u32);

    #[derive(Debug, PartialEq, Eq, DekuRead)]
    struct Pair(u8, u8);

    #[test]
    fn a_value_reads_in_the_byte_order_given() {
        let bytes = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(parse_with(&bytes, deku::ctx::Endian::Big), Some(Word(0x1234_5678)));
        assert_eq!(parse_with(&bytes, deku::ctx::Endian::Little), Some(Word(0x7856_3412)));
        assert_eq!(parse_with::<Word, _>(&bytes[..3], deku::ctx::Endian::Big), None);
    }

    #[test]
    fn all_values_read_only_where_the_bytes_end_with_a_whole_one() {
        assert_eq!(parse_all(&[1, 2, 3, 4]), Some(vec![Pair(1, 2), Pair(3, 4)]));
        assert_eq!(parse_all::<Pair>(&[]), Some(vec![]));
        assert_eq!(parse_all::<Pair>(&[1, 2, 3]), None);
        assert_eq!(parse(&[5, 6, 7]), Some(Pair(5, 6)));
    }
}
