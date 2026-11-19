//! The lazy binding stubs of MIPS.
//!
//! A MIPS executable calls an import through a stub that GNU `ld` writes
//! into `.MIPS.stubs`, one for each import, in MIPS32 even where the code
//! around it is MIPS16e:
//!
//! ```text
//! lw    t9, -0x7ff0(gp)   ; the lazy resolver
//! move  t7, ra
//! jalr  t9
//! li    t8, index         ; the dynamic symbol it resolves, in the delay slot
//! ```
//!
//! `sstrip` removes the section headers, so nothing names the stubs. Read
//! as MIPS16e they decode as nothing a compiler emits, and run together;
//! read by their order, an import added moves every stub after it.

use core::ops::Range;

use deku::prelude::*;

use crate::parse::parse_with;

/// The words of a stub, but for the last.
const LOAD_RESOLVER: u32 = 0x8f99_8010;
/// `move t7, ra`, written as `or` by newer `ld`, as `addu` by older.
const SAVE_RETURN: [u32; 2] = [0x03e0_7825, 0x03e0_7821];
const CALL_RESOLVER: u32 = 0x0320_f809;
/// `li t8, index` as `addiu t8, zero, index`, or as `ori t8, zero, index`,
/// with the index in the low half.
const LOAD_INDEX: [u32; 2] = [0x2418_0000, 0x3418_0000];
/// The bytes of a stub.
pub const STUB_LENGTH: u64 = 16;

/// A lazy binding stub: where it lies, and the dynamic symbol it resolves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LazyStub {
    pub range: Range<u64>,
    pub symbol: u64,
}

/// The order of the bytes of a word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    Little,
    Big,
}

impl From<ByteOrder> for deku::ctx::Endian {
    fn from(order: ByteOrder) -> Self {
        match order {
            ByteOrder::Little => Self::Little,
            ByteOrder::Big => Self::Big,
        }
    }
}

/// The four words a stub would hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
struct StubWords {
    load_resolver: u32,
    save_return: u32,
    call_resolver: u32,
    load_index: u32,
}

impl StubWords {
    /// The dynamic symbol the stub resolves, or `None` where the words are
    /// no stub.
    fn symbol(self) -> Option<u64> {
        let is_stub = self.load_resolver == LOAD_RESOLVER
            && SAVE_RETURN.contains(&self.save_return)
            && self.call_resolver == CALL_RESOLVER
            && LOAD_INDEX.contains(&(self.load_index & 0xffff_0000));
        is_stub.then_some(u64::from(self.load_index & 0xffff))
    }
}

/// Every lazy binding stub in `code`, at `base`, in address order.
pub fn lazy_stubs(base: u64, code: &[u8], order: ByteOrder) -> Vec<LazyStub> {
    // Stubs are aligned to their words, so only aligned offsets are tried.
    let first = ((4 - base % 4) % 4) as usize;
    (first..code.len())
        .step_by(4)
        .filter_map(|offset| {
            let words: StubWords = parse_with(&code[offset..], order.into())?;
            let symbol = words.symbol()?;
            let address = base + offset as u64;
            Some(LazyStub { range: address..address + STUB_LENGTH, symbol })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(words: &[u32], order: ByteOrder) -> Vec<u8> {
        words
            .iter()
            .flat_map(|word| match order {
                ByteOrder::Little => word.to_le_bytes(),
                ByteOrder::Big => word.to_be_bytes(),
            })
            .collect()
    }

    /// Two stubs after a word of other code, in both byte orders, and a
    /// stub cut short at the end.
    #[test]
    fn finds_each_stub_and_its_symbol() {
        let code = [
            0x0000_0000,
            LOAD_RESOLVER,
            SAVE_RETURN[0],
            CALL_RESOLVER,
            0x2418_0012,
            LOAD_RESOLVER,
            SAVE_RETURN[1],
            CALL_RESOLVER,
            0x3418_0013,
            LOAD_RESOLVER,
            SAVE_RETURN[0],
        ];
        for order in [ByteOrder::Big, ByteOrder::Little] {
            let found = lazy_stubs(0x1000, &words(&code, order), order);
            assert_eq!(
                found,
                [
                    LazyStub { range: 0x1004..0x1014, symbol: 0x12 },
                    LazyStub { range: 0x1014..0x1024, symbol: 0x13 },
                ]
            );
        }
    }

    /// A call through the resolver slot in a function, with another word
    /// after `jalr`, is no stub.
    #[test]
    fn a_plain_call_is_no_stub() {
        let code = [LOAD_RESOLVER, SAVE_RETURN[0], CALL_RESOLVER, 0x0000_0000];
        assert!(lazy_stubs(0, &words(&code, ByteOrder::Big), ByteOrder::Big).is_empty());
        assert!(lazy_stubs(0, &[], ByteOrder::Big).is_empty());
    }
}
