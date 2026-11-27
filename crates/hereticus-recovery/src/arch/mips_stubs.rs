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

/// Every lazy binding stub in `code`, at `base`, in address order.
pub fn lazy_stubs(base: u64, code: &[u8], order: ByteOrder) -> Vec<LazyStub> {
    let word = |offset: usize| -> Option<u32> {
        let bytes: [u8; 4] = code.get(offset..offset + 4)?.try_into().ok()?;
        Some(match order {
            ByteOrder::Little => u32::from_le_bytes(bytes),
            ByteOrder::Big => u32::from_be_bytes(bytes),
        })
    };
    // Stubs are aligned to their words, so only aligned offsets are tried.
    let first = ((4 - base % 4) % 4) as usize;
    (first..code.len())
        .step_by(4)
        .filter_map(|offset| {
            let load_index = word(offset + 12)?;
            let is_stub = word(offset)? == LOAD_RESOLVER
                && SAVE_RETURN.contains(&word(offset + 4)?)
                && word(offset + 8)? == CALL_RESOLVER
                && LOAD_INDEX.contains(&(load_index & 0xffff_0000));
            let address = base + offset as u64;
            is_stub.then(|| LazyStub {
                range: address..address + STUB_LENGTH,
                symbol: u64::from(load_index & 0xffff),
            })
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
