//! Property tests over arbitrary input.
//!
//! `tech-heresy` reads files it did not create: firmware images, stripped binaries,
//! objects from compilers nobody tested against. The library must answer
//! "cannot read this" rather than panic, whatever the bytes hold.
//!
//! Each test here runs two ways. `cargo test` runs it as a property test on
//! stable Rust, which is what continuous integration uses. `cargo bolero fuzz
//! <name>` runs the same body under a coverage-guided fuzzer, which explores
//! far more input but needs a nightly toolchain.

use bolero::check;

use tech_heresy::arch::{Arch, DecodeError, InsnKind, arm32::Arm32, decode_all};
use tech_heresy::norm::{normalize, normalize_body};
use tech_heresy::obj::{Binary, Isa};
use tech_heresy::raw::check_base;

/// Reading a file must never panic, whatever it holds.
#[test]
fn parsing_never_panics() {
    check!().with_type::<Vec<u8>>().for_each(|data| {
        let _ = Binary::parse(data);
    });
}

/// Reading a raw image must never panic, at any base.
///
/// A firmware image is bytes with no header to sanity check, and the base
/// comes from a person who may have it wrong. Both are fully controlled by
/// whoever supplies them, so this is the widest attack surface the crate has.
#[test]
fn reading_a_raw_image_never_panics() {
    check!().with_type::<(Vec<u8>, u64)>().for_each(|(data, base)| {
        let _ = Binary::parse_raw(data, *base, Isa::Arm32);
    });
}

/// Checking a load address must never panic, including near the top of the
/// address range where the image would wrap.
#[test]
fn checking_a_base_never_panics() {
    check!().with_type::<(Vec<u8>, u64)>().for_each(|(data, base)| {
        let _ = check_base(data, *base);
    });
}

/// Where an image loads must not change how many functions are found.
///
/// Recovery works from the code, and the code does not change when the base
/// does. A difference here would mean an address calculation had overflowed or
/// wrapped.
#[test]
fn the_base_does_not_change_what_is_recovered() {
    check!().with_type::<Vec<u8>>().for_each(|data| {
        let low = Binary::parse_raw(data, 0, Isa::Arm32);
        let high = Binary::parse_raw(data, 0x0800_0000, Isa::Arm32);

        match (low, high) {
            (Ok(low), Ok(high)) => {
                assert_eq!(
                    low.functions.len(),
                    high.functions.len(),
                    "the base changed how many functions were found"
                );
            }
            (Err(_), Err(_)) => {}
            _ => panic!("the base decided whether the image could be read at all"),
        }
    });
}

/// Decoding must never panic, and must always make progress.
///
/// A decoder that reports success while consuming nothing would hang the
/// caller. [`decode_all`] guards against that, so this checks the guard holds
/// for real input.
#[test]
fn decoding_never_panics_and_always_advances() {
    check!().with_type::<Vec<u8>>().for_each(|code| {
        let (insns, error) = decode_all(&Arm32, code, 0);

        // Every instruction must cover at least one byte, and they must not
        // cover more than the input holds.
        let covered: usize = insns.iter().map(|insn| insn.bytes_len).sum();
        assert!(insns.iter().all(|insn| insn.bytes_len > 0), "an instruction covered no bytes");
        assert!(covered <= code.len(), "decoding covered more bytes than were given");

        // Decoding stops only at the end of the input or on an error.
        if error.is_none() {
            assert_eq!(covered, code.len(), "decoding stopped early without an error");
        }
    });
}

/// Every A32 instruction is four bytes wide, with no exceptions.
///
/// The properties below all compare the decoder against itself, so a width
/// that is wrong by the same amount everywhere satisfies them. This test
/// states the width against the architecture instead, which is what catches
/// the word-versus-byte offset mistake.
#[test]
fn every_instruction_is_four_bytes_wide() {
    check!().with_type::<Vec<u8>>().for_each(|code| {
        let (insns, _) = decode_all(&Arm32, code, 0);
        for insn in &insns {
            assert_eq!(insn.bytes_len, 4, "A32 instructions are always four bytes");
        }
    });
}

/// Addresses must rise by the width of each instruction, with no gaps.
///
/// This is the property the word-versus-byte offset bug broke. A fuzzer
/// reaches encodings that hand-written tests do not.
#[test]
fn decoded_addresses_are_contiguous() {
    check!().with_type::<(Vec<u8>, u32)>().for_each(|(code, base)| {
        let base = u64::from(*base);
        let (insns, _) = decode_all(&Arm32, code, base);

        // Check against the position each instruction must hold, not against
        // the width the decoder reported. Using the reported width would make
        // this test agree with a decoder that is wrong the same way twice.
        for (index, insn) in insns.iter().enumerate() {
            let expected = base + (index as u64 * 4);
            assert_eq!(insn.address, expected, "instruction {index} sits at the wrong address");
        }
    });
}

/// Decoding one instruction must not depend on what follows it.
///
/// ARM32 has a fixed width, so the first instruction of a slice must decode
/// the same whatever comes after. If it does not, the decoder is reading past
/// its instruction.
#[test]
fn decoding_reads_only_its_own_instruction() {
    check!().with_type::<([u8; 4], Vec<u8>)>().for_each(|(head, tail)| {
        let alone = Arm32.decode(head, 0, 0);

        let mut joined = head.to_vec();
        joined.extend_from_slice(tail);
        let with_tail = Arm32.decode(&joined, 0, 0);

        assert_eq!(alone, with_tail, "trailing bytes changed how an instruction decoded");
    });
}

/// Too few bytes must report truncation, never a wrong instruction.
#[test]
fn short_input_reports_truncation() {
    check!().with_type::<Vec<u8>>().for_each(|data| {
        let short = &data[..data.len().min(3)];
        assert_eq!(Arm32.decode(short, 0, 0), Err(DecodeError::Truncated));
    });
}

/// Normalizing must never panic, whatever the decoder produced.
#[test]
fn normalizing_never_panics() {
    check!().with_type::<Vec<u8>>().for_each(|code| {
        let (insns, _) = decode_all(&Arm32, code, 0);
        let normalized = normalize_body(&insns);

        // Dropping frame management can only remove instructions.
        assert!(normalized.len() <= insns.len(), "normalizing invented instructions");
    });
}

/// Normalizing must give the same answer every time.
///
/// Matching compares normalized forms, so an unstable normalizer would make
/// results depend on when they were computed.
#[test]
fn normalizing_is_deterministic() {
    check!().with_type::<Vec<u8>>().for_each(|code| {
        let (insns, _) = decode_all(&Arm32, code, 0);
        assert_eq!(normalize_body(&insns), normalize_body(&insns));
    });
}

/// An instruction must always equal itself once normalized.
///
/// Similarity scoring divides by counts of equal instructions, so a form that
/// failed to equal itself would score a function against its own copy at less
/// than one.
#[test]
fn normalized_instructions_equal_themselves() {
    check!().with_type::<[u8; 4]>().for_each(|bytes| {
        let Ok(insn) = Arm32.decode(bytes, 0, 0) else { return };
        let normalized = normalize(&insn);

        assert_eq!(normalized, normalized.clone(), "a normalized instruction differed from itself");
        assert!(
            !normalized.differs_in_detail(&normalized.clone()),
            "an instruction differed in detail from itself"
        );
    });
}

/// Where an instruction sits must not change what it normalizes to.
///
/// Only the address changes between these two decodes, and normalizing drops
/// addresses, so the results must agree. Without this, a function that moved
/// in the binary would stop matching itself.
#[test]
fn normalizing_ignores_position() {
    check!().with_type::<([u8; 4], u32)>().for_each(|(bytes, base)| {
        let (Ok(first), Ok(second)) =
            (Arm32.decode(bytes, 0, 0), Arm32.decode(bytes, 0, u64::from(*base)))
        else {
            return;
        };

        assert_eq!(normalize(&first), normalize(&second), "position changed the normalized form");
    });
}

/// Unreadable bytes must be reported as opaque, never as a real instruction.
#[test]
fn unreadable_bytes_are_marked_opaque() {
    check!().with_type::<[u8; 4]>().for_each(|bytes| {
        let Ok(insn) = Arm32.decode(bytes, 0, 0) else { return };

        // Opaque bytes still take up their full width, which is what keeps
        // the instructions after them aligned, and they carry the raw word so
        // that one unreadable instruction can be told from another.
        if insn.kind == InsnKind::Unknown {
            assert_eq!(insn.bytes_len, 4);
            assert!(!insn.operands.is_empty(), "opaque bytes must carry their raw word");

            let word = u32::from_le_bytes(*bytes);
            assert_eq!(insn.operands, format!("{word:#010x}"), "the raw word must be reported");
        }
    });
}
