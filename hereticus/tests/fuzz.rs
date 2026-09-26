//! Property tests over arbitrary input.
//!
//! `hereticus` reads files it did not create: firmware images, stripped binaries,
//! objects from compilers nobody tested against. The library must answer
//! "cannot read this" rather than panic, whatever the bytes hold.
//!
//! Each test here runs two ways. `cargo test` runs it as a property test on
//! stable Rust, which is what continuous integration uses. `cargo bolero fuzz
//! <name>` runs the same body under a coverage-guided fuzzer, which explores
//! far more input but needs a nightly toolchain.

use bolero::check;

use hereticus::address::AddressSpace;
use hereticus::arch::{Arch, DecodeError, InsnKind, arm32::Arm32, decode_all, mips::Mips32};
use hereticus::norm::{normalize, normalize_body, normalize_body_in};
use hereticus::obj::{Binary, Isa};
use hereticus::raw::check_base;

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
        let _ = check_base(data, *base, &Arm32);
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
        let normalized = normalize_body(&Arm32, &insns);

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
        assert_eq!(normalize_body(&Arm32, &insns), normalize_body(&Arm32, &insns));
    });
}

/// Normalizing MIPS must hold the same promises as ARM.
///
/// MIPS is the architecture that drops multi-instruction idioms, so the loop
/// that steps over them runs here and nowhere else. A wrong length would skip
/// past the end of the body or fail to advance at all.
#[test]
fn normalizing_mips_never_panics_and_always_advances() {
    // The concrete type rather than `Isa::arch()`: the property harness needs a
    // value it can carry across an unwind boundary, which `&dyn Arch` is not.
    let arch = &Mips32::LITTLE;
    check!().with_type::<Vec<u8>>().for_each(|code| {
        let (insns, _) = decode_all(arch, code, 0);
        let normalized = normalize_body(arch, &insns);

        // Dropping bookkeeping can only remove instructions. Reaching this line
        // at all proves the loop terminated.
        assert!(normalized.len() <= insns.len(), "normalizing invented instructions");
        assert_eq!(normalized, normalize_body(arch, &insns), "normalizing is unstable");
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
        let normalized = normalize(&Arm32, &insn);

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

        assert_eq!(
            normalize(&Arm32, &first),
            normalize(&Arm32, &second),
            "position changed the normalized form"
        );
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

/// Reverse the bytes of each whole word, which turns a little-endian image
/// into the big-endian image of the same code. A partial word at the end is
/// left as it is.
fn swap_words(data: &[u8]) -> Vec<u8> {
    let whole = data.len() - data.len() % 4;
    let mut swapped: Vec<u8> =
        data[..whole].chunks_exact(4).flat_map(|word| word.iter().rev().copied()).collect();
    swapped.extend_from_slice(&data[whole..]);
    swapped
}

/// Reading a raw MIPS image must never panic, in either order, at any base.
#[test]
fn reading_a_raw_mips_image_never_panics() {
    check!().with_type::<(Vec<u8>, u64)>().for_each(|(data, base)| {
        let _ = Binary::parse_raw(data, *base, Isa::Mips32);
        let _ = Binary::parse_raw(data, *base, Isa::Mips32Be);
    });
}

/// Checking a MIPS load address must never panic, in either order.
#[test]
fn checking_a_mips_base_never_panics() {
    check!().with_type::<(Vec<u8>, u64)>().for_each(|(data, base)| {
        let _ = check_base(data, *base, &Mips32::LITTLE);
        let _ = check_base(data, *base, &Mips32::BIG);
    });
}

/// Where a MIPS image loads must not change what is recovered.
///
/// The bases are the MIPS ones a reader meets: KSEG0 and the boot ROM. Every
/// function must move by the base and hold the same bytes.
#[test]
fn the_base_does_not_change_what_mips_recovers() {
    check!().with_type::<(Vec<u8>, bool)>().for_each(|(data, big)| {
        let isa = if *big { Isa::Mips32Be } else { Isa::Mips32 };
        for base in [0x8000_0000, 0xbfc0_0000] {
            let low = Binary::parse_raw(data, 0, isa);
            let high = Binary::parse_raw(data, base, isa);

            match (low, high) {
                (Ok(low), Ok(high)) => {
                    let moved: Vec<(u64, &[u8])> = low
                        .functions
                        .iter()
                        .map(|function| (function.address + base, function.code.as_slice()))
                        .collect();
                    let found: Vec<(u64, &[u8])> = high
                        .functions
                        .iter()
                        .map(|function| (function.address, function.code.as_slice()))
                        .collect();
                    assert_eq!(found, moved, "the base changed what was recovered");
                }
                (Err(_), Err(_)) => {}
                _ => panic!("the base decided whether the image could be read at all"),
            }
        }
    });
}

/// The same code in either byte order gives the same functions.
///
/// Each order has its own decoder, and everything above the decoder reads
/// decoded text. A rule that reached for raw bytes would split the two here.
#[test]
fn both_mips_byte_orders_recover_the_same_functions() {
    check!().with_type::<Vec<u8>>().for_each(|data| {
        let little = Binary::parse_raw(data, 0, Isa::Mips32);
        let big = Binary::parse_raw(&swap_words(data), 0, Isa::Mips32Be);

        match (little, big) {
            (Ok(little), Ok(big)) => {
                let span = |binary: &Binary| -> Vec<(u64, usize)> {
                    binary
                        .functions
                        .iter()
                        .map(|function| (function.address, function.code.len()))
                        .collect()
                };
                assert_eq!(span(&little), span(&big), "the byte order moved a boundary");
            }
            (Err(little), Err(big)) => {
                assert_eq!(format!("{little:?}"), format!("{big:?}"), "the orders failed apart");
            }
            _ => panic!("the byte order decided whether the image could be read at all"),
        }
    });
}

/// The load-address check reads a stored address in the order of the image,
/// so the same table in either order gets the same verdict.
#[test]
fn both_mips_byte_orders_judge_a_base_alike() {
    check!().with_type::<(Vec<u8>, u64)>().for_each(|(data, base)| {
        assert_eq!(
            check_base(data, *base, &Mips32::LITTLE),
            check_base(&swap_words(data), *base, &Mips32::BIG),
        );
    });
}

/// Decoding MIPS must never panic, must always advance, and must place each
/// instruction one word after the last.
fn mips_decoding_is_contiguous(arch: &'static Mips32) {
    check!().with_type::<(Vec<u8>, u32)>().for_each(|(code, base)| {
        let base = u64::from(*base);
        let (insns, error) = decode_all(arch, code, base);

        for (index, insn) in insns.iter().enumerate() {
            assert_eq!(insn.bytes_len, 4, "MIPS32 instructions are always four bytes");
            assert_eq!(insn.address, base + index as u64 * 4, "instruction {index} is misplaced");
        }
        if error.is_none() {
            assert_eq!(insns.len() * 4, code.len(), "decoding stopped early without an error");
        } else {
            assert_eq!(insns.len(), code.len() / 4, "decoding stopped before the partial word");
        }
    });
}

#[test]
fn mips_little_endian_decoding_is_contiguous() {
    mips_decoding_is_contiguous(&Mips32::LITTLE);
}

#[test]
fn mips_big_endian_decoding_is_contiguous() {
    mips_decoding_is_contiguous(&Mips32::BIG);
}

/// A MIPS instruction must not depend on the bytes after it, and too few
/// bytes must report truncation.
fn mips_decoding_reads_only_its_own_word(arch: &'static Mips32) {
    check!().with_type::<([u8; 4], Vec<u8>)>().for_each(|(head, tail)| {
        let alone = arch.decode(head, 0, 0);

        let mut joined = head.to_vec();
        joined.extend_from_slice(tail);
        assert_eq!(alone, arch.decode(&joined, 0, 0), "trailing bytes changed an instruction");

        for length in 0..4 {
            assert_eq!(arch.decode(&head[..length], 0, 0), Err(DecodeError::Truncated));
        }
    });
}

#[test]
fn mips_little_endian_decoding_reads_only_its_own_word() {
    mips_decoding_reads_only_its_own_word(&Mips32::LITTLE);
}

#[test]
fn mips_big_endian_decoding_reads_only_its_own_word() {
    mips_decoding_reads_only_its_own_word(&Mips32::BIG);
}

/// The two MIPS decoders read a word and its byte swap as one instruction.
#[test]
fn mips_byte_orders_decode_alike() {
    check!().with_type::<([u8; 4], u32)>().for_each(|(word, address)| {
        let mut swapped = *word;
        swapped.reverse();
        let address = u64::from(*address);

        assert_eq!(
            Mips32::LITTLE.decode(word, 0, address),
            Mips32::BIG.decode(&swapped, 0, address),
            "the byte order changed what a word means"
        );
    });
}

/// Where a MIPS instruction sits must not change what it normalizes to, in
/// either order, and a normalized MIPS instruction equals itself.
fn mips_normalizing_ignores_position(arch: &'static Mips32) {
    check!().with_type::<([u8; 4], u32)>().for_each(|(bytes, base)| {
        let (Ok(first), Ok(second)) =
            (arch.decode(bytes, 0, 0), arch.decode(bytes, 0, u64::from(*base)))
        else {
            return;
        };

        let normalized = normalize(arch, &first);
        assert_eq!(normalized, normalize(arch, &second), "position changed the normalized form");
        assert!(!normalized.differs_in_detail(&normalized.clone()));
    });
}

#[test]
fn mips_little_endian_normalizing_ignores_position() {
    mips_normalizing_ignores_position(&Mips32::LITTLE);
}

#[test]
fn mips_big_endian_normalizing_ignores_position() {
    mips_normalizing_ignores_position(&Mips32::BIG);
}

/// Normalizing big-endian MIPS holds the same promises as little endian.
#[test]
fn normalizing_big_endian_mips_never_panics_and_always_advances() {
    let arch = &Mips32::BIG;
    check!().with_type::<Vec<u8>>().for_each(|code| {
        let (insns, _) = decode_all(arch, code, 0);
        let normalized = normalize_body(arch, &insns);

        assert!(normalized.len() <= insns.len(), "normalizing invented instructions");
        assert_eq!(normalized, normalize_body(arch, &insns), "normalizing is unstable");
    });
}

/// Judging MIPS addresses must never panic, and must give one kind for each
/// instruction, whatever the code and wherever it sits.
#[test]
fn mips_constant_kinds_cover_every_instruction() {
    check!().with_type::<(Vec<u8>, u32, u32)>().for_each(|(code, base, length)| {
        let space = AddressSpace::of_raw_image(u64::from(*base), u64::from(*length));
        for arch in [&Mips32::LITTLE, &Mips32::BIG] {
            let (insns, _) = decode_all(arch, code, u64::from(*base));
            assert_eq!(arch.constant_kinds(code, &insns, &space).len(), insns.len());
        }
    });
}

/// Placing a body in a space only removes constants: it keeps every
/// instruction and every operand shape, and adds nothing.
#[test]
fn a_space_only_removes_constants() {
    check!().with_type::<(Vec<u8>, u32)>().for_each(|(code, length)| {
        let base = 0x8000_0000;
        let space = AddressSpace::of_raw_image(base, u64::from(*length));
        for arch in [&Mips32::LITTLE, &Mips32::BIG] {
            let (insns, _) = decode_all(arch, code, base);
            let plain = normalize_body(arch, &insns);
            let placed = normalize_body_in(arch, code, &insns, &space);

            assert_eq!(plain, placed, "the space changed an operation or a shape");
            for (without, with) in plain.iter().zip(&placed) {
                assert!(
                    with.constants.is_empty() || with.constants == without.constants,
                    "the space changed a constant rather than removing it"
                );
            }
        }
    });
}

/// An empty space changes nothing at all.
#[test]
fn an_empty_space_changes_nothing() {
    check!().with_type::<Vec<u8>>().for_each(|code| {
        for arch in [&Mips32::LITTLE, &Mips32::BIG] {
            let (insns, _) = decode_all(arch, code, 0x8000_0000);
            let plain = normalize_body(arch, &insns);
            let placed = normalize_body_in(arch, code, &insns, &AddressSpace::none());
            for (without, with) in plain.iter().zip(&placed) {
                assert_eq!(without.constants, with.constants);
            }
        }
    });
}

/// Judging code against data must never panic, in either byte order.
#[test]
fn judging_mips_contents_never_panics() {
    check!().with_type::<(Vec<u8>, u32)>().for_each(|(code, length)| {
        let space = AddressSpace::of_raw_image(0x8000_0000, u64::from(*length));
        for arch in [&Mips32::LITTLE, &Mips32::BIG] {
            let (insns, _) = decode_all(arch, code, 0x8000_0000);
            let _ = arch.contents(code, &insns, &space);
        }
    });
}
