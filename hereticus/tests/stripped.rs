//! Measure function recovery on binaries with no symbol table.
//!
//! Every fixture exists twice: once with symbols and once stripped. The
//! symbol table of the first is the answer for the second, so these tests can
//! state what recovery got right rather than only that it ran.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hereticus::matching::{Changed, Options, UseNames, diff_with};
use hereticus::obj::{Binary, FoundBy};

fn object_path(directory: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/build")
        .join(directory)
        .join(format!("{name}.o"))
}

fn read(directory: &str, name: &str) -> Option<Binary> {
    let data = std::fs::read(object_path(directory, name)).ok()?;
    Binary::parse(&data).ok()
}

/// Where each function starts, and how long it is.
fn extents(binary: &Binary) -> BTreeSet<(u64, usize)> {
    binary.functions.iter().map(|function| (function.address, function.code.len())).collect()
}

fn fixtures_present() -> bool {
    object_path("O2-stripped", "basic").exists()
}

/// Recovery must find every function, at the right place and the right size.
///
/// The fixtures carry an ARM exception index, which lists one entry per
/// function and survives stripping. Where that is present the answer should
/// be exact, so this test demands exactness rather than a ratio.
#[test]
fn recovers_every_function_from_a_stripped_object() {
    assert!(fixtures_present(), "run `just fixtures` first");

    for level in ["O0", "O1", "O2", "Os"] {
        let (Some(truth), Some(stripped)) =
            (read(level, "basic"), read(&format!("{level}-stripped"), "basic"))
        else {
            continue;
        };

        assert_eq!(truth.found_by, FoundBy::Symbols, "{level}: the original keeps its symbols");
        assert_eq!(stripped.found_by, FoundBy::Scanning, "{level}: the copy has none");

        assert_eq!(
            extents(&stripped),
            extents(&truth),
            "{level}: recovered functions must match the symbol table exactly"
        );
    }
}

/// A recovered function has no name, so one is made from its address.
#[test]
fn recovered_functions_have_no_names() {
    assert!(fixtures_present(), "run `just fixtures` first");
    let Some(stripped) = read("O2-stripped", "basic") else { return };

    assert!(
        stripped.functions.iter().all(|function| function.name.is_empty()),
        "a stripped object holds no names to read"
    );
}

/// Comparing two stripped binaries must give the same answer as comparing the
/// two originals.
///
/// This is the property that matters. Firmware ships stripped, so a result
/// that needs symbols is of no use.
#[test]
fn a_stripped_comparison_agrees_with_an_unstripped_one() {
    assert!(fixtures_present(), "run `just fixtures` first");

    let (Some(before), Some(after)) = (read("O2", "basic"), read("O2", "basic_v2")) else {
        panic!("fixtures are missing");
    };
    let (Some(stripped_before), Some(stripped_after)) =
        (read("O2-stripped", "basic"), read("O2-stripped", "basic_v2"))
    else {
        panic!("stripped fixtures are missing");
    };

    let options = Options { use_names: UseNames::No, ..Default::default() };
    let with_symbols = diff_with(&before, &after, options);
    let without = diff_with(&stripped_before, &stripped_after, options);

    assert_eq!(
        without.matched.len(),
        with_symbols.matched.len(),
        "the same functions must be paired either way"
    );
    assert_eq!(
        without.changed().count(),
        with_symbols.changed().count(),
        "the same functions must be reported as changed either way"
    );

    // Compare by address, which is the one name both sides share.
    let changed_addresses = |diff: &hereticus::matching::Diff, binary: &Binary| -> BTreeSet<u64> {
        diff.changed().map(|pair| binary.functions[pair.before].address).collect()
    };

    assert_eq!(
        changed_addresses(&without, &stripped_before),
        changed_addresses(&with_symbols, &before),
        "the same addresses must be reported as changed"
    );
}

/// The three planned edits must still be found without symbols.
#[test]
fn finds_the_planned_edits_in_stripped_objects() {
    assert!(fixtures_present(), "run `just fixtures` first");

    let (Some(before), Some(after)) =
        (read("O2-stripped", "basic"), read("O2-stripped", "basic_v2"))
    else {
        panic!("stripped fixtures are missing");
    };

    let diff = diff_with(&before, &after, Options::default());

    // From the symbol table of the unstripped originals: mul_by_constant at
    // 0x8, classify at 0x3c, array_max at 0x90, and call_chain at 0x80, which
    // inlined the edited constant.
    let changed: BTreeSet<u64> =
        diff.changed().map(|pair| before.functions[pair.before].address).collect();

    assert_eq!(
        changed,
        BTreeSet::from([0x8, 0x3c, 0x80, 0x90]),
        "the edits must be found at the same addresses as with symbols"
    );
}

/// Recovery must still work when the exception index is gone too.
///
/// Then nothing is left but the code, so the boundaries come from call
/// targets and from what follows a return. That is a guess, and this test
/// states how good a guess it is rather than assuming it is perfect.
#[test]
fn recovers_functions_with_nothing_but_the_code() {
    let bare = object_path("bare", "basic");
    if !bare.exists() {
        eprintln!("skipped: run `just fixtures` first");
        return;
    }

    let data = std::fs::read(&bare).expect("the fixture must be readable");
    let recovered = Binary::parse(&data).expect("a bare object must still yield functions");
    assert_eq!(recovered.found_by, FoundBy::Scanning);

    let Some(truth) = read("O2", "basic") else { return };
    let real_starts: BTreeSet<u64> =
        truth.functions.iter().map(|function| function.address).collect();
    let found: BTreeSet<u64> =
        recovered.functions.iter().map(|function| function.address).collect();

    // Every real function must be found. Without the exception index the scan
    // still splits some functions at a return it cannot rule out, so it finds
    // more than there are; those extra boundaries are the cost of guessing.
    let missed: Vec<&u64> = real_starts.difference(&found).collect();
    assert!(missed.is_empty(), "every real function must be found, but missed {missed:?}");

    // How much it over-splits is worth holding still. Ignoring returns that a
    // branch crosses took this corpus from 16 recovered starts to 14, and a
    // kernel object from 10 to exactly its 4. A change that makes this worse
    // should have to say so.
    assert!(
        found.len() <= real_starts.len() * 2,
        "recovered {} starts for {} functions, which is more splitting than expected",
        found.len(),
        real_starts.len()
    );
}

/// A file with code but no recoverable function must say so.
///
/// Returning an empty result would read as "nothing changed", which is the
/// opposite of the truth.
#[test]
fn reports_a_binary_it_cannot_analyze() {
    // An ELF header for ARM with a `.text` section holding one unreadable
    // word is hard to build by hand, so this checks the simpler promise: a
    // file that is not an object at all is refused rather than accepted as
    // empty.
    assert!(Binary::parse(b"not an object at all").is_err());
    assert!(Binary::parse(&[]).is_err());
}

/// Recovery must find the start of a PIC function, not the middle of it.
///
/// MIPS ABI PIC — what every shared object and most firmware is built as —
/// opens a function by computing the global pointer, so the frame allocation
/// that marks a prologue is the third instruction rather than the first.
/// Reading the prologue as the start puts every boundary 8 bytes into its own
/// function: measured on this fixture, five of eight starts were late before
/// the scanner learned to step back over the preamble.
#[test]
fn recovers_the_start_of_a_pic_function() {
    let (Some(truth), Some(stripped)) =
        (read("mips-pic-O2", "calls"), read("mips-pic-O2-stripped", "calls"))
    else {
        // The PIC fixtures need a clang that targets MIPS. Without them there
        // is nothing to check, and the ARM tests already cover the rest.
        return;
    };

    assert_eq!(truth.found_by, FoundBy::Symbols, "the original keeps its symbols");
    assert_eq!(stripped.found_by, FoundBy::Scanning, "the copy has none");

    let real_starts: BTreeSet<u64> = truth.functions.iter().map(|f| f.address).collect();
    let found_starts: BTreeSet<u64> = stripped.functions.iter().map(|f| f.address).collect();

    assert_eq!(
        found_starts, real_starts,
        "a PIC function begins at its global-pointer setup, not at its prologue"
    );
}

/// Dropping the PIC preamble must not take a real address load with it.
///
/// A non-PIC build loads the address of a global with the same two words the
/// preamble opens with — `lui rX, 0x0` then `addiu rX, rX, 0x0`, both immediates
/// zero because the linker has yet to fill them in. Only what consumes the
/// result separates the two, so a rule that went by the shape alone would delete
/// a memory reference from ordinary code.
#[test]
fn a_real_address_load_survives_normalizing() {
    use hereticus::il::Op;
    use hereticus::norm::Operation;
    use hereticus::{norm::normalize_body, recovery::arch::decode_all};

    let Some(binary) = read("mips-nopic-O2", "globals") else { return };
    let arch = binary.isa.arch();

    let Some(reader) = binary.functions.iter().find(|f| f.name == "read_table") else {
        panic!("the fixture must hold read_table");
    };

    let (insns, _) = decode_all(arch, &reader.code, reader.address);
    let body = normalize_body(arch, &insns);

    // The function is `lui`, `addiu`, `andi`, `sll`, `addu`, `lw`, `jr`, `nop`.
    // Nothing here is frame work, so normalizing must keep all of it bar the
    // padding `nop` the decoder reports at the end.
    assert!(
        body.len() >= insns.len() - 1,
        "normalizing dropped {} of {} instructions from a plain address load",
        insns.len() - body.len(),
        insns.len()
    );

    // Said directly: the two words that build the address must still be there.
    let operations: Vec<Operation> = body.iter().map(|insn| insn.operation).collect();
    let lui = Operation::Lifted { op: Op::Address, width: None };
    assert!(operations.contains(&lui), "the address load must survive, got {operations:?}");
}

/// The PIC preamble must not be compared, or it measures the ABI.
///
/// Every function a PIC build compiles carries the same preamble, so leaving it
/// in raises the similarity of functions that have nothing to do with each
/// other. Measured on this fixture, unrelated pairs averaged 0.44 with the
/// preamble against 0.34 without it, which is signal lost to the ABI.
/// Both byte orders must give one answer, because the rules read decoded text
/// rather than stored bytes. Big endian is the order shipped firmware uses, so
/// it is the one that matters most.
#[test]
fn the_pic_preamble_does_not_make_unrelated_functions_look_alike() {
    for (pic_build, nopic_build) in
        [("mips-pic-O2", "mips-nopic-O2"), ("mipsbe-pic-O2", "mipsbe-nopic-O2")]
    {
        pic_costs_the_comparison_nothing(pic_build, nopic_build);
    }
}

/// The body of the test above, run once per byte order.
fn pic_costs_the_comparison_nothing(pic_build: &str, nopic_build: &str) {
    use hereticus::{matching::similarity, norm::normalize_body, recovery::arch::decode_all};

    let (Some(pic), Some(nopic)) = (read(pic_build, "calls"), read(nopic_build, "calls")) else {
        return;
    };

    let mean_unrelated = |binary: &Binary| {
        let arch = binary.isa.arch();
        let bodies: Vec<_> = binary
            .functions
            .iter()
            .map(|function| {
                let (insns, _) = decode_all(arch, &function.code, function.address);
                normalize_body(arch, &insns)
            })
            .collect();

        let mut total = 0.0;
        let mut count = 0;
        for (index, left) in bodies.iter().enumerate() {
            for right in bodies.iter().skip(index + 1) {
                total += similarity(left, right);
                count += 1;
            }
        }
        total / f64::from(count)
    };

    let (pic_noise, nopic_noise) = (mean_unrelated(&pic), mean_unrelated(&nopic));

    // With the whole idiom accounted for — the preamble, the global-pointer
    // restores and the GOT reads — PIC costs the comparison nothing: measured on
    // this fixture the gap is -0.002, so a PIC build is no noisier than the same
    // code built without it. Each piece left in raises it: 0.028 with the GOT
    // reads compared, 0.075 with the `_gp_disp` pair as well, and 0.098 with
    // none of it dropped. The bound sits below the smallest of those, so any
    // part of the idiom returning to the comparison fails this test.
    assert!(
        pic_noise - nopic_noise < 0.02,
        "{pic_build}: PIC decoys at {pic_noise:.3} against {nopic_noise:.3}, \
         so the ABI is being compared"
    );
}

/// The same source must normalize alike in either byte order.
///
/// Every PIC rule reads the decoded text, which the two decoders render the
/// same way, so nothing here should depend on how a word is stored. A rule that
/// reached for raw bytes would work in one order and quietly fail in the other,
/// and firmware ships big endian: the order that would break is the one that
/// matters.
#[test]
fn the_pic_rules_do_not_depend_on_byte_order() {
    use hereticus::{norm::normalize_body, recovery::arch::decode_all};

    let (Some(little), Some(big)) = (read("mips-pic-O2", "calls"), read("mipsbe-pic-O2", "calls"))
    else {
        return;
    };

    assert_eq!(little.isa, hereticus::obj::Isa::Mips32, "the fixture must be little endian");
    assert_eq!(big.isa, hereticus::obj::Isa::Mips32Be, "the fixture must be big endian");

    let kept = |binary: &Binary| -> Vec<(String, usize, usize)> {
        let arch = binary.isa.arch();
        binary
            .functions
            .iter()
            .map(|function| {
                let (insns, _) = decode_all(arch, &function.code, function.address);
                (function.name.clone(), insns.len(), normalize_body(arch, &insns).len())
            })
            .collect()
    };

    assert_eq!(
        kept(&little),
        kept(&big),
        "the same function must keep the same instructions in either order"
    );
}

/// Matching a stripped binary against an unstripped one must still work.
///
/// This is the patch-checking case: a vendor image against a reference build.
#[test]
fn matches_a_stripped_binary_against_an_unstripped_one() {
    assert!(fixtures_present(), "run `just fixtures` first");

    let (Some(reference), Some(shipped)) = (read("O2", "basic"), read("O2-stripped", "basic"))
    else {
        panic!("fixtures are missing");
    };

    let diff = diff_with(&reference, &shipped, Options::default());

    assert_eq!(diff.matched.len(), reference.functions.len(), "every function must be paired");
    assert!(
        diff.matched.iter().all(|pair| pair.changed == Changed::No),
        "stripping changes no code, so nothing must be reported as changed"
    );
}
