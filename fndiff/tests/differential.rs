//! Check the decoder against `llvm-objdump` on every fixture function.
//!
//! Hand-written byte tests only cover encodings someone thought to write. This
//! harness covers everything the compiler emits, which is where a decoder
//! actually fails.
//!
//! The comparison is on instruction **boundaries and mnemonics**, not operand
//! text. Two disassemblers disagree about operand syntax constantly and none
//! of those differences matter. A disagreement on boundaries means the decoder
//! lost sync, and every instruction after it is wrong.

use std::path::{Path, PathBuf};
use std::process::Command;

use fndiff::arch::{Arch, InsnKind, decode_all};
use fndiff::obj::Binary;

/// One instruction as `llvm-objdump` reported it.
#[derive(Debug, PartialEq, Eq)]
struct ObjdumpInsn {
    address: u64,
    mnemonic: String,
}

/// Reduce a mnemonic to a form both disassemblers agree on.
///
/// The two tools decode the same bits but print them differently. Each rule
/// below was confirmed against the encoding, not assumed:
///
/// * `cmp` always sets flags, so `yaxpeax` writes the `s` suffix that LLVM
///   leaves implied.
/// * `movw` is the wide immediate move, which `yaxpeax` prints as `mov`.
/// * `lsr` is an alias of `mov` with a shifted operand; LLVM prefers the
///   alias.
/// * `rrx` is an alias of `mov` with a rotate-right-extended operand.
/// * `adr` is `add <reg>, pc, #imm`, which LLVM prints in the long form.
/// * LLVM folds the condition code into the mnemonic (`movlo`), while
///   `yaxpeax` keeps it separate. Strip a trailing condition before
///   comparing.
///
/// Keep this list short and justified. Each entry hides a real difference, so
/// a wrong entry hides a real bug.
fn canonical_mnemonic(mnemonic: &str) -> String {
    // Fold spellings before stripping, because `movs` ends in `vs`, which is
    // also the overflow-set condition. Fold again after, because a condition
    // can wrap an alias, as in `movwlt`.
    fold_alias(strip_condition(fold_alias(mnemonic))).to_string()
}

/// Map the spellings that mean the same encoding onto one name.
fn fold_alias(mnemonic: &str) -> &str {
    match mnemonic {
        "cmps" => "cmp",
        "adr" => "add",
        "movw" | "movs" | "lsr" | "lsrs" | "rrx" => "mov",
        other => other,
    }
}

/// Remove a trailing ARM condition code.
///
/// Only strip when the stem is still a plausible mnemonic. Several mnemonics
/// end in the same letters as a condition (`movs` in `vs`, `ble` in `le`), and
/// stripping those would produce nonsense.
fn strip_condition(mnemonic: &str) -> &str {
    const CONDITIONS: [&str; 17] = [
        "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al",
        // `lo` and `hs` are the other spellings of `cc` and `cs`.
        "lo", "hs",
    ];

    // Mnemonics that end in condition letters but carry no condition.
    const NOT_CONDITIONAL: [&str; 6] = ["b", "bl", "ble", "bls", "movs", "cmps"];

    if NOT_CONDITIONAL.contains(&mnemonic) {
        return mnemonic;
    }

    for suffix in &CONDITIONS {
        if let Some(stem) = mnemonic.strip_suffix(suffix)
            // A real mnemonic is at least two characters, so `bx` survives
            // but a one-letter stem means the match was a coincidence.
            && stem.len() >= 2
        {
            return stem;
        }
    }
    mnemonic
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build")
}

/// Fixture objects, or an empty list when `just fixtures` has not run.
fn fixture_objects() -> Vec<PathBuf> {
    let mut objects = Vec::new();
    let Ok(levels) = std::fs::read_dir(fixtures_dir()) else { return objects };

    for level in levels.flatten() {
        let Ok(entries) = std::fs::read_dir(level.path()) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "o") {
                objects.push(path);
            }
        }
    }
    objects.sort();
    objects
}

/// Disassemble one symbol with `llvm-objdump`.
///
/// Returns `None` when `llvm-objdump` is missing, so the test can skip instead
/// of failing on a machine without it.
fn objdump_function(object: &Path, triple: &str, symbol: &str) -> Option<Vec<ObjdumpInsn>> {
    let output = Command::new("llvm-objdump")
        .arg("-d")
        .arg(format!("--triple={triple}"))
        .arg(format!("--disassemble-symbols={symbol}"))
        .arg(object)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }
    Some(parse_objdump(&String::from_utf8_lossy(&output.stdout)))
}

/// Pull address and mnemonic out of `llvm-objdump` text.
///
/// Instruction lines look like:
/// ```text
///        0: e0810000     <TAB>add<TAB>r0, r1, r0
/// ```
///
/// The separators are real tab characters, written here as `<TAB>` so the
/// example stays readable.
fn parse_objdump(text: &str) -> Vec<ObjdumpInsn> {
    let mut out = Vec::new();

    for line in text.lines() {
        let Some((address_part, rest)) = line.split_once(':') else { continue };
        let Ok(address) = u64::from_str_radix(address_part.trim(), 16) else { continue };

        // After the colon comes the encoding, then a tab, then the mnemonic.
        let mut fields = rest.split('\t').map(str::trim).filter(|field| !field.is_empty());
        let Some(_encoding) = fields.next() else { continue };
        let Some(mnemonic) = fields.next() else { continue };

        // Data that objdump cannot decode prints as `<unknown>`; skip it.
        if mnemonic.starts_with('<') {
            continue;
        }
        out.push(ObjdumpInsn { address, mnemonic: mnemonic.to_string() });
    }

    out
}

#[test]
fn decoder_agrees_with_objdump() {
    let objects = fixture_objects();
    assert!(
        !objects.is_empty(),
        "no fixtures found in {}; run `just fixtures` first",
        fixtures_dir().display()
    );

    let mut checked_functions = 0usize;
    let mut checked_instructions = 0usize;
    let mut unknown_instructions = 0usize;
    let mut skipped_objects = 0usize;

    for object_path in &objects {
        let data = std::fs::read(object_path).expect("fixture must be readable");
        let binary = Binary::parse(&data).expect("fixture must parse");
        let arch = binary.isa.arch();

        for function in &binary.functions {
            let Some(expected) = objdump_function(object_path, arch.triple(), &function.name)
            else {
                skipped_objects += 1;
                continue;
            };
            if expected.is_empty() {
                continue;
            }

            // The two tools disagree about where a function ends, in both
            // directions, and neither disagreement is a decoder fault:
            //
            // * A symbol can cover data as well as code. Jump tables and
            //   constant pools sit inside `.text` within the function extent,
            //   so this decoder reads words that `llvm-objdump` skips.
            // * `llvm-objdump` disassembles to the next symbol, not to the
            //   end of this one, so it can print alignment padding that the
            //   symbol size excludes.
            //
            // Compare the overlap, which is the part both call code. Deciding
            // where a function truly ends belongs to function recovery.
            let (decoded, _error) = decode_all(&arch, &function.code, function.address);
            let where_ = format!("{}: {}", object_path.display(), function.name);
            let shared = decoded.len().min(expected.len());
            assert!(shared > 0, "{where_}: nothing to compare");

            for (ours, theirs) in decoded.iter().zip(&expected).take(shared) {
                assert_eq!(
                    ours.address, theirs.address,
                    "{where_}: address differs at {:#x}",
                    theirs.address
                );
                // `llvm-objdump` decodes NEON, this decoder does not. Those
                // words come back opaque, and their width is already checked
                // by the address comparison above.
                if ours.kind == InsnKind::Unknown {
                    unknown_instructions += 1;
                    continue;
                }

                assert_eq!(
                    canonical_mnemonic(&ours.mnemonic),
                    canonical_mnemonic(&theirs.mnemonic),
                    "{where_}: mnemonic differs at {:#x}",
                    theirs.address
                );
                checked_instructions += 1;
            }
            checked_functions += 1;
        }
    }

    if checked_functions == 0 {
        // Reaching here means llvm-objdump is absent. Say so rather than
        // passing silently on a machine that checked nothing.
        eprintln!("llvm-objdump unavailable, skipped {skipped_objects} objects");
        return;
    }

    eprintln!(
        "checked {checked_instructions} instructions in {checked_functions} functions \
         ({unknown_instructions} opaque, mostly NEON)"
    );
}

/// The normalizer can hide decoder bugs, so test it directly.
#[test]
fn canonical_mnemonic_folds_known_spellings() {
    // Aliases both tools accept for the same encoding.
    for (ours, theirs) in
        [("cmps", "cmp"), ("movw", "mov"), ("movs", "lsrs"), ("adr", "add"), ("rrx", "mov")]
    {
        assert_eq!(
            canonical_mnemonic(ours),
            canonical_mnemonic(theirs),
            "{ours} and {theirs} are the same instruction"
        );
    }
}

#[test]
fn canonical_mnemonic_strips_condition_codes() {
    assert_eq!(canonical_mnemonic("movlo"), "mov");
    assert_eq!(canonical_mnemonic("bxeq"), "bx");
    assert_eq!(canonical_mnemonic("movwlt"), "mov");
}

/// A mnemonic that merely ends in condition letters must survive intact.
#[test]
fn canonical_mnemonic_keeps_lookalike_mnemonics() {
    for mnemonic in ["b", "bl", "ble", "bls", "mov", "cmp", "mul", "push", "pop"] {
        assert_eq!(canonical_mnemonic(mnemonic), mnemonic, "{mnemonic} carries no condition");
    }
}

/// Different instructions must stay different, or the harness proves nothing.
#[test]
fn canonical_mnemonic_keeps_distinct_instructions_apart() {
    assert_ne!(canonical_mnemonic("add"), canonical_mnemonic("sub"));
    assert_ne!(canonical_mnemonic("ldr"), canonical_mnemonic("str"));
    assert_ne!(canonical_mnemonic("mov"), canonical_mnemonic("mul"));
    assert_ne!(canonical_mnemonic("push"), canonical_mnemonic("pop"));
}

#[test]
fn objdump_parser_reads_instruction_lines() {
    let sample = "\
t.o:\tfile format elf32-littlearm

Disassembly of section .text:

00000000 <add>:
       0: e0810000     \tadd\tr0, r1, r0
       4: e12fff1e     \tbx\tlr
";
    let parsed = parse_objdump(sample);
    assert_eq!(
        parsed,
        vec![
            ObjdumpInsn { address: 0, mnemonic: "add".to_string() },
            ObjdumpInsn { address: 4, mnemonic: "bx".to_string() },
        ]
    );
}
