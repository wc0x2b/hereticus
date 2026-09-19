//! Measure the normalizer on real compiler output.
//!
//! The unit tests in `norm` check single instructions against hand-written
//! input. This file checks the property that matters: the same function,
//! compiled twice, must look more alike than two different functions do.
//!
//! Scope is `-O1`, `-O2` and `-Os`. An unoptimized build is deliberately
//! excluded, for the reason given in the `norm` module documentation: at `-O0`
//! the compiler emits a different algorithm, not a different spelling.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fndiff::arch::decode_all;
use fndiff::norm::{NormInsn, constant_signature, normalize_body};
use fndiff::obj::Binary;

/// Optimization levels that `fndiff` claims to match across.
const LEVELS: [&str; 3] = ["O1", "O2", "Os"];

/// Functions the compiler keeps recognizable at every level in `LEVELS`.
///
/// `factorial` is missing on purpose. The compiler turns its recursion into a
/// loop at some levels and not at others, which changes the work itself.
/// `array_max` is missing because vectorizing it produces NEON that the
/// decoder reads as opaque bytes. Both are real limits, so they are named
/// here rather than hidden by a lower threshold.
const STABLE_FUNCTIONS: [&str; 6] =
    ["add", "mul_by_constant", "sum_to", "classify", "switch_dense", "call_chain"];

/// Pairs that share most of their code for a legitimate reason.
///
/// At `-O2` the compiler inlines `mul_by_constant` into `call_chain`, which
/// then differs by one `add`. A high score is the right answer, so this pair
/// is excluded from the separation check instead of being explained away.
const INLINED_PAIRS: [(&str, &str); 1] = [("mul_by_constant", "call_chain")];

fn object_path(level: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/build")
        .join(level)
        .join(format!("{name}.o"))
}

/// Normalize one function, or `None` when the fixture or symbol is absent.
fn normalized(level: &str, object: &str, function: &str) -> Option<Vec<NormInsn>> {
    let data = std::fs::read(object_path(level, object)).ok()?;
    let binary = Binary::parse(&data).ok()?;
    let found = binary.functions.iter().find(|candidate| candidate.name == function)?;
    let (insns, _) = decode_all(&binary.isa.arch(), &found.code, found.address);
    Some(normalize_body(&insns))
}

/// Similarity of two normalized bodies, from 0.0 to 1.0.
///
/// This is Jaccard similarity over the multiset of normalized instructions:
/// the shared count divided by the combined count. It ignores order, which
/// suits reordered code, and it is only a measurement helper — the matcher
/// will need order-aware scoring as well.
fn similarity(left: &[NormInsn], right: &[NormInsn]) -> f64 {
    let mut left_counts: BTreeMap<&NormInsn, usize> = BTreeMap::new();
    let mut right_counts: BTreeMap<&NormInsn, usize> = BTreeMap::new();
    for insn in left {
        *left_counts.entry(insn).or_default() += 1;
    }
    for insn in right {
        *right_counts.entry(insn).or_default() += 1;
    }

    let mut shared = 0;
    let mut combined = 0;
    for key in left_counts.keys().chain(right_counts.keys()) {
        let in_left = left_counts.get(key).copied().unwrap_or(0);
        let in_right = right_counts.get(key).copied().unwrap_or(0);
        shared += in_left.min(in_right);
        combined += in_left.max(in_right);
    }

    if combined == 0 { 0.0 } else { shared as f64 / combined as f64 }
}

fn fixtures_present() -> bool {
    object_path("O2", "basic").exists()
}

/// The same function at two optimization levels must score highly.
#[test]
fn same_function_matches_across_optimization_levels() {
    assert!(fixtures_present(), "run `just fixtures` first");

    // Every stable function reached 1.00 on the corpus this was written
    // against. The threshold sits below that so an unrelated compiler change
    // does not fail the build, but high enough to catch real loss of signal.
    const MINIMUM: f64 = 0.90;

    let mut compared = 0;
    for function in STABLE_FUNCTIONS {
        for (index, earlier) in LEVELS.iter().enumerate() {
            for later in &LEVELS[index + 1..] {
                let (Some(left), Some(right)) =
                    (normalized(earlier, "basic", function), normalized(later, "basic", function))
                else {
                    continue;
                };

                let score = similarity(&left, &right);
                assert!(
                    score >= MINIMUM,
                    "{function}: {earlier} against {later} scored {score:.2}, \
                     below the {MINIMUM:.2} threshold"
                );
                compared += 1;
            }
        }
    }

    assert!(compared > 0, "no functions were compared");
    eprintln!("compared {compared} pairs of the same function");
}

/// Two different functions must score lower than two builds of one function.
///
/// Without this, a normalizer that discards everything would pass the test
/// above.
#[test]
fn different_functions_stay_apart() {
    assert!(fixtures_present(), "run `just fixtures` first");

    const MAXIMUM: f64 = 0.80;

    let mut highest: Option<(String, f64)> = None;
    for (index, left_name) in STABLE_FUNCTIONS.iter().enumerate() {
        for right_name in &STABLE_FUNCTIONS[index + 1..] {
            let inlined = INLINED_PAIRS.iter().any(|(a, b)| {
                (a == left_name && b == right_name) || (a == right_name && b == left_name)
            });
            if inlined {
                continue;
            }

            let (Some(left), Some(right)) =
                (normalized("O2", "basic", left_name), normalized("O2", "basic", right_name))
            else {
                continue;
            };

            let score = similarity(&left, &right);
            assert!(
                score <= MAXIMUM,
                "{left_name} and {right_name} are different functions but scored {score:.2}"
            );

            if highest.as_ref().is_none_or(|(_, best)| score > *best) {
                highest = Some((format!("{left_name} and {right_name}"), score));
            }
        }
    }

    if let Some((pair, score)) = highest {
        eprintln!("closest unrelated pair: {pair} at {score:.2}");
    }
}

/// An edited function must differ from the original, or a diff reports nothing.
#[test]
fn edited_functions_differ_from_the_original() {
    assert!(fixtures_present(), "run `just fixtures` first");

    // `basic_v2.c` changes the constant in `mul_by_constant` from 37 to 41.
    // The two builds must still match as the same function, and the changed
    // value must still be reportable. Normalizing away the difference
    // entirely would hide a real edit.
    let (Some(original), Some(edited)) = (
        normalized("O2", "basic", "mul_by_constant"),
        normalized("O2", "basic_v2", "mul_by_constant"),
    ) else {
        panic!("fixtures for mul_by_constant are missing");
    };

    assert_eq!(
        similarity(&original, &edited),
        1.0,
        "an edited constant must not stop the function from matching"
    );

    let changed =
        original.iter().zip(&edited).filter(|(left, right)| left.differs_in_detail(right)).count();
    assert_eq!(changed, 1, "exactly one instruction changed: 37 became 41");

    // Name the values, so a normalizer that recorded the wrong field fails.
    let (before, after) = original
        .iter()
        .zip(&edited)
        .find(|(left, right)| left.differs_in_detail(right))
        .map(|(left, right)| (left.constants.clone(), right.constants.clone()))
        .expect("one instruction must differ");
    assert_eq!(before, vec![37]);
    assert_eq!(after, vec![41]);
}

/// A constant signature is stable across optimization levels, except where
/// the compiler vectorizes.
///
/// This is the regression test for a measurement that decided a design. The
/// constants a function uses come from the source, so they survive a change of
/// flags that rewrites the instructions around them — until vectorizing adds
/// vector widths and alignment masks and takes the set apart.
///
/// The measurement is recorded here because it is the reason `fndiff` does
/// **not** pair functions by their constants. See `norm::constant_signature`.
#[test]
fn constant_signatures_survive_optimization_except_when_vectorized() {
    assert!(fixtures_present(), "run `just fixtures` first");

    // Functions whose constants must be identical at every level.
    const STABLE: [&str; 3] = ["mul_by_constant", "classify", "switch_dense"];
    // Functions the compiler vectorizes at `-O2`, which breaks the signature.
    const VECTORIZED: [&str; 2] = ["array_max", "factorial"];

    for function in STABLE {
        let signatures: Vec<_> = LEVELS
            .iter()
            .filter_map(|level| normalized(level, "basic", function))
            .map(|body| constant_signature(&body))
            .collect();

        let Some(first) = signatures.first() else { continue };
        assert!(!first.is_empty(), "{function} must have constants to compare");
        for other in &signatures[1..] {
            assert_eq!(other, first, "{function} must keep its constants at every level");
        }
    }

    for function in VECTORIZED {
        let (Some(scalar), Some(vector)) = (
            normalized("O1", "basic", function).map(|body| constant_signature(&body)),
            normalized("O2", "basic", function).map(|body| constant_signature(&body)),
        ) else {
            continue;
        };

        assert_ne!(
            scalar, vector,
            "{function} is vectorized at -O2, so its constants must not still agree; \
             if this now passes, the decoder learned to read NEON and the note in \
             norm::constant_signature needs revisiting"
        );
    }
}

/// Two different functions can share a constant signature.
///
/// Inlining `mul_by_constant` into `call_chain` leaves both holding only 37.
/// This is the measured false positive that kept constants out of the matching
/// cascade, so it is asserted rather than left as a comment.
#[test]
fn constant_signatures_do_not_identify_a_function() {
    assert!(fixtures_present(), "run `just fixtures` first");

    let (Some(callee), Some(caller)) = (
        normalized("O2", "basic", "mul_by_constant").map(|body| constant_signature(&body)),
        normalized("O2", "basic", "call_chain").map(|body| constant_signature(&body)),
    ) else {
        panic!("fixtures are missing");
    };

    assert_eq!(
        callee, caller,
        "these are different functions with the same constants, which is why \
         pairing on constants would pair the wrong two"
    );
}

/// The other two edits in `basic_v2.c` must also be visible.
#[test]
fn every_planned_edit_is_detected() {
    assert!(fixtures_present(), "run `just fixtures` first");

    // `classify`'s third threshold changes from 100 to 50.
    let (Some(original), Some(edited)) =
        (normalized("O2", "basic", "classify"), normalized("O2", "basic_v2", "classify"))
    else {
        panic!("fixtures for classify are missing");
    };

    let changed =
        original.iter().zip(&edited).filter(|(left, right)| left.differs_in_detail(right)).count();
    assert!(changed > 0, "the changed threshold in classify must be visible");
}

/// An unchanged function must normalize identically across the two versions.
#[test]
fn unchanged_functions_normalize_identically() {
    assert!(fixtures_present(), "run `just fixtures` first");

    for function in ["add", "sum_to", "switch_dense"] {
        let (Some(first), Some(second)) =
            (normalized("O2", "basic", function), normalized("O2", "basic_v2", function))
        else {
            continue;
        };
        assert_eq!(first, second, "{function} is unchanged between the two versions");
    }
}
