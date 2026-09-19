//! Measure the matching cascade against known answers.
//!
//! Ground truth comes from the fixtures. Both sides are built from C source
//! whose function names are known, so the right answer is known for every
//! pair. The tests below check the cascade against it, with names hidden, so
//! that the result reflects what `fndiff` can do on a stripped binary.

use std::path::{Path, PathBuf};

use fndiff::matching::{Changed, Confidence, Options, UseNames, diff_with};
use fndiff::obj::Binary;

fn object_path(level: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/build")
        .join(level)
        .join(format!("{name}.o"))
}

fn read(level: &str, name: &str) -> Option<Binary> {
    let data = std::fs::read(object_path(level, name)).ok()?;
    Binary::parse(&data).ok()
}

/// Match two fixtures without using symbol names.
///
/// Names stay in the file so the test can check the answer, but the cascade
/// does not see them. This is the stripped-binary case.
fn match_blind(before: &Binary, after: &Binary) -> Vec<(String, String, Confidence, Changed)> {
    let diff = diff_with(before, after, Options { use_names: UseNames::No, ..Default::default() });

    diff.matched
        .iter()
        .map(|pair| {
            (
                before.functions[pair.before].name.clone(),
                after.functions[pair.after].name.clone(),
                pair.confidence,
                pair.changed,
            )
        })
        .collect()
}

fn fixtures_present() -> bool {
    object_path("O2", "basic").exists()
}

/// Every function must find its counterpart without help from its name.
///
/// This is the property the project exists for. A firmware image has no
/// symbols, so a matcher that needs them is of no use.
#[test]
fn matches_every_function_without_names() {
    assert!(fixtures_present(), "run `just fixtures` first");
    let (Some(before), Some(after)) = (read("O2", "basic"), read("O2", "basic_v2")) else {
        panic!("fixtures are missing");
    };

    let pairs = match_blind(&before, &after);
    assert_eq!(pairs.len(), before.functions.len(), "every function must be matched");

    // `array_max` was renamed to `array_min` between the two versions, so the
    // names agree for every pair but that one.
    let renamed = [("array_max", "array_min")];
    for (left, right, confidence, _) in &pairs {
        let expected =
            renamed.iter().find(|(from, _)| from == left).map_or(left.as_str(), |(_, to)| *to);
        assert_eq!(
            right, expected,
            "{left} matched {right}, which is the wrong function ({confidence:?})"
        );
    }
}

/// The functions whose code changed must be reported, and no others.
///
/// `basic_v2.c` edits three functions: `mul_by_constant`, `classify` and
/// `array_max`. A fourth is reported, and correctly so. At `-O2` the compiler
/// inlines `mul_by_constant` into `call_chain`, so the edited constant appears
/// there too and `call_chain`'s own machine code differs.
///
/// That is the answer a reader wants. An edit reaches every function that
/// inlined it, and a report that hid this would understate what changed.
#[test]
fn reports_the_planned_edits_and_no_others() {
    assert!(fixtures_present(), "run `just fixtures` first");
    let (Some(before), Some(after)) = (read("O2", "basic"), read("O2", "basic_v2")) else {
        panic!("fixtures are missing");
    };

    let mut edited: Vec<String> = match_blind(&before, &after)
        .into_iter()
        .filter(|(.., changed)| *changed != Changed::No)
        .map(|(left, ..)| left)
        .collect();
    edited.sort();

    assert_eq!(
        edited,
        ["array_max", "call_chain", "classify", "mul_by_constant"],
        "the reported edits must be the three planned ones, plus call_chain, \
         which inlined the edited constant"
    );
}

/// An edit must be reported in every function that inlined it.
///
/// `call_chain` calls `mul_by_constant` in the source, but at `-O2` the
/// compiler inlines it, so the edited constant ends up in both. Finding only
/// the function that was edited in the source would miss where the change
/// actually landed in the binary.
#[test]
fn an_edit_is_reported_wherever_it_was_inlined() {
    assert!(fixtures_present(), "run `just fixtures` first");
    let (Some(before), Some(after)) = (read("O2", "basic"), read("O2", "basic_v2")) else {
        panic!("fixtures are missing");
    };

    let pairs = match_blind(&before, &after);
    for name in ["mul_by_constant", "call_chain"] {
        let found = pairs
            .iter()
            .find(|(left, ..)| left == name)
            .unwrap_or_else(|| panic!("{name} must be matched"));
        assert_eq!(found.3, Changed::InDetail, "{name} holds the edited constant");
    }
}

/// A rewritten function must be reported as rewritten, not as retouched.
///
/// `array_max` became `array_min`, which the compiler vectorizes. The change
/// sits inside NEON instructions the decoder cannot read, so it is only
/// visible if unreadable bytes are compared by content.
#[test]
fn detects_a_change_inside_unreadable_instructions() {
    assert!(fixtures_present(), "run `just fixtures` first");
    let (Some(before), Some(after)) = (read("O2", "basic"), read("O2", "basic_v2")) else {
        panic!("fixtures are missing");
    };

    let found = match_blind(&before, &after)
        .into_iter()
        .find(|(left, ..)| left == "array_max")
        .expect("array_max must be matched");

    assert_eq!(found.1, "array_min");
    assert_eq!(found.3, Changed::Yes, "a rewritten comparison is a real change");
}

/// An edited constant must be reported as a change in detail.
#[test]
fn reports_an_edited_constant_as_a_detail_change() {
    assert!(fixtures_present(), "run `just fixtures` first");
    let (Some(before), Some(after)) = (read("O2", "basic"), read("O2", "basic_v2")) else {
        panic!("fixtures are missing");
    };

    for name in ["mul_by_constant", "classify"] {
        let found = match_blind(&before, &after)
            .into_iter()
            .find(|(left, ..)| left == name)
            .unwrap_or_else(|| panic!("{name} must be matched"));

        assert_eq!(found.3, Changed::InDetail, "{name} changed only a constant");
    }
}

/// Comparing a binary with itself must report no changes at all.
///
/// A matcher that invents differences here would drown a real report in
/// noise.
#[test]
fn a_binary_does_not_differ_from_itself() {
    assert!(fixtures_present(), "run `just fixtures` first");

    for level in ["O1", "O2", "Os"] {
        let Some(binary) = read(level, "basic") else { continue };
        let diff =
            diff_with(&binary, &binary, Options { use_names: UseNames::No, ..Default::default() });

        assert_eq!(diff.matched.len(), binary.functions.len(), "{level}: every function matches");
        assert_eq!(diff.changed().count(), 0, "{level}: nothing changed");
        assert!(diff.removed.is_empty() && diff.added.is_empty(), "{level}: nothing appeared");

        for pair in &diff.matched {
            assert_eq!(pair.before, pair.after, "{level}: a function matched the wrong one");
        }
    }
}

/// Matching must survive a change of optimization level.
///
/// Not every function does: at `-O2` the compiler vectorizes `array_max` and
/// rewrites `factorial`, which genuinely changes the work. The test names the
/// functions that must survive rather than accepting whatever happens.
#[test]
fn matches_across_optimization_levels() {
    assert!(fixtures_present(), "run `just fixtures` first");
    let (Some(before), Some(after)) = (read("O1", "basic"), read("O2", "basic")) else {
        panic!("fixtures are missing");
    };

    const MUST_MATCH: [&str; 6] =
        ["add", "mul_by_constant", "sum_to", "classify", "switch_dense", "call_chain"];

    let pairs = match_blind(&before, &after);
    for name in MUST_MATCH {
        let found = pairs
            .iter()
            .find(|(left, ..)| left == name)
            .unwrap_or_else(|| panic!("{name} must match across optimization levels"));
        assert_eq!(found.1, name, "{name} matched the wrong function");
    }
}

/// A function that is only in one side must be reported as such.
#[test]
fn reports_functions_that_have_no_counterpart() {
    assert!(fixtures_present(), "run `just fixtures` first");
    let (Some(full), Some(other)) = (read("O2", "basic"), read("O2", "basic")) else {
        panic!("fixtures are missing");
    };

    // Drop a function from one side, so it has nothing to match.
    let mut trimmed = other;
    let removed = trimmed.functions.remove(0);

    let diff =
        diff_with(&full, &trimmed, Options { use_names: UseNames::No, ..Default::default() });

    let missing: Vec<&str> =
        diff.removed.iter().map(|index| full.functions[*index].name.as_str()).collect();
    assert_eq!(missing, [removed.name.as_str()], "the dropped function must be reported");
    assert!(diff.added.is_empty(), "nothing was added");
}
