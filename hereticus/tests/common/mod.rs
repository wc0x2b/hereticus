//! Helpers shared by the integration tests.

use std::fmt::Write as _;

use hereticus::matching::Diff;
use hereticus::obj::Binary;

/// Write a report as plain text, one line per function, for a snapshot.
///
/// Names are left out, because a raw image has none. The object comparison is
/// rendered the same way, which is what lets the two be compared as text.
pub fn render(diff: &Diff, before: &Binary, after: &Binary) -> String {
    let mut pairs: Vec<_> = diff.matched.iter().collect();
    pairs.sort_by_key(|pair| before.functions[pair.before].address);

    let mut out = String::new();
    for pair in pairs {
        writeln!(
            out,
            "{:#07x} -> {:#07x} {:?} score={:.3} edits={:?} kinds={:?} confidence={:?}",
            before.functions[pair.before].address,
            after.functions[pair.after].address,
            pair.changed,
            pair.score,
            pair.edits,
            pair.kinds,
            pair.confidence,
        )
        .unwrap();
    }
    for &index in &diff.removed {
        writeln!(out, "gone {:#07x}", before.functions[index].address).unwrap();
    }
    for &index in &diff.added {
        writeln!(out, "new  {:#07x}", after.functions[index].address).unwrap();
    }
    out
}
