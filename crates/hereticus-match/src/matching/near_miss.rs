//! The closest candidate of each function that stayed unmatched.

use std::collections::HashMap;

use rayon::prelude::*;

use super::cascade::Cascade;
use super::score::similarity_of_symbols;
use super::{NearMiss, Prepared, Progress};

impl Cascade<'_> {
    /// Find the closest candidate for each function that stayed unmatched.
    ///
    /// This compares only the functions no stage could place, against only the
    /// functions still free to take. Both sets are small by the time the
    /// cascade is done, so the cost is a fraction of the matching pass that
    /// preceded it.
    ///
    /// The direction is a parameter, so one body serves both removed against
    /// added and added against removed. Each `NearMiss` reads its `unmatched`
    /// index in `theirs` and its `best` index in `others`.
    ///
    /// See RESEARCH.md, A14.
    pub(super) fn near_misses(
        &self,
        unmatched: &[usize],
        theirs: &[Prepared<'_>],
        others: &[usize],
        others_side: &[Prepared<'_>],
        places: &HashMap<usize, usize>,
        progress: &dyn Progress,
    ) -> Vec<NearMiss> {
        // Read-only, like the scoring stage, and the same shape of work. The
        // output keeps the order of `unmatched`, which `Diff` documents.
        unmatched
            .par_iter()
            .map(|one| {
                progress.advance(1);
                let best = others
                    .iter()
                    .map(|other| {
                        (
                            similarity_of_symbols(
                                &theirs[*one].symbols,
                                &others_side[*other].symbols,
                            ),
                            *other,
                        )
                    })
                    .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(core::cmp::Ordering::Equal));

                let in_place = places.get(one).copied();
                match best {
                    Some((score, other)) => {
                        NearMiss { unmatched: *one, best: Some(other), score, in_place }
                    }
                    None => NearMiss { unmatched: *one, best: None, score: 0.0, in_place },
                }
            })
            .collect()
    }
}
