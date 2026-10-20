//! The source files of a binary, guessed from where its functions sit and
//! from what joins them.
//!
//! A compiler emits the functions of one source file together, and they call
//! each other and point at the same texts. A run of functions in address
//! order that such edges hold together is thus one guessed file.
//!
//! See RESEARCH.md, entry 16.

use std::collections::HashMap;

use hereticus_callees::Callee;

use super::Prepared;
use super::score::MOST_HOLDERS_OF_AN_EDGE;

/// The most places in address order that an edge can span and still hold its
/// two ends in one file.
///
/// A call from one end of a kernel to the other says nothing of files.
/// Measured against the symbols over the OpenWrt kernels, with the pairs by
/// similarity alone judged, a span of 32 undid 267 wrong pairs and 31 right,
/// 64 undid 303 wrong and 24 right, and 128 undid 288 wrong and 12 right.
/// With every stage that [`Cascade::unpair_across_files`] judges, 128 undid
/// 374 wrong and 14 right, and 256 only 174 wrong: the files run together.
///
/// [`Cascade::unpair_across_files`]: super::cascade::Cascade::unpair_across_files
pub(super) const MOST_FILE_SPAN: usize = 128;

/// How many other pairs each guessed file of a pair must hold before
/// [`FileVotes::disagree`] can judge it.
///
/// Measured over the OpenWrt kernels, one vote undid 16 more wrong pairs
/// than two and 5 more right, at a span of 32; three undid 6 fewer wrong
/// than two, at 128.
pub(super) const FEWEST_FILE_VOTES: usize = 2;

/// The edges that hold two functions of `side` in one file: each call
/// between two of them, and each text that two of them point at, where few
/// functions do.
pub(super) fn file_edges(side: &[Prepared<'_>]) -> Vec<(usize, usize)> {
    let mut edges = Vec::new();
    for (caller, prepared) in side.iter().enumerate() {
        for callee in &prepared.calls {
            if let Callee::Function(callee) = *callee
                && callee != caller
                && callee < side.len()
            {
                edges.push((caller, callee));
            }
        }
    }
    let mut holders: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, prepared) in side.iter().enumerate() {
        for text in &prepared.texts {
            holders.entry(text).or_default().push(index);
        }
    }
    // A chain through the holders joins them all, as every pair would.
    for list in holders.values().filter(|list| list.len() <= MOST_HOLDERS_OF_AN_EDGE) {
        edges.extend(list.windows(2).map(|pair| (pair[0], pair[1])));
    }
    edges
}

/// The guessed file of each function, as a number that grows along the
/// address order.
///
/// `order` holds the functions by address, and `place` the place of each
/// function in `order`. A file ends at a place that no edge of `edges`
/// spans, where an edge spans at most [`MOST_FILE_SPAN`] places.
pub(super) fn source_files(
    order: &[usize],
    place: &[usize],
    edges: impl IntoIterator<Item = (usize, usize)>,
) -> Vec<usize> {
    // The farthest place that an edge joins to each place.
    let mut reach: Vec<usize> = (0..order.len()).collect();
    for (one, other) in edges {
        let (near, far) = {
            let (one, other) = (place[one], place[other]);
            (one.min(other), one.max(other))
        };
        if far - near <= MOST_FILE_SPAN {
            reach[near] = reach[near].max(far);
        }
    }
    let mut file_of = vec![0; place.len()];
    let mut file = 0;
    let mut open_until = 0;
    for (at, &function) in order.iter().enumerate() {
        if at > open_until {
            file += 1;
        }
        open_until = open_until.max(reach[at]);
        file_of[function] = file;
    }
    file_of
}

/// How many pairs join each guessed file of one binary to each of the other.
pub(super) struct FileVotes {
    /// The pairs of each two files.
    pairs: HashMap<(usize, usize), usize>,
    /// The pairs of each file of the first binary.
    left: HashMap<usize, usize>,
    /// The pairs of each file of the second binary.
    right: HashMap<usize, usize>,
}

impl FileVotes {
    /// Count the pairs, each given as its two files.
    pub(super) fn new(pairs: impl IntoIterator<Item = (usize, usize)>) -> Self {
        let mut votes = Self { pairs: HashMap::new(), left: HashMap::new(), right: HashMap::new() };
        for (left, right) in pairs {
            *votes.pairs.entry((left, right)).or_default() += 1;
            *votes.left.entry(left).or_default() += 1;
            *votes.right.entry(right).or_default() += 1;
        }
        votes
    }

    /// Whether the other pairs of both files of a pair, counted in
    /// [`Self::new`], go elsewhere, and are [`FEWEST_FILE_VOTES`] or more on
    /// each side.
    pub(super) fn disagree(&self, left: usize, right: usize) -> bool {
        let others = |count: Option<&usize>| count.map_or(0, |count| count.saturating_sub(1));
        others(self.pairs.get(&(left, right))) == 0
            && others(self.left.get(&left)) >= FEWEST_FILE_VOTES
            && others(self.right.get(&right)) >= FEWEST_FILE_VOTES
    }
}
