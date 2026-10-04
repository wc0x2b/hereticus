# Research

Published work that can make `hereticus` match functions better and find the
important changes faster. Each entry gives the source, the idea, and where it
applies in `hereticus`. When code applies an idea, the doc comment of that
function names the source from this file.

Survey date: 2026-10-04. The entries are in order of value for the effort.
The results of each entry, as applied and measured, are in
[Results](#results).

## 1. Match functions by their matched neighbors

Source: *Enhancing Binary Code Similarity Analysis for Software Updates: A
Contextual Diffing Framework*, ASIA CCS 2025.
<https://dl.acm.org/doi/10.1145/3708821.3736207>

Idea: match functions recursively through the call graph of each version.
After a sure pair, the callers and callees of that pair become candidates of
each other. This makes Asm2Vec and SAFE up to 38.66% more accurate across
versions.

Applies to: twins that no instruction separates (see `TODO.md`). Two
byte-identical functions get different callers, and the callers often pair
first. `Cascade::pair_by_callers` in `matching.rs` already does a part of
this.

## 2. Diff as network alignment

Source: Mengin and Rossi, *Binary Diffing as a Network Alignment Problem via
Belief Propagation*, ASE 2021 (QBinDiff).
<https://arxiv.org/abs/2112.15337>. Faster solver:
<https://arxiv.org/abs/2112.15336>.

Idea: score a full mapping on two terms together: the similarity of each pair
and the number of call edges that the mapping keeps. Solve it with max-product
belief propagation. Greedy matchers, as BinDiff and Diaphora, solve easy
cases well but fail when the two programs differ more.

Applies to: the last scoring stage of the cascade, where pairs are chosen
greedily by score.

## 3. Seed, chain, extend

Source: Li, *Minimap2: pairwise alignment for nucleotide sequences*,
Bioinformatics 2018. <https://arxiv.org/abs/1708.01492>

Idea: from genomics. Find short exact matches that are unique on both sides
(anchors). Keep the longest chain of anchors that is in order on both sides.
Align only the gaps between the anchors. Patience diff uses the same idea.

Applies to: `instruction_diff` and `longest_common_subsequence` in
`matching.rs`. Fewer bad alignments in long functions, and less time.

## 4. Constants as anchors for the fix

Source: Dong et al., *Fine-Grained 1-Day Vulnerability Detection in Binaries
via Patch Code Localization*, 2025 (PLocator).
<https://arxiv.org/abs/2501.17413>

Idea: scalar constants stay stable across compilers and optimization levels.
Use them as anchors in the control-flow graph to find the code of the patch.
88.2% true positive rate, 12.9% false positive rate, 0.14 s for each case.

Applies to: show *where* in a changed function the fix is.

## 5. Rank changes by security features

Sources: Wang et al., *GraphSPD: Graph-Based Security Patch Detection with
Enriched Code Semantics*, IEEE S&P 2023.
<https://par.nsf.gov/biblio/10426263>. *StriderSPD: Structure-Guided Joint
Representation Learning for Binary Security Patch Detection*, 2026.
<https://arxiv.org/abs/2601.05772>

Idea: a security fix has typical features: a new compare and a branch to an
error path, a new bounds check, or a change in the calls to memory, string or
lock functions. These features need no machine learning.

Applies to: the sort order of the report. A new guard is the strongest sign
of a fix (see "Lift more of what a guard can be" in `TODO.md`).

## 6. Weight an edit by how rare it is

Source: *Sift or Get Off the PoC: Applying Information Retrieval to
Vulnerability Research with SiftRank*, 2025.
<https://arxiv.org/abs/2512.06155>. The weight is inverse document
frequency (IDF) from information retrieval.

Idea: an edit that occurs in 200 functions, as a moved global, is noise from
the build. An edit that occurs in one function is a signal.

Applies to: the sort order of the report, as a weight on each edit.

## Lower fit

- Ye, Zhou and Zhang, *Enhancing Semantic-Aware Binary Diffing with
  High-Confidence Dynamic Instruction Alignment*, NDSS 2026 (BARRACUDA).
  <https://www.ndss-symposium.org/ndss-paper/enhancing-semantic-aware-binary-diffing-with-high-confidence-dynamic-instruction-alignment/>
  Forced execution finds 24% more instruction anchors at 92.1% precision.
  It needs an emulator.
- LLM ranking of changed functions against the text of an advisory:
  <https://bishopfox.com/blog/vulnerability-discovery-with-llm-powered-patch-diffing>,
  SA2Pat <https://link.springer.com/article/10.1007/s10664-026-10942-z>,
  <https://arxiv.org/abs/2509.23970>. This fits a tool that reads
  `--format json`, not `hereticus` itself.
- MinHash and LSH for a fast search of similar functions:
  <https://arxiv.org/abs/2112.05492>. Use it only if the scoring of all pairs
  becomes too slow.

## Other sources

- VERIBIN, NDSS 2025:
  <https://www.ndss-symposium.org/wp-content/uploads/2025-359-paper.pdf>
- N2NMatcher: <https://arxiv.org/abs/2608.10043>
- Cross-Inlining Binary Function Similarity Detection:
  <https://arxiv.org/abs/2401.05739>
- BinEGA, SANER 2025:
  <https://conf.researchr.org/details/saner-2025/saner-2025-papers/32/BinEGA-Enhancing-DNN-based-Binary-Code-Similarity-Detection-through-Efficient-Graph->
- RefactoringMiner AST diff: <https://arxiv.org/abs/2403.05939>
- Code LLMs for binary security patches: <https://arxiv.org/abs/2509.06052>

## Results

Measured with `cargo run --release --example research_bench -p hereticus`.
It reads three sets:

- **Backports**: zlib, Lua, tinyxml2 and smallvec, each built two ways
  (another level or another compiler) with one upstream fix in between,
  130 comparisons on 5 architectures. The pairs of the stripped builds
  are checked against the symbols, as `tests/cross_build.rs` does, and
  the rank is where the first function of the fix sits.
- **Published fixes** (`--cves`): the fixes of `real-life-reports/` whose
  binaries are cached in `~/.cache`.
- **Ubuntu security updates** (`--ubuntu`): every consecutive pair of
  security releases of 15 C libraries for Ubuntu 22.04, arm64 and armhf,
  fetched by `fixtures/ubuntu_cves.py`. The `-dbgsym` symbols are the
  answer for the pairs, and the patches the update added name the fix.

### Summary

The pairs of stripped builds, checked against the symbols, before the
work of this file (commit `feaee43`) and after:

| Set | Right | Wrong | Gone | New |
|---|---|---|---|---|
| Backports, before | 25260 | 956 | 6282 | 8295 |
| Backports, after | 26408 (+1148) | 993 (+37) | 5097 | 7110 |
| Ubuntu, before | 264724 | 282 | 612 | 678 |
| Ubuntu, after | 264757 (+33) | 287 (+5) | 574 | 640 |

The backports are where another build rewrites the code, which is where
context and constants help. An Ubuntu update keeps the compiler and the
flags, so nearly every function already paired; there, the new pairs are
in 11 of 26 library builds, and the 5 wrong ones in expat and gnutls.

The rank of the fix under `--sort added` (the default) and `--sort rare`,
lower is better:

| Set | Order | Rank sum | Top 1 | Top 5 | MRR |
|---|---|---|---|---|---|
| Backports, 130 | added | 2731 | 69 | 82 | 0.582 |
| Backports, 130 | rare | 1821 | 56 | 82 | 0.522 |
| Ubuntu, 170 with a fix found | added | 384 | 114 | 164 | 0.794 |
| Ubuntu, 170 with a fix found | rare | 328 | 113 | 165 | 0.793 |

| Published fix | Rows | added | rare |
|---|---|---|---|
| CVE-2025-24257, IOGPUFamily | 370 | 19 | 8 |
| CVE-2026-28825, smbfs | 458 | 9 | 9 |
| CVE-2025-62526, ubusd | 8 | 5 | 6 |
| CVE-2021-30883, kernel | 331 | 1 | 1 |

`rare` cuts the worst ranks (the Lua backport from row 100 to row 36,
libssh from row 66 to row 9, IOGPUFamily from row 19 to row 8) but moves
some fixes from row 1 to row 2, and one gnutls fix from row 17 to row 42.
On average it is no better, so `added` stays the default.

### By entry

Before any change, on the backports: 25260 right, 956 wrong, 6282 gone,
8295 new.

| Entry | Code | Backports, pairs | Result |
|---|---|---|---|
| 1. Matched neighbors | `Cascade::realign_by_context` | +957 right, +92 wrong | Kept |
| 2. Network alignment | swap two weak pairs for more kept edges | +1 right, −5 wrong | Not kept |
| 4. Constant anchors | `CONSTANT_WEIGHT`, `Prepared::shares_an_anchor_with` | +193 right, −54 wrong | Kept |
| 3. Seed, chain, extend | `align` | no change: no backport function is that large | Kept |
| 6. IDF of additions | `Match::rarity`, `--sort rare` | see below | Kept, not the default |
| 5. Security features | added branches, calls and returns | see below | Not kept |

### 1 and 2: context

572 wrong pairs had their true partner left free, and 358 of those
partners scored under 0.5 on code alone. The code cannot find them, but
their callers, callees and texts can. Pairing on 3 shared edges and a
code score of 0.3 or more gave the best balance: 2 edges paired 228 more
right but 139 more wrong.

Weighing the callers in the order of the similarity stage did nothing
(+2 right, +1 wrong), at any weight from 0.05 to 0.4. A swap of two weak
pairs for more kept edges, as one step of local search on the QBinDiff
objective, did nothing either: `pair_by_callers` already swaps. For the
wrong pairs left, the context of the wrong partner is often as large as
that of the true one, so no more search on this objective helps.

The release comparisons of `tests/versions.rs` paired 57 more right and
15 more wrong. The OpenWrt kernels, which have no symbols to check
against, pair 59 to 981 more functions each.

### 4: constants

`norm::constant_signature` had measured pairing on constants alone as
worse. As one part of the order of the similarity stage it helps: weight
0.1 paired 94 more right and 77 fewer wrong. One shared constant above
0xfff as one edge of context paired 99 more right and 23 more wrong.
Every shared constant as an edge paired more (+361) but at 67% precision.

### 3: alignment

A pair that fits the 16M-cell table aligns exactly as before, so nothing
changed on the backports. On the OpenWrt kernels, each leaves 1 to 13
fewer changed bytes unreported, and a large function shows its real
edit, not a whole rewrite.

### 5 and 6: ranking

Ranks of the fix, lower is better. "added" is the default order.

| Order | Backports, rank sum | Top 1 | Top 5 | MRR | IOGPU | smbfs | ubusd | kernel |
|---|---|---|---|---|---|---|---|---|
| added | 2731 | 69 | 82 | 0.582 | 19 | 9 | 5 | 1 |
| rare (added + IDF) | 1821 | 56 | 82 | 0.522 | 8 | 9 | 6 | 1 |
| IDF alone | 1459 | 52 | 80 | 0.488 | 3 | 32 | 8 | 1 |
| added + 2 × guards | 2370 | 60 | 82 | 0.533 | 18 | 7 | 5 | 1 |
| guards | 1926 | 31 | 59 | 0.341 | 19 | 3 | 6 | 1 |

The fixes of the backports, built at another level, are where `rare`
helps most: the Lua fix, a new guard of three instructions, rose from row
100 to row 36 at most. But eight large fixes fell from row 1 to row 2,
which is why the mean reciprocal rank is lower. The guard features of
entry 5 (added branches, calls and returns) helped the Lua fix and
smbfs, but put the large fixes far down, so they are not kept.
