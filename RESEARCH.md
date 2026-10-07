# Research

Published work that can make `hereticus` match functions better and find the
important changes faster. Each entry gives the source, the idea, and where it
applies in `hereticus`. When code applies an idea, the doc comment of that
function names the source from this file.

Survey date: 2026-10-04, with entry 13 and more sources added on
2026-10-07. The entries are in order of value for the effort.
The results of each entry, as applied and measured, are in
[Results](#results).

## Techniques already in hereticus

What `hereticus` did before this survey, with the name each technique
has in other tools and papers. Each entry names the code that does it,
and that code names the entry back, as `RESEARCH.md, A1`; change both
together. `tests/research.rs` fails where one side names what the other
lacks. The tools: [BinDiff manual](https://www.zynamics.com/bindiff/manual/index.html), [Ghidra Version Tracking correlators](https://ghidradocs.com/11.1_PUBLIC/help/VersionTracking/help/topics/VersionTrackingPlugin/VT_Correlators.html), [Diaphora heuristics](https://github.com/joxeankoret/diaphora/blob/master/diaphora_heuristics.py), and Ghidra BSim
([explained by Quarkslab](https://blog.quarkslab.com/bsim-explained-once-and-for-all.html)).

The stages of the matcher run as a cascade, most reliable first, and a
stage only sees what the stages before it left free. BinDiff and Ghidra
Version Tracking work the same way; BinDiff calls the later rounds
"drilling down".

### A1. Identical bytes

Code: `Cascade::match_identical_code` in `matching.rs`.

Pair two functions whose machine code is byte for byte the same, where
each is the only one of its bytes. BinDiff: *hash matching*. Ghidra:
*Exact Function Bytes Match*. Diaphora: *Bytes hash*, *Function Hash*.

### A2. Identical normalized shape

Code: `Cascade::match_identical_shape` in `matching.rs`;
`normalize_body_in` in `norm.rs`; `AddressSpace` in `address.rs`.

Normalize each instruction to its operation and the kinds of its
operands, without registers, branch targets, addresses or constants, and
pair two functions whose normalized bodies are equal. Ghidra: *Exact
Function Instructions Match*, which masks the operands. Diaphora: *Same
cleaned assembly*. The papers call this instruction normalization; Asm2Vec
and SAFE do the same before they learn.

### A3. Names

Code: `Cascade::match_by_name` in `matching.rs`.

BinDiff: *name hash matching*. Ghidra: *Symbol Name Match*. Diaphora:
*Same name* and its *Perfect match, same name*.

### A4. Twins in address order

Code: `Cascade::match_twins_in_order` in `matching.rs`.

Several functions with one normalized body pair first with first, where
both sides hold as many. BinDiff: *address sequence*, which "matches
functions in order based on their entry point addresses". Diaphora: *Same
order and hash*. Ghidra finds such groups with *Duplicate Function
Instructions Match* but leaves the choice to the user. Entry 7 extends
this to functions that are not twins.

### A5. Stubs aligned in order

Code: `Cascade::align_stubs` in `matching.rs`.

The PLT stubs, which are all one code but for their slot, align as two
ordered lists, with the calls of matched callers as votes: a weighted
longest common subsequence. This joins BinDiff's *address sequence* with
its *call reference matching*.

### A6. Twins told apart by what they reach

Code: `Cascade::pair_leftover_twins`, `Cascade::repair_twins_by_callees`
and `group_by_shape_and_references` in `matching.rs`.

Functions of one shape pair where their constants, callees and texts
single one out. Diaphora: *Same constants*, *Same KOKA hash and
constants*, *Import names hash*.

### A7. Bag of normalized instructions

Code: `similarity_of_symbols`, `Cascade::match_by_similarity`,
`keep_best_candidates` and `CLOSE_SIMILARITY` in `matching.rs`.

The score of two functions is the Jaccard similarity of their normalized
instructions as multisets, so order does not count. The free pairs above
the threshold are taken best first, in two passes: the close pairs first,
whose callees then tell the rest apart. BinDiff's *prime signature
matching*, which multiplies one prime for each mnemonic, is the form of
this that pairs only on equal bags; Diaphora: *Mnemonics small-primes-
product*. Taking candidates best first is the greedy assignment of
Diaphora; entry 9 measured the optimal one, which did worse.

### A8. References as a tie-breaker

Code: `reference_agreement`, `REFERENCE_WEIGHT` and
`Cascade::reference_keys` in `matching.rs`.

What a function calls and the texts it points at rank its candidates.
BinDiff: *string references* and *call reference matching*. Diaphora:
*Import names hash*. Ghidra: *Combined Function and Data Reference Match*.

### A9. Data-flow features

Code: `flow_features` in `il.rs`; `FLOW_RESCUE` in `matching.rs`.

Each value hashes with the operation that defines it and the values that
operation reads, for two rounds, and a pair whose code scores under the
threshold still pairs where these features agree. This is the feature
vector of Ghidra BSim, over the IL of A15 in place of p-code, and it is
a Weisfeiler-Lehman hash of the data-flow graph (entry 11).

### A10. Callers vote

Code: `Cascade::pair_by_callers` and `Cascade::uncross_by_callees` in
`matching.rs`.

The calls of a matched pair whose code agrees line up one for one, and
each votes that its two callees are one function: weak pairs swap or move
where the votes say so. BinDiff: *call graph expansion* and *call sequence
matching*. Ghidra: *Implied Match*, which proposes the callees of an
accepted pair. QBinDiff and entry 2 make the same evidence a term of one
objective.

### A11. A call or a text that changed

Code: `Cascade::compare_callees`, `Cascade::compare_texts` and
`differ_only_by_build_path` in `matching.rs`; `callees_in` in `callee.rs`.

Normalizing hides a call target, so a call to another function, the most
common shape of a fix (`strcpy` to `strlcpy`), is found by resolving each
callee through the PLT, the GOT, Mach-O stubs or relocations, and
comparing the callees once the pairs are known. Texts compare the same
way, without the random build directory a build path holds. Diaphora
compares callees as *Import names hash*; the patch-presence papers of
entry 4 compare the arguments of calls.

### A12. Kinds of change

Code: `classify_change`, `Changed`, `EditKind` and `count_edits` in
`matching.rs`.

A pair is unchanged, reordered, changed in data, changed in a value,
changed where the decoder cannot read, or changed in its instructions,
and each edit is a branch, a call, a jump, a memory access or other work.
BinDiff tells structural changes from instruction changes in its
similarity and confidence; this splits them further, as a reader triages.

### A13. Instruction diff

Code: `count_edits`, `longest_common_subsequence`, `instruction_diff` and
`coalesce_changed_constants` in `matching.rs`.

The two bodies align as a longest common subsequence, the diff of Hunt
and McIlroy, and a removal next to an addition of the same shape folds
into one changed line. Entry 3 aligns a body too large for the table.

### A14. Near misses

Code: `Cascade::near_misses`, `NearMiss` in `matching.rs`.

Each function left unpaired names its closest candidate and the score.
Ghidra Version Tracking lists every candidate with its score in the same
way; BinDiff lists unmatched functions without one.

### A15. Lifting to an IL, and guards

Code: `Lifted`, `Lifted::canonical` and `find_guards` in `il.rs`;
`view.rs`.

Each instruction lifts to what it reads, writes and tests, the same on
every architecture, and a compare and the branch on it read as one guard.
Ghidra: p-code. Binary Ninja: LLIL. BAP: BIL. angr: VEX. This IL is much
smaller than those: it has no full semantics.

### A16. Function recovery

Code: `recover_functions` and `recover_in_memory` in `scan.rs`;
`function_ranges` in `unwind.rs`.

In a stripped binary, functions come from the dynamic symbols, the
unwind index and `.eh_frame`, call targets, and code after a return.
Papers: Andriesse et al., *Compiler-Agnostic Function Detection in
Binaries* (Nucleus), EuroS&P 2017,
<https://www.vusec.net/projects/function-detection/>; Pang et al., *Towards
Optimal Use of Exception Handling Information for Function Detection*
(FETCH), DSN 2021, <https://arxiv.org/abs/2104.03168>.

### A17. Load address of a raw image

Code: `check_base` and `suggest_base` in `raw.rs`.

Words of data that hold absolute addresses, as vector tables and pointer
tables do, fall inside the image only at the right base. Tools: rbasefind
and basefind match pointers against the offsets of strings. Papers:
*Determining image base of firmware for ARM devices by matching literal
pools* (DBMLP), and Zhu, *Determining the base address of MIPS firmware
based on absolute address statistics and string reference matching*,
Computers & Security 88, 2020.

### A18. Unpacking firmware

Code: `unpack` in `unpack.rs`.

zImage, FIT, uImage, sysupgrade, lzma-loader and TP-Link containers. Tool:
binwalk, which finds such containers by their signatures.

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

Code: `Cascade::realign_by_context`, `Cascade::paired_callers` and
`sorted_shared` in `matching.rs`.

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

Code: the count of kept edges in `Cascade::realign_by_context`, in
`matching.rs`. The swap of entry 2 was measured and not kept.

## 3. Seed, chain, extend

Source: Li, *Minimap2: pairwise alignment for nucleotide sequences*,
Bioinformatics 2018. <https://arxiv.org/abs/1708.01492>

Idea: from genomics. Find short exact matches that are unique on both sides
(anchors). Keep the longest chain of anchors that is in order on both sides.
Align only the gaps between the anchors. Patience diff uses the same idea.

Applies to: `instruction_diff` and `longest_common_subsequence` in
`matching.rs`. Fewer bad alignments in long functions, and less time.

Code: `align`, `align_within`, `chain_of_unique_items`,
`longest_increasing_chain` and `steps_by_position` in `matching.rs`.

## 4. Constants as anchors for the fix

Source: Dong et al., *Fine-Grained 1-Day Vulnerability Detection in Binaries
via Patch Code Localization*, 2025 (PLocator).
<https://arxiv.org/abs/2501.17413>

Idea: scalar constants stay stable across compilers and optimization levels.
Use them as anchors in the control-flow graph to find the code of the patch.
88.2% true positive rate, 12.9% false positive rate, 0.14 s for each case.

Applies to: show *where* in a changed function the fix is.

Code: `CONSTANT_WEIGHT`, `constant_agreement`, `LARGEST_PLAIN_CONSTANT`
and `Prepared::shares_an_anchor_with` in `matching.rs`;
`constant_signature` in `norm.rs`.

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

Code: none; measured in `examples/research_bench.rs` and not kept.

## 6. Weight an edit by how rare it is

Source: *Sift or Get Off the PoC: Applying Information Retrieval to
Vulnerability Research with SiftRank*, 2025.
<https://arxiv.org/abs/2512.06155>. The weight is inverse document
frequency (IDF) from information retrieval.

Idea: an edit that occurs in 200 functions, as a moved global, is noise from
the build. An edit that occurs in one function is a signal.

Applies to: the sort order of the report, as a weight on each edit.

Code: `Match::rarity`, `Cascade::weigh_additions` and `sorted_only_in` in
`matching.rs`; `Sort::Rare` in `hereticus-cli/src/main.rs`.

## 7. Conserved order (synteny)

Source: comparative genomics. Genes that sit in the same order in two
genomes (synteny) tell orthologs from paralogs that sequence similarity
alone confuses; see OrthoRefine, which looks for orthologs in a window of
neighbors, and the survey of synteny tools in
<https://bmcbioinformatics.biomedcentral.com/articles/10.1186/s12859-024-05786-7>.

Prior art in binary diffing: BinDiff's *address sequence* pairs
functions in the order of their addresses, its *propagation (size==1)*
pairs the single unmatched child of matched basic blocks, and Diaphora's
*Same order and hash* and *Same compilation unit* use the order of the
functions. A4 already paired twins in order. New here: the gaps are those
of the longest chain of pairs in order, a weak pair off that chain is
undone, and the order counts only where enough of the binary pairs in it.

Idea: a linker places the
functions of one object in source order, and a new release keeps most of
that order. A function that sits between two pairs pairs with the one that
sits between their partners, even where its code changed too much to
score. A pair that breaks the order is more likely wrong.

Applies to: `Cascade::pair_by_layout`.

Code: `Cascade::pair_by_layout`, `LOWEST_LAYOUT_SIMILARITY`,
`LEAST_ANCHORED_SHARE`, `Confidence::SameLayout`, `Cascade::same_places`
and `NearMiss::in_place` in `matching.rs`.

## 8. Saturate repeated evidence (BM25)

Source: Robertson and Zaragoza, *The Probabilistic Relevance Framework:
BM25 and Beyond*, Foundations and Trends in Information Retrieval, 2009.

Idea: the first occurrences of a term are strong evidence, and each more
occurrence adds less. The term frequency saturates as
`tf · (k1 + 1) / (tf + k1)`.

Applies to: `Match::rarity`, so that forty copies of one moved instruction
do not outrank three rare ones.

Code: `saturated` and `SATURATION` in `matching.rs`.

## 9. Optimal assignment

Source: Kuhn, *The Hungarian Method for the Assignment Problem*, Naval
Research Logistics Quarterly, 1955.

Idea: choose the pairs whose scores sum highest, in place of best first,
which is a ½-approximation of that sum.

Applies to: the similarity stage, which takes candidates best first.

Code: none; measured and not kept.

## 10. Reciprocal best hits

Source: ortholog detection, where two genes are orthologs if each is the
other's best match. Known to fail on duplicated genes:
<https://arxiv.org/abs/0706.0117>.

Idea: pair two functions only where each is the other's best candidate.

Code: none; measured and not kept.

## 11. Weisfeiler-Lehman graph hashing

Source: Shervashidze et al., *Weisfeiler-Lehman Graph Kernels*, JMLR 12,
2011. <https://www.jmlr.org/papers/v12/shervashidze11a.html>

Idea: label each node with its own label and the multiset of its
neighbors' labels, and repeat. The labels hash the structure around each
node in linear time.

Code: none; `flow_features` in `il.rs` (A9) hashes the data flow this way.

## 12. Outliers among the changes

Source: anomaly detection; distance from the centroid of a population.

Idea, not found in the binary diffing work above: another compiler or
flag makes the same kind of edit in many functions, so their edits point
the same way as vectors of added instructions. A fix is an edit unlike
the others. Score each pair by one minus the cosine of its edit against
the sum of all edits.

Code: none; measured in `examples/research_bench.rs` and not kept.

## 13. Unique references

Sources: BinDiff's *string references* matcher, which pairs two functions
that point at the same string, and Diaphora's *Same rare constant*
heuristic ([Diaphora heuristics](https://github.com/joxeankoret/diaphora/blob/master/diaphora_heuristics.py)).
Both are much older than this survey; the new part here is where in the
cascade they run, and that they may break a weaker pair.

Idea: a message or a magic number comes from the source. Where one
function alone holds it in each binary, the two are one function, however
far their code moved apart. This is the same evidence as entry 4, but
used to choose a partner, not only to break a tie.

Applies to: functions that a fix or another build rewrote past the
similarity threshold, and pairs by similarity with a look-alike that lacks
the text.

Code: `Cascade::pair_by_unique_references`, `unique_reference_holders`,
`UniqueReference`, `LOWEST_UNIQUE_REFERENCE_SIMILARITY` and
`Confidence::SameReferences` in `matching.rs`.

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
- Ren et al., *RevDecode: Enhancing Binary Function Matching with
  Context-Aware Graph Representations and Relevance Decoding*, USENIX
  Security 2025.
  <https://www.usenix.org/system/files/usenixsecurity25-ren.pdf> It
  ranks the candidates of each function along the address order with a
  variant of Viterbi decoding, and adds an *uncertain* state to each
  layer, so a function with no candidate that its neighbors support
  stays unmatched. Entry 7 already pairs by order; the uncertain state
  is what entry 7 lacks where the counts of a gap differ. It matches
  against a corpus of libraries, not one release against the next.
- Rimsa et al., *Binary Diffing via Library Signatures*, CGO 2026.
  <https://homepages.dcc.ufmg.br/~fernando/publications/papers/CGO26_Rimsa.pdf>
  It compares whole programs by the sequence of library calls they make
  when they run. It needs to run the program, and it answers whether two
  programs are one, not which function is which.
- fnprint, <https://docs.rs/fnprint-core>: Rust, MIT. It runs each
  x86-64 function in a small emulator on random inputs and hashes what
  it does. Like BARRACUDA, it needs an emulator for each architecture.
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
- Bifrost, a Binary Ninja plugin in the BinDiff and Diaphora mold:
  <https://github.com/mutinylaboratories/bifrost>. Among its stages is
  BinDiff's MD-index, a hash of the control-flow graph by the
  topological order and the degrees of each edge's ends (the formula is
  in [QBinDiff](https://diffing.quarkslab.com/_modules/qbindiff/features/graph.html)).
  `hereticus` builds no control-flow graph yet, so it cannot use it.
- Diaphora MCP server and ghidriff, both updated in 2026, wrap the
  existing heuristics of Diaphora and of Ghidra Version Tracking.

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
| Backports, entries 1 to 6 | 26408 (+1148) | 993 (+37) | 5097 | 7110 |
| Backports, entry 7 too | 28904 (+3644) | 810 (−146) | 2781 | 4794 |
| Ubuntu, before | 264724 | 282 | 612 | 678 |
| Ubuntu, entries 1 to 6 | 264757 (+33) | 287 (+5) | 574 | 640 |
| Ubuntu, entry 7 too | 264862 (+138) | 248 (−34) | 228 | 294 |
| Backports, before entry 13 (commit `65c9eb6`) | 28902 | 809 | 2784 | 4797 |
| Backports, entry 13 too | 29347 (+445) | 753 (−56) | 2394 | 4407 |
| Ubuntu, before entry 13 (commit `65c9eb6`) | 264863 | 248 | 227 | 293 |
| Ubuntu, entry 13 too | 264864 (+1) | 251 (+3) | 223 | 289 |

The backports are where another build rewrites the code, which is where
context, constants and order help. An Ubuntu update keeps the compiler
and the flags, so nearly every function already paired. Entry 7, the
order of the functions, is the one change that pairs more right *and*
fewer wrong on both sets. Most of what it pairs in the Ubuntu set is code
no debug symbol covers, such as the PLT, so it counts as neither.

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
| 7. Conserved order | `Cascade::pair_by_layout` | +2496 right, −183 wrong | Kept |
| 8. BM25 saturation | `saturated` in `Match::rarity` | see below | Kept |
| 9. Optimal assignment | Hungarian method per group of candidates | −50 right, +78 wrong | Not kept |
| 10. Reciprocal best hits | only mutual best candidates pair | −81 right, −94 wrong | Not kept: a trade |
| 11. WL hashing of the CFG | — | not built | Not kept: `il::flow_features` already hashes the data flow this way |
| 12. Outliers among changes | cosine against the centroid | see below | see below |
| 13. Unique references | `Cascade::pair_by_unique_references` | +445 right, −56 wrong | Kept |

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
fewer pairs reported unchanged whose bytes differ, and a large function
shows its real edit, not a whole rewrite.

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

### 7: conserved order

Pairing the free functions of a gap in order, where both sides hold as
many, paired 1996 more right and 59 more wrong at a floor of 0.1. Two
safeguards came from cases the fixtures showed:

- Two unrelated objects of eight functions each paired three functions
  by place alone, with no pair around them. Now the order counts only
  where a quarter of the smaller binary pairs in order; this cost 4 right
  pairs on the backports.
- A gap whose counts differ means a function went or came. Aligning such
  a gap by its scores (Needleman-Wunsch) paired at 70% precision at
  best, and at no better when a pair had to share call edges too, so
  these gaps are left alone.

Then the order repairs: a weak pair off the chain of pairs in order is
undone, its functions pair by place where they can, and it comes back
where they do not. This paired 504 more right and 242 fewer wrong.
Leaving the undone pairs unpaired lost 927 right pairs to save 207 wrong.

The fixture tests that showed a function as gone and new, such as
`factorial` from `-O1` to `-O2`, or `check_header` and `dispatch` in the
MIPS firmware, now show it as changed, which the symbols confirm.

A gap whose counts differ still says where a function went, as a hint
and not a pair. Each function gone or new names the one in its place:
in a gap with equal counts the one opposite, and in a gap whose counts
differ the one the alignment by scores gives it. Of the 18 backport
comparisons where no changed pair holds the fix, 13 name a function of
the fix in its place; 888 of the hints are right and 564 wrong. Aligning
the gaps of equal counts by scores too named 38 fewer right and 5 fewer
wrong, and a floor of 0.1 to 0.3 on the scores lost more right hints
than wrong ones.

### 9 and 10: assignment

Choosing the pairs whose scores sum highest paired 50 fewer right and 78
more wrong than best first: the sum trades one sure pair for two weak
ones. Best first takes a pair only when it is the best that remains for
both of its functions, which is already a weak form of reciprocal best
hits. The strict form, the best of all candidates for both, drops pairs
that are right in about half the cases, so it trades recall for
precision and is not kept.

### 8 and 12: ranking, again

After entry 7 pairs more functions, more rows hold a change, so the ranks
below are not comparable with the table above. `rare` is entry 6 with the
BM25 saturation of entry 8.

| Order | Backports MRR | Top 1 | Ubuntu MRR | Top 1 | IOGPU | smbfs | ubusd | kernel |
|---|---|---|---|---|---|---|---|---|
| added | 0.546 | 63 | 0.798 | 115 | 19 | 9 | 5 | 1 |
| rare, entry 6 alone | 0.481 | 51 | 0.792 | 112 | 9 | 9 | 6 | 1 |
| rare, with BM25 | 0.510 | 57 | 0.795 | 113 | 6 | 8 | 6 | 1 |
| rare × (0.5 + outlier) | 0.503 | 55 | 0.778 | 108 | 2 | 6 | 6 | 1 |

BM25 makes `rare` better on every set, and it is kept. The outlier score
of entry 12 ranks the four published fixes best of all, but it is worse
on the 300 backports and Ubuntu updates, and four fixes are too few to
trust over them, so it is not kept. `added` stays the default: no order
beats it on the mean reciprocal rank of any large set.

### Eight published fixes

`--cves` now holds eight cases: the four above, CVE-2024-23265 in
AppleDiskImages2, and the `ubusd` fix of CVE-2025-62526 for A32 and for
MIPS16e in both byte orders. The rank of the fix:

| Order | DiskImages2 | IOGPU | smbfs | ubusd A64 | A32 | MIPS16e BE | LE | kernel |
|---|---|---|---|---|---|---|---|---|
| added | 1 | 19 | 9 | 5 | 4 | 7 | 7 | 1 |
| rare, with BM25 | 1 | 6 | 8 | 6 | 5 | 7 | 7 | 1 |
| rare × (0.5 + outlier) | 1 | 2 | 6 | 6 | 3 | 7 | 7 | 1 |
| rare × outlier | 1 | 2 | 7 | 4 | 2 | 4 | 4 | 1 |

The three `ubusd` cases follow the first: `rare × outlier` ranks the fix
best there too. But the four builds of `ubusd` are one fix, not four, so
the set holds five independent fixes, still too few to trust over the
backports and the Ubuntu updates.

### The OpenWrt kernels, against their symbols

OpenWrt publishes the `vmlinux` of each kernel it builds, with symbols
and without code, as `kernel-debug.tar.zst` beside the images.
`fixtures/openwrt_debug.py` fetches it for each kernel of
`tests/openwrt.rs`, and `examples/research_bench.rs --kernels` checks
their pairs against it. 98% to 99.7% of the functions the scan recovers
start where a symbol does, so the debug files are of the same builds.

| Kernels | Right | Wrong |
|---|---|---|
| 22.03.2 to 22.03.5, six boards | 133065 | 637 |
| 21.02.7 to 22.03.2, three boards | 50497 | 5859 |
| 22.03.5 to 23.05.5, three boards | 58962 | 3727 |

By the stage that paired them, over all twelve:

| Stage | Right | Wrong |
|---|---|---|
| identical code | 20894 | 130 |
| identical shape | 127869 | 677 |
| twins in order | 17823 | 707 |
| similar | 63262 | 5034 |
| callers, entry 1 | 7302 | 2219 |
| place, entry 7 | 5374 | 1456 |

A point release pairs under 1% wrong. Across a kernel upgrade, 6% to 12%
of the pairs are wrong, and the pairs by callers and by place are right
77% and 79% of the time, well below what the backports measured. A pair
that is wrong by the names may still be one function under a new name,
so these counts are an upper bound on the wrong pairs.

Across a kernel upgrade, the pairs by place that score under 0.4 are
mostly wrong: 643 right and 1038 wrong over the six upgrades, where the
backports chose the floor of 0.1. Many pairs wrong by the names are one
function renamed, as `mpage_readpages` to `mpage_readahead`, so the
names overstate the fault. Leaving such a pair out where its gap holds
more than one function each side cut 537 wrong pairs and 180 right from
the kernels, but 935 right and 8 wrong from the backports; more than
two, four or eight functions cut less of both. The length of the gap
does not tell the two kinds of pair apart, and the floor stays.

A wrong pair counts as proven where a name of one side lives on in the
other build, so that its true partner exists. 7927 of the 10223 wrong
pairs are proven: a rename explains about a fifth of them, not most.

Two more checks on the weak pairs did not help. Moving a pair by
similarity, callers or place to a free function that ranks better by
code, references and constants, once more pairs are known, cut 45 wrong
kernel pairs at a margin of 0.15, but cost the backports 332 right and
added 332 wrong. At 0.05 it was worse on both sets.

### 13: unique references

A text or a constant above `LARGEST_PLAIN_CONSTANT` that one function
alone holds on each side pairs the two, where their code scores 0.3 or
more. It breaks a weaker pair where that pair shares fewer such
references, but never a pair by identical code or shape. It runs after
the similarity stage and before the callers vote.

| Set | Right | Wrong |
|---|---|---|
| Backports | +304 | −40 |
| Backports, with named callees | +445 | −56 |
| OpenWrt kernels | +32 | −18 |
| Ubuntu updates | +1 | +3 |

On the backports, every fix now shows on a changed row: 18 comparisons
missed it before. The rank sum rose from 2799 to 3173 because those 18
now count; top 5 rose from 78 to 83 and the MRR from 0.546 to 0.566.

Breaking only a pair that scores no better than the new one cut the 3
wrong Ubuntu pairs, but on the backports it paired 75 fewer right and
kept 48 more wrong. A pair this stage makes is still weak: entry 7 undoes
it where it breaks the order. Kept from that, the stage paired 19 more
wrong kernel pairs, not 18 fewer. Texts alone, without constants, paired
255 more right and 66 fewer wrong on the backports, and a second shared
reference as a floor only 100 more right.

A call to a function the linker names, where one function alone makes it
on each side, counts as such a reference too, as Diaphora's *Import names
hash* does. On top of texts and constants it paired 141 more right and
16 fewer wrong on the backports, and changed nothing on the Ubuntu
updates; a raw kernel names no function. It moved one fix out of the top
5, and the MRR from 0.566 to 0.564.
