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

Code: `Cascade::match_identical_code` in `matching/cascade.rs`.

Pair two functions whose machine code is byte for byte the same, where
each is the only one of its bytes. BinDiff: *hash matching*. Ghidra:
*Exact Function Bytes Match*. Diaphora: *Bytes hash*, *Function Hash*.

### A2. Identical normalized shape

Code: `Cascade::match_identical_shape` in `matching/cascade.rs`;
`normalize_body_in` in `norm.rs`; `AddressSpace` in `crates/hereticus-memory`.

Normalize each instruction to its operation and the kinds of its
operands, without registers, branch targets, addresses or constants, and
pair two functions whose normalized bodies are equal. Ghidra: *Exact
Function Instructions Match*, which masks the operands. Diaphora: *Same
cleaned assembly*. The papers call this instruction normalization; Asm2Vec
and SAFE do the same before they learn.

### A3. Names

Code: `Cascade::match_by_name` in `matching/cascade.rs`.

BinDiff: *name hash matching*. Ghidra: *Symbol Name Match*. Diaphora:
*Same name* and its *Perfect match, same name*.

### A4. Twins in address order

Code: `Cascade::match_twins_in_order` in `matching/cascade.rs`.

Several functions with one normalized body pair first with first, where
both sides hold as many. BinDiff: *address sequence*, which "matches
functions in order based on their entry point addresses". Diaphora: *Same
order and hash*. Ghidra finds such groups with *Duplicate Function
Instructions Match* but leaves the choice to the user. Entry 7 extends
this to functions that are not twins.

### A5. Stubs aligned in order

Code: `Cascade::align_stubs` in `matching/cascade.rs`.

The PLT stubs, which are all one code but for their slot, align as two
ordered lists, with the calls of matched callers as votes: a weighted
longest common subsequence. This joins BinDiff's *address sequence* with
its *call reference matching*.

### A6. Twins told apart by what they reach

Code: `Cascade::pair_leftover_twins` and `Cascade::repair_twins_by_callees`
in `matching/cascade.rs`; `group_by_shape_and_references` in
`matching/score.rs`.

Functions of one shape pair where their constants, callees and texts
single one out. Diaphora: *Same constants*, *Same KOKA hash and
constants*, *Import names hash*.

### A7. Bag of normalized instructions

Code: `Cascade::match_by_similarity` in `matching/cascade.rs`;
`similarity_of_symbols`, `keep_best_candidates` and `CLOSE_SIMILARITY` in
`matching/score.rs`.

The score of two functions is the Jaccard similarity of their normalized
instructions as multisets, so order does not count. The free pairs above
the threshold are taken best first, in two passes: the close pairs first,
whose callees then tell the rest apart. BinDiff's *prime signature
matching*, which multiplies one prime for each mnemonic, is the form of
this that pairs only on equal bags; Diaphora: *Mnemonics small-primes-
product*. Taking candidates best first is the greedy assignment of
Diaphora; entry 9 measured the optimal one, which did worse.

### A8. References as a tie-breaker

Code: `reference_agreement` and `REFERENCE_WEIGHT` in `matching/score.rs`;
`Cascade::reference_keys` in `matching/cascade.rs`.

What a function calls and the texts it points at rank its candidates.
BinDiff: *string references* and *call reference matching*. Diaphora:
*Import names hash*. Ghidra: *Combined Function and Data Reference Match*.

### A9. Data-flow features

Code: `flow_features` in `crates/hereticus-il`; `FLOW_RESCUE` in
`matching/score.rs`.

Each value hashes with the operation that defines it and the values that
operation reads, for two rounds, and a pair whose code scores under the
threshold still pairs where these features agree. This is the feature
vector of Ghidra BSim, over the IL of A15 in place of p-code, and it is
a Weisfeiler-Lehman hash of the data-flow graph (entry 11).

### A10. Callers vote

Code: `Cascade::pair_by_callers` and `Cascade::uncross_by_callees` in
`matching/cascade.rs`.

The calls of a matched pair whose code agrees line up one for one, and
each votes that its two callees are one function: weak pairs swap or move
where the votes say so. BinDiff: *call graph expansion* and *call sequence
matching*. Ghidra: *Implied Match*, which proposes the callees of an
accepted pair. QBinDiff and entry 2 make the same evidence a term of one
objective.

### A11. A call or a text that changed

Code: `Cascade::compare_callees` and `Cascade::compare_texts` in
`matching/cascade.rs`; `differ_only_by_build_path` in `matching/score.rs`;
`callees_in` in `crates/hereticus-callees`.

Normalizing hides a call target, so a call to another function, the most
common shape of a fix (`strcpy` to `strlcpy`), is found by resolving each
callee through the PLT, the GOT, Mach-O stubs or relocations, and
comparing the callees once the pairs are known. Texts compare the same
way, without the random build directory a build path holds. Diaphora
compares callees as *Import names hash*; the patch-presence papers of
entry 4 compare the arguments of calls.

### A12. Kinds of change

Code: `classify_change` and `count_edits` in `matching/change.rs`;
`Changed` and `EditKind` in `matching.rs`.

A pair is unchanged, reordered, changed in data, changed in a value,
changed where the decoder cannot read, or changed in its instructions,
and each edit is a branch, a call, a jump, a memory access or other work.
BinDiff tells structural changes from instruction changes in its
similarity and confidence; this splits them further, as a reader triages.

### A13. Instruction diff

Code: `count_edits` and `difference` in `matching/change.rs`;
`longest_common_subsequence` and `lines_from_alignment` in
`matching/align.rs`; `instruction_diff` in `matching/lines.rs`.

The two bodies align as a longest common subsequence, the diff of Hunt
and McIlroy, and a removal next to an addition of the same shape folds
into one changed line. Entry 3 aligns a body too large for the table.

### A14. Near misses

Code: `Cascade::near_misses` in `matching/near_miss.rs`; `NearMiss` in
`matching.rs`.

Each function left unpaired names its closest candidate and the score.
Ghidra Version Tracking lists every candidate with its score in the same
way; BinDiff lists unmatched functions without one.

### A15. Lifting to an IL, and guards

Code: `Lifted`, `Lifted::canonical` and `find_guards` in `crates/hereticus-il`;
`crates/hereticus-view`.

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

Code: `unpack` in `crates/hereticus-unpack`.

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
first. `Cascade::pair_by_callers` in `matching/cascade.rs` already does a
part of this.

Code: `Cascade::realign_by_context` and `Cascade::paired_callers` in
`matching/cascade.rs`; `sorted_shared`, `common_keys` and
`MOST_HOLDERS_OF_AN_EDGE` in `matching/score.rs`.

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
`matching/cascade.rs`. The swap of entry 2 was measured and not kept.

## 3. Seed, chain, extend

Source: Li, *Minimap2: pairwise alignment for nucleotide sequences*,
Bioinformatics 2018. <https://arxiv.org/abs/1708.01492>

Idea: from genomics. Find short exact matches that are unique on both sides
(anchors). Keep the longest chain of anchors that is in order on both sides.
Align only the gaps between the anchors. Patience diff uses the same idea.

Applies to: `instruction_diff` in `matching/lines.rs` and
`longest_common_subsequence` in `matching/align.rs`. Fewer bad alignments in long functions, and less time.

Code: `align`, `align_within`, `chain_of_unique_items`,
`longest_increasing_chain` and `steps_by_position` in `matching/align.rs`.

## 4. Constants as anchors for the fix

Source: Dong et al., *Fine-Grained 1-Day Vulnerability Detection in Binaries
via Patch Code Localization*, 2025 (PLocator).
<https://arxiv.org/abs/2501.17413>

Idea: scalar constants stay stable across compilers and optimization levels.
Use them as anchors in the control-flow graph to find the code of the patch.
88.2% true positive rate, 12.9% false positive rate, 0.14 s for each case.

Applies to: show *where* in a changed function the fix is.

Code: `CONSTANT_WEIGHT`, `constant_agreement` and `LARGEST_PLAIN_CONSTANT`
in `matching/score.rs`; `Prepared::shares_an_anchor_with` in `matching.rs`;
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

Code: `Match::rarity` in `matching.rs`; `Cascade::weigh_additions` in
`matching/cascade.rs`; `sorted_only_in` in `matching/score.rs`; `Sort::Rare` in `hereticus-cli/src/main.rs`.

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

Code: `Cascade::pair_by_layout` and `Cascade::same_places` in
`matching/cascade.rs`; `LOWEST_LAYOUT_SIMILARITY` and `LEAST_ANCHORED_SHARE`
in `matching/score.rs`; `Confidence::SameLayout` and `NearMiss::in_place`
in `matching.rs`.

## 8. Saturate repeated evidence (BM25)

Source: Robertson and Zaragoza, *The Probabilistic Relevance Framework:
BM25 and Beyond*, Foundations and Trends in Information Retrieval, 2009.

Idea: the first occurrences of a term are strong evidence, and each more
occurrence adds less. The term frequency saturates as
`tf · (k1 + 1) / (tf + k1)`.

Applies to: `Match::rarity`, so that forty copies of one moved instruction
do not outrank three rare ones.

Code: `saturated` and `SATURATION` in `matching/score.rs`.

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

Code: none; `flow_features` in `crates/hereticus-il` (A9) hashes the data flow this way.

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
that point at the same string, and its *call graph propagation*, which
pairs the one unmatched caller left on each side; Diaphora's *Same rare
constant* and *Import names hash* heuristics ([Diaphora heuristics](https://github.com/joxeankoret/diaphora/blob/master/diaphora_heuristics.py)).
Both are much older than this survey; the new part here is where in the
cascade they run, and that they may break a weaker pair.

Idea: a message, a magic number or a call comes from the source. Where
one function alone holds it in each binary, the two are one function,
however far their code moved apart. A call counts where it reaches an
import or a function already paired, and so does the whole set of paired
functions a function calls: many functions call `kmalloc`, but few call
exactly the same three functions. This is the same evidence as entry 4, but
used to choose a partner, not only to break a tie.

Applies to: functions that a fix or another build rewrote past the
similarity threshold, and pairs by similarity with a look-alike that lacks
the text.

Code: `Cascade::pair_by_unique_references` and
`Cascade::pair_by_unique_references_until_settled` in `matching/cascade.rs`;
`unique_reference_holders`, `paired_callee_set`, `UniqueReference`,
`LOWEST_UNIQUE_REFERENCE_SIMILARITY`, `MOST_UNIQUE_REFERENCE_ROUNDS` and
`FEWEST_CALLEES_IN_A_SET` in `matching/score.rs`;
`Confidence::SameReferences` in `matching.rs`.

## 14. Ratio test

Source: Lowe, *Distinctive Image Features from Scale-Invariant
Keypoints*, IJCV 60(2), 2004, section 7.1. To match a point of one image
with one of another, SIFT accepts the nearest neighbour only where it is
clearly nearer than the second nearest; the ratio of the two distances
rejects most false matches and few right ones.

Idea: where a function has two candidates the code ranks alike, best
first picks one by index. Take neither, and leave the function to the
stages that look past its code: its place, its references and its
callers.

Applies to: the similarity stage. A kernel holds many small functions
alike in shape, as `return 2;` or a getter of one field, which paired
with each other at a score of 1.00.

Code: `Cascade::match_by_similarity` in `matching/cascade.rs`;
`RIVAL_MARGIN` in `matching/score.rs`.

## 15. Slots of a table of functions

Source: Pawlowski et al., *Marx: Uncovering Class Hierarchies in C++
Programs*, NDSS 2017, which finds the vtables of a binary as runs of
addresses of functions in its data. No paper found pairs functions by
their slot in such a table; this entry applies the order of a vtable
the way entry 7 applies the order of the code.

Idea: a C++ vtable lists the virtual functions of a class in the order
the source declares them, whatever the compiler, and a C table of
handlers keeps the order of its fields. Where a firm pair joins two
tables, the functions in the same slot of each are partners, even twins
that no instruction separates.

Applies to: twins that pair in address order (A4), and free functions
the code alone leaves unpaired.

Code: `Binary::function_tables` in `crates/hereticus-image`;
`Links::words` in `crates/hereticus-image`; `Cascade::pair_by_tables`
in `matching/tables.rs`.

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
| Backports, entry 13 too | 29449 (+547) | 674 (−135) | 2371 | 4384 |
| Ubuntu, before entry 13 (commit `65c9eb6`) | 264863 | 248 | 227 | 293 |
| Ubuntu, entry 13 too | 264861 (−2) | 254 (+6) | 223 | 289 |

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
| 13. Unique references | `Cascade::pair_by_unique_references` | +547 right, −135 wrong | Kept |
| 14. Ratio test | `RIVAL_MARGIN` in `Cascade::match_by_similarity` | −24 right, −159 wrong | Kept |
| 15. Slots of a table | `Cascade::pair_by_tables` | +275 right, −54 wrong | Kept |

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

Context also says where a pair is wrong. Across a kernel upgrade, a
function deleted pairs with a new one of similar code, and nothing around
the two agrees. Over the kernels, of the pairs by similarity or by place
where each side has two or more callers and callees that paired, and no
two of them are a pair, 26 were right and 482 wrong. Undoing those pairs
last, once all context has paired, cut the kernels from 1.64% wrong to
1.45%, and moved the backports by 1 right and 1 wrong. With one paired
neighbour each, it undid 276 right and 919 wrong on the kernels and
ranked the backport fixes lower; with three, it undid less of both.

A pair that scores under 0.4 has little but its place for it, and one
paired neighbour each is enough to undo it. Checked against the source
files in the DWARF, that undid 16 right and 103 wrong pairs over the
kernels, and 1 right and 7 wrong over the backports, with the fixes
ranked a little higher; tinyxml2 8 to 9, read as raw images, lost 8 right
pairs. Undoing pairs by references, by callers, by twin order or by
identical shape the same way moved fewer than 15 pairs. Moving a weak
pair to a free function that scores 0.25 more cost 79 right and 79 more
wrong on the backports, and more wrong on the kernels.

Code that stays in its source file stays between the same pairs, and a
function deleted and paired with a look-alike of another file does not.
A pair is out of place where its second side does not sit between the
partners of the pairs around its first side. Out of place, the pairs by
similarity with one paired neighbour each, and none that agree, were
right 53 times and wrong 266 over the kernels; in place, 86 and 15. One
neighbour each is now enough to undo a pair out of place: 57 right and
269 wrong pairs undone over the kernels, from 1.31% wrong to 1.20%, and 5
wrong over the backports. Out of place and with no paired neighbour,
447 pairs were right and 201 wrong, so place alone undoes nothing.

The pairs by callers out of place are wrong 20% of the time, and how much
of their context agrees tells which: where under 0.3 of their paired
callers and callees agree, 20 were right and 156 wrong. Undoing those
undid 17 right and 159 wrong over the kernels, to 1.14%, and 2 right and
11 wrong over the backports, with the fixes ranked a little higher. At
0.4 the backport fixes ranked lower. In place, no share told the two
apart, and the pairs by references out of place split too evenly to undo.

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

Across a kernel upgrade, the undoing also broke right pairs. Code moves to
another file or another place in its file, so its pair breaks the order;
undone, its function paired by place with what sat in its old slot. Of
the wrong pairs by place, 346 had left their true partner unpaired at a
higher score, most more than five functions away: `put_mtd_device` lost
its partner at 1.00 to `mtd_read` at 0.35. An undone pair that scores 0.8
or more, and 0.2 more than the pair by place, now comes back in its
place. This paired 401 more right and 160 fewer wrong over the kernels,
and 26 more right and 2 fewer wrong over the backports. Protecting every
undone pair that scores more paired 368 more right and 89 fewer wrong on
the kernels, but 70 fewer right and 96 more wrong on the backports,
where the undoing mostly fixes look-alikes.

Keeping only the pairs of a gap of equal counts that the alignment by
scores also makes, on top of that, saved 87 more wrong kernel pairs and
7 wrong backport pairs, but cost 53 right backport pairs.

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

### Sixteen published fixes

`--cves` now holds the `dropbear` fix of CVE-2025-14282 too, from
OpenWrt 24.10.4 to 24.10.5, for AArch64, A32 and MIPS32 in both byte
orders. The rank of the fix:

| Order | AArch64 | A32 | MIPS32 BE | MIPS32 LE |
|---|---|---|---|---|
| added | 2 | 1 | 2 | 2 |
| rare | 2 | 1 | 2 | 2 |
| rare × (0.5 + outlier) | 2 | 1 | 2 | 2 |
| rare × outlier | 6 | 1 | 5 | 4 |

The function of the fix scores 0.21 to 0.28 on its code, since the
compiler inlined the new `svr_switch_user` into it, and pairs by its
place (entry 7). The outlier orders rank it lower: its edit is large
and like the other large edits.

The `uhttpd` fix of CVE-2026-55614, from OpenWrt 24.10.7 to 24.10.8,
for AArch64, A32 and MIPS16e in both byte orders, the same way:

| Order | AArch64 | A32 | MIPS16e BE | MIPS16e LE |
|---|---|---|---|---|
| added | 5 | 3 | 5 | 5 |
| rare | 3 | 3 | 5 | 5 |
| rare × (0.5 + outlier) | 5 | 4 | 6 | 6 |
| rare × outlier | 5 | 5 | 5 | 7 |

The update holds 17 patches, and the larger ones rank above the fix
under `added`.

Over all sixteen cases of seven fixes, no order wins:

| Order | Rank sum | Top 1 | Top 5 | MRR |
|---|---|---|---|---|
| added | 78 | 3 | 12 | 0.396 |
| rare | 64 | 3 | 11 | 0.407 |
| rare × (0.5 + outlier) | 61 | 3 | 10 | 0.421 |
| rare × outlier | 63 | 3 | 13 | 0.391 |
| added × outlier | 66 | 3 | 13 | 0.383 |

The outlier score ranked the first eight cases best of all, but ranks
the eight OpenWrt cases added here worse than `added` does, so `added`
stays the default.

The OpenWrt cases cover A32, MIPS32 and MIPS16e; OpenWrt builds no user
space as Thumb-2. Ubuntu builds armhf as Thumb-2, so the 109 armhf
updates of `tests/truth_ubuntu.rs` are the published fixes on Thumb-2.

### Published fixes, again

`--cves` now holds the `odhcpd` fix of CVE-2026-53921 too, from OpenWrt
24.10.7 to 24.10.8, for AArch64, A32 and MIPS16e in both byte orders:

| Order | AArch64 | A32 | MIPS16e BE | MIPS16e LE |
|---|---|---|---|---|
| added | 5 | 1 | 1 | 1 |
| rare | 5 | 1 | 1 | 1 |
| rare × (0.5 + outlier) | 4 | 1 | 1 | 1 |
| rare × outlier | 6 | 2 | 1 | 1 |
| added × outlier | 5 | 3 | 1 | 1 |

Over all twenty cases of eight fixes:

| Order | Rank sum | Top 1 | Top 5 | MRR |
|---|---|---|---|---|
| added | 84 | 6 | 16 | 0.479 |
| rare | 70 | 6 | 15 | 0.488 |
| rare × (0.5 + outlier) | 62 | 6 | 18 | 0.508 |
| rare × outlier | 69 | 5 | 16 | 0.458 |
| added × outlier | 72 | 5 | 17 | 0.444 |

`rare × (0.5 + outlier)` leads by a little here, but ranks the
backports and the Ubuntu updates lower (see "8 and 12: ranking,
again"), so `added` stays the default.

With the `scp` fix of CVE-2026-35385 in `dropbear`, OpenWrt 24.10.7 to
24.10.8, on the same four builds, the fix ranks 1, 1, 1 and 2 under
`added`. Over all twenty-four cases of nine fixes:

| Order | Rank sum | Top 1 | Top 5 | MRR |
|---|---|---|---|---|
| added | 89 | 9 | 20 | 0.545 |
| rare | 74 | 10 | 19 | 0.573 |
| rare × (0.5 + outlier) | 70 | 8 | 22 | 0.535 |
| rare × outlier | 88 | 5 | 19 | 0.420 |
| added × outlier | 88 | 5 | 20 | 0.418 |

`rare` now leads on the published fixes, by a little, as it did on the
Ubuntu updates at first; it also ranks the backports lower (top 1 from
64 to 60), so `added` stays.

The `ltq-ptm` fix of CVE-2025-62525, from OpenWrt 24.10.3 to 24.10.4, is
in a kernel module for MIPS32 big endian, and ranks 1 of 1 under every
order. Over all twenty-five cases of ten fixes, `added` has a rank sum
of 90, 10 first, 21 in the top 5 and an MRR of 0.563, and `rare` 75, 11,
20 and 0.590.

OpenWrt's `strip-kmod.sh` keeps only the symbols a module's relocations
need, and renames the local ones to numbers. Read by its symbols, the
module was 8 functions over 1.5 KiB of 12 KiB of code, named `_0` to
`_8` in each build, which paired by name with whatever had the same
number. `Binary::parse_module` now reads an unlinked object whose symbols
cover less than half its code as stripped: each code section after the
one before, the global functions as starts, and the starts that the
relocations of its data point at, but for a run of four or more words in
a row that point within 2 KiB, which is the table of a `switch`. The
`ioctl` handler, which only a `net_device_ops` table points at, was
merged into the probe function before that; with the tables of each
`switch` as starts, it split at each case.

A module for ARM keeps more symbols: `tun.ko` of OpenWrt 24.10.3 for
ARMv7 has 49, over 54% of its code, so it took the path of the symbols,
and each function paired by its number, `_41` with `_41`, whatever it
was. A module with a local renamed to a number now takes the path of a
module too, where a symbol bounds its function but only a name that is
no number names it. `tun.ko` then reads as 70 functions, and `tun`,
`nf_conntrack` and `wireguard` read as unchanged from 24.10.3 to
24.10.4 but for constants.

This case showed two kinds of noise in the report, both fixed, with no
pair moved on the backports or the Ubuntu updates:

- Two PLT stubs of one import read as unchanged. An import added moves
  every slot of the global offset table, and each A32 stub loads its slot
  at an offset from itself: 18 stubs of `odhcpd` read as changed.
- On MIPS, the lazy binding stubs (`hereticus_recovery::mips_stubs`) are
  read as MIPS32 and named for the symbol each resolves, where `sstrip`
  left no section to find them. In MIPS16e code they decoded as MIPS16e
  and ran together, and a new import moved them all: `odhcpd` showed 14
  gone and 18 new. The reports of `ubusd` on MIPS16e lost 15 rows, and
  the fix rose from row 7 to row 6; those of `dropbear` on MIPS32 lost
  24 rows each.

Two fixes of OpenWrt 24.10.6, from the audit of Trail of Bits, on the
same four builds of 24.10.5 and 24.10.6:

- CVE-2026-30873, `jsonfilter`: the lexer frees the text that
  `match_token` copies. The fix is one `if` and one call to `free`, and
  ranks 1 on all four, of 1 to 4 rows.
- CVE-2026-30874, `procd`: the filter of `hotplug-dispatch` compared
  each variable to `"PATH"` with `strcmp`, and now to `"PATH="` with
  `strncmp`. 24 commits came in the same update, and the fix ranks 20 of
  25 on AArch64 and 18 of 28 or 29 on the others under every order.

The `procd` fix is the shape no order here ranks well: one added
instruction, `x2 = 5`, and a callee and a text that changed. `added`
counts the instruction alone. A callee counts only in a pair whose code
is otherwise the same (`compare_callees`), and a text only so too. Over
all thirty-three cases of twelve fixes:

| Order | Rank sum | Top 1 | Top 5 | MRR |
|---|---|---|---|---|
| added | 165 | 15 | 27 | 0.572 |
| rare | 157 | 15 | 24 | 0.575 |
| rare × (0.5 + outlier) | 151 | 13 | 27 | 0.557 |
| rare × outlier | 163 | 10 | 26 | 0.476 |
| added × outlier | 158 | 10 | 25 | 0.474 |

The `procd` case showed four faults of the view, all fixed, with the
same pairs and ranks on the truth tests:

- `--view il` named a call through a register by the last load of the
  register in the order of the code, and a load on another path came
  first: the `strncmp` of the fix read as `avl_delete`, and `strchr` as
  `free`. `hereticus_il::flow` now names a callee only where every path
  that reaches the call loads the same one. AArch64 code of OpenWrt,
  built with `-fno-plt`, calls each import so, and the callees of the
  matcher now read these calls too (`Recovery::register_call_slots`).
- GNU `ld` merged `"PATH"` into `"DEVPATH"`, and the old side read as
  `@0x133f7`. A pointer into a text now reads as `&"DEVPATH"[3]`. GCC
  also reaches data from inside a text, as `"Unexpected character\n"[10]`
  in `jsonfilter`, so the diff aligns such a pointer as an address.
- On A32, `"PATH"` against `"PATH="` folded to one unchanged line, as the
  words of the two lines agree; the texts must now agree whole.
- The literal pool after each A32 function read as instructions, as
  `mrc2` and `andeq`, and its words move with each release. The
  assembly diff shows them as `.word`, and the IL view hides them.

### Callees and texts in a changed pair

A pair whose code changed now counts its changed callees and texts too.
A text counts as in a pair whose code agrees. A call counts where the
alignment of the two bodies keeps it in place, as the diff lines it up,
and its callee differs. Normalizing hides the callee, so the `strcmp`
and the `strncmp` of the `procd` fix align, and the row of the fix now
reads `1 callee, 1 text` where it read `-`.

The alignment alone made noise. At `-O0`, every `jal` normalizes alike,
so where an edit adds a call, the alignment can line up two calls of
functions that both builds still make: `dispatch` of the MIPS `firmware`
fixture gains a case that calls `crypto_verify`, and the object read 3
changed callees, though no call changed its callee. So a call counts
only where its earlier callee lost a call in the pair and its later
callee gained one. On `procd` for A32, that cut the other rows with a
changed callee from 7 to 2, and kept the fix.

These counts change no verdict and no rank. Each order of
`research_bench` that adds them, `r`, to `added` ranks the published
fixes better and the backports and the Ubuntu updates worse:

| Order | Backports (130) | Ubuntu (218) | Published (33) |
|---|---|---|---|
| added | 2970, 64 first | 304, 121 first | 165, 15 first |
| added + r | 3098, 64 | 318, 117 | 146, 16 |
| added + 2r | 3288, 64 | 324, 117 | 140, 16 |
| added + min(r, 2) | 3037, 64 | 311, 120 | 153, 15 |
| added + 5r | 3928, 64 | 378, 107 | 145, 17 |

Under `added + r`, the `procd` fix rises from 20, 18, 18 and 18 to 17,
17, 16 and 17. A fix in a large update shares its shape with many other
edits of the update that change a callee or a text too, so `added`
stays the default. The second alignment of each changed pair took the
MIPS kernel of the VR200 from 9.25 s to 9.4 s.

### Calls swapped for their bounded form

The `procd` fix swaps `strcmp` for `strncmp`, the form of the function
that takes a limit. Such a swap is a common shape of a fix of a memory or
parsing bug, as `sprintf` for `snprintf` and `strcpy` for `strlcpy`, and
it adds only the instruction that loads the limit. Li and Paxson ("A
Large-Scale Empirical Study of Security Patches", CCS 2017) found
security fixes smaller and more local than other fixes, which is the
case `added` ranks worst.

`matching::bounded` holds the functions of the C library that have a
bounded form, and their `_chk` forms that `_FORTIFY_SOURCE` calls. A
pair counts each changed callee of the last entry that swaps a function
for its bounded form, as `Match::bounded_calls`. The default order now
puts such a pair first, before the count of instructions added:

| Corpus | Rank sum before | Rank sum now | Rows with a swap |
|---|---|---|---|
| Backports (130) | 2970, 64 first | 2970, 64 first | none moved a fix |
| Ubuntu (218) | 304, 121 first | 304, 121 first | none moved a fix |
| Published (33) | 165, 15 first | 95, 19 first | the 4 `procd` fixes |

The `procd` fix rises from rows 20, 18, 18 and 18 to row 1 on all four
builds, and is the only row with a swap in each. No row of the backports
or the Ubuntu updates with a swap stands above a fix. One case is little
evidence that the list finds other fixes, but it costs no other fix
its rank: a swap for a bounded form is rare outside a fix.

### Checks before an early exit

Many fixes narrow what a function accepts: they add a test, and where it
fails the function returns at once, so every input the old code handled
well runs as before. SPIDER (Machiry and others, IEEE S&P 2020) finds
such a patch in source by that shape. In machine code, `matching::exits`
reads it as a conditional branch the edit added, from which one way
returns within 8 instructions, through calls and through jumps within
the function, as to a shared exit. `Match::early_exits` counts them.

First, a coarser test: an edit that adds a conditional branch and
removes or rewrites at most 4 instructions, first. It cut the rank sum
of the backports from 2970 to 1808, but raised that of the Ubuntu
updates from 304 to 315 and of the published fixes from 95 to 246: many
edits of a large update only add a branch.

With the early exit, over the rank sum and the fixes on row 1:

| Order | Backports (130) | Ubuntu (218) | Published (33) |
|---|---|---|---|
| added | 2970, 64 | 304, 121 | 95, 19 |
| exit first | 1802, 42 | 280, 136 | 111, 15 |
| exit and narrow (4) first | 1641, 60 | 293, 126 | 104, 17 |
| added + 3 if exit | 2626, 64 | 299, 121 | 96, 19 |
| added + 5 if exit | 2489, 64 | 300, 122 | 97, 19 |
| added + 7 if exit | 2387, 62 | 300, 122 | 98, 19 |
| added + 5 if exit, + 20 if narrow (4) | 1896, 65 | 297, 123 | 104, 19 |
| added + 3 if exit, + 20 if narrow (4) | 1933, 65 | 296, 122 | 103, 19 |

The backports hold four fixes, and the fix of `luaZ_fill` in Lua gives
almost all of their gain: its rank sum fell from 2486 to 2017 under
`added + 5 if exit`, and to 1419 with the more for a narrow edit. That
more sank tinyxml2, from 412 to 441, and five published fixes by one to
three rows; `added + 5 if exit` lifted tinyxml2 to 399, and moved only
the `uhttpd` fix for A32 from row 3 to row 5. So the default now counts
a check before an early exit as five instructions added, once for each
pair. No published fix has such a check, so none rose. It cost no time
measured on the MIPS kernel of the VR200, as the pass runs on every
changed pair at once.

SPIDER also asks that the way out of the check that does not exit runs
into the code it guarded, unchanged. A count of the checks whose other
way runs into code that the alignment keeps in place did no better:

| Order | Backports (130) | Ubuntu (218) | Published (33) |
|---|---|---|---|
| added + 5 if exit | 2489, 64 | 300, 122 | 97, 19 |
| added + 10 if guarded | 2323, 58 | 297, 122 | 98, 19 |
| added + 5 if exit, + 15 if guarded | 1946, 57 | 300, 123 | 101, 18 |
| guarded first | 1768, 44 | 289, 132 | 105, 16 |

Each trades fixes on row 1 for a lower rank sum, as the weights of the
plain check did, so it is not kept.

Nor did where the value a check tests comes from. A trace back from the
check, through moves, to the first write before it in address order,
reads the value as an input (nothing wrote it), a load, the result of a
call, or a computation:

| Order | Backports (130) | Ubuntu (218) | Published (33) |
|---|---|---|---|
| added + 5 if exit | 2489, 64 | 300, 122 | 97, 19 |
| + 5 if it tests a load | 2109, 64 | 298, 122 | 98, 19 |
| + 10 if it tests a load | 1864, 64 | 298, 122 | 99, 18 |
| + 10 if it tests an input | 2534, 64 | 301, 122 | 98, 19 |
| + 5 if it tests a call's result | 2482, 60 | 298, 123 | 98, 19 |
| − 5 if it tests a computation | 2458, 65 | 304, 122 | 97, 19 |

The fix of `luaZ_fill` tests a length it loads, and gives the whole gain
on the backports: 2017 to 1371 under `+ 10 if it tests a load`, while
tinyxml2 sank from 399 to 420. On the Ubuntu updates and the published
fixes, each order moves the rank sum by one or two. The ranks of the
fixes found there are near their floor: of the 176 Ubuntu fixes on a
row, 122 are on row 1 and 172 in the first five.

### The fixes no row shows

`research_bench --ubuntu` found no row for the fix in 42 of the 218
updates, but it reads only the symbols, and in 38 of them no symbol of
the library is a function the patches touched. Most of those patches
touch code outside the library: `tiffcrop` of libtiff, the shell of
sqlite, `bsdtar` of libarchive, the Python binding of libxml2, the test
programs of libssh and curl, and the GnuTLS backend of curl, which
`libcurl4` does not build; the rest live only as inlined copies.
`tests/truth_ubuntu.rs` reads the inlined copies too, and found the fix
in 193 of the 196 updates where a function it touched is in the library.

In each of the other 3, the fix compiled to the same code:

- sqlite, 3.37.2-2ubuntu0.3 to 0.4, for arm64 and armhf: the fix of
  CVE-2025-29088 adds two bounds to `setupLookaside` in `src/main.c`,
  but Debian builds the library from the amalgamation, which the patch
  does not change. The two libraries are of one size, and neither loads
  65528 or 0x7fff0000.
- libtiff, 4.3.0-6ubuntu0.2 to 0.3, for armhf: the fix of CVE-2022-3970
  casts each offset in `TIFFReadRGBATileExt` to `size_t`, which is 32
  bits there, as the offset is. The two libraries differ in 65 bytes, the
  build ID among them; for arm64 they differ in 205134.

So a fix counts as in the library now only where a function that holds
it, by its symbol or an inlined copy, has other bytes in the other
build. Every fix that changed the code is on a row: 193 of 193.

### Two older OpenWrt fixes

The `libubox` fix of CVE-2020-7248, from OpenWrt 19.07.0 to 19.07.1, and
the `uhttpd` fix of CVE-2019-19945, from 18.06.5 to 18.06.6, each for
`armvirt` 32 and 64, which before 21.02 ships its root file system as a
tar. The `libubox` fix turns each `sprintf` of `blobmsg_format_element`
into `snprintf`, and ranks 1 of 3 on both, as a call turned into its
bounded form. Without that rule it ranks 2, below the change to 64-bit
values in `blobmsg_add_json_element`: the second fix that the rule
lifts, and the first that it was not made on. The `uhttpd` fix adds a
test of the sign of the length to `client_parse_header` and to
`client_poll_post_data`, which rank 3 and 2 of 5 on both. Over all
thirty-seven cases of fourteen fixes, the default order has a rank sum
of 105, with 21 first.

### Tables of addresses in MIPS16e code

The MIPS16e build of `uhttpd` of OpenWrt 18.06 is not PIC. GCC puts the
table of each `switch` after its function, as the absolute address of
each case, and a function's literal pool holds the addresses it loads.
The scan read each such table, and each pool it split off, as a function
of its own, and each changed with the code it points into: 25 rows, the
fix on rows 3 and 5. The MIPS16e reading had no test of data at all.

Over the MIPS16e builds of `uhttpd`, `ubusd`, `odhcpd`, `jsonfilter` and
`libblobmsg_json`, the share of the aligned words of a function of 8
words or more that hold an address inside the image is at most 40% for
code, a short function whose pool is most of it, and at least 70% for
the tables. So such a function is data at half. A shorter one is data
where every word is an address, as a pool of 5 words that ends a
function; the top halfword of an address, as `0x0040`, reads as
`addiu s0, sp, 0x100`, which code rarely holds, and never in every word
of a run.

The report of `uhttpd` fell to 13 rows, with the fix on rows 2 and 4,
and those of `jsonfilter` for MIPS16e from 2 rows to 1. No other test
moved.

One row still lost 265 instructions to a new function in the later
build: the scan guessed a start at the pool after a `jrc ra` in one
build and not in the other, as the pool words decode as branches whose
targets move with their values. The MIPS16e reading named no word a
`lw rx, imm(pc)` loads, so no pool was data, as on Thumb-2 it is. Now
both halfwords of each such word are data to the scan, which keeps the
pool with its function, and a pool word that holds an address in the
image is a stored address to the matching, which drops it. The report
of `uhttpd` fell to 6 rows, with the fix on rows 1 and 2, as on ARM;
the fix of `jsonfilter` for MIPS16e reads 5 instructions added, as on
AArch64, where its pool made 11; `odhcpd` for MIPS16e little endian lost
a row. Over the MIPS16e backports built by GCC at `-O2` and `-Os`, 3
fewer functions went and 6 fewer came, with 2 fewer right pairs and 1
fewer wrong.

### Two builds of Mirai

Two static builds of one Mirai variant for ARM, with symbols, from
theZoo (`malware-reports/mirai-arm.md`). Paired with `--ignore-names`
and checked against the symbols, 514 of the 520 functions both builds
have pair right and none wrong; 6 stay unpaired, 3 that changed and 3
template copies, as each `*_IPGen` differs from the others only in its
callee.

The IL view showed the load of a pool word as `r1 = load.32 [pc + 0x4c]`
where the word holds the address of a text, in an image linked high.
`track_pool_words` read the word as an address for matching, but did not
give the load the address it forms. In `exploit_socket_edimax` the old
build sends an F5 BIG-IP request and the new one an Edimax request, and
the diff showed that line as unchanged. The load now reads as
`r1 = &"GET /tmui/..."`; the pairs are the same.

### Two ways MIPS loads an address

PIC code of MIPS loads the address of a static object either from the
slot of its page in the global offset table, then adds the low half with
`addiu`, or from a slot of its own. The linker picks per object, and
`dropbear` of OpenWrt 24.10.8 for MIPS32 little endian moved some
objects from one way to the other: 18 functions read as changed by that
alone. The added half is now a `ConstantKind::AddressTail`: it stays in
the normalized body as a token of its own, `Operation::AddressTail`, so
it still tells functions apart, but no edit counts it.

Dropping it from the body as well paired 22 fewer right and 10 more
wrong on the backports. Kept as a token, the backports paired 2 fewer
right and the same wrong, and the rank sum fell from 3028 to 2970; the
kernels paired 1 fewer wrong, and the Ubuntu updates did not move. The
fix of CVE-2026-35385 in `dropbear` for MIPS32 little endian rose from
row 2 to row 1, among 28 rows in place of 37, and the `ubusd` fix of
CVE-2025-62526 on MIPS16e from row 6 to row 5.

A lazy binding stub of MIPS holds the number of the symbol it resolves,
so the stub of number 5 in 24.10.3 had the same bytes as the stub of
number 5 in 24.10.4, which an added import made another function. The
stage of identical bytes paired 7 stubs of `ubusd` so, and left the
stubs of the same imports as new. `Cascade::pair_stubs_by_import` now
pairs two stubs of one import by the name the linker gives it, before
any stage reads code. No pair the symbols check moved; the backports and
the Ubuntu updates each lost one pair of stubs whose import is on one
side only.

### The Ubuntu updates, checked again

`tests/truth_ubuntu.rs` locks the counts of the 218 updates, which
`fixtures/ubuntu_cases.json` pins. Writing it showed that the check
itself counted 75 pairs wrong that are not, all on arm64:

- 39 are veneers that GNU ld adds for the Cortex-A53 erratum 843419. It
  names each by where it sits, as `e843419@015e_00003dc0_96c4`, so one
  veneer has another name in each build. They now count as neither.
- 36 are one function, named `.lto_priv.0` on one side only. Ubuntu
  builds arm64 with LTO and armhf without, and GCC adds the suffix to a
  local function it keeps under LTO. The suffix is now cut, as `.isra.`
  is.

The same cut finds the fix in 176 of the 218 updates, not 170: a patch
names `foo`, and the symbol is `foo.lto_priv.0`. With both, the Ubuntu
updates pair 264884 right and 179 wrong. The wrong pairs left are 114 on
arm64 and 65 on armhf. Three in four, 133, are twins, paired by identical
code, identical shape or their order: functions alike to the byte, as
`TIFFGetReadProc` and `TIFFGetWriteProc`, that nothing in the code can
tell apart. The counts above this section were taken before the fix.

Only 180 of the 218 updates touch a function that is in the library at
all: the others patch a tool or a test of the same source, as
`tiffcrop` of libtiff, `xmllint` of libxml2 or the test suite of libssh.
The fix shows on a changed row in 176 of those 180. Of the 4 left, one
is in liblzma on arm64: LTO inlined the patched `lzma_index_prealloc`
into `index_decode`, which the report shows second, but which no patch
names.

The test now reads the DWARF of each debug file, and counts a row as the
fix where it holds an inlined copy of a patched function too. Then 196
updates touch the library, and the fix shows on a changed row in 193 of
them: on row 1 in 161, where 121 counted before, and in the first five
in 185. In 51 of the 193, the first row holds the fix only as an inlined
copy, as `output_auth_headers` of libcurl holds `Curl_output_digest`, or
`png_process_data` of libpng holds `png_push_read_chunk`. Inlining is
common even without LTO: 23 of the 51 are on armhf.

Most rows of an arm64 update are `reordered`: LTO schedules the code of
many functions another way in each build. In the libssh update
0.9.6-2ubuntu0.22.04.5 they put the fix on row 66 of 122, where armhf
shows one row. Sorting the reordered rows after every other row put it
on row 28, and cut the rank sums from 3179 to 2921 on the backports and
from 343 to 306 on the Ubuntu updates. But a fix can be a reordering:
CVE-2023-28484 in libxml2 moves code, and fell from row 1 to row 7. The
MRR rose 0.001 on the backports and fell 0.003 on the Ubuntu updates, so
that order was not kept; the bench keeps it as `added, reordered last`.

With the names the libraries export, as the tool uses them by default,
the Ubuntu updates pair 265032 right and 51 wrong. The getters of
libtiff, `return tif->tif_readproc` and its kind, show why the names
matter: an update put a field into `struct tiff`, so each getter's new
code is the old code of the next one, and without names the stage of
identical code pairs every one of them with its neighbour. With names,
13 of the 51 wrong pairs came from entry 13; a pair by name no longer
breaks, which paired 2 more right and 1 fewer wrong.

Entry 13 also broke close pairs for one weak reference. In libexpat
2.4.7-1ubuntu0.6, `storeEntityValue` paired with itself at 0.92, until
the constant 0x1839, which only it held before and only
`appendAttributeValue` holds after, paired it at 0.73 with the wrong one;
6201 reads as the line number of an assertion, which a patch above it
moves. The callee set of `appendAttributeValue` broke its pair at 0.88
the same way. Entry 13 now keeps a pair that scores `CLOSE_SIMILARITY`
or more and more than the new pair:

| Set | Right | Wrong |
|---|---|---|
| Backports | −8 | +8 |
| OpenWrt kernels | +40 | −18 |
| Ubuntu updates | +7 | −6 |
| Ubuntu updates, with names | +5 | −5 |

The rows of an arm64 update that read `reordered` mostly move loads and
arithmetic, as a scheduler does. The fix of CVE-2023-28484 in libxml2
moves code, and with it branches. So the report now puts last a
reordered pair whose edit touches no branch, call or jump
(`is_rescheduled` in `hereticus-cli/src/main.rs`), and leaves the rest
in place. Unlike sorting every reordered pair last, this lost no fix on
any set:

| Set | Rank sum | Top 1 | Top 5 | MRR |
|---|---|---|---|---|
| Backports | 3179 → 3035 | 64 → 64 | 82 → 82 | 0.568 → 0.568 |
| Ubuntu updates | 342 → 303 | 121 → 121 | 171 → 173 | 0.812 → 0.813 |
| Ubuntu updates, with names | 343 → 304 | 121 → 121 | 171 → 173 | 0.812 → 0.813 |
| Eight published fixes | the same rows | | | |

A floor on the unique constants of entry 13, against such line numbers,
did not help: counting only constants of 32768 or more paired 38 fewer
right and 1 more wrong on the backports, and 14 fewer right and 7 more
wrong on the kernels; 65536 or more did as badly. Most constants from
0x1000 to 0xffff are masks and magic numbers, not lines.

Most of the 133 twins left wrong on the Ubuntu updates are exported
functions alike to the byte, as `archive_entry_set_gname` and
`archive_entry_copy_gname` of libarchive. Code outside the library calls
them, so inside it they have no caller to vote, and only their names
tell them apart; with names, 45 wrong pairs are left in all.

### Speed, under callgrind

A comparison of two releases of libxml2 for arm64, under callgrind:

| Change | Instructions |
|---|---|
| Before | 65.6 billion |
| `extended_register` finds a comma, not `", "` | 58.6 billion |
| The table of the instruction diff skips the shared head | 50.3 billion |
| `Cascade::assess` skips a pair of the same bytes | 49.8 billion |

The same update of libxml2 for armhf, which Ubuntu builds as Thumb-2,
ran 144.3 billion instructions, and `str::replace` alone, which took the
width suffix `.w` out of every mnemonic, 16% of them. Checking for a dot
first, and taking the suffix out by bytes, brought it to 122.0 billion.
Of what is left, the decoder of yaxpeax-arm reads its bit fields in 7%,
and the rest is spread over small string work, none of it above 5%.

On the wall clock, with the ratio tests in place too, the CLI compares
the two ARM kernels of the EX6100v2 in 28.3 seconds, from 30.0, and the
arm64 update of libxml2 in 3.9 seconds, from 4.7.

The musl build runs about as many instructions as the glibc build, 65.6
against 66.5 billion before these changes, but takes 4.7 seconds to
glibc's 3.1: musl runs its `memcmp` and the like more slowly. Of what is
left, `decode_all` takes 45%, most of it formatting each instruction as
text, which a function goes through three times: to find it, to prepare
it, and to assess each pair it is in.

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

A name that lives on does not prove the pair wrong, though: the code can
move to a new function and leave the old name on a wrapper, as
`sock_init_data` did to `sock_init_data_uid`. `tests/truth_kernels.rs`
now judges a pair whose names differ by two things the tool never reads.
The first is the names of its callers and callees: over the pairs that
share a name, 91% have at least half of these in common, and 1% have
none. The second is the function that holds each name on the other side,
and whether it is closer in code than the pair is. Where both say the
code went with the new name, the pair is renamed. Where that function
has the same normalized instructions as the one paired, the pair is a
twin, which only names can decide. Of the 6366 pairs wrong by the names,
1182 are renamed, 940 are twins and 4244 stay wrong: 1.70% in place of
2.56%. The pairs by callers, by place and by references keep most of the
wrong, at 9%, 12% and 10%.

The debug files hold DWARF too, which names the source file of each
function. A name alone can belong to two static functions of different
files, and code moves between files across a release: `kernel/futex.c`
became `kernel/futex/core.c`, and `net/core/ethtool.c` became
`net/ethtool/ioctl.c`. Two files correspond where two or more names that
each release holds once move from the one to the other. With that, 62
pairs that share a name come from files that do not correspond, and a
rename must stay in its file. Comparing the paths alone had flagged 1137
such pairs, nearly all moved files. A shared file alone proves too little
in a large file such as `net/ipv4/tcp.c`: of the renames it alone
supported, about one in five read as wrong to a person, so those are
counted apart as unproven. Over the kernels, 1.35% of the pairs are wrong,
and at most 1.57%.

Two more checks on the weak pairs did not help. Moving a pair by
similarity, callers or place to a free function that ranks better by
code, references and constants, once more pairs are known, cut 45 wrong
kernel pairs at a margin of 0.15, but cost the backports 332 right and
added 332 wrong. At 0.05 it was worse on both sets.

Two functions that a pair by similarity or by place joins, where each
points at texts and they share none, are often different: a kernel
function names its own messages. Undoing such pairs, each cell right
then wrong, against no rule:

| Rule | Backports | Kernels |
|---|---|---|
| one sure text or more on each side | −8, −11 | −212, −74 |
| two or more on each side | none | −58, −30 |
| one or more, under a score of 0.8 | −8, −9 | −88, −62 |

Each undoes more right pairs than wrong on the kernels: a release edits
the messages of a function it keeps. None is kept.

### 13: unique references

A text or a constant above `LARGEST_PLAIN_CONSTANT` that one function
alone holds on each side pairs the two, where their code scores 0.3 or
more. It breaks a weaker pair where that pair shares fewer such
references, but never a pair by identical code or shape. It runs after
the similarity stage and before the callers vote.

| Set | Right | Wrong |
|---|---|---|
| Backports | +547 | −135 |
| OpenWrt kernels | +704 | −575 |
| Ubuntu updates | −2 | +6 |

Each part, in the order it was added, against the step before:

| Part | Backports | Kernels | Ubuntu |
|---|---|---|---|
| Texts and constants, one run | +304, −40 | +32, −18 | +1, +3 |
| The one call to a named function | +141, −16 | none | none |
| The one call to a paired function | +28, −11 | +126, −36 | none |
| Up to four rounds | none | +7, −7 | not measured |
| Again after entry 7 | +58, −60 | +256, −270 | −3, +1 |
| The one caller of a set of paired functions | +16, −8 | +283, −244 | none, +2 |

Run after entry 7 alone, without the first run, the stage paired 102
fewer right and 12 more wrong on the backports than both runs did.

Across the kernel upgrades the wrong pairs fell from 10.40% to 9.71% and
from 5.95% to 5.64%, and over all twelve kernel comparisons from 4.04%
to 3.82%. The pairs by place (entry 7) are wrong 15.9% of the time, from
21.3%, since this stage takes the clearest of them first.

On the backports, every fix now shows on a changed row: 18 comparisons
missed it before. The rank sum rose from 2799 to 3173 because those 18
now count; top 1 rose from 63 to 64, top 5 from 78 to 82 and the MRR from
0.546 to 0.568. The ranks of the eight published fixes did not move.

Breaking only a pair that scores no better than the new one cut the 3
wrong Ubuntu pairs, but on the backports it paired 75 fewer right and
kept 48 more wrong. A pair this stage makes is still weak: entry 7 undoes
it where it breaks the order. Kept from that, the stage paired 19 more
wrong kernel pairs, not 18 fewer. Texts alone, without constants, paired
255 more right and 66 fewer wrong on the backports, and a second shared
reference as a floor only 100 more right.

A raw kernel names no function, so the call to a named function cannot
help there; the call to a paired function can. The named calls moved one
fix out of the top 5 on the backports.

A floor on the code similarity of a pair that the callers vote for (A10)
did not help: at 0.4 it paired 86 fewer right and 30 more wrong kernel
pairs, and changed nothing on the backports. The pairs it would undo are
mostly right.

The two floors of entry 1, measured again with entry 13 in place, trade
right pairs for wrong ones at every setting tried, so they stay:

| `realign_by_context` | Backports, right and wrong | Kernels, right and wrong |
|---|---|---|
| 3 shared edges, 0.3 (kept) | 29433, 682 | 242945, 9892 |
| 4 shared edges | 29340, 658 | 242220, 9343 |
| 2 shared edges | 29555, 725 | 243688, 11127 |
| similarity 0.4 | 29387, 662 | 242573, 9668 |

The pairs entry 1 joins are wrong far more often than the rest of the
label it shares with A10: on the kernels, 3300 right and 1762 wrong,
where the callers' own joins, moves and swaps paired 1957 right and 140
wrong. In a kernel, two unrelated functions easily share three edges,
when the edges are `kfree`, `mutex_lock` and `printk`. Counting no edge
that more than N functions of the second binary hold, and no caller that
calls more than N:

| N | Backports | Kernels | Ubuntu updates |
|---|---|---|---|
| 16 | −29, −34 | −951, −1153 | −1, −1 |
| 32 | −16, −8 | −669, −1050 | −1, 0 |
| 64 | 0, 0 | −503, −992 | −1, 0 |
| 128 (kept) | 0, 0 | −390, −918 | −1, 0 |
| 256 | 0, 0 | −305, −777 | 0, 0 |

Each cell is right, then wrong, against no limit. From 256 to 128 the
kernels drop 141 wrong pairs for 85 right; from 128 to 64, 74 wrong for
113 right, so the limit is 128. The wrong kernel pairs fall from 3.81%
to 3.46%. The same limit on the edges that break near ties in the
similarity stage (A8) paired 26 fewer right and 14 more wrong kernel
pairs, and was not kept.

The floor of entry 7, `LOWEST_LAYOUT_SIMILARITY`, measured the same way
with the set of paired callees in place (29449, 674 and 243228, 9648):
0.2 paired 452 fewer right on the backports for 58 fewer wrong on the
kernels; 0.05 paired 161 more right on the backports, but 12 fewer right
and 15 more wrong on the kernels, and put 2 fewer fixes on the first row.
The floor stays at 0.1.

### 14: ratio test

Half the wrong kernel pairs came from the similarity stage, and many
were small functions at a score of 1.00: `kszphy_get_sset_count` with
`irq_default_primary_handler`, both `return 2;`. The stage now takes no
pair where either function has a free rival within a margin of its rank.
Against no margin, each cell right then wrong:

| Margin | Backports | Kernels | Ubuntu updates | With names |
|---|---|---|---|---|
| a tie | −36, −111 | −182, −1922 | −1, −12 | −1, −6 |
| 0.01 | −33, −134 | −171, −2021 | −1, −12 | −1, −6 |
| 0.03 (kept) | −24, −159 | −223, −2201 | −3, −13 | −1, −5 |
| 0.05 | −105, −175 | −271, −2383 | −3, −13 | −1, −5 |
| 0.1 | −142, −233 | −521, −2690 | −3, −13 | −1, −5 |

Up to 0.03, every step is better on every set; past it, the backports
lose right pairs faster than wrong ones, and at 0.1 three fixes leave the
first row. At 0.03 the ranks of the fixes stay the same, and the wrong
kernel pairs fall from 3.46% to 2.61%. Running the similarity stage
once more at the end, when the stages after it have paired many of the
rivals, gave back more wrong pairs than right: 322 more right and 494
more wrong on the kernels, and 35 and 41 on the backports.

The context joins of entry 1 take the same test: no join where a second
candidate shares as many edges and scores within 0.03, nor where two
functions propose the same partner alike. That paired 6 more right and
11 fewer wrong over the backports, 96 fewer right and 145 fewer wrong
over the kernels, to 2.56%, and 3 fewer right and 2 fewer wrong over the
Ubuntu updates. With an exact tie in place of 0.03 it paired 2 fewer
right and 1 more wrong over the backports, and on the kernels less of
both.

The twins of A4 are now the third source of wrong kernel pairs: 710,
of which 551 have their true partner paired with another. A kernel holds
groups of hundreds of twins, as `return 0;`, whose members come and go
between releases, so equal counts no longer mean the same members.
Leaving groups larger than N alone, each cell right then wrong:

| N | Backports | Kernels | Ubuntu updates |
|---|---|---|---|
| 4 | −352, −50 | −203, −361 | −34, +2 |
| 16 | −152, −8 | +24, −234 | −18, +9 |
| 64 | 0, 0 | +10, −29 | −14, +7 |
| 256 | 0, 0 | 0, 0 | 0, 0 |

The kernels gain at every size, but the template instances of tinyxml2
and smallvec, and the wrappers of the Ubuntu libraries, form groups of 5
to 64 that order pairs right, so no limit was kept. The size of a group
does not tell a group in order from one out of it.

The pairs by place of entry 7 under a score of 0.4 are wrong about half
the time on the kernels, and most of those have their true partner free.
A ratio test for place, which took no such pair where either function
had a free rival scoring 0.1 more, cut 408 wrong kernel pairs for 7 more
right, and lifted the MRR of the backports from 0.568 to 0.579. But it
cost the backports 1267 right pairs and the Ubuntu updates 27: between
two compilers, a function with a look-alike elsewhere is still most
often the one in its place. At a margin of 0.2 it cost them 1030 and 15.
It was not kept.


### A branch condition on A32 and A64

`Arch::operation_name` kept the condition of an A32 branch and dropped it
from A64, so a `bne` that became a `beq` showed as a changed row on A32
and as no change at all on A64. The normalizer already reads a guard's
branch by its condition either way (`Operation::GuardBranch`): `eq` and
`ne` are one, since a compiler may branch on the opposite condition and
swap the code after it, but `lt` and `le` are not. So an off-by-one fix,
`b.lt` to `b.le`, was already an edit on both.

A64 now keeps the condition too, as `b.ne`. A branch on the opposite
condition shows as a row changed in detail, with no edit counted, on
both. The pairs and the ranks of every set stayed the same: backports,
published fixes and Ubuntu updates. The kernels have no A64 code.

Not kept: counting a branch on the opposite condition as an edit. A
compiler flips a branch between levels, so this would make each such
row an edit, where the normalizer reads it as a free choice.

### 15: slots of a table

All 58 twins that paired wrong between clang and GCC (see "Tell twins
apart that no instruction separates" in `TODO.md`, as it was) were
virtual functions of tinyxml2, each in a vtable with functions that
differ. `Binary::function_tables` reads the runs of addresses of
functions in the loaded data, and `Cascade::pair_by_tables` pairs by
slot where a firm pair joins two tables. Against the step before, each
cell right then wrong:

| Set | Right | Wrong |
|---|---|---|
| Backports | +275 | −54 |
| OpenWrt kernels | +329 | −21 |
| Ubuntu updates | +9 | −8 |

Against the source files in the DWARF of the kernels
(`tests/truth_kernels.rs`), which count a renamed function and a twin
apart, the kernels paired 325 more right and 3 more wrong; the pairs
by slot are wrong 0.76% of the time. The ranks of the eight published
fixes did not move. On the backports the rank sum rose from 3015 to 3028 and the MRR fell from 0.568 to
0.567, as more changed functions now pair; top 1 and top 5 stayed. Of
the 58 wrong twins, 4 are left: `MemPoolT<52>::SetTracked` and
`MemPoolT<60>::SetTracked`, in two comparisons.

A shared library fills a vtable through dynamic relocations, so the
file holds zero there (RELA, as AArch64) or an addend (REL, as ARM).
`Links::words` reads each word as the loader leaves it: the address an
`ABS` or `RELATIVE` relocation stores, else the stored word.

Each part, in the order it was tried, against the step before:

| Part | Backports | Kernels |
|---|---|---|
| Twins only, after the similarity stage | +54, −54 | +179, −10 |
| Again at the end | none | +59, −8 |
| Free functions of similarity 0.5 or more too | +119, none | +147, +1 |
| Floor 0.3 in place of 0.5 (kept) | +102, none | +84, −5 |
| Floor 0.1 in place of 0.3 | +90, +5 | +52, +12 |
| Break pairs by similarity or place too (kept) | none | +12, −14 |
| Break pairs by callers or references too | none | −4, +2 |
| No two tables where a firm pair crosses a slot (kept) | none | +6, −6 |
| A null inside a table | −7, none | +17, −26 |

The Ubuntu updates paired 9 more right and 8 fewer wrong with twins
only, and moved no further.

A raw image says nothing of where its code ends. In tinyxml2 for
Thumb-2 as a raw image loaded at zero, two halfwords of code often read
as the address of a function, and such pairs of words paired four
functions wrong across the release from 9.0.0 to 10.0.0. A run inside
a function now needs three addresses. Skipping every word inside a
function lost the whole gain on the kernels, since a scan of a raw
kernel takes its data for the end of a function: 77% of the image of
the EX6100v2 lies inside one. Three addresses everywhere cost the
backports 4 right pairs. Against two everywhere, the rule of three
inside a function paired 158 fewer right and 21 more wrong on the
kernels.

Tried again with the rule of three and the recovery fixes in place, for
the kernel upgrades, each against that step: a null inside a table
paired 9 more right and 14 fewer wrong on the kernels, but 2 fewer
right on the backports; moving a pair by similarity or place to a free
function of its slot that scores as well paired 5 more right on the
kernels, but 4 fewer right and 2 more wrong on the backports. Neither
is kept.

### Function recovery, again (A16)

`tests/boundaries.rs` checks the functions the scan finds in each
stripped release against its symbols. Three causes, each fixed alone,
over 46006 functions:

| Fix | Exact | Invented | Missed |
|---|---|---|---|
| Before | 45919 | 25 | 16 |
| Step past padding after an exported function | 45921 | 11 | 13 |
| Read MIPS float branches and compares on any condition code | 45929 | 3 | 13 |
| A frame right after a pool opens a function | 45937 | 3 | 9 |

- An exported function ends where its dynamic symbol says, and the scan
  guessed that the next starts there. GCC for Thumb-2 pads with `nop`
  and zero halfwords to the next 8 bytes, so each gap became a function
  of padding, and clang's `nop`s after `crc32_combine` took in
  `crc32_combine_`. The guess now steps over the padding, and a guess
  that holds only padding makes no function.
- `rabbitizer` reads MIPS I to III, where `bc1t` and `c.lt.d` use
  condition code 0 alone. GCC puts a second compare in `$fcc1`, so
  `bc1t $fcc1` read as no branch, and the code it reaches after an
  internal return read as a new function: `math_ceil` and `math_floor`
  of Lua split in two on every MIPS build by GCC. They lift as the forms
  on code 0 do.
- An unwind entry that cannot unwind covers many functions, and the
  scan reads its range as if there were no index. There, a frame that a
  jump from the function before reaches was taken for a frame made late.
  No code falls into the word after a pool, so a frame there opens a
  function: `codebinexpval` of Lua by clang for ARM and Thumb-2.

The pairs moved little: the backports paired 1 more right, the Ubuntu
updates 29 more right with no more wrong, 27 fewer gone and 20 fewer
new, and one more fix first; the kernels did not move. In
`tests/versions.rs` a few counts of right pairs fell by 2, where the two
halves of `math_ceil` had each paired right.

### Selects as guards (A15)

`il` reads a compare and the branch on it as one guard on AArch64, A32,
Thumb-2 and MIPS32. Measured against the symbols, that paired 231 more
functions right and 61 more wrong over the cross builds, mostly twins
such as `math_max` and `math_min`. A compiler picks a branch or a select
freely, so a select should read as the branch of a guard. Measured again
against the source files in the DWARF:

- A `csel`, `cset`, `csinc` or `csneg` of A64 as the branch of the
  guard its compare starts, with or without its own token: 5 or 6 more
  right and 2 to 4 more wrong over the backports, with one fix fewer
  ranked first, and the Ubuntu fixes ranked a little higher.
- The conditional instructions of A32 the same way: 28 fewer right and
  23 more wrong over the kernels, and 10 more wrong over the backports.
- A `ccmp` as the branch of the guard before it and the compare of the
  guard after it, so that a chain reads as two guards: 3 more right and
  none wrong over the backports, and the Ubuntu fixes ranked 4 places
  lower in sum. With the A64 selects: 12 more right and 2 more wrong,
  and one fix fewer ranked first.

None of these is clearly better, so none is kept. A select reads as a
plain `select`, and the compare before it as a guard's test.

### Instructions weighed by rarity (entry 6)

Ghidra's BSim weighs each feature by how rare it is across a corpus.
Measured again against the source files in the DWARF, with each
instruction weighed by its inverse document frequency over the functions
of both binaries: weighing every code score, or only the scores the
similarity stage chooses by, at a threshold of 0.55 to 0.65, never beat
the plain score on the backports, and always ranked the fixes lower
(top 1 from 64 to 61 to 63). On the kernels, choosing by the weighed
score at 0.6 paired 223 more right and 35 more wrong, a better trade than
the plain score at 0.6 (365 and 203), but the backports paired 10 fewer
right and 26 more wrong. It would also move every score a report shows.
It is not kept. Measure it again only if a new corpus favours it.

### The kernel upgrades, checked again

Over the six kernel upgrades, 2723 pairs were wrong by
`tests/truth_kernels.rs`. A third of the wrong pairs of `mipsel-r6220`
from 21.02.7 to 22.03.2 joined init functions that score 0.95 or more,
as `ip_rt_init` with `neigh_init`, and the function of the later side
overlapped the symbols of several others. The cause is in the truth, not
in the pairs: the end of `.init.text` in the shipped ramips and lantiq
kernels sits apart from where the debug file puts it. In 22.03.2 for
`mipsel-r6220`, from 0x80863148 on, the code is 0xc8c bytes before its
symbols; 549 of the 943 functions of the section start on a symbol, and
409 do 0xc8c bytes on. The test now leaves out a function where one
shift of the addresses puts more of the 17 functions around it on a
symbol than no shift does, and half of them. That holds about 360
functions of each such kernel and none of the ARM or ath79 kernels, as a
function the scan splits into pieces lies at a different distance from
the symbols in each piece.

| Releases | Wrong before | Wrong after |
|---|---|---|
| 21.02.7 to 22.03.2 | 3.19% | 2.60% |
| 22.03.5 to 23.05.5 | 1.61% | 1.45% |
| all | 1.14% | 0.97% |

The wrong pairs of the upgrades, by the stage that paired them and by
where the true partner of each side is, show one fault of the shape
stage (A2). It asked only whether a function of
the first binary had one candidate of its shape on the second. Where a
release deletes one of two twins, the twin that comes first took the
one left, deleted or not, and the true partner then paired elsewhere by
similarity: 111 wrong pairs over the upgrades, counted before the
truth was set right. The stage now pairs only
where the second function has no other free twin on the first side that
could take it, by the same tests of names and of what the twins refer
to. Each cell right, then wrong, against the step before:

| Set | Right | Wrong |
|---|---|---|
| OpenWrt kernels | +218 | −42 |
| Backports | +23 | −30 |
| Ubuntu updates | +28 | −22 |

The wrong kernel pairs fall to 2.56% and 1.41% over the upgrades, and to
0.95% over all twelve. The ranks of the backports, the published fixes
and the Ubuntu updates did not move. Between `gcc-O2` and `gcc-Os` the
backports pair 5 fewer right: GCC folds `gzopen` and `gzopen64` of zlib
into one function at `-Os`, so both twins of `-O2` fit it, and now
neither takes it.

Not kept:

- The same test in the stage of identical code paired 10 more right and
  1 fewer wrong over the kernels, but 4 fewer right and 5 fewer wrong
  over the backports.
- The shape stage once more after the close pairs by similarity, so that
  a twin they pair stops being a rival, paired 2 more right kernel pairs
  and changed nothing else.
- Over the upgrades, neither the score nor the ratio of the sizes of the
  two bodies tells right from wrong in any weak stage: the pairs by
  callers are wrong 10% to 20% of the time at every score from 0.3 to
  0.6, and the pairs by similarity 1% to 9% at every ratio from 0.4 up.
- Before the truth was set right, of the 314 wrong pairs by similarity
  whose first side keeps its name on the second side, free, 283 score
  at least as high as that namesake does:
  the code moved into a new function and left the old name on a small
  wrapper, as `generic_file_read_iter` to `generic_file_buffered_read`.
  The pair follows the code, and the names call it wrong.

Of the wrong pairs by place (entry 7) over the upgrades, 104 have a true
partner left free that is closer in code. Most sit in a gap of equal
counts where the release deleted one function and added another, so
pairing first with first puts the functions after it one off, as
`lockref_put_or_lock` with `lockref_get`. Such a gap now pairs in order
by score, where that sums `SHIFTED_GAP_MARGIN`, 0.3, more than first
with first, each pair counted at its score less the floor of 0.1. Each
cell right, then wrong, against the step before:

| Margin | Kernels | Backports | Ubuntu updates |
|---|---|---|---|
| none | +50, −18 | −135, +90 | none |
| 0.1 | +51, −9 | −33, +23 | none |
| 0.2 | +43, −16 | −16, +15 | none |
| 0.3 (kept) | +39, −12 | +5, none | none |
| 0.5 | +30, −10 | none | none |

The ranks of every set stayed the same. A floor of 0 or 0.2 in place of
0.1 did as well or worse. Undoing the pair by place in such a gap, in
place of moving it, where another function of the gap scores 0.1 to 0.3
more with either side, cost the backports 57 to 303 right pairs: between
two compilers, the first function of a gap is most often the first
one's partner, even where another looks closer.

A gap whose counts differ paired nothing, since a function went or came
and nothing says which. But in a kernel upgrade, close code in such a
gap is often left free: the similarity stage takes no pair with a rival
elsewhere in the binary within 0.03 (entry 14), and the place tells the
two apart. Such a gap now pairs in order by score, each pair less a
floor, where the pair scores `LOWEST_UNEVEN_GAP_SIMILARITY`, 0.8, or
more, no other function of the gap scores within 0.03 of it with either
side, and the two call the same named functions. Each cell right, then
wrong, with homonyms counted wrong, against no such pairs:

| Rule | Kernels | Backports | Ubuntu updates |
|---|---|---|---|
| Floor 0.5, gaps one or two apart | +1379, +44 | +64, +81 | +2, +5 |
| Floor 0.7 | +987, +17 | −7, +26 | +3, +5 |
| Floor 0.8 | +933, +6 | +8, +17 | +3, +5 |
| Floor 0.8, one apart, no rival | +454, −5 | +8, none | +3, +5 |
| Named calls the same | the same | the same | +3, none |
| Any gap (kept) | +752, +3 | +10, none | +4, none |
| Floor 0.7, two apart, no rival, named calls | +643, −6 | +2, +5 | +3, none |

The five wrong Ubuntu pairs were wrappers of libssh that score 1.00 and
call other imports, as `md5_update` with `md5_ctx_free`. A rival margin
of 0.02 to 0.1 did the same within a few pairs. Over the upgrades the
wrong pairs fall to 2.53% and 1.39%, and the pairs by place are wrong
3.23% of the time, from 3.44%, over 1005 more of them. The ranks of every
set stayed the same.

Over the upgrades, 5725 functions stayed free where their namesake on
the other side was free too, and 673 of those pairs score 1.00: twins of
one source file, as `atomic64_add` and `atomic64_sub`, which no caller
tells apart, since a kernel calls such functions through pointers. In a
gap whose counts differ, each twin was the rival of the other, so
neither paired. A rival now counts only where the alignment of the gap
leaves it out: twins that align in order are no rivals of each other.
That paired 331 more right and 2 more wrong over the kernels, and 4 more
right over the backports. Raw zlib from 1.2.11 to 1.2.12 paired 1 more
right and 1 more wrong; the Ubuntu updates stayed the same. A floor of
0.7 in place of 0.8 then paired 83 more right kernel pairs, but 8 fewer
right and 7 more wrong over the backports. Over the upgrades the wrong
pairs fall to 2.52% and 1.39%.

The layout stage runs once, before the stages that pair by references,
by twins and by tables, so a gap they narrow to one function each side
stays free. Of the 423 pairs at 1.00 still missed over the upgrades, 61
sat in a gap of equal counts at the end. Running the whole layout stage
again before the context check paired 25 more right and 13 more wrong
over the kernels, and after it, 97 more right and 313 more wrong, as it
undoes and pairs again what that check undid. Pairing only close code,
by the rule for gaps whose counts differ, and undoing nothing, paired
34 more right and none wrong before the check, with every other set the
same; that is kept. 194 of the 423 sit out of place: the code moved.

Of the pairs still missed at 0.7 or more, 143 have no free rival within
0.03 at the end, most of them out of place. The context check undoes a
pair by similarity out of place where its one paired neighbour each side
disagrees, at any score. Keeping such pairs at 0.9 or more paired 18
more right and 20 more wrong over the kernels, and at 0.7 or more, 55
more right and 164 more wrong. The check stays as it is.
