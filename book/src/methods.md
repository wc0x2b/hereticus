# Methods

This page tells how `hereticus` finds the functions that changed. Each
step is a known method of binary diffing, or of a near field. Each section
names the code that does the step, and its entry in
[`RESEARCH.md`](https://github.com/wc0x2b/hereticus/blob/master/RESEARCH.md).
That file gives the source of each method, and the measurements that
kept it.

## The Steps

```text
 before.bin                                          after.bin
     │                                                   │
     ▼                                                   ▼
  unpack ─▶ read ─▶ find functions ─▶ normalize    (the same steps)
                                         │               │
                                         └──────┬────────┘
                                                ▼
                                     pair the functions
                                                ▼
                                     compare each pair
                                                ▼
                                     sort the changed pairs
```

1. [Unpack](#unpacking-firmware) each firmware image, with `--unpack`.
2. [Read](#reading-a-binary) each binary, and
   [find its functions](#finding-functions).
3. [Normalize](#normalizing) each instruction, and
   [lift](#lifting-to-an-il) it to an IL.
4. [Pair](#pairing-functions) the functions of the two binaries.
5. [Compare](#what-changed) each pair, and say what kind of change it has.
6. [Sort](#sorting-the-report) the changed pairs, so that a fix comes
   first.

## Terms

- **Pair**: a function of the earlier binary and the function of the later
  binary that `hereticus` thinks is the same function.
- **Normalized body**: the instructions of a function, with the details
  that a rebuild can change removed. See [Normalizing](#normalizing).
- **Twins**: two or more functions of one binary with the same normalized
  body, as small wrappers that differ only in the function they call.
- **Stub**: a short piece of code that the linker writes for each function
  that the binary imports. A call to `memcpy` goes to the stub of
  `memcpy`, and the stub jumps through a slot of the **GOT** (global
  offset table) to the library. On ELF the stubs are in the **PLT**
  (procedure linkage table).
- **Text**: a string in the binary that the code points to, as a format
  string or a message.

## Unpacking Firmware

A vendor ships a kernel compressed, behind a header, and often with a
small decompressor before it. `--unpack stub` takes out the decompressor,
and `--unpack kernel` takes out the kernel it holds. `hereticus` reads
these containers: zImage, FIT, uImage, the sysupgrade tar of OpenWrt,
lzma-loader and TP-Link v2. A zImage can hold its kernel as xz, with any
branch filter of xz, or as gzip or zstd. Where a container gives the address its part
loads at, `hereticus` keeps it as the base of the raw image. binwalk finds
such containers by their signatures in the same way.

Code: [`unpack`][unpack]. See `RESEARCH.md`, A18.

## Reading a Binary

`hereticus` reads ELF, Mach-O and raw images. An ELF file with no section
headers, as `sstrip` leaves it, is read through its program headers. The
dynamic segment still gives the dynamic symbols and the relocations.

### The Load Address of a Raw Image

A raw image has no header, so `--base` gives the address it loads at. A
wrong base does not fail: the code still decodes, and each relative branch
still lands in the image. Only the addresses are wrong.

The image holds the full addresses of its own strings and functions: in
tables of handlers, in literal pools and in x86 immediates. At the right
base, many such words point at the start of a string or of a function,
and at any other base few do. `hereticus` finds the base in four steps:

1. **Targets.** Each run of printable bytes that a zero closes is a
   string. Each prologue is a function, with the `$gp` set up of MIPS PIC
   before it.
2. **Votes.** A word `v` that points at the target `t` says the base is
   `v - t`. A few targets each take a vote from every word, and a short
   check against other targets keeps a few thousand candidates. Separately,
   each word votes with each target whose offset into a 4 KiB page agrees
   with its own, as a base on a page needs. That finds the base where few
   targets are pointed at at all, as in PIC code.
3. **Chance.** Words that are not addresses hit targets too, as a run of
   similar A32 opcodes does. They hit as often a few bytes off, and the
   right base does not, so the median of the hits a few bytes off is what
   chance gives. The evidence is the hits above it. A base where the image
   runs past the top of the address space is no candidate: i686 and ARM
   PIC hold offsets from the global offset table, which agree with each
   other about such a base.
4. **Halves.** An instruction can hold the low half of an address, as MIPS
   `addiu a0, a0, %lo(text)` does. Read as a word, it points at text from
   a base just below its opcode. Such hits fall in one window of 64 KiB,
   and they name only text, so they count for nothing.

The best base must have twice the evidence of the next. On MIPS, the
calls also show the base, because a `jal` holds its target: at the right
base most targets land on a function start. Where the two disagree,
`hereticus` gives no base. `--find-base` lists the evidence, `--base
auto` takes the base, and each base that `--base` gives is checked
against it.

Limits: small position-independent code holds too few full addresses, so
nothing shows its base. A base that is wrong by megabytes looks the same
as no evidence when it is checked, but `--find-base` still finds the
right one.

Code: [`rank_bases`, `check_base` and `suggest_base`][raw]. See
`RESEARCH.md`, A17 and entry 20.

## Finding Functions

A binary with symbols names its functions. A stripped binary does not, so
`hereticus` finds them from the code and from what the linker left. It
uses these sources, the strongest first:

1. **The dynamic symbols.** A shared library keeps them after stripping,
   because the loader links through them.
2. **The unwind tables.** `.ARM.exidx` and `.eh_frame` give the start of
   each function, and `.eh_frame` gives its end too. They stay after
   stripping, because the unwinder needs them at run time.
3. **Call targets.** A call goes to the start of a function. A slot of the
   GOT that a call goes through holds the start of one.
4. **The code after a return, and prologues.** Code after the end of a
   function usually starts a new one. This source is the weakest, so it
   fills only the gaps that the others leave.

Not every return ends a function, because most functions return from more
than one place. A return that a branch jumps across is in the function.
A prologue starts a function, whatever comes before it.

`--functions` lists what this step finds. The Ghidra extension uses it to
make the functions that Ghidra misses.

Limits: where the first two sources are missing, the result is a guess. A
function that nothing calls, and that starts with no prologue, can join
the function before it. A stripped binary that mixes A32 and Thumb-2, or
MIPS32 and MIPS16e, is read in one instruction set.

Code: [`recover_functions`][scan]. See `RESEARCH.md`, A16. Papers: Nucleus
(EuroS&P 2017) and FETCH (DSN 2021).

## Normalizing

Two builds of one function differ in what the compiler can choose: which
register holds a value, where a spill goes in the frame, and to which
address a branch goes. These differences do not change what the code
does. Normalizing removes them, and keeps the operation and the kind of
each operand:

| Kept                                      | Removed                         |
|-------------------------------------------|---------------------------------|
| The operation, as `add` or `load`         | The register numbers            |
| The kind of each operand                  | The branch targets              |
| The kind of control flow                  | The constants that are addresses |
| The size of a constant: zero, small, wide | The instructions of the stack frame |

Spellings of one operation become one: `add`, `adds` and `addu` are all
an add. The instructions that only make and remove the stack frame go,
because they are the largest difference between two builds.

A constant is an address when it falls in the memory of the binary. An
address changes each time the linker moves what it points to, so it is
removed, as a branch target is. The other constants stay with each
instruction. The pairing does not compare them, but the report does.

For example, `classify` of `fixtures/src/basic.c`, built at `-O2`:

<!-- output: --diff classify fixtures/build/O2/basic.o fixtures/build/O1/basic.o -->
```console
$ hereticus --diff classify O2/basic.o O1/basic.o
classify
  cmp r0, 0x0
  mvnmi r0, 0x0
  bxmi lr
  moveq r0, 0x0
  bxeq lr
  mov r1, r0
  mov r0, 0x2
  cmp r1, 0x64
  movlt r0, 0x1
  bx lr
```
<!-- end output -->

And built at `-O1`:

<!-- output: --diff classify fixtures/build/O1/basic.o fixtures/build/O2/basic.o -->
```console
$ hereticus --diff classify O1/basic.o O2/basic.o
classify
  cmp r0, 0x0
  mvnmi r0, 0x0
  bxmi lr
  moveq r0, 0x0
  bxeq lr
  mov r1, r0
  mov r0, 0x2
  cmp r1, 0x64
  movlo r0, 0x1
  bx lr
```
<!-- end output -->

The bytes differ in one place: the `-O1` build tests `r1 < 100` with no
sign (`movlo`), and the `-O2` build with a sign (`movlt`). The code before
it returns when `r0` is negative, so the two do the same. Normalizing does
not keep the condition of a conditional move, so the two bodies are equal,
and the pair is `identical shape`:

<!-- output: --all --format markdown fixtures/build/O2/basic.o fixtures/build/O1/basic.o -->
```text
| `classify`        | same      | 1.00  | -      | -                                | identical shape |
```
<!-- end output -->

Limits: normalizing makes `-O1`, `-O2` and `-Os` builds alike. It does not
make an `-O0` build like an optimized one, because at `-O2` the compiler
uses a different algorithm. And, as above, a fix that changes only the
condition of a conditional move shows as no change.

Code: [`normalize_body_in`][norm]. See `RESEARCH.md`, A2.

## Lifting to an IL

Each instruction lifts to a small IL: what it reads, writes and tests,
the same on each architecture. Thus `cbnz x8, L`, and `cmp x8, #0` with
`b.ne L`, read as one **guard**: "branch where `x8` is not zero". A
branch keeps its condition, either way round, because a compiler can
branch on the opposite condition and swap the code after it. `--view il`
shows the IL; see [The Diff of One Function](./examples.md#the-diff-of-one-function).

The IL also gives the **data-flow features** of a function. Each value is
hashed with the operation that makes it and with the values that the
operation reads, for two rounds. This is the main idea of Ghidra BSim,
and it is a Weisfeiler-Lehman hash of the data-flow graph. When the
compiler writes one operation with different instructions, these features
can still agree.

Limits: the IL has no full semantics. It does not say what value an
instruction computes. That keeps it fast: a whole kernel lifts in seconds.

Code: [`Lifted`, `find_guards` and `flow_features`][il]. See `RESEARCH.md`,
A9 and A15.

## Pairing Functions

The pairing is a cascade of stages. Each stage pairs the functions it is
sure of, and leaves the others to the next stage. The stages go from the
most reliable to the least, so a weak stage cannot change a pair that a
strong stage made. BinDiff and Ghidra Version Tracking work in the same
way. The first stages are hashes, and their time is linear. Only the
functions that they leave go to the similarity stage, which compares each
pair.

The `MATCHED BY` column of the report names the stage that made each
pair. The stages, in the order they run:

| Stage | Pairs two functions where | `MATCHED BY` | Also in |
|-------|---------------------------|--------------|---------|
| Stubs by import | Two stubs jump to the same import | `same import` | |
| Identical code | Their bytes are the same | `identical bytes` | BinDiff *hash matching* |
| Identical shape | Their normalized bodies are the same | `identical shape` | Ghidra *Exact Function Instructions Match* |
| Names | Their symbols have the same name, unless `--ignore-names` | `same name` | BinDiff *name hash matching* |
| Twins by their row | A text in the record of the data beside a twin names it, as the name of an option | `twin, by the text in its row` | |
| Twins by their class | A twin fills the same slot of the vtable of the same class, by the name that its type information keeps | `twin, by the class of its vtable` | |
| Twins in order | Equal groups of twins sit in the same order | `twin, in order` | BinDiff *address sequence* |
| Stubs in order | The stubs align as two ordered lists, with the calls of the pairs as votes | `same callers` | |
| Twins by what they reach | One constant, callee or text tells a twin from the others | `identical shape` | Diaphora *Same constants* |
| Similarity | Their score is the best, and no rival comes near it | `similar` | BinDiff *prime signature matching* |
| Tables | They have the same slot in two tables of function pointers, as two vtables | `same slot of a table` | |
| Unique references | Each is the only function of its binary that holds one text, constant or call to an import | `same references` | BinDiff *call graph propagation* |
| Callers | The calls of the pairs vote that they are one function | `same callers` | BinDiff *call graph expansion* |
| Context | Their callers, callees and texts agree, and their code is close enough | `same callers`, or `similar` where a pair by similarity moves | |
| Layout | They sit between the same two pairs, in the same order | `same place` | BinDiff *address sequence*; synteny in genomics |
| Moved code | One is a wrapper that kept the place of the other, and the wrapper with its new callee matches better than the callee alone, or the wrapper is at most 3 instructions and calls only that callee; or the reverse, for a callee inlined into its caller | the stage that paired the callee | O2NMatcher and N2NMatcher, *1-to-n* matching |

Some stages run again, after a later stage pairs more functions.

A release often moves the body of a function into a new helper, and
leaves a wrapper with the old name. The code of the old function then
matches the helper, not the wrapper. The moved-code stage reads the
wrapper and the helper as one function, so the report shows the old
function as changed and the helper as new. That is what the source did.
Where the whole body moved, the wrapper adds too little to show. A
wrapper of at most 3 instructions that calls only the helper then takes
the place of the old function, if it shares a paired caller with it, or
if neither has a caller.

At the end, `hereticus` undoes a weak pair when no caller or callee of it
agrees, or when the other pairs join its two source files elsewhere. Such
a pair is often a deleted function that paired with a new function of
similar code. A stripped binary has no source files, so `hereticus`
guesses them: a compiler emits the functions of one file together, and
they call each other and share texts. BCD splits a binary into its files
by the same edges. With these checks, over the OpenWrt kernels,
0.69%<!-- from truth_kernels: all / wrong% --> of the pairs are wrong
against the debug symbols, and
1.77%<!-- from truth_kernels: 21.02.7/22.03.2 / wrong% --> across the
largest kernel upgrade.

### The Similarity Score

The `SCORE` of two functions is the Jaccard similarity of their normalized
bodies, as multisets: the count of shared instructions divided by the
count of all. The order of the instructions does not count, because a
compiler can change it. A body of `add, load, load` and a body of
`add, load, store` share two instructions of four in all, so they score
0.5. A pair pairs where its score is `--threshold` or more.

The pairs go best first, in two passes. The first pass takes only close
pairs. Their callees then help the second pass to choose. Three things
change the order of the candidates of a function, but not its score:

- **References.** The callees and the texts that the two functions share.
- **Constants.** The constants that the two functions share. A constant
  comes from the source, so another build keeps it.
- **Data flow.** A pair under the threshold still pairs where its
  data-flow features agree.

A pair does not go where a free rival scores almost as high. The code
cannot choose between the two, so a later stage chooses by place,
references or callers. This is the ratio test of image matching.

Limits: a small function has many twins, and its code alone cannot tell
them apart. Thus the stages after the similarity stage use what is around
a function: its callers, its callees, its texts and its place.

Code: [`cascade.rs`][cascade] and [`score.rs`][score]. See `RESEARCH.md`,
A1 to A10, and entries 1, 7, 13, 14, 15, 16, 17, 19 and 21. The moved code and the
source files are in [`moved.rs`][moved] and [`files.rs`][files].

### Gone and New Functions

A function with no pair is `gone` or `new`. It names its closest
candidate, where the score is `--near-miss` or more, and the unpaired
function in the same place. A place is a hint, not a pair. See
[Gone and New Functions](./usage.md#gone-and-new-functions).

See `RESEARCH.md`, A14.

## What Changed

A pair that matched can still differ. `hereticus` gives each pair one of
these kinds, which the `CHANGE` column shows:

| Kind | The pair |
|------|----------|
| No change | Has the same code, or differs only in what normalizing removes |
| Reordered | Has the same instructions in a different order |
| Data | Looks like data, not code, and its bytes differ |
| Changed values | Has the same instructions with different constants or texts |
| Unreadable bytes | Differs in bytes that the decoder cannot read |
| Changed code | Has different instructions |

The two bodies align as a longest common subsequence, as `diff` aligns
lines. The alignment gives the counts of the `+/-/~` column, and each
edit is a branch, a call, a jump, a memory access or other work, as the
`TOUCHED` column shows.

Normalizing hides each call target, so it also hides a call to a
different function. That is the most usual shape of a fix: `strcpy`
becomes `strlcpy`. Thus `hereticus` finds the callee of each call through
the PLT, the GOT, Mach-O stubs or relocations. When all the pairs are
known, it compares the callees of each pair. It compares the texts of
each pair in the same way. A path that differs only in a random build
directory is the same text.

Two shapes of a fix get their own mark:

- **A call changed to its bounded form**, as `sprintf` to `snprintf`.
  This fix adds only the instruction that loads the limit.
- **A check before an early exit.** The edit adds a conditional branch,
  and one way out of it leaves the function in a few instructions.
  SPIDER (IEEE S&P 2020) calls such a patch safe.

Code: [`change.rs`][change], [`bounded.rs`][bounded], [`exits.rs`][exits],
and `Cascade::compare_callees` and `Cascade::compare_texts` in
[`cascade.rs`][cascade]. See `RESEARCH.md`, A11 to A13.

## Sorting the Report

A fix usually adds code, so by default the pair with the most added
instructions comes first. A check before an early exit counts as more
added instructions. A call changed to its bounded form comes first of all.

`--sort rare` gives more weight to an addition that few other functions
share. A fix adds its own code, but another compiler or flag adds the
same code to many functions. This is the inverse document frequency of
information retrieval. On average it does not rank fixes higher than the
default, so it is not the default.

Code: `Sort` in [`main.rs`][main]. See `RESEARCH.md`, entry 6.

## How the Methods Are Measured

A method stays only when a measurement shows that it helps. The tests
compare stripped builds with the symbols of the same builds, which give
the right pairs:

- **Backports.** zlib, Lua, tinyxml2 and smallvec, each built in two ways,
  with one upstream fix between them.
- **Published fixes.** The fixes of
  [Real-Life Examples](./real-life-examples.md).
- **Ubuntu security updates.** Each two releases of a C library in a row,
  with the `-dbgsym` packages as the symbols.
- **OpenWrt kernels.** Kernels of each release, with their symbols.

Each measurement counts the right pairs and the wrong pairs, and the row
of each fix in the report. `RESEARCH.md` records each result, and also
the methods that did not help.

[unpack]: https://github.com/wc0x2b/hereticus/blob/master/crates/hereticus-unpack/src/lib.rs
[raw]: https://github.com/wc0x2b/hereticus/blob/master/crates/hereticus-recovery/src/raw.rs
[scan]: https://github.com/wc0x2b/hereticus/blob/master/crates/hereticus-recovery/src/scan.rs
[norm]: https://github.com/wc0x2b/hereticus/blob/master/crates/hereticus-match/src/norm.rs
[il]: https://github.com/wc0x2b/hereticus/blob/master/crates/hereticus-il/src/lib.rs
[cascade]: https://github.com/wc0x2b/hereticus/blob/master/crates/hereticus-match/src/matching/cascade.rs
[score]: https://github.com/wc0x2b/hereticus/blob/master/crates/hereticus-match/src/matching/score.rs
[moved]: https://github.com/wc0x2b/hereticus/blob/master/crates/hereticus-match/src/matching/moved.rs
[files]: https://github.com/wc0x2b/hereticus/blob/master/crates/hereticus-match/src/matching/files.rs
[change]: https://github.com/wc0x2b/hereticus/blob/master/crates/hereticus-match/src/matching/change.rs
[bounded]: https://github.com/wc0x2b/hereticus/blob/master/crates/hereticus-match/src/matching/bounded.rs
[exits]: https://github.com/wc0x2b/hereticus/blob/master/crates/hereticus-match/src/matching/exits.rs
[main]: https://github.com/wc0x2b/hereticus/blob/master/hereticus-cli/src/main.rs
