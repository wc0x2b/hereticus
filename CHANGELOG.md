# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0](https://github.com/wc0x2b/hereticus/compare/v0.5.0...v0.6.0) - 2026-10-27

### Added

- `hereticus` reads stripped Windows PE files for x86-64, 32-bit x86 and
  ARM64. A stripped DLL keeps the names of its exports and of its
  imports: each thunk that jumps through a slot of the import address
  table, or of the delay-load directory, takes the name of its import, or
  the DLL and the ordinal, as `host.dll#1`. On x86-64 and ARM64 the
  exception directory, `.pdata`, gives the start and the length of each
  function that changes the stack, and the scan finds the leaf functions
  between them. The entry point of an executable starts a function. On
  the fixtures, a stripped DLL gives the same functions as the DLL with
  its symbols. A COFF symbol gives no size, so a PE file with symbols is
  scanned too, with each symbol as the start and the name of a function.
  A symbol of 32-bit Windows drops the decoration of its calling
  convention, as `_send@16` reads as `send`.
- Test fixtures an obfuscator rewrote, built by an LLVM pass plugin in
  `fixtures/obfuscate`: one with its control flow flattened, one with
  bogus flow behind an opaque predicate, and one with its constants hidden
  behind opaque expressions. The machine code shares few instructions with
  the plain code, yet `hereticus` still pairs each function with the one it
  came from.
- The IL view indents each statement two spaces for each jump that it is
  in, in the browser and in `--diff`. A forward jump indents the lines it
  steps over, up to the first line that another path also comes into, so
  an error path that the compiler moves after the return indents only the
  lines before it comes back. A backward jump indents the body of its loop,
  where the target of the jump can run again.
- The diff draws a line from each jump, marked `<`, to its target, marked
  `>`, at the left of the code, in the browser and in `--diff`. The line
  of a jump that a change added or removed takes the color of the change.
  Four lines can pass one row, or as many as the jumps of a change need,
  up to eight. Where more pass, the jumps of a change are drawn first and
  then the shortest.
- A removed or added IL line in a block of at least three lines that the
  other side holds in another place prints in gray, in the browser and in
  `--diff`, as `git diff --color-moved` shows one. The compiler moved the
  code. A block with a branch, a call or a return stays red and green,
  as a fix can move a check before the use it guards.

### Changed

- The IL diff shows a statement that only names other registers as the
  same line, also where the runs of removed and added lines differ in
  length. One more register in use moved such statements, so a whole
  block showed as removed and added. Two names are one register only where
  they hold values of one width, and where the renaming is one to one and
  keeps each register that the lines around it name alike.
- The IL view shows no line for padding that does nothing: `nop`,
  `xchg ax, ax` and `mov r0, r0`. A trap that pads, as `int3`, still shows.
- In the IL view, a branch on the carry after an add reads as
  `if (carry)`, as `add eax, edx` then `jb` tests that the sum overflowed,
  and after a subtract as `if (borrow)`. A branch on the signed overflow
  after either reads as `if (overflow)`. A branch after a shift by a
  constant that is not 0 tests its result, as `lsls r3, r2, #26` then
  `bmi` reads `if (r3 < 0)`.
- The IL diff aligns a slot of the stack of x86, at `[rsp + …]` or
  `[esp + …]`, as one kind, as it does for the other architectures, so a
  frame that grew no longer shows each access to it as removed and added.
- The IL diff shows no statement as the same line where, under a name
  that the other side does not read, it reads a value that an added or
  removed statement wrote: it does other work on another value.
- A comparison of a large binary, as an iPhone kernel, is faster. Three
  stages looked through every function or pair of the binary for each
  one, and now each looks only at those that can take part. The pairs are
  the same.

### Fixed

- In the IL view, a branch after an operation that writes the flags named
  the last compare before it. A branch after `sub rdi, 1` or
  `subs r1, r1, #1` now tests the result, as `if (rdi != 0)`, and a branch
  after a shift or a multiply tests only the flags.
- A 16-bit Thumb instruction inside an `it` block keeps the flags, but the
  IL read it as one that sets them.
- The IL diff showed a statement on registers of another width as the
  same line where the runs of removed and added lines were as long, as
  `mul w10, w10, w8` against `mul x10, x10, x8`, where a product of 32
  bits became one of 64.

## [0.5.0](https://github.com/wc0x2b/hereticus/compare/v0.4.1...v0.5.0) - 2026-10-27

### Added

- `--only` lists only the changed pairs that have each feature it names,
  as `added-call`, `removed-call`, `added-branch` or `early-exit`. Each
  feature is read from the aligned instructions of the two bodies, so a
  call that takes the place of a load is an added call, and a direct call
  rewritten as a call through a register is neither added nor removed.
  The `f` key of the browser steps through the features, `--format json`
  gives the features of each pair, and the summary says how many rows
  `--only` hid. A project that an older version saved does not open.
- The table of functions in the browser has a `#` column with the rank of
  each function in the present order. The filters and the marks do not
  change the rank, so a filtered function shows its place in the full
  list.

### Changed

- Each column of the table of functions in the browser is as wide as its
  widest cell among the rows listed, and the names take the width left.
  Before, the columns had fixed widths, which cut the kinds touched and
  how a pair matched. In a narrow terminal, the kinds touched and how a
  pair matched shrink first, and a cell cut short ends in `…`.
- `m` in the browser marks a function with no label, and `m` again removes
  the mark. `M` asks for the label. Before, `m` asked for the label and
  `M` removed the mark.

## [0.4.1](https://github.com/wc0x2b/hereticus/compare/v0.4.0...v0.4.1) - 2026-10-25

## [0.4.0](https://github.com/wc0x2b/hereticus/compare/v0.3.0...v0.4.0) - 2026-10-24
### Added

- The Ghidra extension has a loader, *Raw Binary (Hereticus Base)*. It is
  the *Raw Binary* loader of Ghidra, but its default *Base Address* is the
  base that `hereticus --find-base` finds for the language of the import.
  Before, a raw image went to 0 unless the user typed the base.
- Pair C++ twins by the class of their vtable. A vtable points to the
  type information of its class, which keeps the name of the class after
  stripping, so template copies and destructors with the same
  instructions pair by the class and slot that each fills. `MATCHED BY`
  names such a pair `twin, by the class of its vtable`, and the Ghidra
  extension gives it a confidence between the two other kinds of twin.
  Over the versions of Assemblage-DeepHistory, 78,358 more pairs are
  right and 15,805 fewer wrong (`RESEARCH.md`, entry 21).
- Unpack a zImage whose kernel is gzip or zstd, and an xz kernel
  filtered for x86, PowerPC, Thumb-2, AArch64 or SPARC, or with a start
  offset. Before, `--unpack` read only an xz kernel filtered for A32.
- Read the jump tables of x86 code that is not PIC, as
  `jmp qword ptr [8*rax + table]`, whose entries are whole addresses.
  Before, the scan cut such code at the return of each case. Over the
  releases of zlib and Lua built so for x86-64 and i686 with no unwind
  tables, the scan of a raw image invents 8 starts in place of 305.
- Read ARM big endian, BE8: a big-endian ARM file reads as such, and
  `--arch arm32-be8` and `thumb2-be8` read a raw image. The instructions
  of BE8 are little endian and its data big endian: the literal pools, the
  unwind index, the jump tables and every pointer. Before, the data read
  little endian, and over the releases built so, 18 pairs were wrong
  stripped and 29 raw, now 6 and 6, as little endian gives. The Ghidra
  extension reads a BE8 program too.

### Changed

- Find the vtables and the tables of handlers of a shared library for
  x86 and x86-64. Each word that an absolute relocation fills read as
  zero, so the tables of each exported class were not found: on tinyxml2
  for x86-64, 1 table in place of 15.
- Split the PLT of a stripped ARM or Thumb-2 library into its entries.
  Each stub is a function with the name of its import, as `malloc@plt`,
  in the instruction set it is in: A32, or T32 where GNU `ld` puts the
  prefix that switches to A32 before it. Before, the scan found the full
  PLT as one function, and in a Thumb-2 library it read the A32 stubs as
  T32. A raw image has no sections, so the scan finds each PLT there by
  the shape of its stubs. In a raw Thumb-2 image, it cut the prefix of a
  stub into two functions and some stubs into two.
- Pair a PLT stub only with the stub of its import, also when names are
  off. Before, the stubs of a comparison without names paired in order,
  so a new import moved each stub after it onto the stub of a different
  import: over the releases of `tests/versions.rs`, 435 such pairs
  stripped and 1540 raw, now 5 and 5. Stubs also do not count toward
  the order of the code, because the linker puts the PLT before the code
  or after it. Across clang and GCC, 13 more pairs are right and 1 more
  is wrong.

## [0.3.0](https://github.com/wc0x2b/hereticus/compare/v0.2.1...v0.3.0) - 2026-10-23
### Added

- Save a comparison as a project, and open it again with no second match.
  `--save <PROJECT>` makes one from the command line, and `w` makes one
  in the browser. `--open <PROJECT>` gives the report that a new run on
  the two binaries gives, with the same flags. A project names each
  binary by its full path and a SHA-256 hash, and does not open when a
  binary moved or changed. See "Marks and Projects" in the book.
- Mark a function in the browser with `m`, and give it a label, as
  `auth bypass`. A marked function goes to the top, as
  `◆ handle [auth bypass]`, also when a filter would hide it. The project
  keeps the marks and the state of the browser, so `--tui --open` opens
  as you left it.
- Each report of an opened project shows the marks. `--format compact`
  adds a last column to a marked line, `--format json` adds `"mark"`, and
  `--diff` finds a function by its label.
- The crates `hereticus`, `hereticus-match` and `hereticus-memory` have a
  `serde` feature, which lets a caller save a `Diff` and read it again.
- `--find-base` finds where a raw image loads, on every architecture:
  ARM, Thumb-2, AArch64, MIPS and x86. It lists the bases with the most
  evidence, and gives the base where one stands out, by more than twice
  the next. `--base auto` takes that base. See "Find the Base" in the
  book.
- The base check warns on every architecture where the words of an image
  show a better base, not only on MIPS. The error for a missing `--base`
  names the base on every architecture too.

### Changed

- The base check of MIPS no longer reads a few words of data in
  position-independent code as calls, which made it warn at the right
  base.

## [0.2.1](https://github.com/wc0x2b/hereticus/compare/v0.2.0...v0.2.1) - 2026-10-21
### Added

- `research_bench --assemblage` counts each pair of names once per
  release too, so a library that a package links into many files counts
  once. `BENCH_WRONG=1` shows where the true partner of each wrong pair
  went.

### Changed

- Pair a function with the thin wrapper that took its place, where a
  release moved its whole body into a new function, as cJSON did with
  `cJSON_ParseWithOpts`. The new function now reads as new
  (`RESEARCH.md`, "Assemblage-DeepHistory: the wrong pairs a report
  shows").

## [0.2.0](https://github.com/wc0x2b/hereticus/compare/v0.1.2...v0.2.0) - 2026-10-20

### Added

- Pair a function by the text beside it in a table of the data, as the
  name of an option in `{"recv-size-max", get, set}`. Twins with the same
  instructions that a release reordered now pair right, and the JSON and
  the Ghidra extension name the new stage `twin, by the text in its row`
  (`RESEARCH.md`, entry 19). Over 8,872 release pairs of
  Assemblage-DeepHistory, the wrong pairs fell by 5.5%.

### Changed

- Fewer wrong pairs across a kernel upgrade: over the OpenWrt kernels, the
  wrong pairs fell from 0.75% to 0.69%.

## [0.1.2](https://github.com/wc0x2b/hereticus/compare/v0.1.1...v0.1.2) - 2026-10-20

### Other

- Undo pairs across source files and pair moved code

### Added

- Pair a function whose code moved into a new callee with the wrapper that
  kept its place, and a callee inlined into its caller with that caller.
  The report then shows the old function as changed and the moved code as
  new, as the source did (`RESEARCH.md`, entry 17).
- Guess the source files of a stripped binary from the address order, the
  calls and the shared texts, and undo a weak pair whose two files the other
  pairs join elsewhere (`RESEARCH.md`, entry 16).

### Changed

- Fewer wrong pairs across a kernel upgrade: over the OpenWrt kernels, the
  wrong pairs fell from 0.95% to 0.75% at this release. The Ubuntu updates
  and the backports built two ways pair more right and fewer wrong, and every
  published fix keeps its rank.
- On the MIPS kernel point releases, identical callers no longer report a
  changed callee where the callee kept its place as a wrapper.

### Fixed

- `just test` no longer stops when `ghidra/dist/` holds the zip of another
  Ghidra release, and `just release-assets` attaches only the zip of the
  pinned release.

## [0.1.1](https://github.com/wc0x2b/hereticus/compare/v0.1.0...v0.1.1) - 2026-10-19

### Other

- Add homepage, license files and readmes to the published crates
- Publish only src in hereticus and hereticus-cli
