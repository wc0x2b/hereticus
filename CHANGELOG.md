# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [0.3.0](https://github.com/wc0x2b/hereticus/compare/v0.2.1...v0.3.0) - 2026-10-23### Added

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
