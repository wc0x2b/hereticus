# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
