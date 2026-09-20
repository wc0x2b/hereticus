# heresy
[<img alt="github" src="https://img.shields.io/badge/github-wc0x2b/heresy-8da0cb?style=for-the-badge&labelColor=555555&logo=github" height="20">](https://github.com/wc0x2b/heresy)
[<img alt="crates.io" src="https://img.shields.io/crates/v/heresy-cli.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/heresy-cli)
[<img alt="build status" src="https://img.shields.io/github/actions/workflow/status/wc0x2b/heresy/main.yml?branch=master&style=for-the-badge" height="20">](https://github.com/wc0x2b/heresy/actions?query=branch%3Amaster)

> [!NOTE]
> Written heavily with the assistance of AI.

Compare two versions of an ARM32 binary and find the functions that changed.

* **No symbols needed**: a stripped firmware image gives the same answer as an object file, because functions are matched from their code.
* **No IDA or Ghidra**: one command line tool, no framework to install.
* **No container needed**: `--raw` reads a flash dump that has no ELF header.

## Installation
Either build from published source in crates.io.
```
$ cargo install heresy-cli --locked
```

Or download from [github releases](https://github.com/wc0x2b/heresy/releases).

## Example
```console
$ heresy before.o after.o                        # what changed
$ heresy --all before.o after.o                  # every function
$ heresy --diff array_max before.o after.o       # the diff of one function
$ heresy --ignore-names before.o after.o         # match from the code alone
$ heresy --raw --base 0x08000000 v1.bin v2.bin   # a flash dump, no ELF header
```

Two OpenWrt releases for the same device, 22.03.2 and 22.03.5 for the Netgear
EX6100v2. The ARM decompressor stub is 15 KB of shipped code with no symbols,
and 43 of its 15,120 bytes changed:

```console
$ heresy --raw --base 0x80208000 stub-22.03.2.bin stub-22.03.5.bin
╭──────────────┬────────────────┬───────┬───────┬────────────╮
│ FUNCTION     │ CHANGE         │ SCORE │ +/-/~ │ MATCHED BY │
├──────────────┼────────────────┼───────┼───────┼────────────┤
│ sub_8020a3bc │ changed        │  1.00 │ 0/0/1 │ similar    │
│ sub_8020b1f8 │ changed        │  0.98 │ 0/0/1 │ similar    │
│ sub_80208e20 │ changed unread │  0.98 │ 0/0/1 │ similar    │
╰──────────────┴────────────────┴───────┴───────┴────────────╯

62 matched (51 unchanged, 11 changed), 0 gone, 0 new
3 changed only a constant, hidden. Use --show-retouched to list them.
```

The `+/-/~` column counts the instructions the edit added, removed and rewrote.
A score of 1.00 with no instruction touched means only a constant changed, so
those are hidden by default.

To see what changed inside one function:

```console
$ heresy --diff mul_by_constant before.o after.o
mul_by_constant
- mov r1, 0x25
+ mov r1, 0x29
  mul r0, r0, r1
  bx lr
```

Exit status is 0 when nothing changed, 1 with `--exit-code` when something did,
and 2 when the input could not be read.

## Limits
* **ARM32 little-endian A32 only.** Thumb is not decoded, and a Thumb image
  reads as nonsense with no warning.
* **NEON is not decoded.** Those words stay opaque, so decoding continues but
  their content is not compared.
* **Unoptimized against optimized is out of scope.** At `-O2` the compiler
  changes the algorithm, which normalizing cannot bridge. Shipped firmware is
  built optimized.

## Usage
```console
Command line tool to compare functions between two binaries

Usage: heresy [OPTIONS] <BEFORE> <AFTER>

Arguments:
  <BEFORE>  The earlier binary
  <AFTER>   The later binary

Options:
  -a, --all                    Report every function, not only the ones that changed
      --diff <FUNCTION>        Show the instruction-level diff of one function, then stop
      --ignore-names           Ignore symbol names, as though both binaries were stripped
      --show-retouched         List functions that differ in nothing but a constant
      --threshold <THRESHOLD>  Lowest similarity that still counts as a match, from 0.0 to 1.0 [default: 0.65]
      --exit-code              Exit with a failure status when anything changed
      --near-miss <NEAR_MISS>  Lowest score at which an unmatched function names its closest candidate, from 0.0 to 1.0 [default: 0.25]
      --raw                    Read the inputs as raw code with no container format
      --base <BASE>            Address a raw image loads at, for example `0x08000000`
      --arch <ARCH>            Architecture of a raw image [default: arm32] [possible values: arm32]
      --format <FORMAT>        How to print the result [default: text] [possible values: text, compact]
      --sort <SORT>            How to order the changed functions. [default: confidence] [possible values: confidence, added, removed, modified]
      --progress <PROGRESS>    When to show a progress bar. [default: auto] [possible values: auto, always, never]
      --color <COLOR>          When to color the report. [default: auto] [possible values: auto, always, never]
  -h, --help                   Print help (see more with '--help')
  -V, --version                Print version
```

## Development
All patches/merge requests are welcome!

```
just quick-test   # about five seconds
just test         # the same, plus slow tests
just fixtures     # rebuild the ARM32 corpus
```

## License
MIT or Apache-2.0, at your option.
</content>
