# hereticus
[<img alt="github" src="https://img.shields.io/badge/github-wc0x2b/hereticus-8da0cb?style=for-the-badge&labelColor=555555&logo=github" height="20">](https://github.com/wc0x2b/hereticus)
[<img alt="crates.io" src="https://img.shields.io/crates/v/hereticus-cli.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/hereticus-cli)
[<img alt="build status" src="https://img.shields.io/github/actions/workflow/status/wc0x2b/hereticus/main.yml?branch=master&style=for-the-badge" height="20">](https://github.com/wc0x2b/hereticus/actions?query=branch%3Amaster)

> [!NOTE]
> Written heavily with the assistance of AI.

Compare two versions of a binary or firmware and find the functions that changed.

* **No IDA or Ghidra**: No frameworks and no GUIs. Great for programmers and agents alike.

## Installation
Either build from published source in crates.io.
```
$ cargo install hereticus-cli --locked
```

Or download from [github releases](https://github.com/wc0x2b/hereticus/releases).

## Example
```console
$ hereticus before.elf after.elf                    # what changed
$ hereticus --all before.elf after.elf              # every function
$ hereticus --diff array_max before.elf after.elf   # the diff of one function
$ hereticus --ignore-names before.elf after.elf     # match from the code alone
$ hereticus --raw --base 0x08000000 v1.bin v2.bin   # a flash dump, no ELF header
```

Two OpenWrt releases for the same device, 22.03.2 and 22.03.5 for the Netgear
EX6100v2. The ARM decompressor stub is 15 KB of shipped code with no symbols,
and 43 of its 15,351 bytes changed:

```console
$ hereticus --raw --base 0x80208000 stub-22.03.2.bin stub-22.03.5.bin
╭──────────────┬────────────────┬───────┬───────┬──────────┬────────────╮
│ FUNCTION     │ CHANGE         │ SCORE │ +/-/~ │ TOUCHED  │ MATCHED BY │
├──────────────┼────────────────┼───────┼───────┼──────────┼────────────┤
│ sub_8020a3bc │ changed        │  1.00 │ 0/0/1 │ -        │ similar    │
│ sub_8020b1fc │ changed        │  0.98 │ 0/0/1 │ -        │ similar    │
│ sub_80208e20 │ changed unread │  0.98 │ 0/0/1 │ -        │ similar    │
│ sub_80209154 │ changed        │  0.96 │ 0/0/1 │ 1 mem    │ similar    │
│ sub_80208b04 │ changed        │  0.94 │ 0/0/1 │ -        │ similar    │
│ sub_8020a338 │ changed        │  0.94 │ 0/0/1 │ -        │ similar    │
│ sub_802082bc │ changed        │  0.89 │ 1/1/1 │ 1 branch │ similar    │
│ sub_80208ab4 │ changed        │  0.87 │ 0/0/1 │ -        │ similar    │
╰──────────────┴────────────────┴───────┴───────┴──────────┴────────────╯

67 matched (56 unchanged, 11 changed), 0 gone, 0 new
3 changed only a constant, hidden. Use --show-retouched to list them.
```

The `+/-/~` column counts the instructions the edit added, removed and rewrote.
A score of 1.00 with no instruction touched means only a constant changed, so
those are hidden by default.

The `TOUCHED` column names what kind of code the edit changed: branches, calls,
jumps, memory accesses, changed constants and bytes the decoder cannot read.
Plain data instructions are left out, because they are the bulk of any rewrite
and name nothing to act on. The column also stays quiet where it would only
repeat the `CHANGE` word beside it, so a row of `changed values` shows a dash
rather than `1 const`.

Two versions of one firmware, built the same way, one release apart:

```console
$ hereticus --show-retouched fw-v1.elf fw-v2.elf
╭─────────────────┬────────────────┬───────┬─────────┬────────────────────────────────────────────────────┬─────────────────╮
│ FUNCTION        │ CHANGE         │ SCORE │ +/-/~   │ TOUCHED                                            │ MATCHED BY      │
├─────────────────┼────────────────┼───────┼─────────┼────────────────────────────────────────────────────┼─────────────────┤
│ validate_length │ changed values │  1.00 │ -       │ -                                                  │ identical shape │
│ handle          │ changed        │  0.70 │ 8/4/6   │ 1 branch, 1 call, 2 jump, 1 mem, 1 const, 3 unread │ same name       │
│ dispatch        │ changed        │  0.60 │ 21/11/5 │ 4 branch, 1 call, 7 jump, 5 mem, 1 const           │ same name       │
│ check_header    │ changed        │  0.31 │ 8/1/0   │ 1 call, 1 jump, 1 mem                              │ same name       │
╰─────────────────┴────────────────┴───────┴─────────┴────────────────────────────────────────────────────┴─────────────────╯
```

The `1 call` on `check_header` is an added call to an authentication routine.
The `1 const` on `handle` is a bound that moved from 1024 to 512, arriving
through inlining: that function was never edited. Both would otherwise read as
plain `changed`, and the constant is invisible to every other column, because
the edit around it is far too large to read as `changed values`.

Run it with `just run`, or `just run O0` to see how much the optimizer moves
the counts.

To see what changed inside one function:

```console
$ hereticus --diff mul_by_constant before.elf after.elf
mul_by_constant
- mov r1, 0x25
+ mov r1, 0x29
  mul r0, r0, r1
  bx lr
```

Exit status is 0 when nothing changed, 1 with `--exit-code` when something did,
and 2 when the input could not be read.

## Limits
* **ARM32 little-endian A32, and MIPS32 in either byte order.** Thumb is not
  decoded, and a Thumb image reads as nonsense with no warning.
* **NEON is not decoded.** Those words stay opaque, so decoding continues but
  their content is not compared.
* **Unoptimized against optimized is out of scope.** At `-O2` the compiler
  changes the algorithm, which normalizing cannot bridge. Shipped firmware is
  built optimized.

## Usage
```console
Command line tool to compare functions between two binaries

Usage: hereticus [OPTIONS] <BEFORE> <AFTER>

Arguments:
  <BEFORE>  The earlier binary
  <AFTER>   The later binary

Options:
  -a, --all                    Report every function, not only the ones that changed
      --diff <FUNCTION>        Show the instruction-level diff of one function, then stop
      --ignore-names           Ignore symbol names, as though both binaries were stripped
      --show-retouched         List functions that differ in nothing but a constant
      --show-data              List regions that look like data rather than code
      --threshold <THRESHOLD>  Lowest similarity that still counts as a match, from 0.0 to 1.0 [default: 0.65]
      --exit-code              Exit with a failure status when anything changed
      --near-miss <NEAR_MISS>  Lowest score at which an unmatched function names its closest candidate, from 0.0 to 1.0 [default: 0.25]
      --raw                    Read the inputs as raw code with no container format
      --base <BASE>            Address a raw image loads at, for example `0x08000000`
      --arch <ARCH>            Architecture of a raw image [default: arm32] [possible values: arm32, mips32, mips32-be]
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
just fixtures     # rebuild the ARM32 and MIPS corpus
```

## License
MIT or Apache-2.0, at your option.
</content>
