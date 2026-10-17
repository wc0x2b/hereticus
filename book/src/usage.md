# Usage

<!-- output: -h -->
```console
Command line tool to compare functions between two binaries

Usage: hereticus [OPTIONS] <BEFORE> [AFTER]

Arguments:
  <BEFORE>  The earlier binary, or with `--functions` the one binary to list
  [AFTER]   The later binary

Options:
  -a, --all                    Report every function, not only the ones that changed
      --diff <FUNCTION>        Show the instruction-level diff of one function, then stop
      --diff-all               Show the instruction-level diff of every changed function, then stop
      --tui                    Browse the report in the terminal, and change its order, its filters and the diff it shows without a second run
      --functions              List the functions of one binary, then stop
      --view <VIEW>            How `--diff`, `--diff-all` and `--tui` show each instruction [default: asm] [possible values: asm, il]
      --ignore-names           Ignore symbol names, as though both binaries were stripped
      --show-retouched         List functions that differ in nothing but a constant
      --show-data              List regions that look like data rather than code
      --threshold <THRESHOLD>  Lowest similarity that still counts as a match, from 0.0 to 1.0 [default: 0.65]
      --exit-code              Exit with a failure status when anything changed
      --near-miss <NEAR_MISS>  Lowest score at which an unmatched function names its closest candidate, from 0.0 to 1.0 [default: 0.25]
      --raw                    Read the inputs as raw code with no container format
      --base <BASE>            Address a raw image loads at, for example `0x08000000`
      --unpack <UNPACK>        Take one part out of each firmware image before reading it raw [possible values: stub, kernel]
      --arch <ARCH>            Architecture of a raw image [default: arm32] [possible values: arm32, thumb2, aarch64, mips32, mips32-be, mips16, mips16-be]
      --format <FORMAT>        How to print the result [default: text] [possible values: text, compact, markdown, json]
      --sort <SORT>            How to order the changed functions. [default: added] [possible values: confidence, added, removed, modified, rare]
      --progress <PROGRESS>    When to show a progress bar. [default: auto] [possible values: auto, always, never]
      --color <COLOR>          When to color the report. [default: auto] [possible values: auto, always, never]
  -h, --help                   Print help (see more with '--help')
  -V, --version                Print version
```
<!-- end output -->

## The Report

The `+/-/~` column counts the instructions the edit added, removed and rewrote.
A score of 1.00 with no instruction touched means only a constant changed, so
those are hidden by default. A changed text is the exception: a fix can change
only a format string, as `"%s"` to `"%.*s"`, so such a row stays visible.

The `TOUCHED` column names what kind of code the edit changed: branches, calls,
jumps, memory accesses, changed constants, changed texts the code points at,
and bytes the decoder cannot read. A text counts when it holds four or more
printable bytes after a NUL, because a shorter one can be a pointer or a
number by chance.
Plain data instructions are left out, because they are the bulk of any rewrite
and name nothing to act on. The column also stays quiet where it would only
repeat the `CHANGE` word beside it, so a row of `changed values` shows a dash
rather than `1 const`.

## Gone and New Functions

A function with no pair is listed after the table as `gone` or `new`. It names
its closest candidate on the other side, with the score, where the score is
`--near-miss` or more. It also names the unpaired function that sits in the
same place, between the same two pairs. A fix can rewrite a function so much
that no score pairs it, or split it in two; its place still shows where it
went. Zlib built for ARM at `-O1` and then `-O2`, stripped:

<!-- output: --ignore-names fixtures/build/backports/zlib-before/arm-O1/lib-stripped.so fixtures/build/backports/zlib-after/arm-O2/lib-stripped.so -->
```text
inflateInit_: gone, same place as inflateInit_
inflate_table: gone, closest inflate_table at 0.57, same place as inflate_table
```
<!-- end output -->

A place is a hint and not a pair: over the backports,
61%<!-- from cross_build: all / right% --> of them are right.

## Terminal Interface

`--tui` compares the two binaries once, then shows the report as a table to
browse, with the functions gone and new after the pairs. `s` changes the
order and `S` reverses it, `t` lists only the pairs that touched one kind of
code, `a`, `r` and `d` show every function, the retouched pairs and the data
regions, and `/` filters on the names, with the letters in order. `Enter`, or
a second click, opens the diff side by side, with the address of each
instruction: `]` and `[` go to the next and the previous change, `v` changes
between assembly and IL, `l` changes to one column, and `n` and `p` go to the
next and the previous function. `?` shows every key.

Exit status is 0 when nothing changed, 1 with `--exit-code` when something did,
and 2 when the input could not be read.

## Listing Functions

`--functions` reads one binary, lists the functions it finds, and compares
nothing. Each row gives the address, the size in bytes, the instruction set,
and whether the function holds code or data. `--raw`, `--base`, `--arch` and
`--unpack` read the binary as they do for a comparison.

<!-- output: --functions fixtures/build/O2/basic.o -->
```console
╭─────────┬──────┬───────┬───────┬─────────────────╮
│ ADDRESS │ SIZE │ ISA   │ HOLDS │ FUNCTION        │
├─────────┼──────┼───────┼───────┼─────────────────┤
│ 0x0     │    8 │ arm32 │ code  │ add             │
│ 0x8     │   12 │ arm32 │ code  │ mul_by_constant │
│ 0x14    │   40 │ arm32 │ code  │ sum_to          │
│ 0x3c    │   40 │ arm32 │ code  │ classify        │
│ 0x64    │   28 │ arm32 │ code  │ switch_dense    │
│ 0x80    │   16 │ arm32 │ code  │ call_chain      │
│ 0x90    │  144 │ arm32 │ code  │ array_max       │
│ 0x120   │  144 │ arm32 │ code  │ factorial       │
╰─────────┴──────┴───────┴───────┴─────────────────╯
```
<!-- end output -->

`--format json` gives the same list to another tool, as a Ghidra script that
makes a function at each address Ghidra missed. Each address is the one the
binary is linked at. A tool that loads the binary at another base must move
each address by the difference.

## Limits
* **Little-endian A32 (ARMv5TE and later), Thumb-2 (Cortex-M too) and
  AArch64, and MIPS32 and MIPS16e in either byte order.** A library that
  mixes A32 and Thumb-2, or MIPS32 and MIPS16e, is read function by function
  where its symbols say which set each is in. Stripped or raw, it is read in
  one set, so its minority reads as nonsense.
* **ELF, raw images, and AArch64 Mach-O.** An ELF file that `sstrip` left
  with no section headers, as OpenWrt ships each binary, is read through
  its segments. A Mach-O file is read as macOS
  and iOS ship it, arm64 or arm64e, stripped or not, and a universal binary
  as its AArch64 slice. A kernelcache of iOS 15 and later is read kext by
  kext. The dyld shared cache and 32-bit Mach-O are not read.
* **NEON data processing is not decoded.** NEON loads and stores are read.
  The other NEON words stay opaque, named `(neon)`: decoding continues, and
  an edit to one shows, but not what it changed.
* **Unoptimized against optimized is out of scope.** At `-O2` the compiler
  changes the algorithm, which normalizing cannot bridge. Shipped firmware is
  built optimized.
