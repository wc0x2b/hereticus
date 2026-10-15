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
$ hereticus --diff-all before.elf after.elf         # the diff of every changed function
$ hereticus --view il --diff array_max a.elf b.elf  # the diff as IL statements
$ hereticus --tui before.elf after.elf              # browse, sort and open diffs in the terminal
$ hereticus --ignore-names before.elf after.elf     # match from the code alone
$ hereticus --format markdown before.elf after.elf  # a table to paste into a document
$ hereticus --format json before.elf after.elf      # for another tool to read
$ hereticus --raw --base 0x08000000 v1.bin v2.bin   # a flash dump, no ELF header
$ hereticus --raw --arch mips32 --unpack stub a.bin b.bin  # the decompressor in two firmware images
```

For real fixes found with `hereticus`, such as the iOS kernel fix for
CVE-2024-23265 and the OpenWrt fixes of `ubusd`, `dropbear`, `uhttpd`,
`odhcpd` and the `ltq-ptm` kernel module, see
[real-life-reports](real-life-reports).

Two OpenWrt releases for the same device, 22.03.2 and 22.03.5 for the Netgear
EX6100v2. The ARM decompressor stub is 15 KB of shipped code with no symbols,
and 43 of its 15,351 bytes changed:

```console
$ hereticus --format markdown --raw --base 0x80208000 stub-22.03.2.bin stub-22.03.5.bin
```

| FUNCTION       | CHANGE         | SCORE | +/-/~ | TOUCHED | MATCHED BY |
|----------------|----------------|-------|-------|---------|------------|
| `sub_80208000` | changed        | 0.98  | 1/1/1 | -       | similar    |
| `sub_8020a338` | changed        | 0.94  | 0/0/1 | -       | similar    |
| `sub_80208af8` | changed        | 0.95  | 0/0/1 | -       | similar    |
| `sub_80208a18` | changed        | 0.96  | 0/0/1 | -       | similar    |
| `sub_80209154` | changed        | 0.96  | 0/0/1 | 1 mem   | similar    |
| `sub_8020b1f8` | changed        | 0.98  | 0/0/1 | -       | similar    |
| `sub_80208e08` | changed unread | 0.98  | 0/0/1 | -       | similar    |
| `sub_8020a3bc` | changed        | 1.00  | 0/0/1 | -       | similar    |

67 matched (57 unchanged, 10 changed), 0 gone, 0 new

1 changed only a constant, hidden. Use --show-retouched to list them.

1 data region changed, hidden. Use --show-data to list them.

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

Two versions of one firmware, built the same way, one release apart:

```console
$ hereticus --format markdown --show-retouched fw-v1.elf fw-v2.elf
```

| FUNCTION          | CHANGE         | SCORE | +/-/~   | TOUCHED                                            | MATCHED BY      |
|-------------------|----------------|-------|---------|----------------------------------------------------|-----------------|
| `dispatch`        | changed        | 0.62  | 21/11/5 | 4 branch, 1 call, 6 jump, 6 mem, 1 const           | same name       |
| `check_header`    | changed        | 0.31  | 8/1/0   | 1 branch, 1 call, 1 mem                            | same name       |
| `handle`          | changed        | 0.76  | 8/4/4   | 1 branch, 1 call, 1 jump, 1 mem, 1 const, 2 unread | same name       |
| `validate_length` | changed values | 1.00  | -       | -                                                  | identical shape |

The `1 call` on `check_header` is an added call to an authentication routine.
The `1 const` on `handle` is a bound that moved from 1024 to 512, arriving
through inlining: that function was never edited. Both would otherwise read as
plain `changed`, and the constant is invisible to every other column, because
the edit around it is far too large to read as `changed values`.

Run it with `just run`, or `just run O0` to see how much the optimizer moves
the counts.

A function with no pair is listed after the table as `gone` or `new`. It names
its closest candidate on the other side, with the score, where the score is
`--near-miss` or more. It also names the unpaired function that sits in the
same place, between the same two pairs. A fix can rewrite a function so much
that no score pairs it, or split it in two; its place still shows where it
went. Zlib built for ARM at `-O1` and then `-O2`, stripped:

```text
inflateInit_: gone, same place as inflateInit_
inflate_table: gone, closest inflate_table at 0.57, same place as inflate_table
```

A place is a hint and not a pair: over the backports, 61% of them are right.

To see what changed inside one function:

```console
$ hereticus --diff mul_by_constant before.elf after.elf
mul_by_constant
- mov r1, 0x25
+ mov r1, 0x29
  mul r0, r0, r1
  bx lr
```

`--view il` shows each instruction as the IL reads it, the same on every
architecture, and a branch with the compare it tests, as
`if (w0 <= 0) goto $-0x40`:

```console
$ hereticus --view il --diff mul_by_constant before.elf after.elf
mul_by_constant
- r1 = 0x25
+ r1 = 0x29
  r0 = r0 * r1
  return
```

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
      --diff-all               Show the instruction-level diff of every changed function, then stop
      --tui                    Browse the report in the terminal, and change its order, its filters and the diff it shows without a second run
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

## Crates
The `hereticus` crate re-exports the crates below. To use only one part,
depend on that crate. Each crate in the table needs only the crates in its
row.

| Crate                | Does                                      | Needs                                            |
|----------------------|-------------------------------------------|--------------------------------------------------|
| `hereticus-il`       | Decode machine code, and lift it to an IL | nothing                                          |
| `hereticus-memory`   | The address space of a binary             | nothing                                          |
| `hereticus-unpack`   | Unpack firmware archives                  | nothing                                          |
| `hereticus-recovery` | Find functions in stripped binaries       | il, memory                                       |
| `hereticus-arch`     | The rules the matching reads              | il, memory, recovery                             |
| `hereticus-image`    | Read ELF, Mach-O and raw images           | arch, il, memory, recovery                       |
| `hereticus-callees`  | Find the callee of each call              | arch, il, image, memory, recovery                |
| `hereticus-view`     | Show code as instructions or as IL        | arch, callees, il, image, memory, recovery       |
| `hereticus-match`    | Compare the functions of two binaries     | arch, callees, il, image, memory, recovery, view |

## Development
All patches/merge requests are welcome!

```
just quick-test   # about five seconds
just test         # the same, plus slow tests
just fixtures     # rebuild the ARM32, MIPS and Mach-O corpus
```

## License
MIT or Apache-2.0, at your option.
</content>
