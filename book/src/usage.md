# Usage

## Compare Two Binaries

Give the earlier binary first, then the later one:

<!-- output: fixtures/build/O2/firmware.o fixtures/build/O2/firmware_v2.o -->
```console
$ hereticus fw-v1.elf fw-v2.elf
╭──────────────┬─────────┬───────┬─────────┬──────────────────────────────────────────┬────────────╮
│ FUNCTION     │ CHANGE  │ SCORE │ +/-/~   │ TOUCHED                                  │ MATCHED BY │
├──────────────┼─────────┼───────┼─────────┼──────────────────────────────────────────┼────────────┤
│ dispatch     │ changed │  0.62 │ 21/11/5 │ 4 branch, 1 call, 6 jump, 6 mem, 1 const │ same name  │
│ check_header │ changed │  0.31 │ 8/1/0   │ 1 branch, 1 call, 1 mem                  │ same name  │
│ handle       │ changed │  0.82 │ 8/4/2   │ 1 branch, 1 call, 1 jump, 1 mem, 1 const │ same name  │
╰──────────────┴─────────┴───────┴─────────┴──────────────────────────────────────────┴────────────╯

5 matched (1 unchanged, 4 changed), 0 gone, 0 new
1 changed only a constant, hidden. Use --show-retouched to list them.
```
<!-- end output -->

The report lists only the functions that changed, the most added code
first. `--all` lists every function.

## Read the Report

| Column | What it shows |
|--------|---------------|
| `FUNCTION` | The name of the function. A stripped function is `sub_<address>`, and `a -> b` gives its address in each binary. |
| `CHANGE` | The kind of change. See the table below. |
| `SCORE` | How alike the two functions are, from 0.00 to 1.00. See [The Similarity Score](./methods.md#the-similarity-score). |
| `+/-/~` | The instructions that the edit added, removed and rewrote. |
| `TOUCHED` | The kind of code that the edit changed. See the list below. |
| `MATCHED BY` | Why the two functions are a pair. See [Pairing Functions](./methods.md#pairing-functions). |

The `CHANGE` column has these words:

| Word | The pair | Shown |
|------|----------|-------|
| `changed` | Has different instructions | Yes |
| `reordered` | Has the same instructions in a different order | Yes |
| `changed unread` | Differs in bytes that the decoder cannot read | Yes |
| `changed values` | Has the same instructions, with other constants or texts | Only with `--show-retouched`, or where a text changed |
| `changed data` | Looks like data, not code, and its bytes differ | Only with `--show-data` |
| `same` | Has no change that a reader would see | Only with `--all` |

A fix can change only a format string, as `"%s"` to `"%.*s"`. Thus a row
of `changed values` stays visible where a text changed.

The `TOUCHED` column counts the edits of each kind:

- `branch`: a conditional branch.
- `call`: a call.
- `callee`: a call that stayed in place, but now goes to a different
  function, as `strcpy` to `strlcpy`.
- `jump`: a jump that is not a call.
- `mem`: a load or a store.
- `const`: a constant that changed.
- `text`: a text that the code points to, and that changed. A text counts
  when it holds four or more printable bytes after a NUL, because a
  shorter one can be a pointer or a number by chance.
- `unread`: bytes that the decoder cannot read.

Plain data instructions are left out, because they are the bulk of any
rewrite and name nothing to act on. The column also stays quiet where it
would only repeat the `CHANGE` word beside it, so a row of
`changed values` shows a dash rather than `1 const`.

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

## Look Inside a Function

`--diff <FUNCTION>` shows the diff of one function, and `--diff-all` shows
the diff of each changed function. `--view il` shows each instruction as
an IL statement that reads the same on each architecture. A stripped
function has the name that the report gives it, as `sub_7630`. See
[The Diff of One Function](./examples.md#the-diff-of-one-function).

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

## Stripped Binaries

A stripped binary needs no option. Where a binary has no symbols,
`hereticus` finds its functions from the code, and pairs them from the
code. A shared library keeps the names of the functions that it exports,
so those keep their names.

`--ignore-names` pairs from the code alone, also where both binaries have
symbols. Use it to see how a stripped build will pair.

## Raw Images and Firmware

A flash dump or a kernel image has no ELF header. Give `--raw`, the
architecture with `--arch`, and the address the image loads at with
`--base`:

```console
$ hereticus --raw --arch mips32 --base 0x80000000 v1.bin v2.bin
```

When you do not know the base, leave out `--base`. `hereticus` then stops,
and gives the base that the calls of the image show, where they show one:

<!-- output: --functions --raw --arch mips32 fixtures/build/openwrt/mipsel-mt300nv2-kernel-22.03.2.bin -->
```console
$ hereticus --functions --raw --arch mips32 kernel.bin
hereticus: --raw needs --base, because a raw image does not say where it loads. Its calls show that it loads at --base 0x80000000
```
<!-- end output -->

`hereticus` does not use that base by itself. A wrong base does not
fail: it gives a report against the wrong addresses, with no other sign.
Where the base that you give looks wrong, `hereticus` warns.

A firmware image holds the kernel compressed, often after a small
decompressor. `--unpack kernel` takes out the kernel, and `--unpack stub`
takes out the decompressor. A uImage gives the address its kernel loads
at, and an lzma-loader gives the address of its stub. There, `--base` is
not needed. For the other containers, give `--base`:

```console
$ hereticus --raw --arch mips32-be --unpack kernel uImage-v1.bin uImage-v2.bin
$ hereticus --raw --arch arm32 --base 0x80208000 --unpack stub zImage-v1 zImage-v2
```

## Output Formats

`--format` changes how the report prints:

- `text`: the table above, for a person. The default.
- `markdown`: the same table in Markdown, to paste into a document or an
  issue.
- `compact`: one line for each pair, with tabs between the columns and no
  header, for `grep`, `cut` and `awk`.
- `json`: one JSON object, for another tool.

The columns of `compact` are the change, the name before, the name after,
the score, and the counts of added, removed and rewritten instructions:

<!-- output: --format compact fixtures/build/O2/firmware.o fixtures/build/O2/firmware_v2.o -->
```console
$ hereticus --format compact fw-v1.elf fw-v2.elf
changed	dispatch	dispatch	0.62	21	11	5
changed	check_header	check_header	0.31	8	1	0
changed	handle	handle	0.82	8	4	2
```
<!-- end output -->

A gone or new function prints as `gone` or `new`, with its closest
candidate and its score in the same columns.

The JSON object holds `pairs`, `gone`, `new` and `totals`. Each address is
a number, so a tool can compare it:

<!-- output: --format json fixtures/build/O2/basic.o fixtures/build/O2/basic_v2.o -->
```console
$ hereticus --format json basic-v1.elf basic-v2.elf
{"pairs":[{"before":{"name":"array_max","address":144},"after":{"name":"array_min","address":144},"change":"changed","score":0.8378,"added":0,"removed":0,"edited":3,"touched":{"other":3},"matched_by":"similar"}],"gone":[],"new":[],"totals":{"matched":8,"unchanged":4,"changed":4,"gone":0,"new":0}}
```
<!-- end output -->

## Use With a Coding Agent

A coding agent can find a fix with four commands. Each one prints little,
and gives the name that the next one takes:

```console
$ hereticus --format markdown before.bin after.bin | head -20       # the most likely fixes
$ hereticus --view il --diff sub_7630 before.bin after.bin          # what one function changed
$ hereticus --view il --diff-all before.bin after.bin | grep -E '^(sub_|[-+].*PATH)'  # find a text
$ hereticus --functions --format json before.bin                     # each function, for a script
```

Use `--format markdown` where the agent needs the `TOUCHED` and
`MATCHED BY` columns, and `--format compact` where it needs only the
names, the scores and the counts. `compact` is the shortest. The text
table is the longest, because it draws a box around each cell.

To teach an agent the tool, put this in its instructions file, as
`AGENTS.md` or `CLAUDE.md`:

```markdown
## Binary diffing with hereticus

To find what changed between two builds of a binary, use `hereticus`:

- `hereticus --format markdown OLD NEW | head -20` lists the changed
  functions, the most likely fix first.
- `hereticus --view il --diff NAME OLD NEW` shows the diff of one function.
  Use the name the report gives, as `sub_7630`.
- `hereticus --view il --diff-all OLD NEW | grep TEXT` finds the function
  that uses a text an advisory names.
- For a raw image, add `--raw --arch ARCH --base ADDRESS`. Without
  `--base`, the error gives the base the code shows; check it before you
  use it.
- Exit status 2 means an input could not be read.
```

## Exit Status

| Status | When |
|--------|------|
| 0 | Nothing changed, or something changed and `--exit-code` is not given |
| 1 | Something changed, and `--exit-code` is given |
| 2 | An input could not be read |

`--exit-code` lets a CI job fail when a build changed:

```console
$ hereticus --exit-code release.elf candidate.elf || echo "the code changed"
```

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

## Tune the Report

- `--threshold` is the lowest score that still pairs two functions. A
  lower value pairs more functions, and more of them wrongly.
- `--near-miss` is the lowest score at which a gone or new function names
  its closest candidate.
- `--sort` changes the order of the changed functions. `added`, the
  default, puts the most added code first, because a fix usually adds a
  check. `rare` gives more weight to code that few other functions add.
  `removed` and `modified` sort by the other two counts, and `confidence`
  keeps the order of the pairing.

## All Options

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
      --arch <ARCH>            Architecture of a raw image [default: arm32] [possible values: arm32, thumb2, aarch64, mips32, mips32-be, mips16, mips16-be, x86-64, x86]
      --format <FORMAT>        How to print the result [default: text] [possible values: text, compact, markdown, json]
      --sort <SORT>            How to order the changed functions. [default: added] [possible values: confidence, added, removed, modified, rare]
      --progress <PROGRESS>    When to show a progress bar. [default: auto] [possible values: auto, always, never]
      --color <COLOR>          When to color the report. [default: auto] [possible values: auto, always, never]
  -h, --help                   Print help (see more with '--help')
  -V, --version                Print version
```
<!-- end output -->

## Limits
* **Little-endian A32 (ARMv5TE and later, soft-float or hard-float, with
  VFP and NEON), Thumb-2 (Cortex-M too) and AArch64, MIPS32 and MIPS16e
  in either byte order, and x86-64 and 32-bit x86.** A library that
  mixes A32 and Thumb-2, or MIPS32 and MIPS16e, is read function by function
  where its symbols say which set each is in. Stripped or raw, it is read in
  one set, so its minority reads as nonsense.
* **ELF, raw images, and AArch64 Mach-O.** An ELF file that `sstrip` left
  with no section headers, as OpenWrt ships each binary, is read through
  its segments. A Mach-O file is read as macOS
  and iOS ship it, arm64 or arm64e, stripped or not, and a universal binary
  as its AArch64 slice. A kernelcache of iOS 15 and later is read kext by
  kext. The dyld shared cache and 32-bit Mach-O are not read.
* **Unoptimized against optimized is out of scope.** At `-O2` the compiler
  changes the algorithm, which normalizing cannot bridge. Shipped firmware is
  built optimized.
