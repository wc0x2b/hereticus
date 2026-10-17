# Comparison With Other Tools

Tests compare `hereticus` with radiff2 of radare2 6.2.4 and with Ghidra
12.1.4 Version Tracking. All three tools read the same
35<!-- from rivals_radare2: hereticus / builds --> pairs of stripped libraries. Each pair
is one release of zlib, Lua, tinyxml2 or smallvec, before and after one
upstream fix, for ARM, Thumb-2, AArch64 or MIPS. The functions that the fix
edits are known, so each report gets a score.

> [!WARNING]
> These numbers are a narrow test, not a full measure of the three tools.
> Read [How Accurate These Numbers Are](#how-accurate-these-numbers-are)
> before you quote them.

| Tool      | Fixes found | Fix on row 1 | Rows | Rows the fix did not touch |
|-----------|-------------|--------------|------|----------------------------|
| hereticus | 35<!-- from rivals_radare2: hereticus / found --> | 20<!-- from rivals_radare2: hereticus / first --> | 85<!-- from rivals_radare2: hereticus / rows --> | 0<!-- from rivals_radare2: hereticus / extras --> |
| radiff2   | 20<!-- from rivals_radare2: radare2 / found --> | 9<!-- from rivals_radare2: radare2 / first --> | 2457<!-- from rivals_radare2: radare2 / rows --> | 2418<!-- from rivals_radare2: radare2 / extras --> |
| Ghidra    | 33<!-- from truth_ghidra: ghidra / found --> | 18<!-- from truth_ghidra: ghidra / first --> | 759<!-- from truth_ghidra: ghidra / rows --> | 629<!-- from truth_ghidra: ghidra / extras --> |

A tool **finds** a fix when its report shows every function that the fix
edits. The **row** of a fix is the last row that a reader must read to see
all of those functions. A fix that edits more than one function cannot be
on row 1: the smallvec fix edits six copies of `insert_many`, so it takes
six rows.

A **row the fix did not touch** names no function that the fix edits or
that can change with it. Such rows are noise: most come from code that
moved, and thus has new addresses in it. For example, radiff2 shows the
zlib fix for MIPS, built by GCC at `-O2`, on
row 33<!-- from rivals_radare2: zlib-mips-gcc-O2 / rank:radare2 --> of
80<!-- from rivals_radare2: zlib-mips-gcc-O2 / rows:radare2 -->. `hereticus` shows it
on row 1<!-- from rivals_radare2: zlib-mips-gcc-O2 / rank:hereticus -->, and on no
other row.

## How the Tests Score Each Tool

- `hereticus` runs with no options, as a user runs it. Its rows are read
  as it lists them.
- radiff2 runs as `radiff2 -A -C`. A row counts as changed when its
  similarity is below 1, or when radiff2 labels it `UNMATCH`.
- Ghidra runs Auto Version Tracking with the options of its own
  `AutoVersionTrackingScript`. Version Tracking pairs functions, but does
  not say which pairs changed. Thus a pair counts as changed by the rule of
  `FindChangedFunctionsScript`, which ships with Ghidra: no exact match of
  the instructions pairs it.
- The rows of radiff2 and Ghidra are read the lowest score first. Rows with
  the same score have no order, so the rows of the fix are read first among
  them. This rule helps the other tool.

On each build, `hereticus` must find the fix, show it on the same row as
the other tool or on an earlier row, and show no more rows that the fix did
not touch. If a change makes `hereticus` worse than the other tool on one
build, the test fails.

## Time

`just rival-times` shows how long each tool takes on each pair. On these
small libraries, `hereticus` and radiff2 each take less than a second, and
Ghidra takes much longer, as it analyses each program and then tracks the
versions. The test checks only that `hereticus` takes less time than
Ghidra in all. A time depends on the machine, so this page quotes none.

## Functions in a Raw Kernel

Before a tool can compare functions, it must find them. A test counts the
functions that `hereticus` and Ghidra find in one raw OpenWrt kernel: 22.03.2
for the GL.iNet GL-MT300N v2, MIPS32 little-endian, with no symbols and no
sections. The symbols of its build say where each of its
20988<!-- from truth_function_starts: hereticus / symbols --> functions really starts.

| Tool | Starts found | Real | Not real |
|------|--------------|------|----------|
| hereticus | 19741<!-- from truth_function_starts: hereticus / found --> | 19277<!-- from truth_function_starts: hereticus / real --> | 464<!-- from truth_function_starts: hereticus / not real --> |
| Ghidra, default | 13801<!-- from truth_function_starts: ghidra default / found --> | 13210<!-- from truth_function_starts: ghidra default / real --> | 591<!-- from truth_function_starts: ghidra default / not real --> |
| Ghidra, Aggressive Instruction Finder | 14144<!-- from truth_function_starts: ghidra aggressive / found --> | 13545<!-- from truth_function_starts: ghidra aggressive / real --> | 599<!-- from truth_function_starts: ghidra aggressive / not real --> |

Ghidra finds a function when code calls it, or when its first bytes look
like the start of a function. Of the real functions that Ghidra finds,
77%<!-- from truth_function_starts: ghidra default finds / jal% --> have a direct call. Of the
6103<!-- from truth_function_starts: only hereticus finds / count --> real functions that only `hereticus`
finds, 5%<!-- from truth_function_starts: only hereticus finds / jal% --> have a direct call, and the
address of 76%<!-- from truth_function_starts: only hereticus finds / word% --> is in a data word. These
functions are callbacks: system calls, `file_operations`, `net_device_ops`,
sysfs handlers. The kernel calls them through tables of pointers. A raw
image does not show where those tables are, and Ghidra does not read data
words as pointers unless it is told to. The Aggressive Instruction Finder
does not follow them either.

This is not a fault in Ghidra. Ghidra is made for a person who reads the
result, and code that it reads from data by mistake is hard to remove. So it
adds only the functions it is sure of, and a person adds the rest. A script
that reads the data words as pointers can close much of the gap. With an
ELF file and its symbols, Ghidra finds every function. This test reads one
kernel for one architecture, and it counts only where functions start, not
how well each tool pairs them.

## Functions in Garbled Go

Go malware is obfuscated, mostly with `garble`, so every Go fixture is
built so too: `shfmt` for seven architectures. `garble` strips the
symbols, scrambles the names, and hides the function table of Go behind a
magic number of its own, so Ghidra's Go analyzer reads nothing and both
tools read the code alone. A test counts the real function starts that each
tool finds, with the hidden table, read with the usual magic put back, as
the answer.

| Build | hereticus finds | hereticus misses | Ghidra finds | Ghidra misses |
|---|---|---|---|---|
| x86-64 | 3624<!-- from go_garbled: amd64 hereticus / real --> | 11<!-- from go_garbled: amd64 hereticus / missed --> | 2429<!-- from go_garbled: amd64 ghidra / real --> | 1206<!-- from go_garbled: amd64 ghidra / missed --> |
| i386 | 3674<!-- from go_garbled: 386 hereticus / real --> | 5<!-- from go_garbled: 386 hereticus / missed --> | 2542<!-- from go_garbled: 386 ghidra / real --> | 1137<!-- from go_garbled: 386 ghidra / missed --> |
| AArch64 | 3554<!-- from go_garbled: arm64 hereticus / real --> | 40<!-- from go_garbled: arm64 hereticus / missed --> | 2373<!-- from go_garbled: arm64 ghidra / real --> | 1221<!-- from go_garbled: arm64 ghidra / missed --> |
| ARMv7 | 3597<!-- from go_garbled: arm-7 hereticus / real --> | 75<!-- from go_garbled: arm-7 hereticus / missed --> | 2509<!-- from go_garbled: arm-7 ghidra / real --> | 1163<!-- from go_garbled: arm-7 ghidra / missed --> |
| ARMv5 | 3632<!-- from go_garbled: arm-5 hereticus / real --> | 71<!-- from go_garbled: arm-5 hereticus / missed --> | 2523<!-- from go_garbled: arm-5 ghidra / real --> | 1180<!-- from go_garbled: arm-5 ghidra / missed --> |
| MIPS32 big-endian | 3491<!-- from go_garbled: mips-softfloat hereticus / real --> | 88<!-- from go_garbled: mips-softfloat hereticus / missed --> | 2379<!-- from go_garbled: mips-softfloat ghidra / real --> | 1200<!-- from go_garbled: mips-softfloat ghidra / missed --> |
| MIPS32 little-endian | 3491<!-- from go_garbled: mipsle-softfloat hereticus / real --> | 88<!-- from go_garbled: mipsle-softfloat hereticus / missed --> | 1517<!-- from go_garbled: mipsle-softfloat ghidra / real --> | 2062<!-- from go_garbled: mipsle-softfloat ghidra / missed --> |

The same test compares shfmt 3.11.0 with 3.12.0, both garbled, as two
releases of one piece of malware. `garble` names each function anew in
each release, so the pairs come from the code alone, and `garble reverse`
gives back the names that judge them. The few wrong pairs join twins with
the same code, as `unix.mmap` and `unix.mremap`.

Ghidra loads the little-endian MIPS build as 64-bit MIPS32r6, which the ELF
header does not say, and so finds the fewest there. On a build that
`garble` did not touch, Ghidra 12 reads the function table of Go for x86-64
and AArch64, and finds almost every function there.

## How Accurate These Numbers Are

The numbers are correct for these pairs and these settings. They do not
show that one tool is better than another in general. Know these limits:

- **The pairs are small and few.** Each pair is a small library with one
  small fix. A large binary, or a release with many changes, can give a
  different result.
- **No kernel pair is compared.** A raw kernel of a few megabytes takes
  radiff2 and Ghidra many minutes for each pair, so the tests do not
  compare the reports on the OpenWrt kernels. `tests/truth_kernels.rs`
  checks only `hereticus` on them. The section above compares only where
  the functions of one kernel start.
- **The other tools run with their default settings.** Other options, or
  a person who reads the results, can make radiff2 or Ghidra do better.
  For example, Ghidra can run more correlators, and radiff2 can analyse
  more deeply.
- **The rules that score the other tools are ours.** Ghidra does not mark
  a pair as changed, so the tests use the rule of its own script. radiff2
  gives no clear label for a change, so the tests count a row below a
  similarity of 1 as changed. Other rules give other numbers.
- **The scores favour what `hereticus` is made for.** The tests count the
  rows that a reader must read to find a fix. Ghidra Version Tracking is
  made to carry names and comments from one version to the next, not to
  rank changes, so this score is not its aim.
- **`hereticus` was developed with these pairs.** Its tests use the same
  backports, so its rules can fit these pairs better than other binaries.
- **The libraries are not fully stripped.** A shared library keeps the
  names of the functions it exports, and all three tools can read them.
  Without names, the results can be different.
- **Times depend on the machine.** The other tools ran alone, and
  `hereticus` ran while other tests ran.

## Run the Tests

```
just rivals         # run radiff2 on the pairs
just quick-test     # compare with radiff2, in rivals_radare2.rs
just rivals-ghidra  # run Ghidra on the pairs
just test           # compare with Ghidra too, in truth_ghidra.rs
just rivals-kernel  # let Ghidra find the functions of one raw kernel
just rivals-go      # let Ghidra find the functions of the garbled Go builds
just rival-times    # show how long each tool takes
```

The Ghidra image is large and a first run takes a long time, so only
`just test` compares with Ghidra. `fixtures/rivals/builds.txt` lists the
pairs. The snapshots of the two tests hold the score of each tool on each
pair.
