# Comparison With Other Tools

Tests compare `hereticus` with radiff2 of radare2 6.2.4 and with Ghidra
12.1.4 Version Tracking. All three tools read the same
64<!-- from rivals_radare2: hereticus / builds --> pairs of stripped libraries. Each pair
is one release of zlib, Lua, tinyxml2 or smallvec, before and after one
upstream fix, for ARM, Thumb-2, AArch64, MIPS, x86-64, i686 or PowerPC.
The functions that the fix
edits are known, so each report gets a score.

> [!WARNING]
> These numbers are a narrow test, not a full measure of the three tools.
> Read [How Accurate These Numbers Are](#how-accurate-these-numbers-are)
> before you quote them.

| Tool      | Fixes found | Fix on row 1 | Rows | Rows the fix did not touch |
|-----------|-------------|--------------|------|----------------------------|
| hereticus | 64<!-- from rivals_radare2: hereticus / found --> | 38<!-- from rivals_radare2: hereticus / first --> | 145<!-- from rivals_radare2: hereticus / rows --> | 3<!-- from rivals_radare2: hereticus / extras --> |
| radiff2   | 35<!-- from rivals_radare2: radare2 / found --> | 18<!-- from rivals_radare2: radare2 / first --> | 4522<!-- from rivals_radare2: radare2 / rows --> | 4450<!-- from rivals_radare2: radare2 / extras --> |
| Ghidra    | 60<!-- from truth_ghidra: ghidra / found --> | 32<!-- from truth_ghidra: ghidra / first --> | 4477<!-- from truth_ghidra: ghidra / rows --> | 4253<!-- from truth_ghidra: ghidra / extras --> |

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

## Real Security Updates

The backports are small, and each has one fix. A test also gives all three
tools the security updates of C libraries of Ubuntu 22.04, for arm64 and
armhf, as `fixtures/ubuntu_cases.json` pins them: each pair of a release
and the next. The patches of each update name the functions that the fix
edits, and the debug files of Ubuntu name the functions of each library.
An update counts where the code of a function that its patches edit
changed, as 176<!-- from truth_ubuntu_rivals: all hereticus / cases --> updates do. A report shows the fix
at the first row that names such a function, or a function that holds a
copy of it that the compiler inlined. The tools read the libraries as
Ubuntu ships them, with the names of the functions they export. A real
update can change more than its fix, so the table gives no count of rows
that the fix did not touch.

| Tool | Fixes found | Fix on row 1 | Fix in the first 10 rows | Rows |
|------|-------------|--------------|--------------------------|------|
| hereticus | 176<!-- from truth_ubuntu_rivals: all hereticus / found --> | 122<!-- from truth_ubuntu_rivals: all hereticus / first --> | 175<!-- from truth_ubuntu_rivals: all hereticus / top10 --> | 5972<!-- from truth_ubuntu_rivals: all hereticus / rows --> |
| radiff2 | 105<!-- from truth_ubuntu_rivals: all radare2 / found --> | 30<!-- from truth_ubuntu_rivals: all radare2 / first --> | 50<!-- from truth_ubuntu_rivals: all radare2 / top10 --> | 80450<!-- from truth_ubuntu_rivals: all radare2 / rows --> |
| Ghidra | 173<!-- from truth_ubuntu_rivals: all ghidra / found --> | 90<!-- from truth_ubuntu_rivals: all ghidra / first --> | 146<!-- from truth_ubuntu_rivals: all ghidra / top10 --> | 50932<!-- from truth_ubuntu_rivals: all ghidra / rows --> |

The order of the rows is where the tools differ most. `hereticus` shows
the fix earlier than Ghidra in
84<!-- from truth_ubuntu_rivals: ghidra / hereticus-earlier --> updates, and Ghidra shows it
earlier than `hereticus` in
27<!-- from truth_ubuntu_rivals: ghidra / rival-earlier -->. Against radiff2, the counts are
146<!-- from truth_ubuntu_rivals: radare2 / hereticus-earlier --> and
5<!-- from truth_ubuntu_rivals: radare2 / rival-earlier -->.
[Where `hereticus` Does Worse](#where-hereticus-does-worse) says why.

## Deeper Settings

The table above runs each other tool with its default settings. The tests
also run each one with its deepest analysis: radiff2 as `radiff2 -AA -C`,
which runs `aaaa`, and Ghidra with three more correlators after Auto Version
Tracking. These are BSim Function Matching, Exact Function Mnemonics and
Combined Function and Data Reference, the correlators of the Version
Tracking window that Auto Version Tracking does not run. Of the matches that
they make, the test accepts the best match of each function that is not in
a pair yet, as a person does in that window. `hereticus` runs with no options,
as before.

| Tool | Fixes found | Fix on row 1 | Rows | Rows the fix did not touch |
|------|-------------|--------------|------|----------------------------|
| hereticus | 64<!-- from rivals_radare2_deeper: hereticus / found --> | 38<!-- from rivals_radare2_deeper: hereticus / first --> | 145<!-- from rivals_radare2_deeper: hereticus / rows --> | 3<!-- from rivals_radare2_deeper: hereticus / extras --> |
| radiff2 `-AA` | 58<!-- from rivals_radare2_deeper: radare2-deeper / found --> | 17<!-- from rivals_radare2_deeper: radare2-deeper / first --> | 7532<!-- from rivals_radare2_deeper: radare2-deeper / rows --> | 7313<!-- from rivals_radare2_deeper: radare2-deeper / extras --> |
| Ghidra, more correlators | 60<!-- from truth_ghidra_deeper: ghidra-deeper / found --> | 33<!-- from truth_ghidra_deeper: ghidra-deeper / first --> | 3044<!-- from truth_ghidra_deeper: ghidra-deeper / rows --> | 2893<!-- from truth_ghidra_deeper: ghidra-deeper / extras --> |

With `-AA`, radiff2 finds more fixes, but it shows more rows that the fix
did not touch, and it shows fewer fixes on row 1. With more correlators,
Ghidra pairs more functions, so fewer rows show a function as gone and
new. On each build of Lua that clang made at `-O2`, Ghidra shows the fix
one or two rows earlier than `hereticus` does: on row
3<!-- from truth_ghidra_deeper: lua-arm-O2 / rank:ghidra-deeper --> for ARM at `-O2`, where
`hereticus` shows it on row
4<!-- from truth_ghidra_deeper: lua-arm-O2 / rank:hereticus -->. The fix edits `luaZ_fill`
and `luaZ_init`, and `luaZ_read` changes with it. A reference correlator
gives the pair of `luaZ_read` a score of 1, so Ghidra lists it last.
`hereticus` lists `luaZ_read` before `luaZ_init`, as more of its code
changed. radiff2 with `-AA` also shows the fix earlier on Lua for 64-bit
PowerPC, as it scores `luaZ_init` 0, and so does Ghidra on Lua for 32-bit
PowerPC with no names. The tests of these setups thus check only the
fixes found and the rows that the fix did not touch.

## Libraries With No Names

A shared library keeps a symbol for each function that it exports, with
the name and the start of the function. `fixtures/rivals/unname.py` writes
a copy of each stripped library with no symbol that the library defines,
as for a library or a program that exports nothing. A relocation that
stored the address of such a symbol stores the same address with no
symbol, as a linker writes it for a symbol that it does not export. All
three tools read these copies with their default settings.

| Tool | Fixes found | Fix on row 1 | Rows | Rows the fix did not touch |
|------|-------------|--------------|------|----------------------------|
| hereticus | 64<!-- from rivals_radare2_unnamed: hereticus / found --> | 38<!-- from rivals_radare2_unnamed: hereticus / first --> | 152<!-- from rivals_radare2_unnamed: hereticus / rows --> | 10<!-- from rivals_radare2_unnamed: hereticus / extras --> |
| radiff2 | 0<!-- from rivals_radare2_unnamed: radare2-unnamed / found --> | 0<!-- from rivals_radare2_unnamed: radare2-unnamed / first --> | 137<!-- from rivals_radare2_unnamed: radare2-unnamed / rows --> | 130<!-- from rivals_radare2_unnamed: radare2-unnamed / extras --> |
| Ghidra | 56<!-- from truth_ghidra_unnamed: ghidra-unnamed / found --> | 26<!-- from truth_ghidra_unnamed: ghidra-unnamed / first --> | 5670<!-- from truth_ghidra_unnamed: ghidra-unnamed / rows --> | 5446<!-- from truth_ghidra_unnamed: ghidra-unnamed / extras --> |

`hereticus` finds each fix, and shows as many on row 1 as with the names.
On tinyxml2 for x86-64, it shows
6<!-- from rivals_radare2_unnamed: tinyxml2-x86_64-O2 / extras:hereticus --> rows that the fix did not
touch: PLT stubs, which show as gone and as new. `unname.py` keeps the
stubs of the functions that the library exported, which a linker does not
write for a library that exports nothing. With no symbols,
`radiff2 -C` lists the function at the entry point, or one or two other
functions of a pair, or none, although the analysis of `aaa` finds many
more. Ghidra finds fewer fixes
than with the names, as the Exact Symbol Name correlator pairs no
function, and it shows more rows that the fix did not touch: on the
tinyxml2 build for AArch64 at `-O2`, it shows
144<!-- from truth_ghidra_unnamed: tinyxml2-aarch64-O2 / rows:ghidra-unnamed --> rows, and
`hereticus` shows
1<!-- from truth_ghidra_unnamed: tinyxml2-aarch64-O2 / rows:hereticus -->.

This test found two errors in `hereticus`. With no symbols, it read the
code of an ARM library as A32 code, also where the code was Thumb-2. It
now reads bit 0 of the addresses of functions that the relocations store.
And it took a PLT stub with no name for the function that it calls, so
where the stubs moved, each caller read as changed, and tinyxml2 for x86
showed dozens of rows that the fix did not touch. A stub whose slot a relocation fills
with the address of a function now stands for that function.

## Pairs Built Two Ways

A vendor can build the next release with another compiler, or at another
level of optimization. Then most functions change, not only those of the
fix. `fixtures/rivals/crossed-builds.txt` lists such pairs of the
backports: clang at `-O2` before the fix and GCC at `-O2` after it, or
`-Os` before and `-O3` after. All three tools read them with their default
settings.

| Tool | Fixes found | Fix on row 1 | Rows | Rows the fix did not touch |
|------|-------------|--------------|------|----------------------------|
| hereticus | 28<!-- from rivals_radare2_crossed: hereticus / found --> | 7<!-- from rivals_radare2_crossed: hereticus / first --> | 7199<!-- from rivals_radare2_crossed: hereticus / rows --> | 7116<!-- from rivals_radare2_crossed: hereticus / extras --> |
| radiff2 | 16<!-- from rivals_radare2_crossed: radare2-crossed / found --> | 0<!-- from rivals_radare2_crossed: radare2-crossed / first --> | 5227<!-- from rivals_radare2_crossed: radare2-crossed / rows --> | 5185<!-- from rivals_radare2_crossed: radare2-crossed / extras --> |
| Ghidra | 28<!-- from truth_ghidra_crossed: ghidra-crossed / found --> | 9<!-- from truth_ghidra_crossed: ghidra-crossed / first --> | 8416<!-- from truth_ghidra_crossed: ghidra-crossed / rows --> | 8280<!-- from truth_ghidra_crossed: ghidra-crossed / extras --> |

`hereticus` finds every fix, but a reader must read far to see a small
one. On zlib the fix is on row 1 or 2, and on Lua on row
149<!-- from rivals_radare2_crossed: lua-x86_64-Os-to-O3 / rank:hereticus --> to
391<!-- from rivals_radare2_crossed: lua-mips-O2-to-gcc-O2 / rank:hereticus -->. The Lua fix changes a few
instructions of `luaZ_fill`, and the other compiler changes many
instructions of almost every function. On the ARM pair of clang and GCC, no
order that `--sort` gives puts the fix in the first hundred rows. `hereticus` also shows more rows than
radiff2, as it pairs more functions, and each pair changed.

Ghidra ranks the fixes of these pairs better than `hereticus` does. It
shows the fix of tinyxml2 on row 1 for each pair, where `hereticus` shows
it on row 2 to
31<!-- from truth_ghidra_crossed: tinyxml2-x86_64-O2-to-gcc-O2 / rank:hereticus -->, and the fix of Lua on row
111<!-- from truth_ghidra_crossed: lua-mips-Os-to-O3 / rank:ghidra-crossed --> to
231<!-- from truth_ghidra_crossed: lua-x86_64-O2-to-gcc-O2 / rank:ghidra-crossed -->. Where the compiler changes
every function, the function that is least alike, which Ghidra lists
first, is more often the fix than the function that gained the most
instructions, which `hereticus` lists first. On zlib and smallvec,
`hereticus` shows the fix earlier.

## Pairs in Raw Kernels

A kernel holds about twenty thousand functions, and a fix has no known
place in it, so the tests check the pairs of each tool, not the row of a
fix. Each tool compares the raw kernels of OpenWrt 22.03.2 and 22.03.5 for
the six boards of `tests/openwrt.rs`, two of them ARM and four MIPS. The
symbols of each build say which function starts where. A pair is
**judged** where a symbol starts at each of its two starts, and it is
**right** where the two symbols have the same name and come from source
files that correspond. All other judged pairs are wrong.

| Tool | Pairs | Judged | Right | Wrong | Share wrong |
|------|-------|--------|-------|-------|-------|
| hereticus | 134021<!-- from truth_kernel_rivals: all hereticus / pairs --> | 132165<!-- from truth_kernel_rivals: all hereticus / judged --> | 131896<!-- from truth_kernel_rivals: all hereticus / right --> | 269<!-- from truth_kernel_rivals: all hereticus / wrong --> | 0.20%<!-- from truth_kernel_rivals: all hereticus / wrong% --> |
| radiff2 | 17792<!-- from truth_kernel_rivals: all radare2 / pairs --> | 14138<!-- from truth_kernel_rivals: all radare2 / judged --> | 13582<!-- from truth_kernel_rivals: all radare2 / right --> | 556<!-- from truth_kernel_rivals: all radare2 / wrong --> | 3.93%<!-- from truth_kernel_rivals: all radare2 / wrong% --> |
| Ghidra | 93202<!-- from truth_kernel_rivals: all ghidra / pairs --> | 91119<!-- from truth_kernel_rivals: all ghidra / judged --> | 91003<!-- from truth_kernel_rivals: all ghidra / right --> | 116<!-- from truth_kernel_rivals: all ghidra / wrong --> | 0.13%<!-- from truth_kernel_rivals: all ghidra / wrong% --> |

`hereticus` makes the most right pairs. Ghidra makes fewer pairs, and a
smaller part of them is wrong. A point release keeps the same kernel, so
the rule calls a function that a release renamed wrong for each tool.
`tests/truth_kernels.rs` judges the pairs of `hereticus` with more care,
and it finds such renamed functions.

radiff2 cannot read a raw image at its load address, so the test gives it
each kernel in an ELF file with one segment at that address. With `-A` or
`-AA`, radiff2 reads such a kernel as one function, and shows two rows. So
the test runs it as `radiff2 -A -e anal.hasnext=true -C`, which reads on
after the end of each function. Ghidra reads each raw kernel as in
[Functions in a Raw Kernel](#functions-in-a-raw-kernel), and Auto Version
Tracking pairs the functions.

## Where `hereticus` Does Worse

The tests above find these weak points of `hereticus`:

- **More wrong pairs in a kernel.** `hereticus` makes
  269<!-- from truth_kernel_rivals: all hereticus / wrong --> wrong pairs in the kernels, and Ghidra
  116<!-- from truth_kernel_rivals: all ghidra / wrong -->. Of the functions that `hereticus` pairs wrong, Ghidra
  pairs 14<!-- from truth_kernel_rivals: all / ghidra-right --> right and
  32<!-- from truth_kernel_rivals: all / ghidra-wrong --> wrong, and leaves
  223<!-- from truth_kernel_rivals: all / ghidra-unpaired --> with no judged pair. Of those that Ghidra pairs
  right, `tcp_v4_get_syncookie` is one: on each MIPS board, `hereticus`
  pairs it with `tcp_v4_early_demux`. Of those that Ghidra leaves, many
  are small functions whose code is almost the same, as
  `memory_high_show` and `swap_high_show`, or the `show` functions of the
  regulator class. `hereticus` pairs such a function with one of them,
  and Ghidra with none. Others are functions of `io_uring` that a backport
  in 22.03.5 renamed or moved. Where `hereticus` shows a wrong pair, a
  reader of Ghidra sees one function gone and one new.
- **A lower rank for some fixes.** In
  27<!-- from truth_ubuntu_rivals: ghidra / rival-earlier --> of the Ubuntu updates, Ghidra shows the fix
  earlier than `hereticus`. `hereticus` puts the function that gained the
  most instructions first, and Ghidra the function that it scores least
  alike. A fix of one instruction thus sinks below functions with larger
  changes that the fix did not make. In the update of libssh for arm64 to
  0.9.6-2ubuntu0.22.04.5, the fix adds one normalized instruction to
  `ssh_make_sessionid`, and the compiler laid out the stack frames of
  other functions anew.
  `hereticus` shows the fix on row
  30<!-- from truth_ubuntu_rivals: libssh-4-arm64-0.9.6-2ubuntu0.22.04.4-0.9.6-2ubuntu0.22.04.5 / rank:hereticus -->, and Ghidra on row
  1<!-- from truth_ubuntu_rivals: libssh-4-arm64-0.9.6-2ubuntu0.22.04.4-0.9.6-2ubuntu0.22.04.5 / rank:ghidra -->. With more correlators, Ghidra also shows the fix
  of Lua earlier on each build by clang at `-O2`, as
  [Deeper Settings](#deeper-settings) says.
- **Changes that the IL view hides.** The rank counts the normalized
  instructions that a function gained, and the IL view folds more of what
  a rebuild changes. In the update of zlib for armhf to
  1:1.2.11.dfsg-2ubuntu9, `inflateBack`, which the fix did not edit, gained
  43 normalized instructions and lost 39, and so came first. The IL view
  shows no changed line in it. The fix is on row
  2<!-- from truth_ubuntu_rivals: zlib1g-armhf-1:1.2.11.dfsg-2ubuntu7-1:1.2.11.dfsg-2ubuntu9 / rank:hereticus -->, and radiff2 and Ghidra show it on row
  1<!-- from truth_ubuntu_rivals: zlib1g-armhf-1:1.2.11.dfsg-2ubuntu7-1:1.2.11.dfsg-2ubuntu9 / rank:ghidra -->.
- **Pairs built two ways.** Where another compiler built the next
  release, Ghidra shows the fix of tinyxml2 and of Lua earlier than
  `hereticus` does, and the fix of Lua is far down the report of each
  tool, as [Pairs Built Two Ways](#pairs-built-two-ways) says.
- **Binaries with no names.** Before the tests read libraries with no
  names, `hereticus` read such Thumb-2 code as A32 code, and took a PLT
  stub whose slot holds a relocated address for its callee, as
  [Libraries With No Names](#libraries-with-no-names) says. Both are
  fixed. Other kinds of binary that the tests do not read can have errors
  of the same kind.

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

Ghidra does this on purpose. It is made for a person who reads the
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

The entry "The other tools in more setups, and on kernels" of
[`RESEARCH.md`](https://github.com/wc0x2b/hereticus/blob/master/RESEARCH.md)
records how these comparisons were made, and what they found. The
numbers are correct for these pairs and these settings. They do not
show that one tool is better than another in general. Know these limits:

- **The pairs are small and few.** Each pair is a small library with one
  small fix. A large binary, or a release with many changes, can give a
  different result.
- **The kernels are of one point release.** Ghidra takes about a quarter
  of an hour for each pair of kernels, so the tests compare only the six
  pairs of 22.03.2 and 22.03.5. A kernel upgrade changes much more code.
- **The other tools run with few settings.** The tests run each with its
  default settings and with its deepest analysis. Other options, or a
  person who reads the results, can make radiff2 or Ghidra do better.
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
- **The libraries with no names are made from libraries with names.**
  `unname.py` removes the symbols of a library after the link. A program
  built to export nothing can have other code, as the compiler can inline
  or remove a function that no other file can call.
- **Times depend on the machine.** The other tools ran alone, and
  `hereticus` ran while other tests ran.

## Run the Tests

```
just rivals         # run radiff2 on the pairs, in each setup
just quick-test     # compare with radiff2, in rivals_radare2*.rs
just rivals-ghidra  # run Ghidra on the pairs, in each setup
just test           # compare with Ghidra too, in truth_ghidra*.rs
just rivals-kernel  # let Ghidra find the functions of one raw kernel
just rivals-kernel-pairs  # let radiff2 and Ghidra pair the raw kernels
just rivals-go      # let Ghidra find the functions of the garbled Go builds
just rival-times    # show how long each tool takes
```

The Ghidra image is large and a first run takes a long time, so only
`just test` compares with Ghidra. `fixtures/rivals/builds.txt` lists the
pairs. The snapshots of the two tests hold the score of each tool on each
pair.
