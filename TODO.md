# TODO

## Check fixes on ARM32, Thumb-2 and MIPS

Four Apple CVE fixes, all AArch64, put each fix in the top 19 rows with
`--sort added`. The `ubusd` fix of CVE-2025-62526 in OpenWrt 24.10.4 shows
in 8 rows on AArch64, 9 on MIPS16e and 8 on A32, where the 7 new PLT
stubs are the 7 functions of the C library that 24.10.4 calls first. Find
more published fixes of OpenWrt or router firmware, for A32 and Thumb-2
too, and add a report to `real-life-reports/` for each.

## Lift more of what a guard can be

`il` reads a compare and the branch on it as one guard on AArch64, A32,
Thumb-2 and MIPS32. Measured against the symbols, that paired 231 more
functions right and 61 more wrong over the cross builds, mostly twins
such as `math_max` and `math_min`. A compiler picks a branch or a select
freely, so a select should read as the branch of a guard. Measured again
against the source files in the DWARF:

- A `csel`, `cset`, `csinc` or `csneg` of A64 as the branch of the
  guard its compare starts, with or without its own token: 5 or 6 more
  right and 2 to 4 more wrong over the backports, with one fix fewer
  ranked first, and the Ubuntu fixes ranked a little higher.
- The conditional instructions of A32 the same way: 28 fewer right and
  23 more wrong over the kernels, and 10 more wrong over the backports.
- A `ccmp` as the branch of the guard before it and the compare of the
  guard after it, so that a chain reads as two guards: 3 more right and
  none wrong over the backports, and the Ubuntu fixes ranked 4 places
  lower in sum. With the A64 selects: 12 more right and 2 more wrong,
  and one fix fewer ranked first.

None of these is clearly better, so none is kept. A select reads as a
plain `select`, and the compare before it as a guard's test.

## Tell twins apart that no instruction separates

The twins this entry named, Lua's `math_ceil` and `math_floor` and
`math_deg` and `math_rad`, paired the wrong way round because every float
operation lifted alike; they pair right now. Of the wrong pairs left
between clang and GCC, 72 score 1.00, and 58 of those paired as twins in
order (`Cascade::match_twins_in_order`): byte-identical twins, as
tinyxml2's `XMLNode::ToComment` and `XMLNode::ToText`, which both return
null, and `MemPool<52>::Free` and `MemPool<60>::Free`. Nothing in their
code tells them apart; only names or callers could. The stages of
`RESEARCH.md` entries 1, 2 and 7, which pair by callers, callees and the
order of the functions, did not move these 58: clang and GCC place the
twins in different orders, and their callers are twins too.

## Unpack more firmware containers

`--unpack` reads the containers the OpenWrt fixtures use: a zImage, alone
or in a FIT image or a sysupgrade tar, a uImage of a kernel or of an
lzma-loader, an ELF lzma-loader and a TP-Link v2 image, and the tests pin
its output to the bytes `fixtures/firmware.py` extracts. Add the formats
still missing, as AVM EVA, a gzip or zstd kernel, and the other branch
filters of xz.

## Read the dyld shared cache

iOS and macOS keep most of their libraries only in the dyld shared cache.
`object` reads one image of a cache, but its calls to other images go
through stubs that the cache builder has bound or removed.

## Recover the last functions of a stripped library

`tests/boundaries.rs` locks how well the scan recovers the functions of the
stripped releases: 45919 of 46006 exact, 16 starts missed and 25 invented,
over ARM, Thumb-2, AArch64 and MIPS, with the PLT and the lazy binding
stubs of MIPS left out. By cause:

- Missed after a pool that no load names, as `codebinexpval` and
  `auxsetnode` of Lua 5.3 by clang for ARM and Thumb-2.
- Missed one by one: `luaV_shiftl` for MIPS, `getS` for ARM and
  `db_getregistry` for Thumb-2, all by GCC, and `crc32_combine_` of zlib
  1.2.11 by clang for Thumb-2.
- Invented inside a function after an internal return, as in Lua's
  `math_ceil` and `math_floor` for MIPS, and in the `luaopen_` functions
  of Lua 5.3 and in zlib 1.2.11 by GCC for Thumb-2.

## Scan a raw binary that mixes two instruction sets

With symbols, each function of an ARM or MIPS library is read in the set
its symbol names, and the `mixed` backports, half A32 and half Thumb-2,
name exactly the functions each fix touched. A stripped library keeps
the set only for what it exports, and a raw image has none, so the scan
reads the whole image in one set. MIPS16e user space mixes the two sets
too: GCC puts a MIPS32 stub before each MIPS16e function that takes a
float argument, and the raw MIPS16e tinyxml2 backports report these
stubs as changed (`KNOWN_EXTRAS` in `tests/backports.rs`). A call says which set its target is in
(`bl` keeps the set, `blx` switches), and so do bit 0 of a pointer and the
unwind index, so a scan could follow them per function.
Measured on the OpenWrt 22.03.5 images for the EX6100v2 and the A385
DB AP, every executable of user space is A32: 41 and 38, none Thumb-2.

## End the code of a raw image where its data begins

`just backports` builds ARMv5TE and ARMv6 too, and every reading of them
names exactly the functions each fix touched, but for one. Read as a raw
image, Lua built by GCC for ARMv5TE joins the first words of `.rodata` to
`luaZ_openspace`, the last function of `.text`, and one build pads
`.rodata` with a zero word that the other lacks. A raw image says nothing
of where its code ends. A run of words that no branch reaches and that
decodes as no code a compiler emits could end it.

## Read big-endian ARM

Some networking parts run ARM big endian (BE8, or BE32 on older cores).
The A32 and T32 decoders read little endian only: BE8 keeps instructions
little endian but data big endian, and BE32 swaps both. Add the byte
order to the ARM architectures, and a fixture built with `-mbig-endian`.

## Read the ARM hard-float ABI and NEON

The fixtures use `-mfloat-abi=softfp`. Most ARMv7 Linux distributions use
`hard`, which passes floats in VFP registers. `yaxpeax-arm` 0.4 reads no
NEON. The tool reads NEON loads and stores itself, but NEON data
processing stays opaque, named `(neon)`. Build a hard-float fixture, and
decode the rest of NEON, with a newer `yaxpeax-arm` or a decoder of its
own.

## Read MIPS64

Cavium Octeon and some newer MIPS routers run MIPS64 (n64 or n32 ABI).
The decoder reads MIPS32 only: no `ld`, `sd`, `daddiu`, or 64-bit
pointers, and the global offset table and `%hi`/`%lo` pairs differ (n64
builds addresses with `lui`, `daddiu` and `dsll`). Add an architecture and
fixtures for `mips64-linux-gnuabi64`.

## Read MIPS32 release 6

MIPS32r6 re-encodes branches, removes `lwl` and `lwr` and the branch
likely forms, and adds compact branches with no delay slot. The decoder
assumes release 2. Few shipped parts use r6, so first confirm a target
worth reading.

## Weigh instructions by how rare they are

Ghidra's BSim weighs each feature by how rare it is across a corpus.
Measured again against the source files in the DWARF, with each
instruction weighed by its inverse document frequency over the functions
of both binaries: weighing every code score, or only the scores the
similarity stage chooses by, at a threshold of 0.55 to 0.65, never beat
the plain score on the backports, and always ranked the fixes lower
(top 1 from 64 to 61 to 63). On the kernels, choosing by the weighed
score at 0.6 paired 223 more right and 35 more wrong, a better trade than
the plain score at 0.6 (365 and 203), but the backports paired 10 fewer
right and 26 more wrong. It would also move every score a report shows.
Leave it unless a new corpus favours it.

## Show the last instructions as IL

`--view il` still shows NEON work as the code prints it: the lift names
it `Vector` only.

## Pair better across a kernel upgrade

`tests/truth_kernels.rs` checks the pairs of the OpenWrt kernels against
the symbols and the source files in the DWARF of their builds, so a
renamed function, a twin and two static functions of one name each count
apart. Over the kernels, 1.14% of the pairs are wrong, and at most 1.35%
where the 528 pairs only the source file calls renamed are wrong too.
Across a kernel upgrade it is 1.6% to 3.2%. Most wrong pairs join a function
the upgrade deleted to one of similar code from another source file, with
no paired caller or callee to say otherwise; a score floor or a move to a
closer free function costs more right pairs than it saves
(`RESEARCH.md`). The pairs by callers and by references are wrong 7% and
11% of the time; the pairs by references out of place split too evenly
on their context to undo.

## Measure on more published fixes, and faster

Eight cases of five published fixes, in `examples/research_bench.rs
--cves`, decide between the orders of the report: each fix of
`real-life-reports/`, and `ubusd` for four architectures. The outlier
score of `RESEARCH.md` entry 12 ranks those best of all, but ranks the
backports and the Ubuntu updates worse, and five fixes are too few to say
which is right. Add more advisories with shipped binaries before and
after.

`tests/truth_ubuntu.rs` locks 218 Ubuntu security updates. Of the 159
wrong pairs left, many are byte-identical twins (see "Tell twins apart
that no instruction separates"), and the fix shows on no changed row in
42 updates.

The CLI on the MIPS kernel of the VR200 takes 12 seconds built for musl,
the target `.cargo/config.toml` picks; "Make the matching faster" below
says where the time goes.

## Treat a branch condition alike on A32 and A64

`Arch::operation_name` keeps the condition of an A32 branch, so a `bne`
that became a `beq` reads as a change, but drops it from `b.ne` of A64.
Both kept what the names did before. A flipped condition is a real edit;
decide one rule for both and measure it.

## Make the matching faster

Every architecture decides by the opcode that `Insn::opcode` holds, and
an `Insn` keeps no name of its own: `Arch::operation_name` names an
operation from its opcode, and the printed text is for a reader. A run
of fixes cut the work done twice.
Against `7bbfb6a`, with each report the same byte for byte:

| Input | Before | Now |
|---|---|---|
| `libgnutls` for arm64 | 3.5 s, 168 MB | 1.1 s, 153 MB |
| `libarchive` for armhf | 4.2 s, 137 MB | 1.0 s, 125 MB |
| ARM kernel of the EX6100v2 | 27.8 s, 1097 MB | 10.0 s, 741 MB |
| MIPS kernel of the VR200 | 36.0 s, 977 MB | 12.0 s, 706 MB |

A decoder now prints an instruction only where `Display` asks, for the
diff and the IL view. On the raw kernels of 22.03.2 and 22.03.5, with
each report and each IL diff the same byte for byte, that took the ARM
kernel of the EX6100v2 from 17.0 s to 12.0 s, and the MIPS kernel of
the EAP245v3 from 11.7 s to 7.3 s.

An alignment numbers its items and holds its table as bits,
the lifted form of an instruction parses no operand text, and `prepare`
keeps each normalized body for the pairs that read it. What is left is
the matching stages themselves; measure them before anything else.

`track_pages` of AArch64 reads typed operands decoded from the code
bytes, which took 10% off libgnutls; keeping the decoded operands in
every `Insn` took 237 MB in place of 137 MB and no time. MIPS compares
register names packed into words. `track_pages` still reads `w24` and
`x24` as two registers, as the text did, though a write of `w24` clears
`x24` too. Ending the page of `x24` there changed the texts of two
functions of the libgnutls update and moved no truth test; find out
whether those two show a real change before it ends them.

## Rust has the idea of MIR, an in-between IL. Would that help this project?

## Our IL is cool, but maybe it could be even better!
1. Tui could show branches graphically, like other tools
2. IL could be an emulator?
3. IL could be an input/output simulator, might be nice for function diffing...
