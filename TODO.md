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
such as `math_max` and `math_min`. Still read as plain work:

- A compare whose result a `cset`, a `csel` or a conditional instruction
  of A32 uses, in place of a branch. Naming the condition in the select,
  either way, was measured: on A64 it paired 8 fewer right, and on the
  conditional instructions of A32, 79 fewer right and 10 fewer wrong,
  over the cross builds. A compiler picks a branch or a select freely, so
  this wants a guard that reads both as one, not a name that splits them.
- A chain of `ccmp`, which tests two conditions with one branch.

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

## Make function recovery a library

`scan.rs` and `arch/` find 45795 of 46006 functions exactly in stripped
libraries, over ARM, Thumb-2, AArch64 and MIPS, and few Rust crates do
that. They depend only on `address.rs` and `obj::Function`. But the `Arch`
trait mixes decoding with the rules of `hereticus`, about 30 methods, and
reads operands back from text. Split a stable API out of it first.

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

## Cache the fixtures in CI

The README shows a build badge, but the repository holds no workflow. Add
one that runs `just test`, and cache `fixtures/build` in it, keyed on the
pinned SHA-256 values and on `fixtures/`. `backports.sh` already keeps
what it built while its inputs stay the same: locally a second run takes
two seconds where the first takes eight minutes.

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
Measured over the cross builds, a Jaccard weighted by the rarity of each
normalized instruction in the two binaries pairs more right for each
wrong pair than the plain one at every threshold: at 0.55 weighted, 736
more right and 256 more wrong, where the plain one at 0.6 paired 624
more right and 332 more wrong. At the present precision the gain is
small, 14 more right and 3 fewer wrong at 0.63, and the change would move
every score a report shows and the meaning of `--threshold`. Revisit it
with the threshold.

## Show the last instructions as IL

`--view il` still shows NEON work as the code prints it: the lift names
it `Vector` only.

## Pair better across a kernel upgrade

`examples/research_bench.rs --kernels` checks the pairs of the OpenWrt
kernels against the symbols of their builds (`RESEARCH.md`, "The OpenWrt
kernels, against their symbols"), and `tests/truth_kernels.rs` locks
the counts. Across a kernel upgrade, 3% to 8% of the pairs are wrong,
and the pairs by callers and by place are right 87% of the time, where
the rest is right 98%. About three in four wrong pairs are proven wrong: the true partner
exists by name. `BENCH_WHERE=1` shows where it went. List the wrong pairs with `BENCH_WRONG=1` and the
right ones with `BENCH_RIGHT=1`, one kernel with `BENCH_ONLY`, and find
what tells them apart. The length of the gap does not (`RESEARCH.md`).
A pair wrong by the names can be a renamed function; a list of the
renames between the kernel versions would make the count exact.

## Measure on more published fixes, and faster

Eight cases of five published fixes, in `examples/research_bench.rs
--cves`, decide between the orders of the report: each fix of
`real-life-reports/`, and `ubusd` for four architectures. The outlier
score of `RESEARCH.md` entry 12 ranks those best of all, but ranks the
backports and the Ubuntu updates worse, and five fixes are too few to say
which is right. Add more advisories with shipped binaries before and
after.

`tests/truth_ubuntu.rs` locks 218 Ubuntu security updates. Of the 179
wrong pairs left, 133 are byte-identical twins (see "Tell twins apart
that no instruction separates"), and the fix shows on no changed row in
42 updates.

The CLI on an OpenWrt kernel takes 28 seconds built for musl, the target
`.cargo/config.toml` picks; the work left is mostly decoding and string
handling, which "Do not decide by mnemonic text" below covers.

## Do not decide by mnemonic text

Decide what an instruction does by the opcode the decoder gives, not by
its printed mnemonic. Text is slow and wrong in ways an opcode is not:

- Slow: under callgrind, a comparison of libxml2 for arm64 spends 17%
  of its instructions in `Aarch64::lift`, where `op_of` holds 132 string
  tests and `role_of` 54; the searches for `", "` and `.w` that this tree
  already took out cost 8% and 16% of whole comparisons.
- Wrong: much of the code of `arch/` only mends what `yaxpeax` prints, as
  `strt` for a wide store, `lsl` for `uxtw`, or the `.w` of Thumb-2, and
  a new release of a decoder that prints otherwise would change what
  pairs, with no test of the decoder to say so.

Keep the text for what a reader sees, and for the normalized body until
a measure says the body may change. Move one architecture at a time, and
keep each report the same: the operand test against llvm-objdump and the
snapshots tell. The musl build of the CLI runs about the same number of
instructions as the glibc build, so its remaining gap is in how fast
musl runs them, as in `memcmp`.
