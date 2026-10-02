# TODO

## Check fixes on ARM32, Thumb-2 and MIPS

Four Apple CVE fixes, all AArch64, put each fix in the top 19 rows with
`--sort added`. Find published patch diffs of OpenWrt or router firmware
CVEs, compare the two releases, and add a report to `real-life-reports/`
for each. This tells if the default sort holds on the other sets.

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
between clang and GCC, 73 score 1.00, and most are byte-identical twins,
as tinyxml2's `XMLNode::ToComment` and `XMLNode::ToText`, which both
return null, and `MemPool<52>::Free` and `MemPool<60>::Free`. Nothing in
their code tells them apart; only names or callers could.

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

## Report a changed short text

A change to a text of fewer than four bytes, such as `"%d"` to `"%u"`, is not
reported, because a word that holds a small pointer or number reads as such a
text by chance. Knowing which data is read-only does not settle it: the two
false texts measured, a panic location of Rust and a table of tinyxml2, are
read-only too, and a linked library merges its string sections into
`.rodata`, so their `SHF_STRINGS` flag is gone. What might: a string pool
holds texts back to back, so a short text with a NUL before it and another
text after its own NUL is likely real.

## Recover the last functions of a stripped library

`tests/boundaries.rs` locks how well the scan recovers the functions of the
stripped releases: 45863 of 46006 exact, 44 starts missed and 55 invented,
over ARM, Thumb-2, AArch64 and MIPS, with the PLT left out. By cause:

- Missed where GCC shrink-wraps: the function tests and returns before it
  pushes, so no prologue opens it, as `little2_scanPi` and `os_execute` for
  ARM.
- Missed after a call that does not return through the GOT, where the next
  function is a leaf with no frame, as `errorProcessor` after
  `__assert_fail` in expat for MIPS. The scan does not know the names of
  what it calls.
- Missed after a pool that no load names, as `codebinexpval` for ARM.
- Invented inside a function after an internal return on ARM, as in the
  two `scanLt` functions of expat, and inside Lua's `math_ceil` and
  `math_floor`.
- Some invented starts are no fault: the lazy binding stubs of MIPS are
  code that no symbol names. The test leaves out only the PLT.

## Scan a stripped or raw binary that mixes A32 and Thumb-2

With symbols, each function of an ARM library is read in the set bit 0 of
its symbol names, and the `mixed` backports, half A32 and half Thumb-2,
name exactly the functions each fix touched. A stripped library keeps that
bit only for what it exports, and a raw image has none, so the scan still
reads the whole image in one set. A call says which set its target is in
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

## Read MIPS16e

Some MIPS firmware is built compressed, as MIPS16e, with 16 and 32-bit
instructions mixed and bit 0 of a function's address marking the mode,
as on Thumb-2. The decoder reads only standard MIPS32, so such code reads
as garbage. Measured on the root filesystems of the OpenWrt 22.03.5
images the tests download, about half of the MIPS binaries hold MIPS16
code: 77 of 156 on the WNDR3700 v2, 77 of 148 on the EAP245 v3, 94 of 177
on the VR200 and 76 of 152 on the GL-MT300N v2, by the MIPS16 flag of
their ELF header. None holds microMIPS. The kernels hold neither, so this
matters for a diff of user space, as of a daemon a CVE fix touched.
`rabbitizer` reads no MIPS16, so it needs a decoder of its own.

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
