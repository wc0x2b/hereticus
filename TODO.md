# TODO

## Unpack firmware containers

`fixtures/firmware.py` unpacks FIT images, uImages, zImages, the TP-Link v1
and v2 headers and the lzma-loader to reach a stub and a kernel. A user has
to do the same by hand before the tool can read a vendor image. Read these
containers directly, and add the formats still missing, such as AVM EVA.

## Cache the fixtures in CI

The tests now download about 150 MB of OpenWrt images and build libraries
in a container. Cache `fixtures/build` in CI, keyed on the pinned SHA-256
values and on `fixtures/`, so a run fetches and builds only what changed.

## Report a changed short text

A change to a text of fewer than four bytes, such as `"%d"` to `"%u"`, is not
reported, because a word that holds a small pointer or number reads as such a
text by chance. Telling the two apart needs to know which data is read-only:
the ELF segment flags give that for a shared library, but a raw image has
none.

## Recover the last functions of a stripped library

`tests/boundaries.rs` locks how well the scan recovers the functions of the
stripped releases: 45579 of 46006 exact, 195 starts missed and 85 invented,
over ARM, Thumb-2, AArch64 and MIPS, with the PLT left out. Most of what is
left is Thumb-2. By cause:

- Missed after a jump back, where nothing calls the next function and no
  table points at it, as some static functions of Lua for ARM with GCC.
- Missed after a call that does not return, where the next function has no
  prologue, or after a pool whose last word decodes as `cdp2` or `mrc2`.
- Invented inside a function after an internal return on ARM, as in the
  two `scanLt` functions of expat, and inside the MIPS `prologTok` and
  Lua's `math_ceil` and `math_floor`, where the cause is not yet known.
- Some invented starts are no fault: the lazy binding stubs of MIPS are
  code that no symbol names. The test leaves out only the PLT.

## Find the functions of a raw Thumb-2 image that only pointers reach

A raw image holds no relocations and no dynamic symbol table, so a
Thumb-2 function that only a vtable or a table of callbacks points at, and
that opens with no prologue, has no start the scan can see. It joins the
tail of the function before, pool and all. And LLD's range extension
thunks, whose bytes hold a distance, pair crossed where two reach the same
distance, since a raw image names no PLT stub they reach. `KNOWN_EXTRAS` in
`tests/backports.rs` lists the 96 false reports these make. Reading the
words of the data that hold an address with bit 0 set, in the code, as
starts could find the functions, where the data can be told from the code.
Pairing thunks by the stub they reach, once stubs pair, could pair them.

## Read a text at the start of .rodata in a raw image

A raw image has no sections, so a string at the first byte of `.rodata`,
right after the code, follows no NUL and is not read as text. A change to
it goes unreported: zlib 1.3 changes `zlibVersion` so, and the raw
readings of the releases miss it. The end of the code, as the scan finds
it, could stand for the start of the section.

## Read a binary that mixes A32 and Thumb-2

An ARM binary is read as A32 or as Thumb-2 as a whole, by what most of its
function symbols say. A binary that holds both, as much ARM user space
does, has its minority read in the wrong set. Bit 0 of each symbol, or of
each pointer to a function, says which set that function is in, so the
decoder could be chosen per function.

## Build the Rust fixture for Thumb-2

The smallvec harness is built for A32 only, and the tests skip Thumb-2 for
it. Build it for `thumbv7neon-unknown-linux-gnueabihf` or a soft-float
Thumb-2 target, so Rust code is measured in Thumb-2 too.

## Align the PLT stubs of a raw AArch64 image

A raw image names no PLT stub, so the stubs of two builds align by their
order and by the callers that call them. Where a new import adds a stub
in the middle of the others, the stubs after it shift once more, and the
alignment keeps the old shift one stub too long: the callers of that stub
then read as calling another function. `KNOWN_EXTRAS` in
`tests/backports.rs` lists 19 such false reports in Lua and tinyxml2 for
AArch64. The slot each stub jumps through, in the order of the global
offset table, could anchor the alignment.

## Measure older ARM cores

The fixtures are built for ARMv7-A only. Much firmware still runs on
ARMv5TE and ARMv6 (Kirkwood, older Broadcom), where there is no `movw` or
`movt`, a return can be `ldm sp!, {..., pc}` or `mov pc, lr`, and
interworking goes through `bx`. Build the fixtures with `-march=armv5te`
and `-march=armv6` and lock their tallies.

## Read big-endian ARM

Some networking parts run ARM big endian (BE8, or BE32 on older cores).
The A32 and T32 decoders read little endian only: BE8 keeps instructions
little endian but data big endian, and BE32 swaps both. Add the byte
order to the ARM architectures, and a fixture built with `-mbig-endian`.

## Measure Cortex-M firmware

Cortex-M firmware is Thumb only (ARMv6-M, ARMv7-M, ARMv8-M), bare metal,
and shipped as a raw image that opens with a vector table. The Thumb-2
decoder reads its instructions, but nothing measures it: no fixture is
built for `thumbv6m` or `thumbv7m`, ARMv6-M lacks most 32-bit forms, and
the vector table names every handler's start, which the scan could read.

## Read the ARM hard-float ABI and NEON

The fixtures use `-mfloat-abi=softfp`. Most ARMv7 Linux distributions use
`hard`, which passes floats in VFP registers, and `yaxpeax-arm` 0.4 reads
no NEON (see the README), so vectorized code stays opaque. Build a
hard-float fixture, and decode NEON, with a newer `yaxpeax-arm` or a
decoder of its own.

## Read MIPS64

Cavium Octeon and some newer MIPS routers run MIPS64 (n64 or n32 ABI).
The decoder reads MIPS32 only: no `ld`, `sd`, `daddiu`, or 64-bit
pointers, and the global offset table and `%hi`/`%lo` pairs differ (n64
builds addresses with `lui`, `daddiu` and `dsll`). Add an architecture and
fixtures for `mips64-linux-gnuabi64`.

## Read MIPS16e and microMIPS

Some MIPS firmware is built compressed, as MIPS16e or microMIPS, with 16
and 32-bit instructions mixed and bit 0 of a function's address marking
the mode, as on Thumb-2. The decoder reads only standard MIPS32, so such
code reads as garbage. Measure how often OpenWrt targets use it before
building it.

## Read MIPS32 release 6

MIPS32r6 re-encodes branches, removes `lwl` and `lwr` and the branch
likely forms, and adds compact branches with no delay slot. The decoder
assumes release 2. Few shipped parts use r6, so first confirm a target
worth reading.
