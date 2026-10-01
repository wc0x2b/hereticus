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
stripped releases: 45795 of 46006 exact, 72 starts missed and 79 invented,
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

## Scan a stripped or raw binary that mixes A32 and Thumb-2

With symbols, each function of an ARM library is read in the set bit 0 of
its symbol names, and the `mixed` backports, half A32 and half Thumb-2,
name exactly the functions each fix touched. A stripped library keeps that
bit only for what it exports, and a raw image has none, so the scan still
reads the whole image in one set. A call says which set its target is in
(`bl` keeps the set, `blx` switches), and so do bit 0 of a pointer and the
unwind index, so a scan could follow them per function.

## Build the Rust fixture for Thumb-2

The smallvec harness is built for A32 only, and the tests skip Thumb-2 for
it. Build it for `thumbv7neon-unknown-linux-gnueabihf` or a soft-float
Thumb-2 target, so Rust code is measured in Thumb-2 too.

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
