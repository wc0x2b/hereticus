# TODO

## Read Thumb-2

The ARM decoder reads A32 only, and `--arch arm32` says Thumb is not
supported. Most Cortex-M firmware, and much ARM user space, is Thumb-2, so
a large share of real ARM firmware cannot be read. Thumb mixes 16-bit and
32-bit instructions, so the scanner, the literal pool rules and the base
check must all handle a width that is not fixed.

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
stripped releases: 27344 of 27500 exact, 47 starts missed and 102 invented.
What is left, by cause:

- Missed after a jump back, where nothing calls the next function and no
  table points at it, as some static functions of Lua for ARM with GCC.
- Missed after a call that does not return, where the next function has no
  prologue, or after a pool whose last word decodes as `cdp2` or `mrc2`.
- Invented inside a function after an internal return on ARM, as in the
  two `scanLt` functions of expat, and inside the MIPS `prologTok` and
  Lua's `math_ceil` and `math_floor`, where the cause is not yet known.
- About 40 of the invented starts are no fault: PLT headers and the lazy
  binding stubs of MIPS are code that no symbol names. The test could
  count them apart.
