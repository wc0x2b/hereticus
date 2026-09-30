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
