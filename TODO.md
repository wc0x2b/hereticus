# TODO

## Test C++ and Rust code

Every fixture and backport is C. C++ and Rust compilers emit code C does not:
long mangled names, templates and generics instantiated once per type,
inlining across whole crates, vtables and trait objects, unwind tables for
every function, and panic and exception paths. A small source edit can move
far more code than it does in C.

Add backport pairs in both languages, as `fixtures/backports.sh` builds zlib
and Lua: a real upstream fix to a C++ library and to a Rust crate, built for
ARM and both MIPS byte orders, with the functions the fix edits as the
answer. Check what a generic function changed in one instance does to the
others, and whether the matcher pairs monomorphized copies correctly.

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

## Hide gone and new data regions

`--show-data` hides a matched region that looks like data, but not one that
is gone or new. In a raw image of a shared library the headers and
`.rodata` show as removed and added functions. Judge those with
`Arch::contents` too, and hide them the same way.

## Split raw ARM images less

Without an exception index, a raw ARM scan still starts a function after a
return inside one: about 18 false starts in each backport library. The
`luaopen_base` extra in `KNOWN_EXTRAS` comes from one of them.

## Cache the fixtures in CI

The tests now download about 150 MB of OpenWrt images and build libraries
in a container. Cache `fixtures/build` in CI, keyed on the pinned SHA-256
values and on `fixtures/`, so a run fetches and builds only what changed.

## Bring the README up to date

The README does not mention `--show-data`, the MIPS `--arch` values, or
`just firmware` and `just backports`.
