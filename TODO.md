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

## Report a changed text

A function whose only change is a string, such as a format that goes from
`"%s"` to `"%.*s"`, reads as unchanged, because normalizing drops the
address of the string. The texts each function points at are now known
(`Prepared::texts`), and they split twins. Reporting a changed text as a
change was tried, and it reported many functions that the backport fixes
did not touch. Three causes:

- GCC for ARM loads one section anchor for all the strings of a file and
  adds an offset later. The text at the anchor is the first string of the
  file, so when a fix adds a string, every function of the file seems to
  change. Follow the `add rX, anchor, #offset` to the real string.
- Rust keeps a string as a pointer and a length, with no NUL, so reading
  to a NUL runs into the strings after it. Read the length, or skip text
  that no NUL comes before.
- Some MIPS functions at `-O3` in tinyxml2, such as `StrPair::GetStr`, not
  yet examined.
