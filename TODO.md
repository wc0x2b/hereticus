# TODO

## Check fixes on ARM32, Thumb-2 and MIPS

Four Apple CVE fixes, all AArch64, put each fix in the top 19 rows with
`--sort added`. Find published patch diffs of OpenWrt or router firmware
CVEs, compare the two releases, and add a report to `real-life-reports/`
for each. This tells if the default sort holds on the other sets.

## Write the reports of the other Apple CVE fixes

CVE-2026-28825 (smbfs), CVE-2025-24257 (IOGPUFamily) and CVE-2021-30883
(AppleCLCD, iPhone 11) are confirmed, but have no report in
`real-life-reports/`. The A14 and later iPhones run the display driver on
the DCP, so CVE-2021-30883 needs a device without one.

## Read a fileset kernelcache directly

A kernelcache of iOS 15 and later is an `MH_FILESET` that holds each kext
as its own Mach-O. Read whole, it gives 648 functions, so a user must
extract the kexts with `ipsw` first. Read each `LC_FILESET_ENTRY`.

## Lift more of what a guard can be

`il` reads a compare and the branch on it as one guard on AArch64, A32,
Thumb-2 and MIPS32. Measured against the symbols, that paired 231 more
functions right and 61 more wrong over the cross builds, mostly twins
such as `math_max` and `math_min`. Still read as plain work:

- A compare whose result a `cset`, a `csel` or a conditional instruction
  of A32 uses, in place of a branch.
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

## Unpack firmware containers

`fixtures/firmware.py` unpacks FIT images, uImages, zImages, the TP-Link v1
and v2 headers and the lzma-loader to reach a stub and a kernel. A user has
to do the same by hand before the tool can read a vendor image. Read these
containers directly, and add the formats still missing, such as AVM EVA.

## Read the pointers of an arm64e Mach-O

An arm64e binary stores each pointer in its data as a chained fixup, with
the pointer authentication bits in its top bits. A pointer to a function
or a text thus does not read as an address, and a changed text that only a
pointer reaches is not reported. Decode `LC_DYLD_CHAINED_FIXUPS`, which the
`object` crate parses, and give the loaded memory the bound addresses.

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
