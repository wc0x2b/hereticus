# TODO

## Tell twins apart that no instruction separates

The slots of a vtable (`RESEARCH.md` entry 15) paired 54 of the 58
byte-identical twins that paired wrong between clang and GCC. The 4 left
are `MemPoolT<52>::SetTracked` and `MemPoolT<60>::SetTracked` of
tinyxml2, in two comparisons: find what keeps their tables apart. A twin
in no table, as a C function reached only by calls from twins, can only
be told apart by its name.

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
stripped releases: 45937 of 46006 exact, 9 starts missed and 3 invented,
over ARM, Thumb-2, AArch64 and MIPS, with the PLT and the lazy binding
stubs of MIPS left out (`RESEARCH.md`, "Function recovery, again"). 8 of
the 9 missed follow a call that never returns, to a function of the
library, and open with no frame: `auxsetnode` of Lua 5.3 by clang for
ARM and Thumb-2, which a pointer reaches, and `luaV_shiftl` by GCC for
MIPS, which only tail calls reach. Telling such a call from one that
returns needs to know which functions of the library never return.

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

## Rank a fix of one instruction that changes a callee

The `procd` fix of CVE-2026-30874 adds one instruction and turns a call
of `strcmp` into one of `strncmp`, with `"PATH"` now `"PATH="`. Its row
counts the callee and the text, but it ranks 18 to 20 of 25 to 29 under
`added`. An order that adds the two counts lifts it to 16 or 17, and
ranks the backports and the Ubuntu updates worse (`RESEARCH.md`,
"Callees and texts in a changed pair"). Find what else tells such a fix
from the other edits of a large update that change a callee or a text.

## Measure on more published fixes, and faster

Thirty-three cases of twelve published fixes, in
`examples/research_bench.rs --cves`, decide between the orders of the
report: each fix of `real-life-reports/`, and each OpenWrt fix for four
architectures. No order wins on them (`RESEARCH.md`, "Published fixes,
again"). Every OpenWrt advisory since 2025 with binaries on both sides
is in, but the `umdns` fixes of 24.10.6 (CVE-2026-30871 and
CVE-2026-30872): `umdns` is in no root file system, and the package
feeds keep only the latest build. Older
ones (the 19.07 fixes of `libubox`, `relayd`, `umdns` and `uhttpd`) and
the fixes of a vendor's firmware are next, and a published fix in a
kernel module for ARM: `tun`, `nf_conntrack` and `wireguard` of OpenWrt
24.10.3 and 24.10.4 for ARMv7 read as unchanged but for constants, which
checks the reading but ranks no fix.

`tests/truth_ubuntu.rs` locks 218 Ubuntu security updates. Of the 151
wrong pairs left, many are byte-identical twins (see "Tell twins apart
that no instruction separates"), and the fix shows on no changed row in
42 updates.

The CLI on the MIPS kernel of the VR200 takes 12 seconds built for musl,
the target `.cargo/config.toml` picks; "Make the matching faster" below
says where the time goes.

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
