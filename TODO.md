# TODO

## Tell twins apart that no instruction separates

The slots of a vtable (`RESEARCH.md` entry 15) and the class each
vtable names (entry 21) pair every byte-identical twin of the backports
built two ways right, `MemPoolT<52>::SetTracked` and
`MemPoolT<60>::SetTracked` of tinyxml2 too. The wrong pairs of the same
bytes left there are no twins, but a function and the static copy of the
other build, as `adler32_combine` at `-O2` and `adler32_combine_` at
`-Os`. A twin in no table, as a C function reached only by calls from
twins, can only be told apart by its name.

## Unpack more firmware containers

`--unpack` reads the containers the OpenWrt fixtures use: a zImage, alone
or in a FIT image or a sysupgrade tar, a uImage of a kernel or of an
lzma-loader, an ELF lzma-loader and a TP-Link v2 image, and the tests pin
its output to the bytes `fixtures/firmware.py` extracts. A zImage can
also hold a gzip or zstd kernel, and xz can filter for any instruction
set but IA-64 and RISC-V, which the unit tests check against streams that
`xz`, `gzip` and `zstd` wrote, and the gzip kernels of Alpine Linux
3.20.2 and 3.20.3 for ARMv7 unpack as `fixtures/firmware.py` extracts
them. No distribution found ships a zstd zImage to check against. Add the
containers still missing, as AVM EVA.

## Read the dyld shared cache

iOS and macOS keep most of their libraries only in the dyld shared cache.
`object` reads one image of a cache, but its calls to other images go
through stubs that the cache builder has bound or removed.

## Recover the last functions of a stripped library

`tests/boundaries.rs` locks how well the scan recovers the functions of the
stripped releases: 64488<!-- from boundaries.rs: exact --> of
64551<!-- from boundaries.rs: functions --> exact, 9<!-- from boundaries.rs: missed -->
starts missed and 3<!-- from boundaries.rs: invented --> invented,
over ARM, Thumb-2, AArch64, MIPS and x86, with the PLT and the lazy binding
stubs of MIPS left out (`RESEARCH.md`, "Function recovery, again"). 8 of
the 9 missed follow a call that never returns, to a function of the
library, and open with no frame: `auxsetnode` of Lua 5.3 by clang for
ARM and Thumb-2, which a pointer reaches, and `luaV_shiftl` by GCC for
MIPS, which only tail calls reach. Which functions of the library never
return can be read from the code, but where the compiler did not know,
it puts more of the caller after the call, and taking that for a new
function invented 12 more starts than it found (`RESEARCH.md`,
"Functions of the library that never return"). A start after such a
call needs a sign of its own, as a pointer to it that the scan does not
yet read.

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

## Read BE32

ARM big endian of BE8 is read, as `ld --be8` links it and every core
since ARMv6 runs it (`tests/be8.rs`). Older cores ran BE32, which stores
the instructions big endian too. The A32 and T32 decoders read
instructions little endian only. Add BE32 where a target shows it is
worth reading, with a fixture that GNU `ld` links without `--be8`.

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

## Read the rest of x86

x86-64 and 32-bit x86 ELF are read, with the backports built by GCC and
clang for both, and the releases built as executables that are not PIC
(`tests/nopic.rs`). An Intel Mach-O dylib is read too, but a universal
binary only by its AArch64 slice (`tests/macho.rs`). Still to do: Windows
PE files, which no fixture covers; the x86-64 slice of a universal binary;
and the published fixes of `real-life-reports/` for x86-64, where most of
them ship.

## Read RISC-V

New embedded parts (ESP32-C3, many SoCs) and Linux distributions run
RISC-V. Add RV32 and RV64 with the compressed (C) extension, which mixes
2-byte and 4-byte instructions. Addresses are built with `auipc` and
`addi` pairs.

## Read PowerPC

Older routers, automotive controllers and avionics firmware run 32-bit
PowerPC, big endian. Addresses are built with `lis` and `addi` pairs, and
calls return through the link register as on ARM.

## Read Xtensa

The ESP32 and ESP8266 run Xtensa, with 2-byte and 3-byte instructions and
the windowed register ABI. Few decoders exist, so the decoder is the
larger part of the work.

## Show the last instructions as IL

`--view il` still shows NEON work as the code prints it: the lift names
it `Vector` only.

## Pair better across a kernel upgrade

`tests/truth_kernels.rs` checks the pairs of the OpenWrt kernels against
the symbols and the source files in the DWARF of their builds, so a
renamed function, a twin and two static functions of one name each count
apart, and code that the debug file does not describe is left out. Over
the kernels, 0.69%<!-- from truth_kernels: all / wrong% --> of the pairs are
wrong, and at most 0.90%<!-- from truth_kernels: all / at most --> where the
543<!-- from truth_kernels: all / unproven --> pairs only the source file calls
renamed are wrong too. Across a kernel upgrade it is
1.01%<!-- from truth_kernels: 22.03.5/23.05.5 / wrong% --> to
1.77%<!-- from truth_kernels: 21.02.7/22.03.2 / wrong% -->.

Most wrong pairs still join a function the upgrade deleted to one of
similar code. The guessed source files (`RESEARCH.md`, entry 16) undo
such a pair where the other pairs join its two files elsewhere, but not
where both sides sit in one file, or in a file with few other pairs. A
score floor, a floor on the ratio of the sizes, a move to a closer free
function, or a cut-off on the score that chance gives (entry 18) costs
more right pairs than it saves. The pairs by callers and by references
are wrong 8.46%<!-- from truth_kernels: SameCallers / wrong% --> and
3.83%<!-- from truth_kernels: SameReferences / wrong% --> of the time; the pairs by references out of place split too evenly
on their context to undo.

Over the upgrades, 6167<!-- from truth_kernels: upgrades / pairs --> pairs of
functions stay free on both sides, though they share a name and a source
file: about four times the wrong pairs. Of these,
873<!-- from truth_kernels: upgrades / close --> score 0.7 or more, and most of
those sit out of place, where the context check undoes them rightly or a
rival scores within 0.03;
403<!-- from truth_kernels: upgrades / identical --> have the same
instructions, mostly small twins that no caller tells apart. See `RESEARCH.md`,
"The kernel upgrades, checked again".

## Learn from the versions of Assemblage-DeepHistory

`just test-research assemblage` pairs 8,872 releases of x86-64 files that
GCC built (see `RESEARCH.md`, "Assemblage-DeepHistory and entry 19"). It
found more to do, most valuable first:

- **C++ twins that no vtable names.** Entry 21 pairs the virtual
  functions of a class by the name its type information keeps
  (`RESEARCH.md`, "21: the class of a vtable"), but 21,504 twins still
  pair wrong in order. 6,021 are destructors, 4,808 of them one body that
  the symbols name twice, as `D1` and `D2`, which only the bench reads as
  two functions. Among the rest are template copies that no vtable holds,
  as those of z3 and fmt. Most of the wrong pairs by place that a report
  shows are near twins of this kind, one slot off: template copies of
  protobuf and draco, and the `log_Z3_*` functions of z3 (`RESEARCH.md`,
  "Assemblage-DeepHistory: the wrong pairs a report shows").
- **Pairs across compilers.** The dataset builds each release with GCC
  and with clang. Those pairs make a set across builds, like the
  backports, but far larger.
- **The rank of a fix.** Only 3 pairs at GCC `-O2` hold a fix that the CVE
  labels name. The other builds may hold more, to rank the fixes too.

## Rank a small fix that swaps no call

A call swapped for its bounded form now goes first, and a check before
an early exit counts as five instructions added (`RESEARCH.md`, "Calls
swapped for their bounded form" and "Checks before an early exit"). A
larger weight for a check lifts the Lua backport further but sinks
tinyxml2 and five published fixes. SPIDER's test that the code on the
way that does not exit stays the same did no better, nor did where the
value a check tests comes from. On the Ubuntu updates and the published
fixes, the fixes on a row are near the floor of their rank, and every
Ubuntu fix that changed the code is on a row (`RESEARCH.md`, "The fixes
no row shows"). More published fixes, with binaries on both sides, are
the next measure.

## Measure on more published fixes, and faster

Thirty-nine cases of fourteen published fixes, in
`examples/research_bench.rs --cves`, decide between the orders of the
report: each fix of `real-life-reports/`, and each OpenWrt fix for four
architectures, or for three before 21.02, where `malta` ships its root
file system only in the initramfs of its kernel. No order wins on them
(`RESEARCH.md`, "Published fixes, again"). Every OpenWrt advisory since
2025 with binaries on both sides is in, and the 2019 and 2020 fixes of
`libubox` and `uhttpd`. The `umdns` fixes of 24.10.6 (CVE-2026-30871 and
CVE-2026-30872), and the 2020 fixes of `relayd` and `umdns`
(CVE-2020-11752 and CVE-2020-11750), are out: neither package is in a
root file system, and the package feeds, on `archive.openwrt.org` too,
keep only the fixed build. The fixes of a vendor's firmware are next, and a published
fix in a kernel module for ARM: `tun`, `nf_conntrack` and `wireguard` of
OpenWrt 24.10.3 and 24.10.4 for ARMv7 read as unchanged but for
constants, which checks the reading but ranks no fix.

`tests/truth_ubuntu.rs` locks 218<!-- from truth_ubuntu: all / cases --> Ubuntu
security updates. Of the 128<!-- from truth_ubuntu: all / wrong --> wrong pairs
left, many are byte-identical twins (see "Tell twins apart
that no instruction separates"). Every fix that changed the code shows
on a changed row.

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
`x24` too. Ending the page there is right for the code that it reads
straight down, but past a jump, the tracker then guesses a page from a
function far above, and the texts it shows change where the code does
not (`RESEARCH.md`, "The low half of an A64 register"). It must follow
the value that each path brings to a block before it ends them.

## Rust has the idea of MIR, an in-between IL. Would that help this project?

## Our IL is cool, but maybe it could be even better!
1. Tui could show branches graphically, like other tools
2. IL could be an emulator?
3. IL could be an input/output simulator, might be nice for function diffing...
