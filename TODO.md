# TODO

## Check a MIPS load address with `jal` targets

`jal` holds an absolute target, so at the right base most targets land on a
function prologue (`addiu sp, sp, -N`). On the TP-Link VR200 kernel (Lantiq
xRX200), 58113 of 95023 targets land on a prologue at `0x80002000`, and
about 2000 at the neighbouring pages. The pointer count of `check_base`
cannot tell those bases apart on an image this large.

Use this as a second test in `raw::check_base` for MIPS, and to suggest a
base when none is given.

## Read the MIPS DSP ASE

Between 106 and 252 words of real code in each OpenWrt MIPS kernel still do
not decode. They are DSP ASE instructions: `mfhi` and `mflo` on a second
accumulator, and `extr`. Add them to `hereticus/src/arch/mips32.rs`.

## Follow a split function across its pieces

A scan without symbols splits a function when the compiler puts a second
piece, with its own frame, after the first return. The later piece reaches
the global offset table through a register the earlier piece set, which the
scan cannot see, so a table offset reads as a changed constant. The backport
tests list the two known cases in `KNOWN_EXTRAS`:

- `_tr_align`, zlib, MIPS `-Os`, stripped and raw.
- `luaopen_base`, Lua, ARM `-Os`, raw.

Carrying the global pointer, and any base built from `pc`, from one
recovered function into the next one would remove both.
