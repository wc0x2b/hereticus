# Examples

The commands you use most:

```console
$ hereticus before.elf after.elf                    # what changed
$ hereticus --all before.elf after.elf              # every function
$ hereticus --diff array_max before.elf after.elf   # the diff of one function
$ hereticus --diff-all before.elf after.elf         # the diff of every changed function
$ hereticus --view il --diff array_max a.elf b.elf  # the diff as IL statements
$ hereticus --tui before.elf after.elf              # browse, sort and open diffs in the terminal
$ hereticus --save p.json before.elf after.elf      # keep the match, to open again at once
$ hereticus --tui --open p.json                     # go on where the last save stopped
$ hereticus --ignore-names before.elf after.elf     # match from the code alone
$ hereticus --format markdown before.elf after.elf  # a table to paste into a document
$ hereticus --format json before.elf after.elf      # for another tool to read
$ hereticus --raw --base 0x08000000 v1.bin v2.bin   # a flash dump, no ELF header
$ hereticus --raw --arch mips32 --unpack stub a.bin b.bin  # the decompressor in two firmware images
```

The sections below run some of them on the test fixtures, and show the
output. For published security fixes, see
[Real-Life Examples](./real-life-examples.md).

## A Decompressor Stub

Two OpenWrt releases for the same device, 22.03.2 and 22.03.5 for the Netgear
EX6100v2. The ARM decompressor stub is 15 KB of shipped code with no symbols,
and 43 of its 15,351 bytes changed:

<!-- output: --format markdown --raw --base 0x80208000 fixtures/build/openwrt/arm-ex6100v2-stub-22.03.2.bin fixtures/build/openwrt/arm-ex6100v2-stub-22.03.5.bin -->
```console
$ hereticus --format markdown --raw --base 0x80208000 stub-22.03.2.bin stub-22.03.5.bin
```

| FUNCTION       | CHANGE         | SCORE | +/-/~ | TOUCHED | MATCHED BY |
|----------------|----------------|-------|-------|---------|------------|
| `sub_80208000` | changed        | 0.98  | 1/1/1 | -       | similar    |
| `sub_8020a338` | changed        | 0.94  | 0/0/1 | -       | similar    |
| `sub_80208af8` | changed        | 0.95  | 0/0/1 | -       | similar    |
| `sub_80208a18` | changed        | 0.96  | 0/0/1 | -       | similar    |
| `sub_80209154` | changed        | 0.96  | 0/0/1 | 1 mem   | similar    |
| `sub_8020b1f8` | changed        | 0.98  | 0/0/1 | -       | similar    |
| `sub_80208e08` | changed unread | 0.98  | 0/0/1 | -       | similar    |
| `sub_8020a3bc` | changed        | 1.00  | 0/0/1 | -       | similar    |

67 matched (57 unchanged, 10 changed), 0 gone, 0 new

1 changed only a constant, hidden. Use --show-retouched to list them.

1 data region changed, hidden. Use --show-data to list them.
<!-- end output -->

## Two Firmware Releases

Two versions of one firmware, built the same way, one release apart:

<!-- output: --format markdown --show-retouched fixtures/build/O2/firmware.o fixtures/build/O2/firmware_v2.o -->
```console
$ hereticus --format markdown --show-retouched fw-v1.elf fw-v2.elf
```

| FUNCTION          | CHANGE         | SCORE | +/-/~   | TOUCHED                                  | MATCHED BY      |
|-------------------|----------------|-------|---------|------------------------------------------|-----------------|
| `dispatch`        | changed        | 0.62  | 21/11/5 | 4 branch, 1 call, 6 jump, 6 mem, 1 const | same name       |
| `check_header`    | changed        | 0.31  | 8/1/0   | 1 branch, 1 call, 1 mem                  | same name       |
| `handle`          | changed        | 0.82  | 8/4/2   | 1 branch, 1 call, 1 jump, 1 mem, 1 const | same name       |
| `validate_length` | changed values | 1.00  | -       | -                                        | identical shape |
<!-- end output -->

The `1 call` on `check_header` is an added call to an authentication routine.
The `1 const` on `handle` is a bound that moved from 1024 to 512, arriving
through inlining: that function was never edited. Both would otherwise read as
plain `changed`, and the constant is invisible to every other column, because
the edit around it is far too large to read as `changed values`.

## The Diff of One Function

To see what changed inside one function:

<!-- output: --diff mul_by_constant fixtures/build/O2/basic.o fixtures/build/O2/basic_v2.o -->
```console
$ hereticus --diff mul_by_constant before.elf after.elf
mul_by_constant
- mov r1, 0x25
+ mov r1, 0x29
  mul r0, r0, r1
  bx lr
```
<!-- end output -->

`--view il` shows each instruction as the IL reads it, the same on every
architecture, and a branch with the compare it tests, as
`if (w0 <= 0) goto $-0x40`:

<!-- output: --view il --diff mul_by_constant fixtures/build/O2/basic.o fixtures/build/O2/basic_v2.o -->
```console
$ hereticus --view il --diff mul_by_constant before.elf after.elf
mul_by_constant
- r1 = 0x25
+ r1 = 0x29
  r0 = r0 * r1
  return
```
<!-- end output -->
