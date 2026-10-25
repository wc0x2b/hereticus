# Troubleshooting

## The Fix Is Not on the First Rows

- **Search the diffs.** An advisory often names a text, a format string or
  a function of the C library. Search the diff of each changed function
  for it:

  ```console
  $ hereticus --view il --diff-all before.bin after.bin | grep -E '^(sub_|[-+].*PATH)'
  ```

  See [CVE-2026-30874](./real-life-examples/cve-2026-30874.md) for this
  search on a real fix.
- **Show the hidden rows.** A fix that changes only a constant, as a
  limit from 1024 to 512, is `changed values`, and is hidden. Use
  `--show-retouched`.
- **Change the order.** `--sort rare` puts first the code that few other
  functions add. It helps where a new compiler or new flags changed many
  functions in the same way.
- **Look at the gone and new functions.** A fix can rewrite a function so
  much that no score pairs it. The list after the table names the closest
  candidate and the function in the same place.

## Almost Every Function Changed

- **The two builds use different compilers or flags.** `hereticus` makes
  `-O1`, `-O2` and `-Os` builds alike, but not an `-O0` build and an
  optimized one. A release that changes the compiler changes much of the
  code, and the report shows that.
- **A raw image has the wrong `--arch`.** A Cortex-M image is Thumb-2, so
  give `--arch thumb2`, not `arm32`. A MIPS image is big-endian or
  little-endian: `mips32-be` or `mips32`.
- **A raw image has the wrong `--base`.** A wrong base gives a report
  against the wrong addresses. See below.

## Error and Warning Messages

### `--raw needs --base, because a raw image does not say where it loads`

Give the load address with `--base`. Where the words of the image show
the base, the message ends with `The words that point into it show that it
loads at --base <address>, which --base auto takes`. Check that address
against the datasheet or the boot log of the device before you use it.

### `<file> may not load at <address>: ...`

The base that you gave looks wrong. The rest of the message tells why:

- `<count> words look like addresses, but none point into the image at
  this base`: the image holds a table of pointers, and no pointer fits
  this base.
- `<count> of <count> calls land on a function start at this base, but
  <count> do at <address>`: another base fits the calls better.

### `a raw image has no exception index, so function boundaries are recovered from the code and are approximate`

This is a note, not an error. A raw image has no symbols, so `hereticus`
finds its functions from the code. See
[Finding Functions](./methods.md#finding-functions).

### `cannot read <file>: cannot parse object: ...`

The file is not an ELF or Mach-O file. For a flash dump or a kernel
image, use `--raw`. For a firmware image, use `--unpack` too. See
[Raw Images and Firmware](./usage.md#raw-images-and-firmware).

### `cannot read <file>: unsupported architecture: ...`

The file is for an architecture that `hereticus` does not decode. See
[Limits](./usage.md#limits).

### `cannot read <file>: object has no executable code`

The file holds no code section or segment, as a file of data only.

### `cannot read <file>: object has code, but no function could be found in it`

The code holds nothing that starts a function. For a raw image, check
`--arch` and `--base`, and that the image holds code from its first byte.

## A Function Is Missing

- `--functions` lists each function that `hereticus` finds in one binary.
  Check that the function is there.
- A region that looks like data, not code, is hidden. Use `--show-data`.
- In a stripped binary, a function that nothing calls and that starts with
  no prologue can join the function before it.

## Two Functions Are Paired Wrongly

The `MATCHED BY` column tells why the two paired. `identical bytes` and
`identical shape` are almost always right. `similar` and `same place` are
the weakest reasons. A higher `--threshold` pairs fewer functions by
similarity.

When a pair is wrong, please
[open an issue](https://github.com/wc0x2b/hereticus/issues) with
the two binaries, or with the commands to get them.
