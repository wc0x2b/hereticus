# fndiff

Compare two versions of a binary and find the functions that changed.

Two builds of one function can share almost no bytes. The same C source, built
at two optimization levels, gives this:

```
-O0   push {fp,lr} / mov fp,sp / sub sp,#8 / str / str / ldr / ldr / add / bx lr
-O2   add r0, r1, r0 / bx lr
```

A byte comparison calls these two different functions. `fndiff` calls them the
same one.

## State

Early. The parts below work and are tested. There is no matcher and no usable
command line tool yet, so `fndiff` cannot diff two binaries end to end.

| Part | State |
|---|---|
| ARM32 (A32) ELF reading | Works |
| Instruction decoding | Works, less NEON |
| Function recovery from symbols | Works |
| Instruction normalizing | Works for `-O1` and above |
| Function matching | Not started |
| Command line tool | Placeholder |

## Scope, and one thing outside it

`fndiff` matches builds at `-O1`, `-O2` and `-Os`. Measured on the test corpus,
18 of 18 pairs of the same function score 1.00, and the closest pair of
different functions scores 0.50.

Matching an unoptimized build against an optimized one is **out of scope**. The
obstacle is not spelling but algorithm. At `-O2` the compiler replaces the loop
in `sum_to` with the closed form `n(n+1)/2`, and turns the ten basic blocks of
`classify` into one block with conditional execution. Normalizing register
names cannot bridge a different algorithm. Measured similarity between `-O0`
and `-O2` is 0.31 for the same function against 0.21 for unrelated functions,
which is too close to separate. Closing that gap needs semantic comparison,
which is separate work.

This matters less than it sounds: shipped firmware is built optimized.

## Other limits

* **NEON is not decoded.** `yaxpeax-arm` 0.4 reports "incomplete decoder" for
  SIMD, and `clang` vectorizes automatically at `-O2`. Those words become
  opaque four-byte instructions, so decoding continues and stays aligned, but
  their content is not compared.
* **Stripped binaries yield nothing yet.** Functions come from the symbol
  table. Finding them in a binary without symbols needs scanning.
* **ARM32 only.** AArch64 is the next architecture. The `Arch` trait exists so
  that adding one does not disturb the normalizer or the matcher.

## Design

```
obj.rs      read ELF, recover functions from the symbol table
arch/       decode machine code behind a trait, so the decoder can be replaced
norm.rs     remove the detail a compiler picks freely
```

`norm.rs` holds the idea the project rests on. A compiler chooses registers,
frame offsets and branch addresses for reasons unrelated to what the code
computes, so normalizing discards them and keeps the shape of the work.

Dropping stack frame traffic raised same-function similarity from 0.13 to 0.31
and left unrelated functions at 0.21, so it removes noise rather than signal.

`NormInsn` keeps exact constants but leaves them out of equality. Both
properties are needed at once: a function whose threshold changed from 100 to
50 must still match the function it came from, and the changed value must still
be reportable afterwards.

## Testing

```
just quick-test   # 60 tests, about four seconds
just test         # the same, plus slow tests
just fixtures     # rebuild the ARM32 corpus
just fuzz <name>  # one property test under a fuzzer, needs nightly
```

Four kinds of test, each covering what the others cannot:

**Against `llvm-objdump`.** Every fixture function is decoded twice, once by
`fndiff` and once by `llvm-objdump`, and the results must agree on instruction
boundaries and mnemonics: 738 instructions in 64 functions. Operand text is not
compared, because the two tools spell the same encoding differently. This is
what catches a decoder that has lost sync.

**A generated corpus.** `fixtures/src/*.c` is compiled to ARM32 at four
optimization levels by `just fixtures`. Ground truth is known by construction:
the same function at two levels must match, two different functions must not.
`basic_v2.c` changes three functions on purpose, and those changes are the
ground truth for detection.

**Property tests.** `bolero` runs one test body as a property test on stable
and under a coverage-guided fuzzer on nightly. Reading a file must never panic,
whatever the bytes hold.

**Unit tests.** Named encodings that are easy to get wrong, such as the four
different ways an ARM function can return.

### Two bugs the tests caught

Recorded because each shows what a kind of test is for.

`yaxpeax`'s `total_offset()` counts words, not bytes. Every address after the
first was wrong by a factor of four. A unit test found it.

Less comfortably: that bug was then put back deliberately, and the first ten
property tests all passed with it present. Each compared the decoder against
itself, and a width that is wrong everywhere stays self-consistent. The tests
now state the four-byte width against the architecture, and check each address
against the position it must hold. A property test is only worth as much as the
property it states.

## Prior art

[BinDiff](https://github.com/google/bindiff),
[Diaphora](https://github.com/joxeankoret/diaphora) and Ghidra's BSim all solve
this problem well, and all need IDA or Ghidra.
[objdiff](https://github.com/encounter/objdiff) is the closest Rust project, but
it matches functions **by symbol name**, which is the one assumption a stripped
firmware image does not allow.

The gap `fndiff` aims at is a standalone command line tool that matches
functions without trusting their names.

## License

MIT or Apache-2.0, at your option.
