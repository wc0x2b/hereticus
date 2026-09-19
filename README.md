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

Works end to end for ARM32 objects, with or without symbols.

```console
$ fndiff before.o after.o
FUNCTION                CHANGE          SCORE  MATCHED BY
mul_by_constant         changed values   1.00  identical shape
classify                changed values   1.00  identical shape
call_chain              changed values   1.00  identical shape
array_max -> array_min  changed          0.84  similar

8 matched (4 unchanged, 4 changed), 0 gone, 0 new
```

Two things to notice, both from the test corpus. `array_max` was renamed *and*
rewritten, and is still matched to its counterpart. `call_chain` is reported
although its source never changed: at `-O2` the compiler inlines
`mul_by_constant` into it, so the edited constant lands there too.

The same comparison on stripped copies of those two files gives the same
answer, with addresses in place of names:

```console
$ fndiff before-stripped.o after-stripped.o
FUNCTION  CHANGE          SCORE  MATCHED BY
sub_8     changed values   1.00  identical shape
sub_3c    changed values   1.00  identical shape
sub_80    changed values   1.00  identical shape
sub_90    changed          0.84  similar

8 matched (4 unchanged, 4 changed), 0 gone, 0 new
```

| Part | State |
|---|---|
| ARM32 (A32) ELF reading | Works |
| Instruction decoding | Works, less NEON |
| Function recovery from symbols | Works |
| Instruction normalizing | Works for `-O1` and above |
| Function matching | Works |
| Command line tool | Works |
| Function recovery without symbols | Works |

## Use

```console
fndiff before.o after.o              # what changed
fndiff --all before.o after.o        # every function
fndiff --ignore-names a.o b.o        # match from the code alone
fndiff --format compact a.o b.o      # tab separated, for scripts
fndiff --exit-code a.o b.o           # exit 1 when anything changed
```

Exit status is 0 when nothing changed, 1 with `--exit-code` when something did,
and 2 when the input could not be read.

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
* **Recovery without symbols is exact only where the ARM exception index
  survives.** `.ARM.exidx` lists one entry per function and outlives
  stripping, and every fixture carries one. Without it the scan falls back to
  call targets and to the code after a return, which finds every real function
  but also splits some at internal returns.
* **ARM32 only.** AArch64 is the next architecture. The `Arch` trait exists so
  that adding one does not disturb the normalizer or the matcher.

## Design

```
obj.rs       read ELF and find its functions
scan.rs      recover functions when there is no symbol table
arch/        decode machine code behind a trait, so the decoder can be replaced
norm.rs      remove the detail a compiler picks freely
matching.rs  pair the functions of one binary with those of another
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

`matching.rs` runs an ordered cascade: identical bytes, then identical
normalized instructions, then names, then similarity above a threshold. Each
stage pairs what it is sure about and removes it from the pool. A confident
answer is therefore never overruled by a guess, and the expensive all-pairs
stage runs only on what the cheap stages could not place.

Names come third, not first. A name is good evidence when it is there, but a
firmware image has none and a renamed function keeps its behavior, so evidence
from the code wins. With `--ignore-names` the cascade skips that stage
entirely, and on the test corpus it still matches every function.

`scan.rs` finds the functions when the symbol table is gone. The ARM exception
index is the strongest source: it lists one entry per function and survives
stripping, and where it is present the weaker sources are not consulted at all.
Guessing on top of an exact answer only does harm, because an internal `bx lr`
would split one function into two.

## Testing

```
just quick-test   # 113 tests, about four seconds
just test         # the same, plus slow tests
just fixtures     # rebuild the ARM32 corpus
just fuzz <name>  # one property test under a fuzzer, needs nightly
```

Six kinds of test, each covering what the others cannot:

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

**Stripped copies of that corpus.** Every fixture exists twice, so the symbol
table of one is the answer for the other. Recovery is exact at every
optimization level: right address, right size, nothing invented. The same
comparison run on stripped files must give the same pairs and the same changes
as on the originals.

**Property tests.** `bolero` runs one test body as a property test on stable
and under a coverage-guided fuzzer on nightly. Reading a file must never panic,
whatever the bytes hold.

**Snapshot tests.** `insta` locks what the command line tool prints, so a
refactor cannot quietly change the output a script depends on.

**Unit tests.** Named encodings that are easy to get wrong, such as the four
different ways an ARM function can return.

### Bugs the tests caught

Recorded because each shows what a kind of test is for.

`yaxpeax`'s `total_offset()` counts words, not bytes. Every address after the
first was wrong by a factor of four. A unit test found it.

Less comfortably: that bug was then put back deliberately, and the first ten
property tests all passed with it present. Each compared the decoder against
itself, and a width that is wrong everywhere stays self-consistent. The tests
now state the four-byte width against the architecture, and check each address
against the position it must hold. A property test is only worth as much as the
property it states.

The third came from the corpus. `array_max` became `array_min`, and `fndiff`
reported it as unchanged. The edit sits inside NEON instructions the decoder
cannot read, and every unreadable instruction normalized to the same thing, so
the change vanished. Unreadable bytes now carry their raw word. Reporting no
change for a function that changed is worse than admitting the bytes cannot be
read.

Three more came from measuring recovery against the symbol table rather than
assuming it worked. `yaxpeax` decodes the ARM `nop` as `Opcode::Invalid` while
returning success, so linker padding looked like a real instruction. A
relocatable object holds unrelocated calls encoding `bl .-8`, which reads back
as the call site, so every call appeared to start a function. And a recovered
function ran to the start of the next one, swallowing the padding between them,
which made `array_max` at `-Os` look changed when only stripping had happened.

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
