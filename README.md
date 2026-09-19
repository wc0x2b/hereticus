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
FUNCTION                CHANGE          SCORE  +/-/~       MATCHED BY
array_max -> array_min  changed unread   0.84  0/0/3       similar

8 matched (4 unchanged, 4 changed), 0 gone, 0 new
3 changed only a constant, hidden. Use --show-retouched to list them.
```

`array_max` was renamed *and* rewritten, and is still matched to its
counterpart.

The `+/-/~` column counts the instructions the edit added, removed and
rewrote, and a dash means it touched none. `changed unread` says the bytes
differ inside instructions the decoder cannot read, so the tool reports the
difference without claiming to know whether it edited code or a word of stored
data.

### What the default hides

A function that scores a perfect 1.00 *and* touched no instruction changed
nothing but a constant. These outnumber the real edits on anything the size of
a kernel, so they are held back and counted in the footer instead. Both tests
must pass to hide a function: an instruction that was rewritten is a real edit
whatever the pair scores.

```console
$ fndiff --show-retouched before.o after.o
FUNCTION                CHANGE          SCORE  +/-/~       MATCHED BY
mul_by_constant         changed values   1.00  -           identical shape
classify                changed values   1.00  -           identical shape
call_chain              changed values   1.00  -           identical shape
array_max -> array_min  changed unread   0.84  0/0/3       similar

8 matched (4 unchanged, 4 changed), 0 gone, 0 new
```

`call_chain` is worth a look: its source never changed, but at `-O2` the
compiler inlines `mul_by_constant` into it, so the edited constant lands there
too. `--all` implies this flag.

The same comparison on stripped copies of those two files gives the same
answer, with addresses in place of names:

```console
$ fndiff before-stripped.o after-stripped.o
FUNCTION  CHANGE          SCORE  +/-/~       MATCHED BY
sub_90    changed unread   0.84  0/0/3       similar

8 matched (4 unchanged, 4 changed), 0 gone, 0 new
3 changed only a constant, hidden. Use --show-retouched to list them.
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
| Raw images with no container format | Works, with `--base` |
| Progress while it runs | Works, on standard error |

## Use

```console
fndiff before.o after.o              # what changed
fndiff --all before.o after.o        # every function
fndiff --show-retouched a.o b.o      # add the ones that only changed a constant
fndiff --ignore-names a.o b.o        # match from the code alone
fndiff --format compact a.o b.o      # tab separated, for scripts
fndiff --exit-code a.o b.o           # exit 1 when anything changed
fndiff --progress never a.o b.o      # no progress bar

# A firmware image dumped from flash, with no ELF header
fndiff --raw --base 0x08000000 v1.bin v2.bin
```

Exit status is 0 when nothing changed, 1 with `--exit-code` when something did,
and 2 when the input could not be read.

A comparison of two firmware images takes seconds, so the tool draws a progress
bar for each stage. The bar goes to standard error, which leaves the report on
standard output for a pipe to read. `--progress` chooses when to draw it:
`auto` draws only to a terminal, `never` turns it off, and `always` draws it
even when standard error is redirected.

## Speed

A comparison scores every remaining pair of functions, so the cost grows with
the product of the two function counts. Two measurements on a 2.8MB ARM32
vendor kernel, 2053 functions against 2024, over 4 cores:

| Stage | Time |
|---|---|
| Reading functions | 2.5s |
| Matching identical code and shape | 0.03s |
| Scoring pairs | 3.3s |
| Finding near misses | 3.3s |

The two scoring stages run on all cores. The result does not depend on how the
work is spread: candidates are sorted before any pair is taken.

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

## Raw firmware images

A flash dump has no ELF header, so nothing in the file says what architecture
it holds or where it loads. `--raw` takes the code as it is and `--base` says
where it sits:

```console
$ fndiff --raw --base 0x08000000 v1.bin v2.bin
```

Two things are worse than with an object file, and both are reported rather
than hidden.

**Boundaries are approximate.** A raw image has no exception index, so
functions are recovered from call targets, from the code after a return, and
from prologues. Every real function is found, and some are still split at a
return the scan cannot rule out: the test corpus recovers 14 starts where there
are 8 functions. Matching still works, because each piece matches its
counterpart, but the function count is not a fact.

Two rules keep the splitting down, and on a stripped kernel object they take
recovery from ten functions to exactly the four that exist. A return that a
branch reaches across is inside a function, because control flows past it. And
a `push` that saves the link register opens a function whatever precedes it,
which matters because an error path can jump backwards over the end of its own
function and hide the next one.

**A wrong `--base` is nearly silent.** ARM branches are relative, so the code
decodes and every branch resolves whatever base you give. Only the reported
addresses are wrong. `fndiff` warns when the image holds stored addresses that
do not fit:

```
fndiff: v1.bin may not load at 0x8000400: 4 words look like addresses,
        but none point into the image at this base
```

It stays quiet when the image holds no stored addresses at all, which is
normal for small position-independent code. Silence means "cannot tell", not
"looks right".

## Tried on shipped vendor firmware

Two OpenWrt releases for the same device — 22.03.2 and 22.03.5 for the Netgear
EX6100v2, an ipq40xx (ARMv7) target. These are the images a user flashes: a
vendor header, a FIT image holding an uncompressed ARM kernel, then a squashfs
root. The kernel declares its own load address, `0x80208000`.

A byte comparison is useless here — 6.8 MB of 6.8 MB differs, because the
squashfs is compressed. The uncompressed ARM decompressor stub is 15 KB of real
shipped code with no symbols and no exception index, and 43 of its 15,120 bytes
changed between the two releases.

```console
$ fndiff --raw --base 0x80208000 stub-22.03.2.bin stub-22.03.5.bin
FUNCTION      CHANGE          SCORE  +/-/~       MATCHED BY
sub_8020a3bc  changed          1.00  0/0/1       similar
sub_8020b1f8  changed          0.98  0/0/1       similar
sub_80208e20  changed unread   0.98  0/0/1       similar
...
62 matched (51 unchanged, 11 changed), 0 gone, 0 new
3 changed only a constant, hidden. Use --show-retouched to list them.
```

Scored against the byte-level truth:

| | |
|---|---|
| Functions recovered | 62 |
| Functions holding a changed byte | 11 |
| Reported | 11 |
| **Precision** | **1.00** |
| **Recall** | **1.00** |

Every function that changed was found, and nothing else was reported.

That was not the first answer. The first run scored 1.00 precision but only
0.73 recall, missing three functions whose only change was a word of **data**
stored among the instructions. Data decodes as some instruction — the stored
kernel size `0x2b08a8` decodes as `eoreq r0, fp, r8, lsr 17` — and normalizing
then bucketed its operands and lost the difference. Calling byte-different code
unchanged is the one answer this tool must never give, so `classify_change` now
checks whether the difference is really just a register before it says no.

## Tried on a real kernel patch

The fixtures are small and written for the tests, so `fndiff` was also run
against a real upstream change: commit `cb6fcef8b4b6`, *"objpool: fix to make
percpu slot allocation more robust"*, which rewrites the allocation path in
`lib/objpool.c`. Both versions were cross compiled for ARM with the kernel's
own build system, giving two objects that differ only by that patch.

Ground truth: the patch touches `objpool_init_percpu_slots`, which is `static`
and inlined into its only caller, so `objpool_init` is the function that should
change and the other three should not.

```console
$ fndiff before.o after.o
FUNCTION      CHANGE          SCORE  +/-/~       MATCHED BY
objpool_init  changed          0.93  0/3/119     same name

4 matched (3 unchanged, 1 changed), 0 gone, 0 new
```

The counts say how big the patch was: it removed three instructions and
rewrote 119, which a score of 0.93 alone does not convey.

Stripping both objects and ignoring names gives the same answer, with the
address in place of the name:

```console
$ fndiff --ignore-names before-stripped.o after-stripped.o
FUNCTION  CHANGE          SCORE  +/-/~       MATCHED BY
sub_0     changed          0.93  0/3/119     similar

4 matched (3 unchanged, 1 changed), 0 gone, 0 new
```

`sub_0` is `objpool_init`. One patched function found, three left alone, with
no symbols at all.

As raw blobs, with no symbols and no exception index, it now gives the same
answer:

```console
$ fndiff --raw --base 0x0 before.bin after.bin
FUNCTION  CHANGE          SCORE  +/-/~       MATCHED BY
sub_0     changed          0.93  0/3/119     similar

4 matched (3 unchanged, 1 changed), 0 gone, 0 new
```

Four functions recovered at exactly the addresses the symbol table names, and
the one that changed reported. An earlier version split those four into ten and
reported two changes plus one gone and one new; the rules in `scan.rs` about
which returns end a function are what closed the gap.

## Using this on firmware

For finding what a vendor changed between two releases, which is the workflow
this was built for:

| Task | Works |
|---|---|
| Vendor v1.2 against v1.3, both stripped — what changed? | **Yes** |
| Find a known function inside a different image built the same way | **Yes**, matched at 1.00 in testing |
| Is this CVE patched? — a reference build against the vendor's build | **No**, reported as a near miss |

The third one fails because the vendor's compiler and flags are rarely the ones
you have. A reference at `-O2` against the same source at `-O1` scores 0.38:
the compiler vectorized one and not the other, so the two really are different
algorithms. `fndiff` reports the near miss with its score rather than claiming
a match, because a wrong "unchanged" is the one answer a defensive tool must
never give. Closing that gap needs semantic comparison, not better
normalizing.

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
* **ARM32 little-endian A32 only.** Thumb is not decoded. A Thumb or
  mixed-mode image reads as nonsense with no warning, which matters most for
  raw images, where nothing declares the instruction set. AArch64 is the next
  architecture; the `Arch` trait exists so adding one does not disturb the
  normalizer or the matcher.

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
be reportable afterwards. The default report holds such a function back,
because a changed constant alone rarely repays a reader's attention at the
scale of a kernel; `--show-retouched` lists it.

`matching.rs` runs an ordered cascade: identical bytes, then identical
normalized instructions, then names, then similarity above a threshold. Each
stage pairs what it is sure about and removes it from the pool. A confident
answer is therefore never overruled by a guess, and the expensive all-pairs
stage runs only on what the cheap stages could not place.

Names come third, not first. A name is good evidence when it is there, but a
firmware image has none and a renamed function keeps its behavior, so evidence
from the code wins. With `--ignore-names` the cascade skips that stage
entirely, and on the test corpus it still matches every function.

A function the cascade cannot pair still names its nearest neighbour, so a
reader can tell a removed function from one that was only compiled differently:

```
sub_0: gone, closest sub_0 at 0.38
```

`--near-miss` sets the floor for showing one. `fndiff` does not lower the match
threshold to swallow these: a wrong "unchanged" hides a live bug, which is the
one failure this tool must not have.

`scan.rs` finds the functions when the symbol table is gone. The ARM exception
index is the strongest source: it lists one entry per function and survives
stripping, and where it is present the weaker sources are not consulted at all.
Guessing on top of an exact answer only does harm, because an internal `bx lr`
would split one function into two.

## Testing

```
just quick-test   # 157 tests, about five seconds
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

## Matching on constants: measured, and rejected

Worth recording, because it sounds obviously right and is not.

The constants a function uses come from the source, so they should outlive a
change of compiler flags that rewrites everything around them. Measured, they
do: `mul_by_constant` keeps `{37}` and `classify` keeps `{2, 100}` at `-O1`,
`-O2` and `-Os`.

As a way to *pair* functions it is still worse than comparing instructions:

* **It pairs the wrong functions.** `mul_by_constant` and `call_chain` both
  reduce to `{37}`, because the compiler inlined the first into the second.
  Constants cannot tell them apart.
* **It misses half of them.** Four of eight fixtures fall below the match
  threshold, including both functions the compiler vectorizes — which were the
  reason to try this.
* **It is worst where it was wanted.** On a reference build against a
  differently optimized one, the true pair scores 0.40 while a decoy scores
  1.00, because most functions there share the same uninformative set.

`norm::constant_signature` remains, because the constants a function uses are
worth *reporting*. Nothing matches on them, and two corpus tests assert the
false positive so the finding cannot quietly be lost.

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
