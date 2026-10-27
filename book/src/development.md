# Development

All patches/merge requests are welcome!

```
just quick-test        # about a minute
just slow-test         # the slow tests of the OpenWrt kernels, which CI runs too
just test              # the same, plus the slow and the `truth_*` tests
just test-research     # the measurements of RESEARCH.md, which no test runs
just fixtures          # rebuild the ARM32, MIPS, Mach-O, PE and garbled Go corpus
just rivals            # run radiff2 on the backports, which `quick-test` compares with
just rivals-ghidra     # run Ghidra Version Tracking on them, which `test` compares with
just ghidra-extension  # build the Ghidra extension and run it in Ghidra, which `test` checks
just bench             # time the read and the comparison of the backports
```

## Tests

| Tests | Where | What they check |
|-------|-------|-----------------|
| Unit and property tests | each crate, beside the code | one function, on regular and on random inputs |
| Fixtures | `hereticus/tests/` | small programs of `fixtures/src/`, built at each level for each architecture |
| Backports | `cross_build.rs`, `backports.rs` | real libraries built before and after one upstream fix, against their symbols |
| Rivals | `hereticus-cli/tests/rivals_radare2.rs`, `truth_ghidra.rs` | that `hereticus` does no worse than radiff2 and Ghidra |
| Truth | `truth_*.rs` | published fixes, OpenWrt kernels and Ubuntu updates, against their symbols |
| Docs | `tests/docs.rs`, `docs_output.rs` | each number and output that the docs show |

A snapshot of `insta` locks each count. When a change moves a count, the
test fails and shows the new count. Accept it with `cargo insta review`
where the change is better, and update the docs that quote it.

## Add a Published Fix

1. Add the URLs and the SHA-256 of the two binaries to
   `fixtures/cve_binaries.py`, and run `just truth`.
2. Add a `Fix` to `hereticus-cli/tests/truth_cves.rs`, with the function of
   the first binary that the fix edits, as the report names it.
3. Write the report in `real-life-reports/`, and a page in
   `book/src/real-life-examples/` that includes it. Tag each number and
   each output, as [Numbers in the Docs](#numbers-in-the-docs) says.
4. Add the page to `book/src/SUMMARY.md`, and a row to the table of
   [Real-Life Examples](./real-life-examples.md).

## Add an Architecture

An architecture needs three parts:

1. A decoder and a lifter in `hereticus-il`.
2. A file of rules in `hereticus-recovery`: which instruction opens a
   function, which word is padding, and where the unwind index is.
3. One file in `hereticus-arch`: which register holds the frame, which
   instruction only keeps it, and which constant is an address.

Then add fixtures for it to `fixtures/build.sh`, and run the tests.

## Benchmarks

`hereticus/benches/` reads and compares backports of zlib for x86-64 and of
Lua for ARM32, with symbols, stripped and as raw images. Each bench has two
forms:

- `criterion_benchmark` measures the wall time.
- `gungraun_benchmark` counts the instructions under Valgrind, and needs
  `gungraun-runner` of the same version as `gungraun` in `Cargo.lock`.

On each pull request, `.github/workflows/benchmark.yml` runs both on the base
branch and on the pull request, and writes the change as a comment. Use the
counts of gungraun to make a decision, because the wall time of a CI runner
changes with its load.

## Crates

The `hereticus` crate re-exports the crates below. To use only one part,
depend on that crate. Each crate in the table needs only the crates in its
row.

| Crate                | Does                                      | Needs                                            |
|----------------------|-------------------------------------------|--------------------------------------------------|
| `hereticus-il`       | Decode machine code, and lift it to an IL | nothing                                          |
| `hereticus-memory`   | The address space of a binary             | nothing                                          |
| `hereticus-unpack`   | Unpack firmware archives                  | nothing                                          |
| `hereticus-recovery` | Find functions in stripped binaries       | il, memory                                       |
| `hereticus-arch`     | The rules the matching reads              | il, memory, recovery                             |
| `hereticus-image`    | Read ELF, Mach-O, PE and raw images       | arch, il, memory, recovery                       |
| `hereticus-callees`  | Find the callee of each call              | arch, il, image, memory, recovery                |
| `hereticus-view`     | Show code as instructions or as IL        | arch, callees, il, image, memory, recovery       |
| `hereticus-match`    | Compare the functions of two binaries     | arch, callees, il, image, memory, recovery, view |

## Numbers in the Docs

A number that the docs quote from a locked test names its source in a
comment right after it, and `tests/docs.rs` checks that the two agree:

```markdown
0.95%<!-- from truth_kernels: all / wrong% --> of the pairs are wrong
64488<!-- from boundaries.rs: exact --> exact
```

A source without `.rs` is a snapshot of `hereticus/tests/snapshots` or of
`hereticus-cli/tests/snapshots`, and
the key is a row and a column of its tables. A source with `.rs` is a test,
and the key is a field that the test sets once. When a snapshot changes,
`just quick-test` fails until the docs quote the new numbers. The entries
of `RESEARCH.md` record the numbers of their own time, so they have no tag.

An output that the docs show names the arguments that make it, and
`hereticus-cli/tests/docs_output.rs` runs the tool with them and checks
that the docs show a part of what it prints:

```markdown
<!-- output: --diff mul_by_constant fixtures/build/O2/basic.o fixtures/build/O2/basic_v2.o -->
...
<!-- end output -->
```

`just quick-test` checks the outputs of the book, of the README and of
each report whose binaries `just truth` fetched to `~/.cache`. The fix of
CVE-2021-30883 is in an iPhone kernelcache, and its outputs take 90
seconds, so only `just test` checks that report. When a change to the
tool changes only the lines of the jumps at the left, the indent or the
spaces of an output, `just docs-output` writes the new output into the
docs. Any other change it names, so that you can choose the part to show.

## The Book

Each page of [Real-Life Examples](./real-life-examples.md) includes a file of
`real-life-reports/`. To change a page, edit its report. To see the book:

```
mdbook serve book
```

`just book` builds the book and checks each link and `#anchor` in it.

The screenshots of the book and the demo of the README are images, so no
test can read them. `just book-media` records them again from
`book/tapes/`, and writes the hash of the screens they show to
`book/tapes/media.sha256`. Where a snapshot of a screen, a snapshot of a
report or a tape changes after, `just quick-test` fails until you run
`just book-media`, look at the images, and commit them.
