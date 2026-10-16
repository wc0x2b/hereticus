# Development

All patches/merge requests are welcome!

```
just quick-test   # about a minute
just test         # the same, plus the slow and the `truth_*` tests
just fixtures     # rebuild the ARM32, MIPS and Mach-O corpus
just rivals       # run radiff2 on the backports, which `quick-test` compares with
just rivals-ghidra  # run Ghidra Version Tracking on them, which `test` compares with
```

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
| `hereticus-image`    | Read ELF, Mach-O and raw images           | arch, il, memory, recovery                       |
| `hereticus-callees`  | Find the callee of each call              | arch, il, image, memory, recovery                |
| `hereticus-view`     | Show code as instructions or as IL        | arch, callees, il, image, memory, recovery       |
| `hereticus-match`    | Compare the functions of two binaries     | arch, callees, il, image, memory, recovery, view |

## Development
All patches/merge requests are welcome!

```
just quick-test   # about a minute
just test         # the same, plus the slow and the `truth_*` tests
just fixtures     # rebuild the ARM32, MIPS and Mach-O corpus
just rivals       # run radiff2 on the backports, which `quick-test` compares with
just rivals-ghidra  # run Ghidra Version Tracking on them, which `test` compares with
```

## Numbers in the Docs

A number that the docs quote from a locked test names its source in a
comment right after it, and `tests/docs.rs` checks that the two agree:

```markdown
0.95%<!-- from truth_kernels: all / wrong% --> of the pairs are wrong
45937<!-- from boundaries.rs: exact --> exact
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

## The Book

Each page of [Real-Life Examples](./real-life-examples.md) includes a file of
`real-life-reports/`. To change a page, edit its report. To see the book:

```
mdbook serve book
```
