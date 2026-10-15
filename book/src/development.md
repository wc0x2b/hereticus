# Development

All patches/merge requests are welcome!

```
just quick-test   # about five seconds
just test         # the same, plus slow tests
just fixtures     # rebuild the ARM32, MIPS and Mach-O corpus
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
just quick-test   # about five seconds
just test         # the same, plus slow tests
just fixtures     # rebuild the ARM32, MIPS and Mach-O corpus
```

## The Book

Each page of [Real-Life Examples](./real-life-examples.md) includes a file of
`real-life-reports/`. To change a page, edit its report. To see the book:

```
mdbook serve book
```
