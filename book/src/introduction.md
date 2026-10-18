# Introduction

**hereticus** compares two versions of a binary or firmware. It finds the
functions that changed.

- **No IDA or Ghidra**: It needs no framework and no GUI. Programmers and
  agents can use it from a shell.
- **Stripped code**: It finds the functions of a binary that has no symbols,
  and of a raw flash dump that has no ELF header.
- **ARM, MIPS and x86**: It reads A32, Thumb-2, AArch64, MIPS32, MIPS16e,
  x86-64 and 32-bit x86 code in ELF, Mach-O and raw images.

> [!NOTE]
> Coding agents wrote much of this code.

For real fixes that `hereticus` found, see
[Real-Life Examples](./real-life-examples.md).

For how it finds them, see [Methods](./methods.md).
