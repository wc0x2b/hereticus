# Introduction

**hereticus** compares two versions of a binary or firmware. It finds the
functions that changed, and puts the security fix near the top.

```console
$ hereticus before.bin after.bin
```

> [!NOTE]
> Coding agents wrote much of this code.

## Why hereticus

A vendor ships a security update with one line of advisory: "a memory
corruption issue was fixed". To know what the bug was, you must find the
function that the update changed. This is patch diffing. Three problems
make it slow:

- **The binaries are stripped.** Firmware and kernels ship with no
  symbols, and often with no ELF header at all.
- **Everything moves.** A new release moves each function and each global,
  so a byte diff marks almost all the code as changed.
- **The usual tools are heavy.** BinDiff and Diaphora need IDA, and Ghidra
  Version Tracking needs a project, a GUI and an analysis of each program.
  None fits in a shell script or a CI job.

`hereticus` is one static binary. It reads the two files, pairs their
functions, and prints a short list, the most likely fix first.

### It finds the fix, on the first rows

On published security fixes, the fixed function is on the first rows of
the report:

| Fix | Binary | Row of the fix | Rows in the report |
|-----|--------|----------------|--------------------|
| [CVE-2026-30874](./real-life-examples/cve-2026-30874.md) | procd, OpenWrt, stripped | 1<!-- from truth_cves: CVE-2026-30874 procd AArch64 / rank --> | 24<!-- from truth_cves: CVE-2026-30874 procd AArch64 / rows --> |
| [CVE-2026-35385](./real-life-examples/cve-2026-35385.md) | dropbear `scp`, OpenWrt, stripped | 1<!-- from truth_cves: CVE-2026-35385 dropbear AArch64 / rank --> | 19<!-- from truth_cves: CVE-2026-35385 dropbear AArch64 / rows --> |
| [CVE-2024-23265](./real-life-examples/cve-2024-23265.md) | AppleDiskImages2, iOS kernelcache | 1<!-- from truth_cves: CVE-2024-23265 AppleDiskImages2 / rank --> | 33<!-- from truth_cves: CVE-2024-23265 AppleDiskImages2 / rows --> |
| [CVE-2021-30883](./real-life-examples/cve-2021-30883.md) | AppleCLCD, iOS kernelcache | 1<!-- from truth_cves: CVE-2021-30883 IOMobileFramebuffer / rank --> | 333<!-- from truth_cves: CVE-2021-30883 IOMobileFramebuffer / rows --> |

See [Real-Life Examples](./real-life-examples.md) for all of them, each
with the commands to do it again.

### It shows less noise than other tools

On 35<!-- from rivals_radare2: hereticus / builds --> stripped libraries,
each built before and after one upstream fix:

| Tool      | Fixes found | Fix on row 1 | Rows the fix did not touch |
|-----------|-------------|--------------|----------------------------|
| hereticus | 35<!-- from rivals_radare2: hereticus / found --> | 20<!-- from rivals_radare2: hereticus / first --> | 0<!-- from rivals_radare2: hereticus / extras --> |
| radiff2   | 20<!-- from rivals_radare2: radare2 / found --> | 9<!-- from rivals_radare2: radare2 / first --> | 2418<!-- from rivals_radare2: radare2 / extras --> |
| Ghidra    | 33<!-- from truth_ghidra: ghidra / found --> | 18<!-- from truth_ghidra: ghidra / first --> | 629<!-- from truth_ghidra: ghidra / extras --> |

This is a narrow test, which `hereticus` was developed with. See
[Comparison With Other Tools](./comparison.md) for how it scores each
tool, and for its limits.

### It finds the functions of stripped code

Before a tool can compare functions, it must find them. In one raw OpenWrt
kernel, with no symbols and no sections, `hereticus` finds
19277<!-- from truth_function_starts: hereticus / real --> of the
20988<!-- from truth_function_starts: hereticus / symbols --> real function
starts, and Ghidra finds
13210<!-- from truth_function_starts: ghidra default / real -->. The
[Ghidra extension](./ghidra.md) adds the functions that Ghidra misses.

### It fits in a shell, a script or an agent

- One static binary for Linux, with no IDA, Ghidra, Python or GUI.
- `--format json` for another tool, `--format markdown` for a document,
  and `--exit-code` for CI.
- `--diff` shows what changed in one function, as assembly or as an IL
  that reads the same on each architecture.
- `--tui` to browse the report in the terminal.

### It reads what firmware ships

- **Architectures:** A32, Thumb-2, AArch64, MIPS32, MIPS16e, x86-64 and
  32-bit x86.
- **Files:** ELF (also with no section headers, as `sstrip` leaves it),
  Mach-O and iOS kernelcaches, and raw flash dumps.
- **Firmware images:** zImage, FIT, uImage, sysupgrade, lzma-loader and
  TP-Link containers, with `--unpack`.

## Who It Is For

- **Security researchers** who find the bug that an update fixed.
- **Vendors and integrators** who check that a backport of a fix is in a
  build.
- **Malware analysts** who compare two builds of one family. See
  [Malware](./malware.md).

## Where to Go Next

1. [Installation](./installation.md): get the binary.
2. [Usage](./usage.md): read the report, and the options.
3. [Examples](./examples.md): a raw firmware stub, and the diff of one
   function.
4. [Real-Life Examples](./real-life-examples.md): published fixes, step by
   step.
5. [Methods](./methods.md): how it finds and pairs the functions, and why
   each method is there.
