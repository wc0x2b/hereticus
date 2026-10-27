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
function that the update changed. This is patch diffing, and it is slow:

- **The binaries are stripped.** Firmware and kernels ship with no
  symbols, and often with no ELF header at all.
- **Everything moves.** A new release moves each function and each global,
  so a byte diff marks almost all the code as changed.
- **The usual tools are heavy.** BinDiff and Diaphora need IDA, and Ghidra
  Version Tracking needs a project, a GUI and an analysis of each program.
  None fits in a shell script or a CI job.

`hereticus` is one static binary. It reads the two files, pairs their
functions, and prints a short list, the most likely fix first.

### Published Fixes

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

### Against Other Tools

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

### Stripped Code

Before a tool can compare functions, it must find them. In one raw OpenWrt
kernel, with no symbols and no sections, `hereticus` finds
19277<!-- from truth_function_starts: hereticus / real --> of the
20988<!-- from truth_function_starts: hereticus / symbols --> real function
starts, and Ghidra finds
13210<!-- from truth_function_starts: ghidra default / real -->. The
[Ghidra extension](./ghidra.md) adds the functions that Ghidra misses.

### Coding Agents

Ghidra, IDA and BinDiff are made for a person at a GUI. An agent can use
them only through a server or a plugin. `hereticus` is one command that
gives one answer, so an agent runs it as it runs `grep`:

- **The answer comes first.** The most likely fix is on the first rows,
  so `| head` is enough.
- **The output is short.** `--format compact` gives one line for each
  pair, and `--format json` gives one object for each pair.
- **Each name works as input.** The report names a stripped function
  `sub_7630`, and `--diff sub_7630` shows its diff.
- **The diff reads alike on each architecture.** `--view il` shows a
  compare, a call or a text in one form, as `if (w0 == 0) goto ...` and
  `call strncmp`, so the agent does not need to know each instruction set.
- **An error tells what to do next.** With no `--base`, the error gives
  the base that the words of the image show, where they show one. A
  failure exits with 2, and `--exit-code` makes a change exit with 1.

See [Use With a Coding Agent](./usage.md#use-with-a-coding-agent).

### Supported Files

- **Architectures:** A32 and Thumb-2, also big endian (BE8), AArch64,
  MIPS32, MIPS16e, x86-64 and 32-bit x86.
- **Files:** ELF (also with no section headers, as `sstrip` leaves it),
  Mach-O and iOS kernelcaches, Windows PE, and raw flash dumps.
- **Firmware images:** zImage, FIT, uImage, sysupgrade, lzma-loader and
  TP-Link containers, with `--unpack`.

## Where to Go Next

1. [Installation](./installation.md): get the binary.
2. [Usage](./usage.md): read the report, and the options.
3. [Examples](./examples.md): a raw firmware stub, and the diff of one
   function.
4. [Real-Life Examples](./real-life-examples.md): published fixes, step by
   step.
5. [Malware](./malware.md): two builds of one malware family.
6. [Methods](./methods.md): how it finds and pairs the functions, and why
   each method is there.
