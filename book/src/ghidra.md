# Ghidra Extension

The Ghidra extension in `ghidra/` runs `hereticus` from inside Ghidra. It
adds two things:

* **Hereticus Function Finder**, an analyzer. It makes a function at each
  start that `hereticus` finds and Ghidra does not.
* **Hereticus Function Match**, a Version Tracking correlator. It proposes
  each pair of functions that `hereticus` finds between two programs.

The extension holds no analysis of its own. It writes the imported file of
each program to a temporary file, runs the `hereticus` tool on it, and reads
the JSON that the tool prints. Thus it finds and pairs functions exactly as
the command line does.

## Installation

1. Install `hereticus` on the `PATH`. See [Installation](./installation.md).
2. Build the extension for your Ghidra. Ghidra ships the Gradle that the
   build needs:

   ```console
   $ cd ghidra
   $ <GhidraInstallDir>/support/gradle/gradlew -PGHIDRA_INSTALL_DIR=<GhidraInstallDir> -p .
   ```

   The build runs the unit tests, then writes the extension zip to
   `ghidra/dist/`.
3. In Ghidra, select *File → Install Extensions*, then the green `+`, then
   the zip. Restart Ghidra.

If `hereticus` is not on the `PATH`, give its path in the
`Hereticus Executable` option of the analyzer and of the correlator.

## Function Finder

The analyzer runs during auto-analysis of each ARM, AArch64 or MIPS
program, after the function analysis of Ghidra. It reads ELF and Mach-O
files, and raw images that Ghidra loaded with the *Raw Binary* loader. A
raw image goes to `hereticus` at the address of its first byte, in the
instruction set of its language. A Cortex language gives Thumb-2.

The analyzer changes nothing that Ghidra decided. It does not make a
function at these starts:

* A start inside a function that Ghidra made.
* A start on data that Ghidra defined.
* A start whose body, as `hereticus` sees it, holds the start of a function
  that Ghidra made. A scan reads the PLT of a stripped library as one
  function, where Ghidra marks up each entry.
* A region that `hereticus` thinks is a table or fill, not code.

The analysis log shows what became of each start, as `Of <count> starts
hereticus found in <program>: <count> made, <count> already a function`, with
a count for each reason above.

`just ghidra-extension` runs the analyzer in headless Ghidra 12.1.4. On the
raw zImage stub of the Netgear EX6100v2, Ghidra finds
19<!-- from ghidra_extension: arm-stub / off --> functions alone and
66<!-- from ghidra_extension: arm-stub / on --> with the analyzer. That is
each of the 66<!-- from ghidra_extension: arm-stub / hereticus --> starts
that `hereticus` finds. On a stripped library, Ghidra already finds almost
every function. On the zlib backport for Thumb-2, Ghidra finds
188<!-- from ghidra_extension: zlib-thumb-O2 / off --> functions alone and
189<!-- from ghidra_extension: zlib-thumb-O2 / on --> with the analyzer.

## Function Match

In the Version Tracking window, add *Hereticus Function Match* to the
correlators of a session. Each match has these values:

* **Similarity:** the score of `hereticus`, from 0.0 to 1.0. Ghidra keeps
  three decimals.
* **Confidence:** how sure the pairing is, from highest for a pair of
  identical bytes to lowest for a pair that is only similar. The `MATCHED BY`
  column of the report names each stage.
* **Tag:** what changed, as `hereticus: same` or `hereticus: changed`.
  Filter the match table on a tag to see only the functions that changed.

The correlator has these options:

* `Lowest Similarity`, the same as `--threshold`.
* `Ignore Symbol Names`, the same as `--ignore-names`.

A pair is proposed only if both programs have a function at its addresses.
Thus, run the Function Finder on both programs first. On the zlib backport
for ARM, the correlator proposes
123<!-- from ghidra_extension: zlib-arm-O2 / matches --> of the
124<!-- from ghidra_extension: zlib-arm-O2 / hereticus pairs --> pairs of
`hereticus`. The one it does not propose is the PLT, which Ghidra holds as
one function for each entry.

## Limits

* **Both programs of a session must be read alike.** Both are ELF or
  Mach-O, or both are raw images at the same base in the same instruction
  set.
* **An unlinked object puts its sections where Ghidra chooses.** The
  addresses of `hereticus` agree with those of Ghidra when the first section
  that `hereticus` reads is the first that Ghidra loads.
* **Only ELF and raw images are tested in Ghidra.** A Mach-O file goes to
  `hereticus` as it does on the command line, but no test runs it in Ghidra.
