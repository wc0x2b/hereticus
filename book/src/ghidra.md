# Ghidra Extension

The Ghidra extension in `ghidra/` runs `hereticus` from inside Ghidra. It
adds three things:

* **Raw Binary (Hereticus Base)**, a loader. It imports a raw image at the
  base that `hereticus --find-base` finds.
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
2. Get the extension zip for your Ghidra. Ghidra installs only a zip built
   for its exact release. If a
   [GitHub release](https://github.com/wc0x2b/hereticus/releases)
   has `hereticus-<tag>-ghidra_<version>.zip` for your Ghidra, download it.
   If not, build the zip. Ghidra ships the Gradle that the build needs:

   ```console
   $ cd ghidra
   $ <GhidraInstallDir>/support/gradle/gradlew -PGHIDRA_INSTALL_DIR=<GhidraInstallDir> -p .
   ```

   The build runs the unit tests, then writes the extension zip to
   `ghidra/dist/`.
3. In Ghidra, select *File → Install Extensions*, then the green `+`, then
   the zip. Restart Ghidra.

If `hereticus` is not on the `PATH`, give its path in the
`Hereticus Executable` option of the analyzer and of the correlator. The
loader has no such option and always runs the `hereticus` on the `PATH`.
Ghidra gets the options of a loader before you can change them.

## Raw Loader

A firmware image has no header that says where it loads. The *Raw Binary*
loader of Ghidra puts it at 0 unless you give the base. The *Raw Binary
(Hereticus Base)* loader is the same loader, but it finds the base for you:

1. Select *File → Import File*, then the image.
2. Set *Format* to *Raw Binary (Hereticus Base)*, and select the language.
3. The loader runs `hereticus --find-base` on the image, in the instruction
   set of the language, and puts the base in the *Base Address* option.
   Look at it in *Options…* before you select *OK*.

The Ghidra log shows `hereticus finds that <file> loads at <base>`. If no
base stands out, or `hereticus` cannot read the language, the *Base
Address* stays as *Raw Binary* gives it. Then find the base as
[Find the Base](./usage.md#find-the-base) tells, and type it.

In headless Ghidra, give the loader and the language, and no base:

```console
$ analyzeHeadless <project> <name> -import firmware.bin \
    -loader HereticusRawLoader -processor ARM:LE:32:Cortex
```

`just ghidra-extension` imports the Cortex-M3 firmware of the zlib backport
so. The loader puts it at 0x8000000, where it is linked. Ghidra then finds
51<!-- from ghidra_extension: m3-firmware / off --> functions alone and
88<!-- from ghidra_extension: m3-firmware / on --> with the Function Finder.

## Function Finder

The analyzer runs during auto-analysis of each ARM, AArch64 or MIPS
program, after the function analysis of Ghidra. It reads ELF and Mach-O
files, and raw images that Ghidra loaded with either raw loader. A
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
192<!-- from ghidra_extension: zlib-thumb-O2 / on --> with the analyzer.

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
170<!-- from ghidra_extension: zlib-arm-O2 / matches --> of the
172<!-- from ghidra_extension: zlib-arm-O2 / hereticus pairs --> pairs of
`hereticus`. The two it does not propose are PLT stubs.

## Limits

* **Both programs of a session must be read alike.** Both are ELF or
  Mach-O, or both are raw images at the same base in the same instruction
  set.
* **An unlinked object puts its sections where Ghidra chooses.** The
  addresses of `hereticus` agree with those of Ghidra when the first section
  that `hereticus` reads is the first that Ghidra loads.
* **Only ELF and raw images are tested in Ghidra.** A Mach-O file goes to
  `hereticus` as it does on the command line, but no test runs it in Ghidra.
