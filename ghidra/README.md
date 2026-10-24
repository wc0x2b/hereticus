# Hereticus Ghidra Extension

This Ghidra extension runs the `hereticus` command line tool from inside
Ghidra:

* **Raw Binary (Hereticus Base)** is a loader. It imports a raw image at
  the base that `hereticus --find-base` finds.
* **Hereticus Function Finder** is an analyzer. It makes a function at each
  start that `hereticus` finds and Ghidra does not.
* **Hereticus Function Match** is a Version Tracking correlator. It proposes
  each pair of functions that `hereticus` finds.

To build and install it, see the
[Ghidra Extension](https://wc0x2b.github.io/hereticus/ghidra.html)
page of the book. Each GitHub release has a zip for one Ghidra release. To
build a zip for your Ghidra:

```console
$ <GhidraInstallDir>/support/gradle/gradlew -PGHIDRA_INSTALL_DIR=<GhidraInstallDir> -p .
```

Then install the zip in `dist/` with *File → Install Extensions*.

## Layout

| Class                               | Does                                                   |
|-------------------------------------|--------------------------------------------------------|
| `HereticusRawLoader`                | The loader                                             |
| `BaseSearch`                        | Runs `--find-base`, and reads its JSON                 |
| `HereticusFunctionAnalyzer`         | The analyzer                                           |
| `FunctionMaker`                     | Makes the functions, and says why it skips a start     |
| `HereticusProgramCorrelatorFactory` | Offers the correlator to Version Tracking              |
| `HereticusProgramCorrelator`        | Proposes the pairs                                     |
| `HereticusTool`                     | Runs `hereticus` as a child process                    |
| `ProgramFile`                       | Writes the imported file of a program for `hereticus`  |
| `LinkedAddresses`                   | Moves addresses between the link base and Ghidra's     |
| `FunctionListing`, `DiffReport`     | Read the JSON of `hereticus`                           |

The unit tests in `src/test` need only the classes of Ghidra, not a running
Ghidra. `just ghidra-extension`, at the top of the repository, runs the
extension in headless Ghidra, and `hereticus-cli/tests/ghidra_extension.rs`
checks what it does.
