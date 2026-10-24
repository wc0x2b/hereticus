# hereticus
[<img alt="github" src="https://img.shields.io/badge/github-wc0x2b/hereticus-8da0cb?style=for-the-badge&labelColor=555555&logo=github" height="20">](https://github.com/wc0x2b/hereticus)
[<img alt="crates.io" src="https://img.shields.io/crates/v/hereticus-cli.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/hereticus-cli)
[<img alt="build status" src="https://img.shields.io/github/actions/workflow/status/wc0x2b/hereticus/main.yml?branch=master&style=for-the-badge" height="20">](https://github.com/wc0x2b/hereticus/actions?query=branch%3Amaster)

> [!NOTE]
> Coding agents wrote much of this code.

Compare two versions of a binary or firmware and find the functions that changed.

![hereticus reports the functions that changed between two builds of a firmware, then shows the diff of one in the terminal, as assembly and as IL](https://raw.githubusercontent.com/wc0x2b/hereticus/master/book/src/images/demo.gif)

* **No IDA or Ghidra**: It needs no framework and no GUI. Programmers and agents can use it from a shell.
* **Or inside Ghidra**: An extension imports firmware at the base it finds, finds the functions that Ghidra misses, and pairs functions for Version Tracking. See [Ghidra Extension](https://wc0x2b.github.io/hereticus/ghidra.html).
* **Raw firmware, base found**: A flash dump has no header that says where it loads. `--find-base` finds the base on every architecture, from the words that point at the strings and functions of the image, and says so when no base stands out. See [Find the Base](https://wc0x2b.github.io/hereticus/usage.html#find-the-base).
* See the [book](https://wc0x2b.github.io/hereticus/) for usage, examples, and real-life examples.

## Installation
Either build from published source in crates.io.
```
$ cargo install hereticus-cli --locked
```

Or download from [github releases](https://github.com/wc0x2b/hereticus/releases).

## Example
```console
$ hereticus before.elf after.elf                    # what changed
$ hereticus --all before.elf after.elf              # every function
$ hereticus --diff array_max before.elf after.elf   # the diff of one function
$ hereticus --diff-all before.elf after.elf         # the diff of every changed function
$ hereticus --view il --diff array_max a.elf b.elf  # the diff as IL statements
$ hereticus --tui before.elf after.elf              # browse, sort and open diffs in the terminal
$ hereticus --save p.json before.elf after.elf      # keep the match, to open again at once
$ hereticus --tui --open p.json                     # go on where the last save stopped
$ hereticus --ignore-names before.elf after.elf     # match from the code alone
$ hereticus --format markdown before.elf after.elf  # a table to paste into a document
$ hereticus --format json before.elf after.elf      # for another tool to read
$ hereticus --raw --base 0x08000000 v1.bin v2.bin   # a flash dump, no ELF header
$ hereticus --find-base --raw --arch arm32 fw.bin   # where a flash dump loads
$ hereticus --raw --base auto v1.bin v2.bin         # load each at the base it shows
$ hereticus --raw --arch mips32 --unpack stub a.bin b.bin  # the decompressor in two firmware images
```

See the [book](https://wc0x2b.github.io/hereticus/) for the output,
the limits, every option, and the crates.

## Development
All patches/merge requests are welcome!

```
just quick-test   # about a minute
just test         # the same, plus the slow and the `truth_*` tests
just test-research  # the measurements of RESEARCH.md, which no test runs
just fixtures     # rebuild the ARM32, MIPS and Mach-O corpus
```

## License
MIT or Apache-2.0, at your option.

> "Innocence proves nothing" - Maxim of the Inquisition, Warhammer 40,000
