# Installation

## GitHub Releases

Download a built binary from
[GitHub releases](https://github.com/wc0x2b/hereticus/releases).
Each release has these assets:

* `hereticus-<tag>-x86_64-unknown-linux-musl.tar.gz`: a static binary that
  runs on any x86-64 Linux system, with nothing else to install.
* `hereticus-<tag>-ghidra_<version>.zip`: the
  [Ghidra extension](./ghidra.md), for that Ghidra release only.

```console
$ tar xf hereticus-<tag>-x86_64-unknown-linux-musl.tar.gz
$ ./hereticus --version
```

## From crates.io

On another system, as macOS or AArch64 Linux, build from the published
source. This needs Rust 1.90 or later, and a C compiler for the mimalloc
allocator. CI tests it only on x86-64 Linux:

```console
$ cargo install hereticus-cli --locked
```

## From the Repository

To build the newest code:

```console
$ git clone https://github.com/wc0x2b/hereticus
$ cd hereticus
$ cargo install --path hereticus-cli --locked
```

The repository builds a static musl binary by default, and
`rust-toolchain.toml` installs the musl target. See
[Development](./development.md) to run the tests.

## As a Library

The `hereticus` crate reads binaries and compares them, with no command
line. Each of its parts is also a crate of its own. See
[Crates](./development.md#crates).
