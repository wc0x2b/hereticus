//! The inputs that the benches share: libraries that `just backports` builds.
//!
//! Each library is built from the pristine release, `before`, and with one
//! upstream fix on top, `after`. See `tests/backports.rs`.

use std::path::{Path, PathBuf};

use hereticus::matching::{Diff, Options, diff_with};
use hereticus::obj::{Binary, Isa};
use object::{Object, ObjectSection};

/// One build of one project.
#[derive(Clone, Copy, Debug)]
pub struct Build {
    pub project: &'static str,
    pub arch: &'static str,
    pub level: &'static str,
    pub isa: Isa,
}

/// zlib 1.2.12 for x86-64, with variable-length instructions.
pub const ZLIB_X86_64: Build =
    Build { project: "zlib", arch: "x86_64", level: "O2", isa: Isa::X86_64 };

/// Lua 5.1.5 for ARM32, the most common architecture of firmware.
pub const LUA_ARM: Build = Build { project: "lua", arch: "arm", level: "O2", isa: Isa::Arm32 };

/// Which build of a pair.
#[derive(Clone, Copy, Debug)]
pub enum Side {
    Before,
    After,
}

impl Side {
    fn name(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
        }
    }
}

/// How a build is read, from the most help to the least.
#[derive(Clone, Copy, Debug)]
pub enum Reading {
    /// The library with its symbols.
    Symbols,
    /// The library with no symbols, thus the scan must find each function.
    Stripped,
    /// The bytes that a flash dump holds, with no ELF header.
    Raw,
}

/// The bytes of a build, and what [`Binary`] needs to read them.
pub struct Image {
    bytes: Vec<u8>,
    kind: Kind,
}

enum Kind {
    Object,
    Raw { base: u64, isa: Isa },
}

impl Image {
    /// Read the file of `build` from the disk.
    pub fn load(build: Build, side: Side, reading: Reading) -> Self {
        match reading {
            Reading::Symbols => Self { bytes: read(build, side, "lib.so"), kind: Kind::Object },
            Reading::Stripped => {
                Self { bytes: read(build, side, "lib-stripped.so"), kind: Kind::Object }
            }
            Reading::Raw => Self {
                bytes: read(build, side, "lib.bin"),
                kind: Kind::Raw { base: load_address(build, side), isa: build.isa },
            },
        }
    }

    /// Find the functions of the image, which is what a bench measures.
    pub fn parse(&self) -> Binary {
        match self.kind {
            Kind::Object => Binary::parse(&self.bytes).expect("a fixture library must parse"),
            Kind::Raw { base, isa } => {
                Binary::parse_raw(&self.bytes, base, isa).expect("a raw image must read")
            }
        }
    }
}

/// The two binaries of a pair, read before the bench starts.
pub fn pair(build: Build, reading: Reading) -> (Binary, Binary) {
    let before = Image::load(build, Side::Before, reading).parse();
    let after = Image::load(build, Side::After, reading).parse();
    (before, after)
}

/// Compare a pair, which is what a bench measures.
pub fn compare((before, after): &(Binary, Binary)) -> Diff {
    diff_with(before, after, Options::default())
}

fn backports() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/backports")
}

fn read(build: Build, side: Side, file: &str) -> Vec<u8> {
    let path = backports()
        .join(format!("{}-{}", build.project, side.name()))
        .join(format!("{}-{}", build.arch, build.level))
        .join(file);
    std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{}: {err}, run `just backports` first", path.display()))
}

/// The address that the raw image of a build loads at.
///
/// `llvm-objcopy -O binary` writes each loaded section that holds bytes, from
/// the lowest address up, thus that address is the base. A section that is
/// not loaded has address zero.
fn load_address(build: Build, side: Side) -> u64 {
    let library = read(build, side, "lib.so");
    let file = object::File::parse(library.as_slice()).expect("a fixture library must parse");
    file.sections()
        .filter(|section| {
            section.address() != 0
                && section.size() != 0
                && section.kind() != object::SectionKind::UninitializedData
        })
        .map(|section| section.address())
        .min()
        .expect("a library loads something")
}
