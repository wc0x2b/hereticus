//! Find the base of raw images whose base is known, on every architecture.
//!
//! Three sets give the answer:
//!
//! - A small program, linked statically with the C library for seven
//!   targets, at the default base of each and at `0x12340000`. Its ELF
//!   gives the base, and its segments, laid out at the addresses they load
//!   from, are the raw image. `just fixtures` builds it.
//! - zlib built as Cortex-M firmware, linked into flash at `0x08000000`, in
//!   the flash image that `just backports` writes.
//! - The kernels and the stubs of six OpenWrt boards, at the bases of
//!   `tests/openwrt.rs`. `just firmware` downloads them.
//!
//! A wrong base gives a report against the wrong addresses with no other
//! sign, so no image may get one. An image may get no base: a stub of
//! position-independent code holds too few full addresses to show it. The
//! counts are locked, so a change shows what it gains and what it costs.

use std::path::{Path, PathBuf};

use hereticus::obj::Isa;
use hereticus::raw::{check_base, suggest_base};
use object::Endianness;
use object::read::elf::{ElfFile32, ElfFile64, ProgramHeader};

/// How the images of every set fared.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Found {
    images: usize,
    /// Images that got their base.
    right: usize,
    /// Images that got no base.
    none: usize,
    /// Images that got another base.
    wrong: usize,
}

impl Found {
    fn add(self, base: Option<u64>, truth: u64) -> Self {
        Self {
            images: self.images + 1,
            right: self.right + usize::from(base == Some(truth)),
            none: self.none + usize::from(base.is_none()),
            wrong: self.wrong + usize::from(base.is_some_and(|base| base != truth)),
        }
    }
}

/// One raw image, with how it reads and where it loads.
struct Image {
    name: String,
    isa: Isa,
    data: Vec<u8>,
    base: u64,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build")
}

/// The loaded segments of an ELF, laid out from the lowest at the address
/// each loads from, as a flash dump holds them, with that address.
fn flatten(elf: &[u8]) -> (u64, Vec<u8>) {
    let segments: Vec<(u64, Vec<u8>)> = match ElfFile32::<Endianness>::parse(elf) {
        Ok(file) => {
            let endian = file.endian();
            file.elf_program_headers()
                .iter()
                .filter(|header| header.p_type(endian) == object::elf::PT_LOAD)
                .map(|header| {
                    let data = header.data(endian, elf).expect("a segment");
                    (u64::from(header.p_paddr(endian)), data.to_vec())
                })
                .collect()
        }
        Err(_) => {
            let file = ElfFile64::<Endianness>::parse(elf).expect("an ELF");
            let endian = file.endian();
            file.elf_program_headers()
                .iter()
                .filter(|header| header.p_type(endian) == object::elf::PT_LOAD)
                .map(|header| {
                    let data = header.data(endian, elf).expect("a segment");
                    (header.p_paddr(endian), data.to_vec())
                })
                .collect()
        }
    };
    let base = segments.iter().map(|&(address, _)| address).min().expect("a segment");
    let end = segments
        .iter()
        .map(|(address, bytes)| address + bytes.len() as u64)
        .max()
        .expect("a segment");
    let mut image = vec![0; usize::try_from(end - base).expect("an image that fits")];
    for (address, bytes) in segments {
        let at = usize::try_from(address - base).expect("an image that fits");
        image[at..at + bytes.len()].copy_from_slice(&bytes);
    }
    (base, image)
}

/// The static programs, or `None` where `just fixtures` has not built them.
fn programs() -> Option<Vec<Image>> {
    let targets = [
        ("x86-64", Isa::X86_64),
        ("x86", Isa::X86),
        ("aarch64", Isa::Aarch64),
        ("thumb2", Isa::Thumb2),
        ("arm32", Isa::Arm32),
        ("mips32", Isa::Mips32),
        ("mips32-be", Isa::Mips32Be),
    ];
    let mut images = Vec::new();
    for (name, isa) in targets {
        for link in ["default", "moved"] {
            let path = root().join("base").join(format!("{name}-{link}.elf"));
            let (base, data) = flatten(&std::fs::read(path).ok()?);
            images.push(Image { name: format!("{name}-{link}"), isa, data, base });
        }
    }
    Some(images)
}

/// The Cortex-M flash images, or `None` where `just backports` has not
/// built them.
fn cortex_m() -> Option<Vec<Image>> {
    let mut images = Vec::new();
    for core in ["cortex-m0", "cortex-m3"] {
        for level in ["O1", "O2", "O3", "Os"] {
            let path = root()
                .join("backports/zlib-before")
                .join(format!("{core}-{level}"))
                .join("lib.bin");
            let data = std::fs::read(path).ok()?;
            let name = format!("zlib {core} {level}");
            images.push(Image { name, isa: Isa::Thumb2, data, base: 0x0800_0000 });
        }
    }
    Some(images)
}

/// The OpenWrt images, or `None` where `just firmware` has not fetched them.
/// The bases are those of `tests/openwrt.rs`.
fn openwrt() -> Option<Vec<Image>> {
    let parts: [(&str, Isa, &str, u64, &[&str]); 10] = [
        (
            "arm-ex6100v2",
            Isa::Arm32,
            "stub",
            0x8020_8000,
            &["21.02.7", "22.03.2", "22.03.5", "23.05.5"],
        ),
        (
            "arm-ex6100v2",
            Isa::Arm32,
            "kernel",
            0xc020_8000,
            &["21.02.7", "22.03.2", "22.03.5", "23.05.5"],
        ),
        (
            "mipsbe-eap245v3",
            Isa::Mips32Be,
            "stub",
            0x8006_0000,
            &["21.02.7", "22.03.2", "22.03.5", "23.05.5"],
        ),
        (
            "mipsbe-eap245v3",
            Isa::Mips32Be,
            "kernel",
            0x8006_0000,
            &["21.02.7", "22.03.2", "22.03.5", "23.05.5"],
        ),
        (
            "mipsel-r6220",
            Isa::Mips32,
            "stub",
            0x8000_1000,
            &["21.02.7", "22.03.2", "22.03.5", "23.05.5"],
        ),
        (
            "mipsel-r6220",
            Isa::Mips32,
            "kernel",
            0x8000_1000,
            &["21.02.7", "22.03.2", "22.03.5", "23.05.5"],
        ),
        ("arm-a385dbap", Isa::Arm32, "stub", 0x8000, &["22.03.2", "22.03.5"]),
        ("arm-a385dbap", Isa::Arm32, "kernel", 0xc000_8000, &["22.03.2", "22.03.5"]),
        ("mipsbe-vr200", Isa::Mips32Be, "kernel", 0x8000_2000, &["22.03.2", "22.03.5"]),
        ("mipsel-mt300nv2", Isa::Mips32, "kernel", 0x8000_0000, &["22.03.2", "22.03.5"]),
    ];
    let mut images = Vec::new();
    for (board, isa, part, base, releases) in parts {
        for release in releases {
            let name = format!("{board}-{part}-{release}.bin");
            let data = std::fs::read(root().join("openwrt").join(&name)).ok()?;
            images.push(Image { name, isa, data, base });
        }
    }
    Some(images)
}

#[test]
fn no_image_gets_a_wrong_base() {
    let (Some(programs), Some(cortex_m), Some(openwrt)) = (programs(), cortex_m(), openwrt())
    else {
        eprintln!("skipped: run `just fixtures`, `just backports` and `just firmware` first");
        return;
    };
    let mut found = Found::default();
    let mut misses = Vec::new();
    for image in programs.iter().chain(&cortex_m).chain(&openwrt) {
        let base = suggest_base(&image.data, image.isa.arch());
        if base != Some(image.base) {
            misses.push(format!("{}: {base:x?}, not {:#x}", image.name, image.base));
        }
        found = found.add(base, image.base);
    }
    assert_eq!(
        found,
        Found { images: 54, right: 40, none: 14, wrong: 0 },
        "the misses: {misses:#?}"
    );
    // Only the stubs, which are position-independent code, get no base.
    assert!(
        misses.iter().all(|miss| miss.contains("-stub-") && miss.contains("None")),
        "{misses:#?}"
    );
}

#[test]
fn a_base_a_page_off_is_suspect_on_every_architecture() {
    let Some(programs) = programs() else {
        eprintln!("skipped: run `just fixtures` first");
        return;
    };
    for image in programs.iter().filter(|image| image.name.ends_with("moved")) {
        let arch = image.isa.arch();
        let right = check_base(&image.data, image.base, arch);
        assert!(!right.is_suspect(), "{}: {right}", image.name);
        let off = check_base(&image.data, image.base + 0x1000, arch);
        assert!(off.is_suspect(), "{}: {off:?}", image.name);
    }
}
