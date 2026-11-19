//! Instruction counts of the code that reads binary formats and instruction
//! words with deku: the headers of firmware containers, the scans of a raw
//! kernel for CIE headers and MIPS lazy stubs, and the read of a library of
//! each architecture whose decoder deku serves. Run `just backports` and
//! `just firmware` first.

use std::hint::black_box;
use std::path::{Path, PathBuf};

use gungraun::{
    Callgrind, LibraryBenchmarkConfig, library_benchmark, library_benchmark_group, main,
};
use hereticus::obj::{Binary, Isa};

// This bench uses only part of what the other benches share.
#[allow(dead_code)]
mod common;
use common::{Build, Image, Reading, Side};

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// The bytes of the kernel that the scans read. 2 MiB keeps a run of
/// Valgrind short, and holds about half a million words.
const KERNEL_BYTES: usize = 2 << 20;

const LUA_MIPS16: Build =
    Build { project: "lua", arch: "mips16", level: "gcc-O2", isa: Isa::Mips16 };
const LUA_MIPS: Build = Build { project: "lua", arch: "mips", level: "O2", isa: Isa::Mips32Be };
const LUA_POWERPC: Build =
    Build { project: "lua", arch: "powerpc", level: "O2", isa: Isa::PowerPc };
const LUA_POWERPC64: Build =
    Build { project: "lua", arch: "powerpc64", level: "gcc-O2", isa: Isa::PowerPc64 };
const LUA_AARCH64: Build =
    Build { project: "lua", arch: "aarch64", level: "O2", isa: Isa::Aarch64 };
const LUA_X86_64: Build = Build { project: "lua", arch: "x86_64", level: "O2", isa: Isa::X86_64 };

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build")
}

/// The start of a big-endian MIPS kernel of OpenWrt.
fn mips_kernel() -> Vec<u8> {
    let path = fixtures().join("openwrt/mipsbe-eap245v3-kernel-22.03.2.bin");
    let mut kernel = std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{}: {err}, run `just firmware` first", path.display()));
    kernel.truncate(KERNEL_BYTES);
    kernel
}

/// A zImage that holds `stream`, as `hereticus-unpack` tests build it.
fn zimage(stream: &[u8]) -> Vec<u8> {
    let mut image = vec![0u8; 0x200];
    image[0x24..0x28].copy_from_slice(&0x016f_2818_u32.to_le_bytes());
    image.extend_from_slice(stream);
    let end = image.len() as u32;
    image[0x2c..0x30].copy_from_slice(&end.to_le_bytes());
    image
}

fn zimage_of_arm_xz() -> Vec<u8> {
    zimage(include_bytes!("../../crates/hereticus-unpack/tests/data/arm.xz"))
}

/// The `.text` of the library of `build`, and the decoder of its
/// architecture.
fn text_of(build: Build) -> (Isa, Vec<u8>) {
    use object::{Object, ObjectSection};
    let path = fixtures()
        .join(format!("backports/{}-before/{}-{}/lib.so", build.project, build.arch, build.level));
    let library = std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{}: {err}, run `just backports` first", path.display()));
    let file = object::File::parse(library.as_slice()).expect("a fixture library must parse");
    let text = file.section_by_name(".text").expect("the library has a .text");
    (build.isa, text.data().expect("the .text holds bytes").to_vec())
}

fn load_before(build: Build, reading: Reading) -> Image {
    Image::load(build, Side::Before, reading)
}

#[library_benchmark]
#[bench::zimage_arm_xz(setup = zimage_of_arm_xz)]
fn bench_unpack(image: Vec<u8>) {
    black_box(hereticus_unpack::unpack(&image).expect("the zImage unpacks"));
}

#[library_benchmark]
#[bench::mips_kernel(setup = mips_kernel)]
fn bench_cie_scan(kernel: Vec<u8>) {
    use hereticus_recovery::unwind::{ByteOrder, find_function_ranges};
    black_box(find_function_ranges(&kernel, 0x8000_0000, ByteOrder::Big));
}

#[library_benchmark]
#[bench::mips_kernel(setup = mips_kernel)]
fn bench_stub_scan(kernel: Vec<u8>) {
    use hereticus_recovery::mips_stubs::{ByteOrder, lazy_stubs};
    black_box(lazy_stubs(0x8000_0000, &kernel, ByteOrder::Big));
}

// Decode and lift each instruction of a `.text`, one after the other.
#[library_benchmark]
#[bench::lua_mips16(args = (LUA_MIPS16,), setup = text_of)]
#[bench::lua_mips(args = (LUA_MIPS,), setup = text_of)]
#[bench::lua_powerpc(args = (LUA_POWERPC,), setup = text_of)]
#[bench::lua_powerpc64(args = (LUA_POWERPC64,), setup = text_of)]
#[bench::lua_aarch64(args = (LUA_AARCH64,), setup = text_of)]
#[bench::lua_x86_64(args = (LUA_X86_64,), setup = text_of)]
fn bench_decode((isa, text): (Isa, Vec<u8>)) {
    let arch = isa.arch();
    let mut offset = 0;
    while offset < text.len() {
        let width = match arch.decode(&text, offset, 0x1000) {
            Ok(insn) => {
                black_box(arch.lift(&insn));
                insn.bytes_len
            }
            Err(_) => arch.instruction_width(),
        };
        offset += width.max(1);
    }
}

#[library_benchmark]
#[bench::lua_mips16_stripped(args = (LUA_MIPS16, Reading::Stripped), setup = load_before)]
#[bench::lua_mips_raw(args = (LUA_MIPS, Reading::Raw), setup = load_before)]
#[bench::lua_powerpc_stripped(args = (LUA_POWERPC, Reading::Stripped), setup = load_before)]
#[bench::lua_powerpc64_symbols(args = (LUA_POWERPC64, Reading::Symbols), setup = load_before)]
#[bench::lua_aarch64_raw(args = (LUA_AARCH64, Reading::Raw), setup = load_before)]
#[bench::lua_x86_64_raw(args = (LUA_X86_64, Reading::Raw), setup = load_before)]
fn bench_parse(image: Image) -> Binary {
    black_box(image.parse())
}

library_benchmark_group!(
    name = formats,
    benchmarks = [bench_unpack, bench_cie_scan, bench_stub_scan]
);

library_benchmark_group!(name = decoders, benchmarks = [bench_decode, bench_parse]);

main!(
    // As in `gungraun_benchmark.rs`: one thread, so a count is the same on
    // each run.
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default())
        .env("RAYON_NUM_THREADS", "1");
    library_benchmark_groups = formats, decoders
);
