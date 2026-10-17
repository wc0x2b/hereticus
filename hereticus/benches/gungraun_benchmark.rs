//! Instruction counts of the two stages of a comparison: read each binary,
//! then compare the pair. Valgrind runs each bench, thus a count is almost
//! the same on each run, and CI can compare two branches. Run
//! `just backports` first.

use std::hint::black_box;

use gungraun::{
    Callgrind, LibraryBenchmarkConfig, library_benchmark, library_benchmark_group, main,
};
use hereticus::obj::Binary;

mod common;
use common::{Build, Image, LUA_ARM, Reading, Side, ZLIB_X86_64, compare, pair};

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn load_before(build: Build, reading: Reading) -> Image {
    Image::load(build, Side::Before, reading)
}

#[library_benchmark]
#[bench::zlib_x86_64_symbols(args = (ZLIB_X86_64, Reading::Symbols), setup = load_before)]
#[bench::zlib_x86_64_stripped(args = (ZLIB_X86_64, Reading::Stripped), setup = load_before)]
#[bench::zlib_x86_64_raw(args = (ZLIB_X86_64, Reading::Raw), setup = load_before)]
#[bench::lua_arm_raw(args = (LUA_ARM, Reading::Raw), setup = load_before)]
fn bench_parse(image: Image) -> Binary {
    black_box(image.parse())
}

#[library_benchmark]
#[bench::zlib_x86_64_symbols(args = (ZLIB_X86_64, Reading::Symbols), setup = pair)]
#[bench::lua_arm_stripped(args = (LUA_ARM, Reading::Stripped), setup = pair)]
#[bench::lua_arm_raw(args = (LUA_ARM, Reading::Raw), setup = pair)]
fn bench_diff(binaries: (Binary, Binary)) {
    black_box(compare(&binaries));
}

library_benchmark_group!(name = parse, benchmarks = bench_parse);

library_benchmark_group!(name = diff, benchmarks = bench_diff);

main!(
    // Valgrind runs one thread at a time, and the idle threads of rayon would
    // add the instructions of their wait loops, which change from run to run.
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default())
        .env("RAYON_NUM_THREADS", "1");
    library_benchmark_groups = parse, diff
);
