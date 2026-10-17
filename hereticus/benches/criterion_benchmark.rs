//! Wall time of the two stages of a comparison: read each binary, then
//! compare the pair. Run `just backports` first.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

mod common;
use common::{Build, Image, LUA_ARM, Reading, Side, ZLIB_X86_64, compare, pair};

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

const PARSE_CASES: &[(&str, Build, Reading)] = &[
    ("zlib_x86_64_symbols", ZLIB_X86_64, Reading::Symbols),
    ("zlib_x86_64_stripped", ZLIB_X86_64, Reading::Stripped),
    ("zlib_x86_64_raw", ZLIB_X86_64, Reading::Raw),
    ("lua_arm_raw", LUA_ARM, Reading::Raw),
];

const DIFF_CASES: &[(&str, Build, Reading)] = &[
    ("zlib_x86_64_symbols", ZLIB_X86_64, Reading::Symbols),
    ("lua_arm_stripped", LUA_ARM, Reading::Stripped),
    ("lua_arm_raw", LUA_ARM, Reading::Raw),
];

fn bench_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse");
    for &(name, build, reading) in PARSE_CASES {
        let image = Image::load(build, Side::Before, reading);
        group.bench_function(name, |b| b.iter(|| black_box(image.parse())));
    }
    group.finish();
}

fn bench_diff(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff");
    for &(name, build, reading) in DIFF_CASES {
        let binaries = pair(build, reading);
        group.bench_function(name, |b| b.iter(|| black_box(compare(&binaries))));
    }
    group.finish();
}

criterion_group!(benches, bench_parse, bench_diff);
criterion_main!(benches);
