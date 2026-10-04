//! The IL view names what code points at: the texts it passes and the
//! functions it calls, on every architecture.

use std::path::Path;

use hereticus::arch::decode_all;
use hereticus::matching::{DiffLine, Options, View, diff_with, instruction_diff_in};
use hereticus::obj::Binary;
use hereticus::view::{Context, il_lines_in};
use rstest::rstest;

/// A library of the backports, built by GCC at -O2 for `arch`.
fn library(project: &str, variant: &str, arch: &str) -> Binary {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../fixtures/build/backports/{project}-{variant}"))
        .join(format!("{arch}-gcc-O2/lib.so"));
    let data = std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{}: {err}, run `just backports` first", path.display()));
    Binary::parse(&data).expect("a fixture library parses")
}

/// The IL of `gz_error` of zlib, built by GCC at -O2 for `arch`.
fn gz_error(arch: &str) -> Vec<String> {
    let binary = library("zlib", "before", arch);
    let function = binary.functions.iter().find(|f| f.name == "gz_error").expect("gz_error");
    let isa = binary.isa_of(function).arch();
    let (insns, _) = decode_all(isa, &function.code, function.address);
    let context =
        Context { links: &binary.links, space: &binary.addresses, functions: &binary.functions };
    il_lines_in(isa, &function.code, &insns, Some(context))
}

#[rstest]
fn the_il_names_texts_and_callees(
    #[values("arm", "thumb", "aarch64", "mips", "mipsel", "mips16")] arch: &str,
) {
    let lines = gz_error(arch);
    let has = |wanted: &str| lines.iter().any(|line| line.ends_with(wanted));
    assert!(has("call strlen"), "{arch}: {lines:#?}");
    // GCC calls `snprintf` last, and for AArch64 it jumps there instead.
    assert!(has("call snprintf") || has("goto snprintf"), "{arch}: {lines:#?}");
    assert!(has("= &\"%s%s%s\""), "{arch}: {lines:#?}");
}

/// The whole IL of one function, so a change to how any statement reads
/// shows in review.
#[rstest]
fn the_il_of_a_function_is_locked(
    #[values("arm", "thumb", "aarch64", "mips", "mipsel", "mips16")] arch: &str,
) {
    insta::assert_snapshot!(format!("gz_error_{arch}"), gz_error(arch).join("\n"));
}

/// The IL view of the Lua fix, as `--view il --diff luaZ_fill` shows it.
#[rstest]
fn the_il_diff_of_a_fix_is_locked(#[values("arm", "aarch64", "mips16")] arch: &str) {
    let (before, after) = (library("lua", "before", arch), library("lua", "after", arch));
    let diff = diff_with(&before, &after, Options::default());
    let index = before.functions.iter().position(|f| f.name == "luaZ_fill").expect("luaZ_fill");
    let pair = diff.matched.iter().find(|pair| pair.before == index).expect("luaZ_fill pairs");
    let lines = instruction_diff_in(View::Il, &before, pair.before, &after, pair.after);
    let shown: Vec<String> = lines
        .iter()
        .map(|line| match line {
            DiffLine::Same(text) => format!("  {text}"),
            DiffLine::Added(text) => format!("+ {text}"),
            DiffLine::Removed(text) => format!("- {text}"),
            DiffLine::Changed { before, after } => format!("- {before}\n+ {after}"),
        })
        .collect();
    insta::assert_snapshot!(format!("lua_fix_{arch}"), shown.join("\n"));
}
