//! The IL view names what code points at: the texts it passes and the
//! functions it calls, on every architecture.

use std::path::Path;

use hereticus::matching::{DiffLine, Options, View, diff_with, instruction_diff_in, line_places};
use hereticus::obj::Binary;
use hereticus::recovery::arch::decode_all;
use hereticus::view::{Context, il_line_addresses, il_line_depths, il_lines_in};
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
    let context = Context {
        links: &binary.links,
        space: &binary.addresses,
        functions: &binary.functions,
        paired: None,
    };
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

/// The IL of `gz_error`, each line indented two spaces for each level
/// deep it sits, as the TUI shows it.
fn gz_error_indented(arch: &str) -> String {
    let binary = library("zlib", "before", arch);
    let function = binary.functions.iter().find(|f| f.name == "gz_error").expect("gz_error");
    let isa = binary.isa_of(function).arch();
    let (insns, _) = decode_all(isa, &function.code, function.address);
    let depths = il_line_depths(isa, &insns);
    let lines = gz_error(arch);
    assert_eq!(depths.len(), lines.len(), "{arch}: a depth for each line");
    depths
        .into_iter()
        .zip(lines)
        .map(|(depth, line)| format!("{}{line}", "  ".repeat(depth)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The indent of the whole IL of one function, so a change to how deep
/// any line sits shows in review.
#[rstest]
fn the_indented_il_of_a_function_is_locked(
    #[values("arm", "thumb", "aarch64", "mips", "mipsel", "mips16", "i686", "x86_64")] arch: &str,
) {
    let indented = gz_error_indented(arch);
    assert!(indented.lines().any(|line| line.starts_with("  ")), "{arch}: {indented}");
    insta::assert_snapshot!(format!("gz_error_indented_{arch}"), indented);
}

/// Each function of a library takes a depth for each line it shows, and
/// a library of loops has lines in a loop in an `if`.
#[rstest]
fn each_line_of_each_function_takes_a_depth(
    #[values("arm", "thumb", "aarch64", "mips", "mipsel", "mips16", "i686", "x86_64")] arch: &str,
) {
    let binary = library("lua", "before", arch);
    let mut deepest = 0;
    for function in &binary.functions {
        let isa = binary.isa_of(function).arch();
        let (insns, _) = decode_all(isa, &function.code, function.address);
        let depths = il_line_depths(isa, &insns);
        assert_eq!(depths.len(), il_line_addresses(isa, &insns).len(), "{arch}: {}", function.name);
        assert_eq!(
            depths.first().copied().unwrap_or(0),
            0,
            "{arch}: {} starts at no depth",
            function.name
        );
        deepest = deepest.max(depths.into_iter().max().unwrap_or(0));
    }
    assert!(deepest >= 2, "{arch}: the deepest line of Lua sits {deepest} levels deep");
}

/// The places of the lines of the IL view hold their depths, and those of
/// the assembly view none.
#[rstest]
fn only_the_il_view_indents(
    #[values("arm", "thumb", "aarch64", "mips", "mipsel", "mips16", "i686", "x86_64")] arch: &str,
) {
    let binary = library("zlib", "before", arch);
    let index = binary.functions.iter().position(|f| f.name == "gz_error").expect("gz_error");
    let assembly = line_places(View::Assembly, &binary, index);
    assert!(assembly.iter().all(|place| place.depth == 0), "{arch}");
    let il = line_places(View::Il, &binary, index);
    assert!(il.iter().any(|place| place.depth > 0), "{arch}");
    assert!(il.is_sorted_by(|earlier, later| earlier.address < later.address), "{arch}");
}

/// The IL view of the Lua fix, as `--view il --diff luaZ_fill` shows it.
#[rstest]
fn the_il_diff_of_a_fix_is_locked(#[values("arm", "aarch64", "mips16")] arch: &str) {
    let (before, after) = (library("lua", "before", arch), library("lua", "after", arch));
    let diff = diff_with(&before, &after, Options::default());
    let index = before.functions.iter().position(|f| f.name == "luaZ_fill").expect("luaZ_fill");
    let pair = diff.matched.iter().find(|pair| pair.before == index).expect("luaZ_fill pairs");
    let lines = instruction_diff_in(
        View::Il,
        Some(&diff.paired_labels(&before, &after)),
        &before,
        pair.before,
        &after,
        pair.after,
    );
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

/// The stripped library of the backports, built by GCC at -O2 for `arch`.
fn stripped(project: &str, variant: &str, arch: &str) -> Binary {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../fixtures/build/backports/{project}-{variant}"))
        .join(format!("{arch}-gcc-O2/lib-stripped.so"));
    let data = std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{}: {err}, run `just backports` first", path.display()));
    Binary::parse(&data).expect("a fixture library parses")
}

/// A call to a stripped function names it as its pair does, so the call
/// reads the same on both sides of a diff, though its address moved. The
/// Lua fix changes no call to a stripped function. MIPS16e code calls
/// through a register, so it names no stripped callee.
#[rstest]
fn a_call_to_a_stripped_function_names_its_pair(
    #[values("arm", "thumb", "aarch64", "mips")] arch: &str,
) {
    let (before, after) = (stripped("lua", "before", arch), stripped("lua", "after", arch));
    let diff = diff_with(&before, &after, Options::default());
    let paired = diff.paired_labels(&before, &after);
    let (mut same, mut differ) = (0, Vec::new());
    for pair in &diff.matched {
        let lines =
            instruction_diff_in(View::Il, Some(&paired), &before, pair.before, &after, pair.after);
        for line in lines {
            match line {
                DiffLine::Same(text) if text.contains("sub_") => same += 1,
                DiffLine::Added(text) | DiffLine::Removed(text) if text.contains("sub_") => {
                    differ.push(text)
                }
                _ => {}
            }
        }
    }
    assert!(same > 1000, "{arch}: {same} calls to a stripped function");
    assert_eq!(differ, Vec::<String>::new(), "{arch}");
}
