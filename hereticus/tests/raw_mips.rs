//! Compare MIPS firmware images that carry no container format.
//!
//! The MIPS twin of `raw.rs`. Each raw image is the `.text` of a known object,
//! so the object's symbol table and its own comparison are the answer a raw
//! read must give. Every case runs in both byte orders, because firmware ships
//! big endian and a desktop build is little endian, and each order has its own
//! decoder.
//!
//! The snapshots record each full report, so a change to any score, edit count
//! or boundary shows up as a diff to review rather than passing unseen.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hereticus::matching::{Diff, Options, UseNames, diff_with};
use hereticus::obj::{Binary, FoundBy, Isa, ObjError};
use hereticus::raw::{BaseFit, check_base};
use rstest::rstest;

mod common;
use common::render;

/// Where the MIPS vector tables are linked. Must agree with
/// `fixtures/build.sh`.
const VECTOR_BASE: u64 = 0x8000_0000;

/// Every C fixture, each built into every MIPS tree.
const SOURCES: [&str; 6] = ["basic", "basic_v2", "calls", "globals", "firmware", "firmware_v2"];

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build")
}

fn read_raw(name: &str) -> Vec<u8> {
    let path = fixtures().join("raw").join(name);
    std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{}: {err}, run `just fixtures` first", path.display()))
}

fn read_object(tree: &str, name: &str) -> Binary {
    let path = fixtures().join(tree).join(format!("{name}.o"));
    let data = std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{}: {err}, run `just fixtures` first", path.display()));
    Binary::parse(&data).expect("a fixture object must parse")
}

fn parse_raw(tree: &str, name: &str, base: u64, isa: Isa) -> Binary {
    Binary::parse_raw(&read_raw(&format!("{tree}-{name}.bin")), base, isa)
        .expect("a raw fixture must yield functions")
}

fn blind() -> Options {
    Options { use_names: UseNames::No, ..Default::default() }
}

fn addresses(binary: &Binary) -> Vec<u64> {
    binary.functions.iter().map(|function| function.address).collect()
}

fn changed_addresses(diff: &Diff, before: &Binary) -> Vec<u64> {
    let mut found: Vec<u64> =
        diff.changed().map(|pair| before.functions[pair.before].address).collect();
    found.sort_unstable();
    found
}

/// A raw image gives up exactly the functions its object holds.
///
/// Unlike ARM, MIPS code keeps no literal pools inside `.text`, and every
/// fixture function ends in a return, so recovery neither splits nor merges
/// here. The test asks for equality rather than a superset for that reason.
#[rstest]
fn recovers_exactly_the_functions_of_its_object(
    #[values(
        "mips-O0",
        "mips-O2",
        "mipsbe-O0",
        "mipsbe-O2",
        "mips-pic-O2",
        "mipsbe-pic-O2",
        "mips-nopic-O2",
        "mipsbe-nopic-O2"
    )]
    tree: &str,
    #[values("basic", "basic_v2", "calls", "globals", "firmware", "firmware_v2")] name: &str,
) {
    let object = read_object(tree, name);
    let raw = parse_raw(tree, name, 0, object.isa);

    assert_eq!(raw.found_by, FoundBy::Scanning);
    assert_eq!(raw.isa, object.isa);

    let mut expected = addresses(&object);
    expected.sort_unstable();
    assert_eq!(addresses(&raw), expected, "{tree}/{name}: boundaries must match the symbols");

    for real in &object.functions {
        let found = raw
            .functions
            .iter()
            .find(|function| function.address == real.address)
            .expect("the address was checked above");
        assert_eq!(found.code, real.code, "{tree}/{name}: {} must hold the same bytes", real.name);
    }
}

/// Comparisons where the object and its raw image pair the same functions
/// for different reasons, because only the object knows the calls.
///
/// A raw fixture is the `.text` of an object that was never linked, so each
/// `jal` holds no target until a relocation fills it in. The object reads
/// the relocations and the raw image cannot. At `-O0`, `check_header` and
/// `dispatch` each gain a call and score under the threshold against
/// themselves. The object pairs them by their callers and callees (see
/// `RESEARCH.md`, entry 1), and the raw image by their place between the
/// pairs around them (entry 7). A linked image holds the targets, so this
/// does not apply to a flash dump.
const CALLS_ONLY_IN_THE_OBJECT: &[(&str, &str)] =
    &[("mips-O0", "firmware"), ("mipsbe-O0", "firmware")];

/// Reading a raw image reports what reading its objects reports.
///
/// This is the property that matters, checked as the whole report: every
/// pair, score, edit count and kind of edit, not only the count of changes.
#[rstest]
fn a_raw_comparison_reports_what_the_objects_report(
    #[values(
        "mips-O0",
        "mips-O2",
        "mipsbe-O0",
        "mipsbe-O2",
        "mips-pic-O2",
        "mipsbe-pic-O2",
        "mips-nopic-O2",
        "mipsbe-nopic-O2"
    )]
    tree: &str,
    #[values("basic", "firmware")] name: &str,
) {
    let v2 = format!("{name}_v2");
    let (before_object, after_object) = (read_object(tree, name), read_object(tree, &v2));
    let isa = before_object.isa;
    let (before_raw, after_raw) = (parse_raw(tree, name, 0, isa), parse_raw(tree, &v2, 0, isa));

    let object_report =
        render(&diff_with(&before_object, &after_object, blind()), &before_object, &after_object);
    let raw_report = render(&diff_with(&before_raw, &after_raw, blind()), &before_raw, &after_raw);

    if CALLS_ONLY_IN_THE_OBJECT.contains(&(tree, name)) {
        let without_reasons = |report: &str| -> String {
            report
                .lines()
                .map(|line| line.split(" confidence=").next().unwrap_or(line))
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(
            without_reasons(&raw_report),
            without_reasons(&object_report),
            "{tree}/{name}: the raw image must pair what the object pairs"
        );
        assert_ne!(raw_report, object_report, "{tree}/{name}: remove it from the list");
    } else {
        assert_eq!(
            raw_report, object_report,
            "{tree}/{name}: the raw report must match the object"
        );
    }
    insta::assert_snapshot!(format!("report_{tree}_{name}"), raw_report);
}

/// The changes each build reports, stated outright.
///
/// The snapshots above hold the same answer, but a snapshot is easy to accept
/// by mistake. This names the addresses a reader can check against the
/// source edits.
#[rstest]
#[case::le_o0_basic("mips-O0", "basic", &[0x3c, 0xfc], 0, 0)]
#[case::be_o0_basic("mipsbe-O0", "basic", &[0x3c, 0xfc], 0, 0)]
#[case::le_o2_basic("mips-O2", "basic", &[0x08, 0x50, 0xa0], 0, 0)]
#[case::be_o2_basic("mipsbe-O2", "basic", &[0x08, 0x50, 0xa0], 0, 0)]
#[case::le_pic_basic("mips-pic-O2", "basic", &[0x08, 0x50, 0xa0], 0, 0)]
#[case::be_pic_basic("mipsbe-pic-O2", "basic", &[0x08, 0x50, 0xa0], 0, 0)]
#[case::le_nopic_basic("mips-nopic-O2", "basic", &[0x08, 0x50, 0xa0], 0, 0)]
#[case::be_nopic_basic("mipsbe-nopic-O2", "basic", &[0x08, 0x50, 0xa0], 0, 0)]
#[case::le_o0_firmware("mips-O0", "firmware", &[0x00, 0x70, 0x17c], 0, 0)]
#[case::be_o0_firmware("mipsbe-O0", "firmware", &[0x00, 0x70, 0x17c], 0, 0)]
#[case::le_o2_firmware("mips-O2", "firmware", &[0x00, 0x10, 0x58, 0xdc], 0, 0)]
#[case::be_o2_firmware("mipsbe-O2", "firmware", &[0x00, 0x10, 0x58, 0xdc], 0, 0)]
#[case::le_pic_firmware("mips-pic-O2", "firmware", &[0x00, 0x10, 0x58, 0xdc], 0, 0)]
#[case::be_pic_firmware("mipsbe-pic-O2", "firmware", &[0x00, 0x10, 0x58, 0xdc], 0, 0)]
#[case::le_nopic_firmware("mips-nopic-O2", "firmware", &[0x00, 0x10, 0x58, 0xdc], 0, 0)]
#[case::be_nopic_firmware("mipsbe-nopic-O2", "firmware", &[0x00, 0x10, 0x58, 0xdc], 0, 0)]
fn a_raw_comparison_finds_the_known_changes(
    #[case] tree: &str,
    #[case] name: &str,
    #[case] changed: &[u64],
    #[case] gone: usize,
    #[case] new: usize,
) {
    let isa = read_object(tree, name).isa;
    let before = parse_raw(tree, name, 0, isa);
    let after = parse_raw(tree, &format!("{name}_v2"), 0, isa);
    let diff = diff_with(&before, &after, blind());

    assert_eq!(changed_addresses(&diff, &before), changed, "{tree}/{name}: changed functions");
    assert_eq!(diff.removed.len(), gone, "{tree}/{name}: gone functions");
    assert_eq!(diff.added.len(), new, "{tree}/{name}: new functions");
}

/// The same source gives the same report in either byte order.
///
/// Every rule above the decoder reads decoded text. A rule that reached for
/// raw bytes would work in one order and fail in the other, and the order it
/// would fail in is the one firmware ships in.
#[rstest]
fn both_byte_orders_give_one_report(
    #[values(("mips-O0", "mipsbe-O0"), ("mips-O2", "mipsbe-O2"), ("mips-pic-O2", "mipsbe-pic-O2"), ("mips-nopic-O2", "mipsbe-nopic-O2"))]
    trees: (&str, &str),
    #[values("basic", "firmware")] name: &str,
) {
    let report = |tree: &str, isa: Isa| {
        let before = parse_raw(tree, name, 0, isa);
        let after = parse_raw(tree, &format!("{name}_v2"), 0, isa);
        render(&diff_with(&before, &after, blind()), &before, &after)
    };

    let (little, big) = trees;
    assert_eq!(report(little, Isa::Mips32), report(big, Isa::Mips32Be), "{little} against {big}");
}

/// Each image compared with itself reports nothing.
#[rstest]
fn an_image_compared_with_itself_reports_nothing(
    #[values(("mips-O0", Isa::Mips32), ("mips-O2", Isa::Mips32), ("mipsbe-O0", Isa::Mips32Be), ("mipsbe-O2", Isa::Mips32Be), ("mips-pic-O2", Isa::Mips32), ("mipsbe-pic-O2", Isa::Mips32Be))]
    build: (&str, Isa),
    #[values("basic", "basic_v2", "calls", "globals", "firmware", "firmware_v2")] name: &str,
) {
    let (tree, isa) = build;
    let binary = parse_raw(tree, name, 0, isa);
    let diff = diff_with(&binary, &binary, blind());

    assert_eq!(diff.matched.len(), binary.functions.len(), "{tree}/{name}: every function pairs");
    assert_eq!(diff.changed().count(), 0, "{tree}/{name}: nothing changed");
    assert!(diff.removed.is_empty() && diff.added.is_empty());
}

/// Where an image loads must not change what the matcher sees.
///
/// The bases are the MIPS ones a reader meets: zero, KSEG0 where a kernel
/// runs, KSEG1 where the same memory is uncached, and the boot ROM.
#[rstest]
fn the_load_address_does_not_change_the_comparison(
    #[values(("mips-O2", Isa::Mips32), ("mipsbe-O2", Isa::Mips32Be), ("mipsbe-pic-O2", Isa::Mips32Be))]
    build: (&str, Isa),
    #[values(0x8000_0000, 0xa000_0000, 0xbfc0_0000, 0xffff_f000)] base: u64,
) {
    let (tree, isa) = build;
    for name in SOURCES {
        let low = parse_raw(tree, name, 0, isa);
        let high = parse_raw(tree, name, base, isa);

        let shifted: Vec<u64> = addresses(&low).iter().map(|address| address + base).collect();
        assert_eq!(addresses(&high), shifted, "{tree}/{name}: boundaries move with the base");

        let diff = diff_with(&low, &high, blind());
        assert_eq!(diff.changed().count(), 0, "{tree}/{name}: only the addresses differ");
        assert!(diff.removed.is_empty() && diff.added.is_empty());
    }
}

/// The change report is the same at any base, shifted by that base.
#[rstest]
fn the_changes_found_move_with_the_base(
    #[values(("mips-O2", Isa::Mips32), ("mipsbe-O2", Isa::Mips32Be))] build: (&str, Isa),
    #[values(0x8000_0000, 0xbfc0_0000)] base: u64,
) {
    let (tree, isa) = build;
    let changes = |base: u64| {
        let before = parse_raw(tree, "basic", base, isa);
        let after = parse_raw(tree, "basic_v2", base, isa);
        changed_addresses(&diff_with(&before, &after, blind()), &before)
    };

    let shifted: Vec<u64> = changes(0).iter().map(|address| address + base).collect();
    assert_eq!(changes(base), shifted);
}

/// Addresses are reported relative to the base the caller gave.
#[rstest]
fn reported_addresses_follow_the_base(
    #[values(("mips-O2", Isa::Mips32), ("mipsbe-O2", Isa::Mips32Be))] build: (&str, Isa),
) {
    let (tree, isa) = build;
    let raw = parse_raw(tree, "basic", VECTOR_BASE, isa);

    assert!(raw.functions.iter().all(|function| function.address >= VECTOR_BASE));
    assert_eq!(raw.functions[0].address, VECTOR_BASE, "the image starts with a function");
}

/// Recovery on a vector table, with its data words at the front.
///
/// The table words and `reset` read as one function, because nothing calls
/// `reset` and no return comes before it. That is a known limit of a scan
/// with no symbols, recorded here so a change to it is seen.
#[rstest]
fn recovers_the_handlers_of_a_vector_table(
    #[values(("vectors-mips.bin", Isa::Mips32), ("vectors-mipsbe.bin", Isa::Mips32Be))] image: (
        &str,
        Isa,
    ),
) {
    let (name, isa) = image;
    let raw = Binary::parse_raw(&read_raw(name), VECTOR_BASE, isa).unwrap();

    assert_eq!(addresses(&raw), [0x8000_0000, 0x8000_0018, 0x8000_0020, 0x8000_0100]);
}

/// The load-address check gives the same verdict at each base as on ARM, in
/// either byte order.
///
/// The image spans `0x80000000..0x80000108`, so a base wrong by a page or less
/// leaves its stored addresses just outside it, and a base further off leaves
/// nothing to judge by.
#[rstest]
#[case::right(VECTOR_BASE, BaseFit::Plausible { pointers: 4, examined: 12 })]
#[case::off_by_0x100(VECTOR_BASE + 0x100, BaseFit::Unlikely { pointers_elsewhere: 3 })]
#[case::off_by_0x400(VECTOR_BASE + 0x400, BaseFit::Unlikely { pointers_elsewhere: 4 })]
#[case::off_by_a_page(VECTOR_BASE + 0x1000, BaseFit::Unlikely { pointers_elsewhere: 4 })]
#[case::off_by_two_pages(VECTOR_BASE + 0x2000, BaseFit::NoEvidence)]
#[case::zero(0, BaseFit::NoEvidence)]
#[case::the_arm_base(0x0800_0000, BaseFit::NoEvidence)]
#[case::kseg1(0xa000_0000, BaseFit::NoEvidence)]
fn the_base_check_judges_a_mips_vector_table(
    #[case] base: u64,
    #[case] expected: BaseFit,
    #[values(("vectors-mips.bin", Isa::Mips32), ("vectors-mipsbe.bin", Isa::Mips32Be))] image: (
        &str,
        Isa,
    ),
) {
    let (name, isa) = image;
    assert_eq!(check_base(&read_raw(name), base, isa.arch()), expected, "{name} at {base:#x}");
}

/// Read in the wrong byte order, the stored addresses are nonsense, so the
/// check finds nothing to judge by rather than a false verdict.
#[rstest]
fn the_base_check_reads_pointers_in_the_image_byte_order(
    #[values(("vectors-mips.bin", Isa::Mips32Be), ("vectors-mipsbe.bin", Isa::Mips32))] image: (
        &str,
        Isa,
    ),
) {
    let (name, wrong) = image;
    assert_eq!(check_base(&read_raw(name), VECTOR_BASE, wrong.arch()), BaseFit::NoEvidence);
}

/// Compiled code holding no stored addresses cannot judge a base either way.
///
/// The C fixtures are unlinked, so they hold no absolute addresses. This is
/// the normal case and must not produce a warning.
#[rstest]
fn the_base_check_stays_quiet_without_evidence(
    #[values(("mips-O2", Isa::Mips32), ("mipsbe-O2", Isa::Mips32Be), ("mips-pic-O2", Isa::Mips32), ("mipsbe-pic-O2", Isa::Mips32Be))]
    build: (&str, Isa),
    #[values(0, 0x8000_0000, 0xbfc0_0000)] base: u64,
) {
    let (tree, isa) = build;
    for name in SOURCES {
        let fit = check_base(&read_raw(&format!("{tree}-{name}.bin")), base, isa.arch());
        assert!(!fit.is_suspect(), "{tree}/{name} at {base:#x}: got {fit:?}");
    }
}

/// An image read in the wrong byte order does not fail. It decodes to one
/// long function, and compares as unchanged against itself.
///
/// The CLI cannot tell the order from the bytes, so this is what a user who
/// picks the wrong `--arch` gets. It must not panic or invent changes.
#[rstest]
fn the_wrong_byte_order_reads_as_one_function(
    #[values(("mips-O2", Isa::Mips32Be), ("mipsbe-O2", Isa::Mips32))] build: (&str, Isa),
) {
    let (tree, wrong) = build;
    for name in SOURCES {
        let binary = parse_raw(tree, name, 0, wrong);
        assert_eq!(binary.functions.len(), 1, "{tree}/{name}");
        assert_eq!(diff_with(&binary, &binary, blind()).changed().count(), 0);
    }
}

/// A partial word at the end does not disturb the functions before it.
#[rstest]
fn a_trailing_partial_word_keeps_every_function(
    #[values(("mips-O2", Isa::Mips32), ("mipsbe-O2", Isa::Mips32Be))] build: (&str, Isa),
    #[values(1, 2, 3)] extra: usize,
) {
    let (tree, isa) = build;
    for name in SOURCES {
        let whole = read_raw(&format!("{tree}-{name}.bin"));
        let mut ragged = whole.clone();
        ragged.extend(core::iter::repeat_n(0xa5, extra));

        let expected = addresses(&Binary::parse_raw(&whole, 0, isa).unwrap());
        let found = addresses(&Binary::parse_raw(&ragged, 0, isa).unwrap());
        assert_eq!(found, expected, "{tree}/{name} with {extra} extra bytes");
    }
}

/// Too few bytes to hold one instruction is refused, in either order.
#[rstest]
fn an_image_shorter_than_an_instruction_is_refused(
    #[values(Isa::Mips32, Isa::Mips32Be)] isa: Isa,
    #[values(0, 1, 2, 3)] length: usize,
) {
    let data = vec![0x24; length];
    assert!(matches!(Binary::parse_raw(&data, 0, isa), Err(ObjError::NoCode)));
}

/// An image of nothing but padding holds no function.
#[rstest]
fn an_image_of_padding_is_refused(
    #[values(Isa::Mips32, Isa::Mips32Be)] isa: Isa,
    #[values(4, 8, 64)] length: usize,
) {
    let data = vec![0; length];
    assert!(matches!(Binary::parse_raw(&data, 0, isa), Err(ObjError::NoFunctions)));
}

/// The smallest real function: `jr $ra` and the `nop` in its delay slot.
#[rstest]
#[case::little(Isa::Mips32, [0x08, 0x00, 0xe0, 0x03, 0, 0, 0, 0])]
#[case::big(Isa::Mips32Be, [0x03, 0xe0, 0x00, 0x08, 0, 0, 0, 0])]
fn a_lone_return_is_one_function(#[case] isa: Isa, #[case] data: [u8; 8]) {
    let binary = Binary::parse_raw(&data, 0x8000_0000, isa).unwrap();

    assert_eq!(binary.functions.len(), 1);
    assert_eq!(binary.functions[0].address, 0x8000_0000);
    assert_eq!(binary.functions[0].code, data, "the delay slot belongs to the return");
}

/// Every source built for MIPS has its raw image, so no case above quietly
/// skips one.
#[test]
fn every_mips_tree_has_its_raw_images() {
    let trees = BTreeSet::from([
        "mips-O0",
        "mips-O2",
        "mipsbe-O0",
        "mipsbe-O2",
        "mips-pic-O2",
        "mipsbe-pic-O2",
        "mips-nopic-O2",
        "mipsbe-nopic-O2",
    ]);
    for tree in trees {
        for name in SOURCES {
            let path = fixtures().join("raw").join(format!("{tree}-{name}.bin"));
            assert!(path.exists(), "{} is missing, run `just fixtures`", path.display());
        }
    }
}
