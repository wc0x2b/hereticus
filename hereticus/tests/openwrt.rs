//! Compare two real OpenWrt releases, 22.03.2 and 22.03.5, on three boards.
//!
//! The fixtures are the code a vendor ships, with no symbols: the stub that
//! decompresses each kernel, and the kernel itself. `just firmware` downloads
//! them and pins every byte by its SHA-256, so the counts below are exact.
//!
//! | Board | Code | Loads at |
//! |---|---|---|
//! | Netgear EX6100v2 | ARM32 zImage stub and kernel | `0x80208000` |
//! | TP-Link EAP245 v3 | MIPS32 big-endian lzma-loader and kernel | `0x80060000` |
//! | Netgear R6220 | MIPS32 little-endian lzma-loader and kernel | `0x80001000` |
//!
//! Nothing here says which answer is right: no symbol table exists to check
//! against. These tests record what the tool reports, so a change to it is
//! seen and judged, and they check the properties that must hold whatever the
//! answer: no changed byte goes unreported, and the byte order and the base
//! do not change the answer.
//!
//! The kernel tests take about ten seconds each, so they are named `slow` and
//! `just quick-test` skips them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hereticus::matching::{Changed, Diff, Options, UseNames, diff_with};
use hereticus::obj::{Binary, Isa};
use hereticus::raw::{BaseFit, check_base};
use rstest::rstest;

mod common;
use common::render;

/// One board: the name its files carry, how its code reads, and where it
/// loads.
#[derive(Clone, Copy, Debug)]
struct Board {
    name: &'static str,
    isa: Isa,
    base: u64,
}

const EX6100V2: Board = Board { name: "arm-ex6100v2", isa: Isa::Arm32, base: 0x8020_8000 };
const EAP245V3: Board = Board { name: "mipsbe-eap245v3", isa: Isa::Mips32Be, base: 0x8006_0000 };
const R6220: Board = Board { name: "mipsel-r6220", isa: Isa::Mips32, base: 0x8000_1000 };

/// The two parts of each image the tests compare.
#[derive(Clone, Copy, Debug)]
enum Part {
    Stub,
    Kernel,
}

impl Part {
    fn file_name(self) -> &'static str {
        match self {
            Self::Stub => "stub",
            Self::Kernel => "kernel",
        }
    }
}

const BEFORE: &str = "22.03.2";
const AFTER: &str = "22.03.5";

fn firmware() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/openwrt")
}

fn read(board: Board, part: Part, release: &str) -> Vec<u8> {
    let path = firmware().join(format!("{}-{}-{release}.bin", board.name, part.file_name()));
    std::fs::read(&path)
        .unwrap_or_else(|err| panic!("{}: {err}, run `just firmware` first", path.display()))
}

fn blind() -> Options {
    Options { use_names: UseNames::No, ..Default::default() }
}

/// Both releases of one part, read and compared.
struct Comparison {
    before_bytes: Vec<u8>,
    after_bytes: Vec<u8>,
    before: Binary,
    after: Binary,
    diff: Diff,
}

fn compare(board: Board, part: Part) -> Comparison {
    compare_at(board, part, board.base)
}

fn compare_at(board: Board, part: Part, base: u64) -> Comparison {
    let before_bytes = read(board, part, BEFORE);
    let after_bytes = read(board, part, AFTER);
    let before = Binary::parse_raw(&before_bytes, base, board.isa).expect("the image must read");
    let after = Binary::parse_raw(&after_bytes, base, board.isa).expect("the image must read");
    let diff = diff_with(&before, &after, blind());
    Comparison { before_bytes, after_bytes, before, after, diff }
}

/// The counts a reader sees in the summary line, and the kind of each change.
fn summary(comparison: &Comparison) -> String {
    let mut verdicts: BTreeMap<Changed, usize> = BTreeMap::new();
    for pair in &comparison.diff.matched {
        *verdicts.entry(pair.changed).or_default() += 1;
    }
    format!(
        "functions {} -> {}\nmatched {}\n{verdicts:?}\ngone {}\nnew {}\n",
        comparison.before.functions.len(),
        comparison.after.functions.len(),
        comparison.diff.matched.len(),
        comparison.diff.removed.len(),
        comparison.diff.added.len(),
    )
}

/// Count the pairs whose bytes differ but which are reported unchanged.
fn unreported_byte_changes(comparison: &Comparison) -> usize {
    comparison
        .diff
        .matched
        .iter()
        .filter(|pair| pair.changed == Changed::No)
        .filter(|pair| {
            comparison.before.functions[pair.before].code
                != comparison.after.functions[pair.after].code
        })
        .count()
}

/// A 64-bit FNV-1a hash, which is stable across Rust versions where the
/// standard hasher is not.
fn fingerprint(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// Reverse the bytes of each whole word, which turns a big-endian image into
/// the little-endian image of the same code.
fn swap_words(data: &[u8]) -> Vec<u8> {
    let whole = data.len() - data.len() % 4;
    let mut swapped: Vec<u8> =
        data[..whole].chunks_exact(4).flat_map(|word| word.iter().rev().copied()).collect();
    swapped.extend_from_slice(&data[whole..]);
    swapped
}

/// The whole stub report, one line per function.
///
/// A stub is 5 to 15 KiB, so its report is short enough to review in full.
#[rstest]
#[case::arm_ex6100v2(EX6100V2)]
#[case::mipsbe_eap245v3(EAP245V3)]
#[case::mipsel_r6220(R6220)]
fn the_stub_report_is_locked(#[case] board: Board) {
    let comparison = compare(board, Part::Stub);
    let report = render(&comparison.diff, &comparison.before, &comparison.after);
    insta::assert_snapshot!(format!("stub_{}", board.name), report);
}

/// What changed in each stub between the two releases, stated outright.
///
/// Each MIPS lzma-loader changed only the constants that say where the
/// kernel sits and how long it is. The ARM stub was rebuilt with real code
/// changes.
#[rstest]
#[case::arm_ex6100v2(EX6100V2, [69, 69], &[(Changed::No, 58), (Changed::InDetail, 3), (Changed::Yes, 7), (Changed::Unreadable, 1)], 0, 0)]
#[case::mipsbe_eap245v3(EAP245V3, [8, 8], &[(Changed::No, 6), (Changed::InDetail, 2)], 0, 0)]
#[case::mipsel_r6220(R6220, [8, 8], &[(Changed::No, 6), (Changed::InDetail, 2)], 0, 0)]
fn the_stub_changes_are_known(
    #[case] board: Board,
    #[case] functions: [usize; 2],
    #[case] verdicts: &[(Changed, usize)],
    #[case] gone: usize,
    #[case] new: usize,
) {
    let comparison = compare(board, Part::Stub);

    assert_eq!(
        [comparison.before.functions.len(), comparison.after.functions.len()],
        functions,
        "functions found in each release"
    );

    let mut found: BTreeMap<Changed, usize> = BTreeMap::new();
    for pair in &comparison.diff.matched {
        *found.entry(pair.changed).or_default() += 1;
    }
    assert_eq!(found, verdicts.iter().copied().collect(), "verdicts of the matched pairs");
    assert_eq!(comparison.diff.removed.len(), gone, "gone functions");
    assert_eq!(comparison.diff.added.len(), new, "new functions");
}

/// The functions each MIPS stub reports as changed, by address.
#[rstest]
#[case::mipsbe_eap245v3(EAP245V3, &[0x8006_005c, 0x8006_0940])]
#[case::mipsel_r6220(R6220, &[0x8000_1044, 0x8000_1920])]
fn the_mips_stub_changes_sit_where_expected(#[case] board: Board, #[case] expected: &[u64]) {
    let comparison = compare(board, Part::Stub);
    let mut changed: Vec<u64> = comparison
        .diff
        .changed()
        .map(|pair| comparison.before.functions[pair.before].address)
        .collect();
    changed.sort_unstable();
    assert_eq!(changed, expected);
}

/// Every byte that differs between the releases lies in a function the report
/// names, as changed or as gone.
///
/// The stubs are the same length in both releases, so a byte offset means the
/// same place in each. This is the property the tool exists for: an edit that
/// fell outside every reported function would be invisible to the reader.
#[rstest]
#[case::arm_ex6100v2(EX6100V2)]
#[case::mipsbe_eap245v3(EAP245V3)]
#[case::mipsel_r6220(R6220)]
fn every_changed_stub_byte_is_reported(#[case] board: Board) {
    let comparison = compare(board, Part::Stub);
    assert_eq!(comparison.before_bytes.len(), comparison.after_bytes.len());

    let span = |index: usize| {
        let function = &comparison.before.functions[index];
        function.address..function.address + function.code.len() as u64
    };
    let reported: Vec<_> = comparison
        .diff
        .changed()
        .map(|pair| span(pair.before))
        .chain(comparison.diff.removed.iter().map(|&index| span(index)))
        .collect();

    let changed_bytes = comparison
        .before_bytes
        .iter()
        .zip(&comparison.after_bytes)
        .enumerate()
        .filter(|(_, (before, after))| before != after)
        .map(|(offset, _)| board.base + offset as u64);

    let mut count = 0;
    for address in changed_bytes {
        count += 1;
        assert!(
            reported.iter().any(|range| range.contains(&address)),
            "{}: the byte at {address:#x} changed, but no reported function holds it",
            board.name
        );
    }
    assert!(count > 0, "the releases must differ, or this test checks nothing");
}

/// A pair whose bytes differ is never reported as unchanged in a stub.
#[rstest]
#[case::arm_ex6100v2(EX6100V2)]
#[case::mipsbe_eap245v3(EAP245V3)]
#[case::mipsel_r6220(R6220)]
fn no_stub_pair_with_different_bytes_reads_as_unchanged(#[case] board: Board) {
    assert_eq!(unreported_byte_changes(&compare(board, Part::Stub)), 0);
}

/// Each release compared with itself reports nothing.
#[rstest]
#[case::arm_ex6100v2(EX6100V2)]
#[case::mipsbe_eap245v3(EAP245V3)]
#[case::mipsel_r6220(R6220)]
fn a_stub_compared_with_itself_reports_nothing(
    #[case] board: Board,
    #[values(BEFORE, AFTER)] release: &str,
) {
    let binary = Binary::parse_raw(&read(board, Part::Stub, release), board.base, board.isa)
        .expect("the image must read");
    let diff = diff_with(&binary, &binary, blind());

    assert_eq!(diff.matched.len(), binary.functions.len());
    assert_eq!(diff.changed().count(), 0);
    assert!(diff.removed.is_empty() && diff.added.is_empty());
}

/// The stubs hold no absolute addresses to judge a base by.
///
/// Each stub runs wherever it is loaded before it moves anything, so it is
/// built to hold only relative addresses. The check must stay silent rather
/// than accuse the right base.
#[rstest]
#[case::arm_ex6100v2(EX6100V2)]
#[case::mipsbe_eap245v3(EAP245V3)]
#[case::mipsel_r6220(R6220)]
fn the_base_check_has_no_evidence_in_a_stub(
    #[case] board: Board,
    #[values(BEFORE, AFTER)] release: &str,
) {
    let data = read(board, Part::Stub, release);
    assert_eq!(check_base(&data, board.base, board.isa.arch()), BaseFit::NoEvidence);
}

/// The base shifts every address in the report, and changes nothing else.
#[rstest]
#[case::arm_ex6100v2(EX6100V2)]
#[case::mipsbe_eap245v3(EAP245V3)]
#[case::mipsel_r6220(R6220)]
fn the_base_does_not_change_a_stub_report(#[case] board: Board) {
    let at_zero = compare_at(board, Part::Stub, 0);
    let at_base = compare(board, Part::Stub);

    assert_eq!(summary(&at_zero), summary(&at_base));

    let changed = |comparison: &Comparison, base: u64| -> Vec<u64> {
        let mut found: Vec<u64> = comparison
            .diff
            .changed()
            .map(|pair| comparison.before.functions[pair.before].address - base)
            .collect();
        found.sort_unstable();
        found
    };
    assert_eq!(changed(&at_zero, 0), changed(&at_base, board.base));
}

/// A big-endian stub, word swapped and read as little endian, reports the
/// same thing. Real firmware exercises far more encodings than the fixtures.
#[test]
fn a_mips_stub_reads_alike_in_either_byte_order() {
    let board = EAP245V3;
    let big = compare(board, Part::Stub);

    let little_before = swap_words(&big.before_bytes);
    let little_after = swap_words(&big.after_bytes);
    let before = Binary::parse_raw(&little_before, board.base, Isa::Mips32).unwrap();
    let after = Binary::parse_raw(&little_after, board.base, Isa::Mips32).unwrap();

    assert_eq!(
        render(&diff_with(&before, &after, blind()), &before, &after),
        render(&big.diff, &big.before, &big.after)
    );
}

/// The kernel comparison of one board, recorded as a summary, the strongest
/// real changes, and a fingerprint of the whole report.
///
/// The full report runs to twenty thousand lines, too long to keep as a
/// snapshot. The fingerprint catches any change to it; the summary and the
/// top rows show where to look when it does.
fn check_kernel(board: Board, unreported: usize, base_fit: [BaseFit; 2]) {
    let comparison = compare(board, Part::Kernel);
    let report = render(&comparison.diff, &comparison.before, &comparison.after);

    let mut strongest: Vec<_> =
        comparison.diff.matched.iter().filter(|pair| pair.changed == Changed::Yes).collect();
    strongest.sort_by(|left, right| {
        right.score.total_cmp(&left.score).then(left.before.cmp(&right.before))
    });
    let top: Vec<String> = strongest
        .iter()
        .take(40)
        .map(|pair| {
            format!(
                "{:#x} -> {:#x} score={:.3} edits={:?} kinds={:?}",
                comparison.before.functions[pair.before].address,
                comparison.after.functions[pair.after].address,
                pair.score,
                pair.edits,
                pair.kinds
            )
        })
        .collect();

    insta::assert_snapshot!(
        format!("kernel_{}", board.name),
        format!(
            "{}fingerprint {:#018x}\n\nstrongest changes:\n{}\n",
            summary(&comparison),
            fingerprint(&report),
            top.join("\n")
        )
    );

    assert_eq!(unreported_byte_changes(&comparison), unreported, "{}", board.name);
    assert_eq!(
        [
            check_base(&comparison.before_bytes, board.base, board.isa.arch()),
            check_base(&comparison.after_bytes, board.base, board.isa.arch()),
        ],
        base_fit,
        "{}",
        board.name
    );
}

/// The ARM kernel.
///
/// Thousands of pairs differ in their bytes yet read as unchanged. ARM code
/// reaches its data through PC-relative loads, so code that only moved gets
/// new offsets, and normalizing drops those on purpose.
#[test]
fn slow_the_arm_kernel_report_is_locked() {
    check_kernel(
        EX6100V2,
        6009,
        [
            BaseFit::Plausible { pointers: 13223, examined: 1_948_430 },
            BaseFit::Plausible { pointers: 13263, examined: 1_957_980 },
        ],
    );
}

/// The big-endian MIPS kernel.
///
/// MIPS code holds absolute addresses in `lui` and `jal`. Those that point
/// into the image are dropped as addresses, so code that only moved reads as
/// unchanged, as it does on ARM, and its bytes still differ. The `changed
/// values` left are mostly struct offsets that moved, which are real.
#[test]
fn slow_the_big_endian_mips_kernel_report_is_locked() {
    check_kernel(
        EAP245V3,
        12978,
        [
            BaseFit::Plausible { pointers: 47586, examined: 1_624_990 },
            BaseFit::Plausible { pointers: 47778, examined: 1_634_158 },
        ],
    );
}

/// The little-endian MIPS kernel.
#[test]
fn slow_the_little_endian_mips_kernel_report_is_locked() {
    check_kernel(
        R6220,
        14649,
        [
            BaseFit::Plausible { pointers: 50248, examined: 1_931_464 },
            BaseFit::Plausible { pointers: 50444, examined: 1_941_370 },
        ],
    );
}

/// The OpenWrt fixtures are all present, so no test above reads a stale or a
/// missing file without saying so.
#[test]
fn every_firmware_file_is_present() {
    for board in [EX6100V2, EAP245V3, R6220] {
        for part in [Part::Stub, Part::Kernel] {
            for release in [BEFORE, AFTER] {
                assert!(!read(board, part, release).is_empty());
            }
        }
    }
}
