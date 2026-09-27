//! Compare real OpenWrt releases on six boards: 22.03.2 against 22.03.5 on
//! all of them, and 21.02.7, 22.03 and 23.05.5 across two kernel upgrades on
//! the first three.
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
//! | Marvell A385-DB-AP | ARM32 zImage stub and kernel, a Cortex-A9 | `0x8000` |
//! | TP-Link VR200 | MIPS32 big-endian kernel, a Lantiq xRX200 | `0x80002000` |
//! | GL.iNet GL-MT300N v2 | MIPS32 little-endian kernel, an MT7628 | `0x80000000` |
//!
//! An ARM kernel is compared at the virtual address it is linked at,
//! `0xc0000000` up, rather than where the bootloader loads it.
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
use hereticus::raw::{BaseFit, check_base, suggest_base};
use rstest::rstest;

mod common;
use common::render;

/// One board: the name its files carry, how its code reads, and where it
/// loads.
#[derive(Clone, Copy, Debug)]
struct Board {
    name: &'static str,
    isa: Isa,
    /// Where the stub runs: the address the bootloader loads it at.
    stub_base: u64,
    /// Where the kernel is linked. An ARM kernel is linked at its virtual
    /// address, `0xc0000000` up, not where the bootloader puts it; measured
    /// with the base check, the virtual base finds five times the pointers.
    kernel_base: u64,
}

impl Board {
    fn base(self, part: Part) -> u64 {
        match part {
            Part::Stub => self.stub_base,
            Part::Kernel => self.kernel_base,
        }
    }
}

const EX6100V2: Board = Board {
    name: "arm-ex6100v2",
    isa: Isa::Arm32,
    stub_base: 0x8020_8000,
    kernel_base: 0xc020_8000,
};
const EAP245V3: Board = Board {
    name: "mipsbe-eap245v3",
    isa: Isa::Mips32Be,
    stub_base: 0x8006_0000,
    kernel_base: 0x8006_0000,
};
const R6220: Board = Board {
    name: "mipsel-r6220",
    isa: Isa::Mips32,
    stub_base: 0x8000_1000,
    kernel_base: 0x8000_1000,
};
const A385DBAP: Board =
    Board { name: "arm-a385dbap", isa: Isa::Arm32, stub_base: 0x8000, kernel_base: 0xc000_8000 };
/// Kernel only: the bootloader decompresses the kernel itself. Lantiq loads
/// at 0x80002000: there, 58113 of 95023 `jal` targets land on a prologue,
/// against about 2000 at the neighbouring pages.
const VR200: Board =
    Board { name: "mipsbe-vr200", isa: Isa::Mips32Be, stub_base: 0, kernel_base: 0x8000_2000 };
/// Kernel only, as above.
const MT300NV2: Board =
    Board { name: "mipsel-mt300nv2", isa: Isa::Mips32, stub_base: 0, kernel_base: 0x8000_0000 };

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
    compare_at(board, part, board.base(part))
}

fn compare_at(board: Board, part: Part, base: u64) -> Comparison {
    compare_releases(board, part, base, BEFORE, AFTER)
}

fn compare_releases(board: Board, part: Part, base: u64, older: &str, newer: &str) -> Comparison {
    let before_bytes = read(board, part, older);
    let after_bytes = read(board, part, newer);
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
#[case::arm_a385dbap(A385DBAP)]
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
#[case::arm_ex6100v2(EX6100V2, [68, 68], &[(Changed::No, 58), (Changed::Data, 1), (Changed::InDetail, 1), (Changed::Yes, 7), (Changed::Unreadable, 1)], 0, 0)]
#[case::mipsbe_eap245v3(EAP245V3, [7, 7], &[(Changed::No, 5), (Changed::InDetail, 2)], 0, 0)]
#[case::mipsel_r6220(R6220, [7, 7], &[(Changed::No, 5), (Changed::InDetail, 2)], 0, 0)]
#[case::arm_a385dbap(A385DBAP, [142, 142], &[(Changed::No, 132), (Changed::Data, 1), (Changed::InDetail, 4), (Changed::Yes, 5)], 0, 0)]
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
#[case::arm_a385dbap(A385DBAP)]
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
        .map(|(offset, _)| board.stub_base + offset as u64);

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
#[case::arm_a385dbap(A385DBAP)]
fn no_stub_pair_with_different_bytes_reads_as_unchanged(#[case] board: Board) {
    assert_eq!(unreported_byte_changes(&compare(board, Part::Stub)), 0);
}

/// Each release compared with itself reports nothing.
#[rstest]
#[case::arm_ex6100v2(EX6100V2)]
#[case::mipsbe_eap245v3(EAP245V3)]
#[case::mipsel_r6220(R6220)]
#[case::arm_a385dbap(A385DBAP)]
fn a_stub_compared_with_itself_reports_nothing(
    #[case] board: Board,
    #[values(BEFORE, AFTER)] release: &str,
) {
    let binary = Binary::parse_raw(&read(board, Part::Stub, release), board.stub_base, board.isa)
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
#[case::arm_a385dbap(A385DBAP)]
fn the_base_check_has_no_evidence_in_a_stub(
    #[case] board: Board,
    #[values(BEFORE, AFTER)] release: &str,
) {
    let data = read(board, Part::Stub, release);
    assert_eq!(check_base(&data, board.stub_base, board.isa.arch()), BaseFit::NoEvidence);
}

/// The base shifts every address in the report, and changes nothing else.
#[rstest]
#[case::arm_ex6100v2(EX6100V2)]
#[case::mipsbe_eap245v3(EAP245V3)]
#[case::mipsel_r6220(R6220)]
#[case::arm_a385dbap(A385DBAP)]
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
    assert_eq!(changed(&at_zero, 0), changed(&at_base, board.stub_base));
}

/// A big-endian stub, word swapped and read as little endian, reports the
/// same thing. Real firmware exercises far more encodings than the fixtures.
#[test]
fn a_mips_stub_reads_alike_in_either_byte_order() {
    let board = EAP245V3;
    let big = compare(board, Part::Stub);

    let little_before = swap_words(&big.before_bytes);
    let little_after = swap_words(&big.after_bytes);
    let before = Binary::parse_raw(&little_before, board.stub_base, Isa::Mips32).unwrap();
    let after = Binary::parse_raw(&little_after, board.stub_base, Isa::Mips32).unwrap();

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
    insta::assert_snapshot!(format!("kernel_{}", board.name), kernel_digest(&comparison));

    assert_eq!(unreported_byte_changes(&comparison), unreported, "{}", board.name);
    assert_eq!(
        [
            check_base(&comparison.before_bytes, board.kernel_base, board.isa.arch()),
            check_base(&comparison.after_bytes, board.kernel_base, board.isa.arch()),
        ],
        base_fit,
        "{}",
        board.name
    );
}

/// A kernel comparison as a summary, the strongest real changes, and a
/// fingerprint of the whole report.
fn kernel_digest(comparison: &Comparison) -> String {
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

    format!(
        "{}fingerprint {:#018x}\n\nstrongest changes:\n{}\n",
        summary(comparison),
        fingerprint(&report),
        top.join("\n")
    )
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
        5856,
        [
            BaseFit::Plausible { pointers: 65274, examined: 1_804_835 },
            BaseFit::Plausible { pointers: 65514, examined: 1_813_763 },
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
        13904,
        [
            BaseFit::Plausible { pointers: 47586, examined: 1_377_328 },
            BaseFit::Plausible { pointers: 47778, examined: 1_385_296 },
        ],
    );
}

/// The little-endian MIPS kernel.
#[test]
fn slow_the_little_endian_mips_kernel_report_is_locked() {
    check_kernel(
        R6220,
        15990,
        [
            BaseFit::Plausible { pointers: 50248, examined: 1_606_891 },
            BaseFit::Plausible { pointers: 50444, examined: 1_615_796 },
        ],
    );
}

/// The Armada 385 kernel, a Cortex-A9.
#[test]
fn slow_the_armada_kernel_report_is_locked() {
    check_kernel(
        A385DBAP,
        6780,
        [
            BaseFit::Plausible { pointers: 76052, examined: 2_107_105 },
            BaseFit::Plausible { pointers: 76384, examined: 2_116_947 },
        ],
    );
}

/// The VR200 kernel, a big-endian Lantiq xRX200.
#[test]
fn slow_the_lantiq_kernel_report_is_locked() {
    check_kernel(
        VR200,
        15894,
        [
            BaseFit::Plausible { pointers: 52265, examined: 1_630_772 },
            BaseFit::Plausible { pointers: 52465, examined: 1_638_279 },
        ],
    );
}

/// The GL-MT300N v2 kernel, a little-endian MT7628.
#[test]
fn slow_the_mt7628_kernel_report_is_locked() {
    check_kernel(
        MT300NV2,
        13584,
        [
            BaseFit::Plausible { pointers: 45805, examined: 1_327_211 },
            BaseFit::Plausible { pointers: 45992, examined: 1_334_689 },
        ],
    );
}

/// Each MIPS kernel names its own base through its calls, in every release.
///
/// A kernel holds so many stored pointers that a base a page off still finds
/// thousands inside the image. The calls tell the two apart.
#[rstest]
#[case::mipsbe_eap245v3(EAP245V3, &["21.02.7", BEFORE, AFTER, "23.05.5"])]
#[case::mipsel_r6220(R6220, &["21.02.7", BEFORE, AFTER, "23.05.5"])]
#[case::mipsbe_vr200(VR200, &[BEFORE, AFTER])]
#[case::mipsel_mt300nv2(MT300NV2, &[BEFORE, AFTER])]
fn slow_the_calls_of_a_mips_kernel_give_its_base(#[case] board: Board, #[case] releases: &[&str]) {
    for &release in releases {
        let data = read(board, Part::Kernel, release);
        let arch = board.isa.arch();
        assert_eq!(suggest_base(&data, arch), Some(board.kernel_base), "{} {release}", board.name);

        for wrong in
            [board.kernel_base - 0x1000, board.kernel_base + 0x1000, board.kernel_base + 0x100]
        {
            let fit = check_base(&data, wrong, arch);
            assert!(
                matches!(fit, BaseFit::CallsMissFunctions { better_base, .. } if better_base == board.kernel_base),
                "{} {release} at {wrong:#x}: got {fit:?}",
                board.name
            );
        }
    }
}

/// An ARM kernel calls by distance, so it names no base.
#[test]
fn slow_an_arm_kernel_suggests_no_base() {
    assert_eq!(suggest_base(&read(EX6100V2, Part::Kernel, BEFORE), Isa::Arm32.arch()), None);
}

/// The OpenWrt fixtures are all present, so no test above reads a stale or a
/// missing file without saying so.
#[test]
fn every_firmware_file_is_present() {
    for board in [EX6100V2, EAP245V3, R6220, A385DBAP] {
        for part in [Part::Stub, Part::Kernel] {
            for release in [BEFORE, AFTER] {
                assert!(!read(board, part, release).is_empty());
            }
        }
    }
    for board in [VR200, MT300NV2] {
        for release in [BEFORE, AFTER] {
            assert!(!read(board, Part::Kernel, release).is_empty());
        }
    }
}

/// Two releases a major version apart: 21.02 to 22.03 moves the kernel from
/// 5.4 to 5.10, and 22.03 to 23.05 from 5.10 to 5.15.
///
/// Thousands of functions change, so no answer can be stated. These tests
/// record the reports and check what must hold however much changed.
const GAPS: [(&str, &str); 2] = [("21.02.7", "22.03.2"), ("22.03.5", "23.05.5")];

/// Check what must hold of any comparison: each function of each side is
/// matched, gone or new exactly once.
fn check_accounting(comparison: &Comparison) {
    let diff = &comparison.diff;
    let mut before: Vec<usize> =
        diff.matched.iter().map(|pair| pair.before).chain(diff.removed.iter().copied()).collect();
    let mut after: Vec<usize> =
        diff.matched.iter().map(|pair| pair.after).chain(diff.added.iter().copied()).collect();
    before.sort_unstable();
    after.sort_unstable();

    let every = |count: usize| (0..count).collect::<Vec<_>>();
    assert_eq!(before, every(comparison.before.functions.len()), "each older function once");
    assert_eq!(after, every(comparison.after.functions.len()), "each newer function once");
}

/// A stub across a major version: the whole report, and the accounting.
#[rstest]
#[case::arm_ex6100v2(EX6100V2)]
#[case::mipsbe_eap245v3(EAP245V3)]
#[case::mipsel_r6220(R6220)]
fn a_stub_across_a_major_version(#[case] board: Board, #[values(0, 1)] gap: usize) {
    let (older, newer) = GAPS[gap];
    let comparison = compare_releases(board, Part::Stub, board.stub_base, older, newer);
    check_accounting(&comparison);

    let report = render(&comparison.diff, &comparison.before, &comparison.after);
    let again = compare_releases(board, Part::Stub, board.stub_base, older, newer);
    assert_eq!(render(&again.diff, &again.before, &again.after), report, "the report is stable");

    insta::assert_snapshot!(format!("stub_{}_{older}_{newer}", board.name), report);
}

/// A kernel across a major version: the digest, and the accounting.
#[rstest]
#[case::arm_ex6100v2(EX6100V2)]
#[case::mipsbe_eap245v3(EAP245V3)]
#[case::mipsel_r6220(R6220)]
fn slow_a_kernel_across_a_major_version(#[case] board: Board, #[values(0, 1)] gap: usize) {
    let (older, newer) = GAPS[gap];
    let comparison = compare_releases(board, Part::Kernel, board.kernel_base, older, newer);
    check_accounting(&comparison);
    insta::assert_snapshot!(
        format!("kernel_{}_{older}_{newer}", board.name),
        kernel_digest(&comparison)
    );
}

/// The accounting holds for the point releases too.
#[rstest]
#[case::arm_ex6100v2(EX6100V2)]
#[case::mipsbe_eap245v3(EAP245V3)]
#[case::mipsel_r6220(R6220)]
#[case::arm_a385dbap(A385DBAP)]
fn every_stub_function_is_accounted_for(#[case] board: Board) {
    check_accounting(&compare(board, Part::Stub));
}
