//! Judge whether a load address fits a raw blob.
//!
//! A firmware image carries no header, so the caller supplies the address it
//! loads at. Getting that wrong does not fail loudly: the code still decodes,
//! and every branch still resolves, because a relative branch moves with the
//! base it is read at. The comparison quietly reports against the wrong
//! addresses instead.
//!
//! # What cannot be used
//!
//! Two obvious checks were tried and measured, and both are useless:
//!
//! * **Branch targets landing inside the blob.** Scores 1.00 at every base,
//!   including nonsense ones, for the reason above.
//! * **Pointer-like words, on compiled position-independent code.** A `clang`
//!   ARM build keeps its constant pools relative even under `-fno-pic`, so the
//!   correct base scored 0.00 while a wrong one scored 0.18.
//!
//! # What works
//!
//! Absolute addresses stored *as data* do not move with the assumed base. A
//! vector table, a table of function pointers, a pointer to a string: each is
//! a word holding a real address. Counting the words that fall inside the blob
//! at a given base separates a right answer from a wrong one. On a vector
//! table linked at `0x08000000`, three of seven words point into the image at
//! that base and none do at `0` or `0x20000000`.
//!
//! The catch is that small position-independent code holds no such words at
//! all. That is [`BaseFit::NoEvidence`], and it must not be read as a wrong
//! base.
//!
//! # What it catches
//!
//! A base wrong by a little, which is the mistake people actually make: the
//! address of the wrong section, or a header not accounted for. Measured on
//! the vector-table fixture, whose addresses span `0x08000010..0x08000100`:
//!
//! | Base | Verdict |
//! |---|---|
//! | `0x08000000` (right) | `Plausible`, 4 pointers |
//! | `0x08000100`, `0x08000400`, `0x08001000` | `Unlikely` |
//! | `0x08002000` and beyond, `0` | `NoEvidence` |
//!
//! A base wrong by megabytes reads as `NoEvidence`, not as wrong. At that
//! distance an image whose addresses point elsewhere is indistinguishable
//! from one loaded somewhere else entirely, and claiming otherwise would be a
//! guess.
//!
//! # Calls that name an absolute target
//!
//! On a large image, stored pointers cannot tell a base from its neighbours:
//! a kernel holds so many that a base a page off still finds thousands inside
//! the image. MIPS gives a second test. `jal` holds its target, so at the
//! right base most targets land on a function prologue, and at any other base
//! few do. Measured on the TP-Link VR200 kernel, 58113 of 95023 calls land on
//! `addiu sp, sp, -N` at `0x80002000`, about 2000 at a neighbouring page, and
//! at most 8379 at any other base.
//!
//! The same counts find the base when none is given. The most common targets
//! each vote for every base that puts them on a prologue, and the few bases
//! with the most votes are then counted in full. On all twelve OpenWrt MIPS
//! kernels in the tests, the right base wins with over five times the calls
//! of the next.

use std::collections::HashMap;

use crate::arch::Recovery;
use hereticus_memory::SMALLEST_ADDRESS;

mod find;
pub use find::{BaseCandidate, RANKED, clear_winner, measure_base, rank_bases};

/// How far outside the image still counts as "nearly pointing at it", as a
/// multiple of the image length.
///
/// A wrong base is usually wrong by a modest amount, so a few image lengths is
/// the window a stored address for a neighbouring image falls in.
const REACH_IN_IMAGES: u64 = 4;

/// How many words must look like pointers before a verdict is worth giving.
///
/// One word pointing into the blob is a coincidence. This keeps a single
/// stray value from being read as evidence either way.
const ENOUGH_POINTERS: usize = 2;

/// How many calls must land on a function start before a base is judged by
/// them.
///
/// A small image holds a handful of calls, and at that count a wrong base can
/// land a few on a prologue by chance.
const ENOUGH_CALLS: usize = 16;

/// How many of the most common call targets vote for a base.
///
/// A popular target, such as `printk`, is almost certainly a function with a
/// frame, so its vote is sound. The rest add time and little else.
const VOTERS: usize = 64;

/// How many of the bases with the most votes are then counted in full.
const CANDIDATES: usize = 8;

/// How many times more calls another base must land than the given one, to
/// call the given one wrong.
///
/// A function without a frame opens with no prologue, so even the right base
/// lands only about 60% of calls. A wrong base lands 9% or fewer, which a
/// factor of two separates with a wide margin.
const CLEARLY_BETTER: usize = 2;

/// How well a load address fits a blob.
///
/// This judges one base at a time and says only what the evidence supports.
/// `Plausible` means "nothing here contradicts you", not "this is right": a
/// wrong base can collect a couple of coincidental hits, which was measured on
/// a real image. Use it to catch a base that is clearly wrong, not to confirm
/// one that is right.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseFit {
    /// Words in the blob hold addresses inside it at this base.
    Plausible {
        /// Words pointing into the blob.
        pointers: usize,
        /// Words that could be addresses at all.
        examined: usize,
    },
    /// The blob holds nothing that points anywhere, so the base cannot be
    /// judged.
    ///
    /// Usual for small position-independent code. Not a sign of a wrong base.
    NoEvidence,
    /// The blob holds pointer-like words, but none point into it here.
    Unlikely {
        /// Words that look like addresses but fall outside the blob.
        pointers_elsewhere: usize,
    },
    /// Calls that name an absolute target land on a function start far more
    /// often at another base.
    CallsMissFunctions {
        /// Calls that land on a function start at this base.
        landed: usize,
        /// Calls that name an absolute target.
        calls: usize,
        /// The base that lands the most calls on a function start.
        better_base: u64,
        /// Calls that land on a function start at `better_base`.
        landed_there: usize,
    },
}

impl BaseFit {
    /// Report whether the caller should be warned.
    pub fn is_suspect(self) -> bool {
        matches!(self, Self::Unlikely { .. } | Self::CallsMissFunctions { .. })
    }
}

impl core::fmt::Display for BaseFit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Plausible { pointers, examined } => {
                write!(f, "{pointers} of {examined} words point into the image")
            }
            Self::NoEvidence => {
                write!(f, "the image holds no stored addresses, so the base cannot be checked")
            }
            Self::Unlikely { pointers_elsewhere } => {
                write!(
                    f,
                    "{pointers_elsewhere} words look like addresses, but none point into the \
                     image at this base"
                )
            }
            Self::CallsMissFunctions { landed, calls, better_base, landed_there } => {
                write!(
                    f,
                    "{landed} of {calls} calls land on a function start at this base, but \
                     {landed_there} do at {better_base:#x}"
                )
            }
        }
    }
}

/// Judge a load address against the words stored in a blob, and against its
/// calls where the architecture has calls that name an absolute target.
///
/// The architecture says how wide a stored address is and how to read one, so
/// an image of 64-bit pointers is examined as such rather than as pairs of
/// halves.
///
/// See RESEARCH.md, A17.
pub fn check_base(data: &[u8], base: u64, arch: &dyn Recovery) -> BaseFit {
    let by_pointers = check_pointers(data, base, arch);
    if by_pointers.is_suspect() {
        return by_pointers;
    }

    let Some(calls) = Calls::read(data, arch) else { return by_pointers };
    let landed = calls.landed_at(base);
    match calls.best() {
        Some((offset, landed_there)) if landed_there > landed.saturating_mul(CLEARLY_BETTER) => {
            BaseFit::CallsMissFunctions {
                landed,
                calls: calls.total,
                better_base: calls.nearest(base, offset),
                landed_there,
            }
        }
        _ => by_pointers,
    }
}

/// Find the load address of a blob from its calls, or `None` when the blob
/// does not say.
///
/// Calls give the base only within the region they reach, so the stored
/// pointers to a function start choose the region. It is `None` when the
/// architecture has no calls that name an absolute target, or when either
/// choice is not clear.
pub fn suggest_base(data: &[u8], arch: &dyn Recovery) -> Option<u64> {
    let calls = Calls::read(data, arch)?;

    let ranked = calls.ranked();
    let &(offset, landed) = ranked.first()?;
    let runner_up = ranked.get(1).map_or(0, |&(_, landed)| landed);
    if landed < ENOUGH_CALLS || landed <= runner_up.saturating_mul(CLEARLY_BETTER) {
        return None;
    }

    // Past a few hundred regions, trying each one costs more than a guess is
    // worth, and no architecture here has that many.
    const MOST_REGIONS: u64 = 256;
    let address_bits = u32::try_from(arch.pointer_width() * 8).ok()?;
    let regions = 1u64.checked_shl(address_bits).map_or(u64::MAX, |space| space / calls.region);
    if regions > MOST_REGIONS {
        return None;
    }

    // Any stored pointer is no use here: MIPS `beq` is `0x10xxxxxx`, so the
    // code itself reads as thousands of pointers into the region at
    // `0x10000000`. A pointer to a function start is rare by chance. Measured
    // on the VR200 kernel, 9829 point at one at `0x80002000`, and 417 at the
    // next best region.
    let mut scored: Vec<(u64, usize)> = (0..regions)
        .map(|region| region * calls.region + offset)
        .map(|base| (base, calls.pointers_to_starts(data, base, arch)))
        .collect();
    scored.sort_unstable_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));

    match scored.as_slice() {
        [(base, most), rest @ ..]
            if *most >= ENOUGH_POINTERS
                && rest
                    .first()
                    .is_none_or(|next| *most > next.1.saturating_mul(CLEARLY_BETTER)) =>
        {
            Some(*base)
        }
        _ => None,
    }
}

/// The calls in a blob that name an absolute target, and the function starts
/// they could land on.
struct Calls {
    /// Each target, as an offset into its region, with how many calls name
    /// it. The most named come first.
    targets: Vec<(u64, usize)>,
    /// How many calls there are in all.
    total: usize,
    /// The region every target is an offset into.
    region: u64,
    /// Whether each instruction of the blob opens a function.
    starts: Vec<bool>,
    /// The width of one instruction, which is also the step of `starts`.
    width: usize,
}

impl Calls {
    /// Read the calls of a blob, or `None` when it has too few to judge by.
    fn read(data: &[u8], arch: &dyn Recovery) -> Option<Self> {
        let width = arch.instruction_width();
        let mut calls = data.chunks_exact(width).filter_map(|word| arch.absolute_call(word));
        let crate::arch::AbsoluteCall { region, .. } = calls.clone().next()?;

        let mut counts: HashMap<u64, usize> = HashMap::new();
        for call in calls.by_ref().filter(|call| call.region == region) {
            *counts.entry(call.offset).or_default() += 1;
        }
        let total = counts.values().sum();
        if total < ENOUGH_CALLS {
            return None;
        }

        let mut targets: Vec<(u64, usize)> = counts.into_iter().collect();
        targets.sort_unstable_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));

        // The address does not change whether an instruction opens a frame.
        let starts = (0..data.len() / width)
            .map(|index| {
                let at = index * width;
                arch.may_be_prologue(&data[at..])
                    && arch.decode(data, at, 0).is_ok_and(|insn| arch.is_prologue(&insn))
            })
            .collect();

        Some(Self { targets, total, region, starts, width })
    }

    /// Count the calls that land on a function start when the blob loads at
    /// `base`.
    ///
    /// Only the offset of `base` into its region matters. A target that
    /// wraps past the end of the region counts as outside the blob, which is
    /// right for any blob that does not straddle two regions.
    fn landed_at(&self, base: u64) -> usize {
        let base_offset = base & (self.region - 1);
        self.targets
            .iter()
            .filter(|&&(target, _)| {
                self.is_start(target.wrapping_sub(base_offset) & (self.region - 1))
            })
            .map(|&(_, count)| count)
            .sum()
    }

    /// Count the stored words that point at a function start when the blob
    /// loads at `base`.
    fn pointers_to_starts(&self, data: &[u8], base: u64, arch: &dyn Recovery) -> usize {
        data.chunks_exact(arch.pointer_width())
            .map(|word| arch.read_pointer(word))
            .filter(|&value| value.checked_sub(base).is_some_and(|offset| self.is_start(offset)))
            .count()
    }

    /// Report whether an offset into the blob opens a function.
    fn is_start(&self, offset: u64) -> bool {
        offset.is_multiple_of(self.width as u64)
            && usize::try_from(offset / self.width as u64)
                .ok()
                .and_then(|index| self.starts.get(index))
                .is_some_and(|&start| start)
    }

    /// The candidate bases, as offsets into a region, with the calls each
    /// lands on a function start. The most landed come first.
    fn ranked(&self) -> Vec<(u64, usize)> {
        let start_offsets: Vec<u64> = (0u64..)
            .step_by(self.width)
            .zip(&self.starts)
            .filter_map(|(offset, &start)| start.then_some(offset))
            .collect();

        let mut votes: HashMap<u64, usize> = HashMap::new();
        for &(target, _) in self.targets.iter().take(VOTERS) {
            for &start in &start_offsets {
                *votes.entry(target.wrapping_sub(start) & (self.region - 1)).or_default() += 1;
            }
        }

        let mut candidates: Vec<(u64, usize)> = votes.into_iter().collect();
        candidates.sort_unstable_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));

        let mut ranked: Vec<(u64, usize)> = candidates
            .into_iter()
            .take(CANDIDATES)
            .map(|(offset, _)| (offset, self.landed_at(offset)))
            .collect();
        ranked.sort_unstable_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
        ranked
    }

    /// The candidate base that lands the most calls on a function start, as
    /// an offset into a region, with that count.
    fn best(&self) -> Option<(u64, usize)> {
        self.ranked().into_iter().next().filter(|&(_, landed)| landed >= ENOUGH_CALLS)
    }

    /// The base at `offset` into a region that lies nearest to `base`.
    ///
    /// A base just below a region edge is nearer to an offset in the next
    /// region than in its own, and the nearest is what the caller most
    /// likely meant.
    fn nearest(&self, base: u64, offset: u64) -> u64 {
        let own = (base & !(self.region - 1)) | offset;
        [own.checked_sub(self.region), Some(own), own.checked_add(self.region)]
            .into_iter()
            .flatten()
            .min_by_key(|&candidate| candidate.abs_diff(base))
            .unwrap_or(own)
    }
}

/// Judge a load address against the words stored in a blob.
fn check_pointers(data: &[u8], base: u64, arch: &dyn Recovery) -> BaseFit {
    let end = base.saturating_add(data.len() as u64);

    let mut inside = 0;
    let mut near = 0;
    let mut examined = 0;

    // A word smaller than the image is an offset or a size within it as
    // readily as an address. Measured on an Armada 385 decompressor stub
    // loaded at 0x8000, 27 such distances landed just below the base and
    // accused the right one.
    let smallest = SMALLEST_ADDRESS.max(data.len() as u64);

    for word in data.chunks_exact(arch.pointer_width()) {
        let value = arch.read_pointer(word);

        // A word near zero is padding, a small count or a null pointer. At a
        // base of zero such words all land "inside" the image, which made a
        // 69 KiB firmware image score 17330 of 17439 words as pointers at
        // base 0 while the right base scored 4. Skipping them is what keeps
        // a base of zero from beating every other answer.
        if value < smallest || is_text(word) {
            continue;
        }
        examined += 1;

        if value >= base && value < end {
            inside += 1;
        } else if lands_near(value, base, data.len() as u64) && !is_round(value) {
            near += 1;
        }
    }

    if inside >= ENOUGH_POINTERS {
        return BaseFit::Plausible { pointers: inside, examined };
    }

    // Nothing points into the image. That counts against the base only when
    // the image holds words that look like addresses for a *neighbouring*
    // image, which is what a wrong base by a small amount produces.
    if near >= ENOUGH_POINTERS {
        BaseFit::Unlikely { pointers_elsewhere: near }
    } else {
        BaseFit::NoEvidence
    }
}

/// Report whether a word is text: printable ASCII and zero bytes only, with
/// at least two printable.
///
/// The tail of a string such as "copy" or "error" reads as a small number,
/// `0x7970` or `0x726f`, which a low base takes for an address just outside
/// it. A real pointer almost always holds a byte outside that range.
pub fn is_text(word: &[u8]) -> bool {
    let printable = word.iter().filter(|byte| (0x20..0x7f).contains(*byte)).count();
    printable >= 2 && word.iter().all(|&byte| byte == 0 || (0x20..0x7f).contains(&byte))
}

/// Report whether a word is a multiple of a page.
///
/// Sizes and masks are round, `0x10000` or `0xf000`, and a pointer to code or
/// to a table almost never is. A round word just outside the image is thus no
/// evidence that the base is wrong.
fn is_round(value: u64) -> bool {
    value.is_multiple_of(0x1000)
}

/// Report whether a word looks like an address just outside the image.
///
/// "Looks like an address" cannot mean "is a large number": an instruction
/// word is usually large too, so that would count the code itself and report a
/// wrong base on every run. It was measured doing exactly that.
///
/// A wrong base is usually wrong by a modest amount — the caller took the
/// address of the wrong section, or forgot a header. So the telling sign is a
/// word that points **just past** where the image would sit, within a few
/// image lengths of it. An instruction word does not do that, because the
/// image is nowhere near the value its own bits spell.
fn lands_near(value: u64, base: u64, length: u64) -> bool {
    // At least a page, so a small image is not held to an impossibly tight
    // window.
    let reach = (length.saturating_mul(REACH_IN_IMAGES)).max(0x1000);

    let low = base.saturating_sub(reach);
    let high = base.saturating_add(length).saturating_add(reach);

    value >= low && value < high
}

#[cfg(test)]
mod tests {
    use super::*;
    use hereticus_il::arch::arm32::Arm32;
    use hereticus_il::arch::mips::Mips32;

    /// Build a blob from words, little endian.
    ///
    /// The words come first, then filler, because a stored address must fall
    /// inside the image for the check to count it. A vector table at the head
    /// of a small blob would point past its own end.
    fn image(words: &[u32], size: usize) -> Vec<u8> {
        let mut data: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        // Filler that is not a plausible address: the value stands for "not a
        // pointer", which is all these tests ask of it.
        data.resize(size.max(data.len()), 0xe1);
        data
    }

    /// A vector table names addresses inside the image it belongs to.
    #[test]
    fn a_right_base_is_plausible() {
        // Three entries pointing into a 4 KiB image loaded at 0x08000000.
        let data = image(&[0x0800_000c, 0x0800_0014, 0x0800_0100, 0xe3a0_0001], 0x1000);
        assert!(
            matches!(
                check_base(&data, 0x0800_0000, &Arm32),
                BaseFit::Plausible { pointers: 3, .. }
            ),
            "got {:?}",
            check_base(&data, 0x0800_0000, &Arm32)
        );
    }

    /// A base near the right one, but wrong, is reported as suspect.
    ///
    /// This is the mistake worth catching: the caller used the address of the
    /// wrong section, or forgot a header, and is off by a little.
    #[test]
    fn a_base_that_is_nearly_right_is_suspect() {
        let data = image(&[0x0800_200c, 0x0800_2014, 0x0800_2100, 0xe3a0_0001], 0x1000);

        // The stored addresses sit just past an image based here.
        let fit = check_base(&data, 0x0800_0000, &Arm32);
        assert!(fit.is_suspect(), "got {fit:?}");
    }

    /// A base far from the stored addresses cannot be judged.
    ///
    /// Nothing in the image points anywhere near it, so there is no evidence
    /// either way. Reporting that as wrong would be a guess dressed up as a
    /// finding.
    #[test]
    fn a_base_far_from_everything_gives_no_evidence() {
        let data = image(&[0x0800_000c, 0x0800_0014, 0x0800_0100, 0xe3a0_0001], 0x1000);
        assert_eq!(check_base(&data, 0x2000_0000, &Arm32), BaseFit::NoEvidence);
    }

    /// A plausible verdict is not a confirmation.
    ///
    /// Measured on a 69 KiB firmware image: the right base scored four
    /// pointers and two wrong bases scored two each. The check rules a base
    /// out, it does not rule one in.
    #[test]
    fn plausible_does_not_mean_certain() {
        // Two words that point into an image based at either of two places.
        let data = image(&[0x0010_1004, 0x0010_1008, 0xe3a0_0001], 0x2000);

        assert!(matches!(check_base(&data, 0x0010_1000, &Arm32), BaseFit::Plausible { .. }));
        assert!(
            matches!(check_base(&data, 0x0010_0000, &Arm32), BaseFit::Plausible { .. }),
            "a coincidental fit still reads as plausible, which is why the \
             verdict is worded as it is"
        );
    }

    /// Position-independent code holds no stored addresses, which is not the
    /// same as holding wrong ones.
    #[test]
    fn code_without_stored_addresses_gives_no_evidence() {
        // Ordinary instructions and small constants. `0xe1...` filler decodes
        // as instructions, not as addresses, so nothing here looks stored.
        let data = image(&[0xe3a0_0001, 0xe12f_ff1e, 0x0000_0008, 0x0000_0010], 0x40);
        assert_eq!(
            check_base(&data, 0x0800_0000, &Arm32),
            BaseFit::NoEvidence,
            "instructions are not addresses"
        );
        assert!(
            !check_base(&data, 0x0800_0000, &Arm32).is_suspect(),
            "silence is not an accusation"
        );
    }

    /// One matching word is a coincidence, not evidence.
    #[test]
    fn a_single_pointer_is_not_enough() {
        let data = image(&[0x0800_0004, 0x0000_0001, 0x0000_0002], 0x1000);
        assert!(!matches!(check_base(&data, 0x0800_0000, &Arm32), BaseFit::Plausible { .. }));
    }

    #[test]
    fn an_empty_blob_gives_no_evidence() {
        assert_eq!(check_base(&[], 0, &Arm32), BaseFit::NoEvidence);
    }

    /// Trailing bytes that do not fill a word are ignored rather than read
    /// past.
    #[test]
    fn a_partial_word_is_ignored() {
        let mut data = image(&[0x0800_000c, 0x0800_0014], 0x1000);
        data.extend_from_slice(&[0xff, 0xff]);

        let fit = check_base(&data, 0x0800_0000, &Arm32);
        assert!(matches!(fit, BaseFit::Plausible { pointers: 2, .. }), "got {fit:?}");
    }

    /// Distances within a small image, loaded low, do not accuse its base.
    #[test]
    fn offsets_within_a_low_image_are_not_near_misses() {
        // A 16 KiB stub at 0x8000 holding offsets into itself and two sizes.
        let data = image(&[0x10ec, 0x11ac, 0x1a14, 0x3164, 0xf000, 0x1_0000, 0x2_0000], 0x4000);
        assert_eq!(check_base(&data, 0x8000, &Arm32), BaseFit::NoEvidence);
    }

    /// The tail of a string is text, not a near miss.
    #[test]
    fn the_tail_of_a_string_is_not_a_near_miss() {
        // "py\0\0", "or\0\0" and "er\0\0" as little-endian words.
        let data = image(&[0x7970, 0x726f, 0x7265], 0x4000);
        assert_eq!(check_base(&data, 0x8000, &Arm32), BaseFit::NoEvidence);
        assert!(is_text(&0x7970u32.to_le_bytes()));
        assert!(!is_text(&0x0800_0010u32.to_le_bytes()), "a pointer is not text");
        assert!(!is_text(&0x0000_0070u32.to_le_bytes()), "one printable byte is a number");
    }

    /// A round size just outside the image is no evidence either way.
    #[test]
    fn a_round_number_is_not_a_near_miss() {
        let data = image(&[0x0800_2000, 0x0800_3000, 0x0800_4000], 0x1000);
        assert_eq!(check_base(&data, 0x0800_0000, &Arm32), BaseFit::NoEvidence);
    }

    /// A base so high that the image would wrap must not panic.
    #[test]
    fn a_base_near_the_top_of_the_range_does_not_overflow() {
        let data = image(&[0xffff_fff0, 0xffff_fff4], 0x20);
        let _ = check_base(&data, u64::MAX - 4, &Arm32);
    }

    /// Build a blob from words, big endian, as MIPS firmware stores them.
    fn image_be(words: &[u32], size: usize) -> Vec<u8> {
        let mut data: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
        data.resize(size.max(data.len()), 0xe1);
        data
    }

    /// A MIPS vector table in KSEG0, in each byte order, fits the base it was
    /// linked at.
    #[test]
    fn a_right_mips_base_is_plausible_in_either_order() {
        let words = [0x8000_0010, 0x8000_0018, 0x8000_0100, 0x03e0_0008];
        // The filler words are large too, so all 1024 words are examined.
        let expected = BaseFit::Plausible { pointers: 3, examined: 1024 };

        assert_eq!(check_base(&image(&words, 0x1000), 0x8000_0000, &Mips32::LITTLE), expected);
        assert_eq!(check_base(&image_be(&words, 0x1000), 0x8000_0000, &Mips32::BIG), expected);
    }

    /// A MIPS base wrong by a little is suspect, in either order.
    #[test]
    fn a_nearly_right_mips_base_is_suspect_in_either_order() {
        let words = [0x8000_2010, 0x8000_2018, 0x8000_2100];
        let expected = BaseFit::Unlikely { pointers_elsewhere: 3 };

        assert_eq!(check_base(&image(&words, 0x1000), 0x8000_0000, &Mips32::LITTLE), expected);
        assert_eq!(check_base(&image_be(&words, 0x1000), 0x8000_0000, &Mips32::BIG), expected);
    }

    /// Read in the wrong order, a table of KSEG0 addresses holds only small
    /// numbers, so it gives no evidence rather than a false verdict.
    #[test]
    fn a_mips_table_read_in_the_wrong_order_gives_no_evidence() {
        let words = [0x8000_0010, 0x8000_0018, 0x8000_0100];

        assert_eq!(
            check_base(&image_be(&words, 0x1000), 0x8000_0000, &Mips32::LITTLE),
            BaseFit::NoEvidence
        );
        assert_eq!(
            check_base(&image(&words, 0x1000), 0x8000_0000, &Mips32::BIG),
            BaseFit::NoEvidence
        );
    }

    /// KSEG0 and KSEG1 map the same memory at two addresses. A table linked
    /// for one does not fit the other, and the two are too far apart for a
    /// near miss.
    #[test]
    fn a_kseg0_table_gives_no_evidence_at_kseg1() {
        let data = image_be(&[0x8000_0010, 0x8000_0018, 0x8000_0100], 0x1000);
        assert_eq!(check_base(&data, 0xa000_0000, &Mips32::BIG), BaseFit::NoEvidence);
    }

    /// MIPS code with no stored addresses gives no evidence.
    #[test]
    fn mips_code_without_stored_addresses_gives_no_evidence() {
        // `jr $ra`, `addiu $v0, $zero, 1`, `lw $ra, 20($sp)`, `nop`.
        let words = [0x03e0_0008, 0x2402_0001, 0x8fbf_0014, 0x0000_0000];

        assert_eq!(
            check_base(&image_be(&words, 0x40), 0x8000_0000, &Mips32::BIG),
            BaseFit::NoEvidence
        );
        assert_eq!(
            check_base(&image(&words, 0x40), 0x8000_0000, &Mips32::LITTLE),
            BaseFit::NoEvidence
        );
    }

    /// Trailing bytes that do not fill a MIPS word are ignored, in either
    /// order.
    #[test]
    fn a_partial_mips_word_is_ignored() {
        let words = [0x8000_0010, 0x8000_0018];
        for (mut data, arch) in
            [(image(&words, 0x1000), Mips32::LITTLE), (image_be(&words, 0x1000), Mips32::BIG)]
        {
            data.extend_from_slice(&[0x80, 0x00, 0x00]);
            let fit = check_base(&data, 0x8000_0000, &arch);
            assert!(matches!(fit, BaseFit::Plausible { pointers: 2, .. }), "got {fit:?}");
        }
    }

    /// The top of the MIPS address space, where KSEG3 ends, must not wrap.
    #[test]
    fn a_mips_base_at_the_top_of_the_range_does_not_overflow() {
        let data = image_be(&[0xffff_fff0, 0xffff_fff4], 0x20);
        assert!(matches!(
            check_base(&data, 0xffff_ffe0, &Mips32::BIG),
            BaseFit::Plausible { pointers: 2, .. }
        ));
        let _ = check_base(&data, u64::MAX - 4, &Mips32::BIG);
    }

    /// Where the functions of a built image sit relative to each other.
    #[derive(Clone, Copy)]
    enum Spacing {
        /// Every function is the same size, so a base one function off lands
        /// the calls as well as the right one.
        Even,
        /// Each function is one word longer than the one before, so no shift
        /// of the base lines up more than one start with another.
        Uneven,
    }

    /// Whether a built image starts with a table of function pointers.
    #[derive(Clone, Copy)]
    enum PointerTable {
        With,
        Without,
    }

    /// Build MIPS code linked at `base`: `count` functions, each opening its
    /// frame and calling the next with `jal`.
    fn calling_code(base: u32, count: usize, spacing: Spacing, table: PointerTable) -> Vec<u32> {
        const PROLOGUE: u32 = 0x27bd_ffe8; // addiu sp, sp, -24
        const RETURN: u32 = 0x03e0_0008; // jr ra
        const UNWIND: u32 = 0x27bd_0018; // addiu sp, sp, 24
        const NOP: u32 = 0;
        const TABLE_WORDS: usize = 4;

        let jal = |target: u32| 0x0c00_0000 | (target >> 2 & 0x03ff_ffff);
        let padding = |index: usize| match spacing {
            Spacing::Even => 0,
            Spacing::Uneven => index,
        };

        let table_words = match table {
            PointerTable::With => TABLE_WORDS,
            PointerTable::Without => 0,
        };
        let starts: Vec<u32> = (0..count)
            .scan(table_words, |next, index| {
                let start = *next;
                *next += 5 + padding(index);
                Some(base + 4 * start as u32)
            })
            .collect();

        let mut words: Vec<u32> = starts.iter().copied().take(table_words).collect();
        for index in 0..count {
            words.push(PROLOGUE);
            words.extend(core::iter::repeat_n(NOP, padding(index)));
            words.extend([jal(starts[(index + 1) % count]), NOP, RETURN, UNWIND]);
        }
        words
    }

    /// The same code in both byte orders, each with its decoder.
    fn in_both_orders(words: &[u32]) -> [(Vec<u8>, Mips32); 2] {
        let size = words.len() * 4;
        [(image(words, size), Mips32::LITTLE), (image_be(words, size), Mips32::BIG)]
    }

    /// At the right base, every call lands on a function start, so the calls
    /// do not contradict the pointers.
    #[test]
    fn calls_agree_with_the_right_mips_base() {
        let words = calling_code(0x8000_2000, 32, Spacing::Uneven, PointerTable::With);
        for (data, arch) in in_both_orders(&words) {
            let fit = check_base(&data, 0x8000_2000, &arch);
            assert!(matches!(fit, BaseFit::Plausible { pointers: 4, .. }), "got {fit:?}");
        }
    }

    /// A base a page off holds no stored pointers to judge by, but its calls
    /// land nowhere, and they name the right base.
    #[test]
    fn calls_catch_a_mips_base_that_pointers_cannot() {
        let words = calling_code(0x8000_2000, 32, Spacing::Uneven, PointerTable::Without);
        for (data, arch) in in_both_orders(&words) {
            assert_eq!(
                check_base(&data, 0x8000_3000, &arch),
                BaseFit::CallsMissFunctions {
                    landed: 0,
                    calls: 32,
                    better_base: 0x8000_2000,
                    landed_there: 32,
                }
            );
        }
    }

    /// A base a few words off still finds the stored pointers inside the
    /// image, which is the case the calls are for.
    #[test]
    fn calls_overrule_pointers_that_still_land_inside() {
        let words = calling_code(0x8000_2000, 32, Spacing::Uneven, PointerTable::With);
        for (data, arch) in in_both_orders(&words) {
            let fit = check_base(&data, 0x8000_2010, &arch);
            assert!(
                matches!(fit, BaseFit::CallsMissFunctions { better_base: 0x8000_2000, .. }),
                "got {fit:?}"
            );
            assert!(fit.is_suspect());
        }
    }

    /// A few calls can land on a function start by chance, so they give no
    /// verdict.
    #[test]
    fn too_few_calls_give_no_evidence() {
        let words =
            calling_code(0x8000_2000, ENOUGH_CALLS - 1, Spacing::Uneven, PointerTable::Without);
        for (data, arch) in in_both_orders(&words) {
            assert_eq!(check_base(&data, 0x8000_3000, &arch), BaseFit::NoEvidence);
            assert_eq!(suggest_base(&data, &arch), None);
        }
    }

    /// Just below a region edge, the better base is the one just above it,
    /// not the one a whole region below.
    #[test]
    fn the_better_base_is_the_nearest_one() {
        let words = calling_code(0x8000_0000, 32, Spacing::Uneven, PointerTable::Without);
        for (data, arch) in in_both_orders(&words) {
            let fit = check_base(&data, 0x7fff_f000, &arch);
            assert!(
                matches!(fit, BaseFit::CallsMissFunctions { better_base: 0x8000_0000, .. }),
                "got {fit:?}"
            );
        }
    }

    /// The calls give the base within its region, and the pointers to
    /// function starts give the region.
    #[rstest::rstest]
    #[case::kseg0(0x8000_2000)]
    #[case::kseg1(0xa000_0000)]
    #[case::low(0x0040_1000)]
    fn calls_and_pointers_suggest_the_base(#[case] base: u32) {
        let words = calling_code(base, 32, Spacing::Uneven, PointerTable::With);
        for (data, arch) in in_both_orders(&words) {
            assert_eq!(suggest_base(&data, &arch), Some(u64::from(base)));
        }
    }

    /// Without pointers the region is unknown, so nothing is suggested.
    #[test]
    fn no_base_is_suggested_without_pointers() {
        let words = calling_code(0x8000_2000, 32, Spacing::Uneven, PointerTable::Without);
        for (data, arch) in in_both_orders(&words) {
            assert_eq!(suggest_base(&data, &arch), None);
        }
    }

    /// Evenly spaced functions land every call at more than one base, so
    /// neither is suggested, and neither accuses the other.
    #[test]
    fn a_tie_suggests_no_base() {
        let words = calling_code(0x8000_2000, 32, Spacing::Even, PointerTable::With);
        for (data, arch) in in_both_orders(&words) {
            assert_eq!(suggest_base(&data, &arch), None);
            assert!(!check_base(&data, 0x8000_2000, &arch).is_suspect());
        }
    }

    /// ARM calls are relative, so they say nothing about a base.
    #[test]
    fn arm_suggests_no_base() {
        let data = image(&[0x0800_0010, 0x0800_0018, 0x0800_0100, 0xeb00_0000], 0x100);
        assert_eq!(suggest_base(&data, &Arm32), None);
    }

    #[test]
    fn an_empty_blob_suggests_no_base() {
        assert_eq!(suggest_base(&[], &Mips32::BIG), None);
        assert_eq!(suggest_base(&[0x0c], &Mips32::BIG), None);
    }
}
