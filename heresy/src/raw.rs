//! Judge whether a load address fits a raw blob.
//!
//! A firmware image carries no header, so the caller supplies the address it
//! loads at. Getting that wrong does not fail loudly: the code still decodes,
//! and every branch still resolves, because ARM branches are relative and
//! their targets move with the base. The comparison quietly reports against
//! the wrong addresses instead.
//!
//! # What cannot be used
//!
//! Two obvious checks were tried and measured, and both are useless:
//!
//! * **Branch targets landing inside the blob.** Scores 1.00 at every base,
//!   including nonsense ones, for the reason above.
//! * **Pointer-like words, on compiled position-independent code.** A `clang`
//!   ARM build keeps its literal pools relative even under `-fno-pic`, so the
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

/// Bytes in one 32-bit word.
const WORD: usize = 4;

/// How many words must look like pointers before a verdict is worth giving.
///
/// One word pointing into the blob is a coincidence. This keeps a single
/// stray value from being read as evidence either way.
const ENOUGH_POINTERS: usize = 2;

/// Below this, a word is padding or a small number rather than an address.
///
/// Firmware is full of zeros and small counts. Counting them would make a
/// base of zero fit every image, because every small word lands inside an
/// image that starts at zero.
const SMALLEST_ADDRESS: u64 = 0x1000;

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
}

impl BaseFit {
    /// Report whether the caller should be warned.
    pub fn is_suspect(self) -> bool {
        matches!(self, Self::Unlikely { .. })
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
        }
    }
}

/// Judge a load address against the words stored in a blob.
pub fn check_base(data: &[u8], base: u64) -> BaseFit {
    let end = base.saturating_add(data.len() as u64);

    let mut inside = 0;
    let mut near = 0;
    let mut examined = 0;

    for word in data.chunks_exact(WORD) {
        let value = u64::from(u32::from_le_bytes([word[0], word[1], word[2], word[3]]));

        // A word near zero is padding, a small count or a null pointer. At a
        // base of zero such words all land "inside" the image, which made a
        // 69 KiB firmware image score 17330 of 17439 words as pointers at
        // base 0 while the right base scored 4. Skipping them is what keeps
        // a base of zero from beating every other answer.
        if value < SMALLEST_ADDRESS {
            continue;
        }
        examined += 1;

        if value >= base && value < end {
            inside += 1;
        } else if lands_near(value, base, data.len() as u64) {
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

/// Report whether a word looks like an address just outside the image.
///
/// "Looks like an address" cannot mean "is a large number": every ARM
/// instruction word is large, so that would count the code itself and report
/// a wrong base on every run. It was measured doing exactly that.
///
/// A wrong base is usually wrong by a modest amount — the caller took the
/// address of the wrong section, or forgot a header. So the telling sign is a
/// word that points **just past** where the image would sit, within a few
/// image lengths of it. An instruction word does not do that, because the
/// image is nowhere near `0xe1e1e1e1`.
fn lands_near(value: u64, base: u64, length: u64) -> bool {
    // How far outside the image still counts as "nearly pointing at it".
    // A few image lengths, and at least a page, so a small image is not held
    // to an impossibly tight window.
    let reach = (length.saturating_mul(4)).max(0x1000);

    let low = base.saturating_sub(reach);
    let high = base.saturating_add(length).saturating_add(reach);

    value >= low && value < high
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a blob from words, little endian.
    ///
    /// The words come first, then filler, because a stored address must fall
    /// inside the image for the check to count it. A vector table at the head
    /// of a small blob would point past its own end.
    fn image(words: &[u32], size: usize) -> Vec<u8> {
        let mut data: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        data.resize(size.max(data.len()), 0xe1);
        data
    }

    /// A vector table names addresses inside the image it belongs to.
    #[test]
    fn a_right_base_is_plausible() {
        // Three entries pointing into a 4 KiB image loaded at 0x08000000.
        let data = image(&[0x0800_000c, 0x0800_0014, 0x0800_0100, 0xe3a0_0001], 0x1000);
        assert!(
            matches!(check_base(&data, 0x0800_0000), BaseFit::Plausible { pointers: 3, .. }),
            "got {:?}",
            check_base(&data, 0x0800_0000)
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
        let fit = check_base(&data, 0x0800_0000);
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
        assert_eq!(check_base(&data, 0x2000_0000), BaseFit::NoEvidence);
    }

    /// A plausible verdict is not a confirmation.
    ///
    /// Measured on a 69 KiB firmware image: the right base scored four
    /// pointers and two wrong bases scored two each. The check rules a base
    /// out, it does not rule one in.
    #[test]
    fn plausible_does_not_mean_certain() {
        // Two words that point into an image based at either of two places.
        let data = image(&[0x0000_1004, 0x0000_1008, 0xe3a0_0001], 0x2000);

        assert!(matches!(check_base(&data, 0x1000), BaseFit::Plausible { .. }));
        assert!(
            matches!(check_base(&data, 0), BaseFit::Plausible { .. }),
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
            check_base(&data, 0x0800_0000),
            BaseFit::NoEvidence,
            "instructions are not addresses"
        );
        assert!(!check_base(&data, 0x0800_0000).is_suspect(), "silence is not an accusation");
    }

    /// One matching word is a coincidence, not evidence.
    #[test]
    fn a_single_pointer_is_not_enough() {
        let data = image(&[0x0800_0004, 0x0000_0001, 0x0000_0002], 0x1000);
        assert!(!matches!(check_base(&data, 0x0800_0000), BaseFit::Plausible { .. }));
    }

    #[test]
    fn an_empty_blob_gives_no_evidence() {
        assert_eq!(check_base(&[], 0), BaseFit::NoEvidence);
    }

    /// Trailing bytes that do not fill a word are ignored rather than read
    /// past.
    #[test]
    fn a_partial_word_is_ignored() {
        let mut data = image(&[0x0800_000c, 0x0800_0014], 0x1000);
        data.extend_from_slice(&[0xff, 0xff]);

        let fit = check_base(&data, 0x0800_0000);
        assert!(matches!(fit, BaseFit::Plausible { pointers: 2, .. }), "got {fit:?}");
    }

    /// A base so high that the image would wrap must not panic.
    #[test]
    fn a_base_near_the_top_of_the_range_does_not_overflow() {
        let data = image(&[0xffff_fff0, 0xffff_fff4], 0x20);
        let _ = check_base(&data, u64::MAX - 4);
    }
}
