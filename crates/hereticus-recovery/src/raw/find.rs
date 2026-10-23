//! Find the load address of a raw image from the words that point into it.
//!
//! An image holds the full addresses of its own strings and functions: in
//! tables of pointers, in literal pools, and in the immediates of x86 code.
//! Such an address does not move with the base the image is read at. At the
//! right base, many of these words point at the start of a string or of a
//! function. At any other base, few do.
//!
//! # How the base is found
//!
//! rbasefind tries every base that is a multiple of 4 KiB, and counts the
//! words that point at a string at each one: a million bases on a 32-bit
//! image, and none on a 64-bit one. Measured on a 13 MiB ARM kernel, it did
//! not finish in ten minutes on 16 threads.
//!
//! Here the targets vote instead. A target is the start of a string or of
//! a function. Each word `v` says that if it points at the target `t`, the
//! base is `v - t`. A few targets, the anchors, take a vote from every word.
//! The right base then also puts words on most other targets, and a wrong
//! one on few, so a short screen against other targets keeps only a few
//! thousand candidates. Each of those is counted against every target.
//!
//! This finds the exact base, not a multiple of a page, on 32-bit and on
//! 64-bit images, in about a second on a kernel.
//!
//! # When it gives no base
//!
//! A count alone can mislead: where the words of the code are dense, as
//! the opcodes of A32 are around `0xe5000000`, a wrong base can put many
//! of them on targets by chance. So each candidate also counts the words
//! that fall anywhere in the image at its base. Only the excess of hits
//! over what those words give by chance counts as evidence, and the best
//! base must beat the next by a clear margin. Small position-independent
//! code holds few full addresses, and then no base wins.

use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasherDefault, Hasher};

use crate::arch::Recovery;
use crate::raw::is_text;
use hereticus_memory::SMALLEST_ADDRESS;

/// The shortest run of printable bytes, closed by a zero byte, that counts
/// as a string.
const SHORTEST_STRING: usize = 6;

/// How many targets of each kind vote. Spread over the image, so that a
/// part of it with no pointers, as a table of numbers, cannot silence them
/// all.
const VOTERS_PER_KIND: usize = 32;

/// How many voters take a vote from every word.
const ANCHORS: usize = 16;

/// How many other voters screen each candidate of an anchor. One hit among
/// them keeps a candidate.
const SCREEN: usize = 16;

/// How many candidates, by their votes, are counted against every target.
const FINALISTS: usize = 64;

/// How far from a base the bases are that show what chance gives near it.
///
/// A word that is an address points at the start of a string or of a
/// function only at the right base, and at a base a few bytes off it points
/// into the middle of one. Words that hit by chance, as a run of similar
/// instruction words does, hit about as often a few bytes off.
const NEARBY: [i64; 16] =
    [-4096, -256, -64, -32, -16, -12, -8, -4, 4, 8, 12, 16, 32, 64, 256, 4096];

/// The alignment that most bases have, and that [`Words::page_votes`]
/// takes for granted.
const PAGE: u64 = 0x1000;

/// How many bases on a page, by their votes, go on to be counted.
const PAGE_CANDIDATES: usize = 32;

/// How many pages, by their votes, are compared with the pages beside them.
const PAGE_CONTRASTED: usize = 16_384;

/// How many pages on each side a page is compared with.
const PAGES_BESIDE: u64 = 8;

/// The most votes that the bases on a page take, which bounds the time on
/// a large image. Past it, only a part of the targets vote.
const PAGE_VOTES: usize = 150_000_000;

/// The width of the window that an address in two halves can reach with
/// its low half alone: see [`BaseCandidate::confined`].
const HALF_WINDOW: u64 = 1 << 16;

/// How many targets of each kind count the hits at the nearby bases.
const SAMPLED: usize = 4096;

/// How many instructions before a prologue can belong to its function: see
/// [`Recovery::preamble_before_prologue`].
const PREAMBLE: usize = 4;

/// How many candidates [`rank_bases`] reports.
pub const RANKED: usize = 8;

/// The fewest hits above chance that a base needs to be suggested.
const ENOUGH_EXCESS: f64 = 8.0;

/// How many times the excess of the next base the best one must have.
const CLEARLY_BETTER: f64 = 2.0;

/// One base an image could load at, with the evidence for it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BaseCandidate {
    pub base: u64,
    /// Strings that a word points at the start of, at this base.
    pub strings: usize,
    /// Function starts that a word points at, at this base.
    pub functions: usize,
    /// The hits that chance gives here: the median of the hits at the
    /// bases a few bytes off this one. See [`NEARBY`].
    pub expected: f64,
    /// Whether the hits look like the low halves of addresses, not whole
    /// ones.
    ///
    /// Code that builds an address from two halves holds the low half in an
    /// instruction, as MIPS `addiu a0, a0, %lo(text)` does. Read as a word,
    /// the opcode is the high half, and the low half points at a target as
    /// a whole address would, for a base just below the opcode. Such halves
    /// reach one window of 64 KiB, and they name text, not functions, which
    /// code reaches by a call. So the hits are confined where they all fall
    /// in one window of an image that holds targets in more, or, in an image
    /// too small to tell, where they are of one kind.
    pub confined: bool,
}

impl BaseCandidate {
    /// The hits on strings and functions together.
    pub fn hits(&self) -> usize {
        self.strings + self.functions
    }

    /// The hits above what chance gives: the evidence for this base. None
    /// where the hits are [`BaseCandidate::confined`].
    pub fn excess(&self) -> f64 {
        if self.confined { 0.0 } else { self.hits() as f64 - self.expected }
    }
}

/// The bases `data` could load at, the best first, at most [`RANKED`].
///
/// Empty when the image holds no strings or functions, or no word points
/// at one.
pub fn rank_bases(data: &[u8], arch: &dyn Recovery) -> Vec<BaseCandidate> {
    let targets = Targets::find(data, arch);
    let words = Words::read(data, arch);
    let voters = targets.voters();
    if voters.len() < 2 {
        return Vec::new();
    }

    let mut candidates: HashSet<u64, Fast> = HashSet::default();
    let anchors = voters.len().min(ANCHORS);
    let per_anchor: Vec<Vec<u64>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..anchors)
            .map(|anchor| {
                let (words, voters) = (&words, &voters);
                scope.spawn(move || words.screen(voters, anchor))
            })
            .collect();
        handles.into_iter().map(|handle| handle.join().expect("a screen does not panic")).collect()
    });
    candidates.extend(per_anchor.into_iter().flatten());

    // An image that runs past the top of the address space cannot load
    // there. Offsets from the global offset table, which i686 and ARM PIC
    // code holds, agree with each other as addresses would, about a base
    // just below the top.
    let fits = |base: u64| match arch.pointer_width() {
        4 => base.checked_add(data.len() as u64).is_some_and(|end| end <= 1 << 32),
        _ => base.checked_add(data.len() as u64).is_some(),
    };
    let mut voted: Vec<(u64, usize)> = candidates
        .into_iter()
        .filter(|&base| fits(base))
        .map(|base| (base, words.votes(&voters, base)))
        .collect();
    voted.sort_unstable_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));

    // The anchors rank their candidates by the voters, which few words point
    // at where few targets are pointed at at all, as in PIC code. The pages
    // ranked theirs by every target, so each one is counted.
    let mut finalists: Vec<u64> = voted.into_iter().take(FINALISTS).map(|(base, _)| base).collect();
    finalists.extend(words.page_votes(&targets).into_iter().filter(|&base| fits(base)));
    finalists.sort_unstable();
    finalists.dedup();
    let mut ranked: Vec<BaseCandidate> =
        finalists.into_iter().map(|base| words.evidence(&targets, base)).collect();
    ranked.sort_unstable_by(|left, right| {
        right.excess().total_cmp(&left.excess()).then(left.base.cmp(&right.base))
    });
    ranked.truncate(RANKED);
    ranked
}

/// The evidence for one base: the strings and the function starts that a
/// word of `data` points at when it loads at `base`.
pub fn measure_base(data: &[u8], arch: &dyn Recovery, base: u64) -> BaseCandidate {
    Words::read(data, arch).evidence(&Targets::find(data, arch), base)
}

/// The base that `ranked`, as [`rank_bases`] gives it, shows clearly, or
/// `None`.
pub fn clear_winner(ranked: &[BaseCandidate]) -> Option<u64> {
    let best = ranked.first()?;
    let next = ranked.get(1).map_or(0.0, |next| next.excess().max(0.0));
    (best.excess() >= ENOUGH_EXCESS && best.excess() > next * CLEARLY_BETTER).then_some(best.base)
}

/// What a word can point at: the start of a string or of a function, as
/// offsets into the image.
struct Targets {
    strings: Vec<u64>,
    functions: Vec<u64>,
}

/// Which list of targets a target is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    String,
    Function,
}

impl Targets {
    fn find(data: &[u8], arch: &dyn Recovery) -> Self {
        Self { strings: string_starts(data), functions: function_starts(data, arch) }
    }

    /// The targets that vote, the anchors first, the two kinds in turn.
    ///
    /// A function is the better anchor: code points at a function from a
    /// table of handlers on every architecture, but at a string through an
    /// immediate on MIPS, which holds no full address.
    fn voters(&self) -> Vec<(u64, Kind)> {
        let spread = |list: &[u64]| -> Vec<u64> {
            let step = (list.len() / VOTERS_PER_KIND).max(1);
            list.iter().step_by(step).take(VOTERS_PER_KIND).copied().collect()
        };
        let functions = spread(&self.functions);
        let strings = spread(&self.strings);
        let mut voters = Vec::with_capacity(functions.len() + strings.len());
        for index in 0..functions.len().max(strings.len()) {
            if let Some(&function) = functions.get(index) {
                voters.push((function, Kind::Function));
            }
            if let Some(&string) = strings.get(index) {
                voters.push((string, Kind::String));
            }
        }
        voters
    }
}

/// The offset of each run of printable bytes that a zero byte closes, and
/// that is at least [`SHORTEST_STRING`] long.
fn string_starts(data: &[u8]) -> Vec<u64> {
    let printable =
        |byte: u8| (0x20..0x7f).contains(&byte) || matches!(byte, b'\t' | b'\n' | b'\r');
    let mut starts = Vec::new();
    let mut run_start = 0;
    for (at, &byte) in data.iter().enumerate() {
        if printable(byte) {
            continue;
        }
        if byte == 0 && at - run_start >= SHORTEST_STRING {
            starts.push(run_start as u64);
        }
        run_start = at + 1;
    }
    starts
}

/// The offset of each instruction that opens a function, as the
/// architecture's prologue says.
///
/// A pointer names the first instruction of a function, which can come a
/// few words before its prologue, as the `$gp` set up of MIPS PIC does.
pub(crate) fn function_starts(data: &[u8], arch: &dyn Recovery) -> Vec<u64> {
    let width = arch.instruction_width();
    (0..data.len())
        .step_by(width)
        .filter(|&at| {
            arch.may_be_prologue(&data[at..])
                && arch.decode(data, at, 0).is_ok_and(|insn| arch.is_prologue(&insn))
        })
        .map(|at| at - preamble(data, arch, at) * width)
        .map(|at| at as u64)
        .collect()
}

/// How many instructions before the prologue at `at` belong to its
/// function: an entry sequence, as [`Recovery::is_function_entry`] names
/// one, or a preamble. Only a fixed width can be read backwards, so a
/// variable one has none.
fn preamble(data: &[u8], arch: &dyn Recovery, at: usize) -> usize {
    let width = arch.instruction_width();
    if width == 1 {
        return 0;
    }
    let decoded = |from: usize, count: usize| -> Vec<_> {
        (0..count).map_while(|index| arch.decode(data, from + index * width, 0).ok()).collect()
    };
    let entry = (1..=PREAMBLE).rev().find(|&back| {
        at.checked_sub(back * width)
            .is_some_and(|from| arch.is_function_entry(&decoded(from, back + 1)))
    });
    if let Some(back) = entry {
        return back;
    }
    let first = at.saturating_sub(PREAMBLE * width);
    let earlier = decoded(first, (at - first) / width);
    arch.preamble_before_prologue(&earlier).min(earlier.len())
}

/// The values of the words of an image that could be addresses.
struct Words {
    /// Each value, as it is stored: what a string is pointed at by.
    values: HashSet<u64, Fast>,
    /// Each value as the address of the function it names, where the
    /// architecture tags a pointer to a function, as Thumb sets bit 0.
    /// `None` where it is the same set.
    functions: Option<HashSet<u64, Fast>>,
}

impl Words {
    /// Read each word of `data` that could be an address.
    ///
    /// A word is read at each multiple of the width of a pointer. x86 code
    /// also holds 32-bit addresses as immediates, at any byte, so on x86
    /// each 4 bytes at each offset are read too.
    fn read(data: &[u8], arch: &dyn Recovery) -> Self {
        let width = arch.pointer_width();
        let mut values: Vec<u64> = data
            .chunks_exact(width)
            .filter(|word| !is_text(word))
            .map(|word| arch.read_pointer(word))
            .collect();
        if arch.instruction_width() == 1 {
            values.extend(
                data.windows(4).filter(|word| !is_text(word)).map(|word| {
                    u64::from(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
                }),
            );
        }
        values.retain(|&value| value >= SMALLEST_ADDRESS);
        let tags = arch.tagged_function(1).is_some();
        let functions = tags.then(|| {
            values.iter().map(|&value| arch.tagged_function(value).unwrap_or(value)).collect()
        });
        Self { values: values.into_iter().collect(), functions }
    }

    fn set(&self, kind: Kind) -> &HashSet<u64, Fast> {
        match (kind, &self.functions) {
            (Kind::Function, Some(functions)) => functions,
            _ => &self.values,
        }
    }

    /// Report whether a word points at the target at `offset` when the
    /// image loads at `base`.
    fn points_at(&self, kind: Kind, offset: u64, base: u64) -> bool {
        base.checked_add(offset).is_some_and(|address| self.set(kind).contains(&address))
    }

    /// The bases at which a word points at the voter `anchor` and at one
    /// or more of the [`SCREEN`] voters after it.
    fn screen(&self, voters: &[(u64, Kind)], anchor: usize) -> Vec<u64> {
        let (offset, kind) = voters[anchor];
        let others: Vec<(u64, Kind)> = voters
            .iter()
            .enumerate()
            .filter(|&(at, _)| at != anchor)
            .map(|(_, &voter)| voter)
            .take(SCREEN)
            .collect();
        self.set(kind)
            .iter()
            .filter_map(|&value| value.checked_sub(offset))
            .filter(|&base| others.iter().any(|&(other, kind)| self.points_at(kind, other, base)))
            .collect()
    }

    /// The bases on a page that the most pairs of a word and a target of
    /// the same kind put the word on the target at.
    ///
    /// A word and a target pair only where their offsets into a page agree,
    /// so every word votes with every target, at a cost of the words times
    /// the targets over the size of a page.
    fn page_votes(&self, targets: &Targets) -> Vec<u64> {
        let words = [
            ByPageOffset::of(self.values.iter().copied()),
            ByPageOffset::of(self.set(Kind::Function).iter().copied()),
        ];
        let lists = [
            ByPageOffset::of(targets.strings.iter().copied()),
            ByPageOffset::of(targets.functions.iter().copied()),
        ];
        let votes: usize = words.iter().zip(&lists).map(|(words, list)| words.pairs(list)).sum();
        let step = votes.div_ceil(PAGE_VOTES).max(1);

        let mut counts: HashMap<u64, u32, Fast> = HashMap::default();
        for (words, list) in words.iter().zip(&lists) {
            for (words, list) in words.0.iter().zip(&list.0) {
                for &target in list.iter().step_by(step) {
                    for base in words.iter().filter_map(|&word| word.checked_sub(target)) {
                        *counts.entry(base / PAGE).or_default() += 1;
                    }
                }
            }
        }

        // Dense words, as the opcodes of A32 are, give each page near them
        // about as many votes as the right base gets. The right base stands
        // above the pages beside it, and those do not.
        let mut ranked: Vec<(u64, u32)> =
            counts.iter().map(|(&page, &count)| (page, count)).collect();
        ranked.sort_unstable_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
        ranked.truncate(PAGE_CONTRASTED);
        let above_beside = |page: u64, count: u32| -> i64 {
            let mut beside: Vec<u32> = (1..=PAGES_BESIDE)
                .flat_map(|step| [page.checked_sub(step), page.checked_add(step)])
                .map(|near| near.and_then(|near| counts.get(&near).copied()).unwrap_or(0))
                .collect();
            beside.sort_unstable();
            i64::from(count) - i64::from(beside[beside.len() / 2])
        };
        let mut contrasted: Vec<(u64, i64)> =
            ranked.into_iter().map(|(page, count)| (page, above_beside(page, count))).collect();
        contrasted.sort_unstable_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
        contrasted.into_iter().take(PAGE_CANDIDATES).map(|(page, _)| page * PAGE).collect()
    }

    /// How many voters a word points at when the image loads at `base`.
    fn votes(&self, voters: &[(u64, Kind)], base: u64) -> usize {
        voters.iter().filter(|&&(offset, kind)| self.points_at(kind, offset, base)).count()
    }

    /// Count every target that a word points at when the image loads at
    /// `base`, and the hits that chance gives near it.
    fn evidence(&self, targets: &Targets, base: u64) -> BaseCandidate {
        let hits = |list: &[u64], kind, base| {
            list.iter().filter(|&&offset| self.points_at(kind, offset, base)).count()
        };
        let strings = hits(&targets.strings, Kind::String, base);
        let functions = hits(&targets.functions, Kind::Function, base);
        let confined = is_confined(targets, |offset, kind| self.points_at(kind, offset, base));

        // A sample of each kind is enough to see the level of chance, and
        // keeps sixteen more counts from costing sixteen times the first.
        let sample = |list: &[u64]| -> (Vec<u64>, f64) {
            let step = (list.len() / SAMPLED).max(1);
            (list.iter().step_by(step).copied().collect(), step as f64)
        };
        let (string_sample, string_scale) = sample(&targets.strings);
        let (function_sample, function_scale) = sample(&targets.functions);
        let mut nearby: Vec<f64> = NEARBY
            .iter()
            .filter_map(|&shift| base.checked_add_signed(shift))
            .map(|near| {
                hits(&string_sample, Kind::String, near) as f64 * string_scale
                    + hits(&function_sample, Kind::Function, near) as f64 * function_scale
            })
            .collect();
        nearby.sort_unstable_by(f64::total_cmp);
        let expected = nearby.get(nearby.len() / 2).copied().unwrap_or(0.0);
        BaseCandidate { base, strings, functions, expected, confined }
    }
}

/// Report whether the targets that `hit` says a word points at are
/// [`BaseCandidate::confined`].
fn is_confined(targets: &Targets, hit: impl Fn(u64, Kind) -> bool) -> bool {
    let window = |offset: u64| offset / HALF_WINDOW;
    let all = targets.strings.iter().chain(&targets.functions);
    let spans_more =
        all.clone().map(|&offset| window(offset)).max() > all.map(|&offset| window(offset)).min();
    let hit_strings: Vec<u64> =
        targets.strings.iter().copied().filter(|&offset| hit(offset, Kind::String)).collect();
    let hit_functions: Vec<u64> =
        targets.functions.iter().copied().filter(|&offset| hit(offset, Kind::Function)).collect();
    if !spans_more {
        return hit_strings.is_empty() != hit_functions.is_empty();
    }
    let mut windows = hit_strings.iter().chain(&hit_functions).map(|&offset| window(offset));
    let Some(first) = windows.next() else { return false };
    windows.all(|other| other == first)
}

/// Values grouped by their offset into a page: a word and a target can
/// meet at a base on a page only where these agree.
struct ByPageOffset(Vec<Vec<u64>>);

impl ByPageOffset {
    fn of(values: impl Iterator<Item = u64>) -> Self {
        let mut groups = vec![Vec::new(); PAGE as usize];
        for value in values {
            groups[(value % PAGE) as usize].push(value);
        }
        Self(groups)
    }

    /// How many pairs of one value of each meet at a base on a page.
    fn pairs(&self, other: &Self) -> usize {
        self.0.iter().zip(&other.0).map(|(left, right)| left.len() * right.len()).sum()
    }
}

/// A hasher for addresses: one multiply, as Fibonacci hashing does.
///
/// The standard hasher resists collisions that an attacker picks, which a
/// set of addresses does not need, and is several times slower.
#[derive(Default)]
struct AddressHasher(u64);

impl Hasher for AddressHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = (self.0 ^ u64::from(byte)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = value.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(29);
    }
}

type Fast = BuildHasherDefault<AddressHasher>;

#[cfg(test)]
mod tests {
    use super::*;
    use hereticus_il::arch::aarch64::Aarch64;
    use hereticus_il::arch::arm32::Arm32;
    use hereticus_il::arch::mips::Mips32;
    use hereticus_il::arch::thumb::Thumb2;
    use hereticus_il::arch::x86::X86;

    /// `push {r4, lr}`, a prologue of A32.
    const PUSH: u32 = 0xe92d_4010;
    /// `pop {r4, pc}`.
    const POP: u32 = 0xe8bd_8010;
    /// `mov r0, r0`, filler that opens nothing.
    const MOV: u32 = 0xe1a0_0000;

    /// A firmware image of A32 that loads at `base`: functions, then texts,
    /// then a table of pointers to each, as a table of commands holds them.
    fn firmware(base: u64) -> Vec<u8> {
        let mut words: Vec<u32> = Vec::new();
        let mut functions = Vec::new();
        for index in 0..40 {
            functions.push(words.len() * 4);
            words.push(PUSH);
            words.extend(std::iter::repeat_n(MOV, 3 + index % 5));
            words.push(POP);
        }
        let mut data: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let mut texts = Vec::new();
        for index in 0..40 {
            texts.push(data.len());
            data.extend_from_slice(format!("command number {index} failed\0").as_bytes());
        }
        while !data.len().is_multiple_of(4) {
            data.push(0);
        }
        for (function, text) in functions.iter().zip(&texts) {
            for offset in [function, text] {
                data.extend_from_slice(&(base as u32).wrapping_add(*offset as u32).to_le_bytes());
            }
        }
        data
    }

    #[test]
    fn a_string_is_printable_bytes_that_a_zero_closes() {
        let data = b"\x01short\0long enough\0\x02text with no end";
        assert_eq!(string_starts(data), [7]);
        assert_eq!(string_starts(b"tabs\tand\nnew lines\0"), [0]);
        assert!(string_starts(b"").is_empty());
    }

    #[test]
    fn a_pic_function_of_mips_starts_at_its_global_pointer() {
        // lui gp, 2; addiu gp, gp, -0x7ff0; addu gp, gp, t9; addiu sp, sp, -32
        let words: [u32; 4] = [0x3c1c_0002, 0x279c_8010, 0x0399_e021, 0x27bd_ffe0];
        let mut data: Vec<u8> = 0u32.to_le_bytes().to_vec();
        data.extend(words.iter().flat_map(|word| word.to_le_bytes()));
        assert_eq!(function_starts(&data, &Mips32::LITTLE), [4]);
    }

    #[rstest::rstest]
    #[case::on_a_page(0x0800_0000)]
    #[case::off_a_page(0x0801_2344)]
    #[case::high(0xc000_8000)]
    fn the_words_of_firmware_show_its_base(#[case] base: u64) {
        let data = firmware(base);
        let ranked = rank_bases(&data, &Arm32);
        assert_eq!(clear_winner(&ranked), Some(base), "{ranked:#?}");
        let found = ranked[0];
        assert_eq!((found.strings, found.functions), (40, 40));
        assert_eq!(measure_base(&data, &Arm32, base), found);
    }

    #[test]
    fn a_base_that_does_not_fit_below_the_top_is_no_answer() {
        // Every pointer wraps past 4 GiB at the base that would fit them.
        let data = firmware(0xffff_ff00);
        let ranked = rank_bases(&data, &Arm32);
        assert!(ranked.iter().all(|candidate| candidate.base + data.len() as u64 <= 1 << 32));
        assert_eq!(clear_winner(&ranked), None);
    }

    #[test]
    fn noise_shows_no_base() {
        // A fixed stream from xorshift, so the test sees the same bytes each run.
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let noise: Vec<u8> = (0..1 << 16)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        for arch in [
            &Arm32 as &dyn Recovery,
            &Thumb2,
            &Aarch64,
            &Mips32::LITTLE,
            &X86::BITS32,
            &X86::BITS64,
        ] {
            assert_eq!(clear_winner(&rank_bases(&noise, arch)), None);
        }
        assert!(rank_bases(&[], &Arm32).is_empty());
        assert!(rank_bases(&[0; 4096], &Arm32).is_empty());
    }

    #[test]
    fn halves_of_addresses_are_no_evidence() {
        // `addiu a0, a0, %lo(text)` for each of many texts: as words, each
        // points at its text from the base 0x24840000.
        let mut data = Vec::new();
        let mut texts = Vec::new();
        for index in 0..60 {
            texts.push(0x400 + index * 0x20);
        }
        for &text in &texts {
            data.extend_from_slice(&(0x2484_0000_u32 | text as u32).to_le_bytes());
        }
        data.resize(0x400, 0);
        for index in 0..texts.len() {
            let text = format!("message {index:02} of the loader\0");
            data.extend_from_slice(text.as_bytes());
            data.resize(0x400 + (index + 1) * 0x20, 0);
        }
        let ranked = rank_bases(&data, &Mips32::LITTLE);
        let near_opcode =
            |candidate: &&BaseCandidate| candidate.base.abs_diff(0x2484_0000) < 0x1_0000;
        assert!(ranked.iter().any(|candidate| near_opcode(&candidate)), "{ranked:#?}");
        assert!(ranked.iter().filter(near_opcode).all(|candidate| candidate.confined));
        assert_eq!(clear_winner(&ranked), None);
    }

    #[test]
    fn any_bytes_rank_in_order_without_a_panic() {
        bolero::check!().with_type::<(u8, Vec<u8>)>().for_each(|(arch, data)| {
            let arches: [&dyn Recovery; 6] =
                [&Arm32, &Thumb2, &Aarch64, &Mips32::LITTLE, &X86::BITS32, &X86::BITS64];
            let arch = arches[usize::from(*arch) % arches.len()];
            let ranked = rank_bases(data, arch);
            assert!(ranked.len() <= RANKED);
            assert!(ranked.windows(2).all(|pair| pair[0].excess() >= pair[1].excess()));
            if let Some(base) = clear_winner(&ranked) {
                assert_eq!(base, ranked[0].base);
            }
        });
    }
}
