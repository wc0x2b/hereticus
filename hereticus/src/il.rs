//! A small intermediate language: what an instruction reads, writes and
//! tests, the same on every architecture.
//!
//! The decoders in [`crate::arch`] give an instruction as text and a kind of
//! control flow. That is enough to compare shapes, but not to see that two
//! spellings do one thing: `cbnz x8, L` and `cmp x8, #0` with `b.ne L` both
//! branch where `x8` is not zero. A lifter turns one instruction into a
//! [`Lifted`], and [`find_guards`] turns a compare and the branch that reads
//! it into one [`Guard`], whatever the spelling.
//!
//! This is no full semantics. It says which registers an instruction reads
//! and writes, whether it touches memory, and what it compares, which is what
//! a check that a fix adds is made of. It does not say what value an
//! instruction computes.

/// A register, named the same way on every architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Reg {
    /// A general register, by its number on its architecture.
    General(u8),
    /// A floating point or vector register, by its number.
    Vector(u8),
    /// The stack pointer.
    Stack,
    /// The condition flags, which a compare writes and a branch reads.
    Flags,
}

impl Reg {
    /// The bit of this register in a [`RegSet`].
    fn bit(self) -> u32 {
        /// The first bit of the vector registers.
        const VECTOR: u32 = 64;
        match self {
            Self::General(number) => u32::from(number % 64),
            Self::Vector(number) => VECTOR + u32::from(number % 32),
            Self::Stack => 126,
            Self::Flags => 127,
        }
    }

    /// The register a bit of a [`RegSet`] stands for.
    fn of_bit(bit: u32) -> Self {
        match bit {
            0..64 => Self::General(bit as u8),
            126 => Self::Stack,
            127 => Self::Flags,
            _ => Self::Vector((bit - 64) as u8),
        }
    }
}

/// A set of registers, held in one word.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RegSet(u128);

impl RegSet {
    /// The empty set.
    pub const EMPTY: Self = Self(0);

    pub fn insert(&mut self, reg: Reg) {
        self.0 |= 1 << reg.bit();
    }

    pub fn contains(self, reg: Reg) -> bool {
        self.0 & (1 << reg.bit()) != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// The registers in the set, in the order of [`Reg`].
    pub fn iter(self) -> impl Iterator<Item = Reg> {
        (0..128).filter(move |&bit| self.0 & (1 << bit) != 0).map(Reg::of_bit)
    }
}

impl FromIterator<Reg> for RegSet {
    fn from_iter<I: IntoIterator<Item = Reg>>(regs: I) -> Self {
        let mut set = Self::EMPTY;
        regs.into_iter().for_each(|reg| set.insert(reg));
        set
    }
}

/// How many bits an operation works on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Width {
    Bits8,
    Bits16,
    Bits32,
    Bits64,
    Bits128,
}

impl Width {
    /// The mask of the bits a value of this width holds.
    pub fn mask(self) -> u64 {
        match self {
            Self::Bits8 => 0xff,
            Self::Bits16 => 0xffff,
            Self::Bits32 => 0xffff_ffff,
            Self::Bits64 | Self::Bits128 => u64::MAX,
        }
    }
}

/// An operand that an instruction reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Value {
    Reg(Reg),
    /// A constant, in the width of the operation.
    Const(u64),
    /// An operand that is no one register and no constant, as a shifted
    /// register.
    Other,
}

/// How an instruction touches memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccessKind {
    Load,
    Store,
    /// Both at once, as an atomic swap or add does.
    LoadStore,
}

/// A memory access.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemoryAccess {
    pub kind: AccessKind,
    /// The width of each value moved, where the instruction says it.
    pub width: Option<Width>,
}

/// A condition on a comparison of two values, `left` against `right`.
///
/// The names read as the test on the values, not on the flags: after
/// `cmp a, b`, [`Cond::UnsignedLess`] holds where `a < b` as unsigned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cond {
    Equal,
    NotEqual,
    UnsignedGreaterOrEqual,
    UnsignedLess,
    /// The result is negative.
    Negative,
    /// The result is zero or positive.
    NotNegative,
    Overflow,
    NoOverflow,
    UnsignedGreater,
    UnsignedLessOrEqual,
    SignedGreaterOrEqual,
    SignedLess,
    SignedGreater,
    SignedLessOrEqual,
    Always,
    /// `left & right` is zero.
    BitsClear,
    /// `left & right` is not zero.
    BitsSet,
}

/// Conditions that test the same relation, with either outcome.
///
/// A compiler can branch on a condition or on its opposite and swap the code
/// after it, so a guard is compared by family, not by condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CondFamily {
    Equality,
    Unsigned,
    Signed,
    Sign,
    Overflow,
    Bits,
    Always,
}

impl Cond {
    /// The condition an ARM condition code tests, for both A32 and A64.
    pub fn from_arm(code: u8) -> Self {
        match code & 0xf {
            0 => Self::Equal,
            1 => Self::NotEqual,
            2 => Self::UnsignedGreaterOrEqual,
            3 => Self::UnsignedLess,
            4 => Self::Negative,
            5 => Self::NotNegative,
            6 => Self::Overflow,
            7 => Self::NoOverflow,
            8 => Self::UnsignedGreater,
            9 => Self::UnsignedLessOrEqual,
            10 => Self::SignedGreaterOrEqual,
            11 => Self::SignedLess,
            12 => Self::SignedGreater,
            13 => Self::SignedLessOrEqual,
            _ => Self::Always,
        }
    }

    pub fn family(self) -> CondFamily {
        match self {
            Self::Equal | Self::NotEqual => CondFamily::Equality,
            Self::UnsignedGreaterOrEqual
            | Self::UnsignedLess
            | Self::UnsignedGreater
            | Self::UnsignedLessOrEqual => CondFamily::Unsigned,
            Self::SignedGreaterOrEqual
            | Self::SignedLess
            | Self::SignedGreater
            | Self::SignedLessOrEqual => CondFamily::Signed,
            Self::Negative | Self::NotNegative => CondFamily::Sign,
            Self::Overflow | Self::NoOverflow => CondFamily::Overflow,
            Self::BitsClear | Self::BitsSet => CondFamily::Bits,
            Self::Always => CondFamily::Always,
        }
    }
}

/// What a compare puts in the flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Comparison {
    /// `left - right`, as `cmp` computes.
    Subtract { left: Value, right: Value },
    /// `left + right`, as `cmn` computes with a register.
    Add { left: Value, right: Value },
    /// `left & right`, as `tst` computes.
    And { left: Value, right: Value },
}

/// A branch on a test of values: the shape a check takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Guard {
    pub cond: Cond,
    pub left: Value,
    pub right: Value,
    pub width: Width,
}

impl Guard {
    /// The same test, with a bound that does not depend on the spelling.
    ///
    /// `x < c` is `x <= c - 1`, and `x >= c` is `x > c - 1`, so a compiler can
    /// write either. Each turns into the second form here. Where `c - 1`
    /// would wrap, as `x < 0` unsigned, which never holds, the guard stays.
    pub fn canonical(self) -> Self {
        let Value::Const(bound) = self.right else { return self };
        let cond = match self.cond {
            Cond::UnsignedLess => Cond::UnsignedLessOrEqual,
            Cond::UnsignedGreaterOrEqual => Cond::UnsignedGreater,
            Cond::SignedLess => Cond::SignedLessOrEqual,
            Cond::SignedGreaterOrEqual => Cond::SignedGreater,
            _ => return self,
        };
        let mask = self.width.mask();
        let lowest = match cond.family() {
            CondFamily::Signed => (mask >> 1).wrapping_add(1) & mask,
            _ => 0,
        };
        if bound & mask == lowest {
            return self;
        }
        Self { cond, right: Value::Const(bound.wrapping_sub(1) & mask), ..self }
    }
}

/// What an instruction tests, or how it uses a test.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Test {
    /// Sets the flags from a comparison and writes nothing else, as `cmp`.
    Compare { comparison: Comparison, width: Width },
    /// Branches where the flags meet a condition, as `b.ne`.
    OnFlags(Cond),
    /// Compares and branches in one, as `cbz` and `tbnz`.
    Guard(Guard),
}

/// One instruction, lifted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Lifted {
    pub reads: RegSet,
    pub writes: RegSet,
    pub memory: Option<MemoryAccess>,
    pub test: Option<Test>,
}

/// Most instructions a compiler puts between a compare and the branch that
/// reads it. GCC schedules other work there, where clang mostly does not.
const MOST_BETWEEN: usize = 4;

/// A guard in a body of instructions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FoundGuard {
    /// The index of the compare, where a separate one sets the flags.
    pub compare: Option<usize>,
    /// The index of the branch.
    pub branch: usize,
    pub guard: Guard,
}

/// Every guard in `body`, in order.
///
/// A guard is one instruction that compares and branches, or a compare and
/// the branch that reads its flags. Between the two, at most
/// [`MOST_BETWEEN`] instructions may come that neither test nor touch the
/// flags; an instruction that cannot be lifted ends the search, since
/// nothing is known of it.
pub fn find_guards(body: &[Option<Lifted>]) -> Vec<FoundGuard> {
    let mut found = Vec::new();
    for (index, lifted) in body.iter().enumerate() {
        match lifted.and_then(|lifted| lifted.test) {
            Some(Test::Guard(guard)) => {
                found.push(FoundGuard { compare: None, branch: index, guard })
            }
            Some(Test::Compare { comparison, width }) => {
                if let Some((branch, cond)) = branch_on_flags(&body[index + 1..])
                    && let Some(guard) = guard_of(comparison, cond, width)
                {
                    found.push(FoundGuard {
                        compare: Some(index),
                        branch: index + 1 + branch,
                        guard,
                    });
                }
            }
            Some(Test::OnFlags(_)) | None => {}
        }
    }
    found
}

/// The first branch on the flags in `after`, by its index and condition,
/// where only work that leaves the flags alone comes before it.
fn branch_on_flags(after: &[Option<Lifted>]) -> Option<(usize, Cond)> {
    for (index, lifted) in after.iter().take(MOST_BETWEEN + 1).enumerate() {
        let lifted = (*lifted)?;
        if let Some(Test::OnFlags(cond)) = lifted.test {
            return Some((index, cond));
        }
        let touches_flags = lifted.reads.contains(Reg::Flags) || lifted.writes.contains(Reg::Flags);
        if lifted.test.is_some() || touches_flags {
            return None;
        }
    }
    None
}

/// The guard that a branch on `cond` after `comparison` makes, where one
/// [`Guard`] can say it.
fn guard_of(comparison: Comparison, cond: Cond, width: Width) -> Option<Guard> {
    match comparison {
        Comparison::Subtract { left, right } => Some(Guard { cond, left, right, width }),
        Comparison::And { left, right } => {
            let cond = match cond {
                Cond::Equal => Cond::BitsClear,
                Cond::NotEqual => Cond::BitsSet,
                _ => return None,
            };
            Some(Guard { cond, left, right, width })
        }
        // The flags of an addition test `left == -right` only for some
        // conditions, so no guard is claimed.
        Comparison::Add { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compare(left: Value, right: Value) -> Option<Lifted> {
        Some(Lifted {
            test: Some(Test::Compare {
                comparison: Comparison::Subtract { left, right },
                width: Width::Bits64,
            }),
            ..Lifted::default()
        })
    }

    fn branch(cond: Cond) -> Option<Lifted> {
        Some(Lifted { test: Some(Test::OnFlags(cond)), ..Lifted::default() })
    }

    fn work() -> Option<Lifted> {
        Some(Lifted { writes: [Reg::General(1)].into_iter().collect(), ..Lifted::default() })
    }

    fn guards(body: &[Option<Lifted>]) -> Vec<(Option<usize>, usize, Cond)> {
        find_guards(body)
            .iter()
            .map(|found| (found.compare, found.branch, found.guard.cond))
            .collect()
    }

    fn guard(cond: Cond, right: u64, width: Width) -> Guard {
        Guard { cond, left: Value::Reg(Reg::General(8)), right: Value::Const(right), width }
    }

    #[test]
    fn a_compare_and_its_branch_are_one_guard() {
        let x8 = Value::Reg(Reg::General(8));
        let body = [compare(x8, Value::Const(0)), branch(Cond::NotEqual)];
        let guard = guard(Cond::NotEqual, 0, Width::Bits64);
        assert_eq!(find_guards(&body), [FoundGuard { compare: Some(0), branch: 1, guard }]);
    }

    #[test]
    fn work_between_a_compare_and_its_branch_is_allowed() {
        let x8 = Value::Reg(Reg::General(8));
        let body = [compare(x8, Value::Const(0)), work(), work(), branch(Cond::Equal)];
        assert_eq!(guards(&body), [(Some(0), 3, Cond::Equal)]);
    }

    #[test]
    fn too_much_work_or_a_flag_write_ends_the_search() {
        let x8 = Value::Reg(Reg::General(8));
        let mut far = vec![compare(x8, Value::Const(0))];
        far.extend(core::iter::repeat_n(work(), MOST_BETWEEN + 1));
        far.push(branch(Cond::Equal));
        assert_eq!(guards(&far), []);

        let flags =
            Some(Lifted { writes: [Reg::Flags].into_iter().collect(), ..Lifted::default() });
        assert_eq!(guards(&[compare(x8, Value::Const(0)), flags, branch(Cond::Equal)]), []);
        assert_eq!(guards(&[compare(x8, Value::Const(0)), None, branch(Cond::Equal)]), []);
    }

    #[test]
    fn a_second_compare_takes_the_branch() {
        let x8 = Value::Reg(Reg::General(8));
        let body =
            [compare(x8, Value::Const(0)), compare(x8, Value::Const(1)), branch(Cond::Equal)];
        assert_eq!(guards(&body), [(Some(1), 2, Cond::Equal)]);
    }

    /// Clang tests `x < 1` where GCC tests `x <= 0`.
    #[test]
    fn a_bound_off_by_one_reads_the_same() {
        let width = Width::Bits32;
        assert_eq!(
            guard(Cond::SignedLess, 1, width).canonical(),
            guard(Cond::SignedLessOrEqual, 0, width).canonical()
        );
        assert_eq!(
            guard(Cond::UnsignedGreaterOrEqual, 0x40, width).canonical(),
            guard(Cond::UnsignedGreater, 0x3f, width).canonical()
        );
        assert_eq!(
            guard(Cond::SignedLess, 0, width).canonical(),
            guard(Cond::SignedLessOrEqual, 0xffff_ffff, width).canonical(),
            "the step wraps in the width"
        );
    }

    #[test]
    fn a_canonical_guard_tests_the_same_values() {
        bolero::check!().with_type::<(u8, u8, u8)>().for_each(|&(code, bound, value)| {
            let cond = Cond::from_arm(code % 14);
            if cond.family() != CondFamily::Signed && cond.family() != CondFamily::Unsigned {
                return;
            }
            let before = guard(cond, u64::from(bound), Width::Bits8);
            let after = before.canonical();
            let Value::Const(after_bound) = after.right else { panic!("still a constant") };
            assert_eq!(
                holds(before.cond, value, bound),
                holds(after.cond, value, after_bound as u8),
                "{before:?} and {after:?} at {value}"
            );
        });
    }

    /// Whether `cond` holds for `value` against `bound`, as 8-bit numbers.
    fn holds(cond: Cond, value: u8, bound: u8) -> bool {
        let (signed, signed_bound) = (value as i8, bound as i8);
        match cond {
            Cond::UnsignedLess => value < bound,
            Cond::UnsignedLessOrEqual => value <= bound,
            Cond::UnsignedGreater => value > bound,
            Cond::UnsignedGreaterOrEqual => value >= bound,
            Cond::SignedLess => signed < signed_bound,
            Cond::SignedLessOrEqual => signed <= signed_bound,
            Cond::SignedGreater => signed > signed_bound,
            Cond::SignedGreaterOrEqual => signed >= signed_bound,
            _ => unreachable!(),
        }
    }

    #[test]
    fn a_test_of_bits_reads_as_bits_clear_or_set() {
        let x0 = Value::Reg(Reg::General(0));
        let tst = Some(Lifted {
            test: Some(Test::Compare {
                comparison: Comparison::And { left: x0, right: Value::Const(4) },
                width: Width::Bits32,
            }),
            ..Lifted::default()
        });
        assert_eq!(guards(&[tst, branch(Cond::Equal)]), [(Some(0), 1, Cond::BitsClear)]);
        assert_eq!(guards(&[tst, branch(Cond::SignedLess)]), [], "no bit test");
    }

    #[test]
    fn nothing_lifted_is_no_guard() {
        assert_eq!(guards(&[]), []);
        assert_eq!(guards(&[None, branch(Cond::Equal)]), []);
        assert_eq!(guards(&[branch(Cond::Equal)]), [], "a branch alone");
    }

    #[test]
    fn opposite_conditions_share_a_family() {
        for code in 0..14_u8 {
            let cond = Cond::from_arm(code);
            let opposite = Cond::from_arm(code ^ 1);
            assert_eq!(cond.family(), opposite.family(), "{cond:?} and {opposite:?}");
        }
    }

    #[test]
    fn a_register_set_holds_what_was_put_in() {
        let regs = [Reg::General(0), Reg::General(30), Reg::Vector(31), Reg::Stack, Reg::Flags];
        let set: RegSet = regs.into_iter().collect();
        assert_eq!(set.len(), regs.len());
        assert!(regs.iter().all(|&reg| set.contains(reg)));
        assert!(!set.contains(Reg::General(1)));
        assert_eq!(set.iter().collect::<Vec<_>>(), regs);
    }

    #[test]
    fn every_register_comes_back_from_its_bit() {
        bolero::check!().with_type::<(u8, bool)>().for_each(|&(number, vector)| {
            let reg = if vector { Reg::Vector(number % 32) } else { Reg::General(number % 64) };
            assert_eq!(Reg::of_bit(reg.bit()), reg);
        });
    }
}
