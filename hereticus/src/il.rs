//! A small intermediate language: what an instruction reads, writes and
//! tests, the same on every architecture.
//!
//! The decoders in [`crate::arch`] give an instruction as text and a kind of
//! control flow. That is enough to compare shapes, but not to see that two
//! spellings do one thing: `cbnz x8, L` and `cmp x8, #0` with `b.ne L` both
//! branch where `x8` is not zero, and MIPS `slt t0, a0, a1` with `bnez t0`
//! tests `a0 < a1` as `cmp a0, a1` with `b.lt` does. A lifter turns one
//! instruction into a [`Lifted`], and [`find_guards`] turns a compare and
//! the branch that reads it into one [`Guard`], whatever the spelling.
//! AArch64, A32, Thumb-2 and MIPS32 each have a lifter: see `Arch::lift`.
//!
//! A lifted instruction also names its operation, as an [`Op`], and its
//! operands, as [`Operand`]s, so that spellings of one operation read
//! alike: `addu` is `add`, a 16-bit Thumb `adds r0, #1` names `r0` twice as
//! `add r0, r0, #1` does, and [`Lifted::canonical`] reads an idiom such as
//! `eor r0, r1, r1` as the move of zero it is.
//!
//! This is no full semantics. It says which registers an instruction reads
//! and writes, whether it touches memory, what it compares, and of which
//! kind each operand is, which is what a check that a fix adds is made of.
//! It does not say what value an instruction computes.
//!
//! # Against the IL of other tools
//!
//! Ghidra lifts to p-code, and its BSim compares functions by features of
//! the SSA form the decompiler builds: each value hashed with the operation
//! that defines it and that operation's inputs, over three rounds, plus the
//! shape of the blocks, weighted by how rare each feature is. Binary Ninja
//! lifts to a stack of ILs; its WARP matches functions exactly, by a hash of
//! each basic block with the relocatable instructions zeroed, and leaves
//! fuzzy matching to BinDiff, which compares flow graphs, call graphs and an
//! order-free product of the mnemonics.
//!
//! This IL is smaller than either: no SSA and no blocks, one instruction at
//! a time, so a whole kernel lifts in seconds. It keeps BSim's core idea in
//! [`flow_features`], which knows an operation by what feeds it, and the
//! matching uses those features to take a pair the instructions alone just
//! miss. Measured against the symbols of the cross builds, what BSim and
//! BinDiff add beyond that did not help here: a weight by rarity, the count
//! of blocks, edges and loops, and looking through copies and spills. The
//! largest gains came from reading what each instruction does one way on
//! every architecture: the operation, its operands, a guard, an idiom.

use smallvec::SmallVec;

/// A register, named the same way on every architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Reg {
    /// A general register, by its number on its architecture. MIPS keeps
    /// `hi` and `lo` at 32 and 33.
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
    /// How many bits wide this is.
    pub fn bits(self) -> u32 {
        match self {
            Self::Bits8 => 8,
            Self::Bits16 => 16,
            Self::Bits32 => 32,
            Self::Bits64 => 64,
            Self::Bits128 => 128,
        }
    }

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

    /// The condition that holds where this one does not.
    pub fn opposite(self) -> Self {
        match self {
            Self::Equal => Self::NotEqual,
            Self::NotEqual => Self::Equal,
            Self::UnsignedGreaterOrEqual => Self::UnsignedLess,
            Self::UnsignedLess => Self::UnsignedGreaterOrEqual,
            Self::Negative => Self::NotNegative,
            Self::NotNegative => Self::Negative,
            Self::Overflow => Self::NoOverflow,
            Self::NoOverflow => Self::Overflow,
            Self::UnsignedGreater => Self::UnsignedLessOrEqual,
            Self::UnsignedLessOrEqual => Self::UnsignedGreater,
            Self::SignedGreaterOrEqual => Self::SignedLess,
            Self::SignedLess => Self::SignedGreaterOrEqual,
            Self::SignedGreater => Self::SignedLessOrEqual,
            Self::SignedLessOrEqual => Self::SignedGreater,
            Self::BitsClear => Self::BitsSet,
            Self::BitsSet => Self::BitsClear,
            Self::Always => Self::Always,
        }
    }

    /// One of this condition and its opposite, the same for both.
    ///
    /// A compiler can branch on a condition or on its opposite and swap the
    /// code after it, so a branch is compared by this. Unlike
    /// [`Self::family`], it keeps `a > b` apart from `a < b`.
    pub fn either_way(self) -> Self {
        match self {
            Self::NotEqual
            | Self::UnsignedLess
            | Self::NotNegative
            | Self::NoOverflow
            | Self::UnsignedLessOrEqual
            | Self::SignedLess
            | Self::SignedLessOrEqual
            | Self::BitsSet => self.opposite(),
            _ => self,
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
    /// Writes 1 to `dest` where `left` meets `cond` against `right`, and 0
    /// where not, as the MIPS `slt` does. A branch on `dest` then makes a
    /// guard of it.
    SetOnCompare { dest: Reg, cond: Cond, left: Value, right: Value, width: Width },
}

/// What an instruction computes, named the same way on every architecture.
///
/// Spellings that compute one thing share a variant: `add`, `adds`, `addu`
/// and `addiu` are all [`Op::Add`], and `ldr` and `lw` are both
/// [`Op::Load`]. What sets them apart stays elsewhere: the flags an `adds`
/// writes are in [`Lifted::writes`], and the width of a load is in
/// [`Lifted::memory`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Op {
    /// Copies a value, or puts a constant in a register.
    Move,
    /// Forms an address from the program counter, as `adrp` and `lui` do.
    Address,
    Add,
    Subtract,
    Multiply,
    /// A multiply with an add or subtract, as `madd` and `mla` do.
    MultiplyAdd,
    Divide,
    And,
    Or,
    Xor,
    /// `left & !right`, as `bic` does.
    AndNot,
    /// `left | !right`, as `orn` does.
    OrNot,
    Not,
    Negate,
    ShiftLeft,
    ShiftRight,
    ShiftRightArithmetic,
    Rotate,
    /// Widens a value with its sign or with zeros, as `sxtb` and `seb` do.
    Extend,
    /// Reads or writes a field of bits, as `ubfx`, `bfi` and `ext` do.
    BitField,
    /// Counts or reverses bits or bytes, as `clz`, `rbit` and `rev` do.
    Bits,
    /// Picks one of two values on a condition, as `csel` and `movn` do.
    Select,
    Load,
    Store,
    /// One step of an atomic sequence: an access that loads and stores in
    /// one, as a swap or add does, or an exclusive load or store, as
    /// `ldxr` and `strex` are.
    Atomic,
    /// Sets the flags from a comparison, or sets a register as `slt` does.
    Compare,
    Branch,
    Jump,
    Call,
    Return,
    FloatAdd,
    FloatSubtract,
    FloatMultiply,
    /// A multiply with an add or subtract, as `fmadd` and `vmla` do.
    FloatMultiplyAdd,
    FloatDivide,
    /// Negates or takes the magnitude, as `fneg` and `fabs` do.
    FloatSign,
    FloatSquareRoot,
    /// Converts between sizes, or to or from an integer, with the rounding
    /// the conversion implies.
    FloatConvert,
    /// Rounds down, as `floor` does: `frintm` and `floor.w.d`.
    FloatRoundDown,
    /// Rounds up, as `ceil` does: `frintp` and `ceil.w.d`.
    FloatRoundUp,
    /// Rounds to the nearest, or as the status register says.
    FloatRoundNearest,
    /// Rounds toward zero, as `trunc` does.
    FloatRoundTowardZero,
    /// The lesser or greater of two values.
    FloatMinMax,
    /// Other floating point work, as a compare.
    Float,
    /// Vector arithmetic.
    Vector,
    /// Talks to the system, as a barrier, a system call or a hint does.
    System,
    /// Anything the lifter does not name.
    #[default]
    Other,
}

impl Op {
    /// The name normalizing gives this operation.
    pub fn name(self) -> &'static str {
        match self {
            Self::Move => "move",
            Self::Address => "address",
            Self::Add => "add",
            Self::Subtract => "subtract",
            Self::Multiply => "multiply",
            Self::MultiplyAdd => "multiply-add",
            Self::Divide => "divide",
            Self::And => "and",
            Self::Or => "or",
            Self::Xor => "xor",
            Self::AndNot => "and-not",
            Self::OrNot => "or-not",
            Self::Not => "not",
            Self::Negate => "negate",
            Self::ShiftLeft => "shift-left",
            Self::ShiftRight => "shift-right",
            Self::ShiftRightArithmetic => "shift-right-arithmetic",
            Self::Rotate => "rotate",
            Self::Extend => "extend",
            Self::BitField => "bit-field",
            Self::Bits => "bits",
            Self::Select => "select",
            Self::Load => "load",
            Self::Store => "store",
            Self::Atomic => "atomic",
            Self::Compare => "compare",
            Self::Branch => "branch",
            Self::Jump => "jump",
            Self::Call => "call",
            Self::Return => "return",
            Self::FloatAdd => "float-add",
            Self::FloatSubtract => "float-subtract",
            Self::FloatMultiply => "float-multiply",
            Self::FloatMultiplyAdd => "float-multiply-add",
            Self::FloatDivide => "float-divide",
            Self::FloatSign => "float-sign",
            Self::FloatSquareRoot => "float-square-root",
            Self::FloatConvert => "float-convert",
            Self::FloatRoundDown => "float-round-down",
            Self::FloatRoundUp => "float-round-up",
            Self::FloatRoundNearest => "float-round-nearest",
            Self::FloatRoundTowardZero => "float-round-toward-zero",
            Self::FloatMinMax => "float-min-max",
            Self::Float => "float",
            Self::Vector => "vector",
            Self::System => "system",
            Self::Other => "other",
        }
    }
}

/// An operand, as the instruction names it.
///
/// The decoders print operands as text, and text is a poor source of their
/// kind: a comma splits `[sp, #8]` and `{r4, lr}` apart, and each
/// architecture spells a frame slot its own way. This says the kind once,
/// from the decoded fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Operand {
    Reg(Reg),
    /// A register that always reads as zero, as `xzr` and the MIPS `zero`.
    Zero,
    /// A constant, with a negative one in two's complement.
    Const(u64),
    /// A memory reference, through `base` plus `offset`. A base the IL does
    /// not name, as the program counter, is `None`, and so is an offset in a
    /// register.
    Memory {
        base: Option<Reg>,
        offset: Option<i64>,
    },
    /// A branch or address target, without the address, which moves.
    Target,
    /// A list of registers, as `push` and `ldm` take.
    RegisterList,
    /// Anything else, as a condition or a system register.
    Other,
}

/// Operands held without a heap allocation. An instruction names four at
/// most, bar a few rare forms, which spill to the heap and still work.
pub type Operands = SmallVec<[Operand; 4]>;

/// One instruction, lifted.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Lifted {
    pub op: Op,
    pub reads: RegSet,
    pub writes: RegSet,
    pub memory: Option<MemoryAccess>,
    pub test: Option<Test>,
    /// The operands, in the order the decoder prints them.
    pub operands: Operands,
}

impl Lifted {
    /// This instruction, with an idiom read as the plain operation it
    /// computes. Compilers pick between spellings of one result freely:
    /// `eor r0, r0, r0` and `mov r0, #0` both clear `r0`, and
    /// `addu v0, a0, zero` is the MIPS `move`.
    pub fn canonical(mut self) -> Self {
        use Operand::{Const, Zero};
        let is_zero = |operand: &Operand| matches!(operand, Zero | Const(0));
        let rewritten: Option<(Op, Operands)> = match (self.op, self.operands.as_slice()) {
            // A register less or exclusive-or itself is zero.
            (Op::Xor | Op::Subtract, [dest, Operand::Reg(left), Operand::Reg(right)])
                if left == right =>
            {
                Some((Op::Move, [*dest, Const(0)].into_iter().collect()))
            }
            (Op::Add | Op::Or | Op::Xor, [dest, value, zero])
            | (Op::Add | Op::Or | Op::Xor, [dest, zero, value])
                if is_zero(zero) =>
            {
                Some((Op::Move, [*dest, *value].into_iter().collect()))
            }
            (Op::Subtract, [dest, zero, value]) if is_zero(zero) => {
                Some((Op::Negate, [*dest, *value].into_iter().collect()))
            }
            _ => None,
        };
        if let Some((op, operands)) = rewritten {
            self.op = op;
            self.operands = operands;
        }
        self
    }
}

/// The data-flow features of `body`, one an instruction, sorted.
///
/// Ghidra's BSim knows an operation by what feeds it, not by its spelling:
/// it hashes each value with the operation that defines it and the values
/// that operation reads. This does the same over a straight walk of the
/// lifted body, to `depth` rounds: at 1, a feature is an operation with the
/// operations that wrote its inputs; at 2, with their features in turn.
/// The register a value sits in never counts, so a change of register
/// allocation changes no feature. The inputs of a commutative operation
/// hash in no order, and a constant counts by its size, never its value.
/// A value read before anything in the body writes it is an argument, and
/// one read after a call is the call's result.
///
/// BSim also looks through copies and spills. Measured over the cross
/// builds, neither helped here: the copies and spills a compiler adds are
/// already frame work that normalizing drops, or show in both builds.
pub fn flow_features(body: &[Option<Lifted>], depth: usize) -> Vec<u64> {
    let mut flow = Flow::default();
    let mut features: Vec<u64> =
        body.iter().flatten().map(|lifted| flow.step(lifted, depth)).collect();
    features.sort_unstable();
    features
}

/// What a walk for [`flow_features`] knows at one point.
#[derive(Default)]
struct Flow {
    /// For each register, the labels of the value it holds, by round: the
    /// first, the defining operation alone.
    values: Vec<(Reg, [u64; FLOW_ROUNDS])>,
    /// The label of a value nothing in the body wrote.
    unknown: Option<[u64; FLOW_ROUNDS]>,
}

/// The most rounds [`flow_features`] runs.
const FLOW_ROUNDS: usize = 3;

/// Labels for the leaves of the data flow.
const ARGUMENT: u64 = 0x4152_4755_4d45_4e54;
const CALL_RESULT: u64 = 0x4341_4c4c_5245_5355;
const ZERO: u64 = 0x5a45_524f;
const MEMORY: u64 = 0x4d45_4d4f_5259;

impl Flow {
    fn label_of(&self, reg: Reg) -> [u64; FLOW_ROUNDS] {
        self.values
            .iter()
            .find(|(held, _)| *held == reg)
            .map(|(_, label)| *label)
            .unwrap_or(self.unknown.unwrap_or([ARGUMENT; FLOW_ROUNDS]))
    }

    fn set(&mut self, reg: Reg, label: [u64; FLOW_ROUNDS]) {
        match self.values.iter_mut().find(|(held, _)| *held == reg) {
            Some((_, held)) => *held = label,
            None => self.values.push((reg, label)),
        }
    }

    /// Walk one instruction, and give its feature.
    fn step(&mut self, lifted: &Lifted, depth: usize) -> u64 {
        let depth = depth.clamp(1, FLOW_ROUNDS - 1);
        let width = lifted.memory.and_then(|access| access.width).map_or(0, Width::bits);
        let tag = mix(lifted.op as u64 + 1, u64::from(width));

        let mut inputs: Vec<[u64; FLOW_ROUNDS]> = Vec::new();
        for (index, operand) in lifted.operands.iter().enumerate() {
            let input = match *operand {
                // The first operand of an operation that writes it, and does
                // not read it, is its result, not an input.
                Operand::Reg(reg)
                    if index == 0 && lifted.writes.contains(reg) && !lifted.reads.contains(reg) =>
                {
                    continue;
                }
                Operand::Reg(reg) => self.label_of(reg),
                Operand::Zero => [ZERO; FLOW_ROUNDS],
                Operand::Const(value) => [constant_label(value); FLOW_ROUNDS],
                Operand::Memory { base, .. } => base
                    .map_or([MEMORY; FLOW_ROUNDS], |base| self.label_of(base))
                    .map(|label| mix(MEMORY, label)),
                Operand::Target | Operand::RegisterList | Operand::Other => continue,
            };
            inputs.push(input);
        }
        // The flags a compare wrote feed the branch that reads them.
        if lifted.reads.contains(Reg::Flags) {
            inputs.push(self.label_of(Reg::Flags));
        }

        let commutative = matches!(lifted.op, Op::Add | Op::Multiply | Op::And | Op::Or | Op::Xor);
        // Round `n` of this instruction reads round `n - 1` of its inputs.
        let mut label = [tag; FLOW_ROUNDS];
        for round in 1..FLOW_ROUNDS {
            let mut previous: Vec<u64> = inputs.iter().map(|input| input[round - 1]).collect();
            if commutative {
                previous.sort_unstable();
            }
            label[round] = previous.into_iter().fold(tag, mix);
        }

        if lifted.op == Op::Call {
            // A call may change any register; what it leaves is its result.
            // Measured, this paired 9 more right over the cross builds.
            self.values.clear();
            self.unknown = Some([CALL_RESULT; FLOW_ROUNDS]);
        }
        for reg in lifted.writes.iter() {
            self.set(reg, label);
        }
        label[depth]
    }
}

/// The label of a constant, by its size.
fn constant_label(value: u64) -> u64 {
    match value {
        0 => ZERO,
        1..=0xff => 0x534d_414c_4c,
        _ => 0x4c41_5247_45,
    }
}

/// Mix two hashes into one, as `splitmix64` finishes a value.
fn mix(left: u64, right: u64) -> u64 {
    let mut value = left.rotate_left(5) ^ right.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
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
    // A branch that a compare before it took is no guard of its own.
    let mut taken = Vec::new();
    for (index, lifted) in body.iter().enumerate() {
        let after = &body[index + 1..];
        let fused = match lifted.as_ref().and_then(|lifted| lifted.test) {
            Some(Test::Guard(guard)) if !taken.contains(&index) => {
                found.push(FoundGuard { compare: None, branch: index, guard });
                continue;
            }
            Some(Test::Compare { comparison, width }) => branch_on_flags(after)
                .and_then(|(branch, cond)| Some((branch, guard_of(comparison, cond, width)?))),
            Some(Test::SetOnCompare { dest, cond, left, right, width }) => {
                branch_on_register(after, dest).map(|(branch, holds)| {
                    let cond = if holds { cond } else { cond.opposite() };
                    (branch, Guard { cond, left, right, width })
                })
            }
            Some(Test::Guard(_) | Test::OnFlags(_)) | None => None,
        };
        if let Some((branch, guard)) = fused {
            let branch = index + 1 + branch;
            taken.push(branch);
            found.push(FoundGuard { compare: Some(index), branch, guard });
        }
    }
    found
}

/// The first branch in `after` on whether `dest` is zero, by its index and
/// whether it branches where `dest` holds 1. Only work that leaves `dest`
/// alone may come before it.
fn branch_on_register(after: &[Option<Lifted>], dest: Reg) -> Option<(usize, bool)> {
    for (index, lifted) in after.iter().take(MOST_BETWEEN + 1).enumerate() {
        let lifted = lifted.as_ref()?;
        if let Some(Test::Guard(guard)) = lifted.test {
            if guard.left != Value::Reg(dest) || guard.right != Value::Const(0) {
                return None;
            }
            return match guard.cond {
                Cond::NotEqual => Some((index, true)),
                Cond::Equal => Some((index, false)),
                _ => None,
            };
        }
        if lifted.test.is_some() || lifted.writes.contains(dest) {
            return None;
        }
    }
    None
}

/// The first branch on the flags in `after`, by its index and condition,
/// where only work that leaves the flags alone comes before it.
fn branch_on_flags(after: &[Option<Lifted>]) -> Option<(usize, Cond)> {
    for (index, lifted) in after.iter().take(MOST_BETWEEN + 1).enumerate() {
        let lifted = lifted.as_ref()?;
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

    fn set_on_less(dest: u8) -> Option<Lifted> {
        Some(Lifted {
            writes: [Reg::General(dest)].into_iter().collect(),
            test: Some(Test::SetOnCompare {
                dest: Reg::General(dest),
                cond: Cond::SignedLess,
                left: Value::Reg(Reg::General(4)),
                right: Value::Reg(Reg::General(5)),
                width: Width::Bits32,
            }),
            ..Lifted::default()
        })
    }

    fn branch_on(reg: u8, cond: Cond) -> Option<Lifted> {
        Some(Lifted {
            test: Some(Test::Guard(Guard {
                cond,
                left: Value::Reg(Reg::General(reg)),
                right: Value::Const(0),
                width: Width::Bits32,
            })),
            ..Lifted::default()
        })
    }

    /// `slt t0, a0, a1` with `bnez t0` branches where `a0 < a1`, and with
    /// `beqz t0` where not.
    #[test]
    fn a_set_on_less_and_its_branch_are_one_guard() {
        let found = find_guards(&[set_on_less(8), work(), branch_on(8, Cond::NotEqual)]);
        assert_eq!(found.len(), 1, "the branch is no guard of its own");
        assert_eq!((found[0].compare, found[0].branch), (Some(0), 2));
        assert_eq!(found[0].guard.cond, Cond::SignedLess);
        assert_eq!(found[0].guard.left, Value::Reg(Reg::General(4)));

        let found = find_guards(&[set_on_less(8), branch_on(8, Cond::Equal)]);
        assert_eq!(found[0].guard.cond, Cond::SignedGreaterOrEqual);
    }

    #[test]
    fn a_branch_on_another_register_or_a_rewrite_is_no_fusion() {
        let other = find_guards(&[set_on_less(8), branch_on(9, Cond::NotEqual)]);
        assert_eq!(other.iter().map(|found| found.compare).collect::<Vec<_>>(), [None]);

        let rewrite =
            Some(Lifted { writes: [Reg::General(8)].into_iter().collect(), ..Lifted::default() });
        let rewritten = find_guards(&[set_on_less(8), rewrite, branch_on(8, Cond::NotEqual)]);
        assert_eq!(rewritten.iter().map(|found| found.compare).collect::<Vec<_>>(), [None]);
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
        assert_eq!(guards(&[tst.clone(), branch(Cond::Equal)]), [(Some(0), 1, Cond::BitsClear)]);
        assert_eq!(guards(&[tst, branch(Cond::SignedLess)]), [], "no bit test");
    }

    #[test]
    fn nothing_lifted_is_no_guard() {
        assert_eq!(guards(&[]), []);
        assert_eq!(guards(&[None, branch(Cond::Equal)]), []);
        assert_eq!(guards(&[branch(Cond::Equal)]), [], "a branch alone");
    }

    #[test]
    fn a_condition_and_its_opposite_are_one_either_way() {
        for code in 0..14_u8 {
            let cond = Cond::from_arm(code);
            assert_eq!(cond.opposite(), Cond::from_arm(code ^ 1), "ARM pairs opposites");
            assert_eq!(cond.opposite().opposite(), cond);
            assert_eq!(cond.either_way(), cond.opposite().either_way());
        }
        assert_ne!(
            Cond::SignedGreater.either_way(),
            Cond::SignedLess.either_way(),
            "max is no min"
        );
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

    fn computes(op: Op, operands: &[Operand]) -> Lifted {
        Lifted { op, operands: operands.iter().copied().collect(), ..Lifted::default() }
    }

    fn canonical(op: Op, operands: &[Operand]) -> (Op, Vec<Operand>) {
        let lifted = computes(op, operands).canonical();
        (lifted.op, lifted.operands.into_vec())
    }

    const R0: Operand = Operand::Reg(Reg::General(0));
    const R1: Operand = Operand::Reg(Reg::General(1));
    const R2: Operand = Operand::Reg(Reg::General(2));

    #[test]
    fn a_register_less_or_exclusive_or_itself_is_zero() {
        let zero = (Op::Move, vec![R0, Operand::Const(0)]);
        assert_eq!(canonical(Op::Xor, &[R0, R1, R1]), zero, "eor r0, r1, r1");
        assert_eq!(canonical(Op::Subtract, &[R0, R1, R1]), zero, "subu v0, a1, a1");
        assert_eq!(canonical(Op::Xor, &[R0, R1, R2]), (Op::Xor, vec![R0, R1, R2]));
    }

    #[test]
    fn adding_zero_is_a_copy() {
        let copy = (Op::Move, vec![R0, R1]);
        assert_eq!(canonical(Op::Add, &[R0, R1, Operand::Zero]), copy, "addu v0, a1, zero");
        assert_eq!(canonical(Op::Or, &[R0, Operand::Zero, R1]), copy, "orr x0, xzr, x1");
        assert_eq!(canonical(Op::Add, &[R0, R1, Operand::Const(0)]), copy, "add x0, x1, #0");
        assert_eq!(canonical(Op::Add, &[R0, R1, Operand::Const(1)]).0, Op::Add);
    }

    #[test]
    fn subtracting_from_zero_is_a_negate() {
        let negate = (Op::Negate, vec![R0, R1]);
        assert_eq!(canonical(Op::Subtract, &[R0, Operand::Zero, R1]), negate, "sub x0, xzr, x1");
        let less_zero = [R0, R1, Operand::Zero];
        assert_eq!(canonical(Op::Subtract, &less_zero), (Op::Subtract, less_zero.to_vec()));
    }

    /// Over every operation and every three operands from a small set,
    /// the rewrite is done in one step and touches only the operation and
    /// its operands.
    #[test]
    fn the_canonical_form_is_reached_in_one_step() {
        const OPS: [Op; 6] = [Op::Add, Op::Subtract, Op::Or, Op::Xor, Op::And, Op::Move];
        let choices = [R0, R1, Operand::Zero, Operand::Const(0), Operand::Const(7)];
        for op in OPS {
            for a in choices {
                for b in choices {
                    for c in choices {
                        let lifted = Lifted {
                            writes: [Reg::Flags].into_iter().collect(),
                            ..computes(op, &[a, b, c])
                        };
                        let once = lifted.clone().canonical();
                        assert_eq!(once.clone().canonical(), once, "{op:?} {a:?} {b:?} {c:?}");
                        assert_eq!((once.reads, once.writes), (lifted.reads, lifted.writes));
                        assert_eq!((once.memory, once.test), (lifted.memory, lifted.test));
                    }
                }
            }
        }
    }

    /// An instruction that writes `dest` from `sources` by `op`.
    fn computes_into(op: Op, dest: u8, sources: &[Operand]) -> Option<Lifted> {
        let reads = sources
            .iter()
            .filter_map(|source| match source {
                Operand::Reg(reg) => Some(*reg),
                _ => None,
            })
            .collect();
        Some(Lifted {
            op,
            reads,
            writes: [Reg::General(dest)].into_iter().collect(),
            operands: [Operand::Reg(Reg::General(dest))]
                .into_iter()
                .chain(sources.iter().copied())
                .collect(),
            ..Lifted::default()
        })
    }

    fn r(number: u8) -> Operand {
        Operand::Reg(Reg::General(number))
    }

    /// `r2 = load; r3 = r2 + 1; r4 = r3 * r2`, in registers `base` up.
    fn sample(base: u8) -> Vec<Option<Lifted>> {
        let load = Some(Lifted {
            op: Op::Load,
            reads: [Reg::General(base)].into_iter().collect(),
            writes: [Reg::General(base + 2)].into_iter().collect(),
            memory: Some(MemoryAccess { kind: AccessKind::Load, width: Some(Width::Bits32) }),
            operands: [
                r(base + 2),
                Operand::Memory { base: Some(Reg::General(base)), offset: Some(8) },
            ]
            .into_iter()
            .collect(),
            ..Lifted::default()
        });
        vec![
            load,
            computes_into(Op::Add, base + 3, &[r(base + 2), Operand::Const(1)]),
            computes_into(Op::Multiply, base + 4, &[r(base + 3), r(base + 2)]),
        ]
    }

    #[test]
    fn the_registers_chosen_change_no_flow_feature() {
        for depth in [1, 2] {
            assert_eq!(flow_features(&sample(0), depth), flow_features(&sample(10), depth));
        }
    }

    #[test]
    fn a_commutative_operation_reads_its_inputs_in_no_order() {
        let mut swapped = sample(0);
        swapped[2] = computes_into(Op::Multiply, 4, &[r(2), r(3)]);
        assert_eq!(flow_features(&sample(0), 2), flow_features(&swapped, 2));
        // A subtract keeps its order.
        let mut less = sample(0);
        less[2] = computes_into(Op::Subtract, 4, &[r(3), r(2)]);
        let mut reversed = sample(0);
        reversed[2] = computes_into(Op::Subtract, 4, &[r(2), r(3)]);
        assert_ne!(flow_features(&less, 2), flow_features(&reversed, 2));
    }

    /// An operation is known by what defines its inputs, so one spelling
    /// over another source is another feature.
    #[test]
    fn what_defines_an_input_is_part_of_the_feature() {
        let mut moved = sample(0);
        moved[0] = computes_into(Op::Move, 2, &[Operand::Const(0x1000)]);
        let (loaded, constant) = (flow_features(&sample(0), 1), flow_features(&moved, 1));
        assert_eq!(loaded.len(), constant.len());
        assert_ne!(loaded, constant);
    }

    /// After a call, a register holds what the call left, not what was
    /// written before it.
    #[test]
    fn a_call_ends_what_registers_held() {
        let call = Some(Lifted {
            op: Op::Call,
            operands: [Operand::Target].into_iter().collect(),
            ..Lifted::default()
        });
        let mut before = sample(0);
        before.insert(2, call.clone());
        let mut other = sample(0);
        other[0] = computes_into(Op::Move, 2, &[Operand::Const(0x1000)]);
        other.insert(2, call);
        // The multiply after the call reads `r2` and `r3` as call results,
        // whatever wrote them before.
        let last = |body: &[Option<Lifted>]| flow_features(&body[3..], 2);
        assert_eq!(last(&before), last(&other));
    }

    #[test]
    fn nothing_lifted_has_no_flow_feature() {
        assert!(flow_features(&[None, None], 2).is_empty());
        assert!(flow_features(&[], 2).is_empty());
    }
}
