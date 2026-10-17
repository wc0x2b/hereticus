//! The NEON data processing words of A32, and the moves between NEON and
//! core registers, which `yaxpeax-arm` 0.4 refuses. A wide T32 word reads
//! as its A32 twin: see `thumb::as_a32`.
//!
//! The encodings follow the Arm Architecture Reference Manual for ARMv7-A
//! and ARMv7-R: section A7.4, "Advanced SIMD data-processing instructions",
//! and section A7.8, the transfers between core and extension registers.
//!
//! The IL names a `d` register as [`il::Reg::Vector`] by its number, and a
//! `q` register as the two `d` registers it is. A lane is part of the text
//! alone, as on AArch64.

use crate as il;
use crate::arch::arm32::{ARM_REGISTERS, expand_float_constant, il_reg};
use compact_str::{CompactString, format_compact};
use yaxpeax_arm::armv7::Reg;

macro_rules! operations {
    ($($variant:ident => $name:literal,)*) => {
        /// A NEON operation, by the name the Arm manual gives it.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum NeonOperation {
            $(
                #[doc = concat!("`", $name, "`.")]
                $variant,
            )*
        }

        impl NeonOperation {
            /// The name, as `vadd`.
            pub fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)*
                }
            }
        }
    };
}

operations! {
    Vaba => "vaba",
    Vabal => "vabal",
    Vabd => "vabd",
    Vabdl => "vabdl",
    Vabs => "vabs",
    Vacge => "vacge",
    Vacgt => "vacgt",
    Vadd => "vadd",
    Vaddhn => "vaddhn",
    Vaddl => "vaddl",
    Vaddw => "vaddw",
    Vand => "vand",
    Vbic => "vbic",
    Vbif => "vbif",
    Vbit => "vbit",
    Vbsl => "vbsl",
    Vceq => "vceq",
    Vcge => "vcge",
    Vcgt => "vcgt",
    Vcle => "vcle",
    Vcls => "vcls",
    Vclt => "vclt",
    Vclz => "vclz",
    Vcnt => "vcnt",
    Vcvt => "vcvt",
    Vdup => "vdup",
    Veor => "veor",
    Vext => "vext",
    Vfma => "vfma",
    Vfms => "vfms",
    Vhadd => "vhadd",
    Vhsub => "vhsub",
    Vmax => "vmax",
    Vmin => "vmin",
    Vmla => "vmla",
    Vmlal => "vmlal",
    Vmls => "vmls",
    Vmlsl => "vmlsl",
    Vmov => "vmov",
    Vmovl => "vmovl",
    Vmovn => "vmovn",
    Vmul => "vmul",
    Vmull => "vmull",
    Vmvn => "vmvn",
    Vneg => "vneg",
    Vorn => "vorn",
    Vorr => "vorr",
    Vpadal => "vpadal",
    Vpadd => "vpadd",
    Vpaddl => "vpaddl",
    Vpmax => "vpmax",
    Vpmin => "vpmin",
    Vqabs => "vqabs",
    Vqadd => "vqadd",
    Vqdmlal => "vqdmlal",
    Vqdmlsl => "vqdmlsl",
    Vqdmulh => "vqdmulh",
    Vqdmull => "vqdmull",
    Vqmovn => "vqmovn",
    Vqmovun => "vqmovun",
    Vqneg => "vqneg",
    Vqrdmulh => "vqrdmulh",
    Vqrshl => "vqrshl",
    Vqrshrn => "vqrshrn",
    Vqrshrun => "vqrshrun",
    Vqshl => "vqshl",
    Vqshlu => "vqshlu",
    Vqshrn => "vqshrn",
    Vqshrun => "vqshrun",
    Vqsub => "vqsub",
    Vraddhn => "vraddhn",
    Vrecpe => "vrecpe",
    Vrecps => "vrecps",
    Vrev16 => "vrev16",
    Vrev32 => "vrev32",
    Vrev64 => "vrev64",
    Vrhadd => "vrhadd",
    Vrshl => "vrshl",
    Vrshr => "vrshr",
    Vrshrn => "vrshrn",
    Vrsqrte => "vrsqrte",
    Vrsqrts => "vrsqrts",
    Vrsra => "vrsra",
    Vrsubhn => "vrsubhn",
    Vshl => "vshl",
    Vshll => "vshll",
    Vshr => "vshr",
    Vshrn => "vshrn",
    Vsli => "vsli",
    Vsra => "vsra",
    Vsri => "vsri",
    Vsub => "vsub",
    Vsubhn => "vsubhn",
    Vsubl => "vsubl",
    Vsubw => "vsubw",
    Vswp => "vswp",
    Vtbl => "vtbl",
    Vtbx => "vtbx",
    Vtrn => "vtrn",
    Vtst => "vtst",
    Vuzp => "vuzp",
    Vzip => "vzip",
}

/// What [`crate::arch::arm32::Decoded::Neon`] holds: the operation, and the
/// type of its elements as its name prints it, as the `i32` of `vadd.i32`.
/// A conversion names both types, as `f32.s32`. Some operations name none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Neon {
    /// The operation.
    pub operation: NeonOperation,
    /// The type of the elements, or empty.
    pub element: &'static str,
}

impl Neon {
    /// The name, with the type of the elements where it names one, as
    /// `vadd.i32`.
    pub fn name(self) -> CompactString {
        if self.element.is_empty() {
            self.operation.name().into()
        } else {
            format_compact!("{}.{}", self.operation.name(), self.element)
        }
    }
}

const SIGNED: [&str; 4] = ["s8", "s16", "s32", "s64"];
const UNSIGNED: [&str; 4] = ["u8", "u16", "u32", "u64"];
const INTEGER: [&str; 4] = ["i8", "i16", "i32", "i64"];
const UNTYPED: [&str; 4] = ["8", "16", "32", "64"];

/// The type of `table` for a `size` field, where the field names one.
fn element(table: [&'static str; 4], size: u32) -> Option<&'static str> {
    table.get(size as usize).copied()
}

/// The signed or unsigned type for a `size` field, as `U` says.
fn typed(unsigned: bool, size: u32) -> Option<&'static str> {
    element(if unsigned { UNSIGNED } else { SIGNED }, size)
}

/// One operand of a NEON word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Value {
    /// A 64-bit register, `d0` to `d31`.
    Double(u32),
    /// A 128-bit register, `q0` to `q15`: two `d` registers.
    Quad(u32),
    /// One lane of a `d` register, as `d0[1]`.
    Scalar { double: u32, lane: u32 },
    /// A core register.
    Core(u32),
    /// An integer constant, as a shift amount or an immediate.
    Constant(u64),
    /// The bits of an `f32` constant.
    Float(u32),
    /// The table of `vtbl`: `count` `d` registers from `first`.
    Table { first: u32, count: u32 },
}

impl Value {
    /// The register `number` of the register fields names: a `q` register
    /// where `quad`, which needs an even number, else a `d` register.
    fn vector(number: u32, quad: Quad) -> Option<Self> {
        match quad {
            Quad::Yes => number.is_multiple_of(2).then_some(Self::Quad(number / 2)),
            Quad::No => Some(Self::Double(number)),
        }
    }

    fn text(self) -> CompactString {
        match self {
            Self::Double(number) => format_compact!("d{number}"),
            Self::Quad(number) => format_compact!("q{number}"),
            Self::Scalar { double, lane } => format_compact!("d{double}[{lane}]"),
            Self::Core(number) => ARM_REGISTERS[number as usize].into(),
            Self::Constant(value) => format_compact!("{value:#x}"),
            Self::Float(bits) => format_compact!("#{:?}", f64::from(f32::from_bits(bits))),
            Self::Table { first, count } => {
                let list: Vec<CompactString> =
                    (first..first + count).map(|number| format_compact!("d{number}")).collect();
                format_compact!("{{{}}}", list.join(", "))
            }
        }
    }

    /// The registers this operand names.
    fn registers(self) -> il::RegSet {
        let vector = |number: u32| il::Reg::Vector(number as u8);
        match self {
            Self::Double(number) | Self::Scalar { double: number, .. } => {
                [vector(number)].into_iter().collect()
            }
            Self::Quad(number) => {
                [vector(number * 2), vector(number * 2 + 1)].into_iter().collect()
            }
            Self::Core(number) => il_reg(Reg::from_u8(number as u8)).into_iter().collect(),
            Self::Table { first, count } => (first..first + count).map(vector).collect(),
            Self::Constant(_) | Self::Float(_) => il::RegSet::EMPTY,
        }
    }

    fn operand(self) -> il::Operand {
        match self {
            Self::Double(number) | Self::Scalar { double: number, .. } => {
                il::Operand::Reg(il::Reg::Vector(number as u8))
            }
            Self::Quad(number) => il::Operand::Reg(il::Reg::Vector((number * 2) as u8)),
            Self::Core(number) => {
                il_reg(Reg::from_u8(number as u8)).map_or(il::Operand::Other, il::Operand::Reg)
            }
            Self::Constant(value) => il::Operand::Const(value),
            Self::Float(bits) => il::Operand::Const(u64::from(bits)),
            Self::Table { .. } => il::Operand::RegisterList(self.registers()),
        }
    }
}

/// Whether a NEON word works on `q` registers, as its `Q` bit says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Quad {
    Yes,
    No,
}

impl Quad {
    fn of(set: bool) -> Self {
        if set { Self::Yes } else { Self::No }
    }
}

/// What a NEON word does with its first operands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// Writes the first from the others.
    Writes,
    /// Reads and writes the first, as `vmla` adds to it and `vbsl` selects
    /// into it.
    Accumulates,
    /// Reads and writes the first two, as `vswp` swaps them.
    Exchanges,
}

/// A NEON word this module reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NeonWord {
    neon: Neon,
    role: Role,
    operands: Vec<Value>,
}

/// The fields of a word.
#[derive(Clone, Copy)]
struct Fields(u32);

impl Fields {
    fn get(self, shift: u32, width: u32) -> u32 {
        self.0 >> shift & ((1 << width) - 1)
    }

    fn flag(self, shift: u32) -> bool {
        self.get(shift, 1) == 1
    }

    /// `U`, which says unsigned for most words.
    fn unsigned(self) -> bool {
        self.flag(24)
    }

    fn quad(self) -> Quad {
        Quad::of(self.flag(6))
    }

    fn size(self) -> u32 {
        self.get(20, 2)
    }

    /// The destination register: `D:Vd`.
    fn d(self) -> u32 {
        self.get(22, 1) << 4 | self.get(12, 4)
    }

    /// The first source register: `N:Vn`.
    fn n(self) -> u32 {
        self.get(7, 1) << 4 | self.get(16, 4)
    }

    /// The second source register: `M:Vm`.
    fn m(self) -> u32 {
        self.get(5, 1) << 4 | self.get(0, 4)
    }
}

impl NeonWord {
    fn new(
        operation: NeonOperation,
        element: &'static str,
        role: Role,
        operands: &[Value],
    ) -> Self {
        Self { neon: Neon { operation, element }, role, operands: operands.to_vec() }
    }

    /// Read `word`, an A32 word or the A32 twin of a T32 word.
    pub(crate) fn of(word: u32) -> Option<Self> {
        let fields = Fields(word);
        if word >> 25 == 0b111_1001 {
            return data_processing(fields);
        }
        if word >> 28 != 0b1111 {
            return transfer(fields);
        }
        None
    }

    /// What [`crate::arch::arm32::Decoded::Neon`] holds for this word.
    pub(crate) fn neon(&self) -> Neon {
        self.neon
    }

    /// The name and the operands, as the decoder prints them.
    pub(crate) fn text(&self) -> (String, String) {
        let operands: Vec<CompactString> = self.operands.iter().map(|value| value.text()).collect();
        (self.neon.name().into(), operands.join(", "))
    }

    /// The name of each operand of [`NeonWord::lift`].
    pub(crate) fn names(&self) -> il::Names {
        self.operands.iter().map(|value| value.text()).collect()
    }

    /// The IL form of this word. A `vmov` moves, and the rest is
    /// [`il::Op::Vector`].
    pub(crate) fn lift(&self) -> il::Lifted {
        let mut lifted = il::Lifted {
            op: match self.neon.operation {
                NeonOperation::Vmov => il::Op::Move,
                _ => il::Op::Vector,
            },
            operands: self.operands.iter().map(|value| value.operand()).collect(),
            ..il::Lifted::default()
        };
        let (written, read_too) = match self.role {
            Role::Writes => (1, false),
            Role::Accumulates => (1, true),
            Role::Exchanges => (2, true),
        };
        for (index, value) in self.operands.iter().enumerate() {
            let registers = value.registers();
            if index < written {
                registers.iter().for_each(|reg| lifted.writes.insert(reg));
                if read_too {
                    registers.iter().for_each(|reg| lifted.reads.insert(reg));
                }
            } else {
                registers.iter().for_each(|reg| lifted.reads.insert(reg));
            }
        }
        lifted
    }
}

/// `1111 001U A B C`: section A7.4 of the manual sorts the words by `A`,
/// bits 23 to 19, `B`, bits 11 to 8, and `C`, bits 7 to 4.
fn data_processing(fields: Fields) -> Option<NeonWord> {
    let a = fields.get(19, 5);
    let c = fields.get(4, 4);
    if a >> 4 == 0 {
        return same_length(fields);
    }
    if c & 0b0001 == 1 {
        if a & 0b10111 == 0b10000 && c >> 3 == 0 {
            return modified_immediate(fields);
        }
        return shift(fields);
    }
    if fields.size() != 0b11 {
        return if c & 0b0100 == 0 { different_lengths(fields) } else { scalar(fields) };
    }
    if !fields.unsigned() {
        return extract(fields);
    }
    match fields.get(8, 4) {
        0b0000..=0b0111 => miscellaneous(fields),
        0b1000..=0b1011 => table(fields),
        0b1100 if c >> 3 == 0 => duplicate_scalar(fields),
        _ => None,
    }
}

/// Three registers of the same length: section A7.4.1.
fn same_length(fields: Fields) -> Option<NeonWord> {
    use NeonOperation as Op;
    use Role::{Accumulates, Writes};
    let (unsigned, quad, size) = (fields.unsigned(), fields.quad(), fields.size());
    let b = fields.flag(4);
    let a = fields.get(8, 4);
    let d = Value::vector(fields.d(), quad)?;
    let n = Value::vector(fields.n(), quad)?;
    let m = Value::vector(fields.m(), quad)?;
    // `A` 0b1100 and up work on floats: bit 21 picks the operation, and
    // bit 20 the size, where only `f32` is ARMv7.
    let high = fields.flag(21);
    if a >= 0b1100 && fields.flag(20) {
        return None;
    }
    let typed = typed(unsigned, size)?;
    let integer = element(INTEGER, size)?;
    let float = "f32";
    let (operation, element, role) = match (a, b, unsigned) {
        (0b0000, false, _) => (Op::Vhadd, typed, Writes),
        (0b0000, true, _) => (Op::Vqadd, typed, Writes),
        (0b0001, false, _) => (Op::Vrhadd, typed, Writes),
        // The logic operations take `size` as part of the opcode.
        (0b0001, true, false) => match size {
            0b00 => (Op::Vand, "", Writes),
            0b01 => (Op::Vbic, "", Writes),
            0b10 => (Op::Vorr, "", Writes),
            _ => (Op::Vorn, "", Writes),
        },
        (0b0001, true, true) => match size {
            0b00 => (Op::Veor, "", Writes),
            0b01 => (Op::Vbsl, "", Accumulates),
            0b10 => (Op::Vbit, "", Accumulates),
            _ => (Op::Vbif, "", Accumulates),
        },
        (0b0010, false, _) => (Op::Vhsub, typed, Writes),
        (0b0010, true, _) => (Op::Vqsub, typed, Writes),
        (0b0011, false, _) => (Op::Vcgt, typed, Writes),
        (0b0011, true, _) => (Op::Vcge, typed, Writes),
        // A shift by register names the shifted value before the amounts.
        (0b0100 | 0b0101, _, _) => {
            let operation = match (a, b) {
                (0b0100, false) => Op::Vshl,
                (0b0100, true) => Op::Vqshl,
                (_, false) => Op::Vrshl,
                (_, true) => Op::Vqrshl,
            };
            return Some(NeonWord::new(operation, typed, Writes, &[d, m, n]));
        }
        (0b0110, false, _) => (Op::Vmax, typed, Writes),
        (0b0110, true, _) => (Op::Vmin, typed, Writes),
        (0b0111, false, _) => (Op::Vabd, typed, Writes),
        (0b0111, true, _) => (Op::Vaba, typed, Accumulates),
        (0b1000, false, false) => (Op::Vadd, integer, Writes),
        (0b1000, false, true) => (Op::Vsub, integer, Writes),
        (0b1000, true, false) => (Op::Vtst, element(UNTYPED, size)?, Writes),
        (0b1000, true, true) => (Op::Vceq, integer, Writes),
        (0b1001, false, false) => (Op::Vmla, integer, Accumulates),
        (0b1001, false, true) => (Op::Vmls, integer, Accumulates),
        (0b1001, true, false) => (Op::Vmul, integer, Writes),
        (0b1001, true, true) if size == 0 => (Op::Vmul, "p8", Writes),
        (0b1010, false, _) if quad == Quad::No => (Op::Vpmax, typed, Writes),
        (0b1010, true, _) if quad == Quad::No => (Op::Vpmin, typed, Writes),
        (0b1011, false, false) => (Op::Vqdmulh, element(SIGNED, size)?, Writes),
        (0b1011, false, true) => (Op::Vqrdmulh, element(SIGNED, size)?, Writes),
        (0b1011, true, false) if quad == Quad::No => (Op::Vpadd, integer, Writes),
        (0b1100, true, false) if high => (Op::Vfms, float, Accumulates),
        (0b1100, true, false) => (Op::Vfma, float, Accumulates),
        (0b1101, false, false) if high => (Op::Vsub, float, Writes),
        (0b1101, false, false) => (Op::Vadd, float, Writes),
        (0b1101, false, true) if high => (Op::Vabd, float, Writes),
        (0b1101, false, true) if quad == Quad::No => (Op::Vpadd, float, Writes),
        (0b1101, true, false) if high => (Op::Vmls, float, Accumulates),
        (0b1101, true, false) => (Op::Vmla, float, Accumulates),
        (0b1101, true, true) if !high => (Op::Vmul, float, Writes),
        (0b1110, false, false) if !high => (Op::Vceq, float, Writes),
        (0b1110, false, true) if high => (Op::Vcgt, float, Writes),
        (0b1110, false, true) => (Op::Vcge, float, Writes),
        (0b1110, true, true) if high => (Op::Vacgt, float, Writes),
        (0b1110, true, true) => (Op::Vacge, float, Writes),
        (0b1111, false, false) if high => (Op::Vmin, float, Writes),
        (0b1111, false, false) => (Op::Vmax, float, Writes),
        (0b1111, false, true) if quad == Quad::No && high => (Op::Vpmin, float, Writes),
        (0b1111, false, true) if quad == Quad::No => (Op::Vpmax, float, Writes),
        (0b1111, true, false) if high => (Op::Vrsqrts, float, Writes),
        (0b1111, true, false) => (Op::Vrecps, float, Writes),
        _ => return None,
    };
    // Of the integer operations, only these and the logic take 64-bit
    // elements.
    let takes_64 =
        matches!(operation, Op::Vqadd | Op::Vqsub | Op::Vadd | Op::Vsub) || element.is_empty();
    if a < 0b1100 && size == 0b11 && !takes_64 {
        return None;
    }
    Some(NeonWord::new(operation, element, role, &[d, n, m]))
}

/// One register and a modified immediate: section A7.4.6. The constant is
/// the element the instruction prints, as `AdvSIMDExpandImm` makes it
/// before it copies it into each element.
fn modified_immediate(fields: Fields) -> Option<NeonWord> {
    use NeonOperation as Op;
    let imm8 = u64::from(fields.get(24, 1) << 7 | fields.get(16, 3) << 4 | fields.get(0, 4));
    let (cmode, invert) = (fields.get(8, 4), fields.flag(5));
    let d = Value::vector(fields.d(), fields.quad())?;
    let (operation, element, value, role) = match (cmode, invert) {
        (0b1111, true) => return None,
        (0b1111, false) => {
            let bits = expand_float_constant(imm8 as u32, false) as u32;
            (Op::Vmov, "f32", Value::Float(bits), Role::Writes)
        }
        (0b1110, false) => (Op::Vmov, "i8", Value::Constant(imm8), Role::Writes),
        // Each bit of the constant fills one byte.
        (0b1110, true) => {
            let bytes = (0..8)
                .filter(|bit| imm8 >> bit & 1 == 1)
                .fold(0u64, |value, bit| value | 0xff << (bit * 8));
            (Op::Vmov, "i64", Value::Constant(bytes), Role::Writes)
        }
        _ => {
            let (element, value) = match cmode >> 1 {
                shift @ 0b000..=0b011 => ("i32", imm8 << (8 * shift)),
                shift @ 0b100..=0b101 => ("i16", imm8 << (8 * (shift & 1))),
                // Ones shift in from the right.
                _ if cmode & 1 == 0 => ("i32", imm8 << 8 | 0xff),
                _ => ("i32", imm8 << 16 | 0xffff),
            };
            // `cmode` 0b110x shifts ones in, and has no `vorr` or `vbic`.
            let adds_bits = cmode & 1 == 1 && cmode < 0b1100;
            let (operation, role) = match (invert, adds_bits) {
                (false, false) => (Op::Vmov, Role::Writes),
                (false, true) => (Op::Vorr, Role::Accumulates),
                (true, false) => (Op::Vmvn, Role::Writes),
                (true, true) => (Op::Vbic, Role::Accumulates),
            };
            (operation, element, Value::Constant(value), role)
        }
    };
    Some(NeonWord::new(operation, element, role, &[d, value]))
}

/// Two registers and a shift amount: section A7.4.4.
fn shift(fields: Fields) -> Option<NeonWord> {
    use NeonOperation as Op;
    use Role::{Accumulates, Writes};
    let (unsigned, quad) = (fields.unsigned(), fields.quad());
    // `L:imm6` holds both the size of an element and the amount.
    let long = fields.flag(7);
    let imm6 = fields.get(16, 6);
    let size = match (long, imm6.leading_zeros() - 26) {
        (true, _) => 3,
        (false, 0) => 2,
        (false, 1) => 1,
        (false, 2) => 0,
        _ => return None,
    };
    let esize = 8 << size;
    let (right, left) = if long { (64 - imm6, imm6) } else { (2 * esize - imm6, imm6 - esize) };
    let amount = |shift: u32| Value::Constant(u64::from(shift));
    let d = || Value::vector(fields.d(), quad);
    let m = || Value::vector(fields.m(), quad);
    let typed = typed(unsigned, size)?;
    let simple = |operation, element, role, shift: u32| {
        Some(NeonWord::new(operation, element, role, &[d()?, m()?, amount(shift)]))
    };
    let narrow = |operation, element: Option<&'static str>| {
        let d = Value::Double(fields.d());
        let m = Value::vector(fields.m(), Quad::Yes)?;
        Some(NeonWord::new(operation, element?, Writes, &[d, m, amount(right)]))
    };
    let rounds = fields.flag(6);
    match fields.get(8, 4) {
        0b0000 => simple(Op::Vshr, typed, Writes, right),
        0b0001 => simple(Op::Vsra, typed, Accumulates, right),
        0b0010 => simple(Op::Vrshr, typed, Writes, right),
        0b0011 => simple(Op::Vrsra, typed, Accumulates, right),
        0b0100 if unsigned => simple(Op::Vsri, element(UNTYPED, size)?, Accumulates, right),
        0b0101 if unsigned => simple(Op::Vsli, element(UNTYPED, size)?, Accumulates, left),
        0b0101 => simple(Op::Vshl, element(INTEGER, size)?, Writes, left),
        0b0110 if unsigned => simple(Op::Vqshlu, element(SIGNED, size)?, Writes, left),
        0b0111 => simple(Op::Vqshl, typed, Writes, left),
        // The narrowing shifts name the type of the source.
        0b1000 if !long => match (unsigned, rounds) {
            (false, false) => narrow(Op::Vshrn, element(INTEGER, size + 1)),
            (false, true) => narrow(Op::Vrshrn, element(INTEGER, size + 1)),
            (true, false) => narrow(Op::Vqshrun, element(SIGNED, size + 1)),
            (true, true) => narrow(Op::Vqrshrun, element(SIGNED, size + 1)),
        },
        0b1001 if !long => match rounds {
            false => narrow(Op::Vqshrn, self::typed(unsigned, size + 1)),
            true => narrow(Op::Vqrshrn, self::typed(unsigned, size + 1)),
        },
        // `vmovl` is `vshll` by zero.
        0b1010 if !long && !rounds => {
            let d = Value::vector(fields.d(), Quad::Yes)?;
            let m = Value::Double(fields.m());
            Some(match left {
                0 => NeonWord::new(Op::Vmovl, typed, Writes, &[d, m]),
                _ => NeonWord::new(Op::Vshll, typed, Writes, &[d, m, amount(left)]),
            })
        }
        // To and from fixed point, with `64 - imm6` bits of fraction.
        0b1110 | 0b1111 if !long && size == 2 => {
            let element = match (fields.flag(8), unsigned) {
                (false, false) => "f32.s32",
                (false, true) => "f32.u32",
                (true, false) => "s32.f32",
                (true, true) => "u32.f32",
            };
            simple(Op::Vcvt, element, Writes, 64 - imm6)
        }
        _ => None,
    }
}

/// Three registers of different lengths: section A7.4.2. A long form
/// writes a `q` register from two `d` registers, a wide form adds a `d`
/// register to a `q` register, and a narrow form writes a `d` register
/// from two `q` registers.
fn different_lengths(fields: Fields) -> Option<NeonWord> {
    use NeonOperation as Op;
    use Role::{Accumulates, Writes};
    let (unsigned, size) = (fields.unsigned(), fields.size());
    let typed = typed(unsigned, size)?;
    let quad = |number: u32| Value::vector(number, Quad::Yes);
    let double = Value::Double;
    let long = |operation, element, role| {
        let operands = [quad(fields.d())?, double(fields.n()), double(fields.m())];
        Some(NeonWord::new(operation, element, role, &operands))
    };
    let wide = |operation| {
        let operands = [quad(fields.d())?, quad(fields.n())?, double(fields.m())];
        Some(NeonWord::new(operation, typed, Writes, &operands))
    };
    let narrow = |operation| {
        let operands = [double(fields.d()), quad(fields.n())?, quad(fields.m())?];
        Some(NeonWord::new(operation, element(INTEGER, size + 1)?, Writes, &operands))
    };
    // The saturating doubling forms take 16 and 32-bit elements alone.
    let doubling = || (size == 1 || size == 2).then(|| element(SIGNED, size)).flatten();
    match (fields.get(8, 4), unsigned) {
        (0b0000, _) => long(Op::Vaddl, typed, Writes),
        (0b0001, _) => wide(Op::Vaddw),
        (0b0010, _) => long(Op::Vsubl, typed, Writes),
        (0b0011, _) => wide(Op::Vsubw),
        (0b0100, false) => narrow(Op::Vaddhn),
        (0b0100, true) => narrow(Op::Vraddhn),
        (0b0101, _) => long(Op::Vabal, typed, Accumulates),
        (0b0110, false) => narrow(Op::Vsubhn),
        (0b0110, true) => narrow(Op::Vrsubhn),
        (0b0111, _) => long(Op::Vabdl, typed, Writes),
        (0b1000, _) => long(Op::Vmlal, typed, Accumulates),
        (0b1001, false) => long(Op::Vqdmlal, doubling()?, Accumulates),
        (0b1010, _) => long(Op::Vmlsl, typed, Accumulates),
        (0b1011, false) => long(Op::Vqdmlsl, doubling()?, Accumulates),
        (0b1100, _) => long(Op::Vmull, typed, Writes),
        (0b1101, false) => long(Op::Vqdmull, doubling()?, Writes),
        (0b1110, false) if size == 0 => long(Op::Vmull, "p8", Writes),
        _ => None,
    }
}

/// Two registers and a scalar: section A7.4.3. `U` is `Q` for the forms
/// that are not long.
fn scalar(fields: Fields) -> Option<NeonWord> {
    use NeonOperation as Op;
    use Role::{Accumulates, Writes};
    let (unsigned, size) = (fields.unsigned(), fields.size());
    // A 16-bit lane takes two bits of `Vm` for its index, and leaves
    // `d0` to `d7`.
    let scalar = match size {
        0b01 => Value::Scalar {
            double: fields.get(0, 3),
            lane: fields.get(5, 1) << 1 | fields.get(3, 1),
        },
        0b10 => Value::Scalar { double: fields.get(0, 4), lane: fields.get(5, 1) },
        _ => return None,
    };
    let quad = Quad::of(unsigned);
    let float = fields.flag(8);
    let same = |operation, element, role| {
        let d = Value::vector(fields.d(), quad)?;
        let n = Value::vector(fields.n(), quad)?;
        Some(NeonWord::new(operation, element, role, &[d, n, scalar]))
    };
    let long = |operation, element, role| {
        let d = Value::vector(fields.d(), Quad::Yes)?;
        Some(NeonWord::new(operation, element, role, &[d, Value::Double(fields.n()), scalar]))
    };
    let multiplied = if float { (size == 2).then_some("f32")? } else { element(INTEGER, size)? };
    let typed = typed(unsigned, size)?;
    let signed = element(SIGNED, size)?;
    match (fields.get(8, 4), unsigned) {
        (0b0000 | 0b0001, _) => same(Op::Vmla, multiplied, Accumulates),
        (0b0100 | 0b0101, _) => same(Op::Vmls, multiplied, Accumulates),
        (0b1000 | 0b1001, _) => same(Op::Vmul, multiplied, Writes),
        (0b0010, _) => long(Op::Vmlal, typed, Accumulates),
        (0b0110, _) => long(Op::Vmlsl, typed, Accumulates),
        (0b1010, _) => long(Op::Vmull, typed, Writes),
        (0b0011, false) => long(Op::Vqdmlal, signed, Accumulates),
        (0b0111, false) => long(Op::Vqdmlsl, signed, Accumulates),
        (0b1011, false) => long(Op::Vqdmull, signed, Writes),
        (0b1100, _) => same(Op::Vqdmulh, signed, Writes),
        (0b1101, _) => same(Op::Vqrdmulh, signed, Writes),
        _ => None,
    }
}

/// `vext`, which takes bytes from two registers, from the byte `imm4`. It
/// prints with the widest element that `imm4` is a whole number of, up to
/// half the register, as `llvm-objdump` prints it: `vext.32 q0, q1, q2, #1`
/// for the byte 4.
fn extract(fields: Fields) -> Option<NeonWord> {
    let quad = fields.quad();
    let start = fields.get(8, 4);
    if quad == Quad::No && start > 7 {
        return None;
    }
    let widest = if quad == Quad::Yes { 3 } else { 2 };
    let size = start.trailing_zeros().min(widest);
    let operands = [
        Value::vector(fields.d(), quad)?,
        Value::vector(fields.n(), quad)?,
        Value::vector(fields.m(), quad)?,
        Value::Constant(u64::from(start >> size)),
    ];
    Some(NeonWord::new(NeonOperation::Vext, element(UNTYPED, size)?, Role::Writes, &operands))
}

/// Two registers, miscellaneous: section A7.4.5. `A`, bits 17 and 16, and
/// `B`, bits 10 to 6, pick the operation, and bits 19 and 18 the size.
fn miscellaneous(fields: Fields) -> Option<NeonWord> {
    use NeonOperation as Op;
    use Role::{Accumulates, Exchanges, Writes};
    let size = fields.get(18, 2);
    let quad = fields.quad();
    let d = || Value::vector(fields.d(), quad);
    let m = || Value::vector(fields.m(), quad);
    let unary = |operation, element: Option<&'static str>, role| {
        Some(NeonWord::new(operation, element?, role, &[d()?, m()?]))
    };
    let narrow = |operation, element: Option<&'static str>| {
        let m = Value::vector(fields.m(), Quad::Yes)?;
        Some(NeonWord::new(operation, element?, Writes, &[Value::Double(fields.d()), m]))
    };
    // Bits 10 to 7: `B` less `Q`.
    let b = fields.get(7, 4);
    let low = fields.flag(6);
    let unsigned = fields.flag(7);
    match (fields.get(16, 2), b) {
        (0b00, 0b0000) => unary(Op::Vrev64, element(UNTYPED, size), Writes),
        (0b00, 0b0001) => unary(Op::Vrev32, element(UNTYPED, size), Writes),
        (0b00, 0b0010) => unary(Op::Vrev16, element(UNTYPED, size), Writes),
        (0b00, 0b0100 | 0b0101) => unary(Op::Vpaddl, typed(unsigned, size), Writes),
        (0b00, 0b1000) => unary(Op::Vcls, element(SIGNED, size), Writes),
        (0b00, 0b1001) => unary(Op::Vclz, element(INTEGER, size), Writes),
        (0b00, 0b1010) if size == 0 => unary(Op::Vcnt, Some("8"), Writes),
        (0b00, 0b1011) if size == 0 => unary(Op::Vmvn, Some(""), Writes),
        (0b00, 0b1100 | 0b1101) => unary(Op::Vpadal, typed(unsigned, size), Accumulates),
        (0b00, 0b1110) => unary(Op::Vqabs, element(SIGNED, size), Writes),
        (0b00, 0b1111) => unary(Op::Vqneg, element(SIGNED, size), Writes),
        // Bit 10 says float, and the rest compare with zero or take the
        // sign.
        (0b01, b) => {
            let float = b >> 3 == 1;
            let typed = if float { (size == 2).then_some("f32") } else { element(SIGNED, size) };
            let operation = match b & 0b111 {
                0b000 => Op::Vcgt,
                0b001 => Op::Vcge,
                0b010 => Op::Vceq,
                0b011 => Op::Vcle,
                0b100 => Op::Vclt,
                0b110 => Op::Vabs,
                0b111 => Op::Vneg,
                _ => return None,
            };
            let typed = match (operation, float) {
                (Op::Vceq, false) => element(INTEGER, size),
                _ => typed,
            }?;
            Some(match operation {
                Op::Vabs | Op::Vneg => NeonWord::new(operation, typed, Writes, &[d()?, m()?]),
                _ => NeonWord::new(operation, typed, Writes, &[d()?, m()?, Value::Constant(0)]),
            })
        }
        (0b10, 0b0000) => unary(Op::Vswp, Some(""), Exchanges),
        (0b10, 0b0001) => unary(Op::Vtrn, element(UNTYPED, size), Exchanges),
        (0b10, 0b0010) => unary(Op::Vuzp, element(UNTYPED, size), Exchanges),
        (0b10, 0b0011) => unary(Op::Vzip, element(UNTYPED, size), Exchanges),
        (0b10, 0b0100) if low => narrow(Op::Vqmovun, element(SIGNED, size + 1)),
        (0b10, 0b0100) => narrow(Op::Vmovn, element(INTEGER, size + 1)),
        (0b10, 0b0101) => narrow(Op::Vqmovn, typed(low, size + 1)),
        // `vshll` by the size of the element, which the shift form cannot
        // encode.
        (0b10, 0b0110) if !low => {
            let d = Value::vector(fields.d(), Quad::Yes)?;
            let amount = Value::Constant(8 << size);
            let operands = [d, Value::Double(fields.m()), amount];
            Some(NeonWord::new(Op::Vshll, element(INTEGER, size)?, Writes, &operands))
        }
        (0b10, 0b1100) if !low && size == 1 => narrow(Op::Vcvt, Some("f16.f32")),
        (0b10, 0b1110) if !low && size == 1 => {
            let d = Value::vector(fields.d(), Quad::Yes)?;
            let operands = [d, Value::Double(fields.m())];
            Some(NeonWord::new(Op::Vcvt, "f32.f16", Writes, &operands))
        }
        // Bit 8 says float.
        (0b11, 0b1000 | 0b1010) if size == 2 => {
            unary(Op::Vrecpe, Some(if b & 0b10 == 0 { "u32" } else { "f32" }), Writes)
        }
        (0b11, 0b1001 | 0b1011) if size == 2 => {
            unary(Op::Vrsqrte, Some(if b & 0b10 == 0 { "u32" } else { "f32" }), Writes)
        }
        (0b11, 0b1100..=0b1111) if size == 2 => {
            let element = match b & 0b11 {
                0b00 => "f32.s32",
                0b01 => "f32.u32",
                0b10 => "s32.f32",
                _ => "u32.f32",
            };
            unary(Op::Vcvt, Some(element), Writes)
        }
        _ => None,
    }
}

/// `vtbl` and `vtbx`, which look up each byte of `Vm` in a table of up to
/// four registers. `vtbx` keeps the bytes of its destination that fall
/// outside the table.
fn table(fields: Fields) -> Option<NeonWord> {
    let (first, count) = (fields.n(), fields.get(8, 2) + 1);
    if first + count > 32 {
        return None;
    }
    let (operation, role) = match fields.flag(6) {
        false => (NeonOperation::Vtbl, Role::Writes),
        true => (NeonOperation::Vtbx, Role::Accumulates),
    };
    let operands =
        [Value::Double(fields.d()), Value::Table { first, count }, Value::Double(fields.m())];
    Some(NeonWord::new(operation, "8", role, &operands))
}

/// `vdup` of a scalar: the lowest set bit of `imm4` says the size, and the
/// bits above it the lane.
fn duplicate_scalar(fields: Fields) -> Option<NeonWord> {
    let imm4 = fields.get(16, 4);
    let (element, lane) = match imm4.trailing_zeros() {
        0 => ("8", imm4 >> 1),
        1 => ("16", imm4 >> 2),
        2 => ("32", imm4 >> 3),
        _ => return None,
    };
    let d = Value::vector(fields.d(), fields.quad())?;
    let scalar = Value::Scalar { double: fields.m(), lane };
    Some(NeonWord::new(NeonOperation::Vdup, element, Role::Writes, &[d, scalar]))
}

/// The moves between a core register and a NEON lane, and `vdup` of a core
/// register: section A7.8.
///
/// ```text
/// cccc 1110 U opc1 1 Vn Rt 1011 N opc2 1 0000   vmov.s8 rt, dn[x]
/// cccc 1110 0 opc1 0 Vd Rt 1011 D opc2 1 0000   vmov.8 dd[x], rt
/// cccc 1110 1 B Q 0  Vd Rt 1011 D 0 E 1 0000    vdup.8 qd, rt
/// ```
fn transfer(fields: Fields) -> Option<NeonWord> {
    use NeonOperation as Op;
    if fields.get(24, 4) != 0b1110
        || fields.get(8, 4) != 0b1011
        || !fields.flag(4)
        || fields.get(0, 4) != 0
    {
        return None;
    }
    let core = fields.get(12, 4);
    if core == 15 {
        return None;
    }
    let core = Value::Core(core);
    // Both moves keep their register in the place of `Vn`.
    let register = fields.n();
    let (opc1, opc2) = (fields.get(21, 2), fields.get(5, 2));
    // The lowest set bit of `opc1:opc2` says the size, as for `vdup`.
    let lane = || match (opc1 >> 1, opc2) {
        (1, _) => Some((0, (opc1 & 1) << 2 | opc2)),
        (0, 0b01 | 0b11) => Some((1, (opc1 & 1) << 1 | opc2 >> 1)),
        (0, 0b00) => Some((2, opc1 & 1)),
        _ => None,
    };
    if fields.flag(20) {
        let (size, lane) = lane()?;
        // `U` is bit 23 here. A 32-bit lane fills the core register, and is
        // neither signed nor unsigned.
        let unsigned = fields.flag(23);
        let element = match size {
            2 if unsigned => return None,
            2 => "32",
            _ => typed(unsigned, size)?,
        };
        let scalar = Value::Scalar { double: register, lane };
        return Some(NeonWord::new(Op::Vmov, element, Role::Writes, &[core, scalar]));
    }
    if !fields.flag(23) {
        let (size, lane) = lane()?;
        // The move keeps the other lanes.
        let scalar = Value::Scalar { double: register, lane };
        let element = element(UNTYPED, size)?;
        return Some(NeonWord::new(Op::Vmov, element, Role::Accumulates, &[scalar, core]));
    }
    if fields.flag(6) {
        return None;
    }
    let element = match (fields.flag(22), fields.flag(5)) {
        (false, false) => "32",
        (false, true) => "16",
        (true, false) => "8",
        (true, true) => return None,
    };
    let d = Value::vector(register, Quad::of(fields.flag(21)))?;
    Some(NeonWord::new(Op::Vdup, element, Role::Writes, &[d, core]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The text of `word`, as the decoder prints it.
    fn text(word: u32) -> String {
        let (name, operands) = NeonWord::of(word).expect("a NEON word").text();
        format!("{name} {operands}")
    }

    /// Each word, as `llvm-mc --triple=armv7a -mattr=+neon,+vfp4` encodes and
    /// prints it, but for the constants, which print as `yaxpeax-arm` prints
    /// them.
    #[test]
    fn reads_what_the_assembler_writes() {
        let cases: &[(u32, &str)] = &[
            (0xf2600844, "vadd.i32 q8, q0, q2"),
            (0xf3600844, "vsub.i32 q8, q0, q2"),
            (0xf2400d84, "vadd.f32 d16, d16, d4"),
            (0xf3400d94, "vmul.f32 d16, d16, d4"),
            (0xf2400c94, "vfma.f32 d16, d16, d4"),
            (0xf2600c94, "vfms.f32 d16, d16, d4"),
            (0xf2400d94, "vmla.f32 d16, d16, d4"),
            (0xf26601f8, "vorr q8, q11, q12"),
            (0xf2600150, "vorr q8, q0, q0"),
            (0xf3400154, "veor q8, q0, q2"),
            (0xf3500154, "vbsl q8, q0, q2"),
            (0xf2400154, "vand q8, q0, q2"),
            (0xf3600654, "vmin.u32 q8, q0, q2"),
            (0xf2600644, "vmax.s32 q8, q0, q2"),
            (0xf3600854, "vceq.i32 q8, q0, q2"),
            (0xf2640340, "vcgt.s32 q8, q2, q0"),
            (0xf3600440, "vshl.u32 q8, q0, q0"),
            (0xf2600b14, "vpadd.i32 d16, d0, d4"),
            (0xf2c00050, "vmov.i32 q8, 0x0"),
            (0xf2c70e5f, "vmov.i8 q8, 0x7f"),
            (0xf2c70f50, "vmov.f32 q8, #1.0"),
            (0xf2c00e31, "vmov.i64 d16, 0xff"),
            (0xf2c00151, "vorr.i32 q8, 0x1"),
            (0xf2c00030, "vmvn.i32 d16, 0x0"),
            (0xf2e00070, "vshr.s32 q8, q8, 0x20"),
            (0xf3e10070, "vshr.u32 q8, q8, 0x1f"),
            (0xf2e10570, "vshl.i32 q8, q8, 0x1"),
            (0xf2c80a30, "vmovl.s8 q8, d16"),
            (0xf3d00a30, "vmovl.u16 q8, d16"),
            (0xf2c90830, "vshrn.i16 d16, q8, 0x7"),
            (0xf2a10e50, "vcvt.f32.s32 q0, q0, 0x1f"),
            (0xf2c00c20, "vmull.s8 q8, d0, d16"),
            (0xf3d00020, "vaddl.u16 q8, d0, d16"),
            (0xf2d00820, "vmlal.s16 q8, d0, d16"),
            (0xf2c00420, "vaddhn.i16 d16, q0, q8"),
            (0xf3e00948, "vmul.f32 q8, q0, d8[0]"),
            (0xf2e00168, "vmla.f32 d16, d0, d8[1]"),
            (0xf2e00a48, "vmull.s32 q8, d0, d8[0]"),
            (0xf2f00960, "vext.8 q8, q0, q8, 0x9"),
            (0xf2b20444, "vext.32 q0, q1, q2, 0x1"),
            (0xf2b20044, "vext.64 q0, q1, q2, 0x0"),
            (0xf2b10202, "vext.16 d0, d1, d2, 0x1"),
            (0xf3f80060, "vrev64.32 q8, q8"),
            (0xf3f005e0, "vmvn q8, q8"),
            (0xf3f00560, "vcnt.8 q8, q8"),
            (0xf3f50060, "vcgt.s16 q8, q8, 0x0"),
            (0xf3f90760, "vabs.f32 q8, q8"),
            (0xf3f20021, "vswp d16, d17"),
            (0xf3f60220, "vmovn.i32 d16, q8"),
            (0xf3fb0760, "vcvt.s32.f32 q8, q8"),
            (0xf3f408a0, "vtbl.8 d16, {d20}, d16"),
            (0xf3f60c40, "vdup.16 q8, d0[1]"),
            (0xee100b90, "vmov.32 r0, d16[0]"),
            (0xee300b90, "vmov.32 r0, d16[1]"),
            (0xeed25b90, "vmov.u8 r5, d18[0]"),
            (0xee000b90, "vmov.32 d16[0], r0"),
            (0xee803b90, "vdup.32 d16, r3"),
            (0xeee03b90, "vdup.8 q8, r3"),
            (0xf3d00869, "vmul.i16 q8, q0, d1[3]"),
            (0xf2110b02, "vqdmulh.s16 d0, d1, d2"),
            (0xf3bb0542, "vrecpe.f32 q0, q1"),
            (0xf3b10a44, "vtbx.8 d0, {d1, d2, d3}, d4"),
            (0xf3bd01d2, "vsra.u64 q0, q1, 0x3"),
            (0xf3b20301, "vshll.i8 q0, d1, 0x8"),
            (0xf2810e02, "vmull.p8 q0, d1, d2"),
            (0xf3b60181, "vzip.16 d0, d1"),
            (0xf3b60242, "vqmovun.s32 d0, q1"),
            (0xf3b60602, "vcvt.f16.f32 d0, q1"),
            (0xf3b60701, "vcvt.f32.f16 q0, d1"),
            (0xf3b002c2, "vpaddl.u8 q0, q1"),
            (0xf3a50511, "vsli.32 d0, d1, 0x5"),
            (0xf38d0411, "vsri.8 d0, d1, 0x3"),
            (0xf3a30652, "vqshlu.s32 q0, q1, 0x3"),
            (0xf2220f54, "vrsqrts.f32 q0, q1, q2"),
            (0xf3220e54, "vacgt.f32 q0, q1, q2"),
            (0xf3870b3f, "vbic.i16 d0, 0xff00"),
            (0xf2810d12, "vmov.i32 d0, 0x12ffff"),
        ];
        for (word, expected) in cases {
            assert_eq!(text(*word), *expected, "{word:#010x}");
        }
    }

    #[test]
    fn the_other_words_are_no_neon() {
        // `add r0, r0, r0`, a VFP `vmov s0, r0`, and an odd `q` register.
        for word in [0xe080_0000, 0xee00_0a10, 0xf260_1844] {
            assert_eq!(NeonWord::of(word), None, "{word:#010x}");
        }
    }

    #[test]
    fn a_quad_register_is_two_doubles() {
        let lifted = NeonWord::of(0xf260_0844).expect("vadd.i32 q8, q0, q2").lift();
        let vector = il::Reg::Vector;
        assert_eq!(lifted.op, il::Op::Vector);
        assert_eq!(lifted.writes, [vector(16), vector(17)].into_iter().collect());
        assert_eq!(
            lifted.reads,
            [vector(0), vector(1), vector(4), vector(5)].into_iter().collect()
        );
    }

    #[test]
    fn an_accumulating_word_reads_its_destination() {
        let lifted = NeonWord::of(0xf240_0d94).expect("vmla.f32 d16, d16, d4").lift();
        assert!(lifted.reads.contains(il::Reg::Vector(16)));
        assert!(lifted.writes.contains(il::Reg::Vector(16)));
    }

    #[test]
    fn a_swap_writes_both_registers() {
        let lifted = NeonWord::of(0xf3f2_0021).expect("vswp d16, d17").lift();
        let both: il::RegSet = [il::Reg::Vector(16), il::Reg::Vector(17)].into_iter().collect();
        assert_eq!(lifted.writes, both);
        assert_eq!(lifted.reads, both);
    }

    #[test]
    fn a_move_to_core_writes_the_core_register() {
        let lifted = NeonWord::of(0xee10_0b90).expect("vmov.32 r0, d16[0]").lift();
        assert_eq!(lifted.op, il::Op::Move);
        assert_eq!(lifted.writes, [il::Reg::General(0)].into_iter().collect());
        assert_eq!(lifted.reads, [il::Reg::Vector(16)].into_iter().collect());
    }

    #[test]
    fn a_move_to_a_lane_keeps_the_other_lanes() {
        let lifted = NeonWord::of(0xee00_0b90).expect("vmov.32 d16[0], r0").lift();
        assert!(lifted.reads.contains(il::Reg::Vector(16)));
        assert!(lifted.reads.contains(il::Reg::General(0)));
        assert_eq!(lifted.writes, [il::Reg::Vector(16)].into_iter().collect());
    }

    #[test]
    fn a_constant_is_the_element_it_prints() {
        let lifted = NeonWord::of(0xf2c7_0e5f).expect("vmov.i8 q8, 0x7f").lift();
        assert_eq!(lifted.operands[1], il::Operand::Const(0x7f));
        let lifted = NeonWord::of(0xf2c7_0f50).expect("vmov.f32 q8, #1.0").lift();
        assert_eq!(lifted.operands[1], il::Operand::Const(0x3f80_0000));
    }

    #[test]
    fn a_names_entry_for_each_operand() {
        for word in [0xf260_0844, 0xf3e0_0948, 0xf3f4_08a0, 0xee10_0b90] {
            let neon = NeonWord::of(word).expect("a NEON word");
            assert_eq!(neon.names().len(), neon.lift().operands.len(), "{word:#010x}");
        }
    }

    /// No word panics, and each word read names its operands once and
    /// lifts no register past `d31`.
    #[test]
    fn every_data_processing_word_reads_safely() {
        for high in 0..=0x1ffu32 {
            for low in (0..0x10000u32).step_by(0x0101) {
                let word = 0xf200_0000 | high << 16 | low;
                let word = word & 0xf3ff_ffff;
                if let Some(neon) = NeonWord::of(word) {
                    assert_eq!(neon.names().len(), neon.lift().operands.len(), "{word:#010x}");
                }
            }
        }
    }
}
