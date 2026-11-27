//! The rules of the IL view that each architecture keeps: the statements
//! it reads from the decoded instruction where the IL holds too little, and
//! what its instructions say of the flags, of their conditions and of the
//! addresses they form. [`rules_of`] gives the rules of an instruction by
//! the decoder that read it, as one body can mix instruction sets.

mod aarch64;
mod arm32;
mod mips;
mod powerpc;
mod x86;

use hereticus_il::arch::{Insn, InstructionSet, Opcode};
use hereticus_il::{Lifted, Named, Op, Reg};

use crate::{CarryFlag, Compared};

/// The state that the statements of one function carry from one
/// instruction to the next, for the architectures that keep one.
#[derive(Default)]
pub(crate) struct Reading {
    /// The test of the last float compare into each condition code of MIPS.
    float_conditions: mips::FloatConditions,
}

/// Whether an instruction makes a frame or drops it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameStep {
    Makes,
    Drops,
}

/// A frame that one instruction makes or drops whole, with the registers
/// it keeps there, as the MIPS16e `save` and `restore` do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WholeFrame {
    pub(crate) step: FrameStep,
    /// The bytes of the frame.
    pub(crate) size: i64,
    /// The registers kept at the top of the frame, the lowest first, or
    /// `None` where one has a name the lift does not know.
    pub(crate) kept: Option<Vec<Reg>>,
}

/// The rules of the IL view of one architecture. Each default holds for an
/// architecture that has no such rule.
pub(crate) trait Rules: Sync {
    /// Whether the view hides `insn`, as it does the T32 `it`, which only
    /// sets the conditions of the instructions after it.
    fn hides(&self, _insn: &Insn) -> bool {
        false
    }

    /// Which condition on the flags reads a carry out of a sum.
    fn carry_flag(&self) -> CarryFlag {
        CarryFlag::SetAtOrAbove
    }

    /// Whether `insn` adds or subtracts but keeps the carry flag of the
    /// code before it.
    fn keeps_carry(&self, _insn: &Insn) -> bool {
        false
    }

    /// The condition that `insn` runs on, as the `ne` of `addne`, where the
    /// IL holds none. `op` is the operation the lift names, where it names
    /// one.
    fn condition(&self, _insn: &Insn, _op: Option<Op>) -> Option<&'static str> {
        None
    }

    /// The printed `name` of an instruction that runs on a condition,
    /// without the condition: `clz` of `clzeq`.
    fn without_condition<'a>(&self, name: &'a str) -> &'a str {
        name
    }

    /// Whether the decoder prints `insn` with `ld` first, as a load of a
    /// slot of the GOT.
    fn is_named_load(&self, _insn: &Insn) -> bool {
        false
    }

    /// Whether `insn` reads as the code prints it, where the IL holds a
    /// plainer operation than the code does, for the matching.
    fn reads_as_printed(&self, _insn: &Insn) -> bool {
        false
    }

    /// The statement of `insn` whose operands the code does not print, as
    /// the `hi` and `lo` of a MIPS multiply, from the operands it shows.
    fn own_statement(
        &self,
        _insn: &Insn,
        _shown: &[&str],
        _reading: &mut Reading,
    ) -> Option<String> {
        None
    }

    /// The statement of an access to a list of registers as one load or
    /// store, as `push {r4, lr}`.
    fn list_statement(&self, _insn: &Insn, _tokens: &[&str], _lifted: &Lifted) -> Option<String> {
        None
    }

    /// Where an access to a list of `count` registers puts the first, from
    /// its base, and how far it moves the base where it writes it back.
    fn list_offsets(&self, _insn: &Insn, _lifted: &Lifted, _count: usize) -> Option<(i64, i64)> {
        None
    }

    /// The statement of `insn` whose operands the IL does not read as an
    /// operator does, as a conditional compare, from its operands
    /// `tokens`.
    fn operand_statement(
        &self,
        _insn: &Insn,
        _tokens: &[&str],
        _last_compare: &mut Option<Compared>,
    ) -> Option<String> {
        None
    }

    /// Whether `insn` traps, and so ends the code as a jump does, but goes
    /// nowhere it names.
    fn traps(&self, _insn: &Insn) -> bool {
        false
    }

    /// Whether `insn` forms the page of an address, as `adrp` does.
    fn forms_page(&self, _insn: &Insn) -> bool {
        false
    }

    /// How far `insn`, which forms the upper half of a value, shifts the
    /// constant the IL holds: 16 for a MIPS `lui`, and none for a PowerPC
    /// `lis`, whose IL holds the constant shifted.
    fn upper_half_shift(&self, _insn: &Insn) -> Option<u32> {
        None
    }

    /// Whether the multiply-add `insn` subtracts the product, as `mls`
    /// does.
    fn subtracts_product(&self, _insn: &Insn) -> bool {
        false
    }

    /// Whether the compare `insn` adds its right operand, as `cmn r1, #1`
    /// does: the lift reads it as a subtract of -1.
    fn compares_by_adding(&self, _insn: &Insn) -> bool {
        false
    }

    /// The statement of `insn`, a compare that runs on a condition, of
    /// `left` and `right`.
    fn conditional_compare(&self, _insn: &Insn, left: &str, right: &str) -> String {
        format!("flags = compare({left}, {right})")
    }

    /// Whether `insn` sets the upper half of its register and keeps the
    /// lower, as `movt` does.
    fn sets_upper_half(&self, _insn: &Insn) -> bool {
        false
    }

    /// The value that the select `insn` picks where its condition holds,
    /// where it picks a constant or 0: 1 for `cset`.
    fn select_constant(&self, _insn: &Insn) -> &'static str {
        "1"
    }

    /// The statement of the select `insn`, which writes `dest` with
    /// `chosen` where `cond` holds and with what it makes of `other` where
    /// not. `other_is_zero` tells that `other` is the zero register.
    fn select_statement(
        &self,
        _insn: &Insn,
        [dest, chosen, other, cond]: [&str; 4],
        _other_is_zero: bool,
    ) -> String {
        format!("{dest} = {cond} ? {chosen} : {other}")
    }

    /// Whether `insn` joins the low half of an address to a page that a
    /// load from the GOT gives, as a MIPS `addiu` does.
    fn joins_page_offset(&self, _insn: &Insn) -> bool {
        false
    }

    /// Whether `insn` loads a page from the GOT, as a MIPS `lw` does.
    fn loads_page(&self, _insn: &Insn) -> bool {
        false
    }

    /// Whether `insn`, lifted as `named`, loads a word of a literal pool,
    /// which the view shows as what the word holds.
    fn loads_pool_word(&self, _insn: &Insn, _named: &Named) -> bool {
        false
    }

    /// The address of the word of a literal pool that `insn` loads at
    /// `offset` from the program counter.
    fn pool_address(&self, _insn: &Insn, _offset: i64) -> Option<u64> {
        None
    }

    /// Whether an instruction holds an address in one field of an operand
    /// that can add registers, as `[4*rdi + table]`, or as a constant it
    /// pushes, so that field takes the name of what a relocation names.
    fn names_field(&self) -> bool {
        false
    }

    /// The frame that `insn` makes or drops whole, where it does.
    fn whole_frame(&self, _insn: &Insn) -> Option<WholeFrame> {
        None
    }
}

/// The rules of an instruction that no decoder read.
struct Plain;

impl Rules for Plain {}

/// The rules of the instruction set that `insn` is in.
pub(crate) fn rules_of(insn: &Insn) -> &'static dyn Rules {
    use InstructionSet as Set;
    match insn.opcode {
        Opcode::Aarch64(_) | Opcode::Unread(Set::Aarch64) => &aarch64::Aarch64,
        Opcode::Arm(_) | Opcode::Unread(Set::Arm) => &arm32::Arm32,
        Opcode::Thumb(_) | Opcode::Unread(Set::Thumb) => &arm32::Thumb2,
        Opcode::Mips(..) | Opcode::Mips16(..) | Opcode::Unread(Set::Mips(_) | Set::Mips16(_)) => {
            &mips::Mips
        }
        Opcode::X86(..) | Opcode::Unread(Set::X86(_)) => &x86::X86,
        Opcode::PowerPc(..) | Opcode::Unread(Set::PowerPc(_)) => &powerpc::PowerPc,
        Opcode::None | Opcode::Data => &Plain,
    }
}
