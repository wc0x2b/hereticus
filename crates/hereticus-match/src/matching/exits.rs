//! Checks that a fix adds before an early exit.
//!
//! Many fixes narrow what a function accepts: they add a test, and where it
//! fails the function returns at once, so every input the old code handled
//! well runs as before. SPIDER (Machiry and others, IEEE S&P 2020) calls
//! such a patch safe, and finds it in source by that shape. In machine code
//! the shape is a conditional branch the edit added, with one way out of it
//! that leaves the function within a few instructions.
//!
//! See RESEARCH.md, "Checks before an early exit".

use hereticus_arch::Arch;
use hereticus_il::arch::{Insn, InsnKind};

/// How many instructions a way out of a check may run before it leaves
/// the function. An error path sets the value to return, may call a
/// function to log or free, and returns or jumps to the shared exit.
const LOOKAHEAD: usize = 8;

/// Report whether the conditional branch at `index` of `insns`, which are
/// one function in address order, has a way out that leaves the function
/// within [`LOOKAHEAD`] instructions.
pub(super) fn exits_early(arch: &dyn Arch, insns: &[Insn], index: usize) -> bool {
    let Some(insn) = insns.get(index) else { return false };
    let InsnKind::Branch { target } = insn.kind else { return false };
    let taken = target.and_then(|target| index_of(insns, target));
    let not_taken = index + 1 + arch.delay_slots(insn);
    [taken, Some(not_taken)].into_iter().flatten().any(|start| leaves(insns, start))
}

/// Report whether the straight run of `insns` from `start` returns within
/// [`LOOKAHEAD`] instructions. A jump within the function is followed, as
/// to the shared exit; a branch, a jump elsewhere and bytes no decoder
/// reads end the run.
fn leaves(insns: &[Insn], start: usize) -> bool {
    let mut at = start;
    for _ in 0..LOOKAHEAD {
        let Some(insn) = insns.get(at) else { return false };
        match insn.kind {
            InsnKind::Return => return true,
            InsnKind::Normal | InsnKind::Call { .. } => at += 1,
            InsnKind::Jump { target: Some(target) } => match index_of(insns, target) {
                Some(next) => at = next,
                None => return false,
            },
            InsnKind::Jump { target: None } | InsnKind::Branch { .. } | InsnKind::Unknown => {
                return false;
            }
        }
    }
    false
}

/// The index of the instruction of `insns` at `address`.
fn index_of(insns: &[Insn], address: u64) -> Option<usize> {
    insns.binary_search_by_key(&address, |insn| insn.address).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hereticus_il::arch::arm32::Arm32;
    use hereticus_recovery::arch::decode_all;

    fn insns(words: &[u32]) -> Vec<Insn> {
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        decode_all(&Arm32, &code, 0x1000).0
    }

    const CMP_R0_0: u32 = 0xe350_0000;
    const MOV_R0_1: u32 = 0xe3a0_0001;
    const MVN_R0_0: u32 = 0xe3e0_0000;
    const ADD: u32 = 0xe080_0001;
    const BX_LR: u32 = 0xe12f_ff1e;

    /// `bne` over an error return of -1: the way taken where `r0` is 0
    /// returns at once.
    #[test]
    fn a_check_before_a_return_exits_early() {
        let bne_over_two = 0x1a00_0000; // bne 0x100c
        let code = insns(&[CMP_R0_0, bne_over_two, MVN_R0_0, BX_LR, ADD, ADD, ADD, BX_LR]);
        assert!(exits_early(&Arm32, &code, 1));
    }

    /// A jump to the shared exit is followed.
    #[test]
    fn a_jump_to_the_shared_exit_is_followed() {
        let beq_to_jump = 0x0a00_0001; // beq 0x1010
        let b_to_exit = 0xea00_0000; // b 0x1018
        let code = insns(&[CMP_R0_0, beq_to_jump, ADD, ADD, b_to_exit, ADD, MOV_R0_1, BX_LR]);
        assert!(exits_early(&Arm32, &code, 1));
    }

    /// A branch between two long runs of work exits nowhere near.
    #[test]
    fn a_branch_into_more_work_does_not_exit_early() {
        let beq_far = 0x0a00_0009; // beq 0x1030
        let mut words = vec![CMP_R0_0, beq_far];
        words.extend([ADD; 10]);
        words.extend([ADD; 10]);
        words.push(BX_LR);
        assert!(!exits_early(&Arm32, &insns(&words), 1));
    }

    /// Only a conditional branch is a check.
    #[test]
    fn an_instruction_that_is_no_branch_is_no_check() {
        let code = insns(&[CMP_R0_0, BX_LR]);
        assert!(!exits_early(&Arm32, &code, 0));
        assert!(!exits_early(&Arm32, &code, 7), "past the end");
    }
}
