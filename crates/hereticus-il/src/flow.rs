//! What a register holds before each instruction of a function, on every
//! path that reaches it.
//!
//! A compiler loads a callee into a register that a call preserves, once,
//! and calls through it in a loop or on several paths. The register can
//! hold another callee on a path that comes before in the code but never
//! reaches the call, so the order of the code alone names the wrong one:
//! `procd` of OpenWrt 24.10.6 for AArch64 loads `avl_delete` into `x26` on
//! one path, and calls `strncmp` through `x26` on another.

use std::collections::HashMap;
use std::hash::Hash;

use crate::arch::{Insn, InsnKind};

/// The indices of the instructions that can run right after each
/// instruction of `insns`, which are one function.
///
/// `delay_slots` counts the instructions after a branch that still belong
/// to it. A delay slot runs before its branch goes, so the edges of a
/// branch leave from its last slot. A jump through a register, as to a case
/// of a `switch`, can reach any instruction that no other edge reaches.
pub fn successors(insns: &[Insn], delay_slots: impl Fn(&Insn) -> usize) -> Vec<Vec<usize>> {
    let index_of = |target: u64| insns.binary_search_by_key(&target, |insn| insn.address).ok();
    let mut next: Vec<Vec<usize>> = vec![Vec::new(); insns.len()];
    let mut indirect = Vec::new();
    let mut index = 0;
    while index < insns.len() {
        let insn = &insns[index];
        let slots = match insn.kind {
            InsnKind::Normal | InsnKind::Unknown => 0,
            _ => delay_slots(insn),
        };
        let after = index + slots + 1;
        let flow: Vec<usize> = match insn.kind {
            InsnKind::Normal | InsnKind::Unknown | InsnKind::Call { .. } => vec![after],
            InsnKind::Branch { target } => {
                core::iter::once(after).chain(target.and_then(index_of)).collect()
            }
            InsnKind::Jump { target: Some(target) } => index_of(target).into_iter().collect(),
            InsnKind::Jump { target: None } => {
                indirect.push(index + slots);
                Vec::new()
            }
            InsnKind::Return => Vec::new(),
        };
        let end = (index + slots).min(insns.len());
        for (slot, edges) in next[index..end].iter_mut().enumerate() {
            *edges = vec![index + slot + 1];
        }
        if let Some(last) = next.get_mut(index + slots) {
            *last = flow;
        }
        index = after;
    }
    for edges in &mut next {
        edges.retain(|&successor| successor < insns.len());
    }
    let mut reached = vec![false; insns.len()];
    for &successor in next.iter().flatten() {
        reached[successor] = true;
    }
    let unreached: Vec<usize> = (1..insns.len()).filter(|&index| !reached[index]).collect();
    for from in indirect {
        if let Some(edges) = next.get_mut(from) {
            edges.extend(&unreached);
        }
    }
    next
}

/// What each register holds before each instruction of `insns`, where
/// every path from the first instruction agrees on it.
///
/// `transfer` applies instruction `index` to what the registers hold.
/// A register missing from the map holds nothing known, as each does at the
/// start.
pub fn held_on_every_path<K, V>(
    insns: &[Insn],
    delay_slots: impl Fn(&Insn) -> usize,
    transfer: impl Fn(usize, &mut HashMap<K, V>),
) -> Vec<HashMap<K, V>>
where
    K: Clone + Eq + Hash,
    V: Clone + Eq,
{
    held_on_every_path_of(&successors(insns, delay_slots), transfer)
}

/// [`held_on_every_path`], over the instructions whose successors `next`
/// gives, as [`successors`] makes them, for a caller that knows more edges.
pub fn held_on_every_path_of<K, V>(
    next: &[Vec<usize>],
    transfer: impl Fn(usize, &mut HashMap<K, V>),
) -> Vec<HashMap<K, V>>
where
    K: Clone + Eq + Hash,
    V: Clone + Eq,
{
    // `None` until a path reaches the instruction.
    let mut held: Vec<Option<HashMap<K, V>>> = vec![None; next.len()];
    let Some(entry) = held.first_mut() else { return Vec::new() };
    *entry = Some(HashMap::new());
    let mut work = vec![0];
    while let Some(index) = work.pop() {
        let mut out = held[index].clone().unwrap_or_default();
        transfer(index, &mut out);
        for &successor in &next[index] {
            // Each join only drops entries, so the work ends.
            let joined = match &held[successor] {
                None => out.clone(),
                Some(before) => before
                    .iter()
                    .filter(|(register, value)| out.get(*register) == Some(value))
                    .map(|(register, value)| (register.clone(), value.clone()))
                    .collect(),
            };
            if held[successor].as_ref() != Some(&joined) {
                held[successor] = Some(joined);
                work.push(successor);
            }
        }
    }
    held.into_iter().map(Option::unwrap_or_default).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::Opcode;

    /// One instruction of `kind` at `address`, four bytes wide.
    fn insn(address: u64, kind: InsnKind) -> Insn {
        Insn::new(address, &[0; 4], kind, Opcode::default())
    }

    /// A load at 0 on one path, a different one at 8 on the other, and
    /// both meet at 0x10.
    fn diamond() -> Vec<Insn> {
        vec![
            insn(0x0, InsnKind::Branch { target: Some(0xc) }),
            insn(0x4, InsnKind::Normal),
            insn(0x8, InsnKind::Jump { target: Some(0x10) }),
            insn(0xc, InsnKind::Normal),
            insn(0x10, InsnKind::Return),
        ]
    }

    #[test]
    fn successors_follow_branches_jumps_and_returns() {
        assert_eq!(successors(&diamond(), |_| 0), [vec![1, 3], vec![2], vec![4], vec![4], vec![]]);
        assert!(successors(&[], |_| 0).is_empty());
    }

    #[test]
    fn a_delay_slot_runs_before_its_branch_goes() {
        let insns = [
            insn(0x0, InsnKind::Branch { target: Some(0xc) }),
            insn(0x4, InsnKind::Normal),
            insn(0x8, InsnKind::Normal),
            insn(0xc, InsnKind::Return),
        ];
        let next = successors(&insns, |insn| usize::from(insn.kind != InsnKind::Return));
        assert_eq!(next, [vec![1], vec![2, 3], vec![3], vec![]]);
        // A branch whose slot is past the end has no edge out of range.
        let last = [insn(0x0, InsnKind::Jump { target: Some(0x0) })];
        assert_eq!(successors(&last, |_| 1), [vec![1usize; 0]]);
    }

    #[test]
    fn a_jump_through_a_register_reaches_what_nothing_else_does() {
        let insns = [
            insn(0x0, InsnKind::Jump { target: None }),
            insn(0x4, InsnKind::Return),
            insn(0x8, InsnKind::Return),
        ];
        assert_eq!(successors(&insns, |_| 0), [vec![1, 2], vec![], vec![]]);
    }

    #[test]
    fn a_value_holds_only_where_every_path_agrees() {
        let insns = diamond();
        let held = held_on_every_path(
            &insns,
            |_| 0,
            |index, held: &mut HashMap<&str, u32>| match index {
                0 => drop(held.insert("same", 7)),
                1 => drop(held.insert("x", 1)),
                3 => drop(held.insert("x", 2)),
                _ => {}
            },
        );
        assert_eq!(held[2], HashMap::from([("same", 7), ("x", 1)]));
        assert_eq!(held[3], HashMap::from([("same", 7)]));
        assert_eq!(held[4], HashMap::from([("same", 7)]), "x is 1 on one path and 2 on the other");
    }

    #[test]
    fn a_loop_keeps_what_its_body_does_not_change() {
        // 0: load; 4: work; 8: back to 4 or on; c: return.
        let insns = [
            insn(0x0, InsnKind::Normal),
            insn(0x4, InsnKind::Call { target: None }),
            insn(0x8, InsnKind::Branch { target: Some(0x4) }),
            insn(0xc, InsnKind::Return),
        ];
        let held = held_on_every_path(
            &insns,
            |_| 0,
            |index, held: &mut HashMap<u8, u8>| {
                if index == 0 {
                    held.insert(26, 1);
                }
            },
        );
        assert_eq!(held[1], HashMap::from([(26, 1)]));
        assert_eq!(held[3], HashMap::from([(26, 1)]));
    }

    #[test]
    fn no_code_holds_nothing() {
        let held = held_on_every_path(&[], |_| 0, |_, _: &mut HashMap<u8, u8>| {});
        assert!(held.is_empty());
    }
}
