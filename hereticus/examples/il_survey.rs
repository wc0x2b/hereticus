//! Scratch: one example of each mnemonic in the binaries named on the
//! command line, with its assembly and its IL, to read each lift once.
//! `SAMPLES=n` keeps n examples of each, with different operands.
use std::collections::BTreeMap;

use hereticus::obj::Binary;
use hereticus::recovery::arch::decode_all;
use hereticus::view::il_statements_in;

fn main() {
    let samples: usize = std::env::var("SAMPLES").ok().and_then(|n| n.parse().ok()).unwrap_or(1);
    let mut seen: BTreeMap<String, (usize, Vec<(String, String)>)> = BTreeMap::new();
    for path in std::env::args().skip(1) {
        let Ok(data) = std::fs::read(&path) else { continue };
        let Ok(binary) = Binary::parse(&data) else { continue };
        for function in &binary.functions {
            let arch = binary.isa_of(function).arch();
            let (insns, _) = decode_all(arch, &function.code, function.address);
            let statements = il_statements_in(arch, &function.code, &insns, None);
            let by_address: std::collections::HashMap<u64, String> = statements
                .into_iter()
                .map(|statement| (statement.address, statement.text))
                .collect();
            for insn in &insns {
                let Some(line) = by_address.get(&insn.address).cloned() else { continue };
                let asm = insn.to_string();
                if asm == line {
                    continue;
                }
                let mnemonic =
                    format!("{} {}", arch.triple(), hereticus::il::arch::printed_name(insn));
                let entry = seen.entry(mnemonic).or_default();
                entry.0 += 1;
                if entry.1.len() < samples && entry.1.iter().all(|(_, il)| *il != line) {
                    entry.1.push((asm, line));
                }
            }
        }
    }
    for (mnemonic, (count, examples)) in seen {
        for (asm, il) in examples {
            println!("{mnemonic:24} {count:>7}  {asm:40} | {il}");
        }
    }
}
