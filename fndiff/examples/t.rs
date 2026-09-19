use fndiff::{
    arch::decode_all,
    norm::{constant_signature, normalize_body},
    obj::Binary,
};
use std::collections::BTreeSet;
fn sigs(lvl: &str) -> Vec<(String, BTreeSet<u64>)> {
    let d = std::fs::read(format!("fixtures/build/{lvl}/basic.o")).unwrap();
    let b = Binary::parse(&d).unwrap();
    b.functions
        .iter()
        .map(|f| {
            let (i, _) = decode_all(&b.isa.arch(), &f.code, f.address);
            (f.name.clone(), constant_signature(&normalize_body(&i)))
        })
        .collect()
}
fn jac(a: &BTreeSet<u64>, b: &BTreeSet<u64>) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    a.intersection(b).count() as f64 / a.union(b).count() as f64
}
fn main() {
    let (o1, o2) = (sigs("O1"), sigs("O2"));
    println!("=== FALSE PAIRS scoring >= 0.65 (should be none) ===");
    let mut bad = 0;
    for (n1, s1) in &o1 {
        for (n2, s2) in &o2 {
            if n1 != n2 {
                let j = jac(s1, s2);
                if j >= 0.65 {
                    println!("  {n1} (O1) vs {n2} (O2) = {j:.2}  {:?} vs {:?}", s1, s2);
                    bad += 1;
                }
            }
        }
    }
    println!("  total false positives >= 0.65: {bad}");
    println!("\n=== TRUE pairs below 0.65 (misses) ===");
    for (n1, s1) in &o1 {
        for (n2, s2) in &o2 {
            if n1 == n2 {
                let j = jac(s1, s2);
                if j < 0.65 {
                    println!("  {n1} = {j:.2}  {:?} vs {:?}", s1, s2);
                }
            }
        }
    }
}
