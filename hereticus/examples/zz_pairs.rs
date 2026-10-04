// Throwaway: list right and wrong pairs for one project, arch, two builds.
use hereticus::matching::{Options, UseNames, diff_with};
use hereticus::obj::Binary;
use std::collections::BTreeSet;
fn read(p: &str) -> Binary {
    Binary::parse(&std::fs::read(p).unwrap()).unwrap()
}
fn fname(s: &str) -> &str {
    [".isra.", ".constprop.", ".part.", ".cold"]
        .iter()
        .filter_map(|x| s.find(x))
        .min()
        .map_or(s, |e| &s[..e])
}
fn names(sym: &Binary, b: &Binary, i: usize) -> BTreeSet<String> {
    let f = &b.functions[i];
    let (a, l) = (f.address, f.code.len() as u64);
    sym.functions
        .iter()
        .filter(|s| s.address < a + l && s.address + s.code.len() as u64 > a)
        .map(|s| fname(&s.name).to_owned())
        .collect()
}
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let d = format!("fixtures/build/backports/{}-", a[1]);
    let (s0, s1) = (
        read(&format!("{d}before/{}-{}/lib.so", a[2], a[3])),
        read(&format!("{d}after/{}-{}/lib.so", a[2], a[4])),
    );
    let (b0, b1) = (
        read(&format!("{d}before/{}-{}/lib-stripped.so", a[2], a[3])),
        read(&format!("{d}after/{}-{}/lib-stripped.so", a[2], a[4])),
    );
    let diff = diff_with(&b0, &b1, Options { use_names: UseNames::No, ..Default::default() });
    for p in &diff.matched {
        let (l, r) = (names(&s0, &b0, p.before), names(&s1, &b1, p.after));
        if l.is_empty() || r.is_empty() {
            continue;
        }
        println!(
            "{} {:?} -> {:?} {:.2}",
            if l.is_disjoint(&r) { "WRONG" } else { "right" },
            l,
            r,
            p.score
        );
    }
}
