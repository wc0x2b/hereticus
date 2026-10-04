use hereticus::matching::{Changed, Options, UseNames, diff_with};
use hereticus::obj::Binary;
use std::collections::BTreeSet;
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
    let (project, v1, v2) = (&a[1], &a[2], &a[3]);
    for arch in ["arm", "thumb", "aarch64", "mips", "mipsel"] {
        for level in ["O2", "gcc-O2"] {
            let rd = |v: &str, f: &str| {
                Binary::parse(
                    &std::fs::read(format!(
                        "fixtures/build/versions/{project}-{v}/{arch}-{level}/{f}"
                    ))
                    .unwrap(),
                )
                .unwrap()
            };
            let sym = [rd(v1, "lib.so"), rd(v2, "lib.so")];
            let raw = |v: &str| {
                let lib = std::fs::read(format!(
                    "fixtures/build/versions/{project}-{v}/{arch}-{level}/lib.so"
                ))
                .unwrap();
                let file = object::File::parse(lib.as_slice()).unwrap();
                use object::{Object, ObjectSection};
                let base = file
                    .sections()
                    .filter(|s| {
                        s.address() != 0
                            && s.size() != 0
                            && s.kind() != object::SectionKind::UninitializedData
                    })
                    .map(|s| s.address())
                    .min()
                    .unwrap();
                let isa = match arch {
                    "arm" => hereticus::obj::Isa::Arm32,
                    "thumb" => hereticus::obj::Isa::Thumb2,
                    "aarch64" => hereticus::obj::Isa::Aarch64,
                    "mips" => hereticus::obj::Isa::Mips32Be,
                    _ => hereticus::obj::Isa::Mips32,
                };
                Binary::parse_raw(
                    &std::fs::read(format!(
                        "fixtures/build/versions/{project}-{v}/{arch}-{level}/lib.bin"
                    ))
                    .unwrap(),
                    base,
                    isa,
                )
                .unwrap()
            };
            let st = if a.len() > 4 {
                [raw(v1), raw(v2)]
            } else {
                [rd(v1, "lib-stripped.so"), rd(v2, "lib-stripped.so")]
            };
            let ans = diff_with(&sym[0], &sym[1], Options::default());
            let d = diff_with(
                &st[0],
                &st[1],
                Options { use_names: UseNames::No, ..Default::default() },
            );
            let must: BTreeSet<String> = ans
                .changed()
                .map(|p| fname(&sym[0].functions[p.before].name).to_owned())
                .chain(ans.removed.iter().map(|&i| fname(&sym[0].functions[i].name).to_owned()))
                .chain(ans.added.iter().map(|&i| fname(&sym[1].functions[i].name).to_owned()))
                .collect();
            let mut shown = BTreeSet::new();
            for p in &d.matched {
                let (l, r) = (names(&sym[0], &st[0], p.before), names(&sym[1], &st[1], p.after));
                if p.changed != Changed::No {
                    shown.extend(l.iter().cloned());
                    shown.extend(r.iter().cloned());
                }
                if !l.is_empty() && !r.is_empty() && l.is_disjoint(&r) {
                    {
                        let cl = hereticus::callee::callees(
                            st[0].isa.arch(),
                            &st[0].links,
                            &st[0].functions,
                            &st[0].functions[p.before],
                        );
                        let cr = hereticus::callee::callees(
                            st[1].isa.arch(),
                            &st[1].links,
                            &st[1].functions,
                            &st[1].functions[p.after],
                        );
                        println!(
                            "{arch}-{level} WRONG {:?} {:.2} {:?} -> {:?} ({:?}) len {} {} at {:x} {:x} calls {:?} {:?}",
                            p.confidence,
                            p.score,
                            l,
                            r,
                            p.changed,
                            st[0].functions[p.before].code.len(),
                            st[1].functions[p.after].code.len(),
                            st[0].functions[p.before].address,
                            st[1].functions[p.after].address,
                            cl,
                            cr
                        );
                    }
                }
            }
            for &i in &d.removed {
                shown.extend(names(&sym[0], &st[0], i));
            }
            for &i in &d.added {
                shown.extend(names(&sym[1], &st[1], i));
            }
            for m in must.difference(&shown) {
                println!("{arch}-{level} MISSED {m}");
                for p in &d.matched {
                    let (l, r) =
                        (names(&sym[0], &st[0], p.before), names(&sym[1], &st[1], p.after));
                    if l.contains(m) || r.contains(m) {
                        println!(
                            "    in {:?} {:.3} {:?} -> {:?} ({:?}) at {:x} {:x}",
                            p.confidence,
                            p.score,
                            l,
                            r,
                            p.changed,
                            st[0].functions[p.before].address,
                            st[1].functions[p.after].address
                        );
                    }
                }
            }
        }
    }
}
