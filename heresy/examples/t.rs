use heresy::{
    matching::{Options, UseNames, diff_with},
    obj::{Binary, Isa},
};
fn main() {
    // Does a split ever LOSE a changed byte? Check every changed byte lands
    // inside some reported function, across all three real samples.
    for (ap, bp, base, label) in [
        ("/tmp/claude-1000/raw-basic.bin", "/tmp/claude-1000/raw-basic_v2.bin", 0u64, "fixture"),
        ("/tmp/claude-1000/kernel/before.bin", "/tmp/claude-1000/kernel/after.bin", 0, "kernel"),
        (
            "/tmp/claude-1000/vendor/stub-22.03.2.bin",
            "/tmp/claude-1000/vendor/stub-22.03.5.bin",
            0x80208000,
            "vendor",
        ),
    ] {
        let a = std::fs::read(ap).unwrap();
        let b = std::fs::read(bp).unwrap();
        let ba = Binary::parse_raw(&a, base, Isa::Arm32).unwrap();
        let bb = Binary::parse_raw(&b, base, Isa::Arm32).unwrap();
        let d = diff_with(&ba, &bb, Options { use_names: UseNames::No, ..Default::default() });
        // a change is "caught" if its function pair has differing bytes AND is reported
        let mut caught = 0;
        let mut missed = 0;
        for m in &d.matched {
            let (fa, fb) = (&ba.functions[m.before], &bb.functions[m.after]);
            if fa.code != fb.code {
                if m.changed != heresy::matching::Changed::No {
                    caught += 1
                } else {
                    missed += 1;
                    println!("  {label}: MISSED {:#x}", fa.address);
                }
            }
        }
        println!(
            "{label:8}: {} funcs | byte-differing pairs: {} caught, {} silently missed | {} gone {} new",
            ba.functions.len(),
            caught,
            missed,
            d.removed.len(),
            d.added.len()
        );
    }
}
