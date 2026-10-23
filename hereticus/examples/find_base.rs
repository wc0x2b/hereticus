//! Rank the bases of raw images, and time it: `cargo run --release
//! --example find_base -- ARCH FILE...`.

use hereticus::obj::Isa;
use hereticus::raw::rank_bases;

fn main() {
    let mut args = std::env::args().skip(1);
    let isa = match args.next().as_deref() {
        Some("arm32") => Isa::Arm32,
        Some("thumb2") => Isa::Thumb2,
        Some("aarch64") => Isa::Aarch64,
        Some("mips32") => Isa::Mips32,
        Some("mips32-be") => Isa::Mips32Be,
        Some("x86") => Isa::X86,
        Some("x86-64") => Isa::X86_64,
        other => panic!("unknown arch {other:?}"),
    };
    for path in args {
        let mut data = std::fs::read(&path).expect("a file");
        if path.ends_with(".elf") {
            let (base, flat) = flatten(&data);
            let truth = hereticus::raw::measure_base(&flat, isa.arch(), base);
            println!(
                "truth {base:#x}  strings {}  functions {}  expected {:.0}",
                truth.strings, truth.functions, truth.expected
            );
            data = flat;
        }
        let at = std::time::Instant::now();
        let ranked = rank_bases(&data, isa.arch());
        let took = at.elapsed();
        println!("{path} ({} bytes) in {took:?}", data.len());
        for candidate in ranked.iter().take(4) {
            println!(
                "  {:#x}  strings {}  functions {}  expected {:.0}  excess {:.0}",
                candidate.base,
                candidate.strings,
                candidate.functions,
                candidate.expected,
                candidate.excess()
            );
        }
        println!(
            "  winner {:?}",
            hereticus::raw::clear_winner(&ranked).map(|base| format!("{base:#x}"))
        );
    }
}

/// The loaded segments of an ELF, laid out from the lowest, at the address
/// each loads from, as a flash dump holds them, with that address.
fn flatten(elf: &[u8]) -> (u64, Vec<u8>) {
    use object::Endianness;
    use object::read::elf::{ElfFile32, ElfFile64, ProgramHeader};
    let segments: Vec<(u64, Vec<u8>)> = if let Ok(file) = ElfFile32::<Endianness>::parse(elf) {
        let endian = file.endian();
        file.elf_program_headers()
            .iter()
            .filter(|header| header.p_type(endian) == object::elf::PT_LOAD)
            .map(|header| {
                (
                    u64::from(header.p_paddr(endian)),
                    header.data(endian, elf).expect("data").to_vec(),
                )
            })
            .collect()
    } else {
        let file = ElfFile64::<Endianness>::parse(elf).expect("an ELF");
        let endian = file.endian();
        file.elf_program_headers()
            .iter()
            .filter(|header| header.p_type(endian) == object::elf::PT_LOAD)
            .map(|header| {
                (header.p_paddr(endian), header.data(endian, elf).expect("data").to_vec())
            })
            .collect()
    };
    let base = segments.iter().map(|(address, _)| *address).min().expect("a segment");
    let end = segments
        .iter()
        .map(|(address, bytes)| address + bytes.len() as u64)
        .max()
        .expect("a segment");
    let mut image = vec![0; (end - base) as usize];
    for (address, bytes) in segments {
        let at = (address - base) as usize;
        image[at..at + bytes.len()].copy_from_slice(&bytes);
    }
    (base, image)
}
