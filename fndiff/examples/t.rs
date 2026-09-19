use fndiff::obj::{Binary, Isa};
fn main() {
    for d in [vec![0x00, 0x01], vec![0x00, 0x01, 0x02], vec![0x1e, 0xff, 0x2f, 0xe1]] {
        match Binary::parse_raw(&d, 0, Isa::Arm32) {
            Ok(b) => println!(
                "{} bytes -> {} functions, first code len {}",
                d.len(),
                b.functions.len(),
                b.functions.first().map_or(0, |f| f.code.len())
            ),
            Err(e) => println!("{} bytes -> error: {e}", d.len()),
        }
    }
}
