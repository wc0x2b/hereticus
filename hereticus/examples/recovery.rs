//! Compare the functions that the scan finds in a stripped binary against
//! the symbols of the same build.
//!
//! ```text
//! cargo run --release --example recovery -- <with symbols> <stripped> [shown]
//! ```
//!
//! A distribution ships its debug symbols apart: `eu-unstrip` joins them to
//! the stripped binary, which gives the first argument. The report counts
//! the functions found exactly, the starts missed and invented, and the
//! functions that start right but end wrong, and lists up to `shown` of
//! each kind (30 if not given) with what told the scan of each invented
//! start. The padding at the end of a function counts on neither side.

use std::collections::BTreeMap;

use hereticus::obj::Binary;
use hereticus::recovery::scan::{Source, recover_functions};
use object::{Object, ObjectSection};

/// Where each function starts, mapped to where it ends and its name.
type Spans = BTreeMap<u64, (u64, String)>;

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let [_, with_symbols, stripped, rest @ ..] = args.as_slice() else {
        return Err("usage: recovery <with symbols> <stripped> [shown]".to_string());
    };
    let shown = match rest.first() {
        Some(shown) => shown.parse().map_err(|error| format!("{shown}: {error}"))?,
        None => 30,
    };
    let read = |path: &str| std::fs::read(path).map_err(|error| format!("{path}: {error}"));
    let (with_symbols, stripped) = (read(with_symbols)?, read(stripped)?);
    let parse = |data: &[u8]| Binary::parse(data).map_err(|error| error.to_string());
    let (truth, found) = (parse(&with_symbols)?, parse(&stripped)?);

    // The PLT, and the lazy binding stubs of MIPS, are code no symbol
    // names, so the scan's stubs there are no error.
    let file = object::File::parse(with_symbols.as_slice()).map_err(|error| error.to_string())?;
    let stubs: Vec<core::ops::Range<u64>> = file
        .sections()
        .filter(|section| {
            section.name().is_ok_and(|name| name.starts_with(".plt") || name == ".MIPS.stubs")
        })
        .map(|section| section.address()..section.address() + section.size())
        .collect();
    let Some(middle) = found.functions.get(found.functions.len() / 2) else {
        return Err("the stripped binary holds no function".to_string());
    };
    let arch = found.isa_of(middle).arch();
    // Go counts the padding after a function in the size of its symbol, and
    // the scan leaves padding out, so both ends are read without it.
    let spans = |binary: &Binary| -> Spans {
        binary
            .functions
            .iter()
            .filter(|function| !stubs.iter().any(|range| range.contains(&function.address)))
            .map(|function| {
                let end = function.address + arch.trim_padding(&function.code).len() as u64;
                (function.address, (end, function.name.clone()))
            })
            .collect()
    };
    let (truth_spans, found_spans) = (spans(&truth), spans(&found));

    let sources: BTreeMap<u64, Source> = recover_functions(&stripped, arch)
        .into_iter()
        .map(|recovered| (recovered.address, recovered.source))
        .collect();

    report(&truth_spans, &found_spans, &sources, shown);
    Ok(())
}

fn report(truth: &Spans, found: &Spans, sources: &BTreeMap<u64, Source>, shown: usize) {
    let exact = truth
        .iter()
        .filter(|(start, (end, _))| found.get(start).is_some_and(|(found_end, _)| found_end == end))
        .count();
    let missed: Vec<u64> =
        truth.keys().filter(|start| !found.contains_key(start)).copied().collect();
    let invented: Vec<u64> =
        found.keys().filter(|start| !truth.contains_key(start)).copied().collect();
    let wrong_end: Vec<(u64, u64, &str, u64)> = truth
        .iter()
        .filter_map(|(&start, (end, name))| {
            let (found_end, _) = found.get(&start)?;
            (found_end != end).then_some((start, *end, name.as_str(), *found_end))
        })
        .collect();
    println!(
        "functions {} exact {exact} missed {} invented {} wrong_end {}",
        truth.len(),
        missed.len(),
        invented.len(),
        wrong_end.len()
    );

    // The symbol an address falls in, as `name+offset`.
    let place = |address: u64| match truth.range(..=address).next_back() {
        Some((start, (end, name))) => {
            let past = if address >= *end { " (past end)" } else { "" };
            format!("{name}+{:#x}{past}", address - start)
        }
        None => "?".to_string(),
    };
    for start in missed.iter().take(shown) {
        println!("missed   {start:#x} {}", truth[start].1);
    }
    for start in invented.iter().take(shown) {
        let source = sources.get(start).map_or("?".to_string(), |source| format!("{source:?}"));
        println!(
            "invented {start:#x} in {}  ends {:#x} by {source}",
            place(*start),
            found[start].0
        );
    }
    for (start, end, name, found_end) in wrong_end.iter().take(shown) {
        println!("end      {start:#x} {name} true end {end:#x} found {found_end:#x}");
    }
}
