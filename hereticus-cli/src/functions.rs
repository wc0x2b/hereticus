//! The functions of one binary, as `--functions` lists them.
//!
//! The list lets another tool use the scan without the comparison: a Ghidra
//! script reads the JSON and makes a function at each address that Ghidra
//! missed.

use hereticus::address::Contents;
use hereticus::matching::contents_of;
use hereticus::obj::{Binary, FoundBy, Function, Isa};
use tabled::settings::object::Columns;
use tabled::settings::style::HorizontalLine;
use tabled::settings::{Alignment, Style};
use tabled::{Table, Tabled};

use super::Format;
use crate::formats::json_string;

/// One function, with what a listing says about it.
struct Listed<'a> {
    function: &'a Function,
    isa: Isa,
    contents: Contents,
}

impl<'a> Listed<'a> {
    fn of(binary: &'a Binary) -> impl Iterator<Item = Self> + 'a {
        binary.functions.iter().map(move |function| Self {
            function,
            isa: binary.isa_of(function),
            contents: contents_of(binary, function),
        })
    }
}

#[derive(Tabled)]
struct Row {
    #[tabled(rename = "ADDRESS")]
    address: String,
    #[tabled(rename = "SIZE")]
    size: usize,
    #[tabled(rename = "ISA")]
    isa: &'static str,
    #[tabled(rename = "HOLDS")]
    holds: &'static str,
    #[tabled(rename = "FUNCTION")]
    function: String,
}

impl From<&Listed<'_>> for Row {
    fn from(listed: &Listed<'_>) -> Self {
        Self {
            address: format!("{:#x}", listed.function.address),
            size: listed.function.code.len(),
            isa: name_of_isa(listed.isa),
            holds: name_of_contents(listed.contents),
            function: listed.function.label(),
        }
    }
}

/// The size column is a number, so it reads better against the right edge.
const SIZE_COLUMN: usize = 1;

/// Print every function of `binary`, in the order of their addresses.
pub(crate) fn print_functions(binary: &Binary, format: Format) {
    let listed = Listed::of(binary);
    match format {
        Format::Text => {
            let mut table = Table::new(listed.map(|listed| Row::from(&listed)));
            table
                .with(
                    Style::rounded()
                        .horizontals([(1, HorizontalLine::inherit(Style::modern_rounded()))]),
                )
                .with(Alignment::left())
                .modify(Columns::one(SIZE_COLUMN), Alignment::right());
            println!("{table}");
        }
        Format::Compact => {
            for listed in listed {
                let row = Row::from(&listed);
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    row.address, row.size, row.isa, row.holds, row.function
                );
            }
        }
        Format::Markdown => {
            let mut table = Table::new(listed.map(|listed| Row::from(&listed)));
            table.with(Style::markdown());
            println!("{table}");
        }
        Format::Json => println!("{}", json_functions(binary)),
    }
}

/// The functions of `binary` as one JSON object.
///
/// Every address and size is a number, not a string, so a tool can do
/// arithmetic on it. The addresses are the ones the binary is linked at, so
/// a tool that loads it at another base must move them.
fn json_functions(binary: &Binary) -> String {
    let functions: Vec<String> = Listed::of(binary)
        .map(|listed| {
            format!(
                "{{\"name\":{},\"address\":{},\"size\":{},\"isa\":\"{}\",\"holds\":\"{}\"}}",
                json_string(&listed.function.label()),
                listed.function.address,
                listed.function.code.len(),
                name_of_isa(listed.isa),
                name_of_contents(listed.contents),
            )
        })
        .collect();
    let found_by = match binary.found_by {
        FoundBy::Symbols => "symbols",
        FoundBy::Scanning => "scanning",
    };
    format!(
        "{{\"isa\":\"{}\",\"found_by\":\"{found_by}\",\"functions\":[{}]}}",
        name_of_isa(binary.isa),
        functions.join(",")
    )
}

/// The name `--arch` takes for an instruction set.
fn name_of_isa(isa: Isa) -> &'static str {
    match isa {
        Isa::Arm32 => "arm32",
        Isa::Thumb2 => "thumb2",
        Isa::Arm32Be8 => "arm32-be8",
        Isa::Thumb2Be8 => "thumb2-be8",
        Isa::Aarch64 => "aarch64",
        Isa::Mips32 => "mips32",
        Isa::Mips32Be => "mips32-be",
        Isa::Mips16 => "mips16",
        Isa::Mips16Be => "mips16-be",
        Isa::X86_64 => "x86-64",
        Isa::X86 => "x86",
    }
}

fn name_of_contents(contents: Contents) -> &'static str {
    match contents {
        Contents::Code => "code",
        Contents::Data => "data",
    }
}

#[cfg(test)]
mod tests {
    use clap::ValueEnum;

    use super::*;
    use crate::ArchName;

    /// A listing names each instruction set as `--arch` takes it, so a tool
    /// can give the name back to `--arch`.
    #[test]
    fn each_isa_takes_the_name_arch_takes() {
        for &arch in ArchName::value_variants() {
            let wanted = arch.to_possible_value().expect("each architecture has a name");
            assert_eq!(name_of_isa(arch.into()), wanted.get_name());
        }
    }
}
