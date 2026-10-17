//! The function symbols of a debug file, as a kernel build leaves it.

use std::path::Path;

/// A function symbol of a debug file: start, end and name.
pub type Symbol = (u64, u64, String);

/// The name of a function without the suffix of a GCC clone.
pub fn function_name(symbol: &str) -> &str {
    [".isra.", ".constprop.", ".part.", ".cold"]
        .iter()
        .filter_map(|suffix| symbol.find(suffix))
        .min()
        .map_or(symbol, |end| &symbol[..end])
}

/// The function symbols of a debug file, sorted by their start.
pub fn debug_symbols(path: &Path) -> Vec<Symbol> {
    use object::{Object, ObjectSymbol, SymbolKind};
    let data = std::fs::read(path)
        .unwrap_or_else(|err| panic!("{}: {err}; run `just test`", path.display()));
    let file = object::File::parse(&*data).expect("the debug file parses");
    let mut symbols: Vec<Symbol> = file
        .symbols()
        .filter(|symbol| symbol.kind() == SymbolKind::Text && symbol.size() > 0)
        .filter_map(|symbol| {
            let name = function_name(symbol.name().ok()?).to_owned();
            // A Thumb symbol has its low bit set.
            let start = symbol.address() & !1;
            Some((start, start + symbol.size(), name))
        })
        .collect();
    symbols.sort();
    symbols
}
