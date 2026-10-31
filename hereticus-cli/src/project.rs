//! Save a comparison as a project, and open it again: the parts of
//! `hereticus-project` that the flags of the command line decide.

pub use hereticus_project::*;

use crate::{Args, Base};

/// Describe how `args` read the two binaries.
pub fn source_of(args: &Args, inputs: [Input; 2]) -> Source {
    let raw = args.raw.then(|| Raw {
        base: match args.base {
            Some(Base::Address(base)) => Some(base),
            Some(Base::Auto) | None => None,
        },
        auto_base: args.base == Some(Base::Auto),
        arch: args.arch,
        unpack: args.unpack,
    });
    let names = if args.ignore_names { Names::Ignore } else { Names::Use };
    Source { inputs, raw, threshold: args.threshold, names }
}

/// The arguments that read the two binaries as `source` did, with every
/// other flag as `args` gives it.
pub fn replay(source: &Source, args: &Args) -> Args {
    let raw = source.raw.as_ref();
    Args {
        before: Some(source.inputs[0].path.clone()),
        after: Some(source.inputs[1].path.clone()),
        raw: raw.is_some(),
        base: raw.and_then(|raw| match (raw.auto_base, raw.base) {
            (true, _) => Some(Base::Auto),
            (false, base) => base.map(Base::Address),
        }),
        arch: raw.map_or(args.arch, |raw| raw.arch),
        unpack: raw.and_then(|raw| raw.unpack),
        threshold: source.threshold,
        ignore_names: source.names == Names::Ignore,
        ..args.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn input(bytes: &[u8]) -> Input {
        Input {
            path: PathBuf::from("/tmp/a.elf"),
            anchor: Anchor::Absolute,
            sha256: sha256_hex(bytes),
            functions: String::new(),
        }
    }

    #[test]
    fn a_source_reads_the_binaries_again_as_the_first_run_did() {
        use clap::Parser;
        let first = Args::parse_from([
            "hereticus",
            "--raw",
            "--base",
            "0x80000000",
            "--arch",
            "mips32-be",
            "--unpack",
            "kernel",
            "--threshold",
            "0.5",
            "--ignore-names",
            "a.bin",
            "b.bin",
        ]);
        let source = source_of(&first, [input(b"a"), input(b"b")]);
        let text = serde_json::to_string(&source).expect("a source serializes");
        assert!(text.contains(r#""arch":"mips32-be""#), "{text}");
        let source: Source = serde_json::from_str(&text).expect("a source reads back");

        let later = Args::parse_from(["hereticus", "--open", "p.json", "--sort", "removed"]);
        let replayed = replay(&source, &later);
        assert!(replayed.raw && replayed.ignore_names);
        assert_eq!(replayed.base, Some(Base::Address(0x8000_0000)));
        assert_eq!(replayed.arch, ArchName::Mips32Be);
        assert_eq!(replayed.unpack, Some(PartName::Kernel));
        assert_eq!(replayed.threshold, 0.5);
        assert_eq!(replayed.before, Some(PathBuf::from("/tmp/a.elf")));
        assert_eq!(replayed.sort, crate::Sort::Removed, "a flag of the report stays");

        // `--base auto` finds the base again when the project opens.
        let auto = Args::parse_from(["hereticus", "--raw", "--base", "auto", "a.bin", "b.bin"]);
        let source = source_of(&auto, [input(b"a"), input(b"b")]);
        let text = serde_json::to_string(&source).expect("a source serializes");
        let source: Source = serde_json::from_str(&text).expect("a source reads back");
        assert_eq!(replay(&source, &later).base, Some(Base::Auto));

        // A binary with a container format leaves `--raw` off.
        let plain = Args::parse_from(["hereticus", "a.elf", "b.elf"]);
        let replayed = replay(&source_of(&plain, [input(b"a"), input(b"b")]), &later);
        assert!(!replayed.raw && !replayed.ignore_names);
        assert_eq!((replayed.base, replayed.unpack), (None, None));
    }
}
