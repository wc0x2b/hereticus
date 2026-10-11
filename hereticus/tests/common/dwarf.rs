//! The source file of each function, from the DWARF of a debug file, and
//! which files of one build went on as which of another.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// A range of code and a name: start, end and the name.
pub type Symbol = (u64, u64, String);

/// The source file that declares each function a debug file describes, as
/// a [`Symbol`] whose name is the file, sorted by its start.
///
/// The file is read from `DW_AT_decl_file` of each `DW_TAG_subprogram`
/// with code, or of the entry it names as its abstract origin or its
/// specification,
/// and the path is cut as [`source_relative`] does.
pub fn source_files(path: &Path) -> Vec<Symbol> {
    use gimli::{AttributeValue, DebugInfoOffset, EndianSlice, RunTimeEndian, constants};
    use object::{Object, ObjectSection};
    use std::borrow::Cow;
    let data = std::fs::read(path)
        .unwrap_or_else(|err| panic!("{}: {err}; run `just test`", path.display()));
    let file = object::File::parse(&*data).expect("the debug file parses");
    let endian = if file.is_little_endian() { RunTimeEndian::Little } else { RunTimeEndian::Big };
    let sections = gimli::DwarfSections::load(|id| -> Result<Cow<'_, [u8]>, gimli::Error> {
        Ok(file
            .section_by_name(id.name())
            .and_then(|section| section.uncompressed_data().ok())
            .unwrap_or(Cow::Borrowed(&[])))
    })
    .expect("the DWARF sections load");
    let dwarf = sections.borrow(|section| EndianSlice::new(section, endian));

    // Under LTO, the entry of a function with code names its file through
    // an abstract origin, often in another unit. So each entry is first
    // recorded by its offset in `.debug_info`: its file, or the entry it
    // takes its file from.
    let reference = |unit: &gimli::Unit<_>, value| match value {
        AttributeValue::UnitRef(offset) => offset.to_debug_info_offset(&unit.header),
        AttributeValue::DebugInfoRef(offset) => Some(offset),
        _ => None,
    };
    let mut origins: BTreeMap<DebugInfoOffset, (Option<String>, Option<DebugInfoOffset>)> =
        BTreeMap::new();
    let mut functions: Vec<(u64, u64, DebugInfoOffset)> = Vec::new();
    let mut headers = dwarf.units();
    while let Some(header) = headers.next().expect("a unit header reads") {
        let unit = dwarf.unit(header).expect("a unit reads");
        let line_header = unit.line_program.as_ref().map(|program| program.header().clone());
        let file_name = |index: u64| -> Option<String> {
            let line_header = line_header.as_ref()?;
            let entry = line_header.file(index)?;
            let name = dwarf.attr_string(&unit, entry.path_name()).ok()?;
            let directory = entry
                .directory(line_header)
                .and_then(|directory| dwarf.attr_string(&unit, directory).ok());
            let joined = match directory {
                Some(directory) => {
                    format!("{}/{}", directory.to_string_lossy(), name.to_string_lossy())
                }
                None => name.to_string_lossy().into_owned(),
            };
            Some(source_relative(&joined).to_owned())
        };
        let mut entries = unit.entries();
        while let Some(entry) = entries.next_dfs().expect("an entry reads") {
            if entry.tag() != constants::DW_TAG_subprogram {
                continue;
            }
            let Some(offset) = entry.offset().to_debug_info_offset(&unit.header) else { continue };
            let file = match entry.attr_value(constants::DW_AT_decl_file) {
                Some(AttributeValue::FileIndex(index) | AttributeValue::Udata(index)) => {
                    file_name(index)
                }
                _ => None,
            };
            let origin = [constants::DW_AT_abstract_origin, constants::DW_AT_specification]
                .iter()
                .find_map(|&at| reference(&unit, entry.attr_value(at)?));
            if file.is_some() || origin.is_some() {
                origins.insert(offset, (file, origin));
            }
            if let Ok(mut ranges) = dwarf.die_ranges(&unit, entry) {
                while let Ok(Some(range)) = ranges.next() {
                    if range.begin < range.end {
                        functions.push((range.begin, range.end, offset));
                    }
                }
            }
        }
    }

    let file_of = |mut offset: DebugInfoOffset| {
        for _ in 0..4 {
            match origins.get(&offset)? {
                (Some(file), _) => return Some(file.clone()),
                (None, Some(next)) => offset = *next,
                (None, None) => return None,
            }
        }
        None
    };
    let mut files: Vec<Symbol> = functions
        .into_iter()
        // A Thumb function has its low bit set.
        .filter_map(|(start, end, offset)| Some((start & !1, end & !1, file_of(offset)?)))
        .collect();
    files.sort();
    files
}

/// A path cut to what follows the versioned source directory, as
/// `mm/filemap.c` from `.../linux-5.10.146/mm/filemap.c`, or `lib/url.c`
/// from `/build/curl-yrY3l1/curl-7.81.0/lib/url.c`. The directories above
/// it differ from build to build.
pub fn source_relative(path: &str) -> &str {
    let path = path.strip_prefix("./").unwrap_or(path);
    let mut at = 0;
    for component in path.split('/') {
        at += component.len() + 1;
        let versioned = component.rsplit_once('-').is_some_and(|(name, version)| {
            !name.is_empty() && version.starts_with(|c: char| c.is_ascii_digit())
        });
        if versioned {
            return path.get(at..).unwrap_or(path);
        }
    }
    path
}

/// Which source files of the earlier release went on as which of the later.
///
/// Between releases, code moves to other files: `kernel/futex.c`
/// became `kernel/futex/core.c`, and `net/core/ethtool.c` became
/// `net/ethtool/ioctl.c`. Two files correspond where they share a path, or
/// where [`FEWEST_MOVED_NAMES`] or more function names that each release
/// holds once live in the one file before and in the other after.
pub struct FileMoves<'a> {
    moved: BTreeSet<(&'a str, &'a str)>,
}

/// See [`FileMoves`]: one name alone can be a homonym.
const FEWEST_MOVED_NAMES: usize = 2;

impl<'a> FileMoves<'a> {
    pub fn new(symbols: &'a [Vec<Symbol>; 2], sources: &'a [Vec<Symbol>; 2]) -> Self {
        // The file of each name that one function of the release holds.
        let files_by_name = |side: usize| {
            let file_at: BTreeMap<u64, &str> =
                sources[side].iter().map(|source| (source.0, source.2.as_str())).collect();
            let mut by_name: BTreeMap<&str, Option<&str>> = BTreeMap::new();
            for symbol in &symbols[side] {
                let Some(&file) = file_at.get(&symbol.0) else { continue };
                by_name
                    .entry(symbol.2.as_str())
                    .and_modify(|seen| *seen = None)
                    .or_insert(Some(file));
            }
            by_name
        };
        let [before, after] = [files_by_name(0), files_by_name(1)];
        let mut shared: BTreeMap<(&str, &str), usize> = BTreeMap::new();
        for (name, &file) in &before {
            if let (Some(file), Some(Some(other))) = (file, after.get(name)) {
                *shared.entry((file, other)).or_default() += 1;
            }
        }
        let moved = shared
            .into_iter()
            .filter(|&(_, count)| count >= FEWEST_MOVED_NAMES)
            .map(|(files, _)| files)
            .collect();
        Self { moved }
    }

    pub fn corresponds(&self, before: &str, after: &str) -> bool {
        before == after || self.moved.contains(&(before, after))
    }
}

#[test]
fn a_path_is_cut_below_its_versioned_source_directory() {
    let kernel = "target-arm_cortex-a7+neon-vfpv4_musl_eabi/linux-ipq40xx_generic/linux-5.10.146/mm/filemap.c";
    assert_eq!(source_relative(kernel), "mm/filemap.c");
    assert_eq!(source_relative("/build/curl-yrY3l1/curl-7.81.0/lib/url.c"), "lib/url.c");
    assert_eq!(source_relative("./include/net/udplite.h"), "include/net/udplite.h");
    assert_eq!(source_relative("lib/url.c"), "lib/url.c");
    assert_eq!(source_relative(""), "");
}
