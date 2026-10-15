//! Read binaries and find the functions in them.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use object::elf::PF_X;
use object::{
    Object, ObjectKind, ObjectSection, ObjectSegment, ObjectSymbol, SegmentFlags, SymbolKind,
};

use crate::Links;
use crate::links::{ByteOrder, Width};
use hereticus_arch::Arch;
use hereticus_il::arch::aarch64::Aarch64;
use hereticus_il::arch::arm32::Arm32;
use hereticus_il::arch::mips::Mips32;
use hereticus_il::arch::thumb::Thumb2;
use hereticus_memory::AddressSpace;
pub use hereticus_memory::Function;
use hereticus_recovery::dynamic::Dynamic;
use hereticus_recovery::mips_stubs;
use hereticus_recovery::scan;
use hereticus_recovery::unwind;

/// Why a binary could not be read.
#[derive(Debug)]
pub enum ObjError {
    /// The bytes are not an object file this crate can read.
    Parse(object::Error),
    /// The file is a valid object, but not for an architecture `hereticus` knows.
    UnsupportedArch(object::Architecture),
    /// The file holds no executable code.
    NoCode,
    /// The file holds code, but no function could be found in it.
    ///
    /// Reported rather than returning nothing, because an empty result would
    /// read as "nothing changed" when the truth is "nothing was examined".
    NoFunctions,
}

impl core::fmt::Display for ObjError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parse(err) => write!(f, "cannot parse object: {err}"),
            Self::UnsupportedArch(arch) => write!(f, "unsupported architecture: {arch:?}"),
            Self::NoCode => write!(f, "object has no executable code"),
            Self::NoFunctions => {
                write!(f, "object has code, but no function could be found in it")
            }
        }
    }
}

impl core::error::Error for ObjError {}

impl From<object::Error> for ObjError {
    fn from(err: object::Error) -> Self {
        Self::Parse(err)
    }
}

/// The architectures `hereticus` can decode.
///
/// More variants arrive as more decoders do. Keeping this an enum rather than
/// a boxed trait object lets the matcher check that two binaries agree on
/// architecture before it compares them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Isa {
    Arm32,
    /// ARM32 in Thumb-2 mode, as most Cortex-M firmware and much ARM user
    /// space is built.
    Thumb2,
    /// ARMv8-A in AArch64 mode, 64-bit.
    Aarch64,
    /// MIPS32, little endian, as a desktop-built object usually is.
    Mips32,
    /// MIPS32, big endian, as most shipped firmware is.
    Mips32Be,
    /// MIPS16e, little endian, which much MIPS user space is built as.
    Mips16,
    /// MIPS16e, big endian.
    Mips16Be,
}

impl Isa {
    /// The decoder for this architecture.
    ///
    /// Returned behind the trait so that everything above [`hereticus_arch`]
    /// works on any architecture. Adding a variant here must not oblige a
    /// caller to change.
    pub fn arch(self) -> &'static dyn Arch {
        match self {
            Self::Arm32 => &Arm32,
            Self::Thumb2 => &Thumb2,
            Self::Aarch64 => &Aarch64,
            Self::Mips32 => &Mips32::LITTLE,
            Self::Mips32Be => &Mips32::BIG,
            Self::Mips16 => &hereticus_il::arch::mips16::Mips16::LITTLE,
            Self::Mips16Be => &hereticus_il::arch::mips16::Mips16::BIG,
        }
    }

    /// The other instruction set of a core that runs two, as ARM runs A32 and
    /// Thumb-2, or `None`.
    pub fn other_set(self) -> Option<Self> {
        match self {
            Self::Arm32 => Some(Self::Thumb2),
            Self::Thumb2 => Some(Self::Arm32),
            Self::Mips32 => Some(Self::Mips16),
            Self::Mips16 => Some(Self::Mips32),
            Self::Mips32Be => Some(Self::Mips16Be),
            Self::Mips16Be => Some(Self::Mips32Be),
            Self::Aarch64 => None,
        }
    }

    /// The width of an address.
    pub fn address_width(self) -> Width {
        match self {
            Self::Aarch64 => Width::Bits64,
            _ => Width::Bits32,
        }
    }

    /// The order of the bytes of a word of data.
    pub fn byte_order(self) -> ByteOrder {
        match self {
            Self::Mips32Be | Self::Mips16Be => ByteOrder::Big,
            _ => ByteOrder::Little,
        }
    }

    /// Choose a decoder for what an object file says it holds.
    ///
    /// `little_endian` decides nothing for ARM, which is only read in that
    /// order anyway, and decides which decoder for MIPS, which ships in both.
    fn from_object(arch: object::Architecture, little_endian: bool) -> Result<Self, ObjError> {
        match arch {
            object::Architecture::Arm => Ok(Self::Arm32),
            object::Architecture::Aarch64 => Ok(Self::Aarch64),
            object::Architecture::Mips if little_endian => Ok(Self::Mips32),
            object::Architecture::Mips => Ok(Self::Mips32Be),
            _ => Err(ObjError::UnsupportedArch(arch)),
        }
    }
}

/// Where a word lies, as [`Coverage::place_of`] tells.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Place {
    /// Outside every function.
    #[default]
    Outside,
    /// Inside a function: code, a literal pool, or data that a scan of a
    /// raw image took for the end of a function.
    InFunction,
}

/// The extent of the functions of a binary.
struct Coverage {
    /// The start of each function in order, and the furthest end of it
    /// and every function before it, so that one search answers.
    starts_and_ends: Vec<(u64, u64)>,
}

impl Coverage {
    fn of(functions: &[Function]) -> Self {
        let mut starts_and_ends: Vec<(u64, u64)> = functions
            .iter()
            .map(|function| (function.address, function.address + function.code.len() as u64))
            .collect();
        starts_and_ends.sort_unstable();
        let mut furthest = 0;
        for (_, end) in &mut starts_and_ends {
            furthest = furthest.max(*end);
            *end = furthest;
        }
        Self { starts_and_ends }
    }

    /// Where `address` lies.
    fn place_of(&self, address: u64) -> Place {
        let after = self.starts_and_ends.partition_point(|&(start, _)| start <= address);
        match after.checked_sub(1).map(|last| self.starts_and_ends[last].1) {
            Some(end) if address < end => Place::InFunction,
            _ => Place::Outside,
        }
    }
}

/// A run of addresses of functions that may make a table.
#[derive(Default)]
struct Run {
    functions: Vec<usize>,
    /// Inside a function where any word of the run is.
    place: Place,
}

impl Run {
    /// Add the function whose address lies at `place`.
    fn push(&mut self, function: usize, place: Place) {
        self.functions.push(function);
        if place == Place::InFunction {
            self.place = place;
        }
    }

    /// The table this run makes, if any, and start a new run.
    ///
    /// Two addresses make a table outside every function. Inside one, as
    /// in a literal pool, it takes three: two words of code can read as
    /// addresses by chance. Measured on tinyxml2 for Thumb-2 as a raw image
    /// loaded at zero, such pairs paired four functions wrong. A scan of a
    /// raw kernel takes its data for the end of a function, so its tables
    /// count as inside too.
    fn end(&mut self) -> Option<Vec<usize>> {
        let shortest = match self.place {
            Place::InFunction => 3,
            Place::Outside => 2,
        };
        let run = core::mem::take(self);
        (run.functions.len() >= shortest).then_some(run.functions)
    }
}

/// Where the functions of a binary came from.
///
/// A caller should treat a scanned binary more carefully than one read from a
/// symbol table: boundaries found by scanning can be wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoundBy {
    /// The symbol table named every function.
    Symbols,
    /// The binary is stripped, so the functions were recovered from the code,
    /// or from what the linker left, as the `LC_FUNCTION_STARTS` of Mach-O.
    /// Only the names of what the binary exports are left.
    Scanning,
}

/// A binary, with the functions found in it.
#[derive(Clone, Debug)]
pub struct Binary {
    pub isa: Isa,
    pub functions: Vec<Function>,
    /// How the functions were found.
    pub found_by: FoundBy,
    /// Where the binary sits in memory, which tells an address from a number.
    pub addresses: AddressSpace,
    /// What the linker left that names the callee of each call.
    pub links: Links,
    /// The addresses of the functions in [`Isa::other_set`] of `isa`.
    ///
    /// An ARM library can mix A32 and Thumb-2 functions, and bit 0 of each
    /// symbol says which a function is. `isa` is the set most of them are
    /// in. Empty where the binary holds one set, or where nothing says.
    pub other_set: BTreeSet<u64>,
}

impl Binary {
    /// The instruction set `function`, one of this binary's, is in.
    pub fn isa_of(&self, function: &Function) -> Isa {
        match self.isa.other_set() {
            Some(other) if self.other_set.contains(&function.address) => other,
            _ => self.isa,
        }
    }

    /// The tables of functions the data holds, each as the indices of its
    /// functions in order: runs of words in a row, each the address of a
    /// function, as a C++ vtable or a C table of handlers.
    ///
    /// Bit 0 of an address is dropped, since on ARM and MIPS it only says
    /// the function runs as Thumb-2 or MIPS16e.
    pub fn function_tables(&self) -> Vec<Vec<usize>> {
        let starts: HashMap<u64, usize> = self
            .functions
            .iter()
            .enumerate()
            .map(|(index, function)| (function.address, index))
            .collect();
        let covered = Coverage::of(&self.functions);
        let width = self.isa.address_width().bytes() as u64;
        let mut tables = Vec::new();
        let mut run = Run::default();
        let mut next = None;
        for (address, value) in self.links.words(self.isa.address_width(), self.isa.byte_order()) {
            // A zero word is a null pointer, even where a function starts
            // at zero.
            let function = (value != 0).then(|| starts.get(&(value & !1)).copied()).flatten();
            if next != Some(address) || function.is_none() {
                tables.extend(run.end());
            }
            if let Some(index) = function {
                run.push(index, covered.place_of(address));
            }
            next = Some(address + width);
        }
        tables.extend(run.end());
        tables
    }

    /// Read a binary and find the functions in it.
    ///
    /// The symbol table comes first, because a name is exact. A stripped
    /// binary has none, so the functions are recovered from the code instead.
    /// See [`hereticus_recovery::scan`] for how, and for what that costs in accuracy.
    pub fn parse(data: &[u8]) -> Result<Self, ObjError> {
        let data = crate::macho::aarch64_slice(data);
        let file = object::File::parse(data)?;
        let isa = match Isa::from_object(file.architecture(), file.is_little_endian())? {
            isa @ (Isa::Arm32 | Isa::Mips32 | Isa::Mips32Be) => {
                set_of_symbol(isa, most_functions_encoded(&file))
            }
            isa => isa,
        };

        if let object::File::MachO64(macho) = &file
            && let Some((functions, found_by)) =
                crate::macho::fileset_functions(macho).or_else(|| crate::macho::functions(macho))
        {
            return Ok(Self {
                isa,
                functions,
                found_by,
                addresses: address_space(&file),
                links: Links::of_object(&file),
                other_set: BTreeSet::new(),
            });
        }

        let mut functions = Vec::new();
        let mut other_set = BTreeSet::new();
        for symbol in file.symbols() {
            if symbol.kind() != SymbolKind::Text || symbol.size() == 0 {
                continue;
            }

            let own = set_of_symbol(isa, encoding_of(&symbol));
            let address = own.arch().function_address(symbol.address());
            if own != isa {
                other_set.insert(address);
            }
            let Some(code) = symbol_code(&file, &symbol, address) else { continue };
            functions.push(Function {
                name: stable_name(symbol.name().unwrap_or_default()).to_string(),
                address,
                code,
            });
        }

        if file.kind() == ObjectKind::Relocatable
            && (covers_little_code(&file, &functions) || has_renamed_locals(&functions))
        {
            return Self::parse_module(&file, isa);
        }
        if !functions.is_empty() {
            // A stable order keeps output and snapshots reproducible; the
            // symbol table order is not guaranteed.
            functions.sort_by_key(|function| (function.address, function.name.clone()));
            let addresses = address_space(&file);
            let links = Links::of_object(&file);
            return Ok(Self {
                isa,
                functions,
                found_by: FoundBy::Symbols,
                addresses,
                links,
                other_set,
            });
        }

        if !has_code_section(&file) {
            return Self::parse_segments(&file, isa);
        }

        // Stripping keeps the dynamic symbol table, which names what the
        // library exports, so those functions keep their names, and their
        // instruction sets.
        let mut exported: BTreeMap<u64, &str> = BTreeMap::new();
        let mut other_set = BTreeSet::new();
        for symbol in file.dynamic_symbols() {
            if symbol.kind() == SymbolKind::Text
                && symbol.size() > 0
                && let Ok(name) = symbol.name()
            {
                // ARM marks a Thumb function by setting bit 0 of its address.
                let address = symbol.address() & !1;
                if set_of_symbol(isa, encoding_of(&symbol)) != isa {
                    other_set.insert(address);
                }
                let name_of = exported.entry(address).or_insert(name);
                // Aliases share an address. The first by name keeps the
                // result the same whatever order the table lists them in.
                *name_of = (*name_of).min(name);
            }
        }
        let links = Links::of_object(&file);
        let scanned: Vec<Function> = scan::recover_functions(data, isa.arch())
            .into_iter()
            .map(unnamed)
            .map(|function| match exported.get(&function.address) {
                Some(name) => Function { name: stable_name(name).to_string(), ..function },
                None => name_stub(function, isa.arch(), &links),
            })
            .collect();

        // Code that yields no functions means the scan failed, not that the
        // binary is empty. Saying so beats reporting that nothing changed.
        if scanned.is_empty() {
            return Err(ObjError::NoFunctions);
        }

        Ok(Self {
            isa,
            functions: scanned,
            found_by: FoundBy::Scanning,
            addresses: address_space(&file),
            links,
            other_set,
        })
    }

    /// Read an unlinked object whose symbols name little of its code, or
    /// name it by numbers, as a kernel module OpenWrt ships.
    ///
    /// OpenWrt's `strip-kmod.sh` keeps only the symbols that relocations
    /// need, and renames the local ones to numbers, as `_7`: measured on
    /// `ltq_ptm_vr9.ko` of 24.10.3, 8 symbols named 1.5 KiB of 12 KiB of
    /// code. On ARM more are kept, but named `_41` in one build and `_43`
    /// in the next for one function. So the code is scanned as a stripped
    /// binary's, with each function a symbol bounds as a start, and only
    /// the names that are not numbers kept. An unlinked object
    /// starts every section at zero, so each code section is placed after
    /// the one before it.
    fn parse_module(file: &object::File<'_>, isa: Isa) -> Result<Self, ObjError> {
        /// The least alignment of a section, so that a function starts
        /// where it would in the module.
        const LEAST_ALIGNMENT: u64 = 16;

        let arch = isa.arch();
        let mut bases: BTreeMap<usize, u64> = BTreeMap::new();
        let mut code: Vec<(u64, &[u8])> = Vec::new();
        let mut next: u64 = 0;
        for section in file.sections() {
            if section.kind() != object::SectionKind::Text || section.size() == 0 {
                continue;
            }
            let Ok(data) = section.data() else { continue };
            let base = next.next_multiple_of(section.align().max(LEAST_ALIGNMENT));
            bases.insert(section.index().0, base);
            code.push((base, data));
            next = base + data.len() as u64;
        }
        if code.is_empty() {
            return Err(ObjError::NoCode);
        }

        let mut named: BTreeMap<u64, &str> = BTreeMap::new();
        let mut exported = Vec::new();
        for symbol in file.symbols() {
            let Ok(name) = symbol.name() else { continue };
            let Some(base) = symbol.section_index().and_then(|index| bases.get(&index.0)) else {
                continue;
            };
            if symbol.kind() != SymbolKind::Text || symbol.size() == 0 {
                continue;
            }
            // A local renamed to a number still bounds its function, but
            // its name says nothing.
            let start = base + symbol.address();
            exported.push(start..start + symbol.size());
            if !name.is_empty() && !crate::links::is_renamed_local(name) {
                named.insert(start, name);
            }
        }
        let linked =
            scan::Linked { exported, pointers: code_pointers(file, &bases), ..Default::default() };
        let memory = hereticus_recovery::arch::Memory::new(&code);
        let functions: Vec<Function> =
            scan::recover_in_memory(&code, &[], &linked, scan::Regions::CodeOnly, arch, &memory)
                .into_iter()
                .map(unnamed)
                .map(|function| match named.get(&function.address) {
                    Some(name) => Function { name: stable_name(name).to_string(), ..function },
                    None => function,
                })
                .collect();
        if functions.is_empty() {
            return Err(ObjError::NoFunctions);
        }
        Ok(Self {
            isa,
            functions,
            found_by: FoundBy::Scanning,
            addresses: AddressSpace::none(),
            links: Links::of_module(file, &bases),
            other_set: BTreeSet::new(),
        })
    }

    /// Read an ELF file with no section headers through its segments.
    ///
    /// `sstrip`, which OpenWrt runs on every binary it ships, removes the
    /// section headers as well as the symbols. What the loader maps is still
    /// there, so each executable segment is read as a raw image at the
    /// address it loads at, with every loaded segment as the memory the code
    /// reads.
    ///
    /// Such a segment holds the headers and the read-only data as well as
    /// the code. The dynamic segment says where the code lies: `DT_INIT`
    /// opens it and `DT_FINI` comes last, so only what lies between is
    /// read. `.fini` is left out, as `crti` and `crtn` of the C library
    /// make it the same in every program.
    fn parse_segments(file: &object::File<'_>, isa: Isa) -> Result<Self, ObjError> {
        /// The tags of the dynamic segment that give where `.init` and
        /// `.fini` start.
        const DT_INIT: u64 = 12;
        const DT_FINI: u64 = 13;

        let arch = isa.arch();
        let dynamic = Dynamic::of(file);
        let init = dynamic.as_ref().and_then(|dynamic| dynamic.value(DT_INIT));
        let fini = dynamic.as_ref().and_then(|dynamic| dynamic.value(DT_FINI));
        let loaded: Vec<(u64, &[u8])> = file
            .segments()
            .filter_map(|segment| Some((segment.address(), segment.data().ok()?)))
            .filter(|(_, data)| !data.is_empty())
            .collect();
        let executable: Vec<(u64, &[u8])> = file
            .segments()
            .filter(|segment| {
                matches!(segment.flags(), SegmentFlags::Elf { p_flags, .. } if p_flags.0 & PF_X.0 != 0)
            })
            .filter_map(|segment| Some((segment.address(), segment.data().ok()?)))
            .collect();
        let code: Vec<(u64, &[u8])> = executable
            .iter()
            .map(|&(base, data)| match (init, fini) {
                (Some(init), Some(fini)) => clip(base, data, init..fini),
                _ => (base, data),
            })
            .filter(|(_, data)| data.len() >= arch.instruction_width())
            .collect();
        if code.is_empty() {
            return Err(ObjError::NoCode);
        }
        // The lazy binding stubs of MIPS are read apart, as MIPS32 whatever
        // the code around them is, and named for the import each resolves.
        let stubs = lazy_stubs(isa, &code);
        let code = without(&code, stubs.iter().map(|stub| stub.range.clone()));

        // The index of ARM lies after the code, so the whole segment is
        // searched for it. The call frame information of the others is
        // found the same way.
        let order = match file.is_little_endian() {
            true => unwind::ByteOrder::Little,
            false => unwind::ByteOrder::Big,
        };
        let index: Vec<scan::IndexEntry> = executable
            .iter()
            .flat_map(|&(base, data)| {
                let index = scan::find_exception_index(data, base, arch);
                if !index.is_empty() {
                    return index;
                }
                let ranges = unwind::find_function_ranges(data, base, order);
                scan::index_from_ranges(&ranges, arch)
            })
            .collect();
        let exports = dynamic.as_ref().map(|dynamic| dynamic.exports()).unwrap_or_default();
        let linked = scan::Linked {
            exported: exports
                .iter()
                .map(|export| {
                    let start = export.address & !1;
                    start..(start + export.size) & !1
                })
                .collect(),
            pointers: Vec::new(),
            slot_names: dynamic.as_ref().map(|dynamic| dynamic.slot_names()).unwrap_or_default(),
        };
        let functions: Vec<Function> = scan::recover_in_memory(
            &code,
            &index,
            &linked,
            scan::Regions::CodeAndData,
            arch,
            &hereticus_recovery::arch::Memory::new(&loaded),
        )
        .into_iter()
        .map(unnamed)
        .collect();
        if functions.is_empty() {
            return Err(ObjError::NoFunctions);
        }

        // The dynamic symbol table names what the file exports, and the set
        // each export is in, as for a file stripped the usual way.
        let mut exported: BTreeMap<u64, &str> = BTreeMap::new();
        let mut other_set = BTreeSet::new();
        for export in &exports {
            let encoding = match export.address & 1 == 1 || export.other & STO_MIPS16 == STO_MIPS16
            {
                true => Encoding::Compact,
                false => Encoding::Full,
            };
            let address = export.address & !1;
            if set_of_symbol(isa, encoding) != isa {
                other_set.insert(address);
            }
            let name_of = exported.entry(address).or_insert(export.name);
            *name_of = (*name_of).min(export.name);
        }
        let links = Links::of_object(file);
        let mut functions: Vec<Function> = functions
            .into_iter()
            .map(|function| match exported.get(&function.address) {
                Some(name) => Function { name: stable_name(name).to_string(), ..function },
                None => name_stub(function, arch, &links),
            })
            .collect();
        for stub in &stubs {
            let Some(bytes) = loaded.iter().find_map(|&(base, data)| {
                let start = usize::try_from(stub.range.start.checked_sub(base)?).ok()?;
                data.get(start..start + mips_stubs::STUB_LENGTH as usize)
            }) else {
                continue;
            };
            let name = dynamic
                .as_ref()
                .and_then(|dynamic| dynamic.symbol_name(stub.symbol))
                .map(|name| format!("{name}@plt"))
                .unwrap_or_default();
            // A stub is MIPS32, so in MIPS16e code it is in the other set.
            if set_of_symbol(isa, Encoding::Full) != isa {
                other_set.insert(stub.range.start);
            }
            functions.push(Function { name, address: stub.range.start, code: bytes.to_vec() });
        }
        functions.extend(plt_stubs_after(arch, &executable, &code, &links));
        functions.sort_by_key(|function| function.address);

        Ok(Self {
            isa,
            functions,
            found_by: FoundBy::Scanning,
            addresses: AddressSpace::from_ranges(
                file.segments()
                    .map(|segment| segment.address()..segment.address() + segment.size()),
            ),
            links,
            other_set,
        })
    }

    /// Read a blob that carries no container format.
    ///
    /// A flash dump is bytes and nothing else. There is no header to say what
    /// architecture the code is for, and no section table to say where it
    /// loads, so the caller states both.
    ///
    /// The whole blob is treated as code. Data mixed into it decodes as
    /// instructions, which is wrong but harmless: those words become opaque or
    /// meaningless entries that the matcher compares by content, so they
    /// affect one function's score rather than derailing the comparison.
    ///
    /// Boundaries are less reliable than in an object file. A raw image has no
    /// exception index, so recovery falls back to call targets and to the code
    /// after a return, which splits some functions at an internal return. See
    /// [`hereticus_recovery::scan`].
    pub fn parse_raw(data: &[u8], base: u64, isa: Isa) -> Result<Self, ObjError> {
        // Too short to hold one instruction. Without this the scanner reports
        // a "function" of two or three bytes that can never decode.
        if data.len() < isa.arch().instruction_width() {
            return Err(ObjError::NoCode);
        }

        let regions = [(base, data)];
        let mut index = scan::find_exception_index(data, base, isa.arch());
        if index.is_empty() {
            let order = match isa {
                Isa::Mips32Be | Isa::Mips16Be => unwind::ByteOrder::Big,
                Isa::Arm32 | Isa::Thumb2 | Isa::Aarch64 | Isa::Mips32 | Isa::Mips16 => {
                    unwind::ByteOrder::Little
                }
            };
            let ranges = unwind::find_function_ranges(data, base, order);
            index = scan::index_from_ranges(&ranges, isa.arch());
        }
        let functions: Vec<Function> = scan::recover_from_regions(&regions, &index, isa.arch())
            .into_iter()
            .map(unnamed)
            .collect();

        if functions.is_empty() {
            return Err(ObjError::NoFunctions);
        }

        let addresses = AddressSpace::of_raw_image(base, data.len() as u64);
        let links = Links::of_raw_image(base, data);
        Ok(Self {
            isa,
            functions,
            found_by: FoundBy::Scanning,
            addresses,
            links,
            other_set: BTreeSet::new(),
        })
    }
}

/// Copy out the bytes a symbol covers.
/// A symbol name without the part that changes when unrelated code does.
///
/// LLVM gives a local function it makes visible across a module a suffix
/// `.llvm.` and a hash of the module, so any edit to the module renames all
/// of them. Measured on smallvec built by Rust for ARM at `-Os`, the fix
/// renamed `SmallVec::reserve`, and each unedited caller of it read as calling
/// a different function. GCC's `.constprop.0` and `.isra.0` count clones in
/// order, so they stay.
pub fn stable_name(name: &str) -> &str {
    match name.rsplit_once(".llvm.") {
        Some((stem, hash))
            if !hash.is_empty() && hash.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            stem
        }
        _ => name,
    }
}

fn symbol_code(
    file: &object::File<'_>,
    symbol: &object::Symbol<'_, '_>,
    address: u64,
) -> Option<Vec<u8>> {
    let section = file.section_by_index(symbol.section_index()?).ok()?;
    let data = section.data().ok()?;

    // Symbol addresses are absolute; section data starts at the section
    // address, so rebase before slicing.
    let start = address.checked_sub(section.address())? as usize;
    let end = start.checked_add(symbol.size() as usize)?;
    data.get(start..end).map(<[u8]>::to_vec)
}

/// How a function's instructions are encoded, where an architecture has a
/// compact set beside its full one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Encoding {
    /// A32, or MIPS32.
    Full,
    /// Thumb-2, or MIPS16e.
    Compact,
}

/// The `st_other` value of an ELF symbol that names a MIPS16e function.
const STO_MIPS16: u8 = 0xf0;

/// The encoding of the function a symbol names.
///
/// A linked file sets bit 0 of a Thumb-2 or MIPS16e function's address. An
/// unlinked MIPS object does not: it marks the symbol in `st_other` instead.
fn encoding_of(symbol: &object::Symbol<'_, '_>) -> Encoding {
    let marked = match symbol.flags() {
        object::SymbolFlags::Elf { st_other, .. } => st_other.0 & STO_MIPS16 == STO_MIPS16,
        _ => false,
    };
    match symbol.address() & 1 == 1 || marked {
        true => Encoding::Compact,
        false => Encoding::Full,
    }
}

/// The instruction set of a function in `encoding`, in a binary read as
/// `isa`.
fn set_of_symbol(isa: Isa, encoding: Encoding) -> Isa {
    match (isa, encoding) {
        (Isa::Arm32 | Isa::Thumb2, Encoding::Compact) => Isa::Thumb2,
        (Isa::Arm32 | Isa::Thumb2, Encoding::Full) => Isa::Arm32,
        (Isa::Mips32 | Isa::Mips16, Encoding::Compact) => Isa::Mips16,
        (Isa::Mips32 | Isa::Mips16, Encoding::Full) => Isa::Mips32,
        (Isa::Mips32Be | Isa::Mips16Be, Encoding::Compact) => Isa::Mips16Be,
        (Isa::Mips32Be | Isa::Mips16Be, Encoding::Full) => Isa::Mips32Be,
        (Isa::Aarch64, _) => isa,
    }
}

/// The encoding of most functions of a file, as their symbols say.
///
/// The symbol table says it where there is one, and the dynamic symbol
/// table where it was stripped, through the dynamic segment where `sstrip`
/// removed the section headers too. Where neither is left, as in stripped
/// firmware, a MIPS file says in its header that it holds MIPS16e code,
/// and on ARM bit 0 of the entry point says which set the code runs in.
/// The entry of a MIPS16e program is MIPS32 code of the C library.
fn most_functions_encoded(file: &object::File<'_>) -> Encoding {
    /// The functions `crti` and `crtn` of the C library make, in the full
    /// set whatever set the program is built in. An executable exports
    /// little more, so they would outvote it.
    const FROM_THE_C_LIBRARY: [&str; 2] = ["_init", "_fini"];

    let count = |symbols: &mut dyn Iterator<Item = object::Symbol<'_, '_>>| {
        symbols
            .filter(|symbol| symbol.kind() == SymbolKind::Text && symbol.size() > 0)
            .filter(|symbol| !symbol.name().is_ok_and(|name| FROM_THE_C_LIBRARY.contains(&name)))
            .fold((0usize, 0usize), |(compact, all), symbol| {
                let found = usize::from(encoding_of(&symbol) == Encoding::Compact);
                (compact + found, all + 1)
            })
    };
    // A file with no section headers keeps its dynamic symbols only in the
    // dynamic segment.
    let exported = || {
        let exports = Dynamic::of(file).map(|dynamic| dynamic.exports());
        let exports = exports.unwrap_or_default();
        let ours = exports.iter().filter(|export| !FROM_THE_C_LIBRARY.contains(&export.name));
        ours.fold((0usize, 0usize), |(compact, all), export| {
            let marked = export.address & 1 == 1 || export.other & STO_MIPS16 == STO_MIPS16;
            (compact + usize::from(marked), all + 1)
        })
    };
    let (compact, all) = match count(&mut file.symbols()) {
        (_, 0) => match count(&mut file.dynamic_symbols()) {
            (_, 0) => exported(),
            counted => counted,
        },
        counted => counted,
    };
    let most = match all {
        0 => holds_mips16(file) || file.entry() & 1 == 1,
        _ => compact * 2 > all,
    };
    match most {
        true => Encoding::Compact,
        false => Encoding::Full,
    }
}

/// The function the scan found, with no name yet.
fn unnamed(found: scan::Recovered) -> Function {
    Function { name: String::new(), address: found.address, code: found.code }
}

/// `function`, named for its callee where it is a PLT stub whose slot a
/// relocation names. Every stub is the same code but for its slot, so
/// without the name, stubs pair by their order, which a new import moves.
fn name_stub(function: Function, arch: &dyn Arch, links: &Links) -> Function {
    match links.stub_name(arch, &function) {
        Some(name) => Function { name, ..function },
        None => function,
    }
}

/// The PLT stubs in `executable` past the end of `code`, each named for
/// its callee, where a relocation names the slot it jumps through.
///
/// GNU `ld` puts the PLT of a MIPS16e executable that is not PIC after
/// `.fini`, which the scan of the code between `DT_INIT` and `DT_FINI`
/// does not reach. The stubs lie in a row, so each runs to the next.
fn plt_stubs_after(
    arch: &dyn Arch,
    executable: &[(u64, &[u8])],
    code: &[(u64, &[u8])],
    links: &Links,
) -> Vec<Function> {
    /// Each stub starts on a word.
    const STUB_ALIGNMENT: u64 = 4;
    /// More bytes than any PLT stub holds.
    const STUB_BYTES: u64 = 16;

    let code_end = code.iter().map(|&(base, data)| base + data.len() as u64).max().unwrap_or(0);
    let starts: Vec<(u64, &[u8])> = executable
        .iter()
        .flat_map(|&(base, data)| {
            let end = base + data.len() as u64;
            let first = code_end.max(base).next_multiple_of(STUB_ALIGNMENT);
            (first..end).step_by(STUB_ALIGNMENT as usize).filter_map(move |address| {
                let offset = usize::try_from(address - base).ok()?;
                let stub = &data[offset..(offset + STUB_BYTES as usize).min(data.len())];
                arch.stub_slot(stub, address).and_then(|slot| links.slot_name(slot))?;
                Some((address, stub))
            })
        })
        .collect();
    let next_starts = starts.iter().skip(1).map(|&(address, _)| Some(address)).chain([None]);
    starts
        .iter()
        .zip(next_starts)
        .filter_map(|(&(address, stub), next)| {
            let length = next.map_or(STUB_BYTES, |next| (next - address).min(STUB_BYTES));
            let code = stub.get(..usize::try_from(length).ok()?).unwrap_or(stub).to_vec();
            let function = Function { name: String::new(), address, code };
            Some(Function { name: links.stub_name(arch, &function)?, ..function })
        })
        .collect()
}

/// The lazy binding stubs of MIPS in `code`: see [`mips_stubs`]. None
/// for another architecture.
fn lazy_stubs(isa: Isa, code: &[(u64, &[u8])]) -> Vec<mips_stubs::LazyStub> {
    let order = match isa {
        Isa::Mips32 | Isa::Mips16 => mips_stubs::ByteOrder::Little,
        Isa::Mips32Be | Isa::Mips16Be => mips_stubs::ByteOrder::Big,
        Isa::Arm32 | Isa::Thumb2 | Isa::Aarch64 => return Vec::new(),
    };
    code.iter().flat_map(|&(base, data)| mips_stubs::lazy_stubs(base, data, order)).collect()
}

/// The parts of `regions` outside every one of `cuts`, which are sorted.
fn without<'a>(
    regions: &[(u64, &'a [u8])],
    cuts: impl Iterator<Item = core::ops::Range<u64>> + Clone,
) -> Vec<(u64, &'a [u8])> {
    let mut parts = Vec::new();
    for &(base, data) in regions {
        let end = base + data.len() as u64;
        let mut from = base;
        for cut in cuts.clone().filter(|cut| cut.start < end && cut.end > base) {
            if cut.start > from {
                parts.push((from, &data[(from - base) as usize..(cut.start - base) as usize]));
            }
            from = from.max(cut.end.min(end));
        }
        if from < end {
            parts.push((from, &data[(from - base) as usize..]));
        }
    }
    parts
}

/// The bytes of `data`, at `base`, that lie in `range`, where the two
/// overlap. Where they do not, all of `data`.
fn clip(base: u64, data: &[u8], range: core::ops::Range<u64>) -> (u64, &[u8]) {
    let start = range.start.max(base);
    let end = range.end.min(base + data.len() as u64);
    if start >= end {
        return (base, data);
    }
    (start, &data[(start - base) as usize..(end - base) as usize])
}

/// The flag of the header of a MIPS file that holds MIPS16e code.
const EF_MIPS_ARCH_ASE_M16: u32 = 0x0400_0000;

/// Report whether the header of a MIPS file says that it holds MIPS16e
/// code.
fn holds_mips16(file: &object::File<'_>) -> bool {
    let is_mips = matches!(file.architecture(), object::Architecture::Mips);
    match file.flags() {
        object::FileFlags::Elf { e_flags, .. } => is_mips && e_flags.0 & EF_MIPS_ARCH_ASE_M16 != 0,
        _ => false,
    }
}

/// The addresses a linked file occupies: each section it loads, `.bss`
/// included.
///
/// An unlinked object gets none. Its sections all start at zero, and the code
/// holds zeros where the linker will write addresses, so nothing in it is an
/// address yet.
fn address_space(file: &object::File<'_>) -> AddressSpace {
    if file.kind() == ObjectKind::Relocatable {
        return AddressSpace::none();
    }
    AddressSpace::from_ranges(
        file.sections()
            .filter(|section| section.address() != 0)
            .map(|section| section.address()..section.address().saturating_add(section.size())),
    )
}

/// The addresses in code, as `bases` places each code section, that the
/// data of the unlinked `file` points at: a table of callbacks, as the
/// `net_device_ops` of a driver, holds the address of each, and a
/// relocation of the table names the section and the offset in it.
///
/// The table a `switch` jumps through points into code too, at each case.
/// Its words lie in a row and point into one function, where a table of
/// callbacks has gaps, or points at functions far apart. Measured on
/// `ltq_ptm_vr9.ko`, the cases of the `ioctl` handler cut it in eight.
fn code_pointers(file: &object::File<'_>, bases: &BTreeMap<usize, u64>) -> Vec<u64> {
    let order = if file.is_little_endian() {
        crate::links::ByteOrder::Little
    } else {
        crate::links::ByteOrder::Big
    };
    let width: u64 = if file.is_64() { 8 } else { 4 };
    let mut pointers = Vec::new();
    for section in file.sections().filter(|section| section.kind() != object::SectionKind::Text) {
        let data = section.data().unwrap_or_default();
        // Each word that points into code, by its offset in the section.
        let words: Vec<(u64, u64)> = section
            .relocations()
            .filter_map(|(offset, relocation)| {
                let object::RelocationTarget::Symbol(index) = relocation.target() else {
                    return None;
                };
                let symbol = file.symbol_by_index(index).ok()?;
                let base = bases.get(&symbol.section_index()?.0)?;
                let addend = match relocation.has_implicit_addend() {
                    true => {
                        let start = usize::try_from(offset).ok()?;
                        order.read(data.get(start..start + width as usize)?)
                    }
                    false => relocation.addend() as u64,
                };
                Some((offset, base.wrapping_add(symbol.address()).wrapping_add(addend)))
            })
            .collect();
        pointers.extend(without_switch_tables(words, width));
    }
    pointers.sort_unstable();
    pointers.dedup();
    pointers
}

/// The targets of `words`, each `(offset, target)` of one section, but for
/// those of a run that looks like the table of a `switch`: see
/// [`code_pointers`].
fn without_switch_tables(mut words: Vec<(u64, u64)>, width: u64) -> Vec<u64> {
    /// A table this long, of words in a row, may be a `switch`.
    const LEAST_CASES: usize = 4;
    /// Wider than the cases of any `switch` in one function.
    const WIDEST_CASES: u64 = 0x800;

    words.sort_unstable();
    words
        .chunk_by(|before, after| after.0 == before.0 + width)
        .filter(|run| {
            let (low, high) = run.iter().fold((u64::MAX, 0), |(low, high), &(_, target)| {
                (low.min(target), high.max(target))
            });
            run.len() < LEAST_CASES || high - low >= WIDEST_CASES
        })
        .flatten()
        .map(|&(_, target)| target)
        .collect()
}

/// Report whether any of `functions` is named by a local that OpenWrt's
/// `strip-kmod.sh` renamed to a number: see [`crate::links::is_renamed_local`].
fn has_renamed_locals(functions: &[Function]) -> bool {
    functions.iter().any(|function| crate::links::is_renamed_local(&function.name))
}

/// Report whether `functions`, read from the symbols of `file`, cover less
/// than half of its code.
fn covers_little_code(file: &object::File<'_>, functions: &[Function]) -> bool {
    let code: u64 = file
        .sections()
        .filter(|section| section.kind() == object::SectionKind::Text)
        .map(|section| section.size())
        .sum();
    let covered: u64 = functions.iter().map(|function| function.code.len() as u64).sum();
    covered * 2 < code
}

fn has_code_section(file: &object::File<'_>) -> bool {
    file.sections().any(|section| section.kind() == object::SectionKind::Text && section.size() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bytes_that_are_not_an_object() {
        assert!(matches!(Binary::parse(b"not an elf"), Err(ObjError::Parse(_))));
    }

    /// A table is two or more addresses of functions in a row, or three
    /// inside a function. A null, a word that is no function, or a gap ends
    /// one, and bit 0 of an address is dropped.
    #[test]
    fn a_table_is_a_run_of_function_addresses() {
        let functions: Vec<Function> = (0..3)
            .map(|index| Function {
                name: String::new(),
                address: 0x1000 + index * 0x10,
                code: vec![0; if index == 2 { 0x18 } else { 4 }],
            })
            .collect();
        let words = |words: &[u32]| -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        };
        let memory = vec![
            (0x2000, words(&[0x1000, 0x1011, 0x5555, 0x1020, 0x1000, 0, 0x1010, 0x1020])),
            // One address alone, then a table that the gap before it ends.
            (0x3000, words(&[0x1000])),
            (0x3008, words(&[0x1010, 0x1000])),
            // Inside the function at 0x1020: two are not enough, three are.
            (0x1020, words(&[0x1000, 0x1010, 0, 0x1000, 0x1010, 0x1000])),
        ];
        let binary = Binary {
            isa: Isa::Arm32,
            functions,
            found_by: FoundBy::Symbols,
            addresses: AddressSpace::none(),
            links: Links::of_parts(memory, BTreeMap::new()),
            other_set: BTreeSet::new(),
        };
        assert_eq!(
            binary.function_tables(),
            [vec![0, 1], vec![2, 0], vec![1, 2], vec![1, 0], vec![0, 1, 0]]
        );
    }

    /// Cuts take their bytes out of the regions they overlap, and a cut
    /// that covers a whole region removes it.
    #[test]
    fn without_cuts_out_ranges() {
        let data = [0u8, 1, 2, 3, 4, 5, 6, 7];
        let regions = [(0x100, &data[..]), (0x200, &data[..4])];
        let parts = without(&regions, [0x102..0x104, 0x106..0x10a, 0x200..0x204].into_iter());
        assert_eq!(parts, [(0x100, &data[..2]), (0x104, &data[4..6])]);
        assert_eq!(without(&regions, core::iter::empty()), regions);
    }

    /// A run of four or more words in a row that point close together is
    /// the table of a `switch`; a table of callbacks has gaps, or points
    /// far apart.
    #[test]
    fn a_switch_table_points_at_no_function() {
        let switch: Vec<(u64, u64)> = (0..4).map(|case| (case * 4, 0x2700 + case * 0x20)).collect();
        assert!(without_switch_tables(switch, 4).is_empty());
        let callbacks = vec![(0x80, 0x100), (0x90, 0x2000), (0x94, 0x2100), (0x98, 0x2200)];
        assert_eq!(without_switch_tables(callbacks, 4), [0x100, 0x2000, 0x2100, 0x2200]);
        let far: Vec<(u64, u64)> = (0..4).map(|slot| (slot * 4, slot * 0x1000)).collect();
        assert_eq!(without_switch_tables(far, 4), [0, 0x1000, 0x2000, 0x3000]);
    }

    /// An unlinked object whose functions are named by numbers, as a kernel
    /// module OpenWrt ships, reads with the symbols as bounds and no names
    /// but the real ones.
    #[test]
    fn a_kernel_module_keeps_no_name_that_is_a_number() {
        use object::write::{Object as Written, Symbol, SymbolSection};
        let mut written = Written::new(
            object::BinaryFormat::Elf,
            object::Architecture::Arm,
            object::Endianness::Little,
        );
        let text = written.section_id(object::write::StandardSection::Text);
        // mov r0, #1; bx lr, and mov r0, #2; bx lr.
        let code: Vec<u8> = [0xe3a0_0001_u32, 0xe12f_ff1e, 0xe3a0_0002, 0xe12f_ff1e]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        written.append_section_data(text, &code, 4);
        for (name, value, scope) in [
            ("_3", 0, object::SymbolScope::Compilation),
            ("tun_init", 8, object::SymbolScope::Dynamic),
        ] {
            written.add_symbol(Symbol {
                name: name.as_bytes().to_vec(),
                value,
                size: 8,
                kind: SymbolKind::Text,
                scope,
                weak: false,
                section: SymbolSection::Section(text),
                flags: object::SymbolFlags::None,
            });
        }
        let binary = Binary::parse(&written.write().expect("the object writes")).expect("parses");
        let found: Vec<(u64, &str)> = binary
            .functions
            .iter()
            .map(|function| (function.address, function.name.as_str()))
            .collect();
        assert_eq!(found, [(0, ""), (8, "tun_init")]);
        assert_eq!(binary.found_by, FoundBy::Scanning);
    }

    #[test]
    fn rejects_empty_input() {
        assert!(Binary::parse(&[]).is_err());
    }

    #[test]
    fn a_name_loses_the_hash_of_its_module() {
        assert_eq!(stable_name("_RNvMs_reserve.llvm.17076722752549331491"), "_RNvMs_reserve");
        assert_eq!(stable_name("inflate"), "inflate");
        assert_eq!(stable_name("deflate.constprop.0"), "deflate.constprop.0");
        assert_eq!(stable_name("odd.llvm."), "odd.llvm.", "no hash");
        assert_eq!(stable_name("odd.llvm.12a"), "odd.llvm.12a", "not a hash");
        assert_eq!(stable_name(""), "");
    }

    const EVERY_ISA: [Isa; 7] = [
        Isa::Arm32,
        Isa::Thumb2,
        Isa::Aarch64,
        Isa::Mips32,
        Isa::Mips32Be,
        Isa::Mips16,
        Isa::Mips16Be,
    ];

    #[test]
    fn clip_keeps_what_lies_in_the_range() {
        let data = [0u8, 1, 2, 3, 4, 5, 6, 7];
        assert_eq!(clip(0x100, &data, 0x102..0x106), (0x102, &data[2..6]));
        assert_eq!(clip(0x100, &data, 0x0..0x104), (0x100, &data[..4]));
        assert_eq!(clip(0x100, &data, 0x106..0x200), (0x106, &data[6..]));
        assert_eq!(clip(0x100, &data, 0x200..0x300), (0x100, &data[..]), "no overlap");
        assert_eq!(clip(0x100, &data, 0x104..0x104), (0x100, &data[..]), "empty range");
    }

    #[test]
    fn the_other_set_of_the_other_set_is_the_set() {
        for isa in EVERY_ISA {
            if let Some(other) = isa.other_set() {
                assert_ne!(other, isa);
                assert_eq!(other.other_set(), Some(isa), "{isa:?}");
            }
        }
    }

    #[test]
    fn a_symbol_keeps_to_the_sets_of_its_binary() {
        for isa in EVERY_ISA {
            for encoding in [Encoding::Full, Encoding::Compact] {
                let own = set_of_symbol(isa, encoding);
                assert!(own == isa || isa.other_set() == Some(own), "{isa:?} {encoding:?}");
                assert_eq!(set_of_symbol(own, encoding), own, "{isa:?} {encoding:?}");
            }
        }
        assert_eq!(set_of_symbol(Isa::Mips32, Encoding::Compact), Isa::Mips16);
        assert_eq!(set_of_symbol(Isa::Mips16Be, Encoding::Full), Isa::Mips32Be);
        assert_eq!(set_of_symbol(Isa::Arm32, Encoding::Compact), Isa::Thumb2);
        assert_eq!(set_of_symbol(Isa::Aarch64, Encoding::Compact), Isa::Aarch64);
    }

    /// How a MIPS object marks a MIPS16e function.
    #[derive(Clone, Copy, Debug)]
    enum Marking {
        /// As an unlinked object does.
        StOther,
        /// As a linked file does.
        Bit0,
    }

    /// A MIPS object with one function in each set: `full` at 0, and
    /// `compact` at 8, marked as `marking` says.
    fn mips_object(marking: Marking) -> Vec<u8> {
        use object::write::{Object, Symbol, SymbolSection};
        let mut object = Object::new(
            object::BinaryFormat::Elf,
            object::Architecture::Mips,
            object::Endianness::Little,
        );
        let text = object.section_id(object::write::StandardSection::Text);
        // `jr ra` and its delay slot, then MIPS16e `jrc ra`, `nop`, padded.
        let code =
            [0x08, 0x00, 0xe0, 0x03, 0, 0, 0, 0, 0xa0, 0xe8, 0x00, 0x65, 0x00, 0x65, 0x00, 0x65];
        object.append_section_data(text, &code, 4);
        let mut add = |name: &str, value: u64, size: u64, st_other: u8| {
            object.add_symbol(Symbol {
                name: name.as_bytes().to_vec(),
                value,
                size,
                kind: object::SymbolKind::Text,
                scope: object::SymbolScope::Linkage,
                weak: false,
                section: SymbolSection::Section(text),
                flags: object::SymbolFlags::Elf {
                    st_info: object::elf::SymbolInfo::new(
                        object::elf::STB_GLOBAL,
                        object::elf::STT_FUNC,
                    ),
                    st_other: object::elf::SymbolOther(st_other),
                },
            });
        };
        add("full", 0, 8, 0);
        match marking {
            Marking::StOther => add("compact", 8, 4, STO_MIPS16),
            Marking::Bit0 => add("compact", 9, 4, 0),
        }
        object.write().expect("a small object writes")
    }

    #[test]
    fn a_mips16_function_is_found_by_st_other_or_by_bit_0() {
        for marking in [Marking::StOther, Marking::Bit0] {
            let binary = Binary::parse(&mips_object(marking)).expect("the object parses");
            let set = |name: &str| {
                let function =
                    binary.functions.iter().find(|function| function.name == name).unwrap();
                binary.isa_of(function)
            };
            assert_eq!(set("full"), Isa::Mips32, "{marking:?}");
            assert_eq!(set("compact"), Isa::Mips16, "{marking:?}");
            let compact = binary.functions.iter().find(|function| function.name == "compact");
            assert_eq!(compact.map(|function| function.address), Some(8), "{marking:?}");
        }
    }
}
