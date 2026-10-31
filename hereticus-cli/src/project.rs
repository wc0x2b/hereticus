//! Save a comparison as a project, and open it again.
//!
//! The match is the slow part of a run: minutes on a kernel. A project holds
//! its result, how to read the two binaries again, the state of the browser
//! and the functions a reader marked, so the reader can stop and go on later.
//! The binaries stay where they are. A project names each one by its path
//! from the directory of the project, or by the absolute path the command
//! line gave, with a hash of its bytes, and opens only when both are as they
//! were.

use std::borrow::Cow;
use std::path::{Component, Path, PathBuf};

use hereticus::matching::Diff;
use hereticus::obj::Binary;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::tui::{Browser, Mark};
use crate::{ArchName, Args, Base, PartName};

/// The layout of the file. A change that an older `hereticus` cannot read
/// must increment it. Layout 3 names each binary from the directory of the
/// project, where layout 2 named it by its absolute path.
const LAYOUT: u32 = 3;

/// The oldest layout that this version reads. The absolute paths of layout 2
/// read as they are.
const OLDEST_LAYOUT: u32 = 2;

/// A saved comparison.
#[derive(Debug, Serialize, Deserialize)]
pub struct Project<'a> {
    /// See [`LAYOUT`].
    layout: u32,
    /// The version of `hereticus` that saved the project, for a reader.
    hereticus: String,
    pub source: Source,
    pub browser: Browser,
    pub marks: Vec<Mark>,
    /// Last, because it is by far the largest part.
    pub diff: Cow<'a, Diff>,
}

impl<'a> Project<'a> {
    pub fn new(source: Source, browser: Browser, marks: Vec<Mark>, diff: &'a Diff) -> Self {
        Self {
            layout: LAYOUT,
            hereticus: env!("CARGO_PKG_VERSION").to_string(),
            source,
            browser,
            marks,
            diff: Cow::Borrowed(diff),
        }
    }

    /// Write the project to `path`.
    ///
    /// The project goes to a file beside `path` first and then takes its
    /// name, so a failed write leaves the last save as it was.
    pub fn write(&self, path: &Path) -> Result<(), String> {
        let cannot = |error: &dyn core::fmt::Display| {
            format!("cannot save the project to {}: {error}", path.display())
        };
        let directory = directory_of(path);
        let mut source = self.source.clone();
        for input in &mut source.inputs {
            if input.anchor == Anchor::Relative {
                input.path = path_from(directory, &input.path)?;
            }
        }
        let on_disk = Project {
            layout: self.layout,
            hereticus: self.hereticus.clone(),
            source,
            browser: self.browser.clone(),
            marks: self.marks.clone(),
            diff: Cow::Borrowed(&self.diff),
        };
        let mut text = serde_json::to_vec_pretty(&on_disk).map_err(|error| cannot(&error))?;
        text.push(b'\n');
        let mut partial = path.as_os_str().to_owned();
        partial.push(".partial");
        let partial = PathBuf::from(partial);
        let written = std::fs::write(&partial, text).and_then(|()| std::fs::rename(&partial, path));
        if let Err(error) = written {
            let _ = std::fs::remove_file(&partial);
            return Err(cannot(&error));
        }
        Ok(())
    }
}

impl Project<'static> {
    /// Read a project that [`Project::write`] saved.
    pub fn read(path: &Path) -> Result<Self, String> {
        let cannot = |error: &dyn core::fmt::Display| {
            format!("cannot open the project {}: {error}", path.display())
        };
        let text = std::fs::read(path).map_err(|error| cannot(&error))?;
        let mut project: Self = serde_json::from_slice(&text).map_err(|error| cannot(&error))?;
        if !(OLDEST_LAYOUT..=LAYOUT).contains(&project.layout) {
            return Err(cannot(&format!(
                "hereticus {} saved it in layout {}, and this version reads only layouts \
                 {OLDEST_LAYOUT} to {LAYOUT}",
                project.hereticus, project.layout
            )));
        }
        // An absolute path stays as it is.
        let directory = directory_of(path);
        for input in &mut project.source.inputs {
            input.anchor = Anchor::of(&input.path);
            input.path = lexical(&directory.join(&input.path));
        }
        Ok(project)
    }

    /// Make sure that the two binaries, as read again, are the ones the
    /// project compared, and that the saved result fits them.
    pub fn check_binaries(&self, before: &Binary, after: &Binary) -> Result<(), String> {
        let [earlier, later] = &self.source.inputs;
        earlier.check_functions(before)?;
        later.check_functions(after)?;
        let fits = |list: &[usize], binary: &Binary| {
            list.iter().all(|&index| index < binary.functions.len())
        };
        let diff = &self.diff;
        let pairs_fit = diff
            .matched
            .iter()
            .all(|pair| pair.before < before.functions.len() && pair.after < after.functions.len());
        let misses_fit =
            |misses: &[hereticus::matching::NearMiss], own: &Binary, other: &Binary| {
                misses.iter().all(|miss| {
                    miss.unmatched < own.functions.len()
                        && miss.best.is_none_or(|best| best < other.functions.len())
                        && miss.in_place.is_none_or(|place| place < other.functions.len())
                })
            };
        let fit = pairs_fit
            && fits(&diff.removed, before)
            && fits(&diff.added, after)
            && diff.removed_contents.len() == diff.removed.len()
            && diff.added_contents.len() == diff.added.len()
            && misses_fit(&diff.near_misses, before, after)
            && misses_fit(&diff.added_near_misses, after, before);
        if fit {
            Ok(())
        } else {
            Err("the project names functions that the binaries do not hold".to_string())
        }
    }
}

/// How the two binaries were read and compared: what reading them again
/// needs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Source {
    /// The earlier binary, then the later one.
    pub inputs: [Input; 2],
    /// How to read a raw image. None for a binary with a container format.
    pub raw: Option<Raw>,
    pub threshold: f64,
    pub names: Names,
}

/// Whether the match could pair functions by their names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Names {
    Use,
    Ignore,
}

/// How a raw image was read, as `--raw` and the flags it allows say.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Raw {
    pub base: Option<u64>,
    /// Whether `--base auto` found the base. The words of the image are
    /// the same when the project opens, so they give the same base again.
    #[serde(default)]
    pub auto_base: bool,
    pub arch: ArchName,
    pub unpack: Option<PartName>,
}

/// Where the path of a binary starts. A path that the reader gave from the
/// root stays so, and any other path goes from the directory of the project,
/// so that the project and its binaries can move together.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Anchor {
    #[default]
    Relative,
    Absolute,
}

impl Anchor {
    fn of(path: &Path) -> Self {
        if path.is_absolute() { Self::Absolute } else { Self::Relative }
    }
}

/// One binary of the comparison.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    /// The path as the command line gave it, and from the directory of the
    /// project in the file.
    pub path: PathBuf,
    /// Not in the file: the path in the file tells it.
    #[serde(skip)]
    pub anchor: Anchor,
    /// The SHA-256 of the file, in hex.
    pub sha256: String,
    /// The SHA-256 of the address and the size of each function found, in
    /// hex. Another version of `hereticus` can find other functions in the
    /// same bytes, and the saved result names functions by their place in
    /// this list.
    pub functions: String,
}

impl Input {
    /// Describe the binary at `path`, from the hash of its file, as
    /// [`sha256_hex`] gives it, and the functions found in it.
    pub fn new(path: &Path, sha256: String, binary: &Binary) -> Self {
        Self {
            path: path.to_path_buf(),
            anchor: Anchor::of(path),
            sha256,
            functions: functions_hash(binary),
        }
    }

    /// Make sure that the file has the hash it had when the project read it.
    pub fn check_hash(&self, sha256: &str) -> Result<(), String> {
        if sha256 == self.sha256 {
            Ok(())
        } else {
            Err(format!(
                "{} changed since the project was saved, so its result no longer applies. \
                 Compare the binaries again",
                self.path.display()
            ))
        }
    }

    /// Make sure that this version of `hereticus` finds the functions the
    /// project names.
    fn check_functions(&self, binary: &Binary) -> Result<(), String> {
        if functions_hash(binary) == self.functions {
            Ok(())
        } else {
            Err(format!(
                "this version of hereticus finds other functions in {} than the version that \
                 saved the project. Compare the binaries again",
                self.path.display()
            ))
        }
    }
}

impl Source {
    /// Describe how `args` read the two binaries.
    pub fn new(args: &Args, inputs: [Input; 2]) -> Self {
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
        Self { inputs, raw, threshold: args.threshold, names }
    }

    /// The arguments that read the two binaries as the project did, with
    /// every other flag as `args` gives it.
    pub fn replay(&self, args: &Args) -> Args {
        let raw = self.raw.as_ref();
        Args {
            before: Some(self.inputs[0].path.clone()),
            after: Some(self.inputs[1].path.clone()),
            raw: raw.is_some(),
            base: raw.and_then(|raw| match (raw.auto_base, raw.base) {
                (true, _) => Some(Base::Auto),
                (false, base) => base.map(Base::Address),
            }),
            arch: raw.map_or(args.arch, |raw| raw.arch),
            unpack: raw.and_then(|raw| raw.unpack),
            threshold: self.threshold,
            ignore_names: self.names == Names::Ignore,
            ..args.clone()
        }
    }
}

/// The directory that holds the project at `path`, as a path from the
/// present directory: empty for a project in it.
fn directory_of(path: &Path) -> &Path {
    path.parent().unwrap_or(Path::new(""))
}

/// The path from `directory` to `file`, where each is absolute or a path
/// from the present directory.
fn path_from(directory: &Path, file: &Path) -> Result<PathBuf, String> {
    let full = |path: &Path| {
        // `absolute` takes no empty path.
        let path = if path.as_os_str().is_empty() { Path::new(".") } else { path };
        std::path::absolute(path)
            .map(|path| lexical(&path))
            .map_err(|error| format!("cannot find where {} is: {error}", path.display()))
    };
    let (directory, file) = (full(directory)?, full(file)?);
    let shared = directory.components().zip(file.components()).take_while(|(a, b)| a == b).count();
    let up = directory.components().skip(shared).map(|_| Component::ParentDir);
    Ok(up.chain(file.components().skip(shared)).collect())
}

/// `path` with each `.` taken out and each `..` joined to the directory
/// before it. A symbolic link is not read, so this can name another file
/// than the operating system would, as the shell does for `cd`.
fn lexical(path: &Path) -> PathBuf {
    let mut kept = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir if matches!(kept.last(), Some(Component::Normal(_))) => {
                kept.pop();
            }
            // The root is its own parent.
            Component::ParentDir if matches!(kept.last(), Some(Component::RootDir)) => {}
            other => kept.push(other),
        }
    }
    kept.into_iter().collect()
}

/// The SHA-256 of `bytes`, in hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// See [`Input::functions`].
fn functions_hash(binary: &Binary) -> String {
    let mut hasher = Sha256::new();
    for function in &binary.functions {
        hasher.update(function.address.to_le_bytes());
        hasher.update((function.code.len() as u64).to_le_bytes());
    }
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hash_of_known_bytes_is_the_published_one() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
    }

    fn input(bytes: &[u8]) -> Input {
        Input {
            path: PathBuf::from("/tmp/a.elf"),
            anchor: Anchor::Absolute,
            sha256: sha256_hex(bytes),
            functions: String::new(),
        }
    }

    #[test]
    fn a_path_goes_from_the_directory_of_the_project() {
        let from = |directory: &str, file: &str| {
            path_from(Path::new(directory), Path::new(file)).expect("a path")
        };
        assert_eq!(from("", "fw/a.bin"), Path::new("fw/a.bin"));
        assert_eq!(from("projects", "fw/a.bin"), Path::new("../fw/a.bin"));
        assert_eq!(from("fw", "fw/a.bin"), Path::new("a.bin"));
        assert_eq!(from("fw/old", "fw/new/./a.bin"), Path::new("../new/a.bin"));
        assert_eq!(from("a/../b", "b/c.bin"), Path::new("c.bin"));
        assert_eq!(from("/srv/projects", "/srv/fw/a.bin"), Path::new("../fw/a.bin"));
    }

    #[test]
    fn a_path_from_the_project_reads_back_as_the_same_file() {
        bolero::check!().with_type::<(Vec<u8>, Vec<u8>)>().for_each(|(directory, file)| {
            // Paths of a few short names, `.` and `..`, from the present
            // directory.
            let path = |picks: &[u8]| -> PathBuf {
                picks
                    .iter()
                    .take(6)
                    .map(|pick| ["a", "b", ".", ".."][usize::from(pick % 4)])
                    .collect()
            };
            let (directory, file) = (path(directory), path(file).join("x.bin"));
            let stored = path_from(&directory, &file).expect("a path");
            let read = lexical(&std::path::absolute(directory.join(&stored)).expect("a path"));
            let wanted = lexical(&std::path::absolute(&file).expect("a path"));
            assert_eq!(read, wanted, "{directory:?} {file:?} -> {stored:?}");
        });
    }

    #[test]
    fn changed_bytes_fail_the_check() {
        let input = input(b"before");
        assert!(input.check_hash(&sha256_hex(b"before")).is_ok());
        let error = input.check_hash(&sha256_hex(b"after")).expect_err("other bytes");
        assert!(error.contains("/tmp/a.elf changed"), "{error}");
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
        let source = Source::new(&first, [input(b"a"), input(b"b")]);
        let text = serde_json::to_string(&source).expect("a source serializes");
        assert!(text.contains(r#""arch":"mips32-be""#), "{text}");
        let source: Source = serde_json::from_str(&text).expect("a source reads back");

        let later = Args::parse_from(["hereticus", "--open", "p.json", "--sort", "removed"]);
        let replayed = source.replay(&later);
        assert!(replayed.raw && replayed.ignore_names);
        assert_eq!(replayed.base, Some(Base::Address(0x8000_0000)));
        assert_eq!(replayed.arch, ArchName::Mips32Be);
        assert_eq!(replayed.unpack, Some(PartName::Kernel));
        assert_eq!(replayed.threshold, 0.5);
        assert_eq!(replayed.before, Some(PathBuf::from("/tmp/a.elf")));
        assert_eq!(replayed.sort, crate::Sort::Removed, "a flag of the report stays");

        // `--base auto` finds the base again when the project opens.
        let auto = Args::parse_from(["hereticus", "--raw", "--base", "auto", "a.bin", "b.bin"]);
        let source = Source::new(&auto, [input(b"a"), input(b"b")]);
        let text = serde_json::to_string(&source).expect("a source serializes");
        let source: Source = serde_json::from_str(&text).expect("a source reads back");
        assert_eq!(source.replay(&later).base, Some(Base::Auto));

        // A binary with a container format leaves `--raw` off.
        let plain = Args::parse_from(["hereticus", "a.elf", "b.elf"]);
        let replayed = Source::new(&plain, [input(b"a"), input(b"b")]).replay(&later);
        assert!(!replayed.raw && !replayed.ignore_names);
        assert_eq!((replayed.base, replayed.unpack), (None, None));
    }

    #[test]
    fn a_file_that_is_no_project_fails_to_open() {
        let directory = std::env::temp_dir().join(format!("hereticus-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a directory");
        let path = directory.join("bad.json");

        std::fs::write(&path, "not json").expect("a file");
        let error = Project::read(&path).expect_err("not json");
        assert!(error.starts_with("cannot open the project"), "{error}");

        let error = Project::read(&directory.join("missing.json")).expect_err("no file");
        assert!(error.contains("missing.json"), "{error}");
        std::fs::remove_dir_all(&directory).expect("clean up");
    }
}
