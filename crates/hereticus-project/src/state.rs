//! The state of the browser that a project keeps, and the names of the
//! flags that read the two binaries.

use hereticus::matching::{EditKind, View};
use hereticus::obj::Isa;
use serde::{Deserialize, Serialize};

/// What the browser shows: each thing that a key changes, so a project
/// opens as the reader left it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Browser {
    pub sort: Sort,
    pub order: Order,
    /// Lists only the pairs whose edit touched this kind of code.
    pub touched: Option<EditKind>,
    /// Lists only the pairs that have each of these features.
    pub only: Vec<Feature>,
    pub scope: Scope,
    pub hidden: Hidden,
    /// The lowest score at which a function gone or new names its closest
    /// candidate, as `--near-miss` sets.
    pub near_miss_floor: f64,
    pub view: View,
    pub layout: Layout,
    /// The text that the names of the listed rows hold.
    pub filter: String,
    pub selected: Option<Key>,
    /// The first row of the diff of the selected row, where it is open.
    pub opened: Option<usize>,
}

/// A row of the table, by what it stands for, as a project names it.
///
/// A pair goes by its two functions, not by its place in the list of pairs,
/// so a reader of the file can follow it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Key {
    Pair { before: usize, after: usize },
    Gone { function: usize },
    New { function: usize },
}

/// A function the reader marked, with the label the reader gave it.
///
/// Marked rows list first, whatever the order, the scope or the kind
/// touched. The label shows beside the name, and the filter matches it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mark {
    pub row: Key,
    /// May be empty: a mark needs no name.
    pub label: String,
}

/// Which pairs the table lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    /// The pairs that changed, less the quiet changes [`Hidden`] holds back.
    Changed,
    /// Every pair, as `--all` lists.
    All,
}

/// How the diff of a pair is laid out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Layout {
    /// The earlier function on the left, the later one on the right.
    SideBySide,
    /// One column, as a patch reads.
    Unified,
}

/// Which way the sort runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Order {
    /// As `--sort` names it: the most first, or the strongest match.
    Descending,
    /// The other way.
    Ascending,
}

/// Which quiet changes to list.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hidden {
    pub retouched: Retouched,
    pub data: DataRegions,
}

/// Whether to list pairs that look like data.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DataRegions {
    Show,
    Hide,
}

impl From<bool> for DataRegions {
    fn from(show: bool) -> Self {
        if show { Self::Show } else { Self::Hide }
    }
}

/// Whether to list pairs that only differ in a constant.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Retouched {
    Show,
    Hide,
}

impl From<bool> for Retouched {
    fn from(show: bool) -> Self {
        if show { Self::Show } else { Self::Hide }
    }
}

/// How to order the changed functions in the report.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[serde(rename_all = "kebab-case")]
pub enum Sort {
    /// Strongest match first, then closest score.
    Confidence,
    /// Most instructions added first, with a check before an early exit
    /// as five more, after the functions that turned a call into its
    /// bounded form. The default.
    Added,
    /// Most instructions removed first.
    Removed,
    /// Most instructions rewritten first.
    Modified,
    /// Most instructions added first, where an addition that few other
    /// functions share weighs more. A fix adds its own code, while another
    /// compiler or flag adds the same code to many functions.
    Rare,
}

impl Sort {
    /// The order after this one, to step through them all with one key.
    pub fn next(self) -> Self {
        match self {
            Self::Added => Self::Removed,
            Self::Removed => Self::Modified,
            Self::Modified => Self::Rare,
            Self::Rare => Self::Confidence,
            Self::Confidence => Self::Added,
        }
    }

    /// The name `--sort` takes for this order.
    pub fn name(self) -> &'static str {
        match self {
            Self::Confidence => "confidence",
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Modified => "modified",
            Self::Rare => "rare",
        }
    }
}

/// A thing a changed pair can do, which `--only` and the `f` key of the
/// browser list the pairs by.
///
/// Each one is read from the lifted instructions of the two bodies, as
/// aligned: see [`hereticus::matching::EditKinds`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[serde(rename_all = "kebab-case")]
pub enum Feature {
    /// Adds a call, or puts a call in the place of another instruction.
    AddedCall,
    /// Removes a call, or puts another instruction in its place.
    RemovedCall,
    /// Adds a conditional branch, or puts one in the place of another
    /// instruction.
    AddedBranch,
    /// Removes a conditional branch, or puts another instruction in its
    /// place.
    RemovedBranch,
    /// Keeps a call in place that now reaches another function.
    OtherCallee,
    /// Turns a call into its bounded form, as `strcmp` into `strncmp`.
    BoundedCall,
    /// Adds a check that leaves the function early.
    EarlyExit,
    /// Changes a text that the function points at.
    Text,
    /// Changes a constant, with the instructions around it the same.
    Constant,
}

impl Feature {
    /// Every feature, in the order the `f` key steps through them.
    pub const ALL: [Self; 9] = [
        Self::AddedCall,
        Self::RemovedCall,
        Self::AddedBranch,
        Self::RemovedBranch,
        Self::OtherCallee,
        Self::BoundedCall,
        Self::EarlyExit,
        Self::Text,
        Self::Constant,
    ];

    /// The name `--only` takes for this feature.
    pub fn name(self) -> &'static str {
        match self {
            Self::AddedCall => "added-call",
            Self::RemovedCall => "removed-call",
            Self::AddedBranch => "added-branch",
            Self::RemovedBranch => "removed-branch",
            Self::OtherCallee => "other-callee",
            Self::BoundedCall => "bounded-call",
            Self::EarlyExit => "early-exit",
            Self::Text => "text",
            Self::Constant => "constant",
        }
    }
}

/// The architectures `--arch` takes for a raw image.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[serde(rename_all = "kebab-case")]
pub enum ArchName {
    /// ARM32, little endian, A32 instructions.
    Arm32,
    /// ARM32, little endian, Thumb-2 instructions, as Cortex-M firmware is.
    Thumb2,
    /// ARM32, big endian (BE8: data big endian, instructions little
    /// endian), A32 instructions.
    Arm32Be8,
    /// ARM32, big endian (BE8), Thumb-2 instructions.
    Thumb2Be8,
    /// ARMv8-A, 64-bit, little endian.
    Aarch64,
    /// MIPS32, little endian.
    Mips32,
    /// MIPS32, big endian, as most shipped firmware is.
    Mips32Be,
    /// MIPS16e, little endian.
    Mips16,
    /// MIPS16e, big endian.
    Mips16Be,
    /// x86-64.
    #[cfg_attr(feature = "clap", value(name = "x86-64"))]
    #[serde(rename = "x86-64")]
    X86_64,
    /// 32-bit x86.
    X86,
}

impl From<ArchName> for Isa {
    fn from(name: ArchName) -> Self {
        match name {
            ArchName::Arm32 => Self::Arm32,
            ArchName::Thumb2 => Self::Thumb2,
            ArchName::Arm32Be8 => Self::Arm32Be8,
            ArchName::Thumb2Be8 => Self::Thumb2Be8,
            ArchName::Aarch64 => Self::Aarch64,
            ArchName::Mips32 => Self::Mips32,
            ArchName::Mips32Be => Self::Mips32Be,
            ArchName::Mips16 => Self::Mips16,
            ArchName::Mips16Be => Self::Mips16Be,
            ArchName::X86_64 => Self::X86_64,
            ArchName::X86 => Self::X86,
        }
    }
}

/// The parts `--unpack` takes out of a firmware image.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[serde(rename_all = "kebab-case")]
pub enum PartName {
    /// The decompressor that runs first.
    Stub,
    /// The kernel, decompressed.
    Kernel,
}
