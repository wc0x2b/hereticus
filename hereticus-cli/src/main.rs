//! Command line front end for `hereticus`.
//!
//! The library holds the analysis. This binary reads arguments, prints
//! results, and chooses an exit status.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use console::Term;
use hereticus::address::Contents;
use hereticus::matching::{
    Changed, Confidence, Diff, DiffLine, EditKind, EditKinds, Edits, Match, Options, Phase,
    Progress, UseNames, diff_reporting, instruction_diff,
};
use hereticus::obj::{Binary, Isa};
use hereticus::raw::{check_base, suggest_base};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use tabled::settings::object::{Columns, Rows};
use tabled::settings::style::HorizontalLine;
use tabled::settings::{Alignment, Color, Style};
use tabled::{Table, Tabled};

/// Compare two binaries and report the functions that changed.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The earlier binary.
    before: PathBuf,

    /// The later binary.
    after: PathBuf,

    /// Report every function, not only the ones that changed.
    #[arg(short, long)]
    all: bool,

    /// Show the instruction-level diff of one function, then stop.
    ///
    /// Give a name, or `sub_<hex>` for a function the binary did not name. The
    /// function is looked up in the earlier binary and diffed against whatever
    /// it was matched to in the later one.
    #[arg(long, value_name = "FUNCTION")]
    diff: Option<String>,

    /// Ignore symbol names, as though both binaries were stripped.
    ///
    /// Useful to see what `hereticus` finds from the code alone.
    #[arg(long)]
    ignore_names: bool,

    /// List functions that differ in nothing but a constant.
    ///
    /// A function whose shape is identical and whose instruction counts are
    /// all zero changed only a stored value. These outnumber the real edits on
    /// a whole kernel, so they are hidden by default.
    #[arg(long)]
    show_retouched: bool,

    /// List regions that look like data rather than code.
    ///
    /// A raw image holds tables and zero fill after its code, and a scan
    /// reads them as long functions. Every release changes thousands of
    /// their words, so they are hidden by default.
    #[arg(long)]
    show_data: bool,

    /// Lowest similarity that still counts as a match, from 0.0 to 1.0.
    #[arg(long, default_value_t = 0.65, value_parser = parse_threshold)]
    threshold: f64,

    /// Exit with a failure status when anything changed.
    ///
    /// For use as a build gate.
    #[arg(long)]
    exit_code: bool,

    /// Lowest score at which an unmatched function names its closest
    /// candidate, from 0.0 to 1.0.
    ///
    /// A function that no stage could pair still has a nearest neighbour.
    /// Naming it says whether the function was removed or only compiled
    /// differently. Raise this to hide weak guesses, lower it to see them all.
    #[arg(long, default_value_t = 0.25, value_parser = parse_threshold)]
    near_miss: f64,

    /// Read the inputs as raw code with no container format.
    ///
    /// For a firmware image dumped from flash, which has no ELF header. Needs
    /// `--base`, because nothing in the file says where it loads.
    #[arg(long)]
    raw: bool,

    /// Address a raw image loads at, for example `0x08000000`.
    ///
    /// Required with `--raw`. Branch targets and reported addresses are all
    /// relative to this, so a wrong value produces a report against the wrong
    /// addresses. Without it, the tool stops, and for MIPS it names the base
    /// that the calls in the image show.
    #[arg(long, value_parser = parse_address, requires = "raw")]
    base: Option<u64>,

    /// Architecture of a raw image.
    #[arg(long, value_enum, default_value_t = ArchName::Arm32, requires = "raw")]
    arch: ArchName,

    /// How to print the result.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// How to order the changed functions.
    ///
    /// The default puts the strongest match first. On a whole kernel the real
    /// edits hide among thousands of small changes, so `--sort modified` (or
    /// `added` / `removed`) brings the functions that changed the most to the
    /// top.
    #[arg(long, value_enum, default_value_t = Sort::Confidence, verbatim_doc_comment)]
    sort: Sort,

    /// When to show a progress bar.
    ///
    /// The bar goes to standard error, so it never mixes with the report.
    #[arg(long, value_enum, default_value_t = When::Auto, verbatim_doc_comment)]
    progress: When,

    /// When to color the report.
    ///
    /// Color goes to standard output with the report, so it is off by default
    /// unless standard output is a terminal. A redirected report stays plain
    /// text that another tool can read.
    #[arg(long, value_enum, default_value_t = When::Auto, verbatim_doc_comment)]
    color: When,
}

/// Whether to show a display that only a terminal can use.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum When {
    /// Show it when standard error is a terminal.
    Auto,
    /// Show it even when standard error is redirected.
    Always,
    /// Never show it.
    Never,
}

/// The architectures a raw image can be read as.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum ArchName {
    /// ARM32, little endian, A32 instructions. Thumb is not supported.
    Arm32,
    /// MIPS32, little endian.
    Mips32,
    /// MIPS32, big endian, as most shipped firmware is.
    Mips32Be,
}

impl From<ArchName> for Isa {
    fn from(name: ArchName) -> Self {
        match name {
            ArchName::Arm32 => Self::Arm32,
            ArchName::Mips32 => Self::Mips32,
            ArchName::Mips32Be => Self::Mips32Be,
        }
    }
}

/// Read a load address, in hex with `0x` or in decimal.
fn parse_address(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse::<u64>(),
    };
    parsed.map_err(|_| format!("`{text}` is not an address"))
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Format {
    /// A table for a person to read.
    Text,
    /// One line per function, for a script to read.
    Compact,
}

/// How to order the changed functions in the report.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Sort {
    /// Strongest match first, then closest score. The default.
    Confidence,
    /// Most instructions added first.
    Added,
    /// Most instructions removed first.
    Removed,
    /// Most instructions rewritten first.
    Modified,
}

impl Sort {
    /// The edit count this order ranks by, if any.
    ///
    /// `Confidence` ranks by no count, so it returns nothing and the report
    /// keeps the order the library gave it.
    fn count_of(self, edits: Edits) -> Option<usize> {
        match self {
            Self::Confidence => None,
            Self::Added => Some(edits.added),
            Self::Removed => Some(edits.removed),
            Self::Modified => Some(edits.edited),
        }
    }
}

/// Reject a threshold outside the range a similarity score can take.
fn parse_threshold(text: &str) -> Result<f64, String> {
    let value: f64 = text.parse().map_err(|_| format!("`{text}` is not a number"))?;
    if (0.0..=1.0).contains(&value) {
        Ok(value)
    } else {
        Err(format!("threshold must be between 0.0 and 1.0, but is {value}"))
    }
}

/// A progress bar on standard error, one phase at a time.
///
/// The library reports steps; this draws them. Keeping the bar on standard
/// error leaves standard output holding only the report, so a pipe still works
/// while a person still sees the tool is alive.
struct Bar {
    bar: ProgressBar,
}

impl Bar {
    fn new(when: When) -> Self {
        // A hidden bar still accepts every call, so the reporting code needs no
        // test for whether anything is drawn. `stderr` hides itself when
        // standard error is not a terminal, which is the behavior `Auto` wants.
        let target = match when {
            When::Auto => ProgressDrawTarget::stderr(),
            // `stderr` draws nothing when standard error is redirected, which
            // is what `Auto` wants and what `Always` must override. A
            // `TermLike` target skips that test, so the bar is written whatever
            // standard error happens to be.
            When::Always => ProgressDrawTarget::term_like(Box::new(Term::stderr())),
            When::Never => ProgressDrawTarget::hidden(),
        };

        Self { bar: ProgressBar::with_draw_target(None, target) }
    }
}

impl Progress for Bar {
    fn start(&self, phase: Phase, total: usize) {
        self.bar.reset();
        self.bar.set_length(total as u64);
        self.bar.set_message(phase.label());
        self.bar.set_style(
            ProgressStyle::with_template("{msg:26} [{bar:32}] {pos}/{len} {elapsed_precise}")
                .expect("the template is a constant")
                .progress_chars("=> "),
        );
    }

    fn advance(&self, steps: usize) {
        self.bar.inc(steps as u64);
    }

    fn finish(&self) {
        // Clear rather than leave the bar behind: six finished bars above a
        // report is noise, and the report is what a reader came for.
        self.bar.finish_and_clear();
    }
}

fn main() -> ExitCode {
    let args = Args::parse();

    match run(&args) {
        Ok(changed) => {
            // A build gate wants a failure status when something changed.
            if args.exit_code && changed { ExitCode::from(1) } else { ExitCode::SUCCESS }
        }
        Err(error) => {
            eprintln!("hereticus: {error}");
            ExitCode::from(2)
        }
    }
}

/// Compare the two binaries and print the result.
///
/// Returns whether anything changed.
fn run(args: &Args) -> Result<bool, String> {
    let before_bytes = read_file(&args.before)?;
    let after_bytes = read_file(&args.after)?;

    let (before, after) = if args.raw {
        let isa: Isa = args.arch.into();
        let base = args.base.ok_or_else(|| missing_base(&before_bytes, isa))?;

        check_and_report_base(&before_bytes, base, isa, &args.before);
        // Comparing a file with itself is a normal way to inspect one image,
        // and saying the same thing twice about it helps nobody.
        if args.after != args.before {
            check_and_report_base(&after_bytes, base, isa, &args.after);
        }
        eprintln!(
            "hereticus: a raw image has no exception index, so function boundaries \
             are recovered from the code and are approximate"
        );

        (
            parse_raw(&before_bytes, base, isa, &args.before)?,
            parse_raw(&after_bytes, base, isa, &args.after)?,
        )
    } else {
        (parse(&before_bytes, &args.before)?, parse(&after_bytes, &args.after)?)
    };

    if before.isa != after.isa {
        return Err(format!(
            "the two binaries are for different architectures: {:?} and {:?}",
            before.isa, after.isa
        ));
    }

    let options = Options {
        threshold: args.threshold,
        use_names: if args.ignore_names { UseNames::No } else { UseNames::Yes },
    };
    let diff = diff_reporting(&before, &after, options, &Bar::new(args.progress));

    // `--diff` asks about one function, so it answers and stops rather than
    // printing the whole report.
    if let Some(wanted) = &args.diff {
        let paint = Paint::resolve(args.color);
        return print_one_diff(&diff, &before, &after, wanted, paint).map(|()| false);
    }

    match args.format {
        Format::Text => {
            let hidden = Hidden::from_args(args);
            let paint = Paint::resolve(args.color);
            print_text(&diff, &before, &after, args.all, args.near_miss, hidden, paint, args.sort)
        }
        Format::Compact => {
            print_compact(&diff, &before, &after, args.all, Hidden::from_args(args), args.sort)
        }
    }

    Ok(diff.changed().count() > 0 || !diff.removed.is_empty() || !diff.added.is_empty())
}

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn parse(data: &[u8], path: &Path) -> Result<Binary, String> {
    Binary::parse(data).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn parse_raw(data: &[u8], base: u64, isa: Isa, path: &Path) -> Result<Binary, String> {
    Binary::parse_raw(data, base, isa)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))
}

/// Say that `--raw` needs `--base`, and suggest one when the image shows it.
///
/// The suggestion is not used in place of `--base`. It can be wrong, and a
/// wrong base gives a report against the wrong addresses with no other sign.
fn missing_base(data: &[u8], isa: Isa) -> String {
    let needed = "--raw needs --base, because a raw image does not say where it loads";
    match suggest_base(data, isa.arch()) {
        Some(base) => format!("{needed}. Its calls show that it loads at --base {base:#x}"),
        None => needed.to_string(),
    }
}

/// Warn when the given load address looks wrong for an image.
///
/// A wrong base does not stop anything: the code still decodes and every
/// branch still resolves, because a relative branch moves with the base it is
/// read at. Only the reported addresses are wrong, and silently so. This is
/// the one chance to notice.
fn check_and_report_base(data: &[u8], base: u64, isa: Isa, path: &Path) {
    let fit = check_base(data, base, isa.arch());
    if fit.is_suspect() {
        eprintln!("hereticus: {} may not load at {base:#x}: {fit}", path.display());
    }
}

/// Name a function, falling back to its address when it has no symbol.
fn name_of(binary: &Binary, index: usize) -> String {
    let function = &binary.functions[index];
    if function.name.is_empty() {
        format!("sub_{:x}", function.address)
    } else {
        function.name.clone()
    }
}

/// Describe what happened to a matched pair.
fn describe(change: Changed) -> &'static str {
    match change {
        Changed::No => "same",
        Changed::Reordered => "reordered",
        Changed::InDetail => "changed values",
        Changed::Data => "changed data",
        Changed::Unreadable => "changed unread",
        Changed::Yes => "changed",
    }
}

/// Render an edit as added, removed and rewritten instructions.
///
/// A dash rather than three zeros where nothing was counted, so the eye finds
/// the functions that did change.
///
/// A function whose constants changed shows a dash, and that is right: no
/// instruction was touched. The `CHANGE` column names what did change, and
/// the two columns answer different questions.
///
/// Each count carries the color of its own kind, not of the row, because the
/// three numbers say three different things. The colors follow a patch: green
/// added, red removed, yellow rewritten. The separators stay plain, so the
/// field still reads as one value.
fn describe_edits(edits: Edits, paint: Paint) -> String {
    if edits.total() == 0 {
        return "-".to_string();
    }

    let added = paint.pick(ADDED_COLOR).colorize(edits.added.to_string());
    let removed = paint.pick(REMOVED_COLOR).colorize(edits.removed.to_string());
    let edited = paint.pick(EDITED_COLOR).colorize(edits.edited.to_string());
    format!("{added}/{removed}/{edited}")
}

/// Name what kind of code an edit touched, most telling kind first.
///
/// Reads as `2 branch, 1 const`. Control flow leads, because a branch that
/// appeared can change what the function does for some input, which a moved
/// load cannot. A dash where nothing was touched, as in the `+/-/~` column.
///
/// This is the one place a changed constant shows inside a larger edit. Once a
/// rewrite is big enough the `CHANGE` column only says `changed`, and the
/// value that moved with it would otherwise not appear at all.
///
/// Plain data instructions are left out. They are the bulk of any rewrite and
/// name nothing a reader can act on, so listing them would crowd out the kinds
/// that do. The `+/-/~` column already reports the size of the edit.
///
/// The names are short so that the column stays narrow. `const` rather than
/// `constant` keeps the common case to one short word.
///
/// The column stays quiet where it would only repeat the `CHANGE` word beside
/// it. `changed values` already says a constant moved and `changed unread`
/// already says the difference is unreadable, so naming that one kind again
/// fills the column on every row of a report and tells the reader nothing. A
/// second kind alongside it is new information, and then the whole list shows.
fn describe_kinds(kinds: EditKinds, change: Changed) -> String {
    let named: Vec<(EditKind, usize)> =
        kinds.present().filter(|(kind, _)| *kind != EditKind::Other).collect();

    if let [(only, _)] = named[..]
        && restates(change, only)
    {
        return "-".to_string();
    }

    let listed: Vec<String> =
        named.iter().map(|(kind, count)| format!("{count} {}", name_of_kind(*kind))).collect();

    if listed.is_empty() { "-".to_string() } else { listed.join(", ") }
}

/// Report whether naming this kind would only repeat the `CHANGE` column.
fn restates(change: Changed, kind: EditKind) -> bool {
    matches!(
        (change, kind),
        (Changed::InDetail, EditKind::Constant) | (Changed::Unreadable, EditKind::Opaque)
    )
}

/// The short name of one kind, for the `TOUCHED` column.
fn name_of_kind(kind: EditKind) -> &'static str {
    match kind {
        EditKind::Branch => "branch",
        EditKind::Call => "call",
        EditKind::Jump => "jump",
        EditKind::Memory => "mem",
        EditKind::Constant => "const",
        EditKind::Other => "other",
        EditKind::Opaque => "unread",
    }
}

/// The color of each count in the `+/-/~` column.
const ADDED_COLOR: Color = Color::FG_GREEN;
const REMOVED_COLOR: Color = Color::FG_RED;
const EDITED_COLOR: Color = Color::FG_YELLOW;

/// Describe why two functions were paired.
fn describe_confidence(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::IdenticalCode => "identical bytes",
        Confidence::IdenticalShape => "identical shape",
        Confidence::SameName => "same name",
        Confidence::TwinInOrder => "twin, in order",
        Confidence::Similar => "similar",
    }
}

/// Report whether a pair should appear when only changes are wanted.
///
/// A pair that scores a perfect 1.00 and touched no instruction has nothing a
/// reader can act on: the shape is identical and only a constant moved. On a
/// whole kernel these crowd out the real edits, so they are hidden unless
/// asked for. Measured on a whole-kernel pair, hiding them drops
/// the report from 8744 rows to 6375 while keeping every function that added,
/// removed or rewrote an instruction.
fn is_interesting(pair: &Match, hidden: Hidden) -> bool {
    match pair.changed {
        Changed::No => false,
        Changed::Data => hidden.data == DataRegions::Show,
        _ => hidden.retouched == Retouched::Show || !is_retouched(pair),
    }
}

/// Report whether a function that went or came should appear.
///
/// A raw image holds its headers and read-only data among its code, and they
/// move when the code before them grows. Data goes and comes as code does, so
/// it is hidden as a changed data region is.
fn is_shown_unmatched(contents: Contents, hidden: Hidden) -> bool {
    contents == Contents::Code || hidden.data == DataRegions::Show
}

/// The word that says a function went, or came, for what it holds.
fn unmatched_word(word: &'static str, contents: Contents) -> String {
    match contents {
        Contents::Code => word.to_string(),
        Contents::Data => format!("{word} data"),
    }
}

/// Report whether a pair differs in nothing but its constants.
///
/// The score and the edit counts must both be clean. A function that rewrote
/// an instruction is a real edit whatever it scores, and one that scores below
/// a perfect match differs in shape even if the counts round to nothing.
fn is_retouched(pair: &Match) -> bool {
    pair.edits.total() == 0 && pair.score >= 1.0
}

/// Which quiet changes to list.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Hidden {
    retouched: Retouched,
    data: DataRegions,
}

impl Hidden {
    /// `--all` asks for every function, so it lists every quiet change too.
    fn from_args(args: &Args) -> Self {
        Self {
            retouched: Retouched::from(args.show_retouched || args.all),
            data: DataRegions::from(args.show_data || args.all),
        }
    }
}

/// Whether to list pairs that look like data.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DataRegions {
    Show,
    Hide,
}

impl From<bool> for DataRegions {
    fn from(show: bool) -> Self {
        if show { Self::Show } else { Self::Hide }
    }
}

/// Whether to list pairs that only differ in a constant.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Retouched {
    Show,
    Hide,
}

impl From<bool> for Retouched {
    fn from(show: bool) -> Self {
        if show { Self::Show } else { Self::Hide }
    }
}

/// Whether the report is colored.
///
/// Resolved once, before anything prints, so every line agrees.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Paint {
    On,
    Off,
}

impl Paint {
    /// Decide from the flag and, for `Auto`, from what standard output is.
    ///
    /// Color belongs to a person reading a terminal. A report sent to a file
    /// or a pipe must stay plain, or the escape codes become part of whatever
    /// reads it next.
    fn resolve(when: When) -> Self {
        match when {
            When::Always => Self::On,
            When::Never => Self::Off,
            When::Auto => {
                if console::colors_enabled() && Term::stdout().is_term() {
                    Self::On
                } else {
                    Self::Off
                }
            }
        }
    }

    /// Give a color, or an empty one that prints no escape codes.
    fn pick(self, color: Color) -> Color {
        match self {
            Self::On => color,
            Self::Off => Color::empty(),
        }
    }
}

/// Where the change sits in [`Row`], which is the one column to color.
const CHANGE_COLUMN: usize = 1;

/// Where the score sits in [`Row`], which is the one column to align right.
const SCORE_COLUMN: usize = 2;

/// One line of the text report.
///
/// The column headings are short because the table sizes itself to the widest
/// cell, and a long heading would widen a column that holds nothing wide.
#[derive(Tabled)]
struct Row {
    #[tabled(rename = "FUNCTION")]
    function: String,
    #[tabled(rename = "CHANGE")]
    change: &'static str,
    #[tabled(rename = "SCORE")]
    score: String,
    /// Added, removed and rewritten instructions.
    #[tabled(rename = "+/-/~")]
    edits: String,
    /// What kind of code the edit touched.
    #[tabled(rename = "TOUCHED")]
    kinds: String,
    #[tabled(rename = "MATCHED BY")]
    matched_by: &'static str,
}

/// Color a row by what happened to the function.
///
/// The severity runs from an unread difference, through a changed constant, to
/// a rewritten body. A reader scanning a long report finds the real edits by
/// color before reading a word.
fn color_of(change: Changed) -> Color {
    match change {
        Changed::Yes => Color::FG_RED,
        Changed::Unreadable => Color::FG_MAGENTA,
        Changed::InDetail => Color::FG_YELLOW,
        Changed::Reordered => Color::FG_CYAN,
        Changed::Data => Color::FG_BLUE,
        Changed::No => Color::FG_GREEN,
    }
}

/// Find a function in a binary by the name the report would print for it.
///
/// A named function matches its name. A stripped one matches `sub_<hex>`, the
/// same label the report shows, so a reader can copy a name straight out of the
/// table.
fn find_function(binary: &Binary, wanted: &str) -> Option<usize> {
    let by_address = wanted
        .strip_prefix("sub_")
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .and_then(|address| binary.functions.iter().position(|f| f.address == address));

    by_address
        .or_else(|| binary.functions.iter().position(|f| !f.name.is_empty() && f.name == wanted))
}

/// Print the instruction-level diff of one function.
///
/// The function is looked up in the earlier binary. If it was matched, the diff
/// runs against its counterpart; if it was removed, there is nothing to diff
/// against and the tool says so.
fn print_one_diff(
    diff: &Diff,
    before: &Binary,
    after: &Binary,
    wanted: &str,
    paint: Paint,
) -> Result<(), String> {
    let index = find_function(before, wanted)
        .ok_or_else(|| format!("no function `{wanted}` in the earlier binary"))?;

    let pair = diff.matched.iter().find(|pair| pair.before == index).ok_or_else(|| {
        // A removed function has no counterpart, so say that rather than print
        // an empty diff.
        match diff.near_miss(index).and_then(|miss| miss.best) {
            Some(best) => format!(
                "`{wanted}` was not matched; its closest candidate is {}",
                name_of(after, best)
            ),
            None => format!("`{wanted}` was not matched to anything in the later binary"),
        }
    })?;

    let before_name = name_of(before, pair.before);
    let after_name = name_of(after, pair.after);
    if before_name == after_name {
        println!("{before_name}");
    } else {
        println!("{before_name} -> {after_name}");
    }

    let lines = instruction_diff(
        &before.functions[pair.before],
        before.isa,
        &after.functions[pair.after],
        after.isa,
    );
    for line in &lines {
        println!("{}", render_diff_line(line, paint));
    }

    Ok(())
}

/// Draw one diff line with a leading sign, in the color of its kind.
///
/// The signs follow a patch: a space for an unchanged line, `+` added, `-`
/// removed, `~` for a line kept but retouched. Color repeats the sign so the
/// line reads on a terminal that drops it and on one that keeps it.
fn render_diff_line(line: &DiffLine, paint: Paint) -> String {
    match line {
        DiffLine::Same(text) => format!("  {text}"),
        DiffLine::Added(text) => paint.pick(ADDED_COLOR).colorize(format!("+ {text}")).to_string(),
        DiffLine::Removed(text) => {
            paint.pick(REMOVED_COLOR).colorize(format!("- {text}")).to_string()
        }
        DiffLine::Changed { before, after } => {
            let removed = paint.pick(REMOVED_COLOR).colorize(format!("- {before}"));
            let added = paint.pick(ADDED_COLOR).colorize(format!("+ {after}"));
            format!("{removed}\n{added}")
        }
    }
}

/// Order the shown pairs by the chosen edit count, most first.
///
/// `Confidence` keeps the order the library gave, which is already strongest
/// match first. The count orders break a tie by the lowest score, so the least
/// certain of an equal-sized edit sits on top, where it wants the most
/// attention. The sort is stable, so pairs that tie on both keep their place.
fn sort_shown(shown: &mut [&Match], sort: Sort) {
    if sort == Sort::Confidence {
        return;
    }

    shown.sort_by(|a, b| {
        let a_count = sort.count_of(a.edits).unwrap_or(0);
        let b_count = sort.count_of(b.edits).unwrap_or(0);
        b_count
            .cmp(&a_count)
            .then_with(|| a.score.partial_cmp(&b.score).unwrap_or(core::cmp::Ordering::Equal))
    });
}

fn print_text(
    diff: &Diff,
    before: &Binary,
    after: &Binary,
    show_all: bool,
    near_miss_floor: f64,
    hidden: Hidden,
    paint: Paint,
    sort: Sort,
) {
    let mut shown: Vec<&Match> =
        diff.matched.iter().filter(|pair| show_all || is_interesting(pair, hidden)).collect();
    sort_shown(&mut shown, sort);

    if !shown.is_empty() {
        let rows = shown.iter().map(|pair| {
            // A renamed function reads as `old -> new`. The table sizes the
            // column to the widest label, so a rename cannot push it out of
            // line.
            let name = name_of(before, pair.before);
            let renamed = name_of(after, pair.after);
            Row {
                function: if name == renamed { name } else { format!("{name} -> {renamed}") },
                change: describe(pair.changed),
                score: format!("{:.2}", pair.score),
                edits: describe_edits(pair.edits, paint),
                kinds: describe_kinds(pair.kinds, pair.changed),
                matched_by: describe_confidence(pair.confidence),
            }
        });

        let mut table = Table::new(rows);
        table
            // `rounded` draws no line under the heading, so borrow one from
            // `modern_rounded`, which uses the same corner characters.
            .with(
                Style::rounded()
                    .horizontals([(1, HorizontalLine::inherit(Style::modern_rounded()))]),
            )
            .with(Alignment::left())
            // The score is a number, so it reads better against the decimal
            // point than against the left edge.
            .modify(Columns::one(SCORE_COLUMN), Alignment::right())
            .modify(Rows::first(), paint.pick(Color::BOLD));

        // Only the `CHANGE` cell takes the severity color. A whole colored row
        // buries the one word a reader is looking for, and the counts beside it
        // carry colors of their own. Row 0 is the heading, so the pairs start
        // at row 1.
        for (offset, pair) in shown.iter().enumerate() {
            let cell = (offset + 1, CHANGE_COLUMN);
            table.modify(cell, paint.pick(color_of(pair.changed)));
        }

        println!("{table}");
    }

    // Only the status word takes a color, as in the `CHANGE` column. The name
    // beside it stays plain, so the word is what the eye finds.
    for (index, contents) in diff.removed_with_contents() {
        if !is_shown_unmatched(contents, hidden) {
            continue;
        }
        let name = name_of(before, index);
        let gone = paint.pick(REMOVED_COLOR).colorize(unmatched_word("gone", contents));
        match near_miss_note(diff, index, after, near_miss_floor) {
            Some(note) => println!("{name}: {gone}, {note}"),
            None => println!("{name}: {gone}"),
        }
    }
    for (index, contents) in diff.added_with_contents() {
        if !is_shown_unmatched(contents, hidden) {
            continue;
        }
        let name = name_of(after, index);
        let new = paint.pick(ADDED_COLOR).colorize(unmatched_word("new", contents));
        match added_near_miss_note(diff, index, before, near_miss_floor) {
            Some(note) => println!("{name}: {new}, {note}"),
            None => println!("{name}: {new}"),
        }
    }

    summarize(diff, hidden);
}

/// Describe the closest candidate for a function that went unmatched.
///
/// A function can go unmatched because it was removed, or because the two
/// builds compiled it too differently to recognize. The score separates those
/// two, and naming the candidate turns a dead end into somewhere to look.
fn near_miss_note(diff: &Diff, index: usize, after: &Binary, floor: f64) -> Option<String> {
    let miss = diff.near_miss(index)?;
    let best = miss.best?;
    if miss.score < floor {
        return None;
    }
    Some(format!("closest {} at {:.2}", name_of(after, best), miss.score))
}

/// Describe the closest candidate for a function that appears to be new.
///
/// The mirror of [`near_miss_note`]: the candidate is on the first binary. A
/// new function with a close candidate is likely one the cascade could not
/// pair, not truly new code, which is the distinction the finding needed.
fn added_near_miss_note(diff: &Diff, index: usize, before: &Binary, floor: f64) -> Option<String> {
    let miss = diff.added_near_miss(index)?;
    let best = miss.best?;
    if miss.score < floor {
        return None;
    }
    Some(format!("closest {} at {:.2}", name_of(before, best), miss.score))
}

/// Print one line per function, with no header or alignment.
fn print_compact(
    diff: &Diff,
    before: &Binary,
    after: &Binary,
    show_all: bool,
    hidden: Hidden,
    sort: Sort,
) {
    let mut shown: Vec<&Match> =
        diff.matched.iter().filter(|pair| show_all || is_interesting(pair, hidden)).collect();
    sort_shown(&mut shown, sort);

    for pair in shown {
        // The edit counts go last so a reader of the first four columns keeps
        // working.
        println!(
            "{}\t{}\t{}\t{:.2}\t{}\t{}\t{}",
            describe(pair.changed),
            name_of(before, pair.before),
            name_of(after, pair.after),
            pair.score,
            pair.edits.added,
            pair.edits.removed,
            pair.edits.edited,
        );
    }
    for (index, contents) in diff.removed_with_contents() {
        if !show_all && !is_shown_unmatched(contents, hidden) {
            continue;
        }
        // The fourth column holds the near-miss score, so a script reading
        // this format finds it where a matched pair keeps its score.
        let miss = diff.near_miss(index);
        let closest =
            miss.and_then(|miss| miss.best).map(|best| name_of(after, best)).unwrap_or_default();
        let score = miss.map_or(0.0, |miss| miss.score);
        let gone = unmatched_word("gone", contents);
        println!("{gone}\t{}\t{closest}\t{score:.2}\t\t\t", name_of(before, index));
    }
    for (index, contents) in diff.added_with_contents() {
        if !show_all && !is_shown_unmatched(contents, hidden) {
            continue;
        }
        // The candidate on the first binary and its score go in the same two
        // columns a removed line uses, so one reader parses both.
        let miss = diff.added_near_miss(index);
        let closest =
            miss.and_then(|miss| miss.best).map(|best| name_of(before, best)).unwrap_or_default();
        let score = miss.map_or(0.0, |miss| miss.score);
        let new = unmatched_word("new", contents);
        println!("{new}\t{closest}\t{}\t{score:.2}\t\t\t", name_of(after, index));
    }
}

fn summarize(diff: &Diff, hidden: Hidden) {
    let changed = diff.changed().count();
    let same = diff.matched.len() - changed;
    let nothing_happened = changed == 0 && diff.removed.is_empty() && diff.added.is_empty();

    // A count that disagrees with the table reads like a bug, so say how many
    // rows were held back and how to see them.
    let hidden_retouched = if hidden.retouched == Retouched::Hide {
        diff.changed().filter(|pair| pair.changed != Changed::Data && is_retouched(pair)).count()
    } else {
        0
    };
    // A data region that went or came is a change too, so it counts here.
    let hidden_data = if hidden.data == DataRegions::Hide {
        let changed = diff.changed().filter(|pair| pair.changed == Changed::Data).count();
        let unmatched = diff.removed_contents.iter().chain(&diff.added_contents);
        changed + unmatched.filter(|&&contents| contents == Contents::Data).count()
    } else {
        0
    };

    // Say so plainly when there is nothing to report. A bare count after an
    // empty table reads like the tool failed.
    if nothing_happened {
        println!("No functions changed. {} matched.", diff.matched.len());
        return;
    }

    println!();
    println!(
        "{} matched ({same} unchanged, {changed} changed), {} gone, {} new",
        diff.matched.len(),
        diff.removed.len(),
        diff.added.len()
    );
    if hidden_retouched > 0 {
        println!(
            "{hidden_retouched} changed only a constant, hidden. Use --show-retouched to list them."
        );
    }
    if hidden_data > 0 {
        let regions = if hidden_data == 1 { "region" } else { "regions" };
        println!("{hidden_data} data {regions} changed, hidden. Use --show-data to list them.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_threshold_outside_its_range() {
        assert!(parse_threshold("-0.1").is_err());
        assert!(parse_threshold("1.5").is_err());
        assert!(parse_threshold("not a number").is_err());
    }

    #[test]
    fn accepts_a_threshold_inside_its_range() {
        assert_eq!(parse_threshold("0.0"), Ok(0.0));
        assert_eq!(parse_threshold("0.65"), Ok(0.65));
        assert_eq!(parse_threshold("1.0"), Ok(1.0));
    }

    #[test]
    fn every_change_has_a_description() {
        for change in [
            Changed::No,
            Changed::Reordered,
            Changed::Data,
            Changed::InDetail,
            Changed::Unreadable,
            Changed::Yes,
        ] {
            assert!(!describe(change).is_empty());
        }
    }

    /// Build a pair with a given edit count and score, for the sort tests.
    fn pair_with(edits: Edits, score: f64) -> Match {
        Match { score, edits, ..edited_pair(Changed::Yes) }
    }

    /// `--sort modified` puts the most-rewritten function first.
    #[test]
    fn sort_by_modified_ranks_by_rewritten_count() {
        let small = pair_with(Edits { added: 0, removed: 0, edited: 1 }, 0.9);
        let large = pair_with(Edits { added: 0, removed: 0, edited: 9 }, 0.9);
        let mut shown = vec![&small, &large];

        sort_shown(&mut shown, Sort::Modified);
        assert_eq!(shown[0].edits.edited, 9, "the largest edit is first");
    }

    /// Each count order ranks by its own column.
    #[test]
    fn each_sort_ranks_by_its_own_column() {
        let grew = pair_with(Edits { added: 5, removed: 0, edited: 0 }, 0.9);
        let shrank = pair_with(Edits { added: 0, removed: 5, edited: 0 }, 0.9);
        let mut shown = vec![&grew, &shrank];

        sort_shown(&mut shown, Sort::Added);
        assert_eq!(shown[0].edits.added, 5, "added ranks by the + column");

        sort_shown(&mut shown, Sort::Removed);
        assert_eq!(shown[0].edits.removed, 5, "removed ranks by the - column");
    }

    /// An equal-sized edit is broken by the lowest score, which wants the most
    /// attention.
    #[test]
    fn an_equal_edit_puts_the_least_certain_first() {
        let sure = pair_with(Edits { added: 0, removed: 0, edited: 3 }, 0.95);
        let unsure = pair_with(Edits { added: 0, removed: 0, edited: 3 }, 0.60);
        let mut shown = vec![&sure, &unsure];

        sort_shown(&mut shown, Sort::Modified);
        assert_eq!(shown[0].score, 0.60, "the least certain of an equal edit is first");
    }

    /// The default order leaves the pairs as the library gave them.
    #[test]
    fn sort_by_confidence_keeps_the_order() {
        let first = pair_with(Edits { added: 0, removed: 0, edited: 1 }, 0.9);
        let second = pair_with(Edits { added: 0, removed: 0, edited: 9 }, 0.9);
        let mut shown = vec![&first, &second];

        sort_shown(&mut shown, Sort::Confidence);
        assert_eq!(shown[0].edits.edited, 1, "the library's order is untouched");
    }

    /// Build a pair that scores below a perfect match and rewrote one
    /// instruction, so only its [`Changed`] decides whether it is shown.
    fn edited_pair(changed: Changed) -> Match {
        Match {
            before: 0,
            after: 0,
            confidence: Confidence::IdenticalCode,
            score: 0.9,
            changed,
            edits: Edits { added: 0, removed: 0, edited: 1 },
            kinds: EditKinds { other: 1, ..EditKinds::default() },
        }
    }

    /// Build a pair that changed nothing but a constant.
    fn retouched_pair(changed: Changed) -> Match {
        Match { score: 1.0, edits: Edits::default(), ..edited_pair(changed) }
    }

    /// A lone changed constant is left to the `CHANGE` column to report.
    #[test]
    fn a_constant_alone_does_not_repeat_the_change_column() {
        let kinds = EditKinds { constants: 1, ..EditKinds::default() };
        assert_eq!(describe_kinds(kinds, Changed::InDetail), "-");
    }

    /// The same for a difference that sits in unreadable bytes.
    #[test]
    fn unreadable_bytes_alone_do_not_repeat_the_change_column() {
        let kinds = EditKinds { opaque: 3, ..EditKinds::default() };
        assert_eq!(describe_kinds(kinds, Changed::Unreadable), "-");
    }

    /// A second kind makes the whole list worth printing.
    ///
    /// `changed unread` says the difference is unreadable, but it cannot say a
    /// branch went with it, so the column speaks up.
    #[test]
    fn a_second_kind_brings_the_list_back() {
        let kinds = EditKinds { opaque: 3, branches: 1, ..EditKinds::default() };
        assert_eq!(describe_kinds(kinds, Changed::Unreadable), "1 branch, 3 unread");
    }

    /// A constant inside a larger rewrite is the case the column exists for.
    ///
    /// Here `CHANGE` says only `changed`, so nothing else reports the value.
    #[test]
    fn a_constant_inside_a_rewrite_is_still_named() {
        let kinds = EditKinds { constants: 1, branches: 2, ..EditKinds::default() };
        assert_eq!(describe_kinds(kinds, Changed::Yes), "2 branch, 1 const");
    }

    /// The suppression follows the `CHANGE` word, not the kind alone.
    ///
    /// A lone constant under a plain `changed` is not a repeat of anything, so
    /// it must still be named.
    #[test]
    fn a_constant_under_a_plain_change_is_not_suppressed() {
        let kinds = EditKinds { constants: 1, ..EditKinds::default() };
        assert_eq!(describe_kinds(kinds, Changed::Yes), "1 const");
    }

    /// Plain data instructions never reach the column.
    #[test]
    fn other_instructions_are_left_out() {
        let kinds = EditKinds { other: 12, ..EditKinds::default() };
        assert_eq!(describe_kinds(kinds, Changed::Yes), "-");
    }

    /// What the report hides when no flag asks for more.
    const DEFAULT: Hidden = Hidden { retouched: Retouched::Hide, data: DataRegions::Hide };

    /// Data that went or came is hidden by the flag that hides changed data,
    /// and code never is.
    #[test]
    fn unmatched_data_is_hidden_as_changed_data_is() {
        assert!(is_shown_unmatched(Contents::Code, DEFAULT));
        assert!(!is_shown_unmatched(Contents::Data, DEFAULT));
        assert!(is_shown_unmatched(Contents::Data, Hidden { data: DataRegions::Show, ..DEFAULT }));
        assert!(
            !is_shown_unmatched(Contents::Data, Hidden { retouched: Retouched::Show, ..DEFAULT }),
            "--show-retouched does not show data"
        );
    }

    #[test]
    fn unmatched_data_says_it_is_data() {
        assert_eq!(unmatched_word("gone", Contents::Code), "gone");
        assert_eq!(unmatched_word("gone", Contents::Data), "gone data");
        assert_eq!(unmatched_word("new", Contents::Data), "new data");
    }

    /// Only unchanged functions and quiet changes are hidden when a reader
    /// wants changes.
    #[test]
    fn unchanged_functions_are_the_only_ones_hidden() {
        let shown = |changed| is_interesting(&edited_pair(changed), DEFAULT);

        assert!(!shown(Changed::No));
        assert!(!shown(Changed::Data), "data is hidden too, by its own flag");
        assert!(shown(Changed::Reordered));
        assert!(shown(Changed::InDetail));
        assert!(shown(Changed::Unreadable));
        assert!(shown(Changed::Yes));
    }

    /// A function that only changed a constant is held back by default.
    #[test]
    fn a_retouched_function_is_hidden_unless_asked_for() {
        let pair = retouched_pair(Changed::InDetail);

        assert!(is_retouched(&pair));
        assert!(!is_interesting(&pair, DEFAULT), "hidden by default");
        assert!(
            is_interesting(&pair, Hidden { retouched: Retouched::Show, ..DEFAULT }),
            "--show-retouched lists it"
        );
        assert!(
            !is_interesting(&pair, Hidden { data: DataRegions::Show, ..DEFAULT }),
            "--show-data does not"
        );
    }

    /// A pair that looks like data is held back by default, even with a
    /// perfect score, and `--show-data` lists it.
    #[test]
    fn a_data_region_is_hidden_unless_asked_for() {
        for pair in [edited_pair(Changed::Data), retouched_pair(Changed::Data)] {
            assert!(!is_interesting(&pair, DEFAULT), "hidden by default");
            assert!(
                !is_interesting(&pair, Hidden { retouched: Retouched::Show, ..DEFAULT }),
                "--show-retouched does not list it"
            );
            assert!(
                is_interesting(&pair, Hidden { data: DataRegions::Show, ..DEFAULT }),
                "--show-data lists it"
            );
        }
    }

    /// A rewritten instruction is a real edit whatever the pair scores.
    ///
    /// `do_mount` in a measured kernel pair scores 1.00 and rewrote
    /// one instruction. Hiding it would lose a real finding.
    #[test]
    fn a_perfect_score_with_an_edit_is_still_shown() {
        let pair = Match { score: 1.0, ..edited_pair(Changed::Yes) };

        assert!(!is_retouched(&pair), "an edited instruction is not a retouch");
        assert!(is_interesting(&pair, DEFAULT));
    }

    /// A pair below a perfect score differs in shape, so it is shown even
    /// when its counts round to nothing.
    #[test]
    fn an_imperfect_score_without_counts_is_still_shown() {
        let pair = Match { score: 0.9, edits: Edits::default(), ..edited_pair(Changed::Yes) };

        assert!(!is_retouched(&pair));
        assert!(is_interesting(&pair, DEFAULT));
    }

    /// The two flags that do not ask about the terminal always agree.
    #[test]
    fn the_color_flag_overrides_what_standard_output_is() {
        assert_eq!(Paint::resolve(When::Always), Paint::On);
        assert_eq!(Paint::resolve(When::Never), Paint::Off);
    }

    /// A test suite captures standard output through a pipe, so `Auto` must
    /// decide against color while these tests run.
    #[test]
    fn auto_gives_no_color_when_standard_output_is_not_a_terminal() {
        assert_eq!(Paint::resolve(When::Auto), Paint::Off);
    }

    /// An unpainted report must write no escape codes at all.
    #[test]
    fn no_color_prints_nothing_around_the_text() {
        let painted = Paint::On.pick(Color::FG_RED).colorize("do_mount").to_string();
        let plain = Paint::Off.pick(Color::FG_RED).colorize("do_mount").to_string();

        assert_eq!(plain, "do_mount");
        assert_ne!(painted, plain, "a painted cell carries escape codes");
    }

    /// The counts read the same with color as without.
    #[test]
    fn color_does_not_change_what_the_counts_say() {
        let edits = Edits { added: 1, removed: 2, edited: 3 };

        assert_eq!(describe_edits(edits, Paint::Off), "1/2/3");
        assert_eq!(describe_edits(Edits::default(), Paint::Off), "-");
        // A dash is not a count, so no color applies to it.
        assert_eq!(describe_edits(Edits::default(), Paint::On), "-");
    }

    /// Each count carries the color of its own kind.
    ///
    /// Coloring the three numbers alike would waste the column: the point is
    /// to tell an addition from a removal at a glance.
    #[test]
    fn each_count_carries_its_own_color() {
        let painted = describe_edits(Edits { added: 1, removed: 2, edited: 3 }, Paint::On);

        assert!(painted.contains(&ADDED_COLOR.colorize("1").to_string()));
        assert!(painted.contains(&REMOVED_COLOR.colorize("2").to_string()));
        assert!(painted.contains(&EDITED_COLOR.colorize("3").to_string()));
        // The separators stay plain, so the field still reads as one value.
        assert_eq!(painted.matches('/').count(), 2);
    }

    /// Each kind of change must be told apart by color.
    ///
    /// Two kinds sharing a color would hide the difference the report exists
    /// to show.
    #[test]
    fn every_change_has_its_own_color() {
        let changes = [
            Changed::No,
            Changed::Reordered,
            Changed::Data,
            Changed::InDetail,
            Changed::Unreadable,
            Changed::Yes,
        ];

        for (index, change) in changes.iter().enumerate() {
            for other in &changes[index + 1..] {
                assert_ne!(
                    color_of(*change).colorize("x").to_string(),
                    color_of(*other).colorize("x").to_string(),
                    "{change:?} and {other:?} must not share a color"
                );
            }
        }
    }
}
