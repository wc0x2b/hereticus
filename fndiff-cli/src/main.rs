//! Command line front end for `fndiff`.
//!
//! The library holds the analysis. This binary reads arguments, prints
//! results, and chooses an exit status.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use console::Term;
use fndiff::matching::{
    Changed, Confidence, Diff, Match, Options, Phase, Progress, UseNames, diff_reporting,
};
use fndiff::obj::{Binary, Isa};
use fndiff::raw::check_base;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

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

    /// Ignore symbol names, as though both binaries were stripped.
    ///
    /// Useful to see what `fndiff` finds from the code alone.
    #[arg(long)]
    ignore_names: bool,

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
    /// addresses.
    #[arg(long, value_parser = parse_address, requires = "raw")]
    base: Option<u64>,

    /// Architecture of a raw image.
    #[arg(long, value_enum, default_value_t = ArchName::Arm32, requires = "raw")]
    arch: ArchName,

    /// How to print the result.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// When to show a progress bar.
    ///
    /// The bar goes to standard error, so it never mixes with the report.
    #[arg(long, value_enum, default_value_t = When::Auto)]
    progress: When,
}

/// Whether to show a display that only a terminal can use.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum When {
    /// Show it when standard error is a terminal.
    Auto,
    Always,
    Never,
}

/// The architectures a raw image can be read as.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum ArchName {
    /// ARM32, little endian, A32 instructions. Thumb is not supported.
    Arm32,
}

impl From<ArchName> for Isa {
    fn from(name: ArchName) -> Self {
        match name {
            ArchName::Arm32 => Self::Arm32,
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
            eprintln!("fndiff: {error}");
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
        let base = args
            .base
            .ok_or("--raw needs --base, because a raw image does not say where it loads")?;

        check_and_report_base(&before_bytes, base, &args.before);
        // Comparing a file with itself is a normal way to inspect one image,
        // and saying the same thing twice about it helps nobody.
        if args.after != args.before {
            check_and_report_base(&after_bytes, base, &args.after);
        }
        eprintln!(
            "fndiff: a raw image has no exception index, so function boundaries \
             are recovered from the code and are approximate"
        );

        (
            parse_raw(&before_bytes, base, args.arch.into(), &args.before)?,
            parse_raw(&after_bytes, base, args.arch.into(), &args.after)?,
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

    match args.format {
        Format::Text => print_text(&diff, &before, &after, args.all, args.near_miss),
        Format::Compact => print_compact(&diff, &before, &after, args.all),
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

/// Warn when the given load address looks wrong for an image.
///
/// A wrong base does not stop anything: the code still decodes and every
/// branch still resolves, because ARM branches are relative. Only the reported
/// addresses are wrong, and silently so. This is the one chance to notice.
fn check_and_report_base(data: &[u8], base: u64, path: &Path) {
    let fit = check_base(data, base);
    if fit.is_suspect() {
        eprintln!("fndiff: {} may not load at {base:#x}: {fit}", path.display());
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
        Changed::Yes => "changed",
    }
}

/// Describe why two functions were paired.
fn describe_confidence(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::IdenticalCode => "identical bytes",
        Confidence::IdenticalShape => "identical shape",
        Confidence::SameName => "same name",
        Confidence::Similar => "similar",
    }
}

/// Report whether a pair should appear when only changes are wanted.
fn is_interesting(pair: &Match) -> bool {
    pair.changed != Changed::No
}

fn print_text(diff: &Diff, before: &Binary, after: &Binary, show_all: bool, near_miss_floor: f64) {
    let shown: Vec<&Match> =
        diff.matched.iter().filter(|pair| show_all || is_interesting(pair)).collect();

    if !shown.is_empty() {
        // A renamed function prints as `old -> new`, which is longer than
        // either name. Build the labels first, then size the column to them,
        // so a rename cannot push the table out of line.
        let labels: Vec<String> = shown
            .iter()
            .map(|pair| {
                let name = name_of(before, pair.before);
                let renamed = name_of(after, pair.after);
                if name == renamed { name } else { format!("{name} -> {renamed}") }
            })
            .collect();

        let width = labels.iter().map(String::len).max().unwrap_or(0).clamp(8, 60);

        println!("{:<width$}  {:<14}  {:>5}  MATCHED BY", "FUNCTION", "CHANGE", "SCORE");
        for (pair, label) in shown.iter().zip(&labels) {
            println!(
                "{:<width$}  {:<14}  {:>5.2}  {}",
                label,
                describe(pair.changed),
                pair.score,
                describe_confidence(pair.confidence),
            );
        }
    }

    for index in &diff.removed {
        match near_miss_note(diff, *index, after, near_miss_floor) {
            Some(note) => println!("{}: gone, {note}", name_of(before, *index)),
            None => println!("{}: gone", name_of(before, *index)),
        }
    }
    for index in &diff.added {
        println!("{}: new", name_of(after, *index));
    }

    summarize(diff);
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

/// Print one line per function, with no header or alignment.
fn print_compact(diff: &Diff, before: &Binary, after: &Binary, show_all: bool) {
    for pair in &diff.matched {
        if show_all || is_interesting(pair) {
            println!(
                "{}\t{}\t{}\t{:.2}",
                describe(pair.changed),
                name_of(before, pair.before),
                name_of(after, pair.after),
                pair.score
            );
        }
    }
    for index in &diff.removed {
        // The fourth column holds the near-miss score, so a script reading
        // this format finds it where a matched pair keeps its score.
        let miss = diff.near_miss(*index);
        let closest =
            miss.and_then(|miss| miss.best).map(|best| name_of(after, best)).unwrap_or_default();
        let score = miss.map_or(0.0, |miss| miss.score);
        println!("gone\t{}\t{closest}\t{score:.2}", name_of(before, *index));
    }
    for index in &diff.added {
        println!("new\t\t{}\t", name_of(after, *index));
    }
}

fn summarize(diff: &Diff) {
    let changed = diff.changed().count();
    let same = diff.matched.len() - changed;
    let nothing_happened = changed == 0 && diff.removed.is_empty() && diff.added.is_empty();

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
        for change in [Changed::No, Changed::Reordered, Changed::InDetail, Changed::Yes] {
            assert!(!describe(change).is_empty());
        }
    }

    /// Only unchanged functions are hidden when a reader wants changes.
    #[test]
    fn unchanged_functions_are_the_only_ones_hidden() {
        let pair = |changed| Match {
            before: 0,
            after: 0,
            confidence: Confidence::IdenticalCode,
            score: 1.0,
            changed,
        };

        assert!(!is_interesting(&pair(Changed::No)));
        assert!(is_interesting(&pair(Changed::Reordered)));
        assert!(is_interesting(&pair(Changed::InDetail)));
        assert!(is_interesting(&pair(Changed::Yes)));
    }
}
