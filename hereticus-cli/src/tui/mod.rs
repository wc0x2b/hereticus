//! Browse a comparison in the terminal.
//!
//! The comparison runs once. The view then sorts, filters and opens the
//! pairs as the reader asks, with no second run. A reader can mark the
//! functions that matter, name them, and save it all as a project to open
//! again later: see [`crate::project`]. [`App`] holds the state and reads the
//! keys, apart from the drawing, so a test can drive it with no terminal.

mod columns;
mod draw;
mod fuzzy;
mod rows;
mod theme;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hereticus::address::Contents;
use hereticus::matching::{
    Diff, DiffLine, EditKind, PairedLabels, View, instruction_diff_in, line_places,
};
use hereticus::obj::Binary;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::crossterm::execute;
use ratatui::layout::{Position, Rect};
use ratatui::widgets::TableState;
use serde::{Deserialize, Serialize};

use rows::{Places, change_starts, side_by_side, unified};

use crate::project::{Project, Source};
use crate::{
    Args, DataRegions, Feature, Hidden, Retouched, Sort, has_features, is_interesting,
    is_shown_unmatched, name_of, rank,
};
use columns::{Column, Widths};

/// How the browser starts.
#[derive(Clone, Debug)]
pub struct Start {
    /// The names of the two files, as the title shows them.
    pub files: [String; 2],
    /// How the two binaries were read, for a project to save.
    pub source: Source,
    /// The project the browser opened, where it opened one.
    pub project: Option<PathBuf>,
    pub saved: Saved,
}

/// What a project keeps of the browser.
#[derive(Clone, Debug)]
pub struct Saved {
    pub browser: Browser,
    pub marks: Vec<Mark>,
}

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
    /// See [`App::filter`].
    pub filter: String,
    pub selected: Option<Key>,
    /// The first row of the diff of the selected row, where it is open.
    pub opened: Option<usize>,
}

impl Browser {
    /// The browser as the flags of the command line start it.
    pub fn from_args(args: &Args) -> Self {
        Self {
            sort: args.sort,
            order: Order::Descending,
            touched: None,
            only: args.only.clone(),
            scope: if args.all { Scope::All } else { Scope::Changed },
            hidden: Hidden::from_args(args),
            near_miss_floor: args.near_miss,
            view: args.view.into(),
            layout: Layout::SideBySide,
            filter: String::new(),
            selected: None,
            opened: None,
        }
    }
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

/// What the keys act on.
#[derive(Debug)]
enum Screen {
    /// The table of pairs.
    Table,
    /// The table, with the keys typing a filter on the names.
    Filter,
    /// The diff of one pair. Boxed, as it is far larger than the rest.
    Pair(Box<Opened>),
}

/// What a row of the table stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Entry {
    /// A pair, by its index in `diff.matched`.
    Pair(usize),
    /// A function of the earlier binary with no counterpart, by its index
    /// in that binary.
    Gone { function: usize, contents: Contents },
    /// A function of the later binary with no counterpart.
    New { function: usize, contents: Contents },
}

/// A row of the table, with the name it shows and filters on.
#[derive(Clone, Debug)]
struct Labeled {
    entry: Entry,
    label: String,
}

/// The diff of the selected row, kept so a redraw does not compute it
/// again.
#[derive(Debug)]
struct Opened {
    lines: Vec<DiffLine>,
    /// The lines of the other view and their places, once shown, so `v`
    /// back is at once.
    other_view: Option<(Vec<DiffLine>, Places)>,
    places: Places,
    /// What a gone or new function is shown against: its closest
    /// candidate.
    against: Option<String>,
    /// The first line shown.
    scroll: usize,
    /// Whether each row shows a change, in the present layout. A long
    /// function has many thousand rows, so a key does not lay them out
    /// again.
    changes: Vec<bool>,
    /// Where each run of changes starts, from `changes`.
    starts: Vec<usize>,
}

impl Opened {
    /// Lay the rows out again, for another layout or other lines.
    fn relayout(&mut self, layout: Layout) {
        self.changes = match layout {
            Layout::SideBySide => side_by_side(&self.lines, &self.places)
                .iter()
                .map(|row| row.left.is_change() || row.right.is_change())
                .collect(),
            Layout::Unified => {
                unified(&self.lines, &self.places).iter().map(|half| half.is_change()).collect()
            }
        };
        self.starts = change_starts(self.changes.iter().copied());
        self.scroll = self.scroll.min(self.changes.len().saturating_sub(1));
    }
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

/// The kinds of code `t` steps through, as the `TOUCHED` column names
/// them. `Other` names nothing a reader can act on, so it is left out.
const TOUCHED_KINDS: [EditKind; 8] = [
    EditKind::Branch,
    EditKind::Call,
    EditKind::Callee,
    EditKind::Jump,
    EditKind::Memory,
    EditKind::Constant,
    EditKind::Text,
    EditKind::Opaque,
];

/// Which way a jump between changes goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Next,
    Previous,
}

/// The rows a jump to a change leaves above it.
const CONTEXT: usize = 3;

/// The kind `t` steps to after `touched`, and none after the last.
/// The features to list by after `only`: the first feature, then each one
/// alone in turn, then none. Two or more, as `--only` can give, go to none.
fn next_features(only: &[Feature]) -> Vec<Feature> {
    let next = match only {
        [] => Feature::ALL.first(),
        [feature] => Feature::ALL
            .iter()
            .position(|known| known == feature)
            .and_then(|at| Feature::ALL.get(at + 1)),
        _ => None,
    };
    next.copied().into_iter().collect()
}

fn next_touched(touched: Option<EditKind>) -> Option<EditKind> {
    let Some(touched) = touched else { return TOUCHED_KINDS.first().copied() };
    let at = TOUCHED_KINDS.iter().position(|&kind| kind == touched)?;
    TOUCHED_KINDS.get(at + 1).copied()
}

/// What shows over the screen and holds the keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Overlay {
    None,
    Help,
    /// Asks whether to quit, as `heretek` does: `Enter` quits and `Esc`
    /// goes back.
    Quit,
}

/// A line of text the reader types, over the screen, and what it is for.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Prompt {
    purpose: Purpose,
    text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Purpose {
    /// The path to save the project to.
    Save,
    /// The label of a mark on a row, by its index in `entries`.
    Label(usize),
}

/// Whether the marks hold a change that no save has kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Changes {
    Saved,
    Unsaved,
}

/// The name a project takes where the reader does not give one.
const PROJECT_EXTENSION: &str = "hereticus.json";

/// Whether the browser goes on after a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    Continue,
    Quit,
}

/// The state of the browser.
pub struct App<'a> {
    diff: &'a Diff,
    paired: PairedLabels,
    before: &'a Binary,
    after: &'a Binary,
    files: [String; 2],
    source: Source,
    /// Where the project was opened from or last saved to.
    project: Option<PathBuf>,
    sort: Sort,
    order: Order,
    /// Lists only the pairs whose edit touched this kind of code.
    touched: Option<EditKind>,
    /// Lists only the pairs that have each of these features.
    only: Vec<Feature>,
    scope: Scope,
    hidden: Hidden,
    near_miss_floor: f64,
    view: View,
    layout: Layout,
    /// Matches a name that holds the letters of this text in order, in any
    /// case: see [`fuzzy`].
    filter: String,
    /// Every row the table can list: the pairs, then the functions gone,
    /// then the new ones.
    entries: Vec<Labeled>,
    /// The rows the table lists, in order, by their index in `entries`.
    rows: Vec<usize>,
    /// The place of each entry in the order, among the rows the scope
    /// lists, from 1. The filters and the marks do not change it, so a
    /// filtered row keeps the rank it has in the full list.
    ranks: Vec<Option<usize>>,
    /// The width of the cells of each entry, as unmarked.
    cell_widths: Vec<Widths>,
    /// The width of the widest cell of each column, over the rows listed.
    natural: Widths,
    table: TableState,
    screen: Screen,
    overlay: Overlay,
    /// The label of each marked row, by its index in `entries`.
    marks: BTreeMap<usize, String>,
    changes: Changes,
    /// Holds the keys while it shows.
    prompt: Option<Prompt>,
    /// What the last save did, until the next key.
    notice: Option<String>,
    /// The height of the last drawn list, which a page moves by.
    page: usize,
    /// Where the last draw put what a click acts on.
    regions: Regions,
}

/// Where the last draw put what a click acts on.
#[derive(Clone, Copy, Debug, Default)]
struct Regions {
    /// The tab of each screen: the functions, then the diff.
    tabs: [Rect; 2],
    /// The rows of the table, below its heading.
    list: Rect,
}

/// How many rows a turn of the mouse wheel moves.
const WHEEL_STEP: isize = 3;

impl<'a> App<'a> {
    pub fn new(diff: &'a Diff, before: &'a Binary, after: &'a Binary, start: Start) -> Self {
        let pairs = diff.matched.iter().enumerate().map(|(index, pair)| {
            let name = name_of(before, pair.before);
            let renamed = name_of(after, pair.after);
            let label = if name == renamed { name } else { format!("{name} -> {renamed}") };
            Labeled { entry: Entry::Pair(index), label }
        });
        let gone = diff.removed_with_contents().map(|(function, contents)| Labeled {
            entry: Entry::Gone { function, contents },
            label: name_of(before, function),
        });
        let new = diff.added_with_contents().map(|(function, contents)| Labeled {
            entry: Entry::New { function, contents },
            label: name_of(after, function),
        });
        let entries = pairs.chain(gone).chain(new).collect();
        let Saved { browser, marks } = start.saved;
        let mut app = Self {
            diff,
            paired: diff.paired_labels(before, after),
            before,
            after,
            files: start.files,
            source: start.source,
            project: start.project,
            sort: browser.sort,
            order: browser.order,
            touched: browser.touched,
            only: browser.only,
            scope: browser.scope,
            hidden: browser.hidden,
            near_miss_floor: browser.near_miss_floor,
            view: browser.view,
            layout: browser.layout,
            filter: browser.filter,
            entries,
            rows: Vec::new(),
            ranks: Vec::new(),
            cell_widths: Vec::new(),
            natural: columns::heading_widths(),
            table: TableState::default(),
            screen: Screen::Table,
            overlay: Overlay::None,
            marks: BTreeMap::new(),
            changes: Changes::Saved,
            prompt: None,
            notice: None,
            page: 10,
            regions: Regions::default(),
        };
        // A mark on a row that the result does not hold is lost: only a
        // project edited by hand names one.
        app.marks = marks
            .into_iter()
            .filter_map(|mark| Some((app.entry_of(mark.row)?, mark.label)))
            .collect();
        app.cell_widths = (0..app.entries.len()).map(|index| app.widths_of(index)).collect();
        app.refresh();
        let selected = browser.selected.and_then(|key| app.entry_of(key));
        if let Some(position) =
            selected.and_then(|kept| app.rows.iter().position(|&row| row == kept))
        {
            app.table.select(Some(position));
            if let Some(scroll) = browser.opened {
                app.open_at(scroll);
            }
        }
        app
    }

    /// The width of each cell of the row of `index` in `entries`.
    fn widths_of(&self, index: usize) -> Widths {
        self.cells(index).map(|cell| u16::try_from(cell.width()).unwrap_or(u16::MAX))
    }

    /// The width of the widest cell of each column, over the rows listed.
    /// The widths of the cells are kept from the start, as building each
    /// row of a kernel again for each order took longer than a sort; a
    /// marked row is measured again, as its label widens its name. The
    /// rank changes with the order, so it is measured each time.
    fn measure(&self) -> Widths {
        self.rows.iter().fold(columns::heading_widths(), |mut widest, &index| {
            let mut widths = if self.marks.contains_key(&index) {
                self.widths_of(index)
            } else {
                self.cell_widths[index]
            };
            widths[Column::Rank.index()] =
                u16::try_from(self.rank_text(index).len()).unwrap_or(u16::MAX);
            for (wide, width) in widest.iter_mut().zip(widths) {
                *wide = (*wide).max(width);
            }
            widest
        })
    }

    /// The key a project names the row `index` of `entries` by.
    fn key_of(&self, index: usize) -> Key {
        match self.entries[index].entry {
            Entry::Pair(pair) => {
                let pair = &self.diff.matched[pair];
                Key::Pair { before: pair.before, after: pair.after }
            }
            Entry::Gone { function, .. } => Key::Gone { function },
            Entry::New { function, .. } => Key::New { function },
        }
    }

    /// The index in `entries` of the row that `key` names.
    fn entry_of(&self, key: Key) -> Option<usize> {
        (0..self.entries.len()).find(|&index| self.key_of(index) == key)
    }

    /// What a project keeps of the browser as it is now.
    fn saved(&self) -> Saved {
        let browser = Browser {
            sort: self.sort,
            order: self.order,
            touched: self.touched,
            only: self.only.clone(),
            scope: self.scope,
            hidden: self.hidden,
            near_miss_floor: self.near_miss_floor,
            view: self.view,
            layout: self.layout,
            filter: self.filter.clone(),
            selected: self.selected_entry().map(|index| self.key_of(index)),
            opened: match &self.screen {
                Screen::Pair(opened) => Some(opened.scroll),
                Screen::Table | Screen::Filter => None,
            },
        };
        let marks = self
            .marks
            .iter()
            .map(|(&index, label)| Mark { row: self.key_of(index), label: label.clone() })
            .collect();
        Saved { browser, marks }
    }

    /// Save the project to `path`, and open it from there from now on.
    fn save(&mut self, path: &Path) -> Result<(), String> {
        let Saved { browser, marks } = self.saved();
        Project::new(self.source.clone(), browser, marks, self.diff).write(path)?;
        self.project = Some(path.to_path_buf());
        self.changes = Changes::Saved;
        Ok(())
    }

    /// The path a save offers first: the last one, or one named for the two
    /// files.
    fn save_path(&self) -> String {
        match &self.project {
            Some(path) => path.display().to_string(),
            None => {
                let [before, after] = &self.files;
                format!("{before}-{after}.{PROJECT_EXTENSION}")
            }
        }
    }

    /// Mark the selected row with no label, or take its mark off.
    fn toggle_mark(&mut self) {
        let Some(index) = self.selected_entry() else { return };
        if self.marks.remove(&index).is_none() {
            self.marks.insert(index, String::new());
        }
        self.changes = Changes::Unsaved;
        self.refresh();
    }

    /// Ask for the label of the selected row, with its present label to
    /// edit. `Enter` marks the row.
    fn ask_label(&mut self) {
        let Some(index) = self.selected_entry() else { return };
        let text = self.marks.get(&index).cloned().unwrap_or_default();
        self.prompt = Some(Prompt { purpose: Purpose::Label(index), text });
    }

    /// Type into the prompt. `Enter` acts on the text, and `Esc` goes back.
    fn handle_prompt(&mut self, code: KeyCode) {
        let Some(prompt) = &mut self.prompt else { return };
        match code {
            KeyCode::Esc => self.prompt = None,
            KeyCode::Backspace => {
                prompt.text.pop();
            }
            KeyCode::Char(character) => prompt.text.push(character),
            KeyCode::Enter => {
                let Some(Prompt { purpose, text }) = self.prompt.take() else { return };
                match purpose {
                    Purpose::Save if text.trim().is_empty() => {
                        self.notice = Some("no path given, so nothing was saved".to_string());
                    }
                    Purpose::Save => {
                        let path = PathBuf::from(text.trim());
                        self.notice = Some(match self.save(&path) {
                            Ok(()) => format!("saved to {}", path.display()),
                            Err(error) => error,
                        });
                    }
                    Purpose::Label(index) => {
                        self.marks.insert(index, text.trim().to_string());
                        self.changes = Changes::Unsaved;
                        self.refresh();
                    }
                }
            }
            _ => {}
        }
    }

    /// Act on a key that each screen but the filter shares, and report
    /// whether it was one.
    fn handle_shared(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Char('m') => self.toggle_mark(),
            KeyCode::Char('M') => self.ask_label(),
            KeyCode::Char('w') => {
                self.prompt = Some(Prompt { purpose: Purpose::Save, text: self.save_path() });
            }
            _ => return false,
        }
        true
    }

    /// Report whether the present scope and the kinds hidden list `entry`.
    fn is_in_scope(&self, entry: Entry) -> bool {
        self.scope == Scope::All
            || match entry {
                Entry::Pair(index) => is_interesting(&self.diff.matched[index], self.hidden),
                Entry::Gone { contents, .. } | Entry::New { contents, .. } => {
                    is_shown_unmatched(contents, self.hidden)
                }
            }
    }

    /// Report whether the table lists `entry` with the present scope and
    /// the kind of code asked for.
    fn is_listed(&self, entry: Entry) -> bool {
        let in_scope = self.is_in_scope(entry);
        // A function gone or new has no edit to touch anything.
        let touches = match (self.touched, entry) {
            (None, _) => true,
            (Some(wanted), Entry::Pair(index)) => {
                self.diff.matched[index].kinds.present().any(|(kind, _)| kind == wanted)
            }
            (Some(_), Entry::Gone { .. } | Entry::New { .. }) => false,
        };
        let has = match entry {
            Entry::Pair(index) => has_features(&self.diff.matched[index], &self.only),
            Entry::Gone { .. } | Entry::New { .. } => self.only.is_empty(),
        };
        in_scope && touches && has
    }

    /// List the rows again, after the order or a filter changed. The
    /// selected row stays selected where it is still listed.
    fn refresh(&mut self) {
        let kept = self.selected_entry();
        // Each entry is put in order, so that each has its rank before the
        // filters take some out.
        let mut rows: Vec<usize> = (0..self.entries.len()).collect();
        // The library lists the pairs strongest first, which is the order
        // `confidence` names. The functions gone and new keep their place
        // after the pairs, as the text report lists them.
        let matched = &self.diff.matched;
        let pair_of = |row: usize| match self.entries[row].entry {
            Entry::Pair(index) => Some(&matched[index]),
            _ => None,
        };
        let pairs = rows.iter().take_while(|&&row| pair_of(row).is_some()).count();
        if self.sort != Sort::Confidence {
            rows[..pairs].sort_by(|&a, &b| match (pair_of(a), pair_of(b)) {
                (Some(a), Some(b)) => rank(a, b, self.sort),
                _ => core::cmp::Ordering::Equal,
            });
        }
        if self.order == Order::Ascending {
            rows[..pairs].reverse();
        }
        let mut ranks = vec![None; self.entries.len()];
        let in_scope = rows.iter().filter(|&&row| self.is_in_scope(self.entries[row].entry));
        for (rank, &row) in (1..).zip(in_scope) {
            ranks[row] = Some(rank);
        }
        self.ranks = ranks;
        let matches = |text: &str| fuzzy::positions(&self.filter, text).is_some();
        rows.retain(|index| {
            let listed =
                self.marks.contains_key(index) || self.is_listed(self.entries[*index].entry);
            listed
                && (matches(&self.entries[*index].label)
                    || self.marks.get(index).is_some_and(|label| matches(label)))
        });
        // A stable sort keeps the order above within the marked rows and
        // within the rest.
        rows.sort_by_key(|row| !self.marks.contains_key(row));
        self.rows = rows;
        self.natural = self.measure();
        let position = kept.and_then(|kept| self.rows.iter().position(|&row| row == kept));
        self.table.select(match (position, self.rows.is_empty()) {
            (_, true) => None,
            (Some(position), false) => Some(position),
            (None, false) => Some(0),
        });
    }

    /// The rank of the row `index` of `entries`, or `-` where the scope
    /// does not list it but a mark does.
    fn rank_text(&self, index: usize) -> String {
        self.ranks
            .get(index)
            .copied()
            .flatten()
            .map_or_else(|| "-".to_string(), |rank| rank.to_string())
    }

    /// The index in `entries` of the selected row.
    fn selected_entry(&self) -> Option<usize> {
        self.rows.get(self.table.selected()?).copied()
    }

    /// Move the selection by `step` rows, and stop at either end.
    fn move_selection(&mut self, step: isize) {
        let Some(last) = self.rows.len().checked_sub(1) else { return };
        let at = self.table.selected().unwrap_or(0);
        self.table.select(Some(at.saturating_add_signed(step).min(last)));
    }

    /// The closest candidate of a function gone or new, with its score,
    /// where it scores at least the floor.
    fn closest(&self, entry: Entry) -> Option<(usize, f64)> {
        let miss = match entry {
            Entry::Pair(_) => return None,
            Entry::Gone { function, .. } => self.diff.near_miss(function),
            Entry::New { function, .. } => self.diff.added_near_miss(function),
        }?;
        Some((miss.best?, miss.score)).filter(|&(_, score)| score >= self.near_miss_floor)
    }

    /// The unpaired function of the other side that sits in the place of a
    /// function gone or new: see [`hereticus::matching::NearMiss::in_place`].
    fn in_place(&self, entry: Entry) -> Option<usize> {
        let miss = match entry {
            Entry::Pair(_) => return None,
            Entry::Gone { function, .. } => self.diff.near_miss(function),
            Entry::New { function, .. } => self.diff.added_near_miss(function),
        }?;
        miss.in_place
    }

    /// Show the diff of the selected row from its top.
    fn open(&mut self) {
        self.open_at(0);
    }

    /// Show the diff of the selected row from the row `scroll`. A function
    /// gone or new shows against its closest candidate, or alone where it
    /// has none.
    fn open_at(&mut self, scroll: usize) {
        let Some(index) = self.selected_entry() else { return };
        let (view, before, after) = (self.view, self.before, self.after);
        let alone = |binary: &Binary, function: usize, side: fn(String) -> DiffLine| {
            let lines = instruction_diff_in(view, None, binary, function, binary, function);
            lines
                .into_iter()
                .map(|line| match line {
                    DiffLine::Same(text) => side(text),
                    line => line,
                })
                .collect()
        };
        let entry = self.entries[index].entry;
        // The two functions the diff compares, as each side of a pair.
        let shown = match (entry, self.closest(entry)) {
            (Entry::Pair(index), _) => {
                let pair = &self.diff.matched[index];
                [(before, pair.before), (after, pair.after)]
            }
            (Entry::Gone { function, .. }, Some((best, _))) => [(before, function), (after, best)],
            (Entry::Gone { function, .. }, None) => [(before, function), (before, function)],
            (Entry::New { function, .. }, Some((best, _))) => [(before, best), (after, function)],
            (Entry::New { function, .. }, None) => [(after, function), (after, function)],
        };
        let places = Places {
            before: line_places(view, shown[0].0, shown[0].1),
            after: line_places(view, shown[1].0, shown[1].1),
        };
        let (lines, against) = match (entry, self.closest(entry)) {
            (Entry::Pair(index), _) => {
                let pair = &self.diff.matched[index];
                (
                    instruction_diff_in(
                        view,
                        Some(&self.paired),
                        before,
                        pair.before,
                        after,
                        pair.after,
                    ),
                    None,
                )
            }
            (Entry::Gone { function, .. }, Some((best, score))) => (
                instruction_diff_in(view, Some(&self.paired), before, function, after, best),
                Some(format!("{} at {score:.2}", name_of(after, best))),
            ),
            (Entry::Gone { function, .. }, None) => {
                (alone(before, function, DiffLine::Removed), None)
            }
            (Entry::New { function, .. }, Some((best, score))) => (
                instruction_diff_in(view, Some(&self.paired), before, best, after, function),
                Some(format!("{} at {score:.2}", name_of(before, best))),
            ),
            (Entry::New { function, .. }, None) => (alone(after, function, DiffLine::Added), None),
        };
        let mut opened = Opened {
            lines,
            other_view: None,
            places,
            against,
            scroll,
            changes: Vec::new(),
            starts: Vec::new(),
        };
        opened.relayout(self.layout);
        self.screen = Screen::Pair(Box::new(opened));
    }

    /// Show the open diff in the other view, from the same row. The two
    /// views hold about a line for each instruction, so the row shows about
    /// the same code.
    fn switch_view(&mut self) {
        self.view = match self.view {
            View::Assembly => View::Il,
            View::Il => View::Assembly,
        };
        let Screen::Pair(opened) = &mut self.screen else { return };
        if let Some((lines, places)) = opened.other_view.take() {
            let lines = core::mem::replace(&mut opened.lines, lines);
            let places = core::mem::replace(&mut opened.places, places);
            opened.other_view = Some((lines, places));
            opened.relayout(self.layout);
            return;
        }
        let shown = (core::mem::take(&mut opened.lines), core::mem::take(&mut opened.places));
        let scroll = opened.scroll;
        self.open_at(scroll);
        if let Screen::Pair(opened) = &mut self.screen {
            opened.other_view = Some(shown);
        }
    }

    /// Scroll the open diff by `step` rows, and stop at either end.
    fn scroll_by(&mut self, step: isize) {
        if let Screen::Pair(opened) = &mut self.screen {
            let last = opened.changes.len().saturating_sub(1);
            opened.scroll = opened.scroll.saturating_add_signed(step).min(last);
        }
    }

    /// Scroll the open diff to the next run of changes, or the one before,
    /// with a few rows above it to read it in.
    fn jump_to_change(&mut self, direction: Direction) {
        let Screen::Pair(opened) = &mut self.screen else { return };
        let at = opened.scroll + CONTEXT;
        // The starts are in order, so a search finds the ones on each side.
        let after = opened.starts.partition_point(|&start| start <= at);
        let before = opened.starts.partition_point(|&start| start < at);
        let target = match direction {
            Direction::Next => opened.starts.get(after),
            Direction::Previous => before.checked_sub(1).and_then(|at| opened.starts.get(at)),
        };
        if let Some(&target) = target {
            opened.scroll = target.saturating_sub(CONTEXT);
        }
    }

    /// Which run of changes the open diff shows at its top, and how many
    /// it holds, as `(2, 5)`.
    fn change_position(&self) -> (usize, usize) {
        let Screen::Pair(opened) = &self.screen else { return (0, 0) };
        let at = opened.scroll + CONTEXT;
        (opened.starts.partition_point(|&start| start <= at), opened.starts.len())
    }

    fn handle(&mut self, key: KeyEvent) -> Flow {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Flow::Quit;
        }
        self.notice = None;
        if self.prompt.is_some() {
            self.handle_prompt(key.code);
            return Flow::Continue;
        }
        match (self.overlay, key.code) {
            (Overlay::Quit, KeyCode::Enter) => return Flow::Quit,
            (Overlay::Help, KeyCode::Esc | KeyCode::Char('q' | '?'))
            | (Overlay::Quit, KeyCode::Esc) => {
                self.overlay = Overlay::None;
                return Flow::Continue;
            }
            (Overlay::Help | Overlay::Quit, _) => return Flow::Continue,
            (Overlay::None, _) => {}
        }
        if key.code == KeyCode::Char('?') && !matches!(self.screen, Screen::Filter) {
            self.overlay = Overlay::Help;
            return Flow::Continue;
        }
        match self.screen {
            Screen::Table => self.handle_table(key.code),
            Screen::Filter => {
                self.handle_filter(key.code);
                Flow::Continue
            }
            Screen::Pair(_) => self.handle_pair(key.code),
        }
    }

    /// Act on the mouse: the wheel moves the list or the diff, a click on a
    /// tab changes the screen, and a click on a row selects it, or opens it
    /// where it is selected already.
    fn handle_mouse(&mut self, mouse: MouseEvent) {
        if self.overlay != Overlay::None || self.prompt.is_some() {
            return;
        }
        let step = match mouse.kind {
            MouseEventKind::ScrollDown => WHEEL_STEP,
            MouseEventKind::ScrollUp => -WHEEL_STEP,
            MouseEventKind::Down(MouseButton::Left) => {
                self.click(Position::new(mouse.column, mouse.row));
                return;
            }
            _ => return,
        };
        match self.screen {
            Screen::Table | Screen::Filter => self.move_selection(step),
            Screen::Pair(_) => self.scroll_by(step),
        }
    }

    fn click(&mut self, at: Position) {
        let [functions, diff] = self.regions.tabs;
        if functions.contains(at) {
            self.screen = Screen::Table;
        } else if diff.contains(at) {
            if !matches!(self.screen, Screen::Pair(_)) {
                self.open();
            }
        } else if self.regions.list.contains(at) && !matches!(self.screen, Screen::Pair(_)) {
            let row = self.table.offset() + usize::from(at.y - self.regions.list.y);
            if row >= self.rows.len() {
                return;
            }
            self.screen = Screen::Table;
            if self.table.selected() == Some(row) {
                self.open();
            } else {
                self.table.select(Some(row));
            }
        }
    }

    fn handle_table(&mut self, code: KeyCode) -> Flow {
        if self.handle_shared(code) {
            return Flow::Continue;
        }
        let page = self.page as isize;
        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.overlay = Overlay::Quit,
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::PageDown => self.move_selection(page),
            KeyCode::PageUp => self.move_selection(-page),
            KeyCode::Home | KeyCode::Char('g') => self.move_selection(isize::MIN),
            KeyCode::End | KeyCode::Char('G') => self.move_selection(isize::MAX),
            KeyCode::Enter => self.open(),
            KeyCode::Char('/') => self.screen = Screen::Filter,
            KeyCode::Char('s') => {
                self.sort = self.sort.next();
                self.refresh();
            }
            KeyCode::Char('S') => {
                self.order = match self.order {
                    Order::Descending => Order::Ascending,
                    Order::Ascending => Order::Descending,
                };
                self.refresh();
            }
            KeyCode::Char('t') => {
                self.touched = next_touched(self.touched);
                self.refresh();
            }
            KeyCode::Char('f') => {
                self.only = next_features(&self.only);
                self.refresh();
            }
            KeyCode::Char('a') => {
                self.scope = match self.scope {
                    Scope::Changed => Scope::All,
                    Scope::All => Scope::Changed,
                };
                self.refresh();
            }
            KeyCode::Char('r') => {
                self.hidden.retouched = match self.hidden.retouched {
                    Retouched::Show => Retouched::Hide,
                    Retouched::Hide => Retouched::Show,
                };
                self.refresh();
            }
            KeyCode::Char('d') => {
                self.hidden.data = match self.hidden.data {
                    DataRegions::Show => DataRegions::Hide,
                    DataRegions::Hide => DataRegions::Show,
                };
                self.refresh();
            }
            _ => {}
        }
        Flow::Continue
    }

    /// Type the filter. The table follows each key, and `Esc` clears it.
    fn handle_filter(&mut self, code: KeyCode) {
        match code {
            KeyCode::Enter => self.screen = Screen::Table,
            KeyCode::Esc => {
                self.filter.clear();
                self.screen = Screen::Table;
            }
            KeyCode::Backspace => {
                self.filter.pop();
            }
            KeyCode::Char(character) => self.filter.push(character),
            _ => return,
        }
        self.refresh();
    }

    fn handle_pair(&mut self, code: KeyCode) -> Flow {
        if self.handle_shared(code) {
            return Flow::Continue;
        }
        let page = self.page as isize;
        let scroll = |app: &mut Self, step: isize| app.scroll_by(step);
        match code {
            KeyCode::Char('q') => self.overlay = Overlay::Quit,
            KeyCode::Esc | KeyCode::Backspace => self.screen = Screen::Table,
            KeyCode::Down | KeyCode::Char('j') => scroll(self, 1),
            KeyCode::Up | KeyCode::Char('k') => scroll(self, -1),
            KeyCode::PageDown | KeyCode::Char(' ') => scroll(self, page),
            KeyCode::PageUp => scroll(self, -page),
            KeyCode::Home | KeyCode::Char('g') => scroll(self, isize::MIN),
            KeyCode::End | KeyCode::Char('G') => scroll(self, isize::MAX),
            KeyCode::Char('v') => self.switch_view(),
            KeyCode::Char('l') => {
                self.layout = match self.layout {
                    Layout::SideBySide => Layout::Unified,
                    Layout::Unified => Layout::SideBySide,
                };
                if let Screen::Pair(opened) = &mut self.screen {
                    opened.relayout(self.layout);
                }
            }
            KeyCode::Char(']') => self.jump_to_change(Direction::Next),
            KeyCode::Char('[') => self.jump_to_change(Direction::Previous),
            KeyCode::Char('n') => {
                self.move_selection(1);
                self.open();
            }
            KeyCode::Char('p') => {
                self.move_selection(-1);
                self.open();
            }
            _ => {}
        }
        Flow::Continue
    }

    /// Whether each row of the open diff shows a change, in the present
    /// layout.
    #[cfg(test)]
    fn diff_changes(&self) -> Vec<bool> {
        let Screen::Pair(opened) = &self.screen else { return Vec::new() };
        opened.changes.clone()
    }

    /// How many rows the open diff takes in the present layout.
    #[cfg(test)]
    fn diff_rows(&self) -> usize {
        match &self.screen {
            Screen::Pair(opened) => opened.changes.len(),
            _ => 0,
        }
    }
}

/// Run the browser until the reader quits.
pub fn run(diff: &Diff, before: &Binary, after: &Binary, start: Start) -> Result<(), String> {
    let mut app = App::new(diff, before, after, start);
    let mut terminal = ratatui::init();
    let result = execute!(std::io::stdout(), EnableMouseCapture)
        .and_then(|()| event_loop(&mut app, &mut terminal));
    // The terminal must get its mouse back even after a failed draw.
    let _ = execute!(std::io::stdout(), DisableMouseCapture);
    ratatui::restore();
    result.map_err(|error| format!("cannot draw on the terminal: {error}"))
}

fn event_loop(app: &mut App<'_>, terminal: &mut DefaultTerminal) -> std::io::Result<()> {
    loop {
        terminal.draw(|frame| app.draw(frame))?;
        match event::read()? {
            // A terminal on Windows sends a release of each key too.
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if app.handle(key) == Flow::Quit {
                    return Ok(());
                }
            }
            Event::Mouse(mouse) => app.handle_mouse(mouse),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use hereticus::matching::{Options, diff_with};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;

    /// Report whether `rows` are in the order `sort` names.
    fn is_ranked(diff: &Diff, rows: &[usize], sort: Sort) -> bool {
        rows.windows(2).all(|pair| {
            rank(&diff.matched[pair[0]], &diff.matched[pair[1]], sort)
                != core::cmp::Ordering::Greater
        })
    }

    fn fixture(name: &str) -> Option<Binary> {
        fixture_in("O2", name)
    }

    /// The fixture `name` of `directory` in `fixtures/build`.
    fn fixture_in(directory: &str, name: &str) -> Option<Binary> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/build")
            .join(directory)
            .join(name);
        let Ok(data) = std::fs::read(&path) else {
            eprintln!("skipped: run `just fixtures` first");
            return None;
        };
        Some(Binary::parse(&data).expect("a fixture parses"))
    }

    /// The firmware fixture before and after its edit.
    fn firmware() -> Option<(Binary, Binary)> {
        Some((fixture("firmware.o")?, fixture("firmware_v2.o")?))
    }

    /// The firmware fixture with no symbols, so each function is named
    /// `sub_<hex>` of its address.
    fn stripped_firmware() -> Option<(Binary, Binary)> {
        Some((
            fixture_in("O2-stripped", "firmware.o")?,
            fixture_in("O2-stripped", "firmware_v2.o")?,
        ))
    }

    /// `basic` at `-O0` and `-O2`, compared from the code alone, where every
    /// function goes and comes: the two levels rewrite too much to pair.
    fn basic_across_levels() -> Option<(Binary, Binary)> {
        let read = |level: &str| {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../fixtures/build")
                .join(level)
                .join("basic.o");
            Some(Binary::parse(&std::fs::read(path).ok()?).expect("a fixture parses"))
        };
        Some((read("O0")?, read("O2")?))
    }

    fn browser() -> Browser {
        Browser {
            sort: Sort::Added,
            order: Order::Descending,
            touched: None,
            only: Vec::new(),
            scope: Scope::Changed,
            hidden: Hidden { retouched: Retouched::Hide, data: DataRegions::Hide },
            near_miss_floor: 0.25,
            view: View::Assembly,
            layout: Layout::SideBySide,
            filter: String::new(),
            selected: None,
            opened: None,
        }
    }

    /// A source that names no real file: a test that saves reads the
    /// project back with no check of the binaries.
    fn source() -> Source {
        let input = |name: &str| crate::project::Input {
            path: PathBuf::from(name),
            sha256: String::new(),
            functions: String::new(),
        };
        Source {
            inputs: [input("/firmware.o"), input("/firmware_v2.o")],
            raw: None,
            threshold: 0.65,
            names: crate::project::Names::Use,
        }
    }

    fn start_with(browser: Browser) -> Start {
        Start {
            files: ["firmware.o".to_string(), "firmware_v2.o".to_string()],
            source: source(),
            project: None,
            saved: Saved { browser, marks: Vec::new() },
        }
    }

    fn start() -> Start {
        start_with(browser())
    }

    fn press(app: &mut App<'_>, codes: &[KeyCode]) -> Flow {
        let mut flow = Flow::Continue;
        for &code in codes {
            flow = app.handle(KeyEvent::from(code));
        }
        flow
    }

    /// The text a draw leaves on a terminal of the given size.
    fn screen(app: &mut App<'_>, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("a test terminal");
        terminal.draw(|frame| app.draw(frame)).expect("a draw");
        let buffer = terminal.backend().buffer();
        let text = buffer.content().chunks(usize::from(width).max(1)).fold(
            String::new(),
            |mut text, row| {
                row.iter().for_each(|cell| text.push_str(cell.symbol()));
                text.push('\n');
                text
            },
        );
        // A release would otherwise change every snapshot.
        let version = concat!(" v", env!("CARGO_PKG_VERSION"), " ");
        text.replace(version, &format!(" v{:<width$} ", "X", width = version.len() - 3))
    }

    #[test]
    fn each_sort_ranks_the_rows_by_its_count() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        let count = app.rows.len();
        assert!(count > 1, "the fixture changes more than one function");
        let pairs = |app: &App<'_>| -> Vec<usize> {
            app.rows
                .iter()
                .filter_map(|&row| match app.entries[row].entry {
                    Entry::Pair(index) => Some(index),
                    _ => None,
                })
                .collect()
        };
        for sort in [Sort::Removed, Sort::Modified, Sort::Rare, Sort::Confidence, Sort::Added] {
            press(&mut app, &[KeyCode::Char('s')]);
            assert_eq!(app.sort, sort);
            assert_eq!(app.rows.len(), count, "a sort keeps every row");
            if sort != Sort::Confidence {
                assert!(is_ranked(&diff, &pairs(&app), sort), "{sort:?}");
            }
        }
    }

    #[test]
    fn the_selection_follows_its_pair_across_a_sort() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        press(&mut app, &[KeyCode::End]);
        let chosen = app.selected_entry();
        press(&mut app, &[KeyCode::Char('s'), KeyCode::Char('s')]);
        assert_eq!(app.selected_entry(), chosen);
    }

    #[test]
    fn all_lists_every_pair_and_toggles_back() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        let changed = app.rows.len();
        press(&mut app, &[KeyCode::Char('a')]);
        let every = diff.matched.len() + diff.removed.len() + diff.added.len();
        assert_eq!(app.rows.len(), every);
        press(&mut app, &[KeyCode::Char('a')]);
        assert_eq!(app.rows.len(), changed);
    }

    #[test]
    fn a_filter_narrows_the_rows_and_escape_clears_it() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        let count = app.rows.len();
        let wanted = app.entries[app.rows[0]].label.clone();
        let mut keys = vec![KeyCode::Char('/')];
        keys.extend(wanted.to_uppercase().chars().map(KeyCode::Char));
        press(&mut app, &keys);
        assert!(app.rows.iter().all(|&row| app.entries[row].label.contains(&wanted)));
        assert!(app.rows.contains(&app.selected_entry().expect("a row")));

        press(&mut app, &[KeyCode::Char('#')]);
        assert!(app.rows.is_empty(), "no name holds `#`");
        assert_eq!(app.selected_entry(), None);
        press(&mut app, &[KeyCode::Enter, KeyCode::Enter]);
        assert!(matches!(app.screen, Screen::Table), "no row to open");

        press(&mut app, &[KeyCode::Char('/'), KeyCode::Backspace, KeyCode::Esc]);
        assert_eq!(app.rows.len(), count);
        assert!(app.filter.is_empty());
    }

    #[test]
    fn a_pair_opens_switches_view_and_closes() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        press(&mut app, &[KeyCode::Enter]);
        let Screen::Pair(opened) = &app.screen else { panic!("the pair opens") };
        let assembly = opened.lines.clone();
        assert!(!assembly.is_empty());
        assert!(screen(&mut app, 120, 30).contains("view asm"));

        press(&mut app, &[KeyCode::Char('v')]);
        let Screen::Pair(opened) = &app.screen else { panic!("the pair stays open") };
        assert_eq!(app.view, View::Il);
        assert_ne!(opened.lines, assembly, "IL reads otherwise");
        assert!(screen(&mut app, 120, 30).contains("view il"));

        press(&mut app, &[KeyCode::End]);
        let Screen::Pair(opened) = &app.screen else { panic!("the pair stays open") };
        assert_eq!(opened.scroll, app.diff_rows() - 1);

        assert_eq!(press(&mut app, &[KeyCode::Esc]), Flow::Continue);
        assert!(matches!(app.screen, Screen::Table));
        assert_eq!(press(&mut app, &[KeyCode::Char('q')]), Flow::Continue);
        assert_eq!(app.overlay, Overlay::Quit, "`q` asks first");
        assert_eq!(press(&mut app, &[KeyCode::Enter]), Flow::Quit);
    }

    #[test]
    fn functions_gone_and_new_follow_the_pairs() {
        let Some((before, after)) = basic_across_levels() else { return };
        let options =
            Options { use_names: hereticus::matching::UseNames::No, ..Options::default() };
        let diff = diff_with(&before, &after, options);
        assert_eq!((diff.removed.len(), diff.added.len()), (8, 8), "the fixture is as expected");
        let mut app = App::new(&diff, &before, &after, start());
        let kinds: Vec<Entry> = app.rows.iter().map(|&row| app.entries[row].entry).collect();
        let first_unmatched = kinds.iter().position(|entry| !matches!(entry, Entry::Pair(_)));
        let first_unmatched = first_unmatched.expect("gone and new rows");
        assert!(kinds[first_unmatched..].iter().all(|entry| !matches!(entry, Entry::Pair(_))));
        assert!(matches!(kinds[first_unmatched], Entry::Gone { .. }), "gone rows come first");
        assert!(matches!(kinds.last(), Some(Entry::New { .. })));
        insta::assert_snapshot!("tui_gone_and_new", screen(&mut app, 120, 12));

        // A function with a close candidate shows against it.
        let row = |app: &App<'_>, label: &str, gone: bool| {
            app.rows.iter().position(|&row| {
                app.entries[row].label == label
                    && matches!(app.entries[row].entry, Entry::Gone { .. }) == gone
            })
        };
        app.table.select(row(&app, "mul_by_constant", true));
        press(&mut app, &[KeyCode::Enter]);
        let Screen::Pair(opened) = &app.screen else { panic!("the row opens") };
        assert_eq!(opened.against.as_deref(), Some("mul_by_constant at 0.50"));

        // One with none shows alone, every line removed or added.
        press(&mut app, &[KeyCode::Esc]);
        app.table.select(row(&app, "factorial", true));
        press(&mut app, &[KeyCode::Enter]);
        let Screen::Pair(opened) = &app.screen else { panic!("the row opens") };
        assert_eq!(opened.against, None);
        assert!(opened.lines.iter().all(|line| matches!(line, DiffLine::Removed(_))));
        press(&mut app, &[KeyCode::Esc]);
        app.table.select(row(&app, "factorial", false));
        press(&mut app, &[KeyCode::Enter]);
        let Screen::Pair(opened) = &app.screen else { panic!("the row opens") };
        assert!(opened.lines.iter().all(|line| matches!(line, DiffLine::Added(_))));
    }

    #[test]
    fn the_diff_jumps_between_its_changes() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        press(&mut app, &[KeyCode::Enter]);
        let starts = change_starts(app.diff_changes());
        assert!(starts.len() > 2, "the fixture changes more than two places");
        let scroll = |app: &App<'_>| match &app.screen {
            Screen::Pair(opened) => opened.scroll,
            _ => panic!("the diff stays open"),
        };

        for &start in &starts[1..] {
            press(&mut app, &[KeyCode::Char(']')]);
            assert_eq!(scroll(&app), start.saturating_sub(CONTEXT));
        }
        let last = scroll(&app);
        press(&mut app, &[KeyCode::Char(']')]);
        assert_eq!(scroll(&app), last, "no change after the last");
        assert_eq!(app.change_position(), (starts.len(), starts.len()));

        press(&mut app, &[KeyCode::Char('[')]);
        let before_last = starts[starts.len() - 2];
        assert_eq!(scroll(&app), before_last.saturating_sub(CONTEXT));

        // A change of view keeps the place.
        let kept = scroll(&app);
        press(&mut app, &[KeyCode::Char('v')]);
        assert_eq!(scroll(&app), kept);
        press(&mut app, &[KeyCode::Char('n')]);
        assert_eq!(scroll(&app), 0, "another function opens at its top");
    }

    /// How many lines of `lines` each side shows.
    fn lines_per_side(lines: &[DiffLine]) -> (usize, usize) {
        lines.iter().fold((0, 0), |(before, after), line| match line {
            DiffLine::Same(_) | DiffLine::Changed { .. } => (before + 1, after + 1),
            DiffLine::Removed(_) => (before + 1, after),
            DiffLine::Added(_) => (before, after + 1),
        })
    }

    /// The IL view folds the making of the global pointer into one line, so
    /// it shows fewer lines than instructions, and each view keeps its own
    /// addresses.
    #[test]
    fn each_view_holds_an_address_for_each_line() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/backports");
        let read = |variant: &str| {
            let data =
                std::fs::read(path.join(format!("lua-{variant}/mips-gcc-O2/lib.so"))).ok()?;
            Some(Binary::parse(&data).expect("a fixture parses"))
        };
        let (Some(before), Some(after)) = (read("before"), read("after")) else { return };
        let diff = diff_with(&before, &after, Options::default());
        let start = start_with(Browser { view: View::Il, scope: Scope::All, ..browser() });
        let mut app = App::new(&diff, &before, &after, start);
        let per_side = |app: &App<'_>| match &app.screen {
            Screen::Pair(opened) => {
                let places = (opened.places.before.len(), opened.places.after.len());
                assert_eq!(lines_per_side(&opened.lines), places, "{:?}", app.view);
                opened
                    .lines
                    .iter()
                    .any(|line| matches!(line, DiffLine::Same(text) if text == "gp = _gp"))
            }
            _ => panic!("the diff stays open"),
        };
        press(&mut app, &[KeyCode::Enter]);
        let mut folded = false;
        // The first pairs are enough to meet the global pointer.
        for _ in 0..app.rows.len().min(50) {
            folded |= per_side(&app);
            press(&mut app, &[KeyCode::Char('v')]);
            per_side(&app);
            press(&mut app, &[KeyCode::Char('v')]);
            per_side(&app);
            press(&mut app, &[KeyCode::Char('n')]);
        }
        assert!(folded, "a function makes the global pointer");
    }

    /// On each architecture, the IL view indents the lines in the jumps of
    /// a function and the assembly view does not, and `v` and `l` keep the
    /// depth of each line.
    #[test]
    fn the_il_view_indents_on_each_architecture() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/backports");
        let read = |variant: &str, arch: &str| {
            let data =
                std::fs::read(path.join(format!("lua-{variant}/{arch}-gcc-O2/lib.so"))).ok()?;
            Some(Binary::parse(&data).expect("a fixture parses"))
        };
        let places = |app: &App<'_>| match &app.screen {
            Screen::Pair(opened) => {
                let counts = (opened.places.before.len(), opened.places.after.len());
                assert_eq!(lines_per_side(&opened.lines), counts, "{:?}", app.view);
                opened.places.clone()
            }
            _ => panic!("the diff stays open"),
        };
        let depths = |places: &Places| -> Vec<usize> {
            places.before.iter().chain(&places.after).map(|place| place.depth).collect()
        };
        for arch in ["arm", "thumb", "aarch64", "mips", "mipsel", "mips16", "i686", "x86_64"] {
            let (Some(before), Some(after)) = (read("before", arch), read("after", arch)) else {
                return;
            };
            let diff = diff_with(&before, &after, Options::default());
            let start = start_with(Browser { view: View::Il, scope: Scope::All, ..browser() });
            let mut app = App::new(&diff, &before, &after, start);
            press(&mut app, &[KeyCode::Enter]);
            let mut indented = false;
            for _ in 0..app.rows.len().min(30) {
                let il = places(&app);
                indented |= depths(&il).iter().any(|&depth| depth > 0);
                press(&mut app, &[KeyCode::Char('v')]);
                assert!(depths(&places(&app)).iter().all(|&depth| depth == 0), "{arch}: asm");
                press(&mut app, &[KeyCode::Char('v')]);
                assert_eq!(places(&app), il, "{arch}: the IL again");
                let side_by_side_depths: Vec<usize> = match &app.screen {
                    Screen::Pair(opened) => side_by_side(&opened.lines, &opened.places)
                        .iter()
                        .flat_map(|row| [row.left, row.right])
                        .filter(|half| half.address.is_some())
                        .map(|half| half.depth)
                        .collect(),
                    _ => panic!("the diff stays open"),
                };
                assert_eq!(
                    side_by_side_depths.iter().sum::<usize>(),
                    depths(&il).iter().sum::<usize>(),
                    "{arch}: each line of each side shows its depth"
                );
                press(&mut app, &[KeyCode::Char('n')]);
            }
            assert!(indented, "{arch}: a function of Lua has a jump");
        }
    }

    #[test]
    fn each_line_of_a_diff_names_its_address() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        press(&mut app, &[KeyCode::Enter]);
        let Some(Entry::Pair(index)) = app.selected_entry().map(|row| app.entries[row].entry)
        else {
            panic!("a pair is selected");
        };
        let pair = &diff.matched[index];
        let Screen::Pair(opened) = &app.screen else { panic!("the diff opens") };
        let rows = side_by_side(&opened.lines, &opened.places);
        let first = |side: fn(&rows::SideRow<'_>) -> Option<u64>| rows.iter().find_map(side);
        assert_eq!(first(|row| row.left.address), Some(before.functions[pair.before].address));
        assert_eq!(first(|row| row.right.address), Some(after.functions[pair.after].address));
        let count =
            |side: fn(&rows::SideRow<'_>) -> Option<u64>| rows.iter().filter_map(side).count();
        assert_eq!(count(|row| row.left.address), opened.places.before.len());
        assert_eq!(count(|row| row.right.address), opened.places.after.len());
    }

    #[test]
    fn a_feature_narrows_the_pairs_and_cycles_back() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        let every = app.rows.len();
        for feature in Feature::ALL {
            press(&mut app, &[KeyCode::Char('f')]);
            assert_eq!(app.only, [feature]);
            for &row in &app.rows {
                let Entry::Pair(index) = app.entries[row].entry else {
                    panic!("only pairs have a feature");
                };
                assert!(feature.holds(&diff.matched[index]), "{feature:?}");
            }
        }
        press(&mut app, &[KeyCode::Char('f')]);
        assert!(app.only.is_empty(), "after the last feature, every pair");
        assert_eq!(app.rows.len(), every);

        // The fixture adds a call, so `added-call` keeps a row.
        app.only = vec![Feature::AddedCall];
        app.refresh();
        assert!(!app.rows.is_empty());
        assert!(screen(&mut app, 120, 12).contains("only added-call"));
    }

    /// A narrow terminal shrinks the kinds touched and how a pair matched
    /// before the names, and ends each cell cut short in `…`. One narrower
    /// still drops those two columns.
    #[test]
    fn a_narrow_screen_shrinks_the_columns_read_last() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        let narrow = screen(&mut app, 90, 8);
        assert!(narrow.contains('…'), "{narrow}");
        assert!(narrow.contains("check_header"), "{narrow}");
        insta::assert_snapshot!("tui_narrow", narrow);
        let narrower = screen(&mut app, 60, 8);
        assert!(!narrower.contains("MATCHED"), "{narrower}");
        assert!(narrower.contains("check_header"), "{narrower}");
    }

    /// The screen of the book that shows a feature in use.
    #[test]
    fn the_screen_of_a_feature_is_locked() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        press(&mut app, &[KeyCode::Char('f'); 4]);
        assert_eq!(app.only, [Feature::RemovedBranch], "as `book/tapes/tui.tape` presses it");
        insta::assert_snapshot!("tui_feature", screen(&mut app, 120, 12));
    }

    /// Two features, as `--only` can give, go to none with one key.
    #[test]
    fn the_next_features_after_two_are_none() {
        assert!(next_features(&[Feature::AddedCall, Feature::Text]).is_empty());
        assert_eq!(next_features(&[]), [Feature::AddedCall]);
        assert_eq!(next_features(&[Feature::AddedCall]), [Feature::RemovedCall]);
        assert!(next_features(&[Feature::Constant]).is_empty(), "the last goes to none");
    }

    #[test]
    fn a_kind_touched_narrows_the_pairs_and_cycles_back() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        let every = app.rows.len();
        for &kind in &TOUCHED_KINDS {
            press(&mut app, &[KeyCode::Char('t')]);
            assert_eq!(app.touched, Some(kind));
            for &row in &app.rows {
                let Entry::Pair(index) = app.entries[row].entry else {
                    panic!("only pairs touch code");
                };
                assert!(diff.matched[index].kinds.present().any(|(touched, _)| touched == kind));
            }
        }
        press(&mut app, &[KeyCode::Char('t')]);
        assert_eq!(app.touched, None, "after the last kind, every kind");
        assert_eq!(app.rows.len(), every);

        // The fixture adds a call, so `call` keeps a row.
        app.touched = Some(EditKind::Call);
        app.refresh();
        assert!(!app.rows.is_empty());
        assert!(screen(&mut app, 120, 12).contains("touched call"));
    }

    #[test]
    fn a_reversed_sort_lists_the_pairs_the_other_way() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        let forward = app.rows.clone();
        press(&mut app, &[KeyCode::Char('S')]);
        assert_eq!(app.order, Order::Ascending);
        let backward: Vec<usize> = app.rows.iter().rev().copied().collect();
        assert_eq!(backward, forward);
        assert!(screen(&mut app, 120, 12).contains("sort added ↑"));
        press(&mut app, &[KeyCode::Char('S')]);
        assert_eq!(app.rows, forward);
    }

    #[test]
    fn the_filter_matches_letters_in_order() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        // `dsp` is no part of `dispatch`, but its letters come in order.
        press(
            &mut app,
            &[KeyCode::Char('/'), KeyCode::Char('d'), KeyCode::Char('s'), KeyCode::Char('p')],
        );
        let labels: Vec<&str> =
            app.rows.iter().map(|&row| app.entries[row].label.as_str()).collect();
        assert_eq!(labels, ["dispatch"]);
    }

    /// The A385-DB-AP kernels of two releases, read raw: about 20000
    /// functions each.
    fn kernels() -> Option<(Binary, Binary)> {
        let read = |release: &str| {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../fixtures/build/openwrt")
                .join(format!("arm-a385dbap-kernel-{release}.bin"));
            let Ok(data) = std::fs::read(&path) else {
                eprintln!("skipped: run `just firmware` first");
                return None;
            };
            let isa = hereticus::obj::Isa::Arm32;
            Some(Binary::parse_raw(&data, 0xc000_8000, isa).expect("a kernel parses"))
        };
        Some((read("22.03.2")?, read("22.03.5")?))
    }

    /// A kernel lists many thousand functions, and one of its regions
    /// diffs to some 200000 rows. A key must answer at once on both: the
    /// budgets are ten times what each takes, and a fifth of what each took
    /// when every frame built every row.
    #[test]
    fn slow_a_kernel_stays_responsive() {
        use std::time::{Duration, Instant};
        let Some((before, after)) = kernels() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        press(&mut app, &[KeyCode::Char('a')]);
        assert!(app.rows.len() > 20_000, "the kernels list {} rows", app.rows.len());

        // The mean time of a key and the draw after it, a hundred times.
        let per_step = |app: &mut App<'_>, key: KeyCode| {
            let at = Instant::now();
            for _ in 0..100 {
                press(app, &[key]);
                screen(app, 200, 60);
            }
            at.elapsed() / 100
        };
        let list = per_step(&mut app, KeyCode::Down);
        assert!(list < Duration::from_millis(12), "a step of the list takes {list:?}");
        let sort = per_step(&mut app, KeyCode::Char('s'));
        assert!(sort < Duration::from_millis(30), "a sort takes {sort:?}");

        let longest = (0..app.rows.len())
            .max_by_key(|&at| match app.entries[app.rows[at]].entry {
                Entry::Pair(index) => before.functions[diff.matched[index].before].code.len(),
                _ => 0,
            })
            .expect("a row");
        app.table.select(Some(longest));
        press(&mut app, &[KeyCode::Enter]);
        assert!(app.diff_rows() > 100_000, "the diff holds {} rows", app.diff_rows());
        let scroll = per_step(&mut app, KeyCode::Down);
        assert!(scroll < Duration::from_millis(35), "a step of the diff takes {scroll:?}");
        let jump = per_step(&mut app, KeyCode::Char(']'));
        assert!(jump < Duration::from_millis(35), "a jump takes {jump:?}");

        // A row past what a `u16` holds still shows.
        press(&mut app, &[KeyCode::End]);
        let Screen::Pair(opened) = &app.screen else { panic!("the diff stays open") };
        assert!(opened.scroll > usize::from(u16::MAX));
        let last = screen(&mut app, 200, 60);
        assert!(last.lines().nth(3).is_some_and(|line| line.contains(['+', '-', '~'])), "{last}");

        // The second change of view takes the lines the first one kept.
        press(&mut app, &[KeyCode::Char('v')]);
        let at = Instant::now();
        press(&mut app, &[KeyCode::Char('v')]);
        let back = at.elapsed();
        assert!(back < Duration::from_millis(50), "a change of view back takes {back:?}");
    }

    #[test]
    fn quitting_asks_first() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        for opening in [KeyCode::Char('q'), KeyCode::Esc] {
            assert_eq!(press(&mut app, &[opening]), Flow::Continue);
            assert_eq!(app.overlay, Overlay::Quit);
            // The question holds the keys and the mouse.
            let selected = app.table.selected();
            assert_eq!(press(&mut app, &[KeyCode::Down, KeyCode::Char('q')]), Flow::Continue);
            screen(&mut app, 120, 12);
            app.handle_mouse(mouse(MouseEventKind::ScrollDown, 10, 10));
            assert_eq!(app.table.selected(), selected);
            assert_eq!(press(&mut app, &[KeyCode::Esc]), Flow::Continue);
            assert_eq!(app.overlay, Overlay::None, "`Esc` goes back");
        }
        press(&mut app, &[KeyCode::Char('q')]);
        insta::assert_snapshot!("tui_quit", screen(&mut app, 120, 12));
        assert_eq!(press(&mut app, &[KeyCode::Enter]), Flow::Quit);

        // Ctrl+C quits at once, from anywhere.
        let mut app = App::new(&diff, &before, &after, start());
        press(&mut app, &[KeyCode::Char('?')]);
        let control_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(app.handle(control_c), Flow::Quit);
    }

    #[test]
    fn help_opens_over_any_screen_and_holds_the_keys() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        press(&mut app, &[KeyCode::Char('?')]);
        assert_eq!(app.overlay, Overlay::Help);
        let sort = app.sort;
        assert_eq!(press(&mut app, &[KeyCode::Char('s'), KeyCode::Char('q')]), Flow::Continue);
        assert_eq!(app.sort, sort, "the help holds the keys");
        assert_eq!(app.overlay, Overlay::None, "`q` closes the help, not the browser");

        // In the filter, `?` is a letter of a name.
        press(&mut app, &[KeyCode::Char('/'), KeyCode::Char('?')]);
        assert_eq!(app.overlay, Overlay::None);
        assert_eq!(app.filter, "?");

        press(&mut app, &[KeyCode::Esc, KeyCode::Enter, KeyCode::Char('?')]);
        assert!(matches!(app.screen, Screen::Pair(_)));
        assert_eq!(app.overlay, Overlay::Help);
        press(&mut app, &[KeyCode::Esc]);
        assert_eq!(app.overlay, Overlay::None);
        assert!(matches!(app.screen, Screen::Pair(_)), "`esc` closes the help only");
    }

    /// Each screen as a reader sees it, so a change to the look shows in
    /// review.
    #[test]
    fn each_screen_is_locked() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        insta::assert_snapshot!("tui_pairs", screen(&mut app, 120, 12));
        press(&mut app, &[KeyCode::Char('/'), KeyCode::Char('h')]);
        insta::assert_snapshot!("tui_filter", screen(&mut app, 120, 12));
        press(&mut app, &[KeyCode::Esc, KeyCode::Enter]);
        insta::assert_snapshot!("tui_diff", screen(&mut app, 120, 24));
        press(&mut app, &[KeyCode::Char('v'), KeyCode::Char('l')]);
        insta::assert_snapshot!("tui_diff_il_unified", screen(&mut app, 120, 16));
        press(&mut app, &[KeyCode::Char('?')]);
        insta::assert_snapshot!("tui_help", screen(&mut app, 120, 24));
    }

    #[test]
    fn the_table_shows_its_heading_and_order() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        let shown = screen(&mut app, 120, 20);
        assert!(shown.contains("FUNCTION"), "{shown}");
        assert!(shown.contains("sort added"), "{shown}");
        assert!(shown.contains(&app.entries[app.rows[0]].label), "{shown}");
    }

    #[test]
    fn any_keys_keep_the_selection_inside_the_rows() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        const KEYS: [KeyCode; 25] = [
            KeyCode::Up,
            KeyCode::Down,
            KeyCode::PageUp,
            KeyCode::PageDown,
            KeyCode::Home,
            KeyCode::End,
            KeyCode::Enter,
            KeyCode::Esc,
            KeyCode::Backspace,
            KeyCode::Char('/'),
            KeyCode::Char('s'),
            KeyCode::Char('a'),
            KeyCode::Char('r'),
            KeyCode::Char('d'),
            KeyCode::Char('v'),
            KeyCode::Char('l'),
            KeyCode::Char('n'),
            KeyCode::Char('p'),
            KeyCode::Char(']'),
            KeyCode::Char('['),
            KeyCode::Char('?'),
            KeyCode::Char('t'),
            KeyCode::Char('S'),
            // Not `w`: `Enter` on its prompt would write a file.
            KeyCode::Char('m'),
            KeyCode::Char('M'),
        ];
        const MICE: [MouseEventKind; 3] = [
            MouseEventKind::ScrollDown,
            MouseEventKind::ScrollUp,
            MouseEventKind::Down(MouseButton::Left),
        ];
        type Input = (Vec<(u8, u8, u8)>, u8, u8);
        bolero::check!().with_type::<Input>().for_each(|(events, width, height)| {
            let (width, height) = (u16::from(*width), u16::from(*height));
            let mut app = App::new(&diff, &before, &after, start());
            for &(kind, column, row) in events {
                // A click acts on where the last draw put things.
                screen(&mut app, width, height);
                let kind = usize::from(kind);
                if let Some(&mouse) = MICE.get(kind % 32) {
                    let (column, row) = (u16::from(column), u16::from(row));
                    let modifiers = KeyModifiers::NONE;
                    app.handle_mouse(MouseEvent { kind: mouse, column, row, modifiers });
                } else if app.handle(KeyEvent::from(KEYS[kind % KEYS.len()])) == Flow::Quit {
                    // `Enter` on the question to quit ends the run.
                    return;
                }
                match app.table.selected() {
                    Some(at) => assert!(at < app.rows.len()),
                    None => assert!(app.rows.is_empty()),
                }
                if let Screen::Pair(opened) = &app.screen {
                    assert!(opened.scroll < app.diff_rows().max(1));
                }
            }
        });
    }

    /// Type `text` into the prompt or the filter.
    fn type_text(app: &mut App<'_>, text: &str) {
        let keys: Vec<KeyCode> = text.chars().map(KeyCode::Char).collect();
        press(app, &keys);
    }

    /// Mark the selected row with `label`.
    fn mark(app: &mut App<'_>, label: &str) {
        press(app, &[KeyCode::Char('M')]);
        type_text(app, label);
        press(app, &[KeyCode::Enter]);
    }

    /// A directory of its own for each test that saves.
    fn scratch(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("hereticus-tui-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a directory");
        directory
    }

    #[test]
    fn a_marked_row_rises_to_the_top_with_its_label() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        press(&mut app, &[KeyCode::End]);
        let chosen = app.selected_entry().expect("a row");
        assert_ne!(app.rows[0], chosen, "the fixture lists more than one row");

        mark(&mut app, "auth bypass");
        assert_eq!(app.rows[0], chosen);
        assert_eq!(app.selected_entry(), Some(chosen), "the selection follows the row");
        assert_eq!(app.changes, Changes::Unsaved);
        let shown = screen(&mut app, 120, 12);
        assert!(shown.contains(&format!(
            "{}{}",
            crate::marks::MARK_SIGN,
            app.entries[chosen].label
        )));
        assert!(shown.contains("[auth bypass]"), "{shown}");
        assert!(shown.contains("1 marked"), "{shown}");
        insta::assert_snapshot!("tui_marked", shown);

        // Each order, and the other way, keeps it first.
        for _ in 0..5 {
            press(&mut app, &[KeyCode::Char('s')]);
            assert_eq!(app.rows[0], chosen, "{:?}", app.sort);
        }
        press(&mut app, &[KeyCode::Char('S')]);
        assert_eq!(app.rows[0], chosen);

        // `M` again edits the label, and `Esc` keeps the old one.
        press(&mut app, &[KeyCode::Char('M')]);
        assert_eq!(app.prompt.as_ref().map(|prompt| prompt.text.as_str()), Some("auth bypass"));
        type_text(&mut app, " again");
        press(&mut app, &[KeyCode::Esc]);
        assert_eq!(app.marks.get(&chosen).map(String::as_str), Some("auth bypass"));

        press(&mut app, &[KeyCode::Char('m')]);
        assert!(app.marks.is_empty());
        let unmarked =
            App::new(&diff, &before, &after, start_with(Browser { order: app.order, ..browser() }));
        assert_eq!(app.rows, unmarked.rows, "an unmarked row goes back to its place");
    }

    #[test]
    fn m_marks_with_no_label_and_again_unmarks() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        let unmarked = app.rows.clone();
        press(&mut app, &[KeyCode::End]);
        let chosen = app.selected_entry().expect("a row");

        press(&mut app, &[KeyCode::Char('m')]);
        assert!(app.prompt.is_none(), "no label is asked for");
        assert_eq!(app.marks.get(&chosen).map(String::as_str), Some(""));
        assert_eq!(app.rows[0], chosen);
        assert_eq!(app.changes, Changes::Unsaved);

        press(&mut app, &[KeyCode::Char('m')]);
        assert!(app.marks.is_empty());
        assert_eq!(app.rows, unmarked);
        assert_eq!(app.selected_entry(), Some(chosen), "the selection follows the row");
    }

    #[test]
    fn a_stripped_function_marks_with_and_without_a_label() {
        let Some((before, after)) = stripped_firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        assert!(
            app.rows.iter().all(|&row| app.entries[row].label.starts_with("sub_")),
            "a stripped binary names no function"
        );
        press(&mut app, &[KeyCode::End]);
        let unlabeled = app.selected_entry().expect("a row");
        press(&mut app, &[KeyCode::Char('m')]);
        press(&mut app, &[KeyCode::End]);
        let labeled = app.selected_entry().expect("a row");
        mark(&mut app, "parser");

        let shown = screen(&mut app, 120, 12);
        let name =
            |index: usize| format!("{}{}", crate::marks::MARK_SIGN, app.entries[index].label);
        assert!(shown.contains(&name(unlabeled)), "{shown}");
        assert!(shown.contains(&format!("{}  [parser]", name(labeled))), "{shown}");
        assert!(shown.contains("2 marked"), "{shown}");
        insta::assert_snapshot!("tui_marked_stripped", shown);

        // The filter finds a row by the address in its name.
        press(&mut app, &[KeyCode::Char('/')]);
        let address = app.entries[unlabeled].label.trim_start_matches("sub_").to_string();
        type_text(&mut app, &address);
        assert_eq!(app.rows.first(), Some(&unlabeled), "{:?}", app.rows);
    }

    #[test]
    fn a_row_keeps_its_rank_through_the_filters_and_the_marks() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        let ranks: Vec<String> = app.rows.iter().map(|&row| app.rank_text(row)).collect();
        let wanted: Vec<String> = (1..=app.rows.len()).map(|rank| rank.to_string()).collect();
        assert_eq!(ranks, wanted, "with no filter, the rank is the place in the list");

        let last = *app.rows.last().expect("a row");
        let rank = app.rank_text(last);
        press(&mut app, &[KeyCode::End, KeyCode::Char('m')]);
        assert_eq!(app.rows[0], last);
        assert_eq!(app.rank_text(last), rank, "a mark lifts the row but keeps its rank");

        press(&mut app, &[KeyCode::Char('m'), KeyCode::Char('/')]);
        let name = app.entries[last].label.clone();
        type_text(&mut app, &name);
        assert_eq!(app.rows.first(), Some(&last));
        assert_eq!(app.rank_text(last), rank, "the filter keeps the rank");
        let shown = screen(&mut app, 120, 12);
        assert!(shown.contains(&format!("{rank}  {}", app.entries[last].label)), "{shown}");

        // The other order turns the ranks around.
        press(&mut app, &[KeyCode::Esc, KeyCode::Char('S')]);
        assert_eq!(app.rank_text(last), "1");
    }

    #[test]
    fn a_mark_outlasts_every_filter_but_the_names() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        // A pair that did not change, which the default scope hides.
        let mut app = App::new(
            &diff,
            &before,
            &after,
            start_with(Browser { scope: Scope::All, ..browser() }),
        );
        let same = app
            .rows
            .iter()
            .position(|&row| matches!(app.entries[row].entry, Entry::Pair(pair) if diff.matched[pair].changed == hereticus::matching::Changed::No))
            .expect("a pair that did not change");
        app.table.select(Some(same));
        let chosen = app.selected_entry().expect("a row");
        mark(&mut app, "");
        press(&mut app, &[KeyCode::Char('a')]);
        assert_eq!(app.scope, Scope::Changed);
        assert_eq!(app.rows[0], chosen, "out of scope, but marked");
        assert_eq!(app.rank_text(chosen), "-", "out of scope, so with no rank");
        for _ in TOUCHED_KINDS {
            press(&mut app, &[KeyCode::Char('t')]);
            assert_eq!(app.rows.first(), Some(&chosen), "{:?}", app.touched);
        }
        press(&mut app, &[KeyCode::Char('t')]);

        // The filter matches a label as it matches a name.
        app.table.select(Some(0));
        mark(&mut app, "zzqx");
        press(&mut app, &[KeyCode::Char('/')]);
        type_text(&mut app, "zzqx");
        assert_eq!(app.rows, [chosen]);
        press(&mut app, &[KeyCode::Char('#')]);
        assert!(app.rows.is_empty(), "the filter still applies to a marked row");
    }

    #[test]
    fn a_saved_project_opens_as_it_was_left() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        press(&mut app, &[KeyCode::Char('s'), KeyCode::Char('S'), KeyCode::End]);
        mark(&mut app, "the fix");
        press(&mut app, &[KeyCode::Down, KeyCode::Enter, KeyCode::Char('v'), KeyCode::Char('l')]);
        press(&mut app, &[KeyCode::Char(']')]);
        let left = app.saved();
        assert!(left.browser.opened.is_some(), "a diff is open");

        let path = scratch("save").join("firmware.hereticus.json");
        press(&mut app, &[KeyCode::Char('w')]);
        let offered = app.prompt.as_ref().map(|prompt| prompt.text.clone());
        assert_eq!(offered.as_deref(), Some("firmware.o-firmware_v2.o.hereticus.json"));
        let prompt = app.prompt.as_mut().expect("the prompt shows");
        prompt.text = path.display().to_string();
        press(&mut app, &[KeyCode::Enter]);
        assert_eq!(app.notice, Some(format!("saved to {}", path.display())));
        assert!(screen(&mut app, 160, 12).contains("saved to"));
        assert_eq!(app.changes, Changes::Saved);
        press(&mut app, &[KeyCode::Char('w')]);
        let offered = app.prompt.as_ref().map(|prompt| prompt.text.clone());
        assert_eq!(offered, Some(path.display().to_string()), "the next save offers the last path");
        press(&mut app, &[KeyCode::Esc]);
        assert_eq!(app.notice, None, "a key clears the notice");

        let project = Project::read(&path).expect("the project reads back");
        assert_eq!(project.source, source());
        let json = |diff: &Diff| serde_json::to_string(diff).expect("a diff serializes");
        assert_eq!(json(&project.diff), json(&diff), "the result reads back as it was");
        let saved = Saved { browser: project.browser, marks: project.marks };
        assert_eq!(saved.browser, left.browser);
        assert_eq!(saved.marks, left.marks);

        let start = Start { saved, project: Some(path.clone()), ..start() };
        let mut opened = App::new(&project.diff, &before, &after, start);
        let again = opened.saved();
        assert_eq!(again.browser, left.browser);
        assert_eq!(again.marks, left.marks);
        assert_eq!(opened.rows, app.rows);
        assert_eq!(screen(&mut opened, 120, 24), screen(&mut app, 120, 24));
        std::fs::remove_dir_all(path.parent().expect("a directory")).expect("clean up");
    }

    #[test]
    fn a_save_that_fails_says_why_and_keeps_the_marks_unsaved() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        mark(&mut app, "x");
        press(&mut app, &[KeyCode::Char('w')]);
        let missing = scratch("fail").join("no such directory/project.json");
        app.prompt.as_mut().expect("the prompt shows").text = missing.display().to_string();
        press(&mut app, &[KeyCode::Enter]);
        let notice = app.notice.clone().expect("a notice");
        assert!(notice.starts_with("cannot save the project to"), "{notice}");
        assert_eq!(app.changes, Changes::Unsaved);
        let partial = missing.with_extension("json.partial");
        assert!(!partial.exists(), "no partial file is left");

        press(&mut app, &[KeyCode::Char('w'), KeyCode::Char('q')]);
        app.prompt.as_mut().expect("the prompt shows").text = "  ".to_string();
        press(&mut app, &[KeyCode::Enter]);
        assert_eq!(app.notice.as_deref(), Some("no path given, so nothing was saved"));
        std::fs::remove_dir_all(missing.parent().and_then(Path::parent).expect("a directory"))
            .expect("clean up");
    }

    #[test]
    fn quitting_with_unsaved_marks_warns() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        press(&mut app, &[KeyCode::Char('q')]);
        assert!(!screen(&mut app, 120, 12).contains("not saved"));
        press(&mut app, &[KeyCode::Esc]);
        mark(&mut app, "x");
        press(&mut app, &[KeyCode::Char('q')]);
        insta::assert_snapshot!("tui_quit_unsaved", screen(&mut app, 120, 12));
        assert_eq!(press(&mut app, &[KeyCode::Enter]), Flow::Quit);
    }

    #[test]
    fn the_prompt_holds_the_keys_and_the_mouse() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        press(&mut app, &[KeyCode::Char('M')]);
        insta::assert_snapshot!("tui_label", screen(&mut app, 120, 12));
        let selected = app.table.selected();
        // `q`, `?` and `j` are letters of the label here.
        type_text(&mut app, "q?j");
        app.handle_mouse(mouse(MouseEventKind::ScrollDown, 10, 10));
        assert_eq!(app.overlay, Overlay::None);
        assert_eq!(app.table.selected(), selected);
        press(&mut app, &[KeyCode::Backspace, KeyCode::Enter]);
        assert_eq!(app.marks.values().collect::<Vec<_>>(), ["q?"]);
    }

    fn mouse(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
        MouseEvent { kind, column, row, modifiers: KeyModifiers::NONE }
    }

    #[test]
    fn the_mouse_scrolls_selects_and_opens() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        let click = |column, row| mouse(MouseEventKind::Down(MouseButton::Left), column, row);
        screen(&mut app, 120, 20);

        // The wheel moves the selection, and stops at the last row.
        app.handle_mouse(mouse(MouseEventKind::ScrollDown, 10, 10));
        assert_eq!(app.table.selected(), Some(app.rows.len().min(4) - 1));
        app.handle_mouse(mouse(MouseEventKind::ScrollUp, 10, 10));
        assert_eq!(app.table.selected(), Some(0));

        // A click on a row selects it, and a second click opens it.
        let second = app.regions.list.y + 1;
        app.handle_mouse(click(10, second));
        assert_eq!(app.table.selected(), Some(1));
        assert!(matches!(app.screen, Screen::Table));
        app.handle_mouse(click(10, second));
        assert!(matches!(app.screen, Screen::Pair(_)));

        // The wheel scrolls the diff.
        screen(&mut app, 120, 20);
        app.handle_mouse(mouse(MouseEventKind::ScrollDown, 10, 10));
        let Screen::Pair(opened) = &app.screen else { panic!("the diff stays open") };
        assert_eq!(opened.scroll, WHEEL_STEP as usize);

        // A click on a tab changes the screen.
        let [functions, diff_tab] = app.regions.tabs;
        app.handle_mouse(click(functions.x, functions.y));
        assert!(matches!(app.screen, Screen::Table));
        screen(&mut app, 120, 20);
        app.handle_mouse(click(diff_tab.x + 1, diff_tab.y));
        assert!(matches!(app.screen, Screen::Pair(_)));

        // A click past the last row, or under the help, does nothing.
        press(&mut app, &[KeyCode::Esc]);
        screen(&mut app, 120, 20);
        let selected = app.table.selected();
        app.handle_mouse(click(10, app.regions.list.y + 10));
        assert_eq!(app.table.selected(), selected);
        press(&mut app, &[KeyCode::Char('?')]);
        app.handle_mouse(click(10, app.regions.list.y));
        assert_eq!(app.table.selected(), selected);
    }
}
