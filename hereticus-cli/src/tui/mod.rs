//! Browse a comparison in the terminal.
//!
//! The comparison runs once. The view then sorts, filters and opens the
//! pairs as the reader asks, with no second run. [`App`] holds the state and
//! reads the keys, apart from the drawing, so a test can drive it with no
//! terminal.

mod draw;
mod fuzzy;
mod rows;
mod theme;

use hereticus::address::Contents;
use hereticus::matching::{
    Diff, DiffLine, EditKind, PairedLabels, View, instruction_diff_in, line_addresses,
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

use rows::{Addresses, change_starts, side_by_side, unified};

use crate::{
    DataRegions, Hidden, Retouched, Sort, is_interesting, is_shown_unmatched, name_of, rank,
};

/// How the browser starts, from the flags of the command line.
#[derive(Clone, Debug)]
pub struct Start {
    /// The names of the two files, as the title shows them.
    pub files: [String; 2],
    pub sort: Sort,
    pub view: View,
    pub scope: Scope,
    pub hidden: Hidden,
    /// The lowest score at which a function gone or new names its closest
    /// candidate, as `--near-miss` sets.
    pub near_miss_floor: f64,
}

/// Which pairs the table lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// The pairs that changed, less the quiet changes [`Hidden`] holds back.
    Changed,
    /// Every pair, as `--all` lists.
    All,
}

/// How the diff of a pair is laid out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layout {
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
    /// The diff of one pair.
    Pair(Opened),
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
    /// The lines of the other view and their addresses, once shown, so `v`
    /// back is at once.
    other_view: Option<(Vec<DiffLine>, Addresses)>,
    addresses: Addresses,
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
            Layout::SideBySide => side_by_side(&self.lines, &self.addresses)
                .iter()
                .map(|row| row.left.is_change() || row.right.is_change())
                .collect(),
            Layout::Unified => {
                unified(&self.lines, &self.addresses).iter().map(|half| half.is_change()).collect()
            }
        };
        self.starts = change_starts(self.changes.iter().copied());
        self.scroll = self.scroll.min(self.changes.len().saturating_sub(1));
    }
}

/// Which way the sort runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Order {
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
    sort: Sort,
    order: Order,
    /// Lists only the pairs whose edit touched this kind of code.
    touched: Option<EditKind>,
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
    table: TableState,
    screen: Screen,
    overlay: Overlay,
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
        let mut app = Self {
            diff,
            paired: PairedLabels::new(diff, before, after),
            before,
            after,
            files: start.files,
            sort: start.sort,
            order: Order::Descending,
            touched: None,
            scope: start.scope,
            hidden: start.hidden,
            near_miss_floor: start.near_miss_floor,
            view: start.view,
            layout: Layout::SideBySide,
            filter: String::new(),
            entries,
            rows: Vec::new(),
            table: TableState::default(),
            screen: Screen::Table,
            overlay: Overlay::None,
            page: 10,
            regions: Regions::default(),
        };
        app.refresh();
        app
    }

    /// Report whether the table lists `entry` with the present scope and
    /// the kind of code asked for.
    fn is_listed(&self, entry: Entry) -> bool {
        let shown = |contents| is_shown_unmatched(contents, self.hidden);
        let in_scope = self.scope == Scope::All
            || match entry {
                Entry::Pair(index) => is_interesting(&self.diff.matched[index], self.hidden),
                Entry::Gone { contents, .. } | Entry::New { contents, .. } => shown(contents),
            };
        // A function gone or new has no edit to touch anything.
        let touches = match (self.touched, entry) {
            (None, _) => true,
            (Some(wanted), Entry::Pair(index)) => {
                self.diff.matched[index].kinds.present().any(|(kind, _)| kind == wanted)
            }
            (Some(_), Entry::Gone { .. } | Entry::New { .. }) => false,
        };
        in_scope && touches
    }

    /// List the rows again, after the order or a filter changed. The
    /// selected row stays selected where it is still listed.
    fn refresh(&mut self) {
        let kept = self.selected_entry();
        let mut rows: Vec<usize> = (0..self.entries.len())
            .filter(|&index| self.is_listed(self.entries[index].entry))
            .filter(|&index| fuzzy::positions(&self.filter, &self.entries[index].label).is_some())
            .collect();
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
        self.rows = rows;
        let position = kept.and_then(|kept| self.rows.iter().position(|&row| row == kept));
        self.table.select(match (position, self.rows.is_empty()) {
            (_, true) => None,
            (Some(position), false) => Some(position),
            (None, false) => Some(0),
        });
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
        let addresses = Addresses {
            before: line_addresses(view, shown[0].0, shown[0].1),
            after: line_addresses(view, shown[1].0, shown[1].1),
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
            addresses,
            against,
            scroll,
            changes: Vec::new(),
            starts: Vec::new(),
        };
        opened.relayout(self.layout);
        self.screen = Screen::Pair(opened);
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
        if let Some((lines, addresses)) = opened.other_view.take() {
            let lines = core::mem::replace(&mut opened.lines, lines);
            let addresses = core::mem::replace(&mut opened.addresses, addresses);
            opened.other_view = Some((lines, addresses));
            opened.relayout(self.layout);
            return;
        }
        let shown = (core::mem::take(&mut opened.lines), core::mem::take(&mut opened.addresses));
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
        if self.overlay != Overlay::None {
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
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/build/O2").join(name);
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

    /// `basic` at two levels, compared from the code alone, where two
    /// functions go and two come.
    fn basic_across_levels() -> Option<(Binary, Binary)> {
        let read = |level: &str| {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../fixtures/build")
                .join(level)
                .join("basic.o");
            Some(Binary::parse(&std::fs::read(path).ok()?).expect("a fixture parses"))
        };
        Some((read("O1")?, read("O2")?))
    }

    fn start() -> Start {
        Start {
            files: ["firmware.o".to_string(), "firmware_v2.o".to_string()],
            sort: Sort::Added,
            view: View::Assembly,
            scope: Scope::Changed,
            hidden: Hidden { retouched: Retouched::Hide, data: DataRegions::Hide },
            near_miss_floor: 0.25,
        }
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
        for sort in [Sort::Removed, Sort::Modified, Sort::Confidence, Sort::Added] {
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
        assert_eq!((diff.removed.len(), diff.added.len()), (2, 2), "the fixture is as expected");
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
        app.table.select(row(&app, "array_max", true));
        press(&mut app, &[KeyCode::Enter]);
        let Screen::Pair(opened) = &app.screen else { panic!("the row opens") };
        assert_eq!(opened.against.as_deref(), Some("array_max at 0.40"));

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
        let start = Start { view: View::Il, scope: Scope::All, ..start() };
        let mut app = App::new(&diff, &before, &after, start);
        let per_side = |app: &App<'_>| match &app.screen {
            Screen::Pair(opened) => {
                let addresses = (opened.addresses.before.len(), opened.addresses.after.len());
                assert_eq!(lines_per_side(&opened.lines), addresses, "{:?}", app.view);
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
        let rows = side_by_side(&opened.lines, &opened.addresses);
        let first = |side: fn(&rows::SideRow<'_>) -> Option<u64>| rows.iter().find_map(side);
        assert_eq!(first(|row| row.left.address), Some(before.functions[pair.before].address));
        assert_eq!(first(|row| row.right.address), Some(after.functions[pair.after].address));
        let count =
            |side: fn(&rows::SideRow<'_>) -> Option<u64>| rows.iter().filter_map(side).count();
        assert_eq!(count(|row| row.left.address), opened.addresses.before.len());
        assert_eq!(count(|row| row.right.address), opened.addresses.after.len());
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
        const KEYS: [KeyCode; 23] = [
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
