//! Browse a comparison in the terminal.
//!
//! The comparison runs once. The view then sorts, filters and opens the
//! pairs as the reader asks, with no second run. [`App`] holds the state and
//! reads the keys, apart from the drawing, so a test can drive it with no
//! terminal.

use hereticus::matching::{Changed, Diff, DiffLine, Edits, View, instruction_diff_in};
use hereticus::obj::Binary;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout as Split, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table, TableState};
use ratatui::{DefaultTerminal, Frame};

use crate::{
    DataRegions, Hidden, Retouched, Sort, describe, describe_confidence, describe_kinds,
    is_interesting, name_of, rank, summary_lines,
};

/// How the browser starts, from the flags of the command line.
#[derive(Clone, Copy, Debug)]
pub struct Start {
    pub sort: Sort,
    pub view: View,
    pub scope: Scope,
    pub hidden: Hidden,
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

/// The diff of the selected pair, kept so a redraw does not compute it again.
#[derive(Debug)]
struct Opened {
    lines: Vec<DiffLine>,
    /// The first line shown.
    scroll: usize,
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
    before: &'a Binary,
    after: &'a Binary,
    sort: Sort,
    scope: Scope,
    hidden: Hidden,
    view: View,
    layout: Layout,
    /// Matches a name that holds this text, in any case.
    filter: String,
    /// The label of each pair of `diff.matched`, as the table shows it.
    labels: Vec<String>,
    /// The pairs the table lists, in order, by their index in
    /// `diff.matched`.
    rows: Vec<usize>,
    table: TableState,
    screen: Screen,
    /// The height of the last drawn list, which a page moves by.
    page: usize,
}

impl<'a> App<'a> {
    pub fn new(diff: &'a Diff, before: &'a Binary, after: &'a Binary, start: Start) -> Self {
        let labels = diff
            .matched
            .iter()
            .map(|pair| {
                let name = name_of(before, pair.before);
                let renamed = name_of(after, pair.after);
                if name == renamed { name } else { format!("{name} -> {renamed}") }
            })
            .collect();
        let mut app = Self {
            diff,
            before,
            after,
            sort: start.sort,
            scope: start.scope,
            hidden: start.hidden,
            view: start.view,
            layout: Layout::SideBySide,
            filter: String::new(),
            labels,
            rows: Vec::new(),
            table: TableState::default(),
            screen: Screen::Table,
            page: 10,
        };
        app.refresh();
        app
    }

    /// List the pairs again, after the order or a filter changed. The
    /// selected pair stays selected where it is still listed.
    fn refresh(&mut self) {
        let kept = self.selected_pair();
        let needle = self.filter.to_lowercase();
        let matched = &self.diff.matched;
        self.rows = (0..matched.len())
            .filter(|&index| {
                self.scope == Scope::All || is_interesting(&matched[index], self.hidden)
            })
            .filter(|&index| {
                needle.is_empty() || self.labels[index].to_lowercase().contains(&needle)
            })
            .collect();
        // The library lists the pairs strongest first, which is the order
        // `confidence` names.
        if self.sort != Sort::Confidence {
            self.rows.sort_by(|&a, &b| rank(&matched[a], &matched[b], self.sort));
        }
        let position = kept.and_then(|pair| self.rows.iter().position(|&row| row == pair));
        self.table.select(match (position, self.rows.is_empty()) {
            (_, true) => None,
            (Some(position), false) => Some(position),
            (None, false) => Some(0),
        });
    }

    /// The index in `diff.matched` of the selected pair.
    fn selected_pair(&self) -> Option<usize> {
        self.rows.get(self.table.selected()?).copied()
    }

    /// Move the selection by `step` rows, and stop at either end.
    fn move_selection(&mut self, step: isize) {
        let Some(last) = self.rows.len().checked_sub(1) else { return };
        let at = self.table.selected().unwrap_or(0);
        self.table.select(Some(at.saturating_add_signed(step).min(last)));
    }

    /// Show the diff of the selected pair.
    fn open(&mut self) {
        let Some(pair) = self.selected_pair().map(|index| &self.diff.matched[index]) else {
            return;
        };
        let lines =
            instruction_diff_in(self.view, self.before, pair.before, self.after, pair.after);
        self.screen = Screen::Pair(Opened { lines, scroll: 0 });
    }

    fn handle(&mut self, key: KeyEvent) -> Flow {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Flow::Quit;
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

    fn handle_table(&mut self, code: KeyCode) -> Flow {
        let page = self.page as isize;
        match code {
            KeyCode::Char('q') | KeyCode::Esc => return Flow::Quit,
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
        let scroll = |app: &mut Self, step: isize| {
            let rows = app.diff_rows();
            if let Screen::Pair(opened) = &mut app.screen {
                let last = rows.saturating_sub(1);
                opened.scroll = opened.scroll.saturating_add_signed(step).min(last);
            }
        };
        match code {
            KeyCode::Char('q') => return Flow::Quit,
            KeyCode::Esc | KeyCode::Backspace => self.screen = Screen::Table,
            KeyCode::Down | KeyCode::Char('j') => scroll(self, 1),
            KeyCode::Up | KeyCode::Char('k') => scroll(self, -1),
            KeyCode::PageDown | KeyCode::Char(' ') => scroll(self, page),
            KeyCode::PageUp => scroll(self, -page),
            KeyCode::Home | KeyCode::Char('g') => scroll(self, isize::MIN),
            KeyCode::End | KeyCode::Char('G') => scroll(self, isize::MAX),
            KeyCode::Char('v') => {
                self.view = match self.view {
                    View::Assembly => View::Il,
                    View::Il => View::Assembly,
                };
                self.open();
            }
            KeyCode::Char('l') => {
                self.layout = match self.layout {
                    Layout::SideBySide => Layout::Unified,
                    Layout::Unified => Layout::SideBySide,
                };
                scroll(self, 0);
            }
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

    /// How many rows the open diff takes in the present layout.
    fn diff_rows(&self) -> usize {
        let Screen::Pair(opened) = &self.screen else { return 0 };
        match self.layout {
            Layout::SideBySide => side_by_side(&opened.lines).len(),
            Layout::Unified => unified(&opened.lines).len(),
        }
    }

    fn draw(&mut self, frame: &mut Frame<'_>) {
        let [body, status, keys] =
            Split::vertical([Constraint::Min(1), Constraint::Length(1), Constraint::Length(1)])
                .areas(frame.area());
        // The block border takes two lines.
        self.page = usize::from(body.height.saturating_sub(3)).max(1);
        let hints = match self.screen {
            Screen::Table => {
                self.draw_table(frame, body);
                "↑↓ move  ⏎ open  s sort  a all  r retouched  d data  / filter  q quit"
            }
            Screen::Filter => {
                self.draw_table(frame, body);
                "type to filter  ⏎ keep  esc clear"
            }
            Screen::Pair(_) => {
                self.draw_pair(frame, body);
                "↑↓ scroll  v asm/il  l layout  n next  p previous  esc back  q quit"
            }
        };
        frame.render_widget(Line::from(self.status()), status);
        frame
            .render_widget(Line::from(hints).style(Style::new().add_modifier(Modifier::DIM)), keys);
    }

    /// The order, the filters and the count of the table, in one line.
    fn status(&self) -> String {
        let mut parts = vec![
            format!("sort: {}", self.sort.name()),
            format!("{} of {} pairs", self.rows.len(), self.diff.matched.len()),
        ];
        if let Screen::Pair(_) = self.screen {
            let view = match self.view {
                View::Assembly => "asm",
                View::Il => "il",
            };
            parts.insert(0, format!("view: {view}"));
        }
        let mut hidden = Vec::new();
        if self.scope == Scope::Changed {
            if self.hidden.retouched == Retouched::Hide {
                hidden.push("retouched");
            }
            if self.hidden.data == DataRegions::Hide {
                hidden.push("data");
            }
        }
        if !hidden.is_empty() {
            parts.push(format!("hidden: {}", hidden.join(", ")));
        }
        if self.scope == Scope::All {
            parts.push("all".to_string());
        }
        match self.screen {
            Screen::Filter => parts.push(format!("filter: {}▏", self.filter)),
            _ if !self.filter.is_empty() => parts.push(format!("filter: {}", self.filter)),
            _ => {}
        }
        // The totals of the report, as its last lines say them.
        if let Some(totals) = summary_lines(self.diff, self.hidden).into_iter().next() {
            parts.push(totals);
        }
        parts.join(" │ ")
    }

    fn draw_table(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let header = ["FUNCTION", "CHANGE", "SCORE", "+/-/~", "TOUCHED", "MATCHED BY"]
            .map(|title| Cell::from(title).style(Style::new().add_modifier(Modifier::BOLD)));
        let rows = self.rows.iter().map(|&index| {
            let pair = &self.diff.matched[index];
            Row::new([
                Cell::from(self.labels[index].as_str()),
                Cell::from(describe(pair.changed)).style(Style::new().fg(tone_of(pair.changed))),
                Cell::from(Line::from(format!("{:.2}", pair.score)).right_aligned()),
                Cell::from(edits_line(pair.edits)),
                Cell::from(describe_kinds(pair.kinds, pair.changed)),
                Cell::from(describe_confidence(pair.confidence)),
            ])
        });
        let widths = [
            Constraint::Fill(1),
            Constraint::Length(14),
            Constraint::Length(5),
            Constraint::Length(11),
            Constraint::Length(30),
            Constraint::Length(15),
        ];
        let table = Table::new(rows, widths)
            .header(Row::new(header))
            .block(Block::bordered().title(" hereticus "))
            .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED));
        frame.render_stateful_widget(table, area, &mut self.table);
    }

    fn draw_pair(&self, frame: &mut Frame<'_>, area: Rect) {
        let Screen::Pair(opened) = &self.screen else { return };
        let Some(pair) = self.selected_pair().map(|index| &self.diff.matched[index]) else {
            return;
        };
        let scroll = u16::try_from(opened.scroll).unwrap_or(u16::MAX);
        match self.layout {
            Layout::SideBySide => {
                let rows = side_by_side(&opened.lines);
                let (left, right): (Vec<Line<'_>>, Vec<Line<'_>>) =
                    rows.iter().map(|row| (row.left.line(), row.right.line())).unzip();
                let [left_area, right_area] =
                    Split::horizontal([Constraint::Fill(1), Constraint::Fill(1)]).areas(area);
                let title = |binary: &Binary, index| format!(" {} ", name_of(binary, index));
                let left_block = Block::bordered().title(title(self.before, pair.before));
                let right_block = Block::bordered().title(title(self.after, pair.after));
                frame.render_widget(
                    Paragraph::new(left).block(left_block).scroll((scroll, 0)),
                    left_area,
                );
                frame.render_widget(
                    Paragraph::new(right).block(right_block).scroll((scroll, 0)),
                    right_area,
                );
            }
            Layout::Unified => {
                let title = format!(" {} ", self.labels[self.selected_pair().unwrap_or(0)]);
                let lines: Vec<Line<'_>> =
                    unified(&opened.lines).into_iter().map(Side::line).collect();
                frame.render_widget(
                    Paragraph::new(lines).block(Block::bordered().title(title)).scroll((scroll, 0)),
                    area,
                );
            }
        }
    }
}

/// Run the browser until the reader quits.
pub fn run(diff: &Diff, before: &Binary, after: &Binary, start: Start) -> Result<(), String> {
    let mut app = App::new(diff, before, after, start);
    let mut terminal = ratatui::init();
    let result = event_loop(&mut app, &mut terminal);
    ratatui::restore();
    result.map_err(|error| format!("cannot draw on the terminal: {error}"))
}

fn event_loop(app: &mut App<'_>, terminal: &mut DefaultTerminal) -> std::io::Result<()> {
    loop {
        terminal.draw(|frame| app.draw(frame))?;
        // A terminal on Windows sends a release of each key too.
        if let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && app.handle(key) == Flow::Quit
        {
            return Ok(());
        }
    }
}

/// The color of the `CHANGE` cell, as the text report paints it.
fn tone_of(change: Changed) -> Color {
    match change {
        Changed::Yes => Color::Red,
        Changed::Unreadable => Color::Magenta,
        Changed::InDetail => Color::Yellow,
        Changed::Reordered => Color::Cyan,
        Changed::Data => Color::Blue,
        Changed::No => Color::Green,
    }
}

/// The `+/-/~` cell, each count in the color of its kind.
fn edits_line(edits: Edits) -> Line<'static> {
    if edits.total() == 0 {
        return Line::from("-");
    }
    Line::from(vec![
        Span::styled(edits.added.to_string(), Style::new().fg(Color::Green)),
        Span::raw("/"),
        Span::styled(edits.removed.to_string(), Style::new().fg(Color::Red)),
        Span::raw("/"),
        Span::styled(edits.edited.to_string(), Style::new().fg(Color::Yellow)),
    ])
}

/// One side of a row of a diff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side<'l> {
    /// Nothing, across from a line the other side alone has.
    Empty,
    Same(&'l str),
    Removed(&'l str),
    Added(&'l str),
}

impl Side<'_> {
    /// The line with the sign and the color of a patch.
    fn line(self) -> Line<'static> {
        match self {
            Self::Empty => Line::default(),
            Self::Same(text) => Line::from(format!("  {text}")),
            Self::Removed(text) => Line::styled(format!("- {text}"), Style::new().fg(Color::Red)),
            Self::Added(text) => Line::styled(format!("+ {text}"), Style::new().fg(Color::Green)),
        }
    }
}

/// One row of a diff laid side by side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SideRow<'l> {
    left: Side<'l>,
    right: Side<'l>,
}

/// Lay a diff side by side. A run of removed lines and the run of added
/// lines next to it share rows, so a rewritten block reads across.
fn side_by_side(lines: &[DiffLine]) -> Vec<SideRow<'_>> {
    let mut rows = Vec::with_capacity(lines.len());
    let mut removed: Vec<&str> = Vec::new();
    let mut added: Vec<&str> = Vec::new();
    for line in lines {
        match line {
            DiffLine::Removed(text) => removed.push(text),
            DiffLine::Added(text) => added.push(text),
            DiffLine::Same(text) => {
                flush_runs(&mut rows, &mut removed, &mut added);
                rows.push(SideRow { left: Side::Same(text), right: Side::Same(text) });
            }
            DiffLine::Changed { before, after } => {
                flush_runs(&mut rows, &mut removed, &mut added);
                rows.push(SideRow { left: Side::Removed(before), right: Side::Added(after) });
            }
        }
    }
    flush_runs(&mut rows, &mut removed, &mut added);
    rows
}

/// Put a run of removed lines and a run of added lines on shared rows.
fn flush_runs<'l>(
    rows: &mut Vec<SideRow<'l>>,
    removed: &mut Vec<&'l str>,
    added: &mut Vec<&'l str>,
) {
    let longest = removed.len().max(added.len());
    let left = removed.drain(..).map(Side::Removed).chain(core::iter::repeat(Side::Empty));
    let right = added.drain(..).map(Side::Added).chain(core::iter::repeat(Side::Empty));
    rows.extend(left.zip(right).take(longest).map(|(left, right)| SideRow { left, right }));
}

/// Lay a diff in one column, as a patch reads.
fn unified(lines: &[DiffLine]) -> Vec<Side<'_>> {
    lines
        .iter()
        .flat_map(|line| match line {
            DiffLine::Same(text) => [Side::Same(text), Side::Empty],
            DiffLine::Removed(text) => [Side::Removed(text), Side::Empty],
            DiffLine::Added(text) => [Side::Added(text), Side::Empty],
            DiffLine::Changed { before, after } => [Side::Removed(before), Side::Added(after)],
        })
        .filter(|side| *side != Side::Empty)
        .collect()
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

    fn start() -> Start {
        Start {
            sort: Sort::Added,
            view: View::Assembly,
            scope: Scope::Changed,
            hidden: Hidden { retouched: Retouched::Hide, data: DataRegions::Hide },
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
        buffer.content().chunks(usize::from(width).max(1)).fold(String::new(), |mut text, row| {
            row.iter().for_each(|cell| text.push_str(cell.symbol()));
            text.push('\n');
            text
        })
    }

    #[test]
    fn each_sort_ranks_the_rows_by_its_count() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        let count = app.rows.len();
        assert!(count > 1, "the fixture changes more than one function");
        for sort in [Sort::Removed, Sort::Modified, Sort::Confidence, Sort::Added] {
            press(&mut app, &[KeyCode::Char('s')]);
            assert_eq!(app.sort, sort);
            assert_eq!(app.rows.len(), count, "a sort keeps every row");
            if sort != Sort::Confidence {
                assert!(is_ranked(&diff, &app.rows, sort), "{sort:?}");
            }
        }
    }

    #[test]
    fn the_selection_follows_its_pair_across_a_sort() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        press(&mut app, &[KeyCode::End]);
        let chosen = app.selected_pair();
        press(&mut app, &[KeyCode::Char('s'), KeyCode::Char('s')]);
        assert_eq!(app.selected_pair(), chosen);
    }

    #[test]
    fn all_lists_every_pair_and_toggles_back() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        let changed = app.rows.len();
        press(&mut app, &[KeyCode::Char('a')]);
        assert_eq!(app.rows.len(), diff.matched.len());
        press(&mut app, &[KeyCode::Char('a')]);
        assert_eq!(app.rows.len(), changed);
    }

    #[test]
    fn a_filter_narrows_the_rows_and_escape_clears_it() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        let count = app.rows.len();
        let wanted = app.labels[app.rows[0]].clone();
        let mut keys = vec![KeyCode::Char('/')];
        keys.extend(wanted.to_uppercase().chars().map(KeyCode::Char));
        press(&mut app, &keys);
        assert!(app.rows.iter().all(|&row| app.labels[row].contains(&wanted)));
        assert!(app.rows.contains(&app.selected_pair().expect("a row")));

        press(&mut app, &[KeyCode::Char('#')]);
        assert!(app.rows.is_empty(), "no name holds `#`");
        assert_eq!(app.selected_pair(), None);
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
        assert!(screen(&mut app, 120, 30).contains("view: asm"));

        press(&mut app, &[KeyCode::Char('v')]);
        let Screen::Pair(opened) = &app.screen else { panic!("the pair stays open") };
        assert_eq!(app.view, View::Il);
        assert_ne!(opened.lines, assembly, "IL reads otherwise");
        assert!(screen(&mut app, 120, 30).contains("view: il"));

        press(&mut app, &[KeyCode::End]);
        let Screen::Pair(opened) = &app.screen else { panic!("the pair stays open") };
        assert_eq!(opened.scroll, app.diff_rows() - 1);

        assert_eq!(press(&mut app, &[KeyCode::Esc]), Flow::Continue);
        assert!(matches!(app.screen, Screen::Table));
        assert_eq!(press(&mut app, &[KeyCode::Char('q')]), Flow::Quit);
    }

    #[test]
    fn the_table_shows_its_heading_and_order() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        let shown = screen(&mut app, 120, 20);
        assert!(shown.contains("FUNCTION"), "{shown}");
        assert!(shown.contains("sort: added"), "{shown}");
        assert!(shown.contains(&app.labels[app.rows[0]]), "{shown}");
    }

    #[test]
    fn any_keys_keep_the_selection_inside_the_rows() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        const KEYS: [KeyCode; 20] = [
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
            KeyCode::Char('e'),
            KeyCode::Char('x'),
        ];
        bolero::check!().with_type::<(Vec<u8>, u8, u8)>().for_each(|(keys, width, height)| {
            let mut app = App::new(&diff, &before, &after, start());
            for &key in keys {
                // `Esc` on the table ends the run.
                if app.handle(KeyEvent::from(KEYS[usize::from(key) % KEYS.len()])) == Flow::Quit {
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
            screen(&mut app, u16::from(*width), u16::from(*height));
        });
    }

    fn same(text: &str) -> DiffLine {
        DiffLine::Same(text.into())
    }

    #[test]
    fn a_removed_run_and_an_added_run_share_rows() {
        let lines = [
            same("a"),
            DiffLine::Removed("b".into()),
            DiffLine::Removed("c".into()),
            DiffLine::Added("d".into()),
            same("e"),
            DiffLine::Changed { before: "f".into(), after: "g".into() },
            DiffLine::Added("h".into()),
        ];
        let row = |left, right| SideRow { left, right };
        assert_eq!(
            side_by_side(&lines),
            [
                row(Side::Same("a"), Side::Same("a")),
                row(Side::Removed("b"), Side::Added("d")),
                row(Side::Removed("c"), Side::Empty),
                row(Side::Same("e"), Side::Same("e")),
                row(Side::Removed("f"), Side::Added("g")),
                row(Side::Empty, Side::Added("h")),
            ]
        );
        assert!(side_by_side(&[]).is_empty());
    }

    #[test]
    fn a_unified_diff_puts_a_changed_line_on_two_rows() {
        let lines = [same("a"), DiffLine::Changed { before: "b".into(), after: "c".into() }];
        assert_eq!(unified(&lines), [Side::Same("a"), Side::Removed("b"), Side::Added("c")]);
    }
}
