//! Browse a comparison in the terminal.
//!
//! The comparison runs once. The view then sorts, filters and opens the
//! pairs as the reader asks, with no second run. [`App`] holds the state and
//! reads the keys, apart from the drawing, so a test can drive it with no
//! terminal.

mod draw;
mod theme;

use hereticus::matching::{Diff, DiffLine, View, instruction_diff_in};
use hereticus::obj::Binary;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::widgets::TableState;

use crate::{DataRegions, Hidden, Retouched, Sort, is_interesting, name_of, rank};

/// How the browser starts, from the flags of the command line.
#[derive(Clone, Debug)]
pub struct Start {
    /// The names of the two files, as the title shows them.
    pub files: [String; 2],
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

/// Whether the help shows over the screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Help {
    Shown,
    Hidden,
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
    files: [String; 2],
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
    help: Help,
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
            files: start.files,
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
            help: Help::Hidden,
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
        if self.help == Help::Shown {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('q' | '?')) {
                self.help = Help::Hidden;
            }
            return Flow::Continue;
        }
        if key.code == KeyCode::Char('?') && !matches!(self.screen, Screen::Filter) {
            self.help = Help::Shown;
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

/// One side of a row of a diff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side<'l> {
    /// Nothing, across from a line the other side alone has.
    Empty,
    Same(&'l str),
    Removed(&'l str),
    Added(&'l str),
    /// A line kept in place with a changed constant, as `~` names it in the
    /// `+/-/~` column.
    Changed(&'l str),
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
                rows.push(SideRow { left: Side::Changed(before), right: Side::Changed(after) });
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
            files: ["firmware.o".to_string(), "firmware_v2.o".to_string()],
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
        assert_eq!(press(&mut app, &[KeyCode::Char('q')]), Flow::Quit);
    }

    #[test]
    fn help_opens_over_any_screen_and_holds_the_keys() {
        let Some((before, after)) = firmware() else { return };
        let diff = diff_with(&before, &after, Options::default());
        let mut app = App::new(&diff, &before, &after, start());
        press(&mut app, &[KeyCode::Char('?')]);
        assert_eq!(app.help, Help::Shown);
        let sort = app.sort;
        assert_eq!(press(&mut app, &[KeyCode::Char('s'), KeyCode::Char('q')]), Flow::Continue);
        assert_eq!(app.sort, sort, "the help holds the keys");
        assert_eq!(app.help, Help::Hidden, "`q` closes the help, not the browser");

        // In the filter, `?` is a letter of a name.
        press(&mut app, &[KeyCode::Char('/'), KeyCode::Char('?')]);
        assert_eq!(app.help, Help::Hidden);
        assert_eq!(app.filter, "?");

        press(&mut app, &[KeyCode::Esc, KeyCode::Enter, KeyCode::Char('?')]);
        assert!(matches!(app.screen, Screen::Pair(_)));
        assert_eq!(app.help, Help::Shown);
        press(&mut app, &[KeyCode::Esc]);
        assert_eq!(app.help, Help::Hidden);
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
            KeyCode::Char('?'),
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
                row(Side::Changed("f"), Side::Changed("g")),
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
