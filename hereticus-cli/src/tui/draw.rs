//! Draw the browser: a title with tabs, the pane of the screen, and a
//! status bar, as `heretek` lays them out.

use hereticus::matching::{Changed, Edits};
use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout as Split, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
    Table, TableState, Tabs,
};

use super::rows::{Half, Side, side_by_side, unified};
use super::theme::{
    ADDED, BLUE, DARK_GRAY, EDITED, Focus, GRAY, GRAY_FG, GREEN, ORANGE, PURPLE, REMOVED, YELLOW,
    pane_block, tone_of,
};
use super::{App, Entry, Labeled, Layout, Order, Overlay, Scope, Screen, fuzzy};
use crate::{
    DataRegions, Retouched, describe, describe_confidence, describe_kinds, name_of, name_of_kind,
    name_of_view, unmatched_word,
};

/// The keys of each pane, at the right of its frame.
const TABLE_HINTS: &str = "⏎ open  s/S sort  t touched  / filter";
const FILTER_HINTS: &str = "⏎ keep  esc clear";
const PAIR_HINTS: &str = "]/[ change  v asm/il  l layout  n/p next/prev  esc back";

impl App<'_> {
    pub(super) fn draw(&mut self, frame: &mut Frame<'_>) {
        let filter_height = if matches!(self.screen, Screen::Filter) { 3 } else { 0 };
        let [title, body, filter, status] = Split::vertical([
            Constraint::Length(2),
            Constraint::Fill(1),
            Constraint::Length(filter_height),
            Constraint::Length(1),
        ])
        .areas(frame.area());

        self.draw_title(frame, title);
        match self.screen {
            Screen::Table | Screen::Filter => self.draw_table(frame, body),
            Screen::Pair(_) => self.draw_pair(frame, body),
        }
        if matches!(self.screen, Screen::Filter) {
            self.draw_filter(frame, filter);
        }
        self.draw_status(frame, status);
        match self.overlay {
            Overlay::None => {}
            Overlay::Help => draw_help(frame),
            Overlay::Quit => draw_quit(frame),
        }
    }

    /// The name and version over the tabs of the two screens, with the two
    /// files at the right.
    fn draw_title(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let [name, tabs] =
            Split::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
        let heading = Line::from(vec![
            Span::raw(" "),
            env!("CARGO_BIN_NAME").bold(),
            Span::styled(concat!(" v", env!("CARGO_PKG_VERSION"), " "), Style::new().fg(GRAY_FG)),
        ])
        .centered();
        let rule = Block::new().borders(Borders::TOP).border_style(Style::new().fg(GRAY));
        frame.render_widget(rule.title_top(heading), name);

        let selected = match self.screen {
            Screen::Table | Screen::Filter => 0,
            Screen::Pair(_) => 1,
        };
        let tabs_widget = Tabs::new(["Functions", "Diff"])
            .highlight_style(Style::new().fg(GREEN).bold())
            .select(selected)
            .divider("|".fg(GRAY_FG));
        frame.render_widget(tabs_widget, tabs);
        // `Tabs` pads each title by one column, and a divider parts them.
        let mut x = tabs.x;
        for (region, title) in self.regions.tabs.iter_mut().zip(["Functions", "Diff"]) {
            let width = title.chars().count() as u16;
            *region = Rect { x: x.saturating_add(1), width, height: 1, ..tabs }.intersection(tabs);
            x = x.saturating_add(width + 3);
        }
        let [before, after] = &self.files;
        let files = Line::from(vec![
            Span::styled(before.as_str(), Style::new().fg(GRAY_FG)),
            Span::styled(" → ", Style::new().fg(GRAY)),
            Span::styled(after.as_str(), Style::new().fg(GRAY_FG)),
            Span::raw(" "),
        ])
        .right_aligned();
        frame.render_widget(files, tabs);
    }

    fn draw_table(&mut self, frame: &mut Frame<'_>, area: Rect) {
        // The frame and the heading take a line each.
        self.page = usize::from(area.height.saturating_sub(2)).max(1);
        let (focus, hints) = match self.screen {
            Screen::Filter => (Focus::Inactive, FILTER_HINTS),
            _ => (Focus::Active, TABLE_HINTS),
        };
        let context = (!self.filter.is_empty()).then(|| format!("filter: \"{}\"", self.filter));
        let block = pane_block("Functions", context, hints, focus);

        let header = Row::new(["FUNCTION", "CHANGE", "SCORE", "+/-/~", "TOUCHED", "MATCHED BY"])
            .style(Style::new().fg(BLUE).bold());
        // Only the rows in sight are built: a kernel lists many thousand.
        let shown = usize::from(area.height.saturating_sub(2));
        let offset =
            visible_offset(self.table.offset(), self.table.selected(), shown, self.rows.len());
        *self.table.offset_mut() = offset;
        let rows: Vec<Row<'static>> = self.rows[offset..]
            .iter()
            .take(shown)
            .map(|&index| self.table_row(&self.entries[index]))
            .collect();
        // The names and the kinds touched are the long cells.
        let widths = [
            Constraint::Fill(3),
            Constraint::Length(14),
            Constraint::Length(5),
            Constraint::Length(11),
            Constraint::Fill(2),
            Constraint::Length(15),
        ];
        let table = Table::new(rows, widths)
            .header(header)
            .block(block)
            .row_highlight_style(Style::new().fg(ORANGE).bold())
            .highlight_symbol("▶ ");
        let selected = self.table.selected().map(|selected| selected - offset);
        frame.render_stateful_widget(
            table,
            area,
            &mut TableState::default().with_selected(selected),
        );
        // The frame and the heading take the first two lines.
        self.regions.list =
            Rect { y: area.y.saturating_add(2), height: area.height.saturating_sub(2), ..area };
        let position = self.table.selected().unwrap_or(0);
        draw_scrollbar(frame, area, self.rows.len(), position);
    }

    /// One row of the table. A function gone or new names its closest
    /// candidate where it has one, in the column of what a pair touched.
    fn table_row(&self, labeled: &Labeled) -> Row<'static> {
        let name = Cell::from(highlighted(&labeled.label, &self.filter));
        let (word, color, closest_in) = match labeled.entry {
            Entry::Pair(index) => {
                let pair = &self.diff.matched[index];
                return Row::new([
                    name,
                    Cell::from(describe(pair.changed))
                        .style(Style::new().fg(tone_of(pair.changed))),
                    Cell::from(Line::from(format!("{:.2}", pair.score)).right_aligned()),
                    Cell::from(edits_line(pair.edits)),
                    Cell::from(describe_kinds(pair.kinds, pair.changed))
                        .style(Style::new().fg(GRAY_FG)),
                    Cell::from(describe_confidence(pair.confidence)).style(Style::new().fg(PURPLE)),
                ]);
            }
            Entry::Gone { contents, .. } => (unmatched_word("gone", contents), REMOVED, self.after),
            Entry::New { contents, .. } => (unmatched_word("new", contents), ADDED, self.before),
        };
        let (score, note) = match self.closest(labeled.entry) {
            Some((best, score)) => {
                (format!("{score:.2}"), format!("closest {}", name_of(closest_in, best)))
            }
            None => (String::new(), "-".to_string()),
        };
        Row::new([
            name,
            Cell::from(word).style(Style::new().fg(color)),
            Cell::from(Line::styled(score, Style::new().fg(GRAY_FG)).right_aligned()),
            Cell::from(Line::styled("-", Style::new().fg(GRAY_FG))),
            Cell::from(note).style(Style::new().fg(GRAY_FG)),
            Cell::from(Line::styled("-", Style::new().fg(GRAY_FG))),
        ])
    }

    /// The box the filter is typed in, with the cursor at its end.
    fn draw_filter(&self, frame: &mut Frame<'_>, area: Rect) {
        let block = Block::bordered()
            .border_style(Style::new().fg(ORANGE))
            .title(Span::styled("Filter", Style::new().fg(YELLOW).bold()));
        let width = usize::from(area.width.saturating_sub(2));
        let length = self.filter.chars().count();
        // Keep the end of a long filter, where the cursor is, in sight.
        let shift = length.saturating_sub(width.saturating_sub(1));
        let shown: String = self.filter.chars().skip(shift).collect();
        frame.render_widget(Paragraph::new(shown.as_str()).block(block), area);
        let column = u16::try_from(length - shift).unwrap_or(u16::MAX);
        if area.width > 2 && area.height > 2 {
            frame
                .set_cursor_position((area.x.saturating_add(1).saturating_add(column), area.y + 1));
        }
    }

    fn draw_pair(&mut self, frame: &mut Frame<'_>, area: Rect) {
        // The frame takes a line.
        self.page = usize::from(area.height.saturating_sub(1)).max(1);
        let Screen::Pair(opened) = &self.screen else { return };
        let Some(index) = self.selected_entry() else { return };
        let scroll = opened.scroll;
        let label = &self.entries[index].label;
        let view = name_of_view(self.view);
        let (at, changes) = self.change_position();
        let position = match changes {
            0 => "no change".to_string(),
            changes => format!("change {at} of {changes}"),
        };
        let context = Some(match &opened.against {
            Some(against) => format!("{label}  against {against}  {view}  {position}"),
            None => format!("{label}  {view}  {position}"),
        });
        let block = pane_block("Diff", context, PAIR_HINTS, Focus::Active);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        // The scrollbar takes the last column.
        let content = Rect { width: inner.width.saturating_sub(1), ..inner };
        let addresses = &opened.addresses;
        let width = address_width(addresses.before.iter().chain(&addresses.after).copied());
        // Only the rows in sight are drawn: a long function has many
        // thousand, more than a `u16` scroll reaches.
        let shown = usize::from(content.height);
        let total = opened.changes.len();
        match self.layout {
            Layout::SideBySide => {
                let rows = side_by_side(&opened.lines, addresses);
                let (left, right): (Vec<Line<'_>>, Vec<Line<'_>>) = rows
                    .iter()
                    .skip(scroll)
                    .take(shown)
                    .map(|row| (half_line(row.left, width), half_line(row.right, width)))
                    .unzip();
                let [left_area, divider, right_area] = Split::horizontal([
                    Constraint::Fill(1),
                    Constraint::Length(1),
                    Constraint::Fill(1),
                ])
                .areas(content);
                frame.render_widget(Paragraph::new(left), left_area);
                frame.render_widget(
                    Block::new().borders(Borders::LEFT).border_style(Style::new().fg(GRAY)),
                    divider,
                );
                frame.render_widget(Paragraph::new(right), right_area);
            }
            Layout::Unified => {
                let sides = unified(&opened.lines, addresses);
                let lines: Vec<Line<'_>> = sides
                    .iter()
                    .skip(scroll)
                    .take(shown)
                    .map(|half| half_line(*half, width))
                    .collect();
                frame.render_widget(Paragraph::new(lines), content);
            }
        }
        draw_scrollbar(frame, area, total, scroll);
    }

    /// The state of the browser at the left, and the totals and the key to
    /// the help at the right.
    fn draw_status(&self, frame: &mut Frame<'_>, area: Rect) {
        let separator = || Span::styled("  │  ", Style::new().fg(GRAY_FG));
        let label = |text: &'static str| Span::styled(text, Style::new().fg(GRAY_FG));
        let mut spans = vec![
            Span::raw(" "),
            label("sort "),
            Span::styled(self.sort.name(), Style::new().fg(ORANGE).bold()),
            Span::styled(
                match self.order {
                    Order::Descending => " ↓",
                    Order::Ascending => " ↑",
                },
                Style::new().fg(ORANGE),
            ),
            separator(),
            Span::styled(
                format!("{} of {} functions", self.rows.len(), self.entries.len()),
                Style::new().fg(GREEN),
            ),
        ];
        if let Some(kind) = self.touched {
            spans.extend([
                separator(),
                label("touched "),
                Span::styled(name_of_kind(kind), Style::new().fg(YELLOW).bold()),
            ]);
        }
        if let Screen::Pair(_) = self.screen {
            spans.extend([
                separator(),
                label("view "),
                Span::styled(name_of_view(self.view), Style::new().fg(PURPLE).bold()),
            ]);
        }
        match self.scope {
            Scope::All => spans.extend([separator(), Span::styled("all", Style::new().fg(BLUE))]),
            Scope::Changed => {
                let hidden: Vec<&str> = [
                    (self.hidden.retouched == Retouched::Hide).then_some("retouched"),
                    (self.hidden.data == DataRegions::Hide).then_some("data"),
                ]
                .into_iter()
                .flatten()
                .collect();
                if !hidden.is_empty() {
                    spans.extend([
                        separator(),
                        label("hidden "),
                        Span::styled(hidden.join(", "), Style::new().fg(PURPLE)),
                    ]);
                }
            }
        }
        let gone = self.diff.removed.len();
        let new = self.diff.added.len();
        let right = Line::from(vec![
            Span::styled(format!("{gone} gone"), Style::new().fg(REMOVED)),
            label("  "),
            Span::styled(format!("{new} new"), Style::new().fg(ADDED)),
            label("  "),
            Span::styled("? help", Style::new().fg(BLUE).bold()),
            Span::raw(" "),
        ])
        .right_aligned();
        frame.render_widget(
            Paragraph::new(Line::from(spans)).style(Style::new().bg(DARK_GRAY)),
            area,
        );
        frame.render_widget(Paragraph::new(right), area);
    }
}

/// The first row a list of `rows` shows in `shown` lines: the one it showed
/// before, moved as little as keeps the selected row in sight.
fn visible_offset(before: usize, selected: Option<usize>, shown: usize, rows: usize) -> usize {
    let last_start = rows.saturating_sub(shown);
    let offset = match selected {
        Some(selected) if selected < before => selected,
        Some(selected) if shown > 0 && selected >= before + shown => selected + 1 - shown,
        _ => before,
    };
    offset.min(last_start)
}

/// A name with the letters a filter matched in bold yellow.
fn highlighted(name: &str, filter: &str) -> Line<'static> {
    let matched = fuzzy::positions(filter, name).unwrap_or_default();
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut run = String::new();
    let mut run_matched = false;
    for (at, letter) in name.chars().enumerate() {
        let is_matched = matched.binary_search(&at).is_ok();
        if is_matched != run_matched && !run.is_empty() {
            spans.push(name_span(core::mem::take(&mut run), run_matched));
        }
        run_matched = is_matched;
        run.push(letter);
    }
    if !run.is_empty() {
        spans.push(name_span(run, run_matched));
    }
    Line::from(spans)
}

fn name_span(text: String, matched: bool) -> Span<'static> {
    match matched {
        true => Span::styled(text, Style::new().fg(YELLOW).bold()),
        false => Span::raw(text),
    }
}

/// How many hex digits the widest address takes.
fn address_width(addresses: impl Iterator<Item = u64>) -> usize {
    let widest = addresses.max().unwrap_or(0);
    (u64::BITS - widest.leading_zeros()).div_ceil(4).max(1) as usize
}

/// A line of a diff: the address of its instruction in gray, then the line
/// with the sign and the color of a patch.
fn half_line(half: Half<'_>, width: usize) -> Line<'static> {
    let (sign, text, color) = match half.side {
        Side::Empty => return Line::default(),
        Side::Same(text) => (' ', text, None),
        Side::Removed(text) => ('-', text, Some(REMOVED)),
        Side::Added(text) => ('+', text, Some(ADDED)),
        Side::Changed(text) => ('~', text, Some(EDITED)),
    };
    let address = match half.address {
        Some(address) => format!("{address:>width$x} "),
        None => " ".repeat(width + 1),
    };
    let style = color.map_or_else(Style::new, |color| Style::new().fg(color));
    Line::from(vec![
        Span::styled(address, Style::new().fg(GRAY_FG)),
        Span::styled(format!("{sign} {text}"), style),
    ])
}

/// The `+/-/~` cell, each count in the color of its kind.
fn edits_line(edits: Edits) -> Line<'static> {
    if edits.total() == 0 {
        return Line::styled("-", Style::new().fg(GRAY_FG));
    }
    let slash = || Span::styled("/", Style::new().fg(GRAY_FG));
    Line::from(vec![
        Span::styled(edits.added.to_string(), Style::new().fg(ADDED)),
        slash(),
        Span::styled(edits.removed.to_string(), Style::new().fg(REMOVED)),
        slash(),
        Span::styled(edits.edited.to_string(), Style::new().fg(EDITED)),
    ])
}

/// A scrollbar at the right of a pane, below its frame line, where the
/// `total` lines do not fit.
fn draw_scrollbar(frame: &mut Frame<'_>, area: Rect, total: usize, position: usize) {
    let below_frame =
        Rect { y: area.y.saturating_add(1), height: area.height.saturating_sub(1), ..area };
    let shown = usize::from(below_frame.height);
    if total <= shown {
        return;
    }
    let mut state = ScrollbarState::new(total).position(position).viewport_content_length(shown);
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(None)
        .end_symbol(None)
        .track_style(Style::new().fg(GRAY))
        .thumb_style(Style::new().fg(GRAY_FG));
    frame.render_stateful_widget(scrollbar, below_frame, &mut state);
}

fn help_header(text: &'static str) -> Line<'static> {
    Line::styled(text, Style::new().fg(BLUE).bold())
}

fn help_entry(key: &str, what: &'static str) -> Line<'static> {
    Line::from(vec![Span::styled(format!("  {key:<11}"), Style::new().fg(GREEN)), Span::raw(what)])
}

/// The keys of each screen and what the colors mean, over the middle of the
/// screen.
fn draw_help(frame: &mut Frame<'_>) {
    let swatch = |text: &'static str, color| Span::styled(text, Style::new().fg(color).bold());
    let left = vec![
        help_header("Functions"),
        help_entry("j / k", "down / up"),
        help_entry("PgDn/PgUp", "a page down / up"),
        help_entry("g / G", "first / last"),
        help_entry("⏎", "open the diff"),
        help_entry("s", "next order"),
        help_entry("S", "reverse the order"),
        help_entry("t", "next kind touched"),
        help_entry("a", "every function"),
        help_entry("r", "retouched pairs"),
        help_entry("d", "data regions"),
        help_entry("/", "filter the names, fuzzy"),
        Line::default(),
        help_header("Global"),
        help_entry("?", "this help"),
        help_entry("q", "quit, after a question"),
        help_entry("wheel", "scroll"),
        help_entry("click", "select, again to open"),
    ];
    let right = vec![
        help_header("Diff"),
        help_entry("j / k", "down / up"),
        help_entry("PgDn/PgUp", "a page down / up"),
        help_entry("g / G", "top / bottom"),
        help_entry("] / [", "next / previous change"),
        help_entry("v", "assembly or IL"),
        help_entry("l", "side by side or one"),
        help_entry("n / p", "next / previous"),
        help_entry("esc", "back to the list"),
        Line::default(),
        help_header("Colors"),
        Line::from(vec![
            Span::raw("  "),
            swatch("changed ", tone_of(Changed::Yes)),
            swatch("values ", tone_of(Changed::InDetail)),
            swatch("unread", tone_of(Changed::Unreadable)),
        ]),
        Line::from(vec![
            Span::raw("  "),
            swatch("reordered ", tone_of(Changed::Reordered)),
            swatch("data ", tone_of(Changed::Data)),
            swatch("same", tone_of(Changed::No)),
        ]),
        Line::from(vec![
            Span::raw("  "),
            swatch("+ added ", ADDED),
            swatch("- removed ", REMOVED),
            swatch("~ value", EDITED),
        ]),
    ];

    let height = u16::try_from(left.len().max(right.len()) + 2).unwrap_or(u16::MAX);
    let area = popup_area(frame.area(), 78, height);
    let block = Block::bordered()
        .border_style(Style::new().fg(ORANGE))
        .title(Span::styled("Help", Style::new().fg(YELLOW).bold()))
        .title_bottom(Line::styled("esc/q/? close", Style::new().fg(GRAY_FG)).right_aligned());
    let inner = block.inner(area);
    frame.render_widget(Clear, area);
    frame.render_widget(block, area);
    let [left_area, right_area] =
        Split::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(inner);
    frame.render_widget(Paragraph::new(left), left_area);
    frame.render_widget(Paragraph::new(right), right_area);
}

/// The question whether to quit, over the middle of the screen.
fn draw_quit(frame: &mut Frame<'_>) {
    let [area] = Split::vertical([Constraint::Length(3)]).flex(Flex::Center).areas(frame.area());
    let [area] = Split::horizontal([Constraint::Percentage(60)]).flex(Flex::Center).areas(area);
    let question = Paragraph::new(Line::from(vec![
        Span::raw("Are you sure you want to exit? ("),
        Span::styled("Enter", Style::new().fg(GREEN)),
        Span::raw(" to confirm, "),
        Span::styled("Esc", Style::new().fg(GREEN)),
        Span::raw(" to cancel)"),
    ]))
    .block(
        Block::bordered()
            .border_style(Style::new().fg(ORANGE))
            .title(Span::styled("Quit Confirmation", Style::new().fg(YELLOW).bold())),
    );
    frame.render_widget(Clear, area);
    frame.render_widget(question, area);
}

/// A box of at most `width` by `height` in the middle of `area`.
fn popup_area(area: Rect, width: u16, height: u16) -> Rect {
    let [area] = Split::vertical([Constraint::Max(height)]).flex(Flex::Center).areas(area);
    let [area] = Split::horizontal([Constraint::Max(width)]).flex(Flex::Center).areas(area);
    area
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_moves_as_little_as_keeps_the_selection_in_sight() {
        assert_eq!(visible_offset(0, Some(3), 10, 100), 0, "in sight already");
        assert_eq!(visible_offset(0, Some(10), 10, 100), 1, "one below");
        assert_eq!(visible_offset(20, Some(5), 10, 100), 5, "above");
        assert_eq!(visible_offset(95, Some(99), 10, 100), 90, "no blank rows at the end");
        assert_eq!(visible_offset(5, None, 10, 3), 0, "fewer rows than lines");
        assert_eq!(visible_offset(5, Some(7), 0, 100), 5, "no lines");
        bolero::check!().with_type::<(u16, u16, u8, u16)>().for_each(
            |&(before, selected, shown, rows)| {
                let (before, shown, rows) =
                    (usize::from(before), usize::from(shown), usize::from(rows));
                if rows == 0 {
                    return;
                }
                let selected = usize::from(selected) % rows;
                let offset = visible_offset(before, Some(selected), shown, rows);
                assert!(offset <= rows.saturating_sub(shown));
                if shown > 0 {
                    assert!((offset..offset + shown).contains(&selected));
                }
            },
        );
    }

    #[test]
    fn the_letters_a_filter_matched_stand_out() {
        let line = highlighted("dispatch", "dsp");
        let spans: Vec<(&str, bool)> = line
            .spans
            .iter()
            .map(|span| (span.content.as_ref(), span.style.fg == Some(YELLOW)))
            .collect();
        assert_eq!(spans, [("d", true), ("i", false), ("sp", true), ("atch", false)],);
        assert_eq!(highlighted("main", "").spans.len(), 1, "no filter, one plain span");
        assert_eq!(highlighted("", "x").spans.len(), 0);
    }
}
