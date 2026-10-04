//! Draw the browser: a title with tabs, the pane of the screen, and a
//! status bar, as `heretek` lays them out.

use hereticus::matching::{Changed, Edits};
use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout as Split, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
    Table, Tabs,
};

use super::rows::{Half, Side, side_by_side, unified};
use super::theme::{
    ADDED, BLUE, DARK_GRAY, EDITED, Focus, GRAY, GRAY_FG, GREEN, ORANGE, PURPLE, REMOVED, YELLOW,
    pane_block, tone_of,
};
use super::{App, Entry, Help, Labeled, Layout, Scope, Screen};
use crate::{
    DataRegions, Retouched, describe, describe_confidence, describe_kinds, name_of, name_of_view,
    unmatched_word,
};

/// The keys of each pane, at the right of its frame.
const TABLE_HINTS: &str = "⏎ open  s sort  / filter";
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
        if self.help == Help::Shown {
            draw_help(frame);
        }
    }

    /// The name and version over the tabs of the two screens, with the two
    /// files at the right.
    fn draw_title(&self, frame: &mut Frame<'_>, area: Rect) {
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
        let rows: Vec<Row<'static>> =
            self.rows.iter().map(|&index| self.table_row(&self.entries[index])).collect();
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
        frame.render_stateful_widget(table, area, &mut self.table);
        let position = self.table.selected().unwrap_or(0);
        draw_scrollbar(frame, area, self.rows.len(), position);
    }

    /// One row of the table. A function gone or new names its closest
    /// candidate where it has one, in the column of what a pair touched.
    fn table_row(&self, labeled: &Labeled) -> Row<'static> {
        let name = Cell::from(labeled.label.clone());
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
        let scroll = u16::try_from(opened.scroll).unwrap_or(u16::MAX);
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
        let total = match self.layout {
            Layout::SideBySide => {
                let rows = side_by_side(&opened.lines, addresses);
                let (left, right): (Vec<Line<'_>>, Vec<Line<'_>>) = rows
                    .iter()
                    .map(|row| (half_line(row.left, width), half_line(row.right, width)))
                    .unzip();
                let [left_area, divider, right_area] = Split::horizontal([
                    Constraint::Fill(1),
                    Constraint::Length(1),
                    Constraint::Fill(1),
                ])
                .areas(content);
                frame.render_widget(Paragraph::new(left).scroll((scroll, 0)), left_area);
                frame.render_widget(
                    Block::new().borders(Borders::LEFT).border_style(Style::new().fg(GRAY)),
                    divider,
                );
                frame.render_widget(Paragraph::new(right).scroll((scroll, 0)), right_area);
                rows.len()
            }
            Layout::Unified => {
                let sides = unified(&opened.lines, addresses);
                let lines: Vec<Line<'_>> =
                    sides.iter().map(|half| half_line(*half, width)).collect();
                frame.render_widget(Paragraph::new(lines).scroll((scroll, 0)), content);
                sides.len()
            }
        };
        draw_scrollbar(frame, area, total, usize::from(scroll));
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
            separator(),
            Span::styled(
                format!("{} of {} functions", self.rows.len(), self.entries.len()),
                Style::new().fg(GREEN),
            ),
        ];
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
        help_entry("a", "every function"),
        help_entry("r", "retouched pairs"),
        help_entry("d", "data regions"),
        help_entry("/", "filter the names"),
        Line::default(),
        help_header("Global"),
        help_entry("?", "this help"),
        help_entry("q", "quit"),
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
    let area = popup_area(frame.area(), 72, height);
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

/// A box of at most `width` by `height` in the middle of `area`.
fn popup_area(area: Rect, width: u16, height: u16) -> Rect {
    let [area] = Split::vertical([Constraint::Max(height)]).flex(Flex::Center).areas(area);
    let [area] = Split::horizontal([Constraint::Max(width)]).flex(Flex::Center).areas(area);
    area
}
