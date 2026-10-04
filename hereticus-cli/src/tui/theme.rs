//! The colors and the pane frame of the browser, as `heretek` draws them.

use hereticus::matching::Changed;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders};

// The Ayu palette.
pub const BLUE: Color = Color::Rgb(0x59, 0xc2, 0xff);
pub const PURPLE: Color = Color::Rgb(0xd2, 0xa6, 0xff);
pub const ORANGE: Color = Color::Rgb(0xff, 0x8f, 0x40);
pub const YELLOW: Color = Color::Rgb(0xe6, 0xb4, 0x50);
pub const GREEN: Color = Color::Rgb(0xaa, 0xd9, 0x4c);
pub const RED: Color = Color::Rgb(0xff, 0x33, 0x33);
pub const DARK_GRAY: Color = Color::Rgb(0x20, 0x27, 0x34);
pub const GRAY: Color = Color::Rgb(0x44, 0x44, 0x44);
pub const GRAY_FG: Color = Color::Rgb(100, 100, 100);

/// The colors of a patch, as the `+/-/~` column uses them.
pub const ADDED: Color = GREEN;
pub const REMOVED: Color = RED;
pub const EDITED: Color = YELLOW;

/// Whether a pane has the keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Focus {
    Active,
    Inactive,
}

/// The color of a change, from a rewritten body to no change at all.
pub fn tone_of(change: Changed) -> Color {
    match change {
        Changed::Yes => RED,
        Changed::Unreadable => PURPLE,
        Changed::InDetail => YELLOW,
        Changed::Reordered => BLUE,
        Changed::Data => GRAY_FG,
        Changed::No => GREEN,
    }
}

/// The frame of a pane: a top border, a bold title, what the pane shows in
/// gray, and the keys of the pane at the right.
pub fn pane_block<'a>(
    title: &str,
    context: Option<String>,
    hints: &str,
    focus: Focus,
) -> Block<'a> {
    let title_color = match focus {
        Focus::Active => GREEN,
        Focus::Inactive => ORANGE,
    };
    let mut left = vec![
        Span::styled("──", Style::new().fg(GRAY)),
        Span::styled(format!(" {title}"), Style::new().fg(title_color).bold()),
    ];
    if let Some(context) = context {
        left.push(Span::styled(format!(" {context}"), Style::new().fg(GRAY_FG)));
    }
    left.push(Span::raw(" "));
    let block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::new().fg(GRAY))
        .title_top(Line::from(left));
    match hints {
        "" => block,
        hints => block.title_top(
            Line::from(Span::styled(format!(" {hints} "), Style::new().fg(GRAY_FG)))
                .right_aligned(),
        ),
    }
}
