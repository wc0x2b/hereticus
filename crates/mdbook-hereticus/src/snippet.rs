//! Turn the text of a diff that a page shows into colored HTML.
//!
//! A page marks each output of the tool with the arguments that make it,
//! as `tests/docs_output.rs` of `hereticus-cli` reads them:
//!
//! ```text
//! <!-- output: --view hil --diff f a.o b.o -->
//! ```console
//! $ hereticus --view hil --diff f a.o b.o
//! ...
//! │ - if (x0 == 0) goto $+0x8
//! ```
//! <!-- end output -->
//! ```
//!
//! The text stays in the page, where the test checks it against what the
//! tool prints, and where a reader of the Markdown sees it. The book shows
//! the code block of an output of `--diff` as HTML in its place: each line
//! in the color of its sign and each word in the color of its kind, as the
//! HTML report shows them, with only the jumps that start and end in sight
//! and a guide for each level of indent.

use hereticus_highlight::{Syntax, tokens};

use crate::gutter::Gutter;

const OUTPUT_START: &str = "<!-- output: ";
const OUTPUT_END: &str = "<!-- end output -->";

/// The characters that draw the lines of the jumps.
const GUTTER_GLYPHS: &str = "│─┼┌└┬┴<>";

/// Each output of `--diff` in `page` shown as HTML, the rest of the page
/// as it was.
pub fn rewrite(page: &str) -> String {
    let mut out = String::with_capacity(page.len());
    let mut rest = page;
    let mut done = 0;
    while let Some(found) = rest.find(OUTPUT_START) {
        let start = done + found;
        let Some(output) = Output::at(page, start) else {
            out.push_str(&rest[..found + OUTPUT_START.len()]);
            done = start + OUTPUT_START.len();
            rest = &page[done..];
            continue;
        };
        out.push_str(&page[done..output.body.start]);
        out.push_str(&output.rewritten(&page[output.body.clone()]));
        done = output.body.end;
        rest = &page[done..];
    }
    out.push_str(rest);
    out
}

/// A marked output whose code block shows a diff.
struct Output {
    syntax: Syntax,
    /// Where the body, between the marker and its end, sits in the page.
    body: core::ops::Range<usize>,
}

impl Output {
    /// The output whose marker starts at `start` of `page`, where it shows
    /// a diff as text.
    fn at(page: &str, start: usize) -> Option<Self> {
        if in_code_block(page, start) {
            return None;
        }
        let marker = &page[start + OUTPUT_START.len()..];
        let args_end = marker.find("-->")?;
        let args: Vec<&str> = marker[..args_end].split_whitespace().collect();
        let shows_a_diff = args.iter().any(|arg| arg.starts_with("--diff"))
            && !args.iter().any(|arg| arg.starts_with("--format"));
        if !shows_a_diff {
            return None;
        }
        let body_start = start + OUTPUT_START.len() + args_end + "-->".len();
        let body_end = body_start + page[body_start..].find(OUTPUT_END)?;
        Some(Self { syntax: syntax_of(&args), body: body_start..body_end })
    }

    /// The body with its code block as HTML.
    fn rewritten(&self, body: &str) -> String {
        let lines: Vec<&str> = body.split('\n').collect();
        let fences: Vec<usize> = (0..lines.len())
            .filter(|&at| lines[at].trim_start().starts_with("```"))
            .take(2)
            .collect();
        let [open, close] = fences[..] else { return body.to_owned() };
        let shown = render(&lines[open + 1..close], self.syntax);
        let mut out: Vec<&str> = lines[..open].to_vec();
        out.push(&shown);
        out.extend(&lines[close + 1..]);
        out.join("\n")
    }
}

/// Whether `at` is inside a fenced code block of `text`, which shows a
/// marker and does not use it.
fn in_code_block(text: &str, at: usize) -> bool {
    text[..at].lines().filter(|line| line.trim_start().starts_with("```")).count() % 2 == 1
}

/// The language of the lines that `--view` of `args` shows.
fn syntax_of(args: &[&str]) -> Syntax {
    let named = args.iter().enumerate().find_map(|(at, arg)| match arg.strip_prefix("--view") {
        Some("") => args.get(at + 1).copied(),
        Some(value) => value.strip_prefix('='),
        None => None,
    });
    match named {
        Some("il") => Syntax::Il,
        Some("hil") => Syntax::Hil,
        _ => Syntax::Assembly,
    }
}

/// The sign of a line of a diff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sign {
    Same,
    Added,
    Removed,
    Edited,
}

impl Sign {
    fn of(c: char) -> Option<Self> {
        match c {
            ' ' => Some(Self::Same),
            '+' => Some(Self::Added),
            '-' => Some(Self::Removed),
            '~' => Some(Self::Edited),
            _ => None,
        }
    }

    fn class(self) -> &'static str {
        match self {
            Self::Same => "same",
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Edited => "edited",
        }
    }

    fn symbol(self) -> char {
        match self {
            Self::Same => ' ',
            Self::Added => '+',
            Self::Removed => '-',
            Self::Edited => '~',
        }
    }
}

/// One line of a code block that shows a diff.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Line<'a> {
    /// `$ hereticus …`.
    Command(&'a str),
    /// `...`, or `... 12 lines`: lines left out.
    Elision(&'a str),
    /// A line of the diff, with the text of its gutter.
    Diff { gutter: String, sign: Sign, code: &'a str },
    /// Any other line, as the name of the pair above its diff.
    Other(&'a str),
}

fn is_elision(line: &str) -> bool {
    line.trim_end().strip_prefix("...").is_some_and(|rest| {
        let rest = rest.trim();
        let count = rest.strip_suffix(" lines").or_else(|| rest.strip_suffix(" line"));
        rest.is_empty() || count.is_some_and(|n| n.parse::<usize>().is_ok())
    })
}

/// Where the sign of a line of `line` sits, as a count of characters,
/// where the line reads as a line of a diff.
fn sign_column(line: &str) -> Option<usize> {
    let mut chars =
        line.chars().enumerate().skip_while(|&(_, c)| c == ' ' || GUTTER_GLYPHS.contains(c));
    let (at, sign) = chars.next()?;
    let spaced = chars.next().is_none_or(|(_, c)| c == ' ');
    (matches!(sign, '+' | '-' | '~') && spaced && at != 1).then_some(at)
}

/// How many columns the gutter of `lines` takes, with the space after it.
/// The tool draws a gutter only where a jump shows, then a space, then the
/// sign of each line.
fn gutter_width(lines: &[&str]) -> usize {
    if let Some(sign) = lines.iter().filter_map(|line| sign_column(line)).min() {
        return sign;
    }
    let last_glyph = |line: &&str| {
        let lead = line.chars().take_while(|&c| c == ' ' || GUTTER_GLYPHS.contains(c));
        lead.enumerate().filter(|&(_, c)| c != ' ').map(|(at, _)| at + 1).last()
    };
    lines.iter().filter_map(last_glyph).max().map_or(0, |width| width + 1)
}

/// Each of `lines` read as what it shows.
fn parse<'a>(lines: &[&'a str]) -> Vec<Line<'a>> {
    let diff_lines: Vec<&str> =
        lines.iter().copied().filter(|line| !line.starts_with("$ ") && !is_elision(line)).collect();
    let width = gutter_width(&diff_lines);
    lines
        .iter()
        .map(|&line| {
            if let Some(command) = line.strip_prefix("$ ") {
                return Line::Command(command);
            }
            if is_elision(line) {
                return Line::Elision(line.trim());
            }
            diff_line(line, width).unwrap_or(Line::Other(line))
        })
        .collect()
}

/// `line` as a line of a diff whose gutter, with its space, takes `width`
/// columns.
fn diff_line(line: &str, width: usize) -> Option<Line<'_>> {
    let split = line.char_indices().nth(width).map_or(line.len(), |(at, _)| at);
    let (lead, rest) = line.split_at(split);
    let gutter = match width {
        0 => "",
        _ => lead.strip_suffix(' ')?,
    };
    if lead.chars().count() != width
        || !gutter.chars().all(|c| c == ' ' || GUTTER_GLYPHS.contains(c))
    {
        return None;
    }
    let mut chars = rest.chars();
    let sign = Sign::of(chars.next()?)?;
    let code = match chars.next() {
        Some(' ') => &rest[2..],
        None => "",
        Some(_) => return None,
    };
    if sign == Sign::Same && code.trim().is_empty() {
        return None;
    }
    Some(Line::Diff { gutter: gutter.to_owned(), sign, code })
}

/// The lines of the gutters of `lines` with only the jumps whose two ends
/// show in one run of lines, and without the columns that hold no jump.
fn prune_gutters(lines: &mut [Line<'_>]) {
    let diffs: Vec<usize> =
        (0..lines.len()).filter(|&at| matches!(lines[at], Line::Diff { .. })).collect();
    let gutters = diffs.iter().map(|&at| match &lines[at] {
        Line::Diff { gutter, .. } => gutter.as_str(),
        _ => unreachable!("only the lines of the diff"),
    });
    let Some(mut gutter) = Gutter::parse(gutters) else { return };
    // A run ends where a line that is no line of the diff comes between.
    let mut start = 0;
    for row in 1..=diffs.len() {
        if row == diffs.len() || diffs[row] != diffs[row - 1] + 1 {
            gutter.keep_whole_jumps(start..row);
            start = row;
        }
    }
    gutter.drop_empty_columns();
    let empty = gutter.is_empty();
    for (at, row) in diffs.into_iter().zip(gutter.rows()) {
        if let Line::Diff { gutter, .. } = &mut lines[at] {
            *gutter = if empty { String::new() } else { row };
        }
    }
}

/// `lines` of a code block that shows a diff, as one HTML block.
fn render(lines: &[&str], syntax: Syntax) -> String {
    let mut parsed = parse(lines);
    prune_gutters(&mut parsed);
    let mut html = String::from(r#"<pre class="hereticus-diff">"#);
    for line in parsed {
        match line {
            Line::Command(command) => {
                html.push_str(r#"<span class="line command"><span class="prompt">$ </span>"#);
                escape_into(&mut html, command);
            }
            Line::Elision(text) => {
                html.push_str(r#"<span class="line elision">"#);
                escape_into(&mut html, text);
            }
            Line::Other(text) => {
                html.push_str(r#"<span class="line other">"#);
                escape_into(&mut html, text);
            }
            Line::Diff { gutter, sign, code } => {
                html.push_str(r#"<span class="line "#);
                html.push_str(sign.class());
                html.push_str(r#"">"#);
                if !gutter.is_empty() {
                    html.push_str(r#"<span class="flow">"#);
                    escape_into(&mut html, &gutter);
                    html.push_str("</span> ");
                }
                html.push_str(r#"<span class="sign">"#);
                html.push(sign.symbol());
                html.push_str("</span> ");
                code_into(&mut html, code, syntax);
            }
        }
        // Each line is a block of its own, so a new line in the text
        // would show as an empty line.
        html.push_str("</span>");
    }
    html.push_str("</pre>");
    html
}

/// `code`, which starts with two spaces for each level of indent, with a
/// guide for each level and each token in the color of its kind.
fn code_into(html: &mut String, code: &str, syntax: Syntax) {
    let text = code.trim_start_matches(' ');
    let indent = code.len() - text.len();
    for _ in 0..indent / 2 {
        html.push_str(r#"<span class="indent">  </span>"#);
    }
    html.push_str(&" ".repeat(indent % 2));
    for (kind, token) in tokens(text, syntax) {
        match kind.class() {
            Some(class) => {
                html.push_str(r#"<span class=""#);
                html.push_str(class);
                html.push_str(r#"">"#);
                escape_into(html, token);
                html.push_str("</span>");
            }
            None => escape_into(html, token),
        }
    }
}

fn escape_into(html: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '&' => html.push_str("&amp;"),
            '<' => html.push_str("&lt;"),
            '>' => html.push_str("&gt;"),
            '"' => html.push_str("&quot;"),
            c => html.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HIL_PAGE: &str = "Text\n\
        <!-- output: --view hil --diff f a b -->\n\
        ```console\n\
        $ hereticus --view hil --diff f a b\n\
        ...\n\
        │   -   x1 = &\"<null>\"\n\
        │┌> -   strcpy(&var_28, x1)\n\
        ││  +   strcpy(&var_148, &\"null\")\n\
        │└< +   goto $-0x40\n\
        ... 3 lines\n\
        \x20     return\n\
        ```\n\
        <!-- end output -->\n\
        After\n";

    #[test]
    fn a_page_keeps_its_text_and_its_markers() {
        let page = rewrite(HIL_PAGE);
        assert!(page.starts_with("Text\n<!-- output: --view hil --diff f a b -->\n<pre"), "{page}");
        assert!(page.ends_with("</pre>\n<!-- end output -->\nAfter\n"), "{page}");
        assert!(!page.contains("```"), "{page}");
    }

    #[test]
    fn only_a_diff_shown_as_text_turns_to_html() {
        for page in [
            "<!-- output: --format markdown a b -->\n```console\n$ x\n```\n<!-- end output -->",
            "<!-- output: -h -->\n```console\n$ x\n```\n<!-- end output -->",
            "```markdown\n<!-- output: --diff f a b -->\n- a\n<!-- end output -->\n```\n",
            "<!-- output: --diff f a b -->\n- a\n<!-- end output -->",
            "<!-- output: --diff f a b -->\n```console\n- a\n```\n",
            "No marker",
        ] {
            assert_eq!(rewrite(page), page);
        }
    }

    #[test]
    fn each_line_takes_the_class_of_its_sign() {
        let page = rewrite(HIL_PAGE);
        assert!(page.contains(r#"<span class="line removed"><span class="flow">"#), "{page}");
        assert!(page.contains(r#"</span> <span class="sign">-</span> "#), "{page}");
        assert!(page.contains(r#"<span class="line added">"#), "{page}");
        assert!(page.contains(r#"<span class="line elision">... 3 lines</span>"#), "{page}");
        assert!(
            page.contains(r#"<span class="line command"><span class="prompt">$ </span>hereticus"#)
        );
    }

    #[test]
    fn the_jump_in_sight_stays_and_the_cut_one_goes() {
        let page = rewrite(HIL_PAGE);
        assert!(page.contains(r#"<span class="flow">┌&gt;</span>"#), "{page}");
        assert!(page.contains(r#"<span class="flow">└&lt;</span>"#), "{page}");
        assert!(page.contains(r#"<span class="flow">│ </span>"#), "{page}");
        assert!(!page.contains("│┌"), "lane 0 runs out of sight: {page}");
    }

    #[test]
    fn a_line_is_escaped_and_colored() {
        let page = rewrite(HIL_PAGE);
        assert!(page.contains(r#"<span class="str">&quot;&lt;null&gt;&quot;</span>"#), "{page}");
        assert!(page.contains(r#"<span class="fn">strcpy</span>"#), "{page}");
        assert!(page.contains(r#"<span class="kw">goto</span> <span class="num">$-0x40</span>"#));
    }

    #[test]
    fn each_level_of_indent_takes_a_guide() {
        let mut html = String::new();
        code_into(&mut html, "     x", Syntax::Il);
        assert_eq!(html, r#"<span class="indent">  </span><span class="indent">  </span> x"#);
    }

    #[test]
    fn the_view_names_the_syntax() {
        assert_eq!(syntax_of(&["--view", "hil", "--diff"]), Syntax::Hil);
        assert_eq!(syntax_of(&["--view=il"]), Syntax::Il);
        assert_eq!(syntax_of(&["--diff", "f"]), Syntax::Assembly);
        assert_eq!(syntax_of(&["--view"]), Syntax::Assembly);
    }

    #[test]
    fn a_line_of_a_diff_reads_back_with_and_without_a_gutter() {
        assert_eq!(
            parse(&["│┌> - a", "││      b"]),
            [
                Line::Diff { gutter: "│┌>".into(), sign: Sign::Removed, code: "a" },
                Line::Diff { gutter: "││ ".into(), sign: Sign::Same, code: "  b" },
            ]
        );
        assert_eq!(
            parse(&["sub_1 -> sub_2", "- a", "  b"]),
            [
                Line::Other("sub_1 -> sub_2"),
                Line::Diff { gutter: String::new(), sign: Sign::Removed, code: "a" },
                Line::Diff { gutter: String::new(), sign: Sign::Same, code: "b" },
            ]
        );
    }

    #[test]
    fn a_gutter_of_only_same_lines_takes_the_width_of_its_glyphs() {
        assert_eq!(gutter_width(&["┌─<   a", "│     b"]), 4);
        assert_eq!(gutter_width(&["  a"]), 0);
    }

    #[test]
    fn an_elision_may_give_its_count() {
        assert!(is_elision("..."));
        assert!(is_elision("... 12 lines"));
        assert!(is_elision("... 1 line"));
        assert!(!is_elision("... many lines"));
        assert!(!is_elision("...x"));
    }

    #[test]
    fn any_block_turns_to_html_with_each_line() {
        bolero::check!().with_type::<Vec<String>>().for_each(|lines| {
            let lines: Vec<&str> =
                lines.iter().map(|line| line.split('\n').next().unwrap_or("")).collect();
            let html = render(&lines, Syntax::Hil);
            assert_eq!(html.matches(r#"<span class="line "#).count(), lines.len());
            assert!(html.starts_with("<pre") && html.ends_with("</pre>"));
        });
    }
}
