//! The report as one HTML page, to read in a browser or send to a person.
//!
//! The page holds what the markdown report holds, then the diff of each
//! listed pair, side by side, with the lines of its jumps. It holds each
//! diff as assembly and as IL, and a button in the header selects which
//! one shows. The page loads nothing from the network: the style and the
//! one short script are part of it.

use hereticus::matching::{
    Changed, Diff, LinePlace, Match, NearMiss, PairedLabels, View, instruction_diff_in,
    line_places, motions,
};
use hereticus::obj::Binary;
use maud::{DOCTYPE, Markup, PreEscaped, html};

use super::marks::Side as MarkSide;
use super::tui::{Cell, Glyph, Gutter, Half, Places, Side, Tint, side_by_side};
use super::{
    Listing, Paint, describe, describe_confidence, describe_edits, describe_kinds, name_of,
    name_of_view, pair_name, summary_lines, unmatched_word,
};

/// The style of the page: dark, in the colors of the TUI, or light where
/// the system asks for light.
const PAGE_CSS: &str = include_str!("html/report.css");

/// Opens the diff that a link of the table goes to. A browser that does
/// not run it still goes to the diff, closed.
const OPEN_TARGET_JS: &str = "\
function openTarget() {
  const target = document.getElementById(decodeURIComponent(location.hash.slice(1)));
  if (target && target.tagName === 'DETAILS') target.open = true;
}
window.addEventListener('hashchange', openTarget);
openTarget();";

/// What the HTML report shows, other than the comparison.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HtmlReport<'a> {
    pub listing: Listing<'a>,
    /// The lowest score at which an unpaired function names its closest
    /// neighbour.
    pub near_miss_floor: f64,
    /// The view that shows when the page opens.
    pub view: View,
    /// The two files as the command line gave them.
    pub paths: [&'a str; 2],
}

/// Print the report as one HTML page.
pub(crate) fn print_html(diff: &Diff, before: &Binary, after: &Binary, report: HtmlReport<'_>) {
    println!("{}", page(diff, before, after, report).into_string());
}

fn page(diff: &Diff, before: &Binary, after: &Binary, report: HtmlReport<'_>) -> Markup {
    let HtmlReport { listing, near_miss_floor, view, paths: [before_path, after_path] } = report;
    let shown = listing.pairs(diff);
    let paired = diff.paired_labels(before, after);
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta name="generator" content=(concat!("hereticus ", env!("CARGO_PKG_VERSION")));
                title { "hereticus: " (before_path) " to " (after_path) }
                style { (PreEscaped(PAGE_CSS)) }
            }
            body {
                // The page holds each diff in each view. The checked
                // button of these two shows one view and hides the other,
                // with no script; the style keys on their order.
                @for each in VIEWS {
                    input.view-choice type="radio" name="view" id={ "view-" (name_of_view(each)) }
                        checked[each == view];
                }
                header {
                    h1 {
                        code.before { (before_path) }
                        " to "
                        code.after { (after_path) }
                    }
                    p.meta {
                        a href=(env!("CARGO_PKG_HOMEPAGE")) { "hereticus" }
                        " " (env!("CARGO_PKG_VERSION"))
                    }
                    p.views {
                        "Show the diffs as "
                        @for each in VIEWS {
                            label for={ "view-" (name_of_view(each)) } { (view_label(each)) }
                        }
                    }
                }
                main {
                    section.summary {
                        @for line in summary_lines(diff, listing.hidden, listing.only) {
                            p { (line) }
                        }
                    }
                    @if !shown.is_empty() {
                        (pair_table(&shown, before, after, listing))
                    }
                    (unmatched_list(diff, before, after, listing, near_miss_floor))
                    @if !shown.is_empty() {
                        section.diffs {
                            h2 { "Diffs" }
                            @for (at, pair) in shown.iter().enumerate() {
                                (pair_diff(at, pair, &paired, [before, after], listing))
                            }
                        }
                    }
                }
                script { (PreEscaped(OPEN_TARGET_JS)) }
            }
        }
    }
}

/// The views the page holds each diff in.
const VIEWS: [View; 2] = [View::Assembly, View::Il];

/// The name of a view on its button.
fn view_label(view: View) -> &'static str {
    match view {
        View::Assembly => "assembly",
        View::Il => "IL",
    }
}

/// The anchor of the diff of the pair at `at` in the table.
fn anchor(at: usize) -> String {
    format!("diff-{at}")
}

/// The class that colors a change, as the TUI colors it.
fn change_class(change: Changed) -> &'static str {
    match change {
        Changed::Yes => "yes",
        Changed::Unreadable => "unreadable",
        Changed::InDetail => "detail",
        Changed::Reordered => "reordered",
        Changed::Data => "data",
        Changed::No => "same",
    }
}

/// A name, with the sign and the label of its mark where it has one.
fn marked_name(name: String, label: Option<&str>) -> Markup {
    html! {
        @if label.is_some() {
            span.mark title="marked" { (super::marks::MARK_SIGN) }
            " "
        }
        code { (name) }
        @if let Some(label) = label.filter(|label| !label.is_empty()) {
            " " span.label { "[" (label) "]" }
        }
    }
}

/// The table of the listed pairs. Each name links to its diff.
fn pair_table(shown: &[&Match], before: &Binary, after: &Binary, listing: Listing<'_>) -> Markup {
    html! {
        section {
            h2 { "Changed functions" }
            div.scroll {
                table.report {
                    thead {
                        tr {
                            th { "Function" }
                            th { "Change" }
                            th.number { "Score" }
                            th.number title="added, removed and rewritten instructions" { "+/-/~" }
                            th { "Touched" }
                            th { "Matched by" }
                        }
                    }
                    tbody {
                        @for (at, pair) in shown.iter().enumerate() {
                            tr {
                                td {
                                    @let name = marked_name(
                                        pair_name(pair, before, after),
                                        listing.marks.of_pair(pair),
                                    );
                                    a href={ "#" (anchor(at)) } { (name) }
                                }
                                td class={ "change " (change_class(pair.changed)) } {
                                    (describe(pair.changed))
                                }
                                td.number { (format!("{:.2}", pair.score)) }
                                td.number { (edit_counts(pair)) }
                                td { (describe_kinds(pair.kinds, pair.changed)) }
                                td { (describe_confidence(pair.confidence)) }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The added, removed and rewritten counts, each in the color of its kind,
/// or the dash of the text report where there is none.
fn edit_counts(pair: &Match) -> Markup {
    let edits = pair.edits;
    if edits.total() == 0 {
        return html! { (describe_edits(edits, Paint::Off)) };
    }
    html! {
        span.added { (edits.added) } "/"
        span.removed { (edits.removed) } "/"
        span.edited { (edits.edited) }
    }
}

/// The functions gone and new, with the closest function on the other side
/// where it scores `floor` or more.
fn unmatched_list(
    diff: &Diff,
    before: &Binary,
    after: &Binary,
    listing: Listing<'_>,
    floor: f64,
) -> Markup {
    let gone = listing.unmatched(diff, MarkSide::Gone);
    let new = listing.unmatched(diff, MarkSide::New);
    if gone.is_empty() && new.is_empty() {
        return html! {};
    }
    let marks = listing.marks;
    html! {
        section {
            h2 { "Unmatched functions" }
            ul.unmatched {
                @for (index, contents) in gone {
                    li {
                        (marked_name(name_of(before, index), marks.of_unmatched(MarkSide::Gone, index)))
                        ": " span.removed { (unmatched_word("gone", contents)) }
                        (near_miss(diff.near_miss(index), after, floor))
                    }
                }
                @for (index, contents) in new {
                    li {
                        (marked_name(name_of(after, index), marks.of_unmatched(MarkSide::New, index)))
                        ": " span.added { (unmatched_word("new", contents)) }
                        (near_miss(diff.added_near_miss(index), before, floor))
                    }
                }
            }
        }
    }
}

/// The closest function on the other side, and the one in the same place,
/// as the text report names them.
fn near_miss(miss: Option<&NearMiss>, other: &Binary, floor: f64) -> Markup {
    let closest =
        miss.filter(|miss| miss.score >= floor).and_then(|miss| Some((miss.best?, miss.score)));
    let in_place = miss.and_then(|miss| miss.in_place);
    html! {
        @if let Some((best, score)) = closest {
            ", closest " code { (name_of(other, best)) } " at " (format!("{score:.2}"))
        }
        @if let Some(place) = in_place {
            ", same place as " code { (name_of(other, place)) }
        }
    }
}

/// The diff of one pair, side by side, closed but for the first.
fn pair_diff(
    at: usize,
    pair: &Match,
    paired: &PairedLabels,
    binaries: [&Binary; 2],
    listing: Listing<'_>,
) -> Markup {
    let [before, after] = binaries;
    html! {
        details.pair id=(anchor(at)) open[at == 0] {
            summary {
                (marked_name(pair_name(pair, before, after), listing.marks.of_pair(pair)))
                " "
                span class={ "change " (change_class(pair.changed)) } { (describe(pair.changed)) }
                " "
                span.counts { (edit_counts(pair)) }
            }
            @for view in VIEWS {
                (diff_table(pair, paired, binaries, view))
            }
        }
    }
}

/// The diff of one pair in one view, side by side.
fn diff_table(
    pair: &Match,
    paired: &PairedLabels,
    [before, after]: [&Binary; 2],
    view: View,
) -> Markup {
    let lines = instruction_diff_in(view, Some(paired), before, pair.before, after, pair.after);
    let places = Places {
        before: line_places(view, before, pair.before),
        after: line_places(view, after, pair.after),
    };
    let moves = motions(&lines, view);
    let rows = side_by_side(&lines, &places, &moves);
    let left: Vec<Half<'_>> = rows.iter().map(|row| row.left).collect();
    let right: Vec<Half<'_>> = rows.iter().map(|row| row.right).collect();
    let gutters = [Gutter::of(&left), Gutter::of(&right)];
    let width = address_width(places.before.iter().chain(&places.after));
    let addresses = [before.functions[pair.before].address, after.functions[pair.after].address];
    html! {
        div class={ "scroll view " (name_of_view(view)) } {
            table.diff {
                thead {
                    tr {
                        th colspan="3" { "before " (format!("{:#x}", addresses[0])) }
                        th colspan="3" { "after " (format!("{:#x}", addresses[1])) }
                    }
                }
                tbody {
                    @for (row, halves) in rows.iter().enumerate() {
                        tr class=[row_class(halves.left, halves.right)] {
                            (half_cells(halves.left, halves.right, gutters[0].row(row), width, view))
                            (half_cells(halves.right, halves.left, gutters[1].row(row), width, view))
                        }
                    }
                }
            }
        }
    }
}

/// How many hex digits the widest address of a diff takes.
fn address_width<'p>(places: impl Iterator<Item = &'p LinePlace>) -> usize {
    places.map(|place| format!("{:x}", place.address).len()).max().unwrap_or(0)
}

/// The class of a row that shows a change, so the eye finds it.
fn row_class(left: Half<'_>, right: Half<'_>) -> Option<&'static str> {
    (left.is_change() || right.is_change()).then_some("change")
}

/// The three cells of one half of a row: the lines of the jumps, the
/// address, and the line with the sign of a patch.
///
/// A rewritten line marks the words that differ from `other`, the line
/// across from it.
fn half_cells(
    half: Half<'_>,
    other: Half<'_>,
    gutter: &[Cell],
    width: usize,
    view: View,
) -> Markup {
    let moved = half.motion == hereticus::matching::Motion::Moved;
    let (sign, text, class) = match half.side {
        Side::Empty => (' ', None, "empty"),
        Side::Same(text) => (' ', Some(text), "same"),
        Side::Removed(text) if moved => ('-', Some(text), "moved"),
        Side::Added(text) if moved => ('+', Some(text), "moved"),
        Side::Removed(text) => ('-', Some(text), "removed"),
        Side::Added(text) => ('+', Some(text), "added"),
        Side::Changed(text) => ('~', Some(text), "edited"),
    };
    let address = half.address().map(|address| format!("{address:>width$x}"));
    let across = match other.side {
        Side::Changed(other) => Some(other),
        _ => None,
    };
    html! {
        td.flow { (gutter_spans(gutter)) }
        td.address { (address.unwrap_or_default()) }
        td class={ "code " (class) } {
            @if let Some(text) = text {
                span.sign { (sign) " " }
                (half.indent())
                (highlighted(text, across, view))
            }
        }
    }
}

/// The cells of a gutter, each glyph in the color of its jump.
fn gutter_spans(cells: &[Cell]) -> Markup {
    html! {
        @for cell in cells {
            @match cell.glyph {
                Glyph::Blank => " ",
                glyph => span class=(tint_class(cell.tint)) { (glyph.symbol()) },
            }
        }
    }
}

fn tint_class(tint: Tint) -> &'static str {
    match tint {
        Tint::Same => "jump",
        Tint::Removed => "removed",
        Tint::Added => "added",
        Tint::Changed => "edited",
    }
}

/// What a token of a line is, for its color.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenKind {
    /// A word the IL gives meaning to, as `if` and `goto`, or the
    /// mnemonic of an instruction.
    Keyword,
    /// A function called or jumped to by name.
    Function,
    Number,
    /// A string the code points at, as `&"text"`.
    Text,
    /// A register, or anything else.
    Plain,
    /// Spaces and signs between the words.
    Punctuation,
}

impl TokenKind {
    fn class(self) -> Option<&'static str> {
        match self {
            Self::Keyword => Some("kw"),
            Self::Function => Some("fn"),
            Self::Number => Some("num"),
            Self::Text => Some("str"),
            Self::Plain | Self::Punctuation => None,
        }
    }
}

/// The words of the IL that read as keywords. A load or a store also
/// carries its width, as `load.32`.
const IL_KEYWORDS: [&str; 7] = ["if", "goto", "call", "return", "load", "store", "compare"];

/// Split one line of a diff into tokens, each with its kind.
fn tokens(text: &str, view: View) -> Vec<(TokenKind, &str)> {
    let mut found = Vec::new();
    let mut rest = text;
    let mut after_call = false;
    while let Some(first) = rest.chars().next() {
        let length = match first {
            '"' => quoted_length(rest),
            // `$+0x24` is one place: the `+` belongs to it.
            '$' => {
                1 + rest[1..].find(|c: char| !is_word_char(c) && c != '+').unwrap_or(rest.len() - 1)
            }
            '@' => 1 + rest[1..].find(|c: char| !is_word_char(c)).unwrap_or(rest.len() - 1),
            _ if is_word_start(first) => {
                rest.find(|c: char| !is_word_char(c)).unwrap_or(rest.len())
            }
            _ => rest.find(|c: char| is_word_start(c) || c == '"').unwrap_or(rest.len()),
        };
        let (token, tail) = rest.split_at(length.max(first.len_utf8()));
        let kind = kind_of(token, found.is_empty(), after_call, view);
        if kind != TokenKind::Punctuation {
            after_call = names_a_target(token, view);
        }
        found.push((kind, token));
        rest = tail;
    }
    found
}

/// The length of the string at the start of `text`, to its closing quote
/// or to the end of the line. A quote after a backslash does not close it.
fn quoted_length(text: &str) -> usize {
    let mut escaped = false;
    for (at, c) in text.char_indices().skip(1) {
        match c {
            '"' if !escaped => return at + 1,
            '\\' => escaped = !escaped,
            _ => escaped = false,
        }
    }
    text.len()
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.'
}

/// The first character of a word: `@` starts an address of the IL.
fn is_word_start(c: char) -> bool {
    is_word_char(c) || c == '@' || c == '$'
}

/// Report whether the word after `token` names a function to go to.
fn names_a_target(token: &str, view: View) -> bool {
    match view {
        View::Il => matches!(token, "call" | "goto"),
        View::Assembly => matches!(token, "call" | "jmp" | "bl" | "b" | "jal" | "j" | "blx"),
    }
}

fn kind_of(token: &str, first: bool, after_call: bool, view: View) -> TokenKind {
    let starts = token.chars().next().unwrap_or(' ');
    if starts == '"' {
        return TokenKind::Text;
    }
    if !is_word_start(starts) {
        return TokenKind::Punctuation;
    }
    let digits = token.trim_start_matches(['$', '@', '+']);
    if digits.starts_with(|c: char| c.is_ascii_digit()) {
        return TokenKind::Number;
    }
    let word = token.split('.').next().unwrap_or(token);
    let keyword = match view {
        View::Il => IL_KEYWORDS.contains(&word),
        View::Assembly => first,
    };
    match () {
        () if keyword => TokenKind::Keyword,
        () if after_call => TokenKind::Function,
        () => TokenKind::Plain,
    }
}

/// A line with each token in the color of its kind. Where `across` is the
/// line it was rewritten from or to, the tokens that differ are marked,
/// from the first that differs to the last.
fn highlighted(text: &str, across: Option<&str>, view: View) -> Markup {
    let own = tokens(text, view);
    let changed = match across {
        Some(other) => differing(&own, &tokens(other, view)),
        None => 0..0,
    };
    html! {
        @for (at, &(kind, token)) in own.iter().enumerate() {
            @if changed.contains(&at) {
                mark { (token_span(kind, token)) }
            } @else {
                (token_span(kind, token))
            }
        }
    }
}

fn token_span(kind: TokenKind, token: &str) -> Markup {
    html! {
        @match kind.class() {
            Some(class) => span class=(class) { (token) },
            None => (token),
        }
    }
}

/// The tokens of `own` between the first and the last that differ from
/// `other`, compared from each end.
fn differing(own: &[(TokenKind, &str)], other: &[(TokenKind, &str)]) -> core::ops::Range<usize> {
    let same = |(a, b): (&(TokenKind, &str), &(TokenKind, &str))| a.1 == b.1;
    let prefix = own.iter().zip(other).take_while(|pair| same(*pair)).count();
    let longest_suffix = own.len().min(other.len()) - prefix;
    let suffix = own
        .iter()
        .rev()
        .zip(other.iter().rev())
        .take(longest_suffix)
        .take_while(|pair| same(*pair))
        .count();
    prefix..own.len() - suffix
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str, view: View) -> Vec<(TokenKind, String)> {
        tokens(text, view)
            .into_iter()
            .filter(|(kind, _)| *kind != TokenKind::Punctuation)
            .map(|(kind, token)| (kind, token.to_string()))
            .collect()
    }

    #[test]
    fn the_tokens_of_a_line_make_the_line() {
        for line in
            ["if (v0 != 0) goto $+0x24", "a1 = &\"No \\\"pending\n\"", "", "ü → x", "\"open"]
        {
            let joined: String =
                tokens(line, View::Il).into_iter().map(|(_, token)| token).collect();
            assert_eq!(joined, line);
        }
    }

    #[test]
    fn an_il_branch_has_its_keywords_and_numbers() {
        use TokenKind::*;
        assert_eq!(
            kinds("if (v0 != 0) goto $+0x24", View::Il),
            [
                (Keyword, "if".into()),
                (Plain, "v0".into()),
                (Number, "0".into()),
                (Keyword, "goto".into()),
                (Number, "$+0x24".into()),
            ]
        );
    }

    #[test]
    fn a_called_name_is_a_function_and_a_width_stays_with_its_keyword() {
        use TokenKind::*;
        assert_eq!(
            kinds("call sub_4072ac", View::Il),
            [(Keyword, "call".into()), (Function, "sub_4072ac".into())]
        );
        assert_eq!(
            kinds("v0 = load.32 [s8 + 0x1C]", View::Il),
            [
                (Plain, "v0".into()),
                (Keyword, "load.32".into()),
                (Plain, "s8".into()),
                (Number, "0x1C".into())
            ]
        );
    }

    #[test]
    fn an_il_address_is_one_number() {
        assert_eq!(kinds("v0 = @0x410000", View::Il)[1], (TokenKind::Number, "@0x410000".into()));
    }

    #[test]
    fn a_string_is_one_token() {
        assert_eq!(kinds("a1 = &\"a b\"", View::Il)[1], (TokenKind::Text, "\"a b\"".into()));
        assert_eq!(
            kinds(r#"&"say \"hi\"" x"#, View::Il)[0],
            (TokenKind::Text, r#""say \"hi\"""#.into())
        );
        assert_eq!(kinds("&\"open", View::Il), [(TokenKind::Text, "\"open".into())]);
    }

    #[test]
    fn the_mnemonic_is_the_keyword_of_an_instruction() {
        use TokenKind::*;
        assert_eq!(
            kinds("bl strncmp", View::Assembly),
            [(Keyword, "bl".into()), (Function, "strncmp".into())]
        );
        assert_eq!(kinds("mov x0, x1", View::Assembly)[1], (Plain, "x0".into()));
    }

    #[test]
    fn only_the_tokens_that_differ_are_marked() {
        let own = tokens("v0 = load.32 [s8 + 0x1C]", View::Il);
        let other = tokens("v0 = load.32 [s8 + 0x20]", View::Il);
        let range = differing(&own, &other);
        assert_eq!(own[range].iter().map(|(_, token)| *token).collect::<String>(), "0x1C");
    }

    #[test]
    fn a_line_that_differs_in_length_marks_what_is_between_the_same_ends() {
        let own = tokens("call strcmp", View::Il);
        let other = tokens("call strncmp", View::Il);
        assert_eq!(own[differing(&own, &other)], [(TokenKind::Function, "strcmp")]);
        let short = tokens("return", View::Il);
        let long = tokens("return", View::Il);
        assert!(differing(&short, &long).is_empty());
        let grown = tokens("a b c", View::Il);
        let base = tokens("a c", View::Il);
        assert_eq!(
            grown[differing(&grown, &base)].iter().map(|(_, t)| *t).collect::<String>(),
            "b "
        );
    }

    #[test]
    fn a_name_and_a_label_are_escaped() {
        let markup = marked_name("<script>".to_string(), Some("a&b")).into_string();
        assert!(markup.contains("&lt;script&gt;"), "{markup}");
        assert!(markup.contains("[a&amp;b]"), "{markup}");
        assert!(!markup.contains("<script>"), "{markup}");
    }

    #[test]
    fn a_line_from_the_binary_is_escaped() {
        let markup = highlighted("a1 = &\"<b>\"", None, View::Il).into_string();
        assert!(markup.contains("&lt;b&gt;"), "{markup}");
    }

    #[test]
    fn every_change_has_a_class() {
        for change in [
            Changed::Yes,
            Changed::Unreadable,
            Changed::InDetail,
            Changed::Reordered,
            Changed::Data,
            Changed::No,
        ] {
            assert!(!change_class(change).is_empty());
        }
    }
}
