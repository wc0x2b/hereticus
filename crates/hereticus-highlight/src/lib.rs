//! Split one line of a diff into tokens, each with the kind its color
//! comes from.
//!
//! The HTML report of `hereticus-cli` and the preprocessor of the book
//! color a line the same way, from these tokens.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// The language of a line: each view of a diff reads its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syntax {
    /// An instruction as the decoder prints it, as `bl strncmp`.
    Assembly,
    /// A statement of the IL, as `if (v0 != 0) goto $+0x24`.
    Il,
    /// A statement of the high IL, which also calls a function by name,
    /// as `ret = strcmp(arg1, &"a")`.
    Hil,
}

/// What a token of a line is, for its color.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
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
    /// The CSS class of the kind, or none for a kind in the plain color.
    pub fn class(self) -> Option<&'static str> {
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

/// Split one line of a diff into tokens, each with its kind. The tokens,
/// joined, make the line.
pub fn tokens(text: &str, syntax: Syntax) -> Vec<(TokenKind, &str)> {
    let mut found = Vec::new();
    let mut rest = text;
    let mut after_call = false;
    while let Some(first) = rest.chars().next() {
        let length = match first {
            '"' => quoted_length(rest),
            // `$+0x24` and `$-0x40` are each one place: the sign belongs
            // to it.
            '$' => {
                let signed = 1 + usize::from(rest[1..].starts_with(['+', '-']));
                signed
                    + rest[signed..].find(|c: char| !is_word_char(c)).unwrap_or(rest.len() - signed)
            }
            '@' => 1 + rest[1..].find(|c: char| !is_word_char(c)).unwrap_or(rest.len() - 1),
            _ if is_word_start(first) => {
                rest.find(|c: char| !is_word_char(c)).unwrap_or(rest.len())
            }
            _ => rest.find(|c: char| is_word_start(c) || c == '"').unwrap_or(rest.len()),
        };
        let (token, tail) = rest.split_at(length.max(first.len_utf8()));
        let mut kind = kind_of(token, found.is_empty(), after_call, syntax);
        if syntax == Syntax::Hil
            && kind == TokenKind::Plain
            && calls(&text[..text.len() - rest.len()], tail)
        {
            kind = TokenKind::Function;
        }
        if kind != TokenKind::Punctuation {
            after_call = names_a_target(token, syntax);
        }
        found.push((kind, token));
        rest = tail;
    }
    found
}

/// Whether a word of a high IL line between `before` and `after` names
/// the callee of the call the line makes, as `strcmp` of
/// `ret = strcmp(arg1, &"a")`. An operation such as `compare(` follows a
/// ` = ` of another register, or comes later in the line.
fn calls(before: &str, after: &str) -> bool {
    after.starts_with('(') && matches!(before, "" | "ret = ")
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
fn names_a_target(token: &str, syntax: Syntax) -> bool {
    match syntax {
        Syntax::Il | Syntax::Hil => matches!(token, "call" | "goto"),
        Syntax::Assembly => matches!(token, "call" | "jmp" | "bl" | "b" | "jal" | "j" | "blx"),
    }
}

fn kind_of(token: &str, first: bool, after_call: bool, syntax: Syntax) -> TokenKind {
    let starts = token.chars().next().unwrap_or(' ');
    if starts == '"' {
        return TokenKind::Text;
    }
    if !is_word_start(starts) {
        return TokenKind::Punctuation;
    }
    let digits = token.trim_start_matches(['$', '@', '+', '-']);
    if digits.starts_with(|c: char| c.is_ascii_digit()) {
        return TokenKind::Number;
    }
    let word = token.split('.').next().unwrap_or(token);
    let keyword = match syntax {
        Syntax::Il | Syntax::Hil => IL_KEYWORDS.contains(&word),
        Syntax::Assembly => first,
    };
    match () {
        () if keyword => TokenKind::Keyword,
        () if after_call => TokenKind::Function,
        () => TokenKind::Plain,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::string::{String, ToString};

    fn kinds(text: &str, syntax: Syntax) -> Vec<(TokenKind, String)> {
        tokens(text, syntax)
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
                tokens(line, Syntax::Il).into_iter().map(|(_, token)| token).collect();
            assert_eq!(joined, line);
        }
    }

    #[test]
    fn the_tokens_of_any_line_make_the_line() {
        bolero::check!().with_type::<(String, u8)>().for_each(|(line, pick)| {
            let syntax = [Syntax::Assembly, Syntax::Il, Syntax::Hil][usize::from(*pick % 3)];
            let found = tokens(line, syntax);
            assert!(found.iter().all(|(_, token)| !token.is_empty()), "no token is empty");
            let joined: String = found.into_iter().map(|(_, token)| token).collect();
            assert_eq!(&joined, line);
        });
    }

    #[test]
    fn an_il_branch_has_its_keywords_and_numbers() {
        use TokenKind::*;
        assert_eq!(
            kinds("if (v0 != 0) goto $+0x24", Syntax::Il),
            [
                (Keyword, "if".into()),
                (Plain, "v0".into()),
                (Number, "0".into()),
                (Keyword, "goto".into()),
                (Number, "$+0x24".into()),
            ]
        );
        assert_eq!(kinds("goto $-0x40", Syntax::Hil)[1], (Number, "$-0x40".into()));
        assert_eq!(kinds("x = $", Syntax::Il)[1], (Plain, "$".into()));
    }

    #[test]
    fn a_called_name_is_a_function_and_a_width_stays_with_its_keyword() {
        use TokenKind::*;
        assert_eq!(
            kinds("call sub_4072ac", Syntax::Il),
            [(Keyword, "call".into()), (Function, "sub_4072ac".into())]
        );
        assert_eq!(
            kinds("v0 = load.32 [s8 + 0x1C]", Syntax::Il),
            [
                (Plain, "v0".into()),
                (Keyword, "load.32".into()),
                (Plain, "s8".into()),
                (Number, "0x1C".into())
            ]
        );
    }

    #[test]
    fn a_high_il_call_names_its_callee() {
        use TokenKind::*;
        let call = kinds("ret = strcmp(arg1, &\"a\")", Syntax::Hil);
        assert_eq!(call[0], (Plain, "ret".into()));
        assert_eq!(call[1], (Function, "strcmp".into()));
        assert_eq!(call[2], (Plain, "arg1".into()));
        assert_eq!(kinds("free(x0)", Syntax::Hil)[0], (Function, "free".into()));
        assert_eq!(kinds("flags = compare(arg1, 0)", Syntax::Hil)[1], (Keyword, "compare".into()));
        assert_eq!(kinds("x1 = sxtw(w1)", Syntax::Hil)[1], (Plain, "sxtw".into()));
        assert_eq!(
            kinds("strcmp(x0)", Syntax::Il)[0],
            (Plain, "strcmp".into()),
            "no call in the IL"
        );
    }

    #[test]
    fn an_il_address_is_one_number() {
        assert_eq!(kinds("v0 = @0x410000", Syntax::Il)[1], (TokenKind::Number, "@0x410000".into()));
    }

    #[test]
    fn a_string_is_one_token() {
        assert_eq!(kinds("a1 = &\"a b\"", Syntax::Il)[1], (TokenKind::Text, "\"a b\"".into()));
        assert_eq!(
            kinds(r#"&"say \"hi\"" x"#, Syntax::Il)[0],
            (TokenKind::Text, r#""say \"hi\"""#.into())
        );
        assert_eq!(kinds("&\"open", Syntax::Il), [(TokenKind::Text, "\"open".into())]);
    }

    #[test]
    fn the_mnemonic_is_the_keyword_of_an_instruction() {
        use TokenKind::*;
        assert_eq!(
            kinds("bl strncmp", Syntax::Assembly),
            [(Keyword, "bl".into()), (Function, "strncmp".into())]
        );
        assert_eq!(kinds("mov x0, x1", Syntax::Assembly)[1], (Plain, "x0".into()));
    }

    #[test]
    fn only_some_kinds_take_a_class() {
        assert_eq!(TokenKind::Keyword.class(), Some("kw"));
        assert_eq!(TokenKind::Plain.class(), None);
        assert_eq!(TokenKind::Punctuation.class(), None);
    }
}
