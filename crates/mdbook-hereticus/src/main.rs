//! The preprocessor of the book, which `book/book.toml` names: it shows
//! each output of `--diff` that a page marks as colored HTML, as
//! [`snippet`] tells.
//!
//! mdbook first runs `mdbook-hereticus supports <renderer>`, and runs the
//! preprocessor only where it exits with success. It then writes the
//! context and the book as JSON to standard input, and reads the book back
//! from standard output.

mod gutter;
mod snippet;

use std::io::{Read, Write};
use std::process::ExitCode;

use serde_json::Value;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        // The HTML is of no use to another renderer.
        Some("supports") => match args.get(1).map(String::as_str) {
            Some("html") => ExitCode::SUCCESS,
            _ => ExitCode::FAILURE,
        },
        Some(other) => {
            eprintln!("mdbook-hereticus: unknown command `{other}`");
            ExitCode::FAILURE
        }
        None => match preprocess() {
            Ok(()) => ExitCode::SUCCESS,
            Err(problem) => {
                eprintln!("mdbook-hereticus: {problem}");
                ExitCode::FAILURE
            }
        },
    }
}

/// Read `[context, book]` from standard input, and write the book with
/// each chapter rewritten to standard output.
fn preprocess() -> Result<(), String> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).map_err(|err| format!("cannot read: {err}"))?;
    let book = book_of(&input)?;
    let out = serde_json::to_string(&book).map_err(|err| format!("cannot write: {err}"))?;
    std::io::stdout().write_all(out.as_bytes()).map_err(|err| format!("cannot write: {err}"))
}

/// The book of the input `[context, book]`, each chapter rewritten.
fn book_of(input: &str) -> Result<Value, String> {
    let parsed: Value = serde_json::from_str(input).map_err(|err| format!("bad input: {err}"))?;
    let Value::Array(mut pair) = parsed else {
        return Err("the input is no `[context, book]`".to_owned());
    };
    if pair.len() != 2 {
        return Err("the input is no `[context, book]`".to_owned());
    }
    let mut book = pair.pop().unwrap_or_default();
    rewrite_chapters(&mut book);
    Ok(book)
}

/// Rewrite the content of each chapter in `value`, at any depth: the
/// shape of the book changes between versions of mdbook, and each chapter
/// stays an object `{"Chapter": {"content": …}}`.
fn rewrite_chapters(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(content)) =
                map.get_mut("Chapter").and_then(|chapter| chapter.get_mut("content"))
            {
                *content = snippet::rewrite(content);
            }
            map.values_mut().for_each(rewrite_chapters);
        }
        Value::Array(items) => items.iter_mut().for_each(rewrite_chapters),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_chapter_at_any_depth_is_rewritten() {
        let page = "<!-- output: --diff f a b -->\\n```console\\n- a\\n```\\n<!-- end output -->";
        let input = format!(
            r#"[{{"root": "."}}, {{"items": [{{"Chapter": {{"content": "{page}",
               "sub_items": [{{"Chapter": {{"content": "{page}", "sub_items": []}}}}]}}}},
               "Separator"]}}]"#
        );
        let book = book_of(&input).expect("a book");
        let outer = &book["items"][0]["Chapter"];
        let inner = &outer["sub_items"][0]["Chapter"];
        for chapter in [outer, inner] {
            let content = chapter["content"].as_str().expect("content");
            assert!(content.contains(r#"<pre class="hereticus-diff">"#), "{content}");
        }
        assert_eq!(book["items"][1], "Separator");
    }

    #[test]
    fn input_that_is_no_pair_is_an_error() {
        assert!(book_of("{}").is_err());
        assert!(book_of("[1]").is_err());
        assert!(book_of("not json").is_err());
    }
}
