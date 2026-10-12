//! Keep `RESEARCH.md` and the code that applies it in step.
//!
//! Each entry of `RESEARCH.md` names its code on a `Code:` line, and that
//! code names the entry back, as `See RESEARCH.md, A1` or `RESEARCH.md,
//! entry 7`. A rename on one side and not the other fails here.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn research() -> String {
    std::fs::read_to_string(root().join("RESEARCH.md")).expect("RESEARCH.md is at the root")
}

/// Every Rust source of the crates, as one text.
fn sources() -> String {
    fn walk(dir: &Path, text: &mut String) {
        for entry in std::fs::read_dir(dir).expect("a source directory").flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, text);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                text.push_str(&std::fs::read_to_string(&path).expect("a source file"));
            }
        }
    }
    let mut text = String::new();
    for dir in ["hereticus/src", "hereticus-cli/src", "crates/hereticus-il/src"] {
        walk(&root().join(dir), &mut text);
    }
    text
}

/// The text of each `Code:` paragraph, up to the blank line after it.
fn code_paragraphs(research: &str) -> Vec<String> {
    let mut paragraphs = Vec::new();
    let mut current: Option<String> = None;
    for line in research.lines() {
        match (&mut current, line) {
            (None, line) if line.starts_with("Code: ") => current = Some(line.to_owned()),
            (Some(paragraph), "") => {
                paragraphs.push(core::mem::take(paragraph));
                current = None;
            }
            (Some(paragraph), line) => {
                paragraph.push(' ');
                paragraph.push_str(line);
            }
            (None, _) => {}
        }
    }
    paragraphs.extend(current);
    paragraphs
}

/// The last segment of each item a `Code:` paragraph names in backticks,
/// leaving out file names.
fn named_items(paragraph: &str) -> Vec<String> {
    paragraph
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|name| !name.contains('.') && !name.contains('/'))
        .map(|name| name.rsplit("::").next().unwrap_or(name).to_owned())
        .collect()
}

/// Report whether `source` defines `name` as a function, type, constant,
/// field or enum variant.
fn defines(source: &str, name: &str) -> bool {
    ["fn ", "struct ", "enum ", "const ", "trait ", "type "].iter().any(|keyword| {
        source.contains(&format!("{keyword}{name}("))
            || source.contains(&format!("{keyword}{name} "))
            || source.contains(&format!("{keyword}{name}<"))
            || source.contains(&format!("{keyword}{name}:"))
    }) || source.contains(&format!("pub {name}:"))
        || source.contains(&format!("    {name},"))
        || source.contains(&format!("    {name} {{"))
}

#[test]
fn every_item_research_names_is_in_the_code() {
    let (research, sources) = (research(), sources());
    let missing: Vec<String> = code_paragraphs(&research)
        .iter()
        .flat_map(|paragraph| named_items(paragraph))
        .filter(|name| !defines(&sources, name))
        .collect();
    assert!(missing.is_empty(), "RESEARCH.md names code that is gone: {missing:?}");
}

#[test]
fn every_entry_the_code_names_is_in_research() {
    let (research, sources) = (research(), sources());
    let headings: BTreeSet<String> = research
        .lines()
        .filter_map(|line| line.strip_prefix("## ").or_else(|| line.strip_prefix("### ")))
        .filter_map(|heading| heading.split('.').next())
        .map(str::to_owned)
        .collect();

    let mut cited = BTreeSet::new();
    for citation in sources.split("RESEARCH.md, ").skip(1) {
        let tag = citation.trim_start_matches("entry ").trim_start_matches("entries ");
        let tag: String = tag.chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
        if !tag.is_empty() {
            cited.insert(tag);
        }
    }
    assert!(!cited.is_empty(), "the code cites RESEARCH.md");
    let missing: Vec<&String> = cited.iter().filter(|tag| !headings.contains(*tag)).collect();
    assert!(missing.is_empty(), "the code cites entries RESEARCH.md lacks: {missing:?}");
}

#[test]
fn every_entry_names_its_code() {
    let research = research();
    let mut entry = None;
    let mut without = Vec::new();
    for line in research.lines() {
        let heading = line.strip_prefix("## ").or_else(|| line.strip_prefix("### "));
        if let Some(heading) = heading {
            if let Some(name) = entry.take() {
                without.push(name);
            }
            let tag = heading.split('.').next().unwrap_or_default();
            let numbered = tag.chars().next().is_some_and(|c| c.is_ascii_digit())
                || (tag.starts_with('A') && tag[1..].chars().all(|c| c.is_ascii_digit()));
            if numbered && !tag.is_empty() && tag.len() < 4 {
                entry = Some(heading.to_owned());
            }
        } else if line.starts_with("Code: ") {
            entry = None;
        }
    }
    without.extend(entry);
    assert!(without.is_empty(), "entries with no Code: line: {without:?}");
}
