//! Keep the HTML reports that the book publishes in step with what the
//! tool prints.
//!
//! Each page of [`PAGES`] is the output of `--format html` on binaries that
//! `just truth` fetches to `~/.cache`. The test makes each page again and
//! fails where the committed page differs. `just docs-output` writes the
//! new pages. A page whose binaries were not fetched is skipped.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A page of the book, and how the tool makes it.
struct Page {
    /// The page, from the root of the repository.
    file: &'static str,
    /// Where the tool runs, under the home folder. Each argument with a `/`
    /// is a binary under it. The page shows the paths
    /// of the binaries as the arguments give them, so they are short and
    /// name no home folder.
    dir: &'static str,
    args: &'static [&'static str],
    /// The anchor of the diff of the fix, which the book links to, and the
    /// function the fix edits.
    fix: (&'static str, &'static str),
}

const PAGES: &[Page] = &[Page {
    file: "book/src/reports/cve-2026-18368.html",
    dir: ".cache/hereticus-teltonika",
    args: &["--view", "il", "7.24/RUT9M/usr/sbin/modbusgwd", "7.24.3/RUT9M/usr/sbin/modbusgwd"],
    fix: ("diff-2", "sub_404494"),
}];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").expect("HOME is set"))
}

/// The version of the tool that made `page`, from its `generator`.
fn version_of(page: &str) -> Option<&str> {
    let start = page.find("content=\"hereticus ")? + "content=\"hereticus ".len();
    let length = page[start..].find('"')?;
    Some(&page[start..start + length])
}

#[test]
fn each_html_report_of_the_book_is_what_the_tool_prints() {
    let update = std::env::var_os("DOCS_OUTPUT_UPDATE").is_some();
    let mut stale = Vec::new();
    for page in PAGES {
        let dir = home().join(page.dir);
        if let Some(missing) =
            page.args.iter().find(|arg| arg.contains('/') && !dir.join(arg).exists())
        {
            eprintln!("skipped {}: ~/{}/{missing} is missing", page.file, page.dir);
            continue;
        }
        let output = Command::new(env!("CARGO_BIN_EXE_hereticus"))
            .current_dir(&dir)
            .args(["--progress", "never", "--format", "html"])
            .args(page.args)
            .output()
            .expect("the tool runs");
        let printed = String::from_utf8(output.stdout).expect("the page is text");
        let (anchor, function) = page.fix;
        let fix = printed.find(&format!("id=\"{anchor}\"")).expect("the anchor of the fix");
        let summary = &printed[fix..fix + printed[fix..].find("</summary>").expect("a summary")];
        assert!(summary.contains(function), "{}: #{anchor} is not {function}", page.file);

        let path = root().join(page.file);
        // A release changes the version on each page and nothing else, so
        // the pages compare as though the same version made them.
        let committed = std::fs::read_to_string(&path).unwrap_or_default();
        let committed = match version_of(&committed) {
            Some(version) => committed.replace(version, env!("CARGO_PKG_VERSION")),
            None => committed,
        };
        if committed == printed {
            continue;
        }
        match update {
            true => {
                std::fs::write(&path, &printed).expect("the page is written");
                eprintln!("wrote {}", page.file);
            }
            false => stale.push(page.file),
        }
    }
    assert!(stale.is_empty(), "stale pages, run `just docs-output`: {stale:?}");
}

#[test]
fn the_version_of_a_page_is_read_from_its_generator() {
    let page = r#"<meta name="generator" content="hereticus 1.2.3">"#;
    assert_eq!(version_of(page), Some("1.2.3"));
    assert_eq!(version_of("<html>"), None);
}
