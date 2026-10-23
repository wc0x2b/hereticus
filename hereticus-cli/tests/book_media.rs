//! Keep the screenshots of the book and the demo of the README as new as the
//! screens they show.
//!
//! An image cannot be checked against the tool as text can, so this checks
//! what makes it instead. The snapshots lock the text of each screen and of
//! each report, and the tapes say what each image records. `just
//! book-media` records the images again and writes the hash of all of these
//! to `book/tapes/media.sha256`. Where a screen or a tape changed after, the
//! hash differs, and this fails until the images are recorded again.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Set by `just book-media`, after it records the images, to write the hash.
const UPDATE: &str = "BOOK_MEDIA_UPDATE";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn stamp() -> PathBuf {
    root().join("book/tapes/media.sha256")
}

/// The files the images depend on, in a fixed order.
fn inputs() -> Vec<PathBuf> {
    let in_dir = |dir: &str, extension: &str| -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(root().join(dir))
            .expect("a folder of inputs")
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|found| found == extension))
            .collect();
        files.sort();
        files
    };
    let mut files = in_dir("book/tapes", "tape");
    files.extend(in_dir("hereticus-cli/src/tui/snapshots", "snap"));
    files.extend(in_dir("hereticus-cli/tests/snapshots", "snap"));
    files
}

/// The part of a file that the images depend on.
///
/// The header of a snapshot names the line of its test, which moves with
/// every edit above it and changes no screen, so only the text after the
/// header counts.
fn content(path: &Path) -> String {
    let text = std::fs::read_to_string(path).expect("an input");
    if path.extension().is_some_and(|extension| extension == "snap") {
        let mut parts = text.splitn(3, "---\n");
        let _ = (parts.next(), parts.next());
        parts.next().unwrap_or_default().to_owned()
    } else {
        text
    }
}

/// The hash of every input, with its name, so a renamed one counts too.
fn hash() -> String {
    let mut hasher = Sha256::new();
    for path in inputs() {
        let name = path.strip_prefix(root()).unwrap_or(&path);
        hasher.update(name.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update(content(&path).as_bytes());
        hasher.update([0]);
    }
    hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn the_images_of_the_book_are_as_new_as_the_screens() {
    let hash = hash();
    if std::env::var_os(UPDATE).is_some() {
        std::fs::write(stamp(), format!("{hash}\n")).expect("the stamp writes");
        return;
    }
    let recorded = std::fs::read_to_string(stamp()).unwrap_or_default();
    assert_eq!(
        recorded.trim(),
        hash,
        "a screen, a report or a tape changed after the screenshots of the book and the \
         demo of the README were recorded. Run `just book-media`, look at the images, \
         and commit them with book/tapes/media.sha256"
    );
}

#[test]
fn a_header_of_a_snapshot_does_not_count() {
    let directory = std::env::temp_dir().join(format!("hereticus-media-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("a folder");
    let path = directory.join("a.snap");
    std::fs::write(&path, "---\nassertion_line: 10\n---\nscreen\n").expect("a file");
    let first = content(&path);
    std::fs::write(&path, "---\nassertion_line: 99\n---\nscreen\n").expect("a file");
    assert_eq!(content(&path), first);
    assert_eq!(first, "screen\n");
    std::fs::remove_dir_all(&directory).expect("clean up");
}
