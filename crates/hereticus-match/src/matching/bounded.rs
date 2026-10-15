//! Calls that a fix turns into their bounded form.
//!
//! A common fix of a memory or parsing bug keeps the call where it was and
//! swaps the callee for one that takes a limit: `strcmp` to `strncmp`,
//! `sprintf` to `snprintf`. The fix of CVE-2026-30874 in `procd` is such a
//! swap, and adds only the instruction that loads the limit, so a count of
//! the instructions added ranks it low.
//!
//! See RESEARCH.md, "Calls swapped for their bounded form".

/// Each function of the C library, and the functions that do its work
/// with a limit.
const BOUNDED_FORMS: &[(&str, &[&str])] = &[
    ("strcmp", &["strncmp"]),
    ("strcasecmp", &["strncasecmp"]),
    ("strcpy", &["strncpy", "strlcpy", "stpncpy"]),
    ("stpcpy", &["stpncpy", "strlcpy"]),
    ("strcat", &["strncat", "strlcat"]),
    ("strlen", &["strnlen"]),
    ("strdup", &["strndup"]),
    ("sprintf", &["snprintf"]),
    ("vsprintf", &["vsnprintf"]),
    ("gets", &["fgets"]),
    ("wcscpy", &["wcsncpy", "wcslcpy"]),
    ("wcscat", &["wcsncat", "wcslcat"]),
    ("wcscmp", &["wcsncmp"]),
    ("wcslen", &["wcsnlen"]),
    // The checked forms that `_FORTIFY_SOURCE` calls in their place.
    ("strcpy_chk", &["strncpy_chk", "strlcpy_chk", "stpncpy_chk"]),
    ("stpcpy_chk", &["stpncpy_chk"]),
    ("strcat_chk", &["strncat_chk", "strlcat_chk"]),
    ("sprintf_chk", &["snprintf_chk"]),
    ("vsprintf_chk", &["vsnprintf_chk"]),
];

/// Report whether a call of `before` that became a call of `after` swapped
/// a function for its bounded form, as `strcmp` for `strncmp`.
///
/// The names are as the linker gives them: a version, as `@GLIBC_2.4`, or
/// a stub, as `@plt`, is dropped, and so are the leading underscores that
/// Mach-O and the checked forms add.
pub(super) fn is_bounded_swap(before: &str, after: &str) -> bool {
    let (before, after) = (plain_name(before), plain_name(after));
    BOUNDED_FORMS.iter().any(|&(plain, bounded)| plain == before && bounded.contains(&after))
}

/// `name` without its version or stub, and without leading underscores.
fn plain_name(name: &str) -> &str {
    let name = name.split_once('@').map_or(name, |(name, _)| name);
    name.trim_start_matches('_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_swap_for_the_bounded_form_counts() {
        assert!(is_bounded_swap("strcmp", "strncmp"));
        assert!(is_bounded_swap("strcmp@plt", "strncmp@plt"));
        assert!(is_bounded_swap("_sprintf", "_snprintf"));
        assert!(is_bounded_swap("__strcpy_chk@GLIBC_2.3.4", "__strncpy_chk@GLIBC_2.3.4"));
        assert!(is_bounded_swap("strcpy", "strlcpy"));
    }

    #[test]
    fn other_swaps_do_not_count() {
        assert!(!is_bounded_swap("strncmp", "strcmp"), "the bound went");
        assert!(!is_bounded_swap("strcmp", "strcmp"));
        assert!(!is_bounded_swap("strcmp", "memcmp"));
        assert!(!is_bounded_swap("my_strcmp", "my_strncmp"));
        assert!(!is_bounded_swap("", "strncmp"));
    }
}
