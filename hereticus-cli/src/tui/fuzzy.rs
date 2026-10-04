//! Match a typed filter to a name, as `heretek` searches its symbols: the
//! letters of the filter must come in the name in order, with any letters
//! between them, in any case.

/// The positions, in characters, of the letters of `name` that match the
/// letters of `filter`, or `None` where the name does not hold them in
/// order. Each letter matches the first one it can, so `lfil` matches the
/// `l` and `f` of `luaZ_fill` and then `il`.
pub fn positions(filter: &str, name: &str) -> Option<Vec<usize>> {
    let mut letters = name.chars().enumerate();
    filter
        .chars()
        .map(|wanted| {
            letters
                .find(|(_, letter)| letter.to_lowercase().eq(wanted.to_lowercase()))
                .map(|(at, _)| at)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_letters_of_a_filter_match_in_order() {
        assert_eq!(positions("lfil", "luaZ_fill"), Some(vec![0, 5, 6, 7]));
        assert_eq!(positions("ZF", "luaZ_fill"), Some(vec![3, 5]), "in any case");
        assert_eq!(positions("", "main"), Some(vec![]), "an empty filter matches all");
        assert_eq!(positions("fl", "lf"), None, "out of order");
        assert_eq!(positions("mm", "main"), None, "a letter once only");
        assert_eq!(positions("x", ""), None);
    }

    #[test]
    fn any_filter_matches_at_letters_it_names() {
        bolero::check!().with_type::<(String, String)>().for_each(|(filter, name)| {
            let letters: Vec<char> = name.chars().collect();
            if let Some(found) = positions(filter, name) {
                assert_eq!(found.len(), filter.chars().count());
                assert!(found.windows(2).all(|pair| pair[0] < pair[1]), "in order");
                for (at, wanted) in found.iter().zip(filter.chars()) {
                    assert!(letters[*at].to_lowercase().eq(wanted.to_lowercase()));
                }
            }
            // A name always holds itself, and any part of itself.
            assert!(positions(name, name).is_some());
            let half: String = letters.iter().skip(letters.len() / 2).collect();
            assert!(positions(&half, name).is_some());
        });
    }
}
