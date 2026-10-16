//! Check the comparison against radiff2 of radare2 on the backport pairs.
//!
//! `just rivals` runs `radiff2 -A -C` on each stripped pair of
//! `fixtures/rivals/builds.txt`. On every build, this tool must report the
//! fix, rank it no lower than radiff2 does, and report no more functions
//! that the fix did not touch. `rivals/mod.rs` says how each report is
//! scored. The snapshot locks the scores of both tools.

mod rivals;

use rivals::Rival;

#[test]
fn hereticus_does_no_worse_than_radiff2() {
    let contests = rivals::contests(Rival::Radare2);
    let losses = rivals::losses(&contests);
    assert!(losses.is_empty(), "hereticus does worse than radiff2:\n{}", losses.join("\n"));
}

#[test]
fn the_scores_against_radiff2_are_locked() {
    let contests = rivals::contests(Rival::Radare2);
    insta::assert_snapshot!(rivals::table(Rival::Radare2, &contests));
}

mod reading_order {
    use super::rivals::{Order, reading_order};

    #[test]
    fn listed_rows_are_read_as_listed() {
        let scores = [Some(0.9), None, Some(0.1)];
        assert_eq!(reading_order(&scores, &[false, true, false], Order::AsListed), [0, 1, 2]);
    }

    #[test]
    fn sorted_rows_are_read_the_lowest_score_first() {
        let scores = [Some(0.9), Some(0.1), Some(0.5)];
        assert_eq!(reading_order(&scores, &[false; 3], Order::ByScore), [1, 2, 0]);
    }

    #[test]
    fn the_rows_of_the_fix_are_read_first_among_their_score() {
        let scores = [Some(0.5), Some(1.0), Some(1.0), Some(1.0)];
        let fix = [false, false, false, true];
        assert_eq!(reading_order(&scores, &fix, Order::ByScore), [0, 3, 1, 2]);
    }

    #[test]
    fn the_rows_of_the_fix_do_not_pass_a_lower_score() {
        let scores = [Some(0.2), Some(0.7)];
        assert_eq!(reading_order(&scores, &[false, true], Order::ByScore), [0, 1]);
    }

    #[test]
    fn rows_with_no_score_are_read_last() {
        let scores = [None, Some(1.0), None, Some(0.2)];
        let fix = [false, false, true, false];
        assert_eq!(reading_order(&scores, &fix, Order::ByScore), [3, 1, 2, 0]);
    }

    #[test]
    fn every_row_is_read_once_in_either_order() {
        let scores = [Some(0.1), None, Some(0.4), Some(0.4), None, Some(0.1), Some(0.4)];
        let fix = [true, false, false, true, true, false, false];
        for order in [Order::AsListed, Order::ByScore] {
            let mut read = reading_order(&scores, &fix, order);
            read.sort_unstable();
            assert_eq!(read, (0..scores.len()).collect::<Vec<_>>());
        }
    }
}
