//! Parsing a reviewer's answer and building the reviewer's task messages.

/// A parsed review verdict and its feedback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    /// Whether the reviewer accepted the deliverable.
    pub accept: bool,
    /// Concrete feedback for the worker.
    pub feedback: String,
}

fn is_decoration(character: char) -> bool {
    matches!(character, '*' | '`' | '-' | '#') || character.is_whitespace()
}

/// Parse the last valid `VERDICT:` line in a reviewer's answer.
///
/// The last line whose content (after trimming markdown decoration: `*`, `` ` ``,
/// `-`, `#`, whitespace) starts with `VERDICT:` decides. `ACCEPT`, `ACCEPTED`,
/// and `PASS` accept; `REJECT`, `REJECTED`, and `FAIL` reject; any other verdict
/// word makes the line ignored. Feedback is the text after that line, or the
/// text before it when there is nothing after. Returns `None` when no valid
/// verdict line exists.
pub fn parse_review(text: &str) -> Option<Review> {
    let lines: Vec<&str> = text.lines().collect();
    for (index, line) in lines.iter().enumerate().rev() {
        let content = line.trim_matches(is_decoration);
        let Some(prefix) = content.get(..8) else {
            continue;
        };
        if !prefix.eq_ignore_ascii_case("VERDICT:") {
            continue;
        }
        let rest = &content[8..];
        let verdict = rest
            .trim_start_matches(is_decoration)
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches(|character: char| !character.is_ascii_alphabetic())
            .to_ascii_uppercase();
        let accept = match verdict.as_str() {
            "ACCEPT" | "ACCEPTED" | "PASS" => true,
            "REJECT" | "REJECTED" | "FAIL" => false,
            _ => continue,
        };
        let after = lines[index + 1..].join("\n");
        let after = after.trim();
        let feedback = if after.is_empty() {
            lines[..index].join("\n").trim().to_string()
        } else {
            after.to_string()
        };
        return Some(Review { accept, feedback });
    }
    None
}

const INSTRUCTIONS: &str = "The workspace you are in already contains the worker's changes. Check them against every acceptance criterion: read the changed files and run whatever checks prove it (tests, the program itself). Do not fix anything yourself — any change you make is discarded. Be brief. End with exactly one line `VERDICT: ACCEPT` or `VERDICT: REJECT`, and after a REJECT give concrete, actionable feedback: what is wrong, where, and what would make it acceptable.";

/// Build the deterministic reviewer task for one ticket.
pub fn review_task(
    goal: &str,
    acceptance: &[String],
    worker_summary: &str,
    changed: &[String],
) -> String {
    let criteria = if acceptance.is_empty() {
        "(none given — judge against the goal)".to_string()
    } else {
        acceptance
            .iter()
            .map(|criterion| format!("- {criterion}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let changed = if changed.is_empty() {
        "(no files changed)".to_string()
    } else {
        changed.join("\n")
    };
    format!(
        "Goal:\n{goal}\n\nAcceptance criteria:\n{criteria}\n\nWorker summary:\n{worker_summary}\n\nChanged paths:\n{changed}\n\n{INSTRUCTIONS}"
    )
}

/// The follow-up message sent to the same worker after a rejection.
pub fn rework_message(feedback: &str, attempt: u32, max: u32) -> String {
    format!(
        "A reviewer rejected your work (attempt {attempt} of {max}). Fix it and report again.\n\nReviewer feedback:\n{feedback}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_plain_accept_verdict() {
        let review = parse_review("Looks good.\nVERDICT: ACCEPT").expect("review");
        assert!(review.accept);
        assert_eq!(review.feedback, "Looks good.");
    }

    #[test]
    fn rejection_uses_feedback_after_the_verdict() {
        let review = parse_review("VERDICT: REJECT\nMissing edge-case tests in src/lib.rs.")
            .expect("review");
        assert!(!review.accept);
        assert_eq!(review.feedback, "Missing edge-case tests in src/lib.rs.");
    }

    #[test]
    fn rejection_falls_back_to_feedback_before_the_verdict() {
        let review = parse_review("The build fails.\nVERDICT: REJECT").expect("review");
        assert!(!review.accept);
        assert_eq!(review.feedback, "The build fails.");
    }

    #[test]
    fn markdown_decorated_verdict_is_parsed() {
        let review = parse_review("**VERDICT:** REJECT\nFix the public API.").expect("review");
        assert!(!review.accept);
        assert_eq!(review.feedback, "Fix the public API.");
        assert!(parse_review("`VERDICT: ACCEPT`").expect("review").accept);
    }

    #[test]
    fn the_last_valid_verdict_wins() {
        let review = parse_review("VERDICT: ACCEPT\nActually no.\nVERDICT: REJECT\nTry again.")
            .expect("review");
        assert!(!review.accept);
        assert_eq!(review.feedback, "Try again.");
    }

    #[test]
    fn verdict_synonyms_are_recognized() {
        for line in ["VERDICT: ACCEPT", "VERDICT: ACCEPTED", "VERDICT: PASS"] {
            assert!(parse_review(line).expect(line).accept, "{line}");
        }
        for line in ["VERDICT: REJECT", "VERDICT: REJECTED", "VERDICT: FAIL"] {
            assert!(!parse_review(line).expect(line).accept, "{line}");
        }
    }

    #[test]
    fn missing_verdict_is_none() {
        assert_eq!(parse_review("The code looks fine to me."), None);
        assert_eq!(parse_review(""), None);
    }

    #[test]
    fn garbage_verdict_line_is_ignored() {
        let review = parse_review("VERDICT: ACCEPT\nVERDICT: MAYBE\nExtra prose.").expect("review");
        assert!(review.accept);
        assert_eq!(review.feedback, "VERDICT: MAYBE\nExtra prose.");
        assert_eq!(parse_review("VERDICT: MAYBE"), None);
    }

    #[test]
    fn review_task_contains_the_ticket_and_fixed_instructions() {
        let task = review_task(
            "Add a --verbose flag",
            &["parses --verbose".to_string(), "tests pass".to_string()],
            "Added the flag and ran the tests.",
            &["src/main.rs".to_string(), "tests/cli.rs".to_string()],
        );
        assert!(task.contains("Add a --verbose flag"));
        assert!(task.contains("- parses --verbose\n- tests pass"));
        assert!(task.contains("Added the flag and ran the tests."));
        assert!(task.contains("src/main.rs\ntests/cli.rs"));
        assert!(task.contains(INSTRUCTIONS));
        assert!(task.contains("`VERDICT: ACCEPT`"));
        assert_eq!(
            task,
            review_task(
                "Add a --verbose flag",
                &["parses --verbose".to_string(), "tests pass".to_string()],
                "Added the flag and ran the tests.",
                &["src/main.rs".to_string(), "tests/cli.rs".to_string()],
            )
        );
    }

    #[test]
    fn review_task_uses_placeholders_for_empty_lists() {
        let task = review_task("Do the thing", &[], "Nothing yet.", &[]);
        assert!(task.contains("(none given — judge against the goal)"));
        assert!(task.contains("(no files changed)"));
        assert!(task.contains(INSTRUCTIONS));
    }

    #[test]
    fn rework_message_has_the_exact_shape() {
        assert_eq!(
            rework_message("Add the missing test.", 2, 3),
            "A reviewer rejected your work (attempt 2 of 3). Fix it and report again.\n\nReviewer feedback:\nAdd the missing test."
        );
    }
}
