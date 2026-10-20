//! Completion gate (C5): before a job is accepted as done, verify the
//! deliverable contract mechanically (files exist, acceptance checks pass — run
//! in the VM by the driver) and run a self-review against fixed criteria
//! (adapted from Harness²'s selection criteria). Pure logic lives here; the VM
//! calls and the model call are done by the driver.

use serde::{Deserialize, Serialize};

/// The self-review a model must pass before declaring completion. Ordered so the
/// cheap, objective checks come first.
pub const SELF_REVIEW_CRITERIA: &str = "\
Review your own work against the request before declaring it done. For EACH point, \
answer and justify briefly:\n\
1. DELIVERY: does every requested deliverable exist?\n\
2. CONFORMANCE: does each match the requested shape (format, columns, names) with no extras?\n\
3. FIDELITY: is every claim supported by the sources? If a source is silent, say so — do not invent.\n\
4. CONSISTENCY: are the parts internally consistent?\n\
5. USABILITY: would the deliverable actually work / run / open?\n\
6. FINISH: no TODOs, placeholders, or stubs left.\n\
Length and polish are not merits. End with exactly one line: `VERDICT: PASS` or `VERDICT: FAIL`.";

/// One mechanical check the driver ran in the VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    pub what: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    pub checks: Vec<Check>,
    /// The model's self-review verdict, if a self-review was run.
    pub self_review_passed: Option<bool>,
}

impl GateReport {
    /// The gate passes when every mechanical check passed and the self-review,
    /// if run, said PASS.
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.passed) && self.self_review_passed != Some(false)
    }

    /// Message fed back to the model when the gate fails, listing what to fix.
    pub fn failure_feedback(&self) -> String {
        let mut lines = vec!["The work is not complete yet. Fix these before finishing:".to_string()];
        for check in self.checks.iter().filter(|c| !c.passed) {
            lines.push(format!("- {}: {}", check.what, check.detail));
        }
        if self.self_review_passed == Some(false) {
            lines.push("- Self-review returned FAIL; address the point(s) you raised.".into());
        }
        lines.join("\n")
    }
}

/// Parse a self-review reply's final verdict line.
pub fn parse_verdict(text: &str) -> Option<bool> {
    text.lines().rev().find_map(|line| {
        let line = line.trim().trim_start_matches('`').trim_end_matches('`').trim();
        let upper = line.to_ascii_uppercase();
        if upper.contains("VERDICT:") {
            if upper.contains("PASS") {
                Some(true)
            } else if upper.contains("FAIL") {
                Some(false)
            } else {
                None
            }
        } else {
            None
        }
    })
}

/// A plan is stalled when several steps pass with no item moving to done and no
/// new in-progress item. The driver tracks `steps_since_progress`.
pub fn plan_stalled(steps_since_progress: u64, threshold: u64) -> bool {
    steps_since_progress >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(passed: bool) -> Check {
        Check { what: "deliverable report.md exists".into(), passed, detail: "…".into() }
    }

    #[test]
    fn gate_passes_only_when_all_checks_and_review_pass() {
        assert!(GateReport { checks: vec![check(true)], self_review_passed: Some(true) }.passed());
        assert!(GateReport { checks: vec![check(true)], self_review_passed: None }.passed());
        assert!(!GateReport { checks: vec![check(false)], self_review_passed: Some(true) }.passed());
        assert!(!GateReport { checks: vec![check(true)], self_review_passed: Some(false) }.passed());
    }

    #[test]
    fn verdict_parsing() {
        assert_eq!(parse_verdict("blah\nVERDICT: PASS"), Some(true));
        assert_eq!(parse_verdict("`VERDICT: FAIL`"), Some(false));
        assert_eq!(parse_verdict("thinking... verdict: pass please"), Some(true));
        assert_eq!(parse_verdict("no verdict here"), None);
        // The last verdict line wins.
        assert_eq!(parse_verdict("VERDICT: FAIL\nactually VERDICT: PASS"), Some(true));
    }

    #[test]
    fn failure_feedback_lists_failures() {
        let report = GateReport { checks: vec![check(false), Check { what: "tests pass".into(), passed: true, detail: "ok".into() }], self_review_passed: Some(false) };
        let fb = report.failure_feedback();
        assert!(fb.contains("report.md exists"));
        assert!(!fb.contains("tests pass"));
        assert!(fb.contains("Self-review"));
    }
}
