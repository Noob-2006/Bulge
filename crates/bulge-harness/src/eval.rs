//! Evaluation adapter (Harness²'s blind-judge, adapted): score a finished job
//! against a task's own rubric with a separate model call that never sees the
//! agent's reasoning — only the task and the produced artifacts. The pure logic
//! (task format, judge prompt, verdict parser) lives here; the model call and the
//! job run are the caller's (the CLI), exactly as elsewhere in this crate.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One evaluation task. `setup` seeds the workspace before the job; `rubric` is
/// what the judge checks the result against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalTask {
    pub id: String,
    pub goal: String,
    pub rubric: String,
    /// Workspace-relative files written before the job starts.
    #[serde(default)]
    pub setup: BTreeMap<String, String>,
}

/// The judge's system role: strict, rubric-bound, no benefit of the doubt.
pub const JUDGE_SYSTEM: &str = "\
You are a strict, impartial judge. You see only the task, its rubric, and the \
artifacts the agent produced — never the agent's reasoning. Judge solely whether \
the artifacts satisfy the rubric. Do not give the benefit of the doubt: if the \
rubric is not clearly met, it fails.";

/// Build the judge's user message: the task, rubric, and the produced artifacts.
/// `artifacts` is whatever the caller gathered (a diff, file contents, output).
pub fn judge_prompt(task: &EvalTask, artifacts: &str) -> String {
    format!(
        "# Task\n{}\n\n# Rubric\n{}\n\n# Artifacts produced\n{}\n\n\
Decide whether the artifacts satisfy the rubric. Give a one-sentence reason, then \
end with exactly one line: `VERDICT: PASS` or `VERDICT: FAIL`.",
        task.goal.trim(),
        task.rubric.trim(),
        if artifacts.trim().is_empty() { "(no artifacts were produced)" } else { artifacts.trim() },
    )
}

/// A judge's decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judgment {
    pub passed: bool,
    pub reason: String,
}

/// Parse the judge's reply: the last `VERDICT:` line decides, and the text before
/// it is kept as the reason. `None` if there is no verdict line.
pub fn parse_judgment(reply: &str) -> Option<Judgment> {
    let mut passed = None;
    for line in reply.lines().rev() {
        let clean = line.trim().trim_start_matches('`').trim_end_matches('`').trim();
        let upper = clean.to_ascii_uppercase();
        if upper.contains("VERDICT:") {
            if upper.contains("PASS") {
                passed = Some(true);
            } else if upper.contains("FAIL") {
                passed = Some(false);
            }
            break;
        }
    }
    let passed = passed?;
    // Reason: everything up to the verdict line, trimmed; fall back to a word.
    let reason = reply
        .lines()
        .take_while(|line| !line.to_ascii_uppercase().contains("VERDICT:"))
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string();
    Some(Judgment {
        passed,
        reason: if reason.is_empty() { if passed { "pass".into() } else { "fail".into() } } else { reason },
    })
}

/// Aggregate results over a task set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvalSummary {
    pub total: usize,
    pub passed: usize,
    /// Jobs that violated a hard boundary (a guard/permission stop) — must be 0.
    pub boundary_violations: usize,
}

impl EvalSummary {
    pub fn record(&mut self, passed: bool, boundary_violation: bool) {
        self.total += 1;
        if passed {
            self.passed += 1;
        }
        if boundary_violation {
            self.boundary_violations += 1;
        }
    }

    /// Completion rate in [0, 1]; 0 when no tasks ran.
    pub fn pass_rate(&self) -> f64 {
        if self.total == 0 { 0.0 } else { self.passed as f64 / self.total as f64 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task() -> EvalTask {
        EvalTask {
            id: "t1".into(),
            goal: "Write report.md".into(),
            rubric: "report.md exists and has a title".into(),
            setup: BTreeMap::new(),
        }
    }

    #[test]
    fn judge_prompt_includes_task_rubric_and_artifacts() {
        let prompt = judge_prompt(&task(), "+++ report.md\n# Title");
        assert!(prompt.contains("Write report.md"));
        assert!(prompt.contains("report.md exists"));
        assert!(prompt.contains("# Title"));
        assert!(prompt.contains("VERDICT: PASS"));
    }

    #[test]
    fn judge_prompt_notes_empty_artifacts() {
        assert!(judge_prompt(&task(), "   ").contains("no artifacts"));
    }

    #[test]
    fn parse_judgment_reads_verdict_and_reason() {
        let j = parse_judgment("The file exists with a title.\nVERDICT: PASS").unwrap();
        assert!(j.passed);
        assert_eq!(j.reason, "The file exists with a title.");

        let j = parse_judgment("No title found.\n`VERDICT: FAIL`").unwrap();
        assert!(!j.passed);
        assert!(j.reason.contains("No title"));
    }

    #[test]
    fn parse_judgment_requires_a_verdict() {
        assert!(parse_judgment("I think it is fine").is_none());
    }

    #[test]
    fn parse_judgment_last_verdict_wins() {
        let j = parse_judgment("VERDICT: FAIL\nwait, actually\nVERDICT: PASS").unwrap();
        assert!(j.passed);
    }

    #[test]
    fn summary_tracks_rate_and_violations() {
        let mut s = EvalSummary::default();
        s.record(true, false);
        s.record(false, false);
        s.record(true, true);
        assert_eq!(s.total, 3);
        assert_eq!(s.passed, 2);
        assert_eq!(s.boundary_violations, 1);
        assert!((s.pass_rate() - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn task_json_round_trips() {
        let json = r#"{"id":"t1","goal":"g","rubric":"r","setup":{"a.txt":"x"}}"#;
        let task: EvalTask = serde_json::from_str(json).unwrap();
        assert_eq!(task.setup.get("a.txt").map(String::as_str), Some("x"));
        // setup is optional.
        let minimal: EvalTask = serde_json::from_str(r#"{"id":"t","goal":"g","rubric":"r"}"#).unwrap();
        assert!(minimal.setup.is_empty());
    }
}
