//! Edit → verify-before-finish loop (Hermes `verify_hooks.py` / `verification_stop.py`).
//! Per turn the kernel records which files were changed; when the model tries to finish
//! it may be nudged (bounded by `max_verify_nudges`) to verify its work first.

use std::collections::BTreeSet;

/// Built-in nudge appended when the model stops after editing code.
pub const NUDGE: &str = "You changed files this turn but have not verified the result. Before finishing, run the relevant build, tests or a quick check, and fix anything that fails.";
/// Extra clean-up guidance (`verify_guidance = true`).
pub const GUIDANCE: &str = "Also remove debugging leftovers, temporary files and unused code you introduced.";

/// Tools whose successful calls count as edits.
const EDIT_TOOLS: &[&str] = &["write", "edit", "patch", "apply_patch", "multi_edit"];

/// Per-session, per-turn verify-loop state (kept in `CtxState::verify`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TurnState {
    /// Paths changed this turn.
    pub changed: BTreeSet<String>,
    /// Nudges / pre_verify continues already issued this turn.
    pub nudges: u32,
    /// A verification-looking command ran after the last edit.
    pub verified: bool,
}

impl TurnState {
    /// A new turn starts.
    pub fn reset(&mut self) {
        *self = TurnState::default();
    }

    /// Record a settled tool call.
    pub fn observe(&mut self, tool: &str, input: &serde_json::Value, is_error: bool) {
        if is_error {
            return;
        }
        if EDIT_TOOLS.contains(&tool) {
            let mut paths = Vec::new();
            if let Some(p) = input.get("path").and_then(|v| v.as_str()) {
                paths.push(p.to_string());
            }
            if let Some(edits) = input.get("edits").and_then(|v| v.as_array()) {
                paths.extend(edits.iter().filter_map(|e| e.get("path").and_then(|v| v.as_str())).map(String::from));
            }
            if paths.is_empty() {
                paths.push(format!("<{tool}>"));
            }
            self.changed.extend(paths);
            self.verified = false;
        } else if (tool == "shell" || tool == "run") && !self.changed.is_empty() {
            let cmd = input.get("command").or_else(|| input.get("script")).and_then(|v| v.as_str()).unwrap_or("");
            if looks_like_verification(cmd) {
                self.verified = true;
            }
        }
    }

    /// Whether to nudge now. `budget` is `max_verify_nudges`.
    pub fn should_nudge(&self, budget: u32) -> bool {
        !self.changed.is_empty() && !self.verified && self.nudges < budget
    }

    /// Whether a pre_verify gate may still continue the turn.
    pub fn can_continue(&self, budget: u32) -> bool {
        !self.changed.is_empty() && self.nudges < budget
    }

    /// Record a nudge and return the attempt number (1-based).
    pub fn nudged(&mut self) -> u32 {
        self.nudges += 1;
        self.nudges
    }

    pub fn changed_paths(&self) -> Vec<String> {
        self.changed.iter().cloned().collect()
    }
}

/// `verify_on_stop`: off | on | auto (auto = not on messaging channels).
pub fn enabled(mode: &str, messaging_channel: bool) -> bool {
    match mode {
        "on" | "true" => true,
        "auto" => !messaging_channel,
        _ => false,
    }
}

/// The nudge text, with guidance appended when requested.
pub fn nudge_text(guidance: bool) -> String {
    if guidance { format!("{NUDGE} {GUIDANCE}") } else { NUDGE.to_string() }
}

/// Heuristic: does a shell command look like a build / test / lint run?
pub fn looks_like_verification(cmd: &str) -> bool {
    let c = cmd.to_lowercase();
    const MARKERS: &[&str] = &[
        "cargo test", "cargo check", "cargo build", "cargo clippy", "pytest", "npm test", "npm run test", "npm run build", "pnpm test", "yarn test", "go test", "go build", "go vet", "make", "tsc", "mypy", "ruff", "eslint", "unittest", "jest", "vitest", "gradle", "mvn ", "ctest",
    ];
    MARKERS.iter().any(|m| c.contains(m))
}

/// Parse a `pre_verify` hook's stdout (Hermes protocol): `{"action":"continue","message":..}`
/// or `{"decision":"block","reason":..}` keep the turn going with that message.
pub fn parse_hook_output(stdout: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).ok()?;
    let msg = if v.get("action").and_then(|a| a.as_str()) == Some("continue") {
        v.get("message")
    } else if v.get("decision").and_then(|a| a.as_str()) == Some("block") {
        v.get("reason")
    } else {
        None
    }?;
    msg.as_str().map(str::trim).filter(|s| !s.is_empty()).map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn edits_then_verification() {
        let mut t = TurnState::default();
        assert!(!t.should_nudge(3));
        t.observe("shell", &json!({"command": "cargo test"}), false);
        assert!(!t.verified, "verification before any edit does not count");
        t.observe("edit", &json!({"path": "src/a.rs"}), false);
        t.observe("write", &json!({"path": "src/b.rs"}), true);
        assert_eq!(t.changed_paths(), vec!["src/a.rs"]);
        assert!(t.should_nudge(3));
        assert_eq!(t.nudged(), 1);
        t.observe("shell", &json!({"command": "CARGO_INCREMENTAL=0 cargo check"}), false);
        assert!(t.verified && !t.should_nudge(3));
        assert!(t.can_continue(3));
        t.observe("patch", &json!({"edits": [{"path": "x"}, {"path": "y"}]}), false);
        assert!(!t.verified && t.changed.contains("y"));
        assert!(!t.should_nudge(1));
        t.reset();
        assert_eq!(t, TurnState::default());
    }

    #[test]
    fn modes_text_and_hook_protocol() {
        assert!(enabled("on", true) && enabled("auto", false));
        assert!(!enabled("auto", true) && !enabled("off", false));
        assert!(nudge_text(true).ends_with(GUIDANCE));
        assert_eq!(nudge_text(false), NUDGE);
        assert_eq!(parse_hook_output(r#"{"action":"continue","message":"run tests"}"#).as_deref(), Some("run tests"));
        assert_eq!(parse_hook_output(r#"{"decision":"block","reason":"lint"}"#).as_deref(), Some("lint"));
        assert_eq!(parse_hook_output(r#"{"decision":"approve"}"#), None);
        assert_eq!(parse_hook_output("not json"), None);
    }
}
