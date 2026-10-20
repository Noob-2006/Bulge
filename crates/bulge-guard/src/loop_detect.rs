//! Runaway-loop detection over recent tool outcomes.
//! MARK: M17 — transcribed by dsh; see marks/M17-loop-detect.md.
//!
//! The driver records each completed call here; before the next call it asks
//! for a verdict. Detectors look at a bounded window of recent calls, each
//! reduced to a stable signature (tool + canonical args) and an outcome hash
//! with volatile fields stripped, so identical no-progress repeats are caught.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};

use serde_json::Value;

/// One finished tool call fed into the detector.
#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    pub tool: String,
    /// Canonical arguments (object key order does not matter).
    pub arguments: Value,
    /// True when the call succeeded and produced an observable change.
    pub ok: bool,
    /// Structured result (for outcome hashing); volatile fields are stripped.
    pub result: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detector {
    GenericRepeat,
    ArgumentChurn,
    UnknownToolRepeat,
    NoProgressPoll,
    PingPong,
    GlobalCircuitBreaker,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub level: Level,
    pub detector: Detector,
    pub count: usize,
    /// A reminder to inject for the model (what is stuck, what to do instead).
    pub message: String,
}

/// Window of recent calls (openclaw keeps 30).
pub const HISTORY_SIZE: usize = 30;
/// A warning fires at this streak; critical doubles it (except the breaker).
pub const WARNING_THRESHOLD: usize = 10;
pub const CRITICAL_THRESHOLD: usize = 20;
pub const UNKNOWN_TOOL_THRESHOLD: usize = 10;
pub const GLOBAL_CIRCUIT_BREAKER_THRESHOLD: usize = 30;
/// bulge addition: the loop stops after this many consecutive identical errors.
pub const IDENTICAL_ERROR_STOP: usize = 3;

/// One recorded call, reduced to facts the detectors need.
#[derive(Debug, Clone)]
struct Record {
    tool: String,
    /// Hash of the tool name plus canonical arguments (the call signature).
    signature: u64,
    /// Hash of the result with volatile fields stripped.
    outcome_hash: u64,
    /// The call errored, changed nothing, or repeated an earlier outcome.
    no_progress: bool,
    /// The call itself failed (as opposed to merely not changing anything).
    is_error: bool,
}

#[derive(Debug, Default)]
pub struct LoopDetector {
    history: VecDeque<Record>,
}

/// Result of the argument-churn scan.
struct ChurnStreak {
    count: usize,
    variants: usize,
}

/// Result of the ping-pong scan.
struct PingPongStreak {
    count: usize,
    no_progress_evidence: bool,
}

impl LoopDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verdict for the call *about to run*, given history so far. `unknown_tool`
    /// is true when `tool` is not a registered tool name. Returns `None` when
    /// nothing is stuck.
    pub fn check(&self, tool: &str, arguments: &Value, unknown_tool: bool) -> Option<Verdict> {
        let signature = call_signature(tool, arguments);

        if unknown_tool {
            let count = self.unknown_tool_streak(tool);
            if count >= UNKNOWN_TOOL_THRESHOLD {
                return Some(Verdict {
                    level: Level::Critical,
                    detector: Detector::UnknownToolRepeat,
                    count,
                    message: format!(
                        "CRITICAL: attempted unknown tool `{tool}` {count} times in a row. \
                         Stop retrying a tool that does not exist; change to a bounded \
                         alternative with an explicit stop condition, or report the task as failed."
                    ),
                });
            }
        }

        let no_progress_count = self.no_progress_streak(tool, signature);

        if no_progress_count >= GLOBAL_CIRCUIT_BREAKER_THRESHOLD {
            return Some(Verdict {
                level: Level::Critical,
                detector: Detector::GlobalCircuitBreaker,
                count: no_progress_count,
                message: format!(
                    "CRITICAL: `{tool}` repeated the same no-progress outcome \
                     {no_progress_count} times in a row; the runaway-loop limit has been \
                     reached. Change to a bounded alternative with an explicit stop \
                     condition, or report the task as failed."
                ),
            });
        }

        if no_progress_count >= WARNING_THRESHOLD {
            let critical = no_progress_count >= CRITICAL_THRESHOLD;
            let level = if critical {
                Level::Critical
            } else {
                Level::Warning
            };
            let prefix = if critical { "CRITICAL" } else { "WARNING" };
            return Some(Verdict {
                level,
                detector: Detector::NoProgressPoll,
                count: no_progress_count,
                message: format!(
                    "{prefix}: `{tool}` produced the same no-progress outcome \
                     {no_progress_count} times in a row. Stop retrying; change to a \
                     bounded alternative with an explicit stop condition, or report \
                     the task as failed."
                ),
            });
        }

        if let Some(ping_pong) = self.ping_pong_streak()
            && ping_pong.count >= WARNING_THRESHOLD
        {
            let critical =
                ping_pong.count >= CRITICAL_THRESHOLD && ping_pong.no_progress_evidence;
            let level = if critical {
                Level::Critical
            } else {
                Level::Warning
            };
            let prefix = if critical { "CRITICAL" } else { "WARNING" };
            let evidence = if critical {
                " with no progress"
            } else {
                ""
            };
            return Some(Verdict {
                level,
                detector: Detector::PingPong,
                count: ping_pong.count,
                message: format!(
                    "{prefix}: `{tool}` is alternating between two tool-call signatures\
                     {evidence} ({} consecutive calls). Stop retrying; change to a \
                     bounded alternative with an explicit stop condition, or report \
                     the task as failed.",
                    ping_pong.count,
                ),
            });
        }

        if let Some(churn) = self.argument_churn_streak(tool)
            && churn.count >= WARNING_THRESHOLD
        {
            return Some(Verdict {
                level: Level::Warning,
                detector: Detector::ArgumentChurn,
                count: churn.count,
                message: format!(
                    "WARNING: `{tool}` produced the same no-progress outcome across \
                     {} different argument patterns for {} calls in a row. Change to \
                     a bounded alternative with an explicit stop condition, or report \
                     the task as failed.",
                    churn.variants, churn.count,
                ),
            });
        }

        let error_count = self.identical_error_streak(tool, signature);
        if error_count >= IDENTICAL_ERROR_STOP {
            return Some(Verdict {
                level: Level::Critical,
                detector: Detector::GenericRepeat,
                count: error_count,
                message: format!(
                    "CRITICAL: `{tool}` failed with the same error {error_count} times in \
                     a row. Stop retrying; change to a bounded alternative with an \
                     explicit stop condition, or report the task as failed."
                ),
            });
        }

        None
    }

    /// Record a finished call (call this after each tool completes).
    pub fn observe(&mut self, observation: Observation) {
        let signature = call_signature(&observation.tool, &observation.arguments);
        let outcome_hash = outcome_hash(&observation.result);
        let is_error = !observation.ok || result_is_error(&observation.result);
        let explicit_no_progress = is_error || result_is_no_change(&observation.result);
        // An identical outcome seen before is also no progress: the call produced
        // exactly what an earlier call already produced.
        let repeated_outcome = self
            .history
            .iter()
            .any(|record| record.tool == observation.tool && record.outcome_hash == outcome_hash);

        self.history.push_back(Record {
            tool: observation.tool,
            signature,
            outcome_hash,
            no_progress: explicit_no_progress || repeated_outcome,
            is_error,
        });

        while self.history.len() > HISTORY_SIZE {
            self.history.pop_front();
        }
    }

    /// Consecutive completed calls with the same signature and outcome. Returns
    /// zero once the most recent call made progress (a changed outcome).
    fn no_progress_streak(&self, tool: &str, signature: u64) -> usize {
        let mut latest_outcome = None;
        let mut count = 0;
        let mut latest_no_progress = false;

        for record in self.history.iter().rev() {
            if record.tool != tool || record.signature != signature {
                break;
            }
            match latest_outcome {
                None => {
                    latest_outcome = Some(record.outcome_hash);
                    latest_no_progress = record.no_progress;
                }
                Some(hash) if hash == record.outcome_hash => {}
                Some(_) => break,
            }
            count += 1;
        }

        if latest_no_progress { count } else { 0 }
    }

    /// Consecutive prior calls to `tool`; the check is for the next call to the
    /// same unknown tool, so the streak is the completed tail.
    fn unknown_tool_streak(&self, tool: &str) -> usize {
        let mut count = 0;
        for record in self.history.iter().rev() {
            if record.tool != tool {
                break;
            }
            count += 1;
        }
        count
    }

    /// A tail of the same tool that keeps the same outcome while its arguments
    /// change. The count includes the first call that established the outcome.
    fn argument_churn_streak(&self, tool: &str) -> Option<ChurnStreak> {
        let mut latest_outcome = None;
        let mut latest_no_progress = false;
        let mut count = 0;
        let mut variants = 0;
        let mut seen_signatures = Vec::new();

        for record in self.history.iter().rev() {
            if record.tool != tool {
                break;
            }
            match latest_outcome {
                None => {
                    latest_outcome = Some(record.outcome_hash);
                    latest_no_progress = record.no_progress;
                }
                Some(hash) if hash == record.outcome_hash => {}
                Some(_) => break,
            }
            count += 1;
            if !seen_signatures.contains(&record.signature) {
                seen_signatures.push(record.signature);
                variants += 1;
            }
        }

        if latest_no_progress && variants >= 2 {
            Some(ChurnStreak { count, variants })
        } else {
            None
        }
    }

    /// A stable A,B,A,B tail over the recorded calls.
    fn ping_pong_streak(&self) -> Option<PingPongStreak> {
        let last = self.history.back()?;
        let other = self
            .history
            .iter()
            .rev()
            .find(|record| record.signature != last.signature)?;

        let mut alternating_tail = 0;
        for record in self.history.iter().rev() {
            let expected = if alternating_tail % 2 == 0 {
                last.signature
            } else {
                other.signature
            };
            if record.signature != expected {
                break;
            }
            alternating_tail += 1;
        }
        if alternating_tail < 2 {
            return None;
        }

        let mut outcomes: HashMap<u64, u64> = HashMap::new();
        let mut stable = true;
        let tail_start = self.history.len() - alternating_tail;
        for record in self.history.iter().skip(tail_start) {
            match outcomes.get(&record.signature) {
                Some(hash) if *hash != record.outcome_hash => {
                    stable = false;
                    break;
                }
                Some(_) => {}
                None => {
                    outcomes.insert(record.signature, record.outcome_hash);
                }
            }
        }

        Some(PingPongStreak {
            count: alternating_tail,
            no_progress_evidence: stable && outcomes.len() >= 2,
        })
    }

    /// Consecutive failures of the exact same call with the exact same outcome.
    fn identical_error_streak(&self, tool: &str, signature: u64) -> usize {
        let mut latest_outcome = None;
        let mut count = 0;

        for record in self.history.iter().rev() {
            if record.tool != tool || record.signature != signature || !record.is_error {
                break;
            }
            match latest_outcome {
                None => latest_outcome = Some(record.outcome_hash),
                Some(hash) if hash == record.outcome_hash => {}
                Some(_) => break,
            }
            count += 1;
        }

        count
    }
}

/// Hash of the tool name and a canonical rendering of its arguments.
fn call_signature(tool: &str, arguments: &Value) -> u64 {
    let mut hasher = DefaultHasher::new();
    tool.hash(&mut hasher);
    canonical_json(arguments).hash(&mut hasher);
    hasher.finish()
}

/// Hash of a result after common per-call volatile fields are removed.
fn outcome_hash(result: &Value) -> u64 {
    let mut hasher = DefaultHasher::new();
    canonical_json(&strip_volatile(result)).hash(&mut hasher);
    hasher.finish()
}

/// Keys that describe when/how a call ran rather than what it produced.
fn is_volatile_key(key: &str, value: &Value) -> bool {
    match key {
        "timestamp"
        | "time"
        | "duration"
        | "durationMs"
        | "duration_ms"
        | "elapsed"
        | "elapsedMs"
        | "elapsed_ms"
        | "pid"
        | "requestId"
        | "request_id"
        | "startedAt"
        | "started_at"
        | "finishedAt"
        | "finished_at"
        | "at_ms"
        | "atMs" => true,
        "id" => looks_random(value),
        _ => false,
    }
}

/// Heuristic for per-call ids such as UUIDs or hex tokens. A plain meaningful
/// `id` (for example `"report"`) is kept so that it can still prove progress.
fn looks_random(value: &Value) -> bool {
    let Value::String(text) = value else {
        return false;
    };
    let has_digit = text.chars().any(|c| c.is_ascii_digit());
    let has_alpha = text.chars().any(|c| c.is_ascii_alphabetic());
    let all_hex = text.chars().all(|c| c.is_ascii_hexdigit());
    text.len() >= 8 && ((has_digit && has_alpha) || all_hex)
}

/// Recursively drop volatile keys from a result value.
fn strip_volatile(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(strip_volatile).collect()),
        Value::Object(map) => {
            let mut stripped = serde_json::Map::with_capacity(map.len());
            for (key, nested) in map {
                if is_volatile_key(key, nested) {
                    continue;
                }
                stripped.insert(key.clone(), strip_volatile(nested));
            }
            Value::Object(stripped)
        }
        _ => value.clone(),
    }
}

/// Deterministic JSON: object keys sorted, array order preserved, strings
/// escaped by serde_json.
fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(boolean) => boolean.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_owned()),
        Value::Array(items) => {
            let mut out = String::from("[");
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&canonical_json(item));
            }
            out.push(']');
            out
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = String::from("{");
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_owned()));
                out.push(':');
                if let Some(nested) = map.get(*key) {
                    out.push_str(&canonical_json(nested));
                }
            }
            out.push('}');
            out
        }
    }
}

/// True when the structured result explicitly says nothing changed.
fn result_is_no_change(result: &Value) -> bool {
    let Some(object) = result.as_object() else {
        return false;
    };

    if object.get("changed").and_then(Value::as_bool) == Some(false) {
        return true;
    }
    if object.get("no_progress").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    if object.get("noProgress").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    if object.get("status").and_then(Value::as_str) == Some("unchanged") {
        return true;
    }

    if let Some(details) = object.get("details").and_then(Value::as_object) {
        if details.get("changed").and_then(Value::as_bool) == Some(false) {
            return true;
        }
        if details.get("noProgress").and_then(Value::as_bool) == Some(true) {
            return true;
        }
        if details.get("status").and_then(Value::as_str) == Some("unchanged") {
            return true;
        }
    }

    false
}

/// True when the structured result carries its own error marker.
fn result_is_error(result: &Value) -> bool {
    let Some(object) = result.as_object() else {
        return false;
    };

    if object.get("is_error").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    if object.get("isError").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    if object.get("error").is_some_and(|error| !error.is_null()) {
        return true;
    }
    matches!(
        object.get("status").and_then(Value::as_str),
        Some("error" | "failed")
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn observe(
        detector: &mut LoopDetector,
        tool: &str,
        arguments: Value,
        ok: bool,
        result: Value,
    ) {
        detector.observe(Observation {
            tool: tool.to_owned(),
            arguments,
            ok,
            result,
        });
    }

    fn error_observation(detector: &mut LoopDetector, tool: &str, arguments: Value, error: Value) {
        observe(detector, tool, arguments, false, error);
    }

    #[test]
    fn identical_errors_stop_at_three() {
        let mut detector = LoopDetector::new();
        let arguments = json!({"command": "cargo build"});

        for _ in 0..IDENTICAL_ERROR_STOP {
            error_observation(
                &mut detector,
                "shell",
                arguments.clone(),
                json!({"error": "compilation failed"}),
            );
        }

        let verdict = detector
            .check("shell", &arguments, false)
            .expect("identical errors should be detected");
        assert_eq!(verdict.level, Level::Critical);
        assert_eq!(verdict.detector, Detector::GenericRepeat);
        assert_eq!(verdict.count, IDENTICAL_ERROR_STOP);
        assert!(verdict.message.contains("shell"));
        assert!(verdict.message.contains("same error"));
    }

    #[test]
    fn no_progress_poll_warns_at_ten_and_blocks_at_twenty() {
        let arguments = json!({"path": "state.json"});

        let mut warning_detector = LoopDetector::new();
        for _ in 0..WARNING_THRESHOLD {
            observe(
                &mut warning_detector,
                "read",
                arguments.clone(),
                true,
                json!({"changed": false}),
            );
        }
        let warning = warning_detector
            .check("read", &arguments, false)
            .expect("ten no-progress calls should warn");
        assert_eq!(warning.level, Level::Warning);
        assert_eq!(warning.detector, Detector::NoProgressPoll);
        assert_eq!(warning.count, WARNING_THRESHOLD);

        let mut critical_detector = LoopDetector::new();
        for _ in 0..CRITICAL_THRESHOLD {
            observe(
                &mut critical_detector,
                "read",
                arguments.clone(),
                true,
                json!({"changed": false}),
            );
        }
        let critical = critical_detector
            .check("read", &arguments, false)
            .expect("twenty no-progress calls should be critical");
        assert_eq!(critical.level, Level::Critical);
        assert_eq!(critical.detector, Detector::NoProgressPoll);
        assert_eq!(critical.count, CRITICAL_THRESHOLD);
    }

    #[test]
    fn global_breaker_fires_at_the_history_limit() {
        let mut detector = LoopDetector::new();
        let arguments = json!({"path": "state.json"});

        for _ in 0..(HISTORY_SIZE + 5) {
            error_observation(
                &mut detector,
                "read",
                arguments.clone(),
                json!({"error": "permission denied"}),
            );
        }

        let verdict = detector
            .check("read", &arguments, false)
            .expect("the breaker should fire");
        assert_eq!(verdict.level, Level::Critical);
        assert_eq!(verdict.detector, Detector::GlobalCircuitBreaker);
        assert_eq!(verdict.count, HISTORY_SIZE);
    }

    #[test]
    fn unknown_tool_repeats_are_critical() {
        let mut detector = LoopDetector::new();
        let arguments = json!({});

        for _ in 0..UNKNOWN_TOOL_THRESHOLD {
            error_observation(
                &mut detector,
                "missing_tool",
                arguments.clone(),
                json!({"error": "unknown tool: missing_tool"}),
            );
        }

        let verdict = detector
            .check("missing_tool", &arguments, true)
            .expect("repeated unknown tools should be detected");
        assert_eq!(verdict.level, Level::Critical);
        assert_eq!(verdict.detector, Detector::UnknownToolRepeat);
        assert_eq!(verdict.count, UNKNOWN_TOOL_THRESHOLD);
        assert!(verdict.message.contains("missing_tool"));
    }

    #[test]
    fn changing_arguments_with_a_stable_outcome_is_churn() {
        let mut detector = LoopDetector::new();

        for index in 0..WARNING_THRESHOLD {
            error_observation(
                &mut detector,
                "search",
                json!({"query": format!("attempt-{index}")}),
                json!({"error": "no results"}),
            );
        }

        let verdict = detector
            .check("search", &json!({"query": "another attempt"}), false)
            .expect("argument churn should warn");
        assert_eq!(verdict.level, Level::Warning);
        assert_eq!(verdict.detector, Detector::ArgumentChurn);
        assert_eq!(verdict.count, WARNING_THRESHOLD);
        assert!(verdict.message.contains("argument patterns"));
    }

    #[test]
    fn alternating_calls_are_ping_pong() {
        let mut detector = LoopDetector::new();
        let first = json!({"url": "https://example.test/a"});
        let second = json!({"url": "https://example.test/b"});

        for index in 0..WARNING_THRESHOLD {
            let arguments = if index % 2 == 0 {
                first.clone()
            } else {
                second.clone()
            };
            error_observation(
                &mut detector,
                "fetch",
                arguments,
                json!({"error": "timed out"}),
            );
        }

        let verdict = detector
            .check("fetch", &first, false)
            .expect("alternating calls should warn");
        assert_eq!(verdict.level, Level::Warning);
        assert_eq!(verdict.detector, Detector::PingPong);
        assert_eq!(verdict.count, WARNING_THRESHOLD);
        assert!(verdict.message.contains("alternating"));
    }

    #[test]
    fn alternating_calls_with_stable_outcomes_become_critical() {
        let mut detector = LoopDetector::new();
        let first = json!({"url": "https://example.test/a"});
        let second = json!({"url": "https://example.test/b"});

        for index in 0..CRITICAL_THRESHOLD {
            let arguments = if index % 2 == 0 {
                first.clone()
            } else {
                second.clone()
            };
            error_observation(
                &mut detector,
                "fetch",
                arguments,
                json!({"error": "timed out"}),
            );
        }

        let verdict = detector
            .check("fetch", &first, false)
            .expect("long alternating calls should be critical");
        assert_eq!(verdict.level, Level::Critical);
        assert_eq!(verdict.detector, Detector::PingPong);
        assert_eq!(verdict.count, CRITICAL_THRESHOLD);
        assert!(verdict.message.contains("no progress"));
    }

    #[test]
    fn volatile_result_fields_do_not_hide_a_loop() {
        let mut detector = LoopDetector::new();
        let arguments = json!({"command": "flaky"});

        for index in 0..WARNING_THRESHOLD {
            error_observation(
                &mut detector,
                "shell",
                arguments.clone(),
                json!({
                    "error": "failed",
                    "timestamp": 1_700_000_000 + index,
                    "pid": 1000 + index,
                    "durationMs": index,
                    "id": format!("req-{index}-abcdef"),
                }),
            );
        }

        let verdict = detector
            .check("shell", &arguments, false)
            .expect("volatile fields should be stripped");
        assert_eq!(verdict.detector, Detector::NoProgressPoll);
        assert_eq!(verdict.count, WARNING_THRESHOLD);
    }

    #[test]
    fn progress_resets_the_streak() {
        let mut detector = LoopDetector::new();
        let arguments = json!({"path": "state.json"});

        for _ in 0..WARNING_THRESHOLD {
            error_observation(
                &mut detector,
                "read",
                arguments.clone(),
                json!({"error": "not ready"}),
            );
        }
        observe(
            &mut detector,
            "read",
            arguments.clone(),
            true,
            json!({"value": "ready"}),
        );

        assert!(
            detector.check("read", &arguments, false).is_none(),
            "a changed outcome must reset the no-progress streak"
        );
    }

    #[test]
    fn argument_object_key_order_is_ignored() {
        let mut detector = LoopDetector::new();
        let observed = json!({"alpha": 1, "beta": 2});

        for _ in 0..WARNING_THRESHOLD {
            error_observation(
                &mut detector,
                "read",
                observed.clone(),
                json!({"error": "not ready"}),
            );
        }

        let reordered = json!({"beta": 2, "alpha": 1});
        let verdict = detector
            .check("read", &reordered, false)
            .expect("key order must not create a new signature");
        assert_eq!(verdict.detector, Detector::NoProgressPoll);
        assert_eq!(verdict.count, WARNING_THRESHOLD);
    }

    #[test]
    fn argument_array_order_is_preserved() {
        let mut detector = LoopDetector::new();
        let observed = json!({"paths": ["a", "b"]});

        for _ in 0..WARNING_THRESHOLD {
            error_observation(
                &mut detector,
                "read",
                observed.clone(),
                json!({"error": "not ready"}),
            );
        }

        let reordered = json!({"paths": ["b", "a"]});
        assert!(
            detector.check("read", &reordered, false).is_none(),
            "array order is part of the signature"
        );
    }

    #[test]
    fn progress_by_same_output_is_not_flagged_until_it_repeats() {
        let mut detector = LoopDetector::new();
        let arguments = json!({"path": "state.json"});

        observe(
            &mut detector,
            "read",
            arguments.clone(),
            true,
            json!({"value": 1}),
        );
        assert!(detector.check("read", &arguments, false).is_none());
    }
}
