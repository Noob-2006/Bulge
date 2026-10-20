//! Runaway-loop detection over recent tool outcomes.
//! MARK: M17 — transcribed by dsh; see marks/M17-loop-detect.md.
//!
//! The driver records each completed call here; before the next call it asks
//! for a verdict. Detectors look at a bounded window of recent calls, each
//! reduced to a stable signature (tool + canonical args) and an outcome hash
//! with volatile fields stripped, so identical no-progress repeats are caught.

use serde_json::Value;

/// One finished tool call fed into the detector.
#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    pub tool: String,
    /// Canonical arguments (object key order does not matter).
    pub arguments: Value,
    /// True if the call errored or made no observable change.
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

#[derive(Debug, Default)]
pub struct LoopDetector {
    // M17
}

impl LoopDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verdict for the call *about to run*, given history so far. `unknown_tool`
    /// is true when `tool` is not a registered tool name. Returns `None` when
    /// nothing is stuck.
    pub fn check(&self, tool: &str, arguments: &Value, unknown_tool: bool) -> Option<Verdict> {
        let _ = (tool, arguments, unknown_tool);
        todo!("M17")
    }

    /// Record a finished call (call this after each tool completes).
    pub fn observe(&mut self, observation: Observation) {
        let _ = observation;
        todo!("M17")
    }
}
