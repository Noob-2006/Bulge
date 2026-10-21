//! bulge-guard: cautious decision layer around the agent loop.

pub mod loop_detect;
pub mod netgate;
pub mod permission;
pub mod redact;
pub mod risk;
pub mod threat;
pub mod wildcard;

pub use loop_detect::{Detector, Level, LoopDetector, Observation, Verdict};
pub use netgate::{DomainVerdict, NetDecision, NetGate};
pub use permission::{Effect, Rule, Ruleset, evaluate, evaluate_resources};
pub use redact::{Redactor, redact_secrets};
pub use risk::{Autonomy, ChangeKind, Risk, classify_change, gate, is_sensitive_path, max_risk};
pub use threat::{Scope, ThreatHit, is_threat, scan as threat_scan};
