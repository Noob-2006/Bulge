//! Rule-based risk tiers for cross-boundary actions (adapted from DSH's
//! auto-review taxonomy, made deterministic). VM-internal tool calls are low by
//! construction — the VM is the boundary — so this classifies what crosses it:
//! write-backs to the host workspace, and (via `netgate`) egress.

use serde::{Deserialize, Serialize};

use crate::permission::Effect;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Low,
    Medium,
    High,
}

/// The autonomy mode of the job (mirrors `bulge_store::Autonomy` without the
/// dependency).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Autonomy {
    Collaborative,
    Autonomous,
    FullAuto,
}

/// What a single workspace change does to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// New file where none existed.
    Add,
    /// Overwrite an existing regular file's contents.
    Modify,
    /// Remove a pre-existing file or directory (irreversible on the host).
    Delete,
    /// New directory.
    Dir,
    /// A symlink (can point outside; always reviewed).
    Symlink,
}

/// Classify one change. `sensitive_path` marks executables, dotfiles, and
/// known config/credential locations.
pub fn classify_change(kind: ChangeKind, sensitive_path: bool) -> Risk {
    match kind {
        ChangeKind::Delete | ChangeKind::Symlink => Risk::Medium,
        ChangeKind::Add | ChangeKind::Modify | ChangeKind::Dir if sensitive_path => Risk::Medium,
        ChangeKind::Add | ChangeKind::Modify | ChangeKind::Dir => Risk::Low,
    }
}

/// A path is sensitive if it is hidden, looks like config/credentials, or is a
/// shell/CI entry point an attacker would target.
pub fn is_sensitive_path(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let lower = name.to_ascii_lowercase();
    name.starts_with('.')
        || path.contains("/.")
        || lower.ends_with(".env")
        || matches!(lower.as_str(), "makefile" | "dockerfile" | "justfile")
        || lower.ends_with(".sh")
        || lower.ends_with(".service")
        || lower.contains("secret")
        || lower.contains("credential")
        || lower.contains("password")
        || lower.ends_with(".pem")
        || lower.ends_with(".key")
}

/// Highest risk among several changes (empty → Low).
pub fn max_risk(risks: impl IntoIterator<Item = Risk>) -> Risk {
    risks.into_iter().max().unwrap_or(Risk::Low)
}

/// How a risk tier is gated under an autonomy mode.
/// - High always asks (never auto-applied, even in full-auto).
/// - Collaborative asks for everything that changes host state.
/// - Autonomous asks for Medium and above; Low proceeds.
/// - FullAuto applies Low and Medium; High asks.
pub fn gate(risk: Risk, autonomy: Autonomy) -> Effect {
    match (autonomy, risk) {
        (_, Risk::High) => Effect::Ask,
        (Autonomy::Collaborative, _) => Effect::Ask,
        (Autonomy::Autonomous, Risk::Low) => Effect::Allow,
        (Autonomy::Autonomous, Risk::Medium) => Effect::Ask,
        (Autonomy::FullAuto, Risk::Low | Risk::Medium) => Effect::Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_and_symlink_are_medium() {
        assert_eq!(classify_change(ChangeKind::Delete, false), Risk::Medium);
        assert_eq!(classify_change(ChangeKind::Symlink, false), Risk::Medium);
    }

    #[test]
    fn plain_text_add_modify_is_low_but_sensitive_is_medium() {
        assert_eq!(classify_change(ChangeKind::Modify, false), Risk::Low);
        assert_eq!(classify_change(ChangeKind::Modify, true), Risk::Medium);
    }

    #[test]
    fn sensitive_paths_detected() {
        for p in [".env", "config/.secrets", "deploy.sh", "Makefile", "app/id_rsa.pem", "a/.hidden"] {
            assert!(is_sensitive_path(p), "{p} should be sensitive");
        }
        for p in ["src/main.rs", "report.md", "data/table.csv"] {
            assert!(!is_sensitive_path(p), "{p} should not be sensitive");
        }
    }

    #[test]
    fn gating_by_autonomy() {
        assert_eq!(gate(Risk::Low, Autonomy::Autonomous), Effect::Allow);
        assert_eq!(gate(Risk::Medium, Autonomy::Autonomous), Effect::Ask);
        assert_eq!(gate(Risk::Medium, Autonomy::FullAuto), Effect::Allow);
        assert_eq!(gate(Risk::High, Autonomy::FullAuto), Effect::Ask);
        assert_eq!(gate(Risk::Low, Autonomy::Collaborative), Effect::Ask);
    }
}
