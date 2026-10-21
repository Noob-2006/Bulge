//! Skill usage ledger: a sidecar JSON file beside the skills directory that
//! records how each skill came to be and how it has been used since.
//!
//! The ledger is keyed by skill name — the directory/file stem, not the
//! frontmatter — so a rename in frontmatter never orphans a counter. It tracks
//! authorship, use and patch counts, and a lifecycle a curator can move skills
//! through (active → stale → archived). Pinned skills are exempt from automatic
//! transitions, which lets a user protect one that matters.
//!
//! Like `memory`, this is plain, dependency-free persistence: one JSON file,
//! loaded tolerantly (missing means empty) and saved atomically so a crash never
//! leaves a half-written ledger.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The ledger file name, kept beside the skills (a dotfile so it is not a skill).
pub const USAGE_FILE: &str = ".usage.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Lifecycle {
    #[default]
    Active,
    Stale,
    Archived,
}

/// Who authored a skill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Author {
    #[default]
    Agent,
    User,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillUsage {
    pub created_by: Author,
    pub uses: u32,
    pub patches: u32,
    pub state: Lifecycle,
    /// Pinned skills are never auto-transitioned by a curator.
    pub pinned: bool,
}

impl SkillUsage {
    /// A fresh, active, unpinned entry authored by `by`.
    fn new(by: Author) -> Self {
        Self {
            created_by: by,
            uses: 0,
            patches: 0,
            state: Lifecycle::Active,
            pinned: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UsageLedger {
    /// Keyed by skill name (NOT frontmatter) — the directory/file stem.
    #[serde(default)]
    pub entries: BTreeMap<String, SkillUsage>,
}

impl UsageLedger {
    /// Load the ledger at `path`. A missing file is an empty ledger; a malformed
    /// one is an error, so a corrupt ledger is never silently overwritten.
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(source) => serde_json::from_str(&source)
                .map_err(|error| format!("parse {}: {error}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(format!("read {}: {error}", path.display())),
        }
    }

    /// Save the ledger atomically: write a sibling temp file, then rename it over
    /// `path`. Creates the parent directory when needed.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let source = serde_json::to_string_pretty(self)
            .map_err(|error| format!("serialize usage ledger: {error}"))?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        let file = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(USAGE_FILE);
        let temp = path.with_file_name(format!("{file}.tmp-{}", std::process::id()));
        std::fs::write(&temp, source)
            .map_err(|error| format!("write {}: {error}", temp.display()))?;
        std::fs::rename(&temp, path).map_err(|error| {
            let _ = std::fs::remove_file(&temp);
            format!("rename {} to {}: {error}", temp.display(), path.display())
        })
    }

    /// Record a newly created skill. An existing entry is left untouched.
    pub fn record_created(&mut self, name: &str, by: Author) {
        self.entries
            .entry(name.to_string())
            .or_insert_with(|| SkillUsage::new(by));
    }

    /// Count one use, creating an active agent entry when the skill is unknown.
    pub fn bump_use(&mut self, name: &str) {
        let entry = self
            .entries
            .entry(name.to_string())
            .or_insert_with(|| SkillUsage::new(Author::Agent));
        entry.uses = entry.uses.saturating_add(1);
    }

    /// Count one patch, creating an active agent entry when the skill is unknown.
    pub fn bump_patch(&mut self, name: &str) {
        let entry = self
            .entries
            .entry(name.to_string())
            .or_insert_with(|| SkillUsage::new(Author::Agent));
        entry.patches = entry.patches.saturating_add(1);
    }

    /// Drop a skill's history entirely.
    pub fn forget(&mut self, name: &str) {
        self.entries.remove(name);
    }

    /// Pin or unpin a skill, creating an active agent entry when it is unknown.
    pub fn set_pinned(&mut self, name: &str, pinned: bool) {
        let entry = self
            .entries
            .entry(name.to_string())
            .or_insert_with(|| SkillUsage::new(Author::Agent));
        entry.pinned = pinned;
    }

    /// Move a skill through its lifecycle, creating an active agent entry when it
    /// is unknown. A pinned skill's state is deliberately left alone.
    pub fn set_state(&mut self, name: &str, state: Lifecycle) {
        let entry = self
            .entries
            .entry(name.to_string())
            .or_insert_with(|| SkillUsage::new(Author::Agent));
        if !entry.pinned {
            entry.state = state;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("bulge-usage-{}-{label}", std::process::id()))
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = temp_path("round-trip");
        let path = dir.join(USAGE_FILE);
        let _ = std::fs::remove_dir_all(&dir);

        let mut ledger = UsageLedger::default();
        ledger.record_created("release-checklist", Author::User);
        ledger.bump_use("release-checklist");
        ledger.bump_patch("release-checklist");
        ledger.set_state("release-checklist", Lifecycle::Stale);
        ledger.save(&path).expect("saves");

        let loaded = UsageLedger::load(&path).expect("loads");
        assert_eq!(loaded, ledger);
        assert_eq!(loaded.entries["release-checklist"].created_by, Author::User);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_created_is_idempotent() {
        let mut ledger = UsageLedger::default();
        ledger.record_created("a", Author::User);
        ledger.bump_use("a");
        ledger.bump_patch("a");
        ledger.record_created("a", Author::Agent);

        let entry = &ledger.entries["a"];
        assert_eq!(entry.created_by, Author::User);
        assert_eq!(entry.uses, 1);
        assert_eq!(entry.patches, 1);
    }

    #[test]
    fn bump_use_and_patch_create_then_increment() {
        let mut ledger = UsageLedger::default();
        ledger.bump_use("a");
        ledger.bump_use("a");
        ledger.bump_patch("a");

        let entry = &ledger.entries["a"];
        assert_eq!(entry.created_by, Author::Agent);
        assert_eq!(entry.uses, 2);
        assert_eq!(entry.patches, 1);
        assert_eq!(entry.state, Lifecycle::Active);
        assert!(!entry.pinned);
    }

    #[test]
    fn pinned_entries_ignore_state_changes() {
        let mut ledger = UsageLedger::default();
        ledger.set_pinned("a", true);
        ledger.set_state("a", Lifecycle::Archived);
        assert_eq!(
            ledger.entries["a"].state,
            Lifecycle::Active,
            "pinned means no auto-transition"
        );

        ledger.set_pinned("a", false);
        ledger.set_state("a", Lifecycle::Archived);
        assert_eq!(ledger.entries["a"].state, Lifecycle::Archived);
    }

    #[test]
    fn missing_file_loads_as_empty() {
        let dir = temp_path("missing");
        let path = dir.join(USAGE_FILE);
        let _ = std::fs::remove_dir_all(&dir);

        let ledger = UsageLedger::load(&path).expect("missing file is not an error");
        assert_eq!(ledger, UsageLedger::default());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
