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
    /// When the skill was first recorded, in Unix seconds.
    #[serde(default)]
    pub created_at: Option<u64>,
    /// When the skill was last used, in Unix seconds.
    #[serde(default)]
    pub last_used_at: Option<u64>,
}

impl SkillUsage {
    /// A fresh, active, unpinned entry authored by `by`.
    fn new(by: Author, now: u64) -> Self {
        Self {
            created_by: by,
            uses: 0,
            patches: 0,
            state: Lifecycle::Active,
            pinned: false,
            created_at: Some(now),
            last_used_at: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UsageLedger {
    /// Keyed by skill name (NOT frontmatter) — the directory/file stem.
    #[serde(default)]
    pub entries: BTreeMap<String, SkillUsage>,
}

/// Inactivity thresholds for automatic lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CuratePolicy {
    /// Active -> Stale after this many seconds without a use.
    pub stale_after_secs: u64,
    /// Stale -> Archived after this many seconds without a use.
    pub archive_after_secs: u64,
}

impl Default for CuratePolicy {
    fn default() -> Self {
        Self {
            stale_after_secs: 14 * 24 * 3600,
            // CORE.md §5: a skill unused for 30 days is archived.
            archive_after_secs: 30 * 24 * 3600,
        }
    }
}

impl UsageLedger {
    /// Find an entry, creating one when missing. `now` is the creation time for
    /// events that count as a use; non-use events pass `None` (unknown age).
    fn entry_or_insert(&mut self, name: &str, now: Option<u64>) -> &mut SkillUsage {
        self.entries.entry(name.to_string()).or_insert_with(|| {
            let mut entry = SkillUsage::new(Author::Agent, now.unwrap_or_default());
            entry.created_at = now;
            entry
        })
    }

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
    pub fn record_created(&mut self, name: &str, by: Author, now: u64) {
        self.entries
            .entry(name.to_string())
            .or_insert_with(|| SkillUsage::new(by, now));
    }

    /// Count one use, creating an active agent entry when the skill is unknown.
    /// A stale skill that is used again is active again (an archived one is not
    /// offered, so it is not used; restoring it is a user's decision).
    pub fn bump_use(&mut self, name: &str, now: u64) {
        let entry = self.entry_or_insert(name, Some(now));
        entry.uses = entry.uses.saturating_add(1);
        entry.last_used_at = Some(now);
        if entry.state == Lifecycle::Stale {
            entry.state = Lifecycle::Active;
        }
    }

    /// The state of `name`, or `None` when the ledger does not know it.
    pub fn state(&self, name: &str) -> Option<Lifecycle> {
        self.entries.get(name).map(|entry| entry.state)
    }

    /// Count one patch, creating an active agent entry when the skill is unknown.
    pub fn bump_patch(&mut self, name: &str, now: u64) {
        let entry = self.entry_or_insert(name, Some(now));
        entry.patches = entry.patches.saturating_add(1);
    }

    /// Drop a skill's history entirely.
    pub fn forget(&mut self, name: &str) {
        self.entries.remove(name);
    }

    /// Pin or unpin a skill, creating an active agent entry when it is unknown.
    pub fn set_pinned(&mut self, name: &str, pinned: bool) {
        let entry = self.entry_or_insert(name, None);
        entry.pinned = pinned;
    }

    /// Move a skill through its lifecycle, creating an active agent entry when it
    /// is unknown. A pinned skill's state is deliberately left alone.
    pub fn set_state(&mut self, name: &str, state: Lifecycle) {
        let entry = self.entry_or_insert(name, None);
        if !entry.pinned {
            entry.state = state;
        }
    }

    /// Move unused skills along their lifecycle. For each non-pinned entry,
    /// measure idle from the last use, falling back to creation time; an entry
    /// with neither timestamp has unknown age and is left alone. Transitions
    /// never move backwards, pinned entries are skipped, and nothing is removed.
    /// Returns the `(name, new_state)` pairs that actually changed.
    pub fn curate(&mut self, now: u64, policy: CuratePolicy) -> Vec<(String, Lifecycle)> {
        let mut changed = Vec::new();
        for (name, entry) in &mut self.entries {
            if entry.pinned {
                continue;
            }
            let Some(last_activity) = entry.last_used_at.or(entry.created_at) else {
                continue;
            };
            let idle = now.saturating_sub(last_activity);
            let next = if idle >= policy.archive_after_secs {
                Lifecycle::Archived
            } else if idle >= policy.stale_after_secs {
                Lifecycle::Stale
            } else {
                continue;
            };
            if next == Lifecycle::Archived && entry.state != Lifecycle::Archived {
                entry.state = Lifecycle::Archived;
                changed.push((name.clone(), Lifecycle::Archived));
            } else if next == Lifecycle::Stale && entry.state == Lifecycle::Active {
                entry.state = Lifecycle::Stale;
                changed.push((name.clone(), Lifecycle::Stale));
            }
        }
        changed
    }

    /// Convenience: names currently in a given state (sorted).
    pub fn in_state(&self, state: Lifecycle) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.state == state)
            .map(|(name, _)| name.clone())
            .collect()
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
        ledger.record_created("release-checklist", Author::User, 100);
        ledger.bump_use("release-checklist", 200);
        ledger.bump_patch("release-checklist", 300);
        ledger.set_state("release-checklist", Lifecycle::Stale);
        ledger.save(&path).expect("saves");

        let loaded = UsageLedger::load(&path).expect("loads");
        assert_eq!(loaded, ledger);
        assert_eq!(loaded.entries["release-checklist"].created_by, Author::User);
        assert_eq!(loaded.entries["release-checklist"].created_at, Some(100));
        assert_eq!(loaded.entries["release-checklist"].last_used_at, Some(200));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn old_ledgers_without_timestamps_load() {
        let source = r#"{"entries":{"a":{"created_by":"agent","uses":2,"patches":1,"state":"active","pinned":false}}}"#;
        let ledger: UsageLedger = serde_json::from_str(source).expect("old ledger loads");

        let entry = &ledger.entries["a"];
        assert_eq!(entry.created_at, None);
        assert_eq!(entry.last_used_at, None);
    }

    #[test]
    fn record_created_is_idempotent() {
        let mut ledger = UsageLedger::default();
        ledger.record_created("a", Author::User, 100);
        ledger.bump_use("a", 200);
        ledger.bump_patch("a", 300);
        ledger.record_created("a", Author::Agent, 400);

        let entry = &ledger.entries["a"];
        assert_eq!(entry.created_by, Author::User);
        assert_eq!(entry.created_at, Some(100));
        assert_eq!(entry.uses, 1);
        assert_eq!(entry.patches, 1);
    }

    #[test]
    fn bump_use_and_patch_create_then_increment() {
        let mut ledger = UsageLedger::default();
        ledger.bump_use("a", 100);
        ledger.bump_use("a", 200);
        ledger.bump_patch("a", 300);

        let entry = &ledger.entries["a"];
        assert_eq!(entry.created_by, Author::Agent);
        assert_eq!(entry.created_at, Some(100));
        assert_eq!(entry.last_used_at, Some(200));
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
    fn curate_ages_entries_along_the_lifecycle() {
        let policy = CuratePolicy {
            stale_after_secs: 100,
            archive_after_secs: 1_000,
        };
        let mut ledger = UsageLedger::default();
        ledger.record_created("archive-me", Author::Agent, 0);
        ledger.record_created("stale-me", Author::Agent, 900);
        ledger.record_created("young", Author::Agent, 1_000);

        let changed = ledger.curate(1_050, policy);

        assert_eq!(
            changed,
            vec![
                ("archive-me".to_string(), Lifecycle::Archived),
                ("stale-me".to_string(), Lifecycle::Stale),
            ]
        );
        assert_eq!(ledger.entries["archive-me"].state, Lifecycle::Archived);
        assert_eq!(ledger.entries["stale-me"].state, Lifecycle::Stale);
        assert_eq!(ledger.entries["young"].state, Lifecycle::Active);
        assert!(
            ledger.curate(1_050, policy).is_empty(),
            "already-curated entries do not change again"
        );
    }

    #[test]
    fn curate_skips_pinned_entries() {
        let policy = CuratePolicy {
            stale_after_secs: 10,
            archive_after_secs: 20,
        };
        let mut ledger = UsageLedger::default();
        ledger.record_created("pinned", Author::Agent, 0);
        ledger.set_pinned("pinned", true);

        let changed = ledger.curate(1_000, policy);

        assert!(changed.is_empty());
        assert_eq!(ledger.entries["pinned"].state, Lifecycle::Active);
    }

    #[test]
    fn curate_leaves_entries_with_unknown_age_alone() {
        let policy = CuratePolicy {
            stale_after_secs: 10,
            archive_after_secs: 20,
        };
        let mut ledger = UsageLedger::default();
        let mut entry = SkillUsage::new(Author::Agent, 0);
        entry.created_at = None;
        ledger.entries.insert("unknown".to_string(), entry);

        let changed = ledger.curate(1_000, policy);

        assert!(changed.is_empty());
        assert_eq!(ledger.entries["unknown"].state, Lifecycle::Active);
    }

    #[test]
    fn a_recent_use_keeps_an_old_skill_active() {
        let policy = CuratePolicy {
            stale_after_secs: 100,
            archive_after_secs: 1_000,
        };
        let mut ledger = UsageLedger::default();
        ledger.record_created("a", Author::Agent, 0);
        ledger.bump_use("a", 900);

        let changed = ledger.curate(950, policy);

        assert!(changed.is_empty());
        assert_eq!(ledger.entries["a"].last_used_at, Some(900));
        assert_eq!(ledger.entries["a"].state, Lifecycle::Active);
    }

    #[test]
    fn in_state_returns_sorted_names() {
        let mut ledger = UsageLedger::default();
        ledger.record_created("zulu", Author::Agent, 0);
        ledger.record_created("alpha", Author::Agent, 0);
        ledger.record_created("mike", Author::Agent, 0);
        ledger.set_state("mike", Lifecycle::Archived);
        ledger.set_state("alpha", Lifecycle::Archived);

        assert_eq!(
            ledger.in_state(Lifecycle::Archived),
            vec!["alpha".to_string(), "mike".to_string()]
        );
        assert_eq!(ledger.in_state(Lifecycle::Active), vec!["zulu".to_string()]);
        assert!(ledger.in_state(Lifecycle::Stale).is_empty());
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
