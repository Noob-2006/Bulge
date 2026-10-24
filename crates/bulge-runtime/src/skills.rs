//! Skills on the host: the agent-facing `skill` tool that loads one skill's
//! steps (and counts the use), and the lifecycle pass run when a session starts.
//!
//! Skills live in the harness tree on the host, which the VM cannot read, so the
//! `<available_skills>` index alone gave the model a name and one line — never
//! the procedure. Loading through this tool is also what feeds the usage ledger:
//! a skill that is never loaded ages to stale and then archived (CORE.md §5),
//! and archived skills leave the index.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use bulge_harness::SurfaceSpec;
use bulge_harness::usage::{CuratePolicy, Lifecycle, USAGE_FILE, UsageLedger};

/// Schema for the `skill` tool.
pub fn skill_tool() -> bulge_llm::ToolSchema {
    bulge_llm::ToolSchema {
        name: bulge_core::dispatch::SKILL_TOOL.into(),
        description: "Load the steps of one skill listed in <available_skills>. When a listed skill fits \
            the task, load it before you start and follow it as far as the request needs; skip skills \
            that do not fit."
            .into(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "The skill's name exactly as listed." }
            },
            "required": ["name"]
        }),
        defer_loading: false,
    }
}

/// The skills directory and its usage ledger for a harness root.
fn skills_root(harness_dir: &Path) -> PathBuf {
    harness_dir.join(SurfaceSpec::default().skill_dir.trim_end_matches('/'))
}

/// A [`bulge_core::driver::SkillHandler`] over the harness skills directory.
pub struct HarnessSkills {
    harness_dir: PathBuf,
    /// Serializes ledger read-modify-write between concurrent loads.
    ledger_lock: Mutex<()>,
}

impl HarnessSkills {
    pub fn new(harness_dir: &Path) -> Self {
        Self { harness_dir: harness_dir.to_path_buf(), ledger_lock: Mutex::new(()) }
    }
}

impl bulge_core::driver::SkillHandler for HarnessSkills {
    fn load(&self, name: &str) -> Result<String, String> {
        let tree = crate::run::read_tree(&self.harness_dir);
        let spec = SurfaceSpec::default();
        let skills = bulge_harness::tree::skills(&tree, &spec).map_err(|problem| format!("skills are unreadable: {}", problem.message))?;
        let Some(skill) = skills.into_iter().find(|skill| skill.name == name) else {
            return Err(format!("no skill named `{name}`; use a name exactly as listed in <available_skills>"));
        };

        let _guard = self.ledger_lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let ledger_path = skills_root(&self.harness_dir).join(USAGE_FILE);
        // A corrupt ledger is reported, never overwritten (it would lose history).
        let mut ledger = UsageLedger::load(&ledger_path)?;
        if ledger.state(name) == Some(Lifecycle::Archived) {
            return Err(format!("skill `{name}` is archived; it is not offered any more"));
        }
        ledger.bump_use(name, bulge_util::now_secs());
        if let Err(error) = ledger.save(&ledger_path) {
            eprintln!("skill usage not recorded: {error}");
        }
        Ok(format!("# Skill: {}\n{}\n\n{}", skill.name, skill.description, skill.body.trim()))
    }
}

/// Move unused skills along their lifecycle (active → stale → archived) once per
/// session, before the skills index is built. Returns what changed.
pub fn curate(harness_dir: &Path, now: u64) -> Result<Vec<(String, Lifecycle)>, String> {
    let ledger_path = skills_root(harness_dir).join(USAGE_FILE);
    let mut ledger = UsageLedger::load(&ledger_path)?;
    let changed = ledger.curate(now, CuratePolicy::default());
    if !changed.is_empty() {
        ledger.save(&ledger_path)?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulge_core::driver::SkillHandler;

    fn harness(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bulge-skills-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (name, body) in [("alpha", "1. Do alpha."), ("beta", "1. Do beta.")] {
            let skill = dir.join("skills").join(name);
            std::fs::create_dir_all(&skill).unwrap();
            std::fs::write(skill.join("SKILL.md"), format!("---\nname: {name}\ndescription: When {name}.\n---\n{body}\n")).unwrap();
        }
        dir
    }

    fn ledger(dir: &Path) -> UsageLedger {
        UsageLedger::load(&skills_root(dir).join(USAGE_FILE)).unwrap()
    }

    #[test]
    fn loading_returns_the_steps_and_counts_the_use() {
        let dir = harness("load");
        let skills = HarnessSkills::new(&dir);
        let text = skills.load("alpha").unwrap();
        assert!(text.contains("# Skill: alpha") && text.contains("1. Do alpha."));
        skills.load("alpha").unwrap();
        let entry = ledger(&dir).entries["alpha"].clone();
        assert_eq!(entry.uses, 2);
        assert!(entry.last_used_at.is_some());
        assert!(skills.load("nope").unwrap_err().contains("no skill named"));
    }

    #[test]
    fn archived_skills_cannot_be_loaded_and_stale_ones_revive() {
        let dir = harness("lifecycle");
        let path = skills_root(&dir).join(USAGE_FILE);
        let mut book = UsageLedger::default();
        book.set_state("alpha", Lifecycle::Archived);
        book.set_state("beta", Lifecycle::Stale);
        book.save(&path).unwrap();
        let skills = HarnessSkills::new(&dir);
        assert!(skills.load("alpha").unwrap_err().contains("archived"));
        skills.load("beta").unwrap();
        assert_eq!(ledger(&dir).state("beta"), Some(Lifecycle::Active));
    }

    #[test]
    fn a_corrupt_ledger_is_reported_not_overwritten() {
        let dir = harness("corrupt");
        let path = skills_root(&dir).join(USAGE_FILE);
        std::fs::write(&path, "{ not json").unwrap();
        assert!(HarnessSkills::new(&dir).load("alpha").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{ not json");
        assert!(curate(&dir, 0).is_err());
    }

    #[test]
    fn curate_archives_skills_unused_for_thirty_days() {
        let dir = harness("curate");
        let path = skills_root(&dir).join(USAGE_FILE);
        let mut book = UsageLedger::default();
        book.record_created("alpha", bulge_harness::Author::Agent, 0);
        book.record_created("beta", bulge_harness::Author::Agent, 0);
        book.bump_use("beta", 29 * 24 * 3600);
        book.save(&path).unwrap();
        let changed = curate(&dir, 31 * 24 * 3600).unwrap();
        assert_eq!(changed, vec![("alpha".to_string(), Lifecycle::Archived)]);
        assert_eq!(ledger(&dir).state("beta"), Some(Lifecycle::Active));
    }
}
