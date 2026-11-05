//! `[skills]` settings used by the skills system and the hub (Hermes `config_defaults.py`
//! `skills:` and `curator:` sections). Lenient: unknown keys are ignored here so other
//! readers of `[skills]` (gating, auto_load …) can add their own.
//!
//! ```toml
//! [skills]
//! template_vars = true          # ${SEAGENT_SKILL_DIR} / ${SEAGENT_SESSION_ID}
//! inline_shell = false          # !`cmd` expansion (never for community hub installs)
//! inline_shell_timeout = 10
//! disabled = ["name"]
//! external_dirs = ["~/team-skills"]
//! ledger = true
//! ledger_max_bytes = 5242880
//! tier1_advisory = true         # SkillEvaluator advisory scan when the binary is on PATH
//! write_approval = false        # stage every `skill` write for `/skills approve <id>`
//! guard_agent_created = false   # block caution findings on agent-written skills (dangerous always blocks)
//! [skills.review]               # background review (candidate procedures → SKILL.md)
//! enabled = true
//! min_steps = 4                 # tools a turn must use before it looks like a procedure
//! auto_apply = false            # write the candidate straight away at turn end
//! [skills.curator]              # enabled, interval_hours, min_idle_hours, stale_after_days …
//! [skills.hub]                  # registry base URLs (tests point them at local servers)
//! ```

use seagent_kernel::config::{Config, Paths};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Curator {
    pub enabled: bool,
    pub interval_hours: u64,
    pub min_idle_hours: f64,
    pub stale_after_days: u64,
    pub archive_after_days: u64,
    pub consolidate: bool,
    pub prune_builtins: bool,
    pub archive_ttl_days: u64,
    pub backup: bool,
    pub backup_keep: usize,
}

#[derive(Debug, Clone)]
pub struct Hub {
    /// Allow loopback / private registry hosts (local mirrors, tests). Off by default (SSRF guard).
    pub allow_private: bool,
    pub github_api: String,
    pub github_raw: String,
    pub github_token_env: String,
    pub clawhub: String,
    pub skills_sh: String,
    pub lobehub: String,
    pub browse_sh: String,
    pub official_repo: String,
    pub official_prefix: String,
    /// Default taps searched besides the ones added with `seagent skills tap add`.
    pub default_taps: Vec<(String, String)>,
    pub cache_ttl_secs: u64,
}

#[derive(Debug, Clone)]
pub struct Review {
    /// Record candidate procedures at the end of a turn (`[skills.review] enabled`).
    pub enabled: bool,
    /// Tools a turn must use before it looks like a repeatable procedure.
    pub min_steps: usize,
    /// Write the candidate's SKILL.md at turn end instead of waiting for `curator review --apply`.
    pub auto_apply: bool,
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub template_vars: bool,
    pub inline_shell: bool,
    pub inline_shell_timeout: u64,
    pub disabled: Vec<String>,
    pub external_dirs: Vec<PathBuf>,
    pub ledger: bool,
    pub ledger_max_bytes: u64,
    pub tier1_advisory: bool,
    /// Hermes `skills.write_approval`: stage every skill write for out-of-band approval.
    pub write_approval: bool,
    /// Hermes `skills.guard_agent_created`: block caution findings on agent-written skills.
    pub guard_agent_created: bool,
    pub review: Review,
    pub curator: Curator,
    pub hub: Hub,
}

fn b(t: &toml::Table, k: &str, d: bool) -> bool {
    t.get(k).and_then(|v| v.as_bool()).unwrap_or(d)
}
fn n(t: &toml::Table, k: &str, d: u64) -> u64 {
    t.get(k).and_then(|v| v.as_integer()).map(|i| i.max(0) as u64).unwrap_or(d)
}
fn s(t: &toml::Table, k: &str, d: &str) -> String {
    t.get(k).and_then(|v| v.as_str()).unwrap_or(d).trim_end_matches('/').to_string()
}
/// Integer or float (upstream `curator.min_idle_hours` is a float, `2` by default).
fn f(t: &toml::Table, k: &str, d: f64) -> f64 {
    t.get(k).and_then(|v| v.as_float().or_else(|| v.as_integer().map(|i| i as f64))).unwrap_or(d)
}
fn list(t: &toml::Table, k: &str) -> Vec<String> {
    t.get(k).and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

pub fn expand(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(h) = std::env::var_os("HOME") {
            return PathBuf::from(h).join(rest);
        }
    }
    PathBuf::from(p)
}

impl Settings {
    pub fn from_table(t: &toml::Table) -> Settings {
        let empty = toml::Table::new();
        let c = t.get("curator").and_then(|v| v.as_table()).unwrap_or(&empty);
        let r = t.get("review").and_then(|v| v.as_table()).unwrap_or(&empty);
        let h = t.get("hub").and_then(|v| v.as_table()).unwrap_or(&empty);
        let default_taps = match h.get("taps").and_then(|v| v.as_array()) {
            Some(a) => a.iter().filter_map(|x| x.as_str()).map(|r| (r.to_string(), "skills/".to_string())).collect(),
            None => vec![("openai/skills".into(), "skills/".into()), ("anthropics/skills".into(), "skills/".into())],
        };
        Settings {
            template_vars: b(t, "template_vars", true),
            inline_shell: b(t, "inline_shell", false),
            inline_shell_timeout: n(t, "inline_shell_timeout", 10).max(1),
            disabled: list(t, "disabled"),
            external_dirs: list(t, "external_dirs").iter().map(|p| expand(p)).collect(),
            ledger: b(t, "ledger", true),
            ledger_max_bytes: n(t, "ledger_max_bytes", 5 * 1024 * 1024),
            tier1_advisory: b(t, "tier1_advisory", true),
            write_approval: b(t, "write_approval", false),
            guard_agent_created: b(t, "guard_agent_created", false),
            review: Review { enabled: b(r, "enabled", true), min_steps: n(r, "min_steps", 4).max(2) as usize, auto_apply: b(r, "auto_apply", false) },
            curator: Curator {
                enabled: b(c, "enabled", true),
                interval_hours: n(c, "interval_hours", 24 * 7).max(1),
                min_idle_hours: f(c, "min_idle_hours", 2.0),
                stale_after_days: n(c, "stale_after_days", 14).max(1),
                archive_after_days: n(c, "archive_after_days", 30).max(1),
                consolidate: b(c, "consolidate", false),
                prune_builtins: b(c, "prune_builtins", false),
                archive_ttl_days: n(c, "archive_ttl_days", 0),
                backup: b(c, "backup", true),
                backup_keep: n(c, "backup_keep", 2).max(1) as usize,
            },
            hub: Hub {
                allow_private: b(h, "allow_private", false),
                github_api: s(h, "github_api", "https://api.github.com"),
                github_raw: s(h, "github_raw", "https://raw.githubusercontent.com"),
                github_token_env: s(h, "github_token_env", "GITHUB_TOKEN"),
                clawhub: s(h, "clawhub", "https://clawhub.ai/api/v1"),
                skills_sh: s(h, "skills_sh", "https://skills.sh"),
                lobehub: s(h, "lobehub", "https://chat-agents.lobehub.com"),
                browse_sh: s(h, "browse_sh", "https://browse.sh/api/skills"),
                official_repo: s(h, "official_repo", "NousResearch/hermes-agent"),
                official_prefix: s(h, "official_prefix", "optional-skills"),
                default_taps,
                cache_ttl_secs: n(h, "cache_ttl_secs", 3600),
            },
        }
    }

    pub fn load(cfg: &Config) -> Settings {
        Settings::from_table(&cfg.skills)
    }

    pub fn is_disabled(&self, name: &str) -> bool {
        self.disabled.iter().any(|d| d == name)
    }
}

/// On-disk layout of the skills store (`<data>/skills`), mirroring `~/.hermes/skills`.
#[derive(Debug, Clone)]
pub struct Store {
    pub data: PathBuf,
    pub skills: PathBuf,
}

impl Store {
    pub fn new(paths: &Paths) -> Store {
        Store { data: paths.data.clone(), skills: paths.data.join("skills") }
    }
    pub fn at(data: &Path) -> Store {
        Store { data: data.to_path_buf(), skills: data.join("skills") }
    }
    pub fn hub(&self) -> PathBuf {
        self.skills.join(".hub")
    }
    pub fn archive(&self) -> PathBuf {
        self.skills.join(".archive")
    }
    pub fn usage(&self) -> PathBuf {
        self.skills.join(".usage.json")
    }
    pub fn ledger(&self) -> PathBuf {
        self.skills.join(".curator_ledger.jsonl")
    }
    pub fn blobs(&self) -> PathBuf {
        self.data.join(".curator_backups/blobs")
    }
    pub fn backups(&self) -> PathBuf {
        self.skills.join(".curator_backups")
    }
    pub fn manifest(&self) -> PathBuf {
        self.skills.join(".bundled_manifest")
    }
    pub fn suppressed(&self) -> PathBuf {
        self.skills.join(".curator_suppressed")
    }
    pub fn curator_state(&self) -> PathBuf {
        self.skills.join(".curator_state")
    }
    pub fn no_bundled_marker(&self) -> PathBuf {
        self.skills.join(".no-bundled-skills")
    }
    pub fn bundles(&self) -> PathBuf {
        match std::env::var_os("SEAGENT_BUNDLES_DIR") {
            Some(p) => PathBuf::from(p),
            None => self.data.join("skill-bundles"),
        }
    }
    pub fn curator_reports(&self) -> PathBuf {
        self.data.join("logs/curator")
    }
    /// Staged skill writes awaiting approval (Hermes `pending/skills/<id>.json`).
    pub fn pending(&self) -> PathBuf {
        self.data.join("pending/skills")
    }
    /// Background-review observations (per-session tool steps, loaded skills, candidates).
    pub fn review_state(&self) -> PathBuf {
        self.skills.join(".review_state.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_overrides() {
        let s = Settings::from_table(&toml::Table::new());
        assert!(s.template_vars && !s.inline_shell && s.inline_shell_timeout == 10 && s.ledger);
        assert_eq!((s.curator.interval_hours, s.curator.stale_after_days, s.curator.archive_after_days), (168, 14, 30));
        assert_eq!(s.hub.clawhub, "https://clawhub.ai/api/v1");
        assert!(!s.write_approval && !s.guard_agent_created, "both Hermes gates default off");
        assert!(s.review.enabled && s.review.min_steps == 4 && !s.review.auto_apply);
        let t: toml::Table = toml::from_str("inline_shell = true\ndisabled = [\"x\"]\n[curator]\nstale_after_days = 0\nmin_idle_hours = 0.5\n[hub]\nclawhub = \"http://127.0.0.1:9/api/\"\n").unwrap();
        let s = Settings::from_table(&t);
        assert!(s.inline_shell && s.is_disabled("x") && !s.is_disabled("y"));
        let t2: toml::Table = toml::from_str("write_approval = true\nguard_agent_created = true\n[review]\nmin_steps = 1\nauto_apply = true\n").unwrap();
        let g = Settings::from_table(&t2);
        assert!(g.write_approval && g.guard_agent_created);
        assert_eq!(g.review.min_steps, 2, "floored at 2: one tool call is not a procedure");
        assert!(g.review.auto_apply);
        assert_eq!(s.curator.stale_after_days, 1, "floored at 1 like upstream _bounded_count");
        assert_eq!(s.curator.min_idle_hours, 0.5, "upstream reads a float");
        assert_eq!(s.hub.clawhub, "http://127.0.0.1:9/api");
    }
}
