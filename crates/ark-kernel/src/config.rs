//! Layered TOML config: built-in defaults → user → project (`.ark/config.toml`)
//! → `--set key=value` overrides. `dump()` prints the effective result.

use crate::gate::GateConfig;
use crate::ledger::{Budget, Price};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct Config {
    pub model: ModelConfig,
    /// Provider overrides / additions, passed through to the model layer.
    pub providers: BTreeMap<String, toml::Table>,
    /// USD per million tokens, keyed by `provider/model`.
    pub prices: BTreeMap<String, Price>,
    pub budget: Budget,
    pub runner: RunnerConfig,
    pub compaction: CompactionConfig,
    pub gate: GateConfig,
    pub schedule: ScheduleConfig,
    pub tools: ToolsConfig,
    pub learn: LearnConfig,
    pub checkpoint: CheckpointConfig,
    /// Extra persona / standing instructions appended to the identity segment.
    pub identity: String,
    /// Lifecycle hooks (shell commands, Claude Code–compatible protocol).
    pub hooks: Vec<crate::hooks::HookConfig>,
    /// MCP servers / connectors, plugins and channels: parsed by their crates.
    pub mcp: BTreeMap<String, toml::Table>,
    pub plugins: BTreeMap<String, toml::Table>,
    pub channels: BTreeMap<String, toml::Table>,
    /// Workspaces whose `.ark/config.toml` may define the keys in `PROJECT_GATED`.
    pub trusted_projects: Vec<String>,
}

/// Keys that run programs or open listeners. A cloned repo must not get them
/// for free: they are dropped from a project config unless the user trusts it.
pub const PROJECT_GATED: &[&str] = &["hooks", "mcp", "plugins", "channels", "providers", "trusted_projects"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelConfig {
    /// `provider/model`, e.g. `anthropic/claude-sonnet-5-5`.
    pub default: String,
    /// Tried in order when the default fails with a retryable/auth error.
    pub fallback: Vec<String>,
    /// Cheap model for compaction, titles and memory review. Empty = default.
    pub aux: String,
    /// Model for spawned sub-agents. Empty = default.
    pub subagent: String,
    pub max_tokens: u32,
    pub temperature: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RunnerConfig {
    pub max_steps_per_turn: u64,
    pub max_retries: u32,
    pub retry_base_ms: u64,
    pub retry_max_ms: u64,
    /// Tool outputs larger than this are spilled to an artifact file.
    pub spill_bytes: usize,
    /// Same tool + same input this many times in a row → watchdog notice.
    pub repeat_limit: usize,
    pub max_spawn_depth: u32,
    /// Auto-continue when the model stops on max_tokens.
    pub max_continuations: u32,
    /// Parallel tool calls per step.
    pub max_parallel_tools: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CompactionConfig {
    /// Compact when the prompt exceeds this fraction of the context window.
    pub threshold: f64,
    /// Prune old tool outputs first when above this fraction.
    pub prune_threshold: f64,
    /// Most recent tool results never pruned.
    pub keep_tool_results: usize,
    /// Most recent messages kept verbatim by summarisation.
    pub keep_messages: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScheduleConfig {
    /// Fixed UTC offset used for cron expressions (Taiwan = 480).
    pub utc_offset_minutes: i32,
    pub tick_secs: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ToolsConfig {
    pub disabled: Vec<String>,
    /// Force these to ship full schemas.
    pub pinned: Vec<String>,
    /// Force these behind progressive disclosure.
    pub unpinned: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LearnConfig {
    /// Background review after each turn proposes memory entries (staged, not applied).
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CheckpointConfig {
    pub enabled: bool,
    /// Skip snapshotting workspaces with more files than this.
    pub max_files: usize,
}

impl Default for ModelConfig {
    fn default() -> Self {
        ModelConfig { default: "anthropic/claude-sonnet-5-5".into(), fallback: vec![], aux: String::new(), subagent: String::new(), max_tokens: 8192, temperature: None }
    }
}
impl Default for RunnerConfig {
    fn default() -> Self {
        RunnerConfig { max_steps_per_turn: 200, max_retries: 5, retry_base_ms: 1000, retry_max_ms: 60_000, spill_bytes: 16_000, repeat_limit: 3, max_spawn_depth: 2, max_continuations: 3, max_parallel_tools: 8 }
    }
}
impl Default for CompactionConfig {
    fn default() -> Self {
        CompactionConfig { threshold: 0.75, prune_threshold: 0.5, keep_tool_results: 6, keep_messages: 8 }
    }
}
impl Default for ScheduleConfig {
    fn default() -> Self {
        ScheduleConfig { utc_offset_minutes: 480, tick_secs: 30 }
    }
}
impl Default for CheckpointConfig {
    fn default() -> Self {
        CheckpointConfig { enabled: true, max_files: 20_000 }
    }
}

impl Config {
    pub fn aux_model(&self) -> &str {
        if self.model.aux.is_empty() {
            &self.model.default
        } else {
            &self.model.aux
        }
    }
    pub fn subagent_model(&self) -> &str {
        if self.model.subagent.is_empty() {
            &self.model.default
        } else {
            &self.model.subagent
        }
    }
    pub fn price(&self, model: &str) -> Option<Price> {
        self.prices.get(model).copied()
    }

    /// Load and merge layers. Missing files are fine; malformed ones are errors.
    pub fn load(user: Option<&Path>, project: Option<&Path>, sets: &[String]) -> Result<Config, String> {
        let mut merged = toml::Table::new();
        let mut dropped = Vec::new();
        for (layer, p) in [(0, user), (1, project)] {
            let Some(p) = p.filter(|p| p.exists()) else { continue };
            let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            let mut t: toml::Table = text.parse().map_err(|e| format!("{}: {e}", p.display()))?;
            if layer == 1 && !project_trusted(&merged, p) {
                for k in PROJECT_GATED {
                    if t.remove(*k).is_some() {
                        dropped.push(*k);
                    }
                }
            }
            merge(&mut merged, t);
        }
        if !dropped.is_empty() {
            eprintln!("ark: ignoring {} from untrusted project config (add the workspace to `trusted_projects` in your user config)", dropped.join(", "));
        }
        for s in sets {
            let (k, v) = s.split_once('=').ok_or_else(|| format!("--set expects key=value, got `{s}`"))?;
            set_path(&mut merged, k.trim(), parse_value(v.trim()))?;
        }
        let cfg: Config = toml::Value::Table(merged).try_into().map_err(|e: toml::de::Error| format!("config: {}", e.message()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.model.default.contains('/') {
            return Err(format!("model.default must be `provider/model`, got `{}`", self.model.default));
        }
        for m in self.model.fallback.iter().chain([&self.model.aux, &self.model.subagent].into_iter().filter(|s| !s.is_empty())) {
            if !m.contains('/') {
                return Err(format!("model `{m}` must be `provider/model`"));
            }
        }
        let c = &self.compaction;
        if !(0.1..=0.98).contains(&c.threshold) || !(0.05..=c.threshold).contains(&c.prune_threshold) {
            return Err("compaction: need 0.05 <= prune_threshold <= threshold <= 0.98".into());
        }
        if self.runner.max_parallel_tools == 0 || self.runner.max_steps_per_turn == 0 {
            return Err("runner: max_parallel_tools and max_steps_per_turn must be > 0".into());
        }
        if !(-720..=840).contains(&self.schedule.utc_offset_minutes) {
            return Err("schedule.utc_offset_minutes out of range".into());
        }
        Ok(())
    }

    pub fn dump(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }
}

fn merge(base: &mut toml::Table, over: toml::Table) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(toml::Value::Table(b)), toml::Value::Table(o)) => merge(b, o),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

fn set_path(t: &mut toml::Table, path: &str, v: toml::Value) -> Result<(), String> {
    let parts: Vec<&str> = path.split('.').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(format!("bad key `{path}`"));
    }
    let mut cur = t;
    for p in &parts[..parts.len() - 1] {
        let e = cur.entry(p.to_string()).or_insert_with(|| toml::Value::Table(toml::Table::new()));
        cur = e.as_table_mut().ok_or_else(|| format!("`{p}` is not a table"))?;
    }
    cur.insert(parts[parts.len() - 1].to_string(), v);
    Ok(())
}

/// `--set` values: TOML literal when it parses (numbers, bools, arrays), else string.
fn parse_value(s: &str) -> toml::Value {
    format!("v = {s}").parse::<toml::Table>().ok().and_then(|mut t| t.remove("v")).unwrap_or_else(|| toml::Value::String(s.to_string()))
}

/// `project` is `<ws>/.ark/config.toml`; trust is listed by workspace path.
fn project_trusted(user: &toml::Table, project: &Path) -> bool {
    let Some(ws) = project.parent().and_then(Path::parent).and_then(|w| w.canonicalize().ok()) else { return false };
    user.get("trusted_projects").and_then(|v| v.as_array()).is_some_and(|a| a.iter().filter_map(|v| v.as_str()).any(|t| Path::new(t).canonicalize().is_ok_and(|t| t == ws)))
}

/// Unix socket paths are capped at 107 bytes and the runtime dir holds
/// `call-<16 hex>.sock`, so a deep home moves its runtime dir somewhere short.
/// The replacement is derived from the original path, so daemon and clients agree.
const RUNTIME_MAX: usize = 80;

fn short_runtime(dir: PathBuf) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    if dir.as_os_str().len() <= RUNTIME_MAX {
        return dir;
    }
    // FNV-1a: stable across builds, unlike DefaultHasher.
    let h = dir.as_os_str().as_bytes().iter().fold(0xcbf29ce484222325u64, |h, b| (h ^ *b as u64).wrapping_mul(0x100000001b3));
    let tag = format!("ark-{:012x}", h & 0xffff_ffff_ffff);
    if let Some(r) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|r| r.is_absolute() && r.as_os_str().len() + tag.len() < RUNTIME_MAX) {
        return r.join(tag);
    }
    // Shared /tmp: our own 0700 directory, refusing one someone else planted.
    let uid = unsafe { libc::getuid() };
    let base = PathBuf::from(format!("/tmp/ark-{uid}"));
    let _ = std::fs::DirBuilder::new().mode(0o700).create(&base);
    match std::fs::symlink_metadata(&base) {
        Ok(m) if m.is_dir() && m.uid() == uid && m.mode() & 0o077 == 0 => base.join(tag),
        _ => dir, // fails later with a clear "path too long" rather than trusting a foreign dir
    }
}

/// Filesystem layout. `ARK_HOME` overrides everything (tests, portable installs).
#[derive(Debug, Clone)]
pub struct Paths {
    pub data: PathBuf,
    pub config_dir: PathBuf,
    pub runtime: PathBuf,
}

impl Paths {
    pub fn from_env() -> Paths {
        if let Some(h) = std::env::var_os("ARK_HOME") {
            let h = PathBuf::from(h);
            return Paths { data: h.join("data"), config_dir: h.join("config"), runtime: short_runtime(h.join("run")) };
        }
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"));
        let xdg = |var: &str, def: &str| std::env::var_os(var).map(PathBuf::from).filter(|p| p.is_absolute()).unwrap_or_else(|| home.join(def));
        let data = xdg("XDG_DATA_HOME", ".local/share").join("ark");
        let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(|r| PathBuf::from(r).join("ark")).unwrap_or_else(|| data.join("run"));
        Paths { data, config_dir: xdg("XDG_CONFIG_HOME", ".config").join("ark"), runtime: short_runtime(runtime) }
    }
    pub fn user_config(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }
    pub fn secrets(&self) -> PathBuf {
        self.config_dir.join("secrets.toml")
    }
    pub fn sessions(&self) -> PathBuf {
        self.data.join("sessions")
    }
    pub fn socket(&self) -> PathBuf {
        self.runtime.join("arkd.sock")
    }
    pub fn skills_dirs(&self, workspace: &Path) -> Vec<PathBuf> {
        let mut v = vec![workspace.join(".ark/skills"), workspace.join(".claude/skills"), workspace.join(".agents/skills"), self.data.join("skills")];
        if let Some(h) = std::env::var_os("HOME") {
            v.push(PathBuf::from(h).join(".claude/skills"));
        }
        v
    }
}

pub fn project_config(workspace: &Path) -> PathBuf {
    workspace.join(".ark/config.toml")
}

pub const SAMPLE: &str = r#"# ark configuration — every key is optional.
[model]
default = "anthropic/claude-sonnet-5-5"   # provider/model
fallback = ["openrouter/anthropic/claude-sonnet-5-5"]
aux = ""        # cheap model for compaction / review, e.g. "deepseek/deepseek-chat"
max_tokens = 8192

[budget]        # per session; omit for unlimited
# max_tokens = 2000000
# max_cost_usd = 5.0

[gate]          # only two gates: privilege (sudo & system changes) and egress (data leaving)
privilege = "ask"   # ask | deny | allow
egress = "ask"
egress_allow = ["github.com"]
egress_deny = []

[schedule]
utc_offset_minutes = 480   # cron timezone (UTC+8)

# [providers.myvllm]
# format = "openai_chat"
# base_url = "http://localhost:8000/v1"
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn untrusted_project_cannot_add_hooks_or_servers() {
        let root = std::env::temp_dir().join(format!("ark-trust-{}", crate::util::random_hex(6)));
        let ws = root.join("ws");
        std::fs::create_dir_all(ws.join(".ark")).unwrap();
        let user = root.join("user.toml");
        let proj = ws.join(".ark/config.toml");
        std::fs::write(&proj, "identity = \"proj\"\n[[hooks]]\nevent = \"pre_tool\"\ncommand = \"curl evil\"\n[mcp.x]\ncommand = \"evil\"\n").unwrap();
        std::fs::write(&user, "[mcp.mine]\ncommand = \"ok\"\n").unwrap();
        let c = Config::load(Some(&user), Some(&proj), &[]).unwrap();
        assert_eq!(c.identity, "proj", "harmless keys still apply");
        assert!(c.hooks.is_empty() && !c.mcp.contains_key("x") && c.mcp.contains_key("mine"));
        std::fs::write(&user, format!("trusted_projects = [\"{}\"]\n", ws.display())).unwrap();
        let c = Config::load(Some(&user), Some(&proj), &[]).unwrap();
        assert_eq!(c.hooks.len(), 1);
        assert!(c.mcp.contains_key("x"));
        // A project can't trust itself.
        std::fs::write(&user, "").unwrap();
        std::fs::write(&proj, format!("trusted_projects = [\"{}\"]\n[[hooks]]\nevent = \"pre_tool\"\ncommand = \"x\"\n", ws.display())).unwrap();
        assert!(Config::load(Some(&user), Some(&proj), &[]).unwrap().hooks.is_empty());
    }

    #[test]
    fn deep_runtime_dir_is_shortened_deterministically() {
        let short = PathBuf::from("/home/u/.local/share/ark/run");
        assert_eq!(short_runtime(short.clone()), short);
        let deep = PathBuf::from(format!("/home/u/{}/run", "very-long-directory-name/".repeat(6)));
        let a = short_runtime(deep.clone());
        assert!(a.as_os_str().len() <= RUNTIME_MAX, "{}", a.display());
        assert_eq!(a, short_runtime(deep.clone()), "daemon and client must agree");
        assert_ne!(a, short_runtime(deep.join("other")), "different homes don't share a socket");
        assert!(a.join("call-0123456789abcdef.sock").as_os_str().len() < 108);
    }

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("ark-cfg-{}", crate::util::random_hex(8)));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn layering_and_sets() {
        let d = tmp();
        let u = d.join("u.toml");
        let p = d.join("p.toml");
        fs::write(&u, "[model]\ndefault = \"a/b\"\nmax_tokens = 100\n[gate]\negress_allow=[\"x.com\"]\n").unwrap();
        fs::write(&p, "[model]\nmax_tokens = 200\n").unwrap();
        let c = Config::load(Some(&u), Some(&p), &["budget.max_steps=7".into(), "gate.privilege=deny".into(), "identity=be terse".into()]).unwrap();
        assert_eq!(c.model.default, "a/b");
        assert_eq!(c.model.max_tokens, 200);
        assert_eq!(c.budget.max_steps, Some(7));
        assert_eq!(c.gate.privilege, crate::gate::Mode::Deny);
        assert_eq!(c.gate.egress_allow, ["x.com"]);
        assert_eq!(c.identity, "be terse");
        assert!(c.dump().contains("max_tokens = 200"));
        // Dump must round-trip.
        let again: Config = toml::from_str(&c.dump()).unwrap();
        assert_eq!(again.model.max_tokens, 200);
    }

    #[test]
    fn errors_are_reported_not_ignored() {
        let d = tmp();
        let bad = d.join("bad.toml");
        fs::write(&bad, "[model\n").unwrap();
        assert!(Config::load(Some(&bad), None, &[]).is_err());
        fs::write(&bad, "[model]\ndefualt = \"x/y\"\n").unwrap();
        assert!(Config::load(Some(&bad), None, &[]).unwrap_err().contains("defualt"), "typos are caught");
        assert!(Config::load(None, None, &["model.default=nomodel".into()]).unwrap_err().contains("provider/model"));
        assert!(Config::load(None, None, &["noequals".into()]).is_err());
        assert!(Config::load(None, None, &["a..b=1".into()]).is_err());
        assert!(Config::load(None, None, &["compaction.threshold=2".into()]).is_err());
        assert!(Config::load(None, None, &["model.max_tokens=\"lots\"".into()]).is_err());
    }

    #[test]
    fn sample_config_is_valid() {
        let d = tmp();
        let f = d.join("c.toml");
        fs::write(&f, SAMPLE).unwrap();
        Config::load(Some(&f), None, &[]).unwrap();
    }

    #[test]
    fn missing_files_use_defaults() {
        let c = Config::load(Some(Path::new("/nonexistent/x.toml")), None, &[]).unwrap();
        assert_eq!(c.runner.max_spawn_depth, 2);
        assert_eq!(c.aux_model(), c.model.default);
    }
}
