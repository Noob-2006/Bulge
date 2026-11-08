//! Multi-agent Kanban board (Hermes `kanban_*`, OpenClaw `workboard_*`): one board
//! engine, two tool vocabularies. Boards live under `<data>/kanban/boards/<slug>/`
//! as a file-locked JSON document (`kanban.json`) plus attachments / workspaces /
//! worker logs. The dispatcher (driven by seagentd's scheduler) claims ready cards and
//! runs each one as a kernel session with the worker tools bound to its task.

pub mod boards;
pub mod context;
pub mod diagnostics;
pub mod dispatch;
pub mod llm;
pub mod methods;
pub mod notify;
pub mod ops;
pub mod pr;
pub mod sessions_board;
pub mod store;
pub mod swarm;
pub mod tools;
pub mod transfer;
pub mod widget_board;
pub mod workboard;
pub mod workflow;

use crate::kernel::{Kernel, Runtime};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{RwLock, Weak};

pub const DEFAULT_BOARD: &str = "default";
/// One cap for dashboard, tools and CLI.
pub const ATTACHMENT_MAX_BYTES: u64 = 25 * 1024 * 1024;

/// `[kanban]` — the multi-agent board. Everything is optional.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KanbanConfig {
    /// Offer the orchestrator tools (`kanban_*`, `workboard_*`) to every session and run
    /// the dispatcher inside seagentd. Default false.
    pub enabled: bool,
    /// Let seagentd's scheduler run dispatcher ticks (needs `enabled`). Default true.
    pub dispatch: bool,
    /// Seconds between dispatcher ticks in seagentd / `seagent kanban daemon`. Default 30.
    pub dispatch_interval_secs: u64,
    /// Host-wide cap on running workers across every board. None = derived from
    /// memory: MemTotal / 512 MiB clamped to 2..=8.
    pub max_in_progress: Option<usize>,
    /// Per-board cap on running workers. None = uncapped.
    pub max_spawn: Option<usize>,
    /// Per-assignee cap on running workers. None = uncapped.
    pub max_in_progress_per_profile: Option<usize>,
    /// Consecutive non-success attempts before a task is auto-blocked. Default 2.
    pub failure_limit: u32,
    /// Claim TTL in seconds (extended by heartbeats). Default 900.
    pub claim_ttl_secs: i64,
    /// A live worker whose heartbeat is older than this is reclaimed anyway. Default 3600.
    pub heartbeat_max_stale_secs: i64,
    /// Reclaim running tasks with no heartbeat progress for this long (0 = off). Default 14400.
    pub stale_timeout_secs: i64,
    /// A freshly spawned worker is never judged crashed within this window. Default 30.
    pub crash_grace_secs: i64,
    /// Cooldown after a rate-limited requeue before respawning. Default 300.
    pub rate_limit_cooldown_secs: i64,
    /// Assignee applied to unassigned ready tasks (and decomposed children). Empty = none.
    pub default_assignee: String,
    /// Profile that owns a decomposed root after fan-out. Empty = the root's assignee.
    pub orchestrator_profile: String,
    /// Let the dispatcher decompose triage tasks with the aux model. Default false.
    pub auto_decompose: bool,
    /// Triage tasks decomposed per tick when `auto_decompose`. Default 1.
    pub auto_decompose_per_tick: usize,
    /// Promote decomposed children right away (false = they wait in todo). Default true.
    pub auto_promote_children: bool,
    /// Subscribe the creating session to a task's completion/block events. Default true.
    pub auto_subscribe_on_create: bool,
    /// Dispatch reviewers for tasks in `review`. Default true.
    pub review_dispatch: bool,
    /// Name recorded as author/creator for calls outside a worker. Default "default".
    pub identity: String,
    /// Worker profiles (assignees). Empty = any assignee is spawnable with the default model.
    pub profiles: BTreeMap<String, KanbanProfile>,
    /// GitHub REST base for PR acceptance. Default `https://api.github.com`.
    pub github_api: String,
    /// GitHub token (`{{secret:NAME}}` allowed). Empty = `$GH_TOKEN` / `$GITHUB_TOKEN`.
    pub github_token: String,
    /// Let `kanban_attach_url` fetch loopback/private addresses (tests, LAN). Default false.
    pub attach_url_allow_private: bool,
    /// Default goal-mode turn budget. Default 20.
    pub goal_max_turns: u32,
    pub diagnostics: DiagnosticsConfig,
}

/// `[kanban.profiles.<name>]` — what a worker for this assignee runs as.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KanbanProfile {
    /// One line shown to the decomposer when routing work.
    pub description: String,
    /// `provider/model` for this profile's workers. Empty = `model.default`.
    pub model: String,
    /// Extra standing instructions prepended to the worker prompt.
    pub instructions: String,
    /// Skills always force-loaded for this profile.
    pub skills: Vec<String>,
}

/// `[kanban.diagnostics]` thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiagnosticsConfig {
    /// Consecutive failures that raise `repeated_failures`. None = `failure_limit`.
    pub failure_threshold: Option<u32>,
    /// Trailing crashes that raise `repeated_crashes`. Default 2.
    pub crash_threshold: u32,
    /// Hours blocked without comment before `stuck_in_blocked`. Default 24.
    pub blocked_stale_hours: f64,
    /// Seconds an assigned task may sit in ready before `stranded_in_ready`. Default 1800.
    pub stranded_threshold_secs: i64,
    /// Seconds past an expired claim before `stale_running`. Default 3600.
    pub stale_running_grace_secs: i64,
    /// Block→unblock cycles inside the window before `block_unblock_cycling`. Default 3.
    pub block_cycle_threshold: u32,
    /// Window for cycle counting, seconds. Default 86400.
    pub block_cycle_window_secs: i64,
}

impl Default for KanbanConfig {
    fn default() -> Self {
        KanbanConfig {
            enabled: false,
            dispatch: true,
            dispatch_interval_secs: 30,
            max_in_progress: None,
            max_spawn: None,
            max_in_progress_per_profile: None,
            failure_limit: 2,
            claim_ttl_secs: 15 * 60,
            heartbeat_max_stale_secs: 3600,
            stale_timeout_secs: 4 * 3600,
            crash_grace_secs: 30,
            rate_limit_cooldown_secs: 300,
            default_assignee: String::new(),
            orchestrator_profile: String::new(),
            auto_decompose: false,
            auto_decompose_per_tick: 1,
            auto_promote_children: true,
            auto_subscribe_on_create: true,
            review_dispatch: true,
            identity: "default".into(),
            profiles: BTreeMap::new(),
            github_api: "https://api.github.com".into(),
            github_token: String::new(),
            attach_url_allow_private: false,
            goal_max_turns: 20,
            diagnostics: DiagnosticsConfig::default(),
        }
    }
}

impl Default for DiagnosticsConfig {
    fn default() -> Self {
        DiagnosticsConfig { failure_threshold: None, crash_threshold: 2, blocked_stale_hours: 24.0, stranded_threshold_secs: 1800, stale_running_grace_secs: 3600, block_cycle_threshold: 3, block_cycle_window_secs: 86_400 }
    }
}

impl KanbanConfig {
    /// Whether `name` may be spawned as a worker (any name when no profiles are configured).
    pub fn profile_exists(&self, name: &str) -> bool {
        self.profiles.is_empty() || self.profiles.contains_key(name)
    }
}

// ───────────────────────── paths & board slugs ─────────────────────────

pub fn kanban_home(data: &Path) -> PathBuf {
    data.join("kanban")
}
pub fn boards_root(data: &Path) -> PathBuf {
    kanban_home(data).join("boards")
}
pub fn board_dir(data: &Path, slug: &str) -> PathBuf {
    boards_root(data).join(slug)
}
pub fn attachments_dir(data: &Path, slug: &str, task: &str) -> PathBuf {
    board_dir(data, slug).join("attachments").join(task)
}
pub fn workspaces_root(data: &Path, slug: &str) -> PathBuf {
    board_dir(data, slug).join("workspaces")
}
pub fn worker_log_path(data: &Path, slug: &str, task: &str) -> PathBuf {
    board_dir(data, slug).join("logs").join(format!("{task}.log"))
}

/// Lower-case slug `[a-z0-9][a-z0-9-_]{0,63}`; `None` for empty input.
pub fn normalize_slug(raw: Option<&str>) -> Result<Option<String>, String> {
    let Some(s) = raw.map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()) else { return Ok(None) };
    let ok = s.len() <= 64 && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric()) && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !ok {
        return Err(format!("invalid board slug {s:?}: use lowercase letters, digits, '-' or '_' (max 64, starting with a letter or digit)"));
    }
    Ok(Some(s))
}

/// The active board: `$SEAGENT_KANBAN_BOARD`, else the `current` pointer, else `default`.
pub fn current_board(data: &Path) -> String {
    if let Ok(Some(s)) = normalize_slug(std::env::var("SEAGENT_KANBAN_BOARD").ok().as_deref()) {
        return s;
    }
    let p = kanban_home(data).join("current");
    match std::fs::read_to_string(&p).ok().and_then(|s| normalize_slug(Some(&s)).ok().flatten()) {
        Some(s) if board_dir(data, &s).join("board.json").exists() || s == DEFAULT_BOARD => s,
        _ => DEFAULT_BOARD.into(),
    }
}

pub fn set_current_board(data: &Path, slug: &str) -> Result<(), String> {
    let p = kanban_home(data).join("current");
    crate::util::atomic_write(&p, slug.as_bytes()).map_err(|e| e.to_string())
}

/// Explicit slug or the active board; errors on a malformed slug.
pub fn resolve_board(data: &Path, board: Option<&str>) -> Result<String, String> {
    Ok(normalize_slug(board)?.unwrap_or_else(|| current_board(data)))
}

// ───────────────────────── kernel handle ─────────────────────────

static KERNEL: RwLock<Option<Weak<Runtime>>> = RwLock::new(None);

/// Give the board engine access to the kernel (judge / sampling, live sessions).
pub fn attach(k: &Kernel) {
    *KERNEL.write().unwrap() = Some(std::sync::Arc::downgrade(k));
}
pub fn kernel() -> Option<Kernel> {
    KERNEL.read().unwrap().as_ref().and_then(Weak::upgrade)
}

// ───────────────────────── process identity ─────────────────────────

/// `/proc/sys/kernel/hostname`, then `/etc/hostname` on Linux (the platform layer reads the
/// same files); `gethostname` / `GetComputerNameExW` elsewhere; `"localhost"` when unknown.
pub fn hostname() -> String {
    seagent_core::platform::sysinfo::hostname()
}
/// Every claim issued on this host starts with this.
pub fn host_prefix() -> String {
    format!("{}:", hostname())
}
/// `host:pid` claim lock for workers this process owns.
pub fn claimer_id() -> String {
    format!("{}{}", host_prefix(), std::process::id())
}
#[cfg(unix)]
pub fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: signal 0 only checks existence/permission.
    let r = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if r == 0 {
        // A zombie has exited even though kill(0) succeeds.
        return !std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| s.rsplit(')').next().is_some_and(|r| r.trim_start().starts_with('Z')));
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}
/// Windows: `OpenProcess` + exit code (a process we may not open counts as alive, like EPERM).
#[cfg(not(unix))]
pub fn pid_alive(pid: u32) -> bool {
    pid != 0 && seagent_core::platform::proc::alive(pid as i32)
}
/// Process start time (clock ticks since boot): tells our process from a recycled pid.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn process_birth(pid: u32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    s.rsplit(')').next()?.split_whitespace().nth(19)?.parse().ok()
}
/// Process start time as the platform layer's opaque token (macOS: µs since the epoch;
/// Windows: creation FILETIME): tells our process from a recycled pid.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn process_birth(pid: u32) -> Option<u64> {
    seagent_core::platform::proc::start_time(pid as i32)
}
/// Live and the same process that was recorded (birth matches when known).
pub fn process_alive(pid: u32, birth: Option<u64>) -> bool {
    pid_alive(pid) && birth.is_none_or(|b| process_birth(pid) == Some(b))
}

pub fn now() -> i64 {
    crate::util::unix_now()
}

/// `{"ok": true, ...}` / tool-error JSON shared by both tool vocabularies.
pub fn tool_error(msg: impl Into<String>) -> String {
    serde_json::json!({ "error": msg.into() }).to_string()
}

/// Self-registration (`seagent_core::registry`): the `kanban_*` / `workboard_*` tools, empty unless
/// `[kanban] enabled = true`. The switch is read here, so the board tools are never on a session
/// that did not ask for them.
pub fn register() {
    seagent_core::registry::register_tool_provider("kanban", 500, |env| {
        let cfg = env.config::<crate::config::Config>()?;
        Ok(tools::session_tools(&cfg.kanban))
    });
    seagent_core::registry::register_config_validator("kanban", |cfg, out| {
        let Some(c) = cfg.downcast_ref::<crate::config::Config>() else { return };
        // Values that would make the dispatcher spin or never reclaim a task: refuse them here
        // instead of inside a background tick where nobody sees the message.
        if c.kanban.dispatch_interval_secs == 0 {
            out.push("dispatch_interval_secs must be >= 1 (the dispatcher would spin)".into());
        }
        if c.kanban.failure_limit == 0 {
            out.push("failure_limit must be >= 1 (a task could never be auto-blocked)".into());
        }
        if c.kanban.claim_ttl_secs <= 0 {
            out.push("claim_ttl_secs must be > 0 (claims would be expired on arrival)".into());
        }
    });
}

#[cfg(test)]
mod config_validation {
    use crate::config::Config;

    /// The `[kanban]` table validates itself: `register()` wires the validator into
    /// `Config::validate` through `seagent_core::registry`, so a bad value is reported at load
    /// time with the section name, not from inside a dispatcher tick.
    #[test]
    fn a_broken_kanban_table_names_its_section() {
        super::register();
        let mut cfg = Config::default();
        assert!(cfg.validate().is_ok(), "the defaults stay valid");
        cfg.kanban.dispatch_interval_secs = 0;
        cfg.kanban.claim_ttl_secs = 0;
        let err = cfg.validate().unwrap_err();
        assert!(err.starts_with("kanban: "), "the message names its section: {err}");
        assert!(err.contains("dispatch_interval_secs"), "{err}");
        cfg.kanban.dispatch_interval_secs = 30;
        assert!(cfg.validate().unwrap_err().contains("claim_ttl_secs"));
        cfg.kanban.claim_ttl_secs = 900;
        assert!(cfg.validate().is_ok());
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use seagent_core::*;
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    pub fn data() -> PathBuf {
        let d = seagent_core::tmp::scratch_path(format!("seagent-kanban-{}", crate::util::random_hex(10)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Scripted provider: each step answers one model request (text or tool calls).
    pub struct Scripted {
        pub steps: Mutex<VecDeque<Vec<Block>>>,
        pub seen: Mutex<Vec<ModelRequest>>,
    }
    impl Scripted {
        pub fn text(&self, t: &str) {
            self.steps.lock().unwrap().push_back(vec![Block::text(t)]);
        }
        pub fn call(&self, name: &str, input: serde_json::Value) {
            self.steps.lock().unwrap().push_back(vec![Block::ToolUse { id: format!("tu_{}", crate::util::random_hex(6)), name: name.into(), input }]);
        }
    }
    impl Provider for Scripted {
        fn id(&self) -> &str {
            "fake"
        }
        fn caps(&self, _: &str) -> ModelCaps {
            ModelCaps { context_window: 200_000, max_output: 8192, tools: true, vision: false, explicit_cache: false }
        }
        fn complete(&self, req: &ModelRequest, _: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
            self.seen.lock().unwrap().push(req.clone());
            let content = self.steps.lock().unwrap().pop_front().unwrap_or_else(|| vec![Block::text("(script exhausted)")]);
            let stop = if content.iter().any(|b| matches!(b, Block::ToolUse { .. })) { StopReason::ToolUse } else { StopReason::EndTurn };
            Ok(ModelResponse { message: Message { role: Role::Assistant, content }, stop, usage: Usage::default(), model: "m".into() })
        }
    }
    struct Res(Arc<Scripted>);
    impl crate::kernel::Resolver for Res {
        fn provider(&self, _: &str) -> Result<Arc<dyn Provider>, String> {
            Ok(self.0.clone())
        }
    }

    pub fn kernel(f: impl FnOnce(&mut crate::config::Config)) -> (crate::kernel::Kernel, Arc<Scripted>, PathBuf) {
        build(f, |cfg| super::tools::orchestrator_tools(&cfg.kanban))
    }

    /// A kernel carrying exactly what a real session gets from `wire::tools`:
    /// `[kanban] enabled` → the board tools, otherwise nothing.
    pub fn session_kernel(f: impl FnOnce(&mut crate::config::Config)) -> (crate::kernel::Kernel, Arc<Scripted>, PathBuf) {
        build(f, |cfg| super::tools::session_tools(&cfg.kanban))
    }

    fn build(f: impl FnOnce(&mut crate::config::Config), tools: impl FnOnce(&crate::config::Config) -> Vec<Arc<dyn seagent_core::Tool>>) -> (crate::kernel::Kernel, Arc<Scripted>, PathBuf) {
        let root = data();
        let ws = root.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let paths = crate::config::Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
        let mut cfg = crate::config::Config::default();
        cfg.model.default = "fake/m".into();
        cfg.checkpoint.enabled = false;
        cfg.runner.max_retries = 1;
        f(&mut cfg);
        let p = Arc::new(Scripted { steps: Mutex::new(VecDeque::new()), seen: Mutex::new(vec![]) });
        let tools = tools(&cfg);
        let k = crate::kernel::new_kernel(cfg, paths, Arc::new(Res(p.clone())), tools, Arc::new(crate::vault::Vault::empty()), Arc::new(crate::approver::Policy { allow_privilege: true, allow_egress: true }));
        (k, p, ws)
    }

    struct NoHost;
    impl ToolHost for NoHost {
        fn spawn_agent(&self, _: seagent_core::tool::SpawnRequest, _: &Cancel) -> Result<String, String> {
            Err("no".into())
        }
        fn ask_user(&self, _: &str) -> Result<String, String> {
            Err("no".into())
        }
    }
    pub fn ctx(data: &std::path::Path, session: &str) -> ToolCtx {
        ToolCtx { workspace: data.to_path_buf(), session_id: session.into(), artifacts: data.join("art"), home: data.to_path_buf(), cancel: Cancel::new(), host: Arc::new(NoHost), secrets: Arc::new(|s: &str| s.to_string()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_and_current_board() {
        assert_eq!(normalize_slug(Some(" Atm10-Server ")).unwrap().as_deref(), Some("atm10-server"));
        assert!(normalize_slug(Some("-bad")).is_err());
        assert!(normalize_slug(Some("has space")).is_err());
        assert_eq!(normalize_slug(Some("")).unwrap(), None);
        let d = testutil::data();
        assert_eq!(current_board(&d), "default");
        set_current_board(&d, "ghost").unwrap();
        assert_eq!(current_board(&d), "default", "pointer at a board that does not exist falls back");
        boards::create_board(&d, "proj", Default::default()).unwrap();
        set_current_board(&d, "proj").unwrap();
        assert_eq!(current_board(&d), "proj");
        assert_eq!(resolve_board(&d, Some("Other")).unwrap(), "other");
    }

    #[test]
    fn board_tools_reach_a_session_only_when_enabled() {
        // Off by default: a plain session's kernel carries no board tools at all.
        let (off, _, _) = testutil::session_kernel(|_| {});
        let names: Vec<String> = off.specs().into_iter().map(|s| s.name).collect();
        assert!(!names.iter().any(|n| n.starts_with("kanban_") || n.starts_with("workboard_")), "kanban is opt-in: {names:?}");

        // `[kanban] enabled` offers both vocabularies to the session (Hermes: "offer the
        // orchestrator tools to every session"), with the real descriptions attached.
        let (on, _, _) = testutil::session_kernel(|c| c.kanban.enabled = true);
        let specs = on.specs();
        for n in tools::NAMES.iter().chain(workboard::NAMES.iter()) {
            let s = specs.iter().find(|s| s.name == *n).unwrap_or_else(|| panic!("{n} is not on the session's kernel"));
            assert!(!s.description.trim().is_empty(), "{n} lost its description");
            assert_eq!(s.input_schema["type"], "object", "{n} lost its schema");
        }
        for n in ["kanban_list", "kanban_complete", "workboard_claim"] {
            assert!(specs.iter().find(|s| s.name == n).unwrap().description.len() > 100, "{n} lost its description");
        }
        assert_eq!(specs.iter().filter(|s| s.name.starts_with("kanban_") || s.name.starts_with("workboard_")).count(), tools::NAMES.len() + workboard::NAMES.len());
        // The registration point itself is the gate.
        assert!(tools::session_tools(&KanbanConfig::default()).is_empty());
        assert_eq!(tools::session_tools(&KanbanConfig { enabled: true, ..Default::default() }).len(), tools::NAMES.len() + workboard::NAMES.len());
        // A dispatched worker still gets the mutating subset only.
        let w = tools::worker_tools(&KanbanConfig { enabled: true, ..Default::default() });
        assert!(!w.iter().any(|t| t.spec().name == "kanban_list" || t.spec().name == "workboard_reassign"));
    }

    #[test]
    fn process_identity() {
        let me = std::process::id();
        assert!(pid_alive(me));
        let b = process_birth(me);
        assert!(b.is_some());
        assert!(process_alive(me, b));
        assert!(!process_alive(me, b.map(|x| x + 1)));
        assert!(!pid_alive(0));
        assert!(claimer_id().starts_with(&host_prefix()));
    }
}
