//! Approval policy and state: modes (Hermes manual/smart/off + OpenClaw auto),
//! process `--yolo` and per-session `/yolo`, OpenClaw exec security/ask/askFallback
//! with a per-binary allowlist and safe bins, `/elevated` and `/exec` session
//! overrides, durable "always" grants, the smart-denial circuit breaker, and
//! human-wait accounting.
//!
//! Durable state lives in files under `<data>/approvals/` so the daemon, the CLI and
//! channel commands agree without IPC: `sessions.json` (per-session toggles) and
//! `allowlist.json` (durable grants). Both are re-read when their mtime changes.

use crate::glob::{expand_home, path_glob};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

// ───────────────────────── config ─────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Ask a human for every flagged action (default).
    #[default]
    Manual,
    /// Hermes smart approvals: an aux-model guardian answers APPROVE / DENY / ESCALATE.
    Smart,
    /// OpenClaw exec auto-review: an aux-model reviewer returns allow / deny (with a
    /// reason for the agent) / ask, with a risk level.
    Auto,
    /// Skip approval prompts (floors still apply).
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Unattended {
    #[default]
    Deny,
    Approve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ExecSecurity {
    Deny,
    Allowlist,
    /// No allowlist requirement (seagent's default: only the privilege/egress gates ask).
    #[default]
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum ExecAsk {
    #[default]
    #[serde(rename = "off")]
    Off,
    #[serde(rename = "on-miss")]
    OnMiss,
    #[serde(rename = "always")]
    Always,
}

impl ExecSecurity {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "deny" => Some(Self::Deny),
            "allowlist" => Some(Self::Allowlist),
            "full" => Some(Self::Full),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Allowlist => "allowlist",
            Self::Full => "full",
        }
    }
}

impl ExecAsk {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "on-miss" | "onmiss" | "on_miss" => Some(Self::OnMiss),
            "always" => Some(Self::Always),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::OnMiss => "on-miss",
            Self::Always => "always",
        }
    }
}

/// OpenClaw `minSecurity`: the stricter security.
pub fn min_security(a: ExecSecurity, b: ExecSecurity) -> ExecSecurity {
    a.min(b)
}
/// OpenClaw `maxAsk`: the stricter ask.
pub fn max_ask(a: ExecAsk, b: ExecAsk) -> ExecAsk {
    a.max(b)
}

pub const DEFAULT_SAFE_BINS: &[&str] = &["cut", "uniq", "head", "tail", "tr", "wc"];

fn default_safe_bins() -> Vec<String> {
    DEFAULT_SAFE_BINS.iter().map(|s| s.to_string()).collect()
}

/// `[approvals.exec]` (OpenClaw `tools.exec` / exec-approvals defaults).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExecPolicy {
    pub security: ExecSecurity,
    pub ask: ExecAsk,
    /// When a prompt is needed but nobody can answer (headless) or it timed out.
    pub ask_fallback: ExecSecurity,
    /// Stdin-only filters that pass allowlist mode without entries.
    pub safe_bins: Vec<String>,
    /// Executable path globs (`~/bin/*`, `/usr/bin/rg`, `**/node_modules/.bin/*`) or bare names.
    pub allowlist: Vec<String>,
}

impl Default for ExecPolicy {
    fn default() -> Self {
        ExecPolicy { security: ExecSecurity::Full, ask: ExecAsk::Off, ask_fallback: ExecSecurity::Deny, safe_bins: default_safe_bins(), allowlist: vec![] }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Elevated {
    #[default]
    Off,
    On,
    Ask,
    Full,
}

impl Elevated {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "false" | "no" => Some(Self::Off),
            "on" | "true" | "yes" => Some(Self::On),
            "ask" => Some(Self::Ask),
            "full" => Some(Self::Full),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
            Self::Ask => "ask",
            Self::Full => "full",
        }
    }
}

/// `[approvals.elevated]` (OpenClaw `tools.elevated`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ElevatedConfig {
    pub enabled: bool,
    /// channel → sender ids (or `name:`/`username:` prefixed) allowed to use `/elevated`.
    pub allow_from: BTreeMap<String, Vec<String>>,
    pub default: Elevated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ForwardMode {
    /// The chat the session is bound to.
    #[default]
    Session,
    Targets,
    Both,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ForwardTarget {
    pub channel: String,
    pub to: String,
    pub thread: Option<String>,
}

/// `[approvals.forward]` (OpenClaw `approvals.exec` forwarding).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ForwardConfig {
    pub enabled: bool,
    pub mode: ForwardMode,
    pub targets: Vec<ForwardTarget>,
    /// Only forward approvals of these sessions (id prefixes); empty = all.
    pub session_filter: Vec<String>,
    /// channel → sender ids allowed to answer approvals there. Without a list, the
    /// sender of a direct chat (or the session's own sender) may answer.
    pub approvers: BTreeMap<String, Vec<String>>,
    /// srv-018: channel → sender ids of the *owner*. Only they may answer a tier-3
    /// (irreversible) approval from a chat, and only after a second confirmation; wildcards
    /// never count. Without an entry the explicit (non-`*`) `approvers` of that channel are
    /// used; with neither, tier 3 is answered from the CLI only. Deferred tier-2/3 calls
    /// (cron, unattended sessions) with no chat route are sent to these owners directly.
    pub owners: BTreeMap<String, Vec<String>>,
}

impl Default for ForwardConfig {
    fn default() -> Self {
        ForwardConfig { enabled: true, mode: ForwardMode::Session, targets: vec![], session_filter: vec![], approvers: BTreeMap::new(), owners: BTreeMap::new() }
    }
}

impl ApprovalsConfig {
    /// The preset that applies to a session driven at `trust` (`owner`/`channel`/`stranger`).
    pub fn preset_for(&self, trust: &str) -> crate::risk::Preset {
        self.trust_presets.get(trust).copied().unwrap_or(if trust == "stranger" { crate::risk::Preset::Strict } else { self.preset })
    }
}

impl ForwardConfig {
    /// Owner ids for `channel` (explicit `owners`, else explicit non-wildcard `approvers`).
    pub fn owners_of(&self, channel: &str) -> Vec<String> {
        let pick = |m: &BTreeMap<String, Vec<String>>| m.get(channel).map(|l| l.iter().filter(|x| !x.trim().is_empty() && x.as_str() != "*").cloned().collect::<Vec<_>>()).filter(|l| !l.is_empty());
        pick(&self.owners).or_else(|| pick(&self.approvers)).unwrap_or_default()
    }
    /// Is `sender` the owner on `channel` (tier-3 approvals)?
    pub fn is_owner(&self, channel: &str, sender: &str) -> bool {
        !sender.is_empty() && self.owners_of(channel).iter().any(|x| x == sender)
    }
}

/// `[approvals]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApprovalsConfig {
    pub mode: Mode,
    /// Seconds a pending approval waits for a human before failing closed.
    pub timeout_secs: u64,
    /// Command globs that never run, even under yolo / mode = "off".
    pub deny: Vec<String>,
    /// Command text / globs that never prompt (Hermes `command_allowlist`).
    pub allowlist: Vec<String>,
    /// Trusted operator rules appended to the smart/auto reviewer's system prompt.
    pub smart_policy: String,
    pub reviewer_timeout_secs: u64,
    /// Consecutive reviewer denials before the hard-stop note (0 = off).
    pub denial_breaker_threshold: u32,
    /// Interpreter one-liners (`python -c`, `node -e`…) always need approval.
    pub strict_inline_eval: bool,
    /// Flagged actions in scheduled jobs (nobody present).
    pub cron_mode: Unattended,
    /// Flagged actions in sessions driven by webhook / API sources (nobody present).
    pub unattended_mode: Unattended,
    /// Memory writes are staged for `seagent memory review` instead of applied.
    pub memory_write_approval: bool,
    /// Skill writes need approval (staged when nobody can answer).
    pub skill_write_approval: bool,
    /// How long an "allow always" grant lasts before the question is asked again
    /// (§0-2 #02: no permanent global grants). 0 = grants never expire (discouraged).
    pub grant_ttl_days: u64,
    /// `[security.risk] preset`: relaxed | standard | strict (§0-2 #10).
    pub preset: crate::risk::Preset,
    /// Tier 3 has no unattended approval path: when nobody answers a tier-3 ask, the
    /// call is refused *for that branch* and the refusal text suggests a reversible
    /// alternative (§0-2 #04).
    pub tier3_fallback: bool,
    /// gen2-412 (§0-2 #08): the risk preset per trust level of whoever drives the session —
    /// `owner` (CLI/TUI/schedule, or a chat sender listed in `forward.owners`), `channel`
    /// (another person on a connected chat), `stranger` (webhooks, e-mail and other
    /// untrusted inbound channels). Missing entries: `owner`/`channel` use `preset`,
    /// `stranger` defaults to `strict`. Tier 3 stays the hard floor whatever is set.
    pub trust_presets: BTreeMap<String, crate::risk::Preset>,
    /// gen2-413 (§0-2 #09): `seagent doctor` warns when the owner was asked more than this many
    /// times a day on average over the last 7 days (0 = never warn).
    pub fatigue_daily_asks: u32,
    pub exec: ExecPolicy,
    pub elevated: ElevatedConfig,
    pub forward: ForwardConfig,
    /// Four-eyes approval for selected high-risk actions (`[approvals.dual_control]`).
    #[serde(skip_serializing_if = "crate::dual_control::DualControlConfig::is_default")]
    pub dual_control: crate::dual_control::DualControlConfig,
}

impl Default for ApprovalsConfig {
    fn default() -> Self {
        ApprovalsConfig {
            mode: Mode::Manual,
            timeout_secs: 600,
            deny: vec![],
            allowlist: vec![],
            smart_policy: String::new(),
            reviewer_timeout_secs: 30,
            denial_breaker_threshold: 3,
            strict_inline_eval: false,
            cron_mode: Unattended::Deny,
            unattended_mode: Unattended::Deny,
            memory_write_approval: false,
            skill_write_approval: false,
            grant_ttl_days: 7,
            preset: crate::risk::Preset::Standard,
            tier3_fallback: true,
            trust_presets: BTreeMap::new(),
            fatigue_daily_asks: 30,
            exec: ExecPolicy::default(),
            elevated: ElevatedConfig::default(),
            forward: ForwardConfig::default(),
            dual_control: Default::default(),
        }
    }
}

// ───────────────────────── yolo (process) ─────────────────────────

static PROCESS_YOLO: OnceLock<bool> = OnceLock::new();

/// Freeze the process-wide `--yolo` (or `SEAGENT_YOLO=1`) once at startup. Later calls and
/// later environment changes have no effect (a skill setting the variable mid-run
/// must not lift every approval).
pub fn freeze_process_yolo(flag: bool) -> bool {
    *PROCESS_YOLO.get_or_init(|| flag || std::env::var("SEAGENT_YOLO").is_ok_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")))
}

pub fn process_yolo() -> bool {
    *PROCESS_YOLO.get_or_init(|| std::env::var("SEAGENT_YOLO").is_ok_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")))
}

// ───────────────────────── session state file ─────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecOverride {
    pub host: Option<String>,
    pub node: Option<String>,
    pub security: Option<ExecSecurity>,
    pub ask: Option<ExecAsk>,
    /// `security`/`ask` apply only while the session's completed-turn count equals this.
    pub for_turn: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionState {
    pub yolo: bool,
    pub elevated: Option<Elevated>,
    pub exec: ExecOverride,
}

fn dir(data: &Path) -> PathBuf {
    data.join("approvals")
}

#[derive(Default)]
struct FileCache<T> {
    path: PathBuf,
    mtime: Option<SystemTime>,
    len: u64,
    value: T,
}

fn cached<T: Default + Clone + for<'de> Deserialize<'de>>(slot: &Mutex<Option<FileCache<T>>>, path: PathBuf) -> T {
    let meta = std::fs::metadata(&path).ok();
    let (mtime, len) = (meta.as_ref().and_then(|m| m.modified().ok()), meta.as_ref().map(|m| m.len()).unwrap_or(0));
    let mut g = slot.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(c) = g.as_ref() {
        if c.path == path && c.mtime == mtime && c.len == len && mtime.is_some() {
            return c.value.clone();
        }
    }
    let value: T = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    *g = Some(FileCache { path, mtime, len, value: value.clone() });
    value
}

fn write_json<T: Serialize>(path: &Path, v: &T) -> Result<(), String> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700));
        }
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, serde_json::to_string_pretty(v).unwrap_or_default()).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

static SESSIONS: Mutex<Option<FileCache<BTreeMap<String, SessionState>>>> = Mutex::new(None);
static FILE_LOCK: Mutex<()> = Mutex::new(());

pub fn sessions_path(data: &Path) -> PathBuf {
    dir(data).join("sessions.json")
}

pub fn session_state(data: &Path, session: &str) -> SessionState {
    cached(&SESSIONS, sessions_path(data)).get(session).cloned().unwrap_or_default()
}

/// Read-modify-write one session's state (removes it when back to defaults).
pub fn update_session(data: &Path, session: &str, f: impl FnOnce(&mut SessionState)) -> Result<SessionState, String> {
    let _g = FILE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = sessions_path(data);
    let mut all: BTreeMap<String, SessionState> = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    let mut st = all.remove(session).unwrap_or_default();
    f(&mut st);
    if st != SessionState::default() {
        all.insert(session.to_string(), st.clone());
    }
    write_json(&path, &all)?;
    Ok(st)
}

/// Move a session's toggles to a new id (branch / fork) — Hermes `transfer_session_yolo`.
pub fn transfer_session(data: &Path, old: &str, new: &str) -> Result<(), String> {
    let st = session_state(data, old);
    if st == SessionState::default() || old == new {
        return Ok(());
    }
    update_session(data, new, |s| *s = st.clone())?;
    Ok(())
}

pub fn clear_session(data: &Path, session: &str) {
    let _ = update_session(data, session, |s| *s = SessionState::default());
    denials().lock().unwrap_or_else(|p| p.into_inner()).remove(session);
}

/// Hermes `toggle_session_yolo`: flip (None) or set; returns the new state.
pub fn set_session_yolo(data: &Path, session: &str, on: Option<bool>) -> Result<bool, String> {
    let st = update_session(data, session, |s| s.yolo = on.unwrap_or(!s.yolo))?;
    Ok(st.yolo)
}

pub fn yolo_active(data: &Path, session: &str) -> bool {
    process_yolo() || session_state(data, session).yolo
}

pub fn elevated_level(cfg: &ApprovalsConfig, data: &Path, session: &str) -> Elevated {
    if !cfg.elevated.enabled {
        return Elevated::Off;
    }
    session_state(data, session).elevated.unwrap_or(cfg.elevated.default)
}

/// One memory write the approval pipeline stages for `seagent memory review` / `accept`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MemoryWrite {
    /// `add` | `replace` | `patch` | `remove`.
    pub action: String,
    pub text: Option<String>,
    /// Unique substring (or the whole entry) a replace / patch / remove selects.
    pub old: Option<String>,
}

/// Split a memory file into its entries (the store's `§` separator).
fn memory_entries(text: &str) -> Vec<String> {
    text.split("\n§\n").map(|e| e.trim().to_string()).filter(|e| !e.is_empty()).collect()
}

/// The single entry `old` selects: an exact entry, else the only entry containing it.
fn memory_find_one(entries: &[String], old: &str) -> Result<usize, String> {
    let needle = old.trim();
    if needle.is_empty() {
        return Err("no unique entry matching `old`: `old` must not be empty".into());
    }
    if let Some(i) = entries.iter().position(|e| e == needle) {
        return Ok(i);
    }
    let hits: Vec<usize> = entries.iter().enumerate().filter(|(_, e)| e.contains(needle)).map(|(i, _)| i).collect();
    match hits.len() {
        1 => Ok(hits[0]),
        n => Err(format!("no unique entry matching `old`: `{needle}` {}", if n == 0 { "appears in no entry (use action=read to see them)".to_string() } else { format!("appears in {n} entries; give a longer substring") })),
    }
}

fn stage_seq() -> u32 {
    static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 10000
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

/// Stage memory writes for the user's approval (`approvals.memory_write_approval`) and return
/// the staged file's path. Nothing is written to `MEMORY.md` / `USER.md` here.
///
/// The record's shape **must match** `seagent_tools::memory_store::apply_staged`
/// (`crates/seagent-tools/src/memory.rs`), which `seagent memory accept` replays:
/// * pure adds → `{"session", "origin", "created_ms", "memory"|"user": [text, …], "summary"}`;
/// * anything else (replace / patch / remove / a batch) →
///   `{"session", "origin", "created_ms", "ops": {"file", "operations": [{action, text, old, matched_entry}]}, "summary"}`.
///   `apply_staged` refuses destructive operations without `matched_entry`, so every
///   replace / patch / remove pins the whole entry it selected (what the user reviews is what
///   gets applied). Files go to `<data>/memory/staging/<ms:013>-<pid:x><seq:04>.json`, the same
///   naming and directory `seagent-tools` uses, so both stagers land in one review queue.
pub fn stage_memory_write(data_dir: &Path, session: &str, file: &str, action: &str, text: &str, old: Option<&str>) -> Result<PathBuf, String> {
    stage_memory_writes(data_dir, session, file, &[MemoryWrite { action: action.into(), text: Some(text.into()), old: old.map(str::to_string) }])
}

/// [`stage_memory_write`] for a batch: one staged file, operations applied atomically by
/// `apply_staged`.
pub fn stage_memory_writes(data_dir: &Path, session: &str, file: &str, ops: &[MemoryWrite]) -> Result<PathBuf, String> {
    let file = match file {
        "user" => "user",
        _ => "memory",
    };
    if ops.is_empty() {
        return Err("no memory operation to stage".into());
    }
    let store = data_dir.join("memory").join(if file == "user" { "USER.md" } else { "MEMORY.md" });
    let mut working = memory_entries(&std::fs::read_to_string(&store).unwrap_or_default());
    let mut operations = Vec::with_capacity(ops.len());
    let mut summary = Vec::with_capacity(ops.len());
    for op in ops {
        if !matches!(op.action.as_str(), "add" | "replace" | "patch" | "remove") {
            return Err(format!("unknown action `{}`: use add, replace, patch or remove", op.action));
        }
        let text = op.text.as_deref().unwrap_or("").trim().to_string();
        let old = op.old.as_deref().unwrap_or("").trim().to_string();
        if op.action != "add" && op.action != "remove" && text.is_empty() {
            return Err(format!("`text` is required for {}", op.action));
        }
        let mut rec = json!({"action": op.action});
        if !text.is_empty() {
            rec["text"] = json!(text);
        }
        if !old.is_empty() {
            rec["old"] = json!(old);
        }
        if op.action != "add" {
            let i = memory_find_one(&working, &old)?;
            rec["matched_entry"] = json!(working[i]);
            match op.action.as_str() {
                "remove" => {
                    working.remove(i);
                }
                "replace" => working[i].clone_from(&text),
                _ => working[i] = working[i].replacen(&old, &text, 1).trim().to_string(),
            }
        } else if !working.iter().any(|e| e == &text) {
            working.push(text.clone());
        }
        summary.push(format!("{} {}", op.action, if text.is_empty() { old.as_str() } else { text.as_str() }));
        operations.push(rec);
    }
    let ms = now_ms();
    let mut record = json!({"session": session, "origin": "foreground", "created_ms": ms as u64});
    if operations.iter().all(|o| o["action"] == "add") {
        record[file] = serde_json::Value::Array(operations.iter().map(|o| o["text"].clone()).collect());
    } else {
        record["ops"] = json!({"file": file, "operations": operations});
    }
    record["summary"] = json!(summary.join("; ").chars().take(200).collect::<String>());
    let dir = data_dir.join("memory/staging");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let id = format!("{:013}-{:x}{:04}", ms, std::process::id(), stage_seq());
    let path = dir.join(format!("{id}.json"));
    let tmp = dir.join(format!("{id}.tmp"));
    std::fs::write(&tmp, record.to_string()).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

/// Effective exec security / ask for a session turn: config tightened by a `/exec` override
/// (overrides can only tighten).
pub fn effective_exec(cfg: &ApprovalsConfig, data: &Path, session: &str, completed_turns: u64) -> (ExecSecurity, ExecAsk) {
    let o = session_state(data, session).exec;
    let live = match o.for_turn {
        Some(t) => t == completed_turns,
        None => true,
    };
    let sec = match (live, o.security) {
        (true, Some(s)) => min_security(cfg.exec.security, s),
        _ => cfg.exec.security,
    };
    let ask = match (live, o.ask) {
        (true, Some(a)) => max_ask(cfg.exec.ask, a),
        _ => cfg.exec.ask,
    };
    (sec, ask)
}

/// OpenClaw elevated allowlist: `allow_from.<channel>` entries match the sender id, or
/// `name:` / `username:` / `id:` prefixed identities.
pub fn sender_allowed(list: &BTreeMap<String, Vec<String>>, channel: &str, sender: &str, sender_name: &str) -> bool {
    let Some(l) = list.get(channel).or_else(|| list.get("*")) else { return false };
    l.iter().any(|e| {
        let e = e.trim();
        e == "*" || e == sender || e.strip_prefix("id:").or_else(|| e.strip_prefix("from:")).or_else(|| e.strip_prefix("e164:")).is_some_and(|x| x == sender) || e.strip_prefix("name:").or_else(|| e.strip_prefix("username:")).is_some_and(|x| !sender_name.is_empty() && x.eq_ignore_ascii_case(sender_name))
    })
}

// ───────────────────────── durable allowlist ─────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GrantKind {
    /// A gate finding (`gate` + exact `reason`) approved "always".
    Gate,
    /// An executable path glob for exec allowlist mode.
    Exec,
    /// Command text / glob that never prompts.
    Command,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    pub kind: GrantKind,
    pub pattern: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate: Option<String>,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub added_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_command: Option<String>,
    /// Unix seconds after which the grant no longer applies (§0-2 #02).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl Grant {
    pub fn expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|e| now >= e)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowFile {
    pub version: u32,
    pub grants: Vec<Grant>,
}

static ALLOW: Mutex<Option<FileCache<AllowFile>>> = Mutex::new(None);

pub fn allowlist_path(data: &Path) -> PathBuf {
    dir(data).join("allowlist.json")
}

pub fn grants(data: &Path) -> Vec<Grant> {
    let now = unix_now();
    cached(&ALLOW, allowlist_path(data)).grants.into_iter().filter(|g| !g.expired(now)).collect()
}

/// Every grant on disk, including expired ones (`seagent approvals list --all`).
pub fn grants_with_expired(data: &Path) -> Vec<Grant> {
    cached(&ALLOW, allowlist_path(data)).grants
}

/// Default lifetime of a durable grant (§0-2 #02).
pub const DEFAULT_GRANT_TTL_DAYS: u64 = 7;

fn unix_now() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn new_id() -> String {
    let mut b = [0u8; 6];
    let _ = crate::os::fill_random(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Add a durable grant (deduplicated); returns its id. Lives `DEFAULT_GRANT_TTL_DAYS`.
pub fn add_grant(data: &Path, kind: GrantKind, pattern: &str, gate: Option<&str>, source: &str) -> Result<String, String> {
    add_grant_ttl(data, kind, pattern, gate, source, Some(DEFAULT_GRANT_TTL_DAYS))
}

/// Add a durable grant with an explicit lifetime in days (`None` = never expires).
pub fn add_grant_ttl(data: &Path, kind: GrantKind, pattern: &str, gate: Option<&str>, source: &str, ttl_days: Option<u64>) -> Result<String, String> {
    let _g = FILE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = allowlist_path(data);
    let mut f: AllowFile = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    f.version = 1;
    if let Some(g) = f.grants.iter().find(|g| g.kind == kind && g.pattern == pattern && g.gate.as_deref() == gate) {
        return Ok(g.id.clone());
    }
    let id = new_id();
    let now = unix_now();
    let expires_at = ttl_days.filter(|d| *d > 0).map(|d| now.saturating_add(d.saturating_mul(86_400)));
    f.grants.push(Grant { id: id.clone(), kind, pattern: pattern.to_string(), gate: gate.map(String::from), source: source.to_string(), added_at: now, last_used_at: None, last_used_command: None, expires_at });
    write_json(&path, &f)?;
    Ok(id)
}

/// Remove grants by id or exact pattern; returns how many were removed.
pub fn remove_grant(data: &Path, key: &str) -> Result<usize, String> {
    let _g = FILE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = allowlist_path(data);
    let mut f: AllowFile = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    let before = f.grants.len();
    f.grants.retain(|g| g.id != key && g.pattern != key);
    let n = before - f.grants.len();
    if n > 0 {
        write_json(&path, &f)?;
    }
    Ok(n)
}

/// Record use of a grant (OpenClaw `lastUsedAt` / `lastUsedCommand`). Best effort.
pub fn touch_grant(data: &Path, id: &str, command: &str) {
    let _g = FILE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = allowlist_path(data);
    let Some(mut f) = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str::<AllowFile>(&s).ok()) else { return };
    if let Some(g) = f.grants.iter_mut().find(|g| g.id == id) {
        g.last_used_at = Some(unix_now());
        g.last_used_command = Some(command.chars().take(300).collect());
        let _ = write_json(&path, &f);
    }
}

pub fn gate_granted(data: &Path, gate: &str, reason: &str) -> Option<Grant> {
    grants(data).into_iter().find(|g| g.kind == GrantKind::Gate && g.gate.as_deref() == Some(gate) && g.pattern == reason)
}

pub fn command_granted(cfg: &ApprovalsConfig, data: &Path, command: &str) -> Option<String> {
    let mut pats: Vec<String> = cfg.allowlist.clone();
    pats.extend(grants(data).into_iter().filter(|g| g.kind == GrantKind::Command).map(|g| g.pattern));
    crate::hardline::matches_command_allowlist(command, &pats)
}

// ───────────────────────── exec allowlist evaluation ─────────────────────────

/// Builtins that cannot run external code (OpenClaw `DEFAULT_SAFE_BUILTINS`).
pub const SAFE_BUILTINS: &[&str] = &[":", "cd", "false", "pwd", "test", "true", "["];

/// Predicate builtins whose operands the shell may re-evaluate as grammar. Bash >= 4.2
/// evaluates the array subscript of a `test -v` operand even inside single quotes, so
/// `test -v 'a[$(cmd)]'` runs `cmd`; ANSI-C (`$'…'`) operands can rebuild the same text
/// after quoting. These never get the closed safe-builtin exemption.
fn safe_predicate_ok(argv: &[String], raw: Option<&str>) -> bool {
    let head = argv.first().map(|a| a.as_str()).unwrap_or("");
    if head == "[" && argv.last().map(|a| a.as_str()) != Some("]") {
        return false;
    }
    // `-v` (bash array test) and `-R` (zsh conditional) take an operand the shell parses.
    if argv.iter().skip(1).any(|a| {
        let a = a.trim();
        a == "-v" || a == "-R"
    }) {
        return false;
    }
    // ANSI-C quoting can reassemble glob/subscript text after our lexer has run.
    if raw.is_some_and(|r| r.contains("$'")) {
        return false;
    }
    let end = if head == "[" { argv.len().saturating_sub(1) } else { argv.len() };
    for a in &argv[1.min(end)..end] {
        if a.chars().any(|c| "\\$`*?{}[]".contains(c)) {
            return false;
        }
    }
    true
}

/// Is this argv the closed safe-builtin form? `raw` is the original command source when
/// available, so quoting the parsed argv cannot hide dynamic text.
pub fn safe_builtin_ok(argv: &[String], raw: Option<&str>) -> bool {
    let Some(first) = argv.first() else { return false };
    let name = first.rsplit('/').next().unwrap_or(first);
    if !SAFE_BUILTINS.contains(&name) {
        return false;
    }
    if name == "test" || name == "[" {
        return safe_predicate_ok(argv, raw);
    }
    true
}

struct SafeBinProfile {
    min_positional: usize,
    max_positional: usize,
    value_flags: &'static [&'static str],
    bool_flags: &'static [&'static str],
    denied: &'static [&'static str],
}

fn safe_bin_profile(bin: &str) -> Option<SafeBinProfile> {
    const HT_BOOL: &[&str] = &["--quiet", "--silent", "--verbose", "--zero-terminated", "-q", "-v", "-z"];
    Some(match bin {
        "jq" => SafeBinProfile { min_positional: 0, max_positional: 1, value_flags: &["--arg", "--argjson", "--argstr"], bool_flags: &["-r", "-c", "-e", "-s", "-n", "-j", "-a", "-S", "-C", "-M", "--raw-output", "--compact-output", "--slurp", "--null-input", "--sort-keys", "--exit-status", "--join-output", "--ascii-output", "--tab", "--indent"], denied: &["--argfile", "--rawfile", "--slurpfile", "--from-file", "--library-path", "-L", "-f"] },
        "grep" => SafeBinProfile { min_positional: 0, max_positional: 0, value_flags: &["--regexp", "--max-count", "--after-context", "--before-context", "--context", "--devices", "--binary-files", "--exclude", "--include", "--label", "-e", "-m", "-A", "-B", "-C", "-D"], bool_flags: &["-i", "-v", "-c", "-n", "-o", "-q", "-s", "-w", "-x", "-E", "-F", "-G", "-P", "-h", "-H", "--ignore-case", "--invert-match", "--count", "--line-number", "--only-matching", "--quiet", "--word-regexp", "--line-regexp", "--extended-regexp", "--fixed-strings"], denied: &["--file", "--exclude-from", "--dereference-recursive", "--directories", "--recursive", "-f", "-d", "-r", "-R"] },
        "cut" => SafeBinProfile { min_positional: 0, max_positional: 0, value_flags: &["--bytes", "--characters", "--fields", "--delimiter", "--output-delimiter", "-b", "-c", "-f", "-d"], bool_flags: &["--complement", "--only-delimited", "--zero-terminated", "-n", "-s", "-z"], denied: &[] },
        "sort" => SafeBinProfile { min_positional: 0, max_positional: 0, value_flags: &["--key", "--field-separator", "--buffer-size", "--parallel", "--batch-size", "-k", "-t", "-S"], bool_flags: &["-r", "-n", "-u", "-f", "-b", "-h", "-V", "-s", "-z", "--reverse", "--numeric-sort", "--unique", "--ignore-case", "--human-numeric-sort", "--version-sort", "--stable"], denied: &["--compress-program", "--files0-from", "--output", "--random-source", "--temporary-directory", "-T", "-o"] },
        "uniq" => SafeBinProfile { min_positional: 0, max_positional: 0, value_flags: &["--skip-fields", "--skip-chars", "--check-chars", "--group", "-f", "-s", "-w"], bool_flags: &["--count", "--repeated", "--unique", "--ignore-case", "--zero-terminated", "-c", "-d", "-u", "-i", "-z"], denied: &[] },
        "head" => SafeBinProfile { min_positional: 0, max_positional: 0, value_flags: &["--lines", "--bytes", "-n", "-c"], bool_flags: HT_BOOL, denied: &[] },
        "tail" => SafeBinProfile { min_positional: 0, max_positional: 0, value_flags: &["--lines", "--bytes", "--sleep-interval", "--max-unchanged-stats", "--pid", "-n", "-c"], bool_flags: HT_BOOL, denied: &["--follow", "--retry", "-F", "-f"] },
        "tr" => SafeBinProfile { min_positional: 1, max_positional: 2, value_flags: &[], bool_flags: &["--complement", "--delete", "--squeeze-repeats", "--truncate-set1", "-C", "-c", "-d", "-s", "-t"], denied: &[] },
        "wc" => SafeBinProfile { min_positional: 0, max_positional: 0, value_flags: &[], bool_flags: &["--bytes", "--chars", "--lines", "--max-line-length", "--words", "-L", "-c", "-l", "-m", "-w"], denied: &["--files0-from"] },
        _ => return None,
    })
}

/// A safe-bin invocation stays stdin-only: no file operands, no path-like tokens, known flags only.
pub fn safe_bin_ok(argv: &[String], safe_bins: &[String]) -> bool {
    let Some(name) = argv.first().map(|a| a.rsplit('/').next().unwrap_or(a)) else { return false };
    if !safe_bins.iter().any(|b| b == name) {
        return false;
    }
    let Some(p) = safe_bin_profile(name) else { return false };
    let mut positional = 0;
    let mut i = 1;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "--" {
            positional += argv.len() - i - 1;
            if argv[i + 1..].iter().any(|x| x.contains('/')) {
                return false;
            }
            break;
        }
        if a.starts_with('-') && a.len() > 1 {
            let (flag, has_val) = match a.split_once('=') {
                Some((f, _)) => (f, true),
                None => (a, false),
            };
            if p.denied.contains(&flag) || p.denied.iter().any(|d| d.len() == 2 && !flag.starts_with("--") && flag.len() > 2 && flag[1..].contains(&d[1..])) {
                return false;
            }
            if p.value_flags.contains(&flag) {
                if !has_val {
                    i += 1;
                }
            } else if !p.bool_flags.contains(&flag) {
                // Short-flag bundle of known booleans (`wc -lw`), or an attached value (`head -n5`).
                let attached = flag.len() > 2 && !flag.starts_with("--") && p.value_flags.contains(&&flag[..2]);
                let bundle = flag.len() > 2 && !flag.starts_with("--") && flag[1..].chars().all(|c| p.bool_flags.contains(&format!("-{c}").as_str()));
                if !attached && !bundle {
                    return false;
                }
            }
        } else {
            if a.contains('/') || a.starts_with('~') || a == "." || a == ".." {
                return false;
            }
            positional += 1;
        }
        i += 1;
    }
    (p.min_positional..=p.max_positional).contains(&positional)
}

/// Resolve a command name on PATH (absolute / relative paths pass through).
pub fn resolve_executable(name: &str, cwd: &Path) -> Option<PathBuf> {
    if name.contains('/') {
        let p = if Path::new(name).is_absolute() { PathBuf::from(name) } else { cwd.join(name) };
        return Some(crate::paths::realpath(&p));
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(name)).find(|p| p.is_file()).map(|p| crate::paths::realpath(&p))
}

/// Does one simple command satisfy the exec allowlist? Returns the matching rule.
/// `raw` is the original command source (when the parser has it), used to refuse a
/// safe-builtin exemption for dynamic predicate operands.
pub fn exec_allowlisted(argv: &[String], raw: Option<&str>, cfg: &ApprovalsConfig, data: &Path, cwd: &Path) -> Option<String> {
    let first = argv.first()?;
    let name = first.rsplit('/').next().unwrap_or(first);
    if safe_builtin_ok(argv, raw) {
        return Some(format!("safe builtin `{name}`"));
    }
    if safe_bin_ok(argv, &cfg.exec.safe_bins) {
        return Some(format!("safe bin `{name}`"));
    }
    let resolved = resolve_executable(first, cwd);
    let mut pats: Vec<(Option<String>, String)> = cfg.exec.allowlist.iter().map(|p| (None, p.clone())).collect();
    pats.extend(grants(data).into_iter().filter(|g| g.kind == GrantKind::Exec).map(|g| (Some(g.id), g.pattern)));
    for (id, p) in pats {
        let p = p.trim().to_string();
        let hit = if !p.contains('/') && !p.starts_with('~') {
            // Bare names match the command name (OpenClaw matches the resolved name too).
            crate::glob::fnmatch(&p, name)
        } else {
            resolved.as_ref().is_some_and(|r| path_glob(&p, &r.to_string_lossy())) || path_glob(&expand_home(&p), first)
        };
        if hit {
            if let Some(id) = id {
                touch_grant(data, &id, &argv.join(" "));
            }
            return Some(p);
        }
    }
    None
}

// ───────────────────────── denial breaker ─────────────────────────

fn denials() -> &'static Mutex<HashMap<String, u32>> {
    static D: OnceLock<Mutex<HashMap<String, u32>>> = OnceLock::new();
    D.get_or_init(Default::default)
}

/// Count one more consecutive reviewer denial; returns the tally.
pub fn record_denial(session: &str) -> u32 {
    let mut m = denials().lock().unwrap_or_else(|p| p.into_inner());
    if m.len() > 256 && !m.contains_key(session) {
        if let Some(k) = m.keys().next().cloned() {
            m.remove(&k);
        }
    }
    let n = m.entry(session.to_string()).or_insert(0);
    *n += 1;
    *n
}

pub fn reset_denials(session: &str) {
    denials().lock().unwrap_or_else(|p| p.into_inner()).remove(session);
}

/// Hard-stop text once the breaker tripped, else "".
pub fn breaker_addendum(session: &str, threshold: u32) -> String {
    let n = denials().lock().unwrap_or_else(|p| p.into_inner()).get(session).copied().unwrap_or(0);
    if threshold == 0 || n < threshold {
        return String::new();
    }
    format!(" CIRCUIT BREAKER: {n} consecutive commands were blocked by the security reviewer. STOP attempting variations of this operation. Report the blocked operation to the user and either ask them to run it manually or use /approve.")
}

// ───────────────────────── human wait ─────────────────────────

#[derive(Default)]
struct Wait {
    pending: u32,
    started: Option<Instant>,
    completed: Duration,
}

fn waits() -> &'static Mutex<HashMap<String, Wait>> {
    static W: OnceLock<Mutex<HashMap<String, Wait>>> = OnceLock::new();
    W.get_or_init(Default::default)
}

/// Marks time spent blocked on a human; the wall-clock budget excludes it. Overlapping
/// windows coalesce; each window contributes at most `ceiling` (timeout + 60 s).
pub struct HumanWait {
    session: String,
    ceiling: Duration,
}

pub fn human_wait(session: &str, timeout: Duration) -> HumanWait {
    let mut m = waits().lock().unwrap_or_else(|p| p.into_inner());
    if m.len() >= 256 && !m.contains_key(session) {
        let idle: Vec<String> = m.iter().filter(|(_, w)| w.pending == 0).map(|(k, _)| k.clone()).take(m.len() - 255).collect();
        for k in idle {
            m.remove(&k);
        }
    }
    let w = m.entry(session.to_string()).or_default();
    if w.pending == 0 {
        w.started = Some(Instant::now());
    }
    w.pending += 1;
    HumanWait { session: session.to_string(), ceiling: timeout + Duration::from_secs(60) }
}

impl Drop for HumanWait {
    fn drop(&mut self) {
        let mut m = waits().lock().unwrap_or_else(|p| p.into_inner());
        if let Some(w) = m.get_mut(&self.session) {
            w.pending = w.pending.saturating_sub(1);
            if w.pending == 0 {
                if let Some(s) = w.started.take() {
                    w.completed += s.elapsed().min(self.ceiling);
                }
            }
        }
    }
}

/// Total human-wait time recorded for `session` (completed windows plus the open one).
pub fn human_wait_total(session: &str) -> Duration {
    let m = waits().lock().unwrap_or_else(|p| p.into_inner());
    m.get(session).map(|w| w.completed + w.started.map(|s| s.elapsed()).unwrap_or_default()).unwrap_or_default()
}

// ───────────────────────── deny reasons (`/deny <reason>`) ─────────────────────────

fn reasons() -> &'static Mutex<HashMap<String, String>> {
    static R: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

/// Remember the free-text reason given with a deny for approval `id`.
pub fn set_deny_reason(id: &str, reason: &str) {
    let mut m = reasons().lock().unwrap_or_else(|p| p.into_inner());
    if m.len() > 512 {
        m.clear();
    }
    m.insert(id.to_string(), reason.trim().chars().take(500).collect());
}

pub fn take_deny_reason(id: &str) -> Option<String> {
    reasons().lock().unwrap_or_else(|p| p.into_inner()).remove(id).filter(|r| !r.is_empty())
}

// ───────────────────────── who answered (srv-018) ─────────────────────────

fn answered_by() -> &'static Mutex<HashMap<String, String>> {
    static R: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

/// Record who answered approval `id` (`channel:sender`), for the gate record and the audit.
pub fn set_answered_by(id: &str, who: &str) {
    let mut m = answered_by().lock().unwrap_or_else(|p| p.into_inner());
    if m.len() > 512 {
        m.clear();
    }
    m.insert(id.to_string(), who.to_string());
}

pub fn take_answered_by(id: &str) -> Option<String> {
    answered_by().lock().unwrap_or_else(|p| p.into_inner()).remove(id).filter(|r| !r.is_empty())
}

/// Parse an approval answer: `once|allow|yes|allow-once`, `session|always`,
/// `permanent|allow-always`, `deny|no|reject [reason]`. Returns (choice, reason).
pub fn parse_answer(s: &str) -> (&'static str, Option<String>) {
    let s = s.trim();
    let (head, rest) = s.split_once(|c: char| c.is_whitespace() || c == ':').map(|(a, b)| (a, b.trim())).unwrap_or((s, ""));
    let rest = (!rest.is_empty()).then(|| rest.to_string());
    match head.to_ascii_lowercase().as_str() {
        "once" | "allow" | "yes" | "y" | "allow-once" | "allowonce" | "approve" => ("once", None),
        "session" | "always" | "a" => ("session", None),
        "permanent" | "allow-always" | "allowalways" | "forever" => ("permanent", None),
        _ => ("deny", rest),
    }
}

fn forwarded() -> &'static Mutex<std::collections::HashSet<String>> {
    static F: std::sync::OnceLock<Mutex<std::collections::HashSet<String>>> = std::sync::OnceLock::new();
    F.get_or_init(Default::default)
}

/// An approval forwarded into a direct chat may be answered there by that chat's peer
/// (`approvals.forward` without an approvers list); the host records the peer here.
pub fn allow_forwarded(id: &str, channel: &str, sender: &str) {
    let mut f = forwarded().lock().unwrap_or_else(|p| p.into_inner());
    if f.len() > 4096 {
        f.clear();
    }
    f.insert(format!("{id}\u{1f}{channel}\u{1f}{sender}"));
}

pub fn forwarded_allowed(id: &str, channel: &str, sender: &str) -> bool {
    forwarded().lock().unwrap_or_else(|p| p.into_inner()).contains(&format!("{id}\u{1f}{channel}\u{1f}{sender}"))
}

// ───────────────────────── deferred approvals (§0-2 #03/#05) ─────────────────────────

/// A call that needed the owner while nobody was there. The branch that wanted it is
/// blocked; everything else in the task keeps running, and the owner can answer later
/// (`seagent approvals queue`, `seagent approvals allow <id>`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Deferred {
    pub id: String,
    pub session: String,
    pub tool: String,
    pub summary: String,
    pub tier: u8,
    pub reason: String,
    pub created_at: u64,
    /// Allow-once grants expire like every other grant.
    #[serde(default)]
    pub status: String,
    /// Who answered it (`cli`, `telegram:42`…) — srv-018 records the approver.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub answered_by: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct QueueFile {
    pub version: u32,
    pub items: Vec<Deferred>,
}

pub fn queue_path(data: &Path) -> PathBuf {
    dir(data).join("approvals").join("queue.json")
}

pub fn deferred(data: &Path) -> Vec<Deferred> {
    std::fs::read_to_string(queue_path(data)).ok().and_then(|s| serde_json::from_str::<QueueFile>(&s).ok()).map(|f| f.items.into_iter().filter(|i| i.status == "pending").collect()).unwrap_or_default()
}

/// Queue a call for the owner. Returns the id the agent's error message quotes.
pub fn defer(data: &Path, session: &str, tool: &str, summary: &str, tier: u8, reason: &str) -> Result<String, String> {
    let _g = FILE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = queue_path(data);
    let mut f: QueueFile = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    f.version = 1;
    // Same call, same session, still pending: reuse the entry instead of spamming.
    if let Some(i) = f.items.iter().find(|i| i.status == "pending" && i.session == session && i.tool == tool && i.reason == reason) {
        return Ok(i.id.clone());
    }
    let id = new_id();
    f.items.push(Deferred { id: id.clone(), session: session.into(), tool: tool.into(), summary: summary.chars().take(600).collect(), tier, reason: reason.into(), created_at: unix_now(), status: "pending".into(), answered_by: String::new() });
    if f.items.len() > 200 {
        let cut = f.items.len() - 200;
        f.items.drain(..cut);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    write_json(&path, &f)?;
    Ok(id)
}

/// Answer a queued call. `allow` adds a grant for that exact gate reason so the agent's
/// next attempt runs without asking; `deny` just closes the entry.
pub fn resolve_deferred(data: &Path, id: &str, allow: bool, ttl_days: u64) -> Result<Option<Deferred>, String> {
    resolve_deferred_by(data, id, allow, ttl_days, "cli")
}

/// [`resolve_deferred`], recording who answered.
pub fn resolve_deferred_by(data: &Path, id: &str, allow: bool, ttl_days: u64, by: &str) -> Result<Option<Deferred>, String> {
    // The file lock is released before `add_grant_ttl` (which takes it again): the two
    // locks are not reentrant.
    let item = {
        let _g = FILE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let path = queue_path(data);
        let mut f: QueueFile = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let Some(i) = f.items.iter_mut().find(|i| i.id == id || i.tool == id) else { return Ok(None) };
        if i.status != "pending" {
            return Ok(None);
        }
        i.status = if allow { "allowed" } else { "denied" }.into();
        i.answered_by = by.to_string();
        let item = i.clone();
        write_json(&path, &f)?;
        item
    };
    if allow {
        let _ = add_grant_ttl(data, GrantKind::Gate, &item.reason, Some(&gate_name(&item.reason)), "queue-allowed", Some(ttl_days));
    }
    Ok(Some(item))
}

fn gate_name(_reason: &str) -> String {
    // The gate kind is not stored on the queue entry; `gate_granted` matches on the
    // reason text, so any name works for the ones the queue can re-open.
    "exec".into()
}

/// Snapshot for `seagent approvals status` / `/approvals`.
pub fn describe(cfg: &ApprovalsConfig, data: &Path, session: Option<&str>) -> serde_json::Value {
    let st = session.map(|s| session_state(data, s)).unwrap_or_default();
    json!({
        "mode": format!("{:?}", cfg.mode).to_lowercase(),
        "process_yolo": process_yolo(),
        "session_yolo": st.yolo,
        "exec": {"security": cfg.exec.security.as_str(), "ask": cfg.exec.ask.as_str(), "ask_fallback": cfg.exec.ask_fallback.as_str(), "safe_bins": cfg.exec.safe_bins, "allowlist": cfg.exec.allowlist},
        "session_exec": st.exec,
        "elevated": {"enabled": cfg.elevated.enabled, "level": st.elevated.unwrap_or(cfg.elevated.default).as_str()},
        "deny_rules": cfg.deny.len(),
        "command_allowlist": cfg.allowlist.len(),
        "durable_grants": grants(data).len(),
        "strict_inline_eval": cfg.strict_inline_eval,
        "cron_mode": format!("{:?}", cfg.cron_mode).to_lowercase(),
        "unattended_mode": format!("{:?}", cfg.unattended_mode).to_lowercase(),
        "trust_presets": {"owner": cfg.preset_for("owner").as_str(), "channel": cfg.preset_for("channel").as_str(), "stranger": cfg.preset_for("stranger").as_str()},
        "deferred": deferred(data).len(),
        "fatigue": fatigue(data, 7),
    })
}

// ───────────────────────── approval fatigue (gen2-413) ─────────────────────────

/// One question put to a human, as `asks.jsonl` keeps it (no inputs, no secrets).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AskRecord {
    pub at: u64,
    pub tool: String,
    pub gate: String,
    pub tier: u8,
    /// `allow` | `deny` | `timeout`.
    pub outcome: String,
    pub wait_ms: u64,
    /// Gate reason (what kept being asked about), truncated.
    pub reason: String,
}

pub fn asks_path(data: &Path) -> PathBuf {
    dir(data).join("asks.jsonl")
}

/// Append one human ask (best effort: monitoring must never break the gate).
pub fn record_ask(data: &Path, mut r: AskRecord) {
    use std::io::Write;
    r.reason = r.reason.chars().take(200).collect();
    let p = asks_path(data);
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
        let _ = writeln!(f, "{}", serde_json::to_string(&r).unwrap_or_default());
    }
}

/// Approval-fatigue numbers over the last `days` days.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Fatigue {
    pub days: u64,
    pub asks: usize,
    pub per_day: f64,
    pub denied: usize,
    pub timed_out: usize,
    pub deny_rate: f64,
    pub mean_wait_secs: f64,
    /// (reason, times asked, times allowed) — almost always allowed ⇒ pre-authorise it.
    pub mostly_allowed: Vec<(String, usize, usize)>,
}

pub fn fatigue(data: &Path, days: u64) -> Fatigue {
    let since = unix_now().saturating_sub(days.max(1) * 86_400);
    let recs: Vec<AskRecord> = std::fs::read_to_string(asks_path(data)).unwrap_or_default().lines().filter_map(|l| serde_json::from_str::<AskRecord>(l).ok()).filter(|r| r.at >= since).collect();
    let asks = recs.len();
    let denied = recs.iter().filter(|r| r.outcome != "allow").count();
    let timed_out = recs.iter().filter(|r| r.outcome == "timeout").count();
    let mut by: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for r in &recs {
        let e = by.entry(r.reason.clone()).or_default();
        e.0 += 1;
        if r.outcome == "allow" {
            e.1 += 1;
        }
    }
    let mut mostly_allowed: Vec<(String, usize, usize)> = by.into_iter().filter(|(_, (n, ok))| *n >= 3 && *ok * 10 >= *n * 9).map(|(r, (n, ok))| (r, n, ok)).collect();
    mostly_allowed.sort_by_key(|x| std::cmp::Reverse(x.1));
    mostly_allowed.truncate(5);
    Fatigue {
        days: days.max(1),
        asks,
        per_day: asks as f64 / days.max(1) as f64,
        denied,
        timed_out,
        deny_rate: if asks == 0 { 0.0 } else { denied as f64 / asks as f64 },
        mean_wait_secs: if asks == 0 { 0.0 } else { recs.iter().map(|r| r.wait_ms).sum::<u64>() as f64 / asks as f64 / 1000.0 },
        mostly_allowed,
    }
}

/// The doctor line: `Err` (a warning) when the owner is asked more than `threshold` a day.
pub fn fatigue_check(data: &Path, threshold: u32) -> Result<String, String> {
    let f = fatigue(data, 7);
    let line = format!("{:.1} asks/day over 7 days, {:.0}% denied ({} timed out), mean wait {:.0}s", f.per_day, f.deny_rate * 100.0, f.timed_out, f.mean_wait_secs);
    if threshold > 0 && f.per_day > threshold as f64 {
        let hint = f.mostly_allowed.first().map(|(r, n, ok)| format!("; \"{r}\" was allowed {ok}/{n} times — pre-authorise it (task envelope, `seagent approvals suggest`)")).unwrap_or_default();
        return Err(format!("{line} — above approvals.fatigue_daily_asks = {threshold}: approval fatigue makes people click Allow blindly{hint}"));
    }
    Ok(line)
}

/// gen2-409 (§0-2 #05): pending deferred calls of the same kind (tool + tier + reason),
/// so the owner previews them together and answers a whole group at once.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeferredGroup {
    pub tool: String,
    pub tier: u8,
    pub reason: String,
    pub ids: Vec<String>,
    /// Impact lines of the members (what each would do), for the preview.
    pub impacts: Vec<String>,
}

pub fn deferred_groups(data: &Path) -> Vec<DeferredGroup> {
    let mut out: Vec<DeferredGroup> = Vec::new();
    for d in deferred(data) {
        match out.iter_mut().find(|g| g.tool == d.tool && g.tier == d.tier && g.reason == d.reason) {
            Some(g) => {
                g.ids.push(d.id);
                g.impacts.push(d.summary);
            }
            None => out.push(DeferredGroup { tool: d.tool, tier: d.tier, reason: d.reason, ids: vec![d.id], impacts: vec![d.summary] }),
        }
    }
    out
}

/// Answer every member of a group in one go (one confirmation for "delete these 40 temp
/// branches"). Tier 3 is never batched: each irreversible call is confirmed on its own.
pub fn resolve_group(data: &Path, group: &DeferredGroup, allow: bool, ttl_days: u64, by: &str) -> Result<usize, String> {
    if allow && group.tier >= 3 && group.ids.len() > 1 {
        return Err(format!("tier 3 is never approved in bulk: answer the {} calls one by one", group.ids.len()));
    }
    let mut n = 0;
    for id in &group.ids {
        if resolve_deferred_by(data, id, allow, ttl_days, by)?.is_some() {
            n += 1;
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let d = seagent_core::tmp::scratch_path(format!("seagent-appr-{}-{}", std::process::id(), new_id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn config_defaults_and_parsing() {
        let c: ApprovalsConfig = serde_json::from_value(json!({"mode": "smart", "exec": {"security": "allowlist", "ask": "on-miss"}})).unwrap();
        assert_eq!(c.mode, Mode::Smart);
        assert_eq!((c.exec.security, c.exec.ask, c.exec.ask_fallback), (ExecSecurity::Allowlist, ExecAsk::OnMiss, ExecSecurity::Deny));
        assert_eq!(c.exec.safe_bins.len(), 6);
        assert_eq!(ApprovalsConfig::default().timeout_secs, 600);
        assert!(serde_json::from_value::<ApprovalsConfig>(json!({"modee": 1})).is_err());
        assert_eq!(min_security(ExecSecurity::Full, ExecSecurity::Allowlist), ExecSecurity::Allowlist);
        assert_eq!(max_ask(ExecAsk::Off, ExecAsk::Always), ExecAsk::Always);
    }

    #[test]
    fn session_toggles_persist_and_overrides_only_tighten() {
        let d = tmp();
        assert!(!yolo_active(&d, "s1") || process_yolo());
        assert!(set_session_yolo(&d, "s1", None).unwrap());
        assert!(session_state(&d, "s1").yolo);
        assert!(!set_session_yolo(&d, "s1", None).unwrap(), "toggle flips back");
        update_session(&d, "s1", |s| {
            s.exec.security = Some(ExecSecurity::Full);
            s.exec.ask = Some(ExecAsk::Always);
            s.exec.for_turn = Some(3);
        })
        .unwrap();
        let cfg = ApprovalsConfig { exec: ExecPolicy { security: ExecSecurity::Allowlist, ask: ExecAsk::OnMiss, ..Default::default() }, ..Default::default() };
        assert_eq!(effective_exec(&cfg, &d, "s1", 3), (ExecSecurity::Allowlist, ExecAsk::Always), "full cannot loosen allowlist; ask tightens");
        assert_eq!(effective_exec(&cfg, &d, "s1", 4), (ExecSecurity::Allowlist, ExecAsk::OnMiss), "turn-scoped");
        transfer_session(&d, "s1", "s2").unwrap();
        assert_eq!(session_state(&d, "s2").exec.ask, Some(ExecAsk::Always));
        clear_session(&d, "s1");
        assert_eq!(session_state(&d, "s1"), SessionState::default());
        let mut e = cfg.clone();
        assert_eq!(elevated_level(&e, &d, "s2"), Elevated::Off, "disabled");
        e.elevated.enabled = true;
        update_session(&d, "s2", |s| s.elevated = Some(Elevated::Full)).unwrap();
        assert_eq!(elevated_level(&e, &d, "s2"), Elevated::Full);
    }

    #[test]
    fn durable_grants() {
        let d = tmp();
        let id = add_grant(&d, GrantKind::Gate, "`sudo` runs with elevated privileges", Some("privilege"), "allow-always").unwrap();
        assert_eq!(add_grant(&d, GrantKind::Gate, "`sudo` runs with elevated privileges", Some("privilege"), "x").unwrap(), id, "dedup");
        assert!(gate_granted(&d, "privilege", "`sudo` runs with elevated privileges").is_some());
        assert!(gate_granted(&d, "egress", "`sudo` runs with elevated privileges").is_none());
        add_grant(&d, GrantKind::Command, "podman *", None, "manual").unwrap();
        assert!(command_granted(&ApprovalsConfig::default(), &d, "podman ps").is_some());
        assert!(command_granted(&ApprovalsConfig { allowlist: vec!["make test".into()], ..Default::default() }, &d, "make test").is_some());
        assert_eq!(remove_grant(&d, &id).unwrap(), 1);
        assert!(gate_granted(&d, "privilege", "`sudo` runs with elevated privileges").is_none());
    }

    #[test]
    fn exec_allowlist_safe_bins_and_paths() {
        let d = tmp();
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let cfg = ApprovalsConfig { exec: ExecPolicy { allowlist: vec!["git".into()], ..Default::default() }, ..Default::default() };
        let usr = ApprovalsConfig { exec: ExecPolicy { allowlist: vec!["/usr/bin/*".into()], ..Default::default() }, ..Default::default() };
        assert!(exec_allowlisted(&a(&["wc", "-l"]), None, &cfg, &d, &d).is_some());
        assert!(exec_allowlisted(&a(&["head", "-n", "5"]), None, &cfg, &d, &d).is_some());
        assert!(exec_allowlisted(&a(&["head", "-n5"]), None, &cfg, &d, &d).is_some());
        assert!(exec_allowlisted(&a(&["head", "/etc/passwd"]), None, &cfg, &d, &d).is_none(), "file operand breaks stdin-only");
        assert!(exec_allowlisted(&a(&["tail", "-f"]), None, &cfg, &d, &d).is_none(), "denied flag");
        assert!(exec_allowlisted(&a(&["sort", "-o", "x"]), None, &cfg, &d, &d).is_none(), "sort not a default safe bin and -o denied");
        assert!(exec_allowlisted(&a(&["cd", "x"]), None, &cfg, &d, &d).is_some());
        assert!(exec_allowlisted(&a(&["git", "status"]), None, &cfg, &d, &d).is_some());
        assert!(exec_allowlisted(&a(&["/usr/bin/env"]), None, &usr, &d, &d).is_some());
        assert!(exec_allowlisted(&a(&["/opt/x/tool"]), None, &cfg, &d, &d).is_none());
        add_grant(&d, GrantKind::Exec, "/opt/x/*", None, "allow-always").unwrap();
        assert!(exec_allowlisted(&a(&["/opt/x/tool", "arg"]), None, &cfg, &d, &d).is_some());
        assert!(grants(&d)[0].last_used_command.as_deref() == Some("/opt/x/tool arg"), "usage recorded");
    }

    #[test]
    fn dynamic_test_and_bracket_predicates_are_not_safe_builtins() {
        let d = tmp();
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let cfg = ApprovalsConfig::default();
        // The exact regression: bash >= 4.2 evaluates the array subscript even inside
        // single quotes, so the parsed argv looks harmless but still runs a command.
        assert!(exec_allowlisted(&a(&["test", "-v", "a[$(cmd)]"]), Some("test -v 'a[$(cmd)]'"), &cfg, &d, &d).is_none(), "array-subscript operand");
        assert!(exec_allowlisted(&a(&["[", "-v", "a[$(cmd)]", "]"]), Some("[ -v 'a[$(cmd)]' ]"), &cfg, &d, &d).is_none());
        assert!(exec_allowlisted(&a(&["test", "-R", "a[$(cmd)]"]), Some("test -R 'a[$(cmd)]'"), &cfg, &d, &d).is_none(), "-R operand");
        assert!(exec_allowlisted(&a(&["test", "$'x'"]), Some("test $'x'"), &cfg, &d, &d).is_none(), "ANSI-C quoting");
        assert!(exec_allowlisted(&a(&["test", "-e", "*.txt"]), Some("test -e *.txt"), &cfg, &d, &d).is_none(), "glob operand");
        assert!(exec_allowlisted(&a(&["test", "a[b]"]), Some("test 'a[b]'"), &cfg, &d, &d).is_none(), "bracket operand");
        assert!(exec_allowlisted(&a(&["[", "-d", "dir"]), Some("[ -d dir ]"), &cfg, &d, &d).is_none(), "no closing bracket in argv is not the safe form");
        // Static predicates stay on the safe list.
        for (argv, raw) in [(a(&["test", "-f", "x"]), "test -f x"), (a(&["test", "-d", "dir"]), "test -d dir"), (a(&["[", "-d", "dir", "]"]), "[ -d dir ]"), (a(&["pwd"]), "pwd"), (a(&["cd", "build"]), "cd build")] {
            assert!(exec_allowlisted(&argv, Some(raw), &cfg, &d, &d).is_some(), "{raw}");
        }
    }

    #[test]
    fn breaker_waits_answers_and_senders() {
        reset_denials("bk");
        for _ in 0..2 {
            record_denial("bk");
        }
        assert!(breaker_addendum("bk", 3).is_empty());
        record_denial("bk");
        assert!(breaker_addendum("bk", 3).contains("CIRCUIT BREAKER: 3"));
        assert!(breaker_addendum("bk", 0).is_empty());
        reset_denials("bk");
        {
            let _w = human_wait("hw", Duration::from_secs(1));
            let _w2 = human_wait("hw", Duration::from_secs(1));
            std::thread::sleep(Duration::from_millis(30));
        }
        let t = human_wait_total("hw");
        assert!(t >= Duration::from_millis(30) && t < Duration::from_secs(2), "{t:?}");
        assert_eq!(parse_answer("allow-always"), ("permanent", None));
        assert_eq!(parse_answer("always"), ("session", None));
        assert_eq!(parse_answer("deny too risky"), ("deny", Some("too risky".into())));
        assert_eq!(parse_answer("deny:no thanks"), ("deny", Some("no thanks".into())));
        assert_eq!(parse_answer("garbage"), ("deny", None));
        set_deny_reason("x1", "use a dry run");
        assert_eq!(take_deny_reason("x1").as_deref(), Some("use a dry run"));
        assert!(take_deny_reason("x1").is_none());
        let mut l = BTreeMap::new();
        l.insert("telegram".to_string(), vec!["123".to_string(), "username:Alice".to_string()]);
        assert!(sender_allowed(&l, "telegram", "123", ""));
        assert!(sender_allowed(&l, "telegram", "9", "alice"));
        assert!(!sender_allowed(&l, "telegram", "9", "bob") && !sender_allowed(&l, "discord", "123", ""));
    }

    /// `stage_memory_write` must emit exactly what `seagent_tools::memory_store::apply_staged`
    /// replays: `{memory|user: [..]}` for adds, `{ops: {file, operations[..]}}` (with a pinned
    /// `matched_entry`) for everything that edits or removes an existing entry.
    #[test]
    fn staged_memory_writes_match_apply_staged() {
        let d = tmp();
        std::fs::create_dir_all(d.join("memory")).unwrap();
        std::fs::write(d.join("memory/MEMORY.md"), "builds need --release\n§\nold note about tests\n§\nsecond old note\n").unwrap();
        let read = |p: &PathBuf| -> serde_json::Value { serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap() };

        // add → the add-only shape `seagent memory review` prints and `accept` appends.
        let p = stage_memory_write(&d, "s1", "memory", "add", "prefer small diffs", None).unwrap();
        assert_eq!(p.parent(), Some(d.join("memory/staging").as_path()));
        assert!(p.file_name().unwrap().to_string_lossy().ends_with(".json"));
        let v = read(&p);
        assert_eq!((v["session"].as_str(), v["origin"].as_str()), (Some("s1"), Some("foreground")));
        assert_eq!(v["memory"], json!(["prefer small diffs"]));
        assert!(v.get("ops").is_none() && v["created_ms"].as_u64().unwrap() > 0, "{v}");
        assert!(v["summary"].as_str().unwrap().contains("prefer small diffs"));
        // The store itself is untouched.
        assert_eq!(std::fs::read_to_string(d.join("memory/MEMORY.md")).unwrap().split("\n§\n").count(), 3);

        // replace → ops shape pinned to the whole matched entry.
        let p = stage_memory_write(&d, "s1", "memory", "replace", "new note about tests", Some("old note about tests")).unwrap();
        let v = read(&p);
        assert!(v.get("memory").is_none() && v["ops"]["file"] == "memory", "{v}");
        let op = &v["ops"]["operations"][0];
        assert_eq!(op["action"], "replace");
        assert_eq!(op["old"], "old note about tests");
        assert_eq!(op["text"], "new note about tests");
        assert_eq!(op["matched_entry"], "old note about tests");

        // A batch is one record; the user file uses the same shape.
        std::fs::write(d.join("memory/USER.md"), "prefers Japanese\n§\nold job note\n").unwrap();
        let p = stage_memory_writes(&d, "s2", "user", &[MemoryWrite { action: "add".into(), text: Some("runs in UTC+8".into()), old: None }, MemoryWrite { action: "remove".into(), text: None, old: Some("old job note".into()) }]).unwrap();
        let v = read(&p);
        assert_eq!(v["ops"]["file"], "user");
        let ops = v["ops"]["operations"].as_array().unwrap();
        assert_eq!((ops.len(), ops[0]["action"].as_str()), (2, Some("add")));
        assert_eq!(ops[1]["matched_entry"], "old job note");

        // Ambiguous / missing `old` never stages.
        let e = stage_memory_write(&d, "s1", "memory", "remove", "", Some("old note")).unwrap_err();
        assert!(e.contains("no unique entry matching `old`") && e.contains("2 entries"), "{e}");
        let e = stage_memory_write(&d, "s1", "memory", "replace", "x", Some("nothing like this")).unwrap_err();
        assert!(e.contains("no unique entry matching `old`") && e.contains("no entry"), "{e}");
        assert!(stage_memory_write(&d, "s1", "memory", "upsert", "x", None).unwrap_err().contains("unknown action"));

        // Sequential ops in one batch see each other's effect (the second op's `old` is gone).
        let e = stage_memory_writes(&d, "s1", "memory", &[MemoryWrite { action: "remove".into(), text: None, old: Some("second old note".into()) }, MemoryWrite { action: "remove".into(), text: None, old: Some("second old note".into()) }]).unwrap_err();
        assert!(e.contains("no unique entry matching `old`"), "{e}");
    }

    #[test]
    fn deferred_calls_of_one_kind_are_previewed_and_answered_together() {
        let t = seagent_core::tmp::TempDir::new("seagent-appr-group");
        let d = t.to_path_buf();
        for b in ["tmp-1", "tmp-2", "tmp-3"] {
            defer(&d, &format!("s-{b}"), "sh", &format!("git push origin --delete {b}"), 2, "tier 2: deletes a remote branch").unwrap();
        }
        defer(&d, "s9", "sh", "aws s3 rb s3://a", 3, "tier 3: deletes a bucket").unwrap();
        defer(&d, "s10", "sh", "aws s3 rb s3://b", 3, "tier 3: deletes a bucket").unwrap();
        let g = deferred_groups(&d);
        assert_eq!(g.len(), 2, "{g:?}");
        assert_eq!((g[0].ids.len(), g[0].impacts[1].as_str()), (3, "git push origin --delete tmp-2"));
        assert_eq!(resolve_group(&d, &g[0], true, 7, "cli").unwrap(), 3, "one confirmation for the whole group");
        assert_eq!(deferred(&d).len(), 2);
        assert!(resolve_group(&d, &g[1], true, 7, "cli").unwrap_err().contains("never approved in bulk"));
        assert_eq!(resolve_group(&d, &g[1], false, 7, "cli").unwrap(), 2, "denying in bulk is fine");
        let q: QueueFile = serde_json::from_str(&std::fs::read_to_string(queue_path(&d)).unwrap()).unwrap();
        assert!(q.items.iter().all(|i| i.answered_by == "cli"), "the approver is recorded");
    }

    #[test]
    fn trust_levels_pick_their_own_preset() {
        let mut c = ApprovalsConfig::default();
        assert_eq!((c.preset_for("owner"), c.preset_for("channel"), c.preset_for("stranger")), (crate::risk::Preset::Standard, crate::risk::Preset::Standard, crate::risk::Preset::Strict));
        c.trust_presets.insert("owner".into(), crate::risk::Preset::Relaxed);
        assert_eq!(c.preset_for("owner"), crate::risk::Preset::Relaxed);
        let c: ApprovalsConfig = serde_json::from_value(json!({"trust_presets": {"channel": "strict", "stranger": "standard"}})).unwrap();
        assert_eq!((c.preset_for("channel"), c.preset_for("stranger")), (crate::risk::Preset::Strict, crate::risk::Preset::Standard));
    }

    #[test]
    fn fatigue_counts_asks_denials_and_waits_and_warns_over_the_threshold() {
        let t = seagent_core::tmp::TempDir::new("seagent-appr-fatigue");
        let d = t.to_path_buf();
        assert!(fatigue_check(&d, 30).is_ok(), "no asks, no warning");
        let now = unix_now();
        for i in 0..20u64 {
            let outcome = if i < 15 { "allow" } else if i < 19 { "deny" } else { "timeout" };
            let reason = if i < 15 { "exec policy: `cargo` not on the allowlist" } else { "egress" };
            record_ask(&d, AskRecord { at: now - i, tool: "shell".into(), gate: "exec".into(), tier: 2, outcome: outcome.into(), wait_ms: 2000, reason: reason.into() });
        }
        let f = fatigue(&d, 7);
        assert_eq!((f.asks, f.denied, f.timed_out), (20, 5, 1));
        assert!((f.deny_rate - 0.25).abs() < 1e-9 && (f.mean_wait_secs - 2.0).abs() < 1e-9, "{f:?}");
        assert_eq!(f.mostly_allowed[0].0, "exec policy: `cargo` not on the allowlist");
        assert!(fatigue_check(&d, 30).is_ok(), "20 in 7 days is under 30/day");
        let e = fatigue_check(&d, 2).unwrap_err();
        assert!(e.contains("approval fatigue") && e.contains("pre-authorise"), "{e}");
    }
}
