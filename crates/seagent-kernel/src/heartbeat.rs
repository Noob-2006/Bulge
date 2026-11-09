//! Proactive heartbeat runner (OpenClaw `src/infra/heartbeat-*.ts`, `auto-reply/heartbeat.ts`,
//! `agents/tools/heartbeat-response-tool.ts`).
//!
//! Every `every` (default 30m) — or immediately when a `now` system event is queued
//! (`wake.rs`: `seagent system event`, the `automations` tool, cron `systemEvent` jobs) — the
//! daemon runs one turn in the heartbeat session, inside the configured active hours:
//! - prompt: the configured prompt (or the default) plus the `heartbeat_respond` instructions,
//!   queued system events (`System:` lines; cron events become a reminder prompt), the
//!   monitor scratch (`<data>/heartbeat_scratch.md`, else the workspace `HEARTBEAT.md`), and
//!   `heartbeat_prompt_contribution` hook context;
//! - an effectively empty scratch with no events skips the model call entirely;
//! - outcome: a `heartbeat_respond` call decides notify / text / scratch; otherwise the reply
//!   is stripped of `HEARTBEAT_OK` / `NO_REPLY` acknowledgements (short acks are silent);
//! - delivery: `target` (outbound grammar; `none` = keep in the session).
//!
//! ```toml
//! [heartbeat]
//! every = "30m"
//! target = "telegram:12345"      # none (default) | <channel>[:<chat>] | webhook URL
//! prompt = "Check the deploy dashboard."
//! ack_max_chars = 300
//! workspace = "~/ops"            # default: seagent's data dir
//! active_hours = { start = "08:00", end = "22:00", timezone = "Asia/Taipei" }
//! ```

use crate::kernel::{Kernel, RunOpts};
use crate::outbound::{self, Payload, Target};
use crate::util::unix_now;
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub const HEARTBEAT_TOKEN: &str = "HEARTBEAT_OK";
pub const SILENT_REPLY_TOKEN: &str = "NO_REPLY";
pub const DEFAULT_EVERY_SECS: i64 = 30 * 60;
pub const DEFAULT_ACK_MAX_CHARS: usize = 300;
pub const SCRATCH_MAX_BYTES: usize = 256 * 1024;
pub const TOOL_NAME: &str = "heartbeat_respond";

const CONTEXT_PROMPT: &str = "Follow the heartbeat monitor scratch context when provided. Recurring tasks are automations; create or change their schedules with the automations tool, not heartbeat scratch. Do not infer or repeat old tasks from prior chats.";
pub const TOOL_INSTRUCTIONS: &str = "Use heartbeat_respond to report the wake outcome. Set notify=false when nothing needs the user's attention. Set notify=true with notificationText only when the user should be interrupted.";
const TOOL_FALLBACK_INSTRUCTIONS: &str = "If the heartbeat_respond tool is not available in this run, reply NO_REPLY when nothing needs the user's attention; when the user should be interrupted, reply with only the alert text instead of a prose report.";
pub const OUTCOMES: &[&str] = &["no_change", "progress", "done", "blocked", "needs_attention"];
pub const PRIORITIES: &[&str] = &["low", "normal", "high"];

// ───────────────────────── config ─────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct ActiveHours {
    pub start: Option<u32>,
    pub end: Option<u32>,
    pub timezone: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HeartbeatConfig {
    pub every_secs: i64,
    pub active_hours: Option<ActiveHours>,
    pub target: String,
    pub prompt: Option<String>,
    pub ack_max_chars: usize,
    pub session: Option<String>,
    pub model: Option<String>,
    pub workspace: Option<PathBuf>,
    /// Fresh session every beat instead of one long-lived heartbeat session.
    pub isolated_session: bool,
}

/// `HH:MM` minutes; `24:00` only allowed as an end (OpenClaw `parseActiveHoursTime`).
fn hhmm(s: &str, allow24: bool) -> Option<u32> {
    let (h, m) = s.trim().split_once(':')?;
    if h.len() != 2 || m.len() != 2 {
        return None;
    }
    let (h, m): (u32, u32) = (h.parse().ok()?, m.parse().ok()?);
    if h == 24 && m == 0 {
        return allow24.then_some(1440);
    }
    (h < 24 && m < 60).then_some(h * 60 + m)
}

impl HeartbeatConfig {
    /// `None` when `[heartbeat]` is absent/empty or `enabled = false`.
    pub fn from_table(t: &toml::Table) -> Result<Option<HeartbeatConfig>, String> {
        if t.is_empty() || t.get("enabled").and_then(|v| v.as_bool()) == Some(false) {
            return Ok(None);
        }
        let str_of = |k: &str| t.get(k).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(String::from);
        // Upstream (OpenClaw `heartbeat`) spells some keys camelCase; a config migrated from it
        // (`seagent claw migrate`) keeps them, so both spellings are read.
        let any = |snake: &str, camel: &str| t.get(snake).or_else(|| t.get(camel));
        let every_secs = match str_of("every") {
            None => DEFAULT_EVERY_SECS,
            Some(e) => {
                // OpenClaw: default unit minutes.
                let ms = if e.chars().all(|c| c.is_ascii_digit()) { e.parse::<u64>().map(|m| m * 60_000).map_err(|_| "heartbeat.every: invalid duration".to_string())? } else { crate::cronjob::schedule::parse_duration_ms(&e).map_err(|_| "heartbeat.every: invalid duration (use ms, s, m, h)".to_string())? };
                ((ms / 1000) as i64).max(60)
            }
        };
        let active_hours = any("active_hours", "activeHours").and_then(|v| v.as_table()).map(|a| {
            let g = |k: &str| a.get(k).and_then(|v| v.as_str()).map(String::from);
            ActiveHours { start: g("start").and_then(|s| hhmm(&s, false)), end: g("end").and_then(|s| hhmm(&s, true)), timezone: g("timezone") }
        });
        let target = str_of("target").or_else(|| str_of("to")).unwrap_or_else(|| "none".into());
        if !matches!(target.as_str(), "none" | "local" | "last") {
            for p in target.split(',') {
                Target::parse(p.trim()).map_err(|e| format!("heartbeat.target: {e}"))?;
            }
        }
        Ok(Some(HeartbeatConfig {
            every_secs,
            active_hours,
            target,
            prompt: str_of("prompt"),
            ack_max_chars: any("ack_max_chars", "ackMaxChars").and_then(|v| v.as_integer()).map(|n| n.max(0) as usize).unwrap_or(DEFAULT_ACK_MAX_CHARS),
            session: str_of("session"),
            model: str_of("model"),
            workspace: str_of("workspace").map(|w| seagent_core::expand_home(&w)),
            isolated_session: any("isolated_session", "isolatedSession").and_then(|v| v.as_bool()).unwrap_or(false),
        }))
    }
}

/// OpenClaw `isWithinActiveHours`: invalid config is permissive; start == end is never active.
pub fn within_active_hours(ah: Option<&ActiveHours>, now: i64, default_offset: i32) -> bool {
    let Some(a) = ah else { return true };
    let (Some(start), Some(end)) = (a.start, a.end) else { return true };
    if start == end {
        return false;
    }
    let offset = match a.timezone.as_deref().map(str::trim).filter(|t| !t.is_empty() && *t != "user") {
        None => default_offset,
        Some(tz) => match crate::tzfile::offset_minutes(tz, now) {
            Some(o) => o,
            None => default_offset, // explicit but unknown: fall back to the user zone
        },
    };
    let cur = ((now + offset as i64 * 60).rem_euclid(86_400) / 60) as u32;
    if end > start {
        cur >= start && cur < end
    } else {
        cur >= start || cur < end
    }
}

// ───────────────────────── text helpers ─────────────────────────

/// OpenClaw `isHeartbeatContentEffectivelyEmpty`: only blank lines, comments, headers,
/// fence markers and empty list stubs. A missing scratch is not "empty".
pub fn effectively_empty(content: Option<&str>) -> bool {
    let Some(content) = content else { return false };
    let mut in_comment = false;
    for raw in content.split('\n') {
        let mut line = raw.to_string();
        while in_comment || line.trim_start().starts_with("<!--") {
            let search = if in_comment { line.clone() } else { line.trim_start().to_string() };
            match search.find("-->") {
                None => {
                    in_comment = true;
                    line.clear();
                    break;
                }
                Some(i) => {
                    in_comment = false;
                    line = search[i + 3..].to_string();
                }
            }
        }
        let t = line.trim();
        let header = t.starts_with('#') && t.trim_start_matches('#').chars().next().is_none_or(char::is_whitespace);
        let stub = {
            let mut c = t.chars();
            matches!(c.next(), Some('-' | '*' | '+')) && {
                let rest = c.as_str().trim();
                rest.is_empty() || matches!(rest, "[ ]" | "[]" | "[x]" | "[X]")
            }
        };
        let fence = t.strip_prefix("```").is_some_and(|r| r.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'));
        if t.is_empty() || header || stub || fence {
            continue;
        }
        return false;
    }
    true
}

fn strip_token_at_edges(raw: &str) -> (String, bool) {
    let mut text = raw.trim().to_string();
    if !text.contains(HEARTBEAT_TOKEN) {
        return (text, false);
    }
    let mut did = false;
    loop {
        let next = text.trim().to_string();
        if let Some(r) = next.strip_prefix(HEARTBEAT_TOKEN) {
            text = r.trim_start().to_string();
            did = true;
            continue;
        }
        // Token at the end, plus up to 4 trailing non-word chars.
        if let Some(idx) = next.rfind(HEARTBEAT_TOKEN) {
            let after = &next[idx + HEARTBEAT_TOKEN.len()..];
            if after.chars().count() <= 4 && after.chars().all(|c| !(c.is_alphanumeric() || c == '_')) {
                text = format!("{}{}", next[..idx].trim_end(), after.trim_start()).trim_end().to_string();
                did = true;
                continue;
            }
        }
        break;
    }
    (text.split_whitespace().collect::<Vec<_>>().join(" "), did)
}

/// OpenClaw `stripHeartbeatToken` (heartbeat mode): `(should_skip, text)`.
pub fn strip_heartbeat_token(raw: &str, max_ack: usize) -> (bool, String) {
    let t = raw.trim();
    if t.is_empty() {
        return (true, String::new());
    }
    let up = t.to_ascii_uppercase();
    if up == SILENT_REPLY_TOKEN || (up.len() >= 4 && up.len() < SILENT_REPLY_TOKEN.len() && SILENT_REPLY_TOKEN.starts_with(&up)) {
        return (true, String::new());
    }
    if !t.contains(HEARTBEAT_TOKEN) {
        return (false, t.to_string());
    }
    let markup = {
        let mut s = String::new();
        let mut in_tag = false;
        for c in t.chars() {
            match c {
                '<' => in_tag = true,
                '>' if in_tag => {
                    in_tag = false;
                    s.push(' ');
                }
                c if !in_tag => s.push(c),
                _ => {}
            }
        }
        s.replace("&nbsp;", " ").trim_matches(|c| "*`~_".contains(c)).to_string()
    };
    let a = strip_token_at_edges(t);
    let b = strip_token_at_edges(&markup);
    let picked = if a.1 && !a.0.is_empty() { a } else { b };
    if !picked.1 {
        return (false, t.to_string());
    }
    let rest = picked.0.trim().to_string();
    let skip = rest.is_empty() || rest.chars().count() <= max_ack;
    (skip, if skip { String::new() } else { rest })
}

/// OpenClaw `resolveHeartbeatPromptForResponseTool`.
pub fn base_prompt(configured: Option<&str>) -> String {
    match configured.map(str::trim).filter(|p| !p.is_empty()) {
        None => format!("{CONTEXT_PROMPT} {TOOL_INSTRUCTIONS} {TOOL_FALLBACK_INSTRUCTIONS}"),
        Some(p) => {
            let mut r = p.to_string();
            for ins in [TOOL_INSTRUCTIONS, TOOL_FALLBACK_INSTRUCTIONS] {
                if !r.contains(ins) {
                    r = format!("{r}\n\n{ins}");
                }
            }
            r
        }
    }
}

/// System events → prompt (generic events as `System:` lines; cron events as a reminder).
pub fn compose_prompt(base: &str, events: &[crate::wake::WakeEvent], scratch: Option<&str>, deliver_to_user: bool, offset: i32) -> String {
    let (cron, generic): (Vec<_>, Vec<_>) = events.iter().partition(|e| e.source.starts_with("cron:"));
    let mut prompt = if !cron.is_empty() {
        let text = cron.iter().map(|e| e.text.trim()).collect::<Vec<_>>().join("\n");
        let ins = if deliver_to_user { "Please relay this reminder to the user in a helpful and friendly way." } else { "Handle this reminder internally. Do not relay it to the user unless explicitly requested." };
        format!("A scheduled reminder has been triggered. The reminder content is:\n\n{text}\n\n{ins}\n\n{TOOL_INSTRUCTIONS}")
    } else {
        base.to_string()
    };
    if !generic.is_empty() {
        let mut lines = Vec::new();
        for (i, e) in generic.iter().enumerate() {
            for (j, sub) in e.text.lines().enumerate() {
                if i == 0 && j == 0 {
                    lines.push(format!("System: [{}] {sub}", crate::util::fmt_time(e.at, offset)));
                } else {
                    lines.push(format!("System: {sub}"));
                }
            }
        }
        prompt = format!("{}\n\n{prompt}", lines.join("\n"));
    }
    if let Some(s) = scratch.map(str::trim).filter(|s| !s.is_empty()) {
        prompt = format!("{prompt}\n\nHeartbeat monitor scratch:\n{s}");
    }
    prompt
}

// ───────────────────────── heartbeat_respond ─────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub outcome: String,
    pub notify: bool,
    pub summary: String,
    pub notification_text: Option<String>,
    pub reason: Option<String>,
    pub priority: Option<String>,
    pub next_check: Option<String>,
    pub scratch: Option<String>,
}

/// Sessions with a heartbeat run in flight → the response recorded for that run.
static ACTIVE: Mutex<Option<HashMap<String, Option<Response>>>> = Mutex::new(None);

fn begin(session: &str) {
    ACTIVE.lock().unwrap().get_or_insert_with(HashMap::new).insert(session.to_string(), None);
}
fn finish(session: &str) -> Option<Response> {
    ACTIVE.lock().unwrap().as_mut().and_then(|m| m.remove(session)).flatten()
}

pub fn normalize_response(v: &Value) -> Result<Response, String> {
    let o = v.as_object().ok_or("Heartbeat response arguments required")?;
    let notify = o.get("notify").and_then(Value::as_bool).ok_or("notify required")?;
    let txt = |k: &[&str]| k.iter().find_map(|k| o.get(*k).and_then(Value::as_str)).map(str::trim).filter(|s| !s.is_empty()).map(String::from);
    if let Some(s) = o.get("scratch").and_then(Value::as_str) {
        if s.len() > SCRATCH_MAX_BYTES {
            return Err(format!("cron scratch exceeds {SCRATCH_MAX_BYTES} bytes ({} bytes provided)", s.len()));
        }
    }
    let outcome = txt(&["outcome"]).filter(|x| OUTCOMES.contains(&x.as_str()));
    let summary = txt(&["summary"]);
    let (Some(outcome), Some(summary)) = (outcome, summary) else { return Err("Invalid heartbeat response. Provide outcome, notify, and non-empty summary.".into()) };
    Ok(Response {
        outcome,
        notify,
        summary,
        notification_text: txt(&["notificationText", "notification_text"]),
        reason: txt(&["reason"]),
        priority: txt(&["priority"]).filter(|p| PRIORITIES.contains(&p.as_str())),
        next_check: txt(&["nextCheck", "next_check"]),
        scratch: o.get("scratch").and_then(Value::as_str).map(String::from),
    })
}

/// The one-shot heartbeat decision tool. Offered on the heartbeat session; accepted only
/// while a heartbeat run is in flight, once per run.
pub struct HeartbeatRespond;

impl Tool for HeartbeatRespond {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: TOOL_NAME.into(),
            description: "Accept heartbeat result for post-turn handling. `notify=false` no visible send. `notify=true` needs concise notificationText. Scratch is monitor prose only.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "outcome": {"type": "string", "enum": OUTCOMES},
                    "notify": {"type": "boolean"},
                    "summary": {"type": "string"},
                    "notificationText": {"type": "string"},
                    "reason": {"type": "string"},
                    "priority": {"type": "string", "enum": PRIORITIES},
                    "nextCheck": {"type": "string"},
                    "scratch": {"type": "string", "description": "Complete replacement for heartbeat monitor prose; not a recurring schedule."}
                },
                "required": ["outcome", "notify", "summary"],
                "additionalProperties": false
            }),
            parallel_safe: false,
            idempotent: false,
            // The heartbeat prompt instructs the model to call it; it must not hide behind tool search.
            pinned: true,
        }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let mut guard = ACTIVE.lock().unwrap();
        let Some(slot) = guard.as_mut().and_then(|m| m.get_mut(&ctx.session_id)) else {
            return ToolOutput::err("heartbeat_respond is not accepted in this run; follow the configured reply instructions instead");
        };
        let r = match normalize_response(&input) {
            Ok(r) => r,
            Err(e) => return ToolOutput::err(e),
        };
        if slot.is_some() {
            return ToolOutput::err("heartbeat_respond already accepted for this turn");
        }
        let mut public = json!({"status": "accepted", "outcome": r.outcome, "notify": r.notify, "summary": r.summary});
        for (k, v) in [("notificationText", &r.notification_text), ("reason", &r.reason), ("priority", &r.priority), ("nextCheck", &r.next_check)] {
            if let Some(v) = v {
                public[k] = json!(v);
            }
        }
        if let Some(s) = &r.scratch {
            // Persistence happens after the turn; scratch text never echoes into the transcript.
            public["scratchPending"] = json!(true);
            public["scratchBytes"] = json!(s.len());
        }
        *slot = Some(r);
        ToolOutput::ok(serde_json::to_string_pretty(&public).unwrap_or_default())
    }
}

// ───────────────────────── state ─────────────────────────

pub fn state_path(data: &Path) -> PathBuf {
    data.join("heartbeat.json")
}
pub fn scratch_path(data: &Path) -> PathBuf {
    data.join("heartbeat_scratch.md")
}

pub fn load_state(data: &Path) -> Value {
    std::fs::read_to_string(state_path(data)).ok().and_then(|s| serde_json::from_str(&s).ok()).filter(Value::is_object).unwrap_or(json!({}))
}
fn save_state(data: &Path, v: &Value) {
    let _ = std::fs::create_dir_all(data);
    let _ = crate::util::atomic_write(&state_path(data), serde_json::to_string_pretty(v).unwrap_or_default().as_bytes());
}
fn update_state(data: &Path, f: impl FnOnce(&mut Value)) {
    let mut v = load_state(data);
    f(&mut v);
    save_state(data, &v);
}

/// `seagent system heartbeat enable|disable` (an override on top of the config).
pub fn set_enabled(data: &Path, on: bool) {
    update_state(data, |v| {
        v["enabled"] = json!(on);
        if on {
            v["next_due"] = json!(0);
        }
    });
}
pub fn enabled_override(data: &Path) -> Option<bool> {
    load_state(data)["enabled"].as_bool()
}
/// The last heartbeat record (`seagent system heartbeat last`).
pub fn last(data: &Path) -> Value {
    load_state(data).get("last").cloned().unwrap_or(Value::Null)
}

// ───────────────────────── presence ─────────────────────────

pub fn presence_path(data: &Path) -> PathBuf {
    data.join("presence.json")
}

/// Refresh this process's presence entry (`seagent system presence`; OpenClaw `system-presence`).
pub fn touch_presence(data: &Path, mode: &str) {
    let pid = std::process::id();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname").map(|h| h.trim().to_string()).unwrap_or_default();
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let host = seagent_core::platform::sysinfo::hostname();
    let _ = crate::automation::with_list(&presence_path(data), |v: &mut Vec<Value>| {
        v.retain(|e| e["pid"].as_u64() != Some(pid as u64) && e["ts"].as_i64().is_some_and(|t| unix_now() - t < 7 * 86_400));
        v.push(json!({"mode": mode, "pid": pid, "host": host, "version": env!("CARGO_PKG_VERSION"), "platform": format!("{} {}", std::env::consts::OS, std::env::consts::ARCH), "ts": unix_now()}));
    });
}

/// Presence entries with liveness (`alive` = the pid still runs and refreshed recently).
pub fn presence(data: &Path) -> Vec<Value> {
    let now = unix_now();
    crate::automation::read_list::<Value>(&presence_path(data))
        .unwrap_or_default()
        .into_iter()
        .map(|mut e| {
            let pid = e["pid"].as_u64().unwrap_or(0) as i32;
            let fresh = e["ts"].as_i64().is_some_and(|t| now - t < PRESENCE_FRESH_SECS);
            #[cfg(unix)]
            let alive = pid > 0 && unsafe { libc::kill(pid, 0) } == 0;
            #[cfg(not(unix))]
            let alive = pid > 0 && seagent_core::platform::proc::alive(pid);
            e["alive"] = json!(alive && fresh);
            e["age_secs"] = json!(e["ts"].as_i64().map(|t| now - t));
            e
        })
        .collect()
}

// ───────────────────────── runner ─────────────────────────

static RUNNING: AtomicBool = AtomicBool::new(false);
static LAST_PRESENCE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
/// A presence entry counts as live while it is younger than this (and its pid runs).
pub const PRESENCE_FRESH_SECS: i64 = 300;
/// How often the daemon re-stamps its entry: comfortably inside the freshness window, but
/// not every minute — each stamp is a whole-file rewrite with two fsyncs, and the pid check
/// already catches a daemon that died.
pub const PRESENCE_REFRESH_SECS: i64 = 240;
const _: () = assert!(PRESENCE_REFRESH_SECS < PRESENCE_FRESH_SECS, "a live daemon must never look stale between stamps");

/// Last `[heartbeat]` error reported (reported once per distinct message, never every tick).
fn config_error() -> &'static Mutex<Option<String>> {
    static E: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    E.get_or_init(|| Mutex::new(None))
}

/// Say why heartbeat runs are skipped, once: `true` when this message was printed now.
/// A bad table must never take the daemon down (upstream `loadHeartbeatConfig` logs and
/// keeps serving), and it must not be silent either — a typo in `every` used to stall the
/// heartbeat forever with no diagnostic.
pub fn report_config_error(msg: Option<&str>) -> bool {
    let mut last = config_error().lock().unwrap_or_else(|e| e.into_inner());
    let want = msg.map(String::from);
    if *last == want {
        return false;
    }
    if let Some(m) = &want {
        eprintln!("seagentd: {m} — heartbeat runs are skipped until it is fixed (`seagent config get heartbeat`)");
    }
    *last = want;
    true
}

/// Called from the daemon's scheduler loop every ~200ms: starts a beat in the background when due.
pub fn daemon_tick(k: &Kernel) {
    let now = unix_now();
    if now - LAST_PRESENCE.load(Ordering::Relaxed) >= PRESENCE_REFRESH_SECS {
        LAST_PRESENCE.store(now, Ordering::Relaxed);
        touch_presence(&k.paths.data, "daemon");
    }
    let cfg = match HeartbeatConfig::from_table(&k.cfg.heartbeat) {
        Ok(Some(c)) => {
            report_config_error(None);
            c
        }
        Ok(None) => {
            report_config_error(None);
            return;
        }
        Err(e) => {
            report_config_error(Some(&format!("[heartbeat] {e}")));
            return;
        }
    };
    if enabled_override(&k.paths.data) == Some(false) || seagent_security::estop::is_engaged(&k.paths.data) {
        return;
    }
    let now = unix_now();
    let due = load_state(&k.paths.data)["next_due"].as_i64().unwrap_or(0);
    if now < due && !crate::wake::wants_now(&k.paths.data) {
        return;
    }
    if RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    let k = k.clone();
    std::thread::spawn(move || {
        let _ = run_once(&k, &cfg, now);
        RUNNING.store(false, Ordering::SeqCst);
    });
}

/// What one beat did (also stored as `last`).
#[derive(Debug, Clone, PartialEq)]
pub struct Beat {
    pub status: String,
    pub notified: bool,
    pub text: String,
    pub session: Option<String>,
    pub delivery: Option<String>,
}

fn heartbeat_session(k: &Kernel, cfg: &HeartbeatConfig, ws: &Path) -> Result<String, String> {
    if let Some(s) = cfg.session.as_deref().filter(|s| k.store.exists(s)) {
        return Ok(s.to_string());
    }
    if !cfg.isolated_session {
        if let Some(s) = load_state(&k.paths.data)["session"].as_str().filter(|s| k.store.exists(s)) {
            return Ok(s.to_string());
        }
    }
    let id = k.create_session(ws, cfg.model.as_deref(), None, Some("heartbeat")).map_err(|e| e.to_string())?;
    update_state(&k.paths.data, |v| v["session"] = json!(id));
    Ok(id)
}

/// Run one heartbeat now (the daemon calls this when due; tests and `seagent system heartbeat run` too).
pub fn run_once(k: &Kernel, cfg: &HeartbeatConfig, now: i64) -> Result<Beat, String> {
    let data = k.paths.data.clone();
    update_state(&data, |v| v["next_due"] = json!(now + cfg.every_secs));
    let record = |b: &Beat, extra: Value| {
        update_state(&data, |v| {
            v["last"] = json!({"at": now, "status": b.status, "notified": b.notified, "text": b.text, "session": b.session, "delivery": b.delivery, "detail": extra});
        });
    };
    if !within_active_hours(cfg.active_hours.as_ref(), now, k.cfg.schedule.utc_offset_minutes) {
        let b = Beat { status: "skipped:quiet-hours".into(), notified: false, text: String::new(), session: None, delivery: None };
        record(&b, Value::Null);
        return Ok(b);
    }
    let ws = cfg.workspace.clone().filter(|w| w.is_dir()).unwrap_or_else(|| data.clone());
    let scratch = std::fs::read_to_string(scratch_path(&data)).ok().or_else(|| std::fs::read_to_string(ws.join("HEARTBEAT.md")).ok());
    let has_events = !crate::wake::pending(&data).is_empty();
    if !has_events && effectively_empty(scratch.as_deref()) {
        let b = Beat { status: "skipped:empty-scratch".into(), notified: false, text: String::new(), session: None, delivery: None };
        record(&b, Value::Null);
        return Ok(b);
    }
    let session = heartbeat_session(k, cfg, &ws)?;
    if k.is_running(&session) {
        let b = Beat { status: "skipped:busy".into(), notified: false, text: String::new(), session: Some(session), delivery: None };
        record(&b, Value::Null);
        return Ok(b);
    }
    let events = crate::wake::drain(&data);
    let deliver = !matches!(cfg.target.as_str(), "none" | "local");
    let prompt = compose_prompt(&base_prompt(cfg.prompt.as_deref()), &events, scratch.as_deref(), deliver, k.cfg.schedule.utc_offset_minutes);
    let prompt = crate::hooks::heartbeat_prompt(k, &session, &ws.to_string_lossy(), "heartbeat", &prompt);
    k.set_session_tools(&session, vec![Arc::new(HeartbeatRespond)]);
    begin(&session);
    let r = k.submit(&session, &prompt, "heartbeat").map_err(|e| e.to_string()).and_then(|_| k.run(&session, RunOpts::default()).map_err(|e| e.to_string()));
    let resp = finish(&session);
    let o = match r {
        Ok(o) => o,
        Err(e) => {
            let b = Beat { status: "error".into(), notified: false, text: e.clone(), session: Some(session), delivery: None };
            record(&b, Value::Null);
            return Err(e);
        }
    };
    let (notify, text, detail) = match &resp {
        Some(r) => {
            if let Some(s) = &r.scratch {
                let _ = crate::util::atomic_write(&scratch_path(&data), s.as_bytes());
            }
            (r.notify, if r.notify { r.notification_text.clone().unwrap_or_else(|| r.summary.clone()) } else { String::new() }, json!({"outcome": r.outcome, "summary": r.summary, "priority": r.priority, "nextCheck": r.next_check, "reason": r.reason}))
        }
        None => {
            let (skip, t) = strip_heartbeat_token(&o.text, cfg.ack_max_chars);
            (!skip, t, json!({"reply": crate::util::head_tail(&o.text, 500).0}))
        }
    };
    let mut delivery = None;
    if notify && deliver && !text.trim().is_empty() {
        let receipts: Vec<String> = cfg.target.split(',').map(str::trim).filter(|p| !p.is_empty() && *p != "last").filter_map(|p| Target::parse(p).ok()).map(|t| match outbound::deliver(&t, &Payload::new("heartbeat", text.clone())) {
            Ok(r) => r,
            Err(e) => format!("delivery to {} failed: {e}", t.render()),
        }).collect();
        delivery = Some(receipts.join("; "));
    }
    let b = Beat { status: if notify { "notified".into() } else { "ok".into() }, notified: notify, text, session: Some(session), delivery };
    record(&b, detail);
    Ok(b)
}

#[cfg(test)]
mod tests;
