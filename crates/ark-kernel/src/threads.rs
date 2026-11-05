//! Thread-bound sub-agent sessions and visible sub-agent sessions.
//!
//! Ports two OpenClaw behaviours `sessions_spawn` has and ark used to fake with labels:
//!
//! * `thread: true | "<name>"` — `src/agents/subagents/spawn/subagent-spawn-thread-binding.ts`
//!   plus `src/channels/thread-bindings-{policy,messages}.ts`. A *new thread* is opened in the
//!   requester's channel conversation, the child session is bound to it, that thread gets an
//!   intro ("… session active. Messages here go directly to this session."), the child's
//!   completion announcement is delivered *into the thread*, and messages posted in the thread
//!   are handled by the bound child. Bindings expire (idle timeout, max age) and the expiry is
//!   announced in the thread; after that messages go back to the parent conversation.
//! * `visible: true` — `src/agents/tools/sessions-spawn-visible.ts`. The child is not a hidden
//!   helper run: it is a first-class, persistent session that shows up in the session list
//!   (sidebar) with its title, group and a live status line, keeps running state visible and is
//!   never cleaned up when it finishes (`cleanup: "keep"` upstream).
//!
//! The channel itself is behind `kernel::HostRoutes` (`create_thread` / `deliver`), so this
//! module owns the policy, the registry and the text; the daemon owns the wire calls.

use crate::config::Config;
use crate::event::now_ms;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

// ───────────────────────── policy ─────────────────────────

/// Upstream `DEFAULT_THREAD_BINDING_IDLE_HOURS` / `DEFAULT_THREAD_BINDING_MAX_AGE_HOURS`.
pub const DEFAULT_IDLE_MS: u64 = 24 * 60 * 60 * 1000;
pub const DEFAULT_MAX_AGE_MS: u64 = 0;

/// Effective thread-binding policy for one channel (`resolveThreadBindingSpawnPolicy`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub channel: String,
    pub enabled: bool,
    pub spawn: bool,
    pub idle_ms: u64,
    pub max_age_ms: u64,
}

fn hours(table: &toml::Table, key: &str) -> Option<f64> {
    match table.get(key)? {
        toml::Value::Integer(n) if *n >= 0 => Some(*n as f64),
        toml::Value::Float(f) if *f >= 0.0 => Some(*f),
        _ => None,
    }
}

fn flag(table: &toml::Table, key: &str) -> Option<bool> {
    table.get(key)?.as_bool()
}

fn binding_table<'a>(cfg: &'a Config, channel: &str) -> Option<&'a toml::Table> {
    cfg.channels
        .get(&channel.to_ascii_lowercase())
        .or_else(|| cfg.channels.get(channel))?
        .get("threadBindings")
        .or_else(|| cfg.channels.get(channel)?.get("thread_bindings"))?
        .as_table()
}

/// `channels.<channel>.threadBindings { enabled, spawnSessions, idleHours, maxAgeHours }`.
/// Defaults follow upstream: bindings on, spawns on, idle 24h, no max age.
pub fn policy(cfg: &Config, channel: &str) -> Policy {
    let t = binding_table(cfg, channel);
    let idle_ms = match t.and_then(|t| hours(t, "idleHours")) {
        Some(h) => (h * 3_600_000.0) as u64,
        None => DEFAULT_IDLE_MS,
    };
    let max_age_ms = match t.and_then(|t| hours(t, "maxAgeHours")) {
        Some(h) => (h * 3_600_000.0) as u64,
        None => DEFAULT_MAX_AGE_MS,
    };
    Policy {
        channel: channel.to_ascii_lowercase(),
        enabled: t.and_then(|t| flag(t, "enabled")).unwrap_or(true),
        spawn: t.and_then(|t| flag(t, "spawnSessions")).unwrap_or(true),
        idle_ms,
        max_age_ms,
    }
}

/// `formatThreadBindingDurationLabel`: "disabled" / "<1m" / "3h" / "45m".
pub fn duration_label(ms: u64) -> String {
    if ms == 0 {
        return "disabled".into();
    }
    if ms < 60_000 {
        return "<1m".into();
    }
    let minutes = ms / 60_000;
    if minutes.is_multiple_of(60) {
        format!("{}h", minutes / 60)
    } else {
        format!("{minutes}m")
    }
}

fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// `resolveThreadBindingThreadName`: "🤖 {label|agent}", whitespace collapsed, ≤100 chars.
pub fn thread_name(agent: &str, label: Option<&str>) -> String {
    let base = label.map(str::trim).filter(|l| !l.is_empty()).unwrap_or(agent);
    let raw = format!("🤖 {base}").split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_chars(&raw, 100)
}

/// `resolveThreadBindingIntroText`, posted into the new thread.
pub fn intro_text(label: &str, idle_ms: u64, max_age_ms: u64, cwd: Option<&str>) -> String {
    let base = truncate_chars(&label.split_whitespace().collect::<Vec<_>>().join(" "), 100);
    let base = if base.is_empty() { "agent".to_string() } else { base };
    let mut lifecycle = Vec::new();
    if idle_ms > 0 {
        lifecycle.push(format!("idle expiry after {} inactivity", duration_label(idle_ms)));
    }
    if max_age_ms > 0 {
        lifecycle.push(format!("max age {}", duration_label(max_age_ms)));
    }
    let head = if lifecycle.is_empty() {
        format!("{base} session active. Messages here go directly to this session.")
    } else {
        format!("{base} session active ({}). Messages here go directly to this session.", lifecycle.join("; "))
    };
    match cwd.map(str::trim).filter(|c| !c.is_empty()) {
        Some(c) => format!("[system] {head}\ncwd: {c}"),
        None => format!("[system] {head}"),
    }
}

/// `resolveThreadBindingFarewellText`, posted when a binding expires or is released.
pub fn farewell_text(reason: &str, idle_ms: u64, max_age_ms: u64) -> String {
    match reason {
        "idle-expired" => format!(
            "[system] Conversation binding expired after {} of inactivity. Messages here will no longer go to that session.",
            duration_label(idle_ms)
        ),
        "max-age-expired" => format!(
            "[system] Conversation binding expired at max age of {}. Messages here will no longer go to that session.",
            duration_label(max_age_ms)
        ),
        _ => "[system] This conversation is no longer bound to that session.".into(),
    }
}

// ───────────────────────── registry ─────────────────────────

/// One bound thread. `session` is the child session the thread talks to.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Binding {
    pub session: String,
    pub parent: String,
    pub channel: String,
    pub chat: String,
    pub thread: String,
    pub agent: String,
    pub label: String,
    pub name: String,
    pub intro: String,
    pub bound_at: u64,
    pub last_activity_ms: u64,
    pub idle_ms: u64,
    pub max_age_ms: u64,
}

impl Binding {
    fn key(&self) -> String {
        format!("{}\u{1f}{}\u{1f}{}", self.channel, self.chat, self.thread)
    }

    /// Delivery origin usable by `HostRoutes::deliver` — the thread, not the parent chat.
    pub fn origin(&self) -> Value {
        json!({"channel": self.channel, "to": self.chat, "thread_id": self.thread, "thread_name": self.name, "session_id": self.session})
    }

    /// `{channel, to, thread_id}` summary for tool handles and the `/agents` panel.
    pub fn as_json(&self) -> Value {
        json!({
            "channel": self.channel,
            "chat": self.chat,
            "thread_id": self.thread,
            "name": self.name,
            "session": self.session,
            "idle_ms": self.idle_ms,
            "max_age_ms": self.max_age_ms,
            "bound_at": self.bound_at,
        })
    }
}

pub fn file(paths: &crate::config::Paths) -> PathBuf {
    paths.data.join("thread-bindings.json")
}

pub fn load(paths: &crate::config::Paths) -> Vec<Binding> {
    std::fs::read_to_string(file(paths)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save(paths: &crate::config::Paths, all: &[Binding]) {
    let _ = std::fs::create_dir_all(&paths.data);
    let body = serde_json::to_string_pretty(all).unwrap_or_else(|_| "[]".into());
    let _ = crate::util::atomic_write(&file(paths), body.as_bytes());
}

/// Why `b` is expired at `now`, if it is (`resolveThreadBindingLifecycle`).
pub fn expired(b: &Binding, now: u64) -> Option<&'static str> {
    if b.idle_ms > 0 && now > b.last_activity_ms.max(b.bound_at) + b.idle_ms {
        return Some("idle-expired");
    }
    if b.max_age_ms > 0 && now > b.bound_at + b.max_age_ms {
        return Some("max-age-expired");
    }
    None
}

/// Bind `session` to a freshly opened thread; replaces any earlier binding of that session or
/// thread (one thread ↔ one session).
pub fn bind(paths: &crate::config::Paths, mut b: Binding) -> Binding {
    let now = now_ms();
    b.bound_at = if b.bound_at == 0 { now } else { b.bound_at };
    b.last_activity_ms = now;
    let mut all = load(paths);
    all.retain(|x| x.session != b.session && x.key() != b.key());
    all.push(b.clone());
    save(paths, &all);
    b
}

/// Every binding, in insertion order.
pub fn list(paths: &crate::config::Paths) -> Vec<Binding> {
    load(paths)
}

pub fn by_thread(paths: &crate::config::Paths, channel: &str, chat: &str, thread: &str) -> Option<Binding> {
    load(paths).into_iter().find(|b| b.channel.eq_ignore_ascii_case(channel) && b.chat == chat && b.thread == thread)
}

pub fn by_session(paths: &crate::config::Paths, session: &str) -> Option<Binding> {
    load(paths).into_iter().find(|b| b.session == session)
}

/// Drop the binding of `session` (if any) and return it.
pub fn unbind(paths: &crate::config::Paths, session: &str) -> Option<Binding> {
    let mut all = load(paths);
    let gone = all.iter().position(|b| b.session == session).map(|i| all.remove(i));
    if gone.is_some() {
        save(paths, &all);
    }
    gone
}

fn drop_thread(paths: &crate::config::Paths, channel: &str, chat: &str, thread: &str) -> Option<Binding> {
    let mut all = load(paths);
    let gone = all.iter().position(|b| b.channel.eq_ignore_ascii_case(channel) && b.chat == chat && b.thread == thread).map(|i| all.remove(i));
    if gone.is_some() {
        save(paths, &all);
    }
    gone
}

/// A run in a bound session counts as activity in its thread (keeps the idle timer fresh).
pub fn touch_session(paths: &crate::config::Paths, session: &str) -> bool {
    let mut all = load(paths);
    let Some(b) = all.iter_mut().find(|b| b.session == session) else { return false };
    b.last_activity_ms = now_ms();
    save(paths, &all);
    true
}

/// What an inbound message in a channel thread resolves to.
#[derive(Debug, Clone, PartialEq)]
pub enum Route {
    /// No binding for this thread: handle it like any other message of the chat.
    Unbound,
    /// The thread's child session; activity was refreshed.
    Bound(Box<Binding>),
    /// Expired: the binding is gone (and the caller should post the farewell in the thread).
    Expired { binding: Box<Binding>, reason: &'static str, farewell: String },
}

/// Resolve (and refresh, or expire) the binding an inbound message in `thread` hits.
pub fn route_inbound(paths: &crate::config::Paths, channel: &str, chat: &str, thread: &str) -> Route {
    let Some(b) = by_thread(paths, channel, chat, thread) else { return Route::Unbound };
    let now = now_ms();
    if let Some(reason) = expired(&b, now) {
        drop_thread(paths, channel, chat, thread);
        return Route::Expired { farewell: farewell_text(reason, b.idle_ms, b.max_age_ms), reason, binding: Box::new(b) };
    }
    let mut all = load(paths);
    if let Some(x) = all.iter_mut().find(|x| x.session == b.session) {
        x.last_activity_ms = now;
    }
    save(paths, &all);
    Route::Bound(Box::new(b))
}

// ───────────────────────── visible sessions ─────────────────────────

/// A sub-agent session the user can see and open (`visible: true`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Visible {
    pub session: String,
    pub parent: String,
    pub agent: String,
    pub label: String,
    pub group: String,
    /// `running` / `completed` / `failed` / `timeout` / `interrupted`.
    pub status: String,
    pub created_ms: u64,
    pub updated_ms: u64,
}

fn visible_file(paths: &crate::config::Paths) -> PathBuf {
    paths.data.join("visible-sessions.json")
}

pub fn visible_all(paths: &crate::config::Paths) -> Vec<Visible> {
    std::fs::read_to_string(visible_file(paths)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save_visible(paths: &crate::config::Paths, all: &[Visible]) {
    let _ = std::fs::create_dir_all(&paths.data);
    let body = serde_json::to_string_pretty(all).unwrap_or_else(|_| "[]".into());
    let _ = crate::util::atomic_write(&visible_file(paths), body.as_bytes());
}

/// Publish `v` as a visible session (idempotent: one row per session).
pub fn mark_visible(paths: &crate::config::Paths, mut v: Visible) {
    let now = now_ms();
    v.created_ms = if v.created_ms == 0 { now } else { v.created_ms };
    v.updated_ms = now;
    if v.status.is_empty() {
        v.status = "running".into();
    }
    let mut all = visible_all(paths);
    all.retain(|x| x.session != v.session);
    all.push(v);
    save_visible(paths, &all);
}

/// Update the sidebar status line of a visible session (`run_child` calls this at the end).
pub fn set_visible_status(paths: &crate::config::Paths, session: &str, status: &str) -> bool {
    let mut all = visible_all(paths);
    let Some(v) = all.iter_mut().find(|v| v.session == session) else { return false };
    v.status = status.into();
    v.updated_ms = now_ms();
    save_visible(paths, &all);
    true
}

pub fn visible_of(paths: &crate::config::Paths, session: &str) -> Option<Visible> {
    visible_all(paths).into_iter().find(|v| v.session == session)
}

/// The session behind a path (a session directory or its `events.jsonl`).
pub fn session_of_path(p: &Path) -> Option<String> {
    let name = p.file_name()?.to_string_lossy().to_string();
    if name == "events.jsonl" || name == "live.log" {
        return p.parent()?.file_name().map(|n| n.to_string_lossy().to_string());
    }
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(name: &str) -> crate::config::Paths {
        let root = ark_core::tmp::scratch_path(format!("ark-threads-{name}-{}", crate::util::random_hex(6)));
        let _ = std::fs::create_dir_all(root.join("data"));
        crate::config::Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run"), ..Default::default() }
    }

    fn b(session: &str, thread: &str) -> Binding {
        Binding {
            session: session.into(),
            parent: "parent".into(),
            channel: "discord".into(),
            chat: "C1".into(),
            thread: thread.into(),
            agent: "main".into(),
            label: "audit".into(),
            name: "🤖 audit".into(),
            intro: intro_text("audit", DEFAULT_IDLE_MS, 0, None),
            idle_ms: DEFAULT_IDLE_MS,
            max_age_ms: 0,
            ..Default::default()
        }
    }

    #[test]
    fn thread_names_intro_and_farewell_follow_upstream_text() {
        assert_eq!(thread_name("main", None), "🤖 main");
        assert_eq!(thread_name("main", Some("  audit   pass ")), "🤖 audit pass");
        assert_eq!(thread_name("main", Some(&"x".repeat(300))).chars().count(), 100);
        assert_eq!(duration_label(0), "disabled");
        assert_eq!(duration_label(30_000), "<1m");
        assert_eq!(duration_label(3 * 3_600_000), "3h");
        assert_eq!(duration_label(45 * 60_000), "45m");
        let i = intro_text("audit", DEFAULT_IDLE_MS, 12 * 3_600_000, Some("/w"));
        assert!(i.starts_with("[system] audit session active (idle expiry after 24h inactivity; max age 12h). Messages here go directly to this session."), "{i}");
        assert!(i.ends_with("cwd: /w"));
        assert!(farewell_text("idle-expired", DEFAULT_IDLE_MS, 0).contains("expired after 24h of inactivity"));
        assert!(farewell_text("max-age-expired", DEFAULT_IDLE_MS, 2 * 3_600_000).contains("at max age of 2h"));
        assert_eq!(farewell_text("released", 0, 0), "[system] This conversation is no longer bound to that session.");
    }

    #[test]
    fn spawn_policy_reads_channel_config_with_upstream_defaults() {
        let cfg = Config::default();
        let p = policy(&cfg, "discord");
        assert!(p.enabled && p.spawn);
        assert_eq!((p.idle_ms, p.max_age_ms), (DEFAULT_IDLE_MS, 0));
        let mut cfg = Config::default();
        let t: toml::Table = "kind = \"discord\"\n[threadBindings]\nenabled = false\nspawnSessions = false\nidleHours = 2\nmaxAgeHours = 48\n".parse().unwrap();
        cfg.channels.insert("discord".into(), t);
        let p = policy(&cfg, "discord");
        assert!(!p.enabled && !p.spawn);
        assert_eq!((p.idle_ms, p.max_age_ms), (7_200_000, 172_800_000));
    }

    #[test]
    fn bindings_are_one_thread_one_session_and_looked_up_both_ways() {
        let p = paths("bind");
        bind(&p, b("child-1", "t1"));
        bind(&p, b("child-2", "t2"));
        assert_eq!(by_session(&p, "child-1").unwrap().thread, "t1");
        assert_eq!(by_thread(&p, "DISCORD", "C1", "t2").unwrap().session, "child-2");
        // Rebinding the same session moves it, it never duplicates.
        let mut again = b("child-1", "t3");
        again.label = "second".into();
        bind(&p, again);
        assert_eq!(list(&p).len(), 2);
        assert_eq!(by_thread(&p, "discord", "C1", "t1"), None);
        assert_eq!(by_session(&p, "child-1").unwrap().label, "second");
        assert_eq!(unbind(&p, "child-1").unwrap().thread, "t3");
        assert_eq!(list(&p).len(), 1);
    }

    #[test]
    fn inbound_refreshes_activity_and_expires_on_idle_or_max_age() {
        let p = paths("route");
        let mut one = b("child-1", "t1");
        one.idle_ms = 60_000;
        bind(&p, one);
        match route_inbound(&p, "discord", "C1", "t1") {
            Route::Bound(x) => assert_eq!(x.session, "child-1"),
            other => panic!("{other:?}"),
        }
        assert_eq!(route_inbound(&p, "discord", "C1", "nope"), Route::Unbound);
        // Idle expiry: bound 5 minutes ago, no activity since.
        let mut rows = load(&p);
        rows[0].bound_at = now_ms() - 300_000;
        rows[0].last_activity_ms = rows[0].bound_at;
        save(&p, &rows);
        match route_inbound(&p, "discord", "C1", "t1") {
            Route::Expired { reason, farewell, .. } => {
                assert_eq!(reason, "idle-expired");
                assert!(farewell.contains("24h") || farewell.contains("<1m") || farewell.contains("1m"), "{farewell}");
            }
            other => panic!("{other:?}"),
        }
        assert!(list(&p).is_empty(), "an expired binding is dropped");
        assert_eq!(route_inbound(&p, "discord", "C1", "t1"), Route::Unbound);
        // Max age wins even while the thread is active.
        let mut two = b("child-2", "t2");
        two.max_age_ms = 1_000;
        bind(&p, two);
        let mut rows = load(&p);
        rows[0].bound_at = now_ms() - 5_000;
        rows[0].last_activity_ms = now_ms();
        save(&p, &rows);
        match route_inbound(&p, "discord", "C1", "t2") {
            Route::Expired { reason, .. } => assert_eq!(reason, "max-age-expired"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn visible_sessions_are_published_and_their_status_follows_the_run() {
        let p = paths("visible");
        mark_visible(&p, Visible { session: "sa-1".into(), parent: "p".into(), agent: "main".into(), label: "audit".into(), group: "reviews".into(), ..Default::default() });
        let v = visible_of(&p, "sa-1").unwrap();
        assert_eq!((v.status.as_str(), v.group.as_str()), ("running", "reviews"));
        assert!(set_visible_status(&p, "sa-1", "completed"));
        assert_eq!(visible_of(&p, "sa-1").unwrap().status, "completed");
        assert!(!set_visible_status(&p, "shy", "completed"));
        mark_visible(&p, Visible { session: "sa-1".into(), status: "running".into(), ..Default::default() });
        assert_eq!(visible_all(&p).len(), 1, "one row per session");
        assert_eq!(session_of_path(Path::new("/x/sessions/sa-1/live.log")).as_deref(), Some("sa-1"));
    }
}
