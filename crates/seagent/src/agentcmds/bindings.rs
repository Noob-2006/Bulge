//! `/session idle <duration|off> | max-age <duration|off> | unbind` (OpenClaw
//! `commands-session.ts`): lifecycle of the binding between a chat and its session.
//!
//! A binding is a channel router route (chat → session). Its lifecycle record lives in
//! `<data>/session-bindings.json` keyed by channel + chat: `bound_at`, `last_activity_ms`,
//! `bound_by` (first sender), `idle_ms`, `max_age_ms`. Every inbound refreshes the activity
//! and, before routing, an expired binding (idle since `last_activity + idle`, or older than
//! `bound_at + max_age`) is unbound so the message opens a fresh session — the
//! "auto-unbind" upstream performs.

use super::{iso, now_ms, text};
use crate::slash::{Ctx, Reply};
use seagent_channel::router::{RouteKey, Router};
use seagent_kernel::config::Paths;
use seagent_kernel::kernel::Kernel;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

const USAGE: &str = "Usage: /session idle <duration|off> | /session max-age <duration|off> | /session unbind (example: /session idle 24h)";
const OFF: &[&str] = &["off", "disable", "disabled", "none", "0"];

static ROUTER: OnceLock<Arc<Router>> = OnceLock::new();
static LOCK: Mutex<()> = Mutex::new(());

/// The daemon's channel router (set by the channel hub when it starts).
pub fn set_router(r: Arc<Router>) {
    let _ = ROUTER.set(r);
}
pub fn router() -> Option<&'static Arc<Router>> {
    ROUTER.get()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Binding {
    pub session: String,
    pub bound_at: u64,
    pub last_activity_ms: u64,
    #[serde(default)]
    pub bound_by: String,
    #[serde(default)]
    pub idle_ms: u64,
    #[serde(default)]
    pub max_age_ms: u64,
}

fn file(paths: &Paths) -> std::path::PathBuf {
    paths.data.join("session-bindings.json")
}
fn key(channel: &str, chat: &str) -> String {
    format!("{channel}\u{1f}{chat}")
}

pub fn load(paths: &Paths) -> BTreeMap<String, Binding> {
    std::fs::read_to_string(file(paths)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}
fn save(paths: &Paths, m: &BTreeMap<String, Binding>) {
    let _ = std::fs::create_dir_all(&paths.data);
    let _ = seagent_kernel::util::atomic_write(&file(paths), serde_json::to_string_pretty(m).unwrap_or_default().as_bytes());
}

/// `24h`, `90m`, `1h30m`, `2d`, `45s`, a bare number = hours (upstream `parseDurationMs`, default unit h).
pub fn parse_duration_ms(raw: &str) -> Result<u64, String> {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() {
        return Err("missing duration".into());
    }
    if OFF.contains(&s.as_str()) {
        return Ok(0);
    }
    if let Ok(n) = s.parse::<f64>() {
        return if n >= 0.0 { Ok((n * 3_600_000.0) as u64) } else { Err("negative duration".into()) };
    }
    let (mut total, mut num) = (0f64, String::new());
    let mut chars = s.chars().peekable();
    let mut any = false;
    while let Some(ch) = chars.next() {
        if ch.is_ascii_digit() || ch == '.' {
            num.push(ch);
            continue;
        }
        let mut unit = ch.to_string();
        while let Some(&n) = chars.peek() {
            if n.is_ascii_alphabetic() {
                unit.push(n);
                chars.next();
            } else {
                break;
            }
        }
        let v: f64 = num.parse().map_err(|_| format!("invalid duration: {raw}"))?;
        num.clear();
        let mul = match unit.as_str() {
            "ms" => 1.0,
            "s" | "sec" | "secs" => 1000.0,
            "m" | "min" | "mins" => 60_000.0,
            "h" | "hr" | "hrs" => 3_600_000.0,
            "d" | "day" | "days" => 86_400_000.0,
            "w" => 604_800_000.0,
            _ => return Err(format!("invalid duration: {raw}")),
        };
        total += v * mul;
        any = true;
    }
    if !num.is_empty() || !any {
        return Err(format!("invalid duration: {raw}"));
    }
    Ok(total as u64)
}

/// Upstream `formatThreadBindingDurationLabel`.
pub fn label(ms: u64) -> String {
    let m = ms / 60_000;
    if ms.is_multiple_of(86_400_000) && ms > 0 {
        format!("{}d", ms / 86_400_000)
    } else if ms.is_multiple_of(3_600_000) && ms > 0 {
        format!("{}h", ms / 3_600_000)
    } else if m > 0 {
        format!("{m}m")
    } else {
        format!("{}s", ms / 1000)
    }
}

/// Why `b` is expired at `now`, if it is.
pub fn expired(b: &Binding, now: u64) -> Option<&'static str> {
    if b.idle_ms > 0 && now > b.last_activity_ms.max(b.bound_at) + b.idle_ms {
        return Some("idle");
    }
    if b.max_age_ms > 0 && now > b.bound_at + b.max_age_ms {
        return Some("max-age");
    }
    None
}

/// Refresh activity, then auto-unbind an expired binding before the router sees the message.
pub fn on_inbound(k: &Kernel, router: &Router, m: &seagent_channel::Inbound) {
    let rk = router.key_for(m);
    let Some(session) = router.session_for(&rk) else { return };
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut all = load(&k.paths);
    let kk = key(&rk.channel, &rk.chat);
    let now = now_ms();
    let b = all.entry(kk.clone()).or_insert_with(|| Binding { session: session.clone(), bound_at: now, last_activity_ms: now, bound_by: m.sender.clone(), ..Default::default() });
    if b.session != session {
        *b = Binding { session: session.clone(), bound_at: now, last_activity_ms: now, bound_by: m.sender.clone(), idle_ms: b.idle_ms, max_age_ms: b.max_age_ms };
    }
    if let Some(why) = expired(b, now) {
        eprintln!("seagentd: channel {}: session binding {} expired ({why}); next message starts fresh", rk.channel, rk.chat);
        router.reset(&rk);
        k.end_session(&session, why);
        all.remove(&kk);
    } else {
        b.last_activity_ms = now;
    }
    save(&k.paths, &all);
}

pub fn cmd_session(c: &Ctx, a: &str) -> Result<Reply, String> {
    let toks: Vec<&str> = a.split_whitespace().collect();
    let action = toks.first().map(|s| s.to_lowercase()).unwrap_or_default();
    if !matches!(action.as_str(), "idle" | "max-age" | "unbind") || (action == "unbind" && toks.len() > 1) {
        return text(USAGE);
    }
    let Some(s) = &c.sender else { return text("⚠️ /session commands must be run inside a bindable conversation.") };
    let rk = RouteKey::chat(&s.channel, &s.chat);
    let router = router();
    let routed = router.and_then(|r| r.session_for(&rk)).or_else(|| router.and_then(|r| r.routes().into_iter().find(|x| x.key.channel == s.channel && x.key.chat == s.chat).map(|x| x.session)));
    let Some(session) = routed.or_else(|| c.session.clone()) else { return text("ℹ️ This conversation is not currently bound.") };
    let paths = &c.k.paths;
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut all = load(paths);
    let kk = key(&s.channel, &s.chat);
    let now = now_ms();
    let b = all.entry(kk.clone()).or_insert_with(|| Binding { session: session.clone(), bound_at: now, last_activity_ms: now, bound_by: String::new(), ..Default::default() });
    let dur = toks[1..].join("");
    if action == "unbind" || !dur.is_empty() {
        if !b.bound_by.is_empty() && b.bound_by != "system" && !s.sender.is_empty() && s.sender != b.bound_by && !s.admin {
            return text(if action == "unbind" { format!("⚠️ Only {} can unbind this conversation.", b.bound_by) } else { format!("⚠️ Only {} can update session lifecycle settings for this conversation.", b.bound_by) });
        }
        if action == "unbind" {
            if let Some(r) = router {
                r.reset(&rk);
            }
            all.remove(&kk);
            save(paths, &all);
            c.k.end_session(&session, "unbind");
            return text("✅ Conversation unbound.");
        }
    }
    let idle = action == "idle";
    let (setting, expiry) = if idle { ("Idle timeout", "next auto-unbind") } else { ("Max age", "hard auto-unbind") };
    if dur.is_empty() {
        let ms = if idle { b.idle_ms } else { b.max_age_ms };
        let base = if idle { b.last_activity_ms.max(b.bound_at) } else { b.bound_at };
        let r = if ms > 0 && base + ms > now { format!("ℹ️ {setting} active ({}, {expiry} at {}).", label(ms), iso(base + ms)) } else { format!("ℹ️ {setting} is currently disabled for this bound session.") };
        save(paths, &all);
        return text(r);
    }
    let Ok(ms) = parse_duration_ms(&dur) else { return text(USAGE) };
    if idle {
        b.idle_ms = ms;
    } else {
        b.max_age_ms = ms;
    }
    let base = if idle { b.last_activity_ms.max(b.bound_at) } else { b.bound_at };
    save(paths, &all);
    if ms == 0 {
        return text(format!("✅ {setting} disabled for 1 binding."));
    }
    text(format!("✅ {setting} set to {} for 1 binding ({expiry} at {}).", label(ms), iso(base + ms)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slash::{self, Sender, Surface};
    use crate::testkit::kit;

    #[test]
    fn durations_and_labels() {
        assert_eq!(parse_duration_ms("24h").unwrap(), 86_400_000);
        assert_eq!(parse_duration_ms("90m").unwrap(), 5_400_000);
        assert_eq!(parse_duration_ms("1h30m").unwrap(), 5_400_000);
        assert_eq!(parse_duration_ms("2").unwrap(), 7_200_000, "default unit hours");
        assert_eq!(parse_duration_ms("off").unwrap(), 0);
        assert!(parse_duration_ms("soon").is_err());
        assert_eq!(label(86_400_000), "1d");
        assert_eq!(label(5_400_000), "90m");
        let b = Binding { bound_at: 1000, last_activity_ms: 5000, idle_ms: 1000, ..Default::default() };
        assert_eq!(expired(&b, 5500), None);
        assert_eq!(expired(&b, 6001), Some("idle"));
        let b = Binding { bound_at: 1000, last_activity_ms: 9000, max_age_ms: 2000, ..Default::default() };
        assert_eq!(expired(&b, 3001), Some("max-age"));
    }

    #[test]
    fn session_command_sets_reports_and_unbinds() {
        let t = kit();
        let router = Arc::new(Router::open(t.paths.data.join("routes"), Default::default()));
        let sid = t.k.create_session(&t.ws, None, None, None).unwrap();
        let rk = RouteKey::chat("tg", "42");
        router.bind(&rk, &sid);
        set_router(router.clone());
        let r = super::router();
        let mk = |sender: &str| crate::slash::Ctx { k: &t.k, ext: None, session: Some(sid.clone()), workspace: t.ws.clone(), surface: Surface::Channel, sender: Some(Sender { channel: "tg".into(), chat: "42".into(), sender: sender.into(), ..Default::default() }), notify: None };
        let c = mk("alice");
        let out = |c: &crate::slash::Ctx, l: &str| slash::run(c, l).unwrap().text.unwrap();
        assert_eq!(out(&c, "/session"), USAGE);
        assert_eq!(out(&c, "/session unbind now"), USAGE);
        if r.is_some_and(|r| Arc::ptr_eq(r, &router)) {
            assert!(out(&c, "/session idle").contains("disabled"));
            let s = out(&c, "/session idle 2h");
            assert!(s.starts_with("✅ Idle timeout set to 2h for 1 binding (next auto-unbind at "), "{s}");
            assert!(out(&c, "/session idle").starts_with("ℹ️ Idle timeout active (2h"));
            assert!(out(&c, "/session max-age 1d").contains("Max age set to 1d"));
            assert!(out(&c, "/session max-age off").contains("Max age disabled"));
            assert_eq!(out(&c, "/session idle soon"), USAGE);
            // Inbound activity: an expired binding is reset before routing.
            let mut all = load(&t.paths);
            let b = all.values_mut().next().unwrap();
            b.last_activity_ms = 1;
            b.bound_at = 1;
            b.bound_by = "bob".into();
            save(&t.paths, &all);
            assert!(out(&mk("alice"), "/session unbind").contains("Only bob can unbind"));
            let m = seagent_channel::Inbound { channel: "tg".into(), chat: "42".into(), sender: "bob".into(), text: "hi".into(), ..Default::default() };
            on_inbound(&t.k, &router, &m);
            assert!(router.session_for(&rk).is_none(), "expired binding unbound");
            router.bind(&rk, &sid);
            assert_eq!(out(&mk("bob"), "/session unbind"), "✅ Conversation unbound.");
            assert!(router.session_for(&rk).is_none());
        }
        let cli = crate::slash::Ctx { k: &t.k, ext: None, session: Some(sid.clone()), workspace: t.ws.clone(), surface: Surface::Cli, sender: None, notify: None };
        assert!(out(&cli, "/session idle 1h").contains("bindable conversation"));
    }
}
