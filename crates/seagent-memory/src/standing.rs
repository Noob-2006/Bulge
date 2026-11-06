//! Standing intents (OpenClaw `extensions/memory-core/src/standing-intents*`, MIT): a durable
//! reminder fires when the user's message mentions one of its trigger phrases, scoped to a
//! conversation / sender / channel, with cooldown, a fire cap and an optional expiry.
//!
//! Storage is `<data>/memory/standing-intents.json`, one bounded array. The lifecycle only
//! *reads and fires*; `seagent memory intents add|list|remove|clear` is the user's control
//! surface (an agent's own tool writes are not registered here).

use crate::util;
use crate::Host;
use seagent_kernel::lifecycle::Lifecycle;
use serde_json::{json, Value};
use std::sync::Arc;

pub const MAX_TEXT_CHARS: usize = 500;
pub const MAX_TRIGGER_CHARS: usize = 100;

fn path(h: &Host) -> std::path::PathBuf {
    h.memory_dir().join("standing-intents.json")
}

fn load(h: &Host) -> Vec<Value> {
    util::read_json(&path(h)).and_then(|v| v.as_array().cloned()).unwrap_or_default()
}

fn save(h: &Host, rows: &[Value]) -> Result<(), String> {
    util::write_json(&path(h), &Value::Array(rows.to_vec()))
}

/// A trigger phrase matches case-insensitively anywhere in the prompt; whitespace is collapsed
/// so a wrapped message still matches. Triggers are plain keyword phrases, not regexes.
pub fn matches(text: &str, triggers: &[String]) -> bool {
    let t = util::compact_ws(text).to_lowercase();
    triggers.iter().map(|x| util::compact_ws(x).to_lowercase()).filter(|x| !x.is_empty()).any(|x| t.contains(&x))
}

fn scope_matches(intent: &Value, session: &str) -> bool {
    let scope = intent["scope"].as_str().unwrap_or("conversation");
    let value = intent["scopeValue"].as_str().unwrap_or("");
    match scope {
        "conversation" => value.is_empty() || session == value,
        // Session keys carry the channel/sender segments; a value names the one it applies to.
        "sender" | "channel" => value.is_empty() || session.contains(value),
        _ => false,
    }
}

fn expired(intent: &Value, now: u64) -> bool {
    intent["expiresAt"].as_u64().is_some_and(|t| t <= now)
}

/// Whether an intent is due now (enabled, unexpired, below its cap, past cooldown, scope match).
pub fn due(intent: &Value, session: &str, prompt: &str, now: u64) -> bool {
    let triggers: Vec<String> = intent["triggers"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from)).collect();
    intent["enabled"].as_bool().unwrap_or(true)
        && !expired(intent, now)
        && intent["fires"].as_u64().unwrap_or(0) < intent["maxFires"].as_u64().unwrap_or(3)
        && intent["lastFiredAt"].as_u64().is_none_or(|last| now.saturating_sub(last) >= intent["cooldownSecs"].as_u64().unwrap_or(3_600) * 1000)
        && scope_matches(intent, session)
        && matches(prompt, &triggers)
}

/// Fire every due intent, persist the counters, and return their reminders (bounded).
pub fn fire(h: &Host, session: &str, prompt: &str) -> Option<String> {
    let s = &h.settings.standing;
    if !s.enabled {
        return None;
    }
    let now = util::now_ms();
    let mut rows = load(h);
    let mut fired: Vec<String> = Vec::new();
    let mut changed = false;
    for row in rows.iter_mut() {
        if due(row, session, prompt, now) {
            row["fires"] = json!(row["fires"].as_u64().unwrap_or(0) + 1);
            row["lastFiredAt"] = json!(now);
            if let Some(t) = row["text"].as_str() {
                fired.push(t.to_string());
            }
            changed = true;
        }
    }
    if changed {
        let _ = save(h, &rows);
    }
    if fired.is_empty() {
        None
    } else {
        Some(fired.iter().map(|t| format!("- Standing reminder: {t}")).collect::<Vec<_>>().join("\n"))
    }
}

/// Parse `--flag value` from a CLI argv (the memory parser treats unknown switches as text).
fn opt(args: &[String], f: &str) -> Option<String> {
    args.iter().position(|a| a == f).and_then(|i| args.get(i + 1)).cloned().or_else(|| args.iter().find_map(|a| a.strip_prefix(&format!("{f}=")).map(String::from)))
}

/// `seagent memory intents [list|add <triggers> <text>|remove <id>|clear]` with
/// `--scope conversation|sender|channel`, `--scope-value v`, `--cooldown secs`,
/// `--max-fires n`, `--ttl secs`.
pub fn cli(h: &Host, args: &[String]) -> Result<String, String> {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    let mut rows = load(h);
    match sub {
        "list" => {
            if rows.is_empty() {
                return Ok("no standing intents".into());
            }
            Ok(rows.iter().map(|r| format!("{}  {:<12} fires {}/{}  triggers: {}  → {}", r["id"].as_str().unwrap_or(""), r["scope"].as_str().unwrap_or("conversation"), r["fires"].as_u64().unwrap_or(0), r["maxFires"].as_u64().unwrap_or(0), r["triggers"].as_array().into_iter().flatten().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "), r["text"].as_str().unwrap_or(""))).collect::<Vec<_>>().join("\n"))
        }
        "add" => {
            let triggers: Vec<String> = args.get(1).map(|s| s.split(',').map(util::compact_ws).filter(|x| !x.is_empty()).collect()).unwrap_or_default();
            let text = args.get(2).map(|s| s.trim().to_string()).unwrap_or_default();
            if triggers.is_empty() || text.is_empty() {
                return Err("usage: seagent memory intents add \"trigger one,trigger two\" \"the reminder text\" [--scope conversation|sender|channel] [--scope-value v] [--cooldown secs] [--max-fires n] [--ttl secs]".into());
            }
            if text.chars().count() > MAX_TEXT_CHARS || triggers.iter().any(|t| t.chars().count() > MAX_TRIGGER_CHARS) {
                return Err(format!("a reminder is ≤{MAX_TEXT_CHARS} chars and each trigger ≤{MAX_TRIGGER_CHARS} chars"));
            }
            if rows.len() >= h.settings.standing.max_intents {
                return Err(format!("at most {} standing intents ([memory.standing] max_intents)", h.settings.standing.max_intents));
            }
            let scope = opt(args, "--scope").unwrap_or_else(|| "conversation".into());
            if !["conversation", "sender", "channel"].contains(&scope.as_str()) {
                return Err("--scope must be conversation, sender or channel".into());
            }
            let ttl = opt(args, "--ttl").and_then(|v| v.parse::<u64>().ok());
            let now = util::now_ms();
            let r = json!({
                "id": seagent_kernel::util::random_hex(4),
                "text": text,
                "triggers": triggers,
                "scope": scope,
                "scopeValue": opt(args, "--scope-value").unwrap_or_default(),
                "cooldownSecs": opt(args, "--cooldown").and_then(|v| v.parse().ok()).unwrap_or(h.settings.standing.cooldown_secs),
                "maxFires": opt(args, "--max-fires").and_then(|v| v.parse().ok()).unwrap_or(h.settings.standing.max_fires),
                "fires": 0,
                "createdAt": now,
                "lastFiredAt": Value::Null,
                "expiresAt": ttl.map(|s| now + s * 1000),
                "enabled": true,
            });
            rows.push(r.clone());
            save(h, &rows)?;
            Ok(format!("standing intent {} added ({} trigger(s), fires at most {} time(s))", r["id"].as_str().unwrap_or(""), r["triggers"].as_array().map_or(0, |a| a.len()), r["maxFires"]))
        }
        "remove" | "rm" | "delete" => {
            let id = args.get(1).ok_or("usage: seagent memory intents remove <id>")?;
            let before = rows.len();
            rows.retain(|r| r["id"].as_str() != Some(id.as_str()));
            if rows.len() == before {
                return Err(format!("no standing intent `{id}`"));
            }
            save(h, &rows)?;
            Ok(format!("standing intent {id} removed"))
        }
        "clear" => {
            let n = rows.len();
            save(h, &[])?;
            Ok(format!("cleared {n} standing intent(s)"))
        }
        o => Err(format!("unknown `memory intents {o}`; use list, add, remove or clear")),
    }
}

/// Prefetch lifecycle: inject due reminders into the user turn, never into later turns.
pub struct StandingIntents {
    pub host: Arc<Host>,
}

impl StandingIntents {
    pub fn new(host: Arc<Host>) -> StandingIntents {
        StandingIntents { host }
    }
}

impl Lifecycle for StandingIntents {
    fn name(&self) -> String {
        "standing-intents".into()
    }
    fn prefetch(&self, session: &str, _ws: &str, prompt: &str) -> Option<String> {
        fire(&self.host, session, prompt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reminder_fires_scoped_cooldown_cap_and_expiry() {
        let h = crate::test_host("standing", |s| s.standing.enabled = true);
        let a = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(cli(&h, &a(&["add", "deploy freeze,change freeze", "Remind the user that deploys are frozen", "--scope", "channel", "--scope-value", "ops", "--cooldown", "0"])).unwrap().contains("added"));
        assert!(cli(&h, &a(&["add", "expired", "gone", "--ttl", "0"])).unwrap().contains("added"));
        assert!(cli(&h, &a(&["add", "cap", "capped", "--max-fires", "1", "--cooldown", "0"])).unwrap().contains("added"));
        let list = cli(&h, &a(&["list"])).unwrap();
        assert!(list.contains("deploy freeze") && list.contains("Remind the user"));
        // Only the matching channel and phrase fire.
        assert!(fire(&h, "channel:slack:ops", "there is a deploy freeze today").unwrap().contains("deploys are frozen"));
        assert!(fire(&h, "channel:slack:other", "deploy freeze today").is_none(), "other channel");
        assert!(fire(&h, "channel:slack:ops", "nothing relevant").is_none());
        // Cooldown: a zero-cooldown intent fires again; a capped intent stops after one.
        assert!(fire(&h, "channel:slack:ops", "deploy freeze again").is_some());
        assert!(fire(&h, "channel:slack:ops", "cap now").is_some());
        assert!(fire(&h, "channel:slack:ops", "cap again").is_none(), "maxFires honoured");
        assert!(fire(&h, "channel:slack:ops", "expired now").is_none(), "ttl 0 is already expired");
        // The persisted file is bounded JSON and the user can remove/clear.
        let v: Value = serde_json::from_str(&std::fs::read_to_string(path(&h)).unwrap()).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 3);
        let id = v[0]["id"].as_str().unwrap().to_string();
        assert!(cli(&h, &a(&["remove", &id])).unwrap().contains("removed"));
        assert!(cli(&h, &a(&["remove", "nope"])).unwrap_err().contains("no standing intent"));
        assert!(cli(&h, &a(&["clear"])).unwrap().contains("cleared 2"));
        assert!(cli(&h, &a(&["add", "only-trigger"])).unwrap_err().contains("usage"));
        // Disabled means the lifecycle never injects (the file still exists for the CLI).
        let off = crate::test_host("standing-off", |_| {});
        cli(&off, &a(&["add", "deploy", "frozen"])).unwrap();
        assert!(fire(&off, "s", "deploy freeze").is_none());
    }
}
