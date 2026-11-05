//! System-event queue for proactive runs (OpenClaw `cron wake` / `system event`):
//! anyone (the `automations` tool, `ark system event`, a hook) enqueues a short
//! text; the heartbeat runner drains it into its next prompt. `mode = "now"`
//! asks the heartbeat to run immediately instead of at the next interval.

use crate::automation::{read_list, with_list};
use crate::util::unix_now;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WakeEvent {
    pub text: String,
    /// `now` | `next-heartbeat`
    pub mode: String,
    pub at: i64,
    /// Who asked (tool, cli, hook…).
    #[serde(default)]
    pub source: String,
}

pub fn path(data: &Path) -> PathBuf {
    data.join("wake.json")
}

/// Queue a system event. Capped at 100 pending events (oldest dropped).
pub fn request(data: &Path, text: &str, mode: &str, source: &str) -> Result<WakeEvent, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("wake text is empty".into());
    }
    let mode = match mode {
        "" | "now" => "now",
        "next-heartbeat" | "next_heartbeat" | "next" => "next-heartbeat",
        m => return Err(format!("wake mode must be `now` or `next-heartbeat`, got `{m}`")),
    };
    let ev = WakeEvent { text: text.into(), mode: mode.into(), at: unix_now(), source: source.into() };
    with_list(&path(data), |v: &mut Vec<WakeEvent>| {
        v.push(ev.clone());
        let n = v.len();
        if n > 100 {
            v.drain(..n - 100);
        }
    })?;
    Ok(ev)
}

/// Pending events without removing them.
pub fn pending(data: &Path) -> Vec<WakeEvent> {
    read_list(&path(data)).unwrap_or_default()
}

/// True when some pending event asks for an immediate run.
pub fn wants_now(data: &Path) -> bool {
    pending(data).iter().any(|e| e.mode == "now")
}

/// Take every pending event (the heartbeat calls this when it builds its prompt).
pub fn drain(data: &Path) -> Vec<WakeEvent> {
    with_list(&path(data), |v: &mut Vec<WakeEvent>| std::mem::take(v)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_and_drain() {
        let d = std::env::temp_dir().join(format!("ark-wake-{}", crate::util::random_hex(8)));
        assert!(request(&d, " ", "now", "t").is_err());
        assert!(request(&d, "x", "later", "t").is_err());
        request(&d, "deploy finished", "next-heartbeat", "tool").unwrap();
        assert!(!wants_now(&d));
        request(&d, "page me", "", "cli").unwrap();
        assert!(wants_now(&d));
        let got = drain(&d);
        assert_eq!(got.iter().map(|e| e.mode.as_str()).collect::<Vec<_>>(), ["next-heartbeat", "now"]);
        assert!(pending(&d).is_empty());
        for i in 0..105 {
            request(&d, &format!("e{i}"), "next", "t").unwrap();
        }
        let p = pending(&d);
        assert_eq!((p.len(), p[0].text.as_str()), (100, "e5"));
    }
}
