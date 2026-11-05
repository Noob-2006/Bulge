//! Bot Desktop control lease (Hermes `tools/bot_desktop/lease.py`, MIT): who may act
//! on the agent's screen. `<home>/bot-desktop/lease.json`; missing = the agent holds it,
//! unreadable = fail closed (a human holds it). Every real transition bumps `epoch`.

use crate::util;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Lease {
    pub holder: String,
    #[serde(default)]
    pub viewer_id: String,
    #[serde(default)]
    pub since: f64,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub epoch: u64,
}

pub const HUMAN_HAS_CONTROL: &str = "A human has taken over this desktop (they may be entering a credential). Screen actions and captures are refused until they hand control back. Tell the user what you need in your reply.";

fn path(home: &Path) -> PathBuf {
    home.join("bot-desktop").join("lease.json")
}

pub fn get(home: &Path) -> Lease {
    match std::fs::read_to_string(path(home)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Lease { holder: "agent".into(), viewer_id: String::new(), since: 0.0, reason: String::new(), epoch: 0 },
        Err(_) => Lease { holder: "human".into(), viewer_id: "unreadable-lease".into(), since: 0.0, reason: String::new(), epoch: 0 },
        Ok(s) => serde_json::from_str(&s).unwrap_or(Lease { holder: "human".into(), viewer_id: "unreadable-lease".into(), since: 0.0, reason: String::new(), epoch: 0 }),
    }
}

fn locked<T>(home: &Path, f: impl FnOnce() -> T) -> T {
    let dir = home.join("bot-desktop");
    let _ = util::private_dir(&dir);
    let lf = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("lease.lock"));
    use std::os::unix::io::AsRawFd;
    let fd = lf.as_ref().map(|f| f.as_raw_fd()).unwrap_or(-1);
    if fd >= 0 {
        unsafe { libc::flock(fd, libc::LOCK_EX) };
    }
    let r = f();
    if fd >= 0 {
        unsafe { libc::flock(fd, libc::LOCK_UN) };
    }
    r
}

fn write(home: &Path, l: &Lease) -> Result<(), String> {
    util::write_private(&path(home), serde_json::to_string(l).unwrap().as_bytes()).map_err(|e| e.to_string())
}

/// A human takes the screen (last writer wins; no-op when the same viewer holds it).
pub fn acquire(home: &Path, viewer: &str, reason: &str) -> Result<Lease, String> {
    locked(home, || {
        let cur = get(home);
        if cur.holder == "human" && cur.viewer_id == viewer {
            return Ok(cur);
        }
        let l = Lease { holder: "human".into(), viewer_id: viewer.into(), since: util::now_s(), reason: reason.into(), epoch: cur.epoch + 1 };
        write(home, &l)?;
        Ok(l)
    })
}

/// Hand control back. Only the holder may release; `unless_human` makes it a no-op while a human holds.
pub fn release(home: &Path, viewer: Option<&str>, unless_human: bool) -> Result<Lease, String> {
    locked(home, || {
        let cur = get(home);
        if cur.holder == "agent" || (unless_human && cur.holder == "human") || viewer.is_some_and(|v| v != cur.viewer_id) {
            return Ok(cur);
        }
        let l = Lease { holder: "agent".into(), viewer_id: String::new(), since: util::now_s(), reason: String::new(), epoch: cur.epoch + 1 };
        write(home, &l)?;
        Ok(l)
    })
}

pub fn agent_may_act(home: &Path) -> Result<u64, String> {
    let l = get(home);
    if l.holder == "human" {
        return Err(HUMAN_HAS_CONTROL.into());
    }
    Ok(l.epoch)
}

/// The fence after an action: a takeover during it discards the result.
pub fn fence(home: &Path, admitted: u64) -> Result<(), String> {
    if get(home).epoch != admitted {
        return Err("A human took over this desktop while the action ran; its result was discarded. Tell the user what you need in your reply.".into());
    }
    Ok(())
}

pub fn viewer_may_send_input(home: &Path, viewer: &str) -> bool {
    let l = get(home);
    l.holder == "human" && l.viewer_id == viewer
}

pub fn public_view(home: &Path) -> serde_json::Value {
    let l = get(home);
    let hash = if l.viewer_id.is_empty() { String::new() } else { ark_net::crypto::hex(&ark_net::crypto::sha256(l.viewer_id.as_bytes()))[..12].to_string() };
    json!({"holder": l.holder, "viewer_hash": hash, "since": l.since, "reason": l.reason, "epoch": l.epoch})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_transitions() {
        let home = std::env::temp_dir().join(format!("ark-lease-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        assert_eq!(agent_may_act(&home).unwrap(), 0);
        let l = acquire(&home, "viewer-1", "typing a password").unwrap();
        assert_eq!((l.epoch, l.holder.as_str()), (1, "human"));
        assert_eq!(acquire(&home, "viewer-1", "again").unwrap().epoch, 1, "same viewer: no-op");
        assert_eq!(agent_may_act(&home).unwrap_err(), HUMAN_HAS_CONTROL);
        assert!(fence(&home, 0).is_err());
        assert!(viewer_may_send_input(&home, "viewer-1") && !viewer_may_send_input(&home, "other"));
        assert_eq!(release(&home, None, true).unwrap().holder, "human", "unless_human");
        assert_eq!(release(&home, Some("other"), false).unwrap().holder, "human", "only the holder");
        assert_eq!(release(&home, Some("viewer-1"), false).unwrap().epoch, 2);
        assert_eq!(public_view(&home)["holder"], "agent");
        std::fs::write(home.join("bot-desktop/lease.json"), "garbage").unwrap();
        assert!(agent_may_act(&home).is_err(), "corrupt lease fails closed");
    }
}
