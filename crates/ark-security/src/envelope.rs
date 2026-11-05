//! Task envelopes (GAPS-next §0-2 #01) and the store behind them.
//!
//! A long unattended task should be approved **once**, up front: "this task may edit
//! these paths, reach these hosts, run these command patterns, spend at most N, for at
//! most T". Inside the envelope nothing prompts; outside it the normal policy applies.
//! That is what keeps schedules, goals and channel bots usable (§0: 保護不能吃掉自主性).
//!
//! Two invariants the tests pin down:
//! - an envelope can never pre-authorise tier 3 (§0-1 A6 hard floor);
//! - an envelope is bounded in time and scope, so a poisoned task cannot widen it
//!   (§0-2 #02: no permanent global grants).

use crate::risk::{Candidate, Tier};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const MAX_ENVELOPE_MS: u64 = 30 * 24 * 3600 * 1000;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Envelope {
    pub id: String,
    pub label: String,
    /// Session it was opened for (`None` = every session's owner-approved scope is not
    /// what we want; creation always sets it).
    pub session: Option<String>,
    pub created_ms: u64,
    pub expires_ms: u64,
    /// Highest tier this envelope may pre-authorise; clamped to ≤ 2 at creation.
    pub max_tier: u8,
    /// Path globs writes may touch.
    pub paths: Vec<String>,
    /// Host rules (`api.github.com`, `*.github.com`).
    pub hosts: Vec<String>,
    /// Command prefix patterns (`cargo *`, `npm test`).
    pub commands: Vec<String>,
    /// Spend cap for this task.
    pub spend_usd: Option<f64>,
    pub note: String,
    pub revoked: bool,
}

impl Default for Envelope {
    fn default() -> Self {
        Envelope { id: String::new(), label: String::new(), session: None, created_ms: 0, expires_ms: 0, max_tier: 2, paths: vec![], hosts: vec![], commands: vec![], spend_usd: None, note: String::new(), revoked: false }
    }
}

/// What a caller may specify when opening an envelope.
#[derive(Debug, Clone, Default)]
pub struct Spec {
    pub label: String,
    pub session: Option<String>,
    pub ttl_ms: u64,
    pub max_tier: u8,
    pub paths: Vec<String>,
    pub hosts: Vec<String>,
    pub commands: Vec<String>,
    pub spend_usd: Option<f64>,
    pub note: String,
    /// Preset ceiling: the envelope may not exceed it.
    pub ceiling: Tier,
}

pub fn store_path(data: &Path) -> PathBuf {
    data.join("envelopes.json")
}

pub fn load(data: &Path) -> Vec<Envelope> {
    std::fs::read(store_path(data)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save(data: &Path, v: &[Envelope]) -> Result<(), String> {
    std::fs::create_dir_all(data).map_err(|e| e.to_string())?;
    let p = store_path(data);
    // Unique per writer: concurrent sessions open envelopes at the same time.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = p.with_extension(format!("json.{}.{n}.tmp", std::process::id()));
    std::fs::write(&tmp, serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &p).map_err(|e| e.to_string())
}

/// Open an envelope. The tier cap is clamped to `min(spec.max_tier, ceiling, 2)`: tier 3
/// is never pre-authorisable, whatever the caller asks for.
pub fn create(data: &Path, spec: &Spec) -> Result<Envelope, String> {
    if spec.ttl_ms == 0 {
        return Err("an envelope needs a time limit (--ttl)".into());
    }
    let ceiling = spec.ceiling.as_u8().min(2);
    let max_tier = spec.max_tier.min(ceiling);
    let now = now_ms();
    let ttl = spec.ttl_ms.min(MAX_ENVELOPE_MS);
    let e = Envelope {
        id: format!("env-{:x}", now ^ (std::process::id() as u64)),
        label: if spec.label.trim().is_empty() { "task".into() } else { spec.label.clone() },
        session: spec.session.clone(),
        created_ms: now,
        expires_ms: now + ttl,
        max_tier,
        paths: spec.paths.clone(),
        hosts: spec.hosts.clone(),
        commands: spec.commands.clone(),
        spend_usd: spec.spend_usd,
        note: spec.note.clone(),
        revoked: false,
    };
    let mut all = load(data);
    all.retain(|x| x.expires_ms > now && !x.revoked);
    all.push(e.clone());
    save(data, &all)?;
    Ok(e)
}

pub fn revoke(data: &Path, id: &str) -> Result<bool, String> {
    let mut all = load(data);
    let mut hit = false;
    for e in all.iter_mut() {
        if e.id == id || e.label == id {
            e.revoked = true;
            hit = true;
        }
    }
    if hit {
        save(data, &all)?;
    }
    Ok(hit)
}

/// The live envelope for a session, dropping expired ones.
pub fn active(data: &Path, session: &str) -> Option<Envelope> {
    let now = now_ms();
    let all = load(data);
    all.into_iter().rev().find(|e| !e.revoked && e.expires_ms > now && e.session.as_deref().is_none_or(|s| s == session))
}

pub fn remaining_ms(e: &Envelope) -> u64 {
    e.expires_ms.saturating_sub(now_ms())
}

impl Envelope {
    pub fn tier_cap(&self) -> Tier {
        Tier::from_u8(self.max_tier.min(2))
    }

    pub fn covers_path(&self, p: &Path) -> bool {
        let s = p.to_string_lossy().replace('\\', "/");
        self.paths.iter().any(|g| crate::glob::fnmatch(g, &s) || crate::glob::fnmatch(&format!("{g}/**"), &s) || s.starts_with(g.trim_end_matches("/**")))
    }

    pub fn covers_host(&self, h: &str) -> bool {
        self.hosts.iter().any(|r| crate::egress_proxy::host_rule(h, r))
    }

    /// `cargo *` matches `cargo test --all`; a bare `npm test` matches that prefix.
    pub fn covers_command(&self, cmd: &str) -> bool {
        let c = cmd.trim();
        self.commands.iter().any(|p| {
            let p = p.trim();
            if p == "*" {
                return true;
            }
            match p.strip_suffix('*') {
                Some(prefix) => c.starts_with(prefix.trim_end()),
                None => c == p || c.starts_with(&format!("{p} ")),
            }
        })
    }

    /// Does this envelope pre-authorise the call at `tier`?
    pub fn covers(&self, c: &Candidate, tier: Tier) -> bool {
        if self.revoked || now_ms() >= self.expires_ms {
            return false;
        }
        // Hard floor: tier 3 is never covered (§0-1).
        if tier.is_irreversible() || tier > self.tier_cap() {
            return false;
        }
        if !c.writes.iter().all(|p| self.covers_path(p)) {
            return false;
        }
        if !c.hosts.iter().all(|h| self.covers_host(h)) {
            return false;
        }
        if !c.exec.is_empty() && !c.exec.iter().all(|x| self.covers_command(x)) {
            return false;
        }
        if let Some(cap) = self.spend_usd {
            let spend = c.input.get("amount").and_then(|v| v.as_f64()).unwrap_or(0.0);
            if spend > cap {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-removing scratch dir: tests must not leave temp state behind.
    struct D(PathBuf);
    impl Drop for D {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    impl std::ops::Deref for D {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    fn dir() -> D {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let d = ark_core::tmp::scratch_path(format!("ark-env-{}-{}-{}", std::process::id(), now_ms(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
        std::fs::create_dir_all(&d).unwrap();
        D(d)
    }

    fn spec() -> Spec {
        Spec { label: "ship the release".into(), session: Some("s1".into()), ttl_ms: 3_600_000, max_tier: 2, paths: vec!["/work/repo/**".into()], hosts: vec!["*.github.com".into()], commands: vec!["cargo *".into()], spend_usd: Some(5.0), ceiling: Tier::Impactful, ..Default::default() }
    }

    #[test]
    fn inside_the_envelope_nothing_asks() {
        let d = dir();
        let e = create(&d, &spec()).unwrap();
        assert_eq!(active(&d, "s1").as_ref().map(|x| x.id.clone()), Some(e.id.clone()));
        let c = Candidate { exec: vec!["cargo test --all".into()], writes: vec![PathBuf::from("/work/repo/src/x.rs")], hosts: vec!["api.github.com".into()], ..Default::default() };
        assert!(e.covers(&c, Tier::Impactful));
        // Outside the scope: other command, other host, other path, more money.
        let mut c2 = c.clone();
        c2.exec = vec!["cargo publish".into()];
        assert!(e.covers(&c2, Tier::Impactful), "a prefix pattern covers its subcommands");
        c2.exec = vec!["rm -rf /".into()];
        assert!(!e.covers(&c2, Tier::Impactful));
        c2.exec = vec!["cargo test".into()];
        c2.hosts = vec!["evil.test".into()];
        assert!(!e.covers(&c2, Tier::Impactful));
        c2.hosts = vec!["api.github.com".into()];
        c2.writes = vec![PathBuf::from("/etc/passwd")];
        assert!(!e.covers(&c2, Tier::Impactful));
        c2.writes = vec![];
        c2.input = serde_json::json!({"amount": 50});
        assert!(!e.covers(&c2, Tier::Impactful), "the spend cap binds");
        let mut c3 = c.clone();
        c3.writes = vec![];
        assert!(e.covers(&c3, Tier::Impactful), "everything in scope again");
    }

    #[test]
    fn tier_three_is_never_pre_authorised() {
        let d = dir();
        let mut s = spec();
        s.max_tier = 3;
        let e = create(&d, &s).unwrap();
        assert_eq!(e.max_tier, 2, "the cap is clamped below 3");
        let c = Candidate { exec: vec!["psql -c 'drop database prod'".into()], ..Default::default() };
        assert!(!e.covers(&c, Tier::Irreversible));
        s.ceiling = Tier::Recoverable;
        let e = create(&d, &s).unwrap();
        assert_eq!(e.max_tier, 1, "a strict preset's envelope may not reach tier 2");
    }

    #[test]
    fn envelopes_expire_and_can_be_revoked() {
        let d = dir();
        let mut s = spec();
        s.ttl_ms = 1;
        let e = create(&d, &s).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(active(&d, "s1").is_none(), "an expired envelope is gone");
        s.ttl_ms = 3_600_000;
        let e2 = create(&d, &s).unwrap();
        assert!(revoke(&d, &e2.id).unwrap());
        assert!(active(&d, "s1").is_none(), "a revoked envelope is gone");
        assert!(create(&d, &Spec { ttl_ms: 0, ..spec() }).is_err(), "no open-ended envelopes");
        let _ = e;
    }
}

