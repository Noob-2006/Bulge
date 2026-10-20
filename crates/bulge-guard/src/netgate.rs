//! Egress domain policy. The VM already blocks host/LAN/special IPs at the
//! packet layer (`bulge-vm`); this decides, per *domain*, whether the guest may
//! reach it, and records which domains and IPs were used (the audit trail and,
//! once wired, the set of IPs egress will pin — see note).
//!
//! Default is "allow but log" in autonomous mode (the user's choice), "ask" for
//! a first-seen domain in collaborative mode. A built-in allowlist of package
//! and dev sources is always allowed without a prompt.
//!
//! NOTE: enforcement ("connect only to IPs this gate resolved") belongs to the
//! network rework in the system-hardening phase; this module is the decision
//! and record layer it will use.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::risk::Autonomy;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetDecision {
    Allow,
    Ask,
    Deny,
}

/// Suffixes always allowed without a prompt (package registries, source hosts,
/// language toolchains). Matched against the domain's end on a label boundary.
const ALLOWLIST: &[&str] = &[
    "crates.io",
    "static.crates.io",
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "npmjs.com",
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "golang.org",
    "proxy.golang.org",
    "sum.golang.org",
    "rustup.rs",
    "sh.rustup.rs",
    "debian.org",
    "ubuntu.com",
    "alpinelinux.org",
    "pkg-containers.githubusercontent.com",
];

fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    domain == suffix || domain.ends_with(&format!(".{suffix}"))
}

pub fn is_allowlisted(domain: &str) -> bool {
    ALLOWLIST.iter().any(|s| domain_matches_suffix(domain, s))
}

#[derive(Debug, Default)]
pub struct NetGate {
    /// domain → the IPs it has resolved to so far.
    seen: BTreeMap<String, Vec<String>>,
    /// Extra per-job allowed suffixes.
    extra_allow: Vec<String>,
    /// Per-job denied suffixes (override everything).
    deny: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainVerdict {
    pub decision: NetDecision,
    /// True the first time this gate saw the domain (drives the log/ask).
    pub first_seen: bool,
}

impl NetGate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow_suffix(&mut self, suffix: impl Into<String>) {
        self.extra_allow.push(suffix.into().to_ascii_lowercase());
    }

    pub fn deny_suffix(&mut self, suffix: impl Into<String>) {
        self.deny.push(suffix.into().to_ascii_lowercase());
    }

    fn allowed_without_prompt(&self, domain: &str) -> bool {
        is_allowlisted(domain) || self.extra_allow.iter().any(|s| domain_matches_suffix(domain, s))
    }

    /// Decide for a domain under the job's autonomy. A denied suffix always
    /// wins. An allowlisted (or already-seen) domain is allowed. A first-seen
    /// domain is allowed+logged in autonomous/full-auto, asked in collaborative.
    pub fn decide(&self, domain: &str, autonomy: Autonomy) -> DomainVerdict {
        let key = domain.trim_end_matches('.').to_ascii_lowercase();
        if self.deny.iter().any(|s| domain_matches_suffix(&key, s)) {
            return DomainVerdict { decision: NetDecision::Deny, first_seen: !self.seen.contains_key(&key) };
        }
        let first_seen = !self.seen.contains_key(&key);
        if self.allowed_without_prompt(&key) || !first_seen {
            return DomainVerdict { decision: NetDecision::Allow, first_seen };
        }
        let decision = match autonomy {
            Autonomy::Collaborative => NetDecision::Ask,
            Autonomy::Autonomous | Autonomy::FullAuto => NetDecision::Allow,
        };
        DomainVerdict { decision, first_seen }
    }

    /// Record that `domain` resolved to `ips` (adds to the known set).
    pub fn record(&mut self, domain: &str, ips: impl IntoIterator<Item = String>) {
        let key = domain.trim_end_matches('.').to_ascii_lowercase();
        let entry = self.seen.entry(key).or_default();
        for ip in ips {
            if !entry.contains(&ip) {
                entry.push(ip);
            }
        }
    }

    pub fn known_domains(&self) -> impl Iterator<Item = (&String, &Vec<String>)> {
        self.seen.iter()
    }

    /// Every IP this gate has resolved (the set egress will eventually pin to).
    pub fn resolved_ips(&self) -> Vec<String> {
        let mut ips: Vec<String> = self.seen.values().flatten().cloned().collect();
        ips.sort();
        ips.dedup();
        ips
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlisted_sources_need_no_prompt() {
        let gate = NetGate::new();
        for d in ["crates.io", "static.crates.io", "github.com", "codeload.github.com", "files.pythonhosted.org"] {
            assert_eq!(gate.decide(d, Autonomy::Collaborative).decision, NetDecision::Allow, "{d}");
        }
    }

    #[test]
    fn suffix_matching_is_label_bounded() {
        assert!(is_allowlisted("github.com"));
        assert!(is_allowlisted("api.github.com"));
        assert!(!is_allowlisted("evilgithub.com"));
        assert!(!is_allowlisted("github.com.attacker.net"));
    }

    #[test]
    fn first_seen_domain_autonomous_allows_collaborative_asks() {
        let gate = NetGate::new();
        assert_eq!(gate.decide("example.com", Autonomy::Autonomous), DomainVerdict { decision: NetDecision::Allow, first_seen: true });
        assert_eq!(gate.decide("example.com", Autonomy::Collaborative), DomainVerdict { decision: NetDecision::Ask, first_seen: true });
    }

    #[test]
    fn seen_domain_is_allowed_thereafter() {
        let mut gate = NetGate::new();
        gate.record("example.com", ["93.184.216.34".to_string()]);
        assert_eq!(gate.decide("example.com", Autonomy::Collaborative).decision, NetDecision::Allow);
        assert_eq!(gate.resolved_ips(), vec!["93.184.216.34".to_string()]);
    }

    #[test]
    fn deny_suffix_overrides() {
        let mut gate = NetGate::new();
        gate.deny_suffix("evil.test");
        assert_eq!(gate.decide("c2.evil.test", Autonomy::Autonomous).decision, NetDecision::Deny);
    }
}
