//! Trust tiers (plan B5, H4/H7).
//!
//! Every piece of work has a provenance: the owner's own request, a message from
//! a channel participant, content pulled in from somewhere unknown, or a
//! third-party plugin. B5 requires the ends of that range never to share a VM —
//! and therefore never a workspace, a snapshot or a guest process — because the
//! writable workspace is the one channel through which untrusted code could
//! influence trusted work.
//!
//! A tier is only a label: the pool turns [`TrustTier::vm_key`] into a run
//! directory (hence a VM) and [`TrustTier::may_share_workspace_with`] into a sync
//! decision. As everywhere in §0, the answer is separation, not a prompt: no
//! approval dialog, no "trust this plugin?" question — the work simply runs in a
//! VM that owns nothing the owner's work touches.

use crate::config::VmConfig;
use serde::Serialize;

/// How much a piece of work is trusted, from most ([`TrustTier::Owner`]) to least
/// ([`TrustTier::Untrusted`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustTier {
    /// The owner's own request, in the owner's own session.
    Owner,
    /// A message from a participant on one of ark's channels: a real person the
    /// owner connected, but not the owner.
    Channel,
    /// Work steered by content of unknown provenance (fetched pages, forwarded
    /// mail, tool output) or by someone ark has never seen.
    Stranger,
    /// Third-party code: plugins, MCP tool servers, anything not written by the
    /// owner.
    Untrusted,
}

/// How much network a tier may ask the host broker for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkPolicy {
    /// The ordinary egress allow-list, through the broker.
    Full,
    /// Broker only, with the narrowest allow-list (no writes, no auth headers).
    Restricted,
    /// No egress at all; the guest has no NIC and the broker refuses.
    None,
}

impl TrustTier {
    /// Every tier, most trusted first (stable order for docs and tests).
    pub const ALL: [TrustTier; 4] = [TrustTier::Owner, TrustTier::Channel, TrustTier::Stranger, TrustTier::Untrusted];

    /// Wire/on-disk label (`owner`, `channel`, `stranger`, `untrusted`); it is
    /// part of VM ids and log lines, so it must stay stable.
    pub fn label(self) -> &'static str {
        match self {
            TrustTier::Owner => "owner",
            TrustTier::Channel => "channel",
            TrustTier::Stranger => "stranger",
            TrustTier::Untrusted => "untrusted",
        }
    }

    /// Parse a label (case-insensitive), plus the few synonyms ark configs and
    /// plugins used before tiers were one enum.
    pub fn parse(s: &str) -> Option<TrustTier> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "owner" | "user" | "self" => TrustTier::Owner,
            "channel" | "chat" => TrustTier::Channel,
            "stranger" | "external" | "guest" => TrustTier::Stranger,
            "untrusted" | "plugin" | "untrusted_plugin" => TrustTier::Untrusted,
            _ => return None,
        })
    }

    /// Classify a session. Precedence, highest first:
    ///
    /// 1. `plugin` — third-party code is [`TrustTier::Untrusted`] even when the
    ///    owner started the session;
    /// 2. `untrusted_content` — a session that read foreign content can be steered
    ///    by it, so it is a [`TrustTier::Stranger`] even for the owner;
    /// 3. `known_owner` — the owner's own work;
    /// 4. otherwise a channel participant ([`TrustTier::Channel`]).
    pub fn from_session(known_owner: bool, untrusted_content: bool, plugin: bool) -> TrustTier {
        if plugin {
            TrustTier::Untrusted
        } else if untrusted_content {
            TrustTier::Stranger
        } else if known_owner {
            TrustTier::Owner
        } else {
            TrustTier::Channel
        }
    }

    /// May these two tiers use the same workspace? Only identical, non-untrusted
    /// tiers: a VM of another tier would put its files where this tier's agent can
    /// read them (B5).
    pub fn may_share_workspace_with(self, other: TrustTier) -> bool {
        self == other && matches!(self, TrustTier::Owner | TrustTier::Channel)
    }

    /// May this tier make *any* broker request? Width comes from
    /// [`TrustTier::network_policy`]; this is the boolean the exec backend needs.
    pub fn network_allowed(self) -> bool {
        self.network_policy() != NetworkPolicy::None
    }

    /// Full for owner/channel, restricted for strangers, none for untrusted code.
    pub fn network_policy(self) -> NetworkPolicy {
        match self {
            TrustTier::Owner | TrustTier::Channel => NetworkPolicy::Full,
            TrustTier::Stranger => NetworkPolicy::Restricted,
            TrustTier::Untrusted => NetworkPolicy::None,
        }
    }

    /// Stable id of the VM this work runs in — and hence of its run dir,
    /// snapshots and workspace copy.
    ///
    /// * `one_vm_per_session`: the owner gets `s-<session>`; every other tier gets
    ///   `s-<tier>-<session>`, so a stranger session never lands in the owner's VM
    ///   (and two stranger sessions do not contaminate each other).
    /// * otherwise: `tier-<label>` — one VM per tier, shared by all sessions of
    ///   that tier, never across tiers.
    ///
    /// `trust_tiers = false` cannot merge tiers here on purpose: the owner/stranger
    /// boundary is protection, not a preference, so it is not configurable away.
    /// The session part is sanitised to `[A-Za-z0-9._-]` and length-capped, so the
    /// key is always a safe directory name and stable for a given input.
    pub fn vm_key(self, session: &str, cfg: &VmConfig) -> String {
        if cfg.one_vm_per_session {
            let session = sanitize_session(session);
            match self {
                TrustTier::Owner => format!("s-{session}"),
                other => format!("s-{}-{session}", other.label()),
            }
        } else {
            format!("tier-{}", self.label())
        }
    }
}

/// Longest session component kept in a VM key; run-dir paths stay well inside
/// `PATH_MAX` and a hostile session id cannot bloat the tree.
const MAX_SESSION_LEN: usize = 64;

fn sanitize_session(session: &str) -> String {
    let mut out = String::with_capacity(session.len().min(MAX_SESSION_LEN));
    for c in session.chars() {
        if out.len() >= MAX_SESSION_LEN {
            break;
        }
        out.push(if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '-' });
    }
    let trimmed = out.trim_matches(|c| c == '.' || c == '-');
    if trimmed.is_empty() {
        "anon".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(per_session: bool) -> VmConfig {
        VmConfig { one_vm_per_session: per_session, ..VmConfig::default() }
    }

    #[test]
    fn owner_and_stranger_never_share_a_vm_or_workspace() {
        for per_session in [true, false] {
            let c = cfg(per_session);
            let owner = TrustTier::Owner.vm_key("session-1", &c);
            let stranger = TrustTier::Stranger.vm_key("session-1", &c);
            assert_ne!(owner, stranger, "one VM for both tiers (per_session={per_session})");
            assert!(!TrustTier::Owner.may_share_workspace_with(TrustTier::Stranger));
            assert!(!TrustTier::Stranger.may_share_workspace_with(TrustTier::Owner));
        }
        let c = cfg(true);
        let keys: Vec<String> = TrustTier::ALL.iter().map(|t| t.vm_key("session-1", &c)).collect();
        let mut unique = keys.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), keys.len(), "every tier gets its own VM: {keys:?}");
        assert_eq!(keys[0], "s-session-1", "the owner's VM is keyed by session");
    }

    #[test]
    fn stranger_sessions_share_one_vm_only_without_per_session_vms() {
        let shared = cfg(false);
        assert_eq!(TrustTier::Stranger.vm_key("a", &shared), "tier-stranger");
        assert_eq!(TrustTier::Stranger.vm_key("b", &shared), TrustTier::Stranger.vm_key("a", &shared));
        assert_ne!(TrustTier::Stranger.vm_key("a", &shared), TrustTier::Owner.vm_key("a", &shared));

        let per_session = cfg(true);
        assert_ne!(
            TrustTier::Stranger.vm_key("a", &per_session),
            TrustTier::Stranger.vm_key("b", &per_session),
            "a fresh VM per stranger session is strictly safer"
        );
        assert!(TrustTier::Stranger.vm_key("a", &per_session).starts_with("s-stranger-"));
    }

    #[test]
    fn untrusted_has_no_network() {
        assert_eq!(TrustTier::Untrusted.network_policy(), NetworkPolicy::None);
        assert!(!TrustTier::Untrusted.network_allowed());
        assert!(TrustTier::Owner.network_allowed() && TrustTier::Channel.network_allowed());
        assert_eq!(TrustTier::Stranger.network_policy(), NetworkPolicy::Restricted);
        assert!(TrustTier::Stranger.network_allowed(), "a stranger gets broker egress with the narrowest allow-list");
    }

    #[test]
    fn parse_and_labels_are_stable() {
        for t in TrustTier::ALL {
            assert_eq!(TrustTier::parse(t.label()), Some(t));
            assert_eq!(TrustTier::parse(&t.label().to_ascii_uppercase()), Some(t));
        }
        assert_eq!(TrustTier::parse("plugin"), Some(TrustTier::Untrusted));
        assert_eq!(TrustTier::parse(" user "), Some(TrustTier::Owner));
        assert_eq!(TrustTier::parse("nonsense"), None);
        assert_eq!(TrustTier::Owner.label(), "owner");
        assert_eq!(TrustTier::Untrusted.label(), "untrusted");
    }

    #[test]
    fn workspaces_are_never_shared_across_tiers() {
        for a in TrustTier::ALL {
            for b in TrustTier::ALL {
                let expected = a == b && matches!(a, TrustTier::Owner | TrustTier::Channel);
                assert_eq!(a.may_share_workspace_with(b), expected, "{a:?} vs {b:?}");
            }
        }
        assert!(!TrustTier::Untrusted.may_share_workspace_with(TrustTier::Untrusted), "untrusted code never gets a shared workspace, not even with itself");
    }

    #[test]
    fn session_classification_precedence_is_plugin_then_content_then_owner() {
        assert_eq!(TrustTier::from_session(true, true, true), TrustTier::Untrusted);
        assert_eq!(TrustTier::from_session(true, true, false), TrustTier::Stranger);
        assert_eq!(TrustTier::from_session(true, false, false), TrustTier::Owner);
        assert_eq!(TrustTier::from_session(false, false, false), TrustTier::Channel);
        assert_eq!(TrustTier::from_session(false, true, false), TrustTier::Stranger);
    }

    #[test]
    fn vm_keys_are_safe_stable_directory_names() {
        let c = cfg(true);
        assert_eq!(TrustTier::Owner.vm_key("../../etc/passwd", &c), "s-etc-passwd", "no traversal, no separators");
        assert_eq!(TrustTier::Owner.vm_key("", &c), "s-anon");
        assert_eq!(TrustTier::Owner.vm_key("A b\tc", &c), TrustTier::Owner.vm_key("A b\tc", &c), "stable");
        assert_eq!(TrustTier::Stranger.vm_key(&"x".repeat(500), &c).len(), "s-stranger-".len() + MAX_SESSION_LEN);
    }
}
