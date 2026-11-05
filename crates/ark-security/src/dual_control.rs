//! Four-eyes / dual control for high-risk actions (`[approvals.dual_control]`).
//!
//! ```toml
//! [approvals.dual_control]
//! enabled = true
//! min_approvals = 2                  # distinct principals, never the requester
//! tools = ["shell", "sql_query"]     # tool names (fnmatch globs)
//! gates = ["privilege"]              # gate kinds: privilege | egress | exec | write
//! rules = ["*sudo*", "*DROP*"]       # globs over the gate rule / reason text
//! min_tier = 3                       # every call at or above this risk tier (0 = off)
//! approver_roles = ["admin"]         # roles that may vote (empty = anyone allowed to approve)
//! approvers = ["sso:ciso@corp.example"]  # explicit principals that may vote too
//! expiry_secs = 3600                 # the request is denied when the quorum is not reached
//! ```
//!
//! A request that matches any selector skips every quiet path (durable grants, `/yolo`,
//! `mode = "off"`, remembered "always", task envelopes, the smart/auto reviewer) and waits for
//! `min_approvals` approvals from **distinct** principals, none of them the session's owner.
//! One deny from an eligible approver ends it. "always" / "permanent" answers count as one
//! approval of this call only: a durable grant would let the next call skip the second pair
//! of eyes. This module is the pure state machine; the kernel keeps the open quorums and
//! writes every request / vote / outcome to the audit stream.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DualControlConfig {
    pub enabled: bool,
    pub min_approvals: u32,
    pub tools: Vec<String>,
    pub gates: Vec<String>,
    pub rules: Vec<String>,
    pub min_tier: u8,
    pub approver_roles: Vec<String>,
    pub approvers: Vec<String>,
    pub expiry_secs: u64,
    /// Open a change request in the on-prem ticketing system for every dual-controlled
    /// request; the ticket's approval counts as one approver, its rejection denies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_control: Option<ChangeControlConfig>,
}

/// `[approvals.dual_control.change_control]` — ServiceNow / Jira Server change control.
///
/// ```toml
/// [approvals.dual_control.change_control]
/// system = "servicenow"                 # servicenow | jira
/// url = "https://itsm.corp.example"
/// user = "ark-integration"              # basic auth user (ServiceNow) / empty for a Jira PAT
/// token = "{{secret:ITSM_TOKEN}}"       # password (with `user`) or bearer token
/// poll_secs = 30
/// # ServiceNow: the `change_request` record's `approval` field decides.
/// # Jira: the issue's status name decides.
/// project = "CHG"                       # Jira project key
/// issue_type = "Change"
/// approved = ["Approved"]               # Jira statuses that approve
/// rejected = ["Declined", "Rejected"]   # Jira statuses that reject
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ChangeControlConfig {
    pub system: String,
    pub url: String,
    pub user: String,
    pub token: String,
    pub poll_secs: u64,
    pub project: String,
    pub issue_type: String,
    pub approved: Vec<String>,
    pub rejected: Vec<String>,
}

impl Default for ChangeControlConfig {
    fn default() -> Self {
        ChangeControlConfig {
            system: "servicenow".into(),
            url: String::new(),
            user: String::new(),
            token: String::new(),
            poll_secs: 30,
            project: String::new(),
            issue_type: "Change".into(),
            approved: vec![],
            rejected: vec![],
        }
    }
}

impl Default for DualControlConfig {
    fn default() -> Self {
        DualControlConfig {
            enabled: false,
            min_approvals: 2,
            tools: vec![],
            gates: vec![],
            rules: vec![],
            min_tier: 0,
            approver_roles: vec![],
            approvers: vec![],
            expiry_secs: 3600,
            change_control: None,
        }
    }
}

impl DualControlConfig {
    /// Untouched defaults (left out of config dumps).
    pub fn is_default(&self) -> bool {
        *self == DualControlConfig::default()
    }

    /// Does a gated call need the quorum? `gate` is the lower-case gate kind.
    pub fn applies(&self, tool: &str, gate: &str, reason: &str, tier: u8) -> bool {
        if !self.enabled {
            return false;
        }
        self.tools.iter().any(|p| crate::glob::fnmatch(p, tool))
            || self.gates.iter().any(|g| g.eq_ignore_ascii_case(gate))
            || self
                .rules
                .iter()
                .any(|p| crate::glob::fnmatch(&p.to_lowercase(), &reason.to_lowercase()))
            || (self.min_tier > 0 && tier >= self.min_tier)
    }

    pub fn required(&self) -> u32 {
        self.min_approvals.max(1)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.enabled
            && self.tools.is_empty()
            && self.gates.is_empty()
            && self.rules.is_empty()
            && self.min_tier == 0
        {
            return Err("[approvals.dual_control] is enabled but selects nothing (set tools, gates, rules or min_tier)".into());
        }
        for g in &self.gates {
            if !matches!(
                g.to_ascii_lowercase().as_str(),
                "privilege" | "egress" | "exec" | "write"
            ) {
                return Err(format!("[approvals.dual_control] gates: unknown gate `{g}` (privilege, egress, exec, write)"));
            }
        }
        if let Some(cc) = &self.change_control {
            if !matches!(cc.system.as_str(), "servicenow" | "jira") {
                return Err(format!(
                    "[approvals.dual_control.change_control] system `{}`: use servicenow or jira",
                    cc.system
                ));
            }
            if !cc.url.starts_with("https://") && !cc.url.starts_with("http://") {
                return Err(
                    "[approvals.dual_control.change_control] url must be http(s)://".into(),
                );
            }
            if cc.system == "jira" && (cc.project.trim().is_empty() || cc.approved.is_empty()) {
                return Err("[approvals.dual_control.change_control] jira needs `project` and the `approved` statuses".into());
            }
        }
        for r in &self.approver_roles {
            if !matches!(r.as_str(), "admin" | "user" | "operator") {
                return Err(format!("[approvals.dual_control] approver_roles: `{r}` cannot approve (admin, user or operator; auditors never approve)"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vote {
    /// `kind:name` principal label.
    pub by: String,
    pub role: String,
    pub approve: bool,
    pub at_ms: u64,
    pub via: String,
}

/// One open dual-control request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Quorum {
    pub id: String,
    pub session: String,
    pub tool: String,
    /// Owner of the session that asked (`kind:name`); never an eligible approver.
    pub requester: String,
    pub required: u32,
    pub approver_roles: Vec<String>,
    pub approvers: Vec<String>,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub votes: Vec<Vote>,
    /// The change ticket (`change:<system>:<number>`) whose approval counts as one vote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_ticket: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Counted; more approvals are needed.
    Recorded { have: u32, need: u32 },
    /// Quorum reached: the approvers, in order.
    Approved(Vec<String>),
    /// An eligible approver said no.
    Denied(String),
    /// The vote does not count (and nothing changed).
    Refused(String),
}

impl Quorum {
    pub fn new(
        cfg: &DualControlConfig,
        id: &str,
        session: &str,
        tool: &str,
        requester: &str,
        now_ms: u64,
    ) -> Quorum {
        Quorum {
            id: id.into(),
            session: session.into(),
            tool: tool.into(),
            requester: requester.into(),
            required: cfg.required(),
            approver_roles: cfg.approver_roles.clone(),
            approvers: cfg.approvers.clone(),
            created_ms: now_ms,
            expires_ms: now_ms + cfg.expiry_secs.max(1) * 1000,
            votes: vec![],
            change_ticket: None,
        }
    }

    pub fn approvals(&self) -> Vec<String> {
        self.votes
            .iter()
            .filter(|v| v.approve)
            .map(|v| v.by.clone())
            .collect()
    }

    /// Why `who` (with `roles`) may not vote, if it may not. `same_person` says whether a label
    /// is the requester under another name (a registered user's SSO login and chat id).
    pub fn ineligible(
        &self,
        who: &str,
        roles: &[String],
        same_person: &dyn Fn(&str, &str) -> bool,
        now_ms: u64,
    ) -> Option<String> {
        if now_ms >= self.expires_ms {
            return Some("this dual-control request has expired".into());
        }
        if who.is_empty() {
            return Some("an anonymous answer cannot count towards dual control".into());
        }
        if who == self.requester || same_person(who, &self.requester) {
            return Some(format!(
                "`{who}` asked for this action and cannot approve it (dual control)"
            ));
        }
        if self
            .votes
            .iter()
            .any(|v| v.by == who || same_person(&v.by, who))
        {
            return Some(format!(
                "`{who}` has already answered this request; dual control needs a different person"
            ));
        }
        if !roles.is_empty() && roles.iter().all(|r| r == "auditor") {
            return Some("auditors never approve".into());
        }
        // The change ticket opened for this request is the change advisory board's vote.
        let listed =
            self.approvers.iter().any(|a| a == who) || self.change_ticket.as_deref() == Some(who);
        // No role list: anyone may vote unless an explicit approver list narrows it.
        let by_role = if self.approver_roles.is_empty() {
            self.approvers.is_empty()
        } else {
            roles.iter().any(|r| self.approver_roles.contains(r))
        };
        if !listed && !by_role {
            return Some(format!(
                "`{who}` is not an eligible approver (needs role {} or a listed approver)",
                if self.approver_roles.is_empty() {
                    "any".to_string()
                } else {
                    self.approver_roles.join("|")
                }
            ));
        }
        None
    }

    /// Record one answer.
    pub fn vote(
        &mut self,
        who: &str,
        roles: &[String],
        approve: bool,
        via: &str,
        same_person: &dyn Fn(&str, &str) -> bool,
        now_ms: u64,
    ) -> Outcome {
        // The requester may always withdraw (deny) their own request; only approving needs
        // somebody else.
        let own = !who.is_empty() && (who == self.requester || same_person(who, &self.requester));
        if !approve && own && now_ms < self.expires_ms {
            self.votes.push(Vote {
                by: who.into(),
                role: roles.join("+"),
                approve: false,
                at_ms: now_ms,
                via: format!("{via} (withdrawn)"),
            });
            return Outcome::Denied(who.into());
        }
        if let Some(why) = self.ineligible(who, roles, same_person, now_ms) {
            return Outcome::Refused(why);
        }
        self.votes.push(Vote {
            by: who.into(),
            role: roles.join("+"),
            approve,
            at_ms: now_ms,
            via: via.into(),
        });
        if !approve {
            return Outcome::Denied(who.into());
        }
        let have = self.approvals().len() as u32;
        if have >= self.required {
            Outcome::Approved(self.approvals())
        } else {
            Outcome::Recorded {
                have,
                need: self.required,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> DualControlConfig {
        DualControlConfig {
            enabled: true,
            tools: vec!["sql_*".into()],
            gates: vec!["privilege".into()],
            rules: vec!["*drop table*".into()],
            min_tier: 3,
            ..Default::default()
        }
    }
    fn nobody(_: &str, _: &str) -> bool {
        false
    }
    fn roles(r: &str) -> Vec<String> {
        vec![r.into()]
    }

    #[test]
    fn selectors_pick_tools_gates_rules_and_tiers() {
        let c = cfg();
        assert!(c.applies("sql_query", "exec", "", 1));
        assert!(c.applies("shell", "privilege", "sudo", 1));
        assert!(c.applies("shell", "exec", "runs DROP TABLE users", 1));
        assert!(c.applies("shell", "exec", "x", 3));
        assert!(!c.applies("shell", "exec", "ls", 2));
        assert!(!DualControlConfig {
            enabled: false,
            ..cfg()
        }
        .applies("sql_query", "exec", "", 3));
        assert!(c.validate().is_ok());
        assert!(
            DualControlConfig {
                enabled: true,
                ..Default::default()
            }
            .validate()
            .is_err(),
            "enabled but selects nothing"
        );
        assert!(DualControlConfig {
            approver_roles: vec!["auditor".into()],
            ..cfg()
        }
        .validate()
        .is_err());
        assert!(DualControlConfig {
            gates: vec!["nope".into()],
            ..cfg()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn two_distinct_non_requesters_are_needed() {
        let mut q = Quorum::new(&cfg(), "a1", "s1", "shell", "sso:req", 1000);
        assert!(
            matches!(q.vote("sso:req", &roles("admin"), true, "app", &nobody, 1001), Outcome::Refused(m) if m.contains("asked for this action"))
        );
        assert_eq!(
            q.vote("sso:ann", &roles("admin"), true, "app", &nobody, 1002),
            Outcome::Recorded { have: 1, need: 2 }
        );
        assert!(
            matches!(q.vote("sso:ann", &roles("admin"), true, "app", &nobody, 1003), Outcome::Refused(m) if m.contains("already answered"))
        );
        assert!(
            matches!(q.vote("token:audit", &roles("auditor"), true, "app", &nobody, 1004), Outcome::Refused(m) if m.contains("auditors"))
        );
        assert_eq!(
            q.vote("sso:bob", &roles("user"), true, "app", &nobody, 1005),
            Outcome::Approved(vec!["sso:ann".into(), "sso:bob".into()])
        );
    }

    #[test]
    fn same_person_under_another_name_and_expiry_and_deny() {
        let same = |a: &str, b: &str| {
            (a == "channel:slack:U1" && b == "sso:req")
                || (b == "channel:slack:U1" && a == "sso:req")
        };
        let mut q = Quorum::new(&cfg(), "a1", "s1", "shell", "sso:req", 0);
        assert!(
            matches!(
                q.vote("channel:slack:U1", &[], true, "button", &same, 1),
                Outcome::Refused(_)
            ),
            "the requester's chat id is still the requester"
        );
        assert!(
            matches!(q.vote("sso:ann", &roles("admin"), true, "app", &nobody, 3_600_000), Outcome::Refused(m) if m.contains("expired"))
        );
        let mut q = Quorum::new(&cfg(), "a2", "s1", "shell", "sso:req", 0);
        assert_eq!(
            q.vote("sso:ann", &roles("admin"), false, "app", &nobody, 1),
            Outcome::Denied("sso:ann".into())
        );
    }

    #[test]
    fn approver_roles_and_explicit_approvers() {
        let c = DualControlConfig {
            approver_roles: vec!["admin".into()],
            approvers: vec!["channel:slack:CISO".into()],
            ..cfg()
        };
        let mut q = Quorum::new(&c, "a1", "s1", "shell", "sso:req", 0);
        assert!(
            matches!(q.vote("sso:dev", &roles("user"), true, "app", &nobody, 1), Outcome::Refused(m) if m.contains("not an eligible approver"))
        );
        assert_eq!(
            q.vote("channel:slack:CISO", &[], true, "button", &nobody, 2),
            Outcome::Recorded { have: 1, need: 2 }
        );
        assert!(matches!(
            q.vote("sso:boss", &roles("admin"), true, "app", &nobody, 3),
            Outcome::Approved(_)
        ));
        // Only an explicit list: roles alone do not qualify.
        let c = DualControlConfig {
            approvers: vec!["sso:x".into()],
            ..cfg()
        };
        let mut q = Quorum::new(&c, "a1", "s1", "shell", "sso:req", 0);
        assert!(matches!(
            q.vote("sso:boss", &roles("admin"), true, "app", &nobody, 1),
            Outcome::Refused(_)
        ));
    }

    #[test]
    fn the_requester_can_withdraw_but_not_approve() {
        let cfg = DualControlConfig { enabled: true, min_approvals: 2, expiry_secs: 60, ..Default::default() };
        let never = |_: &str, _: &str| false;
        let mut r = Quorum::new(&cfg, "a1", "s1", "shell", "token:alice", 1_000);
        assert!(matches!(r.vote("token:alice", &[], true, "web", &never, 2_000), Outcome::Refused(_)));
        assert!(matches!(r.vote("token:alice", &[], false, "web", &never, 2_000), Outcome::Denied(ref w) if w == "token:alice"));
        assert!(r.votes.last().unwrap().via.contains("withdrawn"));
    }
}
