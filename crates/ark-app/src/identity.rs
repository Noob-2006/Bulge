//! Who is calling, and what that person or machine may do (ent-053…058, ent-047, ent-060).
//!
//! A request resolves to one [`Principal`]: an `[app] token` / `[app] tokens` entry, an issued
//! **service account** (`ark app accounts issue`), or a dashboard login (basic or OIDC). Its
//! [`Access`] decides each ARP method / HTTP route:
//!
//! * legacy tokens keep their **scope** ladder (`read < write < approve < admin`, see
//!   [`crate::exposure`]);
//! * logins and service accounts carry **roles**, and a principal may hold several (the
//!   permissions are the union):
//!
//! | role       | may do |
//! |------------|--------|
//! | `admin`    | everything |
//! | `user`     | chat, run sessions, answer approvals, read everything it can see (scope `approve`) |
//! | `operator` | status / metadata reads, restart the daemon, manage channels — **no conversation content** |
//! | `auditor`  | metadata reads and the audit stream (`audit.*`) — **no conversation content** |
//!
//! "Content" is anything that returns what was said or shown: `session.history|view|attach`,
//! event subscriptions, `*.search`, transcripts, the live browser/desktop view and the logbook.
//!
//! Role mapping for logins (`[app.rbac]`), first match wins:
//! 1. a registered user (`ark users`) with an `oidc` identity = the subject, or a linked email,
//!    and a `role` set → that role (a `disabled` profile is refused);
//! 2. `[app.rbac] users` by email / subject / login name;
//! 3. `[app.rbac] groups` against the ID token's groups claim (`groups_claim`, default `groups`;
//!    every matching group adds its role);
//! 4. `default_role` (`user`; `none` refuses the login). Without any `[app.rbac]` table a
//!    `basic` login keeps its historical `admin`; an OIDC login never does.

use crate::exposure::{required_scope, Scope};
use ark_net::crypto;
use ark_security::audit::Actor;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Operator,
    User,
    Auditor,
}

impl Role {
    pub fn parse(s: &str) -> Result<Role, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "admin" | "administrator" => Ok(Role::Admin),
            "operator" | "ops" => Ok(Role::Operator),
            "user" | "member" => Ok(Role::User),
            "auditor" | "audit" => Ok(Role::Auditor),
            other => Err(format!("unknown role `{other}` (expected admin, operator, user or auditor)")),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Operator => "operator",
            Role::User => "user",
            Role::Auditor => "auditor",
        }
    }
}

/// Methods that return what was said, typed or shown.
pub fn is_content_method(m: &str) -> bool {
    const EXACT: &[&str] = &["session.history", "session.view", "session.attach", "events.subscribe", "subscribe", "logbook.list", "session.export", "session.transcript", "chat.send", "message.send"];
    EXACT.contains(&m) || m.ends_with(".search") || m.ends_with(".transcript") || m.ends_with(".history") || m.starts_with("view.") || m.starts_with("memory.") || m.starts_with("ediscovery.")
}

/// Admin-grade methods an operator may still call: lifecycle and channel management.
const OPERATOR_METHODS: &[&str] = &["shutdown", "daemon.", "channel.", "channels.", "plugin.restart", "plugins.restart", "gateway.restart", "node.", "nodes.", "device.", "devices."];

/// The `audit.*` methods an auditor may call (all read-only).
pub const AUDITOR_AUDIT_READS: &[&str] = &["audit.query", "audit.verify", "audit.report"];

fn operator_extra(m: &str) -> bool {
    OPERATOR_METHODS.iter().any(|p| if p.ends_with('.') { m.starts_with(p) } else { m == *p })
}

/// What a principal may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    Scope(Scope),
    Roles(Vec<Role>),
}

impl Access {
    pub fn admin() -> Access {
        Access::Roles(vec![Role::Admin])
    }

    pub fn has(&self, r: Role) -> bool {
        matches!(self, Access::Roles(v) if v.contains(&r))
    }

    /// `Ok(())` or the reason (for a 403 / JSON-RPC -32003).
    pub fn permits(&self, method: &str) -> Result<(), String> {
        let need = required_scope(method);
        match self {
            Access::Scope(s) => {
                // The audit stream is admin-only for scoped tokens.
                let need = if method.starts_with("audit.") { Scope::Admin } else { need };
                if s.allows(need) {
                    Ok(())
                } else {
                    Err(format!("forbidden: this token has scope `{}`; `{method}` needs `{}`", s.as_str(), need.as_str()))
                }
            }
            Access::Roles(roles) => {
                let ok = roles.iter().any(|r| match r {
                    Role::Admin => true,
                    Role::User => !method.starts_with("audit.") && need <= Scope::Approve,
                    Role::Operator => !is_content_method(method) && !method.starts_with("audit.") && (need == Scope::Read || operator_extra(method)),
                    // Read-only by construction: reads, plus the audit stream's read methods
                    // (never a write, an approval or a review mark, whatever is added later).
                    Role::Auditor => !is_content_method(method) && (need == Scope::Read || AUDITOR_AUDIT_READS.contains(&method)),
                });
                if ok {
                    Ok(())
                } else {
                    Err(format!("forbidden: role {} may not call `{method}`", self.label()))
                }
            }
        }
    }

    /// Plain HTTP routes (`/view/*`, `/v1/*`, plugin routes).
    pub fn permits_http(&self, method: &str, path: &str) -> Result<(), String> {
        let need = crate::exposure::required_scope_http(method, path);
        match self {
            Access::Scope(s) if s.allows(need) => Ok(()),
            Access::Scope(s) => Err(format!("forbidden: this token has scope `{}`; `{path}` needs `{}`", s.as_str(), need.as_str())),
            Access::Roles(r) if r.iter().any(|r| matches!(r, Role::Admin | Role::User)) => Ok(()),
            // Live views and the chat API are content; plugin GET pages are treated as reads.
            Access::Roles(_) if need == Scope::Read && !path.starts_with("/view/") && !path.starts_with("/v1/") => Ok(()),
            Access::Roles(_) => Err(format!("forbidden: role {} may not use `{path}`", self.label())),
        }
    }

    /// Metrics / readiness: anything except a bare legacy `read`-less principal (there is none).
    pub fn label(&self) -> String {
        match self {
            Access::Scope(s) => format!("scope:{}", s.as_str()),
            Access::Roles(r) => r.iter().map(|r| r.as_str()).collect::<Vec<_>>().join("+"),
        }
    }
}

/// The authenticated caller of one request.
#[derive(Debug, Clone, PartialEq)]
pub struct Principal {
    /// `token`, `service`, `sso`, `basic`, `plugin`.
    pub kind: String,
    pub name: String,
    pub access: Access,
    /// Client address after trusted-proxy resolution.
    pub ip: String,
    /// Organization / team reach (ent-050); global for the installation owner.
    pub tenant: ark_kernel::tenancy::Viewer,
}

impl Principal {
    pub fn actor(&self) -> Actor {
        Actor { kind: self.kind.clone(), name: self.name.clone(), role: self.access.label(), ip: self.ip.clone() }
    }
    pub fn label(&self) -> String {
        format!("{}:{}", self.kind, self.name)
    }
}

// ───────────────────────── [app.rbac] ─────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RbacConfig {
    /// Role for a login nothing else maps: `user` (default), `auditor`, `operator`, `admin`,
    /// or `none` to refuse unmapped logins.
    pub default_role: String,
    /// ID-token claim holding the group list (Keycloak/Authentik/Entra: `groups`; Okta: often `groups` too).
    pub groups_claim: String,
    /// Group → role.
    pub groups: BTreeMap<String, String>,
    /// Email / subject / login name → role.
    pub users: BTreeMap<String, String>,
    /// IdP group → team (ent-050) for logins that are not registered with a team.
    pub teams: BTreeMap<String, String>,
}

impl Default for RbacConfig {
    fn default() -> Self {
        RbacConfig { default_role: "user".into(), groups_claim: "groups".into(), groups: BTreeMap::new(), users: BTreeMap::new(), teams: BTreeMap::new() }
    }
}

impl RbacConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.default_role != "none" {
            Role::parse(&self.default_role).map_err(|e| format!("[app.rbac] default_role: {e}"))?;
        }
        for (k, v) in self.groups.iter().chain(self.users.iter()) {
            Role::parse(v).map_err(|e| format!("[app.rbac] `{k}`: {e}"))?;
        }
        Ok(())
    }
}

/// What a login presented.
#[derive(Debug, Clone, Default)]
pub struct LoginFacts<'a> {
    /// `basic`, `sso` (OIDC) or `plugin`.
    pub provider: &'a str,
    pub subject: &'a str,
    pub email: &'a str,
    pub groups: Vec<String>,
    /// A plugin provider vouched for admin.
    pub provider_admin: bool,
}

/// Groups from an ID token claim (array of strings, or one space/comma separated string).
pub fn groups_from_claims(claims: &serde_json::Value, claim: &str) -> Vec<String> {
    let c = if claim.trim().is_empty() { "groups" } else { claim.trim() };
    match &claims[c] {
        serde_json::Value::Array(a) => a.iter().filter_map(|g| g.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect(),
        serde_json::Value::String(s) => s.split([',', ' ']).map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect(),
        _ => vec![],
    }
}

/// The roles a login gets, or why it is refused.
pub fn login_roles(rbac: Option<&RbacConfig>, paths: &ark_kernel::config::Paths, f: &LoginFacts) -> Result<Vec<Role>, String> {
    let registered = ark_kernel::agents::find_login(paths, f.subject, f.email).or_else(|| ark_kernel::agents::users(paths).into_iter().find(|u| matches!(f.provider, "basic" | "header") && (u.name == f.subject || u.id == f.subject)));
    // SCIM-provisioned group memberships count like the IdP's groups claim (ent-049).
    let mut groups = f.groups.clone();
    if let Some(u) = &registered {
        groups.extend(crate::scim::groups_of(&paths.data, &u.id));
    }
    if let Some(u) = registered {
        if u.disabled {
            return Err(format!("user `{}` is disabled", u.name));
        }
        if !u.role.trim().is_empty() {
            return Ok(vec![Role::parse(&u.role)?]);
        }
    }
    let Some(rb) = rbac else {
        // Historical behaviour for the operator's own password list; never for an IdP.
        return if f.provider == "basic" || f.provider_admin { Ok(vec![Role::Admin]) } else { Ok(vec![Role::User]) };
    };
    for key in [f.email, f.subject] {
        if let Some(r) = rb.users.iter().find(|(k, _)| !key.is_empty() && k.eq_ignore_ascii_case(key)).map(|(_, r)| r) {
            return Ok(vec![Role::parse(r)?]);
        }
    }
    let mut roles: Vec<Role> = groups.iter().filter_map(|g| rb.groups.get(g)).filter_map(|r| Role::parse(r).ok()).collect();
    roles.sort();
    roles.dedup();
    if !roles.is_empty() {
        return Ok(roles);
    }
    if f.provider_admin {
        return Ok(vec![Role::Admin]);
    }
    if rb.default_role.trim() == "none" {
        return Err("no role mapping for this login ([app.rbac] default_role = \"none\")".into());
    }
    Ok(vec![Role::parse(&rb.default_role)?])
}

/// Channel senders (ent-047 / ent-060): a registered, role-bearing profile limits what a
/// chat identity may do. `Err` = refuse. Unregistered senders keep the channel's own rules.
pub fn channel_permits(paths: &ark_kernel::config::Paths, channel: &str, sender: &str, approve: bool) -> Result<(), String> {
    let Some(u) = ark_kernel::agents::find_user(paths, channel, sender) else { return Ok(()) };
    if u.disabled {
        return Err(format!("user `{}` is disabled", u.name));
    }
    match u.role.trim() {
        "" | "admin" | "user" => Ok(()),
        r if approve => Err(format!("role `{r}` may not answer approvals")),
        r => Err(format!("role `{r}` may not start or drive conversations")),
    }
}

// ───────────────────────── service accounts (ent-058) ─────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ServiceAccount {
    pub name: String,
    /// Roles (preferred) or a legacy scope (`scope:read`).
    pub role: String,
    pub description: String,
    /// SHA-256 of the current token (the token itself is shown once, at issue/rotate).
    pub token_sha256: String,
    /// Previous token, still accepted until `previous_expires_ms` (rotation grace).
    pub previous_sha256: String,
    pub previous_expires_ms: u64,
    pub created_ms: u64,
    pub rotated_ms: u64,
    /// 0 = never.
    pub expires_ms: u64,
    pub revoked: bool,
    pub last_used_ms: u64,
    /// Organization / team this account is limited to (ent-050); both empty = installation-wide.
    pub org: String,
    pub team: String,
}

impl ServiceAccount {
    pub fn access(&self) -> Result<Access, String> {
        if let Some(s) = self.role.strip_prefix("scope:") {
            return Ok(Access::Scope(Scope::parse(s)?));
        }
        let roles = self.role.split('+').map(Role::parse).collect::<Result<Vec<_>, _>>()?;
        Ok(Access::Roles(roles))
    }
    pub fn active(&self, now: u64) -> bool {
        !self.revoked && (self.expires_ms == 0 || now < self.expires_ms)
    }
}

pub fn accounts_path(data: &Path) -> PathBuf {
    data.join("app").join("service_accounts.json")
}

pub fn accounts(data: &Path) -> Vec<ServiceAccount> {
    std::fs::read_to_string(accounts_path(data)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save_accounts(data: &Path, v: &[ServiceAccount]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let p = accounts_path(data);
    std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(v).unwrap_or_default()).map_err(|e| e.to_string())?;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    std::fs::rename(&tmp, &p).map_err(|e| e.to_string())
}

fn now_ms() -> u64 {
    ark_security::audit::now_ms()
}

fn digest(token: &str) -> String {
    crypto::hex(&crypto::sha256(token.as_bytes()))
}

fn new_token() -> String {
    format!("arksa_{}", crypto::random_token(40))
}

fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 64 && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Issue a new named account. Returns `(account, token)`; the token is never stored.
pub fn issue(data: &Path, name: &str, role: &str, ttl_days: u64, description: &str, by: &Actor) -> Result<(ServiceAccount, String), String> {
    if !valid_name(name) {
        return Err(format!("service account name `{name}`: use letters, digits, - _ . (max 64)"));
    }
    let mut all = accounts(data);
    if all.iter().any(|a| a.name == name && !a.revoked) {
        return Err(format!("service account `{name}` exists (rotate or revoke it)"));
    }
    all.retain(|a| a.name != name);
    let token = new_token();
    let now = now_ms();
    let a = ServiceAccount { name: name.into(), role: role.trim().to_ascii_lowercase(), description: description.into(), token_sha256: digest(&token), created_ms: now, rotated_ms: now, expires_ms: if ttl_days == 0 { 0 } else { now + ttl_days * 86_400_000 }, ..Default::default() };
    a.access()?;
    all.push(a.clone());
    save_accounts(data, &all)?;
    ark_security::audit::record(data, ark_security::audit::Event::new("token.issue", by.clone(), name, "ok").detail(json!({"role": a.role, "expires_ms": a.expires_ms})));
    Ok((a, token))
}

/// New token for `name`; the old one keeps working for `grace_hours` (0 = cut over now).
pub fn rotate(data: &Path, name: &str, grace_hours: u64, ttl_days: Option<u64>, by: &Actor) -> Result<(ServiceAccount, String), String> {
    let mut all = accounts(data);
    let a = all.iter_mut().find(|a| a.name == name && !a.revoked).ok_or_else(|| format!("no active service account `{name}`"))?;
    let token = new_token();
    let now = now_ms();
    a.previous_sha256 = if grace_hours > 0 { a.token_sha256.clone() } else { String::new() };
    a.previous_expires_ms = if grace_hours > 0 { now + grace_hours * 3_600_000 } else { 0 };
    a.token_sha256 = digest(&token);
    a.rotated_ms = now;
    if let Some(d) = ttl_days {
        a.expires_ms = if d == 0 { 0 } else { now + d * 86_400_000 };
    }
    let out = a.clone();
    save_accounts(data, &all)?;
    ark_security::audit::record(data, ark_security::audit::Event::new("token.rotate", by.clone(), name, "ok").detail(json!({"grace_hours": grace_hours, "expires_ms": out.expires_ms})));
    Ok((out, token))
}

/// Limit an account to an organization / team (ent-050). Empty values = installation-wide.
pub fn set_tenant(data: &Path, name: &str, org: &str, team: &str, by: &Actor) -> Result<ServiceAccount, String> {
    let mut all = accounts(data);
    let a = all.iter_mut().find(|a| a.name == name && !a.revoked).ok_or_else(|| format!("no active service account `{name}`"))?;
    a.org = org.trim().into();
    a.team = team.trim().into();
    let out = a.clone();
    save_accounts(data, &all)?;
    ark_security::audit::record(data, ark_security::audit::Event::new("token.tenant", by.clone(), name, "ok").detail(json!({"org": out.org, "team": out.team})));
    Ok(out)
}

pub fn revoke(data: &Path, name: &str, by: &Actor) -> Result<(), String> {
    let mut all = accounts(data);
    let a = all.iter_mut().find(|a| a.name == name && !a.revoked).ok_or_else(|| format!("no active service account `{name}`"))?;
    a.revoked = true;
    a.previous_sha256.clear();
    save_accounts(data, &all)?;
    ark_security::audit::record(data, ark_security::audit::Event::new("token.revoke", by.clone(), name, "ok"));
    Ok(())
}

/// Constant-time lookup of a presented token among the active accounts.
pub fn lookup(data: &Path, token: &str) -> Option<ServiceAccount> {
    if !token.starts_with("arksa_") {
        return None;
    }
    let d = digest(token);
    let now = now_ms();
    let mut hit = None;
    for a in accounts(data) {
        let cur = crypto::ct_eq(d.as_bytes(), a.token_sha256.as_bytes());
        let prev = !a.previous_sha256.is_empty() && now < a.previous_expires_ms && crypto::ct_eq(d.as_bytes(), a.previous_sha256.as_bytes());
        if (cur || prev) && a.active(now) {
            hit = Some(a);
        }
    }
    hit
}

/// Accounts expiring within `days` (for `ark doctor` / alerts).
pub fn expiring(data: &Path, days: u64) -> Vec<ServiceAccount> {
    let now = now_ms();
    accounts(data).into_iter().filter(|a| !a.revoked && a.expires_ms > 0 && a.expires_ms < now + days * 86_400_000).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The auditor role is read-only: no method that needs more than `read` (writes,
    /// approvals, review marks, config, unknown names) and no conversation content, except
    /// the read-only audit methods.
    #[test]
    fn auditor_never_writes_or_approves() {
        let au = Access::Roles(vec![Role::Auditor]);
        for (m, scope) in crate::exposure::method_scope_table() {
            if scope > Scope::Read {
                assert!(au.permits(m).is_err(), "auditor may not call {m}");
            }
        }
        for m in ["gate.answer", "session.review.set", "audit.prune", "audit.hold", "audit.rotate", "config.set", "secrets.set", "some.new.method"] {
            assert!(au.permits(m).is_err(), "auditor may not call {m}");
        }
        for m in ["audit.query", "audit.verify", "audit.report", "session.review.list", "session.review.get", "gate.pending", "usage.query"] {
            assert!(au.permits(m).is_ok(), "auditor reads {m}");
        }
        assert!(au.permits_http("POST", "/plugins/x").is_err());
    }

    #[test]
    fn roles_map_methods_and_hide_content_from_operator_and_auditor() {
        let op = Access::Roles(vec![Role::Operator]);
        let au = Access::Roles(vec![Role::Auditor]);
        let us = Access::Roles(vec![Role::User]);
        let ad = Access::admin();
        for m in ["session.list", "gate.pending", "models.list", "surfaces.list"] {
            assert!(op.permits(m).is_ok() && au.permits(m).is_ok() && us.permits(m).is_ok(), "{m}");
        }
        for m in ["session.history", "session.view", "session.attach", "events.subscribe", "subscribe", "view.browser.frame", "memory.search", "logbook.list"] {
            assert!(op.permits(m).is_err() && au.permits(m).is_err(), "{m} is content");
            assert!(us.permits(m).is_ok() && ad.permits(m).is_ok(), "{m}");
        }
        assert!(op.permits("shutdown").is_ok() && op.permits("channels.restart").is_ok() && op.permits("daemon.status").is_ok());
        assert!(op.permits("config.set").is_err() && op.permits("session.submit").is_err() && op.permits("gate.answer").is_err());
        assert!(au.permits("audit.query").is_ok() && au.permits("audit.verify").is_ok());
        assert!(au.permits("shutdown").is_err() && au.permits("session.submit").is_err());
        assert!(us.permits("session.submit").is_ok() && us.permits("gate.answer").is_ok());
        assert!(us.permits("config.set").is_err() && us.permits("audit.query").is_err());
        assert!(ad.permits("audit.query").is_ok() && ad.permits("config.set").is_ok());
        // Union of roles.
        let both = Access::Roles(vec![Role::User, Role::Operator]);
        assert!(both.permits("shutdown").is_ok() && both.permits("session.history").is_ok());
        // Legacy scopes are unchanged, but audit needs admin.
        assert!(Access::Scope(Scope::Read).permits("session.history").is_ok());
        assert!(Access::Scope(Scope::Read).permits("audit.query").is_err());
        // HTTP routes.
        assert!(op.permits_http("GET", "/view/browser/frame").is_err());
        assert!(us.permits_http("POST", "/v1/chat/completions").is_ok());
        assert!(au.permits_http("POST", "/v1/chat/completions").is_err());
    }

    #[test]
    fn login_role_mapping_order() {
        let tmp = ark_core::tmp::TempDir::new("ark-rbac");
        let paths = ark_kernel::config::Paths { data: tmp.path().join("d"), config_dir: tmp.path().join("c"), runtime: tmp.path().join("r"), ..Default::default() };
        std::fs::create_dir_all(&paths.data).unwrap();
        let facts = |provider: &'static str, sub: &'static str, email: &'static str, groups: &[&str]| LoginFacts { provider, subject: sub, email, groups: groups.iter().map(|s| s.to_string()).collect(), provider_admin: false };
        // No [app.rbac]: basic stays admin, OIDC becomes user (never admin by default).
        assert_eq!(login_roles(None, &paths, &facts("basic", "alice", "", &[])).unwrap(), vec![Role::Admin]);
        assert_eq!(login_roles(None, &paths, &facts("sso", "s1", "a@x.org", &[])).unwrap(), vec![Role::User]);
        let mut rb = RbacConfig::default();
        rb.groups.insert("ark-ops".into(), "operator".into());
        rb.groups.insert("ark-audit".into(), "auditor".into());
        rb.users.insert("boss@x.org".into(), "admin".into());
        assert_eq!(login_roles(Some(&rb), &paths, &facts("sso", "s2", "boss@x.org", &["ark-ops"])).unwrap(), vec![Role::Admin]);
        assert_eq!(login_roles(Some(&rb), &paths, &facts("sso", "s3", "o@x.org", &["ark-ops", "ark-audit", "other"])).unwrap(), vec![Role::Operator, Role::Auditor]);
        assert_eq!(login_roles(Some(&rb), &paths, &facts("sso", "s4", "n@x.org", &[])).unwrap(), vec![Role::User]);
        rb.default_role = "none".into();
        assert!(login_roles(Some(&rb), &paths, &facts("sso", "s4", "n@x.org", &[])).is_err());
        // Registry wins, and a disabled profile is refused.
        let u = ark_kernel::agents::user_add(&paths, "Nina").unwrap();
        ark_kernel::agents::user_link_email(&paths, &u.id, "n@x.org").unwrap();
        ark_kernel::agents::user_update(&paths, &u.id, |u| {
            u.role = "auditor".into();
            Ok(())
        })
        .unwrap();
        assert_eq!(login_roles(Some(&rb), &paths, &facts("sso", "s4", "n@x.org", &[])).unwrap(), vec![Role::Auditor]);
        ark_kernel::agents::user_update(&paths, &u.id, |u| {
            u.disabled = true;
            Ok(())
        })
        .unwrap();
        assert!(login_roles(Some(&rb), &paths, &facts("sso", "s4", "n@x.org", &[])).unwrap_err().contains("disabled"));
        assert_eq!(groups_from_claims(&json!({"groups": ["a", " b "]}), "groups"), vec!["a", "b"]);
        assert_eq!(groups_from_claims(&json!({"roles": "x,y"}), "roles"), vec!["x", "y"]);
        // Channel identities follow the same profile.
        ark_kernel::agents::user_link(&paths, &u.id, "slack", "U9").unwrap();
        assert!(channel_permits(&paths, "slack", "U9", false).is_err());
        assert!(channel_permits(&paths, "slack", "U-unknown", true).is_ok());
    }

    #[test]
    fn service_accounts_issue_rotate_expire_revoke() {
        let tmp = ark_core::tmp::TempDir::new("ark-sa");
        let d = tmp.path();
        let by = Actor::local();
        assert!(issue(d, "bad name", "user", 0, "", &by).is_err());
        assert!(issue(d, "ci", "root", 0, "", &by).is_err());
        let (a, t1) = issue(d, "ci", "operator", 30, "CI bot", &by).unwrap();
        assert!(a.expires_ms > now_ms() && !accounts_path(d).to_string_lossy().is_empty());
        assert!(!std::fs::read_to_string(accounts_path(d)).unwrap().contains(&t1), "the token is never stored");
        assert_eq!(lookup(d, &t1).unwrap().name, "ci");
        assert!(issue(d, "ci", "user", 0, "", &by).is_err(), "names are unique");
        let (_, t2) = rotate(d, "ci", 1, None, &by).unwrap();
        assert!(lookup(d, &t1).is_some() && lookup(d, &t2).is_some(), "grace period keeps the old token");
        let (_, t3) = rotate(d, "ci", 0, None, &by).unwrap();
        assert!(lookup(d, &t2).is_none() && lookup(d, &t3).is_some());
        assert_eq!(lookup(d, &t3).unwrap().access().unwrap(), Access::Roles(vec![Role::Operator]));
        revoke(d, "ci", &by).unwrap();
        assert!(lookup(d, &t3).is_none());
        let (_, legacy) = issue(d, "reader", "scope:read", 0, "", &by).unwrap();
        assert_eq!(lookup(d, &legacy).unwrap().access().unwrap(), Access::Scope(Scope::Read));
        // Expiry.
        let mut all = accounts(d);
        all.iter_mut().for_each(|a| a.expires_ms = 1);
        save_accounts(d, &all).unwrap();
        assert!(lookup(d, &legacy).is_none());
        let kinds: Vec<String> = ark_security::audit::all(d).iter().map(|r| r["kind"].as_str().unwrap().to_string()).collect();
        assert!(kinds.contains(&"token.issue".into()) && kinds.contains(&"token.rotate".into()) && kinds.contains(&"token.revoke".into()));
    }
}
