//! Tenant isolation at the app server (ent-050): every remote principal carries a
//! [`Viewer`], and while multi-tenancy is active (see [`seagent_kernel::tenancy`]) a principal bound
//! to an organization only reaches its own data.
//!
//! * **Which principals are bound.** Dashboard logins (OIDC, SAML, basic, plugin) are bound to
//!   the registered user's organization / team (`seagent users org|team`), or to the team the IdP
//!   groups map to (`[app.rbac] teams = { "<group>" = "<team>" }`), else to the default
//!   organization. Service accounts and `[app] tokens` entries are bound when they name an `org`
//!   or `team`. The `[app] token`, untenanted service accounts and the local unix socket are
//!   global (the installation owner). A user with `org = "*"` and the admin role is global.
//! * **What a bound principal may call.** A fixed allowlist ([`TENANT_METHODS`]): sessions,
//!   approvals, event streams, `whoami`, usage, the audit stream and the knowledge base — each
//!   filtered. Everything else (configuration, channels, plugins, daemon control, schedules,
//!   the live browser view …) is installation-wide and refused (`-32003`).
//! * **How filtering works.** A session outside the viewer's reach answers exactly like a
//!   session that does not exist (`-32004 no such session`), lists and streams drop foreign rows,
//!   `session.create` stamps the new session with the caller's tenant (and an optional
//!   `project`, checked against membership), audit queries are pinned to the caller's
//!   organization (and team for non-admins), and usage is reduced to the caller's teams.
//!   Downstream handlers receive the viewer as `params._viewer` (set here, never by the client).

use crate::identity::{Principal, Role};
use crate::server::App;
use seagent_kernel::tenancy::{self, Registry, Tenant, Viewer};
use serde_json::{json, Value};

/// What an organization-bound principal may call (everything else is installation-wide).
pub const TENANT_METHODS: &[&str] = &[
    "ping", "initialize", "whoami", "models.list", "tools.list", "session.list", "session.create", "session.submit", "session.interrupt", "session.history", "session.view", "session.command", "gate.pending", "gate.answer", "approval.answer", "question.answer",
    "events.subscribe", "subscribe", "unsubscribe", "session.attach", "audit.query", "usage.query", "tenancy.show", "kb.search", "kb.status", "session.review.set", "session.review.get",
];

/// Methods whose `params.id` names a session.
const SESSION_METHODS: &[&str] = &["session.review.set", "session.review.get", "session.submit", "session.interrupt", "session.history", "session.view", "session.command", "session.attach", "subscribe"];

pub fn not_found() -> (i32, String) {
    (-32004, "no such session".into())
}

/// Is tenant enforcement on for this principal?
pub fn bound(app: &App, p: &Principal) -> bool {
    !p.tenant.global && tenancy::active(&app.d.k.paths.data)
}

/// The team an IdP login maps to through `[app.rbac] teams` (first match in group order).
pub fn login_team(app: &App, groups: &[String]) -> String {
    let Some(rb) = &app.cfg.rbac else { return String::new() };
    groups.iter().find_map(|g| rb.teams.get(g).cloned()).unwrap_or_default()
}

/// The viewer of a dashboard login: the registry profile wins, else the team signed into the
/// session at login (from the IdP groups), else the default organization.
pub fn login_viewer(app: &App, subject: &str, email: &str, roles: &[Role], signed_team: &str) -> Viewer {
    let reg = tenancy::registry(&app.d.k.paths.data);
    let admin = roles.contains(&Role::Admin);
    if let Some(u) = seagent_kernel::agents::find_login(&app.d.k.paths, subject, email) {
        if !u.team.is_empty() || !u.org.is_empty() {
            return tenancy::user_viewer(&reg, &u, admin);
        }
        return Viewer::member(&tenancy::team_org(&reg, signed_team), signed_team, &u.id, admin);
    }
    let org = if signed_team.is_empty() { tenancy::DEFAULT_ORG.to_string() } else { tenancy::team_org(&reg, signed_team) };
    Viewer::member(&org, signed_team, if email.is_empty() { subject } else { email }, admin)
}

/// A service account or configured token: bound only when it names an org or team.
pub fn credential_viewer(app: &App, org: &str, team: &str, admin: bool, name: &str) -> Viewer {
    if org.is_empty() && team.is_empty() {
        return Viewer::global();
    }
    let reg = tenancy::registry(&app.d.k.paths.data);
    let org = if org.is_empty() { tenancy::team_org(&reg, team) } else { org.to_string() };
    Viewer::member(&org, team, name, admin)
}

fn sees_session(app: &App, reg: &Registry, v: &Viewer, sid: &str) -> bool {
    v.sees(&tenancy::session_tenant(&app.d.k.paths.data, sid), reg)
}

/// The session a pending approval / question belongs to.
fn pending_session(app: &App, id: &str) -> Option<String> {
    let list = app.d.call("gate.pending", &json!({})).ok()?;
    list.as_array()?.iter().find(|i| i["id"].as_str() == Some(id)).and_then(|i| i["session"].as_str()).map(str::to_string)
}

/// Before a bound principal's call: refuse, or adjust `params` (viewer, tenant defaults).
pub fn guard(app: &App, p: &Principal, method: &str, params: &mut Value) -> Result<(), (i32, String)> {
    if let Some(o) = params.as_object_mut() {
        o.remove("_viewer");
    }
    if !bound(app, p) {
        return Ok(());
    }
    if !TENANT_METHODS.contains(&method) {
        return Err((-32003, format!("forbidden: `{method}` is installation-wide and not available to an organization-scoped principal ({})", p.tenant.label())));
    }
    let reg = tenancy::registry(&app.d.k.paths.data);
    let v = &p.tenant;
    if SESSION_METHODS.contains(&method) {
        if let Some(sid) = params["id"].as_str() {
            if !sees_session(app, &reg, v, sid) {
                return Err(not_found());
            }
        }
    }
    if matches!(method, "gate.answer" | "approval.answer" | "question.answer") {
        let id = params["id"].as_str().unwrap_or("");
        match pending_session(app, id) {
            Some(sid) if sees_session(app, &reg, v, &sid) => {}
            _ => return Err((-32001, "no such pending item (already answered or timed out)".into())),
        }
    }
    if method == "session.create" {
        let t = Tenant { org: if v.org == tenancy::DEFAULT_ORG { String::new() } else { v.org.clone() }, team: params["team"].as_str().filter(|_| v.org_admin).map(str::to_string).unwrap_or_else(|| v.team.clone()), project: params["project"].as_str().unwrap_or("").to_string() };
        tenancy::may_create(&reg, v, &t).map_err(|e| (-32003, e))?;
        // Tenant defaults (model, workspace) unless the caller chose.
        for key in ["model", "workspace"] {
            if params[key].as_str().is_none_or(|s| s.trim().is_empty()) {
                if let Some(val) = tenancy::setting(&reg, &t, key) {
                    params[key] = val.into();
                }
            }
        }
        params["_tenant"] = serde_json::to_value(&t).unwrap_or(Value::Null);
    }
    if let Some(o) = params.as_object_mut() {
        o.insert("_viewer".into(), serde_json::to_value(v).unwrap_or(Value::Null));
    }
    Ok(())
}

/// After a successful call: stamp new sessions, drop foreign rows from lists.
pub fn after(app: &App, p: &Principal, method: &str, params: &Value, result: &mut Value) {
    let data = &app.d.k.paths.data;
    if method == "session.create" {
        if let Some(sid) = result["id"].as_str() {
            let t: Tenant = serde_json::from_value(params["_tenant"].clone()).unwrap_or_default();
            tenancy::stamp(data, sid, &t);
        }
    }
    if !bound(app, p) {
        return;
    }
    let reg = tenancy::registry(data);
    let stamps = tenancy::session_tenants(data);
    let visible = |sid: &str| p.tenant.sees(stamps.get(sid).unwrap_or(&Tenant::default()), &reg);
    match method {
        "session.list" => {
            if let Some(a) = result.as_array_mut() {
                a.retain(|r| r["id"].as_str().is_some_and(visible));
            }
        }
        "gate.pending" => {
            if let Some(a) = result.as_array_mut() {
                a.retain(|r| r["session"].as_str().is_some_and(visible));
            }
        }
        _ => {}
    }
}

/// May this streamed message (event / delta / pending) reach the viewer?
pub fn stream_visible(app: &App, p: &Principal, msg: &Value) -> bool {
    if !bound(app, p) {
        return true;
    }
    let sid = msg["params"]["session"].as_str().unwrap_or("");
    if sid.is_empty() {
        // Results, heartbeats and errors carry no session.
        return msg.get("method").is_none() || msg["method"] == "heartbeat";
    }
    sees_session(app, &tenancy::registry(&app.d.k.paths.data), &p.tenant, sid)
}

/// `audit.query` for a bound principal: pinned to its organization (and team, unless an admin
/// or auditor).
pub fn audit_scope(app: &App, p: &Principal) -> (Option<String>, Option<String>) {
    if !bound(app, p) {
        return (None, None);
    }
    // Auditors and organization admins read the whole organization; anyone else their team.
    let org_wide = p.tenant.org_admin || p.access.has(Role::Auditor);
    (Some(p.tenant.org.clone()), if org_wide { None } else { Some(p.tenant.team.clone()) })
}

/// `usage.query {by: "user"|"team", days}` with the rows a principal may see.
pub fn usage(app: &App, p: Option<&Principal>, params: &Value) -> Result<Value, (i32, String)> {
    let by = params["by"].as_str().unwrap_or("team");
    if by != "user" && by != "team" {
        return Err((-32602, "`by` is user or team".into()));
    }
    let days = params["days"].as_u64().unwrap_or(30).min(3650);
    let since = seagent_security::audit::now_ms().saturating_sub(days * 86_400_000);
    let mut rows = seagent_kernel::governance::usage_by(&app.d.k, by, since);
    if let Some(p) = p.filter(|p| bound(app, p)) {
        let reg = tenancy::registry(&app.d.k.paths.data);
        let users = seagent_kernel::agents::users(&app.d.k.paths);
        let team_ok = |team: &str| p.tenant.sees_team(&tenancy::team_org(&reg, team), team) && (p.tenant.org_admin || team == p.tenant.team);
        rows.retain(|r| match by {
            "team" => !r.key.is_empty() && team_ok(&r.key),
            _ => users.iter().find(|u| u.name == r.key).is_some_and(|u| team_ok(&u.team)),
        });
    }
    Ok(json!(rows.iter().map(|r| json!({"key": r.key, "usd": r.usd, "tokens": r.tokens, "sessions": r.sessions})).collect::<Vec<_>>()))
}

/// Tag an audit record with the principal's tenant.
pub fn tag(ev: seagent_security::audit::Event, p: &Principal) -> seagent_security::audit::Event {
    if p.tenant.global {
        ev
    } else {
        ev.tenant(&p.tenant.org, &p.tenant.team)
    }
}

/// Shared harness for the enterprise identity tests (SAML, SCIM, tenancy): a real `App` over a
/// throw-away data directory (removed when the test thread ends) and request builders.
#[cfg(test)]
pub(crate) mod harness {
    use crate::server::App;
    use crate::AppConfig;
    use seagent_kernel::config::{Config, Paths};
    use seagent_kernel::daemon::Daemon;
    use seagent_net::httpd::{Body, Request, Response};
    use serde_json::{json, Value};
    use std::sync::Arc;
    use std::time::Duration;

    struct NoRes;
    impl seagent_kernel::kernel::Resolver for NoRes {
        fn provider(&self, id: &str) -> Result<Arc<dyn seagent_core::Provider>, String> {
            Err(format!("no provider {id}"))
        }
    }

    pub fn app(cfg: AppConfig) -> Arc<App> {
        let home = seagent_core::tmp::scratch("seagent-app-ent");
        let paths = Paths { data: home.join("data"), config_dir: home.join("cfg"), runtime: home.join("run"), ..Default::default() };
        std::fs::create_dir_all(&paths.data).unwrap();
        std::fs::create_dir_all(home.join("ws")).unwrap();
        let (pending, _cell) = seagent_kernel::daemon::pending_approver(Duration::from_secs(1));
        let k = seagent_kernel::kernel::new_kernel(Config::default(), paths, Arc::new(NoRes), vec![], Arc::new(seagent_kernel::vault::Vault::empty()), pending.clone());
        let d = Arc::new(Daemon::new(k, pending));
        Arc::new(App { d, cfg: AppConfig { workspace: Some(home.join("ws").display().to_string()), ..cfg }, token: "admin-token".into(), host_methods: vec![], routes: vec![] })
    }

    pub fn req(method: &str, target: &str, hs: &[(&str, &str)], body: &str) -> Request {
        let (path, q) = target.split_once('?').unwrap_or((target, ""));
        Request { method: method.into(), path: path.into(), query: seagent_net::parse_query(q), raw_query: q.into(), headers: hs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), body: body.as_bytes().to_vec(), peer: None, head: String::new() }
    }

    pub fn text(r: &Response) -> String {
        match &r.body {
            Body::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        }
    }

    pub fn header(r: &Response, name: &str) -> Option<String> {
        r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone())
    }

    /// `POST /arp` with a bearer token (or a cookie when `cred` starts with `cookie:`).
    pub fn arp(a: &Arc<App>, cred: &str, method: &str, params: Value) -> Value {
        let auth = format!("Bearer {cred}");
        let mut hs = vec![("content-type", "application/json")];
        match cred.strip_prefix("cookie:") {
            Some(c) => hs.push(("cookie", c)),
            None => hs.push(("authorization", &auth)),
        }
        let r = a.clone().handle(req("POST", "/arp", &hs, &json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string()));
        serde_json::from_str(&text(&r)).unwrap_or_else(|_| json!({"http": r.status, "body": text(&r)}))
    }
}

#[cfg(test)]
mod tests {
    use super::harness::*;
    use crate::exposure::TokenConfig;
    use crate::AppConfig;
    use seagent_kernel::tenancy;
    use serde_json::json;

    fn tok(token: &str, scope: &str, org: &str, team: &str) -> TokenConfig {
        TokenConfig { token: token.into(), scope: scope.into(), name: Some(token.into()), org: org.into(), team: team.into() }
    }

    /// ent-050: two organizations (and two teams in one of them) on one server; every way of
    /// reaching another tenant's data is refused, and the owner's view is unchanged.
    #[test]
    fn cross_tenant_access_is_refused_everywhere() {
        let a = app(AppConfig {
            enabled: true,
            listen: "127.0.0.1:0".into(),
            tokens: vec![tok("eng-tok", "user", "acme", "eng"), tok("ops-tok", "user", "acme", "ops"), tok("acme-admin", "admin", "acme", ""), tok("globex-tok", "user", "globex", "rnd"), tok("acme-auditor", "auditor", "acme", "")],
            ..AppConfig::default()
        });
        let data = a.d.k.paths.data.clone();
        // Single-tenant first: nothing is bound, a legacy session is visible to every token.
        let legacy = arp(&a, "admin-token", "session.create", json!({}))["result"]["id"].as_str().unwrap().to_string();
        assert!(!tenancy::active(&data));
        assert_eq!(arp(&a, "globex-tok", "session.list", json!({}))["result"].as_array().unwrap().len(), 1, "before the registry exists nothing changes");
        // Now set up the organizations.
        tenancy::org_add(&data, "acme", "").unwrap();
        tenancy::org_add(&data, "globex", "").unwrap();
        tenancy::team_add(&data, "eng", "acme", "").unwrap();
        tenancy::team_add(&data, "ops", "acme", "").unwrap();
        tenancy::team_add(&data, "rnd", "globex", "").unwrap();
        tenancy::project_add(&data, "secret-proj", "eng", "", &["someone-else".into()]).unwrap();
        tenancy::set_setting(&data, "team:eng", "model", Some("local/eng-model")).unwrap();
        let create = |cred: &str, extra: serde_json::Value| arp(&a, cred, "session.create", extra)["result"]["id"].as_str().map(str::to_string);
        let eng = create("eng-tok", json!({})).unwrap();
        let ops = create("ops-tok", json!({})).unwrap();
        let glx = create("globex-tok", json!({})).unwrap();
        assert_eq!(tenancy::session_tenant(&data, &eng), tenancy::Tenant { org: "acme".into(), team: "eng".into(), project: String::new() });
        // Team default model was applied.
        assert!(arp(&a, "admin-token", "session.view", json!({"id": eng})).get("result").is_some());
        assert_eq!(a.d.k.store.list().into_iter().find(|s| s.id == eng).unwrap().model, "local/eng-model");
        // A project the caller is not a member of cannot be used; another team cannot be claimed.
        assert_eq!(arp(&a, "eng-tok", "session.create", json!({"project": "secret-proj"}))["error"]["code"], -32003);
        // Lists only show the caller's tenant.
        let ids = |cred: &str| arp(&a, cred, "session.list", json!({}))["result"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!(ids("eng-tok"), vec![eng.clone()]);
        assert_eq!(ids("ops-tok"), vec![ops.clone()]);
        assert_eq!(ids("globex-tok"), vec![glx.clone()]);
        let mut admin_view = ids("acme-admin");
        admin_view.sort();
        let mut want = vec![eng.clone(), ops.clone()];
        want.sort();
        assert_eq!(admin_view, want, "an org admin sees the org, not other orgs nor legacy data");
        assert_eq!(ids("admin-token").len(), 4, "the installation owner sees everything");
        // Direct access by id: indistinguishable from a missing session.
        for (cred, sid) in [("eng-tok", &ops), ("eng-tok", &glx), ("globex-tok", &eng), ("ops-tok", &legacy), ("acme-admin", &glx)] {
            for m in ["session.history", "session.view", "session.submit", "session.interrupt", "session.command"] {
                let r = arp(&a, cred, m, json!({"id": sid, "text": "hi", "line": "/status"}));
                assert_eq!(r["error"]["code"], -32004, "{cred} {m} {sid}: {r}");
                assert_eq!(r["error"]["message"], "no such session");
            }
        }
        assert!(arp(&a, "eng-tok", "session.history", json!({"id": eng}))["result"].is_array());
        // Installation-wide methods are refused to bound principals, even an org admin.
        for m in ["config.set", "shutdown", "channels.restart", "schedule.list", "goal.list", "audit.verify", "view.browser.list"] {
            assert_eq!(arp(&a, "acme-admin", m, json!({}))["error"]["code"], -32003, "{m}");
        }
        // …and the same holds for the HTTP form of the live view.
        assert_eq!(a.handle(req("GET", "/view/browser", &[("authorization", "Bearer acme-admin")], "")).status, 403);
        // Approvals of another tenant cannot be answered (the item looks absent).
        assert_eq!(arp(&a, "eng-tok", "gate.answer", json!({"id": "nope", "answer": "yes"}))["error"]["code"], -32001);
        // Streams: another tenant's event never passes the filter.
        let p_eng = a.principal(&req("GET", "/arp", &[("authorization", "Bearer eng-tok")], "")).unwrap();
        let ev = |sid: &str| json!({"jsonrpc": "2.0", "method": "event", "params": {"session": sid, "event": {}}});
        assert!(super::stream_visible(&a, &p_eng, &ev(&eng)) && !super::stream_visible(&a, &p_eng, &ev(&ops)) && !super::stream_visible(&a, &p_eng, &ev(&glx)));
        assert!(super::stream_visible(&a, &p_eng, &json!({"jsonrpc": "2.0", "method": "heartbeat", "params": {}})));
        // Audit: requests are tagged with the tenant, and an org auditor only reads its org.
        let recs = arp(&a, "acme-auditor", "audit.query", json!({"kind": "app.request", "limit": 1000}))["result"].as_array().unwrap().clone();
        assert!(!recs.is_empty() && recs.iter().all(|r| r["org"] == "acme"), "{recs:?}");
        assert!(recs.iter().any(|r| r["team"] == "eng") && recs.iter().any(|r| r["team"] == "ops"), "auditor sees the whole org");
        let engs = arp(&a, "eng-tok", "audit.query", json!({"org": "globex", "limit": 1000}))["result"].as_array().cloned();
        // A plain user may not read the audit stream at all; were it allowed, the org is pinned.
        assert!(engs.is_none());
        let p_glx = a.principal(&req("GET", "/arp", &[("authorization", "Bearer globex-tok")], "")).unwrap();
        assert_eq!(super::audit_scope(&a, &p_glx), (Some("globex".into()), Some("rnd".into())));
        // whoami / tenancy.show describe the caller's reach only.
        let show = arp(&a, "eng-tok", "tenancy.show", json!({}))["result"].clone();
        assert_eq!(show["viewer"]["team"], "eng");
        assert_eq!(show["teams"].as_array().unwrap().len(), 1);
        // Usage rows are limited to visible teams.
        assert!(arp(&a, "eng-tok", "usage.query", json!({"by": "team"}))["result"].as_array().unwrap().iter().all(|r| r["key"] == "eng"));
        // A client cannot smuggle a viewer or tenant.
        let forged = arp(&a, "globex-tok", "session.create", json!({"_tenant": {"org": "acme", "team": "eng"}, "_viewer": {"global": true}}));
        let fid = forged["result"]["id"].as_str().unwrap();
        assert_eq!(tenancy::session_tenant(&data, fid).org, "globex");
    }

    /// Service accounts bound to an organization are scoped like logins; untenanted ones are global.
    #[test]
    fn service_accounts_carry_their_tenant() {
        let a = app(AppConfig { enabled: true, listen: "127.0.0.1:0".into(), ..AppConfig::default() });
        let data = a.d.k.paths.data.clone();
        tenancy::org_add(&data, "acme", "").unwrap();
        tenancy::team_add(&data, "eng", "acme", "").unwrap();
        let by = seagent_security::audit::Actor::local();
        let (_, t_bound) = crate::identity::issue(&data, "bot-eng", "user", 0, "", &by).unwrap();
        crate::identity::set_tenant(&data, "bot-eng", "", "eng", &by).unwrap();
        let (_, t_global) = crate::identity::issue(&data, "bot-ops", "admin", 0, "", &by).unwrap();
        let s_global = arp(&a, &t_global, "session.create", json!({}))["result"]["id"].as_str().unwrap().to_string();
        let s_eng = arp(&a, &t_bound, "session.create", json!({}))["result"]["id"].as_str().unwrap().to_string();
        assert_eq!(arp(&a, &t_bound, "session.view", json!({"id": s_global}))["error"]["code"], -32004);
        assert!(arp(&a, &t_global, "session.view", json!({"id": s_eng}))["result"].is_object());
        assert_eq!(arp(&a, &t_bound, "whoami", json!({}))["result"]["kind"], "service");
    }
}
