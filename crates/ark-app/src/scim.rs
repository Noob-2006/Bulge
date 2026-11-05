//! SCIM 2.0 service provider (ent-049, RFC 7643 / 7644) at `/scim/v2/…`, so an IdP (Okta,
//! Entra ID, Keycloak, authentik …) provisions and deprovisions ark users and groups.
//!
//! ```toml
//! [app]
//! scim = true      # off by default: no /scim route exists while off
//! ```
//! Authentication is a bearer token — an admin service account is the intended credential
//! (`ark accounts issue scim --role admin [--org acme]`) — and every request goes through the
//! same RBAC (`admin` only) and the unified audit stream (`scim.user.create`,
//! `scim.user.deactivate`, `scim.group.patch` …). A service account bound to an organization
//! provisions into that organization and sees only its users and groups.
//!
//! * **Users** are the `ark users` registry (`<data>/users.json`): `userName`, `externalId`,
//!   `name`/`displayName`, `emails` (linked for SSO logins) and `active` (= not disabled).
//!   `GET` (list with `filter=userName eq "…"` / `externalId eq` / `emails.value eq`,
//!   `startIndex`, `count`), `POST`, `GET /{id}`, `PUT`, `PATCH` (add / replace / remove,
//!   with or without `path`), `DELETE` (soft: the profile is disabled and hidden from SCIM so
//!   history stays attributable).
//! * **Groups** live in `<data>/scim/groups.json`: `displayName`, `externalId`, `members`.
//!   Membership feeds login role mapping (`[app.rbac] groups`) and sets the user's team when a
//!   group maps to one (`[app.rbac] teams`).
//! * **Deprovisioning is immediate**: `active: false` (or `DELETE`) disables the profile, which
//!   at once refuses its dashboard cookie and personal tokens (checked on every request), closes
//!   its open WebSockets (re-checked every second), refuses its chat-channel identities
//!   (`identity::channel_permits`), and interrupts its running sessions.

use crate::identity::Principal;
use crate::server::App;
use ark_kernel::agents::{self, User};
use ark_net::httpd::{Request, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const S_USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const S_GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const S_LIST: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const S_ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const S_PATCH: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const MAX_PAGE: usize = 200;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Group {
    pub id: String,
    pub display_name: String,
    pub external_id: String,
    /// ark user ids.
    pub members: Vec<String>,
    /// Organization of the provisioning credential (empty = default).
    pub org: String,
    pub created_ms: u64,
    pub modified_ms: u64,
}

fn groups_path(data: &Path) -> PathBuf {
    data.join("scim").join("groups.json")
}

pub fn groups(data: &Path) -> Vec<Group> {
    std::fs::read_to_string(groups_path(data)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save_groups(data: &Path, g: &[Group]) -> Result<(), String> {
    let p = groups_path(data);
    std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
    ark_kernel::util::atomic_write(&p, serde_json::to_string_pretty(g).map_err(|e| e.to_string())?.as_bytes()).map_err(|e| e.to_string())
}

/// The SCIM groups a user belongs to (display names), for login role mapping.
pub fn groups_of(data: &Path, user_id: &str) -> Vec<String> {
    groups(data).into_iter().filter(|g| g.members.iter().any(|m| m == user_id)).map(|g| g.display_name).collect()
}

fn now_ms() -> u64 {
    ark_security::audit::now_ms()
}

fn iso(ms: u64) -> String {
    crate::saml::instant((ms / 1000) as i64)
}

type Res = Result<(u16, Value), (u16, String, &'static str)>;

fn err(status: u16, detail: impl Into<String>, scim_type: &'static str) -> (u16, String, &'static str) {
    (status, detail.into(), scim_type)
}

fn reply(r: Res) -> Response {
    let (status, body) = match r {
        Ok((s, v)) => (s, v),
        Err((s, detail, t)) => {
            let mut v = json!({"schemas": [S_ERROR], "status": s.to_string(), "detail": detail});
            if !t.is_empty() {
                v["scimType"] = json!(t);
            }
            (s, v)
        }
    };
    if status == 204 {
        return Response::empty(204);
    }
    Response::json(status, &body.to_string()).with_header("content-type", "application/scim+json").with_header("cache-control", "no-store")
}

/// Organization the credential provisions into (empty = default / installation-wide).
fn org_of(p: &Principal) -> String {
    if p.tenant.global || p.tenant.org == ark_kernel::tenancy::DEFAULT_ORG {
        String::new()
    } else {
        p.tenant.org.clone()
    }
}

fn in_scope_user(p: &Principal, u: &User) -> bool {
    !u.scim_deleted && (p.tenant.global || u.org == org_of(p) || (u.org.is_empty() && org_of(p).is_empty()))
}

fn in_scope_group(p: &Principal, g: &Group) -> bool {
    p.tenant.global || g.org == org_of(p)
}

fn user_json(data: &Path, u: &User, base: &str) -> Value {
    let groups: Vec<Value> = groups(data).into_iter().filter(|g| g.members.contains(&u.id)).map(|g| json!({"value": g.id, "display": g.display_name, "$ref": format!("{base}/Groups/{}", g.id)})).collect();
    json!({
        "schemas": [S_USER],
        "id": u.id,
        "externalId": if u.external_id.is_empty() { Value::Null } else { json!(u.external_id) },
        "userName": if u.user_name.is_empty() { u.emails.first().cloned().unwrap_or_else(|| u.name.clone()) } else { u.user_name.clone() },
        "name": {"formatted": u.name},
        "displayName": u.name,
        "emails": u.emails.iter().enumerate().map(|(i, e)| json!({"value": e, "primary": i == 0, "type": "work"})).collect::<Vec<_>>(),
        "active": !u.disabled,
        "groups": groups,
        "meta": {"resourceType": "User", "created": iso(u.created_ms), "lastModified": iso(u.created_ms), "location": format!("{base}/Users/{}", u.id)},
    })
}

fn group_json(data: &Path, g: &Group, base: &str) -> Value {
    let users = agents::users(&paths_of(data));
    json!({
        "schemas": [S_GROUP],
        "id": g.id,
        "externalId": if g.external_id.is_empty() { Value::Null } else { json!(g.external_id) },
        "displayName": g.display_name,
        "members": g.members.iter().map(|m| json!({"value": m, "display": users.iter().find(|u| &u.id == m).map(|u| u.name.clone()).unwrap_or_default(), "$ref": format!("{base}/Users/{m}")})).collect::<Vec<_>>(),
        "meta": {"resourceType": "Group", "created": iso(g.created_ms), "lastModified": iso(g.modified_ms), "location": format!("{base}/Groups/{}", g.id)},
    })
}

/// The registry API wants `Paths`; SCIM only ever touches `data`.
fn paths_of(data: &Path) -> ark_kernel::config::Paths {
    ark_kernel::config::Paths { data: data.to_path_buf(), config_dir: PathBuf::new(), runtime: PathBuf::new() }
}

/// `attr eq "value"` (the only filter IdP provisioning clients send).
fn parse_filter(f: &str) -> Result<(String, String), (u16, String, &'static str)> {
    let f = f.trim();
    let mut it = f.splitn(3, ' ');
    let (Some(attr), Some(op), Some(val)) = (it.next(), it.next(), it.next()) else {
        return Err(err(400, format!("unsupported filter `{f}`"), "invalidFilter"));
    };
    if !op.eq_ignore_ascii_case("eq") || !(val.starts_with('"') && val.ends_with('"') && val.len() >= 2) {
        return Err(err(400, format!("unsupported filter `{f}` (only `attribute eq \"value\"`)"), "invalidFilter"));
    }
    Ok((attr.to_string(), serde_json::from_str::<String>(val).map_err(|_| err(400, "bad filter value", "invalidFilter"))?))
}

fn page<T>(items: Vec<T>, r: &Request) -> (Vec<T>, usize, usize) {
    let total = items.len();
    let start = r.query("startIndex").and_then(|s| s.parse::<usize>().ok()).unwrap_or(1).max(1);
    let count = r.query("count").and_then(|s| s.parse::<usize>().ok()).unwrap_or(100).min(MAX_PAGE);
    (items.into_iter().skip(start - 1).take(count).collect(), total, start)
}

fn list(resources: Vec<Value>, total: usize, start: usize) -> Value {
    json!({"schemas": [S_LIST], "totalResults": total, "startIndex": start, "itemsPerPage": resources.len(), "Resources": resources})
}

fn body(r: &Request) -> Result<Value, (u16, String, &'static str)> {
    serde_json::from_slice(&r.body).map_err(|e| err(400, format!("invalid JSON: {e}"), "invalidSyntax"))
}

fn audit(app: &App, p: &Principal, kind: &str, target: &str, detail: Value) {
    let ev = ark_security::audit::Event::new(kind, p.actor(), target, "ok").detail(detail);
    ark_security::audit::record(&app.d.k.paths.data, crate::tenant::tag(ev, p));
}

/// Serve `/scim/v2/…` for an authenticated principal (the server checked the credential).
pub fn handle(app: &App, r: &Request, p: &Principal) -> Response {
    // RBAC: provisioning is admin work (a role-based admin or an admin-scoped token).
    let method_name = if r.method == "GET" { "scim.read" } else { "scim.write" };
    if let Err(e) = p.access.permits(method_name) {
        audit_deny(app, p, &r.path);
        return reply(Err(err(403, e, "")));
    }
    let base = r.header("host").map(|h| format!("{}://{h}/scim/v2", if r.header("x-forwarded-proto") == Some("https") { "https" } else { "http" })).unwrap_or_else(|| "/scim/v2".into());
    let rest = r.path.trim_start_matches("/scim/v2").trim_end_matches('/');
    let parts: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    let res = match (r.method.as_str(), parts.as_slice()) {
        ("GET", ["ServiceProviderConfig"]) => Ok((200, json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": true}, "bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": true, "maxResults": MAX_PAGE}, "changePassword": {"supported": false},
            "sort": {"supported": false}, "etag": {"supported": false},
            "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token", "description": "An ark admin service account token", "primary": true}],
        }))),
        ("GET", ["ResourceTypes"]) => Ok((200, list(vec![
            json!({"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "User", "name": "User", "endpoint": "/Users", "schema": S_USER}),
            json!({"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": S_GROUP}),
        ], 2, 1))),
        ("GET", ["Schemas"]) => Ok((200, list(vec![json!({"id": S_USER, "name": "User"}), json!({"id": S_GROUP, "name": "Group"})], 2, 1))),
        ("GET", ["Users"]) => list_users(app, r, p, &base),
        ("POST", ["Users"]) => create_user(app, r, p, &base),
        ("GET", ["Users", id]) => find_user(app, p, id).map(|u| (200, user_json(&app.d.k.paths.data, &u, &base))),
        ("PUT", ["Users", id]) => put_user(app, r, p, id, &base),
        ("PATCH", ["Users", id]) => patch_user(app, r, p, id, &base),
        ("DELETE", ["Users", id]) => delete_user(app, p, id),
        ("GET", ["Groups"]) => list_groups(app, r, p, &base),
        ("POST", ["Groups"]) => create_group(app, r, p, &base),
        ("GET", ["Groups", id]) => find_group(app, p, id).map(|g| (200, group_json(&app.d.k.paths.data, &g, &base))),
        ("PUT", ["Groups", id]) => put_group(app, r, p, id, &base),
        ("PATCH", ["Groups", id]) => patch_group(app, r, p, id, &base),
        ("DELETE", ["Groups", id]) => delete_group(app, p, id),
        _ => Err(err(404, "no such SCIM endpoint", "")),
    };
    reply(res)
}

fn audit_deny(app: &App, p: &Principal, path: &str) {
    let ev = ark_security::audit::Event::new("scim.denied", p.actor(), path, "deny");
    ark_security::audit::record(&app.d.k.paths.data, crate::tenant::tag(ev, p));
}

// ───────────────────────── users ─────────────────────────

fn find_user(app: &App, p: &Principal, id: &str) -> Result<User, (u16, String, &'static str)> {
    agents::get_user(&app.d.k.paths, id).filter(|u| in_scope_user(p, u)).ok_or_else(|| err(404, format!("no user `{id}`"), ""))
}

fn list_users(app: &App, r: &Request, p: &Principal, base: &str) -> Res {
    let mut us: Vec<User> = agents::users(&app.d.k.paths).into_iter().filter(|u| in_scope_user(p, u)).collect();
    if let Some(f) = r.query("filter") {
        let (attr, val) = parse_filter(f)?;
        us.retain(|u| match attr.as_str() {
            a if a.eq_ignore_ascii_case("userName") => u.user_name.eq_ignore_ascii_case(&val) || (u.user_name.is_empty() && u.emails.iter().any(|e| e.eq_ignore_ascii_case(&val))),
            a if a.eq_ignore_ascii_case("externalId") => u.external_id == val,
            a if a.eq_ignore_ascii_case("emails.value") || a.eq_ignore_ascii_case("emails") => u.emails.iter().any(|e| e.eq_ignore_ascii_case(&val)),
            a if a.eq_ignore_ascii_case("id") => u.id == val,
            _ => false,
        });
    }
    let (items, total, start) = page(us, r);
    Ok((200, list(items.iter().map(|u| user_json(&app.d.k.paths.data, u, base)).collect(), total, start)))
}

/// Fields a SCIM user document sets.
#[derive(Default)]
struct UserDoc {
    user_name: Option<String>,
    external_id: Option<String>,
    name: Option<String>,
    emails: Option<Vec<String>>,
    active: Option<bool>,
}

fn user_doc(v: &Value) -> UserDoc {
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|x| x.trim().to_string());
    let name = s("displayName").filter(|x| !x.is_empty()).or_else(|| v["name"]["formatted"].as_str().map(str::to_string)).or_else(|| {
        let g = v["name"]["givenName"].as_str().unwrap_or("");
        let f = v["name"]["familyName"].as_str().unwrap_or("");
        Some(format!("{g} {f}").trim().to_string()).filter(|x| !x.is_empty())
    });
    let emails = v.get("emails").and_then(|e| e.as_array()).map(|a| {
        let mut out: Vec<(bool, String)> = a.iter().filter_map(|e| e["value"].as_str().map(|x| (e["primary"].as_bool().unwrap_or(false), x.trim().to_lowercase()))).collect();
        out.sort_by_key(|(primary, _)| !primary);
        out.into_iter().map(|(_, e)| e).collect()
    });
    UserDoc { user_name: s("userName"), external_id: s("externalId"), name, emails, active: v.get("active").and_then(active_of) }
}

/// `true`, `"True"`, `"false"` (Entra sends strings).
fn active_of(v: &Value) -> Option<bool> {
    v.as_bool().or_else(|| v.as_str().and_then(|s| s.trim().to_ascii_lowercase().parse().ok()))
}

fn user_name_taken(app: &App, name: &str, except: &str) -> bool {
    agents::users(&app.d.k.paths).iter().any(|u| u.id != except && !u.scim_deleted && u.user_name.eq_ignore_ascii_case(name))
}

/// Apply a document to a profile; returns whether the user went inactive.
fn apply_user(app: &App, id: &str, d: &UserDoc) -> Result<(User, bool), (u16, String, &'static str)> {
    if let Some(n) = &d.user_name {
        if user_name_taken(app, n, id) {
            return Err(err(409, format!("userName `{n}` exists"), "uniqueness"));
        }
    }
    let paths = &app.d.k.paths;
    if let Some(emails) = &d.emails {
        for e in emails {
            if let Some(o) = agents::users(paths).into_iter().find(|u| u.id != id && u.emails.contains(e)) {
                return Err(err(409, format!("{e} already belongs to {}", o.id), "uniqueness"));
            }
        }
    }
    let mut deactivated = false;
    let u = agents::user_update(paths, id, |u| {
        if let Some(n) = &d.user_name {
            u.user_name = n.clone();
        }
        if let Some(x) = &d.external_id {
            u.external_id = x.clone();
        }
        if let Some(n) = d.name.as_ref().filter(|n| !n.is_empty()) {
            u.name = n.clone();
        }
        if let Some(e) = &d.emails {
            u.emails = e.iter().filter(|e| e.contains('@')).cloned().collect();
        }
        // userName is the SSO login name: make it resolvable when it is an email.
        if u.user_name.contains('@') && !u.emails.iter().any(|e| e.eq_ignore_ascii_case(&u.user_name)) {
            u.emails.push(u.user_name.to_lowercase());
        }
        if let Some(a) = d.active {
            deactivated = !a && !u.disabled;
            u.disabled = !a;
        }
        Ok(())
    })
    .map_err(|e| err(400, e, "invalidValue"))?;
    Ok((u, deactivated))
}

/// Disabling a profile also stops what it has running (tokens and sockets stop on their own).
fn revoke(app: &App, p: &Principal, u: &User) {
    let k = &app.d.k;
    let stopped: Vec<String> = ark_kernel::governance::sessions_of_user(&k.paths, &k.store, &k.running_ids(), u).into_iter().filter(|s| k.interrupt(s)).collect();
    audit(app, p, "scim.user.deactivate", &u.id, json!({"user": u.name, "interrupted": stopped}));
}

fn create_user(app: &App, r: &Request, p: &Principal, base: &str) -> Res {
    let v = body(r)?;
    let d = user_doc(&v);
    let Some(user_name) = d.user_name.clone().filter(|n| !n.is_empty()) else {
        return Err(err(400, "userName is required", "invalidValue"));
    };
    if user_name_taken(app, &user_name, "") {
        return Err(err(409, format!("userName `{user_name}` exists"), "uniqueness"));
    }
    let display = d.name.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| user_name.clone());
    let paths = &app.d.k.paths;
    let created = agents::user_add(paths, &display).map_err(|e| err(400, e, "invalidValue"))?;
    let org = org_of(p);
    let _ = agents::user_update(paths, &created.id, |u| {
        u.org = org.clone();
        Ok(())
    });
    let (u, _) = match apply_user(app, &created.id, &d) {
        Ok(x) => x,
        Err(e) => {
            let _ = agents::user_remove(paths, &created.id);
            return Err(e);
        }
    };
    audit(app, p, "scim.user.create", &u.id, json!({"user": u.name, "userName": u.user_name, "active": !u.disabled}));
    Ok((201, user_json(&app.d.k.paths.data, &u, base)))
}

fn put_user(app: &App, r: &Request, p: &Principal, id: &str, base: &str) -> Res {
    let before = find_user(app, p, id)?;
    let v = body(r)?;
    let mut d = user_doc(&v);
    // PUT replaces: an omitted `active` means active, omitted emails mean none.
    d.active = Some(d.active.unwrap_or(true));
    d.emails = Some(d.emails.unwrap_or_default());
    let (u, deactivated) = apply_user(app, &before.id, &d)?;
    audit(app, p, "scim.user.replace", &u.id, json!({"user": u.name, "active": !u.disabled}));
    if deactivated {
        revoke(app, p, &u);
    }
    Ok((200, user_json(&app.d.k.paths.data, &u, base)))
}

fn patch_user(app: &App, r: &Request, p: &Principal, id: &str, base: &str) -> Res {
    let before = find_user(app, p, id)?;
    let v = body(r)?;
    if !v["schemas"].as_array().is_some_and(|a| a.iter().any(|s| s == S_PATCH)) {
        return Err(err(400, "not a PatchOp", "invalidSyntax"));
    }
    let mut d = UserDoc::default();
    for op in v["Operations"].as_array().ok_or_else(|| err(400, "no Operations", "invalidSyntax"))? {
        let kind = op["op"].as_str().unwrap_or("").to_ascii_lowercase();
        let path = op["path"].as_str().unwrap_or("");
        let value = &op["value"];
        match (kind.as_str(), path) {
            ("add" | "replace", "") => {
                let x = user_doc(value);
                d.user_name = x.user_name.or(d.user_name);
                d.external_id = x.external_id.or(d.external_id);
                d.name = x.name.or(d.name);
                d.emails = x.emails.or(d.emails);
                d.active = x.active.or(d.active);
            }
            ("add" | "replace", "active") => d.active = active_of(value),
            ("add" | "replace", "userName") => d.user_name = value.as_str().map(str::to_string),
            ("add" | "replace", "externalId") => d.external_id = value.as_str().map(str::to_string),
            ("add" | "replace", "displayName" | "name.formatted") => d.name = value.as_str().map(str::to_string),
            ("add" | "replace", "emails") => d.emails = user_doc(&json!({"emails": value})).emails,
            ("add" | "replace", p) if p.starts_with("emails[") => d.emails = value.as_str().map(|e| vec![e.to_lowercase()]).or_else(|| user_doc(&json!({"emails": value})).emails),
            ("add" | "replace", p) if p.starts_with("name.") => {}
            ("remove", "externalId") => d.external_id = Some(String::new()),
            ("remove", "emails") => d.emails = Some(vec![]),
            (o, p) => return Err(err(400, format!("unsupported patch `{o}` on `{p}`"), "invalidPath")),
        }
    }
    let (u, deactivated) = apply_user(app, &before.id, &d)?;
    audit(app, p, "scim.user.patch", &u.id, json!({"user": u.name, "active": !u.disabled}));
    if deactivated {
        revoke(app, p, &u);
    }
    Ok((200, user_json(&app.d.k.paths.data, &u, base)))
}

fn delete_user(app: &App, p: &Principal, id: &str) -> Res {
    let before = find_user(app, p, id)?;
    let u = agents::user_update(&app.d.k.paths, &before.id, |u| {
        u.disabled = true;
        u.scim_deleted = true;
        Ok(())
    })
    .map_err(|e| err(400, e, ""))?;
    let data = &app.d.k.paths.data;
    let mut gs = groups(data);
    for g in gs.iter_mut() {
        g.members.retain(|m| m != &u.id);
    }
    let _ = save_groups(data, &gs);
    audit(app, p, "scim.user.delete", &u.id, json!({"user": u.name}));
    revoke(app, p, &u);
    Ok((204, Value::Null))
}

// ───────────────────────── groups ─────────────────────────

fn find_group(app: &App, p: &Principal, id: &str) -> Result<Group, (u16, String, &'static str)> {
    groups(&app.d.k.paths.data).into_iter().find(|g| g.id == id && in_scope_group(p, g)).ok_or_else(|| err(404, format!("no group `{id}`"), ""))
}

fn list_groups(app: &App, r: &Request, p: &Principal, base: &str) -> Res {
    let mut gs: Vec<Group> = groups(&app.d.k.paths.data).into_iter().filter(|g| in_scope_group(p, g)).collect();
    if let Some(f) = r.query("filter") {
        let (attr, val) = parse_filter(f)?;
        gs.retain(|g| match attr.as_str() {
            a if a.eq_ignore_ascii_case("displayName") => g.display_name.eq_ignore_ascii_case(&val),
            a if a.eq_ignore_ascii_case("externalId") => g.external_id == val,
            a if a.eq_ignore_ascii_case("id") => g.id == val,
            _ => false,
        });
    }
    let (items, total, start) = page(gs, r);
    Ok((200, list(items.iter().map(|g| group_json(&app.d.k.paths.data, g, base)).collect(), total, start)))
}

fn member_ids(app: &App, p: &Principal, v: &Value) -> Result<Vec<String>, (u16, String, &'static str)> {
    let mut out = Vec::new();
    for m in v.as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
        let id = m["value"].as_str().unwrap_or("");
        find_user(app, p, id).map_err(|_| err(400, format!("member `{id}` is not a user"), "invalidValue"))?;
        if !out.iter().any(|x| x == id) {
            out.push(id.to_string());
        }
    }
    Ok(out)
}

/// Save groups and push the group → team mapping into the members' profiles.
fn commit_groups(app: &App, gs: &[Group], touched: &[String]) -> Result<(), (u16, String, &'static str)> {
    let data = &app.d.k.paths.data;
    save_groups(data, gs).map_err(|e| err(500, e, ""))?;
    let Some(rb) = &app.cfg.rbac else { return Ok(()) };
    if rb.teams.is_empty() {
        return Ok(());
    }
    for uid in touched {
        let mut names: Vec<&str> = gs.iter().filter(|g| g.members.contains(uid)).map(|g| g.display_name.as_str()).collect();
        names.sort();
        if let Some(team) = names.iter().find_map(|n| rb.teams.get(*n)) {
            let _ = agents::user_update(&app.d.k.paths, uid, |u| {
                u.team = team.clone();
                Ok(())
            });
        }
    }
    Ok(())
}

fn create_group(app: &App, r: &Request, p: &Principal, base: &str) -> Res {
    let v = body(r)?;
    let name = v["displayName"].as_str().unwrap_or("").trim().to_string();
    if name.is_empty() {
        return Err(err(400, "displayName is required", "invalidValue"));
    }
    let data = &app.d.k.paths.data;
    let mut gs = groups(data);
    let org = org_of(p);
    if gs.iter().any(|g| g.org == org && g.display_name.eq_ignore_ascii_case(&name)) {
        return Err(err(409, format!("group `{name}` exists"), "uniqueness"));
    }
    let members = member_ids(app, p, &v["members"])?;
    let now = now_ms();
    let g = Group { id: format!("g-{}", ark_kernel::util::random_hex(8)), display_name: name, external_id: v["externalId"].as_str().unwrap_or("").into(), members: members.clone(), org, created_ms: now, modified_ms: now };
    gs.push(g.clone());
    commit_groups(app, &gs, &members)?;
    audit(app, p, "scim.group.create", &g.id, json!({"group": g.display_name, "members": g.members}));
    Ok((201, group_json(data, &g, base)))
}

fn put_group(app: &App, r: &Request, p: &Principal, id: &str, base: &str) -> Res {
    find_group(app, p, id)?;
    let v = body(r)?;
    let members = member_ids(app, p, &v["members"])?;
    let data = &app.d.k.paths.data;
    let mut gs = groups(data);
    let g = gs.iter_mut().find(|g| g.id == id).ok_or_else(|| err(404, "gone", ""))?;
    let mut touched = g.members.clone();
    touched.extend(members.iter().cloned());
    if let Some(n) = v["displayName"].as_str().filter(|n| !n.trim().is_empty()) {
        g.display_name = n.trim().into();
    }
    g.external_id = v["externalId"].as_str().unwrap_or(&g.external_id).to_string();
    g.members = members;
    g.modified_ms = now_ms();
    let out = g.clone();
    commit_groups(app, &gs, &touched)?;
    audit(app, p, "scim.group.replace", id, json!({"group": out.display_name, "members": out.members}));
    Ok((200, group_json(data, &out, base)))
}

fn patch_group(app: &App, r: &Request, p: &Principal, id: &str, base: &str) -> Res {
    find_group(app, p, id)?;
    let v = body(r)?;
    if !v["schemas"].as_array().is_some_and(|a| a.iter().any(|s| s == S_PATCH)) {
        return Err(err(400, "not a PatchOp", "invalidSyntax"));
    }
    let data = &app.d.k.paths.data;
    let mut gs = groups(data);
    let gi = gs.iter().position(|g| g.id == id).ok_or_else(|| err(404, "gone", ""))?;
    let mut touched: Vec<String> = gs[gi].members.clone();
    for op in v["Operations"].as_array().ok_or_else(|| err(400, "no Operations", "invalidSyntax"))? {
        let kind = op["op"].as_str().unwrap_or("").to_ascii_lowercase();
        let path = op["path"].as_str().unwrap_or("");
        let value = &op["value"];
        let g = &mut gs[gi];
        match (kind.as_str(), path) {
            ("add", "members") => {
                for m in member_ids(app, p, value)? {
                    if !g.members.contains(&m) {
                        touched.push(m.clone());
                        g.members.push(m);
                    }
                }
            }
            ("replace", "members") => {
                let ms = member_ids(app, p, value)?;
                touched.extend(ms.iter().cloned());
                g.members = ms;
            }
            ("remove", "members") => {
                let drop = member_ids(app, p, value)?;
                if drop.is_empty() {
                    g.members.clear();
                } else {
                    g.members.retain(|m| !drop.contains(m));
                }
            }
            // `members[value eq "u-1"]` (Entra / Okta remove form).
            ("remove", p) if p.starts_with("members[") => {
                let (_, val) = parse_filter(p.trim_start_matches("members[").trim_end_matches(']'))?;
                g.members.retain(|m| *m != val);
            }
            ("replace" | "add", "displayName") => g.display_name = value.as_str().unwrap_or(&g.display_name).trim().to_string(),
            ("replace" | "add", "externalId") => g.external_id = value.as_str().unwrap_or("").into(),
            ("replace", "") => {
                if let Some(n) = value["displayName"].as_str() {
                    g.display_name = n.trim().into();
                }
                if value.get("members").is_some() {
                    let ms = member_ids(app, p, &value["members"])?;
                    let g = &mut gs[gi];
                    touched.extend(ms.iter().cloned());
                    g.members = ms;
                }
            }
            (o, p) => return Err(err(400, format!("unsupported patch `{o}` on `{p}`"), "invalidPath")),
        }
    }
    gs[gi].modified_ms = now_ms();
    let out = gs[gi].clone();
    commit_groups(app, &gs, &touched)?;
    audit(app, p, "scim.group.patch", id, json!({"group": out.display_name, "members": out.members}));
    Ok((200, group_json(data, &out, base)))
}

fn delete_group(app: &App, p: &Principal, id: &str) -> Res {
    let g = find_group(app, p, id)?;
    let data = &app.d.k.paths.data;
    let mut gs = groups(data);
    gs.retain(|x| x.id != id);
    save_groups(data, &gs).map_err(|e| err(500, e, ""))?;
    audit(app, p, "scim.group.delete", id, json!({"group": g.display_name}));
    Ok((204, Value::Null))
}

#[cfg(test)]
mod tests {
    use crate::tenant::harness::{app, arp, req, text};
    use crate::AppConfig;
    use serde_json::{json, Value};
    use std::sync::Arc;

    fn call(a: &Arc<crate::server::App>, token: &str, method: &str, path: &str, body: Value) -> (u16, Value) {
        let auth = format!("Bearer {token}");
        let b = if body.is_null() { String::new() } else { body.to_string() };
        let r = a.clone().handle(req(method, path, &[("authorization", &auth), ("content-type", "application/scim+json")], &b));
        (r.status, serde_json::from_str(&text(&r)).unwrap_or(Value::Null))
    }

    /// ent-049: provisioning, group sync into roles and teams, and deprovisioning that takes
    /// effect at once for cookies, personal tokens, open sockets and chat identities.
    #[test]
    fn scim_provisions_and_deprovisioning_is_immediate() {
        let mut rbac = crate::identity::RbacConfig::default();
        rbac.groups.insert("Engineering".into(), "operator".into());
        rbac.teams.insert("Engineering".into(), "eng".into());
        let secret = "0123456789abcdef0123";
        let mut basic = crate::dashboard_auth::BasicConfig::default();
        basic.users.insert("x".into(), "y".into());
        let a = app(AppConfig { enabled: true, listen: "127.0.0.1:0".into(), scim: true, rbac: Some(rbac.clone()), auth: crate::dashboard_auth::AuthConfig { enabled: true, provider: "basic".into(), secret: secret.into(), basic, ..Default::default() }, ..AppConfig::default() });
        let data = a.d.k.paths.data.clone();
        let by = ark_security::audit::Actor::local();
        let (_, scim) = crate::identity::issue(&data, "scim", "admin", 0, "IdP provisioning", &by).unwrap();
        let (_, weak) = crate::identity::issue(&data, "weak", "user", 0, "", &by).unwrap();
        // Authentication and RBAC.
        assert_eq!(a.clone().handle(req("GET", "/scim/v2/Users", &[], "")).status, 401);
        assert_eq!(call(&a, &weak, "GET", "/scim/v2/Users", Value::Null).0, 403);
        assert_eq!(call(&a, &scim, "GET", "/scim/v2/ServiceProviderConfig", Value::Null).1["patch"]["supported"], true);
        // Create, uniqueness, filter.
        let dave = json!({"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "dave@corp.example", "externalId": "ext-1", "name": {"givenName": "Dave", "familyName": "Doe"}, "emails": [{"value": "Dave@Corp.example", "primary": true}], "active": true});
        let (st, u) = call(&a, &scim, "POST", "/scim/v2/Users", dave.clone());
        assert_eq!(st, 201, "{u}");
        let id = u["id"].as_str().unwrap().to_string();
        assert_eq!(u["displayName"], "Dave Doe");
        assert_eq!(call(&a, &scim, "POST", "/scim/v2/Users", dave).0, 409);
        let (_, l) = call(&a, &scim, "GET", "/scim/v2/Users?filter=userName%20eq%20%22DAVE@corp.example%22", Value::Null);
        assert_eq!(l["totalResults"], 1);
        assert_eq!(call(&a, &scim, "GET", "/scim/v2/Users?filter=userName%20co%20%22d%22", Value::Null).0, 400);
        // Group membership → role at login and team on the profile.
        let (st, g) = call(&a, &scim, "POST", "/scim/v2/Groups", json!({"displayName": "Engineering", "members": [{"value": id}]}));
        assert_eq!(st, 201, "{g}");
        let gid = g["id"].as_str().unwrap().to_string();
        assert_eq!(ark_kernel::agents::get_user(&a.d.k.paths, &id).unwrap().team, "eng");
        let facts = crate::identity::LoginFacts { provider: "sso", subject: "sub-dave", email: "dave@corp.example", groups: vec![], provider_admin: false };
        assert_eq!(crate::identity::login_roles(Some(&rbac), &a.d.k.paths, &facts).unwrap(), vec![crate::identity::Role::Operator]);
        assert_eq!(call(&a, &scim, "GET", &format!("/scim/v2/Users/{id}"), Value::Null).1["groups"][0]["display"], "Engineering");
        // Dave's live credentials: a cookie, a personal token, a chat identity, a session he owns.
        let s = ark_plugin::dashboard_auth::Session { subject: "sub-dave".into(), email: Some("dave@corp.example".into()), name: Some("Dave".into()), expires_at: None, admin: false };
        let now = crate::dashboard_auth::unix_now();
        let cookie = format!("ark_session={}", crate::dashboard_auth::mint_with(secret.as_bytes(), &s, &[crate::identity::Role::User], "sso", now, 3600));
        let personal = crate::dashboard_auth::mint_with(secret.as_bytes(), &s, &[crate::identity::Role::User], "sso", now, 600);
        ark_kernel::agents::user_link(&a.d.k.paths, &id, "slack", "UDAVE").unwrap();
        let p_ws = a.principal(&req("GET", "/arp", &[("cookie", &cookie)], "")).expect("cookie works while active");
        assert!(a.still_valid(&p_ws));
        let sid = arp(&a, &format!("cookie:{cookie}"), "session.create", json!({}))["result"]["id"].as_str().unwrap().to_string();
        let user = ark_kernel::agents::get_user(&a.d.k.paths, &id).unwrap();
        assert_eq!(ark_kernel::governance::sessions_of_user(&a.d.k.paths, &a.d.k.store, std::slice::from_ref(&sid), &user), vec![sid.clone()]);
        assert!(crate::identity::channel_permits(&a.d.k.paths, "slack", "UDAVE", false).is_ok());
        // Okta-style deactivation.
        let (st, u) = call(&a, &scim, "PATCH", &format!("/scim/v2/Users/{id}"), json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "value": {"active": false}}]}));
        assert_eq!((st, u["active"].clone()), (200, json!(false)));
        assert!(a.principal(&req("GET", "/arp", &[("cookie", &cookie)], "")).is_none(), "cookie refused");
        assert!(a.principal(&req("GET", "/arp", &[("authorization", &format!("Bearer {personal}"))], "")).is_none(), "personal token refused");
        assert!(!a.still_valid(&p_ws), "an open socket is closed on its next check");
        assert!(crate::identity::channel_permits(&a.d.k.paths, "slack", "UDAVE", false).unwrap_err().contains("disabled"));
        let recs = ark_security::audit::query(&data, &ark_security::audit::Query { kind: Some("scim".into()), limit: 100, ..Default::default() });
        let kinds: Vec<&str> = recs.iter().map(|r| r["kind"].as_str().unwrap()).collect();
        assert!(kinds.contains(&"scim.user.create") && kinds.contains(&"scim.group.create") && kinds.contains(&"scim.user.deactivate") && kinds.contains(&"scim.denied"), "{kinds:?}");
        assert!(recs.iter().all(|r| r["actor"]["name"] == "scim" || r["actor"]["name"] == "weak"));
        // Entra-style reactivation and path form; group member removal by filter.
        let (st, u) = call(&a, &scim, "PATCH", &format!("/scim/v2/Users/{id}"), json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "Replace", "path": "active", "value": "True"}]}));
        assert_eq!((st, u["active"].clone()), (200, json!(true)));
        assert!(a.principal(&req("GET", "/arp", &[("cookie", &cookie)], "")).is_some());
        let (st, g) = call(&a, &scim, "PATCH", &format!("/scim/v2/Groups/{gid}"), json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "remove", "path": format!("members[value eq \"{id}\"]")}]}));
        assert_eq!((st, g["members"].as_array().unwrap().len()), (200, 0));
        // DELETE: soft, hidden from SCIM, and access ends.
        assert_eq!(call(&a, &scim, "DELETE", &format!("/scim/v2/Users/{id}"), Value::Null).0, 204);
        assert_eq!(call(&a, &scim, "GET", &format!("/scim/v2/Users/{id}"), Value::Null).0, 404);
        assert!(ark_kernel::agents::get_user(&a.d.k.paths, &id).unwrap().disabled, "history stays attributable");
        assert!(a.principal(&req("GET", "/arp", &[("cookie", &cookie)], "")).is_none());
    }

    /// A provisioning credential bound to an organization creates users there and sees no others.
    #[test]
    fn scim_tokens_are_tenant_scoped() {
        let a = app(AppConfig { enabled: true, listen: "127.0.0.1:0".into(), scim: true, ..AppConfig::default() });
        let data = a.d.k.paths.data.clone();
        ark_kernel::tenancy::org_add(&data, "acme", "").unwrap();
        let by = ark_security::audit::Actor::local();
        let (_, acme) = crate::identity::issue(&data, "scim-acme", "admin", 0, "", &by).unwrap();
        crate::identity::set_tenant(&data, "scim-acme", "acme", "", &by).unwrap();
        let (_, global) = crate::identity::issue(&data, "scim-all", "admin", 0, "", &by).unwrap();
        let (_, other) = call(&a, &global, "POST", "/scim/v2/Users", json!({"userName": "zed@else.example"}));
        let (st, mine) = call(&a, &acme, "POST", "/scim/v2/Users", json!({"userName": "amy@acme.example"}));
        assert_eq!(st, 201);
        assert_eq!(ark_kernel::agents::get_user(&a.d.k.paths, mine["id"].as_str().unwrap()).unwrap().org, "acme");
        assert_eq!(call(&a, &acme, "GET", "/scim/v2/Users", Value::Null).1["totalResults"], 1);
        assert_eq!(call(&a, &acme, "GET", &format!("/scim/v2/Users/{}", other["id"].as_str().unwrap()), Value::Null).0, 404);
        assert_eq!(call(&a, &acme, "PATCH", &format!("/scim/v2/Users/{}", other["id"].as_str().unwrap()), json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "active", "value": false}]})).0, 404);
        assert_eq!(call(&a, &global, "GET", "/scim/v2/Users", Value::Null).1["totalResults"], 2);
        // Off by default: no route at all.
        let off = app(AppConfig { enabled: true, listen: "127.0.0.1:0".into(), ..AppConfig::default() });
        assert_eq!(off.clone().handle(req("GET", "/scim/v2/Users", &[("authorization", "Bearer admin-token")], "")).status, 404);
    }
}
