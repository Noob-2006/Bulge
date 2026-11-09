//! Who may manage which conversation through the web console's `ui.chat.*` methods (the rail's
//! "⋯" menu, the conversation settings, the composer's model switch).
//!
//! * **Admin** (the `[app] token`, admin-scoped tokens and service accounts, logins with the
//!   admin role) manages every conversation.
//! * **Organization-bound principals** (ent-050, [`crate::tenant`]) manage the conversations of
//!   their tenant: the tenant guard already answers `-32004 no such session` for another
//!   tenant's id, and these methods are on its allowlist.
//! * **Every other principal** — a write-scoped token or a paired device that is not bound to an
//!   organization — manages only the conversations it owns: the ones it created or forked (and
//!   their sub-agent children), as recorded in the owner registry
//!   (`seagent_kernel::governance::note_owner`). Someone else's conversation answers exactly like
//!   a missing one.
//!
//! Each non-admin scope also gets its own rail state (sections, unread markers): the server
//! passes `_rail` to the handler (`crates/seagent/src/ops/chat_ux.rs`), never the client.
//! `ui.chat.list` tells the console which rows it may manage (`manage`: `"all"` or a list).

use crate::identity::{Access, Principal, Role};
use crate::server::App;
use seagent_kernel::governance;
use serde_json::{json, Value};

/// `ui.chat.*` methods whose `params.id` names a conversation.
pub const SESSION_METHODS: &[&str] = &[
    "ui.chat.meta.set", "ui.chat.read", "ui.chat.fork", "ui.chat.delete", "ui.chat.restore", "ui.chat.purge",
    "ui.chat.settings.get", "ui.chat.settings.set", "ui.chat.export",
];

/// The `ui.chat.*` methods an organization-bound principal may call (on its own tenant).
pub const TENANT_METHODS: &[&str] = &[
    "ui.chat.list", "ui.chat.section", "ui.chat.models.list", "ui.chat.meta.set", "ui.chat.read", "ui.chat.fork", "ui.chat.delete", "ui.chat.restore",
    "ui.chat.settings.get", "ui.chat.settings.set", "ui.chat.export",
];

pub fn is_admin(p: &Principal) -> bool {
    p.access == Access::Scope(crate::exposure::Scope::Admin) || p.access.has(Role::Admin)
}

/// Limited to its own conversations (see the module docs).
fn owner_scoped(app: &App, p: &Principal) -> bool {
    !is_admin(p) && !crate::tenant::bound(app, p)
}

/// Does `p` own conversation `sid` (directly, or through the parent it was spawned from)?
pub fn owns(app: &App, p: &Principal, sid: &str) -> bool {
    !sid.is_empty() && governance::owner_label_in(&app.d.k.paths, &app.d.k.store, sid) == p.label()
}

/// The rail-state scope of a principal ("" = the installation owner's).
fn rail_scope(app: &App, p: &Principal) -> String {
    if crate::tenant::bound(app, p) {
        let team = if p.tenant.org_admin { "" } else { p.tenant.team.as_str() };
        format!("tenant:{}:{team}", p.tenant.org)
    } else if is_admin(p) {
        String::new()
    } else {
        p.label()
    }
}

/// Before a `ui.chat.*` call: refuse someone else's conversation, set the rail scope.
pub fn guard(app: &App, p: &Principal, method: &str, params: &mut Value) -> Result<(), (i32, String)> {
    if let Some(o) = params.as_object_mut() {
        o.remove("_rail");
    }
    if !method.starts_with("ui.chat.") {
        return Ok(());
    }
    if owner_scoped(app, p) && SESSION_METHODS.contains(&method) && !owns(app, p, params["id"].as_str().unwrap_or("")) {
        return Err(crate::tenant::not_found());
    }
    let rail = rail_scope(app, p);
    if !rail.is_empty() {
        params["_rail"] = json!(rail);
    }
    Ok(())
}

/// After a successful call: a fork belongs to whoever forked it; `ui.chat.list` only shows the
/// trash a principal may restore and says which rows it may manage.
pub fn after(app: &App, p: &Principal, method: &str, result: &mut Value) {
    let data = &app.d.k.paths.data;
    if method == "ui.chat.fork" {
        if let Some(sid) = result["id"].as_str() {
            governance::note_owner(data, sid, &p.label());
        }
    }
    if method != "ui.chat.list" {
        return;
    }
    if owner_scoped(app, p) {
        let mine: Vec<String> = app.d.k.store.list().into_iter().map(|s| s.id).filter(|id| owns(app, p, id)).collect();
        if let Some(t) = result["trash"].as_array_mut() {
            t.retain(|x| x["id"].as_str().is_some_and(|id| owns(app, p, id)));
        }
        result["manage"] = json!(mine);
    } else {
        if crate::tenant::bound(app, p) {
            let reg = seagent_kernel::tenancy::registry(data);
            if let Some(t) = result["trash"].as_array_mut() {
                t.retain(|x| x["id"].as_str().is_some_and(|id| p.tenant.sees(&seagent_kernel::tenancy::session_tenant(data, id), &reg)));
            }
        }
        result["manage"] = json!("all");
    }
}

#[cfg(test)]
mod tests {
    use crate::exposure::TokenConfig;
    use crate::tenant::harness::*;
    use crate::AppConfig;
    use seagent_kernel::tenancy;
    use serde_json::{json, Value};
    use std::sync::Arc;

    fn tok(token: &str, scope: &str, org: &str, team: &str) -> TokenConfig {
        TokenConfig { token: token.into(), scope: scope.into(), name: Some(token.into()), org: org.into(), team: team.into() }
    }

    /// The handlers live in the `seagent` crate; here a stand-in answers every `ui.chat.*` call
    /// with what it received, so the test sees exactly what passed the guard.
    fn with_stub(a: &Arc<crate::server::App>) {
        let k = a.d.k.clone();
        a.d.add_methods(Arc::new(move |m: &str, p: &Value| {
            if !m.starts_with("ui.chat.") {
                return None;
            }
            Some(Ok(match m {
                "ui.chat.fork" => json!({"id": k.create_session(&k.paths.data, None, None, Some("fork")).unwrap()}),
                "ui.chat.list" => json!({"sections": [], "trash": [], "rail": p["_rail"]}),
                _ => json!({"ok": true, "id": p["id"], "rail": p["_rail"]}),
            }))
        }));
    }

    #[test]
    fn write_tokens_and_devices_manage_only_their_own_conversations() {
        let a = app(AppConfig { enabled: true, listen: "127.0.0.1:0".into(), tokens: vec![tok("alice-tok", "write", "", ""), tok("bob-tok", "write", "", ""), tok("viewer-tok", "read", "", "")], ..AppConfig::default() });
        with_stub(&a);
        let create = |cred: &str| arp(&a, cred, "session.create", json!({}))["result"]["id"].as_str().unwrap().to_string();
        let alice = create("alice-tok");
        let bob = create("bob-tok");
        let admins = create("admin-token");
        // Own conversation: every menu / settings / model-switch method passes.
        for m in ["ui.chat.settings.get", "ui.chat.settings.set", "ui.chat.meta.set", "ui.chat.read", "ui.chat.delete", "ui.chat.restore", "ui.chat.export"] {
            let r = arp(&a, "alice-tok", m, json!({"id": alice, "model": "x/y"}));
            assert_eq!(r["result"]["ok"], true, "alice {m} on her own: {r}");
            assert_eq!(r["result"]["rail"], "token:alice-tok", "her own rail scope");
        }
        // Someone else's (another token's, or the owner's): indistinguishable from a missing one.
        for sid in [&bob, &admins] {
            for m in ["ui.chat.settings.get", "ui.chat.settings.set", "ui.chat.meta.set", "ui.chat.delete", "ui.chat.export", "ui.chat.fork"] {
                let r = arp(&a, "alice-tok", m, json!({"id": sid}));
                assert_eq!(r["error"]["code"], -32004, "alice {m} on {sid}: {r}");
            }
        }
        // A forged scope cannot be smuggled in.
        assert_eq!(arp(&a, "alice-tok", "ui.chat.settings.get", json!({"id": alice, "_rail": ""}))["result"]["rail"], "token:alice-tok");
        // The admin token manages everything and keeps the installation's rail.
        for sid in [&alice, &bob, &admins] {
            let r = arp(&a, "admin-token", "ui.chat.settings.set", json!({"id": sid}));
            assert_eq!(r["result"]["ok"], true, "{r}");
            assert!(r["result"]["rail"].is_null());
        }
        // A fork belongs to whoever made it; the list says which rows are manageable.
        let f = arp(&a, "alice-tok", "ui.chat.fork", json!({"id": alice}))["result"]["id"].as_str().unwrap().to_string();
        assert_eq!(arp(&a, "alice-tok", "ui.chat.settings.get", json!({"id": f}))["result"]["ok"], true);
        assert_eq!(arp(&a, "bob-tok", "ui.chat.settings.get", json!({"id": f}))["error"]["code"], -32004);
        let mut mine: Vec<String> = serde_json::from_value(arp(&a, "alice-tok", "ui.chat.list", json!({}))["result"]["manage"].clone()).unwrap();
        mine.sort();
        let mut want = vec![alice.clone(), f.clone()];
        want.sort();
        assert_eq!(mine, want);
        assert_eq!(arp(&a, "admin-token", "ui.chat.list", json!({}))["result"]["manage"], "all");
        // Read scope: the reads only (settings.get is a read), never a change.
        assert!(arp(&a, "viewer-tok", "ui.chat.settings.set", json!({"id": bob})).to_string().contains("forbidden"));
        // Permanent deletion stays with the admin.
        assert!(arp(&a, "alice-tok", "ui.chat.purge", json!({"id": alice})).to_string().contains("forbidden"));
    }

    #[test]
    fn tenant_tokens_manage_their_tenants_conversations_only() {
        let a = app(AppConfig { enabled: true, listen: "127.0.0.1:0".into(), tokens: vec![tok("eng-tok", "user", "acme", "eng"), tok("glx-tok", "user", "globex", "rnd")], ..AppConfig::default() });
        with_stub(&a);
        let data = a.d.k.paths.data.clone();
        tenancy::org_add(&data, "acme", "").unwrap();
        tenancy::org_add(&data, "globex", "").unwrap();
        tenancy::team_add(&data, "eng", "acme", "").unwrap();
        tenancy::team_add(&data, "rnd", "globex", "").unwrap();
        let eng = arp(&a, "eng-tok", "session.create", json!({}))["result"]["id"].as_str().unwrap().to_string();
        let glx = arp(&a, "glx-tok", "session.create", json!({}))["result"]["id"].as_str().unwrap().to_string();
        for m in ["ui.chat.settings.get", "ui.chat.settings.set", "ui.chat.meta.set", "ui.chat.delete", "ui.chat.export"] {
            let own = arp(&a, "eng-tok", m, json!({"id": eng}));
            assert_eq!(own["result"]["ok"], true, "{m} own: {own}");
            assert_eq!(own["result"]["rail"], "tenant:acme:eng");
            let other = arp(&a, "eng-tok", m, json!({"id": glx}));
            assert_eq!(other["error"]["code"], -32004, "{m} other tenant: {other}");
        }
        assert_eq!(arp(&a, "eng-tok", "ui.chat.list", json!({}))["result"]["manage"], "all");
        // Installation-wide key management is still out of reach.
        assert!(arp(&a, "eng-tok", "ui.keys.list", json!({})).to_string().contains("forbidden"));
    }
}
