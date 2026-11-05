//! Microsoft Entra ID (Graph) and Okta, read-only.

use super::{clip, Provider, Query};
use crate::pro_http;
use serde_json::{json, Value};
use std::sync::Mutex;
use std::time::{Duration, Instant};

fn odata(v: &str) -> String {
    v.replace('\'', "''")
}

/// Path segments (ids, UPNs, logins) are interpolated into URLs: a conservative charset only.
pub fn segment_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.chars().all(|c| c.is_alphanumeric() || matches!(c, '@' | '.' | '_' | '-' | '+'))
}

fn guid(s: &str) -> bool {
    s.len() == 36 && s.chars().enumerate().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { c == '-' } else { c.is_ascii_hexdigit() })
}

static TOKENS: Mutex<Vec<(String, String, Instant)>> = Mutex::new(Vec::new());

/// Bearer token: a configured `token`, or the client-credentials flow when
/// `tenant` + `client_id` + `client_secret` are set (cached for 50 minutes).
fn graph_token(p: &Provider, ctx: &ark_core::ToolCtx) -> Result<String, String> {
    if let Some(t) = p.token.as_deref().filter(|t| !t.trim().is_empty()) {
        return super::secret(ctx, t);
    }
    let (Some(tenant), Some(id), Some(sec)) = (p.tenant.as_deref(), p.client_id.as_deref(), p.client_secret.as_deref()) else {
        return Err("entra needs `token`, or `tenant` + `client_id` + `client_secret`".into());
    };
    let (id, secret) = (super::secret(ctx, id)?, super::secret(ctx, sec)?);
    let key = format!("{tenant}/{id}");
    {
        let mut c = TOKENS.lock().unwrap_or_else(|e| e.into_inner());
        c.retain(|(_, _, t)| t.elapsed() < Duration::from_secs(50 * 60));
        if let Some((_, t, _)) = c.iter().find(|(k, ..)| *k == key) {
            return Ok(t.clone());
        }
    }
    let base = p.login_base.as_deref().unwrap_or("https://login.microsoftonline.com").trim_end_matches('/');
    let r = pro_http::post_form(&format!("{base}/{}/oauth2/v2.0/token", crate::web::http::enc(tenant)), &[("grant_type", "client_credentials"), ("client_id", &id), ("client_secret", &secret), ("scope", "https://graph.microsoft.com/.default")], p.timeout(), &[&secret])?;
    if !r.ok() {
        return Err(pro_http::api_error("Entra token request", &r, &[&secret]));
    }
    let tok = r.json()?["access_token"].as_str().ok_or("Entra answered without an access_token")?.to_string();
    TOKENS.lock().unwrap_or_else(|e| e.into_inner()).push((key, tok.clone(), Instant::now()));
    Ok(tok)
}

fn graph_get(p: &Provider, ctx: &ark_core::ToolCtx, path_and_query: &str) -> Result<Value, String> {
    let tok = graph_token(p, ctx)?;
    let base = p.api_base.as_deref().unwrap_or("https://graph.microsoft.com/v1.0").trim_end_matches('/');
    let r = pro_http::get(&format!("{base}{path_and_query}"), &[("Authorization", format!("Bearer {tok}")), ("Accept", "application/json".into()), ("ConsistencyLevel", "eventual".into())], p.timeout(), &[&tok])?;
    if !r.ok() {
        return Err(pro_http::api_error("Microsoft Graph", &r, &[&tok]));
    }
    r.json()
}

const USER_SELECT: &str = "id,displayName,userPrincipalName,mail,accountEnabled,jobTitle,department,createdDateTime,onPremisesSamAccountName";
const GROUP_SELECT: &str = "id,displayName,description,mail,securityEnabled,groupTypes";

fn graph_user(v: &Value) -> Value {
    json!({"id": v["id"], "login": v["onPremisesSamAccountName"], "upn": v["userPrincipalName"], "name": v["displayName"].as_str().map(clip), "mail": v["mail"], "title": v["jobTitle"], "department": v["department"], "enabled": v["accountEnabled"], "created": v["createdDateTime"]})
}

fn graph_group(v: &Value) -> Value {
    json!({"id": v["id"], "name": v["displayName"].as_str().map(clip), "description": v["description"].as_str().map(clip), "mail": v["mail"], "security": v["securityEnabled"], "kind": v["groupTypes"]})
}

fn graph_list(p: &Provider, ctx: &ark_core::ToolCtx, path: &str, select: &str, filter: Option<String>, limit: usize) -> Result<(Vec<Value>, bool), String> {
    let mut url = format!("{path}?$select={select}&$top={}", limit + 1);
    if let Some(f) = filter {
        url.push_str(&format!("&$filter={}", crate::web::http::enc(&f)));
    }
    let v = graph_get(p, ctx, &url)?;
    let mut items = v["value"].as_array().cloned().unwrap_or_default();
    let more = items.len() > limit || v.get("@odata.nextLink").is_some();
    items.truncate(limit);
    Ok((items, more))
}

fn graph_resolve(p: &Provider, ctx: &ark_core::ToolCtx, kind: &str, q: &str) -> Result<String, String> {
    if guid(q) || (kind == "users" && q.contains('@') && segment_ok(q)) {
        return Ok(q.to_string());
    }
    let (path, field, select) = if kind == "users" { ("/users", "displayName", USER_SELECT) } else { ("/groups", "displayName", GROUP_SELECT) };
    let f = if kind == "users" { format!("{field} eq '{0}' or userPrincipalName eq '{0}' or mail eq '{0}' or onPremisesSamAccountName eq '{0}'", odata(q)) } else { format!("{field} eq '{}'", odata(q)) };
    let (items, _) = graph_list(p, ctx, path, select, Some(f), 2)?;
    match items.as_slice() {
        [] => Err(format!("nothing named `{q}`")),
        [one] => Ok(one["id"].as_str().unwrap_or("").to_string()),
        _ => Err(format!("`{q}` is ambiguous; use the object id")),
    }
}

pub fn entra(p: &Provider, ctx: &ark_core::ToolCtx, q: &Query) -> Result<Value, String> {
    let s = odata(&q.query);
    match q.kind.as_str() {
        "user" => {
            let f = format!("startswith(displayName,'{s}') or startswith(userPrincipalName,'{s}') or startswith(mail,'{s}') or startswith(onPremisesSamAccountName,'{s}')");
            let (items, more) = graph_list(p, ctx, "/users", USER_SELECT, Some(f), q.limit)?;
            Ok(json!({"results": items.iter().map(graph_user).collect::<Vec<_>>(), "truncated": more}))
        }
        "group" => {
            let (items, more) = graph_list(p, ctx, "/groups", GROUP_SELECT, Some(format!("startswith(displayName,'{s}')")), q.limit)?;
            Ok(json!({"results": items.iter().map(graph_group).collect::<Vec<_>>(), "truncated": more}))
        }
        "members" => {
            let id = graph_resolve(p, ctx, "groups", &q.query)?;
            if !segment_ok(&id) {
                return Err("bad group id".into());
            }
            let (items, more) = graph_list(p, ctx, &format!("/groups/{id}/members"), USER_SELECT, None, q.limit)?;
            Ok(json!({"results": [{"group": q.query, "members": items.iter().map(graph_user).collect::<Vec<_>>()}], "truncated": more}))
        }
        "groups_of" => {
            let id = graph_resolve(p, ctx, "users", &q.query)?;
            if !segment_ok(&id) {
                return Err("bad user id".into());
            }
            let (items, more) = graph_list(p, ctx, &format!("/users/{id}/memberOf"), GROUP_SELECT, None, q.limit)?;
            Ok(json!({"results": [{"user": q.query, "groups": items.iter().filter(|g| g["displayName"].is_string()).map(graph_group).collect::<Vec<_>>()}], "truncated": more}))
        }
        k => Err(format!("unknown kind `{k}`")),
    }
}

// ───────────────────────────── Okta ─────────────────────────────

fn okta_get(p: &Provider, ctx: &ark_core::ToolCtx, path_and_query: &str) -> Result<Value, String> {
    let tok = super::secret(ctx, p.token.as_deref().ok_or("okta needs `token` (an API token with read-only admin rights)")?)?;
    let base = p.org_url.as_deref().ok_or("okta needs `org_url`")?.trim_end_matches('/');
    let r = pro_http::get(&format!("{base}/api/v1{path_and_query}"), &[("Authorization", format!("SSWS {tok}")), ("Accept", "application/json".into())], p.timeout(), &[&tok])?;
    if !r.ok() {
        return Err(pro_http::api_error("Okta", &r, &[&tok]));
    }
    r.json()
}

fn okta_user(v: &Value) -> Value {
    let pr = &v["profile"];
    json!({"id": v["id"], "login": pr["login"], "name": format!("{} {}", pr["firstName"].as_str().unwrap_or(""), pr["lastName"].as_str().unwrap_or("")).trim().to_string(), "mail": pr["email"], "title": pr["title"], "department": pr["department"], "status": v["status"], "enabled": !matches!(v["status"].as_str(), Some("SUSPENDED" | "DEPROVISIONED" | "LOCKED_OUT")), "last_login": v["lastLogin"], "created": v["created"]})
}

fn okta_group(v: &Value) -> Value {
    json!({"id": v["id"], "name": v["profile"]["name"].as_str().map(clip), "description": v["profile"]["description"].as_str().map(clip), "kind": v["type"]})
}

fn okta_resolve(p: &Provider, ctx: &ark_core::ToolCtx, kind: &str, q: &str) -> Result<String, String> {
    let looks_id = q.len() == 20 && q.starts_with("00") && q.chars().all(|c| c.is_ascii_alphanumeric());
    if looks_id {
        return Ok(q.to_string());
    }
    let v = okta_get(p, ctx, &format!("/{kind}?q={}&limit=5", crate::web::http::enc(q)))?;
    let items = v.as_array().cloned().unwrap_or_default();
    let exact: Vec<&Value> = items.iter().filter(|i| if kind == "users" { [&i["profile"]["login"], &i["profile"]["email"]].iter().any(|x| x.as_str().is_some_and(|s| s.eq_ignore_ascii_case(q))) } else { i["profile"]["name"].as_str().is_some_and(|s| s.eq_ignore_ascii_case(q)) }).collect();
    let pick = if exact.len() == 1 { exact } else { items.iter().collect() };
    match pick.as_slice() {
        [] => Err(format!("nothing named `{q}`")),
        [one] => Ok(one["id"].as_str().unwrap_or("").to_string()),
        _ => Err(format!("`{q}` is ambiguous; use the exact login/name or the id")),
    }
}

pub fn okta(p: &Provider, ctx: &ark_core::ToolCtx, q: &Query) -> Result<Value, String> {
    let enc = crate::web::http::enc;
    let cut = |v: Value, limit: usize| -> (Vec<Value>, bool) {
        let mut a = v.as_array().cloned().unwrap_or_default();
        let more = a.len() > limit;
        a.truncate(limit);
        (a, more)
    };
    match q.kind.as_str() {
        "user" => {
            let (items, more) = cut(okta_get(p, ctx, &format!("/users?q={}&limit={}", enc(&q.query), q.limit + 1))?, q.limit);
            Ok(json!({"results": items.iter().map(okta_user).collect::<Vec<_>>(), "truncated": more}))
        }
        "group" => {
            let (items, more) = cut(okta_get(p, ctx, &format!("/groups?q={}&limit={}", enc(&q.query), q.limit + 1))?, q.limit);
            Ok(json!({"results": items.iter().map(okta_group).collect::<Vec<_>>(), "truncated": more}))
        }
        "members" => {
            let id = okta_resolve(p, ctx, "groups", &q.query)?;
            let (items, more) = cut(okta_get(p, ctx, &format!("/groups/{}/users?limit={}", enc(&id), q.limit + 1))?, q.limit);
            Ok(json!({"results": [{"group": q.query, "members": items.iter().map(okta_user).collect::<Vec<_>>()}], "truncated": more}))
        }
        "groups_of" => {
            let id = okta_resolve(p, ctx, "users", &q.query)?;
            let (items, more) = cut(okta_get(p, ctx, &format!("/users/{}/groups", enc(&id)))?, q.limit);
            Ok(json!({"results": [{"user": q.query, "groups": items.iter().map(okta_group).collect::<Vec<_>>()}], "truncated": more}))
        }
        k => Err(format!("unknown kind `{k}`")),
    }
}
