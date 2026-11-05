//! `browser_vault` actions (Hermes `browser_vault_tool.py`, MIT): list, fill,
//! save_login, enter_code, unlock. Secrets are resolved here, registered with the
//! redaction boundary before they touch the page, and injected over CDP only.

use crate::manager::Env;
use crate::tools;
use crate::vault::{self, Classified, Control};
use crate::{engine::Browser, policy};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const TAB_PROBES: &[(&str, &str)] = &[
    ("login", "!!document.querySelector('input[type=password]')"),
    ("payment", "!!document.querySelector('input[autocomplete^=cc-], [name*=card i], [placeholder*=card i], [name*=cvc i], [name*=cvv i]')"),
    ("address", "!!document.querySelector('input[autocomplete^=address-], [autocomplete=postal-code], [name*=address i], [name*=zip i], [name*=postal i]')"),
    ("otp", "!!document.querySelector('input[autocomplete=one-time-code], input[name*=otp i], input[name*=code i], input[id*=otp i], input[id*=code i], input[name*=totp i], input[aria-label*=code i]')"),
];

fn page_origin(b: &Browser, t: &str) -> Option<String> {
    let href = b.eval(t, "window.location.href").ok()?;
    let h = href.as_str()?.trim();
    if h.is_empty() || h == "about:blank" {
        return None;
    }
    vault::normalize_origin(h).ok()
}

/// Switch the session to the open tab on `origin` that holds a `kind` form (Hermes `focus_page`).
fn focus_origin(env: &Env, sid: &str, b: &Browser, origin: &str, kind: &str) -> Option<String> {
    let probe = TAB_PROBES.iter().find(|(k, _)| *k == kind).map(|(_, p)| *p)?;
    for tab in b.tabs(None).ok()? {
        let tid = tab["targetId"].as_str()?.to_string();
        let o = vault::normalize_origin(tab["url"].as_str().unwrap_or("")).ok();
        if !origin.is_empty() && o.as_deref() != Some(origin) {
            continue;
        }
        if b.eval(&tid, probe).ok().and_then(|v| v.as_bool()) == Some(true) {
            crate::manager::global().focus(sid, b, &tid);
            let _ = env;
            return o;
        }
    }
    None
}

fn inspect(b: &Browser, t: &str, nonce: &str) -> Result<Vec<Control>, String> {
    let v = b.eval(t, &vault::inspection_js(nonce)).map_err(|e| format!("Could not inspect page inputs: {e}"))?;
    let arr = v.as_array().ok_or("Page input inspection returned no usable controls.")?;
    Ok(arr.iter().map(Control::from_json).collect())
}

fn run_fill(b: &Browser, t: &str, fills: &[Value], origin: &str, nonce: &str, secret: &BTreeMap<String, String>) -> Result<i64, String> {
    // CDP Runtime.evaluate over the browser socket: never argv, never logged.
    let r = b.eval(t, &vault::fill_js(fills, origin, nonce)).map_err(|e| vault::scrub(&e, secret))?;
    if r["refused"] == "origin_changed" {
        return Err(format!("origin_changed: Refused: the page navigated away from the bound origin ({origin}) before the fill could run (now on {}). Nothing was written.", r["found"].as_str().unwrap_or("unknown")));
    }
    Ok(r["filled"].as_i64().unwrap_or(0))
}

fn err(kind: &str, msg: impl Into<String>) -> Value {
    json!({"success": false, "error_type": kind, "error": msg.into()})
}

pub fn call(env: &Env, sid: &str, input: &Value) -> Result<Value, String> {
    let action = input["action"].as_str().unwrap_or("");
    match action {
        "list" => Ok(list(env)),
        "unlock" => Ok(unlock(input["backend"].as_str().unwrap_or(""))),
        "fill" | "save_login" | "enter_code" => {
            if crate::desktop_lease_human(&env.home) {
                return Ok(err("human_has_control", "A human has taken over this desktop (they may be entering a credential). Screen actions and captures are refused until they hand control back. Tell the user what you need in your reply."));
            }
            let (b, t) = tools::existing(env, sid)?;
            Ok(match action {
                "fill" => fill(env, sid, &b, &t, input["handle"].as_str().unwrap_or("")),
                "save_login" => save_login(env, sid, &b, &t, input["label"].as_str().unwrap_or("")),
                _ => enter_code(env, sid, &b, &t, input["handle"].as_str().unwrap_or("")),
            })
        }
        o => Err(format!("Unknown action {o:?}; use list, fill, save_login, enter_code or unlock.")),
    }
}

fn list(env: &Env) -> Value {
    let (mut items, mut locked, mut errors) = (vec![], vec![], vec![]);
    for b in vault::backends_enabled() {
        if !vault::is_unlocked(b) {
            locked.push(json!({"backend": b, "display_name": vault::display_name(b), "unlock": if vault::can_prompt() { "browser_vault action=unlock" } else { "unavailable_in_this_session" }}));
            continue;
        }
        let r = if b == "local" { vault::load(&env.home) } else { vault::list_external(b) };
        match r {
            Ok(v) => items.extend(v.iter().map(|i| {
                let mut m = i.meta(b);
                if b != "local" && m.get("two_factor").is_none() {
                    m["two_factor"] = "automatic if the manager stores a TOTP seed, else the user is asked".into();
                }
                m
            })),
            Err(e) => errors.push(json!({"backend": b, "error": crate::util::cut(&e, 200)})),
        }
    }
    let mut out = json!({"success": true, "items": items});
    if out["items"].as_array().unwrap().is_empty() {
        out["hint"] = "No saved logins. On a login page, call browser_vault action=save_login to ask the user to save one. Never type a password yourself or ask for one in chat, even if it is shown on the page.".into();
    }
    if !locked.is_empty() {
        out["locked"] = locked.into();
    }
    if !errors.is_empty() {
        out["errors"] = errors.into();
    }
    out
}

fn unlock(backend: &str) -> Value {
    if !matches!(backend, "bitwarden" | "onepassword") || !vault::backends_enabled().contains(&backend) {
        return json!({"success": false, "error": format!("No unlockable vault backend named {backend:?}.")});
    }
    if vault::is_unlocked(backend) {
        return json!({"success": true, "backend": backend, "already_unlocked": true});
    }
    let name = vault::display_name(backend);
    if !vault::can_prompt() {
        return err("unlock_unavailable", format!("{name} is locked and this session cannot prompt for the master password (headless/cron/API). Unlock it from an interactive ark session first."));
    }
    let Some(master) = vault::prompt(&format!("{name} master password"), true) else {
        return err("unlock_cancelled", format!("The user declined to unlock {name}."));
    };
    match vault::unlock(backend, &master) {
        Ok(()) => json!({"success": true, "backend": backend}),
        Err(e) => err("unlock_failed", crate::util::cut(&e, 300)),
    }
}

fn fill(env: &Env, sid: &str, b: &Browser, t: &str, handle: &str) -> Value {
    let backend = vault::backend_of(handle);
    if !vault::is_unlocked(backend) {
        let u = unlock(backend);
        if u["success"] != true {
            return u;
        }
    }
    let item = match vault::get(&env.home, handle) {
        Ok(Some(i)) => i,
        Ok(None) => return json!({"success": false, "error": format!("No vault item with handle {handle:?}. Use browser_vault action=list. To save a credential: run `ark browser vault add` in a terminal.")}),
        Err(e) if e.starts_with("unlock_required") => return err("unlock_required", e),
        Err(e) => return json!({"success": false, "error": e}),
    };
    if item.kind != "login" && item.origin.is_empty() {
        return err("no_origin", format!("Vault item {handle:?} has no bound origin; {} items are filled only on the site they were saved for.", item.kind));
    }
    // Payment fills were approved through the egress gate (the tool declared Effect::Remote).
    let allowed = item.origins();
    let mut origin = None;
    for o in &allowed {
        if let Some(x) = focus_origin(env, sid, b, o, &item.kind) {
            origin = Some(x);
            break;
        }
    }
    let t = crate::manager::global().session(sid).target.unwrap_or_else(|| t.to_string());
    let Some(origin) = origin.or_else(|| page_origin(b, &t)) else {
        return json!({"success": false, "error": "Could not determine the current page origin. Navigate to the login page first."});
    };
    if !allowed.contains(&origin) {
        return err("origin_mismatch", format!("Refused: current page origin ({origin}) does not match the vault item's bound origin(s) ({}). Vault fills only run on the exact origin(s) the credential was saved for.", allowed.join(", ")));
    }
    let nonce = ark_net::crypto::hex(&ark_net::crypto::random_bytes(8));
    let controls = match inspect(b, &t, &nonce) {
        Ok(c) => c,
        Err(e) => return json!({"success": false, "error": e}),
    };
    let classified: Vec<Classified> = controls.iter().filter_map(|c| if item.kind == "login" { vault::classify_login(c) } else { vault::classify_checkout(c) }).collect();
    if classified.is_empty() {
        return json!({"success": false, "error": format!("No {} form fields were found on the current page.", item.kind)});
    }
    let secret = match vault::resolve(&env.home, &item) {
        Ok(s) => s,
        Err(e) if e.starts_with("unlock_required") => return err("unlock_required", e),
        Err(e) => return json!({"success": false, "error": e}),
    };
    let fills = match item.kind.as_str() {
        "login" => vault::select_password(&classified, secret.get("password").map(String::as_str).unwrap_or("")),
        "payment" => vault::select_checkout(&classified, &secret, vault::PAYMENT_FIELDS),
        _ => vault::select_checkout(&classified, &secret, vault::ADDRESS_FIELDS),
    };
    if fills.is_empty() {
        return json!({"success": false, "error": format!("No fillable {} field matched the saved item on this page.", item.kind)});
    }
    match item.kind.as_str() {
        "login" => policy::register_secret(secret.get("password").map(String::as_str).unwrap_or("")),
        "payment" => secret.values().for_each(|v| policy::register_secret(v)),
        _ => {}
    }
    match run_fill(b, &t, &fills, &origin, &nonce, &secret) {
        Ok(n) => {
            let mut o = json!({"success": n > 0, "filled_fields": n, "backend": backend, "kind": item.kind, "origin": origin});
            if item.kind == "login" {
                o["next"] = format!("Submit. If the site then asks for a verification code, call browser_vault action=enter_code with this handle{}", if item.secret.contains_key("totp_secret") || backend != "local" { " (a code will be generated automatically when a seed is stored)." } else { "." }).into();
            } else {
                let mut f: Vec<String> = fills.iter().filter_map(|f| f["token"].as_str().map(str::to_string)).collect();
                f.sort();
                o["fields"] = json!(f);
            }
            o
        }
        Err(e) if e.starts_with("origin_changed") => err("origin_changed", e.trim_start_matches("origin_changed: ").to_string()),
        Err(e) => json!({"success": false, "error": e}),
    }
}

fn save_login(env: &Env, sid: &str, b: &Browser, t: &str, label: &str) -> Value {
    let _ = focus_origin(env, sid, b, "", "login");
    let t = crate::manager::global().session(sid).target.unwrap_or_else(|| t.to_string());
    let Some(origin) = page_origin(b, &t) else {
        return json!({"success": false, "error": "Open the site's login page first; the login is saved for that page's origin."});
    };
    let host = origin.split("://").nth(1).unwrap_or(&origin).to_string();
    if !vault::can_prompt() {
        return err("prompt_unavailable", format!("This session cannot ask the user for a login (headless/cron/API). Tell them to run `ark browser vault add {origin}` in a terminal."));
    }
    let Some(ident) = vault::prompt(&format!("Save a login for {host} — username or email (empty to cancel)"), false) else {
        return err("save_declined", "The user chose not to save a login for this site. Do not ask again this turn.");
    };
    let Some(pw) = vault::prompt(&format!("Password for {ident} on {host}"), true) else {
        return err("save_declined", "The user chose not to save a login for this site. Do not ask again this turn.");
    };
    let it = match vault::add(&env.home, "login", if label.trim().is_empty() { &host } else { label.trim() }, &origin, BTreeMap::from([("identifier".into(), ident.clone()), ("password".into(), pw)])) {
        Ok(i) => i,
        Err(e) => return err("save_failed", crate::util::cut(&e, 200)),
    };
    let filled = fill(env, sid, b, &t, &it.id);
    json!({"success": true, "handle": it.id, "origin": origin, "identifier": it.identifier, "identifier_type": it.identifier_type, "fill": filled, "next": "Type the identifier into the username field if the form has one, then submit."})
}

fn enter_code(env: &Env, sid: &str, b: &Browser, t: &str, handle: &str) -> Value {
    let _ = focus_origin(env, sid, b, "", "otp");
    let t = crate::manager::global().session(sid).target.unwrap_or_else(|| t.to_string());
    let Some(origin) = page_origin(b, &t) else {
        return json!({"success": false, "error": "No page with a code field is open."});
    };
    let site = origin.split("://").nth(1).unwrap_or(&origin).to_string();
    let nonce = ark_net::crypto::hex(&ark_net::crypto::random_bytes(8));
    let controls = inspect(b, &t, &nonce).unwrap_or_default();
    let otp = vault::classify_otp(&controls);
    if otp.is_empty() {
        return err("no_code_field", "No one-time-code field on the current page. If the site wants a passkey, hardware key or an approval tap in an app, tell the user to complete it on their device and wait for the page to move on.");
    }
    let (code, source) = match (!handle.is_empty()).then(|| vault::resolve_otp(&env.home, handle)).flatten() {
        Some(c) => (c, vault::backend_of(handle)),
        None => {
            if !vault::can_prompt() {
                return err("prompt_unavailable", format!("{site} asks for a one-time code and this session cannot ask the user (headless/cron/API). Save an authenticator key for this login so codes can be generated automatically."));
            }
            match vault::prompt(&format!("One-time code for {site}"), true).map(|c| c.replace([' ', '-'], "")).filter(|c| !c.is_empty()) {
                Some(c) => (c, "user"),
                None => return err("code_declined", "The user did not enter a code. Do not ask again this turn."),
            }
        }
    };
    policy::register_secret(&code);
    let fills = vault::otp_fills(&otp, &code);
    let secret = BTreeMap::from([("code".to_string(), code)]);
    match run_fill(b, &t, &fills, &origin, &nonce, &secret) {
        Ok(n) => json!({"success": n > 0, "filled_fields": n, "origin": origin, "source": source, "next": "Submit the form (many sites auto-submit when the last digit lands)."}),
        Err(e) if e.starts_with("origin_changed") => err("origin_changed", "The page navigated before the code could be entered. Nothing was written."),
        Err(e) => json!({"success": false, "error": crate::util::cut(&e, 200)}),
    }
}
