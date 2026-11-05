//! Telegram Mini App for the Control UI (OpenClaw `extensions/telegram/src/miniapp`, MIT).
//!
//! `/controlui` (Telegram DM, numeric owner id only) issues a single-use launch ticket
//! (5 min) and sends a `web_app` button to `<public_url>/tg-miniapp/?channel=<name>#launchTicket=…`.
//! The page posts Telegram's signed `initData` plus the ticket to `/tg-miniapp/auth`, which
//! checks the HMAC (`WebAppData` key over the bot token, ≤ 5 min old), that the user is
//! still an owner, consumes the ticket for that (channel, user), rejects replays of the
//! same `hash`, rate-limits per IP (10/min) and only then hands the page the Control UI
//! URL with the app token in its fragment (ark has a single operator token, no scoped
//! bootstrap tokens). Requires `[surfaces] public_url` to be an https:// URL.

use ark_kernel::config::Config;
use ark_net::httpd::{Request, Response};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

pub const PATH: &str = "/tg-miniapp/";
pub const EXPIRED: &str = "This link expired. Run /controlui again in your bot chat.";
pub const URL_ERROR: &str = "Mini App needs an HTTPS Control UI URL. Set `[surfaces] public_url = \"https://…\"` (e.g. behind Tailscale Serve/Funnel or a reverse proxy), then retry /controlui.";
const TICKET_TTL_MS: u64 = 5 * 60_000;
const TICKET_LIMIT: usize = 1000;
const INIT_DATA_MAX_AGE_MS: u64 = 300_000;
const MAX_BODY: usize = 4096;
const RATE_WINDOW_MS: u64 = 60_000;
const RATE_MAX: u32 = 10;

fn now_ms() -> u64 {
    ark_kernel::event::now_ms()
}

#[derive(Default)]
struct State {
    /// ticket → (channel, user, expires)
    tickets: HashMap<String, (String, String, u64)>,
    /// initData hash → expires
    replay: HashMap<String, u64>,
    /// ip → (window start, count)
    rate: HashMap<String, (u64, u32)>,
}

fn state() -> &'static Mutex<State> {
    static S: OnceLock<Mutex<State>> = OnceLock::new();
    S.get_or_init(Default::default)
}

fn prune_to<V>(m: &mut HashMap<String, V>, max: usize) {
    while m.len() > max {
        let Some(k) = m.keys().next().cloned() else { break };
        m.remove(&k);
    }
}

pub fn issue_ticket(channel: &str, user: &str) -> String {
    let mut s = state().lock().unwrap();
    let t = now_ms();
    s.tickets.retain(|_, v| v.2 > t);
    let ticket = ark_net::crypto::b64url(&ark_net::crypto::random_bytes(32));
    s.tickets.insert(ticket.clone(), (channel.into(), user.into(), t + TICKET_TTL_MS));
    prune_to(&mut s.tickets, TICKET_LIMIT);
    ticket
}

pub fn consume_ticket(ticket: &str, channel: &str, user: &str) -> bool {
    let mut s = state().lock().unwrap();
    let t = now_ms();
    s.tickets.retain(|_, v| v.2 > t);
    match s.tickets.get(ticket) {
        Some((c, u, _)) if c == channel && u == user => {
            s.tickets.remove(ticket);
            true
        }
        _ => false,
    }
}

fn remember_replay(hash: &str, expires: u64) -> bool {
    let mut s = state().lock().unwrap();
    let t = now_ms();
    s.replay.retain(|_, e| *e > t);
    if s.replay.contains_key(hash) {
        return false;
    }
    s.replay.insert(hash.into(), expires);
    prune_to(&mut s.replay, TICKET_LIMIT);
    true
}

fn rate_limited(ip: &str) -> bool {
    let mut s = state().lock().unwrap();
    let t = now_ms();
    s.rate.retain(|_, (start, _)| t - *start < RATE_WINDOW_MS);
    let e = s.rate.entry(ip.into()).or_insert((t, 0));
    e.1 += 1;
    let limited = e.1 > RATE_MAX;
    prune_to(&mut s.rate, 4096);
    limited
}

pub struct InitData {
    pub hash: String,
    pub auth_date_ms: u64,
    pub user_id: String,
}

/// Telegram WebApp `initData` validation (core.telegram.org/bots/webapps#validating-data).
pub fn validate_init_data(init_data: &str, bot_token: &str, now: u64) -> Option<InitData> {
    let (init_data, bot_token) = (init_data.trim(), bot_token.trim());
    if init_data.is_empty() || bot_token.is_empty() {
        return None;
    }
    let pairs = ark_net::parse_query(init_data);
    let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.trim().to_string()).filter(|v| !v.is_empty());
    let (hash, auth, user) = (get("hash")?, get("auth_date")?, get("user")?);
    let secs: u64 = auth.parse().ok().filter(|s| *s > 0)?;
    let auth_ms = secs * 1000;
    if auth_ms > now || now - auth_ms > INIT_DATA_MAX_AGE_MS {
        return None;
    }
    let mut lines: Vec<String> = pairs.iter().filter(|(k, _)| k != "hash").map(|(k, v)| format!("{k}={v}")).collect();
    lines.sort();
    let secret = ark_net::crypto::hmac_sha256(b"WebAppData", bot_token.as_bytes());
    let computed = ark_net::crypto::hex(&ark_net::crypto::hmac_sha256(&secret, lines.join("\n").as_bytes()));
    if !ark_net::crypto::ct_eq(computed.as_bytes(), hash.to_ascii_lowercase().as_bytes()) {
        return None;
    }
    let u: Value = serde_json::from_str(&user).ok()?;
    let id = match &u["id"] {
        Value::Number(n) => n.as_u64().filter(|i| *i > 0).map(|i| i.to_string()),
        Value::String(s) if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) => Some(s.clone()),
        _ => None,
    }?;
    Some(InitData { hash, auth_date_ms: auth_ms, user_id: id })
}

/// Numeric Telegram ids listed in the channel's `allow` / `allow_admin_from` (wildcards and
/// usernames never grant Control UI access).
pub fn is_owner(channel: &toml::Table, user: &str) -> bool {
    if user.is_empty() || !user.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    ["allow_admin_from", "allow"].iter().any(|k| {
        channel.get(*k).and_then(|v| v.as_array()).is_some_and(|a| a.iter().any(|x| x.as_str().map(|s| s.trim().trim_start_matches("telegram:").to_string()).or_else(|| x.as_integer().map(|i| i.to_string())).as_deref() == Some(user)))
    })
}

/// `https://host[/base]` from `[surfaces] public_url`.
pub fn public_base(cfg: &Config) -> Result<String, String> {
    let u = cfg.surfaces.get("public_url").and_then(|v| v.as_str()).unwrap_or("").trim().trim_end_matches('/').to_string();
    if !u.starts_with("https://") || u.len() <= "https://".len() {
        return Err(URL_ERROR.into());
    }
    Ok(u)
}

pub fn page_url(cfg: &Config, channel: &str, ticket: &str) -> Result<String, String> {
    Ok(format!("{}{PATH}?channel={}#launchTicket={}", public_base(cfg)?, ark_net::urlencode(channel), ark_net::urlencode(ticket)))
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub fn render_page(channel: &str, nonce: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>ark</title>
<style>:root{{color-scheme:light dark;font-family:system-ui,sans-serif}}body{{margin:0;min-height:100vh;display:grid;place-items:center;background:Canvas;color:CanvasText}}main{{width:min(28rem,calc(100vw - 2rem))}}h1{{font-size:1.25rem;margin:0 0 .5rem}}p{{margin:0;line-height:1.5}}</style>
<script src="https://telegram.org/js/telegram-web-app.js"></script></head>
<body><main><h1>ark</h1><p id="status">Opening Control UI...</p></main>
<script nonce="{nonce}">
const channel = {ch};
const launchTicket = new URLSearchParams(location.hash.slice(1)).get("launchTicket") || "";
const status = document.getElementById("status");
const showExpired = () => {{ status.textContent = {expired}; }};
const webApp = window.Telegram && window.Telegram.WebApp;
const initData = webApp && typeof webApp.initData === "string" ? webApp.initData : "";
if (!initData || !launchTicket) {{ showExpired(); }} else {{
  webApp.ready();
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 15000);
  fetch("auth", {{ method: "POST", headers: {{ "content-type": "application/json" }}, body: JSON.stringify({{ initData, channel, launchTicket }}), credentials: "same-origin", signal: ctl.signal }})
    .then(async (r) => {{ if (!r.ok) throw new Error("auth failed"); return await r.json(); }})
    .then((p) => {{ const next = new URL(p.controlUiUrl); next.hash = "token=" + encodeURIComponent(p.token); location.replace(next.toString()); }})
    .catch(showExpired).then(() => clearTimeout(timer));
}}
</script></body></html>"#,
        nonce = esc(nonce),
        ch = serde_json::to_string(channel).unwrap_or_default().replace('<', "\\u003c"),
        expired = serde_json::to_string(EXPIRED).unwrap_or_default(),
    )
}

fn send(status: u16, body: &str, ctype: &str) -> Response {
    Response::new(status, &format!("{ctype}; charset=utf-8"), body.as_bytes().to_vec()).with_header("cache-control", "no-store").with_header("referrer-policy", "no-referrer").with_header("x-robots-tag", "noindex")
}

/// What the routes need from the host: current config, the vault substitution for the
/// bot token, and the app token handed to authenticated owners.
pub struct Env {
    pub config: Arc<dyn Fn() -> Config + Send + Sync>,
    pub secrets: Arc<dyn Fn(&str) -> String + Send + Sync>,
    pub app_token: String,
}

pub fn handle(env: &Env, r: &Request) -> Response {
    let sub = r.path.strip_prefix(PATH.trim_end_matches('/')).unwrap_or("");
    match sub {
        "" | "/" => {
            if r.method != "GET" {
                return send(405, "Method not allowed", "text/plain");
            }
            let channel = r.query("channel").unwrap_or("telegram").to_string();
            let nonce = ark_net::crypto::random_token(16);
            send(200, &render_page(&channel, &nonce), "text/html").with_header("content-security-policy", &format!("default-src 'none'; script-src 'nonce-{nonce}' https://telegram.org; connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"))
        }
        "/auth" => auth(env, r),
        _ => send(404, "Not found", "text/plain"),
    }
}

fn auth(env: &Env, r: &Request) -> Response {
    if r.method != "POST" {
        return send(405, "Method not allowed", "text/plain");
    }
    if !r.header("content-type").unwrap_or("").split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/json") {
        return send(415, "Unsupported media type", "text/plain");
    }
    let ip = r.peer.map(|p| p.ip().to_string()).unwrap_or_else(|| "unknown".into());
    if rate_limited(&ip) {
        return send(429, "Too many requests", "text/plain");
    }
    if r.body.len() > MAX_BODY {
        return send(413, "Payload too large", "text/plain");
    }
    let Ok(body) = serde_json::from_slice::<Value>(&r.body) else { return send(401, EXPIRED, "text/plain") };
    let (Some(init), Some(ticket)) = (body["initData"].as_str(), body["launchTicket"].as_str()) else { return send(401, EXPIRED, "text/plain") };
    let channel = body["channel"].as_str().unwrap_or("telegram").to_string();
    let cfg = (env.config)();
    let Some(ch) = cfg.channels.get(&channel).filter(|c| c.get("kind").and_then(|k| k.as_str()).unwrap_or(&channel) == "telegram") else { return send(401, EXPIRED, "text/plain") };
    let token = (env.secrets)(ch.get("token").and_then(|t| t.as_str()).unwrap_or(""));
    let Some(v) = validate_init_data(init, &token, now_ms()) else { return send(401, EXPIRED, "text/plain") };
    if !is_owner(ch, &v.user_id) {
        return send(403, "Restricted to the bot owner.", "text/plain");
    }
    let Ok(base) = public_base(&cfg) else { return send(503, URL_ERROR, "text/plain") };
    if !consume_ticket(ticket, &channel, &v.user_id) || !remember_replay(&v.hash, v.auth_date_ms + INIT_DATA_MAX_AGE_MS) {
        return send(401, EXPIRED, "text/plain");
    }
    if env.app_token.is_empty() {
        return send(503, "the app server has no token configured", "text/plain");
    }
    send(200, &json!({"token": env.app_token, "controlUiUrl": format!("{base}/"), "gatewayUrl": format!("{}/arp", base.replacen("https://", "wss://", 1))}).to_string(), "application/json")
}

/// Host environment reading the config and vault fresh on every request.
pub fn env(paths: &ark_kernel::config::Paths, ws: &std::path::Path, app_token: &str) -> Env {
    let (p, w) = (paths.clone(), ws.to_path_buf());
    let p2 = paths.clone();
    Env {
        config: Arc::new(move || Config::load(Some(&p.user_config()), Some(&ark_kernel::config::project_config(&w)), &[]).unwrap_or_default()),
        secrets: Arc::new(move |s: &str| ark_kernel::vault::Vault::load(&p2.secrets()).map(|v| v.substitute(s)).unwrap_or_else(|_| s.to_string())),
        app_token: app_token.to_string(),
    }
}

/// The route for `ark_app::App.routes` (served before the app-token check).
pub fn routes(env: Arc<Env>) -> Vec<(String, ark_net::httpd::Handler)> {
    let h: ark_net::httpd::Handler = Arc::new(move |r: Request| handle(&env, &r));
    vec![(PATH.trim_end_matches('/').to_string(), h)]
}

#[cfg(test)]
pub(crate) fn signed_init_data(token: &str, user: &str, auth_s: u64) -> String {
    let user_json = format!("{{\"id\":{user},\"first_name\":\"A\"}}");
    let fields = [("auth_date", auth_s.to_string()), ("query_id", "AAH".to_string()), ("user", user_json.clone())];
    let mut lines: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
    lines.sort();
    let secret = ark_net::crypto::hmac_sha256(b"WebAppData", token.as_bytes());
    let hash = ark_net::crypto::hex(&ark_net::crypto::hmac_sha256(&secret, lines.join("\n").as_bytes()));
    format!("auth_date={auth_s}&query_id=AAH&user={}&hash={hash}", ark_net::urlencode(&user_json))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        let mut c = Config::default();
        c.surfaces.insert("public_url".into(), toml::Value::String("https://ark.example.ts.net".into()));
        let ch: toml::Table = "kind = \"telegram\"\ntoken = \"{{secret:TG}}\"\nallow = [\"42\", \"*\", \"@bob\"]\n".parse().unwrap();
        c.channels.insert("tg".into(), ch);
        c
    }

    fn req(method: &str, path: &str, body: &str) -> Request {
        Request { method: method.into(), path: path.into(), query: vec![], raw_query: String::new(), headers: vec![("content-type".into(), "application/json".into())], body: body.as_bytes().to_vec(), peer: Some("10.9.9.9:1".parse().unwrap()), head: String::new() }
    }

    #[test]
    fn init_data_validation_follows_telegram_rules() {
        let now = 1_800_000_000_000;
        let d = signed_init_data("123:ABC", "42", now / 1000 - 10);
        let v = validate_init_data(&d, "123:ABC", now).unwrap();
        assert_eq!(v.user_id, "42");
        assert!(validate_init_data(&d, "123:XYZ", now).is_none(), "wrong bot token");
        assert!(validate_init_data(&d, "123:ABC", now + 400_000).is_none(), "too old");
        assert!(validate_init_data(&d.replace("query_id=AAH", "query_id=AAX"), "123:ABC", now).is_none(), "tampered");
        assert!(validate_init_data("", "123:ABC", now).is_none());
    }

    #[test]
    fn owner_rules_and_urls() {
        let c = cfg();
        let ch = &c.channels["tg"];
        assert!(is_owner(ch, "42"));
        assert!(!is_owner(ch, "43"), "wildcards never grant access");
        assert!(!is_owner(ch, "bob"));
        let url = page_url(&c, "tg", "tk").unwrap();
        assert_eq!(url, "https://ark.example.ts.net/tg-miniapp/?channel=tg#launchTicket=tk");
        let mut plain = Config::default();
        plain.surfaces.insert("public_url".into(), toml::Value::String("http://lan:8640".into()));
        assert_eq!(public_base(&plain).unwrap_err(), URL_ERROR);
    }

    #[test]
    fn auth_route_consumes_ticket_once_and_hands_off_token() {
        let env = Env { config: Arc::new(cfg), secrets: Arc::new(|s: &str| s.replace("{{secret:TG}}", "123:ABC")), app_token: "app-tok".into() };
        let page = handle(&env, &req("GET", "/tg-miniapp/", ""));
        assert_eq!(page.status, 200);
        assert!(page.headers.iter().any(|(k, v)| k == "content-security-policy" && v.contains("script-src 'nonce-")));
        let ticket = issue_ticket("tg", "42");
        let now_s = now_ms() / 1000;
        let body = json!({"initData": signed_init_data("123:ABC", "42", now_s), "channel": "tg", "launchTicket": ticket}).to_string();
        let r = handle(&env, &req("POST", "/tg-miniapp/auth", &body));
        assert_eq!(r.status, 200);
        let v: Value = match &r.body {
            ark_net::httpd::Body::Bytes(b) => serde_json::from_slice(b).unwrap(),
            _ => panic!("body"),
        };
        assert_eq!((v["token"].as_str(), v["controlUiUrl"].as_str()), (Some("app-tok"), Some("https://ark.example.ts.net/")));
        // Same ticket / same initData again: refused.
        assert_eq!(handle(&env, &req("POST", "/tg-miniapp/auth", &body)).status, 401);
        // Non-owner with a valid signature.
        let t2 = issue_ticket("tg", "43");
        let b2 = json!({"initData": signed_init_data("123:ABC", "43", now_s), "channel": "tg", "launchTicket": t2}).to_string();
        assert_eq!(handle(&env, &req("POST", "/tg-miniapp/auth", &b2)).status, 403);
        // A ticket issued for someone else does not work.
        let t3 = issue_ticket("tg", "7");
        let b3 = json!({"initData": signed_init_data("123:ABC", "42", now_s - 1), "channel": "tg", "launchTicket": t3}).to_string();
        assert_eq!(handle(&env, &req("POST", "/tg-miniapp/auth", &b3)).status, 401);
        let mut wrong = req("POST", "/tg-miniapp/auth", &b3);
        wrong.headers = vec![("content-type".into(), "text/plain".into())];
        assert_eq!(handle(&env, &wrong).status, 415);
    }
}
