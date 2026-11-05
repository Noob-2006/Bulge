//! Cloud browser providers (Hermes `plugins/browser/*`, MIT): create a remote
//! Chromium session over the provider's REST API, drive it over the returned CDP
//! WebSocket, release it when done.
//! - Browserbase: POST /v1/sessions (402 → drop keepAlive, then proxies), release with REQUEST_RELEASE.
//! - Browser Use: POST /browsers, stop with PATCH {action: stop}.
//! - Firecrawl: POST /v2/browser {ttl}, DELETE to release.

use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct CloudSession {
    pub provider: String,
    pub id: String,
    pub cdp_url: String,
    pub features: Value,
    /// Provider-authoritative deadline (Browser Use `timeoutAt`); the session is retired past it.
    pub expires_at: Option<String>,
    /// `ark_<task>_<hex8>` (Hermes `hermes_<task>_<hex8>`).
    pub session_name: String,
    base: String,
    key: String,
    project: String,
}

/// Look up a credential: environment first, then the ark vault (`{{secret:NAME}}`).
pub type Secrets<'a> = &'a dyn Fn(&str) -> String;

impl CloudSession {
    /// Metadata-only construction for a registered backend: `base` / `key` / `project` stay empty
    /// because the provider's own `close` / `cleanup` handle teardown. `session_name` follows
    /// `ark_<task>_<hex8>` (see `session_name`), `features` is the provider's flag object.
    pub fn new(provider: &str, id: &str, cdp_url: &str, features: Value, expires_at: Option<String>, session_name: &str) -> CloudSession {
        CloudSession { provider: provider.into(), id: id.into(), cdp_url: cdp_url.into(), features, expires_at, session_name: session_name.into(), base: String::new(), key: String::new(), project: String::new() }
    }
}

pub fn secret(secrets: Secrets, name: &str) -> Option<String> {
    if let Ok(v) = std::env::var(name) {
        if !v.trim().is_empty() {
            return Some(v.trim().to_string());
        }
    }
    let ph = format!("{{{{secret:{name}}}}}");
    let v = secrets(&ph);
    (v != ph && !v.trim().is_empty()).then(|| v.trim().to_string())
}

/// Display label (Hermes provider `label`).
pub fn label(provider: &str) -> &'static str {
    match provider {
        "browserbase" => "Browserbase",
        "browser-use" => "Browser Use",
        "firecrawl" => "Firecrawl",
        _ => "Cloud browser",
    }
}

fn send(method: &str, url: &str, headers: &[(&str, &str)], body: Option<&Value>, label: &str, timeout: Duration) -> Result<(u16, Value, Option<String>), String> {
    let a: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(timeout)).http_status_as_error(false).build().into();
    let mut r = match (method, body) {
        ("GET", _) | ("DELETE", None) => {
            let mut q = if method == "GET" { a.get(url) } else { a.delete(url) };
            for (k, v) in headers {
                q = q.header(*k, *v);
            }
            q.call()
        }
        _ => {
            let mut q = match method {
                "PATCH" => a.patch(url),
                "DELETE" => a.delete(url).force_send_body(),
                _ => a.post(url),
            };
            for (k, v) in headers {
                q = q.header(*k, *v);
            }
            q.header("Content-Type", "application/json").send(body.map(|b| b.to_string()).unwrap_or_else(|| "{}".into()))
        }
    }
    .map_err(|e| format!("{label} API connection failed: {e}"))?;
    let status = r.status().as_u16();
    let ext = r.headers().get("x-external-call-id").and_then(|h| h.to_str().ok()).map(str::to_string);
    let text = r.body_mut().read_to_string().unwrap_or_default();
    Ok((status, serde_json::from_str(&text).unwrap_or(Value::String(text)), ext))
}

/// Hermes reads these with `os.environ.get(X, default).lower() != "false"` / `== "true"`.
fn env_flag(name: &str, default: bool) -> bool {
    match std::env::var(name).ok().map(|v| v.trim().to_ascii_lowercase()) {
        Some(v) if default => v != "false",
        Some(v) => v == "true",
        None => default,
    }
}

fn base_url(secrets: Secrets, name: &str, default: &str) -> String {
    secret(secrets, name).unwrap_or_else(|| default.into()).trim_end_matches('/').to_string()
}

pub fn available(provider: &str, secrets: Secrets) -> bool {
    match provider {
        "browserbase" => secret(secrets, "BROWSERBASE_API_KEY").is_some() && secret(secrets, "BROWSERBASE_PROJECT_ID").is_some(),
        "browser-use" => secret(secrets, "BROWSER_USE_API_KEY").is_some(),
        "firecrawl" => secret(secrets, "FIRECRAWL_API_KEY").is_some(),
        other => registered_provider(other).map(|p| p.available(secrets)).unwrap_or(false),
    }
}

/// Auto-detect order when `cloud_provider` is unset (Hermes `_LEGACY_PREFERENCE`): Browser Use,
/// then Browserbase. Firecrawl shares its key with web extract and is never auto-selected.
pub fn autodetect(secrets: Secrets) -> Option<&'static str> {
    ["browser-use", "browserbase"].into_iter().find(|p| available(p, secrets))
}

// ── runtime registration (Hermes `PluginContext.register_browser_provider`) ────────────────────

/// A cloud browser backend supplied at runtime by a plugin (Hermes `agent/browser_provider.py`
/// `register_browser_provider()`; shipped backends live in `plugins/browser/<name>/`). Bundled
/// names are reserved and always win, and `autodetect()` keeps walking only the bundled order, so a
/// registered backend services calls only when config names it (`browser.cloud_provider = "<id>"`).
///
/// Session metadata contract (Hermes `CloudBrowserProvider` shape, no translation): `create`
/// returns a `CloudSession` whose `session_name` is the agent-browser session name, `id` the
/// provider session id (used by `close` / `cleanup`), `cdp_url` the CDP websocket, `expires_at` the
/// provider-authoritative deadline (if any) and `features` the enabled-flag object.
pub trait CloudProvider: Send + Sync {
    /// Config id (`browser.cloud_provider = "<id>"`).
    fn id(&self) -> &str;
    fn label(&self) -> String;
    /// Cheap credential check (no network); runs at registration/selection time.
    fn available(&self, secrets: Secrets<'_>) -> bool;
    /// Create a session for ark session `task` (Hermes `create_session`).
    fn create(&self, secrets: Secrets<'_>, task: &str) -> Result<CloudSession, String>;
    /// Release the session `session` (Hermes `close_session`): true on success.
    fn close(&self, secrets: Secrets<'_>, session: &str) -> bool;
    /// Shutdown path (Hermes `emergency_cleanup`): one best-effort release, errors ignored.
    fn cleanup(&self, secrets: Secrets<'_>, session: &str);
}

/// Reserved names: the bundled ids plus the spellings Hermes accepts for them.
const BUNDLED: [&str; 4] = ["browserbase", "browser-use", "browser_use", "firecrawl"];

fn registry() -> &'static std::sync::RwLock<Vec<std::sync::Arc<dyn CloudProvider>>> {
    static REG: std::sync::OnceLock<std::sync::RwLock<Vec<std::sync::Arc<dyn CloudProvider>>>> = std::sync::OnceLock::new();
    REG.get_or_init(|| std::sync::RwLock::new(Vec::new()))
}

/// Register a cloud browser backend at runtime; the last registration for an id wins.
pub fn register(p: std::sync::Arc<dyn CloudProvider>) -> Result<(), String> {
    let id = p.id().trim().to_ascii_lowercase();
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
        return Err(format!("invalid cloud browser provider id `{}`: expected a non-empty trimmed id matching [a-z0-9_-]", p.id()));
    }
    if BUNDLED.contains(&id.as_str()) {
        return Err(format!("cloud browser provider `{id}` is the bundled name of a shipped backend; bundled ids and aliases cannot be registered"));
    }
    let mut reg = registry().write().unwrap_or_else(|e| e.into_inner());
    reg.retain(|q| !q.id().trim().eq_ignore_ascii_case(&id));
    reg.push(p);
    Ok(())
}

/// Backends registered at runtime, in registration order. Never part of `autodetect()`.
pub fn registered() -> Vec<std::sync::Arc<dyn CloudProvider>> {
    registry().read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Registry lookup by id (case-insensitive); bundled names are not in it.
fn registered_provider(provider: &str) -> Option<std::sync::Arc<dyn CloudProvider>> {
    let id = provider.trim();
    registered().into_iter().find(|p| p.id().trim().eq_ignore_ascii_case(id))
}

/// No secrets are threaded through `release` / `emergency_release`: a registered backend correlates
/// `session` with its own state, since the id came back from its `create`.
fn no_secrets(_: &str) -> String {
    String::new()
}

fn bundled(provider: &str) -> bool {
    matches!(provider, "browserbase" | "browser-use" | "firecrawl")
}

/// `ark_<task>_<hex8>`: the agent-browser session name for an ark session (`task`).
pub fn session_name(task: &str) -> String {
    let t: String = task.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')).take(32).collect();
    format!("ark_{t}_{}", ark_net::crypto::hex(&ark_net::crypto::random_bytes(4)))
}

fn failed(provider: &str, st: u16, v: &Value) -> String {
    let suffix = if provider == "firecrawl" { " browser" } else { "" };
    format!("Failed to create {}{suffix} session: {st} {}", label(provider), short(v))
}

/// Create a session for ark session `task` (Hermes `create_session`).
pub fn create(provider: &str, secrets: Secrets, task: &str) -> Result<CloudSession, String> {
    if !bundled(provider) {
        if let Some(p) = registered_provider(provider) {
            return p.create(secrets, task);
        }
    }
    let name = session_name(task);
    match provider {
        "browserbase" => {
            let (Some(key), Some(project)) = (secret(secrets, "BROWSERBASE_API_KEY"), secret(secrets, "BROWSERBASE_PROJECT_ID")) else {
                return Err("Browserbase requires BROWSERBASE_API_KEY and BROWSERBASE_PROJECT_ID environment variables.".into());
            };
            let base = base_url(secrets, "BROWSERBASE_BASE_URL", "https://api.browserbase.com");
            let keep_alive = env_flag("BROWSERBASE_KEEP_ALIVE", true);
            let proxies = env_flag("BROWSERBASE_PROXIES", true);
            let stealth = env_flag("BROWSERBASE_ADVANCED_STEALTH", false);
            // Invalid or non-positive BROWSERBASE_SESSION_TIMEOUT is ignored (Hermes logs a warning).
            let timeout = std::env::var("BROWSERBASE_SESSION_TIMEOUT").ok().and_then(|v| v.trim().parse::<i64>().ok()).filter(|v| *v > 0);
            let mut body = json!({"projectId": project});
            if keep_alive {
                body["keepAlive"] = true.into();
            }
            if let Some(t) = timeout {
                body["timeout"] = t.into();
            }
            if proxies {
                body["proxies"] = true.into();
            }
            if stealth {
                body["browserSettings"] = json!({"advancedStealth": true});
            }
            let url = format!("{base}/v1/sessions");
            let post = |b: &Value| send("POST", &url, &[("X-BB-API-Key", &key)], Some(b), "Browserbase", Duration::from_secs(30));
            let (mut st, mut v, _) = post(&body)?;
            // 402 = paid feature: drop keepAlive, then proxies, retrying once each (in that order).
            let mut dropped = vec![];
            for k in ["keepAlive", "proxies"] {
                if st == 402 && body.get(k).is_some() {
                    body.as_object_mut().unwrap().remove(k);
                    dropped.push(k);
                    (st, v, _) = post(&body)?;
                }
            }
            if !(200..300).contains(&st) {
                return Err(failed(provider, st, &v));
            }
            Ok(CloudSession {
                provider: provider.into(),
                id: v["id"].as_str().ok_or("Browserbase response has no session id")?.into(),
                cdp_url: v["connectUrl"].as_str().ok_or("Browserbase response has no connectUrl")?.into(),
                features: json!({"basic_stealth": true, "proxies": proxies && !dropped.contains(&"proxies"), "advanced_stealth": stealth, "keep_alive": keep_alive && !dropped.contains(&"keepAlive"), "custom_timeout": timeout.is_some()}),
                expires_at: None,
                session_name: name,
                base,
                key,
                project,
            })
        }
        "browser-use" => {
            // Direct key only: the managed Nous Tool Gateway lane is a Nous-subscription service.
            let key = secret(secrets, "BROWSER_USE_API_KEY").ok_or("Browser Use requires a direct BROWSER_USE_API_KEY credential.")?;
            let base = base_url(secrets, "BROWSER_USE_BASE_URL", "https://api.browser-use.com/api/v3");
            let (st, v, _) = send("POST", &format!("{base}/browsers"), &[("X-Browser-Use-API-Key", &key)], Some(&json!({})), "Browser Use", Duration::from_secs(30))?;
            if !(200..300).contains(&st) {
                return Err(failed(provider, st, &v));
            }
            let cdp = v["cdpUrl"].as_str().filter(|s| !s.is_empty()).or(v["connectUrl"].as_str()).unwrap_or("");
            Ok(CloudSession { provider: provider.into(), id: v["id"].as_str().ok_or("Browser Use response has no session id")?.into(), cdp_url: cdp.into(), features: json!({"browser_use": true}), expires_at: v["timeoutAt"].as_str().map(str::to_string), session_name: name, base, key, project: String::new() })
        }
        "firecrawl" => {
            let key = secret(secrets, "FIRECRAWL_API_KEY").ok_or("FIRECRAWL_API_KEY environment variable is required. Get your key at https://firecrawl.dev")?;
            let base = base_url(secrets, "FIRECRAWL_API_URL", "https://api.firecrawl.dev");
            let ttl = std::env::var("FIRECRAWL_BROWSER_TTL").ok().and_then(|v| v.trim().parse::<i64>().ok()).unwrap_or(300);
            let auth = format!("Bearer {key}");
            let (st, v, _) = send("POST", &format!("{base}/v2/browser"), &[("Authorization", &auth)], Some(&json!({"ttl": ttl})), "Firecrawl", Duration::from_secs(30))?;
            if !(200..300).contains(&st) {
                return Err(failed(provider, st, &v));
            }
            Ok(CloudSession { provider: provider.into(), id: v["id"].as_str().ok_or("Firecrawl response has no session id")?.into(), cdp_url: v["cdpUrl"].as_str().ok_or("Firecrawl response has no cdpUrl")?.into(), features: json!({"firecrawl": true}), expires_at: None, session_name: name, base, key, project: String::new() })
        }
        other => Err(format!("unknown cloud browser provider `{other}` (browserbase, browser-use, firecrawl)")),
    }
}

fn short(v: &Value) -> String {
    let t = match v {
        Value::String(s) => s.clone(),
        v => v.to_string(),
    };
    crate::util::cut(&crate::policy::redact(&t), 300).to_string()
}

fn release_with(s: &CloudSession, t: Duration) -> Result<u16, String> {
    let r = match s.provider.as_str() {
        "browserbase" => send("POST", &format!("{}/v1/sessions/{}", s.base, s.id), &[("X-BB-API-Key", &s.key)], Some(&json!({"projectId": s.project, "status": "REQUEST_RELEASE"})), "Browserbase", t),
        "browser-use" => send("PATCH", &format!("{}/browsers/{}", s.base, s.id), &[("X-Browser-Use-API-Key", &s.key)], Some(&json!({"action": "stop"})), "Browser Use", t),
        "firecrawl" => send("DELETE", &format!("{}/v2/browser/{}", s.base, s.id), &[("Authorization", &format!("Bearer {}", s.key))], None, "Firecrawl", t),
        p => return Err(format!("unknown provider {p}")),
    };
    r.map(|(st, _, _)| st)
}

/// Release a cloud session (Hermes `close_session`: 10 s, success on 200/201/204). A session from a
/// registered backend is closed through its own `close`.
pub fn release(s: &CloudSession) -> bool {
    if let Some(p) = registered_provider(&s.provider) {
        let ok = p.close(&no_secrets, &s.id);
        if !ok {
            eprintln!("ark-browser: failed to close {} session {}", p.label(), s.id);
        }
        return ok;
    }
    release_bundled(s, Duration::from_secs(10))
}

fn release_bundled(s: &CloudSession, t: Duration) -> bool {
    match release_with(s, t) {
        Ok(200 | 201 | 204) => true,
        Ok(st) => {
            eprintln!("ark-browser: failed to close {} session {}: HTTP {st}", label(&s.provider), s.id);
            false
        }
        Err(e) => {
            eprintln!("ark-browser: exception closing {} session {}: {e}", label(&s.provider), s.id);
            false
        }
    }
}

/// Release a session by name, for callers that no longer hold the `CloudSession` (a registered
/// backend closes through its own `close`; bundled ones rebuild the release call from `secrets`).
pub fn close(provider: &str, secrets: Secrets, session: &str) -> bool {
    if let Some(p) = registered_provider(provider) {
        return p.close(secrets, session);
    }
    match named_session(provider, secrets, session) {
        Some(s) => release_bundled(&s, Duration::from_secs(10)),
        None => {
            eprintln!("ark-browser: cannot close {provider} session {session}: unknown provider or missing credential");
            false
        }
    }
}

/// Best-effort release by name for the shutdown path (Hermes `emergency_cleanup`).
pub fn cleanup(provider: &str, secrets: Secrets, session: &str) {
    if let Some(p) = registered_provider(provider) {
        p.cleanup(secrets, session);
        return;
    }
    if let Some(s) = named_session(provider, secrets, session) {
        let _ = release_with(&s, Duration::from_secs(5));
    }
}

/// A `CloudSession` rebuilt from config/secrets + a session id, for `close` / `cleanup`.
fn named_session(provider: &str, secrets: Secrets, session: &str) -> Option<CloudSession> {
    let (base, key, project) = match provider {
        "browserbase" => (base_url(secrets, "BROWSERBASE_BASE_URL", "https://api.browserbase.com"), secret(secrets, "BROWSERBASE_API_KEY")?, secret(secrets, "BROWSERBASE_PROJECT_ID").unwrap_or_default()),
        "browser-use" => (base_url(secrets, "BROWSER_USE_BASE_URL", "https://api.browser-use.com/api/v3"), secret(secrets, "BROWSER_USE_API_KEY")?, String::new()),
        "firecrawl" => (base_url(secrets, "FIRECRAWL_API_URL", "https://api.firecrawl.dev"), secret(secrets, "FIRECRAWL_API_KEY")?, String::new()),
        _ => return None,
    };
    Some(CloudSession { provider: provider.into(), id: session.into(), cdp_url: String::new(), features: Value::Null, expires_at: None, session_name: String::new(), base, key, project })
}

/// Shutdown path (Hermes `emergency_cleanup`): one 5 s attempt, errors ignored.
pub fn emergency_release(s: &CloudSession) {
    if let Some(p) = registered_provider(&s.provider) {
        p.cleanup(&no_secrets, &s.id);
        return;
    }
    let _ = release_with(s, Duration::from_secs(5));
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// Requests the fake server saw: (method, path, headers, body).
    pub type Seen = Arc<Mutex<Vec<(String, String, String, String)>>>;

    /// Minimal HTTP server: records (method, path, headers, body) and answers from `reply`.
    pub fn http_fake(reply: impl Fn(&str, &str, &str) -> (u16, String) + Send + Sync + 'static) -> (String, Seen) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        let reply = Arc::new(reply);
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(mut c) = c else { break };
                let (head, mut rest) = ark_net::ws::read_head(&mut c, 1 << 16).unwrap();
                let len: usize = ark_net::ws::header(&head, "content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
                while rest.len() < len {
                    let mut b = [0u8; 4096];
                    let n = c.read(&mut b).unwrap();
                    if n == 0 {
                        break;
                    }
                    rest.extend_from_slice(&b[..n]);
                }
                let mut parts = head.split_whitespace();
                let (m, p) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string());
                let body = String::from_utf8_lossy(&rest).into_owned();
                s2.lock().unwrap().push((m.clone(), p.clone(), head.clone(), body.clone()));
                let (st, out) = reply(&m, &p, &body);
                let ctype = if out.starts_with('{') || out.starts_with('[') { "application/json" } else { "application/octet-stream" };
                let _ = write!(c, "HTTP/1.1 {st} X\r\ncontent-type: {ctype}\r\nx-external-call-id: call-1\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}", out.len());
            }
        });
        (base, seen)
    }

    #[test]
    fn browserbase_retries_402_and_releases() {
        let (base, seen) = http_fake(|m, _p, body| {
            if m == "POST" && body.contains("keepAlive") {
                (402, "{\"error\":\"plan\"}".into())
            } else if m == "POST" && body.contains("REQUEST_RELEASE") {
                (200, "{}".into())
            } else {
                (201, "{\"id\":\"bb1\",\"connectUrl\":\"wss://connect.example/?apiKey=x\"}".into())
            }
        });
        std::env::set_var("BROWSERBASE_BASE_URL", &base);
        let secrets = |s: &str| s.replace("{{secret:BROWSERBASE_API_KEY}}", "bb_key").replace("{{secret:BROWSERBASE_PROJECT_ID}}", "proj");
        assert!(available("browserbase", &secrets));
        let s = create("browserbase", &secrets, "").unwrap();
        assert_eq!((s.id.as_str(), s.features["keep_alive"].as_bool()), ("bb1", Some(false)));
        assert!(release(&s));
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 3);
        assert!(seen[0].2.to_ascii_lowercase().contains("x-bb-api-key: bb_key") && seen[1].3.contains("\"projectId\":\"proj\"") && !seen[1].3.contains("keepAlive"));
        assert_eq!(seen[2].1, "/v1/sessions/bb1");
        std::env::remove_var("BROWSERBASE_BASE_URL");
    }

    #[test]
    fn browser_use_and_firecrawl() {
        let (base, seen) = http_fake(|m, p, _| match (m, p) {
            ("POST", "/browsers") => (200, "{\"id\":\"bu1\",\"cdpUrl\":\"wss://bu.example/x\",\"timeoutAt\":\"2030-01-01T00:00:00Z\"}".into()),
            ("PATCH", _) => (200, "{}".into()),
            ("POST", "/v2/browser") => (200, "{\"id\":\"fc1\",\"cdpUrl\":\"wss://fc.example/x\"}".into()),
            ("DELETE", _) => (204, String::new()),
            _ => (404, "{}".into()),
        });
        std::env::set_var("BROWSER_USE_BASE_URL", &base);
        std::env::set_var("FIRECRAWL_API_URL", &base);
        let secrets = |s: &str| s.replace("{{secret:BROWSER_USE_API_KEY}}", "bu").replace("{{secret:FIRECRAWL_API_KEY}}", "fc");
        let s = create("browser-use", &secrets, "").unwrap();
        assert_eq!((s.cdp_url.as_str(), s.features["external_call_id"].as_str(), s.expires_at.as_deref()), ("wss://bu.example/x", None, Some("2030-01-01T00:00:00Z")));
        // Hermes records x-external-call-id only on the managed (Nous gateway) lane; direct keys never do.
        assert!(release(&s));
        let f = create("firecrawl", &secrets, "").unwrap();
        assert!(release(&f));
        let seen = seen.lock().unwrap();
        assert!(seen[1].3.contains("\"action\":\"stop\"") && seen[2].3.contains("\"ttl\":300") && seen[2].2.contains("Bearer fc"));
        assert_eq!(seen[3].1, "/v2/browser/fc1");
        assert!(create("firecrawl", &|s: &str| s.to_string(), "").is_err() || std::env::var("FIRECRAWL_API_KEY").is_ok());
        std::env::remove_var("BROWSER_USE_BASE_URL");
        std::env::remove_var("FIRECRAWL_API_URL");
    }

    /// A plugin-supplied cloud backend: records every lifecycle call, never touches the network.
    struct Acme {
        calls: Mutex<Vec<String>>,
    }

    impl CloudProvider for Acme {
        fn id(&self) -> &str {
            "acme"
        }
        fn label(&self) -> String {
            "Acme".into()
        }
        fn available(&self, _secrets: Secrets<'_>) -> bool {
            true
        }
        fn create(&self, _secrets: Secrets<'_>, task: &str) -> Result<CloudSession, String> {
            self.calls.lock().unwrap().push(format!("create:{task}"));
            Ok(CloudSession::new("acme", "acme-1", "wss://acme.test/1", json!({"acme": true}), None, &session_name(task)))
        }
        fn close(&self, _secrets: Secrets<'_>, session: &str) -> bool {
            self.calls.lock().unwrap().push(format!("close:{session}"));
            true
        }
        fn cleanup(&self, _secrets: Secrets<'_>, session: &str) {
            self.calls.lock().unwrap().push(format!("cleanup:{session}"));
        }
    }

    /// A would-be registration under a bundled name.
    struct Reserved(&'static str);

    impl CloudProvider for Reserved {
        fn id(&self) -> &str {
            self.0
        }
        fn label(&self) -> String {
            "Reserved".into()
        }
        fn available(&self, _secrets: Secrets<'_>) -> bool {
            true
        }
        fn create(&self, _secrets: Secrets<'_>, _task: &str) -> Result<CloudSession, String> {
            Err("unused".into())
        }
        fn close(&self, _secrets: Secrets<'_>, _session: &str) -> bool {
            false
        }
        fn cleanup(&self, _secrets: Secrets<'_>, _session: &str) {}
    }

    #[test]
    fn registered_provider_services_named_calls_only() {
        let p = Arc::new(Acme { calls: Mutex::new(Vec::new()) });
        register(p.clone()).expect("register");
        for name in ["browserbase", "browser-use", "browser_use", "firecrawl", "Firecrawl"] {
            let e = register(Arc::new(Reserved(name))).unwrap_err();
            assert!(e.contains("bundled"), "{name}: {e}");
        }
        let none = |_: &str| String::new();
        assert!(available("acme", &none) && available("ACME", &none));
        assert!(!available("nope", &none));
        let s = create("acme", &none, "sess1").unwrap();
        assert_eq!((s.provider.as_str(), s.id.as_str(), s.cdp_url.as_str(), s.features["acme"].as_bool()), ("acme", "acme-1", "wss://acme.test/1", Some(true)));
        assert!(s.session_name.starts_with("ark_sess1_"));
        // Autodetect only ever walks the bundled order.
        assert_ne!(autodetect(&none), Some("acme"));
        assert!(release(&s));
        assert!(close("acme", &none, "acme-2"));
        emergency_release(&s);
        cleanup("acme", &none, "acme-3");
        assert_eq!(p.calls.lock().unwrap().clone(), vec!["create:sess1", "close:acme-1", "close:acme-2", "cleanup:acme-1", "cleanup:acme-3"]);
        // The last registration for an id wins.
        let q = Arc::new(Acme { calls: Mutex::new(Vec::new()) });
        register(q.clone()).expect("replace");
        assert!(create("acme", &none, "sess2").is_ok());
        assert_eq!(q.calls.lock().unwrap().len(), 1);
        assert_eq!(registered().iter().filter(|p| p.id() == "acme").count(), 1);
    }
}
