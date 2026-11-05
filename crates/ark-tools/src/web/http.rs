//! Context and HTTP plumbing shared by the web providers: credential lookup
//! (config → env var → vault), per-provider settings, JSON calls with timeouts.

use super::config::WebConfig;
use ark_core::Cancel;
use serde_json::Value;
use std::io::Read as _;
use std::sync::Arc;
use std::time::Duration;

/// Environment lookup: process env, then the vault (`{{secret:NAME}}`). Injectable for tests.
pub type EnvFn = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

pub fn process_env() -> EnvFn {
    Arc::new(|k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
}

/// Everything a provider call may consult.
#[derive(Clone)]
pub struct WebCtx {
    pub cfg: Arc<WebConfig>,
    pub env: EnvFn,
    /// `{{secret:NAME}}` substitution (the vault).
    pub secrets: Arc<dyn Fn(&str) -> String + Send + Sync>,
    pub cancel: Cancel,
    /// Where truncated full texts / spills are written (`<artifacts>/web`).
    pub spill_dir: std::path::PathBuf,
    /// Ark home, for relative blocklist files.
    pub home: std::path::PathBuf,
}

impl WebCtx {
    pub fn new(cfg: Arc<WebConfig>, env: EnvFn) -> WebCtx {
        WebCtx { cfg, env, secrets: Arc::new(|s: &str| s.to_string()), cancel: Cancel::new(), spill_dir: std::env::temp_dir().join("ark-web"), home: std::env::temp_dir() }
    }
    pub fn from_tool(cfg: Arc<WebConfig>, env: EnvFn, t: &ark_core::ToolCtx) -> WebCtx {
        WebCtx { cfg, env, secrets: t.secrets.clone(), cancel: t.cancel.clone(), spill_dir: t.artifacts.join("web"), home: t.home.clone() }
    }
    /// Environment variable, falling back to a vault secret of the same name.
    pub fn var(&self, name: &str) -> Option<String> {
        if let Some(v) = (self.env)(name) {
            return Some(v);
        }
        let ph = format!("{{{{secret:{name}}}}}");
        let v = (self.secrets)(&ph);
        (v != ph && !v.trim().is_empty()).then_some(v)
    }
    /// `[web.providers.<id>].<key>` as a trimmed, secret-substituted string.
    pub fn opt(&self, id: &str, key: &str) -> Option<String> {
        let v = self.cfg.provider(id).get(key)?;
        let s = match v {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            _ => return None,
        };
        let s = (self.secrets)(s.trim());
        (!s.is_empty() && !s.contains("{{secret:")).then_some(s)
    }
    pub fn opt_value(&self, id: &str, key: &str) -> Option<&Value> {
        self.cfg.provider(id).get(key)
    }
    pub fn opt_bool(&self, id: &str, key: &str) -> Option<bool> {
        self.opt_value(id, key).and_then(|v| v.as_bool())
    }
    pub fn opt_u64(&self, id: &str, key: &str) -> Option<u64> {
        self.opt_value(id, key).and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())))
    }
    pub fn opt_list(&self, id: &str, key: &str) -> Vec<String> {
        match self.opt_value(id, key) {
            Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            Some(Value::String(s)) => s.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            _ => vec![],
        }
    }
    /// API key: `[web.providers.<id>].api_key`, then the first set env var (or vault secret).
    pub fn key(&self, id: &str, env_vars: &[&str]) -> Option<String> {
        self.opt(id, "api_key").or_else(|| env_vars.iter().find_map(|e| self.var(e)))
    }
    /// Base URL: config `base_url`, then `env_var`, then `default`; no trailing slash.
    pub fn base_url(&self, id: &str, env_var: Option<&str>, default: &str) -> String {
        let b = self.opt(id, "base_url").or_else(|| env_var.and_then(|e| self.var(e))).unwrap_or_else(|| default.to_string());
        b.trim().trim_end_matches('/').to_string()
    }
    /// Request timeout for a provider: `[web.providers.<id>].timeout_seconds`, else `web.search.timeout_seconds`.
    pub fn timeout(&self, id: &str) -> u64 {
        self.opt_u64(id, "timeout_seconds").unwrap_or(self.cfg.search.timeout_seconds).clamp(1, 600)
    }
    pub fn check_cancel(&self) -> Result<(), String> {
        if self.cancel.is_cancelled() {
            Err("Interrupted".into())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub body: String,
    pub content_type: String,
}

impl Resp {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
    pub fn json(&self) -> Result<Value, String> {
        serde_json::from_str(&self.body).map_err(|e| format!("response is not JSON: {e}"))
    }
}

const MAX_PROVIDER_BODY: u64 = 16 * 1024 * 1024;

fn agent(timeout: u64) -> ureq::Agent {
    ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(timeout.max(1)))).http_status_as_error(false).max_redirects(5).build().into()
}

fn finish(r: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Result<Resp, String> {
    let mut resp = r.map_err(|e| super::ssrf::error_text(&e))?;
    let status = resp.status().as_u16();
    let content_type = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let mut raw = Vec::new();
    resp.body_mut().with_config().limit(u64::MAX).reader().take(MAX_PROVIDER_BODY).read_to_end(&mut raw).map_err(|e| format!("reading response failed: {e}"))?;
    Ok(Resp { status, body: String::from_utf8_lossy(&raw).into_owned(), content_type })
}

/// POST a JSON body. `headers` are sent as given (Content-Type defaults to JSON).
pub fn post_json(url: &str, headers: &[(&str, String)], body: &Value, timeout: u64) -> Result<Resp, String> {
    let mut req = agent(timeout).post(url);
    let mut has_ct = false;
    for (k, v) in headers {
        has_ct |= k.eq_ignore_ascii_case("content-type");
        req = req.header(*k, v);
    }
    if !has_ct {
        req = req.header("Content-Type", "application/json");
    }
    finish(req.send(serde_json::to_vec(body).unwrap_or_default().as_slice()))
}

/// GET with query parameters (percent-encoded here).
pub fn get(url: &str, query: &[(&str, String)], headers: &[(&str, String)], timeout: u64) -> Result<Resp, String> {
    let mut full = url.to_string();
    for (i, (k, v)) in query.iter().enumerate() {
        full.push(if i == 0 && !url.contains('?') { '?' } else { '&' });
        full.push_str(&enc(k));
        full.push('=');
        full.push_str(&enc(v));
    }
    let mut req = agent(timeout).get(&full);
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    finish(req.call())
}

/// POST a form body (`application/x-www-form-urlencoded`).
pub fn post_form(url: &str, form: &[(&str, String)], headers: &[(&str, String)], timeout: u64) -> Result<Resp, String> {
    let body = form.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&");
    let mut req = agent(timeout).post(url).header("Content-Type", "application/x-www-form-urlencoded");
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    finish(req.send(body.as_bytes()))
}

/// RFC 3986 unreserved-only percent encoding.
pub fn enc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// `"<label> API error (<status>): <body>"` with the key redacted and the body capped.
pub fn api_error(label: &str, r: &Resp, secret: Option<&str>) -> String {
    let mut body = r.body.trim().to_string();
    if let Some(k) = secret.filter(|k| k.len() >= 4) {
        body = body.replace(k, "***");
    }
    if body.is_empty() {
        body = format!("HTTP {}", r.status);
    }
    format!("{label} API error ({}): {}", r.status, crate::util::truncate_str(&body, 2000))
}

/// Host of a URL for gate effects (`api.search.brave.com`).
pub fn host_of(url: &str) -> String {
    super::ssrf::parse_url(url).map(|u| u.host).unwrap_or_else(|_| url.to_string())
}

/// String field of a JSON object (empty when absent / not a string).
pub fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::{env_of, FakeServer};
    use serde_json::json;

    #[test]
    fn ctx_lookups() {
        let cfg = WebConfig::from_value(json!({"providers":{"brave":{"api_key":"{{secret:BK}}","base_url":"http://x/","timeout_seconds":"7","domains":"a.com, b.com","flag":true}}})).unwrap();
        let mut c = WebCtx::new(Arc::new(cfg), env_of(&[("TAVILY_API_KEY", "tv")]));
        c.secrets = Arc::new(|s: &str| s.replace("{{secret:BK}}", "bk").replace("{{secret:EXA_API_KEY}}", "ex"));
        assert_eq!(c.key("brave", &["BRAVE_API_KEY"]).as_deref(), Some("bk"));
        assert_eq!(c.key("tavily", &["TAVILY_API_KEY"]).as_deref(), Some("tv"));
        assert_eq!(c.key("exa", &["EXA_API_KEY"]).as_deref(), Some("ex"), "vault fallback");
        assert_eq!(c.key("none", &["NOPE"]), None);
        assert_eq!(c.base_url("brave", None, "https://d"), "http://x");
        assert_eq!(c.base_url("other", None, "https://d/"), "https://d");
        assert_eq!(c.timeout("brave"), 7);
        assert_eq!(c.opt_list("brave", "domains"), vec!["a.com", "b.com"]);
        assert_eq!(c.opt_bool("brave", "flag"), Some(true));
        c.cancel.cancel();
        assert!(c.check_cancel().is_err());
    }

    #[test]
    fn requests_and_errors() {
        let srv = FakeServer::start(vec![("POST /p", 200, "application/json", r#"{"ok":1}"#.into()), ("GET /g", 401, "text/plain", "bad key sekrit".into())]);
        let r = post_json(&format!("{}/p", srv.url), &[("X-A", "1".into())], &json!({"q":"x"}), 5).unwrap();
        assert!(r.ok() && r.json().unwrap()["ok"] == 1);
        let g = get(&format!("{}/g", srv.url), &[("q", "a b&c".into())], &[], 5).unwrap();
        assert_eq!(api_error("Brave Search", &g, Some("sekrit")), "Brave Search API error (401): bad key ***");
        let reqs = srv.requests();
        assert!(reqs[0].head.to_ascii_lowercase().contains("x-a: 1") && reqs[0].body == r#"{"q":"x"}"#);
        assert!(reqs[1].head.starts_with("GET /g?q=a%20b%26c "), "{}", reqs[1].head);
        assert_eq!(enc("a/b c"), "a%2Fb%20c");
        assert_eq!(host_of("https://api.x.ai/v1"), "api.x.ai");
    }
}
