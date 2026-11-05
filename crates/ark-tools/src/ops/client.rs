//! The one outbound HTTP path of the ops / secops integrations: endpoint + auth from an
//! `[integrations.<id>]` section, secrets resolved at call time, a hard response-size cap and
//! a timeout. Credentials never appear in errors (every known secret value is redacted).

use super::Integrations;
use ark_core::ToolCtx;
use serde_json::Value;
use std::io::Read as _;
use std::time::Duration;

/// Default response cap (bytes read from the wire); `[integrations.<id>] max_bytes` overrides.
pub const DEFAULT_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Default model-facing output cap; `[integrations.<id>] max_output_chars` overrides.
pub const DEFAULT_MAX_OUTPUT: usize = 20_000;

#[derive(Debug, Clone, PartialEq)]
pub enum Auth {
    None,
    Bearer(String),
    Basic(String, String),
    /// A named header (`Authorization: Splunk <t>`, `X-API-Key`, …).
    Header(String, String),
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub id: String,
    pub base: String,
    pub auth: Auth,
    pub headers: Vec<(String, String)>,
    pub timeout: u64,
    pub max_bytes: usize,
    pub max_output: usize,
}

/// Resolve `{{secret:NAME}}` through the vault; an unresolved reference is an error naming
/// the secret (never the value).
pub fn secret(ctx: &ToolCtx, raw: &str) -> Result<String, String> {
    let v = (ctx.secrets)(raw);
    if let Some(i) = v.find("{{secret:") {
        let name: String = v[i + 9..].chars().take_while(|c| *c != '}').collect();
        return Err(format!("secret `{name}` is not in the vault (add it with `ark secrets set {name}`)"));
    }
    Ok(v)
}

impl Endpoint {
    /// Build the endpoint of section `id`. `default_url` is used when the section names none
    /// (SaaS APIs with a fixed host). `via_grafana = "<datasource uid>"` routes Prometheus /
    /// Loki queries through Grafana's datasource proxy with Grafana's credentials.
    pub fn from_config(cfg: &Integrations, id: &str, default_url: Option<&str>, ctx: &ToolCtx) -> Result<Endpoint, String> {
        if let Some(uid) = cfg.str(id, "via_grafana") {
            if !uid.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) {
                return Err(format!("[integrations.{id}] via_grafana `{uid}` is not a datasource uid"));
            }
            let mut g = Endpoint::from_config(cfg, "grafana", None, ctx)?;
            g.base = format!("{}/api/datasources/proxy/uid/{uid}", g.base);
            g.id = id.to_string();
            if let Some(m) = cfg.u64(id, "max_bytes") {
                g.max_bytes = m as usize;
            }
            if let Some(m) = cfg.u64(id, "max_output_chars") {
                g.max_output = m as usize;
            }
            return Ok(g);
        }
        let base = cfg.str(id, "url").or_else(|| cfg.str(id, "base_url")).or_else(|| default_url.map(String::from)).ok_or_else(|| format!("[integrations.{id}] url is not set"))?;
        let base = secret(ctx, &base)?.trim_end_matches('/').to_string();
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            return Err(format!("[integrations.{id}] url must be http(s)://…"));
        }
        let token = cfg.str(id, "token").map(|t| secret(ctx, &t)).transpose()?;
        let user = cfg.str(id, "user").or_else(|| cfg.str(id, "username")).or_else(|| cfg.str(id, "email")).map(|u| secret(ctx, &u)).transpose()?;
        let password = cfg.str(id, "password").map(|p| secret(ctx, &p)).transpose()?;
        let kind = cfg.str(id, "auth").unwrap_or_default().to_ascii_lowercase();
        let auth = match (kind.as_str(), token, user, password) {
            ("none", ..) => Auth::None,
            ("header", Some(t), ..) => Auth::Header(cfg.str(id, "header").unwrap_or_else(|| "Authorization".into()), t),
            ("basic", Some(t), Some(u), _) | ("", Some(t), Some(u), None) => Auth::Basic(u, t),
            (_, _, Some(u), Some(p)) => Auth::Basic(u, p),
            (_, Some(t), ..) => Auth::Bearer(t),
            _ => Auth::None,
        };
        let mut headers = vec![];
        if let Some(org) = cfg.str(id, "org_id") {
            headers.push(("X-Grafana-Org-Id".to_string(), org));
        }
        if let Some(t) = cfg.str(id, "tenant") {
            headers.push(("X-Scope-OrgID".to_string(), t));
        }
        Ok(Endpoint {
            id: id.to_string(),
            base,
            auth,
            headers,
            timeout: cfg.u64(id, "timeout_seconds").unwrap_or(30).clamp(1, 600),
            max_bytes: cfg.u64(id, "max_bytes").map(|m| m as usize).unwrap_or(DEFAULT_MAX_BYTES).clamp(1024, 64 << 20),
            max_output: cfg.u64(id, "max_output_chars").map(|m| m as usize).unwrap_or(DEFAULT_MAX_OUTPUT).clamp(1000, 200_000),
        })
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    fn secrets(&self) -> Vec<String> {
        match &self.auth {
            Auth::Bearer(t) | Auth::Header(_, t) => vec![t.clone()],
            Auth::Basic(u, p) => vec![p.clone(), ark_net::crypto::b64(format!("{u}:{p}").as_bytes())],
            Auth::None => vec![],
        }
    }

    /// Redact every credential of this endpoint from `s`.
    pub fn redact(&self, s: &str) -> String {
        let mut o = s.to_string();
        for k in self.secrets() {
            if k.len() >= 4 {
                o = o.replace(&k, "***");
            }
        }
        o
    }

    pub fn get(&self, path: &str, query: &[(&str, String)]) -> Result<Resp, String> {
        self.send("GET", path, query, None)
    }

    pub fn post(&self, path: &str, body: &Value) -> Result<Resp, String> {
        self.send("POST", path, &[], Some(body))
    }

    /// A form POST (`application/x-www-form-urlencoded`), e.g. Splunk's search export.
    pub fn post_form(&self, path: &str, form: &[(&str, String)]) -> Result<Resp, String> {
        let body = form.iter().map(|(k, v)| format!("{}={}", crate::web::http::enc(k), crate::web::http::enc(v))).collect::<Vec<_>>().join("&");
        self.request("POST", path, &[], Some((body.into_bytes(), "application/x-www-form-urlencoded")))
    }

    /// One request. Only the integrations' own code chooses the method; the model never does.
    pub fn send(&self, method: &str, path: &str, query: &[(&str, String)], body: Option<&Value>) -> Result<Resp, String> {
        let b = if method == "GET" { None } else { Some((body.map(|v| v.to_string()).unwrap_or_default().into_bytes(), "application/json")) };
        self.request(method, path, query, b)
    }

    fn request(&self, method: &str, path: &str, query: &[(&str, String)], body: Option<(Vec<u8>, &str)>) -> Result<Resp, String> {
        let mut url = self.url(path);
        for (i, (k, v)) in query.iter().enumerate() {
            url.push(if i == 0 && !url.contains('?') { '?' } else { '&' });
            url.push_str(&crate::web::http::enc(k));
            url.push('=');
            url.push_str(&crate::web::http::enc(v));
        }
        let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(self.timeout))).http_status_as_error(false).max_redirects(0).build().into();
        let mut headers: Vec<(String, String)> = vec![("Accept".into(), "application/json".into()), ("User-Agent".into(), "ark-ops/1".into())];
        match &self.auth {
            Auth::None => {}
            Auth::Bearer(t) => headers.push(("Authorization".into(), format!("Bearer {t}"))),
            Auth::Basic(u, p) => headers.push(("Authorization".into(), format!("Basic {}", ark_net::crypto::b64(format!("{u}:{p}").as_bytes())))),
            Auth::Header(k, v) => headers.push((k.clone(), v.clone())),
        }
        headers.extend(self.headers.iter().cloned());
        let r = match (method, body) {
            ("GET", _) => {
                let mut req = agent.get(&url);
                for (k, v) in &headers {
                    req = req.header(k, v);
                }
                req.call()
            }
            (m, b) => {
                let mut req = match m {
                    "POST" => agent.post(&url),
                    "PUT" => agent.put(&url),
                    "PATCH" => agent.patch(&url),
                    other => return Err(format!("unsupported method {other}")),
                };
                for (k, v) in &headers {
                    req = req.header(k, v);
                }
                let (bytes, ct) = b.unwrap_or((vec![], "application/json"));
                req = req.header("Content-Type", ct);
                req.send(bytes.as_slice())
            }
        };
        let mut resp = r.map_err(|e| self.redact(&format!("{} request failed: {e}", self.id)))?;
        let status = resp.status().as_u16();
        let mut raw = Vec::new();
        resp.body_mut().with_config().limit(u64::MAX).reader().take(self.max_bytes as u64 + 1).read_to_end(&mut raw).map_err(|e| format!("{}: reading response failed: {e}", self.id))?;
        let truncated = raw.len() > self.max_bytes;
        raw.truncate(self.max_bytes);
        Ok(Resp { status, body: String::from_utf8_lossy(&raw).into_owned(), truncated })
    }

    /// `Err` with a redacted, capped body for a non-2xx answer; the parsed JSON otherwise.
    pub fn json(&self, r: Resp) -> Result<Value, String> {
        if !(200..300).contains(&r.status) {
            let body = self.redact(r.body.trim());
            let hint = match r.status {
                401 | 403 => " (check the credential and that the account is read-only-scoped as intended)",
                404 => " (check the URL / id)",
                _ => "",
            };
            return Err(format!("{} API error ({}){hint}: {}", self.id, r.status, crate::util::truncate_str(&body, 1500)));
        }
        if r.truncated {
            return Err(format!("{}: response exceeded max_bytes ({} bytes); narrow the query (shorter time range, lower limit)", self.id, self.max_bytes));
        }
        if r.body.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&r.body).map_err(|e| format!("{}: response is not JSON: {e}", self.id))
    }
}

#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub body: String,
    /// The body hit `max_bytes` and was cut.
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::FakeServer;
    use serde_json::json;

    #[test]
    fn auth_secrets_caps_and_redaction() {
        let ctx = crate::testutil::ctx("ops-client");
        let srv = FakeServer::start(vec![("GET /ok", 200, "application/json", r#"{"a":1}"#.into()), ("GET /big", 200, "application/json", format!("\"{}\"", "x".repeat(5000))), ("GET /deny", 401, "text/plain", "bad token s3cr3t".into())]);
        let cfg = Integrations::new(json!({"p": {"url": srv.url, "token": "{{secret:TOKEN}}", "max_bytes": 2048, "tenant": "t1"}, "b": {"url": srv.url, "user": "u", "password": "{{secret:TOKEN}}"}, "m": {"url": srv.url, "token": "{{secret:MISSING}}"}}));
        let e = Endpoint::from_config(&cfg, "p", None, &ctx).unwrap();
        assert_eq!(e.auth, Auth::Bearer("s3cr3t".into()));
        assert_eq!(e.json(e.get("/ok", &[("q", "a b".into())]).unwrap()).unwrap()["a"], 1);
        let req = srv.last();
        assert_eq!(req.header("authorization").as_deref(), Some("Bearer s3cr3t"));
        assert_eq!(req.header("x-scope-orgid").as_deref(), Some("t1"));
        assert!(req.path.ends_with("?q=a%20b"));
        let big = e.get("/big", &[]).unwrap();
        assert!(big.truncated && big.body.len() == 2048);
        assert!(e.json(big).unwrap_err().contains("max_bytes"));
        let err = e.json(e.get("/deny", &[]).unwrap()).unwrap_err();
        assert!(err.contains("401") && !err.contains("s3cr3t") && err.contains("***"), "{err}");
        let b = Endpoint::from_config(&cfg, "b", None, &ctx).unwrap();
        assert_eq!(b.auth, Auth::Basic("u".into(), "s3cr3t".into()));
        let m = Endpoint::from_config(&cfg, "m", None, &ctx).unwrap_err();
        assert!(m.contains("MISSING") && m.contains("vault"), "{m}");
        let g = Integrations::new(json!({"grafana": {"url": "http://g/", "token": "{{secret:TOKEN}}"}, "loki": {"via_grafana": "lk1"}}));
        let l = Endpoint::from_config(&g, "loki", None, &ctx).unwrap();
        assert_eq!(l.base, "http://g/api/datasources/proxy/uid/lk1");
        assert_eq!(l.auth, Auth::Bearer("s3cr3t".into()));
        assert!(Endpoint::from_config(&Integrations::new(json!({"x": {"via_grafana": "../admin"}, "grafana": {"url": "http://g"}})), "x", None, &ctx).is_err());
    }
}
