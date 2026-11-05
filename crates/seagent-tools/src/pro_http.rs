//! Small JSON-over-HTTP helper for the professional-role tools (directory, forge).
//!
//! Unlike the web tools these talk to endpoints the **operator** configured (a self-hosted
//! GitLab, an Okta org, a LAN directory), so loopback and private addresses are allowed; the
//! model only ever supplies path segments, which the callers validate. Redirects are never
//! followed (a bearer token must not travel to a host the config did not name), the body is
//! capped, and error text is scrubbed of the credential.

use serde_json::Value;
use std::io::Read as _;
use std::time::Duration;

pub const MAX_BODY: u64 = 8 * 1024 * 1024;

pub struct Reply {
    pub status: u16,
    pub body: String,
}

impl Reply {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
    pub fn json(&self) -> Result<Value, String> {
        serde_json::from_str(&self.body).map_err(|_| format!("the server answered something that is not JSON (HTTP {})", self.status))
    }
}

fn agent(timeout: u64) -> ureq::Agent {
    seagent_net::http::builder().timeout_global(Some(Duration::from_secs(timeout.max(1)))).http_status_as_error(false).max_redirects(0).build().into()
}

fn finish(r: Result<ureq::http::Response<ureq::Body>, ureq::Error>, secrets: &[&str]) -> Result<Reply, String> {
    let mut resp = r.map_err(|e| scrub(&e.to_string(), secrets))?;
    let status = resp.status().as_u16();
    let mut raw = Vec::new();
    resp.body_mut().with_config().limit(u64::MAX).reader().take(MAX_BODY).read_to_end(&mut raw).map_err(|e| format!("reading the response failed: {e}"))?;
    Ok(Reply { status, body: String::from_utf8_lossy(&raw).into_owned() })
}

pub fn scrub(s: &str, secrets: &[&str]) -> String {
    let mut o = s.to_string();
    for k in secrets.iter().filter(|k| k.len() >= 4) {
        o = o.replace(k, "***");
    }
    o
}

pub fn get(url: &str, headers: &[(&str, String)], timeout: u64, secrets: &[&str]) -> Result<Reply, String> {
    let mut req = agent(timeout).get(url);
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    finish(req.call(), secrets)
}

/// `method` is POST, PUT, PATCH or DELETE (with an optional JSON body).
pub fn send(method: &str, url: &str, headers: &[(&str, String)], body: Option<&Value>, timeout: u64, secrets: &[&str]) -> Result<Reply, String> {
    let a = agent(timeout);
    let bytes = body.map(|b| serde_json::to_vec(b).unwrap_or_default());
    macro_rules! with_body {
        ($req:expr) => {{
            let mut req = $req;
            for (k, v) in headers {
                req = req.header(*k, v);
            }
            req = req.header("Content-Type", "application/json");
            finish(req.send(bytes.as_deref().unwrap_or(b"")), secrets)
        }};
    }
    match method {
        "POST" => with_body!(a.post(url)),
        "PUT" => with_body!(a.put(url)),
        "PATCH" => with_body!(a.patch(url)),
        other => Err(format!("unsupported method {other}")),
    }
}

/// POST `application/x-www-form-urlencoded`.
pub fn post_form(url: &str, form: &[(&str, &str)], timeout: u64, secrets: &[&str]) -> Result<Reply, String> {
    let body = form.iter().map(|(k, v)| format!("{}={}", crate::web::http::enc(k), crate::web::http::enc(v))).collect::<Vec<_>>().join("&");
    finish(agent(timeout).post(url).header("Content-Type", "application/x-www-form-urlencoded").send(body.as_bytes()), secrets)
}

/// `scheme://host[:port]` of an operator-configured base URL, for the gate effect.
pub fn dest_of(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let hp = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    hp.rsplit('@').next().unwrap_or(hp).to_string()
}

/// The API error as one line: HTTP status plus the server's message, credential removed.
pub fn api_error(label: &str, r: &Reply, secrets: &[&str]) -> String {
    let msg = serde_json::from_str::<Value>(&r.body)
        .ok()
        .and_then(|v| v["message"].as_str().or(v["error"]["message"].as_str()).or(v["error_description"].as_str()).or(v["errorSummary"].as_str()).or(v["error"].as_str()).map(str::to_string))
        .unwrap_or_else(|| r.body.trim().to_string());
    let hint = match r.status {
        401 => " (the token is missing, expired or revoked)",
        403 => " (the token lacks permission, or a rate limit was hit)",
        404 => " (not found, or the token cannot see it)",
        _ => "",
    };
    format!("{label}: HTTP {}{hint}: {}", r.status, crate::util::truncate_str(&scrub(&msg, secrets), 600))
}
