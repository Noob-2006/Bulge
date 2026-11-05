//! Memory-provider OAuth connect (Hermes hermes_cli/memory_oauth.py, MIT): a zero-CLI
//! loopback authorization-code + PKCE flow. `start` returns the browser URL immediately and
//! a background listener on 127.0.0.1 waits for the redirect, exchanges the code and stores
//! the tokens at `<data>/memory/oauth/<provider>.json` (0600); `status` reports
//! idle | pending | connected | error. Hosts mount these as
//! `POST /api/memory/providers/<p>/oauth/start` and `GET …/oauth/status`.

use crate::util;
use base64::Engine;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct OAuthConfig {
    pub authorize_url: String,
    pub token_url: String,
    pub client_id: String,
    pub scope: String,
    /// 0 = any free port.
    pub port: u16,
    /// How long to wait for the browser redirect (default 300 s).
    pub timeout_secs: u64,
}

fn valid(provider: &str) -> bool {
    !provider.is_empty() && provider.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn dir(data: &Path) -> PathBuf {
    data.join("memory/oauth")
}

fn set_status(data: &Path, provider: &str, v: Value) {
    let p = dir(data).join(format!("{provider}.status.json"));
    let _ = util::write_json(&p, &v);
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn random(n: usize) -> String {
    let mut b = vec![0u8; n];
    let _ = ring::rand::SystemRandom::new().fill(&mut b);
    b64(&b)
}

fn form(s: &str) -> String {
    crate::sigv4::uri_encode(s, false)
}

fn query_param(q: &str, k: &str) -> Option<String> {
    q.split('&').filter_map(|p| p.split_once('=')).find(|(a, _)| *a == k).map(|(_, v)| {
        let v = v.replace('+', " ");
        let mut out = Vec::new();
        let b = v.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                if let Ok(x) = u8::from_str_radix(&v[i + 1..i + 3], 16) {
                    out.push(x);
                    i += 3;
                    continue;
                }
            }
            out.push(b[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    })
}

/// Begin the flow; returns `{status: "pending", authorize_url, redirect_uri}`.
pub fn start(data: &Path, provider: &str, cfg: &OAuthConfig) -> Result<Value, String> {
    if !valid(provider) {
        return Err(format!("unknown memory provider {provider:?}"));
    }
    if cfg.authorize_url.is_empty() || cfg.token_url.is_empty() || cfg.client_id.is_empty() {
        return Err(format!("{provider} does not support OAuth connect (authorize_url, token_url and client_id are required)"));
    }
    let l = TcpListener::bind(("127.0.0.1", cfg.port)).map_err(|e| format!("cannot open loopback listener: {e}"))?;
    let port = l.local_addr().map_err(|e| e.to_string())?.port();
    let redirect = format!("http://127.0.0.1:{port}/callback");
    let verifier = random(48);
    let challenge = b64(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref());
    let state = random(16);
    let sep = if cfg.authorize_url.contains('?') { '&' } else { '?' };
    let url = format!("{}{sep}response_type=code&client_id={}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256&state={state}{}", cfg.authorize_url, form(&cfg.client_id), form(&redirect), if cfg.scope.is_empty() { String::new() } else { format!("&scope={}", form(&cfg.scope)) });
    set_status(data, provider, json!({"status": "pending", "authorize_url": url}));
    let (data, provider, cfg, redirect2) = (data.to_path_buf(), provider.to_string(), cfg.clone(), redirect.clone());
    std::thread::spawn(move || {
        let r = wait_and_exchange(&l, &cfg, &state, &verifier, &redirect2);
        match r {
            Ok(tok) => {
                let p = dir(&data).join(format!("{provider}.json"));
                let mut tok = tok;
                tok["obtained_ms"] = json!(util::now_ms());
                if util::write_json(&p, &tok).is_ok() {
                    let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
                }
                set_status(&data, &provider, json!({"status": "connected"}));
            }
            Err(e) => set_status(&data, &provider, json!({"status": "error", "error": e})),
        }
    });
    Ok(json!({"status": "pending", "authorize_url": url, "redirect_uri": redirect}))
}

fn wait_and_exchange(l: &TcpListener, cfg: &OAuthConfig, state: &str, verifier: &str, redirect: &str) -> Result<Value, String> {
    let deadline = Instant::now() + Duration::from_secs(if cfg.timeout_secs == 0 { 300 } else { cfg.timeout_secs });
    l.set_nonblocking(true).map_err(|e| e.to_string())?;
    loop {
        if Instant::now() > deadline {
            return Err("timed out waiting for the browser redirect".into());
        }
        let mut s = match l.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(e) => return Err(e.to_string()),
        };
        let _ = s.set_nonblocking(false);
        let mut line = String::new();
        let _ = BufReader::new(s.try_clone().map_err(|e| e.to_string())?).read_line(&mut line);
        let target = line.split_whitespace().nth(1).unwrap_or("");
        let Some(q) = target.strip_prefix("/callback?") else {
            let _ = s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            continue;
        };
        let reply = |s: &mut std::net::TcpStream, msg: &str| {
            let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}", msg.len()).as_bytes());
        };
        if query_param(q, "state").as_deref() != Some(state) {
            reply(&mut s, "State mismatch; close this window and retry.");
            return Err("OAuth state mismatch".into());
        }
        if let Some(e) = query_param(q, "error") {
            reply(&mut s, "Authorization was denied; you can close this window.");
            return Err(format!("authorization denied: {e}"));
        }
        let code = query_param(q, "code").ok_or("redirect without code")?;
        let body = format!("grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={verifier}", form(&code), form(redirect), form(&cfg.client_id));
        let r = util::http("POST", &cfg.token_url, &[("Content-Type".into(), "application/x-www-form-urlencoded".into()), ("Accept".into(), "application/json".into())], Some(body.as_bytes()), Duration::from_secs(30))?;
        if !r.ok() {
            reply(&mut s, "Token exchange failed; close this window and retry.");
            return Err(format!("token exchange HTTP {}: {}", r.status, util::clip(&r.text(), 300)));
        }
        reply(&mut s, "Connected. You can close this window.");
        let v = r.json()?;
        if v["access_token"].as_str().is_none() {
            return Err("token response has no access_token".into());
        }
        return Ok(v);
    }
}

pub fn status(data: &Path, provider: &str) -> Value {
    if !valid(provider) {
        return json!({"status": "error", "error": format!("unknown memory provider {provider:?}")});
    }
    util::read_json(&dir(data).join(format!("{provider}.status.json"))).unwrap_or_else(|| if dir(data).join(format!("{provider}.json")).is_file() { json!({"status": "connected"}) } else { json!({"status": "idle"}) })
}

/// The stored access token, if connected.
pub fn token(data: &Path, provider: &str) -> Option<String> {
    util::read_json(&dir(data).join(format!("{provider}.json")))?["access_token"].as_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::testutil::fake;

    #[test]
    fn loopback_pkce_flow() {
        let d = crate::tmp("oauth");
        let tokens = fake(|r, _| {
            let b = String::from_utf8_lossy(&r.body).into_owned();
            assert!(b.contains("grant_type=authorization_code") && b.contains("code=abc") && b.contains("code_verifier="));
            (200, r#"{"access_token":"at-1","refresh_token":"rt-1","token_type":"bearer"}"#.into())
        });
        let cfg = OAuthConfig { authorize_url: "https://auth.example/authorize".into(), token_url: format!("{}/token", tokens.url), client_id: "seagent".into(), scope: "memory".into(), port: 0, timeout_secs: 10 };
        assert!(start(&d, "../x", &cfg).is_err());
        assert!(start(&d, "honcho", &OAuthConfig::default()).unwrap_err().contains("does not support OAuth"));
        let v = start(&d, "honcho", &cfg).unwrap();
        assert_eq!(status(&d, "honcho")["status"], "pending");
        let url = v["authorize_url"].as_str().unwrap();
        assert!(url.contains("code_challenge_method=S256") && url.contains("scope=memory"));
        let state = query_param(url.split_once('?').unwrap().1, "state").unwrap();
        let redirect = v["redirect_uri"].as_str().unwrap();
        let r = util::http("GET", &format!("{redirect}?code=abc&state={state}"), &[], None, Duration::from_secs(10)).unwrap();
        assert!(r.text().contains("Connected"));
        for _ in 0..100 {
            if status(&d, "honcho")["status"] == "connected" {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(status(&d, "honcho")["status"], "connected");
        assert_eq!(token(&d, "honcho").as_deref(), Some("at-1"));
        assert_eq!(status(&d, "mem0")["status"], "idle");
    }
}
