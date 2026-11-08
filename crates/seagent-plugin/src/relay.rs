//! mcp-relay (ported from OpenClaw's `extensions/mcp-relay`): expose `seagent mcp
//! serve` through an outbound WebSocket, so no inbound port or token is shared.
//!
//! - Identity: an Ed25519 key kept in `<data>/mcp-relay.json` (0600); the relay
//!   knows us by the public key (`?key=`), `gatewayId = "gw_" + b64url(sha256(pk))[..22]`.
//! - Handshake: relay → `{type: challenge, protocol: 1, relay: <host>, nonce}`;
//!   we sign `openclaw-mcp-relay/v1\n<nonce>\n<host>` and answer `hello`; relay
//!   → `ready {gatewayId}`. Keepalive `ping` every 30 s, `pong` within 60 s.
//! - Grants: a single-use pairing code (10 chars, Crockford-style alphabet) is
//!   offered as its hash (`pair.offer`); the relay redeems it with `grant.create`
//!   and withdraws with `grant.revoked`. Every other request names a live grant.
//! - Operations: `status`, and `mcp` (`{message}` → `{message}`: one JSON-RPC
//!   message for seagent's MCP server). Frames ≤ 1 MiB, results ≤ 512 KiB.

use seagent_core::Cancel;
use seagent_net::crypto;
use seagent_net::ws::{Message, WebSocket};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_FRAME: usize = 1 << 20;
const MAX_RESULT: usize = 512 * 1024;
const CODE_TTL_MS: u64 = 10 * 60_000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    pub client_id: String,
    pub client_name: String,
    pub created_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    /// base64url Ed25519 seed.
    pub seed: String,
    /// The relay origin the identity is bound to (changing it is refused).
    pub relay: String,
    #[serde(default)]
    pub codes: Vec<(String, u64)>,
    #[serde(default)]
    pub grants: Vec<Grant>,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

impl State {
    pub fn load_or_create(path: &Path, relay: &str) -> Result<State, String> {
        match std::fs::read(path) {
            Ok(b) => {
                let s: State = serde_json::from_slice(&b).map_err(|e| format!("{}: corrupt relay identity ({e}); restore it from backup", path.display()))?;
                if s.seed_bytes().is_none() {
                    return Err(format!("{}: invalid relay identity; restore it from backup", path.display()));
                }
                if s.relay != relay {
                    return Err(format!("the relay identity belongs to {}; its grants cannot move to {relay}", s.relay));
                }
                Ok(s)
            }
            Err(_) => {
                let s = State { seed: crypto::b64url(&crypto::random_bytes(32)), relay: relay.into(), ..Default::default() };
                s.save(path)?;
                Ok(s)
            }
        }
    }
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        let tmp = path.with_extension("tmp");
        let mut f = crate::oauth::create_private(&tmp).map_err(|e| e.to_string())?;
        std::io::Write::write_all(&mut f, &serde_json::to_vec_pretty(self).unwrap_or_default()).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())
    }
    fn seed_bytes(&self) -> Option<[u8; 32]> {
        crypto::b64url_decode(&self.seed)?.try_into().ok()
    }
    pub fn public_key(&self) -> String {
        crypto::b64url(&crypto::ed25519_public(&self.seed_bytes().expect("validated seed")))
    }
    pub fn gateway_id(&self) -> String {
        let pk = crypto::ed25519_public(&self.seed_bytes().expect("validated seed"));
        format!("gw_{}", &crypto::b64url(&crypto::sha256(&pk))[..22])
    }
    pub fn sign_challenge(&self, nonce: &str, relay_host: &str) -> String {
        crypto::b64url(&crypto::ed25519_sign(&self.seed_bytes().expect("validated seed"), format!("openclaw-mcp-relay/v1\n{nonce}\n{relay_host}").as_bytes()))
    }
}

fn normalize_code(code: &str) -> String {
    code.to_uppercase().replace(['-', ' ', '\t'], "").replace('O', "0").replace(['I', 'L'], "1")
}

pub fn code_hash(code: &str) -> String {
    crypto::b64url(&crypto::sha256(format!("openclaw-mcp-relay-pair/v1:{}", normalize_code(code)).as_bytes()))
}

pub fn new_code() -> String {
    const A: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let c: String = crypto::random_bytes(10).iter().map(|b| A[(b & 31) as usize] as char).collect();
    format!("{}-{}", &c[..5], &c[5..])
}

/// `https://relay.example` (or http://localhost for development) → canonical origin.
pub fn parse_relay_url(u: &str) -> Result<String, String> {
    let p = seagent_net::Url::parse(u)?;
    let local = matches!(p.host.as_str(), "localhost" | "127.0.0.1");
    if !(p.scheme == "https" || (p.scheme == "http" && local)) {
        return Err("relay URL must be https:// (http only for localhost)".into());
    }
    if !(p.path.is_empty() || p.path == "/") || u.contains('@') {
        return Err("relay URL must be an origin without credentials, path or query".into());
    }
    Ok(format!("{}://{}", p.scheme, p.host_header()))
}

pub struct Opts {
    pub relay: String,
    pub state: PathBuf,
    pub name: String,
    pub version: String,
    /// Offer a fresh pairing code after connecting.
    pub pair: bool,
}

#[derive(Debug)]
enum End {
    Stop,
    Closed(u16),
}

fn relay_error(code: &str, message: &str) -> Value {
    json!({"code": code, "message": message})
}

/// Connect, serve, reconnect with backoff until `stop`. `handle` is one MCP message → reply.
pub fn run(o: &Opts, handle: &dyn Fn(&Value) -> Option<Value>, stop: &Cancel, log: &dyn Fn(&str)) -> Result<(), String> {
    let relay = parse_relay_url(&o.relay)?;
    let mut st = State::load_or_create(&o.state, &relay)?;
    log(&format!("mcp-relay: gateway {} → {relay}", st.gateway_id()));
    let mut attempt = 0u32;
    let mut pair = o.pair;
    while !stop.is_cancelled() {
        let r = session(o, &relay, &mut st, &mut pair, handle, stop, log);
        let code = match r {
            Ok(End::Stop) => return Ok(()),
            Ok(End::Closed(c)) => {
                attempt = 0;
                c
            }
            Err(e) => {
                log(&format!("mcp-relay: {e}"));
                0
            }
        };
        let base = if code == 4401 { 60_000 } else { 1000u64 << attempt.min(6) };
        attempt += 1;
        let jitter = 0.8 + (crypto::random_bytes(1)[0] as f64 / 255.0) * 0.4;
        let until = Instant::now() + Duration::from_millis(((base.min(60_000) as f64) * jitter) as u64);
        while Instant::now() < until && !stop.is_cancelled() {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    Ok(())
}

fn send(ws: &mut WebSocket<seagent_net::Stream>, v: &Value) -> Result<(), String> {
    ws.send_text(&v.to_string()).map_err(|e| format!("send: {e}"))
}

fn session(o: &Opts, relay: &str, st: &mut State, pair: &mut bool, handle: &dyn Fn(&Value) -> Option<Value>, stop: &Cancel, log: &dyn Fn(&str)) -> Result<End, String> {
    let host = relay.split_once("://").map(|(_, h)| h).unwrap_or(relay).to_string();
    let ws_url = format!("{}/v1/gateway/connect?key={}", relay.replacen("https://", "wss://", 1).replacen("http://", "ws://", 1), st.public_key());
    let (mut ws, _) = WebSocket::connect(&ws_url, &[], Duration::from_secs(10)).map_err(|e| format!("connect {relay}: {e}"))?;
    ws.set_max_message(MAX_FRAME);
    ws.set_read_timeout(Some(Duration::from_millis(200))).map_err(|e| e.to_string())?;
    let started = Instant::now();
    let (mut ready, mut hello) = (false, false);
    let mut last_ping = Instant::now();
    let mut pong_deadline = Instant::now() + Duration::from_secs(60);
    let mut next_id = 0u64;
    loop {
        if stop.is_cancelled() {
            let _ = ws.send(&Message::Close(Some((1001, "stopping".into()))));
            return Ok(End::Stop);
        }
        if !ready && started.elapsed() > Duration::from_secs(10) {
            let _ = ws.send(&Message::Close(Some((4400, "Handshake timed out".into()))));
            return Err("relay handshake timed out".into());
        }
        if ready && last_ping.elapsed() >= Duration::from_secs(30) {
            send(&mut ws, &json!({"type": "ping"}))?;
            last_ping = Instant::now();
        }
        if ready && Instant::now() > pong_deadline {
            let _ = ws.send(&Message::Close(Some((1001, "Relay keepalive timed out".into()))));
            return Err("relay keepalive timed out".into());
        }
        let m = match ws.recv() {
            Ok(None) => continue,
            Ok(Some(m)) => m,
            Err(e) => return Err(format!("relay connection: {e}")),
        };
        let text = match m {
            Message::Text(t) => t,
            Message::Close(c) => return Ok(End::Closed(c.map(|c| c.0).unwrap_or(1005))),
            Message::Binary(_) => {
                let _ = ws.send(&Message::Close(Some((4400, "Text frames required".into()))));
                return Err("relay sent a binary frame".into());
            }
            _ => continue,
        };
        let Ok(f) = serde_json::from_str::<Value>(&text) else {
            let _ = ws.send(&Message::Close(Some((4400, "Invalid JSON".into()))));
            return Err("relay sent invalid JSON".into());
        };
        let ty = f["type"].as_str().unwrap_or("");
        if !ready {
            let nonce_ok = |n: &str| n.len() == 43 && crypto::b64url_decode(n).is_some_and(|b| b.len() == 32 && crypto::b64url(&b) == n);
            match ty {
                "challenge" if !hello && f["protocol"] == 1 && f["relay"].as_str() == Some(host.as_str()) && f["nonce"].as_str().is_some_and(nonce_ok) => {
                    hello = true;
                    let sig = st.sign_challenge(f["nonce"].as_str().unwrap(), &host);
                    send(&mut ws, &json!({"type": "hello", "protocol": 1, "signature": sig, "gateway": {"name": o.name, "version": o.version}}))?;
                }
                "ready" if hello && f["gatewayId"].as_str() == Some(st.gateway_id().as_str()) => {
                    ready = true;
                    pong_deadline = Instant::now() + Duration::from_secs(60);
                    log(&format!("mcp-relay: connected ({} grant(s))", st.grants.len()));
                    if std::mem::take(pair) {
                        let code = new_code();
                        let expires = now_ms() + CODE_TTL_MS;
                        st.codes.retain(|(_, e)| *e > now_ms());
                        st.codes.push((code_hash(&code), expires));
                        st.save(&o.state)?;
                        next_id += 1;
                        send(&mut ws, &json!({"type": "req", "id": format!("seagent-{next_id}"), "op": "pair.offer", "params": {"codeHash": code_hash(&code), "expiresAt": expires, "principal": "owner", "ceiling": ["operator.read", "operator.write"]}}))?;
                        log(&format!("mcp-relay: pairing code {code} (valid 10 minutes); MCP URL {relay}/mcp"));
                    }
                }
                _ => {
                    let _ = ws.send(&Message::Close(Some((4400, "Invalid handshake".into()))));
                    return Err(format!("relay handshake failed at `{ty}`"));
                }
            }
            continue;
        }
        match ty {
            "pong" => pong_deadline = Instant::now() + Duration::from_secs(60),
            "res" => {} // answers to pair.offer; nothing waits on them
            "req" if f["id"].as_str().is_some_and(|i| !i.is_empty() && i.len() <= 128) => {
                let id = f["id"].clone();
                let out = match op(o, st, &f, handle) {
                    Ok(r) if r.to_string().len() >= MAX_RESULT => json!({"type": "res", "id": id, "ok": false, "error": relay_error("too_large", "This result is too large. Request less data.")}),
                    Ok(r) => json!({"type": "res", "id": id, "ok": true, "result": r}),
                    Err(e) => json!({"type": "res", "id": id, "ok": false, "error": e}),
                };
                send(&mut ws, &out)?;
            }
            _ if ty.starts_with("ui.") => {
                if let Some(sid) = f["sid"].as_str() {
                    send(&mut ws, &json!({"type": "ui.error", "sid": sid, "code": "unavailable", "message": "seagent does not tunnel a control UI through the relay"}))?;
                }
            }
            _ => {
                let _ = ws.send(&Message::Close(Some((4400, "Invalid request".into()))));
                return Err(format!("relay sent an invalid frame `{ty}`"));
            }
        }
    }
}

/// One relay request → result, or a `{code, message}` error.
fn op(o: &Opts, st: &mut State, f: &Value, handle: &dyn Fn(&Value) -> Option<Value>) -> Result<Value, Value> {
    let p = &f["params"];
    match f["op"].as_str().unwrap_or("") {
        "grant.create" => {
            let (gid, hash) = (p["grantId"].as_str().unwrap_or(""), p["codeHash"].as_str().unwrap_or(""));
            let (cid, cname) = (p["client"]["id"].as_str().unwrap_or(""), p["client"]["name"].as_str().unwrap_or(""));
            if gid.is_empty() || gid.len() > 200 || hash.len() != 43 || cid.is_empty() || cid.len() > 2000 || cname.is_empty() || cname.len() > 2000 {
                return Err(relay_error("invalid_params", "Supply a grantId, code hash and client id/name, then retry pairing."));
            }
            let now = now_ms();
            let Some(i) = st.codes.iter().position(|(h, e)| crypto::ct_eq(h.as_bytes(), hash.as_bytes()) && *e > now) else {
                return Err(relay_error("not_found", "That pairing code is unknown, expired, or already used. Pair again."));
            };
            st.codes.remove(i);
            st.grants.push(Grant { id: gid.into(), client_id: cid.into(), client_name: cname.into(), created_ms: now });
            st.save(&o.state).map_err(|e| relay_error("internal", &e))?;
            Ok(json!({}))
        }
        "grant.revoked" => {
            let gid = p["grantId"].as_str().unwrap_or("");
            if !matches!(p["reason"].as_str(), Some("client_revoked" | "refresh_reuse")) {
                return Err(relay_error("invalid_params", "Supply a valid revocation reason."));
            }
            st.grants.retain(|g| g.id != gid);
            st.save(&o.state).map_err(|e| relay_error("internal", &e))?;
            Ok(json!({}))
        }
        other => {
            // Unknown and revoked grants are refused identically.
            let gid = f["grantId"].as_str().unwrap_or("");
            if !st.grants.iter().any(|g| g.id == gid) {
                return Err(relay_error("grant_revoked", "This connection was revoked. Pair again and reconnect."));
            }
            match other {
                "status" => Ok(json!({"gateway": {"name": o.name, "version": o.version}, "gatewayId": st.gateway_id(), "grantsCount": st.grants.len()})),
                "mcp" => {
                    let msg = p.get("message").filter(|m| m.is_object()).ok_or_else(|| relay_error("invalid_params", "`mcp` needs params.message (one JSON-RPC message)."))?;
                    Ok(json!({"message": handle(msg)}))
                }
                _ => Err(relay_error("invalid_params", &format!("seagent's relay supports `status` and `mcp`, not `{other}`"))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_identity_and_urls() {
        let c = new_code();
        assert_eq!(c.len(), 11);
        assert_eq!(code_hash(&c), code_hash(&c.to_lowercase().replace('-', " ")));
        assert_eq!(code_hash("ABCDE-0I1LO"), code_hash("abcde01110"), "O→0, I/L→1");
        assert_eq!(code_hash("x").len(), 43);
        let dir = seagent_core::tmp::scratch_path(format!("seagent-relay-{}", std::process::id()));
        let path = dir.join("mcp-relay.json");
        let s = State::load_or_create(&path, "https://relay.example").unwrap();
        assert!(s.gateway_id().starts_with("gw_") && s.gateway_id().len() == 25);
        let again = State::load_or_create(&path, "https://relay.example").unwrap();
        assert_eq!(s.public_key(), again.public_key(), "identity persists");
        assert!(State::load_or_create(&path, "https://other.example").unwrap_err().contains("belongs to"));
        let sig = crypto::b64url_decode(&s.sign_challenge("n", "relay.example")).unwrap();
        assert!(crypto::ed25519_verify(&crypto::b64url_decode(&s.public_key()).unwrap(), b"openclaw-mcp-relay/v1\nn\nrelay.example", &sig));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_dir_all(dir).ok();
        assert_eq!(parse_relay_url("https://mcp.openclaw.ai/").unwrap(), "https://mcp.openclaw.ai");
        assert_eq!(parse_relay_url("http://127.0.0.1:9").unwrap(), "http://127.0.0.1:9");
        assert!(parse_relay_url("http://relay.example").is_err());
        assert!(parse_relay_url("https://relay.example/path").is_err());
    }
}
