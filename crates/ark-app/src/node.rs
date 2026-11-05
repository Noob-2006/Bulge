//! Nodes: devices that connect to the app server and run commands for the agent
//! (parity with OpenClaw's node-host, linux-node and device-pair, MIT).
//!
//! Wire (JSON-RPC 2.0 over WebSocket `GET /node`):
//! 1. server → `connect.challenge {nonce}`
//! 2. device → `node.connect {id, name, platform, caps, commands, publicKey, signature, deviceToken?, bootstrapToken?}`
//!    where `signature` = Ed25519 over `"ark-node|v1|<id>|<nonce>"`.
//!    Unknown devices are held as pending pairing requests (8-char code) until the
//!    operator runs `ark nodes approve <code>`, or are approved at once when they present
//!    the `bootstrapToken` of a setup code (`ark nodes setup-code`); the device then receives
//!    `node.pair.resolved {deviceToken}` and reconnects.
//! 3. server → `node.invoke.request {id, command, params, timeoutMs}`, later maybe
//!    `node.invoke.input {id, seq, data, eof?}` (stdin for `system.run {stdin: true}`) or
//!    `node.invoke.cancel {id}`; device → `node.invoke.progress {id, …}` / `node.invoke.result {id, ok, payload, error}`.
//! 4. Offline queue: invokes with `queue: true` for a paired node that is offline wait (TTL,
//!    default 10 min); on connect the server sends `node.pending {count}` and the device calls
//!    `node.pending.pull` → `{actions: [{id, command, params, enqueuedAtMs}]}`, runs them, sends
//!    their results and `node.pending.ack {ids}`. Work items (`status.request`,
//!    `location.request`, one per type, TTL default 24 h) come from `node.pending.drain {maxItems}`.
//! 5. device → `node.event {event, payload}` (kept per node, see `node.events`);
//!    server → `node.token.rotated {deviceToken}` after `node.token.rotate`.
//!
//! ARP methods: see [`METHODS`].

pub(crate) mod a11y;
mod cdp;
mod talk;

use crate::App;
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use ark_net::ws::{Message, WebSocket};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const ACTION_TTL_MS: u64 = 10 * 60_000;
pub const WORK_TTL_MS: u64 = 24 * 3_600_000;
const MAX_QUEUED: usize = 50;
const MAX_EVENTS: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Paired {
    pub name: String,
    pub public_key: String,
    /// Salted hash of the device token.
    pub token_hash: String,
    pub salt: String,
    pub approved_at: u64,
    /// Last seen platform and commands (queued invokes are checked against them).
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub token_rotated_at: u64,
    /// Plugin-provided commands' `{description, dangerous, params}` as the device declared them.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, Value>,
    /// Workload identity (ent-059): the SPIFFE ID (or other verified certificate identity) this
    /// device is bound to. Once set, it replaces the device token: a connection must present
    /// the same verified identity through mTLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PendingPair {
    pub code: String,
    pub id: String,
    pub name: String,
    pub platform: String,
    #[serde(skip)]
    public_key: String,
    #[serde(skip)]
    created: Instant,
    #[serde(skip)]
    notify: Option<mpsc::Sender<Value>>,
}

struct Live {
    name: String,
    platform: String,
    caps: Vec<String>,
    commands: Vec<String>,
    meta: BTreeMap<String, Value>,
    tx: mpsc::Sender<Value>,
    since: u64,
}

/// An invoke waiting for its node to come back.
#[derive(Debug, Clone, Serialize)]
pub struct Queued {
    pub id: String,
    pub command: String,
    pub params: Value,
    #[serde(rename = "enqueuedAtMs")]
    pub enqueued_ms: u64,
    #[serde(rename = "expiresAtMs")]
    pub expires_ms: u64,
}

/// A pull-style work item (OpenClaw `node.pending.enqueue`).
#[derive(Debug, Clone, Serialize)]
pub struct Work {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub priority: String,
    #[serde(rename = "createdAtMs")]
    pub created_ms: u64,
    #[serde(rename = "expiresAtMs")]
    pub expires_ms: u64,
}

#[derive(Default)]
struct Registry {
    live: HashMap<String, Live>,
    pending: Vec<PendingPair>,
    calls: HashMap<String, mpsc::Sender<Value>>,
    paired: BTreeMap<String, Paired>,
    store: Option<PathBuf>,
    queue: HashMap<String, Vec<Queued>>,
    /// Results of queued invokes, newest last.
    results: VecDeque<Value>,
    work: HashMap<String, Vec<Work>>,
    work_rev: u64,
    events: VecDeque<Value>,
    /// Setup-code bootstrap tokens: (salted hash, expiry ms). Single use.
    bootstrap: Vec<(String, u64)>,
}

fn reg() -> &'static Mutex<Registry> {
    static R: OnceLock<Mutex<Registry>> = OnceLock::new();
    R.get_or_init(Default::default)
}

fn now() -> u64 {
    now_ms() / 1000
}
fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Load approved devices from `<data>/nodes.json` (call once at startup).
pub fn init(data: &Path) {
    let path = data.join("nodes.json");
    let paired = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    let mut r = reg().lock().unwrap();
    r.paired = paired;
    r.store = Some(path);
}

fn write_private(p: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, p)
}

fn save(r: &Registry) {
    if let Some(p) = &r.store {
        let _ = write_private(p, &serde_json::to_vec_pretty(&r.paired).unwrap_or_default());
    }
}

fn token_hash(salt: &str, token: &str) -> String {
    ark_net::crypto::hex(&ark_net::crypto::sha256(format!("{salt}:{token}").as_bytes()))
}

pub fn signed_message(id: &str, nonce: &str) -> String {
    format!("ark-node|v1|{id}|{nonce}")
}

fn rpc_ok(id: &Value, result: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string()
}

/// Server side of one device connection.
pub fn session(_app: &Arc<App>, s: TcpStream, head: &str, rest: Vec<u8>, workload: Option<String>) {
    let _ = s.set_read_timeout(Some(Duration::from_millis(100)));
    let Ok(ws) = WebSocket::accept(s, head, rest) else { return };
    let mut ws = ws;
    ws.set_max_message(32 * 1024 * 1024);
    let nonce = ark_net::crypto::random_token(18);
    let (tx, rx) = mpsc::channel::<Value>();
    let _ = ws.send_text(&json!({"jsonrpc": "2.0", "method": "connect.challenge", "params": {"nonce": nonce, "protocol": "ark-node/1"}}).to_string());
    let mut me: Option<String> = None;
    let started = Instant::now();
    loop {
        for m in rx.try_iter() {
            if ws.send_text(&m.to_string()).is_err() {
                break;
            }
        }
        let text = match ws.recv() {
            Ok(None) => {
                if me.is_none() && started.elapsed() > Duration::from_secs(600) {
                    break; // never paired
                }
                continue;
            }
            Ok(Some(Message::Text(t))) => t,
            Ok(Some(Message::Close(_))) | Err(_) => break,
            Ok(Some(_)) => continue,
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
        let p = &v["params"];
        let rid = &v["id"];
        let me_now = me.clone();
        match (v["method"].as_str().unwrap_or(""), me_now.as_deref()) {
            ("node.connect", None) => match connect(p, &nonce, &tx, workload.as_deref()) {
                Ok(Conn::Live(id)) => {
                    let _ = ws.send_text(&rpc_ok(rid, json!({"connected": true, "id": id})));
                    let n = reg().lock().unwrap().queue.get(&id).map_or(0, Vec::len);
                    if n > 0 {
                        let _ = ws.send_text(&json!({"jsonrpc": "2.0", "method": "node.pending", "params": {"count": n}}).to_string());
                    }
                    me = Some(id);
                }
                Ok(Conn::Pending(code)) => {
                    let _ = ws.send_text(&rpc_ok(rid, json!({"connected": false, "pairing": {"code": code, "hint": format!("ask the operator to run: ark nodes approve {code}")}})));
                }
                Ok(Conn::Bootstrapped) => {
                    let _ = ws.send_text(&rpc_ok(rid, json!({"connected": false, "paired": true})));
                }
                Err(e) => {
                    let _ = ws.send_text(&json!({"jsonrpc": "2.0", "id": rid, "error": {"code": -32050, "message": e}}).to_string());
                    break;
                }
            },
            ("node.invoke.result" | "node.invoke.progress", Some(node)) => {
                let id = p["id"].as_str().unwrap_or("");
                let mut r = reg().lock().unwrap();
                match r.calls.get(id).cloned() {
                    Some(tx) => {
                        let mut msg = p.clone();
                        msg["_kind"] = json!(v["method"]);
                        let _ = tx.send(msg);
                    }
                    // A queued invoke that ran after reconnecting: keep its result for `node.queue`.
                    None if v["method"] == "node.invoke.result" && id.starts_with("q-") => {
                        let mut res = p.clone();
                        res["node"] = json!(node);
                        res["completedAtMs"] = json!(now_ms());
                        r.results.push_back(res);
                        while r.results.len() > 100 {
                            r.results.pop_front();
                        }
                    }
                    None => {}
                }
            }
            ("node.pending.pull", Some(node)) => {
                let actions = pull(&mut reg().lock().unwrap(), node, now_ms());
                let _ = ws.send_text(&rpc_ok(rid, json!({"nodeId": node, "actions": actions})));
            }
            ("node.pending.ack", Some(node)) => {
                let ids: Vec<String> = p["ids"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
                let left = ack(&mut reg().lock().unwrap(), node, &ids);
                let _ = ws.send_text(&rpc_ok(rid, json!({"nodeId": node, "ackedIds": ids, "remainingCount": left})));
            }
            ("node.pending.drain", Some(node)) => {
                let max = p["maxItems"].as_u64().unwrap_or(4).clamp(1, 10) as usize;
                let (items, more, rev) = drain(&mut reg().lock().unwrap(), node, max, now_ms());
                let _ = ws.send_text(&rpc_ok(rid, json!({"nodeId": node, "items": items, "hasMore": more, "revision": rev})));
            }
            ("node.event", Some(node)) => {
                let ev = p["event"].as_str().unwrap_or("").chars().take(64).collect::<String>();
                let payload: Value = if p["payload"].to_string().len() > 64 * 1024 { json!({"truncated": true}) } else { p["payload"].clone() };
                eprintln!("arkd: node {node} event {ev}: {}", payload.to_string().chars().take(200).collect::<String>());
                let mut r = reg().lock().unwrap();
                r.events.push_back(json!({"node": node, "event": ev, "payload": payload, "ts": now_ms()}));
                while r.events.len() > MAX_EVENTS {
                    r.events.pop_front();
                }
                if !rid.is_null() {
                    let _ = ws.send_text(&rpc_ok(rid, json!({"ok": true})));
                }
            }
            (_, _) if !rid.is_null() && v.get("method").is_some() => {
                let _ = ws.send_text(&json!({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not available (connect first?)"}}).to_string());
            }
            _ => {}
        }
    }
    if let Some(id) = me {
        reg().lock().unwrap().live.remove(&id);
    }
}

enum Conn {
    Live(String),
    Pending(String),
    /// Approved through a setup code's bootstrap token; `node.pair.resolved` is queued.
    Bootstrapped,
}

fn issue_token(r: &mut Registry, id: &str, name: &str, platform: &str, pk: &str, commands: Vec<String>) -> String {
    let token = ark_net::crypto::random_token(32);
    let salt = ark_net::crypto::random_token(12);
    r.paired.insert(id.into(), Paired { name: name.into(), public_key: pk.into(), token_hash: token_hash(&salt, &token), salt, approved_at: now(), platform: platform.into(), commands, token_rotated_at: 0, meta: BTreeMap::new(), workload_id: None });
    save(r);
    token
}

/// `workload`: the connection's verified, operator-allowed workload identity (ent-059; a SPIFFE
/// ID from the mTLS client certificate), `None` without one. It stands in for the device token
/// and for operator approval: the mesh CA already attested who this is.
fn connect(p: &Value, nonce: &str, tx: &mpsc::Sender<Value>, workload: Option<&str>) -> Result<Conn, String> {
    let id = p["id"].as_str().filter(|s| !s.is_empty() && s.len() <= 64).ok_or("missing node id")?.to_string();
    let pk_hex = p["publicKey"].as_str().ok_or("missing publicKey")?;
    let pk = ark_net::crypto::hex_decode(pk_hex).filter(|k| k.len() == 32).ok_or("publicKey must be 32-byte hex (Ed25519)")?;
    let sig = p["signature"].as_str().and_then(ark_net::crypto::hex_decode).ok_or("missing signature")?;
    if !ark_net::crypto::ed25519_verify(&pk, signed_message(&id, nonce).as_bytes(), &sig) {
        return Err("bad signature".into());
    }
    let name = p["name"].as_str().unwrap_or(&id).chars().take(80).collect::<String>();
    let platform = p["platform"].as_str().unwrap_or("").to_string();
    let strs = |k: &str| p[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).take(256).collect::<Vec<_>>()).unwrap_or_default();
    let mut r = reg().lock().unwrap();
    let known = r.paired.get(&id).cloned();
    match known {
        Some(d) if d.public_key == pk_hex => {
            match (&d.workload_id, workload) {
                // Bound to a workload identity: only that verified identity gets in.
                (Some(bound), Some(w)) if bound == w => {}
                (Some(bound), _) => return Err(format!("this node is bound to workload identity {bound}; connect through mTLS with that SVID")),
                // Not bound yet: an allowed identity replaces the token from now on.
                (None, Some(w)) => {
                    if let Some(e) = r.paired.get_mut(&id) {
                        e.workload_id = Some(w.to_string());
                    }
                    save(&r);
                }
                (None, None) => {
                    let tok = p["deviceToken"].as_str().unwrap_or("");
                    if !ark_net::crypto::ct_eq(token_hash(&d.salt, tok).as_bytes(), d.token_hash.as_bytes()) {
                        return Err("bad device token; re-pair this node".into());
                    }
                }
            }
            let commands = strs("commands");
            let meta = command_meta(&p["commandMeta"], &commands);
            if let Some(e) = r.paired.get_mut(&id) {
                if e.commands != commands || e.platform != platform || e.meta != meta {
                    e.commands = commands.clone();
                    e.platform = platform.clone();
                    e.meta = meta.clone();
                    save(&r);
                }
            }
            // The operator's chosen name (node.rename) wins over the one the device reports.
            r.live.insert(id.clone(), Live { name: d.name, platform, caps: strs("caps"), commands, meta, tx: tx.clone(), since: now() });
            Ok(Conn::Live(id))
        }
        Some(_) => Err("this node id is paired with a different key".into()),
        None if workload.is_some() => {
            // A new device with an allowed workload identity pairs itself (no code to approve).
            let w = workload.unwrap_or_default().to_string();
            if r.paired.values().any(|x| x.workload_id.as_deref() == Some(w.as_str())) {
                return Err(format!("workload identity {w} is already bound to another node id"));
            }
            let commands = strs("commands");
            let _ = issue_token(&mut r, &id, &name, &platform, pk_hex, commands.clone());
            let meta = command_meta(&p["commandMeta"], &commands);
            if let Some(e) = r.paired.get_mut(&id) {
                e.workload_id = Some(w.clone());
                e.meta = meta.clone();
            }
            save(&r);
            eprintln!("arkd: node `{name}` ({id}, {platform}) paired by workload identity {w}");
            r.live.insert(id.clone(), Live { name, platform, caps: strs("caps"), commands, meta, tx: tx.clone(), since: now() });
            Ok(Conn::Live(id))
        }
        None => {
            if let Some(bt) = p["bootstrapToken"].as_str().filter(|t| !t.is_empty()) {
                let t = now_ms();
                r.bootstrap.retain(|(_, exp)| *exp > t);
                let h = token_hash("bootstrap", bt);
                let Some(i) = r.bootstrap.iter().position(|(x, _)| ark_net::crypto::ct_eq(x.as_bytes(), h.as_bytes())) else {
                    return Err("setup code is unknown, used or expired; ask for a new one (ark nodes setup-code)".into());
                };
                r.bootstrap.remove(i);
                let token = issue_token(&mut r, &id, &name, &platform, pk_hex, strs("commands"));
                eprintln!("arkd: node `{name}` ({id}, {platform}) paired with a setup code");
                let _ = tx.send(json!({"jsonrpc": "2.0", "method": "node.pair.resolved", "params": {"decision": "approved", "deviceToken": token, "id": id}}));
                return Ok(Conn::Bootstrapped);
            }
            let code = add_pending(&mut r, &id, &name, &platform, pk_hex, Some(tx.clone()))?;
            Ok(Conn::Pending(code))
        }
    }
}

/// `commandMeta` from node.connect: only for offered commands, only the known keys.
fn command_meta(v: &Value, commands: &[String]) -> BTreeMap<String, Value> {
    let Some(o) = v.as_object() else { return BTreeMap::new() };
    o.iter()
        .filter(|(k, _)| commands.contains(k) && schema_of(k).is_none())
        .take(128)
        .map(|(k, m)| {
            let desc: String = m["description"].as_str().unwrap_or("").chars().take(300).collect();
            let params = if m["params"].is_object() && m["params"].to_string().len() <= 8192 { m["params"].clone() } else { json!({"type": "object"}) };
            (k.clone(), json!({"description": desc, "dangerous": m["dangerous"] == true, "params": params}))
        })
        .collect()
}

/// How long a pending pairing request stays approvable. After it the operator must ask the
/// device to reconnect (`node.pair.list` no longer shows it).
pub const PAIR_TTL: Duration = Duration::from_secs(3600);

/// Drop pairing requests older than [`PAIR_TTL`].
fn prune_pending(r: &mut Registry) {
    r.pending.retain(|x| x.created.elapsed() < PAIR_TTL);
}

/// Record a device that asked to pair as a pending request and return its 8-char code. The
/// `node.connect` handshake calls this for an unknown device; nothing is paired (and no
/// token is issued) until [`approve`].
pub fn request_pairing(id: &str, name: &str, platform: &str, public_key: &str) -> Result<String, String> {
    add_pending(&mut reg().lock().unwrap(), id, name, platform, public_key, None)
}

fn add_pending(r: &mut Registry, id: &str, name: &str, platform: &str, public_key: &str, notify: Option<mpsc::Sender<Value>>) -> Result<String, String> {
    let name: String = name.chars().take(80).collect();
    r.pending.retain(|x| x.id != id);
    prune_pending(r);
    if r.pending.len() >= 10 {
        return Err("too many pending pairing requests".into());
    }
    const ALPHA: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let code: String = ark_net::crypto::random_bytes(8).iter().map(|b| ALPHA[*b as usize % ALPHA.len()] as char).collect();
    eprintln!("arkd: node `{name}` ({id}, {platform}) asks to pair; approve with `ark nodes approve {code}`");
    r.pending.push(PendingPair { code: code.clone(), id: id.into(), name, platform: platform.into(), public_key: public_key.into(), created: Instant::now(), notify });
    Ok(code)
}

pub fn approve(code: &str) -> Result<String, String> {
    let mut r = reg().lock().unwrap();
    prune_pending(&mut r);
    let i = r.pending.iter().position(|p| p.code.eq_ignore_ascii_case(code.trim())).ok_or("no pending node with that code (unknown, used or expired)")?;
    let p = r.pending.remove(i);
    let token = issue_token(&mut r, &p.id, &p.name, &p.platform, &p.public_key, vec![]);
    if let Some(tx) = &p.notify {
        let _ = tx.send(json!({"jsonrpc": "2.0", "method": "node.pair.resolved", "params": {"decision": "approved", "deviceToken": token, "id": p.id}}));
    }
    Ok(p.id)
}

/// New device token for a connected node; the old one stops working.
pub fn rotate_token(id: &str) -> Result<(), String> {
    let mut r = reg().lock().unwrap();
    let tx = r.live.get(id).map(|l| l.tx.clone()).ok_or_else(|| format!("node `{id}` must be connected to receive a new token"))?;
    let token = ark_net::crypto::random_token(32);
    let salt = ark_net::crypto::random_token(12);
    let d = r.paired.get_mut(id).ok_or("node is not paired")?;
    d.token_hash = token_hash(&salt, &token);
    d.salt = salt;
    d.token_rotated_at = now();
    save(&r);
    tx.send(json!({"jsonrpc": "2.0", "method": "node.token.rotated", "params": {"deviceToken": token}})).map_err(|_| "node connection closed".to_string())
}

/// Create a one-time bootstrap token for a setup code.
pub fn bootstrap_token(ttl: Duration) -> (String, u64) {
    let token = ark_net::crypto::random_token(18);
    let exp = now_ms() + ttl.as_millis() as u64;
    let mut r = reg().lock().unwrap();
    let t = now_ms();
    r.bootstrap.retain(|(_, e)| *e > t);
    r.bootstrap.push((token_hash("bootstrap", &token), exp));
    (token, exp)
}

/// Invalidate every unused setup code (`/pair cleanup`); returns how many were active.
pub fn clear_bootstrap() -> usize {
    let mut r = reg().lock().unwrap();
    let t = now_ms();
    let n = r.bootstrap.iter().filter(|(_, e)| *e > t).count();
    r.bootstrap.clear();
    n
}

// ── queue (pure functions over the registry, unit-tested) ──

fn enqueue(r: &mut Registry, node: &str, command: &str, params: Value, ttl_ms: u64, t: u64) -> Result<Queued, String> {
    let d = r.paired.get(node).ok_or_else(|| format!("node `{node}` is not paired"))?;
    if !d.commands.is_empty() && !d.commands.iter().any(|c| c == command) {
        return Err(format!("node `{node}` did not offer `{command}` when last connected"));
    }
    let q = r.queue.entry(node.to_string()).or_default();
    q.retain(|x| x.expires_ms > t);
    if q.len() >= MAX_QUEUED {
        return Err(format!("node `{node}` already has {MAX_QUEUED} queued invokes"));
    }
    let item = Queued { id: format!("q-{}", ark_net::crypto::random_token(10)), command: command.into(), params, enqueued_ms: t, expires_ms: t + ttl_ms.clamp(1000, 7 * 24 * 3_600_000) };
    q.push(item.clone());
    Ok(item)
}

/// Unexpired queued invokes the node still offers (others are dropped).
fn pull(r: &mut Registry, node: &str, t: u64) -> Vec<Queued> {
    let offered: Option<Vec<String>> = r.live.get(node).map(|l| l.commands.clone());
    let q = r.queue.entry(node.to_string()).or_default();
    q.retain(|x| x.expires_ms > t && offered.as_ref().is_none_or(|c| c.contains(&x.command)));
    q.clone()
}

fn ack(r: &mut Registry, node: &str, ids: &[String]) -> usize {
    let q = r.queue.entry(node.to_string()).or_default();
    q.retain(|x| !ids.contains(&x.id));
    q.len()
}

fn enqueue_work(r: &mut Registry, node: &str, kind: &str, priority: &str, ttl_ms: u64, t: u64) -> Result<(Work, bool), String> {
    if !matches!(kind, "status.request" | "location.request") {
        return Err(format!("unknown work type `{kind}` (status.request, location.request)"));
    }
    let w = r.work.entry(node.to_string()).or_default();
    w.retain(|x| x.expires_ms > t);
    // One outstanding item per type: repeats collapse until the node drains.
    if let Some(x) = w.iter().find(|x| x.kind == kind) {
        return Ok((x.clone(), true));
    }
    let item = Work { id: ark_net::crypto::random_token(10), kind: kind.into(), priority: if matches!(priority, "high" | "normal" | "default") { priority.into() } else { "normal".into() }, created_ms: t, expires_ms: t + ttl_ms.max(1000) };
    w.push(item.clone());
    r.work_rev += 1;
    Ok((item, false))
}

fn drain(r: &mut Registry, node: &str, max: usize, t: u64) -> (Vec<Work>, bool, u64) {
    let rank = |p: &str| match p {
        "high" => 3,
        "normal" => 2,
        _ => 1,
    };
    let w = r.work.entry(node.to_string()).or_default();
    w.retain(|x| x.expires_ms > t);
    w.sort_by(|a, b| rank(&b.priority).cmp(&rank(&a.priority)).then(a.created_ms.cmp(&b.created_ms)).then(a.id.cmp(&b.id)));
    let n = max.min(w.len());
    let out: Vec<Work> = w.drain(..n).collect();
    let more = !w.is_empty();
    if !out.is_empty() {
        r.work_rev += 1;
    }
    (out, more, r.work_rev)
}

/// Send a command to a connected node and wait for its result. A paired node that is offline
/// gets the invoke queued when `queue` is set (result `{queued: id}`).
pub fn invoke(node: &str, command: &str, params: Value, timeout: Duration, queue: Option<u64>) -> Result<Value, String> {
    if let Some(m) = schema_of(command) {
        validate(m, &params)?;
    }
    let (tx, rx) = mpsc::channel();
    let id = ark_net::crypto::random_token(10);
    {
        let mut r = reg().lock().unwrap();
        let Some(live) = r.live.get(node) else {
            return match queue {
                Some(ttl) => enqueue(&mut r, node, command, params, ttl, now_ms()).map(|q| json!({"queued": q.id, "expiresAtMs": q.expires_ms})),
                None => Err(format!("node `{node}` is not connected (pass queue to run it when it reconnects)")),
            };
        };
        if !live.commands.iter().any(|c| c == command) {
            return Err(format!("node `{node}` does not offer `{command}` (has: {})", live.commands.join(", ")));
        }
        live.tx.send(json!({"jsonrpc": "2.0", "method": "node.invoke.request", "params": {"id": id, "command": command, "params": params, "timeoutMs": timeout.as_millis() as u64}})).map_err(|_| "node connection closed".to_string())?;
        r.calls.insert(id.clone(), tx);
    }
    let deadline = Instant::now() + timeout;
    let out = loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            // Tell the device to stop working on it.
            cancel(node, &id);
            break Err(format!("node `{node}` did not answer `{command}` within {}s", timeout.as_secs()));
        }
        match rx.recv_timeout(left) {
            Ok(m) if m["_kind"] == "node.invoke.progress" => continue,
            Ok(m) if m["ok"].as_bool() == Some(true) => break Ok(m.get("payload").cloned().unwrap_or(Value::Null)),
            Ok(m) => break Err(m["error"]["message"].as_str().unwrap_or("node reported an error").to_string()),
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break Err(format!("node `{node}` disconnected")),
        }
    };
    reg().lock().unwrap().calls.remove(&id);
    out
}

/// Connected nodes offering `command` whose id or display name matches `query` (all when empty).
pub(crate) fn live_nodes_with(command: &str, query: &str) -> Vec<String> {
    let r = reg().lock().unwrap();
    let mut v: Vec<String> = r.live.iter().filter(|(id, l)| l.commands.iter().any(|c| c == command) && (query.is_empty() || id.as_str() == query || l.name.eq_ignore_ascii_case(query))).map(|(id, _)| id.clone()).collect();
    v.sort();
    v
}

fn send_to(node: &str, msg: Value) -> Result<(), String> {
    let r = reg().lock().unwrap();
    let l = r.live.get(node).ok_or_else(|| format!("node `{node}` is not connected"))?;
    l.tx.send(msg).map_err(|_| "node connection closed".to_string())
}

pub fn cancel(node: &str, invoke_id: &str) -> bool {
    let ok = send_to(node, json!({"jsonrpc": "2.0", "method": "node.invoke.cancel", "params": {"id": invoke_id}})).is_ok();
    if let Some(tx) = reg().lock().unwrap().calls.get(invoke_id) {
        let _ = tx.send(json!({"_kind": "node.invoke.result", "ok": false, "error": {"code": "ABORTED", "message": "node invoke cancelled"}}));
    }
    ok
}

fn describe(r: &Registry, id: &str) -> Option<Value> {
    let p = r.paired.get(id);
    let l = r.live.get(id);
    if p.is_none() && l.is_none() {
        return None;
    }
    let commands = l.map(|l| l.commands.clone()).or_else(|| p.map(|p| p.commands.clone())).unwrap_or_default();
    let meta = l.map(|l| &l.meta).or(p.map(|p| &p.meta));
    let schemas: serde_json::Map<String, Value> = commands.iter().filter_map(|c| schema_of(c).map(schema_json).or_else(|| meta?.get(c).map(|m| m["params"].clone())).map(|s| (c.clone(), s))).collect();
    let descriptions: serde_json::Map<String, Value> = meta.map(|m| m.iter().map(|(k, v)| (k.clone(), v["description"].clone())).collect()).unwrap_or_default();
    Some(json!({
        "id": id,
        "name": l.map(|l| l.name.clone()).or_else(|| p.map(|p| p.name.clone())),
        "platform": l.map(|l| l.platform.clone()).or_else(|| p.map(|p| p.platform.clone())),
        "connected": l.is_some(),
        "connected_since": l.map(|l| l.since),
        "caps": l.map(|l| l.caps.clone()).unwrap_or_default(),
        "commands": commands,
        "schemas": schemas,
        "descriptions": descriptions,
        "dangerous": commands.iter().filter(|c| dangerous(c) || meta.is_some_and(|m| m.get(*c).is_some_and(|x| x["dangerous"] == true))).collect::<Vec<_>>(),
        "paired": p.is_some(),
        "approved_at": p.map(|p| p.approved_at),
        "token_rotated_at": p.map(|p| p.token_rotated_at),
        "queued": r.queue.get(id).map_or(0, Vec::len),
        "work": r.work.get(id).map_or(0, Vec::len),
    }))
}

/// ARP methods for the daemon.
pub fn methods() -> ark_kernel::daemon::MethodExt {
    Arc::new(|m: &str, p: &Value| {
        let s = |k: &str| p[k].as_str().unwrap_or("").to_string();
        let r = match m {
            "node.list" => {
                let r = reg().lock().unwrap();
                let live: Vec<Value> = r.live.iter().map(|(id, l)| json!({"id": id, "name": l.name, "platform": l.platform, "caps": l.caps, "commands": l.commands, "connected_since": l.since})).collect();
                let paired: Vec<Value> = r.paired.iter().map(|(id, d)| json!({"id": id, "name": d.name, "platform": d.platform, "approved_at": d.approved_at, "connected": r.live.contains_key(id), "queued": r.queue.get(id).map_or(0, Vec::len)})).collect();
                Ok(json!({"connected": live, "paired": paired}))
            }
            "node.describe" => describe(&reg().lock().unwrap(), &s("id")).ok_or((-32001, format!("unknown node `{}`", s("id")))),
            "node.rename" => {
                let name = s("name").trim().chars().take(80).collect::<String>();
                if name.is_empty() {
                    return Some(Err((-32602, "name is required".into())));
                }
                let mut r = reg().lock().unwrap();
                let id = s("id");
                let had = r.paired.get_mut(&id).map(|d| d.name = name.clone()).is_some();
                if let Some(l) = r.live.get_mut(&id) {
                    l.name = name.clone();
                }
                save(&r);
                if had { Ok(json!({"id": id, "name": name})) } else { Err((-32001, format!("node `{id}` is not paired"))) }
            }
            "node.invoke" => {
                let t = Duration::from_millis(p["timeoutMs"].as_u64().unwrap_or(60_000).clamp(1000, 600_000));
                let q = (p["queue"] == true || p["ttlMs"].is_u64()).then(|| p["ttlMs"].as_u64().unwrap_or(ACTION_TTL_MS));
                let queued = q.is_some();
                invoke(&s("id"), &s("command"), p.get("params").cloned().unwrap_or(json!({})), t, q).map(|v| if queued && v.get("queued").is_some() { v } else { json!({"payload": v}) }).map_err(|e| (-32000, e))
            }
            "node.invoke.cancel" => Ok(json!({"cancelled": cancel(&s("id"), &s("invokeId"))})),
            "node.invoke.input" => send_to(&s("id"), json!({"jsonrpc": "2.0", "method": "node.invoke.input", "params": {"id": s("invokeId"), "seq": p["seq"], "data": p["data"], "eof": p["eof"] == true}})).map(|_| json!({"sent": true})).map_err(|e| (-32000, e)),
            "node.pending.enqueue" => {
                let mut r = reg().lock().unwrap();
                let id = s("nodeId");
                if !r.paired.contains_key(&id) {
                    return Some(Err((-32001, format!("node `{id}` is not paired"))));
                }
                let pr = p["priority"].as_str().unwrap_or("normal").to_string();
                enqueue_work(&mut r, &id, &s("type"), &pr, p["expiresInMs"].as_u64().unwrap_or(WORK_TTL_MS), now_ms()).map(|(w, dedup)| json!({"item": w, "deduped": dedup, "connected": r.live.contains_key(&id)})).map_err(|e| (-32602, e))
            }
            "node.queue" => {
                let r = reg().lock().unwrap();
                let id = s("id");
                let t = now_ms();
                let pick = |x: &&Value| id.is_empty() || x["node"] == id.as_str();
                let queue: Vec<Value> = r.queue.iter().filter(|(n, _)| id.is_empty() || **n == id).flat_map(|(n, q)| q.iter().filter(|x| x.expires_ms > t).map(move |x| json!({"node": n, "item": x}))).collect();
                Ok(json!({"queued": queue, "work": r.work.iter().filter(|(n, _)| id.is_empty() || **n == id).map(|(n, w)| json!({"node": n, "items": w})).collect::<Vec<_>>(), "results": r.results.iter().filter(pick).cloned().collect::<Vec<_>>()}))
            }
            "node.events" => {
                let r = reg().lock().unwrap();
                let id = s("id");
                let limit = p["limit"].as_u64().unwrap_or(50) as usize;
                let ev: Vec<Value> = r.events.iter().rev().filter(|e| id.is_empty() || e["node"] == id.as_str()).take(limit).cloned().collect();
                Ok(json!(ev))
            }
            "node.token.rotate" => rotate_token(&s("id")).map(|_| json!({"rotated": true})).map_err(|e| (-32000, e)),
            "node.setup.create" => {
                let url = s("url");
                if !(url.starts_with("ws://") || url.starts_with("wss://")) {
                    return Some(Err((-32602, "url must be ws:// or wss:// (the app server's /node endpoint)".into())));
                }
                let fp = match p["tlsFingerprint"].as_str() {
                    Some(f) => match normalize_fingerprint(f) {
                        Some(f) => Some(f),
                        None => return Some(Err((-32602, "tlsFingerprint must be a SHA-256 certificate fingerprint".into()))),
                    },
                    None => None,
                };
                let (token, exp) = bootstrap_token(Duration::from_millis(p["ttlMs"].as_u64().unwrap_or(10 * 60_000).clamp(60_000, 24 * 3_600_000)));
                let sc = SetupCode { url, bootstrap_token: token, expires_at_ms: Some(exp), tls_fingerprint: fp };
                Ok(json!({"code": sc.encode(), "url": sc.url, "expiresAtMs": exp}))
            }
            "node.pair.list" => {
                let mut r = reg().lock().unwrap();
                prune_pending(&mut r);
                Ok(json!(r.pending.clone()))
            }
            "node.pair.approve" => approve(&s("code")).map(|id| json!({"approved": id})).map_err(|e| (-32001, e)),
            "node.pair.reject" => {
                let mut r = reg().lock().unwrap();
                prune_pending(&mut r);
                let code = s("code");
                let before = r.pending.len();
                r.pending.retain(|x| !x.code.eq_ignore_ascii_case(&code));
                Ok(json!({"rejected": before != r.pending.len()}))
            }
            "node.remove" => {
                let mut r = reg().lock().unwrap();
                let id = s("id");
                let had = r.paired.remove(&id).is_some();
                r.live.remove(&id);
                r.queue.remove(&id);
                r.work.remove(&id);
                save(&r);
                Ok(json!({"removed": had}))
            }
            _ => return None,
        };
        Some(r)
    })
}

pub const METHODS: &[&str] = &[
    "node.list",
    "node.describe",
    "node.rename",
    "node.invoke",
    "node.invoke.cancel",
    "node.invoke.input",
    "node.pending.enqueue",
    "node.queue",
    "node.events",
    "node.token.rotate",
    "node.setup.create",
    "node.pair.list",
    "node.pair.approve",
    "node.pair.reject",
    "node.remove",
];

// ───────────────────────── command schemas ─────────────────────────

/// (command, [(param, type, required)], dangerous). Commands of OpenClaw's iOS/Android/macOS
/// apps that ark has no device side for: a node advertising them is invoked as-is, with the
/// parameters checked here. Dangerous ones always ask the egress gate first.
/// (param, JSON type, required).
pub type Param = (&'static str, &'static str, bool);

pub const SCHEMAS: &[(&str, &[Param], bool)] = &[
    ("photos.latest", &[("limit", "integer", false), ("maxWidth", "integer", false)], false),
    ("contacts.search", &[("query", "string", true), ("limit", "integer", false)], false),
    ("contacts.add", &[("givenName", "string", true), ("familyName", "string", false), ("phone", "string", false), ("email", "string", false)], true),
    ("calendar.events", &[("startISO", "string", false), ("endISO", "string", false), ("limit", "integer", false)], false),
    ("calendar.add", &[("title", "string", true), ("startISO", "string", true), ("endISO", "string", false), ("location", "string", false), ("notes", "string", false)], true),
    ("reminders.list", &[("limit", "integer", false), ("includeCompleted", "boolean", false)], false),
    ("reminders.add", &[("title", "string", true), ("dueISO", "string", false), ("notes", "string", false)], true),
    ("motion.activity", &[("startISO", "string", false), ("endISO", "string", false)], false),
    ("motion.pedometer", &[("startISO", "string", false), ("endISO", "string", false)], false),
    ("sms.send", &[("to", "string", true), ("body", "string", true)], true),
    ("sms.search", &[("query", "string", false), ("limit", "integer", false)], true),
    ("callLog.search", &[("query", "string", false), ("limit", "integer", false)], false),
    ("health.summary", &[("days", "integer", false)], true),
    ("device.status", &[], false),
    ("device.permissions", &[], false),
    ("device.health", &[], false),
    ("device.apps", &[("limit", "integer", false)], false),
    ("camera.clip", &[("durationMs", "integer", false), ("facing", "string", false)], true),
    ("camera.snap", &[("device", "string", false), ("facing", "string", false)], true),
    ("screen.record", &[("durationMs", "integer", false), ("fps", "integer", false)], true),
    ("location.get", &[("desiredAccuracy", "string", false)], false),
    ("watch.status", &[], false),
    ("watch.notify", &[("title", "string", true), ("body", "string", false)], false),
    ("mobile.ui.observe", &[], false),
    ("mobile.ui.act", &[("action", "string", true)], true),
    ("talk.ptt.start", &[], true),
    ("talk.ptt.stop", &[("captureId", "string", false)], false),
    ("talk.ptt.cancel", &[("captureId", "string", false)], false),
    ("talk.ptt.once", &[("durationMs", "integer", false)], true),
    ("notifications.list", &[("limit", "integer", false)], false),
    ("notifications.actions", &[("id", "string", false), ("action", "string", true)], false),
    (
        "computer.act",
        &[("action", "string", true), ("x", "number", false), ("y", "number", false), ("text", "string", false), ("keys", "string", false), ("windowRef", "string", false), ("elementRef", "string", false), ("observationId", "string", false), ("pageRef", "string", false), ("url", "string", false), ("value", "string", false), ("query", "string", false), ("app", "string", false)],
        true,
    ),
    ("canvas.present", &[("url", "string", false), ("html", "string", false)], false),
    ("system.notify", &[("title", "string", false), ("body", "string", false)], false),
    ("system.run", &[("command", "string", true), ("stdin", "boolean", false), ("timeoutMs", "integer", false)], false),
    ("file.fetch", &[("path", "string", true), ("maxBytes", "integer", false)], false),
    ("dir.list", &[("path", "string", true), ("pageToken", "string", false), ("maxEntries", "integer", false)], false),
    ("dir.fetch", &[("path", "string", true), ("maxBytes", "integer", false)], false),
    ("file.write", &[("path", "string", true), ("contentBase64", "string", true), ("overwrite", "boolean", false), ("createParents", "boolean", false)], true),
    ("canvas.hide", &[], false),
    ("canvas.navigate", &[("url", "string", true)], false),
    ("canvas.eval", &[("javaScript", "string", true)], true),
    ("canvas.snapshot", &[("format", "string", false), ("maxWidth", "integer", false)], false),
    ("canvas.a2ui.pushJSONL", &[("jsonl", "string", true)], false),
    ("canvas.a2ui.push", &[("messages", "array", false)], false),
    ("canvas.a2ui.reset", &[], false),
    ("fs.listDir", &[("path", "string", false)], false),
];

type Schema = &'static [Param];

fn schema_of(command: &str) -> Option<Schema> {
    SCHEMAS.iter().find(|(c, _, _)| *c == command).map(|(_, s, _)| *s)
}

pub fn dangerous(command: &str) -> bool {
    SCHEMAS.iter().any(|(c, _, d)| *c == command && *d)
}

/// `dangerous`, or a plugin command the node declared dangerous.
pub fn dangerous_on(node: &str, command: &str) -> bool {
    if dangerous(command) {
        return true;
    }
    let r = reg().lock().unwrap();
    let m = r.live.get(node).map(|l| &l.meta).or_else(|| r.paired.get(node).map(|p| &p.meta));
    m.is_some_and(|m| m.get(command).is_some_and(|x| x["dangerous"] == true))
}

fn schema_json(s: Schema) -> Value {
    let props: serde_json::Map<String, Value> = s.iter().map(|(k, t, _)| (k.to_string(), json!({"type": t}))).collect();
    json!({"type": "object", "properties": props, "required": s.iter().filter(|x| x.2).map(|x| x.0).collect::<Vec<_>>()})
}

/// Check known parameters' types and required ones; unknown keys pass through.
pub fn validate(s: Schema, params: &Value) -> Result<(), String> {
    let obj = params.as_object().ok_or("params must be an object")?;
    for (k, t, req) in s {
        match obj.get(*k) {
            None | Some(Value::Null) if *req => return Err(format!("missing required parameter `{k}`")),
            None | Some(Value::Null) => {}
            Some(v) => {
                let ok = match *t {
                    "string" => v.is_string(),
                    "integer" => v.is_i64() || v.is_u64(),
                    "number" => v.is_number(),
                    "boolean" => v.is_boolean(),
                    _ => true,
                };
                if !ok {
                    return Err(format!("parameter `{k}` must be {t}"));
                }
            }
        }
    }
    Ok(())
}

/// The agent's handle on connected devices.
pub struct NodeInvoke;

impl Tool for NodeInvoke {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "node_invoke".into(),
            description: "Run a command on a paired device (node). action=list shows nodes and their commands; describe {id} gives parameter schemas; invoke runs `command` with `params` on node `id` (e.g. system.run {command}, system.notify {title, body}, screen.snapshot, screen.record {durationMs}, computer.act {action, x, y, text, keys}, canvas.present {url|html}, canvas.navigate/eval/snapshot/a2ui.pushJSONL, camera.snap, location.get, file.fetch {path}, dir.list, dir.fetch, file.write {path, contentBase64}, notifications.list, and phone commands such as photos.latest, contacts.search, calendar.events when a phone node offers them); queue=true runs it when an offline node reconnects; events shows what nodes reported.".into(),
            input_schema: json!({"type": "object", "properties": {"action": {"type": "string", "enum": ["list", "describe", "invoke", "events", "queue"]}, "id": {"type": "string"}, "command": {"type": "string"}, "params": {"type": "object"}, "timeout_secs": {"type": "integer"}, "queue": {"type": "boolean"}}, "required": ["action"]}),
            parallel_safe: true,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let node = input["id"].as_str().unwrap_or("");
        match (input["action"].as_str(), input["command"].as_str()) {
            // A shell on another machine is still a shell: judge it like local commands.
            (Some("invoke"), Some("system.run")) => vec![Effect::Exec { command: input["params"]["command"].as_str().unwrap_or("").to_string() }],
            (Some("invoke"), Some(c)) if dangerous_on(node, c) => vec![Effect::Remote { dest: format!("node:{node}"), reason: format!("`{c}` on node {node} acts on a person's device or data") }],
            (Some("invoke"), Some(_)) => vec![Effect::Net { dest: format!("node:{node}"), payload: input["params"].to_string() }],
            _ => vec![],
        }
    }
    fn call(&self, _ctx: &ToolCtx, input: Value) -> ToolOutput {
        let id = input["id"].as_str().unwrap_or("");
        match input["action"].as_str() {
            Some("list") => {
                let r = reg().lock().unwrap();
                if r.live.is_empty() && r.paired.is_empty() {
                    return ToolOutput::ok("no nodes paired");
                }
                let mut lines: Vec<String> = r.live.iter().map(|(id, l)| format!("{id} ({}, {}): {}", l.name, l.platform, l.commands.join(", "))).collect();
                lines.extend(r.paired.iter().filter(|(id, _)| !r.live.contains_key(*id)).map(|(id, d)| format!("{id} ({}) offline; last offered: {}", d.name, d.commands.join(", "))));
                ToolOutput::ok(lines.join("\n"))
            }
            Some("describe") => match describe(&reg().lock().unwrap(), id) {
                Some(v) => ToolOutput::ok(serde_json::to_string_pretty(&v).unwrap_or_default()),
                None => ToolOutput::err(format!("unknown node `{id}`")),
            },
            Some("events") => {
                let r = reg().lock().unwrap();
                let ev: Vec<String> = r.events.iter().rev().filter(|e| id.is_empty() || e["node"] == id).take(20).map(|e| e.to_string()).collect();
                ToolOutput::ok(if ev.is_empty() { "no events".into() } else { ev.join("\n") })
            }
            Some("queue") => {
                let r = reg().lock().unwrap();
                let q: Vec<String> = r.queue.iter().filter(|(n, _)| id.is_empty() || n.as_str() == id).flat_map(|(n, q)| q.iter().map(move |x| format!("{n}: {} {} (queued)", x.id, x.command))).chain(r.results.iter().filter(|x| id.is_empty() || x["node"] == id).map(|x| x.to_string())).collect();
                ToolOutput::ok(if q.is_empty() { "nothing queued".into() } else { q.join("\n") })
            }
            Some("invoke") => {
                let t = Duration::from_secs(input["timeout_secs"].as_u64().unwrap_or(60).clamp(1, 600));
                let q = (input["queue"] == true).then_some(ACTION_TTL_MS);
                match invoke(id, input["command"].as_str().unwrap_or(""), input.get("params").cloned().unwrap_or(json!({})), t, q) {
                    Ok(v) => ToolOutput::ok(match v {
                        Value::String(s) => s,
                        v if v.get("queued").is_some() => format!("queued as {} (runs when the node reconnects; see action=queue)", v["queued"].as_str().unwrap_or("")),
                        other => other.to_string(),
                    }),
                    Err(e) => ToolOutput::err(e),
                }
            }
            _ => ToolOutput::err("action must be list, describe, invoke, events or queue"),
        }
    }
}

// ───────────────────────── setup code ─────────────────────────

/// OpenClaw's pairing setup code: base64url(JSON {url, bootstrapToken, expiresAtMs?, tlsFingerprint?}).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupCode {
    pub url: String,
    pub bootstrap_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_fingerprint: Option<String>,
}

/// `sha256:` prefix and colons stripped, lower-case hex; `None` if not a SHA-256 fingerprint.
pub fn normalize_fingerprint(f: &str) -> Option<String> {
    let v = f.trim();
    let v = v.strip_prefix("sha256:").or_else(|| v.strip_prefix("SHA256:")).unwrap_or(v).replace(':', "").to_ascii_lowercase();
    (v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit())).then_some(v)
}

impl SetupCode {
    pub fn encode(&self) -> String {
        ark_net::crypto::b64url(serde_json::to_string(self).unwrap_or_default().as_bytes())
    }

    /// Accepts the bare code or an `oc-pair://` / `ark-pair://` link.
    pub fn decode(input: &str, now_ms: u64) -> Result<SetupCode, String> {
        let t = input.trim();
        let code = ["oc-pair://", "ark-pair://"].iter().find_map(|p| t.get(..p.len()).filter(|h| h.eq_ignore_ascii_case(p)).map(|_| &t[p.len()..])).unwrap_or(t);
        if code.is_empty() || !code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err("invalid setup code".into());
        }
        let raw = ark_net::crypto::b64url_decode(code.trim_end_matches('=')).ok_or("invalid setup code")?;
        let mut sc: SetupCode = serde_json::from_slice(&raw).map_err(|_| "invalid setup payload".to_string())?;
        if !(sc.url.starts_with("ws://") || sc.url.starts_with("wss://")) || sc.bootstrap_token.trim().is_empty() {
            return Err("invalid setup payload".into());
        }
        if sc.expires_at_ms.is_some_and(|e| e <= now_ms) {
            return Err("setup code has expired; ask for a new one (ark nodes setup-code)".into());
        }
        if let Some(f) = &sc.tls_fingerprint {
            sc.tls_fingerprint = Some(normalize_fingerprint(f).ok_or("invalid setup payload: tlsFingerprint")?);
        }
        Ok(sc)
    }
}

// ───────────────────────── device side (`ark node`) ─────────────────────────

/// What this machine lets the server run (`node.toml`). Everything optional is off by default.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct HostPolicy {
    /// "deny" | "allowlist" | "full" for system.run.
    pub run: String,
    pub allow: Vec<String>,
    pub camera: bool,
    /// screen.snapshot and screen.record.
    pub screen: bool,
    pub location: bool,
    /// computer.act: mouse and keyboard control (xdotool on X11, ydotool on Wayland).
    pub computer: bool,
    /// canvas.present: open a URL or an HTML page in the default browser.
    pub canvas: bool,
    /// notifications.list / notifications.actions (dunst or mako).
    pub notifications: bool,
    /// Directories file.fetch / fs.listDir / dir.list / dir.fetch may read.
    pub read_roots: Vec<PathBuf>,
    /// Directories file.write may write into (empty = file.write is not offered).
    pub write_roots: Vec<PathBuf>,
    /// talk.ptt.*: record the microphone (pw-record or ffmpeg) and transcribe with `stt`.
    pub microphone: bool,
    pub stt: Option<talk::Stt>,
    /// computer.act browser_* actions: a browser started with --remote-debugging-port
    /// (`http://127.0.0.1:9222`; loopback only).
    pub cdp_url: String,
    /// Plugins whose `node_commands` this node offers (`[plugins.<name>]` as in config.toml).
    pub plugins: BTreeMap<String, ark_plugin::McpServerConfig>,
}

pub(crate) fn which(bin: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join(bin)).find(|f| f.is_file()))
}

fn within(roots: &[PathBuf], p: &Path) -> bool {
    let Ok(c) = p.canonicalize() else { return false };
    roots.iter().any(|r| r.canonicalize().is_ok_and(|r| c.starts_with(r)))
}

/// Cancel flag and streamed stdin for one running invoke.
#[derive(Default)]
pub struct Ctl {
    pub cancel: Arc<AtomicBool>,
    /// `Some(bytes)` = write, `None` = close stdin.
    pub input: Option<mpsc::Receiver<Option<Vec<u8>>>>,
}

pub(crate) fn run_cmd(argv: &[&str], timeout: Duration) -> Result<String, String> {
    run_ctl(argv, timeout, &Ctl::default(), false)
}

thread_local! {
    /// Extra environment for commands spawned on this thread (`""` removes a variable).
    static ENV: std::cell::RefCell<Vec<(String, String)>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Run `f` with `env` applied to every command node.rs spawns on this thread
/// (computer_use on the Bot Desktop: its DISPLAY, XAUTHORITY and session bus).
pub(crate) fn with_env<R>(env: &[(String, String)], f: impl FnOnce() -> R) -> R {
    let prev = ENV.with(|e| std::mem::replace(&mut *e.borrow_mut(), env.to_vec()));
    let r = f();
    ENV.with(|e| *e.borrow_mut() = prev);
    r
}

fn x11_override() -> bool {
    ENV.with(|e| e.borrow().iter().any(|(k, v)| k == "DISPLAY" && !v.is_empty()))
}

fn run_ctl(argv: &[&str], timeout: Duration, ctl: &Ctl, stdin: bool) -> Result<String, String> {
    use std::process::Stdio;
    let mut cmd = std::process::Command::new(argv[0]);
    ENV.with(|e| {
        for (k, v) in e.borrow().iter() {
            if v.is_empty() {
                cmd.env_remove(k);
            } else {
                cmd.env(k, v);
            }
        }
    });
    let mut child = cmd.args(&argv[1..]).stdin(if stdin { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| format!("{}: {e}", argv[0]))?;
    let mut pipe = child.stdin.take();
    let deadline = Instant::now() + timeout;
    loop {
        if let (Some(rx), Some(_)) = (&ctl.input, &pipe) {
            for chunk in rx.try_iter() {
                use std::io::Write;
                match chunk {
                    Some(b) => {
                        if pipe.as_mut().is_some_and(|p| p.write_all(&b).and_then(|_| p.flush()).is_err()) {
                            pipe = None;
                        }
                    }
                    None => pipe = None,
                }
                if pipe.is_none() {
                    break;
                }
            }
        }
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            let out = child.wait_with_output().map_err(|e| e.to_string())?;
            let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
            let e = String::from_utf8_lossy(&out.stderr);
            if !e.trim().is_empty() {
                s.push_str(&format!("\n[stderr]\n{e}"));
            }
            s.truncate(64 * 1024);
            return if st.success() { Ok(s) } else { Err(format!("exit {}: {s}", st.code().unwrap_or(-1))) };
        }
        if ctl.cancel.load(Ordering::SeqCst) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("cancelled".into());
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("timed out".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Which input tool drives computer.act here.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Input {
    Xdotool,
    Ydotool,
}

pub(crate) fn input_backend() -> Option<Input> {
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
    match (wayland, which("xdotool").is_some(), which("ydotool").is_some()) {
        (true, _, true) => Some(Input::Ydotool),
        (false, true, _) if std::env::var_os("DISPLAY").is_some() => Some(Input::Xdotool),
        (_, _, true) => Some(Input::Ydotool),
        _ => None,
    }
}

/// Linux input event codes for ydotool (`key CODE:1 CODE:0`).
fn keycode(k: &str) -> Option<u16> {
    const LETTERS: &[u16] = &[30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38, 50, 49, 24, 25, 16, 19, 31, 20, 22, 47, 17, 45, 21, 44];
    const DIGITS: &[u16] = &[11, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let l = k.to_ascii_lowercase();
    if l.len() == 1 {
        let c = l.as_bytes()[0];
        return match c {
            b'a'..=b'z' => Some(LETTERS[(c - b'a') as usize]),
            b'0'..=b'9' => Some(DIGITS[(c - b'0') as usize]),
            b'-' => Some(12),
            b'=' => Some(13),
            b'[' => Some(26),
            b']' => Some(27),
            b';' => Some(39),
            b'\'' => Some(40),
            b',' => Some(51),
            b'.' => Some(52),
            b'/' => Some(53),
            b' ' => Some(57),
            _ => None,
        };
    }
    if let Some(n) = l.strip_prefix('f').and_then(|n| n.parse::<u16>().ok()).filter(|n| (1..=12).contains(n)) {
        return Some(if n <= 10 { 58 + n } else { 76 + n });
    }
    Some(match l.as_str() {
        "ctrl" | "control" | "control_l" => 29,
        "shift" | "shift_l" => 42,
        "alt" | "alt_l" | "option" => 56,
        "super" | "meta" | "cmd" | "win" | "super_l" => 125,
        "enter" | "return" => 28,
        "esc" | "escape" => 1,
        "tab" => 15,
        "space" => 57,
        "backspace" => 14,
        "delete" | "del" => 111,
        "insert" => 110,
        "home" => 102,
        "end" => 107,
        "pageup" | "page_up" | "prior" => 104,
        "pagedown" | "page_down" | "next" => 109,
        "up" => 103,
        "down" => 108,
        "left" => 105,
        "right" => 106,
        "capslock" | "caps_lock" => 58,
        "print" => 99,
        _ => return None,
    })
}

/// xdotool key names for the common aliases (`ctrl+c`, `cmd+enter` → `ctrl+c`, `super+Return`).
fn xkey(combo: &str) -> String {
    combo
        .split('+')
        .map(|k| match k.to_ascii_lowercase().as_str() {
            "cmd" | "meta" | "win" => "super".to_string(),
            "enter" => "Return".into(),
            "esc" => "Escape".into(),
            "backspace" => "BackSpace".into(),
            "del" => "Delete".into(),
            "pageup" => "Prior".into(),
            "pagedown" => "Next".into(),
            "up" | "down" | "left" | "right" | "home" | "end" | "tab" => {
                let mut c = k.to_ascii_lowercase();
                c[..1].make_ascii_uppercase();
                c
            }
            "space" => "space".into(),
            _ => k.to_string(),
        })
        .collect::<Vec<_>>()
        .join("+")
}

/// The commands to run for one computer.act step (OpenClaw's computer-use v1 actions).
pub fn computer_argv(b: Input, p: &Value) -> Result<Vec<Vec<String>>, String> {
    let action = p["action"].as_str().ok_or("computer.act needs `action`")?;
    let num = |k: &str| p[k].as_f64().map(|f| f.max(0.0).round() as i64);
    let xy = || -> Option<(String, String)> { Some((num("x")?.to_string(), num("y")?.to_string())) };
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let mut out: Vec<Vec<String>> = Vec::new();
    let mv = |out: &mut Vec<Vec<String>>| {
        if let Some((x, y)) = xy() {
            out.push(match b {
                Input::Xdotool => s(&["xdotool", "mousemove", "--sync", &x, &y]),
                Input::Ydotool => s(&["ydotool", "mousemove", "--absolute", "-x", &x, "-y", &y]),
            });
        }
    };
    let keys_of = |combo: &str| -> Result<Vec<u16>, String> { combo.split('+').map(|k| keycode(k).ok_or_else(|| format!("unknown key `{k}`"))).collect() };
    let ykeys = |codes: &[u16], down: bool, up: bool| -> Vec<String> {
        let mut v = s(&["ydotool", "key"]);
        if down {
            v.extend(codes.iter().map(|c| format!("{c}:1")));
        }
        if up {
            v.extend(codes.iter().rev().map(|c| format!("{c}:0")));
        }
        v
    };
    match action {
        "mouse_move" => {
            xy().ok_or("mouse_move needs x and y")?;
            mv(&mut out);
        }
        "left_click" | "right_click" | "middle_click" | "double_click" | "triple_click" => {
            mv(&mut out);
            let (btn, ybtn) = match action {
                "right_click" => ("3", "0xC1"),
                "middle_click" => ("2", "0xC2"),
                _ => ("1", "0xC0"),
            };
            let n = match action {
                "double_click" => 2,
                "triple_click" => 3,
                _ => 1,
            };
            let mods: Vec<String> = p["modifiers"].as_str().filter(|m| !m.is_empty()).map(|m| m.split('+').map(str::to_string).collect()).unwrap_or_default();
            match b {
                Input::Xdotool => {
                    let combo = xkey(&mods.join("+"));
                    if !mods.is_empty() {
                        out.push(s(&["xdotool", "keydown", &combo]));
                    }
                    out.push(s(&["xdotool", "click", "--repeat", &n.to_string(), btn]));
                    if !mods.is_empty() {
                        out.push(s(&["xdotool", "keyup", &combo]));
                    }
                }
                Input::Ydotool => {
                    let codes = keys_of(&mods.join("+")).unwrap_or_default();
                    if !mods.is_empty() {
                        out.push(ykeys(&codes, true, false));
                    }
                    out.push(s(&["ydotool", "click", "--repeat", &n.to_string(), ybtn]));
                    if !mods.is_empty() {
                        out.push(ykeys(&codes, false, true));
                    }
                }
            }
        }
        "left_mouse_down" | "left_mouse_up" => {
            mv(&mut out);
            let down = action == "left_mouse_down";
            out.push(match b {
                Input::Xdotool => s(&["xdotool", if down { "mousedown" } else { "mouseup" }, "1"]),
                Input::Ydotool => s(&["ydotool", "click", if down { "0x40" } else { "0x80" }]),
            });
        }
        "left_click_drag" => {
            let from = (num("fromX"), num("fromY"));
            let (Some(fx), Some(fy)) = from else { return Err("left_click_drag needs fromX, fromY, x, y".into()) };
            let (x, y) = xy().ok_or("left_click_drag needs fromX, fromY, x, y")?;
            match b {
                Input::Xdotool => {
                    out.push(s(&["xdotool", "mousemove", "--sync", &fx.to_string(), &fy.to_string(), "mousedown", "1"]));
                    out.push(s(&["xdotool", "mousemove", "--sync", &x, &y, "mouseup", "1"]));
                }
                Input::Ydotool => {
                    out.push(s(&["ydotool", "mousemove", "--absolute", "-x", &fx.to_string(), "-y", &fy.to_string()]));
                    out.push(s(&["ydotool", "click", "0x40"]));
                    out.push(s(&["ydotool", "mousemove", "--absolute", "-x", &x, "-y", &y]));
                    out.push(s(&["ydotool", "click", "0x80"]));
                }
            }
        }
        "scroll" => {
            mv(&mut out);
            let dir = p["scrollDirection"].as_str().unwrap_or("down");
            let n = p["scrollAmount"].as_u64().unwrap_or(3).clamp(1, 50);
            match b {
                Input::Xdotool => {
                    let btn = match dir {
                        "up" => "4",
                        "left" => "6",
                        "right" => "7",
                        _ => "5",
                    };
                    out.push(s(&["xdotool", "click", "--repeat", &n.to_string(), btn]));
                }
                Input::Ydotool => {
                    let (h, v) = match dir {
                        "up" => (0, n as i64),
                        "left" => (-(n as i64), 0),
                        "right" => (n as i64, 0),
                        _ => (0, -(n as i64)),
                    };
                    out.push(s(&["ydotool", "mousemove", "--wheel", "-x", &h.to_string(), "-y", &v.to_string()]));
                }
            }
        }
        "type" => {
            let t = p["text"].as_str().ok_or("type needs text")?;
            if t.len() > 4000 {
                return Err("text longer than 4000 bytes".into());
            }
            out.push(match b {
                Input::Xdotool => s(&["xdotool", "type", "--delay", "8", "--", t]),
                Input::Ydotool => s(&["ydotool", "type", "--", t]),
            });
        }
        "key" | "hold_key" => {
            let combos = p["keys"].as_str().filter(|k| !k.trim().is_empty()).ok_or("key needs keys (e.g. ctrl+c)")?;
            let hold = p["durationMs"].as_u64().unwrap_or(500).min(10_000);
            for combo in combos.split_whitespace() {
                match (b, action) {
                    (Input::Xdotool, "key") => out.push(s(&["xdotool", "key", "--", &xkey(combo)])),
                    (Input::Xdotool, _) => {
                        out.push(s(&["xdotool", "keydown", &xkey(combo)]));
                        out.push(s(&["sleep", &format!("{:.3}", hold as f64 / 1000.0)]));
                        out.push(s(&["xdotool", "keyup", &xkey(combo)]));
                    }
                    (Input::Ydotool, "key") => out.push(ykeys(&keys_of(combo)?, true, true)),
                    (Input::Ydotool, _) => {
                        let codes = keys_of(combo)?;
                        out.push(ykeys(&codes, true, false));
                        out.push(s(&["sleep", &format!("{:.3}", hold as f64 / 1000.0)]));
                        out.push(ykeys(&codes, false, true));
                    }
                }
            }
        }
        "wait" => out.push(s(&["sleep", &format!("{:.3}", p["durationMs"].as_u64().unwrap_or(1000).min(30_000) as f64 / 1000.0)])),
        "get_cursor_position" => match b {
            Input::Xdotool => out.push(s(&["xdotool", "getmouselocation", "--shell"])),
            Input::Ydotool => return Err("get_cursor_position is not available with ydotool (Wayland)".into()),
        },
        other => return Err(format!("computer.act action `{other}` is not supported on Linux")),
    }
    Ok(out)
}

/// Commands this host offers under `policy`.
pub fn host_commands(policy: &HostPolicy) -> Vec<&'static str> {
    let mut c = vec!["system.which", "system.notify", "device.info", "fs.listDir", "file.fetch"];
    if policy.run != "deny" && !policy.run.is_empty() {
        c.push("system.run");
    }
    let shot = which("grim").is_some() || which("import").is_some();
    if policy.screen && shot {
        c.push("screen.snapshot");
    }
    if policy.screen && (which("ffmpeg").is_some() || which("wf-recorder").is_some()) {
        c.push("screen.record");
    }
    if policy.camera && which("ffmpeg").is_some() {
        c.extend(["camera.list", "camera.snap"]);
    }
    if policy.location {
        c.push("location.get");
    }
    if policy.computer && (input_backend().is_some() || which("gdbus").is_some() || !policy.cdp_url.is_empty()) {
        c.push("computer.act");
    }
    if policy.microphone && policy.stt.is_some() && talk::available() {
        c.extend(["talk.ptt.start", "talk.ptt.stop", "talk.ptt.cancel", "talk.ptt.once"]);
    }
    if policy.canvas && which("xdg-open").is_some() {
        c.push("canvas.present");
    }
    if policy.notifications && (which("dunstctl").is_some() || which("makoctl").is_some()) {
        c.extend(["notifications.list", "notifications.actions"]);
    }
    c.extend(crate::surfaces::canvas::node_commands(policy.canvas, !policy.cdp_url.is_empty()).into_iter().filter(|x| !c.contains(x)).collect::<Vec<_>>());
    c.extend(["dir.list", "dir.fetch"].into_iter().chain((!policy.write_roots.is_empty()).then_some("file.write")));
    c.extend(crate::session_share::node_commands());
    if policy.canvas && !policy.cdp_url.is_empty() && !c.contains(&"canvas.present") {
        c.push("canvas.present");
    }
    c
}

pub(crate) fn tmp_file(tag: &str, ext: &str) -> PathBuf {
    let dir = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|d| d.is_dir()).unwrap_or_else(std::env::temp_dir);
    dir.join(format!("ark-{tag}-{}-{}.{ext}", std::process::id(), ark_net::crypto::random_token(6)))
}

pub(crate) fn snapshot(t: Duration) -> Result<Vec<u8>, String> {
    let tmp = tmp_file("shot", "png");
    let path = tmp.display().to_string();
    if which("grim").is_some() && !x11_override() { run_cmd(&["grim", &path], t) } else { run_cmd(&["import", "-window", "root", &path], t) }?;
    let b = std::fs::read(&tmp).map_err(|e| e.to_string());
    let _ = std::fs::remove_file(&tmp);
    b
}

pub fn host_run(policy: &HostPolicy, command: &str, p: &Value) -> Result<Value, String> {
    host_run_ctl(policy, command, p, &Ctl::default())
}

pub fn host_run_ctl(policy: &HostPolicy, command: &str, p: &Value, ctl: &Ctl) -> Result<Value, String> {
    let t = Duration::from_millis(p["timeoutMs"].as_u64().unwrap_or(30_000).min(300_000));
    match command {
        // Canvas over DevTools and file transfer (surfaces::canvas, surfaces::file_transfer).
        c if crate::surfaces::canvas::node_handles(policy.canvas, !policy.cdp_url.is_empty(), c) => crate::surfaces::canvas::node_run(&policy.cdp_url, c, p, t),
        c @ ("file.fetch" | "dir.list" | "dir.fetch" | "file.write") => crate::surfaces::file_transfer::node_run(&policy.read_roots, &policy.write_roots, c, p),
        c if crate::session_share::handles(c) => crate::session_share::node_run(c, p),
        "system.which" => Ok(json!(which(p["bin"].as_str().unwrap_or("")).map(|x| x.display().to_string()))),
        "system.notify" => run_cmd(&["notify-send", p["title"].as_str().unwrap_or("ark"), p["body"].as_str().unwrap_or("")], t).map(|_| json!("shown")),
        "device.info" => Ok(json!({"hostname": std::fs::read_to_string("/etc/hostname").unwrap_or_default().trim(), "os": std::env::consts::OS, "arch": std::env::consts::ARCH, "kernel": std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim(), "commands": host_commands(policy)})),
        "fs.listDir" => {
            let d = PathBuf::from(p["path"].as_str().unwrap_or("."));
            if !within(&policy.read_roots, &d) {
                return Err("path is outside the node's read_roots".into());
            }
            let mut out: Vec<Value> = std::fs::read_dir(&d).map_err(|e| e.to_string())?.flatten().take(500).map(|e| json!({"name": e.file_name().to_string_lossy(), "dir": e.file_type().map(|t| t.is_dir()).unwrap_or(false)})).collect();
            out.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
            Ok(json!(out))
        }
        "system.run" => {
            let cmd = p["command"].as_str().unwrap_or("");
            let first = cmd.split_whitespace().next().unwrap_or("");
            match policy.run.as_str() {
                "full" => {}
                "allowlist" if policy.allow.iter().any(|a| a == first || a == cmd) => {}
                _ => return Err(format!("`{first}` is not allowed on this node (run policy: {})", if policy.run.is_empty() { "deny" } else { &policy.run })),
            }
            run_ctl(&["sh", "-c", cmd], t, ctl, p["stdin"] == true).map(Value::String)
        }
        "screen.snapshot" if policy.screen => Ok(json!({"mime": "image/png", "base64": ark_net::crypto::b64(&snapshot(t)?)})),
        "screen.record" if policy.screen => {
            let ms = p["durationMs"].as_u64().unwrap_or(5000).clamp(500, 60_000);
            let fps = p["fps"].as_u64().unwrap_or(10).clamp(1, 30).to_string();
            let tmp = tmp_file("rec", "mp4");
            let path = tmp.display().to_string();
            let secs = format!("{:.1}", ms as f64 / 1000.0);
            let budget = Duration::from_millis(ms + 20_000);
            let r = if std::env::var_os("WAYLAND_DISPLAY").is_some() && which("wf-recorder").is_some() {
                // wf-recorder records until interrupted: `timeout -s INT` ends it cleanly.
                run_ctl(&["timeout", "-s", "INT", &secs, "wf-recorder", "-y", "-r", &fps, "-f", &path], budget, ctl, false).or_else(|e| if tmp.exists() { Ok(String::new()) } else { Err(e) })
            } else {
                let display = std::env::var("DISPLAY").map_err(|_| "screen.record needs X11 ($DISPLAY) or wf-recorder on Wayland")?;
                run_ctl(&["ffmpeg", "-loglevel", "error", "-y", "-f", "x11grab", "-framerate", &fps, "-i", &display, "-t", &secs, "-pix_fmt", "yuv420p", &path], budget, ctl, false)
            };
            let b = r.and_then(|_| std::fs::read(&tmp).map_err(|e| e.to_string()));
            let _ = std::fs::remove_file(&tmp);
            let b = b?;
            if b.len() > 24 << 20 {
                return Err("recording larger than 24 MB; record less".into());
            }
            Ok(json!({"mime": "video/mp4", "durationMs": ms, "base64": ark_net::crypto::b64(&b)}))
        }
        "computer.act" if policy.computer => {
            let action = p["action"].as_str().unwrap_or("");
            let pointer = !p["x"].is_null() || !p["y"].is_null();
            match action {
                "screenshot" => return Ok(json!({"mime": "image/png", "base64": ark_net::crypto::b64(&snapshot(t)?)})),
                // v2: accessibility tree and element actions (AT-SPI).
                "list_apps" | "list_windows" | "get_accessibility_tree" | "get_window_state" | "set_value" | "bring_to_front" => return a11y::act(p),
                "left_click" | "double_click" if !pointer && p["elementRef"].is_string() && p["pageRef"].is_null() => return a11y::act(p),
                // v2: browser actions (CDP).
                "get_browser_state" | "browser_navigate" | "browser_click" | "browser_type" => return cdp::act(&policy.cdp_url, p),
                "launch_app" => {
                    let app = p["app"].as_str().filter(|a| !a.is_empty() && !a.starts_with('-') && a.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))).ok_or("launch_app needs `app`: a desktop entry id such as org.gnome.TextEditor")?;
                    which("gtk-launch").ok_or("launch_app needs gtk-launch (GTK 3)")?;
                    run_cmd(&["gtk-launch", app], t)?;
                    return Ok(json!({"ok": true, "app": app}));
                }
                "kill_app" | "zoom" | "invoke_menu" | "browser_prepare" | "browser_dialog" | "browser_set_input_files" | "browser_download" | "browser_pointer" | "escalate_scope" | "get_recording_state" | "start_recording" | "stop_recording" | "replay_trajectory" => {
                    return Err(format!("computer.act action `{action}` is not available on Linux nodes"));
                }
                _ => {}
            }
            let b = input_backend().ok_or("no input tool: install xdotool (X11) or ydotool (Wayland, needs ydotoold)")?;
            let mut out = String::new();
            for argv in computer_argv(b, p)? {
                let a: Vec<&str> = argv.iter().map(String::as_str).collect();
                out.push_str(&run_ctl(&a, t, ctl, false)?);
            }
            if p["action"] == "get_cursor_position" {
                let get = |k: &str| out.lines().find_map(|l| l.strip_prefix(k)).and_then(|v| v.trim().parse::<i64>().ok());
                return Ok(json!({"x": get("X="), "y": get("Y=")}));
            }
            Ok(json!({"ok": true, "action": p["action"], "backend": format!("{b:?}").to_lowercase()}))
        }
        "canvas.present" if policy.canvas => {
            let target = match (p["url"].as_str(), p["html"].as_str()) {
                (Some(u), _) if u.starts_with("https://") || u.starts_with("http://") => u.to_string(),
                (Some(_), _) => return Err("canvas.present url must be http(s)".into()),
                (None, Some(h)) => {
                    if h.len() > 4 << 20 {
                        return Err("html larger than 4 MB".into());
                    }
                    let f = tmp_file("canvas", "html");
                    write_private(&f, h.as_bytes()).map_err(|e| e.to_string())?;
                    format!("file://{}", f.display())
                }
                (None, None) => return Err("canvas.present needs url or html".into()),
            };
            std::process::Command::new("xdg-open").arg(&target).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().map_err(|e| format!("xdg-open: {e}"))?;
            Ok(json!({"presented": target}))
        }
        "notifications.list" if policy.notifications => {
            if which("makoctl").is_some() {
                let v: Value = serde_json::from_str(&run_cmd(&["makoctl", "history"], t)?).map_err(|e| format!("makoctl history: {e}"))?;
                let items = v["data"][0].as_array().cloned().unwrap_or_default();
                Ok(json!(items.iter().map(|n| json!({"id": n["id"]["data"], "app": n["app-name"]["data"], "title": n["summary"]["data"], "body": n["body"]["data"]})).collect::<Vec<_>>()))
            } else {
                let v: Value = serde_json::from_str(&run_cmd(&["dunstctl", "history"], t)?).map_err(|e| format!("dunstctl history: {e}"))?;
                let items = v["data"][0].as_array().cloned().unwrap_or_default();
                let limit = p["limit"].as_u64().unwrap_or(50) as usize;
                Ok(json!(items.iter().take(limit).map(|n| json!({"id": n["id"]["data"], "app": n["appname"]["data"], "title": n["summary"]["data"], "body": n["body"]["data"]})).collect::<Vec<_>>()))
            }
        }
        "notifications.actions" if policy.notifications => {
            let id = match &p["id"] {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => String::new(),
            };
            if !id.chars().all(|c| c.is_ascii_digit()) {
                return Err("id must be numeric".into());
            }
            let action = p["action"].as_str().unwrap_or("");
            let mako = which("makoctl").is_some();
            let argv: Vec<&str> = match (action, mako, id.is_empty()) {
                ("dismiss_all", true, _) => vec!["makoctl", "dismiss", "--all"],
                ("dismiss_all", false, _) => vec!["dunstctl", "close-all"],
                ("dismiss", true, false) => vec!["makoctl", "dismiss", "-n", &id],
                ("dismiss", false, false) => vec!["dunstctl", "history-rm", &id],
                ("dismiss", true, true) => vec!["makoctl", "dismiss"],
                ("dismiss", false, true) => vec!["dunstctl", "close"],
                ("invoke", true, false) => vec!["makoctl", "invoke", "-n", &id],
                ("invoke", false, _) => vec!["dunstctl", "action"],
                _ => return Err("action must be dismiss, dismiss_all or invoke (with id)".into()),
            };
            run_cmd(&argv, t).map(|_| json!({"ok": true}))
        }
        "camera.list" if policy.camera => Ok(json!(std::fs::read_dir("/dev").map(|d| d.flatten().filter_map(|e| e.file_name().to_str().filter(|n| n.starts_with("video")).map(|n| format!("/dev/{n}"))).collect::<Vec<_>>()).unwrap_or_default())),
        "camera.snap" if policy.camera => {
            let dev = p["device"].as_str().unwrap_or("/dev/video0");
            if !dev.starts_with("/dev/video") {
                return Err("device must be /dev/videoN".into());
            }
            let tmp = tmp_file("cam", "jpg");
            run_cmd(&["ffmpeg", "-loglevel", "error", "-y", "-f", "v4l2", "-i", dev, "-frames:v", "1", &tmp.display().to_string()], t)?;
            let b = std::fs::read(&tmp).map_err(|e| e.to_string());
            let _ = std::fs::remove_file(&tmp);
            Ok(json!({"mime": "image/jpeg", "base64": ark_net::crypto::b64(&b?)}))
        }
        c if c.starts_with("talk.ptt.") && policy.microphone => talk::run(policy.stt.as_ref(), c, p),
        "location.get" if policy.location => run_cmd(&["sh", "-c", "command -v where-am-i >/dev/null && where-am-i -t 10 || /usr/libexec/geoclue-2.0/demos/where-am-i -t 10"], t).map(Value::String),
        other => Err(format!("unknown or disabled command `{other}`")),
    }
}

/// Start node.toml's plugins; their `node_commands` (minus built-in names) with metadata.
fn node_plugins(policy: &HostPolicy) -> (Vec<Arc<ark_plugin::PluginHost>>, BTreeMap<String, Value>) {
    let mut hosts = Vec::new();
    let mut meta = BTreeMap::new();
    for (n, c) in &policy.plugins {
        match ark_plugin::PluginHost::start(n, c, ark_plugin::no_secrets()) {
            Ok(h) => {
                for d in h.node_commands.iter().filter(|d| schema_of(&d.command).is_none() && !host_commands(policy).contains(&d.command.as_str())) {
                    meta.entry(d.command.clone()).or_insert_with(|| json!({"description": d.description, "dangerous": d.dangerous, "params": d.params, "plugin": n}));
                }
                hosts.push(Arc::new(h));
            }
            Err(e) => eprintln!("ark node: plugin {n}: {e}"),
        }
    }
    (hosts, meta)
}

/// How `ark node` reaches the server.
pub struct HostConn {
    pub url: String,
    pub id: String,
    pub name: String,
    /// Ed25519 PKCS#8 key file (created on first run).
    pub key_path: PathBuf,
    pub token_path: PathBuf,
    /// From a setup code: approves this device on first connect.
    pub bootstrap: Option<String>,
    /// From a setup code: the server certificate must have this SHA-256.
    pub tls_fingerprint: Option<String>,
}

struct Running {
    cancel: Arc<AtomicBool>,
    input: mpsc::Sender<Option<Vec<u8>>>,
}

/// Run this machine as a node until the connection drops.
pub fn run_host(c: &HostConn, policy: &HostPolicy) -> Result<(), String> {
    use ring::signature::KeyPair;
    let pkcs8 = match std::fs::read(&c.key_path) {
        Ok(b) => b,
        Err(_) => {
            let rng = ring::rand::SystemRandom::new();
            let doc = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| "keygen failed")?;
            write_private(&c.key_path, doc.as_ref()).map_err(|e| e.to_string())?;
            doc.as_ref().to_vec()
        }
    };
    let kp = ring::signature::Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| format!("{} is not an Ed25519 key", c.key_path.display()))?;
    let (mut ws, _) = WebSocket::connect(&c.url, &[], Duration::from_secs(15)).map_err(|e| format!("connect {}: {e}", c.url))?;
    if let Some(want) = &c.tls_fingerprint {
        match ws.get_ref().peer_fingerprint() {
            Some(got) if ark_net::crypto::ct_eq(got.as_bytes(), want.as_bytes()) => {}
            Some(got) => return Err(format!("server certificate fingerprint {got} does not match the setup code; refusing to connect")),
            None => return Err("the setup code pins a TLS certificate but the URL is not wss://".into()),
        }
    }
    ws.set_max_message(32 * 1024 * 1024);
    ws.set_read_timeout(Some(Duration::from_millis(100))).ok();
    let mut token = std::fs::read_to_string(&c.token_path).unwrap_or_default().trim().to_string();
    let mut cmds: Vec<String> = host_commands(policy).into_iter().map(str::to_string).collect();
    let (plugins, meta) = node_plugins(policy);
    for c in meta.keys() {
        if !cmds.contains(c) {
            cmds.push(c.clone());
        }
    }
    let plugins = Arc::new(plugins);
    let (out_tx, out_rx) = mpsc::channel::<Value>();
    let running: Arc<Mutex<HashMap<String, Running>>> = Arc::default();
    let policy = Arc::new(policy.clone());
    let start = |rid: Value, command: String, params: Value, ack: bool| {
        let id = rid.as_str().unwrap_or("").to_string();
        let (itx, irx) = mpsc::channel();
        let ctl = Ctl { cancel: Arc::default(), input: Some(irx) };
        running.lock().unwrap().insert(id.clone(), Running { cancel: ctl.cancel.clone(), input: itx });
        let (out, pol, run, plugs) = (out_tx.clone(), policy.clone(), running.clone(), plugins.clone());
        std::thread::spawn(move || {
            let r = match plugs.iter().find(|p| p.node_commands.iter().any(|c| c.command == command)) {
                // Plugin commands never shadow the built-in ones (node_plugins skips those names).
                Some(p) => p.node_invoke(&command, params.clone(), Duration::from_millis(params["timeoutMs"].as_u64().unwrap_or(60_000).clamp(1_000, 600_000))),
                None => host_run_ctl(&pol, &command, &params, &ctl),
            };
            let msg = match r {
                Ok(payload) => json!({"jsonrpc": "2.0", "method": "node.invoke.result", "params": {"id": rid, "ok": true, "payload": payload}}),
                Err(e) => json!({"jsonrpc": "2.0", "method": "node.invoke.result", "params": {"id": rid, "ok": false, "error": {"code": if ctl.cancel.load(Ordering::SeqCst) { "ABORTED" } else { "FAILED" }, "message": e}}}),
            };
            let _ = out.send(msg);
            if ack {
                let _ = out.send(json!({"jsonrpc": "2.0", "id": "ack", "method": "node.pending.ack", "params": {"ids": [rid]}}));
            }
            run.lock().unwrap().remove(&id);
        });
    };
    loop {
        for m in out_rx.try_iter() {
            ws.send_text(&m.to_string()).map_err(|e| e.to_string())?;
        }
        let m = match ws.recv() {
            Ok(None) => continue,
            Ok(Some(Message::Text(t))) => t,
            Ok(Some(Message::Close(_))) => return Ok(()),
            Ok(Some(_)) => continue,
            Err(e) => return Err(format!("connection lost: {e}")),
        };
        let v: Value = serde_json::from_str(&m).map_err(|e| e.to_string())?;
        let p = &v["params"];
        match v["method"].as_str() {
            Some("connect.challenge") => {
                let nonce = p["nonce"].as_str().unwrap_or("");
                let sig = kp.sign(signed_message(&c.id, nonce).as_bytes());
                let mut hello = json!({"jsonrpc": "2.0", "id": 1, "method": "node.connect", "params": {
                    "id": c.id, "name": c.name, "platform": format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
                    "caps": ["system", "fs", "device"], "commands": cmds, "commandMeta": meta,
                    "publicKey": ark_net::crypto::hex(kp.public_key().as_ref()), "signature": ark_net::crypto::hex(sig.as_ref()), "deviceToken": token,
                }});
                // Ignored by the server once this device is paired (the device token decides then).
                if let Some(b) = &c.bootstrap {
                    hello["params"]["bootstrapToken"] = json!(b);
                }
                ws.send_text(&hello.to_string()).map_err(|e| e.to_string())?;
            }
            Some("node.pair.resolved") => {
                token = p["deviceToken"].as_str().unwrap_or("").to_string();
                write_private(&c.token_path, token.as_bytes()).map_err(|e| e.to_string())?;
                eprintln!("ark node: paired; reconnecting");
                return run_host(&HostConn { bootstrap: None, url: c.url.clone(), id: c.id.clone(), name: c.name.clone(), key_path: c.key_path.clone(), token_path: c.token_path.clone(), tls_fingerprint: c.tls_fingerprint.clone() }, &policy);
            }
            Some("node.token.rotated") => {
                token = p["deviceToken"].as_str().unwrap_or("").to_string();
                write_private(&c.token_path, token.as_bytes()).map_err(|e| e.to_string())?;
                eprintln!("ark node: device token rotated");
            }
            Some("node.invoke.request") => start(p["id"].clone(), p["command"].as_str().unwrap_or("").to_string(), p["params"].clone(), false),
            Some("node.invoke.cancel") => {
                if let Some(r) = running.lock().unwrap().get(p["id"].as_str().unwrap_or("")) {
                    r.cancel.store(true, Ordering::SeqCst);
                }
            }
            Some("node.invoke.input") => {
                if let Some(r) = running.lock().unwrap().get(p["id"].as_str().unwrap_or("")) {
                    if let Some(d) = p["data"].as_str() {
                        let _ = r.input.send(Some(d.as_bytes().to_vec()));
                    }
                    if p["eof"] == true {
                        let _ = r.input.send(None);
                    }
                }
            }
            Some("node.pending") => ws.send_text(&json!({"jsonrpc": "2.0", "id": "pull", "method": "node.pending.pull"}).to_string()).map_err(|e| e.to_string())?,
            None if v["id"] == "pull" => {
                for a in v["result"]["actions"].as_array().cloned().unwrap_or_default() {
                    start(a["id"].clone(), a["command"].as_str().unwrap_or("").to_string(), a["params"].clone(), true);
                }
            }
            None if v["id"] == "drain" => {
                for w in v["result"]["items"].as_array().cloned().unwrap_or_default() {
                    let (event, payload) = match w["type"].as_str() {
                        Some("location.request") => ("location", host_run(&policy, "location.get", &json!({})).unwrap_or_else(|e| json!({"error": e}))),
                        _ => ("status", host_run(&policy, "device.info", &json!({})).unwrap_or_default()),
                    };
                    let _ = out_tx.send(json!({"jsonrpc": "2.0", "method": "node.event", "params": {"event": event, "payload": payload, "workId": w["id"]}}));
                }
            }
            None if v["id"] == 1 => {
                if let Some(pair) = v["result"].get("pairing") {
                    eprintln!("ark node: waiting for approval — on the server run: ark nodes approve {}", pair["code"].as_str().unwrap_or("?"));
                } else if v["result"]["paired"] == true {
                    eprintln!("ark node: setup code accepted");
                } else if v["result"]["connected"] == true {
                    eprintln!("ark node: connected as {} with {}", c.id, cmds.join(", "));
                    // Work that piled up while we were away.
                    ws.send_text(&json!({"jsonrpc": "2.0", "id": "drain", "method": "node.pending.drain", "params": {"maxItems": 10}}).to_string()).map_err(|e| e.to_string())?;
                } else if let Some(e) = v.get("error") {
                    return Err(format!("refused: {}", e["message"]));
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ent-059: a verified SPIFFE ID pairs a new node without a code, then replaces its device
    /// token; another identity (or none) cannot take the node over.
    #[test]
    fn spiffe_workload_identity_replaces_the_node_token() {
        use ring::signature::KeyPair;
        let rng = ring::rand::SystemRandom::new();
        let kp = ring::signature::Ed25519KeyPair::from_pkcs8(ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref()).unwrap();
        let id = format!("wl-{}", ark_net::crypto::random_token(6));
        let hello = |nonce: &str, token: &str| {
            json!({"id": id, "name": "build-agent", "platform": "linux", "commands": [], "publicKey": ark_net::crypto::hex(kp.public_key().as_ref()), "signature": ark_net::crypto::hex(kp.sign(signed_message(&id, nonce).as_bytes()).as_ref()), "deviceToken": token})
        };
        let (tx, _rx) = mpsc::channel();
        let svid = "spiffe://example.org/ark/node/build-1";
        // New device + allowed identity: paired and live at once, no pairing code.
        match connect(&hello("n1", ""), "n1", &tx, Some(svid)).unwrap() {
            Conn::Live(got) => assert_eq!(got, id),
            _ => panic!("expected a live node"),
        }
        assert_eq!(reg().lock().unwrap().paired[&id].workload_id.as_deref(), Some(svid));
        reg().lock().unwrap().live.remove(&id);
        // Reconnect with the same SVID and no token: accepted.
        assert!(matches!(connect(&hello("n2", ""), "n2", &tx, Some(svid)), Ok(Conn::Live(_))));
        reg().lock().unwrap().live.remove(&id);
        // Without the SVID, or with another one: refused, even with a guessed token.
        assert!(connect(&hello("n3", "guess"), "n3", &tx, None).err().unwrap_or_default().contains("bound to workload identity"));
        assert!(connect(&hello("n4", ""), "n4", &tx, Some("spiffe://example.org/ark/node/other")).is_err());
        // A second node id cannot reuse a bound identity.
        let mut other = hello("n5", "");
        other["id"] = json!(format!("{id}-b"));
        assert!(connect(&other, "n5", &tx, Some(svid)).is_err());
        reg().lock().unwrap().paired.remove(&id);
    }

    #[test]
    fn setup_code_matches_openclaw_format() {
        let sc = SetupCode { url: "wss://gw.example:8640/node".into(), bootstrap_token: "tok".into(), expires_at_ms: Some(2_000), tls_fingerprint: Some("AB:".repeat(31) + "AB") };
        let code = sc.encode();
        let raw = String::from_utf8(ark_net::crypto::b64url_decode(&code).unwrap()).unwrap();
        assert!(raw.contains("\"bootstrapToken\":\"tok\"") && raw.contains("\"expiresAtMs\":2000") && raw.contains("\"tlsFingerprint\""), "{raw}");
        assert!(!code.contains(['+', '/', '=']), "base64url without padding");
        let back = SetupCode::decode(&format!("oc-pair://{code}"), 1_000).unwrap();
        assert_eq!(back.tls_fingerprint.as_deref(), Some("ab".repeat(32).as_str()), "normalized");
        assert!(SetupCode::decode(&code, 2_000).unwrap_err().contains("expired"));
        assert!(SetupCode::decode("not a code!", 0).is_err());
        let http = SetupCode { url: "http://x".into(), ..back.clone() }.encode();
        assert!(SetupCode::decode(&http, 0).is_err(), "ws/wss only");
        assert_eq!(normalize_fingerprint(&format!("sha256:{}", "0F".repeat(32))), Some("0f".repeat(32)));
        assert_eq!(normalize_fingerprint("abc"), None);
    }

    #[test]
    fn queue_ttl_dedup_and_command_filter() {
        let mut r = Registry::default();
        assert!(enqueue(&mut r, "n", "device.info", json!({}), 1000, 0).is_err(), "unpaired");
        r.paired.insert("n".into(), Paired { name: "n".into(), public_key: String::new(), token_hash: String::new(), salt: String::new(), approved_at: 0, platform: String::new(), commands: vec!["device.info".into(), "photos.latest".into()], token_rotated_at: 0, meta: BTreeMap::new(), workload_id: None });
        assert!(enqueue(&mut r, "n", "system.run", json!({}), 1000, 0).unwrap_err().contains("did not offer"));
        let a = enqueue(&mut r, "n", "device.info", json!({}), 5_000, 0).unwrap();
        let b = enqueue(&mut r, "n", "photos.latest", json!({"limit": 1}), 60_000, 0).unwrap();
        assert!(a.id.starts_with("q-"));
        assert_eq!(pull(&mut r, "n", 1_000).len(), 2);
        assert_eq!(pull(&mut r, "n", 6_000).len(), 1, "expired after its TTL");
        assert_eq!(ack(&mut r, "n", std::slice::from_ref(&b.id)), 0);
        // Work items: one per type, priority order, drained in pages.
        let (w1, d1) = enqueue_work(&mut r, "n", "status.request", "normal", 1000, 0).unwrap();
        let (w2, d2) = enqueue_work(&mut r, "n", "status.request", "high", 1000, 0).unwrap();
        assert!(!d1 && d2 && w1.id == w2.id, "deduped");
        enqueue_work(&mut r, "n", "location.request", "high", 1000, 0).unwrap();
        assert!(enqueue_work(&mut r, "n", "reboot", "high", 1000, 0).is_err());
        let (items, more, _) = drain(&mut r, "n", 1, 10);
        assert_eq!((items[0].kind.as_str(), more), ("location.request", true));
        let (items, more, _) = drain(&mut r, "n", 5, 10);
        assert_eq!((items.len(), more), (1, false));
        enqueue_work(&mut r, "n", "status.request", "normal", 100, 0).unwrap();
        assert!(drain(&mut r, "n", 5, 2_000).0.is_empty(), "expired work is dropped");
    }

    /// A pairing code goes stale after an hour: it disappears from the list and can neither
    /// be approved nor rejected any more (the device has to reconnect).
    #[test]
    fn stale_pairing_codes_cannot_be_approved() {
        let id = format!("stale-{}", ark_net::crypto::random_token(4));
        let code = request_pairing(&id, "old phone", "ios", &"ab".repeat(32)).unwrap();
        let f = methods();
        let listed = |f: &ark_kernel::daemon::MethodExt| f("node.pair.list", &json!({})).unwrap().unwrap().as_array().unwrap().iter().any(|p| p["code"] == code.as_str());
        assert!(listed(&f), "a fresh request is listed");
        // Age it past PAIR_TTL: no test waits an hour.
        {
            let mut r = reg().lock().unwrap();
            for p in r.pending.iter_mut().filter(|p| p.id == id) {
                p.created = Instant::now() - PAIR_TTL - Duration::from_secs(1);
            }
        }
        assert!(!listed(&f), "an expired request is hidden from `node.pair.list`");
        let (num, msg) = f("node.pair.approve", &json!({"code": code})).unwrap().unwrap_err();
        assert_eq!(num, -32001);
        assert!(msg.contains("expired"), "{msg}");
        assert_eq!(f("node.pair.reject", &json!({"code": code})).unwrap().unwrap()["rejected"], false);
    }

    #[test]
    fn schemas_validate_and_flag_dangerous_commands() {
        let s = schema_of("contacts.search").unwrap();
        assert!(validate(s, &json!({"query": "amy", "limit": 5})).is_ok());
        assert!(validate(s, &json!({"limit": 5})).unwrap_err().contains("query"));
        assert!(validate(s, &json!({"query": 3})).unwrap_err().contains("string"));
        assert!(validate(s, &json!({"query": "a", "extra": true})).is_ok(), "unknown keys pass through");
        assert!(dangerous("sms.send") && dangerous("computer.act") && !dangerous("photos.latest") && !dangerous("my.custom"));
        let t = NodeInvoke;
        let ctx_free = |input: Value| match (input["action"].as_str(), input["command"].as_str()) {
            (Some("invoke"), Some(c)) if dangerous(c) => "remote",
            _ => "other",
        };
        assert_eq!(ctx_free(json!({"action": "invoke", "command": "contacts.add"})), "remote");
        assert_eq!(t.spec().name, "node_invoke");
        assert_eq!(schema_json(s)["required"], json!(["query"]));
    }

    #[test]
    fn computer_act_maps_to_xdotool_and_ydotool() {
        let x = |p: Value| computer_argv(Input::Xdotool, &p).unwrap().into_iter().map(|a| a.join(" ")).collect::<Vec<_>>();
        let y = |p: Value| computer_argv(Input::Ydotool, &p).unwrap().into_iter().map(|a| a.join(" ")).collect::<Vec<_>>();
        assert_eq!(x(json!({"action": "left_click", "x": 10.4, "y": 20})), ["xdotool mousemove --sync 10 20", "xdotool click --repeat 1 1"]);
        assert_eq!(x(json!({"action": "double_click"})), ["xdotool click --repeat 2 1"]);
        assert_eq!(x(json!({"action": "right_click", "x": 1, "y": 2, "modifiers": "ctrl+shift"})), ["xdotool mousemove --sync 1 2", "xdotool keydown ctrl+shift", "xdotool click --repeat 1 3", "xdotool keyup ctrl+shift"]);
        assert_eq!(x(json!({"action": "key", "keys": "cmd+enter ctrl+c"})), ["xdotool key -- super+Return", "xdotool key -- ctrl+c"]);
        assert_eq!(x(json!({"action": "type", "text": "-rf hi"})), ["xdotool type --delay 8 -- -rf hi"]);
        assert_eq!(x(json!({"action": "scroll", "scrollDirection": "up", "scrollAmount": 2})), ["xdotool click --repeat 2 4"]);
        assert_eq!(y(json!({"action": "left_click", "x": 5, "y": 6})), ["ydotool mousemove --absolute -x 5 -y 6", "ydotool click --repeat 1 0xC0"]);
        assert_eq!(y(json!({"action": "key", "keys": "ctrl+c"})), ["ydotool key 29:1 46:1 46:0 29:0"]);
        assert_eq!(y(json!({"action": "scroll"})), ["ydotool mousemove --wheel -x 0 -y -3"]);
        assert_eq!(y(json!({"action": "left_click_drag", "fromX": 1, "fromY": 2, "x": 3, "y": 4})).len(), 4);
        assert_eq!(keycode("F12"), Some(88));
        assert_eq!(keycode("f1"), Some(59));
        assert!(computer_argv(Input::Ydotool, &json!({"action": "key", "keys": "hyper"})).is_err());
        assert!(computer_argv(Input::Ydotool, &json!({"action": "get_cursor_position"})).is_err());
        assert!(computer_argv(Input::Xdotool, &json!({"action": "launch_app"})).is_err());
        assert!(computer_argv(Input::Xdotool, &json!({"action": "mouse_move"})).is_err());
    }

    #[test]
    fn policy_gates_device_commands() {
        let off = HostPolicy { run: "deny".into(), ..Default::default() };
        let c = host_commands(&off);
        assert!(!c.contains(&"computer.act") && !c.contains(&"canvas.present") && !c.contains(&"system.run") && !c.contains(&"screen.record"));
        assert!(host_run(&off, "computer.act", &json!({"action": "left_click"})).unwrap_err().contains("disabled"));
        assert!(host_run(&off, "canvas.present", &json!({"url": "https://x"})).unwrap_err().contains("disabled"));
        let on = HostPolicy { canvas: true, ..off.clone() };
        assert!(host_run(&on, "canvas.present", &json!({"url": "javascript:alert(1)"})).unwrap_err().contains("http"));
        let full = HostPolicy { run: "full".into(), ..off };
        // Streamed stdin and cancellation.
        let (tx, rx) = mpsc::channel();
        tx.send(Some(b"hello\n".to_vec())).unwrap();
        tx.send(None).unwrap();
        let ctl = Ctl { cancel: Arc::default(), input: Some(rx) };
        assert_eq!(host_run_ctl(&full, "system.run", &json!({"command": "cat", "stdin": true}), &ctl).unwrap(), "hello\n");
        let ctl = Ctl::default();
        let flag = ctl.cancel.clone();
        let h = std::thread::spawn(move || host_run_ctl(&full, "system.run", &json!({"command": "sleep 20"}), &ctl));
        std::thread::sleep(Duration::from_millis(100));
        flag.store(true, Ordering::SeqCst);
        assert_eq!(h.join().unwrap().unwrap_err(), "cancelled");
    }

    #[test]
    fn v2_actions_and_push_to_talk_are_gated() {
        let off = HostPolicy { run: "deny".into(), ..Default::default() };
        assert!(!host_commands(&off).iter().any(|c| c.starts_with("talk.ptt")), "microphone is off by default");
        assert!(host_run(&off, "talk.ptt.start", &json!({})).unwrap_err().contains("disabled"));
        let on = HostPolicy { computer: true, microphone: true, ..off };
        // Browser actions refuse a non-loopback endpoint before touching the network.
        assert!(host_run(&HostPolicy { cdp_url: "http://192.168.1.5:9222".into(), ..on.clone() }, "computer.act", &json!({"action": "get_browser_state"})).unwrap_err().contains("this machine"));
        assert!(host_run(&on, "computer.act", &json!({"action": "browser_navigate", "pageRef": "P"})).unwrap_err().contains("cdp_url"));
        assert!(host_run(&on, "computer.act", &json!({"action": "launch_app", "app": "--help"})).unwrap_err().contains("desktop entry"));
        assert!(host_run(&on, "computer.act", &json!({"action": "kill_app", "app": "x"})).unwrap_err().contains("not available"));
        assert!(host_run(&on, "computer.act", &json!({"action": "set_value", "elementRef": "bad", "value": "x"})).is_err());
        assert!(host_run(&on, "talk.ptt.start", &json!({})).unwrap_err().contains("[stt]"));
        assert!(dangerous("talk.ptt.start") && dangerous("talk.ptt.once") && !dangerous("talk.ptt.stop"));
    }

    #[test]
    fn plugin_commands_carry_metadata_to_the_server() {
        let cmds: Vec<String> = vec!["kinds.hello".into(), "kinds.wipe".into(), "system.run".into()];
        let m = command_meta(&json!({"kinds.hello": {"description": "Greet", "params": {"type": "object"}}, "kinds.wipe": {"dangerous": true}, "system.run": {"dangerous": false}, "not.offered": {}}), &cmds);
        assert_eq!(m.keys().collect::<Vec<_>>(), ["kinds.hello", "kinds.wipe"], "built-in and unoffered names are ignored");
        assert_eq!((m["kinds.hello"]["dangerous"].as_bool(), m["kinds.wipe"]["dangerous"].as_bool()), (Some(false), Some(true)));
        {
            let mut r = reg().lock().unwrap();
            let (tx, _rx) = mpsc::channel();
            r.live.insert("meta-node".into(), Live { name: "n".into(), platform: "linux".into(), caps: vec![], commands: cmds.clone(), meta: m, tx, since: 0 });
        }
        assert!(dangerous_on("meta-node", "kinds.wipe") && !dangerous_on("meta-node", "kinds.hello") && dangerous_on("meta-node", "computer.act"));
        let d = describe(&reg().lock().unwrap(), "meta-node").unwrap();
        assert_eq!(d["schemas"]["kinds.hello"], json!({"type": "object"}));
        assert_eq!(d["descriptions"]["kinds.hello"], "Greet");
        assert!(d["dangerous"].as_array().unwrap().contains(&json!("kinds.wipe")));
        reg().lock().unwrap().live.remove("meta-node");
        // node.toml plugins: their node_commands are offered (python3 needed for the fixture).
        if std::process::Command::new("python3").arg("-c").arg("1").output().is_ok() {
            let f = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/plugin/kinds.py");
            let toml = format!("[plugins.kinds]\ncommand = \"python3\"\nargs = [\"-I\", {:?}]\n", f.display().to_string());
            let policy: HostPolicy = toml::from_str(&toml).unwrap();
            let (hosts, meta) = node_plugins(&policy);
            assert_eq!(meta.keys().collect::<Vec<_>>(), ["kinds.hello", "kinds.wipe"]);
            assert_eq!(meta["kinds.wipe"]["dangerous"], true);
            assert_eq!(hosts[0].node_invoke("kinds.hello", json!({"name": "node"}), Duration::from_secs(5)).unwrap()["greeting"], "hello node");
        }
    }
}
