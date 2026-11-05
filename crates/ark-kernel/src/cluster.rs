//! Central console (ent-062): node registry, signed managed-policy distribution and the
//! all-nodes view; plus the ARP surface of HA (`ha.*`) and the worker pool (`workers.*`).
//! Design: docs/ARCHITECTURE.md §7.4. No upstream has a multi-node console; the policy layer
//! extends the `/etc/ark` managed mechanism (`crate::managed`) instead of inventing a new one.
//!
//! - **Registry.** Every HA / `[cluster] enabled` daemon writes a heartbeat snapshot to
//!   `<data>/cluster/nodes/<node>.json`; nodes sharing a data directory see each other for free.
//!   Nodes that do not share storage are registered by an admin (`cluster.node.add`) with a URL
//!   and the *name* of a vault secret holding a read token; the console calls their
//!   `cluster.self.status` / `session.list` over `POST <url>/arp`.
//! - **Policy.** A bundle is the policy TOML plus `version`, `issued_ms`, the signer's public key
//!   and an Ed25519 signature over [`signed_message`]. Nodes accept it only when it verifies
//!   against the `[managed] cluster_key` their root-owned system files pin and its version is
//!   strictly newer than the installed one — whether it was pushed (`cluster.policy.apply`),
//!   pulled from a console (`cluster.policy.get`) or read from the shared publish file.
//! - **RBAC.** Method names follow the app server's scope rules: `*.status`, `*.list`, `*.get`
//!   are read-only metadata (operator / auditor may call them); every other `cluster.*`,
//!   `ha.stepdown` and `workers.dispatch` is unlisted and therefore admin-only. Every change
//!   is written to the unified audit stream.

use crate::daemon::Daemon;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

type Res = Result<Value, (i32, String)>;

/// `[cluster]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClusterConfig {
    /// Write this node's heartbeat into the registry even without `[ha]`.
    pub enabled: bool,
    /// Node name when `[ha]` is off ("" = host name).
    pub name: String,
    /// A console to pull the managed policy from (`POST <url>/arp`, `cluster.policy.get`).
    pub console_url: String,
    /// Bearer token for the console (read scope is enough; `{{secret:NAME}}` allowed).
    pub console_token: String,
    /// Seconds between policy pulls (console and shared publish file).
    pub pull_secs: u64,
    /// Seconds between heartbeats.
    pub heartbeat_secs: u64,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        ClusterConfig { enabled: false, name: String::new(), console_url: String::new(), console_token: String::new(), pull_secs: 300, heartbeat_secs: 5 }
    }
}

/// ARP method names this module serves (for `initialize` / capability lists).
pub const METHODS: &[&str] = &[
    "ha.status", "ha.stepdown", "workers.status", "workers.list", "workers.dispatch",
    "cluster.status", "cluster.self.status", "cluster.nodes.list", "cluster.sessions.list", "cluster.agents.list",
    "cluster.node.add", "cluster.node.remove",
    "cluster.policy.get", "cluster.policy.status", "cluster.policy.publish", "cluster.policy.apply", "cluster.policy.push", "cluster.policy.pull",
];

fn bad(e: impl Into<String>) -> (i32, String) {
    (-32602, e.into())
}
fn fail(e: impl Into<String>) -> (i32, String) {
    (-32000, e.into())
}

fn actor(p: &Value) -> ark_security::audit::Actor {
    p["_by"].as_str().map(ark_security::audit::Actor::parse_label).unwrap_or_else(ark_security::audit::Actor::local)
}

fn audit(data: &Path, kind: &str, p: &Value, target: &str, outcome: &str, detail: Value) {
    ark_security::audit::record(data, ark_security::audit::Event::new(kind, actor(p), target, outcome).detail(detail));
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().ok_or("no parent directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".{}.{}", path.file_name().and_then(|n| n.to_str()).unwrap_or("x"), std::process::id()));
    let mut f = std::fs::OpenOptions::new().create(true).truncate(true).write(true).mode(mode).open(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(bytes).and_then(|_| f.sync_all()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

// ───────────────────────── policy bundles ─────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bundle {
    pub v: u32,
    pub version: u64,
    pub issued_ms: u64,
    /// The managed policy, TOML (same shape as `/etc/ark/managed.toml`).
    pub policy: String,
    /// Signer public key, `ed25519:<base64>`.
    pub key: String,
    pub sig: String,
}

/// The exact bytes a bundle signature covers.
pub fn signed_message(version: u64, issued_ms: u64, policy: &str) -> Vec<u8> {
    format!("ark-cluster-policy\n1\n{version}\n{issued_ms}\n{}\n", ark_security::signing::sha256_hex(policy.as_bytes())).into_bytes()
}

/// Sign `policy` with a 32-byte Ed25519 seed (base64). Only `ark cluster policy sign` calls this.
pub fn sign_bundle(seed_b64: &str, policy: &str, version: u64) -> Result<Bundle, String> {
    if version == 0 {
        return Err("the policy version starts at 1".into());
    }
    check_policy(policy)?;
    let issued_ms = crate::event::now_ms();
    let sig = ark_security::signing::sign(seed_b64, &signed_message(version, issued_ms, policy))?;
    Ok(Bundle { v: 1, version, issued_ms, policy: policy.to_string(), key: ark_security::signing::public_of(seed_b64)?, sig })
}

/// The policy must be valid TOML whose `[managed]` only lists `locked` keys (a bundle can
/// never re-pin the console key or relax `cluster_required`).
fn check_policy(policy: &str) -> Result<toml::Table, String> {
    let t: toml::Table = policy.parse().map_err(|e| format!("policy is not valid TOML: {e}"))?;
    if let Some(m) = t.get("managed") {
        let m = m.as_table().ok_or("`managed` must be a table")?;
        if let Some(k) = m.keys().find(|k| *k != "locked") {
            return Err(format!("a cluster policy may only set `managed.locked`, not `managed.{k}`"));
        }
    }
    Ok(t)
}

/// Verify the signature (and, if given, that it was made by the pinned key). Returns the policy table.
pub fn verify_bundle(b: &Bundle, pinned: Option<&str>) -> Result<toml::Table, String> {
    use ark_security::signing::PublicKey;
    if b.v != 1 {
        return Err(format!("unsupported bundle format v{}", b.v));
    }
    let key = PublicKey::parse(&b.key)?;
    if let Some(p) = pinned {
        let pin = PublicKey::parse(p)?;
        if pin != key {
            return Err(format!("signed by key {} but this node pins {}", key.id(), pin.id()));
        }
    }
    ark_security::signing::verify(&key, &signed_message(b.version, b.issued_ms, &b.policy), &b.sig)?;
    check_policy(&b.policy)
}

/// `<data>/managed/cluster.json`: the bundle this node applies.
pub fn installed_path(data: &Path) -> PathBuf {
    data.join("managed").join("cluster.json")
}
/// `<data>/cluster/policy.json`: what this node publishes as a console.
pub fn published_path(data: &Path) -> PathBuf {
    data.join("cluster").join("policy.json")
}

fn read_bundle(p: &Path) -> Result<Option<Bundle>, String> {
    match std::fs::read(p) {
        Ok(b) => serde_json::from_slice(&b).map(Some).map_err(|e| format!("{}: {e}", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

/// Load + verify an installed bundle for the config loader (`crate::managed`).
pub fn load_installed(path: &Path, pinned: &str, min_version: u64) -> Result<Option<(Bundle, toml::Table)>, String> {
    let Some(b) = read_bundle(path)? else { return Ok(None) };
    let t = verify_bundle(&b, Some(pinned))?;
    if b.version < min_version {
        return Err(format!("version {} is older than managed.cluster_min_version {min_version}", b.version));
    }
    Ok(Some((b, t)))
}

/// Verify against the pinned key and install if strictly newer. `Ok(false)` = already current.
pub fn install(data: &Path, b: &Bundle, pinned: &str) -> Result<bool, String> {
    verify_bundle(b, Some(pinned))?;
    let cur = read_bundle(&installed_path(data)).ok().flatten().filter(|c| verify_bundle(c, Some(pinned)).is_ok());
    match cur.as_ref().map(|c| c.version) {
        Some(v) if v == b.version && cur.as_ref() == Some(b) => return Ok(false),
        Some(v) if v >= b.version => return Err(format!("version {} is not newer than the installed version {v} (rollback refused)", b.version)),
        _ => {}
    }
    write_atomic(&installed_path(data), &serde_json::to_vec_pretty(b).map_err(|e| e.to_string())?, 0o644)?;
    Ok(true)
}

/// Store a bundle as this console's published policy (verified; pinned key if one is set).
pub fn publish(data: &Path, b: &Bundle, pinned: Option<&str>) -> Result<(), String> {
    verify_bundle(b, pinned)?;
    if let Some(cur) = read_bundle(&published_path(data))? {
        if cur.version >= b.version && cur != *b {
            return Err(format!("version {} is not newer than the published version {}", b.version, cur.version));
        }
    }
    write_atomic(&published_path(data), &serde_json::to_vec_pretty(b).map_err(|e| e.to_string())?, 0o644)
}

/// One pull: the console (if configured) and the shared publish file. Returns the version
/// installed, if any changed. Errors are reported, never fatal.
pub fn pull(data: &Path, cfg: &ClusterConfig, pinned: Option<&str>, token: &str) -> Result<Option<u64>, String> {
    let Some(pin) = pinned else { return Err("no `[managed] cluster_key` is pinned in the system policy; refusing to apply unverifiable policy".into()) };
    let mut candidates: Vec<Bundle> = vec![];
    if let Some(b) = read_bundle(&published_path(data))? {
        candidates.push(b);
    }
    let mut errs = vec![];
    if !cfg.console_url.trim().is_empty() {
        match arp_call(&cfg.console_url, token, "cluster.policy.get", json!({}), Duration::from_secs(10)) {
            Ok(v) if v.is_null() => {}
            Ok(v) => match serde_json::from_value::<Bundle>(v) {
                Ok(b) => candidates.push(b),
                Err(e) => errs.push(format!("console sent a malformed bundle: {e}")),
            },
            Err(e) => errs.push(format!("console {}: {e}", cfg.console_url)),
        }
    }
    candidates.sort_by_key(|b| std::cmp::Reverse(b.version));
    for b in candidates {
        match install(data, &b, pin) {
            Ok(true) => return Ok(Some(b.version)),
            Ok(false) => return Ok(None),
            Err(e) if e.contains("not newer") => return Ok(None),
            Err(e) => errs.push(e),
        }
    }
    if errs.is_empty() {
        Ok(None)
    } else {
        Err(errs.join("; "))
    }
}

// ───────────────────────── registry ─────────────────────────

pub fn nodes_dir(data: &Path) -> PathBuf {
    data.join("cluster").join("nodes")
}

fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

pub fn write_heartbeat(data: &Path, snap: &Value) -> Result<(), String> {
    let node = snap["node"].as_str().filter(|n| valid_name(n)).ok_or("bad node name")?;
    write_atomic(&nodes_dir(data).join(format!("{node}.json")), snap.to_string().as_bytes(), 0o644)
}

/// Every heartbeat in the shared registry, newest first, with `alive` (seen within `stale_ms`).
pub fn local_nodes(data: &Path, stale_ms: u64) -> Vec<Value> {
    let now = crate::event::now_ms();
    let mut v: Vec<Value> = std::fs::read_dir(nodes_dir(data))
        .map(|rd| rd.flatten().filter(|e| e.path().extension().is_some_and(|x| x == "json")).filter_map(|e| std::fs::read(e.path()).ok()).filter_map(|b| serde_json::from_slice::<Value>(&b).ok()).collect())
        .unwrap_or_default();
    for n in v.iter_mut() {
        let seen = n["seen_ms"].as_u64().unwrap_or(0);
        n["alive"] = json!(now.saturating_sub(seen) <= stale_ms);
        n["source"] = json!("shared");
    }
    v.sort_by_key(|n| std::cmp::Reverse(n["seen_ms"].as_u64().unwrap_or(0)));
    v
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Remote {
    pub name: String,
    pub url: String,
    /// Vault secret holding a read token for that node.
    pub token_secret: String,
    /// Vault secret holding an admin token (only needed to push policy).
    #[serde(default)]
    pub admin_secret: String,
    #[serde(default)]
    pub added_ms: u64,
}

fn remotes_path(data: &Path) -> PathBuf {
    data.join("cluster").join("remotes.json")
}

pub fn remotes(data: &Path) -> Vec<Remote> {
    std::fs::read(remotes_path(data)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save_remotes(data: &Path, r: &[Remote]) -> Result<(), String> {
    write_atomic(&remotes_path(data), &serde_json::to_vec_pretty(r).map_err(|e| e.to_string())?, 0o600)
}

pub fn remote_add(data: &Path, r: Remote) -> Result<(), String> {
    if !valid_name(&r.name) {
        return Err(format!("bad node name `{}` (letters, digits, - _ .)", r.name));
    }
    if !(r.url.starts_with("http://") || r.url.starts_with("https://")) {
        return Err("the node URL must start with http:// or https://".into());
    }
    for s in [&r.token_secret, &r.admin_secret] {
        if s.contains("{{") || s.contains(' ') {
            return Err("give the *name* of a vault secret (`ark secrets set NAME …`), not the token".into());
        }
    }
    let mut all = remotes(data);
    all.retain(|x| x.name != r.name);
    all.push(r);
    all.sort_by(|a, b| a.name.cmp(&b.name));
    save_remotes(data, &all)
}

pub fn remote_remove(data: &Path, name: &str) -> Result<bool, String> {
    let mut all = remotes(data);
    let n = all.len();
    all.retain(|x| x.name != name);
    if all.len() == n {
        return Ok(false);
    }
    save_remotes(data, &all)?;
    Ok(true)
}

/// One JSON-RPC call to another node's app server (`POST <url>/arp`).
pub fn arp_call(url: &str, token: &str, method: &str, params: Value, timeout: Duration) -> Result<Value, String> {
    let agent: ureq::Agent = ark_net::http::builder().timeout_global(Some(timeout)).http_status_as_error(false).max_redirects(0).build().into();
    let endpoint = format!("{}/arp", url.trim_end_matches('/'));
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    let mut req = agent.post(&endpoint).header("Content-Type", "application/json");
    if !token.is_empty() {
        req = req.header("Authorization", &format!("Bearer {token}"));
    }
    let mut resp = req.send(body.as_bytes()).map_err(|e| format!("{endpoint}: {e}"))?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().with_config().limit(4 << 20).read_to_string().map_err(|e| e.to_string())?;
    if !(200..300).contains(&status) {
        return Err(format!("HTTP {status}: {}", text.chars().take(200).collect::<String>()));
    }
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("bad JSON-RPC reply: {e}"))?;
    if let Some(e) = v.get("error") {
        return Err(e["message"].as_str().unwrap_or("error").to_string());
    }
    Ok(v.get("result").cloned().unwrap_or(Value::Null))
}

fn secret(d: &Daemon, name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    let v = d.k.vault.substitute(&format!("{{{{secret:{name}}}}}"));
    if v.contains("{{secret:") {
        String::new()
    } else {
        v
    }
}

// ───────────────────────── node snapshot / overview ─────────────────────────

/// This node's name in the registry.
pub fn node_name(d: &Daemon) -> String {
    match d.ha() {
        Some(h) => h.node.clone(),
        None if !d.k.cfg.cluster.name.trim().is_empty() => d.k.cfg.cluster.name.trim().to_string(),
        None => crate::kanban::hostname(),
    }
}

/// What this node reports about itself (heartbeat file and `cluster.self.status`).
pub fn snapshot(d: &Daemon) -> Value {
    let k = &d.k;
    let mut running = k.running_ids();
    if let Some(p) = d.pool() {
        running.extend(p.running());
    }
    running.sort();
    running.dedup();
    let (role, epoch) = match d.ha() {
        Some(h) if h.is_leader() => ("leader", h.epoch()),
        Some(_) => ("standby", 0),
        None => ("single", 0),
    };
    let agents: Vec<Value> = k.cfg.agents.keys().map(|a| json!(a)).collect();
    let fleet = crate::coord::fleet_overview(k);
    json!({
        "node": node_name(d),
        "host": crate::kanban::hostname(),
        "pid": std::process::id(),
        "version": env!("CARGO_PKG_VERSION"),
        "role": role,
        "epoch": epoch,
        "advertise": if k.cfg.ha.advertise.is_empty() { k.paths.socket().display().to_string() } else { k.cfg.ha.advertise.clone() },
        "started_ms": d.started_ms(),
        "seen_ms": crate::event::now_ms(),
        "running": running,
        "agents": agents,
        "fleet": fleet["counts"],
        "workers": d.pool().map(|p| json!({"count": k.cfg.workers.count, "busy": p.running().len()})),
        "policy_version": k.cfg.managed.cluster_version,
        "policy_installed": read_bundle(&installed_path(&k.paths.data)).ok().flatten().map(|b| b.version),
    })
}

fn stale_ms(d: &Daemon) -> u64 {
    d.k.cfg.cluster.heartbeat_secs.max(1) * 3000 + d.k.cfg.ha.lease().as_millis() as u64
}

/// Every node: shared-registry heartbeats plus registered remote nodes (polled live).
pub fn nodes(d: &Daemon) -> Vec<Value> {
    let data = &d.k.paths.data;
    let me = node_name(d);
    let mut out = local_nodes(data, stale_ms(d));
    if !out.iter().any(|n| n["node"] == me.as_str()) {
        let mut s = snapshot(d);
        s["alive"] = json!(true);
        s["source"] = json!("self");
        out.insert(0, s);
    }
    for n in out.iter_mut() {
        n["self"] = json!(n["node"] == me.as_str());
    }
    for r in remotes(data) {
        let tok = secret(d, &r.token_secret);
        match arp_call(&r.url, &tok, "cluster.self.status", json!({}), Duration::from_secs(5)) {
            Ok(mut v) => {
                v["alive"] = json!(true);
                v["source"] = json!("remote");
                v["name"] = json!(r.name);
                v["url"] = json!(r.url);
                out.push(v);
            }
            Err(e) => out.push(json!({"node": r.name, "name": r.name, "url": r.url, "source": "remote", "alive": false, "error": e})),
        }
    }
    out
}

/// Sessions across the cluster: the shared store (annotated with the node running each) plus
/// every reachable remote node's `session.list`. Metadata only (titles, ids, counts).
pub fn sessions(d: &Daemon, all_nodes: &[Value], limit: usize) -> Vec<Value> {
    let mut owner: std::collections::HashMap<String, String> = Default::default();
    for n in all_nodes.iter().filter(|n| n["source"] != "remote" && n["alive"] == true) {
        for s in n["running"].as_array().into_iter().flatten().filter_map(|s| s.as_str()) {
            owner.insert(s.to_string(), n["node"].as_str().unwrap_or("").to_string());
        }
    }
    let mut out: Vec<Value> = d
        .k
        .store
        .list()
        .into_iter()
        .take(limit)
        .map(|s| json!({"id": s.id, "title": s.title, "model": s.model, "updated_ms": s.updated_ms, "messages": s.messages, "parent": s.parent, "node": owner.get(&s.id), "running": owner.contains_key(&s.id), "store": "shared"}))
        .collect();
    for r in remotes(&d.k.paths.data) {
        let tok = secret(d, &r.token_secret);
        if let Ok(Value::Array(list)) = arp_call(&r.url, &tok, "session.list", json!({"limit": limit}), Duration::from_secs(5)) {
            for mut s in list {
                s["node"] = json!(r.name);
                s["store"] = json!(r.name);
                out.push(s);
            }
        }
    }
    out
}

fn agents(all_nodes: &[Value]) -> Vec<Value> {
    all_nodes.iter().map(|n| json!({"node": n["node"], "alive": n["alive"], "agents": n["agents"], "fleet": n["fleet"], "running": n["running"].as_array().map(|a| a.len()).unwrap_or(0)})).collect()
}

fn policy_status(d: &Daemon) -> Value {
    let data = &d.k.paths.data;
    let m = &d.k.cfg.managed;
    let inst = read_bundle(&installed_path(data)).ok().flatten();
    let publ = read_bundle(&published_path(data)).ok().flatten();
    let key_id = |k: &str| ark_security::signing::PublicKey::parse(k).map(|p| p.id()).unwrap_or_default();
    json!({
        "pinned_key": m.cluster_key,
        "pinned_key_id": m.cluster_key.as_deref().map(key_id),
        "active_version": m.cluster_version,
        "error": m.cluster_error,
        "installed": inst.as_ref().map(|b| json!({"version": b.version, "issued_ms": b.issued_ms, "key_id": key_id(&b.key)})),
        "published": publ.as_ref().map(|b| json!({"version": b.version, "issued_ms": b.issued_ms, "key_id": key_id(&b.key)})),
        "restart_required": inst.as_ref().map(|b| b.version) != m.cluster_version && inst.is_some(),
        "console_url": d.k.cfg.cluster.console_url,
        "locked": m.locked,
    })
}

fn bundle_param(p: &Value) -> Result<Bundle, (i32, String)> {
    let b = p.get("bundle").ok_or_else(|| bad("missing param `bundle`"))?;
    let b = match b {
        Value::String(s) => serde_json::from_str(s),
        v => serde_json::from_value(v.clone()),
    };
    b.map_err(|e| bad(format!("malformed bundle: {e}")))
}

/// Serve `ha.*`, `workers.*` and `cluster.*`. `None` = not ours.
pub fn call(d: &Daemon, m: &str, p: &Value) -> Option<Res> {
    if !(m.starts_with("ha.") || m.starts_with("workers.") || m.starts_with("cluster.")) {
        return None;
    }
    let data = d.k.paths.data.clone();
    let s = |k: &str| p[k].as_str().unwrap_or("").trim().to_string();
    Some(match m {
        "ha.status" => Ok(match d.ha() {
            Some(h) => h.status(),
            None => json!({"enabled": false, "node": node_name(d), "role": "single"}),
        }),
        "ha.stepdown" => match d.ha() {
            None => Err(fail("HA is not enabled ([ha] enabled = true)")),
            Some(h) => {
                let r = h.step_down().map_err(fail);
                if let Ok(true) = r {
                    audit(&data, "ha.stepdown", p, &h.node, "ok", json!({}));
                    d.on_lost("stepped down by an operator");
                }
                r.map(|ok| json!({"stepped_down": ok}))
            }
        },
        "workers.status" | "workers.list" => Ok(match d.pool() {
            Some(pool) => pool.status(),
            None => json!({"count": d.k.cfg.workers.count, "workers": [], "note": if d.k.cfg.workers.count == 0 { "no worker pool ([workers] count = 0)" } else { "this node is not the leader" }}),
        }),
        "workers.dispatch" => {
            let id = s("id");
            if !d.k.store.exists(&id) {
                return Some(Err(bad(format!("no such session `{id}`"))));
            }
            match d.pool() {
                None => Err(fail("no worker pool on this node")),
                Some(pool) if d.k.is_running(&id) => Err(fail(format!("session {id} is running in the daemon; interrupt it first ({})", pool.status()["count"]))),
                Some(pool) => Ok(json!({"queued": pool.dispatch(&id)})),
            }
        }
        "cluster.self.status" => Ok(snapshot(d)),
        "cluster.nodes.list" => Ok(json!(nodes(d))),
        "cluster.sessions.list" => {
            let n = nodes(d);
            Ok(json!(sessions(d, &n, p["limit"].as_u64().unwrap_or(200) as usize)))
        }
        "cluster.agents.list" => Ok(json!(agents(&nodes(d)))),
        "cluster.status" => {
            let n = nodes(d);
            let sess = sessions(d, &n, p["limit"].as_u64().unwrap_or(100) as usize);
            Ok(json!({
                "self": node_name(d),
                "ha": d.ha().map(|h| h.status()).unwrap_or(json!({"enabled": false})),
                "workers": d.pool().map(|p| p.status()),
                "nodes": n,
                "agents": agents(&n),
                "sessions": sess,
                "policy": policy_status(d),
            }))
        }
        "cluster.node.add" => {
            let r = Remote { name: s("name"), url: s("url"), token_secret: s("token_secret"), admin_secret: s("admin_secret"), added_ms: crate::event::now_ms() };
            let target = r.name.clone();
            let res = remote_add(&data, r.clone()).map_err(bad);
            audit(&data, "cluster.node.add", p, &target, if res.is_ok() { "ok" } else { "error" }, json!({"url": r.url, "token_secret": r.token_secret}));
            res.map(|_| json!({"added": target}))
        }
        "cluster.node.remove" => {
            let name = s("name");
            let res = remote_remove(&data, &name).map_err(fail);
            audit(&data, "cluster.node.remove", p, &name, if matches!(res, Ok(true)) { "ok" } else { "noop" }, json!({}));
            res.map(|r| json!({"removed": r}))
        }
        "cluster.policy.get" => read_bundle(&published_path(&data)).map(|b| json!(b)).map_err(fail),
        "cluster.policy.status" => Ok(policy_status(d)),
        "cluster.policy.publish" => {
            let b = match bundle_param(p) {
                Ok(b) => b,
                Err(e) => return Some(Err(e)),
            };
            let res = publish(&data, &b, d.k.cfg.managed.cluster_key.as_deref()).map_err(bad);
            audit(&data, "cluster.policy.publish", p, &format!("v{}", b.version), if res.is_ok() { "ok" } else { "denied" }, json!({"version": b.version, "error": res.as_ref().err().map(|e| &e.1)}));
            res.map(|_| json!({"published": b.version}))
        }
        "cluster.policy.apply" => {
            let b = match bundle_param(p) {
                Ok(b) => b,
                Err(e) => return Some(Err(e)),
            };
            let res = match d.k.cfg.managed.cluster_key.as_deref() {
                None => Err(bad("this node pins no `[managed] cluster_key`; it cannot accept cluster policy")),
                Some(pin) => install(&data, &b, pin).map_err(bad),
            };
            audit(&data, "cluster.policy.apply", p, &format!("v{}", b.version), if res.is_ok() { "ok" } else { "denied" }, json!({"version": b.version, "via": "push", "error": res.as_ref().err().map(|e| &e.1)}));
            res.map(|changed| json!({"installed": b.version, "changed": changed, "restart_required": changed}))
        }
        "cluster.policy.pull" => {
            let tok = (d.k.vault_substitute())(&d.k.cfg.cluster.console_token);
            let res = pull(&data, &d.k.cfg.cluster, d.k.cfg.managed.cluster_key.as_deref(), if tok.contains("{{secret:") { "" } else { &tok });
            if let Ok(Some(v)) = &res {
                audit(&data, "cluster.policy.apply", p, &format!("v{v}"), "ok", json!({"version": v, "via": "pull"}));
            }
            res.map(|v| json!({"installed": v, "restart_required": v.is_some()})).map_err(fail)
        }
        "cluster.policy.push" => {
            let Some(b) = read_bundle(&published_path(&data)).ok().flatten() else {
                return Some(Err(fail("nothing published yet (cluster.policy.publish)")));
            };
            let only = s("node");
            let mut results = vec![];
            for r in remotes(&data).into_iter().filter(|r| only.is_empty() || r.name == only) {
                let tok = secret(d, if r.admin_secret.is_empty() { &r.token_secret } else { &r.admin_secret });
                let out = arp_call(&r.url, &tok, "cluster.policy.apply", json!({"bundle": b}), Duration::from_secs(10));
                audit(&data, "cluster.policy.push", p, &r.name, if out.is_ok() { "ok" } else { "error" }, json!({"version": b.version, "error": out.as_ref().err()}));
                results.push(match out {
                    Ok(v) => json!({"node": r.name, "ok": true, "result": v}),
                    Err(e) => json!({"node": r.name, "ok": false, "error": e}),
                });
            }
            Ok(json!({"version": b.version, "nodes": results}))
        }
        other => Err((-32601, format!("unknown method `{other}`"))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="; // test-only seed (0..31)

    #[test]
    fn bundles_verify_against_the_pin_and_refuse_rollback_and_tampering() {
        let d = ark_core::tmp::TempDir::new("ark-cluster");
        let data = d.path();
        let pin = ark_security::signing::public_of(SEED).unwrap();
        let other = ark_security::signing::public_of("HyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4=").unwrap();
        let b1 = sign_bundle(SEED, "[managed]\nlocked = [\"model.allow\"]\n[model]\nallow = [\"anthropic/*\"]\n", 1).unwrap();
        assert!(verify_bundle(&b1, Some(&pin)).is_ok());
        assert!(verify_bundle(&b1, Some(&other)).unwrap_err().contains("pins"));
        let mut forged = b1.clone();
        forged.policy = forged.policy.replace("anthropic/*", "*");
        assert!(verify_bundle(&forged, Some(&pin)).unwrap_err().contains("bad signature"));
        let mut bumped = b1.clone();
        bumped.version = 9;
        assert!(verify_bundle(&bumped, None).is_err(), "the version is covered by the signature");
        assert!(sign_bundle(SEED, "[managed]\ncluster_key = \"x\"\n", 2).unwrap_err().contains("managed.cluster_key"), "a bundle cannot re-pin the key");
        assert!(install(data, &b1, &pin).unwrap());
        assert!(!install(data, &b1, &pin).unwrap(), "same bundle twice is a no-op");
        let b2 = sign_bundle(SEED, "[model]\nallow = [\"local/*\"]\n", 2).unwrap();
        assert!(install(data, &b2, &pin).unwrap());
        assert!(install(data, &b1, &pin).unwrap_err().contains("rollback"));
        let (b, t) = load_installed(&installed_path(data), &pin, 0).unwrap().unwrap();
        assert_eq!(b.version, 2);
        assert!(t.get("model").is_some());
        assert!(load_installed(&installed_path(data), &pin, 3).unwrap_err().contains("min_version"));
        // Tampering with the installed file on disk is caught at load time.
        let mut onfile: Bundle = serde_json::from_slice(&std::fs::read(installed_path(data)).unwrap()).unwrap();
        onfile.policy.push_str("[gate]\negress_allow = [\"*\"]\n");
        std::fs::write(installed_path(data), serde_json::to_vec(&onfile).unwrap()).unwrap();
        assert!(load_installed(&installed_path(data), &pin, 0).is_err());
    }

    #[test]
    fn managed_layer_applies_a_verified_bundle_and_locks_its_keys() {
        let d = ark_core::tmp::TempDir::new("ark-cluster");
        let pin = ark_security::signing::public_of(SEED).unwrap();
        let sys = d.path().join("managed.toml");
        std::fs::write(&sys, format!("[managed]\nlocked = [\"approvals.preset\"]\ncluster_key = \"{pin}\"\n")).unwrap();
        let bundle = d.path().join("cluster.json");
        // No bundle yet: fine unless required.
        let l = crate::managed::load_system_layer_at(std::slice::from_ref(&sys), &bundle).unwrap();
        assert_eq!((l.cluster_key.as_deref(), l.cluster_version), (Some(pin.as_str()), None));
        let b = sign_bundle(SEED, "[managed]\nlocked = [\"model.allow\"]\n[model]\nallow = [\"anthropic/*\"]\n", 3).unwrap();
        std::fs::write(&bundle, serde_json::to_vec(&b).unwrap()).unwrap();
        let l = crate::managed::load_system_layer_at(std::slice::from_ref(&sys), &bundle).unwrap();
        assert_eq!(l.cluster_version, Some(3));
        assert!(l.locked.contains(&"model.allow".to_string()) && l.locked.contains(&"approvals.preset".to_string()));
        assert_eq!(l.table["model"]["allow"].as_array().unwrap()[0].as_str(), Some("anthropic/*"));
        // A bundle signed by someone else is ignored (warning) — or refused when required.
        let foreign = sign_bundle("HyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4=", "[model]\nallow = [\"*\"]\n", 4).unwrap();
        std::fs::write(&bundle, serde_json::to_vec(&foreign).unwrap()).unwrap();
        let l = crate::managed::load_system_layer_at(std::slice::from_ref(&sys), &bundle).unwrap();
        assert!(l.cluster_version.is_none() && l.cluster_error.as_deref().unwrap().contains("pins"));
        std::fs::write(&sys, format!("[managed]\ncluster_key = \"{pin}\"\ncluster_required = true\n")).unwrap();
        assert!(crate::managed::load_system_layer_at(std::slice::from_ref(&sys), &bundle).is_err());
        // The pin itself must parse.
        std::fs::write(&sys, "[managed]\ncluster_key = \"ed25519:nope\"\n").unwrap();
        assert!(crate::managed::load_system_layer_at(std::slice::from_ref(&sys), &bundle).is_err());
    }

    struct NoModels;
    impl crate::kernel::Resolver for NoModels {
        fn provider(&self, id: &str) -> Result<std::sync::Arc<dyn ark_core::Provider>, String> {
            Err(format!("no provider {id}"))
        }
    }

    #[test]
    fn daemon_methods_report_the_node_and_audit_every_change() {
        let d = ark_core::tmp::TempDir::new("ark-cluster");
        let paths = crate::config::Paths { data: d.path().join("data"), config_dir: d.path().join("cfg"), runtime: d.path().join("run") };
        let (pending, _cell) = crate::daemon::pending_approver(Duration::from_secs(5));
        let mut cfg = crate::config::Config::default();
        cfg.cluster.name = "solo".into();
        let k = crate::kernel::new_kernel(cfg, paths, std::sync::Arc::new(NoModels), vec![], std::sync::Arc::new(crate::vault::Vault::empty()), pending.clone());
        let dm = Daemon::new(k.clone(), pending);
        let sid = k.create_session(d.path(), Some("x/y"), None, Some("t")).unwrap();
        assert_eq!(dm.call("ha.status", &json!({})).unwrap()["role"], "single");
        assert!(dm.call("ha.stepdown", &json!({})).is_err(), "no HA, nothing to step down from");
        assert!(dm.call("workers.status", &json!({})).unwrap()["note"].as_str().unwrap().contains("count = 0"));
        let st = dm.call("cluster.status", &json!({})).unwrap();
        assert_eq!(st["self"], "solo");
        assert_eq!(st["nodes"][0]["node"], "solo");
        assert!(st["sessions"].as_array().unwrap().iter().any(|s| s["id"] == sid.as_str()));
        assert!(dm.call("cluster.node.add", &json!({"name": "far", "url": "http://127.0.0.1:9", "token_secret": "FAR", "_by": "user:alice"})).is_ok());
        // An unreachable remote node is listed as down, not an error for the whole view.
        let n = dm.call("cluster.nodes.list", &json!({})).unwrap();
        assert!(n.as_array().unwrap().iter().any(|x| x["node"] == "far" && x["alive"] == false), "{n}");
        assert_eq!(dm.call("cluster.node.remove", &json!({"name": "far"})).unwrap()["removed"], true);
        // Without a pinned key a node accepts no cluster policy.
        let b = sign_bundle(SEED, "[model]\nallow = [\"x/*\"]\n", 1).unwrap();
        assert!(dm.call("cluster.policy.apply", &json!({"bundle": b})).unwrap_err().1.contains("pins no"));
        assert_eq!(dm.call("cluster.policy.publish", &json!({"bundle": serde_json::to_string(&b).unwrap()})).unwrap()["published"], 1);
        assert_eq!(dm.call("cluster.policy.get", &json!({})).unwrap()["version"], 1);
        let audit = std::fs::read_to_string(k.paths.data.join("audit").join("events.jsonl")).unwrap_or_default();
        for kind in ["cluster.node.add", "cluster.node.remove", "cluster.policy.apply", "cluster.policy.publish"] {
            assert!(audit.contains(kind), "{kind} missing from the audit stream:\n{audit}");
        }
        assert!(audit.contains("alice"), "the acting principal is recorded");
    }

    #[test]
    fn registry_and_remotes() {
        let d = ark_core::tmp::TempDir::new("ark-cluster");
        write_heartbeat(d.path(), &json!({"node": "a", "seen_ms": crate::event::now_ms(), "running": ["s1"]})).unwrap();
        write_heartbeat(d.path(), &json!({"node": "b", "seen_ms": 1, "running": []})).unwrap();
        assert!(write_heartbeat(d.path(), &json!({"node": "../x"})).is_err());
        let n = local_nodes(d.path(), 10_000);
        assert_eq!(n.len(), 2);
        assert_eq!((n[0]["node"].as_str(), n[0]["alive"].as_bool()), (Some("a"), Some(true)));
        assert_eq!(n[1]["alive"], false);
        assert!(remote_add(d.path(), Remote { name: "far".into(), url: "ftp://x".into(), token_secret: "T".into(), admin_secret: String::new(), added_ms: 0 }).is_err());
        assert!(remote_add(d.path(), Remote { name: "far".into(), url: "https://x".into(), token_secret: "{{secret:T}}".into(), admin_secret: String::new(), added_ms: 0 }).is_err());
        remote_add(d.path(), Remote { name: "far".into(), url: "https://far.example:8640".into(), token_secret: "FAR_TOKEN".into(), admin_secret: String::new(), added_ms: 0 }).unwrap();
        assert_eq!(remotes(d.path()).len(), 1);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(remotes_path(d.path())).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(remote_remove(d.path(), "far").unwrap());
        assert!(!remote_remove(d.path(), "far").unwrap());
    }

    #[test]
    fn arp_call_speaks_json_rpc_with_a_bearer_token() {
        use std::io::{BufRead, BufReader, Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let (mut len, mut auth) = (0usize, String::new());
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            loop {
                let mut h = String::new();
                r.read_line(&mut h).unwrap();
                if h.trim().is_empty() {
                    break;
                }
                let lower = h.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                if lower.starts_with("authorization:") {
                    auth = h.trim().to_string();
                }
            }
            let mut body = vec![0; len];
            r.read_exact(&mut body).unwrap();
            let req: Value = serde_json::from_slice(&body).unwrap();
            let out = json!({"jsonrpc": "2.0", "id": 1, "result": {"method": req["method"], "auth": auth}}).to_string();
            write!(s, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}", out.len()).unwrap();
            line
        });
        let v = arp_call(&url, "tok-1", "cluster.self.status", json!({}), Duration::from_secs(5)).unwrap();
        assert_eq!(v["method"], "cluster.self.status");
        assert!(v["auth"].as_str().unwrap().ends_with("Bearer tok-1"));
        assert!(h.join().unwrap().starts_with("POST /arp "));
    }
}
