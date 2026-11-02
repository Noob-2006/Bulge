//! MCP client (protocol 2025-11-25 and the 2026-07-28 stateless revision; older
//! versions accepted). One `Client` per configured server: it connects lazily,
//! reconnects after a crash on the next call, and never lets server stderr reach
//! the model.
//!
//! Beyond plain request/response it drives the multi-round flows: tasks
//! (task-augmented `tools/call`, `tasks/get` polling, `tasks/result`,
//! `tasks/cancel`), MRTR `input_required` results (2026-07-28), URL-mode
//! elicitation (`-32042` → user opens the URL → `notifications/elicitation/complete`
//! → retry), `outputSchema` validation, and MCP Apps `ui://` resources.

use crate::transport::{tls_from, Conn, HttpConn, HttpOpts, Notify, OnRequest, SseConn, StdioConn};
use crate::{McpServerConfig, Secrets};
use ark_core::Cancel;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

pub const PROTOCOL: &str = "2025-11-25";
pub const SUPPORTED: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
/// The stateless revision: no `initialize`, protocol fields in every request's `_meta`.
pub const MODERN: &str = "2026-07-28";
pub const UI_EXTENSION: &str = "io.modelcontextprotocol/ui";
pub const UI_MIME: &str = "text/html;profile=mcp-app";
const RELATED_TASK: &str = "io.modelcontextprotocol/related-task";
/// MRTR / URL-elicitation retries before giving up on a request.
const MAX_INPUT_ROUNDS: usize = 8;
const UI_MAX_BYTES: usize = 2 << 20;
const URL_ELICITATION_WAIT: Duration = Duration::from_secs(300);

/// Answers `sampling/createMessage` (params → CreateMessageResult) with ark's model.
pub type Sampler = Arc<dyn Fn(&Value) -> Result<Value, String> + Send + Sync>;
/// Answers `elicitation/create` (params → {action, content}) by asking the user.
pub type Elicitor = Arc<dyn Fn(&str, &Value) -> Result<Value, String> + Send + Sync>;
const STARTUP_MAX: Duration = Duration::from_secs(10);
/// After a failed start, calls fail fast for this long instead of respawning.
const RESTART_COOLDOWN: Duration = Duration::from_secs(3);
const MAX_PAGES: usize = 50;
const MAX_SAMPLING_TOOLS: usize = 64;

/// A remote tool as listed by `tools/list` (also the cache format).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub input_schema: Value,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub idempotent: bool,
    #[serde(default)]
    pub destructive: bool,
    #[serde(default)]
    pub open_world: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// MCP Apps: `_meta.ui.resourceUri` (a `ui://` resource rendered with the result).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui_resource: Option<String>,
    /// MCP Apps `_meta.ui.visibility` (`model`, `app`); None = both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui_visibility: Option<Vec<String>>,
    /// `execution.taskSupport`: forbidden (default) | optional | required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_support: Option<String>,
}

impl ToolDef {
    /// Hidden from the model when the server marks it app-only.
    pub fn model_visible(&self) -> bool {
        self.ui_visibility.as_ref().is_none_or(|v| v.iter().any(|x| x == "model"))
    }
    pub fn app_visible(&self) -> bool {
        self.ui_visibility.as_ref().is_none_or(|v| v.iter().any(|x| x == "app"))
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CallResult {
    pub text: String,
    pub is_error: bool,
    /// The CallToolResult as the server sent it (MCP Apps hand it to the view).
    pub raw: Value,
}

struct Live {
    conn: Arc<dyn Conn>,
    init: Value,
    started: Instant,
    /// Set by the keepalive thread when a ping fails.
    sick: Arc<AtomicBool>,
    /// 2026-07-28 stateless era: protocol fields go in every request's `_meta`.
    modern: bool,
    /// Our capabilities, repeated per request in the modern era.
    caps: Value,
    /// Answers server→client requests (also MRTR `inputRequests`).
    on_req: OnRequest,
}

/// `notifications/elicitation/complete` ids seen, for the URL-elicitation retry.
type Completions = Arc<(Mutex<HashSet<String>>, Condvar)>;

#[derive(Clone)]
struct Session {
    conn: Arc<dyn Conn>,
    init: Value,
    modern: bool,
    caps: Value,
    on_req: OnRequest,
}

impl Session {
    fn of(l: &Live) -> Session {
        Session { conn: l.conn.clone(), init: l.init.clone(), modern: l.modern, caps: l.caps.clone(), on_req: l.on_req.clone() }
    }
}

fn client_info() -> Value {
    json!({"name": "ark", "title": "ark", "version": env!("CARGO_PKG_VERSION")})
}

/// Per-request protocol fields of the stateless revision.
fn modern_meta(caps: &Value) -> Value {
    json!({"io.modelcontextprotocol/protocolVersion": MODERN, "io.modelcontextprotocol/clientInfo": client_info(), "io.modelcontextprotocol/clientCapabilities": caps})
}

fn discover_ok(d: &Value) -> bool {
    d["supportedVersions"].as_array().is_some_and(|v| v.iter().any(|x| x == MODERN))
}

/// A DiscoverResult in the shape of an InitializeResult, so the rest of ark reads one format.
fn from_discover(d: Value) -> Value {
    json!({"protocolVersion": MODERN, "capabilities": d["capabilities"], "serverInfo": d["_meta"]["io.modelcontextprotocol/serverInfo"], "instructions": d["instructions"], "supportedVersions": d["supportedVersions"]})
}

/// Errors only a 2026-07-28 server sends (unsupported version, header mismatch, missing capability).
fn is_modern_error(e: &str) -> bool {
    ["server error -32022", "server error -32020", "server error -32021"].iter().any(|c| e.contains(c))
}

/// A `-32022` whose `supported` list still offers a handshake-era version.
fn legacy_offered(e: &str) -> bool {
    error_data(e).is_some_and(|d| d["supported"].as_array().is_some_and(|v| v.iter().any(|x| x.as_str().is_some_and(|x| SUPPORTED.contains(&x)))))
}

/// The JSON-RPC `error.data` the transports append to error strings (`[data:{…}]`).
pub fn error_data(e: &str) -> Option<Value> {
    let i = e.find("[data:")?;
    let rest = &e[i + 6..];
    let j = rest.rfind(']')?;
    serde_json::from_str(&rest[..j]).ok()
}

/// Header-safe value, or the `=?base64?…?=` sentinel form (2026-07-28 value encoding).
fn header_value(v: &str) -> String {
    let plain = v.bytes().all(|b| b == b' ' || b == b'\t' || (0x21..=0x7e).contains(&b)) && v.trim() == v && !(v.starts_with("=?base64?") && v.ends_with("?="));
    if plain {
        v.to_string()
    } else {
        format!("=?base64?{}?=", ark_net::crypto::b64(v.as_bytes()))
    }
}

/// `x-mcp-header` annotations reachable through `properties` only: (path, header name).
fn x_mcp_paths(schema: &Value) -> Vec<(Vec<String>, String, String)> {
    fn walk(s: &Value, path: &mut Vec<String>, out: &mut Vec<(Vec<String>, String, String)>) {
        for (k, p) in s["properties"].as_object().into_iter().flatten() {
            path.push(k.clone());
            if let Some(h) = p.get("x-mcp-header") {
                out.push((path.clone(), h.as_str().unwrap_or("").to_string(), p["type"].as_str().unwrap_or("").to_string()));
            }
            walk(p, path, out);
            path.pop();
        }
    }
    let mut out = vec![];
    walk(schema, &mut vec![], &mut out);
    out
}

/// A tool whose `x-mcp-header` annotations break the rules must be rejected.
fn x_mcp_headers_valid(schema: &Value) -> bool {
    // Any annotation outside a pure `properties` chain makes the tool invalid.
    fn count(v: &Value) -> usize {
        match v {
            Value::Object(o) => o.iter().map(|(k, x)| usize::from(k == "x-mcp-header") + count(x)).sum(),
            Value::Array(a) => a.iter().map(count).sum(),
            _ => 0,
        }
    }
    let paths = x_mcp_paths(schema);
    let token = |h: &str| !h.is_empty() && h.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
    let mut seen = HashSet::new();
    paths.len() == count(schema) && paths.iter().all(|(_, h, ty)| token(h) && matches!(ty.as_str(), "string" | "integer" | "boolean") && seen.insert(h.to_ascii_lowercase()))
}

/// Request metadata headers of the stateless HTTP binding: Mcp-Method, Mcp-Name, Mcp-Param-*.
fn modern_headers(method: &str, p: &Value, schema: Option<&Value>) -> Vec<(String, String)> {
    let mut h = vec![("mcp-method".to_string(), method.to_string())];
    let name = match method {
        "tools/call" | "prompts/get" => p["name"].as_str(),
        "resources/read" => p["uri"].as_str(),
        _ => None,
    };
    if let Some(n) = name {
        h.push(("mcp-name".into(), header_value(n)));
    }
    for (path, header, _) in schema.map(x_mcp_paths).unwrap_or_default() {
        let mut v = &p["arguments"];
        for k in &path {
            v = &v[k.as_str()];
        }
        let s = match v {
            Value::String(s) => s.clone(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) if n.is_i64() || n.is_u64() => n.to_string(),
            _ => continue,
        };
        h.push((format!("mcp-param-{header}"), header_value(&s)));
    }
    h
}

pub struct Client {
    pub name: String,
    cfg: McpServerConfig,
    secrets: Secrets,
    sink: Mutex<Option<Notify>>,
    live: Mutex<Option<Live>>,
    failed: Mutex<Option<(Instant, String)>>,
    stale: Arc<AtomicBool>,
    cache: Mutex<Option<PathBuf>>,
    starts: AtomicUsize,
    /// resources / prompts changed since listed.
    resources_stale: Arc<AtomicBool>,
    prompts_stale: Arc<AtomicBool>,
    /// Read per request, so a host service set after connecting still answers.
    sampler: Arc<Mutex<Option<Sampler>>>,
    elicitor: Arc<Mutex<Option<Elicitor>>>,
    roots: Mutex<Vec<PathBuf>>,
    auth: Mutex<Option<Arc<crate::oauth::Store>>>,
    last_used: Mutex<Instant>,
    sampling_log: Arc<Mutex<std::collections::VecDeque<Instant>>>,
    progress: AtomicUsize,
    /// Accumulated configured cost of calls this process.
    pub spent: Mutex<f64>,
    /// Tool definitions by remote name (output schemas, task support, ui, x-mcp-header).
    defs: Mutex<HashMap<String, ToolDef>>,
    completions: Completions,
    ui_cache: Mutex<HashMap<String, Value>>,
}

impl Client {
    pub fn new(name: &str, cfg: McpServerConfig, secrets: Secrets) -> Result<Self, String> {
        cfg.validate(name)?;
        Ok(Client {
            name: name.into(),
            cfg,
            secrets,
            sink: Mutex::new(None),
            live: Mutex::new(None),
            failed: Mutex::new(None),
            stale: Arc::default(),
            cache: Mutex::new(None),
            starts: AtomicUsize::new(0),
            resources_stale: Arc::default(),
            prompts_stale: Arc::default(),
            sampler: Arc::default(),
            elicitor: Arc::default(),
            roots: Mutex::new(vec![]),
            auth: Mutex::new(None),
            last_used: Mutex::new(Instant::now()),
            sampling_log: Arc::default(),
            progress: AtomicUsize::new(1),
            spent: Mutex::new(0.0),
            defs: Mutex::default(),
            completions: Arc::default(),
            ui_cache: Mutex::default(),
        })
    }

    /// Where OAuth tokens live (`<data>/mcp-oauth/<name>.json`); required for `auth = "oauth"`.
    pub fn set_data_dir(&self, dir: &std::path::Path) {
        if self.cfg.uses_oauth() {
            *self.auth.lock().unwrap() = Some(Arc::new(crate::oauth::Store::new(dir, &self.name)));
        }
    }
    pub fn oauth_store(&self) -> Option<Arc<crate::oauth::Store>> {
        self.auth.lock().unwrap().clone()
    }
    pub fn set_sampler(&self, s: Sampler) {
        *self.sampler.lock().unwrap() = Some(s);
    }
    pub fn set_elicitor(&self, e: Elicitor) {
        *self.elicitor.lock().unwrap() = Some(e);
    }
    /// Roots offered to the server (the workspace unless configured).
    pub fn set_roots(&self, r: Vec<PathBuf>) {
        *self.roots.lock().unwrap() = if self.cfg.roots.is_empty() { r } else { self.cfg.roots.clone() };
    }
    pub fn resources_stale(&self) -> bool {
        self.resources_stale.load(Ordering::SeqCst)
    }
    pub fn prompts_stale(&self) -> bool {
        self.prompts_stale.load(Ordering::SeqCst)
    }

    pub fn config(&self) -> &McpServerConfig {
        &self.cfg
    }
    /// Definitions served from the catalog cache (no `tools/list` this process).
    pub fn remember_tools(&self, defs: &[ToolDef]) {
        let mut m = self.defs.lock().unwrap();
        for d in defs {
            m.insert(d.name.clone(), d.clone());
        }
    }
    pub fn tool_def(&self, name: &str) -> Option<ToolDef> {
        self.defs.lock().unwrap().get(name).cloned()
    }
    /// Notifications (other than tools/list_changed) go here; set before the first call.
    pub fn on_notification(&self, f: Notify) {
        *self.sink.lock().unwrap() = Some(f);
    }
    /// Catalog cache to delete when the server reports its tool list changed.
    pub fn set_cache_path(&self, p: PathBuf) {
        *self.cache.lock().unwrap() = Some(p);
    }
    pub fn is_running(&self) -> bool {
        self.live.lock().unwrap().as_ref().is_some_and(|l| l.conn.alive())
    }
    /// How many times the server process / session was started.
    pub fn starts(&self) -> usize {
        self.starts.load(Ordering::SeqCst)
    }
    /// The server said its tool list changed since we cached it.
    pub fn is_stale(&self) -> bool {
        self.stale.load(Ordering::SeqCst)
    }
    pub fn stderr_tail(&self) -> String {
        self.live.lock().unwrap().as_ref().map(|l| l.conn.stderr_tail()).unwrap_or_default()
    }
    pub fn shutdown(&self) {
        self.live.lock().unwrap().take();
    }

    fn connect(&self) -> Result<Live, String> {
        let sub = |s: &String| (self.secrets)(s);
        let notify: Notify = {
            let (stale, sink, cache) = (self.stale.clone(), self.sink.lock().unwrap().clone(), self.cache.lock().unwrap().clone());
            let (rs, ps, done) = (self.resources_stale.clone(), self.prompts_stale.clone(), self.completions.clone());
            Arc::new(move |m: &str, p: &Value| {
                match m {
                    "notifications/elicitation/complete" => {
                        if let Some(id) = p["elicitationId"].as_str() {
                            done.0.lock().unwrap().insert(id.to_string());
                            done.1.notify_all();
                        }
                    }
                    "notifications/tools/list_changed" => {
                        stale.store(true, Ordering::SeqCst);
                        if let Some(c) = &cache {
                            let _ = std::fs::remove_file(c);
                        }
                    }
                    "notifications/resources/list_changed" => rs.store(true, Ordering::SeqCst),
                    "notifications/prompts/list_changed" => ps.store(true, Ordering::SeqCst),
                    _ => {}
                }
                // Everything (logging, progress, resources/updated, elicitation/complete…) also reaches the sink.
                if let Some(s) = &sink {
                    s(m, p);
                }
            })
        };
        let roots: Vec<Value> = self.roots.lock().unwrap().iter().map(|r| json!({"uri": format!("file://{}", r.display()), "name": r.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default()})).collect();
        let (sampling_on, elicit_on) = (self.cfg.sampling.enabled, self.cfg.elicitation);
        let (sampler, elicitor) = (self.sampler.clone(), self.elicitor.clone());
        let (scfg, slog, server) = (self.cfg.sampling.clone(), self.sampling_log.clone(), self.name.clone());
        let (has_sampler, has_elicitor) = (sampling_on && sampler.lock().unwrap().is_some(), elicit_on && elicitor.lock().unwrap().is_some());
        let on_req: OnRequest = Arc::new(move |m: &str, p: &Value| match m {
            "ping" => Ok(json!({})),
            "roots/list" => Ok(json!({"roots": roots})),
            "sampling/createMessage" => match sampler.lock().unwrap().clone().filter(|_| sampling_on) {
                Some(s) => sample(&s, &scfg, &slog, p),
                None => Err((-32601, "sampling is disabled for this server (set sampling.enabled = true)".into())),
            },
            "elicitation/create" => match elicitor.lock().unwrap().clone().filter(|_| elicit_on) {
                Some(e) => e(&server, p).map_err(|e| (-32603, e)),
                None => Ok(json!({"action": "decline"})),
            },
            _ => Err((-32601, format!("method `{m}` not supported by ark"))),
        });
        let on_req_keep = on_req.clone();
        let startup = self.cfg.timeout().min(STARTUP_MAX);
        self.starts.fetch_add(1, Ordering::SeqCst);
        let conn: Arc<dyn Conn> = match (&self.cfg.command, &self.cfg.url) {
            (Some(cmd), _) => {
                let env: Vec<(String, String)> = self.cfg.env.iter().map(|(k, v)| (k.clone(), sub(v))).collect();
                StdioConn::spawn(cmd, &self.cfg.args, &env, self.cfg.cwd.as_ref(), notify, on_req)?
            }
            (None, Some(url)) => {
                let o = HttpOpts {
                    headers: self.cfg.headers.iter().map(|(k, v)| (k.clone(), sub(v))).collect(),
                    timeout: self.cfg.timeout(),
                    auth: self.auth.lock().unwrap().clone(),
                    server: self.name.clone(),
                    tls: tls_from(self.cfg.ca_cert.as_ref(), self.cfg.client_cert.as_ref(), self.cfg.client_key.as_ref(), self.cfg.ssl_verify)?,
                };
                if self.cfg.uses_oauth() && o.auth.as_ref().is_none_or(|a| !a.has_tokens()) {
                    return Err(format!("not logged in; run `ark mcp login {}`", self.name));
                }
                if let (Some(a), Some(want)) = (o.auth.as_ref(), self.cfg.oauth.authorization_server.as_deref()) {
                    a.check_issuer(want)?;
                }
                if self.cfg.transport.as_deref() == Some("sse") {
                    SseConn::connect(url, o, notify, on_req)? as Arc<dyn Conn>
                } else {
                    HttpConn::new(url, o, notify, on_req) as Arc<dyn Conn>
                }
            }
            _ => return Err("no transport".into()),
        };
        let mut caps = json!({"roots": {"listChanged": false}});
        if has_sampler {
            caps["sampling"] = if self.cfg.sampling.tools { json!({"tools": {}}) } else { json!({}) };
        }
        if has_elicitor {
            caps["elicitation"] = json!({"form": {}, "url": {}});
        }
        if self.cfg.apps {
            caps["extensions"] = json!({UI_EXTENSION: {"mimeTypes": [UI_MIME]}});
        }
        let fail = |e: String| {
            let tail = conn.stderr_tail();
            if tail.is_empty() {
                e
            } else {
                format!("{e}\n--- server stderr (tail) ---\n{}", last_lines(&tail, 15))
            }
        };
        // Era negotiation (hermes' order): `auto` tries the legacy handshake first and
        // moves to `server/discover` only on a modern-only answer; `stateless` probes
        // discover first and falls back on anything that is not a modern error.
        let mode = self.cfg.protocol.as_deref().unwrap_or("auto");
        let modern_first = matches!(mode, "stateless" | "modern" | MODERN);
        let handshake = || -> Result<Value, String> {
            conn.set_protocol("");
            let params = json!({"protocolVersion": PROTOCOL, "capabilities": caps, "clientInfo": client_info()});
            conn.request("initialize", params, startup, &Cancel::new())
        };
        // Every stateless POST carries MCP-Protocol-Version and Mcp-Method, the probe included.
        let discover = || {
            conn.set_protocol(MODERN);
            conn.request_h("server/discover", json!({"_meta": modern_meta(&caps)}), &[("mcp-method".into(), "server/discover".into())], startup, &Cancel::new())
        };
        let (init, modern) = if modern_first {
            match discover() {
                Ok(d) if discover_ok(&d) => (from_discover(d), true),
                Err(e) if is_modern_error(&e) && !legacy_offered(&e) => return Err(fail(e)),
                _ if mode == "auto" || mode == "stateless" || mode == "modern" => (handshake().map_err(fail)?, false),
                _ => return Err(fail(format!("server/discover failed and protocol = \"{mode}\" forbids the legacy handshake"))),
            }
        } else {
            match handshake() {
                Ok(i) => (i, false),
                Err(e) if mode == "auto" && (is_modern_error(&e) || e.contains("-32601")) => match discover() {
                    Ok(d) if discover_ok(&d) => (from_discover(d), true),
                    _ => return Err(fail(e)),
                },
                Err(e) => return Err(fail(e)),
            }
        };
        let v = init.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
        if !modern && !SUPPORTED.contains(&v) {
            return Err(format!("server speaks MCP `{v}`, ark supports {}, {MODERN}", SUPPORTED.join(", ")));
        }
        conn.set_protocol(if modern { MODERN } else { v });
        if !modern {
            conn.notify("notifications/initialized", json!({}))?;
        }
        self.stale.store(false, Ordering::SeqCst);
        let sick = Arc::new(AtomicBool::new(false));
        // Stateless servers hold no connection state worth pinging (and ping would need `_meta`).
        if let Some(secs) = self.cfg.keepalive_secs.filter(|s| *s > 0 && !modern) {
            let (c, k) = (Arc::downgrade(&conn), sick.clone());
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_secs(secs.max(5)));
                let Some(c) = c.upgrade() else { return };
                if !c.alive() {
                    return;
                }
                match c.request("ping", json!({}), Duration::from_secs(10), &Cancel::new()) {
                    Ok(_) => {}
                    // Servers that do not implement ping are alive enough.
                    Err(e) if e.contains("-32601") => {}
                    Err(_) => {
                        k.store(true, Ordering::SeqCst);
                        return;
                    }
                }
            });
        }
        Ok(Live { conn, init, started: Instant::now(), sick, modern, caps, on_req: on_req_keep })
    }

    fn conn(&self) -> Result<(Arc<dyn Conn>, Value), String> {
        self.session().map(|s| (s.conn, s.init))
    }

    fn session(&self) -> Result<Session, String> {
        let mut live = self.live.lock().unwrap();
        let idle = self.last_used.lock().unwrap().elapsed();
        *self.last_used.lock().unwrap() = Instant::now();
        let expired = |l: &Live| {
            l.sick.load(Ordering::SeqCst)
                || self.cfg.idle_timeout_secs.is_some_and(|s| idle > Duration::from_secs(s))
                || self.cfg.max_lifetime_secs.is_some_and(|s| l.started.elapsed() > Duration::from_secs(s))
        };
        if let Some(l) = live.as_ref().filter(|l| l.conn.alive() && !expired(l)) {
            return Ok(Session::of(l));
        }
        if let Some((at, e)) = self.failed.lock().unwrap().as_ref() {
            if at.elapsed() < RESTART_COOLDOWN {
                return Err(e.clone());
            }
        }
        *live = None;
        match self.connect() {
            Ok(l) => {
                *self.failed.lock().unwrap() = None;
                let r = Session::of(&l);
                *live = Some(l);
                Ok(r)
            }
            Err(e) => {
                let e = format!("mcp server `{}`: {e}", self.name);
                *self.failed.lock().unwrap() = Some((Instant::now(), e.clone()));
                Err(e)
            }
        }
    }

    /// The `initialize` result (connects if needed).
    pub fn info(&self) -> Result<Value, String> {
        self.conn().map(|c| c.1)
    }

    pub fn request(&self, method: &str, params: Value, cancel: &Cancel) -> Result<Value, String> {
        self.request_timeout(method, params, self.cfg.timeout(), cancel)
    }

    /// Whether the live connection speaks the 2026-07-28 stateless revision.
    pub fn is_modern(&self) -> bool {
        self.live.lock().unwrap().as_ref().is_some_and(|l| l.modern)
    }

    pub fn request_timeout(&self, method: &str, params: Value, timeout: Duration, cancel: &Cancel) -> Result<Value, String> {
        let s = self.session()?;
        let conn = s.conn.clone();
        let (params, headers) = if s.modern {
            let mut p = if params.is_object() { params } else { json!({}) };
            let meta = p["_meta"].as_object().cloned().unwrap_or_default();
            let mut m = modern_meta(&s.caps).as_object().cloned().unwrap_or_default();
            m.extend(meta);
            p["_meta"] = Value::Object(m);
            let schema = p["name"].as_str().filter(|_| method == "tools/call").and_then(|n| self.tool_def(n)).map(|d| d.input_schema);
            let h = modern_headers(method, &p, schema.as_ref());
            (p, h)
        } else {
            (params, vec![])
        };
        conn.request_h(method, params, &headers, timeout, cancel).map_err(|e| {
            if conn.alive() {
                format!("mcp `{}` {e}", self.name)
            } else {
                // Dead now: the next call restarts it. Show why it died.
                let tail = conn.stderr_tail();
                format!("mcp `{}` {e} (server stopped; it will be restarted on the next call){}", self.name, if tail.is_empty() { String::new() } else { format!("\n--- server stderr (tail) ---\n{}", last_lines(&tail, 10)) })
            }
        })
    }

    pub fn notify(&self, method: &str, params: Value) -> Result<(), String> {
        self.conn()?.0.notify(method, params)
    }

    fn paged(&self, method: &str, key: &str) -> Result<Vec<Value>, String> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let params = match &cursor {
                Some(c) => json!({"cursor": c}),
                None => json!({}),
            };
            let r = self.request(method, params, &Cancel::new())?;
            out.extend(r.get(key).and_then(Value::as_array).cloned().unwrap_or_default());
            match r.get("nextCursor").and_then(Value::as_str) {
                Some(c) if !c.is_empty() && cursor.as_deref() != Some(c) => cursor = Some(c.into()),
                _ => return Ok(out),
            }
        }
        Ok(out)
    }

    pub fn list_tools(&self) -> Result<Vec<ToolDef>, String> {
        Ok(self
            .paged("tools/list", "tools")?
            .into_iter()
            // A tool with an invalid `x-mcp-header` annotation is dropped (2026-07-28 HTTP rule).
            .filter(|t| self.cfg.url.is_none() || !self.is_modern() || x_mcp_headers_valid(&t["inputSchema"]))
            .filter_map(|t| {
                let ann = t.get("annotations");
                let hint = |k: &str| ann.and_then(|a| a.get(k)).and_then(Value::as_bool).unwrap_or(false);
                Some(ToolDef {
                    name: t.get("name")?.as_str()?.to_string(),
                    description: t.get("description").and_then(Value::as_str).unwrap_or("").to_string(),
                    input_schema: t.get("inputSchema").cloned().unwrap_or_else(|| json!({"type": "object"})),
                    read_only: hint("readOnlyHint"),
                    idempotent: hint("idempotentHint"),
                    // Per spec the default for destructiveHint / openWorldHint is true.
                    destructive: ann.and_then(|a| a.get("destructiveHint")).and_then(Value::as_bool).unwrap_or(!hint("readOnlyHint")),
                    open_world: ann.and_then(|a| a.get("openWorldHint")).and_then(Value::as_bool).unwrap_or(true),
                    output_schema: t.get("outputSchema").cloned(),
                    title: t.get("title").or_else(|| ann.and_then(|a| a.get("title"))).and_then(Value::as_str).map(str::to_string),
                    // `_meta.ui.resourceUri`, or the older flat `_meta["ui/resourceUri"]`.
                    ui_resource: t["_meta"]["ui"]["resourceUri"].as_str().or_else(|| t["_meta"]["ui/resourceUri"].as_str()).filter(|u| u.starts_with("ui://")).map(str::to_string),
                    ui_visibility: t["_meta"]["ui"]["visibility"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()),
                    task_support: t["execution"]["taskSupport"].as_str().map(str::to_string),
                })
            })
            .collect::<Vec<_>>())
        .inspect(|defs| self.remember_tools(defs))
    }

    pub fn call_tool(&self, name: &str, args: Value, cancel: &Cancel) -> Result<CallResult, String> {
        let token = format!("{}-{}", self.name, self.progress.fetch_add(1, Ordering::SeqCst));
        let def = self.tool_def(name);
        let mut params = json!({"name": name, "arguments": args, "_meta": {"progressToken": token}});
        // Task augmentation: only when the server offers it for tools/call and the tool allows it.
        let (_, init) = self.conn()?;
        let server_tasks = init["capabilities"]["tasks"]["requests"]["tools"].get("call").is_some();
        let support = def.as_ref().and_then(|d| d.task_support.as_deref()).unwrap_or("forbidden");
        let as_task = server_tasks && (support == "required" || (support == "optional" && self.cfg.tasks));
        if as_task {
            params["task"] = json!({"ttl": self.task_timeout().as_millis() as u64});
        }
        let mut r = self.rounds("tools/call", params, cancel)?;
        if let Some(task) = r.get("task").filter(|_| r.get("content").is_none()).cloned() {
            r = self.await_task(&task, cancel)?;
        }
        let mut is_error = r.get("isError").and_then(Value::as_bool).unwrap_or(false);
        let mut text = render_content(&r);
        // outputSchema: structured results must conform; a mismatch is a tool error for the model.
        if let Some(schema) = def.as_ref().and_then(|d| d.output_schema.as_ref()).filter(|_| !is_error) {
            let problem = match r.get("structuredContent").filter(|s| !s.is_null()) {
                None => Some("the tool declares an outputSchema but returned no structuredContent".to_string()),
                Some(sc) => crate::schema::validate(schema, sc).err().map(|e| format!("structuredContent does not match the tool's outputSchema: {e}")),
            };
            if let Some(p) = problem {
                is_error = true;
                text = format!("[ark] invalid result from MCP server `{}`: {p}\n{text}", self.name);
            }
        }
        Ok(CallResult { text, is_error, raw: r })
    }

    fn task_timeout(&self) -> Duration {
        Duration::from_secs(self.cfg.task_timeout_secs.unwrap_or(600).max(1))
    }

    /// One request through the multi-round flows: MRTR `input_required` results are
    /// answered and retried; a `-32042` URL-elicitation error is shown to the user,
    /// completion awaited, and the request retried.
    pub fn rounds(&self, method: &str, mut params: Value, cancel: &Cancel) -> Result<Value, String> {
        let mut url_retries = 0;
        for _ in 0..MAX_INPUT_ROUNDS {
            let r = match self.request(method, params.clone(), cancel) {
                Err(e) if e.contains("server error -32042") && url_retries < 2 => {
                    url_retries += 1;
                    self.url_elicitations(&e, cancel)?;
                    continue;
                }
                r => r?,
            };
            if r["resultType"].as_str() != Some("input_required") {
                return Ok(r);
            }
            let s = self.session()?;
            let mut answers = serde_json::Map::new();
            for (k, ask) in r["inputRequests"].as_object().into_iter().flatten() {
                if let Ok(v) = (s.on_req)(ask["method"].as_str().unwrap_or(""), &ask["params"]) {
                    answers.insert(k.clone(), v);
                }
            }
            let o = params.as_object_mut().ok_or("request params must be an object")?;
            o.insert("inputResponses".into(), Value::Object(answers));
            match r.get("requestState") {
                Some(st) => o.insert("requestState".into(), st.clone()),
                None => o.remove("requestState"),
            };
        }
        Err(format!("mcp `{}`: {method} still needs input after {MAX_INPUT_ROUNDS} rounds", self.name))
    }

    /// `-32042`: every listed URL elicitation goes to the user; then wait (bounded)
    /// for the server's `notifications/elicitation/complete` before retrying.
    fn url_elicitations(&self, err: &str, cancel: &Cancel) -> Result<(), String> {
        let data = error_data(err).ok_or_else(|| err.to_string())?;
        let el = self.elicitor.lock().unwrap().clone().filter(|_| self.cfg.elicitation).ok_or_else(|| format!("{err} (elicitation is disabled for this server)"))?;
        let mut ids = vec![];
        for e in data["elicitations"].as_array().into_iter().flatten().filter(|e| e["mode"] == "url") {
            let r = el(&self.name, e)?;
            if r["action"] != "accept" {
                return Err(format!("mcp `{}`: the user did not open {} ({})", self.name, e["url"].as_str().unwrap_or("?"), r["action"].as_str().unwrap_or("declined")));
            }
            ids.extend(e["elicitationId"].as_str().map(str::to_string));
        }
        let deadline = Instant::now() + URL_ELICITATION_WAIT.min(self.task_timeout());
        let (m, cv) = &*self.completions;
        let mut seen = m.lock().unwrap();
        while !ids.iter().all(|i| seen.contains(i)) && Instant::now() < deadline && !cancel.is_cancelled() {
            seen = cv.wait_timeout(seen, Duration::from_millis(100)).unwrap().0;
        }
        if cancel.is_cancelled() {
            return Err("cancelled while waiting for the browser step".into());
        }
        for i in &ids {
            seen.remove(i);
        }
        Ok(())
    }

    /// Poll a task (`tasks/get`, honouring `pollInterval`) until it is terminal or needs
    /// input, then fetch its result with `tasks/result` (which blocks server-side while
    /// the server asks its elicitation / sampling questions on that stream).
    fn await_task(&self, task: &Value, cancel: &Cancel) -> Result<Value, String> {
        let id = task["taskId"].as_str().ok_or("CreateTaskResult without taskId")?.to_string();
        let deadline = Instant::now() + self.task_timeout();
        let mut t = task.clone();
        let cancel_task = |why: &str| {
            let _ = self.request_timeout("tasks/cancel", json!({"taskId": id}), Duration::from_secs(10), &Cancel::new());
            format!("mcp `{}`: task {id} {why}", self.name)
        };
        loop {
            match t["status"].as_str().unwrap_or("working") {
                "completed" | "failed" | "cancelled" | "input_required" => {
                    let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_secs(1));
                    let r = self.request_timeout("tasks/result", json!({"taskId": id}), left, cancel).map_err(|e| if cancel.is_cancelled() { cancel_task("cancelled") } else { e })?;
                    let mut r = r;
                    if let Some(m) = r.get_mut("_meta").and_then(Value::as_object_mut) {
                        m.remove(RELATED_TASK);
                    }
                    if t["status"] == "failed" && r.get("isError").is_none() && r.get("content").is_none() {
                        return Err(format!("mcp `{}`: task {id} failed: {}", self.name, t["statusMessage"].as_str().unwrap_or("no reason given")));
                    }
                    return Ok(r);
                }
                _ => {}
            }
            let wait = Duration::from_millis(t["pollInterval"].as_u64().unwrap_or(1000).clamp(50, 30_000));
            let until = Instant::now() + wait;
            while Instant::now() < until {
                if cancel.is_cancelled() {
                    return Err(cancel_task("cancelled"));
                }
                if Instant::now() > deadline {
                    return Err(cancel_task(&format!("timed out after {}s", self.task_timeout().as_secs())));
                }
                std::thread::sleep(Duration::from_millis(25).min(until.saturating_duration_since(Instant::now())));
            }
            t = self.request("tasks/get", json!({"taskId": id}), cancel)?;
        }
    }

    /// `tasks/list` (one page per call; `cursor` from the previous page).
    pub fn list_tasks(&self) -> Result<Vec<Value>, String> {
        self.paged("tasks/list", "tasks")
    }

    /// MCP Apps: the `ui://` resource as {uri, html, mimeType, csp, permissions, prefersBorder}.
    /// Cached per URI for the life of the process (servers version URIs on change).
    pub fn ui_resource(&self, uri: &str, cancel: &Cancel) -> Result<Value, String> {
        if !uri.starts_with("ui://") {
            return Err(format!("`{uri}` is not a ui:// resource"));
        }
        if let Some(v) = self.ui_cache.lock().unwrap().get(uri) {
            return Ok(v.clone());
        }
        let r = self.rounds("resources/read", json!({"uri": uri}), cancel)?;
        let contents = r["contents"].as_array().cloned().unwrap_or_default();
        let c = contents
            .iter()
            .find(|c| c["mimeType"].as_str().is_some_and(|m| m.starts_with("text/html")))
            .or(contents.first())
            .ok_or_else(|| format!("ui resource {uri} has no contents"))?;
        let html = match (c["text"].as_str(), c["blob"].as_str()) {
            (Some(t), _) => t.to_string(),
            (None, Some(b)) => String::from_utf8(ark_net::crypto::b64_decode(b).ok_or("ui resource blob is not base64")?).map_err(|_| "ui resource is not UTF-8")?,
            _ => return Err(format!("ui resource {uri} has neither text nor blob")),
        };
        if html.len() > UI_MAX_BYTES {
            return Err(format!("ui resource {uri} is larger than {UI_MAX_BYTES} bytes"));
        }
        let meta = c["_meta"]["ui"].clone();
        let v = json!({"uri": uri, "html": html, "mimeType": c["mimeType"], "csp": meta["csp"], "permissions": meta["permissions"], "prefersBorder": meta["prefersBorder"]});
        self.ui_cache.lock().unwrap().insert(uri.to_string(), v.clone());
        Ok(v)
    }

    pub fn list_resource_templates(&self) -> Result<Vec<Value>, String> {
        self.paged("resources/templates/list", "resourceTemplates")
    }

    pub fn subscribe_resource(&self, uri: &str) -> Result<(), String> {
        self.request("resources/subscribe", json!({"uri": uri}), &Cancel::new()).map(|_| ())
    }

    /// Argument completion for a prompt or resource template (`ref` = {type, name|uri}).
    pub fn complete(&self, reference: Value, arg: &str, value: &str) -> Result<Vec<String>, String> {
        let r = self.request("completion/complete", json!({"ref": reference, "argument": {"name": arg, "value": value}}), &Cancel::new())?;
        Ok(r["completion"]["values"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default())
    }

    pub fn set_log_level(&self, level: &str) -> Result<(), String> {
        self.request("logging/setLevel", json!({"level": level}), &Cancel::new()).map(|_| ())
    }

    pub fn list_resources(&self) -> Result<Vec<Value>, String> {
        self.paged("resources/list", "resources")
    }

    pub fn read_resource(&self, uri: &str, cancel: &Cancel) -> Result<String, String> {
        let r = self.rounds("resources/read", json!({"uri": uri}), cancel)?;
        let parts: Vec<String> = r
            .get("contents")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(|c| c.get("text").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| blob_placeholder(c))).collect())
            .unwrap_or_default();
        Ok(parts.join("\n"))
    }

    pub fn list_prompts(&self) -> Result<Vec<Value>, String> {
        self.paged("prompts/list", "prompts")
    }

    /// A prompt rendered to plain text (message texts joined).
    pub fn get_prompt(&self, name: &str, args: &std::collections::BTreeMap<String, String>) -> Result<String, String> {
        let r = self.rounds("prompts/get", json!({"name": name, "arguments": args}), &Cancel::new())?;
        let msgs = r.get("messages").and_then(Value::as_array).cloned().unwrap_or_default();
        let parts: Vec<String> = msgs.iter().filter_map(|m| m.get("content")).map(|c| render_content(&json!({"content": if c.is_array() { c.clone() } else { json!([c]) }}))).collect();
        Ok(parts.join("\n\n"))
    }
}

/// Rate-limit and cap a sampling request, then hand it to ark's model.
fn sample(s: &Sampler, cfg: &crate::SamplingConfig, log: &Mutex<std::collections::VecDeque<Instant>>, p: &Value) -> Result<Value, (i64, String)> {
    {
        let mut l = log.lock().unwrap();
        while l.front().is_some_and(|t| t.elapsed() > Duration::from_secs(60)) {
            l.pop_front();
        }
        if l.len() as u32 >= cfg.max_rpm.max(1) {
            return Err((-32603, format!("sampling rate limit ({} per minute) reached", cfg.max_rpm)));
        }
        l.push_back(Instant::now());
    }
    let mut p = p.clone();
    if let Some(tools) = p.get("tools").filter(|t| !t.is_null()) {
        if !cfg.tools {
            return Err((-32602, "sampling with tools is disabled for this server (sampling.tools = false)".into()));
        }
        let list = tools.as_array().ok_or((-32602, "`tools` must be an array".to_string()))?;
        if list.len() > MAX_SAMPLING_TOOLS || list.iter().any(|t| t["name"].as_str().is_none_or(str::is_empty) || !t["inputSchema"].is_object()) {
            return Err((-32602, format!("`tools`: at most {MAX_SAMPLING_TOOLS}, each with a name and an object inputSchema")));
        }
        let mode = p["toolChoice"]["mode"].as_str().unwrap_or("auto");
        if !matches!(mode, "auto" | "required" | "none") {
            return Err((-32602, format!("toolChoice.mode `{mode}`: use auto, required or none")));
        }
        let msgs = p["messages"].as_array().cloned().unwrap_or_default();
        let blocks = |m: &Value| -> Vec<Value> {
            match &m["content"] {
                Value::Array(a) => a.clone(),
                c => vec![c.clone()],
            }
        };
        let rounds = msgs.iter().filter(|m| m["role"] == "assistant" && blocks(m).iter().any(|b| b["type"] == "tool_use")).count();
        if rounds as u32 >= cfg.max_tool_rounds.max(1) {
            return Err((-32603, format!("sampling tool-round limit ({}) reached", cfg.max_tool_rounds)));
        }
        // A user turn that carries tool results carries nothing else (spec constraint).
        for m in msgs.iter().filter(|m| m["role"] == "user") {
            let b = blocks(m);
            if b.iter().any(|x| x["type"] == "tool_result") && !b.iter().all(|x| x["type"] == "tool_result") {
                return Err((-32602, "a user message with tool_result content must contain only tool results".into()));
            }
        }
    }
    let asked = p.get("maxTokens").and_then(Value::as_u64).unwrap_or(cfg.max_tokens_cap as u64);
    p["maxTokens"] = json!(asked.min(cfg.max_tokens_cap as u64));
    // Only honour model hints that are explicitly allowed.
    let hinted = p["modelPreferences"]["hints"].as_array().into_iter().flatten().filter_map(|h| h["name"].as_str()).find(|n| cfg.allowed_models.iter().any(|a| a == n || n.contains(a.as_str()))).map(str::to_string);
    p["_arkModel"] = json!(hinted.or_else(|| cfg.model.clone()));
    let offered: Vec<String> = p["tools"].as_array().into_iter().flatten().filter_map(|t| t["name"].as_str().map(str::to_string)).collect();
    let (tx, rx) = std::sync::mpsc::channel();
    let s = s.clone();
    std::thread::spawn(move || {
        let _ = tx.send(s(&p));
    });
    match rx.recv_timeout(Duration::from_secs(cfg.timeout_secs.max(1))) {
        Ok(Ok(r)) => {
            let content = match &r["content"] {
                Value::Array(a) => a.clone(),
                c => vec![c.clone()],
            };
            if let Some(bad) = content.iter().filter(|b| b["type"] == "tool_use").find(|b| !offered.iter().any(|n| b["name"] == n.as_str())) {
                return Err((-32603, format!("the model called `{}`, which the server did not offer", bad["name"].as_str().unwrap_or("?"))));
            }
            Ok(r)
        }
        Ok(Err(e)) => Err((-32603, e)),
        Err(_) => Err((-32603, format!("sampling timed out after {}s", cfg.timeout_secs))),
    }
}

fn last_lines(s: &str, n: usize) -> String {
    let v: Vec<&str> = s.lines().collect();
    v[v.len().saturating_sub(n)..].join("\n")
}

/// Decoded size of a base64 string (without decoding it).
fn b64_len(s: &str) -> usize {
    let s = s.trim();
    (s.len() / 4 * 3).saturating_sub(s.bytes().rev().take(2).filter(|&b| b == b'=').count())
}

fn blob_placeholder(c: &Value) -> String {
    let mime = c.get("mimeType").and_then(Value::as_str).unwrap_or("application/octet-stream");
    let n = c.get("blob").or_else(|| c.get("data")).and_then(Value::as_str).map(b64_len).unwrap_or(0);
    match c.get("uri").and_then(Value::as_str) {
        Some(u) => format!("[binary resource {u}: {mime}, {n} bytes]"),
        None => format!("[binary: {mime}, {n} bytes]"),
    }
}

/// Tool-result content blocks → text the model sees. Binary data never enters context.
pub fn render_content(r: &Value) -> String {
    let mut out: Vec<String> = Vec::new();
    for b in r.get("content").and_then(Value::as_array).into_iter().flatten() {
        let ty = b.get("type").and_then(Value::as_str).unwrap_or("");
        out.push(match ty {
            "text" => b.get("text").and_then(Value::as_str).unwrap_or("").to_string(),
            "image" | "audio" => {
                let mime = b.get("mimeType").and_then(Value::as_str).unwrap_or("?");
                let n = b.get("data").and_then(Value::as_str).map(b64_len).unwrap_or(0);
                format!("[{ty}: {mime}, {n} bytes]")
            }
            "resource" => {
                let res = b.get("resource").cloned().unwrap_or_default();
                match res.get("text").and_then(Value::as_str) {
                    Some(t) => format!("[resource {}]\n{t}", res.get("uri").and_then(Value::as_str).unwrap_or("?")),
                    None => blob_placeholder(&res),
                }
            }
            "resource_link" => format!("[resource link: {}]", b.get("uri").and_then(Value::as_str).unwrap_or("?")),
            other => format!("[unsupported content type `{other}`]"),
        });
    }
    // structuredContent: shown once; text blocks that only repeat it are dropped.
    if let Some(s) = r.get("structuredContent").filter(|s| !s.is_null()) {
        let compact = s.to_string();
        out.retain(|t| serde_json::from_str::<Value>(t).ok().as_ref() != Some(s));
        if out.is_empty() {
            return compact;
        }
        out.push(format!("structuredContent: {compact}"));
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_rendering_keeps_binary_out() {
        let r = json!({"content": [
            {"type": "text", "text": "hi"},
            {"type": "image", "mimeType": "image/png", "data": "AAAA"},
            {"type": "resource", "resource": {"uri": "file:///a", "text": "body"}},
            {"type": "resource", "resource": {"uri": "file:///b", "blob": "AAAAAAAA", "mimeType": "x/y"}},
            {"type": "resource_link", "uri": "file:///c"},
            {"type": "weird"}
        ]});
        let t = render_content(&r);
        assert!(t.contains("hi") && t.contains("[image: image/png, 3 bytes]") && t.contains("[resource file:///a]\nbody"));
        assert!(t.contains("[binary resource file:///b: x/y, 6 bytes]") && t.contains("file:///c") && t.contains("`weird`"));
        assert!(!t.contains("AAAA"));
        assert_eq!(render_content(&json!({"content": [], "structuredContent": {"a": 1}})), r#"{"a":1}"#);
    }
}
