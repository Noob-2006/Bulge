//! Generic webhook channel. Outbound: JSON POST to a URL. Inbound: a minimal
//! HTTP/1.1 listener accepting `POST /inbound` with a bearer token, plus
//! Hermes-style signed routes (ported from Hermes `gateway/platforms/webhook*.py`, MIT):
//!
//! ```toml
//! [channels.hooks]
//! kind = "webhook"
//! listen = "127.0.0.1:8644"
//! secret = "{{secret:HOOK_SECRET}}"      # default for every route
//! [channels.hooks.routes.github]
//! events = ["pull_request"]              # X-GitHub-Event / X-GitLab-Event / payload.event_type|type
//! prompt = "PR #{number}: {pull_request.title}"
//! filters = [{ field = "action", in = ["opened", "synchronize"] }]
//! coalesce = { key = "pull_request.number", window_seconds = 30, max_wait_seconds = 300 }
//! ```
//!
//! Each route listens on `path` (default `/webhooks/<name>`) and verifies, in
//! Hermes' order: Standard Webhooks / Svix (`webhook-*`/`svix-*`, base64 HMAC of
//! `id.ts.body`, `whsec_` keys, 300 s replay window), Linear (`linear-signature`),
//! GitHub (`X-Hub-Signature-256`), GitLab (`X-Gitlab-Token`), generic V2
//! (`X-Webhook-Signature-V2` over `<ts>.<body>` + `X-Webhook-Timestamp`) and the
//! legacy body-only `X-Webhook-Signature`; `scheme` pins one (or `bearer`). Incident and
//! ticket sources: PagerDuty v3 (`X-PagerDuty-Signature: v1=<hex HMAC>`, several during a
//! secret rotation) and Jira / JSM (`X-Hub-Signature: sha256=<hex HMAC>`); their event types
//! come from `event.event_type` (PagerDuty) and `webhookEvent` (Jira).
//! Then a per-route rate limit (30/min), a 1 MB cap, a 1 h idempotency cache
//! (X-GitHub-Delivery / svix-id / webhook-id / X-Request-ID), declarative
//! filters, the prompt template, and optional coalescing (latest event wins).
//!
//! Also from Hermes: `script` transforms (an executable under `<data>/scripts`
//! gets the payload on stdin; a JSON object on stdout replaces it, other text
//! lands in `script_output`, non-zero / empty / `[SILENT]` drops the event; no
//! shell, cleared environment, `script_timeout_seconds`), `deliver` (the reply
//! goes to `log`, `github_comment` via the GitHub REST API with `github_token`,
//! or any configured channel as `<channel>` / `<channel>:<chat>`, with
//! `deliver_extra.chat_id` / `thread_id`; the daemon wires the peers through
//! `Channel::wire`), `deliver_only` (the rendered prompt is the message, no
//! agent run), `cron_job` (fire an existing seagent schedule with the rendered
//! prompt as per-run context), MCP event routes (`mcp_event = {server, name}`:
//! verification echo, terminated / gap envelopes, `eventId` idempotency,
//! `{data}`), and dynamic subscriptions in `<data>/channels/<name>.subscriptions.json`
//! (`seagent webhook subscribe|list|rm`, hot-reloaded when the file changes; static
//! routes win). Chunked request bodies are decoded under the same size cap.

use crate::http::{agent, post_cancellable};
use crate::{sleep_cancellable, Channel, ChannelError, ChannelErrorKind as K, Inbound, Outbound, Sent, Wiring};
use seagent_core::Cancel;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_BODY: usize = 1024 * 1024;
const MAX_HEAD: usize = 16 * 1024;
pub const INSECURE_NO_AUTH: &str = "INSECURE_NO_AUTH";
const REPLAY_WINDOW: i64 = 300;
const RATE_WINDOW: Duration = Duration::from_secs(60);
const IDEMPOTENCY_TTL: Duration = Duration::from_secs(3600);
/// How long a delivery's reply destination is remembered.
const REPLY_TTL: Duration = Duration::from_secs(6 * 3600);
const MAX_SCRIPT_OUTPUT: u64 = 1024 * 1024;
const MCP_DATA_CHARS: usize = 32_000;

pub struct Webhook {
    id: String,
    outbound_url: Option<String>,
    outbound_token: Option<String>,
    agent: ureq::Agent,
    rx: Mutex<Receiver<Inbound>>,
    server: Option<Server>,
    coalesced: Arc<Mutex<HashMap<String, Pending>>>,
    poll_timeout: Duration,
    out: Arc<Out>,
    ingress: Option<Arc<Ingress>>,
    pub retry_base: Duration,
    pub max_retries: u32,
}

struct Server {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl std::fmt::Debug for Webhook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Webhook").field("id", &self.id).field("listen", &self.local_addr()).field("outbound", &self.outbound_url.is_some()).finish()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr); // wake accept()
    }
}

pub struct WebhookOpts<'a> {
    pub listen: Option<&'a str>,
    pub token: Option<&'a str>,
    pub outbound_url: Option<&'a str>,
    pub outbound_token: Option<&'a str>,
    pub poll_timeout: Duration,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoalesceConfig {
    /// Payload field (`pull_request.number`) or template (`{repo.full_name}#{number}`).
    pub key: String,
    #[serde(default)]
    pub window_seconds: Option<f64>,
    #[serde(default)]
    pub max_wait_seconds: Option<f64>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Default `/webhooks/<name>`.
    #[serde(default)]
    pub path: Option<String>,
    /// Falls back to the channel-wide `secret`. `INSECURE_NO_AUTH` (loopback only) skips checks.
    #[serde(default)]
    pub secret: Option<String>,
    /// auto (default) | standard-webhooks | svix | github | gitlab | linear | pagerduty | jira | generic | bearer.
    #[serde(default)]
    pub scheme: Option<String>,
    #[serde(default)]
    pub events: Vec<String>,
    /// A filter spec or a list of them (all must match).
    #[serde(default)]
    pub filters: Option<Value>,
    /// `{dotted.field}` template; empty = the event as JSON.
    #[serde(default)]
    pub prompt: String,
    /// Template for the Inbound chat id; default one chat per delivery (Hermes).
    #[serde(default)]
    pub chat: Option<String>,
    #[serde(default)]
    pub coalesce: Option<CoalesceConfig>,
    /// Requests per minute (default: the channel's `rate_limit`, 30).
    #[serde(default)]
    pub rate_limit: Option<u32>,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Reply destination: `log`, `github_comment`, `<channel>` or `<channel>:<chat>`.
    /// Unset: the channel's `outbound_url`.
    #[serde(default)]
    pub deliver: Option<String>,
    /// `chat_id` / `thread_id` / `message_thread_id`, or `repo` + `pr_number` (templates).
    #[serde(default)]
    pub deliver_extra: serde_json::Map<String, Value>,
    /// The rendered prompt IS the message: deliver it without an agent run.
    #[serde(default)]
    pub deliver_only: bool,
    /// Fire this existing schedule (`seagent schedule list` id) per event instead of a webhook session.
    #[serde(default)]
    pub cron_job: Option<String>,
    /// Executable under the scripts dir; payload JSON on stdin, transformed JSON on stdout.
    #[serde(default)]
    pub script: Option<String>,
    /// MCP events subscription route: `{ server = "…", name = "…" }`.
    #[serde(default)]
    pub mcp_event: Option<Value>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
}

/// Signed routes (all optional; `Webhook::new` keeps the plain bearer behaviour).
#[derive(Debug, Clone, Default)]
pub struct RoutesOpts {
    pub routes: Vec<(String, RouteConfig)>,
    pub secret: Option<String>,
    pub rate_limit: u32,
    pub max_body: usize,
    /// Dynamic subscriptions file (hot-reloaded).
    pub subscriptions: Option<PathBuf>,
    /// Root `script` paths must resolve under.
    pub scripts_dir: Option<PathBuf>,
    /// Default 30 s.
    pub script_timeout: Duration,
    /// `github_comment` delivery: (API base URL, token).
    pub github: Option<(String, String)>,
}

#[derive(Clone)]
struct Route {
    name: String,
    path: String,
    secret: Option<String>,
    scheme: String,
    cfg: RouteConfig,
}

#[derive(Default)]
struct Limits {
    hits: HashMap<String, VecDeque<Instant>>,
    seen: HashMap<(String, String), Instant>,
}

struct Pending {
    msg: Inbound,
    first: Instant,
    due: Instant,
    count: usize,
}

struct Ingress {
    channel: String,
    token: Option<String>,
    tx: Sender<Inbound>,
    routes: Mutex<RouteTable>,
    listen: String,
    secret: Option<String>,
    out: Arc<Out>,
    scripts_dir: Option<PathBuf>,
    script_timeout: Duration,
    cursors: Mutex<std::collections::BTreeMap<String, String>>,
    rate_limit: u32,
    max_body: usize,
    limits: Mutex<Limits>,
    coalesced: Arc<Mutex<HashMap<String, Pending>>>,
}

fn is_loopback(listen: &str) -> bool {
    let host = match listen.rsplit_once(':') {
        Some((h, _)) => h.trim_start_matches('[').trim_end_matches(']'),
        None => listen,
    };
    host == "localhost" || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

impl Webhook {
    pub fn new(id: &str, o: WebhookOpts) -> Result<Self, String> {
        Self::with_routes(id, o, RoutesOpts::default())
    }

    pub fn with_routes(id: &str, o: WebhookOpts, r: RoutesOpts) -> Result<Self, String> {
        let (tx, rx) = mpsc::channel();
        let coalesced = Arc::new(Mutex::new(HashMap::new()));
        let out = Arc::new(Out { channel: id.to_string(), agent: agent(Duration::from_secs(30)), github: r.github.clone(), wiring: Mutex::new(Wiring::default()), replies: Mutex::new(HashMap::new()) });
        let mut ingress = None;
        let server = match o.listen {
            None => None,
            Some(addr) => {
                let token = o.token.map(str::trim).filter(|t| !t.is_empty()).map(str::to_string);
                // Subscriptions alone are enough once the file exists or a channel-wide secret is set.
                let subs = r.secret.is_some() || r.subscriptions.as_ref().is_some_and(|p| p.exists());
                if token.is_none() && r.routes.is_empty() && !subs {
                    return Err(format!("channel {id}: an inbound webhook needs a token (or signed `routes`, or `seagent webhook subscribe`)"));
                }
                let mut routes: Vec<Route> = Vec::new();
                for (name, cfg) in &r.routes {
                    let taken: Vec<&str> = routes.iter().map(|x| x.path.as_str()).collect();
                    routes.push(make_route(id, addr, &r.secret, name, cfg, &taken)?);
                }
                let l = TcpListener::bind(addr).map_err(|e| format!("channel {id}: cannot listen on {addr}: {e}"))?;
                let bound = l.local_addr().map_err(|e| e.to_string())?;
                let stop = Arc::new(AtomicBool::new(false));
                let mut table = RouteTable { fixed: routes, dynamic: vec![], subs: r.subscriptions.clone(), stat: None, terminated: Default::default() };
                table.reload(id, addr, &r.secret);
                let cursors = r.subscriptions.as_deref().map(|p| cursors_path(p, id)).and_then(|p| std::fs::read_to_string(p).ok()).and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
                let ing = Arc::new(Ingress {
                    channel: id.to_string(),
                    token,
                    tx,
                    routes: Mutex::new(table),
                    listen: addr.to_string(),
                    secret: r.secret.clone(),
                    out: out.clone(),
                    scripts_dir: r.scripts_dir.clone(),
                    script_timeout: if r.script_timeout.is_zero() { Duration::from_secs(30) } else { r.script_timeout },
                    cursors: Mutex::new(cursors),
                    rate_limit: if r.rate_limit == 0 { 30 } else { r.rate_limit },
                    max_body: if r.max_body == 0 { MAX_BODY } else { r.max_body },
                    limits: Mutex::new(Limits::default()),
                    coalesced: coalesced.clone(),
                });
                ingress = Some(ing.clone());
                let s = stop.clone();
                std::thread::spawn(move || accept_loop(l, s, ing));
                Some(Server { addr: bound, stop })
            }
        };
        if server.is_none() && o.outbound_url.is_none() {
            return Err(format!("channel {id}: webhook needs `listen` and/or `outbound_url`"));
        }
        Ok(Webhook {
            id: id.to_string(),
            outbound_url: o.outbound_url.map(str::to_string),
            outbound_token: o.outbound_token.map(str::to_string).filter(|t| !t.is_empty()),
            agent: agent(Duration::from_secs(30)),
            rx: Mutex::new(rx),
            server,
            coalesced,
            poll_timeout: o.poll_timeout,
            out,
            ingress,
            retry_base: Duration::from_millis(200),
            max_retries: 2,
        })
    }

    /// Last replay cursor an MCP event route was sent.
    pub fn mcp_cursor(&self, route: &str) -> Option<String> {
        self.ingress.as_ref().and_then(|i| i.cursors.lock().unwrap().get(route).cloned())
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.server.as_ref().map(|s| s.addr)
    }

    /// Coalesced events whose quiet window (or max wait) has passed.
    fn settle(&self, now: Instant) -> Vec<Inbound> {
        let mut g = self.coalesced.lock().unwrap();
        let due: Vec<String> = g.iter().filter(|(_, p)| p.due <= now).map(|(k, _)| k.clone()).collect();
        due.into_iter()
            .filter_map(|k| g.remove(&k))
            .map(|p| {
                let mut m = p.msg;
                if p.count > 1 {
                    m.text = format!("{}\n\n(Note: {} webhook events for this item arrived in quick succession and were coalesced — this is the most recent one; earlier events are superseded.)", m.text, p.count);
                }
                m
            })
            .collect()
    }
}

fn make_route(id: &str, listen: &str, default_secret: &Option<String>, name: &str, cfg: &RouteConfig, taken: &[&str]) -> Result<Route, String> {
    let secret = cfg.secret.clone().or_else(|| default_secret.clone()).filter(|s| !s.trim().is_empty());
    if secret.is_none() {
        return Err(format!("channel {id}: route `{name}` has no secret (set `secret` on the route or the channel; `{INSECURE_NO_AUTH}` for local tests)"));
    }
    if secret.as_deref() == Some(INSECURE_NO_AUTH) && !is_loopback(listen) {
        return Err(format!("channel {id}: route `{name}` uses {INSECURE_NO_AUTH} but listens on non-loopback {listen}"));
    }
    let scheme = cfg.scheme.clone().unwrap_or_else(|| "auto".into());
    if !["auto", "standard-webhooks", "svix", "github", "gitlab", "linear", "pagerduty", "jira", "generic", "bearer"].contains(&scheme.as_str()) {
        return Err(format!("channel {id}: route `{name}` has unknown scheme `{scheme}`"));
    }
    if let Some(c) = &cfg.coalesce {
        if c.key.trim().is_empty() {
            return Err(format!("channel {id}: route `{name}` coalesce needs a non-empty key"));
        }
        if c.window_seconds.is_some_and(|w| w <= 0.0) || c.max_wait_seconds.is_some_and(|w| w <= 0.0) {
            return Err(format!("channel {id}: route `{name}` coalesce windows must be positive"));
        }
    }
    if cfg.deliver_only {
        if matches!(cfg.deliver.as_deref(), None | Some("") | Some("log")) {
            return Err(format!("channel {id}: route `{name}` has deliver_only but no real `deliver` target"));
        }
        if cfg.cron_job.is_some() {
            return Err(format!("channel {id}: route `{name}` sets both deliver_only and cron_job"));
        }
    }
    let path = cfg.path.clone().unwrap_or_else(|| format!("/webhooks/{name}"));
    let path = if path.starts_with('/') { path } else { format!("/{path}") };
    if path == "/inbound" || taken.contains(&path.as_str()) {
        return Err(format!("channel {id}: route `{name}` path {path} is already taken"));
    }
    Ok(Route { name: name.to_string(), path, secret, scheme, cfg: cfg.clone() })
}

/// Static routes plus the hot-reloaded subscriptions file.
struct RouteTable {
    fixed: Vec<Route>,
    dynamic: Vec<Route>,
    subs: Option<PathBuf>,
    stat: Option<(u64, u64, i64, i64)>,
    /// MCP event routes whose server ended the subscription.
    terminated: std::collections::HashSet<String>,
}

impl RouteTable {
    /// Re-read the subscriptions file when its identity (inode, size, mtime) changed;
    /// a malformed file keeps the last good snapshot.
    fn reload(&mut self, id: &str, listen: &str, secret: &Option<String>) {
        let Some(p) = &self.subs else { return };
        #[cfg(unix)]
        let key = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(p).ok().map(|m| (m.ino(), m.len(), m.mtime(), m.mtime_nsec()))
        };
        // No portable inode: size + mtime (the writer renames a fresh temp file into place,
        // which always moves the mtime).
        #[cfg(not(unix))]
        let key = std::fs::metadata(p).ok().map(|m| {
            let t = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).unwrap_or_default();
            (0, m.len(), t.as_secs() as i64, t.subsec_nanos() as i64)
        });
        if key == self.stat {
            return;
        }
        self.stat = key;
        if key.is_none() {
            self.dynamic.clear();
            return;
        }
        let map = match std::fs::read_to_string(p).map(|t| serde_json::from_str::<Value>(&t)) {
            Ok(Ok(Value::Object(m))) => m,
            _ => return eprintln!("webhook {id}: cannot parse {}; keeping the previous subscriptions", p.display()),
        };
        let mut dynamic: Vec<Route> = vec![];
        for (name, v) in map {
            if self.fixed.iter().any(|r| r.name == name) {
                continue; // static routes take precedence
            }
            let taken: Vec<&str> = self.fixed.iter().chain(&dynamic).map(|r| r.path.as_str()).collect();
            match serde_json::from_value::<RouteConfig>(v).map_err(|e| e.to_string()).and_then(|c| make_route(id, listen, secret, &name, &c, &taken)) {
                Ok(r) => dynamic.push(r),
                Err(e) => eprintln!("webhook {id}: subscription `{name}` skipped: {e}"),
            }
        }
        self.dynamic = dynamic;
    }

    fn find(&self, path: &str) -> Option<Route> {
        self.fixed.iter().chain(&self.dynamic).find(|r| r.path == path && !self.terminated.contains(&r.name)).cloned()
    }
}

fn cursors_path(subs: &Path, channel: &str) -> PathBuf {
    subs.with_file_name(format!("{channel}.mcp_cursors.json"))
}

/// Where one delivery's reply goes (only the fields the sender consumes, as Hermes keeps them).
#[derive(Debug, Clone, PartialEq)]
struct Delivery {
    deliver: String,
    extra: serde_json::Map<String, Value>,
}

impl Delivery {
    fn new(deliver: &str, extra: &serde_json::Map<String, Value>, payload: &Value) -> Delivery {
        let fields: &[&str] = match deliver {
            "log" => &[],
            "github_comment" => &["repo", "pr_number"],
            _ => &["chat_id", "message_thread_id", "thread_id"],
        };
        let extra = fields
            .iter()
            .filter_map(|k| {
                let v = extra.get(*k)?;
                Some((k.to_string(), match v {
                    Value::String(t) if !t.is_empty() => Value::String(render_prompt(t, payload, "", "")),
                    v => v.clone(),
                }))
            })
            .collect();
        Delivery { deliver: deliver.to_string(), extra }
    }

    fn field(&self, k: &str) -> Option<String> {
        self.extra.get(k).map(py_str).filter(|v| !v.is_empty() && v != "None")
    }
}

fn repo_ok(repo: &str) -> bool {
    let ok = |p: &str| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
    matches!(repo.split_once('/'), Some((o, n)) if ok(o) && ok(n))
}

/// Hermes' autonomous silence rule: `[SILENT]` alone, or on the first or last line.
fn missing_chat(channel: &str, target: &str) -> String {
    format!("webhook {channel}: no chat to deliver to on `{target}` — use deliver = \"{target}:<chat id>\", set deliver_extra.chat_id, or set default_chat in [channels.{target}]")
}

fn is_silence(text: &str) -> bool {
    let t = text.trim();
    let lines: Vec<&str> = t.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    t == "[SILENT]" || lines.first() == Some(&"[SILENT]") || lines.last() == Some(&"[SILENT]")
}

/// Reply delivery shared by `send` and the listener (`deliver_only`).
struct Out {
    channel: String,
    agent: ureq::Agent,
    github: Option<(String, String)>,
    wiring: Mutex<Wiring>,
    replies: Mutex<HashMap<String, (Instant, Delivery)>>,
}

impl Out {
    fn remember(&self, chat: &str, d: Delivery) {
        let now = Instant::now();
        let mut g = self.replies.lock().unwrap();
        if g.len() >= 4096 {
            g.retain(|_, (t, _)| now.duration_since(*t) < REPLY_TTL);
        }
        g.insert(chat.to_string(), (now, d));
    }

    fn destination(&self, chat: &str) -> Option<Delivery> {
        self.replies.lock().unwrap().get(chat).filter(|(t, _)| t.elapsed() < REPLY_TTL).map(|(_, d)| d.clone())
    }

    fn deliver(&self, d: &Delivery, text: &str) -> Result<Sent, ChannelError> {
        match d.deliver.as_str() {
            "log" => {
                eprintln!("webhook {}: {}", self.channel, truncate_chars(text, 200));
                Ok(Sent::default())
            }
            "github_comment" => self.github_comment(d, text),
            target => {
                let (name, chat) = match target.split_once(':') {
                    Some((n, c)) => (n, Some(c.to_string()).filter(|c| !c.is_empty())),
                    None => (target, None),
                };
                if name == self.channel {
                    return Err(ChannelError::new(K::Fatal, format!("webhook {}: a route cannot deliver to its own channel", self.channel)));
                }
                let (ch, home) = {
                    let w = self.wiring.lock().unwrap();
                    let peer = w.peers.iter().find(|(n, ..)| n == name);
                    match peer.and_then(|(_, ch, home)| ch.upgrade().map(|c| (c, home.clone()))) {
                        Some(x) => x,
                        None => return Err(ChannelError::new(K::Fatal, format!("webhook {}: deliver target channel `{name}` is not running", self.channel))),
                    }
                };
                let chat = d.field("chat_id").or(chat).or(home).ok_or_else(|| ChannelError::new(K::Fatal, missing_chat(&self.channel, name)))?;
                let thread = d.field("message_thread_id").or_else(|| d.field("thread_id"));
                ch.send(&Outbound { chat, text: text.to_string(), thread, ..Default::default() })
            }
        }
    }

    /// POST /repos/{repo}/issues/{n}/comments (issues and PRs share it).
    fn github_comment(&self, d: &Delivery, text: &str) -> Result<Sent, ChannelError> {
        let (Some(repo), Some(n)) = (d.field("repo"), d.field("pr_number")) else {
            return Err(ChannelError::new(K::Fatal, "github_comment delivery missing repo or pr_number"));
        };
        let Some(n) = n.parse::<u64>().ok().filter(|n| *n > 0) else { return Err(ChannelError::new(K::Fatal, "github_comment: invalid pr_number")) };
        if !repo_ok(&repo) {
            return Err(ChannelError::new(K::Fatal, "github_comment: invalid repo format"));
        }
        let Some((api, token)) = &self.github else { return Err(ChannelError::new(K::Fatal, format!("webhook {}: github_comment needs `github_token`", self.channel))) };
        let url = format!("{}/repos/{repo}/issues/{n}/comments", api.trim_end_matches('/'));
        let headers = [("authorization", format!("Bearer {token}")), ("accept", "application/vnd.github+json".into()), ("x-github-api-version", "2022-11-28".into()), ("user-agent", "seagent-webhook".into()), ("content-type", "application/json".into())];
        let headers: Vec<(String, String)> = headers.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        let body = serde_json::to_vec(&json!({ "body": text })).expect("json");
        match post_cancellable(&self.agent, &url, &headers, body, &Cancel::new())? {
            Some(r) => match r.status {
                200..=299 => Ok(Sent { ids: serde_json::from_str::<Value>(&r.body).ok().and_then(|v| id_str(&v["id"])).into_iter().collect() }),
                401 | 403 => Err(ChannelError::new(K::Auth, format!("GitHub rejected the token (HTTP {})", r.status))),
                404 => Err(ChannelError::new(K::NotFound, format!("GitHub: {repo}#{n} not found"))),
                429 => Err(ChannelError::new(K::RateLimited { retry_after: r.retry_after }, "GitHub rate limited")),
                s if s >= 500 => Err(ChannelError::new(K::Network, format!("GitHub HTTP {s}"))),
                s => Err(ChannelError::new(K::Protocol, format!("GitHub HTTP {s}: {}", truncate_chars(&r.body, 200)))),
            },
            None => Err(ChannelError::new(K::Network, "cancelled")),
        }
    }
}


fn accept_loop(l: TcpListener, stop: Arc<AtomicBool>, ing: Arc<Ingress>) {
    for stream in l.incoming() {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let Ok(stream) = stream else { continue };
        let ing = ing.clone();
        std::thread::spawn(move || handle(stream, &ing));
    }
}

fn write_response(s: &mut TcpStream, status: u16, ctype: &str, body: &str) {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    };
    let _ = write!(s, "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    // Lingering close: drain what the client is still sending so the kernel
    // doesn't answer with RST and destroy the response before it is read.
    let _ = s.shutdown(std::net::Shutdown::Write);
    let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
    let mut sink = [0u8; 4096];
    let mut drained = 0;
    while drained < 2 * MAX_BODY {
        match s.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
}

fn respond(s: &mut TcpStream, status: u16, msg: &str) {
    let body = if status == 202 { msg.to_string() } else { json!({ "ok": false, "error": msg }).to_string() };
    write_response(s, status, "application/json", &body)
}

fn respond_json(s: &mut TcpStream, status: u16, v: Value) {
    write_response(s, status, "application/json", &v.to_string())
}

/// Constant-time comparison so the token can't be guessed byte by byte.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn id_str(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string).filter(|s| !s.is_empty()).or_else(|| v.as_i64().map(|n| n.to_string()))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn too_large(max: usize) -> &'static str {
    if max == MAX_BODY {
        "body over 1 MiB"
    } else {
        "Payload too large"
    }
}

/// Decode a `Transfer-Encoding: chunked` body, enforcing `max` on the decoded size.
fn read_chunked(s: &mut TcpStream, mut data: Vec<u8>, max: usize) -> Result<Vec<u8>, (u16, &'static str)> {
    let mut tmp = [0u8; 4096];
    let mut more = |data: &mut Vec<u8>| match s.read(&mut tmp) {
        Ok(0) | Err(_) => false,
        Ok(n) => {
            data.extend_from_slice(&tmp[..n]);
            true
        }
    };
    let (mut pos, mut body) = (0, Vec::new());
    loop {
        let eol = loop {
            if let Some(i) = data[pos..].windows(2).position(|w| w == b"\r\n") {
                break pos + i;
            }
            if data.len() - pos > 1024 || !more(&mut data) {
                return Err((400, "bad chunked body"));
            }
        };
        let line = std::str::from_utf8(&data[pos..eol]).unwrap_or("");
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16).map_err(|_| (400, "bad chunk size"))?;
        pos = eol + 2;
        if size == 0 {
            return Ok(body); // trailers are drained by the lingering close
        }
        if body.len() + size > max {
            return Err((413, too_large(max)));
        }
        while data.len() < pos + size + 2 {
            if !more(&mut data) {
                return Err((400, "body shorter than its chunks"));
            }
        }
        body.extend_from_slice(&data[pos..pos + size]);
        pos += size + 2;
    }
}

/// Read the rest of the body (`None` after answering an error). Like aiohttp: chunked is
/// decoded, and a request with neither Content-Length nor Transfer-Encoding has no body.
fn read_body(s: &mut TcpStream, h: &dyn Fn(&str) -> Option<String>, buf: &[u8], head_end: usize, max: usize) -> Option<Vec<u8>> {
    if let Some(te) = h("transfer-encoding") {
        if !te.to_ascii_lowercase().split(',').any(|t| t.trim() == "chunked") {
            respond(s, 400, "unsupported Transfer-Encoding");
            return None;
        }
        return match read_chunked(s, buf[head_end + 4..].to_vec(), max) {
            Ok(b) => Some(b),
            Err((st, msg)) => {
                respond(s, st, msg);
                None
            }
        };
    }
    let Some(len) = h("content-length") else { return Some(Vec::new()) };
    let Ok(len) = len.parse::<usize>() else {
        respond(s, 400, "bad Content-Length");
        return None;
    };
    if len > max {
        respond(s, 413, too_large(max));
        return None;
    }
    let mut tmp = [0u8; 4096];
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => {
                respond(s, 400, "body shorter than Content-Length");
                return None;
            }
            Ok(n) => body.extend_from_slice(&tmp[..n]),
        }
    }
    body.truncate(len);
    Some(body)
}

fn handle(mut s: TcpStream, ing: &Ingress) {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            if i > MAX_HEAD {
                return respond(&mut s, 431, "headers too large");
            }
            break i;
        }
        if buf.len() > MAX_HEAD {
            return respond(&mut s, 431, "headers too large");
        }
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut rl = lines.next().unwrap_or("").split_whitespace();
    let (method, path) = (rl.next().unwrap_or(""), rl.next().unwrap_or(""));
    let headers: Vec<(String, String)> = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    let h = |k: &str| headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let bare = path.split('?').next().unwrap_or("");
    let route = {
        let mut t = ing.routes.lock().unwrap();
        t.reload(&ing.channel, &ing.listen, &ing.secret);
        if bare == "/health" && method == "GET" && (!t.fixed.is_empty() || t.subs.is_some()) {
            drop(t);
            return respond_json(&mut s, 200, json!({"status": "ok", "platform": "webhook"}));
        }
        t.find(bare)
    };
    if let Some(route) = route {
        return handle_route(&mut s, ing, &route, method, &headers, &buf, head_end);
    }
    if bare != "/inbound" || ing.token.is_none() {
        return respond(&mut s, 404, "not found");
    }
    let token = ing.token.as_deref().unwrap_or("");
    if method != "POST" {
        return respond(&mut s, 405, "use POST");
    }
    let auth = h("authorization").unwrap_or_default();
    let auth = auth.strip_prefix("Bearer ").unwrap_or("");
    if !same(auth.trim().as_bytes(), token.as_bytes()) {
        return respond(&mut s, 401, "bad or missing bearer token");
    }
    let Some(body) = read_body(&mut s, &h, &buf, head_end, MAX_BODY) else { return };
    let v: Value = match serde_json::from_slice(&body) {
        Ok(v @ Value::Object(_)) => v,
        Ok(_) => return respond(&mut s, 400, "body must be a JSON object"),
        Err(e) => return respond(&mut s, 400, &format!("malformed JSON: {e}")),
    };
    let (Some(chat), Some(sender), Some(text)) = (id_str(&v["chat"]), id_str(&v["sender"]), v["text"].as_str().filter(|t| !t.trim().is_empty())) else {
        return respond(&mut s, 400, "need `chat`, `sender` and non-empty `text`");
    };
    let ts = now_unix();
    let message_id = id_str(&v["id"]).unwrap_or_else(|| format!("wh-{ts}-{}", SEQ.fetch_add(1, Ordering::SeqCst)));
    let m = Inbound { channel: ing.channel.clone(), chat, sender, sender_name: v["sender_name"].as_str().unwrap_or("").to_string(), text: text.to_string(), message_id: message_id.clone(), ts, ..Default::default() };
    if ing.tx.send(m).is_err() {
        return respond(&mut s, 404, "channel closed");
    }
    respond(&mut s, 202, &json!({ "ok": true, "message_id": message_id }).to_string());
}

fn handle_route(s: &mut TcpStream, ing: &Ingress, route: &Route, method: &str, headers: &[(String, String)], buf: &[u8], head_end: usize) {
    let h = |k: &str| headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let name = route.name.as_str();
    if method != "POST" {
        return respond_json(s, 405, json!({"error": "use POST"}));
    }
    if !route.cfg.enabled {
        return respond_json(s, 403, json!({"error": format!("Route disabled: {name}")}));
    }
    let Some(body) = read_body(s, &h, buf, head_end, ing.max_body) else { return };
    let Some(secret) = route.secret.as_deref() else { return respond_json(s, 403, json!({"error": "Webhook route is missing an HMAC secret"})) };
    if secret != INSECURE_NO_AUTH && !verify_signature(&route.scheme, headers, &body, secret, now_unix()) {
        return respond_json(s, 401, json!({"error": "Invalid signature"}));
    }
    let now = Instant::now();
    {
        let mut lim = ing.limits.lock().unwrap();
        let limit = route.cfg.rate_limit.unwrap_or(ing.rate_limit) as usize;
        let w = lim.hits.entry(name.to_string()).or_default();
        while w.front().is_some_and(|t| now.duration_since(*t) >= RATE_WINDOW) {
            w.pop_front();
        }
        if w.len() >= limit {
            return respond_json(s, 429, json!({"error": "Rate limit exceeded"}));
        }
        w.push_back(now);
    }
    let payload = match serde_json::from_slice::<Value>(&body) {
        Ok(v @ Value::Object(_)) => v,
        Ok(_) => return respond_json(s, 400, json!({"error": "Cannot parse body"})),
        Err(_) => match std::str::from_utf8(&body) {
            Ok(t) if t.contains('=') => Value::Object(seagent_net::parse_query(t.trim()).into_iter().map(|(k, v)| (k, Value::String(v))).collect()),
            _ => return respond_json(s, 400, json!({"error": "Cannot parse body"})),
        },
    };
    let mut header_id = ["x-github-delivery", "svix-id", "webhook-id", "x-request-id"].iter().find_map(|k| h(k)).filter(|v| !v.is_empty());
    let mcp = route.cfg.mcp_event.is_some();
    if mcp {
        // A top-level `type` is a control envelope; occurrences dedupe on `eventId`.
        if let Some(kind) = payload.get("type") {
            return mcp_control(s, ing, route, kind, &payload);
        }
        if let Some(c) = payload["cursor"].as_str().filter(|c| !c.is_empty()) {
            ing.store_cursor(name, c);
        }
        if let Some(e) = payload["eventId"].as_str().filter(|e| !e.is_empty()) {
            header_id = Some(format!("mcp-event:{e}"));
        }
    }
    let delivery_id = header_id.clone().unwrap_or_else(|| seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(16)));
    let event_type = h("x-github-event")
        .filter(|e| !e.is_empty())
        .or_else(|| h("x-gitlab-event").filter(|e| !e.is_empty()))
        .or_else(|| payload["event_type"].as_str().filter(|e| !e.is_empty()).map(str::to_string))
        .or_else(|| payload["event"]["event_type"].as_str().filter(|e| !e.is_empty()).map(str::to_string))
        .or_else(|| payload["webhookEvent"].as_str().filter(|e| !e.is_empty()).map(str::to_string))
        .or_else(|| payload["type"].as_str().filter(|e| !e.is_empty()).map(str::to_string))
        .unwrap_or_else(|| "unknown".into());
    if !route.cfg.events.is_empty() && !route.cfg.events.contains(&event_type) {
        return respond_json(s, 200, json!({"status": "ignored", "event": event_type}));
    }
    if let Some(f) = &route.cfg.filters {
        if !route_filters_match(f, &payload, &event_type, headers) {
            return respond_json(s, 200, json!({"status": "ignored", "reason": "filter", "route": name}));
        }
    }
    let mut payload = payload;
    if let Some(script) = &route.cfg.script {
        match run_script(ing.scripts_dir.as_deref(), script, &payload, ing.script_timeout) {
            Some(p) => payload = p,
            None => return respond_json(s, 200, json!({"status": "ignored", "reason": "script", "route": name})),
        }
    }
    let prompt = match mcp && route.cfg.prompt.contains("{data}") {
        true => render_mcp_prompt(&route.cfg.prompt, &payload, &event_type, name),
        false => render_prompt(&route.cfg.prompt, &payload, &event_type, name),
    };
    {
        let mut lim = ing.limits.lock().unwrap();
        if header_id.is_some() {
            let key = (name.to_string(), delivery_id.clone());
            if lim.seen.get(&key).is_some_and(|t| now.duration_since(*t) < IDEMPOTENCY_TTL) {
                return respond_json(s, 200, json!({"status": "duplicate", "delivery_id": delivery_id}));
            }
            lim.seen.insert(key, now);
            if lim.seen.len() > (ing.rate_limit as usize * 2).max(128) {
                lim.seen.retain(|_, t| now.duration_since(*t) < IDEMPOTENCY_TTL);
            }
        }
    }
    let delivery = route.cfg.deliver.as_deref().filter(|d| !d.is_empty()).map(|d| Delivery::new(d, &route.cfg.deliver_extra, &payload));
    if let Some(job) = &route.cfg.cron_job {
        let Some(fire) = ing.out.wiring.lock().unwrap().cron.clone() else { return respond_json(s, 503, json!({"error": "cron_job routes need the seagent daemon"})) };
        if let Err(e) = fire(job, &format!("Webhook event '{event_type}' on route '{name}' (delivery {delivery_id}):\n\n{prompt}")) {
            eprintln!("webhook {}: cron-trigger route {name} job {job}: {e}", ing.channel);
            return respond_json(s, 502, json!({"status": "error", "error": "Cron trigger failed", "delivery_id": delivery_id}));
        }
        return respond_json(s, 202, json!({"status": "accepted", "route": name, "cron_job": job, "event": event_type, "delivery_id": delivery_id}));
    }
    if route.cfg.deliver_only {
        let d = delivery.expect("validated: deliver_only has a target");
        return match ing.out.deliver(&d, &prompt) {
            Ok(_) => respond_json(s, 200, json!({"status": "delivered", "route": name, "target": d.deliver, "delivery_id": delivery_id})),
            Err(e) => {
                eprintln!("webhook {}: direct-deliver route {name} to {}: {e}", ing.channel, d.deliver);
                respond_json(s, 502, json!({"status": "error", "error": "Delivery failed", "delivery_id": delivery_id}))
            }
        };
    }
    let chat = match &route.cfg.chat {
        Some(t) => render_prompt(t, &payload, &event_type, name),
        None => format!("webhook:{name}:{delivery_id}"),
    };
    if let Some(d) = delivery {
        ing.out.remember(&chat, d);
    }
    let msg = Inbound {
        channel: ing.channel.clone(),
        chat,
        chat_name: format!("webhook/{name}"),
        sender: format!("webhook:{name}"),
        sender_name: name.to_string(),
        text: prompt,
        message_id: delivery_id.clone(),
        ts: now_unix(),
        ..Default::default()
    };
    if let Some(c) = &route.cfg.coalesce {
        if let Some(key) = coalesce_key(name, &c.key, &payload, &event_type) {
            let window = Duration::from_secs_f64(c.window_seconds.unwrap_or(30.0));
            let max_wait = Duration::from_secs_f64(c.max_wait_seconds.unwrap_or(300.0));
            let mut g = ing.coalesced.lock().unwrap();
            let (first, count) = g.get(&key).map(|p| (p.first, p.count + 1)).unwrap_or((now, 1));
            let due = (now + window).min(first + max_wait);
            g.insert(key, Pending { msg, first, due, count });
            return respond_json(s, 202, json!({"status": "coalesced", "route": name, "event": event_type, "delivery_id": delivery_id}));
        }
    }
    if ing.tx.send(msg).is_err() {
        return respond_json(s, 503, json!({"error": "channel closed"}));
    }
    respond_json(s, 202, json!({"status": "accepted", "route": name, "event": event_type, "delivery_id": delivery_id}))
}

impl Ingress {
    fn store_cursor(&self, route: &str, cursor: &str) {
        let mut g = self.cursors.lock().unwrap();
        g.insert(route.to_string(), cursor.to_string());
        if let Some(p) = self.routes.lock().unwrap().subs.as_deref().map(|p| cursors_path(p, &self.channel)) {
            let _ = write_private(&p, &serde_json::to_vec_pretty(&*g).unwrap_or_default());
        }
    }
}

/// Hermes `webhook_mcp_events`: answer verification / terminated / gap without an agent run.
fn mcp_control(s: &mut TcpStream, ing: &Ingress, route: &Route, kind: &Value, p: &Value) {
    let name = route.name.as_str();
    match kind.as_str() {
        Some("verification") => match p["challenge"].as_str().filter(|c| !c.is_empty() && c.chars().count() <= 512) {
            Some(c) => respond_json(s, 200, json!({"challenge": c})),
            None => respond_json(s, 400, json!({"error": "Invalid verification challenge"})),
        },
        Some("terminated") => {
            let subs = {
                let mut t = ing.routes.lock().unwrap();
                t.terminated.insert(name.to_string());
                t.dynamic.iter().any(|r| r.name == name).then(|| t.subs.clone()).flatten()
            };
            if let Some(p) = subs {
                let _ = unsubscribe(&p, name);
            }
            ing.cursors.lock().unwrap().remove(name);
            let ev = route.cfg.mcp_event.clone().unwrap_or_default();
            eprintln!("webhook {}: MCP server '{}' ended event subscription {name}", ing.channel, py_str(&ev["server"]));
            if let Some(d) = route.cfg.deliver.as_deref().filter(|d| !d.is_empty() && *d != "log").map(|d| Delivery::new(d, &route.cfg.deliver_extra, p)) {
                let err = &p["error"];
                let detail = err["message"].as_str().filter(|m| !m.is_empty()).map(str::to_string).unwrap_or_else(|| match &err["message"] {
                    Value::Null => "no reason given".into(),
                    v => py_str(v),
                });
                let notice = format!(
                    "MCP server '{}' ended the subscription to '{}': {} (code {}). Subscribe again to keep receiving these events.",
                    py_str(&ev["server"]),
                    py_str(&ev["name"]),
                    truncate_chars(&detail, 200),
                    py_str(&err["code"])
                );
                if let Err(e) = ing.out.deliver(&d, &notice) {
                    eprintln!("webhook {}: terminated notice for {name}: {e}", ing.channel);
                }
            }
            respond_json(s, 200, json!({"status": "terminated"}))
        }
        Some("gap") => {
            if let Some(c) = p["cursor"].as_str().filter(|c| !c.is_empty()) {
                ing.store_cursor(name, c);
            }
            respond_json(s, 200, json!({"status": "gap"}))
        }
        // A later revision's envelope: acknowledge so the server stops retrying; never a run.
        other => respond_json(s, 200, json!({"status": "ignored", "type": other})),
    }
}

/// `{data}` takes the whole event payload (32 000 chars, noted when cut) and goes in after the
/// rest renders, so text inside the payload is never read as a placeholder.
fn render_mcp_prompt(template: &str, payload: &Value, event_type: &str, route: &str) -> String {
    let mut data = pretty(&payload["data"]);
    let n = data.chars().count();
    if n > MCP_DATA_CHARS {
        data = format!("{}\n[truncated: the first {MCP_DATA_CHARS} of {n} characters]", truncate_chars(&data, MCP_DATA_CHARS));
    }
    template.split("{data}").map(|part| if part.is_empty() { String::new() } else { render_prompt(part, payload, event_type, route) }).collect::<Vec<_>>().join(&data)
}

/// Hermes `run_route_script`: `Some(payload)` to continue, `None` drops the event. The
/// script must resolve under `dir`; `.py` runs with python3, `.sh`/`.bash` with bash, anything
/// else is executed directly. No shell, a cleared environment, killed after `timeout`.
fn run_script(dir: Option<&Path>, script: &str, payload: &Value, timeout: Duration) -> Option<Value> {
    use std::process::{Command, Stdio};
    let fail = |why: String| -> Option<Value> {
        eprintln!("webhook: script ignored webhook: {why}");
        None
    };
    let Some(root) = dir.and_then(|d| d.canonicalize().ok()) else { return fail("no scripts directory".into()) };
    let raw = Path::new(script.trim());
    let Ok(path) = (if raw.is_absolute() { raw.to_path_buf() } else { root.join(raw) }).canonicalize() else { return fail(format!("script not found: {script}")) };
    if !path.starts_with(&root) || !path.is_file() {
        return fail(format!("script path resolves outside {} or is not a file", root.display()));
    }
    #[cfg(unix)]
    let mut cmd = match path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).as_deref() {
        Some("py") => Command::new("python3"),
        Some("sh" | "bash") => Command::new("bash"),
        _ => Command::new(&path),
    };
    #[cfg(not(unix))]
    let mut cmd = match path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).as_deref() {
        Some("py") => {
            use seagent_core::platform::layout::which;
            match which("python3").or_else(|| which("python")).or_else(|| which("py")) {
                Some(p) => Command::new(p),
                None => return fail("python script but no python3 / python / py on PATH".into()),
            }
        }
        Some("sh" | "bash") => {
            let sh = seagent_core::platform::shell::active();
            if !sh.kind.is_posix() {
                return fail(format!("{} needs bash (Git for Windows or MSYS2); this machine's shell is {}", path.display(), sh.kind.as_str()));
            }
            Command::new(&sh.program)
        }
        _ => Command::new(&path),
    };
    if cmd.get_program() != path.as_os_str() {
        cmd.arg(&path);
    }
    cmd.current_dir(path.parent().unwrap_or(&root)).env_clear();
    for k in ["PATH", "HOME", "LANG", "LC_ALL", "TZ"] {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }
    // Windows programs cannot start (or find their profile / temp dir) without these.
    #[cfg(windows)]
    for k in ["SYSTEMROOT", "WINDIR", "USERPROFILE", "TEMP", "TMP", "PATHEXT", "COMSPEC"] {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(not(unix))]
    seagent_core::platform::proc::new_group(&mut cmd, false);
    let mut child = match cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(e) => return fail(format!("cannot run {}: {e}", path.display())),
    };
    #[cfg(not(unix))]
    if let Err(e) = seagent_core::platform::proc::adopt(&child) {
        let _ = child.kill();
        let _ = child.wait();
        return fail(format!("cannot contain {}: {e}", path.display()));
    }
    let (mut stdin, stdout, stderr) = (child.stdin.take()?, child.stdout.take()?, child.stderr.take()?);
    let input = payload.to_string();
    std::thread::spawn(move || {
        let _ = stdin.write_all(input.as_bytes());
    });
    let collect = |r: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = r.take(MAX_SCRIPT_OUTPUT).read_to_end(&mut b);
            String::from_utf8_lossy(&b).trim().to_string()
        })
    };
    let (out, err) = (collect(Box::new(stdout)), collect(Box::new(stderr)));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                // SAFETY: signalling the process group we created for this child.
                #[cfg(unix)]
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL)
                };
                #[cfg(not(unix))]
                seagent_core::platform::proc::kill_group(child.id() as i32, Duration::ZERO);
                let _ = child.wait();
                return fail(format!("script timed out: {}", path.display()));
            }
        }
    };
    let (stdout, stderr) = (out.join().unwrap_or_default(), err.join().unwrap_or_default());
    if !status.success() || stdout.is_empty() || stdout == "[SILENT]" {
        if !status.success() {
            eprintln!("webhook: script ignored webhook path={} code={:?} stderr={}", path.display(), status.code(), truncate_chars(&stderr, 200));
        }
        return None;
    }
    let v = match serde_json::from_str::<Value>(&stdout) {
        Ok(v) => v,
        Err(_) => {
            let mut p = payload.clone();
            if let Some(o) = p.as_object_mut() {
                o.insert("script_output".into(), Value::String(stdout));
            }
            p
        }
    };
    let Some(o) = v.as_object() else { return fail("script stdout must be a JSON object or text".into()) };
    if o.get("[SILENT]") == Some(&Value::Bool(true)) || o.get("__hermes_ignore__") == Some(&Value::Bool(true)) {
        return None;
    }
    Some(v)
}

// ---------------------------------------------------------------------------
// Dynamic subscriptions (`seagent webhook subscribe`, Hermes `webhook_subscriptions.json`)
// ---------------------------------------------------------------------------

/// `<data>/channels/<channel>.subscriptions.json`.
pub fn subscriptions_path(state_dir: &Path, channel: &str) -> PathBuf {
    state_dir.join(format!("{channel}.subscriptions.json"))
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut f = crate::open_private_tmp(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path) // new inode: the listener's stat check sees it
}

pub fn list_subscriptions(path: &Path) -> Result<serde_json::Map<String, Value>, String> {
    match std::fs::read_to_string(path) {
        Ok(t) if t.trim().is_empty() => Ok(Default::default()),
        Ok(t) => match serde_json::from_str(&t) {
            Ok(Value::Object(m)) => Ok(m),
            _ => Err(format!("{} is not a JSON object", path.display())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
        Err(e) => Err(e.to_string()),
    }
}

/// Add or replace route `name`; a missing secret is generated. Returns the stored route.
pub fn subscribe(path: &Path, name: &str, route: Value) -> Result<Value, String> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("route names use letters, digits, `-` and `_`".into());
    }
    let Value::Object(mut r) = route else { return Err("route must be an object".into()) };
    let mut subs = list_subscriptions(path)?;
    let old_secret = subs.get(name).and_then(|o| o["secret"].as_str()).map(str::to_string);
    if !r.get("secret").is_some_and(|s| s.as_str().is_some_and(|s| !s.trim().is_empty())) {
        r.insert("secret".into(), Value::String(old_secret.unwrap_or_else(|| seagent_net::crypto::b64url(&seagent_net::crypto::random_bytes(32)))));
    }
    r.entry("created_at").or_insert_with(|| Value::String(rfc3339(now_unix())));
    let v = Value::Object(r);
    let cfg: RouteConfig = serde_json::from_value(v.clone()).map_err(|e| format!("route `{name}`: {e}"))?;
    make_route("subscriptions", "127.0.0.1:0", &None, name, &cfg, &[])?;
    subs.insert(name.to_string(), v.clone());
    write_private(path, &serde_json::to_vec_pretty(&subs).unwrap_or_default()).map_err(|e| e.to_string())?;
    Ok(v)
}

pub fn unsubscribe(path: &Path, name: &str) -> Result<bool, String> {
    let mut subs = list_subscriptions(path)?;
    if subs.remove(name).is_none() {
        return Ok(false);
    }
    write_private(path, &serde_json::to_vec_pretty(&subs).unwrap_or_default()).map_err(|e| e.to_string())?;
    Ok(true)
}

fn rfc3339(t: i64) -> String {
    let (days, secs) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, secs % 3600 / 60, secs % 60)
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

fn hex_hmac(secret: &str, data: &[u8]) -> String {
    seagent_net::crypto::hex(&seagent_net::crypto::hmac_sha256(secret.as_bytes(), data))
}

fn str_eq(a: &str, b: &str) -> bool {
    seagent_net::crypto::ct_eq(a.as_bytes(), b.as_bytes())
}

fn fresh(ts: &str, now: i64) -> bool {
    ts.trim().parse::<i64>().is_ok_and(|t| (now - t).abs() <= REPLAY_WINDOW)
}

/// Svix / Standard Webhooks: base64 HMAC-SHA256 of "{id}.{timestamp}.{body}", `v1,<sig>` list.
pub(crate) fn verify_svix(body: &[u8], secret: &str, id: &str, ts: &str, sigs: &str, now: i64) -> bool {
    if id.is_empty() || ts.is_empty() || sigs.is_empty() || secret.is_empty() || !fresh(ts, now) {
        return false;
    }
    let key = match secret.strip_prefix("whsec_") {
        Some(k) => match seagent_net::crypto::b64_decode(k) {
            Some(k) if k.iter().any(|b| !b" \t\r\n\x0b\x0c\x00".contains(b)) => k,
            _ => return false,
        },
        None => secret.as_bytes().to_vec(),
    };
    let mut signed = format!("{id}.{ts}.").into_bytes();
    signed.extend_from_slice(body);
    let expected = seagent_net::crypto::b64(&seagent_net::crypto::hmac_sha256(&key, &signed));
    sigs.split_whitespace().any(|part| matches!(part.split_once(','), Some(("v1", sig)) if str_eq(sig, &expected)))
}

/// Hermes' detection order (`auto`), or one pinned scheme. `headers` keys are lowercase.
pub(crate) fn verify_signature(scheme: &str, headers: &[(String, String)], body: &[u8], secret: &str, now: i64) -> bool {
    let h = |k: &str| headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str()).unwrap_or("");
    let svix = || verify_svix(body, secret, h("svix-id"), h("svix-timestamp"), h("svix-signature"), now);
    let standard = || verify_svix(body, secret, h("webhook-id"), h("webhook-timestamp"), h("webhook-signature"), now);
    let generic = || {
        let v2 = h("x-webhook-signature-v2");
        if !v2.is_empty() {
            // The V2 header commits to V2: never fall back to the replayable V1 check.
            let ts = h("x-webhook-timestamp");
            if ts.is_empty() || !fresh(ts, now) {
                return false;
            }
            let mut data = format!("{ts}.").into_bytes();
            data.extend_from_slice(body);
            return str_eq(v2, &hex_hmac(secret, &data));
        }
        let v1 = h("x-webhook-signature");
        !v1.is_empty() && str_eq(v1, &hex_hmac(secret, body))
    };
    let provided = |k: &str| Some(h(k)).filter(|v| !v.is_empty());
    // PagerDuty: comma-separated `v1=<hex>` (more than one while a secret rotates).
    let pagerduty = |p: &str| {
        let want = format!("v1={}", hex_hmac(secret, body));
        p.split(',').any(|s| str_eq(s.trim(), &want))
    };
    let jira = |p: &str| str_eq(p, &format!("sha256={}", hex_hmac(secret, body)));
    match scheme {
        "svix" | "standard-webhooks" => {
            if !h("svix-signature").is_empty() || !h("svix-id").is_empty() {
                svix()
            } else {
                standard()
            }
        }
        "github" => provided("x-hub-signature-256").is_some_and(|p| str_eq(p, &format!("sha256={}", hex_hmac(secret, body)))),
        "gitlab" => provided("x-gitlab-token").is_some_and(|p| str_eq(p, secret)),
        "linear" => provided("linear-signature").is_some_and(|p| str_eq(p, &hex_hmac(secret, body))),
        "pagerduty" => provided("x-pagerduty-signature").is_some_and(pagerduty),
        "jira" => provided("x-hub-signature").or_else(|| provided("x-hub-signature-256")).is_some_and(jira),
        "generic" => generic(),
        "bearer" => h("authorization").strip_prefix("Bearer ").is_some_and(|t| str_eq(t.trim(), secret)),
        _ => {
            if !h("svix-id").is_empty() || !h("svix-timestamp").is_empty() || !h("svix-signature").is_empty() {
                return svix();
            }
            if !h("webhook-signature").is_empty() {
                return standard();
            }
            if let Some(p) = provided("linear-signature") {
                return str_eq(p, &hex_hmac(secret, body));
            }
            if let Some(p) = provided("x-hub-signature-256") {
                return str_eq(p, &format!("sha256={}", hex_hmac(secret, body)));
            }
            if let Some(p) = provided("x-gitlab-token") {
                return str_eq(p, secret);
            }
            if let Some(p) = provided("x-pagerduty-signature") {
                return pagerduty(p);
            }
            if let Some(p) = provided("x-hub-signature") {
                return jira(p);
            }
            generic()
        }
    }
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

/// Python `str()` of a JSON scalar (Hermes renders with it).
pub(crate) fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Null => "None".into(),
        other => other.to_string(),
    }
}

fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Substitute `{dotted.key}` placeholders; unknown keys stay literal. `special` claims
/// names first; objects/arrays render through `nested`.
pub(crate) fn render_template(t: &str, root: &Value, special: &dyn Fn(&str) -> Option<String>, nested: &dyn Fn(&Value) -> String) -> String {
    let mut out = String::with_capacity(t.len());
    let mut rest = t;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 1..];
        let end = tail.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'));
        match end {
            Some(e) if e > 0 && tail[e..].starts_with('}') => {
                let key = &tail[..e];
                out.push_str(&special(key).unwrap_or_else(|| {
                    let mut v = root;
                    for part in key.split('.') {
                        match v.get(part) {
                            Some(x) if v.is_object() => v = x,
                            _ => return format!("{{{key}}}"),
                        }
                    }
                    if v.is_object() || v.is_array() {
                        nested(v)
                    } else {
                        py_str(v)
                    }
                }));
                rest = &tail[e + 1..];
            }
            _ => {
                out.push('{');
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

pub(crate) fn render_prompt(template: &str, payload: &Value, event_type: &str, route: &str) -> String {
    if template.is_empty() {
        return format!("Webhook event '{event_type}' on route '{route}':\n\n```json\n{}\n```", truncate_chars(&pretty(payload), 4000));
    }
    let special = |k: &str| match k {
        "__raw__" => Some(truncate_chars(&pretty(payload), 4000)),
        "event_type" => Some(event_type.to_string()),
        _ => None,
    };
    render_template(template, payload, &special, &|v| truncate_chars(&pretty(v), 2000))
}

fn has_placeholder(s: &str) -> bool {
    let mut rest = s;
    while let Some(i) = rest.find('{') {
        let tail = &rest[i + 1..];
        if let Some(e) = tail.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.')) {
            if e > 0 && tail[e..].starts_with('}') {
                return true;
            }
        }
        rest = tail;
    }
    false
}

/// `route|rendered key`, or None when a field did not resolve (dispatch immediately).
fn coalesce_key(route: &str, key: &str, payload: &Value, event_type: &str) -> Option<String> {
    let k = key.trim();
    let template = if k.contains('{') { k.to_string() } else { format!("{{{k}}}") };
    let rendered = render_prompt(&template, payload, event_type, route);
    (!has_placeholder(&rendered)).then(|| format!("{route}|{rendered}"))
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

/// Resolve `payload.x`, `headers.x`, `event`/`event_type`, or a bare dotted path into the payload.
fn resolve_field(field: &Value, payload: &Value, event_type: &str, headers: &[(String, String)]) -> Option<Value> {
    let f = field.as_str()?.trim();
    let parts: Vec<&str> = f.split('.').filter(|p| !p.is_empty()).collect();
    let (first, rest) = parts.split_first()?;
    let headers_obj = || Value::Object(headers.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect());
    let (mut v, rest): (Value, &[&str]) = match *first {
        "payload" => (payload.get("payload").cloned().unwrap_or_else(|| payload.clone()), rest),
        "event" | "event_type" => (Value::String(event_type.to_string()), rest),
        "headers" => (headers_obj(), rest),
        _ => (payload.clone(), &parts[..]),
    };
    for (i, part) in rest.iter().enumerate() {
        let next = match &v {
            Value::Object(o) => o.get(*part).or_else(|| if *first == "headers" && i == 0 { o.get(&part.to_ascii_lowercase()) } else { None }).cloned(),
            Value::Array(a) => part.parse::<usize>().ok().and_then(|n| a.get(n)).cloned(),
            _ => None,
        };
        v = next?;
    }
    Some(v)
}

/// JSON equality with Python's numeric semantics (1 == 1.0).
fn json_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| json_eq(p, q)),
        _ => a == b,
    }
}

fn stringify(v: &Value) -> String {
    match v {
        Value::Object(_) | Value::Array(_) => v.to_string(),
        other => py_str(other),
    }
}

fn file_values(path: &Value) -> Vec<Value> {
    let Some(p) = path.as_str() else { return vec![] };
    let p = match p.strip_prefix("~/") {
        Some(rest) => std::env::var("HOME").map(|h| format!("{h}/{rest}")).unwrap_or_else(|_| p.to_string()),
        None => p.to_string(),
    };
    let Ok(raw) = std::fs::read_to_string(p) else { return vec![] };
    match serde_json::from_str::<Value>(raw.trim_start_matches('\u{feff}')) {
        Ok(Value::Array(a)) => a,
        Ok(Value::Object(o)) => o.keys().map(|k| Value::String(k.clone())).collect(),
        Ok(other) => vec![other],
        Err(_) => raw.lines().map(str::trim).filter(|l| !l.is_empty()).map(|l| Value::String(l.to_string())).collect(),
    }
}

pub(crate) fn filter_matches(spec: &Value, payload: &Value, event_type: &str, headers: &[(String, String)]) -> bool {
    let Some(o) = spec.as_object() else { return false };
    let sub = |s: &Value| filter_matches(s, payload, event_type, headers);
    if let Some(items) = o.get("all") {
        return items.as_array().is_some_and(|a| a.iter().all(sub));
    }
    if let Some(items) = o.get("any") {
        return items.as_array().is_some_and(|a| a.iter().any(sub));
    }
    if let Some(s) = o.get("not") {
        return !sub(s);
    }
    let value = resolve_field(o.get("field").unwrap_or(&Value::Null), payload, event_type, headers);
    if !o.contains_key("exists") && o.get("missing") == Some(&Value::Bool(true)) {
        return value.is_none();
    }
    if let Some(arg) = o.get("exists") {
        let want = match arg {
            Value::Bool(b) => *b,
            Value::Null => false,
            Value::Number(n) => n.as_f64() != Some(0.0),
            Value::String(s) => !s.is_empty(),
            _ => true,
        };
        return value.is_some() == want;
    }
    if let Some(arg) = o.get("equals") {
        return value.is_some_and(|v| json_eq(&v, arg));
    }
    if let Some(arg) = o.get("not_equals") {
        return value.is_none_or(|v| !json_eq(&v, arg));
    }
    if let Some(arg) = o.get("contains") {
        return match value {
            None => false,
            Some(Value::Array(a)) => a.iter().any(|x| json_eq(x, arg)),
            Some(Value::Object(m)) => arg.as_str().is_some_and(|k| m.contains_key(k)),
            Some(v) => stringify(&v).contains(&stringify(arg)),
        };
    }
    if let Some(arg) = o.get("in") {
        return value.is_some_and(|v| arg.as_array().is_some_and(|a| a.iter().any(|x| json_eq(x, &v))));
    }
    if let Some(arg) = o.get("in_file") {
        return value.is_some_and(|v| file_values(arg).iter().any(|x| json_eq(x, &v)));
    }
    if let Some(arg) = o.get("regex") {
        return value.is_some_and(|v| regex::is_match(&py_str(arg), &stringify(&v)).unwrap_or(false));
    }
    false
}

pub(crate) fn route_filters_match(filters: &Value, payload: &Value, event_type: &str, headers: &[(String, String)]) -> bool {
    match filters {
        Value::Null => true,
        Value::Array(a) => a.iter().all(|f| filter_matches(f, payload, event_type, headers)),
        Value::Object(_) => filter_matches(filters, payload, event_type, headers),
        _ => false,
    }
}

/// A small backtracking regex (no regex crate here): literals, `.`, classes with
/// ranges/negation, `\d \w \s` (and negations), `\b`, anchors, groups with `|`,
/// `(?:…)`, `(?i)`, and `* + ? {n} {n,} {n,m}` (greedy or lazy). `re.search` semantics.
pub(crate) mod regex {
    #[derive(Debug, Clone)]
    enum Node {
        Char(char),
        Any,
        Class(Vec<(char, char)>, bool),
        Start,
        End,
        WordB(bool),
        Group(Vec<Vec<Node>>),
        Repeat(Box<Node>, usize, Option<usize>, bool),
    }

    struct Parser {
        c: Vec<char>,
        i: usize,
    }

    const DIGIT: &[(char, char)] = &[('0', '9')];
    const WORD: &[(char, char)] = &[('a', 'z'), ('A', 'Z'), ('0', '9'), ('_', '_')];
    const SPACE: &[(char, char)] = &[(' ', ' '), ('\t', '\r')];

    fn negate(r: &[(char, char)]) -> Vec<(char, char)> {
        let mut v: Vec<(char, char)> = r.to_vec();
        v.sort();
        let mut out = vec![];
        let mut lo = '\0';
        for (a, b) in v {
            if a > lo {
                out.push((lo, char::from_u32(a as u32 - 1).unwrap_or(lo)));
            }
            lo = char::from_u32(b as u32 + 1).unwrap_or(char::MAX);
        }
        out.push((lo, char::MAX));
        out
    }

    impl Parser {
        fn peek(&self) -> Option<char> {
            self.c.get(self.i).copied()
        }
        fn alt(&mut self) -> Result<Vec<Vec<Node>>, String> {
            let mut alts = vec![self.seq()?];
            while self.peek() == Some('|') {
                self.i += 1;
                alts.push(self.seq()?);
            }
            Ok(alts)
        }
        fn seq(&mut self) -> Result<Vec<Node>, String> {
            let mut out = vec![];
            while let Some(c) = self.peek() {
                if c == '|' || c == ')' {
                    break;
                }
                let atom = self.atom()?;
                out.push(self.quant(atom)?);
            }
            Ok(out)
        }
        fn number(&mut self) -> Option<usize> {
            let s = self.i;
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.i += 1;
            }
            self.c[s..self.i].iter().collect::<String>().parse().ok()
        }
        fn quant(&mut self, atom: Node) -> Result<Node, String> {
            let (min, max) = match self.peek() {
                Some('*') => (0, None),
                Some('+') => (1, None),
                Some('?') => (0, Some(1)),
                Some('{') => {
                    let save = self.i;
                    self.i += 1;
                    let Some(lo) = self.number() else {
                        self.i = save;
                        return Ok(atom);
                    };
                    let hi = if self.peek() == Some(',') {
                        self.i += 1;
                        self.number()
                    } else {
                        Some(lo)
                    };
                    if self.peek() != Some('}') {
                        self.i = save;
                        return Ok(atom);
                    }
                    if hi.is_some_and(|h| h < lo) {
                        return Err("bad repeat range".into());
                    }
                    (lo, hi)
                }
                _ => return Ok(atom),
            };
            self.i += 1;
            if matches!(atom, Node::Start | Node::End | Node::WordB(_)) {
                return Err("nothing to repeat".into());
            }
            let greedy = if self.peek() == Some('?') {
                self.i += 1;
                false
            } else {
                true
            };
            Ok(Node::Repeat(Box::new(atom), min, max, greedy))
        }
        fn escape(&mut self) -> Result<Node, String> {
            let c = self.peek().ok_or("trailing backslash")?;
            self.i += 1;
            Ok(match c {
                'd' => Node::Class(DIGIT.to_vec(), false),
                'D' => Node::Class(DIGIT.to_vec(), true),
                'w' => Node::Class(WORD.to_vec(), false),
                'W' => Node::Class(WORD.to_vec(), true),
                's' => Node::Class(SPACE.to_vec(), false),
                'S' => Node::Class(SPACE.to_vec(), true),
                'b' => Node::WordB(true),
                'B' => Node::WordB(false),
                'n' => Node::Char('\n'),
                't' => Node::Char('\t'),
                'r' => Node::Char('\r'),
                other => Node::Char(other),
            })
        }
        fn class(&mut self) -> Result<Node, String> {
            let neg = self.peek() == Some('^');
            if neg {
                self.i += 1;
            }
            let mut ranges = vec![];
            let mut first = true;
            loop {
                let c = self.peek().ok_or("unterminated character class")?;
                self.i += 1;
                if c == ']' && !first {
                    break;
                }
                first = false;
                let lo = if c == '\\' {
                    let e = self.peek().ok_or("bad escape")?;
                    self.i += 1;
                    match e {
                        'd' => {
                            ranges.extend_from_slice(DIGIT);
                            continue;
                        }
                        'w' => {
                            ranges.extend_from_slice(WORD);
                            continue;
                        }
                        's' => {
                            ranges.extend_from_slice(SPACE);
                            continue;
                        }
                        'D' | 'W' | 'S' => {
                            let base = match e {
                                'D' => DIGIT,
                                'W' => WORD,
                                _ => SPACE,
                            };
                            ranges.extend(negate(base));
                            continue;
                        }
                        'n' => '\n',
                        't' => '\t',
                        other => other,
                    }
                } else {
                    c
                };
                if self.peek() == Some('-') && self.c.get(self.i + 1).is_some_and(|&n| n != ']') {
                    self.i += 1;
                    let mut hi = self.peek().ok_or("bad range")?;
                    self.i += 1;
                    if hi == '\\' {
                        hi = self.peek().ok_or("bad range")?;
                        self.i += 1;
                    }
                    if hi < lo {
                        return Err("bad character range".into());
                    }
                    ranges.push((lo, hi));
                } else {
                    ranges.push((lo, lo));
                }
            }
            Ok(Node::Class(ranges, neg))
        }
        fn atom(&mut self) -> Result<Node, String> {
            let c = self.peek().ok_or("unexpected end")?;
            self.i += 1;
            Ok(match c {
                '.' => Node::Any,
                '^' => Node::Start,
                '$' => Node::End,
                '\\' => self.escape()?,
                '[' => self.class()?,
                '(' => {
                    if self.peek() == Some('?') {
                        if self.c.get(self.i + 1) == Some(&':') {
                            self.i += 2;
                        } else {
                            return Err("unsupported group syntax".into());
                        }
                    }
                    let alts = self.alt()?;
                    if self.peek() != Some(')') {
                        return Err("missing )".into());
                    }
                    self.i += 1;
                    Node::Group(alts)
                }
                '*' | '+' | '?' => return Err("nothing to repeat".into()),
                ')' => return Err("unbalanced )".into()),
                other => Node::Char(other),
            })
        }
    }

    struct M<'a> {
        t: &'a [char],
        icase: bool,
        steps: std::cell::Cell<usize>,
    }

    const MAX_STEPS: usize = 2_000_000;

    impl M<'_> {
        fn fold(&self, c: char) -> char {
            if self.icase {
                c.to_lowercase().next().unwrap_or(c)
            } else {
                c
            }
        }
        fn single(&self, n: &Node, c: char) -> Option<bool> {
            Some(match n {
                Node::Char(x) => self.fold(*x) == self.fold(c),
                Node::Any => c != '\n',
                Node::Class(r, neg) => {
                    let hit = |ch: char| r.iter().any(|(a, b)| *a <= ch && ch <= *b);
                    let inside = hit(c) || (self.icase && (hit(c.to_lowercase().next().unwrap_or(c)) || hit(c.to_uppercase().next().unwrap_or(c))));
                    inside != *neg
                }
                _ => return None,
            })
        }
        fn word(&self, i: usize) -> bool {
            self.t.get(i).is_some_and(|c| c.is_alphanumeric() || *c == '_')
        }
        fn tick(&self) -> bool {
            self.steps.set(self.steps.get() + 1);
            self.steps.get() < MAX_STEPS
        }
        fn seq(&self, s: &[Node], pos: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
            if !self.tick() {
                return false;
            }
            match s.split_first() {
                None => k(pos),
                Some((n, rest)) => self.node(n, pos, &mut |p| self.seq(rest, p, k)),
            }
        }
        fn node(&self, n: &Node, pos: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
            match n {
                Node::Start => pos == 0 && k(pos),
                Node::End => pos == self.t.len() && k(pos),
                Node::WordB(want) => {
                    let b = pos > 0 && self.word(pos - 1);
                    ((b != self.word(pos)) == *want) && k(pos)
                }
                Node::Group(alts) => alts.iter().any(|a| self.seq(a, pos, k)),
                Node::Repeat(inner, min, max, greedy) => {
                    if self.single(inner, 'a').is_some() {
                        // Single-character repeats: count the run iteratively (no deep recursion).
                        let mut run = 0;
                        while max.is_none_or(|m| run < m) && pos + run < self.t.len() && self.single(inner, self.t[pos + run]) == Some(true) {
                            run += 1;
                        }
                        if run < *min {
                            return false;
                        }
                        if *greedy {
                            (*min..=run).rev().any(|c| self.tick() && k(pos + c))
                        } else {
                            (*min..=run).any(|c| self.tick() && k(pos + c))
                        }
                    } else {
                        self.rep(inner, *min, *max, *greedy, pos, 0, k)
                    }
                }
                single => pos < self.t.len() && self.single(single, self.t[pos]) == Some(true) && k(pos + 1),
            }
        }
        #[allow(clippy::too_many_arguments)]
        fn rep(&self, inner: &Node, min: usize, max: Option<usize>, greedy: bool, pos: usize, count: usize, k: &mut dyn FnMut(usize) -> bool) -> bool {
            if !self.tick() {
                return false;
            }
            let can_more = max.is_none_or(|m| count < m);
            if count < min {
                return can_more && self.node(inner, pos, &mut |p| self.rep(inner, min, max, greedy, p, count + 1, k));
            }
            if greedy {
                if can_more && self.node(inner, pos, &mut |p| p != pos && self.rep(inner, min, max, greedy, p, count + 1, k)) {
                    return true;
                }
                k(pos)
            } else {
                if k(pos) {
                    return true;
                }
                can_more && self.node(inner, pos, &mut |p| p != pos && self.rep(inner, min, max, greedy, p, count + 1, k))
            }
        }
    }

    pub fn is_match(pattern: &str, text: &str) -> Result<bool, String> {
        let (pattern, icase) = match pattern.strip_prefix("(?i)") {
            Some(p) => (p, true),
            None => (pattern, false),
        };
        let mut p = Parser { c: pattern.chars().collect(), i: 0 };
        let alts = p.alt()?;
        if p.i != p.c.len() {
            return Err("unbalanced )".into());
        }
        let root = vec![Node::Group(alts)];
        let t: Vec<char> = text.chars().take(64 * 1024).collect();
        let m = M { t: &t, icase, steps: std::cell::Cell::new(0) };
        Ok((0..=t.len()).any(|start| m.seq(&root, start, &mut |_| true)))
    }
}

impl Channel for Webhook {
    fn id(&self) -> &str {
        &self.id
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        if self.server.is_none() {
            sleep_cancellable(self.poll_timeout, cancel);
            return Ok(vec![]);
        }
        let rx = self.rx.lock().unwrap();
        let until = Instant::now() + self.poll_timeout;
        let mut out = vec![];
        while !cancel.is_cancelled() && Instant::now() < until {
            out.extend(self.settle(Instant::now()));
            match rx.recv_timeout(Duration::from_millis(25)) {
                Ok(m) => {
                    out.push(m);
                    out.extend(rx.try_iter());
                    break;
                }
                Err(RecvTimeoutError::Timeout) if !out.is_empty() => break,
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(ChannelError::new(K::Fatal, "webhook listener stopped")),
            }
        }
        Ok(out)
    }

    fn wire(&self, w: &Wiring) {
        *self.out.wiring.lock().unwrap() = w.clone();
        // Say at startup what would otherwise fail on the first event, in the daemon log only.
        if let Some(ing) = &self.ingress {
            for r in ing.routes.lock().unwrap().fixed.iter() {
                let Some(target) = r.cfg.deliver.as_deref() else { continue };
                if matches!(target, "log" | "github_comment") || target.contains(':') || r.cfg.deliver_extra.contains_key("chat_id") {
                    continue;
                }
                match w.peers.iter().find(|(n, ..)| n == target) {
                    None => eprintln!("seagent: warning: [channels.{}.routes.{}] delivers to `{target}`, which is not a running channel", self.id, r.name),
                    Some((_, _, None)) => eprintln!("seagent: warning: [channels.{}.routes.{}] {}", self.id, r.name, missing_chat(&self.id, target)),
                    _ => {}
                }
            }
        }
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        // Replies to a routed delivery go where its route says (Hermes `deliver`).
        if let Some(d) = self.out.destination(&out.chat) {
            if is_silence(&out.text) {
                return Ok(Sent::default());
            }
            return self.out.deliver(&d, &out.text);
        }
        let url = self.outbound_url.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, format!("channel {} has no outbound_url", self.id)))?;
        let headers: Vec<(String, String)> = self.outbound_token.iter().map(|t| ("authorization".to_string(), format!("Bearer {t}"))).collect();
        let body = serde_json::to_vec(&json!({ "chat": out.chat, "text": out.text, "reply_to": out.reply_to })).expect("json");
        let cancel = Cancel::new();
        let mut attempt = 0;
        loop {
            let err = match post_cancellable(&self.agent, url, &headers, body.clone(), &cancel) {
                Ok(Some(r)) => match r.status {
                    200..=299 => return Ok(Sent { ids: serde_json::from_str::<Value>(&r.body).ok().and_then(|v| id_str(&v["message_id"])).into_iter().collect() }),
                    401 | 403 => return Err(ChannelError::new(K::Auth, format!("webhook rejected credentials (HTTP {})", r.status))),
                    429 => ChannelError::new(K::RateLimited { retry_after: r.retry_after }, "webhook rate limited"),
                    s if s >= 500 => ChannelError::new(K::Network, format!("webhook HTTP {s}")),
                    s => return Err(ChannelError::new(K::Protocol, format!("webhook HTTP {s}: {}", r.body.chars().take(200).collect::<String>()))),
                },
                Ok(None) => return Err(ChannelError::new(K::Network, "cancelled")),
                Err(e) => e,
            };
            if attempt >= self.max_retries {
                return Err(err);
            }
            let wait = match err.kind {
                K::RateLimited { retry_after: Some(d) } if d > Duration::from_secs(10) => return Err(err),
                K::RateLimited { retry_after: Some(d) } => d,
                _ => self.retry_base * 2u32.pow(attempt),
            };
            sleep_cancellable(wait, &cancel);
            attempt += 1;
        }
    }
}

fn d_poll() -> u64 {
    25
}
fn d_rate() -> u32 {
    30
}
fn d_max_body() -> usize {
    MAX_BODY
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    outbound_url: Option<String>,
    #[serde(default)]
    outbound_token: Option<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    /// Default HMAC secret for `routes`.
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    routes: std::collections::BTreeMap<String, RouteConfig>,
    /// Per-route requests per minute.
    #[serde(default = "d_rate")]
    rate_limit: u32,
    #[serde(default = "d_max_body")]
    max_body_bytes: usize,
    /// For `deliver = "github_comment"`.
    #[serde(default)]
    github_token: Option<String>,
    #[serde(default = "d_github")]
    github_api_url: String,
    /// Default `<data>/scripts`.
    #[serde(default)]
    scripts_dir: Option<String>,
    #[serde(default = "d_script_timeout")]
    script_timeout_seconds: u64,
}

fn d_github() -> String {
    "https://api.github.com".into()
}
fn d_script_timeout() -> u64 {
    30
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<std::sync::Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let token = ctx.opt_secret("token", &st.token)?;
    let outbound_token = ctx.opt_secret("outbound_token", &st.outbound_token)?;
    let outbound_url = ctx.opt_secret("outbound_url", &st.outbound_url)?;
    let secret = ctx.opt_secret("secret", &st.secret)?;
    let mut routes = Vec::new();
    for (name, mut r) in st.routes {
        r.secret = ctx.opt_secret(&format!("routes.{name}.secret"), &r.secret)?;
        routes.push((name, r));
    }
    let github = ctx.opt_secret("github_token", &st.github_token)?.map(|t| (st.github_api_url.clone(), t));
    let scripts_dir = st.scripts_dir.map(PathBuf::from).or_else(|| ctx.state_dir.parent().map(|d| d.join("scripts")));
    let w = Webhook::with_routes(
        ctx.name,
        WebhookOpts { listen: st.listen.as_deref(), token: token.as_deref(), outbound_url: outbound_url.as_deref(), outbound_token: outbound_token.as_deref(), poll_timeout: Duration::from_secs(st.poll_timeout_secs) },
        RoutesOpts {
            routes,
            secret,
            rate_limit: st.rate_limit,
            max_body: st.max_body_bytes,
            subscriptions: Some(subscriptions_path(ctx.state_dir, ctx.name)),
            scripts_dir,
            script_timeout: Duration::from_secs(st.script_timeout_seconds),
            github,
        },
    )?;
    Ok(std::sync::Arc::new(w))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakeServer;

    fn inbound_only() -> Webhook {
        Webhook::new("wh", WebhookOpts { listen: Some("127.0.0.1:0"), token: Some("tok"), outbound_url: None, outbound_token: None, poll_timeout: Duration::from_millis(300) }).unwrap()
    }

    /// Raw request; returns (status, body).
    fn raw(addr: SocketAddr, req: &[u8]) -> (u16, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(req).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        let status = out.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
        (status, out.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
    }

    fn post(addr: SocketAddr, path: &str, auth: Option<&str>, body: &str) -> (u16, String) {
        let a = auth.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
        raw(addr, format!("POST {path} HTTP/1.1\r\nHost: x\r\n{a}Content-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
    }

    #[test]
    fn accepts_authorised_messages_and_rejects_everything_else() {
        let w = inbound_only();
        let a = w.local_addr().unwrap();
        let good = r#"{"chat":"c1","sender":7,"text":"hello","id":"m1"}"#;
        assert_eq!(post(a, "/inbound", None, good).0, 401);
        assert_eq!(post(a, "/inbound", Some("tok2"), good).0, 401);
        assert_eq!(post(a, "/inbound", Some("to"), good).0, 401);
        assert_eq!(post(a, "/other", Some("tok"), good).0, 404);
        assert_eq!(raw(a, b"GET /inbound HTTP/1.1\r\nAuthorization: Bearer tok\r\n\r\n").0, 405);
        assert_eq!(post(a, "/inbound", Some("tok"), "{not json").0, 400);
        assert_eq!(post(a, "/inbound", Some("tok"), "[1,2]").0, 400);
        assert_eq!(post(a, "/inbound", Some("tok"), r#"{"chat":"c","sender":"s","text":"  "}"#).0, 400);
        assert_eq!(raw(a, b"POST /inbound HTTP/1.1\r\nAuthorization: Bearer tok\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n").0, 400, "chunked is decoded (then not JSON)");
        assert_eq!(raw(a, b"POST /inbound HTTP/1.1\r\nAuthorization: Bearer tok\r\n\r\n").0, 400, "no length = empty body");
        assert_eq!(raw(a, b"POST /inbound HTTP/1.1\r\nAuthorization: Bearer tok\r\nTransfer-Encoding: gzip\r\n\r\n").0, 400);
        assert_eq!(raw(a, b"POST /inbound HTTP/1.1\r\nAuthorization: Bearer tok\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n").0, 400);
        let big_chunk = format!("POST /inbound HTTP/1.1\r\nAuthorization: Bearer tok\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n", MAX_BODY + 1);
        assert_eq!(raw(a, big_chunk.as_bytes()).0, 413, "decoded size is capped");
        let big = format!("POST /inbound HTTP/1.1\r\nAuthorization: Bearer tok\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1);
        assert_eq!(raw(a, big.as_bytes()).0, 413, "rejected before reading the body");
        let huge_head = format!("POST /inbound HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD + 10));
        assert_eq!(raw(a, huge_head.as_bytes()).0, 431);
        assert!(w.poll(&Cancel::new()).unwrap().is_empty(), "nothing rejected got through");

        let (st, body) = post(a, "/inbound", Some("tok"), good);
        assert_eq!(st, 202, "{body}");
        assert!(body.contains("\"m1\""));
        assert_eq!(post(a, "/inbound?x=1", Some("tok"), r#"{"chat":5,"sender":"u","text":"two"}"#).0, 202);
        let chunked = b"POST /inbound HTTP/1.1\r\nAuthorization: Bearer tok\r\nTransfer-Encoding: chunked\r\n\r\n11;ext=1\r\n{\"chat\":\"c\",\"send\r\n17\r\ner\":\"s\",\"text\":\"three\"}\r\n0\r\n\r\n";
        assert_eq!(raw(a, chunked).0, 202, "chunked body accepted");
        std::thread::sleep(Duration::from_millis(50));
        let got = w.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[2].text, "three");
        assert_eq!((got[0].chat.as_str(), got[0].sender.as_str(), got[0].text.as_str(), got[0].message_id.as_str()), ("c1", "7", "hello", "m1"));
        assert_eq!(got[1].chat, "5");
        assert!(got[1].message_id.starts_with("wh-"));
    }

    #[test]
    fn slow_or_truncated_clients_do_not_wedge_the_listener() {
        let w = inbound_only();
        let a = w.local_addr().unwrap();
        // Client promises 100 bytes and hangs up after 3.
        let mut half = TcpStream::connect(a).unwrap();
        half.write_all(b"POST /inbound HTTP/1.1\r\nAuthorization: Bearer tok\r\nContent-Length: 100\r\n\r\n{\"a").unwrap();
        half.shutdown(std::net::Shutdown::Write).unwrap();
        let mut out = String::new();
        let _ = half.read_to_string(&mut out);
        assert!(out.starts_with("HTTP/1.1 400"), "{out}");
        let _idle = TcpStream::connect(a).unwrap(); // never sends anything
        assert_eq!(post(a, "/inbound", Some("tok"), r#"{"chat":"c","sender":"s","text":"ok"}"#).0, 202);
        let c = Cancel::new();
        assert_eq!(w.poll(&c).unwrap().len(), 1);
        // Timeout and cancel both return empty quickly.
        let t = Instant::now();
        assert!(w.poll(&c).unwrap().is_empty());
        assert!(t.elapsed() < Duration::from_secs(2));
        c.cancel();
        assert!(w.poll(&c).unwrap().is_empty());
    }

    #[test]
    fn listener_requires_token_and_free_port() {
        let o = |listen, token| WebhookOpts { listen, token, outbound_url: None, outbound_token: None, poll_timeout: Duration::from_millis(10) };
        assert!(Webhook::new("w", o(Some("127.0.0.1:0"), None)).unwrap_err().contains("token"));
        assert!(Webhook::new("w", o(Some("127.0.0.1:0"), Some(" "))).is_err());
        assert!(Webhook::new("w", o(None, None)).unwrap_err().contains("outbound_url"));
        let w = inbound_only();
        let taken = w.local_addr().unwrap().to_string();
        assert!(Webhook::new("w", o(Some(&taken), Some("t"))).unwrap_err().contains("cannot listen"));
        drop(w);
    }

    #[test]
    fn outbound_posts_json_with_bearer_and_maps_errors() {
        let srv = FakeServer::start(|req, _| match req.json()["chat"].as_str() {
            Some("ok") => (200, vec![], "{}".into()),
            Some("auth") => (403, vec![], "".into()),
            Some("bad") => (422, vec![], "unprocessable".into()),
            Some("slow") => (429, vec![("Retry-After".into(), "120".into())], "".into()),
            _ => (503, vec![], "".into()),
        });
        let mut w = Webhook::new("wh", WebhookOpts { listen: None, token: None, outbound_url: Some(&format!("{}/hook", srv.url)), outbound_token: Some("out"), poll_timeout: Duration::from_millis(10) }).unwrap();
        w.retry_base = Duration::from_millis(1);
        let send = |chat: &str| w.send(&Outbound { chat: chat.into(), text: "hi".into(), reply_to: Some("r".into()), ..Default::default() });
        send("ok").unwrap();
        let r = &srv.requests()[0];
        assert_eq!((r.path.as_str(), r.header("authorization")), ("/hook", Some("Bearer out")));
        assert_eq!(r.json(), json!({"chat": "ok", "text": "hi", "reply_to": "r"}));
        assert_eq!(send("auth").unwrap_err().kind, K::Auth);
        assert_eq!(send("bad").unwrap_err().kind, K::Protocol);
        assert_eq!(send("slow").unwrap_err().kind, K::RateLimited { retry_after: Some(Duration::from_secs(120)) });
        let before = srv.requests().len();
        assert_eq!(send("down").unwrap_err().kind, K::Network);
        assert_eq!(srv.requests().len() - before, 3, "retried 5xx");
        // Inbound-only channel cannot send; outbound-only poll just waits.
        assert_eq!(inbound_only().send(&Outbound { chat: "c".into(), text: "x".into(), reply_to: None, ..Default::default() }).unwrap_err().kind, K::Fatal);
        assert!(w.poll(&Cancel::new()).unwrap().is_empty());
    }

    // ---- Hermes-style signed routes ----

    fn route(v: Value) -> RouteConfig {
        serde_json::from_value(v).unwrap()
    }

    fn routed(routes: Vec<(&str, Value)>) -> Webhook {
        Webhook::with_routes(
            "wh",
            WebhookOpts { listen: Some("127.0.0.1:0"), token: None, outbound_url: None, outbound_token: None, poll_timeout: Duration::from_millis(300) },
            RoutesOpts { routes: routes.into_iter().map(|(n, v)| (n.to_string(), route(v))).collect(), secret: Some("topsecret".into()), rate_limit: 30, max_body: 2048, ..Default::default() },
        )
        .unwrap()
    }

    fn post_h(addr: SocketAddr, path: &str, headers: &[(&str, &str)], body: &str) -> (u16, Value) {
        let hs: String = headers.iter().map(|(k, v)| format!("{k}: {v}\r\n")).collect();
        let (st, b) = raw(addr, format!("POST {path} HTTP/1.1\r\nHost: x\r\n{hs}Content-Length: {}\r\n\r\n{body}", body.len()).as_bytes());
        (st, serde_json::from_str(&b).unwrap_or(Value::Null))
    }

    /// PagerDuty v3 and Jira webhook signatures (ent-105 / ent-107), pinned and auto-detected.
    #[test]
    fn pagerduty_and_jira_signatures() {
        let body = br#"{"event":{"event_type":"incident.triggered","data":{"id":"P1"}}}"#;
        let sig = hexmac("pdsecret", std::str::from_utf8(body).unwrap());
        let hs = |k: &str, v: String| vec![(k.to_string(), v)];
        assert!(verify_signature("pagerduty", &hs("x-pagerduty-signature", format!("v1=deadbeef, v1={sig}")), body, "pdsecret", 0), "any v1 of a rotation");
        assert!(verify_signature("auto", &hs("x-pagerduty-signature", format!("v1={sig}")), body, "pdsecret", 0));
        assert!(!verify_signature("pagerduty", &hs("x-pagerduty-signature", format!("v1={sig}")), body, "other", 0));
        assert!(!verify_signature("pagerduty", &hs("x-pagerduty-signature", sig.clone()), body, "pdsecret", 0), "the v1= prefix is required");
        assert!(!verify_signature("pagerduty", &[], body, "pdsecret", 0));
        let jb = br#"{"webhookEvent":"jira:issue_created","issue":{"key":"OPS-1"}}"#;
        let js = format!("sha256={}", hexmac("jsecret", std::str::from_utf8(jb).unwrap()));
        assert!(verify_signature("jira", &hs("x-hub-signature", js.clone()), jb, "jsecret", 0));
        assert!(verify_signature("auto", &hs("x-hub-signature", js.clone()), jb, "jsecret", 0));
        assert!(!verify_signature("jira", &hs("x-hub-signature", js), jb, "wrong", 0));
        let cfg = RouteConfig { scheme: Some("pagerduty".into()), ..serde_json::from_value(json!({})).unwrap() };
        assert!(make_route("c", "127.0.0.1:0", &Some("s".into()), "pd", &cfg, &[]).is_ok());
    }

    fn hexmac(key: &str, data: &str) -> String {
        seagent_net::crypto::hex(&seagent_net::crypto::hmac_sha256(key.as_bytes(), data.as_bytes()))
    }

    #[test]
    fn routes_verify_every_signature_scheme() {
        let whsec_key = b"0123456789abcdef0123456789abcdef";
        let whsec = format!("whsec_{}", seagent_net::crypto::b64(whsec_key));
        let w = routed(vec![
            ("auto", json!({})),
            ("svix", json!({"secret": whsec, "scheme": "svix"})),
            ("gl", json!({"scheme": "gitlab"})),
            ("bear", json!({"scheme": "bearer", "path": "/custom/hook"})),
            ("open", json!({"secret": INSECURE_NO_AUTH})),
        ]);
        let a = w.local_addr().unwrap();
        let body = r#"{"action":"opened","number":7}"#;
        let now = now_unix().to_string();
        let gh = format!("sha256={}", hexmac("topsecret", body));
        assert_eq!(post_h(a, "/webhooks/auto", &[("X-Hub-Signature-256", &gh)], body).0, 202, "github");
        assert_eq!(post_h(a, "/webhooks/auto", &[("X-Hub-Signature-256", "sha256=00")], body).0, 401);
        assert_eq!(post_h(a, "/webhooks/auto", &[], body).0, 401, "missing signature");
        assert_eq!(post_h(a, "/webhooks/auto", &[("linear-signature", &hexmac("topsecret", body))], body).0, 202, "linear");
        assert_eq!(post_h(a, "/webhooks/auto", &[("X-Gitlab-Token", "topsecret")], body).0, 202, "gitlab token");
        assert_eq!(post_h(a, "/webhooks/auto", &[("X-Gitlab-Token", "nope")], body).0, 401);
        let v2 = hexmac("topsecret", &format!("{now}.{body}"));
        assert_eq!(post_h(a, "/webhooks/auto", &[("X-Webhook-Signature-V2", &v2), ("X-Webhook-Timestamp", &now)], body).0, 202, "generic v2");
        let old = (now_unix() - 301).to_string();
        let v2_old = hexmac("topsecret", &format!("{old}.{body}"));
        assert_eq!(post_h(a, "/webhooks/auto", &[("X-Webhook-Signature-V2", &v2_old), ("X-Webhook-Timestamp", &old)], body).0, 401, "v2 replay window");
        let v1 = hexmac("topsecret", body);
        assert_eq!(post_h(a, "/webhooks/auto", &[("X-Webhook-Signature-V2", &v2), ("X-Webhook-Signature", &v1)], body).0, 401, "V2 without timestamp never falls back to V1");
        assert_eq!(post_h(a, "/webhooks/auto", &[("X-Webhook-Signature", &v1)], body).0, 202, "legacy v1 still accepted");
        // Standard Webhooks (raw secret) on the auto route.
        let std_sig = seagent_net::crypto::b64(&seagent_net::crypto::hmac_sha256(b"topsecret", format!("msg_1.{now}.{body}").as_bytes()));
        assert_eq!(post_h(a, "/webhooks/auto", &[("webhook-id", "msg_1"), ("webhook-timestamp", &now), ("webhook-signature", &format!("v0,xx v1,{std_sig}"))], body).0, 202, "standard webhooks");
        // Svix with a whsec_ key.
        let sig = seagent_net::crypto::b64(&seagent_net::crypto::hmac_sha256(whsec_key, format!("msg_2.{now}.{body}").as_bytes()));
        assert_eq!(post_h(a, "/webhooks/svix", &[("svix-id", "msg_2"), ("svix-timestamp", &now), ("svix-signature", &format!("v1,{sig}"))], body).0, 202);
        assert_eq!(post_h(a, "/webhooks/svix", &[("svix-id", "msg_3"), ("svix-timestamp", &now), ("svix-signature", &format!("v1,{sig}"))], body).0, 401, "id is signed");
        let sig_old = seagent_net::crypto::b64(&seagent_net::crypto::hmac_sha256(whsec_key, format!("msg_2.{old}.{body}").as_bytes()));
        assert_eq!(post_h(a, "/webhooks/svix", &[("svix-id", "msg_2"), ("svix-timestamp", &old), ("svix-signature", &format!("v1,{sig_old}"))], body).0, 401, "svix replay window");
        assert_eq!(post_h(a, "/webhooks/svix", &[("X-Hub-Signature-256", &gh)], body).0, 401, "pinned scheme ignores other headers");
        assert_eq!(post_h(a, "/webhooks/gl", &[("X-Hub-Signature-256", &gh)], body).0, 401);
        assert_eq!(post_h(a, "/webhooks/gl", &[("X-Gitlab-Token", "topsecret")], body).0, 202);
        assert_eq!(post_h(a, "/custom/hook", &[("Authorization", "Bearer topsecret")], body).0, 202, "bearer + custom path");
        assert_eq!(post_h(a, "/custom/hook", &[("Authorization", "Bearer wrong")], body).0, 401);
        assert_eq!(post_h(a, "/webhooks/open", &[], body).0, 202, "INSECURE_NO_AUTH on loopback");
        assert_eq!(post_h(a, "/webhooks/missing", &[], body).0, 404);
        assert_eq!(post_h(a, "/inbound", &[("Authorization", "Bearer x")], "{}").0, 404, "no token → no /inbound");
        let got = w.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 10, "every accepted post, nothing rejected: {got:#?}");
        assert!(got.iter().all(|m| m.sender.starts_with("webhook:")));
    }

    #[test]
    fn routes_rate_limit_dedup_filter_and_render() {
        let w = routed(vec![
            ("gh", json!({"secret": INSECURE_NO_AUTH, "events": ["pull_request"], "prompt": "PR #{number}: {pull_request.title} by {pull_request.user.login} [{event_type}] {missing.key} {labels}", "filters": [{"field": "action", "in": ["opened", "synchronize"]}, {"not": {"field": "pull_request.draft", "equals": true}}, {"any": [{"field": "headers.x-github-event", "equals": "pull_request"}, {"field": "zzz", "exists": true}]}], "chat": "gh:{repository.full_name}"})),
            ("lim", json!({"secret": INSECURE_NO_AUTH, "rate_limit": 2})),
            ("off", json!({"secret": INSECURE_NO_AUTH, "enabled": false})),
        ]);
        let a = w.local_addr().unwrap();
        let pr = |action: &str, draft: bool| json!({"action": action, "number": 7, "labels": ["a"], "repository": {"full_name": "o/r"}, "pull_request": {"title": "Fix", "draft": draft, "user": {"login": "amy"}}}).to_string();
        let ev = ("X-GitHub-Event", "pull_request");
        let (st, b) = post_h(a, "/webhooks/gh", &[ev, ("X-GitHub-Delivery", "d1")], &pr("opened", false));
        assert_eq!((st, b["status"].as_str()), (202, Some("accepted")), "{b}");
        assert_eq!(post_h(a, "/webhooks/gh", &[ev, ("X-GitHub-Delivery", "d1")], &pr("opened", false)).1["status"], "duplicate");
        assert_eq!(post_h(a, "/webhooks/gh", &[("X-GitHub-Event", "push"), ("X-GitHub-Delivery", "d2")], &pr("opened", false)).1, json!({"status": "ignored", "event": "push"}));
        assert_eq!(post_h(a, "/webhooks/gh", &[ev, ("X-GitHub-Delivery", "d3")], &pr("closed", false)).1["reason"], "filter");
        assert_eq!(post_h(a, "/webhooks/gh", &[ev, ("X-GitHub-Delivery", "d4")], &pr("opened", true)).1["reason"], "filter");
        assert_eq!(post_h(a, "/webhooks/gh", &[ev], "not json, no form").0, 400);
        assert_eq!(post_h(a, "/webhooks/gh", &[ev], &"x".repeat(3000)).0, 413, "max_body_bytes");
        assert_eq!(post_h(a, "/webhooks/off", &[], "{}").0, 403);
        let lim: Vec<u16> = (0..3).map(|_| post_h(a, "/webhooks/lim", &[], "{}").0).collect();
        assert_eq!(lim, [202, 202, 429]);
        // Form-encoded bodies (Twilio-style) parse too.
        assert_eq!(post_h(a, "/webhooks/lim", &[], "a=1").0, 429, "still limited");
        let got = w.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 3);
        let m = &got[0];
        assert_eq!(m.text, "PR #7: Fix by amy [pull_request] {missing.key} [\n  \"a\"\n]");
        assert_eq!((m.chat.as_str(), m.sender.as_str(), m.message_id.as_str(), m.chat_name.as_str()), ("gh:o/r", "webhook:gh", "d1", "webhook/gh"));
        assert!(got[1].chat.starts_with("webhook:lim:") && got[1].text.starts_with("Webhook event 'unknown' on route 'lim'"));
        assert_ne!(got[1].message_id, got[2].message_id, "fresh ids without a delivery header");
    }

    #[test]
    fn routes_coalesce_bursts_latest_wins() {
        let w = routed(vec![("c", json!({"secret": INSECURE_NO_AUTH, "prompt": "{title}", "coalesce": {"key": "{repo}#{number}", "window_seconds": 0.3, "max_wait_seconds": 5}}))]);
        let a = w.local_addr().unwrap();
        for (i, t) in ["one", "two", "three"].iter().enumerate() {
            let (st, b) = post_h(a, "/webhooks/c", &[("X-Request-ID", &format!("r{i}"))], &json!({"repo": "x", "number": 1, "title": t}).to_string());
            assert_eq!((st, b["status"].as_str()), (202, Some("coalesced")));
        }
        // Unresolved key: dispatched immediately.
        assert_eq!(post_h(a, "/webhooks/c", &[], &json!({"title": "solo"}).to_string()).1["status"], "accepted");
        let first = w.poll(&Cancel::new()).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].text, "solo");
        let mut got = vec![];
        let start = Instant::now();
        while got.is_empty() && start.elapsed() < Duration::from_secs(3) {
            got = w.poll(&Cancel::new()).unwrap();
        }
        assert_eq!(got.len(), 1);
        assert!(got[0].text.starts_with("three\n\n(Note: 3 webhook events"), "{}", got[0].text);
        assert_eq!(got[0].message_id, "r2");
    }

    #[test]
    fn route_config_is_validated() {
        let mk = |listen: &str, secret: Option<&str>, r: Value| {
            Webhook::with_routes("w", WebhookOpts { listen: Some(listen), token: None, outbound_url: None, outbound_token: None, poll_timeout: Duration::from_millis(10) }, RoutesOpts { routes: vec![("r".into(), route(r))], secret: secret.map(str::to_string), ..Default::default() })
        };
        assert!(mk("127.0.0.1:0", None, json!({})).unwrap_err().contains("no secret"));
        assert!(mk("127.0.0.1:0", Some("  "), json!({})).unwrap_err().contains("no secret"));
        assert!(mk("0.0.0.0:0", None, json!({"secret": INSECURE_NO_AUTH})).unwrap_err().contains("non-loopback"));
        assert!(mk("127.0.0.1:0", Some("s"), json!({"scheme": "md5"})).unwrap_err().contains("scheme"));
        assert!(mk("127.0.0.1:0", Some("s"), json!({"coalesce": {"key": " "}})).is_err());
        assert!(mk("127.0.0.1:0", Some("s"), json!({"path": "/inbound"})).is_err());
        assert!(serde_json::from_value::<RouteConfig>(json!({"bogus": true})).is_err(), "unknown route keys rejected");
        assert!(mk("127.0.0.1:0", Some("s"), json!({"deliver_only": true})).unwrap_err().contains("deliver"));
        assert!(mk("127.0.0.1:0", Some("s"), json!({"deliver_only": true, "deliver": "log"})).is_err());
        assert!(mk("127.0.0.1:0", Some("s"), json!({"deliver_only": true, "deliver": "tg", "cron_job": "j"})).unwrap_err().contains("cron_job"));
        assert!(mk("127.0.0.1:0", Some("s"), json!({})).is_ok());
    }

    #[test]
    fn filter_operators_and_mini_regex() {
        let p = json!({"a": {"b": [10, {"c": "Hello World"}]}, "n": 1, "flag": false, "tags": ["x", "y"], "obj": {"k": 1}});
        let hs = vec![("x-github-event".to_string(), "push".to_string())];
        let m = |f: Value| filter_matches(&f, &p, "push", &hs);
        assert!(m(json!({"field": "a.b.1.c", "equals": "Hello World"})));
        assert!(m(json!({"field": "n", "equals": 1.0})), "numeric equality like Python");
        assert!(m(json!({"field": "nope", "not_equals": 3})));
        assert!(m(json!({"field": "a.b.1.c", "contains": "World"})));
        assert!(m(json!({"field": "tags", "contains": "x"})) && !m(json!({"field": "tags", "contains": "z"})));
        assert!(m(json!({"field": "obj", "contains": "k"})));
        assert!(m(json!({"field": "flag", "contains": "False"})), "Python str()");
        assert!(m(json!({"field": "nope", "missing": true})) && !m(json!({"field": "n", "missing": true})));
        assert!(m(json!({"field": "n", "exists": true})) && m(json!({"field": "zz", "exists": false})));
        assert!(m(json!({"field": "event", "equals": "push"})) && m(json!({"field": "headers.X-GitHub-Event", "equals": "push"})));
        assert!(m(json!({"field": "payload.n", "in": [1, 2]})));
        assert!(m(json!({"all": [{"field": "n", "equals": 1}, {"not": {"field": "flag", "equals": true}}]})));
        assert!(!m(json!({"any": []})) && m(json!({"all": []})));
        assert!(!m(json!({"field": "n"})), "no operator → false");
        assert!(!m(json!("bad spec")));
        assert!(m(json!({"field": "a.b.1.c", "regex": "^Hel+o\\s+W\\w+$"})));
        assert!(!m(json!({"field": "a.b.1.c", "regex": "("})), "invalid regex → false");
        let f = temp_file("allow.txt", "alice\n\nbob\n");
        assert!(filter_matches(&json!({"field": "u", "in_file": f}), &json!({"u": "bob"}), "", &[]));
        assert!(route_filters_match(&Value::Null, &p, "", &[]) && route_filters_match(&json!([]), &p, "", &[]));
        use super::regex::is_match as r;
        assert!(r("a.c", "xxabcxx").unwrap());
        assert!(!r("^a.c$", "xxabcxx").unwrap());
        assert!(r("^(foo|ba[rz])+$", "foobazbar").unwrap());
        assert!(r("colou?r", "color") .unwrap() && r("colou?r", "colour").unwrap());
        assert!(r("^\\d{3}-\\d{2,}$", "123-4567").unwrap() && !r("^\\d{3}-\\d{2,}$", "12-45").unwrap());
        assert!(r("(?i)HELLO", "say hello").unwrap());
        assert!(r("[^a-z]", "abc1").unwrap() && !r("^[^a-z]+$", "abc").unwrap());
        assert!(r("\\bcat\\b", "a cat sat").unwrap() && !r("\\bcat\\b", "concatenate").unwrap());
        assert!(r("<.+?>", "<a><b>").unwrap());
        assert!(r("(?:ab)*c", "ababc").unwrap());
        assert!(r("release/v[0-9]+\\.[0-9]+", "refs/heads/release/v1.20").unwrap());
        assert!(!r("(a*)*b", &"a".repeat(40)).unwrap(), "pathological pattern stops at the step budget");
        assert!(r("[", "x").is_err() && r("a{2,1}", "x").is_err() && r("*a", "x").is_err());
    }

    // ---- delivery, cron, scripts, MCP events, subscriptions ----

    #[derive(Default)]
    struct Peer(Mutex<Vec<Outbound>>);
    impl Channel for Peer {
        fn id(&self) -> &str {
            "tg"
        }
        fn poll(&self, _: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
            Ok(vec![])
        }
        fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
            self.0.lock().unwrap().push(out.clone());
            Ok(Sent { ids: vec!["p1".into()] })
        }
    }

    fn with_opts(routes: Vec<(&str, Value)>, f: impl FnOnce(&mut RoutesOpts)) -> Webhook {
        let mut r = RoutesOpts { routes: routes.into_iter().map(|(n, v)| (n.to_string(), route(v))).collect(), secret: Some(INSECURE_NO_AUTH.into()), ..Default::default() };
        f(&mut r);
        Webhook::with_routes("wh", WebhookOpts { listen: Some("127.0.0.1:0"), token: None, outbound_url: None, outbound_token: None, poll_timeout: Duration::from_millis(300) }, r).unwrap()
    }

    fn wire_peer(w: &Webhook, peer: &Arc<Peer>, cron: Option<crate::CronFire>) {
        let ch: Arc<dyn Channel> = peer.clone();
        w.wire(&Wiring { peers: vec![("tg".into(), Arc::downgrade(&ch), Some("home".into()))], cron, session_origin: None });
    }

    #[test]
    fn replies_and_deliver_only_go_to_other_channels() {
        let w = with_opts(
            vec![
                ("a", json!({"prompt": "a {n}", "deliver": "tg", "deliver_extra": {"chat_id": "c{n}", "thread_id": "t1", "token": "dropped"}})),
                ("b", json!({"prompt": "b", "deliver": "tg:room9"})),
                ("c", json!({"prompt": "alert {n}", "deliver": "tg", "deliver_only": true})),
                ("l", json!({"prompt": "l", "deliver": "log"})),
                ("self", json!({"prompt": "s", "deliver": "wh:x"})),
            ],
            |_| {},
        );
        let a = w.local_addr().unwrap();
        assert_eq!(post_h(a, "/webhooks/c", &[], r#"{"n":1}"#).0, 502, "nothing wired yet");
        let peer = Arc::new(Peer::default());
        wire_peer(&w, &peer, None);
        for r in ["a", "b", "l", "self"] {
            assert_eq!(post_h(a, &format!("/webhooks/{r}"), &[], r#"{"n":5}"#).0, 202);
        }
        let (st, b) = post_h(a, "/webhooks/c", &[], r#"{"n":2}"#);
        assert_eq!((st, b["status"].as_str(), b["target"].as_str()), (200, Some("delivered"), Some("tg")));
        let got = w.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 4, "deliver_only never starts a run");
        for m in &got {
            w.send(&Outbound::text(&m.chat, &format!("reply to {}", m.text))).unwrap_or_default();
        }
        assert!(w.send(&Outbound::text(&got[3].chat, "x")).unwrap_err().message.contains("own channel"));
        w.send(&Outbound::text(&got[0].chat, "thinking\n[SILENT]")).unwrap();
        let sent: Vec<(String, String, Option<String>)> = peer.0.lock().unwrap().iter().map(|o| (o.chat.clone(), o.text.clone(), o.thread.clone())).collect();
        assert_eq!(
            sent,
            [("home".into(), "alert 2".into(), None), ("c5".into(), "reply to a 5".into(), Some("t1".into())), ("room9".into(), "reply to b".into(), None)],
            "log route logged, silence dropped"
        );
        assert_eq!(w.send(&Outbound::text("unknown-chat", "x")).unwrap_err().kind, K::Fatal, "no outbound_url");
    }

    #[test]
    fn github_comment_posts_through_the_rest_api() {
        let srv = FakeServer::start(|req, _| match req.path.as_str() {
            "/repos/o/r/issues/7/comments" => (201, vec![], r#"{"id": 991}"#.into()),
            _ => (404, vec![], "{}".into()),
        });
        let w = with_opts(vec![("gh", json!({"deliver": "github_comment", "deliver_extra": {"repo": "{repository.full_name}", "pr_number": "{number}"}}))], |r| r.github = Some((srv.url.clone(), "ghtok".into())));
        let a = w.local_addr().unwrap();
        let chat = |body: &str| {
            assert_eq!(post_h(a, "/webhooks/gh", &[], body).0, 202);
            w.poll(&Cancel::new()).unwrap().remove(0).chat
        };
        let c = chat(r#"{"number": 7, "repository": {"full_name": "o/r"}}"#);
        assert_eq!(w.send(&Outbound::text(&c, "LGTM")).unwrap().ids, ["991"]);
        let r = &srv.requests()[0];
        assert_eq!((r.header("authorization"), r.header("x-github-api-version")), (Some("Bearer ghtok"), Some("2022-11-28")));
        assert_eq!(r.json(), json!({"body": "LGTM"}));
        assert_eq!(w.send(&Outbound::text(&chat(r#"{"number": 8, "repository": {"full_name": "o/r"}}"#), "x")).unwrap_err().kind, K::NotFound);
        assert!(w.send(&Outbound::text(&chat(r#"{"number": 7, "repository": {"full_name": "o/r --x"}}"#), "x")).unwrap_err().message.contains("repo"));
        assert!(w.send(&Outbound::text(&chat(r#"{"number": -1, "repository": {"full_name": "o/r"}}"#), "x")).unwrap_err().message.contains("pr_number"));
        assert_eq!(srv.requests().len(), 2, "invalid targets never reach GitHub");
        assert!(repo_ok("a.b/c_d-1") && !repo_ok("a/b/c") && !repo_ok("/b") && !repo_ok("a b/c"));
    }

    #[test]
    fn cron_job_routes_fire_the_schedule_with_context() {
        let w = with_opts(vec![("cr", json!({"prompt": "build {status}", "cron_job": "job1"}))], |_| {});
        let a = w.local_addr().unwrap();
        assert_eq!(post_h(a, "/webhooks/cr", &[], r#"{"status":"red"}"#).0, 503, "needs the daemon");
        let fired: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
        let f = fired.clone();
        wire_peer(&w, &Arc::new(Peer::default()), Some(Arc::new(move |j: &str, c: &str| {
            f.lock().unwrap().push((j.into(), c.into()));
            if j == "job1" { Ok(()) } else { Err("no".into()) }
        })));
        let (st, b) = post_h(a, "/webhooks/cr", &[("X-Request-ID", "d1")], r#"{"status":"red"}"#);
        assert_eq!((st, b["status"].as_str(), b["cron_job"].as_str()), (202, Some("accepted"), Some("job1")));
        assert_eq!(post_h(a, "/webhooks/cr", &[("X-Request-ID", "d1")], r#"{"status":"red"}"#).1["status"], "duplicate");
        let f = fired.lock().unwrap();
        assert_eq!(f.len(), 1);
        assert!(f[0].1.contains("route 'cr'") && f[0].1.ends_with("build red"), "{}", f[0].1);
        assert!(w.poll(&Cancel::new()).unwrap().is_empty(), "no webhook session");
    }

    #[test]
    fn scripts_transform_or_drop_payloads() {
        let dir = crate::testutil::temp_dir("whs");
        let put = |n: &str, body: &str| std::fs::write(dir.join(n), body).unwrap();
        put("t.sh", "read -r x; echo \"{\\\"title\\\": \\\"T\\\", \\\"env\\\": \\\"${SECRET_X:-none}\\\"}\"\n");
        put("text.sh", "cat >/dev/null; echo plain words\n");
        put("fail.sh", "echo nope >&2; exit 3\n");
        put("silent.sh", "echo '[SILENT]'\n");
        put("ignore.sh", "echo '{\"__hermes_ignore__\": true}'\n");
        put("list.sh", "echo '[1]'\n");
        put("slow.sh", "sleep 5\n");
        std::env::set_var("SECRET_X", "leak");
        let outside = crate::testutil::temp_dir("whs-out").join("o.sh");
        std::fs::write(&outside, "echo '{}'").unwrap();
        let mut routes = vec![];
        for n in ["t", "text", "fail", "silent", "ignore", "list", "slow", "missing"] {
            routes.push((n, json!({"prompt": "{title}|{env}|{script_output}|{n}", "script": format!("{n}.sh")})));
        }
        routes.push(("out", json!({"script": outside.display().to_string()})));
        routes.push(("dotdot", json!({"script": "../whs-out/o.sh"})));
        let w = with_opts(routes, |r| {
            r.scripts_dir = Some(dir.clone());
            r.script_timeout = Duration::from_millis(400);
        });
        let a = w.local_addr().unwrap();
        let st = |r: &str| post_h(a, &format!("/webhooks/{r}"), &[], r#"{"n": 1}"#).1["status"].as_str().unwrap_or("").to_string();
        assert_eq!(st("t"), "accepted");
        assert_eq!(st("text"), "accepted");
        for r in ["fail", "silent", "ignore", "list", "slow", "missing", "out", "dotdot"] {
            assert_eq!(st(r), "ignored", "{r}");
        }
        let got = w.poll(&Cancel::new()).unwrap();
        assert_eq!(got.iter().map(|m| m.text.as_str()).collect::<Vec<_>>(), ["T|none|{script_output}|{n}", "{title}|{env}|plain words|1"], "environment is cleared");
    }

    #[test]
    fn mcp_event_routes_answer_control_envelopes() {
        let w = with_opts(vec![("ev", json!({"prompt": "[{event_type}] {data} end", "mcp_event": {"server": "gh", "name": "push"}, "deliver": "tg"}))], |_| {});
        let a = w.local_addr().unwrap();
        let peer = Arc::new(Peer::default());
        wire_peer(&w, &peer, None);
        let p = |b: Value| post_h(a, "/webhooks/ev", &[], &b.to_string());
        assert_eq!(p(json!({"type": "verification", "challenge": "abc"})), (200, json!({"challenge": "abc"})));
        assert_eq!(p(json!({"type": "verification", "challenge": "x".repeat(513)})).0, 400);
        assert_eq!(p(json!({"type": "gap", "cursor": "c9"})).1, json!({"status": "gap"}));
        assert_eq!(w.mcp_cursor("ev").as_deref(), Some("c9"));
        assert_eq!(p(json!({"type": "future"})).1, json!({"status": "ignored", "type": "future"}));
        let ev = json!({"eventId": "e1", "cursor": "c10", "event_type": "push", "data": {"ref": "{n}"}});
        assert_eq!(p(ev.clone()).1["delivery_id"], "mcp-event:e1");
        assert_eq!(p(ev).1["status"], "duplicate", "eventId dedupes without delivery headers");
        assert_eq!(w.mcp_cursor("ev").as_deref(), Some("c10"));
        let got = w.poll(&Cancel::new()).unwrap();
        assert_eq!(got[0].text, "[push] {\n  \"ref\": \"{n}\"\n} end", "payload text is never a placeholder");
        assert_eq!(p(json!({"type": "terminated", "error": {"code": 403, "message": "revoked"}})).1, json!({"status": "terminated"}));
        assert_eq!(peer.0.lock().unwrap()[0].text, "MCP server 'gh' ended the subscription to 'push': revoked (code 403). Subscribe again to keep receiving these events.");
        assert_eq!(p(json!({"eventId": "e2"})).0, 404, "route gone after terminated");
        assert!(render_mcp_prompt("{data}", &json!({"data": "x".repeat(MCP_DATA_CHARS + 10)}), "", "").contains("[truncated: the first 32000 of"));
    }

    #[cfg(unix)]
    #[test]
    fn dynamic_subscriptions_hot_reload() {
        let dir = crate::testutil::temp_dir("whsub");
        let subs = subscriptions_path(&dir, "wh");
        let w = with_opts(vec![("fixed", json!({"prompt": "static"}))], |r| r.subscriptions = Some(subs.clone()));
        let a = w.local_addr().unwrap();
        assert_eq!(post_h(a, "/webhooks/dyn", &[], "{}").0, 404);
        let stored = subscribe(&subs, "dyn", json!({"prompt": "dyn {x}", "events": ["e"]})).unwrap();
        let secret = stored["secret"].as_str().unwrap().to_string();
        assert!(secret.len() >= 40 && stored["created_at"].as_str().unwrap().ends_with('Z'));
        {
            #[cfg(unix)]
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&subs).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let body = r#"{"type":"e","x":1}"#;
        let sig = format!("sha256={}", hexmac(&secret, body));
        assert_eq!(post_h(a, "/webhooks/dyn", &[("X-Hub-Signature-256", &sig)], body).0, 202);
        assert_eq!(post_h(a, "/webhooks/dyn", &[], body).0, 401, "generated secret enforced");
        assert_eq!(subscribe(&subs, "dyn", json!({"prompt": "v2 {x}", "events": ["e"]})).unwrap()["secret"], secret.as_str(), "re-subscribe keeps the secret");
        subscribe(&subs, "fixed", json!({"prompt": "shadow"})).unwrap();
        assert!(subscribe(&subs, "bad name", json!({})).is_err());
        assert!(subscribe(&subs, "x", json!({"bogus": 1})).is_err());
        assert_eq!(post_h(a, "/webhooks/dyn", &[("X-Hub-Signature-256", &sig)], body).0, 202);
        assert_eq!(post_h(a, "/webhooks/fixed", &[], "{}").0, 202);
        let got = w.poll(&Cancel::new()).unwrap();
        assert_eq!(got.iter().map(|m| m.text.as_str()).collect::<Vec<_>>(), ["dyn 1", "v2 1", "static"], "static routes win");
        assert_eq!(list_subscriptions(&subs).unwrap().len(), 2);
        std::fs::write(&subs, "{broken").unwrap();
        assert_eq!(post_h(a, "/webhooks/dyn", &[("X-Hub-Signature-256", &sig)], body).0, 202, "malformed file keeps the last good snapshot");
        std::fs::remove_file(&subs).unwrap();
        assert_eq!(post_h(a, "/webhooks/dyn", &[("X-Hub-Signature-256", &sig)], body).0, 404);
        subscribe(&subs, "dyn", json!({})).unwrap();
        assert!(unsubscribe(&subs, "dyn").unwrap() && !unsubscribe(&subs, "dyn").unwrap());
        assert_eq!(post_h(a, "/webhooks/dyn", &[], body).0, 404);
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert!(is_silence("[SILENT]") && is_silence("no\n[SILENT]") && !is_silence("say [SILENT] maybe"));
    }

    fn temp_file(name: &str, body: &str) -> String {
        let p = crate::testutil::temp_dir("wh").join(name);
        std::fs::write(&p, body).unwrap();
        p.display().to_string()
    }
}

