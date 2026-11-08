//! Raft external-agent channel (ported from OpenClaw `extensions/raft` and Hermes
//! `plugins/platforms/raft`, both MIT).
//!
//! Raft never hands message bodies to the host. We listen on a loopback wake
//! endpoint, spawn `raft --profile P agent bridge --wake-adapter wake-channel
//! --wake-channel-endpoint http://127.0.0.1:<port>/wake` with `RAFT_CHANNEL_TOKEN`
//! (generated per start unless `bridge_token` is set) and `RAFT_PROFILE`, and turn
//! each content-free wake hint into an inbound prompt telling the agent to read
//! and answer through the Raft CLI. `send` is therefore a no-op (the agent
//! replies with `raft --profile P message send`).
//!
//! Endpoints (bridge token in `x-raft-bridge-token`, or `Authorization: Bearer`,
//! compared in constant time):
//! - `GET /health` (no auth) → status, runtime session, activity queue size.
//! - `POST /wake` → 202; 400 for invalid JSON / non-object / any message-content
//!   key (`body`, `text`, `message`…), 413 over `max_body_bytes`, 503 when stopping.
//! - `POST /activity` → validated `raft-activity.v1` telemetry into a bounded queue.
//! - `GET /activity/drain?max=N` → `raft-activity-drain.v1` batch (at-most-once).
//!
//! The bridge runs in its own process group, dies with us (`PR_SET_PDEATHSIG` on
//! Linux), is restarted with backoff when it exits (`restart = true`), and is
//! terminated (TERM, then KILL after 5 s) by `stop`.

use crate::{Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, Outbound, Sent};
use seagent_core::Cancel;
use seagent_net::httpd::{Opts, Request, Response, Server};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const TOKEN_HEADER: &str = "x-raft-bridge-token";
const ACTIVITY_SCHEMA: &str = "raft-activity.v1";
const DRAIN_SCHEMA: &str = "raft-activity-drain.v1";
const ACTIVITY_CAP: usize = 500;
const ACTIVITY_CONTENT_CAP: usize = 4096;
const WAKE_ID_KEYS: [&str; 6] = ["eventId", "attemptId", "messageId", "delivery_id", "wake_id", "id"];
const CONTENT_KEYS: [&str; 7] = ["body", "content", "message", "messages", "preview", "snippet", "text"];
const ACTIVITY_FIELDS: [&str; 14] = ["schema", "eventId", "sessionId", "hookEventName", "status", "occurredAt", "toolName", "toolInput", "toolOutput", "toolInputTruncated", "toolOutputTruncated", "truncated", "errorClass", "durationMs"];

fn has_content(v: &Value) -> bool {
    match v {
        Value::Object(m) => m.iter().any(|(k, c)| CONTENT_KEYS.contains(&k.trim().to_ascii_lowercase().as_str()) || has_content(c)),
        Value::Array(a) => a.iter().any(has_content),
        _ => false,
    }
}

fn safe_scalar(v: &Value) -> bool {
    v.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 120 && s.chars().all(|c| c.is_ascii_alphanumeric() || "._:@/ -".contains(c)))
}

/// Hermes' activity-event validation; returns the (possibly truncated) event.
fn validate_activity(v: &Value) -> Result<Value, String> {
    let m = v.as_object().ok_or("activity event must be an object")?;
    if m.get("schema").and_then(Value::as_str) != Some(ACTIVITY_SCHEMA) {
        return Err("unsupported activity event schema".into());
    }
    if let Some(k) = m.keys().filter(|k| !ACTIVITY_FIELDS.contains(&k.as_str())).min() {
        return Err(format!("activity event field {k} is not allowed"));
    }
    for k in ["eventId", "sessionId", "hookEventName", "occurredAt"] {
        if !safe_scalar(&m[k]) {
            return Err(format!("activity event {k} must be a safe non-empty string"));
        }
    }
    if !matches!(m["status"].as_str(), Some("ok") | Some("error")) {
        return Err("activity event status must be ok|error".into());
    }
    let present = |k: &str| m.get(k).is_some_and(|x| !x.is_null());
    for k in ["toolName", "errorClass"] {
        if present(k) && !safe_scalar(&m[k]) {
            return Err(format!("activity event {k} must be a safe string"));
        }
    }
    if present("durationMs") && !m["durationMs"].as_f64().is_some_and(|d| d >= 0.0) {
        return Err("activity event durationMs must be a non-negative number".into());
    }
    for k in ["truncated", "toolInputTruncated", "toolOutputTruncated"] {
        if present(k) && !m[k].is_boolean() {
            return Err(format!("activity event {k} must be a boolean"));
        }
    }
    let mut out = m.clone();
    if let Some(d) = m.get("durationMs").and_then(Value::as_f64) {
        out.insert("durationMs".into(), json!(d as u64));
    }
    for k in ["toolInput", "toolOutput"] {
        match m.get(k) {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) if s.chars().count() > ACTIVITY_CONTENT_CAP => {
                out.insert(k.into(), json!(s.chars().take(ACTIVITY_CONTENT_CAP).collect::<String>()));
                out.insert("truncated".into(), json!(true));
                out.insert(format!("{k}Truncated"), json!(true));
            }
            Some(Value::String(_)) => {}
            _ => return Err(format!("activity event {k} must be a string")),
        }
    }
    Ok(Value::Object(out))
}

#[derive(Default)]
struct Activity {
    events: VecDeque<Value>,
    dropped: u64,
}

struct Shared {
    stopping: AtomicBool,
    activity: Mutex<Activity>,
    /// Set when the bridge died and will not be restarted.
    bridge_error: Mutex<Option<String>>,
    child_pid: AtomicI32,
    spawns: AtomicI32,
}

impl Shared {
    fn push_activity(&self, v: &Value) -> Result<(), String> {
        let ev = validate_activity(v)?;
        let mut a = self.activity.lock().unwrap();
        a.events.push_back(ev);
        while a.events.len() > ACTIVITY_CAP {
            a.events.pop_front();
            a.dropped += 1;
        }
        Ok(())
    }
}

pub struct Raft {
    id: String,
    endpoint: String,
    rx: Mutex<mpsc::Receiver<Inbound>>,
    shared: Arc<Shared>,
    server: Mutex<Option<Server>>,
    supervisor: Mutex<Option<std::thread::JoinHandle<()>>>,
    poll_timeout: Duration,
}

/// What to spawn; `None` = wake-only (an externally run bridge).
pub struct BridgeCmd {
    pub binary: PathBuf,
    pub restart: bool,
    /// First restart delay; doubles up to 60 s, resets after a minute of uptime.
    pub restart_base: Duration,
}

fn wake_text(profile: &str) -> String {
    let cmd = format!("raft --profile {}", shell_quote(profile));
    format!(
        "Raft wake hint received. New Raft messages may be pending. Check Raft for pending messages, then reply through the Raft CLI.\n\n\
         Use `{cmd} message check` to read pending messages and `{cmd} message send` to respond. \
         If you have not read the Raft manual in this session, run `{cmd} manual get raft-cli-overview` first. \
         Always pass `--profile {}` to every raft CLI call.",
        shell_quote(profile)
    )
}

fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./:@".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

fn err(status: u16, e: &str) -> Response {
    Response::new(status, "application/json", json!({"ok": false, "error": e}).to_string()).with_header("cache-control", "no-store")
}

fn jresp(status: u16, v: Value) -> Response {
    Response::new(status, "application/json", v.to_string()).with_header("cache-control", "no-store")
}

#[allow(clippy::too_many_arguments)]
fn handle(r: Request, token: &str, wake_path: &str, session: &str, profile: &str, channel: &str, max_body: usize, shared: &Shared, tx: &Mutex<mpsc::Sender<Inbound>>) -> Response {
    let authed = || r.header(TOKEN_HEADER).or_else(|| r.bearer()).is_some_and(|t| !token.is_empty() && seagent_net::crypto::ct_eq(t.as_bytes(), token.as_bytes()));
    match (r.method.as_str(), r.path.as_str()) {
        ("GET", "/health") => {
            let q = shared.activity.lock().unwrap().events.len();
            jresp(200, json!({"ok": true, "status": "ok", "platform": "raft", "runtimeSession": session, "activity": {"queueSize": q, "endpoint": "/activity", "drainEndpoint": "/activity/drain"}}))
        }
        ("GET", "/activity/drain") => {
            if !authed() {
                return err(401, "unauthorized");
            }
            let max = r.query("max").and_then(|m| m.parse::<usize>().ok()).filter(|&m| m > 0).unwrap_or(200);
            let mut a = shared.activity.lock().unwrap();
            let n = max.min(a.events.len());
            let events: Vec<Value> = a.events.drain(..n).collect();
            let dropped = std::mem::take(&mut a.dropped);
            jresp(200, json!({"schema": DRAIN_SCHEMA, "events": events, "dropped": dropped}))
        }
        ("POST", "/activity") => {
            if !authed() {
                return err(401, "unauthorized");
            }
            if r.body.len() > max_body {
                return err(413, "payload_too_large");
            }
            let Ok(v) = serde_json::from_slice::<Value>(&r.body) else { return err(400, "invalid_json") };
            match shared.push_activity(&v) {
                Ok(()) => jresp(202, json!({"ok": true})),
                Err(e) => err(400, &e),
            }
        }
        ("POST", p) if p == wake_path => {
            if !authed() {
                return err(401, "unauthorized");
            }
            if r.body.len() > max_body {
                return err(413, "payload_too_large");
            }
            let payload: Value = if r.body.iter().all(u8::is_ascii_whitespace) {
                json!({})
            } else {
                match serde_json::from_slice(&r.body) {
                    Ok(v) => v,
                    Err(_) => return err(400, "invalid_json"),
                }
            };
            if !payload.is_object() {
                return err(400, "invalid_payload");
            }
            // Raft owns message bodies; only content-free hints may enter agent state.
            if has_content(&payload) {
                return err(400, "content_not_allowed");
            }
            if shared.stopping.load(Ordering::SeqCst) {
                return jresp(503, json!({"ok": false, "error": "not_ready", "runtimeSession": session}));
            }
            let id = WAKE_ID_KEYS
                .iter()
                .find_map(|k| match &payload[*k] {
                    Value::String(s) if !s.is_empty() => Some(s.clone()),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
                .unwrap_or_else(|| format!("raft-wake-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)));
            let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
            let msg = Inbound {
                channel: channel.to_string(),
                chat: profile.to_string(),
                chat_type: ChatType::Direct,
                chat_name: format!("Raft {profile}"),
                sender: "raft-bridge".into(),
                sender_name: "Raft Bridge".into(),
                text: wake_text(profile),
                message_id: id,
                ts,
                ..Default::default()
            };
            if tx.lock().unwrap().send(msg).is_err() {
                return jresp(503, json!({"ok": false, "error": "not_ready", "runtimeSession": session}));
            }
            jresp(202, json!({"ok": true, "accepted": true, "runtimeSession": session}))
        }
        _ => err(404, "not_found"),
    }
}

fn spawn_bridge(cmd: &BridgeCmd, profile: &str, endpoint: &str, token: &str) -> std::io::Result<Child> {
    let mut c = Command::new(&cmd.binary);
    c.args(["--profile", profile, "agent", "bridge", "--wake-adapter", "wake-channel", "--wake-channel-endpoint", endpoint])
        .env("RAFT_PROFILE", profile)
        .env("RAFT_CHANNEL_TOKEN", token)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut c, 0);
    #[cfg(target_os = "linux")]
    // SAFETY: prctl is async-signal-safe and touches no Rust state in the forked child.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut c, || {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    // Windows: a kill-on-close Job Object stands in for the group and PDEATHSIG.
    #[cfg(not(unix))]
    return seagent_core::platform::proc::spawn_in_group(&mut c, false);
    #[cfg(unix)]
    c.spawn()
}

fn kill_group(child: &mut Child) {
    let pid = child.id() as i32;
    #[cfg(unix)]
    unsafe {
        libc::kill(-pid, libc::SIGTERM);
    }
    // CTRL_BREAK, then the whole job after the same 5 s.
    #[cfg(not(unix))]
    seagent_core::platform::proc::kill_group(pid, Duration::from_secs(5));
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        if matches!(child.try_wait(), Ok(Some(_))) {
            #[cfg(unix)]
            unsafe {
                // Stragglers the leader left in its group.
                libc::kill(-pid, libc::SIGKILL);
            }
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    #[cfg(unix)]
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Owns the child: spawns, restarts, and kills it on stop. All spawns happen on this
/// thread so the Linux parent-death signal stays tied to a live thread.
fn supervise(cmd: BridgeCmd, profile: String, endpoint: String, token: String, shared: Arc<Shared>) {
    let mut delay = cmd.restart_base;
    loop {
        if shared.stopping.load(Ordering::SeqCst) {
            return;
        }
        let started = Instant::now();
        let mut child = match spawn_bridge(&cmd, &profile, &endpoint, &token) {
            Ok(c) => c,
            Err(e) => {
                *shared.bridge_error.lock().unwrap() = Some(format!("raft bridge failed to start ({}): {e}", cmd.binary.display()));
                return;
            }
        };
        shared.spawns.fetch_add(1, Ordering::SeqCst);
        shared.child_pid.store(child.id() as i32, Ordering::SeqCst);
        let status = loop {
            if shared.stopping.load(Ordering::SeqCst) {
                kill_group(&mut child);
                shared.child_pid.store(0, Ordering::SeqCst);
                return;
            }
            match child.try_wait() {
                Ok(Some(s)) => break s.to_string(),
                Ok(None) => std::thread::sleep(Duration::from_millis(25)),
                Err(e) => break e.to_string(),
            }
        };
        shared.child_pid.store(0, Ordering::SeqCst);
        #[cfg(unix)]
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        if !cmd.restart {
            *shared.bridge_error.lock().unwrap() = Some(format!("raft bridge exited unexpectedly ({status})"));
            return;
        }
        if started.elapsed() > Duration::from_secs(60) {
            delay = cmd.restart_base;
        }
        let until = Instant::now() + delay;
        while Instant::now() < until {
            if shared.stopping.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        delay = (delay * 2).min(Duration::from_secs(60));
    }
}

impl Raft {
    /// `listen` = `host:port` (port 0 = any). Starts the wake server, then the bridge.
    #[allow(clippy::too_many_arguments)]
    pub fn start(id: &str, profile: &str, listen: &str, path: &str, token: Option<&str>, runtime_session: &str, max_body: usize, bridge: Option<BridgeCmd>, poll_timeout_secs: u64) -> Result<Raft, String> {
        let profile = profile.trim().to_string();
        if profile.is_empty() {
            return Err(format!("channel {id}: raft needs `profile` (the Raft CLI profile slug)"));
        }
        let token = token.map(str::trim).filter(|t| !t.is_empty()).map(str::to_string).unwrap_or_else(|| seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(32)));
        let path = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
        let shared = Arc::new(Shared { stopping: AtomicBool::new(false), activity: Mutex::new(Activity::default()), bridge_error: Mutex::new(None), child_pid: AtomicI32::new(0), spawns: AtomicI32::new(0) });
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        let (t2, p2, s2, pr2, ch2, sh2) = (token.clone(), path.clone(), runtime_session.to_string(), profile.clone(), id.to_string(), shared.clone());
        let handler: seagent_net::httpd::Handler = Arc::new(move |r: Request| handle(r, &t2, &p2, &s2, &pr2, &ch2, max_body, &sh2, &tx));
        let opts = Opts { max_body: max_body + 1024, ..Opts::default() };
        let server = Server::bind(listen, opts, handler).map_err(|e| format!("channel {id}: cannot listen on {listen}: {e}"))?;
        let addr = server.local_addr();
        let endpoint = format!("http://{}:{}{path}", if addr.ip().is_unspecified() { "127.0.0.1".to_string() } else { addr.ip().to_string() }, addr.port());
        let supervisor = match bridge {
            Some(cmd) => {
                let (pr, ep, tk, sh) = (profile.clone(), endpoint.clone(), token.clone(), shared.clone());
                Some(std::thread::Builder::new().name(format!("raft bridge {id}")).spawn(move || supervise(cmd, pr, ep, tk, sh)).map_err(|e| format!("channel {id}: {e}"))?)
            }
            None => None,
        };
        Ok(Raft { id: id.to_string(), endpoint, rx: Mutex::new(rx), shared, server: Mutex::new(Some(server)), supervisor: Mutex::new(supervisor), poll_timeout: Duration::from_secs(poll_timeout_secs.max(1)) })
    }

    /// The wake URL handed to the bridge.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Host-side agent activity (tool calls, turn ends) for Raft's activity drain.
    pub fn report_activity(&self, event: &Value) -> Result<(), String> {
        self.shared.push_activity(event)
    }
}

impl Channel for Raft {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps { chat_types: vec![ChatType::Direct], max_len: 100_000, ..Caps::default() }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let rx = self.rx.lock().unwrap();
        let until = Instant::now() + self.poll_timeout;
        loop {
            let got: Vec<Inbound> = rx.try_iter().collect();
            if !got.is_empty() {
                return Ok(got);
            }
            if let Some(e) = self.shared.bridge_error.lock().unwrap().clone() {
                return Err(ChannelError::new(K::Fatal, e));
            }
            if cancel.is_cancelled() || Instant::now() >= until {
                return Ok(vec![]);
            }
            if let Ok(m) = rx.recv_timeout(Duration::from_millis(50)) {
                let mut v = vec![m];
                v.extend(rx.try_iter());
                return Ok(v);
            }
        }
    }

    /// The agent replies through the Raft CLI; nothing goes out from here.
    fn send(&self, _out: &Outbound) -> Result<Sent, ChannelError> {
        Ok(Sent::default())
    }

    fn stop(&self) {
        self.shared.stopping.store(true, Ordering::SeqCst);
        if let Some(h) = self.supervisor.lock().unwrap().take() {
            let _ = h.join();
        }
        self.server.lock().unwrap().take();
    }
}

impl Drop for Raft {
    fn drop(&mut self) {
        self.stop();
    }
}

fn d_listen() -> String {
    "127.0.0.1:0".into()
}
fn d_path() -> String {
    "/wake".into()
}
fn d_session() -> String {
    "default".into()
}
fn d_max_body() -> usize {
    16_384
}
fn d_true() -> bool {
    true
}
fn d_poll() -> u64 {
    25
}
fn d_binary() -> String {
    "raft".into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    /// Raft CLI profile slug (`raft agent login … --profile-slug`); falls back to $RAFT_PROFILE.
    #[serde(default)]
    profile: Option<String>,
    #[serde(default = "d_binary")]
    binary: String,
    #[serde(default = "d_listen")]
    listen: String,
    #[serde(default = "d_path")]
    path: String,
    /// Fixed bridge token (generated per start when unset).
    #[serde(default)]
    bridge_token: Option<String>,
    #[serde(default = "d_session")]
    runtime_session: String,
    #[serde(default = "d_max_body")]
    max_body_bytes: usize,
    /// Spawn `raft agent bridge` (false = an external bridge posts to `listen`).
    #[serde(default = "d_true")]
    spawn: bool,
    #[serde(default = "d_true")]
    restart: bool,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
}

fn which(bin: &str) -> Option<PathBuf> {
    if bin.contains('/') {
        let p = PathBuf::from(bin);
        return p.is_file().then_some(p);
    }
    std::env::var_os("PATH").and_then(|paths| std::env::split_paths(&paths).map(|d| d.join(bin)).find(|p| p.is_file()))
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let profile = st.profile.or_else(|| std::env::var("RAFT_PROFILE").ok()).unwrap_or_default();
    let token = ctx.opt_secret("bridge_token", &st.bridge_token)?;
    let host = st.listen.rsplit_once(':').map(|(h, _)| h.trim_matches(['[', ']'])).unwrap_or("");
    if !matches!(host, "127.0.0.1" | "localhost" | "::1") {
        return Err(format!("channel {}: raft listen must be a loopback address (got {})", ctx.name, st.listen));
    }
    let bridge = if st.spawn {
        let binary = which(&st.binary).ok_or_else(|| format!("channel {}: Raft CLI `{}` not found on PATH (install from https://raft.build, or set spawn = false)", ctx.name, st.binary))?;
        Some(BridgeCmd { binary, restart: st.restart, restart_base: Duration::from_secs(1) })
    } else {
        None
    };
    Ok(Arc::new(Raft::start(ctx.name, &profile, &st.listen, &st.path, token.as_deref(), &st.runtime_session, st.max_body_bytes, bridge, st.poll_timeout_secs)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;

    fn post(url: &str, token: Option<&str>, body: &str) -> (u16, Value) {
        let a = crate::http::agent(Duration::from_secs(5));
        let mut r = a.post(url);
        if let Some(t) = token {
            r = r.header(TOKEN_HEADER, t);
        }
        match r.send(body.as_bytes()) {
            Ok(mut r) => (r.status().as_u16(), serde_json::from_str(&r.body_mut().read_to_string().unwrap_or_default()).unwrap_or_default()),
            Err(_) => (0, Value::Null),
        }
    }

    fn get(url: &str, auth: Option<(&str, &str)>) -> (u16, Value) {
        let a = crate::http::agent(Duration::from_secs(5));
        let mut r = a.get(url);
        if let Some((k, v)) = auth {
            r = r.header(k, v);
        }
        let mut r = r.call().unwrap();
        (r.status().as_u16(), serde_json::from_str(&r.body_mut().read_to_string().unwrap_or_default()).unwrap_or_default())
    }

    fn wake_only(token: &str) -> Raft {
        Raft::start("raft", "my-agent", "127.0.0.1:0", "/wake", Some(token), "default", 16_384, None, 1).unwrap()
    }

    #[test]
    fn wake_endpoint_checks_token_content_and_size() {
        let r = wake_only("tok-123");
        let url = r.endpoint().to_string();
        assert!(url.starts_with("http://127.0.0.1:") && url.ends_with("/wake"));
        assert_eq!(post(&url, None, r#"{"eventId":"e1"}"#).0, 401, "missing token");
        assert_eq!(post(&url, Some("wrong"), r#"{"eventId":"e1"}"#).0, 401, "bad token");
        assert_eq!(post(&url, Some("tok-123"), "{nope").0, 400);
        assert_eq!(post(&url, Some("tok-123"), "[1]").0, 400);
        let (s, v) = post(&url, Some("tok-123"), r#"{"eventId":"e2","meta":{"Preview":"secret words"}}"#);
        assert_eq!((s, v["error"].as_str()), (400, Some("content_not_allowed")), "nested content keys rejected");
        assert_eq!(post(&url, Some("tok-123"), &format!(r#"{{"eventId":"{}"}}"#, "x".repeat(20_000))).0, 413);
        let (s, v) = post(&url, Some("tok-123"), r#"{"eventId":"e3","schema":"raft-wake.v1"}"#);
        assert_eq!((s, v["runtimeSession"].as_str()), (202, Some("default")));
        // Bearer works too.
        let a = crate::http::agent(Duration::from_secs(5));
        let st = a.post(&url).header("authorization", "Bearer tok-123").send(br#"{"delivery_id": 77}"#.as_slice()).unwrap().status().as_u16();
        assert_eq!(st, 202);
        let got = r.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].chat.as_str(), got[0].sender.as_str(), got[0].message_id.as_str(), got[0].chat_type), ("my-agent", "raft-bridge", "e3", ChatType::Direct));
        assert!(got[0].text.contains("raft --profile my-agent message check") && !got[0].text.contains("secret"));
        assert_eq!(got[1].message_id, "77");
        assert_eq!(r.send(&Outbound::text("my-agent", "hi")).unwrap(), Sent::default(), "replies go through the CLI");
        let health = url.replace("/wake", "/health");
        let (s, v) = get(&health, None);
        assert_eq!((s, v["platform"].as_str()), (200, Some("raft")));
        assert_eq!(get(&url.replace("/wake", "/nope"), None).0, 404);
        r.stop();
        assert_eq!(post(&url, Some("tok-123"), r#"{"eventId":"e4"}"#).0, 0, "listener closed after stop");
    }

    #[test]
    fn activity_queue_validates_bounds_and_drains() {
        let r = wake_only("t0k");
        let base = r.endpoint().trim_end_matches("/wake").to_string();
        let ev = |i: usize| json!({"schema": ACTIVITY_SCHEMA, "eventId": format!("e{i}"), "sessionId": "s1", "hookEventName": "PreToolUse", "status": "ok", "occurredAt": "2026-01-01T00:00:00Z", "toolName": "shell", "toolInput": "x".repeat(5000)});
        assert_eq!(post(&format!("{base}/activity"), Some("t0k"), &ev(0).to_string()).0, 202);
        assert_eq!(post(&format!("{base}/activity"), None, &ev(1).to_string()).0, 401);
        let mut bad = ev(2);
        bad["extra"] = json!(1);
        assert_eq!(post(&format!("{base}/activity"), Some("t0k"), &bad.to_string()).0, 400);
        bad = ev(3);
        bad["status"] = json!("maybe");
        assert_eq!(post(&format!("{base}/activity"), Some("t0k"), &bad.to_string()).0, 400);
        for i in 0..ACTIVITY_CAP + 5 {
            r.report_activity(&ev(i + 10)).unwrap();
        }
        assert_eq!(get(&format!("{base}/activity/drain"), None).0, 401);
        let (s, v) = get(&format!("{base}/activity/drain?max=3"), Some((TOKEN_HEADER, "t0k")));
        assert_eq!((s, v["schema"].as_str(), v["events"].as_array().unwrap().len(), v["dropped"].as_u64()), (200, Some(DRAIN_SCHEMA), 3, Some(6)));
        assert_eq!(v["events"][0]["eventId"], "e15", "oldest dropped first");
        assert_eq!(v["events"][0]["toolInput"].as_str().unwrap().len(), ACTIVITY_CONTENT_CAP);
        assert_eq!(v["events"][0]["toolInputTruncated"], true);
        let (_, v) = get(&format!("{base}/activity/drain"), Some(("authorization", "Bearer t0k")));
        assert_eq!((v["events"].as_array().unwrap().len(), v["dropped"].as_u64()), (200, Some(0)), "default batch of 200");
        let (_, v) = get(&format!("{base}/activity/drain?max=1000"), Some((TOKEN_HEADER, "t0k")));
        assert_eq!(v["events"].as_array().unwrap().len(), ACTIVITY_CAP - 203);
    }

    fn stub(dir: &std::path::Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("raft");
        std::fs::write(&p, format!("#!/bin/sh\nD={}\n{body}\n", dir.display())).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn wait_for(f: impl Fn() -> bool) -> bool {
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(10) {
            if f() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    #[test]
    fn spawns_bridge_with_token_restarts_and_stop_kills_it() {
        let dir = temp_dir("raft");
        let bin = stub(&dir, r#"n=$(cat "$D/count" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$D/count"
echo "$@" > "$D/args"; echo "$RAFT_CHANNEL_TOKEN" > "$D/token"; echo "$RAFT_PROFILE" > "$D/profile"
[ $n -eq 1 ] && exit 3
exec sleep 30"#);
        let cmd = BridgeCmd { binary: bin, restart: true, restart_base: Duration::from_millis(50) };
        let r = Raft::start("raft", "my-agent", "127.0.0.1:0", "wake", None, "default", 16_384, Some(cmd), 1).unwrap();
        assert!(wait_for(|| r.shared.spawns.load(Ordering::SeqCst) >= 2 && r.shared.child_pid.load(Ordering::SeqCst) > 0), "restarted after exit 3");
        assert!(wait_for(|| std::fs::read_to_string(dir.join("count")).map(|c| c.trim() == "2").unwrap_or(false)));
        let args = std::fs::read_to_string(dir.join("args")).unwrap();
        assert_eq!(args.trim(), format!("--profile my-agent agent bridge --wake-adapter wake-channel --wake-channel-endpoint {}", r.endpoint()));
        assert_eq!(std::fs::read_to_string(dir.join("profile")).unwrap().trim(), "my-agent");
        let token = std::fs::read_to_string(dir.join("token")).unwrap().trim().to_string();
        assert_eq!(token.len(), 64, "generated token");
        assert_eq!(post(r.endpoint(), Some(&token), r#"{"eventId":"w1"}"#).0, 202, "bridge's token accepted");
        assert_eq!(r.poll(&Cancel::new()).unwrap()[0].message_id, "w1");
        let pid = r.shared.child_pid.load(Ordering::SeqCst);
        let t0 = Instant::now();
        r.stop();
        assert!(t0.elapsed() < Duration::from_secs(3), "TERM is enough for sleep");
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "bridge process gone");
    }

    #[test]
    fn bridge_exit_without_restart_surfaces_fatal() {
        let dir = temp_dir("raft");
        let bin = stub(&dir, "exit 1");
        let r = Raft::start("raft", "p", "127.0.0.1:0", "/wake", Some("t"), "default", 16_384, Some(BridgeCmd { binary: bin, restart: false, restart_base: Duration::from_millis(10) }), 5).unwrap();
        let t0 = Instant::now();
        let e = r.poll(&Cancel::new()).unwrap_err();
        assert_eq!(e.kind, K::Fatal);
        assert!(e.message.contains("exited") && t0.elapsed() < Duration::from_secs(3), "{}", e.message);
        let r = Raft::start("raft", "p", "127.0.0.1:0", "/wake", Some("t"), "default", 16_384, Some(BridgeCmd { binary: dir.join("missing"), restart: true, restart_base: Duration::from_millis(10) }), 5).unwrap();
        assert!(r.poll(&Cancel::new()).unwrap_err().message.contains("failed to start"));
    }

    #[test]
    fn cancel_returns_promptly_and_build_validates() {
        let r = Raft::start("raft", "p", "127.0.0.1:0", "/wake", Some("t"), "default", 16_384, None, 30).unwrap();
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.cancel();
        });
        let t0 = Instant::now();
        assert!(r.poll(&c).unwrap().is_empty());
        assert!(t0.elapsed() < Duration::from_millis(500));
        let d = temp_dir("raft");
        let secrets: crate::config::Secrets = Arc::new(|s: &str| s.to_string());
        let ctx = crate::config::Ctx { name: "rf", state_dir: &d, secrets: &secrets };
        let ok = json!({"profile": "p", "spawn": false});
        assert!(build(&ctx, ok.as_object().unwrap()).is_ok());
        for bad in [json!({"profile": "p", "spawn": false, "listen": "0.0.0.0:0"}), json!({"profile": "p", "binary": "/nonexistent/raft"}), json!({"profile": "p", "spawn": false, "prof": 1})] {
            assert!(build(&ctx, bad.as_object().unwrap()).is_err(), "{bad}");
        }
        assert!(Raft::start("raft", " ", "127.0.0.1:0", "/wake", None, "default", 10, None, 1).is_err(), "profile required");
    }
}
