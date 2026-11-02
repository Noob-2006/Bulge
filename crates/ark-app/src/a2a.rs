//! Agent2Agent protocol 1.0 (JSON-RPC binding), server and client — parity with
//! OpenClaw `extensions/a2a` and Hermes `plugins/platforms/a2a` (both MIT).
//!
//! Server: agent card at `/.well-known/agent-card.json` (and legacy `agent.json`),
//! JSON-RPC at `POST /a2a/v1`: SendMessage, SendStreamingMessage (SSE), GetTask,
//! ListTasks, CancelTask, SubscribeToTask and push-notification config CRUD, each
//! also under its v0.3 name (`message/send`, `tasks/get`, …). A task's contextId maps
//! to one ark session. Peers authenticate with per-peer bearer tokens; push
//! notifications are signed (HMAC-SHA256). Client: `a2a_*` tools in [`tools`]:
//! list, discover, call, task, history (client-side transcripts per contextId that
//! survive restarts and compaction) and orchestrate (fan a task out to several
//! peers by name or capability; all / first / best, per-peer timeout — Hermes
//! `plugins/platforms/a2a/tools.py` semantics).

use crate::App;
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use ark_kernel::kernel::RunOpts;
use ark_net::httpd::{Request, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct A2aConfig {
    pub enabled: bool,
    pub name: Option<String>,
    pub description: Option<String>,
    /// Public base URL advertised in the card (default: the request's Host).
    pub public_url: Option<String>,
    /// Peer name → bearer token (secret references allowed). Empty = only the app token.
    pub peers: BTreeMap<String, String>,
    /// Requests per minute per peer.
    pub rate_per_min: Option<u32>,
    /// HMAC secret for push notifications.
    pub push_secret: Option<String>,
    /// Remote agents the `a2a_*` tools may call: name → {url, token}.
    pub agents: BTreeMap<String, RemoteAgent>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteAgent {
    pub url: String,
    #[serde(default)]
    pub token: Option<String>,
    /// What this peer is good at (`a2a_orchestrate` matches on these).
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Task {
    id: String,
    context_id: String,
    session: String,
    state: State,
    updated: u64,
    history: Vec<(String, String)>,
    output: String,
    peer: String,
    #[serde(default)]
    push: Vec<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum State {
    Submitted,
    Working,
    InputRequired,
    Completed,
    Failed,
    Canceled,
    Rejected,
}

impl State {
    fn v1(self) -> &'static str {
        match self {
            State::Submitted => "TASK_STATE_SUBMITTED",
            State::Working => "TASK_STATE_WORKING",
            State::InputRequired => "TASK_STATE_INPUT_REQUIRED",
            State::Completed => "TASK_STATE_COMPLETED",
            State::Failed => "TASK_STATE_FAILED",
            State::Canceled => "TASK_STATE_CANCELED",
            State::Rejected => "TASK_STATE_REJECTED",
        }
    }
    fn v03(self) -> &'static str {
        match self {
            State::Submitted => "submitted",
            State::Working => "working",
            State::InputRequired => "input-required",
            State::Completed => "completed",
            State::Failed => "failed",
            State::Canceled => "canceled",
            State::Rejected => "rejected",
        }
    }
    fn terminal(self) -> bool {
        matches!(self, State::Completed | State::Failed | State::Canceled | State::Rejected)
    }
}

#[derive(Default)]
struct Book {
    tasks: HashMap<String, Task>,
    contexts: HashMap<String, String>,
    rate: HashMap<String, VecDeque<Instant>>,
}

fn book() -> &'static Mutex<Book> {
    static B: OnceLock<Mutex<Book>> = OnceLock::new();
    B.get_or_init(Default::default)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn base_url(app: &App, r: &Request) -> String {
    app.cfg.a2a.public_url.clone().unwrap_or_else(|| format!("http://{}", r.header("host").unwrap_or(&app.cfg.listen)))
}

pub fn card(app: &App, r: &Request) -> Response {
    let c = &app.cfg.a2a;
    let base = base_url(app, r);
    let v = json!({
        "name": c.name.clone().unwrap_or_else(|| "ark".into()),
        "description": c.description.clone().unwrap_or_else(|| "ark agent: tools, files, shell, memory, web, channels".into()),
        "version": env!("CARGO_PKG_VERSION"),
        "protocolVersion": "1.0",
        "url": format!("{base}/a2a/v1"),
        "preferredTransport": "JSONRPC",
        "supportedInterfaces": [{"url": format!("{base}/a2a/v1"), "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
        "capabilities": {"streaming": true, "pushNotifications": true, "stateTransitionHistory": false, "extendedAgentCard": false},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{"id": "general", "name": "General agent", "description": "Plans and executes multi-step tasks with tools", "tags": ["agent", "coding", "automation"]}],
        "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        "security": [{"bearer": []}],
    });
    Response::json(200, &v.to_string())
}

fn rpc_err(id: &Value, code: i64, msg: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}})
}

/// Which peer this bearer token belongs to (the app token counts as "operator").
fn peer_of(app: &App, r: &Request, secrets: &dyn Fn(&str) -> String) -> Option<String> {
    let t = r.bearer()?;
    if ark_net::crypto::ct_eq(t.as_bytes(), app.token.as_bytes()) {
        return Some("operator".into());
    }
    app.cfg.a2a.peers.iter().find(|(_, tok)| ark_net::crypto::ct_eq(secrets(tok).as_bytes(), t.as_bytes())).map(|(n, _)| n.clone())
}

fn task_json(t: &Task, v1: bool) -> Value {
    let msg = |role: &str, text: &str| {
        if v1 {
            json!({"role": if role == "agent" { "ROLE_AGENT" } else { "ROLE_USER" }, "parts": [{"text": text}], "messageId": ark_net::crypto::random_token(8)})
        } else {
            json!({"kind": "message", "role": role, "parts": [{"kind": "text", "text": text}], "messageId": ark_net::crypto::random_token(8)})
        }
    };
    let mut v = json!({
        "id": t.id, "contextId": t.context_id,
        "status": {"state": if v1 { t.state.v1() } else { t.state.v03() }, "timestamp": t.updated},
        "history": t.history.iter().map(|(r, x)| msg(r, x)).collect::<Vec<_>>(),
    });
    if !t.output.is_empty() {
        v["artifacts"] = json!([{"artifactId": format!("{}-out", t.id), "name": "response", "parts": [if v1 { json!({"text": t.output}) } else { json!({"kind": "text", "text": t.output}) }]}]);
        v["status"]["message"] = msg("agent", &t.output);
    }
    if !v1 {
        v["kind"] = json!("task");
    }
    v
}

fn text_parts(m: &Value) -> String {
    m["parts"].as_array().into_iter().flatten().filter_map(|p| p["text"].as_str().or_else(|| p["root"]["text"].as_str())).collect::<Vec<_>>().join("\n")
}

pub fn handle(app: &Arc<App>, r: Request) -> Response {
    if r.method != "POST" {
        return Response::text(405, "POST JSON-RPC to /a2a/v1");
    }
    if let Some(v) = r.header("a2a-version") {
        if !v.starts_with("1.") && v != "0.3" {
            return Response::json(400, &rpc_err(&Value::Null, -32600, &format!("unsupported A2A-Version {v}")).to_string());
        }
    }
    let secrets = &*app.d.k.vault_substitute();
    let Some(peer) = peer_of(app, &r, secrets) else { return Response::json(401, &rpc_err(&Value::Null, -32050, "unauthorized").to_string()) };
    let limit = app.cfg.a2a.rate_per_min.unwrap_or(30) as usize;
    {
        let mut b = book().lock().unwrap();
        let q = b.rate.entry(peer.clone()).or_default();
        while q.front().is_some_and(|t| t.elapsed() > Duration::from_secs(60)) {
            q.pop_front();
        }
        if q.len() >= limit {
            return Response::json(429, &rpc_err(&Value::Null, -32051, "rate limited").to_string());
        }
        q.push_back(Instant::now());
    }
    let req: Value = match serde_json::from_slice(&r.body) {
        Ok(v) => v,
        Err(e) => return Response::json(200, &rpc_err(&Value::Null, -32700, &e.to_string()).to_string()),
    };
    let id = req["id"].clone();
    let method = req["method"].as_str().unwrap_or("");
    let p = &req["params"];
    let v1 = !method.contains('/');
    match method {
        "SendMessage" | "message/send" => Response::json(200, &send_message(app, &peer, &id, p, v1, true).to_string()),
        "SendStreamingMessage" | "message/stream" => {
            let first = send_message(app, &peer, &id, p, v1, false);
            if first.get("error").is_some() {
                return Response::json(200, &first.to_string());
            }
            let task_id = first["result"]["task"]["id"].as_str().or_else(|| first["result"]["id"].as_str()).unwrap_or("").to_string();
            Response::sse(Box::new(move |w| stream_task(w, &id, &task_id, v1)))
        }
        "GetTask" | "tasks/get" => {
            let tid = p["id"].as_str().or_else(|| p["name"].as_str().map(|n| n.trim_start_matches("tasks/"))).unwrap_or("");
            let b = book().lock().unwrap();
            match b.tasks.get(tid).filter(|t| t.peer == peer || peer == "operator") {
                Some(t) => Response::json(200, &json!({"jsonrpc": "2.0", "id": id, "result": task_json(t, v1)}).to_string()),
                None => Response::json(200, &rpc_err(&id, -32001, "task not found").to_string()),
            }
        }
        "ListTasks" | "tasks/list" => {
            let b = book().lock().unwrap();
            let mut ts: Vec<&Task> = b.tasks.values().filter(|t| t.peer == peer || peer == "operator").collect();
            ts.sort_by_key(|t| std::cmp::Reverse(t.updated));
            let list: Vec<Value> = ts.iter().take(100).map(|t| task_json(t, v1)).collect();
            Response::json(200, &json!({"jsonrpc": "2.0", "id": id, "result": {"tasks": list}}).to_string())
        }
        "CancelTask" | "tasks/cancel" => {
            let tid = p["id"].as_str().unwrap_or("").to_string();
            let mut b = book().lock().unwrap();
            match b.tasks.get_mut(&tid).filter(|t| t.peer == peer || peer == "operator") {
                Some(t) if t.state.terminal() => Response::json(200, &rpc_err(&id, -32002, "task is not cancelable").to_string()),
                Some(t) => {
                    app.d.k.interrupt(&t.session);
                    t.state = State::Canceled;
                    t.updated = now_ms();
                    Response::json(200, &json!({"jsonrpc": "2.0", "id": id, "result": task_json(t, v1)}).to_string())
                }
                None => Response::json(200, &rpc_err(&id, -32001, "task not found").to_string()),
            }
        }
        "SubscribeToTask" | "tasks/resubscribe" | "tasks/subscribe" => {
            let tid = p["id"].as_str().unwrap_or("").to_string();
            if !book().lock().unwrap().tasks.contains_key(&tid) {
                return Response::json(200, &rpc_err(&id, -32001, "task not found").to_string());
            }
            Response::sse(Box::new(move |w| stream_task(w, &id, &tid, v1)))
        }
        "CreateTaskPushNotificationConfig" | "tasks/pushNotificationConfig/set" => {
            let tid = p["taskId"].as_str().or_else(|| p["id"].as_str()).unwrap_or("").to_string();
            let cfg = p.get("pushNotificationConfig").or_else(|| p.get("config")).cloned().unwrap_or_default();
            if cfg["url"].as_str().is_none_or(|u| !u.starts_with("https://") && !u.starts_with("http://127.0.0.1") && !u.starts_with("http://localhost")) {
                return Response::json(200, &rpc_err(&id, -32602, "push url must be https (or loopback)").to_string());
            }
            let mut b = book().lock().unwrap();
            match b.tasks.get_mut(&tid) {
                Some(t) => {
                    let mut c = cfg.clone();
                    c["id"] = json!(c["id"].as_str().map(str::to_string).unwrap_or_else(|| ark_net::crypto::random_token(6)));
                    t.push.push(c.clone());
                    Response::json(200, &json!({"jsonrpc": "2.0", "id": id, "result": {"taskId": tid, "pushNotificationConfig": c}}).to_string())
                }
                None => Response::json(200, &rpc_err(&id, -32001, "task not found").to_string()),
            }
        }
        "GetTaskPushNotificationConfig" | "ListTaskPushNotificationConfig" | "tasks/pushNotificationConfig/get" | "tasks/pushNotificationConfig/list" => {
            let tid = p["taskId"].as_str().or_else(|| p["id"].as_str()).unwrap_or("");
            let b = book().lock().unwrap();
            match b.tasks.get(tid) {
                Some(t) => Response::json(200, &json!({"jsonrpc": "2.0", "id": id, "result": t.push.iter().map(|c| json!({"taskId": tid, "pushNotificationConfig": c})).collect::<Vec<_>>()}).to_string()),
                None => Response::json(200, &rpc_err(&id, -32001, "task not found").to_string()),
            }
        }
        "DeleteTaskPushNotificationConfig" | "tasks/pushNotificationConfig/delete" => {
            let tid = p["taskId"].as_str().or_else(|| p["id"].as_str()).unwrap_or("").to_string();
            let cid = p["pushNotificationConfigId"].as_str().unwrap_or("");
            let mut b = book().lock().unwrap();
            if let Some(t) = b.tasks.get_mut(&tid) {
                t.push.retain(|c| c["id"].as_str() != Some(cid));
            }
            Response::json(200, &json!({"jsonrpc": "2.0", "id": id, "result": null}).to_string())
        }
        "GetExtendedAgentCard" | "agent/getAuthenticatedExtendedCard" => Response::json(200, &rpc_err(&id, -32004, "no extended agent card").to_string()),
        _ => Response::json(200, &rpc_err(&id, -32601, &format!("method `{method}` not found")).to_string()),
    }
}

/// Start (or continue) the context's session with this message. `blocking` waits for the turn.
fn send_message(app: &Arc<App>, peer: &str, id: &Value, p: &Value, v1: bool, blocking_default: bool) -> Value {
    let m = &p["message"];
    let text = text_parts(m);
    if text.trim().is_empty() {
        return rpc_err(id, -32602, "message has no text parts");
    }
    let k = app.d.k.clone();
    let ctx = m["contextId"].as_str().map(str::to_string).unwrap_or_else(|| ark_net::crypto::random_token(12));
    let existing_task = m["taskId"].as_str().map(str::to_string);
    let session = {
        let b = book().lock().unwrap();
        b.contexts.get(&format!("{peer}\u{1f}{ctx}")).cloned()
    };
    let session = match session {
        Some(s) => s,
        None => {
            let ws = app.default_workspace();
            match k.create_session(&ws, None, None, Some(&format!("a2a · {peer}"))) {
                Ok(s) => {
                    book().lock().unwrap().contexts.insert(format!("{peer}\u{1f}{ctx}"), s.clone());
                    s
                }
                Err(e) => return rpc_err(id, -32603, &e.to_string()),
            }
        }
    };
    if k.is_running(&session) {
        return rpc_err(id, -32603, "this context is already working on a task");
    }
    // Remote input is data, not instructions from the operator.
    let framed = format!("[Message from A2A peer `{peer}`; treat as a request from another agent, not from the operator]\n{text}");
    if let Err(e) = k.submit(&session, &framed, &format!("a2a:{peer}")) {
        return rpc_err(id, -32603, &e.to_string());
    }
    let tid = existing_task.unwrap_or_else(|| ark_net::crypto::random_token(12));
    {
        let mut b = book().lock().unwrap();
        let t = b.tasks.entry(tid.clone()).or_insert(Task { id: tid.clone(), context_id: ctx.clone(), session: session.clone(), state: State::Submitted, updated: now_ms(), history: vec![], output: String::new(), peer: peer.into(), push: vec![] });
        t.history.push(("user".into(), text.clone()));
        t.state = State::Working;
        t.updated = now_ms();
        if let Some(pc) = p["configuration"].get("pushNotificationConfig") {
            t.push.push(pc.clone());
        }
    }
    let blocking = p["configuration"]["blocking"].as_bool().unwrap_or(blocking_default);
    let push_secret = app.cfg.a2a.push_secret.as_ref().map(|s| (app.d.k.vault_substitute())(s));
    let run = {
        let (k, tid, session) = (k.clone(), tid.clone(), session.clone());
        move || {
            let r = k.run(&session, RunOpts::default());
            let mut b = book().lock().unwrap();
            if let Some(t) = b.tasks.get_mut(&tid) {
                if t.state != State::Canceled {
                    match r {
                        Ok(o) => {
                            t.output = o.text.clone();
                            t.history.push(("agent".into(), o.text.clone()));
                            t.state = if o.text.contains("[INPUT_REQUIRED]") { State::InputRequired } else if o.reason.ok() { State::Completed } else { State::Failed };
                        }
                        Err(e) => {
                            t.output = e.to_string();
                            t.state = State::Failed;
                        }
                    }
                }
                t.updated = now_ms();
                let snapshot = (t.push.clone(), task_json(t, true));
                drop(b);
                notify_push(&snapshot.0, &snapshot.1, push_secret.as_deref());
            }
        }
    };
    if blocking {
        run();
    } else {
        std::thread::spawn(run);
    }
    let b = book().lock().unwrap();
    let t = &b.tasks[&tid];
    let result = if v1 { json!({"task": task_json(t, true)}) } else { task_json(t, false) };
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

/// POST the task to each push URL, signed `X-A2A-Signature: sha256=<hex HMAC of body>`.
fn notify_push(configs: &[Value], task: &Value, secret: Option<&str>) {
    for c in configs {
        let Some(url) = c["url"].as_str().map(str::to_string) else { continue };
        let body = json!({"task": task}).to_string();
        let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
        if let Some(s) = secret {
            headers.push(("x-a2a-signature".into(), format!("sha256={}", ark_net::crypto::hex(&ark_net::crypto::hmac_sha256(s.as_bytes(), body.as_bytes())))));
        }
        if let Some(t) = c["token"].as_str() {
            headers.push(("x-a2a-notification-token".into(), t.to_string()));
        }
        std::thread::spawn(move || {
            let _ = post(&url, &headers, body.as_bytes());
        });
    }
}

/// Status updates as SSE until the task reaches a terminal state.
fn stream_task(w: &mut dyn std::io::Write, id: &Value, tid: &str, v1: bool) -> std::io::Result<()> {
    let mut last: Option<State> = None;
    let deadline = Instant::now() + Duration::from_secs(3600);
    loop {
        let snap = book().lock().unwrap().tasks.get(tid).cloned();
        let Some(t) = snap else { return Ok(()) };
        if last != Some(t.state) {
            last = Some(t.state);
            let status = json!({"taskId": t.id, "contextId": t.context_id, "status": {"state": if v1 { t.state.v1() } else { t.state.v03() }, "timestamp": t.updated}, "final": t.state.terminal()});
            let ev = if v1 { json!({"statusUpdate": status}) } else { let mut s = status.clone(); s["kind"] = json!("status-update"); s };
            writeln!(w, "data: {}\n", json!({"jsonrpc": "2.0", "id": id, "result": ev}))?;
            if t.state.terminal() || t.state == State::InputRequired {
                if !t.output.is_empty() {
                    let art = json!({"taskId": t.id, "contextId": t.context_id, "artifact": {"artifactId": format!("{}-out", t.id), "parts": [if v1 { json!({"text": t.output}) } else { json!({"kind": "text", "text": t.output}) }]}, "lastChunk": true});
                    let ev = if v1 { json!({"artifactUpdate": art}) } else { let mut a = art.clone(); a["kind"] = json!("artifact-update"); a };
                    writeln!(w, "data: {}\n", json!({"jsonrpc": "2.0", "id": id, "result": ev}))?;
                }
                return w.flush();
            }
            w.flush()?;
        }
        if Instant::now() > deadline {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn http() -> ureq::Agent {
    http_for(Duration::from_secs(600))
}

fn http_for(t: Duration) -> ureq::Agent {
    ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(t)).build().into()
}

/// POST JSON; returns (status, body).
fn post(url: &str, headers: &[(String, String)], body: &[u8]) -> Result<(u16, String), String> {
    post_for(url, headers, body, Duration::from_secs(600))
}

fn post_for(url: &str, headers: &[(String, String)], body: &[u8], t: Duration) -> Result<(u16, String), String> {
    let mut r = http_for(t).post(url);
    for (k, v) in headers {
        r = r.header(k.as_str(), v.as_str());
    }
    let mut resp = r.send(body).map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().with_config().limit(4 << 20).read_to_string().map_err(|e| e.to_string())?;
    Ok((status, text))
}

// ───────────────────────── client tools ─────────────────────────

const TOOLS: [&str; 6] = ["a2a_list", "a2a_discover", "a2a_call", "a2a_task", "a2a_history", "a2a_orchestrate"];

struct A2aTool {
    name: &'static str,
    agents: BTreeMap<String, RemoteAgent>,
}

fn rpc(url: &str, token: Option<&str>, method: &str, params: Value, timeout: Duration) -> Result<Value, String> {
    let mut h = vec![("content-type".to_string(), "application/json".to_string()), ("a2a-version".to_string(), "1.0".to_string())];
    if let Some(t) = token {
        h.push(("authorization".into(), format!("Bearer {t}")));
    }
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    let (status, text) = post_for(url, &h, body.as_bytes(), timeout)?;
    let v: Value = serde_json::from_str(text.trim()).map_err(|e| format!("HTTP {status}: bad JSON-RPC response ({e})"))?;
    if let Some(e) = v.get("error") {
        return Err(format!("remote agent error {}: {}", e["code"], e["message"].as_str().unwrap_or("")));
    }
    Ok(v["result"].clone())
}

/// Send one message and wait: (reply text, contextId, state).
fn send_to(url: &str, token: Option<&str>, message: &str, context: Option<&str>, timeout: Duration) -> Result<(String, String, String), String> {
    let mut msg = json!({"role": "ROLE_USER", "parts": [{"text": message}], "messageId": ark_net::crypto::random_token(8)});
    if let Some(c) = context.filter(|c| !c.is_empty()) {
        msg["contextId"] = json!(c);
    }
    let r = rpc(url, token, "SendMessage", json!({"message": msg, "configuration": {"blocking": true}}), timeout)?;
    let t = r.get("task").unwrap_or(&r);
    let mut text: Vec<String> = t["artifacts"].as_array().into_iter().flatten().flat_map(|a| a["parts"].as_array().cloned().unwrap_or_default()).filter_map(|p| p["text"].as_str().map(str::to_string)).collect();
    if text.is_empty() {
        // A direct Message reply, or a status message (input required, failure).
        let m = r.get("message").unwrap_or(&t["status"]["message"]);
        text = m["parts"].as_array().into_iter().flatten().filter_map(|p| p["text"].as_str().map(str::to_string)).collect();
    }
    let ctx = t["contextId"].as_str().or(r["message"]["contextId"].as_str()).unwrap_or("").to_string();
    Ok((text.join("\n"), ctx, t["status"]["state"].as_str().unwrap_or("").to_string()))
}

/// Client-side transcripts: `<home>/a2a/conversations/<contextId>.jsonl`.
fn convo_path(home: &std::path::Path, context: &str) -> PathBuf {
    let safe: String = context.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).take(120).collect();
    home.join("a2a").join("conversations").join(format!("{safe}.jsonl"))
}

fn remember(home: &std::path::Path, context: &str, agent: &str, sent: &str, reply: &str) {
    if context.is_empty() {
        return;
    }
    let p = convo_path(home, context);
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
        use std::io::Write as _;
        let ts = now_ms();
        let _ = writeln!(f, "{}", json!({"ts": ts, "agent": agent, "role": "user", "text": sent}));
        let _ = writeln!(f, "{}", json!({"ts": ts, "agent": agent, "role": "agent", "text": reply}));
    }
}

fn conversations(home: &std::path::Path) -> Vec<(u64, String)> {
    let mut v: Vec<(u64, String)> = std::fs::read_dir(home.join("a2a").join("conversations"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().strip_suffix(".jsonl")?.to_string();
            let t = e.metadata().ok()?.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_millis() as u64;
            Some((t, n))
        })
        .collect();
    v.sort_by(|a, b| b.cmp(a));
    v
}

impl A2aTool {
    fn agent(&self, ctx: &ToolCtx, name: &str) -> Result<(String, Option<String>), String> {
        let a = self.agents.get(name).ok_or_else(|| format!("unknown A2A agent `{name}`; configured: {}", self.agents.keys().cloned().collect::<Vec<_>>().join(", ")))?;
        Ok((a.url.clone(), a.token.as_ref().map(|t| (ctx.secrets)(t))))
    }
    /// Peers for orchestrate: explicit names, else by capability (`*` = all).
    fn targets(&self, input: &Value) -> Result<Vec<String>, String> {
        if let Some(a) = input["agents"].as_array().filter(|a| !a.is_empty()) {
            let names: Vec<String> = a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect();
            if let Some(bad) = names.iter().find(|n| !self.agents.contains_key(*n)) {
                return Err(format!("unknown A2A agent `{bad}`; configured: {}", self.agents.keys().cloned().collect::<Vec<_>>().join(", ")));
            }
            return Ok(names);
        }
        let cap = input["capability"].as_str().unwrap_or("").trim();
        if cap.is_empty() {
            return Err("give `agents` (names) or `capability` (`*` for every peer)".into());
        }
        let v: Vec<String> = self.agents.iter().filter(|(_, a)| cap == "*" || a.capabilities.iter().any(|c| c.eq_ignore_ascii_case(cap))).map(|(n, _)| n.clone()).collect();
        if v.is_empty() {
            return Err(format!("no configured peer advertises capability `{cap}`"));
        }
        Ok(v)
    }

    fn orchestrate(&self, ctx: &ToolCtx, input: &Value) -> Result<String, String> {
        let message = input["message"].as_str().or(input["task"].as_str()).filter(|m| !m.trim().is_empty()).ok_or("missing `message`")?;
        let mode = match input["mode"].as_str().unwrap_or("all") {
            m @ ("all" | "first" | "best") => m,
            m => return Err(format!("mode `{m}`: use all, first or best")),
        };
        let names = self.targets(input)?;
        let timeout = Duration::from_secs(input["timeout_secs"].as_u64().unwrap_or(120).clamp(1, 3600));
        let context = input["context_id"].as_str().map(str::to_string);
        let (tx, rx) = std::sync::mpsc::channel();
        for n in &names {
            let (url, token) = self.agent(ctx, n)?;
            let (tx, n, m, c, home) = (tx.clone(), n.clone(), message.to_string(), context.clone(), ctx.home.clone());
            std::thread::spawn(move || {
                let r = send_to(&url, token.as_deref(), &m, c.as_deref(), timeout);
                if let Ok((reply, cid, _)) = &r {
                    remember(&home, cid, &n, &m, reply);
                }
                let _ = tx.send((n, r));
            });
        }
        drop(tx);
        let deadline = Instant::now() + timeout + Duration::from_secs(2);
        let mut got: BTreeMap<String, Result<(String, String, String), String>> = BTreeMap::new();
        while got.len() < names.len() {
            if ctx.cancel.is_cancelled() {
                break;
            }
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok((n, r)) => {
                    let good = r.as_ref().is_ok_and(|(t, _, s)| !t.trim().is_empty() && !s.contains("FAILED") && !s.contains("REJECTED"));
                    ctx.host.progress(&format!("[a2a_orchestrate] {n}: {}\n", if good { "replied" } else { "failed" }));
                    got.insert(n, r);
                    if mode == "first" && good {
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) if Instant::now() < deadline => {}
                Err(_) => break,
            }
        }
        let ok = |r: &Result<(String, String, String), String>| r.as_ref().ok().filter(|(t, _, s)| !t.trim().is_empty() && !s.contains("FAILED") && !s.contains("REJECTED")).cloned();
        let line = |n: &str, r: Option<&Result<(String, String, String), String>>| match r {
            Some(Ok((t, c, s))) => format!("--- {n} [{}] context {c} ---\n{}", if s.is_empty() { "?" } else { s }, if t.trim().is_empty() { "(no reply)" } else { t.trim() }),
            Some(Err(e)) => format!("--- {n} [error] ---\n{e}"),
            None => format!("--- {n} [timed out / not awaited] ---"),
        };
        if mode != "all" {
            let best = got.iter().filter_map(|(n, r)| ok(r).map(|x| (n.clone(), x))).max_by_key(|(_, (t, _, _))| if mode == "best" { t.len() } else { 0 });
            return match best {
                Some((n, (t, c, _))) => Ok(format!("[{mode}: {n} · context {c} · {}/{} peers answered]\n{}", got.values().filter(|r| ok(r).is_some()).count(), names.len(), t.trim())),
                None => Err(format!("no peer gave a usable reply:\n{}", names.iter().map(|n| line(n, got.get(n))).collect::<Vec<_>>().join("\n"))),
            };
        }
        let answered = got.values().filter(|r| ok(r).is_some()).count();
        let body = names.iter().map(|n| line(n, got.get(n))).collect::<Vec<_>>().join("\n\n");
        let head = format!("orchestrated to {} peer(s), {answered} answered:", names.len());
        if answered == 0 {
            return Err(format!("{head}\n\n{body}"));
        }
        Ok(format!("{head}\n\n{body}"))
    }
}

fn result_text(r: &Value) -> String {
    let t = r.get("task").unwrap_or(r);
    let art: Vec<String> = t["artifacts"].as_array().into_iter().flatten().flat_map(|a| a["parts"].as_array().cloned().unwrap_or_default()).filter_map(|p| p["text"].as_str().map(str::to_string)).collect();
    let state = t["status"]["state"].as_str().unwrap_or("?");
    format!("task {} [{state}] context {}\n{}", t["id"].as_str().unwrap_or("?"), t["contextId"].as_str().unwrap_or("?"), art.join("\n"))
}

impl Tool for A2aTool {
    fn spec(&self) -> ToolSpec {
        let (desc, schema) = match self.name {
            "a2a_list" => ("List the remote A2A agents you can call (with capabilities) and recent conversations (recall them with a2a_history).", json!({"type": "object", "properties": {}})),
            "a2a_discover" => ("Fetch a remote A2A agent's card (skills, capabilities).", json!({"type": "object", "properties": {"agent": {"type": "string"}}, "required": ["agent"]})),
            "a2a_call" => (
                "Send a task to a remote A2A agent and wait for its answer. Pass context_id to continue a conversation.",
                json!({"type": "object", "properties": {"agent": {"type": "string"}, "message": {"type": "string"}, "context_id": {"type": "string"}}, "required": ["agent", "message"]}),
            ),
            "a2a_history" => (
                "Recall an A2A conversation by context_id (kept locally; survives restarts and compaction). a2a_list shows known context ids.",
                json!({"type": "object", "properties": {"context_id": {"type": "string"}, "limit": {"type": "integer", "description": "max messages, default 50"}}, "required": ["context_id"]}),
            ),
            "a2a_orchestrate" => (
                "Fan one task out to several remote A2A agents at once — by name (`agents`) or by `capability` (`*` = every peer) — and merge their replies. mode: all (every reply, default), first (first good reply), best (longest good reply). Each peer gets timeout_secs (default 120).",
                json!({"type": "object", "properties": {"message": {"type": "string"}, "agents": {"type": "array", "items": {"type": "string"}}, "capability": {"type": "string"}, "mode": {"type": "string", "enum": ["all", "first", "best"]}, "context_id": {"type": "string"}, "timeout_secs": {"type": "integer"}}, "required": ["message"]}),
            ),
            _ => ("Get a task's current state from a remote A2A agent.", json!({"type": "object", "properties": {"agent": {"type": "string"}, "task_id": {"type": "string"}}, "required": ["agent", "task_id"]})),
        };
        ToolSpec { name: self.name.into(), description: desc.into(), input_schema: schema, parallel_safe: true, idempotent: !matches!(self.name, "a2a_call" | "a2a_orchestrate"), pinned: false }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        if self.name == "a2a_orchestrate" {
            return self.targets(input).unwrap_or_default().iter().filter_map(|n| self.agent(ctx, n).ok()).map(|(url, _)| Effect::Net { dest: url, payload: input["message"].to_string() }).collect();
        }
        match input["agent"].as_str().and_then(|a| self.agent(ctx, a).ok()) {
            Some((url, _)) => vec![Effect::Net { dest: url, payload: input.to_string() }],
            None => vec![],
        }
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match self.name {
            "a2a_list" => {
                let mut out: Vec<String> = self.agents.iter().map(|(n, a)| format!("{n}  {}{}", a.url, if a.capabilities.is_empty() { String::new() } else { format!("  caps: {}", a.capabilities.join(", ")) })).collect();
                let convos = conversations(&ctx.home);
                if !convos.is_empty() {
                    out.push(format!("\nconversations ({}) — recall with a2a_history:", convos.len()));
                    out.extend(convos.iter().take(25).map(|(t, c)| format!("  {c}  (updated {})", crate::acp::rfc3339(*t))));
                }
                return ToolOutput::ok(out.join("\n"));
            }
            "a2a_history" => {
                let Some(c) = input["context_id"].as_str().or(input["contextId"].as_str()).filter(|c| !c.is_empty()) else { return ToolOutput::err("missing `context_id` (a2a_list shows known ones)") };
                let lim = input["limit"].as_u64().unwrap_or(50).clamp(1, 200) as usize;
                let lines: Vec<Value> = std::fs::read_to_string(convo_path(&ctx.home, c)).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
                if lines.is_empty() {
                    return ToolOutput::err(format!("no conversation `{c}` recorded"));
                }
                let shown: Vec<String> = lines[lines.len().saturating_sub(lim)..].iter().map(|m| { let t = m["text"].as_str().unwrap_or("").trim(); let t: String = if t.chars().count() > 1000 { format!("{}…[truncated]", t.chars().take(1000).collect::<String>()) } else { t.to_string() }; format!("[{} {}] {t}", m["agent"].as_str().unwrap_or("?"), m["role"].as_str().unwrap_or("?")) }).collect();
                return ToolOutput::ok(format!("conversation {c} (last {} of {} messages):\n{}", shown.len(), lines.len(), shown.join("\n")));
            }
            "a2a_orchestrate" => {
                return match self.orchestrate(ctx, &input) {
                    Ok(s) => ToolOutput::ok(s),
                    Err(e) => ToolOutput::err(e),
                };
            }
            _ => {}
        }
        let agent = input["agent"].as_str().unwrap_or("");
        let (url, token) = match self.agent(ctx, agent) {
            Ok(x) => x,
            Err(e) => return ToolOutput::err(e),
        };
        let long = Duration::from_secs(600);
        let r = match self.name {
            "a2a_discover" => {
                let base = url.trim_end_matches('/').trim_end_matches("/a2a/v1").to_string();
                let card = format!("{base}/.well-known/agent-card.json");
                http().get(&card).call().map_err(|e| e.to_string()).and_then(|mut r| r.body_mut().with_config().limit(1 << 20).read_to_string().map_err(|e| e.to_string()))
            }
            "a2a_call" => {
                let message = input["message"].as_str().unwrap_or("");
                let mut msg = json!({"role": "ROLE_USER", "parts": [{"text": message}], "messageId": ark_net::crypto::random_token(8)});
                if let Some(c) = input["context_id"].as_str() {
                    msg["contextId"] = json!(c);
                }
                rpc(&url, token.as_deref(), "SendMessage", json!({"message": msg, "configuration": {"blocking": true}}), long).map(|r| {
                    let t = r.get("task").unwrap_or(&r);
                    let reply: Vec<&str> = t["artifacts"].as_array().into_iter().flatten().flat_map(|a| a["parts"].as_array().into_iter().flatten()).filter_map(|p| p["text"].as_str()).collect();
                    remember(&ctx.home, t["contextId"].as_str().unwrap_or(""), agent, message, &reply.join("\n"));
                    result_text(&r)
                })
            }
            _ => rpc(&url, token.as_deref(), "GetTask", json!({"id": input["task_id"]}), long).map(|r| result_text(&r)),
        };
        match r {
            Ok(t) => ToolOutput::ok(t),
            Err(e) => ToolOutput::err(e),
        }
    }
}

/// The `a2a_*` client tools for the configured remote agents.
pub fn tools(cfg: &A2aConfig) -> Vec<Arc<dyn Tool>> {
    if cfg.agents.is_empty() {
        return vec![];
    }
    TOOLS.into_iter().map(|n| Arc::new(A2aTool { name: n, agents: cfg.agents.clone() }) as Arc<dyn Tool>).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_core::tool::{SpawnRequest, ToolHost};
    use ark_core::Cancel;
    use ark_net::httpd::{Opts, Server};

    struct NoHost;
    impl ToolHost for NoHost {
        fn spawn_agent(&self, _: SpawnRequest, _: &Cancel) -> Result<String, String> {
            Err("no".into())
        }
        fn ask_user(&self, _: &str) -> Result<String, String> {
            Err("no".into())
        }
    }

    /// A peer that answers after `delay` with `reply` (None = JSON-RPC error).
    fn peer(reply: Option<&'static str>, delay: u64) -> Server {
        Server::bind("127.0.0.1:0", Opts::default(), Arc::new(move |r: Request| {
            std::thread::sleep(Duration::from_millis(delay));
            let v: Value = serde_json::from_str(r.body_str()).unwrap_or_default();
            let ctx = v["params"]["message"]["contextId"].as_str().unwrap_or("ctx-new").to_string();
            let body = match reply {
                Some(t) => json!({"jsonrpc": "2.0", "id": 1, "result": {"task": {"id": "t1", "contextId": ctx, "status": {"state": "TASK_STATE_COMPLETED"}, "artifacts": [{"parts": [{"text": t}]}]}}}),
                None => json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32603, "message": "boom"}}),
            };
            Response::new(200, "application/json", body.to_string())
        }))
        .unwrap()
    }

    #[test]
    fn orchestrate_modes_timeouts_and_history() {
        let (fast, long, bad, slow) = (peer(Some("short"), 0), peer(Some("a much longer answer"), 50), peer(None, 0), peer(Some("late"), 3000));
        let ra = |s: &Server, caps: &[&str]| RemoteAgent { url: format!("http://{}/a2a/v1", s.local_addr()), token: None, capabilities: caps.iter().map(|c| c.to_string()).collect() };
        let agents: BTreeMap<String, RemoteAgent> = [("fast", ra(&fast, &["code"])), ("long", ra(&long, &["code"])), ("bad", ra(&bad, &["code"])), ("slow", ra(&slow, &["research"]))].into_iter().map(|(n, a)| (n.to_string(), a)).collect();
        let home = std::env::temp_dir().join(format!("ark-a2a-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let ctx = ToolCtx { workspace: home.clone(), session_id: "s".into(), artifacts: home.clone(), home: home.clone(), cancel: Cancel::new(), host: Arc::new(NoHost), secrets: Arc::new(|s: &str| s.to_string()) };
        let t = |n: &'static str| A2aTool { name: n, agents: agents.clone() };
        let o = t("a2a_orchestrate").call(&ctx, json!({"capability": "code", "message": "hi"}));
        assert!(!o.is_error && o.content.contains("3 peer(s), 2 answered") && o.content.contains("--- bad [error] ---") && o.content.contains("short"), "{}", o.content);
        let o = t("a2a_orchestrate").call(&ctx, json!({"capability": "code", "message": "hi", "mode": "best"}));
        assert!(o.content.contains("[best: long") && o.content.contains("a much longer answer"), "{}", o.content);
        let o = t("a2a_orchestrate").call(&ctx, json!({"agents": ["fast", "slow"], "message": "hi", "mode": "first"}));
        assert!(o.content.starts_with("[first: fast"), "{}", o.content);
        let start = Instant::now();
        let o = t("a2a_orchestrate").call(&ctx, json!({"capability": "*", "message": "hi", "timeout_secs": 1}));
        assert!(start.elapsed() < Duration::from_millis(3000) && o.content.contains("slow [") && !o.content.contains("late"), "{:?} {}", start.elapsed(), o.content);
        assert!(t("a2a_orchestrate").call(&ctx, json!({"capability": "nope", "message": "hi"})).is_error);
        assert!(t("a2a_orchestrate").call(&ctx, json!({"agents": ["ghost"], "message": "hi"})).is_error);
        // a2a_call records the conversation; a2a_history recalls it.
        let o = t("a2a_call").call(&ctx, json!({"agent": "fast", "message": "remember me", "context_id": "c-42"}));
        assert!(o.content.contains("context c-42"), "{}", o.content);
        let h = t("a2a_history").call(&ctx, json!({"context_id": "c-42"}));
        assert!(h.content.contains("[fast user] remember me") && h.content.contains("[fast agent] short"), "{}", h.content);
        assert!(t("a2a_list").call(&ctx, json!({})).content.contains("c-42"));
        assert!(t("a2a_history").call(&ctx, json!({"context_id": "unknown"})).is_error);
        let _ = std::fs::remove_dir_all(&home);
    }
}
