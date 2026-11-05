//! ACP (Agent Client Protocol, Zed) agent over stdio: editors drive ark like any
//! ACP agent. Parity with OpenClaw `src/acp` and Hermes `acp_adapter` (MIT).
//!
//! Handles initialize, authenticate, session/new, session/load (history replayed as
//! updates), session/list, session/resume, session/fork, session/close,
//! session/prompt, session/cancel, session/set_mode, session/set_model and
//! session/set_config_option (mode, model, thought_level). Streams
//! agent_message_chunk / agent_thought_chunk / user_message_chunk, tool_call and
//! tool_call_update (kind inferred from the tool; edits carry a whole-file diff),
//! plan (from the todo tool), available_commands_update, current_mode_update,
//! config_option_update, session_info_update (title) and usage_update (context
//! window, cost). Gate approvals become `session/request_permission` to the editor,
//! with the diff for edits. Image prompt content reaches the model as image input.
//! MCP servers the editor passes in session/new / load / resume are started for
//! that session only (untrusted unless `[acp] trust_editor_mcp`) and stopped on
//! session/close and at exit. The client side (ark driving other ACP agents) is
//! in [`crate::acp_client`].

use crate::acp_client::AcpConfig;
use ark_core::{Block, Message, Role};
use ark_kernel::approver::{Approval, ApprovalRequest, Approver};
use ark_kernel::event::EventKind;
use ark_kernel::kernel::{BusMsg, EndReason, Kernel, RunOpts};
use ark_kernel::projection::{project, View};
use ark_plugin::{McpServerConfig, Registry};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::Duration;

pub const PROTOCOL_VERSION: u64 = 1;

/// The editor on the other end: writes frames, matches responses to our requests.
pub struct Peer {
    out: Mutex<Box<dyn Write + Send>>,
    next: AtomicU64,
    waiting: Mutex<HashMap<u64, mpsc::Sender<Value>>>,
    modes: Mutex<HashMap<String, String>>,
    caps: Mutex<Value>,
    /// Workspace per session (diff previews for permission requests).
    cwds: Mutex<HashMap<String, PathBuf>>,
    /// Editor-provided MCP servers, owned by their session.
    mcp: Mutex<HashMap<String, Registry>>,
    /// Edit diffs taken when a call is written ahead (before it runs), by tool_use_id.
    diffs: Mutex<HashMap<String, Vec<Value>>>,
}

impl Peer {
    pub fn new(out: Box<dyn Write + Send>) -> Arc<Peer> {
        Arc::new(Peer { out: Mutex::new(out), next: AtomicU64::new(1), waiting: Mutex::default(), modes: Mutex::default(), caps: Mutex::new(Value::Null), cwds: Mutex::default(), mcp: Mutex::default(), diffs: Mutex::default() })
    }
    fn send(&self, v: &Value) {
        let mut o = self.out.lock().unwrap();
        let _ = writeln!(o, "{v}");
        let _ = o.flush();
    }
    fn notify(&self, method: &str, params: Value) {
        self.send(&json!({"jsonrpc": "2.0", "method": method, "params": params}));
    }
    fn update(&self, session: &str, update: Value) {
        self.notify("session/update", json!({"sessionId": session, "update": update}));
    }
    /// Agent → client request; blocks for the answer.
    fn request(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, String> {
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1_000_000;
        let (tx, rx) = mpsc::channel();
        self.waiting.lock().unwrap().insert(id, tx);
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        let r = rx.recv_timeout(timeout).map_err(|_| format!("{method}: no answer from the editor"));
        self.waiting.lock().unwrap().remove(&id);
        let v = r?;
        match v.get("error") {
            Some(e) => Err(e["message"].as_str().unwrap_or("error").to_string()),
            None => Ok(v["result"].clone()),
        }
    }
    fn mode(&self, session: &str) -> String {
        self.modes.lock().unwrap().get(session).cloned().unwrap_or_else(|| "default".into())
    }
    fn stop_mcp(&self, k: &Kernel, session: &str) {
        if let Some(r) = self.mcp.lock().unwrap().remove(session) {
            r.shutdown();
        }
        k.set_session_tools(session, vec![]);
    }
}

/// Gate approvals go to the editor as permission requests.
pub struct AcpApprover(pub Arc<OnceLock<Arc<Peer>>>);

impl Approver for AcpApprover {
    fn approve(&self, req: &ApprovalRequest) -> Approval {
        let Some(peer) = self.0.get() else { return Approval::Deny };
        match peer.mode(&req.session).as_str() {
            "auto" => return Approval::Once,
            "strict" => return Approval::Deny,
            _ => {}
        }
        let id = if req.tool_use_id.is_empty() { &req.id } else { &req.tool_use_id };
        let mut tool_call = json!({"toolCallId": id, "title": format!("{} — {}", req.tool, req.reason), "kind": if req.tool == "shell" { "execute" } else { kind_of(&req.tool) }, "status": "pending", "rawInput": if req.input.is_null() { json!({"summary": req.summary}) } else { req.input.clone() }, "locations": locations(&req.input)});
        let ws = peer.cwds.lock().unwrap().get(&req.session).cloned();
        let d = ws.map(|ws| edit_diffs(&ws, &req.tool, &req.input)).unwrap_or_default();
        if !d.is_empty() {
            tool_call["content"] = json!(d);
        }
        let options = json!([
            {"optionId": "allow_once", "name": "允許一次", "kind": "allow_once"},
            {"optionId": "allow_always", "name": "本次對話都允許", "kind": "allow_always"},
            {"optionId": "deny", "name": "拒絕", "kind": "reject_once"},
        ]);
        match peer.request("session/request_permission", json!({"sessionId": req.session, "toolCall": tool_call, "options": options}), Duration::from_secs(600)) {
            Ok(r) if r["outcome"]["outcome"] == "selected" => match r["outcome"]["optionId"].as_str() {
                Some("allow_once") => Approval::Once,
                Some("allow_always") => Approval::Always,
                _ => Approval::Deny,
            },
            _ => Approval::Deny,
        }
    }
    fn ask(&self, session: &str, question: &str) -> Result<String, String> {
        let peer = self.0.get().ok_or("editor not connected")?;
        // Clients that advertise form elicitation get a real question; others cannot answer free text.
        if peer.caps.lock().unwrap()["elicitation"]["form"].is_object() {
            let r = peer.request("elicitation/create", json!({"sessionId": session, "message": question, "requestedSchema": {"type": "object", "properties": {"answer": {"type": "string"}}, "required": ["answer"]}}), Duration::from_secs(600))?;
            if r["action"] == "accept" {
                return Ok(r["content"]["answer"].as_str().unwrap_or("").to_string());
            }
            return Err("the user declined to answer".into());
        }
        Err("this editor cannot answer free-form questions; proceed with your best judgement and state assumptions".into())
    }
}

/// ACP tool kinds: read, edit, delete, move, search, execute, think, fetch, other.
pub fn kind_of(tool: &str) -> &'static str {
    match tool {
        "read" | "memory" | "session_search" | "skill" | "a2a_history" | "a2a_list" => "read",
        "write" | "edit" | "patch" | "apply_patch" => "edit",
        "grep" | "glob" | "web_search" => "search",
        "shell" | "job" | "run" | "spawn" | "node_invoke" | "acp_delegate" => "execute",
        "web_fetch" | "a2a_call" | "a2a_discover" | "a2a_orchestrate" | "a2a_task" => "fetch",
        "todo" => "think",
        _ => "other",
    }
}

fn locations(input: &Value) -> Vec<Value> {
    let mut v: Vec<Value> = ["path", "file", "file_path"].iter().filter_map(|k| input[*k].as_str()).map(|p| json!({"path": p})).collect();
    v.extend(input["edits"].as_array().into_iter().flatten().filter_map(|e| e["path"].as_str()).map(|p| json!({"path": p})));
    v.dedup();
    v
}

/// Edits as snippet diffs (no file access).
fn diff_content(name: &str, input: &Value) -> Vec<Value> {
    match name {
        "edit" => vec![json!({"type": "diff", "path": input["path"], "oldText": input["old_string"], "newText": input["new_string"]})],
        "write" => vec![json!({"type": "diff", "path": input["path"], "oldText": null, "newText": input["content"]})],
        "patch" => input["edits"].as_array().into_iter().flatten().map(|e| json!({"type": "diff", "path": e["path"], "oldText": e["old_string"], "newText": e["new_string"]})).collect(),
        _ => vec![],
    }
}

/// Edits as whole-file diffs computed against the files in `ws` (before the call
/// runs); snippet diffs when the preview fails (file gone, ambiguous edit).
fn edit_diffs(ws: &Path, name: &str, input: &Value) -> Vec<Value> {
    if !matches!(name, "write" | "edit" | "patch" | "apply_patch") {
        return vec![];
    }
    match ark_tools::preview(ws, name, input) {
        Ok(files) => files.into_iter().map(|(p, old, new)| json!({"type": "diff", "path": p.to_string_lossy(), "oldText": old, "newText": new})).collect(),
        Err(_) => diff_content(name, input),
    }
}

/// `[x] 1. a` / `[>] 2. b` / `[ ] 3. c` → ACP plan entries.
fn plan_from_todo(text: &str) -> Option<Value> {
    let entries: Vec<Value> = text
        .lines()
        .filter_map(|l| {
            let l = l.trim_start();
            let (st, rest) = if let Some(r) = l.strip_prefix("[x]") { ("completed", r) } else if let Some(r) = l.strip_prefix("[>]") { ("in_progress", r) } else { ("pending", l.strip_prefix("[ ]")?) };
            let content = rest.trim().split_once(". ").map(|(_, c)| c).unwrap_or(rest.trim());
            Some(json!({"content": content, "priority": "medium", "status": st}))
        })
        .collect();
    (!entries.is_empty()).then(|| json!({"sessionUpdate": "plan", "entries": entries}))
}

/// Prompt blocks → (text for the model, image blocks).
fn prompt_content(blocks: &Value) -> (String, Vec<Block>) {
    let mut out = Vec::new();
    let mut images = Vec::new();
    let image = |mt: &str, data: Option<&str>| data.filter(|d| mt.starts_with("image/") && !d.is_empty()).map(|d| Block::Image { media_type: mt.to_string(), data: d.to_string() });
    for b in blocks.as_array().into_iter().flatten() {
        match b["type"].as_str() {
            Some("text") => out.push(b["text"].as_str().unwrap_or("").to_string()),
            Some("resource") => {
                let r = &b["resource"];
                let uri = r["uri"].as_str().unwrap_or("");
                match (r["text"].as_str(), image(r["mimeType"].as_str().unwrap_or(""), r["blob"].as_str())) {
                    (Some(t), _) => out.push(format!("<context uri=\"{uri}\">\n{t}\n</context>")),
                    (None, Some(img)) => {
                        out.push(format!("[image {uri} attached]"));
                        images.push(img);
                    }
                    (None, None) => out.push(format!("[binary resource {uri}]")),
                }
            }
            Some("resource_link") => out.push(format!("[Resource link ({})] {}", b["name"].as_str().or_else(|| b["title"].as_str()).unwrap_or(""), b["uri"].as_str().unwrap_or(""))),
            Some("image") => match image(b["mimeType"].as_str().unwrap_or(""), b["data"].as_str()) {
                Some(img) => images.push(img),
                // URI-only images: the model cannot fetch them, say where they are.
                None => out.push(format!("[image {} {}]", b["mimeType"].as_str().unwrap_or(""), b["uri"].as_str().unwrap_or("(no data)"))),
            },
            Some(other) => out.push(format!("[{other} content omitted]")),
            None => {}
        }
    }
    (out.join("\n\n"), images)
}

const MODES: &[(&str, &str, &str)] = &[
    ("default", "詢問", "閘門觸發時詢問你"),
    ("auto", "自動核准", "閘門觸發時直接允許（仍會記錄）"),
    ("strict", "嚴格", "閘門觸發時一律拒絕"),
];

const THOUGHT: &[(&str, &str)] = &[("default", "模型預設"), ("off", "關閉"), ("low", "低"), ("medium", "中"), ("high", "高")];

fn modes_json(current: &str) -> Value {
    json!({"currentModeId": current, "availableModes": MODES.iter().map(|(id, n, d)| json!({"id": id, "name": n, "description": d})).collect::<Vec<_>>()})
}

/// Models the editor's picker offers: the session's, the configured ones, priced ones, `[acp] models`.
fn model_ids(k: &Kernel, acp: &AcpConfig, current: &str) -> Vec<String> {
    let c = &k.cfg.model;
    let mut v: Vec<String> = vec![current.to_string(), c.default.clone()];
    v.extend(c.fallback.iter().cloned());
    v.extend([c.aux.clone(), c.subagent.clone()]);
    v.extend(k.cfg.prices.keys().cloned());
    v.extend(acp.models.iter().cloned());
    let mut seen = std::collections::HashSet::new();
    v.retain(|m| m.contains('/') && seen.insert(m.clone()));
    v
}

fn models_json(k: &Kernel, acp: &AcpConfig, current: &str) -> Value {
    let avail: Vec<Value> = model_ids(k, acp, current).iter().map(|m| { let (p, n) = m.split_once('/').unwrap_or(("", m)); json!({"modelId": m, "name": n, "description": p}) }).collect();
    json!({"currentModelId": current, "availableModels": avail})
}

fn view_of(k: &Kernel, sid: &str) -> View {
    k.store.read(sid).map(|e| project(&e)).unwrap_or_default()
}

fn config_options(k: &Kernel, peer: &Peer, acp: &AcpConfig, sid: &str) -> Value {
    let v = view_of(k, sid);
    let sel = |id: &str, name: &str, cur: &str, opts: Vec<Value>| json!({"id": id, "name": name, "category": id, "type": "select", "currentValue": cur, "options": opts});
    json!([
        sel("mode", "模式", &peer.mode(sid), MODES.iter().map(|(id, n, d)| json!({"value": id, "name": n, "description": d})).collect()),
        sel("model", "模型", &v.model, model_ids(k, acp, &v.model).iter().map(|m| json!({"value": m, "name": m})).collect()),
        sel("thought_level", "思考深度", v.thinking.as_deref().unwrap_or("default"), THOUGHT.iter().map(|(id, n)| json!({"value": id, "name": n})).collect()),
    ])
}

/// What session/new, load, resume and fork answer with (plus sessionId for new/fork).
fn session_state(k: &Kernel, peer: &Peer, acp: &AcpConfig, sid: &str) -> Value {
    let v = view_of(k, sid);
    json!({"modes": modes_json(&peer.mode(sid)), "models": models_json(k, acp, &v.model), "configOptions": config_options(k, peer, acp, sid)})
}

fn stop_reason(r: &EndReason) -> &'static str {
    match r {
        EndReason::Interrupted => "cancelled",
        EndReason::MaxTokens | EndReason::Budget(_) => "max_tokens",
        EndReason::MaxSteps => "max_turn_requests",
        EndReason::Refusal => "refusal",
        _ => "end_turn",
    }
}

/// RFC 3339 UTC timestamp from unix millis.
pub fn rfc3339(ms: u64) -> String {
    let s = (ms / 1000) as i64;
    let (y, m, d) = ark_kernel::util::civil_from_days(s.div_euclid(86_400));
    let r = s.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", r / 3600, r % 3600 / 60, r % 60)
}

/// Context window in use, its size, and the session's spend (when priced).
fn usage_update(k: &Kernel, sid: &str) -> Value {
    let v = view_of(k, sid);
    let (pid, m) = ark_kernel::context::split_model(&v.model);
    let size = k.resolver.provider(pid).map(|p| p.caps(m).context_window).unwrap_or(0);
    let used = if v.last_input_tokens > 0 { v.last_input_tokens } else { v.usage.input_tokens + v.usage.output_tokens };
    let mut u = json!({"sessionUpdate": "usage_update", "used": used, "size": size});
    if let Some(p) = k.cfg.price(&v.model) {
        let x = &v.usage;
        let amount = (x.input_tokens + x.cache_write_tokens) as f64 * p.input / 1e6 + x.output_tokens as f64 * p.output / 1e6 + x.cache_read_tokens as f64 * if p.cache_read > 0.0 { p.cache_read } else { p.input * 0.1 } / 1e6;
        u["cost"] = json!({"amount": (amount * 1e6).round() / 1e6, "currency": "USD"});
    }
    u
}

/// Replay a session's history as ACP updates (session/load).
fn replay(peer: &Peer, k: &Kernel, sid: &str) {
    let Ok(evs) = k.store.read(sid) else { return };
    for e in evs {
        if let EventKind::Message { message, .. } = &e.kind {
            send_message(peer, sid, message);
        }
    }
}

fn send_message(peer: &Peer, sid: &str, m: &Message) {
    for b in &m.content {
        match (b, m.role) {
            (Block::Text { text }, Role::User) => peer.update(sid, json!({"sessionUpdate": "user_message_chunk", "content": {"type": "text", "text": text}})),
            (Block::Image { media_type, data }, Role::User) => peer.update(sid, json!({"sessionUpdate": "user_message_chunk", "content": {"type": "image", "mimeType": media_type, "data": data}})),
            (Block::Text { text }, Role::Assistant) => peer.update(sid, json!({"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": text}})),
            (Block::ToolUse { id, name, input }, _) => {
                let mut tc = json!({"sessionUpdate": "tool_call", "toolCallId": id, "title": name, "kind": kind_of(name), "status": "completed", "rawInput": input, "locations": locations(input)});
                let d = diff_content(name, input);
                if !d.is_empty() {
                    tc["content"] = json!(d);
                }
                peer.update(sid, tc);
            }
            _ => {}
        }
    }
}

/// `mcpServers` from session/new | load | resume → ark MCP configs. Names are
/// sanitised; servers whose name `[mcp]` already uses (config wins) or that are ark
/// itself are skipped with a warning.
pub fn editor_mcp(servers: &Value, k: &Kernel, cwd: &Path, trusted: bool) -> (BTreeMap<String, McpServerConfig>, Vec<String>) {
    let mut out = BTreeMap::new();
    let mut warn = Vec::new();
    let pairs = |v: &Value| -> BTreeMap<String, String> { v.as_array().into_iter().flatten().filter_map(|e| Some((e["name"].as_str()?.to_string(), e["value"].as_str().unwrap_or("").to_string()))).collect() };
    for s in servers.as_array().into_iter().flatten() {
        let raw = s["name"].as_str().unwrap_or("editor");
        let mut name: String = raw.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).collect();
        while name.contains("__") {
            name = name.replace("__", "_");
        }
        if name.is_empty() {
            name = "editor".into();
        }
        if k.cfg.mcp.contains_key(&name) {
            warn.push(format!("editor MCP server `{raw}`: `[mcp.{name}]` is already configured; using the configured one"));
            continue;
        }
        let mut c = McpServerConfig { trust: (!trusted).then(|| "untrusted".to_string()), roots: vec![cwd.to_path_buf()], ..Default::default() };
        match s["type"].as_str() {
            Some(t @ ("http" | "sse")) => {
                c.url = s["url"].as_str().map(str::to_string);
                c.headers = pairs(&s["headers"]);
                c.transport = Some(t.to_string());
            }
            _ => {
                c.command = s["command"].as_str().map(str::to_string);
                c.args = s["args"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(str::to_string)).collect();
                c.env = pairs(&s["env"]);
                c.cwd = Some(cwd.to_path_buf());
                let me = std::env::current_exe().ok();
                let is_ark = c.command.as_deref().is_some_and(|cmd| cmd == "ark" || me.as_deref().is_some_and(|m| Path::new(cmd).canonicalize().ok().as_deref() == Some(m)));
                if is_ark && c.args.first().map(String::as_str) == Some("mcp") {
                    warn.push(format!("editor MCP server `{raw}` is ark itself; its tools are already built in"));
                    continue;
                }
            }
        }
        match c.validate(&name) {
            Ok(()) => {
                out.insert(name, c);
            }
            Err(e) => warn.push(format!("editor MCP server `{raw}`: {e}")),
        }
    }
    (out, warn)
}

/// Start the editor's MCP servers for `sid` (replacing any it had).
fn attach_mcp(k: &Kernel, peer: &Peer, acp: &AcpConfig, sid: &str, cwd: &Path, servers: &Value) {
    peer.stop_mcp(k, sid);
    if servers.as_array().is_none_or(|a| a.is_empty()) {
        return;
    }
    let (cfgs, mut warn) = editor_mcp(servers, k, cwd, acp.trust_editor_mcp);
    if !cfgs.is_empty() {
        let opts = ark_plugin::LoadOpts { roots: vec![cwd.to_path_buf()], ..Default::default() };
        let reg = Registry::load_with(&cfgs, &k.paths.data.join("mcp-cache"), k.vault_substitute(), &opts);
        warn.extend(reg.warnings().iter().cloned());
        k.set_session_tools(sid, reg.tools());
        peer.mcp.lock().unwrap().insert(sid.to_string(), reg);
    }
    // Editors keep the agent's stderr in their logs.
    for w in warn {
        eprintln!("ark acp: session {sid}: {w}");
    }
}

/// Serve ACP on `input`/`out` until EOF. `slot` receives the peer so the approver can reach it.
pub fn serve(k: Kernel, commands: Vec<(String, String)>, acp: AcpConfig, slot: Arc<OnceLock<Arc<Peer>>>, input: impl BufRead, out: Box<dyn Write + Send>) {
    let peer = Peer::new(out);
    let _ = slot.set(peer.clone());
    let acp = Arc::new(acp);
    // Diffs must be taken before the edit runs; the bus is too late for that.
    let p2 = peer.clone();
    k.add_tap(Arc::new(move |sid: &str, ev: &ark_kernel::event::Event| {
        if let EventKind::ToolCalled { tool_use_id, name, input, .. } = &ev.kind {
            let ws = p2.cwds.lock().unwrap().get(sid).cloned();
            if let Some(ws) = ws.filter(|_| matches!(name.as_str(), "write" | "edit" | "patch" | "apply_patch")) {
                p2.diffs.lock().unwrap().insert(tool_use_id.clone(), edit_diffs(&ws, name, input));
            }
        }
    }));
    for line in input.lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(&line) else {
            peer.send(&json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}}));
            continue;
        };
        // Responses to our own requests.
        if v.get("method").is_none() {
            if let Some(id) = v["id"].as_u64() {
                if let Some(tx) = peer.waiting.lock().unwrap().remove(&id) {
                    let _ = tx.send(v);
                }
            }
            continue;
        }
        let (k, peer, commands, acp) = (k.clone(), peer.clone(), commands.clone(), acp.clone());
        // Prompts run concurrently so cancel and permission answers keep flowing.
        std::thread::spawn(move || {
            let id = v.get("id").cloned();
            let r = handle(&k, &peer, &commands, &acp, v["method"].as_str().unwrap_or(""), &v["params"]);
            if let Some(id) = id {
                peer.send(&match r {
                    Ok(res) => json!({"jsonrpc": "2.0", "id": id, "result": res}),
                    Err((code, msg)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}}),
                });
            }
        });
    }
    // The editor went away: session-owned servers go with it.
    let sids: Vec<String> = peer.mcp.lock().unwrap().keys().cloned().collect();
    for s in sids {
        k.interrupt(&s);
        peer.stop_mcp(&k, &s);
    }
}

fn handle(k: &Kernel, peer: &Arc<Peer>, commands: &[(String, String)], acp: &AcpConfig, method: &str, p: &Value) -> Result<Value, (i64, String)> {
    let sid = || p["sessionId"].as_str().map(str::to_string).ok_or((-32602, "missing sessionId".to_string()));
    let known = |id: &str| if k.store.exists(id) { Ok(()) } else { Err((-32602, format!("unknown session `{id}`"))) };
    let options_changed = |id: &str| peer.update(id, json!({"sessionUpdate": "config_option_update", "configOptions": config_options(k, peer, acp, id)}));
    match method {
        "initialize" => {
            *peer.caps.lock().unwrap() = p["clientCapabilities"].clone();
            // Some editors send an MCP-style date string; answer with ours.
            let asked = p["protocolVersion"].as_u64().unwrap_or(PROTOCOL_VERSION);
            Ok(json!({
                "protocolVersion": asked.min(PROTOCOL_VERSION),
                "agentCapabilities": {
                    "loadSession": true,
                    "promptCapabilities": {"image": true, "audio": false, "embeddedContext": true},
                    "mcpCapabilities": {"http": true, "sse": true},
                    "sessionCapabilities": {"list": {}, "resume": {}, "fork": {}, "close": {}},
                },
                "authMethods": [],
                "agentInfo": {"name": "ark", "title": "ark", "version": env!("CARGO_PKG_VERSION")},
            }))
        }
        "authenticate" => Ok(json!({})),
        "session/new" | "session/fork" => {
            let cwd = p["cwd"].as_str().map(PathBuf::from).unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
            if !cwd.is_absolute() {
                return Err((-32602, "cwd must be an absolute path".into()));
            }
            let parent = if method == "session/fork" { p["sessionId"].as_str() } else { None };
            let model = parent.map(|s| view_of(k, s).model).filter(|m| !m.is_empty());
            let id = k.create_session(&cwd, model.as_deref(), parent, None).map_err(|e| (-32603, e.to_string()))?;
            let mode = parent.map(|s| peer.mode(s)).unwrap_or_else(|| "default".into());
            peer.modes.lock().unwrap().insert(id.clone(), mode);
            peer.cwds.lock().unwrap().insert(id.clone(), cwd.clone());
            attach_mcp(k, peer, acp, &id, &cwd, &p["mcpServers"]);
            let p2 = peer.clone();
            let cmds: Vec<Value> = commands.iter().map(|(n, d)| json!({"name": n, "description": d, "input": {"hint": "arguments"}})).collect();
            let sid2 = id.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                p2.update(&sid2, json!({"sessionUpdate": "available_commands_update", "availableCommands": cmds}));
            });
            let mut r = session_state(k, peer, acp, &id);
            r["sessionId"] = json!(id);
            Ok(r)
        }
        "session/load" | "session/resume" => {
            let id = sid()?;
            known(&id)?;
            let v = view_of(k, &id);
            let cwd = p["cwd"].as_str().map(PathBuf::from).filter(|c| c.is_absolute()).unwrap_or_else(|| PathBuf::from(&v.workspace));
            peer.cwds.lock().unwrap().insert(id.clone(), cwd.clone());
            attach_mcp(k, peer, acp, &id, &cwd, &p["mcpServers"]);
            if method == "session/load" {
                replay(peer, k, &id);
            }
            Ok(session_state(k, peer, acp, &id))
        }
        "session/list" => {
            let cwd = p["cwd"].as_str();
            let list: Vec<Value> = k.store.list().into_iter().filter(|s| cwd.is_none_or(|c| s.workspace == c)).take(100).map(|s| json!({"sessionId": s.id, "cwd": s.workspace, "title": s.title, "updatedAt": rfc3339(s.updated_ms)})).collect();
            Ok(json!({"sessions": list}))
        }
        "session/close" => {
            let id = sid()?;
            k.interrupt(&id);
            peer.stop_mcp(k, &id);
            peer.modes.lock().unwrap().remove(&id);
            peer.cwds.lock().unwrap().remove(&id);
            Ok(json!({}))
        }
        "session/set_mode" => {
            let id = sid()?;
            set_mode(peer, &id, p["modeId"].as_str().unwrap_or(""))?;
            options_changed(&id);
            Ok(json!({}))
        }
        "session/set_model" => {
            let id = sid()?;
            known(&id)?;
            set_model(k, acp, &id, p["modelId"].as_str().unwrap_or(""))?;
            options_changed(&id);
            Ok(json!({}))
        }
        "session/set_config_option" => {
            let id = sid()?;
            known(&id)?;
            let value = match &p["value"] {
                Value::String(s) => s.clone(),
                v => v.to_string(),
            };
            match p["configId"].as_str().unwrap_or("") {
                "mode" => set_mode(peer, &id, &value)?,
                "model" => set_model(k, acp, &id, &value)?,
                "thought_level" => {
                    if !THOUGHT.iter().any(|(t, _)| *t == value) {
                        return Err((-32602, format!("unknown thought level `{value}`")));
                    }
                    busy(k, &id)?;
                    k.set_thinking(&id, if value == "default" { "" } else { &value }).map_err(|e| (-32603, e.to_string()))?;
                }
                c => return Err((-32602, format!("unknown config option `{c}`"))),
            }
            Ok(json!({"configOptions": config_options(k, peer, acp, &id)}))
        }
        "session/cancel" => {
            k.interrupt(&sid()?);
            Ok(json!({}))
        }
        "session/prompt" => {
            let id = sid()?;
            known(&id)?;
            let (text, images) = prompt_content(&p["prompt"]);
            if text.trim().is_empty() && images.is_empty() {
                return Err((-32602, "empty prompt".into()));
            }
            let view = view_of(k, &id);
            let ws = PathBuf::from(&view.workspace);
            let rx = k.bus.subscribe();
            k.submit_with(&id, &text, images, "acp").map_err(|e| (-32603, e.to_string()))?;
            if view.title.is_none() && !k.is_running(&id) {
                let title: String = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("image").trim().chars().take(60).collect();
                if k.set_title(&id, &title).is_ok() {
                    peer.update(&id, json!({"sessionUpdate": "session_info_update", "title": title, "updatedAt": rfc3339(ark_kernel::event::now_ms())}));
                }
            }
            let (done_tx, done_rx) = mpsc::channel();
            let (k2, id2) = (k.clone(), id.clone());
            std::thread::spawn(move || {
                let _ = done_tx.send(k2.run(&id2, RunOpts::default()));
            });
            let mut names: HashMap<String, String> = HashMap::new();
            loop {
                if let Ok(r) = done_rx.try_recv() {
                    for m in rx.try_iter() {
                        forward(peer, &id, &ws, m, &mut names);
                    }
                    return match r {
                        Ok(o) => {
                            peer.update(&id, usage_update(k, &id));
                            Ok(json!({"stopReason": stop_reason(&o.reason)}))
                        }
                        Err(e) => Err((-32603, e.to_string())),
                    };
                }
                if let Ok(m) = rx.recv_timeout(Duration::from_millis(50)) {
                    forward(peer, &id, &ws, m, &mut names);
                }
            }
        }
        m => Err((-32601, format!("method `{m}` not supported"))),
    }
}

fn busy(k: &Kernel, id: &str) -> Result<(), (i64, String)> {
    if k.is_running(id) {
        return Err((-32603, "session is busy; change settings while it is idle".into()));
    }
    Ok(())
}

fn set_mode(peer: &Peer, id: &str, m: &str) -> Result<(), (i64, String)> {
    if !MODES.iter().any(|(x, _, _)| *x == m) {
        return Err((-32602, format!("unknown mode `{m}`")));
    }
    peer.modes.lock().unwrap().insert(id.to_string(), m.into());
    peer.update(id, json!({"sessionUpdate": "current_mode_update", "currentModeId": m}));
    Ok(())
}

fn set_model(k: &Kernel, acp: &AcpConfig, id: &str, m: &str) -> Result<(), (i64, String)> {
    let cur = view_of(k, id).model;
    if !model_ids(k, acp, &cur).iter().any(|x| x == m) {
        return Err((-32602, format!("unknown model `{m}`; pick one of the session's available models")));
    }
    let (pid, _) = ark_kernel::context::split_model(m);
    k.resolver.provider(pid).map_err(|e| (-32602, format!("{m}: {e}")))?;
    busy(k, id)?;
    k.set_model(id, m).map_err(|e| (-32603, e.to_string()))
}

fn forward(peer: &Peer, sid: &str, ws: &Path, m: BusMsg, names: &mut HashMap<String, String>) {
    match m {
        BusMsg::Delta { session, text, thinking } if session == sid => {
            peer.update(sid, json!({"sessionUpdate": if thinking { "agent_thought_chunk" } else { "agent_message_chunk" }, "content": {"type": "text", "text": text}}));
        }
        BusMsg::Event { session, event } if session == sid => match event.kind {
            EventKind::ToolCalled { tool_use_id, name, input, .. } => {
                let mut tc = json!({"sessionUpdate": "tool_call", "toolCallId": tool_use_id, "title": name, "kind": kind_of(&name), "status": "in_progress", "rawInput": input, "locations": locations(&input)});
                let d = peer.diffs.lock().unwrap().remove(&tool_use_id).unwrap_or_else(|| edit_diffs(ws, &name, &input));
                if !d.is_empty() {
                    tc["content"] = json!(d);
                }
                names.insert(tool_use_id, name);
                peer.update(sid, tc);
            }
            EventKind::Message { message, .. } if message.role == Role::User => {
                // Tool results arrive as a user message; report them on their tool calls.
                for b in &message.content {
                    if let Block::ToolResult { tool_use_id, content, is_error } = b {
                        let short: String = content.chars().take(4000).collect();
                        let mut u = json!({"sessionUpdate": "tool_call_update", "toolCallId": tool_use_id, "status": if *is_error { "failed" } else { "completed" }});
                        // Keep an edit's diff on screen; other tools show their output.
                        if !matches!(names.get(tool_use_id).map(String::as_str), Some("edit" | "write" | "patch")) || *is_error {
                            u["content"] = json!([{"type": "content", "content": {"type": "text", "text": short}}]);
                        }
                        peer.update(sid, u);
                        if names.get(tool_use_id).map(String::as_str) == Some("todo") {
                            if let Some(plan) = plan_from_todo(content) {
                                peer.update(sid, plan);
                            }
                        }
                    }
                }
            }
            EventKind::Notice { level, text } => peer.update(sid, json!({"sessionUpdate": "agent_thought_chunk", "content": {"type": "text", "text": format!("[{level}] {text}\n")}})),
            _ => {}
        },
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_diffs_plans_and_prompts() {
        assert_eq!(kind_of("edit"), "edit");
        assert_eq!(kind_of("shell"), "execute");
        assert_eq!(kind_of("grep"), "search");
        let d = diff_content("patch", &json!({"edits": [{"path": "a", "old_string": "x", "new_string": "y"}]}));
        assert_eq!(d[0]["newText"], "y");
        let p = plan_from_todo("[x] 1. read\n[>] 2. write\n[ ] 3. test\n1/3 done").unwrap();
        assert_eq!(p["entries"].as_array().unwrap().len(), 3);
        assert_eq!(p["entries"][1]["status"], "in_progress");
        assert_eq!(p["entries"][1]["content"], "write");
        let (t, imgs) = prompt_content(&json!([{"type": "text", "text": "fix"}, {"type": "resource", "resource": {"uri": "file:///a.rs", "text": "fn a(){}"}}, {"type": "resource_link", "uri": "file:///b", "name": "b"}, {"type": "image", "mimeType": "image/png", "data": "AAAA"}, {"type": "image", "mimeType": "image/png", "uri": "https://x/y.png"}]));
        assert!(t.contains("fix") && t.contains("<context uri=\"file:///a.rs\">") && t.contains("[Resource link (b)] file:///b") && t.contains("https://x/y.png"), "{t}");
        assert_eq!(imgs, vec![Block::Image { media_type: "image/png".into(), data: "AAAA".into() }]);
        assert_eq!(stop_reason(&EndReason::Interrupted), "cancelled");
        assert_eq!(rfc3339(86_400_000 + 3_723_000), "1970-01-02T01:02:03Z");
    }

    #[test]
    fn edit_diffs_use_whole_files() {
        let d = std::env::temp_dir().join(format!("ark-acp-diff-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("a.rs"), "fn a() {}\nfn b() {}\n").unwrap();
        let v = edit_diffs(&d, "edit", &json!({"path": "a.rs", "old_string": "fn b() {}", "new_string": "fn b() { 1 }"}));
        assert_eq!(v[0]["oldText"], "fn a() {}\nfn b() {}\n");
        assert_eq!(v[0]["newText"], "fn a() {}\nfn b() { 1 }\n");
        assert!(v[0]["path"].as_str().unwrap().ends_with("a.rs"));
        let v = edit_diffs(&d, "write", &json!({"path": "new.txt", "content": "hi"}));
        assert!(v[0]["oldText"].is_null() && v[0]["newText"] == "hi");
        let v = edit_diffs(&d, "edit", &json!({"path": "missing.rs", "old_string": "x", "new_string": "y"}));
        assert_eq!(v[0]["oldText"], "x", "falls back to the snippet");
        assert!(edit_diffs(&d, "read", &json!({"path": "a.rs"})).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }
}
