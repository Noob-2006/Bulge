//! Meta Muse Code CLI as a runtime (`muse serve`, MSP JSON-RPC over stdio): OpenClaw
//! `extensions/muse` (`src/runtime.ts`, `src/events.ts`) and the protocol schema
//! `@muse-code/sdk/dist/src/msp.d.ts`. One long-lived child per provider instance:
//! `initialize` → `session/start` (one per conversation, `sessionId` remembered) →
//! `turn/start`, streaming `item/delta` / `item/completed`, usage from
//! `session/tokenUsage`, done at `turn/completed`. Approvals are answered so the child
//! never blocks (see [`Muse::new`]); Muse runs its own tools, so seagent's tool schemas stay
//! out of the wire (`caps.tools = false`, like `codex_app`).
//!
//! Conversation identity: the kernel hands us a transcript and no conversation id, so a
//! session is remembered under a digest of (model, system prompt, first user message) —
//! [`conversation_key`]. A changed digest opens a new Muse session on the same child.

use crate::{finalize_usage, ProviderConfig};
use seagent_core::*;
use serde_json::{json, Value};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT_SECS: u64 = 900;

pub struct Muse {
    id: String,
    command: String,
    args: Vec<String>,
    /// `workspaceRoot` for every session (= the child's cwd).
    cwd: PathBuf,
    /// The MSP `approvalMode` (`allowAll` | `promptUnmatched` | `denyUnmatched`); also
    /// decides how an `approval/requested` the server still raises is answered.
    approval: String,
    timeout: Duration,
    host: Mutex<Option<Host>>,
}

impl Muse {
    /// `quirks` select the server-side approval mode: `approve_all` → `allowAll`,
    /// `deny_all` → `denyUnmatched`, otherwise `promptUnmatched`. seagent has no interactive
    /// approval surface inside a model turn, so a request the server still raises is
    /// answered per that mode: `allowAll`/`promptUnmatched` approve once (the kernel's
    /// own policy already vetted the command), `denyUnmatched` denies.
    pub fn new(cfg: &ProviderConfig) -> Result<Muse, String> {
        let cwd =
            std::env::current_dir().map_err(|e| format!("provider `{}`: cwd: {e}", cfg.id))?;
        let approval = if cfg.has_quirk("approve_all") {
            "allowAll"
        } else if cfg.has_quirk("deny_all") {
            "denyUnmatched"
        } else {
            "promptUnmatched"
        };
        Ok(Muse {
            id: cfg.id.clone(),
            command: cfg
                .command
                .clone()
                .filter(|c| !c.is_empty())
                .unwrap_or_else(|| "muse".into()),
            args: if cfg.args.is_empty() {
                vec!["serve".into()]
            } else {
                cfg.args.clone()
            },
            cwd,
            approval: approval.to_string(),
            timeout: Duration::from_secs(
                cfg.idle_timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS).max(1),
            ),
            host: Mutex::new(None),
        })
    }

    fn spawn(&self) -> Result<Host, ProviderError> {
        let mut child = crate::auth::program(&self.command)
            .args(&self.args)
            .current_dir(&self.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                ProviderError::new(
                    ProviderErrorKind::Network,
                    format!(
                        "{}: cannot start Muse (`{}`): {e} (install Muse Code and run `muse login`)",
                        self.id, self.command
                    ),
                )
            })?;
        let stdin = child.stdin.take().unwrap();
        let out = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for l in BufReader::new(out).lines().map_while(Result::ok) {
                match serde_json::from_str::<Value>(&l) {
                    Ok(v) => {
                        if tx.send(v).is_err() {
                            break;
                        }
                    }
                    // Muse may print progress lines on stdout; a non-JSON line is noise.
                    Err(_) => continue,
                }
            }
        });
        Ok(Host {
            child,
            stdin,
            rx,
            next: 0,
            session: None,
        })
    }

    /// `initialize` on a fresh child (single-shot: the child lives for the whole instance).
    fn handshake(
        &self,
        host: &mut Host,
        deadline: Instant,
        cancel: &Cancel,
    ) -> Result<(), ProviderError> {
        let id = host.request(
            "initialize",
            json!({"clientInfo": {"name": "seagent", "version": env!("CARGO_PKG_VERSION")}}),
        )?;
        let mut sink = |h: &mut Host, v: Value| -> Result<bool, ProviderError> {
            serve_request(h, &v, &self.approval)?;
            Ok(false)
        };
        host.wait(id, deadline, cancel, &mut sink)?;
        Ok(())
    }

    /// `session/start` for a new conversation; returns the session id.
    fn open_session(
        &self,
        host: &mut Host,
        req: &ModelRequest,
        deadline: Instant,
        cancel: &Cancel,
    ) -> Result<String, ProviderError> {
        let mut params = json!({
            "commandId": command_id(),
            "workspaceRoot": self.cwd.to_string_lossy(),
            "providerId": "meta",
            "approvalMode": self.approval,
        });
        if !req.model.is_empty() && req.model != "default" {
            params["modelId"] = req.model.clone().into();
        }
        let id = host.request("session/start", params)?;
        let mut sink = |h: &mut Host, v: Value| -> Result<bool, ProviderError> {
            serve_request(h, &v, &self.approval)?;
            Ok(false)
        };
        let r = host.wait(id, deadline, cancel, &mut sink)?;
        r["session"]["sessionId"]
            .as_str()
            .or(r["sessionId"].as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .ok_or_else(|| {
                ProviderError::new(
                    ProviderErrorKind::Protocol,
                    "Muse session/start returned no sessionId",
                )
            })
    }

    /// One turn on an open session.
    fn turn(
        &self,
        host: &mut Host,
        req: &ModelRequest,
        on_event: &mut dyn FnMut(StreamEvent),
        cancel: &Cancel,
    ) -> Result<ModelResponse, ProviderError> {
        let deadline = Instant::now() + self.timeout;
        let key = conversation_key(req);
        let fresh = host.session.as_ref().is_none_or(|(k, _)| *k != key);
        let session_id = if fresh {
            let sid = self.open_session(host, req, deadline, cancel)?;
            host.session = Some((key, sid.clone()));
            sid
        } else {
            host.session.as_ref().unwrap().1.clone()
        };

        let mut params = json!({
            "sessionId": session_id,
            "commandId": command_id(),
            "ifBusy": "queue",
            "input": turn_input(req, fresh),
        });
        if let Some(e) = req.reasoning.as_deref().and_then(|r| {
            crate::reasoning::clamp(
                r,
                &["none", "minimal", "low", "medium", "high", "xhigh", "max"],
            )
        }) {
            params["reasoningEffort"] = e.into();
        }
        let id = host.request("turn/start", params)?;
        let ack = {
            let mut sink = |h: &mut Host, v: Value| -> Result<bool, ProviderError> {
                serve_request(h, &v, &self.approval)?;
                Ok(false)
            };
            host.wait(id, deadline, cancel, &mut sink)?
        };
        let turn_id = ack["turnId"].as_str().unwrap_or_default().to_string();
        if ack["status"].as_str().is_some_and(|s| s != "accepted") {
            return Err(ProviderError::new(
                ProviderErrorKind::Server,
                format!("Muse refused the turn: {}", ack["status"]),
            ));
        }

        let mut state = Turn::default();
        loop {
            let v = match host.recv(deadline, cancel) {
                Ok(v) => v,
                // A cancelled turn: ask the runtime to stop before the connection dies.
                Err(e) if e.kind == ProviderErrorKind::Cancelled => {
                    let _ = host.request(
                        "turn/interrupt",
                        json!({
                            "sessionId": session_id,
                            "commandId": command_id(),
                            "turnId": turn_id,
                        }),
                    );
                    return Err(e);
                }
                Err(e) => return Err(e),
            };
            if state.handle(host, &v, &turn_id, &self.approval, on_event)? {
                break;
            }
        }
        if let Some(failed) = state.failed {
            let kind = if failed.to_lowercase().contains("rate limit") {
                ProviderErrorKind::RateLimited { retry_after: None }
            } else {
                ProviderErrorKind::Server
            };
            return Err(ProviderError::new(kind, format!("muse: {failed}")));
        }
        let mut content = Vec::new();
        if !state.reasoning.is_empty() {
            content.push(Block::Thinking {
                text: state.reasoning,
                signature: None,
            });
        }
        let text = state.final_text.unwrap_or(state.text);
        if !text.is_empty() {
            content.push(Block::Text { text });
        }
        let message = Message {
            role: Role::Assistant,
            content,
        };
        let usage = finalize_usage(state.usage, req, &message);
        let model = if req.model.is_empty() {
            "default"
        } else {
            req.model.as_str()
        };
        Ok(ModelResponse {
            message,
            stop: StopReason::EndTurn,
            usage,
            model: format!("{}/{}", self.id, model),
        })
    }
}

impl Provider for Muse {
    fn id(&self) -> &str {
        &self.id
    }
    fn caps(&self, model: &str) -> ModelCaps {
        ModelCaps {
            tools: false,
            ..crate::caps_for(model)
        }
    }
    fn complete(
        &self,
        req: &ModelRequest,
        on_event: &mut dyn FnMut(StreamEvent),
        cancel: &Cancel,
    ) -> Result<ModelResponse, ProviderError> {
        let mut guard = self.host.lock().unwrap_or_else(|e| e.into_inner());
        let fresh = guard.is_none();
        if fresh {
            *guard = Some(self.spawn()?);
        }
        let out = {
            let host = guard.as_mut().unwrap();
            let deadline = Instant::now() + self.timeout;
            // `initialize` is once per connection: a live child is already initialized.
            let ready = if fresh {
                self.handshake(host, deadline, cancel)
            } else {
                Ok(())
            };
            ready.and_then(|_| self.turn(host, req, on_event, cancel))
        };
        if out.is_err() {
            // Whatever went wrong, the child's session state is unknown: kill it so the
            // next call starts a fresh `initialize` + `session/start`.
            *guard = None;
        }
        out
    }
}

impl Drop for Muse {
    fn drop(&mut self) {
        if let Ok(host) = self.host.get_mut() {
            *host = None; // Host::drop kills the child
        }
    }
}

struct Host {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<Value>,
    next: u64,
    /// (conversation digest, sessionId) of the open Muse session.
    session: Option<(u64, String)>,
}

impl Host {
    fn send(&mut self, v: &Value) -> Result<(), ProviderError> {
        writeln!(self.stdin, "{v}")
            .and_then(|_| self.stdin.flush())
            .map_err(|e| {
                ProviderError::new(
                    ProviderErrorKind::Network,
                    format!("muse stdin: {e} (is the child still running?)"),
                )
            })
    }
    fn request(&mut self, method: &str, params: Value) -> Result<u64, ProviderError> {
        self.next += 1;
        let id = self.next;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        Ok(id)
    }
    /// Wait for the response to `id`, handing notifications and server→client requests to
    /// `on` meanwhile.
    fn wait(
        &mut self,
        id: u64,
        deadline: Instant,
        cancel: &Cancel,
        on: &mut dyn FnMut(&mut Host, Value) -> Result<bool, ProviderError>,
    ) -> Result<Value, ProviderError> {
        loop {
            let v = self.recv(deadline, cancel)?;
            if v.get("method").is_none() && v["id"].as_u64() == Some(id) {
                if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
                    return Err(rpc_error("request", e));
                }
                return Ok(v["result"].clone());
            }
            on(self, v)?;
        }
    }
    fn recv(&mut self, deadline: Instant, cancel: &Cancel) -> Result<Value, ProviderError> {
        loop {
            if cancel.is_cancelled() {
                return Err(ProviderError::new(
                    ProviderErrorKind::Cancelled,
                    "cancelled",
                ));
            }
            if Instant::now() > deadline {
                return Err(ProviderError::new(
                    ProviderErrorKind::Timeout,
                    "Muse turn timed out waiting for the runtime",
                ));
            }
            match self.rx.recv_timeout(Duration::from_millis(50)) {
                Ok(v) => return Ok(v),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if self.child.try_wait().is_ok_and(|s| s.is_some()) {
                        return Err(ProviderError::new(
                            ProviderErrorKind::Network,
                            "Muse exited (run `muse login` on this host?)",
                        ));
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(ProviderError::new(
                        ProviderErrorKind::Network,
                        "Muse exited while a turn was running",
                    ))
                }
            }
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Default)]
struct Turn {
    text: String,
    reasoning: String,
    /// Authoritative final text from `item/completed`.
    final_text: Option<String>,
    usage: Option<Usage>,
    /// itemId → `Item.kind` for the items currently open.
    kinds: HashMap<String, String>,
    /// itemIds that already streamed reasoning (a completed item must not re-emit it).
    streamed: HashSet<String>,
    failed: Option<String>,
}

impl Turn {
    /// Fold one frame; `Ok(true)` when the turn is over.
    fn handle(
        &mut self,
        host: &mut Host,
        v: &Value,
        turn_id: &str,
        approval: &str,
        on_event: &mut dyn FnMut(StreamEvent),
    ) -> Result<bool, ProviderError> {
        let Some(method) = v["method"].as_str().filter(|m| !m.is_empty()) else {
            // A late response to one of our commands (e.g. `approval/decide`).
            return Ok(false);
        };
        // Server→client requests and the approval lane (notification or request).
        if v.get("id").is_some() || method.starts_with("approval/") {
            return serve_request(host, v, approval);
        }
        let p = &v["params"];
        match method {
            "item/started" | "item/updated" | "item/completed" => {
                let item = &p["item"];
                let item_id = item["itemId"]
                    .as_str()
                    .or(p["itemId"].as_str())
                    .unwrap_or_default()
                    .to_string();
                let kind = item["kind"].as_str().unwrap_or_default().to_string();
                if !item_id.is_empty() && !kind.is_empty() {
                    self.kinds.insert(item_id.clone(), kind.clone());
                }
                if method != "item/completed" {
                    return Ok(false);
                }
                match kind.as_str() {
                    "agentMessage" => {
                        // Several agent messages around tool calls: keep them all.
                        let t = item["text"].as_str().unwrap_or_default();
                        let acc = self.final_text.get_or_insert_with(String::new);
                        if !t.is_empty() {
                            if !acc.is_empty() {
                                acc.push('\n');
                            }
                            acc.push_str(t);
                        }
                    }
                    // `reasoning.text` is never streamed in v1: emit it once, here.
                    "reasoning" if !self.streamed.contains(&item_id) => {
                        if let Some(t) = item["text"].as_str().filter(|t| !t.is_empty()) {
                            self.reasoning.push_str(t);
                            on_event(StreamEvent::ThinkingDelta(t.to_string()));
                        }
                    }
                    _ => {}
                }
            }
            "item/delta" => {
                let d = p["delta"].as_str().unwrap_or_default();
                if d.is_empty() {
                    return Ok(false);
                }
                let item_id = p["itemId"].as_str().unwrap_or_default();
                let field = p["field"].as_str().unwrap_or("text");
                let kind = self.kinds.get(item_id).map(String::as_str).unwrap_or("");
                let reasoning_field = field == "text" || field.starts_with("summary.");
                match kind {
                    // An item we never saw `item/started` for: `text` is the reply.
                    "" | "agentMessage" if field == "text" => {
                        self.text.push_str(d);
                        on_event(StreamEvent::TextDelta(d.to_string()));
                    }
                    "" | "reasoning" if reasoning_field => {
                        self.streamed.insert(item_id.to_string());
                        self.reasoning.push_str(d);
                        on_event(StreamEvent::ThinkingDelta(d.to_string()));
                    }
                    // `toolCall` output and everything else the runtime streams is its own
                    // business; seagent does not surface it as assistant text.
                    _ => {}
                }
            }
            "session/tokenUsage" => {
                self.usage = Some(usage_from(p));
            }
            "turn/completed" => {
                let same = p["turnId"]
                    .as_str()
                    .is_none_or(|t| turn_id.is_empty() || t == turn_id);
                if !same {
                    return Ok(false);
                }
                match p["terminal"].as_str().unwrap_or("completed") {
                    "completed" => {}
                    "cancelled" => {
                        self.failed = Some("turn cancelled by the runtime".into());
                    }
                    _ => {
                        self.failed = Some(
                            p["error"]["message"]
                                .as_str()
                                .unwrap_or("Muse turn failed")
                                .to_string(),
                        );
                    }
                }
                return Ok(true);
            }
            // `turn/started`, `turn/foregroundCompleted` (Muse's own background reminder
            // work), `session/statusChanged`, `approval/resolved`… need no action.
            _ => {}
        }
        Ok(false)
    }
}

/// Answer a server→client `approval/requested` per the approval mode — as a notification
/// (send the decision) or as a request (decide and answer it too). Anything seagent does not
/// implement gets a JSON-RPC `-32601`, so the child never blocks on us.
fn serve_request(host: &mut Host, v: &Value, approval: &str) -> Result<bool, ProviderError> {
    let Some(method) = v["method"].as_str() else {
        return Ok(false);
    };
    let id = v.get("id").cloned();
    let approve = approval != "denyUnmatched";
    if method == "approval/requested" || method == "approval/request" {
        let p = &v["params"];
        let want = if approve {
            ["approved", "approvedForSession"]
        } else {
            ["denied", "abort"]
        };
        let choice = p["availableChoices"]
            .as_array()
            .and_then(|cs| {
                want.iter()
                    .find_map(|w| cs.iter().find(|c| c["decision"].as_str() == Some(*w)))
            })
            .or_else(|| p["availableChoices"].as_array().and_then(|cs| cs.first()))
            .and_then(|c| c["choiceId"].as_str());
        if let Some(choice_id) = choice {
            let command_id = command_id();
            host.request(
                "approval/decide",
                json!({
                    "sessionId": p["sessionId"],
                    "approvalId": p["approvalId"],
                    "choiceId": choice_id,
                    "commandId": command_id,
                    "requirementId": p["currentRequirementId"],
                }),
            )?;
            if let Some(id) = id {
                // The command's own ack (`ApprovalDecideResult`) arrives later; answer the
                // request now with the same admission shape.
                host.send(&json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "approvalId": p["approvalId"],
                        "commandId": command_id,
                        "status": "accepted",
                        "terminal": true,
                    },
                }))?;
            }
            return Ok(false);
        }
    }
    if let Some(id) = id {
        host.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32601, "message": format!("{method} not supported by seagent")},
        }))?;
    }
    Ok(false)
}

fn rpc_error(what: &str, e: &Value) -> ProviderError {
    let msg = e["message"].as_str().unwrap_or("JSON-RPC error");
    let l = msg.to_lowercase();
    let kind = if l.contains("rate limit") || l.contains("429") {
        ProviderErrorKind::RateLimited { retry_after: None }
    } else if l.contains("overload") || l.contains("backpressure") || l.contains("busy") {
        ProviderErrorKind::Overloaded
    } else {
        ProviderErrorKind::BadRequest
    };
    ProviderError::new(kind, format!("muse {what}: {msg}"))
}

/// Usage from `session/tokenUsage`: the counted-once `promptTokens` (minus the cache-read
/// share seagent bills separately) plus the raw counters.
fn usage_from(p: &Value) -> Usage {
    let u = &p["usage"];
    let cached = u["cachedTokens"]
        .as_u64()
        .or_else(|| u["cacheReadTokens"].as_u64())
        .unwrap_or(0);
    let prompt = p["promptTokens"]
        .as_u64()
        .or_else(|| u["inputTokens"].as_u64())
        .unwrap_or(0);
    Usage {
        input_tokens: prompt.saturating_sub(cached),
        output_tokens: u["outputTokens"]
            .as_u64()
            .or_else(|| p["totalTokens"].as_u64().map(|t| t.saturating_sub(prompt)))
            .unwrap_or(0),
        cache_read_tokens: cached,
        cache_write_tokens: u["cacheWriteTokens"].as_u64().unwrap_or(0),
        estimated: false,
    }
}

/// Session digest: model + system prompt + first user message (see the module docs).
fn conversation_key(req: &ModelRequest) -> u64 {
    let mut h = DefaultHasher::new();
    req.model.hash(&mut h);
    req.system
        .iter()
        .map(|s| s.text.as_str())
        .collect::<String>()
        .hash(&mut h);
    req.messages
        .iter()
        .find(|m| m.role == Role::User)
        .map(|m| m.text())
        .unwrap_or_default()
        .hash(&mut h);
    h.finish()
}

/// The rendered prompt: the last message alone, else the whole transcript (as
/// `codex_app` does). The system prompt only rides the first turn of a session, since
/// the Muse session keeps its own history.
fn turn_input(req: &ModelRequest, fresh: bool) -> Value {
    let mut prompt = if req.messages.len() == 1 {
        req.messages[0].text()
    } else {
        format!(
            "<conversation>\n{}</conversation>\n\nReply to the last User message.",
            crate::transcript(req)
        )
    };
    let sys = req.system_text();
    if fresh && !sys.is_empty() {
        prompt = format!("{sys}\n\n{prompt}");
    }
    let mut parts = vec![json!({"type": "text", "text": prompt})];
    // Images from the newest user message travel as their own parts.
    if let Some(m) = req.messages.iter().rev().find(|m| m.role == Role::User) {
        for b in &m.content {
            if let Block::Image { media_type, data } = b {
                parts.push(json!({"type": "image", "mediaType": media_type, "base64Data": data}));
            }
        }
    }
    Value::Array(parts)
}

/// A syntactically valid UUIDv7 (MSP's idempotency handle): 48-bit ms timestamp, version
/// and variant bits set, the rest from a counter-mixed xorshift.
fn command_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut x = (SEQ.fetch_add(1, Ordering::Relaxed) << 24)
        ^ ((std::process::id() as u64) << 40)
        ^ ms
        ^ 0x9E37_79B9_7F4A_7C15;
    let mut b = [0u8; 16];
    b[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
    for slot in b.iter_mut().skip(6) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *slot = x as u8;
    }
    b[6] = 0x70 | (b[6] & 0x0f);
    b[8] = 0x80 | (b[8] & 0x3f);
    let hex: String = b.iter().map(|v| format!("{v:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake `muse serve`: MSP over stdin/stdout. The scenario is chosen by `SCENARIO`
    /// baked into each script so one file serves the whole suite.
    const FAKE: &str = r#"import json, sys
scenario = sys.argv[1]
sid = "sess-1"
starts = 0
inits = 0
decisions = []

def out(o):
    print(json.dumps(o), flush=True)

def item(kind, text, item_id="i1", delta=False, field="text"):
    if delta:
        return {"jsonrpc": "2.0", "method": "item/delta",
                "params": {"sessionId": sid, "itemId": item_id, "field": field, "delta": text, "viewCursor": "c2"}}
    return {"jsonrpc": "2.0", "method": "item/completed",
            "params": {"sessionId": sid, "item": {"itemId": item_id, "kind": kind, "text": text,
                                                  "revision": 2, "status": "completed"},
                       "sourceRange": {}, "viewCursor": "c3"}}

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    m = json.loads(line)
    meth, mid, p = m.get("method"), m.get("id"), m.get("params") or {}
    if meth == "initialize":
        inits += 1
        assert inits == 1, "initialize is once per connection"
        out({"jsonrpc": "2.0", "id": mid, "result": {"serverInfo": {"name": "fake-muse"}, "userAgent": "fake"}})
    elif meth == "session/start":
        starts += 1
        assert p["providerId"] == "meta", p
        assert p["approvalMode"] in ("allowAll", "promptUnmatched", "denyUnmatched"), p
        assert p["workspaceRoot"], p
        out({"jsonrpc": "2.0", "id": mid, "result": {"session": {"sessionId": sid, "modelId": p.get("modelId")}, "viewCursor": "c1"}})
    elif meth == "turn/start":
        assert p["sessionId"] == sid, p
        assert starts == 1, "a second turn must reuse the session"
        out({"jsonrpc": "2.0", "id": mid, "result": {"commandId": p["commandId"], "turnId": "t1",
                                                     "status": "accepted", "disposition": "started", "startedNewTurn": True}})
        out({"jsonrpc": "2.0", "method": "turn/started", "params": {"sessionId": sid, "turnId": "t1", "viewCursor": "c2"}})
        out({"jsonrpc": "2.0", "method": "item/started",
             "params": {"sessionId": sid, "item": {"itemId": "i1", "kind": "agentMessage", "revision": 1,
                                                   "status": "inProgress"}, "viewCursor": "c2"}})
        if scenario == "timeout":
            continue
        if scenario == "unknown-request":
            out({"jsonrpc": "2.0", "id": 77, "method": "view/subscribe", "params": {"sessionId": sid}})
            continue
        if scenario == "approval":
            out({"jsonrpc": "2.0", "method": "approval/requested",
                 "params": {"approvalId": "ap1", "sessionId": sid, "turnId": "t1", "itemId": "i1",
                            "toolName": "shell", "subject": {"kind": "shell", "command": "ls"},
                            "currentRequirementId": {"approvalId": "ap1", "sourceIndex": 0},
                            "availableChoices": [
                                {"choiceId": "yes", "decision": "approved", "scope": "once", "label": "Allow"},
                                {"choiceId": "no", "decision": "denied", "scope": "once", "label": "Deny"}],
                            "viewCursor": "c3"}})
            continue
        for d in ["Hel", "lo"]:
            out(item("agentMessage", d, delta=True))
        out(item("agentMessage", "Hello"))
        out({"jsonrpc": "2.0", "method": "session/tokenUsage",
             "params": {"sessionId": sid, "turnId": "t1", "promptTokens": 20, "totalTokens": 25,
                        "usage": {"inputTokens": 20, "cachedTokens": 8, "cacheReadTokens": 8,
                                  "outputTokens": 5, "reasoningTokens": 0},
                        "cumulative": {"promptTokens": 20, "outputTokens": 5}, "sourceRange": {},
                        "viewCursor": "c4"}})
        out({"jsonrpc": "2.0", "method": "turn/completed",
             "params": {"sessionId": sid, "turnId": "t1", "terminal": "completed",
                        "sourceRange": {}, "viewCursor": "c5"}})
    elif meth == "approval/decide":
        decisions.append(p["choiceId"])
        out({"jsonrpc": "2.0", "id": mid, "result": {"approvalId": p["approvalId"],
                                                     "commandId": p["commandId"],
                                                     "status": "accepted", "terminal": True}})
        out(item("agentMessage", "decided:" + p["choiceId"], delta=True))
        out(item("agentMessage", "decided:" + p["choiceId"]))
        out({"jsonrpc": "2.0", "method": "turn/completed",
             "params": {"sessionId": sid, "turnId": "t1", "terminal": "completed",
                        "sourceRange": {}, "viewCursor": "c5"}})
    elif meth == "turn/interrupt":
        out({"jsonrpc": "2.0", "id": mid, "result": {"commandId": p["commandId"], "status": "accepted", "turnId": "t1"}})
    elif mid is not None and m.get("error"):
        # The client refused a server→client request: report the code as the answer.
        code = "error:%d" % m["error"]["code"]
        out(item("agentMessage", code, delta=True))
        out(item("agentMessage", code))
        out({"jsonrpc": "2.0", "method": "turn/completed",
             "params": {"sessionId": sid, "turnId": "t1", "terminal": "completed",
                        "sourceRange": {}, "viewCursor": "c6"}})
"#;

    fn provider(scenario: &str, quirks: Vec<String>, timeout: u64) -> Muse {
        let d = seagent_core::tmp::scratch_path(format!("seagent-muse-{}-{}", std::process::id(), scenario));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("fake_muse.py");
        std::fs::write(&f, FAKE).unwrap();
        Muse::new(&ProviderConfig {
            id: "muse-code".into(),
            format: crate::WireFormat::Muse,
            command: Some("python3".into()),
            args: vec![
                "-I".into(),
                f.to_string_lossy().into_owned(),
                scenario.to_string(),
            ],
            quirks,
            idle_timeout_secs: Some(timeout),
            ..Default::default()
        })
        .unwrap()
    }

    fn req(user: &str) -> ModelRequest {
        ModelRequest {
            model: "muse-spark-1.3".into(),
            system: vec![SystemSegment {
                id: "s".into(),
                text: "be brief".into(),
                cache: false,
            }],
            messages: vec![Message::user(user)],
            max_tokens: 512,
            ..Default::default()
        }
    }

    #[test]
    fn drives_a_turn_and_reports_usage() {
        let p = provider("text", vec![], 30);
        let mut evs = Vec::new();
        let r = p
            .complete(&req("hi"), &mut |e| evs.push(e), &Cancel::new())
            .unwrap();
        assert_eq!(
            evs,
            vec![
                StreamEvent::TextDelta("Hel".into()),
                StreamEvent::TextDelta("lo".into())
            ]
        );
        assert_eq!(r.message.text(), "Hello");
        assert_eq!(r.stop, StopReason::EndTurn);
        assert_eq!(
            (
                r.usage.input_tokens,
                r.usage.cache_read_tokens,
                r.usage.output_tokens
            ),
            (12, 8, 5)
        );
        assert_eq!(r.model, "muse-code/muse-spark-1.3");

        // A second turn on the same conversation reuses the child and the session (the
        // fake asserts `session/start` ran exactly once).
        let mut next = req("hi");
        next.messages.push(Message::assistant("Hello"));
        next.messages.push(Message::user("again"));
        assert_eq!(
            p.complete(&next, &mut |_| {}, &Cancel::new())
                .unwrap()
                .message
                .text(),
            "Hello"
        );
        assert!(!p.caps("muse-spark-1.3").tools);
    }

    #[test]
    fn answers_approval_requests() {
        let p = provider("approval", vec![], 30);
        let r = p
            .complete(&req("rm something"), &mut |_| {}, &Cancel::new())
            .unwrap();
        assert_eq!(r.message.text(), "decided:yes");
        // `deny_all` flips the same request to the deny choice.
        let p = provider("approval", vec!["deny_all".into()], 30);
        let r = p
            .complete(&req("rm something"), &mut |_| {}, &Cancel::new())
            .unwrap();
        assert_eq!(r.message.text(), "decided:no");
    }

    #[test]
    fn unknown_server_requests_get_minus_32601() {
        let p = provider("unknown-request", vec![], 5);
        let r = p.complete(&req("hi"), &mut |_| {}, &Cancel::new()).unwrap();
        assert_eq!(r.message.text(), "error:-32601");
    }

    #[test]
    fn a_silent_runtime_times_out_and_the_next_call_respawns() {
        let p = provider("timeout", vec![], 1);
        let t = Instant::now();
        let err = p
            .complete(&req("hi"), &mut |_| {}, &Cancel::new())
            .unwrap_err();
        assert_eq!(err.kind, ProviderErrorKind::Timeout, "{err}");
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
        // The dead child was reaped: the next call starts a fresh `initialize`.
        assert!(p.host.lock().unwrap().is_none());
    }

    #[test]
    fn cancellation_interrupts_the_turn() {
        let p = std::sync::Arc::new(provider("timeout", vec![], 30));
        let cancel = std::sync::Arc::new(Cancel::new());
        let fire = std::sync::Arc::clone(&cancel);
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            fire.cancel();
        });
        let err = p.complete(&req("hi"), &mut |_| {}, &cancel).unwrap_err();
        handle.join().unwrap();
        assert_eq!(err.kind, ProviderErrorKind::Cancelled, "{err}");
    }

    #[test]
    fn command_ids_are_uuid_shaped() {
        let id = command_id();
        assert_eq!(id.len(), 36, "{id}");
        assert_eq!(id.as_bytes()[14], b'7', "{id}");
        assert!(
            matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b'),
            "{id}"
        );
        assert_ne!(id, command_id());
    }
}
