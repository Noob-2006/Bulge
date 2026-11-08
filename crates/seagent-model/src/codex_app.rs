//! `codex app-server` as a runtime (Hermes `agent/codex_runtime.py`,
//! `transports/codex_app_server*.py`; OpenClaw `extensions/codex`): JSON-RPC over stdio —
//! `initialize` → `thread/start` → `turn/start`, streaming `item/agentMessage/delta`,
//! usage from `thread/tokenUsage/updated`, done at `turn/completed`. Codex runs its own
//! tools; command/file approvals are declined unless `quirks = ["approve_all"]`.

use crate::{finalize_usage, ProviderConfig};
use seagent_core::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

pub struct AppServer {
    id: String,
    command: String,
    args: Vec<String>,
    approve: bool,
    timeout: Duration,
}

impl AppServer {
    pub fn new(cfg: &ProviderConfig) -> Result<AppServer, String> {
        Ok(AppServer {
            id: cfg.id.clone(),
            command: cfg.command.clone().unwrap_or_else(|| "codex".into()),
            args: if cfg.args.is_empty() {
                vec!["app-server".into()]
            } else {
                cfg.args.clone()
            },
            approve: cfg.has_quirk("approve_all"),
            timeout: Duration::from_secs(cfg.idle_timeout_secs.unwrap_or(1800).max(1)),
        })
    }
}

struct Rpc {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<Value>,
    next: u64,
}

impl Rpc {
    fn send(&mut self, v: &Value) -> Result<(), ProviderError> {
        writeln!(self.stdin, "{v}")
            .and_then(|_| self.stdin.flush())
            .map_err(|e| {
                ProviderError::new(
                    ProviderErrorKind::Network,
                    format!("codex app-server stdin: {e}"),
                )
            })
    }
    fn request(&mut self, method: &str, params: Value) -> Result<u64, ProviderError> {
        self.next += 1;
        let id = self.next;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        Ok(id)
    }
    /// Wait for the response to `id`, handing notifications to `on` meanwhile.
    fn wait(
        &mut self,
        id: u64,
        deadline: Instant,
        cancel: &Cancel,
        on: &mut dyn FnMut(&mut Rpc, Value) -> Result<bool, ProviderError>,
    ) -> Result<Value, ProviderError> {
        loop {
            let v = self.recv(deadline, cancel)?;
            if v.get("method").is_none() && v["id"].as_u64() == Some(id) {
                if let Some(e) = v.get("error") {
                    return Err(ProviderError::new(
                        ProviderErrorKind::BadRequest,
                        format!(
                            "codex app-server: {}",
                            e["message"].as_str().unwrap_or("error")
                        ),
                    ));
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
                    "codex app-server turn timed out",
                ));
            }
            match self.rx.recv_timeout(Duration::from_millis(50)) {
                Ok(v) => return Ok(v),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(ProviderError::new(
                        ProviderErrorKind::Network,
                        "codex app-server exited",
                    ))
                }
            }
        }
    }
}

impl Drop for Rpc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Provider for AppServer {
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
        let mut child = Command::new(crate::auth::program(&self.command))
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                ProviderError::new(
                    ProviderErrorKind::Network,
                    format!("cannot start `{}`: {e}", self.command),
                )
            })?;
        let stdin = child.stdin.take().unwrap();
        let out = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for l in BufReader::new(out).lines().map_while(Result::ok) {
                if let Ok(v) = serde_json::from_str::<Value>(&l) {
                    if tx.send(v).is_err() {
                        break;
                    }
                }
            }
        });
        let mut rpc = Rpc {
            child,
            stdin,
            rx,
            next: 0,
        };
        let deadline = Instant::now() + self.timeout;
        let approve = self.approve;
        let mut ignore = |r: &mut Rpc, v: Value| -> Result<bool, ProviderError> {
            server_request(r, &v, approve)?;
            Ok(false)
        };
        let id = rpc.request("initialize", json!({"clientInfo": {"name": "seagent", "title": "seagent", "version": env!("CARGO_PKG_VERSION")}, "capabilities": {}}))?;
        rpc.wait(id, deadline, cancel, &mut ignore)?;
        rpc.send(&json!({"jsonrpc": "2.0", "method": "initialized"}))?;
        let mut tp = json!({"cwd": std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default(), "personality": "none"});
        let sys = req.system_text();
        if !sys.is_empty() {
            tp["developerInstructions"] = sys.into();
        }
        let model = (!req.model.is_empty() && req.model != "default").then(|| req.model.clone());
        if let Some(m) = &model {
            tp["model"] = m.clone().into();
        }
        let id = rpc.request("thread/start", tp)?;
        let thread = rpc.wait(id, deadline, cancel, &mut ignore)?;
        let tid = thread["thread"]["id"]
            .as_str()
            .or(thread["threadId"].as_str())
            .ok_or_else(|| {
                ProviderError::new(
                    ProviderErrorKind::Protocol,
                    "thread/start returned no thread id",
                )
            })?
            .to_string();
        let prompt = if req.messages.len() == 1 {
            req.messages[0].text()
        } else {
            format!(
                "<conversation>\n{}</conversation>\n\nReply to the last User message.",
                crate::transcript(req)
            )
        };
        let mut sp = json!({"threadId": tid, "input": [{"type": "text", "text": prompt}]});
        if let Some(m) = &model {
            sp["model"] = m.clone().into();
        }
        if let Some(e) = req
            .reasoning
            .as_deref()
            .and_then(|l| crate::reasoning::clamp(l, &["low", "medium", "high", "xhigh"]))
        {
            sp["effort"] = e.into();
        }
        if req.options.service_tier.as_deref() == Some("priority") {
            sp["serviceTier"] = "fast".into();
        }
        let id = rpc.request("turn/start", sp)?;
        let mut text = String::new();
        let mut final_text: Option<String> = None;
        let mut usage: Option<Usage> = None;
        let mut failed: Option<String> = None;
        let done = std::cell::Cell::new(false);
        let mut on = |r: &mut Rpc, v: Value| -> Result<bool, ProviderError> {
            match v["method"].as_str().unwrap_or("") {
                "item/agentMessage/delta" => {
                    let d = v["params"]["delta"].as_str().unwrap_or("");
                    text.push_str(d);
                    on_event(StreamEvent::TextDelta(d.into()));
                }
                "item/reasoning/summaryTextDelta" | "item/reasoning/textDelta" => on_event(
                    StreamEvent::ThinkingDelta(v["params"]["delta"].as_str().unwrap_or("").into()),
                ),
                "item/completed" if v["params"]["item"]["type"] == "agentMessage" => {
                    final_text = v["params"]["item"]["text"].as_str().map(String::from)
                }
                "thread/tokenUsage/updated" => {
                    let l = &v["params"]["tokenUsage"]["last"];
                    let cached = l["cachedInputTokens"].as_u64().unwrap_or(0);
                    usage = Some(Usage {
                        input_tokens: l["inputTokens"]
                            .as_u64()
                            .unwrap_or(0)
                            .saturating_sub(cached),
                        output_tokens: l["outputTokens"].as_u64().unwrap_or(0),
                        cache_read_tokens: cached,
                        ..Default::default()
                    });
                }
                "turn/completed" => {
                    let t = &v["params"]["turn"];
                    if t["status"]
                        .as_str()
                        .is_some_and(|s| s != "completed" && s != "interrupted")
                    {
                        failed = Some(
                            t["error"]["message"]
                                .as_str()
                                .unwrap_or("turn failed")
                                .to_string(),
                        );
                    }
                    done.set(true);
                    return Ok(true);
                }
                _ => server_request(r, &v, approve)?,
            }
            Ok(false)
        };
        rpc.wait(id, deadline, cancel, &mut on)?;
        while !done.get() {
            let v = rpc.recv(deadline, cancel)?;
            on(&mut rpc, v)?;
        }
        if let Some(e) = failed {
            let k = if e.to_lowercase().contains("rate") {
                ProviderErrorKind::RateLimited { retry_after: None }
            } else {
                ProviderErrorKind::Server
            };
            return Err(ProviderError::new(k, format!("codex: {e}")));
        }
        let message = Message {
            role: Role::Assistant,
            content: vec![Block::Text {
                text: final_text.unwrap_or(text),
            }],
        };
        let usage = finalize_usage(usage, req, &message);
        Ok(ModelResponse {
            message,
            stop: StopReason::EndTurn,
            usage,
            model: format!("{}/{}", self.id, model.unwrap_or_else(|| "default".into())),
        })
    }
}

/// Answer server→client requests (approvals, elicitations).
fn server_request(r: &mut Rpc, v: &Value, approve: bool) -> Result<(), ProviderError> {
    let (Some(id), Some(m)) = (v.get("id").cloned(), v["method"].as_str()) else {
        return Ok(());
    };
    let result = match m {
        "item/commandExecution/requestApproval" | "item/fileChange/requestApproval" => json!({"decision": if approve { "accept" } else { "decline" }}),
        "item/permissions/requestApproval" => json!({"decision": "decline"}),
        "mcpServer/elicitation/request" => json!({"action": "decline", "content": null}),
        _ => return r.send(&json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "not supported by seagent"}})),
    };
    r.send(&json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE: &str = r#"import json, sys
for line in sys.stdin:
    m = json.loads(line)
    meth, mid = m.get("method"), m.get("id")
    def out(o): print(json.dumps(o), flush=True)
    if meth == "initialize": out({"id": mid, "result": {"userAgent": "fake"}})
    elif meth == "thread/start": out({"id": mid, "result": {"thread": {"id": "th1"}}})
    elif meth == "turn/start":
        assert m["params"]["threadId"] == "th1"
        out({"id": mid, "result": {"turn": {"id": "t1"}}})
        out({"id": 99, "method": "item/commandExecution/requestApproval", "params": {"command": "rm -rf /"}})
    elif mid == 99:
        out({"method": "item/agentMessage/delta", "params": {"delta": "dec:" + m["result"]["decision"]}})
        out({"method": "thread/tokenUsage/updated", "params": {"tokenUsage": {"last": {"inputTokens": 9, "cachedInputTokens": 3, "outputTokens": 2}}}})
        out({"method": "turn/completed", "params": {"turn": {"id": "t1", "status": "completed"}}})
"#;

    #[test]
    fn drives_a_turn_and_declines_approvals() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-codexapp-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("fake.py");
        std::fs::write(&f, FAKE).unwrap();
        let cfg = ProviderConfig {
            id: "codex-app-server".into(),
            format: crate::WireFormat::CodexAppServer,
            command: Some("python3".into()),
            args: vec!["-I".into(), f.to_string_lossy().into()],
            ..Default::default()
        };
        let p = AppServer::new(&cfg).unwrap();
        let req = ModelRequest {
            model: "gpt-5.5".into(),
            messages: vec![Message::user("go")],
            max_tokens: 10,
            ..Default::default()
        };
        let r = p.complete(&req, &mut |_| {}, &Cancel::new()).unwrap();
        assert_eq!(r.message.text(), "dec:decline");
        assert_eq!(
            (
                r.usage.input_tokens,
                r.usage.cache_read_tokens,
                r.usage.output_tokens
            ),
            (6, 3, 2)
        );
        let p = AppServer::new(&ProviderConfig {
            quirks: vec!["approve_all".into()],
            ..cfg
        })
        .unwrap();
        assert_eq!(
            p.complete(&req, &mut |_| {}, &Cancel::new())
                .unwrap()
                .message
                .text(),
            "dec:accept"
        );
    }
}
