//! `ark worker` (OpenClaw `openclaw worker`, `src/worker/worker-process.ts`): the
//! restricted worker runtime a supervisor starts as a child and drives over a private
//! JSONL protocol on stdin/stdout. Nothing else is printed on stdout.
//!
//! Requests (one JSON object per line, ≤ 1 MiB):
//! - `{"type":"turn","turnId":"t1","workspace":"/abs","prompt":"…","model":"p/m",
//!   "containmentRoot":"/abs","tools":["read","grep"],"deny":["shell"],"maxSteps":20}`
//! - `{"type":"run","turnId":"r1","sessionId":"…"}` (ark extension, ent-097): continue an
//!   existing session of the shared store — how the daemon's worker pool
//!   (`ark_kernel::workers`) hands a session to this process.
//! - `{"type":"cancel","turnId":"t1"}`
//!
//! Replies: `{"type":"started","turnId","sessionId"}`, then `{"type":"result","turnId",
//! "status":"completed"|"failed"|"cancelled"|"rejected","reason"?,"text"?,"usage"?}`.
//!
//! Restrictions: the workspace must resolve inside `containmentRoot` (symlinks
//! resolved); the session's tool policy is the descriptor's `tools` allow-list (none =
//! the default toolset) minus `deny`; privilege and egress are never granted (the
//! approver denies). One turn at a time. Supervisor loss (stdin EOF) cancels the
//! running turn and exits. A worker started by an HA leader inherits its fencing token
//! (`ARK_HA_NODE` / `ARK_HA_EPOCH` / `ARK_HA_DIR`) and cannot write once that leader is deposed.

use crate::args::Args;
use crate::R;
use ark_kernel::event::EventKind;
use ark_kernel::kernel::{Kernel, RunOpts};
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::mpsc;

pub const COMMANDS: &[&str] = &["worker"];
pub const VALUE_FLAGS: &[&str] = &[];
pub const BOOL_FLAGS: &[&str] = &["internal-worker-ipc", "internal-worker-native-inference"];

pub const MAX_LINE: usize = 1 << 20;

fn reply(out: &mut dyn Write, v: Value) {
    let _ = writeln!(out, "{v}");
    let _ = out.flush();
}

/// An admitted turn: (workspace, allow list, deny list).
pub type Admitted = (std::path::PathBuf, Option<Vec<String>>, Vec<String>);

/// Validate a turn → (workspace, allow, deny).
pub fn admit(req: &Value) -> Result<Admitted, String> {
    let id = req["turnId"].as_str().filter(|s| !s.is_empty() && s.len() <= 128).ok_or("turnId is required (1-128 chars)")?;
    let _ = id;
    if req["prompt"].as_str().is_none_or(|p| p.trim().is_empty()) {
        return Err("prompt is required".into());
    }
    let ws = req["workspace"].as_str().ok_or("workspace is required")?;
    let root = req["containmentRoot"].as_str().ok_or("containmentRoot is required")?;
    if !Path::new(ws).is_absolute() || !Path::new(root).is_absolute() {
        return Err("workspace and containmentRoot must be absolute".into());
    }
    let wsr = Path::new(ws).canonicalize().map_err(|e| format!("workspace {ws}: {e}"))?;
    let rootr = Path::new(root).canonicalize().map_err(|e| format!("containmentRoot {root}: {e}"))?;
    if !wsr.starts_with(&rootr) {
        return Err(format!("workspace {} escapes the containment root {}", wsr.display(), rootr.display()));
    }
    let list = |k: &str| -> Result<Option<Vec<String>>, String> {
        match &req[k] {
            Value::Null => Ok(None),
            Value::Array(a) => a.iter().map(|v| v.as_str().map(String::from).ok_or(format!("{k} must be a list of tool names"))).collect::<Result<Vec<_>, _>>().map(Some),
            _ => Err(format!("{k} must be a list of tool names")),
        }
    };
    Ok((wsr, list("tools")?, list("deny")?.unwrap_or_default()))
}

/// Serve the protocol until EOF; `k` must carry a deny-privilege/deny-egress approver.
pub fn serve(k: &Kernel, input: Box<dyn BufRead + Send>, out: &mut dyn Write) -> i32 {
    let (tx, rx) = mpsc::channel::<Option<Value>>();
    std::thread::spawn(move || {
        let mut input = input;
        loop {
            let mut buf = Vec::new();
            let r: &mut dyn BufRead = input.as_mut();
            match std::io::Read::take(r, MAX_LINE as u64 + 1).read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => {
                    let _ = tx.send(None);
                    return;
                }
                Ok(_) if buf.len() > MAX_LINE => {
                    let _ = tx.send(Some(json!({"type": "invalid", "reason": "request exceeds the protocol payload limit"})));
                    let _ = tx.send(None);
                    return;
                }
                Ok(_) => {
                    let v = serde_json::from_slice::<Value>(&buf).unwrap_or_else(|_| json!({"type": "invalid", "reason": "invalid JSON request"}));
                    if tx.send(Some(v)).is_err() {
                        return;
                    }
                }
            }
        }
    });
    // (turn id, session id, the thread running that turn)
    type Running = (String, String, std::thread::JoinHandle<Result<ark_kernel::kernel::Outcome, ark_kernel::kernel::KernelError>>);
    let mut running: Option<Running> = None;
    let mut cancelled = false;
    loop {
        // Finish a completed turn.
        if running.as_ref().is_some_and(|(_, _, h)| h.is_finished()) {
            let (turn, sid, h) = running.take().unwrap();
            let v = match h.join() {
                Ok(Ok(o)) if cancelled || matches!(o.reason, ark_kernel::kernel::EndReason::Interrupted) => json!({"type": "result", "turnId": turn, "sessionId": sid, "status": "cancelled", "text": o.text}),
                Ok(Ok(o)) => {
                    use ark_kernel::kernel::EndReason;
                    let ok = matches!(o.reason, EndReason::Done | EndReason::Idle);
                    let reason = o.reason.label();
                    json!({"type": "result", "turnId": turn, "sessionId": sid, "status": if ok { "completed" } else { "failed" }, "reason": if ok { Value::Null } else { json!(reason) }, "text": o.text, "usage": {"input": o.usage.input_tokens, "output": o.usage.output_tokens}})
                }
                Ok(Err(e)) => json!({"type": "result", "turnId": turn, "sessionId": sid, "status": "failed", "reason": "turn-failed", "error": e.to_string()}),
                Err(_) => json!({"type": "result", "turnId": turn, "sessionId": sid, "status": "failed", "reason": "turn-failed"}),
            };
            cancelled = false;
            reply(out, v);
        }
        let msg = match rx.recv_timeout(std::time::Duration::from_millis(20)) {
            Ok(m) => m,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => None,
        };
        let Some(req) = msg else {
            // Supervisor gone: cancel and wait for the turn to stop.
            if let Some((turn, sid, h)) = running.take() {
                k.interrupt(&sid);
                let _ = h.join();
                reply(out, json!({"type": "result", "turnId": turn, "sessionId": sid, "status": "cancelled", "reason": "supervisor-lost"}));
            }
            return 0;
        };
        match req["type"].as_str().unwrap_or("") {
            "turn" => {
                let turn = req["turnId"].as_str().unwrap_or("").to_string();
                if running.is_some() {
                    reply(out, json!({"type": "result", "turnId": turn, "status": "rejected", "reason": "busy"}));
                    continue;
                }
                let (ws, allow, deny) = match admit(&req) {
                    Ok(x) => x,
                    Err(e) => {
                        reply(out, json!({"type": "result", "turnId": turn, "status": "rejected", "reason": e}));
                        continue;
                    }
                };
                let sid = match k.create_session(&ws, req["model"].as_str(), None, Some(&format!("worker {turn}"))) {
                    Ok(s) => s,
                    Err(e) => {
                        reply(out, json!({"type": "result", "turnId": turn, "status": "rejected", "reason": e.to_string()}));
                        continue;
                    }
                };
                let _ = k.record(&sid, EventKind::Tools { allow, deny });
                if let Err(e) = k.submit(&sid, req["prompt"].as_str().unwrap_or(""), "worker") {
                    reply(out, json!({"type": "result", "turnId": turn, "status": "rejected", "reason": e.to_string()}));
                    continue;
                }
                reply(out, json!({"type": "started", "turnId": turn, "sessionId": sid}));
                let h = k.start(&sid, RunOpts::default());
                running = Some((turn, sid, h));
            }
            "run" => {
                let turn = req["turnId"].as_str().unwrap_or("").to_string();
                let sid = req["sessionId"].as_str().unwrap_or("").to_string();
                if running.is_some() {
                    reply(out, json!({"type": "result", "turnId": turn, "sessionId": sid, "status": "rejected", "reason": "busy"}));
                    continue;
                }
                if turn.is_empty() || !k.store.exists(&sid) {
                    reply(out, json!({"type": "result", "turnId": turn, "sessionId": sid, "status": "rejected", "reason": "unknown session"}));
                    continue;
                }
                reply(out, json!({"type": "started", "turnId": turn, "sessionId": sid}));
                let h = k.start(&sid, RunOpts::default());
                running = Some((turn, sid, h));
            }
            "cancel" => {
                if let Some((turn, sid, _)) = &running {
                    if req["turnId"].as_str() == Some(turn.as_str()) {
                        cancelled = true;
                        k.interrupt(sid);
                    }
                }
            }
            _ => reply(out, json!({"type": "error", "reason": req["reason"].as_str().unwrap_or("unknown request type")})),
        }
    }
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if cmd != "worker" {
        return None;
    }
    Some((|| -> R {
        // Never auto-approve: a worker has exactly the authority its descriptor names.
        let approver: std::sync::Arc<dyn ark_kernel::approver::Approver> = std::sync::Arc::new(ark_kernel::approver::Policy { allow_privilege: false, allow_egress: false });
        let c = crate::build_agent(a, approver, false)?;
        // ent-095: started by an HA leader → write only while that leader's epoch holds.
        if let Some(f) = ark_kernel::ha::fence_from_env() {
            c.k.store.set_fence(f);
        }
        let input: Box<dyn BufRead + Send> = Box::new(std::io::BufReader::new(std::io::stdin()));
        Ok(serve(&c.k, input, &mut std::io::stdout()))
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_only_worker_and_accepts_hidden_flags() {
        // Registration facts `mod.rs` relies on (upstream `registerWorkerCli` flags are
        // both hidden boolean switches; the native-inference one is a no-op upstream).
        assert_eq!(COMMANDS, &["worker"]);
        assert!(BOOL_FLAGS.contains(&"internal-worker-ipc") && BOOL_FLAGS.contains(&"internal-worker-native-inference"));
        let raw: Vec<String> = ["worker", "--internal-worker-ipc"].iter().map(|s| s.to_string()).collect();
        let a = Args::parse(&raw).unwrap();
        assert!(dispatch("not-worker", &a, &raw).is_none(), "other commands fall through");
    }

    #[test]
    fn admission_rules() {
        let root = std::env::temp_dir().join(format!("ark-wk-{}", ark_kernel::util::random_hex(4)));
        let inside = root.join("job");
        std::fs::create_dir_all(&inside).unwrap();
        let ok = json!({"turnId": "t", "prompt": "hi", "workspace": inside, "containmentRoot": root, "tools": ["read"]});
        let (ws, allow, deny) = admit(&ok).unwrap();
        assert!(ws.ends_with("job") && allow == Some(vec!["read".to_string()]) && deny.is_empty());
        let esc = json!({"turnId": "t", "prompt": "hi", "workspace": std::env::temp_dir(), "containmentRoot": inside});
        assert!(admit(&esc).unwrap_err().contains("escapes"));
        std::os::unix::fs::symlink(std::env::temp_dir(), inside.join("link")).unwrap();
        let sym = json!({"turnId": "t", "prompt": "hi", "workspace": inside.join("link"), "containmentRoot": inside});
        assert!(admit(&sym).unwrap_err().contains("escapes"), "symlinks are resolved");
        assert!(admit(&json!({"turnId": "t", "workspace": inside, "containmentRoot": root})).unwrap_err().contains("prompt"));
        assert!(admit(&json!({"turnId": "t", "prompt": "x", "workspace": "rel", "containmentRoot": root})).is_err());
        assert!(admit(&json!({"turnId": "t", "prompt": "x", "workspace": inside, "containmentRoot": root, "tools": "read"})).is_err());
    }

    #[test]
    fn run_continues_an_existing_session() {
        let kit = crate::testkit::kit();
        let sid = kit.k.create_session(&kit.ws, None, None, Some("pooled")).unwrap();
        kit.k.submit(&sid, "from the pool", "test").unwrap();
        let input = format!("{}\n{}\n", json!({"type": "run", "turnId": "r1", "sessionId": sid}), json!({"type": "run", "turnId": "r2", "sessionId": "nope"}));
        let mut out = vec![];
        assert_eq!(serve(&kit.k, Box::new(std::io::Cursor::new(input.into_bytes())), &mut out), 0);
        let lines: Vec<Value> = String::from_utf8(out).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert!(lines.iter().any(|l| l["type"] == "started" && l["sessionId"] == sid.as_str()), "{lines:?}");
        assert!(lines.iter().any(|l| l["turnId"] == "r2" && l["status"] == "rejected"), "{lines:?}");
    }

    #[test]
    fn serves_turns_over_jsonl() {
        let kit = crate::testkit::kit();
        let ws = kit.ws.display().to_string();
        let input = format!(
            "{}\n{}\nnot json\n{}\n",
            json!({"type": "turn", "turnId": "t1", "prompt": "hello worker", "workspace": ws, "containmentRoot": ws, "tools": ["read"], "deny": ["shell"]}),
            json!({"type": "turn", "turnId": "t0", "prompt": "x", "workspace": "/", "containmentRoot": ws}),
            json!({"type": "bogus"})
        );
        let mut out = vec![];
        let rc = serve(&kit.k, Box::new(std::io::Cursor::new(input.into_bytes())), &mut out);
        assert_eq!(rc, 0);
        let lines: Vec<Value> = String::from_utf8(out).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        let started = lines.iter().find(|l| l["type"] == "started").expect("started");
        let sid = started["sessionId"].as_str().unwrap().to_string();
        assert!(lines.iter().any(|l| l["turnId"] == "t0" && l["status"] == "rejected"), "{lines:?}");
        assert!(lines.iter().any(|l| l["type"] == "error" && l["reason"] == "invalid JSON request"));
        // EOF after the turn started: either it completed or it was cancelled for supervisor loss
        let res = lines.iter().find(|l| l["type"] == "result" && l["turnId"] == "t1").expect("result");
        assert!(res["status"] == "completed" || res["status"] == "cancelled", "{res}");
        let ev = ark_kernel::store::Store::new(kit.paths.sessions()).read(&sid).unwrap();
        assert!(ev.iter().any(|e| matches!(&e.kind, EventKind::Tools { allow: Some(a), deny } if a == &["read".to_string()] && deny == &["shell".to_string()])));
    }
}
