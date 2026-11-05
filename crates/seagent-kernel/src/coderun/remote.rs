//! Code mode on a remote / sandboxed execution backend (Hermes `tools/code_execution_tool.py`
//! remote path, `_rpc_poll_loop`). A backend only offers "run this script", so nested tool calls
//! use a file protocol in a private directory inside the backend: the `seagent-call` helper written
//! there drops `req_<id>.req` (token, tool, JSON input) and waits for `res_<id>.res` (`ok`/`err`
//! line, then the output). The host polls the directory through the backend while the script
//! runs, checks the token, services each call through the same gates and budget as a local run,
//! and writes the response back. The script sees no host environment at all.

use super::{Budget, Nested};
use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest};
use seagent_core::{Cancel, ToolOutput};
use base64::Engine as _;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

const HELPER: &str = r#"#!/bin/sh
# seagent-call <tool> '<json input>': call an seagent tool from a code-mode script (remote backend).
d="$SEAGENT_RPC_DIR"; id="$$.$(date +%s%N 2>/dev/null || date +%s).$(od -An -N4 -tu4 /dev/urandom 2>/dev/null | tr -d ' ')"
in="$2"; [ -n "$in" ] || in='{}'
{ printf '%s\n%s\n' "$SEAGENT_CALL_TOKEN" "$1"; printf '%s' "$in"; } > "$d/req_$id.tmp" && mv "$d/req_$id.tmp" "$d/req_$id.req"
while [ ! -e "$d/res_$id.res" ]; do sleep 0.05; done
st=$(head -n1 "$d/res_$id.res"); tail -n +2 "$d/res_$id.res"; rm -f "$d/res_$id.res"
[ "$st" = ok ]
"#;

fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Run a helper script to completion in the backend.
fn capture(b: &dyn ExecBackend, script: &str, stdin: Option<&[u8]>, timeout: Duration) -> Result<String, String> {
    let req = ExecRequest { script: script.into(), stdin: stdin.is_some(), stdin_data: stdin.map(|s| s.to_vec()), ..Default::default() };
    let mut c = b.spawn(&req).map_err(|e| format!("{}: {e}", b.id()))?;
    c.close_stdin();
    let deadline = Instant::now() + timeout;
    let mut out = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        match c.read(&mut buf, Duration::from_millis(20)) {
            Ok(0) => std::thread::sleep(Duration::from_millis(5)),
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                continue;
            }
            Err(_) => {}
        }
        if let Ok(Some(st)) = c.try_wait() {
            while let Ok(n) = c.read(&mut buf, Duration::from_millis(10)) {
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            let s = String::from_utf8_lossy(&out).into_owned();
            return if st.success() { Ok(s) } else { Err(format!("{}: {}", st.describe(), s.trim())) };
        }
        if Instant::now() >= deadline {
            c.kill(true);
            return Err("backend helper timed out".into());
        }
    }
}

/// Pending requests: (id, token, tool, input).
fn poll(b: &dyn ExecBackend, dir: &str) -> Vec<(String, String, String, String)> {
    let script = format!("for f in {d}/req_*.req; do [ -e \"$f\" ] || continue; n=${{f##*/req_}}; printf '%s\\n' \"${{n%.req}}\"; base64 < \"$f\" | tr -d '\\n'; echo; rm -f \"$f\"; done", d = q(dir));
    let Ok(out) = capture(b, &script, None, Duration::from_secs(30)) else { return vec![] };
    let lines: Vec<&str> = out.lines().collect();
    lines
        .chunks(2)
        .filter_map(|c| {
            let (id, b64) = (c.first()?, c.get(1)?);
            let raw = base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok()?;
            let raw = String::from_utf8_lossy(&raw).into_owned();
            let mut it = raw.splitn(3, '\n');
            Some((id.to_string(), it.next()?.to_string(), it.next()?.to_string(), it.next().unwrap_or("{}").to_string()))
        })
        .collect()
}

// A dozen script-run parameters (backend, script, interpreter, limits, budget, nested-tool
// callback) travel together; threading them through a struct would only move the plumbing.
#[allow(clippy::too_many_arguments)]
pub fn run(b: Arc<dyn ExecBackend>, script: &str, interp: &str, timeout: Duration, workspace: &std::path::Path, cancel: &Cancel, budget: &mut Budget, handle: &mut dyn FnMut(Nested) -> ToolOutput) -> ToolOutput {
    let token = crate::util::random_hex(32);
    let dir = format!("{}/seagent-rpc-{}", b.temp_dir().trim_end_matches('/'), crate::util::random_hex(8));
    let setup = format!("mkdir -p {d} && chmod 700 {d} && cat > {d}/seagent-call && chmod 755 {d}/seagent-call", d = q(&dir));
    if let Err(e) = capture(b.as_ref(), &setup, Some(HELPER.as_bytes()), Duration::from_secs(60)) {
        return ToolOutput::err(format!("code mode could not prepare the {} backend: {e}", b.id()));
    }
    if let Err(e) = b.before_exec() {
        return ToolOutput::err(format!("{}: sync before run failed: {e}", b.id()));
    }
    let ws = b.map_path(workspace);
    let body = format!("export SEAGENT_RPC_DIR={d} SEAGENT_CALL_TOKEN={t} PATH={d}:\"$PATH\" PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONUTF8=1\ncd {ws} 2>/dev/null\nexec {interp} -c {s}", d = q(&dir), t = token, ws = q(&ws), s = q(script));
    let req = ExecRequest { script: body, cwd: Some(workspace.to_path_buf()), ..Default::default() };
    let mut child: Box<dyn ExecChild> = match b.spawn(&req) {
        Ok(c) => c,
        Err(e) => return ToolOutput::err(format!("{}: cannot start {interp}: {e}", b.id())),
    };
    let deadline = Instant::now() + timeout;
    let mut out = Vec::new();
    let mut buf = [0u8; 16384];
    let mut last_poll = Instant::now() - Duration::from_secs(1);
    let mut killed: Option<&str> = None;
    let status = loop {
        match child.read(&mut buf, Duration::from_millis(50)) {
            Ok(n) if n > 0 && out.len() < super::MAX_OUTPUT * 2 => out.extend_from_slice(&buf[..n]),
            _ => {}
        }
        if last_poll.elapsed() >= Duration::from_millis(200) {
            last_poll = Instant::now();
            for (id, tok, tool, input) in poll(b.as_ref(), &dir) {
                let (content, ok) = if tok != token {
                    ("bad token".to_string(), false)
                } else if tool == "run" {
                    ("`run` cannot be nested".to_string(), false)
                } else {
                    let input = serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
                    let (rtx, _rrx) = mpsc::channel();
                    let o = budget.dispatch(Nested { tool, input, reply: rtx }, handle);
                    (o.content, !o.is_error)
                };
                let resp = format!("{}\n{content}", if ok { "ok" } else { "err" });
                let w = format!("cat > {d}/res_{id}.tmp && mv {d}/res_{id}.tmp {d}/res_{id}.res", d = q(&dir), id = id.replace(|c: char| !c.is_ascii_alphanumeric() && c != '.', ""));
                let _ = capture(b.as_ref(), &w, Some(resp.as_bytes()), Duration::from_secs(30));
            }
        }
        if let Ok(Some(st)) = child.try_wait() {
            while let Ok(n) = child.read(&mut buf, Duration::from_millis(20)) {
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            break Some(st);
        }
        if killed.is_none() && (cancel.is_cancelled() || Instant::now() >= deadline) {
            killed = Some(if cancel.is_cancelled() { "cancelled" } else { "timed out" });
            child.kill(true);
        }
        if killed.is_some() && child.try_wait().ok().flatten().is_none() && Instant::now() >= deadline + Duration::from_secs(5) {
            break None;
        }
    };
    let _ = capture(b.as_ref(), &format!("rm -rf {}", q(&dir)), None, Duration::from_secs(30));
    let _ = b.after_exec();
    let (mut text, _) = crate::util::head_tail(&String::from_utf8_lossy(&out), super::MAX_OUTPUT);
    if let Some(k) = killed {
        text.push_str(&format!("\n[script {k}; killed in the {} backend]", b.id()));
        return ToolOutput::err(text);
    }
    match status {
        Some(s) if s.success() => ToolOutput::ok(text),
        Some(s) => ToolOutput::err(format!("{text}\n[{} in the {} backend]", s.describe(), b.id())),
        None => ToolOutput::err(format!("{text}\n[could not collect exit status]")),
    }
}
