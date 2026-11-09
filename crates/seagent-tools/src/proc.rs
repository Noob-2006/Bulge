//! `process`: drive the background processes `job` / `shell` started — the union of
//! Hermes `process_manage` (`tools/process_registry.py`) and OpenClaw's `process`
//! tool (`src/agents/bash-tools.process.ts` + `pty-keys.ts`).
//!
//! `list` / `poll` / `log` / `wait` observe, `kill` / `clear` / `remove` collect,
//! and `write` / `submit` / `send-keys` / `paste` / `close` type into a running
//! process — the difference between `write` (raw bytes) and `submit` (bytes +
//! Enter) and between `send-keys` (terminal key sequences: `Enter`, `C-c`, `Up`…)
//! and `paste` (bracketed paste on a terminal) is the whole point of the tool.
//! `handoff` releases supervision and says how to take over.
//!
//! Processes that outlived an seagent restart are adopted from `<home>/jobs/*.json`
//! before every call (`exec::process::restore`).

use crate::exec::process as reg;
use seagent_core::tool::{arg_opt_str, arg_opt_u64};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Hermes `read_log` default page.
const DEFAULT_LOG_LINES: usize = 200;
/// OpenClaw clamps a poll wait to 30 s.
const MAX_POLL_WAIT_MS: u64 = 30_000;
const DEFAULT_WAIT_MS: u64 = 30_000;
const MAX_WAIT_MS: u64 = 600_000;
/// Bytes of a finished process shown by poll/wait (Hermes `_output_tail(…, 1000)` is
/// too short for a stack trace, OpenClaw returns the whole unread output).
const TAIL: usize = 4 * 1024;
/// OpenClaw `inputWaitIdleMs`: silence this long on a writable stdin looks like a prompt.
const INPUT_WAIT_IDLE_MS: u64 = 15_000;

const ACTIONS: &[&str] = &["list", "poll", "log", "wait", "kill", "write", "submit", "send-keys", "paste", "close", "clear", "remove", "handoff"];

/// Where each `(session, id)`'s poll got to (absolute byte offset). Hermes dedups
/// polls the same way; the cursor is per tool, not per process.
static CURSORS: Mutex<BTreeMap<(String, u32), u64>> = Mutex::new(BTreeMap::new());

pub struct Proc;

impl Tool for Proc {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "process".into(),
            description: "Control a background process started by `job` (or any detached process seagent still tracks). \
action=list shows this session's processes; poll {id} returns status and new output; log {id, offset?, limit?} pages the full log (200 lines by default); \
wait {id, timeout_ms?} blocks until it exits or the timeout elapses; kill {id} terminates it; \
write {id, text, eof?} sends raw bytes (no newline); submit {id, text} sends the text plus Enter — use it to answer a prompt; \
send-keys {id, keys:[\"Up\",\"C-c\",\"Enter\"…]} sends terminal key sequences (pty only); paste {id, text} pastes a block (bracketed on a terminal); \
close {id} sends EOF/^D without killing it; clear {id} drops the buffered output; remove {id} forgets a finished process; \
handoff {id, note} stops supervising it and reports the pid and how to take over."
                .into(),
            input_schema: json!({"type":"object","properties":{
                "action":{"type":"string","enum":ACTIONS,"description":"Process action."},
                "id":{"type":["integer","string"],"description":"Process id from `job`/`process list` (also accepted as session_id/process_id). Required for every action except list."},
                "text":{"type":"string","description":"Text for write/submit/paste (write also accepts `data`)."},
                "data":{"type":"string","description":"Raw bytes for write (alias of text); for handoff: one sentence on what the process is for."},
                "keys":{"type":["array","string"],"items":{"type":"string"},"description":"send-keys tokens: Enter, Return, Tab, Escape, Space, Backspace, Up, Down, Left, Right, Home, End, PgUp, PgDn, Insert, Delete, F1…F12, C-c, M-x, S-Tab, ^C, or a single character."},
                "hex":{"type":"array","items":{"type":"string"},"description":"send-keys raw hex bytes ('1b', '0d')."},
                "literal":{"type":"string","description":"send-keys: literal text sent before the keys."},
                "eof":{"type":"boolean","description":"write: close stdin after writing."},
                "bracketed":{"type":"boolean","description":"paste: wrap the text in bracketed-paste markers (default true on a terminal, ignored on a pipe)."},
                "offset":{"type":"integer","minimum":0,"description":"log: 0-based first line (omit for the last `limit` lines)."},
                "limit":{"type":"integer","minimum":1,"description":"log: number of lines (default 200)."},
                "timeout_ms":{"type":"integer","minimum":0,"description":"wait/poll: milliseconds to block (wait default 30000, max 600000; poll max 30000; 0 = return at once)."},
                "timeout":{"type":"integer","minimum":0,"description":"Alias of timeout_ms for wait, in seconds (Hermes process_manage)."}},
                "required":["action"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, _: &ToolCtx, input: &Value) -> Vec<Effect> {
        // A command given here is judged, and so is text typed into a shell: it runs.
        if let Some(c) = arg_opt_str(input, "command") {
            return vec![Effect::Exec { command: c.to_string() }];
        }
        let action = arg_opt_str(input, "action").unwrap_or("");
        if matches!(action, "write" | "submit" | "paste" | "send-keys") {
            if let Some(t) = arg_opt_str(input, "text").or_else(|| arg_opt_str(input, "data")).or_else(|| arg_opt_str(input, "literal")) {
                if !t.is_empty() {
                    return vec![Effect::Exec { command: t.to_string() }];
                }
            }
        }
        vec![]
    }

    fn call(&self, ctx: &ToolCtx, mut input: Value) -> ToolOutput {
        crate::util::rename(&mut input, "id", &["session_id", "sessionId", "process_id", "proc_id"]);
        crate::util::rename(&mut input, "keys", &["key"]);
        // Adopt processes that outlived an seagent restart before answering anything.
        reg::restore(&ctx.home.join("jobs"));
        let action = match arg_opt_str(&input, "action").map(|a| a.to_ascii_lowercase()) {
            Some(a) => a,
            None => return ToolOutput::err(format!("missing `action`; use one of {}", ACTIONS.join(", "))),
        };
        if action == "list" {
            return list(ctx);
        }
        if !ACTIONS.contains(&action.as_str()) {
            return ToolOutput::err(format!("unknown action `{action}`; use one of {}", ACTIONS.join(", ")));
        }
        let id = match parse_id(input.get("id")) {
            Ok(Some(i)) => i,
            Ok(None) => return ToolOutput::err(format!("`id` is required for {action} (the id from job/process list)")),
            Err(e) => return ToolOutput::err(e),
        };
        match action.as_str() {
            "poll" => poll(ctx, id, timeout_ms(&input, 0).min(MAX_POLL_WAIT_MS)),
            "log" => log(ctx, id, &input),
            "wait" => wait(ctx, id, &input),
            "kill" => kill(ctx, id),
            "write" => write(ctx, id, &input),
            "submit" => submit(ctx, id, &input),
            "send-keys" => send_keys(ctx, id, &input),
            "paste" => paste(ctx, id, &input),
            "close" => close(ctx, id),
            "clear" => clear(ctx, id),
            "remove" => remove(ctx, id),
            "handoff" => handoff(ctx, id, &input),
            _ => unreachable!(),
        }
    }
}

// ───────────── actions ─────────────

fn list(ctx: &ToolCtx) -> ToolOutput {
    let items = reg::list(&ctx.session_id);
    if items.is_empty() {
        return ToolOutput::ok("no background processes in this session (start one with job action=start)");
    }
    let mut lines = Vec::new();
    for s in &items {
        let mut tags = String::new();
        if s.pty {
            tags.push_str("[pty] ");
        }
        if s.stdin {
            tags.push_str("[stdin] ");
        }
        if s.detached {
            tags.push_str("[detached] ");
        }
        if s.running && s.stdin && s.idle.as_millis() as u64 >= INPUT_WAIT_IDLE_MS {
            tags.push_str("[input-wait] ");
        }
        lines.push(format!("{:<3} {:<10} {:>6} {:>7}  {tags}{}", s.id, status_word(s), secs(s.elapsed), bytes(s.bytes), one_line(&s.command, 120)));
    }
    ToolOutput::ok(lines.join("\n"))
}

fn poll(ctx: &ToolCtx, id: u32, wait_ms: u64) -> ToolOutput {
    let deadline = Instant::now() + Duration::from_millis(wait_ms);
    let snap = loop {
        let Some(s) = reg::poll(&ctx.session_id, id) else { return ToolOutput::err(unknown(id)) };
        if !s.running || Instant::now() >= deadline {
            break s;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let (mut out, _) = header(&snap);
    let (text, next, dropped) = take_new(&ctx.session_id, id, TAIL);
    let _ = next;
    if dropped > 0 {
        out.push_str(&format!("\n[{dropped} bytes of earlier output left the rolling buffer; action=log pages the full log]\n"));
    }
    let body = if !text.trim().is_empty() {
        text
    } else if snap.running {
        "(no new output)".to_string()
    } else {
        reg::tail(&ctx.session_id, id, TAIL).unwrap_or_default()
    };
    let body = crate::tokenjuice::reduce_output(&body, crate::tokenjuice::DEFAULT_BUDGET).unwrap_or(body);
    out.push('\n');
    out.push_str(&body);
    out.push_str(&hint(&snap));
    ToolOutput::ok(out)
}

fn log(ctx: &ToolCtx, id: u32, input: &Value) -> ToolOutput {
    let limit = arg_opt_u64(input, "limit").map(|l| l as usize).unwrap_or(DEFAULT_LOG_LINES);
    let offset = input.get("offset").and_then(Value::as_u64).map(|o| o as usize);
    let Some(snap) = reg::poll(&ctx.session_id, id) else { return ToolOutput::err(unknown(id)) };
    let page = match reg::log_page(&ctx.session_id, id, offset, limit) {
        Ok(p) => p,
        Err(e) => return ToolOutput::err(e),
    };
    let mut out = String::new();
    if page.earlier_bytes > 0 {
        out.push_str(&format!("…[{} earlier bytes in {}]\n", page.earlier_bytes, snap.log.display()));
    }
    if page.text.is_empty() {
        out.push_str(if snap.running { "(no output yet)" } else { "(no output recorded)" });
    } else {
        out.push_str(&page.text);
    }
    if page.tail && page.total_lines > page.shown {
        out.push_str(&format!("\n\n[showing the last {} of {} lines; pass offset/limit to page]", page.shown, page.total_lines));
    } else if !page.tail {
        out.push_str(&format!("\n\n[lines {}–{} of {}]", offset.unwrap_or(0), offset.unwrap_or(0) + page.shown, page.total_lines));
    }
    ToolOutput::ok(out)
}

fn wait(ctx: &ToolCtx, id: u32, input: &Value) -> ToolOutput {
    let ms = match input.get("timeout_ms").and_then(Value::as_u64) {
        Some(v) => v,
        None => match arg_opt_u64(input, "timeout") {
            Some(secs) => secs.saturating_mul(1000),
            None => DEFAULT_WAIT_MS,
        },
    }
    .min(MAX_WAIT_MS);
    let t = Duration::from_millis(ms);
    let Some(snap) = reg::wait_with(&ctx.session_id, id, t, || ctx.cancel.is_cancelled()) else { return ToolOutput::err(unknown(id)) };
    if !snap.running {
        // A PTY process's pane is a second consumer: let it catch up first.
        crate::job::wait_pane(id, Duration::from_secs(3));
    }
    let (mut out, _) = header(&snap);
    out.push('\n');
    let body = reg::tail(&ctx.session_id, id, TAIL).unwrap_or_default();
    out.push_str(&crate::tokenjuice::reduce_output(&body, crate::tokenjuice::DEFAULT_BUDGET).unwrap_or(body));
    if snap.running {
        out.push_str(&format!(
            "\n\n[wait window of {} elapsed — the process is still running. This is not an error; poll again later or raise timeout_ms.]",
            secs(t)
        ));
    }
    ToolOutput::ok(out)
}

fn kill(ctx: &ToolCtx, id: u32) -> ToolOutput {
    let Some(snap) = reg::poll(&ctx.session_id, id) else { return ToolOutput::err(unknown(id)) };
    if !snap.running {
        return ToolOutput::err(format!("process {id} has already exited ({}); nothing to kill", exit_word(&snap)));
    }
    match reg::kill(&ctx.session_id, id) {
        Ok(()) => ToolOutput::ok(format!("killed process {id} (SIGKILL to its process group)\n{}", reg::tail(&ctx.session_id, id, 2048).unwrap_or_default())),
        Err(e) => ToolOutput::err(e),
    }
}

fn write(ctx: &ToolCtx, id: u32, input: &Value) -> ToolOutput {
    let text = match arg_opt_str(input, "text").or_else(|| arg_opt_str(input, "data")) {
        Some(t) => t.to_string(),
        None => return ToolOutput::err("write needs `text` (or `data`): the bytes to send"),
    };
    let eof = input.get("eof").and_then(Value::as_bool).unwrap_or(false);
    if text.is_empty() && !eof {
        return ToolOutput::err("write needs non-empty `text` (use `eof: true` to only close stdin)");
    }
    let n = text.len();
    match reg::write_tracked(&ctx.session_id, id, text.as_bytes()) {
        Ok(()) => {}
        Err(e) => return ToolOutput::err(e),
    }
    if eof {
        if let Err(e) = reg::close_stdin(&ctx.session_id, id) {
            return ToolOutput::err(format!("wrote {n} bytes, but closing stdin failed: {e}"));
        }
    }
    ToolOutput::ok(format!("wrote {n} bytes to process {id}{}", if eof { " and closed its stdin" } else { "" }))
}

fn submit(ctx: &ToolCtx, id: u32, input: &Value) -> ToolOutput {
    let Some(snap) = reg::poll(&ctx.session_id, id) else { return ToolOutput::err(unknown(id)) };
    if !snap.running {
        return ToolOutput::err(format!("process {id} has exited ({}); nothing to submit to", exit_word(&snap)));
    }
    let text = arg_opt_str(input, "text").or_else(|| arg_opt_str(input, "data")).unwrap_or("");
    // Hermes: "\n" on a POSIX pipe; OpenClaw: a carriage return is Enter on a PTY.
    let enter = if snap.pty { "\r" } else { "\n" };
    let mut payload = text.to_string();
    payload.push_str(enter);
    match reg::write_tracked(&ctx.session_id, id, payload.as_bytes()) {
        Ok(()) => ToolOutput::ok(format!("submitted process {id} ({} bytes + Enter)", text.len())),
        Err(e) => ToolOutput::err(e),
    }
}

fn send_keys(ctx: &ToolCtx, id: u32, input: &Value) -> ToolOutput {
    let Some(snap) = reg::poll(&ctx.session_id, id) else { return ToolOutput::err(unknown(id)) };
    if !snap.running {
        return ToolOutput::err(format!("process {id} has exited ({}); nothing to send to", exit_word(&snap)));
    }
    if !snap.pty {
        return ToolOutput::err(format!(
            "process {id} is not running under a terminal, so key sequences have no meaning (it has no PTY to interpret Up/Escape/C-c). \
Start it with job action=start pty=true, or use write/submit to send bytes."
        ));
    }
    let keys = string_list(input.get("keys"));
    let hex = string_list(input.get("hex"));
    let literal = arg_opt_str(input, "literal").unwrap_or("");
    if keys.is_empty() && hex.is_empty() && literal.is_empty() {
        return ToolOutput::err("send-keys needs `keys` (e.g. [\"Enter\"]), `hex` or `literal`");
    }
    let (data, warnings) = match encode_keys(&keys, &hex, literal) {
        Ok(v) => v,
        Err(e) => return ToolOutput::err(e),
    };
    if data.is_empty() {
        return ToolOutput::err(format!("no key data encoded from {}", keys.join(" ")));
    }
    match reg::write_tracked(&ctx.session_id, id, &data) {
        Ok(()) => {
            let mut out = format!("sent {} bytes to process {id}", data.len());
            if !warnings.is_empty() {
                out.push_str(&format!("\nWarnings:\n- {}", warnings.join("\n- ")));
            }
            ToolOutput::ok(out)
        }
        Err(e) => ToolOutput::err(e),
    }
}

fn paste(ctx: &ToolCtx, id: u32, input: &Value) -> ToolOutput {
    let Some(snap) = reg::poll(&ctx.session_id, id) else { return ToolOutput::err(unknown(id)) };
    if !snap.running {
        return ToolOutput::err(format!("process {id} has exited ({}); nothing to paste into", exit_word(&snap)));
    }
    let text = match arg_opt_str(input, "text").or_else(|| arg_opt_str(input, "data")) {
        Some(t) if !t.is_empty() => t,
        _ => return ToolOutput::err("paste needs non-empty `text`"),
    };
    let bracketed = input.get("bracketed").and_then(Value::as_bool).unwrap_or(true) && snap.pty;
    let payload = if bracketed { format!("\x1b[200~{text}\x1b[201~") } else { text.to_string() };
    match reg::write_tracked(&ctx.session_id, id, payload.as_bytes()) {
        Ok(()) => ToolOutput::ok(format!(
            "pasted {} chars to process {id}{}",
            text.chars().count(),
            if bracketed { " (bracketed paste)" } else { "" }
        )),
        Err(e) => ToolOutput::err(e),
    }
}

fn close(ctx: &ToolCtx, id: u32) -> ToolOutput {
    match reg::close_stdin(&ctx.session_id, id) {
        Ok(()) => {
            let pty = reg::poll(&ctx.session_id, id).is_some_and(|s| s.pty);
            ToolOutput::ok(format!("closed stdin of process {id} ({})", if pty { "EOF (^D) sent" } else { "the program sees end-of-file" }))
        }
        Err(e) => ToolOutput::err(e),
    }
}

fn clear(ctx: &ToolCtx, id: u32) -> ToolOutput {
    match reg::clear(&ctx.session_id, id) {
        Ok(()) => {
            CURSORS.lock().unwrap().remove(&(ctx.session_id.clone(), id));
            ToolOutput::ok(format!("cleared the buffered output of process {id}"))
        }
        Err(e) => ToolOutput::err(e),
    }
}

fn remove(ctx: &ToolCtx, id: u32) -> ToolOutput {
    let log = reg::poll(&ctx.session_id, id).map(|s| s.log);
    match reg::remove(&ctx.session_id, id) {
        Ok(()) => {
            CURSORS.lock().unwrap().remove(&(ctx.session_id.clone(), id));
            ToolOutput::ok(match log {
                Some(l) => format!("removed process {id} (its log stays at {})", l.display()),
                None => format!("removed process {id}"),
            })
        }
        Err(e) => ToolOutput::err(e),
    }
}

fn handoff(ctx: &ToolCtx, id: u32, input: &Value) -> ToolOutput {
    let Some(snap) = reg::poll(&ctx.session_id, id) else { return ToolOutput::err(unknown(id)) };
    let note = arg_opt_str(input, "data").or_else(|| arg_opt_str(input, "text")).unwrap_or("").trim().to_string();
    let Some(entry) = reg::get(&ctx.session_id, id) else { return ToolOutput::err(unknown(id)) };
    let (snapshot, exit_file) = {
        let mut e = entry.lock().unwrap();
        e.handed_off = true;
        (e.snapshot.clone(), e.exit_file.clone())
    };
    let pid = snap.pid.map(|p| p.to_string()).unwrap_or_else(|| "(no host pid: the command runs in a container or on a remote host)".into());
    let mut out = format!("handed off process {id}: no completion notice will be delivered for it any more.");
    out.push_str(&format!("\n  pid: {pid}\n  command: {}\n  log: {}", snap.command, snap.log.display()));
    if let Some(e) = &exit_file {
        out.push_str(&format!("\n  exit status: {}", e.display()));
    }
    if let Some(s) = &snapshot {
        // Keep the record, but as a note: `restore` must not re-adopt it.
        let note_path = s.with_extension("handoff.json");
        let _ = std::fs::rename(s, &note_path);
        out.push_str(&format!("\n  snapshot: {}", note_path.display()));
    }
    if snap.detached {
        reg::forget(&ctx.session_id, id);
        out.push_str(&format!(
            "\nThe process keeps running on its own (detached) and this seagent no longer supervises it: read it with `tail -f {log}`, stop it with `kill -TERM -{pid}`.",
            log = snap.log.display()
        ));
    } else if snap.running {
        out.push_str("\nIt is still owned by this seagent and stays in `process list`: it dies when seagent exits (start background work with job detach=true to survive a restart).");
    } else {
        out.push_str(&format!("\nIt has already finished ({}); its output above and in the log is all that is left.", exit_word(&snap)));
    }
    if !note.is_empty() {
        out.push_str(&format!("\nnote: {note}"));
    }
    ToolOutput::ok(out)
}

// ───────────── helpers ─────────────

/// `process 3 running (4.2s, pid 1234, 2.0KB)` / `process 3 exited 0 (1.2s, 15B)`.
fn header(s: &reg::Snapshot) -> (String, bool) {
    let mut tags = String::new();
    if let Some(p) = s.pid {
        tags.push_str(&format!("pid {p}, "));
    }
    tags.push_str(&format!("{}, {}", secs(s.elapsed), bytes(s.bytes)));
    if s.detached {
        tags.push_str(", detached");
    }
    if s.stdin && s.running {
        tags.push_str(", stdin open");
    }
    (format!("process {} {} ({tags})", s.id, status_word(s)), s.running)
}

fn status_word(s: &reg::Snapshot) -> String {
    if s.running {
        "running".into()
    } else {
        match s.exit {
            Some(c) => format!("exited {c}"),
            None => "exited".into(),
        }
    }
}

fn exit_word(s: &reg::Snapshot) -> String {
    match s.exit {
        Some(c) => format!("exit {c}"),
        None => "exit status unknown".into(),
    }
}

fn hint(s: &reg::Snapshot) -> String {
    if s.running && s.stdin && s.idle.as_millis() as u64 >= INPUT_WAIT_IDLE_MS {
        return "\n\nNo new output; this process may be waiting for input. Use process write, send-keys, submit or paste to provide input.".into();
    }
    if s.running {
        return "\n\nProcess still running.".into();
    }
    String::new()
}

fn take_new(session: &str, id: u32, first_tail: usize) -> (String, u64, u64) {
    let mut cursors = CURSORS.lock().unwrap();
    let key = (session.to_string(), id);
    let from = match cursors.get(&key) {
        Some(o) => *o,
        None => reg::offset_now(session, id).unwrap_or(0).saturating_sub(first_tail as u64),
    };
    match reg::read_since(session, id, from) {
        Some((text, next, dropped)) => {
            cursors.insert(key, next);
            (text, next, dropped)
        }
        None => (String::new(), from, 0),
    }
}

fn secs(d: Duration) -> String {
    let s = d.as_secs_f32();
    if s < 60.0 {
        format!("{s:.1}s")
    } else {
        let m = (s / 60.0).floor();
        format!("{m:.0}m{:02.0}s", s - m * 60.0)
    }
}

fn bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n}B")
    } else if n < 1024 * 1024 {
        format!("{:.1}KB", n as f64 / 1024.0)
    } else {
        format!("{:.1}MB", n as f64 / (1024.0 * 1024.0))
    }
}

fn one_line(s: &str, max: usize) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        flat
    } else {
        format!("{}…", flat.chars().take(max).collect::<String>())
    }
}

fn unknown(id: u32) -> String {
    format!("unknown process id {id}; use action=list to see this session's processes")
}

fn parse_id(v: Option<&Value>) -> Result<Option<u32>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_u64().map(|n| Some(n as u32)).ok_or_else(|| "`id` must be a process id".to_string()),
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                return Ok(None);
            }
            let t = t.trim_start_matches("process").trim_start_matches("proc").trim_start_matches("job").trim().trim_start_matches('_');
            t.parse::<u32>().map(Some).map_err(|_| format!("`{s}` is not a process id (see action=list; ids are numbers like 3)"))
        }
        _ => Err("`id` must be a process id".into()),
    }
}

fn timeout_ms(input: &Value, default: u64) -> u64 {
    match input.get("timeout_ms").and_then(Value::as_u64) {
        Some(v) => v,
        None => match arg_opt_u64(input, "timeout") {
            Some(secs) => secs.saturating_mul(1000),
            None => default,
        },
    }
}

fn string_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str()).map(str::to_string).collect(),
        // Models pass "Enter" or "C-c Enter"; whitespace separates tokens.
        Some(Value::String(s)) => s.split_whitespace().map(str::to_string).collect(),
        _ => vec![],
    }
}

// ───────────── key encoding (OpenClaw `pty-keys.ts`) ─────────────

struct Mods {
    ctrl: bool,
    alt: bool,
    shift: bool,
}

impl Mods {
    fn any(&self) -> bool {
        self.ctrl || self.alt || self.shift
    }
    /// xterm modifier parameter (`ESC[1;5A` = ctrl-Up).
    fn param(&self) -> u8 {
        1 + self.shift as u8 + 2 * self.alt as u8 + 4 * self.ctrl as u8
    }
}

/// Named keys with an xterm sequence; the cursor/home/end/paging ones take modifiers.
fn named(key: &str) -> Option<(&'static str, bool)> {
    let (seq, modifiable) = match key {
        "up" => ("\x1b[A", true),
        "down" => ("\x1b[B", true),
        "right" => ("\x1b[C", true),
        "left" => ("\x1b[D", true),
        "home" => ("\x1b[1~", true),
        "end" => ("\x1b[4~", true),
        "pageup" | "pgup" | "ppage" => ("\x1b[5~", true),
        "pagedown" | "pgdn" | "npage" => ("\x1b[6~", true),
        "insert" | "ic" => ("\x1b[2~", true),
        "delete" | "del" | "dc" => ("\x1b[3~", true),
        "f1" => ("\x1bOP", true),
        "f2" => ("\x1bOQ", true),
        "f3" => ("\x1bOR", true),
        "f4" => ("\x1bOS", true),
        "f5" => ("\x1b[15~", true),
        "f6" => ("\x1b[17~", true),
        "f7" => ("\x1b[18~", true),
        "f8" => ("\x1b[19~", true),
        "f9" => ("\x1b[20~", true),
        "f10" => ("\x1b[21~", true),
        "f11" => ("\x1b[23~", true),
        "f12" => ("\x1b[24~", true),
        "enter" | "return" => ("\r", false),
        "tab" => ("\t", false),
        "escape" | "esc" => ("\x1b", false),
        "space" => (" ", false),
        "bspace" | "backspace" => ("\x7f", false),
        "btab" => ("\x1b[Z", false),
        "kp/" => ("\x1bOo", false),
        "kp*" => ("\x1bOj", false),
        "kp-" => ("\x1bOm", false),
        "kp+" => ("\x1bOk", false),
        "kp7" => ("\x1bOw", false),
        "kp8" => ("\x1bOx", false),
        "kp9" => ("\x1bOy", false),
        "kp4" => ("\x1bOt", false),
        "kp5" => ("\x1bOu", false),
        "kp6" => ("\x1bOv", false),
        "kp1" => ("\x1bOq", false),
        "kp2" => ("\x1bOr", false),
        "kp3" => ("\x1bOs", false),
        "kp0" => ("\x1bOp", false),
        "kp." => ("\x1bOn", false),
        "kpenter" => ("\x1bOM", false),
        _ => return None,
    };
    Some((seq, modifiable))
}

fn ctrl_char(c: char) -> Option<char> {
    match c {
        '?' => Some('\x7f'),
        ' ' => Some('\x00'),
        _ => {
            let u = c.to_ascii_uppercase() as u32;
            (64..=95).contains(&u).then(|| char::from_u32(u & 0x1f).unwrap())
        }
    }
}

fn parse_mods(token: &str) -> (Mods, String) {
    let mut mods = Mods { ctrl: false, alt: false, shift: false };
    let mut rest = token.to_string();
    while rest.chars().count() > 2 && rest.as_bytes().get(1) == Some(&b'-') {
        match rest.chars().next().unwrap().to_ascii_lowercase() {
            'c' => mods.ctrl = true,
            'm' => mods.alt = true,
            's' => mods.shift = true,
            _ => break,
        }
        rest = rest.chars().skip(2).collect();
    }
    (mods, rest)
}

fn apply_mods(seq: &str, mods: &Mods) -> String {
    let mut value: String = seq.to_string();
    if mods.shift && value.chars().count() == 1 {
        let c = value.chars().next().unwrap();
        if c.is_ascii_lowercase() {
            value = c.to_ascii_uppercase().to_string();
        }
    }
    if mods.ctrl {
        if let Some(c) = value.chars().next().filter(|_| value.chars().count() == 1) {
            if let Some(c) = ctrl_char(c) {
                value = c.to_string();
            }
        }
    }
    if mods.alt {
        value = format!("\x1b{value}");
    }
    value
}

fn encode_token(raw: &str, warnings: &mut Vec<String>) -> String {
    let token = raw.trim();
    if token.is_empty() {
        return String::new();
    }
    // caret notation: ^C, ^[
    let chars: Vec<char> = token.chars().collect();
    if chars.len() == 2 && chars[0] == '^' {
        if let Some(c) = ctrl_char(chars[1]) {
            return c.to_string();
        }
    }
    let (mods, base) = parse_mods(token);
    let lower = base.to_ascii_lowercase();
    if lower == "tab" && mods.shift {
        return "\x1b[Z".into();
    }
    if let Some((seq, modifiable)) = named(&lower) {
        if modifiable && mods.any() {
            // Bare cursor sequences omit the parameter; xterm modifiers need it.
            let parameter = seq.get(2..seq.len() - 1).filter(|p| !p.is_empty()).unwrap_or("1");
            return format!("\x1b[{parameter};{}{}", mods.param(), seq.chars().last().unwrap());
        }
        return apply_mods(seq, &mods);
    }
    let base_chars: Vec<char> = base.chars().collect();
    if base_chars.len() == 1 {
        return apply_mods(&base, &mods);
    }
    if mods.any() {
        warnings.push(format!("unknown key `{base}` with modifiers; sent literally"));
    }
    base
}

fn parse_hex_byte(raw: &str) -> Option<u8> {
    let lower = raw.trim().to_ascii_lowercase();
    let t = lower.strip_prefix("0x").unwrap_or(&lower);
    if t.is_empty() || t.len() > 2 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u8::from_str_radix(t, 16).ok()
}

fn encode_keys(keys: &[String], hex: &[String], literal: &str) -> Result<(Vec<u8>, Vec<String>), String> {
    let mut warnings = Vec::new();
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(literal.as_bytes());
    for h in hex {
        match parse_hex_byte(h) {
            Some(b) => data.push(b),
            None => warnings.push(format!("invalid hex byte `{h}` (skipped)")),
        }
    }
    for k in keys {
        data.extend_from_slice(encode_token(k, &mut warnings).as_bytes());
    }
    Ok((data, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::Job;
    use crate::testutil::ctx;

    fn start(c: &ToolCtx, cmd: &str, extra: Value) -> u32 {
        let mut v = json!({"action":"start","command":cmd});
        if let Some(o) = extra.as_object() {
            for (k, val) in o {
                v[k] = val.clone();
            }
        }
        let o = Job.call(c, v);
        assert!(!o.is_error, "{}", o.content);
        o.content.split_whitespace().nth(1).unwrap().parse().unwrap()
    }

    fn until(c: &ToolCtx, id: u32, needle: &str) -> String {
        let t0 = Instant::now();
        loop {
            let t = Proc.call(c, json!({"action":"log","id":id,"limit":200})).content;
            if t.contains(needle) || t0.elapsed() > Duration::from_secs(10) {
                return t;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn list_poll_log_wait_and_ids_are_shared_with_job() {
        let c = ctx("proclist");
        let id = start(&c, "echo first; echo second 1>&2; sleep 0.2; echo third", json!({}));
        let l = Proc.call(&c, json!({"action":"list"}));
        assert!(!l.is_error && l.content.contains(&format!("{id} ")) && l.content.contains("echo first"), "{}", l.content);
        let w = Proc.call(&c, json!({"action":"wait","id":id,"timeout_ms":8000}));
        assert!(w.content.contains(&format!("process {id} exited 0")) && w.content.contains("third"), "{}", w.content);
        let p = Proc.call(&c, json!({"action":"poll","id":format!("job {id}")}));
        assert!(p.content.contains("exited 0"), "{}", p.content);
        let l = Proc.call(&c, json!({"action":"log","id":id,"offset":0,"limit":2}));
        assert!(l.content.starts_with("first\nsecond") && l.content.contains("lines 0–2 of 3"), "{}", l.content);
        let l = Proc.call(&c, json!({"action":"log","id":id}));
        assert!(l.content.contains("first") && l.content.contains("third"), "{}", l.content);
        // Errors name the reason.
        assert!(Proc.call(&c, json!({"action":"poll","id":999})).content.contains("unknown process id 999"));
        assert!(Proc.call(&c, json!({"action":"poll","id":"abc"})).content.contains("is not a process id"));
        assert!(Proc.call(&c, json!({"action":"nope","id":id})).content.contains("unknown action `nope`"));
        assert!(Proc.call(&c, json!({"action":"list"})).content.contains(&format!("{id}")));
    }

    #[test]
    fn write_submit_close_clear_remove() {
        let c = ctx("procwr");
        let id = start(&c, "while read -r line; do echo \"got:$line\"; done", json!({}));
        let o = Proc.call(&c, json!({"action":"submit","id":id,"text":"hello"}));
        assert!(!o.is_error && o.content.contains("submitted"), "{}", o.content);
        assert!(until(&c, id, "got:hello").contains("got:hello"));
        let o = Proc.call(&c, json!({"action":"write","id":id,"text":"raw"}));
        assert!(o.content.contains("wrote 3 bytes"), "{}", o.content);
        let o = Proc.call(&c, json!({"action":"close","id":id}));
        assert!(o.content.contains("closed stdin") && o.content.contains("end-of-file"), "{}", o.content);
        let w = Proc.call(&c, json!({"action":"wait","id":id,"timeout_ms":8000}));
        assert!(w.content.contains("exited 0"), "{}", w.content);
        assert!(Proc.call(&c, json!({"action":"write","id":id,"text":"x"})).content.contains("has exited"));
        assert!(Proc.call(&c, json!({"action":"remove","id":id})).content.contains("removed process"));
        assert!(Proc.call(&c, json!({"action":"poll","id":id})).content.contains("unknown process id"));

        // clear keeps the process, drops its output (buffer and log).
        let id = start(&c, "echo doomed; sleep 30", json!({}));
        assert!(until(&c, id, "doomed").contains("doomed"));
        let o = Proc.call(&c, json!({"action":"clear","id":id}));
        assert!(o.content.contains("cleared the buffered output"), "{}", o.content);
        assert!(!Proc.call(&c, json!({"action":"log","id":id})).content.contains("doomed"));
        // remove refuses while running, kill ends it.
        assert!(Proc.call(&c, json!({"action":"remove","id":id})).content.contains("still running"));
        assert!(Proc.call(&c, json!({"action":"kill","id":id})).content.contains("killed process"));
        let w = Proc.call(&c, json!({"action":"wait","id":id,"timeout_ms":8000}));
        assert!(w.content.contains("exited -9") || w.content.contains("signal"), "{}", w.content);
    }

    #[test]
    fn wait_timeout_is_not_an_error_and_poll_shows_new_output_only() {
        let c = ctx("procwait");
        let id = start(&c, "echo one; sleep 30", json!({}));
        let t0 = Instant::now();
        let o = Proc.call(&c, json!({"action":"wait","id":id,"timeout_ms":300}));
        assert!(t0.elapsed() < Duration::from_secs(5) && !o.is_error, "{}", o.content);
        assert!(o.content.contains("still running") && o.content.contains("not an error"), "{}", o.content);
        let p = Proc.call(&c, json!({"action":"poll","id":id}));
        assert!(p.content.contains("one"), "the first poll shows the output so far: {}", p.content);
        let p = Proc.call(&c, json!({"action":"poll","id":id}));
        assert!(p.content.contains("(no new output)"), "the next one reports only what is new: {}", p.content);
        Proc.call(&c, json!({"action":"kill","id":id}));
    }

    #[test]
    fn send_keys_and_paste_need_a_terminal_and_encode_keys() {
        let c = ctx("prockeys");
        // Encoding: the OpenClaw pty-keys table.
        let (b, w) = encode_keys(&["Enter".into(), "C-c".into(), "^D".into()], &[], "").unwrap();
        assert_eq!(b, b"\r\x03\x04");
        assert!(w.is_empty());
        let (b, _) = encode_keys(&["Up".into(), "S-Tab".into(), "C-M-x".into()], &["1b".into(), "zz".into()], "ab").unwrap();
        assert_eq!(b, b"ab\x1b\x1b[A\x1b[Z\x1b\x18", "C-M-x is ESC then ^X");
        let (b, _) = encode_keys(&["PageUp".into(), "F5".into()], &[], "").unwrap();
        assert_eq!(b, b"\x1b[5~\x1b[15~");

        let id = start(&c, "while read -r line; do echo \"read:$line\"; done", json!({"pty":true}));
        let non_pty = start(&c, "cat", json!({}));
        assert!(Proc.call(&c, json!({"action":"send-keys","id":non_pty,"keys":["Enter"]})).content.contains("not running under a terminal"));
        let o = Proc.call(&c, json!({"action":"send-keys","id":id,"keys":["typed"]}));
        assert!(!o.is_error && o.content.contains("sent 5 bytes"), "{}", o.content);
        // send-keys sends no newline: the line still holds what it typed.
        let o = Proc.call(&c, json!({"action":"submit","id":id,"text":"hello"}));
        assert!(!o.is_error, "{}", o.content);
        assert!(until(&c, id, "read:").contains("read:typedhello"), "{}", until(&c, id, "read:"));
        // C-u clears the terminal's line, so the next submit sees only its own text.
        assert!(!Proc.call(&c, json!({"action":"send-keys","id":id,"keys":["C-u"]})).is_error);
        Proc.call(&c, json!({"action":"submit","id":id,"text":"clean"}));
        assert!(until(&c, id, "read:clean").contains("read:clean"), "{}", until(&c, id, "read:"));
        Proc.call(&c, json!({"action":"kill","id":id}));
        Proc.call(&c, json!({"action":"kill","id":non_pty}));
    }

    #[test]
    fn paste_uses_bracketed_markers_and_handoff_reports_the_pid() {
        let c = ctx("procpaste");
        let id = start(&c, "cat -v", json!({"pty":true}));
        let o = Proc.call(&c, json!({"action":"paste","id":id,"text":"hi"}));
        assert!(o.content.contains("bracketed paste"), "{}", o.content);
        #[cfg(unix)]
        {
            let t = until(&c, id, "201~");
            assert!(t.contains("^[[200~hi^[[201~"), "cat -v shows the markers: {t}");
        }
        // Windows: ConPTY (conhost) reads the markers as VT input and delivers the pasted text
        // as key events, so a program that did not ask for bracketed paste sees just the text.
        #[cfg(windows)]
        {
            let t = until(&c, id, "hi");
            assert!(t.contains("hi"), "the pasted text arrives: {t}");
        }
        // A pipe process gets the text as-is (no terminal to interpret the markers).
        let pipe = start(&c, "cat", json!({}));
        let o = Proc.call(&c, json!({"action":"paste","id":pipe,"text":"plain"}));
        assert!(!o.content.contains("bracketed"), "{}", o.content);
        assert!(until(&c, pipe, "plain").contains("plain"));

        let h = Proc.call(&c, json!({"action":"handoff","id":id,"data":"watch the build"}));
        assert!(!h.is_error && h.content.contains("handed off process"), "{}", h.content);
        assert!(h.content.contains("pid: ") && h.content.contains("note: watch the build"), "{}", h.content);
        assert!(h.content.contains("dies when seagent exits"), "a job that is not detached is reported honestly: {}", h.content);
        // No completion notice for a handed-off process.
        let id2 = start(&c, "echo quick", json!({}));
        let h = Proc.call(&c, json!({"action":"handoff","id":id2}));
        assert!(h.content.contains("already finished") || h.content.contains("handed off"), "{}", h.content);
        Proc.call(&c, json!({"action":"kill","id":id}));
        Proc.call(&c, json!({"action":"kill","id":pipe}));
    }

    /// End to end: a detached job is adopted by a fresh registry and reported as
    /// running, then as exited with the status from its exit file.
    #[test]
    fn detached_job_is_adopted_after_a_restart() {
        let c = ctx("procrestart");
        let o = Job.call(&c, json!({"action":"start","command":"sleep 1; echo finished","detach":true}));
        assert!(o.content.contains("detached"), "{}", o.content);
        let id: u32 = o.content.split_whitespace().nth(1).unwrap().parse().unwrap();
        // seagent restarts: the in-memory entry is gone, the process and its snapshot are not.
        assert!(crate::exec::process::forget(&c.session_id, id));
        assert!(crate::exec::process::poll(&c.session_id, id).is_none());
        let l = Proc.call(&c, json!({"action":"list"}));
        assert!(l.content.contains(&format!("{id} ")) && l.content.contains("sleep 1"), "adopted from its snapshot: {}", l.content);
        let s = crate::exec::process::poll(&c.session_id, id).unwrap();
        assert!(s.running && s.detached, "{s:?}");
        let w = Proc.call(&c, json!({"action":"wait","id":id,"timeout_ms":15000}));
        assert!(w.content.contains(&format!("process {id} exited 0")) && w.content.contains("finished"), "{}", w.content);
        assert!(Proc.call(&c, json!({"action":"log","id":id})).content.contains("finished"));
        assert!(Proc.call(&c, json!({"action":"remove","id":id})).content.contains("removed process"));
    }

    /// Effects are honest: typing into a shell runs a command.
    #[test]
    fn effects_are_judged_for_typed_input() {
        let c = ctx("proceff");
        assert_eq!(Proc.effects(&c, &json!({"action":"write","id":1,"text":"rm -rf /"})), vec![Effect::Exec { command: "rm -rf /".into() }]);
        assert_eq!(Proc.effects(&c, &json!({"action":"submit","id":1,"text":"make"})), vec![Effect::Exec { command: "make".into() }]);
        assert!(Proc.effects(&c, &json!({"action":"poll","id":1})).is_empty());
        assert_eq!(Proc.spec().name, "process");
    }
}
