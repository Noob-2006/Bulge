//! Google Meet bot (Hermes `plugins/google_meet`, MIT): `meet_join`, `meet_status`,
//! `meet_transcript`, `meet_leave`, `meet_say`, the `seagent meet` CLI and session-end cleanup.
//!
//! One active meeting at a time, recorded in `<data>/meetings/.active.json` (`pid`,
//! `meeting_id`, `out_dir`, `url`, `started_at`, `session_id`, `log_path`, `mode`). The bot is a
//! detached `seagent meet bot` process driving Chromium over DevTools ([`super::meet_bot`]); the
//! only IPC is files in `<data>/meetings/<meeting-id>/`: `status.json`, `transcript.txt`,
//! `say_queue.jsonl`. Explicit by design: only `https://meet.google.com/` URLs passed in are
//! joined — no calendar scanning, no auto-dial, no automatic consent announcement.
//! `node` runs the same operation on a paired seagent node (`system.run seagent meet … --json`).

use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use seagent_kernel::hooks::{Hook, HookDecision, HookEvent};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How the bot process is started (tests substitute a fake).
#[derive(Clone)]
pub struct Manager {
    pub root: PathBuf,
    pub bot: Vec<String>,
    /// Extra environment for the bot (realtime key, Chromium path…).
    pub env: Vec<(String, String)>,
}

pub fn root(data: &Path) -> PathBuf {
    data.join("meetings")
}

/// Hermes `MEET_URL_RE`: a three-segment code, a lookup URL, or `/new`.
pub fn is_safe_meet_url(url: &str) -> bool {
    let Some(rest) = url.trim().strip_prefix("https://meet.google.com/") else { return false };
    let path = rest.split(['/', '?', '#']).next().unwrap_or("");
    let seg = |s: &str| s.len() >= 3 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let code = { let p: Vec<&str> = path.split('-').collect(); p.len() == 3 && p.iter().all(|s| seg(s)) };
    let lookup = rest.strip_prefix("lookup/").map(|r| r.split(['/', '?', '#']).next().unwrap_or("")).is_some_and(|x| !x.is_empty());
    code || lookup || path == "new"
}

pub fn meeting_id_from_url(url: &str) -> String {
    let rest = url.trim().strip_prefix("https://meet.google.com/").unwrap_or("");
    let path = rest.split(['/', '?', '#']).next().unwrap_or("");
    let p: Vec<&str> = path.split('-').collect();
    if p.len() == 3 && p.iter().all(|s| s.len() >= 3 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())) {
        return path.to_string();
    }
    format!("meet-{}", now_secs() as u64)
}

pub fn now_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn read_json(p: &Path) -> Option<Value> {
    let t = std::fs::read_to_string(p).ok()?;
    serde_json::from_str(t.trim_start_matches('\u{feff}')).ok()
}

pub fn write_json(p: &Path, v: &Value) {
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = seagent_kernel::util::atomic_write(p, serde_json::to_string_pretty(v).unwrap_or_default().as_bytes());
}

fn pid_alive(pid: i64) -> bool {
    pid > 0 && seagent_browser::util::pid_alive(pid as i32)
}

fn no_active() -> Value {
    json!({"ok": false, "reason": "no active meeting"})
}

pub struct JoinOpts {
    pub url: String,
    pub guest_name: String,
    pub duration: Option<String>,
    pub headed: bool,
    pub mode: String,
    pub session_id: Option<String>,
    pub auth_state: Option<String>,
}

impl Manager {
    fn active_file(&self) -> PathBuf {
        self.root.join(".active.json")
    }

    fn active(&self) -> Option<Value> {
        read_json(&self.active_file())
    }

    /// Spawn the bot for `url`, stopping any running one first (one active meeting).
    pub fn start(&self, o: &JoinOpts) -> Value {
        if !is_safe_meet_url(&o.url) {
            return json!({"ok": false, "error": format!("refusing: only https://meet.google.com/ URLs are allowed. got: {:?}", o.url)});
        }
        if self.active().and_then(|a| a["pid"].as_i64()).is_some_and(pid_alive) {
            self.stop("replaced by new meet_join");
        }
        let id = meeting_id_from_url(&o.url);
        let out = self.root.join(&id);
        if let Err(e) = std::fs::create_dir_all(&out) {
            return json!({"ok": false, "error": format!("cannot create {}: {e}", out.display())});
        }
        for f in ["transcript.txt", "status.json"] {
            let _ = std::fs::remove_file(out.join(f));
        }
        let log_path = out.join("bot.log");
        let log = match std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
            Ok(f) => f,
            Err(e) => return json!({"ok": false, "error": format!("cannot open {}: {e}", log_path.display())}),
        };
        let mut cmd = std::process::Command::new(&self.bot[0]);
        cmd.args(&self.bot[1..]).stdin(std::process::Stdio::null()).stdout(log.try_clone().map(std::process::Stdio::from).unwrap_or(std::process::Stdio::null())).stderr(std::process::Stdio::from(log));
        cmd.env("SEAGENT_MEET_URL", &o.url).env("SEAGENT_MEET_OUT_DIR", &out).env("SEAGENT_MEET_GUEST_NAME", &o.guest_name).env("SEAGENT_MEET_MODE", &o.mode);
        if o.headed {
            cmd.env("SEAGENT_MEET_HEADED", "1");
        }
        if let Some(d) = &o.duration {
            cmd.env("SEAGENT_MEET_DURATION", d);
        }
        if let Some(a) = &o.auth_state {
            cmd.env("SEAGENT_MEET_AUTH_STATE", a);
        }
        cmd.envs(self.env.iter().map(|(k, v)| (k, v)));
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid is async-signal-safe; detaches the bot from our signals.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => return json!({"ok": false, "error": format!("cannot start the meet bot: {e}")}),
        };
        let pid = child.id();
        // Reap it whenever it exits so it never lingers as a zombie in a long-lived daemon.
        std::thread::spawn(move || {
            let mut c = child;
            let _ = c.wait();
        });
        let rec = json!({"pid": pid, "meeting_id": id, "out_dir": out, "url": o.url, "started_at": now_secs(), "session_id": o.session_id, "log_path": log_path, "mode": o.mode});
        write_json(&self.active_file(), &rec);
        let mut v = json!({"ok": true});
        v.as_object_mut().unwrap().extend(rec.as_object().cloned().unwrap_or_default());
        v
    }

    /// Where a saved Google sign-in state (Playwright `storage_state` JSON — cookies) lives.
    pub fn auth_path(&self) -> PathBuf {
        self.root.join("auth.json")
    }

    /// `[meetings.google_meet] auth_state`, else the saved `<data>/meetings/auth.json`
    /// (upstream `_cmd_join` auto-uses the file `hermes meet auth` wrote).
    pub fn auth_state(&self, cfg: &toml::Table) -> Option<String> {
        let cfg = cfg.get("auth_state").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        cfg.or_else(|| self.auth_path().is_file().then(|| self.auth_path().display().to_string()))
    }

    pub fn status(&self) -> Value {
        let Some(a) = self.active() else { return no_active() };
        let pid = a["pid"].as_i64().unwrap_or(0);
        let mut v = json!({"ok": true, "alive": pid_alive(pid), "pid": pid, "meetingId": a["meeting_id"], "url": a["url"], "startedAt": a["started_at"], "outDir": a["out_dir"]});
        if let Some(Value::Object(s)) = read_json(&Path::new(a["out_dir"].as_str().unwrap_or("")).join("status.json")) {
            v.as_object_mut().unwrap().extend(s);
        }
        v
    }

    pub fn transcript(&self, last: Option<usize>) -> Value {
        let Some(a) = self.active() else { return no_active() };
        let tp = Path::new(a["out_dir"].as_str().unwrap_or("")).join("transcript.txt");
        let text = std::fs::read_to_string(&tp).unwrap_or_default();
        let lines: Vec<&str> = text.trim_start_matches('\u{feff}').lines().filter(|l| !l.trim().is_empty()).collect();
        let shown: Vec<&str> = match last {
            Some(n) => lines[lines.len().saturating_sub(n)..].to_vec(),
            None => lines.clone(),
        };
        json!({"ok": true, "meetingId": a["meeting_id"], "lines": shown, "total": lines.len(), "path": tp})
    }

    pub fn enqueue_say(&self, text: &str) -> Value {
        let text = text.trim();
        if text.is_empty() {
            return json!({"ok": false, "reason": "text is required"});
        }
        let Some(a) = self.active() else { return no_active() };
        if a["mode"] != "realtime" {
            return json!({"ok": false, "reason": "active meeting is in transcribe mode — pass mode='realtime' to meet_join to enable agent speech"});
        }
        let out = PathBuf::from(a["out_dir"].as_str().unwrap_or(""));
        if !out.is_dir() {
            return json!({"ok": false, "reason": format!("out_dir missing: {}", out.display())});
        }
        let q = out.join("say_queue.jsonl");
        let id = seagent_net::crypto::random_token(6);
        let entry = json!({"id": id, "text": text});
        let r = super::with_lock(&q, || {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&q)?;
            writeln!(f, "{entry}")
        });
        if let Err(e) = r {
            return json!({"ok": false, "reason": format!("cannot queue speech: {e}")});
        }
        json!({"ok": true, "meetingId": a["meeting_id"], "enqueued_id": id, "queue_path": q})
    }

    /// SIGTERM the bot (SIGKILL after 10 s), then clear the active pointer.
    pub fn stop(&self, reason: &str) -> Value {
        let Some(a) = self.active() else { return no_active() };
        let pid = a["pid"].as_i64().unwrap_or(0);
        if pid_alive(pid) {
            // SAFETY: plain kill(2) on the bot we spawned.
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            let mut gone = false;
            for _ in 0..40 {
                if !pid_alive(pid) {
                    gone = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            if !gone {
                // SAFETY: as above.
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
            }
        }
        let _ = std::fs::remove_file(self.active_file());
        let out = a["out_dir"].as_str().map(|o| Path::new(o).join("transcript.txt"));
        json!({"ok": true, "reason": reason, "meetingId": a["meeting_id"], "transcriptPath": out})
    }

    /// The session that started the active meeting (session-end cleanup).
    pub fn active_session(&self) -> Option<String> {
        self.active()?.get("session_id")?.as_str().map(str::to_string)
    }

    /// Whether a bot is running right now (upstream `_on_session_end` guard).
    pub fn alive(&self) -> bool {
        self.active().and_then(|a| a["pid"].as_i64()).is_some_and(pid_alive)
    }
}

/// Upstream `on_session_end`: leave a still-running call so we never orphan a headless
/// Chromium. Only the meeting this session started (or one launched from the CLI, which has
/// no session id) is stopped — a daemon hosts many sessions and must not hang up theirs.
pub struct SessionEndHook {
    mgr: Arc<Manager>,
}

impl SessionEndHook {
    pub fn new(mgr: Arc<Manager>) -> SessionEndHook {
        SessionEndHook { mgr }
    }
}

impl Hook for SessionEndHook {
    fn name(&self) -> String {
        "google-meet-session-end".into()
    }

    fn wants(&self, event: HookEvent, _tool: Option<&str>) -> bool {
        event == HookEvent::SessionEnd
    }

    fn run(&self, _event: HookEvent, payload: &Value) -> Result<HookDecision, String> {
        let ending = payload.get("session_id").and_then(Value::as_str).unwrap_or("");
        let ours = self.mgr.active_session().is_none_or(|s| s.is_empty() || s == ending);
        if ours && self.mgr.alive() {
            self.mgr.stop("session ended");
        }
        Ok(HookDecision::Allow)
    }
}

// ───────────── tools ─────────────

#[derive(Clone, Copy, PartialEq)]
enum Op {
    Join,
    Status,
    Transcript,
    Leave,
    Say,
}

pub struct MeetTool {
    op: Op,
    mgr: Arc<Manager>,
    cfg: Arc<toml::Table>,
}

pub fn tools(mgr: Arc<Manager>, cfg: toml::Table) -> Vec<Arc<dyn Tool>> {
    let cfg = Arc::new(cfg);
    [Op::Join, Op::Status, Op::Transcript, Op::Leave, Op::Say].into_iter().map(|op| Arc::new(MeetTool { op, mgr: mgr.clone(), cfg: cfg.clone() }) as Arc<dyn Tool>).collect()
}

fn s(v: &Value) -> Value {
    json!({"type": "string", "description": v})
}

fn spec(op: Op) -> (&'static str, &'static str, Value) {
    let node = json!({"type": "string", "description": "Paired seagent node id to run on (see `seagent nodes list`); default: this machine."});
    let obj = |props: Value, req: &[&str]| {
        let mut v = json!({"type": "object", "properties": props, "additionalProperties": false});
        if !req.is_empty() {
            v["required"] = json!(req);
        }
        v
    };
    match op {
        Op::Join => ("meet_join", "Join a Google Meet call and start scraping live captions into a transcript file. Only meet.google.com URLs are accepted; no calendar scanning, no auto-dial. Spawns a headless Chromium subprocess that runs in parallel with the agent loop — returns immediately. Poll with meet_status and read captions with meet_transcript. Reminder to the agent: you should announce yourself in the meeting (there is no automatic consent announcement).", obj(json!({
            "url": s(&json!("Full https://meet.google.com/... URL. Required.")),
            "mode": {"type": "string", "enum": ["transcribe", "realtime"], "description": "transcribe (default): listen-only, scrape captions. realtime: also enable agent speech via meet_say (requires a TTS provider + PulseAudio for the virtual microphone)."},
            "guest_name": s(&json!("Display name to use when joining as guest. Defaults to 'SE Agent Agent'.")),
            "duration": s(&json!("Optional max duration before auto-leave (e.g. '30m', '2h', '90s'). Omit to stay until meet_leave is called.")),
            "headed": {"type": "boolean", "description": "Run Chromium headed instead of headless (debug only). Default false."},
            "node": node
        }), &["url"])),
        Op::Status => ("meet_status", "Report the current Meet session state — whether the bot is alive, has joined, is sitting in the lobby, number of transcript lines captured, and last-caption timestamp.", obj(json!({"node": node}), &[])),
        Op::Transcript => ("meet_transcript", "Read the scraped transcript for the active Meet session. Returns full transcript unless 'last' is set, in which case returns the last N lines only.", obj(json!({"last": {"type": "integer", "minimum": 1, "description": "Optional: return only the last N caption lines. Useful for polling during a meeting without re-reading the whole transcript."}, "node": node}), &[])),
        Op::Leave => ("meet_leave", "Leave the active Meet call cleanly, stop caption scraping, and finalize the transcript file. Safe to call when no meeting is active — returns ok=false with a reason.", obj(json!({"node": node}), &[])),
        Op::Say => ("meet_say", "Speak text into the active Meet call. Requires the active meeting to have been joined with mode='realtime'. The text is synthesized (the configured TTS chain) and streamed into Chrome's fake microphone via a PulseAudio null-sink. Returns immediately — the actual speech lags by a couple of seconds.", obj(json!({"text": s(&json!("Text to speak.")), "node": node}), &["text"])),
    }
}

/// `{success, …result}` like upstream's `_dispatch`.
fn wrap(res: Value, node: Option<&str>) -> String {
    let mut v = json!({"success": res["ok"].as_bool().unwrap_or(false)});
    if let Some(n) = node {
        v["node"] = json!(n);
    }
    v.as_object_mut().unwrap().extend(res.as_object().cloned().unwrap_or_default());
    v.to_string()
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// `seagent meet <args> --json` on a paired node.
fn remote(node: &str, args: &[String]) -> Value {
    if node == "auto" {
        return json!({"ok": false, "error": "name the node to use (`seagent nodes list`); 'auto' needs exactly one paired node id"});
    }
    let cmd = std::iter::once("seagent meet".to_string()).chain(args.iter().map(|a| sh_quote(a))).chain(std::iter::once("--json".to_string())).collect::<Vec<_>>().join(" ");
    match seagent_app::node::invoke(node, "system.run", json!({"command": cmd, "timeoutMs": 60_000}), Duration::from_secs(70), None) {
        Ok(Value::String(out)) => serde_json::from_str(out.trim()).unwrap_or_else(|_| json!({"ok": false, "error": format!("remote node returned: {}", out.trim())})),
        Ok(v) => v,
        Err(e) => json!({"ok": false, "error": format!("remote node meet failed: {e}")}),
    }
}

impl MeetTool {
    fn run(&self, ctx: &ToolCtx, a: &Value) -> String {
        let node = a.get("node").and_then(Value::as_str).map(str::trim).filter(|n| !n.is_empty());
        let local = |args: Vec<String>| node.map(|n| remote(n, &args));
        match self.op {
            Op::Join => {
                let url = a.get("url").and_then(Value::as_str).unwrap_or("").trim().to_string();
                if url.is_empty() {
                    return json!({"success": false, "error": "url is required"}).to_string();
                }
                let mode = a.get("mode").and_then(Value::as_str).unwrap_or("transcribe").trim().to_lowercase();
                if mode != "transcribe" && mode != "realtime" {
                    return json!({"success": false, "error": format!("mode must be 'transcribe' or 'realtime' (got {mode:?})")}).to_string();
                }
                let guest = a.get("guest_name").and_then(Value::as_str).filter(|g| !g.trim().is_empty()).map(str::to_string).or_else(|| self.cfg.get("guest_name").and_then(|v| v.as_str()).map(str::to_string)).unwrap_or_else(|| "SE Agent Agent".into());
                let duration = a.get("duration").and_then(|d| d.as_str().map(str::to_string).or_else(|| d.as_u64().map(|n| n.to_string())));
                let headed = a.get("headed").and_then(Value::as_bool).unwrap_or(false);
                let mut args = vec!["join".to_string(), url.clone(), "--mode".into(), mode.clone(), "--guest-name".into(), guest.clone()];
                if let Some(d) = &duration {
                    args.extend(["--duration".into(), d.clone()]);
                }
                if headed {
                    args.push("--headed".into());
                }
                let res = local(args).unwrap_or_else(|| {
                    if let Some(e) = super::meet_bot::prerequisites(&self.cfg) {
                        return json!({"ok": false, "error": e});
                    }
                    self.mgr.start(&JoinOpts { url, guest_name: guest, duration, headed, mode, session_id: Some(ctx.session_id.clone()).filter(|s| !s.is_empty()), auth_state: self.mgr.auth_state(&self.cfg) })
                });
                wrap(res, node)
            }
            Op::Status => wrap(local(vec!["status".into()]).unwrap_or_else(|| self.mgr.status()), node),
            Op::Transcript => {
                let last = a.get("last").and_then(Value::as_u64).filter(|n| *n >= 1).map(|n| n as usize);
                let mut args = vec!["transcript".to_string()];
                if let Some(n) = last {
                    args.extend(["--last".into(), n.to_string()]);
                }
                wrap(local(args).unwrap_or_else(|| self.mgr.transcript(last)), node)
            }
            Op::Leave => wrap(local(vec!["stop".into()]).unwrap_or_else(|| self.mgr.stop("agent called meet_leave")), node),
            Op::Say => {
                let text = a.get("text").and_then(Value::as_str).unwrap_or("").trim().to_string();
                if text.is_empty() {
                    return json!({"success": false, "error": "text is required"}).to_string();
                }
                wrap(local(vec!["say".into(), text.clone()]).unwrap_or_else(|| self.mgr.enqueue_say(&text)), node)
            }
        }
    }
}

impl Tool for MeetTool {
    fn spec(&self) -> ToolSpec {
        let (name, d, schema) = spec(self.op);
        let read = matches!(self.op, Op::Status | Op::Transcript);
        ToolSpec { name: name.into(), description: d.into(), input_schema: schema, parallel_safe: read, idempotent: read, pinned: false }
    }

    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        match self.op {
            Op::Join => vec![Effect::Net { dest: input.get("url").and_then(Value::as_str).unwrap_or("https://meet.google.com/").to_string(), payload: "join a Google Meet call (headless Chromium) and record its captions".into() }],
            Op::Say => vec![Effect::Send { channel: "google_meet".into(), payload: input.get("text").and_then(Value::as_str).unwrap_or("").to_string() }],
            _ => vec![],
        }
    }

    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let out = self.run(ctx, &input);
        let ok = serde_json::from_str::<Value>(&out).ok().and_then(|v| v["success"].as_bool()).unwrap_or(false);
        // A soft failure (`no active meeting`) is still a normal answer for the model.
        let hard = !ok && serde_json::from_str::<Value>(&out).ok().is_some_and(|v| v.get("error").is_some());
        ToolOutput { content: out, is_error: hard, ui_resource: None }
    }
}

// ───────────── CLI ─────────────

pub const USAGE: &str = "usage: seagent meet <join URL [--mode transcribe|realtime] [--guest-name N] [--duration 30m] [--headed] [--node NAME] | status | transcript [--last N] | say TEXT [--node NAME] | stop | setup | auth> [--json]";

fn print_result(res: &Value, json_out: bool) -> i32 {
    if json_out {
        println!("{res}");
    } else {
        println!("{}", serde_json::to_string_pretty(res).unwrap_or_default());
    }
    if res["ok"].as_bool().unwrap_or(false) {
        0
    } else {
        1
    }
}

pub fn cli(mgr: &Manager, cfg: &toml::Table, argv: &[String]) -> Result<i32, String> {
    let json_out = argv.iter().any(|a| a == "--json");
    let args: Vec<String> = argv.iter().filter(|a| a.as_str() != "--json").cloned().collect();
    let flag = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    // `--node NAME` runs the same subcommand on a paired seagent node (`system.run seagent meet … --json`).
    let node = flag("--node");
    let fwd: Vec<String> = {
        let mut v = Vec::new();
        let mut skip = false;
        for a in &args {
            if skip {
                skip = false;
            } else if a == "--node" {
                skip = true;
            } else {
                v.push(a.clone());
            }
        }
        v
    };
    let local_or_remote = |args: Vec<String>| node.as_deref().map(|n| remote(n, &args));
    match args.first().map(String::as_str) {
        Some("join") => {
            let url = args.get(1).cloned().ok_or(USAGE)?;
            // Upstream `_cmd_join`: refuse before anything launches.
            if !is_safe_meet_url(&url) {
                println!("refusing: not a meet.google.com URL: {url}");
                return Ok(2);
            }
            let mode = flag("--mode").unwrap_or_else(|| "transcribe".into()).to_lowercase();
            if mode != "transcribe" && mode != "realtime" {
                println!("mode must be 'transcribe' or 'realtime' (got {mode:?})");
                return Ok(2);
            }
            let res = local_or_remote(fwd.clone()).unwrap_or_else(|| {
                if let Some(e) = super::meet_bot::prerequisites(cfg) {
                    return json!({"ok": false, "error": e});
                }
                let guest = flag("--guest-name").unwrap_or_else(|| cfg.get("guest_name").and_then(|v| v.as_str()).unwrap_or("SE Agent Agent").into());
                mgr.start(&JoinOpts { url, guest_name: guest, duration: flag("--duration"), headed: args.iter().any(|a| a == "--headed"), mode, session_id: None, auth_state: mgr.auth_state(cfg) })
            });
            Ok(print_result(&res, json_out))
        }
        Some("status") => Ok(print_result(&mgr.status(), json_out)),
        Some("transcript") => {
            let last = flag("--last").and_then(|n| n.parse().ok()).filter(|n| *n >= 1);
            let res = local_or_remote(fwd.clone()).unwrap_or_else(|| mgr.transcript(last));
            // Upstream `_cmd_transcript` prints the caption lines, one per line.
            if !json_out && res["ok"].as_bool() == Some(true) {
                for ln in res["lines"].as_array().map(Vec::as_slice).unwrap_or_default() {
                    println!("{}", ln.as_str().unwrap_or(""));
                }
                return Ok(0);
            }
            Ok(print_result(&res, json_out))
        }
        Some("say") => {
            let text = args[1..].join(" ");
            if text.trim().is_empty() {
                println!("refusing: empty text");
                return Ok(2);
            }
            let res = local_or_remote(fwd.clone()).unwrap_or_else(|| mgr.enqueue_say(&text));
            Ok(print_result(&res, json_out))
        }
        Some("stop") | Some("leave") => {
            let res = local_or_remote(fwd.clone()).unwrap_or_else(|| mgr.stop("seagent meet stop"));
            Ok(print_result(&res, json_out))
        }
        Some("setup") => Ok(print_result(&super::meet_bot::setup_report(cfg), json_out)),
        Some("auth") => Ok(print_result(&auth_report(mgr), json_out)),
        // The detached bot process (`meet_join` spawns `<seagent> meet bot`).
        Some("bot") => Ok(super::meet_bot::run_from_env(cfg)),
        Some("help") | Some("--help") | Some("-h") => {
            println!("{USAGE}");
            Ok(0)
        }
        _ => Err(USAGE.into()),
    }
}

/// `seagent meet auth`: where the signed-in Google `storage_state` JSON goes (upstream `_cmd_auth`
/// opens Playwright and saves it; seagent accepts the same file — cookies — instead of a browser UI).
fn auth_report(mgr: &Manager) -> Value {
    let path = mgr.auth_path();
    json!({
        "ok": path.is_file(),
        "authStatePath": path,
        "exists": path.is_file(),
        "note": "Put a Playwright storage_state JSON (cookies) here for guest-less joins, or set [meetings.google_meet] auth_state = \"/path/to/auth.json\".",
    })
}

/// Self-registration (`seagent_core::registry`): `meet_join` / `meet_status` / `meet_transcript` /
/// `meet_leave` / `meet_say` (Hermes `plugins/google_meet`). The bot re-execs this binary as
/// `seagent meet bot`.
pub fn register() {
    seagent_core::registry::register_tool_provider("google-meet", 400, |env| {
        let cfg = env.config::<seagent_kernel::config::Config>()?;
        let paths = seagent_kernel::config::Paths { data: env.data.clone(), config_dir: env.config_dir.clone(), runtime: env.runtime.clone(), ..Default::default() };
        Ok(tools(crate::meetings::manager(&paths), crate::meetings::google_meet_cfg(&cfg.meetings)))
    });
}

/// Self-registration (`seagent_kernel::hooks::register_provider`): leaving a still-running Meet call
/// when its session ends (upstream `on_session_end`). `wire::attach` installs it; the binary
/// does not name this hook anywhere.
pub fn register_hooks() {
    seagent_kernel::hooks::register_provider("google-meet-session-end", 400, |k| {
        Ok(vec![std::sync::Arc::new(SessionEndHook::new(crate::meetings::manager(&k.paths))) as std::sync::Arc<dyn seagent_kernel::hooks::Hook>])
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_core::Cancel;

    #[test]
    fn url_guard_and_ids_match_upstream() {
        assert!(is_safe_meet_url("https://meet.google.com/abc-defg-hij"));
        assert!(is_safe_meet_url("https://meet.google.com/abc-defg-hij?authuser=1"));
        assert!(is_safe_meet_url("https://meet.google.com/lookup/xyz"));
        assert!(is_safe_meet_url("https://meet.google.com/new"));
        for bad in ["http://meet.google.com/abc-defg-hij", "https://meet.google.com.evil.com/abc-defg-hij", "https://meet.google.com/ab-cd-ef", "https://zoom.us/j/1", "https://meet.google.com/ABC-DEFG-HIJ"] {
            assert!(!is_safe_meet_url(bad), "{bad}");
        }
        assert_eq!(meeting_id_from_url("https://meet.google.com/abc-defg-hij?x"), "abc-defg-hij");
        assert!(meeting_id_from_url("https://meet.google.com/new").starts_with("meet-"));
    }

    fn temp_root(name: &str) -> PathBuf {
        let d = seagent_core::tmp::scratch_path(format!("seagent-meet-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A fake bot: writes `status.json` + `transcript.txt`, then idles until SIGTERM.
    fn fake_bot(dir: &Path) -> Vec<String> {
        let script = dir.join("fake-bot.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\nprintf '{\"inCall\": true, \"joinedAt\": 1, \"transcriptLines\": 2}' > \"$SEAGENT_MEET_OUT_DIR/status.json\"\nprintf '[00:00:01] Alice: hi\\n[00:00:02] Bob: hello\\n' > \"$SEAGENT_MEET_OUT_DIR/transcript.txt\"\nwhile :; do sleep 0.1; done\n",
        )
        .unwrap();
        vec!["sh".to_string(), script.display().to_string()]
    }

    fn wait_for(path: &Path) {
        for _ in 0..100 {
            if path.is_file() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("{} never appeared", path.display());
    }

    /// The CLI over the file IPC: join (fake bot) → status → transcript → say → stop.
    #[test]
    fn cli_drives_a_fake_bot_through_the_file_ipc() {
        let dir = temp_root("cli");
        let mgr = Manager { root: dir.join("meetings"), bot: fake_bot(&dir), env: vec![] };
        let cfg: toml::Table = "cdp_url = \"http://127.0.0.1:1\"\nguest_name = \"SE Agent Bot\"\n".parse().unwrap();
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // A non-Meet URL is refused before anything launches (upstream `_cmd_join`).
        assert_eq!(cli(&mgr, &cfg, &argv(&["join", "https://zoom.us/j/1"])).unwrap(), 2);
        assert!(!mgr.root.join(".active.json").exists());
        // Join.
        assert_eq!(cli(&mgr, &cfg, &argv(&["join", "https://meet.google.com/abc-defg-hij", "--mode", "realtime", "--json"])).unwrap(), 0);
        let active = read_json(&mgr.root.join(".active.json")).expect("active pointer");
        assert_eq!((active["meeting_id"].as_str(), active["mode"].as_str()), (Some("abc-defg-hij"), Some("realtime")));
        let out = PathBuf::from(active["out_dir"].as_str().unwrap());
        wait_for(&out.join("status.json"));
        // Status merges the bot's status.json into the active record.
        assert_eq!(cli(&mgr, &cfg, &argv(&["status", "--json"])).unwrap(), 0);
        let st = mgr.status();
        assert_eq!((st["alive"].as_bool(), st["inCall"].as_bool(), st["transcriptLines"].as_u64()), (Some(true), Some(true), Some(2)));
        // Transcript: `--last 1` returns the newest caption line (JSON form).
        let t = mgr.transcript(Some(1));
        assert_eq!((t["total"].as_u64(), t["lines"].as_array().map(Vec::len)), (Some(2), Some(1)));
        assert_eq!(t["lines"][0], "[00:00:02] Bob: hello");
        assert_eq!(cli(&mgr, &cfg, &argv(&["transcript", "--last", "1", "--json"])).unwrap(), 0);
        // Say: queued (realtime mode) under the cross-process lock.
        assert_eq!(cli(&mgr, &cfg, &argv(&["say", "hello", "there", "--json"])).unwrap(), 0);
        let queue = std::fs::read_to_string(out.join("say_queue.jsonl")).unwrap();
        assert!(queue.contains("\"text\":\"hello there\""), "{queue}");
        // Empty speech is refused.
        assert_eq!(cli(&mgr, &cfg, &argv(&["say"])).unwrap(), 2);
        // Stop leaves the bot and clears the pointer; a second stop is a soft `no active meeting`.
        assert_eq!(cli(&mgr, &cfg, &argv(&["stop", "--json"])).unwrap(), 0);
        assert!(!mgr.root.join(".active.json").exists());
        assert!(!mgr.alive());
        assert_eq!(mgr.status(), no_active());
        assert_eq!(cli(&mgr, &cfg, &argv(&["stop", "--json"])).unwrap(), 1);
        assert_eq!(cli(&mgr, &cfg, &argv(&["auth", "--json"])).unwrap(), 1, "no saved auth state yet");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `say` is refused while the active meeting is transcribe-only (upstream `enqueue_say`).
    #[test]
    fn say_requires_realtime_mode() {
        let dir = temp_root("say");
        let mgr = Manager { root: dir.join("meetings"), bot: fake_bot(&dir), env: vec![] };
        let cfg: toml::Table = "cdp_url = \"http://127.0.0.1:1\"\n".parse().unwrap();
        assert_eq!(cli(&mgr, &cfg, &["join".to_string(), "https://meet.google.com/abc-defg-hij".to_string()]).unwrap(), 0);
        let r = mgr.enqueue_say("hi");
        assert_eq!(r["ok"], false);
        assert_eq!(r["reason"], "active meeting is in transcribe mode — pass mode='realtime' to meet_join to enable agent speech");
        assert_eq!(mgr.enqueue_say("   ")["reason"], "text is required");
        mgr.stop("test");
        let _ = std::fs::remove_dir_all(&dir);
    }

    struct NoHost;
    impl seagent_core::ToolHost for NoHost {
        fn spawn_agent(&self, _: seagent_core::tool::SpawnRequest, _: &Cancel) -> Result<String, String> {
            Err("no sub-agents in this test".into())
        }
        fn ask_user(&self, _: &str) -> Result<String, String> {
            Err("no user in this test".into())
        }
    }

    fn ctx(dir: &Path) -> ToolCtx {
        ToolCtx { workspace: dir.to_path_buf(), session_id: "meet-test".into(), artifacts: dir.join(".artifacts"), home: dir.join(".home"), cancel: Cancel::new(), host: Arc::new(NoHost), secrets: Arc::new(|s: &str| s.to_string()) }
    }

    fn tool<'a>(ts: &'a [Arc<dyn Tool>], name: &str) -> &'a Arc<dyn Tool> {
        ts.iter().find(|t| t.spec().name == name).unwrap_or_else(|| panic!("no tool {name}"))
    }

    /// The five model tools: names/schemas, the URL guard's message and the `ok:false` shape.
    #[test]
    fn tools_reject_bad_input_and_report_no_active_meeting() {
        let dir = temp_root("tools");
        let mgr = Arc::new(Manager { root: dir.join("meetings"), bot: fake_bot(&dir), env: vec![] });
        let cfg: toml::Table = "cdp_url = \"http://127.0.0.1:1\"\n".parse().unwrap();
        let ts = tools(mgr.clone(), cfg);
        let names: Vec<String> = ts.iter().map(|t| t.spec().name).collect();
        assert_eq!(names, ["meet_join", "meet_status", "meet_transcript", "meet_leave", "meet_say"]);
        for t in &ts {
            assert_eq!(t.spec().input_schema["type"], "object");
            assert!(t.spec().input_schema["properties"].get("node").is_some());
        }
        assert_eq!(tool(&ts, "meet_join").spec().input_schema["required"], json!(["url"]));
        assert_eq!(tool(&ts, "meet_say").spec().input_schema["required"], json!(["text"]));
        let c = ctx(&dir);
        // No active meeting: every read/leave tool answers with upstream's `no active meeting`.
        for name in ["meet_status", "meet_transcript", "meet_leave"] {
            let out = tool(&ts, name).call(&c, json!({}));
            let v: Value = serde_json::from_str(&out.content).unwrap();
            assert_eq!((v["success"].as_bool(), v["reason"].as_str()), (Some(false), Some("no active meeting")), "{name}: {}", out.content);
            assert!(!out.is_error, "a soft failure is still a normal answer");
        }
        // `meet_join` guards the URL with upstream's message.
        let out = tool(&ts, "meet_join").call(&c, json!({"url": "https://zoom.us/j/1"}));
        let v: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(v["success"], false);
        assert!(v["error"].as_str().unwrap().starts_with("refusing: only https://meet.google.com/ URLs are allowed. got:"), "{}", out.content);
        assert!(out.is_error, "a refused URL is a hard error");
        // Argument validation mirrors upstream.
        let out = serde_json::from_str::<Value>(&tool(&ts, "meet_join").call(&c, json!({"mode": "realtime"})).content).unwrap();
        assert_eq!(out["error"], "url is required");
        let out = serde_json::from_str::<Value>(&tool(&ts, "meet_join").call(&c, json!({"url": "https://meet.google.com/abc-defg-hij", "mode": "loud"})).content).unwrap();
        assert_eq!(out["error"], "mode must be 'transcribe' or 'realtime' (got \"loud\")");
        let out = serde_json::from_str::<Value>(&tool(&ts, "meet_say").call(&c, json!({"text": "  "})).content).unwrap();
        assert_eq!(out["error"], "text is required");
        // A good join starts the bot and records the session id.
        let out = tool(&ts, "meet_join").call(&c, json!({"url": "https://meet.google.com/abc-defg-hij"}));
        let v: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(v["success"], true, "{}", out.content);
        assert_eq!(mgr.active_session().as_deref(), Some("meet-test"));
        let out = serde_json::from_str::<Value>(&tool(&ts, "meet_status").call(&c, json!({})).content).unwrap();
        assert_eq!((out["success"].as_bool(), out["meetingId"].as_str()), (Some(true), Some("abc-defg-hij")));
        // Session-end cleanup leaves the call (upstream `on_session_end`).
        let hook = SessionEndHook::new(mgr.clone());
        assert!(hook.wants(HookEvent::SessionEnd, None) && !hook.wants(HookEvent::SessionStart, None));
        assert!(matches!(hook.run(HookEvent::SessionEnd, &json!({"session_id": "other"})), Ok(HookDecision::Allow)));
        assert!(mgr.active().is_some(), "another session's meeting is left alone");
        assert!(matches!(hook.run(HookEvent::SessionEnd, &json!({"session_id": "meet-test"})), Ok(HookDecision::Allow)));
        assert!(mgr.active().is_none(), "our meeting is left on session end");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
