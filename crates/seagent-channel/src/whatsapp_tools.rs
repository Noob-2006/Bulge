//! WhatsApp agent tools (OpenClaw `extensions/whatsapp/src/agent-tools-{login,call}.ts`, MIT).
//!
//! `whatsapp_login` — link the bridge's WhatsApp account: `start` returns the pairing QR
//! (a `data:image/png;base64,…` image plus the raw payload), `wait` polls until the scan
//! completes or the QR changes. `force` on a linked bridge wipes the supervised bridge's
//! session and restarts it for a fresh QR. Every call needs the egress gate's approval
//! (upstream only offers the tool to the owner).
//!
//! `whatsapp_call` — off unless `actions = { calls = true }`: call the *current requester*
//! (never an arbitrary number) through the MeowCaller companion CLI and play a synthesized
//! message: TTS (host-installed via [`set_telephony_tts`]) → 16-bit mono WAV →
//! `meowcaller notify --store <db> --answer-timeout 45s --max-duration 65s <+E164> <file>`,
//! bounded by the call window, one call per account at a time. `status` reports setup.
//! The requester comes from the session's route (host-installed [`super::SessionOrigin`]).

use super::Shared;
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

const QR_DATA_URL_MAX_LENGTH: usize = 16_384;
const DEFAULT_LOGIN_TIMEOUT_MS: u64 = 30_000;
/// `wait` long-polls for a scan; upstream gives it four times the `start` budget
/// (`waitForWebLogin`, login-qr.ts:496) instead of the QR-capture timeout (login-qr.ts:340).
const DEFAULT_WAIT_TIMEOUT_MS: u64 = 120_000;
pub(super) const MEOWCALLER: &str = "meowcaller";
const SESSION_DATABASE: &str = "wa-voip.db";
const CONNECT_TIMEOUT_MS: u64 = 60_000;
const ANSWER_TIMEOUT_MS: u64 = 45_000;
const SHUTDOWN_GRACE_MS: u64 = 10_000;
const MAX_AUDIO_MS: u64 = 60_000;
const MIN_CALL_WINDOW_MS: u64 = CONNECT_TIMEOUT_MS + ANSWER_TIMEOUT_MS + SHUTDOWN_GRACE_MS;
const MAX_CALL_WINDOW_MS: u64 = MIN_CALL_WINDOW_MS + MAX_AUDIO_MS;
const MAX_CALL_MESSAGE: usize = 4_000;
const MAX_COMMAND_OUTPUT: usize = 64 * 1024;

/// Telephony speech for a text: (PCM16 mono little-endian, sample rate, provider id).
pub type TelephonyTts = Arc<dyn Fn(&str) -> Result<(Vec<u8>, u32, String), String> + Send + Sync>;

static TTS: RwLock<Option<TelephonyTts>> = RwLock::new(None);

/// Installed by the host (seagent-media's TTS chain); `whatsapp_call` fails without it.
pub fn set_telephony_tts(f: TelephonyTts) {
    *TTS.write().unwrap() = Some(f);
}

static ACTIVE_CALLS: Mutex<Option<HashSet<String>>> = Mutex::new(None);

pub(super) fn tools(sh: &Arc<Shared>) -> Vec<Arc<dyn Tool>> {
    let safe: String = sh.id.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }).collect();
    let name = |b: &str| if safe == "whatsapp" { b.to_string() } else { format!("{b}_{safe}") };
    let mut v: Vec<Arc<dyn Tool>> = vec![Arc::new(Login { name: name("whatsapp_login"), sh: sh.clone() })];
    if sh.calls {
        v.push(Arc::new(Call { name: name("whatsapp_call"), sh: sh.clone() }));
    }
    v
}

fn text_result(text: String, details: Value) -> ToolOutput {
    ToolOutput::ok(format!("{text}\n\n{details}"))
}

// ───────────── login ─────────────

struct Login {
    name: String,
    sh: Arc<Shared>,
}

fn qr_reply(message: &str, qr: &str, connected: bool) -> ToolOutput {
    let Some(code) = crate::whatsapp::qr::Qr::encode(qr.as_bytes()) else {
        return text_result(format!("{message}\n\nThe pairing code is too long to draw; pairing payload:\n{qr}"), json!({"connected": connected, "qr": true}));
    };
    let text = [message, "", "Open WhatsApp → Linked Devices and scan:", "", &format!("![whatsapp-qr]({})", code.png_data_url()), "", &code.render(2)].join("\n");
    text_result(text, json!({"connected": connected, "qr": true}))
}

impl Login {
    fn status(&self) -> Result<(String, Option<String>), String> {
        let v = self.sh.get("/qr").map_err(|e| e.to_string())?;
        Ok((v["status"].as_str().unwrap_or("disconnected").to_string(), v["qr"].as_str().filter(|q| !q.is_empty()).map(str::to_string)))
    }

    /// Poll the bridge until `done` says stop (or the deadline passes).
    fn poll(&self, timeout: Duration, mut done: impl FnMut(&str, Option<&str>) -> bool) -> Result<(String, Option<String>), String> {
        let until = Instant::now() + timeout;
        loop {
            let st = self.status();
            if let Ok((s, q)) = &st {
                if done(s, q.as_deref()) {
                    return st;
                }
            }
            if Instant::now() >= until {
                return st;
            }
            std::thread::sleep(self.sh.login_poll);
        }
    }

    fn run(&self, input: &Value) -> Result<ToolOutput, String> {
        let action = input.get("action").and_then(Value::as_str).unwrap_or("start");
        let default_ms = if action == "wait" { DEFAULT_WAIT_TIMEOUT_MS } else { DEFAULT_LOGIN_TIMEOUT_MS };
        let timeout = Duration::from_millis(input.get("timeoutMs").and_then(Value::as_u64).filter(|t| *t > 0).unwrap_or(default_ms));
        match action {
            "wait" => {
                let current = input.get("currentQrDataUrl").and_then(Value::as_str).filter(|q| !q.trim().is_empty());
                if current.is_some_and(|c| c.len() > QR_DATA_URL_MAX_LENGTH || !c.starts_with("data:image/png;base64,")) {
                    return Err("currentQrDataUrl must be a data:image/png;base64 URL".into());
                }
                let shown = current.map(str::to_string);
                // The bridge serves `qr: null` only while no pairing is in flight (it clears the
                // payload once connected): report that at once (login-qr.ts:481) rather than
                // long-polling for a login that does not exist.
                let (status, qr) = self.poll(timeout, |s, q| s == "connected" || q.is_none() || q.and_then(|q| crate::whatsapp::qr::Qr::encode(q.as_bytes())).map(|c| c.png_data_url()).is_some_and(|u| shown.as_deref().is_some_and(|c| c != u)))?;
                if status == "connected" {
                    return Ok(text_result("✅ Linked! WhatsApp is ready.".into(), json!({"connected": true})));
                }
                match qr {
                    Some(q) if shown.is_some() && crate::whatsapp::qr::Qr::encode(q.as_bytes()).map(|c| c.png_data_url()) != shown => Ok(qr_reply("QR refreshed. Scan the latest code in WhatsApp → Linked Devices.", &q, false)),
                    Some(_) => Ok(text_result("Still waiting for the QR scan. Let me know when you’ve scanned it.".into(), json!({"connected": false}))),
                    None => Ok(text_result("No active WhatsApp login in progress.".into(), json!({"connected": false}))),
                }
            }
            "start" => {
                let force = input.get("force").and_then(Value::as_bool).unwrap_or(false);
                let (status, _) = self.status()?;
                if status == "connected" && !force {
                    return Ok(text_result("WhatsApp is already linked. Say “relink” if you want a fresh QR.".into(), json!({"qr": false})));
                }
                if status == "connected" {
                    self.relink()?;
                }
                let (status, qr) = self.poll(timeout, |s, q| s == "connected" || q.is_some())?;
                match qr {
                    Some(q) if status != "connected" => Ok(qr_reply("Scan this QR in WhatsApp → Linked Devices.", &q, false)),
                    _ if status == "connected" => Ok(text_result("✅ Linked! WhatsApp is ready.".into(), json!({"connected": true}))),
                    _ => Ok(text_result("Failed to get QR: Timed out waiting for WhatsApp QR".into(), json!({"qr": false}))),
                }
            }
            _ => Err("Unknown WhatsApp login action. Expected \"start\" or \"wait\".".into()),
        }
    }

    /// Upstream `logoutWeb` + new login: clear the supervised session and restart the bridge.
    fn relink(&self) -> Result<(), String> {
        let (Some(bounce), Some(session)) = (&self.sh.bounce, &self.sh.session) else {
            return Err("WhatsApp login failed: existing auth could not be cleared (the bridge is not supervised by seagent; remove its session directory and restart it).".into());
        };
        match std::fs::remove_dir_all(session) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("WhatsApp login failed: existing auth could not be cleared: {e}")),
        }
        bounce();
        Ok(())
    }
}

impl Tool for Login {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: self.name.clone(),
            description: "Generate a WhatsApp QR code for linking, or wait for the scan to complete.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["start", "wait"]},
                    "timeoutMs": {"type": "integer", "minimum": 1},
                    "force": {"type": "boolean"},
                    "currentQrDataUrl": {"type": "string", "maxLength": QR_DATA_URL_MAX_LENGTH, "pattern": "^data:image/png;base64,.+$"}
                },
                "required": ["action"]
            }),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let force = input.get("force").and_then(Value::as_bool).unwrap_or(false);
        vec![Effect::Remote { dest: format!("whatsapp:{}", self.sh.id), reason: if force { "relink the WhatsApp account (clears the current session)".into() } else { "link a WhatsApp account to this agent".into() } }]
    }

    fn call(&self, _ctx: &ToolCtx, input: Value) -> ToolOutput {
        self.run(&input).unwrap_or_else(ToolOutput::err)
    }
}

// ───────────── call ─────────────

struct Call {
    name: String,
    sh: Arc<Shared>,
}

fn calls_dir(sh: &Shared) -> PathBuf {
    sh.state_dir.join(format!("{}.whatsapp-calls", sh.id))
}

fn find_binary(cmd: &str) -> Option<PathBuf> {
    if cmd.contains('/') {
        return Path::new(cmd).is_file().then(|| PathBuf::from(cmd));
    }
    std::env::split_paths(&std::env::var_os("PATH")?).map(|d| d.join(cmd)).find(|p| p.is_file())
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// `+<digits>` from a WhatsApp id (`15551234567@s.whatsapp.net`, `whatsapp:+1555…`, `+1555…`).
/// LID ids (`…@lid`) have no phone number.
pub(super) fn requester_e164(id: &str) -> Option<String> {
    let id = id.trim().trim_start_matches("whatsapp:");
    let (user, server) = id.split_once('@').unwrap_or((id, "s.whatsapp.net"));
    if !matches!(server, "s.whatsapp.net" | "c.us") {
        return None;
    }
    let digits: String = user.split(':').next().unwrap_or("").chars().filter(char::is_ascii_digit).collect();
    (7..=15).contains(&digits.len()).then(|| format!("+{digits}"))
}

pub(super) fn wav_pcm16_mono(pcm: &[u8], rate: u32) -> Result<Vec<u8>, String> {
    if rate == 0 {
        return Err("TTS returned an invalid sample rate".into());
    }
    if pcm.is_empty() || !pcm.len().is_multiple_of(2) {
        return Err("TTS returned invalid 16-bit PCM audio".into());
    }
    let mut h = Vec::with_capacity(44 + pcm.len());
    h.extend_from_slice(b"RIFF");
    h.extend_from_slice(&(36 + pcm.len() as u32).to_le_bytes());
    h.extend_from_slice(b"WAVEfmt ");
    h.extend_from_slice(&16u32.to_le_bytes());
    h.extend_from_slice(&1u16.to_le_bytes());
    h.extend_from_slice(&1u16.to_le_bytes());
    h.extend_from_slice(&rate.to_le_bytes());
    h.extend_from_slice(&(rate * 2).to_le_bytes());
    h.extend_from_slice(&2u16.to_le_bytes());
    h.extend_from_slice(&16u16.to_le_bytes());
    h.extend_from_slice(b"data");
    h.extend_from_slice(&(pcm.len() as u32).to_le_bytes());
    h.extend_from_slice(pcm);
    Ok(h)
}

pub(super) fn call_window_ms(pcm_bytes: usize, rate: u32) -> Result<u64, String> {
    let audio_ms = (pcm_bytes as f64 / 2.0 / rate as f64) * 1000.0;
    if audio_ms > MAX_AUDIO_MS as f64 {
        return Err("TTS audio exceeds the 60-second WhatsApp call limit".into());
    }
    Ok(MAX_CALL_WINDOW_MS.min((audio_ms + MIN_CALL_WINDOW_MS as f64).ceil() as u64))
}

enum Ended {
    Exit(i32),
    Timeout,
    Cancelled,
}

/// Run `argv` in its own process group; kill the group on timeout or cancel.
fn run_bounded(argv: &[String], cwd: &Path, window: Duration, cancel: &seagent_core::Cancel) -> Result<(Ended, String), String> {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]).current_dir(cwd).env("MEOW_LOG_LEVEL", "warn").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // SAFETY: setpgid is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let mut child = cmd.spawn().map_err(|e| format!("cannot start MeowCaller: {e}"))?;
    let out = Arc::new(Mutex::new(Vec::new()));
    let mut readers = Vec::new();
    for r in [child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>), child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>)].into_iter().flatten() {
        let o = out.clone();
        readers.push(std::thread::spawn(move || {
            let mut r = r;
            let mut buf = [0u8; 4096];
            while let Ok(n) = r.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let mut o = o.lock().unwrap();
                let room = MAX_COMMAND_OUTPUT.saturating_sub(o.len());
                o.extend_from_slice(&buf[..n.min(room)]);
            }
        }));
    }
    let until = Instant::now() + window;
    let pid = child.id() as i32;
    let ended = loop {
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            break Ended::Exit(st.code().unwrap_or(-1));
        }
        let why = if cancel.is_cancelled() { Some(Ended::Cancelled) } else if Instant::now() >= until { Some(Ended::Timeout) } else { None };
        if let Some(w) = why {
            // SAFETY: kill(2) on the child's own process group.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
            let _ = child.wait();
            break w;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    for r in readers {
        let _ = r.join();
    }
    let text = String::from_utf8_lossy(&out.lock().unwrap()).into_owned();
    Ok((ended, text))
}

impl Call {
    fn status(&self) -> Value {
        let dir = calls_dir(&self.sh);
        let store = dir.join(SESSION_DATABASE);
        json!({
            "binaryFound": find_binary(&self.sh.meowcaller).is_some(),
            "sessionStoreFound": store.is_file(),
            "accountId": self.sh.id,
            "stateDir": dir,
            "setupCommand": format!("mkdir -p {d} && chmod 700 {d} && meowcaller pair --store {s}", d = sh_quote(&dir.display().to_string()), s = sh_quote(&store.display().to_string())),
            "setupShell": "POSIX shell",
            "requiredCommand": "meowcaller notify --store <path> --answer-timeout 45s --max-duration 65s <target> <file>",
            "note": "MeowCaller uses a separate WhatsApp linked-device session; it cannot reuse seagent's Baileys bridge credentials.",
        })
    }

    fn run(&self, ctx: &ToolCtx, input: &Value) -> Result<Value, String> {
        match input.get("action").and_then(Value::as_str).unwrap_or("") {
            "status" => return Ok(self.status()),
            "call" => {}
            other => return Err(format!("unknown action `{other}`; use status or call")),
        }
        let message = input.get("message").and_then(Value::as_str).map(str::trim).unwrap_or("");
        if message.is_empty() {
            return Err("message required for call action".into());
        }
        if message.chars().count() > MAX_CALL_MESSAGE {
            return Err(format!("message must be at most {MAX_CALL_MESSAGE} characters"));
        }
        let bin = find_binary(&self.sh.meowcaller).ok_or("MeowCaller is not installed; run whatsapp_call with action=status")?;
        let dir = calls_dir(&self.sh);
        let store = dir.join(SESSION_DATABASE);
        if !store.is_file() {
            return Err("MeowCaller has no session store; run whatsapp_call with action=status, then run its setupCommand in an interactive terminal and scan the QR as a linked device".into());
        }
        let route = self.sh.origin.read().unwrap().as_ref().and_then(|f| f(&ctx.session_id));
        let requester = route.filter(|r| r.channel == self.sh.id).and_then(|r| r.sender.or_else(|| (!r.chat.ends_with("@g.us")).then_some(r.chat)));
        let requester = requester.ok_or("whatsapp_call only works in a WhatsApp conversation with a known requester")?;
        let target = requester_e164(&requester).ok_or("Could not resolve the current WhatsApp requester to a phone number")?;
        if self.sh.mode == "self-chat" {
            return Err("WhatsApp cannot call the linked account itself; use a dedicated WhatsApp number (mode = \"bot\")".into());
        }
        {
            let mut active = ACTIVE_CALLS.lock().unwrap();
            if !active.get_or_insert_with(HashSet::new).insert(self.sh.id.clone()) {
                return Err("A WhatsApp call is already active for this account".into());
            }
        }
        let r = self.place(ctx, &bin, &dir, &store, &target, message);
        ACTIVE_CALLS.lock().unwrap().get_or_insert_with(HashSet::new).remove(&self.sh.id);
        r
    }

    fn place(&self, ctx: &ToolCtx, bin: &Path, dir: &Path, store: &Path, target: &str, message: &str) -> Result<Value, String> {
        let tts = TTS.read().unwrap().clone().ok_or("TTS synthesis failed: no text-to-speech provider is configured")?;
        let (pcm, rate, provider) = tts(message)?;
        let wav = wav_pcm16_mono(&pcm, rate)?;
        let window = call_window_ms(pcm.len(), rate)?;
        let tmp = dir.join(format!("call-{}", seagent_net::crypto::random_token(8)));
        std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
        let audio = tmp.join("message.wav");
        let res = (|| {
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&audio).map_err(|e| e.to_string())?;
                std::io::Write::write_all(&mut f, &wav).map_err(|e| e.to_string())?;
            }
            let argv: Vec<String> = [bin.display().to_string(), "notify".into(), "--store".into(), store.display().to_string(), "--answer-timeout".into(), "45s".into(), "--max-duration".into(), "65s".into(), target.into(), audio.display().to_string()].into();
            let (ended, _out) = run_bounded(&argv, dir, Duration::from_millis(window), &ctx.cancel)?;
            match ended {
                Ended::Cancelled => Err("WhatsApp call cancelled".to_string()),
                Ended::Timeout => Err("MeowCaller exceeded the bounded WhatsApp call window".to_string()),
                Ended::Exit(0) => Ok(json!({
                    "completed": true,
                    "recipient": "current WhatsApp requester",
                    "callWindowSeconds": window.div_ceil(1000),
                    "ttsProvider": provider,
                    "note": "MeowCaller completed answer, playback, and hangup for the requester-bound call.",
                })),
                Ended::Exit(c) => Err(format!("MeowCaller did not complete the call (code {c})")),
            }
        })();
        let _ = std::fs::remove_dir_all(&tmp);
        res
    }
}

impl Tool for Call {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: self.name.clone(),
            description: "Call the current WhatsApp requester and play a synthesized spoken message. This tool cannot call arbitrary phone numbers.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["status", "call"], "description": "Check MeowCaller setup or call the current WhatsApp requester"},
                    "message": {"type": "string", "maxLength": MAX_CALL_MESSAGE, "description": "Spoken message to play after the requester answers (maximum 60 seconds)"}
                },
                "required": ["action"],
                "additionalProperties": false
            }),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        if input.get("action").and_then(Value::as_str) != Some("call") {
            return vec![];
        }
        vec![Effect::Send { channel: self.sh.id.clone(), payload: format!("voice call to the requester: {}", input.get("message").and_then(Value::as_str).unwrap_or("")) }]
    }

    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match self.run(ctx, &input) {
            Ok(v) => ToolOutput::ok(v.to_string()),
            Err(e) => ToolOutput::err(e),
        }
    }
}
#[cfg(test)]
mod tests {
    //! Hermetic coverage for the two agent tools. `whatsapp_login` talks to a loopback
    //! `FakeServer` standing in for the bridge; `whatsapp_call` never leaves the machine (its
    //! `meowcaller` is a shell script inside a `temp_dir`). The TTS global is deliberately left
    //! alone: `whatsapp.rs` owns it, and every path below runs before synthesis (or needs no
    //! provider at all).

    use super::*;
    use crate::router::RouteKey;
    use crate::testutil::{temp_dir, tool_ctx, FakeServer};
    use crate::whatsapp::SessionOrigin;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn base_shared(id: &str, base: &str, state_dir: &Path) -> Shared {
        Shared {
            id: id.to_string(),
            base: base.trim_end_matches('/').to_string(),
            http: crate::http::Http::new(Duration::from_secs(5)),
            bounce: None,
            session: None,
            state_dir: state_dir.to_path_buf(),
            mode: "bot".into(),
            calls: true,
            meowcaller: MEOWCALLER.into(),
            origin: RwLock::new(None),
            login_poll: Duration::from_millis(20),
        }
    }

    fn login_tool(sh: Shared) -> Arc<dyn Tool> {
        tools(&Arc::new(sh)).remove(0)
    }

    fn call_tool(sh: Shared) -> Arc<dyn Tool> {
        tools(&Arc::new(sh)).remove(1)
    }

    /// A `Shared` for `whatsapp_call` with a requester route installed.
    fn call_shared(id: &str, state_dir: &Path, meowcaller: &Path, origin: Option<SessionOrigin>) -> Shared {
        let mut sh = base_shared(id, "http://127.0.0.1:9", state_dir);
        sh.meowcaller = meowcaller.display().to_string();
        *sh.origin.get_mut().unwrap() = origin;
        sh
    }

    /// A `meowcaller` stand-in: no PATH games, `find_binary` uses the path verbatim.
    fn fake_bin(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("meowcaller");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// `wa-voip.db` where `whatsapp_call` expects it for `id`.
    fn paired_store(state_dir: &Path, id: &str) {
        let dir = state_dir.join(format!("{id}.whatsapp-calls"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(SESSION_DATABASE), b"sqlite").unwrap();
    }

    fn route(channel: &str, chat: &str, sender: Option<&str>) -> SessionOrigin {
        let (channel, chat, sender) = (channel.to_string(), chat.to_string(), sender.map(str::to_string));
        Arc::new(move |_: &str| Some(RouteKey { channel: channel.clone(), chat: chat.clone(), sender: sender.clone() }))
    }

    /// Holds a channel id in the process-global `ACTIVE_CALLS` for the test's lifetime.
    struct Busy(&'static str);

    impl Busy {
        fn new(id: &'static str) -> Busy {
            ACTIVE_CALLS.lock().unwrap().get_or_insert_with(HashSet::new).insert(id.into());
            Busy(id)
        }
    }

    impl Drop for Busy {
        fn drop(&mut self) {
            ACTIVE_CALLS.lock().unwrap().get_or_insert_with(HashSet::new).remove(self.0);
        }
    }

    // ───────────── login ─────────────

    /// OpenClaw `login-qr.ts:281-300` (`authState.exists && force` → `logoutWeb`): a supervised
    /// relink wipes the session, restarts the bridge and hands back a fresh QR, while a plain
    /// `start` on a linked account touches nothing.
    #[test]
    fn whatsapp_login_force_relinks_supervised_session_and_returns_fresh_qr() {
        let dir = temp_dir("wa-tools-force");
        let session = dir.join("whatsapp.whatsapp-session");
        std::fs::create_dir_all(&session).unwrap();
        std::fs::write(session.join("creds.json"), b"{}").unwrap();
        let srv = FakeServer::start(|_, n| (200, vec![], if n <= 1 { json!({"status": "connected", "qr": null}) } else { json!({"status": "disconnected", "qr": "2@fresh,KEY1,KEY2,ADV"}) }.to_string()));
        let bounced = Arc::new(AtomicBool::new(false));
        let b = bounced.clone();
        let mut sh = base_shared("whatsapp", &srv.url, &dir);
        sh.session = Some(session.clone());
        sh.bounce = Some(Box::new(move || b.store(true, Ordering::SeqCst)));
        let login = login_tool(sh);
        let ctx = tool_ctx();

        let r = login.call(&ctx, json!({"action": "start"}));
        assert!(r.content.starts_with("WhatsApp is already linked"), "{}", r.content);
        assert!(session.is_dir() && !bounced.load(Ordering::SeqCst), "a plain start keeps the linked session");

        let r = login.call(&ctx, json!({"action": "start", "force": true, "timeoutMs": 2000}));
        assert!(!r.is_error, "{}", r.content);
        assert!(r.content.starts_with("Scan this QR in WhatsApp → Linked Devices."), "{}", r.content);
        assert!(r.content.contains("![whatsapp-qr](data:image/png;base64,iVBOR"), "{}", r.content);
        assert!(r.content.ends_with(r#"{"connected":false,"qr":true}"#), "{}", r.content);
        assert!(!session.exists(), "force clears the supervised session dir");
        assert!(bounced.load(Ordering::SeqCst), "force restarts the bridge");
        assert_eq!(srv.requests().len(), 3, "status, status, then the fresh QR after the bounce");
    }

    /// Without a supervisor nothing may be deleted: upstream's "existing auth could not be
    /// cleared" refusal (`login-qr.ts:289-294`), which seagent words with the fix in it.
    #[test]
    fn whatsapp_login_force_without_supervision_refuses_to_wipe_the_session() {
        let dir = temp_dir("wa-tools-force-guard");
        let session = dir.join("whatsapp.whatsapp-session");
        std::fs::create_dir_all(&session).unwrap();
        let srv = FakeServer::start(|_, _| (200, vec![], json!({"status": "connected", "qr": null}).to_string()));
        let mut sh = base_shared("whatsapp", &srv.url, &dir);
        sh.session = Some(session.clone());
        let r = login_tool(sh).call(&tool_ctx(), json!({"action": "start", "force": true, "timeoutMs": 2000}));
        assert!(r.is_error, "{}", r.content);
        assert_eq!(r.content, "WhatsApp login failed: existing auth could not be cleared (the bridge is not supervised by seagent; remove its session directory and restart it).");
        assert!(session.is_dir(), "nothing is deleted without a supervisor to restart it");
    }

    /// Registration and schema (`agent-tools-login.ts:31-46`): owner-only upstream, egress-gated
    /// here; the name carries the channel suffix except for the default `whatsapp` account, and
    /// the tool is offered even when `actions.calls` is off.
    #[test]
    fn whatsapp_login_registration_schema_and_effects() {
        let dir = temp_dir("wa-tools-schema");
        let mut sh = base_shared("wa/2", "http://127.0.0.1:9", &dir);
        sh.calls = false;
        let v = tools(&Arc::new(sh));
        assert_eq!(v.len(), 1, "whatsapp_call is opt-in, whatsapp_login is not");
        let spec = v[0].spec();
        assert_eq!(spec.name, "whatsapp_login_wa_2", "unsafe channel id chars are folded");
        let props = &spec.input_schema["properties"];
        assert_eq!(spec.input_schema["required"], json!(["action"]));
        assert_eq!(props["action"]["enum"], json!(["start", "wait"]));
        assert_eq!(props["timeoutMs"]["type"], "integer");
        assert_eq!(props["timeoutMs"]["minimum"], json!(1));
        assert_eq!(props["force"]["type"], "boolean");
        assert_eq!(props["currentQrDataUrl"]["maxLength"], json!(16_384));
        assert_eq!(props["currentQrDataUrl"]["pattern"], "^data:image/png;base64,.+$");
        assert!(props.get("to").is_none() && props.get("number").is_none(), "no arbitrary recipient");
        assert!(!spec.parallel_safe);

        let ctx = tool_ctx();
        for (input, needle) in [(json!({"action": "start"}), "link a WhatsApp account"), (json!({"action": "start", "force": true}), "clears the current session")] {
            let eff = v[0].effects(&ctx, &input);
            assert_eq!(eff.len(), 1);
            match &eff[0] {
                Effect::Remote { dest, reason } => {
                    assert_eq!(dest.as_str(), "whatsapp:wa/2");
                    assert!(reason.contains(needle), "{reason}");
                }
                _ => panic!("whatsapp_login must ask the egress gate"),
            }
        }

        let names: Vec<String> = tools(&Arc::new(base_shared("whatsapp", "http://127.0.0.1:9", &dir))).iter().map(|t| t.spec().name.clone()).collect();
        assert_eq!(names, ["whatsapp_login", "whatsapp_call"], "the default account keeps the upstream names");
    }

    /// The `currentQrDataUrl` guard is pure input validation: no `/qr` GET may happen first
    /// (`agent-tools-login.ts:38-45` bounds it at 16 384 chars of `data:image/png;base64,`).
    #[test]
    fn whatsapp_login_wait_rejects_bad_current_qr_before_contacting_the_bridge() {
        let dir = temp_dir("wa-tools-qrarg");
        let srv = FakeServer::start(|_, _| (200, vec![], json!({"status": "connected", "qr": null}).to_string()));
        let login = login_tool(base_shared("whatsapp", &srv.url, &dir));
        let ctx = tool_ctx();
        let long = format!("data:image/png;base64,{}", "A".repeat(QR_DATA_URL_MAX_LENGTH));
        for bad in ["http://evil.example/qr.png", "data:image/jpeg;base64,AAAA", long.as_str()] {
            let r = login.call(&ctx, json!({"action": "wait", "currentQrDataUrl": bad, "timeoutMs": 1000}));
            assert!(r.is_error, "{bad}");
            assert_eq!(r.content, "currentQrDataUrl must be a data:image/png;base64 URL");
        }
        assert!(srv.requests().is_empty(), "rejected before any bridge request");
    }

    /// No pairing in flight (`qr: null` is only served while nothing is pairing, or right after
    /// connecting): answered on the first probe like `login-qr.ts:481-486`, instead of burning
    /// the whole 120 s wait budget.
    #[test]
    fn whatsapp_login_wait_without_an_active_login_answers_at_once() {
        let dir = temp_dir("wa-tools-wait-idle");
        let srv = FakeServer::start(|_, _| (200, vec![], json!({"status": "disconnected", "qr": null}).to_string()));
        let login = login_tool(base_shared("whatsapp", &srv.url, &dir));
        let t = Instant::now();
        let r = login.call(&tool_ctx(), json!({"action": "wait"}));
        let elapsed = t.elapsed();
        assert!(!r.is_error, "{}", r.content);
        assert!(r.content.starts_with("No active WhatsApp login in progress."), "{}", r.content);
        assert!(elapsed < Duration::from_secs(5), "returned without long-polling: {elapsed:?}");
        assert_eq!(srv.requests().len(), 1);
    }

    // ───────────── call ─────────────

    /// `agent-tools-call.ts:237-241`: one whatsmeow session must never be driven twice.
    #[test]
    fn whatsapp_call_rejects_a_second_call_for_the_same_account() {
        let dir = temp_dir("wa-tools-busy");
        let ran = dir.join("ran");
        let bin = fake_bin(&dir, &format!("echo \"$@\" > {}", ran.display()));
        paired_store(&dir, "wa-guard");
        let sh = call_shared("wa-guard", &dir, &bin, Some(route("wa-guard", "15550001111@s.whatsapp.net", None)));
        let call = call_tool(sh);
        let _busy = Busy::new("wa-guard");
        let r = call.call(&tool_ctx(), json!({"action": "call", "message": "hi"}));
        assert!(r.is_error, "{}", r.content);
        assert_eq!(r.content, "A WhatsApp call is already active for this account");
        assert!(!ran.exists(), "the guard rejects before MeowCaller is spawned");
    }

    /// `agent-tools-call.ts:190-220`: `status` needs no requester and no TTS and must tell the
    /// truth about the companion's two prerequisites.
    #[test]
    fn whatsapp_call_status_reports_installed_binary_and_session_store() {
        let dir = temp_dir("wa-tools-status");
        let bin = fake_bin(&dir, "exit 0");
        let missing = dir.join("missing/meowcaller");
        for (id, meow, binary_found, store_found) in [("absent", &missing, false, false), ("binary-only", &bin, true, false)] {
            let mut sh = base_shared(id, "http://127.0.0.1:9", &dir);
            sh.meowcaller = meow.display().to_string();
            let r = call_tool(sh).call(&tool_ctx(), json!({"action": "status"}));
            assert!(!r.is_error, "{}", r.content);
            let v: Value = serde_json::from_str(&r.content).unwrap();
            assert_eq!((v["binaryFound"].as_bool(), v["sessionStoreFound"].as_bool()), (Some(binary_found), Some(store_found)), "{id}");
            assert_eq!(v["accountId"], id);
            assert_eq!(v["stateDir"], json!(dir.join(format!("{id}.whatsapp-calls"))));
            assert!(v["setupCommand"].as_str().unwrap().contains("meowcaller pair --store"));
            assert!(v["requiredCommand"].as_str().unwrap().ends_with("notify --store <path> --answer-timeout 45s --max-duration 65s <target> <file>"));
        }
        paired_store(&dir, "paired");
        let mut sh = base_shared("paired", "http://127.0.0.1:9", &dir);
        sh.meowcaller = bin.display().to_string();
        let v: Value = serde_json::from_str(&call_tool(sh).call(&tool_ctx(), json!({"action": "status"})).content).unwrap();
        assert_eq!((v["binaryFound"].as_bool(), v["sessionStoreFound"].as_bool()), (Some(true), Some(true)));
    }

    /// `agent-tools-call.ts:192-219`: action and message are checked before anything is spawned,
    /// with the upstream wording (4 000 characters, trimmed).
    #[test]
    fn whatsapp_call_validates_action_and_message_before_running_anything() {
        let dir = temp_dir("wa-tools-args");
        let mut sh = base_shared("wa-args", "http://127.0.0.1:9", &dir);
        sh.meowcaller = dir.join("missing/meowcaller").display().to_string();
        let call = call_tool(sh);
        let ctx = tool_ctx();
        assert_eq!(call.call(&ctx, json!({"action": "ring"})).content, "unknown action `ring`; use status or call");
        assert_eq!(call.call(&ctx, json!({})).content, "unknown action ``; use status or call");
        assert_eq!(call.call(&ctx, json!({"action": "call"})).content, "message required for call action");
        assert_eq!(call.call(&ctx, json!({"action": "call", "message": "   "})).content, "message required for call action");
        let at_limit = "a".repeat(MAX_CALL_MESSAGE);
        assert_eq!(call.call(&ctx, json!({"action": "call", "message": at_limit})).content, "MeowCaller is not installed; run whatsapp_call with action=status");
        let over = "a".repeat(MAX_CALL_MESSAGE + 1);
        assert_eq!(call.call(&ctx, json!({"action": "call", "message": over})).content, "message must be at most 4000 characters");
        let spec = call.spec();
        assert_eq!(spec.input_schema["properties"]["action"]["enum"], json!(["status", "call"]));
        assert_eq!(spec.input_schema["properties"]["message"]["maxLength"], json!(4_000));
        assert_eq!(spec.input_schema["required"], json!(["action"]));
        assert_eq!(spec.input_schema["additionalProperties"], json!(false));
        assert!(!spec.parallel_safe, "one call per account at a time");
        let eff = call.effects(&ctx, &json!({"action": "call", "message": "hi"}));
        match &eff[..] {
            [Effect::Send { channel, payload }] => {
                assert_eq!(channel.as_str(), "wa-args");
                assert!(payload.contains("hi"), "{payload}");
            }
            _ => panic!("a placed call is announced on the channel"),
        }
        assert!(call.effects(&ctx, &json!({"action": "status"})).is_empty(), "status sends nothing");
    }

    /// The target comes from the session's route only (`agent-tools-call.ts:120-134, 222-235`):
    /// no route, another channel, a group without a sender or a LID all refuse instead of
    /// dialling something arbitrary.
    #[test]
    fn whatsapp_call_only_ever_dials_the_current_requester() {
        let dir = temp_dir("wa-tools-requester");
        let bin = fake_bin(&dir, "exit 0");
        paired_store(&dir, "wa-req");
        let none: Option<SessionOrigin> = None;
        let other_channel = Some(route("telegram", "1", None));
        let group = Some(route("wa-req", "120363@g.us", None));
        let unmapped: Option<SessionOrigin> = Some(Arc::new(|_: &str| None));
        let ctx = tool_ctx();
        for origin in [none, other_channel, group, unmapped] {
            let r = call_tool(call_shared("wa-req", &dir, &bin, origin)).call(&ctx, json!({"action": "call", "message": "hi"}));
            assert!(r.is_error, "{}", r.content);
            assert_eq!(r.content, "whatsapp_call only works in a WhatsApp conversation with a known requester");
        }
        let lid = call_tool(call_shared("wa-req", &dir, &bin, Some(route("wa-req", "999999999999999@lid", None))));
        assert_eq!(lid.call(&ctx, json!({"action": "call", "message": "hi"})).content, "Could not resolve the current WhatsApp requester to a phone number");
    }

    /// The process runner behind `place()`: bounded window, cancel, exit status and the output
    /// cap (`agent-tools-call.ts:256-288`). Driven directly because reaching it through
    /// `place()` would install a TTS provider into the process-global.
    #[test]
    fn whatsapp_call_bounded_runner_bounds_window_and_honours_cancel() {
        let dir = temp_dir("wa-tools-run");
        let sh = |c: &str| vec!["/bin/sh".to_string(), "-c".to_string(), c.to_string()];
        let free = seagent_core::Cancel::new();

        let (ended, out) = run_bounded(&sh("echo out; echo err 1>&2; exit 3"), &dir, Duration::from_secs(10), &free).unwrap();
        assert!(matches!(ended, Ended::Exit(3)), "an early failure is reported, not hidden");
        assert!(out.contains("out") && out.contains("err"), "{out}");

        let cancel = seagent_core::Cancel::new();
        let c = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            c.cancel();
        });
        let t = Instant::now();
        let (ended, _) = run_bounded(&sh("sleep 30"), &dir, Duration::from_millis(MAX_CALL_WINDOW_MS), &cancel).unwrap();
        assert!(matches!(ended, Ended::Cancelled), "a cancelled call is not a success");
        assert!(t.elapsed() < Duration::from_secs(5), "cancel does not wait for the window: {:?}", t.elapsed());

        let t = Instant::now();
        let (ended, _) = run_bounded(&sh("sleep 30"), &dir, Duration::from_millis(150), &seagent_core::Cancel::new()).unwrap();
        assert!(matches!(ended, Ended::Timeout), "the window is enforced");
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());

        let (_, out) = run_bounded(&sh("head -c 200000 /dev/zero | tr '\\0' x"), &dir, Duration::from_secs(20), &seagent_core::Cancel::new()).unwrap();
        assert_eq!(out.len(), MAX_COMMAND_OUTPUT, "captured output is capped");
        assert!(out.bytes().all(|b| b == b'x'));

        match run_bounded(&["/nonexistent/meowcaller".into()], &dir, Duration::from_secs(5), &seagent_core::Cancel::new()) {
            Err(e) => assert!(e.starts_with("cannot start MeowCaller:"), "{e}"),
            Ok(_) => panic!("a missing binary must be reported, not silently ignored"),
        }
    }

    // ───────────── helpers ─────────────

    /// `requester_e164` is the only path from a WhatsApp id to a dialled number.
    #[test]
    fn whatsapp_requester_e164_maps_phone_jids_only() {
        for (id, want) in [
            ("15551234567", Some("+15551234567")),
            ("whatsapp:+1 555 000 1111", Some("+15550001111")),
            ("15551234567@c.us", Some("+15551234567")),
            ("15551234567@s.whatsapp.net", Some("+15551234567")),
            (" 15551234567:12@s.whatsapp.net ", Some("+15551234567")),
            ("155123", None),
            ("1555123456789012", None),
            ("999999999999999@lid", None),
            ("123456789@lid", None),
            ("120363@g.us", None),
            ("@s.whatsapp.net", None),
        ] {
            assert_eq!(requester_e164(id).as_deref(), want, "{id}");
        }
    }

    /// The synthesized speech is framed as a 44-byte RIFF/WAVE PCM16 mono header
    /// (`agent-tools-call.ts:76-99`), and malformed TTS output is refused.
    #[test]
    fn whatsapp_wav_pcm16_mono_writes_a_riff_header() {
        let pcm = [1u8, 0, 2, 0];
        let wav = wav_pcm16_mono(&pcm, 8_000).unwrap();
        assert_eq!(wav.len(), 44 + pcm.len());
        let u32le = |at: usize| u32::from_le_bytes(wav[at..at + 4].try_into().unwrap());
        let u16le = |at: usize| u16::from_le_bytes(wav[at..at + 2].try_into().unwrap());
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(u32le(4), 36 + pcm.len() as u32);
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(&wav[12..16], b"fmt ");
        assert_eq!(u32le(16), 16, "fmt chunk size");
        assert_eq!(u16le(20), 1, "PCM");
        assert_eq!(u16le(22), 1, "mono");
        assert_eq!(u32le(24), 8_000, "sample rate");
        assert_eq!(u32le(28), 16_000, "byte rate = rate * block align");
        assert_eq!(u16le(32), 2, "block align");
        assert_eq!(u16le(34), 16, "bits per sample");
        assert_eq!(&wav[36..40], b"data");
        assert_eq!(u32le(40), pcm.len() as u32);
        assert_eq!(&wav[44..], &pcm[..]);
        assert_eq!(wav_pcm16_mono(&[], 8_000).unwrap_err(), "TTS returned invalid 16-bit PCM audio");
        assert_eq!(wav_pcm16_mono(&[0], 8_000).unwrap_err(), "TTS returned invalid 16-bit PCM audio");
        assert_eq!(wav_pcm16_mono(&pcm, 0).unwrap_err(), "TTS returned an invalid sample rate");
    }

    /// `agent-tools-call.ts:112-118`: connect + answer + shutdown grace, plus the audio length,
    /// capped at the 60-second message limit.
    #[test]
    fn whatsapp_call_window_is_the_upstream_budget() {
        assert_eq!(MIN_CALL_WINDOW_MS, 115_000, "60 s connect + 45 s answer + 10 s grace");
        assert_eq!(MAX_CALL_WINDOW_MS, 175_000);
        assert_eq!(call_window_ms(0, 16_000).unwrap(), MIN_CALL_WINDOW_MS, "no audio still needs the handshake");
        assert_eq!(call_window_ms(16_000 * 2, 16_000).unwrap(), 116_000, "one second of speech");
        assert_eq!(call_window_ms(8_000 * 2 * 10, 8_000).unwrap(), 125_000, "the rate, not the byte count, sets the duration");
        assert_eq!(call_window_ms(16_000 * 2 * 60, 16_000).unwrap(), MAX_CALL_WINDOW_MS, "a 60 s message is the maximum");
        assert_eq!(call_window_ms(16_000 * 2 * 61, 16_000).unwrap_err(), "TTS audio exceeds the 60-second WhatsApp call limit");
    }

    /// The companion state lives beside the channel's other state, scoped to the account.
    #[test]
    fn whatsapp_calls_dir_is_scoped_to_the_account() {
        let sh = base_shared("wa-guard", "http://127.0.0.1:9", Path::new("/var/lib/seagent"));
        assert_eq!(calls_dir(&sh), Path::new("/var/lib/seagent/wa-guard.whatsapp-calls"));
        assert_eq!(calls_dir(&sh).join(SESSION_DATABASE), Path::new("/var/lib/seagent/wa-guard.whatsapp-calls/wa-voip.db"));
    }
}
