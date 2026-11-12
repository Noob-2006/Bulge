//! The Meet bot process (`seagent meet bot`; Hermes `plugins/google_meet/meet_bot.py`, MIT).
//!
//! Configured by `SEAGENT_MEET_*` env, writes `status.json` + `transcript.txt` under
//! `SEAGENT_MEET_OUT_DIR`. Drives Chromium over DevTools instead of Playwright: navigate, fill
//! the guest name and press "Join now" / "Ask to join", toggle captions (`c`), install the
//! caption MutationObserver and drain it every second. No WebRTC audio parsing: Meet's
//! live captions are the transcript (lossy, English-biased, but no STT billing).
//! Exit reasons: SIGTERM, `duration_expired`, `lobby_timeout`, `denied`, `page_closed`.
//!
//! Realtime mode: a PulseAudio null-sink + virtual source (`pactl`) becomes Chrome's mic
//! (`PULSE_SOURCE`); `say_queue.jsonl` entries are synthesized with the configured TTS
//! chain and played into the sink (`paplay --raw`). A caption from a human speaker while
//! we talk cancels the current utterance (barge-in), as upstream.

use super::meet::{now_secs, write_json};
use seagent_browser::cdp::Conn;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

/// Caption scraper (upstream `_CAPTION_OBSERVER_JS`), queue drained by `__arkMeetDrain()`.
pub const CAPTION_OBSERVER_JS: &str = r#"(() => {
  if (window.__arkMeetInstalled) return true;
  window.__arkMeetInstalled = true;
  window.__arkMeetQueue = [];
  const captionSelector = '[role="region"][aria-label*="aption" i], div[jsname="YSxPC"], div[jsname="tgaKEf"]';
  function pushEntry(speaker, text) {
    if (!text || !text.trim()) return;
    window.__arkMeetQueue.push({ ts: Date.now(), speaker: (speaker || '').trim(), text: text.trim() });
  }
  function scan(root) {
    const rows = root.querySelectorAll('div[jsname="dsyhDe"], div.CNusmb, div.TBMuR');
    if (rows.length) {
      rows.forEach((row) => {
        const spkEl = row.querySelector('div.KcIKyf, div.zs7s8d, span[jsname="YSxPC"]');
        const txtEl = row.querySelector('div.bh44bd, span[jsname="tgaKEf"], div.iTTPOb');
        pushEntry(spkEl ? spkEl.innerText : '', txtEl ? txtEl.innerText : row.innerText);
      });
      return;
    }
    pushEntry('', (root.innerText || '').split('\n').filter(Boolean).pop());
  }
  function attach() {
    const el = document.querySelector(captionSelector);
    if (!el) return false;
    new MutationObserver(() => scan(el)).observe(el, { childList: true, subtree: true, characterData: true });
    scan(el);
    return true;
  }
  if (!attach()) { const iv = setInterval(() => { if (attach()) clearInterval(iv); }, 1500); }
  window.__arkMeetDrain = () => { const out = window.__arkMeetQueue.slice(); window.__arkMeetQueue = []; return out; };
  return true;
})()"#;

const ENABLE_CAPTIONS_JS: &str = "(() => { document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'c', code: 'KeyC', keyCode: 67, which: 67, bubbles: true })); return true; })()";
const LEAVE_CALL_JS: &str = "(() => { const b = document.querySelector('button[aria-label*=\"eave call\"]'); if (b) b.click(); return !!b; })()";
const ADMISSION_PROBE_JS: &str = r#"(() => {
  if (document.querySelector('button[aria-label*="eave call" i]')) return true;
  if (window.__arkMeetInstalled && document.querySelector('[role="region"][aria-label*="aption" i], div[jsname="YSxPC"], div[jsname="tgaKEf"]')) return true;
  return !!document.querySelector('[aria-label*="articipants" i]');
})()"#;
const DENIED_PROBE_JS: &str = r#"(() => {
  const text = document.body ? document.body.innerText || '' : '';
  return /You can't join this video call|You were removed from the meeting|No one responded to your request to join/i.test(text);
})()"#;
const DRAIN_JS: &str = "window.__arkMeetDrain && window.__arkMeetDrain()";
/// Unmute once admitted (upstream `_ensure_mic_on`).
const MIC_JS: &str = r#"(() => {
  const vis = (el) => !!el && el.getClientRects().length > 0;
  const muted = document.querySelector('button[aria-label*="Turn on microphone" i]');
  if (vis(muted)) { muted.click(); return 'unmuted_clicked'; }
  return vis(document.querySelector('button[aria-label*="Turn off microphone" i]')) ? 'unmuted' : 'unknown';
})()"#;

/// Fill the guest name, then press "Join now" or "Ask to join" (upstream `_join`).
fn join_js(name: &str) -> String {
    format!(
        r#"(() => {{
  const vis = (el) => !!el && el.getClientRects().length > 0;
  const box = [...document.querySelectorAll('input')].find((i) => /name/i.test(i.getAttribute('aria-label') || '') && vis(i));
  if (box && box.value !== {name}) {{
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(box, {name});
    box.dispatchEvent(new Event('input', {{ bubbles: true }}));
  }}
  for (const label of ['Join now', 'Ask to join']) {{
    const b = [...document.querySelectorAll('button, [role="button"]')].find((el) => vis(el) && ((el.innerText || el.getAttribute('aria-label') || '').toLowerCase().includes(label.toLowerCase())));
    if (b) {{ b.click(); return label; }}
  }}
  return null;
}})()"#,
        name = Value::String(name.to_string())
    )
}

pub fn parse_duration(raw: &str) -> Option<f64> {
    let r = raw.trim().to_lowercase();
    if r.is_empty() {
        return None;
    }
    let (num, mult) = match r.chars().last() {
        Some('h') => (&r[..r.len() - 1], 3600.0),
        Some('m') => (&r[..r.len() - 1], 60.0),
        Some('s') => (&r[..r.len() - 1], 1.0),
        _ => (r.as_str(), 1.0),
    };
    num.trim().parse::<f64>().ok().map(|n| n * mult)
}

/// Whether a caption speaker is probably a human rather than our own echo.
pub fn looks_like_human(speaker: &str, guest: &str) -> bool {
    let s = speaker.trim().to_lowercase();
    !s.is_empty() && s != "unknown" && s != "you" && s != guest.trim().to_lowercase()
}

/// Text-to-speech for `meet_say`: (PCM16 mono, sample rate).
pub type Speech = Arc<dyn Fn(&str) -> Result<(Vec<u8>, u32), String> + Send + Sync>;

pub struct BotConfig {
    pub url: String,
    pub out_dir: PathBuf,
    pub headed: bool,
    pub auth_state: Option<String>,
    pub guest_name: String,
    pub duration: Option<f64>,
    pub realtime: bool,
    pub lobby_timeout: f64,
    /// An existing DevTools endpoint instead of launching Chromium.
    pub cdp_url: Option<String>,
    pub chromium: String,
    pub pactl: String,
    pub player: String,
    pub speech: Option<Speech>,
}

/// Mirror of upstream `_BotState`: every change is flushed to `status.json`.
struct State {
    v: Value,
    path: PathBuf,
    transcript: PathBuf,
    seen: HashSet<String>,
}

impl State {
    fn new(out: &Path, id: &str, url: &str) -> State {
        let _ = std::fs::create_dir_all(out);
        let v = json!({
            "meetingId": id, "url": url, "inCall": false, "captioning": false, "captionsEnabledAttempted": false,
            "lobbyWaiting": false, "joinAttemptedAt": null, "joinedAt": null, "lastCaptionAt": null,
            "transcriptLines": 0, "transcriptPath": out.join("transcript.txt"), "error": null, "exited": false,
            "pid": std::process::id(), "realtime": false, "realtimeReady": false, "realtimeDevice": null,
            "audioBytesOut": 0, "lastAudioOutAt": null, "lastBargeInAt": null, "leaveReason": null, "micState": null,
        });
        let s = State { v, path: out.join("status.json"), transcript: out.join("transcript.txt"), seen: HashSet::new() };
        s.flush();
        s
    }
    fn flush(&self) {
        write_json(&self.path, &self.v);
    }
    fn set(&mut self, kv: Value) {
        if let Some(o) = kv.as_object() {
            for (k, x) in o {
                self.v[k] = x.clone();
            }
        }
        self.flush();
    }
    fn get(&self, k: &str) -> &Value {
        &self.v[k]
    }
    fn record(&mut self, speaker: &str, text: &str) {
        let speaker = Some(speaker.trim()).filter(|s| !s.is_empty()).unwrap_or("Unknown");
        let text = text.trim();
        let key = format!("{speaker}|{text}");
        if text.is_empty() || !self.seen.insert(key) {
            return;
        }
        let n = self.v["transcriptLines"].as_u64().unwrap_or(0) + 1;
        let now = now_secs();
        let ts = seagent_kernel::util::fmt_time(now as i64, local_offset_minutes());
        let hms = ts.rsplit(' ').next().unwrap_or(&ts).chars().take(8).collect::<String>();
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.transcript) {
            let _ = writeln!(f, "[{hms}] {speaker}: {text}");
        }
        self.v["transcriptLines"] = json!(n);
        self.v["lastCaptionAt"] = json!(now);
        self.flush();
    }
}

/// Minutes east of UTC now (`GetTimeZoneInformation`: UTC = local + bias).
#[cfg(windows)]
fn local_offset_minutes() -> i32 {
    use windows_sys::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
    // SAFETY: zeroed POD out-parameter.
    unsafe {
        let mut tz: TIME_ZONE_INFORMATION = std::mem::zeroed();
        let id = GetTimeZoneInformation(&mut tz);
        let extra = match id {
            2 => tz.DaylightBias, // TIME_ZONE_ID_DAYLIGHT
            1 => tz.StandardBias, // TIME_ZONE_ID_STANDARD
            _ => 0,
        };
        -(tz.Bias + extra)
    }
}

#[cfg(not(windows))]
fn local_offset_minutes() -> i32 {
    // SAFETY: localtime_r only writes into the struct we pass.
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        (tm.tm_gmtoff / 60) as i32
    }
}

/// DevTools page handle: browser connection + flattened target session.
struct Page {
    conn: Conn,
    session: String,
    target: String,
}

impl Page {
    fn eval(&self, expr: &str) -> Result<Value, String> {
        let r = self.conn.call("Runtime.evaluate", json!({"expression": expr, "returnByValue": true, "awaitPromise": false}), Some(&self.session))?;
        if let Some(e) = r.get("exceptionDetails") {
            return Err(e["text"].as_str().unwrap_or("evaluation failed").to_string());
        }
        Ok(r["result"]["value"].clone())
    }
    fn probe(&self, js: &str) -> bool {
        self.eval(js).ok().and_then(|v| v.as_bool()).unwrap_or(false)
    }
}

/// Virtual microphone (upstream `AudioBridge`, Linux PulseAudio / pipewire-pulse).
struct Bridge {
    pactl: String,
    modules: Vec<String>,
    source: String,
    sink: String,
}

impl Bridge {
    #[cfg_attr(windows, allow(dead_code))]
    fn setup(pactl: &str) -> Result<Bridge, String> {
        let run = |args: &[&str]| -> Result<String, String> {
            let o = seagent_core::platform::proc::command(pactl).args(args).stdin(Stdio::null()).output().map_err(|e| if e.kind() == std::io::ErrorKind::NotFound { "pactl not found — install PulseAudio/pipewire-pulse".to_string() } else { e.to_string() })?;
            if !o.status.success() {
                return Err(format!("pactl {} failed: {}", args[..2.min(args.len())].join(" "), String::from_utf8_lossy(&o.stderr).trim()));
            }
            let out = String::from_utf8_lossy(&o.stdout).to_string();
            let id = out.trim().lines().next().unwrap_or("").split_whitespace().last().unwrap_or("").to_string();
            if id.parse::<u64>().is_err() {
                return Err(format!("could not parse pactl module id from: {out:?}"));
            }
            Ok(id)
        };
        let (sink, src) = ("seagent_meet_sink".to_string(), "seagent_meet_src".to_string());
        let sink_id = run(&["load-module", "module-null-sink", &format!("sink_name={sink}"), "sink_properties=device.description=SeagentMeetSink"])?;
        match run(&["load-module", "module-virtual-source", &format!("source_name={src}"), &format!("master={sink}.monitor")]) {
            Ok(src_id) => Ok(Bridge { pactl: pactl.into(), modules: vec![sink_id, src_id], source: src, sink }),
            Err(e) => {
                let _ = seagent_core::platform::proc::command(pactl).args(["unload-module", &sink_id]).output();
                Err(e)
            }
        }
    }
    fn teardown(&mut self) {
        for m in self.modules.drain(..).rev() {
            let _ = seagent_core::platform::proc::command(&self.pactl).args(["unload-module", &m]).stdin(Stdio::null()).output();
        }
    }
}

/// The say-queue speaker: synthesize each new entry and play it into the sink.
struct Speaker {
    queue: PathBuf,
    processed: PathBuf,
    done: HashSet<String>,
    playing: Arc<Mutex<Option<Child>>>,
}

impl Speaker {
    fn pending(&mut self) -> Vec<(String, String)> {
        let text = super::with_lock(&self.queue, || std::fs::read_to_string(&self.queue)).unwrap_or_default();
        text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter_map(|v| Some((v["id"].as_str()?.to_string(), v["text"].as_str()?.to_string()))).filter(|(id, _)| !self.done.contains(id)).collect()
    }
    fn mark(&mut self, id: &str, status: &str, err: Option<&str>) {
        self.done.insert(id.to_string());
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.processed) {
            let _ = writeln!(f, "{}", json!({"id": id, "status": status, "error": err, "at": now_secs()}));
        }
    }
    /// Barge-in: stop the current utterance.
    fn cancel(&self) -> bool {
        let mut guard = self.playing.lock().unwrap();
        let Some(c) = guard.as_mut() else { return false };
        if c.try_wait().ok().flatten().is_some() {
            return false;
        }
        let _ = c.kill();
        true
    }
}

fn play(player: &str, sink: &str, pcm: &[u8], rate: u32) -> Result<Child, String> {
    let mut c = seagent_core::platform::proc::command(player)
        .args(["--raw", &format!("--rate={rate}"), "--format=s16le", "--channels=1", &format!("--device={sink}"), "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| if e.kind() == std::io::ErrorKind::NotFound { "paplay not found — install pulseaudio-utils for realtime on Linux".to_string() } else { e.to_string() })?;
    let mut stdin = c.stdin.take().ok_or("player has no stdin")?;
    let data = pcm.to_vec();
    std::thread::spawn(move || {
        use std::io::Write;
        let _ = stdin.write_all(&data);
    });
    Ok(c)
}

fn connect(cfg: &BotConfig, profile: &Path, env: Vec<(String, String)>) -> Result<(Conn, Option<i32>), String> {
    if let Some(u) = &cfg.cdp_url {
        let ws = if u.starts_with("ws") { u.clone() } else { seagent_browser::cdp::resolve_ws(u, None, Duration::from_secs(10))? };
        return Ok((Conn::connect(&ws, &[], Duration::from_secs(10))?, None));
    }
    let exe = seagent_browser::launch::find_executable(&cfg.chromium)?;
    let mut args = vec!["--use-fake-ui-for-media-stream".to_string(), "--disable-blink-features=AutomationControlled".to_string()];
    if !cfg.realtime {
        args.insert(1, "--use-fake-device-for-media-stream".into());
    }
    let opts = seagent_browser::launch::LaunchOpts { exe: &exe, user_data_dir: profile, headless: !cfg.headed, no_sandbox: false, extra_args: &args, port: 0, managed: true, env };
    let l = seagent_browser::launch::launch(&opts, Duration::from_secs(30))?;
    Ok((Conn::connect(&l.ws, &[], Duration::from_secs(10))?, l.owned.then_some(l.pid)))
}

fn open_page(conn: Conn, cfg: &BotConfig) -> Result<Page, String> {
    let t = conn.call("Target.createTarget", json!({"url": "about:blank"}), None)?;
    let target = t["targetId"].as_str().ok_or("Target.createTarget returned no targetId")?.to_string();
    let a = conn.call("Target.attachToTarget", json!({"targetId": target, "flatten": true}), None)?;
    let session = a["sessionId"].as_str().ok_or("Target.attachToTarget returned no sessionId")?.to_string();
    let page = Page { conn, session, target };
    let _ = page.conn.call("Browser.grantPermissions", json!({"origin": "https://meet.google.com", "permissions": ["audioCapture", "videoCapture"]}), None);
    for m in ["Page.enable", "Runtime.enable"] {
        let _ = page.conn.call(m, json!({}), Some(&page.session));
    }
    let _ = page.conn.call("Emulation.setUserAgentOverride", json!({"userAgent": USER_AGENT}), Some(&page.session));
    let _ = page.conn.call("Emulation.setDeviceMetricsOverride", json!({"width": 1280, "height": 800, "deviceScaleFactor": 1, "mobile": false}), Some(&page.session));
    // Playwright `storage_state` (signed-in Google profile): cookies only.
    if let Some(st) = cfg.auth_state.as_deref().filter(|p| Path::new(p).is_file()) {
        if let Some(cookies) = std::fs::read_to_string(st).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).and_then(|v| v["cookies"].as_array().cloned()) {
            let _ = page.conn.call("Network.setCookies", json!({"cookies": cookies}), Some(&page.session));
        }
    }
    Ok(page)
}

/// Run the bot; returns the process exit code (0 clean, 1 crash, 2 bad config, 4 navigation).
pub fn run(cfg: BotConfig) -> i32 {
    if !super::meet::is_safe_meet_url(&cfg.url) {
        eprintln!("google_meet bot: refusing to launch — SEAGENT_MEET_URL must be a meet.google.com URL. got: {:?}", cfg.url);
        return 2;
    }
    let mut st = State::new(&cfg.out_dir, &super::meet::meeting_id_from_url(&cfg.url), &cfg.url);
    let mut bridge = None;
    let mut env = Vec::new();
    if cfg.realtime {
        if cfg.speech.is_none() {
            st.set(json!({"error": "realtime mode requested but no text-to-speech provider is configured ([media.tts]) — falling back to transcribe"}));
        } else {
            // Windows has no PulseAudio null-sink: the virtual microphone would be a third-party
            // audio cable driver (VB-CABLE), not wired up yet — say so and transcribe.
            #[cfg(windows)]
            let setup: Result<Bridge, String> = Err("realtime speaking needs a virtual microphone; on Windows that is a virtual audio cable driver, which seagent does not drive yet (run the bot on a Linux / macOS node for realtime)".into());
            #[cfg(not(windows))]
            let setup = Bridge::setup(&cfg.pactl);
            match setup {
                Ok(b) => {
                    st.set(json!({"realtime": true, "realtimeDevice": b.source}));
                    env.push(("PULSE_SOURCE".to_string(), b.source.clone()));
                    bridge = Some(b);
                }
                Err(e) => st.set(json!({"error": format!("audio bridge setup failed: {e} — falling back to transcribe")})),
            }
        }
    }
    let realtime = bridge.is_some();
    let code = match session(&cfg, &mut st, &bridge, env, realtime) {
        Ok(code) => code,
        Err(e) => {
            st.set(json!({"error": format!("unhandled: {e}"), "exited": true}));
            1
        }
    };
    if let Some(b) = bridge.as_mut() {
        b.teardown();
    }
    code
}

fn session(cfg: &BotConfig, st: &mut State, bridge: &Option<Bridge>, env: Vec<(String, String)>, realtime: bool) -> Result<i32, String> {
    let profile = cfg.out_dir.join("chrome-profile");
    let (conn, owned) = connect(&BotConfig { realtime, ..clone_cfg(cfg) }, &profile, env)?;
    let page = open_page(conn, cfg)?;
    if let Err(e) = page.conn.call("Page.navigate", json!({"url": cfg.url}), Some(&page.session)).and_then(|r| r.get("errorText").and_then(Value::as_str).map(|e| Err(e.to_string())).unwrap_or(Ok(()))) {
        st.set(json!({"error": format!("navigate failed: {e}"), "exited": true}));
        close(&page, owned);
        return Ok(4);
    }
    // Wait for the DOM, then poll for the pre-join controls for up to 30 s.
    let until = Instant::now() + Duration::from_secs(30);
    while Instant::now() < until && !STOP.load(Ordering::SeqCst) && page.eval("document.readyState").ok().and_then(|v| v.as_str().map(str::to_string)).is_none_or(|s| s == "loading") {
        std::thread::sleep(Duration::from_millis(200));
    }
    let js = join_js(&cfg.guest_name);
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(Value::String(label)) = page.eval(&js) {
            if label == "Ask to join" {
                st.set(json!({"lobbyWaiting": true}));
            }
            break;
        }
        if Instant::now() >= until || STOP.load(Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if page.eval(ENABLE_CAPTIONS_JS).is_ok() {
        st.set(json!({"captionsEnabledAttempted": true}));
    }
    if let Err(e) = page.eval(CAPTION_OBSERVER_JS) {
        st.set(json!({"error": format!("caption observer install failed: {e}")}));
    }
    st.set(json!({"captioning": true, "joinAttemptedAt": now_secs()}));
    let mut speaker = None;
    if let (true, Some(b)) = (realtime, bridge) {
        let q = cfg.out_dir.join("say_queue.jsonl");
        let _ = std::fs::OpenOptions::new().create(true).append(true).open(&q);
        speaker = Some((Speaker { queue: q, processed: cfg.out_dir.join("say_processed.jsonl"), done: HashSet::new(), playing: Arc::new(Mutex::new(None)) }, b.sink.clone()));
        st.set(json!({"realtimeReady": true}));
    }
    drain_loop(&page, cfg, st, &mut speaker);
    let _ = page.eval(LEAVE_CALL_JS);
    if let Some((s, _)) = &speaker {
        s.cancel();
    }
    close(&page, owned);
    st.set(json!({"inCall": false, "captioning": false, "exited": true}));
    Ok(0)
}

fn clone_cfg(c: &BotConfig) -> BotConfig {
    BotConfig { url: c.url.clone(), out_dir: c.out_dir.clone(), headed: c.headed, auth_state: c.auth_state.clone(), guest_name: c.guest_name.clone(), duration: c.duration, realtime: c.realtime, lobby_timeout: c.lobby_timeout, cdp_url: c.cdp_url.clone(), chromium: c.chromium.clone(), pactl: c.pactl.clone(), player: c.player.clone(), speech: c.speech.clone() }
}

fn close(page: &Page, owned: Option<i32>) {
    let _ = page.conn.call("Target.closeTarget", json!({"targetId": page.target}), None);
    if let Some(pid) = owned {
        let _ = page.conn.call("Browser.close", json!({}), None);
        seagent_browser::util::kill_group(pid, Duration::from_secs(3));
    }
    page.conn.close();
}

fn drain_loop(page: &Page, cfg: &BotConfig, st: &mut State, speaker: &mut Option<(Speaker, String)>) {
    let start = now_secs();
    let deadline = cfg.duration.map(|d| start + d);
    let lobby_deadline = start + cfg.lobby_timeout;
    let mut last_check = 0.0;
    while !STOP.load(Ordering::SeqCst) {
        let now = now_secs();
        if deadline.is_some_and(|d| now > d) {
            st.set(json!({"leaveReason": "duration_expired"}));
            return;
        }
        if st.get("inCall") != &json!(true) && now - last_check > 3.0 {
            last_check = now;
            if page.probe(ADMISSION_PROBE_JS) {
                let mic = page.eval(MIC_JS).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_else(|| "unknown".into());
                st.set(json!({"inCall": true, "lobbyWaiting": false, "joinedAt": now, "micState": mic}));
            } else if now > lobby_deadline {
                let waited = st.get("joinAttemptedAt").as_f64().map(|t| (lobby_deadline - t) as i64).unwrap_or(0);
                st.set(json!({"error": format!("lobby timeout — host never admitted the bot within {waited}s"), "leaveReason": "lobby_timeout"}));
                return;
            } else if page.probe(DENIED_PROBE_JS) {
                st.set(json!({"error": "host denied admission", "leaveReason": "denied"}));
                return;
            }
        }
        match page.eval(DRAIN_JS) {
            Ok(Value::Array(items)) => {
                for e in items.iter().filter(|e| e.is_object()) {
                    let who = e["speaker"].as_str().unwrap_or("").to_string();
                    st.record(&who, e["text"].as_str().unwrap_or(""));
                    if let Some((s, _)) = speaker.as_ref() {
                        if looks_like_human(&who, &cfg.guest_name) && s.cancel() {
                            st.set(json!({"lastBargeInAt": now}));
                        }
                    }
                }
            }
            Ok(_) => {}
            Err(_) if page.conn.is_closed() => {
                st.set(json!({"leaveReason": "page_closed"}));
                return;
            }
            Err(_) => {}
        }
        if let (Some((s, sink)), Some(tts)) = (speaker.as_mut(), cfg.speech.as_ref()) {
            let busy = s.playing.lock().unwrap().as_mut().is_some_and(|c| c.try_wait().ok().flatten().is_none());
            if !busy {
                if let Some((id, text)) = s.pending().into_iter().next() {
                    match tts(&text).and_then(|(pcm, rate)| play(&cfg.player, sink, &pcm, rate).map(|c| (c, pcm.len()))) {
                        Ok((child, n)) => {
                            *s.playing.lock().unwrap() = Some(child);
                            let total = st.get("audioBytesOut").as_u64().unwrap_or(0) + n as u64;
                            st.set(json!({"audioBytesOut": total, "lastAudioOutAt": now_secs()}));
                            s.mark(&id, "spoken", None);
                        }
                        Err(e) => {
                            s.mark(&id, "failed", Some(&e));
                            st.set(json!({"error": format!("realtime speech failed: {e}")}));
                        }
                    }
                }
            }
        }
        let tick = Instant::now() + Duration::from_secs(1);
        while Instant::now() < tick && !STOP.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn cfg_str(cfg: &toml::Table, k: &str) -> Option<String> {
    cfg.get(k).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

/// `None` when the plugin can run locally, else what is missing (upstream `check_meet_requirements`).
pub fn prerequisites(cfg: &toml::Table) -> Option<String> {
    // Windows: the transcript bot drives Edge / Chrome over CDP like elsewhere; realtime
    // speaking (the virtual microphone) is Linux / macOS only and reported when asked for.
    if !cfg!(any(target_os = "linux", target_os = "macos", windows)) {
        return Some("google_meet is supported on Linux, macOS and Windows only".into());
    }
    if cfg_str(cfg, "cdp_url").is_some() {
        return None;
    }
    seagent_browser::launch::find_executable(&cfg_str(cfg, "chromium").unwrap_or_default()).err().map(|e| format!("google_meet prerequisites missing — {e}; install Chromium or set [meetings.google_meet] chromium = \"/path/to/chrome\""))
}

fn which(cmd: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(cmd).is_file()))
}

/// `seagent meet setup`: what each mode needs and whether it is there.
pub fn setup_report(cfg: &toml::Table) -> Value {
    let chromium = seagent_browser::launch::find_executable(&cfg_str(cfg, "chromium").unwrap_or_default());
    json!({
        "ok": prerequisites(cfg).is_none(),
        "platform": std::env::consts::OS,
        "chromium": chromium.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|e| e.clone()),
        "transcribe_ready": chromium.is_ok() || cfg_str(cfg, "cdp_url").is_some(),
        "realtime": {"pactl": which(&cfg_str(cfg, "pactl").unwrap_or_else(|| "pactl".into())), "paplay": which(&cfg_str(cfg, "player").unwrap_or_else(|| "paplay".into())), "tts": "uses [media.tts] (any configured provider)"},
        "auth_state": cfg_str(cfg, "auth_state"),
        "note": "Explicit by design: the bot only joins meet.google.com URLs you pass; announce yourself in the meeting.",
    })
}

/// Telephony-free speech for the bot: seagent-media's TTS chain as raw PCM.
fn speech_from_config() -> Option<Speech> {
    let paths = seagent_kernel::config::Paths::from_env();
    let media = super::media(&paths)?;
    Some(Arc::new(move |text: &str| super::pcm_speech(&media, text)))
}

/// `seagent meet bot`: the detached bot process (configuration from `SEAGENT_MEET_*`).
pub fn run_from_env(cfg: &toml::Table) -> i32 {
    // SAFETY: installing a handler that only stores to an atomic.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }
    #[cfg(windows)]
    crate::ops::hostos::on_stop_signals(&STOP);
    let env = |k: &str| std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let Some(out) = env("SEAGENT_MEET_OUT_DIR") else {
        eprintln!("google_meet bot: SEAGENT_MEET_OUT_DIR is required");
        return 2;
    };
    let realtime = env("SEAGENT_MEET_MODE").is_some_and(|m| m.eq_ignore_ascii_case("realtime"));
    run(BotConfig {
        url: env("SEAGENT_MEET_URL").unwrap_or_default(),
        out_dir: PathBuf::from(out),
        headed: env("SEAGENT_MEET_HEADED").is_some_and(|h| matches!(h.to_lowercase().as_str(), "1" | "true" | "yes")),
        auth_state: env("SEAGENT_MEET_AUTH_STATE"),
        guest_name: env("SEAGENT_MEET_GUEST_NAME").unwrap_or_else(|| "SE Agent Agent".into()),
        duration: env("SEAGENT_MEET_DURATION").and_then(|d| parse_duration(&d)),
        realtime,
        lobby_timeout: env("SEAGENT_MEET_LOBBY_TIMEOUT").and_then(|t| t.parse().ok()).unwrap_or(300.0),
        cdp_url: env("SEAGENT_MEET_CDP").or_else(|| cfg_str(cfg, "cdp_url")),
        chromium: cfg_str(cfg, "chromium").unwrap_or_default(),
        pactl: cfg_str(cfg, "pactl").unwrap_or_else(|| "pactl".into()),
        player: cfg_str(cfg, "player").unwrap_or_else(|| "paplay".into()),
        speech: if realtime { speech_from_config() } else { None },
    })
}

#[cfg(test)]
#[cfg_attr(not(unix), allow(dead_code, unused_imports))]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn helpers_match_upstream() {
        assert_eq!(parse_duration("30m"), Some(1800.0));
        assert_eq!(parse_duration("2h"), Some(7200.0));
        assert_eq!(parse_duration("90"), Some(90.0));
        assert_eq!(parse_duration("x"), None);
        assert!(looks_like_human("Alice", "SE Agent Agent"));
        assert!(!looks_like_human("seagent agent", "Seagent Agent") && !looks_like_human("You", "x") && !looks_like_human("", "x"));
        assert!(join_js("O'Neil \"x\"").contains("\"O'Neil \\\"x\\\"\""));
    }

    #[cfg(unix)]
    /// The bot against a fake DevTools endpoint: join → lobby → admitted, captions deduped
    /// into the transcript, realtime say-queue spoken through a fake pactl/paplay, barge-in,
    /// leave on duration expiry.
    #[test]
    fn bot_joins_scrapes_captions_speaks_and_leaves() {
        let dir = seagent_core::tmp::scratch_path(format!("seagent-meet-bot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let drains = Arc::new(AtomicUsize::new(0));
        let d2 = drains.clone();
        let fake = crate::meetings::fakecdp::start(Arc::new(move |m, p, _s| match m {
            "Target.createTarget" => (json!({"targetId": "T1"}), vec![]),
            "Target.attachToTarget" => (json!({"sessionId": "S1"}), vec![]),
            "Runtime.evaluate" => {
                let e = p["expression"].as_str().unwrap_or("");
                let v = if e == "document.readyState" {
                    json!("complete")
                } else if e.contains("Ask to join") {
                    json!("Ask to join")
                } else if e.contains("eave call\" i]')) return true") {
                    json!(true)
                } else if e.contains("__arkMeetDrain()") {
                    match d2.fetch_add(1, Ordering::SeqCst) {
                        0 => json!([{"speaker": "Alice", "text": "Hello team"}, {"speaker": "Alice", "text": "Hello team"}]),
                        1 => json!([{"speaker": "", "text": "anonymous line"}]),
                        2 => json!([{"speaker": "Bob", "text": "wait"}]),
                        _ => json!([]),
                    }
                } else if e.contains("Turn on microphone") {
                    json!("unmuted_clicked")
                } else {
                    json!(false)
                };
                (json!({"result": {"value": v}}), vec![])
            }
            _ => (json!({}), vec![]),
        }));
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let pactl = bin.join("pactl");
        let player = bin.join("paplay");
        std::fs::write(&pactl, format!("#!/bin/sh\necho \"$@\" >> {}/pactl.log\necho 42\n", dir.display())).unwrap();
        std::fs::write(&player, format!("#!/bin/sh\necho \"$@\" >> {d}/play.log\ncat > {d}/played.raw\nsleep 3\n", d = dir.display())).unwrap();
        for f in [&pactl, &player] {
            #[cfg(unix)]
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let out = dir.join("abc-defg-hij");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("say_queue.jsonl"), "{\"id\":\"q1\",\"text\":\"hi all\"}\n").unwrap();
        let code = run(BotConfig {
            url: "https://meet.google.com/abc-defg-hij".into(),
            out_dir: out.clone(),
            headed: false,
            auth_state: None,
            guest_name: "SE Agent Agent".into(),
            duration: Some(4.5),
            realtime: true,
            lobby_timeout: 60.0,
            cdp_url: Some(fake.http.clone()),
            chromium: String::new(),
            pactl: pactl.display().to_string(),
            player: player.display().to_string(),
            speech: Some(Arc::new(|t: &str| Ok((vec![1u8; t.len() * 2], 24000)))),
        });
        assert_eq!(code, 0);
        let status: Value = serde_json::from_str(&std::fs::read_to_string(out.join("status.json")).unwrap()).unwrap();
        assert_eq!((status["exited"].as_bool(), status["leaveReason"].as_str(), status["micState"].as_str()), (Some(true), Some("duration_expired"), Some("unmuted_clicked")));
        assert_eq!((status["realtime"].as_bool(), status["realtimeDevice"].as_str(), status["audioBytesOut"].as_u64()), (Some(true), Some("seagent_meet_src"), Some(12)));
        assert!(status["lastBargeInAt"].is_number(), "Bob spoke while we were talking: {status}");
        let t = std::fs::read_to_string(out.join("transcript.txt")).unwrap();
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines.len(), 3, "{t}");
        assert!(lines[0].ends_with("] Alice: Hello team") && lines[1].ends_with("] Unknown: anonymous line"));
        assert!(std::fs::read_to_string(dir.join("play.log")).unwrap().contains("--rate=24000 --format=s16le --channels=1 --device=seagent_meet_sink -"));
        assert_eq!(std::fs::read(dir.join("played.raw")).unwrap().len(), 12);
        let pl = std::fs::read_to_string(dir.join("pactl.log")).unwrap();
        assert!(pl.contains("module-null-sink") && pl.contains("master=seagent_meet_sink.monitor") && pl.matches("unload-module 42").count() == 2, "{pl}");
        assert!(std::fs::read_to_string(out.join("say_processed.jsonl")).unwrap().contains("\"spoken\""));
        let seen: Vec<String> = fake.seen.lock().unwrap().iter().filter_map(|v| v["params"]["expression"].as_str().map(str::to_string)).collect();
        assert!(seen.iter().any(|e| e.contains("KeyC")) && seen.iter().any(|e| e.contains("eave call\"]')")), "captions toggled and leave clicked");
        let urls: Vec<Value> = fake.seen.lock().unwrap().iter().filter(|v| v["method"] == "Page.navigate").map(|v| v["params"]["url"].clone()).collect();
        assert_eq!(urls, [json!("https://meet.google.com/abc-defg-hij")]);
        // Unsafe URL: refused before anything launches.
        assert_eq!(run(BotConfig { url: "https://evil.example/abc-defg-hij".into(), ..clone_cfg(&BotConfig { url: String::new(), out_dir: out.clone(), headed: false, auth_state: None, guest_name: String::new(), duration: None, realtime: false, lobby_timeout: 1.0, cdp_url: None, chromium: String::new(), pactl: String::new(), player: String::new(), speech: None }) }), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
