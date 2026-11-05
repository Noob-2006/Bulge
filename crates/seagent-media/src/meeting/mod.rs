//! Meeting bots (OpenClaw `src/meeting-bot` + `extensions/{google-meet,teams-meetings,
//! zoom-meetings,slack-huddles}`, MIT): the `google_meet`, `teams_meetings`,
//! `zoom_meetings` and `slack_huddles` tools join a meeting as a browser guest in a
//! dedicated Chromium profile driven over CDP ([`cdp`]), using each platform's DOM
//! knowledge ([`platforms`], [`scripts`]).
//!
//! Modes: `transcribe` (observe-only: microphone off, live captions archived into the
//! session transcript) and `agent` (talk-back: microphone on; new caption lines are sent
//! to the agent ([`crate::agent`]) and its reply is spoken into the meeting through a
//! PulseAudio virtual microphone `seagent_meeting` — `action=setup` creates it). Google Meet
//! can also join by phone (`transport = "twilio"`: dial-in number + PIN through
//! [`crate::phone`]) and `create` a meeting through the Meet REST API.
//!
//! When a page needs a human (sign-in, host admission, passcode, CAPTCHA, permissions) the
//! session reports a `manualAction` instead of guessing.
//!
//! ```toml
//! [media.meeting]
//! cdp_url = ""                   # attach to this DevTools endpoint; "" = launch our own
//! port = 9333                    # DevTools port of the launched meeting browser
//! executable = ""                # Chromium-family binary ("" = search)
//! profile_dir = ""               # default ~/.local/share/seagent/meeting-chrome (keep signed in here)
//! headless = false
//! guest_name = "seagent"
//! default_mode = "transcribe"    # transcribe | agent
//! join_timeout_secs = 60
//! audio_sink = "seagent_meeting"     # PulseAudio sink the bot speaks into (its monitor is the mic)
//! player = ""                    # playback command template ({path} {sink}); default paplay
//! reply_quiet_secs = 3           # agent mode: speak after this much caption silence
//! [media.meeting.google-meet] guest_name = "…"   # per-platform overrides
//! [media.providers.google-meet] api_key = "<OAuth access token>"   # for create (Meet API)
//! ```

pub mod cdp;
pub mod platforms;
pub mod scripts;

use crate::Media;
use seagent_core::tool::arg_opt_str;
use seagent_core::{Cancel, Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use cdp::{Cdp, Tab};
use platforms::Platform;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub struct Line {
    pub speaker: String,
    pub text: String,
    pub at: u64,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub platform: Platform,
    pub url: String,
    pub mode: String,
    /// joining | waiting | active | ended
    pub state: String,
    pub transport: String,
    pub tab: Option<Tab>,
    pub health: Value,
    pub transcript: Vec<Line>,
    pub notes: Vec<String>,
    pub call_id: Option<String>,
    pub agent_session: Option<String>,
    consulted: usize,
}

impl Session {
    pub fn view(&self) -> Value {
        json!({"sessionId": self.id, "platform": self.platform.id(), "url": self.url, "mode": self.mode, "state": self.state, "transport": self.transport,
            "health": self.health, "manualAction": self.health.get("manualAction").cloned().unwrap_or(Value::Null), "transcriptLines": self.transcript.len(), "notes": self.notes, "callId": self.call_id})
    }
}

pub struct Meetings {
    pub m: Arc<Media>,
    sessions: Mutex<HashMap<String, Session>>,
    browser: Mutex<Option<String>>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Meetings {
    pub fn new(m: Arc<Media>) -> Arc<Meetings> {
        Arc::new(Meetings {
            m,
            sessions: Mutex::new(HashMap::new()),
            browser: Mutex::new(None),
        })
    }

    fn pcfg(&self, p: Platform, k: &str, d: &str) -> String {
        self.m
            .cfg
            .str(&format!("meeting.{}.{k}", p.id()))
            .or_else(|| self.m.cfg.str(&format!("meeting.{k}")))
            .unwrap_or_else(|| d.to_string())
    }

    /// The DevTools endpoint: configured, already running, or a freshly launched meeting browser.
    pub fn devtools(&self) -> Result<Cdp, String> {
        let mut g = self.browser.lock().unwrap();
        if let Some(b) = g.as_ref() {
            let c = Cdp::new(b);
            if c.version().is_ok() {
                return Ok(c);
            }
        }
        let cfg = self.m.cfg.str_or("meeting.cdp_url", "");
        if !cfg.is_empty() {
            let c = Cdp::new(&cfg);
            c.version()
                .map_err(|e| format!("meeting browser at {cfg} is not reachable: {e}"))?;
            *g = Some(cfg);
            return Ok(c);
        }
        let port = self.m.cfg.int_or("meeting.port", 9333) as u16;
        let base = format!("http://127.0.0.1:{port}");
        if Cdp::new(&base).version().is_err() {
            let exe = cdp::find_chrome(&self.m.cfg.str_or("meeting.executable", "")).ok_or("no Chromium-family browser found for meeting bots (install Chrome/Chromium or set [media.meeting] executable / cdp_url)")?;
            let dir = self
                .m
                .cfg
                .str("meeting.profile_dir")
                .map(|d| seagent_core::tool::expand_home(&d))
                .unwrap_or_else(|| {
                    seagent_core::layout::data_dir().join("meeting-chrome")
                });
            cdp::launch(
                &exe,
                port,
                &dir,
                self.m.cfg.bool_or("meeting.headless", false),
            )?;
        }
        *g = Some(base.clone());
        Ok(Cdp::new(&base))
    }

    fn origin(url: &str) -> String {
        let (s, r) = url.split_once("://").unwrap_or(("https", url));
        format!("{s}://{}", r.split(['/', '?', '#']).next().unwrap_or(""))
    }

    /// Join `url` (already validated) on `p`; polls the page until in the call, a manual
    /// action is needed, or the join timeout passes.
    pub fn join_url(
        self: &Arc<Self>,
        p: Platform,
        url: &str,
        mode: &str,
        cancel: &Cancel,
    ) -> Result<Value, String> {
        if !matches!(mode, "transcribe" | "agent") {
            return Err(format!("mode must be transcribe or agent, got `{mode}`"));
        }
        if let Some(s) = self.sessions.lock().unwrap().values().find(|s| {
            s.platform == p && s.state != "ended" && (p.same_meeting(&s.url, url) || s.url == url)
        }) {
            return Ok(json!({"reused": true, "session": s.view()}));
        }
        let c = self.devtools()?;
        let tab = match c
            .tabs()?
            .into_iter()
            .find(|t| p.same_meeting(&t.url, url) || t.url == url)
        {
            Some(t) => {
                c.activate(&t.id);
                t
            }
            None => c.open(url)?,
        };
        let _ = c.grant(
            &Self::origin(url),
            &["audioCapture", "videoCapture", "notifications"],
        );
        let id = format!(
            "{}-{}",
            p.reason_prefix(),
            seagent_net::crypto::random_token(6).to_ascii_lowercase()
        );
        let s = Session {
            id: id.clone(),
            platform: p,
            url: url.into(),
            mode: mode.into(),
            state: "joining".into(),
            transport: "chrome".into(),
            tab: Some(tab.clone()),
            health: json!({}),
            transcript: vec![],
            notes: vec![],
            call_id: None,
            agent_session: None,
            consulted: 0,
        };
        self.sessions.lock().unwrap().insert(id.clone(), s);
        let timeout =
            Duration::from_secs(self.m.cfg.int_or("meeting.join_timeout_secs", 60).max(1) as u64);
        let deadline = Instant::now() + timeout;
        let params = json!({"autoJoin": true, "guestName": self.pcfg(p, "guest_name", "seagent"), "allowMicrophone": mode == "agent", "captureCaptions": true, "prefix": p.reason_prefix(), "sessionId": id});
        let script = scripts::status(&p.dom(), &params);
        let mut last = json!({});
        while Instant::now() < deadline && !cancel.is_cancelled() {
            match c.eval(&tab, &script, Duration::from_secs(15)) {
                Ok(h) => {
                    last = h.clone();
                    let notes: Vec<String> = h["notes"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|n| n.as_str().map(str::to_string))
                        .collect();
                    let in_call = h["inCall"] == true;
                    let manual = h.get("manualAction").filter(|v| v.is_object()).cloned();
                    self.with(&id, |s| {
                        s.health = h.clone();
                        for n in notes {
                            if !s.notes.contains(&n) {
                                s.notes.push(n);
                            }
                        }
                        s.state = if in_call {
                            "active".into()
                        } else if manual.is_some() {
                            "waiting".into()
                        } else {
                            "joining".into()
                        };
                    });
                    if in_call {
                        if mode == "agent" {
                            self.start_consult(&id);
                        }
                        break;
                    }
                    if h["meetingEnded"] == true {
                        self.with(&id, |s| s.state = "ended".into());
                        return Err(format!("The {} has already ended.", p.display()));
                    }
                    // Admission waits keep polling; sign-in / passcode / CAPTCHA need a human now.
                    if let Some(ma) = &manual {
                        if !ma["reason"]
                            .as_str()
                            .unwrap_or("")
                            .ends_with("admission-required")
                        {
                            break;
                        }
                    }
                }
                Err(e) => {
                    self.with(&id, |s| {
                        s.state = "waiting".into();
                        s.health = json!({"manualAction": {"reason": "browser-control-unavailable", "message": e}});
                    });
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(1000));
        }
        let _ = last;
        Ok(json!({"reused": false, "session": self.get(&id)?.view()}))
    }

    fn with<T>(&self, id: &str, f: impl FnOnce(&mut Session) -> T) -> Option<T> {
        self.sessions.lock().unwrap().get_mut(id).map(f)
    }

    pub fn get(&self, id: &str) -> Result<Session, String> {
        self.sessions
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| format!("unknown meeting session `{id}`"))
    }

    /// Resolve `sessionId`, or the only live session of `p`.
    pub fn resolve(&self, p: Platform, id: Option<&str>) -> Result<String, String> {
        if let Some(i) = id {
            return self.get(i).map(|s| s.id);
        }
        let live: Vec<String> = self
            .sessions
            .lock()
            .unwrap()
            .values()
            .filter(|s| s.platform == p && s.state != "ended")
            .map(|s| s.id.clone())
            .collect();
        match live.as_slice() {
            [one] => Ok(one.clone()),
            [] => Err(format!("no active {} session; join one first", p.display())),
            _ => Err(format!(
                "several {} sessions are active; pass sessionId ({})",
                p.display(),
                live.join(", ")
            )),
        }
    }

    /// Re-read the page state (read-only: nothing is clicked).
    pub fn status(&self, id: &str) -> Result<Value, String> {
        let s = self.get(id)?;
        if let (Some(tab), "chrome", false) = (&s.tab, s.transport.as_str(), s.state == "ended") {
            let c = self.devtools()?;
            let params = json!({"autoJoin": false, "guestName": "", "allowMicrophone": s.mode == "agent", "captureCaptions": true, "readOnly": true, "prefix": s.platform.reason_prefix(), "sessionId": s.id});
            match c.eval(
                tab,
                &scripts::status(&s.platform.dom(), &params),
                Duration::from_secs(15),
            ) {
                Ok(h) => {
                    self.with(id, |x| {
                        if h["meetingEnded"] == true && x.state == "active" {
                            x.state = "ended".into();
                        } else if h["inCall"] == true {
                            x.state = "active".into();
                        }
                        x.health = h;
                    });
                }
                Err(e) => {
                    self.with(id, |x| x.health = json!({"manualAction": {"reason": "browser-control-unavailable", "message": e}}));
                }
            }
        }
        Ok(self.get(id)?.view())
    }

    /// Pull new caption lines into the session transcript.
    pub fn refresh_transcript(&self, id: &str, finalize: bool) -> Result<Vec<Line>, String> {
        let s = self.get(id)?;
        let Some(tab) = s.tab.clone() else {
            return Ok(s.transcript);
        };
        let v = self.devtools()?.eval(
            &tab,
            &scripts::transcript(finalize),
            Duration::from_secs(15),
        )?;
        let mut out = vec![];
        self.with(id, |x| {
            for l in v["lines"].as_array().into_iter().flatten() {
                let line = Line {
                    speaker: l["speaker"].as_str().unwrap_or("").into(),
                    text: l["text"].as_str().unwrap_or("").trim().into(),
                    at: l["at"].as_u64().unwrap_or_else(now_ms),
                };
                if line.text.is_empty() {
                    continue;
                }
                // Captions grow in place: replace the last line when this one extends it.
                if let Some(last) = x.transcript.last_mut() {
                    if last.speaker == line.speaker && line.text.starts_with(&last.text) {
                        *last = line;
                        continue;
                    }
                }
                if !x
                    .transcript
                    .iter()
                    .any(|t| t.speaker == line.speaker && t.text == line.text)
                {
                    x.transcript.push(line);
                }
            }
            out = x.transcript.clone();
        });
        Ok(out)
    }

    /// Speak into the meeting (virtual mic for browser sessions, the phone leg for dial-in).
    pub fn speak(self: &Arc<Self>, id: &str, text: &str, cancel: &Cancel) -> Result<Value, String> {
        let s = self.get(id)?;
        if s.state == "ended" {
            return Err("the meeting session has ended".into());
        }
        if s.transport == "twilio" {
            let call = s
                .call_id
                .clone()
                .ok_or("the dial-in call is not connected")?;
            crate::phone::phone(&self.m)?.speak(&call, text, false)?;
            return Ok(json!({"spoken": true, "transport": "twilio"}));
        }
        if s.mode != "agent" {
            return Err("this session joined observe-only (mode=transcribe, microphone off); join with mode=agent to speak".into());
        }
        let (_, speech) =
            crate::tts::synthesize(&self.m, &crate::tts::TtsRequest::new(text), cancel)?;
        let pcm =
            crate::audio::decode_to_pcm(&speech.audio.bytes, &speech.audio.mime, 48000, cancel)
                .or_else(|_| {
                    if speech.audio.mime == "audio/pcm" {
                        Ok(crate::audio::resample(
                            &crate::audio::pcm16_from_bytes(&speech.audio.bytes),
                            speech.sample_rate.unwrap_or(24000),
                            48000,
                        ))
                    } else {
                        Err("could not decode the synthesized speech".to_string())
                    }
                })?;
        let guard = seagent_core::tmp::TempDir::new("seagent-meeting");
        let dir = guard.path().to_path_buf();
        let path = dir.join(format!("{}.wav", crate::store::stem("say")));
        std::fs::write(&path, crate::audio::wav_encode(&pcm, 48000, 1))
            .map_err(|e| e.to_string())?;
        let sink = self.m.cfg.str_or("meeting.audio_sink", "seagent_meeting");
        let tpl = self.m.cfg.str_or("meeting.player", "");
        let r = if tpl.is_empty() {
            let pa = crate::proc::which("paplay").ok_or("paplay (PulseAudio/PipeWire) is required to speak into meetings; or set [media.meeting] player")?;
            crate::proc::run(
                &[
                    pa.display().to_string(),
                    format!("--device={sink}"),
                    path.display().to_string(),
                ],
                None,
                Duration::from_secs(300),
                cancel,
            )
        } else {
            let line = crate::proc::render_template(
                &tpl,
                &[("path", &path.display().to_string()), ("sink", &sink)],
            );
            crate::proc::run_shell(&line, None, &[], Duration::from_secs(300), cancel)
        };
        let _ = std::fs::remove_file(&path);
        r.and_then(|o| o.check("meeting audio playback"))?;
        self.with(id, |x| {
            x.transcript.push(Line {
                speaker: self.pcfg(x.platform, "guest_name", "seagent"),
                text: text.into(),
                at: now_ms(),
            })
        });
        Ok(json!({"spoken": true, "transport": "chrome", "sink": sink}))
    }

    pub fn leave(&self, id: &str) -> Result<Value, String> {
        let s = self.get(id)?;
        let mut departed = true;
        if s.transport == "twilio" {
            if let Some(c) = &s.call_id {
                let _ = crate::phone::phone(&self.m)?.end(c, "hangup-bot");
            }
        } else if let Some(tab) = &s.tab {
            let _ = self.refresh_transcript(id, true);
            let c = self.devtools()?;
            match c.eval(
                tab,
                &scripts::leave(&s.platform.dom()),
                Duration::from_secs(15),
            ) {
                Ok(v) => departed = v["departed"] != false,
                Err(_) => departed = false,
            }
            c.close(&tab.id);
        }
        self.with(id, |x| x.state = "ended".into());
        Ok(json!({"left": true, "departed": departed, "session": self.get(id)?.view()}))
    }

    /// Agent mode: after `reply_quiet_secs` of caption silence, new lines go to the agent and
    /// a non-empty reply is spoken.
    fn start_consult(self: &Arc<Self>, id: &str) {
        let Some(agent) = crate::agent() else {
            self.with(id, |s| {
                s.notes
                    .push("No agent is attached; agent mode only captures captions.".into())
            });
            return;
        };
        let me = self.clone();
        let id = id.to_string();
        std::thread::spawn(move || {
            let quiet =
                Duration::from_secs(me.m.cfg.int_or("meeting.reply_quiet_secs", 3).max(1) as u64);
            let mut last_change = Instant::now();
            let mut seen = 0;
            loop {
                std::thread::sleep(Duration::from_millis(1000));
                let Ok(s) = me.get(&id) else { return };
                if s.state == "ended" {
                    return;
                }
                let Ok(lines) = me.refresh_transcript(&id, false) else {
                    continue;
                };
                if lines.len() != seen {
                    seen = lines.len();
                    last_change = Instant::now();
                    continue;
                }
                let me_name = me.pcfg(s.platform, "guest_name", "seagent");
                let fresh: Vec<&Line> = lines
                    .iter()
                    .skip(s.consulted)
                    .filter(|l| l.speaker != me_name)
                    .collect();
                if fresh.is_empty() || last_change.elapsed() < quiet {
                    continue;
                }
                let text = fresh
                    .iter()
                    .map(|l| {
                        format!(
                            "{}: {}",
                            if l.speaker.is_empty() {
                                "Participant"
                            } else {
                                &l.speaker
                            },
                            l.text
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                me.with(&id, |x| x.consulted = lines.len());
                let prompt = format!("[You are {me_name}, a participant in a {} ({}). New captions follow. Reply with one or two short spoken sentences only if you were addressed or can clearly help; otherwise reply exactly NO_REPLY.]\n{text}", s.platform.display(), s.url);
                if let Ok((sid, reply)) = agent.turn(
                    s.agent_session.as_deref(),
                    &prompt,
                    s.platform.tool(),
                    &Cancel::new(),
                ) {
                    me.with(&id, |x| x.agent_session = Some(sid));
                    let r = reply.trim();
                    if !r.is_empty() && !r.contains("NO_REPLY") {
                        let _ = me.speak(&id, r, &Cancel::new());
                    }
                }
            }
        });
    }

    /// Google Meet by phone: dial the Meet number and enter the PIN (`ww` = pauses).
    pub fn dial_in(self: &Arc<Self>, number: &str, pin: &str, mode: &str) -> Result<Value, String> {
        let pin = meet_pin(pin)?;
        let ph = crate::phone::phone(&self.m)?;
        let intro = format!(
            "Hi, this is {} joining by phone.",
            self.pcfg(Platform::GoogleMeet, "guest_name", "seagent")
        );
        let r = ph.initiate(number, &intro, "conversation", Some(&format!("ww{pin}#")))?;
        let id = format!(
            "meet-{}",
            seagent_net::crypto::random_token(6).to_ascii_lowercase()
        );
        let call = r["callId"].as_str().map(str::to_string);
        self.sessions.lock().unwrap().insert(
            id.clone(),
            Session {
                id: id.clone(),
                platform: Platform::GoogleMeet,
                url: format!("tel:{number}"),
                mode: mode.into(),
                state: "active".into(),
                transport: "twilio".into(),
                tab: None,
                health: json!({"inCall": true}),
                transcript: vec![],
                notes: vec!["Joined by phone dial-in.".into()],
                call_id: call,
                agent_session: None,
                consulted: 0,
            },
        );
        Ok(json!({"session": self.get(&id)?.view(), "call": r}))
    }

    /// Meet REST API `spaces.create` → meeting URL.
    pub fn create_meet(&self, access: Option<&str>) -> Result<Value, String> {
        self.create_meet_with(access, None)
    }

    /// `spaces.create` with the space's join policy (`config.accessType` + `config.entryPointAccess`).
    pub fn create_meet_with(
        &self,
        access: Option<&str>,
        entry_point: Option<&str>,
    ) -> Result<Value, String> {
        // Policy validation happens before the token lookup and the request.
        let body = meet_space_config(access, entry_point)?;
        let c = self.m.creds(
            "google-meet",
            &["GOOGLE_MEET_ACCESS_TOKEN"],
            "https://meet.googleapis.com/v2",
        );
        let tok = c.key.clone().ok_or("Google Meet create needs an OAuth access token ([media.providers.google-meet] api_key or GOOGLE_MEET_ACCESS_TOKEN) with the meetings.space.created scope")?;
        let v = self
            .m
            .http
            .post_json(
                &c.url("/spaces"),
                &[("Authorization".into(), format!("Bearer {tok}"))],
                &body,
            )
            .map_err(|e| format!("Meet API spaces.create failed: {e}"))?;
        let uri = v["meetingUri"]
            .as_str()
            .ok_or("Meet API returned no meetingUri")?;
        Ok(json!({"meetingUri": uri, "meetingCode": v["meetingCode"], "space": v["name"]}))
    }

    /// Readiness checks for `setup_status`.
    pub fn setup_status(&self) -> Value {
        let chrome = cdp::find_chrome(&self.m.cfg.str_or("meeting.executable", ""));
        let pactl = crate::proc::which("pactl");
        let sink = self.m.cfg.str_or("meeting.audio_sink", "seagent_meeting");
        let sink_ok = pactl
            .as_ref()
            .and_then(|p| {
                crate::proc::run(
                    &[
                        p.display().to_string(),
                        "list".into(),
                        "short".into(),
                        "sinks".into(),
                    ],
                    None,
                    Duration::from_secs(5),
                    &Cancel::new(),
                )
                .ok()
            })
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .any(|w| w == sink)
            });
        json!({"checks": [
            {"id": "browser", "ok": chrome.is_some() || !self.m.cfg.str_or("meeting.cdp_url", "").is_empty(), "message": chrome.map(|p| format!("Chromium: {}", p.display())).unwrap_or_else(|| "no Chromium-family browser found".into())},
            {"id": "audio", "ok": sink_ok == Some(true), "message": match sink_ok { Some(true) => format!("PulseAudio sink {sink} is present"), Some(false) => format!("sink {sink} missing; run action=setup"), None => "pactl not found (PulseAudio/PipeWire needed for talk-back)".into() }},
            {"id": "tts", "ok": true, "message": format!("speech via [media.tts] provider {}", crate::tts::configured_provider(&self.m))}
        ]})
    }

    /// Create the virtual microphone: a null sink whose monitor is remapped as a source.
    pub fn setup_audio(&self) -> Result<Value, String> {
        let pactl = crate::proc::which("pactl")
            .ok_or("pactl not found (PulseAudio or PipeWire-pulse is required)")?;
        let sink = self.m.cfg.str_or("meeting.audio_sink", "seagent_meeting");
        let run = |args: &[&str]| {
            crate::proc::run(
                &std::iter::once(pactl.display().to_string())
                    .chain(args.iter().map(|s| s.to_string()))
                    .collect::<Vec<_>>(),
                None,
                Duration::from_secs(10),
                &Cancel::new(),
            )
        };
        let have = run(&["list", "short", "sinks"])
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .any(|w| w == sink)
            })
            .unwrap_or(false);
        if !have {
            run(&[
                "load-module",
                "module-null-sink",
                &format!("sink_name={sink}"),
                "sink_properties=device.description=seagent_Meeting_Audio",
            ])?
            .check("pactl load-module module-null-sink")?;
            run(&[
                "load-module",
                "module-remap-source",
                &format!("master={sink}.monitor"),
                &format!("source_name={sink}_mic"),
                "source_properties=device.description=seagent_Meeting_Audio_Mic",
            ])?
            .check("pactl load-module module-remap-source")?;
        }
        Ok(json!({"sink": sink, "microphone": format!("{sink}_mic"), "created": !have}))
    }
}

/// Meet dial-in PIN → DTMF digits. Upstream appends the closing `#` unless the PIN
/// already carries it, so a trailing `#` is stripped here and re-added once.
fn meet_pin(pin: &str) -> Result<String, String> {
    let compact: String = pin.chars().filter(|c| !c.is_whitespace()).collect();
    let digits = compact.strip_suffix('#').unwrap_or(&compact);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err("pin must be the Meet dial-in PIN digits".into());
    }
    Ok(digits.to_string())
}

/// The `spaces.create` body: `{"config": {"accessType": …, "entryPointAccess": …}}` when a
/// policy was given, `{}` otherwise. Values are case-insensitive and `-` reads as `_`.
fn meet_space_config(access: Option<&str>, entry_point: Option<&str>) -> Result<Value, String> {
    let norm = |v: &str| v.trim().to_ascii_uppercase().replace('-', "_");
    let mut config = serde_json::Map::new();
    if let Some(a) = access.map(norm).filter(|a| !a.is_empty()) {
        if !matches!(a.as_str(), "OPEN" | "TRUSTED" | "RESTRICTED") {
            return Err(
                "Invalid Google Meet accessType. Expected OPEN, TRUSTED, or RESTRICTED.".into(),
            );
        }
        config.insert("accessType".into(), json!(a));
    }
    if let Some(e) = entry_point.map(norm).filter(|e| !e.is_empty()) {
        if !matches!(e.as_str(), "ALL" | "CREATOR_APP_ONLY") {
            return Err(
                "Invalid Google Meet entryPointAccess. Expected ALL or CREATOR_APP_ONLY.".into(),
            );
        }
        config.insert("entryPointAccess".into(), json!(e));
    }
    Ok(if config.is_empty() {
        json!({})
    } else {
        json!({ "config": config })
    })
}

fn registry() -> &'static Mutex<Vec<Arc<Meetings>>> {
    static R: OnceLock<Mutex<Vec<Arc<Meetings>>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn meetings(m: &Arc<Media>) -> Arc<Meetings> {
    let mut g = registry().lock().unwrap();
    g.retain(|x| Arc::strong_count(&x.m) > 1);
    if let Some(x) = g.iter().find(|x| Arc::ptr_eq(&x.m, m)) {
        return x.clone();
    }
    let x = Meetings::new(m.clone());
    g.push(x.clone());
    x
}

pub struct MeetingTool {
    pub m: Arc<Media>,
    pub platform: Platform,
}

impl Tool for MeetingTool {
    fn spec(&self) -> ToolSpec {
        let p = self.platform;
        let meet = p == Platform::GoogleMeet;
        let extra = if meet {
            " create (Meet API; join=false only mints the URL), dial-in with transport=twilio + dialInNumber + pin."
        } else {
            ""
        };
        let mut actions = vec![
            "join",
            "status",
            "transcript",
            "speak",
            "leave",
            "sessions",
            "setup_status",
            "setup",
        ];
        if meet {
            actions.push("create");
        }
        let mut props = serde_json::Map::new();
        props.insert("action".into(), json!({"type": "string", "enum": actions}));
        props.insert(
            "url".into(),
            json!({"type": "string", "description": format!("{} URL", p.display())}),
        );
        props.insert(
            "mode".into(),
            json!({"type": "string", "enum": ["transcribe", "agent"]}),
        );
        props.insert("sessionId".into(), json!({"type": "string"}));
        props.insert("message".into(), json!({"type": "string"}));
        props.insert(
            "transport".into(),
            json!({"type": "string", "enum": ["chrome", "twilio"]}),
        );
        if meet {
            props.insert("join".into(), json!({"type": "boolean"}));
            props.insert(
                "dialInNumber".into(),
                json!({"type": "string", "description": "dial-in: the Meet phone number"}),
            );
            props.insert(
                "pin".into(),
                json!({"type": "string", "description": "dial-in: the Meet PIN; # is appended if omitted"}),
            );
            props.insert(
                "accessType".into(),
                json!({"type": "string", "enum": ["OPEN", "TRUSTED", "RESTRICTED"], "description": "create: who can join without knocking"}),
            );
            props.insert(
                "entryPointAccess".into(),
                json!({"type": "string", "enum": ["ALL", "CREATOR_APP_ONLY"], "description": "create: allowed join entry points"}),
            );
        }
        ToolSpec {
            name: p.tool().into(),
            description: format!("Join a {} as a browser guest and take part. Actions: join (url, mode transcribe|agent), status, transcript, speak (message; agent mode), leave, sessions, setup_status, setup (create the virtual microphone).{extra}", p.display()),
            input_schema: json!({"type": "object", "properties": props, "required": ["action"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let a = arg_opt_str(input, "action").unwrap_or("");
        let url = arg_opt_str(input, "url").unwrap_or("").trim().to_string();
        let host = {
            let h = crate::http::host_of(&url);
            if h.is_empty() {
                self.platform.host().to_string()
            } else {
                h
            }
        };
        match a {
            // Dial-in places a real phone call through [media.phone], not a browser request.
            "join" if arg_opt_str(input, "transport") == Some("twilio") => vec![Effect::Send {
                channel: format!(
                    "phone:{}",
                    arg_opt_str(input, "dialInNumber").unwrap_or("")
                ),
                payload: format!(
                    "Google Meet dial-in, PIN {}",
                    arg_opt_str(input, "pin").unwrap_or("")
                ),
            }],
            "join" => vec![Effect::Net {
                dest: host,
                payload: url.clone(),
            }],
            // create posts to the Meet REST API (POST /v2/spaces), never to the meeting URL.
            "create" => vec![Effect::Net {
                dest: "meet.googleapis.com".into(),
                payload: format!(
                    "spaces.create accessType={} entryPointAccess={}",
                    arg_opt_str(input, "accessType").unwrap_or("(default)"),
                    arg_opt_str(input, "entryPointAccess").unwrap_or("(default)")
                ),
            }],
            "speak" => vec![Effect::Send {
                channel: format!(
                    "{}:{}",
                    self.platform.id(),
                    arg_opt_str(input, "sessionId").unwrap_or("")
                ),
                payload: arg_opt_str(input, "message").unwrap_or("").into(),
            }],
            "setup" => vec![Effect::Exec {
                command: format!(
                    "pactl load-module module-null-sink sink_name={}",
                    self.m.cfg.str_or("meeting.audio_sink", "seagent_meeting")
                ),
            }],
            _ => vec![],
        }
    }

    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let p = self.platform;
        let mt = meetings(&self.m);
        let s = |k: &str| {
            arg_opt_str(&input, k)
                .map(str::trim)
                .filter(|v| !v.is_empty())
        };
        let r = (|| -> Result<Value, String> {
            match s("action").unwrap_or("") {
                "join" => {
                    let mode = s("mode")
                        .map(str::to_string)
                        .unwrap_or_else(|| mt.pcfg(p, "default_mode", "transcribe"));
                    if s("transport") == Some("twilio") {
                        if p != Platform::GoogleMeet {
                            return Err("phone dial-in is only available for Google Meet".into());
                        }
                        return mt.dial_in(
                            s("dialInNumber")
                                .ok_or("dialInNumber required for transport=twilio")?,
                            s("pin").unwrap_or(""),
                            &mode,
                        );
                    }
                    let url = p.normalize(s("url").unwrap_or(""))?;
                    mt.join_url(p, &url, &mode, &ctx.cancel)
                }
                "create" => {
                    if p != Platform::GoogleMeet {
                        return Err("create is only available for Google Meet".into());
                    }
                    let c = mt.create_meet_with(s("accessType"), s("entryPointAccess"))?;
                    if input["join"] == false {
                        return Ok(c);
                    }
                    let url = p.normalize(c["meetingUri"].as_str().unwrap_or(""))?;
                    let mode = s("mode")
                        .map(str::to_string)
                        .unwrap_or_else(|| mt.pcfg(p, "default_mode", "transcribe"));
                    let mut j = mt.join_url(p, &url, &mode, &ctx.cancel)?;
                    j["created"] = c;
                    Ok(j)
                }
                "status" => mt.status(&mt.resolve(p, s("sessionId"))?),
                "transcript" => {
                    let id = mt.resolve(p, s("sessionId"))?;
                    let lines = mt.refresh_transcript(&id, false)?;
                    Ok(
                        json!({"sessionId": id, "lines": lines.iter().map(|l| json!({"speaker": l.speaker, "text": l.text, "at": l.at})).collect::<Vec<_>>()}),
                    )
                }
                "speak" => mt.speak(
                    &mt.resolve(p, s("sessionId"))?,
                    s("message").ok_or("message required")?,
                    &ctx.cancel,
                ),
                "leave" => mt.leave(&mt.resolve(p, s("sessionId"))?),
                "sessions" => Ok(
                    json!({"sessions": mt.sessions.lock().unwrap().values().filter(|x| x.platform == p).map(Session::view).collect::<Vec<_>>()}),
                ),
                "setup_status" => Ok(mt.setup_status()),
                "setup" => mt.setup_audio(),
                other => Err(format!("unknown action `{other}`")),
            }
        })();
        match r {
            Ok(v) => ToolOutput::ok(v.to_string()),
            Err(e) => ToolOutput::err(json!({"error": e}).to_string()),
        }
    }
}

pub fn tools(m: &Arc<Media>) -> Vec<Arc<dyn Tool>> {
    platforms::ALL
        .iter()
        .map(|p| {
            Arc::new(MeetingTool {
                m: m.clone(),
                platform: *p,
            }) as Arc<dyn Tool>
        })
        .collect()
}

#[cfg(test)]
mod tests;
