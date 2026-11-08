//! GPT-Live voice chat mode (Hermes `tools/voice_live.py`): one full-duplex voice
//! model owns the microphone and the speaker and delegates every real request to
//! the agent ("client delegation"). The agent stays the agent — whatever model the
//! session uses answers, with its full toolset; the voice model only talks.
//!
//! Two transports:
//! * WebRTC (web/desktop UIs): the browser holds the media session; the server
//!   exchanges its SDP offer for an answer with the project key
//!   ([`create_webrtc_session`], `POST /v1/live/sessions`) so the key never reaches
//!   the client. Session shape from [`session_config`].
//! * Terminal ([`run`]): the CLI has no WebRTC stack, so it drives an OpenAI Realtime
//!   (or any [`super::open_voice`] provider) WebSocket session with the same persona
//!   and a `delegate_to_agent` function tool; recorder/player are subprocesses
//!   (`pw-record`/`parecord`/`arecord`, `pw-play`/`pacat`/`aplay`).
//!
//! ```toml
//! [media.voice]
//! voice_chat_mode = "chained"    # or "gpt-live"
//! [media.voice.gpt_live]
//! api_key = ""                   # default: VOICE_TOOLS_OPENAI_KEY, OPENAI_API_KEY, [media.providers.openai]
//! base_url = "https://api.openai.com/v1"
//! model = "gpt-live-1"           # WebRTC session model
//! voice = "marin"
//! instructions = ""              # appended to the persona
//! realtime_provider = "openai"   # terminal transport (openai | xai | google)
//! realtime_model = ""            # default per provider (gpt-realtime-2.1)
//! realtime_voice = ""            # default per provider (alloy / Kore / eve)
//! sample_rate = 24000
//! max_duration_secs = 0           # terminal transport: stop after this long (0 = until quit)
//! recorder = ""                  # shell command writing raw s16le mono at {rate} to stdout
//! player = ""                    # shell command reading raw s16le mono at {rate} from stdin
//! ```

use super::{RealtimeVoice, VoiceEvent, VoiceOpts};
use crate::Media;
use seagent_core::{Cancel, ToolSchema};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const GPT_LIVE_MODE: &str = "gpt-live";
pub const CHAINED_MODE: &str = "chained";
pub const DEFAULT_LIVE_MODEL: &str = "gpt-live-1";
pub const DEFAULT_LIVE_VOICE: &str = "marin";
pub const DEFAULT_LIVE_BASE_URL: &str = "https://api.openai.com/v1";
/// Voices the vendor lists for gpt-live-1; free text stays allowed for custom voices.
pub const GPT_LIVE_VOICES: &[&str] = &[
    "marin", "cedar", "quartz", "ripple", "vesper", "willow", "stone", "gleam", "meridian",
    "bossa", "tempo", "beacon", "delta", "cinder",
];
pub const DELEGATE_TOOL: &str = "delegate_to_agent";

/// Persona for the voice layer: role + style + a labelled delegation policy (the live
/// model has a small context window; the agent carries the real instructions and tools).
pub const LIVE_PERSONA: &str =
    "You are seagent, a calm and friendly voice assistant. Speak naturally at an unhurried pace. \
Be clear and direct, not overly cheerful. If the user is frustrated, acknowledge it briefly \
and focus on the next helpful step.\n\n\
Backchannel policy: Use moderate backchannels. Acknowledge naturally without competing with \
the main response.\n\n\
Interruption policy: Stop speaking when the user interrupts. Listen to what they say.\n\n\
Delegation policy:\n\
Backend tools:\n\
- seagent agent: a full AI agent with tools — it can run commands, read and edit files, \
browse the web, search, remember things across sessions, schedule tasks, and reason \
carefully about anything. It is the one who actually does work and knows facts.\n\n\
Delegate to the backend when:\n\
- The user asks a question that needs facts, current information, or careful reasoning.\n\
- The user asks you to do, check, find, make, fix, run or remember anything.\n\
- A correction changes work already requested.\n\n\
Do not delegate to the backend when:\n\
- The user greets you, makes small talk, or asks you to repeat a result already provided.\n\
- You need a brief clarification to understand the request.\n\n\
Delegate before giving an answer that depends on backend work. Do not guess the result \
while waiting; say briefly that you are checking, then wait for the result.";

/// Per-turn note prepended to the agent's model input for a delegated turn.
pub const VOICE_LIVE_TURN_NOTE: &str =
    "[Note: this message is a delegation from a live spoken conversation. The text is a voice \
transcript (it may contain mis-hearings, hesitations and later corrections; use the latest \
intent). Your reply will be spoken aloud by a voice model that paraphrases it: answer in plain \
conversational sentences, keep it short (a few sentences unless the user asked for detail), no \
markdown, no lists, no code blocks, no URLs read out character by character. Do the work with \
your tools as usual; only the final facts need to be spoken. Do not claim an action succeeded \
before it actually did.]";

/// The turn note plus, when present, the recent spoken exchange the delegation refers to
/// (the user's last words alone are often "yes" or "Thursday, not Friday").
pub fn voice_live_turn_note(context: &str) -> String {
    let c = context.trim();
    if c.is_empty() {
        VOICE_LIVE_TURN_NOTE.to_string()
    } else {
        format!("{VOICE_LIVE_TURN_NOTE}\n[Recent spoken conversation, newest last:\n{c}]")
    }
}

fn live(m: &Media, key: &str) -> Option<String> {
    m.cfg.str(&format!("voice.gpt_live.{key}"))
}

/// `chained` (default) or `gpt-live` (accepts `gpt_live`, `gptlive`, `live`).
pub fn voice_chat_mode(m: &Media) -> &'static str {
    let raw = m
        .cfg
        .str("voice.voice_chat_mode")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .replace('_', "-");
    if matches!(raw.as_str(), "gpt-live" | "gptlive" | "live") {
        GPT_LIVE_MODE
    } else {
        CHAINED_MODE
    }
}

/// `(api_key, base_url)`: `gpt_live.api_key`, else the OpenAI audio chain.
fn credentials(m: &Media) -> (Option<String>, String) {
    let c = m.creds(
        "openai",
        &["VOICE_TOOLS_OPENAI_KEY", "OPENAI_API_KEY"],
        DEFAULT_LIVE_BASE_URL,
    );
    let key = live(m, "api_key").or(c.key);
    let base = live(m, "base_url")
        .unwrap_or(c.base)
        .trim_end_matches('/')
        .to_string();
    (key, base)
}

pub fn live_instructions(m: &Media) -> String {
    match live(m, "instructions") {
        Some(x) => format!("{LIVE_PERSONA}\n\n{x}"),
        None => LIVE_PERSONA.to_string(),
    }
}

/// Non-secret readiness verdict: which mode is selected and whether GPT-Live can start.
pub fn status(m: &Media) -> Value {
    let (key, _) = credentials(m);
    json!({
        "mode": voice_chat_mode(m),
        "available": key.is_some(),
        "reason": if key.is_some() { Value::Null } else { json!("no OpenAI API key (set OPENAI_API_KEY or [media.voice.gpt_live] api_key)") },
        "model": live(m, "model").unwrap_or_else(|| DEFAULT_LIVE_MODEL.into()),
        "voice": live(m, "voice").unwrap_or_else(|| DEFAULT_LIVE_VOICE.into()),
    })
}

/// The `session` object for `POST /v1/live/sessions` (client delegation; WebRTC
/// negotiates the audio format, so none is set).
pub fn session_config(m: &Media, history: Option<&Value>) -> Value {
    let mut c = json!({
        "model": live(m, "model").unwrap_or_else(|| DEFAULT_LIVE_MODEL.into()),
        "instructions": live_instructions(m),
        "audio": {"output": {"voice": live(m, "voice").unwrap_or_else(|| DEFAULT_LIVE_VOICE.into())}},
        "delegation": {"type": "client"},
    });
    if let Some(h) = history.filter(|h| h.as_array().is_some_and(|a| !a.is_empty())) {
        c["input"] = h.clone();
    }
    c
}

/// Exchange a browser's SDP offer for the Live session answer
/// (`{"session": {"id"}, "transport": {"type": "webrtc", "sdp"}}`).
pub fn create_webrtc_session(
    m: &Media,
    sdp_offer: &str,
    history: Option<&Value>,
) -> Result<Value, String> {
    let (key, base) = credentials(m);
    let key = key.ok_or(
        "GPT-Live needs an OpenAI API key (OPENAI_API_KEY or [media.voice.gpt_live] api_key)",
    )?;
    let body = json!({"session": session_config(m, history), "transport": {"type": "webrtc", "sdp": sdp_offer}});
    let h = vec![("authorization".to_string(), format!("Bearer {key}"))];
    let b = serde_json::to_vec(&body).unwrap_or_default();
    let r = m.http.send(
        "POST",
        &format!("{base}/live/sessions"),
        &h,
        Some(("application/json", &b)),
    )?;
    if !r.ok() {
        return Err(format!(
            "GPT-Live session creation failed ({}): {}",
            r.status,
            crate::http::excerpt(&r.text(), 600)
        ));
    }
    r.json()
}

/// The terminal transport's tool: the voice model hands real work to the agent.
pub fn delegate_tool() -> ToolSchema {
    ToolSchema {
        name: DELEGATE_TOOL.into(),
        description: "Hand the user's request to the seagent agent, which has tools, files, the web and memory, and wait for its answer. Use for anything that needs facts, reasoning or action.".into(),
        input_schema: json!({"type": "object", "properties": {
            "request": {"type": "string", "description": "What the user wants, in their words, with corrections applied."},
            "context": {"type": "string", "description": "The recent spoken exchange this refers to, newest last (optional)."}
        }, "required": ["request"]}),
    }
}

/// Microphone in, speaker out.
pub trait AudioIo: Send {
    /// Recorded PCM since the last call (empty = none yet); `Err` = the recorder died.
    fn read(&mut self) -> Result<Vec<i16>, String>;
    fn play(&mut self, pcm: &[i16]) -> Result<(), String>;
    /// Barge-in: drop whatever is queued for playback.
    fn stop_playback(&mut self);
    /// Block until queued playback has been written out (end of session).
    fn drain(&mut self) {}
}

/// Recorder/player subprocesses speaking raw s16le mono at `rate`.
pub struct ProcAudio {
    rate: u32,
    player_cmd: String,
    player: Option<Child>,
    recorder: Option<Child>,
    rx: mpsc::Receiver<Result<Vec<i16>, String>>,
}

fn default_recorder(rate: u32) -> Option<String> {
    let p = crate::proc::which;
    if p("pw-record").is_some() {
        Some(format!(
            "pw-record --rate {rate} --channels 1 --format s16 -"
        ))
    } else if p("parecord").is_some() {
        Some(format!(
            "parecord --raw --rate={rate} --channels=1 --format=s16le"
        ))
    } else if p("arecord").is_some() {
        Some(format!("arecord -q -f S16_LE -r {rate} -c 1 -t raw"))
    } else if cfg!(any(windows, target_vendor = "apple")) {
        // No PipeWire/Pulse/ALSA there: ffmpeg's native capture (AVFoundation / DirectShow).
        let ff = crate::audio::ffmpeg()?;
        let input = crate::voice::record::ffmpeg_input(&ff)?;
        let q = |s: &str| crate::proc::shell_quote(s);
        Some(format!("{} -nostdin -loglevel quiet {} -ac 1 -ar {rate} -f s16le -", q(&ff.display().to_string()), input.iter().map(|a| q(a)).collect::<Vec<_>>().join(" ")))
    } else {
        None
    }
}

fn default_player(rate: u32) -> Option<String> {
    let p = crate::proc::which;
    if p("pw-play").is_some() {
        Some(format!("pw-play --rate {rate} --channels 1 --format s16 -"))
    } else if p("pacat").is_some() {
        Some(format!(
            "pacat --playback --raw --rate={rate} --channels=1 --format=s16le"
        ))
    } else if p("aplay").is_some() {
        Some(format!("aplay -q -f S16_LE -r {rate} -c 1 -t raw"))
    } else if cfg!(any(windows, target_vendor = "apple")) && p("ffplay").is_some() {
        // Raw PCM from stdin through ffplay (part of every ffmpeg build).
        Some(format!("ffplay -nodisp -autoexit -loglevel quiet -f s16le -ar {rate} -ch_layout mono -i -"))
    } else {
        None
    }
}

impl ProcAudio {
    /// From `[media.voice.gpt_live] recorder/player` (`{rate}` substituted) or the first
    /// PipeWire/PulseAudio/ALSA tool found.
    pub fn from_config(m: &Media, rate: u32) -> Result<ProcAudio, String> {
        let rec = live(m, "recorder").map(|c| c.replace("{rate}", &rate.to_string())).or_else(|| default_recorder(rate)).ok_or("no audio recorder found (install pipewire, pulseaudio-utils or alsa-utils, or set [media.voice.gpt_live] recorder)")?;
        let play = live(m, "player").map(|c| c.replace("{rate}", &rate.to_string())).or_else(|| default_player(rate)).ok_or("no audio player found (install pipewire, pulseaudio-utils or alsa-utils, or set [media.voice.gpt_live] player)")?;
        ProcAudio::new(&rec, &play, rate)
    }

    pub fn new(recorder: &str, player: &str, rate: u32) -> Result<ProcAudio, String> {
        let mut child = crate::proc::shell_command(recorder)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("recorder `{recorder}`: {e}"))?;
        let mut out = child.stdout.take().ok_or("recorder has no stdout")?;
        let (tx, rx) = mpsc::channel();
        // 20 ms reads: low latency without flooding the socket.
        let chunk = (rate as usize / 50).max(1) * 2;
        std::thread::spawn(move || {
            let mut buf = vec![0u8; chunk];
            let mut carry: Option<u8> = None;
            loop {
                match out.read(&mut buf) {
                    Ok(0) => {
                        let _ = tx.send(Err("recorder stopped".into()));
                        return;
                    }
                    Ok(n) => {
                        let mut bytes: Vec<u8> = carry.take().into_iter().collect();
                        bytes.extend_from_slice(&buf[..n]);
                        if bytes.len() % 2 == 1 {
                            carry = bytes.pop();
                        }
                        if tx.send(Ok(crate::audio::pcm16_from_bytes(&bytes))).is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("recorder: {e}")));
                        return;
                    }
                }
            }
        });
        Ok(ProcAudio {
            rate,
            player_cmd: player.to_string(),
            player: None,
            recorder: Some(child),
            rx,
        })
    }

    fn player(&mut self) -> Result<&mut Child, String> {
        if self
            .player
            .as_mut()
            .is_some_and(|c| c.try_wait().ok().flatten().is_some())
        {
            self.player = None;
        }
        if self.player.is_none() {
            let c = crate::proc::shell_command(&self.player_cmd)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| format!("player `{}`: {e}", self.player_cmd))?;
            self.player = Some(c);
        }
        Ok(self.player.as_mut().unwrap())
    }

    pub fn rate(&self) -> u32 {
        self.rate
    }
}

impl AudioIo for ProcAudio {
    fn read(&mut self) -> Result<Vec<i16>, String> {
        let mut v = Vec::new();
        loop {
            match self.rx.try_recv() {
                Ok(Ok(s)) => v.extend(s),
                Ok(Err(e)) => {
                    if v.is_empty() {
                        return Err(e);
                    }
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    if v.is_empty() {
                        return Err("recorder stopped".into());
                    }
                    break;
                }
            }
        }
        Ok(v)
    }
    fn play(&mut self, pcm: &[i16]) -> Result<(), String> {
        let bytes = crate::audio::pcm16_to_bytes(pcm);
        let p = self.player()?;
        p.stdin
            .as_mut()
            .ok_or("player has no stdin")?
            .write_all(&bytes)
            .map_err(|e| format!("player: {e}"))
    }
    fn stop_playback(&mut self) {
        if let Some(mut c) = self.player.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
    fn drain(&mut self) {
        if let Some(mut c) = self.player.take() {
            drop(c.stdin.take());
            let _ = c.wait();
        }
    }
}

impl Drop for ProcAudio {
    fn drop(&mut self) {
        for c in [self.recorder.take(), self.player.take()]
            .into_iter()
            .flatten()
        {
            let mut c = c;
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// The agent behind the voice: `(request, turn_note)` → reply text.
pub type Delegate = dyn Fn(&str, &str) -> Result<String, String> + Send + Sync;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct LiveReport {
    /// Final transcripts in order: `(role, text)`.
    pub transcript: Vec<(String, String)>,
    pub delegations: usize,
    pub interruptions: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct LiveOpts {
    /// Realtime provider for the terminal transport (`None` = `gpt_live.realtime_provider`, then openai).
    pub provider: Option<String>,
    pub model: Option<String>,
    pub voice: Option<String>,
    /// PCM rate for mic and speaker (0 = `gpt_live.sample_rate`, default 24000).
    pub sample_rate: u32,
    /// Stop after this long (None = until cancelled or the session ends).
    pub max_duration: Option<Duration>,
    /// Stop once the recorder ends and the last reply finished (scripted input).
    pub stop_on_recorder_end: bool,
}

impl LiveOpts {
    /// Options from `[media.voice.gpt_live]` (`realtime_provider`, `realtime_model`,
    /// `realtime_voice`, `sample_rate`, `max_duration_secs`); CLI flags override the
    /// fields afterwards.
    pub fn from_config(m: &Media) -> LiveOpts {
        let secs = m.cfg.float_or("voice.gpt_live.max_duration_secs", 0.0);
        LiveOpts {
            provider: live(m, "realtime_provider"),
            model: live(m, "realtime_model"),
            voice: live(m, "realtime_voice"),
            sample_rate: m.cfg.int_or("voice.gpt_live.sample_rate", 0).clamp(0, 192_000) as u32,
            max_duration: (secs > 0.0).then(|| Duration::from_secs_f64(secs)),
            stop_on_recorder_end: false,
        }
    }

    /// `--provider/--model/--voice/--seconds` overrides (0 = keep the configured cap).
    pub fn with_flags(mut self, provider: Option<String>, model: Option<String>, voice: Option<String>, max_seconds: u32) -> LiveOpts {
        self.provider = provider.or(self.provider);
        self.model = model.or(self.model);
        self.voice = voice.or(self.voice);
        if max_seconds > 0 {
            self.max_duration = Some(Duration::from_secs(max_seconds as u64));
        }
        self
    }
}

/// Run GPT-Live in the terminal until cancelled, the session closes or `max_duration`.
pub fn run(
    m: &Media,
    opts: &LiveOpts,
    io: &mut dyn AudioIo,
    delegate: Arc<Delegate>,
    on_event: &mut dyn FnMut(&VoiceEvent),
    cancel: &Cancel,
) -> Result<LiveReport, String> {
    let rate = if opts.sample_rate > 0 {
        opts.sample_rate
    } else {
        m.cfg.int_or("voice.gpt_live.sample_rate", 24000).max(8000) as u32
    };
    let provider = opts
        .provider
        .clone()
        .or_else(|| live(m, "realtime_provider"))
        .unwrap_or_else(|| "openai".into());
    let vo = VoiceOpts {
        instructions: live_instructions(m),
        voice: opts.voice.clone().or_else(|| live(m, "realtime_voice")),
        model: opts.model.clone().or_else(|| live(m, "realtime_model")),
        sample_rate: rate,
        tools: vec![delegate_tool()],
    };
    let mut s = super::open_voice(m, Some(&provider), &vo)?;
    let r = drive(s.as_mut(), opts, io, delegate, on_event, cancel);
    s.close();
    io.drain();
    r
}

/// `seagent voice live` (`/voice live`): GPT-Live on this terminal with the installed
/// agent ([`crate::set_agent`]). Prints final transcripts; `seagent voice live --status`
/// prints [`status`] instead.
pub fn run_cli(m: &Media, opts: &LiveOpts, cancel: &Cancel) -> Result<LiveReport, String> {
    let agent = crate::agent().ok_or("GPT-Live needs the agent runtime (seagent_media::set_agent was not called)")?;
    run_with_agent(m, opts, agent, cancel)
}

/// The same session with the agent supplied by the caller (daemons own their
/// `Agent` object; the CLI goes through [`run_cli`]).
pub fn run_with_agent(m: &Media, opts: &LiveOpts, agent: Arc<dyn crate::Agent>, cancel: &Cancel) -> Result<LiveReport, String> {
    let rate = if opts.sample_rate > 0 { opts.sample_rate } else { m.cfg.int_or("voice.gpt_live.sample_rate", 24000).max(8000) as u32 };
    let mut io = ProcAudio::from_config(m, rate)?;
    let c = cancel.clone();
    let delegate: Arc<Delegate> = Arc::new(move |request: &str, note: &str| {
        agent.turn(None, &format!("{note}\n\n{request}"), "voice-live", &c).map(|(_, reply)| reply)
    });
    let mut on_event = |e: &VoiceEvent| match e {
        VoiceEvent::Transcript { role, text, is_final: true } => println!("{role}: {text}"),
        VoiceEvent::Error(e) => eprintln!("[gpt-live] {e}"),
        _ => {}
    };
    run(m, opts, &mut io, delegate, &mut on_event, cancel)
}

fn drive(
    s: &mut dyn RealtimeVoice,
    opts: &LiveOpts,
    io: &mut dyn AudioIo,
    delegate: Arc<Delegate>,
    on_event: &mut dyn FnMut(&VoiceEvent),
    cancel: &Cancel,
) -> Result<LiveReport, String> {
    let start = Instant::now();
    let mut rep = LiveReport::default();
    let (tx, rx) = mpsc::channel::<(String, Result<String, String>)>();
    let mut outstanding = 0usize;
    let mut recorder_done = false;
    let mut idle_since: Option<Instant> = None;
    loop {
        if cancel.is_cancelled() || opts.max_duration.is_some_and(|d| start.elapsed() >= d) {
            break;
        }
        if !recorder_done {
            match io.read() {
                Ok(pcm) if !pcm.is_empty() => s.send_audio(&pcm)?,
                Ok(_) => {}
                Err(e) => {
                    recorder_done = true;
                    if !opts.stop_on_recorder_end {
                        return Err(e);
                    }
                }
            }
        }
        let evs = s.poll()?;
        let busy = !evs.is_empty();
        for e in evs {
            on_event(&e);
            match &e {
                VoiceEvent::Audio(pcm) => io.play(pcm)?,
                VoiceEvent::Interrupted => {
                    rep.interruptions += 1;
                    io.stop_playback();
                }
                VoiceEvent::Transcript {
                    role,
                    text,
                    is_final: true,
                } => rep.transcript.push((role.clone(), text.clone())),
                VoiceEvent::ToolCall { id, name, args } => {
                    if name != DELEGATE_TOOL {
                        s.tool_result(
                            id,
                            &json!({"error": format!("unknown tool `{name}`")}).to_string(),
                        )?;
                        continue;
                    }
                    let a: Value = serde_json::from_str(args).unwrap_or_default();
                    let request = a["request"].as_str().unwrap_or("").trim().to_string();
                    if request.is_empty() {
                        s.tool_result(id, &json!({"error": "request is required"}).to_string())?;
                        continue;
                    }
                    let context = a["context"]
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| {
                            rep.transcript
                                .iter()
                                .rev()
                                .take(6)
                                .rev()
                                .map(|(r, t)| format!("{r}: {t}"))
                                .collect::<Vec<_>>()
                                .join("\n")
                        });
                    rep.delegations += 1;
                    outstanding += 1;
                    let (d, tx, id) = (delegate.clone(), tx.clone(), id.clone());
                    std::thread::spawn(move || {
                        let r = d(&request, &voice_live_turn_note(&context));
                        let _ = tx.send((id, r));
                    });
                }
                VoiceEvent::Error(err) => rep.errors.push(err.clone()),
                _ => {}
            }
        }
        while let Ok((id, r)) = rx.try_recv() {
            outstanding -= 1;
            let out = match r {
                Ok(t) => json!({"result": t}),
                Err(e) => json!({"error": e}),
            };
            s.tool_result(&id, &out.to_string())?;
        }
        if recorder_done && opts.stop_on_recorder_end && outstanding == 0 {
            if busy {
                idle_since = None;
            } else if idle_since.get_or_insert_with(Instant::now).elapsed()
                > Duration::from_millis(300)
            {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(rep)
}
