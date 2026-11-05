//! CLI voice mode (Hermes `tools/voice_mode.py` + the CLI voice loop): push-to-talk
//! or hands-free (continuous / wake word) capture → STT (live streaming when
//! `[media.stt] streaming`, else the file path) → hallucination / stop-phrase filter
//! → one agent turn → spoken reply (TTS + playback) with barge-in.
//!
//! ```toml
//! [media.voice]
//! mode = "ptt"            # ptt (Enter to talk) | continuous (re-listen after each reply)
//! wake_word = false       # wait for [media.wake] phrase before each turn
//! speak = true            # read replies aloud
//! barge_in = true         # talking over playback stops it
//! beep = true             # start/stop beeps
//! beep_volume = 0.3
//! ```

use super::record::{self, PcmSource};
use super::transcript;
use crate::Media;
use seagent_core::Cancel;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub type MicFactory = Arc<dyn Fn(&Media) -> Result<Box<dyn PcmSource>, String> + Send + Sync>;

pub fn default_mic() -> MicFactory {
    Arc::new(|m: &Media| record::Mic::open(m).map(|x| Box::new(x) as Box<dyn PcmSource>))
}

#[derive(Debug, Clone, PartialEq)]
pub struct VoiceModeOpts {
    pub continuous: bool,
    pub wake_word: bool,
    pub speak: bool,
    pub barge_in: bool,
    pub beep: bool,
    /// Agent session to continue (`None` = a new one).
    pub session: Option<String>,
    /// Stop after this many listening rounds (0 = until quit / stop phrase).
    pub max_turns: usize,
}

impl VoiceModeOpts {
    pub fn from_config(m: &Media) -> Self {
        VoiceModeOpts {
            continuous: m.cfg.str("voice.mode").is_some_and(|s| s.eq_ignore_ascii_case("continuous")),
            wake_word: m.cfg.bool_or("voice.wake_word", false),
            speak: m.cfg.bool_or("voice.speak", true),
            barge_in: m.cfg.bool_or("voice.barge_in", true),
            beep: m.cfg.bool_or("voice.beep", true),
            session: None,
            max_turns: 0,
        }
    }

    /// Config plus the `seagent voice` flags: `--continuous`, `--wake`, `--no-speak`,
    /// `--no-barge-in`, `--session ID`, `--max-turns N` (0 = no cap).
    pub fn from_flags(m: &Media, f: &VoiceFlags) -> Self {
        let mut o = VoiceModeOpts::from_config(m);
        o.continuous |= f.continuous;
        o.wake_word |= f.wake;
        o.speak &= !f.no_speak;
        o.barge_in &= !f.no_barge_in;
        if f.session.as_deref().is_some_and(|s| !s.trim().is_empty()) {
            o.session = f.session.clone();
        }
        if f.max_turns > 0 {
            o.max_turns = f.max_turns;
        }
        o
    }
}

/// `seagent voice` command-line flags (CLI parsing stays in the binary; this is the
/// documented shape it fills in).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VoiceFlags {
    /// `--continuous`: re-listen after every reply.
    pub continuous: bool,
    /// `--wake`: wait for the wake word before each turn.
    pub wake: bool,
    /// `--no-speak`: print replies instead of speaking them.
    pub no_speak: bool,
    /// `--no-barge-in`: ignore the microphone while a reply plays.
    pub no_barge_in: bool,
    /// `--session ID`: continue an existing agent session.
    pub session: Option<String>,
    /// `--max-turns N` (0 = until quit / stop phrase).
    pub max_turns: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Key {
    /// Push-to-talk (start / stop a take).
    Talk,
    Quit,
}

/// The terminal side of voice mode.
pub trait VoiceIo {
    /// Block until the user presses talk or quit.
    fn wait_key(&mut self, prompt: &str) -> Key;
    /// Non-blocking: the user pressed talk again (ends the current take).
    fn released(&self) -> bool;
    fn say(&mut self, line: &str);
}

/// stdin/stdout: Enter = talk (Enter again ends the take early), `q` + Enter = quit.
pub struct TermIo {
    rx: std::sync::mpsc::Receiver<String>,
    released: Arc<AtomicBool>,
}

impl TermIo {
    pub fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        let released = Arc::new(AtomicBool::new(false));
        let r2 = released.clone();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut line = String::new();
            while stdin.read_line(&mut line).unwrap_or(0) > 0 {
                r2.store(true, Ordering::SeqCst);
                if tx.send(line.trim().to_string()).is_err() {
                    break;
                }
                line.clear();
            }
        });
        TermIo { rx, released }
    }
}

impl Default for TermIo {
    fn default() -> Self {
        Self::new()
    }
}

impl VoiceIo for TermIo {
    fn wait_key(&mut self, prompt: &str) -> Key {
        println!("{prompt}");
        while self.rx.try_recv().is_ok() {}
        let k = match self.rx.recv() {
            Ok(l) if matches!(l.to_ascii_lowercase().as_str(), "q" | "quit" | "exit" | "/quit") => Key::Quit,
            Ok(_) => Key::Talk,
            Err(_) => Key::Quit,
        };
        self.released.store(false, Ordering::SeqCst);
        k
    }
    fn released(&self) -> bool {
        self.released.load(Ordering::SeqCst)
    }
    fn say(&mut self, line: &str) {
        println!("{line}");
    }
}

/// What a voice-mode run did.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VoiceSummary {
    pub turns: usize,
    pub session: Option<String>,
    pub stopped_by_phrase: bool,
    pub interrupted: usize,
}

/// Transcribe one take: the live session's text when it produced one, else the file
/// path; hallucinations dropped (stop phrases kept). `None` = nothing was said.
pub fn transcribe_take(m: &Media, pcm: &[i16], live: Option<crate::stt::stream::StreamingSession>, cancel: &Cancel) -> Result<Option<String>, String> {
    let phrases = transcript::stop_phrases(m);
    if let Some(s) = live {
        if let Ok(t) = s.finalize() {
            return Ok(transcript::filter_with_stop(&t, &phrases));
        }
    }
    let wav = crate::audio::wav_encode(pcm, record::SAMPLE_RATE, 1);
    let (_, t) = crate::stt::transcribe(m, &crate::stt::SttRequest::new(wav, "audio/wav"), cancel)?;
    Ok(transcript::filter_with_stop(&t.text, &phrases))
}

fn play_pcm(m: &Media, pcm: &[i16], cancel: &Cancel) {
    let Ok(d) = crate::stt::local::work_dir("beep") else { return };
    let p = d.join("beep.wav");
    if std::fs::write(&p, crate::audio::wav_encode(pcm, record::SAMPLE_RATE, 1)).is_ok() {
        let _ = crate::tts::play(m, &p, cancel);
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// Speak `text`; with barge-in a mic monitor stops playback when the user talks over
/// it. Returns `true` when interrupted.
///
/// Replies stream (`tts::speak_streaming_gated`): the first sentence plays while the rest is
/// still being synthesized, so voice mode stops waiting for the whole reply. A backend that
/// cannot stream, an operator opt-out (`[media.voice] streaming = false`) or a pass that fails
/// before any audio played falls back to whole-file synthesis — a degradation, never an error.
pub fn speak(m: &Media, text: &str, mic: Option<&MicFactory>, cancel: &Cancel) -> Result<bool, String> {
    let spoken = crate::tts::normalize(text);
    if spoken.trim().is_empty() {
        return Ok(false);
    }
    let stop_play = cancel.child();
    let done = Arc::new(AtomicBool::new(false));
    let barge = Arc::new(AtomicBool::new(false));
    let monitor = mic.and_then(|f| f(m).ok()).map(|mut src| {
        let (done, barge, sp, c) = (done.clone(), barge.clone(), stop_play.clone(), cancel.clone());
        std::thread::spawn(move || {
            if record::listen_for_speech(src.as_mut(), &c, &|| done.load(Ordering::SeqCst)) {
                barge.store(true, Ordering::SeqCst);
                sp.cancel();
            }
        })
    });
    let mut interrupted = false;
    let mut err: Option<String> = None;
    // Sentence-by-sentence by default; whole-file when the operator opted out or when the
    // streaming pass never got audio out (the backend cannot stream this reply).
    let mut whole_file = !crate::tts::streaming_enabled(m);
    if !whole_file {
        // The raw reply goes in: every chunk is normalized on its way out.
        let rep = crate::tts::speak_streaming_gated(m, text, &stop_play, &|| barge.load(Ordering::SeqCst));
        interrupted = rep.interrupted && barge.load(Ordering::SeqCst);
        match (rep.error, rep.played) {
            (None, _) => {}
            (Some(_), 0) => whole_file = true,
            // Audio already went out: stop instead of repeating sentences from the top.
            (Some(e), _) => err = Some(e),
        }
        // A barge-in (or any cancel) that landed during synthesis: do not start over.
        if stop_play.is_cancelled() {
            interrupted = true;
        }
    }
    if whole_file && err.is_none() && !interrupted {
        err = say_whole_file(m, &spoken, &stop_play).err();
    }
    done.store(true, Ordering::SeqCst);
    if let Some(h) = monitor {
        let _ = h.join();
    }
    interrupted |= barge.load(Ordering::SeqCst);
    if !interrupted {
        if let Some(e) = err {
            return Err(e);
        }
    }
    Ok(interrupted)
}

/// One synthesize + play of the whole text (`[media.voice] streaming = false`, or the
/// fallback after a streaming pass that never produced audio).
fn say_whole_file(m: &Media, spoken: &str, cancel: &Cancel) -> Result<(), String> {
    let (pid, s) = crate::tts::synthesize(m, &crate::tts::TtsRequest::new(spoken), cancel)?;
    let (asset, _) = crate::tts::finalize(m, &pid, s, false, cancel);
    let d = crate::stt::local::work_dir("say")?;
    let path = d.join(format!("reply.{}", crate::store::ext_for(&asset.mime)));
    std::fs::write(&path, &asset.bytes).map_err(|e| e.to_string())?;
    let r = crate::tts::play(m, &path, cancel);
    let _ = std::fs::remove_dir_all(&d);
    r
}

/// Run voice mode until quit, a stop phrase, `max_turns` or cancel.
pub fn voice_mode(m: &Media, opts: &VoiceModeOpts, io: &mut dyn VoiceIo, mic: &MicFactory, agent: &dyn crate::Agent, cancel: &Cancel) -> Result<VoiceSummary, String> {
    let mut sum = VoiceSummary { session: opts.session.clone(), ..Default::default() };
    let hint = transcript::voice_stop_hint(m);
    io.say(&format!("Voice mode on ({}).{}{hint}", if opts.wake_word { format!("say \"{}\"", super::wake::phrase(m)) } else if opts.continuous { "hands-free".into() } else { "press Enter to talk, q to quit".into() }, if hint.is_empty() { "" } else { " " }));
    let mut skip_wait = false;
    let mut rounds = 0;
    loop {
        if cancel.is_cancelled() || (opts.max_turns > 0 && rounds >= opts.max_turns) {
            break;
        }
        rounds += 1;
        if !skip_wait {
            if opts.wake_word {
                let mut eng = super::wake::Engine::open(m)?;
                let mut src = mic(m)?;
                let fired = super::wake::listen(&mut eng, src.as_mut(), cancel, &|| false, &mut |a| eprintln!("{a}"))?;
                if fired.is_none() {
                    break;
                }
            } else if !opts.continuous && io.wait_key("[voice] Enter = talk, q = quit") == Key::Quit {
                break;
            }
        }
        skip_wait = false;
        if opts.beep {
            play_pcm(m, &record::beep(880.0, 0.12, 1, m.cfg.float_or("voice.beep_volume", 0.3)), cancel);
        }
        io.say("[listening…]");
        let mut src = mic(m)?;
        let mut live = crate::stt::stream::open(m, None);
        let released = || io.released();
        let take = {
            let live_ref = &mut live;
            record::record_utterance_with(m, src.as_mut(), cancel, &released, &mut |b| {
                if let Some(s) = live_ref.as_mut() {
                    s.push(b);
                }
            })?
        };
        drop(src);
        if opts.beep {
            play_pcm(m, &record::beep(660.0, 0.1, 2, m.cfg.float_or("voice.beep_volume", 0.3)), cancel);
        }
        let Some(pcm) = take else {
            io.say("[no speech heard]");
            continue;
        };
        let text = match transcribe_take(m, &pcm, live, cancel) {
            Ok(Some(t)) => t,
            Ok(None) => {
                io.say("[nothing recognisable]");
                continue;
            }
            Err(e) => {
                io.say(&format!("[transcription failed: {e}]"));
                continue;
            }
        };
        if transcript::is_voice_stop_phrase(&text, &transcript::stop_phrases(m)) {
            sum.stopped_by_phrase = true;
            io.say("Voice mode off.");
            break;
        }
        io.say(&format!("you: {text}"));
        let (session, reply) = agent.turn(sum.session.as_deref(), &text, "voice", cancel)?;
        sum.session = Some(session);
        sum.turns += 1;
        io.say(&format!("seagent: {reply}"));
        if opts.speak {
            match speak(m, &reply, opts.barge_in.then_some(mic), cancel) {
                Ok(true) => {
                    sum.interrupted += 1;
                    skip_wait = true;
                }
                Ok(false) => {}
                Err(e) => io.say(&format!("[speech failed: {e}]")),
            }
        }
    }
    Ok(sum)
}

/// Voice requirements for `/voice status` (Hermes `check_voice_requirements`).
pub fn requirements(m: &Media) -> serde_json::Value {
    let stt = crate::stt::resolve_provider(m);
    serde_json::json!({
        "recorder": record::recorder_command(m).map(|c| c.join(" ")),
        "recorder_error": record::audio_unavailable_reason(m),
        "stt_provider": stt,
        "stt_available": stt != "none",
        "stt_streaming": crate::stt::stream::streaming_enabled(m),
        "tts_provider": crate::tts::configured_provider(m),
        "wake_word": super::wake::status(m),
        "stop_hint": transcript::voice_stop_hint(m),
        "available": record::recorder_command(m).is_some() && stt != "none",
    })
}

/// `seagent voice` entry: voice mode on this terminal with the installed agent.
pub fn run_cli(m: &Media, opts: &VoiceModeOpts, cancel: &Cancel) -> Result<VoiceSummary, String> {
    if let Some(why) = record::audio_unavailable_reason(m) {
        return Err(why);
    }
    let agent = crate::agent().ok_or("voice mode needs the agent runtime (seagent_media::set_agent was not called)")?;
    let mut io = TermIo::new();
    voice_mode(m, opts, &mut io, &default_mic(), agent.as_ref(), cancel)
}
