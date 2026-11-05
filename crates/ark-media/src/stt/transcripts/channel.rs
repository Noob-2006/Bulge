//! Channel and meeting transcript sources: a Discord voice channel and Google Meet
//! live captions (OpenClaw `extensions/discord/src/voice/transcripts-source.ts` +
//! `extensions/discord/transcripts-source-api.ts`, and `extensions/google-meet/index.ts`
//! `registerTranscriptSourceProvider` with
//! `src/transports/google-meet-caption-observer-source.ts`).
//!
//! Neither transport lives in this crate: the Discord gateway, voice socket and
//! per-utterance transcription are `ark-channel`'s, and Meet captions come from the
//! meeting bot's browser tab ([`crate::meeting`]). Each source therefore talks to a
//! narrow back-end trait that the owning subsystem installs once:
//!
//! * [`DiscordVoice`] — installed by the Discord voice manager with
//!   [`set_discord_voice`]. Until then (or when no bot is connected) `start` fails
//!   with the upstream message "Discord voice manager is not available."
//! * [`Captions`] — installed with [`set_captions`]; the default
//!   ([`MeetingCaptions`]) reads the caption stream of the active meeting from
//!   [`crate::meeting`], so Google Meet works whenever the meeting bot is in a call.
//!
//! Parameter rules follow upstream: `discord-voice` needs `guildId` and `channelId`
//! (`accountId` optional) and reports "Discord transcripts require guildId and
//! channelId."; `google-meet` takes an optional `meetingUrl` and otherwise uses the
//! only active Meet session. Both are live sources (`can_start`, no `import`).
//!
//! ```toml
//! [media.transcripts.discord]
//! speaker = ""            # fallback speaker label when the transport sends none
//! [media.transcripts.captions]
//! poll_ms = 1000          # caption poll interval (upstream settles rows for 1 s)
//! ```

use super::sources::{Capture, Sink};
use super::store::{now_iso, Session, Utterance};
use super::TranscriptSource;
use crate::Media;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Upstream `sourceKinds` of these providers.
pub const DISCORD_VOICE_KIND: &str = "live-audio";
pub const CAPTION_KIND: &str = "live-caption";
/// Meeting platform id of the caption source (Google Meet).
pub const MEET_PLATFORM: &str = "google-meet";

/// One line of channel audio that the transport itself already recognized, or one
/// caption row.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Heard {
    pub speaker: Option<String>,
    pub text: String,
}

/// Receives each recognized line from a channel back-end.
pub type HeardSink = Arc<dyn Fn(Heard) + Send + Sync>;

/// The Discord voice client (ark-channel `discord_voice::VoiceManager`): joins a
/// voice channel, transcribes each speaker and hands the text over.
pub trait DiscordVoice: Send + Sync {
    /// A bot for `account` (`""` = the default account) is connected to Discord.
    fn connected(&self, _account: &str) -> bool {
        true
    }
    /// Voice channel display name, for the session title.
    fn channel_name(&self, _account: &str, _guild: &str, _channel: &str) -> Option<String> {
        None
    }
    /// Join `channel` and deliver every utterance to `sink`. Stopping the returned
    /// capture ends transcription only; leaving the channel stays with whoever joined.
    fn capture(&self, account: &str, guild: &str, channel: &str, sink: HeardSink) -> Result<Box<dyn Capture>, String>;
}

static DISCORD: OnceLock<Mutex<Option<Arc<dyn DiscordVoice>>>> = OnceLock::new();

fn discord_slot() -> &'static Mutex<Option<Arc<dyn DiscordVoice>>> {
    DISCORD.get_or_init(|| Mutex::new(None))
}

/// Install the Discord voice back-end (`None`-free: the last install wins).
pub fn set_discord_voice(b: Arc<dyn DiscordVoice>) {
    *discord_slot().lock().unwrap() = Some(b);
}

pub fn discord_voice() -> Option<Arc<dyn DiscordVoice>> {
    discord_slot().lock().unwrap().clone()
}

/// Discord voice-channel capture (`providerId = "discord-voice"`, alias `discord`).
pub struct DiscordVoiceSource;

impl TranscriptSource for DiscordVoiceSource {
    fn id(&self) -> &str {
        "discord-voice"
    }
    fn aliases(&self) -> &[&str] {
        &["discord"]
    }
    fn name(&self) -> &str {
        "Discord Voice"
    }
    fn kinds(&self) -> &[&str] {
        &[DISCORD_VOICE_KIND]
    }
    fn can_start(&self) -> bool {
        true
    }
    fn start(&self, m: &Arc<Media>, s: &Session, sink: Sink) -> Result<Box<dyn Capture>, String> {
        let (guild, channel) = (s.source.guild_id.clone().unwrap_or_default(), s.source.channel_id.clone().unwrap_or_default());
        if guild.trim().is_empty() || channel.trim().is_empty() {
            return Err("Discord transcripts require guildId and channelId.".into());
        }
        let account = s.source.account_id.clone().unwrap_or_default();
        let backend = discord_voice().ok_or("Discord voice manager is not available.")?;
        if !backend.connected(&account) {
            return Err("Discord voice manager is not available.".into());
        }
        let fallback = m.cfg.str("transcripts.discord.speaker").filter(|x| !x.trim().is_empty()).unwrap_or_else(|| "Speaker".into());
        let sid = s.session_id.clone();
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let heard: HeardSink = Arc::new(move |h: Heard| {
            // The channel's own STT can emit whisper hallucinations; drop those, keep the rest.
            let Some(text) = crate::voice::transcript::filter(&h.text) else { return };
            let i = n.fetch_add(1, Ordering::SeqCst) + 1;
            sink(Utterance {
                id: format!("{sid}-{i}"),
                started_at: now_iso(),
                r#final: true,
                speaker: Some(h.speaker.map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).unwrap_or_else(|| fallback.clone())),
                text,
            });
        });
        backend.capture(&account, guild.trim(), channel.trim(), heard)
    }
}

/// One caption row from a meeting.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CaptionLine {
    pub speaker: Option<String>,
    pub text: String,
}

/// The meeting whose captions are being read.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CaptionSession {
    pub id: String,
    pub url: String,
    /// The call is over (captions stop; the tail is committed).
    pub ended: bool,
}

/// A live caption stream (Google Meet today; the same trait serves Teams/Zoom).
pub trait Captions: Send + Sync {
    /// The session to read: `url` when given, else the only active session of
    /// `platform`. `Err` = no such live session.
    fn session(&self, platform: &str, url: Option<&str>) -> Result<CaptionSession, String>;
    /// Every caption row captured so far, oldest first (rows grow in place; the
    /// store keeps the first committed version of each row).
    fn lines(&self, platform: &str, session: &str, finalize: bool) -> Result<Vec<CaptionLine>, String>;
}

static CAPTIONS: OnceLock<Mutex<Option<Arc<dyn Captions>>>> = OnceLock::new();

fn captions_slot() -> &'static Mutex<Option<Arc<dyn Captions>>> {
    CAPTIONS.get_or_init(|| Mutex::new(None))
}

/// Replace the caption back-end (default: the meeting bot, [`MeetingCaptions`]).
pub fn set_captions(c: Arc<dyn Captions>) {
    *captions_slot().lock().unwrap() = Some(c);
}

pub fn captions() -> Option<Arc<dyn Captions>> {
    captions_slot().lock().unwrap().clone()
}

/// The caption back-end in force: an installed one, else the meeting bot's.
pub fn captions_for(m: &Arc<Media>) -> Arc<dyn Captions> {
    captions().unwrap_or_else(|| Arc::new(MeetingCaptions::new(m)))
}

/// Default caption stream: the meeting session's live transcript
/// ([`crate::meeting::Meetings::refresh_transcript`]), i.e. the same rows the
/// `google_meet` tool archives.
pub struct MeetingCaptions {
    m: Arc<Media>,
}

impl MeetingCaptions {
    pub fn new(m: &Arc<Media>) -> Self {
        MeetingCaptions { m: m.clone() }
    }
}

fn platform_of(id: &str) -> Option<crate::meeting::platforms::Platform> {
    crate::meeting::platforms::ALL.into_iter().find(|p| p.id() == id)
}

/// `https://meet.google.com/abc-defg-hij?authuser=0` → `meet.google.com/abc-defg-hij`.
pub fn meeting_key(url: &str) -> String {
    let u = url.trim();
    let (scheme, rest) = u.split_once("://").unwrap_or(("https", u));
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    format!("{}://{}", scheme.to_ascii_lowercase(), rest.trim_end_matches('/').to_ascii_lowercase())
}

impl Captions for MeetingCaptions {
    fn session(&self, platform: &str, url: Option<&str>) -> Result<CaptionSession, String> {
        let p = platform_of(platform).ok_or_else(|| format!("no meeting platform `{platform}`"))?;
        let ms = crate::meeting::meetings(&self.m);
        let id = ms.resolve(p, None)?;
        let s = ms.get(&id)?;
        if let Some(u) = url.filter(|u| !u.trim().is_empty()) {
            if meeting_key(&s.url) != meeting_key(u) {
                return Err(format!("the active {} session is at {}, not {u}", p.display(), s.url));
            }
        }
        Ok(CaptionSession { id: s.id, url: s.url, ended: s.state == "ended" })
    }
    fn lines(&self, platform: &str, session: &str, finalize: bool) -> Result<Vec<CaptionLine>, String> {
        if platform_of(platform).is_none() {
            return Err(format!("no meeting platform `{platform}`"));
        }
        let ms = crate::meeting::meetings(&self.m);
        Ok(ms
            .refresh_transcript(session, finalize)?
            .into_iter()
            .map(|l| CaptionLine { speaker: Some(l.speaker).filter(|s| !s.trim().is_empty()), text: l.text })
            .collect())
    }
}

/// A worker thread that stops on request.
struct Worker {
    stop: Arc<AtomicBool>,
    /// How long `stop` waits for the tail to be committed.
    settle: Duration,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Capture for Worker {
    fn stop(&mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::SeqCst);
        let t0 = Instant::now();
        while self.active() && t0.elapsed() < self.settle {
            std::thread::sleep(Duration::from_millis(10));
        }
        if let Some(w) = self.worker.take() {
            if w.is_finished() {
                let _ = w.join();
            }
            // A 15 s caption poll still in flight is left to finish on its own; the
            // sink only appends, so late rows are harmless.
        }
        Ok(())
    }
    fn active(&self) -> bool {
        self.worker.as_ref().is_some_and(|w| !w.is_finished())
    }
}

/// Google Meet live captions (`providerId = "google-meet"`, aliases `googlemeet`,
/// `meet`). A caption row is recorded once the next row appears (Meet scrolls rows
/// up as they settle); the last row is recorded when the call ends or capture stops.
pub struct GoogleMeet;

impl TranscriptSource for GoogleMeet {
    fn id(&self) -> &str {
        MEET_PLATFORM
    }
    fn aliases(&self) -> &[&str] {
        &["googlemeet", "meet"]
    }
    fn name(&self) -> &str {
        "Google Meet"
    }
    fn kinds(&self) -> &[&str] {
        &[CAPTION_KIND]
    }
    fn can_start(&self) -> bool {
        true
    }
    fn start(&self, m: &Arc<Media>, s: &Session, sink: Sink) -> Result<Box<dyn Capture>, String> {
        let caps = captions_for(m);
        let wanted = s.source.meeting_url.clone();
        let cs = caps.session(MEET_PLATFORM, wanted.as_deref())?;
        let poll = Duration::from_millis(m.cfg.int_or("transcripts.captions.poll_ms", 1000).clamp(10, 60_000) as u64);
        let stop = Arc::new(AtomicBool::new(false));
        let st = stop.clone();
        let sid = s.session_id.clone();
        let url = cs.url.clone();
        let worker = std::thread::spawn(move || {
            let mut seen = 0usize;
            let mut n = 0usize;
            loop {
                let finalize = st.load(Ordering::SeqCst);
                let alive = caps.session(MEET_PLATFORM, Some(&url)).map(|x| !x.ended).unwrap_or(false);
                let lines = match caps.lines(MEET_PLATFORM, &cs.id, finalize || !alive) {
                    Ok(l) => l,
                    Err(_) => break,
                };
                let ready = if finalize || !alive { lines.len() } else { lines.len().saturating_sub(1) };
                for l in lines.iter().take(ready).skip(seen) {
                    let Some(text) = crate::voice::transcript::filter(&l.text) else { continue };
                    n += 1;
                    sink(Utterance {
                        id: format!("{sid}-{n}"),
                        started_at: now_iso(),
                        r#final: true,
                        speaker: Some(l.speaker.clone().unwrap_or_else(|| "Speaker".into())),
                        text,
                    });
                }
                seen = seen.max(ready);
                if finalize || !alive {
                    break;
                }
                std::thread::sleep(poll);
            }
        });
        Ok(Box::new(Worker { stop, settle: poll + Duration::from_secs(2), worker: Some(worker) }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stt::transcripts::store::SourceLocator;
    use crate::testutil::ctx;
    use serde_json::json;
    use std::sync::atomic::AtomicUsize;

    struct FakeDiscord {
        connected: AtomicBool,
        emitted: Mutex<Vec<Heard>>,
    }

    impl Default for FakeDiscord {
        fn default() -> Self {
            FakeDiscord { connected: AtomicBool::new(true), emitted: Mutex::new(Vec::new()) }
        }
    }

    struct FakeCapture {
        done: AtomicBool,
    }

    impl Capture for FakeCapture {
        fn stop(&mut self) -> Result<(), String> {
            self.done.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn active(&self) -> bool {
            !self.done.load(Ordering::SeqCst)
        }
    }

    impl DiscordVoice for FakeDiscord {
        fn connected(&self, _a: &str) -> bool {
            self.connected.load(Ordering::SeqCst)
        }
        fn channel_name(&self, _a: &str, _g: &str, _c: &str) -> Option<String> {
            Some("Standup".into())
        }
        fn capture(&self, account: &str, guild: &str, channel: &str, sink: HeardSink) -> Result<Box<dyn Capture>, String> {
            if (account, guild, channel) != ("default", "g1", "c1") {
                return Err(format!("unexpected target {account}/{guild}/{channel}"));
            }
            // A real manager transcribes asynchronously; emit what the fixture queued.
            for h in self.emitted.lock().unwrap().drain(..) {
                sink(h);
            }
            Ok(Box::new(FakeCapture { done: AtomicBool::new(false) }))
        }
    }

    struct FakeCaptions {
        rows: Mutex<Vec<CaptionLine>>,
        calls: AtomicUsize,
        /// `session()` reports the call over from this call on.
        end_after: usize,
    }

    impl Captions for FakeCaptions {
        fn session(&self, platform: &str, url: Option<&str>) -> Result<CaptionSession, String> {
            assert_eq!(platform, MEET_PLATFORM);
            let ended = self.calls.load(Ordering::SeqCst) >= self.end_after;
            Ok(CaptionSession { id: "meet-1".into(), url: url.unwrap_or("https://meet.google.com/abc-defg-hij").into(), ended })
        }
        fn lines(&self, platform: &str, session: &str, _finalize: bool) -> Result<Vec<CaptionLine>, String> {
            assert_eq!((platform, session), (MEET_PLATFORM, "meet-1"));
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.rows.lock().unwrap().clone())
        }
    }

    /// The back-end slots are process-global: serialize the tests that install one.
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static L: OnceLock<Mutex<()>> = OnceLock::new();
        L.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
    }

    fn reset_backends() {
        *discord_slot().lock().unwrap() = None;
        *captions_slot().lock().unwrap() = None;
    }

    fn err_of(r: Result<Box<dyn Capture>, String>) -> String {
        match r {
            Ok(_) => panic!("expected the source to refuse"),
            Err(e) => e,
        }
    }

    fn sess(provider: &str, locator: SourceLocator) -> Session {
        Session { session_id: "transcript-test".into(), title: None, source: SourceLocator { provider_id: provider.into(), ..locator }, started_at: now_iso(), stopped_at: None, metadata: json!({}) }
    }

    fn locator(guild: Option<&str>, channel: Option<&str>, url: Option<&str>) -> SourceLocator {
        SourceLocator { provider_id: String::new(), kind: Some(DISCORD_VOICE_KIND.into()), account_id: Some("default".into()), guild_id: guild.map(str::to_string), channel_id: channel.map(str::to_string), meeting_url: url.map(str::to_string) }
    }

    #[test]
    fn discord_and_meet_sources() {
        let _g = test_lock();
        reset_backends();
        // Registry: both providers are built in and listed under the upstream ids.
        let m = Arc::new(Media::new(crate::MediaConfig::from_toml("[transcripts]\nmodel_summary = false\n[transcripts.captions]\npoll_ms = 10\n")));
        assert!(super::super::sources::find_source("discord").is_some());
        assert!(super::super::sources::find_source("meet").is_some());
        assert_eq!(super::super::sources::find_source("googlemeet").unwrap().name(), "Google Meet");

        // No back-end installed yet: upstream's error, and the parameter rules come first.
        assert!(discord_voice().is_none());
        let sink: Sink = Arc::new(|_u: Utterance| {});
        let src = DiscordVoiceSource;
        let e = err_of(src.start(&m, &sess("discord-voice", locator(None, Some("c1"), None)), sink.clone()));
        assert_eq!(e, "Discord transcripts require guildId and channelId.");
        let e = err_of(src.start(&m, &sess("discord-voice", locator(Some("g1"), Some("c1"), None)), sink.clone()));
        assert_eq!(e, "Discord voice manager is not available.");

        // A connected manager with nothing to say, then one that is not connected.
        let fake = Arc::new(FakeDiscord::default());
        fake.emitted.lock().unwrap().extend([
            Heard { speaker: Some("Alice".into()), text: "  hello team  ".into() },
            Heard { speaker: None, text: "Thank you.".into() },
            Heard { speaker: Some("Bob".into()), text: "beta ships friday".into() },
        ]);
        set_discord_voice(fake.clone());
        let got = Arc::new(Mutex::new(Vec::new()));
        let g2 = got.clone();
        let sink: Sink = Arc::new(move |u: Utterance| g2.lock().unwrap().push(u));
        let mut cap = src.start(&m, &sess("discord-voice", locator(Some("g1"), Some("c1"), None)), sink).unwrap();
        assert!(cap.active());
        let got = got.lock().unwrap().clone();
        assert_eq!(got.len(), 2, "the hallucination row is dropped, ids/counting survive it: {got:?}");
        assert_eq!((got[0].id.as_str(), got[0].speaker.as_deref(), got[0].text.as_str()), ("transcript-test-1", Some("Alice"), "hello team"));
        assert_eq!((got[1].id.as_str(), got[1].speaker.as_deref(), got[1].text.as_str()), ("transcript-test-2", Some("Bob"), "beta ships friday"));
        cap.stop().unwrap();
        assert!(!cap.active());
        fake.connected.store(false, Ordering::SeqCst);
        assert_eq!(err_of(src.start(&m, &sess("discord-voice", locator(Some("g1"), Some("c1"), None)), Arc::new(|_u| {}))), "Discord voice manager is not available.");

        // Captions: rows commit as the next row appears; the tail lands at the end.
        let caps_out = Arc::new(Mutex::new(Vec::new()));
        let o2 = caps_out.clone();
        let sink: Sink = Arc::new(move |u: Utterance| o2.lock().unwrap().push(u));
        let rows = vec![
            CaptionLine { speaker: Some("Alice".into()), text: "we should ship the beta".into() },
            CaptionLine { speaker: Some("Bob".into()), text: "agreed, friday works".into() },
            CaptionLine { speaker: Some("Alice".into()), text: "then it is settled".into() },
        ];
        set_captions(Arc::new(FakeCaptions { rows: Mutex::new(rows), calls: AtomicUsize::new(0), end_after: 3 }));
        let mut cap = GoogleMeet.start(&m, &sess("google-meet", locator(None, None, Some("https://meet.google.com/abc-defg-hij?authuser=0"))), sink).unwrap();
        let t0 = Instant::now();
        while cap.active() && t0.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!cap.active(), "the call ended, so capture stops by itself");
        cap.stop().unwrap();
        let out = caps_out.lock().unwrap().clone();
        assert_eq!(out.iter().map(|u| (u.speaker.clone().unwrap_or_default(), u.text.clone())).collect::<Vec<_>>(), vec![
            ("Alice".to_string(), "we should ship the beta".to_string()),
            ("Bob".to_string(), "agreed, friday works".to_string()),
            ("Alice".to_string(), "then it is settled".to_string()),
        ]);
        assert_eq!(out[2].id, "transcript-test-3");

        // Meeting URLs: invitation credentials and query strings never reach the session.
        assert_eq!(meeting_key("https://meet.google.com/ABC-defg-hij/?authuser=0#x"), "https://meet.google.com/abc-defg-hij");

        // The default back-end is the meeting bot: with no call joined it says so
        // instead of pretending to capture.
        reset_backends();
        assert_eq!(MeetingCaptions::new(&m).session(MEET_PLATFORM, None).unwrap_err(), "no active Google Meet session; join one first");
        assert_eq!(MeetingCaptions::new(&m).session("zoom-meetings", None).unwrap_err(), "no active Zoom session; join one first");
        assert!(MeetingCaptions::new(&m).session("teams", None).unwrap_err().contains("no meeting platform `teams`"));
        assert_eq!(err_of(GoogleMeet.start(&m, &sess("google-meet", locator(None, None, None)), Arc::new(|_u| {}))), "no active Google Meet session; join one first");
    }

    /// End-to-end through the `transcripts` tool: start → rows → stop → notes, both sources.
    #[test]
    fn tool_captures_a_discord_channel_and_a_meet_call() {
        let _g = test_lock();
        reset_backends();
        let cfg = "[stt]\nprovider = \"echo\"\n[stt.providers.echo]\ncommand = \"echo utterance heard\"\n[transcripts]\nmodel_summary = false\n[transcripts.captions]\npoll_ms = 10\n";
        let m = Arc::new(Media::new(crate::MediaConfig::from_toml(cfg)));
        let tool = &crate::stt::transcripts::tools(&m)[0];
        let c = ctx("tr-channel");

        let fake = Arc::new(FakeDiscord::default());
        fake.emitted.lock().unwrap().extend([
            Heard { speaker: Some("Alice".into()), text: "standup starts now".into() },
            Heard { speaker: Some("Bob".into()), text: "I fixed the login bug".into() },
        ]);
        set_discord_voice(fake);
        let r = tool.call(&c, json!({"action": "start", "providerId": "discord-voice", "guildId": "g1", "channelId": "c1", "accountId": "default", "title": "Standup"}));
        assert!(!r.is_error, "{}", r.content);
        assert!(r.content.contains("Discord Voice"), "{}", r.content);
        let sel = r.content.lines().find_map(|l| l.strip_prefix("Selector:")).unwrap().trim().to_string();
        let st = tool.call(&c, json!({"action": "status"}));
        assert!(st.content.contains("\"guildId\":\"g1\"") && st.content.contains("\"channelId\":\"c1\""), "{}", st.content);
        let stop = tool.call(&c, json!({"action": "stop", "selector": sel}));
        assert!(stop.content.contains("Utterances: 2"), "{}", stop.content);
        let notes = std::fs::read_to_string(stop.content.lines().find_map(|l| l.strip_prefix("Summary:")).unwrap().trim()).unwrap();
        assert!(notes.contains("- Alice: standup starts now\n- Bob: I fixed the login bug"), "{notes}");

        let rows = vec![
            CaptionLine { speaker: Some("Dana".into()), text: "kickoff at ten".into() },
            CaptionLine { speaker: Some("Eve".into()), text: "I will send the deck".into() },
        ];
        set_captions(Arc::new(FakeCaptions { rows: Mutex::new(rows), calls: AtomicUsize::new(0), end_after: 3 }));
        let r = tool.call(&c, json!({"action": "start", "providerId": "meet", "meetingUrl": "https://meet.google.com/abc-defg-hij", "title": "Kickoff"}));
        assert!(!r.is_error, "{}", r.content);
        let sel = r.content.lines().find_map(|l| l.strip_prefix("Selector:")).unwrap().trim().to_string();
        std::thread::sleep(Duration::from_millis(300));
        let stop = tool.call(&c, json!({"action": "stop", "selector": sel}));
        assert!(stop.content.contains("Utterances: 2"), "{}", stop.content);
        let notes = std::fs::read_to_string(stop.content.lines().find_map(|l| l.strip_prefix("Summary:")).unwrap().trim()).unwrap();
        assert!(notes.contains("- Dana: kickoff at ten\n- Eve: I will send the deck"), "{notes}");
    }
}
