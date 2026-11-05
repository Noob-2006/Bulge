//! Transcript source providers (OpenClaw `TranscriptSourceProvider`,
//! `manual-source.ts`, `provider-registry.ts`).

use super::store::{now_iso, Session, Utterance};
use crate::voice::record::{record_utterance, PcmSource};
use crate::Media;
use ark_core::Cancel;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Receives each captured utterance.
pub type Sink = Arc<dyn Fn(Utterance) + Send + Sync>;

/// A running live capture.
pub trait Capture: Send {
    /// End the capture; final utterances are delivered before this returns.
    fn stop(&mut self) -> Result<(), String>;
    fn active(&self) -> bool;
}

pub trait TranscriptSource: Send + Sync {
    fn id(&self) -> &str;
    fn aliases(&self) -> &[&str] {
        &[]
    }
    fn name(&self) -> &str;
    /// "live-voice" | "live-audio" | "live-caption" | "meeting" | "posthoc-transcript" |
    /// "recording" | "microphone".
    fn kinds(&self) -> &[&str];
    fn can_start(&self) -> bool {
        false
    }
    fn can_import(&self) -> bool {
        false
    }
    fn start(&self, _m: &Arc<Media>, _session: &Session, _sink: Sink) -> Result<Box<dyn Capture>, String> {
        Err(format!("transcripts provider {} cannot start live capture", self.id()))
    }
    fn import(&self, _m: &Media, _session: &Session, _text: &str, _speaker: Option<&str>, _cancel: &Cancel) -> Result<Vec<Utterance>, String> {
        Err(format!("transcripts provider {} cannot import transcripts", self.id()))
    }
}

/// `"Speaker: text"` → `(Some(speaker), text)` (labels up to 80 chars, no newline).
pub fn parse_speaker_line(line: &str) -> (Option<String>, String) {
    let l = line.trim();
    if let Some(i) = l.find(':') {
        let (sp, rest) = (&l[..i], &l[i + 1..]);
        if !sp.is_empty() && sp.chars().count() <= 80 && rest.starts_with(char::is_whitespace) && !rest.trim().is_empty() {
            return (Some(sp.trim().to_string()), rest.trim().to_string());
        }
    }
    (None, l.to_string())
}

/// Built-in post-hoc text import.
pub struct Manual;

impl TranscriptSource for Manual {
    fn id(&self) -> &str {
        "manual-transcript"
    }
    fn aliases(&self) -> &[&str] {
        &["import", "transcript"]
    }
    fn name(&self) -> &str {
        "Manual Transcript Import"
    }
    fn kinds(&self) -> &[&str] {
        &["posthoc-transcript"]
    }
    fn can_import(&self) -> bool {
        true
    }
    fn import(&self, _m: &Media, s: &Session, text: &str, speaker: Option<&str>, _c: &Cancel) -> Result<Vec<Utterance>, String> {
        let now = now_iso();
        Ok(text
            .lines()
            .map(parse_speaker_line)
            .filter(|(_, t)| !t.is_empty())
            .enumerate()
            .map(|(i, (sp, t))| Utterance { id: format!("{}-{}", s.session_id, i + 1), started_at: now.clone(), r#final: true, speaker: Some(sp.or(speaker.map(str::to_string)).unwrap_or_else(|| "Speaker".into())), text: t })
            .collect())
    }
}

/// An audio recording on disk, transcribed with the configured STT provider
/// (`transcript` = the file path). Segments become utterances.
pub struct AudioFile;

impl TranscriptSource for AudioFile {
    fn id(&self) -> &str {
        "audio-file"
    }
    fn aliases(&self) -> &[&str] {
        &["recording", "audio"]
    }
    fn name(&self) -> &str {
        "Audio Recording"
    }
    fn kinds(&self) -> &[&str] {
        &["recording"]
    }
    fn can_import(&self) -> bool {
        true
    }
    fn import(&self, m: &Media, s: &Session, path: &str, speaker: Option<&str>, cancel: &Cancel) -> Result<Vec<Utterance>, String> {
        let p = ark_core::tool::expand_home(path.trim());
        let (_, t) = crate::stt::transcribe_file(m, &p, cancel)?;
        let now = now_iso();
        let sp = speaker.unwrap_or("Speaker").to_string();
        let pieces: Vec<(Option<String>, String)> = if t.segments.is_empty() { vec![(None, t.text.clone())] } else { t.segments.iter().map(|g| (g.speaker.clone(), g.text.clone())).collect() };
        Ok(pieces.into_iter().filter(|(_, x)| !x.trim().is_empty()).enumerate().map(|(i, (gs, x))| Utterance { id: format!("{}-{}", s.session_id, i + 1), started_at: now.clone(), r#final: true, speaker: Some(gs.unwrap_or_else(|| sp.clone())), text: x.trim().to_string() }).collect())
    }
}

pub type SourceFactory = Arc<dyn Fn(&Media) -> Result<Box<dyn PcmSource>, String> + Send + Sync>;

/// Live capture from this machine's microphone: each utterance is cut by the voice
/// silence detector and transcribed. `[media.transcripts.microphone] speaker = "Me"`.
pub struct Microphone {
    pub open: SourceFactory,
}

impl Default for Microphone {
    fn default() -> Self {
        Microphone { open: Arc::new(|m: &Media| crate::voice::record::Mic::open(m).map(|x| Box::new(x) as Box<dyn PcmSource>)) }
    }
}

/// Remembers that the wrapped source ended.
struct Tracked {
    inner: Box<dyn PcmSource>,
    ended: bool,
}

impl PcmSource for Tracked {
    fn read(&mut self, cancel: &Cancel) -> Result<Option<Vec<i16>>, String> {
        let r = self.inner.read(cancel);
        if matches!(r, Ok(None)) {
            self.ended = true;
        }
        r
    }
}

struct MicCapture {
    stop: Arc<AtomicBool>,
    cancel: Cancel,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Capture for MicCapture {
    fn stop(&mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::SeqCst);
        // Let the current take finish and be transcribed; a stalled recorder is cancelled.
        let t0 = std::time::Instant::now();
        while self.active() && t0.elapsed() < std::time::Duration::from_secs(2) {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        self.cancel.cancel();
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
        Ok(())
    }
    fn active(&self) -> bool {
        self.worker.as_ref().is_some_and(|w| !w.is_finished())
    }
}

impl TranscriptSource for Microphone {
    fn id(&self) -> &str {
        "microphone"
    }
    fn aliases(&self) -> &[&str] {
        &["mic", "local"]
    }
    fn name(&self) -> &str {
        "Local Microphone"
    }
    fn kinds(&self) -> &[&str] {
        &["microphone", "live-voice"]
    }
    fn can_start(&self) -> bool {
        true
    }
    fn start(&self, m: &Arc<Media>, s: &Session, sink: Sink) -> Result<Box<dyn Capture>, String> {
        let mut src = Tracked { inner: (self.open)(m)?, ended: false };
        let stop = Arc::new(AtomicBool::new(false));
        let cancel = Cancel::new();
        let (m2, st, c2, sid) = (m.clone(), stop.clone(), cancel.clone(), s.session_id.clone());
        let speaker = m.cfg.str("transcripts.microphone.speaker").unwrap_or_else(|| "Me".into());
        let worker = std::thread::spawn(move || {
            let mut n = 0;
            let st2 = st.clone();
            while !st.load(Ordering::SeqCst) {
                // The take ends at silence; a stop request finishes the current take first.
                let take = match record_utterance(&m2, &mut src, &c2, &|| st2.load(Ordering::SeqCst)) {
                    Ok(Some(pcm)) => pcm,
                    Ok(None) if src.ended => break,
                    Ok(None) => continue,
                    Err(_) => break,
                };
                let wav = crate::audio::wav_encode(&take, crate::voice::record::SAMPLE_RATE, 1);
                if let Ok((_, t)) = crate::stt::transcribe(&m2, &crate::stt::SttRequest::new(wav, "audio/wav"), &Cancel::new()) {
                    if let Some(text) = crate::voice::transcript::filter(&t.text) {
                        n += 1;
                        sink(Utterance { id: format!("{sid}-{n}"), started_at: now_iso(), r#final: true, speaker: Some(speaker.clone()), text });
                    }
                }
                // A source that ended (file, closed recorder) ends the capture.
                if src.ended {
                    break;
                }
            }
        });
        Ok(Box::new(MicCapture { stop, cancel, worker: Some(worker) }))
    }
}

fn registry() -> &'static Mutex<Vec<Arc<dyn TranscriptSource>>> {
    static R: OnceLock<Mutex<Vec<Arc<dyn TranscriptSource>>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(vec![Arc::new(Manual), Arc::new(AudioFile), Arc::new(Microphone::default()), Arc::new(super::channel::DiscordVoiceSource), Arc::new(super::channel::GoogleMeet)]))
}

/// Register a source provider (channel/meeting integrations); same id replaces.
pub fn register_source(p: Arc<dyn TranscriptSource>) {
    let mut r = registry().lock().unwrap();
    r.retain(|x| x.id() != p.id());
    r.push(p);
}

pub fn sources() -> Vec<Arc<dyn TranscriptSource>> {
    registry().lock().unwrap().clone()
}

pub fn find_source(id: &str) -> Option<Arc<dyn TranscriptSource>> {
    let k = id.trim().to_ascii_lowercase();
    sources().into_iter().find(|p| p.id() == k || p.aliases().contains(&k.as_str()))
}
