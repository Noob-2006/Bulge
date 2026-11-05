//! Live speech-to-text for voice front-ends (Hermes `tools/transcription_streaming.py`):
//! callers feed 16 kHz mono PCM while the user speaks, see partial text as the
//! provider recognizes it, and `finalize` at end of speech. Opt-in with
//! `[media.stt] streaming = true`; the socket itself is a [`crate::realtime`]
//! transcription session (`[media.stt] streaming_provider`, default = the STT provider
//! when it streams: openai, xai, elevenlabs, deepgram, mistral). Every caller falls
//! back to file transcription when no session opens or the session fails.

use crate::realtime::{RealtimeStt, SttEvent};
use crate::Media;

/// The contract every caller feeds.
pub const INPUT_RATE: u32 = 16000;
pub const STREAMING_PROVIDERS: &[&str] = &["openai", "xai", "elevenlabs", "deepgram", "mistral"];

pub fn streaming_enabled(m: &Media) -> bool {
    m.cfg.bool_or("stt.streaming", false)
}

/// Provider for live sessions: explicit `streaming_provider`, else the STT provider
/// when it is a streaming one.
pub fn streaming_provider(m: &Media) -> Option<String> {
    m.cfg.str("stt.streaming_provider").or_else(|| {
        let p = super::resolve_provider(m);
        STREAMING_PROVIDERS.contains(&p.as_str()).then_some(p)
    })
}

pub struct StreamingSession {
    inner: Box<dyn RealtimeStt>,
    partial: String,
    finals: Vec<String>,
    pub provider: String,
    failed: Option<String>,
}

impl StreamingSession {
    pub fn new(provider: &str, inner: Box<dyn RealtimeStt>) -> Self {
        StreamingSession { inner, partial: String::new(), finals: Vec::new(), provider: provider.into(), failed: None }
    }
    fn absorb(&mut self, evs: Vec<SttEvent>) {
        for e in evs {
            match e {
                SttEvent::Partial(t) => self.partial = t,
                SttEvent::Final(t) => {
                    if !t.trim().is_empty() {
                        self.finals.push(t.trim().to_string());
                    }
                    self.partial.clear();
                }
                SttEvent::Error(e) => self.failed = Some(e),
                _ => {}
            }
        }
    }
    /// Feed audio; returns the current partial transcript (finals so far + live partial).
    pub fn push(&mut self, pcm16k: &[i16]) -> String {
        if self.failed.is_none() {
            if let Err(e) = self.inner.send_audio(pcm16k) {
                self.failed = Some(e);
            }
            match self.inner.poll() {
                Ok(evs) => self.absorb(evs),
                Err(e) => self.failed = Some(e),
            }
        }
        self.partial_transcript()
    }
    pub fn partial_transcript(&self) -> String {
        let mut v = self.finals.clone();
        if !self.partial.trim().is_empty() {
            v.push(self.partial.trim().to_string());
        }
        v.join(" ")
    }
    /// End of speech: the final transcript, or `Err` (caller falls back to the file path).
    pub fn finalize(mut self) -> Result<String, String> {
        if let Some(e) = self.failed.take() {
            return Err(e);
        }
        let evs = self.inner.finish()?;
        self.absorb(evs);
        if let Some(e) = self.failed.take() {
            return Err(e);
        }
        if !self.partial.trim().is_empty() {
            self.finals.push(self.partial.trim().to_string());
        }
        let t = self.finals.join(" ");
        if t.trim().is_empty() {
            return Err("Transcription returned an empty transcript".into());
        }
        Ok(t)
    }
}

/// Language for a live session: caller hint > `[media.stt.<provider>] language` (plus
/// `language_code` for elevenlabs) > `[media.stt] language` > `HERMES_LOCAL_STT_LANGUAGE`
/// (Hermes `_resolve_stt_language(..., extra_keys=("language_code",))`).
pub fn session_language(m: &Media, provider: &str, language: Option<&str>) -> Option<String> {
    let aliased = |key: &str| super::section_str(m, provider, key);
    language.map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).or_else(|| aliased("language")).or_else(|| if provider == "elevenlabs" { aliased("language_code") } else { None }).or_else(|| super::configured_language(m, provider))
}

/// Open a live session when streaming is enabled and a provider accepts it.
pub fn open(m: &Media, language: Option<&str>) -> Option<StreamingSession> {
    if !streaming_enabled(m) {
        return None;
    }
    let p = streaming_provider(m)?;
    let lang = session_language(m, &p, language);
    crate::realtime::open_stt(m, Some(&p), INPUT_RATE, lang.as_deref()).ok().map(|s| StreamingSession::new(&p, s))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scripted(Vec<Vec<SttEvent>>, Vec<SttEvent>);
    impl RealtimeStt for Scripted {
        fn send_audio(&mut self, _pcm: &[i16]) -> Result<(), String> {
            Ok(())
        }
        fn poll(&mut self) -> Result<Vec<SttEvent>, String> {
            Ok(if self.0.is_empty() { vec![] } else { self.0.remove(0) })
        }
        fn finish(&mut self) -> Result<Vec<SttEvent>, String> {
            Ok(std::mem::take(&mut self.1))
        }
    }

    #[test]
    fn partials_then_final() {
        let s = Scripted(vec![vec![SttEvent::Partial("hel".into())], vec![SttEvent::Final("hello".into()), SttEvent::Partial("wor".into())]], vec![SttEvent::Final("world".into())]);
        let mut ss = StreamingSession::new("openai", Box::new(s));
        assert_eq!(ss.push(&[0; 160]), "hel");
        assert_eq!(ss.push(&[0; 160]), "hello wor");
        assert_eq!(ss.finalize().unwrap(), "hello world");
        let bad = Scripted(vec![vec![SttEvent::Error("socket closed".into())]], vec![]);
        let mut ss = StreamingSession::new("xai", Box::new(bad));
        ss.push(&[0; 10]);
        assert_eq!(ss.finalize().unwrap_err(), "socket closed");
        let m = Media::new(crate::MediaConfig::default());
        assert!(open(&m, None).is_none(), "streaming is opt-in");
    }
}
