//! Live media-provider smoke tests (gen1-307): text → speech → text through real APIs.
//!
//! The rest of ark-media runs against `testutil::FakeServer`. Each case here synthesizes a short
//! sentence with a real TTS provider and transcribes it back with a real STT provider, so one
//! run proves both directions. `#[ignore]`, and they need `ARK_LIVE_PROVIDERS=1` plus the
//! provider keys:
//!
//! ```sh
//! ARK_LIVE_PROVIDERS=1 OPENAI_API_KEY=… ELEVENLABS_API_KEY=… DEEPGRAM_API_KEY=… \
//!   cargo test -p ark-media --test live_media_providers -- --ignored --test-threads=1
//! # or: tests/real/live_providers.sh
//! ```
//!
//! Missing keys print `SKIPPED …` and pass. Each case costs one short TTS + one STT request.

use ark_core::Cancel;
use ark_media::stt::SttRequest;
use ark_media::tts::TtsRequest;
use ark_media::{Media, MediaConfig};

const SENTENCE: &str = "The quick brown fox jumps over the lazy dog.";

fn opted_in(what: &str, vars: &[&str]) -> bool {
    if std::env::var("ARK_LIVE_PROVIDERS").ok().as_deref() != Some("1") {
        eprintln!("SKIPPED {what}: set ARK_LIVE_PROVIDERS=1 to call real provider APIs");
        return false;
    }
    let missing: Vec<&str> = vars.iter().copied().filter(|v| std::env::var(v).map(|x| x.trim().is_empty()).unwrap_or(true)).collect();
    if !missing.is_empty() {
        eprintln!("SKIPPED {what}: {} not set", missing.join(", "));
        return false;
    }
    true
}

fn roundtrip(tts: &str, stt: &str) {
    let m = Media { cfg: MediaConfig::from_toml(&format!("[tts]\nprovider = \"{tts}\"\n[stt]\nprovider = \"{stt}\"\n")), http: Default::default() };
    let (id, speech) = ark_media::tts::synthesize(&m, &TtsRequest::new(SENTENCE), &Cancel::new()).unwrap_or_else(|e| panic!("tts {tts}: {e}"));
    assert_eq!(id, tts);
    assert!(speech.audio.bytes.len() > 1000, "{tts}: {} bytes of audio", speech.audio.bytes.len());
    let (sid, t) = ark_media::stt::transcribe(&m, &SttRequest::new(speech.audio.bytes.clone(), &speech.audio.mime), &Cancel::new()).unwrap_or_else(|e| panic!("stt {stt}: {e}"));
    assert_eq!(sid, stt);
    let heard = t.text.to_lowercase();
    assert!(heard.contains("fox") && heard.contains("dog"), "{tts} → {stt}: heard {heard:?}");
    eprintln!("{tts} → {stt}: {heard:?}");
}

#[test]
#[ignore]
fn live_openai_tts_and_whisper() {
    if opted_in("openai", &["OPENAI_API_KEY"]) {
        roundtrip("openai", "openai");
    }
}

#[test]
#[ignore]
fn live_elevenlabs_tts_and_scribe() {
    if opted_in("elevenlabs", &["ELEVENLABS_API_KEY"]) {
        roundtrip("elevenlabs", "elevenlabs");
    }
}

#[test]
#[ignore]
fn live_edge_tts_to_deepgram() {
    // Edge TTS is keyless; Deepgram needs a key.
    if opted_in("edge+deepgram", &["DEEPGRAM_API_KEY"]) {
        roundtrip("edge", "deepgram");
    }
}

#[test]
#[ignore]
fn live_edge_tts_to_groq_whisper() {
    if opted_in("edge+groq", &["GROQ_API_KEY"]) {
        roundtrip("edge", "groq");
    }
}
