//! Real local speech-to-text integration test: a whisper.cpp build on this machine.
//!
//! Opt in with
//! `ARK_REAL_WHISPER_CPP=/path/to/whisper-cli ARK_REAL_WHISPER_MODELS=/tmp/dir
//!  ARK_REAL_WHISPER_WAV=/path/to/jfk.wav` (see `tests/real/run.sh`, which builds
//! whisper.cpp and fetches its `samples/jfk.wav`). Without them the test is skipped.
//!
//! This exercises ark's *managed* whisper.cpp path (`[media.stt.local] whisper_cpp`
//! with `models_dir`): ark downloads and SHA-256-verifies the ggml model itself, then
//! runs the binary. No cloud provider and no API key is involved.

mod support;

use ark_core::Cancel;
use ark_media::stt::{self, SttRequest};
use ark_media::{Media, MediaConfig};

fn env() -> Option<(String, String, String)> {
    Some((std::env::var("ARK_REAL_WHISPER_CPP").ok()?, std::env::var("ARK_REAL_WHISPER_MODELS").ok()?, std::env::var("ARK_REAL_WHISPER_WAV").ok()?))
}

#[test]
fn transcribes_a_wav_with_a_real_whisper_cpp() {
    let Some((bin, models, wav)) = env() else {
        support::skipped("local whisper.cpp", "ARK_REAL_WHISPER_CPP");
        return;
    };
    let toml = format!(
        "[stt]\nenabled = true\nprovider = \"local_command\"\nlanguage = \"en\"\n[stt.local]\nwhisper_cpp = {bin:?}\nmodels_dir = {models:?}\nmodel = \"base\"\n"
    );
    let m = Media::new(MediaConfig::from_toml(&toml));
    let audio = std::fs::read(&wav).expect("read wav");
    let req = SttRequest::new(audio, "audio/wav");
    let cancel = Cancel::new();
    // First call also downloads + verifies the pinned ggml model, so allow time.
    let (provider, t) = stt::transcribe_with(&m, "local_command", &req, &cancel).expect("transcribe");
    assert_eq!(provider, "local_command", "the local whisper.cpp path, not a cloud provider");
    let text = t.text.to_lowercase();
    assert!(text.contains("ask not what your country can do for you"), "unexpected transcript: {:?}", t.text);
    assert!(t.language.as_deref() == Some("en"), "language: {:?}", t.language);
}

/// A missing binary must fail loudly instead of returning an empty transcript.
#[test]
fn reports_a_missing_whisper_binary() {
    let Some((_bin, models, wav)) = env() else {
        support::skipped("local whisper.cpp error path", "ARK_REAL_WHISPER_CPP");
        return;
    };
    let toml = format!("[stt]\nenabled = true\nprovider = \"local_command\"\n[stt.local]\nwhisper_cpp = \"/nonexistent/whisper-cli\"\nmodels_dir = {models:?}\n");
    let m = Media::new(MediaConfig::from_toml(&toml));
    let audio = std::fs::read(&wav).expect("read wav");
    let e = stt::transcribe_with(&m, "local_command", &SttRequest::new(audio, "audio/wav"), &Cancel::new()).unwrap_err();
    assert!(!e.is_empty(), "an unusable whisper.cpp must produce an error message");
}
