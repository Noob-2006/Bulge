//! End-to-end wiring of the media / desktop CLI surface: every command here goes through the
//! real binary (`build`/`build_agent` → `media_host`), so a green run means the rows are
//! reachable by a user, not just unit-tested.

use std::path::{Path, PathBuf};
use std::process::Command;

fn home(tag: &str) -> PathBuf {
    let d = seagent_core::tmp::scratch_path(format!("seagent-media-cli-{tag}-{}-{}", std::process::id(), line!()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn seagent(h: &Path, args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_seagent"))
        .args(args)
        .env("SEAGENT_HOME", h)
        // Offline by default: no models.dev price download from a fresh SEAGENT_HOME.
        .env("SEAGENT_OFFLINE", "1")
        // Never talk to a real provider from a test.
        .env_remove("OPENAI_API_KEY")
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("XAI_API_KEY")
        .env_remove("GOOGLE_API_KEY")
        .output()
        .expect("run seagent");
    let code = out.status.code().unwrap_or(-1);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (code, text)
}

/// `seagent infer list --json`: the capability catalogue (OpenClaw src/cli/capability-cli).
#[test]
fn infer_lists_every_media_capability() {
    let h = home("infer-list");
    let (code, text) = seagent(&h, &["infer", "list", "--json"]);
    assert_eq!(code, 0, "{text}");
    for id in ["image.generate", "image.edit", "audio.transcribe", "tts.convert", "video.generate", "video.describe", "music.generate"] {
        assert!(text.contains(id), "capability `{id}` missing from `seagent infer list`:\n{text}");
    }
    // `capability` is the documented alias.
    let (code, alias) = seagent(&h, &["capability", "list", "--json"]);
    assert_eq!(code, 0, "{alias}");
    assert!(alias.contains("image.generate"));
}

/// `seagent infer image providers`: the provider/credential table for one domain.
#[test]
fn infer_reports_image_providers_without_a_key() {
    let h = home("infer-providers");
    let (code, text) = seagent(&h, &["infer", "image", "providers", "--json"]);
    assert_eq!(code, 0, "{text}");
    for p in ["fal", "openai", "xai", "google", "openrouter"] {
        assert!(text.contains(p), "provider `{p}` missing:\n{text}");
    }
}

/// `seagent infer tts providers`: the 16 TTS providers, one marked active.
#[test]
fn infer_reports_tts_providers() {
    let h = home("infer-tts");
    let (code, text) = seagent(&h, &["infer", "tts", "providers"]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("edge"), "{text}");
    assert!(text.contains("[active]"), "no active provider marked:\n{text}");
}

/// `seagent voice status`: the voice-mode requirements report (recorder, STT, TTS, wake word).
#[test]
#[cfg(feature = "personal")]
fn voice_status_reports_the_voice_stack() {
    let h = home("voice-status");
    let (code, text) = seagent(&h, &["voice", "status"]);
    assert_eq!(code, 0, "{text}");
    for key in ["\"recorder\"", "\"stt_provider\"", "\"tts_provider\"", "\"wake_word\"", "\"stop_hint\""] {
        assert!(text.contains(key), "`seagent voice status` is missing {key}:\n{text}");
    }
}

/// gen1-306: the default binary carries no voice mode / wake word / GPT-Live, and says how
/// to get them instead of failing obscurely.
#[test]
#[cfg(not(feature = "personal"))]
fn default_build_has_no_voice_mode() {
    let h = home("voice-off");
    for args in [&["voice", "status"][..], &["voice", "live"][..], &["voice"][..]] {
        let (code, text) = seagent(&h, args);
        assert_ne!(code, 0, "{args:?}: {text}");
        assert!(text.contains("--features personal"), "{args:?}: {text}");
    }
}

/// `seagent transcripts list` reads the local transcript store; unknown subcommands fail loudly.
#[test]
fn transcripts_list_and_usage() {
    let h = home("transcripts");
    let (code, text) = seagent(&h, &["transcripts", "list"]);
    assert_eq!(code, 0, "{text}");
    assert!(text.trim().starts_with('['), "expected a JSON array, got:\n{text}");
    let (code, text) = seagent(&h, &["transcripts", "nope"]);
    assert_ne!(code, 0);
    assert!(text.contains("unknown transcripts subcommand"), "{text}");
}

/// `seagent stt` without a file explains itself instead of panicking.
#[test]
fn stt_asks_for_a_file() {
    let h = home("stt");
    let (code, text) = seagent(&h, &["stt"]);
    assert_ne!(code, 0);
    assert!(text.contains("usage: seagent stt"), "{text}");
}

/// `seagent browser`, `seagent screen` and `seagent computer-use` are real subcommands (Hermes
/// `hermes_cli/subcommands/{browser,computer_use,computer_use_screen}.py`). Their exit codes
/// report readiness (Hermes: bare `browser` prints its help and returns 2; a missing desktop
/// or driver is a 1), so only the presence of the documented output is asserted.
#[test]
fn desktop_clis_dispatch() {
    let h = home("desktop-cli");
    let (code, text) = seagent(&h, &["browser"]);
    assert_eq!(code, 2, "Hermes prints the help and returns 2:\n{text}");
    assert!(text.contains("close-profile"), "{text}");
    let (code, text) = seagent(&h, &["screen", "status", "--json"]);
    assert!(code <= 1, "{code}: {text}");
    assert!(text.contains("\"installed\""), "{text}");
    let (code, text) = seagent(&h, &["computer-use", "status"]);
    assert!(code <= 1, "{code}: {text}");
    assert!(text.contains("cua-driver"), "{text}");
    // `computer-use screen …` is the documented alias of `seagent screen`.
    let (code, text) = seagent(&h, &["computer-use", "screen", "status", "--json"]);
    assert!(code <= 1, "{code}: {text}");
    assert!(text.contains("\"installed\""), "{text}");
}
