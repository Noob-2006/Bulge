//! Real local text-to-speech integration test: Piper (piper1-gpl) on this machine.
//!
//! Opt in with
//! `SEAGENT_REAL_PIPER=/path/to/piper SEAGENT_REAL_PIPER_VOICE=/path/to/voice.onnx`
//! (see `tests/real/tts_up.sh`, which installs `piper-tts` + one voice under `$TMPDIR`
//! and prints both). Without them every test here is skipped.
//!
//! This exercises seagent's own piper path — `[media.tts.piper] command` / `voice` /
//! `speaker_id` / `length_scale` — through `tts::synthesize` (the entry point the
//! `text_to_speech` tool uses), not a fake binary. No cloud provider, no API key.
//! Everything it writes stays under the temporary `SEAGENT_HOME` and `$TMPDIR`.

use seagent_core::Cancel;
use seagent_media::tts::{self, TtsRequest};
use seagent_media::{Media, MediaConfig};
use std::path::{Path, PathBuf};

struct Real {
    bin: PathBuf,
    voice: PathBuf,
    /// Throwaway `SEAGENT_HOME`: seagent must not write outside it (and never into the real one).
    home: seagent_core::tmp::TempDir,
}

fn real() -> Option<Real> {
    let bin = std::env::var_os("SEAGENT_REAL_PIPER").map(PathBuf::from)?;
    let voice = std::env::var_os("SEAGENT_REAL_PIPER_VOICE").map(PathBuf::from)?;
    if !bin.exists() || !voice.exists() {
        eprintln!("skipped real piper: SEAGENT_REAL_PIPER={} / SEAGENT_REAL_PIPER_VOICE={} do not exist", bin.display(), voice.display());
        return None;
    }
    // seagent resolves piper voices under `$SEAGENT_HOME/cache/piper-voices`; force a scratch
    // directory so a test can never read or write the real `~/.local/share/seagent`.
    // The house guard removes the tree on drop, also when a test panics.
    let home = seagent_core::tmp::TempDir::new("seagent-real-tts-home");
    std::env::set_var("SEAGENT_HOME", &*home);
    Some(Real { bin, voice, home })
}

/// These tests share one process-global `SEAGENT_HOME`, so they run one at a time.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn skip(what: &str) {
    eprintln!("skipped {what}: set SEAGENT_REAL_PIPER and SEAGENT_REAL_PIPER_VOICE (see tests/real/tts_up.sh)");
}

/// `[media]` config for seagent's piper provider (the section `MediaConfig::from_toml` sees).
fn media(extra: &str) -> std::sync::Arc<Media> {
    Media::new(MediaConfig::from_toml(&format!("[tts]\nprovider = \"piper\"\n{extra}")))
}

fn piper_cfg(bin: &Path, voice: &Path, extra: &str) -> String {
    format!("[tts.piper]\ncommand = {:?}\nvoice = {:?}\n{extra}", bin.display().to_string(), voice.display().to_string())
}

/// A parsed 16-bit PCM WAV.
struct Wav {
    rate: u32,
    channels: u16,
    samples: Vec<i16>,
}

impl Wav {
    fn parse(b: &[u8]) -> Wav {
        assert!(b.len() > 44, "not a WAV: {} bytes", b.len());
        assert_eq!(&b[0..4], b"RIFF", "missing RIFF header");
        assert_eq!(&b[8..12], b"WAVE", "missing WAVE tag");
        let riff_len = u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize;
        assert_eq!(riff_len + 8, b.len(), "RIFF length field disagrees with the file size");
        let (mut rate, mut channels, mut bits, mut samples) = (0u32, 0u16, 0u16, Vec::new());
        let mut i = 12;
        while i + 8 <= b.len() {
            let id = &b[i..i + 4];
            let len = u32::from_le_bytes(b[i + 4..i + 8].try_into().unwrap()) as usize;
            let body = &b[i + 8..(i + 8 + len).min(b.len())];
            match id {
                b"fmt " => {
                    assert_eq!(u16::from_le_bytes(body[0..2].try_into().unwrap()), 1, "not PCM");
                    channels = u16::from_le_bytes(body[2..4].try_into().unwrap());
                    rate = u32::from_le_bytes(body[4..8].try_into().unwrap());
                    bits = u16::from_le_bytes(body[14..16].try_into().unwrap());
                }
                b"data" => samples = body.as_chunks::<2>().0.iter().map(|c| i16::from_le_bytes(*c)).collect(),
                _ => {}
            }
            i += 8 + len + (len & 1);
        }
        assert_eq!(bits, 16, "expected 16-bit samples");
        assert!(!samples.is_empty(), "empty data chunk");
        Wav { rate, channels, samples }
    }

    fn seconds(&self) -> f64 {
        self.samples.len() as f64 / (self.rate as f64 * self.channels as f64)
    }

    /// Root-mean-square of the PCM samples (0…32767); the test's "not silent" measure.
    fn rms(&self) -> f64 {
        let sum: f64 = self.samples.iter().map(|s| (*s as f64) * (*s as f64)).sum();
        (sum / self.samples.len() as f64).sqrt()
    }

    fn peak(&self) -> i16 {
        self.samples.iter().map(|s| s.abs()).max().unwrap_or(0)
    }

    /// Duration of the part above the silence floor (leading/trailing pauses excluded).
    fn voiced_seconds(&self) -> f64 {
        let loud = |s: &i16| s.unsigned_abs() > 200;
        let start = self.samples.iter().position(loud).unwrap_or(0);
        let end = self.samples.iter().rposition(loud).map(|i| i + 1).unwrap_or(0);
        (end - start) as f64 / (self.rate as f64 * self.channels as f64)
    }
}

/// Sample rate declared by the voice's `.onnx.json` (piper's own config).
fn voice_sample_rate(voice: &Path) -> u32 {
    let cfg = std::fs::read_to_string(format!("{}.json", voice.display())).expect("read voice json");
    let v: serde_json::Value = serde_json::from_str(&cfg).expect("parse voice json");
    v["audio"]["sample_rate"].as_u64().expect("audio.sample_rate") as u32
}

fn synth(m: &Media, text: &str) -> (String, Wav) {
    let (id, speech) = tts::synthesize(m, &TtsRequest::new(text), &Cancel::new()).expect("synthesize");
    assert_eq!(speech.audio.mime, "audio/wav", "piper returns a WAV");
    (id, Wav::parse(&speech.audio.bytes))
}

const SENTENCE: &str = "The quick brown fox jumps over the lazy dog.";

fn tmp(tag: &str) -> PathBuf {
    let d = seagent_core::tmp::scratch_path(format!("seagent-real-tts-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

/// A real run produces a valid RIFF/WAVE at the voice's rate, for as long as the text
/// warrants, with audible (non-silent) samples.
#[test]
fn piper_writes_a_valid_wav() {
    let Some(r) = real() else {
        skip("real piper WAV");
        return;
    };
    let _serial = serial();
    let m = media(&piper_cfg(&r.bin, &r.voice, ""));
    let (id, short) = synth(&m, SENTENCE);
    assert_eq!((id.as_str(), short.channels), ("piper", 1), "mono WAV from the piper provider");
    let rate = voice_sample_rate(&r.voice);
    assert_eq!(short.rate, rate, "sample rate must match the voice config");
    assert_eq!(rate, 22050, "en_US-lessac-medium is a 22.05 kHz voice");
    // ~0.06 s per character for this voice: a plausible duration, not a stub.
    let per_char = short.seconds() / SENTENCE.len() as f64;
    assert!((0.02..0.2).contains(&per_char), "implausible {per_char:.3} s/char ({:.2} s)", short.seconds());
    eprintln!("piper wav: {} Hz, {:.2}s, RMS {:.0}, peak {}", short.rate, short.seconds(), short.rms(), short.peak());
    // Real speech: a healthy RMS, not silence and not a single click.
    assert!(short.rms() > 500.0, "RMS {:.0} too low — silent audio", short.rms());
    assert!(short.peak() > 3000, "peak {} too low", short.peak());

    // Duration grows with the amount of text (3× the words ≈ 3× the audio).
    let (_, long) = synth(&m, &format!("{SENTENCE} {SENTENCE} {SENTENCE}"));
    let ratio = long.voiced_seconds() / short.voiced_seconds();
    assert!((2.4..3.6).contains(&ratio), "3× text gave {ratio:.2}× audio ({:.2}s vs {:.2}s)", long.voiced_seconds(), short.voiced_seconds());
    assert_eq!(long.rate, rate);
}

/// `length_scale` and `speaker_id` must reach the binary, not just the config.
#[test]
fn length_scale_and_speaker_id_reach_piper() {
    let Some(r) = real() else {
        skip("real piper knobs");
        return;
    };
    // A wrapper that records the argv seagent builds, then runs the real engine.
    let _serial = serial();
    let dir = tmp("wrap");
    let log = dir.join("argv.txt");
    let wrapper = dir.join("piper");
    std::fs::write(&wrapper, format!("#!/bin/sh\nprintf '%s\\n' \"$@\" >> {:?}\nexec {:?} \"$@\"\n", log.display().to_string(), r.bin.display().to_string())).expect("write wrapper");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    let normal = media(&piper_cfg(&wrapper, &r.voice, "speaker_id = 0\nlength_scale = 1.0\n"));
    let slow = media(&piper_cfg(&wrapper, &r.voice, "speaker_id = 0\nlength_scale = 2.0\n"));
    let (_, a) = synth(&normal, SENTENCE);
    let (_, b) = synth(&slow, SENTENCE);
    let argv = std::fs::read_to_string(&log).expect("argv log");
    let lines: Vec<&str> = argv.lines().collect();
    let voice = r.voice.display().to_string();
    assert!(lines.contains(&"--model") && lines.contains(&voice.as_str()), "voice path not passed: {argv}");
    assert!(lines.contains(&"--speaker") && lines.contains(&"0"), "speaker_id not passed: {argv}");
    assert!(lines.contains(&"--length-scale") && lines.contains(&"1") && lines.contains(&"2"), "length_scale not passed: {argv}");
    // length_scale is not perfectly linear in piper 1.8 (per-phoneme duration floor plus
    // its stochastic duration predictor), but 2.0 must clearly lengthen the audio.
    let ratio = b.voiced_seconds() / a.voiced_seconds();
    assert!((1.5..2.3).contains(&ratio), "length_scale 2.0 gave {ratio:.2}× the audio");
    assert_eq!(a.rate, b.rate);

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&*r.home);
}

/// A voice *name* resolves to `$SEAGENT_HOME/cache/piper-voices/<name>.onnx` and really
/// synthesizes with it (the default location `piper_model` uses).
#[test]
fn voice_name_resolves_from_the_seagent_home_cache() {
    let Some(r) = real() else {
        skip("real piper voice-name cache");
        return;
    };
    let _serial = serial();
    let Some(name) = r.voice.file_stem().and_then(|n| n.to_str()).map(str::to_string) else {
        eprintln!("skipped voice-name cache: unexpected voice file name");
        return;
    };
    let cache = r.home.join("cache").join("piper-voices");
    std::fs::create_dir_all(&cache).expect("cache dir");
    // Hard links: same bytes as the downloaded voice, no extra copy.
    std::fs::hard_link(&r.voice, cache.join(format!("{name}.onnx"))).expect("link model");
    std::fs::hard_link(PathBuf::from(format!("{}.json", r.voice.display())), cache.join(format!("{name}.onnx.json"))).expect("link config");

    let m = media(&format!("[tts.piper]\ncommand = {:?}\nvoice = \"{name}\"\n", r.bin.display().to_string()));
    let (id, w) = synth(&m, SENTENCE);
    assert_eq!(id, "piper");
    assert_eq!(w.rate, voice_sample_rate(&r.voice));
    assert!(w.rms() > 500.0, "cached voice produced silence (RMS {:.0})", w.rms());
    let _ = std::fs::remove_dir_all(&*r.home);
}

/// The voice-name download path uses an interpreter that really has `piper`: for a venv
/// install of the CLI that is `<venv>/bin/python3`, not the system `python3`.
/// Downloads ~63 MiB, so it is opt-in.
#[test]
fn voice_name_downloads_with_the_venv_python() {
    let Some(r) = real() else {
        skip("real piper voice download");
        return;
    };
    let _serial = serial();
    let venv_py = r.bin.parent().map(|d| d.join("python3"));
    if !venv_py.as_ref().is_some_and(|p| p.exists()) {
        eprintln!("skipped voice download: {} is not a venv install (no python3 beside it)", r.bin.display());
        return;
    }
    if std::env::var_os("SEAGENT_REAL_PIPER_ALLOW_DOWNLOAD").is_none() {
        eprintln!("skipped voice download: set SEAGENT_REAL_PIPER_ALLOW_DOWNLOAD=1 (downloads ~63 MB)");
        return;
    }
    let Some(name) = r.voice.file_stem().and_then(|n| n.to_str()).map(str::to_string) else {
        eprintln!("skipped voice download: unexpected voice file name");
        return;
    };
    let dir = tmp("voices");
    // No `python`: seagent must find the venv's own interpreter beside the command.
    let m = media(&format!(
        "[tts.piper]\ncommand = {:?}\nvoice = \"{name}\"\nvoices_dir = {:?}\n",
        r.bin.display().to_string(),
        dir.display().to_string()
    ));
    let (id, w) = synth(&m, "Downloaded voice.");
    assert_eq!(id, "piper");
    assert!(dir.join(format!("{name}.onnx")).exists() && dir.join(format!("{name}.onnx.json")).exists(), "voice not downloaded into {}", dir.display());
    assert!(w.rms() > 500.0, "downloaded voice produced silence");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&*r.home);
}

/// A missing binary, model or model config is a clear error naming the path — never a
/// panic and never a truncated file.
#[test]
fn missing_piper_or_voice_is_reported() {
    let Some(r) = real() else {
        skip("real piper error paths");
        return;
    };
    let _serial = serial();
    let fail = |cfg: &str| -> String {
        let m = media(cfg);
        let e = tts::synthesize(&m, &TtsRequest::new("hello"), &Cancel::new()).expect_err("must fail");
        assert!(!e.trim().is_empty(), "an unusable piper must explain itself");
        e
    };
    // 1. missing executable
    let e = fail(&format!("[tts.piper]\ncommand = \"/nonexistent/piper-cli\"\nvoice = {:?}\n", r.voice.display().to_string()));
    assert!(e.contains("/nonexistent/piper-cli"), "the binary path must be in the error: {e}");
    // 2. missing voice model
    let e = fail(&format!("[tts.piper]\ncommand = {:?}\nvoice = \"/nonexistent/voice.onnx\"\n", r.bin.display().to_string()));
    assert!(e.contains("/nonexistent/voice.onnx"), "the voice path must be in the error: {e}");
    // 3. a model whose `.onnx.json` is missing (piper needs it next to the model)
    let orphan = tmp("orphan");
    let model = orphan.join("voice.onnx");
    std::fs::copy(&r.voice, &model).expect("copy model");
    let e = fail(&format!("[tts.piper]\ncommand = {:?}\nvoice = {:?}\n", r.bin.display().to_string(), model.display().to_string()));
    assert!(e.contains("voice.onnx.json"), "the missing .onnx.json must be named: {e}");
    let leaked: Vec<PathBuf> = std::fs::read_dir(&orphan).unwrap().flatten().map(|f| f.path()).filter(|p| p.extension().is_some_and(|x| x == "wav")).collect();
    assert!(leaked.is_empty(), "no WAV may survive a failure: {leaked:?}");
    let _ = std::fs::remove_dir_all(&orphan);
    let _ = std::fs::remove_dir_all(&*r.home);
}

/// A voice *name* that is not cached needs the `piper-tts` Python package; when that is
/// absent the error must say what to install instead of surfacing a bare traceback.
#[test]
fn voice_download_without_the_piper_package_explains_the_install() {
    let Some(r) = real() else {
        skip("real piper voice download");
        return;
    };
    // Only meaningful when the configured python really lacks piper (the normal state of
    // a system python); otherwise the download would simply work.
    let _serial = serial();
    let py = "python3";
    let has = std::process::Command::new(py).args(["-c", "import piper"]).output().map(|o| o.status.success()).unwrap_or(false);
    if has {
        eprintln!("skipped voice-download error: {py} already has piper installed");
        return;
    }
    let cfg = format!(
        "[tts.piper]\ncommand = {:?}\npython = \"{py}\"\nvoice = \"en_US-does-not-exist-medium\"\nvoices_dir = {:?}\n",
        r.bin.display().to_string(),
        r.home.join("cache/piper-voices").display().to_string()
    );
    let m = media(&cfg);
    let e = tts::synthesize(&m, &TtsRequest::new("hello"), &Cancel::new()).expect_err("unknown voice");
    assert!(e.contains("en_US-does-not-exist-medium"), "voice name in the error: {e}");
    assert!(e.contains("piper-tts"), "the error must name the package to install: {e}");
    let _ = std::fs::remove_dir_all(&*r.home);
}

/// The temporary WAV seagent writes is removed, and nothing lands outside `SEAGENT_HOME`/`$TMPDIR`.
#[test]
fn temp_wav_is_removed_after_synthesis() {
    let Some(r) = real() else {
        skip("real piper temp cleanup");
        return;
    };
    let _serial = serial();
    let leaked = || -> Vec<PathBuf> {
        std::fs::read_dir(seagent_core::tmp::scratch("seagent-ws"))
            .map(|d| {
                d.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("seagent-tts-local-")))
                    .collect()
            })
            .unwrap_or_default()
    };
    let before = leaked().len();
    let m = media(&piper_cfg(&r.bin, &r.voice, ""));
    let _ = synth(&m, SENTENCE);
    // A failed lookup must not leak its temp dir either (the early `?` used to).
    let bad = media(&format!("[tts.piper]\ncommand = {:?}\nvoice = \"/nonexistent/voice.onnx\"\n", r.bin.display().to_string()));
    assert!(tts::synthesize(&bad, &TtsRequest::new("hi"), &Cancel::new()).is_err());
    let after = leaked();
    assert_eq!(after.len(), before, "seagent left a tts-local temp dir behind: {after:?}");
    // An explicit `.onnx` voice never touches the voice cache, so SEAGENT_HOME stays empty.
    let wrote: Vec<String> = std::fs::read_dir(&*r.home).map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
    assert!(wrote.is_empty(), "the test wrote outside its temp scope: {wrote:?}");
    let _ = std::fs::remove_dir_all(&*r.home);
}
