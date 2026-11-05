//! On-device TTS engines (Hermes `tts_tool_local.py`): NeuTTS, Piper, KittenTTS. All
//! synthesize WAV in a child process, so the model's memory is released when it exits
//! (Hermes runs NeuTTS the same way; its in-process LRU caches for Piper/KittenTTS
//! have no equivalent across processes).
//!
//! ```toml
//! [media.tts.piper]     command = "piper", voice = "en_US-lessac-medium", voices_dir = "",
//!                       use_cuda = false, speaker_id, length_scale, noise_scale, noise_w_scale, volume, python = "python3"
//! [media.tts.kittentts] model = "KittenML/kitten-tts-nano-0.8-int8", voice = "Jasper", speed, python = "python3"
//! [media.tts.neutts]    model = "neuphonic/neutts-air-q4-gguf", ref_audio, ref_text, device = "cpu", python = "python3"
//! ```

use super::{num, opt, speech, Speech, TtsProvider, TtsRequest};
use crate::proc;
use crate::Media;
use ark_core::Cancel;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Engine {
    NeuTts,
    Piper,
    Kitten,
}

pub struct Local {
    engine: Engine,
}

impl Local {
    pub fn neutts() -> Self {
        Local { engine: Engine::NeuTts }
    }
    pub fn piper() -> Self {
        Local { engine: Engine::Piper }
    }
    pub fn kittentts() -> Self {
        Local { engine: Engine::Kitten }
    }
    fn name(&self) -> &'static str {
        match self.engine {
            Engine::NeuTts => "neutts",
            Engine::Piper => "piper",
            Engine::Kitten => "kittentts",
        }
    }
    fn python(&self, m: &Media) -> String {
        opt(m, self.name(), "python").unwrap_or_else(|| "python3".into())
    }
    /// The interpreter that has `piper` importable: `[media.tts.piper] python`, else the
    /// one beside a venv-installed `piper` command (`…/venv/bin/piper` → `…/bin/python3`).
    fn piper_python(&self, m: &Media) -> String {
        if let Some(p) = opt(m, "piper", "python") {
            return p;
        }
        let cmd = opt(m, "piper", "command").unwrap_or_else(|| "piper".into());
        if let Some(dir) = std::path::Path::new(&cmd).parent().filter(|d| !d.as_os_str().is_empty()) {
            for name in ["python3", "python"] {
                let p = dir.join(name);
                if p.exists() {
                    return p.display().to_string();
                }
            }
        }
        "python3".into()
    }
}

/// piper 1.8 loads `<model>.onnx.json` beside the model; without it the CLI dies with a
/// Python traceback, so ark checks first and names the missing file.
fn piper_config(model: &Path) -> Result<(), String> {
    let cfg = PathBuf::from(format!("{}.json", model.display()));
    if cfg.exists() {
        Ok(())
    } else {
        Err(format!(
            "Piper voice config not found: {} (piper needs <voice>.onnx.json next to the model — download it from https://huggingface.co/rhasspy/piper-voices)",
            cfg.display()
        ))
    }
}

/// Python tracebacks are noise: keep the last real line (the exception) for the error.
fn piper_stderr(o: &proc::Output) -> String {
    let line = o.stderr.lines().rev().map(str::trim_end).find(|l| !l.trim().is_empty() && !l.starts_with(' ') && !l.starts_with("Traceback")).unwrap_or("");
    line.chars().take(400).collect()
}

/// `proc::run` could not even start the command (`ENOENT`): name the fix, keep the path.
fn piper_spawn_error(e: String) -> String {
    if e.starts_with("cannot run") {
        format!("{e} — install Piper (`pip install piper-tts` or `uv tool install piper-tts`) or set [media.tts.piper] command to the binary")
    } else {
        e
    }
}

const KITTEN_SCRIPT: &str = r#"import sys
from kittentts import KittenTTS
import soundfile as sf
model, voice, speed, clean, out = sys.argv[1], sys.argv[2], float(sys.argv[3]), sys.argv[4] == "1", sys.argv[5]
text = sys.stdin.read()
audio = KittenTTS(model).generate(text, voice=voice, speed=speed, clean_text=clean)
sf.write(out, audio, 24000)
"#;

/// Port of Hermes `tools/neutts_synth.py` (reference-voice cloning helper).
const NEUTTS_SCRIPT: &str = r#"import sys, struct
from pathlib import Path
model, device, ref_audio, ref_text_path, out = sys.argv[1:6]
text = sys.stdin.read()
if not Path(ref_audio).expanduser().exists():
    sys.exit(f"Error: reference audio not found: {ref_audio}")
if not Path(ref_text_path).expanduser().exists():
    sys.exit(f"Error: reference text not found: {ref_text_path}")
ref_text = Path(ref_text_path).expanduser().read_text(encoding="utf-8-sig").strip()
try:
    from neutts import NeuTTS
except ImportError:
    sys.exit("Error: neutts not installed (pip install neutts; espeak-ng is also required).")
tts = NeuTTS(backbone_repo=model, backbone_device="gpu" if device == "cuda" else device, codec_repo="neuphonic/neucodec", codec_device=device)
wav = tts.infer(text, tts.encode_reference(str(Path(ref_audio).expanduser())), ref_text)
try:
    import soundfile as sf
    sf.write(out, wav, 24000)
except ImportError:
    import numpy as np
    pcm = (np.clip(np.asarray(wav, dtype=np.float32).flatten(), -1.0, 1.0) * 32767).astype(np.int16)
    with open(out, "wb") as f:
        f.write(b"RIFF" + struct.pack("<I", 36 + len(pcm) * 2) + b"WAVEfmt ")
        f.write(struct.pack("<IHHIIHH", 16, 1, 1, 24000, 48000, 2, 16))
        f.write(b"data" + struct.pack("<I", len(pcm) * 2) + pcm.tobytes())
print(f"OK: {out}", file=sys.stderr)
"#;

impl Local {
    fn tmp() -> Result<PathBuf, String> {
        // Unique per call and owner-only: it holds the synthesized audio (0700).
        crate::store::temp_dir("tts-local")
    }

    /// Piper voice: an existing `.onnx` path or a voice name fetched into `voices_dir`.
    fn piper_model(&self, m: &Media, voice: &str, cancel: &Cancel) -> Result<PathBuf, String> {
        let p = ark_core::tool::expand_home(voice);
        let model_path = p.extension().is_some_and(|e| e.eq_ignore_ascii_case("onnx")) || voice.contains('/');
        if model_path {
            if !p.exists() {
                return Err(format!("Piper voice model not found: {} (point [media.tts.piper] voice at an existing .onnx file, or at a voice name such as en_US-lessac-medium)", p.display()));
            }
            piper_config(&p)?;
            return Ok(p);
        }
        let dir = opt(m, "piper", "voices_dir").map(|d| ark_core::tool::expand_home(&d)).unwrap_or_else(|| ark_core::layout::cache_dir().join("piper-voices"));
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let cached = dir.join(format!("{voice}.onnx"));
        if cached.exists() && dir.join(format!("{voice}.onnx.json")).exists() {
            return Ok(cached);
        }
        let python = self.piper_python(m);
        let argv = vec![python.clone(), "-m".into(), "piper.download_voices".into(), voice.into(), "--download-dir".into(), dir.display().to_string()];
        let o = proc::run(&argv, None, Duration::from_secs(300), cancel).map_err(|e| format!("Piper voice download failed for '{voice}': {e}"))?;
        if !o.success() {
            let err = crate::http::excerpt(o.stderr.trim(), 400);
            if err.contains("No module named 'piper'") || err.contains("No module named \"piper\"") {
                return Err(format!(
                    "Piper voice '{voice}' is not cached in {} and the piper-tts package is missing for `{python}` — install it (`pip install piper-tts`, or `uv tool install piper-tts`), then rerun `{} -m piper.download_voices {voice} --download-dir {}`; or point [media.tts.piper] voice at an existing .onnx file",
                    dir.display(),
                    python,
                    dir.display()
                ));
            }
            return Err(format!("Piper voice download failed for '{voice}': {err}"));
        }
        if !cached.exists() || !dir.join(format!("{voice}.onnx.json")).exists() {
            return Err(format!("Piper voice download completed but {} is missing — check voice name (see: https://github.com/OHF-Voice/piper1-gpl/blob/main/docs/VOICES.md)", cached.display()));
        }
        Ok(cached)
    }
}

/// The per-call temp dir holding the synthesized WAV: removed on every exit path,
/// including the early `?` returns (a failed voice lookup used to leave
/// `ark-tts-local-*` directories behind in `$TMPDIR`).
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<TempDir, String> {
        Local::tmp().map(TempDir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl TtsProvider for Local {
    fn id(&self) -> &str {
        self.name()
    }    fn env(&self) -> &[&str] {
        &[]
    }
    fn configured(&self, m: &Media) -> bool {
        match self.engine {
            Engine::Piper => proc::which(&opt(m, "piper", "command").unwrap_or_else(|| "piper".into())).is_some(),
            _ => opt(m, self.name(), "model").is_some() && proc::which(&self.python(m)).is_some(),
        }
    }
    fn synthesize(&self, m: &Media, req: &TtsRequest, cancel: &Cancel) -> Result<Speech, String> {
        let dir = TempDir::new()?;
        let out = dir.0.join("speech.wav");
        let timeout = Duration::from_secs(num(m, self.name(), "timeout_secs").unwrap_or(120.0) as u64);
        let res = match self.engine {
            Engine::Piper => {
                let voice = req.voice.clone().or_else(|| opt(m, "piper", "voice")).unwrap_or_else(|| "en_US-lessac-medium".into());
                let model = self.piper_model(m, &voice, cancel)?;
                let cmd = opt(m, "piper", "command").unwrap_or_else(|| "piper".into());
                let mut argv = vec![cmd, "--model".into(), model.display().to_string(), "--output_file".into(), out.display().to_string()];
                if super::flag(m, "piper", "use_cuda").unwrap_or(false) {
                    argv.push("--cuda".into());
                }
                if let Some(s) = opt(m, "piper", "speaker_id").and_then(|s| s.parse::<u32>().ok()) {
                    argv.extend(["--speaker".into(), s.to_string()]);
                }
                let mut length = num(m, "piper", "length_scale");
                if length.is_none() {
                    length = super::speed(m, "piper", req).filter(|s| *s > 0.0 && (*s - 1.0).abs() > f64::EPSILON).map(|s| 1.0 / s);
                }
                for (k, v) in [("--length-scale", length), ("--noise-scale", num(m, "piper", "noise_scale")), ("--noise-w-scale", num(m, "piper", "noise_w_scale")), ("--volume", num(m, "piper", "volume"))] {
                    if let Some(v) = v {
                        argv.extend([k.into(), v.to_string()]);
                    }
                }
                proc::run(&argv, Some(req.text.as_bytes()), timeout, cancel).map_err(piper_spawn_error).and_then(|o| {
                    if o.success() {
                        Ok(())
                    } else {
                        Err(format!("Piper synthesis failed ({}): {}", o.code.map(|c| format!("exit {c}")).unwrap_or_else(|| "a signal".into()), piper_stderr(&o)))
                    }
                })
            }
            Engine::Kitten => {
                let model = opt(m, "kittentts", "model").unwrap_or_else(|| "KittenML/kitten-tts-nano-0.8-int8".into());
                let voice = req.voice.clone().or_else(|| opt(m, "kittentts", "voice")).unwrap_or_else(|| "Jasper".into());
                let speed = super::speed(m, "kittentts", req).unwrap_or(1.0);
                let clean = if super::flag(m, "kittentts", "clean_text").unwrap_or(true) { "1" } else { "0" };
                let argv = vec![self.python(m), "-c".into(), KITTEN_SCRIPT.into(), model, voice, speed.to_string(), clean.into(), out.display().to_string()];
                proc::run(&argv, Some(req.text.as_bytes()), timeout, cancel).and_then(|o| o.check("KittenTTS").map(|_| ()))
            }
            Engine::NeuTts => {
                let model = opt(m, "neutts", "model").unwrap_or_else(|| "neuphonic/neutts-air-q4-gguf".into());
                let device = opt(m, "neutts", "device").unwrap_or_else(|| "cpu".into());
                let samples = ark_core::layout::data_dir().join("neutts_samples");
                let ra = opt(m, "neutts", "ref_audio").unwrap_or_else(|| samples.join("jo.wav").display().to_string());
                let rt = opt(m, "neutts", "ref_text").unwrap_or_else(|| samples.join("jo.txt").display().to_string());
                let argv = vec![self.python(m), "-c".into(), NEUTTS_SCRIPT.into(), model, device, ra, rt, out.display().to_string()];
                proc::run(&argv, Some(req.text.as_bytes()), timeout, cancel).and_then(|o| {
                    if o.success() {
                        Ok(())
                    } else {
                        let lines: Vec<&str> = o.stderr.lines().filter(|l| !l.starts_with("OK:")).collect();
                        Err(format!("NeuTTS synthesis failed: {}", if lines.is_empty() { "unknown error".to_string() } else { lines.join("\n") }))
                    }
                })
            }
        };
        let bytes = res.and_then(|_| std::fs::read(&out).map_err(|e| format!("{} produced no output: {e}", self.name())));
        Ok(speech(super::bounded(bytes?, self.name())?, "audio/wav"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fake_engine(dir: &std::path::Path, name: &str, script: &str) -> String {
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p.display().to_string()
    }

    #[test]
    fn piper_cli_arguments_and_stdin() {
        let d = crate::testutil::temp_dir("piper");
        let model = d.join("v.onnx");
        std::fs::write(&model, b"onnx").unwrap();
        // piper 1.8 also needs the voice config beside the model (checked before the run).
        std::fs::write(format!("{}.json", model.display()), b"{}").unwrap();
        // Fake piper: echo argv to a log, copy stdin into the WAV data chunk.
        let log = d.join("args.txt");
        let cmd = fake_engine(&d, "piper", &format!("echo \"$@\" > {}\nwhile [ \"$1\" != \"--output_file\" ]; do shift; done\nprintf 'RIFF\\0\\0\\0\\0WAVE' > \"$2\"\ncat >> \"$2\"", log.display()));
        let m = Media { cfg: crate::MediaConfig::from_toml(&format!("[tts.piper]\ncommand = \"{cmd}\"\nvoice = \"{}\"\nspeaker_id = 2\n[tts]\nspeed = 2.0", model.display())), http: Default::default() };
        let s = Local::piper().synthesize(&m, &TtsRequest::new("hello"), &Cancel::new()).unwrap();
        assert!(s.audio.bytes.ends_with(b"hello"));
        assert_eq!(s.audio.mime, "audio/wav");
        let args = std::fs::read_to_string(&log).unwrap();
        assert!(args.contains("--speaker 2") && args.contains("--length-scale 0.5") && args.contains(&model.display().to_string()), "{args}");
    }

    #[test]
    fn python_engines_report_failures() {
        let d = crate::testutil::temp_dir("pyengine");
        let py = fake_engine(&d, "python3", "echo 'Error: neutts not installed' >&2\nexit 1");
        let m = Media { cfg: crate::MediaConfig::from_toml(&format!("[tts.neutts]\npython = \"{py}\"\n[tts.kittentts]\npython = \"{py}\"")), http: Default::default() };
        let e = Local::neutts().synthesize(&m, &TtsRequest::new("x"), &Cancel::new()).unwrap_err();
        assert!(e.contains("NeuTTS synthesis failed") && e.contains("neutts not installed"), "{e}");
        assert!(Local::kittentts().synthesize(&m, &TtsRequest::new("x"), &Cancel::new()).is_err());
        // A python that writes the output file works end to end.
        let ok = fake_engine(&d, "pyok", "for a; do last=\"$a\"; done\nprintf 'RIFF\\0\\0\\0\\0WAVEdata' > \"$last\"");
        let m = Media { cfg: crate::MediaConfig::from_toml(&format!("[tts.kittentts]\npython = \"{ok}\"")), http: Default::default() };
        assert_eq!(Local::kittentts().synthesize(&m, &TtsRequest::new("x"), &Cancel::new()).unwrap().audio.mime, "audio/wav");
    }
}
