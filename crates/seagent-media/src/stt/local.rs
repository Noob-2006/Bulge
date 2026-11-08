//! Local speech-to-text (Hermes `tools/transcription_local.py`,
//! `tools/transcription_whisper_cpp.py`).
//!
//! - `local`: faster-whisper, run in a Python child process (the library is Python);
//!   same anti-hallucination kwargs (Silero VAD, `condition_on_previous_text=False`,
//!   confidence gate), cache-first model load and CUDA → CPU fallback as Hermes.
//! - `local_command`: a whisper CLI template — `[media.stt.local] command` /
//!   `SEAGENT_LOCAL_STT_COMMAND`, else a managed whisper.cpp (`whisper-cli` + verified
//!   ggml models under `$SEAGENT_HOME/cache/whisper.cpp`), else the `whisper` CLI.
//!
//! ```toml
//! [media.stt.local]
//! model = "base"            # tiny | base | small | medium | large-v3 | turbo
//! language = ""             # forced language ("" = config stt.language, else "en" for CLI)
//! python = "python3"        # interpreter that has faster_whisper installed
//! device = "auto"           # faster-whisper device / compute_type
//! compute_type = "auto"
//! vad = true                # Silero VAD; false for music/ambient audio
//! vad_min_silence_ms = 500
//! no_speech_prob_threshold = 0.6
//! logprob_threshold = -1.0
//! initial_prompt = ""
//! command = ""              # whisper CLI template: {input_path} {output_dir} {language} {model}
//! whisper_cpp = ""          # whisper.cpp binary (default: whisper-cli / whisper-cpp on PATH)
//! models_dir = ""           # default $SEAGENT_HOME/cache/whisper.cpp
//! ```

use super::{section_str, SttProvider, SttRequest, Transcript};
use crate::proc;
use crate::Media;
use seagent_core::Cancel;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

pub const LOCAL_MODELS: &[&str] = &["base", "tiny", "small", "medium", "large-v3", "turbo"];
pub const DEFAULT_LOCAL_MODEL: &str = "base";
pub const DEFAULT_LOCAL_LANGUAGE: &str = "en";

/// A valid faster-whisper size: cloud-only names (`whisper-1`, Groq models) fall back to `base`.
pub fn normalize_model(name: Option<&str>) -> String {
    match name.map(str::trim).filter(|s| !s.is_empty()) {
        None => DEFAULT_LOCAL_MODEL.into(),
        Some(n) if super::cloud::OPENAI_MODELS.contains(&n) || super::cloud::GROQ_MODELS.contains(&n) || super::cloud::RETIRED_GROQ_MODELS.contains(&n) => DEFAULT_LOCAL_MODEL.into(),
        Some(n) => n.to_string(),
    }
}

/// A Whisper language code, or `None` (Hermes `_normalize_local_stt_language`).
pub fn normalize_language(lang: Option<&str>) -> Option<String> {
    let raw = lang?.trim();
    if raw.is_empty() {
        return None;
    }
    let cand = match raw {
        "繁體中文" | "繁体中文" | "简体中文" | "簡體中文" => "zh".to_string(),
        _ => raw.to_lowercase().replace('_', "-").split('-').next().unwrap_or("").to_string(),
    };
    let shape = cand.chars().count() == 2 || cand == "haw" || cand == "yue";
    (cand.chars().all(|c| c.is_ascii_alphabetic()) && shape).then_some(cand)
}

fn local_str(m: &Media, k: &str) -> Option<String> {
    section_str(m, "local", k)
}

fn local_num(m: &Media, k: &str, d: f64) -> f64 {
    m.cfg.get(&format!("stt.local.{k}")).and_then(|v| v.as_float().or_else(|| v.as_integer().map(|i| i as f64)).or_else(|| v.as_str().and_then(|s| s.parse().ok()))).unwrap_or(d)
}

/// Write the request audio as 16 kHz mono WAV for local engines (WAV/AIFF pass through
/// Hermes `_prepare_local_audio`; anything else is decoded via ffmpeg).
pub(crate) fn prepare_wav(req: &SttRequest, dir: &Path, cancel: &Cancel) -> Result<PathBuf, String> {
    let p = dir.join("input.wav");
    if crate::audio::wav_decode(&req.audio).is_ok() {
        std::fs::write(&p, &req.audio).map_err(|e| e.to_string())?;
        return Ok(p);
    }
    let pcm = crate::audio::decode_to_pcm(&req.audio, &req.mime, 16000, cancel).map_err(|e| format!("audio needs converting for local STT: {e}"))?;
    std::fs::write(&p, crate::audio::wav_encode(&pcm, 16000, 1)).map_err(|e| e.to_string())?;
    Ok(p)
}

pub(crate) fn work_dir(tag: &str) -> Result<PathBuf, String> {
    // Unique per call (Hermes uses `tempfile.TemporaryDirectory`) and owner-only: a
    // millisecond stamp alone collides for two providers starting in the same millisecond,
    // and one caller's cleanup would then delete the other's raw audio.
    crate::store::temp_dir(&format!("stt-{tag}"))
}

// ───────────── faster-whisper ─────────────

/// The child program: load (cache first, Hub on a miss, CUDA → CPU int8 on a missing
/// CUDA runtime), transcribe with the hardened kwargs, drop hallucinated segments,
/// print one JSON object.
const FASTER_WHISPER_PY: &str = r#"
import json, os, platform, subprocess, sys
a = json.loads(sys.argv[1])
MARKERS = ("libcublas", "libcudnn", "libcudart", "cannot be loaded", "cannot open shared object",
           "no kernel image is available", "CUBLAS_STATUS_NOT_SUPPORTED", "no CUDA-capable device",
           "CUDA driver version is insufficient")
def cuda_err(e): return any(m in str(e) for m in MARKERS)
def sysctl(name):
    try:
        return subprocess.check_output(["/usr/sbin/sysctl", "-n", name], stderr=subprocess.DEVNULL,
                                       stdin=subprocess.DEVNULL, text=True, timeout=2).strip()
    except Exception:
        return ""
def force_cpu():
    # Apple Silicon (also x86_64 under Rosetta, where machine() reports x86_64): ctranslate2's
    # device="auto" can abort inside native code before Python can catch it.
    if platform.system() != "Darwin": return False
    if platform.machine().lower() in ("arm64", "aarch64"): return True
    return sysctl("sysctl.proc_translated") == "1" or sysctl("hw.optional.arm64") == "1"
device, ct = a["device"], a["compute_type"]
if force_cpu():
    # Set before the ctranslate2 import: multiple Intel OpenMP runtimes abort otherwise.
    os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE"); device, ct = "cpu", "int8"
from faster_whisper import WhisperModel
def create(device, ct):
    # Catch only what a cache miss raises (OSError/LocalEntryNotFoundError, RuntimeError); a CUDA
    # runtime error or an invalid model size is not a download problem and propagates untouched.
    try:
        return WhisperModel(a["model"], device=device, compute_type=ct, local_files_only=True)
    except (OSError, RuntimeError) as e:
        if isinstance(e, RuntimeError) and "Unable to open file" not in str(e): raise
    try:
        return WhisperModel(a["model"], device=device, compute_type=ct, local_files_only=False)
    except OSError as e:
        raise RuntimeError("Unable to download faster-whisper model '%s': %s. If huggingface.co is unreachable, set HF_ENDPOINT to an accessible mirror; when using a mirror with hf-xet installed, also set HF_HUB_DISABLE_XET=1." % (a["model"], e))
try:
    model = create(device, ct)
except Exception as e:
    if not cuda_err(e): raise
    model = create("cpu", "int8")
kw = a["kwargs"]
lang = kw.get("language")
sup = getattr(model, "supported_languages", None)
if lang and isinstance(sup, (list, tuple, set, frozenset)) and lang not in {str(x).casefold() for x in sup}:
    kw.pop("language", None)
try:
    segs, info = model.transcribe(a["path"], **kw); segs = list(segs)
except Exception as e:
    if not cuda_err(e): raise
    model = create("cpu", "int8"); segs, info = model.transcribe(a["path"], **kw); segs = list(segs)
ns, lp = a["no_speech"], a["logprob"]
out = []
for s in segs:
    try: bad = float(s.no_speech_prob) > ns and float(s.avg_logprob) < lp
    except Exception: bad = False
    if not bad: out.append({"start": s.start, "end": s.end, "text": s.text.strip()})
print(json.dumps({"text": " ".join(x["text"] for x in out).strip(), "language": getattr(info, "language", None),
                  "duration": getattr(info, "duration", None), "segments": out}))
"#;

pub struct FasterWhisper;

/// The child program text (test-only: the helper can't run without faster-whisper).
#[cfg(all(test, unix))]
pub(crate) fn helper_script() -> &'static str {
    FASTER_WHISPER_PY
}

fn python(m: &Media) -> String {
    local_str(m, "python").or_else(|| std::env::var("SEAGENT_STT_PYTHON").ok().filter(|s| !s.is_empty())).unwrap_or_else(|| "python3".into())
}

/// Whether `python` can import faster_whisper (cached per interpreter; never installs).
pub fn faster_whisper_available(m: &Media) -> bool {
    static CACHE: OnceLock<Mutex<Vec<(String, bool)>>> = OnceLock::new();
    let py = python(m);
    let c = CACHE.get_or_init(Default::default);
    if let Some((_, ok)) = c.lock().unwrap().iter().find(|(p, _)| *p == py) {
        return *ok;
    }
    let ok = proc::which(&py).is_some() && proc::run(&[py.clone(), "-c".into(), "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('faster_whisper') else 1)".into()], None, Duration::from_secs(20), &Cancel::new()).map(|o| o.success()).unwrap_or(false);
    c.lock().unwrap().push((py, ok));
    ok
}

/// Hermes `build_local_transcribe_kwargs`.
pub fn transcribe_kwargs(m: &Media, req: &SttRequest) -> Value {
    let vad = m.cfg.get("stt.local.vad").and_then(|v| v.as_bool()).unwrap_or(true);
    let mut kw = json!({"beam_size": 5, "condition_on_previous_text": false, "vad_filter": vad,
        "no_speech_threshold": local_num(m, "no_speech_prob_threshold", 0.6), "log_prob_threshold": local_num(m, "logprob_threshold", -1.0)});
    if vad {
        kw["vad_parameters"] = json!({"min_silence_duration_ms": local_num(m, "vad_min_silence_ms", 500.0) as i64});
    }
    let lang = req.language.clone().or_else(|| super::configured_language(m, "local"));
    if let Some(l) = normalize_language(lang.as_deref()) {
        kw["language"] = json!(l);
    }
    if let Some(p) = req.prompt.clone().or_else(|| local_str(m, "initial_prompt")) {
        kw["initial_prompt"] = json!(p);
    }
    kw
}

impl SttProvider for FasterWhisper {
    fn id(&self) -> &str {
        "local"
    }
    fn env(&self) -> &[&str] {
        &[]
    }
    fn local(&self) -> bool {
        true
    }
    fn available(&self, m: &Media) -> bool {
        faster_whisper_available(m)
    }
    fn transcribe(&self, m: &Media, req: &SttRequest, cancel: &Cancel) -> Result<Transcript, String> {
        if !faster_whisper_available(m) {
            return Err(format!("faster-whisper not installed (pip install faster-whisper for `{}`)", python(m)));
        }
        let dir = work_dir("fw")?;
        let r = (|| {
            let wav = prepare_wav(req, &dir, cancel)?;
            let model = normalize_model(req.model.as_deref().or(local_str(m, "model").as_deref()));
            let args = json!({"path": wav.display().to_string(), "model": model, "device": local_str(m, "device").unwrap_or_else(|| "auto".into()),
                "compute_type": local_str(m, "compute_type").unwrap_or_else(|| "auto".into()), "kwargs": transcribe_kwargs(m, req),
                "no_speech": local_num(m, "no_speech_prob_threshold", 0.6), "logprob": local_num(m, "logprob_threshold", -1.0)});
            let argv = vec![python(m), "-c".into(), FASTER_WHISPER_PY.into(), args.to_string()];
            let o = proc::run(&argv, None, Duration::from_secs(local_num(m, "timeout_secs", 900.0) as u64), cancel)?;
            if !o.success() {
                let tail = o.stderr.trim().lines().last().unwrap_or("").to_string();
                return Err(format!("Local transcription failed: {tail}"));
            }
            let v: Value = serde_json::from_slice(&o.stdout).map_err(|e| format!("Local transcription failed: bad helper output: {e}"))?;
            let segments = v["segments"].as_array().map(|a| a.iter().map(|s| super::Segment { start: s["start"].as_f64().unwrap_or(0.0), end: s["end"].as_f64().unwrap_or(0.0), text: s["text"].as_str().unwrap_or("").into(), speaker: None }).collect()).unwrap_or_default();
            Ok(Transcript { text: v["text"].as_str().unwrap_or("").trim().into(), language: v["language"].as_str().map(str::to_string), duration: v["duration"].as_f64(), segments })
        })();
        let _ = std::fs::remove_dir_all(&dir);
        r
    }
}

// ───────────── whisper.cpp (managed) ─────────────

/// `(file name, pinned URL, sha256)` — Hermes `_MODEL_FILES`.
pub const WHISPER_CPP_MODELS: &[(&str, &str, &str)] = &[
    ("ggml-base.bin", "https://huggingface.co/ggerganov/whisper.cpp/resolve/5359861c739e955e79d9a303bcbc70fb988958b1/ggml-base.bin", "60ed5bc3dd14eea856493d334349b405782ddcaf0028d4b5df4088345fba2efe"),
    ("ggml-silero-v6.2.0.bin", "https://huggingface.co/ggml-org/whisper-vad/resolve/9ffd54a1e1ee413ddf265af9913beaf518d1639b/ggml-silero-v6.2.0.bin", "2aa269b785eeb53a82983a20501ddf7c1d9c48e33ab63a41391ac6c9f7fb6987"),
];

/// `[(name, url, sha256); 2]` = (speech model, VAD model): the pinned base + Silero
/// files, or `[media.stt.local] whisper_cpp_model` / `whisper_cpp_vad` tables
/// (`{ name, url, sha256 }`) for another verified model.
pub fn whisper_cpp_models(m: &Media) -> Vec<(String, String, String)> {
    let pick = |key: &str, d: (&str, &str, &str)| {
        let t = m.cfg.table(&format!("stt.local.{key}"));
        let g = |k: &str| t.get(k).and_then(|v| v.as_str()).map(str::to_string);
        match (g("name"), g("url"), g("sha256")) {
            (Some(n), Some(u), Some(h)) => (n, u, h.to_ascii_lowercase()),
            _ => (d.0.to_string(), d.1.to_string(), d.2.to_string()),
        }
    };
    vec![pick("whisper_cpp_model", WHISPER_CPP_MODELS[0]), pick("whisper_cpp_vad", WHISPER_CPP_MODELS[1])]
}

pub fn whisper_cpp_dir(m: &Media) -> PathBuf {
    local_str(m, "models_dir").map(|d| seagent_core::tool::expand_home(&d)).unwrap_or_else(|| seagent_core::layout::cache_dir().join("whisper.cpp"))
}

pub fn whisper_cpp_binary(m: &Media) -> Option<PathBuf> {
    match local_str(m, "whisper_cpp") {
        Some(b) => proc::which(&b),
        None => proc::which_any(&["whisper-cli", "whisper-cpp", "whisper.cpp"]),
    }
}

/// The managed whisper.cpp command template (Hermes `whisper_cpp_command`).
///
/// The VAD flags (`--vad -vm … -vsd`) are added only when this whisper.cpp build
/// advertises them: a 1.7.4 build made without VAD answers `error: unknown
/// argument: --vad`, exits non-zero and writes no transcript at all (found by the
/// real-whisper.cpp test, `crates/seagent-channel/tests/real_media.rs`).
pub fn whisper_cpp_command(m: &Media) -> Option<String> {
    let bin = whisper_cpp_binary(m)?;
    let d = whisper_cpp_dir(m);
    let files = whisper_cpp_models(m);
    let q = |p: &Path| proc::shell_quote(&p.display().to_string());
    let vad = if whisper_cpp_supports_vad(&bin) { format!(" --vad -vm {} -vsd 500", q(&d.join(&files[1].0))) } else { String::new() };
    Some(format!(
        "{} -m {} -f {{input_path}} -l {{language}} -t 4 -bs 5 -bo 5 -ng -nt -otxt -of {{output_dir}}/transcript{}",
        q(&bin),
        q(&d.join(&files[0].0)),
        vad
    ))
}

/// `whisper-cli --help` mentions `--vad`? Cached per binary path (one extra process
/// on first use, never on the transcription path itself).
fn whisper_cpp_supports_vad(bin: &Path) -> bool {
    static CACHE: OnceLock<Mutex<Vec<(PathBuf, bool)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(Vec::new()));
    if let Some((_, ok)) = cache.lock().unwrap().iter().find(|(p, _)| p == bin) {
        return *ok;
    }
    let ok = proc::run(&[bin.display().to_string(), "--help".into()], None, Duration::from_secs(10), &Cancel::new())
        .map(|o| format!("{}{}", String::from_utf8_lossy(&o.stdout), o.stderr).contains("--vad"))
        .unwrap_or(false);
    cache.lock().unwrap().push((bin.to_path_buf(), ok));
    ok
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Download + SHA-256-verify the base and VAD models on first use; verified files are
/// remembered by `(path, size, mtime)` so a replaced file is checked again.
pub fn ensure_whisper_cpp_models(m: &Media, model: &str, cancel: &Cancel) -> Result<(), String> {
    let custom = !m.cfg.table("stt.local.whisper_cpp_model").is_empty();
    if model != "base" && !custom {
        return Err(format!("managed whisper.cpp supports stt.local.model = \"base\"; requested {model:?} (set [media.stt.local] command for other models)"));
    }
    static VERIFIED: OnceLock<Mutex<Vec<(PathBuf, u64, std::time::SystemTime)>>> = OnceLock::new();
    let verified = VERIFIED.get_or_init(Default::default);
    let dir = whisper_cpp_dir(m);
    for (name, url, digest) in whisper_cpp_models(m) {
        let (name, url, digest) = (name.as_str(), url.as_str(), digest.as_str());
        let dest = dir.join(name);
        let sig = std::fs::metadata(&dest).ok().map(|md| (dest.clone(), md.len(), md.modified().unwrap_or(std::time::UNIX_EPOCH)));
        if let Some(s) = &sig {
            if verified.lock().unwrap().contains(s) {
                continue;
            }
            if hex(&seagent_net::crypto::sha256(&std::fs::read(&dest).unwrap_or_default())) == digest {
                verified.lock().unwrap().push(s.clone());
                continue;
            }
        }
        if cancel.is_cancelled() {
            return Err("cancelled".into());
        }
        let (bytes, _) = m.download(url, &[]).map_err(|e| format!("whisper.cpp model download failed ({name}): {e}"))?;
        let got = hex(&seagent_net::crypto::sha256(&bytes));
        if got != digest {
            return Err(format!("whisper.cpp model {name} failed SHA-256 verification (expected {digest}, got {got})"));
        }
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let part = dir.join(format!("{name}.partial"));
        std::fs::write(&part, &bytes).and_then(|_| std::fs::rename(&part, &dest)).map_err(|e| e.to_string())?;
        if let Ok(md) = std::fs::metadata(&dest) {
            verified.lock().unwrap().push((dest, md.len(), md.modified().unwrap_or(std::time::UNIX_EPOCH)));
        }
    }
    Ok(())
}

// ───────────── local_command ─────────────

/// Where the local whisper CLI template comes from.
#[derive(Debug, Clone, PartialEq)]
pub enum TemplateSource {
    Configured,
    WhisperCpp,
    WhisperCli,
}

/// `[media.stt.local] command` / `SEAGENT_LOCAL_STT_COMMAND` (also `HERMES_LOCAL_STT_COMMAND`)
/// > managed whisper.cpp > `whisper` CLI (Hermes `_get_local_command_template`).
pub fn local_command_template(m: &Media) -> Option<(String, TemplateSource)> {
    let configured = local_str(m, "command").or_else(|| ["SEAGENT_LOCAL_STT_COMMAND", "HERMES_LOCAL_STT_COMMAND"].iter().find_map(|k| std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())));
    if let Some(c) = configured {
        return Some((c, TemplateSource::Configured));
    }
    if let Some(c) = whisper_cpp_command(m) {
        return Some((c, TemplateSource::WhisperCpp));
    }
    let w = proc::which("whisper")?;
    Some((format!("{} {{input_path}} --model {{model}} --output_format txt --output_dir {{output_dir}} --language {{language}}", proc::shell_quote(&w.display().to_string())), TemplateSource::WhisperCli))
}

pub struct LocalCommand;

impl SttProvider for LocalCommand {
    fn id(&self) -> &str {
        "local_command"
    }
    fn env(&self) -> &[&str] {
        &[]
    }
    fn local(&self) -> bool {
        true
    }
    fn available(&self, m: &Media) -> bool {
        local_command_template(m).is_some()
    }
    fn transcribe(&self, m: &Media, req: &SttRequest, cancel: &Cancel) -> Result<Transcript, String> {
        let (template, src) = local_command_template(m).ok_or("SEAGENT_LOCAL_STT_COMMAND not configured and no local whisper binary was found")?;
        let lang = normalize_language(req.language.clone().or_else(|| super::configured_language(m, "local")).as_deref()).unwrap_or_else(|| DEFAULT_LOCAL_LANGUAGE.into());
        let model = normalize_model(req.model.as_deref().or(local_str(m, "model").as_deref()));
        if src == TemplateSource::WhisperCpp {
            ensure_whisper_cpp_models(m, &model, cancel)?;
        }
        let dir = work_dir("cmd")?;
        let r = (|| {
            let input = prepare_wav(req, &dir, cancel)?;
            let out_dir = dir.join("out");
            std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
            let line = super::command::render(&template, &[("input_path", &input.display().to_string()), ("output_dir", &out_dir.display().to_string()), ("language", &lang), ("model", &model)]);
            let argv = super::command::clean_env(&[]).into_iter().chain(crate::proc::shell_argv(&line)).collect::<Vec<_>>();
            let o = proc::run(&argv, None, Duration::from_secs(300), cancel).map_err(|e| format!("Local transcription failed: {e}"))?;
            if !o.success() {
                let detail = if o.stderr.trim().is_empty() { String::from_utf8_lossy(&o.stdout).trim().to_string() } else { o.stderr.trim().to_string() };
                return Err(format!("Local STT failed: {detail}"));
            }
            let mut txts: Vec<PathBuf> = std::fs::read_dir(&out_dir).map_err(|e| e.to_string())?.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.extension().is_some_and(|x| x == "txt")).collect();
            txts.sort();
            let f = txts.first().ok_or("Local STT command completed but did not produce a .txt transcript")?;
            let text = std::fs::read_to_string(f).map_err(|e| e.to_string())?;
            Ok(Transcript { text: text.trim_start_matches('\u{feff}').trim().to_string(), language: Some(lang.clone()), ..Default::default() })
        })();
        let _ = std::fs::remove_dir_all(&dir);
        r
    }
}
