//! Wake-word ("hey ark") detection — hands-free trigger for voice mode (Hermes
//! `tools/wake_word.py`, `tools/wake_word_engines.py`).
//!
//! Engines run fully on-device in a child process fed 16 kHz mono s16le PCM on
//! stdin; the child prints `WAKE <phrase>` when it hears the phrase:
//! - `openwakeword`: the openWakeWord package (`model` = a model name or a
//!   `.onnx`/`.tflite` path); `sensitivity` is the raw 0..1 score threshold and
//!   `confirmation_frames` consecutive hits are required.
//! - `sherpa` (`sherpa-onnx`, `kws`): open-vocabulary keyword spotting — any typed
//!   phrase, BPE-tokenized at runtime; the small GigaSpeech KWS model is downloaded once
//!   to `$ARK_HOME/cache/wakewords`. Threshold = 0.05 + 0.4 × sensitivity.
//! - `porcupine`: Picovoice Porcupine (`PORCUPINE_ACCESS_KEY`, `keyword` = built-in name
//!   or `.ppn` path); sensitivity inverted so "higher = stricter" holds everywhere.
//! - `command`: any program honouring the same stdin/stdout contract.
//!
//! ```toml
//! [media.wake]
//! provider = "auto"           # auto | openwakeword | sherpa | porcupine | command
//! phrase = "hey ark"
//! sensitivity = 0.6           # 0..1, higher = stricter
//! confirmation_frames = 3     # 1..10
//! command = ""                # provider = "command": shell line reading PCM on stdin
//! python = "python3"
//! model = ""                  # openwakeword model; sherpa model_dir; porcupine keyword
//! ```

use super::record::PcmSource;
use crate::Media;
use ark_core::Cancel;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::Receiver;

pub const SAMPLE_RATE: u32 = 16000;
/// 80 ms frames.
pub const FRAME: usize = 1280;
/// Minimum gap between two fires.
pub const FIRE_COOLDOWN_SECS: f64 = 2.0;
/// A stream whose peak stays at/below this for this long is flagged as a dead mic.
pub const SILENCE_PEAK: i16 = 10;
pub const SILENCE_ALERT_SECS: f64 = 10.0;
pub const SHERPA_KWS_MODEL_URL: &str = "https://github.com/k2-fsa/sherpa-onnx/releases/download/kws-models/sherpa-onnx-kws-zipformer-gigaspeech-3.3M-2024-01-01.tar.bz2";

const PROVIDERS: &[(&str, &str)] = &[("openwakeword", "openwakeword"), ("oww", "openwakeword"), ("local", "openwakeword"), ("sherpa", "sherpa"), ("sherpa-onnx", "sherpa"), ("kws", "sherpa"), ("open", "sherpa"), ("porcupine", "porcupine"), ("command", "command")];

fn wstr(m: &Media, k: &str) -> Option<String> {
    m.cfg.str(&format!("wake.{k}"))
}

pub fn phrase(m: &Media) -> String {
    wstr(m, "phrase").unwrap_or_else(|| "hey ark".into())
}

pub fn sensitivity(m: &Media) -> f64 {
    m.cfg.float_or("wake.sensitivity", 0.6).clamp(0.0, 1.0)
}

pub fn confirmation_frames(m: &Media) -> i64 {
    m.cfg.int_or("wake.confirmation_frames", 3).clamp(1, 10)
}

fn python(m: &Media) -> String {
    wstr(m, "python").unwrap_or_else(|| "python3".into())
}

fn has_module(py: &str, module: &str) -> bool {
    crate::proc::which(py).is_some() && crate::proc::run(&[py.to_string(), "-c".into(), format!("import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('{module}') else 1)")], None, std::time::Duration::from_secs(20), &Cancel::new()).map(|o| o.success()).unwrap_or(false)
}

/// The engine to use (`Err` names what to install). Auto prefers an explicit
/// command, then openWakeWord when a model is configured, then sherpa-onnx (any
/// phrase), then Porcupine when an access key exists.
pub fn resolve_provider(m: &Media) -> Result<String, String> {
    let p = wstr(m, "provider").map(|s| s.to_ascii_lowercase()).unwrap_or_else(|| "auto".into());
    if p != "auto" {
        return PROVIDERS.iter().find(|(a, _)| *a == p).map(|(_, e)| e.to_string()).ok_or_else(|| format!("unknown wake word provider `{p}` (openwakeword, sherpa, porcupine, command)"));
    }
    if wstr(m, "command").is_some() {
        return Ok("command".into());
    }
    let py = python(m);
    if wstr(m, "model").is_some() && has_module(&py, "openwakeword") {
        return Ok("openwakeword".into());
    }
    if has_module(&py, "sherpa_onnx") {
        return Ok("sherpa".into());
    }
    if std::env::var("PORCUPINE_ACCESS_KEY").is_ok_and(|k| !k.trim().is_empty()) && has_module(&py, "pvporcupine") {
        return Ok("porcupine".into());
    }
    Err("No wake word engine available: pip install sherpa-onnx (any phrase) or openwakeword (with [media.wake] model), or pvporcupine with PORCUPINE_ACCESS_KEY, or set [media.wake] command".into())
}

/// The child program for the Python engines: reads frames from stdin, prints `WAKE <phrase>`.
const ENGINE_PY: &str = r#"
import json, os, sys
a = json.loads(sys.argv[1]); eng = a["engine"]; phrase = a["phrase"]; sens = a["sensitivity"]
def fire(p): sys.stdout.write("WAKE %s\n" % p); sys.stdout.flush()
import numpy as np
inp = sys.stdin.buffer
if eng == "openwakeword":
    from openwakeword.model import Model
    ref = a["model"]
    model = Model(wakeword_models=[ref]) if ref else Model()
    need, streak = a["confirm"], 0
    process = None
elif eng == "sherpa":
    import sherpa_onnx, tarfile, tempfile, urllib.request, glob
    from sherpa_onnx import text2token
    d = a["model_dir"]
    if not os.path.exists(os.path.join(d, "tokens.txt")):
        root = os.path.dirname(d); os.makedirs(root, exist_ok=True)
        arc = d + ".tar.bz2"; urllib.request.urlretrieve(a["model_url"], arc)
        with tarfile.open(arc, "r:bz2") as tf: tf.extractall(root, filter="data")
        os.unlink(arc)
    toks = text2token([phrase.upper()], tokens=os.path.join(d, "tokens.txt"), tokens_type="bpe", bpe_model=os.path.join(d, "bpe.model"))
    kw = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", prefix="ark-kws-", delete=False, encoding="utf-8")
    kw.write(" ".join(toks[0]) + " @" + phrase.upper().replace(" ", "_") + "\n"); kw.close()
    def mf(part): return sorted(f for f in glob.glob(os.path.join(d, part + "-*.onnx")) if not f.endswith("8.onnx"))[0]
    spot = sherpa_onnx.KeywordSpotter(tokens=os.path.join(d, "tokens.txt"), encoder=mf("encoder"), decoder=mf("decoder"), joiner=mf("joiner"), keywords_file=kw.name, keywords_threshold=0.05 + 0.4 * sens, num_threads=1)
    stream = spot.create_stream()
elif eng == "porcupine":
    import pvporcupine
    kwd = a["model"] or "jarvis"
    kw = {"access_key": os.environ["PORCUPINE_ACCESS_KEY"], "sensitivities": [1.0 - sens]}
    kw["keyword_paths" if (os.sep in kwd or kwd.endswith(".ppn")) else "keywords"] = [kwd]
    por = pvporcupine.create(**kw); buf = np.zeros(0, dtype=np.int16)
sys.stdout.write("READY\n"); sys.stdout.flush()
while True:
    b = inp.read(2560)
    if not b: break
    frame = np.frombuffer(b[: len(b) // 2 * 2], dtype=np.int16)
    if eng == "openwakeword":
        scores = model.predict(frame)
        if max(scores.values() or [0]) >= sens:
            streak += 1
            if streak >= need: streak = 0; fire(phrase)
        else: streak = 0
    elif eng == "sherpa":
        stream.accept_waveform(16000, frame.astype(np.float32) / 32768.0)
        while spot.is_ready(stream):
            spot.decode_stream(stream); r = spot.get_result(stream)
            if r: fire(str(r).replace("_", " ").lower()); spot.reset_stream(stream)
    else:
        buf = np.concatenate([buf, frame])
        while len(buf) >= por.frame_length:
            if por.process(buf[: por.frame_length].tolist()) >= 0: fire(phrase)
            buf = buf[por.frame_length:]
"#;

/// The engine argv for `provider`.
pub fn engine_command(m: &Media, provider: &str) -> Result<Vec<String>, String> {
    if provider == "command" {
        let c = wstr(m, "command").ok_or("[media.wake] command is not set")?;
        return Ok(vec!["sh".into(), "-c".into(), c]);
    }
    if provider == "porcupine" && std::env::var("PORCUPINE_ACCESS_KEY").map(|k| k.trim().is_empty()).unwrap_or(true) {
        return Err("Porcupine wake word requires PORCUPINE_ACCESS_KEY (get a free key at https://console.picovoice.ai).".into());
    }
    let model_dir = wstr(m, "model_dir").map(|d| ark_core::tool::expand_home(&d)).unwrap_or_else(|| crate::stt::local::ark_home().join("cache").join("wakewords").join("sherpa-onnx-kws-zipformer-gigaspeech-3.3M-2024-01-01"));
    let args = serde_json::json!({"engine": provider, "phrase": phrase(m), "sensitivity": sensitivity(m), "confirm": confirmation_frames(m), "model": wstr(m, "model").unwrap_or_default(), "model_dir": model_dir.display().to_string(), "model_url": SHERPA_KWS_MODEL_URL});
    Ok(vec![python(m), "-c".into(), ENGINE_PY.into(), args.to_string()])
}

/// A running engine process.
pub struct Engine {
    child: Child,
    stdin: Option<ChildStdin>,
    rx: Receiver<String>,
}

impl Engine {
    pub fn spawn(argv: &[String]) -> Result<Engine, String> {
        let (prog, args) = argv.split_first().ok_or("empty wake engine command")?;
        let mut child = Command::new(prog).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|e| format!("cannot start wake word engine `{prog}`: {e}"))?;
        let stdin = child.stdin.take();
        let out = child.stdout.take().ok_or("engine has no stdout")?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for l in BufReader::new(out).lines() {
                let Ok(l) = l else { break };
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        Ok(Engine { child, stdin, rx })
    }
    pub fn open(m: &Media) -> Result<Engine, String> {
        let p = resolve_provider(m)?;
        Engine::spawn(&engine_command(m, &p)?)
    }
    /// Feed one frame; `Some(phrase)` when the engine fired.
    pub fn process(&mut self, frame: &[i16]) -> Result<Option<String>, String> {
        if let Some(si) = self.stdin.as_mut() {
            si.write_all(&crate::audio::pcm16_to_bytes(frame)).and_then(|_| si.flush()).map_err(|e| format!("wake word engine stopped: {e}"))?;
        }
        Ok(self.poll())
    }
    fn poll(&mut self) -> Option<String> {
        while let Ok(l) = self.rx.try_recv() {
            let l = l.trim();
            if let Some(p) = l.strip_prefix("WAKE") {
                return Some(p.trim().to_string());
            }
        }
        None
    }
    /// Wait briefly for a fire after the last frame (engines answer asynchronously).
    pub fn drain(&mut self, ms: u64) -> Option<String> {
        let until = std::time::Instant::now() + std::time::Duration::from_millis(ms);
        while std::time::Instant::now() < until {
            if let Ok(l) = self.rx.recv_timeout(std::time::Duration::from_millis(10)) {
                if let Some(p) = l.trim().strip_prefix("WAKE") {
                    return Some(p.trim().to_string());
                }
            }
        }
        None
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Feed `src` to `engine` until it fires (→ `Some(phrase)`), the source ends or
/// `should_stop()`. Fires within [`FIRE_COOLDOWN_SECS`] of `last_fire` are ignored;
/// `on_alert` hears about a dead (all-zero) microphone once.
pub fn listen(engine: &mut Engine, src: &mut dyn PcmSource, cancel: &Cancel, should_stop: &dyn Fn() -> bool, on_alert: &mut dyn FnMut(&str)) -> Result<Option<String>, String> {
    let mut pending: Vec<i16> = Vec::new();
    let (mut t, mut silent_since, mut alerted) = (0.0f64, 0.0f64, false);
    let mut last_fire = f64::NEG_INFINITY;
    let handle = |p: Option<String>, t: f64, last: &mut f64| -> Option<String> {
        let p = p?;
        if t - *last < FIRE_COOLDOWN_SECS {
            return None;
        }
        *last = t;
        Some(p)
    };
    loop {
        if should_stop() {
            return Ok(None);
        }
        let Some(b) = src.read(cancel)? else {
            return Ok(handle(engine.drain(500), t, &mut last_fire));
        };
        pending.extend(b);
        while pending.len() >= FRAME {
            let frame: Vec<i16> = pending.drain(..FRAME).collect();
            t += FRAME as f64 / SAMPLE_RATE as f64;
            let peak = frame.iter().map(|s| s.unsigned_abs()).max().unwrap_or(0);
            if peak <= SILENCE_PEAK as u16 {
                if t - silent_since >= SILENCE_ALERT_SECS && !alerted {
                    alerted = true;
                    on_alert("wake word: the microphone has been silent (all zeros) for 10 seconds — check the input device");
                }
            } else {
                silent_since = t;
                alerted = false;
            }
            if let Some(p) = handle(engine.process(&frame)?, t, &mut last_fire) {
                return Ok(Some(p));
            }
        }
    }
}

/// Status for `/voice status` / `ark voice status`.
pub fn status(m: &Media) -> serde_json::Value {
    match resolve_provider(m) {
        Ok(p) => serde_json::json!({"available": true, "provider": p, "phrase": phrase(m), "sensitivity": sensitivity(m)}),
        Err(e) => serde_json::json!({"available": false, "error": e, "phrase": phrase(m)}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::voice::record::VecSource;

    #[test]
    fn command_engine_fires_and_dead_mic_alerts() {
        let d = crate::testutil::temp_dir("wake");
        // A fake engine: fires once it has read 2 frames of loud audio.
        let script = d.join("eng.py");
        std::fs::write(&script, "import sys\nn=0\nwhile True:\n    b=sys.stdin.buffer.read(2560)\n    if not b: break\n    if max(b) > 50: n+=1\n    if n==2:\n        print('WAKE hey ark', flush=True); n=0\n").unwrap();
        let m = Media::new(crate::MediaConfig::from_toml(&format!("[wake]\ncommand = \"python3 {}\"\n", script.display())));
        assert_eq!(resolve_provider(&m).unwrap(), "command");
        let mut e = Engine::open(&m).unwrap();
        let mut pcm = vec![0i16; 16000 * 11];
        pcm.extend((0..FRAME * 3).map(|i| if i % 2 == 0 { 9000 } else { -9000 }));
        let mut alerts = Vec::new();
        let got = listen(&mut e, &mut VecSource::new(pcm), &Cancel::new(), &|| false, &mut |a| alerts.push(a.to_string())).unwrap();
        assert_eq!(got.as_deref(), Some("hey ark"));
        assert_eq!(alerts.len(), 1, "{alerts:?}");
        let bad = Media::new(crate::MediaConfig::from_toml("[wake]\nprovider = \"siri\"\n"));
        assert!(resolve_provider(&bad).unwrap_err().contains("unknown wake word provider"));
        let sh = Media::new(crate::MediaConfig::from_toml("[wake]\nprovider = \"sherpa\"\nphrase = \"hey computer\"\nsensitivity = 0.5\n"));
        let argv = engine_command(&sh, "sherpa").unwrap();
        assert!(argv[3].contains("\"engine\":\"sherpa\"") && argv[3].contains("hey computer"));
    }
}
