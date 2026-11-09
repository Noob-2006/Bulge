//! talk.ptt.* (OpenClaw `TalkCommands`, MIT): push-to-talk on a node. `start` records
//! the default microphone (Linux: pw-record, else ffmpeg + PulseAudio; Windows: ffmpeg DirectShow;
//! macOS: SoX `rec`, else ffmpeg AVFoundation) to a 16 kHz mono WAV and
//! returns `{captureId}`; `stop` ends it and transcribes through the node's `[stt]` (an
//! OpenAI-compatible `/audio/transcriptions`), returning `{captureId, transcript, status}`;
//! `cancel` discards it; `once` records `durationMs` and transcribes.

use super::{tmp_file, which};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `[stt]` in node.toml.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Stt {
    /// API base (`https://api.openai.com/v1`) or the full endpoint URL.
    pub url: String,
    pub key: Option<String>,
    /// Environment variable holding the key (instead of writing it into node.toml).
    pub key_env: Option<String>,
    pub model: Option<String>,
    pub language: Option<String>,
}

struct Capture {
    id: String,
    child: Child,
    path: PathBuf,
    started: Instant,
}

static ACTIVE: Mutex<Option<Capture>> = Mutex::new(None);
/// A forgotten capture is dropped after this long.
const MAX_CAPTURE: Duration = Duration::from_secs(300);

#[cfg(not(any(windows, target_os = "macos")))]
#[cfg_attr(target_os = "ios", allow(dead_code))]
pub fn available() -> bool {
    which("pw-record").is_some() || which("ffmpeg").is_some()
}

/// Windows: ffmpeg with a DirectShow microphone. macOS: SoX `rec`, else ffmpeg AVFoundation.
#[cfg(any(windows, target_os = "macos"))]
pub fn available() -> bool {
    (cfg!(target_os = "macos") && which("rec").is_some()) || !super::host_os::devices("audio").is_empty()
}

/// The recorder argv on Windows / macOS (16 kHz mono s16 WAV, like the Linux one).
#[cfg(any(windows, target_os = "macos"))]
fn recorder(path: &str, secs: Option<f64>) -> Vec<String> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    if cfg!(target_os = "macos") && which("rec").is_some() {
        let mut v = s(&["rec", "-q", "-r", "16000", "-c", "1", "-b", "16", path]);
        if let Some(t) = secs {
            v.extend(s(&["trim", "0", &format!("{t:.1}")]));
        }
        return v;
    }
    let mut v = s(&["ffmpeg", "-loglevel", "error", "-y"]);
    // A missing device shows up as ffmpeg's own error when it starts.
    v.extend(super::host_os::ffmpeg_input("audio", None).unwrap_or_default());
    if let Some(t) = secs {
        v.extend(s(&["-t", &format!("{t:.1}")]));
    }
    v.extend(s(&["-ac", "1", "-ar", "16000", path]));
    v
}

#[cfg(not(any(windows, target_os = "macos")))]
fn recorder(path: &str, secs: Option<f64>) -> Vec<String> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    match (which("pw-record").is_some(), secs) {
        (true, None) => s(&["pw-record", "--rate", "16000", "--channels", "1", "--format", "s16", path]),
        (true, Some(t)) => s(&["timeout", "-s", "INT", &format!("{t:.1}"), "pw-record", "--rate", "16000", "--channels", "1", "--format", "s16", path]),
        (false, None) => s(&["ffmpeg", "-loglevel", "error", "-y", "-f", "pulse", "-i", "default", "-ac", "1", "-ar", "16000", path]),
        (false, Some(t)) => s(&["ffmpeg", "-loglevel", "error", "-y", "-f", "pulse", "-i", "default", "-t", &format!("{t:.1}"), "-ac", "1", "-ar", "16000", path]),
    }
}

fn spawn(argv: &[String]) -> Result<Child, String> {
    // Windows: stdin stays open so `finish` can send ffmpeg its `q` (there is no SIGINT).
    let stdin = if cfg!(windows) { Stdio::piped() } else { Stdio::null() };
    seagent_core::platform::layout::program_command(&argv[0]).args(&argv[1..]).stdin(stdin).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e| format!("{}: {e}", argv[0]))
}

/// SIGINT lets both recorders finish the WAV header (Windows: ffmpeg's `q` on stdin).
fn finish(mut c: Capture) -> PathBuf {
    #[cfg(unix)]
    unsafe {
        libc::kill(c.child.id() as i32, libc::SIGINT)
    };
    #[cfg(windows)]
    if let Some(mut i) = c.child.stdin.take() {
        use std::io::Write;
        let _ = i.write_all(b"q");
    }
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until && matches!(c.child.try_wait(), Ok(None)) {
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = c.child.kill();
    let _ = c.child.wait();
    c.path
}

fn transcribe_file(stt: Option<&Stt>, id: &str, path: PathBuf) -> Result<Value, String> {
    let wav = std::fs::read(&path).map_err(|e| format!("recording: {e}"));
    let _ = std::fs::remove_file(&path);
    let wav = wav?;
    let stt = stt.ok_or("talk.ptt needs [stt] in node.toml")?;
    // A WAV header alone: nothing was heard.
    if wav.len() <= 44 + 3200 {
        return Ok(json!({"captureId": id, "transcript": null, "status": "empty"}));
    }
    match transcribe(stt, &wav) {
        Ok(t) if t.trim().is_empty() => Ok(json!({"captureId": id, "transcript": null, "status": "empty"})),
        Ok(t) => Ok(json!({"captureId": id, "transcript": t, "status": "transcribed"})),
        Err(e) => Ok(json!({"captureId": id, "transcript": null, "status": "failed", "error": e})),
    }
}

pub fn run(stt: Option<&Stt>, command: &str, p: &Value) -> Result<Value, String> {
    let mut active = ACTIVE.lock().unwrap();
    if active.as_ref().is_some_and(|c| c.started.elapsed() > MAX_CAPTURE) {
        let _ = std::fs::remove_file(finish(active.take().unwrap()));
    }
    match command {
        "talk.ptt.start" => {
            if let Some(c) = active.as_ref() {
                return Err(format!("capture {} is already running; stop or cancel it first", c.id));
            }
            stt.ok_or("talk.ptt needs [stt] in node.toml")?;
            let path = tmp_file("ptt", "wav");
            let child = spawn(&recorder(&path.display().to_string(), None))?;
            let id = seagent_net::crypto::random_token(12);
            *active = Some(Capture { id: id.clone(), child, path, started: Instant::now() });
            Ok(json!({"captureId": id}))
        }
        "talk.ptt.stop" | "talk.ptt.cancel" => {
            let c = active.take().ok_or("no capture is running")?;
            if p["captureId"].as_str().is_some_and(|w| w != c.id) {
                let id = c.id.clone();
                *active = Some(c);
                return Err(format!("capture {id} is running, not the one asked for"));
            }
            let id = c.id.clone();
            let path = finish(c);
            drop(active);
            if command == "talk.ptt.cancel" {
                let _ = std::fs::remove_file(path);
                return Ok(json!({"captureId": id, "transcript": null, "status": "cancelled"}));
            }
            transcribe_file(stt, &id, path)
        }
        "talk.ptt.once" => {
            if active.is_some() {
                return Err("a capture is already running".into());
            }
            stt.ok_or("talk.ptt needs [stt] in node.toml")?;
            drop(active);
            let ms = p["durationMs"].as_u64().unwrap_or(5000).clamp(500, 60_000);
            let path = tmp_file("ptt", "wav");
            let mut child = spawn(&recorder(&path.display().to_string(), Some(ms as f64 / 1000.0)))?;
            let until = Instant::now() + Duration::from_millis(ms + 10_000);
            while Instant::now() < until && matches!(child.try_wait(), Ok(None)) {
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = child.kill();
            let _ = child.wait();
            transcribe_file(stt, &seagent_net::crypto::random_token(12), path)
        }
        other => Err(format!("unknown talk command `{other}`")),
    }
}

/// multipart/form-data body for `/audio/transcriptions`.
pub fn multipart(boundary: &str, fields: &[(&str, &str)], wav: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    for (k, v) in fields {
        b.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").as_bytes());
    }
    b.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"speech.wav\"\r\nContent-Type: audio/wav\r\n\r\n").as_bytes());
    b.extend_from_slice(wav);
    b.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    b
}

pub fn transcribe(stt: &Stt, wav: &[u8]) -> Result<String, String> {
    let base = stt.url.trim_end_matches('/');
    let url = if base.ends_with("/audio/transcriptions") { base.to_string() } else { format!("{base}/audio/transcriptions") };
    let model = stt.model.clone().unwrap_or_else(|| "whisper-1".into());
    let mut fields = vec![("model", model.as_str()), ("response_format", "json")];
    if let Some(l) = stt.language.as_deref() {
        fields.push(("language", l));
    }
    let boundary = format!("seagent{}", seagent_net::crypto::random_token(16));
    let body = multipart(&boundary, &fields, wav);
    let agent: ureq::Agent = seagent_net::http::builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(120))).build().into();
    let mut r = agent.post(&url).header("content-type", &format!("multipart/form-data; boundary={boundary}"));
    let key = stt.key.clone().or_else(|| stt.key_env.as_deref().and_then(|k| std::env::var(k).ok()));
    if let Some(k) = key.filter(|k| !k.is_empty()) {
        r = r.header("authorization", &format!("Bearer {k}"));
    }
    let mut resp = r.send(&body[..]).map_err(|e| format!("STT request failed: {e}"))?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().map_err(|e| e.to_string())?;
    if !(200..300).contains(&status) {
        return Err(format!("STT HTTP {status}: {}", text.chars().take(300).collect::<String>()));
    }
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("STT reply: {e}"))?;
    Ok(v["text"].as_str().unwrap_or("").trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn recorder_argv_and_multipart_body() {
        let a = recorder("/tmp/x.wav", Some(2.0));
        assert!(a.contains(&"16000".to_string()) && a.last().unwrap() == "/tmp/x.wav");
        let b = String::from_utf8(multipart("B", &[("model", "whisper-1")], b"RIFF")).unwrap();
        assert!(b.starts_with("--B\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n"));
        assert!(b.contains("filename=\"speech.wav\"\r\nContent-Type: audio/wav\r\n\r\nRIFF\r\n--B--\r\n"));
    }

    #[test]
    fn transcribes_through_an_openai_compatible_endpoint() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = vec![0u8; 1 << 16];
            let mut got = Vec::new();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            while let Ok(n) = s.read(&mut buf) {
                got.extend_from_slice(&buf[..n]);
                if n == 0 || got.windows(4).any(|w| w == b"--\r\n") {
                    break;
                }
            }
            let body = r#"{"text": " 你好 "}"#;
            write!(s, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).unwrap();
            String::from_utf8_lossy(&got).into_owned()
        });
        let stt = Stt { url: format!("http://127.0.0.1:{port}/v1"), key: Some("k1".into()), language: Some("zh".into()), ..Default::default() };
        assert_eq!(transcribe(&stt, b"RIFFdata").unwrap(), "你好");
        let req = h.join().unwrap();
        assert!(req.starts_with("POST /v1/audio/transcriptions"));
        assert!(req.to_lowercase().contains("authorization: bearer k1") && req.contains("name=\"language\"\r\n\r\nzh"));
    }

    #[test]
    fn stop_without_a_capture_and_missing_stt_are_errors() {
        assert!(run(None, "talk.ptt.stop", &json!({})).unwrap_err().contains("no capture"));
        assert!(run(None, "talk.ptt.start", &json!({})).unwrap_err().contains("[stt]"));
        assert!(run(None, "talk.ptt.bogus", &json!({})).is_err());
    }
}
