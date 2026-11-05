//! Microsoft Edge "read aloud" TTS (free, no key; Hermes default `edge`, OpenClaw
//! `microsoft`). A WebSocket session: `speech.config` text frame, an SSML text frame,
//! then binary frames carrying `Path:audio` until `Path:turn.end`. The connection
//! carries the `Sec-MS-GEC` DRM token (SHA-256 of 5-minute-rounded Windows file time
//! ticks + the trusted client token), as node-edge-tts / edge-tts do.
//!
//! `[media.tts.edge]` voice = "en-US-AriaNeural", lang = "en-US",
//! output_format = "audio-24khz-48kbitrate-mono-mp3", rate / pitch / volume, speed.

use super::{num, opt, speech, Speech, TtsProvider, TtsRequest};
use crate::Media;
use ark_core::Cancel;
use ark_net::ws::{Message, WebSocket};
use std::time::{Duration, Instant};

pub const TRUSTED_CLIENT_TOKEN: &str = "6A5AA1D4EAFF4E9FB37E23D68491D6F4";
pub const CHROMIUM_FULL_VERSION: &str = "143.0.3650.75";
const WS_URL: &str = "wss://api.msedgeservices.com/tts/cognitiveservices/websocket/v1";
const VOICES_URL: &str = "https://speech.platform.bing.com/consumer/speech/synthesize/readaloud/voices/list";
pub const DEFAULT_VOICE: &str = "en-US-AriaNeural";
const DEFAULT_FORMAT: &str = "audio-24khz-48kbitrate-mono-mp3";
const WINDOWS_EPOCH: u64 = 11_644_473_600;

/// `Sec-MS-GEC` for unix time `now` (seconds).
pub fn sec_ms_gec(now: u64) -> String {
    let ticks: u128 = (now as u128 + WINDOWS_EPOCH as u128) * 10_000_000;
    let rounded = ticks - ticks % 3_000_000_000;
    ark_net::crypto::hex(&ark_net::crypto::sha256(format!("{rounded}{TRUSTED_CLIENT_TOKEN}").as_bytes())).to_uppercase()
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

fn cjk_dominant(t: &str) -> bool {
    let chars: Vec<char> = t.chars().filter(|c| !c.is_whitespace()).collect();
    if chars.is_empty() {
        return false;
    }
    let n = chars.iter().filter(|&&c| matches!(c as u32, 0x4e00..=0x9fff | 0x3400..=0x4dbf | 0x3000..=0x303f | 0xff00..=0xffef)).count();
    n as f64 / chars.len() as f64 > 0.3
}

fn format_mime(f: &str) -> &'static str {
    let f = f.to_ascii_lowercase();
    if f.contains("webm") {
        "audio/webm"
    } else if f.contains("ogg") || f.contains("opus") {
        "audio/ogg"
    } else if f.contains("riff") || f.contains("wav") || f.contains("pcm") {
        "audio/wav"
    } else {
        "audio/mpeg"
    }
}

pub struct Edge;

impl Edge {
    fn ua() -> String {
        let major = CHROMIUM_FULL_VERSION.split('.').next().unwrap_or("0");
        format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36 Edg/{major}.0.0.0")
    }

    #[allow(clippy::too_many_arguments)]
    fn run(m: &Media, text: &str, voice: &str, lang: &str, format: &str, rate: &str, pitch: &str, volume: &str, cancel: &Cancel) -> Result<Vec<u8>, String> {
        let base = opt(m, "edge", "ws_url").unwrap_or_else(|| m.creds("edge", &[], WS_URL).base);
        let url = format!("{base}?Ocp-Apim-Subscription-Key={TRUSTED_CLIENT_TOKEN}&Sec-MS-GEC={}&Sec-MS-GEC-Version=1-{CHROMIUM_FULL_VERSION}", sec_ms_gec(super::unix_now()));
        let ua = Self::ua();
        let headers = [("Origin", "chrome-extension://jdiccldimpdaibmpdkjnbmckianbfold"), ("Pragma", "no-cache"), ("Cache-Control", "no-cache"), ("User-Agent", ua.as_str()), ("Accept-Language", "en-US,en;q=0.9")];
        let timeout = Duration::from_secs(num(m, "edge", "timeout_secs").unwrap_or(60.0) as u64);
        let (mut ws, _) = WebSocket::connect(&url, &headers, Duration::from_secs(20)).map_err(|e| format!("Edge TTS connect failed: {e}"))?;
        ws.set_read_timeout(Some(Duration::from_millis(200))).map_err(|e| e.to_string())?;
        let cfg = format!("Content-Type:application/json; charset=utf-8\r\nPath:speech.config\r\n\r\n{{\"context\":{{\"synthesis\":{{\"audio\":{{\"metadataoptions\":{{\"sentenceBoundaryEnabled\":\"false\",\"wordBoundaryEnabled\":\"true\"}},\"outputFormat\":\"{format}\"}}}}}}}}");
        ws.send_text(&cfg).map_err(|e| e.to_string())?;
        let rid = ark_net::crypto::hex(&ark_net::crypto::random_bytes(16));
        let ssml = format!(
            "X-RequestId:{rid}\r\nContent-Type:application/ssml+xml\r\nPath:ssml\r\n\r\n<speak version=\"1.0\" xmlns=\"http://www.w3.org/2001/10/synthesis\" xmlns:mstts=\"https://www.w3.org/2001/mstts\" xml:lang=\"{}\"><voice name=\"{}\"><prosody rate=\"{}\" pitch=\"{}\" volume=\"{}\">{}</prosody></voice></speak>",
            xml_escape(lang),
            xml_escape(voice),
            xml_escape(rate),
            xml_escape(pitch),
            xml_escape(volume),
            xml_escape(text)
        );
        ws.send_text(&ssml).map_err(|e| e.to_string())?;
        let start = Instant::now();
        let mut audio = Vec::new();
        loop {
            if cancel.is_cancelled() {
                return Err("cancelled".into());
            }
            if start.elapsed() > timeout {
                return Err("Edge TTS timed out".into());
            }
            match ws.recv().map_err(|e| format!("Edge TTS: {e}"))? {
                None => continue,
                Some(Message::Binary(b)) => {
                    let sep = b"Path:audio\r\n";
                    if let Some(i) = b.windows(sep.len()).position(|w| w == sep) {
                        audio.extend_from_slice(&b[i + sep.len()..]);
                        if audio.len() > super::MAX_AUDIO_BYTES {
                            return Err("Edge TTS response exceeds the audio size limit".into());
                        }
                    }
                }
                Some(Message::Text(t)) if t.contains("Path:turn.end") => break,
                Some(Message::Close(_)) => break,
                Some(_) => {}
            }
        }
        let _ = ws.send(&Message::Close(None));
        Ok(audio)
    }
}

impl TtsProvider for Edge {
    fn id(&self) -> &str {
        "edge"
    }
    fn aliases(&self) -> &[&str] {
        &["microsoft"]
    }
    fn env(&self) -> &[&str] {
        &[]
    }
    fn configured(&self, m: &Media) -> bool {
        super::flag(m, "edge", "enabled").unwrap_or(true)
    }
    fn dest(&self, _m: &Media) -> Option<String> {
        Some("api.msedgeservices.com".into())
    }
    fn voices(&self, m: &Media, _c: &Cancel) -> Result<Vec<String>, String> {
        let base = opt(m, "edge", "voices_url").unwrap_or_else(|| VOICES_URL.into());
        let major = CHROMIUM_FULL_VERSION.split('.').next().unwrap_or("0");
        let h = vec![
            ("origin".to_string(), "chrome-extension://jdiccldimpdaibmpdkjnbmckianbfold".to_string()),
            ("user-agent".into(), Self::ua()),
            ("sec-ms-gec".into(), sec_ms_gec(super::unix_now())),
            ("sec-ms-gec-version".into(), format!("1-{CHROMIUM_FULL_VERSION}")),
            ("accept".into(), format!("*/* ;chrome {major}")),
        ];
        let v = m.http.get_json(&format!("{base}?trustedclienttoken={TRUSTED_CLIENT_TOKEN}"), &h).map_err(|e| format!("Microsoft voices API error: {e}"))?;
        Ok(v.as_array().into_iter().flatten().filter_map(|x| x["ShortName"].as_str().map(str::to_string)).collect())
    }
    fn synthesize(&self, m: &Media, req: &TtsRequest, cancel: &Cancel) -> Result<Speech, String> {
        if req.text.trim().is_empty() {
            return Err("Microsoft TTS text cannot be empty".into());
        }
        let explicit = req.voice.clone().or_else(|| opt(m, "edge", "voice")).or_else(|| opt(m, "microsoft", "voice"));
        let mut voice = explicit.clone().unwrap_or_else(|| DEFAULT_VOICE.into());
        let mut lang = req.language.clone().or_else(|| opt(m, "edge", "lang")).unwrap_or_else(|| voice.split('-').take(2).collect::<Vec<_>>().join("-"));
        if explicit.is_none() && cjk_dominant(&req.text) {
            voice = "zh-CN-XiaoxiaoNeural".into();
            lang = "zh-CN".into();
        }
        let rate = match (opt(m, "edge", "rate"), super::speed(m, "edge", req)) {
            (Some(r), _) => r,
            (None, Some(s)) if (s - 1.0).abs() > f64::EPSILON => format!("{:+}%", ((s - 1.0) * 100.0).round() as i64),
            _ => "default".into(),
        };
        let pitch = opt(m, "edge", "pitch").unwrap_or_else(|| "default".into());
        let volume = opt(m, "edge", "volume").unwrap_or_else(|| "default".into());
        let format = opt(m, "edge", "output_format").unwrap_or_else(|| DEFAULT_FORMAT.into());
        let mut candidates = vec![format.clone()];
        if format != DEFAULT_FORMAT {
            candidates.push(DEFAULT_FORMAT.to_string());
        }
        let mut last = String::new();
        // Empty output is retried once; a failing custom format falls back to the default one.
        for fmt in candidates {
            for _ in 0..2 {
                match Self::run(m, &req.text, &voice, &lang, &fmt, &rate, &pitch, &volume, cancel) {
                    Ok(a) if !a.is_empty() => return Ok(speech(a, format_mime(&fmt))),
                    Ok(_) => last = "Edge TTS produced empty audio file after retry".into(),
                    Err(e) => {
                        last = e;
                        break;
                    }
                }
            }
        }
        Err(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn gec_token_is_stable_within_five_minutes() {
        let a = sec_ms_gec(1_700_000_000);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()));
        assert_eq!(a, sec_ms_gec(1_700_000_000 - 1_700_000_000 % 300 + 299));
        assert_ne!(a, sec_ms_gec(1_700_000_000 + 600));
    }

    #[test]
    fn websocket_session() {
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let s2 = seen.clone();
        let url = crate::testutil::ws_server(move |head, ws| {
            s2.lock().unwrap().push(head);
            for _ in 0..2 {
                if let Ok(Message::Text(t)) = ws.recv_blocking() {
                    s2.lock().unwrap().push(t);
                }
            }
            let mut frame = vec![0u8, 20];
            frame.extend_from_slice(b"X-RequestId:1\r\nPath:audio\r\nID3\x04audio");
            let _ = ws.send(&Message::Binary(frame));
            let _ = ws.send_text("X-RequestId:1\r\nPath:turn.end\r\n\r\n{}");
        });
        let m = Media { cfg: crate::MediaConfig::from_toml(&format!("[tts.edge]\nws_url = \"{url}\"\nvoice = \"en-GB-SoniaNeural\"\n[tts]\nspeed = 1.5")), http: Default::default() };
        let s = Edge.synthesize(&m, &TtsRequest::new("Fish & <chips>"), &Cancel::new()).unwrap();
        assert_eq!((s.audio.bytes.as_slice(), s.audio.mime.as_str()), (&b"ID3\x04audio"[..], "audio/mpeg"));
        let seen = seen.lock().unwrap();
        assert!(seen[0].contains("Sec-MS-GEC=") && seen[0].to_ascii_lowercase().contains("origin: chrome-extension://jdiccldimpdaibmpdkjnbmckianbfold"), "{}", seen[0]);
        assert!(seen[1].contains("Path:speech.config") && seen[1].contains(DEFAULT_FORMAT));
        assert!(seen[2].contains("<voice name=\"en-GB-SoniaNeural\">") && seen[2].contains("rate=\"+50%\"") && seen[2].contains("Fish &amp; &lt;chips&gt;"), "{}", seen[2]);
    }

    #[test]
    fn cjk_switches_default_voice() {
        assert!(cjk_dominant("你好，世界"));
        assert!(!cjk_dominant("hello 你"));
    }
}
