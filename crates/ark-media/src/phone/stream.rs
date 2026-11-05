//! Carrier media streams (Twilio Media Streams / Telnyx streaming, OpenClaw
//! `voice-call/src/media-stream.ts`, MIT): μ-law 8 kHz JSON frames over WebSocket.
//! Inbound audio runs through an energy VAD; each finished utterance is transcribed with
//! `[media.stt]` and handed to [`super::Phone::on_speech`]. Replies are synthesized with
//! `[media.tts]`, resampled to 8 kHz μ-law and sent as `media` frames; caller speech during
//! playback sends `clear` (barge-in).

use super::Phone;
use crate::audio;
use crate::Media;
use ark_core::Cancel;
use serde_json::{json, Value};
use std::net::TcpStream;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub enum Out {
    Audio(Vec<u8>),
    Hangup,
}

/// TTS → 8 kHz mono μ-law bytes.
pub fn synthesize_ulaw(m: &Media, text: &str) -> Result<Vec<u8>, String> {
    let (_, s) = crate::tts::synthesize(m, &crate::tts::TtsRequest::new(text), &Cancel::new())?;
    let pcm = match s.audio.mime.as_str() {
        "audio/pcm" | "audio/l16" => audio::resample(
            &audio::pcm16_from_bytes(&s.audio.bytes),
            s.sample_rate.unwrap_or(24000),
            8000,
        ),
        mime => audio::decode_to_pcm(&s.audio.bytes, mime, 8000, &Cancel::new())?,
    };
    Ok(pcm.into_iter().map(audio::pcm_to_ulaw).collect())
}

/// Energy VAD over 20 ms frames: speech after `start` loud frames, end after `hang` quiet ones.
pub struct Vad {
    pub threshold: f64,
    start: usize,
    hang: usize,
    loud: usize,
    quiet: usize,
    pub speaking: bool,
    buf: Vec<i16>,
    pre: Vec<i16>,
}

impl Vad {
    pub fn new(threshold: f64, hang_ms: u64) -> Vad {
        Vad {
            threshold,
            start: 3,
            hang: (hang_ms / 20).max(5) as usize,
            loud: 0,
            quiet: 0,
            speaking: false,
            buf: vec![],
            pre: vec![],
        }
    }

    /// Feed one 160-sample frame; returns `(speech_started, finished_utterance)`.
    pub fn feed(&mut self, frame: &[i16]) -> (bool, Option<Vec<i16>>) {
        let loud = audio::rms(frame) >= self.threshold;
        if !self.speaking {
            self.pre.extend_from_slice(frame);
            let keep = 160 * 10;
            if self.pre.len() > keep {
                self.pre.drain(..self.pre.len() - keep);
            }
            self.loud = if loud { self.loud + 1 } else { 0 };
            if self.loud >= self.start {
                self.speaking = true;
                self.quiet = 0;
                self.buf = std::mem::take(&mut self.pre);
                return (true, None);
            }
            return (false, None);
        }
        self.buf.extend_from_slice(frame);
        self.quiet = if loud { 0 } else { self.quiet + 1 };
        if self.quiet >= self.hang || self.buf.len() > 8000 * 30 {
            self.speaking = false;
            self.loud = 0;
            return (false, Some(std::mem::take(&mut self.buf)));
        }
        (false, None)
    }
}

fn transcribe(m: &Media, pcm: &[i16]) -> Result<String, String> {
    let wav = audio::wav_encode(pcm, 8000, 1);
    let req = crate::stt::SttRequest {
        audio: wav,
        mime: "audio/wav".into(),
        file_name: "call.wav".into(),
        language: m
            .cfg
            .str("phone.language")
            .map(|l| l.split('-').next().unwrap_or("en").to_string()),
        ..Default::default()
    };
    crate::stt::transcribe(m, &req, &Cancel::new()).map(|(_, t)| t.text)
}

/// Serve one stream connection until it closes.
pub fn run(phone: Arc<Phone>, mut ws: ark_net::ws::WebSocket<TcpStream>, url_token: String) {
    let telnyx = phone.carrier.id == "telnyx";
    ws.set_max_message(1 << 20);
    let _ = ws
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(20)));
    let (tx, rx) = mpsc::channel::<Out>();
    let mut call: Option<String> = None;
    let mut sid = String::new();
    let threshold = phone.m.cfg.float_or("phone.vad_threshold", 500.0);
    let mut vad = Vad::new(
        threshold,
        phone.m.cfg.int_or("phone.silence_ms", 700).max(100) as u64,
    );
    let mut playing_until = Instant::now();
    let mut pending: Vec<i16> = vec![];
    loop {
        // Outbound first: queued speech / hangup.
        while let Ok(o) = rx.try_recv() {
            match o {
                Out::Audio(ulaw) => {
                    for chunk in ulaw.chunks(160 * 25) {
                        let mut f = json!({"event": "media", "media": {"payload": crate::store::b64(chunk)}});
                        if !telnyx {
                            f["streamSid"] = json!(sid);
                        }
                        if ws.send_text(&f.to_string()).is_err() {
                            return;
                        }
                    }
                    let base = playing_until.max(Instant::now());
                    playing_until = base + Duration::from_millis(ulaw.len() as u64 / 8);
                    let mark = if telnyx {
                        json!({"event": "mark", "mark": {"name": "ark-reply"}})
                    } else {
                        json!({"event": "mark", "streamSid": sid, "mark": {"name": "ark-reply"}})
                    };
                    let _ = ws.send_text(&mark.to_string());
                }
                Out::Hangup => {
                    if let Some(id) = &call {
                        // Let the audio play out, then hang up.
                        let wait = playing_until.saturating_duration_since(Instant::now());
                        let p = phone.clone();
                        let id = id.clone();
                        std::thread::spawn(move || {
                            std::thread::sleep(wait);
                            let _ = p.end(&id, "completed");
                        });
                    }
                }
            }
        }
        let msg = match ws.recv() {
            Ok(Some(ark_net::ws::Message::Text(t))) => t,
            Ok(Some(ark_net::ws::Message::Close(..))) | Err(_) => break,
            Ok(_) => {
                if ws.is_closed() {
                    break;
                }
                continue;
            }
        };
        let Ok(v) = serde_json::from_str::<Value>(&msg) else {
            continue;
        };
        match v["event"].as_str().unwrap_or("") {
            "start" => {
                let token = v["start"]["customParameters"]["token"]
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| url_token.clone());
                sid = v["start"]["streamSid"]
                    .as_str()
                    .or(v["streamSid"].as_str())
                    .or(v["stream_id"].as_str())
                    .unwrap_or("")
                    .to_string();
                match phone.attach_stream(&token, tx.clone()) {
                    Some((id, first)) => {
                        call = Some(id.clone());
                        if let Some(text) = first.filter(|t| !t.trim().is_empty()) {
                            let p = phone.clone();
                            std::thread::spawn(move || {
                                let _ = p.speak(&id, &text, false);
                            });
                        }
                    }
                    None => {
                        let _ = ws.send(&ark_net::ws::Message::Close(Some((
                            1008,
                            "unknown stream token".into(),
                        ))));
                        return;
                    }
                }
            }
            "media" => {
                let Some(id) = &call else { continue };
                if v["media"]["track"]
                    .as_str()
                    .is_some_and(|t| t == "outbound")
                {
                    continue;
                }
                let Some(bytes) = v["media"]["payload"]
                    .as_str()
                    .and_then(|p| crate::store::b64_decode(p).ok())
                else {
                    continue;
                };
                pending.extend(bytes.into_iter().map(audio::ulaw_to_pcm));
                while pending.len() >= 160 {
                    let frame: Vec<i16> = pending.drain(..160).collect();
                    let (started, done) = vad.feed(&frame);
                    if started && Instant::now() < playing_until {
                        // Barge-in: the caller talks over the reply.
                        let clear = if telnyx {
                            json!({"event": "clear"})
                        } else {
                            json!({"event": "clear", "streamSid": sid})
                        };
                        let _ = ws.send_text(&clear.to_string());
                        playing_until = Instant::now();
                    }
                    if let Some(utt) = done {
                        let p = phone.clone();
                        let id = id.clone();
                        std::thread::spawn(move || match transcribe(&p.m, &utt) {
                            Ok(text) => p.on_speech(&id, &text),
                            Err(e) => {
                                p.add_turn(&id, "system", &format!("transcription failed: {e}"))
                            }
                        });
                    }
                }
            }
            "stop" => break,
            _ => {}
        }
    }
    if let Some(id) = call {
        phone.with_call(&id, |c| c.stream_out = None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vad_segments_an_utterance() {
        let mut v = Vad::new(500.0, 200);
        let tone: Vec<i16> = (0..160)
            .map(|i| if i % 2 == 0 { 3000 } else { -3000 })
            .collect();
        let quiet = vec![0i16; 160];
        let mut started = false;
        let mut got = None;
        for _ in 0..5 {
            started |= v.feed(&quiet).0;
        }
        for _ in 0..20 {
            started |= v.feed(&tone).0;
        }
        for _ in 0..20 {
            if let (_, Some(u)) = v.feed(&quiet) {
                got = Some(u);
            }
        }
        assert!(started);
        let u = got.expect("utterance");
        assert!(u.len() >= 160 * 20, "{}", u.len());
        assert!(!v.speaking);
    }
}
