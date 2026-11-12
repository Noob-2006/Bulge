//! Discord voice channels (ported from Hermes `plugins/platforms/discord`
//! `adapter.py` VoiceReceiver / join-leave-play, `voice_mixer.py` and
//! `gateway/run_voice.py`, MIT; the wire protocol from Discord's voice docs and
//! the DAVE whitepaper).
//!
//! * Join: gateway op 4 → VOICE_STATE_UPDATE (our session id) + VOICE_SERVER_UPDATE
//!   (token, endpoint) → voice gateway v8 WebSocket: Hello, Identify (with
//!   `max_dave_protocol_version`) or Resume (`seq_ack`), heartbeats carrying
//!   `seq_ack`, Ready → UDP IP discovery (74-byte request/response) → Select
//!   Protocol → Session Description; Speaking (op 5) both ways, clients
//!   connect/disconnect (11/13), DAVE JSON ops 21–24/31 and binary ops 25–30
//!   (`[seq u16][op u8][payload]` in, `[op u8][payload]` out). Close codes 4006/4009
//!   re-identify, 4015 and dropped sockets resume, 4014/4021/4022 end the session.
//! * Transport: RTP (payload type 0x78) with `aead_aes256_gcm_rtpsize` (preferred)
//!   or `aead_xchacha20_poly1305_rtpsize` (HChaCha20 here + ring ChaCha20-Poly1305),
//!   32-bit nonce suffix, RTP header (+ extension preamble) as AAD, extension
//!   body and padding stripped after decryption; UDP keepalive every 5 s.
//! * DAVE end-to-end encryption on top (`dave`, MLS in `mls`).
//! * Playback: any file or TTS output → ffmpeg → 48 kHz stereo PCM → `Mixer`
//!   (several sources summed and clamped, Hermes' VoiceMixer) → one ffmpeg
//!   libopus encoder per talk spurt (20 ms frames, Ogg demuxed here) → paced RTP,
//!   five Opus silence frames and Speaking off at the end.
//! * Listening: per-SSRC buffers (SSRC → user from Speaking, or the only other
//!   member in the channel), utterance ends after 1.5 s without packets and needs
//!   0.5 s of voice (Hermes' thresholds) → Ogg Opus → ffmpeg → 16 kHz mono WAV →
//!   OpenAI-compatible `/audio/transcriptions` → transcript echoed to the bound
//!   text channel and delivered as an `Inbound`; replies to that chat are spoken
//!   through `/audio/speech`. Capture pauses while the bot talks (as Hermes).

use crate::dave::{Dave, Out, OPUS_SILENCE};
use crate::mls::Signer;
use crate::{sleep_cancellable, ChannelError, ChannelErrorKind as K, ChatType, Inbound};
use seagent_core::Cancel;
use seagent_media::stt::transcripts::channel::{Heard, HeardSink};
use seagent_media::stt::transcripts::Capture as TranscriptCapture;
use seagent_net::ws::{Message, WebSocket};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::UdpSocket;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const FRAME_SAMPLES: u32 = 960;
/// One 20 ms frame of 48 kHz stereo s16le.
pub const FRAME_BYTES: usize = 960 * 2 * 2;

// ---------------------------------------------------------------- transport crypto

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Aes256Gcm,
    XChaCha20,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::Aes256Gcm => "aead_aes256_gcm_rtpsize",
            Mode::XChaCha20 => "aead_xchacha20_poly1305_rtpsize",
        }
    }
    /// AES-GCM first (Discord's recommendation), then XChaCha20-Poly1305.
    pub fn choose(modes: &[String]) -> Option<Mode> {
        [Mode::Aes256Gcm, Mode::XChaCha20].into_iter().find(|m| modes.iter().any(|x| x == m.name()))
    }
    fn key_nonce(self, key: &[u8; 32], counter: u32) -> (LessSafeKey, Nonce) {
        match self {
            Mode::Aes256Gcm => {
                let mut n = [0u8; 12];
                n[..4].copy_from_slice(&counter.to_be_bytes());
                (LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).unwrap()), Nonce::assume_unique_for_key(n))
            }
            Mode::XChaCha20 => {
                let mut n = [0u8; 24];
                n[..4].copy_from_slice(&counter.to_be_bytes());
                xchacha(key, &n)
            }
        }
    }
    pub fn seal(self, key: &[u8; 32], counter: u32, aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let (k, n) = self.key_nonce(key, counter);
        let mut b = pt.to_vec();
        k.seal_in_place_append_tag(n, Aad::from(aad), &mut b).expect("transport seal");
        b
    }
    pub fn open(self, key: &[u8; 32], counter: u32, aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
        let (k, n) = self.key_nonce(key, counter);
        let mut b = ct.to_vec();
        let len = k.open_in_place(n, Aad::from(aad), &mut b).ok()?.len();
        b.truncate(len);
        Some(b)
    }
}

fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// HChaCha20 (draft-irtf-cfrg-xchacha §2.2): the XChaCha20 subkey.
pub fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut s = [0u32; 16];
    s[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    for i in 0..4 {
        s[12 + i] = u32::from_le_bytes(nonce[4 * i..4 * i + 4].try_into().unwrap());
    }
    for _ in 0..10 {
        qr(&mut s, 0, 4, 8, 12);
        qr(&mut s, 1, 5, 9, 13);
        qr(&mut s, 2, 6, 10, 14);
        qr(&mut s, 3, 7, 11, 15);
        qr(&mut s, 0, 5, 10, 15);
        qr(&mut s, 1, 6, 11, 12);
        qr(&mut s, 2, 7, 8, 13);
        qr(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 32];
    for (i, w) in s[..4].iter().chain(&s[12..]).enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// XChaCha20-Poly1305 = ChaCha20-Poly1305 under the HChaCha20 subkey with nonce 0^4 ‖ n[16..24].
fn xchacha(key: &[u8; 32], nonce: &[u8; 24]) -> (LessSafeKey, Nonce) {
    let sub = hchacha20(key, nonce[..16].try_into().unwrap());
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&nonce[16..]);
    (LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &sub).unwrap()), Nonce::assume_unique_for_key(n))
}

// ---------------------------------------------------------------- RTP / UDP

pub fn rtp_packet(mode: Mode, key: &[u8; 32], seq: u16, ts: u32, ssrc: u32, counter: u32, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x80, 0x78];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ts.to_be_bytes());
    p.extend_from_slice(&ssrc.to_be_bytes());
    let ct = mode.seal(key, counter, &p, payload);
    p.extend_from_slice(&ct);
    p.extend_from_slice(&counter.to_be_bytes());
    p
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rtp {
    pub seq: u16,
    pub ts: u32,
    pub ssrc: u32,
    pub payload: Vec<u8>,
}

/// Decrypt a voice RTP packet (rtpsize modes: header + extension preamble are the AAD).
pub fn open_rtp(mode: Mode, key: &[u8; 32], p: &[u8]) -> Option<Rtp> {
    if p.len() < 12 || p[0] >> 6 != 2 || p[1] & 0x7f != 0x78 {
        return None;
    }
    let cc = (p[0] & 0x0f) as usize;
    let ext = p[0] & 0x10 != 0;
    let hs = 12 + 4 * cc + if ext { 4 } else { 0 };
    if p.len() < hs + 16 + 4 {
        return None;
    }
    let n = p.len();
    let counter = u32::from_be_bytes(p[n - 4..].try_into().unwrap());
    let mut pt = mode.open(key, counter, &p[..hs], &p[hs..n - 4])?;
    if ext {
        let words = u16::from_be_bytes([p[12 + 4 * cc + 2], p[12 + 4 * cc + 3]]) as usize;
        if pt.len() < words * 4 {
            return None;
        }
        pt.drain(..words * 4);
    }
    if p[0] & 0x20 != 0 {
        let pad = *pt.last()? as usize;
        if pad == 0 || pad > pt.len() {
            return None;
        }
        pt.truncate(pt.len() - pad);
    }
    Some(Rtp { seq: u16::from_be_bytes([p[2], p[3]]), ts: u32::from_be_bytes(p[4..8].try_into().unwrap()), ssrc: u32::from_be_bytes(p[8..12].try_into().unwrap()), payload: pt })
}

/// IP discovery request: type 1, length 70, SSRC, 64-byte address, port.
pub fn discovery_request(ssrc: u32) -> [u8; 74] {
    let mut b = [0u8; 74];
    b[..2].copy_from_slice(&1u16.to_be_bytes());
    b[2..4].copy_from_slice(&70u16.to_be_bytes());
    b[4..8].copy_from_slice(&ssrc.to_be_bytes());
    b
}

pub fn discovery_response(b: &[u8]) -> Option<(String, u16)> {
    if b.len() < 74 || b[..2] != [0, 2] {
        return None;
    }
    let addr = &b[8..72];
    let end = addr.iter().position(|c| *c == 0).unwrap_or(64);
    Some((String::from_utf8(addr[..end].to_vec()).ok()?, u16::from_be_bytes([b[72], b[73]])))
}

// ---------------------------------------------------------------- Ogg / Opus

/// Opus packets from an Ogg stream (header packets skipped).
pub struct OggReader<R: Read> {
    r: R,
    queue: VecDeque<Vec<u8>>,
    partial: Vec<u8>,
}

impl<R: Read> OggReader<R> {
    pub fn new(r: R) -> Self {
        OggReader { r, queue: VecDeque::new(), partial: Vec::new() }
    }

    pub fn next_packet(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(p) = self.queue.pop_front() {
                if p.starts_with(b"OpusHead") || p.starts_with(b"OpusTags") {
                    continue;
                }
                return Ok(Some(p));
            }
            let mut h = [0u8; 27];
            match self.r.read_exact(&mut h) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e),
            }
            if &h[..4] != b"OggS" {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "not an Ogg page"));
            }
            let mut segs = vec![0u8; h[26] as usize];
            self.r.read_exact(&mut segs)?;
            let mut data = vec![0u8; segs.iter().map(|s| *s as usize).sum()];
            self.r.read_exact(&mut data)?;
            if h[5] & 1 == 0 {
                self.partial.clear();
            }
            let mut off = 0;
            for s in segs {
                self.partial.extend_from_slice(&data[off..off + s as usize]);
                off += s as usize;
                if s < 255 {
                    self.queue.push_back(std::mem::take(&mut self.partial));
                }
            }
        }
    }
}

fn ogg_crc(data: &[u8]) -> u32 {
    let mut crc = 0u32;
    for b in data {
        crc ^= (*b as u32) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 { (crc << 1) ^ 0x04C1_1DB7 } else { crc << 1 };
        }
    }
    crc
}

fn ogg_page(out: &mut Vec<u8>, flags: u8, granule: u64, seq: u32, packet: &[u8]) {
    let mut segs = vec![255u8; packet.len() / 255];
    segs.push((packet.len() % 255) as u8);
    let start = out.len();
    out.extend_from_slice(b"OggS\0");
    out.push(flags);
    out.extend_from_slice(&granule.to_le_bytes());
    out.extend_from_slice(&0x6172_6b21u32.to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.push(segs.len() as u8);
    out.extend_from_slice(&segs);
    out.extend_from_slice(packet);
    let crc = ogg_crc(&out[start..]);
    out[start + 22..start + 26].copy_from_slice(&crc.to_le_bytes());
}

/// Samples (at 48 kHz) in one Opus packet, from its TOC byte (RFC 6716 §3.1).
pub fn opus_samples(p: &[u8]) -> u32 {
    let Some(toc) = p.first() else { return 0 };
    let config = toc >> 3;
    let frame = match config {
        0..=11 => [480, 960, 1920, 2880][(config % 4) as usize],
        12..=15 => [480, 960][(config % 2) as usize],
        _ => [120, 240, 480, 960][(config % 4) as usize],
    };
    let frames = match toc & 3 {
        0 => 1,
        1 | 2 => 2,
        _ => p.get(1).map_or(0, |b| (b & 0x3f) as u32),
    };
    frame * frames
}

/// Wrap stereo Opus packets in an Ogg Opus stream (RFC 7845) for ffmpeg.
pub fn ogg_opus(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut head = b"OpusHead\x01\x02".to_vec();
    head.extend_from_slice(&0u16.to_le_bytes());
    head.extend_from_slice(&48_000u32.to_le_bytes());
    head.extend_from_slice(&[0, 0, 0]);
    ogg_page(&mut out, 2, 0, 0, &head);
    let mut tags = b"OpusTags".to_vec();
    tags.extend_from_slice(&3u32.to_le_bytes());
    tags.extend_from_slice(b"seagent");
    tags.extend_from_slice(&0u32.to_le_bytes());
    ogg_page(&mut out, 0, 0, 1, &tags);
    let mut granule = 0u64;
    for (i, p) in packets.iter().enumerate() {
        granule += opus_samples(p) as u64;
        ogg_page(&mut out, if i + 1 == packets.len() { 4 } else { 0 }, granule, i as u32 + 2, p);
    }
    out
}

/// 16-bit PCM → RIFF WAV.
pub fn wav(pcm: &[u8], rate: u32, channels: u16) -> Vec<u8> {
    let mut w = b"RIFF".to_vec();
    w.extend_from_slice(&(36 + pcm.len() as u32).to_le_bytes());
    w.extend_from_slice(b"WAVEfmt ");
    w.extend_from_slice(&16u32.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&channels.to_le_bytes());
    w.extend_from_slice(&rate.to_le_bytes());
    w.extend_from_slice(&(rate * channels as u32 * 2).to_le_bytes());
    w.extend_from_slice(&(channels * 2).to_le_bytes());
    w.extend_from_slice(&16u16.to_le_bytes());
    w.extend_from_slice(b"data");
    w.extend_from_slice(&(pcm.len() as u32).to_le_bytes());
    w.extend_from_slice(pcm);
    w
}

// ---------------------------------------------------------------- ffmpeg

/// Run ffmpeg with `args`, feeding `input` to stdin; stdout on success.
pub fn ffmpeg(bin: &str, args: &[&str], input: Option<Vec<u8>>, timeout: Duration) -> Result<Vec<u8>, String> {
    let mut child = seagent_core::platform::proc::command(bin)
        .args(["-hide_banner", "-loglevel", "error"])
        .args(args)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {bin}: {e} (voice needs ffmpeg with libopus)"))?;
    let writer = input.zip(child.stdin.take()).map(|(data, mut stdin)| std::thread::spawn(move || stdin.write_all(&data)));
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = stdout.read_to_end(&mut b);
        b
    });
    let err_reader = std::thread::spawn(move || {
        let mut b = String::new();
        let _ = stderr.read_to_string(&mut b);
        b
    });
    let until = Instant::now() + timeout;
    let status = loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            break s;
        }
        if Instant::now() > until {
            let _ = child.kill();
            let _ = child.wait();
            return Err("ffmpeg timed out".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if let Some(w) = writer {
        let _ = w.join();
    }
    let out = reader.join().unwrap_or_default();
    let err = err_reader.join().unwrap_or_default();
    if !status.success() {
        return Err(format!("ffmpeg failed ({status}): {}", err.trim().chars().take(300).collect::<String>()));
    }
    Ok(out)
}

/// Any audio file or byte buffer → 48 kHz stereo s16le.
pub fn decode_to_pcm(bin: &str, path: Option<&str>, data: Option<Vec<u8>>) -> Result<Vec<u8>, String> {
    let input = path.unwrap_or("pipe:0");
    ffmpeg(bin, &["-i", input, "-f", "s16le", "-ar", "48000", "-ac", "2", "pipe:1"], data, Duration::from_secs(60))
}

/// Received Opus frames → 16 kHz mono s16le (what speech-to-text wants).
pub fn opus_to_pcm16k(bin: &str, frames: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    ffmpeg(bin, &["-f", "ogg", "-i", "pipe:0", "-f", "s16le", "-ar", "16000", "-ac", "1", "pipe:1"], Some(ogg_opus(frames)), Duration::from_secs(30))
}

fn rms(pcm: &[u8]) -> f64 {
    let n = pcm.len() / 2;
    if n == 0 {
        return 0.0;
    }
    (pcm.as_chunks::<2>().0.iter().map(|c| (i16::from_le_bytes(*c) as f64).powi(2)).sum::<f64>() / n as f64).sqrt()
}

// ---------------------------------------------------------------- mixer

struct Clip {
    pcm: Vec<i16>,
    pos: usize,
    gain: f32,
}

/// Sums every playing clip into 20 ms frames, clamped to i16 (Hermes VoiceMixer, minus the ambient bed).
#[derive(Default)]
pub struct Mixer {
    clips: Mutex<Vec<Clip>>,
}

impl Mixer {
    pub fn play(&self, pcm: &[u8], gain: f32) {
        let pcm: Vec<i16> = pcm.as_chunks::<2>().0.iter().map(|c| i16::from_le_bytes(*c)).collect();
        if !pcm.is_empty() {
            self.clips.lock().unwrap().push(Clip { pcm, pos: 0, gain });
        }
    }
    pub fn stop(&self) {
        self.clips.lock().unwrap().clear();
    }
    pub fn active(&self) -> bool {
        !self.clips.lock().unwrap().is_empty()
    }
    /// The next mixed frame, or None when nothing is playing.
    pub fn frame(&self) -> Option<Vec<u8>> {
        let mut clips = self.clips.lock().unwrap();
        if clips.is_empty() {
            return None;
        }
        let mut acc = vec![0f32; FRAME_BYTES / 2];
        for c in clips.iter_mut() {
            let end = (c.pos + acc.len()).min(c.pcm.len());
            for (a, s) in acc.iter_mut().zip(&c.pcm[c.pos..end]) {
                *a += *s as f32 * c.gain;
            }
            c.pos = end;
        }
        clips.retain(|c| c.pos < c.pcm.len());
        Some(acc.iter().flat_map(|a| (a.clamp(-32768.0, 32767.0) as i16).to_le_bytes()).collect())
    }
}

// ---------------------------------------------------------------- receiving

#[derive(Debug, Clone)]
pub struct Utterance {
    pub ssrc: u32,
    pub user: u64,
    pub frames: Vec<Vec<u8>>,
}

struct Stream {
    frames: Vec<Vec<u8>>,
    voiced: u32,
    first: Instant,
    last: Instant,
}

/// Voice-activity segmentation by packet timing: Discord stops sending when a user is silent.
pub struct Receiver {
    streams: HashMap<u32, Stream>,
    pub silence: Duration,
    pub min_speech: Duration,
    pub max_len: Duration,
}

impl Receiver {
    pub fn new(silence: Duration, min_speech: Duration) -> Receiver {
        Receiver { streams: HashMap::new(), silence, min_speech, max_len: Duration::from_secs(60) }
    }

    pub fn push(&mut self, ssrc: u32, frame: Vec<u8>, now: Instant) {
        let s = self.streams.entry(ssrc).or_insert_with(|| Stream { frames: vec![], voiced: 0, first: now, last: now });
        if frame != OPUS_SILENCE {
            s.voiced += opus_samples(&frame);
            s.frames.push(frame);
        }
        s.last = now;
    }

    /// Utterances that ended (silence) or grew too long; `user` maps SSRCs to users.
    pub fn take_done(&mut self, now: Instant, user: impl Fn(u32) -> Option<u64>) -> Vec<Utterance> {
        let mut out = Vec::new();
        self.streams.retain(|ssrc, s| {
            let quiet = now.duration_since(s.last) >= self.silence;
            if !(quiet || now.duration_since(s.first) >= self.max_len) {
                return true;
            }
            if Duration::from_millis(s.voiced as u64 / 48) >= self.min_speech {
                if let Some(u) = user(*ssrc) {
                    out.push(Utterance { ssrc: *ssrc, user: u, frames: std::mem::take(&mut s.frames) });
                }
            }
            false
        });
        out
    }

    pub fn clear(&mut self) {
        self.streams.clear();
    }
}

// ---------------------------------------------------------------- speech services

/// A speech service for the voice channel (`[channels.x.stt]` / `[channels.x.tts]`).
///
/// `engine` (gen1-309):
/// * `"http"` (default) — an OpenAI-compatible endpoint at `url`;
/// * `"realtime"` — seagent's realtime transcription providers (`[media.realtime]`: OpenAI,
///   Deepgram, ElevenLabs, Mistral, xAI) streamed per utterance; `provider` picks one
///   (default `[media.realtime] stt_provider`). For TTS it means seagent's `[media.tts]` stack;
/// * `"media"` — seagent's batch `[media.stt]` / `[media.tts]` providers (`provider` = an STT id).
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Speech {
    /// API base (`https://api.openai.com/v1`) or the full endpoint URL (`engine = "http"`).
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub engine: Option<String>,
    /// Provider id/alias for `engine = "realtime" | "media"`.
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    /// TTS voice.
    #[serde(default)]
    pub voice: Option<String>,
    /// STT language hint (ISO 639-1).
    #[serde(default)]
    pub language: Option<String>,
    /// TTS `response_format` (default opus).
    #[serde(default)]
    pub format: Option<String>,
}

impl Speech {
    fn endpoint(&self, path: &str) -> String {
        let u = self.url.trim_end_matches('/');
        if u.ends_with(path) {
            u.to_string()
        } else {
            format!("{u}{path}")
        }
    }

    fn engine(&self) -> &str {
        self.engine.as_deref().map(str::trim).filter(|e| !e.is_empty()).unwrap_or("http")
    }

    fn media(&self) -> Result<std::sync::Arc<seagent_media::Media>, ChannelError> {
        seagent_media::shared().ok_or_else(|| ChannelError::new(K::Fatal, format!("speech engine `{}` needs seagent's [media] stack, which is not running in this process", self.engine())))
    }

    /// One utterance through a realtime transcription provider: stream the PCM in 20 ms frames,
    /// finish, and join the final segments.
    fn transcribe_realtime(&self, wav: &[u8]) -> Result<String, ChannelError> {
        let m = self.media()?;
        let pcm = seagent_media::audio::wav_decode(wav).map_err(|e| ChannelError::new(K::Protocol, e))?;
        let ch = pcm.channels.max(1) as usize;
        let mono: Vec<i16> = if ch == 1 { pcm.samples } else { pcm.samples.chunks(ch).map(|f| (f.iter().map(|&x| x as i32).sum::<i32>() / f.len() as i32) as i16).collect() };
        let fail = |e: String| ChannelError::new(K::Network, format!("realtime STT: {e}"));
        let mut s = seagent_media::realtime::open_stt(&m, self.provider.as_deref(), pcm.sample_rate, self.language.as_deref()).map_err(fail)?;
        let mut events = vec![];
        let frame = (pcm.sample_rate as usize / 50).max(1);
        for chunk in mono.chunks(frame) {
            s.send_audio(chunk).map_err(fail)?;
            events.extend(s.poll().map_err(fail)?);
        }
        events.extend(s.finish().map_err(fail)?);
        let mut out = vec![];
        for e in events {
            match e {
                seagent_media::realtime::SttEvent::Final(t) if !t.trim().is_empty() => out.push(t.trim().to_string()),
                seagent_media::realtime::SttEvent::Error(e) => return Err(fail(e)),
                _ => {}
            }
        }
        Ok(out.join(" "))
    }

    pub fn transcribe(&self, wav: &[u8]) -> Result<String, ChannelError> {
        match self.engine() {
            "realtime" => return self.transcribe_realtime(wav),
            "media" => {
                let m = self.media()?;
                let req = seagent_media::stt::SttRequest::new(wav.to_vec(), "audio/wav");
                let r = match self.provider.as_deref() {
                    Some(p) => seagent_media::stt::transcribe_with(&m, p, &req, &Cancel::new()),
                    None => seagent_media::stt::transcribe(&m, &req, &Cancel::new()),
                };
                return r.map(|(_, t)| t.text.trim().to_string()).map_err(|e| ChannelError::new(K::Network, format!("STT: {e}")));
            }
            "http" => {}
            other => return Err(ChannelError::new(K::Fatal, format!("unknown speech engine `{other}` (http, realtime, media)"))),
        }
        let model = self.model.clone().unwrap_or_else(|| "whisper-1".into());
        let mut parts: Vec<(&str, &str, &str, &[u8])> = vec![("model", "", "", model.as_bytes()), ("response_format", "", "", b"json"), ("file", "speech.wav", "audio/wav", wav)];
        if let Some(l) = &self.language {
            parts.push(("language", "", "", l.as_bytes()));
        }
        let mut http = crate::http::Http::new(Duration::from_secs(120));
        if let Some(k) = self.key.as_deref().filter(|k| !k.is_empty()) {
            http = http.bearer(k);
        }
        let v = http.json("POST", &self.endpoint("/audio/transcriptions"), crate::http::Payload::Multipart(&parts))?;
        Ok(v["text"].as_str().unwrap_or("").trim().to_string())
    }

    pub fn synthesize(&self, text: &str) -> Result<Vec<u8>, ChannelError> {
        match self.engine() {
            "realtime" | "media" => {
                let m = self.media()?;
                let mut req = seagent_media::tts::TtsRequest::new(text);
                req.voice = self.voice.clone();
                req.model = self.model.clone();
                req.format = Some(self.format.clone().unwrap_or_else(|| "opus".into()));
                let (_, sp) = seagent_media::tts::synthesize(&m, &req, &Cancel::new()).map_err(|e| ChannelError::new(K::Network, format!("TTS: {e}")))?;
                return Ok(sp.audio.bytes);
            }
            "http" => {}
            other => return Err(ChannelError::new(K::Fatal, format!("unknown speech engine `{other}` (http, realtime, media)"))),
        }
        let body = json!({
            "model": self.model.clone().unwrap_or_else(|| "tts-1".into()),
            "input": text,
            "voice": self.voice.clone().unwrap_or_else(|| "alloy".into()),
            "response_format": self.format.clone().unwrap_or_else(|| "opus".into()),
        });
        let agent = crate::http::agent(Duration::from_secs(120));
        let mut r = agent.post(&self.endpoint("/audio/speech")).header("content-type", "application/json");
        if let Some(k) = self.key.as_deref().filter(|k| !k.is_empty()) {
            r = r.header("authorization", &format!("Bearer {k}"));
        }
        let mut resp = r.send(body.to_string().as_bytes()).map_err(|e| ChannelError::new(K::Network, format!("TTS request failed: {}", crate::http::redact(&e.to_string()))))?;
        let status = resp.status().as_u16();
        let mut b = Vec::new();
        resp.body_mut().with_config().limit(u64::MAX).reader().take(50 * 1024 * 1024).read_to_end(&mut b).map_err(|e| ChannelError::new(K::Network, format!("reading TTS audio: {e}")))?;
        if !(200..300).contains(&status) {
            return Err(crate::http::classify(status, None, "TTS", &String::from_utf8_lossy(&b)));
        }
        Ok(b)
    }
}

/// Whisper's stock outputs for silence and noise (Hermes `is_whisper_hallucination`).
pub fn is_hallucination(t: &str) -> bool {
    let n: String = t.to_lowercase().chars().filter(|c| c.is_alphanumeric() || c.is_whitespace() || !c.is_ascii()).filter(|c| !"。，！？、．…「」".contains(*c)).collect();
    let n = n.trim();
    n.is_empty()
        || [
            "you",
            "thank you",
            "thanks for watching",
            "thank you for watching",
            "thank you so much for watching",
            "please subscribe",
            "bye",
            "謝謝觀看",
            "谢谢观看",
            "謝謝收看",
            "字幕由amaraorg社群提供",
            "ご視聴ありがとうございました",
            "請不吝點贊 訂閱 轉發 打賞支持明鏡與點點欄目",
        ]
        .contains(&n)
}

/// Markdown → something a TTS voice can read.
pub fn speakable(text: &str) -> String {
    let mut out = String::new();
    let mut in_code = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            in_code = !in_code;
            continue;
        }
        if in_code {
            continue;
        }
        let l = line.trim_start_matches(['#', '>', '-', '*', ' ']).replace(['*', '_', '`', '~'], "");
        if !l.trim().is_empty() {
            out.push_str(l.trim());
            out.push('\n');
        }
    }
    out.trim().chars().take(4000).collect()
}

// ---------------------------------------------------------------- configuration

#[derive(Debug, Clone)]
pub struct VoiceConfig {
    pub stt: Option<Speech>,
    pub tts: Option<Speech>,
    pub ffmpeg: String,
    pub silence: Duration,
    pub min_speech: Duration,
    /// Leave after this long without speech or playback (0 = never).
    pub idle: Duration,
    /// Post `🎙️ <@user>: transcript` in the bound text channel.
    pub echo: bool,
    pub bitrate: u32,
    pub connect_timeout: Duration,
    /// Persistent DAVE signature key (None = a fresh key per call).
    pub dave_signer: Option<Arc<Signer>>,
}

impl Default for VoiceConfig {
    fn default() -> Self {
        VoiceConfig {
            stt: None,
            tts: None,
            ffmpeg: "ffmpeg".into(),
            silence: Duration::from_millis(1500),
            min_speech: Duration::from_millis(500),
            idle: Duration::from_secs(300),
            echo: true,
            bitrate: 64_000,
            connect_timeout: Duration::from_secs(20),
            dave_signer: None,
        }
    }
}

// ---------------------------------------------------------------- one voice connection

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceServer {
    pub guild: u64,
    pub channel: u64,
    pub user: u64,
    pub session_id: String,
    pub token: String,
    pub endpoint: String,
}

struct Transport {
    mode: Mode,
    key: [u8; 32],
    ssrc: u32,
    udp: Arc<UdpSocket>,
    seq: u16,
    ts: u32,
    counter: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Status {
    Connecting,
    Ready,
    Failed(String),
}

enum Event {
    Utterance(u64, Utterance),
    Closed(u64, String),
}

/// A live voice connection in one guild.
pub struct Conn {
    cfg: Arc<VoiceConfig>,
    server: VoiceServer,
    stop: Cancel,
    transport: Mutex<Option<Transport>>,
    dave: Mutex<Dave>,
    ssrc_users: Mutex<HashMap<u32, u64>>,
    receiver: Mutex<Receiver>,
    pub mixer: Mixer,
    outbox: Mutex<Vec<Value>>,
    status: Mutex<Status>,
    cv: Condvar,
    playing: AtomicBool,
    last_activity: Mutex<Instant>,
    events: mpsc::Sender<Event>,
    /// Other members in the voice channel (for SSRCs without a Speaking event).
    members: Mutex<Vec<u64>>,
}

enum WsEnd {
    Stop,
    Resume,
    Identify,
    Fatal(String),
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn new_dave(cfg: &VoiceConfig, server: &VoiceServer) -> Dave {
    match &cfg.dave_signer {
        Some(s) => Dave::with_signer(server.user, server.channel, s.clone()),
        None => Dave::new(server.user, server.channel),
    }
}

fn snowflake(v: &Value) -> Option<u64> {
    v.as_str().and_then(|s| s.parse().ok()).or_else(|| v.as_u64())
}

impl Conn {
    fn new(cfg: Arc<VoiceConfig>, server: VoiceServer, events: mpsc::Sender<Event>) -> Arc<Conn> {
        let rx = Receiver::new(cfg.silence, cfg.min_speech);
        Arc::new(Conn {
            dave: Mutex::new(new_dave(&cfg, &server)),
            cfg,
            server,
            stop: Cancel::new(),
            transport: Mutex::new(None),
            ssrc_users: Mutex::new(HashMap::new()),
            receiver: Mutex::new(rx),
            mixer: Mixer::default(),
            outbox: Mutex::new(vec![]),
            status: Mutex::new(Status::Connecting),
            cv: Condvar::new(),
            playing: AtomicBool::new(false),
            last_activity: Mutex::new(Instant::now()),
            events,
            members: Mutex::new(vec![]),
        })
    }

    fn set_status(&self, s: Status) {
        *self.status.lock().unwrap() = s;
        self.cv.notify_all();
    }

    /// Wait until the connection is ready (or failed).
    pub fn wait_ready(&self, timeout: Duration) -> Result<(), String> {
        let until = Instant::now() + timeout;
        let mut st = self.status.lock().unwrap();
        loop {
            match &*st {
                Status::Ready => return Ok(()),
                Status::Failed(e) => return Err(e.clone()),
                Status::Connecting => {}
            }
            let now = Instant::now();
            if now >= until {
                return Err("timed out connecting to the voice server".into());
            }
            st = self.cv.wait_timeout(st, until - now).unwrap().0;
        }
    }

    pub fn ready(&self) -> bool {
        *self.status.lock().unwrap() == Status::Ready
    }

    pub fn ssrc(&self) -> Option<u32> {
        self.transport.lock().unwrap().as_ref().map(|t| t.ssrc)
    }

    pub fn e2ee(&self) -> bool {
        self.dave.lock().unwrap().active()
    }

    pub fn privacy_code(&self) -> Option<String> {
        self.dave.lock().unwrap().verification_code()
    }

    pub fn pairwise_code(&self, user: u64) -> Option<String> {
        self.dave.lock().unwrap().pairwise_code(user)
    }

    fn touch(&self) {
        *self.last_activity.lock().unwrap() = Instant::now();
    }

    fn url(&self) -> String {
        let ep = self.server.endpoint.trim_end_matches('/');
        let base = if ep.starts_with("ws://") || ep.starts_with("wss://") { ep.to_string() } else { format!("wss://{ep}") };
        format!("{base}/?v=8")
    }

    /// Reconnect loop: resume on drops, re-identify when the session is gone.
    fn run(self: &Arc<Self>) {
        let mut resume = false;
        let mut seq: i64 = -1;
        let mut failures = 0u32;
        while !self.stop.is_cancelled() {
            let end = self.run_ws(resume, &mut seq);
            let (again, why) = match end {
                WsEnd::Stop => return,
                WsEnd::Fatal(e) => {
                    self.set_status(Status::Failed(e.clone()));
                    let _ = self.events.send(Event::Closed(self.server.guild, e));
                    self.stop.cancel();
                    return;
                }
                WsEnd::Resume => (true, "resume"),
                WsEnd::Identify => (false, "identify"),
            };
            failures += 1;
            if failures > 6 {
                let e = format!("voice connection keeps failing (last: {why})");
                self.set_status(Status::Failed(e.clone()));
                let _ = self.events.send(Event::Closed(self.server.guild, e));
                self.stop.cancel();
                return;
            }
            resume = again && self.transport.lock().unwrap().is_some();
            if !resume {
                *self.transport.lock().unwrap() = None;
                *self.dave.lock().unwrap() = new_dave(&self.cfg, &self.server);
            }
            if !sleep_cancellable(Duration::from_millis(250 * failures as u64), &self.stop) {
                return;
            }
        }
    }

    fn send_out(&self, ws: &mut WebSocket<seagent_net::Stream>, outs: Vec<Out>) -> bool {
        outs.into_iter().all(|o| match o {
            Out::Json(v) => ws.send_text(&v.to_string()).is_ok(),
            Out::Binary(b) => ws.send(&Message::Binary(b)).is_ok(),
        })
    }

    fn run_ws(self: &Arc<Self>, resume: bool, seq: &mut i64) -> WsEnd {
        let Ok((mut ws, _)) = WebSocket::connect(&self.url(), &[], Duration::from_secs(10)) else { return WsEnd::Resume };
        if ws.set_read_timeout(Some(Duration::from_millis(50))).is_err() {
            return WsEnd::Resume;
        }
        let s = &self.server;
        let mut heartbeat: Option<(Duration, Instant)> = None;
        let mut acked = true;
        loop {
            if self.stop.is_cancelled() {
                let _ = ws.send(&Message::Close(Some((1000, "leaving".into()))));
                return WsEnd::Stop;
            }
            if let Some((every, next)) = heartbeat {
                if Instant::now() >= next {
                    if !acked {
                        return WsEnd::Resume;
                    }
                    if ws.send_text(&json!({"op": 3, "d": {"t": now_ms(), "seq_ack": seq}}).to_string()).is_err() {
                        return WsEnd::Resume;
                    }
                    acked = false;
                    heartbeat = Some((every, Instant::now() + every));
                }
            }
            let queued: Vec<Value> = std::mem::take(&mut *self.outbox.lock().unwrap());
            for v in queued {
                if ws.send_text(&v.to_string()).is_err() {
                    return WsEnd::Resume;
                }
            }
            let msg = match ws.recv() {
                Ok(None) => continue,
                Ok(Some(m)) => m,
                Err(_) => return WsEnd::Resume,
            };
            let outs = match msg {
                Message::Text(t) => {
                    let Ok(p) = serde_json::from_str::<Value>(&t) else { continue };
                    if let Some(n) = p["seq"].as_i64() {
                        *seq = n;
                    }
                    let d = &p["d"];
                    match p["op"].as_u64() {
                        Some(8) => {
                            let every = Duration::from_millis(d["heartbeat_interval"].as_f64().unwrap_or(13_750.0).max(10.0) as u64);
                            heartbeat = Some((every, Instant::now() + every));
                            let m = if resume {
                                json!({"op": 7, "d": {"server_id": s.guild.to_string(), "session_id": s.session_id, "token": s.token, "seq_ack": seq}})
                            } else {
                                json!({"op": 0, "d": {"server_id": s.guild.to_string(), "user_id": s.user.to_string(), "session_id": s.session_id, "token": s.token, "max_dave_protocol_version": crate::dave::MAX_PROTOCOL_VERSION}})
                            };
                            vec![Out::Json(m)]
                        }
                        Some(2) => match self.on_ready(d) {
                            Ok(m) => vec![Out::Json(m)],
                            Err(e) => return WsEnd::Fatal(e),
                        },
                        Some(4) => match self.on_session_description(d) {
                            Ok(o) => o,
                            Err(e) => return WsEnd::Fatal(e),
                        },
                        Some(6) => {
                            acked = true;
                            vec![]
                        }
                        Some(9) => {
                            self.set_status(Status::Ready);
                            vec![]
                        }
                        Some(5) => {
                            if let (Some(u), Some(ssrc)) = (snowflake(&d["user_id"]), d["ssrc"].as_u64()) {
                                self.ssrc_users.lock().unwrap().insert(ssrc as u32, u);
                            }
                            vec![]
                        }
                        Some(11) => {
                            let ids: Vec<u64> = d["user_ids"].as_array().into_iter().flatten().filter_map(snowflake).collect();
                            self.members.lock().unwrap().extend(ids.iter().copied().filter(|u| *u != s.user));
                            self.dave.lock().unwrap().on_clients_connect(&ids);
                            vec![]
                        }
                        Some(13) => {
                            if let Some(u) = snowflake(&d["user_id"]) {
                                self.members.lock().unwrap().retain(|m| *m != u);
                                self.ssrc_users.lock().unwrap().retain(|_, v| *v != u);
                                self.dave.lock().unwrap().on_client_disconnect(u);
                            }
                            vec![]
                        }
                        Some(21) => self.dave.lock().unwrap().on_prepare_transition(d["transition_id"].as_u64().unwrap_or(0) as u16, d["protocol_version"].as_u64().unwrap_or(0) as u16),
                        Some(22) => {
                            self.dave.lock().unwrap().on_execute_transition(d["transition_id"].as_u64().unwrap_or(0) as u16);
                            vec![]
                        }
                        Some(24) => self.dave.lock().unwrap().on_prepare_epoch(d["epoch"].as_u64().unwrap_or(0), d["protocol_version"].as_u64().unwrap_or(0) as u16),
                        _ => vec![],
                    }
                }
                Message::Binary(b) if b.len() >= 3 => {
                    *seq = u16::from_be_bytes([b[0], b[1]]) as i64;
                    let payload = &b[3..];
                    let mut dave = self.dave.lock().unwrap();
                    match b[2] {
                        25 => {
                            if let Err(e) = dave.on_external_sender(payload) {
                                dave.errors.push(e);
                            }
                            vec![]
                        }
                        27 => dave.on_proposals(payload).unwrap_or_else(|e| {
                            dave.errors.push(e);
                            vec![]
                        }),
                        29 => dave.on_announce_commit(payload).1,
                        30 => dave.on_welcome(payload).1,
                        _ => vec![],
                    }
                }
                Message::Close(c) => {
                    let code = c.map(|(c, _)| c).unwrap_or(1006);
                    return match code {
                        4006 | 4009 => WsEnd::Identify,
                        4004 => WsEnd::Fatal("voice gateway rejected the token (4004)".into()),
                        4014 => WsEnd::Fatal("disconnected from the voice channel (4014)".into()),
                        4016 => WsEnd::Fatal("voice encryption mode refused (4016)".into()),
                        4017 => WsEnd::Fatal("voice gateway requires DAVE end-to-end encryption (4017)".into()),
                        4021 | 4022 => WsEnd::Fatal(format!("voice call ended ({code})")),
                        _ => WsEnd::Resume,
                    };
                }
                _ => vec![],
            };
            if !self.send_out(&mut ws, outs) {
                return WsEnd::Resume;
            }
        }
    }

    /// Ready: UDP socket, IP discovery, Select Protocol.
    fn on_ready(self: &Arc<Self>, d: &Value) -> Result<Value, String> {
        let ssrc = d["ssrc"].as_u64().ok_or("voice ready without ssrc")? as u32;
        let ip = d["ip"].as_str().ok_or("voice ready without ip")?;
        let port = d["port"].as_u64().ok_or("voice ready without port")? as u16;
        let modes: Vec<String> = d["modes"].as_array().into_iter().flatten().filter_map(|m| m.as_str().map(str::to_string)).collect();
        let mode = Mode::choose(&modes).ok_or_else(|| format!("no supported voice encryption mode in {modes:?}"))?;
        let udp = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("udp bind: {e}"))?;
        udp.connect((ip, port)).map_err(|e| format!("udp connect {ip}:{port}: {e}"))?;
        udp.set_read_timeout(Some(Duration::from_millis(1000))).map_err(|e| e.to_string())?;
        let mut found = None;
        for _ in 0..5 {
            let _ = udp.send(&discovery_request(ssrc));
            let mut b = [0u8; 128];
            if let Ok(n) = udp.recv(&mut b) {
                found = discovery_response(&b[..n]);
                if found.is_some() {
                    break;
                }
            }
        }
        let (my_ip, my_port) = found.ok_or("UDP IP discovery got no answer")?;
        udp.set_read_timeout(Some(Duration::from_millis(100))).map_err(|e| e.to_string())?;
        let udp = Arc::new(udp);
        *self.transport.lock().unwrap() = Some(Transport { mode, key: [0; 32], ssrc, udp: udp.clone(), seq: rand16(), ts: rand16() as u32 * 65536, counter: 0 });
        let me = self.clone();
        let _ = std::thread::Builder::new().name("discord voice udp".into()).spawn(move || me.udp_loop(udp));
        Ok(json!({"op": 1, "d": {"protocol": "udp", "data": {"address": my_ip, "port": my_port, "mode": mode.name()}}}))
    }

    fn on_session_description(&self, d: &Value) -> Result<Vec<Out>, String> {
        let key: Vec<u8> = d["secret_key"].as_array().ok_or("session description without secret_key")?.iter().map(|b| b.as_u64().unwrap_or(0) as u8).collect();
        let key: [u8; 32] = key.try_into().map_err(|_| "secret_key is not 32 bytes")?;
        let mode = d["mode"].as_str().unwrap_or("");
        {
            let mut t = self.transport.lock().unwrap();
            let t = t.as_mut().ok_or("session description before ready")?;
            if mode != t.mode.name() {
                return Err(format!("voice server picked an unexpected mode {mode}"));
            }
            t.key = key;
        }
        let out = self.dave.lock().unwrap().on_session_description(d["dave_protocol_version"].as_u64().unwrap_or(0) as u16);
        self.set_status(Status::Ready);
        self.touch();
        Ok(out)
    }

    fn user_for(&self, ssrc: u32) -> Option<u64> {
        if let Some(u) = self.ssrc_users.lock().unwrap().get(&ssrc) {
            return Some(*u);
        }
        // After a rejoin Discord may not resend Speaking: the sole other member must be the speaker.
        let m = self.members.lock().unwrap();
        (m.len() == 1).then(|| m[0])
    }

    fn udp_loop(self: Arc<Self>, udp: Arc<UdpSocket>) {
        let mut buf = vec![0u8; 2048];
        let mut keepalive = Instant::now();
        let mut ka_counter = 0u32;
        while !self.stop.is_cancelled() {
            let current = self.transport.lock().unwrap().as_ref().is_some_and(|t| Arc::ptr_eq(&t.udp, &udp));
            if !current {
                return;
            }
            if keepalive.elapsed() >= Duration::from_secs(5) {
                keepalive = Instant::now();
                ka_counter = ka_counter.wrapping_add(1);
                let mut b = [0u8; 8];
                b[..4].copy_from_slice(&ka_counter.to_le_bytes());
                let _ = udp.send(&b);
            }
            if let Ok(n) = udp.recv(&mut buf) {
                self.on_packet(&buf[..n]);
            }
            let done = self.receiver.lock().unwrap().take_done(Instant::now(), |s| self.user_for(s));
            for u in done {
                let _ = self.events.send(Event::Utterance(self.server.guild, u));
            }
            if !self.cfg.idle.is_zero() && self.last_activity.lock().unwrap().elapsed() > self.cfg.idle && !self.playing.load(Ordering::SeqCst) {
                let _ = self.events.send(Event::Closed(self.server.guild, "idle".into()));
                return;
            }
        }
    }

    fn on_packet(&self, p: &[u8]) {
        let Some((mode, key, mine)) = self.transport.lock().unwrap().as_ref().map(|t| (t.mode, t.key, t.ssrc)) else { return };
        let Some(rtp) = open_rtp(mode, &key, p) else { return };
        if rtp.ssrc == mine || self.playing.load(Ordering::SeqCst) {
            return;
        }
        let frame = match self.user_for(rtp.ssrc) {
            Some(u) => self.dave.lock().unwrap().decrypt(u, &rtp.payload),
            // Unknown speaker: with E2EE on the payload is still ciphertext; drop it.
            None if self.dave.lock().unwrap().active() => None,
            None => Some(rtp.payload),
        };
        if let Some(f) = frame {
            self.receiver.lock().unwrap().push(rtp.ssrc, f, Instant::now());
            self.touch();
        }
    }

    fn speaking(&self, on: bool) {
        if let Some(ssrc) = self.ssrc() {
            self.outbox.lock().unwrap().push(json!({"op": 5, "d": {"speaking": if on { 1 } else { 0 }, "delay": 0, "ssrc": ssrc}}));
        }
    }

    /// One Opus frame → DAVE → RTP → UDP.
    fn send_opus(&self, opus: &[u8]) {
        let frame = self.dave.lock().unwrap().encrypt(opus);
        let mut t = self.transport.lock().unwrap();
        let Some(t) = t.as_mut() else { return };
        let pkt = rtp_packet(t.mode, &t.key, t.seq, t.ts, t.ssrc, t.counter, &frame);
        t.seq = t.seq.wrapping_add(1);
        t.ts = t.ts.wrapping_add(FRAME_SAMPLES);
        t.counter = t.counter.wrapping_add(1);
        let _ = t.udp.send(&pkt);
    }

    /// Queue 48 kHz stereo PCM and make sure the player runs.
    pub fn play_pcm(self: &Arc<Self>, pcm: &[u8]) {
        self.mixer.play(pcm, 1.0);
        self.touch();
        if !self.playing.swap(true, Ordering::SeqCst) {
            let me = self.clone();
            let _ = std::thread::Builder::new().name("discord voice play".into()).spawn(move || {
                while !me.stop.is_cancelled() && me.mixer.active() {
                    if let Err(e) = me.talk_spurt() {
                        me.mixer.stop();
                        let _ = me.events.send(Event::Closed(0, format!("playback failed: {e}")));
                    }
                }
                me.playing.store(false, Ordering::SeqCst);
                // A clip queued while we were stopping still gets played.
                if me.mixer.active() && !me.stop.is_cancelled() {
                    me.play_pcm(&[]);
                }
            });
        }
    }

    /// Encode the mixer's output until it runs dry; paced at one frame per 20 ms.
    fn talk_spurt(self: &Arc<Self>) -> Result<(), String> {
        let bitrate = self.cfg.bitrate.to_string();
        let mut child = seagent_core::platform::proc::command(&self.cfg.ffmpeg)
            .args(["-hide_banner", "-loglevel", "error", "-f", "s16le", "-ar", "48000", "-ac", "2", "-i", "pipe:0", "-c:a", "libopus", "-b:a", &bitrate, "-frame_duration", "20", "-application", "voip", "-f", "ogg", "-page_duration", "20000", "-flush_packets", "1", "pipe:1"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot run {}: {e}", self.cfg.ffmpeg))?;
        let mut stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        self.speaking(true);
        let me = self.clone();
        let feeder = std::thread::spawn(move || {
            let mut next = Instant::now();
            loop {
                let frame = if me.stop.is_cancelled() { None } else { me.mixer.frame() };
                let Some(f) = frame else { break };
                if stdin.write_all(&f).is_err() {
                    return;
                }
                next += Duration::from_millis(20);
                let now = Instant::now();
                if next > now {
                    std::thread::sleep(next - now);
                }
            }
            // Flush the encoder's lookahead with a little silence.
            let _ = stdin.write_all(&vec![0u8; FRAME_BYTES * 3]);
        });
        let mut ogg = OggReader::new(stdout);
        let mut next = Instant::now();
        let pace = |next: &mut Instant| {
            let now = Instant::now();
            if *next > now {
                std::thread::sleep(*next - now);
            } else if now - *next > Duration::from_millis(100) {
                *next = now;
            }
            *next += Duration::from_millis(20);
        };
        let mut sent = 0;
        while let Ok(Some(p)) = ogg.next_packet() {
            if self.stop.is_cancelled() {
                break;
            }
            pace(&mut next);
            self.send_opus(&p);
            sent += 1;
        }
        let _ = feeder.join();
        let _ = child.wait();
        for _ in 0..5 {
            pace(&mut next);
            self.send_opus(&OPUS_SILENCE);
        }
        self.speaking(false);
        self.touch();
        if sent == 0 {
            return Err("the encoder produced no audio".into());
        }
        Ok(())
    }
}

fn rand16() -> u16 {
    let b = seagent_net::crypto::random_bytes(2);
    u16::from_be_bytes([b[0], b[1]])
}

// ---------------------------------------------------------------- manager (per Discord channel)

/// Where a voice session's transcripts go and replies come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub chat: String,
    pub thread: Option<String>,
    pub chat_name: String,
}

impl Binding {
    fn post_channel(&self) -> &str {
        self.thread.as_deref().unwrap_or(&self.chat)
    }
}

pub struct Session {
    pub guild: u64,
    pub channel: u64,
    pub binding: Mutex<Binding>,
    pub conn: Arc<Conn>,
}

#[derive(Default)]
struct Join {
    channel: u64,
    session_id: Option<String>,
    server: Option<(String, String)>,
    binding: Option<Binding>,
}

pub type GatewaySend = Box<dyn Fn(Value) + Send + Sync>;
pub type Post = Box<dyn Fn(&str, &str) + Send + Sync>;

/// Voice state for one Discord bot: who sits where, pending joins, live sessions.
pub struct VoiceManager {
    pub cfg: Arc<VoiceConfig>,
    channel_name: String,
    me: Mutex<u64>,
    gateway: Mutex<Option<GatewaySend>>,
    post: Mutex<Option<Post>>,
    inbound: Mutex<Option<mpsc::Sender<Inbound>>>,
    /// (guild, user) → (voice channel, display name).
    states: Mutex<HashMap<(u64, u64), (u64, String)>>,
    joins: Mutex<HashMap<u64, Join>>,
    sessions: Mutex<HashMap<u64, Arc<Session>>>,
    events: mpsc::Sender<Event>,
    /// Replies waiting to settle before being spoken (streamed replies grow by edits).
    replies: Mutex<HashMap<String, PendingReply>>,
    spoken: Mutex<VecDeque<String>>,
    /// Live transcript taps (`media.transcripts` sessions, see [`crate::discord_transcripts`]).
    taps: Mutex<Vec<Tap>>,
    next_tap: AtomicU64,
}

/// One `media.transcripts` capture: every recognized line of `(guild, channel)` goes to `sink`.
struct Tap {
    id: u64,
    guild: u64,
    channel: u64,
    sink: HeardSink,
}

/// The capture handle `media.transcripts` stops.
struct TapCapture {
    m: Arc<VoiceManager>,
    id: u64,
    active: bool,
}

impl TranscriptCapture for TapCapture {
    fn stop(&mut self) -> Result<(), String> {
        self.m.remove_tap(self.id);
        self.active = false;
        Ok(())
    }
    fn active(&self) -> bool {
        self.active
    }
}

struct PendingReply {
    chat: String,
    thread: Option<String>,
    text: String,
    at: Instant,
}

/// How long a reply must stay unchanged before it is spoken.
pub const REPLY_SETTLE: Duration = Duration::from_millis(1200);

impl VoiceManager {
    pub fn new(channel_name: &str, cfg: VoiceConfig) -> Arc<VoiceManager> {
        let (tx, rx) = mpsc::channel();
        let m = Arc::new(VoiceManager {
            cfg: Arc::new(cfg),
            channel_name: channel_name.into(),
            me: Mutex::new(0),
            gateway: Mutex::new(None),
            post: Mutex::new(None),
            inbound: Mutex::new(None),
            states: Mutex::new(HashMap::new()),
            joins: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            events: tx,
            replies: Mutex::new(HashMap::new()),
            spoken: Mutex::new(VecDeque::new()),
            taps: Mutex::new(Vec::new()),
            next_tap: AtomicU64::new(1),
        });
        let weak = Arc::downgrade(&m);
        let _ = std::thread::Builder::new().name("discord voice events".into()).spawn(move || event_loop(weak, rx));
        m
    }

    pub fn set_hooks(&self, gateway: GatewaySend, post: Post) {
        *self.gateway.lock().unwrap() = Some(gateway);
        *self.post.lock().unwrap() = Some(post);
    }

    pub fn set_inbound(&self, tx: mpsc::Sender<Inbound>) {
        *self.inbound.lock().unwrap() = Some(tx);
    }

    /// The bot is connected to Discord (`on_ready` ran) and `account` names this bot
    /// (`""` / `default` = the only one). What `media.transcripts` asks before capturing.
    pub fn ready_for_account(&self, account: &str) -> bool {
        let a = account.trim();
        *self.me.lock().unwrap() != 0 && (a.is_empty() || a == "default" || a.eq_ignore_ascii_case(&self.channel_name))
    }

    /// Tap every recognized line of one voice channel (`media.transcripts` capture).
    pub fn open_transcripts(self: &Arc<Self>, guild: u64, channel: u64, sink: HeardSink) -> Box<dyn TranscriptCapture> {
        let id = self.next_tap.fetch_add(1, Ordering::SeqCst);
        self.taps.lock().unwrap().push(Tap { id, guild, channel, sink });
        Box::new(TapCapture { m: self.clone(), id, active: true })
    }

    pub fn remove_tap(&self, id: u64) {
        self.taps.lock().unwrap().retain(|t| t.id != id);
    }

    /// One recognized line of `(guild, channel)`: hand it to the transcript taps. Called with the
    /// channel's STT output, so a `media.transcripts` session sees exactly what the agent sees.
    pub fn heard(&self, guild: u64, channel: u64, speaker: Option<String>, text: &str) {
        if text.trim().is_empty() {
            return;
        }
        let heard = Heard { speaker, text: text.to_string() };
        // Collected first: a sink writes to the transcript store and must not run under our lock.
        let sinks: Vec<HeardSink> = self.taps.lock().unwrap().iter().filter(|t| t.guild == guild && t.channel == channel).map(|t| t.sink.clone()).collect();
        for s in sinks {
            s(heard.clone());
        }
    }

    /// One take → text through the channel's `[channels.<name>.stt]` endpoint, with the whisper
    /// hallucination filter applied. `Err` = nothing usable was said.
    pub fn transcribe_pcm(&self, wav_bytes: &[u8]) -> Result<String, String> {
        let Some(stt) = self.cfg.stt.as_ref() else { return Err("no STT endpoint configured".into()) };
        let text = stt.transcribe(wav_bytes).map_err(|e| e.message)?;
        if is_hallucination(&text) {
            return Err("hallucination".into());
        }
        Ok(text)
    }

    fn send_gateway(&self, v: Value) {
        if let Some(g) = &*self.gateway.lock().unwrap() {
            g(v);
        }
    }

    pub fn post(&self, channel: &str, text: &str) {
        if let Some(p) = &*self.post.lock().unwrap() {
            p(channel, text);
        }
    }

    pub fn on_ready(&self, me: &str) {
        *self.me.lock().unwrap() = me.parse().unwrap_or(0);
    }

    fn note_state(&self, guild: u64, s: &Value) {
        let Some(user) = snowflake(&s["user_id"]) else { return };
        let name = s["member"]["nick"].as_str().or_else(|| s["member"]["user"]["global_name"].as_str()).or_else(|| s["member"]["user"]["username"].as_str()).unwrap_or("").to_string();
        let mut st = self.states.lock().unwrap();
        match snowflake(&s["channel_id"]) {
            Some(c) => {
                st.insert((guild, user), (c, name));
            }
            None => {
                st.remove(&(guild, user));
            }
        }
    }

    /// GUILD_CREATE's `voice_states`.
    pub fn on_guild_create(&self, d: &Value) {
        let Some(g) = snowflake(&d["id"]) else { return };
        for s in d["voice_states"].as_array().into_iter().flatten() {
            self.note_state(g, s);
        }
    }

    pub fn on_voice_state(&self, d: &Value) {
        let Some(guild) = snowflake(&d["guild_id"]) else { return };
        self.note_state(guild, d);
        let me = *self.me.lock().unwrap();
        if snowflake(&d["user_id"]) != Some(me) {
            if let Some(s) = self.sessions.lock().unwrap().get(&guild) {
                let mut members: Vec<u64> = self.states.lock().unwrap().iter().filter(|((g, u), (c, _))| *g == guild && *c == s.channel && *u != me).map(|((_, u), _)| *u).collect();
                members.sort();
                *s.conn.members.lock().unwrap() = members;
            }
            return;
        }
        match snowflake(&d["channel_id"]) {
            None => {
                // We were disconnected (or left): end the session.
                if let Some(s) = self.sessions.lock().unwrap().remove(&guild) {
                    s.conn.stop.cancel();
                }
            }
            Some(c) => {
                let sid = d["session_id"].as_str().unwrap_or("").to_string();
                let mut j = self.joins.lock().unwrap();
                let e = j.entry(guild).or_default();
                e.channel = c;
                e.session_id = Some(sid);
                drop(j);
                self.try_start(guild);
            }
        }
    }

    pub fn on_voice_server(&self, d: &Value) {
        let Some(guild) = snowflake(&d["guild_id"]) else { return };
        let (Some(token), Some(ep)) = (d["token"].as_str(), d["endpoint"].as_str()) else { return };
        self.joins.lock().unwrap().entry(guild).or_default().server = Some((token.into(), ep.into()));
        self.try_start(guild);
    }

    fn try_start(&self, guild: u64) {
        let mut joins = self.joins.lock().unwrap();
        let Some(j) = joins.get(&guild) else { return };
        let (Some(sid), Some((token, endpoint))) = (j.session_id.clone(), j.server.clone()) else { return };
        let j = joins.remove(&guild).unwrap();
        drop(joins);
        let mut sessions = self.sessions.lock().unwrap();
        // A server change (region move) replaces the connection but keeps the binding.
        let binding = match (j.binding, sessions.remove(&guild)) {
            (Some(b), old) => {
                if let Some(o) = old {
                    o.conn.stop.cancel();
                }
                b
            }
            (None, Some(old)) => {
                old.conn.stop.cancel();
                old.binding.lock().unwrap().clone()
            }
            (None, None) => return,
        };
        let server = VoiceServer { guild, channel: j.channel, user: *self.me.lock().unwrap(), session_id: sid, token, endpoint };
        let conn = Conn::new(self.cfg.clone(), server, self.events.clone());
        let members: Vec<u64> = self.states.lock().unwrap().iter().filter(|((g, u), (c, _))| *g == guild && *c == j.channel && *u != conn.server.user).map(|((_, u), _)| *u).collect();
        *conn.members.lock().unwrap() = members;
        let c2 = conn.clone();
        let _ = std::thread::Builder::new().name(format!("discord voice {guild}")).spawn(move || c2.run());
        sessions.insert(guild, Arc::new(Session { guild, channel: j.channel, binding: Mutex::new(binding), conn }));
    }

    /// The voice channel `user` sits in.
    pub fn user_channel(&self, guild: u64, user: u64) -> Option<u64> {
        self.states.lock().unwrap().get(&(guild, user)).map(|(c, _)| *c)
    }

    pub fn session(&self, guild: u64) -> Option<Arc<Session>> {
        self.sessions.lock().unwrap().get(&guild).cloned()
    }

    /// The session whose transcripts go to `chat`.
    pub fn bound(&self, chat: &str, thread: Option<&str>) -> Option<Arc<Session>> {
        self.sessions.lock().unwrap().values().find(|s| {
            let b = s.binding.lock().unwrap();
            b.chat == chat && (thread.is_none() || b.thread.as_deref() == thread)
        }).cloned()
    }

    /// Join (blocking until connected or failed).
    pub fn join(&self, guild: u64, channel: u64, binding: Binding) -> Result<Arc<Session>, String> {
        if let Some(s) = self.session(guild) {
            if s.channel == channel && s.conn.ready() {
                *s.binding.lock().unwrap() = binding;
                return Ok(s);
            }
        }
        self.joins.lock().unwrap().insert(guild, Join { channel, binding: Some(binding), ..Default::default() });
        self.send_gateway(json!({"op": 4, "d": {"guild_id": guild.to_string(), "channel_id": channel.to_string(), "self_mute": false, "self_deaf": false}}));
        let until = Instant::now() + self.cfg.connect_timeout;
        loop {
            if let Some(s) = self.session(guild).filter(|s| s.channel == channel) {
                s.conn.wait_ready(until.saturating_duration_since(Instant::now()))?;
                return Ok(s);
            }
            if Instant::now() >= until {
                self.joins.lock().unwrap().remove(&guild);
                return Err("Discord did not hand out a voice server in time".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn leave(&self, guild: u64) -> bool {
        self.joins.lock().unwrap().remove(&guild);
        let s = self.sessions.lock().unwrap().remove(&guild);
        self.send_gateway(json!({"op": 4, "d": {"guild_id": guild.to_string(), "channel_id": null, "self_mute": false, "self_deaf": false}}));
        match s {
            Some(s) => {
                s.conn.mixer.stop();
                s.conn.stop.cancel();
                true
            }
            None => false,
        }
    }

    pub fn shutdown(&self) {
        let guilds: Vec<u64> = self.sessions.lock().unwrap().keys().copied().collect();
        for g in guilds {
            self.leave(g);
        }
    }

    /// Play an audio file in the guild's voice channel.
    pub fn play_file(&self, guild: u64, path: &str) -> Result<(), String> {
        let s = self.session(guild).ok_or("not in a voice channel")?;
        let pcm = decode_to_pcm(&self.cfg.ffmpeg, Some(path), None)?;
        s.conn.play_pcm(&pcm);
        Ok(())
    }

    /// Speak `text` with TTS where `chat` is bound to a voice session (in the background).
    pub fn speak(&self, chat: &str, thread: Option<&str>, text: &str) -> bool {
        let (Some(s), Some(tts)) = (self.bound(chat, thread), self.cfg.tts.clone()) else { return false };
        let text = speakable(text);
        if text.is_empty() {
            return false;
        }
        let ffmpeg = self.cfg.ffmpeg.clone();
        let events = self.events.clone();
        let _ = std::thread::Builder::new().name("discord voice tts".into()).spawn(move || {
            let r = tts.synthesize(&text).map_err(|e| e.message).and_then(|audio| decode_to_pcm(&ffmpeg, None, Some(audio)));
            match r {
                Ok(pcm) => s.conn.play_pcm(&pcm),
                Err(e) => {
                    let _ = events.send(Event::Closed(0, format!("TTS failed: {e}")));
                }
            }
        });
        true
    }

    /// A reply was sent to `chat`: speak it once it stops changing.
    pub fn reply(&self, chat: &str, thread: Option<&str>, message_id: &str, text: &str) -> bool {
        if self.cfg.tts.is_none() || self.bound(chat, thread).is_none() || text.trim().is_empty() || self.spoken.lock().unwrap().iter().any(|m| m == message_id) {
            return false;
        }
        self.replies.lock().unwrap().insert(message_id.into(), PendingReply { chat: chat.into(), thread: thread.map(str::to_string), text: text.into(), at: Instant::now() + REPLY_SETTLE });
        true
    }

    /// A reply was edited before it was spoken: speak the latest text.
    pub fn edited(&self, message_id: &str, text: &str) {
        if let Some(r) = self.replies.lock().unwrap().get_mut(message_id) {
            r.text = text.into();
            r.at = Instant::now() + REPLY_SETTLE;
        }
    }

    fn flush_replies(&self) {
        let now = Instant::now();
        let due: Vec<(String, PendingReply)> = {
            let mut r = self.replies.lock().unwrap();
            let ids: Vec<String> = r.iter().filter(|(_, p)| p.at <= now).map(|(k, _)| k.clone()).collect();
            ids.into_iter().filter_map(|k| r.remove(&k).map(|p| (k, p))).collect()
        };
        for (id, p) in due {
            let mut s = self.spoken.lock().unwrap();
            s.push_back(id);
            if s.len() > 256 {
                s.pop_front();
            }
            drop(s);
            self.speak(&p.chat, p.thread.as_deref(), &p.text);
        }
    }

    pub fn status(&self, guild: u64) -> String {
        match self.session(guild) {
            None => "不在語音頻道。".into(),
            Some(s) => {
                let c = &s.conn;
                let e2ee = if c.e2ee() { format!("DAVE 端對端加密（驗證碼 {}）", c.privacy_code().unwrap_or_default()) } else { "僅傳輸加密".into() };
                format!("在 <#{}>，{}，{}，STT {}，TTS {}", s.channel, if c.ready() { "已連線" } else { "連線中" }, e2ee, if self.cfg.stt.is_some() { "開" } else { "未設定" }, if self.cfg.tts.is_some() { "開" } else { "未設定" })
            }
        }
    }

    /// `/voice join|leave|status [channel]` from `user` in `binding`'s channel. Blocks while joining.
    pub fn command(&self, guild: u64, user: u64, binding: Binding, args: &str) -> String {
        let mut it = args.split_whitespace();
        match it.next().unwrap_or("status").to_lowercase().as_str() {
            "join" | "channel" | "on" => {
                let target = it.next().and_then(|a| a.trim_start_matches("<#").trim_end_matches('>').parse().ok()).or_else(|| self.user_channel(guild, user));
                let Some(channel) = target else { return "請先進入一個語音頻道，或指定 `/voice join <頻道 id>`。".into() };
                match self.join(guild, channel, binding) {
                    Ok(_) => format!("已加入 <#{channel}>，說話後停頓一下我就會回應。"),
                    Err(e) => format!("無法加入語音頻道：{e}"),
                }
            }
            // Pairwise DAVE fingerprint with someone in the call (compare with their client's code).
            "verify" => {
                let who = it.next().and_then(|a| a.trim_start_matches("<@").trim_start_matches('!').trim_end_matches('>').parse().ok()).unwrap_or(user);
                let Some(s) = self.session(guild) else { return "不在語音頻道。".into() };
                if !s.conn.e2ee() {
                    return "這個語音連線沒有 DAVE 端對端加密。".into();
                }
                match s.conn.pairwise_code(who) {
                    Some(c) => format!("與 <@{who}> 的配對驗證碼：{c}"),
                    None => format!("<@{who}> 不在這個加密群組裡。"),
                }
            }
            "leave" | "off" => {
                if self.leave(guild) {
                    "已離開語音頻道。".into()
                } else {
                    "不在語音頻道。".into()
                }
            }
            _ => self.status(guild),
        }
    }

    fn user_name(&self, guild: u64, user: u64) -> String {
        self.states.lock().unwrap().get(&(guild, user)).map(|(_, n)| n.clone()).unwrap_or_default()
    }

    fn on_utterance(&self, guild: u64, u: Utterance) {
        let Some(s) = self.session(guild) else { return };
        let binding = s.binding.lock().unwrap().clone();
        let text = (|| {
            let pcm = opus_to_pcm16k(&self.cfg.ffmpeg, &u.frames)?;
            if rms(&pcm) < 30.0 {
                return Ok(String::new());
            }
            self.transcribe_pcm(&wav(&pcm, 16_000, 1))
        })();
        let text = match text {
            Ok(t) if !t.is_empty() => t,
            _ => return,
        };
        // Dropped if the session moved to another text channel while transcribing.
        if *s.binding.lock().unwrap() != binding {
            return;
        }
        let name = self.user_name(guild, u.user);
        if self.cfg.echo {
            let safe: String = text.replace("@everyone", "@\u{200b}everyone").replace("@here", "@\u{200b}here").chars().take(1900).collect();
            self.post(binding.post_channel(), &format!("🎙️ <@{}>: {safe}", u.user));
        }
        // `media.transcripts` sessions reading this channel (`transcripts start providerId = "discord-voice"`).
        self.heard(guild, s.channel, Some(name.clone()).filter(|n| !n.is_empty()), &text);
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let m = Inbound {
            channel: self.channel_name.clone(),
            chat: binding.chat.clone(),
            chat_type: if binding.thread.is_some() { ChatType::Thread } else { ChatType::Group },
            chat_name: binding.chat_name.clone(),
            thread: binding.thread.clone(),
            sender: u.user.to_string(),
            sender_name: name,
            text,
            message_id: format!("vc:{guild}:{}:{}", u.ssrc, now_ms()),
            ts,
            mentioned: true,
            ..Default::default()
        };
        if let Some(tx) = &*self.inbound.lock().unwrap() {
            let _ = tx.send(m);
        }
    }
}

fn event_loop(m: Weak<VoiceManager>, rx: mpsc::Receiver<Event>) {
    loop {
        let ev = match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(e) => e,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                match m.upgrade() {
                    Some(m) => m.flush_replies(),
                    None => return,
                }
                continue;
            }
            Err(_) => return,
        };
        let Some(m) = m.upgrade() else { return };
        match ev {
            Event::Utterance(g, u) => {
                // Transcription can take seconds; keep the queue moving.
                let m2 = m.clone();
                let _ = std::thread::Builder::new().name("discord voice stt".into()).spawn(move || m2.on_utterance(g, u));
            }
            Event::Closed(0, _) => {}
            Event::Closed(g, why) => {
                let s = m.session(g);
                if let Some(s) = s {
                    let post = s.binding.lock().unwrap().post_channel().to_string();
                    m.leave(g);
                    if why == "idle" {
                        m.post(&post, "閒置太久，已離開語音頻道。");
                    } else {
                        m.post(&post, &format!("語音連線中斷：{why}"));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::dave::{external_sender_payload, Dave};
    use crate::mls::{self, Credential, ExternalSender, Proposal, R, W};
    use seagent_net::crypto::{hex, hex_decode};
    use seagent_net::ws::read_head;
    use std::net::TcpListener;

    pub(crate) fn have_ffmpeg() -> bool {
        seagent_core::platform::proc::command("ffmpeg").arg("-version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
    }

    #[test]
    fn xchacha20_poly1305_vectors() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let nonce: [u8; 16] = hex_decode("000000090000004a0000000031415927").unwrap().try_into().unwrap();
        assert_eq!(hex(&hchacha20(&key, &nonce)), "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
        // draft-irtf-cfrg-xchacha-03 A.3.1
        let key: [u8; 32] = std::array::from_fn(|i| 0x80 + i as u8);
        let iv: [u8; 24] = std::array::from_fn(|i| 0x40 + i as u8);
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad = hex_decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let (k, n) = xchacha(&key, &iv);
        let mut b = pt.to_vec();
        k.seal_in_place_append_tag(n, Aad::from(&aad), &mut b).unwrap();
        assert_eq!(hex(&b[..16]), "bd6d179d3e83d43b9576579493c0e939");
        assert_eq!(hex(&b[b.len() - 16..]), "c0875924c1c7987947deafd8780acf49");
    }

    #[test]
    fn rtp_both_modes_extension_padding_and_discovery() {
        let key = [9u8; 32];
        for mode in [Mode::Aes256Gcm, Mode::XChaCha20] {
            let p = rtp_packet(mode, &key, 7, 960, 42, 5, b"opus!");
            assert_eq!(&p[..12], &[0x80, 0x78, 0, 7, 0, 0, 3, 192, 0, 0, 0, 42]);
            assert_eq!(&p[p.len() - 4..], &[0, 0, 0, 5]);
            assert_eq!(p.len(), 12 + 5 + 16 + 4);
            let r = open_rtp(mode, &key, &p).unwrap();
            assert_eq!((r.seq, r.ts, r.ssrc, r.payload.as_slice()), (7, 960, 42, &b"opus!"[..]));
            let mut bad = p.clone();
            bad[13] ^= 1;
            assert!(open_rtp(mode, &key, &bad).is_none());
            assert!(open_rtp(mode, &[1u8; 32], &p).is_none());
            // A one-word header extension (preamble in the AAD, body encrypted) plus padding.
            let mut h = vec![0x80 | 0x10 | 0x20, 0x78, 0, 1, 0, 0, 0, 0, 0, 0, 0, 9, 0xbe, 0xde, 0, 1];
            let body = [1u8, 2, 3, 4, b'h', b'i', 0, 0, 3];
            let ct = mode.seal(&key, 77, &h, &body);
            h.extend_from_slice(&ct);
            h.extend_from_slice(&77u32.to_be_bytes());
            assert_eq!(open_rtp(mode, &key, &h).unwrap().payload, b"hi");
        }
        assert_eq!(Mode::choose(&["xsalsa20_poly1305".into(), "aead_xchacha20_poly1305_rtpsize".into()]), Some(Mode::XChaCha20));
        assert_eq!(Mode::choose(&["aead_xchacha20_poly1305_rtpsize".into(), "aead_aes256_gcm_rtpsize".into()]), Some(Mode::Aes256Gcm));
        assert_eq!(Mode::choose(&["xsalsa20_poly1305".into()]), None);
        let q = discovery_request(0x01020304);
        assert_eq!((q.len(), &q[..8]), (74, &[0, 1, 0, 70, 1, 2, 3, 4][..]));
        let mut resp = [0u8; 74];
        resp[1] = 2;
        resp[3] = 70;
        resp[8..17].copy_from_slice(b"203.0.113");
        resp[72..].copy_from_slice(&50004u16.to_be_bytes());
        assert_eq!(discovery_response(&resp), Some(("203.0.113".into(), 50004)));
        assert_eq!(discovery_response(&q), None);
    }

    #[test]
    fn ogg_mux_demux_mixer_receiver_and_text() {
        let frames: Vec<Vec<u8>> = vec![vec![0xfc, 1, 2, 3], vec![0xfc; 300], vec![0x78, 9]];
        let ogg = ogg_opus(&frames);
        assert_eq!(&ogg[..4], b"OggS");
        let mut r = OggReader::new(&ogg[..]);
        let mut got = vec![];
        while let Some(p) = r.next_packet().unwrap() {
            got.push(p);
        }
        assert_eq!(got, frames);
        // Page CRC of the first page (27-byte header, one lacing value, 19-byte OpusHead), field zeroed.
        let mut page = ogg[..47].to_vec();
        let crc = u32::from_le_bytes(page[22..26].try_into().unwrap());
        page[22..26].copy_from_slice(&[0; 4]);
        assert_eq!(ogg_crc(&page), crc);
        assert_eq!((opus_samples(&[0xfc]), opus_samples(&[0x78]), opus_samples(&[0x18]), opus_samples(&[0xfb, 0x03])), (960, 960, 2880, 2880));
        // Mixer sums and clamps two sources; ends when both are done.
        let m = Mixer::default();
        let tone = |v: i16, n: usize| (0..n).flat_map(|_| v.to_le_bytes()).collect::<Vec<u8>>();
        m.play(&tone(20000, 1920 + 10), 1.0);
        m.play(&tone(20000, 1920), 1.0);
        let f = m.frame().unwrap();
        assert_eq!((f.len(), i16::from_le_bytes([f[0], f[1]])), (FRAME_BYTES, 32767));
        let f = m.frame().unwrap();
        assert_eq!((i16::from_le_bytes([f[0], f[1]]), i16::from_le_bytes([f[20], f[21]])), (20000, 0));
        assert!(m.frame().is_none() && !m.active());
        // Receiver: silence ends an utterance; too-short bursts and silence frames don't count.
        let mut rx = Receiver::new(Duration::from_millis(100), Duration::from_millis(200));
        let t = Instant::now();
        for i in 0..20 {
            rx.push(1, vec![0xfc, i], t);
        }
        for i in 0..5 {
            rx.push(2, vec![0xfc, i], t);
        }
        rx.push(2, OPUS_SILENCE.to_vec(), t);
        assert!(rx.take_done(t + Duration::from_millis(50), |_| Some(5)).is_empty());
        let done = rx.take_done(t + Duration::from_millis(150), |s| (s == 1).then_some(7));
        assert_eq!(done.len(), 1);
        assert_eq!((done[0].user, done[0].frames.len()), (7, 20));
        assert!(rx.take_done(t + Duration::from_secs(9), |_| Some(1)).is_empty());
        assert_eq!(wav(&[1, 0, 2, 0], 16000, 1).len(), 44 + 4);
        assert!(is_hallucination(" Thank you. ") && is_hallucination("謝謝觀看！") && !is_hallucination("turn on the lights"));
        assert_eq!(speakable("# Title\n**bold** and `code`\n```\nlet x = 1;\n```\n- item"), "Title\nbold and code\nitem");
    }

    #[test]
    fn ffmpeg_round_trip_encodes_20ms_frames() {
        if !have_ffmpeg() {
            eprintln!("ffmpeg missing; skipped");
            return;
        }
        let ogg = ffmpeg("ffmpeg", &["-f", "lavfi", "-i", "sine=frequency=440:duration=0.5", "-ac", "2", "-c:a", "libopus", "-frame_duration", "20", "-f", "ogg", "pipe:1"], None, Duration::from_secs(30)).unwrap();
        let mut r = OggReader::new(&ogg[..]);
        let mut frames = vec![];
        while let Some(p) = r.next_packet().unwrap() {
            frames.push(p);
        }
        assert!(frames.len() >= 24 && frames.iter().all(|f| opus_samples(f) == 960), "{} frames", frames.len());
        let pcm = opus_to_pcm16k("ffmpeg", &frames).unwrap();
        assert!(pcm.len() >= 16000 && rms(&pcm) > 1000.0, "{} bytes rms {}", pcm.len(), rms(&pcm));
        let pcm48 = decode_to_pcm("ffmpeg", None, Some(wav(&pcm, 16000, 1))).unwrap();
        assert!(pcm48.len() >= 4 * 48000 / 2);
    }

    // ------------------------------------------------ end-to-end: fake voice gateway + SFU

    pub(crate) type Ws = WebSocket<std::net::TcpStream>;

    pub(crate) fn send_json(ws: &mut Ws, v: Value) {
        ws.send_text(&v.to_string()).unwrap();
    }

    fn send_bin(ws: &mut Ws, seq: &mut u16, op: u8, payload: &[u8]) {
        *seq += 1;
        let mut b = seq.to_be_bytes().to_vec();
        b.push(op);
        b.extend_from_slice(payload);
        ws.send(&Message::Binary(b)).unwrap();
    }

    /// Next message from the client; heartbeats are acknowledged and logged.
    pub(crate) fn next(ws: &mut Ws, log: &Mutex<Vec<Value>>) -> Message {
        loop {
            let m = ws.recv_blocking().expect("voice client message");
            if let Message::Text(t) = &m {
                let v: Value = serde_json::from_str(t).unwrap();
                log.lock().unwrap().push(v.clone());
                if v["op"] == 3 {
                    send_json(ws, json!({"op": 6, "d": {"t": v["d"]["t"]}}));
                    continue;
                }
            }
            return m;
        }
    }

    pub(crate) fn sine_frames(secs: f32) -> Vec<Vec<u8>> {
        let ogg = ffmpeg("ffmpeg", &["-f", "lavfi", "-i", &format!("sine=frequency=330:duration={secs}"), "-ac", "2", "-c:a", "libopus", "-frame_duration", "20", "-f", "ogg", "pipe:1"], None, Duration::from_secs(30)).unwrap();
        let mut r = OggReader::new(std::io::Cursor::new(ogg));
        let mut v = vec![];
        while let Some(p) = r.next_packet().unwrap() {
            v.push(p);
        }
        v
    }

    /// A Discord voice server: WebSocket signalling, a UDP SFU, (with `e2ee`) the DAVE external
    /// sender, and one simulated human (user 77, ssrc 7700) who joins the MLS group, speaks and listens.
    pub(crate) struct FakeVoice {
        pub url: String,
        pub log: Arc<Mutex<Vec<Value>>>,
        pub heard: Arc<Mutex<Vec<Vec<u8>>>>,
        pub speaking: Arc<Mutex<Vec<u64>>>,
    }

    pub(crate) fn fake_voice(mode_offer: Vec<&'static str>, e2ee: bool) -> FakeVoice {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}", l.local_addr().unwrap());
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_port = udp.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(vec![]));
        let heard = Arc::new(Mutex::new(vec![]));
        let speaking = Arc::new(Mutex::new(vec![]));
        let (log2, heard2, speaking2) = (log.clone(), heard.clone(), speaking.clone());
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
            let (head, rest) = read_head(&mut s, 65536).unwrap();
            let mut ws = WebSocket::accept(s, &head, rest).unwrap();
            log2.lock().unwrap().push(json!({"path": head.split_whitespace().nth(1)}));
            send_json(&mut ws, json!({"op": 8, "d": {"heartbeat_interval": 1500.0, "v": 8}}));
            let Message::Text(_) = next(&mut ws, &log2) else { panic!("identify") };
            send_json(&mut ws, json!({"op": 2, "d": {"ssrc": 4200, "ip": "127.0.0.1", "port": udp_port, "modes": mode_offer, "heartbeat_interval": 1}, "seq": 1}));
            // IP discovery.
            let mut b = [0u8; 2048];
            let (n, client) = udp.recv_from(&mut b).unwrap();
            assert_eq!((n, &b[..4]), (74, &[0, 1, 0, 70][..]));
            let mut resp = [0u8; 74];
            resp[..4].copy_from_slice(&[0, 2, 0, 70]);
            resp[4..8].copy_from_slice(&b[4..8]);
            resp[8..17].copy_from_slice(b"127.0.0.1");
            resp[72..].copy_from_slice(&client.port().to_be_bytes());
            udp.send_to(&resp, client).unwrap();
            let Message::Text(sel) = next(&mut ws, &log2) else { panic!("select protocol") };
            let sel: Value = serde_json::from_str(&sel).unwrap();
            let mode = if sel["d"]["data"]["mode"] == "aead_aes256_gcm_rtpsize" { Mode::Aes256Gcm } else { Mode::XChaCha20 };
            let key = [5u8; 32];
            send_json(&mut ws, json!({"op": 4, "d": {"mode": mode.name(), "secret_key": key.to_vec(), "dave_protocol_version": if e2ee { 1 } else { 0 }}, "seq": 2}));
            let mut human: Option<Dave> = if e2ee {
                // DAVE: the bot sends its key package; we are the external sender.
                let Message::Binary(kp) = next(&mut ws, &log2) else { panic!("key package") };
                assert_eq!(kp[0], 26);
                let bot_kp = mls::parse_key_package(&kp[1..]).unwrap();
                assert!(bot_kp.verify());
                let gw = Signer::generate();
                let es = ExternalSender { sig_key: gw.public(), cred: Credential::basic(b"gateway") };
                let mut seq = 2u16;
                send_bin(&mut ws, &mut seq, 25, &external_sender_payload(&es));
                send_json(&mut ws, json!({"op": 11, "d": {"user_ids": ["77"]}}));
                // The human's client.
                let mut human = Dave::new(77, 999);
                let hkp = human.on_session_description(1);
                let Out::Binary(hkp) = &hkp[0] else { panic!() };
                let human_kp = mls::parse_key_package(&hkp[1..]).unwrap();
                human.on_external_sender(&external_sender_payload(&es)).unwrap();
                human.on_clients_connect(&[77, 1]);
                // Propose the human into the bot's pending group (epoch 0); the bot commits + welcomes.
                let prop = mls::external_proposal(&gw, 0, &999u64.to_be_bytes(), 0, Proposal::Add(human_kp.clone()));
                let mut w = W::default();
                w.u8(0).vec(&prop);
                send_bin(&mut ws, &mut seq, 27, &w.0);
                let Message::Binary(cw) = next(&mut ws, &log2) else { panic!("commit welcome") };
                assert_eq!(cw[0], 28);
                let mut r = R::new(&cw[1..]);
                mls::PublicMessage::read(&mut r).unwrap();
                let (commit, welcome) = cw[1..].split_at(r.i);
                let mut ann = 3u16.to_be_bytes().to_vec();
                ann.extend_from_slice(commit);
                send_bin(&mut ws, &mut seq, 29, &ann);
                let mut wel = 3u16.to_be_bytes().to_vec();
                wel.extend_from_slice(welcome);
                assert!(human.on_welcome(&wel).0.is_some(), "{:?}", human.errors);
                let Message::Text(ready) = next(&mut ws, &log2) else { panic!("ready for transition") };
                assert!(ready.contains("\"op\":23"), "{ready}");
                send_json(&mut ws, json!({"op": 22, "d": {"transition_id": 3}, "seq": 3}));
                human.on_execute_transition(3);
                Some(human)
            } else {
                None
            };
            send_json(&mut ws, json!({"op": 5, "d": {"user_id": "77", "ssrc": 7700, "speaking": 1}, "seq": 4}));
            // The human speaks one second of tone, E2EE + transport encrypted.
            std::thread::sleep(Duration::from_millis(200));
            for (i, f) in sine_frames(1.0).iter().enumerate() {
                let payload = match human.as_mut() {
                    Some(h) => {
                        let e = h.encrypt(f);
                        assert!(crate::dave::parse_frame(&e).is_some());
                        e
                    }
                    None => f.clone(),
                };
                udp.send_to(&rtp_packet(mode, &key, i as u16, i as u32 * 960, 7700, 1000 + i as u32, &payload), client).unwrap();
                std::thread::sleep(Duration::from_millis(5));
            }
            // Listen to what the bot plays back; keep acknowledging heartbeats.
            ws.get_ref().set_read_timeout(Some(Duration::from_millis(20))).unwrap();
            udp.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
            let until = Instant::now() + Duration::from_secs(25);
            while Instant::now() < until {
                match ws.recv() {
                    Ok(Some(Message::Text(t))) => {
                        let v: Value = serde_json::from_str(&t).unwrap();
                        if v["op"] == 3 {
                            send_json(&mut ws, json!({"op": 6, "d": {"t": v["d"]["t"]}}));
                        }
                        if v["op"] == 5 {
                            speaking2.lock().unwrap().push(v["d"]["speaking"].as_u64().unwrap());
                        }
                        log2.lock().unwrap().push(v);
                    }
                    Ok(Some(Message::Close(_))) | Err(_) => break,
                    _ => {}
                }
                while let Ok((n, _)) = udp.recv_from(&mut b) {
                    if let Some(rtp) = open_rtp(mode, &key, &b[..n]) {
                        assert_eq!(rtp.ssrc, 4200);
                        let opus = match human.as_mut() {
                            Some(h) => h.decrypt(1, &rtp.payload),
                            None => Some(rtp.payload),
                        };
                        if let Some(opus) = opus {
                            heard2.lock().unwrap().push(opus);
                        }
                    }
                }
            }
        });
        FakeVoice { url, log, heard, speaking }
    }

    /// Minimal HTTP: STT answers JSON, TTS answers a WAV.
    pub(crate) type Seen = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    pub(crate) fn speech_server() -> (String, Seen) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(vec![]));
        let s2 = seen.clone();
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(mut c) = c else { continue };
                let Ok((head, mut body)) = read_head(&mut c, 65536) else { continue };
                let len: usize = seagent_net::ws::header(&head, "content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
                while body.len() < len {
                    let mut chunk = vec![0u8; 65536];
                    let n = c.read(&mut chunk).unwrap();
                    body.extend_from_slice(&chunk[..n]);
                }
                let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                s2.lock().unwrap().push((path.clone(), body));
                let (ctype, resp) = if path.ends_with("/audio/transcriptions") {
                    ("application/json", br#"{"text":"hello seagent"}"#.to_vec())
                } else {
                    let pcm: Vec<u8> = (0..16000 / 2).flat_map(|i| (((i as f32 * 0.2).sin() * 8000.0) as i16).to_le_bytes()).collect();
                    ("audio/wav", wav(&pcm, 16000, 1))
                };
                let _ = c.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", resp.len()).as_bytes());
                let _ = c.write_all(&resp);
            }
        });
        (url, seen)
    }

    /// Close 4015 → Resume with seq_ack (UDP and keys kept); 4014 → the session ends and the
    /// manager leaves (gateway op 4 with a null channel) and says so in the text channel.
    #[test]
    fn resume_then_disconnect_close_codes() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}", l.local_addr().unwrap());
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_port = udp.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(vec![]));
        let log2 = log.clone();
        std::thread::spawn(move || {
            for (n, s) in l.incoming().enumerate() {
                let mut s = s.unwrap();
                s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let (head, rest) = read_head(&mut s, 65536).unwrap();
                let mut ws = WebSocket::accept(s, &head, rest).unwrap();
                send_json(&mut ws, json!({"op": 8, "d": {"heartbeat_interval": 5000.0}}));
                let Message::Text(t) = next(&mut ws, &log2) else { panic!() };
                let v: Value = serde_json::from_str(&t).unwrap();
                if n == 0 {
                    assert_eq!(v["op"], 0);
                    send_json(&mut ws, json!({"op": 2, "d": {"ssrc": 1, "ip": "127.0.0.1", "port": udp_port, "modes": ["aead_aes256_gcm_rtpsize"]}, "seq": 1}));
                    let mut b = [0u8; 128];
                    let (_, client) = udp.recv_from(&mut b).unwrap();
                    let mut resp = [0u8; 74];
                    resp[..4].copy_from_slice(&[0, 2, 0, 70]);
                    resp[8..17].copy_from_slice(b"127.0.0.1");
                    resp[72..].copy_from_slice(&client.port().to_be_bytes());
                    udp.send_to(&resp, client).unwrap();
                    next(&mut ws, &log2);
                    send_json(&mut ws, json!({"op": 4, "d": {"mode": "aead_aes256_gcm_rtpsize", "secret_key": vec![1; 32], "dave_protocol_version": 0}, "seq": 2}));
                    std::thread::sleep(Duration::from_millis(100));
                    ws.send(&Message::Close(Some((4015, "voice server crashed".into())))).unwrap();
                } else {
                    assert_eq!(v["op"], 7, "{v}");
                    send_json(&mut ws, json!({"op": 9, "d": null, "seq": 3}));
                    std::thread::sleep(Duration::from_millis(100));
                    ws.send(&Message::Close(Some((4014, "disconnected".into())))).unwrap();
                    return;
                }
                let _ = ws.recv_blocking();
            }
        });
        let m = VoiceManager::new("dc", VoiceConfig::default());
        let gw = Arc::new(Mutex::new(vec![]));
        let posts = Arc::new(Mutex::new(vec![]));
        let (g2, p2) = (gw.clone(), posts.clone());
        m.set_hooks(Box::new(move |v| g2.lock().unwrap().push(v)), Box::new(move |c, t| p2.lock().unwrap().push((c.to_string(), t.to_string()))));
        m.on_ready("1");
        m.on_voice_server(&json!({"guild_id": "5", "token": "T", "endpoint": url}));
        m.on_voice_state(&json!({"guild_id": "5", "user_id": "1", "channel_id": "999", "session_id": "S"}));
        assert!(m.session(5).is_none(), "no join was requested");
        let m2 = m.clone();
        let join = std::thread::spawn(move || m2.join(5, 999, Binding { chat: "C1".into(), thread: Some("T9".into()), chat_name: String::new() }).map(|_| ()));
        std::thread::sleep(Duration::from_millis(100));
        m.on_voice_server(&json!({"guild_id": "5", "token": "T", "endpoint": url}));
        m.on_voice_state(&json!({"guild_id": "5", "user_id": "1", "channel_id": "999", "session_id": "S"}));
        join.join().unwrap().unwrap();
        let until = Instant::now() + Duration::from_secs(10);
        while posts.lock().unwrap().is_empty() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        let resume = log.lock().unwrap().iter().find(|v| v["op"] == 7).cloned().unwrap();
        assert_eq!(resume["d"], json!({"server_id": "5", "session_id": "S", "token": "T", "seq_ack": 2}));
        assert_eq!(posts.lock().unwrap()[0], ("T9".to_string(), "語音連線中斷：disconnected from the voice channel (4014)".to_string()));
        assert!(m.session(5).is_none());
        assert_eq!(gw.lock().unwrap().last().unwrap()["d"]["channel_id"], Value::Null);
    }

    #[test]
    fn end_to_end_join_listen_transcribe_and_speak() {
        if !have_ffmpeg() {
            eprintln!("ffmpeg missing; skipped");
            return;
        }
        for modes in [vec!["aead_aes256_gcm_rtpsize", "aead_xchacha20_poly1305_rtpsize"], vec!["aead_xchacha20_poly1305_rtpsize"]] {
            let fv = fake_voice(modes.clone(), true);
            let (speech_url, seen) = speech_server();
            let speech = Speech { url: speech_url, key: Some("sk-test".into()), format: Some("wav".into()), ..Default::default() };
            let signer = Arc::new(Signer::generate());
            let cfg = VoiceConfig { stt: Some(speech.clone()), tts: Some(speech), silence: Duration::from_millis(400), dave_signer: Some(signer.clone()), ..Default::default() };
            let m = VoiceManager::new("dc", cfg);
            let (gtx, grx) = mpsc::channel::<Value>();
            let gtx = Mutex::new(gtx);
            let posts = Arc::new(Mutex::new(vec![]));
            let p2 = posts.clone();
            m.set_hooks(Box::new(move |v| { let _ = gtx.lock().unwrap().send(v); }), Box::new(move |c, t| p2.lock().unwrap().push((c.to_string(), t.to_string()))));
            let (itx, irx) = mpsc::channel();
            m.set_inbound(itx);
            m.on_ready("1");
            m.on_guild_create(&json!({"id": "5", "voice_states": [{"user_id": "77", "channel_id": "999", "member": {"nick": "Amy"}}]}));
            assert_eq!(m.user_channel(5, 77), Some(999));
            let m2 = m.clone();
            let url = fv.url.clone();
            // The main gateway: answer op 4 with our voice state and the voice server.
            std::thread::spawn(move || {
                let v = grx.recv_timeout(Duration::from_secs(5)).unwrap();
                assert_eq!(v, json!({"op": 4, "d": {"guild_id": "5", "channel_id": "999", "self_mute": false, "self_deaf": false}}));
                m2.on_voice_server(&json!({"guild_id": "5", "token": "VTOKEN", "endpoint": url}));
                m2.on_voice_state(&json!({"guild_id": "5", "user_id": "1", "channel_id": "999", "session_id": "VSESS"}));
            });
            let binding = Binding { chat: "C1".into(), thread: None, chat_name: "general".into() };
            let reply = m.command(5, 77, binding, "join");
            assert!(reply.starts_with("已加入 <#999>"), "{reply}");
            // The human's speech arrives as a transcript Inbound in the bound text channel.
            let got: Inbound = irx.recv_timeout(Duration::from_secs(20)).expect("transcript");
            assert_eq!((got.chat.as_str(), got.sender.as_str(), got.sender_name.as_str(), got.text.as_str(), got.channel.as_str()), ("C1", "77", "Amy", "hello seagent", "dc"));
            assert!(got.mentioned && got.message_id.starts_with("vc:5:7700:"));
            assert_eq!(posts.lock().unwrap()[0], ("C1".to_string(), "🎙️ <@77>: hello seagent".to_string()));
            let reqs = seen.lock().unwrap().clone();
            let stt = &reqs[0];
            assert_eq!(stt.0, "/v1/audio/transcriptions");
            let body = String::from_utf8_lossy(&stt.1);
            assert!(body.contains("name=\"file\"; filename=\"speech.wav\"") && body.contains("RIFF") && body.contains("whisper-1"));
            let s = m.session(5).unwrap();
            assert!(s.conn.e2ee(), "DAVE active");
            assert!(m.status(5).contains("DAVE"), "{}", m.status(5));
            // Our MLS leaf carries the persistent key; `/voice verify` shows the pairwise code.
            let leaf_key = s.conn.dave.lock().unwrap().group().unwrap().members().find(|(_, l)| l.cred.body == 1u64.to_be_bytes()).map(|(_, l)| l.sig_key.clone());
            assert_eq!(leaf_key, Some(signer.public()));
            let b = Binding { chat: "C1".into(), thread: None, chat_name: "general".into() };
            let v = m.command(5, 1, b.clone(), "verify <@77>");
            let code = v.strip_prefix("與 <@77> 的配對驗證碼：").unwrap_or_else(|| panic!("{v}"));
            assert_eq!((code.len(), code.split(' ').count()), (53, 9));
            assert!(m.command(5, 1, b, "verify <@42>").contains("不在"));
            // The reply is spoken: TTS → ffmpeg → Opus → DAVE → RTP; the human decrypts it.
            assert!(m.speak("C1", None, "**Hi** there"));
            let until = Instant::now() + Duration::from_secs(15);
            while fv.speaking.lock().unwrap().len() < 2 && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(50));
            }
            assert_eq!(*fv.speaking.lock().unwrap(), [1, 0], "speaking on, then off");
            let heard = fv.heard.lock().unwrap().clone();
            let audio: Vec<&Vec<u8>> = heard.iter().filter(|f| f[..] != OPUS_SILENCE).collect();
            assert!(audio.len() >= 20 && audio.iter().all(|f| opus_samples(f) == 960), "{} frames", audio.len());
            assert!(heard.ends_with(&[OPUS_SILENCE.to_vec(), OPUS_SILENCE.to_vec(), OPUS_SILENCE.to_vec(), OPUS_SILENCE.to_vec(), OPUS_SILENCE.to_vec()]));
            let tts = seen.lock().unwrap().iter().find(|(p, _)| p == "/v1/audio/speech").cloned().unwrap();
            let tb: Value = serde_json::from_slice(&tts.1).unwrap();
            assert_eq!((tb["input"].as_str(), tb["model"].as_str(), tb["response_format"].as_str()), (Some("Hi there"), Some("tts-1"), Some("wav")));
            // Signalling: identify with DAVE, select protocol with the chosen mode, heartbeats with seq_ack.
            let log = fv.log.lock().unwrap().clone();
            assert_eq!(log[0]["path"], "/?v=8");
            let ident = log.iter().find(|v| v["op"] == 0).unwrap();
            assert_eq!(ident["d"], json!({"server_id": "5", "user_id": "1", "session_id": "VSESS", "token": "VTOKEN", "max_dave_protocol_version": 1}));
            let sel = log.iter().find(|v| v["op"] == 1).unwrap();
            assert_eq!((sel["d"]["protocol"].as_str(), sel["d"]["data"]["address"].as_str(), sel["d"]["data"]["mode"].as_str()), (Some("udp"), Some("127.0.0.1"), Some(modes[0])));
            assert!(log.iter().any(|v| v["op"] == 3 && v["d"]["seq_ack"].as_i64().unwrap_or(-1) >= 2), "heartbeat seq_ack");
            // Leave: gateway op 4 with a null channel, connection closed.
            assert!(m.command(5, 77, Binding { chat: "C1".into(), thread: None, chat_name: String::new() }, "leave").contains("已離開"));
            assert!(m.session(5).is_none());
            assert!(m.command(5, 77, Binding { chat: "C1".into(), thread: None, chat_name: String::new() }, "status").contains("不在"));
        }
    }

    /// G8: building the Discord channel with `[channels.dc.voice]` installs the live voice
    /// manager as the media layer's `discord-voice` transcript source, so a real install can
    /// record a call (`transcripts start providerId = "discord-voice"`) — not just a test double.
    /// A take the channel's own STT recognizes lands in a real `media.transcripts` session
    /// (fake STT endpoint, no network, no gateway).
    #[test]
    fn the_media_transcript_source_reads_a_live_voice_channel() {
        use seagent_media::stt::transcripts::channel::DiscordVoiceSource;
        use seagent_media::stt::transcripts::sources::Sink;
        use seagent_media::stt::transcripts::{Session, SourceLocator, TranscriptSource, Utterance};
        let (speech_url, seen) = speech_server();
        let stt = Speech { url: speech_url, key: Some("sk-test".into()), format: Some("wav".into()), ..Default::default() };
        let mut cfg = crate::discord::Config::new("dc", "TOKEN");
        cfg.voice = Some(VoiceConfig { stt: Some(stt), ..Default::default() });
        let channel = crate::discord::Discord::new(cfg).expect("discord channel");
        let vm = channel.voice_manager().expect("voice manager");
        // The production wiring: the media layer sees this manager, not nobody.
        let src = seagent_media::stt::transcripts::channel::discord_voice().expect("the live manager is the media layer's Discord back end");
        assert!(!src.connected(""), "nothing to capture before READY");
        vm.on_ready("1");
        assert!(src.connected("") && src.connected("dc") && !src.connected("other"), "per-account readiness");

        let m = seagent_media::Media::new(seagent_media::MediaConfig::from_toml("[transcripts]\nmodel_summary = false\n"));
        let sess = Session {
            session_id: "tr-dc".into(),
            started_at: "2026-11-04T00:00:00Z".into(),
            source: SourceLocator { provider_id: "discord-voice".into(), guild_id: Some("5".into()), channel_id: Some("999".into()), ..Default::default() },
            ..Default::default()
        };
        let got: Arc<Mutex<Vec<Utterance>>> = Arc::new(Mutex::new(Vec::new()));
        let g2 = got.clone();
        let sink: Sink = Arc::new(move |u: Utterance| g2.lock().unwrap().push(u));
        let mut cap = TranscriptSource::start(&DiscordVoiceSource, &m, &sess, sink).expect("capture starts");
        assert!(cap.active());

        // The channel's own recognizer (the fake `/audio/transcriptions` endpoint) turns a take
        // into a line; `on_utterance` then fans it out (that is the call below).
        let pcm: Vec<u8> = (0..1600i16).flat_map(|i| (i * 17).to_le_bytes()).collect();
        let text = vm.transcribe_pcm(&wav(&pcm, 16_000, 1)).expect("recognized");
        assert_eq!(text, "hello seagent");
        vm.heard(5, 999, Some("Amy".into()), &text);
        vm.heard(5, 111, Some("Bob".into()), "another channel");
        let got_rows = got.lock().unwrap().clone();
        assert_eq!(got_rows.len(), 1, "one line, from the tapped channel: {got_rows:?}");
        assert_eq!((got_rows[0].id.as_str(), got_rows[0].speaker.as_deref(), got_rows[0].text.as_str()), ("tr-dc-1", Some("Amy"), "hello seagent"));
        cap.stop().expect("stop");
        assert!(!cap.active());
        vm.heard(5, 999, Some("Amy".into()), "after stop");
        assert_eq!(got.lock().unwrap().len(), 1, "stopping ends the tap");
        assert!(seen.lock().unwrap().iter().any(|(p, _)| p == "/v1/audio/transcriptions"), "the take went through the channel's STT endpoint");
    }
}

/// gen1-309: the voice channel on seagent's realtime transcription and `[media]` TTS providers.
#[cfg(test)]
mod realtime_speech_tests {
    use super::*;
    use std::net::TcpListener;

    /// A Deepgram-shaped realtime server: takes binary audio, answers the `Finalize` with the
    /// final transcript (what `[media.realtime]` deepgram speaks).
    fn fake_deepgram(said: &'static str) -> (String, std::sync::mpsc::Receiver<usize>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1", l.local_addr().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let Ok((mut s, _)) = l.accept() else { return };
            let Ok((head, rest)) = seagent_net::ws::read_head(&mut s, 64 * 1024) else { return };
            let Ok(mut ws) = WebSocket::accept(s, &head, rest) else { return };
            let mut bytes = 0;
            loop {
                match ws.recv_blocking() {
                    Ok(Message::Binary(b)) => bytes += b.len(),
                    Ok(Message::Text(t)) if t.contains("Finalize") => {
                        let _ = tx.send(bytes);
                        let _ = ws.send_text(&json!({"type": "Results", "from_finalize": true, "is_final": true, "speech_final": true, "channel": {"alternatives": [{"transcript": said}]}}).to_string());
                    }
                    Ok(Message::Text(_)) | Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
                    _ => break,
                }
            }
        });
        (url, rx)
    }

    #[test]
    fn discord_voice_transcribes_with_realtime_stt_and_speaks_with_media_tts() {
        let (url, heard) = fake_deepgram("hello from the voice channel");
        let dir = seagent_core::tmp::TempDir::new("seagent-dv-rt");
        let tts_out = dir.path().join("tts.ogg");
        let cfg = format!(
            "[realtime]\nconnect_timeout_ms = 3000\nclose_timeout_ms = 2000\nreconnect_attempts = 1\n[providers.deepgram]\napi_key = \"k\"\nbase_url = \"{url}\"\n[tts]\nprovider = \"fake\"\n[tts.providers.fake]\ncommand = \"printf OggS-fake-voice > {{output_path}}; cp {{output_path}} {out}\"\nformat = \"opus\"\n",
            // A shell line inside a TOML string: Git Bash spelling on Windows (`C:/…`).
            out = seagent_core::platform::shell::path_str(&tts_out)
        );
        seagent_media::set_shared(seagent_media::Media::new(seagent_media::MediaConfig::from_toml(&cfg)));
        // One second of 48 kHz stereo, as the voice socket decodes it.
        let samples: Vec<i16> = (0..48_000 * 2).map(|i| ((i as f32 * 0.05).sin() * 8000.0) as i16).collect();
        let wav = seagent_media::audio::wav_encode(&samples, 48_000, 2);
        let stt: Speech = serde_json::from_value(json!({"engine": "realtime", "provider": "deepgram"})).unwrap();
        assert_eq!(stt.transcribe(&wav).unwrap(), "hello from the voice channel");
        let sent = heard.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(sent, 48_000 * 2, "the utterance was streamed as mono PCM16");
        let tts: Speech = serde_json::from_value(json!({"engine": "media"})).unwrap();
        assert_eq!(tts.synthesize("hi").unwrap(), b"OggS-fake-voice");
        // Configuration mistakes are reported, not ignored.
        let bad: Speech = serde_json::from_value(json!({"engine": "carrier-pigeon"})).unwrap();
        assert!(bad.transcribe(&wav).unwrap_err().message.contains("unknown speech engine"));
    }
}

