//! PCM plumbing shared by TTS, STT, realtime voice, meetings and phone calls:
//! WAV container, G.711 μ-law/A-law (telephony), resampling, and ffmpeg
//! transcoding for everything else (opus voice notes, mp3, chunking).

use seagent_core::Cancel;
use std::path::Path;
use std::time::Duration;

/// 16-bit little-endian mono/stereo WAV.
pub fn wav_encode(samples: &[i16], sample_rate: u32, channels: u16) -> Vec<u8> {
    let data_len = (samples.len() * 2) as u32;
    let mut b = Vec::with_capacity(44 + data_len as usize);
    b.extend_from_slice(b"RIFF");
    b.extend_from_slice(&(36 + data_len).to_le_bytes());
    b.extend_from_slice(b"WAVEfmt ");
    b.extend_from_slice(&16u32.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&channels.to_le_bytes());
    b.extend_from_slice(&sample_rate.to_le_bytes());
    b.extend_from_slice(&(sample_rate * channels as u32 * 2).to_le_bytes());
    b.extend_from_slice(&(channels * 2).to_le_bytes());
    b.extend_from_slice(&16u16.to_le_bytes());
    b.extend_from_slice(b"data");
    b.extend_from_slice(&data_len.to_le_bytes());
    for s in samples {
        b.extend_from_slice(&s.to_le_bytes());
    }
    b
}

/// Wrap raw PCM16LE bytes in a WAV header.
pub fn wav_from_pcm_bytes(pcm: &[u8], sample_rate: u32, channels: u16) -> Vec<u8> {
    wav_encode(&pcm16_from_bytes(pcm), sample_rate, channels)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pcm {
    pub samples: Vec<i16>,
    pub sample_rate: u32,
    pub channels: u16,
}

impl Pcm {
    /// Mono at `rate` (channels averaged, linear resampling).
    pub fn to_mono(&self, rate: u32) -> Vec<i16> {
        let mono: Vec<i16> = if self.channels <= 1 {
            self.samples.clone()
        } else {
            let c = self.channels as usize;
            self.samples.chunks(c).map(|f| (f.iter().map(|&s| s as i32).sum::<i32>() / f.len() as i32) as i16).collect()
        };
        resample(&mono, self.sample_rate, rate)
    }
    pub fn duration_secs(&self) -> f64 {
        self.samples.len() as f64 / (self.sample_rate.max(1) as f64 * self.channels.max(1) as f64)
    }
}

/// Parse a PCM16 (or 8-bit / float32) WAV file.
pub fn wav_decode(b: &[u8]) -> Result<Pcm, String> {
    if b.len() < 12 || &b[0..4] != b"RIFF" || &b[8..12] != b"WAVE" {
        return Err("not a WAV file".into());
    }
    let (mut fmt, mut channels, mut rate, mut bits) = (0u16, 1u16, 16000u32, 16u16);
    let mut i = 12;
    while i + 8 <= b.len() {
        let id = &b[i..i + 4];
        let len = u32::from_le_bytes([b[i + 4], b[i + 5], b[i + 6], b[i + 7]]) as usize;
        let body = &b[i + 8..(i + 8 + len).min(b.len())];
        if id == b"fmt " && body.len() >= 16 {
            fmt = u16::from_le_bytes([body[0], body[1]]);
            channels = u16::from_le_bytes([body[2], body[3]]);
            rate = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            bits = u16::from_le_bytes([body[14], body[15]]);
            if fmt == 0xfffe && body.len() >= 26 {
                fmt = u16::from_le_bytes([body[24], body[25]]);
            }
        } else if id == b"data" {
            let samples = match (fmt, bits) {
                (1, 16) => pcm16_from_bytes(body),
                (1, 8) => body.iter().map(|&s| ((s as i16) - 128) << 8).collect(),
                (3, 32) => body.as_chunks::<4>().0.iter().map(|c| (f32::from_le_bytes(*c).clamp(-1.0, 1.0) * 32767.0) as i16).collect(),
                (7, 8) => body.iter().map(|&s| ulaw_to_pcm(s)).collect(),
                (6, 8) => body.iter().map(|&s| alaw_to_pcm(s)).collect(),
                _ => return Err(format!("unsupported WAV encoding (format {fmt}, {bits} bits)")),
            };
            return Ok(Pcm { samples, sample_rate: rate, channels: channels.max(1) });
        }
        i += 8 + len + (len & 1);
    }
    Err("WAV file has no data chunk".into())
}

pub fn pcm16_from_bytes(b: &[u8]) -> Vec<i16> {
    b.as_chunks::<2>().0.iter().map(|c| i16::from_le_bytes(*c)).collect()
}

pub fn pcm16_to_bytes(s: &[i16]) -> Vec<u8> {
    s.iter().flat_map(|x| x.to_le_bytes()).collect()
}

/// Linear-interpolation resampler (good enough for speech).
pub fn resample(s: &[i16], from: u32, to: u32) -> Vec<i16> {
    if from == to || s.is_empty() || from == 0 || to == 0 {
        return s.to_vec();
    }
    let n = (s.len() as u64 * to as u64 / from as u64) as usize;
    let step = from as f64 / to as f64;
    (0..n)
        .map(|i| {
            let pos = i as f64 * step;
            let j = pos as usize;
            let f = pos - j as f64;
            let a = s[j.min(s.len() - 1)] as f64;
            let b = s[(j + 1).min(s.len() - 1)] as f64;
            (a + (b - a) * f) as i16
        })
        .collect()
}

const ULAW_BIAS: i32 = 0x84;

/// G.711 μ-law encode (Twilio/Plivo media streams).
pub fn pcm_to_ulaw(sample: i16) -> u8 {
    let mut s = sample as i32;
    let sign = if s < 0 {
        s = -s;
        0x80
    } else {
        0
    };
    s = (s + ULAW_BIAS).min(32635 + ULAW_BIAS);
    let mut exp = 7;
    let mut mask = 0x4000;
    while exp > 0 && s & mask == 0 {
        exp -= 1;
        mask >>= 1;
    }
    let mant = (s >> (exp + 3)) & 0x0f;
    !(sign | (exp << 4) | mant) as u8
}

pub fn ulaw_to_pcm(u: u8) -> i16 {
    let u = !u as i32;
    let sign = u & 0x80;
    let exp = (u >> 4) & 0x07;
    let mant = u & 0x0f;
    let s = (((mant << 3) + ULAW_BIAS) << exp) - ULAW_BIAS;
    (if sign != 0 { -s } else { s }) as i16
}

/// G.711 A-law (Telnyx/European trunks).
pub fn pcm_to_alaw(sample: i16) -> u8 {
    let mut s = sample as i32;
    let sign = if s >= 0 { 0x80 } else { 0 };
    if s < 0 {
        s = -s - 1;
    }
    s = s.min(32767);
    let (exp, mant) = if s >= 256 {
        let mut e = 1;
        while e < 7 && s >= (256 << e) {
            e += 1;
        }
        (e, (s >> (e + 3)) & 0x0f)
    } else {
        (0, s >> 4)
    };
    ((sign | (exp << 4) | mant) ^ 0x55) as u8
}

pub fn alaw_to_pcm(a: u8) -> i16 {
    let a = (a ^ 0x55) as i32;
    let sign = a & 0x80;
    let exp = (a >> 4) & 0x07;
    let mant = a & 0x0f;
    let s = if exp == 0 { (mant << 4) + 8 } else { ((mant << 4) + 0x108) << (exp - 1) };
    (if sign != 0 { s } else { -s }) as i16
}

/// Root-mean-square level of a frame, 0..=32767 (voice activity / silence detection).
pub fn rms(s: &[i16]) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    (s.iter().map(|&x| (x as f64) * (x as f64)).sum::<f64>() / s.len() as f64).sqrt()
}

/// `ffmpeg` path, honouring `SEAGENT_FFMPEG`.
pub fn ffmpeg() -> Option<std::path::PathBuf> {
    std::env::var("SEAGENT_FFMPEG").ok().map(std::path::PathBuf::from).filter(|p| p.exists()).or_else(|| crate::proc::which("ffmpeg"))
}

pub fn ffprobe() -> Option<std::path::PathBuf> {
    crate::proc::which("ffprobe")
}

/// Transcode `input` bytes with ffmpeg; `out_args` select the output (e.g.
/// `["-c:a","libopus","-b:a","32k","-f","ogg"]`). Returns the output bytes.
pub fn ffmpeg_transcode(input: &[u8], in_ext: &str, out_args: &[&str], cancel: &Cancel) -> Result<Vec<u8>, String> {
    let ff = ffmpeg().ok_or("ffmpeg is not installed (needed to convert audio/video)")?;
    let dir = crate::store::temp_dir("ff")?;
    let inp = dir.join(format!("in.{in_ext}"));
    let out = dir.join("out.bin");
    std::fs::write(&inp, input).map_err(|e| e.to_string())?;
    let mut argv: Vec<String> = vec![ff.display().to_string(), "-nostdin".into(), "-hide_banner".into(), "-loglevel".into(), "error".into(), "-y".into(), "-i".into(), inp.display().to_string()];
    argv.extend(out_args.iter().map(|s| s.to_string()));
    argv.push(out.display().to_string());
    let r = crate::proc::run(&argv, None, Duration::from_secs(600), cancel).and_then(|o| o.check("ffmpeg"));
    let bytes = r.and_then(|_| std::fs::read(&out).map_err(|e| e.to_string()));
    let _ = std::fs::remove_dir_all(&dir);
    bytes
}

/// Any audio → mono PCM16 at `rate` (WAV parsed natively, everything else via ffmpeg).
pub fn decode_to_pcm(input: &[u8], mime: &str, rate: u32, cancel: &Cancel) -> Result<Vec<i16>, String> {
    if let Ok(p) = wav_decode(input) {
        return Ok(p.to_mono(rate));
    }
    let r = rate.to_string();
    let raw = ffmpeg_transcode(input, crate::store::ext_for(mime), &["-ac", "1", "-ar", &r, "-f", "s16le", "-acodec", "pcm_s16le"], cancel)?;
    Ok(pcm16_from_bytes(&raw))
}

/// Ogg/Opus voice note (Telegram/WhatsApp voice bubble format) from any audio.
pub fn to_ogg_opus(input: &[u8], mime: &str, cancel: &Cancel) -> Result<Vec<u8>, String> {
    if crate::store::sniff(input) == "audio/ogg" {
        return Ok(input.to_vec());
    }
    ffmpeg_transcode(input, crate::store::ext_for(mime), &["-vn", "-ac", "1", "-ar", "48000", "-c:a", "libopus", "-b:a", "32k", "-f", "ogg"], cancel)
}

/// Media duration in seconds via ffprobe (WAV computed natively).
pub fn duration_secs(path: &Path, cancel: &Cancel) -> Option<f64> {
    if let Ok(b) = std::fs::read(path) {
        if let Ok(p) = wav_decode(&b) {
            return Some(p.duration_secs());
        }
    }
    let fp = ffprobe()?;
    let argv = vec![fp.display().to_string(), "-v".into(), "error".into(), "-show_entries".into(), "format=duration".into(), "-of".into(), "default=noprint_wrappers=1:nokey=1".into(), path.display().to_string()];
    let o = crate::proc::run(&argv, None, Duration::from_secs(30), cancel).ok()?;
    String::from_utf8_lossy(&o.stdout).trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wav_roundtrip_and_resample() {
        let s: Vec<i16> = (0..1600).map(|i| ((i as f64 * 0.1).sin() * 8000.0) as i16).collect();
        let w = wav_encode(&s, 16000, 1);
        assert_eq!(crate::store::sniff(&w), "audio/wav");
        let p = wav_decode(&w).unwrap();
        assert_eq!((p.sample_rate, p.channels, p.samples.len()), (16000, 1, 1600));
        assert!((p.duration_secs() - 0.1).abs() < 1e-9);
        assert_eq!(resample(&s, 16000, 8000).len(), 800);
        assert_eq!(resample(&s, 16000, 24000).len(), 2400);
        let st = Pcm { samples: vec![100, 300, -100, -300], sample_rate: 8000, channels: 2 };
        assert_eq!(st.to_mono(8000), vec![200, -200]);
    }

    #[test]
    fn g711_roundtrip_is_close() {
        for &x in &[0i16, 100, -100, 1000, -1000, 12000, -12000, 32000, -32000] {
            let u = ulaw_to_pcm(pcm_to_ulaw(x));
            let a = alaw_to_pcm(pcm_to_alaw(x));
            let tol = (x.unsigned_abs() as i32 / 16).max(40);
            assert!((u as i32 - x as i32).abs() <= tol, "ulaw {x} -> {u}");
            assert!((a as i32 - x as i32).abs() <= tol, "alaw {x} -> {a}");
        }
        assert_eq!(pcm_to_ulaw(0), 0xff);
    }

    #[test]
    fn rms_of_silence_and_tone() {
        assert_eq!(rms(&[0; 10]), 0.0);
        assert!(rms(&[1000, -1000]) > 999.0);
    }
}
