//! Microphone capture for voice mode, wake word and live transcripts (Hermes
//! `tools/voice_mode.py` `AudioRecorder` / `listen_for_speech`).
//!
//! Capture runs an external recorder that writes raw 16 kHz mono s16le PCM to stdout:
//! `[media.voice] record_command` (a shell line), else `pw-record`, `parec`,
//! `arecord` or `ffmpeg -f pulse` (macOS: `-f avfoundation`, Windows: `-f dshow`),
//! whichever is installed. The silence detector and
//! barge-in VAD are ports of Hermes' state machines, driven by sample time so they
//! behave identically on any source.
//!
//! ```toml
//! [media.voice]
//! record_command = ""            # e.g. "arecord -q -f S16_LE -r 16000 -c 1 -t raw -"
//! silence_threshold = 200        # RMS below this = silence
//! silence_duration = 3.0         # seconds of silence after speech that end a take
//! max_wait = 15.0                # seconds to wait for speech before giving up
//! max_recording_seconds = 0      # hard cap (0 = none)
//! ```

use crate::Media;
use seagent_core::Cancel;
use std::collections::VecDeque;
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

pub const SAMPLE_RATE: u32 = 16000;
/// 30 ms blocks (Hermes VAD block size).
pub const BLOCK: usize = 480;

/// A source of 16 kHz mono PCM blocks.
pub trait PcmSource: Send {
    /// Next block (any length); `Ok(None)` = the source ended.
    fn read(&mut self, cancel: &Cancel) -> Result<Option<Vec<i16>>, String>;
}

/// The argv for one named recorder (`None` = unknown name). Split out of
/// [`recorder_command`] so tests can check the flags without touching `$PATH`.
pub fn recorder_argv(name: &str, ffmpeg: Option<std::path::PathBuf>) -> Option<Vec<String>> {
    let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    Some(match name {
        // `--raw`: to stdout pw-record otherwise writes libsndfile's .au container
        // (header + big-endian PCM) instead of raw little-endian samples.
        "pw-record" => v(&["pw-record", "--raw", "--rate", "16000", "--channels", "1", "--format", "s16", "-"]),
        // `--raw`: parec writes a WAV header ahead of the PCM without it.
        "parec" => v(&["parec", "--raw", "--format=s16le", "--rate=16000", "--channels=1"]),
        "arecord" => v(&["arecord", "-q", "-f", "S16_LE", "-r", "16000", "-c", "1", "-t", "raw", "-"]),
        "ffmpeg" => {
            let ffmpeg = ffmpeg?;
            let mut a = vec![ffmpeg.display().to_string(), "-nostdin".into(), "-loglevel".into(), "quiet".into()];
            a.extend(ffmpeg_input(&ffmpeg)?);
            a.extend(v(&["-ac", "1", "-ar", "16000", "-f", "s16le", "-"]));
            a
        }
        _ => return None,
    })
}

/// ffmpeg's input for this OS's default microphone: PulseAudio/PipeWire `default` (Linux and
/// other unixes, unchanged), AVFoundation device `:0` (macOS), the first DirectShow audio
/// capture device (Windows; ffmpeg has no "default" there, so it is listed and picked).
pub fn ffmpeg_input(ffmpeg: &std::path::Path) -> Option<Vec<String>> {
    let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    #[cfg(target_vendor = "apple")]
    {
        let _ = ffmpeg;
        Some(v(&["-f", "avfoundation", "-i", ":0"]))
    }
    #[cfg(windows)]
    {
        windows_default_mic(ffmpeg).map(|d| v(&["-f", "dshow", "-i", &format!("audio={d}")]))
    }
    #[cfg(not(any(target_vendor = "apple", windows)))]
    {
        let _ = ffmpeg;
        Some(v(&["-f", "pulse", "-i", "default"]))
    }
}

/// The first DirectShow audio device ffmpeg lists (`"Microphone (…)" (audio)`).
#[cfg(windows)]
pub fn windows_default_mic(ffmpeg: &std::path::Path) -> Option<String> {
    let o = Command::new(ffmpeg).args(["-hide_banner", "-list_devices", "true", "-f", "dshow", "-i", "dummy"]).stdin(Stdio::null()).output().ok()?;
    parse_dshow_audio(&String::from_utf8_lossy(&o.stderr))
}

/// Parse `ffmpeg -list_devices true -f dshow` output (pure, tested on every host).
pub fn parse_dshow_audio(listing: &str) -> Option<String> {
    let mut audio_section = false;
    for l in listing.lines() {
        if l.contains("DirectShow audio devices") {
            audio_section = true;
        }
        if l.contains("Alternative name") {
            continue;
        }
        let quoted = l.split('"').nth(1).filter(|s| !s.is_empty());
        if let Some(name) = quoted {
            if l.contains("(audio)") || audio_section {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// The recorder argv for this host (`None` = no recorder installed).
pub fn recorder_command(m: &Media) -> Option<Vec<String>> {
    if let Some(c) = m.cfg.str("voice.record_command") {
        return Some(crate::proc::shell_argv(&c));
    }
    for name in ["pw-record", "parec", "arecord"] {
        if crate::proc::which(name).is_some() {
            return recorder_argv(name, None);
        }
    }
    recorder_argv("ffmpeg", crate::audio::ffmpeg())
}

/// Why capture is unavailable (`None` = a recorder exists).
pub fn audio_unavailable_reason(m: &Media) -> Option<String> {
    #[cfg(windows)]
    let hint = "No audio recorder found: install ffmpeg (it records the first DirectShow microphone) and make sure a microphone is connected and allowed (Settings → Privacy → Microphone), or set [media.voice] record_command";
    #[cfg(target_vendor = "apple")]
    let hint = "No audio recorder found: install ffmpeg (brew install ffmpeg; it records AVFoundation device :0) or set [media.voice] record_command";
    #[cfg(not(any(windows, target_vendor = "apple")))]
    let hint = "No audio recorder found: install pipewire (pw-record), pulseaudio-utils (parec), alsa-utils (arecord) or ffmpeg, or set [media.voice] record_command";
    recorder_command(m).is_none().then(|| hint.to_string())
}

/// A live recorder child process.
pub struct Mic {
    child: Child,
    rx: Receiver<Vec<i16>>,
}

impl Mic {
    pub fn open(m: &Media) -> Result<Mic, String> {
        let argv = recorder_command(m).ok_or_else(|| audio_unavailable_reason(m).unwrap_or_default())?;
        Mic::spawn(&argv)
    }
    pub fn spawn(argv: &[String]) -> Result<Mic, String> {
        let (prog, args) = argv.split_first().ok_or("empty recorder command")?;
        let mut child = seagent_core::platform::layout::program_command(prog).args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|e| format!("cannot start recorder `{prog}`: {e}"))?;
        let mut out = child.stdout.take().ok_or("recorder has no stdout")?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; BLOCK * 2];
            let mut carry: Vec<u8> = Vec::new();
            loop {
                match out.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        carry.extend_from_slice(&buf[..n]);
                        let even = carry.len() / 2 * 2;
                        let pcm = crate::audio::pcm16_from_bytes(&carry[..even]);
                        carry.drain(..even);
                        if tx.send(pcm).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(Mic { child, rx })
    }
}

impl PcmSource for Mic {
    fn read(&mut self, cancel: &Cancel) -> Result<Option<Vec<i16>>, String> {
        loop {
            if cancel.is_cancelled() {
                return Err("cancelled".into());
            }
            match self.rx.recv_timeout(Duration::from_millis(50)) {
                Ok(b) => return Ok(Some(b)),
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return Ok(None),
            }
        }
    }
}

impl Drop for Mic {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// PCM from memory (tests, files, client-streamed audio).
pub struct VecSource {
    pub samples: Vec<i16>,
    pub pos: usize,
}

impl VecSource {
    pub fn new(samples: Vec<i16>) -> Self {
        VecSource { samples, pos: 0 }
    }
}

impl PcmSource for VecSource {
    fn read(&mut self, _cancel: &Cancel) -> Result<Option<Vec<i16>>, String> {
        if self.pos >= self.samples.len() {
            return Ok(None);
        }
        let end = (self.pos + BLOCK).min(self.samples.len());
        let b = self.samples[self.pos..end].to_vec();
        self.pos = end;
        Ok(Some(b))
    }
}

/// Hermes `AudioRecorder` silence auto-stop: speech is confirmed after
/// `min_speech` above threshold (dips < `max_dip` tolerated); after speech, only
/// sustained resumed speech resets the silence timer.
#[derive(Debug, Clone)]
pub struct SilenceDetector {
    pub threshold: f64,
    pub silence_duration: f64,
    pub min_speech: f64,
    pub max_dip: f64,
    pub max_wait: f64,
    pub max_recording: f64,
    pub has_spoken: bool,
    pub peak: f64,
    speech_start: f64,
    dip_start: f64,
    silence_start: f64,
    resume_start: f64,
    resume_dip_start: f64,
}

impl SilenceDetector {
    pub fn new(m: &Media) -> Self {
        SilenceDetector {
            threshold: m.cfg.float_or("voice.silence_threshold", 200.0),
            silence_duration: m.cfg.float_or("voice.silence_duration", 3.0),
            min_speech: 0.3,
            max_dip: 0.3,
            max_wait: m.cfg.float_or("voice.max_wait", 15.0),
            max_recording: m.cfg.float_or("voice.max_recording_seconds", 0.0),
            has_spoken: false,
            peak: 0.0,
            speech_start: 0.0,
            dip_start: 0.0,
            silence_start: 0.0,
            resume_start: 0.0,
            resume_dip_start: 0.0,
        }
    }

    /// `true` when spoken-then-silent for `silence_duration`, no speech for `max_wait`,
    /// or the hard cap elapsed. `now` = seconds since the take started (> 0).
    pub fn feed(&mut self, rms: f64, now: f64) -> bool {
        self.peak = self.peak.max(rms);
        // _track_speech
        if rms > self.threshold {
            self.dip_start = 0.0;
            if self.speech_start == 0.0 {
                self.speech_start = now;
            } else if !self.has_spoken && now - self.speech_start >= self.min_speech {
                self.has_spoken = true;
            }
            if !self.has_spoken {
                self.silence_start = 0.0;
            } else {
                self.resume_dip_start = 0.0;
                if self.resume_start == 0.0 {
                    self.resume_start = now;
                } else if now - self.resume_start >= self.min_speech {
                    self.silence_start = 0.0;
                    self.resume_start = 0.0;
                }
            }
        } else if self.has_spoken {
            if self.resume_start > 0.0 {
                if self.resume_dip_start == 0.0 {
                    self.resume_dip_start = now;
                } else if now - self.resume_dip_start >= self.max_dip {
                    self.resume_start = 0.0;
                    self.resume_dip_start = 0.0;
                }
            }
        } else if self.speech_start > 0.0 {
            if self.dip_start == 0.0 {
                self.dip_start = now;
            } else if now - self.dip_start >= self.max_dip {
                self.speech_start = 0.0;
                self.dip_start = 0.0;
            }
        }
        // _should_auto_stop
        if self.has_spoken && rms <= self.threshold {
            if self.silence_start == 0.0 {
                self.silence_start = now;
            } else if now - self.silence_start >= self.silence_duration {
                return true;
            }
        } else if !self.has_spoken && now >= self.max_wait {
            return true;
        }
        self.max_recording > 0.0 && now >= self.max_recording
    }
}

/// Record one utterance: until silence after speech, `max_wait` without speech, the
/// cap, the source ending, or `stop()` (push-to-talk release). `None` when nobody spoke.
pub fn record_utterance(m: &Media, src: &mut dyn PcmSource, cancel: &Cancel, stop: &dyn Fn() -> bool) -> Result<Option<Vec<i16>>, String> {
    record_utterance_with(m, src, cancel, stop, &mut |_| {})
}

/// [`record_utterance`], handing every captured block to `on_block` as it arrives
/// (live streaming STT).
pub fn record_utterance_with(m: &Media, src: &mut dyn PcmSource, cancel: &Cancel, stop: &dyn Fn() -> bool, on_block: &mut dyn FnMut(&[i16])) -> Result<Option<Vec<i16>>, String> {
    let mut det = SilenceDetector::new(m);
    let mut all: Vec<i16> = Vec::new();
    let mut pending: Vec<i16> = Vec::new();
    loop {
        if stop() {
            break;
        }
        let Some(b) = src.read(cancel)? else { break };
        pending.extend_from_slice(&b);
        let mut done = false;
        while pending.len() >= BLOCK {
            let blk: Vec<i16> = pending.drain(..BLOCK).collect();
            on_block(&blk);
            all.extend_from_slice(&blk);
            let now = all.len() as f64 / SAMPLE_RATE as f64;
            if det.feed(crate::audio::rms(&blk), now) {
                done = true;
                break;
            }
        }
        if done {
            break;
        }
    }
    all.extend(pending);
    // Hermes `AudioRecorder.stop()` keeps a take whose peak cleared the threshold and
    // discards only a silent one; `has_spoken` alone would drop a push-to-talk tap
    // shorter than `min_speech` (0.3 s) before it is ever transcribed.
    Ok((det.has_spoken || det.peak >= det.threshold).then_some(all))
}

/// Barge-in VAD (Hermes `listen_for_speech`): a rolling 90th-percentile floor of the
/// playback bleed, an 8× trigger clamped to [`threshold`, 4000], tripping after
/// `sustained_ms` of consecutive loud blocks.
pub struct BargeIn {
    calib: usize,
    trip: usize,
    window: VecDeque<f64>,
    min_floor: f64,
    consecutive: usize,
    base_threshold: f64,
}

impl BargeIn {
    pub fn new(sustained_ms: usize, calibration_ms: usize) -> Self {
        let calib = (calibration_ms / 30).max(1);
        BargeIn { calib, trip: (sustained_ms / 30).max(1), window: VecDeque::with_capacity(calib.max(100)), min_floor: 0.0, consecutive: 0, base_threshold: 400.0 }
    }
    fn pct90(&self) -> f64 {
        let mut v: Vec<f64> = self.window.iter().copied().collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        // numpy percentile (linear interpolation).
        let pos = 0.9 * (v.len().saturating_sub(1)) as f64;
        let (lo, hi) = (pos.floor() as usize, pos.ceil() as usize);
        v[lo] + (v[hi] - v[lo]) * (pos - lo as f64)
    }
    fn push(&mut self, rms: f64) {
        if self.window.len() == self.calib.max(100) {
            self.window.pop_front();
        }
        self.window.push_back(rms);
    }
    /// Feed one 30 ms block's RMS; `true` when the user is talking over playback.
    pub fn feed(&mut self, rms: f64) -> bool {
        if self.window.len() < self.calib {
            self.push(rms);
            return false;
        }
        let p = self.pct90();
        if self.min_floor == 0.0 {
            self.min_floor = p.max(400.0);
        }
        let floor = p.max(self.min_floor);
        let trigger = self.base_threshold.max(floor * 8.0).min(4000.0);
        if rms < trigger {
            self.push(rms);
        }
        self.consecutive = if rms >= trigger { self.consecutive + 1 } else { 0 };
        self.consecutive >= self.trip
    }
}

/// Watch `src` while TTS plays: returns `true` as soon as the user barges in, `false`
/// when `should_stop()` (playback finished) or the source ends.
pub fn listen_for_speech(src: &mut dyn PcmSource, cancel: &Cancel, should_stop: &dyn Fn() -> bool) -> bool {
    let mut vad = BargeIn::new(300, 400);
    let mut pending: Vec<i16> = Vec::new();
    while !should_stop() {
        let Ok(Some(b)) = src.read(cancel) else { return false };
        pending.extend_from_slice(&b);
        while pending.len() >= BLOCK {
            let blk: Vec<i16> = pending.drain(..BLOCK).collect();
            if vad.feed(crate::audio::rms(&blk)) {
                return true;
            }
        }
    }
    false
}

/// A 16-bit tone burst (beeps marking record start/stop; Hermes `play_beep`).
pub fn beep(frequency: f64, duration: f64, count: usize, volume: f64) -> Vec<i16> {
    let n = (SAMPLE_RATE as f64 * duration) as usize;
    let fade = ((SAMPLE_RATE as f64 * 0.01) as usize).min(n / 4).max(1);
    let mut out = Vec::new();
    for i in 0..count {
        for k in 0..n {
            let t = k as f64 / SAMPLE_RATE as f64;
            let mut s = (2.0 * std::f64::consts::PI * frequency * t).sin();
            if k < fade {
                s *= k as f64 / fade as f64;
            } else if k >= n - fade {
                s *= (n - k) as f64 / fade as f64;
            }
            out.push((s * volume * 32767.0) as i16);
        }
        if i + 1 < count {
            out.extend(std::iter::repeat_n(0, (SAMPLE_RATE as f64 * 0.06) as usize));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tone(secs: f64, amp: f64) -> Vec<i16> {
        (0..(secs * 16000.0) as usize).map(|i| ((i as f64 * 0.3).sin() * amp) as i16).collect()
    }

    #[test]
    fn silence_detector_stops_after_speech_then_silence() {
        let m = Media::new(crate::MediaConfig::from_toml("[voice]\nsilence_duration = 1.0\nmax_wait = 2.0\n"));
        let mut pcm = tone(0.2, 0.0);
        pcm.extend(tone(1.0, 3000.0));
        pcm.extend(tone(0.1, 0.0)); // a micro-pause is tolerated
        pcm.extend(tone(0.5, 3000.0));
        pcm.extend(tone(3.0, 0.0));
        let mut src = VecSource::new(pcm.clone());
        let take = record_utterance(&m, &mut src, &Cancel::new(), &|| false).unwrap().unwrap();
        let secs = take.len() as f64 / 16000.0;
        assert!((2.7..2.95).contains(&secs), "stopped {secs}s in");
        // No speech: gives up after max_wait.
        let mut quiet = VecSource::new(tone(5.0, 50.0));
        assert!(record_utterance(&m, &mut quiet, &Cancel::new(), &|| false).unwrap().is_none());
        assert!(quiet.pos <= 2 * 16000 + BLOCK);
        // Hard cap.
        let capped = Media::new(crate::MediaConfig::from_toml("[voice]\nmax_recording_seconds = 1.0\n"));
        let mut long = VecSource::new(tone(5.0, 3000.0));
        let t = record_utterance(&capped, &mut long, &Cancel::new(), &|| false).unwrap().unwrap();
        assert!(t.len() <= 16000 + BLOCK);
    }

    #[test]
    fn barge_in_trips_on_speech_over_bleed_not_bleed() {
        let mut v = BargeIn::new(300, 400);
        let bleed: Vec<f64> = (0..200).map(|i| 300.0 + (i % 7) as f64 * 40.0).collect();
        assert!(!bleed.iter().any(|r| v.feed(*r)), "speaker bleed never trips");
        let mut tripped = false;
        for _ in 0..12 {
            tripped |= v.feed(6000.0);
        }
        assert!(tripped);
        let mut src = VecSource::new([tone(1.0, 400.0), tone(1.0, 9000.0)].concat());
        assert!(listen_for_speech(&mut src, &Cancel::new(), &|| false));
        let mut calm = VecSource::new(tone(2.0, 400.0));
        assert!(!listen_for_speech(&mut calm, &Cancel::new(), &|| false));
    }

    #[test]
    fn short_take_above_threshold_is_kept() {
        // 0.15 s of speech then release: under `min_speech` (0.3 s), so `has_spoken`
        // never latches — but the peak cleared the threshold, which is what Hermes
        // `stop()` checks before discarding a take.
        let m = Media::new(crate::MediaConfig::from_toml("[voice]\n"));
        let mut src = VecSource::new(tone(0.15, 3000.0));
        assert!(record_utterance(&m, &mut src, &Cancel::new(), &|| false).unwrap().is_some());
        let mut quiet = VecSource::new(tone(0.15, 20.0));
        assert!(record_utterance(&m, &mut quiet, &Cancel::new(), &|| false).unwrap().is_none());
    }

    #[test]
    fn recorders_emit_raw_pcm_not_a_container() {
        // pw-record to stdout writes .au (header + big-endian samples) without --raw;
        // parec writes WAV. Both would corrupt the s16le stream `Mic` parses.
        for name in ["pw-record", "parec"] {
            let argv = recorder_argv(name, None).unwrap();
            assert!(argv.contains(&"--raw".to_string()), "{name} needs --raw: {argv:?}");
        }
        let a = recorder_argv("arecord", None).unwrap();
        assert!(a.windows(2).any(|w| w == ["-t", "raw"]) && a.last().unwrap() == "-", "{a:?}");
        // Linux: PulseAudio `default`. Windows: the first DirectShow microphone, so `None` on a
        // machine without one; the raw-PCM output is the same either way.
        #[cfg(not(windows))]
        let f = recorder_argv("ffmpeg", Some("/usr/bin/ffmpeg".into())).unwrap();
        #[cfg(windows)]
        let f = match crate::audio::ffmpeg().and_then(|ff| recorder_argv("ffmpeg", Some(ff))) {
            Some(f) => {
                assert!(f.windows(2).any(|w| w == ["-f", "dshow"]), "{f:?}");
                f
            }
            None => vec!["-f".into(), "s16le".into(), "-".into()],
        };
        assert!(f.windows(2).any(|w| w == ["-f", "s16le"]) && f.last().unwrap() == "-", "{f:?}");
        assert!(recorder_argv("sox", None).is_none());
        // `record_command` still wins over every discovered recorder.
        let m = Media::new(crate::MediaConfig::from_toml(
            "[voice]\nrecord_command = \"cat /dev/zero\"\n",
        ));
        assert_eq!(recorder_command(&m).unwrap(), crate::proc::shell_argv("cat /dev/zero"));
    }

    #[test]
    fn dshow_listing_yields_the_first_microphone() {
        let new_style = "[dshow @ 0000] \"Integrated Camera\" (video)\n[dshow @ 0000]   Alternative name \"@device_pnp_x\"\n[dshow @ 0000] \"Microphone (Realtek(R) Audio)\" (audio)\n[dshow @ 0000]   Alternative name \"@device_cm_y\"\n";
        assert_eq!(parse_dshow_audio(new_style).as_deref(), Some("Microphone (Realtek(R) Audio)"));
        let old_style = "[dshow @ 0] DirectShow video devices\n[dshow @ 0]  \"Cam\"\n[dshow @ 0] DirectShow audio devices\n[dshow @ 0]  \"Mic Array\"\n";
        assert_eq!(parse_dshow_audio(old_style).as_deref(), Some("Mic Array"));
        assert_eq!(parse_dshow_audio("dummy: Immediate exit requested"), None);
    }

    #[test]
    fn mic_reads_a_recorder_process() {
        let w = crate::audio::pcm16_to_bytes(&tone(0.1, 1000.0));
        let d = crate::testutil::temp_dir("mic");
        std::fs::write(d.join("pcm.raw"), &w).unwrap();
        // A shell line (Git Bash on Windows: `C:/…`), in a TOML literal string.
        let m = Media::new(crate::MediaConfig::from_toml(&format!("[voice]\nrecord_command = 'cat {}'\n", seagent_core::platform::shell::path_str(&d.join("pcm.raw")))));
        let mut mic = Mic::open(&m).unwrap();
        let mut got = Vec::new();
        while let Some(b) = mic.read(&Cancel::new()).unwrap() {
            got.extend(b);
        }
        assert_eq!(got.len(), 1600);
        assert_eq!(beep(880.0, 0.12, 2, 0.3).len(), 1920 * 2 + 960);
    }
}
