//! Per-provider upload limits and long-audio splitting for cloud STT (Hermes
//! `tools/transcription_chunking.py`): an oversized input is re-encoded to 16 kHz mono
//! 32 kbps AAC first; when it still does not fit it is cut at silences close to the
//! limit and each segment is transcribed on its own, transcripts joined in order.

use super::Transcript;
use crate::proc;
use seagent_core::Cancel;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MB: f64 = 1024.0 * 1024.0;
/// Margin under each cap so container overhead and rounding never tip a segment over.
pub const SEGMENT_HEADROOM: f64 = 0.9;
/// How far back from the ideal cut a silence may sit and still be the cut point.
pub const MAX_SILENCE_LOOKBACK: f64 = 60.0;
/// The compact STT encode (Hermes `_STT_M4A_ENCODE_ARGS`).
pub const STT_M4A_ARGS: &[&str] = &["-vn", "-ac", "1", "-ar", "16000", "-c:a", "aac", "-b:a", "32k", "-movflags", "+faststart"];

pub fn fits(size: usize, duration: Option<f64>, limit: (usize, Option<f64>)) -> bool {
    size <= limit.0 && (limit.1.is_none() || duration.is_none() || duration <= limit.1)
}

/// Midpoints (seconds) of the pauses in ffmpeg `silencedetect` stderr.
pub fn silence_midpoints(stderr: &str) -> Vec<f64> {
    let grab = |key: &str| -> Vec<f64> { stderr.match_indices(key).filter_map(|(i, _)| stderr[i + key.len()..].split_whitespace().next().and_then(|v| v.trim_end_matches('|').parse().ok())).collect() };
    let starts = grab("silence_start: ");
    let ends = grab("silence_end: ");
    starts.iter().zip(ends.iter()).map(|(s, e)| (s.max(0.0) + e) / 2.0).collect()
}

/// Cut times giving segments no longer than `target`, each at the latest pause before
/// the ideal cut (Hermes `_cut_points`).
pub fn cut_points(duration: f64, target: f64, silences: &[f64]) -> Vec<f64> {
    let mut cuts = Vec::new();
    let mut pos = 0.0;
    let lookback = MAX_SILENCE_LOOKBACK.min(target / 4.0);
    while duration - pos > target {
        let ideal = pos + target;
        let nearby = silences.iter().copied().filter(|s| *s >= ideal - lookback && *s <= ideal && *s > pos).fold(None, |a: Option<f64>, s| Some(a.map_or(s, |x| x.max(s))));
        pos = nearby.unwrap_or(ideal);
        cuts.push(pos);
    }
    cuts
}

fn run_ff(argv: Vec<String>, cancel: &Cancel) -> Result<proc::Output, String> {
    proc::run(&argv, None, Duration::from_secs(300), cancel)
}

/// Fit `input` under `limit` (re-encode, else split at silences) and run `dispatch` per
/// piece. `dispatch` gets `(bytes, mime, file name)`.
pub fn transcribe_oversized(input: &Path, limit: (usize, Option<f64>), cancel: &Cancel, mut dispatch: impl FnMut(Vec<u8>, &str, &str) -> Result<Transcript, String>) -> Result<Transcript, String> {
    let too_large = |reason: &str| {
        let size = std::fs::metadata(input).map(|m| m.len() as f64).unwrap_or(0.0);
        format!("File too large: {:.1}MB (max {:.0}MB) and it could not be split: {reason}", size / MB, limit.0 as f64 / MB)
    };
    let ff = crate::audio::ffmpeg().ok_or_else(|| too_large("ffmpeg was not found"))?;
    let ffs = ff.display().to_string();
    let dir = super::local::work_dir("split")?;
    let r = (|| {
        let compact = dir.join("compact.m4a");
        let mut argv = vec![ffs.clone(), "-y".into(), "-loglevel".into(), "error".into(), "-i".into(), input.display().to_string()];
        argv.extend(STT_M4A_ARGS.iter().map(|s| s.to_string()));
        argv.push(compact.display().to_string());
        run_ff(argv, cancel)?.check("ffmpeg").map_err(|e| too_large(&e))?;
        let size = std::fs::metadata(&compact).map(|m| m.len() as usize).unwrap_or(0);
        if size == 0 {
            return Err(too_large("re-encoding produced no file"));
        }
        let duration = crate::audio::duration_secs(&compact, cancel);
        if fits(size, duration, limit) {
            return dispatch(std::fs::read(&compact).map_err(|e| e.to_string())?, "audio/mp4", "audio.m4a");
        }
        let duration = duration.filter(|d| *d > 0.0).ok_or_else(|| too_large("its duration could not be read"))?;
        let mut target = limit.0 as f64 * SEGMENT_HEADROOM * duration / size as f64;
        if let Some(s) = limit.1 {
            target = target.min(s * SEGMENT_HEADROOM);
        }
        let sd = run_ff(vec![ffs.clone(), "-hide_banner".into(), "-nostats".into(), "-i".into(), compact.display().to_string(), "-af".into(), "silencedetect=noise=-35dB:d=0.4".into(), "-f".into(), "null".into(), "-".into()], cancel).map(|o| silence_midpoints(&o.stderr)).unwrap_or_default();
        let cuts = cut_points(duration, target, &sd);
        let pattern = dir.join("part%03d.m4a");
        let times: Vec<String> = cuts.iter().map(|c| format!("{c:.3}")).collect();
        run_ff(vec![ffs.clone(), "-y".into(), "-loglevel".into(), "error".into(), "-i".into(), compact.display().to_string(), "-vn".into(), "-c".into(), "copy".into(), "-f".into(), "segment".into(), "-segment_times".into(), times.join(","), "-reset_timestamps".into(), "1".into(), pattern.display().to_string()], cancel)?.check("ffmpeg")?;
        let mut parts: Vec<PathBuf> = std::fs::read_dir(&dir).map_err(|e| e.to_string())?.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("part"))).collect();
        parts.sort();
        join_parts(&parts, &mut dispatch)
    })();
    let _ = std::fs::remove_dir_all(&dir);
    r
}

/// Transcribe each part in order, skipping empty / hallucinated segments.
pub fn join_parts(parts: &[PathBuf], dispatch: &mut impl FnMut(Vec<u8>, &str, &str) -> Result<Transcript, String>) -> Result<Transcript, String> {
    let n = parts.len();
    let mut texts = Vec::new();
    let mut total = 0.0;
    for (i, p) in parts.iter().enumerate() {
        let bytes = std::fs::read(p).map_err(|e| e.to_string())?;
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let t = dispatch(bytes, "audio/mp4", &name).map_err(|e| format!("Segment {}/{n} failed: {e}", i + 1))?;
        total += t.duration.unwrap_or(0.0);
        let s = t.text.trim();
        if !s.is_empty() && !crate::voice::transcript::is_whisper_hallucination(s) {
            texts.push(s.to_string());
        }
    }
    if texts.is_empty() {
        return Err("Transcription returned an empty transcript".into());
    }
    Ok(Transcript { text: texts.join(" "), duration: (total > 0.0).then_some(total), ..Default::default() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cut_points_prefer_recent_silence() {
        assert_eq!(cut_points(100.0, 40.0, &[]), vec![40.0, 80.0]);
        // A pause at 37 s is within the lookback (10 s) of the ideal 40 s cut.
        assert_eq!(cut_points(100.0, 40.0, &[12.0, 37.0, 60.0]), vec![37.0, 77.0]);
        assert!(cut_points(30.0, 40.0, &[10.0]).is_empty());
        let mids = silence_midpoints("[silencedetect @ 0x1] silence_start: 9.5\n[silencedetect @ 0x1] silence_end: 10.5 | silence_duration: 1\n silence_start: -0.01\n silence_end: 0.2 |");
        assert_eq!(mids, vec![10.0, 0.1]);
        assert!(fits(10, Some(5.0), (10, Some(5.0))) && !fits(11, None, (10, None)) && !fits(1, Some(6.0), (10, Some(5.0))) && fits(1, None, (10, Some(5.0))));
    }

    #[test]
    fn parts_join_in_order_and_drop_hallucinations() {
        let d = crate::testutil::temp_dir("parts");
        let parts: Vec<PathBuf> = (0..3).map(|i| d.join(format!("part{i:03}.m4a"))).collect();
        for (i, p) in parts.iter().enumerate() {
            std::fs::write(p, format!("{i}")).unwrap();
        }
        let mut f = |b: Vec<u8>, _: &str, _: &str| Ok(Transcript { text: match b[0] { b'0' => "hello".into(), b'1' => "Thank you.".into(), _ => "world".into() }, duration: Some(2.0), ..Default::default() });
        let t = join_parts(&parts, &mut f).unwrap();
        assert_eq!((t.text.as_str(), t.duration), ("hello world", Some(6.0)));
        let mut g = |b: Vec<u8>, _: &str, _: &str| if b[0] == b'1' { Err("boom".to_string()) } else { Ok(Transcript::default()) };
        assert_eq!(join_parts(&parts, &mut g).unwrap_err(), "Segment 2/3 failed: boom");
    }
}
