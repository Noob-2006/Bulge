//! Playback and streaming speech.
//!
//! [`play`] runs one audio file through the configured player: `[media.tts] player`
//! (a command template with `{path}`, e.g. `"mpv --no-video {path}"`) or the first of
//! `paplay` / `pw-play` / `aplay` / `ffplay` / `mpv` found on `$PATH`. The child gets
//! `[media.tts] timeout_secs` (60 s) and is killed on cancellation — only that child,
//! never anything a test or another session started.
//!
//! [`speak_streaming`] is voice mode's streaming path (Hermes `tools/tts_streaming.py`,
//! OpenClaw `src/tts/tts-streaming.ts`): the text is cut into sentences with
//! [`SentenceChunker`] as it arrives, each sentence is synthesized and played while the
//! rest of the text is still being produced, so the first audio starts long before the
//! reply ends.

use super::normalize::SentenceChunker;
use super::{finalize, synthesize, TtsRequest};
use crate::{proc, Media};
use seagent_core::Cancel;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Players tried in order when `[media.tts] player` is unset.
const DEFAULT_PLAYERS: &[&str] = &["paplay", "pw-play", "aplay", "ffplay", "mpv"];

/// Playback timeout (`[media.tts] timeout_secs`, default 60, clamped to 1 h).
fn timeout(m: &Media) -> Duration {
    Duration::from_secs(m.cfg.int_or("tts.timeout_secs", 60).clamp(1, 3600) as u64)
}

/// Split a command template into argv, honouring single/double quotes and backslashes.
fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut started = false;
    let mut quote: Option<char> = None;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else if c == '\\' && q == '"' {
                    if let Some(n) = chars.next() {
                        cur.push(n);
                    }
                } else {
                    cur.push(c);
                }
            }
            None => {
                if c.is_whitespace() {
                    if started || !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                        started = false;
                    }
                } else if c == '\'' || c == '"' {
                    quote = Some(c);
                    started = true;
                } else if c == '\\' {
                    if let Some(n) = chars.next() {
                        cur.push(n);
                        started = true;
                    }
                } else {
                    cur.push(c);
                    started = true;
                }
            }
        }
    }
    if started || !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn player_argv(m: &Media, path: &Path) -> Result<Vec<String>, String> {
    let file = path.display().to_string();
    if let Some(template) = m.cfg.str("tts.player") {
        let argv = split_args(&proc::render_template(&template, &[("path", &file)]));
        if argv.is_empty() {
            return Err("[media.tts] player is empty".into());
        }
        return Ok(argv);
    }
    for name in DEFAULT_PLAYERS {
        if proc::which(name).is_none() {
            continue;
        }
        let argv: Vec<String> = match *name {
            "ffplay" => vec![(*name).into(), "-nodisp".into(), "-autoexit".into(), "-loglevel".into(), "quiet".into(), file.clone()],
            "mpv" => vec![(*name).into(), "--no-video".into(), "--really-quiet".into(), file.clone()],
            _ => vec![(*name).into(), file.clone()],
        };
        return Ok(argv);
    }
    Err(format!(
        "no audio player found (tried {}); install one or set [media.tts] player",
        DEFAULT_PLAYERS.join(", ")
    ))
}

/// Play one audio file; `Err` carries the player's own message (never panics, never
/// signals a process this call did not start).
pub fn play(m: &Media, path: &Path, cancel: &Cancel) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!("{}: no such audio file", path.display()));
    }
    let argv = player_argv(m, path)?;
    let prog = argv.first().cloned().unwrap_or_default();
    let out = proc::run(&argv, None, timeout(m), cancel)?;
    out.check(&format!("audio playback ({prog})"))?;
    Ok(())
}

fn stream_dir(m: &Media) -> PathBuf {
    super::tool::fallback_out_dir(m, "speech")
}

/// May a reply be spoken sentence by sentence? `[media.voice] streaming` (voice mode) and
/// `[media.tts.streaming] enabled` (the provider path) both default to on; a provider that
/// cannot synthesize a sentence at a time, or an operator who wants whole files, turns it off.
pub fn streaming_enabled(m: &Media) -> bool {
    m.cfg.bool_or("voice.streaming", true) && m.cfg.bool_or("tts.streaming.enabled", true)
}

/// What a streaming pass did: chunks synthesized, how many were played (the fallback decision
/// needs this), whether a listener talked over the reply, and the error that ended it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StreamReport {
    pub chunks: usize,
    pub played: usize,
    pub interrupted: bool,
    pub error: Option<String>,
}

/// Speak `text` sentence by sentence: first audio plays while later sentences are still
/// being synthesized (Hermes `tts_streaming`). `gate` is asked before each chunk — voice mode
/// passes barge-in (`true` = the listener is talking, stop) — and every chunk is normalized to
/// spoken text, so Markdown never reaches a provider.
pub fn speak_streaming_gated(m: &Media, text: &str, cancel: &Cancel, gate: &dyn Fn() -> bool) -> StreamReport {
    let mut rep = StreamReport::default();
    let min_len = m.cfg.int_or("tts.streaming.min_len", 20).clamp(1, 500) as usize;
    let mut chunker = SentenceChunker::new(min_len);
    // Feed line by line so a sentence that is already complete is spoken at once.
    let mut parts: Vec<String> = Vec::new();
    for line in text.split_inclusive('\n') {
        parts.extend(chunker.feed(line));
        if cancel.is_cancelled() {
            rep.error = Some("streaming speech cancelled".into());
            return rep;
        }
    }
    parts.extend(chunker.flush());
    rep.chunks = parts.len();
    if parts.is_empty() {
        return rep;
    }
    let dir = stream_dir(m);
    let base = crate::store::stem("stream");
    for (i, part) in parts.iter().enumerate() {
        if cancel.is_cancelled() || gate() {
            rep.interrupted = true;
            return rep;
        }
        let spoken = super::normalize(part);
        if spoken.trim().is_empty() {
            continue;
        }
        let (provider, speech) = match synthesize(m, &TtsRequest::new(&spoken), cancel) {
            Ok(v) => v,
            Err(e) => {
                rep.error = Some(e);
                return rep;
            }
        };
        let (asset, _) = finalize(m, &provider, speech, false, cancel);
        let path = match crate::store::save(&dir, &format!("{base}-{:03}", i + 1), &asset) {
            Ok(p) => p,
            Err(e) => {
                rep.error = Some(e);
                return rep;
            }
        };
        rep.played += 1;
        let played = play(m, &path, cancel);
        let _ = std::fs::remove_file(&path);
        if let Err(e) = played {
            rep.error = Some(e);
            return rep;
        }
    }
    rep
}

/// Speak `text` sentence by sentence; `Err` when a chunk could not be synthesized or played
/// (or the call was cancelled).
pub fn speak_streaming(m: &Media, text: &str, cancel: &Cancel) -> Result<(), String> {
    let rep = speak_streaming_gated(m, text, cancel, &|| false);
    if cancel.is_cancelled() {
        return Err("streaming speech cancelled".into());
    }
    match rep.error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};

    /// ElevenLabs over a fake server: the audio bytes echo the spoken text, so a fake
    /// player can log exactly which sentences were synthesized (and in which order).
    fn echo_server() -> FakeServer {
        FakeServer::start_raw(|r, _| {
            if r.path.starts_with("/v1/text-to-speech/") {
                let text = r.json()["text"].as_str().unwrap_or("").to_string();
                (200, vec![("content-type".into(), "audio/mpeg".into())], format!("ID3\x04{text}").into_bytes())
            } else {
                (404, vec![], b"{}".to_vec())
            }
        })
    }

    fn media(tag: &str, extra: &str) -> (Media, PathBuf) {
        let dir = temp_dir(tag);
        let cfg = format!("output_dir = \"{}\"\n[tts]\nprefs_path = \"{}\"\n{extra}", dir.join("media").display(), dir.join("p.json").display());
        (Media { cfg: crate::MediaConfig::from_toml(&cfg), http: Default::default() }, dir)
    }

    /// A fake player: appends the audio file's contents to `log`, exits with `code`.
    fn fake_player(dir: &Path, log: &Path, code: i32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let script = bin.join("fakeplay");
        std::fs::write(&script, format!("#!/bin/sh\nfor f in \"$@\"; do cat \"$f\" >> '{}'; echo >> '{}'; done\nexit {code}\n", log.display(), log.display())).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    #[test]
    fn split_args_handles_quotes() {
        assert_eq!(split_args("paplay '/tmp/a b.mp3'"), vec!["paplay", "/tmp/a b.mp3"]);
        assert_eq!(split_args("mpv --no-video \"/x/y.mp3\""), vec!["mpv", "--no-video", "/x/y.mp3"]);
        assert_eq!(split_args("  "), Vec::<String>::new());
        assert_eq!(split_args("a\\ b c"), vec!["a b", "c"]);
    }

    #[test]
    fn play_runs_the_configured_player() {
        let (_, dir) = media("stream-play", "");
        let log = dir.join("played.log");
        let player = fake_player(&dir, &log, 0);
        let audio = dir.join("a.mp3");
        std::fs::write(&audio, b"ID3\x04hello").unwrap();
        let m = Media { cfg: crate::MediaConfig::from_toml(&format!("[tts]\nprefs_path = \"{}\"\nplayer = \"{} {{path}}\"\n", dir.join("p.json").display(), player.display())), http: Default::default() };
        play(&m, &audio, &Cancel::new()).expect("fake player succeeds");
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "ID3\x04hello\n");
        // A second call still only touches the audio it was given.
        play(&m, &audio, &Cancel::new()).unwrap();
        assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 2);
    }

    #[test]
    fn play_reports_failures_without_panicking() {
        let (_, dir) = media("stream-play-fail", "");
        let log = dir.join("played.log");
        let failing = fake_player(&dir, &log, 3);
        let audio = dir.join("b.mp3");
        std::fs::write(&audio, b"ID3\x04x").unwrap();
        let m = Media { cfg: crate::MediaConfig::from_toml(&format!("[tts]\nplayer = \"{} {{path}}\"\n", failing.display())), http: Default::default() };
        let e = play(&m, &audio, &Cancel::new()).unwrap_err();
        assert!(e.contains("exited with 3"), "{e}");

        // Missing player binary and missing file are errors, not panics.
        let m2 = Media { cfg: crate::MediaConfig::from_toml("[tts]\nplayer = \"/nonexistent/seagent-player {path}\"\n"), http: Default::default() };
        let e2 = play(&m2, &audio, &Cancel::new()).unwrap_err();
        assert!(e2.contains("cannot run"), "{e2}");
        let e3 = play(&m2, &dir.join("missing.mp3"), &Cancel::new()).unwrap_err();
        assert!(e3.contains("no such audio file"), "{e3}");

        // A player that never exits is killed by the timeout.
        let slow = dir.join("slow.sh");
        std::fs::write(&slow, "#!/bin/sh\nsleep 30\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&slow, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let m3 = Media { cfg: crate::MediaConfig::from_toml(&format!("[tts]\nplayer = \"{} {{path}}\"\ntimeout_secs = 1\n", slow.display())), http: Default::default() };
        let e4 = play(&m3, &audio, &Cancel::new()).unwrap_err();
        assert!(e4.contains("timed out"), "{e4}");
    }

    #[test]
    fn speak_streaming_plays_every_sentence_in_order() {
        let srv = echo_server();
        let (_, dir) = media("stream-speak", "");
        let log = dir.join("spoken.log");
        let player = fake_player(&dir, &log, 0);
        let m = Media {
            cfg: crate::testutil::cfg_for("elevenlabs", &srv.url, &format!("output_dir = \"{}\"\n[tts]\nprefs_path = \"{}\"\nprovider = \"elevenlabs\"\nplayer = \"{} {{path}}\"\n", dir.join("media").display(), dir.join("p.json").display(), player.display())),
            http: Default::default(),
        };
        let text = "The first sentence is spoken.\nThe second sentence follows it.\nAnd a third one ends the reply.";
        speak_streaming(&m, text, &Cancel::new()).expect("streamed speech");
        let played = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = played.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 3, "one file per sentence, played as they are ready: {played}");
        assert!(lines[0].ends_with("The first sentence is spoken."), "{played}");
        assert!(lines[1].ends_with("The second sentence follows it."), "{played}");
        assert!(lines[2].ends_with("And a third one ends the reply."), "{played}");
        // Temporary audio is cleaned up after playback.
        let left: Vec<_> = std::fs::read_dir(dir.join("media").join("speech")).map(|d| d.flatten().collect()).unwrap_or_default();
        assert!(left.is_empty(), "streamed files are removed: {left:?}");

        // Empty text is a no-op; a failing player surfaces its error.
        speak_streaming(&m, "   ", &Cancel::new()).unwrap();
        let bad = Media {
            cfg: crate::testutil::cfg_for("elevenlabs", &srv.url, &format!("output_dir = \"{}\"\n[tts]\nprefs_path = \"{}\"\nprovider = \"elevenlabs\"\nplayer = \"/nonexistent/seagent-player {{path}}\"\n", dir.join("media2").display(), dir.join("p.json").display())),
            http: Default::default(),
        };
        assert!(speak_streaming(&bad, "This sentence will fail to play.", &Cancel::new()).is_err());
    }

    #[test]
    fn speak_streaming_merges_short_fragments() {
        let srv = echo_server();
        let (_, dir) = media("stream-merge", "");
        let log = dir.join("merged.log");
        let player = fake_player(&dir, &log, 0);
        let m = Media {
            cfg: crate::testutil::cfg_for("elevenlabs", &srv.url, &format!("output_dir = \"{}\"\n[tts]\nprefs_path = \"{}\"\nprovider = \"elevenlabs\"\nplayer = \"{} {{path}}\"\n[tts.streaming]\nmin_len = 40\n", dir.join("media").display(), dir.join("p.json").display(), player.display())),
            http: Default::default(),
        };
        speak_streaming(&m, "Hi. There. A longer closing sentence that clears the minimum length easily.", &Cancel::new()).unwrap();
        let played = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = played.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 1, "fragments under min_len are merged: {played}");
        assert!(lines[0].contains("Hi. There. A longer closing sentence"));
    }
}
