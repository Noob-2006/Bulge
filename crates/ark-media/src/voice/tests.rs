use super::mode::*;
use super::record::{PcmSource, VecSource};
use crate::Media;
use ark_core::Cancel;
use std::sync::{Arc, Mutex};

struct Io {
    keys: Vec<Key>,
    lines: Vec<String>,
}

impl VoiceIo for Io {
    fn wait_key(&mut self, _p: &str) -> Key {
        if self.keys.is_empty() {
            Key::Quit
        } else {
            self.keys.remove(0)
        }
    }
    fn released(&self) -> bool {
        false
    }
    fn say(&mut self, l: &str) {
        self.lines.push(l.to_string());
    }
}

struct Agent(Mutex<Vec<String>>);

impl crate::Agent for Agent {
    fn turn(&self, session: Option<&str>, text: &str, source: &str, _c: &Cancel) -> Result<(String, String), String> {
        assert_eq!(source, "voice");
        self.0.lock().unwrap().push(format!("{session:?}:{text}"));
        Ok(("sess-1".into(), "It is noon.".into()))
    }
}

fn tone(s: f64, a: f64) -> Vec<i16> {
    (0..(s * 16000.0) as usize).map(|i| ((i as f64 * 0.3).sin() * a) as i16).collect()
}

#[test]
fn flags_shape_the_mode_and_a_session_continues() {
    // Config alone.
    let cfg = Media::new(crate::MediaConfig::from_toml("[voice]\nmode = \"Continuous\"\nwake_word = true\nspeak = true\nbarge_in = true\n"));
    let o = VoiceModeOpts::from_config(&cfg);
    assert!(o.continuous && o.wake_word && o.speak && o.barge_in && o.beep, "{o:?}");
    assert_eq!((o.session.as_deref(), o.max_turns), (None, 0));
    // Flags: --no-speak/--no-barge-in/--session/--max-turns win over config.
    let f = VoiceFlags { no_speak: true, no_barge_in: true, session: Some("sess-7".into()), max_turns: 3, ..Default::default() };
    let o = VoiceModeOpts::from_flags(&cfg, &f);
    assert!(!o.speak && !o.barge_in && o.continuous && o.wake_word);
    assert_eq!((o.session.as_deref(), o.max_turns), (Some("sess-7"), 3));
    // --continuous/--wake turn a press-to-talk default into hands-free.
    let ptt = Media::new(crate::MediaConfig::from_toml("[voice]\nmode = \"ptt\"\nwake_word = false\n"));
    assert!(!VoiceModeOpts::from_config(&ptt).continuous);
    let o = VoiceModeOpts::from_flags(&ptt, &VoiceFlags { continuous: true, ..Default::default() });
    assert!(o.continuous && !o.wake_word);
    let o = VoiceModeOpts::from_flags(&ptt, &VoiceFlags { wake: true, ..Default::default() });
    assert!(o.wake_word && !o.continuous);
    // Blank --session / --max-turns 0 change nothing.
    let o = VoiceModeOpts::from_flags(&ptt, &VoiceFlags { session: Some("  ".into()), ..Default::default() });
    assert_eq!(o.session, None);

    // A chosen session is continued by the turn, and --no-speak skips TTS entirely
    // (no provider is configured, so speaking would fail loudly instead).
    let d = crate::testutil::temp_dir("voice-flags");
    let n = d.join("n");
    let cmd = format!("n=$(cat {n} 2>/dev/null || echo 0); n=$((n+1)); echo $n > {n}; echo 'what time is it'", n = n.display());
    let m = Media::new(crate::MediaConfig::from_toml(&format!("[stt]\nprovider = \"fake\"\n[stt.providers.fake]\ncommand = \"{cmd}\"\n[voice]\nsilence_duration = 0.5\nmax_wait = 1.0\n")));
    let take = [tone(0.2, 0.0), tone(0.8, 3000.0), tone(1.0, 0.0)].concat();
    let mic: MicFactory = Arc::new(move |_m: &Media| Ok(Box::new(VecSource::new(take.clone())) as Box<dyn PcmSource>));
    let mut io = Io { keys: vec![Key::Talk, Key::Talk], lines: vec![] };
    let agent = Agent(Mutex::new(vec![]));
    let opts = VoiceModeOpts::from_flags(&m, &VoiceFlags { no_speak: true, session: Some("prev".into()), max_turns: 1, ..Default::default() });
    let s = voice_mode(&m, &opts, &mut io, &mic, &agent, &Cancel::new()).unwrap();
    assert_eq!((s.turns, s.session.as_deref()), (1, Some("sess-1")), "one capped turn, then the new session is reported");
    assert_eq!(agent.0.lock().unwrap().as_slice(), ["Some(\"prev\"):what time is it"]);
    assert!(io.lines.iter().any(|l| l == "ark: It is noon.") && !io.lines.iter().any(|l| l.contains("[speech failed")), "{:?}", io.lines);
    // `ark voice status` reports the pieces the CLI checks before starting.
    let r = requirements(&m);
    assert_eq!((r["stt_provider"].as_str(), r["stt_streaming"].as_bool(), r["stt_available"].as_bool()), (Some("fake"), Some(false), Some(true)), "{r}");
    assert_eq!(r["available"].as_bool(), Some(r["recorder"].is_string()), "usable only with a recorder: {r}");
    assert_eq!(r["wake_word"]["available"], false);
    assert!(r["wake_word"]["error"].as_str().unwrap().starts_with("No wake word engine available"), "{r}");
}

#[test]
fn push_to_talk_turns_filter_and_stop_phrase() {

    let d = crate::testutil::temp_dir("voice-mode");
    let n = d.join("n");
    // STT stand-in: 1st take = a question, 2nd = a Whisper hallucination, 3rd = the stop phrase.
    let cmd = format!("n=$(cat {n} 2>/dev/null || echo 0); n=$((n+1)); echo $n > {n}; case $n in 1) echo 'what time is it';; 2) echo 'Thank you.';; *) echo 'Stop.';; esac", n = n.display());
    let m = Media::new(crate::MediaConfig::from_toml(&format!("[stt]\nprovider = \"fake\"\n[stt.providers.fake]\ncommand = \"{cmd}\"\n[voice]\nsilence_duration = 0.5\nmax_wait = 1.0\n")));
    let take = [tone(0.2, 0.0), tone(0.8, 3000.0), tone(1.0, 0.0)].concat();
    let mic: MicFactory = Arc::new(move |_m: &Media| Ok(Box::new(VecSource::new(take.clone())) as Box<dyn PcmSource>));
    let mut io = Io { keys: vec![Key::Talk, Key::Talk, Key::Talk, Key::Talk], lines: vec![] };
    let agent = Agent(Mutex::new(vec![]));
    let opts = VoiceModeOpts { continuous: false, wake_word: false, speak: false, barge_in: false, beep: false, session: None, max_turns: 0 };
    let s = voice_mode(&m, &opts, &mut io, &mic, &agent, &Cancel::new()).unwrap();
    assert_eq!((s.turns, s.session.as_deref(), s.stopped_by_phrase), (1, Some("sess-1"), true));
    assert_eq!(agent.0.lock().unwrap().as_slice(), ["None:what time is it"]);
    let l = io.lines.join("\n");
    assert!(l.contains("Say \"stop\" to end the voice chat."), "{l}");
    assert!(l.contains("you: what time is it\nark: It is noon.") && l.contains("[nothing recognisable]") && l.ends_with("Voice mode off."), "{l}");
    // Silence only: nothing reaches the agent; quit ends the loop.
    let quiet: MicFactory = Arc::new(|_m: &Media| Ok(Box::new(VecSource::new(tone(1.5, 20.0))) as Box<dyn PcmSource>));
    let mut io2 = Io { keys: vec![Key::Talk], lines: vec![] };
    let s2 = voice_mode(&m, &opts, &mut io2, &quiet, &agent, &Cancel::new()).unwrap();
    assert_eq!(s2.turns, 0);
    assert!(io2.lines.iter().any(|x| x == "[no speech heard]"));
    let r = requirements(&m);
    assert_eq!(r["stt_provider"], "fake");
    assert_eq!(r["stop_hint"], "Say \"stop\" to end the voice chat.");
}

/// The command TTS provider names its work dir after the current millisecond, so two speaking
/// tests at once can share (and delete) each other's directory; the talk-mode runs are serialised.
static TALK: Mutex<()> = Mutex::new(());

/// A talk-mode `Media`: a fake player (`{log}` is replaced by its log path) that records what
/// it plays, a fake STT command provider answering `answers` one take at a time, and a fake
/// command TTS provider. Returns the media, the temp dir and the player log.
fn talk_media(tag: &str, answers: &[&str], player_body: &str) -> (Arc<Media>, std::path::PathBuf, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let d = crate::testutil::temp_dir(tag);
    let log = d.join("played.log");
    let player = d.join("player.sh");
    std::fs::write(&player, format!("#!/bin/sh\n{}", player_body.replace("{log}", &log.display().to_string()))).unwrap();
    std::fs::set_permissions(&player, std::fs::Permissions::from_mode(0o755)).unwrap();
    let n = d.join("takes");
    let case = answers.iter().enumerate().map(|(i, a)| format!("{}) echo '{a}' ;;", i + 1)).collect::<Vec<_>>().join(" ");
    let stt = format!(
        "n=$(cat {n} 2>/dev/null || echo 0); n=$((n+1)); echo $n > {n}; case $n in {case} *) echo '{last}' ;; esac",
        last = answers.last().copied().unwrap_or(""),
        n = n.display(),
        case = case
    );
    let cfg = format!(
        "[stt]\nprovider = \"fake\"\n[stt.providers.fake]\ncommand = \"{stt}\"\n[tts]\nprovider = \"fake\"\nplayer = \"{} {{path}}\"\nprefs_path = \"{}\"\n[tts.providers.fake]\ncommand = \"printf ID3FAKE > {{output_path}}\"\nformat = \"mp3\"\n[voice]\nsilence_duration = 0.5\nmax_wait = 1.0\n",
        player.display(),
        d.join("prefs.json").display()
    );
    (Media::new(crate::MediaConfig::from_toml(&cfg)), d, log)
}

/// OpenClaw talk mode (`src/talk`): hands-free listening round after round with every reply
/// read aloud. The run never asks for a key press (`Io` would answer `Quit`), so two turns
/// prove continuous listening and two player runs prove the replies were spoken.
#[test]
fn talk_mode_listens_hands_free_and_speaks_each_reply() {
    let _g = TALK.lock().unwrap_or_else(|e| e.into_inner());
    let (m, _d, log) = talk_media("talk-mode", &["what time is it", "and tomorrow"], "cat \"$1\" >> {log}\necho >> {log}\n");
    let take = [tone(0.2, 0.0), tone(0.8, 3000.0), tone(1.0, 0.0)].concat();
    let mic: MicFactory = Arc::new(move |_m: &Media| Ok(Box::new(VecSource::new(take.clone())) as Box<dyn PcmSource>));
    let mut io = Io { keys: vec![], lines: vec![] };
    let agent = Agent(Mutex::new(vec![]));
    let opts = VoiceModeOpts { continuous: true, wake_word: false, speak: true, barge_in: false, beep: false, session: None, max_turns: 2 };
    let s = voice_mode(&m, &opts, &mut io, &mic, &agent, &Cancel::new()).unwrap();
    assert_eq!(s.turns, 2, "{:?}", io.lines);
    let l = io.lines.join("\n");
    assert!(l.starts_with("Voice mode on (hands-free)"), "{l}");
    assert!(l.contains("you: what time is it\nark: It is noon."), "{l}");
    assert!(l.contains("you: and tomorrow\nark: It is noon."), "{l}");
    assert!(!l.contains("[speech failed"), "{l}");
    assert_eq!(agent.0.lock().unwrap().as_slice(), ["None:what time is it", "Some(\"sess-1\"):and tomorrow"], "the second turn continues the session");
    let played = std::fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(played.matches("ID3FAKE").count(), 2, "both replies were played: {played:?}");
}

/// A fake player that appends each audio file to `log` (one line per playback), and a fake TTS
/// provider whose "audio" is the text it was asked to speak — so the log is an exact record of
/// what voice mode synthesized, chunk by chunk.
fn echo_media(tag: &str, streaming: bool) -> (Arc<Media>, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let d = crate::testutil::temp_dir(tag);
    let log = d.join("played.log");
    let player = d.join("player.sh");
    std::fs::write(&player, format!("#!/bin/sh\ncat \"$1\" >> '{}'\necho >> '{}'\n", log.display(), log.display())).unwrap();
    std::fs::set_permissions(&player, std::fs::Permissions::from_mode(0o755)).unwrap();
    let cfg = format!(
        "[tts]\nprovider = \"fake\"\nplayer = \"{} {{path}}\"\nprefs_path = \"{}\"\n[tts.providers.fake]\ncommand = \"(printf 'ID3'; cat {{text_path}}) > {{output_path}}\"\nformat = \"mp3\"\n[voice]\nspeak = true\nstreaming = {streaming}\n",
        player.display(),
        d.join("prefs.json").display(),
    );
    (Media::new(crate::MediaConfig::from_toml(&cfg)), log)
}

/// G7: voice mode speaks through the streaming path — one provider call and one playback per
/// sentence, each chunk normalized to spoken text — instead of synthesizing the whole reply in
/// one shot, and falls back to whole-file synthesis when streaming is switched off.
#[test]
fn voice_mode_streams_the_reply_sentence_by_sentence() {
    let _g = TALK.lock().unwrap_or_else(|e| e.into_inner());
    let reply = "**Done.** I opened `notes.md` in the editor.\nThe second sentence explains what changed.";
    let (m, log) = echo_media("voice-stream", true);
    assert_eq!(speak(&m, reply, None, &Cancel::new()), Ok(false), "streamed speech");
    let played = std::fs::read_to_string(&log).unwrap_or_default();
    let lines: Vec<&str> = played.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2, "one synthesize + playback per sentence (the real voice-mode entry point streams): {played:?}");
    assert!(lines[0].ends_with("Done. I opened in the editor."), "Markdown and code identifiers are stripped per streamed chunk: {:?}", lines[0]);
    assert!(lines[1].ends_with("The second sentence explains what changed."), "{:?}", lines[1]);
    assert!(!played.contains("**") && !played.contains('`'), "no Markdown reaches the provider: {played:?}");

    // `[media.voice] streaming = false`: the same reply is one whole-file synthesis.
    let (m2, log2) = echo_media("voice-stream-off", false);
    assert_eq!(speak(&m2, reply, None, &Cancel::new()), Ok(false));
    let whole = std::fs::read_to_string(&log2).unwrap_or_default();
    let wl: Vec<&str> = whole.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    assert_eq!(wl.len(), 1, "streaming off = one call for the whole reply: {whole:?}");
    assert!(wl[0].contains("The second sentence explains what changed."), "{:?}", wl[0]);
}

/// The degrade path (§0: isolate/undo instead of an error): a backend that cannot synthesize a
/// sentence on its own — here one that fails on short inputs — gets one whole-file attempt, so
/// the reply is still spoken rather than lost.
#[test]
fn a_backend_that_cannot_stream_falls_back_to_the_whole_reply() {
    use std::os::unix::fs::PermissionsExt;
    let _g = TALK.lock().unwrap_or_else(|e| e.into_inner());
    let d = crate::testutil::temp_dir("voice-stream-fallback");
    let log = d.join("played.log");
    let player = d.join("player.sh");
    std::fs::write(&player, format!("#!/bin/sh\ncat \"$1\" >> '{}'\necho >> '{}'\n", log.display(), log.display())).unwrap();
    std::fs::set_permissions(&player, std::fs::Permissions::from_mode(0o755)).unwrap();
    let cfg = format!(
        r#"[tts]
provider = "fake"
player = "{} {{path}}"
prefs_path = "{}"
[tts.providers.fake]
command = 'n=$(wc -c < {{text_path}}); [ "$n" -lt 30 ] && exit 3; (printf ID3; cat {{text_path}}) > {{output_path}}'
format = "mp3"
[tts.streaming]
min_len = 10
"#,
        player.display(),
        d.join("prefs.json").display(),
    );
    let m = Media::new(crate::MediaConfig::from_toml(&cfg));
    let reply = "First line here.\nSecond line here too.";
    assert_eq!(speak(&m, reply, None, &Cancel::new()), Ok(false), "the reply is still spoken");
    let played = std::fs::read_to_string(&log).unwrap_or_default();
    let lines: Vec<&str> = played.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 1, "two sentence-sized calls failed, one whole-reply call succeeded: {played:?}");
    assert!(lines[0].ends_with("First line here. Second line here too."), "{:?}", lines[0]);
}

/// Talk mode barge-in (`speak` with the microphone monitor): talking over a reply stops the
/// player and the next round listens immediately instead of waiting for a key.
#[test]
fn barge_in_cuts_the_spoken_reply_and_listens_again_without_a_key() {
    let _g = TALK.lock().unwrap_or_else(|e| e.into_inner());
    // `exec` so the player is one process: killing it (barge-in) ends the playback.
    let (m, _d, log) = talk_media("talk-barge", &["what time is it"], "echo start >> {log}\nexec sleep 10\n");
    let take = [tone(0.2, 0.0), tone(0.8, 3000.0), tone(1.0, 0.0)].concat();
    // Speaker bleed first (the barge-in floor calibration), then a voice over it.
    let barge = [tone(1.0, 400.0), tone(1.0, 9000.0)].concat();
    let calls = Arc::new(Mutex::new(0usize));
    let mic: MicFactory = Arc::new(move |_m: &Media| {
        let mut c = calls.lock().unwrap();
        *c += 1;
        let src = if *c == 1 { take.clone() } else { barge.clone() };
        Ok(Box::new(VecSource::new(src)) as Box<dyn PcmSource>)
    });
    let mut io = Io { keys: vec![], lines: vec![] };
    let agent = Agent(Mutex::new(vec![]));
    let opts = VoiceModeOpts { continuous: true, wake_word: false, speak: true, barge_in: true, beep: false, session: None, max_turns: 1 };
    let started = std::time::Instant::now();
    let s = voice_mode(&m, &opts, &mut io, &mic, &agent, &Cancel::new()).unwrap();
    assert_eq!((s.turns, s.interrupted), (1, 1), "{:?}", io.lines);
    assert!(started.elapsed() < std::time::Duration::from_secs(8), "playback was cut, not waited out");
    // The barge-in is detected while the first sentence is being synthesized or played, so the
    // player either never starts or is stopped right after it does — both cut the reply short.
    let played = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(played.trim().is_empty() || played.trim() == "start", "the reply was cut short: {played:?}");
}
