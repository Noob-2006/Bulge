//! Voice transcript filtering (Hermes `tools/voice_mode_transcript.py`): Whisper
//! silence hallucinations, voice-chat stop phrases and the TTS self-echo guard.
//!
//! `[media.voice] stop_phrases = ["stop"]` (`[]` disables).

use crate::Media;

/// Phrases Whisper commonly hallucinates on silent / near-silent audio (matched with
/// trailing `.`/`!` stripped).
pub const WHISPER_HALLUCINATIONS: &[&str] = &[
    "thank you",
    "thanks for watching",
    "subscribe to my channel",
    "like and subscribe",
    "please subscribe",
    "thank you for watching",
    "bye",
    "you",
    "the end",
    "продолжение следует",
    "sous-titres",
    "sous-titres réalisés par la communauté d'amara.org",
    "sottotitoli creati dalla comunità amara.org",
    "untertitel von stephanie geiges",
    "amara.org",
    "www.mooji.org",
    "ご視聴ありがとうございました",
];

/// Repetitive hallucinations ("Thank you. Thank you. Thank you.") — Hermes
/// `^(?:thank you|thanks|bye|you|ok|okay|the end|\.|\s|,|!)+$`.
fn only_filler(s: &str) -> bool {
    const TOKENS: &[&str] = &["thank you", "thanks", "the end", "okay", "bye", "you", "ok", ".", ",", "!"];
    let mut rest = s;
    if rest.is_empty() {
        return false;
    }
    'outer: while !rest.is_empty() {
        if let Some(c) = rest.chars().next().filter(|c| c.is_whitespace()) {
            rest = &rest[c.len_utf8()..];
            continue;
        }
        for t in TOKENS {
            if rest.starts_with(t) {
                rest = &rest[t.len()..];
                continue 'outer;
            }
        }
        return false;
    }
    true
}

pub fn is_whisper_hallucination(transcript: &str) -> bool {
    let c = transcript.trim().to_lowercase();
    c.is_empty() || WHISPER_HALLUCINATIONS.contains(&c.trim_end_matches(['.', '!'])) || only_filler(&c)
}

pub const DEFAULT_STOP_PHRASES: &[&str] = &["stop"];

/// Configured stop phrases (lower-cased); `[]` disables.
pub fn stop_phrases(m: &Media) -> Vec<String> {
    match m.cfg.get("voice.stop_phrases") {
        Some(toml::Value::String(s)) => vec![s.trim().to_lowercase()].into_iter().filter(|s| !s.is_empty()).collect(),
        Some(toml::Value::Array(a)) => a.iter().filter_map(|v| match v {
            toml::Value::String(s) => Some(s.trim().to_lowercase()),
            toml::Value::Integer(i) => Some(i.to_string()),
            toml::Value::Float(f) => Some(f.to_string()),
            _ => None,
        }).filter(|s| !s.is_empty()).collect(),
        _ => DEFAULT_STOP_PHRASES.iter().map(|s| s.to_string()).collect(),
    }
}

/// True when `transcript` is EXACTLY a stop phrase (surrounding punctuation stripped):
/// "stop doing that" still reaches the agent.
pub fn is_voice_stop_phrase(transcript: &str, phrases: &[String]) -> bool {
    let c = transcript.trim().to_lowercase();
    let c = c.trim_matches(|ch: char| ".,!?;: \t\n\"'".contains(ch));
    !c.is_empty() && phrases.iter().any(|p| p == c)
}

/// `Say "stop" to end the voice chat.` ("" when disabled).
pub fn voice_stop_hint(m: &Media) -> String {
    stop_phrases(m).first().map(|p| format!("Say \"{p}\" to end the voice chat.")).unwrap_or_default()
}

pub const DEFAULT_ECHO_THRESHOLD: f64 = 0.6;
/// Below this a one-word barge-in landing inside a long reply would trivially match.
pub const MIN_FRAGMENT_LENGTH_FOR_ECHO: usize = 10;

fn norm(t: &str) -> Vec<char> {
    t.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase().chars().collect()
}

/// `difflib.SequenceMatcher(None, a, b).ratio()`: Ratcliff/Obershelp, 2·M / (|a|+|b|).
pub fn similarity(a: &[char], b: &[char]) -> f64 {
    fn matches(a: &[char], b: &[char]) -> usize {
        if a.is_empty() || b.is_empty() {
            return 0;
        }
        // Longest common substring (earliest in a, then b — difflib's tie-break).
        let mut best = (0, 0, 0);
        let mut prev = vec![0usize; b.len() + 1];
        for (i, ca) in a.iter().enumerate() {
            let mut cur = vec![0usize; b.len() + 1];
            for (j, cb) in b.iter().enumerate() {
                if ca == cb {
                    cur[j + 1] = prev[j] + 1;
                    let k = cur[j + 1];
                    if k > best.2 {
                        best = (i + 1 - k, j + 1 - k, k);
                    }
                }
            }
            prev = cur;
        }
        let (i, j, k) = best;
        if k == 0 {
            return 0;
        }
        k + matches(&a[..i], &b[..j]) + matches(&a[i + k..], &b[j + k..])
    }
    let t = a.len() + b.len();
    if t == 0 {
        return 1.0;
    }
    2.0 * matches(a, b) as f64 / t as f64
}

/// True when `transcript` looks like a self-capture of `spoken` (speaker bleed): whole
/// string similarity, else a transcript-sized window sliding across `spoken`.
pub fn is_tts_echo(transcript: &str, spoken: &str, threshold: f64) -> bool {
    let (a, b) = (norm(transcript), norm(spoken));
    if a.is_empty() || b.is_empty() {
        return false;
    }
    if similarity(&a, &b) >= threshold {
        return true;
    }
    if a.len() < MIN_FRAGMENT_LENGTH_FOR_ECHO || a.len() >= b.len() {
        return false;
    }
    (0..=b.len() - a.len()).any(|s| similarity(&a, &b[s..s + a.len()]) >= threshold)
}

/// Cleaned user utterance, or `None` when it should be dropped (empty or a known
/// Whisper hallucination).
pub fn filter(text: &str) -> Option<String> {
    let t = text.trim();
    (!t.is_empty() && !is_whisper_hallucination(t)).then(|| t.to_string())
}

/// Like [`filter`] but a configured stop phrase always survives ("bye" overlaps the
/// hallucination list and must still end the chat).
pub fn filter_with_stop(text: &str, phrases: &[String]) -> Option<String> {
    if is_voice_stop_phrase(text, phrases) {
        return Some(text.trim().to_string());
    }
    filter(text)
}

/// True when `heard` is (mostly) an echo of what we just spoke (`spoken`).
pub fn is_echo(heard: &str, spoken: &str) -> bool {
    is_tts_echo(heard, spoken, DEFAULT_ECHO_THRESHOLD)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hallucinations_stop_phrases_and_echo() {
        for h in ["Thank you.", "you", "  Bye! ", "Thank you. Thank you. Thank you.", "ok, okay!", "ご視聴ありがとうございました", ""] {
            assert!(is_whisper_hallucination(h), "{h}");
        }
        for ok in ["Thank you for the help", "you are right", "okay let's go"] {
            assert!(!is_whisper_hallucination(ok), "{ok}");
        }
        let p = vec!["stop".to_string(), "bye".into()];
        assert!(is_voice_stop_phrase("Stop.", &p) && is_voice_stop_phrase(" \"bye!\" ", &p));
        assert!(!is_voice_stop_phrase("stop doing that", &p) && !is_voice_stop_phrase("", &p));
        assert_eq!(filter_with_stop("Bye.", &p).as_deref(), Some("Bye."));
        assert_eq!(filter("Bye."), None);
        assert_eq!(filter("  hello  ").as_deref(), Some("hello"));
        let m = Media::new(crate::MediaConfig::from_toml("[voice]\nstop_phrases = []\n"));
        assert!(stop_phrases(&m).is_empty() && voice_stop_hint(&m).is_empty());
        let d = Media::new(crate::MediaConfig::default());
        assert_eq!(voice_stop_hint(&d), "Say \"stop\" to end the voice chat.");
        // difflib parity: SequenceMatcher(None, "abcd", "bcde").ratio() == 0.75
        assert!((similarity(&norm("abcd"), &norm("bcde")) - 0.75).abs() < 1e-9);
        let spoken = "The weather in Paris today is sunny with a high of twenty degrees and light winds from the west.";
        assert!(is_echo("the weather in paris today is sunny", spoken), "fragment of our own reply");
        assert!(is_echo(spoken, spoken));
        assert!(!is_echo("yes", spoken), "short interjection");
        assert!(!is_echo("what about tomorrow in london", spoken));
    }
}
