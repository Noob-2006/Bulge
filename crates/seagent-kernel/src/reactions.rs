//! Token-free detection of user *reactions* to the agent (Hermes `agent/reactions.py`).
//! The only kind is `vibe`: affection/gratitude aimed at the agent (`ily`, `<3`, `good bot`,
//! a heart emoji) — not general positive sentiment ("this is great" does not fire). UIs show
//! a heart for it; nothing reaches the model.

use regex::Regex;
use std::sync::OnceLock;

pub const VIBE: &str = "vibe";

fn vibe_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)\bgood\s*bot\b",
            r"|\bi\s*(?:love|luv)\s*(?:you|u|ya)\b",
            r"|\b(?:love|luv)\s*(?:you|u|ya)\b",
            r"|\bily(?:sm)?\b",
            r"|\bthank\s*(?:you|u)\b",
            r"|\b(?:thanks|thx|tysm|ty)\b",
            r"|<3+",
            "|[\u{2764}\u{2665}\u{1F970}\u{1F60D}\u{1F618}\u{1F495}\u{1F496}\u{1F497}\u{1F49E}\u{1F49B}\u{1F49C}\u{1F49A}\u{1F499}\u{1F493}\u{1F498}\u{1F49D}\u{1FA77}]",
        ))
        .expect("vibe regex")
    })
}

/// The reaction kind for `text` (currently only [`VIBE`]), or None.
pub fn detect(text: &str) -> Option<&'static str> {
    (!text.is_empty() && vibe_re().is_match(text)).then_some(VIBE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn affection_fires_sentiment_does_not() {
        for t in ["thanks!", "Thank you so much", "good bot", "ily", "ILYSM", "i love you", "luv u", "<3", "<333", "❤️", "great job 🥰", "ty", "thx mate"] {
            assert_eq!(detect(t), Some(VIBE), "{t}");
        }
        for t in ["this is great", "</3", "", "thanksgiving plans", "type it", "lovely weather", "nice work"] {
            assert_eq!(detect(t), None, "{t}");
        }
    }
}
