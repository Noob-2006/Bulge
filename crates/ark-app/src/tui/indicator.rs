//! Busy-indicator styles (Hermes `INDICATOR_STYLES`, ui-tui `renderIndicator`):
//! `kaomoji` (default: rotating faces + verb), `emoji`, `ascii` (spinner + verb) and
//! `unicode` (braille spinner, no verb). Chosen with `/indicator`, saved as `indicator`.

pub const STYLES: &[&str] = &["ascii", "emoji", "kaomoji", "unicode"];
pub const DEFAULT: &str = "kaomoji";

const FACES: &[&str] = &["(｡•́︿•̀｡)", "(◔_◔)", "(¬‿¬)", "( •_•)>⌐■-■", "(⌐■_■)", "(´･_･`)", "◉_◉", "(°ロ°)", "( ˘⌣˘)♡", "ヽ(>∀<☆)☆", "٩(๑❛ᴗ❛๑)۶", "(⊙_⊙)", "(¬_¬)", "( ͡° ͜ʖ ͡°)", "ಠ_ಠ"];
const EMOJI: &[&str] = &["✦ ", "🌀", "🤔", "✨", "🍵", "🔮"];
const ASCII: &[&str] = &["|", "/", "-", "\\"];
const BRAILLE: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const VERBS: &[&str] = &["thinking", "pondering", "working", "cooking", "musing", "reasoning", "brewing", "plotting"];

pub fn normalize(s: &str) -> Option<&'static str> {
    let s = s.trim().to_ascii_lowercase();
    STYLES.iter().copied().find(|x| *x == s)
}

/// Frame for `tick` (TUI ticks ~30 ms between reads; each style has its own cadence)
/// plus whether the rotating verb is shown. Skin spinner faces override kaomoji.
pub fn frame(style: &str, tick: usize, skin_faces: &[String]) -> (String, bool) {
    match style {
        "emoji" => (EMOJI[(tick / 20) % EMOJI.len()].to_string(), true),
        "ascii" => (ASCII[(tick / 4) % ASCII.len()].to_string(), true),
        "unicode" => (BRAILLE[(tick / 3) % BRAILLE.len()].to_string(), false),
        _ => {
            let i = tick / 80;
            if skin_faces.is_empty() {
                (FACES[i % FACES.len()].to_string(), true)
            } else {
                (skin_faces[i % skin_faces.len()].clone(), true)
            }
        }
    }
}

pub fn verb(tick: usize, skin_verbs: &[String]) -> String {
    let i = tick / 100;
    if skin_verbs.is_empty() {
        VERBS[i % VERBS.len()].to_string()
    } else {
        skin_verbs[i % skin_verbs.len()].clone()
    }
}

/// `frame verb…` (or just the frame for `unicode`).
pub fn render(style: &str, tick: usize, faces: &[String], verbs: &[String]) -> String {
    let (f, show_verb) = frame(style, tick, faces);
    if show_verb {
        format!("{f} {}…", verb(tick, verbs))
    } else {
        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn styles_frames_and_verbs() {
        assert_eq!(normalize(" Emoji "), Some("emoji"));
        assert_eq!(normalize("fancy"), None);
        assert_eq!(frame("ascii", 0, &[]), ("|".into(), true));
        assert_eq!(frame("ascii", 4, &[]).0, "/");
        assert_eq!(frame("unicode", 0, &[]), ("⠋".into(), false));
        assert_eq!(render("unicode", 3, &[], &[]), "⠙");
        assert!(render("kaomoji", 0, &[], &[]).starts_with("(｡•́︿•̀｡) thinking"));
        let faces = vec!["(⚔)".to_string()];
        assert_eq!(frame("kaomoji", 999, &faces).0, "(⚔)");
        assert_eq!(verb(0, &["forging".into()]), "forging");
    }
}
