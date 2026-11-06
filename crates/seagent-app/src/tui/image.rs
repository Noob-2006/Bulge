//! Inline images in the TUI transcript (Hermes `agent/terminal_image.py`,
//! `hermes_cli/cli_inline_images.py`, `ui-tui/src/components/inlineImage.tsx`):
//! kitty graphics and iTerm2/WezTerm inline images when the terminal supports them,
//! and a readable text line everywhere else. Attachment data is base64, the same
//! form `Block::Image` carries.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Kitty,
    Iterm,
    Text,
}

/// The terminal's graphics protocol, from the same environment probes pets use.
pub fn detect(env: &HashMap<String, String>) -> Protocol {
    let g = |k: &str| env.get(k).map(String::as_str).unwrap_or("");
    if g("TERM") == "xterm-kitty" || !g("KITTY_WINDOW_ID").is_empty() || g("TERM_PROGRAM") == "ghostty" {
        Protocol::Kitty
    } else if g("TERM_PROGRAM") == "iTerm.app" || g("TERM_PROGRAM") == "WezTerm" || g("LC_TERMINAL") == "iTerm2" {
        Protocol::Iterm
    } else {
        Protocol::Text
    }
}

pub fn detect_env() -> Protocol {
    detect(&std::env::vars().collect())
}

/// A text line that tells the user what the image is when no protocol is available (and
/// remains the accessible row when one is).
pub fn fallback(media_type: &str, data: &str) -> String {
    let bytes = data.len().saturating_mul(3) / 4;
    format!("[image {media_type} · {} KB]", bytes.div_ceil(1024).max(1))
}

/// The escape sequence that draws `data`, or `None` for the text fallback (including a
/// terminal that advertises a protocol but whose bytes we cannot decode).
pub fn render(protocol: Protocol, data: &str, media_type: &str, cols: usize) -> Option<String> {
    if protocol == Protocol::Text {
        return None; // no decode work on a terminal that cannot show it
    }
    let bytes = seagent_net::crypto::b64_decode(data)?;
    match protocol {
        Protocol::Text => None,
        Protocol::Iterm => Some(format!(
            "\x1b]1337;File=inline=1;size={};width={};preserveAspectRatio=1:{}\x07",
            bytes.len(),
            cols.max(1),
            data
        )),
        Protocol::Kitty => {
            // kitty's f=100 transmits a PNG; other formats (JPEG/WebP) are decoded first.
            let png = if media_type == "image/png" {
                bytes
            } else {
                let img = super::png::decode_any(&bytes).ok()?;
                super::png::encode(&img)
            };
            Some(kitty_png(&png, cols))
        }
    }
}

/// kitty graphics protocol, PNG payload, chunked at 4096 bytes.
fn kitty_png(png: &[u8], cols: usize) -> String {
    let data = seagent_net::crypto::b64(png);
    let chunks: Vec<&str> = data.as_bytes().chunks(4096).map(|c| std::str::from_utf8(c).unwrap_or("")).collect();
    let mut out = String::new();
    for (i, chunk) in chunks.iter().enumerate() {
        let more = usize::from(i + 1 < chunks.len());
        if i == 0 {
            out.push_str(&format!("\x1b_Gf=100,a=T,c={},m={more};{chunk}\x1b\\", cols.max(1)));
        } else {
            out.push_str(&format!("\x1b_Gm={more};{chunk}\x1b\\"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn protocol_detection_matches_the_terminal() {
        assert_eq!(detect(&env(&[("TERM", "xterm-kitty")])), Protocol::Kitty);
        assert_eq!(detect(&env(&[("KITTY_WINDOW_ID", "1")])), Protocol::Kitty);
        assert_eq!(detect(&env(&[("TERM_PROGRAM", "iTerm.app")])), Protocol::Iterm);
        assert_eq!(detect(&env(&[("TERM_PROGRAM", "WezTerm")])), Protocol::Iterm);
        assert_eq!(detect(&env(&[("TERM", "xterm-256color")])), Protocol::Text);
    }

    #[test]
    fn render_uses_the_protocol_and_falls_back_to_text() {
        // 1x1 PNG, as base64.
        let png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg==";
        assert!(fallback("image/png", png).starts_with("[image image/png ·"));
        assert_eq!(render(Protocol::Text, png, "image/png", 20), None);
        let iterm = render(Protocol::Iterm, png, "image/png", 20).unwrap();
        assert!(iterm.starts_with("\x1b]1337;File=inline=1;size=") && iterm.ends_with('\x07'));
        let kitty = render(Protocol::Kitty, png, "image/png", 20).unwrap();
        assert!(kitty.starts_with("\x1b_Gf=100,a=T,c=20,") && kitty.ends_with("\x1b\\"));
        // Unreadable base64 never becomes an escape sequence.
        assert_eq!(render(Protocol::Iterm, "not base64!!", "image/png", 20), None);
        // The transcript row still carries a readable description.
        let _ = json!({"type": "image", "media_type": "image/png", "data": png});
    }
}
