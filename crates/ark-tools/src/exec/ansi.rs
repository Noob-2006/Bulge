//! Terminal escape handling for command output (Hermes `tools/ansi_strip.py`,
//! OpenClaw `gateway/terminal/buffer-text.ts`): full ECMA-48 stripping (CSI,
//! OSC with BEL/ST, DCS/SOS/PM/APC, nF, Fp/Fe/Fs, 8-bit C1), display
//! sanitizing, Unicode TAG smuggling removal and a carriage-return aware
//! rendering of a raw terminal buffer.

use regex::Regex;
use std::borrow::Cow;
use std::sync::OnceLock;

fn escape_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(concat!(
            r"(?s)\x1b(?:",
            r"\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]", // CSI
            r"|\].*?(?:\x07|\x1b\\)",                 // OSC (BEL or ST)
            r"|[PX^_].*?\x1b\\",                      // DCS / SOS / PM / APC
            r"|[\x20-\x2f]+[\x30-\x7e]",              // nF (charset designation…)
            r"|[\x30-\x7e]",                          // Fp / Fe / Fs
            r")",
            r"|\x{9b}[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]", // 8-bit CSI
            r"|\x{9d}.*?(?:\x07|\x{9c})",                  // 8-bit OSC
            r"|[\x{80}-\x{9f}]",                           // other C1 controls
        ))
        .expect("ansi regex")
    })
}

fn has_escape(s: &str) -> bool {
    s.chars().any(|c| c == '\x1b' || ('\u{80}'..='\u{9f}').contains(&c))
}

/// Remove ANSI escape sequences; clean text is returned unchanged.
pub fn strip_ansi(s: &str) -> Cow<'_, str> {
    if !has_escape(s) {
        return Cow::Borrowed(s);
    }
    escape_re().replace_all(s, "")
}

/// Escape-free copy of `s` for tool results that are shown as plain text to the model
/// (Hermes `ansi_strip.strip_ansi`, the shell / exec path). Borrowing is not worth a
/// lifetime at the call sites, so this always returns an owned `String`.
pub fn strip(s: &str) -> String {
    strip_ansi(s).into_owned()
}

/// Clean up a captured command transcript for the model: escapes removed and `\r\n`
/// normalized. `pty` transcripts are rendered the way a terminal shows them (a
/// carriage return overwrites its line, as progress bars and REPLs expect), because
/// under a PTY every program thinks it is talking to a screen.
pub fn strip_output(s: &str, pty: bool) -> String {
    if pty {
        if !has_escape(s) && !s.contains('\r') {
            return s.to_string();
        }
        return render_terminal_text(s);
    }
    if !has_escape(s) && !s.contains('\r') {
        return s.to_string();
    }
    strip_ansi(s).into_owned().replace("\r\n", "\n")
}

fn is_bad_control(c: char) -> bool {
    matches!(c, '\x00'..='\x08' | '\x0b' | '\x0c' | '\x0e'..='\x1f' | '\x7f')
}

/// Text safe to echo to a terminal: escapes and bare control characters gone,
/// carriage returns turned into newlines (no `\r` overwrite spoofing).
pub fn sanitize_display_text(s: &str) -> String {
    let t = strip_ansi(s);
    t.replace("\r\n", "\n").replace('\r', "\n").chars().filter(|c| !is_bad_control(*c)).collect()
}

/// Drop invisible Unicode TAG characters (U+E0000–U+E007F, an "ASCII
/// smuggling" prompt-injection channel); emoji tag sequences (🏴 + tags +
/// CANCEL TAG) are kept.
pub fn strip_unicode_tags(s: &str) -> Cow<'_, str> {
    let is_tag = |c: char| ('\u{E0000}'..='\u{E007F}').contains(&c);
    if !s.chars().any(is_tag) {
        return Cow::Borrowed(s);
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\u{1F3F4}' {
            // Valid flag sequence: base, ≥1 tag spec char, CANCEL TAG.
            let mut j = i + 1;
            while j < chars.len() && ('\u{E0020}'..='\u{E007E}').contains(&chars[j]) {
                j += 1;
            }
            if j > i + 1 && chars.get(j) == Some(&'\u{E007F}') {
                out.extend(&chars[i..=j]);
                i = j + 1;
                continue;
            }
        }
        if !is_tag(c) {
            out.push(c);
        }
        i += 1;
    }
    Cow::Owned(out)
}

/// What a terminal would roughly show for a raw buffer, without a VT emulator:
/// escapes stripped, `\r` overwrites collapsed (last write per line wins),
/// remaining C0/C1 controls dropped (OpenClaw renderTerminalBufferText).
pub fn render_terminal_text(raw: &str) -> String {
    let stripped = strip_ansi(raw);
    let mut lines = Vec::new();
    for line in stripped.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let last = line.rsplit('\r').next().unwrap_or(line);
        lines.push(last.chars().filter(|c| !is_bad_control(*c) && !('\u{80}'..='\u{9f}').contains(c)).collect::<String>());
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_every_sequence_family() {
        assert_eq!(strip_ansi("\x1b[1;31mred\x1b[0m plain"), "red plain");
        assert_eq!(strip_ansi("a\x1b]0;title\x07b\x1b]8;;http://x\x1b\\link\x1b]8;;\x1b\\c"), "ablinkc");
        assert_eq!(strip_ansi("x\x1bPq#0;1;2\x1b\\y"), "xy", "DCS");
        assert_eq!(strip_ansi("\x1b(Bcharset\x1b)0"), "charset", "nF");
        assert_eq!(strip_ansi("\x1b=keypad\x1b>\x1b7\x1b8"), "keypad", "Fp/Fe");
        assert_eq!(strip_ansi("\u{9b}31mC1\u{9d}0;t\u{9c}!\u{85}"), "C1!");
        assert_eq!(strip_ansi("\x1b[?25l\x1b[2K\x1b[1G progress"), " progress");
        assert!(matches!(strip_ansi("clean ✓"), Cow::Borrowed(_)));
    }

    #[test]
    fn tool_output_stripping() {
        assert_eq!(strip("\x1b[32mok\x1b[0m"), "ok");
        assert_eq!(strip("plain"), "plain");
        assert_eq!(strip_output("a\r\nb\x1b[1m!\x1b[0m\r\n", false), "a\nb!\n");
        assert_eq!(strip_output("10%\r20%\r30%\n", true), "30%\n", "a PTY transcript renders like a screen");
        assert_eq!(strip_output("plain\n", true), "plain\n");
        assert_eq!(strip_output("l1\r\nl2\r\n", true), "l1\nl2\n");
    }

    #[test]
    fn display_tags_and_render() {
        assert_eq!(sanitize_display_text("a\x07b\x1b[2Jc\r\nd\re\x00"), "abc\nd\ne");
        let smuggled = "ok\u{E0069}\u{E0067}";
        assert_eq!(strip_unicode_tags(smuggled), "ok");
        let flag = "\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}";
        assert_eq!(strip_unicode_tags(&format!("{flag}!")), format!("{flag}!"));
        assert_eq!(render_terminal_text("10%\r20%\r30%\nnext\r\n\x1b[32mok\x1b[0m\x07"), "30%\nnext\nok");
    }
}
