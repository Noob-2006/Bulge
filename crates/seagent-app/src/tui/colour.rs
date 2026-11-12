//! How many colours the terminal can show, and the escape for an RGB colour at that depth.
//!
//! The TUI paints the galaxy palette (`ui/theme.css`: near-black → navy sky, gold accents and
//! gold stars) in 24-bit colour. Terminals that cannot show it get the nearest colour they do
//! have instead of garbage escapes: the xterm 256-colour cube / grey ramp, or the 16 ANSI colours
//! (the sky becomes black, gold becomes yellow, text white).
//!
//! Depth, first match wins: `SEAGENT_TUI_COLORS` (`truecolor` | `256` | `16`); `COLORTERM`
//! `truecolor` / `24bit`; terminals known to do 24-bit (Windows Terminal, iTerm2, WezTerm, VS Code,
//! kitty, Alacritty, Ghostty, the Windows console without a `TERM`); `TERM` with `256color` or
//! `xterm` → 256; `linux`, `vt*`, `ansi`, `cons*`, `dumb` … → 16.

use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    True,
    X256,
    Ansi16,
}

/// The decision of [`depth`], over an environment reader (tests).
pub fn depth_from(env: &dyn Fn(&str) -> Option<String>) -> Depth {
    let get = |k: &str| env(k).map(|v| v.trim().to_ascii_lowercase()).filter(|v| !v.is_empty());
    match get("SEAGENT_TUI_COLORS").as_deref() {
        Some("truecolor" | "24bit" | "true") => return Depth::True,
        Some("256") => return Depth::X256,
        Some("16" | "8" | "ansi") => return Depth::Ansi16,
        _ => {}
    }
    if matches!(get("COLORTERM").as_deref(), Some("truecolor" | "24bit")) {
        return Depth::True;
    }
    if get("WT_SESSION").is_some() || get("KITTY_WINDOW_ID").is_some() || get("ALACRITTY_SOCKET").is_some() || get("GHOSTTY_RESOURCES_DIR").is_some() {
        return Depth::True;
    }
    if matches!(get("TERM_PROGRAM").as_deref(), Some("iterm.app" | "wezterm" | "vscode" | "ghostty" | "tabby" | "hyper")) {
        return Depth::True;
    }
    match get("TERM") {
        // The Windows console (conhost, Windows 10+) speaks 24-bit VT colour and sets no TERM.
        None => {
            if cfg!(windows) {
                Depth::True
            } else {
                Depth::X256
            }
        }
        Some(t) if t.contains("truecolor") || t.contains("direct") || t.starts_with("xterm-kitty") || t == "alacritty" || t.starts_with("foot") => Depth::True,
        Some(t) if t.contains("256") || t.starts_with("xterm") || t.starts_with("tmux") || t.starts_with("screen") || t.starts_with("rxvt") => Depth::X256,
        Some(_) => Depth::Ansi16,
    }
}

/// This terminal's depth (decided once per process).
pub fn depth() -> Depth {
    static D: OnceLock<Depth> = OnceLock::new();
    *D.get_or_init(|| depth_from(&|k| std::env::var(k).ok()))
}

fn dist(a: (u8, u8, u8), b: (u8, u8, u8)) -> u32 {
    let d = |x: u8, y: u8| (x as i32 - y as i32).pow(2) as u32;
    // Weighted towards green, as the eye is (cheap "redmean"-like weighting).
    2 * d(a.0, b.0) + 4 * d(a.1, b.1) + 3 * d(a.2, b.2)
}

/// Nearest xterm-256 index (6×6×6 cube or the 24-step grey ramp).
pub fn to_256(c: (u8, u8, u8)) -> u8 {
    const STEPS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    let near = |v: u8| (0..6).min_by_key(|&i| (STEPS[i] as i32 - v as i32).abs()).unwrap_or(0);
    let (r, g, b) = (near(c.0), near(c.1), near(c.2));
    let cube = (STEPS[r], STEPS[g], STEPS[b]);
    let avg = (c.0 as u32 + c.1 as u32 + c.2 as u32) / 3;
    let gi = (avg.saturating_sub(3) / 10).min(23) as u8;
    let grey = (8 + 10 * gi, 8 + 10 * gi, 8 + 10 * gi);
    if dist(grey, c) < dist(cube, c) {
        232 + gi
    } else {
        16 + 36 * r as u8 + 6 * g as u8 + b as u8
    }
}

/// One of the 16 ANSI colours (index = SGR offset: 0–7 normal, 8–15 bright), by hue rather than
/// RGB distance — terminals tune those 16 freely, but "gold" must stay yellow, not turn white.
/// Very dark colours (the whole sky) are black; unsaturated ones a grey step.
pub fn to_16(c: (u8, u8, u8)) -> u8 {
    let (r, g, b) = (c.0 as f32 / 255.0, c.1 as f32 / 255.0, c.2 as f32 / 255.0);
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    if max < 0.2 {
        return 0;
    }
    let sat = if max > 0.0 { (max - min) / max } else { 0.0 };
    if sat < 0.25 {
        return match max {
            v if v < 0.45 => 8,
            v if v < 0.88 => 7,
            _ => 15,
        };
    }
    let h = if max == r {
        60.0 * (((g - b) / (max - min)).rem_euclid(6.0))
    } else if max == g {
        60.0 * ((b - r) / (max - min) + 2.0)
    } else {
        60.0 * ((r - g) / (max - min) + 4.0)
    };
    // red, yellow, green, cyan, blue, magenta → SGR 1, 3, 2, 6, 4, 5
    let base = [1u8, 3, 2, 6, 4, 5][(((h + 30.0) % 360.0) / 60.0) as usize % 6];
    if max > 0.8 {
        base + 8
    } else {
        base
    }
}

/// Foreground escape for `c` at depth `d`.
pub fn fg_at(d: Depth, c: (u8, u8, u8)) -> String {
    match d {
        Depth::True => format!("\x1b[38;2;{};{};{}m", c.0, c.1, c.2),
        Depth::X256 => format!("\x1b[38;5;{}m", to_256(c)),
        Depth::Ansi16 => {
            let i = to_16(c);
            format!("\x1b[{}m", if i < 8 { 30 + i } else { 90 + i - 8 })
        }
    }
}

/// Background escape for `c` at depth `d`.
pub fn bg_at(d: Depth, c: (u8, u8, u8)) -> String {
    match d {
        Depth::True => format!("\x1b[48;2;{};{};{}m", c.0, c.1, c.2),
        Depth::X256 => format!("\x1b[48;5;{}m", to_256(c)),
        Depth::Ansi16 => {
            // The whole night sky (every navy step) is black: 16-colour blue is far too loud
            // for a background.
            let i = if c.0.max(c.1).max(c.2) < 0x66 { 0 } else { to_16(c) };
            format!("\x1b[{}m", if i < 8 { 40 + i } else { 100 + i - 8 })
        }
    }
}

pub fn fg(c: (u8, u8, u8)) -> String {
    fg_at(depth(), c)
}

pub fn bg(c: (u8, u8, u8)) -> String {
    bg_at(depth(), c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(vars: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    }

    #[test]
    fn depth_follows_the_terminal() {
        assert_eq!(depth_from(&env(&[("COLORTERM", "truecolor"), ("TERM", "xterm-256color")])), Depth::True);
        assert_eq!(depth_from(&env(&[("WT_SESSION", "x")])), Depth::True);
        assert_eq!(depth_from(&env(&[("TERM", "xterm-256color")])), Depth::X256);
        assert_eq!(depth_from(&env(&[("TERM", "screen")])), Depth::X256);
        assert_eq!(depth_from(&env(&[("TERM", "linux")])), Depth::Ansi16);
        assert_eq!(depth_from(&env(&[("TERM", "vt100")])), Depth::Ansi16);
        assert_eq!(depth_from(&env(&[("TERM", "xterm-256color"), ("SEAGENT_TUI_COLORS", "16")])), Depth::Ansi16, "the override wins");
        assert_eq!(depth_from(&env(&[("COLORTERM", "truecolor"), ("SEAGENT_TUI_COLORS", "256")])), Depth::X256);
    }

    #[test]
    fn galaxy_colours_degrade_to_sky_black_and_gold_yellow() {
        let navy = (0x0a, 0x10, 0x20);
        let gold = (0xec, 0xd2, 0x8c);
        let text = (0xea, 0xee, 0xf7);
        assert_eq!(fg_at(Depth::True, gold), "\x1b[38;2;236;210;140m");
        // 16 colours: the sky is black, gold is (bright) yellow, text white.
        assert_eq!(bg_at(Depth::Ansi16, navy), "\x1b[40m");
        assert_eq!(bg_at(Depth::Ansi16, (0x1c, 0x2c, 0x4a)), "\x1b[40m", "the brightest navy step too");
        assert_eq!(to_16(gold), 11, "gold is bright yellow");
        assert_eq!(fg_at(Depth::Ansi16, gold), "\x1b[93m");
        assert!(matches!(to_16(text), 7 | 15));
        assert_eq!(to_16((0xff, 0x6b, 0x7f)), 9, "critical is bright red");
        assert_eq!(to_16((0x6f, 0xd6, 0xa2)), 10, "ok is bright green");
        // 256 colours: a dark grey-blue / black for the sky, a yellow-ish cube entry for gold.
        let n = to_256(navy);
        assert!(n == 16 || n == 17 || (232..=235).contains(&n), "{n}");
        let g = to_256(gold);
        assert!((178..=230).contains(&g), "{g}");
        assert_eq!(bg_at(Depth::X256, navy), format!("\x1b[48;5;{n}m"));
    }
}
