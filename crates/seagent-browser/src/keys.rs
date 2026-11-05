//! Key chords → `Input.dispatchKeyEvent` sequences (Playwright `keyboard.press`
//! semantics as used by OpenClaw act:press and Hermes browser_press).

use serde_json::{json, Value};

pub struct Key {
    pub key: String,
    pub code: String,
    pub vk: i64,
    pub text: Option<String>,
}

const MOD_ALT: i64 = 1;
const MOD_CTRL: i64 = 2;
const MOD_META: i64 = 4;
const MOD_SHIFT: i64 = 8;

/// OpenClaw press aliases (case-insensitive per segment).
fn alias(seg: &str) -> String {
    match seg.to_ascii_lowercase().as_str() {
        "esc" | "escape" => "Escape".into(),
        "return" | "enter" => "Enter".into(),
        "del" | "delete" => "Delete".into(),
        "ctrl" | "control" => "Control".into(),
        "cmd" | "command" | "meta" | "super" | "win" => "Meta".into(),
        "option" | "alt" => "Alt".into(),
        "shift" => "Shift".into(),
        "space" => " ".into(),
        "tab" => "Tab".into(),
        "backspace" => "Backspace".into(),
        "up" | "arrowup" => "ArrowUp".into(),
        "down" | "arrowdown" => "ArrowDown".into(),
        "left" | "arrowleft" => "ArrowLeft".into(),
        "right" | "arrowright" => "ArrowRight".into(),
        "pageup" | "pgup" => "PageUp".into(),
        "pagedown" | "pgdn" => "PageDown".into(),
        "home" => "Home".into(),
        "end" => "End".into(),
        "insert" | "ins" => "Insert".into(),
        _ => seg.to_string(),
    }
}

pub fn key_info(name: &str) -> Result<Key, String> {
    let k = |key: &str, code: &str, vk: i64, text: Option<&str>| Ok(Key { key: key.into(), code: code.into(), vk, text: text.map(str::to_string) });
    match name {
        "Enter" => k("Enter", "Enter", 13, Some("\r")),
        "Tab" => k("Tab", "Tab", 9, None),
        "Escape" => k("Escape", "Escape", 27, None),
        "Backspace" => k("Backspace", "Backspace", 8, None),
        "Delete" => k("Delete", "Delete", 46, None),
        "Insert" => k("Insert", "Insert", 45, None),
        " " => k(" ", "Space", 32, Some(" ")),
        "ArrowUp" => k("ArrowUp", "ArrowUp", 38, None),
        "ArrowDown" => k("ArrowDown", "ArrowDown", 40, None),
        "ArrowLeft" => k("ArrowLeft", "ArrowLeft", 37, None),
        "ArrowRight" => k("ArrowRight", "ArrowRight", 39, None),
        "PageUp" => k("PageUp", "PageUp", 33, None),
        "PageDown" => k("PageDown", "PageDown", 34, None),
        "Home" => k("Home", "Home", 36, None),
        "End" => k("End", "End", 35, None),
        "Control" => k("Control", "ControlLeft", 17, None),
        "Shift" => k("Shift", "ShiftLeft", 16, None),
        "Alt" => k("Alt", "AltLeft", 18, None),
        "Meta" => k("Meta", "MetaLeft", 91, None),
        f if f.len() >= 2 && f.len() <= 3 && (f.starts_with('F') || f.starts_with('f')) && f[1..].parse::<u8>().is_ok_and(|n| (1..=12).contains(&n)) => {
            let n: i64 = f[1..].parse().unwrap();
            Ok(Key { key: format!("F{n}"), code: format!("F{n}"), vk: 111 + n, text: None })
        }
        c if c.chars().count() == 1 => {
            let ch = c.chars().next().unwrap();
            let (code, vk) = if ch.is_ascii_alphabetic() {
                (format!("Key{}", ch.to_ascii_uppercase()), ch.to_ascii_uppercase() as i64)
            } else if ch.is_ascii_digit() {
                (format!("Digit{ch}"), ch as i64)
            } else {
                let (code, vk) = match ch {
                    '-' => ("Minus", 189),
                    '=' => ("Equal", 187),
                    ',' => ("Comma", 188),
                    '.' => ("Period", 190),
                    '/' => ("Slash", 191),
                    ';' => ("Semicolon", 186),
                    '\'' => ("Quote", 222),
                    '[' => ("BracketLeft", 219),
                    ']' => ("BracketRight", 221),
                    '\\' => ("Backslash", 220),
                    '`' => ("Backquote", 192),
                    _ => ("", 0),
                };
                (code.to_string(), vk)
            };
            Ok(Key { key: c.into(), code, vk, text: Some(c.into()) })
        }
        other => Err(format!("unknown key `{other}` (use names like Enter, Tab, Escape, ArrowDown, F5, or a single character; chords like Control+Shift+T)")),
    }
}

fn modifier_bit(k: &str) -> i64 {
    match k {
        "Alt" => MOD_ALT,
        "Control" => MOD_CTRL,
        "Meta" => MOD_META,
        "Shift" => MOD_SHIFT,
        _ => 0,
    }
}

/// `dispatchKeyEvent` params for a chord such as `Control+Shift+T`, `Enter`, `a`.
pub fn chord_events(chord: &str) -> Result<Vec<Value>, String> {
    let chord = chord.trim();
    if chord.is_empty() {
        return Err("press requires key".into());
    }
    let parts: Vec<String> = if chord == " " || chord == "+" { vec![chord.to_string()] } else { chord.split('+').map(|s| alias(s.trim())).collect() };
    let mut mods = 0;
    let mut out = Vec::new();
    let (main, held) = parts.split_last().unwrap();
    for m in held {
        let bit = modifier_bit(m);
        if bit == 0 {
            return Err(format!("`{m}` is not a modifier (Control, Shift, Alt, Meta)"));
        }
        mods |= bit;
        let k = key_info(m)?;
        out.push(json!({"type": "rawKeyDown", "key": k.key, "code": k.code, "windowsVirtualKeyCode": k.vk, "modifiers": mods}));
    }
    let k = key_info(main)?;
    let mut text = k.text.clone();
    if mods & (MOD_CTRL | MOD_META | MOD_ALT) != 0 {
        text = None; // shortcuts insert nothing
    } else if mods & MOD_SHIFT != 0 {
        text = text.map(|t| t.to_uppercase());
    }
    let mut down = json!({"type": if text.is_some() { "keyDown" } else { "rawKeyDown" }, "key": k.key, "code": k.code, "windowsVirtualKeyCode": k.vk, "modifiers": mods});
    if let Some(t) = &text {
        down["text"] = json!(t);
        down["unmodifiedText"] = json!(t);
    }
    out.push(down);
    out.push(json!({"type": "keyUp", "key": k.key, "code": k.code, "windowsVirtualKeyCode": k.vk, "modifiers": mods}));
    for m in held.iter().rev() {
        mods &= !modifier_bit(m);
        let k = key_info(m)?;
        out.push(json!({"type": "keyUp", "key": k.key, "code": k.code, "windowsVirtualKeyCode": k.vk, "modifiers": mods}));
    }
    Ok(out)
}

/// Mouse modifiers bitmask from OpenClaw names (Alt|Control|ControlOrMeta|Meta|Shift).
pub fn mouse_modifiers(names: &[String]) -> Result<i64, String> {
    let mut m = 0;
    for n in names {
        m |= match n.as_str() {
            "Alt" => MOD_ALT,
            "Control" => MOD_CTRL,
            "ControlOrMeta" => {
                if cfg!(target_os = "macos") {
                    MOD_META
                } else {
                    MOD_CTRL
                }
            }
            "Meta" => MOD_META,
            "Shift" => MOD_SHIFT,
            _ => return Err("modifiers must be Alt|Control|ControlOrMeta|Meta|Shift".into()),
        };
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chords() {
        let e = chord_events("Enter").unwrap();
        assert_eq!((e[0]["type"].as_str(), e[0]["text"].as_str(), e.len()), (Some("keyDown"), Some("\r"), 2));
        let e = chord_events("ctrl+shift+t").unwrap();
        assert_eq!(e.len(), 6);
        assert_eq!((e[2]["key"].as_str(), e[2]["modifiers"].as_i64(), e[2].get("text")), (Some("t"), Some(10), None));
        assert_eq!(e[5]["modifiers"], 0);
        assert_eq!(chord_events("Esc").unwrap()[0]["key"], "Escape");
        assert_eq!(chord_events("Shift+a").unwrap()[1]["text"], "A");
        assert_eq!(chord_events("F5").unwrap()[0]["windowsVirtualKeyCode"], 116);
        assert!(chord_events("").is_err() && chord_events("a+b").is_err() && chord_events("Hyper").is_err());
        assert_eq!(mouse_modifiers(&["Shift".into(), "Alt".into()]).unwrap(), 9);
        assert!(mouse_modifiers(&["Fn".into()]).is_err());
    }
}
