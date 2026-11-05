//! Key names and typed characters → QEMU `QKeyCode`s (the `qcode` values of QMP
//! `input-send-event`). The guest keyboard layout is US (the provisioned image's default),
//! so a character maps to one key plus, for upper-case and shifted symbols, `shift`.

/// One character on a US keyboard: (qcode, needs shift). `None` for characters that have
/// no key (non-ASCII text cannot be typed through a keyboard device).
pub fn char_key(c: char) -> Option<(&'static str, bool)> {
    const LOWER: [&str; 26] = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"];
    const DIGITS: [&str; 10] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
    Some(match c {
        'a'..='z' => (LOWER[(c as u8 - b'a') as usize], false),
        'A'..='Z' => (LOWER[(c as u8 - b'A') as usize], true),
        '0'..='9' => (DIGITS[(c as u8 - b'0') as usize], false),
        ' ' => ("spc", false),
        '\n' | '\r' => ("ret", false),
        '\t' => ("tab", false),
        '-' => ("minus", false),
        '_' => ("minus", true),
        '=' => ("equal", false),
        '+' => ("equal", true),
        '[' => ("bracket_left", false),
        '{' => ("bracket_left", true),
        ']' => ("bracket_right", false),
        '}' => ("bracket_right", true),
        '\\' => ("backslash", false),
        '|' => ("backslash", true),
        ';' => ("semicolon", false),
        ':' => ("semicolon", true),
        '\'' => ("apostrophe", false),
        '"' => ("apostrophe", true),
        '`' => ("grave_accent", false),
        '~' => ("grave_accent", true),
        ',' => ("comma", false),
        '<' => ("comma", true),
        '.' => ("dot", false),
        '>' => ("dot", true),
        '/' => ("slash", false),
        '?' => ("slash", true),
        '!' => ("1", true),
        '@' => ("2", true),
        '#' => ("3", true),
        '$' => ("4", true),
        '%' => ("5", true),
        '^' => ("6", true),
        '&' => ("7", true),
        '*' => ("8", true),
        '(' => ("9", true),
        ')' => ("0", true),
        _ => return None,
    })
}

/// A key name (xdotool / Playwright / cua spelling, case-insensitive) → qcode.
pub fn named_key(name: &str) -> Option<String> {
    let n = name.trim();
    if n.chars().count() == 1 {
        let c = n.chars().next()?;
        // A single upper-case letter in a combo means the letter key ("ctrl+L" = ctrl+l).
        return char_key(c.to_ascii_lowercase()).map(|(k, _)| k.to_string());
    }
    let l = n.to_ascii_lowercase().replace(['-', ' '], "_");
    let k = match l.as_str() {
        "ctrl" | "control" | "control_l" | "ctrl_l" | "lctrl" => "ctrl",
        "control_r" | "ctrl_r" | "rctrl" => "ctrl_r",
        "shift" | "shift_l" | "lshift" => "shift",
        "shift_r" | "rshift" => "shift_r",
        "alt" | "alt_l" | "option" | "opt" | "lalt" => "alt",
        "alt_r" | "altgr" | "ralt" => "alt_r",
        "super" | "super_l" | "win" | "windows" | "meta" | "meta_l" | "cmd" | "command" => "meta_l",
        "super_r" | "meta_r" => "meta_r",
        "menu" => "menu",
        "return" | "enter" | "ret" => "ret",
        "kp_enter" => "kp_enter",
        "escape" | "esc" => "esc",
        "tab" => "tab",
        "space" | "spc" => "spc",
        "backspace" | "back_space" => "backspace",
        "delete" | "del" => "delete",
        "insert" | "ins" => "insert",
        "home" => "home",
        "end" => "end",
        "pageup" | "page_up" | "pgup" | "prior" => "pgup",
        "pagedown" | "page_down" | "pgdn" | "next" => "pgdn",
        "up" | "arrowup" | "arrow_up" => "up",
        "down" | "arrowdown" | "arrow_down" => "down",
        "left" | "arrowleft" | "arrow_left" => "left",
        "right" | "arrowright" | "arrow_right" => "right",
        "capslock" | "caps_lock" => "caps_lock",
        "print" | "printscreen" | "print_screen" => "print",
        "minus" => "minus",
        "equal" | "plus" => "equal",
        "comma" => "comma",
        "period" | "dot" => "dot",
        "slash" => "slash",
        "backslash" => "backslash",
        "semicolon" => "semicolon",
        "apostrophe" | "quote" => "apostrophe",
        "grave" | "backquote" | "grave_accent" => "grave_accent",
        "bracketleft" | "bracket_left" => "bracket_left",
        "bracketright" | "bracket_right" => "bracket_right",
        f if f.starts_with('f') && f[1..].parse::<u8>().is_ok_and(|n| (1..=12).contains(&n)) => return Some(f.to_string()),
        _ => return None,
    };
    Some(k.to_string())
}

/// `"ctrl+shift+t"` / `"Return"` / `"ctrl-l"` → the qcodes, modifiers first (pressed in order,
/// released in reverse). A lone `-` / `+` is the key itself.
pub fn combo(keys: &str) -> Result<Vec<String>, String> {
    let k = keys.trim();
    if k.is_empty() {
        return Err("empty key combo".into());
    }
    let parts: Vec<&str> = if k == "+" || k == "-" { vec![k] } else { k.split(['+']).flat_map(|p| if p.len() > 1 && p.contains('-') && !p.starts_with('-') { p.split('-').collect::<Vec<_>>() } else { vec![p] }).collect() };
    let mut out = Vec::new();
    for p in parts {
        let p = if p.is_empty() { "+" } else { p };
        let q = if p == "+" { Some("equal".to_string()) } else { named_key(p) };
        match q {
            Some(q) => out.push(q),
            None => return Err(format!("unknown key `{p}` in `{keys}` (use names like ctrl, alt, shift, super, Return, Escape, Tab, BackSpace, Delete, Up, F5, or single characters)")),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chars_and_combos_map_to_qcodes() {
        assert_eq!(char_key('a'), Some(("a", false)));
        assert_eq!(char_key('Q'), Some(("q", true)));
        assert_eq!(char_key('?'), Some(("slash", true)));
        assert_eq!(char_key(':'), Some(("semicolon", true)));
        assert_eq!(char_key(' '), Some(("spc", false)));
        assert_eq!(char_key('\n'), Some(("ret", false)));
        assert_eq!(char_key('é'), None);
        assert_eq!(combo("ctrl+l").unwrap(), ["ctrl", "l"]);
        assert_eq!(combo("Ctrl+Shift+T").unwrap(), ["ctrl", "shift", "t"]);
        assert_eq!(combo("ctrl-alt-t").unwrap(), ["ctrl", "alt", "t"]);
        assert_eq!(combo("Return").unwrap(), ["ret"]);
        assert_eq!(combo("super").unwrap(), ["meta_l"]);
        assert_eq!(combo("F5").unwrap(), ["f5"]);
        assert_eq!(combo("Page_Down").unwrap(), ["pgdn"]);
        assert_eq!(combo("alt+F4").unwrap(), ["alt", "f4"]);
        assert_eq!(combo("-").unwrap(), ["minus"]);
        assert!(combo("ctrl+nosuchkey").unwrap_err().contains("nosuchkey"));
        assert!(combo(" ").is_err());
    }
}
