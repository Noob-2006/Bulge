//! A minimal QMP client (QEMU Machine Protocol over the VM's private unix socket — a loopback
//! TCP port recorded in the same path on Windows, see [`crate::channel::Endpoint`]): enough
//! for `screendump` (PNG frames) and `input-send-event` (absolute pointer, buttons, wheel,
//! keys) — so neither seagent nor the web console needs a VNC client to see or drive the guest.

use super::keys;
use serde_json::{json, Value};
use crate::channel::{Endpoint, Stream};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::Duration;

/// Absolute axis range of QEMU's input layer (`INPUT_EVENT_ABS_MAX`).
pub const ABS_MAX: u32 = 0x7fff;

pub struct Qmp {
    r: BufReader<Stream>,
    w: Stream,
}

impl Qmp {
    /// Connect, read the greeting and negotiate capabilities.
    pub fn connect(sock: &Path, timeout: Duration) -> Result<Qmp, String> {
        let s = Endpoint::locate(sock).and_then(|e| e.connect()).map_err(|e| format!("QMP {}: {e}", sock.display()))?;
        s.set_read_timeout(Some(timeout)).ok();
        s.set_write_timeout(Some(timeout)).ok();
        let w = s.try_clone().map_err(|e| e.to_string())?;
        let mut q = Qmp { r: BufReader::new(s), w };
        let greet = q.read_msg()?;
        if greet.get("QMP").is_none() {
            return Err(format!("not a QMP greeting: {greet}"));
        }
        q.execute("qmp_capabilities", None)?;
        Ok(q)
    }

    fn read_msg(&mut self) -> Result<Value, String> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.r.read_line(&mut line).map_err(|e| format!("QMP read: {e}"))?;
            if n == 0 {
                return Err("QMP connection closed".into());
            }
            if line.trim().is_empty() {
                continue;
            }
            return serde_json::from_str(line.trim()).map_err(|e| format!("QMP sent invalid JSON ({e}): {}", line.trim()));
        }
    }

    /// Run one command; asynchronous events in between are skipped.
    pub fn execute(&mut self, cmd: &str, args: Option<Value>) -> Result<Value, String> {
        let mut m = json!({"execute": cmd});
        if let Some(a) = args {
            m["arguments"] = a;
        }
        self.w.write_all(format!("{m}\n").as_bytes()).map_err(|e| format!("QMP write: {e}"))?;
        loop {
            let v = self.read_msg()?;
            if let Some(r) = v.get("return") {
                return Ok(r.clone());
            }
            if let Some(e) = v.get("error") {
                return Err(format!("QMP {cmd}: {}", e["desc"].as_str().unwrap_or(&e.to_string())));
            }
        }
    }

    /// The guest framebuffer as PNG bytes. QEMU writes the file itself, so `tmp` must be a
    /// path the QEMU process can write (the VM's private run dir); it is removed afterwards.
    pub fn screendump_png(&mut self, tmp: &Path) -> Result<Vec<u8>, String> {
        let _ = std::fs::remove_file(tmp);
        let r = self.execute("screendump", Some(json!({"filename": tmp.display().to_string(), "format": "png"})));
        let out = r.and_then(|_| std::fs::read(tmp).map_err(|e| format!("screendump output {}: {e}", tmp.display())));
        let _ = std::fs::remove_file(tmp);
        let png = out?;
        if !png.starts_with(b"\x89PNG\r\n\x1a\n") {
            return Err("screendump did not produce a PNG (QEMU 7.1 or newer is required)".into());
        }
        Ok(png)
    }

    pub fn send_events(&mut self, events: Vec<Value>) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        self.execute("input-send-event", Some(json!({"events": events}))).map(|_| ())
    }
}

/// PNG pixel size from the IHDR chunk.
pub fn png_size(b: &[u8]) -> Option<(u32, u32)> {
    if b.len() < 24 || !b.starts_with(b"\x89PNG\r\n\x1a\n") {
        return None;
    }
    let be = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    Some((be(16), be(20)))
}

/// Screen pixel → QEMU absolute axis value (the USB tablet spans the whole framebuffer).
pub fn abs(v: i64, size: u32) -> u32 {
    let max = size.saturating_sub(1).max(1) as i64;
    ((v.clamp(0, max) * ABS_MAX as i64 + max / 2) / max) as u32
}

pub fn move_events(x: i64, y: i64, w: u32, h: u32) -> Vec<Value> {
    vec![json!({"type": "abs", "data": {"axis": "x", "value": abs(x, w)}}), json!({"type": "abs", "data": {"axis": "y", "value": abs(y, h)}})]
}

pub fn button_event(button: &str, down: bool) -> Value {
    json!({"type": "btn", "data": {"down": down, "button": button}})
}

pub fn key_event(qcode: &str, down: bool) -> Value {
    json!({"type": "key", "data": {"down": down, "key": {"type": "qcode", "data": qcode}}})
}

/// `left` / `right` / `middle` (also 1/2/3 as strings) → QMP `InputButton`.
pub fn button_name(b: &str) -> Result<&'static str, String> {
    Ok(match b.trim().to_ascii_lowercase().as_str() {
        "" | "left" | "1" | "primary" => "left",
        "middle" | "2" | "wheel" => "middle",
        "right" | "3" | "secondary" | "context" => "right",
        "back" | "side" => "side",
        "forward" | "extra" => "extra",
        o => return Err(format!("unknown mouse button `{o}` (left, middle, right)")),
    })
}

/// A desktop input event in screen pixels (the `view.desktop.input` / computer-use shape).
#[derive(Debug, Clone, PartialEq)]
pub enum Input {
    Move { x: i64, y: i64 },
    Click { x: Option<i64>, y: Option<i64>, button: String, count: u32 },
    Down { x: Option<i64>, y: Option<i64>, button: String },
    Up { x: Option<i64>, y: Option<i64>, button: String },
    Scroll { x: Option<i64>, y: Option<i64>, dx: i64, dy: i64 },
    Key { keys: String },
    Type { text: String },
    Drag { from: (i64, i64), to: (i64, i64), button: String },
}

impl Input {
    /// `{type: "move"|"click"|"down"|"up"|"scroll"|"key"|"type"|"drag", x, y, button, dx, dy, key, text, count, toX, toY}`.
    pub fn from_json(e: &Value) -> Result<Input, String> {
        let t = e["type"].as_str().unwrap_or("").trim().to_ascii_lowercase();
        let num = |k: &str| e[k].as_f64().map(|f| f.round() as i64);
        let button = e["button"].as_str().map(str::to_string).or_else(|| e["button"].as_u64().map(|n| n.to_string())).unwrap_or_else(|| "left".into());
        let need_xy = || match (num("x"), num("y")) {
            (Some(x), Some(y)) => Ok((x, y)),
            _ => Err(format!("`{t}` needs numeric x and y (screen pixels)")),
        };
        Ok(match t.as_str() {
            "move" | "mousemove" => {
                let (x, y) = need_xy()?;
                Input::Move { x, y }
            }
            "click" | "dblclick" | "double_click" => {
                let count = if t == "click" { e["count"].as_u64().unwrap_or(1).clamp(1, 3) as u32 } else { 2 };
                Input::Click { x: num("x"), y: num("y"), button, count }
            }
            "down" | "mousedown" => Input::Down { x: num("x"), y: num("y"), button },
            "up" | "mouseup" => Input::Up { x: num("x"), y: num("y"), button },
            "scroll" | "wheel" => Input::Scroll { x: num("x"), y: num("y"), dx: num("dx").unwrap_or(0), dy: num("dy").unwrap_or(0) },
            "key" | "keypress" => {
                let k = e["key"].as_str().or(e["keys"].as_str()).unwrap_or("").to_string();
                if k.trim().is_empty() {
                    return Err("`key` needs key (e.g. \"Return\", \"ctrl+l\")".into());
                }
                Input::Key { keys: k }
            }
            "type" | "text" => Input::Type { text: e["text"].as_str().unwrap_or("").to_string() },
            "drag" => {
                let from = need_xy()?;
                let to = match (num("toX"), num("toY")) {
                    (Some(x), Some(y)) => (x, y),
                    _ => return Err("`drag` needs x, y, toX and toY".into()),
                };
                Input::Drag { from, to, button }
            }
            "" => return Err("event.type is required".into()),
            o => return Err(format!("unknown event type `{o}` (move, click, down, up, scroll, key, type, drag)")),
        })
    }

    /// Short label for logs / results.
    pub fn kind(&self) -> &'static str {
        match self {
            Input::Move { .. } => "move",
            Input::Click { .. } => "click",
            Input::Down { .. } => "down",
            Input::Up { .. } => "up",
            Input::Scroll { .. } => "scroll",
            Input::Key { .. } => "key",
            Input::Type { .. } => "type",
            Input::Drag { .. } => "drag",
        }
    }
}

/// Pause between event batches: lets the guest see a press and its release as two reports.
const STEP: Duration = Duration::from_millis(12);
/// Pause after a click or shortcut before the next input (focus changes, popups opening).
const SETTLE: Duration = Duration::from_millis(150);

/// Deliver one input to the guest. `(w, h)` is the current framebuffer size. Returns how
/// many characters were typed (for `type`) or 0.
pub fn deliver(q: &mut Qmp, ev: &Input, w: u32, h: u32) -> Result<usize, String> {
    let pos = |x: Option<i64>, y: Option<i64>| match (x, y) {
        (Some(x), Some(y)) => move_events(x, y, w, h),
        _ => vec![],
    };
    match ev {
        Input::Move { x, y } => q.send_events(move_events(*x, *y, w, h)).map(|_| 0),
        Input::Click { x, y, button, count } => {
            let b = button_name(button)?;
            q.send_events(pos(*x, *y))?;
            for _ in 0..*count {
                std::thread::sleep(STEP);
                q.send_events(vec![button_event(b, true)])?;
                std::thread::sleep(STEP);
                q.send_events(vec![button_event(b, false)])?;
            }
            std::thread::sleep(SETTLE);
            Ok(0)
        }
        Input::Down { x, y, button } | Input::Up { x, y, button } => {
            let b = button_name(button)?;
            let mut evs = pos(*x, *y);
            evs.push(button_event(b, matches!(ev, Input::Down { .. })));
            q.send_events(evs).map(|_| 0)
        }
        Input::Scroll { x, y, dx, dy } => {
            q.send_events(pos(*x, *y))?;
            let mut ticks: Vec<&str> = vec![];
            let (v, hz) = ((*dy).clamp(-50, 50), (*dx).clamp(-50, 50));
            ticks.extend(std::iter::repeat_n(if v > 0 { "wheel-down" } else { "wheel-up" }, v.unsigned_abs() as usize));
            ticks.extend(std::iter::repeat_n(if hz > 0 { "wheel-right" } else { "wheel-left" }, hz.unsigned_abs() as usize));
            for t in ticks {
                q.send_events(vec![button_event(t, true), button_event(t, false)])?;
                std::thread::sleep(STEP);
            }
            Ok(0)
        }
        Input::Key { keys } => {
            // One key per report, then a short settle: a shortcut (ctrl+a, ctrl+l) often makes
            // the guest app re-render, and keys typed right behind it were seen to get lost.
            let ks = keys::combo(keys)?;
            for k in &ks {
                q.send_events(vec![key_event(k, true)])?;
                std::thread::sleep(STEP);
            }
            for k in ks.iter().rev() {
                q.send_events(vec![key_event(k, false)])?;
                std::thread::sleep(STEP);
            }
            std::thread::sleep(SETTLE);
            Ok(0)
        }
        Input::Type { text } => {
            if let Some(c) = text.chars().find(|c| keys::char_key(*c).is_none()) {
                return Err(format!("cannot type {c:?}: the VM keyboard is US ASCII only (type the rest another way, e.g. paste through the guest)"));
            }
            let mut n = 0;
            for c in text.chars() {
                let (k, shift) = keys::char_key(c).unwrap_or(("spc", false));
                let mut down = vec![];
                if shift {
                    down.push(key_event("shift", true));
                }
                down.push(key_event(k, true));
                q.send_events(down)?;
                std::thread::sleep(STEP);
                let mut up = vec![key_event(k, false)];
                if shift {
                    up.push(key_event("shift", false));
                }
                q.send_events(up)?;
                std::thread::sleep(STEP);
                n += 1;
            }
            Ok(n)
        }
        Input::Drag { from, to, button } => {
            let b = button_name(button)?;
            q.send_events(move_events(from.0, from.1, w, h))?;
            std::thread::sleep(STEP);
            q.send_events(vec![button_event(b, true)])?;
            // A few intermediate points so drag thresholds in the guest toolkit trip.
            for i in 1..=8 {
                let x = from.0 + (to.0 - from.0) * i / 8;
                let y = from.1 + (to.1 - from.1) * i / 8;
                std::thread::sleep(STEP);
                q.send_events(move_events(x, y, w, h))?;
            }
            std::thread::sleep(STEP);
            q.send_events(vec![button_event(b, false)])?;
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abs_scaling_and_event_parsing() {
        assert_eq!(abs(0, 1280), 0);
        assert_eq!(abs(1279, 1280), ABS_MAX);
        assert_eq!(abs(5000, 1280), ABS_MAX, "clamped to the screen");
        assert_eq!(abs(-3, 1280), 0);
        let mid = abs(640, 1280);
        assert!((16390..16420).contains(&mid), "{mid}");
        assert_eq!(Input::from_json(&json!({"type": "click", "x": 10, "y": 20})).unwrap(), Input::Click { x: Some(10), y: Some(20), button: "left".into(), count: 1 });
        assert_eq!(Input::from_json(&json!({"type": "scroll", "dy": 3})).unwrap(), Input::Scroll { x: None, y: None, dx: 0, dy: 3 });
        assert_eq!(Input::from_json(&json!({"type": "key", "key": "ctrl+l"})).unwrap(), Input::Key { keys: "ctrl+l".into() });
        assert!(Input::from_json(&json!({"type": "move"})).unwrap_err().contains("x and y"));
        assert!(Input::from_json(&json!({"type": "fly"})).unwrap_err().contains("unknown event type"));
        assert!(Input::from_json(&json!({})).is_err());
        assert_eq!(button_name("3").unwrap(), "right");
        assert!(button_name("seventh").is_err());
        assert_eq!(png_size(&[b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".as_slice(), &640u32.to_be_bytes(), &480u32.to_be_bytes()].concat()), Some((640, 480)));
    }
}
