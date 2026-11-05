//! What happens to input that arrives while a session is running (OpenClaw `/queue`,
//! Hermes `/busy` and `/queue`):
//!
//! - `steer` (default): injected after the next tool call of the running turn.
//! - `followup` / `queue`: held, then each one runs as its own turn after the current one.
//! - `collect`: held, then everything that arrived runs as one combined turn.
//! - `interrupt`: the running turn is stopped and the new input starts a fresh turn.
//!
//! `cap` bounds the held messages; `drop` says what goes when it is exceeded (`old`,
//! `new`, or `summarize` = fold the oldest into one condensed entry).

use crate::projection::Queued;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Steer,
    Followup,
    Collect,
    Interrupt,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "steer" | "steer-backlog" => Mode::Steer,
            "followup" | "follow-up" | "queue" => Mode::Followup,
            "collect" => Mode::Collect,
            "interrupt" => Mode::Interrupt,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Mode::Steer => "steer",
            Mode::Followup => "followup",
            Mode::Collect => "collect",
            Mode::Interrupt => "interrupt",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Drop {
    #[default]
    Old,
    New,
    Summarize,
}

impl Drop {
    pub fn parse(s: &str) -> Option<Drop> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "old" => Drop::Old,
            "new" => Drop::New,
            "summarize" | "summarise" => Drop::Summarize,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Drop::Old => "old",
            Drop::New => "new",
            Drop::Summarize => "summarize",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub mode: Mode,
    /// Most held messages (0 = unlimited).
    pub cap: usize,
    pub drop: Drop,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { mode: Mode::Steer, cap: 20, drop: Drop::Old }
    }
}

impl Settings {
    pub fn describe(&self) -> String {
        format!("mode {} · cap {} · drop {}", self.mode.name(), if self.cap == 0 { "∞".into() } else { self.cap.to_string() }, self.drop.name())
    }
}

/// Add `item` to the held list under `s`. Returns a notice when something was dropped.
pub fn hold(held: &Mutex<Vec<Queued>>, item: Queued, s: &Settings) -> Option<String> {
    let mut h = held.lock().unwrap();
    if s.mode == Mode::Collect {
        if let Some(last) = h.last_mut().filter(|l| l.1 == item.1) {
            last.2 = format!("{}\n\n{}", last.2, item.2);
            last.3.extend(item.3);
            return None;
        }
    }
    h.push(item);
    if s.cap == 0 || h.len() <= s.cap {
        return None;
    }
    match s.drop {
        Drop::Old => {
            h.remove(0);
            Some("queue full: dropped the oldest queued message".into())
        }
        Drop::New => {
            h.pop();
            Some("queue full: dropped the newest message".into())
        }
        Drop::Summarize => {
            let (a, b) = (h.remove(0), h.remove(0));
            let first: String = a.2.chars().take(400).collect();
            let second: String = b.2.chars().take(400).collect();
            let merged = if a.2.starts_with("[queued messages, condensed]") { format!("{first}\n- {second}") } else { format!("[queued messages, condensed]\n- {first}\n- {second}") };
            h.insert(0, (a.0, a.1, merged, [a.3, b.3].concat()));
            Some("queue full: condensed the two oldest queued messages".into())
        }
    }
}

/// Items to release after a turn: one per turn for followup, all merged for collect.
pub fn release(held: &Mutex<Vec<Queued>>, mode: Mode) -> Vec<Queued> {
    let mut h = held.lock().unwrap();
    if h.is_empty() {
        return vec![];
    }
    match mode {
        Mode::Collect => {
            let all: Vec<Queued> = std::mem::take(&mut *h);
            let mut it = all.into_iter();
            let mut first = it.next().unwrap();
            for q in it {
                first.2 = format!("{}\n\n{}", first.2, q.2);
                first.3.extend(q.3);
            }
            vec![first]
        }
        _ => vec![h.remove(0)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(t: &str) -> Queued {
        ("id".into(), "cli".into(), t.into(), vec![])
    }

    #[test]
    fn modes_caps_and_release() {
        assert_eq!(Mode::parse("queue"), Some(Mode::Followup));
        assert_eq!(Mode::parse("Interrupt"), Some(Mode::Interrupt));
        assert!(Mode::parse("nope").is_none());
        let h = Mutex::new(vec![]);
        let s = Settings { mode: Mode::Followup, cap: 2, drop: Drop::Old };
        assert!(hold(&h, q("a"), &s).is_none());
        hold(&h, q("b"), &s);
        assert!(hold(&h, q("c"), &s).unwrap().contains("oldest"));
        assert_eq!(h.lock().unwrap().iter().map(|x| x.2.as_str()).collect::<Vec<_>>(), ["b", "c"]);
        assert_eq!(release(&h, Mode::Followup)[0].2, "b");
        assert_eq!(h.lock().unwrap().len(), 1);

        let h = Mutex::new(vec![]);
        let c = Settings { mode: Mode::Collect, ..Settings::default() };
        hold(&h, q("x"), &c);
        hold(&h, q("y"), &c);
        assert_eq!(h.lock().unwrap().len(), 1, "collect merges");
        assert_eq!(release(&h, Mode::Collect)[0].2, "x\n\ny");

        let h = Mutex::new(vec![]);
        let n = Settings { mode: Mode::Followup, cap: 1, drop: Drop::New };
        hold(&h, q("keep"), &n);
        hold(&h, q("lost"), &n);
        assert_eq!(h.lock().unwrap()[0].2, "keep");
        let h = Mutex::new(vec![]);
        let z = Settings { mode: Mode::Followup, cap: 2, drop: Drop::Summarize };
        for t in ["1", "2", "3", "4"] {
            hold(&h, q(t), &z);
        }
        let v = h.lock().unwrap();
        assert_eq!(v.len(), 2);
        assert!(v[0].2.starts_with("[queued messages, condensed]") && v[0].2.contains("- 1") && v[0].2.contains("- 3"), "{}", v[0].2);
    }
}
