//! Per-session display preferences for the TUI: `/verbose`, `/timestamps`, `/focus`,
//! `/trace` and `/footer` (Hermes `display.*`). The slash layer stores them in
//! `<data>/display.json` keyed by session id (`crate::slash::display_get` lives in the
//! `ark` crate, which the TUI cannot link), so the TUI parses the same file itself.
//!
//! Defaults keep the TUI's original behaviour — every tool line shown, tool notices
//! shown, the footer drawn — and only an explicit value changes it.

use ark_kernel::config::Paths;
use serde_json::Value;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbose {
    /// Tool progress hidden everywhere.
    Off,
    /// Tool progress of the live turn only.
    New,
    /// Everything (the TUI default when the key is absent).
    All,
    /// Everything, with full tool details.
    Verbose,
}

impl Verbose {
    pub fn parse(s: &str) -> Option<Verbose> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "false" => Verbose::Off,
            "new" | "on" | "true" => Verbose::New,
            "all" => Verbose::All,
            "verbose" | "full" => Verbose::Verbose,
            _ => return None,
        })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Verbose::Off => "off",
            Verbose::New => "new",
            Verbose::All => "all",
            Verbose::Verbose => "verbose",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Display {
    pub verbose: Verbose,
    /// `[HH:MM]` in front of every message line.
    pub timestamps: bool,
    /// Only prompts and final answers: tool activity is hidden.
    pub focus: bool,
    /// Daemon notice/trace lines.
    pub trace: bool,
    /// The footer block (dock, hints) under the conversation.
    pub footer: bool,
}

impl Default for Display {
    fn default() -> Self {
        Display { verbose: Verbose::All, timestamps: false, focus: false, trace: true, footer: true }
    }
}

pub fn path(paths: &Paths) -> PathBuf {
    paths.data.join("display.json")
}

/// The preferences of `session` (an absent session or file = the defaults).
pub fn load(paths: &Paths, session: Option<&str>) -> Display {
    let Some(id) = session.filter(|s| !s.is_empty()) else { return Display::default() };
    let all: Value = std::fs::read_to_string(path(paths)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(|| Value::Object(Default::default()));
    match all.get(id) {
        Some(v) => parse(v),
        None => Display::default(),
    }
}

/// One session's entry from `display.json`.
pub fn parse(v: &Value) -> Display {
    let d = Display::default();
    let flag = |key: &str, default: bool| match v.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => matches!(s.trim().to_ascii_lowercase().as_str(), "on" | "true" | "yes" | "1"),
        _ => default,
    };
    Display {
        verbose: v.get("verbose").and_then(Value::as_str).and_then(Verbose::parse).unwrap_or(d.verbose),
        timestamps: flag("timestamps", d.timestamps),
        focus: flag("focus", d.focus),
        trace: flag("trace", d.trace),
        footer: flag("footer", d.footer),
    }
}

/// Should a `tool` line at `index` be drawn? `last_user` = index of the last prompt.
pub fn shows_tool(d: &Display, index: usize, last_user: Option<usize>) -> bool {
    if d.focus {
        return false;
    }
    match d.verbose {
        Verbose::Off => false,
        Verbose::New => last_user.is_none_or(|u| index > u),
        Verbose::All | Verbose::Verbose => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn display_defaults_and_explicit_flags() {
        let d = Display::default();
        assert_eq!(d.verbose, Verbose::All);
        assert!(!d.timestamps && !d.focus && d.trace && d.footer);
        assert_eq!(Verbose::parse("NEW"), Some(Verbose::New));
        assert_eq!(Verbose::parse("bogus"), None);
        assert_eq!(Verbose::parse("verbose").unwrap().as_str(), "verbose");
        let v = json!({"verbose": "new", "timestamps": "on", "focus": true, "trace": "off", "footer": false});
        let p = parse(&v);
        assert_eq!(p.verbose, Verbose::New);
        assert!(p.timestamps && p.focus && !p.trace && !p.footer);
        // Unknown values fall back to the defaults, not to "off".
        assert_eq!(parse(&json!({"verbose": "??"})).verbose, Verbose::All);
        // Tool lines per level: index 3 is in the live turn (after the prompt at 2).
        assert!(shows_tool(&Display::default(), 1, Some(2)));
        assert!(!shows_tool(&Display { verbose: Verbose::Off, ..Default::default() }, 3, Some(2)));
        assert!(!shows_tool(&Display { verbose: Verbose::New, ..Default::default() }, 1, Some(2)));
        assert!(shows_tool(&Display { verbose: Verbose::New, ..Default::default() }, 3, Some(2)));
        assert!(!shows_tool(&Display { focus: true, ..Default::default() }, 3, Some(2)));
    }

    #[test]
    fn loads_by_session_from_display_json() {
        let p = super::super::prefs::test_paths("display");
        assert_eq!(load(&p, Some("s1")), Display::default(), "no file yet");
        std::fs::write(path(&p), json!({"s1": {"timestamps": true, "verbose": "off"}, "s2": {"focus": true}}).to_string()).unwrap();
        let s1 = load(&p, Some("s1"));
        assert!(s1.timestamps);
        assert_eq!(s1.verbose, Verbose::Off);
        assert!(load(&p, Some("s2")).focus);
        assert_eq!(load(&p, Some("nope")), Display::default());
        assert_eq!(load(&p, None), Display::default());
    }
}
