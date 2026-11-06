//! Glue between the TUI loop (`tui.rs`) and the terminal UX pieces: preferences reload,
//! skin palette, Ctrl+S stash, busy indicator, status bar, live dock, pet pane, startup
//! tip and OSC 9/777 notifications. `tui.rs` only calls into this at a handful of points.

use super::{battery, dock::Dock, indicator, notify, pets, prefs, skin, stash::Outcome, stash::Stash, statusbar, tips};
use seagent_kernel::config::Paths;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub struct Ux {
    pub paths: Paths,
    workspace: PathBuf,
    pub prefs: Value,
    pub skin: skin::Skin,
    pub pal: skin::Palette,
    pub stash: Stash,
    pub dock: Dock,
    snapshot: Value,
    snap_at: Option<Instant>,
    prefs_at: Instant,
    turn_started: Option<Instant>,
    last_duration: Option<Duration>,
    finished_at: Option<Instant>,
    flash: Option<(&'static str, Instant)>,
    tool_running: bool,
    awaiting: bool,
    pet: pets::Pane,
    started: Instant,
    branch: Option<String>,
}

fn fg(c: (u8, u8, u8)) -> String {
    format!("\x1b[38;2;{};{};{}m", c.0, c.1, c.2)
}
fn bg(c: (u8, u8, u8)) -> String {
    format!("\x1b[48;2;{};{};{}m", c.0, c.1, c.2)
}

impl Ux {
    pub fn new(workspace: &std::path::Path) -> Ux {
        let paths = Paths::from_env();
        let prefs = prefs::load(&paths);
        let skin = skin::load(&paths, &prefs::get_str(&prefs, "skin", "default"));
        let pal = skin::Palette::of(&skin);
        Ux { branch: statusbar::git_branch(workspace), workspace: workspace.to_path_buf(), paths, prefs, pal, skin, stash: Stash::new(), dock: Dock::default(), snapshot: json!({}), snap_at: None, prefs_at: Instant::now(), turn_started: None, last_duration: None, finished_at: None, flash: None, tool_running: false, awaiting: false, pet: pets::Pane::default(), started: Instant::now() }
    }

    /// Re-read `ui.json` (and the skin) — after a slash command, or every 2 s.
    pub fn reload(&mut self) {
        self.prefs = prefs::load(&self.paths);
        self.skin = skin::load(&self.paths, &prefs::get_str(&self.prefs, "skin", "default"));
        self.pal = skin::Palette::of(&self.skin);
        self.prefs_at = Instant::now();
        self.branch = statusbar::git_branch(&self.workspace);
    }

    pub fn tick(&mut self, call: &dyn Fn(&str, Value) -> Result<Value, String>, session: Option<&str>) {
        if self.prefs_at.elapsed() > Duration::from_secs(2) {
            self.reload();
        }
        if let Some(s) = session {
            if self.snap_at.is_none_or(|t| t.elapsed() > Duration::from_millis(1000)) {
                self.snap_at = Some(Instant::now());
                if let Ok(v) = call("dock.snapshot", json!({"session": s})) {
                    self.dock = Dock::from_snapshot(&v, self.dock.collapsed);
                    self.snapshot = v;
                }
            }
        }
    }

    pub fn is_default_skin(&self) -> bool {
        self.skin.name == "default"
    }

    pub fn startup_tip(&self) -> Option<String> {
        tips::startup_line(&self.prefs)
    }

    pub fn placeholder(&self) -> String {
        let h = self.stash.placeholder_hint();
        if h.is_empty() {
            tips::random_placeholder()
        } else {
            h
        }
    }

    // ── activity ──
    pub fn turn_started(&mut self) {
        self.turn_started.get_or_insert_with(Instant::now);
        self.awaiting = false;
        self.snap_at = None;
    }
    pub fn tool(&mut self, running: bool) {
        self.tool_running = running;
    }
    pub fn turn_ended(&mut self, reason: &str, session: &str) {
        if let Some(t) = self.turn_started.take() {
            self.last_duration = Some(t.elapsed());
        }
        self.finished_at = Some(Instant::now());
        self.tool_running = false;
        self.awaiting = false;
        self.snap_at = None;
        let ok = reason == "done" || reason == "idle" || reason == "end_turn";
        self.flash = Some((if ok { "wave" } else { "failed" }, Instant::now()));
        if prefs::get_bool(&self.prefs, "bell_on_complete", false) {
            let ctx = if ok { "turn complete".to_string() } else { format!("turn ended: {reason}") };
            notify::write_tty(&notify::sequence(&notify::env_map(), &ctx, false, session, "", &self.workspace.display().to_string()));
        }
    }
    /// A turn that kept running after `/new` finished in the background: flash the pet
    /// and notify when `bell_on_complete` is on, without touching the live turn's timer.
    pub fn background_finished(&mut self, title: &str, session: &str, ok: bool) {
        self.flash = Some((if ok { "wave" } else { "failed" }, Instant::now()));
        if prefs::get_bool(&self.prefs, "bell_on_complete", false) {
            let what = format!("background turn complete: {title}");
            notify::write_tty(&notify::sequence(&notify::env_map(), &what, false, session, "", &self.workspace.display().to_string()));
        }
    }

    pub fn prompted(&mut self, what: &str, session: &str) {
        self.awaiting = true;
        if prefs::get_bool(&self.prefs, "bell_on_prompt", false) {
            notify::write_tty(&notify::sequence(&notify::env_map(), what, true, session, what, &self.workspace.display().to_string()));
        }
    }
    pub fn answered(&mut self) {
        self.awaiting = false;
    }

    fn pet_state(&self, running: bool) -> &'static str {
        let flash = self.flash.filter(|(_, t)| t.elapsed() < Duration::from_millis(2200)).map(|f| f.0);
        pets::derive_state(&pets::Activity { busy: running, awaiting_input: self.awaiting, error: flash == Some("failed"), celebrate: false, just_completed: flash == Some("wave"), tool_running: running && self.tool_running, reasoning: running && !self.tool_running })
    }

    /// Busy text for the header (`/indicator` style + skin spinner faces/verbs).
    pub fn indicator(&self, tick: usize) -> String {
        let style = prefs::get_str(&self.prefs, "indicator", indicator::DEFAULT);
        indicator::render(&style, tick, &self.skin.spinner_list("thinking_faces"), &self.skin.spinner_list("thinking_verbs"))
    }

    // ── keys ──
    /// Ctrl+S on the composer.
    pub fn ctrl_s(&mut self, input: &mut String) -> Option<String> {
        match self.stash.ctrl_s(input, 0) {
            Outcome::Stashed => {
                input.clear();
                Some(format!("📌 draft stashed ({} in stash) — Ctrl+S on an empty composer restores", self.stash.len()))
            }
            Outcome::Restored(t) => {
                *input = t;
                None
            }
            _ => None,
        }
    }
    /// Keys while the stash browser is open; true = consumed.
    pub fn stash_key(&mut self, key: &str, input: &mut String) -> bool {
        if !self.stash.panel_open {
            return false;
        }
        match key {
            "up" => {
                self.stash.move_cursor(-1);
            }
            "down" => {
                self.stash.move_cursor(1);
            }
            "enter" => {
                if let Some(t) = self.stash.restore_at_cursor() {
                    *input = t;
                }
            }
            "delete" | "x" => {
                self.stash.delete_at_cursor();
            }
            "esc" => self.stash.close_panel(),
            _ => return false,
        }
        true
    }
    pub fn toggle_dock(&mut self) {
        self.dock.collapsed = !self.dock.collapsed;
    }

    // ── drawing ──
    fn pet_lines(&mut self, running: bool) -> Vec<String> {
        let st = self.pet_state(running);
        let ms = self.started.elapsed().as_millis() as u64;
        self.pet.lines(&self.paths, st, ms)
    }

    /// Pet sprite rows to overlay at the right edge of the conversation (width, lines).
    pub fn overlay(&mut self, running: bool) -> (usize, Vec<String>) {
        let l = self.pet_lines(running);
        let w = l.first().map(|_| pets::resolve_cols(self.prefs["pet"]["scale"].as_f64().unwrap_or(pets::DEFAULT_SCALE), self.prefs["pet"]["unicode_cols"].as_u64().unwrap_or(0) as usize)).unwrap_or(0);
        (w, l)
    }

    fn status_input(&self, running: bool, tick: usize) -> statusbar::Input {
        let s = &self.snapshot["status"];
        statusbar::Input {
            indicator: if running { indicator::frame(&prefs::get_str(&self.prefs, "indicator", indicator::DEFAULT), tick, &self.skin.spinner_list("thinking_faces")).0 } else { "✦".into() },
            model: s["model"].as_str().unwrap_or("").to_string(),
            context_pct: s["context_pct"].as_u64().map(|p| p.min(100) as u8),
            tokens: s["tokens"].as_u64().unwrap_or(0),
            cache_pct: s["cache_pct"].as_f64(),
            compactions: s["compactions"].as_u64().unwrap_or(0),
            elapsed: self.turn_started.map(|t| t.elapsed()).or(self.last_duration),
            live: self.turn_started.is_some(),
            idle_since: self.finished_at.map(|t| t.elapsed()),
            branch: self.branch.clone(),
            battery: prefs::get_bool(&self.prefs, "battery", false).then(|| battery::read(true)),
            stash: self.stash.indicator(),
        }
    }

    /// Rows between the conversation and the composer: stash browser, dock, status bar.
    pub fn footer(&self, w: usize, h: usize, running: bool, tick: usize, sw: &dyn Fn(&str) -> usize) -> Vec<String> {
        let mut out = vec![];
        let p = &self.pal;
        if self.stash.panel_open {
            out.push(format!("{}{} 📌 stashed drafts — ↑/↓ move · Enter restore · x delete · Esc/Ctrl+S close{}", bg(p.panel), fg(p.status_strong), "\x1b[K\x1b[0m"));
            for r in self.stash.panel_rows().into_iter().take(6) {
                out.push(format!("{}{}{}\x1b[K\x1b[0m", bg(p.panel), fg(p.text), r));
            }
        }
        if prefs::get_bool(&self.prefs, "dock", true) {
            for l in self.dock.lines(w, h, sw) {
                out.push(format!("{}{}{l}\x1b[K\x1b[0m", bg(p.status_bg), fg(p.status_text)));
            }
        }
        if prefs::get_bool(&self.prefs, "statusbar", true) {
            let segs = statusbar::fit(&self.status_input(running, tick), w, sw);
            let mut line = format!("{} ", bg(p.status_bg));
            for (i, (t, style)) in segs.iter().enumerate() {
                if i > 0 {
                    line.push_str(&format!("{} │ ", fg(p.status_dim)));
                }
                line.push_str(&format!("{}{t}", fg(p.by_name(style))));
            }
            line.push_str("\x1b[K\x1b[0m");
            out.push(line);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn footer_stash_and_activity() {
        let p = super::super::prefs::test_paths("ux");
        let mut u = Ux::new(&seagent_core::tmp::scratch("seagent-ws"));
        u.paths = p.clone();
        u.reload();
        let sw = |s: &str| s.chars().count();
        let f = u.footer(100, 40, false, 0, &sw);
        assert_eq!(f.len(), 1, "status bar only");
        assert!(f[0].contains("ctx —") && f[0].contains("⏲ 0s"));
        let mut input = "half-written idea".to_string();
        assert!(u.ctrl_s(&mut input).unwrap().contains("stashed"));
        assert!(input.is_empty());
        assert!(u.footer(100, 40, false, 0, &sw)[0].contains("📌 1"));
        assert!(u.ctrl_s(&mut input).is_none());
        assert_eq!(input, "half-written idea");
        input.clear();
        u.stash.stash("a", 0);
        u.stash.stash("b", 0);
        u.ctrl_s(&mut input);
        assert!(u.stash.panel_open);
        assert!(u.footer(100, 40, false, 0, &sw)[0].contains("stashed drafts"));
        assert!(u.stash_key("down", &mut input));
        assert!(u.stash_key("enter", &mut input));
        assert_eq!(input, "a");
        assert!(!u.stash_key("down", &mut input), "panel closed");
        prefs::set(&p, "statusbar", json!(false)).unwrap();
        u.reload();
        assert!(u.footer(100, 40, false, 0, &sw).is_empty());
        u.turn_started();
        assert_eq!(u.pet_state(true), "review");
        u.tool(true);
        assert_eq!(u.pet_state(true), "run");
        u.prompted("approval needed", "s");
        assert_eq!(u.pet_state(true), "waiting");
        u.turn_ended("done", "s");
        assert_eq!(u.pet_state(false), "wave");
        assert!(u.last_duration.is_some());
        assert!(u.indicator(0).contains('…'));
        assert!(u.startup_tip().is_some());
    }
}
