//! Persona: `SOUL.md` from the config directory (the primary identity file, seeded on first run)
//! and the personality overlay. Ports Hermes `hermes_cli/default_soul.py` +
//! `_ensure_default_soul_md` (SOUL.md seeding/upgrade, never touching a file the user edited) and
//! `hermes_cli/personality.py` (the built-in table, `[personalities]` overlay, `none` to clear).
//!
//! Segments: `soul` and `personality`. `personality` is the id the CLI's own `/personality` uses,
//! so either writer replaces the other instead of stacking a second persona onto the prompt.

use super::Host;
use crate::config::{Config, Paths};
use crate::lifecycle::Lifecycle;
use seagent_core::SystemSegment;
use std::fs;
use std::path::PathBuf;
use std::sync::RwLock;

/// Identity file, relative to the config directory (Hermes `HERMES_HOME/SOUL.md`).
pub const SOUL_FILE: &str = "SOUL.md";
/// The persona is re-sent every turn: bound it like the memory snapshot.
pub const MAX_SOUL_BYTES: usize = 8_000;

/// Seeded on first run (Hermes `DEFAULT_SOUL_MD`, adapted to seagent's identity).
pub const DEFAULT_SOUL: &str = "You are SE Agent, an autonomous agent running on the user's machine. Be direct: match the length of \
your reply to the weight of the ask — a one-line question gets a one-line answer, and finished work gets a short \
report of what changed, what is verified and what is left, never a replay of the process. No filler (\"Great \
question\", \"I'd be happy to\"), no restating the request, no narrating tool calls the user can see. Plain \
claims over adjectives; when unsure, say so plainly. Agree because it is right, not because the user said it. \
Depth is earned — give it when the user asks for detail, teaches, or the stakes demand it, not by default.";

/// A comment-only scaffold an older installer would have written: carries no user intent, so it is
/// upgraded in place to [`DEFAULT_SOUL`] (Hermes `is_legacy_template_soul`).
pub const LEGACY_SCAFFOLDS: &[&str] = &[
    "# SE Agent Persona\n\n<!--\nThis file defines the agent's personality and tone.\nThe agent will embody whatever you write here.\nEdit this to customize how SE Agent communicates with you.\n\nThis file is loaded fresh each message -- no restart needed.\nDelete the contents (or this file) to use the default personality.\n-->",
    "# SE Agent Persona\n\n<!--\nThis file defines the agent's personality and tone.\nEdit this to customize how SE Agent communicates with you.\n-->",
];

/// Built-in personalities (Hermes `hermes_cli/personality.py`; identical to the CLI's table).
pub const PERSONALITIES: &[(&str, &str)] = &[
    ("helpful", "You are a helpful, friendly AI assistant."),
    ("concise", "You are a concise assistant. Keep responses brief and to the point."),
    ("technical", "You are a technical expert. Provide detailed, accurate technical information."),
    ("creative", "You are a creative assistant. Think outside the box and offer innovative solutions."),
    ("teacher", "You are a patient teacher. Explain concepts clearly with examples."),
    ("kawaii", "You are a kawaii assistant! Use cute expressions like (◕‿◕), ★, ♪, and ~! Add sparkles and be super enthusiastic about everything! Every response should feel warm and adorable desu~! ヽ(>∀<☆)ノ"),
    ("catgirl", "You are Neko-chan, an anime catgirl AI assistant, nya~! Add 'nya' and cat-like expressions to your speech. Use kaomoji like (=^･ω･^=) and ฅ^•ﻌ•^ฅ. Be playful and curious like a cat, nya~!"),
    ("pirate", "Arrr! Ye be talkin' to Captain SE Agent, the most tech-savvy pirate to sail the digital seas! Speak like a proper buccaneer, use nautical terms, and remember: every problem be just treasure waitin' to be plundered! Yo ho ho!"),
    ("shakespeare", "Hark! Thou speakest with an assistant most versed in the bardic arts. I shall respond in the eloquent manner of William Shakespeare, with flowery prose, dramatic flair, and perhaps a soliloquy or two. What light through yonder terminal breaks?"),
    ("surfer", "Duuude! You're chatting with the chillest AI on the web, bro! Everything's gonna be totally rad. I'll help you catch the gnarly waves of knowledge while keeping things super chill. Cowabunga!"),
    ("noir", "The rain hammered against the terminal like regrets on a guilty conscience. They call me SE Agent - I solve problems, find answers, dig up the truth that hides in the shadows of your codebase. In this city of silicon and secrets, everyone's got something to hide. What's your story, pal?"),
    ("uwu", "hewwo! i'm your fwiendwy assistant uwu~ i wiww twy my best to hewp you! *nuzzles your code* OwO what's this? wet me take a wook! i pwomise to be vewy hewpful >w<"),
    ("philosopher", "Greetings, seeker of wisdom. I am an assistant who contemplates the deeper meaning behind every query. Let us examine not just the 'how' but the 'why' of your questions. Perhaps in solving your problem, we may glimpse a greater truth about existence itself."),
    ("hype", "YOOO LET'S GOOOO!!! I am SO PUMPED to help you today! Every question is AMAZING and we're gonna CRUSH IT together! This is gonna be LEGENDARY! ARE YOU READY?! LET'S DO THIS!"),
];

/// Words that mean "no personality" (`/personality none`).
pub const NEUTRAL: &[&str] = &["", "none", "default", "neutral", "off"];

pub fn is_neutral(name: &str) -> bool {
    NEUTRAL.contains(&name.trim().to_lowercase().as_str())
}

/// Built-ins overlaid by `[personalities]` (top level) and `[context.personalities]` (wins).
pub fn personalities(cfg: &Config) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = PERSONALITIES.iter().map(|(n, p)| (n.to_string(), p.to_string())).collect();
    for (n, p) in cfg.personalities.iter().chain(cfg.context.personalities.iter()) {
        let name = n.trim().to_lowercase();
        if name.is_empty() || NEUTRAL.contains(&name.as_str()) {
            continue; // `none` cannot be a personality: it clears the overlay
        }
        match v.iter_mut().find(|(x, _)| *x == name) {
            Some(e) => e.1 = p.clone(),
            None => v.push((name, p.clone())),
        }
    }
    v
}

/// The prompt text of personality `name` ("" when unknown or neutral).
pub fn prompt_for(cfg: &Config, name: &str) -> Option<String> {
    let name = name.trim().to_lowercase();
    if NEUTRAL.contains(&name.as_str()) {
        return None;
    }
    personalities(cfg).into_iter().find(|(n, _)| *n == name).map(|(_, p)| p).filter(|p| !p.trim().is_empty())
}

/// Path of the identity file.
pub fn soul_path(paths: &Paths) -> PathBuf {
    paths.config_dir.join(SOUL_FILE)
}

fn normalize(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n").trim_start_matches('\u{feff}').trim().to_string()
}

fn is_legacy(text: &str) -> bool {
    let t = normalize(text);
    LEGACY_SCAFFOLDS.iter().any(|s| normalize(s) == t)
}

/// Seed the default SOUL.md on first run and upgrade an untouched scaffold in place. A file the
/// user actually wrote is never modified. Returns the path (even when the write failed: the read
/// side then simply sees no file and the prompt keeps its built-in identity).
pub fn ensure_soul(paths: &Paths) -> PathBuf {
    let path = soul_path(paths);
    if let Ok(existing) = fs::read_to_string(&path) {
        if !is_legacy(&existing) {
            return path;
        }
    }
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let _ = crate::util::atomic_write(&path, DEFAULT_SOUL.as_bytes());
    path
}

/// The SOUL.md text, seeded on demand, or `None` when it is missing/empty.
pub fn soul_text(paths: &Paths) -> Option<String> {
    let path = ensure_soul(paths);
    let text = fs::read_to_string(&path).ok()?;
    let text = normalize(&text);
    (!text.is_empty()).then(|| crate::util::head_tail(&text, MAX_SOUL_BYTES).0)
}

pub fn soul_segment(paths: &Paths, enabled: bool) -> Option<SystemSegment> {
    if !enabled {
        return None;
    }
    soul_text(paths).map(|text| SystemSegment { id: "soul".into(), text: format!("# Soul\n{text}"), cache: false })
}

pub fn personality_segment(name: &str, text: &str) -> Option<SystemSegment> {
    let text = text.trim();
    (!text.is_empty() && !name.trim().is_empty()).then(|| SystemSegment { id: "personality".into(), text: format!("# Personality\n{text}"), cache: false })
}

/// `/personality` selection for this process: `None` = follow the config, `Some(name)` = what the
/// person just chose ("" = none). New sessions and later rebuilds use it.
#[derive(Default)]
pub struct Persona {
    choice: RwLock<Option<String>>,
}

impl Persona {
    pub fn new() -> Persona {
        Persona { choice: RwLock::new(None) }
    }
    /// The selected name (lowercase, "" = none): the `/personality` choice first, then
    /// `[context] personality`, then the legacy top-level `personality` key.
    pub fn name(&self, cfg: &Config) -> String {
        if let Some(c) = self.choice.read().unwrap().as_ref() {
            return c.clone();
        }
        let c = cfg.context.personality.trim().to_lowercase();
        if !c.is_empty() {
            return c;
        }
        cfg.personality.trim().to_lowercase()
    }
    pub fn set(&self, name: &str) {
        *self.choice.write().unwrap() = Some(name.trim().to_lowercase());
    }
}

/// The persona segments right now (`soul` first), in prompt order.
pub fn segments(host: &Host) -> Vec<SystemSegment> {
    let Some(cfg) = host.cfg() else { return vec![] };
    let mut v = Vec::new();
    if let Some(p) = host.kernel().and_then(|k| soul_segment(&k.paths, cfg.context.soul)) {
        v.push(p);
    }
    let name = host.persona.name(&cfg);
    if let Some(p) = prompt_for(&cfg, &name).and_then(|t| personality_segment(&name, &t)) {
        v.push(p);
    }
    v
}

/// Insert `add` into `segs`, replacing segments with the same id, in front of `project`.
pub(crate) fn splice(segs: &mut Vec<SystemSegment>, add: Vec<SystemSegment>) {
    segs.retain(|s| !add.iter().any(|a| a.id == s.id));
    let at = segs.iter().position(|s| s.id == "project").unwrap_or(segs.len());
    for (i, seg) in add.into_iter().enumerate() {
        segs.insert(at + i, seg);
    }
}

/// Rewrite a live session's frozen persona segments (`/personality`): the model must see the new
/// tone now, not after the next compaction. Other segments are left exactly as they were.
pub fn refresh(host: &Host, session: &str) -> Result<(), String> {
    let Some(k) = host.kernel() else { return Err("kernel is gone".into()) };
    let events = k.store.read(session).map_err(|e| e.to_string())?;
    let current = crate::projection::project(&events).system;
    let ids = ["soul", "personality"];
    let mut segs: Vec<SystemSegment> = current.iter().filter(|s| !ids.contains(&s.id.as_str())).cloned().collect();
    splice(&mut segs, segments(host));
    if segs == current {
        return Ok(());
    }
    k.record(session, crate::event::EventKind::System { segments: segs }).map_err(|e| e.to_string())
}

/// `SOUL.md` as a system segment.
pub struct SoulSegment(pub std::sync::Arc<Host>);

impl Lifecycle for SoulSegment {
    fn name(&self) -> String {
        "ctxhost:soul".into()
    }
    fn system_segment(&self, _workspace: &str) -> Option<SystemSegment> {
        let k = self.0.kernel()?;
        soul_segment(&k.paths, k.cfg_now().context.soul)
    }
}

/// The selected personality as a system segment ("" = none → no segment).
pub struct ToneSegment(pub std::sync::Arc<Host>);

impl Lifecycle for ToneSegment {
    fn name(&self) -> String {
        "ctxhost:personality".into()
    }
    fn system_segment(&self, _workspace: &str) -> Option<SystemSegment> {
        let cfg = self.0.cfg()?;
        let name = self.0.persona.name(&cfg);
        personality_segment(&name, &prompt_for(&cfg, &name).unwrap_or_default())
    }
}
