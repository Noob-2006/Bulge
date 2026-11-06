//! Terminal UI: the same ARP client as the web UI, drawn with ANSI truecolor in
//! the shared crimson-and-gold theme (deep crimson gradients, gold four-pointed
//! concave stars ✦ that twinkle while the agent works).
//!
//! Keys: Enter send · Alt+Enter newline · Ctrl+N new session · Ctrl+P command palette
//! (`/palette`) · Ctrl+↑/↓ switch session · PgUp/PgDn scroll · y once / s this session /
//! p permanently / n deny answer an approval (`/deny <reason>` denies with a reason) ·
//! Ctrl+C stop the running turn (twice to quit) · Ctrl+Q quit. Security slash commands
//! (/yolo, /approvals, /elevated, /exec, /pause, /resume, /approve, /deny) go to the
//! daemon's `session.command`; every other slash line goes to `command.run` and its
//! `action` is applied locally ([`actions::apply_reply`]): new session, quit, redraw,
//! copy, paste/image, compose, palette, status bar and the display preferences.

// Terminal UX pieces (g2: skins, pets, status bar, dock, stash, notifications, tips).
pub mod actions;
pub mod battery;
pub mod display;
pub mod dock;
pub mod image;
pub mod indicator;
pub mod notify;
pub mod paste;
pub mod palette;
pub mod pets;
pub mod png;
pub mod prefs;
pub mod rewind;
pub mod skin;
pub mod stash;
pub mod statusbar;
pub mod tips;
pub mod ux;

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::clip;

// Theme (same tokens as ui/theme.css).
const CRIMSON: [(u8, u8, u8); 4] = [(0x0b, 0x01, 0x05), (0x1f, 0x04, 0x11), (0x3a, 0x08, 0x20), (0x5c, 0x0c, 0x2c)];
const GOLD: (u8, u8, u8) = (0xff, 0xd6, 0x6b);
const GOLD_DIM: (u8, u8, u8) = (0xc9, 0x8a, 0x1b);
const TEXT: (u8, u8, u8) = (0xf7, 0xe9, 0xec);
const DIM: (u8, u8, u8) = (0xc9, 0xa3, 0xad);
const STARS: [char; 4] = ['✦', '✧', '✶', '✧'];

fn fg(c: (u8, u8, u8)) -> String {
    format!("\x1b[38;2;{};{};{}m", c.0, c.1, c.2)
}
fn bg(c: (u8, u8, u8)) -> String {
    format!("\x1b[48;2;{};{};{}m", c.0, c.1, c.2)
}

/// Linear blend along the crimson stops, t in 0..=1.
pub fn crimson_at(t: f32) -> (u8, u8, u8) {
    let t = t.clamp(0.0, 1.0) * (CRIMSON.len() - 1) as f32;
    let i = (t.floor() as usize).min(CRIMSON.len() - 2);
    let f = t - i as f32;
    let (a, b) = (CRIMSON[i], CRIMSON[i + 1]);
    let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * f).round() as u8;
    (mix(a.0, b.0), mix(a.1, b.1), mix(a.2, b.2))
}

/// Display width: CJK and other wide characters take two cells, combining marks none.
pub fn char_width(c: char) -> usize {
    let u = c as u32;
    if u == 0 || (0x300..0x370).contains(&u) || (0x200b..0x2010).contains(&u) || (0xfe00..0xfe10).contains(&u) {
        return 0;
    }
    let wide = (0x1100..=0x115f).contains(&u)
        || (0x2e80..=0xa4cf).contains(&u)
        || (0xac00..=0xd7a3).contains(&u)
        || (0xf900..=0xfaff).contains(&u)
        || (0xfe30..=0xfe4f).contains(&u)
        || (0xff00..=0xff60).contains(&u)
        || (0xffe0..=0xffe6).contains(&u)
        || (0x1f300..=0x1faff).contains(&u)
        || (0x20000..=0x3fffd).contains(&u);
    if wide {
        2
    } else {
        1
    }
}

pub fn str_width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

/// Word-wrap to `width` cells (CJK breaks anywhere).
pub fn wrap(s: &str, width: usize) -> Vec<String> {
    let width = width.max(4);
    let mut out = Vec::new();
    for para in s.split('\n') {
        let mut line = String::new();
        let mut w = 0;
        let mut last_space: Option<(usize, usize)> = None; // (byte idx in line, width at that point)
        for c in para.chars() {
            let cw = char_width(c);
            if w + cw > width {
                if let Some((i, sw)) = last_space.filter(|_| c != ' ') {
                    let rest = line[i + 1..].to_string();
                    line.truncate(i);
                    out.push(std::mem::take(&mut line));
                    line = rest;
                    w -= sw + 1;
                } else {
                    out.push(std::mem::take(&mut line));
                    w = 0;
                }
                last_space = None;
                if c == ' ' {
                    continue;
                }
            }
            if c == ' ' {
                last_space = Some((line.len(), w));
            }
            line.push(c);
            w += cw;
        }
        out.push(line);
    }
    out
}

/// Terminal rendering of the model's Markdown: markers removed, fences dropped,
/// bullets as •. (Colour comes from the line kind; widths stay predictable.)
pub fn plain_md(s: &str) -> String {
    let mut out = Vec::new();
    let mut in_code = false;
    for line in s.lines() {
        let t = line.trim_start();
        if t.starts_with("```") {
            in_code = !in_code;
            continue;
        }
        if in_code {
            out.push(format!("  │ {line}"));
            continue;
        }
        let indent = &line[..line.len() - t.len()];
        let t = t.strip_prefix("- ").or_else(|| t.strip_prefix("* ")).map(|r| format!("• {r}")).unwrap_or_else(|| t.trim_start_matches('#').trim_start().to_string());
        out.push(format!("{indent}{}", t.replace("**", "").replace('`', "").replace("~~", "")));
    }
    out.join("\n")
}

fn fit(s: &str, width: usize) -> String {
    let mut out = String::new();
    let mut w = 0;
    for c in s.chars() {
        let cw = char_width(c);
        if w + cw > width {
            break;
        }
        out.push(c);
        w += cw;
    }
    out.push_str(&" ".repeat(width.saturating_sub(w)));
    out
}

struct Raw {
    orig: libc::termios,
    raw: libc::termios,
}

impl Raw {
    fn enter() -> std::io::Result<Raw> {
        // SAFETY: plain termios calls on stdin.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut t) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let orig = t;
            libc::cfmakeraw(&mut t);
            t.c_cc[libc::VMIN] = 0;
            t.c_cc[libc::VTIME] = 1;
            libc::tcsetattr(0, libc::TCSANOW, &t);
            print!("\x1b[?1049h\x1b[?25l\x1b[?2004h");
            let _ = std::io::stdout().flush();
            Ok(Raw { orig, raw: t })
        }
    }

    /// Hand the terminal back for `$EDITOR` (`/prompt`): cooked mode, normal screen.
    fn suspend(&self) {
        // SAFETY: restore the saved terminal state.
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &self.orig);
        }
        print!("\x1b[?2004l\x1b[?25h\x1b[?1049l\x1b[0m");
        let _ = std::io::stdout().flush();
    }

    /// Take the alternate screen and raw mode back after the editor exits.
    fn resume(&self) {
        // SAFETY: re-apply the raw termios captured in `enter`.
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &self.raw);
        }
        print!("\x1b[?1049h\x1b[?25l\x1b[?2004h\x1b[2J\x1b[3J\x1b[H");
        let _ = std::io::stdout().flush();
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        // SAFETY: restore the saved terminal state.
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &self.orig);
        }
        print!("\x1b[?2004l\x1b[?25h\x1b[?1049l\x1b[0m");
        let _ = std::io::stdout().flush();
    }
}

fn term_size() -> (usize, usize) {
    // SAFETY: TIOCGWINSZ fills a winsize struct.
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 {
            return (ws.ws_col as usize, ws.ws_row as usize);
        }
    }
    (100, 30)
}

/// One drawn transcript row: text, colour, and an optional image escape.
type Row = (String, (u8, u8, u8), Option<String>);

#[derive(Clone)]
struct Line {
    kind: &'static str,
    text: String,
    /// `HH:MM` when the line appeared (drawn when `/timestamps` is on).
    ts: String,
    /// A pre-rendered kitty/iTerm escape sequence for an inline image row.
    image: Option<String>,
}

impl Line {
    fn new(kind: &'static str, text: impl Into<String>) -> Line {
        Line { kind, text: text.into(), ts: hhmm(), image: None }
    }
    fn image(media_type: impl Into<String>, data: impl Into<String>) -> Line {
        let (media_type, data) = (media_type.into(), data.into());
        let seq = image::render(image::detect_env(), &data, &media_type, 40);
        Line { kind: "image", text: image::fallback(&media_type, &data), ts: hhmm(), image: seq }
    }
}

/// Local `HH:MM` for `/timestamps` (UTC+8, the offset the slash layer prints with).
pub fn hhmm() -> String {
    let t = seagent_kernel::util::fmt_time(seagent_kernel::util::unix_now(), 480);
    t.get(11..16).unwrap_or("").to_string()
}

/// What the TUI loop does after handling a slash reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Quit,
}

pub(crate) struct State {
    sessions: Vec<Value>,
    current: Option<String>,
    lines: Vec<Line>,
    streaming: String,
    input: String,
    scroll: usize,
    running: bool,
    pending: Vec<Value>,
    status: String,
    tick: usize,
    workspace: PathBuf,
    /// `seagent tui --yolo`: sessions used from here get session YOLO switched on.
    yolo: bool,
    yolo_on: std::collections::HashSet<String>,
    /// Status bar, dock, stash, skin, pet, notifications (tui/ux.rs).
    ux: ux::Ux,
    /// Images from `/paste` and `/image`, attached to the next message.
    attach: Vec<seagent_core::Block>,
    /// `/redraw` and `/clear`: clear the screen before the next frame.
    repaint: bool,
    /// Per-session display preferences (`<data>/display.json`).
    disp: display::Display,
    disp_at: Instant,
    /// `/prompt`: the seed the run loop must hand to `$EDITOR` (raw mode suspended).
    compose: Option<String>,
    /// Ctrl+P / `/palette`.
    palette: palette::Palette,
    /// Esc Esc: pick an earlier prompt to edit/resend or fork.
    rewind: rewind::Picker,
    /// Large pastes stored under composer markers (expanded on submit).
    pastes: Vec<paste::Paste>,
    /// Ctrl+E: show the full text of large transcript lines.
    paste_expanded: bool,
    /// Sessions whose running turn kept going after `/new` (id → title):
    /// their completion is announced when the event arrives, even from another chat.
    background: BTreeMap<String, String>,
}

impl State {
    /// Re-read this session's `/verbose`, `/timestamps`, `/focus`, `/trace`, `/footer`.
    fn reload_display(&mut self) {
        self.disp = display::load(&self.ux.paths, self.current.as_deref());
        self.disp_at = Instant::now();
    }

    /// Another surface may have changed `display.json`: pick it up once a second.
    fn tick_display(&mut self) {
        if self.disp_at.elapsed() > Duration::from_secs(1) {
            self.reload_display();
        }
    }

    /// `/statusbar`: the mode stored in `ui.json` (`top` when unset).
    fn status_mode(&self) -> statusbar::Mode {
        statusbar::Mode::from_value(&prefs::get(&self.ux.prefs, "statusbar"))
    }

    fn notice(&mut self, text: impl Into<String>) {
        self.lines.push(Line::new("notice", text));
    }
}

/// A `State` wired to a throw-away config/data directory (tests only).
#[cfg(test)]
pub(crate) fn test_state(tag: &str) -> State {
    // Removed when the test's thread ends (seagent_core::tmp::scratch).
    let ws = seagent_core::tmp::scratch(&format!("seagent-tui-{tag}"));
    let mut st = State {
        sessions: vec![],
        current: None,
        lines: vec![],
        streaming: String::new(),
        input: String::new(),
        scroll: 0,
        running: false,
        pending: vec![],
        status: String::new(),
        tick: 0,
        workspace: ws.clone(),
        yolo: false,
        yolo_on: Default::default(),
        ux: ux::Ux::new(&ws),
        attach: vec![],
        repaint: false,
        disp: display::Display::default(),
        disp_at: Instant::now(),
        compose: None,
        palette: palette::Palette::default(),
        rewind: rewind::Picker::default(),
        pastes: vec![],
        paste_expanded: false,
        background: BTreeMap::new(),
    };
    st.ux.paths = prefs::test_paths(tag);
    st.ux.reload();
    st.reload_display();
    st
}

/// Slash commands the daemon answers through `session.command` (secgate `chat_command`).
pub const SECURITY_COMMANDS: &[&str] = &["approve", "deny", "yolo", "approvals", "elevated", "elev", "exec", "pause", "resume"];

/// Is `line` one of the security slash commands?
pub fn is_security_command(line: &str) -> bool {
    line.trim().strip_prefix('/').and_then(|r| r.split_whitespace().next()).is_some_and(|n| SECURITY_COMMANDS.contains(&n.split('@').next().unwrap_or(n).to_ascii_lowercase().as_str()))
}

/// Approval keys: y once · s/a this session · p permanently · n deny.
pub fn key_answer(c: char) -> Option<&'static str> {
    Some(match c {
        'y' => "once",
        's' | 'a' => "session",
        'p' => "permanent",
        'n' => "deny",
        _ => return None,
    })
}

enum In {
    Event(Value),
    Gone(String),
}

fn call(sock: &Path, m: &str, p: Value) -> Result<Value, String> {
    seagent_kernel::daemon::call(sock, m, p)
}

fn load_history(sock: &Path, st: &mut State) {
    st.lines.clear();
    st.streaming.clear();
    let Some(id) = st.current.clone() else { return };
    if let Ok(v) = call(sock, "session.view", json!({"id": id})) {
        st.running = v["running"].as_bool().unwrap_or(false);
        for m in v["messages"].as_array().into_iter().flatten() {
            push_message(st, m);
        }
    }
}

fn push_message(st: &mut State, m: &Value) {
    let role = m["role"].as_str().unwrap_or("");
    for b in m["content"].as_array().into_iter().flatten() {
        match (b["type"].as_str(), role) {
            (Some("text"), "user") => st.lines.push(Line::new("user", b["text"].as_str().unwrap_or(""))),
            (Some("text"), _) => st.lines.push(Line::new("assistant", b["text"].as_str().unwrap_or(""))),
            (Some("tool_use"), _) => st.lines.push(Line::new("tool", format!("⚙ {} {}", b["name"].as_str().unwrap_or(""), b["input"].to_string().chars().take(160).collect::<String>()))),
            (Some("tool_result"), _) => st.lines.push(Line::new("tool", format!("↳ {}", b["content"].as_str().unwrap_or("").lines().next().unwrap_or("").chars().take(160).collect::<String>()))),
            (Some("image"), _) => st.lines.push(Line::image(b["media_type"].as_str().unwrap_or("image/png"), b["data"].as_str().unwrap_or(""))),
            _ => {}
        }
    }
}

/// Transcript lines with the display preferences applied: `/focus` (only prompts and
/// final answers) and `/verbose` decide whether tool activity is drawn, `/trace` whether
/// daemon notice lines are.
fn visible_lines(st: &State) -> Vec<Line> {
    let last_user = st.lines.iter().rposition(|l| l.kind == "user");
    let mut out: Vec<Line> = Vec::new();
    for (i, l) in st.lines.iter().enumerate() {
        match l.kind {
            "tool" if !display::shows_tool(&st.disp, i, last_user) => continue,
            "trace" if !st.disp.trace || st.disp.focus => continue,
            _ => out.push(l.clone()),
        }
    }
    if !st.streaming.is_empty() {
        out.push(Line::new("assistant", st.streaming.clone()));
    }
    out
}

/// The footer block (dock, stash panel) and the status-bar row, both rendered by
/// `tui/ux.rs`: the bar is asked for separately so `/statusbar` can move it to the top,
/// to the bottom, or hide it.
fn footer_and_bar(st: &mut State, w: usize, h: usize) -> (Vec<String>, Option<String>) {
    if !st.ux.prefs.is_object() {
        st.ux.prefs = json!({});
    }
    let mode = st.status_mode();
    let saved = st.ux.prefs.get("statusbar").cloned();
    st.ux.prefs["statusbar"] = json!(false);
    let base = st.ux.footer(w, h, st.running, st.tick, &str_width);
    let bar = if mode == statusbar::Mode::Off {
        None
    } else {
        st.ux.prefs["statusbar"] = json!(true);
        let full = st.ux.footer(w, h, st.running, st.tick, &str_width);
        full.into_iter().nth(base.len())
    };
    match saved {
        Some(v) => st.ux.prefs["statusbar"] = v,
        None => {
            if let Some(o) = st.ux.prefs.as_object_mut() {
                o.remove("statusbar");
            }
        }
    }
    (base, bar)
}

/// Palette overlay rows: query line plus the matches around the cursor.
fn palette_rows(st: &State, w: usize) -> Vec<String> {
    let p = &st.palette;
    let sel = p.matches.get(p.cursor).copied();
    let mut out = vec![format!("{}{}{}\x1b[0m", bg(CRIMSON[2]), fg(GOLD), fit(&format!(" ✦ 指令面板 /{}▏  ↑↓ 選擇 · Enter 執行 · Esc 關閉", p.query), w))];
    for &i in p.window() {
        let item = &p.items[i];
        let (mark, colour) = if Some(i) == sel { ("▸", GOLD) } else { (" ", DIM) };
        out.push(format!("{} {} {}{}\x1b[0m", bg(if Some(i) == sel { CRIMSON[2] } else { CRIMSON[1] }), fg(colour), fg(if Some(i) == sel { GOLD } else { TEXT }), fit(&format!(" {mark} {}", item.row()), w.saturating_sub(1))));
    }
    if p.matches.is_empty() {
        out.push(format!("{}{}{}\x1b[0m", bg(CRIMSON[1]), fg(DIM), fit("   沒有符合的指令", w)));
    }
    out
}

/// Rewind overlay rows: title, newest-first prompts around the cursor, the selected
/// prompt's preview and the key hint.
fn rewind_rows(st: &State, w: usize) -> Vec<String> {
    let p = &st.rewind;
    let mut out = vec![format!("{}{}{}\x1b[0m", bg(CRIMSON[2]), fg(GOLD), fit(" ✦ 回到先前的提問 · ↑↓ 選擇 · Enter 編輯重送 · f 從此分支 · Esc 關閉", w))];
    for i in p.window(8) {
        let item = &p.prompts[i];
        let sel = i == p.cursor;
        let mark = if sel { "▸" } else { " " };
        let row = format!(" {mark} {}. {}", item.turn, item.first_line());
        out.push(format!("{} {}{}\x1b[0m", bg(if sel { CRIMSON[2] } else { CRIMSON[1] }), fg(if sel { GOLD } else { TEXT }), fit(&row, w.saturating_sub(1))));
    }
    if let Some(item) = p.selected() {
        for line in item.text.lines().take(3).skip(1) {
            out.push(format!("{}   {}{}", bg(CRIMSON[1]), fg(DIM), fit(&format!("│ {line}"), w.saturating_sub(2))));
        }
    }
    out
}

fn draw(st: &mut State) -> String {
    let (w, h) = term_size();
    let side = if w >= 90 { 28 } else { 0 };
    let main_w = w - side;
    let mut o = String::new();
    if st.repaint {
        o.push_str("\x1b[2J\x1b[3J");
        st.repaint = false;
    }
    o.push_str("\x1b[H");
    // Header: crimson gradient left→right with the gold star mark.
    let star = if st.running { STARS[st.tick % STARS.len()] } else { '✦' };
    let title = st.current.as_ref().and_then(|c| st.sessions.iter().find(|s| s["id"] == c.as_str())).and_then(|s| s["title"].as_str()).unwrap_or("新對話");
    let status = if st.running { st.ux.indicator(st.tick) } else { st.status.clone() };
    let head = format!(" {star} seagent  ·  {title}");
    let head_line = format!("{}{}", fit(&head, w.saturating_sub(str_width(&status) + 2)), status);
    for (i, c) in fit(&head_line, w).chars().enumerate() {
        let t = i as f32 / w.max(1) as f32;
        let colour = if c == star || STARS.contains(&c) || i < 8 { GOLD } else { TEXT };
        o.push_str(&format!("{}{}{c}", bg(crimson_at(0.9 - t * 0.7)), fg(colour)));
    }
    o.push_str("\x1b[0m\r\n");
    let mode = st.status_mode();
    let disp_footer = st.disp.footer || st.ux.stash.panel_open;
    let (mut footer, bar) = if disp_footer { footer_and_bar(st, w, h) } else { (vec![], None) };
    // Ctrl+P / `/palette`: the overlay sits above the composer, under the conversation.
    if st.palette.open {
        let mut pal = palette_rows(st, w);
        pal.extend(footer);
        footer = pal;
    }
    // Esc Esc: earlier prompts, above the composer (like the palette).
    if st.rewind.open {
        let mut rw = rewind_rows(st, w);
        rw.extend(footer);
        footer = rw;
    }
    if mode == statusbar::Mode::Top {
        if let Some(b) = &bar {
            o.push_str(b);
            o.push_str("\r\n");
        }
    }
    let body_h = h.saturating_sub(5 + footer.len() + bar.is_some() as usize);
    let (pet_w, pet) = st.ux.overlay(st.running);
    // Conversation, wrapped and scrolled.
    let mut rendered: Vec<Row> = Vec::new();
    let all: Vec<Line> = visible_lines(st);
    for l in &all {
        let (prefix, colour) = match l.kind {
            "user" => ("你 ▸ ", GOLD),
            "assistant" => ("✦ ", TEXT),
            "tool" => ("  ", DIM),
            "image" => ("▣ ", GOLD_DIM),
            _ => ("  ", DIM),
        };
        let prefix = if st.disp.timestamps && !l.ts.is_empty() && l.kind != "tool" { format!("[{}] {prefix}", l.ts) } else { prefix.to_string() };
        let text = match l.kind {
            "assistant" => plain_md(&l.text),
            "user" => paste::display(&l.text, st.paste_expanded),
            _ => l.text.clone(),
        };
        for (i, piece) in wrap(&text, main_w.saturating_sub(4)).into_iter().enumerate() {
            rendered.push((format!("{}{piece}", if i == 0 { prefix.as_str() } else { "  " }), colour, if i == 0 { l.image.clone() } else { None }));
        }
        rendered.push((String::new(), TEXT, None));
    }
    for p in &st.pending {
        let line = if p["kind"] == "approval" { format!("✦ 需要核准 [{}] {} — {}   (y 允許一次 · s 本次對話都允許 · p 永久允許 · n 拒絕 · /deny 理由)", p["gate"].as_str().unwrap_or(""), p["tool"].as_str().unwrap_or(""), p["reason"].as_str().unwrap_or("")) } else { format!("✦ seagent 想問：{}   (在下方輸入回答)", p["question"].as_str().unwrap_or("")) };
        for piece in wrap(&line, main_w.saturating_sub(4)) {
            rendered.push((piece, GOLD, None));
        }
    }
    let end = rendered.len().saturating_sub(st.scroll);
    let start = end.saturating_sub(body_h);
    let visible = &rendered[start..end];
    for row in 0..body_h {
        // Sidebar with a vertical crimson gradient.
        if side > 0 {
            let t = row as f32 / body_h.max(1) as f32;
            o.push_str(&bg(crimson_at(0.55 - t * 0.45)));
            let text = st.sessions.get(row).map(|s| {
                let mark = if s["running"] == true { '✦' } else { ' ' };
                let cur = st.current.as_deref() == s["id"].as_str();
                (format!("{}{mark} {}", if cur { "▌" } else { " " }, s["title"].as_str().or(s["id"].as_str()).unwrap_or("")), cur)
            });
            match text {
                Some((t, cur)) => o.push_str(&format!("{}{}", fg(if cur { GOLD } else { DIM }), fit(&t, side))),
                None => o.push_str(&" ".repeat(side)),
            }
        }
        o.push_str(&bg(if st.ux.is_default_skin() { CRIMSON[0] } else { st.ux.pal.bg }));
        let pet_row = pet.get(row).filter(|_| pet_w + 4 < main_w);
        let text_w = if pet_row.is_some() { main_w - 1 - pet_w - 1 } else { main_w - 1 };
        match visible.get(row) {
            Some((t, c, seq)) => {
                if let Some(seq) = seq {
                    o.push_str(seq);
                }
                o.push_str(&format!("{} {}", fg(*c), fit(t, text_w)));
            }
            None => o.push_str(&" ".repeat(text_w + 1)),
        }
        if let Some(p) = pet_row {
            o.push_str(&format!(" {p}"));
        }
        o.push_str("\x1b[0m\r\n");
    }
    for l in &footer {
        o.push_str(l);
        o.push_str("\r\n");
    }
    // Composer with gold corner stars.
    let rule = |l: char, r: char| format!("{}{}{l}{}{r}\x1b[0m", bg(CRIMSON[1]), fg(GOLD), "─".repeat(w.saturating_sub(2)));
    o.push_str(&rule('✦', '✦'));
    o.push_str("\r\n");
    let shown: String = {
        let all: Vec<char> = st.input.replace('\n', "↵").chars().collect();
        let mut s = String::new();
        let mut width = 0;
        for c in all.iter().rev() {
            width += char_width(*c);
            if width > w.saturating_sub(6) {
                break;
            }
            s.insert(0, *c);
        }
        s
    };
    let shown = if shown.is_empty() { format!("{}{}", fg(DIM), fit(&st.ux.placeholder(), w.saturating_sub(6))) } else { shown };
    let prompt = st.ux.skin.prompt_symbol();
    o.push_str(&format!("{}{} {}{}{}{}▏\x1b[0m\r\n", bg(CRIMSON[1]), fg(if st.ux.is_default_skin() { GOLD } else { st.ux.pal.accent }), prompt, fg(TEXT), shown, fg(GOLD)));
    if st.disp.footer {
        let mut hint = String::from(" Enter 送出 · Alt+Enter 換行 · Ctrl+P 指令面板 · Ctrl+S 暫存 · Ctrl+N 新對話 · Ctrl+↑↓ 切換 · Ctrl+C 停止 · Ctrl+Q 離開");
        if !st.attach.is_empty() {
            hint = format!(" 📎 {} 張圖片待送出 ·{hint}", st.attach.len());
        }
        if let display::Verbose::Off | display::Verbose::New = st.disp.verbose {
            hint = format!("{}  [verbose {}]", hint, st.disp.verbose.as_str());
        }
        o.push_str(&format!("{}{}{}", bg(CRIMSON[1]), fg(GOLD_DIM), fit(&hint, w)));
        o.push_str("\x1b[0m\r\n");
    }
    if mode == statusbar::Mode::Bottom {
        if let Some(b) = &bar {
            o.push_str(b);
            o.push_str("\r\n");
        }
    }
    o
}

/// Esc Esc: load the current session's replayable prompts into the picker.
fn open_rewind(st: &mut State, rpc: &mut dyn FnMut(&str, Value) -> Result<Value, String>) {
    if st.rewind.open {
        st.rewind.close();
        return;
    }
    let Some(id) = st.current.clone() else {
        st.status = "還沒有提問可以回到".into();
        return;
    };
    if st.running {
        st.status = "這一輪還在跑 — 先 /stop 再回來".into();
        return;
    }
    match rpc("session.view", json!({"id": id})) {
        Ok(v) => {
            let messages = v["messages"].as_array().cloned().unwrap_or_default();
            if st.rewind.open(&messages) {
                st.status = format!("回到先前的提問 · {} 則", st.rewind.prompts.len());
            } else {
                st.status = "沒有可以重送的純文字提問".into();
            }
        }
        Err(e) => st.status = format!("⚠ {e}"),
    }
}

/// Enter (`fork = false`) rewinds to just before the picked prompt and prefills it;
/// `f` (`fork = true`) branches a new session from that point and prefills it there.
fn rewind_apply(st: &mut State, fork: bool, rpc: &mut dyn FnMut(&str, Value) -> Result<Value, String>) -> Flow {
    let Some(p) = st.rewind.selected().cloned() else {
        st.rewind.close();
        return Flow::Continue;
    };
    let n = st.rewind.rewind_turns();
    st.rewind.close();
    let before = st.current.clone();
    let flow = submit(st, if fork { format!("/branch --at {n}") } else { format!("/undo {n}") }, rpc);
    if flow == Flow::Quit {
        return flow;
    }
    if !fork {
        actions::reload_current(st, rpc);
        st.input = p.text;
        st.status = format!("已回到提問 {}（編輯後按 Enter 重送）", p.turn);
    } else if st.current != before {
        st.input = p.text;
        st.status = format!("已從提問 {} 分支（編輯後按 Enter 送出）", p.turn);
    }
    st.scroll = 0;
    Flow::Continue
}

/// Run the TUI against the daemon at `sock`. `workspace` = cwd for new sessions.
pub fn run(sock: &Path, workspace: &Path, yolo: bool) -> Result<(), String> {
    call(sock, "ping", json!({}))?;
    let mut st = State {
        sessions: vec![],
        current: None,
        lines: vec![],
        streaming: String::new(),
        input: String::new(),
        scroll: 0,
        running: false,
        pending: vec![],
        status: if yolo { "已連線 · ⚠ YOLO".into() } else { "已連線".into() },
        tick: 0,
        workspace: workspace.to_path_buf(),
        yolo,
        yolo_on: Default::default(),
        ux: ux::Ux::new(workspace),
        attach: vec![],
        repaint: true,
        disp: display::Display::default(),
        disp_at: Instant::now(),
        compose: None,
        palette: palette::Palette::default(),
        rewind: rewind::Picker::default(),
        pastes: vec![],
        paste_expanded: false,
        background: BTreeMap::new(),
    };
    st.sessions = call(sock, "session.list", json!({"limit": 200}))?.as_array().cloned().unwrap_or_default();
    st.current = st.sessions.first().and_then(|s| s["id"].as_str()).map(str::to_string);
    st.reload_display();
    load_history(sock, &mut st);
    if let Some(tip) = st.ux.startup_tip() {
        st.notice(tip);
    }
    st.pending = call(sock, "gate.pending", json!({})).ok().and_then(|v| v.as_array().cloned()).unwrap_or_default();
    let (tx, rx) = mpsc::channel::<In>();
    let s2 = sock.to_path_buf();
    std::thread::spawn(move || {
        let r = seagent_kernel::daemon::stream(&s2, "events.subscribe", json!({}), |v| tx.send(In::Event(v.clone())).is_ok());
        let _ = tx.send(In::Gone(r.err().unwrap_or_else(|| "daemon closed the stream".into())));
    });
    let raw = Raw::enter().map_err(|e| format!("terminal: {e}"))?;
    // Every slash reply, session call and palette query goes through this one closure.
    let mut rpc = |m: &str, p: Value| call(sock, m, p);
    let mut out = std::io::stdout();
    let mut last_ctrl_c: Option<Instant> = None;
    let mut last_esc: Option<Instant> = None;
    let mut buf = [0u8; 256];
    let mut esc: Vec<u8> = Vec::new();
    loop {
        st.tick += 1;
        while let Ok(m) = rx.try_recv() {
            match m {
                In::Event(v) => on_event(sock, &mut st, &v),
                In::Gone(e) => st.status = format!("與 daemon 斷線：{e}"),
            }
        }
        st.tick_display();
        let cur = st.current.clone();
        st.ux.tick(&|m, p| call(sock, m, p), cur.as_deref());
        // `/prompt`, `/compose`: give the terminal back to $EDITOR, then take it again.
        if let Some(seed) = st.compose.take() {
            raw.suspend();
            match clip::compose(&seed) {
                Ok(t) => {
                    st.input = t;
                    st.status = "已從編輯器取回訊息（Enter 送出）".into();
                }
                Err(e) => st.status = format!("⚠ {e}"),
            }
            raw.resume();
            st.repaint = true;
        }
        let _ = out.write_all(draw(&mut st).as_bytes());
        let _ = out.flush();
        let n = std::io::stdin().read(&mut buf).unwrap_or(0);
        if n == 0 {
            std::thread::sleep(Duration::from_millis(30));
            continue;
        }
        esc.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&esc).into_owned();
        // Wait for the rest of a split multi-byte character or escape sequence.
        if text.ends_with('\u{fffd}') && esc.len() < 8 {
            continue;
        }
        esc.clear();
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            // The palette takes every key but Esc/arrows (handled with the escape parser).
            if st.palette.open && c != '\x1b' {
                match c {
                    '\x11' => return Ok(()),
                    '\r' | '\n' => {
                        if palette_run(&mut st, &mut rpc) == Flow::Quit {
                            return Ok(());
                        }
                    }
                    '\x7f' | '\x08' => st.palette.pop(),
                    '\x10' | '\x03' => st.palette.close(),
                    c if !c.is_control() => st.palette.push(c),
                    _ => {}
                }
                continue;
            }
            // The rewind picker takes plain keys; arrows/Esc go through the escape parser.
            if st.rewind.open && c != '\x1b' {
                match c {
                    '\x11' | '\x03' | '\x10' => st.rewind.close(),
                    '\r' | '\n' => {
                        if rewind_apply(&mut st, false, &mut rpc) == Flow::Quit {
                            return Ok(());
                        }
                    }
                    'f' | 'F' if rewind_apply(&mut st, true, &mut rpc) == Flow::Quit => return Ok(()),
                    'f' | 'F' => {}
                    _ => {}
                }
                continue;
            }
            match c {
                '\x11' => return Ok(()),
                '\x03' => {
                    if st.running {
                        if let Some(id) = &st.current {
                            let _ = call(sock, "session.interrupt", json!({"id": id}));
                        }
                    } else if last_ctrl_c.is_some_and(|t| t.elapsed() < Duration::from_secs(2)) {
                        return Ok(());
                    } else {
                        st.status = "再按一次 Ctrl+C 離開".into();
                    }
                    last_ctrl_c = Some(Instant::now());
                }
                // Ctrl+P: the fuzzy command palette (same overlay as `/palette`).
                '\x10' => {
                    if st.palette.open {
                        st.palette.close();
                    } else {
                        let list = call(sock, "command.list", json!({})).unwrap_or(Value::Null);
                        st.palette.open_with(palette::items(&list), "");
                    }
                }
                '\x0e' => actions::new_session(&mut st, false, &mut rpc),
                '\x13' => {
                    if let Some(note) = st.ux.ctrl_s(&mut st.input) {
                        st.status = note;
                    }
                }
                '\x14' => st.ux.toggle_dock(),
                '\r' | '\n' if st.ux.stash_key("enter", &mut st.input) => {}
                'x' if st.input.is_empty() && st.ux.stash_key("x", &mut st.input) => {}
                '\r' | '\n' => {
                    let text = std::mem::take(&mut st.input);
                    if submit(&mut st, text, &mut rpc) == Flow::Quit {
                        return Ok(());
                    }
                }
                '\x7f' | '\x08' => {
                    st.input.pop();
                }
                '\x1b' => {
                    // Two Esc bytes arriving together (the usual double-tap): open the picker.
                    if chars.peek() == Some(&'\x1b') {
                        chars.next();
                        open_rewind(&mut st, &mut rpc);
                        last_esc = None;
                        continue;
                    }
                    let seq: String = std::iter::from_fn(|| chars.next_if(|c| !c.is_ascii_alphabetic() && *c != '~')).collect();
                    let fin = chars.next().unwrap_or(' ');
                    if st.palette.open {
                        match (seq.as_str(), fin) {
                            ("[", 'A') => st.palette.move_cursor(-1),
                            ("[", 'B') => st.palette.move_cursor(1),
                            _ => st.palette.close(),
                        }
                        continue;
                    }
                    if st.rewind.open {
                        match (seq.as_str(), fin) {
                            ("[", 'A') => st.rewind.move_cursor(-1),
                            ("[", 'B') => st.rewind.move_cursor(1),
                            _ => st.rewind.close(),
                        }
                        continue;
                    }
                    let nav = match (seq.as_str(), fin) {
                        ("[", 'A') => "up",
                        ("[", 'B') => "down",
                        ("[3", '~') => "delete",
                        ("", ' ') => "esc",
                        _ => "",
                    };
                    if nav == "esc" && last_esc.is_some_and(|t| t.elapsed() < Duration::from_millis(500)) {
                        open_rewind(&mut st, &mut rpc);
                        last_esc = None;
                        continue;
                    }
                    if !nav.is_empty() && st.ux.stash_key(nav, &mut st.input) {
                        continue;
                    }
                    if nav == "esc" {
                        last_esc = Some(Instant::now());
                    }
                    match (seq.as_str(), fin) {
                        ("", '\r') => st.input.push('\n'), // Alt+Enter
                        ("[5", '~') => st.scroll += 10,
                        ("[6", '~') => st.scroll = st.scroll.saturating_sub(10),
                        ("[1;5", 'A') | ("[1;5", 'B') => {
                            let i = st.sessions.iter().position(|s| st.current.as_deref() == s["id"].as_str()).unwrap_or(0);
                            let j = if fin == 'A' { i.saturating_sub(1) } else { (i + 1).min(st.sessions.len().saturating_sub(1)) };
                            st.current = st.sessions.get(j).and_then(|s| s["id"].as_str()).map(str::to_string);
                            st.scroll = 0;
                            st.reload_display();
                            load_history(sock, &mut st);
                        }
                        ("[200", '~') => {
                            // Bracketed paste: take everything up to the end marker. A large
                            // paste stays collapsed in the composer and expands on submit.
                            let mut pasted = String::new();
                            for c in chars.by_ref() {
                                pasted.push(c);
                                if pasted.ends_with("\x1b[201~") {
                                    pasted.truncate(pasted.len() - 6);
                                    break;
                                }
                            }
                            let text = pasted.replace('\r', "\n");
                            let (shown, stored) = paste::collapse(&text, st.pastes.len() + 1);
                            if let Some(p) = stored {
                                st.pastes.push(p);
                            }
                            st.input.push_str(&shown);
                        }
                        _ => {}
                    }
                }
                // Ctrl+E: expand large pastes (composer markers and transcript rows).
                '\x05' => {
                    if st.input.contains("[pasted #") {
                        st.input = paste::expand(&st.input, &st.pastes);
                    }
                    st.paste_expanded = !st.paste_expanded;
                    st.status = if st.paste_expanded { "已展開大型貼上（Ctrl+E 收回）".into() } else { "已收回大型貼上（Ctrl+E 展開）".into() };
                }
                c if st.input.is_empty() && !st.pending.is_empty() && st.pending[0]["kind"] == "approval" && key_answer(c).is_some() => {
                    let p = st.pending.remove(0);
                    let _ = call(sock, "gate.answer", json!({"id": p["id"], "answer": key_answer(c).unwrap_or("deny")}));
                }
                c if !c.is_control() => st.input.push(c),
                _ => {}
            }
        }
    }
}

/// One submitted line: an answer to a pending question, a security command, a slash
/// command (whose `action` [`actions::apply_reply`] applies), or a message for the model.
fn submit(st: &mut State, text: String, rpc: &mut dyn FnMut(&str, Value) -> Result<Value, String>) -> Flow {
    if text.trim().is_empty() {
        return Flow::Continue;
    }
    // An open question takes the typed line as its answer.
    if let Some(i) = st.pending.iter().position(|p| p["kind"] == "question") {
        let p = st.pending.remove(i);
        let _ = rpc("gate.answer", json!({"id": p["id"], "answer": text}));
        return Flow::Continue;
    }
    if is_security_command(&text) {
        match rpc("session.command", json!({"id": st.current, "line": text.trim()})) {
            Ok(r) => st.notice(r["text"].as_str().unwrap_or("")),
            Err(e) => st.notice(format!("⚠ {e}")),
        }
        // /approve and /deny may have answered something listed here.
        st.pending = rpc("gate.pending", json!({})).ok().and_then(|v| v.as_array().cloned()).unwrap_or_default();
        st.scroll = 0;
        return Flow::Continue;
    }
    // Plugin slash commands and the built-ins run on the daemon; they may answer, hand
    // back a prompt, or ask this surface to do something (`action`).
    if text.starts_with('/') {
        if let Ok(r) = rpc("command.run", json!({"line": text, "surface": "tui", "session": st.current})) {
            if r["handled"].as_bool() == Some(true) {
                return actions::apply_reply(st, &r, rpc);
            }
        }
    }
    submit_text(st, text, rpc)
}

/// Send `text` to the current session (creating one when needed), with the pending
/// `/paste` / `/image` blocks attached.
fn submit_text(st: &mut State, text: String, rpc: &mut dyn FnMut(&str, Value) -> Result<Value, String>) -> Flow {
    // The model always gets the full paste, even though the composer shows a marker.
    let text = paste::expand(&text, &st.pastes);
    if st.current.is_none() {
        if let Ok(r) = rpc("session.create", json!({"workspace": st.workspace.display().to_string(), "title": "終端機對話"})) {
            st.current = r["id"].as_str().map(str::to_string);
            st.reload_display();
        }
    }
    if let Some(id) = st.current.clone().filter(|id| st.yolo && !st.yolo_on.contains(id)) {
        match rpc("session.command", json!({"id": id, "line": "/yolo on"})) {
            Ok(r) => st.notice(r["text"].as_str().unwrap_or("")),
            Err(e) => st.notice(format!("⚠ --yolo: {e}")),
        }
        st.yolo_on.insert(id);
    }
    if let Some(id) = st.current.clone() {
        let mut params = json!({"id": id, "text": text, "source": "tui"});
        // Messages with `/paste` / `/image` blocks go through the daemon's `submit_with`
        // method (same queue + start, plus the attachments); plain text stays on the
        // original `session.submit`.
        let mut method = "session.submit";
        if !st.attach.is_empty() {
            params["blocks"] = serde_json::to_value(&st.attach).unwrap_or_else(|_| json!([]));
            method = "session.submit_with";
        }
        match rpc(method, params) {
            Ok(_) => {
                st.running = true;
                st.pastes.clear();
                // Hermes reactions: affection aimed at the agent gets a heart (never sent to the model).
                if seagent_kernel::reactions::detect(&text).is_some() {
                    st.notice("♥");
                }
                st.attach.clear();
            }
            Err(e) => st.notice(format!("⚠ {e}")),
        }
    }
    st.scroll = 0;
    Flow::Continue
}

/// Palette Enter: run the highlighted command through the normal submit path, or — when
/// it takes arguments — put `/name ` into the composer so the user can type them.
fn palette_run(st: &mut State, rpc: &mut dyn FnMut(&str, Value) -> Result<Value, String>) -> Flow {
    let Some(item) = st.palette.selected().cloned() else {
        st.palette.close();
        return Flow::Continue;
    };
    st.palette.close();
    let line = item.invocation();
    if item.args.is_empty() {
        st.scroll = 0;
        submit(st, line, rpc)
    } else {
        st.status = format!("/{} 需要參數：{}", item.name, item.args);
        st.input = line;
        Flow::Continue
    }
}

/// `/new` while a turn runs: keep the old session's completion for later. The daemon
/// already runs the turn; this only remembers where to announce it.
pub(crate) fn background_current(st: &mut State) -> Option<String> {
    if !st.running {
        return None;
    }
    let id = st.current.clone()?;
    let title = st.sessions.iter().find(|s| s["id"].as_str() == Some(id.as_str())).and_then(|s| s["title"].as_str().or(s["id"].as_str())).unwrap_or(&id).to_string();
    st.background.insert(id.clone(), title);
    Some(id)
}

/// A `turn_end` for a session that kept running after `/new`: announce it once.
fn background_finished(st: &mut State, session: &str, reason: &str) -> Option<String> {
    let title = st.background.remove(session)?;
    let ok = matches!(reason, "done" | "idle" | "end_turn");
    let msg = format!("・背景對話「{title}」{}（{reason}）", if ok { "已完成" } else { "已結束" });
    st.notice(msg.clone());
    st.ux.background_finished(&title, session, ok);
    Some(msg)
}

fn on_event(sock: &Path, st: &mut State, v: &Value) {
    let p = &v["params"];
    match v["method"].as_str() {
        Some("delta") if p["session"].as_str() == st.current.as_deref() && p["thinking"] != true => st.streaming.push_str(p["text"].as_str().unwrap_or("")),
        Some("pending") => {
            let what = if p["kind"] == "approval" { format!("approval needed: {}", p["tool"].as_str().unwrap_or("")) } else { "question for you".to_string() };
            st.ux.prompted(&what, p["session"].as_str().unwrap_or(""));
            st.pending.push(p.clone());
        }
        Some("event") => {
            let ev = &p["event"];
            let mine = p["session"].as_str() == st.current.as_deref();
            match ev["type"].as_str() {
                Some("message") if mine => {
                    if ev["message"]["role"] == "assistant" {
                        st.streaming.clear();
                    }
                    push_message(st, &ev["message"]);
                }
                Some("turn_start") if mine => {
                    st.running = true;
                    st.ux.turn_started();
                }
                Some("tool_called") if mine => st.ux.tool(true),
                Some("tool_settled") if mine => st.ux.tool(false),
                Some("turn_end") => {
                    let reason = ev["reason"].as_str().unwrap_or("");
                    let sess = p["session"].as_str().unwrap_or("");
                    // A turn we left running behind `/new` still reports back here.
                    background_finished(st, sess, reason);
                    if mine {
                        st.running = false;
                        st.streaming.clear();
                        st.ux.turn_ended(reason, sess);
                    }
                    st.sessions = call(sock, "session.list", json!({"limit": 200})).ok().and_then(|v| v.as_array().cloned()).unwrap_or(std::mem::take(&mut st.sessions));
                }
                // Plugin/hook trace lines (`/trace` toggles them).
                Some("notice") if mine => st.lines.push(Line::new("trace", format!("· {}", ev["text"].as_str().unwrap_or("")))),
                Some("error") if mine => st.notice(format!("⚠ {}", ev["message"].as_str().unwrap_or(""))),
                _ => {}
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths_wrapping_and_gradient() {
        assert_eq!(str_width("seagent 深緋紅"), 8 + 6);
        assert_eq!(char_width('✦'), 1);
        let w = wrap("hello wonderful world", 11);
        assert_eq!(w, vec!["hello", "wonderful", "world"]);
        for l in wrap("一二三四五六七八九十", 7) {
            assert!(str_width(&l) <= 7, "{l}");
        }
        assert_eq!(fit("緋紅", 5), "緋紅 ");
        assert_eq!(plain_md("# T\nhi **b** `c`\n- x\n```rs\nfn a(){}\n```"), "T\nhi b c\n• x\n  │ fn a(){}");
        assert_eq!(crimson_at(0.0), CRIMSON[0]);
        assert_eq!(crimson_at(1.0), CRIMSON[3]);
        let mid = crimson_at(0.5);
        assert!(mid.0 > CRIMSON[1].0 && mid.0 < CRIMSON[2].0);
    }

    #[test]
    fn slash_and_message_submit_paths() {
        use std::cell::RefCell;
        use std::rc::Rc;
        let log = Rc::new(RefCell::new(Vec::<(String, Value)>::new()));
        let l = log.clone();
        let mut rpc = move |m: &str, p: Value| -> Result<Value, String> {
            l.borrow_mut().push((m.to_string(), p.clone()));
            Ok(match m {
                "command.run" => json!({"handled": true, "text": "starting over", "action": {"kind": "new_session", "clear": false}}),
                "session.create" => json!({"id": "s-new"}),
                "session.list" => json!([]),
                "session.view" => json!({"messages": [], "running": false}),
                "session.submit" => json!({"queued": true}),
                _ => json!({}),
            })
        };
        let mut st = test_state("submit");
        st.current = Some("s-old".into());
        assert_eq!(submit(&mut st, "/new".into(), &mut rpc), Flow::Continue);
        let calls = log.borrow().clone();
        assert_eq!(calls[0].0, "command.run");
        assert_eq!(calls[0].1["surface"], json!("tui"));
        assert_eq!(st.current.as_deref(), Some("s-new"), "/new adopts the created session");
        assert!(st.lines.iter().any(|l| l.text == "starting over"), "reply text is shown");
        // A plain line goes straight to the session.
        log.borrow_mut().clear();
        assert_eq!(submit(&mut st, "hello".into(), &mut rpc), Flow::Continue);
        let calls = log.borrow().clone();
        assert_eq!(calls.last().map(|c| c.0.as_str()), Some("session.submit"));
        assert_eq!(calls.last().unwrap().1["text"], json!("hello"));
        assert!(st.running);
        // `/quit --delete` ends the loop.
        let mut rpc2 = |m: &str, p: Value| -> Result<Value, String> {
            let _ = (m, p);
            Ok(json!({"handled": true, "action": {"kind": "quit", "delete": true}}))
        };
        assert_eq!(submit(&mut st, "/quit --delete".into(), &mut rpc2), Flow::Quit);
    }

    #[test]
    fn frame_applies_display_preferences() {
        let mut st = test_state("frame-disp");
        st.lines.push(Line::new("user", "問題"));
        st.lines.push(Line::new("tool", "⚙ shell ls"));
        st.lines.push(Line::new("assistant", "答案"));
        st.lines.push(Line::new("trace", "· hook ran"));
        let ts = st.lines[0].ts.clone();
        let frame = draw(&mut st);
        assert!(frame.contains("你 ▸ 問題") && frame.contains("⚙ shell ls") && frame.contains("· hook ran"));
        assert!(!frame.contains(&format!("[{ts}]")), "timestamps off by default");
        st.disp.timestamps = true;
        st.disp.focus = true;
        st.disp.trace = false;
        let frame = draw(&mut st);
        assert!(frame.contains(&format!("[{ts}] 你 ▸ 問題")), "timestamp prefix");
        assert!(!frame.contains("⚙ shell ls"), "/focus hides tool activity");
        assert!(!frame.contains("· hook ran"), "/trace off hides notices");
        st.disp.focus = false;
        st.disp.verbose = display::Verbose::Off;
        assert!(!draw(&mut st).contains("⚙ shell ls"), "/verbose off hides tool activity");
        st.disp.verbose = display::Verbose::All;
        st.disp.footer = false;
        let frame = draw(&mut st);
        assert!(frame.contains("⚙ shell ls"));
        assert!(!frame.contains("Ctrl+Q 離開"), "/footer off hides the hint line");
    }

    #[test]
    fn frame_places_the_status_bar_and_the_palette() {
        let mut st = test_state("frame-bar");
        st.tick = 3;
        let top = draw(&mut st);
        assert!(top.contains("ctx —"), "the bar is drawn by default (top)");
        // The bar row comes before the conversation/composer when it sits at the top.
        let bar_at = top.find("ctx —").unwrap();
        let composer_at = top.find("Enter 送出").unwrap();
        assert!(bar_at < composer_at, "top bar sits above the composer");
        // …and last when it sits at the bottom.
        st.ux.prefs["statusbar"] = json!("bottom");
        let bottom = draw(&mut st);
        assert!(bottom.find("ctx —").unwrap() > bottom.find("Enter 送出").unwrap(), "bottom bar sits under the composer");
        st.ux.prefs["statusbar"] = json!("off");
        assert!(!draw(&mut st).contains("ctx —"), "off hides it");
        // The palette overlay lists the daemon's commands.
        st.palette.open_with(palette::items(&json!([{"name": "redraw", "args": "", "description": "Force a full repaint", "category": "Session"}])), "");
        let frame = draw(&mut st);
        assert!(frame.contains("指令面板") && frame.contains("/redraw"), "palette rows are rendered");
    }

    #[test]
    fn transcript_draws_image_fallback_and_collapsed_paste() {
        let mut st = test_state("frame-media");
        let big = "line\n".repeat(paste::MAX_LINES + 2);
        st.lines.push(Line::new("user", big.clone()));
        st.lines.push(Line::image("image/png", "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg=="));
        let frame = draw(&mut st);
        assert!(frame.contains("[image image/png ·"), "the image has a readable row");
        assert!(frame.contains("[pasted "), "a large paste is collapsed in the transcript");
        st.paste_expanded = true;
        let expanded = draw(&mut st);
        assert!(!expanded.contains("[pasted "), "Ctrl+E expands it");
    }

    #[test]
    fn submitting_a_collapsed_paste_sends_the_full_text() {
        use std::cell::RefCell;
        use std::rc::Rc;
        let got = Rc::new(RefCell::new(String::new()));
        let g = got.clone();
        let mut rpc = move |m: &str, p: Value| -> Result<Value, String> {
            if m == "session.submit" {
                *g.borrow_mut() = p["text"].as_str().unwrap_or("").to_string();
            }
            Ok(json!({}))
        };
        let mut st = test_state("paste-submit");
        st.current = Some("s1".into());
        let big = "x".repeat(paste::MAX_CHARS + 10);
        let (marker, stored) = paste::collapse(&big, 1);
        st.pastes.push(stored.unwrap());
        assert_eq!(submit_text(&mut st, format!("look: {marker}"), &mut rpc), Flow::Continue);
        assert_eq!(*got.borrow(), format!("look: {big}"), "the marker is expanded, not sent literally");
        assert!(st.pastes.is_empty(), "the stored copy is released after a successful submit");
    }

    #[test]
    fn rewind_picker_undoes_to_the_picked_prompt_and_prefills_it() {
        use std::cell::RefCell;
        use std::rc::Rc;
        let lines = Rc::new(RefCell::new(Vec::<String>::new()));
        let l = lines.clone();
        let mut rpc = move |m: &str, p: Value| -> Result<Value, String> {
            if m == "command.run" {
                l.borrow_mut().push(p["line"].as_str().unwrap_or("").to_string());
                return Ok(json!({"handled": true, "text": "rewound 2 turn(s)"}));
            }
            if m == "session.view" {
                return Ok(json!({"running": false, "messages": [{"role": "user", "content": [{"type": "text", "text": "kept"}]}]}));
            }
            Ok(json!({}))
        };
        let mut st = test_state("rewind-apply");
        st.current = Some("s1".into());
        st.rewind.prompts = vec![rewind::Prompt { turn: 2, text: "second".into() }, rewind::Prompt { turn: 1, text: "first".into() }];
        st.rewind.cursor = 1;
        st.rewind.open = true;
        assert_eq!(rewind_apply(&mut st, false, &mut rpc), Flow::Continue);
        assert_eq!(lines.borrow().as_slice(), ["/undo 2"], "the picked prompt and everything after it are cut");
        assert_eq!(st.input, "first", "the prompt is ready to edit and resend");
        assert!(!st.rewind.open);
        assert!(st.lines.iter().any(|x| x.text == "kept"), "history is reloaded after the rewind");
        assert!(st.status.contains("提問 1"));
    }

    #[test]
    fn background_turn_completion_is_announced_once() {
        let mut st = test_state("bg-done");
        st.background.insert("s1".into(), "deploy".into());
        let msg = background_finished(&mut st, "s1", "done").expect("announced");
        assert!(msg.contains("deploy") && msg.contains("已完成"), "{msg}");
        assert!(st.lines.iter().any(|l| l.text == msg), "the notice is in the transcript");
        assert!(background_finished(&mut st, "s1", "done").is_none(), "only once");
        st.background.insert("s2".into(), "failing job".into());
        assert!(background_finished(&mut st, "s2", "error").unwrap().contains("已結束"));
        // A running session becomes background on /new, then completes.
        let mut st = test_state("bg-new");
        st.current = Some("s3".into());
        st.running = true;
        assert_eq!(background_current(&mut st).as_deref(), Some("s3"));
        assert!(st.background.contains_key("s3"));
        assert!(background_finished(&mut st, "s3", "done").is_some());
        assert!(st.running, "tracking does not stop the old daemon turn");
    }

    #[test]
    fn security_commands_and_keys() {
        for l in ["/yolo", "/yolo on", " /approvals", "/deny too risky", "/approve permanent", "/exec security=deny", "/pause now", "/resume", "/YOLO@bot off"] {
            assert!(is_security_command(l), "{l}");
        }
        for l in ["/compact", "yolo", "/yolox", "/", "hello /yolo"] {
            assert!(!is_security_command(l), "{l}");
        }
        assert_eq!(key_answer('y'), Some("once"));
        assert_eq!(key_answer('s'), Some("session"));
        assert_eq!(key_answer('a'), Some("session"));
        assert_eq!(key_answer('p'), Some("permanent"));
        assert_eq!(key_answer('n'), Some("deny"));
        assert_eq!(key_answer('x'), None);
        // The daemon parses these the same way.
        for (k, want) in [('y', "once"), ('s', "session"), ('p', "permanent"), ('n', "deny")] {
            assert_eq!(seagent_security::approvals::parse_answer(key_answer(k).unwrap()).0, want);
        }
    }
}

