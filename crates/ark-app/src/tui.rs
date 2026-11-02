//! Terminal UI: the same ARP client as the web UI, drawn with ANSI truecolor in
//! the shared crimson-and-gold theme (deep crimson gradients, gold four-pointed
//! concave stars ✦ that twinkle while the agent works).
//!
//! Keys: Enter send · Alt+Enter newline · Ctrl+N new session · Ctrl+↑/↓ switch
//! session · PgUp/PgDn scroll · y / a / n answer an approval · Ctrl+C stop the
//! running turn (twice to quit) · Ctrl+Q quit.

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

// Theme (same tokens as ui/theme.css).
const CRIMSON: [(u8, u8, u8); 4] = [(0x12, 0x02, 0x0a), (0x33, 0x07, 0x16), (0x65, 0x0d, 0x27), (0x8b, 0x10, 0x32)];
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
            Ok(Raw { orig })
        }
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

#[derive(Clone)]
struct Line {
    kind: &'static str,
    text: String,
}

struct State {
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
}

enum In {
    Event(Value),
    Gone(String),
}

fn call(sock: &Path, m: &str, p: Value) -> Result<Value, String> {
    ark_kernel::daemon::call(sock, m, p)
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
            (Some("text"), "user") => st.lines.push(Line { kind: "user", text: b["text"].as_str().unwrap_or("").into() }),
            (Some("text"), _) => st.lines.push(Line { kind: "assistant", text: b["text"].as_str().unwrap_or("").into() }),
            (Some("tool_use"), _) => st.lines.push(Line { kind: "tool", text: format!("⚙ {} {}", b["name"].as_str().unwrap_or(""), b["input"].to_string().chars().take(160).collect::<String>()) }),
            (Some("tool_result"), _) => st.lines.push(Line { kind: "tool", text: format!("↳ {}", b["content"].as_str().unwrap_or("").lines().next().unwrap_or("").chars().take(160).collect::<String>()) }),
            _ => {}
        }
    }
}

fn draw(st: &State) -> String {
    let (w, h) = term_size();
    let side = if w >= 90 { 28 } else { 0 };
    let main_w = w - side;
    let mut o = String::from("\x1b[H");
    // Header: crimson gradient left→right with the gold star mark.
    let star = if st.running { STARS[st.tick % STARS.len()] } else { '✦' };
    let title = st.current.as_ref().and_then(|c| st.sessions.iter().find(|s| s["id"] == c.as_str())).and_then(|s| s["title"].as_str()).unwrap_or("新對話");
    let status = if st.running { format!("{star} 工作中") } else { st.status.clone() };
    let head = format!(" {star} ark  ·  {title}");
    let head_line = format!("{}{}", fit(&head, w.saturating_sub(str_width(&status) + 2)), status);
    for (i, c) in fit(&head_line, w).chars().enumerate() {
        let t = i as f32 / w.max(1) as f32;
        let colour = if c == star || STARS.contains(&c) || i < 8 { GOLD } else { TEXT };
        o.push_str(&format!("{}{}{c}", bg(crimson_at(0.9 - t * 0.7)), fg(colour)));
    }
    o.push_str("\x1b[0m\r\n");
    let body_h = h.saturating_sub(5);
    // Conversation, wrapped and scrolled.
    let mut rendered: Vec<(String, (u8, u8, u8))> = Vec::new();
    let all: Vec<Line> = st.lines.iter().cloned().chain((!st.streaming.is_empty()).then(|| Line { kind: "assistant", text: st.streaming.clone() })).collect();
    for l in &all {
        let (prefix, colour) = match l.kind {
            "user" => ("你 ▸ ", GOLD),
            "assistant" => ("✦ ", TEXT),
            "tool" => ("  ", DIM),
            _ => ("  ", DIM),
        };
        let text = if l.kind == "assistant" { plain_md(&l.text) } else { l.text.clone() };
        for (i, piece) in wrap(&text, main_w.saturating_sub(4)).into_iter().enumerate() {
            rendered.push((format!("{}{piece}", if i == 0 { prefix } else { "  " }), colour));
        }
        rendered.push((String::new(), TEXT));
    }
    for p in &st.pending {
        let line = if p["kind"] == "approval" { format!("✦ 需要核准 [{}] {} — {}   (y 允許一次 · a 本次都允許 · n 拒絕)", p["gate"].as_str().unwrap_or(""), p["tool"].as_str().unwrap_or(""), p["reason"].as_str().unwrap_or("")) } else { format!("✦ ark 想問：{}   (在下方輸入回答)", p["question"].as_str().unwrap_or("")) };
        for piece in wrap(&line, main_w.saturating_sub(4)) {
            rendered.push((piece, GOLD));
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
        o.push_str(&bg(CRIMSON[0]));
        match visible.get(row) {
            Some((t, c)) => o.push_str(&format!("{} {}", fg(*c), fit(t, main_w - 1))),
            None => o.push_str(&" ".repeat(main_w)),
        }
        o.push_str("\x1b[0m\r\n");
    }
    // Composer with gold corner stars.
    let bar = |l: char, r: char| format!("{}{}{l}{}{r}\x1b[0m", bg(CRIMSON[1]), fg(GOLD), "─".repeat(w.saturating_sub(2)));
    o.push_str(&bar('✦', '✦'));
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
    o.push_str(&format!("{}{} ▸ {}{}{}▏\x1b[0m\r\n", bg(CRIMSON[1]), fg(GOLD), fg(TEXT), shown, fg(GOLD)));
    o.push_str(&format!("{}{}{}", bg(CRIMSON[1]), fg(GOLD_DIM), fit(" Enter 送出 · Alt+Enter 換行 · Ctrl+N 新對話 · Ctrl+↑↓ 切換 · PgUp/PgDn 捲動 · Ctrl+C 停止 · Ctrl+Q 離開", w)));
    o.push_str("\x1b[0m");
    o
}

/// Run the TUI against the daemon at `sock`. `workspace` = cwd for new sessions.
pub fn run(sock: &Path, workspace: &Path) -> Result<(), String> {
    call(sock, "ping", json!({}))?;
    let mut st = State { sessions: vec![], current: None, lines: vec![], streaming: String::new(), input: String::new(), scroll: 0, running: false, pending: vec![], status: "已連線".into(), tick: 0, workspace: workspace.to_path_buf() };
    st.sessions = call(sock, "session.list", json!({"limit": 200}))?.as_array().cloned().unwrap_or_default();
    st.current = st.sessions.first().and_then(|s| s["id"].as_str()).map(str::to_string);
    load_history(sock, &mut st);
    st.pending = call(sock, "gate.pending", json!({})).ok().and_then(|v| v.as_array().cloned()).unwrap_or_default();
    let (tx, rx) = mpsc::channel::<In>();
    let s2 = sock.to_path_buf();
    std::thread::spawn(move || {
        let r = ark_kernel::daemon::stream(&s2, "events.subscribe", json!({}), |v| tx.send(In::Event(v.clone())).is_ok());
        let _ = tx.send(In::Gone(r.err().unwrap_or_else(|| "daemon closed the stream".into())));
    });
    let _raw = Raw::enter().map_err(|e| format!("terminal: {e}"))?;
    let mut out = std::io::stdout();
    let mut last_ctrl_c: Option<Instant> = None;
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
        let _ = out.write_all(draw(&st).as_bytes());
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
                '\x0e' => {
                    if let Ok(r) = call(sock, "session.create", json!({"workspace": st.workspace.display().to_string(), "title": "終端機對話"})) {
                        st.current = r["id"].as_str().map(str::to_string);
                        st.sessions = call(sock, "session.list", json!({"limit": 200})).ok().and_then(|v| v.as_array().cloned()).unwrap_or_default();
                        load_history(sock, &mut st);
                    }
                }
                '\r' | '\n' => {
                    let text = std::mem::take(&mut st.input);
                    submit(sock, &mut st, text);
                }
                '\x7f' | '\x08' => {
                    st.input.pop();
                }
                '\x1b' => {
                    let seq: String = std::iter::from_fn(|| chars.next_if(|c| !c.is_ascii_alphabetic() && *c != '~')).collect();
                    let fin = chars.next().unwrap_or(' ');
                    match (seq.as_str(), fin) {
                        ("", '\r') => st.input.push('\n'), // Alt+Enter
                        ("[5", '~') => st.scroll += 10,
                        ("[6", '~') => st.scroll = st.scroll.saturating_sub(10),
                        ("[1;5", 'A') | ("[1;5", 'B') => {
                            let i = st.sessions.iter().position(|s| st.current.as_deref() == s["id"].as_str()).unwrap_or(0);
                            let j = if fin == 'A' { i.saturating_sub(1) } else { (i + 1).min(st.sessions.len().saturating_sub(1)) };
                            st.current = st.sessions.get(j).and_then(|s| s["id"].as_str()).map(str::to_string);
                            st.scroll = 0;
                            load_history(sock, &mut st);
                        }
                        ("[200", '~') => {
                            // Bracketed paste: take everything up to the end marker.
                            let mut pasted = String::new();
                            for c in chars.by_ref() {
                                pasted.push(c);
                                if pasted.ends_with("\x1b[201~") {
                                    pasted.truncate(pasted.len() - 6);
                                    break;
                                }
                            }
                            st.input.push_str(&pasted.replace('\r', "\n"));
                        }
                        _ => {}
                    }
                }
                c if st.input.is_empty() && !st.pending.is_empty() && st.pending[0]["kind"] == "approval" && matches!(c, 'y' | 'a' | 'n') => {
                    let p = st.pending.remove(0);
                    let ans = match c {
                        'y' => "once",
                        'a' => "always",
                        _ => "deny",
                    };
                    let _ = call(sock, "gate.answer", json!({"id": p["id"], "answer": ans}));
                }
                c if !c.is_control() => st.input.push(c),
                _ => {}
            }
        }
    }
}

fn submit(sock: &Path, st: &mut State, text: String) {
    if text.trim().is_empty() {
        return;
    }
    // An open question takes the typed line as its answer.
    if let Some(i) = st.pending.iter().position(|p| p["kind"] == "question") {
        let p = st.pending.remove(i);
        let _ = call(sock, "gate.answer", json!({"id": p["id"], "answer": text}));
        return;
    }
    // Plugin slash commands run on the daemon; they may answer, or hand back a prompt.
    let mut text = text;
    if text.starts_with('/') {
        if let Ok(r) = call(sock, "command.run", json!({"line": text, "surface": "tui", "session": st.current})) {
            if r["handled"] == true {
                if let Some(t) = r["text"].as_str() {
                    st.lines.push(Line { kind: "notice", text: t.to_string() });
                }
                match r["prompt"].as_str() {
                    Some(p) => text = p.to_string(),
                    None => return,
                }
            }
        }
    }
    if st.current.is_none() {
        if let Ok(r) = call(sock, "session.create", json!({"workspace": st.workspace.display().to_string(), "title": "終端機對話"})) {
            st.current = r["id"].as_str().map(str::to_string);
        }
    }
    if let Some(id) = st.current.clone() {
        match call(sock, "session.submit", json!({"id": id, "text": text, "source": "tui"})) {
            Ok(_) => st.running = true,
            Err(e) => st.lines.push(Line { kind: "notice", text: format!("⚠ {e}") }),
        }
    }
    st.scroll = 0;
}

fn on_event(sock: &Path, st: &mut State, v: &Value) {
    let p = &v["params"];
    match v["method"].as_str() {
        Some("delta") if p["session"].as_str() == st.current.as_deref() && p["thinking"] != true => st.streaming.push_str(p["text"].as_str().unwrap_or("")),
        Some("pending") => st.pending.push(p.clone()),
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
                Some("turn_start") if mine => st.running = true,
                Some("turn_end") => {
                    if mine {
                        st.running = false;
                        st.streaming.clear();
                    }
                    st.sessions = call(sock, "session.list", json!({"limit": 200})).ok().and_then(|v| v.as_array().cloned()).unwrap_or(std::mem::take(&mut st.sessions));
                }
                Some("notice") if mine => st.lines.push(Line { kind: "notice", text: format!("· {}", ev["text"].as_str().unwrap_or("")) }),
                Some("error") if mine => st.lines.push(Line { kind: "notice", text: format!("⚠ {}", ev["message"].as_str().unwrap_or("")) }),
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
        assert_eq!(str_width("ark 深緋紅"), 4 + 6);
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
}
