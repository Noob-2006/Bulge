//! Terminal panes for background processes, and the `read_terminal` / `close_terminal` tools
//! (Hermes `tools/read_terminal_tool.py`, `tools/close_terminal_tool.py`).
//!
//! In Hermes the pane is the desktop app's xterm view of a `terminal(background=true)` run. seagent
//! keeps that view itself: a `job` started with `pty=true` runs under a pseudo-terminal whose
//! output feeds a line screen (scrollback + current line; carriage returns overwrite, escape
//! sequences dropped) and the job log, while terminal queries the program sends are answered by
//! [`PtyQueryResponder`] instead of blocking it. `read_terminal` reads a pane the way Hermes
//! reads xterm: no arguments = the visible screen of the newest open pane plus `total_lines`;
//! `start_line` (0 = oldest) + `count` page the scrollback. Plain (pipe) jobs are readable too,
//! line by line from their log. `close_terminal` hides a pane WITHOUT stopping the process.

use crate::exec::ptyq::PtyQueryResponder;
use seagent_core::exec::{ExecChild, ExitInfo};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Lines kept per pane (older ones stay in the job log).
pub const SCROLLBACK: usize = 5000;

/// Line screen fed with raw terminal bytes.
#[derive(Default)]
pub struct Screen {
    lines: Vec<String>,
    cur: String,
    /// The last byte was `\r`: the next printable char starts the line over.
    cr: bool,
    utf8: Vec<u8>,
    esc: Esc,
    dropped: usize,
}

#[derive(Default, PartialEq, Clone, Copy)]
enum Esc {
    #[default]
    None,
    Start,
    Csi,
    Osc,
    OscBackslash,
}

impl Screen {
    pub fn feed(&mut self, data: &[u8]) {
        let mut bytes = std::mem::take(&mut self.utf8);
        bytes.extend_from_slice(data);
        let (text, rest) = match std::str::from_utf8(&bytes) {
            Ok(s) => (s.to_string(), Vec::new()),
            Err(e) if e.error_len().is_none() => (String::from_utf8_lossy(&bytes[..e.valid_up_to()]).into_owned(), bytes[e.valid_up_to()..].to_vec()),
            Err(_) => (String::from_utf8_lossy(&bytes).into_owned(), Vec::new()),
        };
        self.utf8 = rest;
        for c in text.chars() {
            match self.esc {
                Esc::Start => {
                    self.esc = match c {
                        '[' => Esc::Csi,
                        ']' => Esc::Osc,
                        _ => Esc::None,
                    };
                    continue;
                }
                Esc::Csi => {
                    if ('\x40'..='\x7e').contains(&c) {
                        self.esc = Esc::None;
                        if c == 'K' {
                            // Erase in line (progress bars redraw with `\r…\x1b[K`).
                            self.cur.clear();
                        }
                    }
                    continue;
                }
                Esc::Osc => {
                    self.esc = match c {
                        '\x07' => Esc::None,
                        '\x1b' => Esc::OscBackslash,
                        _ => Esc::Osc,
                    };
                    continue;
                }
                Esc::OscBackslash => {
                    self.esc = if c == '\\' { Esc::None } else { Esc::Osc };
                    continue;
                }
                Esc::None => {}
            }
            match c {
                '\x1b' => self.esc = Esc::Start,
                '\n' => {
                    self.lines.push(std::mem::take(&mut self.cur));
                    self.cr = false;
                    if self.lines.len() > SCROLLBACK {
                        let cut = self.lines.len() - SCROLLBACK;
                        self.lines.drain(..cut);
                        self.dropped += cut;
                    }
                }
                '\r' => self.cr = true,
                '\x08' => {
                    self.cur.pop();
                }
                c if c.is_control() && c != '\t' => {}
                c => {
                    if self.cr {
                        self.cur.clear();
                        self.cr = false;
                    }
                    self.cur.push(c);
                }
            }
        }
    }
    /// All lines, the unfinished current one last (when non-empty).
    pub fn all(&self) -> Vec<String> {
        let mut v = self.lines.clone();
        if !self.cur.is_empty() {
            v.push(self.cur.clone());
        }
        v
    }
}

/// A PTY-backed background process.
pub struct Term {
    pub rows: u16,
    pub cols: u16,
    /// Host pid of the process under the pane (a signal path that needs no child handle).
    pid: Option<u32>,
    child: Mutex<Box<dyn ExecChild>>,
    screen: Mutex<Screen>,
    exit: Mutex<Option<ExitInfo>>,
}

impl Term {
    /// Take over a spawned PTY child: a reader thread feeds the screen and `log`, answering
    /// terminal queries on the child's stdin.
    pub fn start(child: Box<dyn ExecChild>, rows: u16, cols: u16, log: PathBuf) -> Arc<Term> {
        let pid = child.pid();
        let t = Arc::new(Term { rows, cols, pid, child: Mutex::new(child), screen: Mutex::new(Screen::default()), exit: Mutex::new(None) });
        let tt = t.clone();
        std::thread::spawn(move || {
            let mut q = PtyQueryResponder::new(rows, cols);
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&log).ok();
            let mut buf = [0u8; 8192];
            loop {
                // Poll without waiting while the child is locked: `Term::kill` takes the same
                // lock, so a read that slept inside it would make a kill queue behind it (and
                // a job kill holds the pane map, which every other pane lookup needs).
                let r = tt.child.lock().unwrap().read(&mut buf, Duration::ZERO);
                match r {
                    Ok(0) => break,
                    Ok(n) => {
                        let (out, replies) = q.process(&buf[..n]);
                        if !replies.is_empty() {
                            let _ = tt.child.lock().unwrap().write_stdin(&replies);
                        }
                        tt.screen.lock().unwrap().feed(&out);
                        if let Some(f) = f.as_mut() {
                            let _ = f.write_all(&out);
                        }
                    }
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => {
                        // Bind the answer first: an `if let` scrutinee keeps its temporary
                        // (the lock guard) alive through the else branch, which would hold
                        // the child locked for the whole sleep below.
                        let exited = tt.child.lock().unwrap().try_wait().ok().flatten().is_some();
                        if exited {
                            // Exited but the PTY stays open (a grandchild holds it): keep reading briefly.
                            let r = tt.child.lock().unwrap().read(&mut buf, Duration::from_millis(50));
                            if !matches!(r, Ok(n) if n > 0) {
                                break;
                            }
                            if let Ok(n) = r {
                                let (out, _) = q.process(&buf[..n]);
                                tt.screen.lock().unwrap().feed(&out);
                            }
                        } else {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                    }
                    Err(_) => break, // EIO: the slave side closed
                }
            }
            let tail = q.flush();
            tt.screen.lock().unwrap().feed(&tail);
            let st = loop {
                let done = tt.child.lock().unwrap().try_wait().ok().flatten();
                if let Some(s) = done {
                    break s;
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            *tt.exit.lock().unwrap() = Some(st);
        });
        t
    }
    pub fn exit(&self) -> Option<ExitInfo> {
        *self.exit.lock().unwrap()
    }
    pub fn kill(&self) {
        // The pane's own reader thread polls `child` (it needs the handle to read), so a
        // plain `lock()` parks behind it and can lose the wake-up race for seconds.
        // Retry without blocking — the reader only holds the lock for the read itself —
        // and signal the process group directly if the reader is wedged in a syscall.
        for _ in 0..200 {
            if let Ok(mut c) = self.child.try_lock() {
                c.kill(true);
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        if let Some(pid) = self.pid.filter(|p| *p > 1) {
            // The process group this pane started (Windows: its job); never pid 1.
            crate::exec::local::kill_group_now(pid as i32);
        }
    }
    pub fn lines(&self) -> Vec<String> {
        self.screen.lock().unwrap().all()
    }
}

/// What `read_terminal` can show for a process: pane, log, state and command.
pub struct Source {
    pub term: Option<Arc<Term>>,
    pub log: PathBuf,
    pub running: bool,
    pub exit: Option<i32>,
    pub command: String,
}

/// The process registry `read_terminal` consults (the `job` tool installs itself).
pub type Lookup = fn(session: &str, id: Option<u32>) -> Option<(u32, Source)>;
static LOOKUP: Mutex<Option<Lookup>> = Mutex::new(None);

pub fn set_lookup(f: Lookup) {
    *LOOKUP.lock().unwrap() = Some(f);
}

/// Hidden panes: (session, process id).
static HIDDEN: Mutex<BTreeSet<(String, u32)>> = Mutex::new(BTreeSet::new());

pub fn is_hidden(session: &str, id: u32) -> bool {
    HIDDEN.lock().unwrap().contains(&(session.to_string(), id))
}

fn log_lines(p: &Path) -> Vec<String> {
    let s = std::fs::read(p).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    let mut sc = Screen::default();
    sc.feed(s.as_bytes());
    sc.all()
}

fn lookup(session: &str, id: Option<u32>) -> Option<(u32, Source)> {
    let f = (*LOOKUP.lock().unwrap())?;
    f(session, id)
}

fn parse_id(v: Option<&Value>) -> Result<Option<u32>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_u64().map(|n| Some(n as u32)).ok_or_else(|| "process_id must be a job id".into()),
        Some(Value::String(s)) => s.trim().trim_start_matches("job").trim().parse::<u32>().map(Some).map_err(|_| format!("process_id `{s}` is not a job id (see job action=list)")),
        _ => Err("process_id must be a job id".into()),
    }
}

pub struct ReadTerminal;

impl Tool for ReadTerminal {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "read_terminal".into(),
            description: "Read a background process's terminal pane (a `job` started with pty=true, or any job's log). No args = the newest open pane's visible screen + total_lines; page scrollback with start_line (0 = oldest) + count. JSON: {process_id, total_lines, start, end, viewport_rows, cursor_row, running, text}.".into(),
            input_schema: json!({"type":"object","properties":{
                "process_id":{"type":["integer","string"],"description":"Job id (from job action=list). Omit for the newest open pane."},
                "start_line":{"type":"integer","minimum":0,"description":"0-indexed first line (0 = oldest). Omit for the visible screen."},
                "count":{"type":"integer","minimum":1,"description":"Lines to read from start_line. Defaults to the visible row count."}}}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let id = match parse_id(input.get("process_id")) {
            Ok(i) => i,
            Err(e) => return ToolOutput::err(e),
        };
        let start_line = match input.get("start_line") {
            None | Some(Value::Null) => None,
            Some(v) => match v.as_u64() {
                Some(n) => Some(n as usize),
                None => return ToolOutput::err("start_line and count must be integers."),
            },
        };
        let count = match input.get("count") {
            None | Some(Value::Null) => None,
            Some(v) => match v.as_u64() {
                Some(n) => Some((n as usize).max(1)),
                None => return ToolOutput::err("start_line and count must be integers."),
            },
        };
        let Some((pid, src)) = lookup(&ctx.session_id, id) else {
            return ToolOutput::err(match id {
                Some(i) => format!("No terminal for process {i} in this session (see job action=list)."),
                None => "No terminal is open: start one with job action=start pty=true.".into(),
            });
        };
        // Reading a pane reopens it.
        HIDDEN.lock().unwrap().remove(&(ctx.session_id.clone(), pid));
        let (lines, rows, cols) = match &src.term {
            Some(t) => (t.lines(), t.rows as usize, t.cols as usize),
            None => (log_lines(&src.log), 24, 80),
        };
        let total = lines.len();
        let n = count.unwrap_or(rows);
        let start = start_line.unwrap_or_else(|| total.saturating_sub(rows)).min(total);
        let end = (start + n).min(total);
        let text = lines[start..end].join("\n");
        let mut v = json!({
            "process_id": pid, "command": src.command, "total_lines": total, "start": start, "end": end,
            "viewport_rows": rows, "viewport_cols": cols, "cursor_row": total.saturating_sub(1), "running": src.running, "pty": src.term.is_some(), "text": text,
        });
        if let Some(c) = src.exit {
            v["exit_code"] = json!(c);
        }
        ToolOutput::ok(v.to_string())
    }
}

pub struct CloseTerminal;

impl Tool for CloseTerminal {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "close_terminal".into(),
            description: "Hide a background process's terminal pane (the process keeps running). This does NOT kill the process — it only drops the pane from view; output keeps buffering and read_terminal with its process_id reopens it. To actually stop the process, use job action=kill.".into(),
            input_schema: json!({"type":"object","properties":{
                "process_id":{"type":["integer","string"],"description":"The background job's id (from job action=list) whose pane should be closed."}},
                "required":["process_id"]}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let id = match parse_id(input.get("process_id")) {
            Ok(Some(i)) => i,
            Ok(None) => return ToolOutput::err("process_id is required (the background process whose pane to close)."),
            Err(e) => return ToolOutput::err(e),
        };
        let Some((pid, src)) = lookup(&ctx.session_id, Some(id)) else {
            return ToolOutput::err(format!("No terminal for process {id} in this session (see job action=list)."));
        };
        let newly = HIDDEN.lock().unwrap().insert((ctx.session_id.clone(), pid));
        ToolOutput::ok(json!({"process_id": pid, "closed": true, "already_closed": !newly, "running": src.running, "note": "The process keeps running; read_terminal reopens the pane, job action=kill stops it."}).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_lines_carriage_returns_and_escapes() {
        let mut s = Screen::default();
        s.feed(b"one\r\ntwo\n\x1b[32mgreen\x1b[0m\n10%\r50%\r100%\ndone \xe2\x9c");
        s.feed(b"\x93\x1b]0;title\x07!");
        assert_eq!(s.all(), ["one", "two", "green", "100%", "done ✓!"]);
        s.feed(b"\x08\x08x\n");
        assert_eq!(s.all().last().unwrap(), "done x", "backspace removes ! and ✓");
        let mut big = Screen::default();
        for i in 0..SCROLLBACK + 10 {
            big.feed(format!("{i}\n").as_bytes());
        }
        assert_eq!(big.all().len(), SCROLLBACK);
        assert_eq!(big.all()[0], "10");
    }
}
