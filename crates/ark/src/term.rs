//! Plain-text output (no TUI): streams assistant text to stdout, tool activity
//! and notices to stderr. `--json` prints raw events instead. Plus the
//! interactive gate approver that reads from /dev/tty.

use ark_core::Block;
use ark_kernel::approver::{Approval, ApprovalRequest, Approver};
use ark_kernel::event::EventKind;
use ark_kernel::kernel::BusMsg;
use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::sync::mpsc::Receiver;
use std::sync::Mutex;

pub fn color() -> bool {
    std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn dim(s: &str) -> String {
    if color() {
        format!("\x1b[2m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}
fn warn(s: &str) -> String {
    if color() {
        format!("\x1b[33m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

pub fn one_line(s: &str, max: usize) -> String {
    let flat: String = s.chars().map(|c| if c == '\n' { ' ' } else { c }).collect();
    if flat.chars().count() > max {
        format!("{}…", flat.chars().take(max).collect::<String>())
    } else {
        flat
    }
}

pub const CLOSE: &str = "\u{0}close";

/// Print bus traffic for one session until the close sentinel arrives.
pub fn render(rx: Receiver<BusMsg>, session: String, json: bool, quiet: bool) {
    let mut at_line_start = true;
    let out = std::io::stdout();
    let err = std::io::stderr();
    for msg in rx {
        if matches!(&msg, BusMsg::Delta { session: s, .. } if s == CLOSE) {
            break;
        }
        match msg {
            BusMsg::Event { session: s, event } if s == session => {
                if json {
                    let _ = writeln!(out.lock(), "{}", serde_json::to_string(&event).unwrap_or_default());
                    continue;
                }
                let line = match &event.kind {
                    EventKind::Message { message, .. } if message.role == ark_core::Role::Assistant => {
                        let calls: Vec<String> = message.content.iter().filter_map(|b| if let Block::ToolUse { name, input, .. } = b { Some(format!("→ {name} {}", one_line(&describe(name, input), 100))) } else { None }).collect();
                        if calls.is_empty() {
                            None
                        } else {
                            Some(dim(&calls.join("\n")))
                        }
                    }
                    EventKind::Message { message, .. } if !quiet => {
                        let errs: Vec<String> = message.content.iter().filter_map(|b| if let Block::ToolResult { content, is_error: true, .. } = b { Some(format!("  ✗ {}", one_line(content, 160))) } else { None }).collect();
                        (!errs.is_empty()).then(|| warn(&errs.join("\n")))
                    }
                    EventKind::Gate { gate, verdict, reason, .. } => Some(warn(&format!("⚑ {gate} gate: {verdict} — {reason}"))),
                    EventKind::Notice { level, text } if !quiet || level == "warn" => Some(warn(&format!("• {text}"))),
                    EventKind::Error { message } => Some(warn(&format!("error: {message}"))),
                    EventKind::Compaction { tokens_before, .. } if !quiet => Some(dim(&format!("• context compacted (~{tokens_before} tokens summarised)"))),
                    _ => None,
                };
                if let Some(l) = line {
                    let mut e = err.lock();
                    if !at_line_start {
                        let _ = writeln!(out.lock());
                        at_line_start = true;
                    }
                    let _ = writeln!(e, "{l}");
                }
            }
            BusMsg::Delta { session: s, text, thinking } if s == session && !json => {
                if thinking {
                    continue;
                }
                let mut o = out.lock();
                let _ = write!(o, "{text}");
                let _ = o.flush();
                at_line_start = text.ends_with('\n');
            }
            _ => {}
        }
    }
    if !at_line_start {
        println!();
    }
}

fn describe(name: &str, input: &serde_json::Value) -> String {
    let key = match name {
        "shell" => "command",
        "read" | "write" | "edit" => "path",
        "grep" | "glob" => "pattern",
        "web_fetch" => "url",
        "spawn" => "task",
        "run" => "script",
        "tool_call" | "tool_describe" => "name",
        _ => "",
    };
    input.get(key).and_then(|v| v.as_str()).map(String::from).unwrap_or_else(|| input.to_string())
}

/// Asks on the controlling terminal (works even when stdin is a pipe).
pub struct TtyApprover {
    lock: Mutex<()>,
}

impl TtyApprover {
    pub fn available() -> bool {
        std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").is_ok() && std::io::stderr().is_terminal()
    }
    pub fn new() -> Self {
        TtyApprover { lock: Mutex::new(()) }
    }
    fn prompt(&self, text: &str) -> Option<String> {
        let _g = self.lock.lock().unwrap();
        let mut tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").ok()?;
        write!(tty, "{text}").ok()?;
        tty.flush().ok()?;
        let mut line = String::new();
        BufReader::new(tty).read_line(&mut line).ok()?;
        Some(line.trim().to_string())
    }
}

impl Approver for TtyApprover {
    fn approve(&self, r: &ApprovalRequest) -> Approval {
        let gate = format!("{:?}", r.gate).to_lowercase();
        let q = format!("\n{}\n  {}: {}\n  Allow? [y] once  [a] always this session  [N] deny: ", warn(&format!("⚑ {gate} gate — {}", r.reason)), r.tool, one_line(&r.summary, 300));
        match self.prompt(&q).as_deref().map(|s| s.to_ascii_lowercase()) {
            Some(s) if s == "y" || s == "yes" => Approval::Once,
            Some(s) if s == "a" || s == "always" => Approval::Always,
            _ => Approval::Deny,
        }
    }
    fn ask(&self, _: &str, question: &str) -> Result<String, String> {
        match self.prompt(&format!("\n? {question}\n> ")) {
            Some(a) if !a.is_empty() => Ok(a),
            _ => Err("the user gave no answer".into()),
        }
    }
}
