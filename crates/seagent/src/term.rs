//! Plain-text output (no TUI): streams assistant text to stdout, tool activity
//! and notices to stderr. `--json` prints raw events instead. Plus the
//! interactive gate approver that reads from /dev/tty.

use seagent_core::Block;
use seagent_kernel::approver::{Approval, ApprovalRequest, Approver};
use seagent_kernel::config::Paths;
use seagent_kernel::event::EventKind;
use seagent_kernel::i18n;
use seagent_kernel::kernel::BusMsg;
use serde_json::Value;
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

/// What may be printed from a streamed response: recalled memory blocks straddle deltas, so
/// partial tags are held back and span interiors dropped (Hermes `StreamingContextScrubber`).
#[derive(Default)]
pub struct Visible(seagent_memory::fence::StreamScrubber);

impl Visible {
    pub fn feed(&mut self, delta: &str) -> String {
        self.0.feed(delta)
    }
    /// End of stream: emit (or drop) whatever was held back.
    pub fn flush(&mut self) -> String {
        self.0.flush()
    }
}

/// `/verbose` level (upstream Hermes tool-progress display): `off` = no tool activity,
/// `new` = one line per tool call, `all` = calls plus results/status, `verbose` = also
/// every notice/event detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbose {
    Off,
    New,
    All,
    Full,
}

impl Verbose {
    pub fn parse(level: Option<&str>) -> Verbose {
        match level {
            Some("off") => Verbose::Off,
            Some("all") => Verbose::All,
            Some("verbose") => Verbose::Full,
            _ => Verbose::New,
        }
    }

    /// The spelling `/verbose` accepts. Only the tests read it back.
    #[cfg(test)]
    pub fn name(self) -> &'static str {
        match self {
            Verbose::Off => "off",
            Verbose::New => "new",
            Verbose::All => "all",
            Verbose::Full => "verbose",
        }
    }
}

/// Display preferences for the plain-text printer, snapshotted per turn from
/// `<data>/display.json` ([`crate::slash::display_get`]): `/timestamps`, `/verbose`,
/// `/focus`, `/trace`, `/reasoning`. None of it is process-global, so two sessions (or a
/// channel and the CLI) printing at the same time keep their own settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefs {
    pub timestamps: bool,
    pub verbose: Verbose,
    /// `/focus`: only the prompt and the final answer.
    pub focus: bool,
    /// `/trace`: `[trace] …` lines for every kernel event (plugin/hook activity included).
    pub trace: bool,
    /// `/reasoning`: stream thinking deltas.
    pub reasoning: bool,
    /// `--quiet`: warnings and errors only.
    pub quiet: bool,
    /// The session's UTC offset (minutes), used for `[HH:MM]`.
    pub utc_offset: i32,
}

impl Default for Prefs {
    fn default() -> Prefs {
        // No `/verbose` stored yet: one line per tool call, as the CLI has always shown.
        Prefs { timestamps: false, verbose: Verbose::New, focus: false, trace: false, reasoning: false, quiet: false, utc_offset: 480 }
    }
}

impl Prefs {
    /// The session's stored preferences, as `/timestamps` etc. wrote them.
    pub fn for_session(paths: &Paths, session: &str) -> Prefs {
        Prefs::from_display(&crate::slash::display_get(paths, session))
    }
    pub fn from_display(d: &Value) -> Prefs {
        Prefs {
            timestamps: d["timestamps"] == Value::Bool(true),
            verbose: Verbose::parse(d["verbose"].as_str()),
            focus: d["focus"] == Value::Bool(true),
            trace: d["trace"] == Value::Bool(true),
            reasoning: d["reasoning"] == Value::Bool(true),
            ..Prefs::default()
        }
    }
    pub fn quiet(mut self, quiet: bool) -> Prefs {
        self.quiet = quiet;
        self
    }
    pub fn offset(mut self, utc_offset_minutes: i32) -> Prefs {
        self.utc_offset = utc_offset_minutes;
        self
    }
}

/// `HH:MM` for `/timestamps` (the session's offset, not the process's locale).
fn hhmm(utc_offset: i32) -> String {
    seagent_kernel::util::fmt_time(seagent_kernel::util::unix_now(), utc_offset).get(11..16).unwrap_or_default().to_string()
}

/// `[HH:MM] ` before every line of an event line.
fn stamp_lines(stamp: &str, text: &str) -> String {
    text.split('\n').map(|l| format!("[{stamp}] {l}")).collect::<Vec<_>>().join("\n")
}

/// `[HH:MM] ` before every line of a streamed delta (`at_line_start` carries across chunks).
fn stamp_text(prefs: &Prefs, text: &str, at_line_start: bool) -> String {
    if !prefs.timestamps {
        return text.to_string();
    }
    let stamp = hhmm(prefs.utc_offset);
    let mut out = String::with_capacity(text.len() + 8);
    let mut start = at_line_start;
    for ch in text.chars() {
        if start {
            out.push_str(&format!("[{stamp}] "));
            start = false;
        }
        out.push(ch);
        if ch == '\n' {
            start = true;
        }
    }
    out
}

/// Print bus traffic for one session until the close sentinel arrives.
pub fn render(rx: Receiver<BusMsg>, session: String, json: bool, quiet: bool) {
    render_with(rx, session, json, &Prefs::default().quiet(quiet))
}

/// [`render`] with the session's display preferences (`/timestamps`, `/verbose`,
/// `/focus`, `/trace`, `/reasoning`); `main.rs` snapshots them per turn.
pub fn render_with(rx: Receiver<BusMsg>, session: String, json: bool, prefs: &Prefs) {
    let mut at_line_start = true;
    let mut scrub = Visible::default();
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
                let lines = lines_for(&event.kind, prefs);
                if lines.is_empty() {
                    continue;
                }
                let mut e = err.lock();
                if !at_line_start {
                    let _ = writeln!(out.lock());
                    at_line_start = true;
                }
                for l in lines {
                    let _ = writeln!(e, "{l}");
                }
            }
            BusMsg::Delta { session: s, text, thinking } if s == session && !json => {
                if thinking {
                    // `/reasoning on` streams the model's thinking; `/focus` hides it.
                    if prefs.reasoning && !prefs.focus {
                        let _ = write!(std::io::stderr(), "\x1b[2m{text}\x1b[0m");
                    }
                    continue;
                }
                let text = scrub.feed(&text);
                if text.is_empty() {
                    continue;
                }
                let text = stamp_text(prefs, &text, at_line_start);
                let mut o = out.lock();
                let _ = write!(o, "{text}");
                let _ = o.flush();
                at_line_start = text.ends_with('\n');
            }
            _ => {}
        }
    }
    let tail = scrub.flush();
    if !tail.is_empty() {
        let tail = stamp_text(prefs, &tail, at_line_start);
        let mut o = out.lock();
        let _ = write!(o, "{tail}");
        at_line_start = tail.ends_with('\n');
    }
    if !at_line_start {
        println!();
    }
}

/// Everything `render` prints on stderr for one event: the plain-text event line, plus the
/// `[trace] …` line when `/trace` is on. Testable without touching stdout.
pub fn lines_for(kind: &EventKind, prefs: &Prefs) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(l) = event_line_with(kind, prefs) {
        out.push(l);
    }
    if prefs.trace {
        out.push(trace_line(kind, prefs));
    }
    out
}

/// One stderr line for an event, or `None` when the event has no plain-text form. The
/// prefixes are localized (`notice.*` catalog keys, `display.language`).
/// [`event_line_with`] with default preferences. `render` always goes through the session-preferences
/// form, so this shorthand only exists for the tests.
#[cfg(test)]
pub fn event_line(kind: &EventKind, quiet: bool) -> Option<String> {
    event_line_with(kind, &Prefs::default().quiet(quiet))
}

/// [`event_line`] with the session's `/verbose`, `/focus` and `/timestamps` preferences.
pub fn event_line_with(kind: &EventKind, prefs: &Prefs) -> Option<String> {
    event_body(kind, prefs).map(|l| if prefs.timestamps { stamp_lines(&hhmm(prefs.utc_offset), &l) } else { l })
}

fn event_body(kind: &EventKind, prefs: &Prefs) -> Option<String> {
    // `/focus` keeps the answer and anything the user must act on (gate verdicts, errors).
    let focus = prefs.focus;
    let level = prefs.verbose;
    match kind {
        // Tool activity. `/verbose off` (and `/focus`) hides it; `new` is one line per
        // call, `all` adds results/status, `verbose` also the call input.
        EventKind::ToolCalled { name, input, .. } if !focus && level != Verbose::Off => Some(match level {
            Verbose::New => format!("⚙ {name}"),
            Verbose::All => dim(&format!("⚙ {name} {}", one_line(&describe(name, input), 100))),
            _ => dim(&format!("⚙ {name} {}", one_line(&input.to_string(), 200))),
        }),
        EventKind::ToolSettled { tool_use_id, is_error, bytes, .. } if !focus && matches!(level, Verbose::All | Verbose::Full) => {
            Some(if *is_error { warn(&format!("✗ {tool_use_id} · {bytes} bytes")) } else { dim(&format!("✓ {tool_use_id} · {bytes} bytes")) })
        }
        // Tool results that failed (the tool's error text lives in the user message).
        EventKind::Message { message, .. } if !prefs.quiet && !focus => {
            let errs: Vec<String> = message
                .content
                .iter()
                .filter_map(|b| if let Block::ToolResult { content, is_error: true, .. } = b { Some(i18n::t_fmt("notice.tool_error", &[("text", &one_line(content, 160))])) } else { None })
                .collect();
            (!errs.is_empty()).then(|| warn(&errs.join("\n")))
        }
        // A gate verdict is what the user must act on: never hidden by `/focus`.
        EventKind::Gate { gate, verdict, reason, .. } => Some(warn(&i18n::t_fmt("notice.gate", &[("gate", gate), ("verdict", verdict), ("reason", reason)]))),
        EventKind::Error { message } => Some(warn(&i18n::t_fmt("notice.error", &[("message", message)]))),
        EventKind::Notice { level: l, text } => {
            if focus {
                return None;
            }
            // Warnings always show; `/verbose verbose` adds the rest even under `--quiet`.
            let show = !prefs.quiet || l == "warn" || level == Verbose::Full;
            show.then(|| warn(&i18n::t_fmt("notice.bullet", &[("text", text)])))
        }
        EventKind::Compaction { tokens_before, .. } if !prefs.quiet && !focus => Some(dim(&i18n::t_fmt("notice.compacted", &[("tokens", &tokens_before.to_string())]))),
        _ => None,
    }
}

fn kind_name(kind: &EventKind) -> &'static str {
    match kind {
        EventKind::Header { .. } => "header",
        EventKind::System { .. } => "system",
        EventKind::Inbox { .. } => "inbox",
        EventKind::Message { .. } => "message",
        EventKind::MessageBoundary => "message_boundary",
        EventKind::ToolCalled { .. } => "tool_called",
        EventKind::ToolSettled { .. } => "tool_settled",
        EventKind::Gate { .. } => "gate",
        EventKind::Compaction { .. } => "compaction",
        EventKind::Prune { .. } => "prune",
        EventKind::TurnStart { .. } => "turn_start",
        EventKind::TurnEnd { .. } => "turn_end",
        EventKind::Notice { .. } => "notice",
        EventKind::Error { .. } => "error",
        EventKind::Model { .. } => "model",
        EventKind::Thinking { .. } => "thinking",
        EventKind::Title { .. } => "title",
        EventKind::Agent { .. } => "agent",
        EventKind::Tools { .. } => "tools",
        EventKind::ToolGuard { .. } => "tool_guard",
        EventKind::Rewind { .. } => "rewind",
        EventKind::Meta { .. } => "meta",
        EventKind::OutputSchema { .. } => "output_schema",
        EventKind::Structured { .. } => "structured",
        EventKind::Checkpoint { .. } => "checkpoint",
        EventKind::Discard { .. } => "discard",
        EventKind::Workspace { .. } => "workspace",
        EventKind::Fast { .. } => "fast",
        EventKind::AuxUsage { .. } => "aux_usage",
        EventKind::Step { .. } => "step",
        EventKind::SystemDelta { .. } => "system_delta",
        EventKind::Request { .. } => "request",
        EventKind::TurnDropped { .. } => "turn_dropped",
    }
}

/// The `/trace` line for one kernel event (upstream Hermes `/trace`: plugin/hook trace
/// lines). Hook activity surfaces here as its event kind and payload: a broken hook is a
/// `Notice` (`hook … failed`), a blocking hook a `Gate` verdict naming the hook, a
/// transform a `ToolSettled`/`ToolCalled` pair.
pub fn trace_line(kind: &EventKind, prefs: &Prefs) -> String {
    let name = kind_name(kind);
    let detail = match kind {
        EventKind::ToolCalled { name, .. } => format!(" {name}"),
        EventKind::ToolSettled { tool_use_id, is_error, bytes, .. } => format!(" {tool_use_id} {} {bytes}b", if *is_error { "error" } else { "ok" }),
        EventKind::Gate { gate, verdict, reason, .. } => format!(" {gate} {verdict}: {reason}"),
        EventKind::Notice { level, text } => format!(" {level}: {}", one_line(text, 120)),
        EventKind::Error { message } => format!(" {}", one_line(message, 120)),
        EventKind::TurnStart { turn } | EventKind::TurnEnd { turn, .. } => format!(" {turn}"),
        EventKind::Model { model } => format!(" {model}"),
        EventKind::Thinking { level } => format!(" {level}"),
        EventKind::Workspace { path } => format!(" {path}"),
        EventKind::AuxUsage { task, .. } => format!(" {task}"),
        _ => String::new(),
    };
    let stamp = if prefs.timestamps { format!("[{}] ", hhmm(prefs.utc_offset)) } else { String::new() };
    format!("{stamp}{}", dim(&format!("⤷ trace: {name}{detail}")))
}


/// The gate confirmation prompt (localized `approval.heading` / `approval.choices`).
pub fn approval_prompt(r: &ApprovalRequest) -> String {
    let gate = format!("{:?}", r.gate).to_lowercase();
    let heading = i18n::t_fmt("approval.heading", &[("gate", &gate), ("reason", &r.reason)]);
    format!("\n{}\n  {}: {}\n  {}", warn(&heading), r.tool, one_line(&r.summary, 300), i18n::t("approval.choices"))
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

/// A typed answer at the approval prompt (Hermes choices): `y`/`o` once, `s`/`a` this
/// session, `p` permanent (durable allowlist grant), anything else denies; text after a
/// deny word (`d too risky`, `n: use a dry run`) is the reason passed to the agent.
pub fn tty_choice(s: &str) -> (Approval, Option<String>) {
    let s = s.trim();
    let head = s.split(|c: char| c.is_whitespace() || c == ':').next().unwrap_or("").to_ascii_lowercase();
    match head.as_str() {
        "o" => return (Approval::Once, None),
        "s" => return (Approval::Always, None),
        "p" => return (Approval::Permanent, None),
        "" => return (Approval::Deny, None),
        _ => {}
    }
    match seagent_security::approvals::parse_answer(s) {
        ("once", _) => (Approval::Once, None),
        ("session", _) => (Approval::Always, None),
        ("permanent", _) => (Approval::Permanent, None),
        (_, reason) => (Approval::Deny, reason),
    }
}

impl Approver for TtyApprover {
    fn approve(&self, r: &ApprovalRequest) -> Approval {
        let q = approval_prompt(r);
        let (choice, reason) = tty_choice(self.prompt(&q).as_deref().unwrap_or(""));
        if let Some(why) = reason.filter(|w| !w.trim().is_empty()) {
            seagent_security::approvals::set_deny_reason(&r.id, &why);
        }
        choice
    }
    fn ask(&self, _: &str, question: &str) -> Result<String, String> {
        match self.prompt(&format!("\n? {question}\n> ")) {
            Some(a) if !a.is_empty() => Ok(a),
            _ => Err("the user gave no answer".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approval() -> ApprovalRequest {
        ApprovalRequest { id: "1".into(), tool_use_id: "tu_1".into(), session: "s".into(), tool: "shell".into(), summary: "rm -rf /tmp/x".into(), input: serde_json::Value::Null, gate: seagent_kernel::gate::GateKind::Privilege, reason: "recursive delete".into(), tier: 0 }
    }

    #[test]
    fn approval_prompt_and_notice_prefixes_follow_display_language() {
        // English by default: the wording seagent has always printed.
        i18n::set_thread_language(None);
        let en = approval_prompt(&approval());
        assert!(en.contains("⚑ privilege gate — recursive delete"), "{en}");
        assert!(en.contains("shell: rm -rf /tmp/x"));
        assert!(en.contains("Allow? [y] once"));
        // The catalog `display.language` feeds; `zh-TW` is an alias for zh-hant.
        i18n::set_thread_language(Some("zh-TW"));
        let tw = approval_prompt(&approval());
        assert!(tw.contains("⚑ privilege 閘門 — recursive delete"), "{tw}");
        assert!(tw.contains("允許？[y] 一次"), "{tw}");
        assert!(!tw.contains("Allow? [y] once"));
        // Notices ride the same catalog.
        let notice = event_line(&EventKind::Notice { level: "warn".into(), text: "queue full".into() }, false).unwrap();
        assert!(notice.contains("• queue full"), "{notice}");
        i18n::set_thread_language(Some("ja"));
        let notice = event_line(&EventKind::Error { message: "boom".into() }, false).unwrap();
        assert!(notice.contains("エラー: boom"), "{notice}");
        i18n::set_thread_language(None);
        assert!(event_line(&EventKind::Error { message: "boom".into() }, false).unwrap().contains("error: boom"));
    }

    #[test]
    fn recalled_blocks_never_reach_the_terminal() {
        // One fenced recall block straddling deltas, as the model would stream it.
        let full = format!("Here is the answer.{}", seagent_kernel::lifecycle::fence("memory", "SSN 123-45-6789"));
        let mut v = Visible::default();
        let shown: String = full.as_bytes().chunks(7).map(|c| v.feed(std::str::from_utf8(c).unwrap())).collect::<String>() + &v.flush();
        assert_eq!(shown, "Here is the answer.");
        // A provider that pre-wrapped its own block is scrubbed too.
        let mut v = Visible::default();
        assert_eq!(v.feed("a <memory-context>secret</memory-context> b"), "a  b");
    }

    #[test]
    fn tty_choices() {
        for (input, want) in [("y", Approval::Once), ("o", Approval::Once), ("yes", Approval::Once), ("once", Approval::Once), ("s", Approval::Always), ("a", Approval::Always), ("session", Approval::Always), ("always", Approval::Always), ("p", Approval::Permanent), ("permanent", Approval::Permanent), ("allow-always", Approval::Permanent), ("", Approval::Deny), ("N", Approval::Deny), ("maybe", Approval::Deny)] {
            assert_eq!(tty_choice(input).0, want, "{input:?}");
        }
        assert_eq!(tty_choice("n too risky"), (Approval::Deny, Some("too risky".into())));
        assert_eq!(tty_choice("deny: use --dry-run"), (Approval::Deny, Some("use --dry-run".into())));
        assert_eq!(tty_choice("d"), (Approval::Deny, None));
    }

    // ───────────────────────── display preferences ─────────────────────────

    /// What `render` prints on stderr for one event (the seam that keeps tests off stdout).
    fn visible(kind: &EventKind, prefs: &Prefs) -> Vec<String> {
        lines_for(kind, prefs)
    }

    fn called() -> EventKind {
        EventKind::ToolCalled { tool_use_id: "tu_1".into(), name: "shell".into(), input: serde_json::json!({"command": "ls -l"}), idempotency_key: "k1".into() }
    }
    fn settled(is_error: bool) -> EventKind {
        EventKind::ToolSettled { tool_use_id: "tu_1".into(), is_error, bytes: 42, artifact: None, ui_resource: None }
    }
    fn notice(level: &str, text: &str) -> EventKind {
        EventKind::Notice { level: level.into(), text: text.into() }
    }
    fn at(level: Verbose) -> Prefs {
        Prefs { verbose: level, ..Prefs::default() }
    }

    #[test]
    fn verbose_levels_gate_tool_activity() {
        i18n::set_thread_language(None);
        // off: no tool activity at all.
        assert!(visible(&called(), &at(Verbose::Off)).is_empty());
        assert!(visible(&settled(false), &at(Verbose::Off)).is_empty());
        assert!(visible(&settled(true), &at(Verbose::Off)).is_empty());
        // new: exactly one line per tool call, no results/status.
        let new = visible(&called(), &at(Verbose::New));
        assert_eq!(new.len(), 1);
        assert_eq!(new[0], "⚙ shell");
        assert!(visible(&settled(false), &at(Verbose::New)).is_empty());
        // all: the call with its argument plus the result/status line.
        let all = visible(&called(), &at(Verbose::All));
        assert!(all.iter().any(|l| l.contains("⚙ shell") && l.contains("ls -l")), "{all:?}");
        let done = visible(&settled(false), &at(Verbose::All));
        assert_eq!(done.len(), 1);
        assert!(done[0].contains("✓ tu_1") && done[0].contains("42 bytes"), "{done:?}");
        assert!(visible(&settled(true), &at(Verbose::All))[0].contains("✗ tu_1"));
        // verbose: the whole call input, and info notices that `--quiet` would drop.
        assert!(visible(&called(), &at(Verbose::Full))[0].contains("\"command\""));
        let quiet = Prefs { quiet: true, ..at(Verbose::New) };
        assert!(visible(&notice("info", "queued"), &quiet).is_empty());
        assert!(!visible(&notice("info", "queued"), &Prefs { quiet: true, ..at(Verbose::Full) }).is_empty());
        assert!(!visible(&notice("warn", "queue full"), &quiet).is_empty(), "warnings always show");
    }

    #[test]
    fn focus_shows_only_the_answer() {
        i18n::set_thread_language(None);
        let focus = Prefs { focus: true, verbose: Verbose::Full, ..Prefs::default() };
        // Hidden: tool activity, notices, compaction, tool errors.
        assert!(visible(&called(), &focus).is_empty());
        assert!(visible(&settled(false), &focus).is_empty());
        assert!(visible(&notice("warn", "queue full"), &focus).is_empty());
        assert!(visible(&EventKind::Compaction { upto_seq: 3, summary: "s".into(), pruned: vec![], tokens_before: 900 }, &focus).is_empty());
        assert!(event_line_with(&EventKind::Message { message: tool_error_message(), usage: None, model: None, inbox: None }, &focus).is_none());
        // Kept: the verdicts and errors the user has to act on.
        assert!(visible(&EventKind::Gate { tool_use_id: "tu_1".into(), gate: "privilege".into(), verdict: "deny".into(), reason: "rm -rf".into() }, &focus).len() == 1);
        assert!(visible(&EventKind::Error { message: "boom".into() }, &focus).len() == 1);
        // Off, the same notice would have shown.
        assert!(visible(&notice("warn", "queue full"), &Prefs::default()).len() == 1);
    }

    fn tool_error_message() -> seagent_core::Message {
        seagent_core::Message { role: seagent_core::Role::User, content: vec![Block::ToolResult { tool_use_id: "tu_1".into(), content: "no such file".into(), is_error: true }] }
    }

    #[test]
    fn timestamps_prefix_message_and_notice_lines() {
        i18n::set_thread_language(None);
        let ts = Prefs { timestamps: true, ..Prefs::default() };
        let line = &visible(&notice("warn", "queue full"), &ts)[0];
        // `[HH:MM] • queue full`
        assert!(line.starts_with('['), "{line}");
        assert_eq!(&line[3..4], ":");
        assert!(line[1..3].chars().all(|c| c.is_ascii_digit()) && line[4..6].chars().all(|c| c.is_ascii_digit()), "{line}");
        assert_eq!(&line[6..8], "] ");
        assert!(line.ends_with("• queue full"), "{line}");
        // Every line of a multi-line event is stamped, not just the first.
        let multi = stamp_lines("09:41", "one\ntwo");
        assert_eq!(multi, "[09:41] one\n[09:41] two");
        // The streamed answer carries the same prefix at every line start (and keeps state).
        let (a, b) = (stamp_text(&ts, "first line\n", true), stamp_text(&ts, "second", false));
        assert!(a.starts_with('[') && a.ends_with("first line\n"), "{a}");
        assert!(!b.starts_with('['), "mid-line deltas are not stamped twice: {b}");
        assert!(stamp_text(&ts, "next", true).starts_with('['));
        // Off: no prefixes at all.
        assert_eq!(stamp_text(&Prefs::default(), "x", true), "x");
        assert!(!visible(&notice("warn", "queue full"), &Prefs::default())[0].starts_with('['));
    }

    #[test]
    fn trace_shows_every_event_kind_and_hook_activity() {
        i18n::set_thread_language(None);
        // Off: no trace lines, the normal event line only.
        let off = Prefs::default();
        assert_eq!(visible(&notice("warn", "queue full"), &off).len(), 1);
        assert!(visible(&settled(false), &off).is_empty(), "no visible line, no trace");
        // On: a `[trace]`-style line for every kernel event, including hidden kinds.
        let on = Prefs { trace: true, ..Prefs::default() };
        let lines = visible(&settled(false), &on);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("trace: tool_settled") && lines[0].contains("tu_1"), "{lines:?}");
        let gate = visible(&EventKind::Gate { tool_use_id: "tu_1".into(), gate: "privilege".into(), verdict: "deny".into(), reason: "hook guard: no rm".into() }, &on);
        assert_eq!(gate.len(), 2, "gate verdict plus its trace line: {gate:?}");
        assert!(gate.iter().any(|l| l.contains("trace: gate") && l.contains("hook guard")), "{gate:?}");
        // Hook activity reaches the printer as notices; /trace names the kind and the text.
        let hook = visible(&notice("warn", "hook guard failed (timeout); continuing"), &on);
        assert!(hook.iter().any(|l| l.contains("trace: notice") && l.contains("hook guard failed")), "{hook:?}");
        // Turn bookkeeping is trace-only (never shown as a plain line).
        let turn = visible(&EventKind::TurnStart { turn: 2 }, &on);
        assert_eq!(turn.len(), 1);
        assert!(turn[0].contains("trace: turn_start") && turn[0].contains('2'), "{turn:?}");
        assert!(visible(&EventKind::TurnStart { turn: 2 }, &off).is_empty());
        // With /timestamps the trace line is stamped too.
        let both = Prefs { trace: true, timestamps: true, ..Prefs::default() };
        assert!(visible(&EventKind::TurnStart { turn: 1 }, &both)[0].starts_with('['));
    }

    #[test]
    fn prefs_come_from_the_session_display_file() {
        // A session's `/…` preferences, as `slash::display_get` reads them back.
        let d = serde_json::json!({"timestamps": true, "verbose": "all", "focus": true, "trace": true, "reasoning": true});
        let p = Prefs::from_display(&d);
        assert_eq!((p.timestamps, p.verbose, p.focus, p.trace, p.reasoning), (true, Verbose::All, true, true, true));
        assert!(!p.quiet && p.utc_offset == 480);
        // Nothing stored: one line per tool call, no timestamps, no focus.
        let p = Prefs::from_display(&serde_json::json!({}));
        assert_eq!((p.timestamps, p.verbose, p.focus, p.trace, p.reasoning), (false, Verbose::New, false, false, false));
        assert_eq!(Verbose::parse(Some("verbose")).name(), "verbose");
        assert_eq!(Verbose::parse(Some("nonsense")), Verbose::New);
    }
}
