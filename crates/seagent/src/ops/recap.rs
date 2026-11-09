//! `/recap` — a short recap of what happened in this session (Hermes
//! `hermes_cli/session_recap.py`).
//!
//! Deliberately free and instant: pure local computation over the projected conversation, no
//! model call, no auxiliary model, no prompt-cache invalidation. It counts the recent turns,
//! tool calls and touched files and previews the last ask and last reply. Only visible text is
//! read — reasoning (`Block::Thinking`) and tool output never leak into the recap — and every
//! preview is sanitised before it is echoed to a terminal (Hermes `sanitize_display_text`, the
//! codex#31494 class of escape-sequence injection).

use crate::slash::{Ctx, Reply};
use seagent_core::{Block, Message, Role};
use seagent_kernel::projection::project;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// user/assistant turns considered "recent activity".
pub const RECENT_TURN_WINDOW: usize = 20;
pub const PROMPT_PREVIEW_CHARS: usize = 140;
pub const ASSISTANT_PREVIEW_CHARS: usize = 200;
pub const MAX_FILES_LISTED: usize = 5;
pub const MAX_TOOLS_LISTED: usize = 5;

/// File-touching tools and the argument key holding the path.
const FILE_TOOL_KEYS: &[(&str, &str)] = &[("read", "path"), ("write", "path"), ("patch", "path"), ("skill_manage", "file_path"), ("skill_view", "file_path")];

/// Multi-line plain-text recap (80-column terminal / chat-bubble friendly).
pub fn build_recap(messages: &[Message], title: Option<&str>, session: Option<&str>, cwd: &Path) -> String {
    let mut lines = vec!["Session recap".to_string()];
    if let Some(name) = title.map(str::trim).filter(|t| !t.is_empty()).or_else(|| session.map(|s| &s[..s.len().min(8)])) {
        lines[0].push_str(&format!(" — {name}"));
    }
    if messages.is_empty() {
        lines.push("  (nothing to recap — no messages yet)".to_string());
        return lines.join("\n");
    }
    let (users, assistants, tool_msgs) = turn_counts(messages);
    let window = recent_window(messages, RECENT_TURN_WINDOW);
    let (win_users, win_assistants, _) = turn_counts(window);
    let mut scope = format!("{win_users} user turn{} / {win_assistants} assistant repl{}", plural(win_users), if win_assistants == 1 { "y" } else { "ies" });
    if (users, assistants) != (win_users, win_assistants) {
        scope.push_str(&format!(" (of {users}/{assistants} total)"));
    }
    lines.push(format!("  Recent: {scope}, {tool_msgs} tool result{}", plural(tool_msgs)));
    let calls = tool_calls(window);
    let (counts, files) = summarise_tool_activity(&calls, cwd);
    if !counts.is_empty() {
        let top: Vec<String> = counts.iter().map(|(n, c)| format!("{n}×{c}")).collect();
        lines.push(format!("  Tools used: {}", join_capped(&top, MAX_TOOLS_LISTED)));
    }
    if !files.is_empty() {
        lines.push(format!("  Files touched: {}", join_capped(&files, MAX_FILES_LISTED)));
    }
    for (role, label, limit) in [(Role::User, "Last ask", PROMPT_PREVIEW_CHARS), (Role::Assistant, "Last reply", ASSISTANT_PREVIEW_CHARS)] {
        if let Some(text) = latest_text(window, role) {
            lines.push(format!("  {label}: {}", truncate(&text, limit)));
        }
    }
    if lines.len() == 2 {
        lines.push("  (no assistant activity yet in this window)".to_string());
    }
    lines.join("\n")
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// A user turn: a message carrying an ask (text or image). Tool results ride in user messages
/// here, where Hermes has a separate `tool` role, so they are counted separately.
fn is_ask(m: &Message) -> bool {
    m.role == Role::User && m.content.iter().any(|b| matches!(b, Block::Text { .. } | Block::Image { .. }))
}

/// `(user_turns, assistant_replies, tool_results)`.
fn turn_counts(messages: &[Message]) -> (usize, usize, usize) {
    let mut users = 0;
    let mut assistants = 0;
    let mut tools = 0;
    for m in messages {
        if is_ask(m) {
            users += 1;
        }
        if m.role == Role::Assistant {
            assistants += 1;
        }
        tools += m.content.iter().filter(|b| matches!(b, Block::ToolResult { .. })).count();
    }
    (users, assistants, tools)
}

/// Tail slice covering at most `window` user+assistant turns (tool results ride along).
fn recent_window(messages: &[Message], window: usize) -> &[Message] {
    let mut count = 0;
    for i in (0..messages.len()).rev() {
        let m = &messages[i];
        if is_ask(m) || m.role == Role::Assistant {
            count += 1;
            if count >= window {
                return &messages[i..];
            }
        }
    }
    messages
}

/// `(tool name, arguments)` in conversation order.
fn tool_calls(messages: &[Message]) -> Vec<(String, serde_json::Value)> {
    messages.iter().flat_map(|m| m.tool_uses().map(|(_, n, i)| (n.to_string(), i.clone())).collect::<Vec<_>>()).collect()
}

/// `(counts sorted desc, recently touched files newest first)`.
fn summarise_tool_activity(calls: &[(String, serde_json::Value)], cwd: &Path) -> (Vec<(String, usize)>, Vec<String>) {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut files: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    // Reversed so the file list comes out newest → oldest.
    for (name, args) in calls.iter().rev() {
        *counts.entry(name.as_str()).or_default() += 1;
        for p in file_paths(name, args) {
            if !seen.contains(&p) {
                seen.push(p.clone());
                files.push(shortened_path(&p, cwd));
            }
        }
    }
    let mut counts: Vec<(String, usize)> = counts.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    (counts, files)
}

/// Paths a tool call touched (`patch` may carry several edits).
fn file_paths(name: &str, args: &serde_json::Value) -> Vec<String> {
    let Some(key) = FILE_TOOL_KEYS.iter().find(|(t, _)| *t == name).map(|(_, k)| *k) else {
        return Vec::new();
    };
    if let Some(p) = args.get(key).and_then(|v| v.as_str()).filter(|p| !p.is_empty()) {
        return vec![p.to_string()];
    }
    args.get("edits")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|e| e.get("path").and_then(|p| p.as_str())).filter(|p| !p.is_empty()).map(String::from).collect())
        .unwrap_or_default()
}

/// `a, b, c (+N more)`.
fn join_capped(items: &[String], limit: usize) -> String {
    let head = items.iter().take(limit).cloned().collect::<Vec<_>>().join(", ");
    let extra = items.len().saturating_sub(limit);
    if extra > 0 {
        format!("{head} (+{extra} more)")
    } else {
        head
    }
}

/// Most recent non-empty visible text for `role` (reasoning is never included).
fn latest_text(messages: &[Message], role: Role) -> Option<String> {
    messages.iter().rev().filter(|m| m.role == role).map(|m| m.text().trim().to_string()).find(|t| !t.is_empty())
}

/// One compact line: sanitised (no escapes/control chars), whitespace collapsed, truncated.
fn truncate(text: &str, limit: usize) -> String {
    let text = sanitize(text).split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() <= limit {
        return text;
    }
    format!("{}…", text.chars().take(limit.saturating_sub(1)).collect::<String>().trim_end())
}

/// Strip ANSI escape sequences, C1 controls and other control characters, keeping newlines and
/// tabs (Hermes `sanitize_display_text`): stored history is untrusted for display.
fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut it = text.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\x1b' => match it.peek() {
                Some('[') => {
                    it.next();
                    for d in it.by_ref() {
                        if ('@'..='~').contains(&d) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    it.next();
                    while let Some(d) = it.next() {
                        if d == '\x07' || (d == '\x1b' && it.peek() == Some(&'\\')) {
                            if d == '\x1b' {
                                it.next();
                            }
                            break;
                        }
                    }
                }
                Some(_) => {
                    it.next();
                }
                None => {}
            },
            // 8-bit CSI (0x9b) plus its parameter bytes and final byte.
            '\u{9b}' => {
                for d in it.by_ref() {
                    if ('@'..='~').contains(&d) {
                        break;
                    }
                }
            }
            '\r' => out.push('\n'),
            c if c.is_control() && c != '\n' && c != '\t' => {}
            c => out.push(c),
        }
    }
    out
}

/// Paths relative to `cwd` when possible, `~`-shortened otherwise (Hermes `_shortened_path`).
fn shortened_path(path: &str, cwd: &Path) -> String {
    if path.is_empty() {
        return String::new();
    }
    let abs = if Path::new(path).is_absolute() { normalize(Path::new(path)) } else { normalize(&cwd.join(path)) };
    let cwd = normalize(cwd);
    if abs == cwd {
        return ".".to_string();
    }
    // Relative paths read with `/` on every OS (`layout::model_path`; Unix: unchanged).
    if let Ok(rel) = abs.strip_prefix(&cwd) {
        return seagent_core::platform::layout::model_path(rel);
    }
    if let Ok(home) = std::env::var("HOME").map(PathBuf::from) {
        let home = normalize(&home);
        if let Ok(rel) = abs.strip_prefix(&home) {
            return format!("~/{}", seagent_core::platform::layout::model_path(rel));
        }
    }
    abs.display().to_string()
}

/// Lexical path normalisation (`abspath` does not touch the filesystem either).
fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `/recap` — show the recap of the current session.
pub fn slash(c: &Ctx, _args: &str) -> Result<Reply, String> {
    let id = c.session.as_deref().ok_or_else(|| "no session yet — send a message first".to_string())?;
    let view = project(&c.k.store.read(id).map_err(|e| e.to_string())?);
    Ok(Reply { text: Some(build_recap(&view.messages, view.title.as_deref(), Some(id), &c.workspace)), ..Default::default() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn user(text: &str) -> Message {
        Message::user(text)
    }

    fn assistant(text: &str) -> Message {
        Message::assistant(text)
    }

    fn call(name: &str, args: serde_json::Value) -> Message {
        Message { role: Role::Assistant, content: vec![Block::ToolUse { id: format!("t-{name}"), name: name.into(), input: args }] }
    }

    fn result(id: &str, text: &str) -> Message {
        Message { role: Role::User, content: vec![Block::ToolResult { tool_use_id: id.into(), content: text.into(), is_error: false }] }
    }

    fn line<'a>(recap: &'a str, needle: &str) -> &'a str {
        recap.split('\n').find(|l| l.contains(needle)).unwrap_or_else(|| panic!("no line with {needle} in:\n{recap}"))
    }

    #[test]
    fn empty_session_recaps_like_upstream() {
        let out = build_recap(&[], Some("fix the parser"), Some("abcd1234ef"), Path::new("/w"));
        assert_eq!(out, "Session recap — fix the parser\n  (nothing to recap — no messages yet)");
        // Without a title the short session id is used (upstream `session_id[:8]`).
        assert!(build_recap(&[], None, Some("abcd1234ef"), Path::new("/w")).starts_with("Session recap — abcd1234\n"));
    }

    #[test]
    fn recap_counts_turns_tools_and_files() {
        let msgs = vec![
            user("please fix src/a.rs"),
            call("read", json!({"path": "src/a.rs"})),
            result("t-read", "file body"),
            assistant("found the bug"),
            user("now also touch src/b.rs"),
            call("read", json!({"path": "src/a.rs"})),
            call("write", json!({"path": "src/b.rs"})),
            result("t-write", "ok"),
            assistant("done"),
        ];
        let out = build_recap(&msgs, None, None, Path::new("/w"));
        // Tool-call messages are assistant turns too (upstream counts roles, not content).
        assert_eq!(line(&out, "Recent:"), "  Recent: 2 user turns / 5 assistant replies, 2 tool results");
        assert_eq!(line(&out, "Tools used:"), "  Tools used: read×2, write×1");
        assert_eq!(line(&out, "Files touched:"), "  Files touched: src/b.rs, src/a.rs");
        assert_eq!(line(&out, "Last ask:"), "  Last ask: now also touch src/b.rs");
        assert_eq!(line(&out, "Last reply:"), "  Last reply: done");
        assert!(!out.contains("no assistant activity"));
    }

    #[test]
    fn recap_caps_the_recent_window_and_says_so() {
        let mut msgs = Vec::new();
        for i in 0..30 {
            msgs.push(user(&format!("ask {i}")));
            msgs.push(assistant(&format!("reply {i}")));
        }
        let out = build_recap(&msgs, None, None, Path::new("/w"));
        // The window counts user+assistant messages: 20 of them is the last 10 exchanges.
        assert_eq!(line(&out, "Recent:"), "  Recent: 10 user turns / 10 assistant replies (of 30/30 total), 0 tool results");
        assert_eq!(line(&out, "Last ask:"), "  Last ask: ask 29");
        // Nothing but tool results in the window: no previews, so the "no activity" note shows.
        let bare = build_recap(&[result("t1", "ok")], None, None, Path::new("/w"));
        assert_eq!(bare, "Session recap\n  Recent: 0 user turns / 0 assistant replies, 1 tool result\n  (no assistant activity yet in this window)");
        // With an ask the preview line itself is the activity, like upstream.
        let only_ask = build_recap(&[user("hi")], None, None, Path::new("/w"));
        assert!(only_ask.contains("Last ask: hi") && !only_ask.contains("no assistant activity"), "{only_ask}");
    }

    #[test]
    fn previews_truncate_and_never_carry_escapes() {
        let long = format!("src/a.rs {}", "x ".repeat(500));
        let msgs = vec![
            user(&long),
            assistant("done \u{9b}31m with it\u{7}"),
        ];
        let out = build_recap(&msgs, None, None, Path::new("/w"));
        let ask = line(&out, "Last ask:");
        assert!(ask.chars().count() < 160, "truncated: {ask}");
        assert!(ask.ends_with('…'), "{ask}");
        let escaped = build_recap(
            &[user("please \u{1b}[2J\u{1b}]0;pwned\u{7} do the thing"), assistant("done \u{9b}31m with it\u{7}")],
            None,
            None,
            Path::new("/w"),
        );
        for bad in ['\u{1b}', '\u{9b}', '\u{7}'] {
            assert!(!escaped.contains(bad), "{bad:?} survived in:\n{escaped}");
        }
        assert!(escaped.contains("do the thing") && escaped.contains("with it"), "{escaped}");
    }

    #[test]
    fn reasoning_and_tool_output_stay_private() {
        let msgs = vec![
            user("go"),
            Message {
                role: Role::Assistant,
                content: vec![
                    Block::Thinking { text: "SECRET-REASONING".into(), signature: None },
                    Block::text("visible answer"),
                ],
            },
            result("t-read", "SECRET-TOOL-OUTPUT"),
        ];
        let out = build_recap(&msgs, None, None, Path::new("/w"));
        assert!(!out.contains("SECRET-REASONING") && !out.contains("SECRET-TOOL-OUTPUT"), "{out}");
        assert_eq!(line(&out, "Last reply:"), "  Last reply: visible answer");
    }

    #[test]
    fn paths_are_shortened_against_the_workspace() {
        assert_eq!(shortened_path("/w/src/a.rs", Path::new("/w")), "src/a.rs");
        assert_eq!(shortened_path("src/./a.rs", Path::new("/w")), "src/a.rs");
        assert_eq!(shortened_path("/w", Path::new("/w")), ".");
        assert_eq!(shortened_path("/elsewhere/x.rs", Path::new("/w")), "/elsewhere/x.rs");
    }

    #[test]
    fn slash_command_shows_the_recap_of_the_current_session() {
        let t = crate::testkit::kit();
        let id = t.k.create_session(&t.ws, None, None, Some("recap me")).unwrap();
        t.k.submit(&id, "add the cache", "cli").unwrap();
        t.k.run(&id, seagent_kernel::kernel::RunOpts::default()).unwrap();
        let c = Ctx { k: &t.k, ext: None, session: Some(id), workspace: t.ws.clone(), surface: crate::slash::Surface::Cli, sender: None, notify: None };
        let out = slash(&c, "").unwrap().text.unwrap();
        assert!(out.starts_with("Session recap — recap me"), "{out}");
        assert!(out.contains("Last ask: add the cache"), "{out}");
        // The registry route (`/recap`) renders the same text.
        assert_eq!(crate::slash::run(&c, "/recap").unwrap().text.unwrap(), out);
        let none = Ctx { session: None, ..c };
        assert!(slash(&none, "").unwrap_err().contains("no session yet"));
    }
}
