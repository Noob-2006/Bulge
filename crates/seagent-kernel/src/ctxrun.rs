//! Kernel glue for the context features that were written but never called (Hermes §12 /
//! OpenClaw): `@`-references, subdirectory hints, micro-compaction bookkeeping, the
//! edit→verify stop loop and BM25 `tool_search`. The modules hold the decisions and pure
//! helpers; this file is the small amount of I/O and state plumbing the run loop needs.
//!
//! Every entry point is a no-op when the corresponding config knob is off, and nothing here
//! may fail a turn: a broken reference, hint or summary is dropped with a note.

use crate::config::{Config, Paths};
use crate::ctxstate::CtxState;
use crate::projection::View;
use crate::verify_loop;
use seagent_core::ToolSpec;
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};

/// `@file:` / `@folder:` / `@diff` / `@url:` expansion for one incoming user message.
/// Returns the rewritten message and the warnings (shown to the user as a note).
pub fn expand_refs(cfg: &Config, paths: &Paths, ws: &Path, text: &str, window: u64) -> (String, Vec<String>) {
    if !cfg.context.references {
        return (text.to_string(), vec![]);
    }
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let deny = vec![paths.secrets(), paths.config_dir.join(".env")];
    let fetch = |u: &str| crate::refs::default_fetch(u);
    let env = crate::refs::Env { cwd: ws, allowed_root: ws, context_length: window.max(1), home, deny, fetch: Some(&fetch) };
    let r = crate::refs::expand(text, &env);
    (r.message, r.warnings)
}

/// Append a touched subdirectory's `AGENTS.md` / `CLAUDE.md` / `.cursorrules` to a tool result
/// (Hermes `subdirectory_hints.py`): once per directory per session, never for the top level.
pub fn subdir_hint(cfg: &Config, st: &CtxState, session: &str, ws: &Path, tool: &str, input: &Value) -> Option<String> {
    if !cfg.context.subdir_hints {
        return None;
    }
    let mut map = st.subdirs.lock().unwrap_or_else(|e| e.into_inner());
    let t = map.entry(session.to_string()).or_insert_with(|| crate::subdir::Tracker::new(ws));
    t.check(tool, input)
}

/// Record a settled tool call for the verify loop.
pub fn observe_tool(cfg: &Config, st: &CtxState, session: &str, tool: &str, input: &Value, is_error: bool) {
    let watching = cfg.context.verify_on_stop != "off" || !cfg.context.pre_verify.is_empty() || !st.verify_gates.read().unwrap_or_else(|e| e.into_inner()).is_empty();
    if !watching {
        return;
    }
    let mut map = st.verify.lock().unwrap_or_else(|e| e.into_inner());
    map.entry(session.to_string()).or_default().observe(tool, input, is_error);
}

/// Reset the per-turn verify state (called when a turn starts).
pub fn reset_turn(st: &CtxState, session: &str) {
    let mut map = st.verify.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = map.get_mut(session) {
        s.reset();
    }
}

/// The message that keeps the turn going after the model tried to finish, if any: the built-in
/// verify nudge first, then the `pre_verify` hook commands, then registered `VerifyGate`s.
pub fn verify_message(cfg: &Config, st: &CtxState, session: &str, ws: &str, reply: &str, messaging_channel: bool) -> Option<String> {
    let budget = cfg.context.max_verify_nudges;
    // The built-in nudge ("you edited files but did not verify"): off | on | auto.
    if verify_loop::enabled(&cfg.context.verify_on_stop, messaging_channel) {
        let mut map = st.verify.lock().unwrap_or_else(|e| e.into_inner());
        let s = map.get_mut(session)?;
        if s.should_nudge(budget) {
            s.nudged();
            return Some(verify_loop::nudge_text(cfg.context.verify_guidance));
        }
    }
    let (changed, attempt) = {
        let map = st.verify.lock().unwrap_or_else(|e| e.into_inner());
        let s = map.get(session)?;
        if s.changed_paths().is_empty() || !s.can_continue(budget) {
            return None;
        }
        (s.changed_paths(), s.nudges + 1)
    };
    for cmd in &cfg.context.pre_verify {
        if let Some(m) = run_pre_verify(cmd, session, ws, &changed, attempt, reply) {
            let mut map = st.verify.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(s) = map.get_mut(session) {
                s.nudged();
            }
            return Some(m);
        }
    }
    let gates = st.verify_gates.read().unwrap_or_else(|e| e.into_inner()).clone();
    for g in gates {
        if let Some(m) = g.pre_verify(session, ws, &changed, attempt, reply).filter(|m| !m.trim().is_empty()) {
            let mut map = st.verify.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(s) = map.get_mut(session) {
                s.nudged();
            }
            return Some(m);
        }
    }
    None
}

/// Run one `context.pre_verify` command (Hermes protocol: JSON on stdin, a `continue`/`block`
/// JSON on stdout keeps the turn going). Bounded, and a failure is never fatal.
pub fn run_pre_verify(cmd: &str, session: &str, ws: &str, changed: &[String], attempt: u32, reply: &str) -> Option<String> {
    use std::io::Write;
    use std::process::Stdio;
    // `bash -c` (Windows: Git Bash / MSYS2; without one the hook is skipped, never fatal).
    let mut child = crate::childproc::bash(cmd)
        .ok()?
        .current_dir(ws)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env("SEAGENT_PRE_VERIFY", "1")
        .spawn()
        .ok()?;
    let payload = json!({"event": "pre_verify", "session": session, "workspace": ws, "changed": changed, "attempt": attempt, "reply": reply});
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(payload.to_string().as_bytes());
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            Ok(None) => {
                let _ = child.kill();
                return None;
            }
            Err(_) => return None,
        }
    }
    let out = child.wait_with_output().ok()?;
    verify_loop::parse_hook_output(&String::from_utf8_lossy(&out.stdout))
}

/// The `tool_search` meta tool's schema (offered with `tool_describe` / `tool_call`).
pub fn tool_search_schema() -> seagent_core::ToolSchema {
    seagent_core::ToolSchema {
        name: "tool_search".into(),
        description: "Search the tool index by keyword (BM25 over names and descriptions) when you do not know which tool fits. Returns names with one-line summaries; use tool_describe for the full schema.".into(),
        input_schema: json!({"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer"}},"required":["query"]}),
    }
}

/// Run the BM25 tool search over the tools this session may use.
pub fn tool_search(specs: &[ToolSpec], cfg: &Config, input: &Value) -> String {
    let q = input.get("query").and_then(Value::as_str).unwrap_or("");
    let want = input.get("limit").and_then(Value::as_u64).map(|n| n.clamp(1, 50) as usize);
    let mut c = cfg.tools.tool_search.clone();
    if let Some(w) = want {
        c.max_results = w;
    }
    let idx = crate::toolsearch::Index::new(specs);
    crate::toolsearch::render(&idx.search(q, &c))
}

/// Fold the oldest un-absorbed exchange into the rolling summary (Hermes micro-compaction).
/// Returns the messages that were absorbed and (the possibly updated) rolling summary, so the
/// kernel can append one `Compaction` event.
pub fn micro_plan(cfg: &Config, st: &CtxState, session: &str, view: &View) -> Option<(usize, usize, String, bool)> {
    let mut map = st.micro.lock().unwrap_or_else(|e| e.into_inner());
    let s = map.entry(session.to_string()).or_default();
    if !s.tick(cfg.compaction.micro_compact_every_n_turns) {
        return None;
    }
    let flags: Vec<bool> = view.messages.iter().map(|m| m.role == seagent_core::Role::User && !m.content.iter().any(|b| matches!(b, seagent_core::Block::ToolResult { .. }))).collect();
    let keep = cfg.compaction.keep_messages.max(1);
    let (start, end) = crate::microcompact::next_exchange(&flags, s.absorbed, keep)?;
    let defrag = s.needs_defrag(cfg.compaction.micro_compact_defrag_threshold_tokens);
    Some((start, end, s.summary.clone(), defrag))
}

/// Commit a micro-compaction pass: the folded exchange text goes into the rolling summary and
/// the new history starts at the summary message itself (`absorbed = 1` after the rebuild).
pub fn micro_commit(st: &CtxState, session: &str, exchange_summary: &str) -> String {
    let mut map = st.micro.lock().unwrap_or_else(|e| e.into_inner());
    let s = map.entry(session.to_string()).or_default();
    s.absorb(exchange_summary, 1);
    s.absorbed = 1;
    s.summary.clone()
}

/// The rolling summary of a session (for the defrag pass).
pub fn micro_summary(st: &CtxState, session: &str) -> Option<String> {
    let map = st.micro.lock().unwrap_or_else(|e| e.into_inner());
    map.get(session).map(|s| s.summary.clone())
}

/// Re-summarise the rolling summary once it passed the defrag threshold.
pub fn micro_defrag(st: &CtxState, session: &str, condensed: &str) {
    let mut map = st.micro.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = map.get_mut(session) {
        s.defrag(condensed);
    }
}

/// A compaction or rewind changed the history: micro state starts over.
pub fn micro_reset(st: &CtxState, session: &str) {
    let mut map = st.micro.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = map.get_mut(session) {
        s.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-removing scratch dir (`seagent-ctxrun-*` used to be left behind on every run); the guard
    /// derefs to `Path`, so the call sites keep using `d.join(..)`.
    fn tmp(tag: &str) -> seagent_core::tmp::TempDir {
        seagent_core::tmp::TempDir::new(&format!("seagent-ctxrun-{tag}"))
    }

    #[test]
    fn refs_attach_a_file_and_are_off_when_disabled() {
        let d = tmp("refs");
        std::fs::write(d.join("a.txt"), "hello ref").unwrap();
        let paths = Paths { data: d.join("data"), config_dir: d.join("cfg"), runtime: d.join("run"), ..Default::default() };
        let cfg = Config::default();
        let (m, w) = expand_refs(&cfg, &paths, &d, "look @file:a.txt", 100_000);
        assert!(m.contains("hello ref") && m.contains("Attached Context"), "{m}");
        assert!(w.is_empty());
        let mut off = cfg.clone();
        off.context.references = false;
        assert_eq!(expand_refs(&off, &paths, &d, "look @file:a.txt", 100_000).0, "look @file:a.txt");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn subdir_hints_fire_once_for_a_touched_directory() {
        let d = tmp("subdir");
        std::fs::create_dir_all(d.join("pkg")).unwrap();
        std::fs::write(d.join("pkg/AGENTS.md"), "pkg rules").unwrap();
        let cfg = Config::default();
        let st = CtxState::default();
        assert!(subdir_hint(&cfg, &st, "s", &d, "read", &json!({"path": "pkg/x.rs"})).is_some());
        assert!(subdir_hint(&cfg, &st, "s", &d, "read", &json!({"path": "pkg/y.rs"})).is_none(), "remembered");
        let mut off = cfg.clone();
        off.context.subdir_hints = false;
        assert!(subdir_hint(&off, &st, "s2", &d, "read", &json!({"path": "pkg/z.rs"})).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn verify_nudge_needs_an_edit_and_respects_the_budget() {
        let cfg: Config = toml::from_str("[context]\nverify_on_stop = \"on\"\nmax_verify_nudges = 1\n").unwrap();
        let st = CtxState::default();
        assert!(verify_message(&cfg, &st, "s", "/w", "done", false).is_none(), "nothing changed");
        observe_tool(&cfg, &st, "s", "write", &json!({"path": "a.rs"}), false);
        let m = verify_message(&cfg, &st, "s", "/w", "done", false).unwrap();
        assert!(m.contains("have not verified"));
        assert!(verify_message(&cfg, &st, "s", "/w", "done", false).is_none(), "budget spent");
        // A verification-looking command satisfies the loop.
        observe_tool(&cfg, &st, "s", "write", &json!({"path": "b.rs"}), false);
        observe_tool(&cfg, &st, "s", "shell", &json!({"command": "cargo test"}), false);
        assert!(verify_message(&cfg, &st, "s", "/w", "done", false).is_none());
    }

    #[test]
    fn pre_verify_commands_and_gates_continue_the_turn() {
        let mut cfg = Config::default();
        cfg.context.verify_on_stop = "off".into();
        cfg.context.pre_verify = vec!["printf '{\"action\":\"continue\",\"message\":\"run the linter\"}'".into()];
        let st = CtxState::default();
        observe_tool(&cfg, &st, "s", "edit", &json!({"path": "a.rs"}), false);
        let ws = tmp("preverify");
        assert_eq!(verify_message(&cfg, &st, "s", ws.to_str().unwrap(), "done", false).as_deref(), Some("run the linter"));
        let _ = std::fs::remove_dir_all(&ws);
        struct Gate;
        impl crate::ctxstate::VerifyGate for Gate {
            fn name(&self) -> String {
                "t".into()
            }
            fn pre_verify(&self, _s: &str, _w: &str, changed: &[String], _a: u32, _r: &str) -> Option<String> {
                Some(format!("gate saw {}", changed.join(",")))
            }
        }
        let mut off: Config = Config::default();
        off.context.pre_verify.clear();
        let st2 = CtxState::default();
        st2.verify_gates.write().unwrap().push(std::sync::Arc::new(Gate));
        observe_tool(&off, &st2, "s", "edit", &json!({"path": "z.rs"}), false);
        assert_eq!(verify_message(&off, &st2, "s", "/w", "done", false).as_deref(), Some("gate saw z.rs"));
    }

    #[test]
    fn tool_search_ranks_the_fitting_tool_first() {
        let spec = |n: &str, d: &str| ToolSpec { name: n.into(), description: d.into(), input_schema: json!({}), parallel_safe: false, idempotent: false, pinned: false };
        let specs = vec![spec("web_fetch", "Fetch a URL over HTTP."), spec("browser_click", "Click a page element."), spec("memory", "Persistent memory.")];
        let cfg = Config::default();
        let out = tool_search(&specs, &cfg, &json!({"query": "click the button on the page"}));
        assert!(out.contains("browser_click"), "{out}");
        assert!(tool_search(&specs, &cfg, &json!({"query": "zzz-none"})).starts_with("No matching"));
    }

    #[test]
    fn micro_plan_absorbs_leading_exchanges_only() {
        use seagent_core::Message;
        let cfg: Config = toml::from_str("[compaction]\nmicro_compact = true\nmicro_compact_every_n_turns = 1\nkeep_messages = 2\n").unwrap();
        let st = CtxState::default();
        let mut v = View::default();
        for i in 0..6 {
            v.messages.push(if i % 2 == 0 { Message::user(format!("q{i}")) } else { Message::assistant(format!("a{i}")) });
        }
        let (start, end, summary, defrag) = micro_plan(&cfg, &st, "s", &v).unwrap();
        assert_eq!((start, end, summary.as_str(), defrag), (0, 2, "", false));
        assert_eq!(micro_commit(&st, "s", "q0 was answered by a0"), "q0 was answered by a0");
        // The rebuilt history starts at the summary message, so the next pass starts after it.
        let (start, end, summary, _) = micro_plan(&cfg, &st, "s", &v).unwrap();
        assert_eq!((start, end, summary.as_str()), (1, 2, "q0 was answered by a0"));
        // With the tail kept, the range never grows past it until new messages arrive.
        assert_eq!(micro_plan(&cfg, &st, "s", &v).map(|p| (p.0, p.1)), Some((1, 2)));
        assert_eq!(micro_summary(&st, "s").as_deref(), Some("q0 was answered by a0"));
        micro_reset(&st, "s");
        assert_eq!(micro_plan(&cfg, &st, "s", &v).unwrap().0, 0);
    }
}
