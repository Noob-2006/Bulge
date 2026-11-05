//! Manual partial compaction — `/compress here [N]`, `seagent compress here N --preview`
//! (Hermes `hermes_cli/partial_compress.py` + `agent/conversation_compression_manual.py`).
//!
//! "Up to here" compresses everything *before* the boundary and keeps the last `N` user
//! exchanges verbatim, so the recent work stays byte-identical instead of being paraphrased.
//! The summary is written as an ordinary `Compaction` event whose `upto_seq` is the first kept
//! message: the projection then keeps the tail verbatim and merges the handoff summary with the
//! kept user ask, which keeps user↔assistant alternation valid (Hermes
//! `rejoin_compressed_head_and_tail`).
//!
//! `--preview` reports the numbers the real run would use and changes nothing. `--aggressive`
//! (LLM-free hard truncation) has no persistence path here either, so it is refused with the
//! same wording instead of being mistaken for a focus topic.

use crate::args::Args;
use crate::slash::{Ctx, Reply};
use crate::R;
use seagent_core::{estimate_tokens, Cancel, Message};
use seagent_kernel::compaction;
use seagent_kernel::event::EventKind;
use seagent_kernel::kernel::Kernel;
use seagent_kernel::projection::{project, View};

/// Recent exchanges preserved verbatim when `here` has no explicit count.
pub const DEFAULT_KEEP_LAST: usize = 2;
/// Hard ceiling, so a fat-fingered `here 9999` clamps instead of no-op'ing.
pub const MAX_KEEP_LAST: usize = 100;
/// `/compress` needs a conversation to compress at all.
pub const MIN_MESSAGES: usize = 4;
pub const AGGRESSIVE_UNSUPPORTED: &str = "--aggressive is not supported; use '/compress here [N]' to keep only recent exchanges, or /undo to drop turns.";

const MAX_SUMMARY_TOKENS: u32 = 4096;
const SUMMARY_SYSTEM: &str = "You write faithful, dense handoff summaries.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub preview: bool,
    pub aggressive: bool,
    /// Boundary-aware (`here`/`--keep`) form.
    pub partial: bool,
    pub keep_last: usize,
    /// Anything else is a focus topic for the summary.
    pub focus: Option<String>,
}

impl Default for Request {
    fn default() -> Self {
        Request { preview: false, aggressive: false, partial: false, keep_last: DEFAULT_KEEP_LAST, focus: None }
    }
}

/// Parse the arguments after `/compress`: flags anywhere, then the boundary-aware or focus
/// positional forms (Hermes `extract_compress_flags` + `parse_partial_compress_args`).
pub fn parse_args(raw: &str) -> Request {
    let mut req = Request::default();
    let mut kept: Vec<&str> = Vec::new();
    for tok in raw.split_whitespace() {
        match tok.to_ascii_lowercase().as_str() {
            "--preview" | "--dry-run" | "--dryrun" => req.preview = true,
            "--aggressive" => req.aggressive = true,
            _ => kept.push(tok),
        }
    }
    let text = kept.join(" ");
    let text = text.trim();
    if text.is_empty() {
        return req;
    }
    let mut lowered = text.to_ascii_lowercase();
    let mut text = text;
    if let Some(rest) = lowered.strip_prefix("up to ") {
        lowered = rest.to_string();
        text = &text["up to ".len()..];
    }
    let toks: Vec<&str> = lowered.split_whitespace().collect();
    let head = toks.first().copied().unwrap_or("");
    if head == "here" {
        req.partial = true;
        req.keep_last = toks.get(1).map(|v| coerce_keep(v)).unwrap_or(DEFAULT_KEEP_LAST);
    } else if matches!(head, "--keep" | "-k") && toks.len() >= 2 {
        req.partial = true;
        req.keep_last = coerce_keep(toks[1]);
    } else if let Some(v) = head.strip_prefix("--keep=") {
        req.partial = true;
        req.keep_last = coerce_keep(v);
    } else {
        req.focus = Some(text.to_string()).filter(|t| !t.is_empty());
    }
    req
}

/// A keep-count token, clamped to `[1, MAX_KEEP_LAST]`; unparsable input keeps the default.
fn coerce_keep(v: &str) -> usize {
    match v.trim().parse::<i64>() {
        Ok(n) => (n.max(1) as usize).min(MAX_KEEP_LAST),
        Err(_) => DEFAULT_KEEP_LAST,
    }
}

/// Shared entry point for `/compress …` and `seagent compress …`.
pub fn cmd(k: &Kernel, session: &str, args: &str) -> Result<String, String> {
    if args.trim().is_empty() {
        // Plain `/compact`: the kernel's own pass (hooks, engine-owned compaction) decides.
        return Ok(if k.compact(session).map_err(|e| e.to_string())? { "compacted".to_string() } else { "nothing to compact".to_string() });
    }
    let req = parse_args(args);
    if req.aggressive && !req.preview {
        return Ok(AGGRESSIVE_UNSUPPORTED.to_string());
    }
    run(k, session, &req)
}

/// Compress (or, with `preview`, only report) up to the boundary.
pub fn run(k: &Kernel, session: &str, req: &Request) -> Result<String, String> {
    let view = project(&k.store.read(session).map_err(|e| e.to_string())?);
    let total = view.messages.len();
    if total < MIN_MESSAGES {
        return Ok(format!("Not enough conversation to compress (need at least {MIN_MESSAGES} messages)."));
    }
    let before = estimate_tokens(&compaction::render_transcript(&view.messages, usize::MAX));
    // `here N` first; a degenerate split falls back to full compression (never a no-op rotation).
    let partial_cut = if req.partial { compaction::partial_cut_index(&view.messages, req.keep_last) } else { None };
    let partial = partial_cut.is_some();
    let cut = partial_cut.or_else(|| compaction::cut_index(&view.messages, k.cfg.compaction.keep_messages));
    if req.preview {
        return Ok(preview_text(&view, cut, before, req, partial));
    }
    let Some(cut) = cut else {
        return Ok("Nothing to compress yet (the whole conversation is protected context).".to_string());
    };
    let head = &view.messages[..cut];
    let (summary, fallback) = summarise(k, head, req.focus.as_deref());
    let mut log = k.store.open(session).map_err(|e| e.to_string())?;
    log.append(EventKind::Compaction { upto_seq: view.message_seqs[cut], summary: summary.clone(), pruned: vec![], tokens_before: before })
        .map_err(|e| e.to_string())?;
    drop(log);

    let tail = &view.messages[cut..];
    let after = estimate_tokens(&compaction::render_transcript(tail, usize::MAX)) + estimate_tokens(&summary);
    let mut lines = vec![if partial {
        format!("Compressed {cut} of {total} messages, keeping the last {} exchange(s) ({} message(s)) verbatim.", req.keep_last, tail.len())
    } else {
        format!("Compressed {cut} of {total} messages.")
    }];
    if let Some(f) = &req.focus {
        lines.push(format!("Focus: \"{f}\""));
    }
    lines.push(format!("Tokens: ~{before} → ~{after}"));
    if fallback {
        lines.push("Note: the summary model was unavailable or returned a low-quality summary; a deterministic digest was used.".to_string());
    }
    Ok(lines.join("\n"))
}

/// The `/compress --preview` report — pure, no side effects.
fn preview_text(view: &View, cut: Option<usize>, tokens: u64, req: &Request, partial: bool) -> String {
    let total = view.messages.len();
    let head = cut.unwrap_or(0);
    if head == 0 {
        return "Nothing to compress yet (the whole conversation is protected context).".to_string();
    }
    let mut lines = vec![
        "Preview — no changes made.".to_string(),
        format!("Would compress {head} of {total} message(s) (~{tokens} tokens currently in context)."),
    ];
    if partial {
        lines.push(format!("Boundary: keeping the last {} exchange(s) ({} message(s)) verbatim.", req.keep_last, total - head));
    } else if req.partial {
        lines.push("Boundary: 'here' split would keep everything — falling back to full compression.".to_string());
    }
    if let Some(f) = &req.focus {
        lines.push(format!("Focus topic: \"{f}\""));
    }
    if req.aggressive {
        lines.push(AGGRESSIVE_UNSUPPORTED.to_string());
    }
    lines.push("Run the command again without --preview to apply.".to_string());
    lines.join("\n")
}

/// Ask the aux model for a handoff summary of the head; one retry, deterministic fallback.
/// The quality gate is the kernel's, so a low-quality reply never reaches the log.
fn summarise(k: &Kernel, head: &[Message], focus: Option<&str>) -> (String, bool) {
    let transcript = compaction::render_transcript(head, 2000);
    let mut prompt = compaction::summary_prompt(&transcript);
    if let Some(f) = focus.filter(|f| !f.trim().is_empty()) {
        prompt.push_str(&format!(
            "\n\nPrioritise everything related to this topic: \"{f}\". For that topic keep exact values, file paths, \
command output, error messages and decisions; summarise unrelated material into brief one-liners."
        ));
    }
    let model = k.cfg.task_model("compaction").to_string();
    for _ in 0..2 {
        let r = k.sample(Some(&model), SUMMARY_SYSTEM, vec![Message::user(prompt.clone())], vec![], MAX_SUMMARY_TOKENS, &Cancel::new());
        if let Ok((m, _, _)) = r {
            let text = m.text();
            if compaction::summary_ok(&text, transcript.len()) {
                return (text, false);
            }
        }
    }
    (compaction::fallback_summary(head), true)
}

// ───────────── surfaces ─────────────

/// `/compress …` (also `/compact …`).
pub fn slash(c: &Ctx, args: &str) -> Result<Reply, String> {
    let id = c.session.as_deref().ok_or_else(|| "no session yet — send a message first".to_string())?;
    Ok(Reply { text: Some(cmd(c.k, id, args)?), ..Default::default() })
}

pub const COMMANDS: &[&str] = &["compress"];
pub const VALUE_FLAGS: &[&str] = &["keep"];
pub const BOOL_FLAGS: &[&str] = &["preview", "aggressive"];

/// `seagent compress [here [N]|up to here [N]] [--keep N] [--preview] [--aggressive] [focus] [-s session]`
pub fn dispatch(cmd_name: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if !COMMANDS.contains(&cmd_name) {
        return None;
    }
    Some((|| -> R {
        let mut arg = a.rest(0);
        if let Some(k) = a.val("keep") {
            arg = format!("--keep {k} {arg}");
        }
        if a.flag("preview") {
            arg = format!("--preview {arg}");
        }
        if a.flag("aggressive") {
            arg = format!("--aggressive {arg}");
        }
        let c = crate::build_agent(a, crate::approver_for(a, false), false)?;
        let id = match a.val("session") {
            Some(s) => s.to_string(),
            None => c.k.store.list().first().map(|s| s.id.clone()).ok_or("no sessions yet — start one with `seagent chat`")?,
        };
        println!("{}", cmd(&c.k, &id, &arg)?);
        Ok(0)
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_core::{ModelCaps, ModelRequest, ModelResponse, Provider, ProviderError, StopReason, StreamEvent, Usage};
    use seagent_kernel::approver::Policy;
    use seagent_kernel::config::{Config, Paths};
    use seagent_kernel::kernel::{new_kernel, Resolver, RunOpts};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    /// Echoes `<tag>` for normal turns and a shape-controlled summary for compaction prompts.
    struct Stub {
        summary: Mutex<Option<String>>,
        seen: Mutex<Vec<String>>,
    }

    impl Provider for Stub {
        fn id(&self) -> &str {
            "stub"
        }
        fn caps(&self, _: &str) -> ModelCaps {
            ModelCaps { context_window: 100_000, max_output: 4096, tools: true, vision: false, explicit_cache: false }
        }
        fn complete(&self, req: &ModelRequest, _: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
            let last = req.messages.last().map(|m| m.text()).unwrap_or_default();
            self.seen.lock().unwrap().push(last.chars().take(4000).collect());
            let text = if last.contains("Summarise the conversation") {
                self.summary.lock().unwrap().clone().unwrap_or_else(|| "too short".into())
            } else {
                format!("did: {}", last.chars().take(60).collect::<String>())
            };
            Ok(ModelResponse { message: Message::assistant(text), stop: StopReason::EndTurn, usage: Usage::default(), model: "m".into() })
        }
    }

    struct Res(Arc<Stub>);
    impl Resolver for Res {
        fn provider(&self, _: &str) -> Result<Arc<dyn Provider>, String> {
            Ok(self.0.clone())
        }
    }

    struct Env {
        k: Kernel,
        ws: PathBuf,
        stub: Arc<Stub>,
    }

    fn env() -> Env {
        let root = seagent_core::tmp::scratch_path(format!("seagent-partial-{}", seagent_kernel::util::random_hex(8)));
        let ws = root.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let ws = ws.canonicalize().unwrap();
        let mut cfg = Config::default();
        cfg.model.default = "stub/m".into();
        cfg.checkpoint.enabled = false;
        let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
        let stub = Arc::new(Stub { summary: Mutex::new(None), seen: Mutex::new(vec![]) });
        let k = new_kernel(cfg, paths, Arc::new(Res(stub.clone())), vec![], Arc::new(seagent_kernel::vault::Vault::empty()), Arc::new(Policy { allow_privilege: false, allow_egress: false }));
        Env { k, ws, stub }
    }

    fn good_summary() -> String {
        format!(
            "{}\nfix the parser\n{}\nedited src/a.rs, tests pass\n{}\nuses cargo test\n{}\nsrc/a.rs\n{}\nnone",
            compaction::HEADINGS[0], compaction::HEADINGS[1], compaction::HEADINGS[2], compaction::HEADINGS[3], compaction::HEADINGS[4]
        )
    }

    /// A session with `n` finished exchanges (user ask + assistant reply each).
    fn session(e: &Env, n: usize) -> String {
        let id = e.k.create_session(&e.ws, None, None, None).unwrap();
        for i in 0..n {
            e.k.submit(&id, &format!("ask {i}"), "cli").unwrap();
            e.k.run(&id, RunOpts::default()).unwrap();
        }
        id
    }

    fn messages(e: &Env, id: &str) -> Vec<Message> {
        project(&e.k.store.read(id).unwrap()).messages
    }

    #[test]
    fn parse_args_covers_every_documented_form() {
        let r = parse_args("");
        assert_eq!(r, Request::default(), "plain /compress");
        assert_eq!(parse_args("here"), Request { partial: true, keep_last: DEFAULT_KEEP_LAST, ..Default::default() });
        assert_eq!(parse_args("here 3").keep_last, 3);
        assert_eq!(parse_args("up to here 4").keep_last, 4);
        assert_eq!(parse_args("--keep 5").keep_last, 5);
        assert_eq!(parse_args("-k 6").keep_last, 6);
        assert_eq!(parse_args("--keep=7").keep_last, 7);
        assert_eq!(parse_args("here 9999").keep_last, MAX_KEEP_LAST, "clamped, not a no-op");
        assert_eq!(parse_args("here 0").keep_last, 1);
        assert_eq!(parse_args("here nope").keep_last, DEFAULT_KEEP_LAST, "unparsable keeps the default");
        assert_eq!(parse_args("fix the auth bug").focus.as_deref(), Some("fix the auth bug"));
        assert_eq!(parse_args("here 2 fix the bug").focus, None, "a count makes it partial, not a focus");
        let p = parse_args("here 3 --preview --aggressive");
        assert!(p.preview && p.aggressive && p.partial && p.keep_last == 3, "flags are stripped anywhere");
        let p = parse_args("--dry-run the login flow");
        assert!(p.preview && p.focus.as_deref() == Some("the login flow"));
    }

    #[test]
    fn here_keeps_the_recent_exchanges_verbatim() {
        let e = env();
        *e.stub.summary.lock().unwrap() = Some(good_summary());
        let id = session(&e, 3);
        let before = messages(&e, &id);
        assert_eq!(before.len(), 6, "{before:?}");
        let out = cmd(&e.k, &id, "here 1").unwrap();
        assert!(out.contains("Compressed 4 of 6 messages, keeping the last 1 exchange(s) (2 message(s)) verbatim."), "{out}");
        assert!(!out.contains("deterministic digest"), "the model summary was good: {out}");
        let after = messages(&e, &id);
        assert_eq!(after.len(), 2, "summary + the kept exchange: {after:?}");
        let seam = after[0].text();
        assert!(seam.contains("Summary of earlier conversation") && seam.contains("## Progress"), "{seam}");
        assert!(seam.ends_with("ask 2"), "the kept ask survives verbatim at the seam: {seam}");
        assert_eq!(after[1].text(), "did: ask 2", "and so does its reply");
        assert!(!after.iter().any(|m| m.text() == "ask 0"), "the summarised head is gone");
        // The kept prompt is what the next turn still sends.
        e.k.submit(&id, "continue", "cli").unwrap();
        e.k.run(&id, RunOpts::default()).unwrap();
        let req = e.stub.seen.lock().unwrap().last().cloned().unwrap_or_default();
        assert!(req.contains("continue"));
    }

    #[test]
    fn here_without_a_summary_model_falls_back_to_the_digest() {
        let e = env();
        let id = session(&e, 2);
        let out = cmd(&e.k, &id, "up to here 1").unwrap();
        assert!(out.contains("Compressed 2 of 4 messages"), "{out}");
        assert!(out.contains("deterministic digest"), "{out}");
        let after = messages(&e, &id);
        let head = after[0].text();
        assert!(head.contains("ask 0"), "the digest keeps the user's own words: {head}");
        assert!(head.ends_with("ask 1"), "{head}");
        assert_eq!(after.last().unwrap().text(), "did: ask 1");
    }

    #[test]
    fn preview_reports_without_touching_the_session() {
        let e = env();
        let id = session(&e, 3);
        let before = e.k.store.read(&id).unwrap().len();
        let out = cmd(&e.k, &id, "here 2 --preview").unwrap();
        assert!(out.starts_with("Preview — no changes made."), "{out}");
        assert!(out.contains("Would compress 2 of 6 message(s)"), "{out}");
        assert!(out.contains("keeping the last 2 exchange(s) (4 message(s)) verbatim"), "{out}");
        assert!(out.ends_with("Run the command again without --preview to apply."), "{out}");
        assert_eq!(e.k.store.read(&id).unwrap().len(), before, "nothing was written");
        assert_eq!(messages(&e, &id).len(), 6);
    }

    #[test]
    fn a_degenerate_here_split_falls_back_to_full_compression() {
        let e = env();
        let id = session(&e, 2);
        let out = cmd(&e.k, &id, "here 99 --preview").unwrap();
        assert!(out.contains("'here' split would keep everything — falling back to full compression."), "{out}");
        // And the real run still compacts rather than rotating the session for a no-op.
        let out = cmd(&e.k, &id, "here 99").unwrap();
        assert!(out.contains("Compressed 1 of 4 messages."), "{out}");
        assert!(messages(&e, &id)[0].text().contains("Summary of earlier conversation"));
    }

    #[test]
    fn short_sessions_and_aggressive_are_refused() {
        let e = env();
        let id = e.k.create_session(&e.ws, None, None, None).unwrap();
        e.k.submit(&id, "only one ask", "cli").unwrap();
        e.k.run(&id, RunOpts::default()).unwrap();
        assert_eq!(cmd(&e.k, &id, "here 1").unwrap(), "Not enough conversation to compress (need at least 4 messages).");
        let id = session(&e, 3);
        assert_eq!(cmd(&e.k, &id, "--aggressive").unwrap(), AGGRESSIVE_UNSUPPORTED);
        let p = cmd(&e.k, &id, "--aggressive --preview").unwrap();
        assert!(p.contains("Preview") && p.contains("--aggressive is not supported"), "{p}");
        // Plain `/compress` is the kernel's own pass.
        assert_eq!(cmd(&e.k, &id, "").unwrap(), "compacted");
    }

    #[test]
    fn slash_route_reaches_partial_compaction() {
        let e = env();
        let id = session(&e, 3);
        let c = crate::slash::Ctx { k: &e.k, ext: None, session: Some(id.clone()), workspace: e.ws.clone(), surface: crate::slash::Surface::Cli, sender: None, notify: None };
        assert_eq!(crate::slash::find("compress").map(|d| d.name), Some("compact"));
        let out = crate::slash::run(&c, "/compress here 1 --preview").unwrap().text.unwrap();
        assert!(out.starts_with("Preview — no changes made."), "{out}");
        assert!(out.contains("keeping the last 1 exchange(s) (2 message(s)) verbatim"), "{out}");
        let out = crate::slash::run(&c, "/compress up to here 1").unwrap().text.unwrap();
        assert!(out.contains("Compressed 4 of 6"), "{out}");
        // Plain `/compact` stays the kernel's own pass, in its own session.
        let fresh = session(&e, 2);
        let c2 = crate::slash::Ctx { session: Some(fresh), ..c };
        assert_eq!(crate::slash::run(&c2, "/compact").unwrap().text.unwrap(), "compacted");
    }

    /// The native-compaction config key has to reach the provider through the request built for
    /// every step (`crates/seagent-model/src/native_compact.rs` turns it into `context_management`).
    #[test]
    fn native_compaction_config_reaches_the_model_request() {
        let t = crate::testkit::kit_with(|c| c.compaction.native.enabled = true);
        let id = t.k.create_session(&t.ws, None, None, None).unwrap();
        t.k.submit(&id, "hi", "cli").unwrap();
        t.k.run(&id, RunOpts::default()).unwrap();
        let req = t.echo.seen.lock().unwrap().last().cloned().unwrap();
        // The echo provider reports a 100k window: 100k × 0.75 − 8192 stays below the local trigger.
        assert_eq!(req.options.native_compaction, Some(66_808));
        // Off by default: local compaction only.
        let t2 = crate::testkit::kit();
        let id2 = t2.k.create_session(&t2.ws, None, None, None).unwrap();
        t2.k.submit(&id2, "hi", "cli").unwrap();
        t2.k.run(&id2, RunOpts::default()).unwrap();
        assert_eq!(t2.echo.seen.lock().unwrap().last().unwrap().options.native_compaction, None);
    }

    #[test]
    fn focus_topic_is_forwarded_to_the_summariser() {
        let e = env();
        *e.stub.summary.lock().unwrap() = Some(good_summary());
        let id = session(&e, 2);
        let out = cmd(&e.k, &id, "the auth bug").unwrap();
        assert!(out.contains("Focus: \"the auth bug\""), "{out}");
        let seen = e.stub.seen.lock().unwrap();
        assert!(seen.iter().any(|p| p.contains("Summarise the conversation")), "the summariser ran");
        let full = format!("{:?}", seen);
        assert!(full.contains("Prioritise everything related to this topic"), "focus reaches the prompt");
    }
}
