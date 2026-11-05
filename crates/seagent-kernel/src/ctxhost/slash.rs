//! Native slash commands for the context features. Registered by `ctxhost::attach` through
//! `Kernel::add_slash`, so `Kernel::run_slash` answers them on every surface (channels included,
//! where only native commands exist).
//!
//! - `/context` (Hermes `hermes_cli/commands.py` + `agent/context_breakdown.py`): what this
//!   session's context window is made of, what is biggest, and what compaction would drop.
//! - `/compact`, `/compress [here N] [--preview]` (Hermes `hermes_cli/partial_compress.py`,
//!   `agent/conversation_compression_manual.py`): compact now, or report the plan.
//! - `/title [text]` (Hermes `hermes_cli/commands.py`): set, show, or generate the session name.
//! - `/btw <question>` (Hermes `agent/side_question.py`): answer against a snapshot of the
//!   conversation without appending anything to it.
//! - `/personality [name|list|none]` (Hermes `hermes_cli/personality.py`): the persona overlay.
//! - `/role [list|<occupation>|none]`: the professional role (`ctxhost/role.rs`).

use super::{persona, title as titles, workspace_of, Host};
use crate::compaction;
use crate::context;
use crate::kernel::Kernel;
use crate::projection::{project, View};
use crate::slash::{Slash, SlashCtx, SlashReply};
use seagent_core::{estimate_tokens, Block, Message, Role};
use std::sync::Arc;

/// `here` without a count keeps the last two exchanges verbatim (upstream `DEFAULT_KEEP_LAST`).
pub const DEFAULT_KEEP_LAST: usize = 2;
/// A fat-fingered `here 9999` clamps instead of no-op'ing (upstream `MAX_KEEP_LAST`).
pub const MAX_KEEP_LAST: usize = 100;
/// Characters of one message shown in a report preview.
const PREVIEW_CHARS: usize = 60;
/// `/btw` answers within these budgets so one side question cannot cost a whole context window.
pub const SIDE_MAX_TOKENS: u32 = 2048;
const SIDE_TRANSCRIPT_CHARS: usize = 24_000;
const SIDE_PER_MESSAGE_CHARS: usize = 2_000;

pub const AGGRESSIVE_UNSUPPORTED: &str =
    "--aggressive is not supported; use '/compress here [N]' to keep only recent exchanges, or /undo to drop turns.";

/// Hermes `_FORK_PROMPT`: the side question must not turn into a second main turn.
pub const BTW_PROMPT: &str = "The user asked a quick SIDE question with /btw while the main work continues in the original session.\nRules:\n- Answer ONLY the side question, using the conversation above as context. Do not continue, redo, or critique the main task.\n- Do NOT call any tools — they are disabled for this side question. Answer directly in text.\n- If the conversation does not contain enough information to answer, say so plainly instead of guessing.\n- Be concise and direct.";

pub struct CtxSlash(pub Arc<Host>);

impl Slash for CtxSlash {
    fn commands(&self) -> Vec<(String, String)> {
        vec![
            ("context".into(), "This session's context window: system prompt, tool schemas, messages, the largest pieces and what compaction would drop".into()),
            ("compact".into(), "Compact this session's context now and report the before/after size".into()),
            ("compress".into(), "Alias of /compact: '/compress here N' summarises everything before the last N exchanges and keeps that tail verbatim; '--preview' changes nothing".into()),
            ("title".into(), "Show, set or generate this session's title: /title [text]".into()),
            ("btw".into(), "Ask a side question about this conversation without adding it to the history: /btw <question>".into()),
            ("personality".into(), "Show or set the persona overlay: /personality [name|list|none]".into()),
            ("role".into(), "Show or set the professional role (ISCO occupation or preset): /role [list [words]|<code or name>|none]".into()),
        ]
    }

    fn run(&self, c: &SlashCtx, name: &str, args: &str) -> Option<Result<SlashReply, String>> {
        let k = &c.kernel;
        let sid = c.session.as_deref();
        Some(match name {
            "context" | "ctx" => Ok(SlashReply::text(context_report(k, sid))),
            "compact" | "compress" => Ok(SlashReply::text(compress(k, sid, args))),
            "title" | "name" => Ok(SlashReply::text(set_or_show_title(k, self.0.titles(), sid, args))),
            "btw" | "side" => side_question(k, sid, args).map(SlashReply::text),
            "personality" => Ok(SlashReply::text(personality_command(&self.0, k, sid, args))),
            "role" | "roles" => Ok(SlashReply::text(super::role::command(&self.0, k, sid, args))),
            _ => return None,
        })
    }
}

fn n(v: u64) -> String {
    let s = v.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Thousands-separated tokens with a percent of the window.
fn frac(tokens: u64, total: u64) -> String {
    if total == 0 {
        return "  -".into();
    }
    format!("{:>3}%", (tokens.saturating_mul(100) / total).min(999))
}

fn one_line(text: &str, max: usize) -> String {
    let t = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.chars().count() <= max {
        return t;
    }
    let mut cut: String = t.chars().take(max).collect();
    cut.push('…');
    cut
}

/// Context window of `model` (provider caps, else the kernel's 128k fallback).
pub fn window_of(k: &Kernel, model: &str) -> u64 {
    let (pid, m) = context::split_model(model);
    k.resolver.provider(pid).map(|p| p.caps(m).context_window).ok().filter(|w| *w > 0).unwrap_or(128_000)
}

fn block_tokens(b: &Block) -> u64 {
    let n = match b {
        Block::Text { text } | Block::Thinking { text, .. } => estimate_tokens(text),
        Block::ToolUse { name, input, .. } => estimate_tokens(name) + estimate_tokens(&input.to_string()),
        Block::ToolResult { content, .. } => estimate_tokens(content),
        Block::Image { .. } => seagent_core::IMAGE_TOKENS,
    };
    n + 4
}

pub fn message_tokens(m: &Message) -> u64 {
    m.content.iter().map(block_tokens).sum()
}

/// Tool schema cost of the tools this session is actually offered (pinned + the meta tools).
pub fn tool_tokens(k: &Kernel, cfg: &crate::config::Config) -> (usize, u64) {
    let specs = k.specs();
    let tv = context::split_tools(&specs, cfg);
    let mut tokens: u64 = tv.pinned.iter().map(|s| estimate_tokens(&s.description) + estimate_tokens(&s.input_schema.to_string())).sum();
    if !tv.unpinned.is_empty() {
        tokens += context::meta_tools().iter().map(|t| estimate_tokens(&t.description) + estimate_tokens(&t.input_schema.to_string())).sum::<u64>();
    }
    (tv.pinned.len() + usize::from(!tv.unpinned.is_empty()) * context::meta_tools().len(), tokens)
}

/// Whole-request estimate: system prompt + tool schemas + transcript.
pub fn request_tokens(k: &Kernel, view: &View) -> u64 {
    let cfg = k.cfg_now();
    let system: u64 = view.system.iter().map(|s| estimate_tokens(&s.text) + 4).sum();
    system + tool_tokens(k, &cfg).1 + view.messages.iter().map(message_tokens).sum::<u64>()
}

fn view_for(k: &Kernel, session: Option<&str>, cfg: &crate::config::Config) -> (View, bool) {
    if let Some(ev) = session.and_then(|s| k.store.read(s).ok()) {
        return (project(&ev), true);
    }
    let ws = workspace_of(k, session);
    let segs = context::system_segments(cfg, &k.paths, &ws, &k.specs(), cfg.schedule.utc_offset_minutes);
    (View { workspace: ws.to_string_lossy().into(), model: cfg.model.default.clone(), system: segs, ..Default::default() }, false)
}

/// `/context`: this session's context usage, biggest pieces first, and what compaction would drop.
pub fn context_report(k: &Kernel, session: Option<&str>) -> String {
    let cfg = k.cfg_now();
    let (view, live) = view_for(k, session, &cfg);
    let window = window_of(k, &view.model);
    let mut out = String::new();
    match (live, session) {
        (true, Some(sid)) => out.push_str(&format!("Context — session {sid}\n")),
        _ => out.push_str(&format!("Context — no session yet, showing the defaults a new session in {} starts with\n", view.workspace)),
    }
    out.push_str(&format!("model {} · window {} tokens\n", if view.model.is_empty() { "(none)" } else { &view.model }, n(window)));

    let system_tokens: u64 = view.system.iter().map(|s| estimate_tokens(&s.text) + 4).sum();
    let (tool_count, tools_tokens) = tool_tokens(k, &cfg);
    let msg_tokens: u64 = view.messages.iter().map(message_tokens).sum();
    let estimate = system_tokens + tools_tokens + msg_tokens;
    let used = if view.last_input_tokens > 0 { view.last_input_tokens } else { estimate };
    out.push_str(&format!(
        "usage ~{} tokens {} of the window{}\n",
        n(used),
        frac(used, window),
        if view.last_input_tokens > 0 { " (provider-reported last request)" } else { " (estimate: no usage event yet)" }
    ));

    out.push_str(&format!("system prompt: ~{} tokens in {} segment(s)\n", n(system_tokens), view.system.len()));
    let mut segs: Vec<(String, u64)> = view.system.iter().map(|s| (s.id.clone(), estimate_tokens(&s.text) + 4)).collect();
    segs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (id, tok) in segs.iter().take(5) {
        out.push_str(&format!("  {:14} {:>9} {}\n", id, n(*tok), frac(*tok, system_tokens)));
    }
    if segs.len() > 5 {
        out.push_str(&format!("  (+{} smaller)\n", segs.len() - 5));
    }
    out.push_str(&super::role::context_line(k, session));
    out.push_str(&format!("tool schemas: {} offered, ~{} tokens\n", tool_count, n(tools_tokens)));

    let users = view.messages.iter().filter(|m| m.role == Role::User && !m.content.iter().any(|b| matches!(b, Block::ToolResult { .. }))).count();
    let results = view.messages.iter().filter(|m| m.content.iter().any(|b| matches!(b, Block::ToolResult { .. }))).count();
    let assistants = view.messages.iter().filter(|m| m.role == Role::Assistant).count();
    out.push_str(&format!(
        "messages: {} ({} user, {} assistant, {} with tool results) ~{} tokens\n",
        view.messages.len(),
        users,
        assistants,
        results,
        n(msg_tokens)
    ));

    let mut big: Vec<(usize, u64)> = view.messages.iter().enumerate().map(|(i, m)| (i, message_tokens(m))).collect();
    big.sort_by_key(|a| std::cmp::Reverse(a.1));
    if !big.is_empty() {
        out.push_str("largest messages:\n");
        for (i, tok) in big.iter().take(3) {
            let m = &view.messages[*i];
            let seq = view.message_seqs.get(*i).copied().unwrap_or(0);
            let role = if m.role == Role::User { "user" } else { "assistant" };
            out.push_str(&format!("  #{} {} seq {} ~{} tok — \"{}\"\n", i, role, seq, n(*tok), one_line(&m.text(), PREVIEW_CHARS)));
        }
    }

    out.push_str(&format!(
        "compaction: {} so far · auto at {} tokens ({} of the window) · keeps the last {} messages\n",
        view.compactions,
        n((cfg.compaction.threshold * window as f64) as u64),
        frac((cfg.compaction.threshold * window as f64) as u64, window),
        cfg.compaction.keep_messages
    ));
    match compaction::cut_index(&view.messages, cfg.compaction.keep_messages) {
        Some(cut) if cut > 0 => {
            let dropped: u64 = view.messages[..cut].iter().map(message_tokens).sum();
            out.push_str(&format!(
                "compaction would drop {} message(s) (~{} tokens) into one summary, keeping {}\n",
                cut,
                n(dropped),
                view.messages.len() - cut
            ));
        }
        _ => out.push_str("compaction would drop nothing yet (the history is shorter than the keep window)\n"),
    }
    let prune = compaction::prune_candidates(&view, cfg.compaction.keep_tool_results);
    if !prune.is_empty() {
        out.push_str(&format!("prunable tool output: {} result(s) — pruned first, no model call\n", prune.len()));
    }
    if view.compactions > 0 {
        if let Some(first) = view.messages.first().filter(|m| m.role == Role::User && m.text().starts_with("[Summary of earlier conversation]")) {
            out.push_str(&format!("the head is a compaction summary (~{} tokens)\n", n(message_tokens(first))));
        }
    }
    out.push_str("Details: /compact --preview · /compact for the real thing.");
    out
}

/// Parsed `/compress` / `/compact` arguments (Hermes `parse_compress_args`).
#[derive(Debug, Clone, PartialEq)]
pub struct CompressPlan {
    pub preview: bool,
    pub aggressive: bool,
    pub partial: bool,
    pub keep_last: usize,
    pub focus: Option<String>,
}

fn coerce_keep(v: &str) -> usize {
    v.parse::<usize>().map(|n| n.clamp(1, MAX_KEEP_LAST)).unwrap_or(DEFAULT_KEEP_LAST)
}

pub fn parse_compress(raw: &str) -> CompressPlan {
    let mut preview = false;
    let mut aggressive = false;
    let mut kept: Vec<&str> = Vec::new();
    for tok in raw.split_whitespace() {
        match tok.to_lowercase().as_str() {
            "--preview" | "--dry-run" | "--dryrun" => preview = true,
            "--aggressive" => aggressive = true,
            _ => kept.push(tok),
        }
    }
    let text = kept.join(" ");
    let lower = text.to_lowercase();
    let (text, lower) = match lower.strip_prefix("up to ") {
        Some(rest) => (text[6..].to_string(), rest.to_string()),
        None => (text.clone(), lower.clone()),
    };
    let tokens: Vec<&str> = lower.split_whitespace().collect();
    let head = tokens.first().copied().unwrap_or("");
    let mut plan = CompressPlan { preview, aggressive, partial: false, keep_last: DEFAULT_KEEP_LAST, focus: None };
    if head == "here" {
        plan.partial = true;
        if let Some(v) = tokens.get(1) {
            plan.keep_last = coerce_keep(v);
        }
    } else if (head == "--keep" || head == "-k") && tokens.len() >= 2 {
        plan.partial = true;
        plan.keep_last = coerce_keep(tokens[1]);
    } else if let Some(v) = head.strip_prefix("--keep=") {
        plan.partial = true;
        plan.keep_last = coerce_keep(v);
    } else {
        plan.focus = Some(text.trim().to_string()).filter(|t| !t.is_empty());
    }
    plan
}

/// `/compact` (and `/compress`): compact now, or report what would happen.
///
/// `here N` runs a boundary-aware partial compaction: everything before the start of the last `N`
/// user exchanges becomes one handoff summary and the tail stays byte-identical, so the recent work
/// is never paraphrased (Hermes `split_history_for_partial_compress`). A degenerate split (nothing
/// older than the first ask) falls back to full compaction instead of rotating the session for a
/// no-op. `--preview` reports the numbers the real run would use and changes nothing.
pub fn compress(k: &Kernel, session: Option<&str>, args: &str) -> String {
    let plan = parse_compress(args);
    let Some(sid) = session else {
        return "No session yet — send a message first.".into();
    };
    if plan.aggressive && !plan.preview {
        return AGGRESSIVE_UNSUPPORTED.into();
    }
    let cfg = k.cfg_now();
    let started = std::time::Instant::now();
    if args.trim().is_empty() {
        // Plain `/compact`: the kernel's own pass decides (hooks, engine-owned compaction, pruning).
        let total = k.store.read(sid).map(|ev| project(&ev).messages.len()).unwrap_or(0);
        if total == 0 {
            return "Nothing to compress yet.".into();
        }
        let tokens_before = k.store.read(sid).map(|ev| request_tokens(k, &project(&ev))).unwrap_or(0);
        return match k.compact(sid) {
            Ok(true) => {
                let after = k.store.read(sid).map(|ev| project(&ev)).unwrap_or_default();
                let after_tokens = request_tokens(k, &after);
                let mut out = format!("Compressed: {} → {} messages", total, after.messages.len());
                out.push_str(&format!("\nApprox request size: ~{} → ~{} tokens", n(tokens_before), n(after_tokens)));
                out.push_str(&format!("\n{:.1}s · the prompt cache restarts after a compaction.", started.elapsed().as_secs_f32()));
                if after.messages.len() >= total {
                    out.push_str("\nNote: fewer messages can still raise this estimate when compaction rewrites the transcript into denser summaries.");
                }
                out
            }
            Ok(false) => "Nothing to compress yet.".into(),
            Err(e) => format!("/compact failed: {e}"),
        };
    }
    let view = match k.store.read(sid) {
        Ok(ev) => project(&ev),
        Err(e) => return format!("cannot read session {sid}: {e}"),
    };
    let total = view.messages.len();
    let tokens_before = request_tokens(k, &view);
    let partial_cut = if plan.partial { compaction::partial_cut_index(&view.messages, plan.keep_last) } else { None };
    let partial = partial_cut.is_some();
    let cut = partial_cut.or_else(|| compaction::cut_index(&view.messages, cfg.compaction.keep_messages));
    if plan.preview {
        let Some(cut) = cut.filter(|c| *c > 0) else {
            return "Nothing to compress yet (the whole conversation is protected context).".into();
        };
        let mut lines = vec![
            "Preview — no changes made.".to_string(),
            format!("Would compress {} of {} message(s) (~{} tokens currently in context).", cut, total, n(tokens_before)),
        ];
        if partial {
            lines.push(format!("Boundary: keeping the last {} exchange(s) ({} message(s)) verbatim.", plan.keep_last, total - cut));
        } else if plan.partial {
            lines.push("Boundary: 'here' split would keep everything — falling back to full compression.".into());
        } else {
            lines.push(format!("Boundary: keeping the last {} message(s) verbatim.", total - cut));
        }
        if let Some(f) = &plan.focus {
            lines.push(format!("Focus topic: \"{f}\""));
        }
        let dropped: u64 = view.messages[..cut].iter().map(message_tokens).sum();
        lines.push(format!("Saving: ~{} tokens moved into one summary.", n(dropped)));
        if plan.aggressive {
            lines.push(AGGRESSIVE_UNSUPPORTED.into());
        }
        lines.push("Run the command again without --preview to apply.".into());
        return lines.join("\n");
    }
    let Some(cut) = cut.filter(|c| *c > 0) else {
        return "Nothing to compress yet (the whole conversation is protected context).".into();
    };
    let (summary, fallback) = summarise_head(k, &view.messages[..cut], plan.focus.as_deref());
    let seq = view.message_seqs.get(cut).copied().unwrap_or_else(|| view.message_seqs.last().copied().unwrap_or(0));
    let mut log = match k.store.open(sid) {
        Ok(l) => l,
        Err(e) => return format!("cannot write session {sid}: {e}"),
    };
    if let Err(e) = log.append(crate::event::EventKind::Compaction { upto_seq: seq, summary, pruned: vec![], tokens_before }) {
        return format!("cannot record the compaction: {e}");
    }
    drop(log);
    let after = k.store.read(sid).map(|ev| project(&ev)).unwrap_or_default();
    let after_tokens = request_tokens(k, &after);
    let mut out = if partial {
        format!("Compressed {} of {} messages, keeping the last {} exchange(s) ({} message(s)) verbatim.", cut, total, plan.keep_last, total - cut)
    } else {
        format!("Compressed: {} → {} messages", total, after.messages.len())
    };
    out.push_str(&format!("\nApprox request size: ~{} → ~{} tokens", n(tokens_before), n(after_tokens)));
    if let Some(f) = &plan.focus {
        out.push_str(&format!("\nFocus: \"{f}\""));
    }
    if fallback {
        out.push_str("\nNote: the summary model was unavailable or low-quality; a deterministic digest was used.");
    }
    out.push_str(&format!("\n{:.1}s · the prompt cache restarts after a compaction.", started.elapsed().as_secs_f32()));
    out
}

/// Ask the aux model for a handoff summary of `head`; one retry, deterministic fallback. The
/// kernel's quality gate decides, so a low-quality reply never reaches the log.
fn summarise_head(k: &Kernel, head: &[Message], focus: Option<&str>) -> (String, bool) {
    let transcript = compaction::render_transcript(head, 2_000);
    let mut prompt = compaction::summary_prompt(&transcript);
    if let Some(f) = focus.filter(|f| !f.trim().is_empty()) {
        prompt.push_str(&format!(
            "\n\nPrioritise everything related to this topic: \"{f}\". For that topic keep exact values, file paths, command output, error messages and decisions; summarise unrelated material into brief one-liners."
        ));
    }
    let model = k.cfg_now().task_model("compaction").to_string();
    for _ in 0..2 {
        if let Ok((m, _, _)) = k.sample(Some(&model), "You write faithful, dense handoff summaries.", vec![Message::user(prompt.clone())], vec![], 4_096, &seagent_core::Cancel::new()) {
            let text = m.text();
            if compaction::summary_ok(&text, transcript.len()) {
                return (text, false);
            }
        }
    }
    (compaction::fallback_summary(head), true)
}

/// Field values a title must not carry: newlines and control characters break log/UI rendering.
pub fn sanitize_title(raw: &str) -> Option<String> {
    let t: String = raw.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
    let t: String = t.chars().take(titles::MAX_TITLE_CHARS).collect();
    let t = t.trim().to_string();
    (!t.is_empty()).then_some(t)
}

/// `/title [text]`: with text, set it; without, show it — and generate one when there is none.
pub fn set_or_show_title(k: &Kernel, titles: &titles::Titles, session: Option<&str>, args: &str) -> String {
    let Some(sid) = session else {
        return "No session yet — send a message first.".into();
    };
    let current = k.store.read(sid).ok().map(|e| project(&e).title).unwrap_or_default().unwrap_or_default();
    let want = args.trim();
    if !want.is_empty() {
        let Some(title) = sanitize_title(want) else {
            return "A title cannot be empty.".into();
        };
        return match k.set_title(sid, &title) {
            Ok(()) => format!("Title set: {title}"),
            Err(e) => format!("could not set the title: {e}"),
        };
    }
    if !current.trim().is_empty() {
        return format!("Title: {current}");
    }
    let cfg = k.cfg_now();
    match titles::generate_now(k, titles, sid, &cfg.context.title_language) {
        Ok(t) => format!("Generated title: {t}\n(rename it with /title <text>)"),
        Err(e) => format!("This session has no title yet — {e}. Set one with /title <text>."),
    }
}

/// Drop trailing messages until the snapshot ends with a finished assistant reply (Hermes
/// `trim_snapshot_for_fork`): a mid-turn tail breaks role alternation on strict providers.
pub fn trim_for_snapshot(mut msgs: Vec<Message>) -> Vec<Message> {
    while let Some(last) = msgs.last() {
        if last.role == Role::Assistant && last.tool_uses().next().is_none() {
            break;
        }
        msgs.pop();
    }
    msgs
}

/// The `/btw` snapshot: the tail bounded by message count and characters (newest-biased).
pub fn side_snapshot(view: &View, keep: usize) -> Vec<Message> {
    let mut msgs = trim_for_snapshot(view.messages.clone());
    let keep = keep.max(2);
    if msgs.len() > keep {
        msgs = msgs.split_off(msgs.len() - keep);
    }
    let mut used = 0usize;
    let mut start = msgs.len();
    while start > 0 {
        let cost = msgs[start - 1].content.iter().map(block_chars).sum::<usize>();
        if used + cost > SIDE_TRANSCRIPT_CHARS {
            break;
        }
        used += cost;
        start -= 1;
    }
    msgs.split_off(start)
}

fn block_chars(b: &Block) -> usize {
    match b {
        Block::Text { text } | Block::Thinking { text, .. } => text.len().min(SIDE_PER_MESSAGE_CHARS),
        Block::ToolUse { name, input, .. } => name.len() + input.to_string().len().min(SIDE_PER_MESSAGE_CHARS),
        Block::ToolResult { content, .. } => content.len().min(SIDE_PER_MESSAGE_CHARS),
        Block::Image { .. } => 0,
    }
}

/// Model for a side question: `[context] side_question_model`, else the aux model, else the session's.
pub fn side_model(k: &Kernel, cfg: &crate::config::Config, session_model: &str) -> String {
    let side = cfg.context.side_question_model.trim();
    if !side.is_empty() {
        return k.cfg.resolve_model(side).to_string();
    }
    let aux = cfg.aux_model().trim();
    if !aux.is_empty() {
        return k.cfg.resolve_model(aux).to_string();
    }
    session_model.to_string()
}

/// `/btw`: answer from a snapshot. Nothing is appended to the session (that is the point).
///
/// The snapshot is the same tail size compaction keeps verbatim (`compaction.keep_messages`):
/// `[context]` has no side-question bound of its own, and a side question should see exactly the
/// part of the conversation the model would keep anyway (Hermes bounds it per message and in total).
pub fn side_question(k: &Kernel, session: Option<&str>, question: &str) -> Result<String, String> {
    let q = question.trim();
    if q.is_empty() {
        return Err("usage: /btw <question>".into());
    }
    let Some(sid) = session else {
        return Err("no session yet — send a message first".into());
    };
    let cfg = k.cfg_now();
    let view = project(&k.store.read(sid).map_err(|e| e.to_string())?);
    let mut msgs = side_snapshot(&view, cfg.compaction.keep_messages);
    msgs.push(Message::user(format!("{BTW_PROMPT}\n\nSide question: {q}")));
    let system: String = view.system.iter().map(|s| s.text.as_str()).collect::<Vec<_>>().join("\n\n");
    let system: String = system.chars().take(8_000).collect();
    let model = side_model(k, &cfg, &view.model);
    let max = cfg.model.max_tokens.clamp(256, SIDE_MAX_TOKENS);
    let (m, _, _) = k.sample(Some(&model), &system, msgs, vec![], max, &seagent_core::Cancel::new())?;
    let answer = m.text().trim().to_string();
    if answer.is_empty() {
        return Err("the side question returned no answer".into());
    }
    Ok(answer)
}

/// `/personality [name|list|none]`.
pub fn personality_command(host: &Host, k: &Kernel, session: Option<&str>, args: &str) -> String {
    let cfg = k.cfg_now();
    let want = args.trim().to_lowercase();
    let all = persona::personalities(&cfg);
    if want.is_empty() || want == "list" {
        let cur = host.persona().name(&cfg);
        let mut out = format!("personalities (current: {}):\n", if cur.is_empty() { "none" } else { &cur });
        for (name, text) in &all {
            out.push_str(&format!("  {name:<12} {}\n", one_line(text, 60)));
        }
        out.push_str("Set one with /personality <name>, clear it with /personality none.");
        return out;
    }
    let name = if persona::is_neutral(&want) { String::new() } else { want.clone() };
    if !name.is_empty() && !all.iter().any(|(n, _)| *n == name) {
        return format!("unknown personality `{want}`.\n\nAvailable: `none`, {}", all.iter().map(|(n, _)| format!("`{n}`")).collect::<Vec<_>>().join(", "));
    }
    host.persona().set(&name);
    let mut out = format!("personality → {}", if name.is_empty() { "none" } else { &name });
    if let Some(sid) = session {
        match persona::refresh(host, sid) {
            Ok(()) => out.push_str("\n(this session's prompt was rewritten; new sessions use it too)"),
            Err(e) => out.push_str(&format!("\n(could not rewrite this session's prompt: {e})")),
        }
    }
    out.push_str("\nNot saved: set `[context] personality` in the config to keep it across restarts.");
    out
}
