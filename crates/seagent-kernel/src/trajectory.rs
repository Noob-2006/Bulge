//! Session transcripts in exchange formats: Hermes ShareGPT trajectories
//! (`from`/`value`), OpenClaw trajectory bundles (`openclaw-trajectory` events)
//! and Claude Code JSONL traces (the shape the Hugging Face trace viewer reads).
//! Pure functions of the event log; writing files and uploading live in the CLI.

use crate::event::{Event, EventKind};
use crate::projection::project;
use seagent_core::{Block, Role, ToolSpec};
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::OnceLock;

/// One flattened transcript message (OpenAI-like roles: user, assistant, tool).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Flat {
    pub role: &'static str,
    pub content: String,
    pub reasoning: String,
    /// (id, name, input) for assistant tool calls.
    pub tool_calls: Vec<(String, String, Value)>,
    pub tool_call_id: String,
    pub tool_name: String,
    pub is_error: bool,
    pub images: usize,
    /// Unix millis of the event.
    pub ts: u64,
    /// Event seq (stable message id).
    pub seq: u64,
}

/// Every message ever appended, in order (compaction does not hide history here).
pub fn flatten(events: &[Event]) -> Vec<Flat> {
    let mut names: HashMap<String, String> = HashMap::new();
    let mut out = Vec::new();
    for ev in events {
        let EventKind::Message { message, .. } = &ev.kind else { continue };
        match message.role {
            Role::Assistant => {
                let mut f = Flat { role: "assistant", ts: ev.ts, seq: ev.seq, ..Default::default() };
                for b in &message.content {
                    match b {
                        Block::Text { text } => push_line(&mut f.content, text),
                        Block::Thinking { text, .. } => push_line(&mut f.reasoning, text),
                        Block::ToolUse { id, name, input } => {
                            names.insert(id.clone(), name.clone());
                            f.tool_calls.push((id.clone(), name.clone(), input.clone()));
                        }
                        Block::Image { .. } => f.images += 1,
                        Block::ToolResult { .. } => {}
                    }
                }
                out.push(f);
            }
            Role::User => {
                let mut user = Flat { role: "user", ts: ev.ts, seq: ev.seq, ..Default::default() };
                let mut any_user = false;
                for b in &message.content {
                    match b {
                        Block::ToolResult { tool_use_id, content, is_error } => out.push(Flat {
                            role: "tool",
                            content: content.clone(),
                            tool_call_id: tool_use_id.clone(),
                            tool_name: names.get(tool_use_id).cloned().unwrap_or_else(|| "unknown".into()),
                            is_error: *is_error,
                            ts: ev.ts,
                            seq: ev.seq,
                            ..Default::default()
                        }),
                        Block::Text { text } => {
                            push_line(&mut user.content, text);
                            any_user = true;
                        }
                        Block::Image { .. } => {
                            user.images += 1;
                            any_user = true;
                        }
                        _ => {}
                    }
                }
                if any_user {
                    out.push(user);
                }
            }
        }
    }
    out
}

fn push_line(s: &mut String, t: &str) {
    if !s.is_empty() {
        s.push('\n');
    }
    s.push_str(t);
}

// ───────────────────────── redaction ─────────────────────────

/// Force-mode redaction for anything leaving the machine: vault values (by the
/// caller's `known` pass) plus credential patterns, whatever the log settings.
pub fn redact_patterns(s: &str) -> String {
    static P: OnceLock<Vec<Regex>> = OnceLock::new();
    let pats = P.get_or_init(|| {
        [
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
            r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}",
            r"\bgh[pousr]_[A-Za-z0-9]{30,}",
            r"\bgithub_pat_[A-Za-z0-9_]{40,}",
            r"\bglpat-[A-Za-z0-9_\-]{20,}",
            r"\bxox[abprs]-[A-Za-z0-9\-]{10,}",
            r"\bhf_[A-Za-z0-9]{30,}",
            r"\bAKIA[0-9A-Z]{16}\b",
            r"\bAIza[0-9A-Za-z_\-]{35}\b",
            r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
            r"\b\d{9,10}:AA[A-Za-z0-9_\-]{33}\b",
            r"(?i)\b(authorization:\s*bearer)\s+[A-Za-z0-9._\-]{12,}",
        ]
        .iter()
        .map(|r| Regex::new(r).expect("static regex"))
        .collect()
    });
    let mut out = s.to_string();
    for (i, re) in pats.iter().enumerate() {
        out = if i == pats.len() - 1 { re.replace_all(&out, "$1 [REDACTED]").into_owned() } else { re.replace_all(&out, "[REDACTED]").into_owned() };
    }
    // Force-mode exports also carry the structural secrets (database URLs and connection
    // strings, client env vars, URL userinfo, non-PEM keys, Azure keys, quoted config values,
    // command-line flags) that the token-shape list above never sees.
    seagent_security::risk::mask_secrets(&out).0
}

/// Apply `redact` to every text-bearing field.
pub fn redact_flats(flats: &mut [Flat], redact: &dyn Fn(&str) -> String) {
    for f in flats {
        f.content = redact(&f.content);
        f.reasoning = redact(&f.reasoning);
        for (_, _, input) in &mut f.tool_calls {
            let r = redact(&input.to_string());
            *input = serde_json::from_str(&r).unwrap_or_else(|_| json!({"_raw": r}));
        }
    }
}

// ───────────────────────── time ─────────────────────────

/// `2026-11-03T08:15:30.123Z` from unix millis.
pub fn iso_ms(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let (y, m, d) = crate::util::civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", rem / 3600, rem / 60 % 60, rem % 60, ms % 1000)
}

pub fn uuid4() -> String {
    let h = crate::util::random_hex(32);
    let variant = ["8", "9", "a", "b"][usize::from_str_radix(&h[16..17], 16).unwrap_or(0) % 4];
    format!("{}-{}-4{}-{variant}{}-{}", &h[0..8], &h[8..12], &h[13..16], &h[17..20], &h[20..32])
}

// ───────────────────────── Hermes ShareGPT trajectory ─────────────────────────

pub const TRAJECTORY_SYSTEM_PROMPT: &str = "You are a function calling AI model. You are provided with function signatures within <tools> </tools> XML tags. You may call one or more functions to assist with the user query. If available tools are not relevant in assisting with user query, just respond in natural conversational language. Don't make assumptions about what values to plug into functions. After calling & executing the functions, you will be provided with function results within <tool_response> </tool_response> XML tags. Here are the available tools:\n<tools>\n{tools}\n</tools>\nFor each function call return a JSON object, with the following pydantic model json schema for each:\n{'title': 'FunctionCall', 'type': 'object', 'properties': {'name': {'title': 'Name', 'type': 'string'}, 'arguments': {'title': 'Arguments', 'type': 'object'}}, 'required': ['name', 'arguments']}\nEach function call should be enclosed within <tool_call> </tool_call> XML tags.\nExample:\n<tool_call>\n{'name': <function-name>,'arguments': <args-dict>}\n</tool_call>";

pub fn tools_for_system_message(specs: &[ToolSpec]) -> String {
    if specs.is_empty() {
        return "[]".into();
    }
    Value::Array(specs.iter().map(|s| json!({"name": s.name, "description": s.description, "parameters": s.input_schema, "required": null})).collect()).to_string()
}

fn scratchpad_to_think(s: &str) -> String {
    s.replace("<REASONING_SCRATCHPAD>", "<think>").replace("</REASONING_SCRATCHPAD>", "</think>")
}

fn gpt_prefix(f: &Flat) -> String {
    if f.reasoning.trim().is_empty() {
        String::new()
    } else {
        format!("<think>\n{}\n</think>\n", f.reasoning)
    }
}

fn with_think_block(c: String) -> String {
    if c.contains("<think>") {
        c
    } else {
        format!("<think>\n</think>\n{c}")
    }
}

/// `[{from, value}]` in Hermes' training format: system (tool list), human, gpt
/// (`<think>` + `<tool_call>` blocks), tool (`<tool_response>` blocks).
pub fn sharegpt(flats: &[Flat], tools_json: &str) -> Vec<Value> {
    let mut t = vec![json!({"from": "system", "value": TRAJECTORY_SYSTEM_PROMPT.replace("{tools}", tools_json)})];
    let mut i = 0;
    while i < flats.len() {
        let f = &flats[i];
        match f.role {
            "user" => t.push(json!({"from": "human", "value": f.content})),
            "assistant" if !f.tool_calls.is_empty() => {
                let mut c = gpt_prefix(f);
                if !f.content.trim().is_empty() {
                    c.push_str(&scratchpad_to_think(&f.content));
                    c.push('\n');
                }
                for (_, name, input) in &f.tool_calls {
                    c.push_str(&format!("<tool_call>\n{}\n</tool_call>\n", json!({"name": name, "arguments": input})));
                }
                t.push(json!({"from": "gpt", "value": with_think_block(c).trim_end()}));
                let mut responses = Vec::new();
                let mut j = i + 1;
                while j < flats.len() && flats[j].role == "tool" {
                    let tm = &flats[j];
                    let trimmed = tm.content.trim_start();
                    let content = if trimmed.starts_with('{') || trimmed.starts_with('[') { serde_json::from_str(&tm.content).unwrap_or_else(|_| json!(tm.content)) } else { json!(tm.content) };
                    let name = f.tool_calls.get(responses.len()).map(|c| c.1.clone()).unwrap_or_else(|| "unknown".into());
                    responses.push(format!("<tool_response>\n{}\n</tool_response>", json!({"tool_call_id": tm.tool_call_id, "name": name, "content": content})));
                    j += 1;
                }
                if !responses.is_empty() {
                    t.push(json!({"from": "tool", "value": responses.join("\n")}));
                    i = j - 1;
                }
            }
            "assistant" => {
                let c = gpt_prefix(f) + &scratchpad_to_think(&f.content);
                t.push(json!({"from": "gpt", "value": with_think_block(c).trim()}));
            }
            _ => {}
        }
        i += 1;
    }
    t
}

/// The JSONL line Hermes appends (`trajectory_samples.jsonl` / `failed_trajectories.jsonl`).
pub fn sharegpt_entry(conversations: Vec<Value>, model: &str, completed: bool, now_ms: u64) -> Value {
    json!({"conversations": conversations, "timestamp": iso_ms(now_ms).trim_end_matches('Z'), "model": model, "completed": completed})
}

/// Default file name by outcome, as upstream.
pub fn sharegpt_file(completed: bool) -> &'static str {
    if completed {
        "trajectory_samples.jsonl"
    } else {
        "failed_trajectories.jsonl"
    }
}

/// Did the session's last turn end cleanly?
pub fn completed(events: &[Event]) -> bool {
    events.iter().rev().find_map(|e| match &e.kind {
        EventKind::TurnEnd { reason, .. } => Some(reason == "done" || reason == "idle"),
        _ => None,
    }) == Some(true)
}

// ───────────────────────── OpenClaw trajectory bundle ─────────────────────────

/// `openclaw-trajectory` v1 events (source "transcript") for the session log.
pub fn bundle_events(events: &[Event], trace_id: &str) -> Vec<Value> {
    let v = project(events);
    let mut out = Vec::new();
    let mut seq = 0u64;
    let mut model = v.model.clone();
    if let Some(EventKind::Header { model: m, .. }) = events.first().map(|e| &e.kind) {
        model = m.clone();
    }
    let mut prev: Option<String> = None;
    for ev in events {
        let mut push = |ty: &str, data: Value, model: &str| {
            seq += 1;
            let (provider, mid) = model.split_once('/').unwrap_or(("", model));
            out.push(json!({
                "traceSchema": "openclaw-trajectory", "schemaVersion": 1, "traceId": trace_id, "source": "transcript",
                "type": ty, "ts": iso_ms(ev.ts), "seq": seq, "sourceSeq": ev.seq, "sessionId": v.session_id,
                "workspaceDir": v.workspace, "provider": provider, "modelId": mid, "entryId": ev.seq.to_string(),
                "parentEntryId": prev, "data": data,
            }));
        };
        match &ev.kind {
            EventKind::Header { title, parent, .. } => push("session.started", json!({"title": title, "parent": parent}), &model),
            EventKind::Message { message, usage, .. } => {
                let ty = match message.role {
                    Role::Assistant => "message.assistant",
                    Role::User if message.content.iter().all(|b| matches!(b, Block::ToolResult { .. })) => "tool.result",
                    Role::User => "message.user",
                };
                push(ty, json!({"message": message, "usage": usage}), &model);
                for (i, b) in message.content.iter().enumerate() {
                    if let Block::ToolUse { id, name, input } = b {
                        push("tool.call", json!({"toolCallId": id, "name": name, "arguments": input, "assistantEntryId": ev.seq.to_string(), "blockIndex": i}), &model);
                    }
                }
            }
            EventKind::Compaction { summary, upto_seq, tokens_before, .. } => push("session.compaction", json!({"summary": summary, "firstKeptEntryId": upto_seq.to_string(), "tokensBefore": tokens_before}), &model),
            EventKind::Model { model: m } => {
                model = m.clone();
                push("session.model_change", json!({"model": m}), &model)
            }
            EventKind::Thinking { level } => push("session.thinking_level_change", json!({"thinkingLevel": level}), &model),
            EventKind::Title { title } => push("session.label", json!({"label": title}), &model),
            EventKind::TurnStart { turn } => push("run.started", json!({"turn": turn}), &model),
            EventKind::TurnEnd { turn, reason, usage } => push("run.ended", json!({"turn": turn, "reason": reason, "usage": usage}), &model),
            EventKind::Error { message } => push("run.error", json!({"message": message}), &model),
            EventKind::Gate { tool_use_id, gate, verdict, reason } => push("tool.gate", json!({"toolCallId": tool_use_id, "gate": gate, "verdict": verdict, "reason": reason}), &model),
            _ => continue,
        }
        prev = Some(ev.seq.to_string());
    }
    out
}

/// `manifest.json` beside `events.jsonl`.
pub fn bundle_manifest(events: &[Event], trace_id: &str, event_count: usize, session_file: &str, now_ms: u64) -> Value {
    let v = project(events);
    json!({
        "traceSchema": "openclaw-trajectory", "schemaVersion": 1, "generatedAt": iso_ms(now_ms), "traceId": trace_id,
        "sessionId": v.session_id, "workspaceDir": v.workspace, "leafId": events.last().map(|e| e.seq.to_string()),
        "eventCount": event_count, "runtimeEventCount": 0, "transcriptEventCount": event_count,
        "sourceFiles": {"session": session_file},
    })
}

/// Directory name upstream uses: `<prefix>-trajectory-<id8>-<YYYY-MM-DDTHH-MM-SS>`.
pub fn bundle_dir_name(session: &str, now_ms: u64) -> String {
    let ts: String = iso_ms(now_ms).chars().take(19).map(|c| if c == ':' || c == '.' { '-' } else { c }).collect();
    let safe: String = session.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(8).collect();
    format!("seagent-trajectory-{safe}-{ts}")
}

// ───────────────────────── Claude Code JSONL trace ─────────────────────────

/// One JSONL line per non-system message, linked by `parentUuid` (Hermes trace_upload).
pub fn claude_code_trace(flats: &[Flat], session: &str, model: &str, cwd: &str, git_branch: &str, now_ms: u64) -> String {
    let ts = iso_ms(now_ms);
    let mut parent: Option<String> = None;
    let mut lines = Vec::new();
    for f in flats {
        let id = uuid4();
        let (ty, message) = match f.role {
            "assistant" => {
                let mut blocks: Vec<Value> = Vec::new();
                if !f.content.is_empty() {
                    blocks.push(json!({"type": "text", "text": f.content}));
                }
                for _ in 0..f.images {
                    blocks.push(json!({"type": "text", "text": "[image omitted]"}));
                }
                for (tid, name, input) in &f.tool_calls {
                    let input = if input.is_object() { input.clone() } else { json!({}) };
                    blocks.push(json!({"type": "tool_use", "id": if tid.is_empty() { format!("toolu_{}", &uuid4().replace('-', "")[..16]) } else { tid.clone() }, "name": name, "input": input}));
                }
                if blocks.is_empty() {
                    blocks.push(json!({"type": "text", "text": ""}));
                }
                ("assistant", json!({"role": "assistant", "model": if model.is_empty() { "unknown" } else { model }, "content": blocks}))
            }
            "tool" => ("user", json!({"role": "user", "content": [{"type": "tool_result", "tool_use_id": if f.tool_call_id.is_empty() { f.tool_name.clone() } else { f.tool_call_id.clone() }, "content": f.content}]})),
            _ if f.images > 0 => {
                let mut blocks = vec![json!({"type": "text", "text": f.content})];
                blocks.extend((0..f.images).map(|_| json!({"type": "text", "text": "[image omitted]"})));
                ("user", json!({"role": "user", "content": blocks}))
            }
            _ => ("user", json!({"role": "user", "content": f.content})),
        };
        let entry = json!({
            "parentUuid": parent, "isSidechain": false, "userType": "external", "cwd": cwd, "sessionId": session,
            "version": concat!("seagent-", env!("CARGO_PKG_VERSION")), "gitBranch": git_branch, "uuid": id, "timestamp": ts, "type": ty, "message": message,
        });
        lines.push(entry.to_string());
        parent = Some(id);
    }
    if lines.is_empty() {
        String::new()
    } else {
        lines.join("\n") + "\n"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::LOG_VERSION;
    use seagent_core::Message;

    fn evs(kinds: Vec<EventKind>) -> Vec<Event> {
        kinds.into_iter().enumerate().map(|(i, k)| Event { seq: i as u64, ts: 1_700_000_000_000 + i as u64, kind: k }).collect()
    }
    fn msg(m: Message) -> EventKind {
        EventKind::Message { message: m, usage: None, model: None, inbox: None }
    }
    fn sample() -> Vec<Event> {
        evs(vec![
            EventKind::Header { version: LOG_VERSION, session_id: "s1".into(), workspace: "/w".into(), model: "p/m".into(), parent: None, title: Some("t".into()) },
            msg(Message::user("count files")),
            msg(Message { role: Role::Assistant, content: vec![Block::Thinking { text: "hmm".into(), signature: None }, Block::text("let me look"), Block::ToolUse { id: "t1".into(), name: "glob".into(), input: json!({"pattern": "*"}) }] }),
            msg(Message { role: Role::User, content: vec![Block::ToolResult { tool_use_id: "t1".into(), content: "{\"n\": 3}".into(), is_error: false }] }),
            msg(Message::assistant("3 files <REASONING_SCRATCHPAD>x</REASONING_SCRATCHPAD>")),
            EventKind::TurnEnd { turn: 0, reason: "done".into(), usage: Default::default() },
        ])
    }

    #[test]
    fn flatten_splits_tool_results_and_names_them() {
        let f = flatten(&sample());
        let roles: Vec<_> = f.iter().map(|x| x.role).collect();
        assert_eq!(roles, ["user", "assistant", "tool", "assistant"]);
        assert_eq!(f[1].reasoning, "hmm");
        assert_eq!(f[2].tool_name, "glob");
        assert!(completed(&sample()));
    }

    #[test]
    fn sharegpt_matches_hermes_shape() {
        let t = sharegpt(&flatten(&sample()), "[]");
        let from: Vec<_> = t.iter().map(|x| x["from"].as_str().unwrap()).collect();
        assert_eq!(from, ["system", "human", "gpt", "tool", "gpt"]);
        assert!(t[0]["value"].as_str().unwrap().contains("<tools>\n[]\n</tools>"));
        let call = t[2]["value"].as_str().unwrap();
        assert!(call.starts_with("<think>\nhmm\n</think>\nlet me look\n<tool_call>\n{\"arguments\":{\"pattern\":\"*\"},\"name\":\"glob\"}\n</tool_call>"), "{call}");
        let resp = t[3]["value"].as_str().unwrap();
        assert!(resp.contains("<tool_response>") && resp.contains("\"content\":{\"n\":3}") && resp.contains("\"name\":\"glob\""));
        assert_eq!(t[4]["value"], "3 files <think>x</think>", "a scratchpad already supplies the think block");
        let e = sharegpt_entry(t, "p/m", true, 0);
        assert_eq!(e["completed"], true);
        assert_eq!(sharegpt_file(false), "failed_trajectories.jsonl");
    }

    #[test]
    fn bundle_events_are_versioned_and_linked() {
        let ev = bundle_events(&sample(), "tr");
        assert!(ev.iter().all(|e| e["traceSchema"] == "openclaw-trajectory" && e["schemaVersion"] == 1));
        let types: Vec<_> = ev.iter().map(|e| e["type"].as_str().unwrap()).collect();
        assert_eq!(types, ["session.started", "message.user", "message.assistant", "tool.call", "tool.result", "message.assistant", "run.ended"]);
        assert_eq!(ev[3]["data"]["name"], "glob");
        assert_eq!(ev[1]["parentEntryId"], "0");
        let m = bundle_manifest(&sample(), "tr", ev.len(), "events.jsonl", 0);
        assert_eq!(m["eventCount"], 7);
        assert!(bundle_dir_name("abcdefghijk", 0).starts_with("seagent-trajectory-abcdefgh-1970-01-01T00-00-00"));
    }

    #[test]
    fn claude_code_trace_links_turns() {
        let jsonl = claude_code_trace(&flatten(&sample()), "s1", "p/m", "/w", "main", 0);
        let lines: Vec<Value> = jsonl.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0]["parentUuid"].is_null());
        assert_eq!(lines[1]["parentUuid"], lines[0]["uuid"]);
        assert_eq!(lines[1]["message"]["content"][1]["type"], "tool_use");
        assert_eq!(lines[2]["type"], "user");
        assert_eq!(lines[2]["message"]["content"][0]["tool_use_id"], "t1");
        assert_eq!(lines[0]["timestamp"], "1970-01-01T00:00:00.000Z");
        assert_eq!(claude_code_trace(&[], "s", "", "", "", 0), "");
    }

    #[test]
    fn redaction_and_ids() {
        let r = redact_patterns("key sk-ant-ABCDEFGHIJKLMNOPQRSTUVWX and hf_abcdefghijklmnopqrstuvwxyz0123456 Authorization: Bearer abcdefghijklmnop");
        assert!(!r.contains("sk-ant-ABC") && !r.contains("hf_abc") && r.contains("Authorization: Bearer [REDACTED]"), "{r}");
        let r = redact_patterns("postgresql://app:s3cret-pg@db/x PGPASSWORD=pgpass1 AccountKey=abc123DEF456ghi789==");
        assert!(!r.contains("s3cret-pg") && !r.contains("pgpass1") && !r.contains("abc123DEF456"), "{r}");
        let mut f = flatten(&sample());
        redact_flats(&mut f, &|s| s.replace("look", "XX"));
        assert_eq!(f[1].content, "let me XX");
        let u = uuid4();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
        assert_eq!(iso_ms(1_700_000_000_123), "2023-11-14T22:13:20.123Z");
    }
}
