//! Derive the live session state from the event log. Pure function of the events,
//! so any request the model ever saw can be rebuilt.

use crate::event::{Event, EventKind};
use seagent_core::{Block, Message, Role, SystemSegment, Usage};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

pub const PRUNED_STUB: &str = "[output pruned to save context";

#[derive(Debug, Clone, Default)]
pub struct View {
    pub session_id: String,
    pub workspace: String,
    pub model: String,
    pub parent: Option<String>,
    pub system: Vec<SystemSegment>,
    /// Conversation as sent to the model (compaction + pruning applied,
    /// consecutive same-role messages merged).
    pub messages: Vec<Message>,
    /// Seq of the event each entry of `messages` started from.
    pub message_seqs: Vec<u64>,
    pub pending_inbox: Vec<Queued>,
    /// Reasoning effort set for this session, if any.
    pub thinking: Option<String>,
    /// Fast mode / service tier set for this session, if any.
    pub fast: Option<String>,
    /// Tokens spent by auxiliary calls (compaction, review…), not part of `usage`.
    pub aux_usage: Usage,
    pub title: Option<String>,
    /// Tool calls written ahead but never settled (crash mid-call).
    pub unsettled: Vec<Unsettled>,
    /// Tool uses in the last assistant message with no result message yet.
    pub dangling: Vec<(String, String, Value)>,
    pub usage: Usage,
    pub turns: u64,
    pub compactions: u64,
    pub last_input_tokens: u64,
    /// Named agent (multi-agent); None = the default agent.
    pub agent: Option<String>,
    pub user: Option<String>,
    pub tool_allow: Option<Vec<String>>,
    pub tool_deny: Vec<String>,
    /// Execution-time-only restrictions (fork children); they leave the request tool list alone.
    pub tool_guard_allow: Option<Vec<String>>,
    pub tool_guard_deny: Vec<String>,
    /// Skills switched off for this conversation ([`EventKind::Skills`]).
    pub skills_disabled: Vec<String>,
    pub pinned: bool,
    pub archived: bool,
    pub group: Option<String>,
    pub status: Option<String>,
    pub output_schema: Option<Value>,
    pub structured: Option<Value>,
    /// (turn, checkpoint id) in log order.
    pub checkpoints: Vec<(u64, String)>,
    /// Seqs of the user messages that started a turn (rewind targets), oldest first.
    pub user_turns: Vec<u64>,
}

/// Whether a user message is a human turn (not tool results / recovery notes).
pub fn is_user_turn(m: &Message) -> bool {
    m.role == Role::User && !m.content.is_empty() && !m.content.iter().any(|b| matches!(b, Block::ToolResult { .. }))
}

/// Queued input: (inbox id, source, text, attachments).
pub type Queued = (String, String, String, Vec<Block>);

#[derive(Debug, Clone, PartialEq)]
pub struct Unsettled {
    pub tool_use_id: String,
    pub name: String,
    pub input: Value,
    pub idempotency_key: String,
}

pub fn project(events: &[Event]) -> View {
    let mut v = View::default();
    let mut compaction: Option<(u64, String)> = None;
    let mut pruned: HashSet<String> = HashSet::new();
    let mut consumed: HashSet<String> = HashSet::new();
    let mut called: Vec<Unsettled> = Vec::new();
    let mut settled: HashSet<String> = HashSet::new();
    let mut artifacts: HashMap<String, String> = HashMap::new();
    let mut rewinds: Vec<(u64, u64)> = Vec::new();
    let mut compactions: Vec<(u64, u64, String)> = Vec::new();
    let mut dropped: Vec<(u64, u64)> = Vec::new();
    let mut break_merge = false;

    for ev in events {
        match &ev.kind {
            EventKind::Header { session_id, workspace, model, parent, title, .. } => {
                v.title = title.clone();
                v.session_id = session_id.clone();
                v.workspace = workspace.clone();
                v.model = model.clone();
                v.parent = parent.clone();
            }
            EventKind::System { segments } => v.system = segments.clone(),
            EventKind::Model { model } => v.model = model.clone(),
            EventKind::Thinking { level } => v.thinking = Some(level.clone()).filter(|l| !l.is_empty()),
            EventKind::Title { title } => v.title = Some(title.clone()).filter(|t| !t.is_empty()),
            EventKind::Fast { tier } => v.fast = Some(tier.clone()).filter(|t| !t.is_empty()),
            EventKind::Skills { disabled } => v.skills_disabled = disabled.clone(),
            EventKind::AuxUsage { usage, .. } => v.aux_usage.add(usage),
            EventKind::Message { usage, inbox, .. } => {
                if let Some(u) = usage {
                    v.usage.add(u);
                    v.last_input_tokens = u.input_tokens + u.cache_read_tokens + u.cache_write_tokens;
                }
                if let Some(i) = inbox {
                    consumed.insert(i.clone());
                }
            }
            EventKind::MessageBoundary => break_merge = true,
            EventKind::Compaction { upto_seq, summary, pruned: p, .. } => {
                compactions.push((ev.seq, *upto_seq, summary.clone()));
                compaction = Some((*upto_seq, summary.clone()));
                pruned.extend(p.iter().cloned());
                v.compactions += 1;
                v.last_input_tokens = 0;
            }
            EventKind::Prune { tool_use_ids } => pruned.extend(tool_use_ids.iter().cloned()),
            EventKind::ToolCalled { tool_use_id, name, input, idempotency_key } => called.push(Unsettled {
                tool_use_id: tool_use_id.clone(),
                name: name.clone(),
                input: input.clone(),
                idempotency_key: idempotency_key.clone(),
            }),
            EventKind::ToolSettled { tool_use_id, artifact, .. } => {
                settled.insert(tool_use_id.clone());
                if let Some(a) = artifact {
                    artifacts.insert(tool_use_id.clone(), a.clone());
                }
            }
            EventKind::TurnEnd { .. } => v.turns += 1,
            EventKind::Discard { inbox } => consumed.extend(inbox.iter().cloned()),
            EventKind::Workspace { path } => v.workspace = path.clone(),
            EventKind::Agent { agent, user } => {
                v.agent = Some(agent.clone()).filter(|a| !a.is_empty());
                v.user = user.clone();
            }
            EventKind::Tools { allow, deny } => {
                v.tool_allow = allow.clone();
                v.tool_deny = deny.clone();
            }
            EventKind::TurnDropped { from_seq, upto_seq, .. } => dropped.push((*from_seq, *upto_seq)),
            EventKind::ToolGuard { allow, deny } => {
                v.tool_guard_allow = allow.clone();
                v.tool_guard_deny = deny.clone();
            }
            EventKind::Rewind { from_seq, .. } => {
                rewinds.push((*from_seq, ev.seq));
                // A summary covering rewound messages is void: older history comes back.
                if compaction.as_ref().is_some_and(|(u, _)| from_seq < u) {
                    compaction = compactions.iter().rev().find(|(_, u, _)| u <= from_seq).map(|(_, u, s)| (*u, s.clone()));
                }
            }
            EventKind::Meta { pinned, archived, group, status } => {
                if let Some(p) = pinned {
                    v.pinned = *p;
                }
                if let Some(a) = archived {
                    v.archived = *a;
                }
                if let Some(g) = group {
                    v.group = Some(g.clone()).filter(|g| !g.is_empty());
                }
                if let Some(s) = status {
                    v.status = Some(s.clone()).filter(|s| !s.is_empty());
                }
            }
            EventKind::OutputSchema { schema } => v.output_schema = Some(schema.clone()).filter(|s| !s.is_null()),
            EventKind::Structured { value } => v.structured = Some(value.clone()),
            EventKind::Checkpoint { id, turn } => v.checkpoints.push((*turn, id.clone())),
            _ => {}
        }
    }
    let rewound = |seq: u64| rewinds.iter().any(|(from, at)| *from <= seq && seq < *at);

    for ev in events {
        if let EventKind::Inbox { id, source, text, attachments } = &ev.kind {
            if !consumed.contains(id) {
                v.pending_inbox.push((id.clone(), source.clone(), text.clone(), attachments.clone()));
            }
        }
    }
    v.unsettled = called.into_iter().filter(|c| !settled.contains(&c.tool_use_id)).collect();

    let cutoff = compaction.as_ref().map(|(s, _)| *s).unwrap_or(0);
    if let Some((seq, summary)) = &compaction {
        push_merged(&mut v, Message::user(format!("[Summary of earlier conversation]\n{summary}")), *seq, false);
    }
    for ev in events {
        if ev.seq < cutoff || rewound(ev.seq) || dropped.iter().any(|(from, upto)| *from <= ev.seq && ev.seq <= *upto) {
            continue;
        }
        match &ev.kind {
            // A fork child's first message must stay separate from the copied parent prefix.
            EventKind::MessageBoundary => break_merge = true,
            EventKind::Message { message, .. } => {
                if is_user_turn(message) && message.text().trim() != "" && !message.text().starts_with("[Your reply was cut off") {
                    v.user_turns.push(ev.seq);
                }
                let mut m = message.clone();
                if !pruned.is_empty() {
                    for b in &mut m.content {
                        if let Block::ToolResult { tool_use_id, content, .. } = b {
                            if pruned.contains(tool_use_id) && !content.starts_with(PRUNED_STUB) {
                                let hint = artifacts.get(tool_use_id).map(|a| format!("; full output at {a}")).unwrap_or_default();
                                *content = format!("{PRUNED_STUB} ({} bytes){hint}]", content.len());
                            }
                        }
                    }
                }
                push_merged(&mut v, m, ev.seq, break_merge);
                break_merge = false;
            }
            // A mid-session prompt update arrives after the cached history. Its own message keeps
            // the previous request a byte prefix; do not mutate the message before it.
            EventKind::SystemDelta { text } => {
                push_new(&mut v, Message::user(format!("[System prompt update]\n{text}")), ev.seq);
                break_merge = false;
            }
            _ => {}
        }
    }

    // Tool uses without results (crash between assistant message and results).
    if let Some(last) = v.messages.last() {
        if last.role == Role::Assistant {
            v.dangling = last.tool_uses().map(|(i, n, inp)| (i.to_string(), n.to_string(), inp.clone())).collect();
        }
    }
    v
}

fn push_merged(v: &mut View, m: Message, seq: u64, force_new: bool) {
    if let Some(last) = v.messages.last_mut() {
        if last.role == m.role && !force_new {
            last.content.extend(m.content);
            return;
        }
    }
    v.messages.push(m);
    v.message_seqs.push(seq);
}

/// Append a message without merging it into the previous same-role message. Used for
/// mid-session system updates: merging would rewrite bytes the provider already cached.
fn push_new(v: &mut View, m: Message, seq: u64) {
    v.messages.push(m);
    v.message_seqs.push(seq);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::LOG_VERSION;
    use serde_json::json;

    fn evs(kinds: Vec<EventKind>) -> Vec<Event> {
        kinds.into_iter().enumerate().map(|(i, k)| Event { seq: i as u64, ts: 0, kind: k }).collect()
    }
    fn header() -> EventKind {
        EventKind::Header { version: LOG_VERSION, session_id: "s".into(), workspace: "/w".into(), model: "p/m".into(), parent: None, title: None }
    }
    fn m(msg: Message) -> EventKind {
        EventKind::Message { message: msg, usage: None, model: None, inbox: None }
    }
    fn tool_use(id: &str) -> Message {
        Message { role: Role::Assistant, content: vec![Block::ToolUse { id: id.into(), name: "read".into(), input: json!({"path":"a"}) }] }
    }
    fn tool_result(id: &str, c: &str) -> Message {
        Message { role: Role::User, content: vec![Block::ToolResult { tool_use_id: id.into(), content: c.into(), is_error: false }] }
    }

    #[test]
    fn inbox_consumption_and_merging() {
        let v = project(&evs(vec![
            header(),
            EventKind::Inbox { id: "i1".into(), source: "cli".into(), text: "a".into(), attachments: vec![] },
            EventKind::Inbox { id: "i2".into(), source: "cli".into(), text: "b".into(), attachments: vec![] },
            EventKind::Message { message: Message::user("a"), usage: None, model: None, inbox: Some("i1".into()) },
            m(Message::user("extra")),
        ]));
        assert_eq!(v.pending_inbox.len(), 1);
        assert_eq!(v.pending_inbox[0].0, "i2");
        assert_eq!(v.messages.len(), 1, "consecutive user messages merge");
        assert_eq!(v.messages[0].content.len(), 2);
    }

    #[test]
    fn message_boundary_keeps_consecutive_user_messages_separate() {
        let v = project(&evs(vec![
            header(),
            m(Message::user("parent question")),
            EventKind::MessageBoundary,
            m(Message::user("child task")),
        ]));
        assert_eq!(v.messages.len(), 2, "the child task must not merge into the parent's last user message");
        assert_eq!(v.messages[0].text(), "parent question");
        assert_eq!(v.messages[1].text(), "child task");
    }

    #[test]
    fn compaction_drops_old_and_prepends_summary() {
        let v = project(&evs(vec![
            header(),
            m(Message::user("old question")),
            m(Message::assistant("old answer")),
            m(Message::user("new question")),
            EventKind::Compaction { upto_seq: 3, summary: "SUM".into(), pruned: vec![], tokens_before: 10 },
        ]));
        assert_eq!(v.messages.len(), 1);
        let t = v.messages[0].text();
        assert!(t.contains("SUM") && t.contains("new question") && !t.contains("old"));
    }

    #[test]
    fn pruning_replaces_tool_output_with_stub() {
        let v = project(&evs(vec![
            header(),
            m(Message::user("go")),
            m(tool_use("t1")),
            EventKind::ToolCalled { tool_use_id: "t1".into(), name: "read".into(), input: json!({}), idempotency_key: "k".into() },
            EventKind::ToolSettled { tool_use_id: "t1".into(), is_error: false, bytes: 9, artifact: Some("/a/t1.txt".into()), ui_resource: None },
            m(tool_result("t1", "BIG OUTPUT")),
            EventKind::Prune { tool_use_ids: vec!["t1".into()] },
        ]));
        let Block::ToolResult { content, .. } = &v.messages[2].content[0] else { panic!() };
        assert!(content.starts_with(PRUNED_STUB) && content.contains("/a/t1.txt"), "{content}");
        assert!(v.unsettled.is_empty() && v.dangling.is_empty());
    }

    #[test]
    fn detects_unsettled_and_dangling_calls() {
        let v = project(&evs(vec![
            header(),
            m(Message::user("go")),
            m(tool_use("t1")),
            EventKind::ToolCalled { tool_use_id: "t1".into(), name: "read".into(), input: json!({}), idempotency_key: "k".into() },
        ]));
        assert_eq!(v.unsettled.len(), 1);
        assert_eq!(v.dangling.len(), 1);
    }

    #[test]
    fn turn_drop_hides_only_the_model_context() {
        let evs = evs(vec![
            header(),
            m(Message::user("first")),
            m(Message::assistant("answer")),
            m(Message::user("dangerous request")),
            m(Message::assistant("I cannot help with that")),
            EventKind::TurnDropped { from_seq: 3, upto_seq: 4, reason: "refusal".into() },
            m(Message::user("next question")),
        ]);
        // The raw log still holds the refused exchange.
        assert_eq!(evs.len(), 7);
        let v = project(&evs);
        assert_eq!(v.messages.len(), 3);
        assert!(v.messages[0].text().contains("first") && v.messages[1].text().contains("answer") && v.messages[2].text().contains("next question"));
        assert!(!v.messages.iter().any(|m| m.text().contains("dangerous") || m.text().contains("cannot help")));
        assert_eq!(v.user_turns, vec![1, 6], "the dropped ask is not a rewind target");
    }

    #[test]
    fn system_delta_appends_after_cached_messages() {
        let v = project(&evs(vec![
            header(),
            m(Message::user("hi")),
            m(Message::assistant("hello")),
            EventKind::SystemDelta { text: "Be terse.".into() },
        ]));
        assert_eq!(v.messages.len(), 3, "the update is a new message, not a head rewrite");
        assert_eq!(v.messages[0].text(), "hi");
        assert_eq!(v.messages[1].text(), "hello");
        assert!(v.messages[2].text().contains("[System prompt update]") && v.messages[2].text().contains("Be terse."));
        assert_eq!(v.message_seqs[2], 3);
    }

    #[test]
    fn model_switch_and_usage_totals() {
        let u = Usage { input_tokens: 10, output_tokens: 5, cache_read_tokens: 90, ..Default::default() };
        let v = project(&evs(vec![
            header(),
            EventKind::Model { model: "q/n".into() },
            EventKind::Message { message: Message::assistant("x"), usage: Some(u), model: None, inbox: None },
            EventKind::TurnEnd { turn: 0, reason: "done".into(), usage: u },
        ]));
        assert_eq!(v.model, "q/n");
        assert_eq!(v.usage.total(), 15);
        assert_eq!(v.last_input_tokens, 100);
        assert_eq!(v.turns, 1);
    }
}
