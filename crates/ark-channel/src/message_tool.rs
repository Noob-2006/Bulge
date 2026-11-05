//! The `message` tool: the one model-facing entry point for sending and managing
//! messages on a chat channel.
//!
//! Ported from OpenClaw `src/agents/tools/message-tool-schema.ts`,
//! `message-tool-execution.ts`, `message-tool-discovery.ts` and `src/polls.ts` (MIT), and
//! Hermes `tools/send_message_tool.py`: a single flat `action` + `target` (`channel:chat[:thread]`)
//! surface whose `action` enum is whatever the enabled channels advertise. `send` (the default)
//! reproduces `channel_send` (text, `thread`, `replyTo`); every other action is handed to
//! `Channel::message_action` with `target` set to the chat — which is where the per-channel
//! ports (`discord_actions`, `slack_actions`, `telegram_actions`, `feishu::tools`) take over.
//!
//! `normalize_poll` validates poll fields once, for the tool *and* for the discord / telegram
//! `poll` actions (upstream `normalizePollInput`): the question is trimmed and bounded, options
//! are trimmed, de-duplicated and bounded (2..=12 here, the channel's own ceiling applies
//! afterwards: Discord 10, Telegram 12), `maxSelections` defaults to 1 (or all options when
//! multi-select is asked for), and `durationSeconds` / `durationHours` are mutually exclusive.

use crate::action_args as aa;
use crate::{Channel, ChannelError, Outbound, TextFormat};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Where a `message` call can go: configured name → (channel, its default chat).
pub type Targets = BTreeMap<String, (Arc<dyn Channel>, Option<String>)>;

/// Actions that address one chat, so a chat (or a configured default) is required.
const CHAT_ACTIONS: &[&str] = &[
    "send", "reply", "edit", "delete", "react", "poll", "read", "pin", "unpin", "list-pins", "reactions", "thread-create", "thread-reply",
];

/// Target segments that name a kind of id rather than a thread (`channel:C1`, `user:U5`).
const ID_KINDS: &[&str] = &["channel", "chat", "dm", "direct", "group", "guild", "room", "team", "thread", "user"];

/// Poll option ceiling of the shared surface (Telegram's `POLL_MAX_OPTIONS`); a channel with a
/// lower ceiling (Discord: 10) rejects the excess in its own `poll` action.
pub const MAX_POLL_OPTIONS: usize = 12;
/// Longest poll question (chars).
pub const MAX_POLL_QUESTION: usize = 300;
/// Longest poll option (chars).
pub const MAX_POLL_OPTION: usize = 100;

pub struct MessageTool {
    targets: Targets,
}

impl MessageTool {
    pub fn new(targets: Targets) -> Self {
        MessageTool { targets }
    }

    /// The actions this tool advertises: `send`, the generic trait actions the channels' caps
    /// allow, and the union of their `message_actions()`.
    pub fn actions(&self) -> Vec<String> {
        actions_of(&self.targets)
    }
}

/// Union of the enabled channels' `message_actions()` plus the generic actions their caps allow
/// (deduplicated, `send` first). This is the `action` enum the model sees.
pub fn actions_of(targets: &Targets) -> Vec<String> {
    let mut out: Vec<String> = vec!["send".into()];
    let add = |a: &str, out: &mut Vec<String>| {
        if !out.iter().any(|x| x == a) {
            out.push(a.to_string());
        }
    };
    for (ch, _) in targets.values() {
        let caps = ch.caps();
        if caps.reply {
            add("reply", &mut out);
        }
        if caps.edit {
            add("edit", &mut out);
        }
        if caps.delete {
            add("delete", &mut out);
        }
        if caps.reactions > 0 {
            add("react", &mut out);
        }
        for a in ch.message_actions() {
            add(a, &mut out);
        }
    }
    out
}

/// The normalised `action` of one call (`send` when absent). Aliases follow upstream:
/// `unsend` → `delete`, `pins` → `list-pins`, `thread` → `thread-create` (`thread-list` with
/// `list: true`).
pub fn action_of(input: &Value) -> String {
    let a = aa::s(input, &["action"]).unwrap_or_else(|| "send".into()).to_ascii_lowercase();
    match a.as_str() {
        "unsend" => "delete".into(),
        "pins" => "list-pins".into(),
        "thread" if aa::flag(input, "list") == Some(true) => "thread-list".into(),
        "thread" => "thread-create".into(),
        _ => a,
    }
}

/// `target` = `channel:chat` or `channel:chat:thread` (Hermes `platform:chat[:thread]`).
/// The leading segment is a channel only when it matches a configured name; `chat` parts that
/// themselves contain `:` (`channel:C1`, `user:U5`, `team:T:channel:C1`, Telegram's
/// `-100:topic:1`) are kept whole.
pub fn parse_target(raw: &str, channels: &[&str]) -> Result<(Option<String>, String, Option<String>), String> {
    let mut segs: Vec<&str> = raw.trim().split(':').collect();
    let mut hint = None;
    if segs.len() > 1 && channels.contains(&segs[0]) {
        hint = Some(segs.remove(0).to_string());
    }
    let (chat, thread) = match segs.len() {
        0 => return Err("`target` is empty".into()),
        1 => (segs[0].trim().to_string(), None),
        2 if !ID_KINDS.contains(&segs[0]) && !segs[0].is_empty() && !segs[1].trim().is_empty() => (segs[0].trim().to_string(), Some(segs[1].trim().to_string())),
        _ => (segs.join(":").trim().to_string(), None),
    };
    if chat.is_empty() {
        return Err("`target` is empty".into());
    }
    Ok((hint, chat, thread))
}

fn pick<'a>(targets: &'a Targets, hint: Option<&'a str>) -> Result<&'a str, String> {
    let names = || if targets.is_empty() { "none".to_string() } else { targets.keys().cloned().collect::<Vec<_>>().join(", ") };
    match hint {
        Some(n) if targets.contains_key(n) => Ok(targets.get_key_value(n).map(|(k, _)| k.as_str()).unwrap_or(n)),
        Some(n) => Err(format!("unknown channel `{n}`; configured: {}", names())),
        None if targets.len() == 1 => Ok(targets.keys().next().map(String::as_str).unwrap_or("")),
        None if targets.is_empty() => Err("no channels are configured".into()),
        None => Err(format!("several channels configured; pass `channel` (one of: {})", names())),
    }
}

/// Which channel, chat and thread a call addresses.
fn resolve(targets: &Targets, input: &Value, session: Option<&str>) -> Result<(String, Option<String>, Option<String>), String> {
    let names: Vec<&str> = targets.keys().map(String::as_str).collect();
    let mut hint = None;
    let mut chat = None;
    let mut thread = None;
    if let Some(raw) = aa::s(input, &["target", "to"]) {
        let (h, c, t) = parse_target(&raw, &names)?;
        hint = h;
        chat = Some(c);
        thread = t;
    }
    if let Some(ex) = aa::s(input, &["channel"]) {
        if let Some(h) = &hint {
            if h != &ex {
                return Err(format!("`target` names channel `{h}` but `channel` is `{ex}`"));
            }
        }
        hint = Some(ex);
    }
    if chat.is_none() {
        chat = aa::s(input, &["chat", "chatId"]);
    }
    if let Some(t) = aa::s(input, &["threadId", "thread_id", "thread"]) {
        thread = Some(t);
    }
    // Nothing addressed: answer in the chat this session came from (so "send me the file"
    // lands where it was asked), when that chat's channel is one of ours.
    if chat.is_none() && hint.is_none() {
        if let Some((c, ch)) = session.and_then(crate::outfile::origin_of) {
            if targets.contains_key(&c) {
                hint = Some(c);
                chat = Some(ch);
            }
        }
    }
    let name = pick(targets, hint.as_deref())?.to_string();
    if chat.is_none() {
        // `/sethome` beats the configured default chat.
        chat = crate::outfile::effective_default(&name, targets.get(&name).and_then(|(_, d)| d.as_ref()));
    }
    Ok((name, chat, thread))
}

fn text_of(input: &Value) -> Option<String> {
    aa::text(input, &["text", "message"]).filter(|t| !t.trim().is_empty())
}

/// One `message` call: `(JSON result, one-line summary)`.
#[derive(Debug)]
pub struct Outcome {
    pub result: Value,
    pub summary: String,
}

/// The single dispatch path shared by the tool and `ark message` (`message_cli`).
pub fn dispatch(targets: &Targets, input: &Value) -> Result<Outcome, String> {
    let cwd = std::env::current_dir().unwrap_or_default();
    dispatch_in(targets, input, &cwd, &[], None)
}

/// [`dispatch`] for a tool call: `base` resolves relative file paths, `roots` are the folders
/// files may be sent from (see [`crate::outfile::authorize`]), `session` lets an unaddressed
/// message go to the chat the session came from.
pub fn dispatch_in(targets: &Targets, input: &Value, base: &std::path::Path, roots: &[std::path::PathBuf], session: Option<&str>) -> Result<Outcome, String> {
    let action = action_of(input);
    let (name, chat, thread) = resolve(targets, input, session)?;
    let channel = &targets.get(&name).ok_or_else(|| format!("unknown channel `{name}`"))?.0;
    if CHAT_ACTIONS.contains(&action.as_str()) && chat.is_none() {
        return Err(format!("pass `chat` (or `target`): channel `{name}` has no default chat"));
    }
    // Every per-channel action reads the chat as `target`; polls and threads ride along.
    let mut args = match input {
        Value::Object(m) => Value::Object(m.clone()),
        _ => json!({}),
    };
    if let Value::Object(m) = &mut args {
        if let Some(c) = &chat {
            m.insert("target".into(), json!(c));
        }
        if let Some(t) = &thread {
            for k in ["threadId", "thread"] {
                if !m.contains_key(k) {
                    m.insert(k.into(), json!(t));
                }
            }
        }
    }
    let chat_str = chat.clone().unwrap_or_default();
    match action.as_str() {
        "send" | "reply" => {
            let media = crate::outfile::media_from_input(input, base, roots)?;
            let text = match text_of(input) {
                Some(t) => t,
                None if !media.is_empty() => String::new(),
                None => return Err(format!("`text` is empty; action={action} needs a message body (or `media` files)")),
            };
            let reply_to = if action == "reply" {
                Some(aa::req(input, &["replyTo", "reply_to", "messageId", "message_id"]).map_err(|e| e.message)?)
            } else {
                aa::s(input, &["replyTo", "reply_to"])
            };
            let out = Outbound {
                chat: chat_str.clone(),
                text: text.clone(),
                reply_to,
                thread: thread.clone(),
                format: match aa::s(input, &["format"]).as_deref() {
                    Some("markdown") | Some("md") => TextFormat::Markdown,
                    _ => TextFormat::Plain,
                },
                silent: aa::flag(input, "silent") == Some(true),
                media: media.clone(),
                ..Default::default()
            };
            if !media.is_empty() && !channel.caps().media {
                return Err(format!("channel `{name}` cannot carry files"));
            }
            let sent = channel.send(&out).map_err(|e| format!("{action} to {name}/{chat_str} failed: {e}"))?;
            let files = if media.is_empty() { String::new() } else { format!(" + {} file(s)", media.len()) };
            let summary = match sent.first() {
                Some(id) => format!("sent {} chars{files} to {name}/{chat_str} (messageId {id})", text.chars().count()),
                None => format!("sent {} chars{files} to {name}/{chat_str}", text.chars().count()),
            };
            Ok(Outcome {
                result: json!({"ok": true, "action": action, "channel": name, "chat": chat_str, "thread": thread, "messageIds": sent.ids, "chars": text.chars().count(), "files": media.len()}),
                summary,
            })
        }
        "edit" => {
            let id = aa::req(input, &["messageId", "message_id"]).map_err(|e| e.message)?;
            let text = text_of(input).ok_or_else(|| "`text` is empty; action=edit needs the new body".to_string())?;
            channel.edit(&chat_str, &id, &text).map_err(|e| format!("edit of {id} in {name}/{chat_str} failed: {e}"))?;
            Ok(Outcome { result: json!({"ok": true, "action": "edit", "channel": name, "chat": chat_str, "messageId": id}), summary: format!("edited message {id} in {name}/{chat_str}") })
        }
        "delete" => {
            let id = aa::req(input, &["messageId", "message_id"]).map_err(|e| e.message)?;
            channel.delete(&chat_str, &id).map_err(|e| format!("delete of {id} in {name}/{chat_str} failed: {e}"))?;
            Ok(Outcome { result: json!({"ok": true, "action": "delete", "channel": name, "chat": chat_str, "messageId": id}), summary: format!("deleted message {id} in {name}/{chat_str}") })
        }
        "react" => {
            let id = aa::req(input, &["messageId", "message_id"]).map_err(|e| e.message)?;
            let emoji = aa::req(input, &["emoji"]).map_err(|e| e.message)?;
            let remove = aa::flag(input, "remove") == Some(true);
            channel.react(&chat_str, &id, &emoji, remove).map_err(|e| format!("reaction on {id} in {name}/{chat_str} failed: {e}"))?;
            let summary = if remove { format!("removed {emoji} from message {id} in {name}/{chat_str}") } else { format!("reacted {emoji} to message {id} in {name}/{chat_str}") };
            Ok(Outcome { result: json!({"ok": true, "action": "react", "channel": name, "chat": chat_str, "messageId": id, "emoji": emoji, "removed": remove}), summary })
        }
        "poll" => {
            // The channel's own `poll` action re-checks its stricter limits (Discord hours only, 10).
            let args = normalize_poll_args(&args, MAX_POLL_OPTIONS).map_err(|e| e.message)?;
            adapter(&name, channel, "poll", &args)
        }
        _ => adapter(&name, channel, &action, &args),
    }
}

fn adapter(name: &str, channel: &Arc<dyn Channel>, action: &str, args: &Value) -> Result<Outcome, String> {
    let avail = channel.message_actions();
    let listed = || if avail.is_empty() { "none".to_string() } else { avail.join(", ") };
    if !avail.is_empty() && !avail.contains(&action) {
        return Err(format!("channel `{name}` does not support action `{action}`; available: {} (plus send/reply/edit/delete/react where the channel allows)", listed()));
    }
    match channel.message_action(action, args) {
        Ok(v) => {
            let summary = serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string());
            Ok(Outcome { result: v, summary })
        }
        Err(e) if matches!(e.kind, crate::ChannelErrorKind::Unsupported) => {
            Err(format!("channel `{name}` does not support action `{action}`; available: {}", listed()))
        }
        Err(e) => Err(format!("`{action}` on {name} failed: {e}")),
    }
}

impl Tool for MessageTool {
    fn spec(&self) -> ToolSpec {
        let actions = self.actions();
        let names: Vec<&str> = self.targets.keys().map(String::as_str).collect();
        let configured = if names.is_empty() { "none".to_string() } else { names.join(", ") };
        let mut p = Map::new();
        p.insert("action".into(), json!({"type": "string", "enum": actions, "default": "send", "description": "`send` (default) posts `text`; `edit`/`delete`/`react`/`poll`/`pin`/`read`/`thread-create`… are the channel's own actions"}));
        p.insert("channel".into(), json!({"type": "string", "description": format!("Channel name; optional when only one is configured (configured: {configured})")}));
        p.insert("target".into(), json!({"type": "string", "description": "Where to act: `channel:chat` or `channel:chat:thread` (e.g. `telegram:-100123:5`, `discord:C1`, `slack:C1:1700000000.000001`). `channel`/`chat` also work."}));
        p.insert("chat".into(), json!({"type": "string", "description": "Chat id; defaults to the channel's configured default chat"}));
        p.insert("threadId".into(), json!({"type": "string", "description": "Thread / topic id inside the chat (Telegram forum topic, Slack thread ts)"}));
        p.insert("text".into(), json!({"type": "string", "description": "Body for send/reply/edit"}));
        p.insert("message".into(), json!({"type": "string", "description": "Alias of `text`"}));
        p.insert("messageId".into(), json!({"type": "string", "description": "Target message for read/react/edit/delete/pin/unpin"}));
        p.insert("emoji".into(), json!({"type": "string", "description": "Unicode emoji for react"}));
        p.insert("remove".into(), json!({"type": "boolean", "description": "react: remove the reaction instead of adding it"}));
        p.insert("replyTo".into(), json!({"type": "string", "description": "Message id to reply to (send)"}));
        p.insert("media".into(), json!({"type": "array", "items": {"type": "string"}, "description": "send/reply: files to attach, as paths inside the workspace or artifacts folder (or public https URLs). With no `target`, the file goes to the chat this conversation is in. `text` becomes the caption."}));
        p.insert("silent".into(), json!({"type": "boolean", "description": "Send without a notification where supported"}));
        p.insert("format".into(), json!({"type": "string", "enum": ["plain", "markdown"]}));
        p.insert("question".into(), json!({"type": "string", "description": "Poll question (action=poll)"}));
        p.insert("options".into(), json!({"type": "array", "items": {"type": "string"}, "description": "Poll options, 2–12 after trimming and de-duplication"}));
        p.insert("pollQuestion".into(), json!({"type": "string", "description": "snake/camel alias of `question`"}));
        p.insert("pollOption".into(), json!({"type": "array", "items": {"type": "string"}, "description": "alias of `options`"}));
        p.insert("pollMulti".into(), json!({"type": "boolean", "description": "Allow multiple selections (alias: allowMultiselect)"}));
        p.insert("maxSelections".into(), json!({"type": "integer", "minimum": 1, "description": "Answers a voter may pick; must not exceed the option count"}));
        p.insert("durationSeconds".into(), json!({"type": "integer", "minimum": 1, "description": "Poll duration (Telegram 5–604800); exclusive with durationHours"}));
        p.insert("durationHours".into(), json!({"type": "integer", "minimum": 1, "description": "Poll duration in hours (Discord); exclusive with durationSeconds"}));
        p.insert("limit".into(), json!({"type": "integer", "minimum": 1, "description": "read/reactions result limit"}));
        p.insert("before".into(), json!({"type": "string", "description": "read: page before this id"}));
        p.insert("after".into(), json!({"type": "string", "description": "read: page after this id"}));
        ToolSpec {
            name: "message".into(),
            description: format!(
                "Send and manage chat messages (configured channels: {configured}). `action` = `send` (default) posts `text` to `target` = `channel:chat[:thread]`; `reply` also takes `replyTo`. Other actions are the channel's own: poll takes `question` + `options`, react takes `messageId` + `emoji`, edit/delete/pin/read take `messageId`. Returns JSON."
            ),
            input_schema: json!({"type": "object", "properties": Value::Object(p)}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        // Text leaving the machine for a human needs the egress gate's say-so (like `channel_send`).
        if !matches!(action_of(input).as_str(), "send" | "reply" | "edit") {
            return Vec::new();
        }
        let channel = aa::s(input, &["channel"])
            .or_else(|| aa::s(input, &["target", "to"]).and_then(|t| t.split(':').next().map(str::to_string)))
            .unwrap_or_else(|| "?".into());
        let mut payload = aa::text(input, &["text", "message"]).unwrap_or_default();
        for k in ["media", "files", "path", "file"] {
            match input.get(k) {
                Some(Value::String(f)) => payload.push_str(&format!("\n[file: {f}]")),
                Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str()).for_each(|f| payload.push_str(&format!("\n[file: {f}]"))),
                _ => {}
            }
        }
        vec![Effect::Send { channel, payload }]
    }

    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let roots = [ctx.workspace.clone(), ctx.artifacts.clone()];
        match dispatch_in(&self.targets, &input, &ctx.workspace, &roots, Some(&ctx.session_id)) {
            Ok(o) => ToolOutput::ok(o.summary),
            Err(e) => ToolOutput::err(e),
        }
    }
}

/// A validated poll (upstream `NormalizedPollInput`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Poll {
    pub question: String,
    pub options: Vec<String>,
    pub max_selections: u64,
    pub duration_seconds: Option<u64>,
    pub duration_hours: Option<u64>,
}

impl Poll {
    /// The camelCase fields the per-channel `poll` actions read.
    pub fn to_args(&self) -> Value {
        let mut m = Map::new();
        m.insert("question".into(), json!(self.question));
        m.insert("options".into(), json!(self.options));
        m.insert("maxSelections".into(), json!(self.max_selections));
        if let Some(s) = self.duration_seconds {
            m.insert("durationSeconds".into(), json!(s));
        }
        if let Some(h) = self.duration_hours {
            m.insert("durationHours".into(), json!(h));
        }
        Value::Object(m)
    }
}

/// `normalizePollInput`: trim and bound the question, trim / drop empty / de-duplicate the
/// options, resolve `maxSelections` (1 unless multi-select is asked for), and keep at most one
/// duration. Accepts camelCase (OpenClaw) and snake_case aliases.
pub fn normalize_poll(a: &Value, max_options: usize) -> Result<Poll, ChannelError> {
    let question = aa::s(a, &["question", "pollQuestion", "poll_question", "title"]).ok_or_else(|| aa::bad("Poll question is required"))?;
    if question.chars().count() > MAX_POLL_QUESTION {
        return Err(aa::bad(format!("Poll question is too long (max {MAX_POLL_QUESTION} characters)")));
    }
    let mut options: Vec<String> = Vec::new();
    for o in aa::list(a, &["options", "pollOption", "poll_option", "answers", "choices"]) {
        let o = o.trim().to_string();
        if o.is_empty() {
            continue;
        }
        if o.chars().count() > MAX_POLL_OPTION {
            return Err(aa::bad(format!("Poll option `{o}` is too long (max {MAX_POLL_OPTION} characters)")));
        }
        if !options.iter().any(|x| x == &o) {
            options.push(o);
        }
    }
    if options.len() < 2 {
        return Err(aa::bad("Poll requires at least 2 options"));
    }
    if options.len() > max_options {
        return Err(aa::bad(format!("Poll supports at most {max_options} options")));
    }
    let multi = ["allowMultiselect", "pollMulti", "allow_multiselect", "poll_multi"].iter().any(|k| aa::flag(a, k) == Some(true));
    let max_selections = match aa::int(a, &["maxSelections", "max_selections"]) {
        Some(n) if n < 1 => return Err(aa::bad("maxSelections must be at least 1")),
        Some(n) if n as usize > options.len() => return Err(aa::bad("maxSelections cannot exceed option count")),
        Some(n) => n as u64,
        None if multi => (options.len() as u64).max(2),
        None => 1,
    };
    let secs = aa::int(a, &["durationSeconds", "duration_seconds", "pollDurationSeconds", "poll_duration_seconds"]);
    let hours = aa::int(a, &["durationHours", "duration_hours", "pollDurationHours", "poll_duration_hours"]);
    if secs.is_some_and(|s| s < 1) {
        return Err(aa::bad("durationSeconds must be at least 1"));
    }
    if hours.is_some_and(|h| h < 1) {
        return Err(aa::bad("durationHours must be at least 1"));
    }
    if secs.is_some() && hours.is_some() {
        return Err(aa::bad("durationSeconds and durationHours are mutually exclusive"));
    }
    Ok(Poll { question, options, max_selections, duration_seconds: secs.map(|s| s as u64), duration_hours: hours.map(|h| h as u64) })
}

/// `a` with the normalised poll fields written over it (channel actions read the camelCase keys;
/// nothing else the caller passed — `target`, `threadId`, `message`, `silent` — is dropped).
pub fn normalize_poll_args(a: &Value, max_options: usize) -> Result<Value, ChannelError> {
    let poll = normalize_poll(a, max_options)?;
    let mut v = match a {
        Value::Object(m) => Value::Object(m.clone()),
        _ => json!({}),
    };
    if let Value::Object(m) = &mut v {
        if let Value::Object(p) = poll.to_args() {
            for (k, val) in p {
                m.insert(k, val);
            }
        }
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::tool_ctx;
    use crate::{Cancel, Caps, Inbound, Sent};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fake {
        actions: Vec<&'static str>,
        caps: Caps,
        sent: Mutex<Vec<Outbound>>,
        edits: Mutex<Vec<(String, String, String)>>,
        deleted: Mutex<Vec<(String, String)>>,
        reactions: Mutex<Vec<(String, String, String, bool)>>,
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl Fake {
        fn new(actions: &[&'static str]) -> Arc<Fake> {
            Arc::new(Fake { actions: actions.to_vec(), caps: Caps { edit: true, delete: true, reply: true, reactions: 1, ..Default::default() }, ..Default::default() })
        }
    }

    impl Channel for Fake {
        fn id(&self) -> &str {
            "fake"
        }
        fn poll(&self, _: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
            Ok(vec![])
        }
        fn caps(&self) -> Caps {
            self.caps.clone()
        }
        fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
            self.sent.lock().unwrap().push(out.clone());
            Ok(Sent { ids: vec!["m1".into()] })
        }
        fn edit(&self, chat: &str, id: &str, text: &str) -> Result<(), ChannelError> {
            self.edits.lock().unwrap().push((chat.into(), id.into(), text.into()));
            Ok(())
        }
        fn delete(&self, chat: &str, id: &str) -> Result<(), ChannelError> {
            self.deleted.lock().unwrap().push((chat.into(), id.into()));
            Ok(())
        }
        fn react(&self, chat: &str, id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
            self.reactions.lock().unwrap().push((chat.into(), id.into(), emoji.into(), remove));
            Ok(())
        }
        fn message_actions(&self) -> Vec<&'static str> {
            self.actions.clone()
        }
        fn message_action(&self, action: &str, args: &Value) -> Result<Value, ChannelError> {
            if !self.actions.contains(&action) {
                return Err(crate::unsupported(action));
            }
            self.calls.lock().unwrap().push((action.into(), args.clone()));
            Ok(json!({"ok": true, "action": action, "messageId": "p1"}))
        }
    }

    fn targets(ch: Arc<Fake>) -> Targets {
        let mut t = Targets::new();
        t.insert("tg".into(), (ch as Arc<dyn Channel>, Some("42".into())));
        t
    }

    #[test]
    fn sends_text_with_target_thread_and_alias() {
        let ch = Fake::new(&["poll", "pin"]);
        let tool = MessageTool::new(targets(ch.clone()));
        let ctx = tool_ctx();
        let r = tool.call(&ctx, json!({"target": "tg:-100:7", "text": "hi there"}));
        assert!(!r.is_error, "{}", r.content);
        assert!(r.content.contains("sent 8 chars to tg/-100"), "{}", r.content);
        let sent = ch.sent.lock().unwrap().clone();
        assert_eq!((sent[0].chat.as_str(), sent[0].text.as_str(), sent[0].thread.as_deref()), ("-100", "hi there", Some("7")));
        // `message` is OpenClaw's send payload key; `replyTo` becomes a reply.
        assert!(!tool.call(&ctx, json!({"chat": "9", "message": "x", "replyTo": "5", "format": "markdown"})).is_error);
        let sent = ch.sent.lock().unwrap().clone();
        assert_eq!((sent[1].chat.as_str(), sent[1].reply_to.as_deref(), sent[1].format), ("9", Some("5"), TextFormat::Markdown));
        // No channel name: the only configured one is used; chat falls back to its default.
        assert!(!tool.call(&ctx, json!({"text": "y"})).is_error);
        assert_eq!(ch.sent.lock().unwrap()[2].chat, "42");
        assert_eq!(tool.effects(&ctx, &json!({"text": "hi"})), vec![Effect::Send { channel: "?".into(), payload: "hi".into() }]);
        assert!(tool.effects(&ctx, &json!({"action": "read"})).is_empty());
        let r = tool.call(&ctx, json!({"text": " "}));
        assert!(r.is_error && r.content.contains("`text` is empty"), "{}", r.content);
    }

    #[test]
    fn generic_actions_use_the_channel_trait() {
        let ch = Fake::new(&["poll"]);
        let tool = MessageTool::new(targets(ch.clone()));
        let ctx = tool_ctx();
        assert!(!tool.call(&ctx, json!({"action": "edit", "chat": "C", "messageId": "5", "text": "new"})).is_error);
        assert_eq!(ch.edits.lock().unwrap().clone(), vec![("C".to_string(), "5".to_string(), "new".to_string())]);
        assert!(!tool.call(&ctx, json!({"action": "delete", "chat": "C", "messageId": "5"})).is_error);
        assert!(!tool.call(&ctx, json!({"action": "react", "chat": "C", "messageId": "5", "emoji": "👍"})).is_error);
        assert!(!tool.call(&ctx, json!({"action": "react", "chat": "C", "messageId": "5", "emoji": "👍", "remove": true})).is_error);
        assert_eq!(ch.reactions.lock().unwrap().len(), 2);
        assert!(ch.reactions.lock().unwrap()[1].3, "remove flag is passed through");
        assert!(ch.calls.lock().unwrap().is_empty(), "generic actions never reach message_action");
        // `reply` is a send carrying the replied-to id.
        assert!(!tool.call(&ctx, json!({"action": "reply", "chat": "C", "messageId": "5", "text": "hey"})).is_error);
        assert_eq!(ch.sent.lock().unwrap()[0].reply_to.as_deref(), Some("5"));
        let r = tool.call(&ctx, json!({"action": "edit", "chat": "C", "text": "x"}));
        assert!(r.is_error && r.content.contains("messageId required"), "{}", r.content);
        let r = tool.call(&ctx, json!({"action": "react", "chat": "C", "messageId": "5"}));
        assert!(r.is_error && r.content.contains("emoji required"), "{}", r.content);
    }

    #[test]
    fn poll_is_normalised_before_the_channel_action() {
        let ch = Fake::new(&["poll", "pin"]);
        let tool = MessageTool::new(targets(ch.clone()));
        let ctx = tool_ctx();
        let r = tool.call(&ctx, json!({"action": "poll", "chat": "C", "question": "  Lunch today? ", "options": ["Pizza", " Sushi ", "Pizza"], "pollMulti": true, "durationHours": 2}));
        assert!(!r.is_error, "{}", r.content);
        let calls = ch.calls.lock().unwrap().clone();
        assert_eq!(calls[0].0, "poll");
        let a = &calls[0].1;
        assert_eq!(a["question"], "Lunch today?");
        assert_eq!(a["options"], json!(["Pizza", "Sushi"]));
        assert_eq!(a["maxSelections"], 2);
        assert_eq!(a["durationHours"], 2);
        assert_eq!(a["target"], "C");
        assert!(r.content.contains("\"messageId\": \"p1\""), "the channel's JSON is returned: {}", r.content);
    }

    #[test]
    fn poll_validation_is_actionable() {
        let bad = |v: Value| normalize_poll(&v, MAX_POLL_OPTIONS).unwrap_err().message;
        assert!(bad(json!({"options": ["a", "b"]})).contains("question is required"));
        assert!(bad(json!({"question": "q", "options": ["a"]})).contains("at least 2"));
        assert!(bad(json!({"question": "q", "options": ["a", "b", "c"], "maxSelections": 4})).contains("cannot exceed"));
        assert!(bad(json!({"question": "q", "options": ["a", "b"], "maxSelections": 0})).contains("at least 1"));
        assert!(bad(json!({"question": "q", "options": ["a", "b"], "durationSeconds": 60, "durationHours": 1})).contains("mutually exclusive"));
        assert!(bad(json!({"question": "q", "options": ["a", "b"], "durationHours": 0})).contains("durationHours must be at least 1"));
        let many: Vec<String> = (0..13).map(|i| format!("o{i}")).collect();
        assert!(bad(json!({"question": "q", "options": many})).contains("at most 12"));
        assert!(bad(json!({"question": "q", "options": ["a", "b".repeat(200)]})).contains("too long"));
        assert!(bad(json!({"question": "q".repeat(400), "options": ["a", "b"]})).contains("too long"));
        // snake_case aliases work (poll_question / poll_option / duration_seconds).
        let p = normalize_poll(&json!({"pollQuestion": "q", "pollOption": "a, b", "allow_multiselect": true, "duration_seconds": 60}), MAX_POLL_OPTIONS).unwrap();
        assert_eq!((p.options.len(), p.max_selections, p.duration_seconds, p.duration_hours), (2, 2, Some(60), None));
        assert_eq!(p.to_args()["durationSeconds"], 60);
        // A poll that fails validation never reaches the channel.
        let ch = Fake::new(&["poll"]);
        let tool = MessageTool::new(targets(ch.clone()));
        assert!(tool.call(&tool_ctx(), json!({"action": "poll", "chat": "C", "question": "q", "options": ["a"]})).is_error);
        assert!(ch.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn unknown_actions_list_the_available_ones() {
        let ch = Fake::new(&["poll", "pin", "read"]);
        let tool = MessageTool::new(targets(ch.clone()));
        let r = tool.call(&tool_ctx(), json!({"action": "kick", "chat": "C", "userId": "1"}));
        assert!(r.is_error);
        assert!(r.content.contains("does not support action `kick`"), "{}", r.content);
        assert!(r.content.contains("poll, pin, read"), "{}", r.content);
        // An action the channel advertises but has no handler for gets the same treatment.
        let r = tool.call(&tool_ctx(), json!({"action": "poll", "chat": "C", "question": "q", "options": ["a", "b"]}));
        assert!(!r.is_error, "{}", r.content);
        let r = tool.call(&tool_ctx(), json!({"action": "nope", "chat": "C"}));
        assert!(r.content.contains("poll, pin, read"), "{}", r.content);
    }

    #[test]
    fn target_parsing_keeps_id_prefixes() {
        let names = ["tg", "discord"];
        assert_eq!(parse_target("tg:-100:7", &names).unwrap(), (Some("tg".into()), "-100".into(), Some("7".into())));
        assert_eq!(parse_target("-100", &names).unwrap(), (None, "-100".into(), None));
        assert_eq!(parse_target("channel:C1", &names).unwrap(), (None, "channel:C1".into(), None));
        assert_eq!(parse_target("user:U5", &names).unwrap(), (None, "user:U5".into(), None));
        assert_eq!(parse_target("team:T9:channel:C1", &names).unwrap(), (None, "team:T9:channel:C1".into(), None));
        assert_eq!(parse_target("discord:C1:1700000000.000001", &names).unwrap(), (Some("discord".into()), "C1".into(), Some("1700000000.000001".into())));
        assert!(parse_target(" ", &names).is_err());
        // `--channel` disagreeing with the target prefix is caught before any send.
        let ch = Fake::new(&[]);
        let mut t = targets(ch.clone());
        t.insert("other".into(), (ch.clone() as Arc<dyn Channel>, None));
        let r = MessageTool::new(t).call(&tool_ctx(), json!({"target": "tg:1", "channel": "other", "text": "x"}));
        assert!(r.is_error && r.content.contains("names channel `tg`"), "{}", r.content);
        assert!(ch.sent.lock().unwrap().is_empty());
    }

    #[test]
    fn spec_advertises_send_plus_the_channels_actions() {
        let ch = Fake::new(&["poll", "pin", "thread-create"]);
        let spec = MessageTool::new(targets(ch)).spec();
        assert_eq!(spec.name, "message");
        let e = spec.input_schema["properties"]["action"]["enum"].as_array().unwrap().clone();
        let names: Vec<&str> = e.iter().filter_map(|v| v.as_str()).collect();
        for n in ["send", "reply", "edit", "delete", "react", "poll", "pin", "thread-create"] {
            assert!(names.contains(&n), "`{n}` missing from {names:?}");
        }
        assert_eq!(names[0], "send", "send is the default and comes first");
        assert!(spec.input_schema["properties"]["target"]["description"].as_str().unwrap().contains("channel:chat"));
        assert!(spec.description.contains("tg"));
        assert!(!spec.pinned && !spec.parallel_safe);
        // A channel with no extra actions still gets the generic ones.
        let bare = Fake::new(&[]);
        assert_eq!(actions_of(&targets(bare)), vec!["send", "reply", "edit", "delete", "react"]);
        // …and an empty target map still yields a usable schema.
        assert_eq!(actions_of(&Targets::new()), vec!["send"]);
        let r = MessageTool::new(Targets::new()).call(&tool_ctx(), json!({"text": "x"}));
        assert!(r.is_error && r.content.contains("no channels"), "{}", r.content);
    }

    #[test]
    fn sends_files_to_the_origin_chat_and_refuses_paths_outside_the_workspace() {
        let ch = Arc::new(Fake { caps: Caps { media: true, ..Default::default() }, ..Default::default() });
        let tool = MessageTool::new(targets(ch.clone()));
        let mut ctx = tool_ctx();
        let outside = ark_core::tmp::scratch("ark-ch-outside");
        std::fs::write(ctx.workspace.join("out.pdf"), b"%PDF").unwrap();
        std::fs::write(outside.join("key.txt"), b"secret").unwrap();
        // No target: the file goes to the chat this session came from.
        ctx.session_id = "origin-test-session".into();
        crate::outfile::set_origin(Some(Arc::new(|s: &str| (s == "origin-test-session").then(|| ("tg".to_string(), "777".to_string())))));
        let r = tool.call(&ctx, json!({"media": ["out.pdf"], "text": "report"}));
        assert!(!r.is_error, "{}", r.content);
        assert!(r.content.contains("1 file(s) to tg/777"), "{}", r.content);
        let sent = ch.sent.lock().unwrap().clone();
        assert_eq!((sent[0].chat.as_str(), sent[0].text.as_str(), sent[0].media.len()), ("777", "report", 1));
        assert_eq!(sent[0].media[0].mime, "application/pdf");
        assert!(sent[0].media[0].path.as_deref().unwrap().ends_with("out.pdf"));
        // A file with no text at all is fine; one outside workspace/artifacts is refused and nothing is sent.
        assert!(!tool.call(&ctx, json!({"media": "out.pdf"})).is_error);
        let n = ch.sent.lock().unwrap().len();
        let r = tool.call(&ctx, json!({"media": [outside.join("key.txt").display().to_string()], "text": "x"}));
        assert!(r.is_error && r.content.contains("outside"), "{}", r.content);
        assert_eq!(ch.sent.lock().unwrap().len(), n);
        // The egress gate sees the file names.
        let e = tool.effects(&ctx, &json!({"media": ["out.pdf"], "text": "report"}));
        assert!(matches!(&e[0], Effect::Send { payload, .. } if payload.contains("[file: out.pdf]")));
        // A channel that cannot carry files says so.
        let plain = MessageTool::new(targets(Fake::new(&[])));
        assert!(plain.call(&ctx, json!({"media": ["out.pdf"]})).content.contains("cannot carry files"));
        crate::outfile::set_origin(None);
        let _ = std::fs::remove_dir_all(&outside);
    }
}
