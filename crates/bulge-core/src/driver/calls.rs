//! The model's tool calls: repair, extraction, the plan tool, harness
//! notes, and how outcomes are rendered back.

use bulge_llm::{ContentBlock, LlmError, Message, Role, ToolSchema};
use bulge_store::{PlanItem, PlanStatus};
use serde_json::Value;
use crate::dispatch::ToolCall;
use crate::schedule::CallOutcome;

/// Parse the plan tool's arguments into plan items. Lenient on status (defaults
/// to `pending`, unknown values rejected); requires a non-empty `text` per item.
pub(crate) fn parse_plan(raw: &str) -> Result<Vec<PlanItem>, String> {
    let value = serde_json::from_str::<Value>(raw).map_err(|e| format!("arguments are not JSON: {e}"))?;
    let items = value.get("items").and_then(Value::as_array).ok_or("expected an `items` array")?;
    let mut plan = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let text = item.get("text").and_then(Value::as_str).unwrap_or("").trim();
        if text.is_empty() {
            return Err(format!("item {index} has an empty `text`"));
        }
        let status = match item.get("status").and_then(Value::as_str) {
            None | Some("pending") => PlanStatus::Pending,
            Some("in_progress") => PlanStatus::InProgress,
            Some("done") => PlanStatus::Done,
            Some("dropped") => PlanStatus::Dropped,
            Some(other) => return Err(format!("item {index} has an unknown status {other:?}")),
        };
        plan.push(PlanItem { text: text.to_string(), status });
    }
    Ok(plan)
}

/// Count of items the plan has finished (used for stall detection).
pub(crate) fn plan_done_count(plan: &[PlanItem]) -> usize {
    plan.iter().filter(|item| item.status == PlanStatus::Done).count()
}

/// A plan is settled when every item is done or dropped (nothing left to stall on).
pub(crate) fn plan_settled(plan: &[PlanItem]) -> bool {
    !plan.is_empty() && plan.iter().all(|item| matches!(item.status, PlanStatus::Done | PlanStatus::Dropped))
}

/// A one-string-argument tool call (for the gate's own read/exec checks).
pub(crate) fn string_call(name: &str, key: &str, value: &str) -> ToolCall {
    let mut arguments = serde_json::Map::new();
    arguments.insert(key.to_string(), Value::String(value.to_string()));
    ToolCall { name: name.to_string(), arguments }
}

/// Truncate on a char boundary for a short, safe diagnostic snippet.
pub(crate) fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let kept: String = text.chars().take(max_chars).collect();
    format!("{kept}…")
}

pub(crate) struct ExtractedCall {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) arguments: String,
}

/// Why a call is not dispatched. `Ask` is failed closed until a human channel
/// exists; it is still logged as an approval request for the UI.
pub(crate) enum PermissionBlock {
    Deny(String),
    Ask { resource: String },
}

/// Marks a message bulge itself puts in the conversation as the user role
/// (budget notes, reminders, completion-gate requests and feedback). It tells
/// the model and the post-job learner apart from what the user wrote: such text
/// is never a user preference.
pub const HARNESS_NOTE_OPEN: &str = "<harness-note>";
pub const HARNESS_NOTE_CLOSE: &str = "</harness-note>";

/// A user-role message carrying a note from bulge itself.
pub fn harness_note(text: impl AsRef<str>) -> Message {
    Message::text(Role::User, format!("{HARNESS_NOTE_OPEN}\n{}\n{HARNESS_NOTE_CLOSE}", text.as_ref()))
}

/// Sent when a reply was cut off by the output token limit.
pub(crate) const TRUNCATED_NOTE: &str = "Your previous reply was cut off by the output token limit. Continue from where it stopped. If you were writing a tool call, make it again with complete arguments; keep large content smaller (split it across several calls).";

/// Weak and local models sometimes write a tool call as plain text instead of
/// a structured call. Turn such standalone blocks (never fenced code, only
/// tools this driver offers) into real calls, so the turn runs the tool rather
/// than being taken as a final answer. A message that already has structured
/// calls is left alone.
pub(crate) fn repair_text_tool_calls(message: &mut Message, tools: &[ToolSchema]) {
    if message.content.iter().any(|block| matches!(block, ContentBlock::ToolCall { .. })) {
        return;
    }
    let Some(text) = assistant_text(message) else { return };
    if !bulge_llm::repair::looks_like_tool_call(&text) {
        return;
    }
    let options = bulge_llm::repair::RepairOptions {
        allowed_tools: tools.iter().map(|tool| tool.name.clone()).collect(),
        ..Default::default()
    };
    let (calls, rest) = bulge_llm::repair::repair(&text, &options);
    if calls.is_empty() {
        return;
    }
    message.content.retain(|block| !matches!(block, ContentBlock::Text { .. }));
    if !rest.trim().is_empty() {
        message.content.push(ContentBlock::Text { text: rest });
    }
    message.content.extend(
        calls
            .into_iter()
            .enumerate()
            .map(|(index, call)| ContentBlock::ToolCall { id: format!("repaired_{index}"), name: call.name, arguments: call.arguments }),
    );
}

/// Make every tool-call id in `message` non-empty and unique. Ids come from
/// the model; a repeated or empty id would collide in the claim log and is
/// rejected by providers on the next request.
pub(crate) fn unique_call_ids(message: &mut Message) {
    let mut seen = std::collections::HashSet::new();
    for (index, block) in message.content.iter_mut().enumerate() {
        if let ContentBlock::ToolCall { id, .. } = block {
            if id.is_empty() {
                *id = format!("call_{index}");
            }
            let mut candidate = id.clone();
            let mut n = 1;
            while !seen.insert(candidate.clone()) {
                n += 1;
                candidate = format!("{id}_{n}");
            }
            *id = candidate;
        }
    }
}

pub(crate) fn extract_tool_calls(message: &Message) -> Vec<ExtractedCall> {
    message
        .content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::ToolCall { id, name, arguments } => {
                Some(ExtractedCall { id: id.clone(), name: name.clone(), arguments: arguments.clone() })
            }
            _ => None,
        })
        .collect()
}

pub(crate) fn assistant_text(message: &Message) -> Option<String> {
    let text = message.joined_text();
    (!text.is_empty()).then_some(text)
}

pub(crate) fn parse_lenient(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_owned()))
}

/// The primary resource a permission rule matches against for this tool.
pub(crate) fn call_resource(call: &ExtractedCall) -> String {
    let args = parse_lenient(&call.arguments);
    if call.name == crate::dispatch::BROWSER_TOOL {
        // "<action> <url>" so a rule can target a site, e.g. `navigate *bank*`.
        let action = args.get("action").and_then(Value::as_str).unwrap_or("");
        let url = args.get("url").and_then(Value::as_str).unwrap_or("");
        return format!("{action} {url}").trim().to_owned();
    }
    let field = match call.name.as_str() {
        "exec" => "command",
        "glob" | "grep" => "pattern",
        _ => "path",
    };
    args.get(field).and_then(Value::as_str).unwrap_or("").to_owned()
}

/// A `view_image` result → the result without the image bytes, and a user
/// message carrying the image (shown to the model right after the results).
pub(crate) fn split_image(outcome: CallOutcome) -> (CallOutcome, Option<Message>) {
    let CallOutcome::Ok(mut value) = outcome else { return (outcome, None) };
    let (Some(media_type), Some(data)) = (value.get("media_type").and_then(Value::as_str).map(str::to_owned), value.get("data").and_then(Value::as_str).map(str::to_owned)) else {
        return (CallOutcome::Ok(value), None);
    };
    let path = value.get("path").and_then(Value::as_str).unwrap_or("").to_owned();
    if let Some(object) = value.as_object_mut() {
        object.remove("data");
        object.insert("shown".into(), Value::String("the image is in the next message".into()));
    }
    let message = Message {
        role: Role::User,
        content: vec![ContentBlock::Text { text: format!("{HARNESS_NOTE_OPEN}\nThe image from view_image `{path}`:\n{HARNESS_NOTE_CLOSE}") }, ContentBlock::Image { media_type, data }],
        ..Message::text(Role::User, String::new())
    };
    (CallOutcome::Ok(value), Some(message))
}

/// Structured value for loop-detection outcome hashing.
pub(crate) fn outcome_value(outcome: &CallOutcome) -> Value {
    match outcome {
        CallOutcome::Ok(value) => value.clone(),
        CallOutcome::Err { code, message } => serde_json::json!({ "error": code, "message": message }),
        CallOutcome::InvalidArguments(detail) => serde_json::json!({ "error": "INVALID_ARGUMENTS", "message": detail }),
        CallOutcome::Skipped => serde_json::json!({ "error": "SKIPPED" }),
    }
}

pub(crate) fn error_summary(error: &LlmError) -> String {
    format!("model error: {error}")
}

/// (ok, structured result for the log, text the model sees).
pub(crate) fn render_outcome(outcome: CallOutcome) -> (bool, Value, String) {
    match outcome {
        CallOutcome::Ok(value) => {
            let text = value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string());
            (true, value, text)
        }
        CallOutcome::Err { code, message } => {
            let text = format!("{code}: {message}");
            (false, serde_json::json!({ "code": code, "message": message }), text)
        }
        CallOutcome::InvalidArguments(detail) => {
            (false, serde_json::json!({ "code": "INVALID_ARGUMENTS", "message": detail.clone() }), format!("INVALID_ARGUMENTS: {detail}"))
        }
        CallOutcome::Skipped => (false, serde_json::json!({ "code": "SKIPPED", "message": "not run (job stopping)" }), "SKIPPED: not run (job stopping)".into()),
    }
}
