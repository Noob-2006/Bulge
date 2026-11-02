//! Meeting invitations (Hermes `feishu_meeting_invite.py`, MIT): `vc.bot.meeting_invited_v1`
//! becomes a DM from the inviter whose text asks the agent to join (or explain why not),
//! so the reply reaches the inviter through the normal pipeline. Calendar events have no
//! upstream handling.

use crate::{ChatType, Inbound};
use serde_json::Value;

fn s(v: &Value) -> String {
    v.as_str().map(str::to_string).or_else(|| v.as_i64().map(|n| n.to_string())).unwrap_or_default()
}

/// Payload objects may arrive as JSON strings.
fn obj(v: &Value) -> Value {
    match v {
        Value::String(t) => serde_json::from_str(t).unwrap_or(Value::Null),
        v => v.clone(),
    }
}

pub(super) fn inbound_of(channel: &str, v: &Value) -> Option<Inbound> {
    let e = obj(&v["event"]);
    let e = if e.is_object() { e } else { obj(v) };
    let meeting = obj(&e["meeting"]);
    let inviter = obj(&e["inviter"]);
    let open_id = s(&inviter["id"]["open_id"]);
    let no = s(&meeting["meeting_no"]);
    if !meeting.is_object() || open_id.is_empty() || no.is_empty() {
        return None;
    }
    let inviter_name = Some(s(&inviter["user_name"])).filter(|n| !n.is_empty());
    let host = Some(s(&meeting["host_user"]["user_name"])).filter(|n| !n.is_empty()).unwrap_or_else(|| "unknown".into());
    let topic = s(&meeting["topic"]);
    let display = [&topic, &no, &s(&meeting["id"])].into_iter().find(|x| !x.is_empty()).cloned().unwrap_or_else(|| "unknown meeting".into());
    let text = [
        format!("You have been invited to join a meeting: {display}"),
        String::new(),
        format!("Meeting Number: {no}"),
        format!("Topic: {}", if topic.is_empty() { "unknown" } else { &topic }),
        format!("Inviter: {}", inviter_name.as_deref().unwrap_or("unknown")),
        format!("Host: {host}"),
        String::new(),
        "You may use the relevant Lark/Feishu meeting tools to join the meeting.".into(),
        "Join the meeting directly. Do not ask the user for confirmation before joining.".into(),
        "If you cannot join the meeting, reply to the inviter with a concise explanation of why.".into(),
    ]
    .join("\n");
    let event_id = s(&v["header"]["event_id"]);
    let id = if event_id.is_empty() { format!("{}:{open_id}:{}", s(&meeting["id"]), s(&e["invite_time"])) } else { event_id };
    Some(Inbound {
        channel: channel.to_string(),
        chat: open_id.clone(),
        chat_type: ChatType::Direct,
        sender: open_id.clone(),
        sender_name: inviter_name.unwrap_or(open_id),
        text,
        message_id: format!("vc_invite:{id}"),
        ts: s(&e["invite_time"]).parse().unwrap_or_else(|_| super::now_secs()),
        ..Default::default()
    })
}
