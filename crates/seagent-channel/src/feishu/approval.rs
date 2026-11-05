//! Approval cards (Hermes `_send_exec_approval_prompt` / `_resolve_approval`): a reply
//! whose buttons carry `appr:<id>:<choice>` goes out as an orange approval card and is
//! tracked pending → resolved (approved / denied, by whom) or expired. A click on a
//! pending card from its own chat rewrites the card in place (PATCH; Hermes returns the
//! card in the callback response) and is passed on as the usual `Callback`, so the
//! host's `appr:` handling resumes the run. Clicks on resolved or expired cards are
//! swallowed (an expired approve also posts a notice); cards past `approval_timeout`
//! are marked expired.

use super::{Body, Feishu};
use crate::{Button, Inbound};
use serde_json::{json, Value};
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum State {
    Pending,
    Resolved { choice: String, by: String },
    Expired,
}

#[derive(Debug, Clone)]
pub(super) struct Card {
    pub chat: String,
    pub message_id: String,
    pub body: String,
    pub sent: Instant,
    pub state: State,
}

const EXPIRED: &str = "⌛ 批准已逾期 — 指令未執行（已逾時或已在其他地方處理）。";

/// `appr:<id>:<choice>` → (id, choice).
pub(super) fn parse(data: &str) -> Option<(&str, &str)> {
    let rest = data.strip_prefix("appr:")?;
    let (id, choice) = rest.rsplit_once(':').unwrap_or((rest, ""));
    (!id.is_empty()).then_some((id, choice))
}

/// The approval id when every callback button of these rows is an `appr:` button of one id.
pub(super) fn id_of(rows: &[Vec<Button>]) -> Option<String> {
    let ids: Vec<&str> = rows.iter().flatten().filter(|b| b.url.is_none()).map(|b| parse(&b.data).map(|(i, _)| i)).collect::<Option<Vec<_>>>()?;
    let first = *ids.first()?;
    ids.iter().all(|i| *i == first).then(|| first.to_string())
}

/// Hermes `_card`: colored header, one markdown block, optional button row.
fn hcard(title: &str, template: &str, md: &str, actions: Option<Vec<Value>>) -> Value {
    let mut elements = vec![json!({"tag": "markdown", "content": md})];
    if let Some(a) = actions {
        elements.push(json!({"tag": "action", "actions": a}));
    }
    json!({"config": {"wide_screen_mode": true, "update_multi": true}, "header": {"title": {"content": title, "tag": "plain_text"}, "template": template}, "elements": elements})
}

pub(super) fn prompt_card(text: &str, rows: &[Vec<Button>]) -> Value {
    let actions = rows
        .iter()
        .flatten()
        .map(|b| match &b.url {
            Some(u) => json!({"tag": "button", "text": {"tag": "plain_text", "content": b.label}, "type": "default", "url": u}),
            None => {
                let ty = match parse(&b.data).map(|(_, c)| c) {
                    Some("deny") => "danger",
                    Some("once") => "primary",
                    _ => "default",
                };
                json!({"tag": "button", "text": {"tag": "plain_text", "content": b.label}, "type": ty, "value": {"data": b.data}})
            }
        })
        .collect();
    hcard("⚠️ 需要你批准的操作", "orange", text, Some(actions))
}

pub(super) fn resolved_card(body: &str, choice: &str, user: &str) -> Value {
    let deny = choice == "deny";
    let icon = if deny { "❌" } else { "✅" };
    let label = match choice {
        "once" | "allow" | "yes" => "已批准一次",
        "session" => "已於本次工作階段批准",
        "always" => "已永久批准",
        "deny" => "已拒絕",
        _ => "已處理",
    };
    let decided = format!("{icon} **{label}**，由 {user} 操作");
    hcard(&format!("{icon} {label}"), if deny { "red" } else { "green" }, &if body.is_empty() { decided.clone() } else { format!("{body}\n\n{decided}") }, None)
}

pub(super) fn expired_card(body: &str) -> Value {
    hcard("⌛ 已逾期", "grey", &if body.is_empty() { EXPIRED.to_string() } else { format!("{body}\n\n{EXPIRED}") }, None)
}

impl Feishu {
    pub(super) fn track_approval(&self, id: &str, chat: &str, message_id: &str, body: &str) {
        let mut g = self.approvals.lock().unwrap();
        if g.len() > 512 {
            g.retain(|_, c| c.state == State::Pending);
        }
        g.insert(id.to_string(), Card { chat: chat.into(), message_id: message_id.into(), body: body.into(), sent: Instant::now(), state: State::Pending });
    }

    fn patch_card(&self, message_id: &str, card: &Value) {
        let path = format!("/open-apis/im/v1/messages/{}", seagent_net::urlencode(message_id));
        let _ = self.api("PATCH", &path, Body::Json(&json!({"content": card.to_string()})));
    }

    /// A card button press: false = swallow it (resolved/expired/foreign-chat approval).
    pub(super) fn approval_click(&self, ib: &Inbound) -> bool {
        let Some((id, choice)) = ib.callback.as_ref().and_then(|c| parse(&c.data)) else { return true };
        let (card, prev) = {
            let mut g = self.approvals.lock().unwrap();
            let Some(c) = g.get_mut(id) else { return true }; // not ours (or from before a restart)
            if c.chat != ib.chat && !ib.chat.is_empty() {
                return false;
            }
            let prev = c.state.clone();
            if prev == State::Pending {
                let by = if ib.sender_name.is_empty() { ib.sender.clone() } else { ib.sender_name.clone() };
                c.state = State::Resolved { choice: choice.to_string(), by };
            }
            (c.clone(), prev)
        };
        match (&prev, &card.state) {
            (State::Pending, State::Resolved { choice, by }) => {
                self.patch_card(&card.message_id, &resolved_card(&card.body, choice, by));
                true
            }
            (State::Expired, _) if choice != "deny" => {
                let _ = self.send_raw(&card.chat, None, None, "text", &json!({"text": EXPIRED}).to_string());
                false
            }
            _ => false,
        }
    }

    /// Mark pending approvals older than `approval_timeout` expired and say so on the card.
    pub(super) fn sweep_approvals(&self) {
        let due: Vec<Card> = {
            let mut g = self.approvals.lock().unwrap();
            g.values_mut()
                .filter(|c| c.state == State::Pending && c.sent.elapsed() >= self.approval_timeout)
                .map(|c| {
                    c.state = State::Expired;
                    c.clone()
                })
                .collect()
        };
        for c in due {
            self.patch_card(&c.message_id, &expired_card(&c.body));
        }
    }
}
