//! Session progress cards (OpenClaw progress_card + src/session-cards, MIT): one durable
//! status surface per session, shown in the web UI and, for sessions that came from a
//! channel chat, mirrored into that chat as one message that is edited in place.

use super::{esc_html, now_ms, read_json, safe_key, strip_invisible, write_json, Env};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub const MAX_MARKDOWN_BYTES: usize = 8192;
pub const MAX_STEPS: usize = 50;
pub const MAX_STEP_BYTES: usize = 512;

/// `[surfaces.cards]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CardsConfig {
    /// Mirror cards of channel sessions into their chat (send once, then edit). Default true.
    pub channel_updates: bool,
}

impl Default for CardsConfig {
    fn default() -> Self {
        CardsConfig { channel_updates: true }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub step: String,
    /// pending | in_progress | completed
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    pub session_key: String,
    pub revision: u64,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub steps: Option<Vec<Step>>,
}

/// Stored row: the card plus its revision tombstone and channel message.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Row {
    revision: u64,
    created_at: u64,
    updated_at: u64,
    markdown: Option<String>,
    steps: Option<Vec<Step>>,
    /// (channel, chat, message id) of the mirrored chat message.
    message: Option<(String, String, String)>,
}

fn path(dir: &Path, session: &str) -> Result<std::path::PathBuf, String> {
    Ok(dir.join("cards").join(format!("{}.json", safe_key(session)?)))
}

static LOCK: Mutex<()> = Mutex::new(());

pub fn get(dir: &Path, session: &str) -> Option<Card> {
    let r: Row = read_json(&path(dir, session).ok()?)?;
    to_card(session, &r)
}

fn to_card(session: &str, r: &Row) -> Option<Card> {
    if r.markdown.is_none() && r.steps.as_ref().is_none_or(|s| s.is_empty()) {
        return None;
    }
    Some(Card { session_key: session.into(), revision: r.revision, updated_at: r.updated_at, markdown: r.markdown.clone(), steps: r.steps.clone().filter(|s| !s.is_empty()) })
}

/// Validate the replace-on-write payload (OpenClaw normalizeProgressCardInput).
pub fn normalize(markdown: &Value, plan: &Value) -> Result<(Option<String>, Option<Vec<Step>>), String> {
    let md = match markdown {
        Value::Null => None,
        Value::String(s) => {
            if s.len() > MAX_MARKDOWN_BYTES {
                return Err(format!("progress card markdown exceeds {MAX_MARKDOWN_BYTES} UTF-8 bytes"));
            }
            let s = strip_invisible(s);
            (!s.trim().is_empty()).then_some(s)
        }
        _ => return Err("markdown must be a string".into()),
    };
    let steps = match plan {
        Value::Null => None,
        Value::Array(a) => {
            if a.len() > MAX_STEPS {
                return Err(format!("plan can contain at most {MAX_STEPS} steps"));
            }
            let mut out = Vec::new();
            for (i, e) in a.iter().enumerate() {
                let o = e.as_object().ok_or_else(|| format!("plan[{i}] must be an object"))?;
                let step = o.get("step").and_then(|s| s.as_str()).ok_or_else(|| format!("plan[{i}].step must be a string"))?;
                if step.len() > MAX_STEP_BYTES {
                    return Err(format!("plan[{i}].step exceeds {MAX_STEP_BYTES} UTF-8 bytes"));
                }
                let step = strip_invisible(step);
                if step.trim().is_empty() {
                    return Err(format!("plan[{i}].step must not be empty"));
                }
                let status = o.get("status").and_then(|s| s.as_str()).filter(|s| matches!(*s, "pending" | "in_progress" | "completed")).ok_or_else(|| format!("plan[{i}].status must be one of pending, in_progress, completed"))?;
                out.push(Step { step, status: status.into() });
            }
            if out.iter().filter(|s| s.status == "in_progress").count() > 1 {
                return Err("plan can contain at most one in_progress step".into());
            }
            (!out.is_empty()).then_some(out)
        }
        _ => return Err("plan must be an array".into()),
    };
    Ok((md, steps))
}

/// Replace the card (both parts empty clears it, keeping the revision).
/// (channel, chat, message id) of a mirrored card message.
pub type Mirror = (String, String, String);

pub fn put(dir: &Path, session: &str, markdown: Option<String>, steps: Option<Vec<Step>>) -> Result<(Option<Card>, Option<Mirror>), String> {
    let _g = LOCK.lock().unwrap();
    let p = path(dir, session)?;
    let mut r: Row = read_json(&p).unwrap_or_default();
    let now = now_ms();
    if r.created_at == 0 {
        r.created_at = now;
    }
    let cleared = markdown.is_none() && steps.is_none();
    if cleared && r.markdown.is_none() && r.steps.is_none() && r.revision == 0 {
        return Ok((None, None));
    }
    r.revision += 1;
    r.updated_at = now;
    r.markdown = markdown;
    r.steps = steps;
    write_json(&p, &r)?;
    Ok((to_card(session, &r), r.message.clone()))
}

fn remember_message(dir: &Path, session: &str, m: Option<(String, String, String)>) {
    let _g = LOCK.lock().unwrap();
    let Ok(p) = path(dir, session) else { return };
    let mut r: Row = read_json(&p).unwrap_or_default();
    r.message = m;
    let _ = write_json(&p, &r);
}

/// Markdown → plain text for the channel summary: links keep their label, HTML is dropped.
pub fn strip_markdown(md: &str) -> String {
    let mut s = String::new();
    let mut in_tag = false;
    for c in md.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            c if !in_tag => s.push(c),
            _ => {}
        }
    }
    // [label](url) → label
    let re = regex_lite_links(&s);
    re.replace(['*', '_', '`', '#', '>'], "").split_whitespace().collect::<Vec<_>>().join(" ")
}

fn regex_lite_links(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('[') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        match (after.find("]("), after.find(']')) {
            (Some(j), Some(k)) if j == k => match after[j + 2..].find(')') {
                Some(e) => {
                    out.push_str(&after[..j]);
                    rest = &after[j + 2 + e + 1..];
                }
                None => {
                    out.push('[');
                    rest = after;
                }
            },
            _ => {
                out.push('[');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The `<progress aria-label value max>` bar the card may lead with.
fn progress_bar(md: &str) -> Option<(String, f64, f64)> {
    let i = md.find("<progress")?;
    let tag = &md[i..i + md[i..].find('>')?];
    let attr = |k: &str| tag.split(&format!("{k}=\"")).nth(1).and_then(|r| r.split('"').next()).map(str::to_string);
    Some((attr("aria-label").unwrap_or_default(), attr("value")?.parse().ok()?, attr("max").unwrap_or("100".into()).parse().ok()?))
}

/// Channel projection (OpenClaw projectProgressCardChannelUpdate): checklist counts, or the
/// readable note; plus the checklist itself.
pub fn channel_text(card: Option<&Card>) -> String {
    let Some(c) = card else { return "Progress card cleared".into() };
    let mut lines = Vec::new();
    if let Some((label, v, max)) = c.markdown.as_deref().and_then(progress_bar) {
        let filled = if max > 0.0 { ((v / max).clamp(0.0, 1.0) * 10.0).round() as usize } else { 0 };
        lines.push(format!("{}{} {label}", "▰".repeat(filled), "▱".repeat(10 - filled)));
    }
    match &c.steps {
        Some(steps) => {
            let done = steps.iter().filter(|s| s.status == "completed").count();
            lines.push(format!("Progress: {done}/{} complete", steps.len()));
            for s in steps {
                let mark = match s.status.as_str() {
                    "completed" => "✓",
                    "in_progress" => "▶",
                    _ => "○",
                };
                lines.push(format!("{mark} {}", s.step));
            }
            if let Some(md) = &c.markdown {
                let t = strip_markdown(md);
                if !t.is_empty() {
                    lines.push(t);
                }
            }
        }
        None => {
            let t = c.markdown.as_deref().map(strip_markdown).unwrap_or_default();
            lines.push(if t.is_empty() { "Progress updated".into() } else { t });
        }
    }
    lines.join("\n")
}

/// HTML for the dashboard's `session:progress` widget and the web UI card.
pub fn render_html(card: Option<&Card>) -> String {
    let Some(c) = card else { return "<p class=\"muted\">No progress card.</p>".into() };
    let mut h = String::new();
    if let Some((label, v, max)) = c.markdown.as_deref().and_then(progress_bar) {
        h.push_str(&format!("<progress aria-label=\"{}\" value=\"{v}\" max=\"{max}\" style=\"width:100%\"></progress><div class=\"muted\">{}</div>", esc_html(&label), esc_html(&label)));
    }
    if let Some(md) = &c.markdown {
        let t = strip_markdown(md);
        if !t.is_empty() {
            h.push_str(&format!("<p>{}</p>", esc_html(&t)));
        }
    }
    if let Some(steps) = &c.steps {
        h.push_str("<ul style=\"list-style:none;padding:0\">");
        for s in steps {
            let (mark, cls) = match s.status.as_str() {
                "completed" => ("✓", "ok"),
                "in_progress" => ("▶", "info"),
                _ => ("○", ""),
            };
            h.push_str(&format!("<li><span class=\"badge {cls}\">{mark}</span> {}</li>", esc_html(&s.step)));
        }
        h.push_str("</ul>");
    }
    h.push_str(&format!("<div class=\"muted\">rev {}</div>", c.revision));
    h
}

pub struct ProgressCard(pub Arc<Env>);

impl ProgressCard {
    /// Post the card to the session's chat once, then edit that message; a channel that
    /// cannot edit gets a new message per update.
    fn mirror(&self, session: &str, card: Option<&Card>, prior: Option<(String, String, String)>) -> Option<String> {
        if !self.0.cfg.cards.channel_updates {
            return None;
        }
        let (channel, chat, thread, _) = self.0.route_of(session)?;
        let ch = self.0.channels.get(&channel)?;
        let text = channel_text(card);
        if let Some((pc, pchat, id)) = prior.filter(|(c, ..)| *c == channel) {
            match ch.edit(&pchat, &id, &text) {
                Ok(()) => return Some(format!("updated in {pc}")),
                Err(e) if card.is_none() => return Some(format!("could not update the {pc} message: {}", e.message)),
                Err(_) => {}
            }
        }
        card?;
        let out = ark_channel::Outbound { chat: chat.clone(), text, thread, silent: true, ..Default::default() };
        match ch.send(&out) {
            Ok(sent) => {
                remember_message(&self.0.dir, session, sent.first().map(|id| (channel.clone(), chat, id.to_string())));
                Some(format!("posted to {channel}"))
            }
            Err(e) => Some(format!("could not post to {channel}: {}", e.message)),
        }
    }
}

impl Tool for ProgressCard {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "progress_card".into(),
            description: "Maintain this session's progress card: the single durable status surface shown next to the session in ark's UIs (and as one edited message in the channel chat the session came from), for someone who is not reading the transcript. Create a card only for substantial work with at least two meaningful sequential steps; not for greetings, quick questions, or single-step requests, and do not invent steps. Each call replaces the whole card. Use either or both parts: `markdown` — for measurable work with a known total, prefer a leading progress bar, e.g. <progress aria-label=\"PRs reviewed · 12/30\" value=\"12\" max=\"30\"></progress>, using observed completed/total counts and labelling what the count measures; never invent percentages. When the total is unknown, use a compact status note or table. Follow the bar with a short result, blocker, or next action. Other raw HTML is stripped. Link known URLs. And `plan` — an ordered checklist (pending | in_progress | completed, at most one in_progress) for genuinely sequential work; omit it when a table, bar, or sentence says it better, and never repeat the same facts in both parts. If work is blocked, keep the blocker, owner and resume condition in markdown and do not mark it completed. Call with both parts empty to clear. Update on meaningful change, not every message. Max 8 KB markdown, 50 steps.".into(),
            input_schema: json!({"type": "object", "properties": {
                "markdown": {"type": "string"},
                "plan": {"type": "array", "maxItems": MAX_STEPS, "items": {"type": "object", "properties": {"step": {"type": "string"}, "status": {"type": "string", "enum": ["pending", "in_progress", "completed"]}}, "required": ["step", "status"], "additionalProperties": false}}
            }, "additionalProperties": false}),
            parallel_safe: false,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        if !self.0.cfg.cards.channel_updates {
            return vec![];
        }
        // Mirroring into the session's own chat is a message to a human.
        match self.0.route_of(&ctx.session_id) {
            Some((channel, ..)) if self.0.channels.contains_key(&channel) => vec![Effect::Send { channel, payload: input["markdown"].as_str().unwrap_or("").chars().take(500).collect() }],
            _ => vec![],
        }
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        if let Some(k) = input.as_object().and_then(|o| o.keys().find(|k| *k != "markdown" && *k != "plan")) {
            return ToolOutput::err(format!("unexpected argument `{k}`"));
        }
        let (md, steps) = match normalize(&input["markdown"], &input["plan"]) {
            Ok(x) => x,
            Err(e) => return ToolOutput::err(e),
        };
        let (card, prior) = match put(&self.0.dir, &ctx.session_id, md, steps) {
            Ok(x) => x,
            Err(e) => return ToolOutput::err(e),
        };
        let mirrored = self.mirror(&ctx.session_id, card.as_ref(), prior);
        let (done, total) = card.as_ref().and_then(|c| c.steps.as_ref()).map(|s| (s.iter().filter(|x| x.status == "completed").count(), s.len())).unwrap_or((0, 0));
        let mut text = match &card {
            None => "Progress card cleared".to_string(),
            Some(c) if total > 0 => format!("Progress card updated (rev {}, {done}/{total} done)", c.revision),
            Some(c) => format!("Progress card updated (rev {})", c.revision),
        };
        if let Some(m) = mirrored {
            text.push_str(&format!("; {m}"));
        }
        let payload = json!({"revision": card.as_ref().map(|c| c.revision), "steps": (total > 0).then(|| json!({"completed": done, "total": total}))});
        ToolOutput::ok(format!("{text}\n{payload}"))
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit;
    use super::*;
    use ark_channel::{Channel, ChannelError, Inbound, Outbound, Sent};
    use ark_core::Cancel;

    #[derive(Default)]
    struct FakeChannel {
        sent: Mutex<Vec<Outbound>>,
        edits: Mutex<Vec<(String, String, String)>>,
    }
    impl Channel for FakeChannel {
        fn id(&self) -> &str {
            "chat"
        }
        fn poll(&self, _: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
            Ok(vec![])
        }
        fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
            self.sent.lock().unwrap().push(out.clone());
            Ok(Sent::one("m42"))
        }
        fn edit(&self, chat: &str, id: &str, text: &str) -> Result<(), ChannelError> {
            self.edits.lock().unwrap().push((chat.into(), id.into(), text.into()));
            Ok(())
        }
    }

    #[test]
    fn input_rules() {
        assert!(normalize(&json!(5), &Value::Null).unwrap_err().contains("markdown must be a string"));
        assert!(normalize(&Value::Null, &json!([{"step": "a", "status": "in_progress"}, {"step": "b", "status": "in_progress"}])).unwrap_err().contains("at most one in_progress"));
        assert!(normalize(&Value::Null, &json!([{"step": " ", "status": "pending"}])).unwrap_err().contains("must not be empty"));
        assert!(normalize(&Value::Null, &json!([{"step": "a", "status": "done"}])).unwrap_err().contains("must be one of"));
        assert!(normalize(&json!("x".repeat(9000)), &Value::Null).unwrap_err().contains("8192"));
        assert_eq!(normalize(&json!("a\u{200B}b"), &json!([])).unwrap(), (Some("ab".into()), None));
        assert_eq!(strip_markdown("**Done**: see [PR 12](https://x/12) <b>now</b>"), "Done: see PR 12 now");
    }

    #[test]
    fn card_is_stored_mirrored_to_the_chat_and_edited() {
        let (env, _) = testkit::env("card", &[], "");
        let fake = Arc::new(FakeChannel::default());
        let mut env2 = (*env).clone();
        env2.channels.insert("tg".into(), fake.clone());
        // The session came from chat 99 on channel tg.
        let router = ark_channel::router::Router::open(env2.routes.clone(), Default::default());
        router.bind(&ark_channel::router::RouteKey::chat("tg", "99:thread:7"), "s1");
        let env2 = Arc::new(env2);
        let t = ProgressCard(env2.clone());
        let ws = testkit::temp("card-ws");
        let ctx = testkit::ctx(&env2, &ws);
        assert!(matches!(t.effects(&ctx, &json!({}))[0], Effect::Send { ref channel, .. } if channel == "tg"));
        let o = t.call(&ctx, json!({"markdown": "<progress aria-label=\"Files · 2/4\" value=\"2\" max=\"4\"></progress> halfway", "plan": [{"step": "Scan", "status": "completed"}, {"step": "Fix", "status": "in_progress"}]}));
        assert!(o.content.starts_with("Progress card updated (rev 1, 1/2 done); posted to tg"), "{}", o.content);
        let sent = fake.sent.lock().unwrap()[0].clone();
        assert_eq!((sent.chat.as_str(), sent.thread.as_deref()), ("99", Some("7")));
        assert!(sent.text.contains("▰▰▰▰▰▱▱▱▱▱ Files · 2/4") && sent.text.contains("Progress: 1/2 complete") && sent.text.contains("▶ Fix"), "{}", sent.text);
        let o = t.call(&ctx, json!({"plan": [{"step": "Scan", "status": "completed"}, {"step": "Fix", "status": "completed"}]}));
        assert!(o.content.contains("rev 2, 2/2 done); updated in tg"), "{}", o.content);
        assert_eq!(fake.edits.lock().unwrap()[0].1, "m42");
        assert_eq!(get(&env2.dir, "s1").unwrap().revision, 2);
        assert!(render_html(get(&env2.dir, "s1").as_ref()).contains("✓"));
        let o = t.call(&ctx, json!({}));
        assert!(o.content.starts_with("Progress card cleared"), "{}", o.content);
        assert!(get(&env2.dir, "s1").is_none());
        assert!(t.call(&ctx, json!({"extra": 1})).is_error);
    }
}
