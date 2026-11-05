//! Telegram `message` tool actions (ported from OpenClaw `extensions/telegram`, MIT:
//! `action-names.ts`, `channel-actions.ts`, `action-runtime.ts`, `history-read.ts`,
//! `sticker-cache-store.ts`, `send-special.ts`, `send-forum-topics.ts`).
//!
//! The Bot API has no history endpoint, so `read` (like upstream) is served from a
//! bounded cache of the messages `Telegram::poll` has seen, and `sticker-search`
//! scores a cache of stickers seen inbound. Both caches live in memory, keyed by
//! channel id. Upstream describes cached stickers with a vision model; ark has none
//! at this layer, so a sticker's description is its emoji and set name.
//!
//! Not ported: per-account action gates (`actions.sticker` etc.; ark has no such
//! config) and the requester/session scope checks of `read` (raw tool args carry no
//! trusted turn context); the group-only rule of `read` is kept. The extension has
//! no pin / member-info / channel-info actions. send/reply/react/edit/delete are
//! handled by the generic tool.

use super::{id_str, Telegram};
use crate::action_args::{self as a, bad};
use crate::ChannelError;
use ark_core::Cancel;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};

/// Every action `Telegram::action` implements (advertised by `message_actions`).
pub(super) const ACTIONS: &[&str] = &["read", "poll", "emoji-list", "sticker", "sticker-search", "topic-create", "topic-edit"];

/// Cached messages per channel (upstream `DEFAULT_MAX_MESSAGES`).
const HISTORY_MAX: usize = 5000;
/// Cached stickers per channel (upstream `TELEGRAM_STICKER_CACHE_MAX_ENTRIES`).
const STICKERS_MAX: usize = 10_000;
const EMOJI_LIST_LIMIT: u64 = 100;
const POLL_MAX_OPTIONS: usize = 12;
const GENERAL_TOPIC: u64 = 1;
const TOPIC_ICON_COLORS: [u64; 6] = [0x6fb9f0, 0xffd67e, 0xcb86db, 0x8eee98, 0xff93b2, 0xfb6f5f];
const HISTORY_SCOPE_ERROR: &str = "Telegram history read requires a group chat (negative chat id) and, in forums, the exact topic.";

/// `TELEGRAM_SUPPORTED_REACTION_EMOJI_LIST` (status-reaction-variants.ts).
const DEFAULT_REACTIONS: [&str; 73] = [
    "❤", "👍", "👎", "🔥", "🥰", "👏", "😁", "🤔", "🤯", "😱", "🤬", "😢", "🎉", "🤩", "🤮", "💩", "🙏", "👌", "🕊", "🤡", "🥱", "🥴", "😍", "🐳", "❤\u{200d}🔥", "🌚", "🌭", "💯", "🤣", "⚡", "🍌", "🏆", "💔", "🤨", "😐", "🍓", "🍾", "💋", "🖕", "😈", "😴", "😭", "🤓", "👻", "👨\u{200d}💻", "👀", "🎃", "🙈", "😇", "😨", "🤝", "✍", "🤗", "🫡", "🎅", "🎄", "☃", "💅", "🤪", "🗿", "🆒", "💘", "🙉", "🦄", "😘", "💊", "🙊", "😎", "👾", "🤷\u{200d}♂", "🤷", "🤷\u{200d}♀", "😡",
];

// ---------------------------------------------------------------- caches

#[derive(Clone)]
struct Sticker {
    file_id: String,
    emoji: Option<String>,
    set_name: Option<String>,
    description: String,
}

#[derive(Default)]
struct Cache {
    /// chat → message id → (thread, node).
    history: HashMap<String, BTreeMap<i64, (Option<String>, Value)>>,
    order: VecDeque<(String, i64)>,
    /// file_unique_id → sticker.
    stickers: HashMap<String, Sticker>,
    sticker_order: VecDeque<String>,
}

fn caches() -> &'static Mutex<HashMap<String, Cache>> {
    static C: OnceLock<Mutex<HashMap<String, Cache>>> = OnceLock::new();
    C.get_or_init(Default::default)
}

/// `normalizeMessageNode` (message-cache-codec.ts): the fields `read` returns.
fn node_of(m: &Value) -> Option<(String, i64, Option<String>, Value)> {
    let chat = id_str(&m["chat"]["id"])?;
    let id = m["message_id"].as_i64()?;
    let from = &m["from"];
    let name = [from["first_name"].as_str(), from["last_name"].as_str()].into_iter().flatten().collect::<Vec<_>>().join(" ").trim().to_string();
    let sender = Some(name).filter(|n| !n.is_empty()).or_else(|| from["username"].as_str().map(str::to_string)).filter(|n| !n.is_empty()).unwrap_or_else(|| "unknown sender".into());
    let photo = m["photo"].as_array().and_then(|p| p.last()).cloned();
    let media = [("image", photo), ("video", m.get("video").or(m.get("video_note")).or(m.get("animation")).cloned()), ("audio", m.get("audio").or(m.get("voice")).cloned()), ("document", m.get("document").cloned()), ("sticker", m.get("sticker").cloned())]
        .into_iter()
        .find_map(|(k, f)| f.filter(Value::is_object).map(|f| (k, f)));
    let text = m["text"].as_str().filter(|t| !t.trim().is_empty()).or_else(|| m["caption"].as_str()).unwrap_or("").trim().to_string();
    let body = if !text.is_empty() {
        Some(text)
    } else {
        m["dice"]["emoji"].as_str().filter(|e| !e.trim().is_empty()).zip(m["dice"]["value"].as_i64()).map(|(e, v)| format!("[Dice {} = {v}]", e.trim()))
    };
    let thread = m["message_thread_id"].as_i64().filter(|_| m["is_topic_message"] == true).map(|t| t.to_string());
    let reply = m["reply_to_message"]["message_id"].as_i64().or_else(|| (m["external_reply"]["chat"]["id"] == m["chat"]["id"]).then(|| m["external_reply"]["message_id"].as_i64()).flatten());
    let mut n = Map::new();
    n.insert("messageId".into(), json!(id.to_string()));
    n.insert("sender".into(), json!(sender));
    let mut put = |k: &str, v: Option<Value>| {
        if let Some(v) = v {
            n.insert(k.into(), v);
        }
    };
    put("senderId", id_str(&from["id"]).map(Value::from));
    put("senderUsername", from["username"].as_str().filter(|u| !u.is_empty()).map(Value::from));
    put("timestamp", m["date"].as_i64().map(|d| json!(d * 1000)));
    put("body", body.map(Value::from));
    put("mediaType", media.as_ref().map(|(k, _)| json!(k)));
    put("mediaRef", media.as_ref().and_then(|(_, f)| f["file_id"].as_str()).map(|f| json!(format!("telegram:file/{f}"))));
    put("replyToId", reply.map(|r| json!(r.to_string())));
    put("threadId", thread.clone().map(Value::from));
    Some((chat, id, thread, Value::Object(n)))
}

/// Record what `poll` received: messages for `read`, static stickers for `sticker-search`.
pub(super) fn observe(channel: &str, updates: &[Value]) {
    let mut all = caches().lock().unwrap();
    let c = all.entry(channel.to_string()).or_default();
    for u in updates {
        let Some(m) = u.get("message").or_else(|| u.get("edited_message")).or_else(|| u.get("channel_post")).filter(|m| m.is_object()) else { continue };
        if let Some((chat, id, thread, node)) = node_of(m) {
            let msgs = c.history.entry(chat.clone()).or_default();
            if msgs.insert(id, (thread, node)).is_none() {
                c.order.push_back((chat, id));
            }
            while c.order.len() > HISTORY_MAX {
                let Some((chat, id)) = c.order.pop_front() else { break };
                if let Some(msgs) = c.history.get_mut(&chat) {
                    msgs.remove(&id);
                    if msgs.is_empty() {
                        c.history.remove(&chat);
                    }
                }
            }
        }
        let s = &m["sticker"];
        // Upstream only caches static stickers (animated / video ones are skipped).
        if let (Some(uid), Some(fid), false, false) = (s["file_unique_id"].as_str(), s["file_id"].as_str(), s["is_animated"] == true, s["is_video"] == true) {
            let emoji = s["emoji"].as_str().map(str::to_string);
            let set_name = s["set_name"].as_str().map(str::to_string);
            let description = format!("{} sticker{}", emoji.as_deref().unwrap_or(""), set_name.as_deref().map(|n| format!(" from set {}", n.replace('_', " "))).unwrap_or_default()).trim().to_string();
            if c.stickers.insert(uid.to_string(), Sticker { file_id: fid.into(), emoji, set_name, description }).is_none() {
                c.sticker_order.push_back(uid.to_string());
            }
            while c.sticker_order.len() > STICKERS_MAX {
                if let Some(old) = c.sticker_order.pop_front() {
                    c.stickers.remove(&old);
                }
            }
        }
    }
}

/// `searchStickers`: substring 10, per query word 5, emoji 8, set name 3.
fn search_stickers(channel: &str, query: &str, limit: usize) -> Vec<Sticker> {
    let q = query.trim().to_lowercase();
    let words: Vec<&str> = q.split_whitespace().collect();
    let all = caches().lock().unwrap();
    let Some(c) = all.get(channel) else { return vec![] };
    let mut scored: Vec<(u32, usize, Sticker)> = c
        .sticker_order
        .iter()
        .enumerate()
        .filter_map(|(i, k)| {
            let s = c.stickers.get(k)?;
            let d = s.description.to_lowercase();
            let dw: Vec<&str> = d.split_whitespace().collect();
            let mut score = if d.contains(&q) { 10 } else { 0 };
            score += 5 * words.iter().filter(|w| dw.iter().any(|x| x.contains(*w))).count() as u32;
            score += if s.emoji.as_deref().is_some_and(|e| !e.is_empty() && query.contains(e)) { 8 } else { 0 };
            score += if s.set_name.as_deref().unwrap_or("").to_lowercase().contains(&q) { 3 } else { 0 };
            (score > 0).then(|| (score, i, s.clone()))
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scored.into_iter().take(limit).map(|(_, _, s)| s).collect()
}

// ---------------------------------------------------------------- params

/// `parseTelegramTarget`, reduced to what ark chat ids look like: an optional
/// `telegram:` / `tg:` / `group:` prefix and a `:topic:<id>` suffix.
fn parse_target(raw: &str) -> (String, Option<u64>) {
    let mut t = raw.trim();
    for p in ["telegram:", "tg:", "group:"] {
        if t.len() > p.len() && t[..p.len()].eq_ignore_ascii_case(p) {
            t = &t[p.len()..];
        }
    }
    match t.split_once(":topic:") {
        Some((c, th)) => (c.to_string(), th.parse().ok()),
        None => (t.to_string(), None),
    }
}

fn chat_of(args: &Value, keys: &[&str], action: &str) -> Result<(String, Option<u64>), ChannelError> {
    a::s(args, keys).map(|t| parse_target(&t)).ok_or_else(|| bad(format!("{action} requires target (the Telegram chat id)")))
}

fn thread_of(args: &Value) -> Result<Option<u64>, ChannelError> {
    Ok(a::pos(args, &["messageThreadId"])?.or(a::pos(args, &["threadId"])?))
}

/// `message_thread_id` (never the General topic, which Telegram rejects) and `reply_parameters`.
fn thread_params(body: &mut Value, thread: Option<u64>, reply_to: Option<u64>) {
    if let Some(t) = thread.filter(|t| *t != GENERAL_TOPIC) {
        body["message_thread_id"] = json!(t);
    }
    if let Some(r) = reply_to {
        body["reply_parameters"] = json!({"message_id": r, "allow_sending_without_reply": true});
    }
}

fn topic_name(n: &str, what: &str) -> Result<String, ChannelError> {
    let n = n.trim();
    if n.is_empty() {
        return Err(bad(format!("{what} name is required")));
    }
    if n.chars().count() > 128 {
        return Err(bad(format!("{what} name must be 128 characters or fewer")));
    }
    Ok(n.to_string())
}

impl Telegram {
    fn bot(&self, method: &str, body: &Value) -> Result<Value, ChannelError> {
        Ok(self.call(method, body, &Cancel::new())?.unwrap_or_default())
    }

    pub(super) fn action(&self, action: &str, args: &Value) -> Result<Value, ChannelError> {
        match action {
            "read" => self.act_read(args),
            "emoji-list" => {
                let (chat, _) = chat_of(args, &["chatId", "channelId", "to", "target"], action)?;
                let limit = a::pos(args, &["limit"])?.unwrap_or(EMOJI_LIST_LIMIT).min(EMOJI_LIST_LIMIT) as usize;
                let c = self.bot("getChat", &json!({"chat_id": chat}))?;
                // A missing / null `available_reactions` means every standard reaction is allowed.
                let (emojis, all): (Vec<Value>, bool) = match &c["available_reactions"] {
                    Value::Array(rs) => (
                        rs.iter()
                            .filter_map(|r| match r["type"].as_str() {
                                Some("emoji") => r["emoji"].as_str().map(|e| json!({"name": e, "identifier": e})),
                                Some("custom_emoji") => r["custom_emoji_id"].as_str().filter(|i| !i.trim().is_empty()).map(|i| json!({"identifier": i.trim(), "type": "custom_emoji"})),
                                _ => None,
                            })
                            .collect(),
                        false,
                    ),
                    Value::Null => (DEFAULT_REACTIONS.iter().map(|e| json!({"name": e, "identifier": e})).collect(), true),
                    _ => (vec![], false),
                };
                let mut out = json!({"ok": true, "emojis": emojis.into_iter().take(limit).collect::<Vec<_>>()});
                if all {
                    out["note"] = json!("All standard Telegram reactions are allowed.");
                }
                Ok(out)
            }
            "poll" => self.act_poll(args),
            "sticker" => {
                let (chat, topic) = chat_of(args, &["to", "target"], action)?;
                let file_id = a::s(args, &["fileId"]).or_else(|| a::list(args, &["stickerId"]).into_iter().next()).ok_or_else(|| bad("fileId is required."))?;
                let reply = a::pos(args, &["replyToMessageId"])?.or(a::pos(args, &["replyTo"])?);
                let mut body = json!({"chat_id": chat, "sticker": file_id});
                thread_params(&mut body, topic.or(thread_of(args)?), reply);
                let r = self.bot("sendSticker", &body)?;
                Ok(json!({"ok": true, "messageId": id_str(&r["message_id"]), "chatId": id_str(&r["chat"]["id"]).unwrap_or(chat)}))
            }
            "sticker-search" => {
                let q = a::req(args, &["query"])?;
                let limit = a::pos(args, &["limit"])?.unwrap_or(5) as usize;
                let found = search_stickers(&self.id, &q, limit);
                Ok(json!({"ok": true, "count": found.len(), "stickers": found.iter().map(|s| json!({"fileId": s.file_id, "emoji": s.emoji, "description": s.description, "setName": s.set_name})).collect::<Vec<_>>()}))
            }
            "topic-create" => {
                let (chat, _) = chat_of(args, &["chatId", "channelId", "to", "target"], action)?;
                let name = a::text(args, &["name"]).filter(|n| !n.trim().is_empty()).or_else(|| a::text(args, &["threadName"])).ok_or_else(|| bad("name required"))?;
                let name = topic_name(&name, "Forum topic")?;
                let mut body = json!({"chat_id": chat, "name": name});
                if let Some(c) = a::pos(args, &["iconColor"]).map_err(|_| bad("iconColor must be one of Telegram's supported forum topic colors."))? {
                    if !TOPIC_ICON_COLORS.contains(&c) {
                        return Err(bad("iconColor must be one of Telegram's supported forum topic colors."));
                    }
                    body["icon_color"] = json!(c);
                }
                if let Some(e) = a::s(args, &["iconCustomEmojiId"]) {
                    body["icon_custom_emoji_id"] = json!(e);
                }
                let r = self.bot("createForumTopic", &body)?;
                Ok(json!({"ok": true, "topicId": r["message_thread_id"], "name": r["name"].as_str().unwrap_or(&name), "chatId": chat}))
            }
            "topic-edit" => {
                let (chat, topic) = chat_of(args, &["chatId", "channelId", "to", "target"], action)?;
                let thread = thread_of(args)?.or(topic).ok_or_else(|| bad("messageThreadId or threadId is required."))?;
                let name = a::text(args, &["name"]).or_else(|| a::text(args, &["threadName"]));
                let name = name.map(|n| topic_name(&n, "Telegram forum topic")).transpose()?;
                let icon = match a::text(args, &["iconCustomEmojiId"]) {
                    Some(i) if i.trim().is_empty() => return Err(bad("Telegram forum topic icon custom emoji ID is required")),
                    i => i.map(|i| i.trim().to_string()),
                };
                if name.is_none() && icon.is_none() {
                    return Err(bad("Telegram forum topic update requires a name or iconCustomEmojiId"));
                }
                let mut body = json!({"chat_id": chat, "message_thread_id": thread});
                let mut out = json!({"ok": true, "chatId": chat, "messageThreadId": thread});
                if let Some(n) = &name {
                    body["name"] = json!(n);
                    out["name"] = json!(n);
                }
                if let Some(i) = &icon {
                    body["icon_custom_emoji_id"] = json!(i);
                    out["iconCustomEmojiId"] = json!(i);
                }
                self.bot("editForumTopic", &body)?;
                Ok(out)
            }
            _ => Err(a::unknown("telegram", action)),
        }
    }

    /// `readTelegramHistoryAction` over the poll-fed cache.
    fn act_read(&self, args: &Value) -> Result<Value, ChannelError> {
        let (chat, topic) = chat_of(args, &["target", "to", "chatId", "channelId"], "read")?;
        let thread = thread_of(args)?;
        if !chat.strip_prefix('-').is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())) || topic.zip(thread).is_some_and(|(a, b)| a != b) {
            return Err(bad(HISTORY_SCOPE_ERROR));
        }
        let thread = topic.or(thread).map(|t| t.to_string());
        if !args["around"].is_null() {
            return Err(bad("Telegram history supports messageId for an exact message, or before/after for paging."));
        }
        let (exact, before, after) = (a::pos(args, &["messageId"])?, a::pos(args, &["before"])?, a::pos(args, &["after"])?);
        if exact.is_some() && (before.is_some() || after.is_some()) {
            return Err(bad("Use messageId alone for an exact Telegram history read."));
        }
        let limit = a::pos(args, &["limit"])?.unwrap_or(50).min(100) as usize;
        let all = caches().lock().unwrap();
        let empty = BTreeMap::new();
        let msgs = all.get(&self.id).and_then(|c| c.history.get(&chat)).unwrap_or(&empty);
        let scoped = |r: &(Option<String>, Value)| r.0 == thread;
        let (messages, has_more): (Vec<Value>, bool) = if let Some(id) = exact {
            (msgs.get(&(id as i64)).filter(|r| scoped(r)).map(|r| r.1.clone()).into_iter().collect(), false)
        } else {
            let lo = after.map_or(i64::MIN, |a| a as i64 + 1);
            let hi = before.map_or(i64::MAX, |b| (b as i64).saturating_sub(1));
            let range: Vec<&Value> = if lo > hi { vec![] } else { msgs.range(lo..=hi).filter(|(_, r)| scoped(r)).map(|(_, r)| &r.1).collect() };
            // `after` alone pages forward (oldest first); otherwise the newest window.
            let page: Vec<&Value> = if after.is_some() && before.is_none() { range.iter().take(limit).copied().collect() } else { range.iter().rev().take(limit).rev().copied().collect() };
            (page.into_iter().cloned().collect(), range.len() > limit)
        };
        let mut out = json!({"ok": true, "chatId": chat, "messages": messages, "hasMore": has_more});
        if let Some(t) = thread.and_then(|t| t.parse::<u64>().ok()) {
            out["threadId"] = json!(t);
        }
        if let Some(first) = out["messages"].as_array().and_then(|m| m.first()).map(|m| m["messageId"].clone()) {
            out["oldestMessageId"] = first;
            out["newestMessageId"] = out["messages"].as_array().and_then(|m| m.last()).map(|m| m["messageId"].clone()).unwrap_or_default();
        }
        Ok(out)
    }

    /// `sendPollTelegram`: Telegram allows 2–12 options and `open_period` 5–604800 s.
    fn act_poll(&self, args: &Value) -> Result<Value, ChannelError> {
        // Shared validation (`message::normalize_poll`); Telegram's own limits (12 options,
        // 5–604800 s, seconds only) still apply below.
        let args = &crate::message_tool::normalize_poll_args(args, POLL_MAX_OPTIONS)?;
        let (chat, topic) = chat_of(args, &["to", "target", "chatId"], "poll")?;
        let (question, options, max, _) = a::poll(args)?;
        if options.len() > POLL_MAX_OPTIONS {
            return Err(bad(format!("Poll supports at most {POLL_MAX_OPTIONS} options")));
        }
        if max as usize > options.len() {
            return Err(bad("maxSelections cannot exceed option count"));
        }
        let secs = a::pos(args, &["durationSeconds"])?.or(a::pos(args, &["pollDurationSeconds"])?);
        let hours = a::pos(args, &["durationHours"])?.or(a::pos(args, &["pollDurationHours"])?);
        if secs.is_none() && hours.is_some() {
            return Err(bad("Telegram poll durationHours is not supported. Use durationSeconds (5-604800) instead."));
        }
        if secs.is_some_and(|s| !(5..=604_800).contains(&s)) {
            return Err(bad("Telegram poll durationSeconds must be between 5 and 604800"));
        }
        let (pa, pp) = (a::flag(args, "pollAnonymous") == Some(true), a::flag(args, "pollPublic") == Some(true));
        if pa && pp {
            return Err(bad("pollAnonymous and pollPublic are mutually exclusive"));
        }
        let anonymous = a::flag(args, "isAnonymous").unwrap_or(!pp);
        let reply = a::pos(args, &["replyToMessageId"])?.or(a::pos(args, &["replyTo"])?);
        let mut body = json!({"chat_id": chat, "question": question, "options": options.iter().map(|o| json!({"text": o})).collect::<Vec<_>>(), "allows_multiple_answers": max > 1, "is_anonymous": anonymous});
        if let Some(s) = secs {
            body["open_period"] = json!(s);
        }
        thread_params(&mut body, topic.or(thread_of(args)?), reply);
        if a::flag(args, "silent") == Some(true) {
            body["disable_notification"] = json!(true);
        }
        let r = self.bot("sendPoll", &body)?;
        // ark subscribes to no `poll_answer` updates, so votes never reach the agent.
        let warning = if anonymous {
            "Poll sent anonymously, so Telegram does not identify voters and answers cannot reach the agent. Send a public poll to route votes into this conversation."
        } else if r["chat"]["type"] == "channel" {
            "Poll sent, but public poll answer routing is not supported for Telegram channels. Send the poll in a direct chat or group, or ask subscribers to reply in text."
        } else {
            "Poll sent, but answers cannot reach the agent: this ark channel does not receive Telegram poll_answer updates. Ask participants to reply in text."
        };
        Ok(json!({"ok": true, "messageId": id_str(&r["message_id"]), "chatId": id_str(&r["chat"]["id"]).unwrap_or(chat), "pollId": r["poll"]["id"], "pollAnswerRouting": "unavailable", "warning": warning}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};
    use crate::{Channel, ChannelErrorKind as K};
    use std::time::Duration;

    fn tg(srv: &FakeServer, id: &str) -> Telegram {
        let mut t = Telegram::new(id, "123:SECRET", Some(&srv.url), temp_dir("tga").join("s.json"), 1).unwrap();
        t.retry_base = Duration::from_millis(5);
        t.max_retries = 0;
        t
    }

    fn ok(result: Value) -> (u16, Vec<(String, String)>, String) {
        (200, vec![], json!({"ok": true, "result": result}).to_string())
    }

    fn method(path: &str) -> &str {
        path.rsplit('/').next().unwrap()
    }

    fn msg(id: i64, chat: i64, text: &str, extra: Value) -> Value {
        let mut m = json!({"message_id": id, "date": 1_700_000_000 + id, "chat": {"id": chat, "type": "supergroup"}, "from": {"id": 42, "first_name": "Amy", "last_name": "Lee", "username": "amy"}, "text": text});
        for (k, v) in extra.as_object().unwrap() {
            m[k] = v.clone();
        }
        m
    }

    #[test]
    fn advertises_exactly_the_implemented_actions() {
        let srv = FakeServer::start(|_, _| ok(json!(true)));
        let t = tg(&srv, "tg-adv");
        assert_eq!(t.message_actions(), ACTIONS.to_vec());
        for x in ["send", "react", "edit", "delete", "reply", "pin", "member-info"] {
            assert_eq!(t.message_action(x, &json!({})).unwrap_err().kind, K::Unsupported);
        }
    }

    #[test]
    fn read_serves_the_poll_fed_history_cache() {
        let updates = json!([
            {"update_id": 1, "message": msg(10, -100, "first", json!({}))},
            {"update_id": 2, "message": msg(11, -100, "", json!({"photo": [{"file_id": "small"}, {"file_id": "big"}], "caption": " pic ", "reply_to_message": {"message_id": 10}}))},
            {"update_id": 3, "message": msg(12, -100, "in topic", json!({"message_thread_id": 7, "is_topic_message": true}))},
            {"update_id": 4, "message": msg(13, -100, "", json!({"dice": {"emoji": "🎲", "value": 4}}))},
            {"update_id": 5, "edited_message": msg(10, -100, "first (edited)", json!({}))},
            {"update_id": 6, "message": msg(1, 5, "dm", json!({}))},
        ]);
        let srv = FakeServer::start(move |_, n| ok(if n == 0 { updates.clone() } else { json!([]) }));
        let t = tg(&srv, "tg-read");
        assert_eq!(t.poll(&Cancel::new()).unwrap().len(), 5, "the dice message is cached but not routed");
        let v = t.message_action("read", &json!({"target": "-100"})).unwrap();
        let ids: Vec<&str> = v["messages"].as_array().unwrap().iter().map(|m| m["messageId"].as_str().unwrap()).collect();
        assert_eq!(ids, ["10", "11", "13"], "topic messages stay in their topic");
        let m = &v["messages"];
        assert_eq!((m[0]["body"].as_str(), m[0]["sender"].as_str(), m[0]["senderUsername"].as_str(), m[0]["timestamp"].as_i64()), (Some("first (edited)"), Some("Amy Lee"), Some("amy"), Some(1_700_000_010_000)));
        assert_eq!((m[1]["mediaType"].as_str(), m[1]["mediaRef"].as_str(), m[1]["replyToId"].as_str(), m[1]["body"].as_str()), (Some("image"), Some("telegram:file/big"), Some("10"), Some("pic")));
        assert_eq!(m[2]["body"], "[Dice 🎲 = 4]");
        assert_eq!((v["hasMore"].as_bool(), v["oldestMessageId"].as_str(), v["newestMessageId"].as_str()), (Some(false), Some("10"), Some("13")));
        let v = t.message_action("read", &json!({"target": "-100", "limit": 1, "before": 13})).unwrap();
        assert_eq!((v["messages"][0]["messageId"].as_str(), v["hasMore"].as_bool()), (Some("11"), Some(true)));
        let v = t.message_action("read", &json!({"target": "-100", "limit": 1, "after": 10})).unwrap();
        assert_eq!(v["messages"][0]["messageId"], "11");
        let v = t.message_action("read", &json!({"target": "-100:topic:7"})).unwrap();
        assert_eq!((v["messages"][0]["body"].as_str(), v["threadId"].as_u64()), (Some("in topic"), Some(7)));
        let v = t.message_action("read", &json!({"chatId": -100, "messageId": "11"})).unwrap();
        assert_eq!(v["messages"].as_array().unwrap().len(), 1);
        for (args, err) in [
            (json!({"target": "5"}), "group chat"),
            (json!({"target": "-100", "around": "3"}), "before/after"),
            (json!({"target": "-100", "messageId": 1, "before": 3}), "messageId alone"),
            (json!({"target": "-100:topic:7", "threadId": 8}), "exact topic"),
            (json!({}), "requires target"),
        ] {
            assert!(t.message_action("read", &args).unwrap_err().message.contains(err), "{args}");
        }
        assert_eq!(srv.requests().len(), 2, "read never calls the Bot API");
    }

    #[test]
    fn emoji_list_uses_get_chat_or_the_default_set() {
        let srv = FakeServer::start(|r, _| match r.json()["chat_id"].as_str() {
            Some("-1") => ok(json!({"id": -1, "available_reactions": [{"type": "emoji", "emoji": "👍"}, {"type": "custom_emoji", "custom_emoji_id": "555"}, {"type": "paid"}]})),
            _ => ok(json!({"id": -2})),
        });
        let t = tg(&srv, "tg-emoji");
        let v = t.message_action("emoji-list", &json!({"target": "-1"})).unwrap();
        assert_eq!(v["emojis"], json!([{"name": "👍", "identifier": "👍"}, {"identifier": "555", "type": "custom_emoji"}]));
        assert!(v.get("note").is_none());
        let v = t.message_action("emoji-list", &json!({"chatId": "-2", "limit": 3})).unwrap();
        assert_eq!((v["emojis"].as_array().unwrap().len(), v["emojis"][1]["name"].as_str()), (3, Some("👍")));
        assert_eq!(v["note"], "All standard Telegram reactions are allowed.");
        let v = t.message_action("emoji-list", &json!({"chatId": "-2", "limit": 500})).unwrap();
        assert_eq!(v["emojis"].as_array().unwrap().len(), 73);
        let r = srv.requests();
        assert_eq!((method(&r[0].path), r[0].method.as_str()), ("getChat", "POST"));
        assert!(t.message_action("emoji-list", &json!({"target": "-1", "limit": 0})).unwrap_err().message.contains("positive"));
    }

    #[test]
    fn poll_maps_to_send_poll_and_validates() {
        let srv = FakeServer::start(|_, _| ok(json!({"message_id": 77, "chat": {"id": -100, "type": "supergroup"}, "poll": {"id": "P9"}})));
        let t = tg(&srv, "tg-poll");
        let v = t.message_action("poll", &json!({"target": "-100", "question": "Lunch?", "options": ["Pizza", "Sushi", "Tacos"], "maxSelections": 3, "durationSeconds": 60, "threadId": 5, "replyTo": 9, "silent": true, "pollPublic": true})).unwrap();
        assert_eq!((v["messageId"].as_str(), v["chatId"].as_str(), v["pollId"].as_str(), v["pollAnswerRouting"].as_str()), (Some("77"), Some("-100"), Some("P9"), Some("unavailable")));
        assert!(v["warning"].as_str().unwrap().contains("poll_answer"));
        let r = &srv.requests()[0];
        assert_eq!(method(&r.path), "sendPoll");
        assert_eq!(
            r.json(),
            json!({"chat_id": "-100", "question": "Lunch?", "options": [{"text": "Pizza"}, {"text": "Sushi"}, {"text": "Tacos"}], "allows_multiple_answers": true, "is_anonymous": false, "open_period": 60, "message_thread_id": 5, "reply_parameters": {"message_id": 9, "allow_sending_without_reply": true}, "disable_notification": true})
        );
        let v = t.message_action("poll", &json!({"to": "-100:topic:1", "question": "q", "options": ["a", "b"]})).unwrap();
        assert!(v["warning"].as_str().unwrap().contains("anonymously"));
        let b = srv.requests()[1].json();
        assert_eq!((b["is_anonymous"].as_bool(), b["allows_multiple_answers"].as_bool(), b.get("message_thread_id")), (Some(true), Some(false), None), "General topic id is never sent");
        let twelve: Vec<String> = (0..13).map(|i| i.to_string()).collect();
        for (args, err) in [
            (json!({"target": "-1", "question": "q", "options": ["a", "b"], "durationHours": 2}), "durationHours is not supported"),
            (json!({"target": "-1", "question": "q", "options": ["a", "b"], "durationSeconds": 3}), "between 5 and 604800"),
            (json!({"target": "-1", "question": "q", "options": twelve}), "at most 12"),
            (json!({"target": "-1", "question": "q", "options": ["a", "b"], "maxSelections": 3}), "exceed"),
            (json!({"target": "-1", "question": "q", "options": ["a", "b"], "pollAnonymous": true, "pollPublic": true}), "mutually exclusive"),
            (json!({"question": "q", "options": ["a", "b"]}), "requires target"),
        ] {
            assert!(t.message_action("poll", &args).unwrap_err().message.contains(err), "{args}");
        }
        assert_eq!(srv.requests().len(), 2);
    }

    #[test]
    fn sticker_send_and_search_over_seen_stickers() {
        let updates = json!([
            {"update_id": 1, "message": {"message_id": 1, "chat": {"id": 3, "type": "private"}, "from": {"id": 3}, "sticker": {"file_id": "FID_CAT", "file_unique_id": "U1", "emoji": "😺", "set_name": "Happy_Cats"}}},
            {"update_id": 2, "message": {"message_id": 2, "chat": {"id": 3, "type": "private"}, "from": {"id": 3}, "sticker": {"file_id": "FID_DOG", "file_unique_id": "U2", "emoji": "🐶", "set_name": "Good_Dogs"}}},
            {"update_id": 3, "message": {"message_id": 3, "chat": {"id": 3, "type": "private"}, "from": {"id": 3}, "sticker": {"file_id": "FID_ANIM", "file_unique_id": "U3", "emoji": "😺", "is_animated": true}}},
        ]);
        let srv = FakeServer::start(move |r, n| match method(&r.path) {
            "getUpdates" => ok(if n == 0 { updates.clone() } else { json!([]) }),
            _ => ok(json!({"message_id": 5, "chat": {"id": 3}})),
        });
        let t = tg(&srv, "tg-sticker");
        t.poll(&Cancel::new()).unwrap();
        let v = t.message_action("sticker-search", &json!({"query": "happy cats"})).unwrap();
        assert_eq!((v["count"].as_u64(), v["stickers"][0]["fileId"].as_str(), v["stickers"][0]["setName"].as_str()), (Some(1), Some("FID_CAT"), Some("Happy_Cats")));
        assert_eq!(v["stickers"][0]["description"], "😺 sticker from set Happy Cats");
        let v = t.message_action("sticker-search", &json!({"query": "🐶 sticker", "limit": 1})).unwrap();
        assert_eq!((v["count"].as_u64(), v["stickers"][0]["emoji"].as_str()), (Some(1), Some("🐶")), "emoji match outranks; animated stickers are not cached");
        assert_eq!(t.message_action("sticker-search", &json!({"query": "zebra"})).unwrap()["count"], 0);
        assert!(t.message_action("sticker-search", &json!({})).unwrap_err().message.contains("query required"));
        let v = t.message_action("sticker", &json!({"target": "3", "stickerId": ["FID_CAT"], "replyToMessageId": 2})).unwrap();
        assert_eq!(v, json!({"ok": true, "messageId": "5", "chatId": "3"}));
        let r = srv.requests().into_iter().find(|r| method(&r.path) == "sendSticker").unwrap();
        assert_eq!(r.json(), json!({"chat_id": "3", "sticker": "FID_CAT", "reply_parameters": {"message_id": 2, "allow_sending_without_reply": true}}));
        assert!(t.message_action("sticker", &json!({"target": "3"})).unwrap_err().message.contains("fileId is required"));
    }

    #[test]
    fn forum_topics_create_and_edit() {
        let srv = FakeServer::start(|r, _| match method(&r.path) {
            "createForumTopic" => ok(json!({"message_thread_id": 42, "name": "Plans", "icon_color": 7322096})),
            _ => ok(json!(true)),
        });
        let t = tg(&srv, "tg-topic");
        let v = t.message_action("topic-create", &json!({"target": "-100", "threadName": " Plans ", "iconColor": 0x6fb9f0, "iconCustomEmojiId": "E1"})).unwrap();
        assert_eq!(v, json!({"ok": true, "topicId": 42, "name": "Plans", "chatId": "-100"}));
        let v = t.message_action("topic-edit", &json!({"chatId": "-100", "messageThreadId": 42, "name": "Renamed"})).unwrap();
        assert_eq!(v, json!({"ok": true, "chatId": "-100", "messageThreadId": 42, "name": "Renamed"}));
        t.message_action("topic-edit", &json!({"target": "-100:topic:42", "iconCustomEmojiId": " E2 "})).unwrap();
        let r = srv.requests();
        assert_eq!((method(&r[0].path), r[0].json()), ("createForumTopic", json!({"chat_id": "-100", "name": "Plans", "icon_color": 0x6fb9f0, "icon_custom_emoji_id": "E1"})));
        assert_eq!((method(&r[1].path), r[1].json()), ("editForumTopic", json!({"chat_id": "-100", "message_thread_id": 42, "name": "Renamed"})));
        assert_eq!(r[2].json(), json!({"chat_id": "-100", "message_thread_id": 42, "icon_custom_emoji_id": "E2"}));
        let long = "x".repeat(129);
        for (action, args, err) in [
            ("topic-create", json!({"target": "-100"}), "name required"),
            ("topic-create", json!({"target": "-100", "name": long}), "128 characters"),
            ("topic-create", json!({"target": "-100", "name": "a", "iconColor": 5}), "supported forum topic colors"),
            ("topic-edit", json!({"target": "-100", "name": "a"}), "messageThreadId or threadId"),
            ("topic-edit", json!({"target": "-100", "threadId": 4}), "requires a name or iconCustomEmojiId"),
            ("topic-edit", json!({"target": "-100", "threadId": 4, "name": "  "}), "name is required"),
        ] {
            assert!(t.message_action(action, &args).unwrap_err().message.contains(err), "{action} {args}");
        }
        assert_eq!(srv.requests().len(), 3);
    }
}
