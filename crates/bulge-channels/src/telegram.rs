//! Telegram through the Bot API with long polling (`getUpdates`): outbound
//! HTTPS only, no webhook, no listening port.

use std::sync::Mutex;
use std::time::Duration;

use futures::future::BoxFuture;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{Attachment, Channel, ChannelError, Inbound, download_capped};

/// Bot API text limit is 4096; keep a margin as openclaw does.
const TEXT_LIMIT: usize = 4000;
/// Long-poll wait per `getUpdates` call.
const POLL_SECS: u64 = 50;

pub const DEFAULT_API: &str = "https://api.telegram.org";

pub struct Telegram {
    name: String,
    api: String,
    token: String,
    http: reqwest::Client,
    bot_id: i64,
    bot_username: String,
    /// Next update id to ask for (Telegram confirms everything below it).
    offset: Mutex<i64>,
}

#[derive(Deserialize)]
struct Envelope {
    ok: bool,
    #[serde(default)]
    result: Value,
    #[serde(default)]
    error_code: Option<u16>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    parameters: Option<Value>,
}

impl Telegram {
    /// Connect: check the token (`getMe`) and learn the bot's own identity.
    /// `cursor` is the persisted update offset, if any.
    pub async fn connect(account: &str, token: &str, api: &str, cursor: Option<&str>) -> Result<Self, ChannelError> {
        let name = format!("telegram:{account}");
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(POLL_SECS + 20))
            .build()
            .map_err(|e| ChannelError::Other { channel: name.clone(), message: e.to_string() })?;
        let mut channel = Self {
            name,
            api: api.trim_end_matches('/').to_owned(),
            token: token.to_owned(),
            http,
            bot_id: 0,
            bot_username: String::new(),
            offset: Mutex::new(cursor.and_then(|c| c.parse().ok()).unwrap_or(0)),
        };
        let me = channel.call("getMe", json!({})).await?;
        channel.bot_id = me.get("id").and_then(Value::as_i64).unwrap_or(0);
        channel.bot_username = me.get("username").and_then(Value::as_str).unwrap_or("").to_owned();
        Ok(channel)
    }

    pub fn bot_username(&self) -> &str {
        &self.bot_username
    }

    async fn call(&self, method: &str, body: Value) -> Result<Value, ChannelError> {
        // The token is part of the URL path: never include the URL in errors.
        let url = format!("{}/bot{}/{method}", self.api, self.token);
        let transient = |message: String| ChannelError::Transient { channel: self.name.clone(), message, retry_after_secs: None };
        let response = self.http.post(url).json(&body).send().await.map_err(|e| transient(format!("{method}: network error: {}", e.without_url())))?;
        let envelope: Envelope = response.json().await.map_err(|e| transient(format!("{method}: unreadable reply: {}", e.without_url())))?;
        if envelope.ok {
            return Ok(envelope.result);
        }
        let message = format!("{method}: {}", envelope.description.unwrap_or_else(|| "request failed".into()));
        Err(match envelope.error_code {
            Some(401 | 404) => ChannelError::Auth { channel: self.name.clone(), message },
            Some(409) => ChannelError::Other {
                channel: self.name.clone(),
                message: format!("{message} (another program is polling this bot, or a webhook is set; remove it with deleteWebhook)"),
            },
            Some(429) => ChannelError::Transient {
                channel: self.name.clone(),
                message,
                retry_after_secs: envelope.parameters.as_ref().and_then(|p| p.get("retry_after")).and_then(Value::as_u64),
            },
            _ => transient(message),
        })
    }

    /// Normalize one update; `None` for anything that is not a text message
    /// from a person (edits, joins, channel posts, bots).
    fn inbound(&self, update: &Value) -> Option<Inbound> {
        let message = update.get("message")?;
        let from = message.get("from")?;
        if from.get("is_bot").and_then(Value::as_bool).unwrap_or(false) {
            return None;
        }
        let attachments = attachments(message);
        let mut text = message.get("text").or_else(|| message.get("caption")).and_then(Value::as_str).unwrap_or("").to_owned();
        if text.is_empty() && attachments.is_empty() {
            return None;
        }
        let chat = message.get("chat")?;
        let is_group = chat.get("type").and_then(Value::as_str) != Some("private");
        let handle = format!("@{}", self.bot_username);
        let mut mentioned = message.pointer("/reply_to_message/from/id").and_then(Value::as_i64) == Some(self.bot_id);
        if !self.bot_username.is_empty()
            && let Some(at) = find_ascii_ci(&text, &handle)
        {
            mentioned = true;
            // `/cmd@bot` or `@bot do this` → the text without the handle.
            text.replace_range(at..at + handle.len(), "");
            text = text.trim().to_owned();
        }
        let first = from.get("first_name").and_then(Value::as_str).unwrap_or("");
        let user = from.get("username").and_then(Value::as_str).map(|u| format!(" (@{u})")).unwrap_or_default();
        Some(Inbound {
            channel: self.name.clone(),
            chat_id: chat.get("id")?.as_i64()?.to_string(),
            sender_id: from.get("id")?.as_i64()?.to_string(),
            sender_name: format!("{first}{user}"),
            is_group,
            mentioned: mentioned || !is_group,
            text,
            message_id: message.get("message_id").and_then(Value::as_i64).map(|id| id.to_string()).unwrap_or_default(),
            attachments,
        })
    }
}

/// Where `needle` (ASCII, like a bot handle) occurs in `text`, ignoring
/// ASCII case, as a byte offset into `text` itself. (Lowercasing the whole
/// text first is wrong: some letters change length, e.g. 'İ', and the offset
/// would no longer fit the original — a panic any sender could trigger.)
fn find_ascii_ci(text: &str, needle: &str) -> Option<usize> {
    text.char_indices().map(|(i, _)| i).find(|&i| text.get(i..i + needle.len()).is_some_and(|slice| slice.eq_ignore_ascii_case(needle)))
}

/// The files of a message: the largest size of a photo, or a document,
/// video, audio clip or voice note.
fn attachments(message: &Value) -> Vec<Attachment> {
    let file = |kind: &str, value: &Value| {
        Some(Attachment {
            kind: kind.to_owned(),
            name: value.get("file_name").and_then(Value::as_str).map(str::to_owned),
            source: value.get("file_id")?.as_str()?.to_owned(),
            size: value.get("file_size").and_then(Value::as_u64),
        })
    };
    let mut out = Vec::new();
    if let Some(largest) = message.get("photo").and_then(Value::as_array).and_then(|sizes| sizes.iter().max_by_key(|p| p.get("file_size").and_then(Value::as_u64).unwrap_or(0))) {
        out.extend(file("image", largest));
    }
    for (key, kind) in [("document", "file"), ("video", "video"), ("audio", "audio"), ("voice", "audio")] {
        if let Some(value) = message.get(key) {
            out.extend(file(kind, value));
        }
    }
    out
}

impl Channel for Telegram {
    fn name(&self) -> &str {
        &self.name
    }

    fn register_commands<'a>(&'a self, commands: &'a [crate::commands::Command]) -> BoxFuture<'a, Result<(), ChannelError>> {
        Box::pin(async move {
            let list: Vec<Value> = commands.iter().map(|c| json!({ "command": c.name, "description": c.summary })).collect();
            // The same menu in private chats and in groups.
            for scope in ["all_private_chats", "all_group_chats"] {
                self.call("setMyCommands", json!({ "commands": list, "scope": { "type": scope } })).await?;
            }
            Ok(())
        })
    }

    fn fetch<'a>(&'a self, attachment: &'a Attachment, max_bytes: u64) -> BoxFuture<'a, Result<Vec<u8>, ChannelError>> {
        Box::pin(async move {
            // The Bot API serves files up to 20 MB: getFile, then the file path.
            let file = self.call("getFile", json!({ "file_id": attachment.source })).await?;
            let path = file.get("file_path").and_then(Value::as_str).ok_or_else(|| ChannelError::Other { channel: self.name.clone(), message: "getFile: no file path".into() })?;
            if path.contains("..") {
                return Err(ChannelError::Other { channel: self.name.clone(), message: "getFile: bad file path".into() });
            }
            let request = self.http.get(format!("{}/file/bot{}/{path}", self.api, self.token));
            download_capped(request, max_bytes, &self.name).await
        })
    }

    fn text_limit(&self) -> usize {
        TEXT_LIMIT
    }

    fn cursor(&self) -> Option<String> {
        self.offset.lock().ok().map(|o| o.to_string())
    }

    fn poll(&self) -> BoxFuture<'_, Result<Vec<Inbound>, ChannelError>> {
        Box::pin(async move {
            let offset = *self.offset.lock().map_err(|_| ChannelError::Other { channel: self.name.clone(), message: "state poisoned".into() })?;
            let updates = self.call("getUpdates", json!({ "offset": offset, "timeout": POLL_SECS, "allowed_updates": ["message"] })).await?;
            let updates = updates.as_array().cloned().unwrap_or_default();
            let mut next = offset;
            let mut batch = Vec::new();
            for update in &updates {
                if let Some(id) = update.get("update_id").and_then(Value::as_i64) {
                    next = next.max(id + 1);
                }
                if let Some(message) = self.inbound(update) {
                    batch.push(message);
                }
            }
            if let Ok(mut current) = self.offset.lock() {
                *current = next;
            }
            Ok(batch)
        })
    }

    fn send(&self, chat_id: &str, text: &str) -> BoxFuture<'_, Result<(), ChannelError>> {
        let body = json!({ "chat_id": chat_id, "text": text, "link_preview_options": { "is_disabled": true } });
        Box::pin(async move { self.call("sendMessage", body).await.map(|_| ()) })
    }

    fn typing(&self, chat_id: &str) -> BoxFuture<'_, ()> {
        let body = json!({ "chat_id": chat_id, "action": "typing" });
        Box::pin(async move {
            let _ = self.call("sendChatAction", body).await;
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A fake Bot API: answers each request by method name from `replies`, and
    /// records the request bodies.
    async fn fake_api(replies: Vec<(&'static str, Value)>) -> (String, std::sync::Arc<Mutex<Vec<(String, Value)>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let mut buf = vec![0u8; 65536];
                let mut len = 0;
                // Read headers + body (Content-Length).
                loop {
                    let n = socket.read(&mut buf[len..]).await.unwrap_or(0);
                    if n == 0 { break; }
                    len += n;
                    let text = String::from_utf8_lossy(&buf[..len]).to_string();
                    if let Some(split) = text.find("\r\n\r\n") {
                        let want = text.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length: ").and_then(|v| v.trim().parse::<usize>().ok())).unwrap_or(0);
                        if len >= split + 4 + want { break; }
                    }
                }
                let text = String::from_utf8_lossy(&buf[..len]).to_string();
                let path = text.split_whitespace().nth(1).unwrap_or("").to_owned();
                let method = path.rsplit('/').next().unwrap_or("").to_owned();
                let body: Value = text.split("\r\n\r\n").nth(1).and_then(|b| serde_json::from_str(b).ok()).unwrap_or(Value::Null);
                assert!(path.starts_with("/botTOKEN/"), "token goes in the path: {path}");
                log.lock().unwrap().push((method.clone(), body));
                let reply = replies.iter().find(|(m, _)| *m == method).map(|(_, r)| r.clone()).unwrap_or(json!({ "ok": true, "result": true }));
                let payload = reply.to_string();
                let head = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", payload.len());
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(payload.as_bytes()).await;
            }
        });
        (format!("http://{addr}"), seen)
    }

    fn me() -> (&'static str, Value) {
        ("getMe", json!({ "ok": true, "result": { "id": 999, "is_bot": true, "username": "BulgeBot" } }))
    }

    #[tokio::test]
    async fn polls_normalizes_and_advances_the_offset() {
        let updates = json!({ "ok": true, "result": [
            { "update_id": 10, "message": { "message_id": 1, "from": { "id": 42, "is_bot": false, "first_name": "Owner", "username": "me" }, "chat": { "id": 42, "type": "private" }, "text": "幫我整理報告" } },
            { "update_id": 11, "message": { "message_id": 2, "from": { "id": 7, "is_bot": false, "first_name": "A" }, "chat": { "id": -100, "type": "supergroup" }, "text": "@BulgeBot summarize this" } },
            { "update_id": 12, "message": { "message_id": 3, "from": { "id": 7, "is_bot": false, "first_name": "A" }, "chat": { "id": -100, "type": "supergroup" }, "text": "just chatting" } },
            { "update_id": 13, "message": { "message_id": 4, "from": { "id": 5, "is_bot": true, "first_name": "Other bot" }, "chat": { "id": -100, "type": "group" }, "text": "beep" } },
            { "update_id": 14, "edited_message": { "message_id": 1 } }
        ]});
        let (api, seen) = fake_api(vec![me(), ("getUpdates", updates)]).await;
        let tg = Telegram::connect("main", "TOKEN", &api, Some("5")).await.unwrap();
        assert_eq!(tg.bot_username(), "BulgeBot");
        let batch = tg.poll().await.unwrap();
        assert_eq!(batch.len(), 3, "bot messages and edits are skipped");
        assert_eq!(batch[0].text, "幫我整理報告");
        assert!(!batch[0].is_group && batch[0].mentioned);
        assert_eq!(batch[0].sender_name, "Owner (@me)");
        assert_eq!((batch[1].is_group, batch[1].mentioned, batch[1].text.as_str()), (true, true, "summarize this"));
        assert!(!batch[2].mentioned);
        assert_eq!(tg.cursor().as_deref(), Some("15"));
        let polls: Vec<Value> = seen.lock().unwrap().iter().filter(|(m, _)| m == "getUpdates").map(|(_, b)| b.clone()).collect();
        assert_eq!(polls[0]["offset"], 5);
    }

    #[tokio::test]
    async fn errors_are_classified_without_leaking_the_token() {
        let (api, _) = fake_api(vec![("getMe", json!({ "ok": false, "error_code": 401, "description": "Unauthorized" }))]).await;
        let Err(error) = Telegram::connect("main", "TOKEN", &api, None).await else { panic!("must fail") };
        assert!(error.is_fatal());
        assert!(!error.to_string().contains("TOKEN"));
        let (api, _) = fake_api(vec![me(), ("getUpdates", json!({ "ok": false, "error_code": 429, "description": "Too Many Requests", "parameters": { "retry_after": 7 } }))]).await;
        let tg = Telegram::connect("main", "TOKEN", &api, None).await.unwrap();
        match tg.poll().await {
            Err(ChannelError::Transient { retry_after_secs: Some(7), .. }) => {}
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn long_replies_are_split_into_sends() {
        let (api, seen) = fake_api(vec![me()]).await;
        let tg = Telegram::connect("main", "TOKEN", &api, None).await.unwrap();
        let long = "段落一。".repeat(1500);
        crate::send_long(&tg, "42", &long).await.unwrap();
        let sends: Vec<Value> = seen.lock().unwrap().iter().filter(|(m, _)| m == "sendMessage").map(|(_, b)| b.clone()).collect();
        assert_eq!(sends.len(), 2);
        assert!(sends.iter().all(|b| b["text"].as_str().unwrap().chars().count() <= TEXT_LIMIT && b["chat_id"] == "42"));
    }

    #[test]
    fn mention_offsets_come_from_the_original_text() {
        assert_eq!(find_ascii_ci("İ@BulgeBot hi", "@bulgebot"), Some(2));
        assert_eq!(find_ascii_ci("hello @BULGEBOT", "@bulgebot"), Some(6));
        assert_eq!(find_ascii_ci("ẞß@bulgebot", "@bulgebot"), Some(5));
        assert_eq!(find_ascii_ci("no mention", "@bulgebot"), None);
        assert_eq!(find_ascii_ci("@bulge", "@bulgebot"), None);
    }

    #[tokio::test]
    async fn the_command_menu_is_published_for_private_chats_and_groups() {
        let (api, seen) = fake_api(vec![me()]).await;
        let tg = Telegram::connect("main", "TOKEN", &api, None).await.unwrap();
        tg.register_commands(crate::commands::COMMANDS).await.unwrap();
        let calls: Vec<Value> = seen.lock().unwrap().iter().filter(|(m, _)| m == "setMyCommands").map(|(_, b)| b.clone()).collect();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["scope"]["type"], "all_private_chats");
        assert_eq!(calls[1]["scope"]["type"], "all_group_chats");
        assert!(calls[0]["commands"].as_array().unwrap().iter().any(|c| c["command"] == "stop"));
    }

    #[test]
    fn photos_take_the_largest_size_and_documents_keep_their_name() {
        let message = json!({
            "photo": [{ "file_id": "small", "file_size": 100 }, { "file_id": "big", "file_size": 9000 }],
            "document": { "file_id": "doc", "file_name": "data.csv", "file_size": 42 },
            "voice": { "file_id": "v" }
        });
        let files = attachments(&message);
        assert_eq!(files.iter().map(|f| (f.kind.as_str(), f.source.as_str())).collect::<Vec<_>>(), [("image", "big"), ("file", "doc"), ("audio", "v")]);
        assert_eq!(files[1].name.as_deref(), Some("data.csv"));
        assert!(attachments(&json!({ "text": "hi" })).is_empty());
    }
}
