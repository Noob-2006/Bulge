//! Matrix through the client-server API with `/sync` long polling: outbound
//! HTTPS only, no appservice registration, no listening port. Unencrypted
//! rooms only for now: encrypted rooms get a one-time notice instead.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures::future::BoxFuture;
use reqwest::Method;
use serde_json::{Value, json};

use crate::{Attachment, Channel, ChannelError, Inbound, download_capped};

/// Servers accept far longer events (64 KiB), but clients render long
/// messages poorly; stay conservative.
const TEXT_LIMIT: usize = 4000;
/// Long-poll wait per `/sync` call.
const POLL_MS: u64 = 30_000;
/// The very first sync (no saved position) only learns where "now" is: a tiny
/// timeline so old history is neither downloaded in bulk nor replayed.
const FIRST_SYNC_FILTER: &str = r#"{"room":{"timeline":{"limit":1}}}"#;
const ENCRYPTED_NOTICE: &str = "This room is end-to-end encrypted, and bulge cannot read encrypted rooms yet. Talk to me in an unencrypted room or DM instead.";

pub struct Matrix {
    name: String,
    homeserver: String,
    token: String,
    http: reqwest::Client,
    user_id: String,
    /// Lowercased strings that address the bot in a message body: the user
    /// id, its localpart, and the display name.
    handles: Vec<String>,
    /// `next_batch` of the last sync that was fully handled.
    since: Mutex<Option<String>>,
    rooms: Mutex<Rooms>,
    /// Random per process, so transaction ids never collide with an earlier
    /// run's (the server deduplicates by token + txn id).
    txn_prefix: String,
    txn_counter: AtomicU64,
}

/// What earlier syncs taught us about rooms (summaries and account data are
/// only sent when they change).
#[derive(Default)]
struct Rooms {
    joined_members: HashMap<String, u64>,
    /// Rooms listed as DMs in the bot's `m.direct` account data.
    direct: HashSet<String>,
    /// User id → display name, from member events.
    names: HashMap<String, String>,
    /// Encrypted rooms already told that they are not supported.
    told_encrypted: HashSet<String>,
}

impl Matrix {
    /// Connect: check the token (`whoami`) and learn the bot's own identity.
    /// `cursor` is the persisted `next_batch`, if any.
    pub async fn connect(account: &str, homeserver: &str, access_token: &str, cursor: Option<&str>) -> Result<Self, ChannelError> {
        let name = format!("matrix:{account}");
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(POLL_MS) + Duration::from_secs(30))
            .build()
            .map_err(|e| ChannelError::Other { channel: name.clone(), message: e.to_string() })?;
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).map_err(|e| ChannelError::Other { channel: name.clone(), message: format!("random: {e}") })?;
        let mut channel = Self {
            name,
            homeserver: homeserver.trim_end_matches('/').to_owned(),
            token: access_token.to_owned(),
            http,
            user_id: String::new(),
            handles: Vec::new(),
            since: Mutex::new(cursor.filter(|c| !c.is_empty()).map(str::to_owned)),
            rooms: Mutex::new(Rooms::default()),
            txn_prefix: random.iter().map(|b| format!("{b:02x}")).collect(),
            txn_counter: AtomicU64::new(0),
        };
        let me = channel.call(Method::GET, "whoami", "/_matrix/client/v3/account/whoami".into(), None).await?;
        channel.user_id = me.get("user_id").and_then(Value::as_str).unwrap_or("").to_owned();
        if channel.user_id.is_empty() {
            return Err(ChannelError::Other { channel: channel.name.clone(), message: "whoami: no user id in reply".into() });
        }
        // The display name is only used to notice mentions: best effort.
        let profile = format!("/_matrix/client/v3/profile/{}/displayname", encode(&channel.user_id));
        let display = channel.call(Method::GET, "profile", profile, None).await.ok();
        let localpart = channel.user_id.trim_start_matches('@').split(':').next().unwrap_or("").to_owned();
        let display = display.as_ref().and_then(|p| p.get("displayname")).and_then(Value::as_str).unwrap_or("").to_owned();
        for handle in [channel.user_id.clone(), localpart, display] {
            let handle = handle.trim().to_lowercase();
            if !handle.is_empty() && !channel.handles.contains(&handle) {
                channel.handles.push(handle);
            }
        }
        // Longest first, so `Bulge Bot:` is stripped whole rather than as `Bulge`.
        channel.handles.sort_by_key(|h| std::cmp::Reverse(h.len()));
        Ok(channel)
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// One client-server API call. The token travels in the Authorization
    /// header only, and is scrubbed from any message the server sends back.
    async fn call(&self, method: Method, what: &str, path: String, body: Option<Value>) -> Result<Value, ChannelError> {
        let transient = |message: String| ChannelError::Transient { channel: self.name.clone(), message: self.scrub(message), retry_after_secs: None };
        let mut request = self.http.request(method, format!("{}{path}", self.homeserver)).bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.map_err(|e| transient(format!("{what}: network error: {}", e.without_url())))?;
        let status = response.status();
        let retry_header = response.headers().get(reqwest::header::RETRY_AFTER).and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok());
        let text = response.text().await.map_err(|e| transient(format!("{what}: unreadable reply: {}", e.without_url())))?;
        let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if status.is_success() {
            return Ok(value);
        }
        let errcode = value.get("errcode").and_then(Value::as_str).unwrap_or("");
        let detail = value.get("error").and_then(Value::as_str).map(str::to_owned).unwrap_or_else(|| status.to_string());
        let message = self.scrub(if errcode.is_empty() { format!("{what}: {detail}") } else { format!("{what}: {detail} ({errcode})") });
        Err(match (status.as_u16(), errcode) {
            (401, _) | (_, "M_UNKNOWN_TOKEN" | "M_MISSING_TOKEN") => ChannelError::Auth { channel: self.name.clone(), message },
            (429, _) | (_, "M_LIMIT_EXCEEDED") => ChannelError::Transient {
                channel: self.name.clone(),
                message,
                retry_after_secs: value.get("retry_after_ms").and_then(Value::as_u64).map(|ms| ms.div_ceil(1000)).or(retry_header),
            },
            (500.., _) => transient(message),
            _ => ChannelError::Other { channel: self.name.clone(), message },
        })
    }

    fn scrub(&self, message: String) -> String {
        if self.token.is_empty() { message } else { message.replace(&self.token, "<redacted>") }
    }

    fn next_txn(&self) -> String {
        format!("bulge-{}-{}", self.txn_prefix, self.txn_counter.fetch_add(1, Ordering::Relaxed))
    }

    async fn send_content(&self, room_id: &str, content: Value) -> Result<(), ChannelError> {
        let path = format!("/_matrix/client/v3/rooms/{}/send/m.room.message/{}", encode(room_id), encode(&self.next_txn()));
        self.call(Method::PUT, "send", path, Some(content)).await.map(|_| ())
    }

    /// Learn what a sync says about rooms: DM list, member counts, names.
    fn absorb(&self, sync: &Value) {
        let Ok(mut rooms) = self.rooms.lock() else { return };
        for event in events(sync.pointer("/account_data/events")) {
            if event.get("type").and_then(Value::as_str) == Some("m.direct")
                && let Some(map) = event.get("content").and_then(Value::as_object)
            {
                rooms.direct = map.values().filter_map(Value::as_array).flatten().filter_map(Value::as_str).map(str::to_owned).collect();
            }
        }
        let Some(joined) = sync.pointer("/rooms/join").and_then(Value::as_object) else { return };
        for (room_id, room) in joined {
            if let Some(count) = room.pointer("/summary/m.joined_member_count").and_then(Value::as_u64) {
                rooms.joined_members.insert(room_id.clone(), count);
            }
            for event in events(room.pointer("/state/events")).chain(events(room.pointer("/timeline/events"))) {
                if event.get("type").and_then(Value::as_str) == Some("m.room.member")
                    && let (Some(user), Some(name)) = (event.get("state_key").and_then(Value::as_str), event.pointer("/content/displayname").and_then(Value::as_str))
                {
                    rooms.names.insert(user.to_owned(), name.to_owned());
                }
            }
        }
    }

    /// Is this event the bot's own (fresh) join? Events before it in the same
    /// timeline are history from before the bot was in the room.
    fn is_own_join(&self, event: &Value) -> bool {
        event.get("type").and_then(Value::as_str) == Some("m.room.member")
            && event.get("state_key").and_then(Value::as_str) == Some(self.user_id.as_str())
            && event.pointer("/content/membership").and_then(Value::as_str) == Some("join")
            && event.pointer("/unsigned/prev_content/membership").and_then(Value::as_str) != Some("join")
    }

    /// Normalize one timeline event; `None` for anything that is not a plain
    /// text message from someone else (own echoes, notices, edits, state).
    fn inbound(&self, room_id: &str, event: &Value) -> Option<Inbound> {
        if event.get("type").and_then(Value::as_str) != Some("m.room.message") {
            return None;
        }
        let sender = event.get("sender").and_then(Value::as_str)?;
        if sender == self.user_id {
            return None;
        }
        let content = event.get("content")?;
        let msgtype = content.get("msgtype").and_then(Value::as_str)?;
        if content.pointer("/m.relates_to/rel_type").and_then(Value::as_str) == Some("m.replace") {
            return None;
        }
        // Media: `body` is the caption when `filename` is set, else the file name.
        let (body, attachments) = match msgtype {
            "m.text" => (content.get("body").and_then(Value::as_str)?, Vec::new()),
            "m.image" | "m.file" | "m.video" | "m.audio" => {
                let url = content.get("url").and_then(Value::as_str)?;
                let filename = content.get("filename").and_then(Value::as_str);
                let body = content.get("body").and_then(Value::as_str).unwrap_or("");
                let attachment = Attachment {
                    kind: msgtype.trim_start_matches("m.").to_owned(),
                    name: filename.or(Some(body)).filter(|n| !n.is_empty()).map(str::to_owned),
                    source: url.to_owned(),
                    size: content.pointer("/info/size").and_then(Value::as_u64),
                };
                (if filename.is_some() { body } else { "" }, vec![attachment])
            }
            _ => return None,
        };
        let rooms = self.rooms.lock().ok()?;
        let is_group = match rooms.joined_members.get(room_id) {
            Some(count) => *count > 2,
            None => !rooms.direct.contains(room_id),
        };
        let lower = body.to_lowercase();
        let tagged = content.pointer("/m.mentions/user_ids").and_then(Value::as_array).is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(self.user_id.as_str())));
        // The full body still holds a reply's quote fallback ("> <@bot:…> …"),
        // so a reply to the bot counts as addressing it.
        let named = self.handles.iter().any(|h| lower.contains(h.as_str()));
        let text = self.strip_handle(strip_reply_fallback(body));
        let sender_name = match rooms.names.get(sender) {
            Some(name) => format!("{name} ({sender})"),
            None => sender.to_owned(),
        };
        Some(Inbound {
            channel: self.name.clone(),
            chat_id: room_id.to_owned(),
            sender_id: sender.to_owned(),
            sender_name,
            is_group,
            mentioned: !is_group || tagged || named,
            text,
            message_id: event.get("event_id").and_then(Value::as_str).unwrap_or("").to_owned(),
            attachments,
        })
    }

    /// `Bulge: do this` (how clients write a mention pill) → `do this`.
    fn strip_handle(&self, body: &str) -> String {
        for handle in &self.handles {
            if let Some(prefix) = body.get(..handle.len())
                && prefix.to_lowercase() == *handle
            {
                return body[handle.len()..].trim_start_matches([':', ',']).trim().to_owned();
            }
        }
        body.trim().to_owned()
    }
}

/// The text after a reply's `> ` quote lines and the blank line after them.
fn strip_reply_fallback(body: &str) -> &str {
    if !body.starts_with("> ") {
        return body;
    }
    match body.find("\n\n") {
        Some(at) if body[..at].lines().all(|l| l.starts_with('>')) => &body[at + 2..],
        _ => body,
    }
}

fn events(list: Option<&Value>) -> impl Iterator<Item = &Value> {
    list.and_then(Value::as_array).into_iter().flatten()
}

/// Percent-encode one path segment or query value.
fn encode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

impl Channel for Matrix {
    fn name(&self) -> &str {
        &self.name
    }

    fn fetch<'a>(&'a self, attachment: &'a Attachment, max_bytes: u64) -> BoxFuture<'a, Result<Vec<u8>, ChannelError>> {
        Box::pin(async move {
            // mxc://<server>/<media id> through the homeserver's authenticated media API.
            let bad = || ChannelError::Other { channel: self.name.clone(), message: "not a valid mxc:// media URL".into() };
            let (server, media) = attachment.source.strip_prefix("mxc://").and_then(|rest| rest.split_once('/')).ok_or_else(bad)?;
            // No "." or ".." segments: they would be resolved into another path on the homeserver.
            let ok = |part: &str| !part.is_empty() && part.chars().any(|c| c != '.') && part.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'));
            if !ok(server) || !ok(media) {
                return Err(bad());
            }
            let url = format!("{}/_matrix/client/v1/media/download/{server}/{media}", self.homeserver);
            download_capped(self.http.get(url).bearer_auth(&self.token), max_bytes, &self.name).await
        })
    }

    fn text_limit(&self) -> usize {
        TEXT_LIMIT
    }

    fn cursor(&self) -> Option<String> {
        self.since.lock().ok().and_then(|s| s.clone())
    }

    fn poll(&self) -> BoxFuture<'_, Result<Vec<Inbound>, ChannelError>> {
        Box::pin(async move {
            let since = self.since.lock().map_err(|_| ChannelError::Other { channel: self.name.clone(), message: "state poisoned".into() })?.clone();
            let path = match &since {
                Some(since) => format!("/_matrix/client/v3/sync?timeout={POLL_MS}&since={}", encode(since)),
                None => format!("/_matrix/client/v3/sync?timeout=0&filter={}", encode(FIRST_SYNC_FILTER)),
            };
            let sync = self.call(Method::GET, "sync", path, None).await?;
            self.absorb(&sync);
            // Invites: join (who may command bulge is still decided upstream).
            // A failed join is not fatal; the inviter can invite again.
            if let Some(invites) = sync.pointer("/rooms/invite").and_then(Value::as_object) {
                for room_id in invites.keys() {
                    match self.call(Method::POST, "join", format!("/_matrix/client/v3/join/{}", encode(room_id)), Some(json!({}))).await {
                        Err(error) if error.is_fatal() => return Err(error),
                        _ => {}
                    }
                }
            }
            let mut batch = Vec::new();
            let mut notify = Vec::new();
            if since.is_some()
                && let Some(joined) = sync.pointer("/rooms/join").and_then(Value::as_object)
            {
                for (room_id, room) in joined {
                    let timeline: Vec<&Value> = events(room.pointer("/timeline/events")).collect();
                    let start = timeline.iter().rposition(|e| self.is_own_join(e)).map_or(0, |at| at + 1);
                    for event in &timeline[start..] {
                        if event.get("type").and_then(Value::as_str) == Some("m.room.encrypted") {
                            let from_other = event.get("sender").and_then(Value::as_str) != Some(self.user_id.as_str());
                            if from_other && self.rooms.lock().is_ok_and(|mut r| r.told_encrypted.insert(room_id.clone())) {
                                notify.push(room_id.clone());
                            }
                        } else if let Some(message) = self.inbound(room_id, event) {
                            batch.push(message);
                        }
                    }
                }
            }
            for room_id in notify {
                // Best effort; an encrypted room cannot read it anyway if the
                // server refuses plaintext, and the room stays marked as told.
                let _ = self.send_content(&room_id, json!({ "msgtype": "m.notice", "body": ENCRYPTED_NOTICE })).await;
            }
            if let Some(next) = sync.get("next_batch").and_then(Value::as_str)
                && let Ok(mut current) = self.since.lock()
            {
                *current = Some(next.to_owned());
            }
            Ok(batch)
        })
    }

    fn send(&self, chat_id: &str, text: &str) -> BoxFuture<'_, Result<(), ChannelError>> {
        let room_id = chat_id.to_owned();
        let content = json!({ "msgtype": "m.text", "body": text });
        Box::pin(async move { self.send_content(&room_id, content).await })
    }

    fn typing(&self, chat_id: &str) -> BoxFuture<'_, ()> {
        let path = format!("/_matrix/client/v3/rooms/{}/typing/{}", encode(chat_id), encode(&self.user_id));
        Box::pin(async move {
            let _ = self.call(Method::PUT, "typing", path, Some(json!({ "typing": true, "timeout": 5000 }))).await;
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// One recorded request: method, path with query, Authorization header, body.
    type Seen = Arc<Mutex<Vec<(String, String, String, Value)>>>;

    /// A fake homeserver: answers by (method, path prefix) from `routes`; when
    /// several routes match, the first is used up and the last one repeats.
    async fn fake_server(routes: Vec<(&'static str, &'static str, u16, Value)>) -> (String, Seen) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let routes = Arc::new(Mutex::new(routes));
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let mut buf = vec![0u8; 65536];
                let mut len = 0;
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
                let mut words = text.split_whitespace();
                let method = words.next().unwrap_or("").to_owned();
                let path = words.next().unwrap_or("").to_owned();
                let auth = text.lines().find_map(|l| l.to_ascii_lowercase().starts_with("authorization:").then(|| l[14..].trim().to_owned())).unwrap_or_default();
                let body: Value = text.split("\r\n\r\n").nth(1).and_then(|b| serde_json::from_str(b).ok()).unwrap_or(Value::Null);
                log.lock().unwrap().push((method.clone(), path.clone(), auth, body));
                let (status, reply) = {
                    let mut routes = routes.lock().unwrap();
                    let matching: Vec<usize> = routes.iter().enumerate().filter(|(_, r)| r.0 == method && path.starts_with(r.1)).map(|(i, _)| i).collect();
                    match matching.as_slice() {
                        [] => (200, json!({})),
                        [only] => (routes[*only].2, routes[*only].3.clone()),
                        [first, ..] => {
                            let route = routes.remove(*first);
                            (route.2, route.3)
                        }
                    }
                };
                let payload = reply.to_string();
                let head = format!("HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", payload.len());
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(payload.as_bytes()).await;
            }
        });
        (format!("http://{addr}"), seen)
    }

    const SYNC: &str = "/_matrix/client/v3/sync";

    fn whoami() -> (&'static str, &'static str, u16, Value) {
        ("GET", "/_matrix/client/v3/account/whoami", 200, json!({ "user_id": "@bulge:ex.org" }))
    }

    fn profile() -> (&'static str, &'static str, u16, Value) {
        ("GET", "/_matrix/client/v3/profile/", 200, json!({ "displayname": "Bulge Bot" }))
    }

    fn text(id: &str, sender: &str, body: &str) -> Value {
        json!({ "type": "m.room.message", "event_id": id, "sender": sender, "content": { "msgtype": "m.text", "body": body } })
    }

    fn requests(seen: &Seen, method: &str, prefix: &str) -> Vec<(String, Value)> {
        seen.lock().unwrap().iter().filter(|r| r.0 == method && r.1.starts_with(prefix)).map(|r| (r.1.clone(), r.3.clone())).collect()
    }

    #[tokio::test]
    async fn first_sync_records_the_position_without_replaying_history() {
        let first = json!({ "next_batch": "s1",
            "rooms": { "join": { "!old:ex.org": { "timeline": { "events": [text("$old", "@owner:ex.org", "rm -rf everything")] } } },
                       "invite": { "!inv:ex.org": { "invite_state": { "events": [] } } } } });
        let second = json!({ "next_batch": "s2", "rooms": { "join": { "!old:ex.org": { "summary": { "m.joined_member_count": 2 }, "timeline": { "events": [text("$new", "@owner:ex.org", "hello")] } } } } });
        let (api, seen) = fake_server(vec![whoami(), profile(), ("GET", SYNC, 200, first), ("GET", SYNC, 200, second)]).await;
        let mx = Matrix::connect("main", &api, "TOKEN", None).await.unwrap();
        assert_eq!(mx.user_id(), "@bulge:ex.org");
        assert!(mx.poll().await.unwrap().is_empty(), "history before the first sync is not a command");
        assert_eq!(mx.cursor().as_deref(), Some("s1"));
        let batch = mx.poll().await.unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!((batch[0].text.as_str(), batch[0].message_id.as_str()), ("hello", "$new"));
        assert_eq!(mx.cursor().as_deref(), Some("s2"));
        let syncs = requests(&seen, "GET", SYNC);
        assert!(syncs[0].0.contains("timeout=0") && syncs[0].0.contains("filter=") && !syncs[0].0.contains("since="), "{}", syncs[0].0);
        assert!(syncs[1].0.contains("since=s1") && syncs[1].0.contains("timeout=30000"));
        let joins = requests(&seen, "POST", "/_matrix/client/v3/join/");
        assert_eq!(joins.len(), 1);
        assert_eq!(joins[0].0, "/_matrix/client/v3/join/%21inv%3Aex.org");
        assert!(seen.lock().unwrap().iter().all(|r| r.2 == "Bearer TOKEN" && !r.1.contains("TOKEN")), "token only in the header");
    }

    #[tokio::test]
    async fn normalizes_rooms_dms_and_mentions() {
        let sync = json!({ "next_batch": "s1",
            "account_data": { "events": [{ "type": "m.direct", "content": { "@owner:ex.org": ["!known-dm:ex.org"] } }] },
            "rooms": { "join": {
                "!dm:ex.org": { "summary": { "m.joined_member_count": 2 },
                    "state": { "events": [{ "type": "m.room.member", "state_key": "@owner:ex.org", "content": { "membership": "join", "displayname": "Owner" } }] },
                    "timeline": { "events": [text("$1", "@owner:ex.org", "幫我整理報告"), text("$own", "@bulge:ex.org", "my own echo")] } },
                "!group:ex.org": { "summary": { "m.joined_member_count": 5 }, "timeline": { "events": [
                    text("$2", "@a:ex.org", "Bulge Bot: summarize this"),
                    text("$3", "@a:ex.org", "just chatting"),
                    { "type": "m.room.message", "event_id": "$4", "sender": "@a:ex.org", "content": { "msgtype": "m.text", "body": "hey you", "m.mentions": { "user_ids": ["@bulge:ex.org"] } } },
                    text("$5", "@a:ex.org", "ping @bulge:ex.org"),
                    { "type": "m.room.message", "event_id": "$6", "sender": "@a:ex.org", "content": { "msgtype": "m.notice", "body": "a bot notice" } },
                    { "type": "m.room.message", "event_id": "$7", "sender": "@a:ex.org", "content": { "msgtype": "m.text", "body": "* edited", "m.relates_to": { "rel_type": "m.replace", "event_id": "$3" } } },
                    text("$8", "@a:ex.org", "> <@bulge:ex.org> done\n\nthanks, now the next one")
                ] } },
                "!known-dm:ex.org": { "timeline": { "events": [text("$9", "@owner:ex.org", "dm without summary")] } },
                "!unknown:ex.org": { "timeline": { "events": [text("$10", "@a:ex.org", "who knows")] } }
            } } });
        let (api, _) = fake_server(vec![whoami(), profile(), ("GET", SYNC, 200, sync)]).await;
        let mx = Matrix::connect("main", &api, "TOKEN", Some("s0")).await.unwrap();
        let batch = mx.poll().await.unwrap();
        let by_id: HashMap<&str, &Inbound> = batch.iter().map(|m| (m.message_id.as_str(), m)).collect();
        assert_eq!(batch.len(), 8, "own echo, notices and edits are skipped: {batch:?}");
        let dm = by_id["$1"];
        assert_eq!((dm.chat_id.as_str(), dm.sender_id.as_str(), dm.sender_name.as_str(), dm.text.as_str()), ("!dm:ex.org", "@owner:ex.org", "Owner (@owner:ex.org)", "幫我整理報告"));
        assert!(!dm.is_group && dm.mentioned);
        assert_eq!(dm.channel, "matrix:main");
        assert_eq!((by_id["$2"].is_group, by_id["$2"].mentioned, by_id["$2"].text.as_str()), (true, true, "summarize this"));
        assert!(!by_id["$3"].mentioned);
        assert!(by_id["$4"].mentioned, "m.mentions");
        assert!(by_id["$5"].mentioned, "user id in body");
        assert!(by_id["$8"].mentioned, "reply to the bot");
        assert_eq!(by_id["$8"].text, "thanks, now the next one");
        assert!(!by_id["$9"].is_group, "m.direct room");
        assert!(by_id["$10"].is_group && !by_id["$10"].mentioned, "unknown size counts as a group");
    }

    #[tokio::test]
    async fn joined_room_history_before_the_join_is_skipped() {
        let sync = json!({ "next_batch": "s1", "rooms": { "join": { "!r:ex.org": { "summary": { "m.joined_member_count": 2 }, "timeline": { "events": [
            text("$before", "@owner:ex.org", "old message"),
            { "type": "m.room.member", "state_key": "@bulge:ex.org", "sender": "@bulge:ex.org", "content": { "membership": "join" }, "unsigned": { "prev_content": { "membership": "invite" } } },
            text("$after", "@owner:ex.org", "new message")
        ] } } } } });
        let (api, _) = fake_server(vec![whoami(), profile(), ("GET", SYNC, 200, sync)]).await;
        let mx = Matrix::connect("main", &api, "TOKEN", Some("s0")).await.unwrap();
        let batch = mx.poll().await.unwrap();
        assert_eq!(batch.iter().map(|m| m.message_id.as_str()).collect::<Vec<_>>(), ["$after"]);
    }

    #[tokio::test]
    async fn encrypted_rooms_are_told_once() {
        let encrypted = |id: &str| json!({ "type": "m.room.encrypted", "event_id": id, "sender": "@owner:ex.org", "content": { "algorithm": "m.megolm.v1.aes-sha2", "ciphertext": "x" } });
        let one = json!({ "next_batch": "s1", "rooms": { "join": { "!e:ex.org": { "timeline": { "events": [encrypted("$1"), encrypted("$2")] } } } } });
        let two = json!({ "next_batch": "s2", "rooms": { "join": { "!e:ex.org": { "timeline": { "events": [encrypted("$3")] } }, "!f:ex.org": { "timeline": { "events": [encrypted("$4")] } } } } });
        let (api, seen) = fake_server(vec![whoami(), profile(), ("GET", SYNC, 200, one), ("GET", SYNC, 200, two)]).await;
        let mx = Matrix::connect("main", &api, "TOKEN", Some("s0")).await.unwrap();
        assert!(mx.poll().await.unwrap().is_empty());
        assert!(mx.poll().await.unwrap().is_empty());
        let sends = requests(&seen, "PUT", "/_matrix/client/v3/rooms/");
        let rooms: Vec<&str> = sends.iter().map(|(p, _)| p.split('/').nth(5).unwrap()).collect();
        assert_eq!(rooms, ["%21e%3Aex.org", "%21f%3Aex.org"]);
        assert!(sends.iter().all(|(_, b)| b["msgtype"] == "m.notice" && b["body"].as_str().unwrap().contains("encrypted")));
    }

    #[tokio::test]
    async fn sends_with_unique_transaction_ids_and_types() {
        let (api, seen) = fake_server(vec![whoami(), profile(), ("PUT", "/_matrix/client/v3/rooms/", 200, json!({ "event_id": "$x" }))]).await;
        let mx = Matrix::connect("main", &api, "TOKEN", None).await.unwrap();
        let long = "段落一。".repeat(1500);
        crate::send_long(&mx, "!r:ex.org", &long).await.unwrap();
        mx.send("!r:ex.org", "short").await.unwrap();
        mx.typing("!r:ex.org").await;
        let sends = requests(&seen, "PUT", "/_matrix/client/v3/rooms/%21r%3Aex.org/send/m.room.message/");
        assert_eq!(sends.len(), 3);
        let txns: HashSet<&str> = sends.iter().map(|(p, _)| p.rsplit('/').next().unwrap()).collect();
        assert_eq!(txns.len(), 3, "transaction ids are unique");
        assert!(sends.iter().all(|(_, b)| b["msgtype"] == "m.text" && b["body"].as_str().unwrap().chars().count() <= TEXT_LIMIT));
        let typing = requests(&seen, "PUT", "/_matrix/client/v3/rooms/%21r%3Aex.org/typing/%40bulge%3Aex.org");
        assert_eq!(typing.len(), 1);
        assert_eq!(typing[0].1, json!({ "typing": true, "timeout": 5000 }));
    }

    #[tokio::test]
    async fn errors_are_classified_without_leaking_the_token() {
        let (api, _) = fake_server(vec![("GET", "/_matrix/client/v3/account/whoami", 401, json!({ "errcode": "M_UNKNOWN_TOKEN", "error": "Invalid access token passed: TOKEN" }))]).await;
        let Err(error) = Matrix::connect("main", &api, "TOKEN", None).await else { panic!("must fail") };
        assert!(error.is_fatal(), "{error:?}");
        assert!(!error.to_string().contains("TOKEN"), "{error}");
        let (api, _) = fake_server(vec![whoami(), profile(), ("GET", SYNC, 429, json!({ "errcode": "M_LIMIT_EXCEEDED", "error": "Too many requests", "retry_after_ms": 2500 }))]).await;
        let mx = Matrix::connect("main", &api, "TOKEN", None).await.unwrap();
        match mx.poll().await {
            Err(ChannelError::Transient { retry_after_secs: Some(3), .. }) => {}
            other => panic!("{other:?}"),
        }
        let (api, _) = fake_server(vec![whoami(), profile(), ("PUT", "/_matrix/client/v3/rooms/", 403, json!({ "errcode": "M_FORBIDDEN", "error": "not in room" }))]).await;
        let mx = Matrix::connect("main", &api, "TOKEN", None).await.unwrap();
        let error = mx.send("!r:ex.org", "hi").await.unwrap_err();
        assert!(!error.is_fatal() && error.to_string().contains("M_FORBIDDEN"), "{error}");
        let Err(dead) = Matrix::connect("main", "http://127.0.0.1:1", "TOKEN", None).await else { panic!("must fail") };
        assert!(matches!(dead, ChannelError::Transient { .. }) && !dead.to_string().contains("TOKEN"), "{dead}");
    }

    #[tokio::test]
    async fn media_messages_become_attachments() {
        let event = |content: Value| json!({ "type": "m.room.message", "event_id": "$m", "sender": "@a:ex.org", "content": content });
        let (api, _) = fake_server(vec![whoami(), profile()]).await;
        let matrix = Matrix::connect("main", &api, "TOKEN", None).await.unwrap();
        let image = matrix.inbound("!r:ex.org", &event(json!({ "msgtype": "m.image", "body": "cat.png", "url": "mxc://ex.org/AbC123", "info": { "size": 99, "mimetype": "image/png" } }))).unwrap();
        assert_eq!(image.text, "", "a bare file name is not a caption");
        assert_eq!(image.attachments[0].kind, "image");
        assert_eq!(image.attachments[0].name.as_deref(), Some("cat.png"));
        assert_eq!(image.attachments[0].source, "mxc://ex.org/AbC123");
        let captioned = matrix.inbound("!r:ex.org", &event(json!({ "msgtype": "m.file", "body": "please summarize", "filename": "report.pdf", "url": "mxc://ex.org/Def" }))).unwrap();
        assert_eq!(captioned.text, "please summarize");
        assert_eq!(captioned.attachments[0].name.as_deref(), Some("report.pdf"));
        assert!(matrix.inbound("!r:ex.org", &event(json!({ "msgtype": "m.location", "body": "here" }))).is_none());
    }
}
