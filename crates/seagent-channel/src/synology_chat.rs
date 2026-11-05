//! Synology Chat bots (ported from OpenClaw `extensions/synology-chat`, MIT).
//!
//! Receive: Synology's outgoing webhook / chatbot posts form or JSON fields
//! (`token`, `user_id`, `username`, `post_id`, `timestamp`, `text`,
//! `trigger_word`, `channel_id`/`channel_name`) to our listener. The token may
//! arrive in the body, the query, `X-Synology-Token` / `X-Webhook-Token` or a
//! Bearer header and is compared in constant time; a missing or wrong token is
//! 401 and repeated failures from one peer are locked out with 429. Authorised
//! senders are throttled per minute (`rate_limit_per_minute`). Accepted
//! events are answered 204. Synology bots are direct-message only, as upstream.
//! With `name_matching` the webhook username is resolved to the Chat API
//! user id via `method=user_list` (cached 5 min).
//!
//! Send: `POST <incoming_url>` (`entry.cgi?api=SYNO.Chat.External&method=chatbot|incoming…`)
//! with `payload=<JSON>` (`text`, `user_ids`, `file_url`), 2000-char chunks
//! and at least `min_interval` (500 ms) between posts. Local files are hosted
//! for 10 minutes behind a random token on the webhook listener and passed as
//! `file_url` (needs the public `webhook_url`).

use crate::http::{classify, Http, Payload};
use crate::{chunk, markup, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, Outbound, Sent, Streaming, TextFormat};
use seagent_core::Cancel;
use seagent_net::crypto;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_PATH: &str = "/webhook/synology";
pub const MAX_MESSAGE: usize = 2000;
const MEDIA_TTL: Duration = Duration::from_secs(600);
const MEDIA_MAX_BYTES: usize = 32 * 1024 * 1024;
const MEDIA_MAX_ENTRIES: usize = 16;
const USERS_TTL: Duration = Duration::from_secs(300);
/// Wrong-token attempts per peer per minute before every request is refused.
const BAD_TOKEN_BUDGET: usize = 10;

pub struct Config {
    pub id: String,
    /// The outgoing-webhook / bot token Synology sends with every event.
    pub token: String,
    /// Incoming webhook or chatbot URL (carries its own token in the query).
    pub incoming_url: String,
    pub listen: String,
    pub path: String,
    /// Public HTTPS URL of `path` (needed to host local files for `file_url`).
    pub webhook_url: Option<String>,
    pub rate_limit_per_minute: u32,
    /// Resolve webhook usernames to Chat API user ids through `user_list`.
    pub name_matching: bool,
    pub poll_timeout_secs: u64,
}

struct Hosted {
    bytes: Vec<u8>,
    mime: String,
    name: String,
    expires: Instant,
}

type Store = Arc<Mutex<HashMap<String, Hosted>>>;

pub struct SynologyChat {
    id: String,
    incoming_url: String,
    webhook_url: Option<String>,
    name_matching: bool,
    http: Http,
    poll_timeout: u64,
    /// Minimum gap between posts to the incoming URL.
    pub min_interval: Duration,
    last_send: Mutex<Option<Instant>>,
    rx: Mutex<Receiver<Value>>,
    server: Mutex<Option<seagent_net::httpd::Server>>,
    media: Store,
    users: Mutex<Option<(Vec<Value>, Instant)>>,
}

/// Sliding one-minute counter per key.
#[derive(Default)]
struct Window(HashMap<String, Vec<Instant>>);

impl Window {
    fn count(&mut self, key: &str) -> usize {
        let now = Instant::now();
        let v = self.0.entry(key.to_string()).or_default();
        v.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
        v.len()
    }
    fn hit(&mut self, key: &str) -> usize {
        let n = self.count(key);
        self.0.get_mut(key).unwrap().push(Instant::now());
        n + 1
    }
}

/// Body fields (form or JSON), falling back to the query.
fn fields(r: &seagent_net::httpd::Request) -> Result<HashMap<String, String>, ()> {
    let mut out: HashMap<String, String> = HashMap::new();
    for (k, v) in &r.query {
        out.insert(k.clone(), v.clone());
    }
    let body = r.body_str().trim();
    let ctype = r.header("content-type").unwrap_or("").to_ascii_lowercase();
    let json_like = ctype.contains("application/json") || (!ctype.contains("form") && body.starts_with('{'));
    if body.is_empty() {
        return Ok(out);
    }
    if json_like {
        let v: Value = serde_json::from_str(body).map_err(|_| ())?;
        for (k, v) in v.as_object().ok_or(())? {
            let s = match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => continue,
            };
            out.insert(k.clone(), s);
        }
    } else {
        for (k, v) in seagent_net::parse_query(body) {
            out.insert(k, v);
        }
    }
    Ok(out)
}

fn pick<'a>(f: &'a HashMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|k| f.get(*k).map(|s| s.trim()).filter(|s| !s.is_empty()))
}

fn header_token(r: &seagent_net::httpd::Request) -> Option<String> {
    for h in ["x-synology-token", "x-webhook-token", "x-openclaw-token"] {
        if let Some(v) = r.header(h).map(str::trim).filter(|v| !v.is_empty()) {
            return Some(v.to_string());
        }
    }
    let a = r.header("authorization")?.trim();
    Some(a.strip_prefix("Bearer ").or_else(|| a.strip_prefix("bearer ")).unwrap_or(a).trim().to_string()).filter(|s| !s.is_empty())
}

fn handler(want: String, path: String, per_minute: u32, tx: std::sync::mpsc::Sender<Value>, media: Store) -> seagent_net::httpd::Handler {
    use seagent_net::httpd::Response;
    let tx = Mutex::new(tx);
    let bad = Mutex::new(Window::default());
    let users = Mutex::new(Window::default());
    Arc::new(move |r: seagent_net::httpd::Request| {
        if r.path != path {
            return Response::text(404, "not found");
        }
        if r.method == "GET" {
            // Hosted outbound media for `file_url`.
            let Some(tok) = r.query("seagent_media") else { return Response::text(405, "method not allowed") };
            let mut m = media.lock().unwrap();
            m.retain(|_, h| h.expires > Instant::now());
            return match m.get(tok) {
                Some(h) => Response::new(200, &h.mime, h.bytes.clone()).with_header("content-disposition", &format!("inline; filename=\"{}\"", h.name.replace('"', ""))),
                None => Response::text(404, "not found"),
            };
        }
        if r.method != "POST" {
            return Response::text(405, "method not allowed");
        }
        let peer = r.peer.map(|p| p.ip().to_string()).unwrap_or_default();
        if bad.lock().unwrap().count(&peer) >= BAD_TOKEN_BUDGET {
            return Response::text(429, "rate limit exceeded");
        }
        let Ok(f) = fields(&r) else { return Response::text(400, "bad body") };
        let token = pick(&f, &["token"]).map(str::to_string).or_else(|| header_token(&r));
        if !token.is_some_and(|t| !want.is_empty() && crypto::ct_eq(t.as_bytes(), want.as_bytes())) {
            bad.lock().unwrap().hit(&peer);
            return Response::text(401, "invalid token");
        }
        let (Some(user), Some(text)) = (pick(&f, &["user_id", "userId", "user"]), pick(&f, &["text", "message", "content"])) else {
            return Response::text(400, "missing required fields (token, user_id, text)");
        };
        if users.lock().unwrap().hit(user) > per_minute.max(1) as usize {
            return Response::text(429, "rate limit exceeded");
        }
        let ev = json!({
            "user_id": user,
            "username": pick(&f, &["username", "user_name", "name"]).unwrap_or("unknown"),
            "text": text,
            "post_id": pick(&f, &["post_id"]),
            "timestamp": pick(&f, &["timestamp"]),
            "trigger_word": pick(&f, &["trigger_word", "triggerWord"]),
            "channel_id": pick(&f, &["channel_id"]),
            "channel_name": pick(&f, &["channel_name"]),
        });
        let _ = tx.lock().unwrap().send(ev);
        Response::empty(204)
    })
}

/// One webhook event → Inbound. `chat` is the user id replies go to.
fn inbound_of(channel: &str, ev: &Value, chat: &str) -> Option<Inbound> {
    let user = ev["user_id"].as_str()?;
    let mut text = ev["text"].as_str().unwrap_or("").to_string();
    if let Some(tw) = ev["trigger_word"].as_str().filter(|t| !t.is_empty()) {
        if let Some(rest) = text.strip_prefix(tw) {
            text = rest.trim().to_string();
        }
    }
    if text.trim().is_empty() {
        return None;
    }
    let ts_raw = ev["timestamp"].as_str().and_then(|t| t.parse::<i64>().ok()).unwrap_or(0);
    // Synology sends milliseconds.
    let ts = if ts_raw > 100_000_000_000 { ts_raw / 1000 } else { ts_raw };
    let message_id = ev["post_id"].as_str().map(str::to_string).unwrap_or_else(|| format!("{user}:{ts_raw}:{}", crypto::hex(&crypto::sha256(text.as_bytes())[..6])));
    Some(Inbound {
        channel: channel.to_string(),
        chat: chat.to_string(),
        chat_type: ChatType::Direct,
        chat_name: ev["channel_name"].as_str().unwrap_or("").to_string(),
        sender: user.to_string(),
        sender_name: ev["username"].as_str().unwrap_or("").to_string(),
        text,
        message_id,
        ts,
        ..Default::default()
    })
}

/// Replace the incoming URL's token (and the whole query) in error text.
fn scrub(s: &str, url: &str) -> String {
    let mut out = s.to_string();
    if let Some((_, q)) = url.split_once('?') {
        out = out.replace(q, "***");
        for (k, v) in seagent_net::parse_query(q) {
            if k == "token" && !v.is_empty() {
                out = out.replace(&v, "***").replace(&seagent_net::urlencode(&v), "***");
            }
        }
    }
    out
}

fn with_options(text: &str, rows: &[Vec<crate::Button>]) -> String {
    let buttons: Vec<&crate::Button> = rows.iter().flatten().collect();
    if buttons.is_empty() {
        return text.to_string();
    }
    let mut s = text.trim_end().to_string();
    s.push('\n');
    for (i, b) in buttons.iter().enumerate() {
        match &b.url {
            // Synology's link syntax.
            Some(u) => s.push_str(&format!("\n<{u}|{}>", b.label)),
            None => s.push_str(&format!("\n{}. {}", i + 1, b.label)),
        }
    }
    s
}

impl SynologyChat {
    pub fn start(c: Config) -> Result<Self, String> {
        if c.token.trim().is_empty() {
            return Err(format!("channel {}: synology-chat token is empty", c.id));
        }
        seagent_net::Url::parse(c.incoming_url.trim()).map_err(|_| format!("channel {}: incoming_url is not a URL", c.id))?;
        if let Some(w) = &c.webhook_url {
            let u = seagent_net::Url::parse(w).map_err(|e| format!("channel {}: webhook_url: {e}", c.id))?;
            if u.scheme != "https" && u.host != "127.0.0.1" && u.host != "localhost" {
                return Err(format!("channel {}: webhook_url must be https", c.id));
            }
        }
        let (tx, rx) = std::sync::mpsc::channel::<Value>();
        let media: Store = Arc::new(Mutex::new(HashMap::new()));
        let path = if c.path.starts_with('/') { c.path.clone() } else { format!("/{}", c.path) };
        let h = handler(c.token.trim().to_string(), path, c.rate_limit_per_minute, tx, media.clone());
        let server = seagent_net::httpd::Server::bind(&c.listen, seagent_net::httpd::Opts::default(), h).map_err(|e| format!("channel {}: cannot listen on {}: {e}", c.id, c.listen))?;
        Ok(SynologyChat {
            id: c.id,
            incoming_url: c.incoming_url.trim().to_string(),
            webhook_url: c.webhook_url,
            name_matching: c.name_matching,
            http: Http::new(Duration::from_secs(30)),
            poll_timeout: c.poll_timeout_secs,
            min_interval: Duration::from_millis(500),
            last_send: Mutex::new(None),
            rx: Mutex::new(rx),
            server: Mutex::new(Some(server)),
            media,
            users: Mutex::new(None),
        })
    }

    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.server.lock().unwrap().as_ref().map(|s| s.local_addr())
    }

    fn net_err(&self, e: ChannelError) -> ChannelError {
        ChannelError::new(e.kind, scrub(&e.message, &self.incoming_url))
    }

    fn user_list_url(&self) -> String {
        let u = &self.incoming_url;
        match u.find("method=") {
            Some(i) => {
                let end = u[i..].find('&').map(|j| i + j).unwrap_or(u.len());
                format!("{}method=user_list{}", &u[..i], &u[end..])
            }
            None => format!("{u}{}method=user_list", if u.contains('?') { "&" } else { "?" }),
        }
    }

    /// Chat API users (cached); stale data on failure.
    fn users(&self) -> Vec<Value> {
        if let Some((u, at)) = self.users.lock().unwrap().as_ref() {
            if at.elapsed() < USERS_TTL {
                return u.clone();
            }
        }
        let fresh = self.http.json("GET", &self.user_list_url(), Payload::None).ok().filter(|v| v["success"] == true).map(|v| v["data"]["users"].as_array().cloned().unwrap_or_default());
        let mut g = self.users.lock().unwrap();
        match fresh {
            Some(u) => {
                *g = Some((u.clone(), Instant::now()));
                u
            }
            None => g.as_ref().map(|(u, _)| u.clone()).unwrap_or_default(),
        }
    }

    /// Webhook username → Chat API user id (nickname first, then username).
    fn resolve_user(&self, username: &str) -> Option<String> {
        let users = self.users();
        let l = username.to_lowercase();
        let by = |field: &str| users.iter().find(|u| u[field].as_str().is_some_and(|n| n.to_lowercase() == l)).and_then(|u| u["user_id"].as_i64()).map(|i| i.to_string());
        by("nickname").or_else(|| by("username"))
    }

    fn wait_slot(&self) {
        let mut last = self.last_send.lock().unwrap();
        if let Some(t) = *last {
            let gap = t.elapsed();
            if gap < self.min_interval {
                std::thread::sleep(self.min_interval - gap);
            }
        }
        *last = Some(Instant::now());
    }

    /// One post to the incoming URL; returns the post id when Synology reports it.
    fn post(&self, chat: &str, payload: Value) -> Result<Option<String>, ChannelError> {
        let mut payload = payload;
        let uid = chat.trim().parse::<u64>().ok();
        if let Some(u) = uid {
            payload["user_ids"] = json!([u]);
        }
        let body = format!("payload={}", seagent_net::urlencode(&payload.to_string()));
        self.wait_slot();
        let r = self.http.call("POST", &self.incoming_url, &[], Payload::Raw("application/x-www-form-urlencoded", body.as_bytes())).map_err(|e| self.net_err(e))?;
        let v: Option<Value> = serde_json::from_str(&r.body).ok();
        if r.status != 200 {
            return Err(self.net_err(classify(r.status, r.retry_after, "synology-chat send", &r.body)));
        }
        let v = v.unwrap_or(Value::Null);
        if v["success"] == false {
            let code = v["error"]["code"].as_i64().unwrap_or(0);
            let msg = format!("synology-chat rejected the post (code {code}): {}", scrub(&v["error"].to_string(), &self.incoming_url));
            // 404/117-style "no such user / channel" and auth failures.
            let kind = match code {
                105 | 401 | 403 => K::Auth,
                404 | 117 | 120 => K::NotFound,
                411 | 429 => K::RateLimited { retry_after: None },
                _ => K::Protocol,
            };
            return Err(ChannelError::new(kind, msg));
        }
        Ok(uid.and_then(|u| {
            let p = &v["data"]["succ"]["user_id_post_map"][u.to_string()];
            p.as_u64().map(|n| n.to_string()).or_else(|| p.as_str().map(str::to_string))
        }))
    }

    /// Host a local file behind a random token; returns its public URL.
    fn host(&self, m: &Media) -> Result<String, ChannelError> {
        let base = self.webhook_url.as_deref().ok_or_else(|| ChannelError::new(K::Unsupported, "synology-chat: local attachments need webhook_url (public URL of the listener)"))?;
        let path = m.path.as_deref().unwrap_or("");
        let bytes = std::fs::read(path).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {path}: {e}")))?;
        if bytes.len() > MEDIA_MAX_BYTES {
            return Err(ChannelError::new(K::Fatal, format!("attachment larger than {MEDIA_MAX_BYTES} bytes")));
        }
        let name = if m.name.is_empty() { std::path::Path::new(path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into()) } else { m.name.clone() };
        let tok = crypto::random_token(24);
        let mut store = self.media.lock().unwrap();
        store.retain(|_, h| h.expires > Instant::now());
        while store.len() >= MEDIA_MAX_ENTRIES {
            let oldest = store.iter().min_by_key(|(_, h)| h.expires).map(|(k, _)| k.clone()).unwrap();
            store.remove(&oldest);
        }
        let mime = if m.mime.is_empty() { "application/octet-stream".into() } else { m.mime.clone() };
        store.insert(tok.clone(), Hosted { bytes, mime, name, expires: Instant::now() + MEDIA_TTL });
        Ok(format!("{base}{}seagent_media={tok}", if base.contains('?') { "&" } else { "?" }))
    }
}

impl Channel for SynologyChat {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps { chat_types: vec![ChatType::Direct], media: true, max_len: MAX_MESSAGE, len_unit: LenUnit::Chars, markup: Markup::Plain, streaming: Streaming::None, ..Caps::default() }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let got: Vec<Value> = {
            let rx = self.rx.lock().unwrap();
            let until = Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
            let mut got = Vec::new();
            while got.is_empty() && !cancel.is_cancelled() && Instant::now() < until {
                if let Ok(v) = rx.recv_timeout(Duration::from_millis(50)) {
                    got.push(v);
                    got.extend(rx.try_iter());
                }
            }
            got
        };
        Ok(got
            .iter()
            .filter_map(|ev| {
                let user = ev["user_id"].as_str()?;
                let chat = if self.name_matching { ev["username"].as_str().and_then(|n| self.resolve_user(n)).unwrap_or_else(|| user.to_string()) } else { user.to_string() };
                inbound_of(&self.id, ev, &chat)
            })
            .collect())
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let text = match out.format {
            TextFormat::Markdown => markup::convert(&out.text, Markup::Plain),
            TextFormat::Plain => out.text.clone(),
        };
        let text = with_options(&text, &out.buttons);
        let mut sent = Sent::default();
        let pieces = chunk::split(&text, MAX_MESSAGE, LenUnit::Chars);
        let mut caption_used = false;
        for m in &out.media {
            let url = match (&m.path, &m.url) {
                (Some(_), _) => self.host(m)?,
                (None, Some(u)) => u.clone(),
                _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
            };
            let mut p = json!({ "file_url": url });
            // A single short text rides along with the first file.
            if !caption_used && pieces.len() == 1 {
                p["text"] = json!(pieces[0]);
                caption_used = true;
            } else if let Some(c) = &m.caption {
                p["text"] = json!(c);
            }
            sent.ids.extend(self.post(&out.chat, p)?);
        }
        if !caption_used {
            for piece in pieces {
                sent.ids.extend(self.post(&out.chat, json!({ "text": piece }))?);
            }
        }
        Ok(sent)
    }

    fn stop(&self) {
        self.server.lock().unwrap().take();
    }
}

fn d_poll() -> u64 {
    25
}

fn d_rate() -> u32 {
    30
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    token: String,
    incoming_url: String,
    listen: String,
    #[serde(default)]
    webhook_path: Option<String>,
    #[serde(default)]
    webhook_url: Option<String>,
    #[serde(default = "d_rate")]
    rate_limit_per_minute: u32,
    #[serde(default)]
    name_matching: bool,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let token = ctx.secret("token", &st.token)?;
    let incoming_url = ctx.secret("incoming_url", &st.incoming_url)?;
    let c = SynologyChat::start(Config {
        id: ctx.name.to_string(),
        token,
        incoming_url,
        listen: st.listen,
        path: st.webhook_path.unwrap_or_else(|| DEFAULT_PATH.into()),
        webhook_url: st.webhook_url,
        rate_limit_per_minute: st.rate_limit_per_minute,
        name_matching: st.name_matching,
        poll_timeout_secs: st.poll_timeout_secs,
    })?;
    Ok(Arc::new(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};

    const TOKEN: &str = "outgoing-token-123";

    fn syno(incoming: &str, webhook_url: Option<&str>, rate: u32, names: bool) -> SynologyChat {
        let mut s = SynologyChat::start(Config {
            id: "syno".into(),
            token: TOKEN.into(),
            incoming_url: incoming.into(),
            listen: "127.0.0.1:0".into(),
            path: DEFAULT_PATH.into(),
            webhook_url: webhook_url.map(str::to_string),
            rate_limit_per_minute: rate,
            name_matching: names,
            poll_timeout_secs: 1,
        })
        .unwrap();
        s.min_interval = Duration::from_millis(40);
        s
    }

    fn hit(s: &SynologyChat, method: &str, path: &str, ctype: &str, body: &str, headers: &[(&str, &str)]) -> (u16, Vec<u8>) {
        let a = crate::http::agent(Duration::from_secs(5));
        let url = format!("http://{}{path}", s.local_addr().unwrap());
        let r = if method == "GET" {
            let mut r = a.get(&url);
            for (k, v) in headers {
                r = r.header(*k, *v);
            }
            r.call()
        } else {
            let mut r = a.post(&url).header("content-type", ctype);
            for (k, v) in headers {
                r = r.header(*k, *v);
            }
            r.send(body.as_bytes())
        };
        match r {
            Ok(mut r) => (r.status().as_u16(), r.body_mut().read_to_vec().unwrap_or_default()),
            Err(_) => (0, vec![]),
        }
    }

    fn form(s: &SynologyChat, body: &str) -> u16 {
        hit(s, "POST", DEFAULT_PATH, "application/x-www-form-urlencoded", body, &[]).0
    }

    fn incoming(srv: &FakeServer) -> String {
        format!("{}/webapi/entry.cgi?api=SYNO.Chat.External&method=chatbot&version=2&token=%22INCOMING-SECRET%22", srv.url)
    }

    #[test]
    fn webhook_token_checks_form_json_header_and_lockout() {
        let s = syno("http://127.0.0.1:1/x?method=chatbot", None, 100, false);
        assert_eq!(form(&s, "user_id=5&username=amy&text=hi"), 401, "missing token");
        assert_eq!(form(&s, "token=wrong&user_id=5&text=hi"), 401, "bad token");
        assert_eq!(form(&s, &format!("token={TOKEN}&username=amy")), 400, "missing fields after auth");
        assert_eq!(form(&s, &format!("token={TOKEN}&user_id=5&username=amy&post_id=77&timestamp=1700000000123&text=hello")), 204);
        let j = json!({"token": TOKEN, "user_id": 6, "username": "bo", "post_id": "78", "text": "via json"}).to_string();
        assert_eq!(hit(&s, "POST", DEFAULT_PATH, "application/json", &j, &[]).0, 204);
        let j = json!({"user_id": "7", "text": "header token", "post_id": "79"}).to_string();
        assert_eq!(hit(&s, "POST", DEFAULT_PATH, "application/json", &j, &[("x-synology-token", TOKEN)]).0, 204);
        assert_eq!(hit(&s, "POST", DEFAULT_PATH, "text/plain", &j, &[("authorization", &format!("Bearer {TOKEN}"))]).0, 204, "JSON sniffed without content-type");
        assert_eq!(hit(&s, "POST", &format!("{DEFAULT_PATH}?token={TOKEN}&user_id=8&text=q"), "application/x-www-form-urlencoded", "", &[]).0, 204, "query fields");
        assert_eq!(hit(&s, "POST", "/other", "application/x-www-form-urlencoded", "", &[]).0, 404);
        assert_eq!(hit(&s, "POST", DEFAULT_PATH, "application/json", "{nope", &[]).0, 400);
        let mut got = Vec::new();
        while got.len() < 5 {
            let b = s.poll(&Cancel::new()).unwrap();
            assert!(!b.is_empty());
            got.extend(b);
        }
        assert_eq!((got[0].chat.as_str(), got[0].sender_name.as_str(), got[0].message_id.as_str(), got[0].ts, got[0].chat_type), ("5", "amy", "77", 1700000000, ChatType::Direct));
        assert_eq!((got[1].chat.as_str(), got[1].text.as_str()), ("6", "via json"));
        assert_eq!(got[4].text, "q");
        assert!(!got[4].message_id.is_empty(), "synthesised id without post_id");
        // Wrong-token lockout per peer.
        for _ in 0..BAD_TOKEN_BUDGET {
            form(&s, "token=bad&user_id=1&text=x");
        }
        assert_eq!(form(&s, &format!("token={TOKEN}&user_id=5&text=hi")), 429, "locked out even with the right token");
    }

    #[test]
    fn per_user_rate_limit_and_trigger_word() {
        let s = syno("http://127.0.0.1:1/x?method=chatbot", None, 2, false);
        assert_eq!(form(&s, &format!("token={TOKEN}&user_id=5&text=%21seagent+do+it&trigger_word=%21seagent&post_id=1")), 204);
        assert_eq!(form(&s, &format!("token={TOKEN}&user_id=5&text=two&post_id=2")), 204);
        assert_eq!(form(&s, &format!("token={TOKEN}&user_id=5&text=three&post_id=3")), 429);
        assert_eq!(form(&s, &format!("token={TOKEN}&user_id=6&text=other+user&post_id=4")), 204);
        assert_eq!(form(&s, &format!("token={TOKEN}&user_id=6&text=%21seagent&trigger_word=%21seagent&post_id=5")), 204);
        let mut got = Vec::new();
        for _ in 0..3 {
            got.extend(s.poll(&Cancel::new()).unwrap());
            if got.len() >= 3 {
                break;
            }
        }
        assert_eq!(got.iter().map(|m| m.text.as_str()).collect::<Vec<_>>(), ["do it", "two", "other user"], "bare trigger word dropped");
    }

    #[test]
    fn name_matching_resolves_chat_user_id_via_user_list() {
        let srv = FakeServer::start(|req, _| {
            assert!(req.path.contains("method=user_list") && !req.path.contains("method=chatbot"), "{}", req.path);
            (200, vec![], json!({"success": true, "data": {"users": [{"user_id": 4, "username": "amy.w", "nickname": "amy"}, {"user_id": 9, "username": "bo", "nickname": ""}]}}).to_string())
        });
        let s = syno(&incoming(&srv), None, 100, true);
        assert_eq!(form(&s, &format!("token={TOKEN}&user_id=55&username=AMY&text=hi&post_id=1")), 204);
        assert_eq!(form(&s, &format!("token={TOKEN}&user_id=56&username=bo&text=hi&post_id=2")), 204);
        assert_eq!(form(&s, &format!("token={TOKEN}&user_id=57&username=ghost&text=hi&post_id=3")), 204);
        let mut got = Vec::new();
        while got.len() < 3 {
            got.extend(s.poll(&Cancel::new()).unwrap());
        }
        let chats: Vec<(&str, &str)> = got.iter().map(|m| (m.chat.as_str(), m.sender.as_str())).collect();
        assert_eq!(chats, [("4", "55"), ("9", "56"), ("57", "57")], "nickname, username, fallback");
        assert_eq!(srv.requests().len(), 1, "user_list cached");
    }

    #[test]
    fn send_posts_payload_form_with_user_ids_chunks_files_and_buttons() {
        let srv = FakeServer::start(|_, n| (200, vec![], json!({"success": true, "data": {"succ": {"user_id_post_map": {"4": 1000 + n}}}}).to_string()));
        let s = syno(&incoming(&srv), None, 100, false);
        let out = Outbound {
            format: TextFormat::Markdown,
            buttons: vec![vec![crate::Button { label: "允許".into(), data: "appr:1".into(), url: None }, crate::Button { label: "docs".into(), data: String::new(), url: Some("https://e.com".into()) }]],
            ..Outbound::text("4", "**hi**")
        };
        assert_eq!(s.send(&out).unwrap().ids, vec!["1000"]);
        let r = &srv.requests()[0];
        assert!(r.path.starts_with("/webapi/entry.cgi?api=SYNO.Chat.External&method=chatbot"));
        assert_eq!(r.header("content-type"), Some("application/x-www-form-urlencoded"));
        let q = seagent_net::parse_query(&r.body);
        assert_eq!(q[0].0, "payload");
        let p: Value = serde_json::from_str(&q[0].1).unwrap();
        assert_eq!(p, json!({"text": "hi\n\n1. 允許\n<https://e.com|docs>", "user_ids": [4]}));
        let start = Instant::now();
        let long = "word ".repeat(1000);
        assert_eq!(s.send(&Outbound::text("4", &long)).unwrap().ids.len(), 3);
        assert!(start.elapsed() >= Duration::from_millis(80), "min interval between posts");
        for r in &srv.requests()[1..4] {
            let p: Value = serde_json::from_str(&seagent_net::parse_query(&r.body)[0].1).unwrap();
            assert!(p["text"].as_str().unwrap().chars().count() <= MAX_MESSAGE);
        }
        let img = Media { url: Some("https://e.com/a.png".into()), ..Default::default() };
        s.send(&Outbound { media: vec![img], ..Outbound::text("channel-hook", "caption") }).unwrap();
        let p: Value = serde_json::from_str(&seagent_net::parse_query(&srv.requests()[4].body)[0].1).unwrap();
        assert_eq!(p, json!({"file_url": "https://e.com/a.png", "text": "caption"}), "non-numeric chat: no user_ids (incoming webhook)");
        assert_eq!(srv.requests().len(), 5);
        assert!(s.edit("4", "1", "x").is_err() && s.typing("4", None).is_err());
    }

    #[test]
    fn local_files_are_hosted_behind_a_token_for_file_url() {
        let srv = FakeServer::start(|_, _| (200, vec![], json!({"success": true}).to_string()));
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let mut s = SynologyChat::start(Config {
            id: "syno".into(),
            token: TOKEN.into(),
            incoming_url: incoming(&srv),
            listen: format!("127.0.0.1:{port}"),
            path: DEFAULT_PATH.into(),
            webhook_url: Some(format!("http://127.0.0.1:{port}{DEFAULT_PATH}")),
            rate_limit_per_minute: 30,
            name_matching: false,
            poll_timeout_secs: 1,
        })
        .unwrap();
        s.min_interval = Duration::ZERO;
        let f = temp_dir("syno").join("chart.png");
        std::fs::write(&f, b"PNGDATA").unwrap();
        let m = Media { path: Some(f.display().to_string()), mime: "image/png".into(), ..Default::default() };
        s.send(&Outbound { media: vec![m], ..Outbound::text("4", "") }).unwrap();
        let p: Value = serde_json::from_str(&seagent_net::parse_query(&srv.requests()[0].body)[0].1).unwrap();
        let url = p["file_url"].as_str().unwrap().to_string();
        assert!(url.starts_with(&format!("http://127.0.0.1:{port}{DEFAULT_PATH}?seagent_media=")), "{url}");
        assert!(p.get("text").is_none());
        let path = url.split_once(&port.to_string()).unwrap().1;
        assert_eq!(hit(&s, "GET", path, "", "", &[]), (200, b"PNGDATA".to_vec()));
        assert_eq!(hit(&s, "GET", &format!("{DEFAULT_PATH}?seagent_media=guess"), "", "", &[]).0, 404);
        let no_public = syno(&incoming(&srv), None, 30, false);
        let m = Media { path: Some(f.display().to_string()), ..Default::default() };
        assert_eq!(no_public.send(&Outbound { media: vec![m], ..Outbound::text("4", "") }).unwrap_err().kind, K::Unsupported);
    }

    #[test]
    fn error_mapping_without_leaking_the_incoming_token() {
        for (status, body, kind) in [
            (401, String::new(), K::Auth),
            (404, String::new(), K::NotFound),
            (502, "bad gateway".to_string(), K::Network),
            (429, String::new(), K::RateLimited { retry_after: Some(Duration::from_secs(7)) }),
            (200, json!({"success": false, "error": {"code": 117, "errors": "user not found"}}).to_string(), K::NotFound),
            (200, json!({"success": false, "error": {"code": 999}}).to_string(), K::Protocol),
        ] {
            let b = body.clone();
            let srv = FakeServer::start(move |_, _| (status, vec![("Retry-After".into(), "7".into())], b.clone()));
            let s = syno(&incoming(&srv), None, 30, false);
            let e = s.send(&Outbound::text("4", "x")).unwrap_err();
            assert_eq!(e.kind, kind, "{status} {body}");
            assert!(!e.message.contains("INCOMING-SECRET"), "{}", e.message);
            assert_eq!(srv.requests().len(), 1, "never re-posted (no duplicate deliveries)");
        }
        let s = syno("http://127.0.0.1:1/webapi/entry.cgi?method=chatbot&token=INCOMING-SECRET", None, 30, false);
        let e = s.send(&Outbound::text("4", "x")).unwrap_err();
        assert_eq!(e.kind, K::Network);
        assert!(!e.message.contains("INCOMING-SECRET"), "{}", e.message);
        assert_eq!(scrub("GET http://h/x?method=a&token=abc failed", "http://h/x?method=a&token=abc"), "GET http://h/x?*** failed");
    }

    #[test]
    fn cancel_returns_promptly_and_build_validates() {
        let s = syno("http://127.0.0.1:1/x?method=chatbot", None, 30, false);
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.cancel();
        });
        let start = Instant::now();
        assert!(s.poll(&c).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_millis(600));
        s.stop();
        assert!(s.local_addr().is_none());
        let d = temp_dir("syno");
        let secrets: crate::config::Secrets = Arc::new(|v: &str| v.replace("{{secret:SY}}", "tok").replace("{{secret:SYURL}}", "https://nas.example/webapi/entry.cgi?method=chatbot&token=x"));
        let ctx = crate::config::Ctx { name: "syno", state_dir: &d, secrets: &secrets };
        let ok = json!({"token": "{{secret:SY}}", "incoming_url": "{{secret:SYURL}}", "listen": "127.0.0.1:0"});
        assert_eq!(build(&ctx, ok.as_object().unwrap()).unwrap().id(), "syno");
        let typo = json!({"token": "t", "incoming_url": "https://nas/x", "listen": "127.0.0.1:0", "dm_polcy": "open"});
        assert!(build(&ctx, typo.as_object().unwrap()).err().unwrap().contains("dm_polcy"));
        let insecure = json!({"token": "t", "incoming_url": "https://nas/x", "listen": "127.0.0.1:0", "webhook_url": "http://public.example/hook"});
        assert!(build(&ctx, insecure.as_object().unwrap()).err().unwrap().contains("https"));
        let empty = json!({"token": " ", "incoming_url": "https://nas/x", "listen": "127.0.0.1:0"});
        assert!(build(&ctx, empty.as_object().unwrap()).is_err());
        assert_eq!(s.user_list_url(), "http://127.0.0.1:1/x?method=user_list");
    }
}
