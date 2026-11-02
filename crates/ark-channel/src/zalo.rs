//! Zalo Official Account Bot API (ported from OpenClaw `extensions/zalo`, MIT).
//!
//! Receive: long-poll `getUpdates` (one update per call; Zalo answers
//! `error_code` 408 when nothing arrived), or webhook mode (`setWebhook` with a
//! `secret_token` that Zalo echoes in `X-Bot-Api-Secret-Token`). Before polling
//! starts, an existing webhook is cleared (`getWebhookInfo` → `deleteWebhook`)
//! exactly as upstream does; `stop()` deletes the webhook in webhook mode.
//! Events: `message.text.received`, `message.image.received` (`photo_url` +
//! caption), `message.sticker.received`, `message.unsupported.received` (kept
//! only when it carries text). DMs (`PRIVATE`) and groups (`GROUP`).
//! Send: `sendMessage` (2000 UTF-16 units per piece), `sendPhoto` by URL with a
//! caption, `sendChatAction` typing. The Bot API has no file upload, so in
//! webhook mode a local file is served once from `<webhook path>/media/<id>?token=…`
//! for two minutes and handed to `sendPhoto` by URL (upstream's hosted media).
//! There are no buttons, edits, deletes, reactions or reply threading in the
//! Bot API; buttons degrade to numbered text options.

use crate::http::{agent, post_cancellable};
use crate::{markup, sleep_cancellable, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, Sent, Streaming};
use ark_core::Cancel;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_BASE: &str = "https://bot-api.zaloplatforms.com";
/// Zalo counts message length in UTF-16 units (upstream `truncateUtf16Safe(text, 2000)`).
pub const MAX_MESSAGE: usize = 2000;
const MEDIA_TTL: Duration = Duration::from_secs(120);

pub struct Zalo {
    id: String,
    token: String,
    base: String,
    poll_timeout: u64,
    agent: ureq::Agent,
    pub retry_base: Duration,
    pub max_retries: u32,
    pub max_wait: Duration,
    /// (bot id, account name) from getMe.
    me: Mutex<Option<(String, String)>>,
    webhook_cleared: std::sync::atomic::AtomicBool,
    hook: Option<Hook>,
}

struct Hook {
    _server: ark_net::httpd::Server,
    rx: Mutex<std::sync::mpsc::Receiver<Value>>,
    /// Public origin + webhook path, for hosted media URLs.
    public_base: String,
    media: Arc<Mutex<HashMap<String, Hosted>>>,
}

struct Hosted {
    token: String,
    mime: String,
    data: Vec<u8>,
    expires: Instant,
}

impl Zalo {
    pub fn new(id: &str, token: &str, base: Option<&str>, poll_timeout_secs: u64) -> Result<Self, String> {
        if token.trim().is_empty() {
            return Err(format!("channel {id}: zalo token is empty"));
        }
        Ok(Zalo {
            id: id.to_string(),
            token: token.trim().to_string(),
            base: base.unwrap_or(DEFAULT_BASE).trim_end_matches('/').to_string(),
            poll_timeout: poll_timeout_secs,
            agent: agent(Duration::from_secs(poll_timeout_secs + 15)),
            retry_base: Duration::from_millis(500),
            max_retries: 4,
            max_wait: Duration::from_secs(60),
            me: Mutex::new(None),
            webhook_cleared: std::sync::atomic::AtomicBool::new(false),
            hook: None,
        })
    }

    /// Webhook mode: listen on `listen`, register `public_url` (HTTPS) with Zalo.
    pub fn with_webhook(mut self, listen: &str, public_url: &str, secret: &str) -> Result<Self, String> {
        if !(8..=256).contains(&secret.len()) {
            return Err(format!("channel {}: webhook_secret must be 8-256 characters", self.id));
        }
        if !public_url.starts_with("https://") {
            return Err(format!("channel {}: zalo webhook_url must use HTTPS", self.id));
        }
        let u = ark_net::Url::parse(public_url).map_err(|e| format!("channel {}: webhook_url: {e}", self.id))?;
        let path = u.path.split('?').next().unwrap_or("/").trim_end_matches('/').to_string();
        let path = if path.is_empty() { "/".to_string() } else { path };
        let media_prefix = if path == "/" { "/media/".to_string() } else { format!("{path}/media/") };
        let (tx, rx) = std::sync::mpsc::channel::<Value>();
        let tx = Mutex::new(tx);
        let want = secret.to_string();
        let media: Arc<Mutex<HashMap<String, Hosted>>> = Arc::default();
        let store = media.clone();
        let hook_path = path.clone();
        let handler: ark_net::httpd::Handler = Arc::new(move |r: ark_net::httpd::Request| {
            use ark_net::httpd::Response;
            if (r.method == "GET" || r.method == "HEAD") && r.path.starts_with(&media_prefix) {
                return serve_media(&store, &r, &r.path[media_prefix.len()..]);
            }
            if r.path != hook_path {
                return Response::text(404, "Not Found");
            }
            if r.method != "POST" {
                return Response::text(405, "Method Not Allowed");
            }
            // Secret before anything else (upstream keeps 401-before-415 ordering).
            let ok = r.header("x-bot-api-secret-token").is_some_and(|t| ark_net::crypto::ct_eq(t.as_bytes(), want.as_bytes()));
            if !ok {
                return Response::text(401, "Unauthorized");
            }
            match serde_json::from_slice::<Value>(&r.body) {
                Ok(v) => {
                    // Some deliveries wrap the update in the {ok, result} envelope.
                    let v = if v["ok"] == true && v["result"].is_object() { v["result"].clone() } else { v };
                    let _ = tx.lock().unwrap().send(v);
                    Response::text(200, "ok")
                }
                Err(_) => Response::text(400, "Bad Request"),
            }
        });
        let server = ark_net::httpd::Server::bind(listen, ark_net::httpd::Opts::default(), handler).map_err(|e| format!("channel {}: cannot listen on {listen}: {e}", self.id))?;
        self.call("setWebhook", &json!({"url": public_url, "secret_token": secret}), &Cancel::new()).map_err(|e| format!("channel {}: setWebhook failed: {}", self.id, e.message))?;
        let origin = format!("{}://{}", u.scheme, u.host_header());
        let public_base = if path == "/" { origin } else { format!("{origin}{path}") };
        self.hook = Some(Hook { _server: server, rx: Mutex::new(rx), public_base, media });
        Ok(self)
    }

    fn url(&self, method: &str) -> String {
        format!("{}/bot{}/{method}", self.base, self.token)
    }

    /// One Bot API call with retries. `Ok(None)` = cancelled.
    fn call(&self, method: &str, body: &Value, cancel: &Cancel) -> Result<Option<Value>, ChannelError> {
        let url = self.url(method);
        let bytes = serde_json::to_vec(body).expect("json");
        let mut attempt = 0;
        loop {
            let err = match post_cancellable(&self.agent, &url, &[], bytes.clone(), cancel)? {
                None => return Ok(None),
                Some(r) => match zalo_result(method, r.status, r.retry_after, &r.body) {
                    Ok(v) => return Ok(Some(v)),
                    Err(e) if e.is_retryable() => e,
                    Err(e) => return Err(e),
                },
            };
            if attempt >= self.max_retries {
                return Err(err);
            }
            let wait = match err.kind {
                K::RateLimited { retry_after: Some(d) } if d > self.max_wait => return Err(err),
                K::RateLimited { retry_after: Some(d) } => d,
                _ => self.retry_base * 2u32.pow(attempt),
            };
            if !sleep_cancellable(wait, cancel) {
                return Ok(None);
            }
            attempt += 1;
        }
    }

    fn me(&self) -> Option<(String, String)> {
        if let Some(m) = self.me.lock().unwrap().clone() {
            return Some(m);
        }
        let v = self.call("getMe", &json!({}), &Cancel::new()).ok()??;
        let m = (id_str(&v["id"])?, v["account_name"].as_str().or_else(|| v["display_name"].as_str()).unwrap_or("").to_string());
        *self.me.lock().unwrap() = Some(m.clone());
        Some(m)
    }

    /// Polling mode: a registered webhook would swallow updates, so clear it once.
    fn clear_webhook_once(&self, cancel: &Cancel) -> Result<(), ChannelError> {
        if self.webhook_cleared.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        match self.call("getWebhookInfo", &json!({}), cancel) {
            Ok(Some(info)) => {
                if info["url"].as_str().is_some_and(|u| !u.trim().is_empty()) {
                    self.call("deleteWebhook", &json!({}), cancel)?;
                }
            }
            Ok(None) => return Ok(()),
            // Some environments do not expose webhook inspection for polling bots.
            Err(e) if e.kind == K::NotFound => {}
            Err(e) => return Err(e),
        }
        self.webhook_cleared.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn host_media(&self, path: &str, mime: &str) -> Result<String, ChannelError> {
        let h = self.hook.as_ref().ok_or_else(|| ChannelError::new(K::Unsupported, "zalo can only send local files in webhook mode (they are served from the webhook URL); pass a public url instead"))?;
        let data = std::fs::read(path).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {path}: {e}")))?;
        let id = ark_net::crypto::hex(&ark_net::crypto::random_bytes(12));
        let token = ark_net::crypto::hex(&ark_net::crypto::random_bytes(16));
        let mut m = h.media.lock().unwrap();
        let now = Instant::now();
        m.retain(|_, v| v.expires > now);
        m.insert(id.clone(), Hosted { token: token.clone(), mime: if mime.is_empty() { guess_mime(path).into() } else { mime.into() }, data, expires: now + MEDIA_TTL });
        Ok(format!("{}/media/{id}?token={token}", h.public_base))
    }

    fn send_photo(&self, chat: &str, m: &Media, caption: Option<&str>) -> Result<String, ChannelError> {
        let url = match (&m.path, &m.url) {
            (Some(p), _) => self.host_media(p, &m.mime)?,
            (None, Some(u)) if u.starts_with("http://") || u.starts_with("https://") => u.clone(),
            _ => return Err(ChannelError::new(K::Fatal, "zalo photo needs a local path or an http(s) url")),
        };
        let mut body = json!({"chat_id": chat, "photo": url});
        if let Some(c) = caption.or(m.caption.as_deref()).filter(|c| !c.is_empty()) {
            body["caption"] = json!(truncate_utf16(c, MAX_MESSAGE));
        }
        let r = self.call("sendPhoto", &body, &Cancel::new())?.unwrap_or_default();
        Ok(id_str(&r["message_id"]).unwrap_or_default())
    }

    fn send_text(&self, chat: &str, text: &str, sent: &mut Sent) -> Result<(), ChannelError> {
        for piece in crate::chunk::split(text, MAX_MESSAGE, LenUnit::Utf16) {
            let r = self.call("sendMessage", &json!({"chat_id": chat, "text": piece}), &Cancel::new())?.unwrap_or_default();
            sent.ids.extend(id_str(&r["message_id"]));
        }
        Ok(())
    }
}

fn serve_media(store: &Mutex<HashMap<String, Hosted>>, r: &ark_net::httpd::Request, id: &str) -> ark_net::httpd::Response {
    use ark_net::httpd::Response;
    let mut m = store.lock().unwrap();
    let now = Instant::now();
    m.retain(|_, v| v.expires > now);
    let Some(entry) = m.get(id) else { return Response::text(404, "Not Found") };
    if !r.query("token").is_some_and(|t| ark_net::crypto::ct_eq(t.as_bytes(), entry.token.as_bytes())) {
        return Response::text(401, "Unauthorized");
    }
    let resp = |data: Vec<u8>, mime: &str| Response::new(200, mime, data).with_header("cache-control", "no-store").with_header("x-content-type-options", "nosniff");
    if r.method == "HEAD" {
        return resp(vec![], &entry.mime);
    }
    // One fetch per URL, like upstream.
    let e = m.remove(id).unwrap();
    resp(e.data, &e.mime)
}

fn guess_mime(path: &str) -> &'static str {
    let p = path.to_ascii_lowercase();
    if p.ends_with(".png") {
        "image/png"
    } else if p.ends_with(".gif") {
        "image/gif"
    } else if p.ends_with(".webp") {
        "image/webp"
    } else {
        "image/jpeg"
    }
}

fn truncate_utf16(s: &str, max: usize) -> String {
    let mut n = 0;
    s.chars().take_while(|c| {
        n += c.len_utf16();
        n <= max
    }).collect()
}

/// Zalo's `{ok, result, error_code, description}` envelope → result or a classified error.
fn zalo_result(method: &str, status: u16, retry_after: Option<Duration>, body: &str) -> Result<Value, ChannelError> {
    let v: Option<Value> = serde_json::from_str(body).ok();
    if status == 200 && v.as_ref().is_some_and(|v| v["ok"] == true) {
        return Ok(v.unwrap()["result"].clone());
    }
    let desc = v.as_ref().and_then(|v| v["description"].as_str()).unwrap_or("").to_string();
    // The envelope's error_code wins over the HTTP status (Zalo often answers 200 + ok:false).
    let code = v.as_ref().and_then(|v| v["error_code"].as_u64()).map(|c| c as u16).unwrap_or(status);
    // 408: the long poll ended without an update.
    if code == 408 && method == "getUpdates" {
        return Ok(Value::Null);
    }
    let lower = desc.to_ascii_lowercase();
    let kind = match code {
        200 => return Err(ChannelError::new(K::Protocol, format!("zalo {method}: unexpected response {}", crate::http::redact(&body.chars().take(200).collect::<String>())))),
        401 => K::Auth,
        403 if lower.contains("token") => K::Auth,
        403 | 404 | 410 => K::NotFound,
        _ if lower.contains("invalid token") || lower.contains("unauthorized") => K::Auth,
        _ if lower.contains("not found") || lower.contains("blocked") || lower.contains("not follow") => K::NotFound,
        408 => K::Network,
        429 => K::RateLimited { retry_after },
        s if s >= 500 => K::Network,
        _ => K::Protocol,
    };
    let what = if kind == K::Auth { "zalo rejected the bot token".to_string() } else { format!("zalo {method}") };
    Err(ChannelError::new(kind, format!("{what}: error {code} {}", crate::http::redact(&desc))))
}

fn id_str(v: &Value) -> Option<String> {
    v.as_str().filter(|s| !s.is_empty()).map(str::to_string).or_else(|| v.as_i64().map(|n| n.to_string()))
}

/// One update → an Inbound. `me` = (bot id, account name).
fn inbound_of(channel: &str, u: &Value, me: Option<&(String, String)>) -> Option<Inbound> {
    let m = &u["message"];
    let event = u["event_name"].as_str().unwrap_or("");
    let chat = id_str(&m["chat"]["id"])?;
    let message_id = id_str(&m["message_id"])?;
    let from = &m["from"];
    let sender = id_str(&from["id"]).unwrap_or_default();
    if me.is_some_and(|(id, _)| *id == sender) {
        return None;
    }
    let mut media = Vec::new();
    let text = match event {
        "message.text.received" | "message.unsupported.received" => m["text"].as_str().unwrap_or("").to_string(),
        "message.image.received" => {
            let url = m["photo_url"].as_str().map(str::to_string);
            media.push(Media { kind: MediaKind::Image, url, mime: "image/jpeg".into(), name: "photo.jpg".into(), ..Default::default() });
            m["caption"].as_str().or_else(|| m["text"].as_str()).unwrap_or("").to_string()
        }
        "message.sticker.received" => {
            let s = m["sticker"].as_str().unwrap_or("");
            let is_url = s.starts_with("http");
            media.push(Media { kind: MediaKind::Sticker, url: is_url.then(|| s.to_string()), id: (!is_url && !s.is_empty()).then(|| s.to_string()), ..Default::default() });
            String::new()
        }
        _ => return None,
    };
    if text.trim().is_empty() && media.is_empty() {
        return None;
    }
    let is_group = m["chat"]["chat_type"].as_str() == Some("GROUP");
    let mentioned = is_group && me.is_some_and(|(_, name)| !name.is_empty() && text.to_lowercase().contains(&format!("@{}", name.to_lowercase())));
    let date = m["date"].as_i64().unwrap_or(0);
    Some(Inbound {
        channel: channel.to_string(),
        chat,
        chat_type: if is_group { ChatType::Group } else { ChatType::Direct },
        sender,
        sender_name: from["display_name"].as_str().or_else(|| from["name"].as_str()).unwrap_or("").to_string(),
        is_bot: from["is_bot"] == true,
        text,
        message_id,
        ts: if date > 100_000_000_000 { date / 1000 } else { date },
        media,
        mentioned,
        ..Default::default()
    })
}

/// No native buttons: append numbered options.
fn with_options(text: &str, rows: &[Vec<crate::Button>]) -> String {
    let mut out = text.to_string();
    let mut n = 0;
    for b in rows.iter().flatten() {
        n += 1;
        out.push_str(&match &b.url {
            Some(u) => format!("\n{n}. {} — {u}", b.label),
            None => format!("\n{n}. {}", b.label),
        });
    }
    out
}

impl Channel for Zalo {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group],
            media: true,
            typing: true,
            streaming: Streaming::None,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Utf16,
            markup: Markup::Plain,
            ..Caps::default()
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let updates: Vec<Value> = if let Some(h) = &self.hook {
            let rx = h.rx.lock().unwrap();
            let until = Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
            let mut got = Vec::new();
            while got.is_empty() && !cancel.is_cancelled() && Instant::now() < until {
                if let Ok(v) = rx.recv_timeout(Duration::from_millis(50)) {
                    got.push(v);
                    got.extend(rx.try_iter());
                }
            }
            got
        } else {
            self.clear_webhook_once(cancel)?;
            match self.call("getUpdates", &json!({"timeout": self.poll_timeout.to_string()}), cancel) {
                Ok(None) => return Ok(vec![]),
                Ok(Some(Value::Array(a))) => a,
                Ok(Some(Value::Null)) => vec![],
                Ok(Some(v)) => vec![v],
                Err(e) => return Err(e),
            }
        };
        let needs_me = updates.iter().any(|u| u["message"]["chat"]["chat_type"].as_str() == Some("GROUP"));
        let me = if needs_me { self.me() } else { self.me.lock().unwrap().clone() };
        Ok(updates.iter().filter_map(|u| inbound_of(&self.id, u, me.as_ref())).collect())
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let mut text = markup::convert(&out.text, Markup::Plain);
        if !out.buttons.is_empty() {
            text = with_options(&text, &out.buttons);
        }
        let mut sent = Sent::default();
        let images: Vec<&Media> = out.media.iter().filter(|m| m.kind == MediaKind::Image || m.kind == MediaKind::Sticker || m.kind == MediaKind::Animation).collect();
        let caption_fits = images.len() == 1 && out.media.len() == 1 && text.encode_utf16().count() <= MAX_MESSAGE;
        for m in &out.media {
            if images.iter().any(|i| std::ptr::eq(*i, m)) {
                let cap = caption_fits.then_some(text.as_str());
                sent.ids.push(self.send_photo(&out.chat, m, cap)?);
            } else if let Some(u) = &m.url {
                // Only photos have a Bot API method; other files go out as links.
                let label = m.caption.clone().filter(|c| !c.is_empty()).unwrap_or_else(|| if m.name.is_empty() { "attachment".into() } else { m.name.clone() });
                self.send_text(&out.chat, &format!("{label}: {u}"), &mut sent)?;
            } else {
                return Err(ChannelError::new(K::Unsupported, "zalo bots can only send photos; non-image files need a public url"));
            }
        }
        if !caption_fits {
            self.send_text(&out.chat, &text, &mut sent)?;
        }
        Ok(sent)
    }

    fn typing(&self, chat: &str, _thread: Option<&str>) -> Result<(), ChannelError> {
        self.call("sendChatAction", &json!({"chat_id": chat, "action": "typing"}), &Cancel::new()).map(|_| ())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        match &m.url {
            Some(u) => crate::http::get_bytes(u, &[], 20 * 1024 * 1024),
            None => Err(ChannelError::new(K::Unsupported, "zalo sticker has no downloadable url")),
        }
    }

    fn stop(&self) {
        if self.hook.is_some() {
            let _ = self.call("deleteWebhook", &json!({}), &Cancel::new());
        }
    }
}

fn d_poll() -> u64 {
    25
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    token: String,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    /// Webhook mode: public HTTPS URL Zalo posts to …
    #[serde(default)]
    webhook_url: Option<String>,
    /// … the local address that URL reaches …
    #[serde(default)]
    webhook_listen: Option<String>,
    /// … and the 8-256 char secret Zalo sends in X-Bot-Api-Secret-Token.
    #[serde(default)]
    webhook_secret: Option<String>,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let token = ctx.secret("token", &st.token)?;
    let mut z = Zalo::new(ctx.name, &token, st.base_url.as_deref(), st.poll_timeout_secs)?;
    if let Some(url) = &st.webhook_url {
        let listen = st.webhook_listen.as_deref().ok_or_else(|| format!("channel {}: webhook_url needs webhook_listen", ctx.name))?;
        let secret = ctx.opt_secret("webhook_secret", &st.webhook_secret)?.ok_or_else(|| format!("channel {}: webhook_url needs webhook_secret", ctx.name))?;
        z = z.with_webhook(listen, url, &secret)?;
    }
    Ok(Arc::new(z))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakeServer;

    fn zl(url: &str) -> Zalo {
        let mut z = Zalo::new("zl", "TOK:SECRET", Some(url), 1).unwrap();
        z.retry_base = Duration::from_millis(5);
        z
    }

    fn ok(result: Value) -> (u16, Vec<(String, String)>, String) {
        (200, vec![], json!({"ok": true, "result": result}).to_string())
    }

    fn err(code: u16, desc: &str) -> (u16, Vec<(String, String)>, String) {
        (200, vec![], json!({"ok": false, "error_code": code, "description": desc}).to_string())
    }

    fn msg(event: &str, chat_type: &str, extra: Value) -> Value {
        let mut m = json!({"message_id": "m1", "date": 1700000000123i64, "chat": {"id": "c1", "chat_type": chat_type}, "from": {"id": "u1", "display_name": "Amy", "name": "amy"}});
        for (k, v) in extra.as_object().unwrap() {
            m[k] = v.clone();
        }
        json!({"event_name": event, "message": m})
    }

    #[test]
    fn polls_after_clearing_webhook_and_parses_every_event_kind() {
        let srv = FakeServer::start(|req, _| {
            let p = req.path.rsplit('/').next().unwrap().to_string();
            match p.as_str() {
                "getWebhookInfo" => ok(json!({"url": "https://old.example.com/hook"})),
                "deleteWebhook" => ok(json!({})),
                "getMe" => ok(json!({"id": "BOT", "account_name": "ArkBot"})),
                _ => ok(Value::Null),
            }
        });
        let z = zl(&srv.url);
        assert!(z.poll(&Cancel::new()).unwrap().is_empty(), "null result = nothing");
        let paths: Vec<String> = srv.requests().iter().map(|r| r.path.rsplit('/').next().unwrap().to_string()).collect();
        assert_eq!(paths, ["getWebhookInfo", "deleteWebhook", "getUpdates"]);
        assert!(srv.requests()[2].path.ends_with("/botTOK:SECRET/getUpdates"));
        assert_eq!(srv.requests()[2].json()["timeout"], "1", "timeout passed as a string");
        z.poll(&Cancel::new()).unwrap();
        assert_eq!(srv.requests().iter().filter(|r| r.path.ends_with("getWebhookInfo")).count(), 1, "cleared once");

        let me = ("BOT".to_string(), "ArkBot".to_string());
        let t = inbound_of("zl", &msg("message.text.received", "PRIVATE", json!({"text": "xin chào"})), Some(&me)).unwrap();
        assert_eq!((t.chat.as_str(), t.sender.as_str(), t.sender_name.as_str(), t.message_id.as_str(), t.ts, t.chat_type), ("c1", "u1", "Amy", "m1", 1700000000, ChatType::Direct));
        let i = inbound_of("zl", &msg("message.image.received", "PRIVATE", json!({"photo_url": "https://cdn/p.jpg", "caption": "look"})), None).unwrap();
        assert_eq!((i.text.as_str(), i.media[0].kind, i.media[0].url.as_deref()), ("look", MediaKind::Image, Some("https://cdn/p.jpg")));
        let s = inbound_of("zl", &msg("message.sticker.received", "PRIVATE", json!({"sticker": "st-42"})), None).unwrap();
        assert_eq!((s.media[0].kind, s.media[0].id.as_deref()), (MediaKind::Sticker, Some("st-42")));
        assert!(inbound_of("zl", &msg("message.unsupported.received", "PRIVATE", json!({})), None).is_none(), "unsupported without text dropped");
        assert_eq!(inbound_of("zl", &msg("message.unsupported.received", "PRIVATE", json!({"text": "voice?"})), None).unwrap().text, "voice?");
        let g = inbound_of("zl", &msg("message.text.received", "GROUP", json!({"text": "hey @arkbot help"})), Some(&me)).unwrap();
        assert!(g.chat_type == ChatType::Group && g.mentioned);
        assert!(!inbound_of("zl", &msg("message.text.received", "GROUP", json!({"text": "hey all"})), Some(&me)).unwrap().mentioned);
        let mut own = msg("message.text.received", "GROUP", json!({"text": "echo"}));
        own["message"]["from"]["id"] = json!("BOT");
        assert!(inbound_of("zl", &own, Some(&me)).is_none(), "own message dropped");
        let mut bot = msg("message.text.received", "PRIVATE", json!({"text": "beep"}));
        bot["message"]["from"]["is_bot"] = json!(true);
        assert!(inbound_of("zl", &bot, None).unwrap().is_bot);
    }

    #[test]
    fn single_update_result_and_group_identity_lookup() {
        let srv = FakeServer::start(|req, _| {
            if req.path.ends_with("/getWebhookInfo") {
                return err(404, "Not Found");
            }
            if req.path.ends_with("/getMe") {
                return ok(json!({"id": "BOT", "account_name": "ArkBot"}));
            }
            ok(msg("message.text.received", "GROUP", json!({"text": "@ArkBot hi"})))
        });
        let z = zl(&srv.url);
        let got = z.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 1, "404 on webhook inspection is tolerated");
        assert!(got[0].mentioned);
        z.poll(&Cancel::new()).unwrap();
        assert_eq!(srv.requests().iter().filter(|r| r.path.ends_with("/getMe")).count(), 1, "identity cached");
    }

    #[test]
    fn poll_408_is_an_empty_poll_not_an_error() {
        let srv = FakeServer::start(|req, _| if req.path.ends_with("/getUpdates") { err(408, "Request timeout") } else { ok(json!({})) });
        assert!(zl(&srv.url).poll(&Cancel::new()).unwrap().is_empty());
    }

    #[test]
    fn send_text_chunks_photo_caption_buttons_and_typing() {
        let srv = FakeServer::start(|_, n| ok(json!({"message_id": format!("s{n}")})));
        let z = zl(&srv.url);
        let out = Outbound {
            format: crate::TextFormat::Markdown,
            reply_to: Some("ignored".into()),
            buttons: vec![vec![crate::Button { label: "Yes".into(), data: "y".into(), url: None }, crate::Button { label: "Docs".into(), data: String::new(), url: Some("https://e.com".into()) }]],
            ..Outbound::text("c1", "**bold** text")
        };
        let s = z.send(&out).unwrap();
        assert_eq!(s.ids, ["s0"]);
        let r = srv.requests()[0].clone();
        assert!(r.path.ends_with("/botTOK:SECRET/sendMessage"));
        assert_eq!(r.json(), json!({"chat_id": "c1", "text": "bold text\n1. Yes\n2. Docs — https://e.com"}));
        let img = Media { kind: MediaKind::Image, url: Some("https://e.com/a.png".into()), ..Default::default() };
        z.send(&Outbound { media: vec![img], ..Outbound::text("c1", "cap") }).unwrap();
        let r = srv.requests()[1].clone();
        assert!(r.path.ends_with("/sendPhoto"));
        assert_eq!(r.json(), json!({"chat_id": "c1", "photo": "https://e.com/a.png", "caption": "cap"}));
        let doc = Media { kind: MediaKind::Document, url: Some("https://e.com/r.pdf".into()), name: "r.pdf".into(), ..Default::default() };
        z.send(&Outbound { media: vec![doc], ..Outbound::text("c1", "") }).unwrap();
        assert_eq!(srv.requests()[2].json()["text"], "r.pdf: https://e.com/r.pdf");
        let local = Media { kind: MediaKind::Image, path: Some("/tmp/x.png".into()), ..Default::default() };
        assert_eq!(z.send(&Outbound { media: vec![local], ..Outbound::text("c1", "") }).unwrap_err().kind, K::Unsupported, "local files need webhook hosting");
        let n = srv.requests().len();
        let long = "😀".repeat(1500); // 3000 UTF-16 units
        let s = z.send(&Outbound::text("c1", &long)).unwrap();
        assert_eq!(s.ids.len(), 2);
        let parts: Vec<String> = srv.requests()[n..].iter().map(|r| r.json()["text"].as_str().unwrap().to_string()).collect();
        assert!(parts.iter().all(|p| p.encode_utf16().count() <= MAX_MESSAGE));
        assert_eq!(parts.concat(), long);
        z.typing("c1", None).unwrap();
        let r = srv.requests().last().unwrap().clone();
        assert!(r.path.ends_with("/sendChatAction"));
        assert_eq!(r.json(), json!({"chat_id": "c1", "action": "typing"}));
        assert_eq!(z.react("c1", "m", "👍", false).unwrap_err().kind, K::Unsupported);
    }

    #[test]
    fn error_envelope_mapping_and_retries() {
        for (status, code, desc, kind) in [(200, 401, "Unauthorized", K::Auth), (401, 0, "", K::Auth), (200, 403, "user blocked the bot", K::NotFound), (200, 404, "chat not found", K::NotFound), (200, 400, "bad params", K::Protocol)] {
            let srv = FakeServer::start(move |_, _| {
                let mut b = json!({"ok": false, "description": desc});
                if code > 0 {
                    b["error_code"] = json!(code);
                }
                (status, vec![], b.to_string())
            });
            let e = zl(&srv.url).send(&Outbound::text("c", "x")).unwrap_err();
            assert_eq!(e.kind, kind, "{status}/{code} {desc}");
            assert!(!e.message.contains("SECRET"), "{}", e.message);
            assert_eq!(srv.requests().len(), 1, "not retried");
        }
        let srv = FakeServer::start(|_, n| match n {
            0 => (429, vec![("Retry-After".into(), "1".into())], json!({"ok": false, "error_code": 429, "description": "slow down"}).to_string()),
            1 => (502, vec![], "<html>".into()),
            _ => ok(json!({"message_id": "ok"})),
        });
        let start = Instant::now();
        assert_eq!(zl(&srv.url).send(&Outbound::text("c", "x")).unwrap().ids, ["ok"]);
        assert!(start.elapsed() >= Duration::from_millis(950), "retry-after honoured");
        let srv = FakeServer::start(|_, _| (429, vec![("Retry-After".into(), "3600".into())], json!({"ok": false, "error_code": 429}).to_string()));
        assert_eq!(zl(&srv.url).send(&Outbound::text("c", "x")).unwrap_err().kind, K::RateLimited { retry_after: Some(Duration::from_secs(3600)) });
        let e = zl("http://127.0.0.1:1").send(&Outbound::text("c", "x")).unwrap_err();
        assert!(e.kind == K::Network && !e.message.contains("SECRET"), "{e}");
        assert!(Zalo::new("z", " ", None, 1).is_err());
    }

    #[test]
    fn cancel_interrupts_a_blocked_long_poll() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            let _keep: Vec<_> = l.incoming().take(3).collect();
            std::thread::sleep(Duration::from_secs(30));
        });
        let z = zl(&url);
        z.webhook_cleared.store(true, std::sync::atomic::Ordering::SeqCst);
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let start = Instant::now();
        assert!(z.poll(&c).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn webhook_secret_check_hosted_media_and_cleanup() {
        let srv = FakeServer::start(|_, n| ok(json!({"message_id": format!("p{n}")})));
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let listen = format!("127.0.0.1:{port}");
        assert!(zl(&srv.url).with_webhook(&listen, "https://bot.example.com/zalo/hook", "short").is_err(), "weak secret");
        assert!(zl(&srv.url).with_webhook(&listen, "http://bot.example.com/zalo/hook", "long-enough-secret").is_err(), "https only");
        let z = zl(&srv.url).with_webhook(&listen, "https://bot.example.com/zalo/hook", "long-enough-secret").unwrap();
        let set = srv.requests()[0].clone();
        assert!(set.path.ends_with("/setWebhook"));
        assert_eq!(set.json(), json!({"url": "https://bot.example.com/zalo/hook", "secret_token": "long-enough-secret"}));
        let a = agent(Duration::from_secs(5));
        let post = |secret: Option<&str>, path: &str| {
            let mut r = a.post(&format!("http://{listen}{path}")).header("content-type", "application/json");
            if let Some(s) = secret {
                r = r.header("x-bot-api-secret-token", s);
            }
            r.send(msg("message.text.received", "PRIVATE", json!({"text": "via hook"})).to_string().as_bytes()).map(|r| r.status().as_u16()).unwrap_or(0)
        };
        assert_eq!(post(Some("wrong-secret-xx"), "/zalo/hook"), 401);
        assert_eq!(post(None, "/zalo/hook"), 401, "missing secret");
        assert_eq!(post(Some("long-enough-secret"), "/other"), 404);
        assert_eq!(post(Some("long-enough-secret"), "/zalo/hook"), 200);
        let got = z.poll(&Cancel::new()).unwrap();
        assert_eq!((got.len(), got[0].text.as_str()), (1, "via hook"));

        // Local photo → hosted once at <path>/media/<id>?token=…
        let f = crate::testutil::temp_dir("zalo").join("a.png");
        std::fs::write(&f, b"PNGDATA").unwrap();
        let img = Media { kind: MediaKind::Image, path: Some(f.display().to_string()), ..Default::default() };
        z.send(&Outbound { media: vec![img], ..Outbound::text("c1", "pic") }).unwrap();
        let photo = srv.requests().last().unwrap().json()["photo"].as_str().unwrap().to_string();
        assert!(photo.starts_with("https://bot.example.com/zalo/hook/media/"), "{photo}");
        let local = photo.replace("https://bot.example.com", &format!("http://{listen}"));
        let get = |u: &str| {
            let mut r = a.get(u).call().unwrap();
            (r.status().as_u16(), r.body_mut().read_to_string().unwrap_or_default())
        };
        let (base, _) = local.split_once("?token=").unwrap();
        assert_eq!(get(&format!("{base}?token=nope")).0, 401);
        assert_eq!(get(&local), (200, "PNGDATA".to_string()));
        assert_eq!(get(&local).0, 404, "served once");
        assert!(srv.requests().iter().all(|r| !r.path.ends_with("/getUpdates")));
        z.stop();
        assert!(srv.requests().last().unwrap().path.ends_with("/deleteWebhook"));
    }
}
