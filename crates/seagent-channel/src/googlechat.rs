//! Google Chat app (ported from OpenClaw `extensions/googlechat` and Hermes
//! `plugins/platforms/google_chat`, both MIT).
//!
//! Receive, either
//! - HTTP: Chat POSTs events to `listen` + `path` with `Authorization: Bearer
//!   <Google-signed JWT>`, verified RS256 before parsing. `audience_type =
//!   "project-number"` (default): signed by `chat@system.gserviceaccount.com`
//!   (its JWKS), `aud` = the project number. `"app-url"`: a Google OIDC ID token
//!   (Google's JWKS), `aud` = the endpoint URL, `email` = the Chat service account.
//! - Pub/Sub pull: `subscription = "projects/P/subscriptions/S"`; messages are
//!   acknowledged on the next poll (at-least-once; the router dedups). Both the
//!   classic Chat event JSON and Workspace Events CloudEvents
//!   (`google.workspace.chat.message.v1.created|updated`) are understood.
//!
//! MESSAGE events (DM vs space, threads, @mention annotations, slash commands,
//! quoted replies, attachments), CARD_CLICKED button presses (→ `Callback`) and
//! the Workspace Add-ons envelope become `Inbound`s; the bot's own and other
//! bots' messages are dropped.
//! Send: service-account JWT → OAuth token (cached) → `spaces/*/messages`
//! create with `thread.name`/`threadKey` + `messageReplyOption`, cardsV2
//! buttons, PATCH `?updateMask=text`, DELETE, attachment download through the
//! media endpoint. Chat apps cannot upload files with app auth, so outbound
//! media must be remote URLs (sent as links, as upstream does) unless a user
//! OAuth refresh token is configured (`user_oauth`, as Hermes' `/setup-files`):
//! then local files go up with `attachments:upload` and are posted as that user,
//! and reactions (`spaces.messages.reactions`, user auth only) work.
//!
//! Dialogs (HTTP endpoint only: they need the synchronous response): a button
//! with data `dialog:<name>` opens the configured card (`OPEN_DIALOG` →
//! `REQUEST_DIALOG` answered with `actionResponse.type = DIALOG`); its submit
//! (`SUBMIT_DIALOG`) closes it with `actionStatus OK` and arrives as a message
//! listing the form inputs; `CANCEL_DIALOG` as a "closed" message. Form inputs of
//! ordinary card clicks (`submitForm`) are appended to the callback data.

use crate::http::{classify, post_cancellable, Http, Payload};
use crate::msteams::{aud_matches, drain, kind_of_mime, now_secs, parse_rfc3339, pem_to_der, sign_rs256, verify_rs256, JwksCache};
use crate::{markup, sleep_cancellable, Callback, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, Outbound, ReplyRef, Sent, Streaming, TextFormat};
use seagent_core::Cancel;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_API: &str = "https://chat.googleapis.com/v1";
pub const DEFAULT_PUBSUB: &str = "https://pubsub.googleapis.com/v1";
pub const DEFAULT_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub const CHAT_JWKS: &str = "https://www.googleapis.com/service_accounts/v1/jwk/chat@system.gserviceaccount.com";
pub const GOOGLE_JWKS: &str = "https://www.googleapis.com/oauth2/v3/certs";
pub const CHAT_ISSUER: &str = "chat@system.gserviceaccount.com";
const SCOPE_CHAT: &str = "https://www.googleapis.com/auth/chat.bot";
const SCOPE_PUBSUB: &str = "https://www.googleapis.com/auth/pubsub";
const UPLOAD_MAX: usize = 200 * 1024 * 1024;
pub const MAX_MESSAGE: usize = 4096;
const SKEW: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience {
    ProjectNumber,
    AppUrl,
}

pub struct ServiceAccount {
    pub email: String,
    pub key_der: Vec<u8>,
    pub key_id: String,
    pub token_uri: String,
}

impl ServiceAccount {
    pub fn from_json(s: &str) -> Result<ServiceAccount, String> {
        let v: Value = serde_json::from_str(s).map_err(|e| format!("service account JSON: {e}"))?;
        let email = v["client_email"].as_str().ok_or("service account JSON has no client_email")?.to_string();
        let pem = v["private_key"].as_str().ok_or("service account JSON has no private_key")?;
        let key_der = pem_to_der(pem).ok_or("service account private_key is not PEM")?;
        ring::signature::RsaKeyPair::from_pkcs8(&key_der).map_err(|e| format!("service account private_key: {e}"))?;
        Ok(ServiceAccount { email, key_der, key_id: v["private_key_id"].as_str().unwrap_or("").to_string(), token_uri: v["token_uri"].as_str().unwrap_or(DEFAULT_TOKEN_URL).to_string() })
    }
}

struct Verifier {
    audience_type: Audience,
    audience: String,
    jwks: JwksCache,
}

impl Verifier {
    fn check(&self, bearer: Option<&str>) -> Result<(), String> {
        let tok = bearer.ok_or("missing bearer token")?;
        let (claims, _) = verify_rs256(tok, &self.jwks, now_secs(), SKEW)?;
        if !aud_matches(&claims, &self.audience) {
            return Err("wrong audience".into());
        }
        match self.audience_type {
            Audience::ProjectNumber if claims["iss"] == CHAT_ISSUER => Ok(()),
            Audience::ProjectNumber => Err("wrong issuer".into()),
            Audience::AppUrl => {
                let iss_ok = matches!(claims["iss"].as_str(), Some("https://accounts.google.com" | "accounts.google.com"));
                let email_ok = claims["email"].as_str().is_some_and(|e| e.eq_ignore_ascii_case(CHAT_ISSUER)) && claims["email_verified"] == true;
                if iss_ok && email_ok {
                    Ok(())
                } else {
                    Err("token not issued for Google Chat".into())
                }
            }
        }
    }
}

/// A user's OAuth client + refresh token (scopes `chat.messages.create`, and
/// `chat.messages.reactions` for reactions).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserOAuth {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
    #[serde(default)]
    pub token_url: Option<String>,
}

pub struct GoogleChat {
    id: String,
    user_oauth: Option<UserOAuth>,
    user_token: Mutex<Option<(String, Instant)>>,
    /// (message, emoji) → reaction name we created.
    reactions: Mutex<HashMap<String, String>>,
    sa: ServiceAccount,
    api: String,
    pubsub: String,
    subscription: Option<String>,
    bot_user: Option<String>,
    http: Http,
    token: Mutex<Option<(String, Instant)>>,
    rx: Mutex<Receiver<Inbound>>,
    server: Option<seagent_net::httpd::Server>,
    pending_acks: Mutex<Vec<String>>,
    sent: Arc<Mutex<HashSet<String>>>,
    poll_timeout: Duration,
    pub retry_base: Duration,
    pub max_retries: u32,
    pub max_wait: Duration,
}

pub struct GoogleChatOpts<'a> {
    pub sa: ServiceAccount,
    pub listen: Option<&'a str>,
    pub path: &'a str,
    pub audience_type: Audience,
    pub audience: Option<&'a str>,
    pub jwks_url: Option<&'a str>,
    pub subscription: Option<&'a str>,
    pub bot_user: Option<&'a str>,
    pub api_base: &'a str,
    pub pubsub_base: &'a str,
    pub poll_timeout: Duration,
    /// name → dialog card (Card v2 `card` object).
    pub dialogs: HashMap<String, Value>,
    pub user_oauth: Option<UserOAuth>,
}

fn str_of(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

/// Markdown → Google Chat text (`*b*`, `_i_`, `~s~`, `` `c` ``, `<url|label>`); Chat shows `<>&` literally.
pub fn to_chat_text(md: &str) -> String {
    markup::convert(md, Markup::SlackMrkdwn).replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

/// Normalise the three event envelopes to (kind, message, space, user, extra).
fn event_parts(ev: &Value) -> Option<(&str, &Value, &Value, &Value)> {
    if let Some(chat) = ev.get("chat").filter(|c| c.is_object()) {
        // Workspace Add-ons envelope.
        if let Some(p) = chat.get("messagePayload") {
            let space = if p["space"].is_object() { &p["space"] } else { &p["message"]["space"] };
            return Some(("MESSAGE", &p["message"], space, &chat["user"]));
        }
        if let Some(p) = chat.get("buttonClickedPayload") {
            let space = if p["space"].is_object() { &p["space"] } else { &p["message"]["space"] };
            return Some(("CARD_CLICKED", &p["message"], space, &chat["user"]));
        }
        return None;
    }
    let space = if ev["space"].is_object() { &ev["space"] } else { &ev["message"]["space"] };
    Some((ev["type"].as_str()?, &ev["message"], space, &ev["user"]))
}

fn media_of(msg: &Value) -> Vec<Media> {
    msg["attachment"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| {
            let resource = a["attachmentDataRef"]["resourceName"].as_str();
            // Drive-picker shares carry no resourceName and need user OAuth; skip them like upstream.
            if resource.is_none() && a["source"] == "DRIVE_FILE" {
                return None;
            }
            let mime = str_of(&a["contentType"]).to_string();
            Some(Media { kind: kind_of_mime(&mime), mime, name: str_of(&a["contentName"]).to_string(), id: resource.map(str::to_string), url: a["downloadUri"].as_str().map(str::to_string), ..Default::default() })
        })
        .collect()
}

/// One Chat event → Inbound. `edited_at` marks Workspace Events updates.
fn inbound_of(channel: &str, ev: &Value, bot_user: Option<&str>, is_sent: &dyn Fn(&str) -> bool, edited_at: Option<&str>) -> Option<Inbound> {
    let (kind, msg, space, user) = event_parts(ev)?;
    let space_name = space["name"].as_str().or_else(|| msg["name"].as_str().and_then(|n| n.split("/messages/").next()))?.to_string();
    let is_dm = matches!(space["spaceType"].as_str(), Some("DIRECT_MESSAGE")) || space["type"] == "DM" || space["singleUserBotDm"] == true;
    let thread_name = msg["thread"]["name"].as_str().filter(|_| !is_dm || msg["threadReply"] == true).map(str::to_string);
    let base = Inbound {
        channel: channel.to_string(),
        chat: space_name,
        chat_type: if is_dm { ChatType::Direct } else { ChatType::Group },
        chat_name: str_of(&space["displayName"]).to_string(),
        thread: thread_name,
        ts: msg["createTime"].as_str().or(ev["eventTime"].as_str()).and_then(parse_rfc3339).unwrap_or(0),
        ..Default::default()
    };
    match kind {
        "CARD_CLICKED" => {
            let data = ev["common"]["parameters"]["data"]
                .as_str()
                .or(ev["commonEventObject"]["parameters"]["data"].as_str())
                .or_else(|| ev["action"]["parameters"].as_array().into_iter().flatten().find(|p| p["key"] == "data").and_then(|p| p["value"].as_str()))?
                .to_string();
            let mut data = data;
            for l in form_lines(ev) {
                data.push('\n');
                data.push_str(&l);
            }
            let msg_name = str_of(&msg["name"]).to_string();
            let cb_id = format!("{msg_name}@{}", str_of(&ev["eventTime"]));
            Some(Inbound {
                sender: str_of(&user["name"]).to_string(),
                sender_name: str_of(&user["displayName"]).to_string(),
                message_id: format!("cb:{cb_id}"),
                callback: Some(Callback { id: cb_id, data }),
                reply: (!msg_name.is_empty()).then(|| ReplyRef { id: msg_name, is_own: true, ..Default::default() }),
                ..base
            })
        }
        "MESSAGE" | "ADDED_TO_SPACE" if msg.is_object() => {
            let sender = if msg["sender"].is_object() { &msg["sender"] } else { user };
            if sender["type"] == "BOT" || bot_user.is_some_and(|b| sender["name"] == b) {
                return None;
            }
            let annotations: Vec<&Value> = msg["annotations"].as_array().into_iter().flatten().collect();
            let mentioned = annotations.iter().any(|a| {
                a["type"] == "USER_MENTION"
                    && match bot_user {
                        Some(b) => a["userMention"]["user"]["name"] == b,
                        None => a["userMention"]["user"]["type"] == "BOT",
                    }
            });
            let mut text = msg["argumentText"].as_str().map(str::trim).filter(|t| !t.is_empty()).unwrap_or_else(|| str_of(&msg["text"]).trim()).to_string();
            if let Some(cmd) = annotations.iter().find(|a| a["type"] == "SLASH_COMMAND").and_then(|a| a["slashCommand"]["commandName"].as_str()) {
                if !text.starts_with('/') {
                    text = format!("{cmd} {text}").trim().to_string();
                }
            }
            let media = media_of(msg);
            if text.is_empty() && media.is_empty() {
                return None;
            }
            let name = str_of(&msg["name"]).to_string();
            let reply = msg["quotedMessageMetadata"]["name"].as_str().map(|q| ReplyRef { id: q.to_string(), is_own: is_sent(q), ..Default::default() });
            Some(Inbound {
                sender: str_of(&sender["name"]).to_string(),
                sender_name: sender["displayName"].as_str().or(sender["email"].as_str()).unwrap_or("").to_string(),
                text,
                message_id: match edited_at {
                    Some(at) => format!("{name}:e{}", parse_rfc3339(at).unwrap_or(0)),
                    None => name,
                },
                media,
                mentioned,
                reply,
                edited: edited_at.is_some(),
                ..base
            })
        }
        _ => None,
    }
}

/// A Pub/Sub message → the Chat event it carries (CloudEvents are unwrapped).
fn pubsub_event(m: &Value) -> Option<(Value, Option<String>)> {
    let data = seagent_net::crypto::b64_decode(m["data"].as_str()?).or_else(|| seagent_net::crypto::b64url_decode(m["data"].as_str()?.trim_end_matches('=')))?;
    let v: Value = serde_json::from_slice(&data).ok()?;
    let ce = m["attributes"]["ce-type"].as_str().unwrap_or("");
    if ce.starts_with("google.workspace.chat.message.v1.") {
        let msg = v["message"].clone();
        let edited = ce.ends_with(".updated").then(|| msg["lastUpdateTime"].as_str().unwrap_or("").to_string());
        if !(ce.ends_with(".created") || ce.ends_with(".updated")) {
            return None;
        }
        let space = json!({"name": msg["space"]["name"].as_str().or_else(|| msg["name"].as_str().and_then(|n| n.split("/messages/").next())).unwrap_or(""), "spaceType": msg["space"]["spaceType"]});
        return Some((json!({"type": "MESSAGE", "message": msg, "space": space}), edited));
    }
    Some((v, None))
}

impl GoogleChat {
    pub fn new(id: &str, o: GoogleChatOpts) -> Result<GoogleChat, String> {
        let (tx, rx) = mpsc::channel::<Inbound>();
        let sent = Arc::new(Mutex::new(HashSet::new()));
        let server = match o.listen {
            None => None,
            Some(listen) => {
                let audience = o.audience.map(str::trim).filter(|a| !a.is_empty()).ok_or_else(|| format!("channel {id}: an inbound Google Chat endpoint needs `audience` (project number or app URL)"))?;
                let default_jwks = if o.audience_type == Audience::ProjectNumber { CHAT_JWKS } else { GOOGLE_JWKS };
                let v = Arc::new(Verifier { audience_type: o.audience_type, audience: audience.to_string(), jwks: JwksCache::new(o.jwks_url.unwrap_or(default_jwks), false) });
                let (path, ch, bot, tx, sent2, dialogs) = (o.path.to_string(), id.to_string(), o.bot_user.map(str::to_string), Mutex::new(tx.clone()), sent.clone(), o.dialogs.clone());
                let handler: seagent_net::httpd::Handler = Arc::new(move |r: seagent_net::httpd::Request| handle(&v, &path, &ch, bot.as_deref(), &tx, &sent2, &dialogs, r));
                let opts = seagent_net::httpd::Opts { max_body: 1024 * 1024, ..Default::default() };
                Some(seagent_net::httpd::Server::bind(listen, opts, handler).map_err(|e| format!("channel {id}: cannot listen on {listen}: {e}"))?)
            }
        };
        if let Some(s) = o.subscription {
            let parts: Vec<&str> = s.split('/').collect();
            if parts.len() != 4 || parts[0] != "projects" || parts[2] != "subscriptions" || parts[1].is_empty() || parts[3].is_empty() {
                return Err(format!("channel {id}: subscription must look like projects/<project>/subscriptions/<name>"));
            }
        }
        if server.is_none() && o.subscription.is_none() {
            return Err(format!("channel {id}: google chat needs `listen` (HTTP endpoint) or `subscription` (Pub/Sub pull)"));
        }
        drop(tx);
        Ok(GoogleChat {
            id: id.to_string(),
            user_oauth: o.user_oauth,
            user_token: Mutex::new(None),
            reactions: Mutex::new(HashMap::new()),
            sa: o.sa,
            api: o.api_base.trim_end_matches('/').to_string(),
            pubsub: o.pubsub_base.trim_end_matches('/').to_string(),
            subscription: o.subscription.map(str::to_string),
            bot_user: o.bot_user.map(str::to_string),
            http: Http::new(Duration::from_secs(30)),
            token: Mutex::new(None),
            rx: Mutex::new(rx),
            server,
            pending_acks: Mutex::new(vec![]),
            sent,
            poll_timeout: o.poll_timeout,
            retry_base: Duration::from_millis(500),
            max_retries: 3,
            max_wait: Duration::from_secs(60),
        })
    }

    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.server.as_ref().map(|s| s.local_addr())
    }

    fn access_token(&self) -> Result<String, ChannelError> {
        if let Some((t, exp)) = self.token.lock().unwrap().clone() {
            if Instant::now() < exp {
                return Ok(t);
            }
        }
        let now = now_secs();
        let scope = if self.subscription.is_some() { format!("{SCOPE_CHAT} {SCOPE_PUBSUB}") } else { SCOPE_CHAT.to_string() };
        let claims = json!({"iss": self.sa.email, "scope": scope, "aud": self.sa.token_uri, "iat": now, "exp": now + 3600});
        let mut header = json!({"alg": "RS256", "typ": "JWT"});
        if !self.sa.key_id.is_empty() {
            header["kid"] = json!(self.sa.key_id);
        }
        let assertion = sign_rs256(&self.sa.key_der, &header, &claims).map_err(|e| ChannelError::new(K::Fatal, e))?;
        let form = [("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"), ("assertion", assertion.as_str())];
        let r = self.http.call("POST", &self.sa.token_uri, &[], Payload::Form(&form))?;
        let v: Value = serde_json::from_str(&r.body).unwrap_or_default();
        if !(200..300).contains(&r.status) {
            let err = str_of(&v["error"]);
            if matches!(r.status, 400 | 401 | 403) && (matches!(err, "invalid_grant" | "invalid_client" | "unauthorized_client") || r.status != 400) {
                return Err(ChannelError::new(K::Auth, format!("google token request rejected ({} {err})", r.status)));
            }
            return Err(classify(r.status, r.retry_after, "google token", err));
        }
        let tok = v["access_token"].as_str().ok_or_else(|| ChannelError::new(K::Protocol, "google token: no access_token"))?.to_string();
        let ttl = v["expires_in"].as_u64().unwrap_or(3600).saturating_sub(120).max(30);
        *self.token.lock().unwrap() = Some((tok.clone(), Instant::now() + Duration::from_secs(ttl)));
        Ok(tok)
    }

    /// Authorised REST call with one token refresh on 401 and retries on 429/5xx.
    fn api_call(&self, method: &str, url: &str, body: Option<&Value>) -> Result<Value, ChannelError> {
        let mut attempt = 0;
        let mut refreshed = false;
        loop {
            let http = self.http.clone().bearer(&self.access_token()?);
            let err = match http.call(method, url, &[], body.map_or(Payload::None, Payload::Json)) {
                Ok(r) if (200..300).contains(&r.status) => return Ok(serde_json::from_str(&r.body).unwrap_or(Value::Null)),
                Ok(r) if r.status == 401 && !refreshed => {
                    refreshed = true;
                    *self.token.lock().unwrap() = None;
                    continue;
                }
                Ok(r) => gchat_error(r.status, r.retry_after, method, &r.body),
                Err(e) => e,
            };
            if !err.is_retryable() || attempt >= self.max_retries {
                return Err(err);
            }
            let wait = match err.kind {
                K::RateLimited { retry_after: Some(d) } if d > self.max_wait => return Err(err),
                K::RateLimited { retry_after: Some(d) } => d,
                _ => self.retry_base * 2u32.pow(attempt),
            };
            sleep_cancellable(wait, &Cancel::new());
            attempt += 1;
        }
    }

    fn pull(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let sub = self.subscription.as_deref().unwrap_or("");
        let acks = std::mem::take(&mut *self.pending_acks.lock().unwrap());
        if !acks.is_empty() {
            if let Err(e) = self.api_call("POST", &format!("{}/{sub}:acknowledge", self.pubsub), Some(&json!({"ackIds": acks}))) {
                *self.pending_acks.lock().unwrap() = acks;
                return Err(e);
            }
        }
        let until = Instant::now() + self.poll_timeout;
        while !cancel.is_cancelled() && Instant::now() < until {
            let started = Instant::now();
            let headers = vec![("authorization".to_string(), format!("Bearer {}", self.access_token()?))];
            let Some(r) = post_cancellable(&self.http.agent, &format!("{}/{sub}:pull", self.pubsub), &headers, json!({"maxMessages": 50}).to_string().into_bytes(), cancel)? else { return Ok(vec![]) };
            if r.status == 401 {
                *self.token.lock().unwrap() = None;
            }
            if !(200..300).contains(&r.status) {
                return Err(gchat_error(r.status, r.retry_after, "pubsub pull", &r.body));
            }
            let v: Value = serde_json::from_str(&r.body).unwrap_or_default();
            let msgs = v["receivedMessages"].as_array().cloned().unwrap_or_default();
            if msgs.is_empty() {
                // The pull returned early with nothing; don't spin.
                if started.elapsed() < Duration::from_secs(1) && !sleep_cancellable(Duration::from_secs(1).min(until.saturating_duration_since(Instant::now())), cancel) {
                    return Ok(vec![]);
                }
                continue;
            }
            let sent = self.sent.lock().unwrap().clone();
            let mut out = vec![];
            let mut acks = vec![];
            for m in &msgs {
                acks.extend(m["ackId"].as_str().map(str::to_string));
                if let Some((ev, edited)) = pubsub_event(&m["message"]) {
                    out.extend(inbound_of(&self.id, &ev, self.bot_user.as_deref(), &|id| sent.contains(id), edited.as_deref()));
                }
            }
            *self.pending_acks.lock().unwrap() = acks;
            return Ok(out);
        }
        Ok(vec![])
    }

    /// The configured user's access token (refresh-token grant, cached).
    fn user_access_token(&self) -> Result<String, ChannelError> {
        let u = self.user_oauth.as_ref().ok_or_else(|| ChannelError::new(K::Unsupported, "google chat: this needs user OAuth (set user_oauth)"))?;
        if let Some((t, exp)) = self.user_token.lock().unwrap().clone() {
            if Instant::now() < exp {
                return Ok(t);
            }
        }
        let url = u.token_url.clone().unwrap_or_else(|| DEFAULT_TOKEN_URL.to_string());
        let form = [("grant_type", "refresh_token"), ("client_id", u.client_id.as_str()), ("client_secret", u.client_secret.as_str()), ("refresh_token", u.refresh_token.as_str())];
        let r = self.http.call("POST", &url, &[], Payload::Form(&form))?;
        let v: Value = serde_json::from_str(&r.body).unwrap_or_default();
        if !(200..300).contains(&r.status) {
            let err = str_of(&v["error"]);
            if matches!(r.status, 400 | 401 | 403) {
                return Err(ChannelError::new(K::Auth, format!("google user token refresh rejected ({} {err})", r.status)));
            }
            return Err(classify(r.status, r.retry_after, "google user token", err));
        }
        let tok = v["access_token"].as_str().ok_or_else(|| ChannelError::new(K::Protocol, "google user token: no access_token"))?.to_string();
        let ttl = v["expires_in"].as_u64().unwrap_or(3600).saturating_sub(120).max(30);
        *self.user_token.lock().unwrap() = Some((tok.clone(), Instant::now() + Duration::from_secs(ttl)));
        Ok(tok)
    }

    /// A call with the user's token (one refresh on 401, no other retries).
    fn user_call(&self, method: &str, url: &str, body: Payload) -> Result<Value, ChannelError> {
        for attempt in 0..2 {
            let r = self.http.clone().bearer(&self.user_access_token()?).call(method, url, &[], body)?;
            if (200..300).contains(&r.status) {
                return Ok(serde_json::from_str(&r.body).unwrap_or(Value::Null));
            }
            if r.status == 401 && attempt == 0 {
                *self.user_token.lock().unwrap() = None;
                continue;
            }
            return Err(gchat_error(r.status, r.retry_after, method, &r.body));
        }
        unreachable!()
    }

    /// `attachments:upload` (multipart/related) then `messages.create` as the user, since
    /// the attachment reference is bound to the uploader (Hermes `_send_file`).
    fn upload(&self, space: &str, thread: Option<&Value>, m: &Media) -> Result<String, ChannelError> {
        let path = m.path.as_deref().unwrap_or_default();
        let data = std::fs::read(path).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {path}: {e}")))?;
        if data.len() > UPLOAD_MAX {
            return Err(ChannelError::new(K::Fatal, "attachment larger than Google Chat's 200 MB limit"));
        }
        let name = if m.name.is_empty() { std::path::Path::new(path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "upload.bin".into()) } else { m.name.clone() };
        let mime = if m.mime.is_empty() { crate::msteams::guess_mime(&name).to_string() } else { m.mime.clone() };
        let boundary = format!("seagent{}", seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(12)));
        let mut body = format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{}\r\n--{boundary}\r\nContent-Type: {mime}\r\n\r\n", json!({"filename": name})).into_bytes();
        body.extend_from_slice(&data);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let upload_base = match self.api.strip_suffix("/v1") {
            Some(root) => format!("{root}/upload/v1"),
            None => format!("{}/upload", self.api),
        };
        let ctype = format!("multipart/related; boundary={boundary}");
        let r = self.user_call("POST", &format!("{upload_base}/{space}/attachments:upload?uploadType=multipart"), Payload::Raw(&ctype, &body))?;
        let att = r["attachmentDataRef"].clone();
        if !att.is_object() {
            return Err(ChannelError::new(K::Protocol, "google chat upload returned no attachmentDataRef"));
        }
        let mut msg = json!({"attachment": [{"attachmentDataRef": att}]});
        if let Some(c) = m.caption.as_deref().filter(|c| !c.is_empty()) {
            msg["text"] = json!(c);
        }
        let mut url = format!("{}/{space}/messages", self.api);
        if let Some(t) = thread {
            msg["thread"] = t.clone();
            url.push_str("?messageReplyOption=REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD");
        }
        let v = self.user_call("POST", &url, Payload::Json(&msg))?;
        Ok(v["name"].as_str().unwrap_or("").to_string())
    }

    /// thread → message body field; reply_to without thread → the replied message's thread.
    fn thread_of(&self, out: &Outbound) -> Result<Option<Value>, ChannelError> {
        if let Some(t) = &out.thread {
            return Ok(Some(if t.starts_with("spaces/") { json!({"name": t}) } else { json!({"threadKey": t}) }));
        }
        if let Some(r) = out.reply_to.as_deref().filter(|r| r.starts_with("spaces/")) {
            let m = self.api_call("GET", &format!("{}/{r}", self.api), None)?;
            return Ok(m["thread"]["name"].as_str().map(|n| json!({"name": n})));
        }
        Ok(None)
    }
}

fn gchat_error(status: u16, retry_after: Option<Duration>, what: &str, body: &str) -> ChannelError {
    let v: Value = serde_json::from_str(body).unwrap_or_default();
    let msg = format!("{} {}", str_of(&v["error"]["status"]), str_of(&v["error"]["message"]));
    match status {
        // The app was removed from the space / the space or message is gone.
        403 | 404 => ChannelError::new(K::NotFound, format!("google chat {what}: HTTP {status} {msg}")),
        _ => classify(status, retry_after, &format!("google chat {what}"), &msg),
    }
}

/// Form inputs (`common.formInputs` / `commonEventObject.formInputs`) as "- name: value" lines.
fn form_lines(ev: &Value) -> Vec<String> {
    let inputs = if ev["common"]["formInputs"].is_object() { &ev["common"]["formInputs"] } else { &ev["commonEventObject"]["formInputs"] };
    let mut out = vec![];
    for (k, v) in inputs.as_object().into_iter().flatten() {
        let mut vals: Vec<String> = v["stringInputs"]["value"].as_array().into_iter().flatten().filter_map(|x| x.as_str()).map(str::to_string).collect();
        for d in ["dateInput", "dateTimeInput"] {
            if let Some(ms) = v[d]["msSinceEpoch"].as_str().and_then(|m| m.parse::<i64>().ok()).or_else(|| v[d]["msSinceEpoch"].as_i64()) {
                vals.push((ms / 1000).to_string());
            }
        }
        if let (Some(h), Some(m)) = (v["timeInput"]["hours"].as_i64(), v["timeInput"]["minutes"].as_i64()) {
            vals.push(format!("{h:02}:{m:02}"));
        }
        out.push(format!("- {k}: {}", vals.join(", ")));
    }
    out.sort();
    out
}

fn param<'a>(ev: &'a Value, key: &str) -> Option<&'a str> {
    ev["common"]["parameters"][key]
        .as_str()
        .or(ev["commonEventObject"]["parameters"][key].as_str())
        .or_else(|| ev["action"]["parameters"].as_array().into_iter().flatten().find(|p| p["key"] == key).and_then(|p| p["value"].as_str()))
}

/// The dialog card for `name`, with a Submit footer carrying the name when it has none.
fn dialog_body(dialogs: &HashMap<String, Value>, name: &str) -> Option<Value> {
    let mut card = dialogs.get(name)?.clone();
    if card.get("fixedFooter").is_none() {
        card["fixedFooter"] = json!({"primaryButton": {"text": "Submit", "onClick": {"action": {"function": "seagent_submit", "parameters": [{"key": "dialog", "value": name}]}}}});
    }
    Some(card)
}

fn dialog_status(code: &str, msg: &str) -> Value {
    json!({"actionResponse": {"type": "DIALOG", "dialogAction": {"actionStatus": {"statusCode": code, "userFacingMessage": msg}}}})
}

/// Dialog events need an answer in the HTTP response: the dialog itself, or a status that
/// closes it. Submissions / cancels also become messages.
fn dialog_event(channel: &str, ev: &Value, dialogs: &HashMap<String, Value>, bot: Option<&str>) -> (Value, Option<Inbound>) {
    let name = param(ev, "dialog").unwrap_or("").to_string();
    match ev["dialogEventType"].as_str().unwrap_or("REQUEST_DIALOG") {
        "SUBMIT_DIALOG" | "CANCEL_DIALOG" => {
            let submit = ev["dialogEventType"] == "SUBMIT_DIALOG";
            let shown = if name.is_empty() { str_of(&ev["common"]["invokedFunction"]).to_string() } else { name };
            let mut text = format!("[Google Chat dialog {shown} {}]", if submit { "submitted" } else { "closed" });
            if submit {
                for l in form_lines(ev) {
                    text.push('\n');
                    text.push_str(&l);
                }
            }
            let m = event_parts(ev).and_then(|(_, msg, space, user)| {
                let chat = space["name"].as_str().or_else(|| msg["name"].as_str().and_then(|n| n.split("/messages/").next()))?.to_string();
                if user["type"] == "BOT" || bot.is_some_and(|b| user["name"] == b) {
                    return None;
                }
                let is_dm = space["spaceType"] == "DIRECT_MESSAGE" || space["type"] == "DM" || space["singleUserBotDm"] == true;
                Some(Inbound {
                    channel: channel.to_string(),
                    chat,
                    chat_type: if is_dm { ChatType::Direct } else { ChatType::Group },
                    thread: msg["thread"]["name"].as_str().filter(|_| !is_dm).map(str::to_string),
                    sender: str_of(&user["name"]).to_string(),
                    sender_name: str_of(&user["displayName"]).to_string(),
                    text: text.clone(),
                    message_id: format!("dialog:{shown}@{}", str_of(&ev["eventTime"])),
                    ts: ev["eventTime"].as_str().and_then(parse_rfc3339).unwrap_or(0),
                    mentioned: true,
                    ..Default::default()
                })
            });
            (dialog_status("OK", ""), m)
        }
        _ => match dialog_body(dialogs, &name) {
            Some(body) => (json!({"actionResponse": {"type": "DIALOG", "dialogAction": {"dialog": {"body": body}}}}), None),
            None => (dialog_status("NOT_FOUND", "This dialog is not available."), None),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn handle(v: &Verifier, path: &str, channel: &str, bot: Option<&str>, tx: &Mutex<Sender<Inbound>>, sent: &Mutex<HashSet<String>>, dialogs: &HashMap<String, Value>, r: seagent_net::httpd::Request) -> seagent_net::httpd::Response {
    use seagent_net::httpd::Response;
    if r.path != path {
        return Response::text(404, "not found");
    }
    if r.method != "POST" {
        return Response::text(405, "use POST");
    }
    if let Err(e) = v.check(r.bearer()) {
        return Response::text(401, &format!("unauthorized: {e}"));
    }
    let Ok(ev) = serde_json::from_slice::<Value>(&r.body) else { return Response::text(400, "bad json") };
    if ev["isDialogEvent"] == true || param(&ev, "seagent_dialog").is_some() {
        let (resp, m) = dialog_event(channel, &ev, dialogs, bot);
        if let Some(m) = m {
            if tx.lock().unwrap().send(m).is_err() {
                return Response::text(503, "channel closed");
            }
        }
        return Response::json(200, &resp.to_string());
    }
    let sent = sent.lock().unwrap().clone();
    if let Some(m) = inbound_of(channel, &ev, bot, &|id| sent.contains(id), None) {
        if tx.lock().unwrap().send(m).is_err() {
            return Response::text(503, "channel closed");
        }
    }
    Response::json(200, &"{}")
}

fn cards(rows: &[Vec<crate::Button>]) -> Value {
    let buttons: Vec<Value> = rows
        .iter()
        .flatten()
        .map(|b| match &b.url {
            Some(u) => json!({"text": b.label, "onClick": {"openLink": {"url": u}}}),
            None => match b.data.strip_prefix("dialog:") {
                Some(name) => json!({"text": b.label, "onClick": {"action": {"function": "seagent_dialog", "interaction": "OPEN_DIALOG", "parameters": [{"key": "dialog", "value": name}, {"key": "seagent_dialog", "value": "1"}]}}}),
                None => json!({"text": b.label, "onClick": {"action": {"function": "seagent", "parameters": [{"key": "data", "value": b.data}]}}}),
            },
        })
        .collect();
    json!([{"cardId": "seagent-buttons", "card": {"sections": [{"widgets": [{"buttonList": {"buttons": buttons}}]}]}}])
}

impl Channel for GoogleChat {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group],
            media: true,
            reply: true,
            threads: true,
            reactions: if self.user_oauth.is_some() { 20 } else { 0 },
            edit: true,
            delete: true,
            typing: false,
            buttons: true,
            polls: false,
            native_commands: true,
            streaming: Streaming::Edit,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::SlackMrkdwn,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        if self.subscription.is_some() {
            return self.pull(cancel);
        }
        Ok(drain(&self.rx, self.poll_timeout, cancel))
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let mut links = vec![];
        let mut files = vec![];
        for m in &out.media {
            match (&m.url, &m.path) {
                (Some(u), _) if u.starts_with("http://") || u.starts_with("https://") => links.push(u.clone()),
                (_, Some(_)) if self.user_oauth.is_some() => files.push(m),
                _ => return Err(ChannelError::new(K::Unsupported, "google chat apps can only send attachments as remote http(s) URLs (local files need user_oauth)")),
            }
        }
        let body_text = if out.format == TextFormat::Markdown { to_chat_text(&out.text) } else { out.text.clone() };
        let full = [body_text.trim_end().to_string(), links.join("\n")].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join("\n\n");
        let thread = self.thread_of(out)?;
        let mut url = format!("{}/{}/messages", self.api, out.chat.trim_matches('/'));
        if thread.is_some() {
            url.push_str("?messageReplyOption=REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD");
        }
        let mut pieces = crate::chunk::split(&full, MAX_MESSAGE, LenUnit::Chars);
        if pieces.is_empty() && !out.buttons.is_empty() {
            pieces.push(String::new());
        }
        let n = pieces.len();
        let mut sent = Sent::default();
        for (i, piece) in pieces.into_iter().enumerate() {
            let mut body = json!({"text": piece});
            if let Some(t) = &thread {
                body["thread"] = t.clone();
            }
            if i + 1 == n && !out.buttons.is_empty() {
                body["cardsV2"] = cards(&out.buttons);
            }
            let r = self.api_call("POST", &url, Some(&body))?;
            if let Some(name) = r["name"].as_str() {
                self.sent.lock().unwrap().insert(name.to_string());
                sent.ids.push(name.to_string());
            }
        }
        for m in files {
            let name = self.upload(out.chat.trim_matches('/'), thread.as_ref(), m)?;
            if !name.is_empty() {
                self.sent.lock().unwrap().insert(name.clone());
                sent.ids.push(name);
            }
        }
        Ok(sent)
    }

    fn edit(&self, _chat: &str, message_id: &str, text: &str) -> Result<(), ChannelError> {
        self.api_call("PATCH", &format!("{}/{message_id}?updateMask=text", self.api), Some(&json!({"text": to_chat_text(text)}))).map(|_| ())
    }

    fn delete(&self, _chat: &str, message_id: &str) -> Result<(), ChannelError> {
        self.api_call("DELETE", &format!("{}/{message_id}", self.api), None).map(|_| ())
    }

    /// Reactions exist only with user auth: created as the configured user; removal deletes
    /// the reaction we made (or the user's matching one, found by listing).
    fn react(&self, _chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        let e = emoji.trim();
        let key = format!("{message_id}\u{1f}{e}");
        if !remove {
            let v = self.user_call("POST", &format!("{}/{message_id}/reactions", self.api), Payload::Json(&json!({"emoji": {"unicode": e}})))?;
            if let Some(n) = v["name"].as_str() {
                let mut r = self.reactions.lock().unwrap();
                if r.len() > 2000 {
                    r.clear();
                }
                r.insert(key, n.to_string());
            }
            return Ok(());
        }
        let name = match self.reactions.lock().unwrap().remove(&key) {
            Some(n) => n,
            None => {
                let filter = seagent_net::urlencode(&format!("emoji.unicode = \"{e}\""));
                let v = self.user_call("GET", &format!("{}/{message_id}/reactions?filter={filter}", self.api), Payload::None)?;
                match v["reactions"].as_array().and_then(|a| a.first()).and_then(|r| r["name"].as_str()) {
                    Some(n) => n.to_string(),
                    None => return Ok(()),
                }
            }
        };
        self.user_call("DELETE", &format!("{}/{name}", self.api), Payload::None).map(|_| ())
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let auth = format!("Bearer {}", self.access_token()?);
        if let Some(res) = &m.id {
            return crate::http::get_bytes(&format!("{}/media/{res}?alt=media", self.api), &[("authorization", &auth)], 50 * 1024 * 1024);
        }
        let url = m.url.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "attachment without resource name or url"))?;
        let host = seagent_net::Url::parse(url).map(|u| u.host).unwrap_or_default();
        // Only send our token to Google.
        if host.ends_with(".google.com") || host.ends_with(".googleapis.com") || host.ends_with(".googleusercontent.com") {
            crate::http::get_bytes(url, &[("authorization", &auth)], 50 * 1024 * 1024)
        } else {
            Err(ChannelError::new(K::Protocol, "refusing to fetch a Google Chat attachment from a non-Google host"))
        }
    }
}

fn d_poll() -> u64 {
    25
}
fn d_path() -> String {
    "/googlechat".into()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    /// Service-account JSON key (inline, usually `{{secret:…}}`) …
    #[serde(default)]
    service_account: Option<String>,
    /// … or a path to it.
    #[serde(default)]
    service_account_file: Option<String>,
    #[serde(default)]
    listen: Option<String>,
    #[serde(default = "d_path")]
    path: String,
    /// "project-number" (default) or "app-url".
    #[serde(default)]
    audience_type: Option<String>,
    #[serde(default)]
    audience: Option<String>,
    /// Pub/Sub pull mode: projects/<p>/subscriptions/<s>.
    #[serde(default)]
    subscription: Option<String>,
    /// The app's `users/<id>`, for exact @mention detection.
    #[serde(default)]
    bot_user: Option<String>,
    #[serde(default)]
    api_base: Option<String>,
    #[serde(default)]
    pubsub_base: Option<String>,
    #[serde(default)]
    jwks_url: Option<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    /// name → dialog card (table or JSON string); buttons `dialog:<name>` open it.
    #[serde(default)]
    dialogs: HashMap<String, Value>,
    /// A user's OAuth client + refresh token, for uploads and reactions (posted as that user).
    #[serde(default)]
    user_oauth: Option<UserOAuth>,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let sa_json = match (ctx.opt_secret("service_account", &st.service_account)?, &st.service_account_file) {
        (Some(j), _) => j,
        (None, Some(f)) => std::fs::read_to_string(f).map_err(|e| format!("channel {}: cannot read service_account_file {f}: {e}", ctx.name))?,
        (None, None) => return Err(format!("channel {}: google chat needs service_account or service_account_file", ctx.name)),
    };
    let sa = ServiceAccount::from_json(&sa_json).map_err(|e| format!("channel {}: {e}", ctx.name))?;
    let audience_type = match st.audience_type.as_deref().unwrap_or("project-number") {
        "project-number" | "project_number" => Audience::ProjectNumber,
        "app-url" | "app_url" => Audience::AppUrl,
        other => return Err(format!("channel {}: audience_type must be project-number or app-url, not {other}", ctx.name)),
    };
    let audience = ctx.opt_secret("audience", &st.audience)?;
    let mut dialogs = HashMap::new();
    for (name, v) in st.dialogs {
        let v = match v {
            Value::String(j) => serde_json::from_str(&j).map_err(|e| format!("channel {}: dialog {name}: {e}", ctx.name))?,
            v @ Value::Object(_) => v,
            _ => return Err(format!("channel {}: dialog {name} must be a table or a JSON string", ctx.name)),
        };
        dialogs.insert(name, v);
    }
    let user_oauth = match st.user_oauth {
        Some(u) => Some(UserOAuth {
            client_id: ctx.secret("user_oauth.client_id", &u.client_id)?,
            client_secret: ctx.secret("user_oauth.client_secret", &u.client_secret)?,
            refresh_token: ctx.secret("user_oauth.refresh_token", &u.refresh_token)?,
            token_url: u.token_url,
        }),
        None => None,
    };
    if !dialogs.is_empty() && st.listen.is_none() {
        eprintln!("seagent: channel {}: dialogs need the HTTP endpoint (listen); Pub/Sub cannot answer them", ctx.name);
    }
    let g = GoogleChat::new(
        ctx.name,
        GoogleChatOpts {
            sa,
            listen: st.listen.as_deref(),
            path: &st.path,
            audience_type,
            audience: audience.as_deref(),
            jwks_url: st.jwks_url.as_deref(),
            subscription: st.subscription.as_deref(),
            bot_user: st.bot_user.as_deref(),
            api_base: st.api_base.as_deref().unwrap_or(DEFAULT_API),
            pubsub_base: st.pubsub_base.as_deref().unwrap_or(DEFAULT_PUBSUB),
            poll_timeout: Duration::from_secs(st.poll_timeout_secs),
            dialogs,
            user_oauth,
        },
    )?;
    Ok(Arc::new(g))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msteams::tests::{jwt, test_jwk, TEST_KEY_PEM};
    use crate::testutil::FakeServer;

    type Reply = (u16, Vec<(String, String)>, String);

    fn jr(v: Value) -> Reply {
        (200, vec![("content-type".into(), "application/json".into())], v.to_string())
    }

    fn sa(token_uri: &str) -> ServiceAccount {
        ServiceAccount::from_json(&json!({"type": "service_account", "client_email": "bot@proj.iam.gserviceaccount.com", "private_key": TEST_KEY_PEM, "private_key_id": "sakid", "token_uri": token_uri}).to_string()).unwrap()
    }

    /// Fake Google: token endpoint, JWKS, Chat API and Pub/Sub, answering `api` for the rest.
    fn fake(api: impl Fn(&crate::testutil::Req, usize) -> Reply + Send + 'static) -> FakeServer {
        FakeServer::start(move |req, n| match req.path.as_str() {
            "/token" => jr(json!({"access_token": "GTOKEN", "expires_in": 3600})),
            "/jwks" => jr(json!({"keys": [test_jwk("gk", &[])]})),
            _ => api(req, n),
        })
    }

    fn gc(srv: &str, listen: Option<&str>, aud: Audience, subscription: Option<&str>) -> GoogleChat {
        let mut g = GoogleChat::new(
            "gchat",
            GoogleChatOpts {
                sa: sa(&format!("{srv}/token")),
                listen,
                path: "/googlechat",
                audience_type: aud,
                audience: Some(if aud == Audience::ProjectNumber { "123456" } else { "https://bot.example.com/googlechat" }),
                jwks_url: Some(&format!("{srv}/jwks")),
                subscription,
                bot_user: Some("users/BOT"),
                api_base: &format!("{srv}/v1"),
                pubsub_base: &format!("{srv}/ps"),
                poll_timeout: Duration::from_millis(300),
                dialogs: HashMap::from([("ticket".to_string(), json!({"header": {"title": "New ticket"}, "sections": [{"widgets": [{"textInput": {"label": "Title", "name": "title"}}]}]}))]),
                user_oauth: None,
            },
        )
        .unwrap();
        g.retry_base = Duration::from_millis(5);
        g
    }

    fn post(addr: std::net::SocketAddr, token: Option<&str>, body: &Value) -> u16 {
        let a = crate::http::agent(Duration::from_secs(5));
        let mut req = a.post(&format!("http://{addr}/googlechat"));
        if let Some(t) = token {
            req = req.header("authorization", &format!("Bearer {t}"));
        }
        req.send(body.to_string().as_bytes()).map(|r| r.status().as_u16()).unwrap_or(0)
    }

    fn chat_claims() -> Value {
        json!({"iss": CHAT_ISSUER, "aud": "123456", "iat": now_secs(), "exp": now_secs() + 3600})
    }

    fn msg_event(space: Value, msg: Value) -> Value {
        let mut m = json!({"name": "spaces/S/messages/M1", "sender": {"name": "users/42", "displayName": "Amy", "email": "amy@x.com", "type": "HUMAN"}, "createTime": "2024-01-02T03:04:05.5Z", "text": "hello", "thread": {"name": "spaces/S/threads/T1"}});
        for (k, v) in msg.as_object().unwrap() {
            m[k] = v.clone();
        }
        json!({"type": "MESSAGE", "eventTime": "2024-01-02T03:04:06Z", "space": space, "message": m, "user": m["sender"].clone()})
    }

    fn dm() -> Value {
        json!({"name": "spaces/D", "type": "DM", "spaceType": "DIRECT_MESSAGE", "singleUserBotDm": true})
    }
    fn room() -> Value {
        json!({"name": "spaces/S", "type": "ROOM", "spaceType": "SPACE", "displayName": "Team"})
    }

    #[test]
    fn http_events_need_a_google_signed_token() {
        let srv = fake(|_, _| jr(json!({})));
        let g = gc(&srv.url, Some("127.0.0.1:0"), Audience::ProjectNumber, None);
        let a = g.local_addr().unwrap();
        let ev = msg_event(dm(), json!({}));
        assert_eq!(post(a, None, &ev), 401);
        let mut wrong = chat_claims();
        wrong["aud"] = json!("999");
        assert_eq!(post(a, Some(&jwt("gk", wrong)), &ev), 401, "audience = project number");
        let mut iss = chat_claims();
        iss["iss"] = json!("someone@else.iam.gserviceaccount.com");
        assert_eq!(post(a, Some(&jwt("gk", iss)), &ev), 401, "issuer = chat service account");
        let mut old = chat_claims();
        old["exp"] = json!(now_secs() - 1000);
        assert_eq!(post(a, Some(&jwt("gk", old)), &ev), 401, "expired");
        let mut forged = jwt("gk", chat_claims());
        forged.truncate(forged.len() - 4);
        forged.push_str("AAAA");
        assert_eq!(post(a, Some(&forged), &ev), 401, "bad signature");
        assert_eq!(post(a, Some(&jwt("gk", chat_claims())), &ev), 200);
        assert_eq!(g.poll(&Cancel::new()).unwrap().len(), 1);
        // app-url mode: Google OIDC token whose email is the Chat service account.
        let g = gc(&srv.url, Some("127.0.0.1:0"), Audience::AppUrl, None);
        let a = g.local_addr().unwrap();
        let oidc = |email: &str, verified: bool| jwt("gk", json!({"iss": "https://accounts.google.com", "aud": "https://bot.example.com/googlechat", "email": email, "email_verified": verified, "exp": now_secs() + 600}));
        assert_eq!(post(a, Some(&oidc("mallory@gmail.com", true)), &ev), 401);
        assert_eq!(post(a, Some(&oidc(CHAT_ISSUER, false)), &ev), 401);
        assert_eq!(post(a, Some(&jwt("gk", chat_claims())), &ev), 401, "project-number token is not an app-url token");
        assert_eq!(post(a, Some(&oidc(CHAT_ISSUER, true)), &ev), 200);
    }

    #[test]
    fn parses_dm_room_threads_mentions_commands_cards_attachments() {
        let none = |_: &str| false;
        let own = |id: &str| id == "spaces/S/messages/OWN";
        let p = |ev: &Value| inbound_of("gc", ev, Some("users/BOT"), &own, None);
        let d = p(&msg_event(dm(), json!({}))).unwrap();
        assert_eq!((d.chat.as_str(), d.chat_type, d.sender.as_str(), d.sender_name.as_str(), d.text.as_str(), d.message_id.as_str()), ("spaces/D", ChatType::Direct, "users/42", "Amy", "hello", "spaces/S/messages/M1"));
        assert_eq!(d.thread, None, "DM top-level messages are not threads");
        assert_eq!(d.ts, 1704164645);
        let r = p(&msg_event(room(), json!({"text": "@Seagent do it", "argumentText": " do it", "annotations": [{"type": "USER_MENTION", "startIndex": 0, "length": 4, "userMention": {"user": {"name": "users/BOT", "type": "BOT"}, "type": "MENTION"}}]}))).unwrap();
        assert!(r.mentioned && r.text == "do it" && r.chat_type == ChatType::Group && r.chat_name == "Team");
        assert_eq!(r.thread.as_deref(), Some("spaces/S/threads/T1"));
        let other = p(&msg_event(room(), json!({"annotations": [{"type": "USER_MENTION", "userMention": {"user": {"name": "users/7", "type": "HUMAN"}}}]}))).unwrap();
        assert!(!other.mentioned);
        assert!(p(&msg_event(room(), json!({"sender": {"name": "users/BOT", "type": "BOT"}}))).is_none(), "own message dropped");
        assert!(p(&msg_event(room(), json!({"sender": {"name": "users/9", "type": "BOT"}}))).is_none(), "other bots dropped");
        let cmd = p(&msg_event(dm(), json!({"text": "now", "argumentText": "now", "annotations": [{"type": "SLASH_COMMAND", "slashCommand": {"commandName": "/new", "commandId": "1"}}]}))).unwrap();
        assert_eq!(cmd.text, "/new now");
        let rep = p(&msg_event(room(), json!({"quotedMessageMetadata": {"name": "spaces/S/messages/OWN"}}))).unwrap();
        assert!(rep.reply.as_ref().unwrap().is_own && rep.addressed());
        let att = p(&msg_event(dm(), json!({"text": "", "attachment": [
            {"name": "a1", "contentName": "cat.png", "contentType": "image/png", "attachmentDataRef": {"resourceName": "RES1"}, "downloadUri": "https://chat.google.com/dl/1", "source": "UPLOADED_CONTENT"},
            {"contentName": "doc", "contentType": "application/pdf", "source": "DRIVE_FILE", "driveDataRef": {"driveFileId": "x"}}]}))).unwrap();
        assert_eq!(att.media.len(), 1, "drive-picker share skipped");
        assert_eq!((att.media[0].kind, att.media[0].id.as_deref(), att.media[0].name.as_str()), (crate::MediaKind::Image, Some("RES1"), "cat.png"));
        let click = json!({"type": "CARD_CLICKED", "eventTime": "2024-01-02T03:04:07Z", "space": room(), "user": {"name": "users/42", "displayName": "Amy"}, "message": {"name": "spaces/S/messages/OWN"}, "action": {"actionMethodName": "seagent", "parameters": [{"key": "data", "value": "appr:1:once"}]}});
        let c = inbound_of("gc", &click, None, &none, None).unwrap();
        assert_eq!(c.callback.as_ref().unwrap().data, "appr:1:once");
        assert_eq!(c.sender, "users/42");
        let addon = json!({"commonEventObject": {"parameters": {"data": "cl:2:1"}}, "chat": {"user": {"name": "users/42"}, "buttonClickedPayload": {"space": room(), "message": {"name": "spaces/S/messages/OWN"}}}});
        assert_eq!(inbound_of("gc", &addon, None, &none, None).unwrap().callback.unwrap().data, "cl:2:1");
        let addon_msg = json!({"chat": {"user": {"name": "users/42"}, "messagePayload": {"space": dm(), "message": {"name": "spaces/D/messages/X", "text": "via addon", "sender": {"name": "users/42", "type": "HUMAN"}}}}});
        assert_eq!(inbound_of("gc", &addon_msg, None, &none, None).unwrap().text, "via addon");
        assert!(inbound_of("gc", &json!({"type": "ADDED_TO_SPACE", "space": room(), "user": {"name": "users/42"}}), None, &none, None).is_none());
        assert!(inbound_of("gc", &json!({"type": "REMOVED_FROM_SPACE", "space": room()}), None, &none, None).is_none());
    }

    #[test]
    fn send_signs_a_service_account_jwt_and_shapes_messages() {
        let srv = fake(|req, n| match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/v1/spaces/S/messages/Q") => jr(json!({"name": "spaces/S/messages/Q", "thread": {"name": "spaces/S/threads/TQ"}})),
            ("GET", p) if p.starts_with("/v1/media/") => (200, vec![], "PNGDATA".into()),
            ("POST", _) => jr(json!({"name": format!("spaces/S/messages/N{n}")})),
            _ => jr(json!({})),
        });
        let g = gc(&srv.url, Some("127.0.0.1:0"), Audience::ProjectNumber, None);
        let out = Outbound {
            format: TextFormat::Markdown,
            thread: Some("spaces/S/threads/T1".into()),
            buttons: vec![vec![crate::Button { label: "OK".into(), data: "appr:x:once".into(), url: None }, crate::Button { label: "docs".into(), data: String::new(), url: Some("https://e.com".into()) }]],
            ..Outbound::text("spaces/S", "**bold** and [site](https://e.com) a<b")
        };
        let s = g.send(&out).unwrap();
        assert_eq!(s.ids.len(), 1);
        let reqs = srv.requests();
        // Token: JWT-bearer grant signed with the service-account key.
        assert_eq!(reqs[0].path, "/token");
        let form = seagent_net::parse_query(&reqs[0].body);
        let get = |k: &str| form.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap();
        assert_eq!(get("grant_type"), "urn:ietf:params:oauth:grant-type:jwt-bearer");
        let jwks = JwksCache::new(&format!("{}/jwks", srv.url), false);
        let header: Value = serde_json::from_slice(&seagent_net::crypto::b64url_decode(get("assertion").split('.').next().unwrap()).unwrap()).unwrap();
        assert_eq!(header["kid"], "sakid");
        let assertion = get("assertion").replacen(get("assertion").split('.').next().unwrap(), &seagent_net::crypto::b64url(json!({"alg": "RS256", "kid": "gk"}).to_string().as_bytes()), 1);
        assert!(verify_rs256(&assertion, &jwks, now_secs(), 0).is_err(), "header is signed too");
        let claims: Value = serde_json::from_slice(&seagent_net::crypto::b64url_decode(get("assertion").split('.').nth(1).unwrap()).unwrap()).unwrap();
        assert_eq!((claims["iss"].as_str(), claims["scope"].as_str()), (Some("bot@proj.iam.gserviceaccount.com"), Some(SCOPE_CHAT)));
        assert_eq!(claims["aud"], format!("{}/token", srv.url));
        let r = &reqs[1];
        assert_eq!(r.path, "/v1/spaces/S/messages?messageReplyOption=REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD");
        assert_eq!(r.header("authorization"), Some("Bearer GTOKEN"));
        let b = r.json();
        assert_eq!(b["text"], "*bold* and <https://e.com|site> a<b");
        assert_eq!(b["thread"]["name"], "spaces/S/threads/T1");
        let btns = &b["cardsV2"][0]["card"]["sections"][0]["widgets"][0]["buttonList"]["buttons"];
        assert_eq!(btns[0]["onClick"]["action"]["parameters"][0], json!({"key": "data", "value": "appr:x:once"}));
        assert_eq!(btns[1]["onClick"]["openLink"]["url"], "https://e.com");
        // threadKey, reply_to → the quoted message's thread, plain top-level.
        g.send(&Outbound { thread: Some("ticket-7".into()), ..Outbound::text("spaces/S", "k") }).unwrap();
        assert_eq!(srv.requests().last().unwrap().json()["thread"], json!({"threadKey": "ticket-7"}));
        g.send(&Outbound { reply_to: Some("spaces/S/messages/Q".into()), ..Outbound::text("spaces/S", "r") }).unwrap();
        let reqs = srv.requests();
        assert_eq!(reqs[reqs.len() - 2].path, "/v1/spaces/S/messages/Q");
        assert_eq!(reqs.last().unwrap().json()["thread"]["name"], "spaces/S/threads/TQ");
        g.send(&Outbound { media: vec![Media { url: Some("https://e.com/a.png".into()), ..Default::default() }], ..Outbound::text("spaces/D", "see") }).unwrap();
        let last = srv.requests().last().unwrap().clone();
        assert_eq!(last.path, "/v1/spaces/D/messages");
        assert_eq!(last.json(), json!({"text": "see\n\nhttps://e.com/a.png"}));
        let e = g.send(&Outbound { media: vec![Media { path: Some("/tmp/x.png".into()), ..Default::default() }], ..Outbound::text("spaces/D", "x") }).unwrap_err();
        assert_eq!(e.kind, K::Unsupported);
        g.edit("spaces/S", "spaces/S/messages/N1", "new **t**").unwrap();
        g.delete("spaces/S", "spaces/S/messages/N1").unwrap();
        let reqs = srv.requests();
        let tail: Vec<(String, String)> = reqs[reqs.len() - 2..].iter().map(|r| (r.method.clone(), r.path.clone())).collect();
        assert_eq!(tail, [("PATCH".to_string(), "/v1/spaces/S/messages/N1?updateMask=text".to_string()), ("DELETE".to_string(), "/v1/spaces/S/messages/N1".to_string())]);
        assert_eq!(reqs[reqs.len() - 2].json()["text"], "new *t*");
        assert_eq!(g.fetch_media(&Media { id: Some("RES1".into()), ..Default::default() }).unwrap(), b"PNGDATA");
        assert_eq!(srv.requests().last().unwrap().path, "/v1/media/RES1?alt=media");
        assert!(g.fetch_media(&Media { url: Some("https://evil.example/x".into()), ..Default::default() }).is_err(), "token never sent off-Google");
        assert_eq!(srv.requests().iter().filter(|r| r.path == "/token").count(), 1, "token cached");
        assert_eq!(g.typing("spaces/S", None).unwrap_err().kind, K::Unsupported);
    }

    #[test]
    fn errors_map_and_retry() {
        let srv = FakeServer::start(|_, _| (400, vec![], json!({"error": "invalid_grant", "error_description": "Invalid JWT Signature."}).to_string()));
        let g = gc(&srv.url, Some("127.0.0.1:0"), Audience::ProjectNumber, None);
        assert_eq!(g.send(&Outbound::text("spaces/S", "x")).unwrap_err().kind, K::Auth);
        let srv = fake(|req, n| match req.path.as_str() {
            p if p.contains("removed") => (403, vec![], json!({"error": {"code": 403, "status": "PERMISSION_DENIED", "message": "not a member"}}).to_string()),
            p if p.contains("gone") => (404, vec![], json!({"error": {"code": 404, "status": "NOT_FOUND"}}).to_string()),
            p if p.contains("slow") && n % 2 == 1 => (429, vec![("Retry-After".into(), "1".into())], json!({"error": {"status": "RESOURCE_EXHAUSTED"}}).to_string()),
            p if p.contains("down") => (503, vec![], String::new()),
            _ => jr(json!({"name": "spaces/x/messages/1"})),
        });
        let g = gc(&srv.url, Some("127.0.0.1:0"), Audience::ProjectNumber, None);
        assert_eq!(g.send(&Outbound::text("spaces/removed", "x")).unwrap_err().kind, K::NotFound);
        assert_eq!(g.send(&Outbound::text("spaces/gone", "x")).unwrap_err().kind, K::NotFound);
        let start = Instant::now();
        assert_eq!(g.send(&Outbound::text("spaces/slow", "x")).unwrap().ids, vec!["spaces/x/messages/1"]);
        assert!(start.elapsed() >= Duration::from_millis(900));
        let before = srv.requests().len();
        assert_eq!(g.send(&Outbound::text("spaces/down", "x")).unwrap_err().kind, K::Network);
        assert_eq!(srv.requests().len() - before, 4);
    }

    #[test]
    fn pubsub_pull_decodes_events_and_acks_on_next_poll() {
        let data = |v: Value| seagent_net::crypto::b64(v.to_string().as_bytes());
        let created = json!({"message": {"name": "spaces/S/messages/CE1", "text": "cloud event", "sender": {"name": "users/42", "type": "HUMAN"}, "space": {"name": "spaces/S", "spaceType": "SPACE"}}});
        let updated = json!({"message": {"name": "spaces/S/messages/CE1", "text": "edited", "lastUpdateTime": "2024-01-02T03:04:09Z", "sender": {"name": "users/42", "type": "HUMAN"}}});
        let batch = json!({"receivedMessages": [
            {"ackId": "A1", "message": {"data": data(msg_event(dm(), json!({}))), "messageId": "1"}},
            {"ackId": "A2", "message": {"data": data(created), "attributes": {"ce-type": "google.workspace.chat.message.v1.created"}}},
            {"ackId": "A3", "message": {"data": data(updated), "attributes": {"ce-type": "google.workspace.chat.message.v1.updated"}}},
            {"ackId": "A4", "message": {"data": "!!notbase64"}}]});
        let srv = fake(move |req, _| match req.path.as_str() {
            p if p.ends_with(":pull") => jr(batch.clone()),
            p if p.ends_with(":acknowledge") => jr(json!({})),
            _ => jr(json!({})),
        });
        let g = gc(&srv.url, None, Audience::ProjectNumber, Some("projects/p/subscriptions/s"));
        let got = g.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 3, "{got:#?}");
        assert_eq!(got[0].text, "hello");
        assert_eq!((got[1].text.as_str(), got[1].chat.as_str()), ("cloud event", "spaces/S"));
        assert!(got[2].edited && got[2].message_id == "spaces/S/messages/CE1:e1704164649" && got[2].chat == "spaces/S");
        let reqs = srv.requests();
        assert_eq!(reqs[1].path, "/ps/projects/p/subscriptions/s:pull");
        assert_eq!(reqs[1].header("authorization"), Some("Bearer GTOKEN"));
        assert!(!reqs.iter().any(|r| r.path.ends_with(":acknowledge")), "not acked before the next poll");
        let tok = form_claims(&reqs[0].body);
        assert_eq!(tok["scope"], format!("{SCOPE_CHAT} {SCOPE_PUBSUB}"));
        g.poll(&Cancel::new()).unwrap();
        let ack = srv.requests().into_iter().find(|r| r.path.ends_with(":acknowledge")).unwrap();
        assert_eq!(ack.json()["ackIds"], json!(["A1", "A2", "A3", "A4"]));
        // Empty pulls wait out the poll timeout; cancel returns promptly.
        let srv = fake(|_, _| jr(json!({})));
        let mut g = gc(&srv.url, None, Audience::ProjectNumber, Some("projects/p/subscriptions/s"));
        g.poll_timeout = Duration::from_secs(30);
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            c2.cancel();
        });
        let start = Instant::now();
        assert!(g.poll(&c).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(GoogleChat::new("x", GoogleChatOpts { sa: sa("http://t"), listen: None, path: "/", audience_type: Audience::ProjectNumber, audience: None, jwks_url: None, subscription: None, bot_user: None, api_base: "", pubsub_base: "", poll_timeout: Duration::ZERO, dialogs: HashMap::new(), user_oauth: None }).is_err());
        assert!(GoogleChat::new("x", GoogleChatOpts { sa: sa("http://t"), listen: None, path: "/", audience_type: Audience::ProjectNumber, audience: None, jwks_url: None, subscription: Some("bad"), bot_user: None, api_base: "", pubsub_base: "", poll_timeout: Duration::ZERO, dialogs: HashMap::new(), user_oauth: None }).is_err());
    }

    fn form_claims(body: &str) -> Value {
        let form = seagent_net::parse_query(body);
        let a = &form.iter().find(|(k, _)| k == "assertion").unwrap().1;
        serde_json::from_slice(&seagent_net::crypto::b64url_decode(a.split('.').nth(1).unwrap()).unwrap()).unwrap()
    }

    fn post_body(addr: std::net::SocketAddr, body: &Value) -> (u16, Value) {
        let a = crate::http::agent(Duration::from_secs(5));
        let mut r = a.post(&format!("http://{addr}/googlechat")).header("authorization", &format!("Bearer {}", jwt("gk", chat_claims()))).send(body.to_string().as_bytes()).unwrap();
        (r.status().as_u16(), serde_json::from_str(&r.body_mut().read_to_string().unwrap_or_default()).unwrap_or_default())
    }

    #[test]
    fn dialogs_open_submit_and_cancel_synchronously() {
        let srv = fake(|_, n| jr(json!({"name": format!("spaces/S/messages/N{n}")})));
        let g = gc(&srv.url, Some("127.0.0.1:0"), Audience::ProjectNumber, None);
        let a = g.local_addr().unwrap();
        // The opener button asks Chat for a dialog interaction.
        g.send(&Outbound { buttons: vec![vec![crate::Button { label: "New ticket".into(), data: "dialog:ticket".into(), url: None }]], ..Outbound::text("spaces/S", "file one?") }).unwrap();
        let b = srv.requests().iter().find(|r| r.path == "/v1/spaces/S/messages").unwrap().json();
        let action = &b["cardsV2"][0]["card"]["sections"][0]["widgets"][0]["buttonList"]["buttons"][0]["onClick"]["action"];
        assert_eq!((action["interaction"].as_str(), action["parameters"][0]["value"].as_str()), (Some("OPEN_DIALOG"), Some("ticket")));
        let click = |typ: &str, params: Value, extra: Value| {
            let mut ev = json!({"type": "CARD_CLICKED", "eventTime": "2024-01-02T03:04:07Z", "isDialogEvent": true, "dialogEventType": typ, "space": room(), "user": {"name": "users/42", "displayName": "Amy"}, "message": {"name": "spaces/S/messages/OWN", "thread": {"name": "spaces/S/threads/T1"}}, "common": {"parameters": params}});
            for (k, v) in extra.as_object().unwrap() {
                ev["common"][k] = v.clone();
            }
            ev
        };
        let (st, resp) = post_body(a, &click("REQUEST_DIALOG", json!({"dialog": "ticket", "seagent_dialog": "1"}), json!({})));
        assert_eq!(st, 200);
        let body = &resp["actionResponse"]["dialogAction"]["dialog"]["body"];
        assert_eq!((resp["actionResponse"]["type"].as_str(), body["header"]["title"].as_str()), (Some("DIALOG"), Some("New ticket")));
        assert_eq!(body["fixedFooter"]["primaryButton"]["onClick"]["action"]["parameters"][0], json!({"key": "dialog", "value": "ticket"}));
        let (_, resp) = post_body(a, &click("REQUEST_DIALOG", json!({"dialog": "nope"}), json!({})));
        assert_eq!(resp["actionResponse"]["dialogAction"]["actionStatus"]["statusCode"], "NOT_FOUND");
        // Submit closes the dialog (actionStatus OK) and reports the inputs.
        let inputs = json!({"formInputs": {"title": {"stringInputs": {"value": ["Printer on fire"]}}, "when": {"dateInput": {"msSinceEpoch": "1704164645000"}}, "at": {"timeInput": {"hours": 9, "minutes": 5}}}});
        let (_, resp) = post_body(a, &click("SUBMIT_DIALOG", json!({"dialog": "ticket"}), inputs.clone()));
        assert_eq!(resp, json!({"actionResponse": {"type": "DIALOG", "dialogAction": {"actionStatus": {"statusCode": "OK", "userFacingMessage": ""}}}}));
        post_body(a, &click("CANCEL_DIALOG", json!({"dialog": "ticket"}), json!({})));
        // A non-dialog click carrying form inputs (submitForm) appends them to the data.
        let mut form_click = click("", json!({"data": "form:save"}), inputs);
        form_click.as_object_mut().unwrap().remove("isDialogEvent");
        form_click.as_object_mut().unwrap().remove("dialogEventType");
        assert_eq!(post_body(a, &form_click).0, 200);
        std::thread::sleep(Duration::from_millis(50));
        let got = g.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 3, "{got:#?}");
        assert_eq!(got[0].text, "[Google Chat dialog ticket submitted]\n- at: 09:05\n- title: Printer on fire\n- when: 1704164645");
        assert_eq!((got[0].chat.as_str(), got[0].thread.as_deref(), got[0].sender.as_str(), got[0].callback.is_none()), ("spaces/S", Some("spaces/S/threads/T1"), "users/42", true));
        assert_eq!(got[1].text, "[Google Chat dialog ticket closed]");
        assert_eq!(got[2].callback.as_ref().unwrap().data, "form:save\n- at: 09:05\n- title: Printer on fire\n- when: 1704164645");
    }

    #[test]
    fn user_oauth_uploads_and_reactions() {
        let srv = fake(|req, n| match (req.method.as_str(), req.path.as_str()) {
            (_, "/utoken") => jr(json!({"access_token": "UTOKEN", "expires_in": 3600})),
            (_, p) if p.starts_with("/upload/v1/") => jr(json!({"attachmentDataRef": {"resourceName": "RES9", "attachmentUploadToken": "UPT"}})),
            ("POST", p) if p.ends_with("/reactions") => jr(json!({"name": format!("spaces/S/messages/M1/reactions/R{n}")})),
            ("GET", p) if p.contains("/reactions?filter=") => jr(json!({"reactions": [{"name": "spaces/S/messages/M1/reactions/OLD"}]})),
            _ => jr(json!({"name": format!("spaces/S/messages/N{n}")})),
        });
        let mut g = gc(&srv.url, None, Audience::ProjectNumber, Some("projects/p/subscriptions/s"));
        assert_eq!(g.caps().reactions, 0);
        assert_eq!(g.react("spaces/S", "spaces/S/messages/M1", "👍", false).unwrap_err().kind, K::Unsupported);
        let f = crate::testutil::temp_dir("gchat").join("notes.txt");
        std::fs::write(&f, b"file body").unwrap();
        let local = Outbound { media: vec![Media { path: Some(f.display().to_string()), ..Default::default() }], ..Outbound::text("spaces/S", "see file") };
        assert_eq!(g.send(&local).unwrap_err().kind, K::Unsupported, "local files need user OAuth");
        g.user_oauth = Some(UserOAuth { client_id: "CID".into(), client_secret: "CSEC".into(), refresh_token: "RTOK".into(), token_url: Some(format!("{}/utoken", srv.url)) });
        assert_eq!(g.caps().reactions, 20);
        let ids = g.send(&Outbound { thread: Some("spaces/S/threads/T1".into()), ..local }).unwrap().ids;
        assert_eq!(ids.len(), 2, "text by the app, file by the user");
        let reqs = srv.requests();
        let tok: HashMap<String, String> = seagent_net::parse_query(&reqs.iter().find(|r| r.path == "/utoken").unwrap().body).into_iter().collect();
        assert_eq!((tok["grant_type"].as_str(), tok["refresh_token"].as_str(), tok["client_id"].as_str()), ("refresh_token", "RTOK", "CID"));
        let up = reqs.iter().find(|r| r.path.starts_with("/upload/")).unwrap();
        assert_eq!((up.path.as_str(), up.header("authorization")), ("/upload/v1/spaces/S/attachments:upload?uploadType=multipart", Some("Bearer UTOKEN")));
        assert!(up.header("content-type").unwrap().starts_with("multipart/related; boundary="));
        assert!(up.body.contains(r#"{"filename":"notes.txt"}"#) && up.body.contains("Content-Type: text/plain") && up.body.contains("file body"));
        let create = reqs.iter().rev().find(|r| r.path.starts_with("/v1/spaces/S/messages")).unwrap();
        assert_eq!(create.header("authorization"), Some("Bearer UTOKEN"));
        assert_eq!(create.json(), json!({"attachment": [{"attachmentDataRef": {"resourceName": "RES9", "attachmentUploadToken": "UPT"}}], "thread": {"name": "spaces/S/threads/T1"}}));
        // Reactions as the user; removal deletes what we created, else what the list finds.
        g.react("spaces/S", "spaces/S/messages/M1", "👍", false).unwrap();
        let add = srv.requests().last().unwrap().clone();
        assert_eq!((add.path.as_str(), add.json()), ("/v1/spaces/S/messages/M1/reactions", json!({"emoji": {"unicode": "👍"}})));
        g.react("spaces/S", "spaces/S/messages/M1", "👍", true).unwrap();
        let del = srv.requests().last().unwrap().clone();
        assert!(del.method == "DELETE" && del.path.starts_with("/v1/spaces/S/messages/M1/reactions/R"), "{del:?}");
        g.react("spaces/S", "spaces/S/messages/M1", "🎉", true).unwrap();
        let reqs = srv.requests();
        assert!(reqs[reqs.len() - 2].path.contains("/reactions?filter=emoji.unicode"));
        assert_eq!(reqs.last().unwrap().path, "/v1/spaces/S/messages/M1/reactions/OLD");
        assert_eq!(reqs.iter().filter(|r| r.path == "/utoken").count(), 1, "user token cached");
    }
}
