//! SMS / MMS through Twilio (kinds `sms`, `twilio`; ported from OpenClaw
//! `extensions/sms` and Hermes `plugins/platforms/sms`, both MIT).
//!
//! Receive: Twilio's form-encoded webhook (default `/webhooks/sms`), validated by
//! `X-Twilio-Signature` = base64 HMAC-SHA1(auth token, public URL + sorted
//! `key+value` POST params), with the default-port variant Twilio sometimes
//! signs. MMS media (`NumMedia`, `MediaUrl0..N`, `MediaContentType0..N`) is
//! fetched with Basic auth. STOP opt-outs are dropped (Twilio answers them).
//! Answered with empty TwiML; replies go out over the REST API.
//! Send: `POST /2010-04-01/Accounts/{sid}/Messages.json` (Basic auth, `From` or
//! `MessagingServiceSid`, `MediaUrl` ×≤10), plain text in ≤1600-char messages.
//! Local media files are served by our listener under `/sms/media/<token>/<file>`
//! (Twilio fetches media by public URL). Phone numbers are redacted in errors.

use crate::http::{classify, Http, Payload};
use crate::{markup, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, Sent, Streaming, TextFormat};
use seagent_core::Cancel;
use seagent_net::httpd::{Opts, Response, Server};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_API: &str = "https://api.twilio.com";
pub const MAX_MESSAGE: usize = 1600;
const MAX_MEDIA: usize = 10;
const MEDIA_PREFIX: &str = "/sms/media/";
const EMPTY_TWIML: &str = r#"<?xml version="1.0" encoding="UTF-8"?><Response></Response>"#;

type MediaMap = Arc<Mutex<HashMap<String, (PathBuf, Instant)>>>;

/// `+886912345678` → `+886****5678` (for logs and errors).
pub fn redact_phone(s: &str) -> String {
    let d: Vec<char> = s.chars().collect();
    if d.iter().filter(|c| c.is_ascii_digit()).count() < 7 {
        return s.to_string();
    }
    let keep_head = d.iter().position(char::is_ascii_digit).map(|i| i + 3).unwrap_or(0).min(d.len());
    let keep_tail = d.len().saturating_sub(4).max(keep_head);
    let mut out: String = d[..keep_head].iter().collect();
    out.push_str("****");
    out.extend(&d[keep_tail..]);
    out
}

/// Redact every phone-number-looking run (`+` and ≥7 digits) inside a message.
pub fn redact_phones_in(s: &str) -> String {
    let mut out = String::new();
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.chars().filter(char::is_ascii_digit).count() >= 7 {
            out.push_str(&redact_phone(run));
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in s.chars() {
        if c.is_ascii_digit() || (c == '+' && run.is_empty()) {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

fn sign(token: &str, url: &str, params: &[(String, String)]) -> String {
    let mut p: Vec<&(String, String)> = params.iter().collect();
    p.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let mut data = url.to_string();
    for (k, v) in p {
        data.push_str(k);
        data.push_str(v);
    }
    seagent_net::crypto::b64(&seagent_net::crypto::hmac_sha1(token.as_bytes(), data.as_bytes()))
}

/// The URL with the scheme's default port added or removed (Twilio signs either form).
fn port_variant(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let default = match scheme {
        "https" => 443,
        "http" => 80,
        _ => return None,
    };
    let (auth, path) = rest.find(['/', '?']).map(|i| (&rest[..i], &rest[i..])).unwrap_or((rest, ""));
    match auth.rsplit_once(':') {
        Some((h, p)) if p == default.to_string() => Some(format!("{scheme}://{h}{path}")),
        Some(_) => None,
        None => Some(format!("{scheme}://{auth}:{default}{path}")),
    }
}

/// Validate `X-Twilio-Signature` for a POST to `url` with form `params`.
pub fn verify_signature(token: &str, url: &str, params: &[(String, String)], sig: Option<&str>) -> bool {
    let Some(sig) = sig.map(str::trim).filter(|s| !s.is_empty()) else { return false };
    if token.is_empty() {
        return false;
    }
    let ok = |u: &str| seagent_net::crypto::ct_eq(sign(token, u, params).as_bytes(), sig.as_bytes());
    ok(url) || port_variant(url).is_some_and(|v| ok(&v))
}

/// Twilio's `{code, message, more_info, status}` error → classified error.
fn twilio_err(status: u16, retry_after: Option<Duration>, body: &str) -> ChannelError {
    let v: Value = serde_json::from_str(body).unwrap_or_default();
    let code = v["code"].as_i64().unwrap_or(0);
    let msg = redact_phones_in(v["message"].as_str().unwrap_or(""));
    let text = format!("twilio error {code} (HTTP {status}): {msg}");
    let kind = match code {
        // Unsubscribed (STOP), invalid / unreachable / non-mobile recipient.
        21610 | 21211 | 21612 | 21614 => K::NotFound,
        21408 | 21606 | 21659 | 21660 | 21212 | 21703 | 21705 => K::Fatal,
        20003 | 20005 | 20008 => K::Auth,
        20429 | 14107 => K::RateLimited { retry_after },
        _ if code != 0 => match status {
            401 | 403 => K::Auth,
            429 => K::RateLimited { retry_after },
            404 => K::NotFound,
            s if s >= 500 => K::Network,
            _ => K::Protocol,
        },
        _ => {
            let mut e = classify(status, retry_after, "twilio", "");
            e.message = text;
            return e;
        }
    };
    ChannelError::new(kind, text)
}

/// Inbound form → Inbound (None for opt-outs, our own number and empty messages).
fn inbound_of(channel: &str, f: &HashMap<String, String>, our: &str) -> Option<Inbound> {
    let get = |k: &str| f.get(k).map(|s| s.trim()).unwrap_or("");
    let from = get("From");
    let sid = [get("MessageSid"), get("SmsMessageSid"), get("SmsSid")].into_iter().find(|s| !s.is_empty())?;
    if from.is_empty() || (!our.is_empty() && from == our) || get("OptOutType").eq_ignore_ascii_case("stop") {
        return None;
    }
    let n: usize = get("NumMedia").parse().unwrap_or(0);
    let media: Vec<Media> = (0..n.min(MAX_MEDIA))
        .filter_map(|i| {
            let url = f.get(&format!("MediaUrl{i}"))?.trim().to_string();
            let mime = f.get(&format!("MediaContentType{i}")).map(|s| s.trim().to_string()).unwrap_or_default();
            let kind = match mime.split('/').next().unwrap_or("") {
                "image" => MediaKind::Image,
                "video" => MediaKind::Video,
                "audio" => MediaKind::Audio,
                _ => MediaKind::Document,
            };
            let name = url.rsplit('/').next().unwrap_or("media").to_string();
            Some(Media { kind, id: Some(name.clone()), name, mime, url: Some(url), ..Default::default() })
        })
        .collect();
    let body = f.get("Body").map(String::as_str).unwrap_or("");
    if body.trim().is_empty() && media.is_empty() {
        return None;
    }
    Some(Inbound {
        channel: channel.to_string(),
        chat: from.to_string(),
        sender: from.to_string(),
        sender_name: [get("ProfileName"), from].into_iter().find(|s| !s.is_empty()).unwrap_or("").to_string(),
        chat_type: ChatType::Direct,
        text: body.to_string(),
        message_id: sid.to_string(),
        account: get("To").to_string(),
        ts: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0),
        media,
        ..Default::default()
    })
}

pub struct Sms {
    id: String,
    sid: String,
    basic: String,
    api: String,
    from: Option<String>,
    service: Option<String>,
    status_callback: Option<String>,
    public_url: Option<String>,
    poll_timeout: u64,
    http: Http,
    pub retry_base: Duration,
    pub max_retries: u32,
    server: Server,
    rx: Mutex<Receiver<HashMap<String, String>>>,
    media: MediaMap,
}

impl Sms {
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.server.local_addr()
    }

    fn serve(&self, path: &str) -> Result<String, ChannelError> {
        let base = self.public_url.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "Twilio fetches MMS media by public URL: set `public_url` (or `webhook_url`) to send local files"))?;
        let p = std::fs::canonicalize(path).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {path}: {e}")))?;
        let tok = seagent_net::crypto::random_token(24);
        let mut m = self.media.lock().unwrap();
        let now = Instant::now();
        m.retain(|_, (_, e)| *e > now);
        m.insert(tok.clone(), (p, now + Duration::from_secs(3600)));
        Ok(format!("{base}{MEDIA_PREFIX}{tok}/{}", seagent_net::urlencode(&crate::line::file_name(path))))
    }

    fn post(&self, to: &str, body: Option<&str>, media: &[String]) -> Result<String, ChannelError> {
        let mut form: Vec<(&str, &str)> = vec![("To", to)];
        if let Some(b) = body {
            form.push(("Body", b));
        }
        for u in media {
            form.push(("MediaUrl", u));
        }
        match (&self.from, &self.service) {
            (Some(f), _) => form.push(("From", f)),
            (None, Some(s)) => form.push(("MessagingServiceSid", s)),
            _ => return Err(ChannelError::new(K::Fatal, "twilio needs from_number or messaging_service_sid")),
        }
        if let Some(cb) = &self.status_callback {
            form.push(("StatusCallback", cb));
        }
        let url = format!("{}/2010-04-01/Accounts/{}/Messages.json", self.api, self.sid);
        let mut attempt = 0;
        loop {
            let err = match self.http.call("POST", &url, &[("authorization", &self.basic)], Payload::Form(&form)) {
                Ok(r) if (200..300).contains(&r.status) => {
                    let v: Value = serde_json::from_str(&r.body).unwrap_or_default();
                    return Ok(v["sid"].as_str().unwrap_or("").to_string());
                }
                Ok(r) => twilio_err(r.status, r.retry_after, &r.body),
                Err(e) => ChannelError::new(e.kind, redact_phones_in(&e.message)),
            };
            if !err.is_retryable() || attempt >= self.max_retries || matches!(err.kind, K::RateLimited { retry_after: Some(d) } if d > Duration::from_secs(30)) {
                return Err(err);
            }
            std::thread::sleep(match err.kind {
                K::RateLimited { retry_after: Some(d) } => d,
                _ => self.retry_base * 2u32.pow(attempt),
            });
            attempt += 1;
        }
    }
}

impl Channel for Sms {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps { chat_types: vec![ChatType::Direct], media: true, max_len: MAX_MESSAGE, len_unit: LenUnit::Chars, markup: Markup::Plain, streaming: Streaming::None, ..Caps::default() }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let until = Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
        let mut got = Vec::new();
        let rx = self.rx.lock().unwrap();
        while got.is_empty() && !cancel.is_cancelled() && Instant::now() < until {
            if let Ok(v) = rx.recv_timeout(Duration::from_millis(50)) {
                got.push(v);
                got.extend(rx.try_iter());
            }
        }
        let our = self.from.as_deref().unwrap_or("");
        Ok(got.iter().filter_map(|f| inbound_of(&self.id, f, our)).collect())
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let mut urls = Vec::new();
        for m in out.media.iter().take(MAX_MEDIA) {
            urls.push(match (&m.path, &m.url) {
                (Some(p), _) => self.serve(p)?,
                (None, Some(u)) => u.clone(),
                _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
            });
        }
        let text = match out.format {
            TextFormat::Markdown => markup::convert(&out.text, Markup::Plain),
            TextFormat::Plain => out.text.clone(),
        };
        let mut text = text;
        // No buttons on SMS: numbered options.
        if !out.buttons.is_empty() {
            let opts: Vec<String> = out.buttons.iter().flatten().enumerate().map(|(i, b)| format!("{}. {}{}", i + 1, b.label, b.url.as_deref().map(|u| format!(" {u}")).unwrap_or_default())).collect();
            text = format!("{}\n\n{}", text.trim_end(), opts.join("\n")).trim().to_string();
        }
        let pieces = crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars);
        let mut sent = Sent::default();
        if pieces.is_empty() && !urls.is_empty() {
            sent.ids.push(self.post(&out.chat, None, &urls)?);
            return Ok(sent);
        }
        for (i, p) in pieces.iter().enumerate() {
            sent.ids.push(self.post(&out.chat, Some(p), if i == 0 { &urls } else { &[] })?);
        }
        Ok(sent)
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let u = m.url.as_deref().ok_or_else(|| ChannelError::new(K::Fatal, "MMS attachment without url"))?;
        crate::http::get_bytes(u, &[("authorization", &self.basic)], 20 * 1024 * 1024)
    }
}

fn d_poll() -> u64 {
    25
}
fn d_path() -> String {
    "/webhooks/sms".into()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub account_sid: String,
    pub auth_token: String,
    #[serde(default, alias = "phone_number")]
    pub from_number: Option<String>,
    #[serde(default)]
    pub messaging_service_sid: Option<String>,
    pub listen: String,
    #[serde(default = "d_path")]
    pub webhook_path: String,
    /// The exact public URL configured in Twilio (signatures are computed over it).
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Dev only: accept unsigned webhooks when no webhook_url is known.
    #[serde(default)]
    pub insecure_no_signature: bool,
    /// Public base for serving outbound local media (default: webhook_url's origin).
    #[serde(default)]
    pub public_url: Option<String>,
    #[serde(default)]
    pub status_callback: Option<String>,
    #[serde(default)]
    pub api_base: Option<String>,
    #[serde(default = "d_poll")]
    pub poll_timeout_secs: u64,
}

impl Sms {
    /// `st.auth_token` already resolved.
    pub fn open(id: &str, st: &Settings) -> Result<Sms, String> {
        if st.account_sid.trim().is_empty() || st.auth_token.trim().is_empty() {
            return Err(format!("channel {id}: twilio needs account_sid and auth_token"));
        }
        if st.from_number.is_none() && st.messaging_service_sid.is_none() {
            return Err(format!("channel {id}: twilio needs from_number or messaging_service_sid"));
        }
        if st.webhook_url.is_none() && !st.insecure_no_signature {
            return Err(format!("channel {id}: webhook_url (the public URL configured in Twilio) is required to validate X-Twilio-Signature"));
        }
        let (tx, rx) = channel::<HashMap<String, String>>();
        let tx = Mutex::new(tx);
        let media: MediaMap = Arc::default();
        let (path, token, hook_url, media2) = (st.webhook_path.clone(), st.auth_token.trim().to_string(), st.webhook_url.clone(), media.clone());
        let twiml = || Response::new(200, "application/xml", EMPTY_TWIML);
        let handler: seagent_net::httpd::Handler = Arc::new(move |r: seagent_net::httpd::Request| {
            if r.method == "GET" && r.path == "/health" {
                return Response::text(200, "ok");
            }
            if r.method == "GET" {
                if let Some(rest) = r.path.strip_prefix(MEDIA_PREFIX) {
                    let tok = rest.split('/').next().unwrap_or("");
                    let e = media2.lock().unwrap().get(tok).cloned();
                    return match e {
                        Some((p, exp)) if exp > Instant::now() => match std::fs::read(&p) {
                            Ok(b) => Response::new(200, crate::line::guess_mime(&p.display().to_string()), b),
                            Err(_) => Response::text(404, "not found"),
                        },
                        _ => Response::text(404, "not found"),
                    };
                }
            }
            if r.method != "POST" || r.path != path {
                return Response::text(404, "not found");
            }
            let params = seagent_net::parse_query(r.body_str());
            if let Some(u) = &hook_url {
                let url = if !r.raw_query.is_empty() && !u.contains('?') { format!("{u}?{}", r.raw_query) } else { u.clone() };
                if !verify_signature(&token, &url, &params, r.header("x-twilio-signature")) {
                    return Response::new(403, "application/xml", EMPTY_TWIML);
                }
            }
            let mut f = HashMap::new();
            for (k, v) in params {
                f.entry(k).or_insert(v);
            }
            let _ = tx.lock().unwrap().send(f);
            twiml()
        });
        let server = Server::bind(&st.listen, Opts { max_body: 64 * 1024, ..Opts::default() }, handler).map_err(|e| format!("channel {id}: cannot listen on {}: {e}", st.listen))?;
        let public = st.public_url.clone().or_else(|| st.webhook_url.as_deref().and_then(|u| seagent_net::Url::parse(u).ok()).map(|u| format!("{}://{}", u.scheme, u.host_header())));
        let sid = st.account_sid.trim().to_string();
        Ok(Sms {
            id: id.to_string(),
            basic: format!("Basic {}", seagent_net::crypto::b64(format!("{sid}:{}", st.auth_token.trim()).as_bytes())),
            sid,
            api: st.api_base.as_deref().unwrap_or(DEFAULT_API).trim_end_matches('/').to_string(),
            from: st.from_number.clone(),
            service: st.messaging_service_sid.clone(),
            status_callback: st.status_callback.clone(),
            public_url: public.map(|p| p.trim_end_matches('/').to_string()),
            poll_timeout: st.poll_timeout_secs,
            http: Http::new(Duration::from_secs(30)),
            retry_base: Duration::from_millis(500),
            max_retries: 2,
            server,
            rx: Mutex::new(rx),
            media,
        })
    }
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let mut st: Settings = ctx.settings(s)?;
    st.auth_token = ctx.secret("auth_token", &st.auth_token)?;
    Ok(Arc::new(Sms::open(ctx.name, &st)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};
    use serde_json::json;

    const HOOK: &str = "https://bot.example.com/webhooks/sms";

    fn sms(api: &str) -> Sms {
        let st: Settings = serde_json::from_value(json!({"account_sid": "AC123", "auth_token": "AUTHTOK", "from_number": "+15550001111", "listen": "127.0.0.1:0", "webhook_url": HOOK, "api_base": api, "poll_timeout_secs": 1})).unwrap();
        let mut s = Sms::open("sms", &st).unwrap();
        s.retry_base = Duration::from_millis(5);
        s
    }

    fn post(s: &Sms, form: &[(&str, &str)], sig: Option<String>) -> u16 {
        let a = crate::http::agent(Duration::from_secs(5));
        let mut r = a.post(&format!("http://{}/webhooks/sms", s.local_addr())).header("content-type", "application/x-www-form-urlencoded");
        if let Some(sig) = sig {
            r = r.header("x-twilio-signature", &sig);
        }
        r.send(seagent_net::form_encode(form).as_bytes()).map(|r| r.status().as_u16()).unwrap_or(0)
    }

    fn signed(url: &str, form: &[(&str, &str)]) -> String {
        sign("AUTHTOK", url, &form.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<Vec<_>>())
    }

    #[test]
    fn signature_good_bad_missing_and_port_variant() {
        let s = sms("http://127.0.0.1:1");
        let form = [("From", "+886912345678"), ("To", "+15550001111"), ("Body", "hi there"), ("MessageSid", "SM1"), ("NumMedia", "0")];
        assert_eq!(post(&s, &form, None), 403, "missing");
        assert_eq!(post(&s, &form, Some("bm9wZQ==".into())), 403, "bad");
        let tampered = [("From", "+886900000000"), ("To", "+15550001111"), ("Body", "hi there"), ("MessageSid", "SM1"), ("NumMedia", "0")];
        assert_eq!(post(&s, &tampered, Some(signed(HOOK, &form))), 403, "params changed after signing");
        assert!(s.poll(&Cancel::new()).unwrap().is_empty());
        assert_eq!(post(&s, &form, Some(signed(HOOK, &form))), 200);
        assert_eq!(post(&s, &[("From", "+886912345678"), ("Body", "x"), ("MessageSid", "SM2")], Some(signed("https://bot.example.com:443/webhooks/sms", &[("From", "+886912345678"), ("Body", "x"), ("MessageSid", "SM2")]))), 200, "default port variant");
        let g = s.poll(&Cancel::new()).unwrap();
        assert_eq!(g.len(), 2);
        assert_eq!((g[0].chat.as_str(), g[0].text.as_str(), g[0].message_id.as_str(), g[0].account.as_str()), ("+886912345678", "hi there", "SM1", "+15550001111"));
        assert_eq!(port_variant("https://h:8443/x"), None);
        assert_eq!(port_variant("http://h/x?a=1").as_deref(), Some("http://h:80/x?a=1"));
    }

    #[test]
    fn mms_opt_out_and_echo() {
        let s = sms("http://127.0.0.1:1");
        let mut sent = 0;
        for form in [
            vec![("From", "+886912345678"), ("Body", ""), ("MessageSid", "MM1"), ("NumMedia", "2"), ("MediaUrl0", "https://api.twilio.com/2010-04-01/Accounts/AC123/Messages/MM1/Media/ME1"), ("MediaContentType0", "image/jpeg"), ("MediaUrl1", "https://api.twilio.com/x/ME2"), ("MediaContentType1", "application/pdf")],
            vec![("From", "+886912345678"), ("Body", "STOP"), ("MessageSid", "SM3"), ("OptOutType", "STOP")],
            vec![("From", "+15550001111"), ("Body", "echo"), ("MessageSid", "SM4")],
            vec![("From", "whatsapp:+886912345678"), ("Body", "via wa"), ("MessageSid", "SM5"), ("ProfileName", "Amy")],
        ] {
            assert_eq!(post(&s, &form, Some(signed(HOOK, &form))), 200);
            sent += 1;
        }
        assert_eq!(sent, 4);
        let g = s.poll(&Cancel::new()).unwrap();
        assert_eq!(g.len(), 2, "opt-out and own number dropped");
        assert_eq!((g[0].media.len(), g[0].media[0].kind, g[0].media[1].kind, g[0].media[0].id.as_deref()), (2, MediaKind::Image, MediaKind::Document, Some("ME1")));
        assert_eq!((g[1].chat.as_str(), g[1].sender_name.as_str()), ("whatsapp:+886912345678", "Amy"));
        // MMS download carries Basic auth.
        let srv = FakeServer::start(|req, _| if req.header("authorization") == Some(&format!("Basic {}", seagent_net::crypto::b64(b"AC123:AUTHTOK"))) { (200, vec![], "IMG".into()) } else { (401, vec![], String::new()) });
        assert_eq!(s.fetch_media(&Media { url: Some(format!("{}/media/ME1", srv.url)), ..Default::default() }).unwrap(), b"IMG");
    }

    #[test]
    fn send_shape_chunks_media_and_service_sid() {
        let srv = FakeServer::start(|_, n| (201, vec![], json!({"sid": format!("SM{n}"), "status": "queued"}).to_string()));
        let s = sms(&srv.url);
        let r = s.send(&Outbound { format: TextFormat::Markdown, buttons: vec![vec![crate::Button { label: "Yes".into(), data: "y".into(), url: None }]], ..Outbound::text("+886912345678", "**Hi** [x](https://e.com)") }).unwrap();
        assert_eq!(r.ids, vec!["SM0"]);
        let q = srv.requests()[0].clone();
        assert_eq!(q.path, "/2010-04-01/Accounts/AC123/Messages.json");
        assert_eq!(q.header("authorization").unwrap(), format!("Basic {}", seagent_net::crypto::b64(b"AC123:AUTHTOK")));
        let f: HashMap<String, String> = seagent_net::parse_query(&q.body).into_iter().collect();
        assert_eq!((f["To"].as_str(), f["From"].as_str(), f["Body"].as_str()), ("+886912345678", "+15550001111", "Hi x (https://e.com)\n\n1. Yes"));
        // 3500 chars → 3 messages ≤1600; media rides on the first; local files are served.
        let file = temp_dir("sms").join("p.png");
        std::fs::write(&file, b"PNG").unwrap();
        let r = s.send(&Outbound { media: vec![Media { kind: MediaKind::Image, url: Some("https://e.com/a.jpg".into()), ..Default::default() }, Media { kind: MediaKind::Image, path: Some(file.display().to_string()), ..Default::default() }], ..Outbound::text("+1", &"ab ".repeat(1200)) }).unwrap();
        assert_eq!(r.ids.len(), 3);
        let reqs = srv.requests();
        let first = seagent_net::parse_query(&reqs[1].body);
        let urls: Vec<&str> = first.iter().filter(|(k, _)| k == "MediaUrl").map(|(_, v)| v.as_str()).collect();
        assert_eq!(urls.len(), 2);
        assert!(urls[1].starts_with("https://bot.example.com/sms/media/") && urls[1].ends_with("/p.png"), "{urls:?}");
        assert!(!reqs[2].body.contains("MediaUrl"));
        assert!(reqs[1..].iter().all(|r| seagent_net::parse_query(&r.body).iter().find(|(k, _)| k == "Body").unwrap().1.chars().count() <= MAX_MESSAGE));
        let local = urls[1].replace("https://bot.example.com", &format!("http://{}", s.local_addr()));
        let a = crate::http::agent(Duration::from_secs(5));
        assert_eq!(a.get(&local).call().unwrap().body_mut().read_to_vec().unwrap(), b"PNG");
        // Media only, messaging service instead of From.
        let st: Settings = serde_json::from_value(json!({"account_sid": "AC1", "auth_token": "t", "messaging_service_sid": "MG9", "listen": "127.0.0.1:0", "insecure_no_signature": true, "api_base": srv.url})).unwrap();
        let s2 = Sms::open("s2", &st).unwrap();
        s2.send(&Outbound { media: vec![Media { url: Some("https://e.com/x.pdf".into()), ..Default::default() }], ..Outbound::text("+1", "") }).unwrap();
        let f: HashMap<String, String> = seagent_net::parse_query(&srv.requests().last().unwrap().body).into_iter().collect();
        assert!(!f.contains_key("Body") && f["MessagingServiceSid"] == "MG9" && !f.contains_key("From"));
        let e = s2.send(&Outbound { media: vec![Media { path: Some(file.display().to_string()), ..Default::default() }], ..Outbound::text("+1", "") }).unwrap_err();
        assert_eq!(e.kind, K::Fatal, "no public URL for local media");
    }

    #[test]
    fn error_codes_and_redaction() {
        for (status, code, kind) in [(400, 21610, K::NotFound), (400, 21211, K::NotFound), (401, 20003, K::Auth), (400, 21408, K::Fatal), (400, 21602, K::Protocol)] {
            let srv = FakeServer::start(move |_, _| (status, vec![], json!({"code": code, "message": "The 'To' number +886912345678 is not valid", "status": status}).to_string()));
            let e = sms(&srv.url).send(&Outbound::text("+886912345678", "x")).unwrap_err();
            assert_eq!(e.kind, kind, "{code}");
            assert!(e.message.contains("+886****5678") && !e.message.contains("912345678") && !e.message.contains("AUTHTOK"), "{}", e.message);
            assert_eq!(srv.requests().len(), 1);
        }
        let srv = FakeServer::start(|_, n| match n {
            0 => (429, vec![("Retry-After".into(), "0".into())], json!({"code": 20429, "message": "Too Many Requests"}).to_string()),
            1 => (503, vec![], String::new()),
            _ => (201, vec![], json!({"sid": "SMok"}).to_string()),
        });
        assert_eq!(sms(&srv.url).send(&Outbound::text("+1", "x")).unwrap().ids, vec!["SMok"]);
        assert_eq!(redact_phone("+15550001111"), "+155****1111");
        assert_eq!(redact_phones_in("to whatsapp:+886912345678 ok 2024"), "to whatsapp:+886****5678 ok 2024");
    }

    #[test]
    fn cancel_and_config() {
        let s = sms("http://127.0.0.1:1");
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.cancel();
        });
        let t = Instant::now();
        assert!(s.poll(&c).unwrap().is_empty());
        assert!(t.elapsed() < Duration::from_millis(600));
        let st: Settings = serde_json::from_value(json!({"account_sid": "AC1", "auth_token": "t", "from_number": "+1", "listen": "127.0.0.1:0"})).unwrap();
        assert!(Sms::open("s", &st).err().unwrap().contains("webhook_url"));
        let st: Settings = serde_json::from_value(json!({"account_sid": "AC1", "auth_token": "t", "listen": "127.0.0.1:0", "webhook_url": HOOK})).unwrap();
        assert!(Sms::open("s", &st).is_err(), "needs a sender");
    }
}
