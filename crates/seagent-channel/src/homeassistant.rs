//! Home Assistant (designed from the Hermes `homeassistant` catalog manifest — state-change
//! events in, notifications out — and HA's documented WebSocket API; the upstream adapter
//! code is not in the tree).
//!
//! One WebSocket to `ws(s)://<host>:8123/api/websocket`: `auth_required` → `{"type":"auth",
//! "access_token": <long-lived token>}` → `auth_ok` (or `auth_invalid` → `Auth`, no retry).
//! Then `subscribe_events` for `event_type` (default `seagent_message`), plus `state_changed`
//! when `watch_entities` is set and `mobile_app_notification_action` when `notify_service`
//! is a mobile-app notifier (button presses). Every command carries an increasing `id`;
//! `ping`/`pong` every `heartbeat_secs`, and a missing pong or dropped socket reconnects
//! with backoff. Outbound commands ride the same socket and wait for their `result`
//! (`not_found` → `NotFound`, `unauthorized` → `Auth`, other failures → `Protocol`).
//!
//! Send: `fire_event` `reply_event` (default `seagent_reply`) with `{chat, text, reply_to,
//! thread, media, buttons}`, and, when `notify_service` is set (e.g.
//! `notify.mobile_app_pixel` or `persistent_notification.create`), `call_service` with
//! `{message, title, data: {image, actions}}`. Buttons become mobile-app notification
//! actions (presses arrive as callbacks), otherwise numbered options in the text.
//!
//! Inbound `seagent_message` data: `{"text", "chat"?, "user"?, "user_name"?, "message_id"?,
//! "thread"?, "reply_to"?}`; the sender defaults to the event context's `user_id`.
//! Watched state changes arrive as text such as `Front door (binary_sensor.front_door): off → on`
//! in chat `state_chat`.
//!
//! Home Assistant side (`configuration.yaml` / automations):
//!
//! ```yaml
//! # Talk to seagent from a dashboard text helper or a voice/Assist sentence:
//! automation:
//!   - alias: "seagent: send message"
//!     trigger:
//!       - platform: state
//!         entity_id: input_text.seagent_prompt
//!     action:
//!       - event: seagent_message
//!         event_data:
//!           text: "{{ trigger.to_state.state }}"
//!           chat: "living_room"
//!           user_name: "{{ trigger.to_state.context.user_id }}"
//!   # Show seagent's replies:
//!   - alias: "seagent: reply"
//!     trigger:
//!       - platform: event
//!         event_type: seagent_reply
//!     action:
//!       - service: persistent_notification.create
//!         data:
//!           title: "seagent"
//!           message: "{{ trigger.event.data.text }}"
//! ```
//!
//! ```toml
//! [channels.home]
//! kind = "homeassistant"
//! url = "http://homeassistant.local:8123"
//! token = "{{secret:HASS_TOKEN}}"
//! notify_service = "notify.mobile_app_pixel"   # optional
//! watch_entities = ["binary_sensor.front_door", "alarm_control_panel.*"]  # optional
//! ```

use crate::{markup, Callback, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, Markup, Outbound, Sent, TextFormat};
use seagent_core::Cancel;
use seagent_net::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Reply = Sender<Result<Value, ChannelError>>;
/// Handed to the worker thread on first use.
type WorkerEnds = (Sender<Inbound>, Receiver<(Value, Reply)>);
const ACTION_EVENT: &str = "mobile_app_notification_action";

pub struct Options {
    pub event_type: String,
    pub reply_event: String,
    pub notify_service: Option<String>,
    pub watch_entities: Vec<String>,
    pub state_chat: String,
    pub heartbeat: Duration,
    pub retry_base: Duration,
    /// How long `send` waits for the connection and the command's `result`.
    pub send_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            event_type: "seagent_message".into(),
            reply_event: "seagent_reply".into(),
            notify_service: None,
            watch_entities: vec![],
            state_chat: "homeassistant".into(),
            heartbeat: Duration::from_secs(30),
            retry_base: Duration::from_secs(1),
            send_timeout: Duration::from_secs(15),
        }
    }
}

pub struct HomeAssistant {
    id: String,
    inner: Arc<Inner>,
    poll_timeout: u64,
    rx: Mutex<Receiver<Inbound>>,
    cmd_tx: Mutex<Sender<(Value, Reply)>>,
    start: Mutex<Option<WorkerEnds>>,
}

struct Inner {
    channel: String,
    ws_url: String,
    token: String,
    o: Options,
    stop: AtomicBool,
    fatal: Mutex<Option<ChannelError>>,
}

/// `http://h:8123` → `ws://h:8123/api/websocket` (a ws/wss URL is used as is).
pub fn ws_url(url: &str) -> Result<String, String> {
    let u = url.trim().trim_end_matches('/');
    let (scheme, rest) = u.split_once("://").ok_or_else(|| format!("not a URL: {u}"))?;
    let scheme = match scheme {
        "http" | "ws" => "ws",
        "https" | "wss" => "wss",
        s => return Err(format!("unsupported scheme {s}")),
    };
    let rest = if rest.ends_with("/api/websocket") { rest.to_string() } else { format!("{rest}/api/websocket") };
    Ok(format!("{scheme}://{rest}"))
}

/// `entity_id` against `watch_entities` (`light.kitchen`, `binary_sensor.*`, `*`).
fn watched(patterns: &[String], entity: &str) -> bool {
    patterns.iter().any(|p| p == "*" || p == entity || p.strip_suffix('*').is_some_and(|pre| entity.starts_with(pre)))
}

/// `2024-05-01T12:00:00.123456+00:00` → unix seconds (offset applied).
pub fn parse_ts(s: &str) -> i64 {
    let n = |a: usize, b: usize| s.get(a..b).and_then(|x| x.parse::<i64>().ok());
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(se)) = (n(0, 4), n(5, 7), n(8, 10), n(11, 13), n(14, 16), n(17, 19)) else { return 0 };
    let (y2, m2) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * m2 + 2) / 5 + d - 1;
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    let tail = &s[19.min(s.len())..];
    let off = tail.rfind(['+', '-']).map(|i| &tail[i..]).filter(|o| o.len() >= 6).map(|o| {
        let sign = if o.starts_with('-') { -1 } else { 1 };
        sign * (o[1..3].parse::<i64>().unwrap_or(0) * 3600 + o[4..6].parse::<i64>().unwrap_or(0) * 60)
    });
    days * 86400 + h * 3600 + mi * 60 + se - off.unwrap_or(0)
}

fn str_of(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string).or_else(|| v.as_i64().map(|n| n.to_string())).filter(|s| !s.is_empty())
}

impl Inner {
    fn mobile(&self) -> bool {
        self.o.notify_service.as_deref().is_some_and(|s| s.starts_with("notify.mobile_app"))
    }

    fn subscriptions(&self) -> Vec<String> {
        let mut s = vec![self.o.event_type.clone()];
        if !self.o.watch_entities.is_empty() {
            s.push("state_changed".into());
        }
        if self.mobile() {
            s.push(ACTION_EVENT.into());
        }
        s
    }

    /// An `event` message → inbound.
    fn inbound_of(&self, ev: &Value) -> Option<Inbound> {
        let et = ev["event_type"].as_str()?;
        let data = &ev["data"];
        let ctx = &ev["context"];
        let ts = ev["time_fired"].as_str().map(parse_ts).unwrap_or(0);
        let ctx_id = str_of(&ctx["id"]).unwrap_or_else(|| format!("{et}:{ts}"));
        let base = Inbound { channel: self.channel.clone(), ts, chat_type: ChatType::Direct, ..Default::default() };
        if et == self.o.event_type {
            let text = data["text"].as_str().or_else(|| data["message"].as_str()).unwrap_or("").trim().to_string();
            if text.is_empty() || data["source"] == "seagent" {
                return None;
            }
            let sender = str_of(&data["user"]).or_else(|| str_of(&ctx["user_id"])).unwrap_or_else(|| "homeassistant".into());
            return Some(Inbound {
                chat: str_of(&data["chat"]).unwrap_or_else(|| self.o.state_chat.clone()),
                sender_name: str_of(&data["user_name"]).unwrap_or_else(|| sender.clone()),
                sender,
                text,
                message_id: str_of(&data["message_id"]).unwrap_or(ctx_id),
                thread: str_of(&data["thread"]),
                reply: str_of(&data["reply_to"]).map(|id| crate::ReplyRef { id, is_own: true, ..Default::default() }),
                ..base
            });
        }
        if et == "state_changed" {
            let entity = data["entity_id"].as_str()?;
            let (old, new) = (data["old_state"]["state"].as_str(), data["new_state"]["state"].as_str());
            // Attribute-only updates are noise.
            if !watched(&self.o.watch_entities, entity) || old == new {
                return None;
            }
            let name = data["new_state"]["attributes"]["friendly_name"].as_str().unwrap_or(entity);
            return Some(Inbound {
                chat: self.o.state_chat.clone(),
                sender: "homeassistant".into(),
                sender_name: "Home Assistant".into(),
                text: format!("{name} ({entity}): {} → {}", old.unwrap_or("unknown"), new.unwrap_or("unavailable")),
                message_id: ctx_id,
                ..base
            });
        }
        if et == ACTION_EVENT {
            let action = data["action"].as_str()?;
            let sender = str_of(&ctx["user_id"]).unwrap_or_else(|| "homeassistant".into());
            return Some(Inbound {
                chat: str_of(&data["tag"]).unwrap_or_else(|| self.o.state_chat.clone()),
                sender_name: sender.clone(),
                sender,
                message_id: format!("cb:{ctx_id}"),
                callback: Some(Callback { id: ctx_id, data: action.to_string() }),
                text: data["reply_text"].as_str().unwrap_or("").to_string(),
                ..base
            });
        }
        None
    }

    fn sleep(&self, d: Duration) {
        let until = Instant::now() + d;
        while Instant::now() < until && !self.stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn recv_json(ws: &mut WebSocket<seagent_net::Stream>, until: Instant) -> Result<Value, String> {
        while Instant::now() < until {
            match ws.recv().map_err(|e| e.to_string())? {
                Some(Message::Text(t)) => return serde_json::from_str(&t).map_err(|e| format!("bad JSON: {e}")),
                Some(Message::Close(_)) => return Err("closed".into()),
                _ => {}
            }
        }
        Err("timed out".into())
    }

    /// Connect and authenticate. Err((true, _)) = bad token: stop.
    fn connect(&self) -> Result<WebSocket<seagent_net::Stream>, (bool, String)> {
        let (mut ws, _) = WebSocket::connect(&self.ws_url, &[], Duration::from_secs(10)).map_err(|e| (false, format!("connect: {e}")))?;
        ws.set_read_timeout(Some(Duration::from_millis(200))).map_err(|e| (false, e.to_string()))?;
        let until = Instant::now() + Duration::from_secs(10);
        let hello = Self::recv_json(&mut ws, until).map_err(|e| (false, e))?;
        if hello["type"] != "auth_required" {
            return Err((false, format!("expected auth_required, got {}", hello["type"])));
        }
        ws.send_text(&json!({"type": "auth", "access_token": self.token}).to_string()).map_err(|e| (false, e.to_string()))?;
        let r = Self::recv_json(&mut ws, until).map_err(|e| (false, e))?;
        match r["type"].as_str() {
            Some("auth_ok") => Ok(ws),
            Some("auth_invalid") => Err((true, format!("home assistant rejected the access token: {}", r["message"].as_str().unwrap_or("")))),
            _ => Err((false, format!("unexpected auth reply {}", r["type"]))),
        }
    }

    fn run(self: Arc<Self>, tx: Sender<Inbound>, cmds: Receiver<(Value, Reply)>) {
        let mut attempt = 0u32;
        let mut next_id: u64 = 1;
        while !self.stop.load(Ordering::SeqCst) {
            let mut ws = match self.connect() {
                Ok(ws) => ws,
                Err((true, msg)) => {
                    let e = ChannelError::new(K::Auth, msg);
                    *self.fatal.lock().unwrap() = Some(e.clone());
                    for (_, r) in cmds.try_iter() {
                        let _ = r.send(Err(e.clone()));
                    }
                    return;
                }
                Err((false, _)) => {
                    attempt += 1;
                    self.sleep((self.o.retry_base * 2u32.pow(attempt.min(5))).min(Duration::from_secs(60)));
                    continue;
                }
            };
            let mut ok = true;
            for et in self.subscriptions() {
                ok &= ws.send_text(&json!({"id": next_id, "type": "subscribe_events", "event_type": et}).to_string()).is_ok();
                next_id += 1;
            }
            let mut pending: HashMap<u64, Reply> = HashMap::new();
            let mut ping: Option<(u64, Instant)> = None;
            let mut last_ping = Instant::now();
            while ok && !self.stop.load(Ordering::SeqCst) {
                while let Ok((mut cmd, reply)) = cmds.try_recv() {
                    cmd["id"] = json!(next_id);
                    if ws.send_text(&cmd.to_string()).is_err() {
                        let _ = reply.send(Err(ChannelError::new(K::Network, "home assistant: socket write failed")));
                        ok = false;
                        break;
                    }
                    pending.insert(next_id, reply);
                    next_id += 1;
                }
                match ping {
                    Some((_, at)) if at.elapsed() > self.o.heartbeat => break, // no pong: reconnect
                    None if last_ping.elapsed() >= self.o.heartbeat => {
                        if ws.send_text(&json!({"id": next_id, "type": "ping"}).to_string()).is_err() {
                            break;
                        }
                        ping = Some((next_id, Instant::now()));
                        last_ping = Instant::now();
                        next_id += 1;
                    }
                    _ => {}
                }
                let msg = match ws.recv() {
                    Ok(Some(Message::Text(t))) => t,
                    Ok(Some(Message::Close(_))) | Err(_) => break,
                    _ => continue,
                };
                let Ok(v) = serde_json::from_str::<Value>(&msg) else { continue };
                let id = v["id"].as_u64().unwrap_or(0);
                match v["type"].as_str() {
                    Some("pong") if ping.is_some_and(|(p, _)| p == id) => ping = None,
                    Some("result") => {
                        if let Some(r) = pending.remove(&id) {
                            let res = if v["success"] == true {
                                attempt = 0;
                                Ok(v["result"].clone())
                            } else {
                                let code = v["error"]["code"].as_str().unwrap_or("");
                                let kind = match code {
                                    "not_found" | "service_not_found" => K::NotFound,
                                    "unauthorized" => K::Auth,
                                    _ => K::Protocol,
                                };
                                Err(ChannelError::new(kind, format!("home assistant: {code} {}", v["error"]["message"].as_str().unwrap_or(""))))
                            };
                            let _ = r.send(res);
                        }
                    }
                    Some("event") => {
                        attempt = 0;
                        if let Some(m) = self.inbound_of(&v["event"]) {
                            let _ = tx.send(m);
                        }
                    }
                    _ => {}
                }
            }
            for (_, r) in pending.drain() {
                let _ = r.send(Err(ChannelError::new(K::Network, "home assistant: connection lost before the result")));
            }
            if self.stop.load(Ordering::SeqCst) {
                let _ = ws.send(&Message::Close(Some((1000, String::new()))));
                return;
            }
            attempt += 1;
            self.sleep((self.o.retry_base * 2u32.pow(attempt.min(5))).min(Duration::from_secs(60)));
        }
    }
}

impl HomeAssistant {
    pub fn new(id: &str, url: &str, token: &str, poll_timeout_secs: u64, o: Options) -> Result<Self, String> {
        if token.trim().is_empty() {
            return Err(format!("channel {id}: homeassistant token is empty"));
        }
        if o.event_type == o.reply_event {
            return Err(format!("channel {id}: event_type and reply_event must differ (replies would loop back)"));
        }
        if let Some(s) = &o.notify_service {
            if !s.contains('.') {
                return Err(format!("channel {id}: notify_service must be domain.service, e.g. notify.mobile_app_phone"));
            }
        }
        let ws_url = ws_url(url).map_err(|e| format!("channel {id}: url: {e}"))?;
        let (tx, rx) = std::sync::mpsc::channel();
        let (ctx, crx) = std::sync::mpsc::channel();
        let inner = Inner { channel: id.to_string(), ws_url, token: token.trim().to_string(), o, stop: AtomicBool::new(false), fatal: Mutex::new(None) };
        Ok(HomeAssistant { id: id.to_string(), inner: Arc::new(inner), poll_timeout: poll_timeout_secs, rx: Mutex::new(rx), cmd_tx: Mutex::new(ctx), start: Mutex::new(Some((tx, crx))) })
    }

    fn ensure_started(&self) -> Result<(), ChannelError> {
        if let Some((tx, crx)) = self.start.lock().unwrap().take() {
            let inner = self.inner.clone();
            std::thread::Builder::new().name(format!("homeassistant {}", self.id)).spawn(move || inner.run(tx, crx)).map_err(|e| ChannelError::new(K::Fatal, format!("spawn: {e}")))?;
        }
        Ok(())
    }

    /// One command over the socket, waiting for its `result`.
    pub fn command(&self, cmd: Value) -> Result<Value, ChannelError> {
        if let Some(e) = self.inner.fatal.lock().unwrap().clone() {
            return Err(e);
        }
        self.ensure_started()?;
        let (rtx, rrx) = std::sync::mpsc::channel();
        self.cmd_tx.lock().unwrap().send((cmd, rtx)).map_err(|_| ChannelError::new(K::Network, "home assistant worker stopped"))?;
        match rrx.recv_timeout(self.inner.o.send_timeout) {
            Ok(r) => r,
            Err(_) => Err(self.inner.fatal.lock().unwrap().clone().unwrap_or_else(|| ChannelError::new(K::Network, "home assistant: not connected (timed out waiting for result)"))),
        }
    }
}

impl Channel for HomeAssistant {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps { chat_types: vec![ChatType::Direct], media: true, reply: true, threads: true, buttons: true, max_len: 4000, markup: Markup::Markdown, ..Caps::default() }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        self.ensure_started()?;
        let rx = self.rx.lock().unwrap();
        let until = Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
        while !cancel.is_cancelled() && Instant::now() < until {
            if let Ok(m) = rx.recv_timeout(Duration::from_millis(50)) {
                let mut got = vec![m];
                got.extend(rx.try_iter());
                return Ok(got);
            }
            if let Some(e) = self.inner.fatal.lock().unwrap().clone() {
                return Err(e);
            }
        }
        Ok(vec![])
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let mut media = Vec::new();
        for m in &out.media {
            match &m.url {
                Some(u) => media.push(u.clone()),
                None => return Err(ChannelError::new(K::Unsupported, "home assistant: only media URLs can be sent")),
            }
        }
        let mobile = self.inner.mobile();
        let mut text = out.text.trim_end().to_string();
        if !out.buttons.is_empty() && !mobile {
            let opts: Vec<String> = out.buttons.iter().flatten().enumerate().map(|(i, b)| format!("{}. {}{}", i + 1, b.label, b.url.as_deref().map(|u| format!(" {u}")).unwrap_or_default())).collect();
            text = format!("{text}\n\n{}", opts.join("\n")).trim().to_string();
        }
        let buttons: Vec<Value> = out.buttons.iter().flatten().map(|b| json!({"label": b.label, "data": b.data, "url": b.url})).collect();
        let data = json!({"chat": out.chat, "text": text, "format": if out.format == TextFormat::Markdown { "markdown" } else { "plain" }, "reply_to": out.reply_to, "thread": out.thread, "media": media, "buttons": buttons, "silent": out.silent, "source": "seagent"});
        let r = self.command(json!({"type": "fire_event", "event_type": self.inner.o.reply_event, "event_data": data}))?;
        let id = str_of(&r["context"]["id"]).unwrap_or_else(|| format!("seagent-{}", seagent_net::crypto::random_token(8)));
        if let Some((domain, service)) = self.inner.o.notify_service.as_deref().and_then(|s| s.split_once('.')) {
            let message = if mobile && out.format == TextFormat::Markdown { markup::convert(&text, Markup::Plain) } else { text.clone() };
            let mut sd = json!({"message": message, "title": self.id});
            if mobile {
                let mut d = json!({"tag": out.chat});
                if let Some(u) = media.first() {
                    d["image"] = json!(u);
                }
                let actions: Vec<Value> = out.buttons.iter().flatten().map(|b| match &b.url {
                    Some(u) => json!({"action": "URI", "title": b.label, "uri": u}),
                    None => json!({"action": b.data, "title": b.label}),
                }).collect();
                if !actions.is_empty() {
                    d["actions"] = json!(actions);
                }
                if out.silent {
                    d["push"] = json!({"interruption-level": "passive"});
                }
                sd["data"] = d;
            } else if domain == "persistent_notification" {
                sd["notification_id"] = json!(format!("seagent_{}", out.chat));
            }
            self.command(json!({"type": "call_service", "domain": domain, "service": service, "service_data": sd}))?;
        }
        Ok(Sent::one(id))
    }

    fn stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for HomeAssistant {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::SeqCst);
    }
}

fn d_poll() -> u64 {
    25
}
fn d_event() -> String {
    "seagent_message".into()
}
fn d_reply() -> String {
    "seagent_reply".into()
}
fn d_chat() -> String {
    "homeassistant".into()
}
fn d_hb() -> u64 {
    30
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    /// `http://homeassistant.local:8123` (or the ws/wss URL of `/api/websocket`).
    url: String,
    /// Long-lived access token.
    token: String,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    #[serde(default = "d_event")]
    event_type: String,
    #[serde(default = "d_reply")]
    reply_event: String,
    #[serde(default)]
    notify_service: Option<String>,
    #[serde(default)]
    watch_entities: Vec<String>,
    #[serde(default = "d_chat")]
    state_chat: String,
    #[serde(default = "d_hb")]
    heartbeat_secs: u64,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let token = ctx.secret("token", &st.token)?;
    let o = Options {
        event_type: st.event_type,
        reply_event: st.reply_event,
        notify_service: st.notify_service,
        watch_entities: st.watch_entities,
        state_chat: st.state_chat,
        heartbeat: Duration::from_secs(st.heartbeat_secs.max(5)),
        ..Options::default()
    };
    Ok(Arc::new(HomeAssistant::new(ctx.name, &st.url, &token, st.poll_timeout_secs, o)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::AtomicUsize;

    type Ws = WebSocket<TcpStream>;

    /// Fake HA: each connection runs `script(conn_index, ws)` after the auth handshake
    /// (`good` = accept the token). Every received text frame is recorded.
    fn fake_ha(good: bool, script: impl Fn(usize, &mut Ws, &Mutex<Vec<Value>>) + Send + Sync + 'static) -> (String, Arc<Mutex<Vec<Value>>>, Arc<AtomicUsize>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let conns = Arc::new(AtomicUsize::new(0));
        let (s2, c2, script) = (seen.clone(), conns.clone(), Arc::new(script));
        std::thread::spawn(move || {
            for s in l.incoming() {
                let mut s = s.unwrap();
                let n = c2.fetch_add(1, Ordering::SeqCst);
                let (seen, script) = (s2.clone(), script.clone());
                std::thread::spawn(move || {
                    let (head, rest) = seagent_net::ws::read_head(&mut s, 65536).unwrap();
                    assert!(head.starts_with("GET /api/websocket "), "{head}");
                    let mut ws = WebSocket::accept(s, &head, rest).unwrap();
                    ws.send_text(r#"{"type":"auth_required","ha_version":"2024.5.0"}"#).unwrap();
                    let Ok(Message::Text(a)) = ws.recv_blocking() else { return };
                    seen.lock().unwrap().push(serde_json::from_str(&a).unwrap());
                    if !good {
                        let _ = ws.send_text(r#"{"type":"auth_invalid","message":"Invalid access token"}"#);
                        return;
                    }
                    ws.send_text(r#"{"type":"auth_ok"}"#).unwrap();
                    script(n, &mut ws, &seen);
                });
            }
        });
        (url, seen, conns)
    }

    /// Read frames until one of `ty` arrives (recording all); returns it.
    fn expect(ws: &mut Ws, seen: &Mutex<Vec<Value>>, ty: &str) -> Value {
        loop {
            let Message::Text(t) = ws.recv_blocking().unwrap() else { continue };
            let v: Value = serde_json::from_str(&t).unwrap();
            seen.lock().unwrap().push(v.clone());
            if v["type"] == ty {
                return v;
            }
        }
    }

    fn event(id: &Value, et: &str, data: Value) -> String {
        json!({"id": id, "type": "event", "event": {"event_type": et, "data": data, "origin": "LOCAL", "time_fired": "2024-05-01T12:00:00.5+00:00", "context": {"id": "CTX1", "user_id": "u-amy"}}}).to_string()
    }

    fn opts() -> Options {
        Options { retry_base: Duration::from_millis(10), heartbeat: Duration::from_secs(30), send_timeout: Duration::from_secs(5), ..Options::default() }
    }

    fn poll_until(h: &HomeAssistant, n: usize) -> Vec<Inbound> {
        let mut got = Vec::new();
        let until = Instant::now() + Duration::from_secs(10);
        while got.len() < n && Instant::now() < until {
            got.extend(h.poll(&Cancel::new()).unwrap());
        }
        got
    }

    #[test]
    fn helpers() {
        assert_eq!(ws_url("http://ha.local:8123/").unwrap(), "ws://ha.local:8123/api/websocket");
        assert_eq!(ws_url("https://ha.example.com").unwrap(), "wss://ha.example.com/api/websocket");
        assert_eq!(ws_url("ws://h/api/websocket").unwrap(), "ws://h/api/websocket");
        assert!(ws_url("ftp://h").is_err());
        assert_eq!(parse_ts("1970-01-01T00:00:00+00:00"), 0);
        assert_eq!(parse_ts("2024-05-01T12:00:00.123456+00:00"), 1714564800);
        assert_eq!(parse_ts("2024-05-01T14:00:00+02:00"), 1714564800);
        assert!(watched(&["binary_sensor.*".into()], "binary_sensor.door") && !watched(&["light.a".into()], "light.b"));
        assert!(HomeAssistant::new("h", "http://h", "t", 1, Options { reply_event: "seagent_message".into(), ..opts() }).is_err(), "loop refused");
        assert!(HomeAssistant::new("h", "http://h", " ", 1, opts()).is_err());
        assert!(HomeAssistant::new("h", "http://h", "t", 1, Options { notify_service: Some("bad".into()), ..opts() }).is_err());
    }

    #[test]
    fn auth_subscribe_inbound_kinds_and_reconnect() {
        let (url, seen, conns) = fake_ha(true, |n, ws, seen| {
            let sub = expect(ws, seen, "subscribe_events");
            expect(ws, seen, "subscribe_events");
            expect(ws, seen, "subscribe_events");
            let id = sub["id"].clone();
            ws.send_text(&json!({"id": id, "type": "result", "success": true, "result": null}).to_string()).unwrap();
            if n == 0 {
                ws.send_text(&event(&id, "seagent_message", json!({"text": "turn on the lights", "chat": "kitchen", "user_name": "Amy"}))).unwrap();
                ws.send_text(&event(&id, "seagent_message", json!({"text": "echo", "source": "seagent"}))).unwrap();
                ws.send_text(&event(&id, "seagent_message", json!({"text": "", "chat": "x"}))).unwrap();
                ws.send_text(&event(&id, "state_changed", json!({"entity_id": "binary_sensor.front_door", "old_state": {"state": "off"}, "new_state": {"state": "on", "attributes": {"friendly_name": "Front door"}}}))).unwrap();
                ws.send_text(&event(&id, "state_changed", json!({"entity_id": "binary_sensor.front_door", "old_state": {"state": "on"}, "new_state": {"state": "on"}}))).unwrap();
                ws.send_text(&event(&id, "state_changed", json!({"entity_id": "light.other", "old_state": {"state": "on"}, "new_state": {"state": "off"}}))).unwrap();
                ws.send_text(&event(&id, ACTION_EVENT, json!({"action": "appr:1:once", "tag": "kitchen"}))).unwrap();
                // Drop the socket without a close frame.
                std::thread::sleep(Duration::from_millis(100));
                return;
            }
            ws.send_text(&event(&id, "seagent_message", json!({"text": "after reconnect", "user": "u2", "message_id": "m-9", "reply_to": "r1", "thread": "t1"}))).unwrap();
            std::thread::sleep(Duration::from_secs(5));
        });
        let o = Options { watch_entities: vec!["binary_sensor.*".into()], notify_service: Some("notify.mobile_app_pixel".into()), ..opts() };
        let h = HomeAssistant::new("ha", &url, "LLTOKEN", 1, o).unwrap();
        let got = poll_until(&h, 4);
        assert_eq!(got.len(), 4, "{got:#?}");
        assert_eq!((got[0].chat.as_str(), got[0].sender.as_str(), got[0].sender_name.as_str(), got[0].text.as_str(), got[0].message_id.as_str(), got[0].ts), ("kitchen", "u-amy", "Amy", "turn on the lights", "CTX1", 1714564800));
        assert_eq!((got[1].chat.as_str(), got[1].text.as_str()), ("homeassistant", "Front door (binary_sensor.front_door): off → on"));
        assert_eq!(got[2].callback.as_ref().unwrap().data, "appr:1:once");
        assert_eq!(got[2].chat, "kitchen");
        assert_eq!((got[3].sender.as_str(), got[3].message_id.as_str(), got[3].thread.as_deref()), ("u2", "m-9", Some("t1")));
        assert!(got[3].reply.as_ref().unwrap().is_own);
        assert_eq!(conns.load(Ordering::SeqCst), 2, "reconnected after the dropped socket");
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen[0], json!({"type": "auth", "access_token": "LLTOKEN"}));
        let subs: Vec<&str> = seen.iter().filter(|v| v["type"] == "subscribe_events").filter_map(|v| v["event_type"].as_str()).collect();
        assert_eq!(&subs[..3], ["seagent_message", "state_changed", ACTION_EVENT]);
        let ids: Vec<u64> = seen.iter().filter_map(|v| v["id"].as_u64()).collect();
        assert!(ids.windows(2).all(|w| w[0] < w[1]), "ids increase across reconnects: {ids:?}");
        h.stop();
    }

    #[test]
    fn send_fires_event_and_calls_notify_with_actions() {
        let (url, seen, _) = fake_ha(true, |_, ws, seen| loop {
            let v = loop {
                let Message::Text(t) = ws.recv_blocking().unwrap() else { continue };
                let v: Value = serde_json::from_str(&t).unwrap();
                seen.lock().unwrap().push(v.clone());
                break v;
            };
            let res = match v["type"].as_str().unwrap() {
                "fire_event" => json!({"id": v["id"], "type": "result", "success": true, "result": {"context": {"id": "EV1"}}}),
                "call_service" if v["service"] == "missing" => json!({"id": v["id"], "type": "result", "success": false, "error": {"code": "not_found", "message": "Service not found."}}),
                "call_service" if v["service"] == "bad" => json!({"id": v["id"], "type": "result", "success": false, "error": {"code": "invalid_format", "message": "x"}}),
                _ => json!({"id": v["id"], "type": "result", "success": true, "result": null}),
            };
            ws.send_text(&res.to_string()).unwrap();
        });
        let h = HomeAssistant::new("ha", &url, "tok", 1, Options { notify_service: Some("notify.mobile_app_pixel".into()), ..opts() }).unwrap();
        let out = Outbound {
            format: TextFormat::Markdown,
            reply_to: Some("m1".into()),
            buttons: vec![vec![crate::Button { label: "Allow".into(), data: "appr:1:once".into(), url: None }]],
            media: vec![crate::Media { url: Some("https://e.com/cam.jpg".into()), ..Default::default() }],
            ..Outbound::text("kitchen", "**done**")
        };
        assert_eq!(h.send(&out).unwrap().ids, ["EV1"]);
        let seen_v = seen.lock().unwrap().clone();
        let fe = seen_v.iter().find(|v| v["type"] == "fire_event").unwrap();
        assert_eq!(fe["event_type"], "seagent_reply");
        let d = &fe["event_data"];
        assert_eq!((d["chat"].as_str(), d["text"].as_str(), d["reply_to"].as_str(), d["media"][0].as_str(), d["buttons"][0]["data"].as_str(), d["source"].as_str()), (Some("kitchen"), Some("**done**"), Some("m1"), Some("https://e.com/cam.jpg"), Some("appr:1:once"), Some("seagent")));
        let cs = seen_v.iter().find(|v| v["type"] == "call_service").unwrap();
        assert_eq!((cs["domain"].as_str(), cs["service"].as_str()), (Some("notify"), Some("mobile_app_pixel")));
        assert_eq!(cs["service_data"]["message"], "done", "mobile push is plain text");
        assert_eq!(cs["service_data"]["data"]["image"], "https://e.com/cam.jpg");
        assert_eq!(cs["service_data"]["data"]["actions"][0], json!({"action": "appr:1:once", "title": "Allow"}));
        // Error mapping from result codes; local files refused.
        let h2 = HomeAssistant::new("ha", &url, "tok", 1, Options { notify_service: Some("notify.missing".into()), ..opts() }).unwrap();
        assert_eq!(h2.send(&Outbound::text("c", "x")).unwrap_err().kind, K::NotFound);
        let h3 = HomeAssistant::new("ha", &url, "tok", 1, Options { notify_service: Some("persistent_notification.bad".into()), ..opts() }).unwrap();
        assert_eq!(h3.send(&Outbound::text("c", "x")).unwrap_err().kind, K::Protocol);
        let local = crate::Media { path: Some("/tmp/a".into()), ..Default::default() };
        assert_eq!(h.send(&Outbound { media: vec![local], ..Outbound::text("c", "x") }).unwrap_err().kind, K::Unsupported);
        // Without a mobile notifier, buttons fall back to numbered text.
        let h4 = HomeAssistant::new("ha", &url, "tok", 1, opts()).unwrap();
        h4.send(&Outbound { buttons: vec![vec![crate::Button { label: "Yes".into(), data: "y".into(), url: None }]], ..Outbound::text("c", "pick") }).unwrap();
        let last = seen.lock().unwrap().iter().rev().find(|v| v["type"] == "fire_event").unwrap().clone();
        assert_eq!(last["event_data"]["text"], "pick\n\n1. Yes");
    }

    #[test]
    fn bad_token_is_auth_and_not_retried() {
        let (url, _, conns) = fake_ha(false, |_, _, _| {});
        let h = HomeAssistant::new("ha", &url, "BAD", 2, opts()).unwrap();
        let e = h.poll(&Cancel::new()).unwrap_err();
        assert_eq!(e.kind, K::Auth);
        assert!(!e.message.contains("BAD"), "{}", e.message);
        assert_eq!(h.send(&Outbound::text("c", "x")).unwrap_err().kind, K::Auth);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(conns.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn missing_pong_reconnects_and_cancel_is_prompt() {
        let (url, seen, conns) = fake_ha(true, |_, ws, seen| {
            // Never answer pings; drain frames until the client gives up.
            while let Ok(m) = ws.recv_blocking() {
                if let Message::Text(t) = m {
                    seen.lock().unwrap().push(serde_json::from_str(&t).unwrap());
                }
            }
        });
        let h = HomeAssistant::new("ha", &url, "tok", 30, Options { heartbeat: Duration::from_millis(200), ..opts() }).unwrap();
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let start = Instant::now();
        assert!(h.poll(&c).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(2));
        let until = Instant::now() + Duration::from_secs(5);
        while conns.load(Ordering::SeqCst) < 2 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(conns.load(Ordering::SeqCst) >= 2, "no pong → reconnect");
        assert!(seen.lock().unwrap().iter().any(|v| v["type"] == "ping"));
        h.stop();
        // Sending with no server at all times out as a retryable Network error.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = format!("http://{}", l.local_addr().unwrap());
        drop(l);
        let h = HomeAssistant::new("ha", &dead, "tok", 1, Options { send_timeout: Duration::from_millis(300), ..opts() }).unwrap();
        let e = h.send(&Outbound::text("c", "x")).unwrap_err();
        assert!(e.is_retryable(), "{e}");
        h.stop();
    }
}
