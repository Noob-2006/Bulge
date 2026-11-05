//! Nostr encrypted DMs (ported from OpenClaw `extensions/nostr`, MIT).
//!
//! Receive: one worker thread per relay keeps a WebSocket open (REQ / EVENT /
//! EOSE / OK / NOTICE / CLOSED / AUTH), reconnects with backoff and re-sends the
//! subscription with `since` = the persisted cursor minus a 120 s lookback.
//! Events from all relays are de-duplicated by id, id and BIP-340 signature
//! are verified, and the guards upstream applies are kept (own events, wrong
//! kind / missing `p` tag, 120 s future skew, 16 KiB ciphertext, 8 KiB
//! plaintext). NIP-04 (kind 4) DMs always; NIP-17 gift-wrapped DMs (kind 1059
//! → seal 13 → rumor 14, NIP-44 v2) when `nip17 = true`.
//! Send: NIP-04 (or NIP-17 to senders who wrote that way) with an `e` tag for
//! replies, published to every relay and acknowledged by the first `OK`.
//! A kind-0 profile is published on the first connection when `profile` is set.
//! NIP-05: a recipient may be `name@domain` (or `domain` for `_@domain`); it is
//! resolved with `GET https://<domain>/.well-known/nostr.json?name=<name>`
//! (redirects refused, as NIP-05 requires) and cached; `Nip05::verify` checks
//! that an identifier maps to a given pubkey. The relay hints of the answer are
//! returned but not dialed (DMs go to our configured relays).
//! Delivery is at-least-once: the cursor is committed when the caller polls again.
//!
//! The relay worker (`Relay`), the event type and the dedup set are shared
//! with the `buzz` channel.

use crate::secp256k1::{self as k1, nip04, nip44};
use crate::{write_atomic, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Outbound, ReplyRef, Sent};
use ark_core::Cancel;
use ark_net::crypto::hex;
use ark_net::ws::{Message, WebSocket};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_RELAYS: [&str; 2] = ["wss://relay.damus.io", "wss://nos.lol"];
const LOOKBACK: i64 = 120;
const MAX_FUTURE_SKEW: i64 = 120;
const MAX_CIPHERTEXT: usize = 16 * 1024;
const MAX_PLAINTEXT: usize = 8 * 1024;
/// NIP-59 randomises wrap / seal timestamps up to two days into the past.
const GIFT_WRAP_SKEW: i64 = 2 * 24 * 3600;
const SEEN_CAP: usize = 1000;

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

// ---------------------------------------------------------------- keys & events

pub struct Keys {
    pub sk: [u8; 32],
    pub pk: [u8; 32],
    pub pk_hex: String,
}

impl Keys {
    pub fn from_secret(s: &str) -> Result<Keys, String> {
        let sk = k1::parse_secret_key(s)?;
        Self::from_bytes(sk)
    }
    pub fn from_bytes(sk: [u8; 32]) -> Result<Keys, String> {
        let pk = k1::xonly_pubkey(&sk).ok_or("invalid private key")?;
        Ok(Keys { sk, pk, pk_hex: hex(&pk) })
    }
    pub fn generate() -> Keys {
        Self::from_bytes(k1::random_secret()).expect("random key")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    #[serde(default)]
    pub sig: String,
}

/// NIP-01 id: sha256 of `[0, pubkey, created_at, kind, tags, content]` (serde_json escaping = NIP-01's).
pub(crate) fn event_id(pubkey: &str, created_at: i64, kind: u32, tags: &[Vec<String>], content: &str) -> [u8; 32] {
    let ser = serde_json::to_string(&json!([0, pubkey, created_at, kind, tags, content])).expect("json");
    ark_net::crypto::sha256(ser.as_bytes())
}

impl Event {
    pub fn signed(keys: &Keys, kind: u32, tags: Vec<Vec<String>>, content: &str, created_at: i64) -> Event {
        let id = event_id(&keys.pk_hex, created_at, kind, &tags, content);
        let sig = k1::sign(&keys.sk, &id).expect("valid key signs");
        Event { id: hex(&id), pubkey: keys.pk_hex.clone(), created_at, kind, tags, content: content.to_string(), sig: hex(&sig) }
    }

    /// Unsigned event with its id (NIP-59 rumor).
    pub fn unsigned(pubkey: &str, kind: u32, tags: Vec<Vec<String>>, content: &str, created_at: i64) -> Event {
        let id = event_id(pubkey, created_at, kind, &tags, content);
        Event { id: hex(&id), pubkey: pubkey.to_string(), created_at, kind, tags, content: content.to_string(), sig: String::new() }
    }

    pub fn id_ok(&self) -> bool {
        hex(&event_id(&self.pubkey, self.created_at, self.kind, &self.tags, &self.content)) == self.id
    }

    /// Recomputes the id and checks the BIP-340 signature.
    pub fn verify(&self) -> bool {
        let (Some(pk), Some(sig)) = (hex32(&self.pubkey), ark_net::crypto::hex_decode(&self.sig).and_then(|s| <[u8; 64]>::try_from(s).ok())) else { return false };
        let id = event_id(&self.pubkey, self.created_at, self.kind, &self.tags, &self.content);
        hex(&id) == self.id && k1::schnorr_verify(&pk, &id, &sig)
    }

    pub fn tag(&self, name: &str) -> Option<&str> {
        self.tags.iter().find(|t| t.first().is_some_and(|n| n == name)).and_then(|t| t.get(1)).map(String::as_str)
    }

    pub fn tags_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Vec<String>> + 'a {
        self.tags.iter().filter(move |t| t.first().is_some_and(|n| n == name) && t.len() > 1)
    }

    pub fn has_p(&self, pk_hex: &str) -> bool {
        self.tags_named("p").any(|t| t[1].eq_ignore_ascii_case(pk_hex))
    }
}

pub(crate) fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    ark_net::crypto::hex_decode(s).and_then(|b| b.try_into().ok())
}

pub(crate) fn tag(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// Bounded insertion-ordered set for event-id dedup.
#[derive(Default)]
pub(crate) struct Seen {
    set: HashSet<String>,
    order: VecDeque<String>,
    cap: usize,
}

impl Seen {
    pub fn new(cap: usize) -> Seen {
        Seen { cap, ..Default::default() }
    }
    /// True when newly inserted.
    pub fn insert(&mut self, id: &str) -> bool {
        if self.set.contains(id) {
            return false;
        }
        self.set.insert(id.to_string());
        self.order.push_back(id.to_string());
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
    pub fn contains(&self, id: &str) -> bool {
        self.set.contains(id)
    }
    pub fn list(&self) -> Vec<String> {
        self.order.iter().cloned().collect()
    }
}

// ---------------------------------------------------------------- relay worker

/// What a relay worker reports to its channel. (`relay` / diagnostic fields are
/// kept for callers that track per-relay health.)
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) enum RelayIn {
    Connected { relay: String },
    Event { relay: String, sub: String, event: Event },
    Eose { relay: String, sub: String },
    Closed { relay: String, sub: String, reason: String },
    Notice { relay: String, message: String },
    AuthFailed { relay: String, reason: String },
    Disconnected { relay: String, error: String },
}

enum Cmd {
    Publish(Event, Sender<Result<(), String>>),
    Raw(String),
    Req(String, Vec<Value>),
}

pub type SubsFn = Arc<dyn Fn() -> Vec<(String, Vec<Value>)> + Send + Sync>;

#[derive(Clone)]
pub struct RelayOpts {
    pub url: String,
    pub keys: Arc<Keys>,
    /// Answer NIP-42 AUTH challenges.
    pub auth: bool,
    /// Wait for the AUTH challenge and its OK before subscribing (Buzz).
    pub require_auth: bool,
    /// Extra tag for the kind-22242 event (Buzz NIP-OA owner attestation).
    pub auth_tag: Option<Vec<String>>,
    /// Subscriptions to (re)send on every connect; computed fresh so `since` resumes.
    pub subs: SubsFn,
    pub connect_timeout: Duration,
    pub backoff_base: Duration,
    pub backoff_max: Duration,
    pub ping_every: Duration,
    /// Reconnect when nothing (not even a pong) arrived for this long.
    pub idle_timeout: Duration,
}

impl RelayOpts {
    pub fn new(url: &str, keys: Arc<Keys>, subs: SubsFn) -> RelayOpts {
        RelayOpts {
            url: url.to_string(),
            keys,
            auth: true,
            require_auth: false,
            auth_tag: None,
            subs,
            connect_timeout: Duration::from_secs(15),
            backoff_base: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            ping_every: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
        }
    }
}

pub(crate) struct Relay {
    pub url: String,
    cmd: Mutex<Sender<Cmd>>,
    stop: Arc<AtomicBool>,
    connected: Arc<AtomicBool>,
}

pub(crate) fn auth_event(keys: &Keys, relay: &str, challenge: &str, extra: Option<&Vec<String>>) -> Event {
    let mut tags = vec![tag(&["relay", relay]), tag(&["challenge", challenge])];
    if let Some(t) = extra {
        tags.push(t.clone());
    }
    Event::signed(keys, 22242, tags, "", now())
}

impl Relay {
    pub fn spawn(opts: RelayOpts, out: Sender<RelayIn>) -> Relay {
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let connected = Arc::new(AtomicBool::new(false));
        let (s2, c2) = (stop.clone(), connected.clone());
        let url = opts.url.clone();
        std::thread::Builder::new()
            .name(format!("relay {url}"))
            .spawn(move || relay_loop(opts, rx, out, s2, c2))
            .expect("spawn relay thread");
        Relay { url, cmd: Mutex::new(tx), stop, connected }
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Queue an EVENT; the receiver yields the relay's OK verdict.
    pub fn publish(&self, ev: &Event) -> Receiver<Result<(), String>> {
        let (tx, rx) = mpsc::channel();
        if !self.is_connected() {
            let _ = tx.send(Err(format!("{}: not connected", self.url)));
        } else if self.cmd.lock().unwrap().send(Cmd::Publish(ev.clone(), tx.clone())).is_err() {
            let _ = tx.send(Err("relay worker stopped".into()));
        }
        rx
    }

    /// Fire-and-forget frame (typing indicators).
    pub fn send_raw(&self, frame: String) {
        let _ = self.cmd.lock().unwrap().send(Cmd::Raw(frame));
    }

    pub fn req(&self, sub: &str, filters: Vec<Value>) {
        let _ = self.cmd.lock().unwrap().send(Cmd::Req(sub.to_string(), filters));
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Publish to every relay; `Ok(relay)` on the first acceptance. Rejections keep
/// their NIP-01 machine-readable prefix for error mapping.
pub(crate) fn publish_any(relays: &[Arc<Relay>], ev: &Event, timeout: Duration) -> Result<String, ChannelError> {
    let mut pending: Vec<(String, Receiver<Result<(), String>>)> = relays.iter().map(|r| (r.url.clone(), r.publish(ev))).collect();
    let deadline = Instant::now() + timeout;
    let mut errors: Vec<String> = Vec::new();
    while !pending.is_empty() {
        let mut i = 0;
        while i < pending.len() {
            match pending[i].1.try_recv() {
                Ok(Ok(())) => return Ok(pending[i].0.clone()),
                Ok(Err(e)) => {
                    errors.push(e);
                    pending.remove(i);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    errors.push(format!("{}: connection lost before OK", pending[i].0));
                    pending.remove(i);
                }
                Err(mpsc::TryRecvError::Empty) => i += 1,
            }
        }
        if pending.is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            errors.extend(pending.iter().map(|(u, _)| format!("{u}: timed out waiting for OK")));
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(publish_error(&errors))
}

fn publish_error(errors: &[String]) -> ChannelError {
    let msg = format!("publish failed on every relay: {}", errors.join("; "));
    let has = |p: &str| errors.iter().any(|e| e.contains(p));
    let kind = if errors.is_empty() {
        K::Network
    } else if has("rate-limited") {
        K::RateLimited { retry_after: None }
    } else if has("auth-required") || has("restricted") {
        K::Auth
    } else if has("blocked") {
        K::NotFound
    } else if errors.iter().all(|e| e.contains("invalid") || e.contains("pow") || e.contains("error:")) {
        K::Protocol
    } else {
        K::Network
    };
    ChannelError::new(kind, msg)
}

fn relay_loop(opts: RelayOpts, rx: Receiver<Cmd>, out: Sender<RelayIn>, stop: Arc<AtomicBool>, connected: Arc<AtomicBool>) {
    let mut backoff = opts.backoff_base;
    while !stop.load(Ordering::SeqCst) {
        let started = Instant::now();
        let r = session(&opts, &rx, &out, &stop, &connected);
        connected.store(false, Ordering::SeqCst);
        match r {
            Ok(()) => return,
            Err(Fail::Auth(reason)) => {
                let _ = out.send(RelayIn::AuthFailed { relay: opts.url.clone(), reason });
            }
            Err(Fail::Io(error)) => {
                if out.send(RelayIn::Disconnected { relay: opts.url.clone(), error }).is_err() {
                    return;
                }
            }
        }
        if started.elapsed() > Duration::from_secs(60) {
            backoff = opts.backoff_base;
        }
        // Back off; publishes meanwhile fail fast.
        let until = Instant::now() + backoff;
        while Instant::now() < until {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            while let Ok(c) = rx.try_recv() {
                if let Cmd::Publish(_, tx) = c {
                    let _ = tx.send(Err(format!("{}: not connected", opts.url)));
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        backoff = (backoff * 2).min(opts.backoff_max);
    }
}

enum Fail {
    Io(String),
    Auth(String),
}

fn io(e: impl std::fmt::Display) -> Fail {
    Fail::Io(e.to_string())
}

fn session(opts: &RelayOpts, rx: &Receiver<Cmd>, out: &Sender<RelayIn>, stop: &AtomicBool, connected: &AtomicBool) -> Result<(), Fail> {
    let (mut ws, _) = WebSocket::connect(&opts.url, &[], opts.connect_timeout).map_err(io)?;
    ws.set_read_timeout(Some(Duration::from_millis(100))).map_err(io)?;
    ws.set_max_message(4 * 1024 * 1024);
    let relay = opts.url.clone();
    let mut pending: HashMap<String, (Sender<Result<(), String>>, Instant)> = HashMap::new();
    let mut auth_id: Option<String> = None;
    let mut last_rx = Instant::now();
    let mut last_ping = Instant::now();
    let mut ready = !opts.require_auth;
    let auth_deadline = Instant::now() + Duration::from_secs(20);
    if ready {
        on_ready(opts, &mut ws, out, connected)?;
    }
    loop {
        if stop.load(Ordering::SeqCst) {
            let _ = ws.send(&Message::Close(Some((1000, String::new()))));
            return Ok(());
        }
        if !ready && Instant::now() > auth_deadline {
            return Err(Fail::Auth("timed out waiting for the NIP-42 AUTH challenge".into()));
        }
        if ready {
            while let Ok(c) = rx.try_recv() {
                match c {
                    Cmd::Publish(ev, tx) => {
                        let frame = json!(["EVENT", ev]).to_string();
                        if let Err(e) = ws.send_text(&frame) {
                            let _ = tx.send(Err(format!("{relay}: {e}")));
                            return Err(io(e));
                        }
                        pending.insert(ev.id.clone(), (tx, Instant::now() + Duration::from_secs(15)));
                    }
                    Cmd::Raw(f) => ws.send_text(&f).map_err(io)?,
                    Cmd::Req(sub, filters) => ws.send_text(&req_frame(&sub, &filters)).map_err(io)?,
                }
            }
        }
        let now_i = Instant::now();
        pending.retain(|_, (tx, dl)| {
            if *dl < now_i {
                let _ = tx.send(Err(format!("{relay}: timed out waiting for OK")));
                false
            } else {
                true
            }
        });
        if last_ping.elapsed() >= opts.ping_every {
            ws.send(&Message::Ping(b"ark".to_vec())).map_err(io)?;
            last_ping = Instant::now();
        }
        if last_rx.elapsed() >= opts.idle_timeout {
            return Err(io("relay went silent"));
        }
        let m = match ws.recv() {
            Ok(None) => continue,
            Ok(Some(m)) => m,
            Err(e) => return Err(io(e)),
        };
        last_rx = Instant::now();
        let text = match m {
            Message::Text(t) => t,
            Message::Close(c) => return Err(io(format!("relay closed the connection {c:?}"))),
            _ => continue,
        };
        let Ok(Value::Array(a)) = serde_json::from_str::<Value>(&text) else { continue };
        let s = |i: usize| a.get(i).and_then(Value::as_str).unwrap_or("").to_string();
        match a.first().and_then(Value::as_str).unwrap_or("") {
            "EVENT" => {
                if let Some(Ok(event)) = a.get(2).map(|v| serde_json::from_value::<Event>(v.clone())) {
                    if out.send(RelayIn::Event { relay: relay.clone(), sub: s(1), event }).is_err() {
                        return Ok(());
                    }
                }
            }
            "EOSE" => {
                let _ = out.send(RelayIn::Eose { relay: relay.clone(), sub: s(1) });
            }
            "OK" => {
                let id = s(1);
                let ok = a.get(2).and_then(Value::as_bool).unwrap_or(false);
                let msg = s(3);
                if auth_id.as_deref() == Some(id.as_str()) {
                    auth_id = None;
                    if !ok {
                        return Err(Fail::Auth(format!("AUTH rejected: {msg}")));
                    }
                    if !ready {
                        ready = true;
                        on_ready(opts, &mut ws, out, connected)?;
                    }
                    continue;
                }
                if let Some((tx, _)) = pending.remove(&id) {
                    // A duplicate means the relay already has it.
                    let _ = tx.send(if ok || msg.starts_with("duplicate:") { Ok(()) } else { Err(format!("{relay}: {msg}")) });
                }
            }
            "NOTICE" => {
                let _ = out.send(RelayIn::Notice { relay: relay.clone(), message: s(1) });
                if !ready {
                    return Err(Fail::Auth(format!("relay notice before AUTH: {}", s(1))));
                }
            }
            "CLOSED" => {
                if !ready {
                    return Err(Fail::Auth(format!("subscription closed before AUTH: {}", s(2))));
                }
                let _ = out.send(RelayIn::Closed { relay: relay.clone(), sub: s(1), reason: s(2) });
            }
            "AUTH" if opts.auth || opts.require_auth => {
                let ev = auth_event(&opts.keys, &relay, &s(1), opts.auth_tag.as_ref());
                auth_id = Some(ev.id.clone());
                ws.send_text(&json!(["AUTH", ev]).to_string()).map_err(io)?;
                if ready {
                    // Relays that demanded auth for a REQ answered CLOSED auth-required; re-send them.
                    resubscribe(opts, &mut ws)?;
                }
            }
            _ => {}
        }
    }
}

fn req_frame(sub: &str, filters: &[Value]) -> String {
    let mut a = vec![json!("REQ"), json!(sub)];
    a.extend(filters.iter().cloned());
    Value::Array(a).to_string()
}

fn resubscribe(opts: &RelayOpts, ws: &mut WebSocket<ark_net::Stream>) -> Result<(), Fail> {
    for (sub, filters) in (opts.subs)() {
        ws.send_text(&req_frame(&sub, &filters)).map_err(io)?;
    }
    Ok(())
}

fn on_ready(opts: &RelayOpts, ws: &mut WebSocket<ark_net::Stream>, out: &Sender<RelayIn>, connected: &AtomicBool) -> Result<(), Fail> {
    connected.store(true, Ordering::SeqCst);
    let _ = out.send(RelayIn::Connected { relay: opts.url.clone() });
    resubscribe(opts, ws)
}

// ---------------------------------------------------------------- NIP-05

const NIP05_TTL: Duration = Duration::from_secs(3600);
const NIP05_MISS_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nip05Found {
    pub pubkey: [u8; 32],
    /// The `relays` hint for this pubkey (ws/wss URLs only).
    pub relays: Vec<String>,
}

/// `name@domain` / `domain` → (lower-case local part, lower-case domain).
pub fn parse_nip05(ident: &str) -> Option<(String, String)> {
    let t = ident.trim().to_ascii_lowercase();
    let (local, domain) = t.split_once('@').unwrap_or(("_", t.as_str()));
    let local_ok = !local.is_empty() && local.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
    let domain_ok = domain.contains('.') && !domain.starts_with(['.', '-']) && domain.chars().all(|c| c.is_ascii_alphanumeric() || "-.:".contains(c));
    (local_ok && domain_ok).then(|| (local.to_string(), domain.to_string()))
}

type Nip05Cached = (Result<Nip05Found, ChannelError>, Instant);

/// NIP-05 resolver with a TTL cache (misses are cached briefly, network errors not at all).
pub struct Nip05 {
    http: crate::http::Http,
    /// Test hook: `http://127.0.0.1:port` instead of `https://<domain>`.
    pub base: Option<String>,
    cache: Mutex<HashMap<String, Nip05Cached>>,
}

impl Nip05 {
    pub fn new(timeout: Duration) -> Nip05 {
        let agent = ark_net::http::builder().http_status_as_error(false).max_redirects(0).timeout_connect(Some(timeout)).timeout_global(Some(timeout)).build().into();
        Nip05 { http: crate::http::Http { agent, headers: Vec::new() }, base: None, cache: Mutex::new(HashMap::new()) }
    }

    pub fn lookup(&self, ident: &str) -> Result<Nip05Found, ChannelError> {
        let (local, domain) = parse_nip05(ident).ok_or_else(|| ChannelError::new(K::Fatal, format!("{ident:?} is not a NIP-05 identifier")))?;
        let key = format!("{local}@{domain}");
        if let Some((r, at)) = self.cache.lock().unwrap().get(&key) {
            if at.elapsed() < if r.is_ok() { NIP05_TTL } else { NIP05_MISS_TTL } {
                return r.clone();
            }
        }
        let r = self.fetch(&local, &domain);
        if r.as_ref().is_ok() || r.as_ref().is_err_and(|e| e.kind == K::NotFound) {
            self.cache.lock().unwrap().insert(key, (r.clone(), Instant::now()));
        }
        r
    }

    /// `ident` resolves to `pubkey` (hex or npub).
    pub fn verify(&self, ident: &str, pubkey: &str) -> Result<bool, ChannelError> {
        let pk = k1::parse_pubkey(pubkey).map_err(|e| ChannelError::new(K::Fatal, e))?;
        match self.lookup(ident) {
            Ok(f) => Ok(f.pubkey == pk),
            Err(e) if e.kind == K::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn fetch(&self, local: &str, domain: &str) -> Result<Nip05Found, ChannelError> {
        let base = self.base.clone().unwrap_or_else(|| format!("https://{domain}"));
        let url = format!("{base}/.well-known/nostr.json?{}", ark_net::form_encode(&[("name", local)]));
        let r = self.http.call("GET", &url, &[("accept", "application/json")], crate::http::Payload::None)?;
        let miss = |why: String| ChannelError::new(K::NotFound, format!("NIP-05 {local}@{domain}: {why}"));
        match r.status {
            200 => {}
            300..=399 => return Err(miss("redirects are not allowed".into())),
            404 | 410 => return Err(miss("no nostr.json".into())),
            s => return Err(crate::http::classify(s, r.retry_after, &format!("NIP-05 {local}@{domain}"), "")),
        }
        let v: Value = serde_json::from_str(&r.body).map_err(|_| miss("nostr.json is not JSON".into()))?;
        // Names are matched case-insensitively.
        let names = v["names"].as_object().ok_or_else(|| miss("no names".into()))?;
        let hex_pk = names.iter().find(|(n, _)| n.eq_ignore_ascii_case(local)).and_then(|(_, p)| p.as_str()).ok_or_else(|| miss("name not listed".into()))?;
        // NIP-05 requires hex here, not npub.
        let pubkey = hex32(&hex_pk.to_ascii_lowercase()).ok_or_else(|| miss("pubkey is not 64 hex characters".into()))?;
        let relays = v["relays"]
            .as_object()
            .and_then(|m| m.iter().find(|(k, _)| k.eq_ignore_ascii_case(hex_pk)).map(|(_, r)| r))
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).filter(|u| u.starts_with("wss://") || u.starts_with("ws://")).map(str::to_string).collect())
            .unwrap_or_default();
        Ok(Nip05Found { pubkey, relays })
    }
}

/// Recipient: hex / npub / nprofile, else a NIP-05 identifier.
fn recipient(chat: &str, nip05: &Nip05) -> Result<[u8; 32], ChannelError> {
    match k1::parse_pubkey(chat) {
        Ok(pk) => Ok(pk),
        Err(e) if !chat.contains('@') && !chat.contains('.') => Err(ChannelError::new(K::Fatal, format!("bad nostr recipient {chat}: {e}"))),
        Err(_) => nip05.lookup(chat).map(|f| f.pubkey),
    }
}

// ---------------------------------------------------------------- the channel

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nip05: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lud16: Option<String>,
}

impl Profile {
    fn validate(&self) -> Result<(), String> {
        for (k, v) in [("picture", &self.picture), ("banner", &self.banner), ("website", &self.website)] {
            if let Some(u) = v {
                if !u.starts_with("https://") {
                    return Err(format!("profile.{k} must use https://"));
                }
            }
        }
        for (k, v, max) in [("name", &self.name, 256), ("display_name", &self.display_name, 256), ("about", &self.about, 2000)] {
            if v.as_ref().is_some_and(|s| s.chars().count() > max) {
                return Err(format!("profile.{k} is longer than {max} characters"));
            }
        }
        Ok(())
    }
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    since: i64,
    #[serde(default)]
    seen: Vec<String>,
    #[serde(default)]
    profile_at: i64,
}

struct Inner {
    seen: Seen,
    /// Highest delivered created_at, committed on the next poll.
    cursor: i64,
    pending_cursor: Option<i64>,
    /// Ids of events we published (reply `is_own`).
    own: Seen,
    /// Senders that wrote over NIP-17: answer the same way.
    nip17_peers: HashSet<String>,
    auth_failed: HashSet<String>,
    profile_done: bool,
    profile_at: i64,
}

pub struct Nostr {
    id: String,
    keys: Arc<Keys>,
    relays: Vec<Arc<Relay>>,
    rx: Mutex<Receiver<RelayIn>>,
    inner: Arc<Mutex<Inner>>,
    state: PathBuf,
    poll_timeout: Duration,
    nip17: bool,
    profile: Option<Profile>,
    pub publish_timeout: Duration,
    pub nip05: Nip05,
}

impl Nostr {
    #[allow(clippy::too_many_arguments)]
    pub fn new(id: &str, secret: &str, relays: &[String], state: PathBuf, poll_timeout_secs: u64, nip17: bool, profile: Option<Profile>, opts: impl Fn(&mut RelayOpts)) -> Result<Nostr, String> {
        let keys = Arc::new(Keys::from_secret(secret).map_err(|e| format!("channel {id}: private_key: {e}"))?);
        if let Some(p) = &profile {
            p.validate().map_err(|e| format!("channel {id}: {e}"))?;
        }
        let relays: Vec<String> = if relays.is_empty() { DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect() } else { relays.to_vec() };
        let mut uniq = Vec::new();
        for r in relays {
            let r = r.trim().trim_end_matches('/').to_string();
            ark_net::Url::parse(&r).map_err(|e| format!("channel {id}: relay {r}: {e}"))?;
            if !r.starts_with("ws://") && !r.starts_with("wss://") {
                return Err(format!("channel {id}: relay {r} must be ws:// or wss://"));
            }
            if !uniq.contains(&r) {
                uniq.push(r);
            }
        }
        let st: State = std::fs::read_to_string(&state).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let cursor = if st.since > 0 { st.since } else { now() };
        let mut seen = Seen::new(SEEN_CAP);
        for s in &st.seen {
            seen.insert(s);
        }
        let inner = Arc::new(Mutex::new(Inner { seen, cursor, pending_cursor: None, own: Seen::new(SEEN_CAP), nip17_peers: HashSet::new(), auth_failed: HashSet::new(), profile_done: false, profile_at: st.profile_at }));
        let (tx, rx) = mpsc::channel();
        let pk = keys.pk_hex.clone();
        let i2 = inner.clone();
        let subs: SubsFn = Arc::new(move || {
            let since = i2.lock().unwrap().cursor;
            let mut filters = vec![json!({"kinds": [4], "#p": [pk], "since": (since - LOOKBACK).max(0)})];
            if nip17 {
                filters.push(json!({"kinds": [1059], "#p": [pk], "since": (since - LOOKBACK - GIFT_WRAP_SKEW).max(0)}));
            }
            vec![("ark-dm".to_string(), filters)]
        });
        let relays = uniq
            .iter()
            .map(|u| {
                let mut o = RelayOpts::new(u, keys.clone(), subs.clone());
                opts(&mut o);
                Arc::new(Relay::spawn(o, tx.clone()))
            })
            .collect();
        Ok(Nostr { id: id.to_string(), keys, relays, rx: Mutex::new(rx), inner, state, poll_timeout: Duration::from_secs(poll_timeout_secs.max(1)), nip17, profile, publish_timeout: Duration::from_secs(10), nip05: Nip05::new(Duration::from_secs(10)) })
    }

    pub fn public_key(&self) -> &str {
        &self.keys.pk_hex
    }

    fn save(&self, g: &Inner) -> Result<(), ChannelError> {
        let st = State { since: g.cursor, seen: g.seen.list(), profile_at: g.profile_at };
        write_atomic(&self.state, serde_json::to_string(&st).unwrap().as_bytes()).map_err(|e| ChannelError::new(K::Fatal, format!("saving nostr state: {e}")))
    }

    fn commit_pending(&self) -> Result<(), ChannelError> {
        let mut g = self.inner.lock().unwrap();
        if let Some(c) = g.pending_cursor.take() {
            g.cursor = g.cursor.max(c);
            self.save(&g)?;
        }
        Ok(())
    }

    /// Kind-0 profile (replaceable: created_at must advance past the last publish).
    fn publish_profile(&self) {
        let Some(p) = &self.profile else { return };
        let at = {
            let mut g = self.inner.lock().unwrap();
            if g.profile_done {
                return;
            }
            g.profile_done = true;
            now().max(g.profile_at + 1)
        };
        let ev = Event::signed(&self.keys, 0, vec![], &serde_json::to_string(p).unwrap(), at);
        let relays = self.relays.clone();
        let inner = self.inner.clone();
        let state = self.state.clone();
        let timeout = self.publish_timeout;
        // Off the poll thread: the OK can take a while.
        std::thread::spawn(move || {
            if publish_any(&relays, &ev, timeout).is_ok() {
                let mut g = inner.lock().unwrap();
                g.profile_at = at;
                let st = State { since: g.cursor, seen: g.seen.list(), profile_at: at };
                let _ = write_atomic(&state, serde_json::to_string(&st).unwrap().as_bytes());
            } else {
                inner.lock().unwrap().profile_done = false;
            }
        });
    }

    fn handle(&self, m: RelayIn) -> Option<Inbound> {
        match m {
            RelayIn::Connected { relay } => {
                self.inner.lock().unwrap().auth_failed.remove(&relay);
                self.publish_profile();
                None
            }
            RelayIn::AuthFailed { relay, .. } => {
                self.inner.lock().unwrap().auth_failed.insert(relay);
                None
            }
            RelayIn::Event { event, .. } => self.inbound(event),
            _ => None,
        }
    }

    fn inbound(&self, ev: Event) -> Option<Inbound> {
        let mut g = self.inner.lock().unwrap();
        if g.seen.contains(&ev.id) {
            return None;
        }
        if ev.pubkey.eq_ignore_ascii_case(&self.keys.pk_hex) {
            return None;
        }
        if ev.created_at > now() + MAX_FUTURE_SKEW {
            return None;
        }
        let wanted = ev.kind == 4 || (self.nip17 && ev.kind == 1059);
        if !wanted || !ev.has_p(&self.keys.pk_hex) || ev.content.len() > MAX_CIPHERTEXT * if ev.kind == 1059 { 4 } else { 1 } {
            return None;
        }
        if !ev.verify() {
            return None;
        }
        g.seen.insert(&ev.id);
        let (sender, text, msg_id, ts, tags) = if ev.kind == 4 {
            let pk = hex32(&ev.pubkey)?;
            let text = nip04::decrypt(&self.keys.sk, &pk, &ev.content).ok()?;
            (ev.pubkey.to_lowercase(), text, ev.id.clone(), ev.created_at, ev.tags.clone())
        } else {
            let rumor = unwrap_gift(&self.keys, &ev)?;
            g.nip17_peers.insert(rumor.pubkey.to_lowercase());
            (rumor.pubkey.to_lowercase(), rumor.content.clone(), rumor.id.clone(), rumor.created_at, rumor.tags.clone())
        };
        if text.len() > MAX_PLAINTEXT || text.trim().is_empty() {
            return None;
        }
        g.pending_cursor = Some(g.pending_cursor.unwrap_or(0).max(ev.created_at.min(now())));
        let reply = tags.iter().rev().find(|t| t.len() > 1 && t[0] == "e").map(|t| ReplyRef { id: t[1].clone(), is_own: g.own.contains(&t[1]), ..Default::default() });
        let npub = hex32(&sender).map(|k| k1::npub(&k)).unwrap_or_default();
        Some(Inbound {
            channel: self.id.clone(),
            chat: sender.clone(),
            chat_type: ChatType::Direct,
            sender,
            sender_name: npub.chars().take(16).collect(),
            text,
            message_id: msg_id,
            ts,
            reply,
            ..Default::default()
        })
    }

    fn dm_event(&self, to: &[u8; 32], text: &str, reply_to: Option<&str>, nip17: bool) -> Result<Vec<Event>, ChannelError> {
        let to_hex = hex(to);
        let mut tags = vec![tag(&["p", &to_hex])];
        if let Some(r) = reply_to {
            tags.push(tag(&["e", r]));
        }
        if !nip17 {
            let c = nip04::encrypt(&self.keys.sk, to, text).map_err(|e| ChannelError::new(K::Fatal, e))?;
            return Ok(vec![Event::signed(&self.keys, 4, tags, &c, now())]);
        }
        let rumor = Event::unsigned(&self.keys.pk_hex, 14, tags, text, now());
        Ok(vec![gift_wrap(&self.keys, to, &rumor).map_err(|e| ChannelError::new(K::Fatal, e))?])
    }
}

/// NIP-59 seal + gift wrap of a rumor for `to`.
pub(crate) fn gift_wrap(keys: &Keys, to: &[u8; 32], rumor: &Event) -> Result<Event, String> {
    let rand_past = |max: i64| now() - (u32::from_le_bytes(ark_net::crypto::random_bytes(4).try_into().unwrap()) as i64 % max.max(1));
    let ck = nip44::conversation_key(&keys.sk, to).ok_or("invalid recipient key")?;
    let seal = Event::signed(keys, 13, vec![], &nip44::encrypt(&ck, &serde_json::to_string(rumor).unwrap(), None)?, rand_past(GIFT_WRAP_SKEW));
    let eph = Keys::generate();
    let ck2 = nip44::conversation_key(&eph.sk, to).ok_or("invalid recipient key")?;
    Ok(Event::signed(&eph, 1059, vec![tag(&["p", &hex(to)])], &nip44::encrypt(&ck2, &serde_json::to_string(&seal).unwrap(), None)?, rand_past(GIFT_WRAP_SKEW)))
}

/// Gift wrap → verified seal → rumor (kind 14, authored by the seal's signer).
pub(crate) fn unwrap_gift(keys: &Keys, wrap: &Event) -> Option<Event> {
    let ck = nip44::conversation_key(&keys.sk, &hex32(&wrap.pubkey)?)?;
    let seal: Event = serde_json::from_str(&nip44::decrypt(&ck, &wrap.content).ok()?).ok()?;
    if seal.kind != 13 || !seal.verify() {
        return None;
    }
    let ck2 = nip44::conversation_key(&keys.sk, &hex32(&seal.pubkey)?)?;
    let rumor: Event = serde_json::from_str(&nip44::decrypt(&ck2, &seal.content).ok()?).ok()?;
    (rumor.kind == 14 && rumor.pubkey.eq_ignore_ascii_case(&seal.pubkey) && rumor.id_ok()).then_some(rumor)
}

/// Text for platforms without buttons / uploads: options and media as plain lines.
pub(crate) fn flatten(out: &Outbound) -> String {
    let mut text = out.text.clone();
    let mut n = 0;
    for row in &out.buttons {
        for b in row {
            n += 1;
            let line = match &b.url {
                Some(u) => format!("{n}. {} — {u}", b.label),
                None => format!("{n}. {}", b.label),
            };
            text = if text.is_empty() { line } else { format!("{text}\n{line}") };
        }
    }
    for m in &out.media {
        if let Some(u) = &m.url {
            let line = match &m.caption {
                Some(c) if !c.is_empty() => format!("{c}: {u}"),
                _ => u.clone(),
            };
            text = if text.is_empty() { line } else { format!("{text}\n{line}") };
        }
    }
    text
}

const MAX_LEN: usize = 4000;

impl Channel for Nostr {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps { chat_types: vec![ChatType::Direct], media: true, reply: true, delete: true, max_len: MAX_LEN, len_unit: LenUnit::Chars, markup: Markup::Markdown, ..Caps::default() }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        self.commit_pending()?;
        let rx = self.rx.lock().unwrap();
        let until = Instant::now() + self.poll_timeout;
        let mut got = Vec::new();
        loop {
            if cancel.is_cancelled() {
                return Ok(got);
            }
            {
                let g = self.inner.lock().unwrap();
                if !self.relays.is_empty() && g.auth_failed.len() == self.relays.len() {
                    return Err(ChannelError::new(K::Auth, "every relay rejected NIP-42 authentication"));
                }
            }
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(m) => {
                    got.extend(self.handle(m));
                    while let Ok(m) = rx.try_recv() {
                        got.extend(self.handle(m));
                    }
                    if !got.is_empty() {
                        return Ok(got);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(ChannelError::new(K::Fatal, "relay workers stopped")),
            }
            if Instant::now() >= until {
                return Ok(got);
            }
        }
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        if let Some(m) = out.media.iter().find(|m| m.url.is_none()) {
            return Err(ChannelError::new(K::Unsupported, format!("nostr DMs cannot upload files ({}); send a URL", m.path.as_deref().unwrap_or("attachment"))));
        }
        let to = recipient(&out.chat, &self.nip05)?;
        let nip17 = self.nip17 && self.inner.lock().unwrap().nip17_peers.contains(&hex(&to));
        let mut sent = Sent::default();
        for (i, piece) in crate::chunk::split(&flatten(out), MAX_LEN, LenUnit::Chars).iter().enumerate() {
            let reply = if i == 0 { out.reply_to.as_deref() } else { None };
            for ev in self.dm_event(&to, piece, reply, nip17)? {
                publish_any(&self.relays, &ev, self.publish_timeout)?;
                self.inner.lock().unwrap().own.insert(&ev.id);
                sent.ids.push(ev.id);
            }
        }
        Ok(sent)
    }

    fn delete(&self, _chat: &str, message_id: &str) -> Result<(), ChannelError> {
        let ev = Event::signed(&self.keys, 5, vec![tag(&["e", message_id]), tag(&["k", "4"])], "", now());
        publish_any(&self.relays, &ev, self.publish_timeout).map(|_| ())
    }

    fn stop(&self) {
        for r in &self.relays {
            r.stop();
        }
    }
}

impl Drop for Nostr {
    fn drop(&mut self) {
        self.stop();
    }
}

fn d_poll() -> u64 {
    25
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    private_key: String,
    #[serde(default)]
    relays: Vec<String>,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    /// Also receive NIP-17 gift-wrapped DMs (and answer them the same way).
    #[serde(default)]
    nip17: bool,
    /// Answer relays' NIP-42 AUTH challenges (needed by relays that only serve DMs to participants).
    #[serde(default = "d_true")]
    relay_auth: bool,
    /// NIP-01 kind-0 metadata published on connect.
    #[serde(default)]
    profile: Option<Profile>,
}

fn d_true() -> bool {
    true
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let key = ctx.secret("private_key", &st.private_key)?;
    let auth = st.relay_auth;
    let n = Nostr::new(ctx.name, &key, &st.relays, ctx.state("nostr.json"), st.poll_timeout_secs, st.nip17, st.profile, |o| o.auth = auth)?;
    Ok(Arc::new(n))
}

// ---------------------------------------------------------------- test relay

#[cfg(test)]
pub(crate) mod testrelay {
    //! A scripted Nostr relay: every client frame goes to `handler(conn, frame)`,
    //! which returns frames to send back; `push` injects frames into the newest
    //! connection; `drop_all` closes every socket.
    use ark_net::ws::{read_head, Message, WebSocket};
    use serde_json::Value;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    pub type Handler = Arc<dyn Fn(usize, &Value) -> Vec<String> + Send + Sync>;

    pub struct FakeRelay {
        pub url: String,
        pub frames: Arc<Mutex<Vec<(usize, Value)>>>,
        outbox: Arc<Mutex<Vec<String>>>,
        kill: Arc<AtomicBool>,
    }

    impl FakeRelay {
        /// `greet(conn)` frames go out right after the upgrade (e.g. an AUTH challenge).
        pub fn start(greet: impl Fn(usize) -> Vec<String> + Send + Sync + 'static, handler: impl Fn(usize, &Value) -> Vec<String> + Send + Sync + 'static) -> FakeRelay {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("ws://{}", l.local_addr().unwrap());
            let frames = Arc::new(Mutex::new(Vec::new()));
            let conns = Arc::new(AtomicUsize::new(0));
            let outbox: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let kill = Arc::new(AtomicBool::new(false));
            let (f2, c2, o2, k2) = (frames.clone(), conns.clone(), outbox.clone(), kill.clone());
            let handler: Handler = Arc::new(handler);
            let greet = Arc::new(greet);
            std::thread::spawn(move || {
                for s in l.incoming() {
                    let Ok(mut s) = s else { continue };
                    let n = c2.fetch_add(1, Ordering::SeqCst);
                    k2.store(false, Ordering::SeqCst);
                    let (f3, o3, k3, h, g) = (f2.clone(), o2.clone(), k2.clone(), handler.clone(), greet.clone());
                    let c3 = c2.clone();
                    std::thread::spawn(move || {
                        let Ok((head, rest)) = read_head(&mut s, 65536) else { return };
                        s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
                        let Ok(mut ws) = WebSocket::accept(s, &head, rest) else { return };
                        for fr in g(n) {
                            let _ = ws.send_text(&fr);
                        }
                        loop {
                            if k3.load(Ordering::SeqCst) {
                                let _ = ws.get_ref().shutdown(std::net::Shutdown::Both);
                                return;
                            }
                            // Only the newest connection drains the outbox.
                            if c3.load(Ordering::SeqCst) == n + 1 {
                                let out: Vec<String> = std::mem::take(&mut *o3.lock().unwrap());
                                for fr in out {
                                    if ws.send_text(&fr).is_err() {
                                        return;
                                    }
                                }
                            }
                            match ws.recv() {
                                Ok(None) => {}
                                Ok(Some(Message::Text(t))) => {
                                    let v: Value = serde_json::from_str(&t).unwrap_or_default();
                                    f3.lock().unwrap().push((n, v.clone()));
                                    for fr in h(n, &v) {
                                        if fr == "__CLOSE__" {
                                            let _ = ws.get_ref().shutdown(std::net::Shutdown::Both);
                                            return;
                                        }
                                        let _ = ws.send_text(&fr);
                                    }
                                }
                                Ok(Some(Message::Close(_))) | Err(_) => return,
                                Ok(Some(_)) => {}
                            }
                        }
                    });
                }
            });
            FakeRelay { url, frames, outbox, kill }
        }

        pub fn push(&self, frame: String) {
            self.outbox.lock().unwrap().push(frame);
        }

        pub fn drop_all(&self) {
            self.kill.store(true, Ordering::SeqCst);
        }

        pub fn frames_of(&self, kind: &str) -> Vec<(usize, Value)> {
            self.frames.lock().unwrap().iter().filter(|(_, v)| v[0] == kind).cloned().collect()
        }

        pub fn wait_for(&self, kind: &str, n: usize) -> Vec<(usize, Value)> {
            for _ in 0..400 {
                let f = self.frames_of(kind);
                if f.len() >= n {
                    return f;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("timed out waiting for {n} {kind} frames; got {:?}", self.frames.lock().unwrap());
        }
    }

    /// Answer every EVENT with OK true and every REQ with EOSE.
    pub fn ok_all(_: usize, v: &Value) -> Vec<String> {
        match v[0].as_str() {
            Some("EVENT") => vec![serde_json::json!(["OK", v[1]["id"], true, ""]).to_string()],
            Some("REQ") => vec![serde_json::json!(["EOSE", v[1]]).to_string()],
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testrelay::{ok_all, FakeRelay};
    use super::*;
    use crate::testutil::temp_dir;

    fn fast(o: &mut RelayOpts) {
        o.backoff_base = Duration::from_millis(30);
        o.backoff_max = Duration::from_millis(100);
        o.connect_timeout = Duration::from_secs(2);
    }

    fn chan(relays: &[&str], state: PathBuf, nip17: bool) -> (Nostr, Keys) {
        let me = Keys::generate();
        let n = Nostr::new("ns", &k1::nsec(&me.sk), &relays.iter().map(|s| s.to_string()).collect::<Vec<_>>(), state, 1, nip17, None, fast).unwrap();
        (n, me)
    }

    fn poll_until(n: &Nostr, want: usize) -> Vec<Inbound> {
        let mut got = Vec::new();
        for _ in 0..20 {
            got.extend(n.poll(&Cancel::new()).unwrap());
            if got.len() >= want {
                break;
            }
        }
        got
    }

    fn dm(from: &Keys, to: &Keys, text: &str, extra: Vec<Vec<String>>) -> Event {
        let mut tags = vec![tag(&["p", &to.pk_hex])];
        tags.extend(extra);
        Event::signed(from, 4, tags, &nip04::encrypt(&from.sk, &to.pk, text).unwrap(), now())
    }

    #[test]
    fn event_id_and_signature_known_answer() {
        // NIP-01 serialization: escapes per JSON, non-ASCII kept raw.
        let id = event_id(&"a".repeat(64), 1, 1, &[tag(&["t", "x\"y"])], "hé\n");
        let ser = format!("[0,\"{}\",1,1,[[\"t\",\"x\\\"y\"]],\"hé\\n\"]", "a".repeat(64));
        assert_eq!(id, ark_net::crypto::sha256(ser.as_bytes()));
        let k = Keys::from_secret(&format!("{}3", "0".repeat(63))).unwrap();
        assert_eq!(k.pk_hex, "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
        let ev = Event::signed(&k, 1, vec![], "hello", 1700000000);
        assert!(ev.verify());
        let mut bad = ev.clone();
        bad.content = "hellO".into();
        assert!(!bad.verify(), "content change breaks id");
        let mut bad2 = ev.clone();
        bad2.sig = format!("{}00", &ev.sig[..126]);
        assert!(!bad2.verify());
    }

    #[test]
    fn receives_nip04_dms_dedups_across_relays_and_filters() {
        let (alice, other) = (Keys::generate(), Keys::generate());
        let r1 = FakeRelay::start(|_| vec![], ok_all);
        let r2 = FakeRelay::start(|_| vec![], ok_all);
        let dir = temp_dir("nostr");
        let (n, me) = chan(&[&r1.url, &r2.url], dir.join("s.json"), false);
        let req = r1.wait_for("REQ", 1);
        assert_eq!(req[0].1[1], "ark-dm");
        assert_eq!(req[0].1[2]["kinds"], json!([4]));
        assert_eq!(req[0].1[2]["#p"], json!([me.pk_hex]));
        r2.wait_for("REQ", 1);
        let good = dm(&alice, &me, "hello bot", vec![]);
        let mut forged = dm(&alice, &me, "forged", vec![]);
        forged.sig = dm(&alice, &me, "x", vec![]).sig;
        let not_for_me = dm(&alice, &other, "not yours", vec![]);
        let mine = dm(&me, &alice, "own message", vec![]);
        let f = dm(&alice, &me, "future", vec![]);
        let future = Event::signed(&alice, 4, f.tags.clone(), &f.content, now() + 3600);
        for ev in [&good, &forged, &not_for_me, &mine, &future] {
            r1.push(json!(["EVENT", "ark-dm", ev]).to_string());
        }
        r2.push(json!(["EVENT", "ark-dm", good]).to_string());
        let got = poll_until(&n, 1);
        std::thread::sleep(Duration::from_millis(150));
        let more = n.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len() + more.len(), 1, "duplicate from the second relay and every bad event dropped: {got:?} {more:?}");
        let m = &got[0];
        assert_eq!((m.chat.as_str(), m.sender.as_str(), m.text.as_str(), m.chat_type, m.message_id.as_str()), (alice.pk_hex.as_str(), alice.pk_hex.as_str(), "hello bot", ChatType::Direct, good.id.as_str()));
        assert!(m.sender_name.starts_with("npub1"));
        // Cursor commits on the next poll and survives restart with dedup.
        n.poll(&Cancel::new()).unwrap();
        let st: State = serde_json::from_str(&std::fs::read_to_string(dir.join("s.json")).unwrap()).unwrap();
        assert!(st.seen.contains(&good.id) && st.since >= good.created_at - 1);
        n.stop();
        drop(n);
        let me2 = me.sk;
        let n2 = Nostr::new("ns", &hex(&me2), std::slice::from_ref(&r1.url), dir.join("s.json"), 1, false, None, fast).unwrap();
        let req = r1.wait_for("REQ", 2);
        let since = req.last().unwrap().1[2]["since"].as_i64().unwrap();
        assert!(since <= good.created_at && since >= good.created_at - LOOKBACK - 5, "resume with lookback: {since}");
        r1.push(json!(["EVENT", "ark-dm", good]).to_string());
        assert!(n2.poll(&Cancel::new()).unwrap().is_empty(), "persisted seen ids dedup the replay");
    }

    #[test]
    fn sends_nip04_with_reply_tag_and_maps_relay_rejections() {
        let alice = Keys::generate();
        let r = FakeRelay::start(|_| vec![], ok_all);
        let (n, me) = chan(&[&r.url], temp_dir("nostr").join("s"), false);
        r.wait_for("REQ", 1);
        let out = Outbound { reply_to: Some("e".repeat(64)), buttons: vec![vec![crate::Button { label: "Yes".into(), data: "y".into(), url: None }]], media: vec![crate::Media { url: Some("https://e.com/a.png".into()), ..Default::default() }], ..Outbound::text(&k1::npub(&alice.pk), "hi **there**") };
        let s = n.send(&out).unwrap();
        let ev: Event = serde_json::from_value(r.wait_for("EVENT", 1)[0].1[1].clone()).unwrap();
        assert_eq!(s.ids, vec![ev.id.clone()]);
        assert!(ev.verify() && ev.kind == 4 && ev.pubkey == me.pk_hex);
        assert_eq!(ev.tags, vec![tag(&["p", &alice.pk_hex]), tag(&["e", &"e".repeat(64)])]);
        assert_eq!(nip04::decrypt(&alice.sk, &me.pk, &ev.content).unwrap(), "hi **there**\n1. Yes\nhttps://e.com/a.png");
        // Replying to our own message is recognised.
        r.push(json!(["EVENT", "ark-dm", dm(&alice, &me, "re", vec![tag(&["e", &ev.id])])]).to_string());
        let got = poll_until(&n, 1);
        assert!(got[0].reply.as_ref().unwrap().is_own && got[0].addressed());
        // Local files cannot be sent; bad recipients are fatal.
        let file = crate::Media { path: Some("/tmp/x".into()), ..Default::default() };
        assert_eq!(n.send(&Outbound { media: vec![file], ..Outbound::text(&alice.pk_hex, "x") }).unwrap_err().kind, K::Unsupported);
        assert_eq!(n.send(&Outbound::text("npub1bogus", "x")).unwrap_err().kind, K::Fatal);
        // Delete is a NIP-09 kind-5 event.
        n.delete(&alice.pk_hex, &ev.id).unwrap();
        let del: Event = serde_json::from_value(r.wait_for("EVENT", 2)[1].1[1].clone()).unwrap();
        assert_eq!((del.kind, del.tag("e")), (5, Some(ev.id.as_str())));
        assert_eq!(publish_error(&["r: rate-limited: slow down".into()]).kind, K::RateLimited { retry_after: None });
        assert_eq!(publish_error(&["r: auth-required: who are you".into()]).kind, K::Auth);
        assert_eq!(publish_error(&["r: blocked: nope".into()]).kind, K::NotFound);
        assert_eq!(publish_error(&["r: invalid: bad sig".into()]).kind, K::Protocol);
        assert_eq!(publish_error(&["r: not connected".into()]).kind, K::Network);
    }

    #[test]
    fn publish_fails_fast_when_no_relay_is_up_and_times_out_without_ok() {
        let silent = FakeRelay::start(|_| vec![], |_, _| vec![]);
        let (mut n, _) = chan(&[&silent.url, "ws://127.0.0.1:1"], temp_dir("nostr").join("s"), false);
        n.publish_timeout = Duration::from_millis(300);
        silent.wait_for("REQ", 1);
        let t = Instant::now();
        let e = n.send(&Outbound::text(&Keys::generate().pk_hex, "x")).unwrap_err();
        assert_eq!(e.kind, K::Network, "{e}");
        assert!(e.message.contains("timed out") && e.message.contains("not connected"), "{e}");
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn nip17_gift_wraps_round_trip() {
        let alice = Keys::generate();
        let r = FakeRelay::start(|_| vec![], ok_all);
        let (n, me) = chan(&[&r.url], temp_dir("nostr").join("s"), true);
        let req = r.wait_for("REQ", 1);
        assert_eq!(req[0].1[3]["kinds"], json!([1059]));
        let rumor = Event::unsigned(&alice.pk_hex, 14, vec![tag(&["p", &me.pk_hex])], "sealed hello", now());
        let wrap = gift_wrap(&alice, &me.pk, &rumor).unwrap();
        assert!(wrap.verify() && wrap.pubkey != alice.pk_hex, "wrapped by an ephemeral key");
        // A seal whose rumor claims another author is rejected.
        let liar = Event::unsigned(&Keys::generate().pk_hex, 14, vec![], "spoof", now());
        r.push(json!(["EVENT", "ark-dm", gift_wrap(&alice, &me.pk, &liar).unwrap()]).to_string());
        r.push(json!(["EVENT", "ark-dm", wrap]).to_string());
        let got = poll_until(&n, 1);
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].sender.as_str(), got[0].text.as_str(), got[0].message_id.as_str()), (alice.pk_hex.as_str(), "sealed hello", rumor.id.as_str()));
        // The answer goes back gift-wrapped.
        n.send(&Outbound::text(&alice.pk_hex, "sealed reply")).unwrap();
        let ev: Event = serde_json::from_value(r.wait_for("EVENT", 1)[0].1[1].clone()).unwrap();
        assert_eq!(ev.kind, 1059);
        let back = unwrap_gift(&alice, &ev).unwrap();
        assert_eq!((back.content.as_str(), back.pubkey.as_str()), ("sealed reply", me.pk_hex.as_str()));
    }

    #[test]
    fn answers_nip42_auth_publishes_profile_and_reconnects() {
        let r = FakeRelay::start(|_| vec![json!(["AUTH", "chal-1"]).to_string()], ok_all);
        let me = Keys::generate();
        let profile = Profile { name: Some("ark".into()), picture: Some("https://e.com/p.png".into()), ..Default::default() };
        let dir = temp_dir("nostr");
        let n = Nostr::new("ns", &hex(&me.sk), std::slice::from_ref(&r.url), dir.join("s"), 1, false, Some(profile), fast).unwrap();
        let auth = r.wait_for("AUTH", 1);
        let ev: Event = serde_json::from_value(auth[0].1[1].clone()).unwrap();
        assert!(ev.verify() && ev.kind == 22242);
        assert_eq!((ev.tag("relay"), ev.tag("challenge")), (Some(r.url.as_str()), Some("chal-1")));
        n.poll(&Cancel::new()).unwrap();
        let evs = r.wait_for("EVENT", 1);
        let p: Event = serde_json::from_value(evs[0].1[1].clone()).unwrap();
        assert_eq!(p.kind, 0);
        assert_eq!(serde_json::from_str::<Value>(&p.content).unwrap(), json!({"name": "ark", "picture": "https://e.com/p.png"}));
        // Dropped socket → reconnect, re-auth, re-subscribe; events still flow.
        r.wait_for("REQ", 1);
        assert_eq!(r.wait_for("REQ", 2)[1].0, 0, "re-subscribed on the same socket after AUTH");
        r.drop_all();
        for _ in 0..300 {
            if r.frames_of("REQ").iter().any(|(c, _)| *c == 1) && r.frames_of("AUTH").iter().any(|(c, _)| *c == 1) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(r.frames_of("AUTH").iter().any(|(c, _)| *c == 1) && r.frames_of("REQ").iter().any(|(c, _)| *c == 1), "re-auth and re-subscribe on the new connection: {:?}", r.frames.lock().unwrap());
        let alice = Keys::generate();
        r.push(json!(["EVENT", "ark-dm", dm(&alice, &me, "after reconnect", vec![])]).to_string());
        let got = poll_until(&n, 1);
        assert_eq!(got[0].text, "after reconnect");
        assert!(Nostr::new("ns", &hex(&me.sk), &[], dir.join("x"), 1, false, Some(Profile { picture: Some("http://e.com".into()), ..Default::default() }), fast).is_err(), "https only");
    }

    #[test]
    fn auth_rejection_surfaces_as_auth_error_and_cancel_is_prompt() {
        let r = FakeRelay::start(|_| vec![json!(["AUTH", "c"]).to_string()], |_, v| match v[0].as_str() {
            Some("AUTH") => vec![json!(["OK", v[1]["id"], false, "restricted: not allowed"]).to_string()],
            _ => vec![],
        });
        let (n, _) = chan(&[&r.url], temp_dir("nostr").join("s"), false);
        let mut err = None;
        for _ in 0..20 {
            if let Err(e) = n.poll(&Cancel::new()) {
                err = Some(e);
                break;
            }
        }
        assert_eq!(err.unwrap().kind, K::Auth);
        let quiet = FakeRelay::start(|_| vec![], ok_all);
        let (n, _) = chan(&[&quiet.url], temp_dir("nostr").join("s"), false);
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let t = Instant::now();
        let mut n = n;
        n.poll_timeout = Duration::from_secs(30);
        assert!(n.poll(&c).unwrap().is_empty());
        assert!(t.elapsed() < Duration::from_millis(400), "{:?}", t.elapsed());
    }

    #[test]
    fn nip05_lookup_verify_cache_and_send() {
        use crate::testutil::FakeServer;
        let me = Keys::generate();
        let bob = Keys::generate();
        let bob_hex = bob.pk_hex.clone();
        let srv = FakeServer::start(move |req, _| match req.path.as_str() {
            "/.well-known/nostr.json?name=bob" => (200, vec![], json!({"names": {"Bob": bob_hex, "eve": "npub1notallowed"}, "relays": {bob_hex.clone(): ["wss://r.example", "https://not-a-relay"]}}).to_string()),
            "/.well-known/nostr.json?name=_" => (200, vec![], json!({"names": {"_": bob_hex}}).to_string()),
            "/.well-known/nostr.json?name=eve" => (200, vec![], json!({"names": {"eve": "npub1notallowed"}}).to_string()),
            "/.well-known/nostr.json?name=moved" => (301, vec![("location".into(), "https://evil.example/".into())], String::new()),
            "/.well-known/nostr.json?name=down" => (503, vec![], String::new()),
            _ => (200, vec![], json!({"names": {}}).to_string()),
        });
        let mut n = Nip05::new(Duration::from_secs(5));
        n.base = Some(srv.url.clone());
        let f = n.lookup("BOB@Example.com").unwrap();
        assert_eq!((f.pubkey, f.relays.clone()), (bob.pk, vec!["wss://r.example".to_string()]));
        assert_eq!(n.lookup("example.com").unwrap().pubkey, bob.pk, "bare domain is _@domain");
        assert!(n.verify("bob@example.com", &k1::npub(&bob.pk)).unwrap());
        assert!(!n.verify("bob@example.com", &me.pk_hex).unwrap());
        assert!(!n.verify("nobody@example.com", &bob.pk_hex).unwrap());
        assert_eq!(n.lookup("eve@example.com").unwrap_err().kind, K::NotFound, "npub in nostr.json is invalid");
        assert_eq!(n.lookup("moved@example.com").unwrap_err().kind, K::NotFound, "redirects refused");
        assert_eq!(n.lookup("down@example.com").unwrap_err().kind, K::Network);
        assert!(n.lookup("bad name@example.com").is_err() && parse_nip05("x@localhost").is_none());
        let before = srv.requests().len();
        n.lookup("bob@example.com").unwrap();
        n.lookup("nobody@example.com").unwrap_err();
        n.lookup("down@example.com").unwrap_err();
        assert_eq!(srv.requests().len(), before + 1, "hits and misses cached, network errors retried");
        // Sending to a NIP-05 recipient encrypts to the resolved key.
        let relay = FakeRelay::start(|_| vec![], ok_all);
        let mut ch = Nostr::new("ns", &k1::nsec(&me.sk), std::slice::from_ref(&relay.url), temp_dir("nostr").join("s.json"), 1, false, None, fast).unwrap();
        ch.nip05.base = Some(srv.url.clone());
        relay.wait_for("REQ", 1);
        ch.send(&Outbound::text("bob@example.com", "hi bob")).unwrap();
        let ev: Event = serde_json::from_value(relay.wait_for("EVENT", 1)[0].1[1].clone()).unwrap();
        assert!(ev.has_p(&bob.pk_hex));
        assert_eq!(nip04::decrypt(&bob.sk, &me.pk, &ev.content).unwrap(), "hi bob");
        assert_eq!(ch.send(&Outbound::text("ghost@example.com", "x")).unwrap_err().kind, K::NotFound);
        assert_eq!(ch.send(&Outbound::text("garbage", "x")).unwrap_err().kind, K::Fatal);
    }

    #[test]
    fn build_validates_settings() {
        let d = temp_dir("nostr");
        let secrets: crate::config::Secrets = Arc::new(|s: &str| s.replace("{{secret:NK}}", &"1".repeat(64)));
        let ctx = crate::config::Ctx { name: "ns", state_dir: &d, secrets: &secrets };
        let ok = json!({"private_key": "{{secret:NK}}", "relays": ["ws://127.0.0.1:1"], "nip17": true});
        assert!(build(&ctx, ok.as_object().unwrap()).is_ok());
        let e = build(&ctx, json!({"private_key": "nsec1bad", "relays": ["ws://127.0.0.1:1"]}).as_object().unwrap()).err().unwrap();
        assert!(e.contains("private_key"), "{e}");
        assert!(build(&ctx, json!({"private_key": "{{secret:NK}}", "relays": ["https://x"]}).as_object().unwrap()).is_err());
        assert!(build(&ctx, json!({"private_key": "{{secret:NK}}", "relayz": []}).as_object().unwrap()).err().unwrap().contains("relayz"));
        assert!(build(&ctx, json!({"private_key": "{{secret:MISSING}}"}).as_object().unwrap()).err().unwrap().contains("not set"));
    }
}
