//! Buzz (Block's Nostr-based human + agent community relay), ported from
//! OpenClaw `extensions/buzz` and Hermes `plugins/platforms/buzz` (both MIT).
//!
//! Transport: one authenticated WebSocket to the community relay (NIP-42: wait
//! for the AUTH challenge, answer a signed kind-22242 event with `relay` +
//! `challenge` tags and the optional NIP-OA `auth` tag, wait for OK), shared
//! `nostr::Relay` worker with reconnect + backoff.
//! Rooms: the relay's own signed metadata (its NIP-11 `self` key) — kind 39000
//! (name/about; "DM" with an empty about is a direct conversation, as Hermes
//! classifies) and kind 39002 (members + roles). Without configured `channels`
//! every room whose 39002 lists us is watched; kind 44100 membership
//! notifications trigger rediscovery.
//! Inbound: kinds 9 (chat), 40002 (rich), 40008 (diff), 45001/45003 (forum
//! post/comment) with an `h` room tag; signature verified, own events and
//! non-members dropped, per-room cursor (`since` = last seen − 1, `limit` 50 for
//! rooms adopted mid-run) and seen ids persisted. Mention = `p` tag to us, our
//! hex/npub, or `@<display name>`; a leading mention is stripped. NIP-10 `e`
//! tags give the reply parent (with `is_own`) and the thread root. `imeta`
//! attachments become media verified against their declared size + SHA-256.
//! Outbound: kind 9 with `h`, a lone NIP-10 `reply` tag on the thread root
//! (Hermes' anchoring, `reply_in_thread = false` posts flat), `p` tags for
//! `@Name` (unique member display names) and `nostr:npub` mentions; typing is
//! kind 20002 (OpenClaw); presence heartbeat kind 20001 every 30 s; optional
//! profile sync (kinds 0 + 10100). Edit / delete / reactions / file upload go
//! through the `buzz` CLI exactly as Hermes runs it when `cli_path` is set;
//! without it delete is NIP-09 kind 5 and reactions NIP-25 kind 7.
//! `transport = "poll"` (Hermes' poll mode; needs `cli_path`) skips the socket:
//! startup seeds each room from `messages get --limit 50` (or its restored
//! cursor), every `poll_interval` s each room is fetched with `--since`, every 5th
//! sweep re-runs discovery (`dms list` + `channels list`; DM = "DM" with an empty
//! description), and sends go through `messages send` with `--mention`s. CLI
//! events are signature-checked when they carry `sig`. `transport = "auto"`
//! starts on the socket and falls back to polling when the relay rejects auth
//! or no authenticated connection comes up within 25 s (Hermes).
//! `require_bot_role` (OpenClaw room admission): a room is used only while the
//! relay-signed kind 39002 roster gives us the `bot` role; configured rooms
//! without it are skipped (none admitted = error), a downgrade blocks the room,
//! and kind 40099 `member_left`/`member_removed` deny that member at once until
//! a newer roster confirms.

use crate::nostr::{flatten, hex32, now, publish_any, tag, Event, Keys, Relay, RelayIn, RelayOpts, Seen, SubsFn};
use crate::secp256k1 as k1;
use crate::{write_atomic, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent};
use ark_core::Cancel;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DISPATCH_KINDS: [u32; 5] = [9, 40002, 40008, 45001, 45003];
const KIND_TYPING: u32 = 20002;
const KIND_PRESENCE: u32 = 20001;
const KIND_ROOM_META: u32 = 39000;
const KIND_ROOM_MEMBERS: u32 = 39002;
const KIND_MEMBER_ADDED: u32 = 44100;
const KIND_AGENT_PROFILE: u32 = 10100;
const KIND_ROOM_SYSTEM: u32 = 40099;
const FETCH_LIMIT: u32 = 50;
const DM_DISCOVERY_EVERY: u64 = 5;
const MIN_POLL_INTERVAL: f64 = 1.0;
const WS_FALLBACK_AFTER: Duration = Duration::from_secs(25);
const MEMBER_CACHE_TTL: Duration = Duration::from_secs(60);
const SEEN_CAP: usize = 500;
const META_CAP: usize = 500;
const MAX_CONTENT: usize = 256 * 1024;
const MAX_DIFF: usize = 60 * 1024;
const MAX_MENTIONS: usize = 50;
const MAX_ATTACHMENTS: usize = 4;
const MAX_ATTACHMENT_BYTES: u64 = 20 * 1024 * 1024;
const MAX_LEN: usize = 16000;
/// Buzz `just dev` signs room metadata with private key 1 and omits NIP-11 `self`.
const LOCAL_DEV_RELAY_KEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const BUZZ_SOFTWARE: &str = "https://github.com/block/buzz";

#[derive(Default, Clone)]
struct Room {
    name: String,
    about: String,
    meta_at: i64,
    members: Option<HashSet<String>>,
    members_at: i64,
    /// Our role in the latest roster (`p` tag 4th field).
    my_role: Option<String>,
    /// Removed per kind 40099 (→ a later join was announced) until the roster confirms (OpenClaw).
    denied: HashMap<String, bool>,
}

impl Room {
    fn is_dm(&self) -> bool {
        self.name.trim() == "DM" && self.about.trim().is_empty()
    }
    /// Bot role in the roster and not removed since (a removal of us blocks the room).
    fn admitted(&self, me: &str) -> bool {
        self.my_role.as_deref() == Some("bot") && !self.denied.contains_key(me)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    WebSocket,
    Poll,
    Auto,
}

#[derive(Default, Serialize, Deserialize)]
struct Cursor {
    #[serde(default)]
    last_ts: i64,
    #[serde(default)]
    seen: Vec<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    identity: String,
    #[serde(default)]
    relay: String,
    #[serde(default)]
    channels: HashMap<String, Cursor>,
}

struct ChanState {
    last_ts: i64,
    seen: Seen,
}

/// Bounded map preserving insertion order.
struct Lru<V> {
    map: HashMap<String, V>,
    order: VecDeque<String>,
    cap: usize,
}

impl<V> Lru<V> {
    fn new(cap: usize) -> Self {
        Lru { map: HashMap::new(), order: VecDeque::new(), cap }
    }
    fn put(&mut self, k: &str, v: V) {
        if self.map.insert(k.to_string(), v).is_none() {
            self.order.push_back(k.to_string());
        }
        while self.order.len() > self.cap {
            if let Some(o) = self.order.pop_front() {
                self.map.remove(&o);
            }
        }
    }
    fn get(&self, k: &str) -> Option<&V> {
        self.map.get(k)
    }
}

struct Inner {
    relay_pk: Option<String>,
    rooms: HashMap<String, Room>,
    watched: HashMap<String, ChanState>,
    restricted: HashSet<String>,
    /// Rooms adopted after the first discovery pass replay their history (`limit`).
    discovery_done: bool,
    profiles: HashMap<String, String>,
    /// event id → (author, snippet) for reply lookups.
    meta: Lru<(String, String)>,
    /// event id → thread root (None = top level).
    roots: Lru<Option<String>>,
    /// Our reaction events: (message, emoji) → reaction event id.
    reactions: Lru<String>,
    dirty: bool,
    auth_error: Option<String>,
    self_profiles: HashMap<u32, Event>,
    profile_synced: bool,
    connected_once: bool,
    /// OpenClaw role admission.
    role_admission: bool,
    /// Poll transport: next sweep, sweep count, startup seeding done.
    next_sweep: Option<Instant>,
    sweeps: u64,
    cli_ready: bool,
    /// Configured rooms without a restored cursor, seeded by the first sweep.
    unseeded: HashSet<String>,
    /// Pubkeys already looked up with `users get --pubkey`.
    name_tried: HashSet<String>,
    /// `channels members` cache for poll-mode mentions.
    cli_members: HashMap<String, (Instant, HashSet<String>)>,
}

pub struct Buzz {
    id: String,
    keys: Arc<Keys>,
    raw_key: String,
    auth_tag: Option<String>,
    relay_http: String,
    relay_ws: String,
    /// None with `transport = "poll"`.
    relay: Option<Arc<Relay>>,
    transport: Transport,
    /// Inbound/outbound run through the CLI (poll, or auto after fallback).
    polling: std::sync::atomic::AtomicBool,
    started: Instant,
    poll_interval: Duration,
    rx: Mutex<Receiver<RelayIn>>,
    inner: Arc<Mutex<Inner>>,
    configured: Vec<String>,
    state: PathBuf,
    poll_timeout: Duration,
    reply_in_thread: bool,
    profile_name: Option<String>,
    cli_path: Option<String>,
    pub publish_timeout: Duration,
    pub cli_timeout: Duration,
    presence_stop: Arc<std::sync::atomic::AtomicBool>,
    /// Cursors of discovered rooms, re-attached when the room is adopted.
    restored: Mutex<HashMap<String, Cursor>>,
}

pub struct Options {
    pub relay_url: String,
    pub private_key: String,
    pub auth_tag: Option<String>,
    pub channels: Vec<String>,
    pub relay_pubkey: Option<String>,
    pub profile_name: Option<String>,
    pub reply_in_thread: bool,
    pub cli_path: Option<String>,
    pub presence_secs: u64,
    pub poll_timeout_secs: u64,
    pub transport: Transport,
    /// Poll transport sweep period (Hermes default 4 s, minimum 1 s).
    pub poll_interval: f64,
    pub require_bot_role: bool,
}

fn ws_url(u: &str) -> Result<(String, String), String> {
    let u = u.trim().trim_end_matches('/');
    let (scheme, rest) = u.split_once("://").ok_or("relay_url must be http(s):// or ws(s)://")?;
    let (ws, http) = match scheme.to_ascii_lowercase().as_str() {
        "https" | "wss" => ("wss", "https"),
        "http" | "ws" => ("ws", "http"),
        _ => return Err("relay_url must be http(s):// or ws(s)://".into()),
    };
    ark_net::Url::parse(&format!("{ws}://{rest}"))?;
    Ok((format!("{ws}://{rest}"), format!("{http}://{rest}")))
}

fn parse_auth_tag(raw: &str) -> Result<Option<Vec<String>>, String> {
    if raw.trim().is_empty() {
        return Ok(None);
    }
    let v: Vec<String> = serde_json::from_str(raw).map_err(|_| "auth_tag must be [\"auth\",\"<pubkey>\",\"<conditions>\",\"<signature>\"]".to_string())?;
    if v.len() != 4 || v[0] != "auth" {
        return Err("auth_tag must be [\"auth\",\"<pubkey>\",\"<conditions>\",\"<signature>\"]".into());
    }
    Ok(Some(v))
}

fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36 && b.iter().enumerate().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { *c == b'-' } else { c.is_ascii_hexdigit() })
}

/// NIP-11 `self` key that signs room metadata.
fn fetch_relay_pubkey(http_url: &str, ws: &str) -> Option<String> {
    let h = crate::http::Http::new(Duration::from_secs(5));
    let r = h.call("GET", http_url, &[("accept", "application/nostr+json")], crate::http::Payload::None).ok()?;
    if !(200..300).contains(&r.status) {
        return None;
    }
    let v: Value = serde_json::from_str(&r.body).ok()?;
    let me = v["self"].as_str().unwrap_or("").trim().to_lowercase();
    if hex32(&me).is_some() {
        return Some(me);
    }
    let host = ark_net::Url::parse(ws).ok()?.host;
    (v["software"] == BUZZ_SOFTWARE && matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1")).then(|| LOCAL_DEV_RELAY_KEY.to_string())
}

impl Buzz {
    pub fn new(id: &str, o: Options, state: PathBuf, tweak: impl Fn(&mut RelayOpts)) -> Result<Buzz, String> {
        let keys = Arc::new(Keys::from_secret(&o.private_key).map_err(|e| format!("channel {id}: private_key: {e}"))?);
        let (relay_ws, relay_http) = ws_url(&o.relay_url).map_err(|e| format!("channel {id}: {e}"))?;
        let auth_tag_v = parse_auth_tag(o.auth_tag.as_deref().unwrap_or("")).map_err(|e| format!("channel {id}: {e}"))?;
        let configured: Vec<String> = o.channels.iter().map(|c| c.trim().to_lowercase()).filter(|c| !c.is_empty()).collect();
        if let Some(bad) = configured.iter().find(|c| !is_uuid(c)) {
            return Err(format!("channel {id}: channels entry {bad} is not a Buzz channel UUID"));
        }
        let relay_pk = match &o.relay_pubkey {
            Some(p) => Some(hex(&k1::parse_pubkey(p).map_err(|e| format!("channel {id}: relay_pubkey: {e}"))?)),
            None => None,
        };
        let cli_path = o.cli_path.filter(|p| !p.trim().is_empty());
        if o.transport != Transport::WebSocket && cli_path.is_none() {
            return Err(format!("channel {id}: transport = \"poll\"/\"auto\" needs cli_path (the buzz CLI)"));
        }
        if o.transport == Transport::Poll && o.require_bot_role {
            return Err(format!("channel {id}: require_bot_role needs the relay-signed rosters of the WebSocket transport"));
        }
        // Restore cursors unless they belong to another identity / relay (ids would collide).
        let st: State = std::fs::read_to_string(&state).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let restored = st.identity == keys.pk_hex && st.relay == relay_ws;
        let mut watched = HashMap::new();
        let mut unseeded = HashSet::new();
        let start = now();
        for c in &configured {
            let mut cs = ChanState { last_ts: start, seen: Seen::new(SEEN_CAP) };
            if let Some(cur) = st.channels.get(c).filter(|_| restored) {
                cs.last_ts = cur.last_ts;
                for s in &cur.seen {
                    cs.seen.insert(s);
                }
            } else {
                unseeded.insert(c.clone());
            }
            watched.insert(c.clone(), cs);
        }
        let mut restored_cursors: HashMap<String, Cursor> = if restored { st.channels } else { HashMap::new() };
        restored_cursors.retain(|k, _| !watched.contains_key(k));
        let inner = Arc::new(Mutex::new(Inner {
            relay_pk,
            rooms: HashMap::new(),
            watched,
            restricted: HashSet::new(),
            discovery_done: false,
            profiles: HashMap::new(),
            meta: Lru::new(META_CAP * 4),
            roots: Lru::new(META_CAP * 2),
            reactions: Lru::new(META_CAP),
            dirty: false,
            auth_error: None,
            self_profiles: HashMap::new(),
            profile_synced: o.profile_name.is_none() || o.transport == Transport::Poll,
            connected_once: false,
            role_admission: o.require_bot_role,
            next_sweep: None,
            sweeps: 0,
            cli_ready: false,
            unseeded,
            name_tried: HashSet::new(),
            cli_members: HashMap::new(),
        }));
        let (i2, pk, cfg2, http2, ws2) = (inner.clone(), keys.pk_hex.clone(), configured.clone(), relay_http.clone(), relay_ws.clone());
        let subs: SubsFn = Arc::new(move || {
            let need = i2.lock().unwrap().relay_pk.is_none();
            if need {
                if let Some(k) = fetch_relay_pubkey(&http2, &ws2) {
                    i2.lock().unwrap().relay_pk = Some(k);
                }
            }
            subscriptions(&i2.lock().unwrap(), &pk, &cfg2)
        });
        let (tx, rx) = mpsc::channel();
        let relay = (o.transport != Transport::Poll).then(|| {
            let mut ro = RelayOpts::new(&relay_ws, keys.clone(), subs);
            ro.require_auth = true;
            ro.auth_tag = auth_tag_v;
            ro.backoff_max = Duration::from_secs(30);
            tweak(&mut ro);
            Arc::new(Relay::spawn(ro, tx))
        });
        let b = Buzz {
            id: id.to_string(),
            keys,
            raw_key: o.private_key.clone(),
            auth_tag: o.auth_tag.filter(|t| !t.trim().is_empty()),
            relay_http,
            relay_ws,
            relay,
            transport: o.transport,
            polling: std::sync::atomic::AtomicBool::new(o.transport == Transport::Poll),
            started: Instant::now(),
            poll_interval: Duration::from_secs_f64(if o.poll_interval.is_finite() { o.poll_interval.max(MIN_POLL_INTERVAL) } else { 4.0 }),
            rx: Mutex::new(rx),
            inner,
            configured,
            state,
            poll_timeout: Duration::from_secs(o.poll_timeout_secs.max(1)),
            reply_in_thread: o.reply_in_thread,
            profile_name: o.profile_name.filter(|n| !n.trim().is_empty()),
            cli_path,
            publish_timeout: Duration::from_secs(10),
            cli_timeout: Duration::from_secs(30),
            presence_stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            restored: Mutex::new(restored_cursors),
        };
        if o.presence_secs > 0 {
            b.start_presence(Duration::from_secs(o.presence_secs));
        }
        Ok(b)
    }

    pub fn public_key(&self) -> &str {
        &self.keys.pk_hex
    }

    /// The socket, unless inbound/outbound run through the CLI.
    fn ws(&self) -> Option<&Arc<Relay>> {
        if self.polling.load(std::sync::atomic::Ordering::SeqCst) {
            return None;
        }
        self.relay.as_ref()
    }

    fn req(&self, sub: &str, f: Vec<Value>) {
        if let Some(r) = self.ws() {
            r.req(sub, f);
        }
    }

    fn start_presence(&self, every: Duration) {
        let Some(relay) = self.relay.clone() else { return };
        let (keys, stop) = (self.keys.clone(), self.presence_stop.clone());
        std::thread::spawn(move || {
            let mut next = Instant::now();
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                if Instant::now() >= next && relay.is_connected() {
                    let ev = Event::signed(&keys, KIND_PRESENCE, vec![], "online", now());
                    relay.send_raw(json!(["EVENT", ev]).to_string());
                    next = Instant::now() + every;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
    }

    fn save(&self) -> Result<(), ChannelError> {
        let mut g = self.inner.lock().unwrap();
        if !g.dirty {
            return Ok(());
        }
        g.dirty = false;
        let channels = g.watched.iter().map(|(k, v)| (k.clone(), Cursor { last_ts: v.last_ts, seen: v.seen.list() })).collect();
        let st = State { identity: self.keys.pk_hex.clone(), relay: self.relay_ws.clone(), channels };
        write_atomic(&self.state, serde_json::to_string(&st).unwrap().as_bytes()).map_err(|e| ChannelError::new(K::Fatal, format!("saving buzz cursors: {e}")))
    }

    fn adopt(&self, g: &mut Inner, room: &str) {
        if g.watched.contains_key(room) || g.restricted.contains(room) {
            return;
        }
        let mut cs = ChanState { last_ts: if g.discovery_done { 0 } else { now() }, seen: Seen::new(SEEN_CAP) };
        if let Some(cur) = self.restored.lock().unwrap().remove(room) {
            cs.last_ts = cur.last_ts;
            for s in &cur.seen {
                cs.seen.insert(s);
            }
        }
        g.watched.insert(room.to_string(), cs);
        g.dirty = true;
        for (sub, f) in subscriptions(g, &self.keys.pk_hex, &self.configured) {
            if sub == channel_sub(room) || sub == "buzz-meta" || sub == "buzz-profiles" {
                self.req(&sub, f);
            }
        }
    }

    fn handle(&self, m: RelayIn) -> Option<Inbound> {
        match m {
            RelayIn::Connected { .. } => {
                let mut g = self.inner.lock().unwrap();
                g.auth_error = None;
                g.connected_once = true;
                None
            }
            RelayIn::AuthFailed { reason, .. } => {
                self.inner.lock().unwrap().auth_error = Some(reason);
                None
            }
            RelayIn::Closed { sub, reason, .. } => {
                let low = reason.to_lowercase();
                if let Some(room) = sub.strip_prefix("buzz-ch-") {
                    if ["restricted", "not a channel member", "auth-required"].iter().any(|m| low.contains(m)) {
                        let mut g = self.inner.lock().unwrap();
                        g.watched.remove(room);
                        g.restricted.insert(room.to_string());
                    }
                }
                None
            }
            RelayIn::Eose { sub, .. } => {
                if sub == "buzz-rooms" {
                    self.inner.lock().unwrap().discovery_done = true;
                } else if sub == "buzz-self" {
                    self.sync_profile();
                }
                None
            }
            RelayIn::Event { sub, event, .. } => self.on_event(&sub, event),
            _ => None,
        }
    }

    fn on_event(&self, sub: &str, ev: Event) -> Option<Inbound> {
        let mut g = self.inner.lock().unwrap();
        let rpk = g.relay_pk.clone();
        let from_relay = rpk.as_deref().is_some_and(|r| r.eq_ignore_ascii_case(&ev.pubkey));
        match ev.kind {
            KIND_ROOM_META | KIND_ROOM_MEMBERS => {
                if !from_relay || !ev.verify() {
                    return None;
                }
                let room = ev.tag("d")?.trim().to_lowercase();
                if !is_uuid(&room) {
                    return None;
                }
                let r = g.rooms.entry(room.clone()).or_default();
                if ev.kind == KIND_ROOM_META {
                    if ev.created_at >= r.meta_at {
                        r.meta_at = ev.created_at;
                        r.name = ev.tag("name").unwrap_or("").to_string();
                        r.about = ev.tag("about").unwrap_or("").to_string();
                    }
                    return None;
                }
                if ev.created_at < r.members_at {
                    return None;
                }
                r.members_at = ev.created_at;
                let members: HashSet<String> = ev.tags_named("p").map(|t| t[1].trim().to_lowercase()).filter(|p| hex32(p).is_some()).collect();
                let has_me = members.contains(&self.keys.pk_hex);
                let was_admitted = r.admitted(&self.keys.pk_hex);
                r.my_role = ev.tags_named("p").filter(|t| t[1].trim().eq_ignore_ascii_case(&self.keys.pk_hex)).filter_map(|t| t.get(3)).map(|x| x.trim().to_lowercase()).filter(|x| !x.is_empty()).last();
                // The roster decides: a removal stays denied while it still lists the member,
                // unless a later join was announced.
                r.denied.retain(|pk, rejoined| members.contains(pk) && !*rejoined);
                r.members = Some(members);
                let admitted = r.admitted(&self.keys.pk_hex);
                let role_ok = !g.role_admission || admitted;
                if has_me && role_ok && self.configured.is_empty() {
                    self.adopt(&mut g, &room);
                } else if g.role_admission && admitted && !was_admitted && g.watched.contains_key(&room) {
                    for (s, f) in subscriptions(&g, &self.keys.pk_hex, &self.configured) {
                        if s == channel_sub(&room) {
                            self.req(&s, f);
                        }
                    }
                }
                // New members: refresh display names for mentions.
                if g.watched.contains_key(&room) {
                    for (s, f) in subscriptions(&g, &self.keys.pk_hex, &self.configured) {
                        if s == "buzz-profiles" {
                            self.req(&s, f);
                        }
                    }
                }
                None
            }
            KIND_MEMBER_ADDED => {
                if ev.has_p(&self.keys.pk_hex) {
                    for (s, f) in subscriptions(&g, &self.keys.pk_hex, &self.configured) {
                        if s == "buzz-rooms" {
                            self.req(&s, f);
                        }
                    }
                }
                None
            }
            0 | KIND_AGENT_PROFILE => {
                if !ev.verify() {
                    return None;
                }
                if ev.pubkey == self.keys.pk_hex && sub == "buzz-self" {
                    let newer = g.self_profiles.get(&ev.kind).is_none_or(|c| ev.created_at > c.created_at);
                    if newer {
                        g.self_profiles.insert(ev.kind, ev.clone());
                    }
                }
                if ev.kind == 0 {
                    let c: Value = serde_json::from_str(&ev.content).unwrap_or_default();
                    let name = c["display_name"].as_str().filter(|s| !s.trim().is_empty()).or(c["name"].as_str()).unwrap_or("").trim().to_string();
                    if !name.is_empty() {
                        g.profiles.insert(ev.pubkey.to_lowercase(), name);
                    }
                }
                None
            }
            KIND_ROOM_SYSTEM if g.role_admission => {
                // Relay system notices invalidate the roster: removals deny at once,
                // joins wait for a roster that lists them; then re-read the rosters.
                if !from_relay || !ev.verify() {
                    return None;
                }
                let room = ev.tag("h")?.trim().to_lowercase();
                let (kind, target) = membership_change(&ev.content)?;
                let r = g.rooms.get_mut(&room).filter(|r| r.members.is_some())?;
                if kind == "member_joined" {
                    if let Some(d) = r.denied.get_mut(&target) {
                        *d = true;
                    }
                } else {
                    r.denied.insert(target, false);
                }
                for (s, f) in subscriptions(&g, &self.keys.pk_hex, &self.configured) {
                    if s == "buzz-meta" {
                        self.req(&s, f);
                    }
                }
                None
            }
            k if DISPATCH_KINDS.contains(&k) => self.message(&mut g, ev, None),
            _ => None,
        }
    }

    /// `cli`: the room polled with `buzz messages get`, whose rows (as Hermes trusts
    /// them) may omit `sig` and the `h` tag.
    fn message(&self, g: &mut Inner, ev: Event, cli: Option<&str>) -> Option<Inbound> {
        let room = ev.tag("h").or(cli)?.trim().to_lowercase();
        let cli = cli.is_some();
        let cs = g.watched.get_mut(&room)?;
        if ev.id.is_empty() || cs.seen.contains(&ev.id) {
            return None;
        }
        if !(ev.verify() || (cli && ev.sig.is_empty())) {
            return None;
        }
        cs.seen.insert(&ev.id);
        cs.last_ts = cs.last_ts.max(ev.created_at.min(now() + 60));
        g.dirty = true;
        let cap = if ev.kind == 40008 { MAX_DIFF } else { MAX_CONTENT };
        let (media, rejected) = imeta_attachments(&ev);
        if ev.content.len() > cap || (ev.content.trim().is_empty() && media.is_empty() && rejected == 0) {
            return None;
        }
        let author = ev.pubkey.to_lowercase();
        g.meta.put(&ev.id, (author.clone(), ev.content.chars().take(500).collect()));
        let root = thread_root(&ev);
        g.roots.put(&ev.id, root.clone());
        if author == self.keys.pk_hex {
            return None;
        }
        let r = g.rooms.get(&room).cloned().unwrap_or_default();
        if r.members.as_ref().is_some_and(|m| !m.contains(&author)) {
            return None;
        }
        if g.role_admission && (!r.admitted(&self.keys.pk_hex) || r.denied.contains_key(&author)) {
            return None;
        }
        if ev.tags_named("p").count() > MAX_MENTIONS {
            return None;
        }
        let my_name = self.my_display_name(g);
        let mentioned = ev.has_p(&self.keys.pk_hex) || self.text_mentions_me(&ev.content, my_name.as_deref());
        let parent = reply_parent(&ev);
        let reply = parent.as_ref().map(|p| {
            let m = g.meta.get(p).cloned();
            ReplyRef {
                id: p.clone(),
                is_own: m.as_ref().is_some_and(|(a, _)| *a == self.keys.pk_hex),
                author: m.as_ref().map(|(a, _)| a.clone()).unwrap_or_default(),
                text: m.map(|(_, t)| t).unwrap_or_default(),
            }
        });
        let mut text = strip_leading_mention(&ev.content, &self.keys.pk_hex, my_name.as_deref());
        if ev.kind == 40008 {
            text = format_diff(&ev, &text)?;
        }
        if rejected > 0 {
            text = format!("{text}\n[{rejected} Buzz attachment(s) rejected as malformed or over limits.]").trim().to_string();
        }
        let sender_name = g.profiles.get(&author).cloned().unwrap_or_else(|| hex32(&author).map(|k| k1::npub(&k)).unwrap_or_default().chars().take(16).collect());
        Some(Inbound {
            channel: self.id.clone(),
            chat: room.clone(),
            chat_type: if r.is_dm() { ChatType::Direct } else { ChatType::Group },
            chat_name: if r.name.is_empty() { room } else { r.name.clone() },
            thread: root,
            sender: author,
            sender_name,
            text,
            message_id: ev.id.clone(),
            ts: ev.created_at,
            reply,
            media,
            mentioned,
            ..Default::default()
        })
    }

    fn my_display_name(&self, g: &Inner) -> Option<String> {
        g.profiles.get(&self.keys.pk_hex).cloned().or_else(|| self.profile_name.clone())
    }

    fn text_mentions_me(&self, content: &str, name: Option<&str>) -> bool {
        let low = content.to_lowercase();
        let npub = k1::npub(&self.keys.pk);
        contains_token(&low, &self.keys.pk_hex, |c| c.is_ascii_hexdigit())
            || contains_token(&low, &npub, |c| c.is_ascii_alphanumeric())
            || name.is_some_and(|n| !n.is_empty() && find_at_name(&low, &n.to_lowercase()).is_some())
    }

    /// OpenClaw profile sync: keep kind 0 `display_name` and kind 10100 `name`/`display_name`/
    /// `channel_add_policy`, merging into whatever is already published.
    fn sync_profile(&self) {
        let Some(name) = self.profile_name.clone() else { return };
        let events = {
            let mut g = self.inner.lock().unwrap();
            if g.profile_synced {
                return;
            }
            g.profile_synced = true;
            let cur0 = g.self_profiles.get(&0).cloned();
            let cur1 = g.self_profiles.get(&KIND_AGENT_PROFILE).cloned();
            let obj = |e: &Option<Event>| -> serde_json::Map<String, Value> { e.as_ref().and_then(|e| serde_json::from_str::<Value>(&e.content).ok()).and_then(|v| v.as_object().cloned()).unwrap_or_default() };
            let (mut c0, mut c1) = (obj(&cur0), obj(&cur1));
            let nonempty = |m: &serde_json::Map<String, Value>, k: &str| m.get(k).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
            let resolved = nonempty(&c0, "display_name").or_else(|| nonempty(&c1, "display_name")).or_else(|| nonempty(&c1, "name")).unwrap_or(name);
            let at = |c: &Option<Event>| c.as_ref().map(|e| now().max(e.created_at + 1)).unwrap_or_else(now);
            let auth_tag = parse_auth_tag(self.auth_tag.as_deref().unwrap_or("")).ok().flatten();
            let mut out = Vec::new();
            let tags0: Vec<Vec<String>> = {
                let mut t: Vec<Vec<String>> = cur0.as_ref().map(|e| e.tags.clone()).unwrap_or_default();
                if let Some(a) = &auth_tag {
                    t.retain(|x| x.first().map(String::as_str) != Some("auth"));
                    t.push(a.clone());
                }
                t
            };
            let auth_ok = auth_tag.as_ref().is_none_or(|a| cur0.as_ref().is_some_and(|e| e.tags_named("auth").count() == 1 && e.tags_named("auth").next() == Some(a)));
            if nonempty(&c0, "display_name").as_deref() != Some(resolved.as_str()) || !auth_ok {
                c0.insert("display_name".into(), json!(resolved));
                out.push(Event::signed(&self.keys, 0, tags0, &Value::Object(c0).to_string(), at(&cur0)));
            }
            let mut changed = false;
            for k in ["name", "display_name"] {
                if nonempty(&c1, k).is_none() {
                    c1.insert(k.into(), json!(resolved));
                    changed = true;
                }
            }
            if !matches!(c1.get("channel_add_policy").and_then(Value::as_str), Some("anyone" | "owner_only" | "nobody")) {
                c1.insert("channel_add_policy".into(), json!("anyone"));
                changed = true;
            }
            if changed {
                out.push(Event::signed(&self.keys, KIND_AGENT_PROFILE, cur1.map(|e| e.tags).unwrap_or_default(), &Value::Object(c1).to_string(), now()));
            }
            g.profiles.insert(self.keys.pk_hex.clone(), resolved);
            out
        };
        let (Some(relay), timeout) = (self.ws().cloned(), self.publish_timeout) else { return };
        std::thread::spawn(move || {
            for ev in events {
                let _ = publish_any(std::slice::from_ref(&relay), &ev, timeout);
            }
        });
    }

    /// Hermes: anchor replies on the trigger's thread root so answers join the thread.
    fn anchor(&self, out: &Outbound) -> Option<String> {
        if !self.reply_in_thread {
            return None;
        }
        let a = out.thread.clone().or_else(|| out.reply_to.clone())?;
        let g = self.inner.lock().unwrap();
        Some(g.roots.get(&a).cloned().flatten().unwrap_or(a))
    }

    fn mention_pubkeys(&self, room: &str, text: &str) -> Vec<String> {
        let g = self.inner.lock().unwrap();
        let mut found: Vec<String> = Vec::new();
        // NIP-27 `nostr:npub1…` references.
        let low = text.to_lowercase();
        let mut rest = low.as_str();
        while let Some(i) = rest.find("nostr:npub1") {
            let cand: String = rest[i + 6..].chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
            if let Ok(k1::Nip19::Npub(pk)) = k1::nip19_decode(&cand) {
                let h = hex(&pk);
                if h != self.keys.pk_hex && !found.contains(&h) {
                    found.push(h);
                }
            }
            rest = &rest[i + 6..];
        }
        // `@Display Name` of unique room members, longest names first; ambiguous names tag nobody.
        if text.contains('@') {
            let members: Vec<String> = g.rooms.get(room).and_then(|r| r.members.clone()).or_else(|| g.cli_members.get(room).map(|(_, m)| m.clone())).map(|m| m.into_iter().collect()).unwrap_or_default();
            let mut by_name: HashMap<String, Vec<String>> = HashMap::new();
            for pk in members.iter().filter(|p| **p != self.keys.pk_hex) {
                if let Some(n) = g.profiles.get(pk).filter(|n| !n.is_empty()) {
                    by_name.entry(n.to_lowercase()).or_default().push(pk.clone());
                }
            }
            let mut names: Vec<String> = by_name.keys().cloned().collect();
            names.sort_by_key(|n| std::cmp::Reverse(n.chars().count()));
            let mut hay = low.clone();
            for n in names {
                let mut hit = false;
                while let Some((s, e)) = find_at_name(&hay, &n) {
                    hit = true;
                    hay.replace_range(s..e, &"\u{0}".repeat(e - s));
                }
                let pks = &by_name[&n];
                if hit && pks.len() == 1 && !found.contains(&pks[0]) {
                    found.push(pks[0].clone());
                }
            }
        }
        found.truncate(MAX_MENTIONS);
        found
    }

    fn msg_tags(&self, room: &str, anchor: Option<&str>, mentions: &[String]) -> Vec<Vec<String>> {
        let mut tags = vec![tag(&["h", room])];
        if let Some(a) = anchor {
            tags.push(tag(&["e", a, "", "reply"]));
        }
        for p in mentions {
            tags.push(tag(&["p", p]));
        }
        tags
    }

    fn publish(&self, ev: &Event) -> Result<(), ChannelError> {
        let relay = self.ws().ok_or_else(|| crate::unsupported("this Buzz operation with the poll transport"))?;
        publish_any(std::slice::from_ref(relay), ev, self.publish_timeout).map(|_| ()).map_err(|e| {
            // "restricted: not a channel member" = we were removed from the room.
            if e.message.contains("not a channel member") {
                ChannelError::new(K::NotFound, e.message)
            } else {
                e
            }
        })
    }

    fn remember_own(&self, room: &str, id: &str, text: &str, anchor: Option<&str>) {
        let mut g = self.inner.lock().unwrap();
        g.meta.put(id, (self.keys.pk_hex.clone(), text.chars().take(500).collect()));
        g.roots.put(id, anchor.map(str::to_string));
        if let Some(cs) = g.watched.get_mut(room) {
            cs.seen.insert(id);
        }
    }

    /// `buzz` CLI (argv, never a shell); the key travels in the environment only.
    fn run_cli(&self, args: &[String], stdin: Option<&str>) -> Result<String, ChannelError> {
        use std::io::{Read, Write};
        use std::process::{Command, Stdio};
        let cli = self.cli_path.as_deref().ok_or_else(|| crate::unsupported("this Buzz operation without cli_path"))?;
        let mut cmd = Command::new(cli);
        cmd.args(args).env("BUZZ_RELAY_URL", &self.relay_http).env("BUZZ_PRIVATE_KEY", &self.raw_key).env_remove("BUZZ_AUTH_TAG");
        if let Some(t) = &self.auth_tag {
            cmd.env("BUZZ_AUTH_TAG", t);
        }
        cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| ChannelError::new(K::Fatal, format!("cannot run buzz CLI: {e}")))?;
        if let (Some(t), Some(mut si)) = (stdin, child.stdin.take()) {
            let _ = si.write_all(t.as_bytes());
        }
        let (mut so, mut se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
        let ho = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = so.read_to_string(&mut s);
            s
        });
        let he = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = se.read_to_string(&mut s);
            s
        });
        let until = Instant::now() + self.cli_timeout;
        let status = loop {
            if let Some(s) = child.try_wait().map_err(|e| ChannelError::new(K::Network, format!("buzz CLI: {e}")))? {
                break s;
            }
            if Instant::now() >= until {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ChannelError::new(K::Network, format!("buzz {} timed out", args.first().map(String::as_str).unwrap_or(""))));
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let (out, err) = (ho.join().unwrap_or_default(), he.join().unwrap_or_default());
        if status.success() {
            return Ok(out);
        }
        let code = status.code().unwrap_or(4);
        let detail = match serde_json::from_str::<Value>(err.trim()) {
            Ok(v) if v["message"].as_str().is_some_and(|m| !m.trim().is_empty()) => format!("{}: {} (exit {code})", v["error"].as_str().unwrap_or("error"), v["message"].as_str().unwrap().trim()),
            _ => if err.trim().is_empty() { format!("buzz CLI failed with exit code {code}") } else { err.trim().to_string() },
        };
        let detail: String = detail.replace(&self.raw_key, "***").chars().take(900).collect();
        let kind = if code == 2 { K::Network } else if detail.contains("not a channel member") || detail.contains("not_found") { K::NotFound } else if detail.contains("auth") { K::Auth } else { K::Protocol };
        Err(ChannelError::new(kind, detail))
    }

    fn receipt(out: &str) -> Result<String, ChannelError> {
        let v: Value = serde_json::from_str(out.trim()).map_err(|_| ChannelError::new(K::Protocol, "invalid buzz CLI response"))?;
        if v["accepted"] == false {
            return Err(ChannelError::new(K::Protocol, v["message"].as_str().unwrap_or("message was not accepted").to_string()));
        }
        match (v["accepted"].as_bool(), v["event_id"].as_str()) {
            (Some(true), Some(id)) if !id.trim().is_empty() => Ok(id.trim().to_string()),
            _ => Err(ChannelError::new(K::Protocol, "invalid buzz CLI response")),
        }
    }
}

fn hex(b: &[u8]) -> String {
    ark_net::crypto::hex(b)
}

fn channel_sub(room: &str) -> String {
    format!("buzz-ch-{room}")
}

fn subscriptions(g: &Inner, me: &str, configured: &[String]) -> Vec<(String, Vec<Value>)> {
    let mut subs = Vec::new();
    let watched: Vec<&String> = {
        let mut w: Vec<&String> = g.watched.keys().collect();
        w.sort();
        w
    };
    if let Some(rpk) = &g.relay_pk {
        if configured.is_empty() {
            subs.push(("buzz-rooms".to_string(), vec![json!({"kinds": [KIND_ROOM_MEMBERS], "authors": [rpk], "#p": [me], "limit": 1000})]));
        }
        if !watched.is_empty() {
            subs.push(("buzz-meta".to_string(), vec![json!({"kinds": [KIND_ROOM_META, KIND_ROOM_MEMBERS], "authors": [rpk], "#d": watched})]));
        }
    }
    subs.push(("buzz-joined".to_string(), vec![json!({"kinds": [KIND_MEMBER_ADDED], "#p": [me], "since": now() - 1})]));
    if !g.profile_synced {
        subs.push(("buzz-self".to_string(), vec![json!({"kinds": [0, KIND_AGENT_PROFILE], "authors": [me], "limit": 2})]));
    }
    let mut members: Vec<String> = watched.iter().filter_map(|r| g.rooms.get(*r)).filter_map(|r| r.members.as_ref()).flatten().cloned().collect();
    members.sort();
    members.dedup();
    members.truncate(500);
    if !members.is_empty() {
        subs.push(("buzz-profiles".to_string(), vec![json!({"kinds": [0], "authors": members})]));
    }
    for room in watched {
        // Role admission: no room traffic until the roster gives us the bot role.
        if g.role_admission && !g.rooms.get(room).is_some_and(|r| r.admitted(me)) {
            continue;
        }
        let cs = &g.watched[room];
        let mut f = json!({"kinds": DISPATCH_KINDS, "#h": [room]});
        if cs.last_ts > 0 {
            f["since"] = json!((cs.last_ts - 1).max(0));
        } else {
            f["limit"] = json!(FETCH_LIMIT);
        }
        let mut fs = vec![f];
        if let (true, Some(rpk)) = (g.role_admission, &g.relay_pk) {
            // Live membership notices only: history is reconciled by the roster itself.
            fs.push(json!({"kinds": [KIND_ROOM_SYSTEM], "authors": [rpk], "#h": [room], "since": now() - 1}));
        }
        subs.push((channel_sub(room), fs));
    }
    subs
}

/// Kind 40099 content `{type, target|actor}` → (type, member) for joins / leaves / removals.
fn membership_change(content: &str) -> Option<(String, String)> {
    let v: Value = serde_json::from_str(content).ok()?;
    let kind = v["type"].as_str().filter(|t| matches!(*t, "member_joined" | "member_left" | "member_removed"))?;
    let target = match (v["target"].as_str(), v["actor"].as_str()) {
        (Some(t), _) => t,
        (None, Some(a)) if kind == "member_left" => a,
        _ => return None,
    };
    let target = target.trim().to_lowercase();
    (target.len() == 64 && target.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))).then(|| (kind.to_string(), target))
}

/// (target, marker) of each NIP-10 `e` tag.
fn e_tags(ev: &Event) -> impl Iterator<Item = (&str, &str)> {
    ev.tags_named("e").map(|t| (t[1].trim(), t.get(3).map(String::as_str).unwrap_or("")))
}

/// Direct parent: `reply` marker, then `root`, else the last positional `e`.
fn reply_parent(ev: &Event) -> Option<String> {
    let (mut reply, mut root, mut last) = (None, None, None);
    for (t, m) in e_tags(ev).filter(|(t, _)| !t.is_empty()) {
        last = Some(t);
        match m {
            "reply" => reply = Some(t),
            "root" => root = Some(t),
            _ => {}
        }
    }
    reply.or(root).or(last).map(str::to_string)
}

/// Thread root; a lone `reply` (or unmarked) tag started a thread off its target.
fn thread_root(ev: &Event) -> Option<String> {
    let (mut root, mut reply) = (None, None);
    for (t, m) in e_tags(ev).filter(|(t, _)| !t.is_empty()) {
        match m.to_lowercase().as_str() {
            "root" => root = Some(t),
            "reply" => reply = Some(t),
            "" if reply.is_none() => reply = Some(t),
            _ => {}
        }
    }
    root.or(reply).map(str::to_string)
}

fn contains_token(hay: &str, needle: &str, word: impl Fn(char) -> bool) -> bool {
    let mut from = 0;
    while let Some(i) = hay[from..].find(needle) {
        let s = from + i;
        let e = s + needle.len();
        let before = hay[..s].chars().next_back();
        let after = hay[e..].chars().next();
        if !before.is_some_and(&word) && !after.is_some_and(&word) {
            return true;
        }
        from = s + 1;
        while !hay.is_char_boundary(from) {
            from += 1;
        }
    }
    false
}

/// `@name` with no word char or `@` before and a punctuation / space / end after.
fn find_at_name(hay: &str, name: &str) -> Option<(usize, usize)> {
    let pat = format!("@{name}");
    let mut from = 0;
    while let Some(i) = hay[from..].find(&pat) {
        let s = from + i;
        let e = s + pat.len();
        let before = hay[..s].chars().next_back();
        let after = hay[e..].chars().next();
        let ok_before = !before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '@');
        let ok_after = after.is_none_or(|c| c.is_whitespace() || ",;.!?:)]}".contains(c));
        if ok_before && ok_after {
            return Some((s, e));
        }
        from = s + 1;
    }
    None
}

/// Strip a leading mention of us so "@Bot /status" reads as a command.
fn strip_leading_mention(content: &str, pk_hex: &str, name: Option<&str>) -> String {
    let text = content.trim();
    let low = text.to_lowercase();
    let npub = hex32(pk_hex).map(|k| k1::npub(&k)).unwrap_or_default();
    let mut cands: Vec<String> = Vec::new();
    if let Some(n) = name.filter(|n| !n.is_empty()) {
        cands.push(format!("@{}", n.to_lowercase()));
    }
    for id in [npub.as_str(), pk_hex] {
        cands.push(format!("@{id}"));
        cands.push(id.to_string());
    }
    for c in cands {
        if low.starts_with(&c) {
            let rest = &text[c.len()..];
            if rest.is_empty() || rest.starts_with(|ch: char| ch.is_whitespace() || ",;.!?:)]}".contains(ch)) {
                return rest.trim_start_matches(|ch: char| ch.is_whitespace() || ch == ':' || ch == ',').trim().to_string();
            }
        }
    }
    text.to_string()
}

/// NIP-94 `imeta` attachments: https URL, 64-hex `x`, size within limits. (accepted, rejected).
fn imeta_attachments(ev: &Event) -> (Vec<Media>, usize) {
    let mut out = Vec::new();
    let (mut rejected, mut total) = (0, 0u64);
    for t in ev.tags_named("imeta") {
        if out.len() >= MAX_ATTACHMENTS {
            rejected += 1;
            continue;
        }
        let mut f: HashMap<&str, &str> = HashMap::new();
        for field in &t[1..] {
            if let Some((k, v)) = field.split_once(' ') {
                f.entry(k).or_insert(v.trim());
            }
        }
        let url = f.get("url").copied().unwrap_or("");
        let x = f.get("x").copied().unwrap_or("").to_lowercase();
        let size: u64 = f.get("size").and_then(|s| s.parse().ok()).unwrap_or(0);
        let ok_url = url.starts_with("https://") && ark_net::Url::parse(url).is_ok_and(|u| !url[8..].split('/').next().unwrap_or("").contains('@') && !u.host.is_empty()) && !url.contains('#');
        if !ok_url || hex32(&x).is_none() || size == 0 || size > MAX_ATTACHMENT_BYTES || total + size > MAX_ATTACHMENT_BYTES {
            rejected += 1;
            continue;
        }
        total += size;
        let mime = f.get("m").copied().unwrap_or("").chars().take(255).collect::<String>();
        let kind = match mime.split('/').next().unwrap_or("") {
            "image" => MediaKind::Image,
            "audio" => MediaKind::Audio,
            "video" => MediaKind::Video,
            _ => MediaKind::Document,
        };
        let name = f.get("filename").map(|n| n.rsplit(['/', '\\']).next().unwrap_or("").chars().filter(|c| !c.is_control()).take(120).collect::<String>()).filter(|n| !n.is_empty() && n != "." && n != "..").unwrap_or_else(|| "attachment.bin".into());
        out.push(Media { kind, url: Some(url.to_string()), mime, name, size, id: Some(x), ..Default::default() });
    }
    (out, rejected)
}

/// OpenClaw's agent-context rendering of a structured diff (kind 40008).
fn format_diff(ev: &Event, body: &str) -> Option<String> {
    let repo = ev.tag("repo").filter(|r| r.starts_with("https://") || r.starts_with("http://"))?;
    let commit = ev.tag("commit").filter(|c| c.len() >= 7 && c.chars().all(|x| x.is_ascii_hexdigit()))?;
    let one = |s: &str| -> String {
        let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
        if s.chars().count() <= 256 {
            s
        } else {
            format!("{}...", s.chars().take(253).collect::<String>())
        }
    };
    let mut lines = vec!["[Buzz structured diff]".to_string(), format!("Repository: {}", one(repo)), format!("Commit: {}", one(commit))];
    for (t, label) in [("parent-commit", "Parent commit"), ("file", "File"), ("l", "Language"), ("description", "Description"), ("alt", "Alt text")] {
        if let Some(v) = ev.tag(t) {
            lines.push(format!("{label}: {}", one(v)));
        }
    }
    if let Some(b) = ev.tags_named("branch").next().filter(|b| b.len() > 2) {
        lines.push(format!("Branches: {} -> {}", one(&b[1]), one(&b[2])));
    }
    if let Some(pr) = ev.tag("pr") {
        lines.push(format!("Pull request: #{pr}"));
    }
    if ev.tag("truncated") == Some("true") {
        lines.push("Truncated: yes".into());
    }
    let full = format!("{}\n\nUnified diff:\n{body}", lines.join("\n"));
    const MAX: usize = 4000;
    const SUFFIX: &str = "\n...[Buzz diff truncated for model context]";
    if full.chars().count() <= MAX {
        return Some(full);
    }
    Some(format!("{}{SUFFIX}", full.chars().take(MAX - SUFFIX.len()).collect::<String>().trim_end()))
}

/// A `buzz messages get` row as an event (Hermes reads id/pubkey/created_at/kind/tags/content).
fn cli_event(v: &Value) -> Option<Event> {
    let tags = v["tags"].as_array().map(|ts| ts.iter().filter_map(|t| t.as_array().map(|p| p.iter().map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string())).collect())).collect()).unwrap_or_default();
    Some(Event {
        id: v["id"].as_str()?.to_string(),
        pubkey: v["pubkey"].as_str()?.to_lowercase(),
        created_at: v["created_at"].as_i64().unwrap_or(0),
        kind: v["kind"].as_u64().unwrap_or(0) as u32,
        tags,
        content: v["content"].as_str()?.to_string(),
        sig: v["sig"].as_str().unwrap_or("").to_string(),
    })
}

fn json_list(out: &str) -> Vec<Value> {
    match serde_json::from_str::<Value>(out.trim()) {
        Ok(Value::Array(a)) => a.into_iter().filter(Value::is_object).collect(),
        _ => vec![],
    }
}

/// Poll transport (Hermes `_poll_loop` / `_seed_channel` / `_discover_dms`).
impl Buzz {
    /// Auto: no authenticated socket (rejected, or none within 25 s) → poll via the CLI.
    fn should_fall_back(&self) -> bool {
        let g = self.inner.lock().unwrap();
        if g.connected_once || !(g.auth_error.is_some() || self.started.elapsed() >= WS_FALLBACK_AFTER) {
            return false;
        }
        drop(g);
        self.polling.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(r) = &self.relay {
            r.stop();
        }
        self.inner.lock().unwrap().auth_error = None;
        true
    }

    /// OpenClaw: configured rooms need the bot role; fail when none has it.
    fn role_check(&self) -> Result<(), ChannelError> {
        let g = self.inner.lock().unwrap();
        if !g.role_admission || self.configured.is_empty() {
            return Ok(());
        }
        let known: Vec<&Room> = self.configured.iter().filter_map(|c| g.rooms.get(c)).filter(|r| r.members.is_some()).collect();
        if known.len() == self.configured.len() && !known.iter().any(|r| r.admitted(&self.keys.pk_hex)) {
            return Err(ChannelError::new(K::Auth, format!("Buzz bot does not have the Bot role in any configured room: {}", self.configured.join(", "))));
        }
        Ok(())
    }

    fn poll_cli(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let until = Instant::now() + self.poll_timeout;
        loop {
            if cancel.is_cancelled() {
                return Ok(vec![]);
            }
            let due = self.inner.lock().unwrap().next_sweep.is_none_or(|t| Instant::now() >= t);
            if due {
                self.inner.lock().unwrap().next_sweep = Some(Instant::now() + self.poll_interval);
                let got = self.sweep()?;
                self.save()?;
                if !got.is_empty() {
                    return Ok(got);
                }
            }
            if Instant::now() >= until {
                return Ok(vec![]);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn sweep(&self) -> Result<Vec<Inbound>, ChannelError> {
        if !self.inner.lock().unwrap().cli_ready {
            // Own display name drives mention detection.
            if self.profile_name.is_none() {
                let me = json_list(&self.run_cli(&["users".into(), "get".into()], None)?);
                if let Some(n) = me.first().and_then(|p| p["display_name"].as_str()).map(str::trim).filter(|n| !n.is_empty()) {
                    self.inner.lock().unwrap().profiles.insert(self.keys.pk_hex.clone(), n.to_string());
                }
            }
            let unseeded: Vec<String> = std::mem::take(&mut self.inner.lock().unwrap().unseeded).into_iter().collect();
            for room in unseeded {
                self.seed_cli(&room);
            }
            self.discover(true)?;
            let mut g = self.inner.lock().unwrap();
            g.cli_ready = true;
            g.discovery_done = true;
            g.dirty = true;
            return Ok(vec![]);
        }
        let n = {
            let mut g = self.inner.lock().unwrap();
            g.sweeps += 1;
            g.sweeps
        };
        if n % DM_DISCOVERY_EVERY == 0 {
            let _ = self.discover(false);
        }
        let mut rooms: Vec<(String, i64)> = self.inner.lock().unwrap().watched.iter().map(|(k, v)| (k.clone(), v.last_ts)).collect();
        rooms.sort();
        let mut got = Vec::new();
        for (room, since) in rooms {
            let mut args: Vec<String> = ["messages", "get", "--channel", &room, "--limit", &FETCH_LIMIT.to_string()].iter().map(|s| s.to_string()).collect();
            if since > 0 {
                // Nostr `since` is inclusive: same-second events re-fetch and de-dupe by id.
                args.extend(["--since".to_string(), since.to_string()]);
            }
            let Ok(out) = self.run_cli(&args, None) else { continue };
            let mut evs: Vec<Event> = json_list(&out).iter().filter_map(cli_event).collect();
            evs.sort_by_key(|e| e.created_at);
            self.resolve_names(evs.iter().filter(|e| e.pubkey != self.keys.pk_hex).map(|e| e.pubkey.clone()).collect());
            let mut g = self.inner.lock().unwrap();
            for ev in evs {
                if DISPATCH_KINDS.contains(&ev.kind) {
                    got.extend(self.message(&mut g, ev, Some(&room)));
                } else if let Some(cs) = g.watched.get_mut(&room) {
                    cs.seen.insert(&ev.id);
                    cs.last_ts = cs.last_ts.max(ev.created_at.min(now() + 60));
                }
            }
        }
        Ok(got)
    }

    /// `dms list` (best effort) + `channels list`; startup seeds, mid-run DMs start fresh.
    fn discover(&self, seed: bool) -> Result<(), ChannelError> {
        if let Ok(out) = self.run_cli(&["dms".into(), "list".into()], None) {
            for dm in json_list(&out) {
                let Some(id) = dm["dm_id"].as_str().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()) else { continue };
                {
                    let mut g = self.inner.lock().unwrap();
                    let r = g.rooms.entry(id.clone()).or_default();
                    if r.name.is_empty() {
                        r.name = "DM".into();
                    }
                }
                self.adopt_cli(&id, seed);
            }
        }
        let out = match self.run_cli(&["channels".into(), "list".into()], None) {
            Ok(o) => o,
            Err(e) if seed => return Err(e),
            Err(_) => return Ok(()),
        };
        for ch in json_list(&out) {
            let Some(id) = ch["channel_id"].as_str().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()) else { continue };
            let is_dm = {
                let mut g = self.inner.lock().unwrap();
                let r = g.rooms.entry(id.clone()).or_default();
                r.name = ch["name"].as_str().unwrap_or("").to_string();
                r.about = ch["description"].as_str().unwrap_or("").to_string();
                r.is_dm()
            };
            if is_dm {
                self.adopt_cli(&id, seed);
            } else if self.configured.is_empty() {
                // Watch-all: a channel joined mid-run is seeded (its history predates us).
                self.adopt_cli(&id, true);
            }
        }
        Ok(())
    }

    fn adopt_cli(&self, room: &str, seed: bool) {
        {
            let g = self.inner.lock().unwrap();
            if g.watched.contains_key(room) || g.restricted.contains(room) {
                return;
            }
        }
        if let Some(cur) = self.restored.lock().unwrap().remove(room) {
            let mut cs = ChanState { last_ts: cur.last_ts, seen: Seen::new(SEEN_CAP) };
            for s in &cur.seen {
                cs.seen.insert(s);
            }
            let mut g = self.inner.lock().unwrap();
            g.watched.insert(room.to_string(), cs);
            g.dirty = true;
        } else if seed {
            self.seed_cli(room);
        } else {
            let mut g = self.inner.lock().unwrap();
            g.watched.insert(room.to_string(), ChanState { last_ts: 0, seen: Seen::new(SEEN_CAP) });
            g.dirty = true;
        }
    }

    /// High-water mark from the newest events; history feeds reply lookups but never dispatches.
    fn seed_cli(&self, room: &str) {
        let out = self.run_cli(&["messages".into(), "get".into(), "--channel".into(), room.into(), "--limit".into(), FETCH_LIMIT.to_string()], None);
        let mut cs = ChanState { last_ts: 0, seen: Seen::new(SEEN_CAP) };
        let mut g = self.inner.lock().unwrap();
        match out {
            // "now" so a transiently unreadable room never replays its history later.
            Err(_) => cs.last_ts = now(),
            Ok(out) => {
                for ev in json_list(&out).iter().filter_map(cli_event) {
                    cs.seen.insert(&ev.id);
                    cs.last_ts = cs.last_ts.max(ev.created_at);
                    g.meta.put(&ev.id, (ev.pubkey.clone(), ev.content.chars().take(500).collect()));
                    g.roots.put(&ev.id, thread_root(&ev));
                }
            }
        }
        g.watched.insert(room.to_string(), cs);
        g.dirty = true;
    }

    /// `users get --pubkey` once per author (negative results cached too).
    fn resolve_names(&self, pks: Vec<String>) {
        for pk in pks {
            {
                let mut g = self.inner.lock().unwrap();
                if g.profiles.contains_key(&pk) || !g.name_tried.insert(pk.clone()) {
                    continue;
                }
            }
            let Ok(out) = self.run_cli(&["users".into(), "get".into(), "--pubkey".into(), pk.clone()], None) else { continue };
            let p = json_list(&out).into_iter().next().unwrap_or_default();
            let c: Value = p["content"].as_str().and_then(|c| serde_json::from_str(c).ok()).unwrap_or_default();
            let name = [&p["display_name"], &p["name"], &c["display_name"], &c["name"]].iter().filter_map(|v| v.as_str()).map(str::trim).find(|n| !n.is_empty()).map(str::to_string);
            if let Some(n) = name {
                self.inner.lock().unwrap().profiles.insert(pk, n);
            }
        }
    }

    /// Mention candidates for `@Name`: `channels members` (cached 60 s) and their names.
    fn cli_members(&self, room: &str, text: &str) {
        if !text.contains('@') {
            return;
        }
        let fresh = self.inner.lock().unwrap().cli_members.get(room).is_some_and(|(t, _)| t.elapsed() < MEMBER_CACHE_TTL);
        if !fresh {
            let rows = self.run_cli(&["channels".into(), "members".into(), "--channel".into(), room.into()], None).map(|o| json_list_any(&o)).unwrap_or_default();
            let pks: HashSet<String> = rows.iter().filter_map(|r| r["pubkey"].as_str().or(r.as_str())).map(|p| p.trim().to_lowercase()).filter(|p| hex32(p).is_some()).collect();
            self.inner.lock().unwrap().cli_members.insert(room.to_string(), (Instant::now(), pks));
        }
        let pks: Vec<String> = self.inner.lock().unwrap().cli_members.get(room).map(|(_, m)| m.iter().filter(|p| **p != self.keys.pk_hex).cloned().collect()).unwrap_or_default();
        self.resolve_names(pks);
    }

    /// `messages send` (content on stdin); a membership-drift rejection retries without `--mention`s.
    fn cli_send(&self, room: &str, anchor: Option<&str>, mentions: &[String], text: &str) -> Result<String, ChannelError> {
        let mut args: Vec<String> = ["messages", "send", "--channel", room, "--content", "-"].iter().map(|s| s.to_string()).collect();
        if let Some(a) = anchor {
            args.extend(["--reply-to".to_string(), a.to_string()]);
        }
        let mut with = args.clone();
        for p in mentions {
            with.extend(["--mention".to_string(), p.clone()]);
        }
        let out = match self.run_cli(&with, Some(text)) {
            Err(e) if !mentions.is_empty() && e.message.contains("not channel members") => self.run_cli(&args, Some(text))?,
            r => r?,
        };
        Self::receipt(&out)
    }
}

fn json_list_any(out: &str) -> Vec<Value> {
    match serde_json::from_str::<Value>(out.trim()) {
        Ok(Value::Array(a)) => a,
        _ => vec![],
    }
}

impl Buzz {
    fn restricted_check(&self, room: &str) -> Result<(), ChannelError> {
        if self.inner.lock().unwrap().restricted.contains(room) {
            return Err(ChannelError::new(K::NotFound, format!("buzz channel {room}: the relay rejected our membership")));
        }
        Ok(())
    }
}

impl Channel for Buzz {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        let cli = self.cli_path.is_some();
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group, ChatType::Thread],
            media: true,
            reply: true,
            threads: true,
            reactions: 2,
            edit: cli,
            delete: true,
            typing: true,
            max_len: MAX_LEN,
            len_unit: LenUnit::Chars,
            markup: Markup::Markdown,
            ..Caps::default()
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        self.save()?;
        if self.polling.load(std::sync::atomic::Ordering::SeqCst) {
            return self.poll_cli(cancel);
        }
        self.role_check()?;
        let rx = self.rx.lock().unwrap();
        let until = Instant::now() + self.poll_timeout;
        let mut got = Vec::new();
        loop {
            if cancel.is_cancelled() {
                return Ok(got);
            }
            if self.transport == Transport::Auto && self.should_fall_back() {
                drop(rx);
                return self.poll_cli(cancel);
            }
            if let Some(r) = self.inner.lock().unwrap().auth_error.clone() {
                return Err(ChannelError::new(K::Auth, format!("buzz relay authentication failed: {r}")));
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
                Err(RecvTimeoutError::Disconnected) => return Err(ChannelError::new(K::Fatal, "buzz relay worker stopped")),
            }
            if Instant::now() >= until {
                return Ok(got);
            }
        }
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let room = out.chat.trim().to_lowercase();
        if !is_uuid(&room) {
            return Err(ChannelError::new(K::Fatal, format!("buzz target {} is not a channel UUID", out.chat)));
        }
        self.restricted_check(&room)?;
        let anchor = self.anchor(out);
        let mut sent = Sent::default();
        let files: Vec<&Media> = out.media.iter().filter(|m| m.url.is_none() && m.path.is_some()).collect();
        if !files.is_empty() && self.cli_path.is_none() {
            return Err(ChannelError::new(K::Unsupported, "uploading files to Buzz needs cli_path (the buzz CLI); send a URL instead"));
        }
        for (i, m) in files.iter().enumerate() {
            let path = m.path.as_deref().unwrap();
            if !std::path::Path::new(path).is_file() {
                return Err(ChannelError::new(K::Fatal, "media file not found"));
            }
            let mut args: Vec<String> = ["messages", "send", "--channel", &room, "--file", path, "--content", "-"].iter().map(|s| s.to_string()).collect();
            if let Some(a) = &anchor {
                args.extend(["--reply-to".to_string(), a.clone()]);
            }
            let caption = if i == 0 && files.len() == 1 && out.media.len() == 1 { out.text.as_str() } else { m.caption.as_deref().unwrap_or("") };
            let id = Self::receipt(&self.run_cli(&args, Some(caption))?)?;
            self.remember_own(&room, &id, caption, anchor.as_deref());
            sent.ids.push(id);
        }
        let consumed_text = files.len() == 1 && out.media.len() == 1;
        let text = if consumed_text { String::new() } else { flatten(out) };
        for piece in crate::chunk::split(&text, MAX_LEN, LenUnit::Chars) {
            if self.ws().is_none() {
                self.cli_members(&room, &piece);
                let mentions = self.mention_pubkeys(&room, &piece);
                let id = self.cli_send(&room, anchor.as_deref(), &mentions, &piece)?;
                self.remember_own(&room, &id, &piece, anchor.as_deref());
                sent.ids.push(id);
                continue;
            }
            let mentions = self.mention_pubkeys(&room, &piece);
            let ev = Event::signed(&self.keys, 9, self.msg_tags(&room, anchor.as_deref(), &mentions), &piece, now());
            self.publish(&ev)?;
            self.remember_own(&room, &ev.id, &piece, anchor.as_deref());
            sent.ids.push(ev.id);
        }
        Ok(sent)
    }

    fn edit(&self, chat: &str, message_id: &str, text: &str) -> Result<(), ChannelError> {
        if text.is_empty() {
            return Err(ChannelError::new(K::Fatal, "empty edit"));
        }
        // `messages edit` takes --content literally; the `=` form keeps leading hyphens text.
        let out = self.run_cli(&["messages".into(), "edit".into(), "--event".into(), message_id.into(), format!("--content={text}")], None)?;
        if let Some(id) = serde_json::from_str::<Value>(&out).ok().and_then(|v| v["event_id"].as_str().map(str::to_string)) {
            self.remember_own(&chat.to_lowercase(), &id, text, None);
        }
        Ok(())
    }

    fn delete(&self, chat: &str, message_id: &str) -> Result<(), ChannelError> {
        if self.cli_path.is_some() {
            self.run_cli(&["messages".into(), "delete".into(), "--event".into(), message_id.into()], None)?;
            return Ok(());
        }
        let ev = Event::signed(&self.keys, 5, vec![tag(&["e", message_id]), tag(&["h", &chat.to_lowercase()])], "", now());
        self.publish(&ev)
    }

    fn typing(&self, chat: &str, thread: Option<&str>) -> Result<(), ChannelError> {
        let Some(relay) = self.ws().filter(|r| r.is_connected()) else { return Ok(()) };
        let room = chat.to_lowercase();
        let anchor = thread.map(|t| self.inner.lock().unwrap().roots.get(t).cloned().flatten().unwrap_or_else(|| t.to_string()));
        let ev = Event::signed(&self.keys, KIND_TYPING, self.msg_tags(&room, anchor.as_deref(), &[]), "", now());
        relay.send_raw(json!(["EVENT", ev]).to_string());
        Ok(())
    }

    fn react(&self, chat: &str, message_id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
        let room = chat.to_lowercase();
        let key = format!("{message_id}\u{0}{emoji}");
        if self.cli_path.is_some() && !remove {
            self.run_cli(&["reactions".into(), "add".into(), "--event".into(), message_id.into(), "--emoji".into(), emoji.into()], None)?;
            return Ok(());
        }
        if remove {
            let Some(rid) = self.inner.lock().unwrap().reactions.get(&key).cloned() else { return Ok(()) };
            let ev = Event::signed(&self.keys, 5, vec![tag(&["e", &rid]), tag(&["h", &room]), tag(&["k", "7"])], "", now());
            return self.publish(&ev);
        }
        let mut tags = vec![tag(&["e", message_id]), tag(&["h", &room]), tag(&["k", "9"])];
        if let Some((author, _)) = self.inner.lock().unwrap().meta.get(message_id).cloned() {
            tags.insert(1, tag(&["p", &author]));
        }
        let ev = Event::signed(&self.keys, 7, tags, emoji, now());
        self.publish(&ev)?;
        self.inner.lock().unwrap().reactions.put(&key, ev.id);
        Ok(())
    }

    /// Download an `imeta` attachment and check its declared size + SHA-256 (Hermes).
    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        let url = m.url.as_deref().ok_or_else(|| crate::unsupported("buzz attachment without url"))?;
        let data = crate::http::get_bytes(url, &[], MAX_ATTACHMENT_BYTES)?;
        if m.size > 0 && data.len() as u64 != m.size {
            return Err(ChannelError::new(K::Protocol, "buzz attachment size does not match its imeta declaration"));
        }
        if let Some(x) = &m.id {
            if hex(&ark_net::crypto::sha256(&data)) != *x {
                return Err(ChannelError::new(K::Protocol, "buzz attachment SHA-256 does not match its imeta declaration"));
            }
        }
        Ok(data)
    }

    fn stop(&self) {
        self.presence_stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(r) = &self.relay {
            r.stop();
        }
    }
}

impl Drop for Buzz {
    fn drop(&mut self) {
        self.stop();
    }
}

fn d_poll() -> u64 {
    25
}
fn d_true() -> bool {
    true
}
fn d_presence() -> u64 {
    30
}
fn d_transport() -> String {
    "websocket".into()
}
fn d_interval() -> f64 {
    4.0
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    /// Community relay, e.g. https://mycommunity.communities.buzz.xyz (ws(s) also accepted).
    relay_url: String,
    /// nsec or hex.
    private_key: String,
    /// NIP-OA owner attestation `["auth", …]` JSON for NIP-42.
    #[serde(default)]
    auth_tag: Option<String>,
    /// Channel UUIDs to watch; empty = every room the relay lists us in.
    #[serde(default)]
    channels: Vec<String>,
    /// Relay metadata signing key, when its NIP-11 document has no `self`.
    #[serde(default)]
    relay_pubkey: Option<String>,
    /// Display name kept in the bot's kind-0 / 10100 profile.
    #[serde(default)]
    profile_name: Option<String>,
    #[serde(default = "d_true")]
    reply_in_thread: bool,
    /// buzz CLI for edit / delete / reactions / file upload (as Hermes).
    #[serde(default)]
    cli_path: Option<String>,
    /// Presence heartbeat (kind 20001) period; 0 disables.
    #[serde(default = "d_presence")]
    presence_secs: u64,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    /// Inbound/outbound transport: "websocket" (default), "poll" (Hermes, via the
    /// buzz CLI) or "auto" (socket, falling back to polling).
    #[serde(default = "d_transport")]
    transport: String,
    /// Poll sweep period in seconds (minimum 1).
    #[serde(default = "d_interval")]
    poll_interval: f64,
    /// OpenClaw room admission: only rooms where the relay roster gives us the `bot` role.
    #[serde(default)]
    require_bot_role: bool,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let transport = match st.transport.as_str() {
        "websocket" => Transport::WebSocket,
        "poll" => Transport::Poll,
        "auto" => Transport::Auto,
        _ => return Err(format!("channel {}: transport must be websocket, poll or auto", ctx.name)),
    };
    let o = Options {
        relay_url: st.relay_url,
        private_key: ctx.secret("private_key", &st.private_key)?,
        auth_tag: ctx.opt_secret("auth_tag", &st.auth_tag)?,
        channels: st.channels,
        relay_pubkey: st.relay_pubkey,
        profile_name: st.profile_name,
        reply_in_thread: st.reply_in_thread,
        cli_path: st.cli_path,
        presence_secs: st.presence_secs,
        poll_timeout_secs: st.poll_timeout_secs,
        transport,
        poll_interval: st.poll_interval,
        require_bot_role: st.require_bot_role,
    };
    Ok(Arc::new(Buzz::new(ctx.name, o, ctx.state("buzz.json"), |_| {})?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::testrelay::FakeRelay;
    use crate::testutil::temp_dir;

    const ROOM: &str = "11111111-2222-3333-4444-555555555555";
    const DMROOM: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    struct World {
        relay_keys: Arc<Keys>,
        me: Keys,
        alice: Keys,
        bob: Keys,
    }

    fn world() -> World {
        World { relay_keys: Arc::new(Keys::generate()), me: Keys::generate(), alice: Keys::generate(), bob: Keys::generate() }
    }

    fn fast(o: &mut RelayOpts) {
        o.backoff_base = Duration::from_millis(30);
        o.backoff_max = Duration::from_millis(100);
        o.connect_timeout = Duration::from_secs(2);
    }

    fn opts(w: &World, url: &str) -> Options {
        Options {
            relay_url: url.replace("ws://", "http://"),
            private_key: k1::nsec(&w.me.sk),
            auth_tag: Some(r#"["auth","00","kind=9","sig"]"#.into()),
            channels: vec![],
            relay_pubkey: Some(w.relay_keys.pk_hex.clone()),
            profile_name: None,
            reply_in_thread: true,
            cli_path: None,
            presence_secs: 0,
            poll_timeout_secs: 1,
            transport: Transport::WebSocket,
            poll_interval: 1.0,
            require_bot_role: false,
        }
    }

    /// A Buzz-like relay: NIP-42 first, room membership + metadata signed by the relay key.
    fn relay(w: &World, reject_auth: bool) -> FakeRelay {
        let (rk, me, alice, bob) = (w.relay_keys.clone(), w.me.pk_hex.clone(), w.alice.pk_hex.clone(), w.bob.pk_hex.clone());
        let profiles = vec![(Keys::from_bytes(w.alice.sk).unwrap(), "Alice"), (Keys::from_bytes(w.bob.sk).unwrap(), "Bob")];
        FakeRelay::start(
            |n| vec![json!(["AUTH", format!("challenge-{n}")]).to_string()],
            move |n, v| {
                let ev = |sub: &str, e: Event| json!(["EVENT", sub, e]).to_string();
                match v[0].as_str() {
                    Some("AUTH") => vec![json!(["OK", v[1]["id"], !reject_auth, if reject_auth { "restricted: unknown agent" } else { "" }]).to_string()],
                    Some("REQ") => {
                        let sub = v[1].as_str().unwrap_or("");
                        let mut out = Vec::new();
                        if sub == "buzz-rooms" {
                            out.push(ev(sub, Event::signed(&rk, KIND_ROOM_MEMBERS, vec![tag(&["d", ROOM]), tag(&["p", &me, "", "bot"]), tag(&["p", &alice]), tag(&["p", &bob])], "", 100)));
                            out.push(ev(sub, Event::signed(&rk, KIND_ROOM_MEMBERS, vec![tag(&["d", DMROOM]), tag(&["p", &me]), tag(&["p", &alice])], "", 100)));
                            // Forged membership (not from the relay key) is ignored.
                            out.push(ev(sub, Event::signed(&Keys::generate(), KIND_ROOM_MEMBERS, vec![tag(&["d", "99999999-2222-3333-4444-555555555555"]), tag(&["p", &me])], "", 100)));
                        }
                        if sub == "buzz-meta" {
                            out.push(ev(sub, Event::signed(&rk, KIND_ROOM_META, vec![tag(&["d", ROOM]), tag(&["name", "general"]), tag(&["about", "chat"])], "", 100)));
                            out.push(ev(sub, Event::signed(&rk, KIND_ROOM_META, vec![tag(&["d", DMROOM]), tag(&["name", "DM"])], "", 100)));
                        }
                        if sub == "buzz-profiles" {
                            for (k, name) in &profiles {
                                out.push(ev(sub, Event::signed(k, 0, vec![], &json!({"display_name": name}).to_string(), 100)));
                            }
                        }
                        out.push(json!(["EOSE", sub]).to_string());
                        let _ = n;
                        out
                    }
                    Some("EVENT") => {
                        let content = v[1]["content"].as_str().unwrap_or("");
                        if content.contains("slow") {
                            return vec![json!(["OK", v[1]["id"], false, "rate-limited: slow down"]).to_string()];
                        }
                        vec![json!(["OK", v[1]["id"], true, ""]).to_string()]
                    }
                    _ => vec![],
                }
            },
        )
    }

    fn msg(k: &Keys, room: &str, text: &str, extra: Vec<Vec<String>>) -> Event {
        let mut tags = vec![tag(&["h", room])];
        tags.extend(extra);
        Event::signed(k, 9, tags, text, now())
    }

    fn poll_until(b: &Buzz, want: usize) -> Vec<Inbound> {
        let mut got = Vec::new();
        for _ in 0..20 {
            got.extend(b.poll(&Cancel::new()).unwrap());
            if got.len() >= want {
                break;
            }
        }
        got
    }

    /// Wait until the room subscriptions (and profiles) are in place.
    fn settle(b: &Buzz, r: &FakeRelay) {
        for _ in 0..200 {
            b.poll(&Cancel::new()).ok();
            let reqs = r.frames_of("REQ");
            let has = |s: &str| reqs.iter().any(|(_, v)| v[1].as_str().is_some_and(|x| x.starts_with(s)));
            if has(&channel_sub(ROOM)) && has(&channel_sub(DMROOM)) && has("buzz-profiles") && b.inner.lock().unwrap().profiles.len() >= 2 {
                return;
            }
        }
        panic!("subscriptions never settled: {:?}", r.frames_of("REQ"));
    }

    #[test]
    fn nip42_auth_comes_first_with_owner_attestation_tag() {
        let w = world();
        let r = relay(&w, false);
        let b = Buzz::new("bz", opts(&w, &r.url), temp_dir("buzz").join("s"), fast).unwrap();
        let first = r.wait_for("AUTH", 1);
        let all = r.frames.lock().unwrap().clone();
        assert_eq!(all[0].1[0], "AUTH", "nothing before AUTH: {all:?}");
        let ev: Event = serde_json::from_value(first[0].1[1].clone()).unwrap();
        assert!(ev.verify() && ev.kind == 22242 && ev.pubkey == w.me.pk_hex);
        assert_eq!(ev.tags, vec![tag(&["relay", &r.url]), tag(&["challenge", "challenge-0"]), tag(&["auth", "00", "kind=9", "sig"])]);
        settle(&b, &r);
        // Rejected AUTH → Auth error from poll.
        let r2 = relay(&w, true);
        let b2 = Buzz::new("bz", opts(&w, &r2.url), temp_dir("buzz").join("s"), fast).unwrap();
        let mut err = None;
        for _ in 0..20 {
            if let Err(e) = b2.poll(&Cancel::new()) {
                err = Some(e);
                break;
            }
        }
        let e = err.unwrap();
        assert!(e.kind == K::Auth && e.message.contains("unknown agent"), "{e}");
        assert!(r2.frames_of("REQ").is_empty(), "no subscriptions without auth");
        assert!(Buzz::new("bz", Options { auth_tag: Some("[\"x\"]".into()), ..opts(&w, &r.url) }, temp_dir("buzz").join("s"), fast).is_err());
        assert!(Buzz::new("bz", Options { channels: vec!["general".into()], ..opts(&w, &r.url) }, temp_dir("buzz").join("s"), fast).is_err());
    }

    #[test]
    fn discovers_rooms_and_parses_messages_mentions_threads_dms_and_media() {
        let w = world();
        let r = relay(&w, false);
        let b = Buzz::new("bz", opts(&w, &r.url), temp_dir("buzz").join("s"), fast).unwrap();
        settle(&b, &r);
        let carol = Keys::generate();
        let root = msg(&w.alice, ROOM, "@Bot can you look?", vec![tag(&["p", &w.me.pk_hex])]);
        let plain = msg(&w.bob, ROOM, "just chatting", vec![]);
        let in_thread = msg(&w.bob, ROOM, "and in the thread", vec![tag(&["e", &root.id, "", "root"]), tag(&["e", &plain.id, "", "reply"])]);
        let by_npub = msg(&w.bob, ROOM, &format!("hey {} ping", k1::npub(&w.me.pk)), vec![]);
        let own = msg(&w.me, ROOM, "my own echo", vec![]);
        let stranger = msg(&carol, ROOM, "not a member", vec![]);
        let mut forged = msg(&w.alice, ROOM, "forged", vec![]);
        forged.content = "tampered".into();
        let dm = msg(&w.alice, DMROOM, "private hi", vec![]);
        let x = "ab".repeat(32);
        let media = msg(&w.alice, ROOM, "see file", vec![vec!["imeta".into(), "url https://cdn.e.com/a.png".into(), format!("x {x}"), "size 10".into(), "m image/png".into(), "filename ../a.png".into()], vec!["imeta".into(), "url http://insecure/a".into(), format!("x {x}"), "size 1".into()]]);
        let other_room = msg(&w.alice, "77777777-2222-3333-4444-555555555555", "unwatched", vec![]);
        for ev in [&root, &plain, &in_thread, &by_npub, &own, &stranger, &forged, &dm, &media, &other_room, &root] {
            r.push(json!(["EVENT", channel_sub(ROOM), ev]).to_string());
        }
        let got = poll_until(&b, 6);
        assert_eq!(got.len(), 6, "{got:#?}");
        let (g0, g1, g2, g3, g4, g5) = (&got[0], &got[1], &got[2], &got[3], &got[4], &got[5]);
        assert_eq!((g0.chat.as_str(), g0.chat_name.as_str(), g0.chat_type, g0.sender.as_str(), g0.sender_name.as_str()), (ROOM, "general", ChatType::Group, w.alice.pk_hex.as_str(), "Alice"));
        assert!(g0.mentioned && g0.thread.is_none() && g0.text == "@Bot can you look?", "p-tag mention; '@Bot' is not our name: {g0:?}");
        assert!(!g1.mentioned && g1.text == "just chatting");
        assert_eq!(g2.thread.as_deref(), Some(root.id.as_str()));
        let rep = g2.reply.as_ref().unwrap();
        assert_eq!((rep.id.as_str(), rep.text.as_str(), rep.author.as_str(), rep.is_own), (plain.id.as_str(), "just chatting", w.bob.pk_hex.as_str(), false));
        assert!(g3.mentioned && g3.text.contains("ping"), "npub mention");
        assert_eq!((g4.chat.as_str(), g4.chat_type, g4.text.as_str()), (DMROOM, ChatType::Direct, "private hi"));
        assert_eq!(g5.media.len(), 1);
        assert_eq!((g5.media[0].kind, g5.media[0].url.as_deref(), g5.media[0].name.as_str(), g5.media[0].size), (MediaKind::Image, Some("https://cdn.e.com/a.png"), "a.png", 10));
        assert!(g5.text.contains("1 Buzz attachment(s) rejected"), "{}", g5.text);
        // Cursor persisted with seen ids on the next poll.
        b.poll(&Cancel::new()).unwrap();
        let st: State = serde_json::from_str(&std::fs::read_to_string(&b.state).unwrap()).unwrap();
        assert_eq!(st.identity, w.me.pk_hex);
        assert!(st.channels[ROOM].seen.contains(&root.id) && st.channels[ROOM].last_ts >= root.created_at);
    }

    #[test]
    fn sends_threaded_replies_with_resolved_mentions_and_native_actions() {
        let w = world();
        let r = relay(&w, false);
        let b = Buzz::new("bz", Options { profile_name: Some("Ark".into()), ..opts(&w, &r.url) }, temp_dir("buzz").join("s"), fast).unwrap();
        settle(&b, &r);
        let root = msg(&w.alice, ROOM, "@Ark question", vec![]);
        let inside = msg(&w.alice, ROOM, "follow-up", vec![tag(&["e", &root.id, "", "root"]), tag(&["e", &root.id, "", "reply"])]);
        r.push(json!(["EVENT", channel_sub(ROOM), root]).to_string());
        r.push(json!(["EVENT", channel_sub(ROOM), inside]).to_string());
        let got = poll_until(&b, 2);
        assert!(got[0].mentioned && got[0].text == "question", "display-name mention stripped: {:?}", got[0]);
        // Reply to the in-thread message anchors on the thread root (Hermes) and p-tags @Bob.
        let s = b.send(&Outbound { reply_to: Some(inside.id.clone()), ..Outbound::text(ROOM, "thanks @Bob, and @Bobby / email@Bob stay text") }).unwrap();
        let evs = r.wait_for("EVENT", 1);
        let sent: Event = serde_json::from_value(evs.iter().map(|(_, v)| v[1].clone()).find(|e| e["kind"] == 9).unwrap()).unwrap();
        assert_eq!(s.ids, vec![sent.id.clone()]);
        assert!(sent.verify());
        assert_eq!(sent.tags, vec![tag(&["h", ROOM]), tag(&["e", &root.id, "", "reply"]), tag(&["p", &w.bob.pk_hex])]);
        // A reply to our message is recognised as own.
        let back = msg(&w.bob, ROOM, "re", vec![tag(&["e", &sent.id, "", "reply"])]);
        r.push(json!(["EVENT", channel_sub(ROOM), back]).to_string());
        let got = poll_until(&b, 1);
        assert!(got[0].reply.as_ref().unwrap().is_own && got[0].addressed());
        // Flat mode: no e tags.
        let flat = Buzz::new("bz", Options { reply_in_thread: false, ..opts(&w, &r.url) }, temp_dir("buzz").join("s"), fast).unwrap();
        assert!(flat.anchor(&Outbound { reply_to: Some("x".into()), ..Outbound::text(ROOM, "") }).is_none());
        // Typing (kind 20002), reaction (kind 7) + removal (kind 5), delete (kind 5).
        b.typing(ROOM, Some(&inside.id)).unwrap();
        b.react(ROOM, &inside.id, "👀", false).unwrap();
        b.react(ROOM, &inside.id, "👀", true).unwrap();
        b.delete(ROOM, &sent.id).unwrap();
        let kinds = |k: u32| -> Vec<Event> {
            r.frames_of("EVENT").into_iter().map(|(_, v)| serde_json::from_value::<Event>(v[1].clone()).unwrap()).filter(|e| e.kind == k).collect()
        };
        for _ in 0..100 {
            if kinds(5).len() >= 2 && !kinds(KIND_TYPING).is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let typing = &kinds(KIND_TYPING)[0];
        assert_eq!(typing.tags, vec![tag(&["h", ROOM]), tag(&["e", &root.id, "", "reply"])]);
        let reaction = &kinds(7)[0];
        assert_eq!((reaction.content.as_str(), reaction.tag("e"), reaction.tag("p"), reaction.tag("h")), ("👀", Some(inside.id.as_str()), Some(w.alice.pk_hex.as_str()), Some(ROOM)));
        let dels = kinds(5);
        assert_eq!(dels[0].tag("e"), Some(reaction.id.as_str()));
        assert_eq!((dels[1].tag("e"), dels[1].tag("h")), (Some(sent.id.as_str()), Some(ROOM)));
        // Profile sync published kind 0 + 10100 with our name and the auth tag.
        let p0 = kinds(0);
        let p1 = kinds(KIND_AGENT_PROFILE);
        assert_eq!(serde_json::from_str::<Value>(&p0[0].content).unwrap()["display_name"], "Ark");
        assert_eq!(p0[0].tag("auth"), Some("00"));
        assert_eq!(serde_json::from_str::<Value>(&p1[0].content).unwrap(), json!({"name": "Ark", "display_name": "Ark", "channel_add_policy": "anyone"}));
        // Errors: rate limit, unsupported upload, edit without CLI, bad target.
        assert_eq!(b.send(&Outbound::text(ROOM, "slow")).unwrap_err().kind, K::RateLimited { retry_after: None });
        let file = Media { path: Some("/etc/hostname".into()), ..Default::default() };
        assert_eq!(b.send(&Outbound { media: vec![file], ..Outbound::text(ROOM, "") }).unwrap_err().kind, K::Unsupported);
        assert_eq!(b.edit(ROOM, &sent.id, "x").unwrap_err().kind, K::Unsupported);
        assert_eq!(b.send(&Outbound::text("general", "x")).unwrap_err().kind, K::Fatal);
    }

    #[test]
    fn restricted_room_is_dropped_and_sends_fail_not_found() {
        let w = world();
        let rk = w.relay_keys.clone();
        let me = w.me.pk_hex.clone();
        let r = FakeRelay::start(
            |_| vec![json!(["AUTH", "c"]).to_string()],
            move |_, v| match v[0].as_str() {
                Some("AUTH") => vec![json!(["OK", v[1]["id"], true, ""]).to_string()],
                Some("REQ") if v[1] == "buzz-rooms" => vec![json!(["EVENT", "buzz-rooms", Event::signed(&rk, KIND_ROOM_MEMBERS, vec![tag(&["d", ROOM]), tag(&["p", &me])], "", 1)]).to_string(), json!(["EOSE", "buzz-rooms"]).to_string()],
                Some("REQ") if v[1].as_str().is_some_and(|s| s.starts_with("buzz-ch-")) => vec![json!(["CLOSED", v[1], "restricted: not a channel member"]).to_string()],
                Some("EVENT") => vec![json!(["OK", v[1]["id"], false, "restricted: not a channel member"]).to_string()],
                _ => vec![],
            },
        );
        let b = Buzz::new("bz", opts(&w, &r.url), temp_dir("buzz").join("s"), fast).unwrap();
        for _ in 0..50 {
            b.poll(&Cancel::new()).unwrap();
            if b.inner.lock().unwrap().restricted.contains(ROOM) {
                break;
            }
        }
        assert!(!b.inner.lock().unwrap().watched.contains_key(ROOM));
        assert_eq!(b.send(&Outbound::text(ROOM, "x")).unwrap_err().kind, K::NotFound);
        let other = "22222222-2222-3333-4444-555555555555";
        assert_eq!(b.send(&Outbound::text(other, "x")).unwrap_err().kind, K::NotFound, "OK false restricted → NotFound");
    }

    #[test]
    fn reconnects_and_resumes_from_persisted_cursor() {
        let w = world();
        let r = relay(&w, false);
        let dir = temp_dir("buzz");
        let o = || Options { channels: vec![ROOM.into()], ..opts(&w, &r.url) };
        let b = Buzz::new("bz", o(), dir.join("s"), fast).unwrap();
        let mut f = Value::Null;
        for _ in 0..300 {
            if let Some((_, v)) = r.frames_of("REQ").into_iter().find(|(_, v)| v[1] == channel_sub(ROOM)) {
                f = v[2].clone();
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(f["kinds"], json!(DISPATCH_KINDS));
        assert_eq!(f["#h"], json!([ROOM]));
        assert!(f["since"].as_i64().unwrap() >= now() - 5, "configured rooms start now: {f}");
        let m1 = Event::signed(&w.alice, 9, vec![tag(&["h", ROOM])], "one", now() - 30);
        r.push(json!(["EVENT", channel_sub(ROOM), m1]).to_string());
        assert_eq!(poll_until(&b, 1)[0].text, "one");
        // Drop the socket: the worker reconnects, re-authenticates and re-subscribes.
        r.drop_all();
        for _ in 0..300 {
            if r.frames_of("AUTH").iter().any(|(c, _)| *c >= 1) && r.frames_of("REQ").iter().any(|(c, v)| *c >= 1 && v[1] == channel_sub(ROOM)) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let m2 = Event::signed(&w.bob, 9, vec![tag(&["h", ROOM])], "two", now());
        r.push(json!(["EVENT", channel_sub(ROOM), m2]).to_string());
        assert_eq!(poll_until(&b, 1)[0].text, "two");
        b.poll(&Cancel::new()).unwrap();
        b.stop();
        drop(b);
        // Restart: the subscription resumes from the stored cursor and the replay is deduped.
        let b2 = Buzz::new("bz", o(), dir.join("s"), fast).unwrap();
        let mut since = None;
        for _ in 0..300 {
            if let Some(v) = r.frames_of("REQ").iter().rev().find(|(c, v)| *c >= 2 && v[1] == channel_sub(ROOM)) {
                since = v.1[2]["since"].as_i64();
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(since, Some(m2.created_at - 1));
        r.push(json!(["EVENT", channel_sub(ROOM), m2]).to_string());
        assert!(b2.poll(&Cancel::new()).unwrap().is_empty());
        // Cancel returns promptly.
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.cancel();
        });
        let mut b2 = b2;
        b2.poll_timeout = Duration::from_secs(30);
        let t = Instant::now();
        assert!(b2.poll(&c).unwrap().is_empty());
        assert!(t.elapsed() < Duration::from_millis(400));
    }

    #[cfg(unix)]
    #[test]
    fn cli_handles_edit_delete_reactions_and_uploads_like_hermes() {
        use std::os::unix::fs::PermissionsExt;
        let w = world();
        let r = relay(&w, false);
        let dir = temp_dir("buzz");
        let log = dir.join("cli.log");
        let script = dir.join("buzz");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"ARGS $*\" \"KEY=${{BUZZ_PRIVATE_KEY}}\" \"RELAY=${{BUZZ_RELAY_URL}}\" \"TAG=${{BUZZ_AUTH_TAG}}\" >> {log}\nif [ \"$1 $2\" = \"messages send\" ]; then cat >> {log}; echo '{{\"accepted\":true,\"event_id\":\"evt-file\"}}'; exit 0; fi\nif [ \"$1\" = \"reactions\" ]; then echo '{{\"error\":\"rate_limited\",\"message\":\"later\"}}' >&2; exit 2; fi\necho '{{\"accepted\":true,\"event_id\":\"evt2\"}}'\n",
                log = log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let o = Options { cli_path: Some(script.display().to_string()), channels: vec![ROOM.into()], ..opts(&w, &r.url) };
        let b = Buzz::new("bz", o, dir.join("s"), fast).unwrap();
        assert!(b.caps().edit);
        b.edit(ROOM, "evt1", "--new text").unwrap();
        b.delete(ROOM, "evt1").unwrap();
        let e = b.react(ROOM, "evt1", "👍", false).unwrap_err();
        assert!(e.kind == K::Network && e.message == "rate_limited: later (exit 2)", "{e}");
        let f = dir.join("report.pdf");
        std::fs::write(&f, b"%PDF").unwrap();
        let s = b.send(&Outbound { reply_to: Some("rootid".into()), media: vec![Media { path: Some(f.display().to_string()), ..Default::default() }], ..Outbound::text(ROOM, "the report") }).unwrap();
        assert_eq!(s.ids, vec!["evt-file"]);
        let l = std::fs::read_to_string(&log).unwrap();
        assert!(l.contains("ARGS messages edit --event evt1 --content=--new text"), "{l}");
        assert!(l.contains("ARGS messages delete --event evt1"));
        assert!(l.contains("ARGS reactions add --event evt1 --emoji 👍"));
        assert!(l.contains(&format!("ARGS messages send --channel {ROOM} --file {} --content - --reply-to rootid", f.display())), "{l}");
        assert!(l.contains("the report"), "caption on stdin");
        assert!(l.contains(&format!("KEY={}", k1::nsec(&w.me.sk))) && l.contains(&format!("RELAY={}", r.url.replace("ws://", "http://"))) && l.contains("TAG=[\"auth\""));
    }

    #[test]
    fn helpers_follow_upstream_rules() {
        let k = Keys::generate();
        let e = |tags: Vec<Vec<String>>| Event::signed(&k, 9, tags, "x", 1);
        assert_eq!(thread_root(&e(vec![tag(&["e", "R", "", "root"]), tag(&["e", "P", "", "reply"])])).as_deref(), Some("R"));
        assert_eq!(thread_root(&e(vec![tag(&["e", "P", "", "reply"])])).as_deref(), Some("P"), "lone reply starts a thread");
        assert_eq!(thread_root(&e(vec![tag(&["e", "A"]), tag(&["e", "B"])])).as_deref(), Some("A"));
        assert_eq!(reply_parent(&e(vec![tag(&["e", "R", "", "root"]), tag(&["e", "P", "", "reply"])])).as_deref(), Some("P"));
        assert_eq!(reply_parent(&e(vec![tag(&["e", "A"]), tag(&["e", "B"])])).as_deref(), Some("B"));
        assert_eq!(strip_leading_mention("@Ark: /status", &k.pk_hex, Some("Ark")), "/status");
        assert_eq!(strip_leading_mention("@Arkham hi", &k.pk_hex, Some("Ark")), "@Arkham hi");
        assert_eq!(strip_leading_mention(&format!("{} hi", k1::npub(&k.pk)), &k.pk_hex, None), "hi");
        assert!(find_at_name("hi @riley!!", "riley").is_some());
        assert!(find_at_name("email@riley", "riley").is_none() && find_at_name("@@riley", "riley").is_none() && find_at_name("@rileyx", "riley").is_none());
        assert_eq!(ws_url("https://c.buzz.xyz/").unwrap(), ("wss://c.buzz.xyz".to_string(), "https://c.buzz.xyz".to_string()));
        assert!(ws_url("ftp://x").is_err());
        let diff = Event::signed(&k, 40008, vec![tag(&["h", ROOM]), tag(&["repo", "https://github.com/a/b"]), tag(&["commit", "abcdef1"]), tag(&["branch", "feat", "main"]), tag(&["pr", "7"])], "@@ -1 +1 @@", 1);
        let t = format_diff(&diff, &diff.content).unwrap();
        assert!(t.starts_with("[Buzz structured diff]\nRepository: https://github.com/a/b\nCommit: abcdef1") && t.contains("Branches: feat -> main") && t.contains("Pull request: #7") && t.ends_with("Unified diff:\n@@ -1 +1 @@"), "{t}");
        assert!(format_diff(&Event::signed(&k, 40008, vec![tag(&["repo", "ftp://x"]), tag(&["commit", "abcdef1"])], "", 1), "").is_none());
    }

    #[test]
    fn fetch_media_checks_size_and_digest() {
        let srv = crate::testutil::FakeServer::start(|_, _| (200, vec![], "0123456789".into()));
        let w = world();
        let b = Buzz::new("bz", Options { relay_url: "http://127.0.0.1:1".into(), presence_secs: 0, ..opts(&w, "ws://127.0.0.1:1") }, temp_dir("buzz").join("s"), fast).unwrap();
        let good = hex(&ark_net::crypto::sha256(b"0123456789"));
        let m = |x: &str, size| Media { url: Some(format!("{}/media/a", srv.url)), id: Some(x.into()), size, ..Default::default() };
        assert_eq!(b.fetch_media(&m(&good, 10)).unwrap(), b"0123456789");
        assert_eq!(b.fetch_media(&m(&good, 11)).unwrap_err().kind, K::Protocol);
        assert_eq!(b.fetch_media(&m(&"0".repeat(64), 10)).unwrap_err().kind, K::Protocol);
    }

    /// A fake `buzz` CLI: canned JSON per command from files in `dir`, argv + stdin logged.
    #[cfg(unix)]
    fn fake_cli(dir: &std::path::Path) -> String {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.join("buzz");
        let d = dir.display();
        std::fs::write(
            &script,
            format!(
                r#"#!/bin/sh
printf '%s\n' "ARGS $*" >> {d}/cli.log
case "$1 $2" in
  "users get") if [ "$3" = "--pubkey" ]; then cat {d}/user-$4.json 2>/dev/null || echo '[]'; else echo '[{{"pubkey":"me","display_name":"Ark"}}]'; fi ;;
  "channels list") cat {d}/channels.json ;;
  "channels members") cat {d}/members.json ;;
  "dms list") echo '[]' ;;
  "messages get") cat {d}/msgs-$4.json 2>/dev/null || echo '[]' ;;
  "messages send") cat >> {d}/cli.log; echo; echo '{{"accepted":true,"event_id":"evt-sent"}}' ;;
  *) echo '{{"error":"unknown","message":"nope"}}' >&2; exit 1 ;;
esac
"#
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script.display().to_string()
    }

    #[cfg(unix)]
    #[test]
    fn poll_transport_seeds_sweeps_and_sends_through_the_cli_like_hermes() {
        let w = world();
        let dir = temp_dir("buzz");
        let cli = fake_cli(&dir);
        let list = json!([{"channel_id": ROOM, "name": "general", "description": "chat"}, {"channel_id": DMROOM, "name": "DM", "description": ""}]);
        std::fs::write(dir.join("channels.json"), list.to_string()).unwrap();
        std::fs::write(dir.join("members.json"), json!([{"pubkey": w.alice.pk_hex}, {"pubkey": w.me.pk_hex}]).to_string()).unwrap();
        std::fs::write(dir.join(format!("user-{}.json", w.alice.pk_hex)), json!([{"display_name": "Alice"}]).to_string()).unwrap();
        let old = Event::signed(&w.alice, 9, vec![tag(&["h", ROOM])], "history", now() - 100);
        std::fs::write(dir.join(format!("msgs-{ROOM}.json")), json!([old]).to_string()).unwrap();
        let o = Options { cli_path: Some(cli), transport: Transport::Poll, relay_url: "http://127.0.0.1:1".into(), ..opts(&w, "ws://127.0.0.1:1") };
        let b = Buzz::new("bz", o, dir.join("s"), fast).unwrap();
        assert!(b.relay.is_none(), "no socket in poll mode");
        assert!(b.poll(&Cancel::new()).unwrap().is_empty(), "startup seeds, never replays history");
        // New traffic: a mention reply to history, a CLI row without sig, a forged row, a DM.
        let hi = Event::signed(&w.alice, 9, vec![tag(&["h", ROOM]), tag(&["e", &old.id, "", "reply"])], "@Ark please check", now());
        let mut unsigned = Event::signed(&w.bob, 9, vec![tag(&["h", ROOM])], "unsigned row", now());
        unsigned.sig.clear();
        let mut forged = Event::signed(&w.bob, 9, vec![tag(&["h", ROOM])], "x", now());
        forged.content = "tampered".into();
        std::fs::write(dir.join(format!("msgs-{ROOM}.json")), json!([forged, unsigned, hi, old]).to_string()).unwrap();
        let dm = Event::signed(&w.alice, 9, vec![], "private", now());
        std::fs::write(dir.join(format!("msgs-{DMROOM}.json")), json!([dm]).to_string()).unwrap();
        let mut got = poll_until(&b, 3);
        got.sort_by_key(|i| i.text.clone());
        assert_eq!(got.len(), 3, "{got:#?}");
        let (h, p, u) = (&got[0], &got[1], &got[2]);
        assert!(h.mentioned && h.text == "please check" && h.sender_name == "Alice" && h.chat_type == ChatType::Group, "{h:?}");
        assert_eq!(h.reply.as_ref().map(|r| r.text.as_str()), Some("history"), "seeded history feeds reply lookups");
        assert_eq!((p.chat.as_str(), p.chat_type), (DMROOM, ChatType::Direct), "DM-shaped channels list entry");
        assert_eq!(u.text, "unsigned row");
        let log = std::fs::read_to_string(dir.join("cli.log")).unwrap();
        assert!(log.contains(&format!("ARGS messages get --channel {ROOM} --limit 50\n")), "seed: {log}");
        assert!(log.contains(&format!("ARGS messages get --channel {ROOM} --limit 50 --since {}", old.created_at)), "inclusive since: {log}");
        assert!(log.contains(&format!("ARGS users get --pubkey {}", w.alice.pk_hex)));
        let s = b.send(&Outbound { reply_to: Some(hi.id.clone()), ..Outbound::text(ROOM, "@Alice done") }).unwrap();
        assert_eq!(s.ids, vec!["evt-sent"]);
        let log = std::fs::read_to_string(dir.join("cli.log")).unwrap();
        assert!(log.contains(&format!("ARGS messages send --channel {ROOM} --content - --reply-to {} --mention {}\n@Alice done", old.id, w.alice.pk_hex)), "{log}");
        b.typing(ROOM, None).unwrap();
        assert!(Buzz::new("bz", Options { transport: Transport::Poll, ..opts(&w, "ws://127.0.0.1:1") }, dir.join("s2"), fast).is_err(), "poll needs cli_path");
    }

    #[cfg(unix)]
    #[test]
    fn auto_transport_falls_back_to_polling_when_auth_is_rejected() {
        let w = world();
        let r = relay(&w, true);
        let dir = temp_dir("buzz");
        let cli = fake_cli(&dir);
        std::fs::write(dir.join("channels.json"), json!([{"channel_id": ROOM, "name": "general", "description": "x"}]).to_string()).unwrap();
        let o = Options { cli_path: Some(cli), transport: Transport::Auto, ..opts(&w, &r.url) };
        let b = Buzz::new("bz", o, dir.join("s"), fast).unwrap();
        r.wait_for("AUTH", 1);
        for _ in 0..20 {
            b.poll(&Cancel::new()).unwrap();
            if b.polling.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
        }
        assert!(b.polling.load(std::sync::atomic::Ordering::SeqCst));
        assert!(std::fs::read_to_string(dir.join("cli.log")).unwrap().contains("ARGS channels list"));
    }

    #[test]
    fn role_admission_needs_the_bot_role_and_denies_removed_members() {
        let w = world();
        let r = relay(&w, false);
        let b = Buzz::new("bz", Options { require_bot_role: true, ..opts(&w, &r.url) }, temp_dir("buzz").join("s"), fast).unwrap();
        let has = |s: &str| r.frames_of("REQ").iter().any(|(_, v)| v[1].as_str() == Some(s));
        for _ in 0..200 {
            b.poll(&Cancel::new()).ok();
            if has(&channel_sub(ROOM)) && b.inner.lock().unwrap().profiles.len() >= 2 {
                break;
            }
        }
        assert!(has(&channel_sub(ROOM)), "bot role in ROOM");
        assert!(!b.inner.lock().unwrap().watched.contains_key(DMROOM) && !has(&channel_sub(DMROOM)), "member without the bot role is not admitted");
        let sub = r.frames_of("REQ").into_iter().find(|(_, v)| v[1] == json!(channel_sub(ROOM))).unwrap().1;
        assert_eq!(sub[3]["kinds"], json!([KIND_ROOM_SYSTEM]), "live membership notices: {sub}");
        r.push(json!(["EVENT", channel_sub(ROOM), msg(&w.alice, ROOM, "before", vec![])]).to_string());
        assert_eq!(poll_until(&b, 1).len(), 1);
        let removal = Event::signed(&w.relay_keys, KIND_ROOM_SYSTEM, vec![tag(&["h", ROOM])], &json!({"type": "member_removed", "target": w.alice.pk_hex, "actor": w.bob.pk_hex}).to_string(), now());
        let spoof = Event::signed(&w.bob, KIND_ROOM_SYSTEM, vec![tag(&["h", ROOM])], &json!({"type": "member_removed", "target": w.bob.pk_hex}).to_string(), now());
        r.push(json!(["EVENT", channel_sub(ROOM), removal]).to_string());
        r.push(json!(["EVENT", channel_sub(ROOM), spoof]).to_string());
        r.push(json!(["EVENT", channel_sub(ROOM), msg(&w.alice, ROOM, "after removal", vec![])]).to_string());
        r.push(json!(["EVENT", channel_sub(ROOM), msg(&w.bob, ROOM, "bob still here", vec![])]).to_string());
        let got = poll_until(&b, 1);
        assert_eq!(got.iter().map(|i| i.text.as_str()).collect::<Vec<_>>(), vec!["bob still here"]);
        // Removing us blocks the room.
        let me_gone = Event::signed(&w.relay_keys, KIND_ROOM_SYSTEM, vec![tag(&["h", ROOM])], &json!({"type": "member_left", "actor": w.me.pk_hex}).to_string(), now());
        r.push(json!(["EVENT", channel_sub(ROOM), me_gone]).to_string());
        r.push(json!(["EVENT", channel_sub(ROOM), msg(&w.bob, ROOM, "into the void", vec![])]).to_string());
        let mut got = Vec::new();
        for _ in 0..3 {
            got.extend(b.poll(&Cancel::new()).unwrap());
        }
        assert!(got.is_empty(), "{got:?}");
        assert_eq!(membership_change(r#"{"type":"member_joined","target":"AB"}"#), None);
    }

    #[test]
    fn role_admission_rejects_configured_rooms_without_the_bot_role() {
        let w = world();
        let (rk, me) = (w.relay_keys.clone(), w.me.pk_hex.clone());
        let r = FakeRelay::start(
            |n| vec![json!(["AUTH", format!("c{n}")]).to_string()],
            move |_, v| match v[0].as_str() {
                Some("AUTH") => vec![json!(["OK", v[1]["id"], true, ""]).to_string()],
                Some("REQ") => {
                    let sub = v[1].as_str().unwrap_or("");
                    let mut out = vec![];
                    if sub == "buzz-meta" {
                        out.push(json!(["EVENT", sub, Event::signed(&rk, KIND_ROOM_MEMBERS, vec![tag(&["d", ROOM]), tag(&["p", &me, "", "member"])], "", 100)]).to_string());
                    }
                    out.push(json!(["EOSE", sub]).to_string());
                    out
                }
                _ => vec![],
            },
        );
        let o = Options { require_bot_role: true, channels: vec![ROOM.into()], ..opts(&w, &r.url) };
        let b = Buzz::new("bz", o, temp_dir("buzz").join("s"), fast).unwrap();
        let mut err = None;
        for _ in 0..50 {
            if let Err(e) = b.poll(&Cancel::new()) {
                err = Some(e);
                break;
            }
        }
        let e = err.expect("no bot role → error");
        assert!(e.kind == K::Auth && e.message.contains("Bot role"), "{e}");
        assert!(!r.frames_of("REQ").iter().any(|(_, v)| v[1] == json!(channel_sub(ROOM))), "never subscribed");
    }
}
