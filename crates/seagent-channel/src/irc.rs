//! IRC (ported from OpenClaw `extensions/irc` and Hermes `plugins/platforms/irc`, both MIT).
//!
//! One background thread owns the connection: TCP or TLS, `CAP LS 302` with
//! SASL PLAIN / `server-time` / `message-tags`, server `PASS`, NickServ
//! IDENTIFY (+ optional REGISTER), nick-collision recovery (GHOST, then
//! `nick_`, `nick_2`…), PING/PONG and a liveness check, JOIN with keys, and
//! reconnect with exponential backoff that only resets after a stable session.
//! Inbound PRIVMSG (and optionally NOTICE) become `Inbound`s on a queue that
//! `poll` drains: CTCP ACTION is rendered as `* nick text`, other CTCP is
//! dropped, `#`/`&` targets are groups, everything else a DM keyed by nick;
//! `mentioned` means our nick appears as a word (RFC 1459 case mapping).
//! Outbound lines are split on UTF-8 boundaries so the line the server relays
//! (`:nick!user@host PRIVMSG target :…`) stays within 512 bytes, and pass a
//! token-bucket flood limiter. Media go out as links; `silent` sends NOTICE;
//! `reply_to` uses the IRCv3 `+draft/reply` tag when the server has message-tags.
//! With IRCv3 `echo-message` a send waits (bounded) for the server to relay each
//! line back, takes the echoed `msgid` as the sent id and fails NotFound when the
//! server answers 401/403/404 instead; echoes are never delivered as inbound.
//! With `account-tag` the services account of the sender is known, and
//! `sender_identity = "account"` makes it the `sender` (nicks are spoofable).
//! Neither upstream implements these two caps; they follow the IRCv3 specs.

use crate::{markup, sleep_cancellable, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Outbound, ReplyRef, Sent, Streaming, TextFormat};
use seagent_core::Cancel;
use seagent_net::stream::{is_timeout, Stream};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// RFC 1459 line limit including CRLF.
pub const MAX_LINE: usize = 512;
/// Ceiling of the `user@host` part the server prepends when relaying our line.
const RELAY_USER: usize = 11;
const RELAY_HOST: usize = 63;
/// Unterminated inbound line cap (IRCv3 tags up to 8191 + 512 body, doubled).
const MAX_INBOUND_LINE: usize = 16 * 1024;
const LIVENESS: Duration = Duration::from_secs(240);
const STABLE: Duration = Duration::from_secs(60);
/// How long a 401/403/404/KICK keeps a target marked as gone.
const GONE_FOR: Duration = Duration::from_secs(600);
const READ_SLICE: Duration = Duration::from_millis(100);

// ---------------------------------------------------------------- protocol

/// One parsed IRC line; a trailing parameter is the last element of `params`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// One parsed IRC line. Public so the recorded protocol vectors
/// (`tests/real/vectors/irc_ngircd_session.txt`) can be replayed without a server.
pub struct Line {
    pub tags: Vec<(String, String)>,
    pub prefix: Option<String>,
    pub command: String,
    pub params: Vec<String>,
}

impl Line {
    pub fn tag(&self, k: &str) -> Option<&str> {
        self.tags.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
    pub fn param(&self, i: usize) -> &str {
        self.params.get(i).map(String::as_str).unwrap_or("")
    }
    pub fn last(&self) -> &str {
        self.params.last().map(String::as_str).unwrap_or("")
    }
    /// Nick part of `nick!user@host`; empty for server prefixes.
    pub fn nick(&self) -> &str {
        let Some(p) = self.prefix.as_deref() else { return "" };
        match p.find(['!', '@']) {
            Some(i) => &p[..i],
            None if p.contains('.') => "",
            None => p,
        }
    }
}

/// `[@tags] [:prefix] COMMAND params… [:trailing]`.
/// Public so recorded vectors (real server output) can be replayed in tests.
pub fn parse_line(raw: &str) -> Option<Line> {
    let mut rest = raw.trim_end_matches(['\r', '\n']).trim_start_matches(' ');
    let mut tags = Vec::new();
    if let Some(r) = rest.strip_prefix('@') {
        let (t, r2) = r.split_once(' ')?;
        for kv in t.split(';').filter(|s| !s.is_empty()) {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            tags.push((k.to_string(), unescape_tag(v)));
        }
        rest = r2.trim_start_matches(' ');
    }
    let mut prefix = None;
    if let Some(r) = rest.strip_prefix(':') {
        let (p, r2) = r.split_once(' ')?;
        if p.is_empty() {
            return None;
        }
        prefix = Some(p.to_string());
        rest = r2.trim_start_matches(' ');
    }
    let (cmd, mut rest) = rest.split_once(' ').unwrap_or((rest, ""));
    if cmd.is_empty() {
        return None;
    }
    let mut params = Vec::new();
    loop {
        rest = rest.trim_start_matches(' ');
        if rest.is_empty() {
            break;
        }
        if let Some(t) = rest.strip_prefix(':') {
            params.push(t.to_string());
            break;
        }
        match rest.split_once(' ') {
            Some((p, r)) => {
                params.push(p.to_string());
                rest = r;
            }
            None => {
                params.push(rest.to_string());
                break;
            }
        }
    }
    Some(Line { tags, prefix, command: cmd.to_ascii_uppercase(), params })
}

pub(crate) fn unescape_tag(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut it = v.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some(':') => out.push(';'),
            Some('s') => out.push(' '),
            Some('r') => out.push('\r'),
            Some('n') => out.push('\n'),
            Some(o) => out.push(o),
            None => {}
        }
    }
    out
}

pub(crate) fn escape_tag(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            ';' => out.push_str("\\:"),
            ' ' => out.push_str("\\s"),
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// Remove mIRC formatting (bold, colours, reset…) from inbound text.
pub(crate) fn strip_formatting(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\x02' | '\x0f' | '\x16' | '\x1d' | '\x1f' | '\x1e' | '\x11' => {}
            '\x03' => {
                for _ in 0..2 {
                    if it.peek().is_some_and(|c| c.is_ascii_digit()) {
                        it.next();
                    }
                }
                if it.peek() == Some(&',') {
                    let mut look = it.clone();
                    look.next();
                    if look.peek().is_some_and(|c| c.is_ascii_digit()) {
                        it.next();
                        for _ in 0..2 {
                            if it.peek().is_some_and(|c| c.is_ascii_digit()) {
                                it.next();
                            }
                        }
                    }
                }
            }
            '\x04' => {
                for _ in 0..6 {
                    if it.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                        it.next();
                    }
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// Control characters (CR, LF, CTCP \x01…) can break out of a line; drop them.
pub(crate) fn sanitize_text(s: &str) -> String {
    s.chars().map(|c| if c == '\t' { ' ' } else { c }).filter(|c| !c.is_control()).collect::<String>().trim().to_string()
}

/// Split one line into pieces of at most `max_bytes` bytes and `max_chars`
/// characters, never inside a UTF-8 sequence, preferring the last space.
pub(crate) fn split_text(line: &str, max_bytes: usize, max_chars: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line.trim();
    let max_chars = max_chars.max(1);
    while !rest.is_empty() {
        let mut end = 0;
        for (n, (i, c)) in rest.char_indices().enumerate() {
            if i + c.len_utf8() > max_bytes || n + 1 > max_chars {
                break;
            }
            end = i + c.len_utf8();
        }
        if end == 0 {
            // A single character wider than the budget; budget checks make this unreachable.
            end = rest.chars().next().map(char::len_utf8).unwrap_or(rest.len());
        }
        if end < rest.len() {
            if let Some(sp) = rest[..end].rfind(' ') {
                if sp > 0 && sp >= end / 2 {
                    end = sp;
                }
            }
        }
        out.push(rest[..end].trim_end().to_string());
        rest = rest[end..].trim_start();
    }
    out
}

/// IRCv3 `server-time` (`2023-04-05T06:07:08.123Z`) → unix seconds.
pub(crate) fn parse_time(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d, hh, mm, ss) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097 + doe - 719468) * 86400 + hh * 3600 + mm * 60 + ss)
}

pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub(crate) fn now_millis() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

/// RFC 1459 case mapping (`[]\~` are the upper case of `{}|^`).
pub(crate) fn fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '[' => '{',
            ']' => '}',
            '\\' => '|',
            '~' => '^',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

fn is_nick_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "_-[]\\`^{}|~".contains(c)
}

/// Our nick appears as a whole word (not inside a longer nick).
pub(crate) fn mentions(text: &str, nick: &str) -> bool {
    if nick.is_empty() {
        return false;
    }
    let (t, n) = (fold(text), fold(nick));
    let mut from = 0;
    while let Some(i) = t[from..].find(&n) {
        let s = from + i;
        let e = s + n.len();
        let before = t[..s].chars().next_back();
        let after = t[e..].chars().next();
        if !before.is_some_and(is_nick_char) && !after.is_some_and(is_nick_char) {
            return true;
        }
        from = s + n.len().max(1);
        while !t.is_char_boundary(from) {
            from += 1;
        }
    }
    false
}

/// `nick: do this` → `do this`.
fn strip_address(text: &str, nick: &str) -> String {
    let (t, n) = (fold(text), fold(nick));
    if !n.is_empty() && t.starts_with(&n) {
        let rest = &text[n.len()..];
        if let Some(r) = rest.strip_prefix([':', ',']) {
            return r.trim_start().to_string();
        }
    }
    text.to_string()
}

pub(crate) fn is_channel(target: &str) -> bool {
    target.starts_with(['#', '&', '+', '!'])
}

/// Accepts `#chan`, `nick`, `irc:#chan`, `channel:chan`, `user:nick`.
pub(crate) fn normalize_target(raw: &str) -> Option<String> {
    let mut t = raw.trim();
    if t.len() > 4 && t[..4].eq_ignore_ascii_case("irc:") {
        t = t[4..].trim();
    }
    let mut owned = t.to_string();
    if t.len() > 8 && t[..8].eq_ignore_ascii_case("channel:") {
        let c = t[8..].trim();
        owned = if is_channel(c) { c.to_string() } else { format!("#{c}") };
    } else if t.len() > 5 && t[..5].eq_ignore_ascii_case("user:") {
        owned = t[5..].trim().to_string();
    }
    let ok = !owned.is_empty() && owned.len() <= 200 && !owned.chars().any(|c| c.is_whitespace() || c.is_control() || c == ':' || c == ',');
    ok.then_some(owned)
}

/// Exponential backoff with ±20 % jitter.
pub(crate) struct Backoff {
    pub base: Duration,
    pub max: Duration,
    attempt: u32,
}

impl Backoff {
    pub fn new(base: Duration, max: Duration) -> Backoff {
        Backoff { base, max, attempt: 0 }
    }
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
    pub fn next_delay(&mut self) -> Duration {
        let d = self.base.saturating_mul(1u32 << self.attempt.min(16)).min(self.max);
        self.attempt += 1;
        let r = seagent_net::crypto::random_bytes(1)[0] as f64 / 255.0;
        d.mul_f64(0.8 + 0.4 * r)
    }
}

/// Token bucket: `burst` lines at once, then one per `per`.
pub(crate) struct Flood {
    burst: f64,
    per: Duration,
    state: Mutex<(f64, Instant)>,
}

impl Flood {
    pub fn new(burst: u32, per: Duration) -> Flood {
        let burst = burst.max(1) as f64;
        Flood { burst, per, state: Mutex::new((burst, Instant::now())) }
    }
    /// Wait for a token; false when cancelled.
    pub fn take(&self, cancel: &Cancel) -> bool {
        if self.per.is_zero() {
            return true;
        }
        let mut g = self.state.lock().unwrap();
        loop {
            let now = Instant::now();
            g.0 = (g.0 + now.duration_since(g.1).as_secs_f64() / self.per.as_secs_f64()).min(self.burst);
            g.1 = now;
            if g.0 >= 1.0 {
                g.0 -= 1.0;
                return true;
            }
            let wait = self.per.mul_f64(1.0 - g.0);
            if !sleep_cancellable(wait, cancel) {
                return false;
            }
        }
    }
}

/// Markdown → plain, media as links, buttons as numbered options.
pub(crate) fn render_body(out: &Outbound) -> Result<String, ChannelError> {
    let mut body = match out.format {
        TextFormat::Markdown => markup::convert(&out.text, Markup::Plain),
        TextFormat::Plain => out.text.clone(),
    };
    for m in &out.media {
        let Some(u) = &m.url else {
            return Err(ChannelError::new(K::Unsupported, "IRC cannot upload files; give the attachment a public url"));
        };
        let label = m.caption.as_deref().filter(|c| !c.is_empty()).unwrap_or(&m.name);
        body.push('\n');
        if label.is_empty() {
            body.push_str(u);
        } else {
            body.push_str(&format!("{label}: {u}"));
        }
    }
    let mut n = 0;
    for b in out.buttons.iter().flatten() {
        body.push('\n');
        match &b.url {
            Some(u) => body.push_str(&format!("{}: {u}", b.label)),
            None => {
                n += 1;
                body.push_str(&format!("{n}. {}", b.label));
            }
        }
    }
    Ok(body)
}

// ---------------------------------------------------------------- channel

#[derive(Debug, Clone)]
pub struct NickServ {
    pub password: String,
    pub service: String,
    pub register_email: Option<String>,
}

/// Connection settings (see `Settings` for the TOML names).
#[derive(Debug, Clone)]
pub struct Cfg {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub nick: String,
    pub username: String,
    pub realname: String,
    pub password: Option<String>,
    /// SASL PLAIN (authcid, password).
    pub sasl: Option<(String, String)>,
    pub nickserv: Option<NickServ>,
    /// (channel, key).
    pub channels: Vec<(String, Option<String>)>,
    pub accept_notices: bool,
    pub max_chars: usize,
    pub flood_burst: u32,
    pub flood_interval: Duration,
    pub connect_timeout: Duration,
    pub reconnect_base: Duration,
    pub reconnect_max: Duration,
    /// How long `send` waits for a (re)connecting session.
    pub send_wait: Duration,
    /// How long `send` waits for `echo-message` echoes.
    pub echo_wait: Duration,
    /// `sender` is the services account (`account` tag) instead of the nick.
    pub sender_account: bool,
}

impl Cfg {
    pub fn new(host: &str, port: u16, tls: bool, nick: &str) -> Cfg {
        Cfg {
            host: host.into(),
            port,
            tls,
            nick: nick.into(),
            username: nick.into(),
            realname: "seagent".into(),
            password: None,
            sasl: None,
            nickserv: None,
            channels: Vec::new(),
            accept_notices: false,
            max_chars: 350,
            flood_burst: 4,
            flood_interval: Duration::from_millis(400),
            connect_timeout: Duration::from_secs(15),
            reconnect_base: Duration::from_secs(1),
            reconnect_max: Duration::from_secs(30),
            send_wait: Duration::from_secs(10),
            echo_wait: Duration::from_secs(5),
            sender_account: false,
        }
    }
}

/// (key, folded target, text, msgid out).
type EchoWait = (u64, String, String, Sender<String>);

struct Shared {
    id: String,
    cfg: Cfg,
    conn: Mutex<Option<Stream>>,
    /// Writers waiting for `conn`; the reader yields to them.
    want_write: AtomicUsize,
    nick: Mutex<String>,
    ready: AtomicBool,
    caps: Mutex<HashSet<String>>,
    fatal: Mutex<Option<ChannelError>>,
    gone: Mutex<HashMap<String, (String, Instant)>>,
    stop: Cancel,
    flood: Flood,
    seq: AtomicU64,
    tx: Mutex<Sender<Inbound>>,
    /// Sends awaiting their `echo-message` echo: (key, folded target, text, msgid out).
    echo: Mutex<Vec<EchoWait>>,
}

impl Shared {
    fn write_raw(&self, line: &str) -> std::io::Result<()> {
        let clean: String = line.chars().filter(|c| *c != '\r' && *c != '\n').collect();
        self.want_write.fetch_add(1, Ordering::SeqCst);
        let r = {
            let mut g = self.conn.lock().unwrap();
            match g.as_mut() {
                Some(s) => s.write_all(format!("{clean}\r\n").as_bytes()).and_then(|_| s.flush()),
                None => Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "not connected")),
            }
        };
        self.want_write.fetch_sub(1, Ordering::SeqCst);
        r
    }
    fn nick(&self) -> String {
        self.nick.lock().unwrap().clone()
    }
    fn next_id(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::SeqCst)
    }
}

enum End {
    Retry(String),
    Fatal(ChannelError),
    Stopped,
}

struct Reg {
    ls: Vec<String>,
    nick_tries: u32,
    ghosted: bool,
}

pub struct Irc {
    sh: Arc<Shared>,
    rx: Mutex<Receiver<Inbound>>,
    poll_timeout: u64,
}

impl Irc {
    /// Validate settings and start the connection thread.
    pub fn start(id: &str, cfg: Cfg, poll_timeout_secs: u64) -> Result<Irc, String> {
        if cfg.host.trim().is_empty() {
            return Err(format!("channel {id}: irc host is empty"));
        }
        if cfg.nick.trim().is_empty() || cfg.nick.contains([' ', ':', ',', '!', '@']) {
            return Err(format!("channel {id}: irc nick is empty or invalid"));
        }
        for (c, _) in &cfg.channels {
            if !is_channel(c) || normalize_target(c).as_deref() != Some(c.as_str()) {
                return Err(format!("channel {id}: `{c}` is not an IRC channel name"));
            }
        }
        if let Some(ns) = &cfg.nickserv {
            if normalize_target(&ns.service).is_none() {
                return Err(format!("channel {id}: invalid nickserv_service"));
            }
        }
        let (tx, rx) = channel();
        let sh = Arc::new(Shared {
            id: id.to_string(),
            nick: Mutex::new(cfg.nick.trim().to_string()),
            flood: Flood::new(cfg.flood_burst, cfg.flood_interval),
            cfg,
            conn: Mutex::new(None),
            want_write: AtomicUsize::new(0),
            ready: AtomicBool::new(false),
            caps: Mutex::new(HashSet::new()),
            fatal: Mutex::new(None),
            gone: Mutex::new(HashMap::new()),
            stop: Cancel::new(),
            seq: AtomicU64::new(1),
            tx: Mutex::new(tx),
            echo: Mutex::new(Vec::new()),
        });
        let s2 = sh.clone();
        std::thread::Builder::new().name(format!("irc-{id}")).spawn(move || run(s2)).map_err(|e| format!("channel {id}: cannot start irc thread: {e}"))?;
        Ok(Irc { sh, rx: Mutex::new(rx), poll_timeout: poll_timeout_secs })
    }

    /// The nick the server currently knows us by.
    pub fn current_nick(&self) -> String {
        self.sh.nick()
    }

    fn wait_ready(&self) -> Result<(), ChannelError> {
        let until = Instant::now() + self.sh.cfg.send_wait;
        loop {
            if let Some(e) = self.sh.fatal.lock().unwrap().clone() {
                return Err(e);
            }
            if self.sh.ready.load(Ordering::SeqCst) {
                return Ok(());
            }
            if Instant::now() >= until || self.sh.stop.is_cancelled() {
                return Err(ChannelError::new(K::Network, "irc: not connected"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Irc {
    /// Wait for the echo of each sent line; echoed msgids replace the local ids.
    fn await_echoes(&self, target: &str, waits: &[Receiver<String>], ids: &mut [String]) -> Result<(), ChannelError> {
        let until = Instant::now() + self.sh.cfg.echo_wait;
        let sent_at = Instant::now();
        let mut r = Ok(());
        'lines: for (i, rx) in waits.iter().enumerate() {
            loop {
                match rx.recv_timeout(Duration::from_millis(20)) {
                    Ok(m) => {
                        if !m.is_empty() {
                            ids[i] = m;
                        }
                        continue 'lines;
                    }
                    Err(RecvTimeoutError::Disconnected) => break 'lines,
                    Err(RecvTimeoutError::Timeout) => {}
                }
                if let Some((why, at)) = self.sh.gone.lock().unwrap().get(&fold(target)) {
                    if *at >= sent_at {
                        r = Err(ChannelError::new(K::NotFound, format!("irc: cannot send to {target}: {why}")));
                        break 'lines;
                    }
                }
                // No echo in time: the line was written, so report it as sent.
                if Instant::now() >= until || self.sh.stop.is_cancelled() {
                    break 'lines;
                }
            }
        }
        r
    }
}

impl Drop for Irc {
    fn drop(&mut self) {
        self.sh.stop.cancel();
    }
}

fn run(sh: Arc<Shared>) {
    let mut backoff = Backoff::new(sh.cfg.reconnect_base, sh.cfg.reconnect_max);
    while !sh.stop.is_cancelled() {
        let started = Instant::now();
        let end = session(&sh);
        sh.ready.store(false, Ordering::SeqCst);
        if let Some(s) = sh.conn.lock().unwrap().take() {
            s.shutdown();
        }
        match end {
            End::Stopped => break,
            End::Fatal(e) => {
                *sh.fatal.lock().unwrap() = Some(e);
                break;
            }
            End::Retry(_why) => {}
        }
        if started.elapsed() >= STABLE {
            backoff.reset();
        }
        if !sleep_cancellable(backoff.next_delay(), &sh.stop) {
            break;
        }
    }
}

fn session(sh: &Arc<Shared>) -> End {
    let c = &sh.cfg;
    let s = match Stream::connect(&c.host, c.port, c.tls, c.connect_timeout) {
        Ok(s) => s,
        Err(e) => return End::Retry(format!("connect {}:{}: {e}", c.host, c.port)),
    };
    let _ = s.set_read_timeout(Some(READ_SLICE));
    *sh.conn.lock().unwrap() = Some(s);
    sh.caps.lock().unwrap().clear();
    *sh.nick.lock().unwrap() = c.nick.trim().to_string();
    let mut hello = vec!["CAP LS 302".to_string()];
    if let Some(p) = c.password.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        // Servers read only the first word of a middle parameter.
        hello.push(if p.contains(' ') || p.starts_with(':') { format!("PASS :{p}") } else { format!("PASS {p}") });
    }
    hello.push(format!("NICK {}", c.nick.trim()));
    hello.push(format!("USER {} 0 * :{}", c.username.trim(), sanitize_text(&c.realname)));
    for l in hello {
        if let Err(e) = sh.write_raw(&l) {
            return End::Retry(format!("write: {e}"));
        }
    }
    let started = Instant::now();
    let mut reg = Reg { ls: Vec::new(), nick_tries: 0, ghosted: false };
    let mut buf: Vec<u8> = Vec::new();
    let mut last_rx = Instant::now();
    let mut pinged = false;
    let mut chunk = [0u8; 8192];
    loop {
        if sh.stop.is_cancelled() {
            let _ = sh.write_raw("QUIT :bye");
            return End::Stopped;
        }
        let ready = sh.ready.load(Ordering::SeqCst);
        if !ready && started.elapsed() > c.connect_timeout * 2 {
            return End::Retry("registration timed out".into());
        }
        if ready && last_rx.elapsed() >= LIVENESS {
            return End::Retry("server went silent".into());
        }
        if ready && !pinged && last_rx.elapsed() >= LIVENESS / 2 {
            pinged = true;
            let _ = sh.write_raw("PING :seagent");
        }
        // Let waiting writers in before blocking on the socket again.
        while sh.want_write.load(Ordering::SeqCst) > 0 {
            std::thread::yield_now();
        }
        let r = {
            let mut g = sh.conn.lock().unwrap();
            match g.as_mut() {
                Some(s) => s.read(&mut chunk),
                None => return End::Retry("connection gone".into()),
            }
        };
        match r {
            Ok(0) => return End::Retry("connection closed".into()),
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                last_rx = Instant::now();
                pinged = false;
            }
            Err(e) if is_timeout(&e) || e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return End::Retry(format!("read: {e}")),
        }
        while let Some(i) = buf.iter().position(|&b| b == b'\n') {
            let raw: Vec<u8> = buf.drain(..=i).collect();
            let text = String::from_utf8_lossy(&raw);
            let Some(line) = parse_line(&text) else { continue };
            if let Some(end) = handle(sh, &mut reg, &line) {
                return end;
            }
        }
        if buf.len() > MAX_INBOUND_LINE {
            return End::Retry("server sent an over-long line".into());
        }
    }
}

fn auth_err(msg: impl Into<String>) -> End {
    End::Fatal(ChannelError::new(K::Auth, msg))
}

/// React to one server line. `Some(end)` ends the session.
fn handle(sh: &Arc<Shared>, reg: &mut Reg, l: &Line) -> Option<End> {
    let c = &sh.cfg;
    let ready = sh.ready.load(Ordering::SeqCst);
    let send = |s: &str| {
        let _ = sh.write_raw(s);
    };
    match l.command.as_str() {
        "PING" => send(&format!("PONG :{}", l.last())),
        "CAP" => match l.param(1).to_ascii_uppercase().as_str() {
            "LS" => {
                let more = l.params.len() >= 4 && l.param(2) == "*";
                reg.ls.extend(l.last().split_whitespace().map(str::to_string));
                if more {
                    return None;
                }
                let avail: HashMap<String, String> = reg.ls.iter().map(|c| c.split_once('=').map(|(k, v)| (k.to_ascii_lowercase(), v.to_string())).unwrap_or((c.to_ascii_lowercase(), String::new()))).collect();
                let mut want = Vec::new();
                if c.sasl.is_some() {
                    match avail.get("sasl") {
                        Some(v) if v.is_empty() || v.split(',').any(|m| m.eq_ignore_ascii_case("PLAIN")) => want.push("sasl"),
                        _ => return Some(auth_err("irc server does not offer SASL PLAIN")),
                    }
                }
                for cap in ["server-time", "message-tags", "echo-message", "account-tag"] {
                    if avail.contains_key(cap) {
                        want.push(cap);
                    }
                }
                if want.is_empty() {
                    send("CAP END");
                } else {
                    send(&format!("CAP REQ :{}", want.join(" ")));
                }
            }
            "ACK" => {
                let acked: Vec<String> = l.last().split_whitespace().filter(|c| !c.starts_with('-')).map(|c| c.to_ascii_lowercase()).collect();
                let sasl = acked.iter().any(|c| c == "sasl");
                sh.caps.lock().unwrap().extend(acked);
                if sasl && c.sasl.is_some() {
                    send("AUTHENTICATE PLAIN");
                } else if !ready {
                    send("CAP END");
                }
            }
            "NAK" => {
                if c.sasl.is_some() && !ready {
                    return Some(auth_err("irc server refused the SASL capability"));
                }
                send("CAP END");
            }
            _ => {}
        },
        "AUTHENTICATE" if l.param(0) == "+" => {
            if let Some((user, pass)) = &c.sasl {
                let payload = seagent_net::crypto::b64(format!("{user}\0{user}\0{pass}").as_bytes());
                let mut rest = payload.as_str();
                while !rest.is_empty() {
                    let (a, b) = rest.split_at(rest.len().min(400));
                    send(&format!("AUTHENTICATE {a}"));
                    rest = b;
                }
                if payload.len().is_multiple_of(400) {
                    send("AUTHENTICATE +");
                }
            }
        }
        "903" => send("CAP END"),
        "902" | "904" | "905" | "906" | "908" if c.sasl.is_some() => return Some(auth_err(format!("irc SASL authentication failed ({})", l.command))),
        "421" if l.param(1).eq_ignore_ascii_case("CAP") && c.sasl.is_some() => return Some(auth_err("irc server does not support CAP/SASL")),
        "001" => {
            sh.ready.store(true, Ordering::SeqCst);
            if !l.param(0).trim().is_empty() {
                *sh.nick.lock().unwrap() = l.param(0).trim().to_string();
            }
            if let Some(ns) = &c.nickserv {
                let pw = sanitize_text(&ns.password);
                if !pw.is_empty() {
                    send(&format!("PRIVMSG {} :IDENTIFY {pw}", ns.service));
                    if let Some(email) = ns.register_email.as_deref().map(sanitize_text).filter(|e| !e.is_empty()) {
                        send(&format!("PRIVMSG {} :REGISTER {pw} {email}", ns.service));
                    }
                }
            }
            for (ch, key) in &c.channels {
                match key {
                    Some(k) => send(&format!("JOIN {ch} {k}")),
                    None => send(&format!("JOIN {ch}")),
                }
            }
        }
        "433" | "436" if !ready => {
            let desired = c.nick.trim();
            if let (Some(ns), false) = (&c.nickserv, reg.ghosted) {
                reg.ghosted = true;
                send(&format!("PRIVMSG {} :GHOST {desired} {}", ns.service, sanitize_text(&ns.password)));
                send(&format!("NICK {desired}"));
                return None;
            }
            if reg.nick_tries >= 5 {
                return Some(End::Fatal(ChannelError::new(K::Fatal, format!("irc nick {desired} and its fallbacks are in use"))));
            }
            reg.nick_tries += 1;
            let base: String = desired.chars().take(24).collect();
            let fallback = if reg.nick_tries == 1 { format!("{base}_") } else { format!("{base}_{}", reg.nick_tries) };
            send(&format!("NICK {fallback}"));
            *sh.nick.lock().unwrap() = fallback;
        }
        "432" if !ready => return Some(End::Fatal(ChannelError::new(K::Fatal, format!("irc server rejected nick {}: {}", c.nick, l.last())))),
        "464" | "465" if !ready => return Some(auth_err(format!("irc login rejected ({}): {}", l.command, l.last()))),
        "ERROR" => return Some(End::Retry(format!("server error: {}", l.last()))),
        "NICK" => {
            let mut n = sh.nick.lock().unwrap();
            if fold(l.nick()) == fold(&n) && !l.param(0).is_empty() {
                *n = l.param(0).to_string();
            }
        }
        "401" | "403" | "404" if ready => {
            sh.gone.lock().unwrap().insert(fold(l.param(1)), (format!("{} {}", l.command, l.last()), Instant::now()));
        }
        "KICK" if fold(l.param(1)) == fold(&sh.nick()) => {
            sh.gone.lock().unwrap().insert(fold(l.param(0)), (format!("kicked: {}", l.last()), Instant::now()));
        }
        "JOIN" if fold(l.nick()) == fold(&sh.nick()) => {
            sh.gone.lock().unwrap().remove(&fold(l.param(0)));
        }
        "PRIVMSG" | "NOTICE" if fold(l.nick()) == fold(&sh.nick()) => {
            // Our own line relayed back (echo-message): confirm the waiting send.
            let mut q = sh.echo.lock().unwrap();
            if let Some(i) = q.iter().position(|(_, t, x, _)| *t == fold(l.param(0)) && x == l.last()) {
                let (_, _, _, tx) = q.remove(i);
                let _ = tx.send(l.tag("msgid").or_else(|| l.tag("draft/msgid")).unwrap_or("").to_string());
            }
        }
        "PRIVMSG" | "NOTICE" => {
            let n = sh.nick();
            let id = format!("{}-{}", now_millis(), sh.next_id());
            if let Some(mut m) = inbound_of(&sh.id, l, &n, c.accept_notices, &id) {
                if c.sender_account {
                    // Logged-out users get a `?` prefix, which no account name can carry.
                    m.sender = account_of(l).map(str::to_string).unwrap_or_else(|| format!("?{}", m.sender));
                }
                let _ = sh.tx.lock().unwrap().send(m);
            }
        }
        _ => {}
    }
    None
}

/// IRCv3 `account` tag; `*` (or absent) means not logged in.
fn account_of(l: &Line) -> Option<&str> {
    l.tag("account").filter(|a| !a.is_empty() && *a != "*")
}

/// PRIVMSG/NOTICE → Inbound. `fallback_id` is used when the server sends no `msgid` tag.
fn inbound_of(channel: &str, l: &Line, my_nick: &str, accept_notices: bool, fallback_id: &str) -> Option<Inbound> {
    let notice = l.command == "NOTICE";
    if notice && !accept_notices {
        return None;
    }
    let nick = l.nick();
    // Server notices (no user@host) and our own lines are not messages.
    if nick.is_empty() || fold(nick) == fold(my_nick) || (notice && !l.prefix.as_deref().unwrap_or("").contains('!')) {
        return None;
    }
    if notice && ["nickserv", "chanserv", "memoserv", "operserv", "global"].contains(&fold(nick).as_str()) {
        return None;
    }
    let target = l.param(0);
    if l.params.len() < 2 || target.is_empty() || target == "*" {
        return None;
    }
    let raw = l.last();
    let text = if let Some(ctcp) = raw.strip_prefix('\x01') {
        let ctcp = ctcp.strip_suffix('\x01').unwrap_or(ctcp);
        let (verb, arg) = ctcp.split_once(' ').unwrap_or((ctcp, ""));
        if !verb.eq_ignore_ascii_case("ACTION") {
            return None;
        }
        format!("* {nick} {}", strip_formatting(arg).trim())
    } else {
        strip_formatting(raw)
    };
    if text.trim().is_empty() {
        return None;
    }
    let group = is_channel(target);
    let mentioned = mentions(&text, my_nick);
    let text = if mentioned { strip_address(&text, my_nick) } else { text };
    let reply = l.tag("+draft/reply").or_else(|| l.tag("+reply")).filter(|r| !r.is_empty()).map(|r| ReplyRef { id: r.to_string(), ..Default::default() });
    Some(Inbound {
        channel: channel.to_string(),
        chat: if group { target.to_string() } else { nick.to_string() },
        chat_type: if group { ChatType::Group } else { ChatType::Direct },
        chat_name: if group { target.to_string() } else { String::new() },
        sender: nick.to_string(),
        sender_name: nick.to_string(),
        is_bot: l.tag("bot").is_some() || l.tag("draft/bot").is_some(),
        text,
        message_id: l.tag("msgid").or_else(|| l.tag("draft/msgid")).filter(|m| !m.is_empty()).unwrap_or(fallback_id).to_string(),
        ts: l.tag("time").and_then(parse_time).unwrap_or_else(now_secs),
        mentioned,
        reply,
        ..Default::default()
    })
}

impl Channel for Irc {
    fn id(&self) -> &str {
        &self.sh.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct, ChatType::Group],
            media: true,
            reply: self.sh.caps.lock().unwrap().contains("message-tags"),
            threads: false,
            reactions: 0,
            edit: false,
            delete: false,
            typing: false,
            buttons: false,
            polls: false,
            native_commands: false,
            streaming: Streaming::None,
            max_len: 2000,
            len_unit: LenUnit::Chars,
            markup: Markup::Plain,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let until = Instant::now() + Duration::from_secs(self.poll_timeout.max(1));
        let rx = self.rx.lock().unwrap();
        loop {
            if let Some(e) = self.sh.fatal.lock().unwrap().clone() {
                return Err(e);
            }
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(m) => {
                    let mut v = vec![m];
                    v.extend(rx.try_iter());
                    return Ok(v);
                }
                Err(RecvTimeoutError::Timeout) => {
                    if cancel.is_cancelled() || Instant::now() >= until {
                        return Ok(vec![]);
                    }
                }
                Err(RecvTimeoutError::Disconnected) => return Err(ChannelError::new(K::Network, "irc worker stopped")),
            }
        }
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let target = normalize_target(&out.chat).ok_or_else(|| ChannelError::new(K::Protocol, format!("invalid IRC target {:?}", out.chat)))?;
        let body = render_body(out)?;
        self.wait_ready()?;
        if let Some((why, at)) = self.sh.gone.lock().unwrap().get(&fold(&target)) {
            if at.elapsed() < GONE_FOR {
                return Err(ChannelError::new(K::NotFound, format!("irc: cannot send to {target}: {why}")));
            }
        }
        let verb = if out.silent { "NOTICE" } else { "PRIVMSG" };
        let nick = self.sh.nick();
        let relay = format!(":{nick}!@ ").len() + RELAY_USER + RELAY_HOST;
        let overhead = relay + format!("{verb} {target} :\r\n").len();
        if overhead + 16 > MAX_LINE {
            return Err(ChannelError::new(K::Protocol, "IRC target leaves no room for text within 512 bytes"));
        }
        let budget = MAX_LINE - overhead;
        let lines: Vec<String> = body.lines().map(sanitize_text).filter(|l| !l.is_empty()).flat_map(|l| split_text(&l, budget, self.sh.cfg.max_chars)).collect();
        if lines.is_empty() {
            return Err(ChannelError::new(K::Protocol, "irc: message is empty"));
        }
        let tag = match out.reply_to.as_deref().filter(|r| !r.is_empty() && !r.contains(' ')) {
            Some(r) if self.sh.caps.lock().unwrap().contains("message-tags") => format!("@+draft/reply={} ", escape_tag(r)),
            _ => String::new(),
        };
        let echo = self.sh.caps.lock().unwrap().contains("echo-message");
        let mut sent = Sent::default();
        let mut waits = Vec::new();
        let mut keys = Vec::new();
        for (i, l) in lines.iter().enumerate() {
            if !self.sh.flood.take(&self.sh.stop) {
                return Err(ChannelError::new(K::Network, "irc: channel stopped"));
            }
            let t = if i == 0 { tag.as_str() } else { "" };
            if echo {
                let (tx, rx) = channel();
                let k = self.sh.next_id();
                self.sh.echo.lock().unwrap().push((k, fold(&target), l.clone(), tx));
                waits.push(rx);
                keys.push(k);
            }
            self.sh.write_raw(&format!("{t}{verb} {target} :{l}")).map_err(|e| ChannelError::new(K::Network, format!("irc send: {e}")))?;
            sent.ids.push(format!("irc:{}", self.sh.next_id()));
        }
        if echo {
            let r = self.await_echoes(&target, &waits, &mut sent.ids);
            self.sh.echo.lock().unwrap().retain(|(k, ..)| !keys.contains(k));
            r?;
        }
        Ok(sent)
    }

    fn stop(&self) {
        self.sh.stop.cancel();
    }
}

// ---------------------------------------------------------------- settings

fn d_true() -> bool {
    true
}
fn d_poll() -> u64 {
    25
}
fn d_chars() -> usize {
    350
}
fn d_burst() -> u32 {
    4
}
fn d_interval() -> u64 {
    400
}
fn d_connect() -> u64 {
    15
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    host: String,
    /// Default 6697 with TLS, 6667 without.
    #[serde(default)]
    port: Option<u16>,
    #[serde(default = "d_true")]
    tls: bool,
    nick: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    realname: Option<String>,
    /// Server password (`PASS`).
    #[serde(default)]
    password: Option<String>,
    /// SASL PLAIN account (defaults to `nick`) and password.
    #[serde(default)]
    sasl_username: Option<String>,
    #[serde(default)]
    sasl_password: Option<String>,
    #[serde(default)]
    nickserv_password: Option<String>,
    #[serde(default)]
    nickserv_service: Option<String>,
    /// Send `REGISTER <password> <email>` on connect (once, for initial registration).
    #[serde(default)]
    nickserv_register: bool,
    #[serde(default)]
    nickserv_register_email: Option<String>,
    /// `"#chan"` or `"#chan key"`.
    #[serde(default)]
    channels: Vec<String>,
    /// Treat NOTICEs from users as messages (off: bots must never answer NOTICEs automatically).
    #[serde(default)]
    accept_notices: bool,
    #[serde(default = "d_chars")]
    max_chars: usize,
    #[serde(default = "d_burst")]
    flood_burst: u32,
    #[serde(default = "d_interval")]
    flood_interval_ms: u64,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    #[serde(default = "d_connect")]
    connect_timeout_secs: u64,
    /// `"nick"` (default) or `"account"`: with the server's `account-tag`, the
    /// sender is the services account; logged-out users become `?nick`.
    #[serde(default)]
    sender_identity: Option<String>,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let mut c = Cfg::new(st.host.trim(), st.port.unwrap_or(if st.tls { 6697 } else { 6667 }), st.tls, st.nick.trim());
    if let Some(u) = st.username.filter(|u| !u.trim().is_empty()) {
        c.username = u.trim().to_string();
    }
    if let Some(r) = st.realname {
        c.realname = r;
    }
    c.password = ctx.opt_secret("password", &st.password)?;
    if let Some(p) = ctx.opt_secret("sasl_password", &st.sasl_password)? {
        c.sasl = Some((st.sasl_username.unwrap_or_else(|| c.nick.clone()), p));
    }
    if let Some(p) = ctx.opt_secret("nickserv_password", &st.nickserv_password)? {
        if st.nickserv_register && st.nickserv_register_email.as_deref().is_none_or(|e| e.trim().is_empty()) {
            return Err(format!("channel {}: nickserv_register needs nickserv_register_email", ctx.name));
        }
        c.nickserv = Some(NickServ { password: p, service: st.nickserv_service.unwrap_or_else(|| "NickServ".into()), register_email: st.nickserv_register.then(|| st.nickserv_register_email.unwrap_or_default()) });
    }
    for ch in &st.channels {
        let mut it = ch.split_whitespace();
        let Some(name) = it.next() else { continue };
        c.channels.push((name.to_string(), it.next().map(str::to_string)));
    }
    c.accept_notices = st.accept_notices;
    c.max_chars = st.max_chars.max(16);
    c.flood_burst = st.flood_burst;
    c.flood_interval = Duration::from_millis(st.flood_interval_ms);
    c.connect_timeout = Duration::from_secs(st.connect_timeout_secs.max(1));
    c.sender_account = match st.sender_identity.as_deref().map(str::trim) {
        None | Some("nick") => false,
        Some("account") => true,
        Some(o) => return Err(format!("channel {}: sender_identity must be \"nick\" or \"account\", not {o:?}", ctx.name)),
    };
    Ok(Arc::new(Irc::start(ctx.name, c, st.poll_timeout_secs)?))
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::{TcpListener, TcpStream};

    /// One accepted client connection in the fake server.
    pub struct Peer {
        r: BufReader<TcpStream>,
        w: TcpStream,
        pub log: Arc<Mutex<Vec<String>>>,
    }

    impl Peer {
        pub fn line(&mut self) -> Option<String> {
            let mut s = String::new();
            match self.r.read_line(&mut s) {
                Ok(0) | Err(_) => None,
                Ok(_) => {
                    let s = s.trim_end_matches(['\r', '\n']).to_string();
                    self.log.lock().unwrap().push(s.clone());
                    Some(s)
                }
            }
        }
        /// Read lines until one starts with `prefix`.
        pub fn expect(&mut self, prefix: &str) -> String {
            loop {
                let l = self.line().unwrap_or_else(|| panic!("connection closed waiting for {prefix}"));
                if l.starts_with(prefix) {
                    return l;
                }
            }
        }
        pub fn send(&mut self, l: &str) {
            let _ = self.w.write_all(format!("{l}\r\n").as_bytes());
        }
    }

    /// Fake IRC server: `script(conn_index, peer)` runs per accepted connection.
    pub fn fake_irc(script: impl Fn(usize, &mut Peer) + Send + 'static) -> (u16, Arc<Mutex<Vec<String>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        std::thread::spawn(move || {
            for (n, s) in l.incoming().enumerate() {
                let Ok(s) = s else { continue };
                s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let mut p = Peer { r: BufReader::new(s.try_clone().unwrap()), w: s, log: log2.clone() };
                script(n, &mut p);
            }
        });
        (port, log)
    }

    fn cfg(port: u16) -> Cfg {
        let mut c = Cfg::new("127.0.0.1", port, false, "seagent");
        c.reconnect_base = Duration::from_millis(20);
        c.reconnect_max = Duration::from_millis(100);
        c.flood_interval = Duration::ZERO;
        c.send_wait = Duration::from_secs(5);
        c
    }

    fn poll_n(i: &Irc, n: usize) -> Vec<Inbound> {
        let mut got = Vec::new();
        let until = Instant::now() + Duration::from_secs(10);
        while got.len() < n && Instant::now() < until {
            got.extend(i.poll(&Cancel::new()).unwrap());
        }
        got
    }

    fn register(p: &mut Peer, nick: &str) {
        p.expect("USER ");
        p.send(&format!(":srv 001 {nick} :Welcome"));
    }

    #[test]
    fn parses_tags_prefix_params_and_trailing() {
        let l = parse_line("@time=2023-04-05T06:07:08.123Z;msgid=a\\sb\\:c;+draft/reply=x :amy!~a@host PRIVMSG #chan :hello :world\r\n").unwrap();
        assert_eq!(l.tag("msgid"), Some("a b;c"));
        assert_eq!((l.nick(), l.command.as_str(), l.param(0), l.last()), ("amy", "PRIVMSG", "#chan", "hello :world"));
        assert_eq!(parse_time(l.tag("time").unwrap()), Some(1680674828));
        let p = parse_line("ping  :abc").unwrap();
        assert_eq!((p.command.as_str(), p.prefix.as_deref(), p.params.clone()), ("PING", None, vec!["abc".to_string()]));
        assert_eq!(parse_line(":irc.example.net 001 seagent :Welcome").unwrap().nick(), "", "server prefix");
        assert_eq!(parse_line(":amy PRIVMSG seagent hi").unwrap().params, vec!["seagent", "hi"]);
        assert!(parse_line("").is_none() && parse_line(": X").is_none());
        assert_eq!(escape_tag("a b;c\\"), "a\\sb\\:c\\\\");
        assert_eq!(unescape_tag(&escape_tag("x; y\\z\n")), "x; y\\z\n");
        assert_eq!(strip_formatting("\x02bold\x02 \x0304,12red\x03 \x1ditalic\x0f"), "bold red italic");
        assert_eq!(parse_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_time("bogus"), None);
    }

    #[test]
    fn mentions_targets_and_splitting() {
        assert!(mentions("seagent: hi", "seagent") && mentions("hey SEAGENT, do it", "seagent") && mentions("ping (seagent)", "seagent"));
        assert!(!mentions("arkansas", "seagent") && !mentions("dark", "seagent") && !mentions("seagent_", "seagent"));
        assert!(mentions("yo {bot}", "[bot]"), "RFC 1459 case mapping");
        assert_eq!(strip_address("Seagent: do it", "seagent"), "do it");
        assert_eq!(normalize_target("irc:channel:ops").as_deref(), Some("#ops"));
        assert_eq!(normalize_target("user:amy").as_deref(), Some("amy"));
        assert!(normalize_target("a b").is_none() && normalize_target(":x").is_none() && normalize_target("#a,#b").is_none() && normalize_target("x\r\nQUIT").is_none());
        let s = "é".repeat(100);
        let parts = split_text(&s, 31, 1000);
        assert!(parts.iter().all(|p| p.len() <= 31 && p.len() % 2 == 0));
        assert_eq!(parts.concat(), s);
        let words = split_text("aaaa bbbb cccc", 10, 1000);
        assert_eq!(words, vec!["aaaa bbbb", "cccc"]);
        assert_eq!(split_text("abcdef", 100, 4), vec!["abcd", "ef"]);
        assert_eq!(sanitize_text("a\x01b\rc\td"), "abc d");
    }

    #[test]
    fn flood_limiter_spaces_out_lines() {
        let f = Flood::new(2, Duration::from_millis(60));
        let t = Instant::now();
        for _ in 0..5 {
            assert!(f.take(&Cancel::new()));
        }
        assert!(t.elapsed() >= Duration::from_millis(170), "{:?}", t.elapsed());
        let c = Cancel::new();
        c.cancel();
        let f = Flood::new(1, Duration::from_secs(10));
        assert!(f.take(&c));
        assert!(!f.take(&c), "cancel interrupts the wait");
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_millis(1000));
        let d: Vec<Duration> = (0..6).map(|_| b.next_delay()).collect();
        assert!(d[0] <= Duration::from_millis(120) && d[3] >= Duration::from_millis(640) && d[5] <= Duration::from_millis(1200));
        b.reset();
        assert!(b.next_delay() <= Duration::from_millis(120));
    }

    #[test]
    fn sasl_registration_nickserv_joins_ping_and_inbound_kinds() {
        let (port, log) = fake_irc(|_, p| {
            assert_eq!(p.expect("CAP "), "CAP LS 302");
            assert_eq!(p.line().unwrap(), "PASS :two words");
            assert_eq!(p.line().unwrap(), "NICK seagent");
            assert_eq!(p.line().unwrap(), "USER seagentuser 0 * :Seagent Bot");
            p.send(":srv CAP * LS * :multi-prefix sasl=PLAIN,EXTERNAL");
            p.send(":srv CAP * LS :server-time message-tags away-notify");
            assert_eq!(p.expect("CAP REQ"), "CAP REQ :sasl server-time message-tags");
            p.send(":srv CAP * ACK :sasl server-time message-tags");
            assert_eq!(p.expect("AUTHENTICATE"), "AUTHENTICATE PLAIN");
            p.send("AUTHENTICATE +");
            let a = p.expect("AUTHENTICATE ");
            assert_eq!(seagent_net::crypto::b64_decode(&a["AUTHENTICATE ".len()..]).unwrap(), b"acct\0acct\0s3cret");
            p.send(":srv 900 seagent seagent!a@h acct :You are now logged in");
            p.send(":srv 903 seagent :SASL successful");
            assert_eq!(p.expect("CAP END"), "CAP END");
            p.send(":srv 001 seagent :Welcome");
            assert_eq!(p.expect("PRIVMSG NickServ"), "PRIVMSG NickServ :IDENTIFY nspw");
            assert_eq!(p.expect("JOIN"), "JOIN #a key1");
            assert_eq!(p.expect("JOIN"), "JOIN #b");
            p.send("PING :tok123");
            assert_eq!(p.expect("PONG"), "PONG :tok123");
            p.send("@time=2023-04-05T06:07:08.000Z;msgid=m1 :amy!~a@h PRIVMSG #a :seagent: summarize this");
            p.send(":amy!~a@h PRIVMSG #a :just chatting about arkansas");
            p.send(":bob!~b@h PRIVMSG seagent :private hello");
            p.send(":amy!~a@h PRIVMSG #a :\x01ACTION waves at seagent\x01");
            p.send(":amy!~a@h PRIVMSG seagent :\x01VERSION\x01");
            p.send(":seagent!~me@h PRIVMSG #a :my own echo");
            p.send(":amy!~a@h NOTICE #a :a notice");
            p.send(":srv NOTICE * :*** server notice");
            p.send("@+draft/reply=m0;bot :helper!~h@h PRIVMSG #a :\x02bold\x02 reply");
            p.expect("QUIT");
        });
        let mut c = cfg(port);
        c.password = Some("two words".into());
        c.username = "seagentuser".into();
        c.realname = "Seagent Bot".into();
        c.sasl = Some(("acct".into(), "s3cret".into()));
        c.nickserv = Some(NickServ { password: "nspw".into(), service: "NickServ".into(), register_email: None });
        c.channels = vec![("#a".into(), Some("key1".into())), ("#b".into(), None)];
        let irc = Irc::start("irc", c, 1).unwrap();
        let g = poll_n(&irc, 5);
        assert_eq!(g.len(), 5, "{g:?}");
        assert_eq!((g[0].chat.as_str(), g[0].chat_type, g[0].sender.as_str(), g[0].text.as_str(), g[0].message_id.as_str(), g[0].ts), ("#a", ChatType::Group, "amy", "summarize this", "m1", 1680674828));
        assert!(g[0].mentioned);
        assert!(!g[1].mentioned && !g[1].message_id.is_empty() && g[1].message_id != g[2].message_id);
        assert_eq!((g[2].chat.as_str(), g[2].chat_type, g[2].text.as_str()), ("bob", ChatType::Direct, "private hello"));
        assert!(g[2].addressed());
        assert_eq!(g[3].text, "* amy waves at seagent");
        assert!(g[3].mentioned);
        assert_eq!((g[4].text.as_str(), g[4].is_bot, g[4].reply.as_ref().map(|r| r.id.as_str())), ("bold reply", true, Some("m0")));
        assert!(irc.caps().reply, "message-tags acked");
        irc.stop();
        std::thread::sleep(Duration::from_millis(300));
        assert!(log.lock().unwrap().iter().any(|l| l.starts_with("QUIT")));
    }

    #[test]
    fn nick_collision_falls_back_and_tracks_nick() {
        let (port, _log) = fake_irc(|_, p| {
            p.expect("USER");
            p.send(":srv 433 * seagent :Nickname is already in use");
            assert_eq!(p.expect("NICK"), "NICK seagent_");
            p.send(":srv 433 * seagent_ :Nickname is already in use");
            assert_eq!(p.expect("NICK"), "NICK seagent_2");
            p.send(":srv 001 seagent_2 :Welcome");
            p.send(":amy!a@h PRIVMSG #x :seagent_2, hello");
            p.send(":seagent_2!a@h NICK :seagent");
            p.send(":amy!a@h PRIVMSG #x :seagent: again");
            p.expect("QUIT");
        });
        let irc = Irc::start("irc", cfg(port), 1).unwrap();
        let g = poll_n(&irc, 2);
        assert!(g[0].mentioned && g[0].text == "hello", "{g:?}");
        assert!(g[1].mentioned && g[1].text == "again");
        assert_eq!(irc.current_nick(), "seagent");
    }

    #[test]
    fn nickserv_ghost_then_register() {
        let (port, _log) = fake_irc(|_, p| {
            p.expect("USER");
            p.send(":srv 433 * seagent :in use");
            assert_eq!(p.expect("PRIVMSG"), "PRIVMSG NickServ :GHOST seagent pw");
            assert_eq!(p.expect("NICK"), "NICK seagent");
            p.send(":srv 001 seagent :Welcome");
            assert_eq!(p.expect("PRIVMSG"), "PRIVMSG NickServ :IDENTIFY pw");
            assert_eq!(p.expect("PRIVMSG"), "PRIVMSG NickServ :REGISTER pw me@example.com");
            p.send(":amy!a@h PRIVMSG seagent :done");
            p.expect("QUIT");
        });
        let mut c = cfg(port);
        c.nickserv = Some(NickServ { password: "pw".into(), service: "NickServ".into(), register_email: Some("me@example.com".into()) });
        let irc = Irc::start("irc", c, 1).unwrap();
        assert_eq!(poll_n(&irc, 1)[0].text, "done");
    }

    #[test]
    fn send_splits_on_utf8_boundaries_with_tags_media_buttons_and_notice() {
        let (port, log) = fake_irc(|_, p| {
            p.expect("USER");
            p.send(":srv CAP * LS :message-tags");
            p.expect("CAP REQ");
            p.send(":srv CAP * ACK :message-tags");
            p.expect("CAP END");
            p.send(":srv 001 seagent :Welcome");
            while p.line().is_some() {}
        });
        let mut c = cfg(port);
        c.max_chars = 10_000;
        let irc = Irc::start("irc", c, 1).unwrap();
        let long = format!("**粗體** {}", "測試文字".repeat(80));
        let out = Outbound {
            format: TextFormat::Markdown,
            reply_to: Some("m 1".into()),
            media: vec![crate::Media { url: Some("https://e.com/a.png".into()), name: "a.png".into(), ..Default::default() }],
            buttons: vec![vec![crate::Button { label: "Yes".into(), data: "y".into(), url: None }, crate::Button { label: "No".into(), data: "n".into(), url: None }]],
            ..Outbound::text("#chan", &long)
        };
        // Wait for message-tags to be acked so the reply tag path is exercised.
        let until = Instant::now() + Duration::from_secs(5);
        while !irc.caps().reply && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        let s = irc.send(&out).unwrap();
        let s2 = irc.send(&Outbound { reply_to: Some("abc".into()), silent: true, ..Outbound::text("bob", "line one\nline two") }).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let lines: Vec<String> = log.lock().unwrap().iter().filter(|l| l.contains("PRIVMSG #chan") || l.contains("NOTICE bob")).cloned().collect();
        assert_eq!(lines.len(), s.ids.len() + s2.ids.len(), "{lines:?}");
        let chan: Vec<&String> = lines.iter().filter(|l| l.contains("#chan")).collect();
        assert!(chan.len() >= 3);
        let relay = ":seagent!~1234567890@".len() + RELAY_HOST + 1;
        let mut text = String::new();
        for l in &chan {
            assert!(l.len() + 2 + relay <= MAX_LINE, "relayed line over 512 bytes: {}", l.len());
            let body = l.split_once("PRIVMSG #chan :").unwrap().1;
            text.push_str(body);
        }
        assert!(!chan[0].starts_with('@'), "reply ids with spaces are not tagged");
        assert!(text.starts_with("粗體 測試文字") && text.contains("a.png: https://e.com/a.png") && text.contains("1. Yes") && text.contains("2. No"), "{text}");
        assert_eq!(text.matches("測試文字").count(), 80, "nothing lost at split points");
        let dm: Vec<&String> = lines.iter().filter(|l| l.contains("NOTICE bob")).collect();
        assert_eq!(dm, vec!["@+draft/reply=abc NOTICE bob :line one", "NOTICE bob :line two"]);
        let path_only = Outbound { media: vec![crate::Media { path: Some("/tmp/x".into()), ..Default::default() }], ..Outbound::text("#chan", "x") };
        assert_eq!(irc.send(&path_only).unwrap_err().kind, K::Unsupported);
        assert_eq!(irc.send(&Outbound::text("bad target", "x")).unwrap_err().kind, K::Protocol);
    }

    #[test]
    fn echo_message_confirms_sends_and_account_tag_names_senders() {
        let (port, log) = fake_irc(|_, p| {
            p.expect("USER");
            p.send(":srv CAP * LS :message-tags echo-message account-tag");
            assert_eq!(p.expect("CAP REQ"), "CAP REQ :message-tags echo-message account-tag");
            p.send(":srv CAP * ACK :message-tags echo-message account-tag");
            p.expect("CAP END");
            p.send(":srv 001 seagent :Welcome");
            p.send("@account=amy_acct;msgid=x1 :amy!a@h PRIVMSG #c :hi seagent");
            p.send("@account=* :mallory!m@h PRIVMSG #c :seagent: i am amy_acct");
            let a = p.expect("PRIVMSG #c");
            let b = p.expect("PRIVMSG #c");
            // Echoes (out of order is fine); our own lines never come back as inbound.
            p.send(&format!("@msgid=e2 :seagent!a@h {}", b));
            p.send(&format!("@msgid=e1;account=seagent :seagent!a@h {}", a));
            assert!(p.expect("PRIVMSG #shut").contains("blocked"));
            p.send(":srv 404 seagent #shut :Cannot send to channel");
            assert!(p.expect("PRIVMSG bob").contains("quiet"));
            while p.line().is_some() {}
        });
        let mut c = cfg(port);
        c.sender_account = true;
        c.echo_wait = Duration::from_millis(400);
        let irc = Irc::start("irc", c, 1).unwrap();
        let g = poll_n(&irc, 2);
        assert_eq!((g[0].sender.as_str(), g[0].sender_name.as_str()), ("amy_acct", "amy"));
        assert_eq!((g[1].sender.as_str(), g[1].sender_name.as_str()), ("?mallory", "mallory"), "logged out cannot pose as an account");
        let s = irc.send(&Outbound::text("#c", "one\ntwo")).unwrap();
        assert_eq!(s.ids, vec!["e1", "e2"]);
        assert_eq!(irc.send(&Outbound::text("#shut", "blocked")).unwrap_err().kind, K::NotFound);
        let t = Instant::now();
        let s = irc.send(&Outbound::text("bob", "quiet")).unwrap();
        assert!(s.ids[0].starts_with("irc:") && t.elapsed() >= Duration::from_millis(350), "no echo: local id after echo_wait");
        assert!(irc.sh.echo.lock().unwrap().is_empty());
        std::thread::sleep(Duration::from_millis(100));
        assert!(irc.poll(&Cancel::new()).unwrap().is_empty(), "echoes are not inbound");
        assert_eq!(log.lock().unwrap().iter().filter(|l| l.starts_with("PRIVMSG #c")).count(), 2);
    }

    #[test]
    fn flood_control_applies_to_sends() {
        let (port, log) = fake_irc(|_, p| {
            register(p, "seagent");
            while p.line().is_some() {}
        });
        let mut c = cfg(port);
        c.flood_burst = 2;
        c.flood_interval = Duration::from_millis(80);
        let irc = Irc::start("irc", c, 1).unwrap();
        let t = Instant::now();
        let s = irc.send(&Outbound::text("#c", "1\n2\n3\n4\n5")).unwrap();
        assert_eq!(s.ids.len(), 5);
        assert!(t.elapsed() >= Duration::from_millis(230), "{:?}", t.elapsed());
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(log.lock().unwrap().iter().filter(|l| l.starts_with("PRIVMSG #c")).count(), 5);
    }

    #[test]
    fn login_and_sasl_failures_are_auth_errors() {
        let (port, _) = fake_irc(|_, p| {
            p.expect("USER");
            p.send(":srv 464 * :Password incorrect");
        });
        let irc = Irc::start("irc", cfg(port), 2).unwrap();
        assert_eq!(irc.poll(&Cancel::new()).unwrap_err().kind, K::Auth);
        assert_eq!(irc.send(&Outbound::text("#c", "x")).unwrap_err().kind, K::Auth);
        let (port, _) = fake_irc(|_, p| {
            p.expect("USER");
            p.send(":srv CAP * LS :sasl");
            p.expect("CAP REQ");
            p.send(":srv CAP * ACK :sasl");
            p.expect("AUTHENTICATE");
            p.send("AUTHENTICATE +");
            p.expect("AUTHENTICATE ");
            p.send(":srv 904 * :SASL authentication failed");
            let _ = p.line();
        });
        let mut c = cfg(port);
        c.sasl = Some(("a".into(), "wrong".into()));
        let irc = Irc::start("irc", c, 2).unwrap();
        let e = irc.poll(&Cancel::new()).unwrap_err();
        assert!(e.kind == K::Auth && !e.message.contains("wrong"), "{e:?}");
        let (port, _) = fake_irc(|_, p| {
            p.expect("USER");
            p.send(":srv CAP * LS :multi-prefix");
            let _ = p.line();
        });
        let mut c = cfg(port);
        c.sasl = Some(("a".into(), "b".into()));
        assert_eq!(Irc::start("irc", c, 2).unwrap().poll(&Cancel::new()).unwrap_err().kind, K::Auth, "SASL required but not offered");
    }

    #[test]
    fn reconnects_after_drop_and_marks_gone_targets() {
        let (port, log) = fake_irc(|n, p| {
            register(p, "seagent");
            if n == 0 {
                return; // drop the connection right after registration
            }
            p.send(":amy!a@h PRIVMSG seagent :after reconnect");
            assert!(p.expect("PRIVMSG #gone").contains("first"));
            p.send(":srv 404 seagent #gone :Cannot send to channel");
            p.send(":srv 401 seagent nobody :No such nick");
            while p.line().is_some() {}
        });
        let irc = Irc::start("irc", cfg(port), 1).unwrap();
        let g = poll_n(&irc, 1);
        assert_eq!(g[0].text, "after reconnect");
        assert_eq!(log.lock().unwrap().iter().filter(|l| l.starts_with("NICK")).count(), 2, "registered twice");
        irc.send(&Outbound::text("#gone", "first")).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(irc.send(&Outbound::text("#gone", "second")).unwrap_err().kind, K::NotFound);
        assert_eq!(irc.send(&Outbound::text("NOBODY", "x")).unwrap_err().kind, K::NotFound, "case-insensitive");
    }

    #[test]
    fn poll_honours_cancel_and_send_fails_when_disconnected() {
        let (port, _) = fake_irc(|_, p| {
            register(p, "seagent");
            while p.line().is_some() {}
        });
        let irc = Irc::start("irc", cfg(port), 30).unwrap();
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            c2.cancel();
        });
        let t = Instant::now();
        assert!(irc.poll(&c).unwrap().is_empty());
        assert!(t.elapsed() < Duration::from_millis(400), "{:?}", t.elapsed());
        // Nothing listens here: send gives up with a retryable Network error.
        let free = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let mut c = cfg(free);
        c.send_wait = Duration::from_millis(200);
        let dead = Irc::start("irc", c, 1).unwrap();
        let e = dead.send(&Outbound::text("#c", "x")).unwrap_err();
        assert!(e.is_retryable(), "{e:?}");
    }

    #[test]
    fn build_parses_settings() {
        let d = crate::testutil::temp_dir("irc");
        let secrets: crate::config::Secrets = Arc::new(|s: &str| s.replace("{{secret:NS}}", "pw"));
        let ctx = crate::config::Ctx { name: "irc", state_dir: &d, secrets: &secrets };
        let ok = serde_json::json!({"host": "127.0.0.1", "port": 1, "tls": false, "nick": "seagent", "channels": ["#a key", "#b"], "nickserv_password": "{{secret:NS}}"});
        assert!(build(&ctx, ok.as_object().unwrap()).is_ok());
        let typo = serde_json::json!({"host": "h", "nick": "seagent", "chanels": []});
        assert!(build(&ctx, typo.as_object().unwrap()).err().unwrap().contains("chanels"));
        let bad = serde_json::json!({"host": "h", "nick": "seagent", "channels": ["nochan"]});
        assert!(build(&ctx, bad.as_object().unwrap()).is_err());
        let reg = serde_json::json!({"host": "h", "nick": "seagent", "nickserv_password": "x", "nickserv_register": true});
        assert!(build(&ctx, reg.as_object().unwrap()).err().unwrap().contains("email"));
        let missing = serde_json::json!({"host": "h", "nick": "seagent", "sasl_password": "{{secret:NOPE}}"});
        assert!(build(&ctx, missing.as_object().unwrap()).err().unwrap().contains("not set"));
        let ident = serde_json::json!({"host": "h", "nick": "seagent", "sender_identity": "host"});
        assert!(build(&ctx, ident.as_object().unwrap()).err().unwrap().contains("sender_identity"));
    }
}
