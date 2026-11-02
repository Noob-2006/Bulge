//! Email over IMAP + SMTP (ported from Hermes `plugins/platforms/email`, MIT).
//!
//! Receive: IMAP over implicit TLS (993), STARTTLS (143) or plain (tests / local
//! bridges). LOGIN, SELECT, then `UID SEARCH UNSEEN UID <last+1>:*`; the cursor
//! (UIDVALIDITY + last UID) is persisted and committed only on the next poll
//! (at-least-once, like Telegram's offset), together with `\Seen`. Waits with IDLE
//! when the server offers it, else polls every `poll_interval_secs`. Headers are
//! fetched first (`BODY.PEEK[HEADER]`, bounded) so automated, own, unauthenticated
//! or oversized mail is consumed without downloading its body.
//! Sender authentication follows Hermes: only the topmost Authentication-Results
//! header counts, its authserv-id must equal `authserv_id`, and the From domain
//! needs DMARC pass, aligned SPF pass or aligned DKIM pass.
//! Sends the RFC 2971 ID (`name "ark"`) when offered (NetEase 163/126 refuse SELECT
//! without it); the mailbox name goes out in RFC 3501 modified UTF-7 (`收件匣` → `&ZTZO9lMj-`).
//! MIME: multipart trees, quoted-printable, base64, RFC 2047 encoded words (adjacent words
//! joined before decoding, so split multi-byte characters survive), RFC 2231 parameters,
//! every WHATWG charset (Big5/HKSCS, GBK/gb18030, Shift_JIS, EUC-JP, ISO-2022-JP, EUC-KR,
//! single-byte, UTF-16; see `charset`), raw 8-bit header bytes in the part's charset;
//! attachments are saved under the state dir and delivered as `Media` with a path.
//! Quoted replies and signatures are stripped. Thread = root Message-ID.
//! Send: SMTP over implicit TLS (465), STARTTLS (587) or plain; EHLO, AUTH PLAIN /
//! LOGIN, MAIL/RCPT/DATA with dot-stuffing; threaded headers (In-Reply-To,
//! References, "Re:" subject); Markdown becomes multipart/alternative; local files
//! are attached (multipart/mixed, base64), URLs become links.

use crate::{chunk, markup, sleep_cancellable, write_atomic, Caps, Channel, ChannelError, ChannelErrorKind as K, ChatType, Inbound, LenUnit, Markup, Media, MediaKind, Outbound, ReplyRef, Sent, Streaming, TextFormat};
use ark_core::Cancel;
use ark_net::crypto;
use ark_net::stream::{is_timeout, Stream};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// One email carries a long body; Hermes caps at 50 000 characters.
pub const MAX_MESSAGE: usize = 50_000;
/// Header preflight limit (Hermes `_MAX_PREAUTH_HEADER_BYTES`).
const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Messages handled per poll; the rest wait for the next one.
const BATCH: usize = 50;
const READ_SLICE: Duration = Duration::from_millis(100);

const NOREPLY_PATTERNS: [&str; 13] = ["noreply", "no-reply", "no_reply", "donotreply", "do-not-reply", "mailer-daemon", "postmaster", "bounce", "notifications@", "automated@", "auto-confirm", "auto-reply", "automailer"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    /// Implicit TLS (IMAPS 993, SMTPS 465).
    Tls,
    StartTls,
    /// No TLS at all: loopback bridges and tests.
    Plain,
}

impl Security {
    fn parse(s: Option<&str>) -> Result<Option<Security>, String> {
        let Some(s) = s else { return Ok(None) };
        match s.trim().to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "" => Ok(None),
            "tls" | "ssl" | "implicit" => Ok(Some(Security::Tls)),
            "starttls" => Ok(Some(Security::StartTls)),
            "plain" | "none" => Ok(Some(Security::Plain)),
            other => Err(format!("unknown security mode `{other}` (tls, starttls, plain)")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub address: String,
    pub username: String,
    pub password: String,
    pub from_name: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_security: Security,
    pub smtp_host: Option<String>,
    pub smtp_port: u16,
    pub smtp_security: Security,
    pub mailbox: String,
    pub poll_timeout: Duration,
    pub poll_interval: Duration,
    pub idle: bool,
    pub timeout: Duration,
    /// Lowercased; empty = none configured.
    pub authserv_id: String,
    pub require_authenticated_sender: bool,
    pub skip_attachments: bool,
    pub skip_existing: bool,
    pub unseen_only: bool,
    pub strip_quotes: bool,
    pub max_attachment_bytes: u64,
    pub max_message_bytes: u64,
    pub subject: String,
}

impl Config {
    /// Sensible defaults for `address` on `host` (implicit TLS both ways).
    pub fn new(address: &str, password: &str, host: &str) -> Config {
        Config {
            address: address.to_string(),
            username: address.to_string(),
            password: password.to_string(),
            from_name: String::new(),
            imap_host: host.to_string(),
            imap_port: 993,
            imap_security: Security::Tls,
            smtp_host: Some(host.to_string()),
            smtp_port: 587,
            smtp_security: Security::StartTls,
            mailbox: "INBOX".into(),
            poll_timeout: Duration::from_secs(25),
            poll_interval: Duration::from_secs(15),
            idle: true,
            timeout: Duration::from_secs(30),
            authserv_id: String::new(),
            require_authenticated_sender: true,
            skip_attachments: false,
            skip_existing: true,
            unseen_only: true,
            strip_quotes: true,
            max_attachment_bytes: 25 * 1024 * 1024,
            max_message_bytes: 40 * 1024 * 1024,
            subject: "ark".into(),
        }
    }
}

/// Persisted cursor plus the batch handed out by the last poll (committed on the next).
#[derive(Default)]
struct Cursor {
    validity: u64,
    last_uid: u64,
    pending: Vec<u64>,
    pending_last: Option<u64>,
}

/// What a reply needs to thread under a message.
#[derive(Clone, Default)]
struct ThreadCtx {
    subject: String,
    /// References chain ending with the message's own id.
    refs: Vec<String>,
}

#[derive(Default)]
struct Threads {
    by_id: HashMap<String, ThreadCtx>,
    order: VecDeque<String>,
    /// Latest message per correspondent (chat = address).
    last: HashMap<String, String>,
}

impl Threads {
    fn put(&mut self, chat: &str, id: &str, ctx: ThreadCtx) {
        if !self.by_id.contains_key(id) {
            self.order.push_back(id.to_string());
        }
        self.by_id.insert(id.to_string(), ctx);
        self.last.insert(chat.to_string(), id.to_string());
        while self.order.len() > 2000 {
            if let Some(old) = self.order.pop_front() {
                self.by_id.remove(&old);
            }
        }
    }
}

pub struct Email {
    id: String,
    cfg: Config,
    state: PathBuf,
    media_dir: PathBuf,
    imap: Mutex<Option<Imap>>,
    cursor: Mutex<Cursor>,
    threads: Mutex<Threads>,
    /// (consecutive failures, earliest next connect).
    backoff: Mutex<(u32, Option<Instant>)>,
    /// First reconnect delay; doubles per failure up to `max_backoff`.
    pub retry_base: Duration,
    pub max_backoff: Duration,
}

/// Internal error: cancellation is not a failure.
enum E {
    Cancelled,
    Err(ChannelError),
}

impl From<ChannelError> for E {
    fn from(e: ChannelError) -> E {
        E::Err(e)
    }
}

type R<T> = Result<T, E>;

fn net(what: &str, e: impl std::fmt::Display) -> E {
    E::Err(ChannelError::new(K::Network, format!("{what}: {e}")))
}

fn err(kind: K, msg: impl Into<String>) -> E {
    E::Err(ChannelError::new(kind, msg))
}

/// Stream::connect on a helper thread so a black-holed host cannot delay cancel.
fn connect_stream(host: &str, port: u16, tls: bool, timeout: Duration, cancel: &Cancel) -> R<Stream> {
    let (tx, rx) = std::sync::mpsc::channel();
    let h = host.to_string();
    std::thread::spawn(move || {
        let _ = tx.send(Stream::connect(&h, port, tls, timeout));
    });
    loop {
        match rx.recv_timeout(Duration::from_millis(25)) {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => return Err(net(&format!("connect {host}:{port}"), e)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) if cancel.is_cancelled() => return Err(E::Cancelled),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Err(net("connect", "worker died")),
        }
    }
}

// ---------------------------------------------------------------- line reader

/// A response line, with IMAP literals (`{n}\r\n<n bytes>`) collected separately.
#[derive(Debug, Clone, Default)]
struct Resp {
    text: String,
    lits: Vec<Vec<u8>>,
}

struct Conn {
    s: Stream,
    buf: Vec<u8>,
    /// Parse `{n}` literals (IMAP) or not (SMTP).
    literals: bool,
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn literal_len(line: &[u8]) -> Option<usize> {
    let l = line.strip_suffix(b"}")?;
    let open = l.iter().rposition(|&c| c == b'{')?;
    let n = std::str::from_utf8(&l[open + 1..]).ok()?.trim_end_matches('+');
    n.parse().ok()
}

impl Conn {
    fn new(s: Stream, literals: bool) -> Conn {
        let _ = s.set_read_timeout(Some(READ_SLICE));
        Conn { s, buf: Vec::new(), literals }
    }

    fn write(&mut self, b: &[u8]) -> R<()> {
        self.s.write_all(b).and_then(|_| self.s.flush()).map_err(|e| net("write", e))
    }

    fn take(&mut self) -> Option<Resp> {
        let mut pos = 0;
        let mut r = Resp::default();
        loop {
            let rel = find(&self.buf[pos..], b"\r\n")?;
            let line = &self.buf[pos..pos + rel];
            let after = pos + rel + 2;
            match literal_len(line).filter(|_| self.literals) {
                Some(n) => {
                    if self.buf.len() < after + n {
                        return None;
                    }
                    r.text.push_str(&String::from_utf8_lossy(line));
                    r.lits.push(self.buf[after..after + n].to_vec());
                    pos = after + n;
                }
                None => {
                    r.text.push_str(&String::from_utf8_lossy(line));
                    self.buf.drain(..after);
                    return Some(r);
                }
            }
        }
    }

    /// A complete response, or `None` when the read slice passes first.
    fn try_resp(&mut self) -> io::Result<Option<Resp>> {
        let mut chunk = [0u8; 16 * 1024];
        loop {
            if let Some(r) = self.take() {
                return Ok(Some(r));
            }
            match self.s.read(&mut chunk) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed by server")),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if is_timeout(&e) => return Ok(None),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    fn resp(&mut self, cancel: &Cancel, timeout: Duration) -> R<Resp> {
        let until = Instant::now() + timeout;
        loop {
            match self.try_resp() {
                Ok(Some(r)) => return Ok(r),
                Ok(None) if cancel.is_cancelled() => return Err(E::Cancelled),
                Ok(None) if Instant::now() >= until => return Err(net("read", "server did not answer in time")),
                Ok(None) => {}
                Err(e) => return Err(net("read", e)),
            }
        }
    }
}

// ---------------------------------------------------------------- IMAP client

struct Imap {
    c: Conn,
    tag: u32,
    caps: Vec<String>,
    timeout: Duration,
    validity: u64,
    uidnext: u64,
}

fn quotable(s: &str) -> bool {
    s.bytes().all(|b| (0x20..0x7f).contains(&b))
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// RFC 3501 §5.1.3 modified UTF-7: printable ASCII stands for itself, `&` is `&-`, the rest
/// is UTF-16 in base64 (`,` for `/`, no padding) between `&` and `-`.
pub fn imap_utf7_encode(s: &str) -> String {
    let mut out = String::new();
    let mut run: Vec<u16> = Vec::new();
    let flush = |run: &mut Vec<u16>, out: &mut String| {
        if !run.is_empty() {
            let b: Vec<u8> = run.drain(..).flat_map(u16::to_be_bytes).collect();
            out.push_str(&format!("&{}-", crypto::b64(&b).trim_end_matches('=').replace('/', ",")));
        }
    };
    for c in s.chars() {
        if (' '..='~').contains(&c) {
            flush(&mut run, &mut out);
            if c == '&' {
                out.push_str("&-");
            } else {
                out.push(c);
            }
        } else {
            run.extend(c.encode_utf16(&mut [0; 2]).iter());
        }
    }
    flush(&mut run, &mut out);
    out
}

/// Strict inverse of `imap_utf7_encode`; None when `s` is not valid modified UTF-7.
pub fn imap_utf7_decode(s: &str) -> Option<String> {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let (b64, tail) = rest[i + 1..].split_once('-')?;
        rest = tail;
        if b64.is_empty() {
            out.push('&');
            continue;
        }
        let (mut acc, mut bits, mut units) = (0u32, 0, Vec::new());
        for c in b64.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b',' => 63,
                _ => return None,
            };
            (acc, bits) = (acc << 6 | v as u32, bits + 6);
            if bits >= 16 {
                bits -= 16;
                units.push((acc >> bits) as u16);
                acc &= (1 << bits) - 1;
            }
        }
        if bits >= 6 || acc != 0 {
            return None;
        }
        out.push_str(&String::from_utf16(&units).ok()?);
    }
    (s.bytes().all(|b| (0x20..0x7f).contains(&b))).then(|| out + rest)
}

/// The configured mailbox on the wire; a name already in modified UTF-7 is kept.
fn imap_mailbox(name: &str) -> String {
    if name.contains('&') && imap_utf7_decode(name).is_some() {
        return name.to_string();
    }
    imap_utf7_encode(name)
}

/// `[CODE n]` → n.
fn code_num(text: &str, code: &str) -> Option<u64> {
    let i = text.to_ascii_uppercase().find(&format!("[{code} "))?;
    text[i + code.len() + 2..].split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}

fn caps_of(text: &str) -> Vec<String> {
    text.split_whitespace().map(|w| w.trim_matches(['[', ']']).to_ascii_uppercase()).collect()
}

/// `UID 5`, `RFC822.SIZE 9` → numbers inside a FETCH response.
fn fetch_num(text: &str, key: &str) -> Option<u64> {
    let up = text.to_ascii_uppercase();
    let mut from = 0;
    while let Some(i) = up[from..].find(key) {
        let at = from + i;
        let before_ok = at == 0 || matches!(up.as_bytes()[at - 1], b'(' | b' ');
        let rest = &up[at + key.len()..];
        if before_ok && rest.starts_with(' ') {
            return rest[1..].split(|c: char| !c.is_ascii_digit()).next()?.parse().ok();
        }
        from = at + key.len();
    }
    None
}

/// The data of a one-item FETCH: a literal, or a quoted string, or NIL.
fn fetch_data(r: &Resp, item: &str) -> Option<Vec<u8>> {
    if let Some(l) = r.lits.first() {
        return Some(l.clone());
    }
    let up = r.text.to_ascii_uppercase();
    let i = up.find(item)?;
    let rest = r.text[i..].split_once(' ')?.1.trim_start();
    let body = rest.strip_prefix('"')?;
    let mut out = Vec::new();
    let mut esc = false;
    for b in body.bytes() {
        match (esc, b) {
            (false, b'\\') => esc = true,
            (false, b'"') => return Some(out),
            (_, b) => {
                out.push(b);
                esc = false;
            }
        }
    }
    None
}

impl Imap {
    fn has(&self, cap: &str) -> bool {
        self.caps.iter().any(|c| c == cap)
    }

    fn next_tag(&mut self) -> String {
        self.tag += 1;
        format!("a{}", self.tag)
    }

    /// Read until the tagged completion; returns (untagged, tagged rest e.g. "OK done").
    fn finish(&mut self, tag: &str, cancel: &Cancel) -> R<(Vec<Resp>, String)> {
        let mut untagged = Vec::new();
        let pre = format!("{tag} ");
        loop {
            let r = self.c.resp(cancel, self.timeout)?;
            if let Some(rest) = r.text.strip_prefix(&pre) {
                return Ok((untagged, rest.to_string()));
            }
            if r.text.len() >= 5 && r.text[..5].eq_ignore_ascii_case("* BYE") {
                return Err(net("imap", format!("server closed the session: {}", r.text.get(6..).unwrap_or(""))));
            }
            untagged.push(r);
        }
    }

    /// A command whose arguments are atoms already (no user data).
    fn run(&mut self, cmd: &str, cancel: &Cancel) -> R<(Vec<Resp>, String)> {
        let tag = self.next_tag();
        self.c.write(format!("{tag} {cmd}\r\n").as_bytes())?;
        self.finish(&tag, cancel)
    }

    /// A command with string arguments: quoted when safe, else synchronizing literals.
    fn run_args(&mut self, verb: &str, args: &[&str], cancel: &Cancel) -> R<(Vec<Resp>, String)> {
        let tag = self.next_tag();
        let mut line = format!("{tag} {verb}");
        for a in args {
            if quotable(a) {
                line.push(' ');
                line.push_str(&quote(a));
                continue;
            }
            line.push_str(&format!(" {{{}}}\r\n", a.len()));
            self.c.write(line.as_bytes())?;
            line.clear();
            let r = self.c.resp(cancel, self.timeout)?;
            if !r.text.starts_with('+') {
                return Ok((vec![], r.text.strip_prefix(&format!("{tag} ")).unwrap_or(&r.text).to_string()));
            }
            line.push_str(a);
        }
        line.push_str("\r\n");
        self.c.write(line.as_bytes())?;
        self.finish(&tag, cancel)
    }

    fn ok(what: &str, (u, status): (Vec<Resp>, String)) -> R<Vec<Resp>> {
        let up = status.to_ascii_uppercase();
        if up.starts_with("OK") {
            return Ok(u);
        }
        Err(err(K::Protocol, format!("IMAP {what}: {status}")))
    }

    fn cmd(&mut self, cmd: &str, cancel: &Cancel) -> R<Vec<Resp>> {
        let r = self.run(cmd, cancel)?;
        Self::ok(cmd.split(' ').take(2).collect::<Vec<_>>().join(" ").as_str(), r)
    }

    fn open(cfg: &Config, cancel: &Cancel) -> R<Imap> {
        let s = connect_stream(&cfg.imap_host, cfg.imap_port, cfg.imap_security == Security::Tls, cfg.timeout, cancel)?;
        let mut im = Imap { c: Conn::new(s, true), tag: 0, caps: vec![], timeout: cfg.timeout, validity: 0, uidnext: 0 };
        let greet = im.c.resp(cancel, cfg.timeout)?;
        let g = greet.text.to_ascii_uppercase();
        if g.starts_with("* BYE") {
            return Err(net("imap", format!("server refused the connection: {}", greet.text)));
        }
        let preauth = g.starts_with("* PREAUTH");
        if g.contains("[CAPABILITY ") {
            im.caps = caps_of(&greet.text);
        } else {
            im.refresh_caps(cancel)?;
        }
        if cfg.imap_security == Security::StartTls {
            if !im.has("STARTTLS") {
                return Err(err(K::Fatal, "IMAP server does not offer STARTTLS (set imap_security = \"tls\")"));
            }
            im.cmd("STARTTLS", cancel)?;
            if !im.c.buf.is_empty() {
                // Bytes sent before the handshake would be trusted as if encrypted (STARTTLS injection).
                return Err(err(K::Protocol, "IMAP server sent data after STARTTLS"));
            }
            let Imap { c, tag, timeout, .. } = im;
            let _ = c.s.set_read_timeout(Some(cfg.timeout));
            let s = c.s.starttls(&cfg.imap_host).map_err(|e| net("IMAP STARTTLS", e))?;
            im = Imap { c: Conn::new(s, true), tag, caps: vec![], timeout, validity: 0, uidnext: 0 };
            im.refresh_caps(cancel)?;
        }
        if !preauth {
            if im.has("LOGINDISABLED") {
                return Err(err(K::Fatal, "IMAP server disables LOGIN on this connection (use TLS or STARTTLS)"));
            }
            let (_, status) = im.run_args("LOGIN", &[&cfg.username, &cfg.password], cancel)?;
            let up = status.to_ascii_uppercase();
            if !up.starts_with("OK") {
                // Gmail answers NO for "too many connections" as well as for bad passwords.
                let transient = ["[UNAVAILABLE]", "[INUSE]", "TOO MANY", "TRY AGAIN"].iter().any(|t| up.contains(t));
                let kind = if transient { K::Network } else { K::Auth };
                return Err(err(kind, format!("IMAP login rejected for {}: {}", cfg.username, status.get(3..).unwrap_or(&status).trim())));
            }
            if up.contains("[CAPABILITY ") {
                im.caps = caps_of(&status);
            } else {
                im.refresh_caps(cancel)?;
            }
        }
        if im.has("ID") {
            // The answer and its status do not matter; only the connection must survive.
            im.run(&format!("ID (\"name\" \"ark\" \"version\" \"{}\")", env!("CARGO_PKG_VERSION")), cancel)?;
        }
        let (u, status) = im.run_args("SELECT", &[&imap_mailbox(&cfg.mailbox)], cancel)?;
        if !status.to_ascii_uppercase().starts_with("OK") {
            return Err(err(K::NotFound, format!("IMAP mailbox {} cannot be selected: {status}", cfg.mailbox)));
        }
        for r in &u {
            if let Some(v) = code_num(&r.text, "UIDVALIDITY") {
                im.validity = v;
            }
            if let Some(v) = code_num(&r.text, "UIDNEXT") {
                im.uidnext = v;
            }
        }
        Ok(im)
    }

    fn refresh_caps(&mut self, cancel: &Cancel) -> R<()> {
        let u = self.cmd("CAPABILITY", cancel)?;
        self.caps = u.iter().filter(|r| r.text.to_ascii_uppercase().starts_with("* CAPABILITY")).flat_map(|r| caps_of(&r.text)).collect();
        Ok(())
    }

    fn search(&mut self, query: &str, cancel: &Cancel) -> R<Vec<u64>> {
        let u = self.cmd(&format!("UID SEARCH {query}"), cancel)?;
        let mut out: Vec<u64> = u.iter().filter(|r| r.text.to_ascii_uppercase().starts_with("* SEARCH")).flat_map(|r| r.text[8..].split_whitespace().filter_map(|n| n.parse().ok()).collect::<Vec<u64>>()).collect();
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    /// uid → (RFC822.SIZE, header bytes) for each uid still present.
    fn fetch_headers(&mut self, uids: &[u64], cancel: &Cancel) -> R<HashMap<u64, (u64, Vec<u8>)>> {
        let set = uids.iter().map(u64::to_string).collect::<Vec<_>>().join(",");
        let u = self.cmd(&format!("UID FETCH {set} (UID RFC822.SIZE BODY.PEEK[HEADER]<0.{}>)", MAX_HEADER_BYTES + 1), cancel)?;
        let mut out = HashMap::new();
        for r in u.iter().filter(|r| r.text.to_ascii_uppercase().contains(" FETCH (")) {
            let (Some(uid), Some(data)) = (fetch_num(&r.text, "UID"), fetch_data(r, "BODY[HEADER]")) else { continue };
            out.insert(uid, (fetch_num(&r.text, "RFC822.SIZE").unwrap_or(0), data));
        }
        Ok(out)
    }

    fn fetch_body(&mut self, uid: u64, cancel: &Cancel) -> R<Option<Vec<u8>>> {
        let u = self.cmd(&format!("UID FETCH {uid} (UID BODY.PEEK[])"), cancel)?;
        Ok(u.iter().filter(|r| r.text.to_ascii_uppercase().contains(" FETCH (") && fetch_num(&r.text, "UID") == Some(uid)).find_map(|r| fetch_data(r, "BODY[]")))
    }

    fn mark_seen(&mut self, uids: &[u64], cancel: &Cancel) -> R<()> {
        if uids.is_empty() {
            return Ok(());
        }
        let set = uids.iter().map(u64::to_string).collect::<Vec<_>>().join(",");
        self.cmd(&format!("UID STORE {set} +FLAGS.SILENT (\\Seen)"), cancel).map(|_| ())
    }

    /// IDLE until new mail (true), `until` (false) or cancel.
    fn idle(&mut self, until: Instant, cancel: &Cancel) -> R<bool> {
        let tag = self.next_tag();
        self.c.write(format!("{tag} IDLE\r\n").as_bytes())?;
        let mut got = false;
        loop {
            let r = self.c.resp(cancel, self.timeout)?;
            if r.text.starts_with('+') {
                break;
            }
            if let Some(rest) = r.text.strip_prefix(&format!("{tag} ")) {
                return Err(err(K::Protocol, format!("IMAP IDLE refused: {rest}")));
            }
            got |= is_new_mail(&r.text);
        }
        while !got {
            match self.c.try_resp() {
                Ok(Some(r)) if r.text.len() >= 5 && r.text[..5].eq_ignore_ascii_case("* BYE") => return Err(net("imap", "server ended IDLE with BYE")),
                Ok(Some(r)) => got = is_new_mail(&r.text),
                Ok(None) if cancel.is_cancelled() => {
                    let _ = self.c.write(b"DONE\r\n");
                    return Err(E::Cancelled);
                }
                Ok(None) if Instant::now() >= until => break,
                Ok(None) => {}
                Err(e) => return Err(net("imap idle", e)),
            }
        }
        self.c.write(b"DONE\r\n")?;
        let (u, status) = self.finish(&tag, cancel)?;
        Self::ok("IDLE", (u, status))?;
        Ok(got)
    }

    fn logout(&mut self) {
        let tag = self.next_tag();
        let _ = self.c.write(format!("{tag} LOGOUT\r\n").as_bytes());
        self.c.s.shutdown();
    }
}

fn is_new_mail(t: &str) -> bool {
    let up = t.to_ascii_uppercase();
    up.starts_with("* ") && (up.ends_with(" EXISTS") || up.ends_with(" RECENT"))
}

// ---------------------------------------------------------------- the channel

impl Email {
    pub fn new(id: &str, cfg: Config, state: PathBuf, media_dir: PathBuf) -> Result<Email, String> {
        if !cfg.address.contains('@') {
            return Err(format!("channel {id}: email address `{}` is not an address", cfg.address));
        }
        if cfg.require_authenticated_sender && cfg.authserv_id.is_empty() {
            return Err(format!(
                "channel {id}: authserv_id is required (the exact authserv-id your receiving mail server stamps on Authentication-Results, e.g. mx.google.com), or set require_authenticated_sender = false to trust the From header"
            ));
        }
        let mut cur = Cursor::default();
        if let Ok(s) = std::fs::read_to_string(&state) {
            if let Ok(v) = serde_json::from_str::<Value>(&s) {
                cur.validity = v["uidvalidity"].as_u64().unwrap_or(0);
                cur.last_uid = v["last_uid"].as_u64().unwrap_or(0);
            }
        }
        Ok(Email {
            id: id.to_string(),
            cfg,
            state,
            media_dir,
            imap: Mutex::new(None),
            cursor: Mutex::new(cur),
            threads: Mutex::new(Threads::default()),
            backoff: Mutex::new((0, None)),
            retry_base: Duration::from_secs(2),
            max_backoff: Duration::from_secs(300),
        })
    }

    fn domain(&self) -> &str {
        self.cfg.address.rsplit_once('@').map(|(_, d)| d).filter(|d| !d.is_empty()).unwrap_or("localhost")
    }

    fn save_cursor(&self, c: &Cursor) -> R<()> {
        write_atomic(&self.state, json!({"uidvalidity": c.validity, "last_uid": c.last_uid}).to_string().as_bytes()).map_err(|e| err(K::Fatal, format!("saving email cursor: {e}")))
    }

    fn connect(&self, cancel: &Cancel) -> R<Imap> {
        let mut im = Imap::open(&self.cfg, cancel)?;
        let mut c = self.cursor.lock().unwrap();
        if c.validity != im.validity || c.validity == 0 {
            let fresh = c.validity == 0;
            c.pending.clear();
            c.pending_last = None;
            c.validity = im.validity;
            c.last_uid = 0;
            // First run: skip what is already in the mailbox (Hermes marks it seen). After a
            // UIDVALIDITY change the old UIDs mean nothing; unseen mail is delivered again.
            if (fresh && self.cfg.skip_existing) || (!fresh && !self.cfg.unseen_only) {
                c.last_uid = if im.uidnext > 0 { im.uidnext - 1 } else { im.search("ALL", cancel)?.last().copied().unwrap_or(0) };
            }
            self.save_cursor(&c)?;
        }
        Ok(im)
    }

    fn commit(&self, im: &mut Imap, cancel: &Cancel) -> R<()> {
        let (uids, last) = {
            let c = self.cursor.lock().unwrap();
            (c.pending.clone(), c.pending_last)
        };
        let Some(last) = last else { return Ok(()) };
        im.mark_seen(&uids, cancel)?;
        let mut c = self.cursor.lock().unwrap();
        c.last_uid = c.last_uid.max(last);
        c.pending.clear();
        c.pending_last = None;
        self.save_cursor(&c)
    }

    /// New mail after the cursor (pending included) → inbound messages.
    fn fetch_new(&self, im: &mut Imap, cancel: &Cancel) -> R<Vec<Inbound>> {
        let from = {
            let c = self.cursor.lock().unwrap();
            c.pending_last.unwrap_or(c.last_uid).max(c.last_uid)
        };
        let query = if self.cfg.unseen_only { format!("UNSEEN UID {}:*", from + 1) } else { format!("UID {}:*", from + 1) };
        // `n:*` always matches the highest UID, even below n.
        let uids: Vec<u64> = im.search(&query, cancel)?.into_iter().filter(|&u| u > from).take(BATCH).collect();
        if uids.is_empty() {
            return Ok(vec![]);
        }
        let heads = im.fetch_headers(&uids, cancel)?;
        let mut out = Vec::new();
        for &uid in &uids {
            let Some((size, head)) = heads.get(&uid) else { continue };
            if head.len() > MAX_HEADER_BYTES {
                continue;
            }
            let h = parse_headers(split_head(head).0);
            if self.gate(&h).is_err() || *size > self.cfg.max_message_bytes {
                continue;
            }
            let Some(raw) = im.fetch_body(uid, cancel)? else { continue };
            out.extend(self.inbound_of(uid, im.validity, &raw));
        }
        let mut c = self.cursor.lock().unwrap();
        c.pending.extend(&uids);
        c.pending_last = uids.last().copied().max(c.pending_last);
        Ok(out)
    }

    /// Pre-dispatch sender gate (Hermes `_sender_accepted` minus the allow-list, which is the host's).
    fn gate(&self, h: &Headers) -> Result<String, String> {
        let from = extract_address(header(h, "from").unwrap_or(""));
        if from.is_empty() {
            return Err("no parseable From address".into());
        }
        if from == self.cfg.address.to_lowercase() {
            return Err("own message".into());
        }
        if is_automated(&from, h) {
            return Err("automated sender".into());
        }
        if self.cfg.require_authenticated_sender {
            let (ok, reason) = verify_sender_authentication(h, &from, &self.cfg.authserv_id);
            if !ok {
                return Err(reason);
            }
        }
        Ok(from)
    }

    fn inbound_of(&self, uid: u64, validity: u64, raw: &[u8]) -> Option<Inbound> {
        let mail = parse_mail(raw);
        let sender = self.gate(&mail.headers).ok()?;
        let h = &mail.headers;
        let from_raw = decode_words(header(h, "from").unwrap_or(""));
        let mut name = from_raw.split('<').next().unwrap_or("").trim().trim_matches('"').trim().to_string();
        if name.is_empty() || name.contains('@') {
            name = sender.clone();
        }
        let subject = decode_words(header(h, "subject").unwrap_or("")).trim().to_string();
        let mut body = if !mail.text.trim().is_empty() { mail.text.clone() } else { strip_html(&mail.html) };
        if self.cfg.strip_quotes {
            body = strip_quoted(&body);
        }
        let body = body.trim();
        let is_reply = is_re(&subject);
        let mut text = if !subject.is_empty() && !is_reply { format!("[Subject: {subject}]\n\n{body}").trim_end().to_string() } else { body.to_string() };
        let media = if self.cfg.skip_attachments { vec![] } else { self.save_attachments(uid, validity, &mail.attachments) };
        if text.is_empty() && media.is_empty() {
            text = "(empty email)".into();
        }
        let message_id = msg_ids(header(h, "message-id").unwrap_or("")).into_iter().next().unwrap_or_else(|| format!("<uid.{validity}.{uid}@{}>", self.cfg.imap_host));
        let in_reply_to = msg_ids(header(h, "in-reply-to").unwrap_or("")).into_iter().next();
        let mut refs = msg_ids(header(h, "references").unwrap_or(""));
        if refs.is_empty() {
            refs.extend(in_reply_to.clone());
        }
        let root = refs.first().cloned().unwrap_or_else(|| message_id.clone());
        let mut chain = refs.clone();
        chain.push(message_id.clone());
        self.threads.lock().unwrap().put(&sender, &message_id, ThreadCtx { subject: subject.clone(), refs: chain });
        Some(Inbound {
            channel: self.id.clone(),
            chat: sender.clone(),
            chat_type: ChatType::Direct,
            chat_name: name.clone(),
            thread: Some(root),
            sender,
            sender_name: name,
            text,
            message_id,
            ts: header(h, "date").and_then(parse_date).unwrap_or(0),
            reply: in_reply_to.map(|id| ReplyRef { is_own: self.is_own_id(&id), id, ..Default::default() }),
            media,
            ..Default::default()
        })
    }

    fn is_own_id(&self, id: &str) -> bool {
        id.starts_with("<ark.") && id.ends_with(&format!("@{}>", self.domain()))
    }

    fn save_attachments(&self, uid: u64, validity: u64, atts: &[Attachment]) -> Vec<Media> {
        let mut out = Vec::new();
        for (i, a) in atts.iter().enumerate() {
            if a.data.is_empty() || a.data.len() as u64 > self.cfg.max_attachment_bytes {
                continue;
            }
            let safe: String = a.name.chars().map(|c| if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' }).collect();
            let safe = safe.trim_start_matches('.').chars().rev().take(100).collect::<Vec<_>>().into_iter().rev().collect::<String>();
            let path = self.media_dir.join(format!("{validity}-{uid}-{i}-{}", if safe.is_empty() { "attachment".into() } else { safe }));
            if write_atomic(&path, &a.data).is_err() {
                continue;
            }
            let kind = match a.mime.split('/').next().unwrap_or("") {
                "image" => MediaKind::Image,
                "audio" => MediaKind::Audio,
                "video" => MediaKind::Video,
                _ => MediaKind::Document,
            };
            let p = path.display().to_string();
            out.push(Media { kind, path: Some(p.clone()), id: Some(p), mime: a.mime.clone(), name: a.name.clone(), size: a.data.len() as u64, ..Default::default() });
        }
        out
    }

    fn poll_inner(&self, slot: &mut Option<Imap>, cancel: &Cancel, until: Instant) -> R<Vec<Inbound>> {
        // A connection kept from the last poll may have died meanwhile: reconnect once, transparently.
        if let Some(im) = slot.as_mut() {
            match self.commit(im, cancel).and_then(|_| im.cmd("NOOP", cancel).map(|_| ())) {
                Ok(()) => {}
                Err(E::Cancelled) => return Err(E::Cancelled),
                Err(E::Err(e)) if e.kind == K::Fatal => return Err(E::Err(e)),
                Err(E::Err(_)) => *slot = None,
            }
        }
        if slot.is_none() {
            let mut im = self.connect(cancel)?;
            self.commit(&mut im, cancel)?;
            *slot = Some(im);
        }
        let im = slot.as_mut().expect("connected");
        let got = self.fetch_new(im, cancel)?;
        if !got.is_empty() {
            return Ok(got);
        }
        while Instant::now() < until {
            if self.cfg.idle && im.has("IDLE") {
                if !im.idle(until, cancel)? {
                    return Ok(vec![]);
                }
            } else {
                let wait = self.cfg.poll_interval.min(until.saturating_duration_since(Instant::now()));
                if !sleep_cancellable(wait, cancel) {
                    return Err(E::Cancelled);
                }
                if Instant::now() >= until {
                    break;
                }
                im.cmd("NOOP", cancel)?;
            }
            let got = self.fetch_new(im, cancel)?;
            if !got.is_empty() {
                return Ok(got);
            }
        }
        Ok(vec![])
    }

    // ------------------------------------------------------------ SMTP

    fn smtp_send(&self, to: &str, data: &[u8]) -> Result<(), ChannelError> {
        let host = self.cfg.smtp_host.as_deref().ok_or_else(|| crate::unsupported("sending (no smtp_host configured)"))?;
        let cancel = Cancel::new();
        let lift = |e: E| match e {
            E::Err(e) => e,
            E::Cancelled => ChannelError::new(K::Network, "cancelled"),
        };
        let s = connect_stream(host, self.cfg.smtp_port, self.cfg.smtp_security == Security::Tls, self.cfg.timeout, &cancel).map_err(lift)?;
        let mut sm = Smtp { c: Conn::new(s, false), timeout: self.cfg.timeout };
        sm.expect("greeting", &[220])?;
        let ehlo = format!("EHLO {}", self.domain());
        let mut caps = sm.cmd(&ehlo, "EHLO", &[250])?;
        if self.cfg.smtp_security == Security::StartTls {
            if !caps.iter().any(|c| c.eq_ignore_ascii_case("STARTTLS")) {
                return Err(ChannelError::new(K::Fatal, "SMTP server does not offer STARTTLS (set smtp_security = \"tls\")"));
            }
            sm.cmd("STARTTLS", "STARTTLS", &[220])?;
            if !sm.c.buf.is_empty() {
                return Err(ChannelError::new(K::Protocol, "SMTP server sent data after STARTTLS"));
            }
            let Smtp { c, timeout } = sm;
            let _ = c.s.set_read_timeout(Some(timeout));
            let s = c.s.starttls(host).map_err(|e| ChannelError::new(K::Network, format!("SMTP STARTTLS: {e}")))?;
            sm = Smtp { c: Conn::new(s, false), timeout };
            caps = sm.cmd(&ehlo, "EHLO", &[250])?;
        }
        if !self.cfg.password.is_empty() {
            let mechs: Vec<String> = caps
                .iter()
                .filter_map(|c| {
                    let up = c.to_ascii_uppercase();
                    up.strip_prefix("AUTH").filter(|r| r.starts_with([' ', '='])).map(|r| r[1..].to_string())
                })
                .flat_map(|r| r.split_whitespace().map(str::to_string).collect::<Vec<_>>())
                .collect();
            let user = &self.cfg.username;
            if mechs.iter().any(|m| m == "LOGIN") && !mechs.iter().any(|m| m == "PLAIN") {
                sm.cmd("AUTH LOGIN", "AUTH", &[334])?;
                sm.cmd(&crypto::b64(user.as_bytes()), "AUTH", &[334])?;
                sm.cmd(&crypto::b64(self.cfg.password.as_bytes()), "AUTH", &[235])?;
            } else {
                let tok = crypto::b64(format!("\0{user}\0{}", self.cfg.password).as_bytes());
                sm.cmd(&format!("AUTH PLAIN {tok}"), "AUTH", &[235])?;
            }
        }
        sm.cmd(&format!("MAIL FROM:<{}>", self.cfg.address), "MAIL FROM", &[250])?;
        sm.cmd(&format!("RCPT TO:<{to}>"), "RCPT TO", &[250, 251])?;
        sm.cmd("DATA", "DATA", &[354])?;
        sm.c.write(&dot_stuff(data)).map_err(lift)?;
        sm.expect("message", &[250])?;
        let _ = sm.c.write(b"QUIT\r\n");
        sm.c.s.shutdown();
        Ok(())
    }

    /// (subject, In-Reply-To, References) for a message to `chat`.
    fn threading(&self, out: &Outbound) -> (String, Option<String>, Vec<String>) {
        let t = self.threads.lock().unwrap();
        let target = out.reply_to.clone().or_else(|| {
            let last = t.last.get(&out.chat.to_lowercase()).cloned();
            match (&out.thread, last) {
                // The latest message of this correspondent when it is in the requested thread.
                (Some(th), Some(l)) if t.by_id.get(&l).is_some_and(|c| c.refs.first() == Some(th)) => Some(l),
                (Some(th), _) => Some(th.clone()),
                (None, l) => l,
            }
        });
        let Some(target) = target else { return (self.cfg.subject.clone(), None, vec![]) };
        let ctx = t.by_id.get(&target).cloned().unwrap_or_default();
        let mut refs = ctx.refs.clone();
        if refs.last() != Some(&target) {
            if let Some(th) = out.thread.as_ref().filter(|th| refs.is_empty() && **th != target) {
                refs.push(th.clone());
            }
            refs.push(target.clone());
        }
        let base = if ctx.subject.is_empty() { self.cfg.subject.clone() } else { ctx.subject };
        let subject = if is_re(&base) { base } else { format!("Re: {base}") };
        (subject, Some(target), refs)
    }

    fn new_message_id(&self) -> String {
        format!("<ark.{}@{}>", crypto::hex(&crypto::random_bytes(8)), self.domain())
    }
}

struct Smtp {
    c: Conn,
    timeout: Duration,
}

impl Smtp {
    /// One (possibly multi-line) reply: (code, text lines).
    fn reply(&mut self) -> Result<(u16, Vec<String>), ChannelError> {
        let mut lines = Vec::new();
        loop {
            let r = self.c.resp(&Cancel::new(), self.timeout).map_err(|e| match e {
                E::Err(e) => e,
                E::Cancelled => ChannelError::new(K::Network, "cancelled"),
            })?;
            let code: u16 = r.text.get(..3).and_then(|c| c.parse().ok()).ok_or_else(|| ChannelError::new(K::Protocol, format!("bad SMTP reply: {}", r.text.chars().take(100).collect::<String>())))?;
            lines.push(r.text.get(4..).unwrap_or("").to_string());
            if r.text.as_bytes().get(3) != Some(&b'-') {
                return Ok((code, lines));
            }
        }
    }

    fn expect(&mut self, stage: &str, want: &[u16]) -> Result<Vec<String>, ChannelError> {
        let (code, lines) = self.reply()?;
        if want.contains(&code) {
            return Ok(lines);
        }
        Err(smtp_error(stage, code, &lines.join(" ")))
    }

    fn cmd(&mut self, line: &str, stage: &str, want: &[u16]) -> Result<Vec<String>, ChannelError> {
        if line.contains(['\r', '\n']) {
            return Err(ChannelError::new(K::Fatal, "SMTP command contains a newline"));
        }
        self.c.write(format!("{line}\r\n").as_bytes()).map_err(|e| match e {
            E::Err(e) => e,
            E::Cancelled => ChannelError::new(K::Network, "cancelled"),
        })?;
        self.expect(stage, want)
    }
}

/// SMTP reply code → error kind the delivery layer acts on.
fn smtp_error(stage: &str, code: u16, text: &str) -> ChannelError {
    let snippet: String = text.chars().take(200).collect();
    let low = text.to_ascii_lowercase();
    let kind = match code {
        530 | 534 | 535 | 538 => K::Auth,
        _ if stage == "AUTH" && code >= 500 => K::Auth,
        421 | 450 | 451 | 452 if low.contains("rate") || low.contains("too many") || low.contains("4.7.0") || low.contains("try again later") => K::RateLimited { retry_after: None },
        400..=499 => K::Network,
        550 | 551 | 553 if stage == "RCPT TO" => K::NotFound,
        _ => K::Protocol,
    };
    ChannelError::new(kind, format!("SMTP {stage}: {code} {snippet}"))
}

/// CRLF line endings, leading dots doubled, terminated by `.`.
fn dot_stuff(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 64);
    let text = data.strip_suffix(b"\r\n").or_else(|| data.strip_suffix(b"\n")).unwrap_or(data);
    for line in text.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.first() == Some(&b'.') {
            out.push(b'.');
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

fn valid_address(a: &str) -> bool {
    let Some((l, d)) = a.rsplit_once('@') else { return false };
    !l.is_empty() && !d.is_empty() && (d.contains('.') || d == "localhost") && !a.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | ',' | '"' | '(' | ')' | ';' | ':' | '\\'))
}

impl Channel for Email {
    fn id(&self) -> &str {
        &self.id
    }

    fn caps(&self) -> Caps {
        Caps {
            chat_types: vec![ChatType::Direct],
            media: true,
            reply: true,
            threads: true,
            reactions: 0,
            edit: false,
            delete: false,
            typing: false,
            buttons: false,
            polls: false,
            native_commands: false,
            streaming: Streaming::None,
            max_len: MAX_MESSAGE,
            len_unit: LenUnit::Chars,
            markup: Markup::Plain,
        }
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let until = Instant::now() + self.cfg.poll_timeout.max(Duration::from_secs(1));
        let next = self.backoff.lock().unwrap().1;
        if let Some(next) = next.filter(|n| *n > Instant::now()) {
            let wait = next.min(until).saturating_duration_since(Instant::now());
            if !sleep_cancellable(wait, cancel) || Instant::now() < next {
                return Ok(vec![]);
            }
        }
        let mut slot = self.imap.lock().unwrap();
        match self.poll_inner(&mut slot, cancel, until) {
            Ok(v) => {
                *self.backoff.lock().unwrap() = (0, None);
                Ok(v)
            }
            Err(E::Cancelled) => {
                // Mid-command state is unknown: start clean next time.
                *slot = None;
                Ok(vec![])
            }
            Err(E::Err(e)) => {
                if let Some(mut im) = slot.take() {
                    im.logout();
                }
                if e.is_retryable() {
                    let mut b = self.backoff.lock().unwrap();
                    let d = self.retry_base.saturating_mul(2u32.saturating_pow(b.0.min(16))).min(self.max_backoff);
                    *b = (b.0 + 1, Some(Instant::now() + d));
                }
                Err(e)
            }
        }
    }

    fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
        let to = out.chat.trim().to_lowercase();
        if !valid_address(&to) {
            return Err(ChannelError::new(K::Fatal, format!("not an email address: {}", out.chat.chars().take(100).collect::<String>())));
        }
        let mut text = out.text.clone();
        let mut options = Vec::new();
        for (i, b) in out.buttons.iter().flatten().enumerate() {
            options.push(match &b.url {
                Some(u) => format!("{}. {}: {u}", i + 1, b.label),
                None => format!("{}. {}", i + 1, b.label),
            });
        }
        if !options.is_empty() {
            text.push_str(&format!("\n\n{}\n(Reply with the number.)", options.join("\n")));
        }
        let mut files = Vec::new();
        for m in &out.media {
            match (&m.path, &m.url) {
                (Some(p), _) => {
                    let data = std::fs::read(p).map_err(|e| ChannelError::new(K::Fatal, format!("cannot read attachment {p}: {e}")))?;
                    let name = if m.name.is_empty() { std::path::Path::new(p).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "attachment".into()) } else { m.name.clone() };
                    let mime = if m.mime.is_empty() { guess_mime(&name).to_string() } else { m.mime.clone() };
                    files.push(Attachment { name, mime, data });
                }
                (None, Some(u)) => {
                    let label = m.caption.clone().filter(|c| !c.is_empty()).unwrap_or_else(|| if m.kind == MediaKind::Image { "Image".into() } else if m.name.is_empty() { "Attachment".into() } else { m.name.clone() });
                    text.push_str(&format!("\n\n{label}: {u}"));
                }
                _ => return Err(ChannelError::new(K::Fatal, "attachment has neither path nor url")),
            }
        }
        let mut pieces = chunk::split(&text, MAX_MESSAGE, LenUnit::Chars);
        if pieces.is_empty() {
            pieces.push(String::new());
        }
        let (subject, mut in_reply_to, mut refs) = self.threading(out);
        let n = pieces.len();
        let mut sent = Sent::default();
        for (i, piece) in pieces.into_iter().enumerate() {
            let (plain, html) = match out.format {
                TextFormat::Markdown => (markup::convert(&piece, Markup::Plain), Some(format!("<html><body>{}</body></html>", markup::convert(&piece, Markup::MatrixHtml).replace('\n', "<br>\n")))),
                TextFormat::Plain => (piece, None),
            };
            let id = self.new_message_id();
            let atts: &[Attachment] = if i + 1 == n { &files } else { &[] };
            let msg = MessageSpec { from: &self.cfg.address, from_name: &self.cfg.from_name, to: &to, subject: &subject, message_id: &id, in_reply_to: in_reply_to.as_deref(), references: &refs, date: now_unix(), text: &plain, html: html.as_deref(), attachments: atts };
            self.smtp_send(&to, &build_message(&msg))?;
            refs.push(id.clone());
            in_reply_to = Some(id.clone());
            self.threads.lock().unwrap().put(&to, &id, ThreadCtx { subject: subject.clone(), refs: refs.clone() });
            sent.ids.push(id);
        }
        Ok(sent)
    }

    fn fetch_media(&self, m: &Media) -> Result<Vec<u8>, ChannelError> {
        match m.path.as_deref().or(m.id.as_deref()) {
            Some(p) => std::fs::read(p).map_err(|e| ChannelError::new(K::NotFound, format!("attachment {p}: {e}"))),
            None => Err(crate::unsupported("media download")),
        }
    }

    fn stop(&self) {
        if let Ok(mut g) = self.imap.try_lock() {
            if let Some(mut im) = g.take() {
                im.logout();
            }
        }
    }
}

fn is_re(s: &str) -> bool {
    s.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("re:"))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn guess_mime(name: &str) -> &'static str {
    match name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).as_deref() {
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("pdf") => "application/pdf",
        Some("txt" | "log" | "md") => "text/plain",
        Some("csv") => "text/csv",
        Some("html" | "htm") => "text/html",
        Some("json") => "application/json",
        Some("zip") => "application/zip",
        Some("mp3") => "audio/mpeg",
        Some("ogg") => "audio/ogg",
        Some("wav") => "audio/wav",
        Some("mp4") => "video/mp4",
        _ => "application/octet-stream",
    }
}

// ---------------------------------------------------------------- outbound MIME

struct MessageSpec<'a> {
    from: &'a str,
    from_name: &'a str,
    to: &'a str,
    subject: &'a str,
    message_id: &'a str,
    in_reply_to: Option<&'a str>,
    references: &'a [String],
    date: i64,
    text: &'a str,
    html: Option<&'a str>,
    attachments: &'a [Attachment],
}

fn one_line(s: &str) -> String {
    s.chars().map(|c| if c == '\r' || c == '\n' { ' ' } else { c }).collect()
}

/// RFC 2047 B-encoding for non-ASCII header text (split into ≤ 45-byte UTF-8 runs).
fn encode_words(s: &str) -> String {
    let s = one_line(s);
    if s.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return s;
    }
    let mut words = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if cur.len() + c.len_utf8() > 45 {
            words.push(format!("=?UTF-8?B?{}?=", crypto::b64(cur.as_bytes())));
            cur.clear();
        }
        cur.push(c);
    }
    if !cur.is_empty() {
        words.push(format!("=?UTF-8?B?{}?=", crypto::b64(cur.as_bytes())));
    }
    words.join("\r\n ")
}

fn qp_encode(text: &str) -> String {
    let mut out = String::new();
    let norm = text.replace("\r\n", "\n");
    for (li, line) in norm.split('\n').enumerate() {
        if li > 0 {
            out.push_str("\r\n");
        }
        let bytes = line.as_bytes();
        let mut col = 0;
        for (i, &b) in bytes.iter().enumerate() {
            let last = i + 1 == bytes.len();
            let enc = if ((b == b' ' || b == b'\t') && last) || b == b'=' || (!(0x20..0x7f).contains(&b) && b != b'\t') {
                format!("={b:02X}")
            } else {
                (b as char).to_string()
            };
            if col + enc.len() > 75 {
                out.push_str("=\r\n");
                col = 0;
            }
            out.push_str(&enc);
            col += enc.len();
        }
    }
    out
}

fn b64_lines(data: &[u8]) -> String {
    let s = crypto::b64(data);
    let mut out = String::with_capacity(s.len() + s.len() / 76 * 2 + 2);
    for (i, c) in s.as_bytes().chunks(76).enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        out.push_str(std::str::from_utf8(c).unwrap_or(""));
    }
    out
}

fn boundary() -> String {
    format!("=_ark_{}", crypto::hex(&crypto::random_bytes(12)))
}

fn filename_params(name: &str) -> (String, String) {
    let name = one_line(name).replace(['"', '\\'], "_");
    if name.is_ascii() {
        return (format!("name=\"{name}\""), format!("filename=\"{name}\""));
    }
    let pct: String = name.bytes().map(|b| if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_') { (b as char).to_string() } else { format!("%{b:02X}") }).collect();
    (format!("name=\"{}\"", encode_words(&name).replace("\r\n ", "")), format!("filename*=UTF-8''{pct}"))
}

fn text_part(ctype: &str, body: &str) -> String {
    format!("Content-Type: {ctype}; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n{}\r\n", qp_encode(body))
}

fn build_message(m: &MessageSpec) -> Vec<u8> {
    let mut h = String::new();
    let from = if m.from_name.is_empty() { m.from.to_string() } else { format!("{} <{}>", encode_words(&m.from_name.replace('"', "")), m.from) };
    h.push_str(&format!("From: {from}\r\nTo: {}\r\nSubject: {}\r\nDate: {}\r\nMessage-ID: {}\r\n", m.to, encode_words(m.subject), format_date(m.date), m.message_id));
    if let Some(r) = m.in_reply_to {
        h.push_str(&format!("In-Reply-To: {}\r\n", one_line(r)));
    }
    if !m.references.is_empty() {
        let refs: Vec<String> = m.references.iter().map(|r| one_line(r)).collect();
        h.push_str(&format!("References: {}\r\n", refs.join("\r\n ")));
    }
    h.push_str("MIME-Version: 1.0\r\n");
    let body = match m.html {
        Some(html) => {
            let b = boundary();
            format!("Content-Type: multipart/alternative; boundary=\"{b}\"\r\n\r\n--{b}\r\n{}--{b}\r\n{}--{b}--\r\n", text_part("text/plain", m.text), text_part("text/html", html))
        }
        None => text_part("text/plain", m.text),
    };
    if m.attachments.is_empty() {
        h.push_str(&body);
        return h.into_bytes();
    }
    let b = boundary();
    h.push_str(&format!("Content-Type: multipart/mixed; boundary=\"{b}\"\r\n\r\nThis is a multi-part message in MIME format.\r\n--{b}\r\n{body}"));
    for a in m.attachments {
        let (np, fp) = filename_params(&a.name);
        h.push_str(&format!("--{b}\r\nContent-Type: {}; {np}\r\nContent-Disposition: attachment; {fp}\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n", one_line(&a.mime), b64_lines(&a.data)));
    }
    h.push_str(&format!("--{b}--\r\n"));
    h.into_bytes()
}

// ---------------------------------------------------------------- inbound MIME

pub type Headers = Vec<(String, String)>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attachment {
    pub name: String,
    pub mime: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct Mail {
    pub headers: Headers,
    pub text: String,
    pub html: String,
    pub attachments: Vec<Attachment>,
    /// Charset label of the first text body ("" when there is none).
    pub charset: String,
}

pub fn header<'a>(h: &'a Headers, name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn headers_all<'a>(h: &'a Headers, name: &str) -> Vec<&'a str> {
    h.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).collect()
}

/// (head, body) split at the first blank line.
fn split_head(raw: &[u8]) -> (&[u8], &[u8]) {
    if raw.starts_with(b"\r\n") {
        return (&[], &raw[2..]);
    }
    if raw.starts_with(b"\n") {
        return (&[], &raw[1..]);
    }
    let crlf = find(raw, b"\r\n\r\n").map(|i| (i, i + 4));
    let lf = find(raw, b"\n\n").map(|i| (i, i + 2));
    match (crlf, lf) {
        (Some(a), Some(b)) => {
            let (h, s) = if a.0 <= b.0 { a } else { b };
            (&raw[..h], &raw[s..])
        }
        (Some((h, s)), None) | (None, Some((h, s))) => (&raw[..h], &raw[s..]),
        (None, None) => (raw, &[]),
    }
}

/// Unfolded header fields in order (topmost first).
pub fn parse_headers(head: &[u8]) -> Headers {
    parse_headers_in(head, None)
}

/// `parse_headers`, with raw 8-bit lines (old mailers) decoded in `enc` instead of lossy
/// UTF-8; raw ISO-2022-JP (`ESC $ B`) lines are recognised on their own.
fn parse_headers_in(head: &[u8], enc: Option<crate::charset::Encoding>) -> Headers {
    use crate::charset::Encoding as C;
    let enc = enc.filter(|e| !matches!(e, C::Utf16Be | C::Utf16Le | C::Replacement));
    let mut out: Headers = Vec::new();
    for raw in head.split(|&b| b == b'\n') {
        let line = match (std::str::from_utf8(raw), enc) {
            _ if find(raw, b"\x1b$").is_some() => C::Iso2022Jp.decode_without_bom(raw),
            (Ok(l), _) => l.to_string(),
            (Err(_), Some(e)) => e.decode_without_bom(raw),
            (Err(_), None) => String::from_utf8_lossy(raw).into_owned(),
        };
        let line = line.strip_suffix('\r').unwrap_or(&line);
        if line.starts_with([' ', '\t']) {
            if let Some((_, v)) = out.last_mut() {
                v.push(' ');
                v.push_str(line.trim_start());
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            if !k.is_empty() && !k.contains(' ') {
                out.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
    }
    out
}

/// `type/sub; k=v; k2="v 2"` → (lowercased type, params with lowercased keys).
fn parse_params(v: &str) -> (String, Vec<(String, String)>) {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut esc = false;
    for c in v.chars() {
        if esc {
            cur.push(c);
            esc = false;
            continue;
        }
        match c {
            '\\' if quoted => esc = true,
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            ';' if !quoted => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    parts.push(cur);
    let main = parts.first().map(|p| p.trim().to_ascii_lowercase()).unwrap_or_default();
    let params = parts[1..]
        .iter()
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            let v = v.trim();
            let v = v.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(v);
            Some((k.trim().to_ascii_lowercase(), v.to_string()))
        })
        .collect();
    (main, params)
}

/// A parameter, honouring RFC 2231 (`name*=utf-8''%E4…`, `name*0*=…; name*1*=…`) and RFC 2047 words.
fn param(params: &[(String, String)], name: &str) -> Option<String> {
    if let Some((_, v)) = params.iter().find(|(k, _)| k == name) {
        return Some(decode_words(v));
    }
    if let Some((_, v)) = params.iter().find(|(k, _)| *k == format!("{name}*")) {
        return Some(decode_2231(v, true));
    }
    let mut segs: Vec<(usize, bool, &str)> = params
        .iter()
        .filter_map(|(k, v)| {
            let rest = k.strip_prefix(name)?.strip_prefix('*')?;
            let (n, enc) = match rest.strip_suffix('*') {
                Some(n) => (n, true),
                None => (rest, false),
            };
            Some((n.parse().ok()?, enc, v.as_str()))
        })
        .collect();
    if segs.is_empty() {
        return None;
    }
    segs.sort_by_key(|s| s.0);
    let charset = segs.iter().find(|s| s.0 == 0 && s.1).and_then(|s| s.2.split('\'').next()).unwrap_or("utf-8").to_string();
    let mut bytes = Vec::new();
    for (i, (_, enc, v)) in segs.iter().enumerate() {
        let v = if i == 0 && *enc { v.splitn(3, '\'').nth(2).unwrap_or(v) } else { v };
        if *enc {
            bytes.extend(pct_decode(v));
        } else {
            bytes.extend_from_slice(v.as_bytes());
        }
    }
    Some(decode_charset(&bytes, &charset))
}

fn decode_2231(v: &str, enc: bool) -> String {
    let mut it = v.splitn(3, '\'');
    match (enc, it.next(), it.next(), it.next()) {
        (true, Some(cs), Some(_lang), Some(text)) => decode_charset(&pct_decode(text), cs),
        _ => v.to_string(),
    }
}

fn pct_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Lenient base64 (whitespace and junk ignored, stops at padding).
pub fn b64_decode_lenient(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in data {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => continue,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

pub fn qp_decode(data: &[u8], header: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    while i < data.len() {
        match data[i] {
            b'=' if data.get(i + 1) == Some(&b'\r') && data.get(i + 2) == Some(&b'\n') => i += 3,
            b'=' if data.get(i + 1) == Some(&b'\n') => i += 2,
            b'=' => match (data.get(i + 1).copied().and_then(hex), data.get(i + 2).copied().and_then(hex)) {
                (Some(a), Some(b)) => {
                    out.push(a << 4 | b);
                    i += 3;
                }
                _ => {
                    out.push(b'=');
                    i += 1;
                }
            },
            b'_' if header => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Decode bytes in `charset` (any WHATWG label, see `charset`); unknown labels fall back
/// to UTF-8 (lossy), never fail.
pub fn decode_charset(b: &[u8], charset: &str) -> String {
    crate::charset::decode_label(b, charset.trim().trim_matches(['"', '\''])).unwrap_or_else(|| String::from_utf8_lossy(b).into_owned())
}

/// One encoded word → (charset, raw bytes, length consumed).
fn decode_word(w: &str) -> Option<(&str, Vec<u8>, usize)> {
    let body = w.strip_prefix("=?")?;
    let q1 = body.find('?')?;
    // RFC 2231 §5: `charset*language`.
    let charset = body[..q1].split('*').next().unwrap_or("");
    let rest = &body[q1 + 1..];
    let enc = rest.chars().next()?.to_ascii_uppercase();
    let rest = rest.get(1..)?.strip_prefix('?')?;
    let end = rest.find("?=")?;
    let text = &rest[..end];
    if text.contains([' ', '\t']) {
        return None;
    }
    let bytes = match enc {
        'B' => b64_decode_lenient(text.as_bytes()),
        'Q' => qp_decode(text.as_bytes(), true),
        _ => return None,
    };
    Some((charset, bytes, 2 + q1 + 1 + 2 + end + 2))
}

/// RFC 2047 encoded words; whitespace between adjacent words is dropped, and adjacent
/// words in one charset are decoded together (mailers split Big5 / UTF-8 characters).
pub fn decode_words(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    let mut pending: Option<(&str, Vec<u8>)> = None;
    let flush = |p: &mut Option<(&str, Vec<u8>)>, out: &mut String| {
        if let Some((cs, b)) = p.take() {
            out.push_str(&decode_charset(&b, cs));
        }
    };
    while let Some(i) = rest.find("=?") {
        let before = &rest[..i];
        match decode_word(&rest[i..]) {
            Some((cs, b, n)) => {
                let adjacent = pending.is_some() && before.chars().all(char::is_whitespace);
                match &mut pending {
                    Some((pcs, pb)) if adjacent && pcs.eq_ignore_ascii_case(cs) => pb.extend(b),
                    _ => {
                        flush(&mut pending, &mut out);
                        if !adjacent {
                            out.push_str(before);
                        }
                        pending = Some((cs, b));
                    }
                }
                rest = &rest[i + n..];
            }
            None => {
                flush(&mut pending, &mut out);
                out.push_str(&rest[..i + 2]);
                rest = &rest[i + 2..];
            }
        }
    }
    flush(&mut pending, &mut out);
    out.push_str(rest);
    out
}

/// Body parts between `--boundary` delimiter lines.
fn split_multipart<'a>(body: &'a [u8], boundary: &str) -> Vec<&'a [u8]> {
    let delim = format!("--{boundary}");
    let d = delim.as_bytes();
    let mut parts = Vec::new();
    let mut start: Option<usize> = None;
    let mut pos = 0;
    while pos <= body.len() {
        let line_end = body[pos..].iter().position(|&c| c == b'\n').map(|i| pos + i).unwrap_or(body.len());
        let line = &body[pos..line_end];
        let line_t = line.strip_suffix(b"\r").unwrap_or(line);
        if line_t.starts_with(d) {
            let tail = &line_t[d.len()..];
            let closing = tail.starts_with(b"--");
            if closing || tail.iter().all(|c| c.is_ascii_whitespace()) {
                if let Some(s) = start {
                    // The line break before a delimiter belongs to it.
                    let mut e = pos;
                    if e > s && body[e - 1] == b'\n' {
                        e -= 1;
                        if e > s && body[e - 1] == b'\r' {
                            e -= 1;
                        }
                    }
                    parts.push(&body[s..e.max(s)]);
                    if parts.len() >= 200 {
                        return parts;
                    }
                }
                if closing {
                    return parts;
                }
                start = Some((line_end + 1).min(body.len()));
            }
        }
        pos = line_end + 1;
    }
    // No closing delimiter: keep what was open.
    if let Some(s) = start {
        parts.push(&body[s..]);
    }
    parts
}

fn transfer_decode(h: &Headers, body: &[u8]) -> Vec<u8> {
    match header(h, "content-transfer-encoding").map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("base64") => b64_decode_lenient(body),
        Some("quoted-printable") => qp_decode(body, false),
        _ => body.to_vec(),
    }
}

fn walk(raw: &[u8], depth: usize, mail: &mut Mail, top: bool) {
    let (head, body) = split_head(raw);
    let mut h = parse_headers(head);
    if std::str::from_utf8(head).is_err() {
        // Raw 8-bit fields: the part's own charset, else the message body's so far.
        let cs = param(&parse_params(header(&h, "content-type").unwrap_or("")).1, "charset").unwrap_or_else(|| mail.charset.clone());
        h = parse_headers_in(head, crate::charset::Encoding::for_label(&cs));
    }
    let (ctype, params) = parse_params(header(&h, "content-type").unwrap_or("text/plain"));
    let ctype = if ctype.contains('/') { ctype } else { "text/plain".into() };
    if top {
        mail.headers = h.clone();
    }
    if ctype.starts_with("multipart/") && depth < 8 {
        if let Some(b) = param(&params, "boundary") {
            for p in split_multipart(body, &b) {
                walk(p, depth + 1, mail, false);
            }
            return;
        }
    }
    let (disp, dparams) = parse_params(header(&h, "content-disposition").unwrap_or(""));
    let filename = param(&dparams, "filename").or_else(|| param(&params, "name")).filter(|f| !f.trim().is_empty());
    let is_text_body = ctype == "text/plain" || ctype == "text/html";
    if ctype.starts_with("multipart/") {
        return;
    }
    let attachment = disp == "attachment" || !is_text_body;
    let data = transfer_decode(&h, body);
    if attachment {
        if mail.attachments.len() < 50 {
            let sub = ctype.split('/').nth(1).unwrap_or("bin").to_string();
            let name = filename.unwrap_or_else(|| if ctype == "message/rfc822" { "message.eml".into() } else { format!("attachment.{sub}") });
            mail.attachments.push(Attachment { name, mime: ctype, data });
        }
        return;
    }
    let charset = param(&params, "charset").unwrap_or_else(|| "utf-8".into());
    if mail.charset.is_empty() {
        mail.charset = charset.clone();
    }
    if ctype == "text/plain" && mail.text.is_empty() {
        mail.text = decode_charset(&data, &charset).replace("\r\n", "\n");
    } else if ctype == "text/html" && mail.html.is_empty() {
        mail.html = decode_charset(&data, &charset);
    }
}

/// Parse an RFC 822 message: headers, first text/plain and text/html bodies, attachments.
pub fn parse_mail(raw: &[u8]) -> Mail {
    let mut m = Mail::default();
    walk(raw, 0, &mut m, true);
    let head = split_head(raw).0;
    // A multipart top level has no charset of its own: decode raw 8-bit fields like the body.
    if std::str::from_utf8(head).is_err() && param(&parse_params(header(&m.headers, "content-type").unwrap_or("")).1, "charset").is_none() {
        m.headers = parse_headers_in(head, crate::charset::Encoding::for_label(&m.charset));
    }
    m
}

/// Naive HTML → text (Hermes `_strip_html`, plus style/script removal and entities).
pub fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let lower = html.to_ascii_lowercase();
    let mut i = 0;
    let b = html.as_bytes();
    while i < b.len() {
        if b[i] == b'<' {
            let end = match lower[i..].find('>') {
                Some(e) => i + e,
                None => break,
            };
            let tag = &lower[i + 1..end];
            let name: String = tag.trim_start_matches('/').chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
            if !tag.starts_with('/') && (name == "style" || name == "script" || name == "head") {
                let close = format!("</{name}");
                i = lower[end..].find(&close).map(|c| end + c).and_then(|c| lower[c..].find('>').map(|e| c + e + 1)).unwrap_or(b.len());
                continue;
            }
            if matches!(name.as_str(), "br" | "p" | "div" | "tr" | "li" | "h1" | "h2" | "h3" | "blockquote") {
                out.push('\n');
            }
            i = end + 1;
            continue;
        }
        let next = lower[i..].find('<').map(|n| i + n).unwrap_or(b.len());
        out.push_str(&decode_entities(&html[i..next]));
        i = next;
    }
    let mut collapsed = String::new();
    let mut nl = 0;
    for c in out.chars() {
        if c == '\n' {
            nl += 1;
            if nl > 2 {
                continue;
            }
        } else if !c.is_whitespace() {
            nl = 0;
        }
        collapsed.push(c);
    }
    collapsed.lines().map(str::trim_end).collect::<Vec<_>>().join("\n").trim().to_string()
}

fn decode_entities(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let semi = tail.find(';').filter(|&n| n <= 10);
        let ent = semi.map(|n| &tail[1..n]);
        let ch = ent.and_then(|e| match e {
            "nbsp" => Some(' '),
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            e if e.starts_with("#x") || e.starts_with("#X") => u32::from_str_radix(&e[2..], 16).ok().and_then(char::from_u32),
            e if e.starts_with('#') => e[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        });
        match (ch, semi) {
            (Some(c), Some(n)) => {
                out.push(c);
                rest = &tail[n + 1..];
            }
            _ => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn is_attribution(t: &str) -> bool {
    (t.starts_with("On ") && t.ends_with("wrote:"))
        || t.ends_with("寫道：")
        || t.ends_with("写道：")
        || t.ends_with("寫道:")
        || (t.starts_with("Le ") && t.ends_with("a écrit :"))
        || (t.starts_with("Am ") && t.ends_with("schrieb:"))
        || (t.starts_with("El ") && t.ends_with("escribió:"))
}

/// Drop quoted history (`>` lines, "On … wrote:" and everything after it, Outlook headers) and the signature.
pub fn strip_quoted(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    let mut out: Vec<&str> = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim();
        let next = lines.get(i + 1).map(|n| n.trim()).unwrap_or("");
        if t.starts_with("-----Original Message") || t.starts_with("----- Original Message") || is_attribution(t) || (t.starts_with("On ") && !next.is_empty() && next.ends_with("wrote:")) || *l == "-- " {
            break;
        }
        if t.starts_with("From: ") && lines[i + 1..].iter().take(4).any(|n| n.trim_start().starts_with("Sent: ") || n.trim_start().starts_with("Date: ")) && out.last().is_none_or(|p| p.trim().is_empty() || p.trim().starts_with("____")) {
            break;
        }
        if t.starts_with('>') {
            continue;
        }
        out.push(l);
    }
    while out.last().is_some_and(|l| l.trim().is_empty() || l.trim().chars().all(|c| c == '_')) {
        out.pop();
    }
    let s = out.join("\n").trim().to_string();
    if s.is_empty() {
        body.trim().to_string()
    } else {
        s
    }
}

/// `<a@b> <c@d>` → ids with brackets.
fn msg_ids(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = v;
    while let Some(i) = rest.find('<') {
        let Some(j) = rest[i..].find('>') else { break };
        let id = &rest[i..i + j + 1];
        if id.len() > 2 && !id.contains(char::is_whitespace) {
            out.push(id.to_string());
        }
        rest = &rest[i + j + 1..];
    }
    if out.is_empty() {
        let t = v.trim();
        if !t.is_empty() && !t.contains(char::is_whitespace) && t.contains('@') {
            out.push(format!("<{}>", t.trim_matches(['<', '>'])));
        }
    }
    out
}

/// Bare lowercased addr-spec of a From value, or "" when it is not exactly one mailbox.
pub fn extract_address(raw: &str) -> String {
    let v = raw.replace(['\r', '\n'], " ");
    if v.len() > 2048 || v.matches('(').count() > 64 {
        return String::new();
    }
    let (mut angles, mut bare, mut cur) = (Vec::new(), String::new(), String::new());
    let (mut depth, mut quoted, mut in_angle, mut esc, mut commas) = (0usize, false, false, false, 0);
    for c in v.chars() {
        if esc {
            esc = false;
            continue;
        }
        if c == '\\' && (quoted || depth > 0) {
            esc = true;
            continue;
        }
        if quoted {
            quoted = c != '"';
            continue;
        }
        if depth > 0 {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            continue;
        }
        match c {
            '"' if !in_angle => quoted = true,
            '(' => depth = 1,
            ')' => return String::new(),
            '<' if !in_angle => {
                in_angle = true;
                cur.clear();
            }
            '>' if in_angle => {
                in_angle = false;
                angles.push(std::mem::take(&mut cur));
            }
            // `Doe, John <j@x>`: an unquoted comma in the display name (Hermes accepts it).
            ',' if !in_angle => commas += 1,
            ';' | ':' | '<' | '>' if !in_angle => return String::new(),
            c if in_angle => cur.push(c),
            c => bare.push(c),
        }
    }
    if quoted || depth > 0 || in_angle {
        return String::new();
    }
    let addr = match angles.len() {
        1 if commas == 0 || !bare.contains('@') => angles.pop().unwrap_or_default(),
        0 if commas == 0 => bare.trim().to_string(),
        _ => return String::new(),
    };
    let addr = addr.trim().to_lowercase();
    if addr.contains(char::is_whitespace) || addr.matches('@').count() != 1 || addr.starts_with('@') || addr.ends_with('@') {
        return String::new();
    }
    addr
}

pub fn is_automated(addr: &str, h: &Headers) -> bool {
    let a = addr.to_lowercase();
    if NOREPLY_PATTERNS.iter().any(|p| a.contains(p)) {
        return true;
    }
    let get = |n: &str| header(h, n).map(|v| v.trim().to_ascii_lowercase()).filter(|v| !v.is_empty());
    get("auto-submitted").is_some_and(|v| v != "no")
        || get("precedence").is_some_and(|v| matches!(v.as_str(), "bulk" | "list" | "junk"))
        || get("x-auto-response-suppress").is_some()
        || get("list-unsubscribe").is_some()
        || get("list-id").is_some()
}

// ------------------------------------------------- Authentication-Results (RFC 8601)

/// Split on `;` outside quoted-strings and comments; comments dropped. None when unbalanced.
fn ar_clauses(text: &str) -> Option<Vec<String>> {
    let c: Vec<char> = text.chars().collect();
    let (mut clauses, mut cur, mut depth, mut quoted, mut i) = (Vec::new(), String::new(), 0i32, false, 0);
    while i < c.len() {
        let ch = c[i];
        if ch == '\\' && (quoted || depth > 0) {
            if quoted {
                cur.extend(c[i..(i + 2).min(c.len())].iter());
            }
            i += 2;
            continue;
        }
        if quoted {
            quoted = ch != '"';
            cur.push(ch);
        } else if depth > 0 {
            depth += match ch {
                '(' => 1,
                ')' => -1,
                _ => 0,
            };
            if depth == 0 {
                cur.push(' ');
            }
        } else if ch == '(' {
            depth = 1;
        } else if ch == '"' {
            quoted = true;
            cur.push(ch);
        } else if ch == ')' {
            return None;
        } else if ch == ';' {
            clauses.push(std::mem::take(&mut cur));
        } else {
            cur.push(ch);
        }
        i += 1;
    }
    if quoted || depth > 0 {
        return None;
    }
    clauses.push(cur);
    Some(clauses)
}

const AUTH_PROPS: [&str; 5] = ["header.from", "header.d", "smtp.mailfrom", "smtp.from", "envelope-from"];

/// Consume a quoted-string starting at `i` (which is '"'); returns the index after it.
fn skip_quoted(c: &[char], mut i: usize) -> Option<usize> {
    i += 1;
    while i < c.len() {
        match c[i] {
            '\\' => i += 2,
            '"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// `(property, value)` pairs of one comment-free clause; quoted contents are never scanned.
fn auth_props(text: &str) -> Vec<(String, String)> {
    let c: Vec<char> = text.chars().collect();
    let lower: Vec<char> = text.to_lowercase().chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        if c[i].is_whitespace() {
            i += 1;
            continue;
        }
        let mut matched = false;
        if lower.len() == c.len() {
            for p in AUTH_PROPS {
                let pc: Vec<char> = p.chars().collect();
                if lower[i..].starts_with(&pc) {
                    let mut j = i + pc.len();
                    while j < c.len() && c[j].is_whitespace() {
                        j += 1;
                    }
                    if j < c.len() && c[j] == '=' {
                        j += 1;
                        while j < c.len() && c[j].is_whitespace() {
                            j += 1;
                        }
                        let vs = j;
                        loop {
                            if j < c.len() && c[j] == '"' {
                                match skip_quoted(&c, j) {
                                    Some(e) => j = e,
                                    None => break,
                                }
                            } else if j < c.len() && !c[j].is_whitespace() && c[j] != '"' && c[j] != ';' {
                                j += 1;
                            } else {
                                break;
                            }
                        }
                        if j > vs {
                            let v: String = c[vs..j].iter().collect();
                            out.push((p.to_string(), v.trim_matches('"').to_string()));
                            i = j;
                            matched = true;
                        }
                    }
                    break;
                }
            }
        }
        if matched {
            continue;
        }
        // Any other token, consumed whole.
        let start = i;
        loop {
            if i < c.len() && c[i] == '"' {
                match skip_quoted(&c, i) {
                    Some(e) => i = e,
                    None => break,
                }
            } else if i < c.len() && !c[i].is_whitespace() && c[i] != '"' {
                i += 1;
            } else {
                break;
            }
        }
        if i == start {
            i += 1;
        }
    }
    out
}

fn domain_of(a: &str) -> String {
    a.rsplit_once('@').map(|(_, d)| d).unwrap_or(a).trim().to_lowercase()
}

/// Relaxed DMARC alignment: equal, or one a dot-suffix of the other.
fn aligned_domains(a: &str, b: &str) -> bool {
    let a = a.trim().to_lowercase();
    let b = b.trim().to_lowercase();
    let (a, b) = (a.trim_end_matches('.'), b.trim_end_matches('.'));
    !a.is_empty() && !b.is_empty() && (a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}")))
}

/// (result, properties) of one method clause.
type Verdict = (String, Vec<(String, String)>);

/// Hermes `_verify_sender_authentication`: (authenticated, reason).
pub fn verify_sender_authentication(h: &Headers, from_addr: &str, authserv_id: &str) -> (bool, String) {
    let from_domain = from_addr.rsplit_once('@').map(|(_, d)| d.trim().to_lowercase()).unwrap_or_default();
    if from_domain.is_empty() {
        return (false, "missing From domain".into());
    }
    let all = headers_all(h, "authentication-results");
    let Some(first) = all.first() else { return (false, "no Authentication-Results header".into()) };
    let trusted = first.split_whitespace().collect::<Vec<_>>().join(" ");
    let Some(clauses) = ar_clauses(&trusted) else { return (false, "unbalanced quote or comment in Authentication-Results".into()) };
    if authserv_id.is_empty() {
        return (false, "authserv-id is not configured; refusing to trust Authentication-Results".into());
    }
    if clauses[0].trim().to_lowercase() != authserv_id.trim().to_lowercase() {
        return (false, "no Authentication-Results from trusted authserv-id".into());
    }
    let mut results: HashMap<&str, Vec<Verdict>> = HashMap::new();
    for clause in &clauses {
        let t = clause.trim_start();
        let low = t.to_lowercase();
        for m in ["dmarc", "dkim", "spf"] {
            let Some(rest) = low.strip_prefix(m) else { continue };
            let rest = rest.trim_start();
            let Some(rest) = rest.strip_prefix('=') else { continue };
            let verdict: String = rest.trim_start().chars().take_while(|c| c.is_ascii_alphabetic()).collect();
            if !verdict.is_empty() {
                results.entry(m).or_default().push((verdict, auth_props(clause)));
            }
            break;
        }
    }
    let aligned = |props: &[(String, String)], names: &[&str], required: bool| {
        let domains: Vec<String> = props.iter().filter(|(p, _)| names.contains(&p.as_str())).map(|(_, v)| domain_of(v)).collect();
        (!domains.is_empty() || !required) && domains.iter().all(|d| aligned_domains(d, &from_domain))
    };
    let dmarc = results.get("dmarc").cloned().unwrap_or_default();
    if dmarc.len() > 1 {
        return (false, "ambiguous dmarc result".into());
    }
    if dmarc.iter().any(|(r, p)| r == "pass" && aligned(p, &["header.from"], false)) {
        return (true, "dmarc=pass".into());
    }
    let spf = results.get("spf").cloned().unwrap_or_default();
    if spf.len() == 1 && spf[0].0 == "pass" && aligned(&spf[0].1, &["smtp.mailfrom", "smtp.from", "envelope-from"], true) {
        return (true, "spf=pass aligned".into());
    }
    let dkim = results.get("dkim").cloned().unwrap_or_default();
    if dkim.iter().any(|(r, p)| r == "pass" && aligned(p, if p.iter().any(|(k, _)| k == "header.d") { &["header.d"] } else { &["header.from"] }, true)) {
        return (true, "dkim=pass aligned".into());
    }
    (false, format!("authentication failed ({})", trusted.chars().take(120).collect::<String>()))
}

// ---------------------------------------------------------------- dates

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];

/// RFC 5322 date in UTC.
pub fn format_date(t: i64) -> String {
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!("{}, {d:02} {} {y} {:02}:{:02}:{:02} +0000", DAYS[days.rem_euclid(7) as usize], MONTHS[(m - 1) as usize], secs / 3600, secs % 3600 / 60, secs % 60)
}

/// RFC 5322 / 2822 date → unix seconds.
pub fn parse_date(s: &str) -> Option<i64> {
    let s = s.split('(').next()?;
    let mut t: Vec<&str> = s.split(|c: char| c.is_whitespace() || c == ',').filter(|x| !x.is_empty()).collect();
    if t.first()?.chars().all(|c| c.is_ascii_alphabetic()) {
        t.remove(0);
    }
    let d: i64 = t.first()?.parse().ok()?;
    let mon = MONTHS.iter().position(|m| t.get(1).is_some_and(|x| x.len() >= 3 && x[..3].eq_ignore_ascii_case(m)))? as i64 + 1;
    let mut y: i64 = t.get(2)?.parse().ok()?;
    if y < 50 {
        y += 2000;
    } else if y < 1000 {
        y += 1900;
    }
    let hms: Vec<i64> = t.get(3)?.split(':').map(|x| x.parse().ok()).collect::<Option<Vec<_>>>()?;
    let (hh, mm, ss) = (*hms.first()?, *hms.get(1)?, hms.get(2).copied().unwrap_or(0));
    let off = match t.get(4).copied().unwrap_or("+0000") {
        z if (z.starts_with('+') || z.starts_with('-')) && z.len() == 5 => {
            let n: i64 = z[1..].parse().ok()?;
            let o = (n / 100) * 3600 + (n % 100) * 60;
            if z.starts_with('-') {
                -o
            } else {
                o
            }
        }
        z => match z.to_ascii_uppercase().as_str() {
            "EDT" => -4 * 3600,
            "EST" | "CDT" => -5 * 3600,
            "CST" | "MDT" => -6 * 3600,
            "MST" | "PDT" => -7 * 3600,
            "PST" => -8 * 3600,
            _ => 0,
        },
    };
    Some(days_from_civil(y, mon, d) * 86400 + hh * 3600 + mm * 60 + ss - off)
}

// ---------------------------------------------------------------- settings

fn d_true() -> bool {
    true
}
fn d_mailbox() -> String {
    "INBOX".into()
}
fn d_poll() -> u64 {
    25
}
fn d_interval() -> u64 {
    15
}
fn d_timeout() -> u64 {
    30
}
fn d_att() -> u64 {
    25
}
fn d_subject() -> String {
    "ark".into()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    address: String,
    password: String,
    /// Login name when it differs from the address.
    #[serde(default)]
    username: Option<String>,
    /// Display name on outgoing mail.
    #[serde(default)]
    from_name: Option<String>,
    imap_host: String,
    #[serde(default)]
    imap_port: Option<u16>,
    /// tls (default) | starttls | plain
    #[serde(default)]
    imap_security: Option<String>,
    /// Without it the channel only receives.
    #[serde(default)]
    smtp_host: Option<String>,
    #[serde(default)]
    smtp_port: Option<u16>,
    /// Default: tls on 465, else starttls.
    #[serde(default)]
    smtp_security: Option<String>,
    #[serde(default = "d_mailbox")]
    mailbox: String,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
    /// Polling period when the server has no IDLE (or `idle = false`).
    #[serde(default = "d_interval")]
    poll_interval_secs: u64,
    #[serde(default = "d_true")]
    idle: bool,
    #[serde(default = "d_timeout")]
    timeout_secs: u64,
    /// Exact authserv-id of the receiving MTA's Authentication-Results (e.g. mx.google.com).
    #[serde(default)]
    authserv_id: Option<String>,
    #[serde(default = "d_true")]
    require_authenticated_sender: bool,
    #[serde(default)]
    skip_attachments: bool,
    /// First run: ignore mail already in the mailbox.
    #[serde(default = "d_true")]
    skip_existing: bool,
    #[serde(default = "d_true")]
    unseen_only: bool,
    #[serde(default = "d_true")]
    strip_quotes: bool,
    #[serde(default = "d_att")]
    max_attachment_mb: u64,
    /// Subject of mail that does not reply to anything.
    #[serde(default = "d_subject")]
    subject: String,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<std::sync::Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let password = ctx.secret("password", &st.password)?;
    let address = st.address.trim().to_string();
    let bad = |e: String| format!("[channels.{}]: {e}", ctx.name);
    let imap_security = Security::parse(st.imap_security.as_deref()).map_err(bad)?.unwrap_or(Security::Tls);
    let imap_port = st.imap_port.unwrap_or(if imap_security == Security::Tls { 993 } else { 143 });
    let smtp_security = Security::parse(st.smtp_security.as_deref()).map_err(bad)?.unwrap_or(if st.smtp_port == Some(465) { Security::Tls } else { Security::StartTls });
    let smtp_port = st.smtp_port.unwrap_or(match smtp_security {
        Security::Tls => 465,
        Security::StartTls => 587,
        Security::Plain => 25,
    });
    let mut cfg = Config::new(&address, &password, st.imap_host.trim());
    cfg.username = st.username.map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).unwrap_or_else(|| address.clone());
    cfg.from_name = st.from_name.unwrap_or_default();
    cfg.imap_port = imap_port;
    cfg.imap_security = imap_security;
    cfg.smtp_host = st.smtp_host.map(|h| h.trim().to_string()).filter(|h| !h.is_empty());
    cfg.smtp_port = smtp_port;
    cfg.smtp_security = smtp_security;
    cfg.mailbox = st.mailbox;
    cfg.poll_timeout = Duration::from_secs(st.poll_timeout_secs.max(1));
    cfg.poll_interval = Duration::from_secs(st.poll_interval_secs.max(1));
    cfg.idle = st.idle;
    cfg.timeout = Duration::from_secs(st.timeout_secs.max(1));
    cfg.authserv_id = st.authserv_id.unwrap_or_default().trim().to_lowercase();
    cfg.require_authenticated_sender = st.require_authenticated_sender;
    cfg.skip_attachments = st.skip_attachments;
    cfg.skip_existing = st.skip_existing;
    cfg.unseen_only = st.unseen_only;
    cfg.strip_quotes = st.strip_quotes;
    cfg.max_attachment_bytes = st.max_attachment_mb.saturating_mul(1024 * 1024);
    cfg.subject = st.subject;
    if cfg.imap_host.is_empty() {
        return Err(bad("imap_host is empty".into()));
    }
    Ok(std::sync::Arc::new(Email::new(ctx.name, cfg, ctx.state("email.json"), ctx.state("email-media"))?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::Arc;

    // ------------------------------------------------------------ fake IMAP server

    #[derive(Default)]
    struct MBox {
        validity: u64,
        next_uid: u64,
        /// (uid, raw, seen)
        msgs: Vec<(u64, Vec<u8>, bool)>,
        password: String,
        idle: bool,
        /// Advertised besides IMAP4rev1 / IDLE.
        extra_caps: &'static str,
        log: Vec<String>,
        logins: usize,
        drop_next: bool,
    }

    struct FakeImap {
        port: u16,
        mb: Arc<Mutex<MBox>>,
    }

    fn crlf(s: &str) -> Vec<u8> {
        s.replace("\r\n", "\n").replace('\n', "\r\n").into_bytes()
    }

    impl FakeImap {
        fn start(idle: bool) -> FakeImap {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = l.local_addr().unwrap().port();
            let mb = Arc::new(Mutex::new(MBox { validity: 7, next_uid: 1, password: "pw".into(), idle, ..Default::default() }));
            let m2 = mb.clone();
            std::thread::spawn(move || {
                for s in l.incoming().flatten() {
                    let m = m2.clone();
                    std::thread::spawn(move || serve_imap(s, m));
                }
            });
            FakeImap { port, mb }
        }
        fn add(&self, raw: &str) -> u64 {
            let mut m = self.mb.lock().unwrap();
            let uid = m.next_uid;
            m.next_uid += 1;
            m.msgs.push((uid, crlf(raw), false));
            uid
        }
        fn log(&self) -> Vec<String> {
            self.mb.lock().unwrap().log.clone()
        }
        fn seen(&self, uid: u64) -> bool {
            self.mb.lock().unwrap().msgs.iter().any(|m| m.0 == uid && m.2)
        }
    }

    /// Some(Some(line)), Some(None) on read timeout, None on EOF.
    fn read_line(s: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Option<String>> {
        loop {
            if let Some(i) = buf.windows(2).position(|w| w == b"\r\n") {
                let line = String::from_utf8_lossy(&buf[..i]).into_owned();
                buf.drain(..i + 2);
                return Some(Some(line));
            }
            let mut c = [0u8; 4096];
            match s.read(&mut c) {
                Ok(0) => return None,
                Ok(n) => buf.extend_from_slice(&c[..n]),
                Err(e) if is_timeout(&e) => return Some(None),
                Err(_) => return None,
            }
        }
    }

    fn next_line(s: &mut TcpStream, buf: &mut Vec<u8>) -> Option<String> {
        loop {
            match read_line(s, buf)? {
                Some(l) => return Some(l),
                None => continue,
            }
        }
    }

    fn quoted_args(s: &str) -> Vec<String> {
        s.split('"').skip(1).step_by(2).map(|x| x.to_string()).collect()
    }

    fn uid_set(s: &str) -> Vec<u64> {
        s.split(',').filter_map(|x| x.parse().ok()).collect()
    }

    fn serve_imap(mut s: TcpStream, mb: Arc<Mutex<MBox>>) {
        s.set_read_timeout(Some(Duration::from_millis(30))).unwrap();
        let (idle, extra) = {
            let m = mb.lock().unwrap();
            (m.idle, m.extra_caps)
        };
        let caps = format!("{}{extra}", if idle { "IMAP4rev1 IDLE " } else { "IMAP4rev1 " });
        let _ = s.write_all(format!("* OK [CAPABILITY {caps}] fake ready\r\n").as_bytes());
        let mut buf = Vec::new();
        loop {
            let Some(line) = next_line(&mut s, &mut buf) else { return };
            let (tag, rest) = line.split_once(' ').unwrap_or((&line, ""));
            let (cmd, args) = rest.split_once(' ').unwrap_or((rest, ""));
            let cmd = cmd.to_ascii_uppercase();
            let mut m = mb.lock().unwrap();
            if m.drop_next {
                m.drop_next = false;
                let _ = s.shutdown(Shutdown::Both);
                return;
            }
            m.log.push(if cmd == "LOGIN" { format!("LOGIN {}", quoted_args(args).first().cloned().unwrap_or_default()) } else { rest.to_string() });
            let mut out: Vec<u8> = Vec::new();
            match cmd.as_str() {
                "CAPABILITY" => out.extend(format!("* CAPABILITY {caps}\r\n{tag} OK done\r\n").bytes()),
                "LOGIN" => {
                    m.logins += 1;
                    let ok = quoted_args(args).get(1) == Some(&m.password);
                    out.extend(if ok { format!("{tag} OK [CAPABILITY {caps}] welcome\r\n") } else { format!("{tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n") }.bytes());
                }
                "SELECT" => out.extend(format!("* {} EXISTS\r\n* OK [UIDVALIDITY {}] v\r\n* OK [UIDNEXT {}] n\r\n{tag} OK [READ-WRITE] selected\r\n", m.msgs.len(), m.validity, m.next_uid).bytes()),
                "NOOP" => out.extend(format!("{tag} OK noop\r\n").bytes()),
                "ID" if caps.contains("ID") => out.extend(format!("* ID (\"name\" \"fake\")\r\n{tag} OK id\r\n").bytes()),
                "LOGOUT" => {
                    let _ = s.write_all(format!("* BYE bye\r\n{tag} OK\r\n").as_bytes());
                    return;
                }
                "UID" => {
                    let (sub, a) = args.split_once(' ').unwrap_or((args, ""));
                    match sub.to_ascii_uppercase().as_str() {
                        "SEARCH" => {
                            let unseen = a.contains("UNSEEN");
                            let from = a.split("UID ").nth(1).and_then(|r| r.split(':').next()).and_then(|n| n.parse().ok()).unwrap_or(1);
                            let mut hits: Vec<u64> = m.msgs.iter().filter(|x| x.0 >= from && (!unseen || !x.2)).map(|x| x.0).collect();
                            // RFC 3501: `n:*` always includes the highest UID.
                            if hits.is_empty() && a.contains(":*") {
                                if let Some(x) = m.msgs.iter().rfind(|x| !unseen || !x.2) {
                                    hits.push(x.0);
                                }
                            }
                            out.extend(format!("* SEARCH{}\r\n{tag} OK search done\r\n", hits.iter().map(|u| format!(" {u}")).collect::<String>()).bytes());
                        }
                        "FETCH" => {
                            let (set, items) = a.split_once(' ').unwrap();
                            for uid in uid_set(set) {
                                let Some((i, x)) = m.msgs.iter().enumerate().find(|(_, x)| x.0 == uid) else { continue };
                                let hdr = items.contains("HEADER");
                                let data = if hdr {
                                    let mut h = split_head(&x.1).0.to_vec();
                                    h.extend_from_slice(b"\r\n\r\n");
                                    h
                                } else {
                                    x.1.clone()
                                };
                                let item = if hdr { format!("RFC822.SIZE {} BODY[HEADER]<0>", x.1.len()) } else { "BODY[]".into() };
                                out.extend(format!("* {} FETCH (UID {uid} {item} {{{}}}\r\n", i + 1, data.len()).bytes());
                                out.extend(&data);
                                out.extend(b")\r\n");
                            }
                            out.extend(format!("{tag} OK fetch done\r\n").bytes());
                        }
                        "STORE" => {
                            let set = uid_set(a.split(' ').next().unwrap());
                            for x in m.msgs.iter_mut().filter(|x| set.contains(&x.0)) {
                                x.2 = true;
                            }
                            out.extend(format!("{tag} OK store\r\n").bytes());
                        }
                        _ => out.extend(format!("{tag} BAD unknown\r\n").bytes()),
                    }
                }
                "IDLE" if m.idle => {
                    let mut known = m.msgs.len();
                    drop(m);
                    let _ = s.write_all(b"+ idling\r\n");
                    loop {
                        match read_line(&mut s, &mut buf) {
                            None => return,
                            Some(Some(l)) if l == "DONE" => {
                                let _ = s.write_all(format!("{tag} OK IDLE terminated\r\n").as_bytes());
                                break;
                            }
                            Some(_) => {
                                let mut g = mb.lock().unwrap();
                                if std::mem::take(&mut g.drop_next) {
                                    let _ = s.shutdown(Shutdown::Both);
                                    return;
                                }
                                let n = g.msgs.len();
                                drop(g);
                                if n > known {
                                    known = n;
                                    let _ = s.write_all(format!("* {n} EXISTS\r\n").as_bytes());
                                }
                            }
                        }
                    }
                    continue;
                }
                _ => out.extend(format!("{tag} BAD unknown command\r\n").bytes()),
            }
            drop(m);
            if s.write_all(&out).is_err() {
                return;
            }
        }
    }

    // ------------------------------------------------------------ fake SMTP server

    struct FakeSmtp {
        port: u16,
        log: Arc<Mutex<Vec<String>>>,
        data: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl FakeSmtp {
        fn start(greeting: &'static str, mechs: &'static str) -> FakeSmtp {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = l.local_addr().unwrap().port();
            let (log, data) = (Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(Vec::new())));
            let (l2, d2) = (log.clone(), data.clone());
            std::thread::spawn(move || {
                for s in l.incoming().flatten() {
                    let (l3, d3) = (l2.clone(), d2.clone());
                    std::thread::spawn(move || serve_smtp(s, greeting, mechs, l3, d3));
                }
            });
            FakeSmtp { port, log, data }
        }
    }

    fn serve_smtp(mut s: TcpStream, greeting: &str, mechs: &str, log: Arc<Mutex<Vec<String>>>, data: Arc<Mutex<Vec<Vec<u8>>>>) {
        s.set_read_timeout(Some(Duration::from_millis(30))).unwrap();
        let _ = s.write_all(format!("{greeting}\r\n").as_bytes());
        if !greeting.starts_with("220") {
            return;
        }
        let mut buf = Vec::new();
        let good = |u: &str, p: &str| u == "bot@ark.test" && p == "pw";
        while let Some(line) = next_line(&mut s, &mut buf) {
            log.lock().unwrap().push(line.clone());
            let up = line.to_ascii_uppercase();
            let reply = if up.starts_with("EHLO") {
                format!("250-fake.test\r\n250-AUTH {mechs}\r\n250 8BITMIME")
            } else if let Some(tok) = line.strip_prefix("AUTH PLAIN ") {
                let d = String::from_utf8(crypto::b64_decode(tok).unwrap()).unwrap();
                let p: Vec<&str> = d.split('\0').collect();
                if p.len() == 3 && good(p[1], p[2]) { "235 2.7.0 ok".into() } else { "535 5.7.8 bad credentials".into() }
            } else if up == "AUTH LOGIN" {
                let mut ask = |prompt: &[u8]| {
                    let _ = s.write_all(prompt);
                    let l = next_line(&mut s, &mut buf).unwrap();
                    log.lock().unwrap().push(l.clone());
                    String::from_utf8(crypto::b64_decode(&l).unwrap()).unwrap()
                };
                let u = ask(b"334 VXNlcm5hbWU6\r\n");
                let p = ask(b"334 UGFzc3dvcmQ6\r\n");
                if good(&u, &p) { "235 2.7.0 ok".into() } else { "535 5.7.8 bad credentials".into() }
            } else if up.starts_with("MAIL FROM") {
                "250 ok".into()
            } else if up.starts_with("RCPT TO") {
                if up.contains("GONE") { "550 5.1.1 user unknown".into() } else { "250 ok".into() }
            } else if up == "DATA" {
                let _ = s.write_all(b"354 go ahead\r\n");
                let mut raw = Vec::new();
                loop {
                    let l = next_line(&mut s, &mut buf).unwrap();
                    if l == "." {
                        break;
                    }
                    log.lock().unwrap().push(format!("D:{l}"));
                    raw.extend_from_slice(l.strip_prefix('.').unwrap_or(&l).as_bytes());
                    raw.extend_from_slice(b"\r\n");
                }
                data.lock().unwrap().push(raw);
                "250 2.0.0 queued".into()
            } else if up == "QUIT" {
                let _ = s.write_all(b"221 bye\r\n");
                return;
            } else {
                "502 unknown".into()
            };
            let _ = s.write_all(format!("{reply}\r\n").as_bytes());
        }
    }

    // ------------------------------------------------------------ helpers

    fn cfg(imap: u16, smtp: u16) -> Config {
        let mut c = Config::new("bot@ark.test", "pw", "127.0.0.1");
        c.imap_port = imap;
        c.imap_security = Security::Plain;
        c.smtp_port = smtp;
        c.smtp_security = Security::Plain;
        c.authserv_id = "mx.ark.test".into();
        c.poll_timeout = Duration::from_millis(800);
        c.poll_interval = Duration::from_millis(100);
        c.timeout = Duration::from_secs(5);
        c
    }

    fn email(c: Config, dir: &std::path::Path) -> Email {
        let mut e = Email::new("mail", c, dir.join("mail.email.json"), dir.join("mail.email-media")).unwrap();
        e.retry_base = Duration::from_millis(10);
        e
    }

    fn simple(from: &str, subject: &str, body: &str, extra: &str) -> String {
        let dom = from.rsplit('@').next().unwrap().trim_end_matches('>');
        format!("Authentication-Results: mx.ark.test; dmarc=pass header.from={dom}\nFrom: {from}\nTo: bot@ark.test\nSubject: {subject}\nMessage-ID: <{}@{dom}>\nDate: Mon, 02 Nov 2026 09:30:00 +0000\n{extra}Content-Type: text/plain; charset=utf-8\n\n{body}\n", crypto::hex(&crypto::random_bytes(4)))
    }

    const RICH: &str = "Authentication-Results: mx.ark.test;\n dkim=pass header.d=example.com;\n spf=pass smtp.mailfrom=amy@example.com;\n dmarc=pass (p=none) header.from=example.com\nAuthentication-Results: evil.test; dmarc=fail\nFrom: =?UTF-8?B?6Zi/576O?= <Amy@Example.com>\nTo: bot@ark.test\nSubject: =?UTF-8?Q?Gr=C3=BC=C3=9Fe?= =?UTF-8?B?IOS9oOWlvQ==?=\nMessage-ID: <m2@example.com>\nIn-Reply-To: <ark.0011223344556677@ark.test>\nReferences: <root@example.com> <ark.0011223344556677@ark.test>\nDate: Tue, 1 Jul 2003 10:52:37 +0200\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"outer\"\n\npreamble\n--outer\nContent-Type: multipart/alternative; boundary=\"inner\"\n\n--inner\nContent-Type: text/plain; charset=iso-8859-1\nContent-Transfer-Encoding: quoted-printable\n\nCaf=E9 au lait, s'il vous pla=EEt. This line is long enough to be soft-=\nwrapped.\n\nOn Mon, 2 Nov 2026 at 09:00, Ark <bot@ark.test> wrote:\n> earlier text\n--inner\nContent-Type: text/html; charset=utf-8\n\n<p>Caf&eacute;</p>\n--inner--\n--outer\nContent-Type: application/pdf; name=\"ignored.pdf\"\nContent-Disposition: attachment; filename*=UTF-8''%E5%A0%B1%E5%91%8A.pdf\nContent-Transfer-Encoding: base64\n\nJVBERi0x\nLjQK\n--outer\nContent-Type: image/png\nContent-Disposition: inline; filename=\"dot.png\"\nContent-Transfer-Encoding: base64\n\niVBORw0K\n--outer--\nepilogue\n";

    // ------------------------------------------------------------ IMAP end-to-end

    #[test]
    fn idle_delivers_rich_mail_commits_on_next_poll_and_survives_restart() {
        let srv = FakeImap::start(true);
        let old = srv.add(&simple("amy@example.com", "old", "already here", ""));
        let dir = temp_dir("email");
        let e = email(cfg(srv.port, 1), &dir);
        let mb = srv.mb.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            let mut m = mb.lock().unwrap();
            let uid = m.next_uid;
            m.next_uid += 1;
            m.msgs.push((uid, crlf(RICH), false));
        });
        let t0 = Instant::now();
        let got = e.poll(&Cancel::new()).unwrap();
        assert!(t0.elapsed() < Duration::from_millis(700), "IDLE wakes on EXISTS: {:?}", t0.elapsed());
        assert_eq!(got.len(), 1, "existing mail skipped on first run");
        let m = &got[0];
        assert_eq!((m.chat.as_str(), m.sender.as_str(), m.sender_name.as_str(), m.chat_type), ("amy@example.com", "amy@example.com", "阿美", ChatType::Direct));
        assert_eq!(m.text, "[Subject: Grüße 你好]\n\nCafé au lait, s'il vous plaît. This line is long enough to be soft-wrapped.", "QP + latin-1 decoded, quote stripped");
        assert_eq!((m.message_id.as_str(), m.thread.as_deref()), ("<m2@example.com>", Some("<root@example.com>")));
        assert!(m.reply.as_ref().unwrap().is_own && m.addressed());
        assert_eq!(m.ts, 1057049557);
        assert_eq!(m.media.len(), 2);
        assert_eq!((m.media[0].name.as_str(), m.media[0].kind, m.media[0].mime.as_str()), ("報告.pdf", MediaKind::Document, "application/pdf"));
        assert_eq!(e.fetch_media(&m.media[0]).unwrap(), b"%PDF-1.4\n");
        assert_eq!((m.media[1].kind, m.media[1].name.as_str()), (MediaKind::Image, "dot.png"));
        assert!(m.media[1].path.as_deref().unwrap().starts_with(dir.join("mail.email-media").to_str().unwrap()));
        let state = dir.join("mail.email.json");
        let st: Value = serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert_eq!((st["uidvalidity"].as_u64(), st["last_uid"].as_u64()), (Some(7), Some(old)), "baseline only; batch not committed yet");
        assert!(!srv.seen(old + 1));
        assert!(srv.log().iter().any(|l| l.contains("BODY.PEEK[HEADER]")) && srv.log().iter().any(|l| l.contains("BODY.PEEK[]")));
        // Next poll commits: \Seen + cursor, then IDLE times out empty.
        assert!(e.poll(&Cancel::new()).unwrap().is_empty());
        assert!(srv.seen(old + 1) && !srv.seen(old), "only delivered mail is marked seen");
        let st: Value = serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert_eq!(st["last_uid"].as_u64(), Some(old + 1));
        // Restart: nothing is delivered twice, even with unseen_only off.
        let mut c = cfg(srv.port, 1);
        c.unseen_only = false;
        let e2 = email(c, &dir);
        assert!(e2.poll(&Cancel::new()).unwrap().is_empty());
        // UIDVALIDITY changes: old UIDs are void, unseen mail is delivered again.
        {
            let mut m = srv.mb.lock().unwrap();
            m.validity = 99;
        }
        let e3 = email(cfg(srv.port, 1), &dir);
        let again = e3.poll(&Cancel::new()).unwrap();
        assert_eq!(again.iter().map(|m| m.text.as_str()).collect::<Vec<_>>(), ["[Subject: old]\n\nalready here"]);
        assert!(e3.poll(&Cancel::new()).unwrap().is_empty());
        let st: Value = serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert_eq!((st["uidvalidity"].as_u64(), st["last_uid"].as_u64()), (Some(99), Some(old)));
    }

    #[test]
    fn automated_list_own_and_unauthenticated_mail_is_consumed_unread() {
        let srv = FakeImap::start(true);
        let auto = srv.add(&simple("amy@example.com", "ooo", "away", "Auto-Submitted: auto-replied\n"));
        let list = srv.add(&simple("amy@example.com", "news", "digest", "List-Unsubscribe: <mailto:u@example.com>\n"));
        let bulk = srv.add(&simple("amy@example.com", "bulk", "promo", "Precedence: bulk\n"));
        let noreply = srv.add(&simple("no-reply@example.com", "receipt", "thanks", ""));
        let own = srv.add(&simple("Bot <BOT@ark.test>", "loop", "mine", ""));
        let forged = srv.add("Authentication-Results: mx.ark.test; dmarc=fail header.from=bank.com; spf=pass smtp.mailfrom=evil.com\nFrom: ceo@bank.com\nSubject: wire\nMessage-ID: <f@x>\n\npay\n");
        let wrong_id = srv.add("Authentication-Results: evil.test; dmarc=pass\nFrom: ceo@bank.com\nSubject: wire\n\npay\n");
        let unsigned = srv.add("From: ceo@bank.com\nSubject: wire\n\npay\n");
        let good = srv.add(&simple("\"Bo, the boss\" <bo@example.org>", "Re: plan", "ok\n\n-- \nBo", ""));
        let dir = temp_dir("email");
        let mut c = cfg(srv.port, 1);
        c.skip_existing = false;
        let e = email(c, &dir);
        let got = e.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!((got[0].sender.as_str(), got[0].sender_name.as_str(), got[0].text.as_str()), ("bo@example.org", "Bo, the boss", "ok"), "Re: subject not prefixed; signature cut");
        let fetched: Vec<String> = srv.log().into_iter().filter(|l| l.contains("BODY.PEEK[]")).collect();
        assert_eq!(fetched, [format!("UID FETCH {good} (UID BODY.PEEK[])")], "rejected mail bodies are never downloaded");
        e.poll(&Cancel::new()).unwrap();
        for uid in [auto, list, bulk, noreply, own, forged, wrong_id, unsigned, good] {
            assert!(srv.seen(uid), "uid {uid} consumed");
        }
        // Trusting From (opt-out) admits the unsigned mail but still drops automated mail.
        let srv2 = FakeImap::start(false);
        srv2.add("From: ceo@bank.com\nSubject: hi\n\nyo\n");
        srv2.add(&simple("amy@example.com", "ooo", "away", "Auto-Submitted: auto-generated\n"));
        let mut c = cfg(srv2.port, 1);
        c.skip_existing = false;
        c.require_authenticated_sender = false;
        let got = email(c, &temp_dir("email")).poll(&Cancel::new()).unwrap();
        assert_eq!(got.iter().map(|m| m.sender.as_str()).collect::<Vec<_>>(), ["ceo@bank.com"]);
    }

    #[test]
    fn bad_login_is_auth_and_unreachable_server_backs_off() {
        let srv = FakeImap::start(true);
        srv.mb.lock().unwrap().password = "other".into();
        let e = email(cfg(srv.port, 1), &temp_dir("email"));
        let err = e.poll(&Cancel::new()).unwrap_err();
        assert_eq!(err.kind, K::Auth, "{err}");
        assert!(!err.message.contains("pw"), "password never echoed: {}", err.message);
        assert_eq!(srv.log(), ["LOGIN bot@ark.test"]);
        // Nothing listens: Network, then the next poll waits out the backoff instead of hammering.
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let mut e = email(cfg(port, 1), &temp_dir("email"));
        e.retry_base = Duration::from_secs(30);
        assert_eq!(e.poll(&Cancel::new()).unwrap_err().kind, K::Network);
        let t0 = Instant::now();
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        assert!(e.poll(&c).unwrap().is_empty());
        assert!(t0.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn cancel_returns_promptly_from_idle() {
        let srv = FakeImap::start(true);
        let mut c = cfg(srv.port, 1);
        c.poll_timeout = Duration::from_secs(20);
        let e = email(c, &temp_dir("email"));
        let cancel = Cancel::new();
        let c2 = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            c2.cancel();
        });
        let t0 = Instant::now();
        assert!(e.poll(&cancel).unwrap().is_empty());
        let el = t0.elapsed();
        assert!(el >= Duration::from_millis(300) && el < Duration::from_millis(550), "{el:?}");
        assert!(srv.log().iter().any(|l| l == "IDLE"));
        // The abandoned IDLE connection is dropped; the next poll logs in again and delivers.
        srv.add(&simple("amy@example.com", "x", "y", ""));
        assert_eq!(e.poll(&Cancel::new()).unwrap().len(), 1);
        assert_eq!(srv.mb.lock().unwrap().logins, 2);
    }

    #[test]
    fn without_idle_polls_on_an_interval() {
        let srv = FakeImap::start(false);
        let e = email(cfg(srv.port, 1), &temp_dir("email"));
        let mb = srv.mb.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            let mut m = mb.lock().unwrap();
            m.next_uid += 1;
            m.msgs.push((1, crlf(&simple("amy@example.com", "ping", "pong", "")), false));
        });
        let got = e.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 1);
        let log = srv.log();
        assert!(log.iter().any(|l| l == "NOOP") && !log.iter().any(|l| l == "IDLE"), "{log:?}");
    }

    #[test]
    fn dropped_connection_reconnects_transparently() {
        let srv = FakeImap::start(true);
        let mut c = cfg(srv.port, 1);
        c.poll_timeout = Duration::from_millis(300);
        let e = email(c, &temp_dir("email"));
        assert!(e.poll(&Cancel::new()).unwrap().is_empty());
        srv.mb.lock().unwrap().drop_next = true;
        srv.add(&simple("amy@example.com", "after outage", "hello", ""));
        let got = e.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(srv.mb.lock().unwrap().logins, 2);
        // The server going away mid-IDLE surfaces as Network; the next poll recovers.
        let srv2 = FakeImap::start(true);
        let mut c = cfg(srv2.port, 1);
        c.poll_timeout = Duration::from_secs(5);
        let e = email(c, &temp_dir("email"));
        let mb = srv2.mb.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            mb.lock().unwrap().drop_next = true;
        });
        let t0 = Instant::now();
        assert_eq!(e.poll(&Cancel::new()).unwrap_err().kind, K::Network);
        assert!(t0.elapsed() < Duration::from_secs(1));
        srv2.add(&simple("amy@example.com", "back", "again", ""));
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(e.poll(&Cancel::new()).unwrap().len(), 1, "reconnected after backoff");
        assert_eq!(srv2.mb.lock().unwrap().logins, 2);
    }

    // ------------------------------------------------------------ SMTP

    #[test]
    fn smtp_reply_threads_dot_stuffs_formats_and_attaches() {
        let smtp = FakeSmtp::start("220 fake ESMTP", "PLAIN LOGIN");
        let dir = temp_dir("email");
        let e = email(cfg(1, smtp.port), &dir);
        let inbound = e.inbound_of(5, 7, &crlf(RICH)).unwrap();
        let f = dir.join("report.txt");
        std::fs::write(&f, b"line1\n.line2\n").unwrap();
        let out = Outbound {
            format: TextFormat::Markdown,
            media: vec![Media { kind: MediaKind::Document, path: Some(f.display().to_string()), ..Default::default() }, Media { kind: MediaKind::Image, url: Some("https://e.com/a.png".into()), ..Default::default() }],
            buttons: vec![vec![crate::Button { label: "Yes".into(), data: "y".into(), url: None }, crate::Button { label: "Docs".into(), data: String::new(), url: Some("https://e.com/d".into()) }]],
            ..Outbound::text("Amy@Example.com", "**Bold** answer\n.hidden dot line\nnaïve")
        };
        let sent = e.send(&out).unwrap();
        assert_eq!(sent.ids.len(), 1);
        // QUIT reaches the server thread asynchronously.
        let t0 = Instant::now();
        while !smtp.log.lock().unwrap().iter().any(|l| l == "QUIT") && t0.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let log = smtp.log.lock().unwrap().clone();
        let cmds: Vec<&str> = log.iter().filter(|l| !l.starts_with("D:")).map(String::as_str).collect();
        let plain = crypto::b64(b"\0bot@ark.test\0pw");
        assert_eq!(cmds, ["EHLO ark.test", &format!("AUTH PLAIN {plain}"), "MAIL FROM:<bot@ark.test>", "RCPT TO:<amy@example.com>", "DATA", "QUIT"]);
        assert!(log.iter().any(|l| l == "D:..hidden dot line"), "dot-stuffed on the wire: {log:?}");
        let raw = smtp.data.lock().unwrap()[0].clone();
        let m = parse_mail(&raw);
        let h = &m.headers;
        assert_eq!(header(h, "subject"), Some("=?UTF-8?B?UmU6IEdyw7zDn2Ug5L2g5aW9?="));
        assert_eq!(decode_words(header(h, "subject").unwrap()), "Re: Grüße 你好");
        assert_eq!(header(h, "in-reply-to"), Some(inbound.message_id.as_str()));
        assert_eq!(header(h, "references"), Some("<root@example.com> <ark.0011223344556677@ark.test> <m2@example.com>"));
        assert_eq!(header(h, "message-id"), sent.first());
        assert_eq!(header(h, "from"), Some("bot@ark.test"));
        assert_eq!(header(h, "to"), Some("amy@example.com"));
        assert!(parse_date(header(h, "date").unwrap()).is_some_and(|t| (t - now_unix()).abs() < 60));
        assert!(m.text.contains("Bold answer\n.hidden dot line\nnaïve") && !m.text.contains("**"), "{}", m.text);
        assert!(m.text.contains("Image: https://e.com/a.png") && m.text.contains("1. Yes") && m.text.contains("2. Docs: https://e.com/d"), "{}", m.text);
        assert!(m.html.contains("<strong>Bold</strong>") || m.html.contains("<b>Bold</b>"), "{}", m.html);
        assert_eq!(m.attachments, vec![Attachment { name: "report.txt".into(), mime: "text/plain".into(), data: b"line1\n.line2\n".to_vec() }]);
        assert!(String::from_utf8_lossy(&raw).contains("multipart/mixed"));
        // A follow-up threads under our own last message.
        let s2 = e.send(&Outbound::text("amy@example.com", "more")).unwrap();
        let raw = smtp.data.lock().unwrap()[1].clone();
        let m = parse_mail(&raw);
        assert_eq!(header(&m.headers, "in-reply-to"), sent.first());
        assert!(header(&m.headers, "references").unwrap().ends_with(sent.first().unwrap()));
        assert_ne!(s2.first(), sent.first());
        // Explicit reply_to wins; a brand-new correspondent gets the default subject.
        e.send(&Outbound { reply_to: Some("<x@y>".into()), ..Outbound::text("new@example.net", "hi") }).unwrap();
        let m = parse_mail(&smtp.data.lock().unwrap()[2]);
        assert_eq!((header(&m.headers, "in-reply-to"), header(&m.headers, "subject")), (Some("<x@y>"), Some("Re: ark")));
        e.send(&Outbound::text("fresh@example.net", "hello")).unwrap();
        let m = parse_mail(&smtp.data.lock().unwrap()[3]);
        assert_eq!((header(&m.headers, "in-reply-to"), header(&m.headers, "subject"), m.text.trim()), (None, Some("ark"), "hello"));
    }

    #[test]
    fn smtp_auth_login_and_error_mapping() {
        let smtp = FakeSmtp::start("220 fake", "LOGIN");
        let e = email(cfg(1, smtp.port), &temp_dir("email"));
        e.send(&Outbound::text("amy@example.com", "x")).unwrap();
        let log = smtp.log.lock().unwrap().clone();
        assert_eq!(&log[1..4], ["AUTH LOGIN", &crypto::b64(b"bot@ark.test"), &crypto::b64(b"pw")]);
        assert_eq!(e.send(&Outbound::text("gone@example.com", "x")).unwrap_err().kind, K::NotFound);
        let mut c = cfg(1, smtp.port);
        c.password = "nope".into();
        let err = email(c, &temp_dir("email")).send(&Outbound::text("amy@example.com", "x")).unwrap_err();
        assert!(err.kind == K::Auth && !err.message.contains("nope"), "{err}");
        let busy = FakeSmtp::start("421 4.7.0 Try again later", "PLAIN");
        assert_eq!(email(cfg(1, busy.port), &temp_dir("email")).send(&Outbound::text("amy@example.com", "x")).unwrap_err().kind, K::RateLimited { retry_after: None });
        let down = FakeSmtp::start("421 service shutting down", "PLAIN");
        assert_eq!(email(cfg(1, down.port), &temp_dir("email")).send(&Outbound::text("amy@example.com", "x")).unwrap_err().kind, K::Network);
        assert_eq!(e.send(&Outbound::text("not an address", "x")).unwrap_err().kind, K::Fatal);
        assert_eq!(e.send(&Outbound::text("a@b.com>\r\nRCPT TO:<c@d.com", "x")).unwrap_err().kind, K::Fatal, "header/command injection");
        let mut c = cfg(1, smtp.port);
        c.smtp_host = None;
        assert_eq!(email(c, &temp_dir("email")).send(&Outbound::text("amy@example.com", "x")).unwrap_err().kind, K::Unsupported);
        let mut c = cfg(1, smtp.port);
        c.smtp_security = Security::StartTls;
        assert_eq!(email(c, &temp_dir("email")).send(&Outbound::text("amy@example.com", "x")).unwrap_err().kind, K::Fatal, "no STARTTLS offered: never downgrade");
    }

    // ------------------------------------------------------------ MIME / headers units

    #[test]
    fn mime_decoding_units() {
        assert_eq!(qp_decode(b"a=3Db=\r\nc=C3=A9 =ZZ", false), "a=bcé =ZZ".as_bytes());
        assert_eq!(decode_words("=?UTF-8?B?5L2g5aW9?= =?UTF-8?Q?caf=C3=A9_ok?= tail"), "你好café ok tail");
        assert_eq!(decode_words("=?iso-8859-1?q?Andr=E9?= Pirard"), "André Pirard");
        assert_eq!(decode_words("a =?bogus b"), "a =?bogus b");
        assert_eq!(decode_charset(&[0x80, 0x93, b'x', 0x94], "Windows-1252"), "€“x”");
        assert_eq!(decode_charset(&[0xa4], "ISO-8859-15"), "€");
        assert_eq!(decode_charset(&[0xe9], "x-unknown-charset"), "\u{fffd}");
        assert_eq!(b64_decode_lenient(b"aGVs\r\nbG8=\r\n"), b"hello");
        let long = format!("{} trailing ", "é".repeat(60));
        let enc = qp_encode(&long);
        assert!(enc.lines().all(|l| l.len() <= 76), "{enc}");
        assert_eq!(String::from_utf8(qp_decode(enc.as_bytes(), false)).unwrap(), long);
        assert_eq!(strip_html("<html><head><style>p{x}</style></head><body><p>Hi&nbsp;&amp; bye</p><br>x&#33;<script>bad()</script></body></html>"), "Hi & bye\n\nx!");
        let m = parse_mail(&crlf(RICH));
        assert!(m.html.contains("Caf&eacute;"));
        assert_eq!(header(&m.headers, "message-id"), Some("<m2@example.com>"));
        assert_eq!(m.attachments.len(), 2);
        let html_only = parse_mail(&crlf("From: a@b.c\nContent-Type: text/html\nContent-Transfer-Encoding: base64\n\nPGI+aGk8L2I+\n"));
        assert_eq!((m.text.is_empty(), strip_html(&html_only.html).as_str()), (false, "hi"));
        // RFC 2231 continuations and RFC 2047 in a filename.
        let (_, p) = parse_params("attachment; filename*0*=utf-8''%E4%BD%A0; filename*1=\"x.txt\"");
        assert_eq!(param(&p, "filename").as_deref(), Some("你x.txt"));
        let (_, p) = parse_params("attachment; filename=\"=?UTF-8?B?5aW9LnR4dA==?=\"");
        assert_eq!(param(&p, "filename").as_deref(), Some("好.txt"));
        // Unterminated multipart keeps its last part.
        assert_eq!(split_multipart(b"--b\r\nA\r\n--b\r\nB", "b"), vec![&b"A"[..], &b"B"[..]]);
        assert_eq!(msg_ids("<a@b>\r\n <c@d>"), ["<a@b>", "<c@d>"]);
    }

    #[test]
    fn cjk_charsets_in_bodies_words_params_and_raw_headers() {
        assert_eq!(decode_charset(&[0xa4, 0xa4, 0xa4, 0xe5], "\"Big5\""), "中文");
        assert_eq!(decode_charset(&[0xd6, 0xd0, 0xce, 0xc4], "GB2312"), "中文");
        assert_eq!(decode_charset(&[0x93, 0xfa, 0x96, 0x7b], "Shift_JIS"), "日本");
        assert_eq!(decode_charset(&[0xc7, 0xd1, 0xb1, 0xb9], "ks_c_5601-1987"), "한국");
        assert_eq!(decode_words("=?big5?B?pKSk5Q==?= =?GB2312?B?1tDOxA==?= =?ISO-2022-JP?B?GyRCRnxLXBsoQg==?= =?euc-kr?B?vsiz5w==?="), "中文中文日本안녕");
        // A Big5 character split across two words, Q and B mixed; other text keeps its spaces.
        assert_eq!(decode_words("Re: =?big5?Q?=B4?=\r\n =?BIG5?B?+rjV?= ok =?utf-8?q?=E4=BD?= =?utf-8?q?=A0?="), "Re: 測試 ok 你");
        assert_eq!(decode_words("=?big5?Q?=B4?= =?utf-8?Q?x?="), "\u{fffd}x", "a dangling lead byte is one error");
        let (_, p) = parse_params("attachment; filename*=gbk''%B8%BD%BC%FE.txt");
        assert_eq!(param(&p, "filename").as_deref(), Some("附件.txt"));
        let (_, p) = parse_params("attachment; filename*0*=big5'zh-TW'%B3; filename*1*=%F8%A7%69.pdf");
        assert_eq!(param(&p, "filename").as_deref(), Some("報告.pdf"), "continuations joined before decoding");
        // Raw 8-bit headers: decoded in the part's charset, multipart tops in the body's; raw ISO-2022-JP anywhere.
        let mut raw = b"From: a@b.c\r\nSubject: ".to_vec();
        raw.extend([0xb7, 0x7c, 0xc4, 0xb3, 0xb3, 0x71, 0xaa, 0xbe]);
        raw.extend(b"\r\nContent-Type: text/plain; charset=big5\r\n\r\n\xa4\xa4\r\n");
        let m = parse_mail(&raw);
        assert_eq!((header(&m.headers, "subject"), m.text.as_str(), m.charset.as_str()), (Some("會議通知"), "中\n", "big5"));
        let mut raw = b"Subject: ".to_vec();
        raw.extend([0x8c, 0x8f, 0x96, 0xbc]);
        raw.extend(b"\nX-Jp: \x1b$BF|K\\\x1b(B\nContent-Type: multipart/alternative; boundary=x\n\n--x\nContent-Type: text/plain; charset=shift_jis\nContent-Disposition: inline; filename=\"");
        raw.extend([0x8c, 0x8f, 0x96, 0xbc]);
        raw.extend(b".txt\"\n\nok\n--x--\n");
        let m = parse_mail(&raw);
        assert_eq!((header(&m.headers, "subject"), header(&m.headers, "x-jp")), (Some("件名"), Some("日本")));
        assert_eq!(header(&parse_headers(b"Subject: \x1b$BF|K\\\x1b(B"), "subject"), Some("日本"));
        // Modified UTF-7 (RFC 3501 §5.1.3 examples).
        assert_eq!(imap_utf7_encode("~peter/mail/台北/日本語"), "~peter/mail/&U,BTFw-/&ZeVnLIqe-");
        assert_eq!(imap_utf7_decode("~peter/mail/&U,BTFw-/&ZeVnLIqe-").as_deref(), Some("~peter/mail/台北/日本語"));
        assert_eq!((imap_utf7_encode("R&D ☺😀"), imap_utf7_decode("&Jjo-!").as_deref()), ("R&-D &JjrYPd4A-".to_string(), Some("☺!")));
        assert_eq!(imap_utf7_decode("R&-D &JjrYPd4A-").as_deref(), Some("R&D ☺😀"));
        assert_eq!([imap_utf7_decode("&ZeVn"), imap_utf7_decode("&Zg-"), imap_utf7_decode("&ZeV/-"), imap_utf7_decode("台")], [None, None, None, None]);
        assert_eq!([imap_mailbox("INBOX"), imap_mailbox("收件匣"), imap_mailbox("&ZTZO9lMj-"), imap_mailbox("R&D")], ["INBOX", "&ZTZO9lMj-", "&ZTZO9lMj-", "R&-D"]);
    }

    #[test]
    fn big5_mail_end_to_end_with_imap_id_and_utf7_mailbox() {
        let srv = FakeImap::start(true);
        srv.mb.lock().unwrap().extra_caps = "ID";
        let dir = temp_dir("email");
        let mut c = cfg(srv.port, 1);
        c.mailbox = "收件匣".into();
        c.skip_existing = false;
        let e = email(c, &dir);
        srv.add("Authentication-Results: mx.ark.test; dmarc=pass header.from=example.tw\nFrom: =?Big5?B?s6+kcKn6?= <ming@example.tw>\nTo: bot@ark.test\nSubject: =?big5?Q?=B4?= =?big5?Q?=FA=B8=D5?=\nMessage-ID: <b5@example.tw>\nDate: Mon, 02 Nov 2026 09:30:00 +0800\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"b5\"\n\n--b5\nContent-Type: text/plain; charset=\"big5\"\nContent-Transfer-Encoding: base64\n\np0GmbqFBs2+sT6SkpOW2bKXzoUMNCq27tOSmcqFHh0ANCg==\n--b5\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename*=big5''%B3%F8%A7%69.txt\nContent-Transfer-Encoding: base64\n\naGk=\n--b5--\n");
        let got = e.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 1);
        let m = &got[0];
        assert_eq!((m.sender.as_str(), m.sender_name.as_str()), ("ming@example.tw", "陳小明"));
        assert_eq!(m.text, "[Subject: 測試]\n\n你好，這是中文郵件。\n香港字：䏰");
        assert_eq!((m.media.len(), m.media[0].name.as_str()), (1, "報告.txt"));
        let log = srv.log();
        let at = |p: &str| log.iter().position(|l| l.starts_with(p)).unwrap_or_else(|| panic!("{p} in {log:?}"));
        assert!(log.contains(&"ID (\"name\" \"ark\" \"version\" \"0.1.0\")".to_string()), "{log:?}");
        assert!(at("LOGIN") < at("ID") && at("ID") < at("SELECT"));
        assert_eq!(log[at("SELECT")], "SELECT \"&ZTZO9lMj-\"");
        // Without the capability no ID is sent.
        let srv2 = FakeImap::start(false);
        let e2 = email(cfg(srv2.port, 1), &dir);
        let _ = e2.poll(&Cancel::new());
        assert!(!srv2.log().iter().any(|l| l.starts_with("ID")));
    }

    #[test]
    fn quoted_replies_are_stripped() {
        assert_eq!(strip_quoted("Sounds good.\n\nOn Mon, Nov 2, 2026 at 9:00 AM Ark <bot@ark.test> wrote:\n> old\n> older"), "Sounds good.");
        assert_eq!(strip_quoted("Yes\nOn Mon, Nov 2, 2026 at 9:00 AM Ark\n<bot@ark.test> wrote:\n> old"), "Yes");
        assert_eq!(strip_quoted("> q1\nanswer 1\n> q2\nanswer 2"), "answer 1\nanswer 2");
        assert_eq!(strip_quoted("ok\n\n-----Original Message-----\nFrom: x"), "ok");
        assert_eq!(strip_quoted("ok\n________________________________\nFrom: Ark\nSent: Monday\nTo: me"), "ok");
        assert_eq!(strip_quoted("好的\n\n在 2026年11月2日 Ark 寫道：\n> 舊"), "好的");
        assert_eq!(strip_quoted("> only quoted"), "> only quoted", "never empty");
    }

    #[test]
    fn dates_round_trip() {
        assert_eq!(parse_date("Tue, 1 Jul 2003 10:52:37 +0200"), Some(1057049557));
        assert_eq!(parse_date("1 Jul 03 08:52:37 GMT"), Some(1057049557));
        assert_eq!(parse_date("Tue, 1 Jul 2003 03:52:37 EST (comment)"), Some(1057049557));
        assert_eq!(format_date(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert_eq!(format_date(1793611800), "Mon, 02 Nov 2026 09:30:00 +0000");
        assert_eq!(parse_date(&format_date(1793611800)), Some(1793611800));
        assert_eq!(parse_date("garbage"), None);
    }

    #[test]
    fn from_addresses_resist_spoofing() {
        assert_eq!(extract_address("\"Amy\" <AMY@Example.com>"), "amy@example.com");
        assert_eq!(extract_address("amy@example.com (Amy)"), "amy@example.com");
        assert_eq!(extract_address("\"boss@corp.com\" <evil@x.com>"), "evil@x.com");
        assert_eq!(extract_address("\"a <boss@corp.com>\" <evil@x.com>"), "evil@x.com");
        assert_eq!(extract_address("Doe, John <j@x.com>"), "j@x.com");
        assert_eq!(extract_address("a@x.com, b@y.com"), "");
        assert_eq!(extract_address("a@x.com, <b@y.com>"), "");
        assert_eq!(extract_address("<a@x.com> <b@y.com>"), "");
        assert_eq!(extract_address("group: a@x.com;"), "");
        assert_eq!(extract_address("John"), "");
        assert_eq!(extract_address(&format!("{} <a@x.com>", "(".repeat(70))), "");
    }

    #[test]
    fn authentication_results_follow_hermes() {
        let h = |v: &[&str]| -> Headers { v.iter().map(|x| ("Authentication-Results".to_string(), x.to_string())).collect() };
        let v = |hs: &[&str], from: &str| verify_sender_authentication(&h(hs), from, "mx.ark.test").0;
        assert!(v(&["mx.ark.test; dmarc=pass header.from=example.com"], "a@example.com"));
        assert!(v(&["MX.ark.test; dmarc=pass"], "a@example.com"), "case-insensitive id, absent header.from trusts the verdict");
        assert!(!v(&["mx.ark.test; dmarc=pass header.from=other.com"], "a@example.com"));
        assert!(!v(&["mx.ark.test; dmarc=pass; dmarc=pass"], "a@example.com"), "ambiguous");
        assert!(!v(&["mx.ark.test; dmarc=fail", "mx.ark.test; dmarc=pass"], "a@example.com"), "only the topmost header counts");
        assert!(!v(&["evil.test; dmarc=pass"], "a@example.com"));
        assert!(v(&["mx.ark.test; spf=pass smtp.mailfrom=bounce@mail.example.com"], "a@example.com"), "relaxed alignment");
        assert!(!v(&["mx.ark.test; spf=pass smtp.mailfrom=x@evil.com"], "a@example.com"));
        assert!(!v(&["mx.ark.test; spf=pass"], "a@example.com"), "spf needs a domain");
        assert!(!v(&["mx.ark.test; spf=pass smtp.mailfrom=a@example.com; spf=fail smtp.mailfrom=a@example.com"], "a@example.com"));
        assert!(v(&["mx.ark.test; dkim=fail header.d=example.com; dkim=pass header.d=example.com"], "a@example.com"));
        assert!(!v(&["mx.ark.test; dkim=pass header.d=other.com header.from=example.com"], "a@example.com"), "header.d decides");
        assert!(!v(&["mx.ark.test; spf=fail smtp.mailfrom=\"x; dmarc=pass\""], "a@example.com"), "quoted ';' does not split");
        assert!(!v(&["mx.ark.test; spf=fail (dmarc=pass) smtp.mailfrom=a@example.com"], "a@example.com"), "comments are not verdicts");
        assert!(!v(&["mx.ark.test; spf=pass smtp.mailfrom=\"a@evil.com header.from=example.com\""], "a@example.com"));
        assert!(!v(&["mx.ark.test; dmarc=pass (unbalanced"], "a@example.com"));
        assert!(!verify_sender_authentication(&h(&["mx.ark.test; dmarc=pass"]), "a@example.com", "").0, "no pin → fail closed");
        assert!(!verify_sender_authentication(&vec![], "a@example.com", "mx.ark.test").0);
    }

    #[test]
    fn imap_literals_and_fetch_items_parse() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.write_all(b"* 1 FETCH (UID 9 BODY[] {5}\r\nab\r\nc)\r\n* 2 FETCH (UID 10 BODY[HEADER] \"q\\\"x\")\r\na1 OK\r\n").unwrap();
            std::thread::sleep(Duration::from_millis(200));
        });
        let s = Stream::connect("127.0.0.1", port, false, Duration::from_secs(2)).unwrap();
        let mut c = Conn::new(s, true);
        let r = c.resp(&Cancel::new(), Duration::from_secs(2)).ok().unwrap();
        assert_eq!((fetch_num(&r.text, "UID"), r.lits.clone()), (Some(9), vec![b"ab\r\nc".to_vec()]));
        let r2 = c.resp(&Cancel::new(), Duration::from_secs(2)).ok().unwrap();
        assert_eq!(fetch_data(&r2, "BODY[HEADER]"), Some(b"q\"x".to_vec()));
        assert_eq!(c.resp(&Cancel::new(), Duration::from_secs(2)).ok().unwrap().text, "a1 OK");
        assert_eq!(code_num("* OK [UIDVALIDITY 3857529045] UIDs valid", "UIDVALIDITY"), Some(3857529045));
        assert_eq!(fetch_num("* 3 FETCH (RFC822.SIZE 44 UID 12)", "UID"), Some(12));
    }

    #[test]
    fn build_parses_settings_and_requires_an_authserv_pin() {
        let dir = temp_dir("email");
        let secrets: crate::config::Secrets = Arc::new(|s: &str| s.replace("{{secret:MAIL}}", "pw"));
        let ctx = crate::config::Ctx { name: "mail", state_dir: &dir, secrets: &secrets };
        let base = json!({"address": "bot@ark.test", "password": "{{secret:MAIL}}", "imap_host": "imap.ark.test", "smtp_host": "smtp.ark.test", "authserv_id": "MX.ark.test", "smtp_port": 465});
        let ch = build(&ctx, base.as_object().unwrap()).ok().unwrap();
        assert_eq!((ch.id(), ch.caps().max_len, ch.caps().media, ch.caps().buttons), ("mail", MAX_MESSAGE, true, false));
        let mut no_pin = base.clone();
        no_pin.as_object_mut().unwrap().remove("authserv_id");
        assert!(build(&ctx, no_pin.as_object().unwrap()).err().unwrap().contains("authserv_id"));
        no_pin["require_authenticated_sender"] = json!(false);
        assert!(build(&ctx, no_pin.as_object().unwrap()).is_ok());
        let mut typo = base.clone();
        typo["imap_securty"] = json!("tls");
        assert!(build(&ctx, typo.as_object().unwrap()).err().unwrap().contains("imap_securty"));
        let mut bad = base.clone();
        bad["smtp_security"] = json!("maybe");
        assert!(build(&ctx, bad.as_object().unwrap()).err().unwrap().contains("maybe"));
        let mut missing = base.clone();
        missing["password"] = json!("{{secret:NOPE}}");
        assert!(build(&ctx, missing.as_object().unwrap()).err().unwrap().contains("not set"));
        // Port/security defaults.
        let st: Settings = ctx.settings(base.as_object().unwrap()).unwrap();
        assert_eq!(Security::parse(st.smtp_security.as_deref()).unwrap(), None);
        assert_eq!(Security::parse(Some("SSL")).unwrap(), Some(Security::Tls));
        assert_eq!(Security::parse(Some("start_tls")).unwrap(), Some(Security::StartTls));
    }
}
