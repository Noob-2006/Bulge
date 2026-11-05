//! Outbound delivery shared by every channel: split to the channel's limit,
//! retry transient failures inline (exponential backoff, honouring
//! `retry_after` up to 60 s), fall back to plain text when the platform
//! rejects formatting, and park what still fails in a persistent outbox that
//! is swept later and resent with a visible marker. Chats that no longer
//! exist are remembered as dead and never retried.

use crate::{chunk, write_atomic, Channel, ChannelError, ChannelErrorKind as K, Outbound, Sent, Streaming, TextFormat};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const INLINE_RETRIES: u32 = 2;
const MAX_INLINE_WAIT: Duration = Duration::from_secs(60);
const OUTBOX_ATTEMPTS: u32 = 3;
const OUTBOX_MAX_AGE: i64 = 24 * 3600;
const OUTBOX_BACKOFF: [i64; 3] = [30, 120, 600];
const OUTBOX_MAX: usize = 500;
pub const RESENT_MARKER: &str = "（補送）";

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Parked {
    pub channel: String,
    pub out: Outbound,
    pub attempts: u32,
    pub next_at: i64,
    pub created: i64,
    pub last_error: String,
}

#[derive(Default, Serialize, Deserialize)]
struct Book {
    #[serde(default)]
    parked: Vec<Parked>,
    #[serde(default)]
    dead: BTreeSet<String>,
}

pub struct Deliverer {
    path: Option<PathBuf>,
    book: Mutex<Book>,
    pub retry_base: Duration,
}

impl Deliverer {
    /// `path` = outbox file; `None` keeps everything in memory (tests, one-shot CLI sends).
    pub fn new(path: Option<PathBuf>) -> Deliverer {
        let book = path.as_ref().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        Deliverer { path, book: Mutex::new(book), retry_base: Duration::from_secs(2) }
    }

    fn save(&self, b: &Book) {
        if let Some(p) = &self.path {
            let _ = write_atomic(p, serde_json::to_string(b).unwrap_or_default().as_bytes());
        }
    }

    pub fn parked(&self) -> Vec<Parked> {
        self.book.lock().unwrap().parked.clone()
    }

    pub fn is_dead(&self, channel: &str, chat: &str) -> bool {
        self.book.lock().unwrap().dead.contains(&format!("{channel}\u{1f}{chat}"))
    }

    /// Split and send. On a retryable failure the remaining pieces are parked and the error returned.
    pub fn send(&self, ch: &dyn Channel, out: &Outbound) -> Result<Sent, ChannelError> {
        if self.is_dead(ch.id(), &out.chat) {
            return Err(ChannelError::new(K::NotFound, format!("chat {} on {} is gone; not sending", out.chat, ch.id())));
        }
        let caps = ch.caps();
        let mut pieces = chunk::split(&out.text, caps.max_len, caps.len_unit);
        if pieces.is_empty() {
            if out.media.is_empty() && out.buttons.is_empty() {
                return Ok(Sent::default());
            }
            pieces.push(String::new());
        }
        let n = pieces.len();
        let mut sent = Sent::default();
        for (i, text) in pieces.into_iter().enumerate() {
            let piece = Outbound {
                text,
                reply_to: if i == 0 { out.reply_to.clone() } else { None },
                media: if i == 0 { out.media.clone() } else { vec![] },
                buttons: if i + 1 == n { out.buttons.clone() } else { vec![] },
                ..out.clone()
            };
            match self.send_one(ch, &piece) {
                Ok(s) => sent.ids.extend(s.ids),
                Err(e) => {
                    if e.kind == K::NotFound {
                        let mut b = self.book.lock().unwrap();
                        b.dead.insert(format!("{}\u{1f}{}", ch.id(), out.chat));
                        self.save(&b);
                    } else if e.is_retryable() {
                        self.park(ch.id(), piece, &e);
                    }
                    return Err(e);
                }
            }
        }
        Ok(sent)
    }

    fn send_one(&self, ch: &dyn Channel, out: &Outbound) -> Result<Sent, ChannelError> {
        let mut attempt = 0;
        let mut out = out.clone();
        loop {
            match ch.send(&out) {
                Ok(s) => return Ok(s),
                // Formatting rejected: retry once as plain text.
                Err(e) if e.kind == K::Protocol && out.format == TextFormat::Markdown => {
                    eprintln!("seagent: {}: formatting rejected ({}); resending as plain text", ch.id(), e.message);
                    out.format = TextFormat::Plain;
                }
                Err(e) if e.is_retryable() && attempt < INLINE_RETRIES => {
                    let wait = match e.kind {
                        K::RateLimited { retry_after: Some(d) } if d > MAX_INLINE_WAIT => return Err(e),
                        K::RateLimited { retry_after: Some(d) } => d,
                        _ => self.retry_base * 2u32.pow(attempt),
                    };
                    std::thread::sleep(wait);
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn park(&self, channel: &str, out: Outbound, e: &ChannelError) {
        let t = now();
        let mut b = self.book.lock().unwrap();
        if b.parked.len() >= OUTBOX_MAX {
            b.parked.remove(0);
        }
        b.parked.push(Parked { channel: channel.into(), out, attempts: 0, next_at: t + OUTBOX_BACKOFF[0], created: t, last_error: e.message.chars().take(300).collect() });
        self.save(&b);
    }

    /// Resend parked messages that are due. `find` maps a channel id to the live channel.
    /// Returns (delivered, abandoned).
    pub fn sweep(&self, find: &dyn Fn(&str) -> Option<std::sync::Arc<dyn Channel>>) -> (usize, usize) {
        self.sweep_at(now(), find)
    }

    pub fn sweep_at(&self, t: i64, find: &dyn Fn(&str) -> Option<std::sync::Arc<dyn Channel>>) -> (usize, usize) {
        let due: Vec<(usize, Parked)> = {
            let b = self.book.lock().unwrap();
            b.parked.iter().cloned().enumerate().filter(|(_, p)| p.next_at <= t).collect()
        };
        let (mut ok, mut gone) = (0, 0);
        let mut keep: Vec<Option<Parked>> = self.book.lock().unwrap().parked.iter().cloned().map(Some).collect();
        for (i, mut p) in due {
            if t - p.created > OUTBOX_MAX_AGE || p.attempts >= OUTBOX_ATTEMPTS {
                keep[i] = None;
                gone += 1;
                continue;
            }
            let Some(ch) = find(&p.channel) else { continue };
            let mut out = p.out.clone();
            if !out.text.starts_with(RESENT_MARKER) {
                out.text = format!("{RESENT_MARKER}{}", out.text);
            }
            match ch.send(&out) {
                Ok(_) => {
                    keep[i] = None;
                    ok += 1;
                }
                Err(e) if e.is_retryable() => {
                    p.attempts += 1;
                    p.next_at = t + OUTBOX_BACKOFF[(p.attempts as usize).min(OUTBOX_BACKOFF.len() - 1)];
                    p.last_error = e.message.chars().take(300).collect();
                    keep[i] = Some(p);
                }
                Err(_) => {
                    keep[i] = None;
                    gone += 1;
                }
            }
        }
        let mut b = self.book.lock().unwrap();
        // Messages parked during the sweep were appended after the snapshot; keep them.
        let added: Vec<Parked> = b.parked.iter().skip(keep.len()).cloned().collect();
        b.parked = keep.into_iter().flatten().chain(added).collect();
        self.save(&b);
        (ok, gone)
    }
}

enum Mode {
    Idle,
    Off,
    Native(String),
    Edit(String),
}

/// One reply streamed while the model writes it: the channel's native stream hooks
/// (`Caps::streaming == Native`), else one message edited in place (`Edit`), with
/// updates throttled to `interval`. Channels that cannot stream make every call a
/// no-op and `finish` returns false, so the caller sends the reply normally.
pub struct Stream {
    ch: std::sync::Arc<dyn Channel>,
    base: Outbound,
    mode: Mode,
    shown: String,
    last: Option<Instant>,
    pub interval: Duration,
    /// Don't open a message for less text than this (short replies are sent whole).
    pub min_chars: usize,
}

pub const STREAM_CURSOR: &str = " …";

impl Stream {
    /// `base` carries chat / thread / reply_to / format; its text is ignored.
    pub fn new(ch: std::sync::Arc<dyn Channel>, base: Outbound) -> Stream {
        let c = ch.caps();
        let able = match c.streaming {
            Streaming::None => false,
            Streaming::Edit => c.edit,
            Streaming::Native => true,
        };
        Stream { ch, base, mode: if able { Mode::Idle } else { Mode::Off }, shown: String::new(), last: None, interval: Duration::from_millis(1200), min_chars: 24 }
    }

    pub fn active(&self) -> bool {
        matches!(self.mode, Mode::Native(_) | Mode::Edit(_))
    }

    fn delta(&self, text: &str) -> String {
        match text.strip_prefix(self.shown.as_str()) {
            Some(d) => d.to_string(),
            // Text was replaced (a new model step): append-only streams start a new paragraph.
            None => format!("\n\n{text}"),
        }
    }

    /// Show `text` (everything so far). Throttled; errors stop streaming silently.
    pub fn update(&mut self, text: &str) {
        if matches!(self.mode, Mode::Off) || text.trim().chars().count() < self.min_chars || text == self.shown {
            return;
        }
        if self.last.is_some_and(|t| t.elapsed() < self.interval) {
            return;
        }
        let caps = self.ch.caps();
        let fits = chunk::split(text, caps.max_len.saturating_sub(4), caps.len_unit).len() <= 1;
        let ok = match &self.mode {
            Mode::Idle => {
                let out = Outbound { text: text.to_string(), buttons: vec![], media: vec![], ..self.base.clone() };
                let native = if caps.streaming == Streaming::Native { self.ch.stream_begin(&out).ok().flatten() } else { None };
                match native {
                    Some(h) => {
                        self.mode = Mode::Native(h);
                        true
                    }
                    None if caps.edit && fits => match self.ch.send(&Outbound { text: format!("{text}{STREAM_CURSOR}"), ..out }) {
                        Ok(s) if s.first().is_some() => {
                            self.mode = Mode::Edit(s.first().unwrap_or_default().to_string());
                            true
                        }
                        _ => false,
                    },
                    None => false,
                }
            }
            Mode::Native(h) => self.ch.stream_update(&self.base.chat, h, text, &self.delta(text)).is_ok(),
            // Past the length limit: hold until `finish` splits it.
            Mode::Edit(_) if !fits => return,
            Mode::Edit(id) => self.ch.edit(&self.base.chat, id, &format!("{text}{STREAM_CURSOR}")).is_ok(),
            Mode::Off => false,
        };
        if ok {
            self.shown = text.to_string();
            self.last = Some(Instant::now());
        } else if matches!(self.mode, Mode::Idle) {
            self.mode = Mode::Off;
        }
    }

    /// Put the final text in place. Returns false when nothing was streamed or the stream
    /// broke (the caller then sends `text` normally; a broken partial is deleted if possible).
    pub fn finish(&mut self, text: &str, d: &Deliverer) -> bool {
        let caps = self.ch.caps();
        let mode = std::mem::replace(&mut self.mode, Mode::Off);
        match mode {
            Mode::Native(h) => self.ch.stream_finish(&self.base.chat, &h, text, &self.delta(text)).is_ok(),
            Mode::Edit(id) => {
                let pieces = chunk::split(text, caps.max_len, caps.len_unit);
                let Some(first) = pieces.first() else { return false };
                if self.ch.edit(&self.base.chat, &id, first).is_err() {
                    let _ = self.ch.delete(&self.base.chat, &id);
                    return false;
                }
                let rest = pieces[1..].join("\n");
                if !rest.trim().is_empty() || !self.base.buttons.is_empty() {
                    let _ = d.send(self.ch.as_ref(), &Outbound { text: rest, reply_to: None, ..self.base.clone() });
                }
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;
    use crate::{Caps, Inbound};
    use seagent_core::Cancel;
    use std::sync::Arc;

    /// Fails with the queued errors first, then succeeds.
    struct Flaky {
        errors: Mutex<Vec<ChannelError>>,
        got: Mutex<Vec<Outbound>>,
        max: usize,
    }
    impl Channel for Flaky {
        fn id(&self) -> &str {
            "f"
        }
        fn poll(&self, _: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
            Ok(vec![])
        }
        fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
            if let Some(e) = self.errors.lock().unwrap().pop() {
                return Err(e);
            }
            let mut g = self.got.lock().unwrap();
            g.push(out.clone());
            Ok(Sent::one(g.len().to_string()))
        }
        fn caps(&self) -> Caps {
            Caps { max_len: self.max, ..Caps::default() }
        }
    }

    fn flaky(errors: Vec<ChannelError>, max: usize) -> Flaky {
        Flaky { errors: Mutex::new(errors), got: Mutex::new(vec![]), max }
    }

    fn fast(d: Deliverer) -> Deliverer {
        Deliverer { retry_base: Duration::from_millis(1), ..d }
    }

    #[test]
    fn splits_attaches_media_first_buttons_last_and_retries_inline() {
        let f = flaky(vec![ChannelError::new(K::Network, "blip")], 40);
        let d = fast(Deliverer::new(None));
        let out = Outbound {
            text: format!("{}\n\n{}", "a".repeat(30), "b".repeat(30)),
            reply_to: Some("9".into()),
            media: vec![crate::Media { path: Some("/x.png".into()), ..Default::default() }],
            buttons: vec![vec![crate::Button { label: "ok".into(), data: "d".into(), url: None }]],
            ..Outbound::text("c", "")
        };
        let s = d.send(&f, &out).unwrap();
        assert_eq!(s.ids.len(), 2);
        let g = f.got.lock().unwrap();
        assert_eq!((g[0].reply_to.as_deref(), g[0].media.len(), g[0].buttons.len()), (Some("9"), 1, 0));
        assert_eq!((g[1].reply_to.as_deref(), g[1].media.len(), g[1].buttons.len()), (None, 0, 1));
    }

    #[test]
    fn markdown_rejection_falls_back_to_plain() {
        let f = flaky(vec![ChannelError::new(K::Protocol, "can't parse entities")], 4000);
        let d = Deliverer::new(None);
        d.send(&f, &Outbound { format: TextFormat::Markdown, ..Outbound::text("c", "*x") }).unwrap();
        assert_eq!(f.got.lock().unwrap()[0].format, TextFormat::Plain);
        let hard = flaky(vec![ChannelError::new(K::Protocol, "bad")], 4000);
        assert!(d.send(&hard, &Outbound::text("c", "plain")).is_err(), "plain text protocol errors are final");
    }

    #[test]
    fn persistent_failure_parks_then_sweep_resends_with_marker() {
        let dir = temp_dir("outbox");
        let path = dir.join("outbox.json");
        let errs = (0..3).map(|_| ChannelError::new(K::Network, "down")).collect();
        let f = Arc::new(flaky(errs, 4000));
        let d = fast(Deliverer::new(Some(path.clone())));
        assert!(d.send(f.as_ref(), &Outbound::text("c", "hello")).is_err());
        assert_eq!(d.parked().len(), 1);
        // Survives restart.
        let d = fast(Deliverer::new(Some(path)));
        let ch: Arc<dyn Channel> = f.clone();
        let find = |id: &str| (id == "f").then(|| ch.clone());
        assert_eq!(d.sweep_at(now(), &find), (0, 0), "not due yet");
        assert_eq!(d.sweep_at(now() + 31, &find), (1, 0));
        assert!(d.parked().is_empty());
        assert_eq!(f.got.lock().unwrap()[0].text, format!("{RESENT_MARKER}hello"));
    }

    /// Records sends and edits; `native` turns on the stream hooks.
    struct Ed {
        log: Mutex<Vec<String>>,
        streaming: crate::Streaming,
        fail_edit: bool,
    }
    impl Channel for Ed {
        fn id(&self) -> &str {
            "e"
        }
        fn poll(&self, _: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
            Ok(vec![])
        }
        fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
            self.log.lock().unwrap().push(format!("send:{}", out.text));
            Ok(Sent::one("m1"))
        }
        fn edit(&self, _: &str, id: &str, text: &str) -> Result<(), ChannelError> {
            if self.fail_edit {
                return Err(ChannelError::new(K::Protocol, "no"));
            }
            self.log.lock().unwrap().push(format!("edit:{id}:{text}"));
            Ok(())
        }
        fn delete(&self, _: &str, id: &str) -> Result<(), ChannelError> {
            self.log.lock().unwrap().push(format!("delete:{id}"));
            Ok(())
        }
        fn caps(&self) -> Caps {
            Caps { edit: true, delete: true, streaming: self.streaming, max_len: 60, ..Caps::default() }
        }
        fn stream_begin(&self, out: &Outbound) -> Result<Option<String>, ChannelError> {
            self.log.lock().unwrap().push(format!("begin:{}", out.text));
            Ok(Some("s1".into()))
        }
        fn stream_update(&self, _: &str, h: &str, _: &str, delta: &str) -> Result<(), ChannelError> {
            self.log.lock().unwrap().push(format!("append:{h}:{delta}"));
            Ok(())
        }
        fn stream_finish(&self, _: &str, h: &str, _: &str, delta: &str) -> Result<(), ChannelError> {
            self.log.lock().unwrap().push(format!("stop:{h}:{delta}"));
            Ok(())
        }
    }

    #[test]
    fn stream_edits_in_place_throttled_and_splits_on_finish() {
        let ch = Arc::new(Ed { log: Mutex::new(vec![]), streaming: crate::Streaming::Edit, fail_edit: false });
        let d = Deliverer::new(None);
        let mut s = Stream::new(ch.clone(), Outbound::text("c", ""));
        s.min_chars = 5;
        s.update("hi");
        assert!(!s.active(), "too short to open");
        s.update("hello world");
        s.update("hello world, more"); // throttled
        s.interval = Duration::ZERO;
        s.update("hello world, more text");
        assert!(s.finish(&format!("{} {}", "a".repeat(50), "b".repeat(50)), &d));
        let log = ch.log.lock().unwrap().clone();
        assert_eq!(log[0], format!("send:hello world{STREAM_CURSOR}"));
        assert_eq!(log[1], format!("edit:m1:hello world, more text{STREAM_CURSOR}"));
        assert!(log[2].starts_with("edit:m1:aaaa") && log[3].starts_with("send:bbbb"), "{log:?}");
        assert_eq!(log.len(), 4);
        // Nothing streamed → caller sends normally.
        let mut quiet = Stream::new(ch.clone(), Outbound::text("c", ""));
        assert!(!quiet.finish("short", &d));
        // A plain channel never streams.
        let plain = Arc::new(flaky(vec![], 4000));
        let mut p = Stream::new(plain.clone(), Outbound::text("c", ""));
        p.update("plenty of text to stream here");
        assert!(!p.active() && plain.got.lock().unwrap().is_empty());
        // Broken edit: the partial is deleted and the caller resends.
        let bad = Arc::new(Ed { log: Mutex::new(vec![]), streaming: crate::Streaming::Edit, fail_edit: true });
        let mut b = Stream::new(bad.clone(), Outbound::text("c", ""));
        b.update("plenty of text to stream here");
        assert!(!b.finish("final", &d));
        assert_eq!(bad.log.lock().unwrap().last().unwrap(), "delete:m1");
    }

    #[test]
    fn stream_native_hooks_get_deltas() {
        let ch = Arc::new(Ed { log: Mutex::new(vec![]), streaming: crate::Streaming::Native, fail_edit: false });
        let mut s = Stream::new(ch.clone(), Outbound::text("c", ""));
        s.interval = Duration::ZERO;
        s.update("first part of the answer");
        s.update("first part of the answer, second");
        assert!(s.finish("first part of the answer, second. end", &Deliverer::new(None)));
        assert_eq!(*ch.log.lock().unwrap(), vec!["begin:first part of the answer", "append:s1:, second", "stop:s1:. end"]);
    }

    #[test]
    fn long_rate_limits_park_and_dead_chats_stop() {
        let f = flaky(vec![ChannelError::new(K::RateLimited { retry_after: Some(Duration::from_secs(600)) }, "flood")], 4000);
        let d = Deliverer::new(None);
        assert!(d.send(&f, &Outbound::text("c", "x")).is_err());
        assert_eq!(d.parked().len(), 1, "flood control beyond 60s goes to the outbox");
        let gone = flaky(vec![ChannelError::new(K::NotFound, "chat not found")], 4000);
        assert!(d.send(&gone, &Outbound::text("dead", "x")).is_err());
        assert!(d.is_dead("f", "dead"));
        assert_eq!(d.send(&gone, &Outbound::text("dead", "y")).unwrap_err().kind, K::NotFound);
        assert!(gone.got.lock().unwrap().is_empty(), "never retried");
        // Expired entries are abandoned.
        let ch: Arc<dyn Channel> = Arc::new(flaky(vec![], 4000));
        assert_eq!(d.sweep_at(now() + OUTBOX_MAX_AGE + 10, &|_| Some(ch.clone())), (0, 1));
    }
}
