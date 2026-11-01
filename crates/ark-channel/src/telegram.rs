//! Telegram Bot API: long-poll `getUpdates`, plain-text `sendMessage`.
//! Delivery is at-least-once: a batch's offset is committed to the state file
//! only when the caller polls again, so a crash redelivers (the router dedups).

use crate::http::{agent, post_cancellable};
use crate::{sleep_cancellable, write_atomic, Channel, ChannelError, ChannelErrorKind as K, Inbound, Outbound};
use ark_core::Cancel;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

pub const DEFAULT_BASE: &str = "https://api.telegram.org";
/// Telegram counts message length in UTF-16 code units.
pub const MAX_MESSAGE: usize = 4096;

pub struct Telegram {
    id: String,
    token: String,
    base: String,
    state: PathBuf,
    poll_timeout: u64,
    agent: ureq::Agent,
    /// First retry delay; doubles each attempt.
    pub retry_base: Duration,
    pub max_retries: u32,
    /// Longest `retry_after` honoured in place; longer waits surface as `RateLimited`.
    pub max_wait: Duration,
    offset: Mutex<Offsets>,
}

struct Offsets {
    committed: i64,
    pending: Option<i64>,
}

impl Telegram {
    /// `state` is a small JSON file holding the next update offset.
    pub fn new(id: &str, token: &str, base: Option<&str>, state: PathBuf, poll_timeout_secs: u64) -> Result<Self, String> {
        if token.trim().is_empty() {
            return Err(format!("channel {id}: telegram token is empty"));
        }
        let committed = match std::fs::read_to_string(&state) {
            Ok(s) => serde_json::from_str::<Value>(&s).ok().and_then(|v| v["offset"].as_i64()).unwrap_or(0),
            Err(_) => 0,
        };
        Ok(Telegram {
            id: id.to_string(),
            token: token.trim().to_string(),
            base: base.unwrap_or(DEFAULT_BASE).trim_end_matches('/').to_string(),
            state,
            poll_timeout: poll_timeout_secs,
            agent: agent(Duration::from_secs(poll_timeout_secs + 15)),
            retry_base: Duration::from_millis(500),
            max_retries: 4,
            max_wait: Duration::from_secs(60),
            offset: Mutex::new(Offsets { committed, pending: None }),
        })
    }

    /// One Bot API call with retries. `Ok(None)` = cancelled.
    fn call(&self, method: &str, body: &Value, cancel: &Cancel) -> Result<Option<Value>, ChannelError> {
        let url = format!("{}/bot{}/{method}", self.base, self.token);
        let bytes = serde_json::to_vec(body).expect("json");
        let mut attempt = 0;
        loop {
            let err = match post_cancellable(&self.agent, &url, &[], bytes.clone(), cancel)? {
                None => return Ok(None),
                Some(r) => {
                    let v: Option<Value> = serde_json::from_str(&r.body).ok();
                    let desc = v.as_ref().and_then(|v| v["description"].as_str()).unwrap_or("").to_string();
                    match r.status {
                        200 if v.as_ref().is_some_and(|v| v["ok"] == true) => return Ok(Some(v.unwrap()["result"].clone())),
                        200 => ChannelError::new(K::Protocol, format!("{method}: unexpected response {}", crate::http::redact(&r.body.chars().take(200).collect::<String>()))),
                        401 | 404 => return Err(ChannelError::new(K::Auth, format!("telegram rejected the bot token ({} {desc})", r.status))),
                        409 => return Err(ChannelError::new(K::Fatal, format!("telegram conflict: {desc} (another poller or a webhook is active)"))),
                        429 => {
                            let ra = v.as_ref().and_then(|v| v["parameters"]["retry_after"].as_u64()).map(Duration::from_secs).or(r.retry_after);
                            ChannelError::new(K::RateLimited { retry_after: ra }, format!("{method}: rate limited {desc}"))
                        }
                        s if s >= 500 => ChannelError::new(K::Network, format!("{method}: HTTP {s} {desc}")),
                        s => return Err(ChannelError::new(K::Protocol, format!("{method}: HTTP {s} {desc}"))),
                    }
                }
            };
            let err = match err.kind {
                K::Protocol => return Err(err),
                _ => err,
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

    fn commit_pending(&self) -> Result<i64, ChannelError> {
        let mut o = self.offset.lock().unwrap();
        if let Some(p) = o.pending.take() {
            write_atomic(&self.state, json!({ "offset": p }).to_string().as_bytes()).map_err(|e| ChannelError::new(K::Fatal, format!("saving telegram offset: {e}")))?;
            o.committed = p;
        }
        Ok(o.committed)
    }
}

/// Text (or a media caption) from one update; other update kinds are skipped.
fn inbound_of(channel: &str, u: &Value) -> Option<Inbound> {
    let m = u.get("message")?;
    let text = m["text"].as_str().or_else(|| m["caption"].as_str())?;
    let id_str = |v: &Value| v.as_i64().map(|n| n.to_string()).or_else(|| v.as_str().map(str::to_string));
    let from = &m["from"];
    Some(Inbound {
        channel: channel.to_string(),
        chat: id_str(&m["chat"]["id"])?,
        sender: id_str(&from["id"]).unwrap_or_default(),
        sender_name: from["username"].as_str().or_else(|| from["first_name"].as_str()).unwrap_or("").to_string(),
        text: text.to_string(),
        message_id: id_str(&m["message_id"]).unwrap_or_default(),
        ts: m["date"].as_i64().unwrap_or(0),
    })
}

/// Split into pieces of at most `max` UTF-16 units, preferring newline boundaries.
pub fn chunk(text: &str, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let mut units = 0;
        let mut cut = rest.len();
        for (i, c) in rest.char_indices() {
            units += c.len_utf16();
            if units > max {
                cut = i;
                break;
            }
        }
        if cut < rest.len() {
            // Prefer the last newline in the back half of the piece.
            if let Some(nl) = rest[..cut].rfind('\n').filter(|&nl| nl >= cut / 2) {
                cut = nl + 1;
            }
        }
        let piece = &rest[..cut];
        if !piece.trim().is_empty() {
            out.push(piece.trim_end_matches('\n').to_string());
        }
        rest = &rest[cut..];
    }
    out
}

impl Channel for Telegram {
    fn id(&self) -> &str {
        &self.id
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let offset = self.commit_pending()?;
        let body = json!({ "offset": offset, "timeout": self.poll_timeout, "allowed_updates": ["message"] });
        let Some(result) = self.call("getUpdates", &body, cancel)? else { return Ok(vec![]) };
        let updates = result.as_array().ok_or_else(|| ChannelError::new(K::Protocol, "getUpdates: result is not an array"))?;
        let mut max = None;
        let mut out = vec![];
        for u in updates {
            let Some(uid) = u["update_id"].as_i64() else { continue };
            max = max.max(Some(uid));
            if let Some(m) = inbound_of(&self.id, u) {
                out.push(m);
            }
        }
        if let Some(m) = max {
            self.offset.lock().unwrap().pending = Some(m + 1);
        }
        Ok(out)
    }

    fn send(&self, out: &Outbound) -> Result<(), ChannelError> {
        let cancel = Cancel::new();
        for (i, piece) in chunk(&out.text, MAX_MESSAGE).into_iter().enumerate() {
            let mut body = json!({ "chat_id": out.chat, "text": piece });
            if let (0, Some(r)) = (i, out.reply_to.as_deref().and_then(|r| r.parse::<i64>().ok())) {
                body["reply_parameters"] = json!({ "message_id": r, "allow_sending_without_reply": true });
            }
            self.call("sendMessage", &body, &cancel)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn tg(url: &str, state: PathBuf) -> Telegram {
        let mut t = Telegram::new("tg", "123:SECRET", Some(url), state, 1).unwrap();
        t.retry_base = Duration::from_millis(5);
        t
    }

    fn ok(result: Value) -> (u16, Vec<(String, String)>, String) {
        (200, vec![], json!({"ok": true, "result": result}).to_string())
    }

    fn update(id: i64, text: &str) -> Value {
        json!({"update_id": id, "message": {"message_id": id * 10, "date": 1700000000, "chat": {"id": -100, "type": "group"}, "from": {"id": 42, "username": "amy"}, "text": text}})
    }

    #[test]
    fn polls_parses_skips_non_text_and_persists_offset_across_restart() {
        let srv = FakeServer::start(|req, _| {
            let off = req.json()["offset"].as_i64().unwrap();
            match off {
                0 => ok(json!([update(5, "hi"), {"update_id": 6, "message": {"message_id": 1, "chat": {"id": 1}, "sticker": {}}}, {"update_id": 7, "edited_message": {}}, {"update_id": 8, "message": {"message_id": 2, "chat": {"id": 9}, "from": {"id": 3, "first_name": "Bo"}, "caption": "photo cap"}}])),
                _ => ok(json!([])),
            }
        });
        let dir = temp_dir("tg");
        let state = dir.join("tg.json");
        let t = tg(&srv.url, state.clone());
        let got = t.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 2, "sticker and edit skipped, caption kept");
        assert_eq!((got[0].chat.as_str(), got[0].sender.as_str(), got[0].sender_name.as_str(), got[0].message_id.as_str()), ("-100", "42", "amy", "50"));
        assert_eq!(got[1].text, "photo cap");
        assert!(!state.exists(), "offset is committed only on the next poll (at-least-once)");
        // Crash before the next poll → a fresh instance redelivers.
        let t2 = tg(&srv.url, state.clone());
        assert_eq!(t2.poll(&Cancel::new()).unwrap().len(), 2);
        // Next poll commits; a restart then continues past it.
        assert!(t2.poll(&Cancel::new()).unwrap().is_empty());
        assert_eq!(std::fs::read_to_string(&state).unwrap(), r#"{"offset":9}"#);
        let t3 = tg(&srv.url, state);
        assert!(t3.poll(&Cancel::new()).unwrap().is_empty());
        let offs: Vec<i64> = srv.requests().iter().map(|r| r.json()["offset"].as_i64().unwrap()).collect();
        assert_eq!(offs, [0, 0, 9, 9]);
        assert!(srv.requests()[0].path.ends_with("/bot123:SECRET/getUpdates"));
    }

    #[test]
    fn rate_limit_honours_retry_after_then_succeeds() {
        let srv = FakeServer::start(|_, n| match n {
            0 => (429, vec![], json!({"ok": false, "error_code": 429, "description": "Too Many Requests", "parameters": {"retry_after": 1}}).to_string()),
            _ => ok(json!({"message_id": 1})),
        });
        let t = tg(&srv.url, temp_dir("tg").join("s"));
        let start = std::time::Instant::now();
        t.send(&Outbound { chat: "1".into(), text: "x".into(), reply_to: None }).unwrap();
        assert!(start.elapsed() >= Duration::from_millis(950), "waited retry_after");
        assert_eq!(srv.requests().len(), 2);
    }

    #[test]
    fn long_retry_after_surfaces_instead_of_blocking() {
        let srv = FakeServer::start(|_, _| (429, vec![], json!({"ok": false, "parameters": {"retry_after": 3600}}).to_string()));
        let t = tg(&srv.url, temp_dir("tg").join("s"));
        let e = t.send(&Outbound { chat: "1".into(), text: "x".into(), reply_to: None }).unwrap_err();
        assert_eq!(e.kind, K::RateLimited { retry_after: Some(Duration::from_secs(3600)) });
        assert!(e.is_retryable());
    }

    #[test]
    fn auth_conflict_and_bad_request_are_not_retried() {
        for (status, kind) in [(401, K::Auth), (404, K::Auth), (409, K::Fatal), (400, K::Protocol)] {
            let srv = FakeServer::start(move |_, _| (status, vec![], json!({"ok": false, "description": "nope"}).to_string()));
            let t = tg(&srv.url, temp_dir("tg").join("s"));
            let e = t.poll(&Cancel::new()).unwrap_err();
            assert_eq!(e.kind, kind, "{status}");
            assert!(!e.message.contains("SECRET"), "token never in errors: {}", e.message);
            assert_eq!(srv.requests().len(), 1, "{status} not retried");
        }
    }

    #[test]
    fn server_errors_and_garbage_retry_with_backoff_then_give_up() {
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        let srv = FakeServer::start(move |_, _| {
            n2.fetch_add(1, Ordering::SeqCst);
            (502, vec![], "<html>bad gateway</html>".into())
        });
        let t = tg(&srv.url, temp_dir("tg").join("s"));
        let e = t.poll(&Cancel::new()).unwrap_err();
        assert_eq!(e.kind, K::Network);
        assert_eq!(n.load(Ordering::SeqCst), 5, "1 + max_retries");
        // Unreachable host → Network, no token leak.
        let t = tg("http://127.0.0.1:1", temp_dir("tg").join("s"));
        let e = t.poll(&Cancel::new()).unwrap_err();
        assert_eq!(e.kind, K::Network);
        assert!(!e.message.contains("SECRET"), "{}", e.message);
    }

    #[test]
    fn cancel_interrupts_a_blocked_long_poll() {
        // A server that never answers.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            let _keep: Vec<_> = l.incoming().take(3).collect();
            std::thread::sleep(Duration::from_secs(30));
        });
        let t = tg(&url, temp_dir("tg").join("s"));
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let start = std::time::Instant::now();
        assert!(t.poll(&c).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn send_chunks_long_text_and_replies_once() {
        let srv = FakeServer::start(|_, _| ok(json!({})));
        let t = tg(&srv.url, temp_dir("tg").join("s"));
        let line = "word ".repeat(19) + "\n"; // 96 chars
        let text = line.repeat(105); // ~10k
        t.send(&Outbound { chat: "-100".into(), text: text.clone(), reply_to: Some("77".into()) }).unwrap();
        let reqs = srv.requests();
        assert_eq!(reqs.len(), 3);
        let parts: Vec<String> = reqs.iter().map(|r| r.json()["text"].as_str().unwrap().to_string()).collect();
        assert!(parts.iter().all(|p| p.encode_utf16().count() <= MAX_MESSAGE));
        assert!(parts[0].ends_with("word "), "split on a newline");
        assert_eq!(parts.concat().replace('\n', ""), text.replace('\n', ""));
        assert_eq!(reqs[0].json()["reply_parameters"]["message_id"], 77);
        assert!(reqs[1].json().get("reply_parameters").is_none());
        assert_eq!(reqs[0].json()["chat_id"], "-100");
        // Empty text sends nothing.
        t.send(&Outbound { chat: "1".into(), text: "  \n".into(), reply_to: None }).unwrap();
        assert_eq!(srv.requests().len(), 3);
    }

    #[test]
    fn chunk_counts_utf16_and_hard_splits_without_newlines() {
        let s = "😀".repeat(3000); // 6000 UTF-16 units
        let c = chunk(&s, MAX_MESSAGE);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].chars().count(), 2048);
        assert_eq!(c.concat(), s);
        assert_eq!(chunk("short", 10), ["short"]);
        assert!(Telegram::new("t", " ", None, temp_dir("tg").join("s"), 1).is_err());
    }
}
