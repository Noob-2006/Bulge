//! Chrome DevTools Protocol client: one browser-level WebSocket, page sessions
//! multiplexed over it with `Target.attachToTarget {flatten: true}` (Hermes
//! `browser_cdp_tool._cdp_call`, OpenClaw `cdp-websocket.ts`, MIT). A single I/O
//! thread owns the socket; callers queue commands and wait for their reply, and every
//! event goes to the handler (the supervisor that records dialogs, console, network…).

use seagent_net::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

/// Event callback: (connection, method, params, sessionId).
pub type EventFn = Arc<dyn Fn(&Conn, &str, &Value, Option<&str>) + Send + Sync>;

struct Inner {
    out: Mutex<Sender<String>>,
    pending: Mutex<HashMap<u64, Sender<Result<Value, String>>>>,
    next: AtomicU64,
    closed: AtomicBool,
    handler: OnceLock<EventFn>,
    url: String,
    /// Live console streams on this connection: while any runs, the I/O thread polls the socket
    /// every [`FAST_POLL`] instead of [`IDLE_POLL`], so a queued frame ack goes out at once.
    fast: AtomicUsize,
}

/// How long the I/O thread waits on the socket before sending what callers queued.
const IDLE_POLL: Duration = Duration::from_millis(15);
const FAST_POLL: Duration = Duration::from_millis(2);

/// A live CDP connection (cheap to clone).
#[derive(Clone)]
pub struct Conn(Arc<Inner>);

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// HTTP agent for DevTools JSON endpoints.
pub fn http(timeout: Duration) -> ureq::Agent {
    seagent_net::http::builder().timeout_global(Some(timeout)).http_status_as_error(false).build().into()
}

/// GET a DevTools JSON endpoint (`/json/version`, `/json/list`).
pub fn get_json(base: &str, path: &str, auth: Option<&str>, timeout: Duration) -> Result<Value, String> {
    let url = format!("{}{path}", base.trim_end_matches('/'));
    let mut req = http(timeout).get(&url);
    if let Some(a) = auth {
        req = req.header("Authorization", a);
    }
    let mut r = req.call().map_err(|e| format!("CDP {base}: {e}"))?;
    let status = r.status().as_u16();
    let body = r.body_mut().read_to_string().map_err(|e| e.to_string())?;
    if status != 200 {
        return Err(format!("CDP {url}: HTTP {status}"));
    }
    serde_json::from_str(&body).map_err(|e| format!("CDP {url}: {e}"))
}

/// Browser WebSocket URL for an endpoint: `ws(s)://…/devtools/browser/…` as is,
/// `http(s)://host:port` (or a bare `ws://host:port`) through `/json/version` (Hermes
/// `_resolve_cdp_override`).
pub fn resolve_ws(endpoint: &str, auth: Option<&str>, timeout: Duration) -> Result<String, String> {
    let e = endpoint.trim();
    if e.contains("/devtools/") && (e.starts_with("ws://") || e.starts_with("wss://")) {
        return Ok(e.to_string());
    }
    let http_base = if let Some(r) = e.strip_prefix("ws://") {
        format!("http://{}", r.split('/').next().unwrap_or(r))
    } else if let Some(r) = e.strip_prefix("wss://") {
        format!("https://{}", r.split('/').next().unwrap_or(r))
    } else if e.starts_with("http://") || e.starts_with("https://") {
        let (scheme, rest) = e.split_once("://").unwrap();
        format!("{scheme}://{}", rest.split('/').next().unwrap_or(rest))
    } else {
        return Err(format!("CDP endpoint must be http(s):// or ws(s)://, got `{e}`"));
    };
    let v = get_json(&http_base, "/json/version", auth, timeout)?;
    let ws = v["webSocketDebuggerUrl"].as_str().ok_or("/json/version has no webSocketDebuggerUrl")?;
    // Chrome answers with its own idea of the host (often 127.0.0.1 behind a port map):
    // keep the host:port we reached and take only the path.
    let path = ws.splitn(4, '/').nth(3).unwrap_or("");
    let host = http_base.split_once("://").map(|(_, h)| h).unwrap_or("");
    let scheme = if http_base.starts_with("https") { "wss" } else { "ws" };
    Ok(format!("{scheme}://{host}/{path}"))
}

impl Conn {
    /// Connect to a browser-level (or page-level) DevTools WebSocket.
    pub fn connect(ws_url: &str, headers: &[(&str, &str)], timeout: Duration) -> Result<Conn, String> {
        let (mut ws, _) = WebSocket::connect(ws_url, headers, timeout).map_err(|e| format!("CDP connect {}: {e}", redact_url(ws_url)))?;
        ws.set_max_message(256 << 20);
        ws.set_read_timeout(Some(IDLE_POLL)).map_err(|e| e.to_string())?;
        let (tx, rx) = mpsc::channel::<String>();
        let inner = Arc::new(Inner { out: Mutex::new(tx), pending: Mutex::new(HashMap::new()), next: AtomicU64::new(1), closed: AtomicBool::new(false), handler: OnceLock::new(), url: ws_url.to_string(), fast: AtomicUsize::new(0) });
        let weak = Arc::downgrade(&inner);
        std::thread::Builder::new().name("seagent-cdp".into()).spawn(move || io_loop(ws, rx, weak)).map_err(|e| e.to_string())?;
        Ok(Conn(inner))
    }

    /// Install the event handler (once).
    pub fn on_event(&self, f: EventFn) {
        let _ = self.0.handler.set(f);
    }

    /// A live stream starts (`true`) or ends (`false`) on this connection: low-latency polling
    /// runs only while at least one does (it costs nothing otherwise).
    pub fn low_latency(&self, on: bool) {
        if on {
            self.0.fast.fetch_add(1, Ordering::SeqCst);
        } else {
            // Never below zero (an unbalanced call must not wrap around).
            let mut n = self.0.fast.load(Ordering::SeqCst);
            while n > 0 {
                match self.0.fast.compare_exchange(n, n - 1, Ordering::SeqCst, Ordering::SeqCst) {
                    Ok(_) => break,
                    Err(cur) => n = cur,
                }
            }
        }
    }

    pub fn is_low_latency(&self) -> bool {
        self.0.fast.load(Ordering::SeqCst) > 0
    }

    pub fn url(&self) -> &str {
        &self.0.url
    }

    pub fn is_closed(&self) -> bool {
        self.0.closed.load(Ordering::SeqCst)
    }

    pub fn close(&self) {
        self.0.closed.store(true, Ordering::SeqCst);
        let _ = self.0.out.lock().unwrap().send(String::new());
    }

    fn queue(&self, method: &str, params: Value, session: Option<&str>) -> Result<(u64, Receiver<Result<Value, String>>), String> {
        if self.is_closed() {
            return Err("browser connection is closed".into());
        }
        let id = self.0.next.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        self.0.pending.lock().unwrap().insert(id, tx);
        let mut m = json!({"id": id, "method": method, "params": params});
        if let Some(s) = session {
            m["sessionId"] = s.into();
        }
        self.0.out.lock().unwrap().send(m.to_string()).map_err(|_| "browser connection is closed".to_string())?;
        Ok((id, rx))
    }

    /// Fire and forget (from event handlers: they run on the I/O thread and must not wait).
    pub fn send_nowait(&self, method: &str, params: Value, session: Option<&str>) {
        if let Ok((id, _rx)) = self.queue(method, params, session) {
            // Reply is dropped on arrival.
            self.0.pending.lock().unwrap().remove(&id);
        }
    }

    pub fn call(&self, method: &str, params: Value, session: Option<&str>) -> Result<Value, String> {
        self.call_with(method, params, session, DEFAULT_TIMEOUT, &|| None)
    }

    /// Send and wait; `abort` is polled while waiting (a modal dialog blocks page
    /// commands until it is answered, so the caller can give up early).
    pub fn call_with(&self, method: &str, params: Value, session: Option<&str>, timeout: Duration, abort: &dyn Fn() -> Option<String>) -> Result<Value, String> {
        let (id, rx) = self.queue(method, params, session)?;
        let until = Instant::now() + timeout;
        loop {
            match rx.recv_timeout(Duration::from_millis(40)) {
                Ok(r) => return r.map_err(|e| format!("CDP {method}: {e}")),
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(format!("CDP {method}: browser connection closed")),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            if let Some(why) = abort() {
                self.0.pending.lock().unwrap().remove(&id);
                return Err(why);
            }
            if Instant::now() >= until {
                self.0.pending.lock().unwrap().remove(&id);
                return Err(format!("CDP {method}: timed out after {}s", timeout.as_secs()));
            }
        }
    }
}

fn io_loop(mut ws: WebSocket<seagent_net::Stream>, rx: Receiver<String>, weak: Weak<Inner>) {
    let fail = |weak: &Weak<Inner>, why: &str| {
        if let Some(i) = weak.upgrade() {
            i.closed.store(true, Ordering::SeqCst);
            for (_, tx) in i.pending.lock().unwrap().drain() {
                let _ = tx.send(Err(why.to_string()));
            }
        }
    };
    let mut fast = false;
    loop {
        if let Some(i) = weak.upgrade() {
            let want = i.fast.load(Ordering::Relaxed) > 0;
            if want != fast {
                fast = want;
                let _ = ws.set_read_timeout(Some(if fast { FAST_POLL } else { IDLE_POLL }));
            }
        }
        loop {
            match rx.try_recv() {
                Ok(m) if m.is_empty() => {
                    let _ = ws.send(&Message::Close(None));
                    fail(&weak, "browser connection closed");
                    return;
                }
                Ok(m) => {
                    if let Err(e) = ws.send_text(&m) {
                        fail(&weak, &format!("browser connection lost: {e}"));
                        return;
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        }
        let msg = match ws.recv() {
            Ok(Some(Message::Text(t))) => t,
            Ok(Some(Message::Close(_))) => {
                fail(&weak, "browser closed the DevTools connection");
                return;
            }
            Ok(_) => {
                if weak.strong_count() == 0 {
                    return;
                }
                continue;
            }
            Err(e) => {
                fail(&weak, &format!("browser connection lost: {e}"));
                return;
            }
        };
        let Some(inner) = weak.upgrade() else { return };
        let v: Value = serde_json::from_str(&msg).unwrap_or_default();
        if let Some(id) = v["id"].as_u64() {
            if let Some(tx) = inner.pending.lock().unwrap().remove(&id) {
                let r = match v.get("error") {
                    Some(e) => Err(e["message"].as_str().unwrap_or("error").to_string() + &e["data"].as_str().map(|d| format!(" ({d})")).unwrap_or_default()),
                    None => Ok(v["result"].clone()),
                };
                let _ = tx.send(r);
            }
            continue;
        }
        if let (Some(method), Some(h)) = (v["method"].as_str(), inner.handler.get().cloned()) {
            let conn = Conn(inner.clone());
            h(&conn, method, &v["params"], v["sessionId"].as_str());
        }
    }
}

/// Mask credentials in a CDP URL for messages (Hermes `redact_cdp_url`).
pub fn redact_url(u: &str) -> String {
    let mut s = u.to_string();
    if let Some((scheme, rest)) = u.split_once("://") {
        if let Some((auth, host)) = rest.split_once('@') {
            if !auth.contains('/') {
                s = format!("{scheme}://***@{host}");
            }
        }
    }
    // Cloud connect URLs carry the key in the query string.
    if let Some((base, q)) = s.split_once('?') {
        let masked: Vec<String> = q
            .split('&')
            .map(|kv| match kv.split_once('=') {
                Some((k, _)) if ["apikey", "api_key", "token", "key", "signingkey", "auth"].contains(&k.to_ascii_lowercase().as_str()) => format!("{k}=***"),
                _ => kv.to_string(),
            })
            .collect();
        s = format!("{base}?{}", masked.join("&"));
    }
    s
}

#[cfg(any(test, feature = "test-util"))]
pub mod fake {
    //! A scriptable fake DevTools endpoint: `/json/version`, `/json/list` and a
    //! browser-level WebSocket whose replies come from a handler.
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// Handler: (method, params, sessionId) → (result, extra events to emit after it).
    pub type Script = Arc<dyn Fn(&str, &Value, Option<&str>) -> (Value, Vec<Value>) + Send + Sync>;

    pub struct Fake {
        pub http: String,
        pub seen: Arc<Mutex<Vec<Value>>>,
    }

    pub fn start(script: Script) -> Fake {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { break };
                let script = script.clone();
                let seen = seen2.clone();
                std::thread::spawn(move || {
                    let Ok((head, rest)) = seagent_net::ws::read_head(&mut s, 1 << 16) else { return };
                    if head.starts_with("GET /json/version") {
                        let body = json!({"Browser": "FakeChrome/1.0", "webSocketDebuggerUrl": format!("ws://127.0.0.1:{port}/devtools/browser/fake")}).to_string();
                        let _ = write!(s, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                        return;
                    }
                    if head.starts_with("GET /json") {
                        let (r, _) = script("http:/json/list", &Value::Null, None);
                        let body = r.to_string();
                        let _ = write!(s, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                        return;
                    }
                    let Ok(mut ws) = WebSocket::accept(s, &head, rest) else { return };
                    ws.set_max_message(64 << 20);
                    while let Ok(m) = ws.recv_blocking() {
                        let Message::Text(t) = m else { break };
                        let v: Value = serde_json::from_str(&t).unwrap();
                        seen.lock().unwrap().push(v.clone());
                        let (result, events) = script(v["method"].as_str().unwrap_or(""), &v["params"], v["sessionId"].as_str());
                        let mut reply = if result.get("__error").is_some() { json!({"id": v["id"], "error": {"message": result["__error"]}}) } else { json!({"id": v["id"], "result": result}) };
                        if let Some(sid) = v.get("sessionId") {
                            reply["sessionId"] = sid.clone();
                        }
                        if result.get("__noreply").is_none() && ws.send_text(&reply.to_string()).is_err() {
                            break;
                        }
                        for e in events {
                            if ws.send_text(&e.to_string()).is_err() {
                                break;
                            }
                        }
                    }
                });
            }
        });
        Fake { http: format!("http://127.0.0.1:{port}"), seen }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_and_multiplexes_sessions() {
        let f = fake::start(Arc::new(|m, p, s| match m {
            "Target.attachToTarget" => (json!({"sessionId": format!("S-{}", p["targetId"].as_str().unwrap())}), vec![]),
            "Runtime.evaluate" => (json!({"result": {"value": s.unwrap_or("none")}}), vec![json!({"method": "Runtime.consoleAPICalled", "params": {"type": "log"}, "sessionId": s})]),
            "Bad.method" => (json!({"__error": "'Bad.method' wasn't found"}), vec![]),
            "Hang.forever" => (json!({"__noreply": true}), vec![]),
            _ => (json!({}), vec![]),
        }));
        let ws = resolve_ws(&f.http, None, Duration::from_secs(5)).unwrap();
        assert!(ws.starts_with("ws://127.0.0.1:") && ws.ends_with("/devtools/browser/fake"));
        assert_eq!(resolve_ws("ws://h:1/devtools/browser/x", None, Duration::from_secs(1)).unwrap(), "ws://h:1/devtools/browser/x");
        assert!(resolve_ws("ftp://x", None, Duration::from_secs(1)).is_err());
        let c = Conn::connect(&ws, &[], Duration::from_secs(5)).unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let e2 = events.clone();
        c.on_event(Arc::new(move |_c, m, _p, s| e2.lock().unwrap().push((m.to_string(), s.map(str::to_string)))));
        let sid = c.call("Target.attachToTarget", json!({"targetId": "T1", "flatten": true}), None).unwrap()["sessionId"].as_str().unwrap().to_string();
        assert_eq!(sid, "S-T1");
        assert_eq!(c.call("Runtime.evaluate", json!({"expression": "1"}), Some(&sid)).unwrap()["result"]["value"], "S-T1");
        assert!(c.call("Bad.method", json!({}), None).unwrap_err().contains("wasn't found"));
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(events.lock().unwrap()[0], ("Runtime.consoleAPICalled".to_string(), Some("S-T1".to_string())));
        assert_eq!(c.call_with("Hang.forever", json!({}), None, Duration::from_secs(5), &|| Some("blocked by a dialog".into())).unwrap_err(), "blocked by a dialog");
        c.close();
        assert!(c.call("Browser.getVersion", json!({}), None).is_err());
    }

    #[test]
    fn redacts_credentials_in_urls() {
        assert_eq!(redact_url("http://u:pw@127.0.0.1:9222"), "http://***@127.0.0.1:9222");
        assert_eq!(redact_url("wss://connect.browserbase.com?apiKey=bb_live_1&sessionId=2"), "wss://connect.browserbase.com?apiKey=***&sessionId=2");
    }
}
