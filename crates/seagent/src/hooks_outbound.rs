//! Outbound webhooks (Hermes agent/outbound_webhooks.py, `hooks.outbound`): hook events
//! POSTed to URLs, notify-only. Fire-and-forget through a bounded queue and one worker so a
//! slow target never blocks a tool call; HMAC-SHA256 signed when a secret is set.
//!
//! ```toml
//! [[hooks_extra.outbound]]
//! url = "https://hooks.example.com/seagent"   # http(s) only; http:// warns (payloads unencrypted)
//! events = ["pre_tool", "session_end"]    # any hook event name or upstream alias (required)
//! name = "audit"                          # label for logs (default: the url)
//! secret_env = "SEAGENT_HOOK_SECRET"          # env var holding the HMAC secret (wins over `secret`)
//! secret = "{{secret:HOOK_SECRET}}"       # inline secret, vault references allowed
//! matcher = "shell|write"                 # tool-name regex, pre_tool / post_tool only
//! timeout = 10                            # seconds, clamped to 1..=60 (default 10)
//! ```
//!
//! Request: `POST` JSON `{hook_event_name, ...payload, delivery_id, timestamp}` with
//! `X-Seagent-Event`, `X-Seagent-Delivery` and `X-Seagent-Signature-256: sha256=<hex HMAC(body)>`.
//! Retries once on connection errors and 5xx (1 s backoff); 3xx (not followed) and 4xx are final.

use seagent_kernel::config::Config;
use seagent_kernel::hooks::{Hook, HookDecision, HookEvent};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const DEFAULT_TIMEOUT_SECONDS: u64 = 10;
pub const MAX_TIMEOUT_SECONDS: u64 = 60;
pub const MAX_DELIVERY_ATTEMPTS: u32 = 2;
pub const RETRY_BACKOFF: Duration = Duration::from_secs(1);
pub const QUEUE_MAX_SIZE: usize = 256;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OutboundCfg {
    pub url: String,
    pub events: Vec<String>,
    pub name: String,
    pub secret: String,
    pub secret_env: String,
    pub matcher: Option<String>,
    pub timeout: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub url: String,
    pub events: Vec<HookEvent>,
    pub name: String,
    pub secret: Option<String>,
    pub matcher: Option<String>,
    compiled: Option<regex::Regex>,
    pub timeout: u64,
}

impl Target {
    pub fn label(&self) -> &str {
        if self.name.is_empty() {
            &self.url
        } else {
            &self.name
        }
    }
    /// Hermes `matches_tool`: full match; a regex that failed to compile compares literally.
    pub fn matches_tool(&self, tool: Option<&str>) -> bool {
        let Some(m) = &self.matcher else { return true };
        let Some(t) = tool else { return false };
        match &self.compiled {
            Some(r) => r.is_match(t),
            None => t == m,
        }
    }
}

/// Validate `[[hooks_extra.outbound]]`; malformed entries are skipped with a warning.
pub fn targets(raw: &[OutboundCfg], cfg: &Config) -> (Vec<Target>, Vec<String>) {
    let _ = cfg;
    let mut out = Vec::new();
    let mut warn = Vec::new();
    for (i, r) in raw.iter().enumerate() {
        let w = |m: String| format!("hooks_extra.outbound[{i}]{m}");
        let url = r.url.trim();
        if url.is_empty() {
            warn.push(w(" is missing a non-empty 'url'".into()));
            continue;
        }
        let lower = url.to_ascii_lowercase();
        if !(lower.starts_with("http://") || lower.starts_with("https://")) {
            warn.push(w(format!(".url must be http(s); got {url:?} — skipped")));
            continue;
        }
        if lower.starts_with("http://") {
            warn.push(w(".url uses plain http:// — payloads (including tool inputs) travel unencrypted. Prefer https.".into()));
        }
        if r.events.is_empty() {
            warn.push(w(" needs a non-empty 'events' list".into()));
            continue;
        }
        let mut events = Vec::new();
        for e in &r.events {
            match HookEvent::parse(e) {
                Some(ev) if !events.contains(&ev) => events.push(ev),
                Some(_) => {}
                None => warn.push(w(format!(": unknown event {e:?} ignored"))),
            }
        }
        if events.is_empty() {
            warn.push(w(" has no valid events — skipped".into()));
            continue;
        }
        let mut matcher = r.matcher.as_deref().map(str::trim).filter(|m| !m.is_empty()).map(String::from);
        if matcher.is_some() && !events.iter().any(|e| matches!(e, HookEvent::PreTool | HookEvent::PostTool)) {
            warn.push(w(format!(".matcher={:?} will be ignored — matcher is only honored for pre_tool / post_tool.", matcher.as_deref().unwrap_or(""))));
            matcher = None;
        }
        let compiled = matcher.as_ref().and_then(|m| match regex::Regex::new(&format!("^(?:{m})$")) {
            Ok(r) => Some(r),
            Err(e) => {
                warn.push(w(format!(".matcher {m:?} is invalid ({e}) — treating as literal equality")));
                None
            }
        });
        let secret = if !r.secret_env.trim().is_empty() {
            let s = std::env::var(r.secret_env.trim()).ok().filter(|s| !s.is_empty());
            if s.is_none() {
                warn.push(w(format!(".secret_env={:?} is not set in the environment — deliveries will be UNSIGNED", r.secret_env.trim())));
            }
            s
        } else {
            Some(r.secret.clone()).filter(|s| !s.is_empty())
        };
        let timeout = r.timeout.unwrap_or(DEFAULT_TIMEOUT_SECONDS as i64).clamp(1, MAX_TIMEOUT_SECONDS as i64) as u64;
        out.push(Target { url: url.to_string(), events, name: r.name.trim().to_string(), secret, matcher, compiled, timeout });
    }
    (out, warn)
}

/// One queued POST.
#[derive(Debug, Clone)]
pub struct Delivery {
    pub url: String,
    pub label: String,
    pub event: String,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
    pub timeout: u64,
}

pub fn serialize(event: HookEvent, payload: &Value, delivery_id: &str) -> Vec<u8> {
    let mut v = json!({"hook_event_name": event.name()});
    if let (Some(o), Value::Object(p)) = (v.as_object_mut(), payload) {
        for (k, val) in p {
            o.insert(k.clone(), val.clone());
        }
    }
    v["delivery_id"] = delivery_id.into();
    v["timestamp"] = crate::hooks_ext::now_iso().into();
    serde_json::to_vec(&v).unwrap_or_default()
}

pub fn sign(secret: &str, body: &[u8]) -> String {
    format!("sha256={}", seagent_net::crypto::hex(&seagent_net::crypto::hmac_sha256(secret.as_bytes(), body)))
}

pub fn build(event: HookEvent, t: &Target, body: Vec<u8>, delivery_id: &str, secrets: &dyn Fn(&str) -> String) -> Delivery {
    let mut headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("User-Agent".into(), "seagent-Outbound-Webhook".into()),
        ("X-Seagent-Event".into(), event.name()),
        ("X-Seagent-Delivery".into(), delivery_id.to_string()),
    ];
    if let Some(s) = &t.secret {
        headers.push(("X-Seagent-Signature-256".into(), sign(&secrets(s), &body)));
    }
    Delivery { url: t.url.clone(), label: t.label().to_string(), event: event.name(), body, headers, timeout: t.timeout }
}

/// POST with bounded retries. Ok(status) on 2xx; Err(last error) otherwise.
pub fn deliver(d: &Delivery, backoff: Duration) -> Result<u16, String> {
    let agent: ureq::Agent = seagent_net::http::builder().http_status_as_error(false).max_redirects(0).timeout_global(Some(Duration::from_secs(d.timeout))).build().into();
    let mut last = String::new();
    for attempt in 1..=MAX_DELIVERY_ATTEMPTS {
        let mut req = agent.post(&d.url);
        for (k, v) in &d.headers {
            req = req.header(k, v);
        }
        match req.send(&d.body[..]) {
            Ok(r) => {
                let s = r.status().as_u16();
                if (200..300).contains(&s) {
                    return Ok(s);
                }
                last = format!("HTTP {s}");
                if (300..400).contains(&s) {
                    let loc = r.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("?").to_string();
                    return Err(format!("{last} redirect to {loc} not followed — update the configured url"));
                }
                if (400..500).contains(&s) {
                    return Err(format!("{last} — rejected, not retrying"));
                }
            }
            Err(e) => last = e.to_string(),
        }
        if attempt < MAX_DELIVERY_ATTEMPTS {
            std::thread::sleep(backoff * attempt);
        }
    }
    Err(format!("failed after {MAX_DELIVERY_ATTEMPTS} attempt(s): {last}"))
}

struct Queue {
    tx: Mutex<Option<SyncSender<Delivery>>>,
    pending: Arc<(Mutex<usize>, std::sync::Condvar)>,
}

pub struct Outbound {
    targets: Vec<Target>,
    q: Queue,
    secrets: Arc<dyn Fn(&str) -> String + Send + Sync>,
    backoff: Duration,
}

impl Outbound {
    /// `secrets` resolves `{{secret:NAME}}` in inline secrets.
    pub fn with(targets: Vec<Target>, secrets: Arc<dyn Fn(&str) -> String + Send + Sync>, backoff: Duration) -> Outbound {
        Outbound { targets, q: Queue { tx: Mutex::new(None), pending: Arc::new((Mutex::new(0), std::sync::Condvar::new())) }, secrets, backoff }
    }
    fn enqueue(&self, d: Delivery) {
        let mut tx = self.q.tx.lock().unwrap();
        if tx.is_none() {
            let (t, rx): (SyncSender<Delivery>, Receiver<Delivery>) = sync_channel(QUEUE_MAX_SIZE);
            let (pending, backoff) = (self.q.pending.clone(), self.backoff);
            std::thread::Builder::new()
                .name("outbound-webhooks".into())
                .spawn(move || {
                    for d in rx {
                        if let Err(e) = deliver(&d, backoff) {
                            eprintln!("seagent: outbound webhook delivery failed (event={} target={}): {e}", d.event, d.label);
                        }
                        let (m, c) = &*pending;
                        *m.lock().unwrap() -= 1;
                        c.notify_all();
                    }
                })
                .ok();
            *tx = Some(t);
        }
        let label = d.label.clone();
        let event = d.event.clone();
        *self.q.pending.0.lock().unwrap() += 1;
        match tx.as_ref().unwrap().try_send(d) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                *self.q.pending.0.lock().unwrap() -= 1;
                eprintln!("seagent: outbound webhook queue full ({QUEUE_MAX_SIZE} pending) — dropping {event} event for {label}");
            }
        }
    }
    /// Wait until queued deliveries are done; true if drained within `timeout`.
    pub fn flush(&self, timeout: Duration) -> bool {
        let (m, c) = &*self.q.pending;
        let g = m.lock().unwrap();
        let (g, _) = c.wait_timeout_while(g, timeout, |n| *n > 0).unwrap();
        *g == 0
    }
}

impl Drop for Outbound {
    fn drop(&mut self) {
        // A short-lived `seagent run` may exit right after session_end: drain, bounded.
        self.flush(Duration::from_secs(5));
    }
}

impl Hook for Outbound {
    fn name(&self) -> String {
        format!("outbound:{}", self.targets.iter().map(|t| t.label()).collect::<Vec<_>>().join(","))
    }
    fn wants(&self, event: HookEvent, tool: Option<&str>) -> bool {
        self.targets.iter().any(|t| t.events.contains(&event) && (tool.is_none() || t.matches_tool(tool)))
    }
    fn run(&self, event: HookEvent, payload: &Value) -> Result<HookDecision, String> {
        let tool = payload.get("tool_name").and_then(Value::as_str);
        for t in self.targets.iter().filter(|t| t.events.contains(&event)) {
            if matches!(event, HookEvent::PreTool | HookEvent::PostTool) && !t.matches_tool(tool) {
                continue;
            }
            let id = seagent_kernel::util::random_hex(32);
            let body = serialize(event, payload, &id);
            self.enqueue(build(event, t, body, &id, self.secrets.as_ref()));
        }
        Ok(HookDecision::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_net::httpd::{Opts, Request, Response, Server};

    fn srv(f: impl Fn(&Request, usize) -> Response + Send + Sync + 'static) -> (Server, Arc<Mutex<Vec<Request>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        let s = Server::bind(
            "127.0.0.1:0",
            Opts::default(),
            Arc::new(move |r: Request| {
                let n = {
                    let mut g = s2.lock().unwrap();
                    g.push(r.clone());
                    g.len()
                };
                f(&r, n)
            }),
        )
        .unwrap();
        (s, seen)
    }

    fn parse(toml_s: &str) -> (Vec<Target>, Vec<String>) {
        let cfg: Config = toml::from_str(toml_s).unwrap();
        let x = crate::hooks_ext::HooksExtra::parse(&cfg).unwrap();
        targets(&x.outbound, &cfg)
    }

    #[test]
    fn config_validation_matches_hermes() {
        let (t, w) = parse(
            r#"
[[hooks_extra.outbound]]
url = "ftp://x"
events = ["pre_tool"]
[[hooks_extra.outbound]]
url = "http://127.0.0.1:1/h"
events = ["pre_tool_call", "bogus", "session_end"]
matcher = " shell "
timeout = 600
[[hooks_extra.outbound]]
url = "https://a.example/h"
events = ["session_end"]
matcher = "x"
[[hooks_extra.outbound]]
url = "https://b.example/h"
events = []
"#,
        );
        assert_eq!(t.len(), 2);
        assert_eq!((t[0].events.clone(), t[0].timeout, t[0].matcher.as_deref()), (vec![HookEvent::PreTool, HookEvent::SessionEnd], 60, Some("shell")));
        assert!(t[0].matches_tool(Some("shell")) && !t[0].matches_tool(Some("shellx")) && !t[0].matches_tool(None));
        assert!(t[1].matcher.is_none(), "matcher only for tool events");
        let all = w.join("\n");
        for needle in ["must be http(s)", "plain http://", "unknown event \"bogus\"", "only honored for pre_tool", "non-empty 'events'"] {
            assert!(all.contains(needle), "{needle} missing in {all}");
        }
    }

    #[test]
    fn signed_delivery_with_retry_on_5xx() {
        let (s, seen) = srv(|_, n| if n == 1 { Response::text(503, "busy") } else { Response::text(200, "ok") });
        let (t, _) = parse(&format!("[[hooks_extra.outbound]]\nurl = \"http://{}/hook\"\nevents = [\"post_tool\"]\nsecret = \"{{{{secret:S}}}}\"\nname = \"audit\"\n", s.local_addr()));
        let o = Outbound::with(t, Arc::new(|s: &str| s.replace("{{secret:S}}", "topsecret")), Duration::from_millis(10));
        assert!(o.wants(HookEvent::PostTool, Some("shell")) && !o.wants(HookEvent::PreTool, None));
        o.run(HookEvent::PostTool, &json!({"session_id": "s1", "tool_name": "shell", "tool_input": {"command": "ls"}})).unwrap();
        assert!(o.flush(Duration::from_secs(10)));
        let reqs = seen.lock().unwrap();
        assert_eq!(reqs.len(), 2, "one retry after 503");
        let r = &reqs[1];
        let body: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!((body["hook_event_name"].as_str(), body["tool_input"]["command"].as_str(), body["session_id"].as_str()), (Some("post_tool"), Some("ls"), Some("s1")));
        assert_eq!(r.header("x-seagent-event"), Some("post_tool"));
        assert_eq!(r.header("x-seagent-delivery"), body["delivery_id"].as_str());
        assert_eq!(r.header("x-seagent-signature-256").unwrap(), sign("topsecret", &r.body));
        assert!(body["timestamp"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn four_xx_and_redirects_are_final_and_matcher_filters() {
        let (s, seen) = srv(|r, _| if r.path == "/moved" { Response::empty(302).with_header("location", "/elsewhere") } else { Response::text(404, "no") });
        let base = format!("http://{}", s.local_addr());
        let d = |path: &str| Delivery { url: format!("{base}{path}"), label: "t".into(), event: "pre_tool".into(), body: b"{}".to_vec(), headers: vec![], timeout: 5 };
        assert!(deliver(&d("/gone"), Duration::from_millis(1)).unwrap_err().contains("not retrying"));
        assert!(deliver(&d("/moved"), Duration::from_millis(1)).unwrap_err().contains("not followed"));
        assert_eq!(seen.lock().unwrap().len(), 2, "no retries, no redirect follow");
        // Connection refused: retried, then reported.
        let dead = Delivery { url: "http://127.0.0.1:1/x".into(), ..d("/") };
        assert!(deliver(&dead, Duration::from_millis(1)).unwrap_err().contains("2 attempt"));
        let (t, _) = parse(&format!("[[hooks_extra.outbound]]\nurl = \"{base}/h\"\nevents = [\"pre_tool\"]\nmatcher = \"write\"\n"));
        let o = Outbound::with(t, Arc::new(|s: &str| s.to_string()), Duration::from_millis(1));
        o.run(HookEvent::PreTool, &json!({"tool_name": "shell"})).unwrap();
        assert!(o.flush(Duration::from_secs(5)));
        assert_eq!(seen.lock().unwrap().len(), 2, "matcher filtered the shell call");
    }
}
