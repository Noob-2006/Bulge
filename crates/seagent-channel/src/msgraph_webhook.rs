//! Microsoft Graph change-notification ingress (ported from Hermes
//! `gateway/platforms/msgraph_webhook.py`, MIT).
//!
//! `GET|POST <webhook_path>?validationToken=…` answers the subscription handshake
//! by echoing the token as `text/plain` 200. Notification batches (`{"value": [...]}`)
//! are checked per item: `resource` against `accepted_resources` (prefixes, `*`
//! suffix allowed), `clientState` against the configured secret (constant time).
//! Accepted items become one `Inbound` each (text = the `prompt` template or a JSON
//! summary); repeated notification ids are dropped (last `max_seen_receipts`).
//! Any accepted/duplicate item → 202; a batch that only failed clientState → 403;
//! otherwise 400. When bound to a non-loopback address, `allowed_source_cidrs` is
//! mandatory and every request from outside it gets 403 before the body is parsed.
//! Receive-only: `send` is `Unsupported` (Graph has no reply path).
//!
//! A host may claim the accepted notifications with [`set_notification_scheduler`] (upstream
//! `MSGraphWebhookAdapter.set_notification_scheduler`, used by the Teams meeting pipeline): the
//! scheduler then persists them before the 202 and no chat `Inbound` is produced. With nothing
//! bound the behaviour is unchanged — accept, hand to `poll` as a chat message, drop.

use crate::msteams::drain;
use crate::webhook::render_template;
use crate::{Channel, ChannelError, ChatType, Inbound, Outbound, Sent};
use seagent_core::Cancel;
use seagent_net::httpd::{Request, Response};
use serde_json::{json, Value};
use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const DEFAULT_PATH: &str = "/msgraph/webhook";

/// A host that claims Graph notifications (upstream `set_notification_scheduler`). It receives each
/// notification that passed the `resource`/`clientState` gates and answers `Ok(())` once the work is
/// durable (the request then gets 202) or `Err(why)` (the request gets 503, so Graph retries).
pub type NotificationScheduler = Arc<dyn Fn(&Value) -> Result<(), String> + Send + Sync>;

fn process_scheduler() -> &'static Mutex<Option<NotificationScheduler>> {
    static S: Mutex<Option<NotificationScheduler>> = Mutex::new(None);
    &S
}

/// Bind (or, with `None`, unbind) the process-wide notification scheduler. This is the late-binding
/// equivalent of upstream's per-adapter `set_notification_scheduler`, for hosts that do not hold this
/// channel's instance (the Teams meeting pipeline binds it from `seagent`'s wiring). A scheduler bound on
/// an instance with [`MsGraphWebhook::set_notification_scheduler`] wins over this one.
pub fn set_notification_scheduler(s: Option<NotificationScheduler>) {
    *process_scheduler().lock().unwrap_or_else(|e| e.into_inner()) = s;
}

/// Whether the process-wide scheduler is bound (hosts log/verify their wiring with this).
pub fn notification_scheduler_installed() -> bool {
    process_scheduler().lock().unwrap_or_else(|e| e.into_inner()).is_some()
}
pub const DEFAULT_MAX_SEEN: usize = 5000;
pub const DEFAULT_MAX_BODY: usize = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    bits: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let s = s.trim();
        let (ip, bits) = match s.split_once('/') {
            Some((ip, b)) => (ip.parse::<IpAddr>().ok()?, Some(b.parse::<u8>().ok()?)),
            None => (s.parse::<IpAddr>().ok()?, None),
        };
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let bits = bits.unwrap_or(max);
        (bits <= max).then_some(Cidr { net: ip, bits })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        // IPv4-mapped IPv6 peers (dual-stack sockets) compare as IPv4.
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = if self.bits == 0 { 0 } else { u32::MAX << (32 - self.bits) };
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = if self.bits == 0 { 0 } else { u128::MAX << (128 - self.bits) };
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

struct Shared {
    channel: String,
    path: String,
    health_path: String,
    client_state: String,
    accepted_resources: Vec<String>,
    cidrs: Vec<Cidr>,
    prompt: Option<String>,
    max_seen: usize,
    seen: Mutex<(HashSet<String>, VecDeque<String>)>,
    accepted: AtomicU64,
    duplicates: AtomicU64,
    tx: Mutex<Sender<Inbound>>,
    /// Upstream `_notification_scheduler`; `None` = ack then hand to `poll` as a chat message.
    scheduler: Mutex<Option<NotificationScheduler>>,
}

pub struct MsGraphWebhook {
    sh: Arc<Shared>,
    rx: Mutex<Receiver<Inbound>>,
    server: seagent_net::httpd::Server,
    poll_timeout: Duration,
}

pub struct MsGraphOpts<'a> {
    pub listen: &'a str,
    pub path: &'a str,
    pub health_path: &'a str,
    pub client_state: &'a str,
    pub accepted_resources: Vec<String>,
    pub allowed_source_cidrs: Vec<String>,
    pub prompt: Option<&'a str>,
    pub max_seen_receipts: usize,
    pub max_body_bytes: usize,
    pub poll_timeout: Duration,
}

fn norm_path(p: &str) -> String {
    let p = p.trim();
    if p.is_empty() {
        "/".into()
    } else if p.starts_with('/') {
        p.to_string()
    } else {
        format!("/{p}")
    }
}

fn is_loopback(listen: &str) -> bool {
    let host = match listen.rsplit_once(':') {
        Some((h, _)) => h.trim_start_matches('[').trim_end_matches(']'),
        None => listen,
    };
    host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

impl Shared {
    fn source_allowed(&self, r: &Request) -> bool {
        if self.cidrs.is_empty() {
            return true; // only possible on a loopback bind (checked at startup)
        }
        r.peer.is_some_and(|p| self.cidrs.iter().any(|c| c.contains(p.ip())))
    }

    fn resource_accepted(&self, resource: &str) -> bool {
        if self.accepted_resources.is_empty() {
            return true;
        }
        let res = resource.trim().trim_matches('/');
        self.accepted_resources.iter().any(|p| {
            let p = p.trim().trim_matches('/');
            let p = p.strip_suffix('*').map(|x| x.trim_end_matches('/')).unwrap_or(p);
            !p.is_empty() && (res == p || res.starts_with(&format!("{p}/")))
        })
    }

    fn remember(&self, key: &str) -> bool {
        let mut g = self.seen.lock().unwrap();
        if !g.0.insert(key.to_string()) {
            return false;
        }
        g.1.push_back(key.to_string());
        while g.1.len() > self.max_seen {
            if let Some(old) = g.1.pop_front() {
                g.0.remove(&old);
            }
        }
        true
    }

    fn render(&self, n: &Value) -> String {
        match &self.prompt {
            Some(t) if !t.is_empty() => {
                let ctx = json!({"notification": n, "resource": n.get("resource").cloned().unwrap_or(json!("")), "change_type": n.get("changeType").cloned().unwrap_or(json!("")), "subscription_id": n.get("subscriptionId").cloned().unwrap_or(json!(""))});
                render_template(t, &ctx, &|_| None, &|v| v.to_string().chars().take(2000).collect())
            }
            _ => {
                let pretty: String = serde_json::to_string_pretty(n).unwrap_or_default().chars().take(4000).collect();
                format!("Microsoft Graph change notification:\n\n```json\n{pretty}\n```")
            }
        }
    }

    /// The bound scheduler: an instance binding wins over the process-wide one.
    fn bound_scheduler(&self) -> Option<NotificationScheduler> {
        self.scheduler.lock().unwrap_or_else(|e| e.into_inner()).clone().or_else(|| process_scheduler().lock().unwrap_or_else(|e| e.into_inner()).clone())
    }

    fn seen_has(&self, key: &str) -> bool {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).0.contains(key)
    }

    /// accepted | duplicate | auth | other | failed
    fn ingest(&self, n: &Value) -> &'static str {
        if !n.is_object() || !self.resource_accepted(n["resource"].as_str().unwrap_or("")) {
            return "other";
        }
        let provided = n["clientState"].as_str().map(str::trim).unwrap_or("");
        if provided.is_empty() || !seagent_net::crypto::ct_eq(provided.as_bytes(), self.client_state.as_bytes()) {
            return "auth";
        }
        let receipt = n["id"].as_str().map(str::trim).filter(|s| !s.is_empty()).map(|id| format!("id:{id}"));
        if let Some(schedule) = self.bound_scheduler() {
            // A bound scheduler owns the notification (upstream `_schedule_notification` returns
            // before `_admit_notification`): replays are deduped by receipt first, the scheduler
            // persists the work before the 202, and no chat Inbound is produced.
            if let Some(k) = &receipt {
                if self.seen_has(k) {
                    self.duplicates.fetch_add(1, Ordering::SeqCst);
                    return "duplicate";
                }
            }
            if schedule(n).is_err() {
                // Not durable: the receipt is not remembered, so Graph's retry is reprocessed.
                return "failed";
            }
            if let Some(k) = &receipt {
                self.remember(k);
            }
            self.accepted.fetch_add(1, Ordering::SeqCst);
            return "accepted";
        }
        if let Some(k) = &receipt {
            if !self.remember(k) {
                self.duplicates.fetch_add(1, Ordering::SeqCst);
                return "duplicate";
            }
        }
        // serde_json maps are ordered, so this matches Hermes' sort_keys digest.
        let message_id = receipt.unwrap_or_else(|| format!("sha1:{}", seagent_net::crypto::hex(&seagent_net::crypto::sha1(n.to_string().as_bytes()))));
        let m = Inbound {
            channel: self.channel.clone(),
            chat: format!("msgraph:{}", n["subscriptionId"].as_str().unwrap_or("unknown")),
            chat_name: "msgraph/webhook".into(),
            chat_type: ChatType::Direct,
            sender: "msgraph".into(),
            sender_name: "Microsoft Graph".into(),
            text: self.render(n),
            message_id,
            ts: crate::msteams::now_secs(),
            ..Default::default()
        };
        if self.tx.lock().unwrap().send(m).is_err() {
            return "other";
        }
        self.accepted.fetch_add(1, Ordering::SeqCst);
        "accepted"
    }

    fn handle(&self, r: Request) -> Response {
        let is_health = r.path == self.health_path && r.method == "GET";
        if r.path != self.path && !is_health {
            return Response::text(404, "not found");
        }
        if !self.source_allowed(&r) {
            return Response::empty(403);
        }
        if is_health && r.path != self.path {
            return Response::json(200, &json!({"status": "ok", "platform": "msgraph_webhook", "webhook_path": self.path, "accepted": self.accepted.load(Ordering::SeqCst), "duplicates": self.duplicates.load(Ordering::SeqCst), "notification_scheduler": self.bound_scheduler().is_some()}).to_string());
        }
        // Validation handshake (Graph uses GET or POST with the token in the query).
        if let Some(tok) = r.query("validationToken").filter(|t| !t.is_empty()) {
            return Response::new(200, "text/plain", tok.as_bytes().to_vec());
        }
        match r.method.as_str() {
            "GET" => return Response::empty(400),
            "POST" => {}
            _ => return Response::empty(405),
        }
        let Ok(body) = serde_json::from_slice::<Value>(&r.body) else { return Response::empty(400) };
        let Some(items) = body["value"].as_array() else { return Response::empty(400) };
        let (mut accepted, mut dup, mut auth, mut other) = (0, 0, 0, 0);
        for n in items {
            match self.ingest(n) {
                "accepted" => accepted += 1,
                "duplicate" => dup += 1,
                "auth" => auth += 1,
                // Upstream: an admission failure inside the batch is a 503 so Graph retries it.
                "failed" => return Response::empty(503),
                _ => other += 1,
            }
        }
        if accepted + dup > 0 {
            Response::empty(202)
        } else if auth > 0 && other == 0 {
            Response::empty(403)
        } else {
            Response::empty(400)
        }
    }
}

impl std::fmt::Debug for MsGraphWebhook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MsGraphWebhook").field("id", &self.sh.channel).field("listen", &self.server.local_addr()).field("path", &self.sh.path).finish()
    }
}

impl MsGraphWebhook {
    pub fn new(id: &str, o: MsGraphOpts) -> Result<MsGraphWebhook, String> {
        let client_state = o.client_state.trim();
        if client_state.is_empty() {
            return Err(format!("channel {id}: msgraph_webhook needs client_state"));
        }
        let mut cidrs = vec![];
        for c in &o.allowed_source_cidrs {
            for part in c.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                cidrs.push(Cidr::parse(part).ok_or_else(|| format!("channel {id}: bad allowed_source_cidrs entry {part:?}"))?);
            }
        }
        if cidrs.is_empty() && !is_loopback(o.listen) {
            return Err(format!("channel {id}: listening on {} requires allowed_source_cidrs (Microsoft Graph's source ranges), or bind to 127.0.0.1 behind a proxy", o.listen));
        }
        let (tx, rx) = mpsc::channel();
        let sh = Arc::new(Shared {
            channel: id.to_string(),
            path: norm_path(o.path),
            health_path: norm_path(o.health_path),
            client_state: client_state.to_string(),
            accepted_resources: o.accepted_resources.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            cidrs,
            prompt: o.prompt.map(str::to_string),
            max_seen: o.max_seen_receipts.max(1),
            seen: Mutex::new((HashSet::new(), VecDeque::new())),
            accepted: AtomicU64::new(0),
            duplicates: AtomicU64::new(0),
            tx: Mutex::new(tx),
            scheduler: Mutex::new(None),
        });
        let sh2 = sh.clone();
        let handler: seagent_net::httpd::Handler = Arc::new(move |r| sh2.handle(r));
        let opts = seagent_net::httpd::Opts { max_body: o.max_body_bytes.max(1), ..Default::default() };
        let server = seagent_net::httpd::Server::bind(o.listen, opts, handler).map_err(|e| format!("channel {id}: cannot listen on {}: {e}", o.listen))?;
        Ok(MsGraphWebhook { sh, rx: Mutex::new(rx), server, poll_timeout: o.poll_timeout })
    }

    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.server.local_addr()
    }

    /// Upstream `MSGraphWebhookAdapter.set_notification_scheduler`: hand every accepted notification
    /// to `scheduler` (persisted before the 202, no chat Inbound) instead of queueing it for `poll`.
    /// `None` restores the default "ack then drop" behaviour.
    pub fn set_notification_scheduler(&self, scheduler: Option<NotificationScheduler>) {
        *self.sh.scheduler.lock().unwrap_or_else(|e| e.into_inner()) = scheduler;
    }
}

impl Channel for MsGraphWebhook {
    fn id(&self) -> &str {
        &self.sh.channel
    }

    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        Ok(drain(&self.rx, self.poll_timeout, cancel))
    }

    fn send(&self, _out: &Outbound) -> Result<Sent, ChannelError> {
        Err(crate::unsupported("replying to Microsoft Graph notifications"))
    }
}

fn d_path() -> String {
    DEFAULT_PATH.into()
}
fn d_health() -> String {
    "/health".into()
}
fn d_seen() -> usize {
    DEFAULT_MAX_SEEN
}
fn d_body() -> usize {
    DEFAULT_MAX_BODY
}
fn d_poll() -> u64 {
    25
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    /// Required (e.g. "127.0.0.1:8646") so the host knows this channel opens a listener.
    listen: String,
    #[serde(default = "d_path")]
    webhook_path: String,
    #[serde(default = "d_health")]
    health_path: String,
    client_state: String,
    #[serde(default)]
    accepted_resources: Vec<String>,
    #[serde(default)]
    allowed_source_cidrs: Vec<String>,
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default = "d_seen")]
    max_seen_receipts: usize,
    #[serde(default = "d_body")]
    max_body_bytes: usize,
    #[serde(default = "d_poll")]
    poll_timeout_secs: u64,
}

pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, Value>) -> Result<Arc<dyn Channel>, String> {
    let st: Settings = ctx.settings(s)?;
    let client_state = ctx.secret("client_state", &st.client_state)?;
    let w = MsGraphWebhook::new(
        ctx.name,
        MsGraphOpts {
            listen: &st.listen,
            path: &st.webhook_path,
            health_path: &st.health_path,
            client_state: &client_state,
            accepted_resources: st.accepted_resources,
            allowed_source_cidrs: st.allowed_source_cidrs,
            prompt: st.prompt.as_deref(),
            max_seen_receipts: st.max_seen_receipts,
            max_body_bytes: st.max_body_bytes,
            poll_timeout: Duration::from_secs(st.poll_timeout_secs),
        },
    )?;
    Ok(Arc::new(w))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts<'a>(listen: &'a str, cidrs: Vec<&str>) -> MsGraphOpts<'a> {
        MsGraphOpts {
            listen,
            path: "/msgraph/webhook",
            health_path: "/health",
            client_state: "s3cret-state",
            accepted_resources: vec!["users/u1/messages".into(), "teams/*".into()],
            allowed_source_cidrs: cidrs.into_iter().map(str::to_string).collect(),
            prompt: None,
            max_seen_receipts: 2,
            max_body_bytes: 4096,
            poll_timeout: Duration::from_millis(300),
        }
    }

    fn req(addr: std::net::SocketAddr, method: &str, path: &str, body: &str) -> (u16, String, String) {
        let a = crate::http::agent(Duration::from_secs(5));
        let r = match method {
            "GET" => a.get(&format!("http://{addr}{path}")).call(),
            _ => a.post(&format!("http://{addr}{path}")).send(body.as_bytes()),
        };
        match r {
            Ok(mut r) => {
                let ct = r.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                (r.status().as_u16(), ct, r.body_mut().read_to_string().unwrap_or_default())
            }
            Err(_) => (0, String::new(), String::new()),
        }
    }

    fn note(id: &str, state: &str, resource: &str) -> Value {
        json!({"id": id, "subscriptionId": "sub-1", "clientState": state, "changeType": "created", "resource": resource, "resourceData": {"id": "AAMk"}})
    }

    #[test]
    fn handshake_client_state_dedup_and_resources() {
        let w = MsGraphWebhook::new("graph", opts("127.0.0.1:0", vec![])).unwrap();
        let a = w.local_addr();
        let (st, ct, body) = req(a, "GET", "/msgraph/webhook?validationToken=abc%20123", "");
        assert_eq!((st, body.as_str()), (200, "abc 123"));
        assert!(ct.starts_with("text/plain"), "{ct}");
        assert_eq!(req(a, "POST", "/msgraph/webhook?validationToken=xyz", "").2, "xyz", "POST handshake too");
        assert_eq!(req(a, "GET", "/msgraph/webhook", "").0, 400, "bare GET");
        assert_eq!(req(a, "POST", "/other", "{}").0, 404);
        assert_eq!(req(a, "POST", "/msgraph/webhook", "not json").0, 400);
        assert_eq!(req(a, "POST", "/msgraph/webhook", r#"{"value": 1}"#).0, 400);
        assert_eq!(req(a, "POST", "/msgraph/webhook", &"x".repeat(5000)).0, 413, "max_body_bytes");
        let forged = json!({"value": [note("n0", "wrong", "users/u1/messages/1"), note("n0b", "", "users/u1/messages/1")]});
        assert_eq!(req(a, "POST", "/msgraph/webhook", &forged.to_string()).0, 403, "every item failed clientState");
        let foreign = json!({"value": [note("n1", "s3cret-state", "users/u2/messages/1")]});
        assert_eq!(req(a, "POST", "/msgraph/webhook", &foreign.to_string()).0, 400, "resource not accepted");
        let good = json!({"value": [note("n2", "s3cret-state", "users/u1/messages/1"), note("n3", "s3cret-state", "/teams/t1/channels/c1/messages"), note("bad", "nope", "users/u1/messages")]});
        assert_eq!(req(a, "POST", "/msgraph/webhook", &good.to_string()).0, 202);
        assert_eq!(req(a, "POST", "/msgraph/webhook", &json!({"value": [note("n2", "s3cret-state", "users/u1/messages")]}).to_string()).0, 202, "duplicate is acked");
        let (st, _, health) = req(a, "GET", "/health", "");
        assert_eq!(st, 200);
        assert_eq!(serde_json::from_str::<Value>(&health).unwrap()["duplicates"], 1);
        let got = w.poll(&Cancel::new()).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].chat.as_str(), got[0].sender.as_str(), got[0].message_id.as_str()), ("msgraph:sub-1", "msgraph", "id:n2"));
        assert!(got[0].text.starts_with("Microsoft Graph change notification:\n\n```json\n{"), "{}", got[0].text);
        // The receipt cache is bounded (max_seen_receipts = 2): n2 was evicted by n3 + n4.
        req(a, "POST", "/msgraph/webhook", &json!({"value": [note("n4", "s3cret-state", "users/u1/messages")]}).to_string());
        req(a, "POST", "/msgraph/webhook", &json!({"value": [note("n2", "s3cret-state", "users/u1/messages")]}).to_string());
        assert_eq!(w.poll(&Cancel::new()).unwrap().len(), 2);
        // No id → stable sha1 message id.
        let mut anon = note("", "s3cret-state", "users/u1/messages");
        anon.as_object_mut().unwrap().remove("id");
        req(a, "POST", "/msgraph/webhook", &json!({"value": [anon]}).to_string());
        assert!(w.poll(&Cancel::new()).unwrap()[0].message_id.starts_with("sha1:"));
        assert_eq!(w.send(&Outbound::text("msgraph:sub-1", "x")).unwrap_err().kind, crate::ChannelErrorKind::Unsupported);
    }

    #[test]
    fn source_cidrs_template_and_config() {
        // A public bind without an allowlist refuses to start.
        assert!(MsGraphWebhook::new("g", opts("0.0.0.0:0", vec![])).unwrap_err().contains("allowed_source_cidrs"));
        assert!(MsGraphWebhook::new("g", opts("127.0.0.1:0", vec!["300.1.1.1/8"])).is_err());
        assert!(MsGraphWebhook::new("g", MsGraphOpts { client_state: " ", ..opts("127.0.0.1:0", vec![]) }).is_err());
        let blocked = MsGraphWebhook::new("g", opts("0.0.0.0:0", vec!["10.0.0.0/8, 2603:1000::/24"])).unwrap();
        let port = blocked.local_addr().port();
        let a: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        assert_eq!(req(a, "GET", "/msgraph/webhook?validationToken=x", "").0, 403, "loopback peer outside the allowlist");
        assert_eq!(req(a, "GET", "/health", "").0, 403);
        let allowed = MsGraphWebhook::new("g", MsGraphOpts { prompt: Some("{change_type} on {resource} ({notification.resourceData.id}) {notification.resourceData} {nope}"), ..opts("0.0.0.0:0", vec!["127.0.0.0/8"]) }).unwrap();
        let a: std::net::SocketAddr = format!("127.0.0.1:{}", allowed.local_addr().port()).parse().unwrap();
        assert_eq!(req(a, "POST", "/msgraph/webhook", &json!({"value": [note("t1", "s3cret-state", "users/u1/messages/9")]}).to_string()).0, 202);
        assert_eq!(allowed.poll(&Cancel::new()).unwrap()[0].text, r#"created on users/u1/messages/9 (AAMk) {"id":"AAMk"} {nope}"#);
        let c = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(c.contains("192.168.1.77".parse().unwrap()) && !c.contains("192.168.2.1".parse().unwrap()));
        assert!(c.contains("::ffff:192.168.1.5".parse().unwrap()), "v4-mapped");
        assert!(Cidr::parse("2603:1000::/24").unwrap().contains("2603:10ff::1".parse().unwrap()));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains("8.8.8.8".parse().unwrap()));
        let c = Cancel::new();
        c.cancel();
        let t = std::time::Instant::now();
        assert!(allowed.poll(&c).unwrap().is_empty());
        assert!(t.elapsed() < Duration::from_millis(200));
    }

    /// A bound scheduler owns the accepted notifications (upstream `set_notification_scheduler`):
    /// each one is handed over before the 202, none becomes a chat `Inbound`, replays are deduped
    /// without calling it, a failure is a 503 (Graph retries) and unbinding restores the default.
    #[test]
    fn notification_scheduler_claims_accepted_notifications() {
        let w = MsGraphWebhook::new("g", opts("127.0.0.1:0", vec![])).unwrap();
        let got = Arc::new(Mutex::new(Vec::<Value>::new()));
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (g, f) = (got.clone(), fail.clone());
        let scheduler: NotificationScheduler = Arc::new(move |n: &Value| {
            if f.load(Ordering::SeqCst) {
                return Err("the pipeline store is unavailable".into());
            }
            g.lock().unwrap().push(n.clone());
            Ok(())
        });
        w.set_notification_scheduler(Some(scheduler));
        let a: std::net::SocketAddr = format!("127.0.0.1:{}", w.local_addr().port()).parse().unwrap();
        assert_eq!(serde_json::from_str::<Value>(&req(a, "GET", "/health", "").2).unwrap()["notification_scheduler"], json!(true));
        assert_eq!(req(a, "POST", "/msgraph/webhook", &json!({"value": [note("n1", "s3cret-state", "users/u1/messages")]}).to_string()).0, 202);
        assert_eq!(got.lock().unwrap().len(), 1);
        assert_eq!(got.lock().unwrap()[0]["id"], json!("n1"), "the scheduler gets the decoded notification");
        assert!(w.poll(&Cancel::new()).unwrap().is_empty(), "no chat Inbound when a scheduler is bound");
        assert_eq!(req(a, "POST", "/msgraph/webhook", &json!({"value": [note("n1", "s3cret-state", "users/u1/messages")]}).to_string()).0, 202);
        assert_eq!(got.lock().unwrap().len(), 1, "a replay is deduped before the scheduler");
        fail.store(true, Ordering::SeqCst);
        assert_eq!(req(a, "POST", "/msgraph/webhook", &json!({"value": [note("n2", "s3cret-state", "users/u1/messages")]}).to_string()).0, 503, "a scheduler failure is retryable");
        fail.store(false, Ordering::SeqCst);
        assert_eq!(req(a, "POST", "/msgraph/webhook", &json!({"value": [note("n2", "s3cret-state", "users/u1/messages")]}).to_string()).0, 202, "the failed receipt was not remembered");
        assert_eq!(got.lock().unwrap().len(), 2);
        w.set_notification_scheduler(None);
        assert_eq!(serde_json::from_str::<Value>(&req(a, "GET", "/health", "").2).unwrap()["notification_scheduler"], json!(false));
        assert_eq!(req(a, "POST", "/msgraph/webhook", &json!({"value": [note("n3", "s3cret-state", "users/u1/messages")]}).to_string()).0, 202);
        assert_eq!(w.poll(&Cancel::new()).unwrap().len(), 1, "unbound → the notification is a chat message again");
        assert_eq!(got.lock().unwrap().len(), 2);
    }
}
