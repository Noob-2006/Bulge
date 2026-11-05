//! Plugin stream hooks — a plugin observes (and, opt-in, rewrites) streamed model deltas
//! and streamed tool events (Hermes `agent/plugin_stream_hooks.py` + `agent/stream_delivery.py`,
//! OpenClaw `llm_input`/`llm_output`; MIT).
//!
//! A plugin opts in by declaring the observers it wants in its `initialize` result:
//!
//! ```json
//! {"capabilities": {"experimental": {"ark": {
//!     "stream_hooks": ["on_stream_start", "on_stream_delta", "on_stream_end", "on_tool_event"]
//! }}}}
//! ```
//!
//! **Observation** is asynchronous and never runs on the token path (upstream: "each registered
//! hook callback gets its own bounded queue + daemon worker thread so plugin code never runs
//! inline on the token path"). Each plugin gets a queue of [`QUEUE_SIZE`] events; when it is full
//! the oldest pending event is dropped (drop-oldest, like upstream) and counted in
//! [`StreamTap::dropped`]. Events reach the plugin as `ark/stream` notifications:
//!
//! ```json
//! {"event": "on_stream_delta", "stream_id": "…", "seq": 3, "model": "anthropic/x",
//!  "provider": "anthropic", "session_id": null, "iteration": 1, "surface": "cli",
//!  "delta": "text", "kind": "text"}
//! ```
//!
//! `on_stream_start` carries only the stream identity; `on_stream_end` adds `final_text`,
//! `finished` and `error`; `on_tool_event` carries `phase: "start"` plus `tool`/`tool_use_id`
//! for a streamed tool call. Thinking deltas are forwarded only when the plugin's
//! `[plugins.<name>] stream.reasoning_deltas = true` (Hermes `plugins.stream_reasoning_deltas`,
//! default off — the reasoning pane is opt-in on the token path).
//!
//! **Rewriting** is explicit and synchronous: a plugin that lists `stream_delta` in `hooks` is
//! called inline (`ark/hook {event: "stream_delta", payload: {…, "input": "<delta>"}}`) for each
//! text (and, when enabled, thinking) delta and may answer
//! `{"decision": "modify", "input": "<replacement>"}`. A failing or slow hook leaves the delta
//! unchanged (`HOOK_TIMEOUT`, fail open): a broken plugin can never stall a reply.
//!
//! The tap wraps a [`Provider`] (`TappedProvider`), so every provider — built-in, model-registry
//! or another plugin — is covered; [`tap_resolver`] applies it to a whole provider registry at
//! once (`crates/ark/src/main.rs` wraps the resolver after plugin providers are registered). Provider-level calls do not know the session; payloads carry
//! `session_id: null` and a per-response `stream_id`, `iteration` (1-based per response) and
//! `provider`/`model`.

use crate::plugin::{PluginHost, HOOK_TIMEOUT};
use crate::McpServerConfig;
use ark_core::{Cancel, ModelCaps, ModelRequest, ModelResponse, Provider, ProviderError, StreamEvent};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Pending events one plugin may accumulate before the oldest is dropped (upstream `_QUEUE_SIZE`).
pub const QUEUE_SIZE: usize = 1024;

/// The observer events a plugin may declare (`stream_hooks`).
pub const STREAM_HOOKS: [&str; 4] = ["on_stream_start", "on_stream_delta", "on_stream_end", "on_tool_event"];

struct Queue {
    items: Mutex<VecDeque<Value>>,
    ready: Condvar,
    cap: usize,
    dropped: AtomicU64,
    closed: Mutex<bool>,
}

impl Queue {
    fn new(cap: usize) -> Arc<Queue> {
        Arc::new(Queue { items: Mutex::new(VecDeque::new()), ready: Condvar::new(), cap, dropped: AtomicU64::new(0), closed: Mutex::new(false) })
    }

    /// Enqueue, dropping the oldest pending event when full (never blocks the caller).
    fn push(&self, v: Value) {
        let mut q = self.items.lock().unwrap();
        while q.len() >= self.cap {
            q.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        q.push_back(v);
        drop(q);
        self.ready.notify_one();
    }

    fn pop(&self) -> Option<Value> {
        let mut q = self.items.lock().unwrap();
        loop {
            if let Some(v) = q.pop_front() {
                return Some(v);
            }
            if *self.closed.lock().unwrap() {
                return None;
            }
            let (g, _) = self.ready.wait_timeout(q, Duration::from_millis(200)).unwrap();
            q = g;
        }
    }

    fn close(&self) {
        *self.closed.lock().unwrap() = true;
        self.ready.notify_all();
    }
}

/// One plugin's stream observers. Dropping the tap closes the queue and stops its worker.
pub struct StreamTap {
    host: Arc<PluginHost>,
    declared: Vec<String>,
    /// Rewrite deltas inline (`stream_delta` listed under `hooks`).
    inline: bool,
    reasoning: bool,
    queue: Arc<Queue>,
    sent: AtomicU64,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Drop for StreamTap {
    fn drop(&mut self) {
        self.queue.close();
        if let Some(h) = self.worker.lock().unwrap().take() {
            let _ = h.join();
        }
    }
}

impl StreamTap {
    /// A tap for `host`, or `None` when the plugin declared no stream hooks (or they are off).
    pub fn new(host: Arc<PluginHost>) -> Option<StreamTap> {
        let (cfg, declared, inline) = {
            let cfg: &McpServerConfig = host.client().config();
            let declared: Vec<String> = host.stream_hooks().iter().filter(|h| STREAM_HOOKS.contains(&h.as_str())).cloned().collect();
            let inline = host.hooks().iter().any(|h| h == "stream_delta" || h == "stream_thinking");
            (cfg.stream.clone(), declared, inline)
        };
        if !cfg.enabled || (declared.is_empty() && !inline) {
            return None;
        }
        let queue = Queue::new(QUEUE_SIZE);
        let q = queue.clone();
        let name = host.name.clone();
        let client = host.client().clone();
        let worker = std::thread::spawn(move || {
            while let Some(mut payload) = q.pop() {
                // `name` rides along so one log line identifies the observer.
                payload["plugin"] = json!(name);
                let _ = client.notify("ark/stream", payload);
            }
        });
        Some(StreamTap { host, declared, inline, reasoning: cfg.reasoning_deltas, queue, sent: AtomicU64::new(0), worker: Mutex::new(Some(worker)) })
    }

    pub fn plugin(&self) -> &str {
        &self.host.name
    }
    /// Does this plugin observe `event` (`on_stream_start` …)?
    pub fn declares(&self, event: &str) -> bool {
        self.declared.iter().any(|d| d == event)
    }
    /// Rewrites streamed deltas inline (`stream_delta` in `hooks`)?
    pub fn rewrites(&self) -> bool {
        self.inline
    }
    /// Whether thinking deltas are forwarded (opt-in).
    pub fn reasoning_deltas(&self) -> bool {
        self.reasoning
    }
    /// Events handed to the worker (queued, whether or not the queue later dropped one).
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
    /// Events dropped because the plugin fell behind (drop-oldest).
    pub fn dropped(&self) -> u64 {
        self.queue.dropped.load(Ordering::Relaxed)
    }

    fn notify(&self, event: &str, payload: Value) {
        if !self.declares(event) {
            return;
        }
        self.sent.fetch_add(1, Ordering::Relaxed);
        self.queue.push(payload);
    }

    /// Rewrite one delta inline; `None` = keep it (not declared, failed, or the hook said allow).
    pub fn rewrite(&self, event: &str, payload: Value) -> Option<String> {
        if !self.inline {
            return None;
        }
        match self.host.hook(event, payload) {
            Ok(crate::plugin::HookDecision::Modify(Value::String(t))) => Some(t),
            Ok(crate::plugin::HookDecision::Modify(v)) if v.is_string() => v.as_str().map(str::to_string),
            _ => None,
        }
    }
}

/// The identity of one provider response, shared by its `on_stream_*` events.
#[derive(Debug, Clone)]
pub struct StreamMeta {
    pub stream_id: String,
    pub provider: String,
    pub model: String,
    /// 1-based per response (Hermes `iteration`).
    pub iteration: u64,
    pub surface: String,
}

impl StreamMeta {
    pub fn payload(&self, event: &str) -> Value {
        json!({
            "event": event, "stream_id": self.stream_id, "session_id": Value::Null,
            "turn_id": Value::Null, "iteration": self.iteration, "model": self.model,
            "provider": self.provider, "surface": self.surface,
        })
    }
}

/// `base` with `extra`'s object fields merged in (the payload builders below).
fn with(base: Value, extra: Value) -> Value {
    let (Value::Object(mut m), Value::Object(e)) = (base, extra) else { unreachable!("payloads are objects") };
    for (k, v) in e {
        m.insert(k, v);
    }
    Value::Object(m)
}

/// A provider wrapped so every plugin stream tap sees its deltas and tool events.
pub struct TappedProvider {
    inner: Arc<dyn Provider>,
    taps: Arc<Vec<Arc<StreamTap>>>,
}

/// Run the inline `stream_delta` rewriting of every tap in order (each sees the previous tap's
/// text, so two plugins compose instead of fighting).
fn rewrite_delta(taps: &[Arc<StreamTap>], kind: &str, payload: &Value, mut text: String) -> String {
    let event = if kind == "thinking" { "stream_thinking" } else { "stream_delta" };
    for tap in taps.iter().filter(|t| t.rewrites()) {
        let mut p = payload.clone();
        p["input"] = json!(text);
        if let Some(t) = tap.rewrite(event, p) {
            text = t;
        }
    }
    text
}

impl TappedProvider {
    pub fn new(inner: Arc<dyn Provider>, taps: Arc<Vec<Arc<StreamTap>>>) -> TappedProvider {
        TappedProvider { inner, taps }
    }
}

impl Provider for TappedProvider {
    fn id(&self) -> &str {
        self.inner.id()
    }
    fn caps(&self, model: &str) -> ModelCaps {
        self.inner.caps(model)
    }
    fn complete(&self, req: &ModelRequest, on_event: &mut dyn FnMut(StreamEvent), cancel: &Cancel) -> Result<ModelResponse, ProviderError> {
        if self.taps.is_empty() {
            return self.inner.complete(req, on_event, cancel);
        }
        let meta = StreamMeta { stream_id: ark_net::crypto::random_token(9), provider: self.inner.id().to_string(), model: req.model.clone(), iteration: 1, surface: "cli".into() };
        let start = meta.payload("on_stream_start");
        for t in self.taps.iter() {
            t.notify("on_stream_start", start.clone());
        }
        // Deltas that were rewritten inline; `on_stream_end` reports what the model actually saw.
        let mut text = String::new();
        let mut thinking = String::new();
        let mut tools: Vec<Value> = Vec::new();
        let taps = self.taps.clone();
        let meta2 = meta.clone();
        let mut on = |e: StreamEvent| match e {
            StreamEvent::TextDelta(d) => {
                let p = with(meta2.payload("on_stream_delta"), json!({"delta": d, "kind": "text"}));
                let d = rewrite_delta(&taps, "text", &p, d);
                text.push_str(&d);
                for t in taps.iter() {
                    t.notify("on_stream_delta", with(p.clone(), json!({"delta": d, "kind": "text"})));
                }
                on_event(StreamEvent::TextDelta(d));
            }
            StreamEvent::ThinkingDelta(d) => {
                let p = with(meta2.payload("on_stream_delta"), json!({"delta": d, "kind": "reasoning"}));
                let d = rewrite_delta(&taps, "thinking", &p, d);
                thinking.push_str(&d);
                for t in taps.iter().filter(|t| t.reasoning_deltas()) {
                    t.notify("on_stream_delta", with(p.clone(), json!({"delta": d, "kind": "reasoning"})));
                }
                on_event(StreamEvent::ThinkingDelta(d));
            }
            StreamEvent::ToolUseStart { id, name } => {
                let p = with(meta2.payload("on_tool_event"), json!({"phase": "start", "tool": name, "tool_use_id": id}));
                tools.push(json!({"id": id, "name": name}));
                for t in taps.iter() {
                    t.notify("on_tool_event", p.clone());
                }
                on_event(StreamEvent::ToolUseStart { id, name });
            }
        };
        let r = self.inner.complete(req, &mut on, cancel);
        let end = match &r {
            Ok(resp) => with(meta.payload("on_stream_end"), json!({"final_text": text, "thinking": thinking, "tool_calls": tools, "finished": true, "stop": format!("{:?}", resp.stop), "error": Value::Null})),
            Err(e) => with(meta.payload("on_stream_end"), json!({"final_text": text, "thinking": thinking, "tool_calls": tools, "finished": false, "stop": Value::Null, "error": e.message})),
        };
        for t in self.taps.iter() {
            t.notify("on_stream_end", end.clone());
        }
        r
    }
}

/// The default inline-hook timeout for one streamed delta (kept short: it sits on the token path).
pub fn inline_timeout() -> Duration {
    HOOK_TIMEOUT
}

/// Wrap a kernel resolver so every provider it hands out carries the stream taps (the host calls
/// this once, in `crates/ark/src/main.rs`, after plugin providers are registered). No taps = the
/// resolver is returned untouched.
pub fn tap_resolver(inner: Arc<dyn ark_kernel::kernel::Resolver>, taps: Vec<Arc<StreamTap>>) -> Arc<dyn ark_kernel::kernel::Resolver> {
    if taps.is_empty() {
        return inner;
    }
    Arc::new(TappedResolver { inner, taps: Arc::new(taps) })
}

struct TappedResolver {
    inner: Arc<dyn ark_kernel::kernel::Resolver>,
    taps: Arc<Vec<Arc<StreamTap>>>,
}

impl ark_kernel::kernel::Resolver for TappedResolver {
    fn provider(&self, id: &str) -> Result<Arc<dyn Provider>, String> {
        self.inner.provider(id).map(|p| Arc::new(TappedProvider::new(p, self.taps.clone())) as Arc<dyn Provider>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_core::{Message, StopReason, Usage};
    use std::sync::atomic::AtomicUsize;

    struct Fake {
        deltas: Vec<StreamEvent>,
    }
    impl Provider for Fake {
        fn id(&self) -> &str {
            "fake"
        }
        fn caps(&self, _: &str) -> ModelCaps {
            ModelCaps::default()
        }
        fn complete(&self, req: &ModelRequest, on_event: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
            for e in &self.deltas {
                on_event(e.clone());
            }
            Ok(ModelResponse { message: Message::assistant("done"), stop: StopReason::EndTurn, usage: Usage::default(), model: req.model.clone() })
        }
    }

    #[test]
    fn queue_drops_the_oldest_event_instead_of_blocking() {
        let q = Queue::new(3);
        for i in 0..5 {
            q.push(json!(i));
        }
        assert_eq!(q.dropped.load(Ordering::Relaxed), 2, "two events evicted");
        let mut got = Vec::new();
        while let Some(v) = q.items.lock().unwrap().pop_front() {
            got.push(v.as_u64().unwrap());
        }
        assert_eq!(got, vec![2, 3, 4], "drop-oldest keeps the newest events");
    }

    #[test]
    fn tapped_provider_forwards_every_event_unchanged_without_taps() {
        let inner = Arc::new(Fake { deltas: vec![StreamEvent::TextDelta("a".into()), StreamEvent::ThinkingDelta("t".into()), StreamEvent::ToolUseStart { id: "1".into(), name: "shell".into() }] });
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let p = TappedProvider::new(inner, Arc::default());
        let req = ModelRequest { model: "m".into(), system: vec![], messages: vec![Message::user("hi")], tools: vec![], max_tokens: 10, temperature: None, cache_after_message: None, reasoning: None, options: Default::default() };
        p.complete(&req, &mut |e| s.lock().unwrap().push(format!("{e:?}")), &Cancel::new()).unwrap();
        assert_eq!(seen.lock().unwrap().len(), 3);
        assert!(p.complete(&req, &mut |_| {}, &Cancel::new()).is_ok());
        let _ = AtomicUsize::new(0);
    }

    #[test]
    fn metapayload_matches_the_upstream_shape() {
        let m = StreamMeta { stream_id: "s1".into(), provider: "anthropic".into(), model: "claude".into(), iteration: 2, surface: "chat".into() };
        let p = m.payload("on_stream_delta");
        for k in ["event", "stream_id", "session_id", "turn_id", "iteration", "model", "provider", "surface"] {
            assert!(p.get(k).is_some(), "payload has {k}");
        }
        assert_eq!((p["iteration"].as_u64(), p["surface"].as_str()), (Some(2), Some("chat")));
    }
}
