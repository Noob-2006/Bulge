//! Provider record/replay: capture a real run as JSONL, then drive the same requests through
//! it in a test without a key or a network (DeepSeek Harness `test-support/llm-replay`,
//! `session-snapshot`, MIT, Copyright (c) 2026 DeepSeek).
//!
//! Set `SEAGENT_MODEL_RECORD=<file>` to wrap every provider the binary builds; each exchange
//! records the exact request, the streamed deltas and the final response (or error). Set
//! `SEAGENT_MODEL_REPLAY=<file>` to serve those requests instead: no credentials are resolved.
//! A replay entry is matched by exact request equality, so a prompt, tool schema or context
//! change makes the fixture fail loudly instead of silently testing different bytes.

use seagent_core::{Cancel, ModelCaps, ModelRequest, ModelResponse, Provider, ProviderError, ProviderErrorKind, StreamEvent};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const RECORD_ENV: &str = "SEAGENT_MODEL_RECORD";
pub const REPLAY_ENV: &str = "SEAGENT_MODEL_REPLAY";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RecordedCaps {
    pub context_window: u64,
    pub max_output: u32,
    pub tools: bool,
    pub vision: bool,
    pub explicit_cache: bool,
}

impl From<ModelCaps> for RecordedCaps {
    fn from(c: ModelCaps) -> Self {
        RecordedCaps { context_window: c.context_window, max_output: c.max_output, tools: c.tools, vision: c.vision, explicit_cache: c.explicit_cache }
    }
}

impl From<RecordedCaps> for ModelCaps {
    fn from(c: RecordedCaps) -> Self {
        ModelCaps { context_window: c.context_window, max_output: c.max_output, tools: c.tools, vision: c.vision, explicit_cache: c.explicit_cache }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RecordedEvent {
    TextDelta { text: String },
    ThinkingDelta { text: String },
    ToolUseStart { id: String, name: String },
}

impl From<StreamEvent> for RecordedEvent {
    fn from(e: StreamEvent) -> Self {
        match e {
            StreamEvent::TextDelta(text) => RecordedEvent::TextDelta { text },
            StreamEvent::ThinkingDelta(text) => RecordedEvent::ThinkingDelta { text },
            StreamEvent::ToolUseStart { id, name } => RecordedEvent::ToolUseStart { id, name },
        }
    }
}

impl From<RecordedEvent> for StreamEvent {
    fn from(e: RecordedEvent) -> Self {
        match e {
            RecordedEvent::TextDelta { text } => StreamEvent::TextDelta(text),
            RecordedEvent::ThinkingDelta { text } => StreamEvent::ThinkingDelta(text),
            RecordedEvent::ToolUseStart { id, name } => StreamEvent::ToolUseStart { id, name },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordedError {
    /// [`ProviderErrorKind`] in snake case (`rate_limited`, `bad_request`, …).
    pub kind: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

fn kind_name(k: &ProviderErrorKind) -> &'static str {
    match k {
        ProviderErrorKind::RateLimited { .. } => "rate_limited",
        ProviderErrorKind::Overloaded => "overloaded",
        ProviderErrorKind::Server => "server",
        ProviderErrorKind::Network => "network",
        ProviderErrorKind::Timeout => "timeout",
        ProviderErrorKind::Auth => "auth",
        ProviderErrorKind::BadRequest => "bad_request",
        ProviderErrorKind::ContextOverflow => "context_overflow",
        ProviderErrorKind::Cancelled => "cancelled",
        ProviderErrorKind::Protocol => "protocol",
    }
}

fn kind_from_name(s: &str) -> ProviderErrorKind {
    match s {
        "rate_limited" => ProviderErrorKind::RateLimited { retry_after: None },
        "overloaded" => ProviderErrorKind::Overloaded,
        "server" => ProviderErrorKind::Server,
        "network" => ProviderErrorKind::Network,
        "timeout" => ProviderErrorKind::Timeout,
        "auth" => ProviderErrorKind::Auth,
        "bad_request" => ProviderErrorKind::BadRequest,
        "context_overflow" => ProviderErrorKind::ContextOverflow,
        "cancelled" => ProviderErrorKind::Cancelled,
        _ => ProviderErrorKind::Protocol,
    }
}

/// One recorded model call: what was sent, what streamed back, and how it ended.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Exchange {
    /// Provider id the request was routed to (`deepseek`, `anthropic`, …).
    pub provider: String,
    pub caps: RecordedCaps,
    pub request: ModelRequest,
    #[serde(default)]
    pub events: Vec<RecordedEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<ModelResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RecordedError>,
}

/// Parse a JSONL fixture. Blank lines and `#` comments are ignored.
pub fn load(path: &Path) -> Result<Vec<Exchange>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.push(serde_json::from_str::<Exchange>(line).map_err(|e| format!("{}:{}: {e}", path.display(), n + 1))?);
    }
    Ok(out)
}

/// Record every completed call from `inner` to `path` (JSONL, append).
pub struct Recorder {
    inner: Arc<dyn Provider>,
    provider: String,
    path: PathBuf,
    file: Mutex<std::fs::File>,
}

impl Recorder {
    pub fn new(inner: Arc<dyn Provider>, path: &Path, provider: &str) -> Result<Arc<Recorder>, String> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(Arc::new(Recorder { inner, provider: provider.to_string(), path: path.to_path_buf(), file: Mutex::new(file) }))
    }

    fn write(&self, ex: &Exchange) {
        let line = match serde_json::to_string(ex) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("seagent: model recording: cannot encode exchange: {e}");
                return;
            }
        };
        let mut f = self.file.lock().unwrap();
        if let Err(e) = writeln!(f, "{line}").and_then(|()| f.flush()) {
            eprintln!("seagent: model recording {}: {e}", self.path.display());
        }
    }
}

impl Provider for Recorder {
    fn id(&self) -> &str {
        self.inner.id()
    }
    fn caps(&self, model: &str) -> ModelCaps {
        self.inner.caps(model)
    }
    fn complete(&self, req: &ModelRequest, on: &mut dyn FnMut(StreamEvent), cancel: &Cancel) -> Result<ModelResponse, ProviderError> {
        let mut events = Vec::new();
        let mut forward = |ev: StreamEvent| {
            events.push(RecordedEvent::from(ev.clone()));
            on(ev);
        };
        let result = self.inner.complete(req, &mut forward, cancel);
        let ex = Exchange {
            provider: self.provider.clone(),
            caps: self.inner.caps(&req.model).into(),
            request: req.clone(),
            events,
            response: result.as_ref().ok().cloned(),
            error: result.as_ref().err().map(|e| RecordedError { kind: kind_name(&e.kind).into(), message: e.message.clone(), status: e.status }),
        };
        self.write(&ex);
        result
    }
}

/// Serve recorded exchanges in order, one per request.
pub struct ReplayProvider {
    provider: String,
    caps: ModelCaps,
    entries: Mutex<VecDeque<Exchange>>,
    total: usize,
}

impl ReplayProvider {
    pub fn from_file(provider: &str, path: &Path) -> Result<ReplayProvider, String> {
        let all = load(path)?;
        Self::from_exchanges(provider, all.into_iter().filter(|e| e.provider == provider).collect())
    }

    pub fn from_exchanges(provider: &str, entries: Vec<Exchange>) -> Result<ReplayProvider, String> {
        let first = entries.first().ok_or_else(|| format!("no recorded exchanges for provider `{provider}`"))?;
        let caps = first.caps.clone().into();
        let total = entries.len();
        Ok(ReplayProvider { provider: provider.to_string(), caps, entries: Mutex::new(entries.into()), total })
    }

    pub fn total(&self) -> usize {
        self.total
    }
    pub fn remaining(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

fn first_difference(a: &ModelRequest, b: &ModelRequest) -> String {
    if a.model != b.model {
        return format!("model `{}` vs `{}`", a.model, b.model);
    }
    if a.system != b.system {
        return "system prompt differs".into();
    }
    if a.tools != b.tools {
        return "tool schemas differ".into();
    }
    if a.messages != b.messages {
        return format!("conversation differs ({} vs {} messages)", a.messages.len(), b.messages.len());
    }
    if a.max_tokens != b.max_tokens || a.temperature != b.temperature || a.reasoning != b.reasoning || a.options != b.options {
        return "request options differ".into();
    }
    "requests differ".into()
}

impl Provider for ReplayProvider {
    fn id(&self) -> &str {
        &self.provider
    }
    fn caps(&self, _: &str) -> ModelCaps {
        self.caps.clone()
    }
    fn complete(&self, req: &ModelRequest, on: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
        let mut entries = self.entries.lock().unwrap();
        let n = self.total - entries.len() + 1;
        let ex = entries.pop_front().ok_or_else(|| ProviderError::new(ProviderErrorKind::Protocol, format!("no more recorded exchanges for provider `{}` (fixture has {})", self.provider, self.total)))?;
        if &ex.request != req {
            return Err(ProviderError::new(
                ProviderErrorKind::Protocol,
                format!("recorded request #{n} does not match this request: {}; re-record the fixture after this change", first_difference(&ex.request, req)),
            ));
        }
        for ev in ex.events {
            on(ev.into());
        }
        match (ex.response, ex.error) {
            (Some(r), _) => Ok(r),
            (None, Some(e)) => Err(ProviderError { kind: kind_from_name(&e.kind), message: e.message, status: e.status }),
            (None, None) => Err(ProviderError::new(ProviderErrorKind::Protocol, format!("recorded request #{n} has neither a response nor an error"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_core::{Block, Message, StopReason, SystemSegment, Usage};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fake {
        calls: AtomicUsize,
        fail: bool,
    }

    impl Provider for Fake {
        fn id(&self) -> &str {
            "deepseek"
        }
        fn caps(&self, _: &str) -> ModelCaps {
            ModelCaps { context_window: 128_000, max_output: 8192, tools: true, vision: false, explicit_cache: false }
        }
        fn complete(&self, req: &ModelRequest, on: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(ProviderError::new(ProviderErrorKind::RateLimited { retry_after: None }, "429 slow down").with_status(429));
            }
            let text = format!("answer {n}");
            on(StreamEvent::TextDelta("ans".into()));
            on(StreamEvent::TextDelta(format!("wer {n}")));
            Ok(ModelResponse { message: Message { role: seagent_core::Role::Assistant, content: vec![Block::text(text)] }, stop: StopReason::EndTurn, usage: Usage { input_tokens: 12, output_tokens: 3, ..Default::default() }, model: req.model.clone() })
        }
    }

    fn req(text: &str) -> ModelRequest {
        ModelRequest {
            model: "deepseek-chat".into(),
            system: vec![SystemSegment { id: "identity".into(), text: "be brief".into(), cache: false }],
            messages: vec![Message::user(text)],
            tools: vec![],
            max_tokens: 100,
            ..Default::default()
        }
    }

    #[test]
    fn a_recorded_run_replays_without_the_inner_provider() {
        let dir = seagent_core::tmp::TempDir::new("seagent-replay");
        let path = dir.join("run.jsonl");
        let fake = Arc::new(Fake { calls: AtomicUsize::new(0), fail: false });
        let rec = Recorder::new(fake.clone(), &path, "deepseek").unwrap();
        let (r1, r2) = (req("one"), req("two"));
        let mut seen1 = vec![];
        let first = rec.complete(&r1, &mut |e| seen1.push(e), &Cancel::new()).unwrap();
        let mut seen2 = vec![];
        let second = rec.complete(&r2, &mut |e| seen2.push(e), &Cancel::new()).unwrap();
        assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
        drop(rec);

        let replay = ReplayProvider::from_file("deepseek", &path).unwrap();
        assert_eq!((replay.total(), replay.remaining()), (2, 2));
        let mut replay_events = vec![];
        assert_eq!(replay.complete(&r1, &mut |e| replay_events.push(e), &Cancel::new()).unwrap(), first);
        assert_eq!(replay_events, seen1, "the streamed deltas are replayed too");
        assert_eq!(replay.complete(&r2, &mut |_| {}, &Cancel::new()).unwrap(), second);
        assert_eq!(replay.remaining(), 0);
        let e = replay.complete(&r1, &mut |_| {}, &Cancel::new()).unwrap_err();
        assert!(e.message.contains("no more recorded exchanges"), "{e}");
        // Caps are recorded and replayed so a profile sees the same limits.
        assert_eq!(replay.caps("deepseek-chat").context_window, 128_000);
    }

    #[test]
    fn replay_refuses_a_changed_request_and_replays_errors() {
        let dir = seagent_core::tmp::TempDir::new("seagent-replay-mismatch");
        let path = dir.join("run.jsonl");
        let rec = Recorder::new(Arc::new(Fake { calls: AtomicUsize::new(0), fail: false }), &path, "deepseek").unwrap();
        rec.complete(&req("one"), &mut |_| {}, &Cancel::new()).unwrap();
        drop(rec);
        let replay = ReplayProvider::from_file("deepseek", &path).unwrap();
        let e = replay.complete(&req("changed"), &mut |_| {}, &Cancel::new()).unwrap_err();
        assert!(e.message.contains("does not match") && e.message.contains("conversation"), "{e}");

        let fail_path = dir.join("fail.jsonl");
        let rec = Recorder::new(Arc::new(Fake { calls: AtomicUsize::new(0), fail: true }), &fail_path, "deepseek").unwrap();
        let err = rec.complete(&req("x"), &mut |_| {}, &Cancel::new()).unwrap_err();
        assert_eq!(err.status, Some(429));
        drop(rec);
        let replay = ReplayProvider::from_file("deepseek", &fail_path).unwrap();
        let err = replay.complete(&req("x"), &mut |_| {}, &Cancel::new()).unwrap_err();
        assert_eq!((err.kind, err.status), (ProviderErrorKind::RateLimited { retry_after: None }, Some(429)));
    }
}
