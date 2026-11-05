//! Interface: model providers. Implementations live in `seagent-model`.

use crate::cancel::Cancel;
use crate::types::{ModelRequest, ModelResponse, StreamEvent};
use std::fmt;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub enum ProviderErrorKind {
    /// 429. `retry_after` from the header when present.
    RateLimited { retry_after: Option<Duration> },
    /// 503/529 "overloaded".
    Overloaded,
    /// Other 5xx.
    Server,
    /// Connection reset, DNS, TLS, broken stream.
    Network,
    Timeout,
    /// 401/403 — never retried.
    Auth,
    /// 400 that is not a context overflow — never retried.
    BadRequest,
    /// Prompt too long for the model; caller should compact and retry.
    ContextOverflow,
    Cancelled,
    /// Response did not parse / violated the wire format.
    Protocol,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderError {
    pub kind: ProviderErrorKind,
    pub message: String,
    pub status: Option<u16>,
}

impl ProviderError {
    pub fn new(kind: ProviderErrorKind, message: impl Into<String>) -> Self {
        ProviderError { kind, message: message.into(), status: None }
    }
    pub fn with_status(mut self, s: u16) -> Self {
        self.status = Some(s);
        self
    }
    pub fn is_retryable(&self) -> bool {
        use ProviderErrorKind::*;
        matches!(self.kind, RateLimited { .. } | Overloaded | Server | Network | Timeout | Protocol)
    }
    /// Whether falling back to another provider makes sense (auth on one provider
    /// says nothing about another).
    pub fn allows_fallback(&self) -> bool {
        use ProviderErrorKind::*;
        self.is_retryable() || matches!(self.kind, Auth)
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            Some(s) => write!(f, "{:?} (HTTP {s}): {}", self.kind, self.message),
            None => write!(f, "{:?}: {}", self.kind, self.message),
        }
    }
}

impl std::error::Error for ProviderError {}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ModelCaps {
    pub context_window: u64,
    pub max_output: u32,
    pub tools: bool,
    pub vision: bool,
    /// Explicit cache breakpoints (Anthropic) vs automatic prefix caching.
    pub explicit_cache: bool,
}

pub trait Provider: Send + Sync {
    /// Stable id, e.g. "anthropic", "deepseek".
    fn id(&self) -> &str;
    fn caps(&self, model: &str) -> ModelCaps;
    /// Run one request. Must poll `cancel` while streaming and return
    /// `Cancelled` promptly. `on_event` receives deltas as they arrive.
    fn complete(
        &self,
        req: &ModelRequest,
        on_event: &mut dyn FnMut(StreamEvent),
        cancel: &Cancel,
    ) -> Result<ModelResponse, ProviderError>;
}
