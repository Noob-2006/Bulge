//! Build the model backend from flags, env, and an on-disk key.
//!
//! The API key is read from `$BULGE_API_KEY` or a per-host file under
//! `~/.bulge/keys/<host>` (expected mode 600). It is only ever held in memory to
//! construct the backend and is never logged or written anywhere.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bulge_llm::http::{HttpBackend, HttpBackendConfig};
use bulge_llm::protocol::WireProtocol;
use bulge_llm::protocol::anthropic::AnthropicMessages;
use bulge_llm::protocol::openai_chat::OpenAiChat;
use bulge_llm::retry::RetryPolicy;
use bulge_llm::{LlmBackend, ModelInfo};

/// Which wire protocol to speak.
#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    OpenAiChat,
    Anthropic,
}

impl Protocol {
    pub fn parse(name: &str) -> Result<Self, String> {
        match name {
            "openai" | "openai_chat" | "openai-chat" => Ok(Self::OpenAiChat),
            "anthropic" | "messages" => Ok(Self::Anthropic),
            other => Err(format!("unknown protocol {other:?} (want `openai` or `anthropic`)")),
        }
    }
}

/// Everything needed to construct the backend.
pub struct BackendSpec {
    pub id: String,
    pub base_url: String,
    pub protocol: Protocol,
    pub model: String,
    pub context_window: u32,
    pub max_tokens: u32,
    pub reasoning: bool,
}

/// The host part of a URL, for locating its key file (`api.deepseek.com`).
fn host_of(base_url: &str) -> &str {
    base_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(base_url)
}

/// Load the key from `$BULGE_API_KEY`, else `~/.bulge/keys/<host>`. The content
/// is returned to the caller unlogged; a missing key is a clear, actionable error.
pub fn load_api_key(base_url: &str) -> Result<String, String> {
    if let Ok(key) = std::env::var("BULGE_API_KEY") {
        let key = key.trim().to_string();
        if !key.is_empty() {
            return Ok(key);
        }
    }
    let host = host_of(base_url);
    let path = key_path(host);
    match std::fs::read_to_string(&path) {
        Ok(contents) => {
            let key = contents.trim().to_string();
            if key.is_empty() {
                Err(format!("key file {} is empty", path.display()))
            } else {
                Ok(key)
            }
        }
        Err(_) => Err(format!(
            "no API key: set $BULGE_API_KEY or place the key (chmod 600) at {}",
            path.display()
        )),
    }
}

/// `~/.bulge/keys/<host>`.
pub fn key_path(host: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".bulge/keys").join(host)
}

/// Construct the backend. The key is loaded here and moved into the config; it
/// does not appear in the returned value's `Debug` or anywhere else.
pub fn build(spec: &BackendSpec) -> Result<Arc<dyn LlmBackend>, String> {
    let api_key = load_api_key(&spec.base_url)?;
    let model = ModelInfo {
        id: spec.model.clone(),
        context_window: spec.context_window,
        max_tokens: spec.max_tokens,
        system_prompt_update: Default::default(),
        deferred_tools: false,
        images: false,
        reasoning: spec.reasoning,
    };
    let config = HttpBackendConfig {
        id: spec.id.clone(),
        base_url: spec.base_url.clone(),
        api_key,
        models: vec![model],
        default_max_tokens: spec.max_tokens,
        stream_idle_timeout: Duration::from_secs(120),
        retry: RetryPolicy::default(),
    };
    let protocol: Arc<dyn WireProtocol> = match spec.protocol {
        Protocol::OpenAiChat => Arc::new(OpenAiChat),
        Protocol::Anthropic => Arc::new(AnthropicMessages),
    };
    let backend = HttpBackend::new(config, protocol).map_err(|e| format!("backend: {e}"))?;
    Ok(Arc::new(backend))
}
