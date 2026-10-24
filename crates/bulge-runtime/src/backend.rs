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
#[derive(Debug, Clone)]
pub struct BackendSpec {
    pub id: String,
    pub base_url: String,
    pub protocol: Protocol,
    pub model: String,
    pub context_window: u32,
    pub max_tokens: u32,
    pub reasoning: bool,
}

/// The model every front end starts with (the CLI, the desktop app, chat
/// channels, schedules, ACP), until the user picks another.
pub const DEFAULT_BASE_URL: &str = "https://api.deepseek.com";
pub const DEFAULT_MODEL: &str = "deepseek-flash";
pub const DEFAULT_CONTEXT_WINDOW: u32 = 128_000;
pub const DEFAULT_MAX_TOKENS: u32 = 8_192;

impl BackendSpec {
    /// A model at `base_url`, named after the URL's host (which also names its
    /// key file), with a 128K context, 8K output and no reasoning effort sent.
    pub fn new(base_url: impl Into<String>, protocol: Protocol, model: impl Into<String>) -> Self {
        let base_url = base_url.into();
        Self { id: host_of(&base_url).to_owned(), base_url, protocol, model: model.into(), context_window: DEFAULT_CONTEXT_WINDOW, max_tokens: DEFAULT_MAX_TOKENS, reasoning: false }
    }
}

/// The host part of a URL, for locating its key file (`api.deepseek.com`).
pub fn host_of(base_url: &str) -> &str {
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
    // Every use of the key goes through here: it is only ever sent over
    // HTTPS (plain http only to this machine, e.g. a local model server).
    check_endpoint(base_url)?;
    if let Ok(key) = std::env::var("BULGE_API_KEY") {
        let key = key.trim().to_string();
        if !key.is_empty() {
            return Ok(key);
        }
    }
    let host = host_of(base_url);
    let path = key_path(host)?;
    if !path.exists() {
        return Err(format!("no API key: set $BULGE_API_KEY or place the key (chmod 600) at {}", path.display()));
    }
    // Refused when other users can read it, as every bulge key file is.
    bulge_util::fs::read_secret_file(&path)
}

/// Refuse to send a key to `base_url` unless it is HTTPS or this machine.
pub fn check_endpoint(base_url: &str) -> Result<(), String> {
    if base_url.starts_with("https://") {
        return Ok(());
    }
    let local = ["http://localhost", "http://127.0.0.1", "http://[::1]"].iter().any(|prefix| base_url.strip_prefix(prefix).is_some_and(|rest| rest.is_empty() || rest.starts_with(':') || rest.starts_with('/')));
    if local { Ok(()) } else { Err(format!("{base_url} is not HTTPS; the API key is only sent over HTTPS (or to this machine)")) }
}

/// `~/.bulge/keys/<host>`.
pub fn key_path(host: &str) -> Result<PathBuf, String> {
    // No fallback to the current directory: a key is never looked for (or
    // saved) wherever the process happens to run.
    Ok(bulge_util::fs::bulge_home()?.join("keys").join(host))
}

/// Whether the provider says `spec.model` accepts images: its `/models`
/// listing carries `input_modalities` (DeepSeek's does). Anything else —
/// no listing, no such field, an error — means no, so a text-only model is
/// never sent an image.
pub async fn probe_images(spec: &BackendSpec) -> bool {
    let Ok(key) = load_api_key(&spec.base_url) else { return false };
    let Ok(http) = reqwest::Client::builder().timeout(Duration::from_secs(10)).build() else { return false };
    let url = format!("{}/models", spec.base_url.trim_end_matches('/'));
    let Ok(response) = http.get(url).bearer_auth(key).send().await else { return false };
    let Ok(listing) = response.json::<serde_json::Value>().await else { return false };
    model_accepts_images(&listing, &spec.model)
}

fn model_accepts_images(listing: &serde_json::Value, model: &str) -> bool {
    listing
        .get("data")
        .and_then(serde_json::Value::as_array)
        .and_then(|models| models.iter().find(|m| m.get("id").and_then(serde_json::Value::as_str) == Some(model)))
        .and_then(|m| m.get("input_modalities"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|modalities| modalities.iter().any(|m| m.as_str() == Some("image")))
}

/// Construct the backend. The key is loaded here and moved into the config; it
/// does not appear in the returned value's `Debug` or anywhere else. `images`:
/// the model accepts image input (see [`probe_images`]).
pub fn build(spec: &BackendSpec, images: bool, default_effort: Option<bulge_llm::ReasoningEffort>) -> Result<Arc<dyn LlmBackend>, String> {
    let api_key = load_api_key(&spec.base_url)?;
    let model = ModelInfo {
        id: spec.model.clone(),
        context_window: spec.context_window,
        max_tokens: spec.max_tokens,
        system_prompt_update: Default::default(),
        deferred_tools: false,
        images,
        reasoning: spec.reasoning,
        // Calls that set no effort (learning, summaries) use the run's.
        default_effort,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_only_travel_over_https_or_to_this_machine() {
        assert!(check_endpoint("https://api.deepseek.com").is_ok());
        assert!(check_endpoint("http://127.0.0.1:11434/v1").is_ok());
        assert!(check_endpoint("http://localhost").is_ok());
        assert!(check_endpoint("http://api.deepseek.com").is_err());
        assert!(check_endpoint("http://localhost.evil.example").is_err());
        assert!(check_endpoint("http://127.0.0.1.evil.example").is_err());
    }

    #[test]
    fn image_support_comes_only_from_the_listing() {
        let listing = serde_json::json!({ "data": [
            { "id": "deepseek-flash", "input_modalities": ["text", "image"] },
            { "id": "deepseek-v4-pro", "input_modalities": ["text"] },
            { "id": "plain" }
        ]});
        assert!(model_accepts_images(&listing, "deepseek-flash"));
        assert!(!model_accepts_images(&listing, "deepseek-v4-pro"));
        assert!(!model_accepts_images(&listing, "plain"));
        assert!(!model_accepts_images(&listing, "missing"));
        assert!(!model_accepts_images(&serde_json::json!({}), "deepseek-flash"));
    }
}
