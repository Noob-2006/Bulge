//! ark-model: streaming adapters for the four wire formats that cover practically
//! every model vendor. No vendor SDKs — just HTTP + SSE.

mod anthropic;
pub mod classify;
mod gemini;
mod http;
mod openai_chat;
mod responses;
pub mod sse;

use ark_core::{estimate_request_tokens, estimate_tokens, Block, Message, ModelCaps, ModelRequest, Provider, Usage};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireFormat {
    #[serde(rename = "openai_chat")]
    OpenAiChat,
    #[serde(rename = "openai_responses")]
    OpenAiResponses,
    Anthropic,
    Gemini,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ProviderConfig {
    pub id: String,
    pub format: WireFormat,
    pub base_url: String,
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
}

pub const DEFAULT_IDLE_SECS: u64 = 120;

fn preset(id: &str, format: WireFormat, base: &str, env: Option<&str>) -> ProviderConfig {
    ProviderConfig {
        id: id.into(),
        format,
        base_url: base.into(),
        api_key_env: env.map(String::from),
        api_key: None,
        headers: BTreeMap::new(),
        idle_timeout_secs: None,
    }
}

pub fn presets() -> Vec<ProviderConfig> {
    use WireFormat::*;
    vec![
        preset("openai", OpenAiResponses, "https://api.openai.com/v1", Some("OPENAI_API_KEY")),
        preset("openai-chat", OpenAiChat, "https://api.openai.com/v1", Some("OPENAI_API_KEY")),
        preset("anthropic", Anthropic, "https://api.anthropic.com/v1", Some("ANTHROPIC_API_KEY")),
        preset("gemini", Gemini, "https://generativelanguage.googleapis.com/v1beta", Some("GEMINI_API_KEY")),
        preset("deepseek", OpenAiChat, "https://api.deepseek.com", Some("DEEPSEEK_API_KEY")),
        preset("openrouter", OpenAiChat, "https://openrouter.ai/api/v1", Some("OPENROUTER_API_KEY")),
        preset("groq", OpenAiChat, "https://api.groq.com/openai/v1", Some("GROQ_API_KEY")),
        preset("xai", OpenAiChat, "https://api.x.ai/v1", Some("XAI_API_KEY")),
        preset("mistral", OpenAiChat, "https://api.mistral.ai/v1", Some("MISTRAL_API_KEY")),
        preset("together", OpenAiChat, "https://api.together.xyz/v1", Some("TOGETHER_API_KEY")),
        preset("fireworks", OpenAiChat, "https://api.fireworks.ai/inference/v1", Some("FIREWORKS_API_KEY")),
        preset("ollama", OpenAiChat, "http://127.0.0.1:11434/v1", None),
        preset("lmstudio", OpenAiChat, "http://127.0.0.1:1234/v1", None),
        preset("vllm", OpenAiChat, "http://127.0.0.1:8000/v1", None),
        preset("dashscope", OpenAiChat, "https://dashscope-intl.aliyuncs.com/compatible-mode/v1", Some("DASHSCOPE_API_KEY")),
        preset("moonshot", OpenAiChat, "https://api.moonshot.ai/v1", Some("MOONSHOT_API_KEY")),
        preset("zhipu", OpenAiChat, "https://open.bigmodel.cn/api/paas/v4", Some("ZHIPU_API_KEY")),
        preset("siliconflow", OpenAiChat, "https://api.siliconflow.cn/v1", Some("SILICONFLOW_API_KEY")),
        preset("minimax", OpenAiChat, "https://api.minimax.io/v1", Some("MINIMAX_API_KEY")),
    ]
}

/// Connection details shared by every adapter.
pub(crate) struct Conn {
    pub id: String,
    pub base: String,
    pub key: Option<String>,
    pub headers: Vec<(String, String)>,
    pub http: http::Http,
}

impl Conn {
    pub fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base.trim_end_matches('/'), path.trim_start_matches('/'))
    }
    pub fn headers_with(&self, auth: Option<(&str, String)>) -> Vec<(String, String)> {
        let mut h: Vec<(String, String)> = auth.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        h.extend(self.headers.iter().cloned());
        h
    }
}

pub fn build(cfg: &ProviderConfig) -> Result<Arc<dyn Provider>, String> {
    build_with_idle(cfg, Duration::from_secs(cfg.idle_timeout_secs.unwrap_or(DEFAULT_IDLE_SECS).max(1)))
}

/// Like [`build`] with an explicit idle timeout (sub-second values are useful in tests).
pub fn build_with_idle(cfg: &ProviderConfig, idle: Duration) -> Result<Arc<dyn Provider>, String> {
    let key = match (&cfg.api_key, &cfg.api_key_env) {
        (Some(k), _) if !k.is_empty() => Some(k.clone()),
        (_, Some(env)) => match std::env::var(env) {
            Ok(k) if !k.trim().is_empty() => Some(k.trim().to_string()),
            _ => return Err(format!("provider `{}`: API key missing — set ${env}", cfg.id)),
        },
        _ => None,
    };
    if !(cfg.base_url.starts_with("http://") || cfg.base_url.starts_with("https://")) {
        return Err(format!("provider `{}`: base_url must start with http:// or https://", cfg.id));
    }
    let conn = Conn {
        id: cfg.id.clone(),
        base: cfg.base_url.clone(),
        key,
        headers: cfg.headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        http: http::Http::new(idle),
    };
    Ok(match cfg.format {
        WireFormat::OpenAiChat => Arc::new(openai_chat::OpenAiChat::new(conn)),
        WireFormat::OpenAiResponses => Arc::new(responses::Responses::new(conn)),
        WireFormat::Anthropic => Arc::new(anthropic::Anthropic::new(conn)),
        WireFormat::Gemini => Arc::new(gemini::Gemini::new(conn)),
    })
}

/// Model ids the provider advertises (`GET {base}/models`), for setup and pickers.
/// Also the cheapest way to tell whether a key works: 401/403 come back as errors.
pub fn list_models(cfg: &ProviderConfig, key: Option<&str>) -> Result<Vec<String>, String> {
    use std::io::Read;
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(20))).build().into();
    let url = format!("{}/models", cfg.base_url.trim_end_matches('/'));
    let mut req = agent.get(&url).header("accept", "application/json");
    match (cfg.format, key) {
        (WireFormat::Anthropic, Some(k)) => req = req.header("x-api-key", k).header("anthropic-version", "2023-06-01"),
        (WireFormat::Gemini, Some(k)) => req = req.header("x-goog-api-key", k),
        (_, Some(k)) => req = req.header("authorization", &format!("Bearer {k}")),
        _ => {}
    }
    for (k, v) in &cfg.headers {
        req = req.header(k, v);
    }
    let resp = req.call().map_err(|e| format!("GET {url}: {e}"))?;
    let status = resp.status().as_u16();
    let mut raw = String::new();
    resp.into_body().into_reader().take(4 << 20).read_to_string(&mut raw).map_err(|e| format!("reading {url}: {e}"))?;
    if !(200..300).contains(&status) {
        let e = classify::from_status(status, None, &raw);
        return Err(format!("{}: {e}", cfg.id));
    }
    let v: Value = serde_json::from_str(&raw).map_err(|e| format!("{url}: not JSON ({e})"))?;
    Ok(parse_model_list(&v))
}

fn parse_model_list(v: &Value) -> Vec<String> {
    let mut out = vec![];
    // OpenAI / Anthropic / most compatible servers: {"data": [{"id": ..}]}
    for m in v["data"].as_array().into_iter().flatten() {
        if let Some(id) = m["id"].as_str() {
            out.push(id.to_string());
        }
    }
    // Gemini: {"models": [{"name": "models/x", "supportedGenerationMethods": [..]}]}
    for m in v["models"].as_array().into_iter().flatten() {
        let chat = m["supportedGenerationMethods"].as_array().is_none_or(|a| a.iter().any(|x| x == "generateContent"));
        if let (Some(n), true) = (m["name"].as_str(), chat) {
            out.push(n.trim_start_matches("models/").to_string());
        }
    }
    out.dedup();
    out
}

pub fn caps_for(model: &str) -> ModelCaps {
    let m = model.to_lowercase();
    let c = |ctx: u64, out: u32, vision: bool, explicit_cache: bool| ModelCaps {
        context_window: ctx,
        max_output: out,
        tools: true,
        vision,
        explicit_cache,
    };
    if m.contains("claude") {
        c(200_000, 64_000, true, true)
    } else if m.contains("gemini") {
        c(1_048_576, 65_536, true, false)
    } else if m.starts_with("gpt-5") {
        c(400_000, 128_000, true, false)
    } else if m.starts_with("gpt-4.1") {
        c(1_047_576, 32_768, true, false)
    } else if m.starts_with("gpt-4o") {
        c(128_000, 16_384, true, false)
    } else if m.starts_with("o3") || m.starts_with("o4") {
        c(200_000, 100_000, true, false)
    } else if m.contains("deepseek") {
        c(128_000, 8_192, false, false)
    } else if m.contains("kimi") || m.contains("moonshot") {
        c(256_000, 16_384, false, false)
    } else if m.contains("grok") {
        c(256_000, 16_384, true, false)
    } else if m.contains("qwen") || m.contains("glm") || m.contains("minimax") || m.contains("mistral") || m.contains("llama") {
        c(128_000, 8_192, false, false)
    } else {
        c(32_768, 4_096, false, false)
    }
}

/// Tool arguments from a streamed JSON string. Malformed arguments are kept so the
/// kernel can report them back to the model instead of failing the whole response.
pub(crate) fn parse_args(raw: &str) -> Value {
    if raw.trim().is_empty() {
        return Value::Object(Default::default());
    }
    serde_json::from_str(raw).unwrap_or_else(|_| serde_json::json!({ "__invalid_json": raw }))
}

/// Token budget for a reasoning effort level (None = off / provider default).
pub(crate) fn thinking_budget(level: Option<&str>) -> Option<u32> {
    match level? {
        "low" => Some(2048),
        "medium" => Some(8192),
        "high" => Some(24576),
        _ => None,
    }
}

/// `data:` URL for an image block (OpenAI formats).
pub(crate) fn data_url(media_type: &str, data: &str) -> String {
    format!("data:{media_type};base64,{data}")
}

/// Fill usage heuristically when the provider sent none.
pub(crate) fn finalize_usage(usage: Option<Usage>, req: &ModelRequest, msg: &Message) -> Usage {
    match usage {
        Some(u) if u.input_tokens + u.output_tokens + u.cache_read_tokens > 0 => u,
        _ => {
            let out: u64 = msg
                .content
                .iter()
                .map(|b| match b {
                    Block::Text { text } | Block::Thinking { text, .. } => estimate_tokens(text),
                    Block::ToolUse { name, input, .. } => estimate_tokens(name) + estimate_tokens(&input.to_string()),
                    Block::ToolResult { content, .. } => estimate_tokens(content),
                    Block::Image { .. } => ark_core::IMAGE_TOKENS,
                })
                .sum();
            Usage { input_tokens: estimate_request_tokens(req), output_tokens: out, estimated: true, ..Default::default() }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_lists_from_each_api_shape() {
        let oa = serde_json::json!({"data": [{"id": "gpt-x"}, {"id": "gpt-y"}]});
        assert_eq!(parse_model_list(&oa), vec!["gpt-x", "gpt-y"]);
        let g = serde_json::json!({"models": [{"name": "models/gemini-a", "supportedGenerationMethods": ["generateContent"]}, {"name": "models/embed", "supportedGenerationMethods": ["embedContent"]}]});
        assert_eq!(parse_model_list(&g), vec!["gemini-a"]);
        assert!(parse_model_list(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn presets_are_unique_and_valid() {
        let ps = presets();
        let mut ids: Vec<_> = ps.iter().map(|p| p.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), ps.len());
        assert!(ps.iter().all(|p| p.base_url.starts_with("http")));
        for local in ["ollama", "lmstudio", "vllm"] {
            let p = ps.iter().find(|p| p.id == local).unwrap();
            assert!(p.api_key_env.is_none());
            assert!(build(p).is_ok());
        }
    }

    #[test]
    fn build_rejects_missing_key_and_bad_url() {
        let mut p = preset("x", WireFormat::Anthropic, "https://e", Some("ARK_TEST_SURELY_UNSET_KEY_42"));
        let err = build(&p).err().unwrap();
        assert!(err.contains("ARK_TEST_SURELY_UNSET_KEY_42"), "{err}");
        p.api_key = Some("k".into());
        assert!(build(&p).is_ok());
        p.base_url = "ftp://x".into();
        assert!(build(&p).is_err());
    }

    #[test]
    fn config_roundtrips_through_toml_like_json() {
        let j = r#"{"id":"my","format":"openai_chat","base_url":"http://h/v1"}"#;
        let c: ProviderConfig = serde_json::from_str(j).unwrap();
        assert_eq!(c.format, WireFormat::OpenAiChat);
        assert!(c.headers.is_empty());
        assert!(serde_json::from_str::<ProviderConfig>(r#"{"id":"x","format":"nope","base_url":"h"}"#).is_err());
    }

    #[test]
    fn caps_table() {
        assert!(caps_for("claude-opus-5-5").explicit_cache);
        assert_eq!(caps_for("gemini-3-pro").context_window, 1_048_576);
        assert_eq!(caps_for("some-unknown-local-model").context_window, 32_768);
    }

    #[test]
    fn args_parsing() {
        assert_eq!(parse_args(""), serde_json::json!({}));
        assert_eq!(parse_args(r#"{"a":1}"#), serde_json::json!({"a":1}));
        assert_eq!(parse_args("{\"a\":"), serde_json::json!({"__invalid_json":"{\"a\":"}));
    }
}
