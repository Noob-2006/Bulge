//! seagent-model: streaming adapters for the wire formats that cover practically
//! every model vendor. No vendor SDKs — just HTTP + SSE (and AWS event streams,
//! SigV4, Google service-account JWTs, OAuth device/PKCE logins, written by hand).
#![allow(clippy::type_complexity)]

pub mod accounts;
#[cfg(feature = "agent-cli")]
pub mod acp;
#[cfg(feature = "agents-api")]
pub mod agentsapi;
mod anthropic;
pub mod auth;
// `aux.rs` is a reserved device name on Windows (Git for Windows cannot check it out).
#[path = "aux_models.rs"]
pub mod aux;
pub mod billing;
#[cfg(feature = "bedrock")]
mod bedrock;
pub mod catalog;
pub mod classify;
#[cfg(feature = "agent-cli")]
pub mod cli;
#[cfg(feature = "agent-cli")]
pub mod codex_app;
pub mod contextpin;
pub mod copilot;
#[cfg(feature = "bedrock")]
pub mod eventstream;
#[cfg(feature = "gemini")]
mod gemini;
pub mod google;
mod http;
#[cfg(feature = "local")]
pub mod local;
pub mod login;
pub mod moa;
pub mod modelsdb;
#[cfg(feature = "agent-cli")]
pub mod muse;
pub mod native_compact;
pub mod nous;
pub mod net;
mod openai_chat;
pub mod ratelimit;
pub mod reasoning;
pub mod replay;
mod responses;
#[cfg(feature = "bedrock")]
pub mod sigv4;
pub mod sse;
pub mod store;

use seagent_core::{
    estimate_request_tokens, estimate_tokens, Block, Message, ModelCaps, ModelRequest, Provider,
    Usage,
};
use auth::{Cred, CredSource};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

pub use anthropic::{fast_capable, is_oauth_token};
pub use catalog::{presets, resolve_alias, Preset};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WireFormat {
    #[serde(rename = "openai_chat")]
    #[default]
    OpenAiChat,
    #[serde(rename = "openai_responses")]
    OpenAiResponses,
    Anthropic,
    Gemini,
    /// AWS Bedrock Converse (ConverseStream, SigV4).
    Bedrock,
    /// An external agent CLI (claude, gemini, codex exec) run once per request.
    Cli,
    /// `codex app-server` over JSON-RPC stdio.
    CodexAppServer,
    /// Agent Client Protocol (`copilot --acp --stdio`) over JSON-RPC stdio.
    #[serde(rename = "acp")]
    Acp,
    /// OpenAI Agents API: hosted agent sessions, streamed turns.
    #[serde(rename = "agents_api")]
    AgentsApi,
    /// Meta Muse Code CLI (`muse serve`) over MSP JSON-RPC stdio.
    #[serde(rename = "muse")]
    Muse,
    /// Mixture of agents: reference models fan out, an aggregator answers.
    Moa,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
pub struct ProviderConfig {
    pub id: String,
    #[serde(default)]
    pub format: WireFormat,
    #[serde(default)]
    pub base_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_secs: Option<u64>,
    /// More env vars tried after `api_key_env` (first non-empty wins).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_envs: Vec<String>,
    /// Extra literal keys: with more than one credential the provider becomes a pool
    /// that rotates on 429/401/402 with per-key cooldowns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api_keys: Vec<String>,
    /// Shell command printing a (short-lived) key, bare or `{"access_token", "expires_in"}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_cmd: Option<String>,
    /// How the credential is sent / obtained. Empty = the format's default.
    /// `bearer` | `x-api-key` | `api-key` | `x-goog-api-key` | `none` | `aws` | `google`
    /// | `azure-ad` | `copilot` | `oauth`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub auth: String,
    /// Login flow whose stored tokens this provider uses (`seagent login <flow>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<String>,
    /// Query parameters added to every request (Azure `api-version`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub query: BTreeMap<String, String>,
    /// AWS / Google Cloud region; fills `{region}` in `base_url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Google Cloud project; fills `{project}` in `base_url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Model ids to offer when the provider has no usable list endpoint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,
    /// Wire quirks: `codex` (ChatGPT backend), `vertex` (Vertex publisher paths),
    /// `no_temperature`, `no_max_tokens`, `copilot`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quirks: Vec<String>,
    /// Reasoning levels this endpoint accepts; requests clamp to the nearest weaker one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_efforts: Option<Vec<String>>,
    /// Credential pool selection: `fill_first` (default) | `round_robin` | `random` | `least_used`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_strategy: Option<String>,
    /// CLI backends, app-server and managed local servers: program and arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// CLI output dialect: `text` | `claude-stream-json` | `gemini-stream-json` | `codex-jsonl`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dialect: Option<String>,
    /// Mixture of agents: reference models (`provider/model`) and the aggregator.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregator: Option<String>,
    /// Managed llama.cpp server: GGUF file (or models dir) served by `command` on demand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_path: Option<String>,
    /// Bedrock guardrail `id:version`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guardrail: Option<String>,
}

pub const DEFAULT_IDLE_SECS: u64 = 120;

impl ProviderConfig {
    pub fn has_quirk(&self, q: &str) -> bool {
        self.quirks.iter().any(|x| x == q)
    }
    /// The env vars a key may come from, in order.
    pub fn key_env_names(&self) -> Vec<String> {
        self.api_key_env
            .iter()
            .chain(self.key_envs.iter())
            .filter(|e| !e.is_empty())
            .cloned()
            .collect()
    }
    /// Whether this provider needs no secret at all (local servers, CLI backends).
    pub fn keyless(&self) -> bool {
        self.auth == "none"
            || self.has_quirk("optional_key")
            || matches!(
                self.format,
                WireFormat::Cli
                    | WireFormat::CodexAppServer
                    | WireFormat::Acp
                    | WireFormat::Muse
                    | WireFormat::Moa
            )
            || (self.auth.is_empty()
                && self.key_env_names().is_empty()
                && self.api_key.is_none()
                && self.api_keys.is_empty()
                && self.key_cmd.is_none()
                && self.oauth.is_none())
    }
    /// Expand `{region}`, `{project}` and `{env:VAR}` in `base_url`.
    pub fn resolved_base(&self) -> Result<String, String> {
        expand_base(
            &self.id,
            &self.base_url,
            self.region.as_deref(),
            self.project.as_deref(),
        )
    }
}

pub(crate) fn expand_base(
    id: &str,
    base: &str,
    region: Option<&str>,
    project: Option<&str>,
) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = base;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let Some(j) = rest[i..].find('}') else {
            out.push_str(&rest[i..]);
            rest = "";
            break;
        };
        let name = &rest[i + 1..i + j];
        let val = match name {
            "region" if base.contains("aiplatform") => region
                .map(String::from)
                .or_else(|| {
                    env_first(&[
                        "GOOGLE_CLOUD_LOCATION",
                        "CLOUD_ML_REGION",
                        "VERTEX_LOCATION",
                    ])
                })
                .or(Some("us-central1".into())),
            "region" if base.contains("amazonaws") || base.contains("api.aws") => region
                .map(String::from)
                .or_else(|| env_first(&["AWS_REGION", "AWS_DEFAULT_REGION"]))
                .or(Some("us-east-1".into())),
            "region" => region.map(String::from).or_else(|| {
                env_first(&[
                    "AWS_REGION",
                    "AWS_DEFAULT_REGION",
                    "GOOGLE_CLOUD_LOCATION",
                    "CLOUD_ML_REGION",
                ])
            }),
            "project" => project
                .map(String::from)
                .or_else(|| {
                    env_first(&[
                        "GOOGLE_CLOUD_PROJECT",
                        "GOOGLE_CLOUD_PROJECT_ID",
                        "ANTHROPIC_VERTEX_PROJECT_ID",
                    ])
                })
                .or_else(google::adc_project),
            n if n.starts_with("env:") => env_first(&[&n[4..]]),
            _ => {
                out.push_str(&rest[i..i + j + 1]);
                rest = &rest[i + j + 1..];
                continue;
            }
        };
        let Some(v) = val else {
            let hint = match name {
                "region" => {
                    "set `region` in [providers.<id>] or $AWS_REGION / $GOOGLE_CLOUD_LOCATION"
                        .to_string()
                }
                "project" => {
                    "set `project` in [providers.<id>] or $GOOGLE_CLOUD_PROJECT".to_string()
                }
                n => format!("set ${}", &n[4..]),
            };
            return Err(format!(
                "provider `{id}`: base_url needs {{{name}}}: {hint}"
            ));
        };
        out.push_str(v.trim().trim_end_matches('/'));
        rest = &rest[i + j + 1..];
    }
    out.push_str(rest);
    // Vertex `global` location lives on the bare host.
    Ok(out.replace("://global-aiplatform.", "://aiplatform."))
}

pub(crate) fn env_first(names: &[&str]) -> Option<String> {
    names.iter().find_map(|n| {
        std::env::var(n)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

/// How a credential travels on the wire.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Style {
    Bearer,
    XApiKey,
    XGoogApiKey,
    ApiKey,
    None,
}

/// A stored key that cannot go in a header is an auth problem, not a network one: it
/// fails the same way every time, so it is never retried and the message says what to do.
pub(crate) fn usable_key(provider: &str, cred: &Cred) -> Result<(), seagent_core::ProviderError> {
    match cred.token.as_deref().map(auth::check_key) {
        Some(Err(e)) => Err(seagent_core::ProviderError::new(
            seagent_core::ProviderErrorKind::Auth,
            format!("{provider}: {e}; enter it again with `seagent setup` or `seagent secrets set <KEY_NAME>`"),
        )),
        _ => Ok(()),
    }
}

/// Connection details shared by every adapter.
pub(crate) struct Conn {
    pub id: String,
    pub base: String,
    pub cred: Arc<dyn CredSource>,
    pub headers: Vec<(String, String)>,
    pub query: Vec<(String, String)>,
    pub auth: String,
    pub quirks: Vec<String>,
    pub efforts: Option<Vec<String>>,
    pub http: http::Http,
}

impl Conn {
    /// Only the gated adapters (bedrock/gemini/agents-api) build URLs by hand; a slim
    /// build leaves this unused.
    #[allow(dead_code)]
    pub fn url(&self, path: &str) -> String {
        self.url_on(&self.base, path)
    }
    pub fn url_on(&self, base: &str, path: &str) -> String {
        let mut u = format!(
            "{}/{}",
            base.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        if !self.query.is_empty() {
            let q: Vec<String> = self
                .query
                .iter()
                .map(|(k, v)| format!("{}={}", login::urlencode(k), login::urlencode(v)))
                .collect();
            u.push(if u.contains('?') { '&' } else { '?' });
            u.push_str(&q.join("&"));
        }
        u
    }
    pub fn quirk(&self, q: &str) -> bool {
        self.quirks.iter().any(|x| x == q)
    }
    fn style(&self, default: Style) -> Style {
        match self.auth.as_str() {
            "bearer" | "google" | "azure-ad" | "copilot" | "oauth" => Style::Bearer,
            "x-api-key" => Style::XApiKey,
            "x-goog-api-key" => Style::XGoogApiKey,
            "api-key" => Style::ApiKey,
            "none" => Style::None,
            _ => default,
        }
    }
    /// The credential for this request: effective base URL, headers (auth first, then
    /// the credential's own, then configured ones) and the credential itself.
    pub fn prepare(
        &self,
        default: Style,
    ) -> Result<(String, Vec<(String, String)>, Cred), seagent_core::ProviderError> {
        let cred = self.cred.get()?;
        usable_key(&self.id, &cred)?;
        let mut h: Vec<(String, String)> = Vec::new();
        if let Some(k) = cred.token.as_deref().filter(|k| !k.is_empty()) {
            match self.style(default) {
                Style::Bearer => h.push(("authorization".into(), format!("Bearer {k}"))),
                Style::XApiKey => h.push(("x-api-key".into(), k.to_string())),
                Style::XGoogApiKey => h.push(("x-goog-api-key".into(), k.to_string())),
                Style::ApiKey => h.push(("api-key".into(), k.to_string())),
                Style::None => {}
            }
        }
        h.extend(cred.headers.iter().cloned());
        for (k, v) in &self.headers {
            h.retain(|(x, _)| !x.eq_ignore_ascii_case(k));
            h.push((k.clone(), v.clone()));
        }
        let base = cred.base.clone().unwrap_or_else(|| self.base.clone());
        Ok((base, h, cred))
    }
    /// Reasoning level clamped to what this endpoint accepts.
    pub fn effort(&self, wire: &[&str], req: &ModelRequest) -> Option<String> {
        let lvl = req.reasoning.as_deref()?;
        let allowed: Vec<&str> = match &self.efforts {
            Some(v) => v.iter().map(String::as_str).collect(),
            None => wire.to_vec(),
        };
        reasoning::clamp(lvl, &allowed).map(String::from)
    }
}

/// Error for a wire format whose adapter was compiled out (`--no-default-features`).
/// Every gated adapter keeps its [`WireFormat`] variant, so config parsing, `seagent models
/// providers` and presets stay identical in a slim build — only `build` refuses.
#[allow(dead_code)] // only referenced by the `#[cfg(not(feature = …))]` arms
fn unavailable(cfg: &ProviderConfig, feature: &str) -> String {
    format!(
        "provider `{}`: the `{}` wire format is not compiled into this build (cargo feature `{}` of seagent-model is off; see docs/BUILD.md)",
        cfg.id,
        format!("{:?}", cfg.format).to_lowercase(),
        feature
    )
}

pub fn build(cfg: &ProviderConfig) -> Result<Arc<dyn Provider>, String> {
    build_with_idle(
        cfg,
        Duration::from_secs(cfg.idle_timeout_secs.unwrap_or(DEFAULT_IDLE_SECS).max(1)),
    )
}

/// Like [`build`] with an explicit idle timeout (sub-second values are useful in tests).
pub fn build_with_idle(cfg: &ProviderConfig, idle: Duration) -> Result<Arc<dyn Provider>, String> {
    let cred = auth::source_for(cfg, None)?;
    build_with(cfg, cred, idle)
}

/// Build an adapter around an explicit credential source (pools, stored logins).
pub fn build_with(
    cfg: &ProviderConfig,
    cred: Arc<dyn CredSource>,
    idle: Duration,
) -> Result<Arc<dyn Provider>, String> {
    match cfg.format {
        #[cfg(feature = "agent-cli")]
        WireFormat::Cli => return Ok(Arc::new(cli::CliBackend::new(cfg)?)),
        #[cfg(feature = "agent-cli")]
        WireFormat::CodexAppServer => return Ok(Arc::new(codex_app::AppServer::new(cfg)?)),
        #[cfg(feature = "agent-cli")]
        WireFormat::Acp => return Ok(Arc::new(acp::CopilotAcp::new(cfg)?)),
        #[cfg(feature = "agent-cli")]
        WireFormat::Muse => return Ok(Arc::new(muse::Muse::new(cfg)?)),
        #[cfg(not(feature = "agent-cli"))]
        WireFormat::Cli | WireFormat::CodexAppServer | WireFormat::Acp | WireFormat::Muse => {
            return Err(unavailable(cfg, "agent-cli"))
        }
        WireFormat::Moa => return Err(format!(
            "provider `{}`: mixture-of-agents providers are built by the resolver (moa::Moa::new)",
            cfg.id
        )),
        _ => {}
    }
    let base = if cfg.format == WireFormat::OpenAiChat && cfg.model_path.is_some() {
        // Managed llama.cpp: the base URL is wherever seagent starts the server.
        String::new()
    } else {
        cfg.resolved_base()?
    };
    if cfg.model_path.is_none() && !(base.starts_with("http://") || base.starts_with("https://")) {
        return Err(format!(
            "provider `{}`: base_url must start with http:// or https://",
            cfg.id
        ));
    }
    let cred: Arc<dyn CredSource> = match &cfg.model_path {
        #[cfg(feature = "local")]
        Some(_) => Arc::new(local::Managed::new(cfg, cred)?),
        #[cfg(not(feature = "local"))]
        Some(_) => return Err(unavailable(cfg, "local")),
        None => cred,
    };
    let conn = Conn {
        id: cfg.id.clone(),
        base,
        cred: cred.clone(),
        headers: cfg
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        query: cfg
            .query
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        auth: cfg.auth.clone(),
        quirks: cfg.quirks.clone(),
        efforts: cfg.reasoning_efforts.clone(),
        http: http::Http::new(idle, &cfg.id),
    };
    let p: Arc<dyn Provider> = match cfg.format {
        WireFormat::OpenAiChat => Arc::new(openai_chat::OpenAiChat::new(conn)),
        WireFormat::OpenAiResponses => Arc::new(responses::Responses::new(conn)),
        WireFormat::Anthropic => Arc::new(anthropic::Anthropic::new(conn)),
        #[cfg(feature = "gemini")]
        WireFormat::Gemini => Arc::new(gemini::Gemini::new(conn)),
        #[cfg(not(feature = "gemini"))]
        WireFormat::Gemini => return Err(unavailable(cfg, "gemini")),
        #[cfg(feature = "bedrock")]
        WireFormat::Bedrock => Arc::new(bedrock::Bedrock::new(conn, cfg)?),
        #[cfg(not(feature = "bedrock"))]
        WireFormat::Bedrock => return Err(unavailable(cfg, "bedrock")),
        #[cfg(feature = "agents-api")]
        WireFormat::AgentsApi => Arc::new(agentsapi::AgentsApi::new(conn, cfg)),
        #[cfg(not(feature = "agents-api"))]
        WireFormat::AgentsApi => return Err(unavailable(cfg, "agents-api")),
        WireFormat::Cli
        | WireFormat::CodexAppServer
        | WireFormat::Acp
        | WireFormat::Muse
        | WireFormat::Moa => unreachable!(),
    };
    Ok(Arc::new(auth::Reauth { inner: p, cred }))
}

/// Model ids the provider advertises (`GET {base}/models`), for setup and pickers.
/// Also the cheapest way to tell whether a key works: 401/403 come back as errors.
pub fn list_models(cfg: &ProviderConfig, key: Option<&str>) -> Result<Vec<String>, String> {
    let cred: Arc<dyn CredSource> = match key {
        Some(k) => Arc::new(auth::Static::new(Some(k.to_string()))),
        None => auth::source_for(cfg, None)?,
    };
    list_models_with(cfg, &*cred)
}

/// [`list_models`] with an explicit credential (stored logins, pools, cloud auth).
pub fn list_models_with(
    cfg: &ProviderConfig,
    cred: &dyn CredSource,
) -> Result<Vec<String>, String> {
    fetch_models(cfg, cred, false)
}

/// [`list_models_with`] for a live picker or a key test: an HTTP error (401 bad key, 404,
/// 5xx) or an empty answer is an error instead of the configured ids, so the caller can tell a
/// fresh listing from its own fallback.
pub fn list_models_live(cfg: &ProviderConfig, cred: &dyn CredSource) -> Result<Vec<String>, String> {
    fetch_models(cfg, cred, true)
}

fn fetch_models(cfg: &ProviderConfig, cred: &dyn CredSource, strict: bool) -> Result<Vec<String>, String> {
    match cfg.format {
        #[cfg(feature = "bedrock")]
        WireFormat::Bedrock => return bedrock::list_models(cfg),
        #[cfg(not(feature = "bedrock"))]
        WireFormat::Bedrock => return Err(unavailable(cfg, "bedrock")),
        // Live ACP list (`session/new` advertises what the account may use); the configured ids stand in when the CLI cannot be reached.
        #[cfg(feature = "agent-cli")]
        WireFormat::Acp => {
            return Ok(acp::models(cfg).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| if cfg.models.is_empty() { vec!["default".into()] } else { cfg.models.clone() }))
        }
        #[cfg(feature = "agent-cli")]
        WireFormat::Cli
        | WireFormat::CodexAppServer
        | WireFormat::Muse
        | WireFormat::Moa => {
            return Ok(if cfg.models.is_empty() {
                vec!["default".into()]
            } else {
                cfg.models.clone()
            });
        }
        #[cfg(not(feature = "agent-cli"))]
        WireFormat::Acp | WireFormat::Cli | WireFormat::CodexAppServer | WireFormat::Muse => {
            return Err(unavailable(cfg, "agent-cli"))
        }
        #[cfg(not(feature = "agent-cli"))]
        WireFormat::Moa => {
            return Ok(if cfg.models.is_empty() {
                vec!["default".into()]
            } else {
                cfg.models.clone()
            });
        }
        _ => {}
    }
    if !cfg.models.is_empty() && cfg.has_quirk("static_models") {
        return Ok(cfg.models.clone());
    }
    let c = cred.get().map_err(|e| format!("{}: {e}", cfg.id))?;
    usable_key(&cfg.id, &c).map_err(|e| e.to_string())?;
    let base = match c.base.clone() {
        Some(b) => b,
        None => cfg.resolved_base()?,
    };
    let agent = net::agent(Duration::from_secs(20), &base);
    let url = if cfg.has_quirk("vertex") && cfg.format == WireFormat::Gemini {
        // Vertex publisher model listing lives on v1beta1.
        format!(
            "{}/models",
            base.replace("/v1/", "/v1beta1/").trim_end_matches('/')
        )
    } else {
        format!("{}/models", base.trim_end_matches('/'))
    };
    let (status, raw) = models_get(cfg, &c, &agent, &url)?;
    // Ollama's OpenAI-compatible `/v1/models` is missing on older servers; the native
    // `/api/tags` (`{"models": [{"name": ..}]}`) lists the same pulled models.
    let (status, raw) = match base.trim_end_matches('/').strip_suffix("/v1") {
        Some(root) if status == 404 && (cfg.id == "ollama" || root.ends_with(":11434")) => models_get(cfg, &c, &agent, &format!("{root}/api/tags"))?,
        _ => (status, raw),
    };
    if !(200..300).contains(&status) {
        if !strict && !cfg.models.is_empty() {
            return Ok(cfg.models.clone());
        }
        let e = classify::from_status(status, None, &raw);
        return Err(format!("{}: HTTP {status}: {e}", cfg.id));
    }
    let v: Value = serde_json::from_str(&raw).map_err(|e| format!("{url}: not JSON ({e})"))?;
    // Learn the windows this endpoint reports about its own models (production writer for
    // `contextpin::learned`, which then beats the registry/table guess everywhere).
    for (m, ctx) in parse_model_contexts(&v) {
        crate::contextpin::learn_from_endpoint(&m, &base, ctx);
    }
    let mut out = parse_model_list(&v);
    if out.is_empty() && !strict {
        out = cfg.models.clone();
    }
    Ok(out)
}

/// One authenticated `GET` of a model listing: (status, body). Paginated APIs are asked for
/// their largest page (Anthropic `limit`, Gemini `pageSize`) so one call sees every model.
fn models_get(cfg: &ProviderConfig, c: &auth::Cred, agent: &ureq::Agent, url: &str) -> Result<(u16, String), String> {
    use std::io::Read;
    let mut req = agent.get(url).header("accept", "application/json");
    let style = match (cfg.auth.as_str(), cfg.format) {
        ("api-key", _) => Style::ApiKey,
        ("x-api-key", _) => Style::XApiKey,
        ("bearer" | "google" | "azure-ad" | "copilot" | "oauth", _) => Style::Bearer,
        (_, WireFormat::Anthropic) if c.token.as_deref().is_some_and(anthropic::is_oauth_token) => {
            Style::Bearer
        }
        (_, WireFormat::Anthropic) => Style::XApiKey,
        (_, WireFormat::Gemini) => Style::XGoogApiKey,
        _ => Style::Bearer,
    };
    if let Some(k) = c.token.as_deref().filter(|k| !k.is_empty()) {
        req = match style {
            Style::XApiKey => req.header("x-api-key", k),
            Style::XGoogApiKey => req.header("x-goog-api-key", k),
            Style::ApiKey => req.header("api-key", k),
            Style::None => req,
            Style::Bearer => req.header("authorization", &format!("Bearer {k}")),
        };
    }
    if cfg.format == WireFormat::Anthropic {
        req = req.header("anthropic-version", "2023-06-01");
    }
    let mut extra = c.headers.clone();
    extra.extend(cfg.headers.iter().map(|(k, v)| (k.clone(), v.clone())));
    for (k, v) in &extra {
        req = req.header(k.as_str(), v.as_str());
    }
    for (k, v) in &cfg.query {
        req = req.query(k, v);
    }
    if url.ends_with("/models") {
        match cfg.format {
            WireFormat::Anthropic if !cfg.query.contains_key("limit") => req = req.query("limit", "1000"),
            WireFormat::Gemini if !cfg.query.contains_key("pageSize") => req = req.query("pageSize", "1000"),
            _ => {}
        }
    }
    let resp = req.call().map_err(|e| format!("GET {url}: {e}"))?;
    let status = resp.status().as_u16();
    let mut raw = String::new();
    resp.into_body()
        .into_reader()
        .take(8 << 20)
        .read_to_string(&mut raw)
        .map_err(|e| format!("reading {url}: {e}"))?;
    Ok((status, raw))
}

/// Per-model context windows as the endpoint's own `/models` answer reports them. Local servers
/// do state their window (vLLM `max_model_len`, LM Studio `loaded_context_length`,
/// OpenAI-compatible `context_length`); hosted APIs usually do not, which is fine — nothing is
/// learned then. This is what feeds `contextpin::learn_from_endpoint`, so a local endpoint needs
/// no `model.context_length` pin.
pub fn parse_model_contexts(v: &Value) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = vec![];
    let entries = [v.get("data").and_then(Value::as_array), v.get("models").and_then(Value::as_array), v.as_array()];
    for m in entries.into_iter().flatten().flatten() {
        let name = ["id", "slug", "name", "model"].iter().find_map(|k| m.get(*k).and_then(Value::as_str));
        let Some(name) = name.map(|n| n.rsplit_once("/models/").map(|(_, x)| x).unwrap_or(n).trim_start_matches("models/")) else { continue };
        let n = ["max_model_len", "context_length", "context_window", "max_context_length", "loaded_context_length", "context"]
            .iter()
            .find_map(|k| m.get(*k).and_then(Value::as_u64))
            .or_else(|| m.get("limit").and_then(|l| l.get("context")).and_then(Value::as_u64));
        if let Some(n) = n.filter(|n| *n > 0) {
            out.push((name.to_string(), n));
        }
    }
    out.dedup();
    out
}

pub fn parse_model_list(v: &Value) -> Vec<String> {
    let mut out = vec![];
    // OpenAI / Anthropic / most compatible servers: {"data": [{"id": ..}]}; bare arrays too.
    let data = v["data"].as_array().or_else(|| v.as_array());
    for m in data.into_iter().flatten() {
        if let Some(id) = m["id"].as_str().or_else(|| m["slug"].as_str()) {
            out.push(id.to_string());
        }
    }
    // Gemini / Vertex: {"models": [{"name": "models/x", "supportedGenerationMethods": [..]}]};
    // Ollama native: {"models": [{"name": "llama3:8b"}]}; Codex: {"models": [{"slug": ..}]}.
    for m in v["models"].as_array().into_iter().flatten() {
        let chat = m["supportedGenerationMethods"]
            .as_array()
            .is_none_or(|a| a.iter().any(|x| x == "generateContent"));
        if let (Some(n), true) = (
            m["name"]
                .as_str()
                .or_else(|| m["slug"].as_str())
                .or_else(|| m["id"].as_str()),
            chat,
        ) {
            let n = n.rsplit_once("/models/").map(|(_, x)| x).unwrap_or(n);
            out.push(n.trim_start_matches("models/").to_string());
        }
    }
    out.dedup();
    out
}

/// Context window, output limit and capabilities for a model: the models.dev-derived
/// table first, then name heuristics.
pub fn caps_for(model: &str) -> ModelCaps {
    if let Some(m) = modelsdb::lookup(model) {
        return m.caps();
    }
    heuristic_caps(model)
}

pub(crate) fn heuristic_caps(model: &str) -> ModelCaps {
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
    } else if m.starts_with("gpt-5") || m.contains("/gpt-5") || m.starts_with("gpt-6") {
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
    } else if m.contains("qwen")
        || m.contains("glm")
        || m.contains("minimax")
        || m.contains("mistral")
        || m.contains("llama")
    {
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
    reasoning::budget(level?)
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
                    Block::ToolUse { name, input, .. } => {
                        estimate_tokens(name) + estimate_tokens(&input.to_string())
                    }
                    Block::ToolResult { content, .. } => estimate_tokens(content),
                    Block::Image { .. } => seagent_core::IMAGE_TOKENS,
                })
                .sum();
            Usage {
                input_tokens: estimate_request_tokens(req),
                output_tokens: out,
                estimated: true,
                ..Default::default()
            }
        }
    }
}

/// Whether the connection talks to one of the vendor's own hosts: billing knobs
/// (service tiers, fast mode) are only sent there, never to proxies.
pub(crate) fn first_party(conn: &Conn, hosts: &[&str]) -> bool {
    conn.quirk("first_party") || {
        let h = net::host_port(&conn.base).0;
        hosts.iter().any(|x| h == *x)
    }
}

/// Render a conversation as plain text (CLI backends, aggregator prompts).
pub fn transcript(req: &ModelRequest) -> String {
    let mut out = String::new();
    for m in &req.messages {
        let who = if m.role == seagent_core::Role::User {
            "User"
        } else {
            "Assistant"
        };
        for b in &m.content {
            let t = match b {
                Block::Text { text } => text.clone(),
                Block::ToolUse { name, input, .. } => format!("[called tool {name} with {input}]"),
                Block::ToolResult {
                    content, is_error, ..
                } => format!(
                    "[tool {}: {content}]",
                    if *is_error { "error" } else { "result" }
                ),
                Block::Image { media_type, .. } => format!("[image {media_type}]"),
                Block::Thinking { .. } => continue,
            };
            out.push_str(&format!("{who}: {t}\n\n"));
        }
    }
    out
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
        let vx = serde_json::json!({"models": [{"name": "publishers/google/models/gemini-3-pro"}]});
        assert_eq!(parse_model_list(&vx), vec!["gemini-3-pro"]);
        let codex = serde_json::json!({"models": [{"slug": "gpt-5.5-codex"}]});
        assert_eq!(parse_model_list(&codex), vec!["gpt-5.5-codex"]);
        assert!(parse_model_list(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn presets_are_unique_and_valid() {
        let ps = presets();
        let mut ids: Vec<_> = ps.iter().map(|p| p.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), ps.len());
        assert!(
            ps.iter().all(|p| p.base_url.starts_with("http")
                || p.base_url.is_empty()
                || p.base_url.starts_with("{env:")),
            "every preset has an http(s) base"
        );
        for local in ["ollama", "lmstudio", "vllm", "sglang"] {
            let p = ps.iter().find(|p| p.id == local).unwrap();
            assert!(p.keyless(), "{local}");
            assert!(build(p).is_ok());
        }
    }

    #[test]
    fn build_rejects_missing_key_and_bad_url() {
        let mut p = ProviderConfig {
            id: "x".into(),
            format: WireFormat::Anthropic,
            base_url: "https://e".into(),
            api_key_env: Some("SEAGENT_TEST_SURELY_UNSET_KEY_42".into()),
            ..Default::default()
        };
        let err = build(&p).err().unwrap();
        assert!(err.contains("SEAGENT_TEST_SURELY_UNSET_KEY_42"), "{err}");
        p.api_key = Some("k".into());
        assert!(build(&p).is_ok());
        p.base_url = "ftp://x".into();
        assert!(build(&p).is_err());
    }

    #[test]
    fn base_placeholders_expand_or_explain() {
        assert_eq!(
            expand_base(
                "b",
                "https://bedrock-runtime.{region}.amazonaws.com",
                Some("eu-west-1"),
                None
            )
            .unwrap(),
            "https://bedrock-runtime.eu-west-1.amazonaws.com"
        );
        std::env::set_var("SEAGENT_TEST_RES_9", "myres");
        assert_eq!(
            expand_base(
                "a",
                "https://{env:SEAGENT_TEST_RES_9}.openai.azure.com/openai/v1",
                None,
                None
            )
            .unwrap(),
            "https://myres.openai.azure.com/openai/v1"
        );
        let e = expand_base("a", "https://{env:SEAGENT_TEST_UNSET_RES_9}.x", None, None).unwrap_err();
        assert!(e.contains("SEAGENT_TEST_UNSET_RES_9"), "{e}");
        assert_eq!(
            expand_base("a", "https://x/{weird}", None, None).unwrap(),
            "https://x/{weird}"
        );
    }

    #[test]
    fn config_roundtrips_through_toml_like_json() {
        let j = r#"{"id":"my","format":"openai_chat","base_url":"http://h/v1"}"#;
        let c: ProviderConfig = serde_json::from_str(j).unwrap();
        assert_eq!(c.format, WireFormat::OpenAiChat);
        assert!(c.headers.is_empty());
        assert!(serde_json::from_str::<ProviderConfig>(
            r#"{"id":"x","format":"nope","base_url":"h"}"#
        )
        .is_err());
        let b: ProviderConfig = serde_json::from_str(
            r#"{"id":"b","format":"bedrock","base_url":"https://x","region":"us-west-2"}"#,
        )
        .unwrap();
        assert_eq!(b.format, WireFormat::Bedrock);
    }

    #[test]
    fn caps_table() {
        assert!(caps_for("claude-opus-5-5").explicit_cache);
        assert_eq!(caps_for("gemini-3-pro").context_window, 1_048_576);
        assert_eq!(caps_for("some-unknown-local-model").context_window, 32_768);
    }

    /// The endpoint's own model list is what teaches `contextpin::learned` (it had no production
    /// writer), so a local server's real window wins over the catalogue without a config pin.
    #[test]
    fn endpoint_model_list_teaches_the_learned_context_window() {
        let _g = crate::modelsdb::test_lock();
        crate::contextpin::clear_learned();
        // vLLM (`max_model_len`), OpenAI-compatible (`context_length`), LM Studio (loaded value).
        let v = serde_json::json!({"data": [
            {"id": "qwen3-local", "max_model_len": 131072},
            {"id": "zz-teach-a", "context_length": 65536},
            {"id": "zz-teach-loaded", "max_context_length": 262144, "loaded_context_length": 98304},
            {"id": "gpt-hosted", "owned_by": "openai"}
        ]});
        assert_eq!(
            parse_model_contexts(&v),
            vec![("qwen3-local".to_string(), 131_072), ("zz-teach-a".to_string(), 65_536), ("zz-teach-loaded".to_string(), 262_144)],
            "hosted entries report nothing and `loaded_context_length` follows the larger limit"
        );
        let base = "http://127.0.0.1:8000/v1";
        for (m, ctx) in parse_model_contexts(&v) {
            assert!(crate::contextpin::learn_from_endpoint(&m, base, ctx).is_some(), "{m}");
        }
        // The runtime-facing number follows the endpoint, not the table.
        let table = caps_for("zz-teach-a").context_window;
        assert_ne!(table, 65_536);
        assert_eq!(crate::contextpin::window("zz-teach-a", base, None), 65_536);
        assert_eq!(crate::contextpin::window("zz-teach-a", "http://elsewhere/v1", None), table, "another endpoint keeps the catalogue value");
        assert_eq!(crate::contextpin::window("zz-teach-a", base, Some(8_192)), 8_192, "an explicit pin still wins");
        // A server reporting an unusably small window is not blessed into the cache.
        assert_eq!(crate::contextpin::learn_from_endpoint("zz-teach-a", base, 512), None);
        assert_eq!(crate::contextpin::learned("zz-teach-a", base), Some(65_536), "the earlier sane value stands");
        crate::contextpin::clear_learned();
    }

    #[test]
    fn args_parsing() {
        assert_eq!(parse_args(""), serde_json::json!({}));
        assert_eq!(parse_args(r#"{"a":1}"#), serde_json::json!({"a":1}));
        assert_eq!(
            parse_args("{\"a\":"),
            serde_json::json!({"__invalid_json":"{\"a\":"})
        );
    }
}

/// Keeps the optional-adapter split honest in **both** configurations (audit row D6).
///
/// Run it twice, exactly like `seagent-channel`'s `feature_wiring`:
///
/// ```sh
/// cargo test -p seagent-model --lib feature_wiring
/// cargo test -p seagent-model --lib --no-default-features feature_wiring
/// ```
///
/// The rule being enforced: turning a feature off may only change `build`/`list_models`
/// (they must say *which* feature is missing). Config parsing, the [`WireFormat`] enum and
/// the preset table stay identical, so a slim binary reads the same config as a full one.
#[cfg(test)]
mod feature_wiring {
    use super::*;

    /// The adapters that exist behind a cargo feature, with the feature that compiles them.
    const GATED: &[(&str, WireFormat, &str)] = &[
        ("bedrock", WireFormat::Bedrock, "bedrock"),
        ("gemini", WireFormat::Gemini, "gemini"),
        ("agents_api", WireFormat::AgentsApi, "agents-api"),
        ("cli", WireFormat::Cli, "agent-cli"),
        ("codex_app_server", WireFormat::CodexAppServer, "agent-cli"),
        ("acp", WireFormat::Acp, "agent-cli"),
        ("muse", WireFormat::Muse, "agent-cli"),
    ];

    fn compiled(feature: &str) -> bool {
        match feature {
            "bedrock" => cfg!(feature = "bedrock"),
            "gemini" => cfg!(feature = "gemini"),
            "agents-api" => cfg!(feature = "agents-api"),
            "agent-cli" => cfg!(feature = "agent-cli"),
            "local" => cfg!(feature = "local"),
            other => panic!("unknown feature {other}"),
        }
    }

    /// A gated format still parses; when its feature is off, `build` names the feature
    /// instead of failing with something the user cannot act on.
    #[test]
    fn gated_formats_stay_configurable() {
        for (wire, fmt, feature) in GATED {
            let json = format!(r#"{{"id":"t","format":"{wire}","base_url":"https://example.invalid"}}"#);
            let cfg: ProviderConfig =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("{wire}: {e}"));
            assert_eq!(&cfg.format, fmt, "{wire} must keep its WireFormat variant");
            let err = build(&cfg).err().unwrap_or_default();
            let compiled_out = err.contains("not compiled into this build");
            assert_eq!(
                compiled_out,
                !compiled(feature),
                "{wire}: feature `{feature}` is {} but the error was: {err}",
                if compiled(feature) { "on" } else { "off" }
            );
            if compiled_out {
                assert!(err.contains(feature), "{wire}: the error must name `{feature}`: {err}");
                assert!(err.contains("docs/BUILD.md"), "{wire}: the error must point at the docs: {err}");
            }
        }
    }

    /// `model_path` (managed llama.cpp) is the one gate that lives on another wire format.
    #[test]
    fn managed_local_server_is_gated() {
        let json = r#"{"id":"l","format":"openai_chat","base_url":"http://127.0.0.1:9/v1","model_path":"/nonexistent/model.gguf"}"#;
        let cfg: ProviderConfig = serde_json::from_str(json).unwrap();
        let err = build(&cfg).err().unwrap_or_default();
        assert_eq!(
            err.contains("not compiled into this build"),
            !compiled("local"),
            "local: {err}"
        );
    }

    /// `default` is the complete set and `full` is exactly the gated list: dropping a
    /// feature from `full` (the way a default build could silently lose a provider) or
    /// adding one without documenting it fails here.
    #[test]
    fn default_is_the_complete_set() {
        let raw = include_str!("../Cargo.toml");
        let doc: toml::Value = toml::from_str(raw).expect("Cargo.toml parses");
        let features = doc.get("features").and_then(|v| v.as_table()).expect("[features]");
        let list = |k: &str| -> Vec<String> {
            features
                .get(k)
                .and_then(|v| v.as_array())
                .unwrap_or_else(|| panic!("feature `{k}` missing"))
                .iter()
                .map(|v| v.as_str().expect("feature names are strings").to_string())
                .collect()
        };
        assert!(list("default").iter().any(|f| f == "full"), "`default` must include `full`");
        let mut full = list("full");
        full.sort();
        let mut want: Vec<String> =
            ["agents-api", "agent-cli", "bedrock", "gemini", "local"].iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(full, want, "`full` must list exactly the gated adapters");
        for name in &full {
            assert!(!list(name).is_empty() || features.get(name).is_some(), "feature `{name}` missing");
        }
    }

    /// The user-facing half: a feature nobody documented is a feature nobody can turn off.
    #[test]
    fn every_feature_is_documented() {
        let doc = include_str!("../../../docs/BUILD.md");
        for (_, _, feature) in GATED {
            assert!(
                doc.contains(&format!("`{feature}`")),
                "docs/BUILD.md must document the `{feature}` feature"
            );
        }
        assert!(doc.contains("`local`"), "docs/BUILD.md must document the `local` feature");
        assert!(
            doc.contains("cargo build -p seagent --release --no-default-features"),
            "docs/BUILD.md must keep the slim build command"
        );
    }
}

/// Live model listings against fake provider servers: every wire format's `/models` shape,
/// the auth header each one expects, pagination parameters, and the strict vs lenient
/// handling of an error status (a key test must see a 401; a picker may fall back).
#[cfg(test)]
mod live_models_tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;

    /// Request line + lowercased headers of every request the fake server saw.
    type Seen = Arc<Mutex<Vec<(String, Vec<(String, String)>)>>>;

    fn fake(respond: impl Fn(&str, &[(String, String)]) -> (u16, String) + Send + 'static) -> (String, Seen) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let seen: Seen = Arc::default();
        let log = seen.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                if r.read_line(&mut line).is_err() {
                    continue;
                }
                let target = line.split_whitespace().nth(1).unwrap_or("").to_string();
                let mut headers = vec![];
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    if r.read_line(&mut h).is_err() || h.trim().is_empty() {
                        break;
                    }
                    if let Some((k, v)) = h.trim_end().split_once(':') {
                        let (k, v) = (k.trim().to_lowercase(), v.trim().to_string());
                        if k == "content-length" {
                            len = v.parse().unwrap_or(0);
                        }
                        headers.push((k, v));
                    }
                }
                let mut body = vec![0u8; len];
                let _ = r.read_exact(&mut body);
                let (status, out) = respond(&target, &headers);
                log.lock().unwrap().push((target, headers));
                let _ = write!(s, "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}", out.len());
            }
        });
        (base, seen)
    }

    fn preset(id: &str, base: &str) -> ProviderConfig {
        let mut c = presets().into_iter().find(|p| p.id == id).unwrap_or_else(|| panic!("preset {id}"));
        c.base_url = base.to_string();
        c
    }

    fn header<'a>(h: &'a [(String, String)], k: &str) -> Option<&'a str> {
        h.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }

    fn key(k: &str) -> auth::Static {
        auth::Static::new(Some(k.to_string()))
    }

    #[test]
    fn openai_compatible_lists_data_ids_with_a_bearer_key() {
        let (base, seen) = fake(|path, h| match (path, header(h, "authorization")) {
            ("/v1/models", Some("Bearer sk-good")) => (200, r#"{"object":"list","data":[{"id":"gpt-live-1"},{"id":"gpt-live-2"}]}"#.into()),
            _ => (401, r#"{"error":{"message":"Incorrect API key provided"}}"#.into()),
        });
        let c = preset("openai", &format!("{base}/v1"));
        assert_eq!(list_models_live(&c, &key("sk-good")).unwrap(), ["gpt-live-1", "gpt-live-2"]);
        let e = list_models_live(&c, &key("sk-bad")).unwrap_err();
        assert!(e.contains("401"), "a bad key is an error in strict mode: {e}");
        assert_eq!(seen.lock().unwrap()[0].0, "/v1/models");
        // The lenient listing keeps its old contract: configured ids stand in for an error.
        let mut with_ids = c.clone();
        with_ids.models = vec!["configured".into()];
        assert_eq!(list_models_with(&with_ids, &key("sk-bad")).unwrap(), ["configured"]);
        assert!(list_models_live(&with_ids, &key("sk-bad")).is_err());
    }

    #[test]
    fn anthropic_uses_x_api_key_version_header_and_a_full_page() {
        let (base, seen) = fake(|path, h| match header(h, "x-api-key") {
            Some("sk-ant-api03-good") if path.starts_with("/v1/models") => (200, r#"{"data":[{"type":"model","id":"claude-live-9","display_name":"Claude Live"}],"has_more":false}"#.into()),
            _ => (401, r#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}"#.into()),
        });
        let c = preset("anthropic", &format!("{base}/v1"));
        assert_eq!(list_models_live(&c, &key("sk-ant-api03-good")).unwrap(), ["claude-live-9"]);
        let (path, headers) = seen.lock().unwrap()[0].clone();
        assert_eq!(path, "/v1/models?limit=1000", "Anthropic pages at 20 by default");
        assert_eq!(header(&headers, "anthropic-version"), Some("2023-06-01"));
        assert!(header(&headers, "authorization").is_none());
        assert!(list_models_live(&c, &key("nope")).unwrap_err().contains("401"));
    }

    #[test]
    fn gemini_lists_generate_content_models_with_x_goog_api_key() {
        let (base, seen) = fake(|_, h| match header(h, "x-goog-api-key") {
            Some("AIza-good") => (200, r#"{"models":[{"name":"models/gemini-live-pro","supportedGenerationMethods":["generateContent","countTokens"]},{"name":"models/text-embedding-9","supportedGenerationMethods":["embedContent"]}]}"#.into()),
            _ => (400, r#"{"error":{"code":400,"message":"API key not valid","status":"INVALID_ARGUMENT"}}"#.into()),
        });
        let c = preset("gemini", &format!("{base}/v1beta"));
        assert_eq!(list_models_live(&c, &key("AIza-good")).unwrap(), ["gemini-live-pro"], "embedding-only models are not chat models");
        assert_eq!(seen.lock().unwrap()[0].0, "/v1beta/models?pageSize=1000");
        assert!(list_models_live(&c, &key("bad")).is_err());
    }

    #[test]
    fn ollama_falls_back_to_api_tags_and_needs_no_key() {
        let (base, seen) = fake(|path, _| match path {
            "/api/tags" => (200, r#"{"models":[{"name":"llama3.3:70b","size":1},{"name":"qwen3:8b","size":2}]}"#.into()),
            _ => (404, "404 page not found".into()),
        });
        let c = preset("ollama", &format!("{base}/v1"));
        let cred = auth::source_for(&c, None).unwrap();
        assert_eq!(list_models_live(&c, &*cred).unwrap(), ["llama3.3:70b", "qwen3:8b"]);
        let paths: Vec<String> = seen.lock().unwrap().iter().map(|(p, _)| p.clone()).collect();
        assert_eq!(paths, ["/v1/models", "/api/tags"]);
    }

    #[test]
    fn openrouter_sends_its_attribution_headers() {
        let (base, seen) = fake(|_, _| (200, r#"{"data":[{"id":"openai/gpt-live","context_length":400000},{"id":"anthropic/claude-live"}]}"#.into()));
        let c = preset("openrouter", &format!("{base}/api/v1"));
        assert_eq!(list_models_live(&c, &key("sk-or-x")).unwrap(), ["openai/gpt-live", "anthropic/claude-live"]);
        let (path, h) = seen.lock().unwrap()[0].clone();
        assert_eq!(path, "/api/v1/models");
        assert_eq!(header(&h, "x-title"), Some("seagent"));
        assert_eq!(header(&h, "authorization"), Some("Bearer sk-or-x"));
    }
}
