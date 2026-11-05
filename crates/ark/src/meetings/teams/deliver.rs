//! Teams delivery for the meeting pipeline (Hermes `plugins/teams_pipeline/runtime.py`'s
//! `build_pipeline_runtime_config` / `build_pipeline_runtime` and `plugins/platforms/teams/
//! summary_writer.py`, MIT).
//!
//! The pipeline writes its summaries through an injected sink. This module builds that sink:
//!
//! * the delivery settings are the pipeline's `teams_delivery` table, completed from the Teams
//!   platform channel (`[channels.<name>]` with `kind = "teams"`, upstream mirrors the same keys);
//! * when that channel carries bot credentials and the target is a conversation, the summary is
//!   posted through `ark_channel`'s msteams adapter (the running bot's own outbound path);
//! * otherwise `super::sinks::teams_write` delivers it — an incoming webhook, or a Graph message in
//!   a chat / channel — exactly as upstream's `TeamsSummaryWriter`.
//!
//! Upstream only builds a sender when the Teams platform is enabled *and* `teams_delivery.enabled`;
//! the same guard applies here, so a pipeline without delivery keeps working (Notion/Linear only).

use super::graph::Client;
use super::models::SummaryPayload;
use super::pipeline::{self, Pipeline, PipelineConfig, SinkKind};
use super::sinks;
use ark_kernel::config::Paths;
use ark_kernel::vault::Vault;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// An injected pipeline output sink (the host's Teams delivery), shared by the pipeline workers.
pub type SummarySink = Arc<dyn Fn(SinkKind, &SummaryPayload, &Map<String, Value>, Option<&Value>) -> Result<Value, String> + Send + Sync>;

/// Delivery keys the Teams platform config may supply when the pipeline's table leaves them empty
/// (upstream `_DELIVERY_KEYS`; `access_token` has no ark equivalent — the Graph client always does a
/// client-credentials exchange).
const DELIVERY_KEYS: [&str; 5] = ["incoming_webhook_url", "team_id", "channel_id", "chat_id", "delivery_mode"];

/// A plain Teams conversation id (the Bot Framework connector's addressing).
fn is_conversation_id(id: &str) -> bool {
    id.contains("@thread") || id.starts_with("19:") || id.starts_with("a:")
}

fn text_of(m: &Map<String, Value>, key: &str) -> Option<String> {
    m.get(key).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

fn blank(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s.trim().is_empty(),
        _ => false,
    }
}

/// The `[channels.<name>]` table of the Teams platform channel, if one is configured.
pub fn teams_platform(channels: &BTreeMap<String, toml::Table>) -> Option<(&str, &toml::Table)> {
    channels.iter().find(|(_, t)| matches!(t.get("kind").and_then(|v| v.as_str()), Some("teams" | "msteams"))).map(|(n, t)| (n.as_str(), t))
}

/// `teams_delivery` completed from the Teams platform config (upstream `build_pipeline_runtime_config`).
pub fn delivery_config(delivery: &Map<String, Value>, channels: &BTreeMap<String, toml::Table>) -> Map<String, Value> {
    let mut merged = delivery.clone();
    let Some((_, platform)) = teams_platform(channels) else { return merged };
    if let Some(mode) = platform.get("delivery_mode").and_then(|v| v.as_str()).map(str::trim).filter(|m| !m.is_empty()) {
        merged.insert("mode".into(), json!(mode));
    }
    for key in DELIVERY_KEYS {
        if blank(merged.get(key)) {
            let non_blank = |v: &toml::Value| !matches!(v, toml::Value::String(s) if s.trim().is_empty());
            if let Some(v) = platform.get(key).filter(|v| non_blank(v)) {
                merged.insert(key.into(), json!(v));
            }
        }
    }
    // Where the channel posts by default is the chat a summary belongs in.
    if blank(merged.get("chat_id")) {
        if let Some(chat) = platform.get("default_chat").and_then(|v| v.as_str()).map(str::trim).filter(|c| !c.is_empty()) {
            merged.insert("chat_id".into(), json!(chat));
        }
    }
    merged
}

/// `teams_delivery.enabled` (a `"true"` string counts, as upstream's `_parse_bool`).
pub fn delivery_enabled(delivery: &Map<String, Value>) -> bool {
    match delivery.get("enabled") {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => matches!(s.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        _ => false,
    }
}

/// The conversation that receives the summaries: `chat_id`, else a conversation-shaped `channel_id`
/// (a bare channel id is only addressable through Graph, which `sinks::teams_write` handles).
pub fn target_chat(merged: &Map<String, Value>) -> Option<String> {
    text_of(merged, "chat_id").or_else(|| text_of(merged, "channel_id").filter(|c| is_conversation_id(c)))
}

/// A send-only msteams adapter for the Teams platform channel (`listen` is deliberately `None`: the
/// channel that `ext::load` builds owns the ingress, this one only posts).
fn msteams_adapter(name: &str, t: &toml::Table, paths: &Paths) -> Option<Arc<dyn ark_channel::Channel>> {
    let vault = Vault::load(&paths.secrets()).unwrap_or_else(|_| Vault::empty());
    let secret = |key: &str| -> Option<String> {
        t.get(key).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(|s| vault.substitute(s)).filter(|s| !s.contains("{{secret:"))
    };
    let (app_id, password) = (secret("app_id")?, secret("app_password")?);
    let tenant = secret("tenant");
    let url = |key: &str, default: &str| secret(key).unwrap_or_else(|| default.to_string());
    let state: PathBuf = paths.data.join("channels").join(format!("{name}.pipeline.json"));
    let teams = ark_channel::msteams::Teams::new(
        name,
        ark_channel::msteams::TeamsOpts {
            app_id: &app_id,
            app_password: &password,
            tenant: tenant.as_deref(),
            listen: None,
            path: "/msteams/pipeline",
            openid_url: &url("openid_url", ark_channel::msteams::DEFAULT_OPENID),
            login_base: &url("login_url", ark_channel::msteams::DEFAULT_LOGIN),
            service_url: &url("service_url", ark_channel::msteams::DEFAULT_SERVICE_URL),
            state,
            poll_timeout: Duration::from_secs(1),
            native_streaming: false,
            reaction_events: false,
            sso_connection: None,
            token_service: &url("token_service_url", ark_channel::msteams::DEFAULT_TOKEN_SERVICE),
        },
    )
    .ok()?;
    Some(Arc::new(teams) as Arc<dyn ark_channel::Channel>)
}

fn force_resend(config: &Map<String, Value>) -> bool {
    match config.get("force_resend") {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => matches!(s.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        _ => false,
    }
}

fn mode_of(config: &Map<String, Value>) -> String {
    text_of(config, "mode").or_else(|| text_of(config, "delivery_mode")).unwrap_or_default().to_ascii_lowercase()
}

/// Deliver one summary: the msteams adapter when it can address the conversation, else
/// [`sinks::teams_write`] (incoming webhook / Graph chat).
pub fn deliver(config: &Map<String, Value>, adapter: Option<&Arc<dyn ark_channel::Channel>>, chat: Option<&str>, payload: &SummaryPayload, existing: Option<&Value>, client: &Client) -> Result<Value, String> {
    if let Some(record) = existing {
        if !force_resend(config) {
            return Ok(record.clone()); // already delivered (upstream `existing_record` guard)
        }
    }
    let mode = mode_of(config);
    if matches!(mode.as_str(), "" | "msteams" | "bot") {
        if let (Some(channel), Some(chat)) = (adapter, chat) {
            let sent = channel.send(&ark_channel::Outbound::text(chat, &pipeline::render_summary_markdown(payload))).map_err(|e| format!("Teams delivery failed: {}", e.message))?;
            return Ok(json!({"delivery_mode": "msteams", "target_type": "conversation", "chat_id": chat, "message_id": sent.first()}));
        }
    }
    sinks::teams_write(payload, config, None, Some(client))
}

/// Build the host sink for this configuration, or `None` when Teams delivery is off — the pipeline
/// then keeps its Notion/Linear sinks and the upstream "delivery disabled" behaviour.
pub fn teams_sink(pipeline_cfg: &PipelineConfig, channels: &BTreeMap<String, toml::Table>, paths: &Paths, client: Arc<Client>) -> Option<SummarySink> {
    let delivery = pipeline_cfg.teams_delivery.clone().unwrap_or_default();
    if !delivery_enabled(&delivery) {
        return None;
    }
    let merged = Arc::new(delivery_config(&delivery, channels));
    let chat = target_chat(&merged);
    let adapter = match (&chat, teams_platform(channels)) {
        (Some(_), Some((name, table))) => msteams_adapter(name, table, paths),
        _ => None,
    };
    Some(Arc::new(move |kind, payload, config, existing| match kind {
        SinkKind::Teams => deliver(&merged, adapter.as_ref(), chat.as_deref(), payload, existing, &client),
        other => pipeline::default_sink(other, payload, config, existing),
    }))
}

/// Inject the Teams sink into `p` (the CLI's `ark teams run` path, which has no channel host).
pub fn install(p: Pipeline, pipeline_cfg: &PipelineConfig, channels: &BTreeMap<String, toml::Table>, paths: &Paths, client: Arc<Client>) -> Pipeline {
    match teams_sink(pipeline_cfg, channels, paths, client) {
        Some(sink) => p.with_sink(Box::new(move |kind, payload, config, existing| sink(kind, payload, config, existing))),
        None => p,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channels(toml_text: &str) -> BTreeMap<String, toml::Table> {
        let doc: toml::Table = toml::from_str(toml_text).unwrap();
        doc.get("channels").and_then(|c| c.as_table()).cloned().unwrap_or_default().into_iter().filter_map(|(k, v)| v.as_table().cloned().map(|t| (k, t))).collect()
    }

    #[test]
    fn delivery_config_is_completed_from_the_teams_channel() {
        let ch = channels("[channels.teams]\nkind = \"teams\"\napp_id = \"a\"\ndefault_chat = \"19:conv@thread.tacv2\"\nincoming_webhook_url = \"https://hook.example/x\"\n");
        let mut delivery = Map::new();
        delivery.insert("enabled".into(), json!(true));
        let merged = delivery_config(&delivery, &ch);
        assert_eq!(merged["incoming_webhook_url"], json!("https://hook.example/x"));
        assert_eq!(merged["chat_id"], json!("19:conv@thread.tacv2"));
        assert_eq!(target_chat(&merged).as_deref(), Some("19:conv@thread.tacv2"));
        // Pipeline values win over the platform's.
        delivery.insert("chat_id".into(), json!("19:pipeline@thread.tacv2"));
        assert_eq!(delivery_config(&delivery, &ch)["chat_id"], json!("19:pipeline@thread.tacv2"));
        // A bare channel id is not a Bot Framework conversation.
        let merged: Map<String, Value> = [("channel_id".to_string(), json!("General"))].into_iter().collect();
        assert_eq!(target_chat(&merged), None);
        assert!(delivery_enabled(&[("enabled".to_string(), json!("on"))].into_iter().collect()));
        assert!(!delivery_enabled(&Map::new()));
    }

    #[test]
    fn sink_is_only_built_when_delivery_is_enabled() {
        let paths = Paths { data: std::env::temp_dir().join("ark-teams-deliver"), config_dir: Default::default(), runtime: Default::default() };
        let client = Arc::new(Client::new(super::super::graph::Credentials::from_parts(Some("contoso".into()), Some("app".into()), Some("s3cret".into()), None, None).unwrap(), "https://graph.microsoft.com/v1.0"));
        assert!(teams_sink(&PipelineConfig::default(), &BTreeMap::new(), &paths, client.clone()).is_none(), "no teams_delivery → no sink");
        let pcfg = PipelineConfig { teams_delivery: Some([("enabled".to_string(), json!(true)), ("incoming_webhook_url".to_string(), json!("https://hook.example/x"))].into_iter().collect()), ..Default::default() };
        assert!(teams_sink(&pcfg, &BTreeMap::new(), &paths, client).is_some());
    }
}
