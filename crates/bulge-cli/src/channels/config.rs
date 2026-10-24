//! `~/.bulge/channels.json` and connecting its accounts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use bulge_channels::access::AccessConfig;
use bulge_channels::Channel;
use bulge_store::Autonomy;
use serde::Deserialize;

/// One account of one app.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    /// telegram | discord | slack | matrix | signal | line
    pub kind: String,
    #[serde(default = "default_account")]
    pub account: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Secret name → key file under `~/.bulge/keys/` (e.g. {"token": "telegram-main"}).
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
    /// App-specific settings (homeserver URL, phone number, …).
    #[serde(default)]
    pub options: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub access: AccessConfig,
}

pub(crate) fn default_account() -> String {
    "main".into()
}
pub(crate) fn yes() -> bool {
    true
}

/// `~/.bulge/channels.json`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelsConfig {
    /// Where chat jobs work (a dedicated folder is recommended).
    pub workspace: PathBuf,
    #[serde(default = "full_auto")]
    pub autonomy: Autonomy,
    #[serde(default = "yes")]
    pub network: bool,
    #[serde(default = "two")]
    pub max_parallel_jobs: usize,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// The model's reasoning effort for chat jobs: off, low, medium, high,
    /// max. Sent explicitly (a provider's own default may think harder than
    /// chat replies need).
    #[serde(default = "default_effort")]
    pub reasoning_effort: String,
    pub accounts: Vec<AccountConfig>,
}

pub(crate) fn full_auto() -> Autonomy {
    Autonomy::FullAuto
}
pub(crate) fn two() -> usize {
    2
}
pub(crate) fn default_model() -> String {
    // DeepSeek's current model; it also takes images (bulge checks the
    // provider's model listing before offering view_image).
    crate::backend::DEFAULT_MODEL.into()
}
pub(crate) fn default_base_url() -> String {
    crate::backend::DEFAULT_BASE_URL.into()
}
pub(crate) fn default_effort() -> String {
    "medium".into()
}
pub(crate) fn default_protocol() -> String {
    "openai".into()
}

pub fn load_config(path: &Path) -> Result<ChannelsConfig, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let config: ChannelsConfig = serde_json::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
    if config.max_parallel_jobs == 0 {
        return Err("max_parallel_jobs must be at least 1".into());
    }
    if bulge_llm::ReasoningEffort::parse(&config.reasoning_effort).is_none() {
        return Err(format!("reasoning_effort must be off, low, medium, high or max, got {:?}", config.reasoning_effort));
    }
    Ok(config)
}

/// Read a secret from `~/.bulge/keys/<name>`, refusing a file other users can read.
pub fn read_secret(home: &Path, name: &str) -> Result<String, String> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(format!("bad key name {name:?}"));
    }
    bulge_util::fs::read_secret_file(&home.join(".bulge/keys").join(name))
}

pub(crate) fn secret(home: &Path, account: &AccountConfig, which: &str) -> Result<String, String> {
    let name = account.secrets.get(which).ok_or_else(|| format!("{}:{}: secrets.{which} is not set", account.kind, account.account))?;
    read_secret(home, name)
}

pub(crate) fn option_str<'a>(account: &'a AccountConfig, key: &str) -> Option<&'a str> {
    account.options.get(key).and_then(serde_json::Value::as_str)
}

/// Connect one configured account.
pub async fn connect(home: &Path, account: &AccountConfig, cursor: Option<&str>) -> Result<Arc<dyn Channel>, String> {
    match account.kind.as_str() {
        "telegram" => {
            let token = secret(home, account, "token")?;
            let api = option_str(account, "api").unwrap_or(bulge_channels::telegram::DEFAULT_API);
            let channel = bulge_channels::telegram::Telegram::connect(&account.account, &token, api, cursor).await.map_err(|e| e.to_string())?;
            Ok(Arc::new(channel))
        }
        "discord" => {
            let token = secret(home, account, "token")?;
            let api = option_str(account, "api").unwrap_or(bulge_channels::discord::DEFAULT_API);
            let channel = bulge_channels::discord::Discord::connect(&account.account, &token, api, option_str(account, "gateway")).await.map_err(|e| e.to_string())?;
            Ok(Arc::new(channel))
        }
        "slack" => {
            let app_token = secret(home, account, "app_token")?;
            let bot_token = secret(home, account, "bot_token")?;
            let api = option_str(account, "api").unwrap_or(bulge_channels::slack::DEFAULT_API);
            let channel = bulge_channels::slack::Slack::connect(&account.account, &app_token, &bot_token, api).await.map_err(|e| e.to_string())?;
            Ok(Arc::new(channel))
        }
        "matrix" => {
            let token = secret(home, account, "access_token")?;
            let homeserver = option_str(account, "homeserver").ok_or_else(|| format!("{}:{}: options.homeserver is not set", account.kind, account.account))?;
            let channel = bulge_channels::matrix::Matrix::connect(&account.account, homeserver, &token, cursor).await.map_err(|e| e.to_string())?;
            Ok(Arc::new(channel))
        }
        "signal" => {
            let number = option_str(account, "number").ok_or_else(|| format!("{}:{}: options.number is not set", account.kind, account.account))?;
            let program = option_str(account, "signal_cli").unwrap_or("signal-cli");
            // signal-cli's default data directory, unless configured.
            let attachments = match option_str(account, "attachments_dir") {
                Some(dir) => PathBuf::from(dir),
                None => std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| home.join(".local/share")).join("signal-cli/attachments"),
            };
            let channel = bulge_channels::signal::Signal::connect(&account.account, number, program, &attachments).await.map_err(|e| e.to_string())?;
            Ok(Arc::new(channel))
        }
        "line" => {
            let listen: std::net::SocketAddr = option_str(account, "listen")
                .unwrap_or("127.0.0.1:8787")
                .parse()
                .map_err(|e| format!("line:{}: options.listen: {e}", account.account))?;
            if !listen.ip().is_loopback() {
                eprintln!("line:{}: listening on {listen}, not loopback — both keys still apply, but prefer 127.0.0.1 behind a tunnel", account.account);
            }
            let channel = bulge_channels::line::Line::start(
                &account.account,
                &secret(home, account, "channel_secret")?,
                &secret(home, account, "access_token")?,
                &secret(home, account, "webhook_path")?,
                listen,
                option_str(account, "api").unwrap_or(bulge_channels::line::DEFAULT_API),
            )
            .await
            .map_err(|e| e.to_string())?;
            eprintln!(
                "line:{}: webhook listening on http://{}/line/<webhook_path secret>; expose it with an HTTPS tunnel and set that URL in the LINE console",
                account.account,
                channel.local_addr()
            );
            Ok(Arc::new(channel))
        }
        "remote" => {
            // bulge's own devices through the relay (`bulge remote init|pair`).
            let channel = bulge_remote::channel::RemoteChannel::start(&account.account, &home.join(".bulge/remote"), bulge_remote::channel::Timing::default())?;
            Ok(Arc::new(channel))
        }
        other => Err(format!("unknown channel kind {other:?}")),
    }
}
