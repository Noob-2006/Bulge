//! `[browser]` config (Hermes `browser.*` in config.yaml, OpenClaw `browser` in
//! openclaw.json). Every key has a documented default; see `DEFAULTS`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrowserConfig {
    /// "auto" (tools appear when a browser is reachable), true, false.
    pub enabled: toml::Value,
    /// "" = auto (cdp_url > camofox url > cloud keys > local), or one of
    /// local | cdp | browserbase | browser-use | firecrawl | camofox | lightpanda | sandbox | extension.
    pub backend: String,
    /// A browser the user runs with --remote-debugging-port (http://host:port or ws://…).
    pub cdp_url: String,
    /// Chromium-family executable for managed profiles ("" = search).
    pub executable: String,
    pub headless: bool,
    /// "auto" → --no-sandbox when root or in a container.
    pub no_sandbox: toml::Value,
    pub extra_args: Vec<String>,
    /// Managed profile used when a call names none.
    pub default_profile: String,
    pub profiles: BTreeMap<String, ProfileConfig>,
    /// Per-command timeout, seconds (Hermes browser.command_timeout, floor 5).
    pub command_timeout: u64,
    /// Close a session's browser after this much inactivity, seconds (floor 30).
    pub inactivity_timeout: u64,
    /// Hermes browser_snapshot truncation budget (min 1000).
    pub snapshot_threshold: usize,
    /// None = private/LAN URLs allowed for local browsers, refused for cloud ones.
    pub allow_private_urls: Option<bool>,
    /// Send private URLs to a local sidecar browser when the backend is a cloud one.
    pub auto_local_for_private_urls: bool,
    pub allowed_domains: Vec<String>,
    pub blocked_domains: Vec<String>,
    /// OpenClaw browser.evaluateEnabled: act:evaluate and wait fn.
    pub evaluate_enabled: bool,
    /// Hermes opt-in sensitive-primitive denylist for browser_console(expression).
    pub restrict_evaluate: bool,
    pub allow_unsafe_evaluate: bool,
    /// must_respond | auto_dismiss | auto_accept.
    pub dialog_policy: String,
    pub dialog_timeout_s: u64,
    /// Record each session's pages (screencast → webm with ffmpeg, else JPEG frames).
    pub record_sessions: bool,
    /// Browse with a copy of the user's real Chromium profile (their logins).
    pub use_real_profile: bool,
    pub real_profile_pin: String,
    pub real_profile_autoclose: bool,
    /// auto | chrome | lightpanda.
    pub engine: String,
    /// Give every ark session its own browser context (cookie jar) in the shared browser.
    pub isolate_sessions: bool,
    pub cloud_provider: String,
    /// Download a pinned Chromium (Chrome for Testing) when no browser is installed
    /// (Hermes PM `chromium`, gated by security.allow_lazy_installs).
    pub auto_install: bool,
    /// Base URL of the Chromium build CDN (pinned paths + SHA-256 are appended).
    pub install_base_url: String,
    /// Offer browser_exec (Browser Use harness code against the session browser).
    pub exec_enabled: bool,
    /// Command that runs Python from stdin with the Browser Use helpers.
    pub exec_command: Vec<String>,
    pub camofox: CamofoxConfig,
    pub sandbox: SandboxConfig,
    pub extension_control: ExtensionConfig,
    /// browser_vault external password managers (Hermes `vault.bitwarden` / `vault.onepassword`).
    pub vault: VaultConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VaultConfig {
    pub bitwarden: ManagerConfig,
    pub onepassword: ManagerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ManagerConfig {
    /// An installed manager CLI is a login source unless this is false.
    pub enabled: bool,
    /// Pinned CLI path ("" = `bw` / `op` on PATH).
    pub binary_path: String,
    /// 1Password account shorthand (OP_ACCOUNT / OP_SESSION_<account>).
    pub account: String,
    /// 1Password: secret/env var holding a service-account token (skips the unlock prompt).
    pub service_account_token_env: String,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        ManagerConfig { enabled: true, binary_path: String::new(), account: String::new(), service_account_token_env: "OP_SERVICE_ACCOUNT_TOKEN".into() }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProfileConfig {
    /// managed (ark launches it) | existing-session (attach to the user's running Chrome) | remote (cdp_url).
    pub driver: String,
    pub cdp_url: String,
    pub cdp_port: u16,
    pub user_data_dir: String,
    pub executable: String,
    pub headless: Option<bool>,
    pub color: String,
    pub engine: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CamofoxConfig {
    pub url: String,
    pub api_key: String,
    pub user_id: String,
    pub session_key: String,
    pub managed_persistence: bool,
    pub adopt_existing_tab: bool,
    pub rewrite_loopback_urls: bool,
    pub loopback_host_alias: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxConfig {
    /// OpenClaw sandbox-browser image (built from packaging/sandbox-browser).
    pub image: String,
    pub novnc: bool,
    pub headless: bool,
    pub network: String,
    pub start_timeout_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExtensionConfig {
    pub enabled: bool,
    /// Also allow evaluate / raw CDP through the extension.
    pub developer_mode: bool,
    /// Loopback port the extension connects to (0 = 18792).
    pub port: u16,
}

impl Default for CamofoxConfig {
    fn default() -> Self {
        CamofoxConfig { url: String::new(), api_key: String::new(), user_id: String::new(), session_key: String::new(), managed_persistence: false, adopt_existing_tab: false, rewrite_loopback_urls: false, loopback_host_alias: "host.docker.internal".into() }
    }
}

impl Default for SandboxConfig {
    fn default() -> Self {
        SandboxConfig { image: "ark-sandbox-browser:latest".into(), novnc: true, headless: false, network: "bridge".into(), start_timeout_ms: 12_000 }
    }
}

impl Default for BrowserConfig {
    fn default() -> Self {
        BrowserConfig {
            enabled: toml::Value::String("auto".into()),
            backend: String::new(),
            cdp_url: String::new(),
            executable: String::new(),
            headless: true,
            no_sandbox: toml::Value::String("auto".into()),
            extra_args: vec![],
            default_profile: "ark".into(),
            profiles: BTreeMap::new(),
            command_timeout: 30,
            inactivity_timeout: 120,
            snapshot_threshold: 15_000,
            allow_private_urls: None,
            auto_local_for_private_urls: true,
            allowed_domains: vec![],
            blocked_domains: vec![],
            evaluate_enabled: true,
            restrict_evaluate: false,
            allow_unsafe_evaluate: false,
            dialog_policy: "must_respond".into(),
            dialog_timeout_s: 300,
            record_sessions: false,
            use_real_profile: false,
            real_profile_pin: String::new(),
            real_profile_autoclose: false,
            engine: "auto".into(),
            isolate_sessions: false,
            cloud_provider: String::new(),
            auto_install: true,
            install_base_url: "https://cdn.playwright.dev".into(),
            exec_enabled: false,
            exec_command: vec!["python3".into(), "-m".into(), "browser_harness.run".into()],
            camofox: CamofoxConfig::default(),
            sandbox: SandboxConfig::default(),
            extension_control: ExtensionConfig::default(),
            vault: VaultConfig::default(),
        }
    }
}

/// Documented defaults (printed by `ark config` docs and checked by a test).
pub const DEFAULTS: &str = r#"[browser]
enabled = "auto"            # "auto": browser tools appear when a browser is reachable; true / false
backend = ""                # "" auto | local | cdp | browserbase | browser-use | firecrawl | camofox | lightpanda | sandbox | extension
cdp_url = ""                # attach to your Chrome: http://127.0.0.1:9222 (started with --remote-debugging-port)
executable = ""             # Chromium/Chrome/Brave/Edge binary for managed profiles ("" = search)
headless = true
no_sandbox = "auto"         # --no-sandbox when root, in a container, or AppArmor blocks user namespaces
extra_args = []
default_profile = "ark"     # managed profile; data in ~/.local/share/ark/browser/profiles/<name>
command_timeout = 30        # seconds per browser command (min 5)
inactivity_timeout = 120    # close idle session browsers after N seconds (min 30)
snapshot_threshold = 15000  # browser_snapshot chars before truncate-and-store
# allow_private_urls =      # unset: allowed for local browsers, refused for cloud ones
auto_local_for_private_urls = true
allowed_domains = []        # non-empty: only these hosts (and subdomains)
blocked_domains = []
evaluate_enabled = true     # browser act:evaluate / wait fn
restrict_evaluate = false   # refuse cookie/storage/fetch primitives in browser_console(expression)
allow_unsafe_evaluate = false
dialog_policy = "must_respond"  # must_respond | auto_dismiss | auto_accept
dialog_timeout_s = 300
record_sessions = false
use_real_profile = false    # browse with a copy of your default Chromium profile
real_profile_pin = ""
real_profile_autoclose = false
engine = "auto"             # auto | chrome | lightpanda
isolate_sessions = false    # one browser context per ark session
cloud_provider = ""         # browserbase | browser-use | firecrawl | camofox | local ("" = auto-detect from keys)
auto_install = true         # no Chromium found: download the pinned Chrome for Testing build (ARK_DISABLE_LAZY_INSTALLS=1 turns off)
install_base_url = "https://cdn.playwright.dev"  # Chromium CDN (pinned path + SHA-256 verified)
exec_enabled = false        # offer browser_exec (Browser Use harness)
exec_command = ["python3", "-m", "browser_harness.run"]
[browser.camofox]           # CAMOFOX_URL / CAMOFOX_API_KEY env override
url = ""
loopback_host_alias = "host.docker.internal"
[browser.sandbox]
image = "ark-sandbox-browser:latest"
novnc = true
[browser.extension_control]
enabled = false
developer_mode = false
port = 18792
[browser.vault.bitwarden]   # browser_vault logins from Bitwarden (`bw`), when installed
enabled = true
binary_path = ""            # "" = bw on PATH
[browser.vault.onepassword] # browser_vault logins from 1Password (`op`), when installed
enabled = true
binary_path = ""            # "" = op on PATH
account = ""                # OP_ACCOUNT shorthand
service_account_token_env = "OP_SERVICE_ACCOUNT_TOKEN"  # token here skips the unlock prompt
"#;

impl BrowserConfig {
    pub fn parse(t: &toml::Table) -> Result<BrowserConfig, String> {
        let c = BrowserConfig::deserialize(toml::Value::Table(t.clone())).map_err(|e| format!("[browser]: {e}"))?;
        if !matches!(c.dialog_policy.as_str(), "must_respond" | "auto_dismiss" | "auto_accept") {
            return Err(format!("[browser] dialog_policy must be must_respond, auto_dismiss or auto_accept, got `{}`", c.dialog_policy));
        }
        if !matches!(c.cloud_provider.trim().to_ascii_lowercase().as_str(), "" | "local" | "camofox" | "nous" | "browserbase" | "browser-use" | "firecrawl") {
            return Err(format!("[browser] cloud_provider `{}`: no browser provider has that name (browserbase, browser-use, firecrawl, camofox, local)", c.cloud_provider));
        }
        if !matches!(c.engine.as_str(), "auto" | "chrome" | "lightpanda") {
            return Err(format!("[browser] engine must be auto, chrome or lightpanda, got `{}`", c.engine));
        }
        for n in c.profiles.keys() {
            valid_profile_name(n)?;
        }
        Ok(c)
    }

    /// `enabled`: Some(bool) when forced, None for "auto".
    pub fn enabled(&self) -> Option<bool> {
        match &self.enabled {
            toml::Value::Boolean(b) => Some(*b),
            toml::Value::String(s) if s == "true" => Some(true),
            toml::Value::String(s) if s == "false" || s == "off" => Some(false),
            _ => None,
        }
    }

    pub fn command_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.command_timeout.max(5))
    }

    pub fn inactivity(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.inactivity_timeout.max(30))
    }

    pub fn snapshot_threshold(&self) -> usize {
        self.snapshot_threshold.max(1000)
    }

    pub fn camofox_url(&self) -> String {
        std::env::var("CAMOFOX_URL").ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| self.camofox.url.clone()).trim().trim_end_matches('/').to_string()
    }

    pub fn cdp_override(&self) -> String {
        cdp_env().unwrap_or_else(|| self.cdp_url.clone()).trim().to_string()
    }

    /// The backend in effect (Hermes `browser_backend_name` precedence: CDP override >
    /// explicit `cloud_provider` (local / camofox / nous / provider) > Camofox URL >
    /// auto-detect (Browser Use, then Browserbase; never Firecrawl) > engine).
    pub fn backend(&self) -> String {
        let b = self.backend.trim();
        if !b.is_empty() {
            return b.to_string();
        }
        if !self.cdp_override().is_empty() {
            return "cdp".into();
        }
        let local = || if self.engine() == "lightpanda" { "lightpanda".to_string() } else { "local".to_string() };
        match self.cloud_provider.trim().to_ascii_lowercase().as_str() {
            "" => {}
            "local" => return local(),
            "nous" => return "browser-use".into(),
            p => return p.to_string(),
        }
        // A stored selection wins over CAMOFOX_URL; with none, the URL alone selects Camofox.
        if !self.camofox_url().is_empty() {
            return "camofox".into();
        }
        if env_set("BROWSER_USE_API_KEY") {
            return "browser-use".into();
        }
        if env_set("BROWSERBASE_API_KEY") && env_set("BROWSERBASE_PROJECT_ID") {
            return "browserbase".into();
        }
        local()
    }

    /// `browser.engine`, then `AGENT_BROWSER_ENGINE` when "auto" (Hermes `_get_browser_engine`);
    /// unknown values fall back to "auto".
    pub fn engine(&self) -> String {
        let mut e = self.engine.trim().to_ascii_lowercase();
        if e.is_empty() || e == "auto" {
            e = std::env::var("AGENT_BROWSER_ENGINE").map(|v| v.trim().to_ascii_lowercase()).unwrap_or_default();
        }
        if matches!(e.as_str(), "chrome" | "lightpanda") {
            e
        } else {
            "auto".into()
        }
    }

    /// Headless unless `headless = false` or `AGENT_BROWSER_HEADED` is truthy (Hermes `_is_headed_mode`).
    pub fn headless_effective(&self) -> bool {
        self.headless && !std::env::var("AGENT_BROWSER_HEADED").is_ok_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
    }

    pub fn is_cloud(&self) -> bool {
        matches!(self.backend().as_str(), "browserbase" | "browser-use" | "firecrawl" | "camofox" | "sandbox")
    }

    /// Private/LAN navigation allowed for this backend?
    pub fn private_allowed(&self) -> bool {
        self.allow_private_urls.unwrap_or(!self.is_cloud())
    }

    pub fn no_sandbox(&self) -> bool {
        match &self.no_sandbox {
            toml::Value::Boolean(b) => *b,
            _ => (unsafe { libc::geteuid() }) == 0 || std::path::Path::new("/.dockerenv").exists() || std::fs::read_to_string("/proc/1/cgroup").is_ok_and(|c| c.contains("docker") || c.contains("kubepods")) || apparmor_restricts_userns(),
        }
    }
}

/// Ubuntu 23.10+: unprivileged user namespaces denied, so a Chromium without a setuid
/// sandbox helper dies with "No usable sandbox" (Hermes `apparmor_restricts_unprivileged_userns`).
pub fn apparmor_restricts_userns() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").is_ok_and(|s| s.trim() == "1")
}

fn env_set(k: &str) -> bool {
    std::env::var(k).is_ok_and(|v| !v.trim().is_empty())
}

/// OpenClaw profile names: `^[a-z0-9][a-z0-9-]*$`, ≤ 64.
pub fn valid_profile_name(n: &str) -> Result<(), String> {
    let ok = !n.is_empty() && n.len() <= 64 && n.as_bytes()[0].is_ascii_alphanumeric() && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(format!("invalid browser profile name `{n}` (lowercase letters, digits and -, at most 64)"))
    }
}

/// `BROWSER_CDP_URL`, as `/browser connect` sets it (Hermes behaviour: a process-wide override).
///
/// Unit tests run as parallel threads of one process, so in test builds only a thread that opted
/// in through [`CDP_ENV_OPT_IN`] (the `/browser connect` test) sees it; otherwise the value that
/// test sets would redirect every other CDP test to its fake endpoint.
pub(crate) fn cdp_env() -> Option<String> {
    #[cfg(test)]
    if !CDP_ENV_OPT_IN.with(|c| c.get()) {
        return None;
    }
    std::env::var("BROWSER_CDP_URL").ok().filter(|s| !s.trim().is_empty())
}

#[cfg(test)]
thread_local! {
    /// See [`cdp_env`].
    pub(crate) static CDP_ENV_OPT_IN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_parse_and_match_the_documented_table() {
        let t: toml::Table = toml::from_str(DEFAULTS).unwrap();
        let c = BrowserConfig::parse(t["browser"].as_table().unwrap()).unwrap();
        let d = BrowserConfig::default();
        assert_eq!((c.headless, c.command_timeout, c.snapshot_threshold, c.dialog_timeout_s, c.default_profile.as_str()), (d.headless, d.command_timeout, d.snapshot_threshold, d.dialog_timeout_s, d.default_profile.as_str()));
        assert_eq!(c.enabled(), None);
        assert!(BrowserConfig::parse(&toml::from_str("dialog_policy = \"ignore\"").unwrap()).is_err());
        assert!(BrowserConfig::parse(&toml::from_str("[profiles.Work]").unwrap()).is_err());
        assert!(BrowserConfig::parse(&toml::from_str("nope = 1").unwrap()).is_err());
    }

    #[test]
    fn backend_precedence_and_private_policy() {
        let mut c = BrowserConfig::default();
        if std::env::var("BROWSER_CDP_URL").is_err() && std::env::var("CAMOFOX_URL").is_err() && std::env::var("BROWSER_USE_API_KEY").is_err() && std::env::var("BROWSERBASE_API_KEY").is_err() {
            assert_eq!(c.backend(), "local");
            assert!(c.private_allowed());
            c.camofox.url = "http://127.0.0.1:9377/".into();
            assert_eq!(c.backend(), "camofox");
            assert!(!c.private_allowed());
            c.cdp_url = "http://127.0.0.1:9222".into();
            assert_eq!(c.backend(), "cdp");
        }
        c.backend = "firecrawl".into();
        assert!(c.is_cloud());
        c.allow_private_urls = Some(true);
        assert!(c.private_allowed());
        assert_eq!(c.command_timeout().as_secs(), 30);
        c.command_timeout = 1;
        assert_eq!(c.command_timeout().as_secs(), 5);
    }
}
