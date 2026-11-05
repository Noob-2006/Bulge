//! seagent-security: policy helpers shared by the kernel, tools, plugins and CLI.
//!
//! Approval floors and state (`hardline`, `approvals`, `review`), prompt-injection
//! threat patterns and external-content wrapping (`threat`, `external`), child-process
//! env scrubbing (`envscrub`), URL/SSRF and website policy (`url_safety`), file-path
//! guards (`paths`), OSV checks (`osv`), plugin scanning and consent (`plugin_guard`),
//! tool profiles (`toolpolicy`), the local egress proxy and its credential injection
//! (`egress_proxy`), the emergency stop (`estop`) and credential-file passthrough for
//! sandboxes (`credfiles`).
//!
//! Supply-chain and secret-at-rest primitives are here too, so there is exactly one copy:
//! Ed25519 manifest/release signatures (`signing`) and the AEAD/password-KDF used by the
//! secret store (`secretbox`).

pub mod approvals;
pub mod audit;
pub mod audit_export;
pub mod audit_report;
pub mod audit_seal;
pub mod broker;
pub mod capability;
pub mod credfiles;
pub mod dual_control;
pub mod envelope;
pub mod exposure;
pub mod egress_proxy;
pub mod envscrub;
pub mod estop;
pub mod external;
pub mod glob;
pub mod guidance;
pub mod hardline;
pub mod osv;
pub mod paths;
pub mod pii;
pub mod plugin_guard;
pub mod review;
pub mod risk;
pub mod secretbox;
pub mod signing;
pub mod skills_guard;
pub mod threat;
pub mod toolpolicy;
pub mod url_safety;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Consent {
    Off,
    /// Load, but log and report unconsented capabilities.
    #[default]
    Warn,
    /// Refuse to load a plugin whose capabilities are not (or no longer) accepted.
    Require,
}

/// Where untrusted external content gets boundary markers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExternalContentConfig {
    pub enabled: bool,
    /// Tool names / globs whose results are wrapped (web pages, browser text, untrusted MCP).
    pub tools: Vec<String>,
    /// Channels whose inbound messages are wrapped (webhooks, e-mail).
    pub channels: Vec<String>,
}

impl Default for ExternalContentConfig {
    fn default() -> Self {
        ExternalContentConfig {
            enabled: true,
            tools: ["web_fetch", "web_search", "web_extract", "browser*", "x_search"].iter().map(|s| s.to_string()).collect(),
            channels: ["webhook", "email", "gmail", "msgraph_webhook"].iter().map(|s| s.to_string()).collect(),
        }
    }
}

/// Which surfaces the threat scanner checks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ThreatScanConfig {
    /// AGENTS.md / CLAUDE.md: blocked on a hit (context scope).
    pub context_files: bool,
    /// Memory writes (blocked) and the memory snapshot (entries replaced).
    pub memory: bool,
    /// Tool output of untrusted tools: a warning note is appended.
    pub tool_output: bool,
    /// Scheduled-job prompts (blocked at creation and at run time).
    pub cron: bool,
}

impl Default for ThreatScanConfig {
    fn default() -> Self {
        ThreatScanConfig { context_files: true, memory: true, tool_output: true, cron: true }
    }
}

/// `[security]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    /// Allow private / loopback / CGNAT URL targets (cloud metadata stays blocked).
    pub allow_private_urls: bool,
    /// CIDR blocks a local fake-ip TUN proxy answers DNS with.
    pub fake_ip_ranges: Vec<String>,
    pub website_blocklist: url_safety::WebsiteBlocklist,
    /// File tools may only touch the workspace (plus session artifacts / skills).
    pub workspace_only: bool,
    pub read_deny: Vec<String>,
    pub write_deny: Vec<String>,
    pub write_safe_roots: Vec<String>,
    /// Strip seagent-managed credentials from child processes.
    pub scrub_env: bool,
    pub env_strip: Vec<String>,
    pub env_passthrough: Vec<String>,
    /// Refuse git operations that rewrite the checkout seagent was built from.
    pub self_repo_guard: bool,
    /// Query OSV for MAL-* advisories before launching npx/uvx/pipx servers.
    pub osv_check: bool,
    pub plugin_consent: Consent,
    /// Operator command consulted before installing/trusting plugins (JSON on stdin).
    pub install_policy: Vec<String>,
    /// Home-relative files sandboxes may mount read-only.
    pub credential_files: Vec<String>,
    pub external_content: ExternalContentConfig,
    /// `[security.egress_proxy]`: local forward proxy every child is routed through.
    pub egress_proxy: egress_proxy::EgressProxyConfig,
    /// `[security.broker]`: daemon-side privileged-command + egress broker for the VM (A2–A4).
    pub broker: broker::BrokerConfig,
    pub threat_scan: ThreatScanConfig,
    /// Findings `seagent security audit` should not report (check ids).
    pub audit_suppress: Vec<String>,
    /// Whether tool execution runs inside the VM sandbox (B). `None` = auto (`SEAGENT_SANDBOX=1`
    /// in the VM image). Only tier 0 auto-approval depends on it, so pin it on hosts
    /// without a VM rather than trusting a variable a skill could set.
    pub sandboxed: Option<bool>,
    /// H11 (runtime half): mask credential-shaped strings (API keys, tokens, private keys —
    /// not only vault values) in tool output before it enters the context, the session log
    /// or a chat, and check `git commit` for staged secrets. Default on.
    pub mask_output_secrets: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            allow_private_urls: false,
            fake_ip_ranges: vec![],
            website_blocklist: Default::default(),
            workspace_only: false,
            read_deny: vec![],
            write_deny: vec![],
            write_safe_roots: vec![],
            scrub_env: true,
            env_strip: vec![],
            env_passthrough: vec![],
            self_repo_guard: false,
            osv_check: true,
            plugin_consent: Consent::Warn,
            install_policy: vec![],
            credential_files: vec![],
            external_content: Default::default(),
            egress_proxy: Default::default(),
            broker: Default::default(),
            threat_scan: Default::default(),
            audit_suppress: vec![],
            sandboxed: None,
            mask_output_secrets: true,
        }
    }
}

impl SecurityConfig {
    pub fn url_policy(&self) -> url_safety::UrlPolicy {
        url_safety::UrlPolicy { allow_private_urls: self.allow_private_urls, fake_ip_ranges: self.fake_ip_ranges.clone() }
    }
    pub fn path_policy(&self) -> paths::PathPolicy {
        paths::PathPolicy { workspace_only: self.workspace_only, read_deny: self.read_deny.clone(), write_deny: self.write_deny.clone(), write_safe_roots: self.write_safe_roots.clone() }
    }
    /// Push process-wide parts (env scrub policy, egress proxy) into effect.
    pub fn activate(&self) {
        envscrub::configure(self.scrub_env, &self.env_strip, &self.env_passthrough);
        osv::set_enabled(self.osv_check);
        // `activate()` is called from `kernel::new_kernel`, which has no data dir. Use the
        // profile root only when the operator pointed `SEAGENT_HOME` at one; otherwise the
        // connection log stays in memory (`egress_proxy::recent()`) and no directory is
        // invented. Callers that do have a data dir call `activate_egress` directly.
        let data = std::env::var_os("SEAGENT_HOME").map(|h| std::path::PathBuf::from(h).join("data"));
        if let Err(e) = self.activate_egress(data.as_deref(), egress_proxy::env_secrets()) {
            eprintln!("seagent: warning: egress proxy not started: {e}");
        }
    }

    /// Start (or re-point) the process-wide egress proxy and point children at it
    /// (`envscrub::set_proxy`). Returns its `http://127.0.0.1:<port>` URL, or `None`
    /// when `[security.egress_proxy] enabled = false`.
    ///
    /// `data_dir` is the profile data dir: connections are appended as JSON lines to
    /// `<data_dir>/egress/proxy.jsonl`. `None` keeps the log in the in-memory ring only.
    /// Only the first call decides the log: one daemon, one proxy (a later call updates
    /// the policy, see `egress_proxy::ensure_started`).
    ///
    /// `secrets` expands `inject` values (`Bearer {{secret:NAME}}`); the proxy calls it
    /// per request, so the child never holds the secret.
    /// `[security]` URL policy and website blocklist into effect for every fetcher
    /// (`seagent_security::url_safety::global_policy` / `check_website_global`), then
    /// [`Self::activate`]. `config_dir` resolves relative `website_blocklist.shared_files`.
    pub fn activate_at(&self, config_dir: Option<&std::path::Path>) {
        url_safety::configure(&self.url_policy(), &self.website_blocklist, config_dir);
        self.activate();
    }

    pub fn activate_egress(&self, data_dir: Option<&std::path::Path>, secrets: egress_proxy::Secrets) -> Result<Option<String>, String> {
        let cfg_dir = data_dir.map(|d| d.to_path_buf()).or_else(|| std::env::var_os("SEAGENT_HOME").map(std::path::PathBuf::from)).unwrap_or_else(|| std::path::PathBuf::from("."));
        let log = data_dir.map(|d| d.join("egress").join("proxy.jsonl"));
        let policy = egress_proxy::Policy::from_config(&self.egress_proxy, self.url_policy(), self.website_blocklist.clone(), &cfg_dir, &[], &[]);
        egress_proxy::ensure_started(&self.egress_proxy, policy, secrets, log)
    }
}

/// RFC 3339 UTC timestamp without a date library.
pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

#[cfg(test)]
pub(crate) mod testserver {
    //! Tiny HTTP fake: answers each request with the next canned body whose path prefix
    //! matches, and records request bodies.
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    pub fn serve(mut routes: Vec<(&'static str, String)>) -> (String, Arc<Mutex<Vec<String>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        std::thread::spawn(move || {
            for stream in l.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                if r.read_line(&mut line).is_err() {
                    continue;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    if r.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; len];
                let _ = r.read_exact(&mut body);
                s2.lock().unwrap().push(format!("{path} {}", String::from_utf8_lossy(&body)));
                let idx = routes.iter().position(|(p, _)| path.starts_with(p));
                let (status, resp) = match idx {
                    Some(i) => ("200 OK", routes.remove(i).1),
                    None => ("404 Not Found", "{}".to_string()),
                };
                let _ = write!(s, "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{resp}", resp.len());
            }
        });
        (url, seen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_and_toml_shape() {
        let c: SecurityConfig = serde_json::from_value(serde_json::json!({"allow_private_urls": true, "workspace_only": true, "website_blocklist": {"enabled": true, "domains": ["x.com"]}})).unwrap();
        assert!(c.url_policy().allow_private_urls && c.path_policy().workspace_only && c.website_blocklist.enabled);
        assert!(serde_json::from_value::<SecurityConfig>(serde_json::json!({"typo": 1})).is_err());
        assert!(c.scrub_env && c.osv_check && c.external_content.enabled && c.threat_scan.context_files);
        assert_eq!(c.plugin_consent, Consent::Warn);
        let ts = now_rfc3339();
        assert_eq!(ts.len(), 20);
        assert!(ts.starts_with("20") && ts.ends_with('Z'));
    }

    /// `[security.egress_proxy]` (the TOML table the exec docs name) round-trips, and a
    /// near-miss table name is refused instead of silently ignored.
    #[test]
    fn egress_proxy_toml_table_parses() {
        let t = r#"
allow_private_urls = false
[egress_proxy]
enabled = true
listen = "127.0.0.1:0"
mode = "allowlist"
allow = ["api.example.com", "*.github.com"]
deny = ["evil.example.com"]
[[egress_proxy.inject]]
host = "api.example.com"
header = "Authorization"
value = "Bearer {{secret:SERVICE_TOKEN}}"
"#;
        let c: SecurityConfig = toml::from_str(t).unwrap();
        let e = &c.egress_proxy;
        assert!(e.enabled);
        assert_eq!(e.listen, "127.0.0.1:0");
        assert_eq!(e.mode, egress_proxy::ProxyMode::Allowlist);
        assert_eq!(e.allow, ["api.example.com", "*.github.com"]);
        assert_eq!(e.deny, ["evil.example.com"]);
        assert_eq!(e.inject, vec![egress_proxy::Inject { host: "api.example.com".into(), header: "Authorization".into(), value: "Bearer {{secret:SERVICE_TOKEN}}".into() }]);
        // Defaults: off, loopback, filter, nothing allowed/denied/injected.
        let d = SecurityConfig::default().egress_proxy;
        assert!(!d.enabled && d.listen == "127.0.0.1:0" && d.mode == egress_proxy::ProxyMode::Filter && d.allow.is_empty() && d.deny.is_empty() && d.inject.is_empty());
        // `deny_unknown_fields` on both structs: a misspelled table, key or enum is an error
        // rather than a silently ignored knob.
        for bad in [
            "[egress]\nenabled = true\n",                                          // the wrong table name
            "[egress_proxy]\nenabled = true\nlisten_port = 3128\n",                // unknown key
            "[egress_proxy]\nmode = \"open\"\n",                                   // unknown mode
            "[egress_proxy]\nenabled = true\n[[egress_proxy.inject]]\nhost = \"x\"\nheader = \"A\"\nvalue = \"v\"\nextra = 1\n",
        ] {
            assert!(toml::from_str::<SecurityConfig>(bad).is_err(), "{bad}");
        }
        // Nothing else in `[security]` moved: the old keys still parse next to it.
        let nested = "allow_private_urls = true\n[egress_proxy]\nenabled = true\ndeny = [\"bad.io\"]\n[threat_scan]\ncron = false\n";
        let n: SecurityConfig = toml::from_str(nested).unwrap();
        assert!(n.allow_private_urls && n.egress_proxy.enabled && !n.threat_scan.cron);
        assert_eq!(n.egress_proxy.deny, ["bad.io"]);
    }
}
