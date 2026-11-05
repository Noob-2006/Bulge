//! `[web]` config: web_search / web_extract / web_fetch / x_search / link understanding.
//! Defaults follow Hermes (`web:` in config.yaml) and OpenClaw (`tools.web`).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebConfig {
    /// Shared backend for search and extract (Hermes `web.backend`). Empty = autodetect.
    pub backend: String,
    pub search: SearchConfig,
    pub extract: ExtractConfig,
    pub fetch: FetchConfig,
    /// Result caches (search memo in memory, extract/fetch cache on disk).
    pub cache_enabled: bool,
    /// TTL of both caches, minutes (clamped 1–1440).
    pub cache_ttl_minutes: f64,
    /// Hosts that always fetch live (staging sites, tunnels): exact, `*.x` or parent domain.
    pub cache_exempt_hosts: Vec<String>,
    /// Anonymous free tiers (Exa / Parallel / Firecrawl / Keenable) as the last autodetect rung.
    pub keyless_fallback: bool,
    /// One-shot keyless rescue when a configured backend fails a call.
    pub keyless_rescue: bool,
    /// Per-vendor tier pin: `free` (keyless even with a key) or `paid`.
    pub provider_tier: BTreeMap<String, String>,
    /// Per-provider settings: `[web.providers.<id>] api_key / base_url / model / …`.
    pub providers: BTreeMap<String, Value>,
    /// SSRF: allow private/internal addresses (cloud metadata stays blocked).
    pub allow_private_urls: bool,
    /// CIDR blocks a local fake-ip proxy answers DNS with (Clash/Mihomo/Surge).
    pub fake_ip_ranges: Vec<String>,
    /// Website blocklist (Hermes `security.website_blocklist`).
    pub blocklist: BlocklistConfig,
    pub x_search: XSearchConfig,
    pub links: LinksConfig,
}

impl Default for WebConfig {
    fn default() -> Self {
        WebConfig {
            backend: String::new(),
            search: SearchConfig::default(),
            extract: ExtractConfig::default(),
            fetch: FetchConfig::default(),
            cache_enabled: true,
            cache_ttl_minutes: 20.0,
            cache_exempt_hosts: vec![],
            keyless_fallback: true,
            keyless_rescue: true,
            provider_tier: BTreeMap::new(),
            providers: BTreeMap::new(),
            allow_private_urls: false,
            fake_ip_ranges: vec![],
            blocklist: BlocklistConfig::default(),
            x_search: XSearchConfig::default(),
            links: LinksConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SearchConfig {
    pub enabled: bool,
    /// Search provider id (Hermes `web.search_backend`, OpenClaw `tools.web.search.provider`).
    pub provider: String,
    /// Default result count when the model gives none.
    pub max_results: usize,
    pub timeout_seconds: u64,
}

impl Default for SearchConfig {
    fn default() -> Self {
        SearchConfig { enabled: true, provider: String::new(), max_results: 5, timeout_seconds: 30 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExtractConfig {
    pub enabled: bool,
    /// Extract provider id (Hermes `web.extract_backend`); `local` = ark's own fetch + readability.
    pub provider: String,
    /// Per-page budget returned to the model (clamped 2 000–500 000).
    pub char_limit: usize,
    /// Wall-clock cap on one provider extract call, seconds (0 = none).
    pub timeout_seconds: u64,
    /// URLs taken from one call (Hermes: 5); extra entries are dropped.
    pub max_urls: usize,
    /// Retry URLs a provider failed on with ark's own guarded fetch + readability.
    pub local_fallback: bool,
}

impl Default for ExtractConfig {
    fn default() -> Self {
        ExtractConfig { enabled: true, provider: String::new(), char_limit: 15_000, timeout_seconds: 120, max_urls: 5, local_fallback: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FetchConfig {
    pub enabled: bool,
    /// Fallback fetch provider when direct fetch / readability fail (`firecrawl`). Empty = autodetect.
    pub provider: String,
    pub max_chars: usize,
    /// Ceiling for the model's `maxChars`.
    pub max_chars_cap: usize,
    pub max_response_bytes: u64,
    pub max_redirects: u32,
    pub timeout_seconds: u64,
    pub cache_ttl_minutes: f64,
    pub user_agent: String,
    /// Extra request headers (reserved / framing headers are dropped).
    pub headers: BTreeMap<String, String>,
    /// Readability main-content extraction (else basic HTML cleanup / provider).
    pub readability: bool,
    /// Hosts allowed to resolve to private addresses (exact names).
    pub allowed_hostnames: Vec<String>,
    /// When non-empty, only these hosts (`x.com`, `*.x.com`) may be fetched.
    pub hostname_allowlist: Vec<String>,
    /// Always refused (`x.com`, `*.x.com` = subdomains only).
    pub blocked_hostnames: Vec<String>,
}

impl Default for FetchConfig {
    fn default() -> Self {
        FetchConfig {
            enabled: true,
            provider: String::new(),
            max_chars: 20_000,
            max_chars_cap: 20_000,
            max_response_bytes: 750_000,
            max_redirects: 3,
            timeout_seconds: 30,
            cache_ttl_minutes: 15.0,
            user_agent: String::new(),
            headers: BTreeMap::new(),
            readability: true,
            allowed_hostnames: vec![],
            hostname_allowlist: vec![],
            blocked_hostnames: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BlocklistConfig {
    pub enabled: bool,
    /// Hosts, URLs or `host/path` rules; `*.x.com` globs, bare hosts also match subdomains.
    pub domains: Vec<String>,
    /// Files with one rule per line (`#` comments); relative paths are under the ark home.
    pub shared_files: Vec<String>,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        BlocklistConfig { enabled: true, domains: vec![], shared_files: vec![] }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct XSearchConfig {
    pub enabled: bool,
    pub model: String,
    pub timeout_seconds: u64,
    pub retries: u32,
    /// `low` | `medium` | `high` | `xhigh`; empty = model default.
    pub reasoning_effort: String,
    /// Inline citations in the answer text (OpenClaw `inlineCitations`).
    pub inline_citations: bool,
    pub max_turns: Option<u32>,
    /// Answer cache TTL, minutes (OpenClaw `xSearch.cacheTtlMinutes`); unset = `web.cache_ttl_minutes`,
    /// 0 = no caching.
    pub cache_ttl_minutes: Option<f64>,
}

impl Default for XSearchConfig {
    fn default() -> Self {
        XSearchConfig { enabled: true, model: String::new(), timeout_seconds: 180, retries: 2, reasoning_effort: String::new(), inline_citations: false, max_turns: None, cache_ttl_minutes: None }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LinksConfig {
    /// Off unless configured: the processors are shell commands.
    pub enabled: bool,
    /// Links taken from one inbound message (default 3).
    pub max_links: Option<usize>,
    /// Fetch timeout and default processor timeout, seconds (default 30).
    pub timeout_seconds: Option<u64>,
    pub scope: Option<LinkScope>,
    /// Processors tried in order; the first non-empty output wins.
    pub models: Vec<LinkModel>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LinkScope {
    /// `allow` | `deny` when no rule matches.
    pub default: Option<String>,
    pub rules: Vec<LinkScopeRule>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LinkScopeRule {
    pub action: String,
    pub channel: Option<String>,
    /// `direct` | `group` | `channel`.
    pub chat_type: Option<String>,
    pub key_prefix: Option<String>,
    /// OpenClaw shape (`{ action, match: { channel, chatType, keyPrefix } }`); its keys win over the flat ones.
    #[serde(rename = "match")]
    pub matches: Option<LinkScopeMatch>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LinkScopeMatch {
    pub channel: Option<String>,
    #[serde(alias = "chatType")]
    pub chat_type: Option<String>,
    #[serde(alias = "keyPrefix")]
    pub key_prefix: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LinkModel {
    /// Only `cli` is supported (as upstream).
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub command: String,
    pub args: Vec<String>,
    pub timeout_seconds: Option<u64>,
}

impl WebConfig {
    /// Parse the `[web]` table; unknown keys are errors.
    pub fn from_value(v: Value) -> Result<WebConfig, String> {
        if v.is_null() {
            return Ok(WebConfig::default());
        }
        serde_json::from_value(v).map_err(|e| format!("[web]: {e}"))
    }
    /// `[web.providers.<id>]` as an object (empty when absent).
    pub fn provider(&self, id: &str) -> &serde_json::Map<String, Value> {
        static EMPTY: std::sync::OnceLock<serde_json::Map<String, Value>> = std::sync::OnceLock::new();
        self.providers.get(id).and_then(|v| v.as_object()).unwrap_or_else(|| EMPTY.get_or_init(serde_json::Map::new))
    }
    pub fn tier(&self, id: &str) -> &str {
        match self.provider_tier.get(id).map(|s| s.trim().to_ascii_lowercase()) {
            Some(t) if t == "free" => "free",
            Some(t) if t == "paid" => "paid",
            _ => "auto",
        }
    }
    pub fn ttl_secs(&self) -> u64 {
        let m = if self.cache_ttl_minutes.is_finite() { self.cache_ttl_minutes } else { 20.0 };
        (m.clamp(1.0, 1440.0) * 60.0) as u64
    }
    /// Effective search provider id: `search.provider` > `backend` (lower-cased).
    pub fn search_pin(&self) -> String {
        let s = self.search.provider.trim();
        if s.is_empty() { self.backend.trim() } else { s }.to_ascii_lowercase()
    }
    pub fn extract_pin(&self) -> String {
        let s = self.extract.provider.trim();
        if s.is_empty() { self.backend.trim() } else { s }.to_ascii_lowercase()
    }
    /// Some backend key names this vendor (it is explicitly selected).
    pub fn selects(&self, id: &str) -> bool {
        [&self.backend, &self.search.provider, &self.extract.provider, &self.fetch.provider].iter().any(|s| s.trim().eq_ignore_ascii_case(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_and_parse() {
        let c = WebConfig::default();
        assert!(c.cache_enabled && c.keyless_fallback && c.keyless_rescue && !c.allow_private_urls);
        assert_eq!((c.search.max_results, c.extract.char_limit, c.fetch.max_chars, c.fetch.max_redirects), (5, 15_000, 20_000, 3));
        assert_eq!(c.ttl_secs(), 1200);
        assert_eq!((c.extract.max_urls, c.extract.local_fallback, c.fetch.max_response_bytes, c.fetch.cache_ttl_minutes), (5, true, 750_000, 15.0));
        assert_eq!((c.x_search.timeout_seconds, c.x_search.retries, c.x_search.cache_ttl_minutes), (180, 2, None));
        let x = WebConfig::from_value(json!({"x_search":{"cache_ttl_minutes":0,"max_turns":2}})).unwrap().x_search;
        assert_eq!((x.cache_ttl_minutes, x.max_turns), (Some(0.0), Some(2)));
        let c = WebConfig::from_value(json!({"backend":"Tavily","search":{"provider":""},"provider_tier":{"exa":"FREE"},"providers":{"brave":{"api_key":"k"}},"cache_ttl_minutes":0})).unwrap();
        assert_eq!((c.search_pin().as_str(), c.extract_pin().as_str()), ("tavily", "tavily"));
        assert_eq!((c.tier("exa"), c.tier("x")), ("free", "auto"));
        assert_eq!(c.provider("brave")["api_key"], "k");
        assert!(c.provider("nope").is_empty());
        assert_eq!(c.ttl_secs(), 60);
        assert!(c.selects("tavily") && !c.selects("exa"));
        assert!(WebConfig::from_value(json!({"bogus":1})).unwrap_err().contains("bogus"));
        assert!(WebConfig::from_value(Value::Null).is_ok());
    }
}
