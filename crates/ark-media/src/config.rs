//! `[media]` config: one TOML table parsed here (the kernel keeps it opaque).
//!
//! ```toml
//! [media]
//! output_dir = ""                       # default <workspace>/.ark/media
//! [media.image]   provider = "auto"  model = ""
//! [media.video]   provider = "auto"  model = ""
//! [media.music]   provider = "auto"  model = ""
//! [media.tts]     provider = "edge"  voice = ""  auto = "off"
//! [media.stt]     provider = "auto"  model = ""  language = ""
//! [media.vision]  model = ""  max_history_images = 8
//! [media.providers.openai]  api_key = "{{secret:OPENAI_API_KEY}}"  base_url = "…"
//! ```
//!
//! Credentials for media provider `id` come from `[media.providers.<id>]`
//! (`api_key`, `api_key_env`, `base_url`, `headers`, plus provider-specific keys),
//! then the provider's documented environment variables, then a vault secret named
//! like one of them.

use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Looks a vault secret up by name (`None` when absent).
pub type SecretFn = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

#[derive(Clone)]
pub struct MediaConfig {
    pub table: toml::Table,
    pub secret: SecretFn,
}

impl Default for MediaConfig {
    fn default() -> Self {
        MediaConfig { table: toml::Table::new(), secret: Arc::new(|_| None) }
    }
}

impl std::fmt::Debug for MediaConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaConfig").field("table", &self.table).finish()
    }
}

/// Resolved connection details for one media provider.
#[derive(Debug, Clone, Default)]
pub struct Creds {
    pub id: String,
    pub key: Option<String>,
    pub base: String,
    pub headers: Vec<(String, String)>,
    /// The provider's whole `[media.providers.<id>]` table, for provider-specific keys.
    pub extra: toml::Table,
}

impl Creds {
    /// `base` + `path` with exactly one slash between them.
    pub fn url(&self, path: &str) -> String {
        if path.is_empty() {
            return self.base.clone();
        }
        format!("{}/{}", self.base.trim_end_matches('/'), path.trim_start_matches('/'))
    }
    pub fn key(&self) -> Result<&str, String> {
        self.key.as_deref().ok_or_else(|| format!("{}: no API key configured", self.id))
    }
    pub fn bearer(&self) -> Vec<(String, String)> {
        let mut h = self.headers.clone();
        if let Some(k) = &self.key {
            h.insert(0, ("authorization".into(), format!("Bearer {k}")));
        }
        h
    }
    /// Headers with the key under a custom header name (`xi-api-key`, `x-goog-api-key`…).
    pub fn header_key(&self, name: &str) -> Vec<(String, String)> {
        let mut h = self.headers.clone();
        if let Some(k) = &self.key {
            h.insert(0, (name.into(), k.clone()));
        }
        h
    }
    pub fn str(&self, k: &str) -> Option<String> {
        self.extra.get(k).and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_string)
    }
}

impl MediaConfig {
    pub fn new(table: toml::Table, secret: SecretFn) -> Self {
        MediaConfig { table, secret }
    }
    pub fn from_toml(s: &str) -> Self {
        MediaConfig { table: s.parse().unwrap_or_default(), secret: Arc::new(|_| None) }
    }

    /// Dotted lookup inside `[media]` (`"tts.provider"`).
    pub fn get(&self, path: &str) -> Option<&toml::Value> {
        let mut cur: Option<&toml::Value> = None;
        let mut table = &self.table;
        for (i, part) in path.split('.').enumerate() {
            let v = table.get(part)?;
            if i + 1 < path.split('.').count() {
                table = v.as_table()?;
            }
            cur = Some(v);
        }
        cur
    }
    pub fn str(&self, path: &str) -> Option<String> {
        self.get(path).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(|s| self.substitute(s))
    }
    pub fn str_or(&self, path: &str, default: &str) -> String {
        self.str(path).unwrap_or_else(|| default.to_string())
    }
    pub fn bool_or(&self, path: &str, default: bool) -> bool {
        self.get(path).and_then(|v| v.as_bool()).unwrap_or(default)
    }
    pub fn int_or(&self, path: &str, default: i64) -> i64 {
        self.get(path).and_then(|v| v.as_integer().or_else(|| v.as_float().map(|f| f as i64))).unwrap_or(default)
    }
    pub fn float_or(&self, path: &str, default: f64) -> f64 {
        self.get(path).and_then(|v| v.as_float().or_else(|| v.as_integer().map(|i| i as f64))).unwrap_or(default)
    }
    pub fn list(&self, path: &str) -> Vec<String> {
        match self.get(path) {
            Some(toml::Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
            Some(toml::Value::String(s)) if !s.trim().is_empty() => s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
            _ => vec![],
        }
    }
    pub fn table(&self, path: &str) -> toml::Table {
        self.get(path).and_then(|v| v.as_table()).cloned().unwrap_or_default()
    }

    /// `host[:port]` of every operator-configured endpoint: values of `url`/`base_url`/
    /// `endpoint`-style keys anywhere under `[media]` (a provider base, a pinned model
    /// download URL), plus environment overrides named `*BASE_URL*`/`*API_BASE*`.
    ///
    /// Providers are untrusted for the *URLs they return*, but the address the operator
    /// pointed ark at is a deliberate choice: a local ComfyUI or LiteLLM-style proxy on
    /// `127.0.0.1`/the LAN must keep working while arbitrary private result URLs stay refused.
    pub fn provider_hosts(&self) -> Vec<String> {
        fn walk(t: &toml::Table, out: &mut Vec<String>) {
            for (k, v) in t {
                match v {
                    toml::Value::String(s) if k.contains("url") || matches!(k.as_str(), "base" | "endpoint" | "api_base") => {
                        let h = crate::http::host_of(s.trim()).to_ascii_lowercase();
                        if !h.is_empty() {
                            out.push(h);
                        }
                    }
                    toml::Value::Table(sub) => walk(sub, out),
                    _ => {}
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.table, &mut out);
        for (k, v) in std::env::vars() {
            if k.contains("BASE_URL") || k.contains("API_BASE") {
                let h = crate::http::host_of(v.trim()).to_ascii_lowercase();
                if !h.is_empty() {
                    out.push(h);
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// Replace `{{secret:NAME}}` with the vault value.
    pub fn substitute(&self, s: &str) -> String {
        let mut out = String::new();
        let mut rest = s;
        while let Some(i) = rest.find("{{secret:") {
            out.push_str(&rest[..i]);
            let after = &rest[i + 9..];
            match after.find("}}") {
                Some(j) => {
                    let name = &after[..j];
                    out.push_str(&(self.secret)(name).unwrap_or_default());
                    rest = &after[j + 2..];
                }
                None => {
                    out.push_str(&rest[i..]);
                    rest = "";
                }
            }
        }
        out.push_str(rest);
        out
    }

    /// Credentials for media provider `id`: config, then `envs` in order, then the vault.
    pub fn creds(&self, id: &str, envs: &[&str], default_base: &str) -> Creds {
        let t = self.table(&format!("providers.{id}"));
        let s = |k: &str| t.get(k).and_then(|v| v.as_str()).map(|v| self.substitute(v.trim())).filter(|v| !v.is_empty());
        let mut key = s("api_key");
        let mut env_names: Vec<String> = s("api_key_env").into_iter().collect();
        env_names.extend(envs.iter().map(|e| e.to_string()));
        if key.is_none() {
            key = env_names.iter().find_map(|e| std::env::var(e).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty()));
        }
        if key.is_none() {
            key = env_names.iter().find_map(|e| (self.secret)(e).filter(|v| !v.is_empty()));
        }
        let base = s("base_url").unwrap_or_else(|| default_base.to_string());
        let headers = t.get("headers").and_then(|h| h.as_table()).map(|h| h.iter().filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), self.substitute(v)))).collect()).unwrap_or_default();
        Creds { id: id.into(), key, base, headers, extra: t }
    }

    /// Whether `id` has a key (or needs none: `envs` empty).
    pub fn configured(&self, id: &str, envs: &[&str]) -> bool {
        envs.is_empty() || self.creds(id, envs, "").key.is_some()
    }

    /// Where generated media is written (`[media] output_dir`, default `<workspace>/.ark/media`).
    pub fn output_dir(&self, workspace: &Path) -> PathBuf {
        match self.str("output_dir") {
            Some(d) => {
                let p = ark_core::tool::expand_home(&d);
                if p.is_absolute() {
                    p
                } else {
                    workspace.join(p)
                }
            }
            None => workspace.join(".ark").join("media"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_lookup_and_defaults() {
        let c = MediaConfig::from_toml("output_dir = \"out\"\n[tts]\nprovider = \"openai\"\nspeed = 1.5\n[vision]\nmax_history_images = 3\n");
        assert_eq!(c.str("tts.provider").as_deref(), Some("openai"));
        assert_eq!(c.str_or("tts.voice", "alloy"), "alloy");
        assert_eq!(c.float_or("tts.speed", 1.0), 1.5);
        assert_eq!(c.int_or("vision.max_history_images", 8), 3);
        assert_eq!(c.output_dir(Path::new("/w")), PathBuf::from("/w/out"));
        assert!(c.get("nope.x").is_none());
    }

    #[test]
    fn creds_order_config_env_vault() {
        let mut c = MediaConfig::from_toml("[providers.fal]\nbase_url = \"http://x/\"\n[providers.oa]\napi_key = \"{{secret:K}}\"\n");
        c.secret = Arc::new(|n| (n == "K" || n == "ARK_MEDIA_TEST_VAULT_ONLY").then(|| "v".to_string()));
        assert_eq!(c.creds("oa", &[], "").key.as_deref(), Some("v"));
        let f = c.creds("fal", &["ARK_MEDIA_TEST_VAULT_ONLY"], "https://fal.run");
        assert_eq!((f.key.as_deref(), f.url("/a")), (Some("v"), "http://x/a".to_string()));
        assert!(c.creds("none", &["ARK_MEDIA_TEST_UNSET_ENV"], "").key.is_none());
        assert!(c.configured("free", &[]));
    }
}
