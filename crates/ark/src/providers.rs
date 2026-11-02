//! Provider resolution: built-in presets, overridden/extended by `[providers.*]`
//! in config. API keys come from config, the environment, or the secret vault
//! (a secret named like the env var), in that order.

use ark_core::Provider;
use ark_kernel::kernel::Resolver;
use ark_kernel::vault::Vault;
use ark_model::{presets, ProviderConfig};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

pub struct Providers {
    configs: BTreeMap<String, ProviderConfig>,
    vault: Arc<Vault>,
    cache: Mutex<HashMap<String, Arc<dyn Provider>>>,
    /// Providers registered by plugins (`ark/provider.complete`); they shadow presets.
    plugins: Mutex<BTreeMap<String, Arc<dyn Provider>>>,
}

impl Providers {
    pub fn new(overrides: &BTreeMap<String, toml::Table>, vault: Arc<Vault>) -> Result<Self, String> {
        let mut configs: BTreeMap<String, ProviderConfig> = presets().into_iter().map(|p| (p.id.clone(), p)).collect();
        for (id, table) in overrides {
            let mut base = match configs.get(id) {
                Some(p) => toml::Value::try_from(p).map_err(|e| e.to_string())?,
                None => toml::Value::Table(toml::Table::new()),
            };
            if let toml::Value::Table(t) = &mut base {
                for (k, v) in table {
                    t.insert(k.clone(), v.clone());
                }
                t.insert("id".into(), toml::Value::String(id.clone()));
            }
            let cfg: ProviderConfig = base.try_into().map_err(|e: toml::de::Error| format!("[providers.{id}]: {}", e.message()))?;
            configs.insert(id.clone(), cfg);
        }
        Ok(Providers { configs, vault, cache: Mutex::new(HashMap::new()), plugins: Mutex::default() })
    }

    pub fn configs(&self) -> &BTreeMap<String, ProviderConfig> {
        &self.configs
    }

    /// Add a plugin's provider to the model registry under `id` (`id/model` in config).
    pub fn register(&self, id: &str, p: Arc<dyn Provider>) {
        self.plugins.lock().unwrap().insert(id.to_string(), p);
    }


    /// Where the key for a provider would come from (for `ark doctor`).
    pub fn key_source(&self, id: &str) -> Result<&'static str, String> {
        let c = self.configs.get(id).ok_or_else(|| format!("unknown provider `{id}`"))?;
        if c.api_key.as_deref().is_some_and(|k| !k.is_empty()) {
            return Ok("config");
        }
        let Some(env) = &c.api_key_env else { return Ok("none needed") };
        if std::env::var(env).is_ok_and(|v| !v.is_empty()) {
            return Ok("environment");
        }
        if self.vault.names().contains(env) {
            return Ok("vault");
        }
        Err(format!("no API key: run `ark setup`, set {env}, or `ark secrets set {env}`"))
    }
}

impl Resolver for Providers {
    fn provider(&self, id: &str) -> Result<Arc<dyn Provider>, String> {
        if let Some(p) = self.plugins.lock().unwrap().get(id) {
            return Ok(p.clone());
        }
        if let Some(p) = self.cache.lock().unwrap().get(id) {
            return Ok(p.clone());
        }
        let mut cfg = self.configs.get(id).cloned().ok_or_else(|| format!("unknown provider `{id}` (see `ark providers list`)"))?;
        if cfg.api_key.as_deref().is_none_or(|k| k.is_empty()) {
            if let Some(env) = &cfg.api_key_env {
                let from_env = std::env::var(env).ok().filter(|v| !v.is_empty());
                let from_vault = || {
                    let v = self.vault.substitute(&format!("{{{{secret:{env}}}}}"));
                    (!v.starts_with("{{secret:")).then_some(v)
                };
                cfg.api_key = from_env.or_else(from_vault);
            }
        }
        let p = ark_model::build(&cfg)?;
        self.cache.lock().unwrap().insert(id.to_string(), p.clone());
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overrides_extend_and_validate() {
        let mut o = BTreeMap::new();
        let t: toml::Table = "base_url = \"http://localhost:9999/v1\"".parse().unwrap();
        o.insert("ollama".to_string(), t);
        let t: toml::Table = "format = \"openai_chat\"\nbase_url = \"http://10.0.0.5:8000/v1\"".parse().unwrap();
        o.insert("mybox".to_string(), t);
        let p = Providers::new(&o, Arc::new(Vault::empty())).unwrap();
        assert_eq!(p.configs()["ollama"].base_url, "http://localhost:9999/v1");
        assert!(p.provider("mybox").is_ok(), "no key needed when no env var configured");
        assert!(p.provider("nope").err().unwrap().contains("unknown provider"));

        let mut bad = BTreeMap::new();
        bad.insert("x".to_string(), "base_url = \"http://a\"".parse::<toml::Table>().unwrap());
        assert!(Providers::new(&bad, Arc::new(Vault::empty())).err().unwrap().contains("format"));
        let mut bad = BTreeMap::new();
        bad.insert("x".to_string(), "format = \"telepathy\"\nbase_url=\"http://a\"".parse::<toml::Table>().unwrap());
        assert!(Providers::new(&bad, Arc::new(Vault::empty())).is_err());
    }

    #[test]
    fn key_resolution_order() {
        let v = Arc::new(Vault::empty());
        let p = Providers::new(&BTreeMap::new(), v.clone()).unwrap();
        // Use a provider whose env var is unlikely to be set in CI.
        std::env::remove_var("SILICONFLOW_API_KEY");
        assert!(p.key_source("siliconflow").is_err());
        assert!(p.provider("siliconflow").is_err(), "missing key is an error, not a silent anonymous call");
        v.set("SILICONFLOW_API_KEY", "sk-from-vault-123").unwrap();
        assert_eq!(p.key_source("siliconflow").unwrap(), "vault");
        assert!(p.provider("siliconflow").is_ok());
        assert_eq!(p.key_source("ollama").unwrap(), "none needed");
    }
}
