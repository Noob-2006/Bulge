//! Provider resolution: built-in presets (and their aliases), overridden/extended by
//! `[providers.*]` in config. Credentials, in order: pooled keys and logins in the
//! credential store (`seagent auth` / `seagent login`), `api_keys`, then the single key from
//! `key_cmd`, config, the environment, or the secret vault (a secret named like the env
//! var). Several credentials make the provider a rotating pool.

use seagent_core::Provider;
use seagent_kernel::kernel::Resolver;
use seagent_kernel::vault::Vault;
use seagent_model::auth::{self, CredSource, Member, Pool, Stored};
use seagent_model::store::Store;
use seagent_model::{presets, ProviderConfig, WireFormat};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub type Labeled = (String, String, Arc<dyn CredSource>);

pub struct Providers {
    configs: BTreeMap<String, ProviderConfig>,
    vault: Arc<Vault>,
    store: Option<Store>,
    cache: Mutex<HashMap<String, Arc<dyn Provider>>>,
    /// Providers registered by plugins (`seagent/provider.complete`); they shadow presets.
    plugins: Mutex<BTreeMap<String, Arc<dyn Provider>>>,
    /// `SEAGENT_MODEL_REPLAY`: recorded exchanges per provider (a keyless test run).
    replay: BTreeMap<String, Arc<dyn Provider>>,
    /// `SEAGENT_MODEL_RECORD`: append every built provider's exchanges here.
    record_path: Option<PathBuf>,
}

impl Providers {
    pub fn new(overrides: &BTreeMap<String, toml::Table>, vault: Arc<Vault>) -> Result<Self, String> {
        let env = |k: &str| std::env::var_os(k).filter(|p| !p.is_empty()).map(PathBuf::from);
        Self::with_fixtures(overrides, vault, env(seagent_model::replay::REPLAY_ENV), env(seagent_model::replay::RECORD_ENV))
    }

    /// [`Providers::new`] with the `SEAGENT_MODEL_REPLAY` / `SEAGENT_MODEL_RECORD` paths given
    /// explicitly (tests pass them here instead of mutating the process environment).
    pub fn with_fixtures(overrides: &BTreeMap<String, toml::Table>, vault: Arc<Vault>, replay_path: Option<PathBuf>, record_path: Option<PathBuf>) -> Result<Self, String> {
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
            if overrides.get(id).is_some_and(|t| !t.contains_key("format")) && !configs.contains_key(id) {
                return Err(format!("[providers.{id}]: missing field `format` (openai_chat, openai_responses, anthropic, gemini, bedrock, cli, codex_app_server, moa)"));
            }
            let cfg: ProviderConfig = base.try_into().map_err(|e: toml::de::Error| format!("[providers.{id}]: {}", e.message()))?;
            configs.insert(id.clone(), cfg);
        }
        let mut replay: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        if let Some(path) = replay_path {
            let mut groups: BTreeMap<String, Vec<seagent_model::replay::Exchange>> = BTreeMap::new();
            for ex in seagent_model::replay::load(&path)? {
                groups.entry(ex.provider.clone()).or_default().push(ex);
            }
            for (id, entries) in groups {
                replay.insert(id.clone(), Arc::new(seagent_model::replay::ReplayProvider::from_exchanges(&id, entries)?));
            }
        }
        Ok(Providers { configs, vault, store: seagent_model::store::default_store(), cache: Mutex::new(HashMap::new()), plugins: Mutex::default(), replay, record_path })
    }

    /// Wrap a built provider when `SEAGENT_MODEL_RECORD` is set. A recording failure must not
    /// break the live call: it is reported once per build and the provider keeps working.
    fn maybe_record(&self, id: &str, p: Arc<dyn Provider>) -> Arc<dyn Provider> {
        let Some(path) = &self.record_path else { return p };
        match seagent_model::replay::Recorder::new(p.clone(), path, id) {
            Ok(r) => r as Arc<dyn Provider>,
            Err(e) => {
                eprintln!("seagent: model recording is off: {e}");
                p
            }
        }
    }

    /// Use this credential store (tests; the binary sets the process default).
    #[cfg(test)]
    pub fn with_store(mut self, s: Store) -> Self {
        self.store = Some(s);
        self
    }

    /// Resolve credentials as agent `agent`: its own profile store
    /// (`<config>/agents/<agent>/auth.json`) is tried before the shared pool
    /// (OpenClaw agent-local auth profiles). Selected by `$SEAGENT_AGENT` in the binary.
    pub fn agent(mut self, config_dir: &std::path::Path, agent: &str) -> Self {
        self.store = Some(Store::for_agent(config_dir, agent));
        self
    }

    pub fn configs(&self) -> &BTreeMap<String, ProviderConfig> {
        &self.configs
    }

    /// Canonical id for `id` or one of its aliases.
    pub fn canonical(&self, id: &str) -> Option<String> {
        if self.configs.contains_key(id) || self.plugins.lock().unwrap().contains_key(id) {
            return Some(id.to_string());
        }
        seagent_model::resolve_alias(id).filter(|c| self.configs.contains_key(c))
    }

    pub fn config(&self, id: &str) -> Option<&ProviderConfig> {
        self.canonical(id).and_then(|c| self.configs.get(&c))
    }

    /// Add a plugin's provider to the model registry under `id` (`id/model` in config).
    pub fn register(&self, id: &str, p: Arc<dyn Provider>) {
        self.plugins.lock().unwrap().insert(id.to_string(), p);
    }

    fn vault_key(&self, name: &str) -> Option<String> {
        let v = self.vault.substitute(&format!("{{{{secret:{name}}}}}"));
        (!v.starts_with("{{secret:")).then_some(v)
    }

    /// Every credential `cfg` can use, labelled (store entries first).
    pub fn credentials(&self, cfg: &ProviderConfig) -> Result<Vec<Labeled>, String> {
        let mut out: Vec<Labeled> = Vec::new();
        if let Some(s) = &self.store {
            for e in s.entries(&cfg.id) {
                let copilot = cfg.auth == "copilot";
                out.push((e.id.clone(), format!("{} `{}`", e.kind, e.label), Arc::new(Stored::new(s.clone(), &cfg.id, &e.id, copilot))));
            }
        }
        for (i, k) in cfg.api_keys.iter().enumerate() {
            out.push((format!("api_keys[{i}]"), format!("config key {}", seagent_model::store::mask(k)), Arc::new(auth::Static::new(Some(k.clone())))));
        }
        let single = ProviderConfig { api_keys: vec![], ..cfg.clone() };
        let vault = |n: &str| self.vault_key(n);
        match auth::source_for(&single, Some(&vault)) {
            Ok(src) => {
                // A keyless fallback adds nothing when real credentials exist.
                let empty = src.get().map(|c| c.token.is_none()).unwrap_or(false) && !matches!(cfg.auth.as_str(), "aws" | "none");
                if out.is_empty() || !empty {
                    out.push(("config".into(), src.describe(), src));
                }
            }
            Err(e) if out.is_empty() => return Err(e),
            Err(_) => {}
        }
        Ok(out)
    }

    /// A team's own key for `cfg` (ent-086): the secret (vault, else environment) named like the
    /// provider's key variable plus `__<TEAM>` — `OPENAI_API_KEY__ENG` for team `eng`. Feed it
    /// from any secret source (`seagent secrets vault set OPENAI_API_KEY__ENG seagent/teams/eng#openai`).
    pub fn team_key(&self, cfg: &ProviderConfig, team: &str) -> Option<String> {
        let suffix = seagent_core::team::secret_suffix(team);
        if suffix.is_empty() {
            return None;
        }
        cfg.key_env_names().iter().find_map(|n| {
            let name = format!("{n}__{suffix}");
            self.vault_key(&name).or_else(|| std::env::var(&name).ok()).filter(|v| !v.trim().is_empty())
        })
    }

    /// `(team, provider)` pairs that have their own key, for `seagent doctor` / `seagent auth`.
    pub fn team_keys(&self, teams: &[String]) -> Vec<(String, String)> {
        let mut v = vec![];
        for t in teams {
            for (id, cfg) in &self.configs {
                if self.team_key(cfg, t).is_some() {
                    v.push((t.clone(), id.clone()));
                }
            }
        }
        v
    }

    /// Where the key for a provider would come from (for `seagent doctor`).
    pub fn key_source(&self, id: &str) -> Result<&'static str, String> {
        let c = self.config(id).ok_or_else(|| format!("unknown provider `{id}`"))?;
        if self.store.as_ref().is_some_and(|s| !s.entries(&c.id).is_empty()) {
            return Ok("credential store");
        }
        if c.api_key.as_deref().is_some_and(|k| !k.is_empty()) || !c.api_keys.is_empty() {
            return Ok("config");
        }
        if c.key_cmd.is_some() {
            return Ok("key_cmd");
        }
        match c.auth.as_str() {
            "aws" => return Ok("AWS credentials"),
            "google" => return Ok("Google Cloud credentials"),
            "azure-ad" => return Ok("Entra ID"),
            _ => {}
        }
        let names = c.key_env_names();
        if names.is_empty() || c.keyless() {
            if c.oauth.is_some() && names.is_empty() {
                return Err(format!("not logged in: run `seagent login {}`", c.oauth.as_deref().unwrap_or(&c.id)));
            }
            return Ok("none needed");
        }
        if names.iter().any(|e| std::env::var(e).is_ok_and(|v| !v.is_empty())) {
            return Ok("environment");
        }
        if names.iter().any(|e| self.vault.names().contains(e)) {
            return Ok("vault");
        }
        if let Some(f) = &c.oauth {
            return Err(format!("no credentials: `seagent login {f}`, set {}, or `seagent auth add {}`", names[0], c.id));
        }
        Err(seagent_model::auth::missing_key_message(c))
    }

    /// Build with the auxiliary-health recorder wrapped around the adapter: a capacity failure
    /// (payment/quota, rate limit, connection, invalid response) benches the provider for the
    /// per-task ladders in `[auxiliary.<task>]` until its hold expires (`seagent_model::aux`).
    fn watched(&self, id: &str, p: Arc<dyn Provider>) -> Arc<dyn Provider> {
        Arc::new(seagent_model::aux::Watched { inner: p, provider: id.to_string() })
    }

    fn build(&self, cfg: &ProviderConfig) -> Result<Arc<dyn Provider>, String> {
        if cfg.format == WireFormat::Moa {
            let resolve = |pid: &str| self.provider(pid);
            return Ok(Arc::new(seagent_model::moa::Moa::new(cfg, &resolve)?));
        }
        if matches!(
            cfg.format,
            WireFormat::Cli
                | WireFormat::CodexAppServer
                | WireFormat::Acp
                | WireFormat::Muse
                | WireFormat::AgentsApi
        ) {
            return seagent_model::build(cfg).map(|p| self.watched(&cfg.id, p));
        }
        let idle = Duration::from_secs(cfg.idle_timeout_secs.unwrap_or(seagent_model::DEFAULT_IDLE_SECS).max(1));
        let creds = self.credentials(cfg)?;
        if creds.len() == 1 {
            let (_, _, c) = creds.into_iter().next().unwrap();
            let p = seagent_model::build_with(cfg, c, idle)?;
            return Ok(self.watched(&cfg.id, p));
        }
        let mut members = Vec::new();
        for (key, label, c) in creds {
            members.push(Member { key, label, provider: seagent_model::build_with(cfg, c, idle)? });
        }
        let strategy = cfg.pool_strategy.clone().or_else(|| self.store.as_ref().and_then(|s| s.strategy(&cfg.id))).unwrap_or_else(|| "fill_first".into());
        Ok(self.watched(&cfg.id, Arc::new(Pool::new(&cfg.id, members, &strategy, self.store.clone()))))
    }
}

impl Resolver for Providers {
    fn provider(&self, id: &str) -> Result<Arc<dyn Provider>, String> {
        if let Some(p) = self.plugins.lock().unwrap().get(id) {
            return Ok(p.clone());
        }
        // Recorded fixtures win over credentials: a replay test needs no key, no network.
        if let Some(p) = self.replay.get(id) {
            return Ok(p.clone());
        }
        if let Some(c) = seagent_model::resolve_alias(id) {
            if let Some(p) = self.replay.get(&c) {
                return Ok(p.clone());
            }
        }
        // ent-086: a team with its own key for this provider gets a provider built from it.
        if let Some(team) = seagent_core::team::current() {
            if let Some(cfg) = self.config(id).cloned() {
                if let Some(key) = self.team_key(&cfg, &team) {
                    let ck = format!("{id}@team:{team}");
                    if let Some(p) = self.cache.lock().unwrap().get(&ck) {
                        return Ok(p.clone());
                    }
                    let idle = Duration::from_secs(cfg.idle_timeout_secs.unwrap_or(seagent_model::DEFAULT_IDLE_SECS).max(1));
                    let p = self.watched(&cfg.id, seagent_model::build_with(&cfg, Arc::new(auth::Static::new(Some(key))), idle)?);
                    let p = self.maybe_record(&cfg.id, p);
                    self.cache.lock().unwrap().insert(ck, p.clone());
                    return Ok(p);
                }
            }
        }
        if let Some(p) = self.cache.lock().unwrap().get(id) {
            return Ok(p.clone());
        }
        let cfg = self.config(id).cloned().ok_or_else(|| format!("unknown provider `{id}` (see `seagent providers list`)"))?;
        let p = self.build(&cfg)?;
        let p = self.maybe_record(&cfg.id, p);
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
        let p = Providers::new(&BTreeMap::new(), v.clone()).unwrap().with_store(Store::new(seagent_core::tmp::scratch_path(format!("seagent-prov-none-{}/auth.json", std::process::id()))));
        // Use a provider whose env var is unlikely to be set in CI.
        std::env::remove_var("SILICONFLOW_API_KEY");
        assert!(p.key_source("siliconflow").is_err());
        assert!(p.provider("siliconflow").is_err(), "missing key is an error, not a silent anonymous call");
        v.set("SILICONFLOW_API_KEY", "sk-from-vault-123").unwrap();
        assert_eq!(p.key_source("siliconflow").unwrap(), "vault");
        assert!(p.provider("siliconflow").is_ok());
        assert_eq!(p.key_source("ollama").unwrap(), "none needed");
        assert!(p.key_source("openai-codex").unwrap_err().contains("seagent login"));
    }

    #[test]
    fn aliases_resolve_and_store_keys_make_a_pool() {
        let dir = seagent_core::tmp::scratch_path(format!("seagent-prov-{}", std::process::id()));
        let store = Store::new(dir.join("auth.json"));
        store.add("groq", seagent_model::store::Entry::new("api_key", "a", Some("gsk-1".into())), None).unwrap();
        store.add("groq", seagent_model::store::Entry::new("api_key", "b", Some("gsk-2".into())), None).unwrap();
        std::env::set_var("GROQ_API_KEY", "gsk-env");
        let p = Providers::new(&BTreeMap::new(), Arc::new(Vault::empty())).unwrap().with_store(store);
        assert_eq!(p.canonical("grok").as_deref(), Some("xai"));
        let creds = p.credentials(p.config("groq").unwrap()).unwrap();
        assert_eq!(creds.len(), 3, "two stored + env");
        assert_eq!(p.key_source("groq").unwrap(), "credential store");
        assert!(p.provider("groq").is_ok());
        assert!(p.provider("aws").is_ok(), "aliases build too");
    }

    #[test]
    fn an_agent_profile_store_shadows_the_shared_pool() {
        let root = seagent_core::tmp::scratch_path(format!("seagent-agentprof-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let shared = Store::shared(&root);
        shared
            .add("groq", seagent_model::store::Entry::new("api_key", "shared", Some("gsk-shared-1".into())), None)
            .unwrap();
        let agent = Store::for_agent(&root, "reviewer");
        assert!(agent.is_agent_scoped());
        let id = agent
            .add("groq", seagent_model::store::Entry::new("api_key", "reviewer", Some("gsk-reviewer-2".into())), None)
            .unwrap();
        // Agent-local first (priority 0), then the inherited shared key.
        let labels: Vec<String> = agent.entries("groq").iter().map(|e| e.label.clone()).collect();
        assert_eq!(labels, vec!["reviewer".to_string(), "shared".to_string()]);
        // The agent's own file is the only one written.
        assert!(root.join("agents/reviewer/auth.json").exists());
        assert_eq!(shared.entries("groq").len(), 1);
        assert_eq!(shared.entries("groq")[0].label, "shared");
        // The runtime's view (Providers) uses that order for the pool.
        let p = Providers::new(&BTreeMap::new(), Arc::new(Vault::empty()))
            .unwrap()
            .agent(&root, "reviewer");
        let creds = p.credentials(p.config("groq").unwrap()).unwrap();
        let labels: Vec<&str> = creds.iter().map(|(_, l, _)| l.as_str()).collect();
        assert!(labels[0].contains("reviewer"), "{labels:?}");
        assert!(labels.iter().any(|l| l.contains("shared")), "{labels:?}");
        // Removing from the agent store leaves the shared credential alone.
        agent.remove("groq", &id).unwrap();
        assert_eq!(agent.entries("groq").len(), 1);
        assert_eq!(shared.entries("groq").len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn moa_resolves_its_members() {
        let mut o = BTreeMap::new();
        o.insert("moa".to_string(), "references = [\"ollama/a\", \"lmstudio/b\"]\naggregator = \"vllm/c\"".parse::<toml::Table>().unwrap());
        let p = Providers::new(&o, Arc::new(Vault::empty())).unwrap();
        assert!(p.provider("moa").is_ok());
        let p = Providers::new(&BTreeMap::new(), Arc::new(Vault::empty())).unwrap();
        assert!(p.provider("moa").err().unwrap().contains("references"));
    }

    #[test]
    fn replay_fixture_serves_a_provider_without_a_key() {
        use seagent_core::{Block, Cancel, Message, ModelCaps, ModelRequest, ModelResponse, StopReason, StreamEvent, Usage};
        use std::ffi::OsString;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static ENV: Mutex<()> = Mutex::new(());
        struct EnvGuard(Vec<(String, Option<OsString>)>);
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                for (k, v) in &self.0 {
                    match v {
                        Some(v) => std::env::set_var(k, v),
                        None => std::env::remove_var(k),
                    }
                }
            }
        }
        struct P(AtomicUsize);
        impl Provider for P {
            fn id(&self) -> &str {
                "deepseek"
            }
            fn caps(&self, _: &str) -> ModelCaps {
                ModelCaps { context_window: 64_000, max_output: 4096, tools: true, vision: false, explicit_cache: false }
            }
            fn complete(&self, req: &ModelRequest, on: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, seagent_core::ProviderError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                on(StreamEvent::TextDelta("from fixture".into()));
                Ok(ModelResponse { message: Message { role: seagent_core::Role::Assistant, content: vec![Block::text("from fixture")] }, stop: StopReason::EndTurn, usage: Usage { input_tokens: 7, output_tokens: 2, ..Default::default() }, model: req.model.clone() })
            }
        }

        let _lock = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let root = seagent_core::tmp::TempDir::new("seagent-prov-replay");
        let fixture = root.join("run.jsonl");
        let old: Vec<(String, Option<OsString>)> = ["SEAGENT_HOME", "SEAGENT_MODEL_REPLAY", "SEAGENT_MODEL_RECORD"]
            .iter()
            .map(|k| ((*k).to_string(), std::env::var_os(k)))
            .collect();
        let _env = EnvGuard(old);
        std::env::set_var("SEAGENT_HOME", root.path());

        let req = ModelRequest { model: "deepseek-chat".into(), system: vec![], messages: vec![Message::user("hello")], tools: vec![], max_tokens: 50, ..Default::default() };
        let fake = Arc::new(P(AtomicUsize::new(0)));
        let rec = seagent_model::replay::Recorder::new(fake.clone(), &fixture, "deepseek").unwrap();
        rec.complete(&req, &mut |_| {}, &Cancel::new()).unwrap();
        drop(rec);
        assert_eq!(fake.0.load(Ordering::SeqCst), 1);

        let p = Providers::with_fixtures(&BTreeMap::new(), Arc::new(Vault::empty()), Some(fixture.clone()), None).unwrap();
        assert!(p.key_source("deepseek").is_err(), "a replay run needs no credentials");
        let provider = p.provider("deepseek").unwrap();
        let mut events = vec![];
        let r = provider.complete(&req, &mut |e| events.push(e), &Cancel::new()).unwrap();
        assert_eq!(r.message.text(), "from fixture");
        assert_eq!(r.usage.input_tokens, 7);
        assert_eq!(events, vec![seagent_core::StreamEvent::TextDelta("from fixture".into())]);
        assert_eq!(fake.0.load(Ordering::SeqCst), 1, "the inner provider is not called again");
    }

    #[test]
    fn record_env_wraps_a_built_provider_and_creates_the_fixture() {
        use std::ffi::OsString;

        static ENV: Mutex<()> = Mutex::new(());
        struct EnvGuard(Vec<(String, Option<OsString>)>);
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                for (k, v) in &self.0 {
                    match v {
                        Some(v) => std::env::set_var(k, v),
                        None => std::env::remove_var(k),
                    }
                }
            }
        }

        let _lock = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let root = seagent_core::tmp::TempDir::new("seagent-prov-record");
        let fixture = root.join("run.jsonl");
        let old: Vec<(String, Option<OsString>)> = ["SEAGENT_HOME", "SEAGENT_MODEL_REPLAY", "SEAGENT_MODEL_RECORD"]
            .iter()
            .map(|k| ((*k).to_string(), std::env::var_os(k)))
            .collect();
        let _env = EnvGuard(old);
        std::env::set_var("SEAGENT_HOME", root.path());
        let mut o = BTreeMap::new();
        o.insert("mybox".to_string(), "format = \"openai_chat\"\nbase_url = \"http://127.0.0.1:9/v1\"".parse::<toml::Table>().unwrap());
        let p = Providers::with_fixtures(&o, Arc::new(Vault::empty()), None, Some(fixture.clone())).unwrap();
        assert!(!fixture.exists(), "nothing is recorded until a provider is built");
        assert!(p.provider("mybox").is_ok());
        assert!(fixture.exists(), "building with SEAGENT_MODEL_RECORD creates the JSONL fixture");
    }

    /// ent-086: a session of team `eng` uses `OPENAI_API_KEY__ENG`, other sessions the shared key.
    #[test]
    fn team_scoped_keys_win_inside_the_team_scope() {
        let v = Vault::empty();
        v.set("GROQ_API_KEY", "gsk-shared").unwrap();
        v.set("GROQ_API_KEY__ENG_PLATFORM", "gsk-eng").unwrap();
        let tmp = seagent_core::tmp::TempDir::new("seagent-tmp-teamkeys");
        let p = Providers::new(&BTreeMap::new(), Arc::new(v)).unwrap().with_store(Store::new(tmp.path().join("auth.json")));
        let cfg = p.config("groq").unwrap().clone();
        assert_eq!(p.team_key(&cfg, "eng-platform").as_deref(), Some("gsk-eng"));
        assert_eq!(p.team_key(&cfg, "sales"), None);
        let shared = p.provider("groq").unwrap();
        let eng = {
            let _t = seagent_core::team::scope("eng-platform");
            p.provider("groq").unwrap()
        };
        let sales = {
            let _t = seagent_core::team::scope("sales");
            p.provider("groq").unwrap()
        };
        assert!(!Arc::ptr_eq(&shared, &eng), "the team gets its own provider");
        assert!(Arc::ptr_eq(&shared, &sales), "a team without keys uses the shared one");
        assert_eq!(p.team_keys(&["eng-platform".into(), "sales".into()]), vec![("eng-platform".to_string(), "groq".to_string())]);
    }
}
