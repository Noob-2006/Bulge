//! Provider API keys and live model lists for the web console: the "API keys" page (`ui.keys.*`:
//! list masked, add / replace, delete, test) and the model pickers of the chat composer and the
//! conversation settings (`ui.chat.models.list`).
//!
//! Keys only ever go to the secret vault (`seagent_kernel::vault`, encrypted at rest whenever a
//! key source exists) under the name the provider config reads (`api_key_env` / `key_envs`) — the
//! same place `seagent secrets set` and the runtime use. A provider whose config names no key
//! variable gets `api_key_env = "<ID>_API_KEY"` (a name, never the value) written to its config
//! table; a plaintext `api_key` left in the config from earlier is removed when a vault key
//! replaces it. Values never leave the daemon: listings show `••••` plus the last four
//! characters, and the write goes through the daemon's own vault, so the next model request
//! uses the new key without a restart (`Providers` drops its cache on a vault change).
//!
//! Model lists come from each provider's own listing endpoint
//! ([`seagent_model::list_models_live`]: OpenAI-compatible `GET /models`, Anthropic
//! `/v1/models`, Gemini `models`, Ollama `/api/tags`, OpenRouter …), cached in
//! `<data>/models-live.json` for [`TTL_MS`] and refreshed on demand. Offline, without a key, or
//! when the endpoint fails, the built-in list stands in: the provider's configured ids, the
//! model refs the config names, and the models.dev snapshot.

use crate::providers::Providers;
use seagent_kernel::config::{project_config, Config, Paths};
use seagent_kernel::daemon::MethodExt;
use seagent_kernel::event::now_ms;
use seagent_kernel::kernel::Kernel;
use seagent_kernel::vault::Vault;
use seagent_model::auth::CredSource;
use seagent_model::ProviderConfig;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const METHODS: &[&str] = &["ui.keys.list", "ui.keys.set", "ui.keys.delete", "ui.keys.test", "ui.chat.models.list"];

/// A live listing is reused this long before the next picker opening fetches it again.
pub const TTL_MS: u64 = 6 * 3600 * 1000;
/// Most models one provider contributes to a picker (OpenRouter lists hundreds).
const MAX_MODELS: usize = 400;

type Res = Result<Value, (i32, String)>;

fn bad(e: impl Into<String>) -> (i32, String) {
    (-32602, e.into())
}
fn fail(e: impl Into<String>) -> (i32, String) {
    (-32000, e.into())
}

pub struct KeyCtx {
    pub paths: Paths,
    pub k: Kernel,
    /// Workspace whose `.seagent/config.toml` layers over the user config.
    pub ws: PathBuf,
}

pub fn methods(paths: &Paths, k: Kernel) -> MethodExt {
    let ws = k.cfg.app.get("workspace").and_then(|v| v.as_str()).map(PathBuf::from).or_else(|| std::env::current_dir().ok()).unwrap_or_else(|| PathBuf::from("."));
    let c = Arc::new(KeyCtx { paths: paths.clone(), k, ws });
    Arc::new(move |m: &str, p: &Value| call(&c, m, p))
}

pub fn call(c: &KeyCtx, m: &str, p: &Value) -> Option<Res> {
    let provider = p["provider"].as_str().unwrap_or("").trim();
    Some(match m {
        "ui.keys.list" => keys_list(c),
        "ui.keys.set" => set_key(c, provider, p["key"].as_str().unwrap_or("")),
        "ui.keys.delete" => delete_key(c, provider),
        "ui.keys.test" => test_key(c, provider, p["key"].as_str().map(str::trim).filter(|k| !k.is_empty())),
        "ui.chat.models.list" => models_list(c, Some(provider).filter(|p| !p.is_empty()), p["refresh"].as_bool().unwrap_or(false)),
        _ => return None,
    })
}

/// The config as it is on disk now (the daemon's copy can be stale after a settings change).
fn fresh(c: &KeyCtx) -> Result<Config, (i32, String)> {
    Config::load(Some(&c.paths.user_config()), Some(&project_config(&c.ws)), &[]).map_err(fail)
}

/// The vault as it is on disk now. Writes go through a fresh handle (it merges with what other
/// processes stored since the daemon started); the daemon's own vault then adopts the result.
fn disk_vault(c: &KeyCtx) -> Result<Arc<Vault>, (i32, String)> {
    Vault::load(&c.paths.secrets()).map(Arc::new).map_err(fail)
}

fn sync_daemon_vault(c: &KeyCtx) -> Result<(), (i32, String)> {
    c.k.vault.adopt(Vault::load(&c.paths.secrets()).map_err(fail)?).map_err(fail)
}

fn providers(cfg: &Config, vault: &Arc<Vault>) -> Result<Providers, (i32, String)> {
    Providers::new(&cfg.providers, vault.clone()).map_err(fail)
}

fn canonical(ps: &Providers, provider: &str) -> Result<ProviderConfig, (i32, String)> {
    if provider.is_empty() {
        return Err(bad("missing param `provider`"));
    }
    let id = ps.canonical(provider).ok_or_else(|| bad(format!("unknown provider `{provider}`")))?;
    ps.config(&id).cloned().ok_or_else(|| bad(format!("unknown provider `{provider}`")))
}

/// `••••` plus the last four characters; short values show nothing of themselves.
pub fn mask(v: &str) -> String {
    let n = v.chars().count();
    if n < 12 {
        return "••••".into();
    }
    format!("••••{}", v.chars().skip(n - 4).collect::<String>())
}

/// The vault name a provider's key lives under: its config's first key variable, or the one
/// [`set_key`] gives a provider that names none.
fn key_name(pc: &ProviderConfig) -> String {
    pc.key_env_names().into_iter().next().unwrap_or_else(|| derived_name(&pc.id))
}

fn derived_name(id: &str) -> String {
    let base: String = id.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' }).collect();
    format!("{base}_API_KEY")
}

fn vault_value(vault: &Vault, name: &str) -> Option<String> {
    let v = vault.substitute(&format!("{{{{secret:{name}}}}}"));
    (!v.starts_with("{{secret:") && !v.is_empty()).then_some(v)
}

fn preset_meta(id: &str) -> (String, String) {
    seagent_model::catalog::catalog().into_iter().find(|p| p.cfg.id == id).map(|p| (p.name.to_string(), p.signup.to_string())).unwrap_or_else(|| (id.to_string(), String::new()))
}

/// Where the key the runtime would use comes from, and its masked form when we can see it.
fn key_state(vault: &Vault, ps: &Providers, pc: &ProviderConfig) -> Value {
    let names = pc.key_env_names();
    let name = key_name(pc);
    let env = names.iter().find_map(|n| std::env::var(n).ok().filter(|v| !v.is_empty()).map(|v| (n.clone(), v)));
    let vault = vault_value(vault, &name);
    let plaintext = pc.api_key.as_deref().filter(|k| !k.is_empty());
    let (source, masked) = match ps.key_source(&pc.id) {
        Ok("config") => ("config", plaintext.map(mask)),
        Ok("environment") => ("env", env.as_ref().map(|(_, v)| mask(v))),
        Ok("vault") => ("vault", vault.as_deref().map(mask)),
        Ok("credential store") => ("credential store", None),
        Ok("key_cmd") => ("key_cmd", None),
        Ok("none needed") => ("none", None),
        Ok(_) => ("cloud", None),
        Err(_) => ("missing", None),
    };
    json!({
        "name": name,
        "source": source,
        "masked": masked,
        "in_vault": vault.is_some(),
        // The environment wins over the vault (`auth::source_for`): say so before a replace.
        "env_override": env.map(|(n, _)| n),
        "plaintext_in_config": plaintext.is_some(),
    })
}

fn keys_list(c: &KeyCtx) -> Res {
    let cfg = fresh(c)?;
    let vault = disk_vault(c)?;
    let ps = providers(&cfg, &vault)?;
    let cache = load_cache(&cache_path(c));
    let rows: Vec<Value> = ps
        .configs()
        .iter()
        // Agent CLIs and `auth = "none"` servers have no key to manage.
        .filter(|(_, pc)| !(pc.keyless() && pc.key_env_names().is_empty()) && pc.auth != "none")
        .map(|(id, pc)| {
            let (label, signup) = preset_meta(id);
            let mut st = key_state(&vault, &ps, pc);
            st["id"] = json!(id);
            st["label"] = json!(label);
            st["signup"] = json!(signup);
            st["configured"] = json!(cfg.providers.contains_key(id));
            st["optional"] = json!(pc.keyless());
            st["models_cached"] = json!(cache.get(id).map(|e| e.models.len()).unwrap_or(0));
            st["checked_ms"] = json!(cache.get(id).map(|e| e.fetched_ms));
            st
        })
        .collect();
    Ok(json!({"providers": rows, "vault": vault.backend().as_str()}))
}

fn conf_unset_lenient(paths: &Paths, key: &str) -> Result<(), (i32, String)> {
    match crate::ops::confcli::unset(paths, key) {
        Ok(_) => Ok(()),
        Err(e) if e.contains("is not set") || e.contains("not found") => Ok(()),
        Err(e) => Err(fail(e)),
    }
}

/// Add or replace a provider's key (vault only). Also what `ui.models.key` calls.
pub fn set_key_for(paths: &Paths, k: &Kernel, ws: &Path, provider: &str, key: &str) -> Res {
    set_key(&KeyCtx { paths: paths.clone(), k: k.clone(), ws: ws.to_path_buf() }, provider, key)
}

/// Remove a provider's key from the vault (and a plaintext config key). Also `ui.models.key ""`.
pub fn delete_key_for(paths: &Paths, k: &Kernel, ws: &Path, provider: &str) -> Res {
    delete_key(&KeyCtx { paths: paths.clone(), k: k.clone(), ws: ws.to_path_buf() }, provider)
}

fn set_key(c: &KeyCtx, provider: &str, key: &str) -> Res {
    let key = key.trim();
    if key.is_empty() {
        return Err(bad("the key is empty (use ui.keys.delete to remove one)"));
    }
    if key.len() > 8192 || key.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return Err(bad("that does not look like an API key (spaces, line breaks or over 8 KiB)"));
    }
    let cfg = fresh(c)?;
    let vault = disk_vault(c)?;
    let ps = providers(&cfg, &vault)?;
    let pc = canonical(&ps, provider)?;
    if pc.auth == "none" {
        return Err(bad(format!("provider `{}` takes no key", pc.id)));
    }
    let name = key_name(&pc);
    if pc.key_env_names().is_empty() {
        // Point the config at the vault name; the value itself never goes there.
        crate::ops::confcli::set(&c.paths, &format!("providers.{}.api_key_env", pc.id), &format!("{name:?}")).map_err(fail)?;
    }
    vault.set(&name, key).map_err(fail)?;
    sync_daemon_vault(c)?;
    // A plaintext key in the config would keep winning over the vault: move it out.
    let migrated = cfg.providers.get(&pc.id).is_some_and(|t| t.contains_key("api_key"));
    if migrated {
        conf_unset_lenient(&c.paths, &format!("providers.{}.api_key", pc.id))?;
    }
    forget_cache(c, &pc.id);
    let env = pc.key_env_names().into_iter().find(|n| std::env::var(n).is_ok_and(|v| !v.is_empty()));
    Ok(json!({"ok": true, "provider": pc.id, "source": "vault", "name": name, "masked": mask(key), "removed_plaintext": migrated, "env_override": env}))
}

fn delete_key(c: &KeyCtx, provider: &str) -> Res {
    let cfg = fresh(c)?;
    let vault = disk_vault(c)?;
    let ps = providers(&cfg, &vault)?;
    let pc = canonical(&ps, provider)?;
    let mut names = pc.key_env_names();
    names.push(derived_name(&pc.id));
    let mut removed = false;
    for n in names {
        removed |= vault.remove(&n).map_err(fail)?;
    }
    sync_daemon_vault(c)?;
    if cfg.providers.get(&pc.id).is_some_and(|t| t.contains_key("api_key")) {
        conf_unset_lenient(&c.paths, &format!("providers.{}.api_key", pc.id))?;
        removed = true;
    }
    forget_cache(c, &pc.id);
    Ok(json!({"removed": removed, "provider": pc.id, "name": key_name(&pc)}))
}

/// The credential a listing uses: the key being tested, else what the runtime would use.
fn cred_for(ps: &Providers, pc: &ProviderConfig, key: Option<&str>) -> Result<Arc<dyn CredSource>, String> {
    if let Some(k) = key {
        return Ok(Arc::new(seagent_model::auth::Static::new(Some(k.to_string()))));
    }
    ps.credentials(pc)?.into_iter().next().map(|(_, _, s)| s).ok_or_else(|| ps.key_source(&pc.id).err().unwrap_or_else(|| "no credentials".into()))
}

/// One live listing call: a key that works answers with its models; a rejected one with the
/// provider's own error (401 / 403 …). A tested stored key also refreshes the cache.
fn test_key(c: &KeyCtx, provider: &str, key: Option<&str>) -> Res {
    let cfg = fresh(c)?;
    let vault = disk_vault(c)?;
    let ps = providers(&cfg, &vault)?;
    let pc = canonical(&ps, provider)?;
    let started = std::time::Instant::now();
    let r = cred_for(&ps, &pc, key).and_then(|cred| seagent_model::list_models_live(&pc, &*cred));
    let ms = started.elapsed().as_millis() as u64;
    Ok(match r {
        Ok(models) => {
            if key.is_none() && !models.is_empty() {
                store_cache(c, &pc.id, &models);
            }
            json!({"ok": true, "provider": pc.id, "models": models.len(), "sample": models.iter().take(5).collect::<Vec<_>>(), "ms": ms})
        }
        Err(e) => json!({"ok": false, "provider": pc.id, "error": short(&vault.redact(&e)), "ms": ms}),
    })
}

// ───────────────────────── live model lists ─────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct Cached {
    models: Vec<String>,
    fetched_ms: u64,
}

static CACHE_LOCK: Mutex<()> = Mutex::new(());

fn cache_path(c: &KeyCtx) -> PathBuf {
    c.paths.data.join("models-live.json")
}

fn load_cache(path: &Path) -> BTreeMap<String, Cached> {
    std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn edit_cache(c: &KeyCtx, f: impl FnOnce(&mut BTreeMap<String, Cached>)) {
    let _g = CACHE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = cache_path(c);
    let mut all = load_cache(&path);
    f(&mut all);
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let tmp = path.with_extension(format!("json.tmp{}", std::process::id()));
    if std::fs::write(&tmp, serde_json::to_vec(&all).unwrap_or_default()).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

fn store_cache(c: &KeyCtx, id: &str, models: &[String]) {
    edit_cache(c, |all| {
        all.insert(id.to_string(), Cached { models: models.to_vec(), fetched_ms: now_ms() });
    });
}

fn forget_cache(c: &KeyCtx, id: &str) {
    edit_cache(c, |all| {
        all.remove(id);
    });
}

/// Providers a picker offers: those holding a key (vault, environment, config, credential
/// store, key_cmd), plus any the config sets up or names in a model ref. Cloud credential chains
/// (gcloud / az / AWS metadata) and local servers nobody configured are not probed: opening a
/// picker must not run a CLI or wait on a metadata endpoint for a provider nobody uses.
fn picker_providers<'a>(cfg: &Config, ps: &'a Providers) -> Vec<&'a ProviderConfig> {
    let mut named: Vec<String> = vec![cfg.model.default.clone()];
    named.extend(cfg.model.fallback.iter().cloned());
    named.extend(cfg.model.aliases.values().cloned());
    let named: Vec<String> = named.iter().filter_map(|m| cfg.resolve_model(m).split_once('/').map(|(p, _)| p.to_string())).filter_map(|p| ps.canonical(&p)).collect();
    ps.configs()
        .values()
        .filter(|pc| {
            let keyed = matches!(ps.key_source(&pc.id), Ok("vault" | "environment" | "config" | "credential store" | "key_cmd"));
            keyed || cfg.providers.contains_key(&pc.id) || named.contains(&pc.id)
        })
        .collect()
}

/// The offline list: configured ids, config refs for this provider, then models.dev.
fn builtin(cfg: &Config, pc: &ProviderConfig) -> Vec<String> {
    let mut out: Vec<String> = pc.models.clone();
    let mut refs: Vec<String> = vec![cfg.model.default.clone()];
    refs.extend(cfg.model.fallback.iter().cloned());
    refs.extend(cfg.model.aliases.values().cloned());
    for r in refs {
        if let Some((p, m)) = cfg.resolve_model(&r).split_once('/') {
            if p == pc.id && !out.iter().any(|x| x == m) {
                out.push(m.to_string());
            }
        }
    }
    for i in seagent_model::modelsdb::models_of(&pc.id) {
        if i.tool_call && !out.contains(&i.id) {
            out.push(i.id);
        }
    }
    out
}

/// One line of at most 160 characters (provider errors can carry a whole CLI transcript).
fn short(e: &str) -> String {
    let line = e.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.chars().count() > 160 {
        format!("{}…", line.chars().take(159).collect::<String>())
    } else {
        line
    }
}

fn model_rows(pid: &str, models: &[String]) -> Vec<Value> {
    models
        .iter()
        .take(MAX_MODELS)
        .map(|m| {
            let ctx = seagent_model::modelsdb::registry_entry(Some(pid), m).map(|i| i.context).filter(|c| *c > 0);
            json!({"id": m, "ref": format!("{pid}/{m}"), "context": ctx})
        })
        .collect()
}

/// `ui.chat.models.list {provider?, refresh?}`: per provider, its live models (fresh, cached or
/// fetched now) or the built-in list with the reason. Fetches run in parallel.
fn models_list(c: &KeyCtx, only: Option<&str>, refresh: bool) -> Res {
    let cfg = fresh(c)?;
    let vault = disk_vault(c)?;
    let ps = providers(&cfg, &vault)?;
    let mut list = picker_providers(&cfg, &ps);
    if let Some(o) = only {
        let want = canonical(&ps, o)?.id;
        list.retain(|pc| pc.id == want);
    }
    let cache = load_cache(&cache_path(c));
    let now = now_ms();
    let offline = seagent_net::http::current().offline;
    let fetched: Vec<(String, Result<Vec<String>, String>)> = std::thread::scope(|s| {
        let jobs: Vec<_> = list
            .iter()
            .filter(|pc| refresh || cache.get(&pc.id).is_none_or(|e| now.saturating_sub(e.fetched_ms) > TTL_MS))
            .map(|pc| {
                let ps = &ps;
                s.spawn(move || {
                    let r = if offline { Err("offline mode: showing the built-in list".to_string()) } else { cred_for(ps, pc, None).and_then(|cred| seagent_model::list_models_live(pc, &*cred)) };
                    (pc.id.clone(), r)
                })
            })
            .collect();
        jobs.into_iter().filter_map(|j| j.join().ok()).collect()
    });
    let mut fresh_ok: Vec<(String, Vec<String>)> = vec![];
    let mut errors: BTreeMap<String, String> = BTreeMap::new();
    for (id, r) in fetched {
        match r {
            Ok(m) if !m.is_empty() => fresh_ok.push((id, m)),
            Ok(_) => {
                errors.insert(id, "the provider listed no models".into());
            }
            Err(e) => {
                errors.insert(id, short(&vault.redact(&e)));
            }
        }
    }
    if !fresh_ok.is_empty() {
        edit_cache(c, |all| {
            for (id, m) in &fresh_ok {
                all.insert(id.clone(), Cached { models: m.clone(), fetched_ms: now });
            }
        });
    }
    let cache = load_cache(&cache_path(c));
    let rows: Vec<Value> = list
        .iter()
        .map(|pc| {
            let (label, _) = preset_meta(&pc.id);
            let live = fresh_ok.iter().find(|(id, _)| *id == pc.id);
            let (source, models, at) = match (live, cache.get(&pc.id)) {
                (Some((_, m)), _) => ("live", m.clone(), Some(now)),
                (None, Some(e)) if !e.models.is_empty() => ("cache", e.models.clone(), Some(e.fetched_ms)),
                _ => ("builtin", builtin(&cfg, pc), None),
            };
            json!({"id": pc.id, "label": label, "source": source, "fetched_ms": at, "error": errors.get(&pc.id), "models": model_rows(&pc.id, &models)})
        })
        .collect();
    Ok(json!({"default": cfg.model.default, "providers": rows, "offline": offline}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{kit, Kit};
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    const ENV: &str = "SEAGENT_KEYS_TEST_PROBE_KEY";

    /// A fake OpenAI-compatible provider: `/v1/models` answers for `Bearer sk-live-good-0001`
    /// only (401 otherwise); counts the listing calls.
    fn fake_provider() -> (String, Arc<Mutex<usize>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/v1", l.local_addr().unwrap());
        let hits = Arc::new(Mutex::new(0usize));
        let h = hits.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                let _ = r.read_line(&mut line);
                let mut auth = String::new();
                loop {
                    let mut x = String::new();
                    if r.read_line(&mut x).is_err() || x.trim().is_empty() {
                        break;
                    }
                    if let Some(v) = x.to_lowercase().strip_prefix("authorization:") {
                        auth = v.trim().to_string();
                    }
                }
                *h.lock().unwrap() += 1;
                let (code, body) = if line.contains("/v1/models") && auth == "bearer sk-live-good-0001" { (200, r#"{"data":[{"id":"probe-live-a"},{"id":"probe-live-b"}]}"#) } else { (401, r#"{"error":{"message":"invalid api key"}}"#) };
                let _ = write!(s, "HTTP/1.1 {code} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
            }
        });
        (base, hits)
    }

    fn setup(base: &str, extra: &str) -> (Kit, KeyCtx) {
        let t = kit();
        std::fs::write(t.paths.user_config(), format!("[model]\ndefault = \"probe/probe-config\"\n[providers.probe]\nformat = \"openai_chat\"\nbase_url = \"{base}\"\nmodels = [\"probe-config\"]\n{extra}")).unwrap();
        let c = KeyCtx { paths: t.paths.clone(), k: t.k.clone(), ws: t.ws.clone() };
        (t, c)
    }
    fn ok(c: &KeyCtx, m: &str, p: Value) -> Value {
        call(c, m, &p).unwrap_or_else(|| panic!("{m} not handled")).unwrap_or_else(|e| panic!("{m}: {e:?}"))
    }
    fn row<'a>(v: &'a Value, id: &str) -> &'a Value {
        v["providers"].as_array().unwrap().iter().find(|p| p["id"] == id).unwrap_or_else(|| panic!("{id} not listed: {v}"))
    }

    #[test]
    fn keys_go_to_the_vault_masked_and_never_to_the_config() {
        let (base, _) = fake_provider();
        let (t, c) = setup(&base, &format!("api_key_env = \"{ENV}\"\n"));
        let r = ok(&c, "ui.keys.set", json!({"provider": "probe", "key": "sk-live-good-0001"}));
        assert_eq!((r["source"].as_str(), r["name"].as_str(), r["masked"].as_str()), (Some("vault"), Some(ENV), Some("••••0001")));
        assert_eq!(t.k.vault.substitute(&format!("{{{{secret:{ENV}}}}}")), "sk-live-good-0001", "the daemon's own vault sees it at once");
        let conf = std::fs::read_to_string(t.paths.user_config()).unwrap();
        assert!(!conf.contains("sk-live-good"), "the value never reaches the config: {conf}");
        let l = ok(&c, "ui.keys.list", json!({}));
        assert!(!l.to_string().contains("sk-live-good-0001"), "no listing carries the value");
        let p = row(&l, "probe");
        assert_eq!((p["source"].as_str(), p["masked"].as_str(), p["in_vault"].as_bool()), (Some("vault"), Some("••••0001"), Some(true)));
        // Replace, then delete.
        ok(&c, "ui.keys.set", json!({"provider": "probe", "key": "sk-live-other-9999"}));
        assert_eq!(row(&ok(&c, "ui.keys.list", json!({})), "probe")["masked"], "••••9999");
        assert_eq!(ok(&c, "ui.keys.delete", json!({"provider": "probe"}))["removed"], true);
        assert_eq!(row(&ok(&c, "ui.keys.list", json!({})), "probe")["source"], "missing");
        for bad_key in ["", "two words", "line\nbreak"] {
            assert!(call(&c, "ui.keys.set", &json!({"provider": "probe", "key": bad_key})).unwrap().is_err(), "{bad_key:?}");
        }
        assert!(call(&c, "ui.keys.set", &json!({"provider": "nosuch", "key": "k-1234567890"})).unwrap().unwrap_err().1.contains("unknown provider"));
    }

    #[test]
    fn a_plaintext_config_key_moves_to_the_vault_and_unnamed_providers_get_a_name() {
        let (base, _) = fake_provider();
        let (t, c) = setup(&base, "api_key = \"sk-plain-in-config-0000\"\n");
        assert_eq!(row(&ok(&c, "ui.keys.list", json!({})), "probe")["plaintext_in_config"], true);
        let r = ok(&c, "ui.keys.set", json!({"provider": "probe", "key": "sk-live-good-0001"}));
        assert_eq!((r["name"].as_str(), r["removed_plaintext"].as_bool()), (Some("PROBE_API_KEY"), Some(true)));
        let conf = std::fs::read_to_string(t.paths.user_config()).unwrap();
        assert!(!conf.contains("sk-plain-in-config") && !conf.contains("sk-live-good"), "{conf}");
        assert!(conf.contains("api_key_env = \"PROBE_API_KEY\""), "{conf}");
        let cfg = fresh(&c).unwrap();
        let ps = providers(&cfg, &disk_vault(&c).unwrap()).unwrap();
        assert_eq!(ps.key_source("probe").unwrap(), "vault", "the runtime now reads it from the vault");
    }

    #[test]
    fn test_reports_working_and_rejected_keys() {
        let (base, _) = fake_provider();
        let (_t, c) = setup(&base, &format!("api_key_env = \"{ENV}\"\n"));
        let good = ok(&c, "ui.keys.test", json!({"provider": "probe", "key": "sk-live-good-0001"}));
        assert_eq!((good["ok"].as_bool(), good["models"].as_u64()), (Some(true), Some(2)));
        let badk = ok(&c, "ui.keys.test", json!({"provider": "probe", "key": "sk-wrong-key-0002"}));
        assert_eq!(badk["ok"], false);
        assert!(badk["error"].as_str().unwrap().contains("401"), "{badk}");
        // No key given and none stored: a clear error, not a panic.
        let none = ok(&c, "ui.keys.test", json!({"provider": "probe"}));
        assert_eq!(none["ok"], false);
        // The stored key is what a key-less test uses.
        ok(&c, "ui.keys.set", json!({"provider": "probe", "key": "sk-live-good-0001"}));
        assert_eq!(ok(&c, "ui.keys.test", json!({"provider": "probe"}))["ok"], true);
    }

    #[test]
    fn model_lists_are_live_cached_refreshed_and_fall_back_offline() {
        let (base, hits) = fake_provider();
        let (_t, c) = setup(&base, &format!("api_key_env = \"{ENV}\"\n"));
        // No key: the endpoint refuses, the built-in list (configured ids) stands in.
        let l = ok(&c, "ui.chat.models.list", json!({"provider": "probe"}));
        let p = row(&l, "probe");
        assert_eq!(p["source"], "builtin");
        assert!(p["error"].as_str().is_some_and(|e| !e.is_empty()));
        assert_eq!(p["models"][0]["ref"], "probe/probe-config");
        ok(&c, "ui.keys.set", json!({"provider": "probe", "key": "sk-live-good-0001"}));
        // (Always filtered: an unfiltered list would also probe any provider whose key happens to
        // be in this machine's environment.)
        let l = ok(&c, "ui.chat.models.list", json!({"provider": "probe"}));
        let p = row(&l, "probe");
        assert_eq!(p["source"], "live");
        let ids: Vec<&str> = p["models"].as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["probe-live-a", "probe-live-b"]);
        // Second call inside the TTL: served from the cache, no request.
        let before = *hits.lock().unwrap();
        assert_eq!(row(&ok(&c, "ui.chat.models.list", json!({"provider": "probe"})), "probe")["source"], "cache");
        assert_eq!(*hits.lock().unwrap(), before, "the cache answered");
        // The refresh button fetches again.
        assert_eq!(row(&ok(&c, "ui.chat.models.list", json!({"provider": "probe", "refresh": true})), "probe")["source"], "live");
        assert_eq!(*hits.lock().unwrap(), before + 1);
        // The server goes away: a refresh keeps the cached list and reports why.
        let dead = KeyCtx { paths: c.paths.clone(), k: c.k.clone(), ws: c.ws.clone() };
        std::fs::write(dead.paths.user_config(), format!("[model]\ndefault = \"probe/probe-config\"\n[providers.probe]\nformat = \"openai_chat\"\nbase_url = \"http://127.0.0.1:9/v1\"\napi_key_env = \"{ENV}\"\nmodels = [\"probe-config\"]\n")).unwrap();
        let p = ok(&dead, "ui.chat.models.list", json!({"provider": "probe", "refresh": true}));
        let p = row(&p, "probe");
        assert_eq!(p["source"], "cache");
        assert!(p["error"].is_string());
        // A replaced key drops the cached list.
        ok(&dead, "ui.keys.set", json!({"provider": "probe", "key": "sk-live-other-9999"}));
        assert_eq!(row(&ok(&dead, "ui.chat.models.list", json!({"provider": "probe"})), "probe")["source"], "builtin");
    }

    #[test]
    fn mask_shows_only_the_tail() {
        assert_eq!(mask("short"), "••••");
        assert_eq!(mask("sk-abcdefghijklmnop"), "••••mnop");
        assert_eq!(derived_name("my-box.local"), "MY_BOX_LOCAL_API_KEY");
    }
}
