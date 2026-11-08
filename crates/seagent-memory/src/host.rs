//! Host wiring for the memory subsystem. Called from `crates/seagent/src/wire.rs`.
//!
//! One [`Host`] per data directory is shared by `tools()` (built before the kernel exists) and
//! `attach()` (called once it does), so the tools and the lifecycles use the same index,
//! settings and embedder. `attach()` also hands the kernel the aux-model sampler, without
//! which query rewrite / dreaming narratives / flush stay off; the tools are already live, so
//! the sampler is filled in later (`Host::set_sampler`).

use crate::manager::Provider;
use crate::settings::Settings;
use crate::{Host, Sampler};
use seagent_core::Tool;
use seagent_kernel::config::{Config, Paths};
use seagent_kernel::kernel::Kernel;
use seagent_kernel::vault::Vault;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

/// `{{secret:NAME}}` → value, from the vault (`paths.secrets()`; what `seagent secrets set`
/// writes). Unknown names are left as-is, and `env:NAME` / the provider's environment
/// fallbacks (`OPENAI_API_KEY`, …) still apply when the configured value is empty.
fn subst(paths: &Paths) -> crate::Subst {
    let vault = Vault::load(&paths.secrets()).unwrap_or_else(|e| {
        eprintln!("seagent: warning: secrets: {e}; {{secret:NAME}} values stay unresolved");
        Vault::empty()
    });
    Arc::new(move |s: &str| vault.substitute(s))
}

/// Live hosts, keyed by data dir (weak: the caller owns the strong reference).
type Registry = Mutex<Vec<(PathBuf, Weak<Host>)>>;

fn registry() -> &'static Registry {
    static REG: OnceLock<Registry> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(Vec::new()))
}

fn build_host(cfg: &Config, paths: &Paths) -> Arc<Host> {
    match Host::new(&paths.data, &cfg.memory, subst(paths), None) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("seagent: warning: [memory] settings: {e}; using defaults");
            Host::with_settings(&paths.data, Settings::default(), subst(paths), None)
        }
    }
}

/// ARP `kb.search {query, limit?, minScore?}` and `kb.status` (srv-037): the knowledge base
/// (team bases, notes, documents, long-term memories) for UIs and scripts. The app server puts
/// the caller's reach in `params._viewer` for organization-bound principals (a client can never
/// set it); without it (the local socket, the installation owner) nothing is filtered.
pub fn methods(cfg: &Config, paths: &Paths) -> seagent_kernel::daemon::MethodExt {
    kb_methods_for(host(cfg, paths))
}

/// [`methods`] over a given host.
pub fn kb_methods_for(h: Arc<Host>) -> seagent_kernel::daemon::MethodExt {
    Arc::new(move |m: &str, p: &serde_json::Value| {
        let viewer: Option<seagent_kernel::tenancy::Viewer> = p.get("_viewer").and_then(|v| serde_json::from_value(v.clone()).ok());
        match m {
            "kb.search" => Some(kb_search(&h, p, viewer.as_ref())),
            "kb.status" => Some(kb_status(&h, viewer.as_ref())),
            _ => None,
        }
    })
}

fn kb_search(h: &Host, p: &serde_json::Value, viewer: Option<&seagent_kernel::tenancy::Viewer>) -> Result<serde_json::Value, (i32, String)> {
    let q = p["query"].as_str().map(str::trim).filter(|q| !q.is_empty()).ok_or((-32602, "missing param `query`".to_string()))?;
    let limit = p["limit"].as_u64().unwrap_or(h.settings.search.max_results as u64).clamp(1, 50) as usize;
    let min = p["minScore"].as_f64().unwrap_or(h.settings.search.min_score);
    let o = h.search_as(q, limit, min, &["memory"], viewer).map_err(|e| (-32000, e))?;
    Ok(serde_json::json!({"mode": o.mode, "results": o.hits.iter().map(|x| serde_json::json!({"path": x.path, "citation": x.citation(), "score": x.score, "snippet": x.snippet, "source": x.source})).collect::<Vec<_>>()}))
}

fn kb_status(h: &Host, viewer: Option<&seagent_kernel::tenancy::Viewer>) -> Result<serde_json::Value, (i32, String)> {
    h.sync();
    let all = seagent_kernel::tenancy::Viewer::global();
    let rows = seagent_kernel::sqlindex::tenant_files(&h.data, viewer.unwrap_or(&all)).map_err(|e| (-32000, e))?;
    Ok(serde_json::json!({"documents": rows.iter().map(|(path, org, team, chunks)| serde_json::json!({"path": path, "org": if org.is_empty() { seagent_kernel::tenancy::DEFAULT_ORG } else { org }, "team": team, "chunks": chunks})).collect::<Vec<_>>()}))
}

/// The live [`Host`] for `paths.data` (created on first use, reused afterwards).
pub fn host(cfg: &Config, paths: &Paths) -> Arc<Host> {
    let mut g = registry().lock().unwrap();
    if let Some((_, w)) = g.iter().find(|(p, _)| *p == paths.data) {
        if let Some(h) = w.upgrade() {
            return h;
        }
    }
    let h = build_host(cfg, paths);
    g.retain(|(p, w)| *p != paths.data && w.strong_count() > 0);
    g.push((paths.data.clone(), Arc::downgrade(&h)));
    h
}

/// Plugin memory providers (`"memory": true`), registered before `attach` by the binary
/// (`crates/seagent/src/main.rs`), joined into the MemoryManager fan-out.
fn plugin_slot() -> &'static Mutex<Vec<Arc<dyn Provider>>> {
    static P: OnceLock<Mutex<Vec<Arc<dyn Provider>>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn set_plugin_providers(v: Vec<Arc<dyn Provider>>) {
    *plugin_slot().lock().unwrap() = v;
}

pub fn plugin_providers() -> Vec<Arc<dyn Provider>> {
    plugin_slot().lock().unwrap().clone()
}

/// Tools to register before the kernel is built (`memory_search`, `memory_get`,
/// `personal_instructions`, `memory_recall`/`memory_store`/`memory_forget`, `wiki_*`, the
/// bundled provider's tools).
pub fn tools(cfg: &Config, paths: &Paths, _ws: &Path) -> Vec<Arc<dyn Tool>> {
    crate::tools(&host(cfg, paths))
}

/// After the kernel exists: the aux sampler, lifecycles (MemoryManager, active memory, vector
/// auto-recall/capture, the pre-compaction flush, workspace bootstrap files, the dreaming
/// scheduler tick) and the native slash commands.
pub fn attach(k: &Kernel, ws: &Path) {
    let h = host(&k.cfg, &k.paths);
    h.set_sampler(crate::kernel_sampler(k));
    for l in crate::lifecycles(&h, plugin_providers()) {
        k.add_lifecycle(l);
    }
    // Workspace bootstrap files (OpenClaw `workspace-bootstrap-*`): AGENTS.md, SOUL.md,
    // IDENTITY.md, USER.md, BOOTSTRAP.md, MEMORY.md plus `[hooks_extra.bootstrap] paths`.
    k.add_lifecycle(Arc::new(crate::bootstrap::Bootstrap::new(&k.cfg, ws)));
    // Dreaming sweep on the scheduler tick (cron-gated, so most turns cost one file read).
    k.add_lifecycle(Arc::new(crate::dreaming::Tick(h.clone())));
    k.add_slash(Arc::new(crate::slash::MemorySlash::new(h, ws.to_path_buf())));
}

/// `seagent memory <sub>` / `seagent journey <sub>` / `seagent index <sub>`: the verbs in [`crate::cli`]. `argv` excludes the
/// command word (the library CLI expects it as `argv[0]`).
pub fn cli(cmd: &str, argv: &[String], cfg: &Config, paths: &Paths, ws: &Path) -> Result<i32, String> {
    let h = host(cfg, paths);
    let argv: Vec<String> = std::iter::once(cmd.to_string()).chain(argv.iter().cloned()).collect();
    let plugins: Vec<String> = cfg.plugins.keys().cloned().collect();
    let out = if cmd == "index" { crate::cli::index_cmd(&h, &argv[1..], Some(cfg))? } else { crate::cli::run_with(&h, &argv, &plugins, &skill_roots(paths, ws))? };
    if !out.is_empty() {
        println!("{out}");
    }
    Ok(0)
}

/// `(source, dir)` for `journey`'s skill nodes: the workspace/profile/external roots the prompt
/// builder uses.
fn skill_roots(paths: &Paths, ws: &Path) -> Vec<(String, PathBuf)> {
    paths
        .skills_dirs(ws)
        .into_iter()
        .map(|d| (if d.starts_with(&paths.data) { "profile".to_string() } else { "base".to_string() }, d))
        .collect()
}

/// The aux-model sampler the lifecycles use (tests, hosts that own a sampler).
pub fn with_sampler(cfg: &Config, paths: &Paths, s: Sampler) -> Arc<Host> {
    let h = host(cfg, paths);
    h.set_sampler(s);
    h
}

/// Self-registration (`seagent_core::registry`): the memory tools (recall / remember / profile …).
pub fn register() {
    seagent_core::registry::register_tool_provider("memory", 110, |env| {
        let cfg = env.config::<Config>()?;
        let paths = Paths { data: env.data.clone(), config_dir: env.config_dir.clone(), runtime: env.runtime.clone(), ..Default::default() };
        Ok(tools(cfg, &paths, &env.workspace))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_kernel::config::MemoryConfig;

    fn env(tag: &str) -> (Config, Paths, PathBuf) {
        let d = crate::tmp(tag);
        // No embedding provider: tests must never reach a network (`auto` would try OpenAI
        // when a key happens to be in the environment).
        let cfg = Config { memory: toml::from_str("[search.embedding]\nprovider = \"none\"\n").unwrap(), ..Default::default() };
        let paths = Paths { data: d.clone(), config_dir: d.join("config"), runtime: d.join("run"), ..Default::default() };
        (cfg, paths, d)
    }

    #[test]
    fn one_host_per_data_dir_and_tools_are_registered() {
        let (cfg, paths, d) = env("host-tools");
        let a = host(&cfg, &paths);
        let b = host(&cfg, &paths);
        assert!(Arc::ptr_eq(&a, &b), "the same index/settings back tools() and attach()");
        let names: Vec<String> = tools(&cfg, &paths, &d).iter().map(|t| t.spec().name).collect();
        for want in ["memory_search", "memory_get", "personal_instructions", "memory_recall", "memory_store", "memory_forget"] {
            assert!(names.contains(&want.to_string()), "{want} missing from {names:?}");
        }
        assert!(names.iter().any(|n| n.starts_with("wiki_")), "wiki tools: {names:?}");
    }

    #[test]
    fn secret_placeholders_in_the_embedding_config_come_from_the_vault() {
        use crate::util::testutil::fake;
        let d = crate::tmp("host-secret");
        let paths = Paths { data: d.clone(), config_dir: d.join("config"), runtime: d.join("run"), ..Default::default() };
        // The vault the binary reads (`seagent secrets set EMBED_KEY …`).
        let secrets = paths.secrets();
        std::fs::create_dir_all(secrets.parent().unwrap()).unwrap();
        std::fs::write(&secrets, "EMBED_KEY = \"sk-from-the-vault\"\n").unwrap();
        seagent_core::platform::fs_private::set_private(&secrets).unwrap();
        let f = fake(|_r, _n| (200, serde_json::json!({"data": [{"index": 0, "embedding": [1.0, 0.0]}]}).to_string()));
        let cfg = Config {
            memory: toml::from_str(&format!(
                "[search.embedding]\nprovider = \"openai\"\nbase_url = \"{}\"\napi_key = \"{{{{secret:EMBED_KEY}}}}\"\n",
                f.url
            ))
            .unwrap(),
            ..Default::default()
        };
        let h = host(&cfg, &paths);
        assert_eq!(h.settings.search.embedding.api_key, "{{secret:EMBED_KEY}}", "the config keeps the placeholder");
        let e = h.embedder().unwrap().unwrap();
        e.embed(&["hello".into()], crate::embed::Kind::Document, crate::util::RETRY_QUERY).unwrap();
        let reqs = f.reqs.lock().unwrap();
        assert_eq!(reqs[0].header("authorization").as_deref(), Some("Bearer sk-from-the-vault"), "the vault value is the bearer token");
        assert!(!reqs[0].headers.iter().any(|(_, v)| v.contains("{{secret:")), "a placeholder never reaches the provider: {:?}", reqs[0].headers);
        assert!(!String::from_utf8_lossy(&reqs[0].body).contains("EMBED_KEY"), "nor does the secret name: {}", String::from_utf8_lossy(&reqs[0].body));
    }

    #[test]
    fn limits_and_write_approval_come_from_config() {
        let (mut cfg, paths, d) = env("host-limits");
        cfg.memory = MemoryConfig { memory_char_limit: Some(1234), user_char_limit: Some(77), write_approval: true, ..Default::default() };
        let h = host(&cfg, &paths);
        assert_eq!(seagent_tools::memory_store::cap_of("memory"), 1234);
        assert_eq!(seagent_tools::memory_store::cap_of("user"), 77);
        assert!(seagent_tools::memory_store::write_approval_enabled(&d));
        assert_eq!(h.memory_dir(), d.join("memory"));
    }

    #[test]
    fn cli_verbs_print_and_fail_like_the_library() {
        let (cfg, paths, d) = env("host-cli");
        // `seagent memory show` on an empty store, and the usage error for an unknown verb.
        assert!(cli("memory", &["status".into()], &cfg, &paths, &d).is_ok());
        assert!(cli("memory", &["bogus".into()], &cfg, &paths, &d).is_err());
        assert!(cli("journey", &[], &cfg, &paths, &d).is_ok());
    }
}
