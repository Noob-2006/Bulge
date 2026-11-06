//! seagent-memory: memory search (hybrid FTS + vectors), embedding providers, the vector memory
//! store, active memory, dreaming, pre-compaction flush, the memory host SDK (events/query),
//! the MemoryManager provider fan-out (builtin + plugin + bundled byterover / retaindb),
//! the compiled wiki, and the `seagent memory` / `seagent journey` / `/dreaming` / `/active-memory`
//! handlers. Ports of OpenClaw memory-core / memory-lancedb / active-memory / memory-wiki
//! and Hermes memory_manager / memory plugins (both MIT).
//!
//! Wiring (host side): `let h = Host::new(&paths.data, &cfg.memory, subst, Some(kernel_sampler(&k)))?;`
//! then `tools(&h)`, `lifecycles(&h, plugin_providers)`, `cli(&h, argv)`, `slash(&h, name, args, session)`.

pub mod active;
pub mod bootstrap;
pub mod byterover;
pub mod cli;
pub mod dreaming;
pub mod embed;
pub mod events;
pub mod fence;
pub mod flush;
pub mod host;
pub mod index;
pub mod journey;
pub mod manager;
pub mod memstore;
pub mod migrate;
pub mod oauth;
pub mod recall;
pub mod retaindb;
pub mod rewrite;
pub mod settings;
pub mod slash;
pub mod sigv4;
pub mod standing;
pub mod tools;
pub mod trust;
pub mod util;
pub mod vector;
pub mod wiki;
#[cfg(test)]
mod ragtests;

use seagent_core::{Cancel, Message, Tool};
use seagent_kernel::config::MemoryConfig;
use seagent_kernel::lifecycle::Lifecycle;
use embed::Embedder;
use index::{Hit, Index};
use serde_json::{json, Value};
use settings::Settings;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
pub use util::Subst;

/// One-shot aux-model completion: (model or None = aux, system, user prompt, max tokens) → text.
pub type Sampler = Arc<dyn Fn(Option<&str>, &str, &str, u32) -> Result<String, String> + Send + Sync>;

/// A `Sampler` backed by the kernel (`Runtime::sample`); holds a weak reference so the
/// kernel can own lifecycles that use it.
pub fn kernel_sampler(k: &seagent_kernel::kernel::Kernel) -> Sampler {
    let w = Arc::downgrade(k);
    Arc::new(move |model: Option<&str>, system: &str, user: &str, max_tokens: u32| {
        let k = w.upgrade().ok_or("kernel is gone")?;
        let (m, _, _) = k.sample(model, system, vec![Message::user(user)], vec![], max_tokens, &Cancel::new())?;
        Ok(m.text())
    })
}

pub struct SearchOutcome {
    pub hits: Vec<Hit>,
    /// `provider/model` or `none`.
    pub provider: String,
    /// `hybrid` | `fts-only`.
    pub mode: String,
    pub warnings: Vec<String>,
}

/// Lazily built embedder: `Ok(None)` = no provider configured, `Err` = build failure (cached).
type EmbedderCache = Mutex<Option<Result<Option<Arc<dyn Embedder>>, String>>>;

/// Shared state of the memory subsystem.
pub struct Host {
    pub data: PathBuf,
    pub settings: Settings,
    pub subst: Subst,
    /// The aux-model sampler: filled in by the host once the kernel exists
    /// (`seagent_memory::host::attach`); unset = rewrite / dreaming narratives / flush are off.
    pub sampler: OnceLock<Sampler>,
    /// Fixed UTC offset for day stamps (seagent `[schedule] utc_offset_minutes`, default 480).
    pub utc_offset_minutes: i32,
    embedder: EmbedderCache,
    index: Mutex<Option<Index>>,
}

impl Host {
    pub fn new(data: &Path, cfg: &MemoryConfig, subst: Subst, sampler: Option<Sampler>) -> Result<Arc<Host>, String> {
        let settings = Settings::from_config(cfg)?;
        seagent_tools::memory_store::set_limits(cfg.memory_char_limit.unwrap_or(seagent_tools::memory_store::CHAR_CAP), cfg.user_char_limit.unwrap_or(seagent_tools::memory_store::CHAR_CAP));
        seagent_tools::memory_store::set_write_approval(cfg.write_approval);
        Ok(Self::with_settings(data, settings, subst, sampler))
    }

    pub fn with_settings(data: &Path, settings: Settings, subst: Subst, sampler: Option<Sampler>) -> Arc<Host> {
        let cell = OnceLock::new();
        if let Some(s) = sampler {
            let _ = cell.set(s);
        }
        Arc::new(Host { data: data.to_path_buf(), settings, subst, sampler: cell, utc_offset_minutes: 480, embedder: Mutex::new(None), index: Mutex::new(None) })
    }

    pub fn memory_dir(&self) -> PathBuf {
        self.data.join("memory")
    }

    /// The configured embedding provider (built once); `Ok(None)` = FTS-only.
    pub fn embedder(&self) -> Result<Option<Arc<dyn Embedder>>, String> {
        let mut g = self.embedder.lock().unwrap();
        if g.is_none() {
            *g = Some(embed::build(&self.settings.search.embedding, &self.subst));
        }
        g.clone().unwrap()
    }

    /// Override the embedder (tests, hosts with their own provider).
    pub fn set_embedder(&self, e: Option<Arc<dyn Embedder>>) {
        *self.embedder.lock().unwrap() = Some(Ok(e));
    }

    /// Install the aux sampler (the first one wins: the kernel outlives every tool instance).
    pub fn set_sampler(&self, s: Sampler) {
        let _ = self.sampler.set(s);
    }

    pub fn has_sampler(&self) -> bool {
        self.sampler.get().is_some()
    }

    pub fn sample(&self, model: &str, system: &str, user: &str, max_tokens: u32) -> Result<String, String> {
        let s = self.sampler.get().ok_or("no model available for memory (aux model not wired)")?;
        s(Some(model).filter(|m| !m.is_empty()), system, user, max_tokens)
    }

    /// Incremental index sync (embedding failures degrade to FTS-only).
    pub fn sync(&self) -> index::SyncReport {
        let e = self.embedder().ok().flatten();
        let mut g = self.index.lock().unwrap();
        let ix = g.get_or_insert_with(|| Index::open(&self.data));
        ix.sync(&self.data, &self.settings.search, e.as_deref())
    }

    pub fn reset_index(&self) -> Result<(), String> {
        let mut g = self.index.lock().unwrap();
        *g = None;
        Index::reset(&self.data)
    }

    /// Sync then search (OpenClaw `sync.onSearch`).
    pub fn search(&self, query: &str, max_results: usize, min_score: f64, sources: &[&str]) -> Result<SearchOutcome, String> {
        self.search_as(query, max_results, min_score, sources, None)
    }

    /// The viewer a session searches as (srv-037): its tenant while multi-tenancy is active,
    /// otherwise unrestricted.
    pub fn session_viewer(&self, session: &str) -> Option<seagent_kernel::tenancy::Viewer> {
        if session.is_empty() || !seagent_kernel::tenancy::active(&self.data) {
            return None;
        }
        Some(seagent_kernel::tenancy::Viewer::of_session(&seagent_kernel::tenancy::session_tenant(&self.data, session)))
    }

    /// [`Host::search`] restricted to what `viewer` may retrieve (team knowledge bases,
    /// transcripts and memories of other tenants are never candidates).
    pub fn search_as(&self, query: &str, max_results: usize, min_score: f64, sources: &[&str], viewer: Option<&seagent_kernel::tenancy::Viewer>) -> Result<SearchOutcome, String> {
        if !self.settings.search.enabled {
            return Err("memory search is disabled ([memory.search] enabled = false)".into());
        }
        let mut warnings = self.sync().warnings;
        let (e, provider) = match self.embedder() {
            Ok(Some(e)) => {
                let p = format!("{}/{}", e.id(), e.model());
                (Some(e), p)
            }
            Ok(None) => (None, "none".into()),
            Err(err) => {
                warnings.push(format!("embedding provider unavailable, keyword search only: {err}"));
                (None, "none".into())
            }
        };
        let mut qv = None;
        if let Some(e) = &e {
            match e.embed(&[query.to_string()], embed::Kind::Query, util::RETRY_QUERY) {
                Ok(mut v) if !v.is_empty() && !v[0].is_empty() => qv = Some(v.remove(0)),
                Ok(_) => {}
                Err(err) => warnings.push(format!("query embedding failed, keyword search only: {err}")),
            }
        }
        let g = self.index.lock().unwrap();
        let ix = g.as_ref().ok_or("index not loaded")?;
        let hits = ix.search_as(&self.data, &self.settings.search, query, qv.as_deref().map(|v| (provider.as_str(), v)), max_results, min_score, sources, util::now_ms(), viewer);
        Ok(SearchOutcome { hits, mode: if qv.is_some() { "hybrid".into() } else { "fts-only".into() }, provider, warnings })
    }

    pub fn status(&self) -> Value {
        let rep = self.sync();
        let (provider, err) = match self.embedder() {
            Ok(Some(e)) => (format!("{}/{}", e.id(), e.model()), None),
            Ok(None) => ("none (keyword search only)".into(), None),
            Err(e) => ("unavailable".into(), Some(e)),
        };
        let g = self.index.lock().unwrap();
        let vectors = g.as_ref().map(|i| i.vector_count()).unwrap_or(0);
        json!({"provider": self.settings.provider, "embedding": provider, "embeddingError": err, "files": rep.files, "chunks": rep.chunks, "vectors": vectors, "sources": self.settings.search.sources, "warnings": rep.warnings, "dir": self.memory_dir()})
    }
}

/// The memory tools: memory_search, memory_get, personal_instructions, memory_recall /
/// memory_store / memory_forget (unless `[memory.vector] enabled = false`), the wiki tools
/// (unless `[memory.wiki] enabled = false`), and the bundled provider's tools.
pub fn tools(h: &Arc<Host>) -> Vec<Arc<dyn Tool>> {
    let mut v: Vec<Arc<dyn Tool>> = vec![Arc::new(tools::MemorySearch(h.clone())), Arc::new(tools::MemoryGet(h.clone())), Arc::new(tools::PersonalInstructions::new(h.clone()))];
    if h.settings.vector.enabled {
        let store = Arc::new(vector::VectorMemory::new(h.clone()));
        v.extend(vector::tools(&store));
    }
    if h.settings.wiki.enabled {
        v.extend(wiki::tools(h));
    }
    match h.settings.provider.as_str() {
        "byterover" => v.extend(byterover::tools(&Arc::new(byterover::Byterover::new(h)))),
        "retaindb" => {
            if let Ok(r) = retaindb::RetainDb::new(h) {
                v.extend(retaindb::tools(&Arc::new(r)));
            }
        }
        _ => {}
    }
    v
}

/// Lifecycles to register with `Runtime::add_lifecycle`: the MemoryManager (builtin + one
/// external provider: a bundled one per `[memory] provider`, else the first of `plugins`),
/// active memory, vector auto-recall/capture, and the pre-compaction flush.
pub fn lifecycles(h: &Arc<Host>, plugins: Vec<Arc<dyn manager::Provider>>) -> Vec<Arc<dyn Lifecycle>> {
    let mut providers: Vec<Arc<dyn manager::Provider>> = vec![Arc::new(manager::Builtin(h.clone()))];
    match h.settings.provider.as_str() {
        "byterover" => providers.push(Arc::new(byterover::Byterover::new(h))),
        "retaindb" => match retaindb::RetainDb::new(h) {
            Ok(r) => providers.push(Arc::new(r)),
            Err(e) => eprintln!("seagent: memory provider retaindb unavailable: {e}"),
        },
        _ => providers.extend(plugins),
    }
    let mut v: Vec<Arc<dyn Lifecycle>> = vec![Arc::new(manager::MemoryManager::new(h.clone(), providers))];
    v.push(Arc::new(active::ActiveMemory::new(h.clone())));
    v.push(Arc::new(active::RecallGate::new(h.clone())));
    if h.settings.vector.enabled {
        v.push(Arc::new(vector::AutoMemory(Arc::new(vector::VectorMemory::new(h.clone())))));
    }
    v.push(Arc::new(flush::Flush(h.clone())));
    v.push(Arc::new(standing::StandingIntents::new(h.clone())));
    v
}

/// `seagent memory …` / `seagent journey …` / `seagent wiki …` (argv starts with the verb's own name).
pub fn cli(h: &Arc<Host>, argv: &[String]) -> Result<String, String> {
    cli::run(h, argv)
}

/// Slash commands `/dreaming`, `/active-memory`, `/memory`, `/journey`; `None` = not ours.
pub fn slash(h: &Arc<Host>, name: &str, args: &str, session: &str) -> Option<Result<String, String>> {
    match name {
        "dreaming" => Some(dreaming::command(h, args)),
        "active-memory" => Some(active::command(h, args, session)),
        "memory" => Some(cli::run(h, &std::iter::once("memory".to_string()).chain(args.split_whitespace().map(str::to_string)).collect::<Vec<_>>())),
        "journey" | "learning" => Some(journey::run(h, &args.split_whitespace().map(str::to_string).collect::<Vec<_>>(), &[])),
        _ => None,
    }
}

/// Scheduler hook: run the dreaming sweep when its cron is due (call every scheduler tick).
pub fn dreaming_tick(h: &Arc<Host>, now_ms: u64) -> Option<Result<String, String>> {
    dreaming::tick(h, now_ms)
}

#[cfg(test)]
pub fn tmp(tag: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let d = seagent_core::tmp::scratch_path(format!("seagent-memory-{tag}-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("memory")).unwrap();
    d
}

#[cfg(test)]
pub fn test_host(tag: &str, mutate: impl FnOnce(&mut Settings)) -> Arc<Host> {
    let mut s = Settings::default();
    mutate(&mut s);
    let h = Host::with_settings(&tmp(tag), s, Arc::new(|s: &str| s.to_string()), None);
    h.set_embedder(None);
    h
}

#[cfg(test)]
pub fn test_host_with(tag: &str, mutate: impl FnOnce(&mut Settings), sampler: Sampler) -> Arc<Host> {
    let mut s = Settings::default();
    mutate(&mut s);
    let h = Host::with_settings(&tmp(tag), s, Arc::new(|s: &str| s.to_string()), Some(sampler));
    h.set_embedder(None);
    h
}
