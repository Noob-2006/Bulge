//! End-to-end wiring of the memory subsystem: `seagent_memory::host::{tools, attach, cli}` called
//! the way `crates/seagent/src/wire.rs` calls them. Proves the rows "MemoryManager", "memory_search",
//! "memory_get", "wiki_*", "memory_recall/store/forget", "active-memory", "Memory flush",
//! "/memory", "/journey", "/dreaming", "/active-memory", "dreaming" and "Project memory /
//! bootstrap files" are reachable, not just implemented.

use seagent_core::{Cancel, ToolCtx, ToolHost};
use seagent_kernel::approver::Policy;
use seagent_kernel::config::{Config, Paths};
use seagent_kernel::kernel::{new_kernel, Kernel, Resolver};
use seagent_kernel::vault::Vault;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

struct NoProviders;
impl Resolver for NoProviders {
    fn provider(&self, id: &str) -> Result<Arc<dyn seagent_core::Provider>, String> {
        Err(format!("no provider `{id}` in this test"))
    }
}

struct NoHost;
impl ToolHost for NoHost {
    fn spawn_agent(&self, _: seagent_core::tool::SpawnRequest, _: &Cancel) -> Result<String, String> {
        Err("no sub-agents in this test".into())
    }
    fn ask_user(&self, _: &str) -> Result<String, String> {
        Err("no user in this test".into())
    }
}

fn paths_at(d: &std::path::Path) -> Paths {
    Paths { data: d.to_path_buf(), config_dir: d.join("config"), runtime: d.join("run"), ..Default::default() }
}

static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn env(tag: &str) -> (Kernel, Paths, PathBuf) {
    let d = seagent_core::tmp::scratch_path(format!("seagent-memory-host-{tag}-{}-{}", std::process::id(), NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("memory")).unwrap();
    let paths = paths_at(&d);
    // No embedding provider: the tests must never reach the network.
    let cfg = Config { memory: toml::from_str("[search.embedding]\nprovider = \"none\"\n").unwrap(), ..Default::default() };
    let k = new_kernel(cfg, paths.clone(), Arc::new(NoProviders), vec![], Arc::new(Vault::empty()), Arc::new(Policy { allow_privilege: false, allow_egress: false }));
    (k, paths, d)
}

fn ctx(home: &std::path::Path, ws: &std::path::Path) -> ToolCtx {
    ToolCtx {
        workspace: ws.to_path_buf(),
        session_id: "s1".into(),
        artifacts: home.join("artifacts"),
        home: home.to_path_buf(),
        cancel: Cancel::new(),
        host: Arc::new(NoHost),
        secrets: Arc::new(|s: &str| s.to_string()),
    }
}

#[test]
fn attach_registers_lifecycles_and_native_commands() {
    let (k, paths, d) = env("attach");
    seagent_memory::host::attach(&k, &d);
    let names = k.lifecycle_names();
    for want in ["memory-manager", "active-memory", "vector-memory", "memory-flush", "bootstrap", "dreaming-tick"] {
        assert!(names.contains(&want.to_string()), "lifecycle `{want}` not registered: {names:?}");
    }
    let slash: Vec<String> = k.slash_commands().into_iter().map(|(n, _)| n).collect();
    for want in ["memory", "journey", "dreaming", "active-memory"] {
        assert!(slash.contains(&want.to_string()), "`/{want}` not registered: {slash:?}");
    }
    // The tools the binary merges into `builtin_tools` for the model.
    let tools: Vec<String> = seagent_memory::host::tools(&k.cfg, &paths, &d).iter().map(|t| t.spec().name).collect();
    for want in ["memory_search", "memory_get", "personal_instructions", "memory_recall", "memory_store", "memory_forget"] {
        assert!(tools.contains(&want.to_string()), "tool `{want}` not contributed: {tools:?}");
    }
    assert!(tools.iter().any(|t| t.starts_with("wiki_")), "{tools:?}");
}

#[test]
fn memory_accept_replays_a_security_staged_record() {
    let (k, _paths, d) = env("accept");
    seagent_memory::host::attach(&k, &d);
    // Exactly the shape `seagent_security::approvals::stage_memory_writes` writes.
    let rec = json!({"session": "s1", "origin": "foreground", "created_ms": 1_700_000_000_000u64,
        "user": ["runs in UTC+8"], "summary": "add runs in UTC+8"});
    let dir = d.join("memory/staging");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("0000000000001-1a0001.json"), rec.to_string()).unwrap();

    let review = k.run_slash("/memory review", None, "cli").expect("registered").expect("review works");
    assert!(review.text.unwrap().contains("runs in UTC+8"), "the queue is visible via /memory review");
    let out = k.run_slash("/memory accept 1", None, "cli").expect("registered").expect("accept works");
    assert!(out.text.unwrap().contains("accepted 1"));
    assert!(std::fs::read_to_string(d.join("memory/USER.md")).unwrap().contains("runs in UTC+8"));
    assert!(!dir.join("0000000000001-1a0001.json").exists(), "the pending record is consumed");
    // Reject on an empty queue is a user-facing error, not a panic.
    assert!(k.run_slash("/memory accept 1", None, "cli").unwrap().is_err());
}

#[test]
fn memory_search_and_get_are_callable_tools() {
    let (k, paths, d) = env("search");
    seagent_memory::host::attach(&k, &d);
    std::fs::write(d.join("memory/MEMORY.md"), "The release train leaves on Fridays.\n§\nProd deploys need two approvals.\n").unwrap();
    let tools = seagent_memory::host::tools(&k.cfg, &paths, &d);
    let search = tools.iter().find(|t| t.spec().name == "memory_search").unwrap().clone();
    let out = search.call(&ctx(&d, &d), json!({"query": "when does the release train leave"})).content;
    assert!(out.contains("Fridays"), "{out}");
    assert!(out.contains("MEMORY.md"), "a citation is included: {out}");
    let get = tools.iter().find(|t| t.spec().name == "memory_get").unwrap().clone();
    let g = get.call(&ctx(&d, &d), json!({"path": "memory/MEMORY.md", "lines": 1})).content;
    assert!(g.contains("Fridays"), "{g}");
}

#[test]
fn dreaming_and_active_memory_commands_round_trip() {
    let (k, _paths, d) = env("commands");
    seagent_memory::host::attach(&k, &d);
    assert!(k.run_slash("/dreaming status", None, "cli").unwrap().unwrap().text.unwrap().contains("Dreaming status"));
    assert!(k.run_slash("/dreaming on", None, "cli").unwrap().unwrap().text.unwrap().contains("enabled"));
    assert!(k.run_slash("/dreaming run light", None, "cli").unwrap().is_ok());
    assert!(k.run_slash("/active-memory on", None, "cli").unwrap().is_ok());
    assert!(k.run_slash("/active-memory status", None, "cli").unwrap().unwrap().text.unwrap().contains("Active memory"));
    assert!(k.run_slash("/journey", None, "cli").unwrap().is_ok());
    // `seagent journey list` on an empty graph is a friendly message, `seagent memory status` a report.
    assert_eq!(seagent_memory::host::cli("journey", &["list".into()], &k.cfg, &paths_at(&d), &d), Ok(0));
    assert_eq!(seagent_memory::host::cli("memory", &["status".into()], &k.cfg, &paths_at(&d), &d), Ok(0));
}

#[test]
fn bootstrap_files_reach_the_system_prompt() {
    let (k, _paths, d) = env("bootstrap");
    std::fs::write(d.join("IDENTITY.md"), "I am the release captain.").unwrap();
    std::fs::write(d.join("AGENTS.md"), "Run cargo test before every commit.").unwrap();
    seagent_memory::host::attach(&k, &d);
    let seg = seagent_memory::bootstrap::render(&d, &[]).expect("both files load");
    assert!(seg.contains("release captain") && seg.contains("cargo test"), "{seg}");
    // The lifecycle is what the kernel asks for its frozen system prompt.
    use seagent_kernel::lifecycle::Lifecycle;
    let b = seagent_memory::bootstrap::Bootstrap::new(&k.cfg, &d);
    let out = b.system_segment(&d.to_string_lossy()).expect("bootstrap segment");
    assert_eq!(out.id, "bootstrap");
    assert!(out.text.contains("release captain"), "{}", out.text);
}
