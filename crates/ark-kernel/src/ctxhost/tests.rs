//! Tests for the context host: the slash commands, the system segments and the title generator.
//!
//! Every test builds a real kernel on a temp `Paths` and drives it through `Kernel::run_slash`, so
//! what is asserted is what a channel chat, the TUI or `ark run` would get. No network: the model
//! is a scripted provider (and, for titles, an injected seam).

use super::slash::{DEFAULT_KEEP_LAST, MAX_KEEP_LAST};
use super::*;
use crate::config::Config;
use crate::event::EventKind;
use crate::kernel::{new_kernel, Resolver};
use crate::projection::project;
use ark_core::*;
use serde_json::json;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

// ───────────── kit ─────────────

/// Scripted provider: `rules` reply when the last user message contains a key, `steps` otherwise.
pub struct Scripted {
    steps: Mutex<VecDeque<String>>,
    rules: Mutex<Vec<(String, String)>>,
    seen: Mutex<Vec<ModelRequest>>,
}

impl Scripted {
    fn when(&self, key: &str, reply: &str) {
        self.rules.lock().unwrap().push((key.into(), reply.into()));
    }
    fn requests(&self) -> Vec<ModelRequest> {
        self.seen.lock().unwrap().clone()
    }
}

impl Provider for Scripted {
    fn id(&self) -> &str {
        "fake"
    }
    fn caps(&self, _: &str) -> ModelCaps {
        ModelCaps { context_window: 200_000, max_output: 8192, tools: true, vision: false, explicit_cache: false }
    }
    fn complete(&self, req: &ModelRequest, _: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
        self.seen.lock().unwrap().push(req.clone());
        let last = req.messages.iter().rev().find(|m| m.role == Role::User).map(|m| m.text()).unwrap_or_default();
        let rule = {
            let mut r = self.rules.lock().unwrap();
            r.iter().position(|(k, _)| last.contains(k.as_str())).map(|i| r.remove(i).1)
        };
        let content = rule.or_else(|| self.steps.lock().unwrap().pop_front()).unwrap_or_else(|| "(script exhausted)".into());
        Ok(ModelResponse { message: Message::assistant(content), stop: StopReason::EndTurn, usage: Usage::default(), model: "m".into() })
    }
}

struct Res(Arc<Scripted>);

impl Resolver for Res {
    fn provider(&self, _: &str) -> Result<Arc<dyn Provider>, String> {
        Ok(self.0.clone())
    }
}

pub struct Kit {
    pub k: Kernel,
    pub p: Arc<Scripted>,
    pub paths: crate::config::Paths,
    pub ws: PathBuf,
    pub att: Arc<Attached>,
}

fn temp_root(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("ark-ctxhost-{tag}-{}", crate::util::random_hex(8)));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn fake_bin(dir: &Path, name: &str, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    let mut perm = std::fs::metadata(&p).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&p, perm).unwrap();
}

/// A toolchain dir with stable fake versions, so the probe never touches the real machine.
fn fake_toolchain(root: &Path) -> PathBuf {
    let dir = root.join("bin");
    fake_bin(&dir, "rustc", "echo 'rustc 1.99.0 (fake 2026-01-01)'");
    fake_bin(&dir, "cargo", "echo 'cargo 1.99.0 (fake)'");
    fake_bin(&dir, "node", "echo 'v20.11.0'");
    fake_bin(&dir, "python3", "echo 'Python 3.12.3'");
    dir
}

fn kit(tag: &str, cfg_mut: impl FnOnce(&mut Config), titler: Option<super::title::Titler>) -> Kit {
    let root = temp_root(tag);
    let ws = root.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let paths = crate::config::Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run") };
    std::fs::create_dir_all(&paths.data).unwrap();
    let mut cfg = Config::default();
    cfg.model.default = "fake/m".into();
    cfg.checkpoint.enabled = false;
    cfg.runner.max_retries = 1;
    cfg_mut(&mut cfg);
    let p = Arc::new(Scripted { steps: Mutex::new(VecDeque::new()), rules: Mutex::new(vec![]), seen: Mutex::new(vec![]) });
    let toolchain = fake_toolchain(&root);
    let k = new_kernel(cfg, paths.clone(), Arc::new(Res(p.clone())), vec![], Arc::new(crate::vault::Vault::empty()), Arc::new(crate::approver::Policy { allow_privilege: true, allow_egress: true }));
    let att = attach_with(&k, &ws, Options { titler, probe_path: Some(toolchain.clone()), lazy_probe: true });
    Kit { k, p, paths, ws, att }
}

fn ws_of(k: &Kit) -> PathBuf {
    k.ws.canonicalize().unwrap()
}

fn session(k: &Kit) -> String {
    k.k.create_session(&ws_of(k), None, None, None).unwrap()
}

fn slash(k: &Kit, line: &str, sid: Option<&str>) -> Result<crate::slash::SlashReply, String> {
    k.k.run_slash(line, sid, "channel").expect("command is registered")
}

fn text(k: &Kit, line: &str, sid: Option<&str>) -> String {
    match slash(k, line, sid) {
        Ok(r) => r.text.unwrap_or_default(),
        Err(e) => format!("error: {e}"),
    }
}

fn push_message(k: &Kit, sid: &str, m: Message) -> u64 {
    let mut log = k.k.store.open(sid).unwrap();
    log.append(EventKind::Message { message: m, usage: None, model: None, inbox: None }).unwrap().seq
}

fn segments(k: &Kit, sid: &str) -> Vec<SystemSegment> {
    project(&k.k.store.read(sid).unwrap()).system
}

fn seg(k: &Kit, sid: &str, id: &str) -> Option<String> {
    segments(k, sid).into_iter().find(|s| s.id == id).map(|s| s.text)
}

fn title_of(k: &Kit, sid: &str) -> Option<String> {
    project(&k.k.store.read(sid).unwrap()).title
}

fn compaction_count(k: &Kit, sid: &str) -> u64 {
    project(&k.k.store.read(sid).unwrap()).compactions
}

fn event_count(k: &Kit, sid: &str) -> usize {
    k.k.store.read(sid).unwrap().len()
}

// ───────────── 6. SOUL.md / personality ─────────────

#[test]
fn soul_is_seeded_once_and_becomes_a_system_segment() {
    let t = kit("soul", |_| {}, None);
    // First run: ark's default file appears in the config dir (Hermes `_ensure_default_soul_md`).
    assert!(!persona::soul_path(&t.paths).exists());
    let sid = session(&t);
    let p = persona::soul_path(&t.paths);
    assert!(p.exists(), "SOUL.md is seeded on first use: {}", p.display());
    assert_eq!(std::fs::read_to_string(&p).unwrap().trim(), persona::DEFAULT_SOUL);
    let text = seg(&t, &sid, "soul").expect("soul segment");
    assert!(text.starts_with("# Soul") && text.contains("match the length of your reply"), "{text}");

    // A file the person wrote wins and is never overwritten.
    std::fs::write(&p, "You are a terse deployment bot.").unwrap();
    let sid2 = session(&t);
    assert!(seg(&t, &sid2, "soul").unwrap().contains("terse deployment bot"));
    assert_eq!(std::fs::read_to_string(&p).unwrap(), "You are a terse deployment bot.");

    // An untouched scaffold is upgraded in place; empty text means no segment.
    std::fs::write(&p, persona::LEGACY_SCAFFOLDS[1]).unwrap();
    assert_eq!(persona::soul_text(&t.paths).unwrap(), persona::DEFAULT_SOUL);
    std::fs::write(&p, "   \n").unwrap();
    let sid3 = session(&t);
    assert!(seg(&t, &sid3, "soul").is_none(), "an emptied SOUL.md contributes nothing");

    // `[context] soul = false` never reads or seeds the file.
    let off = kit("soul-off", |c| c.context.soul = false, None);
    let sid4 = session(&off);
    assert!(seg(&off, &sid4, "soul").is_none());
    assert!(!persona::soul_path(&off.paths).exists());
}

#[test]
fn personality_command_lists_sets_rewrites_and_clears() {
    let t = kit("persona", |_| {}, None);
    let sid = session(&t);
    let list = text(&t, "/personality", Some(&sid));
    assert!(list.contains("current: none") && list.contains("pirate") && list.contains("catgirl"), "{list}");
    assert!(seg(&t, &sid, "personality").is_none(), "none is selected by default");

    let set = text(&t, "/personality Pirate", Some(&sid));
    assert!(set.contains("personality → pirate"), "{set}");
    let now = seg(&t, &sid, "personality").expect("the live session is rewritten");
    assert!(now.starts_with("# Personality") && now.contains("buccaneer"), "{now}");
    assert_eq!(segments(&t, &sid).iter().filter(|s| s.id == "personality").count(), 1, "replaced, not stacked");
    assert!(text(&t, "/personality list", Some(&sid)).contains("current: pirate"));

    // New sessions inherit the selection; switching replaces the overlay.
    let sid2 = session(&t);
    assert!(seg(&t, &sid2, "personality").unwrap().contains("buccaneer"));
    text(&t, "/personality catgirl", Some(&sid));
    assert!(seg(&t, &sid, "personality").unwrap().contains("Neko-chan"));

    // Custom personalities overlay the built-ins by name.
    let custom = kit("persona-custom", |c| {
        c.context.personalities.insert("pirate".into(), "Yarr, custom captain here.".into());
        c.context.personality = "pirate".into();
    }, None);
    let sid3 = session(&custom);
    assert!(seg(&custom, &sid3, "personality").unwrap().contains("custom captain"));

    let unknown = text(&t, "/personality nobody", Some(&sid));
    assert!(unknown.contains("unknown personality `nobody`") && unknown.contains("`pirate`"), "{unknown}");
    text(&t, "/personality none", Some(&sid));
    assert!(seg(&t, &sid, "personality").is_none(), "none removes the segment");
    assert!(seg(&t, &session(&t), "personality").is_none());
}

// ───────────── 7. coding posture ─────────────

fn write(root: &Path, rel: &str, body: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

#[test]
fn coding_posture_uses_the_verify_recipe() {
    let t = kit("coding", |_| {}, None);
    write(&t.ws, "Cargo.toml", "[package]\nname = \"demo\"\n");
    write(&t.ws, "src/main.rs", "fn main() {}\n");
    let sid = session(&t);
    let text = seg(&t, &sid, "coding").expect("coding segment");
    assert!(text.contains("Rust project") && text.contains("`cargo`"), "{text}");
    assert!(text.contains("cargo build") && text.contains("cargo test"), "verify commands: {text}");
    assert!(text.contains("Verify before claiming"), "{text}");

    let node = kit("coding-node", |_| {}, None);
    write(&node.ws, "package.json", r#"{"name":"x","scripts":{"test":"jest","build":"tsc"}}"#);
    write(&node.ws, "pnpm-lock.yaml", "");
    let sid = session(&node);
    let text = seg(&node, &sid, "coding").unwrap();
    assert!(text.contains("pnpm") && text.contains("pnpm test") && text.contains("pnpm build"), "{text}");

    // Plain directory: no posture.
    let plain = kit("coding-plain", |_| {}, None);
    assert!(seg(&plain, &session(&plain), "coding").is_none());
    assert!(posture::posture_text(&plain.ws, &Config::default().context).is_none());

    // `off` disables it; `[context] coding_instructions` is appended.
    let off = kit("coding-off", |c| c.context.coding_context = "off".into(), None);
    write(&off.ws, "Cargo.toml", "[package]\nname = \"demo\"\n");
    assert!(seg(&off, &session(&off), "coding").is_none());
    let extra = kit("coding-extra", |c| c.context.coding_instructions = "Run make lint first.".into(), None);
    write(&extra.ws, "go.mod", "module x\n");
    let t2 = seg(&extra, &session(&extra), "coding").unwrap();
    assert!(t2.contains("Go project") && t2.contains("Run make lint first."), "{t2}");
}

#[test]
fn a_manifest_less_git_repo_counts_only_with_source_files() {
    let root = temp_root("looks");
    let notes = root.join("notes");
    std::fs::create_dir_all(notes.join(".git")).unwrap();
    std::fs::write(notes.join("todo.md"), "# notes").unwrap();
    assert!(!posture::looks_like_code(&notes), "a git-versioned notes folder is not a code workspace");
    std::fs::write(notes.join("script.py"), "print(1)").unwrap();
    assert!(posture::looks_like_code(&notes));
    std::fs::create_dir_all(root.join("bare")).unwrap();
    assert!(!posture::looks_like_code(&root.join("bare")));
}

// ───────────── 8. toolchain probe ─────────────

#[test]
fn toolchain_probe_parses_a_fake_path() {
    let root = temp_root("probe");
    let dir = root.join("bin");
    fake_bin(&dir, "rustc", "echo 'rustc 1.99.0 (fake 2026-01-01)'");
    fake_bin(&dir, "node", "echo 'v20.11.0'");
    fake_bin(&dir, "go", "echo 'go version go1.22.2 linux/amd64'");
    fake_bin(&dir, "java", "echo 'openjdk version \"17.0.9\" 2023-10-17' >&2");
    fake_bin(&dir, "docker", "sleep 5"); // wedged: must be killed, not waited on
    std::fs::write(dir.join("cargo"), "#!/bin/sh\necho cargo 1.99.0\n").unwrap(); // not executable
    let found = posture::probe_dirs(std::slice::from_ref(&dir));
    let map: std::collections::HashMap<&str, &str> = found.iter().map(|(n, v)| (*n, v.as_str())).collect();
    assert_eq!(map.get("rustc"), Some(&"1.99.0"));
    assert_eq!(map.get("node"), Some(&"20.11.0"));
    assert_eq!(map.get("go"), Some(&"1.22.2"));
    assert_eq!(map.get("java"), Some(&"17.0.9"), "java prints its version on stderr");
    assert!(!map.contains_key("docker"), "a hanging --version is dropped");
    assert!(!map.contains_key("cargo"), "a non-executable file is not a tool");
    let line = posture::env_line(&found).unwrap();
    assert!(line.starts_with("rustc 1.99.0") && line.contains("node 20.11.0"), "{line}");

    // The line reaches the prompt through the `environment` segment.
    let t = kit("probe-seg", |_| {}, None);
    let sid = session(&t);
    let env = seg(&t, &sid, "environment").expect("environment segment");
    assert!(env.contains("rustc 1.99.0") && env.contains("node 20.11.0"), "{env}");
    let off = kit("probe-off", |c| c.context.environment_probe = false, None);
    assert!(seg(&off, &session(&off), "environment").is_none());
}

#[test]
fn version_parsing_covers_the_common_shapes() {
    assert_eq!(posture::version_of("cargo 1.80.0 (376290515 2024-07-16)").as_deref(), Some("1.80.0"));
    assert_eq!(posture::version_of("go version go1.22.2 linux/amd64").as_deref(), Some("1.22.2"));
    assert_eq!(posture::version_of("openjdk version \"17.0.9\" 2023-10-17").as_deref(), Some("17.0.9"));
    assert_eq!(posture::version_of("Docker version 24.0.7, build afdd53b").as_deref(), Some("24.0.7"));
    assert_eq!(posture::version_of("v20.11.0").as_deref(), Some("20.11.0"));
    assert_eq!(posture::version_of("Python 3.12.3").as_deref(), Some("3.12.3"));
    assert_eq!(posture::version_of("   \n\n"), None);
}

// ───────────── 1. /context ─────────────

#[test]
fn context_command_reports_the_window_and_the_compaction_plan() {
    let t = kit("context", |_| {}, None);
    let none = text(&t, "/context", None);
    assert!(none.contains("no session yet") && none.contains("window 200,000 tokens"), "{none}");
    assert!(none.contains("system prompt:") && none.contains("tool schemas:"), "{none}");

    let sid = session(&t);
    for i in 0..4 {
        push_message(&t, &sid, Message::user(format!("question {i} {}", "detail ".repeat(40))));
        push_message(&t, &sid, Message::assistant(format!("answer {i}")));
    }
    let out = text(&t, "/context", Some(&sid));
    assert!(out.contains(&format!("Context — session {sid}")), "{out}");
    assert!(out.contains("model fake/m · window 200,000 tokens"), "{out}");
    assert!(out.contains("usage ~") && out.contains("% of the window"), "{out}");
    assert!(out.contains("system prompt: ~"), "{out}");
    assert!(out.contains("segment(s)") && out.contains("  identity"), "the biggest segments are listed: {out}");
    assert!(out.contains("messages: 8 (4 user, 4 assistant, 0 with tool results)"), "{out}");
    assert!(out.contains("largest messages:"), "{out}");
    assert!(out.contains("compaction: 0 so far"), "{out}");
    assert!(out.contains("compaction would drop") || out.contains("would drop nothing yet"), "{out}");
    assert!(out.contains("/compact --preview"), "{out}");

    // Never panics on a session id that does not exist.
    let ghost = text(&t, "/context", Some("nope"));
    assert!(ghost.contains("no session yet"), "{ghost}");
}

#[test]
fn context_counts_a_pruned_tool_result_and_an_active_compaction() {
    let t = kit("context-tools", |c| c.compaction.keep_messages = 2, None);
    let sid = session(&t);
    push_message(&t, &sid, Message::user("go"));
    push_message(&t, &sid, Message::assistant("working"));
    let mut log = t.k.store.open(&sid).unwrap();
    log.append(EventKind::Message { message: Message { role: Role::User, content: vec![Block::ToolResult { tool_use_id: "t1".into(), content: "x".repeat(4000), is_error: false }] }, usage: None, model: None, inbox: None }).unwrap();
    log.append(EventKind::Message { message: Message::assistant("done"), usage: None, model: None, inbox: None }).unwrap();
    drop(log);
    let out = text(&t, "/context", Some(&sid));
    assert!(out.contains("1 with tool results"), "{out}");
    assert!(out.contains("compaction would drop 1 message(s)"), "the plan names the dropped messages: {out}");
}

// ───────────── 2. /compact + /compress ─────────────

fn good_summary() -> String {
    format!("{}\nfix the parser\n{}\nedited src/a.rs, tests pass\n{}\nuses cargo\n{}\nsrc/a.rs\n{}\nnone", crate::compaction::HEADINGS[0], crate::compaction::HEADINGS[1], crate::compaction::HEADINGS[2], crate::compaction::HEADINGS[3], crate::compaction::HEADINGS[4])
}

fn long_history(k: &Kit, sid: &str) {
    for i in 0..6 {
        push_message(k, sid, Message::user(format!("step {i}: {}", "please fix the parser bug in src/a.rs ".repeat(10))));
        push_message(k, sid, Message::assistant(format!("did step {i} {}", "…detail…".repeat(20))));
    }
}

#[test]
fn compact_command_reports_before_and_after() {
    let t = kit("compact", |_| {}, None);
    t.p.when("Summarise the conversation", &good_summary());
    let sid = session(&t);
    long_history(&t, &sid);
    assert_eq!(compaction_count(&t, &sid), 0);

    let out = text(&t, "/compact", Some(&sid));
    assert!(out.contains("Compressed: 12 → "), "{out}");
    assert!(out.contains("Approx request size: ~") && out.contains(" → ~"), "{out}");
    assert_eq!(compaction_count(&t, &sid), 1, "a full compaction ran");
    assert!(project(&t.k.store.read(&sid).unwrap()).messages.len() < 12);

    // `/compress` is the same command (Hermes alias).
    t.p.when("Summarise the conversation", &good_summary());
    long_history(&t, &sid);
    let out = text(&t, "/compress", Some(&sid));
    assert!(out.contains("Compressed:"), "{out}");
    assert_eq!(compaction_count(&t, &sid), 2);

    // Too short to compact: honest no-op.
    let fresh = session(&t);
    push_message(&t, &fresh, Message::user("hi"));
    assert!(text(&t, "/compact", Some(&fresh)).contains("Nothing to compress yet."));
}

#[test]
fn compress_preview_changes_nothing_and_here_keeps_the_tail() {
    let t = kit("compress-plan", |_| {}, None);
    t.p.when("Summarise the conversation", &good_summary());
    let sid = session(&t);
    for i in 0..4 {
        push_message(&t, &sid, Message::user(format!("ask {i}")));
        push_message(&t, &sid, Message::assistant(format!("reply {i}")));
    }
    let before = event_count(&t, &sid);

    let preview = text(&t, "/compact --preview", Some(&sid));
    assert!(preview.contains("Preview — no changes made."), "{preview}");
    assert!(preview.contains("Would compress ") && preview.contains("message(s)"), "{preview}");
    assert!(preview.contains("Run the command again without --preview to apply."), "{preview}");
    assert_eq!(event_count(&t, &sid), before, "--preview writes nothing");
    assert_eq!(compaction_count(&t, &sid), 0);

    // `here 1` summarises everything before the last exchange and keeps that tail verbatim.
    let here = text(&t, "/compress here 1", Some(&sid));
    assert!(here.contains("Compressed 6 of 8 messages, keeping the last 1 exchange(s) (2 message(s)) verbatim."), "{here}");
    assert!(here.contains("Approx request size: ~"), "{here}");
    assert_eq!(compaction_count(&t, &sid), 1, "a partial compaction ran");
    let after = project(&t.k.store.read(&sid).unwrap());
    // The summary is a user-role message and the tail starts on a user ask, so projection folds
    // them into one message (the seam Hermes' `rejoin_compressed_head_and_tail` also guards);
    // the kept reply stays byte-identical.
    let texted: Vec<String> = after.messages.iter().map(|m| m.text()).collect();
    assert_eq!(texted.len(), 2, "{texted:?}");
    assert!(texted[0].starts_with("[Summary of earlier conversation]") && texted[0].ends_with("ask 3"), "{texted:?}");
    assert_eq!(texted[1], "reply 3", "the kept tail is byte-identical");
    assert!(after.messages.len() < 8);

    // A split that would keep everything falls back to full compaction (never a no-op rotation).
    let short = session(&t);
    push_message(&t, &short, Message::user("only one ask"));
    push_message(&t, &short, Message::assistant("only one answer"));
    push_message(&t, &short, Message::user("second ask"));
    push_message(&t, &short, Message::assistant("second answer"));
    let deg = text(&t, "/compress here 5 --preview", Some(&short));
    assert!(deg.contains("would keep everything") || deg.contains("falling back to full"), "{deg}");

    // `--aggressive` is refused, not treated as a focus topic.
    assert!(text(&t, "/compress --aggressive", Some(&sid)).contains("--aggressive is not supported"));
    assert_eq!(compaction_count(&t, &sid), 1, "a refusal changes nothing");
    // No session: clear refusal instead of a panic.
    assert!(text(&t, "/compact", None).contains("No session yet"));
}

#[test]
fn compress_argument_parsing_follows_upstream() {
    let p = crate::ctxhost::slash::parse_compress("here 4");
    assert!(p.partial && p.keep_last == 4 && !p.preview && p.focus.is_none(), "{p:?}");
    assert_eq!(crate::ctxhost::slash::parse_compress("up to here 3").keep_last, 3);
    assert_eq!(crate::ctxhost::slash::parse_compress("here").keep_last, DEFAULT_KEEP_LAST);
    assert_eq!(crate::ctxhost::slash::parse_compress("here 9999").keep_last, MAX_KEEP_LAST);
    assert_eq!(crate::ctxhost::slash::parse_compress("here 0").keep_last, 1);
    assert_eq!(crate::ctxhost::slash::parse_compress("--keep 5").keep_last, 5);
    assert_eq!(crate::ctxhost::slash::parse_compress("-k 2").keep_last, 2);
    assert_eq!(crate::ctxhost::slash::parse_compress("--keep=7").keep_last, 7);
    let p = crate::ctxhost::slash::parse_compress("--preview here 2");
    assert!(p.preview && p.partial && p.keep_last == 2, "{p:?}");
    let p = crate::ctxhost::slash::parse_compress("the auth refactor");
    assert!(!p.partial && p.focus.as_deref() == Some("the auth refactor"), "{p:?}");
    let p = crate::ctxhost::slash::parse_compress("--dry-run");
    assert!(p.preview && !p.partial);
}

// ───────────── 3. /title ─────────────

fn titler(reply: &'static str) -> super::title::Titler {
    Arc::new(move |_input: &str| Ok(reply.to_string()))
}

#[test]
fn title_command_sets_shows_and_generates() {
    let t = kit("title", |_| {}, Some(titler(r#"{"title": "Fix the login button"}"#)));
    assert!(text(&t, "/title", None).contains("No session yet"));
    let sid = session(&t);
    assert!(text(&t, "/title", Some(&sid)).contains("no title yet"), "nothing to name yet");

    push_message(&t, &sid, Message::user("the login button does nothing on mobile"));
    push_message(&t, &sid, Message::assistant("patched it"));
    let gen = text(&t, "/title", Some(&sid));
    assert!(gen.contains("Generated title: Fix the login button"), "{gen}");
    assert_eq!(title_of(&t, &sid).as_deref(), Some("Fix the login button"));
    assert!(text(&t, "/title", Some(&sid)).contains("Title: Fix the login button"));

    let set = text(&t, "/title Deploy   checklist", Some(&sid));
    assert!(set.contains("Title set: Deploy checklist"), "whitespace is collapsed: {set}");
    assert_eq!(title_of(&t, &sid).as_deref(), Some("Deploy checklist"));
    assert!(text(&t, "/title", Some(&sid)).contains("Title: Deploy checklist"));

    // A newline in the argument cannot reach the log.
    text(&t, "/title a\nb", Some(&sid));
    assert_eq!(title_of(&t, &sid).as_deref(), Some("a b"));
    assert!(text(&t, "/title    ", Some(&sid)).contains("Title: a b"));
    let long = "x".repeat(200);
    text(&t, &format!("/title {long}"), Some(&sid));
    assert_eq!(title_of(&t, &sid).unwrap().chars().count(), super::title::MAX_TITLE_CHARS);
}

// ───────────── 5. /btw ─────────────

#[test]
fn btw_answers_from_a_snapshot_without_touching_the_session() {
    let t = kit("btw", |_| {}, None);
    t.p.when("Side question: what did we decide?", "We picked Postgres for storage.");
    let sid = session(&t);
    for i in 0..8 {
        push_message(&t, &sid, Message::user(format!("turn {i}")));
        push_message(&t, &sid, Message::assistant(format!("reply {i}")));
    }
    let before = event_count(&t, &sid);
    let reply = slash(&t, "/btw what did we decide?", Some(&sid)).unwrap();
    assert_eq!(reply.text.as_deref(), Some("We picked Postgres for storage."));
    assert_eq!(event_count(&t, &sid), before, "/btw appends nothing to the session");
    assert!(reply.prompt.is_none(), "no prompt is sent to the session");

    let req = t.p.requests().last().cloned().expect("one request");
    assert!(req.tools.is_empty(), "tools are disabled for the side question");
    assert_eq!(req.model, "m", "the aux/default model answers, not a tool-capable request");
    assert!(req.max_tokens <= crate::ctxhost::slash::SIDE_MAX_TOKENS);
    let user = req.messages.last().unwrap().text();
    assert!(user.contains(crate::ctxhost::slash::BTW_PROMPT) && user.contains("Side question: what did we decide?"), "{user}");
    assert!(req.messages.len() <= t.k.cfg.compaction.keep_messages + 1, "the snapshot is bounded: {}", req.messages.len());

    // Guards.
    assert!(text(&t, "/btw", Some(&sid)).contains("usage: /btw <question>"));
    assert_eq!(slash(&t, "/btw still there?", None).unwrap_err(), "no session yet — send a message first");
}

#[test]
fn btw_prefers_the_configured_side_question_model() {
    let t = kit("btw-model", |c| {
        c.model.aux = "fake/aux".into();
        c.context.side_question_model = "fake/side".into();
    }, None);
    t.p.when("Side question:", "side answer");
    let sid = session(&t);
    push_message(&t, &sid, Message::user("hello"));
    push_message(&t, &sid, Message::assistant("hi"));
    assert!(text(&t, "/btw why?", Some(&sid)).contains("side answer"));
    assert_eq!(t.p.requests().last().unwrap().model, "side");
    let cfg = t.k.cfg_now();
    assert_eq!(crate::ctxhost::slash::side_model(&t.k, &cfg, "fake/m"), "fake/side");
}

#[test]
fn btw_snapshot_trims_a_mid_turn_tail() {
    let mut msgs = vec![Message::user("go"), Message::assistant("done")];
    msgs.push(Message { role: Role::Assistant, content: vec![Block::ToolUse { id: "t".into(), name: "read".into(), input: json!({}) }] });
    msgs.push(Message { role: Role::User, content: vec![Block::ToolResult { tool_use_id: "t".into(), content: "x".into(), is_error: false }] });
    let view = crate::projection::View { messages: msgs, ..Default::default() };
    let snap = crate::ctxhost::slash::side_snapshot(&view, 8);
    assert_eq!(snap.len(), 2, "the unresolved tail is dropped: {snap:?}");
    assert!(snap.last().unwrap().text().contains("done"));
    // Message-count bound survives trimming.
    let mut many = Vec::new();
    for i in 0..20 {
        many.push(Message::user(format!("q{i}")));
        many.push(Message::assistant(format!("a{i}")));
    }
    let view = crate::projection::View { messages: many, ..Default::default() };
    assert_eq!(crate::ctxhost::slash::side_snapshot(&view, 4).len(), 4);
}

// ───────────── 4. automatic titles ─────────────

/// Poll until the session's title equals `want` (background threads), then return it.
fn wait_title(k: &Kit, sid: &str, want: &str, secs: u64) -> Option<String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        let cur = title_of(k, sid);
        if cur.as_deref() == Some(want) {
            return cur;
        }
        if std::time::Instant::now() >= deadline {
            return cur;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[test]
fn auto_title_fills_an_untitled_session_after_the_first_turn() {
    let t = kit("auto-title", |_| {}, Some(titler(r#"{"title": "Fix the login button"}"#)));
    let sid = session(&t);
    t.att.on_turn_end(&sid, "the login button does nothing on mobile", "patched it, tests pass", true);
    assert_eq!(wait_title(&t, &sid, "Fix the login button", 5).as_deref(), Some("Fix the login button"));

    // A name the person set is never overwritten.
    let named = session(&t);
    t.k.set_title(&named, "My own name").unwrap();
    t.att.on_turn_end(&named, "unrelated work", "sure", true);
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(title_of(&t, &named).as_deref(), Some("My own name"));

    // A failed turn, an untitleable opener and `title_generation = false` skip naming entirely.
    for (tag, mut_cfg, ok, user) in [
        ("auto-title-failed", 0, false, "a real question about the parser"),
        ("auto-title-machine", 0, true, "[Summary of earlier conversation]\nstuff"),
        ("auto-title-off", 1, true, "a real question about the parser"),
    ] {
        let t2 = kit(tag, |c| {
            if mut_cfg == 1 { c.context.title_generation = false }
        }, Some(titler(r#"{"title": "Should not appear"}"#)));
        let s = session(&t2);
        t2.att.on_turn_end(&s, user, "answer", ok);
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(title_of(&t2, &s), None, "{tag} must not be titled");
    }

    // `title_model_upgrade = false` keeps the instant title (stage 1) and skips the model call.
    let t3 = kit("auto-title-noupgrade", |c| c.context.title_model_upgrade = false, Some(titler(r#"{"title": "Should not appear"}"#)));
    let s3 = session(&t3);
    t3.att.on_turn_end(&s3, "the login button does nothing on mobile", "patched", true);
    assert_eq!(wait_title(&t3, &s3, "the login button does nothing on mobile", 5).as_deref(), Some("the login button does nothing on mobile"));
}

#[test]
fn auto_title_never_blocks_the_turn_and_falls_back_on_a_bad_reply() {
    // A slow model: `turn_end` returns immediately, the title lands later.
    let slow: super::title::Titler = Arc::new(|_| {
        std::thread::sleep(std::time::Duration::from_millis(400));
        Ok(r#"{"title": "Refactor the parser"}"#.to_string())
    });
    let t = kit("auto-title-slow", |_| {}, Some(slow));
    let sid = session(&t);
    let started = std::time::Instant::now();
    t.att.on_turn_end(&sid, "refactor the parser please", "done", true);
    assert!(started.elapsed() < std::time::Duration::from_millis(150), "turn_end blocked for {:?}", started.elapsed());
    assert_ne!(title_of(&t, &sid).as_deref(), Some("Refactor the parser"), "the model title is never written inline");
    assert_eq!(wait_title(&t, &sid, "Refactor the parser", 5).as_deref(), Some("Refactor the parser"));

    // An unusable reply: the derived title (a slice of the user's own words) is stored instead.
    let bad: super::title::Titler = Arc::new(|_| Ok("I'm sorry, I don't have enough context to name this conversation at all here.".into()));
    let t2 = kit("auto-title-bad", |_| {}, Some(bad));
    let s2 = session(&t2);
    t2.att.on_turn_end(&s2, "fix the flaky upload test on CI", "fixed", true);
    assert_eq!(wait_title(&t2, &s2, "fix the flaky upload test on CI", 5).as_deref(), Some("fix the flaky upload test on CI"));

    // A failing model falls back the same way.
    let err: super::title::Titler = Arc::new(|_| Err("no provider".into()));
    let t3 = kit("auto-title-err", |_| {}, Some(err));
    let s3 = session(&t3);
    t3.att.on_turn_end(&s3, "add a health endpoint", "added", true);
    assert_eq!(wait_title(&t3, &s3, "add a health endpoint", 5).as_deref(), Some("add a health endpoint"));
}

#[test]
fn title_prompt_parse_and_guards() {
    let p = super::title::prompt("");
    assert!(p.contains("same language as the user's message") && p.contains("\"title\""), "{p}");
    assert!(super::title::prompt("Chinese").contains("Write the title in Chinese."));

    assert_eq!(super::title::parse_title(r#"{"title": "Fix login button"}"#).as_deref(), Some("Fix login button"));
    assert_eq!(super::title::parse_title("```json\n{\"title\": \"Fix login\"}\n```").as_deref(), Some("Fix login"));
    assert_eq!(super::title::parse_title("Sure: {\"title\": \"Fix login\"}").as_deref(), Some("Fix login"));
    assert_eq!(super::title::parse_title("Title: Fix the parser\nmore").as_deref(), Some("Fix the parser"));
    assert_eq!(super::title::parse_title("{\"title\": \"trunca"), None, "truncated JSON is never a title");
    assert_eq!(super::title::parse_title("   "), None);

    assert_eq!(super::title::derive_title("  \n  fix the parser please and also "), Some("fix the parser please and also".into()));
    let long = "word ".repeat(40);
    let d = super::title::derive_title(&long).unwrap();
    assert!(d.chars().count() <= super::title::MAX_TITLE_CHARS + 1 && d.ends_with('…'), "{d}");
    assert_eq!(super::title::derive_title("[Summary of earlier conversation]\nold"), None);
    assert_eq!(super::title::derive_title("<command-message>deploy</command-message> ship it"), Some("ship it".into()));
    assert_eq!(super::title::strip_wrappers("<system-reminder>ignore</system-reminder> real ask"), "real ask");

    assert_eq!(super::title::clean_title("\"Fix login button.\"").as_deref(), Some("Fix login button"));
    assert!(super::title::plausible("Fix the login button"));
    assert!(!super::title::plausible("Code changes"), "a prompt example is not a title");
    assert!(!super::title::plausible(&"word ".repeat(20)), "answer-shaped output is rejected, not truncated");
    assert_eq!(super::title::build_input("the ask", "the reply\nsecond line"), "the ask\n\nAssistant replied:\nthe reply");
    assert!(super::title::build_input(&"x".repeat(5000), "y").chars().count() <= super::title::MAX_INPUT_CHARS + super::title::MAX_REPLY_CHARS + 40);
}

// ───────────── registration ─────────────

#[test]
fn every_context_command_is_registered_and_unknown_names_fall_through() {
    let t = kit("register", |_| {}, None);
    let names: Vec<String> = t.k.slash_commands().into_iter().map(|(n, _)| n).collect();
    for want in ["context", "compact", "compress", "title", "btw", "personality"] {
        assert!(names.iter().any(|n| n == want), "{want} is missing from {names:?}");
    }
    assert!(t.k.run_slash("/not-a-command", None, "cli").is_none());
    // The aliases Hermes and the CLI use resolve to the same handlers.
    let sid = session(&t);
    assert!(text(&t, "/ctx", Some(&sid)).starts_with("Context — session"));
    assert!(slash(&t, "/side are you there?", Some(&sid)).is_ok());
    assert!(text(&t, "/name A title", Some(&sid)).contains("Title set: A title"));
}

#[test]
fn attach_keeps_no_strong_reference_to_the_kernel() {
    // A leaked `Arc<Runtime>` inside the slash handlers would keep the session store alive forever;
    // the host holds a `Weak` and the attach handle is the only strong owner besides the test.
    let root = temp_root("weak");
    let ws = root.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let paths = crate::config::Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run") };
    let cfg = Config::default();
    let p = Arc::new(Scripted { steps: Mutex::new(VecDeque::new()), rules: Mutex::new(vec![]), seen: Mutex::new(vec![]) });
    let k = new_kernel(cfg, paths, Arc::new(Res(p)), vec![], Arc::new(crate::vault::Vault::empty()), Arc::new(crate::approver::Policy { allow_privilege: true, allow_egress: true }));
    let att = attach(&k, &ws);
    let weak = Arc::downgrade(&k);
    drop(k);
    assert!(weak.upgrade().is_none(), "the kernel is not kept alive by what attach() registered");
    assert!(att.host.kernel().is_none(), "and the host degrades gracefully");
    assert!(att.host.cfg().is_none());
    drop(att);
}

// ───────────── /role, the role segment and the role hook (crate::roles) ─────────────

fn cleanup(t: &Kit) {
    if let Some(root) = t.paths.data.parent() {
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn identity_always_carries_the_core_and_config_role_adds_a_segment() {
    let t = kit("role-core", |_| {}, None);
    let sid = session(&t);
    let id = seg(&t, &sid, "identity").unwrap();
    assert!(id.contains("# Professional conduct") && id.contains("professional of record"), "L0 in the identity");
    assert!(seg(&t, &sid, "role").is_none(), "default agent = L0 only");
    cleanup(&t);

    let t = kit("role-cfg", |c| c.role.active = "devops".into(), None);
    let sid = session(&t);
    let r = seg(&t, &sid, "role").expect("role segment");
    assert!(r.contains("[role:devops]") && r.contains("ISCO 2522"), "{r}");
    let ctx = text(&t, "/context", Some(&sid));
    assert!(ctx.contains("role: DevOps") && ctx.contains("L0 ~") && ctx.contains("L2 ~"), "{ctx}");
    cleanup(&t);
}

#[test]
fn role_slash_switches_the_live_session_and_new_ones() {
    let t = kit("role-slash", |_| {}, None);
    let sid = session(&t);
    assert!(text(&t, "/role", Some(&sid)).contains("role: none"));
    assert!(text(&t, "/role list", None).contains("itsupport"));
    let many = text(&t, "/role 2149", Some(&sid));
    assert!(many.contains("several roles"), "{many}");
    let out = text(&t, "/role 2512", Some(&sid));
    assert!(out.contains("software-developer") && out.contains("rewritten"), "{out}");
    assert!(seg(&t, &sid, "role").unwrap().contains("[role:software-developer]"));
    // New sessions of this process follow the choice.
    let sid2 = session(&t);
    assert!(seg(&t, &sid2, "role").unwrap().contains("[role:software-developer]"));
    assert!(text(&t, "/role show", Some(&sid)).contains("ISCO 2512"));
    // Back to none: the segment goes, in the live session and in new ones.
    text(&t, "/role none", Some(&sid));
    assert!(seg(&t, &sid, "role").is_none());
    assert!(seg(&t, &session(&t), "role").is_none());
    assert!(t.k.hook_names().iter().any(|n| n == "role"), "the role hook is installed by attach");
    cleanup(&t);
}

#[test]
fn regulated_role_hands_reserved_acts_back_to_a_human() {
    let t = kit("role-boundary", |c| c.context.title_generation = false, None);
    let sid = session(&t);
    text(&t, "/role bedside-nursing", Some(&sid));
    // Final reply that performs a reserved act → the kernel asks for a rewrite; the rewrite passes.
    t.p.steps.lock().unwrap().extend(["我現在幫你注射胰島素 10 單位。".to_string(), "我整理了觀察紀錄，請由執業護理師依醫囑給藥。".to_string()]);
    t.k.submit(&sid, "幫我打胰島素", "cli").unwrap();
    t.k.run(&sid, crate::kernel::RunOpts::default()).unwrap();
    let revisions = |t: &Kit| t.p.requests().iter().filter(|r| r.messages.last().is_some_and(|m| m.text().contains("Reserved act"))).count();
    assert_eq!(revisions(&t), 1, "one revision");
    let revise = t.p.requests().iter().map(|r| r.messages.last().unwrap().text()).find(|x| x.contains("Reserved act")).unwrap();
    assert!(revise.contains("licensed nurse"), "{revise}");
    let v = project(&t.k.store.read(&sid).unwrap());
    assert!(v.messages.last().unwrap().text().contains("執業護理師"));

    // An ordinary answer in the same role is not touched.
    t.p.steps.lock().unwrap().push_back("血壓 128/82，已記錄並交班。".into());
    t.k.submit(&sid, "記錄血壓", "cli").unwrap();
    t.k.run(&sid, crate::kernel::RunOpts::default()).unwrap();
    assert_eq!(revisions(&t), 1, "no revision for ordinary work");
    assert!(project(&t.k.store.read(&sid).unwrap()).messages.last().unwrap().text().contains("已記錄並交班"));
    cleanup(&t);
}

#[test]
fn role_hook_refuses_policy_denied_tool_calls_per_session() {
    use crate::hooks::{Hook, HookDecision, HookEvent};
    let t = kit("role-hook", |_| {}, None);
    let plain = session(&t);
    let data = session(&t);
    text(&t, "/role data", Some(&data));
    let hook = crate::roles::hook::RoleHook::new(Arc::downgrade(&t.k));
    let call = |sid: &str, cmd: &str| hook.run(HookEvent::PreTool, &json!({"session_id": sid, "tool_name": "shell", "tool_input": {"command": cmd}})).unwrap();
    assert!(matches!(call(&data, "psql -c 'DROP TABLE users'"), HookDecision::Block(r) if r.contains("read-only")));
    assert!(matches!(call(&data, "psql -c 'select 1'"), HookDecision::Allow));
    assert!(matches!(call(&plain, "psql -c 'DROP TABLE users'"), HookDecision::Allow), "no role, no role policy");
    cleanup(&t);
}

#[test]
fn named_agent_carries_its_occupation_and_tool_profile() {
    let t = kit("role-agent", |_| {}, None);
    crate::agents::add(&t.paths, "ops", crate::agents::AgentDef { name: "Ops".into(), role: "devops".into(), ..Default::default() }).unwrap();
    crate::agents::add(&t.paths, "lead", crate::agents::AgentDef { role: "coordinator".into(), ..Default::default() }).unwrap();
    let sid = t.k.create_agent_session(&ws_of(&t), Some("ops"), None, None, None, None).unwrap();
    assert!(seg(&t, &sid, "role").unwrap().contains("[role:devops]"));
    let v = project(&t.k.store.read(&sid).unwrap());
    let allow = v.tool_allow.expect("devops tool profile narrows the tools");
    assert!(allow.iter().any(|x| x == "shell") && !allow.iter().any(|x| x == "node_invoke"), "{allow:?}");
    // A team seed is not an occupation.
    let sid2 = t.k.create_agent_session(&ws_of(&t), Some("lead"), None, None, None, None).unwrap();
    assert!(seg(&t, &sid2, "role").is_none());
    // An unknown occupation fails loudly instead of running without its rules.
    crate::agents::add(&t.paths, "bad", crate::agents::AgentDef { role: "no-such-role".into(), ..Default::default() }).unwrap();
    assert!(t.k.create_agent_session(&ws_of(&t), Some("bad"), None, None, None, None).is_err());
    cleanup(&t);
}
