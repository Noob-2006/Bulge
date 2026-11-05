//! The skills system reached the way a user reaches it: through a real kernel — the index frozen
//! into the session's system prompt plus its live delta note on the next turn's user message, and
//! the `/skills` + `/<skill>` native commands registered by `ark_skills::core::attach`.

use ark_core::*;
use ark_kernel::approver::{Approval, ApprovalRequest, Approver};
use ark_kernel::config::{Config, Paths};
use ark_kernel::kernel::{new_kernel, Kernel, RunOpts, Resolver};
use ark_kernel::projection::project;
use ark_kernel::vault::Vault;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// ───────────── scripted provider ─────────────

struct Scripted {
    seen: Mutex<Vec<ModelRequest>>,
}

impl Scripted {
    fn new() -> Arc<Self> {
        Arc::new(Scripted { seen: Mutex::new(vec![]) })
    }
    /// The request of turn `i` (0-based).
    fn turn(&self, i: usize) -> ModelRequest {
        self.seen.lock().unwrap()[i].clone()
    }
}

impl Provider for Scripted {
    fn id(&self) -> &str {
        "fake"
    }
    fn caps(&self, _: &str) -> ModelCaps {
        ModelCaps { context_window: 200_000, max_output: 8192, tools: true, vision: true, explicit_cache: false }
    }
    fn complete(&self, req: &ModelRequest, _: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
        self.seen.lock().unwrap().push(req.clone());
        Ok(ModelResponse {
            message: Message { role: Role::Assistant, content: vec![Block::text("ok")] },
            stop: StopReason::EndTurn,
            usage: Usage { input_tokens: 10, output_tokens: 2, ..Default::default() },
            model: String::new(),
        })
    }
}

struct Res(Arc<Scripted>);
impl Resolver for Res {
    fn provider(&self, _: &str) -> Result<Arc<dyn Provider>, String> {
        Ok(self.0.clone())
    }
}

struct Yes;
impl Approver for Yes {
    fn approve(&self, _: &ApprovalRequest) -> Approval {
        Approval::Always
    }
    fn ask(&self, _: &str, _: &str) -> Result<String, String> {
        Err("headless".into())
    }
}

// ───────────── fixture ─────────────

struct Fixture {
    root: PathBuf,
    paths: Paths,
    ws: PathBuf,
    cfg: Config,
}

fn fixture(tag: &str) -> Fixture {
    let root = ark_core::tmp::scratch_path(format!("ark-skills-live-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run") };
    let ws = root.join("ws");
    std::fs::create_dir_all(ws.join(".ark/skills")).unwrap();
    let mut cfg = Config::default();
    cfg.model.default = "fake/m1".into();
    cfg.checkpoint.enabled = false;
    cfg.learn.enabled = false;
    Fixture { root, paths, ws, cfg }
}

impl Fixture {
    fn skill(&self, name: &str, body: &str) {
        let d = self.ws.join(".ark/skills").join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("SKILL.md"), format!("---\nname: {name}\ndescription: {name} things\n---\n{body}\n")).unwrap();
    }
    /// A skill that declares a required environment variable.
    fn skill_with_env(&self, name: &str, env: &str, body: &str) {
        let d = self.ws.join(".ark/skills").join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("SKILL.md"), format!("---\nname: {name}\ndescription: {name} things\nrequired_environment_variables: [{env}]\n---\n{body}\n")).unwrap();
    }
    /// A skill in the agent's own library (`<data>/skills`) — the only place the guarded writer
    /// creates/patches, and what `/refine` refines.
    fn user_skill(&self, name: &str, body: &str) {
        let d = self.paths.data.join("skills").join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("SKILL.md"), format!("---\nname: {name}\ndescription: {name} things\n---\n\n{body}\n")).unwrap();
    }
    fn kernel(&self, p: Arc<Scripted>) -> Kernel {
        new_kernel(self.cfg.clone(), self.paths.clone(), Arc::new(Res(p)), vec![], Arc::new(Vault::empty()), Arc::new(Yes))
    }
}

fn view(k: &Kernel, id: &str) -> ark_kernel::projection::View {
    project(k.store.open(id).unwrap().events())
}

fn last_user(req: &ModelRequest) -> String {
    req.messages.iter().rev().find(|m| m.role == Role::User).map(|m| m.text()).unwrap_or_default()
}

#[test]
fn skills_index_freezes_into_the_prompt_and_delivers_a_delta_note() {
    let f = fixture("index");
    f.skill("alpha", "Alpha body.");
    let p = Scripted::new();
    let k = f.kernel(p.clone());
    // The real wiring: host::attach → core::attach (lifecycle + slash commands).
    ark_skills::host::attach(&k, &f.ws);
    let id = k.create_session(&f.ws, None, None, Some("t")).unwrap();

    let system = view(&k, &id).system;
    // One `skills` segment only: the lifecycle's index replaces the kernel's builtin one (same id).
    assert_eq!(system.iter().filter(|s| s.id == "skills").count(), 1, "{system:?}");
    let seg = system.iter().find(|s| s.id == "skills").expect("the skills segment is part of the frozen prompt");
    assert!(seg.text.contains("<available_skills>") && seg.text.contains("- alpha: alpha things"), "{}", seg.text);

    // Installed after the prompt was built (hub install / skill tool / another process).
    f.skill("beta", "Beta body.");
    k.submit(&id, "hi", "user").unwrap();
    k.run(&id, RunOpts::default()).unwrap();
    let t0 = p.turn(0);
    assert!(t0.system.iter().any(|s| s.id == "skills" && !s.text.contains("beta")), "the cached prefix keeps the old index");
    let user = last_user(&t0);
    assert!(user.starts_with("hi"), "{user}");
    assert!(user.contains(ark_skills::core::index::NOTE_PREFIX) && user.contains("- beta: beta things"), "delta note rides the turn: {user}");
    assert!(!user.contains("No longer available"), "{user}");

    // Announced once: the next turn is clean, and the note was not repeated.
    k.submit(&id, "again", "user").unwrap();
    k.run(&id, RunOpts::default()).unwrap();
    assert!(!last_user(&p.turn(1)).contains(ark_skills::core::index::NOTE_PREFIX), "sent once");

    // A removal after the note still describes the full difference against the prompt.
    std::fs::remove_dir_all(f.ws.join(".ark/skills/alpha")).unwrap();
    k.submit(&id, "third", "user").unwrap();
    k.run(&id, RunOpts::default()).unwrap();
    let user = last_user(&p.turn(2));
    assert!(user.contains("- beta:") && user.contains("No longer available: alpha"), "{user}");
    let _ = std::fs::remove_dir_all(&f.root);
}

#[test]
fn slash_commands_load_skills_from_the_kernel() {
    let f = fixture("slash");
    f.skill("deploy", "Deploy with ${ARK_SKILL_DIR}/run.sh");
    f.skill("review", "Review carefully.");
    f.skill("status", "A skill that must never shadow /status.");
    let p = Scripted::new();
    let k = f.kernel(p.clone());
    ark_skills::host::attach(&k, &f.ws);
    let id = k.create_session(&f.ws, None, None, Some("t")).unwrap();

    // /skills — the command set, from the registration path (not a direct call).
    assert!(k.slash_commands().iter().any(|(n, _)| n == "skills"), "registered with the kernel");
    let help = k.run_slash("/skills help", Some(&id), "cli").unwrap().unwrap().text.unwrap();
    assert!(help.contains("/skills list") && help.contains("setup <name>"), "{help}");
    let list = k.run_slash("/skills list", Some(&id), "cli").unwrap().unwrap().text.unwrap();
    assert!(list.contains("deploy") && list.contains("review"), "{list}");

    // /<skill> — preprocessing (${ARK_SKILL_DIR}) plus the typed instruction.
    let r = k.run_slash("/deploy now please", Some(&id), "cli").unwrap().unwrap();
    let prompt = r.prompt.expect("a /skill invocation sends a prompt");
    assert!(prompt.starts_with("[IMPORTANT: The user has invoked the \"deploy\" skill"), "{prompt}");
    assert!(prompt.contains(&format!("Deploy with {}/run.sh", f.ws.join(".ark/skills/deploy").display())), "template var expanded: {prompt}");
    assert!(prompt.contains("[Skill directory:") && prompt.ends_with("skill invocation: now please"), "{prompt}");

    // Stacked /<a> /<b> instruction.
    let r = k.run_slash("/deploy /review and ship it", Some(&id), "cli").unwrap().unwrap();
    let stacked = r.prompt.unwrap();
    assert!(stacked.contains("loading 2 skills together") && stacked.contains("Skills loaded: deploy, review"), "{stacked}");
    assert!(stacked.contains("Review carefully.") && stacked.contains("User instruction: and ship it"), "{stacked}");

    // /<bundle> — every member in one message.
    let st = ark_skills::core::settings::Store::new(&f.paths);
    ark_skills::core::bundles::save(&st, "ship", &["deploy".into(), "gone".into()], "", "", false).unwrap();
    let b = k.run_slash("/ship go", Some(&id), "cli").unwrap().unwrap().prompt.unwrap();
    assert!(b.contains("\"ship\" skill bundle") && b.contains("Skills missing (skipped): gone"), "{b}");

    // A collected secret (the file `ark skills setup` writes) makes the skill ready and reaches
    // its commands.
    f.skill_with_env("ops", "ARK_T_OPS_TOKEN", "Run the ops checklist.");
    // /skills setup <name> needs a terminal; the slash surface says how to do it instead.
    let e = k.run_slash("/skills setup ops", Some(&id), "cli").unwrap().unwrap_err();
    assert!(e.contains("interactive terminal") && e.contains("ark secrets set"), "{e}");
    let p1 = k.run_slash("/ops", Some(&id), "cli").unwrap().unwrap().prompt.unwrap();
    assert!(p1.contains("[Skill setup note: Setup needed before using this skill: missing env $ARK_T_OPS_TOKEN."), "{p1}");
    std::fs::create_dir_all(&f.paths.config_dir).unwrap();
    Vault::load(&f.paths.secrets()).unwrap().set("ARK_T_OPS_TOKEN", "ops-tok").unwrap();
    let p2 = k.run_slash("/ops", Some(&id), "cli").unwrap().unwrap().prompt.unwrap();
    assert!(!p2.contains("Skill setup note"), "ready once the vault has the value: {p2}");
    assert_eq!(std::env::var("ARK_T_OPS_TOKEN").as_deref(), Ok("ops-tok"), "the skill's commands see it");

    // A core command wins: /status is not the skill's.
    assert!(k.run_slash("/status", Some(&id), "cli").is_none(), "core commands are never shadowed");
    // An unknown name is not a skill invocation either.
    assert!(k.run_slash("/nope-x", Some(&id), "cli").is_none());
    let _ = std::fs::remove_dir_all(&f.root);
}

#[test]
fn skill_tool_loads_through_the_shared_module() {
    // `wire::tools`/`host::tools` replaces the builtin `skill` tool by name.
    let f = fixture("tool");
    f.skill("deploy", "Deploy with ${ARK_SKILL_DIR}/run.sh");
    let tools = ark_skills::host::tools(&f.cfg, &f.paths, &f.ws);
    let names: Vec<String> = tools.iter().map(|t| t.spec().name).collect();
    assert!(names.iter().any(|n| n == "skill"), "{names:?}");
    let t = tools.iter().find(|t| t.spec().name == "skill").unwrap();
    assert!(t.spec().description.contains("action=view"), "{}", t.spec().description);
    let _ = std::fs::remove_dir_all(&f.root);
}

// ───────────── the skills tool + the round-4 slash commands, through a kernel ─────────────

/// A skill no host can run (`requires.bins` names a missing binary) and a plugin-style local one.
fn gated_skill(f: &Fixture, name: &str, bin: &str) {
    let d = f.ws.join(".ark/skills").join(name);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("SKILL.md"), format!("---\nname: {name}\ndescription: {name} needs a tool\nmetadata:\n  openclaw:\n    requires:\n      bins: [{bin}]\n---\n{name} body\n")).unwrap();
}

struct NoHost;
impl ark_core::ToolHost for NoHost {
    fn spawn_agent(&self, _: ark_core::tool::SpawnRequest, _: &ark_core::Cancel) -> Result<String, String> {
        Err("no sub-agents in this test".into())
    }
    fn ask_user(&self, _: &str) -> Result<String, String> {
        Err("headless".into())
    }
}

#[test]
fn skill_tool_actions_list_search_patch_and_gating_from_the_kernel() {
    let f = fixture("actions");
    f.skill("deploy", "Deploy the service.");
    f.user_skill("notes", "Write things down.");
    gated_skill(&f, "needs-cli", "ark-absent-binary-xyz");
    let p = Scripted::new();
    let k = f.kernel(p);
    ark_skills::host::attach(&k, &f.ws);
    let id = k.create_session(&f.ws, None, None, Some("t")).unwrap();
    let tools = ark_skills::host::tools(&f.cfg, &f.paths, &f.ws);
    let tool = tools.iter().find(|t| t.spec().name == "skill").unwrap();
    let ctx = ToolCtx {
        workspace: f.ws.clone(),
        session_id: id.clone(),
        artifacts: f.ws.join(".ark/artifacts"),
        home: f.paths.data.clone(),
        cancel: Default::default(),
        host: std::sync::Arc::new(NoHost),
        secrets: std::sync::Arc::new(|s: &str| s.to_string()),
    };
    // The gated skill is hidden from the prompt index, list and search, and named by list verbose.
    let system = view(&k, &id).system;
    let seg = system.iter().find(|s| s.id == "skills").unwrap();
    assert!(seg.text.contains("- deploy: deploy things"), "{}", seg.text);
    assert!(!seg.text.contains("needs-cli"), "an unmet requirement hides the skill from the index: {}", seg.text);
    let list = tool.call(&ctx, serde_json::json!({"action": "list"}));
    assert!(list.content.contains("- deploy:") && !list.content.split("cannot run").next().unwrap_or("").contains("needs-cli"), "{}", list.content);
    let verbose = tool.call(&ctx, serde_json::json!({"action": "list", "verbose": true}));
    assert!(verbose.content.contains("needs-cli") && verbose.content.contains("bins: ark-absent-binary-xyz"), "{}", verbose.content);
    let gated = tool.call(&ctx, serde_json::json!({"action": "search", "query": "needs-cli"}));
    assert!(!gated.content.contains("- needs-cli:"), "an ineligible skill is never a search result: {}", gated.content);
    // An explicit load still reaches it (upstream `skill_view` ignores the gate for a named skill).
    let v = tool.call(&ctx, serde_json::json!({"action": "view", "name": "needs-cli"}));
    assert!(!v.is_error && v.content.contains("needs-cli body"), "{}", v.content);
    // patch writes through the guarded writer (the agent's own library only) and is ledgered.
    let out = tool.call(&ctx, serde_json::json!({"action": "patch", "name": "notes", "old_string": "Write things down.", "new_string": "Write things down, then file them."}));
    assert!(!out.is_error && out.content.contains("patched SKILL.md in skill `notes`"), "{}", out.content);
    assert!(out.content.contains("undo with `ark skills rollback"), "{}", out.content);
    assert!(std::fs::read_to_string(f.paths.data.join("skills/notes/SKILL.md")).unwrap().contains("then file them"));
    // A project skill is read-only here, with the way out.
    let denied = tool.call(&ctx, serde_json::json!({"action": "patch", "name": "deploy", "old_string": "Deploy the service.", "new_string": "x"}));
    assert!(denied.is_error && denied.content.contains("read-only here"), "{}", denied.content);
    let _ = std::fs::remove_dir_all(&f.root);
}

#[test]
fn skill_slash_command_loads_lists_and_searches() {
    let f = fixture("skillslash");
    f.skill("deploy", "Deploy the service.");
    f.skill("status", "A skill that must never shadow /status.");
    let p = Scripted::new();
    let k = f.kernel(p);
    ark_skills::host::attach(&k, &f.ws);
    let id = k.create_session(&f.ws, None, None, Some("t")).unwrap();
    // `/skill <name> [instruction]` is `/<name>` by another spelling.
    let r = k.run_slash("/skill deploy go live", Some(&id), "cli").unwrap().unwrap();
    let prompt = r.prompt.expect("/skill sends a prompt");
    assert!(prompt.starts_with("[IMPORTANT: The user has invoked the \"deploy\" skill") && prompt.ends_with("skill invocation: go live"), "{prompt}");
    // …and the escape hatch for a name a core command shadows.
    let r = k.run_slash("/skill status", Some(&id), "cli").unwrap().unwrap();
    assert!(r.prompt.unwrap().contains("A skill that must never shadow"), "an explicit /skill load wins");
    assert!(k.run_slash("/status", Some(&id), "cli").is_none(), "bare /status stays the core command");
    // `/skill list`, `/skill search`, `/skill view` map to the tool's actions.
    let list = k.run_slash("/skill list", Some(&id), "cli").unwrap().unwrap().text.unwrap();
    assert!(list.contains("- deploy: deploy things") && list.contains("skill action=view"), "{list}");
    let search = k.run_slash("/skill search deploy", Some(&id), "cli").unwrap().unwrap().text.unwrap();
    assert!(search.contains("match(es) for \"deploy\"") && search.contains("- deploy: deploy things"), "{search}");
    let v = k.run_slash("/skill view deploy", Some(&id), "cli").unwrap().unwrap().text.unwrap();
    assert!(v.starts_with(&format!("{}", f.ws.join(".ark/skills/deploy/SKILL.md").display())), "{v}");
    assert!(k.run_slash("/skill nope", Some(&id), "cli").unwrap().is_err());
    let usage = k.run_slash("/skill", Some(&id), "cli").unwrap().unwrap().text.unwrap();
    assert!(usage.contains("usage: /skill <name>"), "{usage}");
    let _ = std::fs::remove_dir_all(&f.root);
}

#[test]
fn reload_skills_reports_the_diff_and_the_next_turn_announces_it() {
    let f = fixture("reload");
    f.skill("alpha", "Alpha body.");
    let p = Scripted::new();
    let k = f.kernel(p.clone());
    ark_skills::host::attach(&k, &f.ws);
    let id = k.create_session(&f.ws, None, None, Some("t")).unwrap();
    let unchanged = k.run_slash("/reload-skills", Some(&id), "cli").unwrap().unwrap().text.unwrap();
    assert!(unchanged.starts_with("Skills reloaded.") && unchanged.contains("No new or removed skills."), "{unchanged}");
    f.skill("beta", "Beta body.");
    std::fs::remove_dir_all(f.ws.join(".ark/skills/alpha")).unwrap();
    let text = k.run_slash("/reload-skills", Some(&id), "cli").unwrap().unwrap().text.unwrap();
    assert!(text.contains("Added Skills:\n  - beta: beta things") && text.contains("Removed Skills:\n  - alpha"), "{text}");
    assert!(text.contains("The next turn tells the model what changed"), "{text}");
    // The frozen index is untouched; the delta note carries the same difference into the next turn.
    k.submit(&id, "hi", "user").unwrap();
    k.run(&id, RunOpts::default()).unwrap();
    let user = last_user(&p.turn(0));
    assert!(user.contains(ark_skills::core::index::NOTE_PREFIX) && user.contains("- beta:") && user.contains("No longer available: alpha"), "{user}");
    let _ = std::fs::remove_dir_all(&f.root);
}

#[test]
fn refine_proposes_from_the_sessions_steps_and_applies_on_request() {
    let mut f = fixture("refine");
    f.user_skill("deploy", "Deploy the service.");
    f.cfg.skills.insert("review".into(), toml::from_str("min_steps = 2").unwrap());
    let p = Scripted::new();
    let k = f.kernel(p);
    ark_skills::host::attach(&k, &f.ws);
    let id = k.create_session(&f.ws, None, None, Some("t")).unwrap();
    // Nothing ran yet in this session.
    let e = k.run_slash("/refine", Some(&id), "cli").unwrap().unwrap_err();
    assert!(e.contains("nothing recorded"), "{e}");
    // The review lifecycle records what ran (the same file `/refine` reads).
    let st = ark_skills::core::settings::Store::new(&f.paths);
    ark_skills::core::review::note_loaded(&st, Some(&id), "deploy");
    ark_skills::core::review::note_step(&st, &id, "shell", &serde_json::json!({"command": "ark deploy --region eu"}), false);
    // A proposal first: the file is untouched.
    let text = k.run_slash("/refine Rollout", Some(&id), "cli").unwrap().unwrap().text.unwrap();
    assert!(text.contains("Proposal for `deploy`") && text.contains("## Rollout\n1. Run `ark deploy --region eu`"), "{text}");
    assert!(!std::fs::read_to_string(f.paths.data.join("skills/deploy/SKILL.md")).unwrap().contains("## Rollout"), "the proposal is not written");
    // Then the same call with --apply writes it through the guarded writer.
    let applied = k.run_slash("/refine --apply Rollout", Some(&id), "cli").unwrap().unwrap().text.unwrap();
    assert!(applied.contains("rewrote SKILL.md of `deploy`"), "{applied}");
    assert!(std::fs::read_to_string(f.paths.data.join("skills/deploy/SKILL.md")).unwrap().contains("## Rollout"));
    let _ = std::fs::remove_dir_all(&f.root);
}

#[test]
fn curator_review_writes_candidate_procedures() {
    let mut f = fixture("review");
    f.cfg.skills.insert("review".into(), toml::from_str("min_steps = 2").unwrap());
    let p = Scripted::new();
    let k = f.kernel(p);
    ark_skills::host::attach(&k, &f.ws);
    let id = k.create_session(&f.ws, None, None, Some("t")).unwrap();
    let st = ark_skills::core::settings::Store::new(&f.paths);
    for cmd in ["cargo test -p ark-skills", "cargo clippy -p ark-skills"] {
        ark_skills::core::review::note_step(&st, &id, "shell", &serde_json::json!({ "command": cmd }), false);
    }
    let s = ark_skills::core::settings::Settings::load(&f.cfg);
    ark_skills::core::review::record_candidate(&s, &st, &id, &f.ws.display().to_string(), "Run the ark-skills test and lint loop", true).unwrap();
    // `/curator review` lists, `/curator review --apply` writes.
    let listed = k.run_slash("/curator review", Some(&id), "cli").unwrap().unwrap().text.unwrap();
    assert!(listed.contains("1 candidate(s)") && listed.contains("Run the ark-skills test and lint loop") && listed.contains("--apply"), "{listed}");
    assert!(!f.paths.data.join("skills/run-the-ark-skills-test-and-lint-loop").exists());
    let applied = k.run_slash("/curator review --apply", Some(&id), "cli").unwrap().unwrap().text.unwrap();
    assert!(applied.contains("1 written"), "{applied}");
    assert!(f.paths.data.join("skills/run-the-ark-skills-test-and-lint-loop/SKILL.md").is_file());
    // The new skill reaches the next turn as a live delta.
    let note = ark_skills::core::index::shared(&f.cfg, &f.paths).reload(&f.ws.to_string_lossy());
    assert!(note.added.iter().any(|(n, _)| n == "run-the-ark-skills-test-and-lint-loop"), "{note:?}");
    let _ = std::fs::remove_dir_all(&f.root);
}

#[test]
fn skills_slash_dispatches_every_subcommand() {
    let mut f = fixture("skillsdis");
    f.skill("deploy", "Deploy the service.");
    // No network: every registry points at a closed local port (connections fail instantly).
    let mut hub = toml::Table::new();
    hub.insert("allow_private".into(), toml::Value::Boolean(true));
    for key in ["github_api", "github_raw", "skills_sh", "lobehub", "browse_sh"] {
        hub.insert(key.into(), toml::Value::String("http://127.0.0.1:1".into()));
    }
    hub.insert("clawhub".into(), toml::Value::String("http://127.0.0.1:1/api/v1".into()));
    f.cfg.skills.insert("hub".into(), toml::Value::Table(hub));
    let p = Scripted::new();
    let k = f.kernel(p);
    ark_skills::host::attach(&k, &f.ws);
    let id = k.create_session(&f.ws, None, None, Some("t")).unwrap();
    let run = |line: &str| k.run_slash(line, Some(&id), "cli").unwrap();
    // help
    let help = run("/skills help").unwrap().text.unwrap();
    let subs = ["list", "search", "browse", "inspect", "install", "uninstall", "check", "update", "audit", "view", "setup", "usage", "pending", "approve", "reject", "tap", "config"];
    for s in subs {
        assert!(help.contains(s), "/skills help does not mention {s}: {help}");
    }
    // list / view / usage / check / update / setup / search / browse all dispatch (no "unknown" error)
    let list = run("/skills list").unwrap().text.unwrap();
    assert!(list.contains("deploy"), "{list}");
    let view = run("/skills view deploy").unwrap().text.unwrap();
    assert!(view.contains("deploy (project") && view.contains("Deploy the service"), "{view}");
    let usage = run("/skills usage").unwrap().text.unwrap();
    assert!(usage.contains("deploy"), "{usage}");
    assert!(run("/skills check").unwrap().text.unwrap().contains("no hub-installed skills"));
    assert!(run("/skills update").unwrap().text.unwrap().contains("up to date"));
    assert!(run("/skills audit").unwrap().text.unwrap().contains("no hub-installed"));
    let search = run("/skills search deploy --source official");
    assert!(search.is_ok(), "search dispatches: {search:?}");
    let browse = run("/skills browse --source official");
    assert!(browse.is_ok(), "browse dispatches: {browse:?}");
    // install/uninstall/inspect reach the hub layer and fail on the (closed) registry, not on dispatch
    let install = run("/skills install no-such-skill-xyz --source official").unwrap_err();
    assert!(!install.contains("unknown `ark skills` subcommand"), "{install}");
    let inspect = run("/skills inspect").unwrap_err();
    assert!(inspect.contains("usage: ark skills inspect"), "{inspect}");
    assert!(run("/skills uninstall ghost").is_err());
    // setup on a skill with no declared env says so rather than failing.
    assert!(run("/skills setup deploy").unwrap().text.unwrap().contains("needs no environment setup"));
    // The pending queue (write approval) is reachable from /skills too.
    assert!(run("/skills pending").unwrap().text.unwrap().contains("no pending skill writes"));
    assert!(run("/skills approve nope").is_err());
    assert!(run("/skills reject nope").is_err());
    // A typo still errors as an unknown subcommand (the dispatch table is real).
    assert!(run("/skills nope-nope").unwrap_err().contains("unknown `ark skills` subcommand"));
    let _ = std::fs::remove_dir_all(&f.root);
}

