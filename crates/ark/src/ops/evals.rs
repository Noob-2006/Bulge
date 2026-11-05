//! The in-process eval harness (Hermes `evals/`): a registry of small end-to-end probes of
//! the runtime, each one a hermetic check of behaviour that already exists here.
//!
//! Upstream ships ~74 pytest modules (`evals/acp_empty_session_wire.py`,
//! `evals/gateway_status_render/`, `evals/core_tool_deferral/`, …) and runs them with pytest.
//! The scored runner (benchmarks, model matrices, judge, role scenarios, reports) shares this
//! command: `ark evals bench|roles|fetch|…` are dispatched to [`super::evalkit`].
//!
//! ark has no separate test runner: the evals are functions in this file, registered in
//! [`evals`], and `ark evals run` is a pytest-style front end for them:
//!
//! ```text
//! ark evals list [--json] [--filter SUBSTR]
//! ark evals run [ID …] [--filter SUBSTR] [--json] [--verbose] [--list]
//! ```
//!
//! Each eval prints `PASS/FAIL id (N ms)`, failures add an indented detail block, and the run
//! ends with `12 passed, 1 failed in 0.4s` (exit 1 when anything failed). Every eval is
//! timed and wrapped in `catch_unwind`, so one broken probe can never abort the run.
//!
//! Honesty rules: an eval runs in this process against a throwaway `ARK_HOME` and the echo
//! provider — never the network, never a real model, never a paid API key. Anything that
//! would need one of those is not registered here (that is why there is no "model answers
//! a hard question" eval).
//!
//! Note: `crate::testkit` is `
//! `#[cfg(test)]`, so the shipped binary cannot use it; [`home`]
//! builds the same layout here (temp `ARK_HOME`, echo provider, checkpointing off). Under
//! `cfg(test)` it takes `testkit::env_lock`, the lock every other test that touches process
//! environment holds.
//!
//! Groups mirror the upstream themes: `wire` (protocol/tool schemas), `cli` (arg parsing,
//! slash registry), `kernel` (turns, queue modes), `session`, `config`, `channel` and `ops`
//! (backup, doctor).

use crate::args::Args;
use crate::{usage, R};
use serde_json::{json, Value};
use std::time::Instant;

pub const COMMANDS: &[&str] = &["evals"];
pub const VALUE_FLAGS: &[&str] = &["filter"];
pub const BOOL_FLAGS: &[&str] = &["json", "verbose", "list"];

/// One registered eval: an id (`group/name`), the group it belongs to, a one-line
/// description, whether it is slow enough to skip in a quick run, and its body.
#[derive(Debug)]
pub struct Eval {
    pub id: &'static str,
    pub group: &'static str,
    pub description: &'static str,
    pub slow: bool,
    pub run: fn() -> Result<(), String>,
}

/// Result of [`run_one`]: the eval's identity, timing and error (if any).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub id: &'static str,
    pub group: &'static str,
    pub ok: bool,
    pub ms: u64,
    pub error: Option<String>,
}

impl Outcome {
    pub fn status(&self) -> &'static str {
        if self.ok {
            "pass"
        } else {
            "fail"
        }
    }
}

/// Run one eval, catching panics and measuring wall time.
pub fn run_one(e: &Eval) -> Outcome {
    let start = Instant::now();
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (e.run)()));
    let ms = start.elapsed().as_millis() as u64;
    let (ok, error) = match res {
        Ok(Ok(())) => (true, None),
        Ok(Err(m)) => (false, Some(m)),
        Err(p) => (false, Some(format!("panicked: {}", panic_message(&*p)))),
    };
    Outcome {
        id: e.id,
        group: e.group,
        ok,
        ms,
        error,
    }
}

fn panic_message(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".into()
    }
}

/// Pick the evals to run: exact ids (when given) narrowed by a case-insensitive substring
/// match on the id or the group. Unknown ids are an error, never a silent no-op.
pub fn select<'a>(
    all: &'a [Eval],
    ids: &[String],
    filter: Option<&str>,
) -> Result<Vec<&'a Eval>, String> {
    let mut unknown: Vec<&str> = ids
        .iter()
        .filter(|id| !all.iter().any(|e| e.id == id.as_str()))
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        unknown.sort_unstable();
        return Err(format!(
            "unknown eval id(s): {} (see `ark evals list`)",
            unknown.join(", ")
        ));
    }
    let needle = filter
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    Ok(all
        .iter()
        .filter(|e| ids.is_empty() || ids.iter().any(|id| id == e.id))
        .filter(|e| match &needle {
            None => true,
            Some(n) => {
                e.id.to_ascii_lowercase().contains(n) || e.group.to_ascii_lowercase().contains(n)
            }
        })
        .collect())
}

/// Registry of built-in evals. Order is the order `list` and `run` use.
pub fn evals() -> Vec<Eval> {
    vec![
        Eval {
            id: "wire/tool-schemas",
            group: "wire",
            description: "every runtime tool exposes a provider-safe JSON-object input schema",
            slow: false,
            run: eval_tool_schemas,
        },
        Eval {
            id: "wire/handshake",
            group: "wire",
            description: "ARP `initialize` advertises every daemon method plus the host extensions",
            slow: false,
            run: eval_handshake,
        },
        Eval {
            id: "cli/args",
            group: "cli",
            description: "the argument parser handles value/bool flags and rejects typos",
            slow: false,
            run: eval_cli_args,
        },
        Eval {
            id: "slash/registry",
            group: "cli",
            description: "slash commands have unique names, help text and resolving aliases",
            slow: false,
            run: eval_slash_registry,
        },
        Eval {
            id: "kernel/turn",
            group: "kernel",
            description: "a full turn through the echo provider produces the expected events",
            slow: false,
            run: eval_kernel_turn,
        },
        Eval {
            id: "kernel/queue-modes",
            group: "kernel",
            description: "queue modes hold, cap, drop and release input per turn",
            slow: false,
            run: eval_queue_modes,
        },
        Eval {
            id: "session/roundtrip",
            group: "session",
            description: "daemon session.create → submit → history → projection round-trip",
            slow: false,
            run: eval_session_roundtrip,
        },
        Eval {
            id: "config/roundtrip",
            group: "config",
            description: "config set → get → unset keeps comments and validates values",
            slow: false,
            run: eval_config_roundtrip,
        },
        Eval {
            id: "channel/access",
            group: "channel",
            description: "channel sender access control gates admins and per-user commands",
            slow: false,
            run: eval_channel_access,
        },
        Eval {
            id: "ops/backup-roundtrip",
            group: "ops",
            description: "backup create → verify → restore restores the previous config",
            slow: false,
            run: eval_backup_roundtrip,
        },
        Eval {
            id: "ops/doctor-lint",
            group: "ops",
            description: "doctor lint reports no errors on a clean temp home",
            slow: false,
            run: eval_doctor_lint,
        },
        Eval {
            id: "web/assets",
            group: "web",
            description: "the Control UI serves its shell with i18n, themes, chat slash/attachments and every page",
            slow: false,
            run: eval_web_assets,
        },
    ]
}

// ───────────────────────── hermetic homes ─────────────────────────

/// A throwaway home plus a kernel over the same layout, with the echo provider. The
/// shipped binary cannot use the `#[cfg(test)]` testkit, so the same shape lives here.
struct Kit {
    k: ark_kernel::kernel::Kernel,
    ws: std::path::PathBuf,
    paths: ark_kernel::config::Paths,
    echo: std::sync::Arc<Echo>,
}

/// Replies `reply: <last user text>` and records every request. No network, no key.
struct Echo {
    seen: std::sync::Mutex<Vec<ark_core::ModelRequest>>,
}

impl ark_core::Provider for Echo {
    fn id(&self) -> &str {
        "echo"
    }
    fn caps(&self, _: &str) -> ark_core::ModelCaps {
        ark_core::ModelCaps {
            context_window: 100_000,
            max_output: 4096,
            tools: true,
            vision: true,
            explicit_cache: false,
        }
    }
    fn complete(
        &self,
        req: &ark_core::ModelRequest,
        on: &mut dyn FnMut(ark_core::StreamEvent),
        _: &ark_core::Cancel,
    ) -> Result<ark_core::ModelResponse, ark_core::ProviderError> {
        self.seen.lock().unwrap().push(req.clone());
        let last = req.messages.last().map(|m| m.text()).unwrap_or_default();
        let text = format!("reply: {}", last.chars().take(200).collect::<String>());
        on(ark_core::StreamEvent::TextDelta(text.clone()));
        Ok(ark_core::ModelResponse {
            message: ark_core::Message::assistant(text),
            stop: ark_core::StopReason::EndTurn,
            usage: ark_core::Usage {
                input_tokens: 50,
                output_tokens: 10,
                ..Default::default()
            },
            model: "echo/m".into(),
        })
    }
}

struct EchoResolver(std::sync::Arc<Echo>);

impl ark_kernel::kernel::Resolver for EchoResolver {
    fn provider(&self, _: &str) -> Result<std::sync::Arc<dyn ark_core::Provider>, String> {
        Ok(self.0.clone())
    }
}

/// Process environment (`ARK_HOME`, `XDG_*`) is global: every eval that touches it holds
/// this. Under `cfg(test)` it is the testkit lock every other test uses.
#[cfg(test)]
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    crate::testkit::env_lock()
}

#[cfg(not(test))]
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// A throwaway `ARK_HOME` plus a kernel over the same layout. Holds the environment lock
/// for its whole life and puts `ARK_HOME` back on drop.
struct Home {
    kit: Kit,
    prev: Option<std::ffi::OsString>,
    /// The throwaway tree, removed on drop.
    root: std::path::PathBuf,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl Drop for Home {
    fn drop(&mut self) {
        match self.prev.take() {
            Some(v) => std::env::set_var("ARK_HOME", v),
            None => std::env::remove_var("ARK_HOME"),
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn home() -> Home {
    let lock = env_lock();
    let root = ark_core::tmp::scratch_path(format!("ark-eval-{}", ark_kernel::util::random_hex(8)));
    let ws = root.join("ws");
    let paths = ark_kernel::config::Paths {
        data: root.join("data"),
        config_dir: root.join("config"),
        runtime: root.join("run"),
    };
    for d in [&ws, &paths.data, &paths.config_dir, &paths.runtime] {
        std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("create {}: {e}", d.display()));
    }
    let mut cfg = ark_kernel::config::Config::default();
    cfg.model.default = "echo/m".into();
    cfg.checkpoint.enabled = false;
    let echo = std::sync::Arc::new(Echo {
        seen: std::sync::Mutex::new(vec![]),
    });
    let k = ark_kernel::kernel::new_kernel(
        cfg,
        paths.clone(),
        std::sync::Arc::new(EchoResolver(echo.clone())),
        ark_tools::builtin_tools(),
        std::sync::Arc::new(ark_kernel::vault::Vault::empty()),
        std::sync::Arc::new(ark_kernel::approver::Policy {
            allow_privilege: false,
            allow_egress: false,
        }),
    );
    let prev = std::env::var_os("ARK_HOME");
    std::env::set_var("ARK_HOME", &root);
    Home {
        kit: Kit {
            k,
            ws: ws.canonicalize().unwrap_or(ws),
            paths,
            echo,
        },
        prev,
        root,
        _lock: lock,
    }
}

// ───────────────────────── wire ─────────────────────────

fn eval_tool_schemas() -> Result<(), String> {
    let h = home();
    let specs = h.kit.k.specs();
    if specs.is_empty() {
        return Err("the runtime exposes no tool specs".into());
    }
    let mut seen = std::collections::HashSet::new();
    for s in &specs {
        if !seen.insert(s.name.clone()) {
            return Err(format!("duplicate tool name `{}`", s.name));
        }
        if s.description.trim().is_empty() {
            return Err(format!("tool `{}` has no description", s.name));
        }
        if s.input_schema.get("type").and_then(Value::as_str) != Some("object") {
            return Err(format!(
                "tool `{}` does not declare a JSON object schema: {}",
                s.name, s.input_schema
            ));
        }
        let violations = crate::ops::doctor::schema_violations(&s.name, &s.input_schema);
        if !violations.is_empty() {
            return Err(format!(
                "tool `{}` has an unsupported input schema: {}",
                s.name,
                violations.join("; ")
            ));
        }
    }
    Ok(())
}

fn eval_handshake() -> Result<(), String> {
    use std::sync::Arc;
    let h = home();
    let pending = Arc::new(ark_kernel::approver::Pending::new(
        std::time::Duration::from_secs(5),
        Box::new(|_| {}),
    ));
    let d = Arc::new(ark_kernel::daemon::Daemon::new(h.kit.k.clone(), pending));
    let app = ark_app::App {
        d,
        cfg: ark_app::AppConfig::default(),
        token: "evals-token".into(),
        host_methods: vec!["surfaces.list".into()],
        routes: vec![],
    };
    let caps = app.capabilities();
    if caps["protocol"].as_str() != Some(ark_app::ARP_VERSION) {
        return Err(format!(
            "initialize protocol is {:?}, expected {:?}",
            caps["protocol"],
            ark_app::ARP_VERSION
        ));
    }
    let methods: Vec<&str> = caps["methods"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    for m in ark_kernel::daemon::Daemon::METHODS {
        if !methods.contains(m) {
            return Err(format!("initialize omits daemon method `{m}`"));
        }
    }
    for m in ["initialize", "subscribe", "unsubscribe", "surfaces.list"] {
        if !methods.contains(&m) {
            return Err(format!("initialize omits `{m}`"));
        }
    }
    if caps["server"]["name"].as_str() != Some("ark") {
        return Err(format!("initialize server info is {:?}", caps["server"]));
    }
    if !caps["events"].as_array().is_some_and(|a| !a.is_empty()) {
        return Err("initialize advertises no event streams".into());
    }
    Ok(())
}

// ───────────────────────── cli ─────────────────────────

fn eval_cli_args() -> Result<(), String> {
    let raw = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let a = Args::parse(&raw(&[
        "run",
        "hello",
        "world",
        "-m",
        "echo/m",
        "--json",
        "--set",
        "a=1",
        "--set=b=2",
        "--filter=wire/",
    ]))
    .map_err(|e| format!("parse: {e}"))?;
    if a.pos != ["run", "hello", "world"] {
        return Err(format!("positionals parsed as {:?}", a.pos));
    }
    if a.val("model") != Some("echo/m") {
        return Err(format!("--model/-m parsed as {:?}", a.val("model")));
    }
    if !a.flag("json") {
        return Err("--json was not recorded".into());
    }
    if a.vals("set") != ["a=1", "b=2"] {
        return Err(format!("repeated --set parsed as {:?}", a.vals("set")));
    }
    // `filter` only parses because `evals` registers it as a value flag.
    if a.val("filter") != Some("wire/") {
        return Err(format!("--filter parsed as {:?}", a.val("filter")));
    }
    if a.num::<u64>("max-steps") != Ok(None) {
        return Err("an absent numeric flag did not parse as None".into());
    }
    for bad in [&["--nope", "x"][..], &["-z"][..], &["--model"][..]] {
        if Args::parse(&raw(bad)).is_ok() {
            return Err(format!("parser accepted invalid arguments {bad:?}"));
        }
    }
    if Args::parse(&raw(&["--json=1"])).is_ok() {
        return Err("parser accepted a value for the boolean --json".into());
    }
    Ok(())
}

fn eval_slash_registry() -> Result<(), String> {
    use std::collections::HashSet;
    let defs: Vec<&crate::slash::Def> = crate::slash::defs().collect();
    if defs.len() < 20 {
        return Err(format!("only {} slash commands are registered", defs.len()));
    }
    let mut names = HashSet::new();
    for d in &defs {
        if d.name.is_empty()
            || d.name.chars().any(char::is_whitespace)
            || d.name != d.name.to_ascii_lowercase()
        {
            return Err(format!("malformed slash command name `{}`", d.name));
        }
        if d.help.trim().is_empty() {
            return Err(format!("/{} has no help text", d.name));
        }
        if d.category.trim().is_empty() {
            return Err(format!("/{} has no category", d.name));
        }
        if !names.insert(d.name) {
            return Err(format!("duplicate slash command `{}`", d.name));
        }
    }
    let mut aliases = HashSet::new();
    for d in &defs {
        for a in d.aliases {
            if a.is_empty() || a.chars().any(char::is_whitespace) || *a != a.to_ascii_lowercase() {
                return Err(format!("malformed alias `{a}` of /{}", d.name));
            }
            if names.contains(a) {
                return Err(format!(
                    "alias `{a}` of /{} collides with a command name",
                    d.name
                ));
            }
            if !aliases.insert(*a) {
                return Err(format!("alias `{a}` is used by more than one command"));
            }
        }
    }
    for d in &defs {
        if crate::slash::find(d.name).map(|f| f.name) != Some(d.name) {
            return Err(format!("/{} does not resolve through slash::find", d.name));
        }
        for a in d.aliases {
            if crate::slash::find(a).map(|f| f.name) != Some(d.name) {
                return Err(format!("alias `{a}` does not resolve to /{}", d.name));
            }
        }
    }
    Ok(())
}

// ───────────────────────── kernel ─────────────────────────

fn eval_kernel_turn() -> Result<(), String> {
    use ark_core::Role;
    let h = home();
    let k = &h.kit.k;
    let sid = k
        .create_session(&h.kit.ws, None, None, Some("eval turn"))
        .map_err(|e| format!("create_session: {e}"))?;
    k.submit(&sid, "hello evals", "cli")
        .map_err(|e| format!("submit: {e}"))?;
    let out = k
        .run(&sid, ark_kernel::kernel::RunOpts::default())
        .map_err(|e| format!("run: {e}"))?;
    if !out.text.contains("reply: hello evals") {
        return Err(format!("unexpected assistant text {:?}", out.text));
    }
    if out.turns < 1 {
        return Err("the run reported no turn".into());
    }
    let events = k.store.read(&sid).map_err(|e| format!("read log: {e}"))?;
    let view = ark_kernel::projection::project(&events);
    if view.session_id != sid {
        return Err(format!(
            "projection session id {:?} != {sid}",
            view.session_id
        ));
    }
    if !view
        .messages
        .iter()
        .any(|m| m.role == Role::User && m.text().contains("hello evals"))
    {
        return Err("the user message is missing from the projection".into());
    }
    if !view
        .messages
        .iter()
        .any(|m| m.role == Role::Assistant && m.text().contains("reply: hello evals"))
    {
        return Err("the assistant reply is missing from the projection".into());
    }
    let seen = h.kit.echo.seen.lock().unwrap();
    if seen.len() != 1 {
        return Err(format!(
            "the echo provider saw {} requests, expected 1",
            seen.len()
        ));
    }
    if seen[0].tools.is_empty() {
        return Err("the model request carried no tool schemas".into());
    }
    Ok(())
}

fn eval_queue_modes() -> Result<(), String> {
    use ark_kernel::projection::Queued;
    use ark_kernel::queue::{hold, release, Drop, Mode, Settings};
    use std::sync::Mutex;
    let q = |t: &str| -> Queued { ("id".into(), "cli".into(), t.to_string(), vec![]) };

    for m in [Mode::Steer, Mode::Followup, Mode::Collect, Mode::Interrupt] {
        if Mode::parse(m.name()) != Some(m) {
            return Err(format!("queue mode `{}` does not parse back", m.name()));
        }
    }
    if Mode::parse("nope").is_some() {
        return Err("an unknown queue mode parsed".into());
    }

    // followup keeps one item per turn; the cap drops the oldest message.
    let held = Mutex::new(vec![]);
    let s = Settings {
        mode: Mode::Followup,
        cap: 2,
        drop: Drop::Old,
    };
    hold(&held, q("a"), &s);
    hold(&held, q("b"), &s);
    let notice = hold(&held, q("c"), &s).ok_or("cap 2 must report dropping a third message")?;
    if !notice.contains("oldest") {
        return Err(format!("unexpected drop notice {notice:?}"));
    }
    let texts: Vec<String> = held.lock().unwrap().iter().map(|x| x.2.clone()).collect();
    if texts != ["b", "c"] {
        return Err(format!("oldest drop left {texts:?}"));
    }
    if release(&held, Mode::Followup)[0].2 != "b" || held.lock().unwrap().len() != 1 {
        return Err("followup release did not take exactly one message".into());
    }

    // collect merges everything into one turn.
    let held = Mutex::new(vec![]);
    let c = Settings {
        mode: Mode::Collect,
        ..Settings::default()
    };
    hold(&held, q("x"), &c);
    hold(&held, q("y"), &c);
    if held.lock().unwrap().len() != 1 {
        return Err("collect mode did not merge queued messages".into());
    }
    if release(&held, Mode::Collect)[0].2 != "x\n\ny" {
        return Err("collect release did not join the messages".into());
    }

    // summarize folds the two oldest entries.
    let held = Mutex::new(vec![]);
    let z = Settings {
        mode: Mode::Followup,
        cap: 2,
        drop: Drop::Summarize,
    };
    for t in ["1", "2", "3", "4"] {
        hold(&held, q(t), &z);
    }
    let v = held.lock().unwrap();
    if v.len() != 2
        || !v[0].2.starts_with("[queued messages, condensed]")
        || !v[0].2.contains("- 1")
        || !v[0].2.contains("- 3")
    {
        return Err(format!(
            "summarize drop produced {:?}",
            v.iter().map(|x| x.2.clone()).collect::<Vec<_>>()
        ));
    }
    Ok(())
}

// ───────────────────────── session ─────────────────────────

fn eval_session_roundtrip() -> Result<(), String> {
    use ark_core::Role;
    use std::sync::Arc;
    use std::time::Duration;
    let h = home();
    let k = h.kit.k.clone();
    let pending = Arc::new(ark_kernel::approver::Pending::new(
        Duration::from_secs(5),
        Box::new(|_| {}),
    ));
    let d = ark_kernel::daemon::Daemon::new(k.clone(), pending);
    let err = |m: &str, (c, e): (i32, String)| format!("{m} ({c}): {e}");

    let created = d
        .call(
            "session.create",
            &json!({"workspace": h.kit.ws.display().to_string(), "title": "evals"}),
        )
        .map_err(|e| err("session.create", e))?;
    let id = created["id"]
        .as_str()
        .ok_or("session.create returned no id")?
        .to_string();
    let sub = d
        .call(
            "session.submit",
            &json!({"id": id, "text": "roundtrip", "source": "evals"}),
        )
        .map_err(|e| err("session.submit", e))?;
    if sub["queued"] != json!(true) || sub["started"] != json!(true) {
        return Err(format!("session.submit returned {sub}"));
    }
    // The daemon starts the turn on its own thread, so wait for the reply to appear in the
    // log rather than for `is_running` (which is still false between spawn and registration).
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut events: Vec<ark_kernel::event::Event> = vec![];
    loop {
        let hist = d
            .call("session.history", &json!({"id": id}))
            .map_err(|e| err("session.history", e))?;
        events = serde_json::from_value(hist)
            .map_err(|e| format!("session.history is not an event log: {e}"))?;
        if ark_kernel::projection::project(&events)
            .messages
            .iter()
            .any(|m| {
                m.role == Role::Assistant
                    && m.text().contains("reply:")
                    && m.text().contains("roundtrip")
            })
        {
            break;
        }
        if Instant::now() > deadline {
            return Err(format!(
                "the submitted turn produced no reply within 20s ({} events logged)",
                events.len()
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if events.is_empty() {
        return Err("session.history returned no events".into());
    }
    // The reply is logged before the run thread clears its registration.
    while k.is_running(&id) {
        if Instant::now() > deadline {
            return Err("the session is still running after its reply was logged".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let view = ark_kernel::projection::project(&events);
    if view.session_id != id || view.title.as_deref() != Some("evals") {
        return Err(format!(
            "projection header is {:?}/{id}, title {:?}",
            view.session_id, view.title
        ));
    }
    // Non-cli sources are labelled: the prompt arrives as `[from evals] roundtrip`.
    if !view
        .messages
        .iter()
        .any(|m| m.role == Role::User && m.text().contains("[from evals] roundtrip"))
    {
        return Err("the submitted prompt is missing from the projection".into());
    }
    if !view.messages.iter().any(|m| {
        m.role == Role::Assistant && m.text().contains("reply:") && m.text().contains("roundtrip")
    }) {
        return Err("the assistant reply is missing from the projection".into());
    }

    let v = d
        .call("session.view", &json!({"id": id}))
        .map_err(|e| err("session.view", e))?;
    if v["running"] == json!(true) {
        return Err(format!(
            "session.view still reports the session as running: {v}"
        ));
    }
    if v["messages"].as_array().is_none_or(|a| a.is_empty()) {
        return Err("session.view returned no messages".into());
    }
    Ok(())
}

// ───────────────────────── config ─────────────────────────

fn eval_config_roundtrip() -> Result<(), String> {
    let h = home();
    let paths = &h.kit.paths;
    std::fs::create_dir_all(&paths.config_dir).map_err(|e| format!("config dir: {e}"))?;
    let file = paths.user_config();
    let original = "# keep this comment\n[model]\ndefault = \"echo/one\"\n";
    std::fs::write(&file, original).map_err(|e| format!("write config: {e}"))?;

    crate::ops::confcli::set(paths, "runner.max_steps_per_turn", "7")?;
    let text = std::fs::read_to_string(&file).map_err(|e| format!("read config: {e}"))?;
    if !text.contains("# keep this comment") {
        return Err(format!("config set dropped the comment:\n{text}"));
    }
    if crate::ops::confcli::get(paths, &h.kit.ws, "runner.max_steps_per_turn")? != "7" {
        return Err("config get did not return the value that was set".into());
    }
    if crate::ops::confcli::get(paths, &h.kit.ws, "model.default")? != "echo/one" {
        return Err("config set damaged an unrelated key".into());
    }

    crate::ops::confcli::unset(paths, "runner.max_steps_per_turn")?;
    let text = std::fs::read_to_string(&file).map_err(|e| format!("read config: {e}"))?;
    if !text.contains("# keep this comment") || text.contains("max_steps_per_turn") {
        return Err(format!(
            "config unset did not restore the original file:\n{text}"
        ));
    }
    let default = ark_kernel::config::Config::default()
        .runner
        .max_steps_per_turn
        .to_string();
    if crate::ops::confcli::get(paths, &h.kit.ws, "runner.max_steps_per_turn")? != default {
        return Err("the key did not fall back to its default after unset".into());
    }

    // An invalid value is rejected before it reaches the file.
    if crate::ops::confcli::set(paths, "runner.max_steps_per_turn", "not-a-number").is_ok() {
        return Err("config set accepted a value that does not parse".into());
    }
    let after = std::fs::read_to_string(&file).map_err(|e| format!("read config: {e}"))?;
    if after != text {
        return Err(format!("a rejected set still rewrote the config:\n{after}"));
    }
    Ok(())
}

// ───────────────────────── channel ─────────────────────────

fn eval_channel_access() -> Result<(), String> {
    use ark_channel::{ChatType, Inbound};
    let h = home();
    let cfg = ark_channel::config::parse_config(
        "evals",
        &json!({
            "kind": "telegram",
            "allow_admin_from": ["alice"],
            "user_allowed_commands": ["status", "/version"],
            "group_allow_admin_from": ["@carol"],
            "group_user_allowed_commands": "status, help",
        }),
    )
    .map_err(|e| format!("channel config: {e}"))?;
    let inbound = |sender: &str, chat_type: ChatType| Inbound {
        channel: "evals".into(),
        chat: "c1".into(),
        sender: sender.into(),
        sender_name: sender.into(),
        text: "/status".into(),
        message_id: "m1".into(),
        chat_type,
        ..Default::default()
    };

    let alice = crate::ext::sender_access(Some(&cfg), &inbound("alice", ChatType::Direct));
    if !(alice.gated && alice.admin) {
        return Err(format!(
            "a listed admin was not recognised: gated={} admin={}",
            alice.gated, alice.admin
        ));
    }
    if alice.user_commands != ["status", "version"] {
        return Err(format!(
            "allowed commands parsed as {:?}",
            alice.user_commands
        ));
    }
    let bob = crate::ext::sender_access(Some(&cfg), &inbound("bob", ChatType::Direct));
    if !bob.gated || bob.admin {
        return Err(format!(
            "an unlisted sender was not gated: gated={} admin={}",
            bob.gated, bob.admin
        ));
    }
    let carol = crate::ext::sender_access(Some(&cfg), &inbound("@carol", ChatType::Group));
    if !(carol.gated && carol.admin) {
        return Err("a group admin matched by @name was not recognised".into());
    }
    let open = ark_channel::config::parse_config("open", &json!({"kind": "telegram"}))
        .map_err(|e| format!("channel config: {e}"))?;
    let dave = crate::ext::sender_access(Some(&open), &inbound("dave", ChatType::Direct));
    if dave.gated || dave.admin {
        return Err("a channel without admin lists gated a sender".into());
    }
    if crate::ext::sender_access(None, &inbound("dave", ChatType::Direct)).gated {
        return Err("an unknown channel gated a sender".into());
    }

    // The same sender gates slash commands: admins get the reply, gated users only their list.
    let ctx = crate::slash::Ctx {
        k: &h.kit.k,
        ext: None,
        session: None,
        workspace: h.kit.ws.clone(),
        surface: crate::slash::Surface::Channel,
        sender: Some(bob.clone()),
        notify: None,
    };
    let reply_text = |line: &str| {
        crate::slash::run(&ctx, line)
            .and_then(|r| r.text)
            .unwrap_or_default()
    };
    let denied = reply_text("/history");
    if !denied.contains("not enabled for you") {
        return Err(format!(
            "a gated user could run an unlisted command: {denied:?}"
        ));
    }
    let admin_only = reply_text("/config");
    if !admin_only.contains("admins") {
        return Err(format!(
            "a gated user reached an admin command: {admin_only:?}"
        ));
    }
    if reply_text("/status").contains("not enabled for you") {
        return Err("a gated user was denied a command on their own list".into());
    }
    let admin_ctx = crate::slash::Ctx {
        sender: Some(alice.clone()),
        ..ctx
    };
    let version = crate::slash::run(&admin_ctx, "/version")
        .and_then(|r| r.text)
        .unwrap_or_default();
    if !version.starts_with("ark ") {
        return Err(format!("an admin could not run /version: {version:?}"));
    }
    Ok(())
}

// ───────────────────────── ops ─────────────────────────

fn eval_backup_roundtrip() -> Result<(), String> {
    let h = home();
    let paths = &h.kit.paths;
    std::fs::create_dir_all(&paths.data).map_err(|e| format!("data dir: {e}"))?;
    std::fs::create_dir_all(&paths.config_dir).map_err(|e| format!("config dir: {e}"))?;
    let cfg = paths.user_config();
    std::fs::write(&cfg, "[model]\ndefault = \"echo/before\"\n")
        .map_err(|e| format!("write config: {e}"))?;

    let out = paths.data.join("backups");
    let (file, manifest) =
        crate::ops::backup::create(paths, &out, &crate::ops::backup::Opts::default())
            .map_err(|e| format!("backup create: {e}"))?;
    if !file.is_file() {
        return Err(format!(
            "backup create wrote no archive at {}",
            file.display()
        ));
    }
    let listed = manifest["files"].as_array().is_some_and(|a| {
        a.iter()
            .any(|f| f["path"].as_str() == Some("config/config.toml"))
    });
    if !listed {
        return Err(format!(
            "the manifest does not list config/config.toml: {manifest}"
        ));
    }
    crate::ops::backup::verify(&file).map_err(|e| format!("backup verify: {e}"))?;

    std::fs::write(&cfg, "[model]\ndefault = \"echo/after\"\n")
        .map_err(|e| format!("write config: {e}"))?;
    let (n, _pre) = crate::ops::backup::restore(paths, &file, false)
        .map_err(|e| format!("backup restore: {e}"))?;
    if n == 0 {
        return Err("restore extracted no files".into());
    }
    let text = std::fs::read_to_string(&cfg).map_err(|e| format!("read restored config: {e}"))?;
    if !text.contains("echo/before") || text.contains("echo/after") {
        return Err(format!(
            "restore did not bring back the archived config:\n{text}"
        ));
    }
    Ok(())
}

fn eval_doctor_lint() -> Result<(), String> {
    let h = home();
    let mut cfg = ark_kernel::config::Config::default();
    cfg.checkpoint.enabled = false;
    let checks = crate::ops::doctor::checks();
    let ctx = crate::ops::doctor::Ctx {
        paths: h.kit.paths.clone(),
        cfg,
        ws: h.kit.ws.clone(),
        specs: Ok(h.kit.k.specs()),
        secret_names: vec![],
        daemon_running: false,
    };
    let lint = crate::ops::doctor::lint(&ctx, &checks, &[], &[]);
    if lint.run != checks.len() {
        return Err(format!(
            "doctor ran {} of {} checks",
            lint.run,
            checks.len()
        ));
    }
    if let Some(f) = lint
        .findings
        .iter()
        .find(|f| f.severity == crate::ops::doctor::Severity::Error)
    {
        let req = f
            .requirement
            .as_deref()
            .map(|r| format!(" ({r})"))
            .unwrap_or_default();
        return Err(format!(
            "a clean home reported an error: [{}] {}{req}",
            f.check, f.message
        ));
    }
    Ok(())
}

// ───────────────────────── cli front end ─────────────────────────

#[derive(Debug, Clone, Copy, Default)]
struct RunOpts {
    json: bool,
    verbose: bool,
    quiet: bool,
}

fn list_evals(a: &Args) -> R {
    let all = evals();
    let chosen = select(&all, &[], a.val("filter"))?;
    if a.flag("json") {
        let rows: Vec<Value> = chosen.iter().map(|e| json!({"id": e.id, "group": e.group, "description": e.description, "slow": e.slow})).collect();
        println!("{}", json!({"evals": rows}));
    } else {
        for e in chosen {
            println!(
                "{:<22} {:<8} {}{}",
                e.id,
                e.group,
                e.description,
                if e.slow { " [slow]" } else { "" }
            );
        }
    }
    Ok(0)
}

fn run_evals(a: &Args) -> R {
    let all = evals();
    let ids: Vec<String> = a.pos.iter().skip(1).cloned().collect();
    let chosen = select(&all, &ids, a.val("filter"))?;
    if chosen.is_empty() {
        return usage(format!(
            "no eval matches{}",
            a.val("filter")
                .map(|f| format!(" filter `{f}`"))
                .unwrap_or_default()
        ));
    }
    let opts = RunOpts {
        json: a.flag("json"),
        verbose: a.flag("verbose"),
        quiet: false,
    };
    run_selected(&chosen, &opts)
}

/// Run `list` and print PASS/FAIL lines, failure details, the summary (or the JSON report).
fn run_selected(list: &[&Eval], o: &RunOpts) -> R {
    let start = Instant::now();
    let mut results = Vec::with_capacity(list.len());
    for e in list {
        let out = run_one(e);
        if !o.json && !o.quiet {
            println!(
                "{} {} ({} ms)",
                if out.ok { "PASS" } else { "FAIL" },
                out.id,
                out.ms
            );
            if o.verbose {
                println!("     {}", e.description);
            }
            if let Some(err) = &out.error {
                for line in err.lines() {
                    println!("     {line}");
                }
            }
        }
        results.push(out);
    }
    let duration_ms = start.elapsed().as_millis() as u64;
    let failed = results.iter().filter(|o| !o.ok).count();
    if o.json && !o.quiet {
        println!("{}", json_report(&results, duration_ms));
    } else if !o.quiet {
        println!();
        println!("{}", summary_line(&results, duration_ms));
    }
    Ok(if failed > 0 { 1 } else { 0 })
}

fn json_report(results: &[Outcome], duration_ms: u64) -> Value {
    let rows: Vec<Value> = results
        .iter()
        .map(|o| {
            let mut row = json!({"id": o.id, "group": o.group, "status": o.status(), "ms": o.ms});
            if let Some(e) = &o.error {
                row["error"] = json!(e);
            }
            row
        })
        .collect();
    json!({
        "evals": rows,
        "passed": results.iter().filter(|o| o.ok).count(),
        "failed": results.iter().filter(|o| !o.ok).count(),
        "duration_ms": duration_ms,
    })
}

fn summary_line(results: &[Outcome], duration_ms: u64) -> String {
    let passed = results.iter().filter(|o| o.ok).count();
    let failed = results.len() - passed;
    let mut parts = vec![];
    if passed > 0 {
        parts.push(format!("{passed} passed"));
    }
    if failed > 0 {
        parts.push(format!("{failed} failed"));
    }
    if parts.is_empty() {
        parts.push("no evals run".into());
    }
    format!(
        "{} in {:.1}s",
        parts.join(", "),
        duration_ms as f64 / 1000.0
    )
}

fn run_cli(a: &Args) -> R {
    match a.pos(0) {
        None | Some("list") => list_evals(a),
        Some("run") if a.flag("list") => list_evals(a),
        Some("run") => run_evals(a),
        Some(other) => super::evalkit::dispatch_sub(a).unwrap_or_else(|| usage(format!("unknown `evals {other}` (list, run, bench, roles, fetch, import, report, compare, collect, swe-score, suites, agents)"))),
    }
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if !COMMANDS.contains(&cmd) {
        return None;
    }
    Some(run_cli(a))
}

// ───────────────────────── web / Control UI assets (OpenClaw §10) ─────────────────────────

/// The Control UI is plain assets served by `ark_app::ui`; this eval is its regression test:
/// the shell parses as a script (no template/quote surprises), every page the server advertises
/// has a body, the chat composer really has a slash menu / attachments / tool cards, and the
/// i18n dictionaries and theme palettes stay in sync. No browser, no network.
fn eval_web_assets() -> Result<(), String> {
    use ark_net::httpd::Body;
    let body = |path: &str| -> Result<String, String> {
        let r = ark_app::ui::serve(path);
        if r.status != 200 {
            return Err(format!("{path} served {}", r.status));
        }
        match r.body {
            Body::Bytes(b) => String::from_utf8(b).map_err(|e| format!("{path}: {e}")),
            _ => Err(format!("{path}: not bytes")),
        }
    };
    let index = body("/")?;
    let app = body("/ui/app.js")?;
    let pages = body("/ui/pages.js")?;
    let css = body("/ui/app.css")?;
    for need in ["id=\"slashMenu\"", "id=\"attachments\"", "id=\"file\"", "id=\"lang\"", "id=\"theme\"", "/ui/pages.css", "/ui/app.js"] {
        if !index.contains(need) {
            return Err(format!("index.html is missing {need}"));
        }
    }
    // Chat: commands complete from `command.list` and run through `command.run`; the action the
    // kernel returns (new_session / quit / local) is performed by the client.
    for need in ["command.list", "command.run", "ui.upload", "ui.submit", "ui.upload.delete", "runSlash", "addToolCard", "data-i18n"] {
        if !app.contains(need) {
            return Err(format!("app.js is missing {need}"));
        }
    }
    if app.contains("onclick=\"") || app.contains("onsubmit=\"") {
        return Err("app.js sets an inline event handler (the CSP forbids it)".into());
    }
    // i18n: both dictionaries must define the same keys, and every `data-i18n*` key used by the
    // shell must exist (a missing key shows the raw key to the user).
    let dict_at = app.find("const I18N = {").ok_or("app.js has no I18N dictionary")?;
    let dict_end = app[dict_at..].find("\n};").ok_or("I18N dictionary is not closed")?;
    let region = &app[dict_at..dict_at + dict_end];
    let (zh_src, en_src) = region.split_once("en: {").ok_or("I18N has no `en` dictionary")?;
    let keys = |src: &str| -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        let mut from = 0;
        while let Some(pos) = src[from..].find("': ") {
            let abs = from + pos;
            if let Some(q) = src[..abs].rfind('\'') {
                let k = &src[q + 1..abs];
                // `'zh-Hant': {` names the dictionary; every other quoted key is a message.
                if k != "zh-Hant" && !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-') && !v.iter().any(|x| x == k) {
                    v.push(k.to_string());
                }
            }
            from = abs + 3;
        }
        v
    };
    let zh_keys = keys(zh_src);
    let en_keys = keys(en_src);
    if zh_keys.len() < 30 {
        return Err(format!("zh dictionary has only {} keys", zh_keys.len()));
    }
    if zh_keys.len() != en_keys.len() {
        return Err(format!("i18n dictionaries disagree: {} zh keys vs {} en keys", zh_keys.len(), en_keys.len()));
    }
    for k in &zh_keys {
        if !en_keys.contains(k) {
            return Err(format!("i18n key `{k}` is missing from the English dictionary"));
        }
    }
    for usage in ["data-i18n=\"", "data-i18n-ph=\"", "data-i18n-title=\""] {
        for chunk in index.split(usage).skip(1) {
            let key = chunk.split('"').next().unwrap_or("");
            if !key.is_empty() && !zh_keys.iter().any(|k| k == key) {
                return Err(format!("index.html uses i18n key `{key}`, which the dictionary does not define"));
            }
        }
    }
    // Themes: the picker offers exactly the palettes app.css defines (crimson is theme.css).
    let offered: Vec<String> = index.split("<option value=\"").skip(1).map(|c| c.split('"').next().unwrap_or("").to_string()).collect();
    let themes = ["crimson", "midnight", "daylight"];
    if offered != themes {
        return Err(format!("theme picker offers {offered:?}, expected {themes:?}"));
    }
    for th in &themes[1..] {
        if !css.contains(&format!(":root[data-theme=\"{th}\"]")) {
            return Err(format!("app.css has no palette for theme `{th}`"));
        }
    }
    // Pages: every advertised page id has a body in pages.js.
    for (id, ..) in crate::ops::ui_methods::PAGES {
        if !pages.contains(&format!("  {id}: {{ title:")) && !pages.contains(&format!("  '{id}': {{ title:")) {
            return Err(format!("page `{id}` has no renderer in pages.js"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passes() -> Result<(), String> {
        Ok(())
    }
    fn fails() -> Result<(), String> {
        Err("deliberate failure: 2 != 3".into())
    }
    fn panics() -> Result<(), String> {
        panic!("deliberate panic in an eval");
    }

    fn eval(id: &'static str, run: fn() -> Result<(), String>) -> Eval {
        Eval {
            id,
            group: "test",
            description: "test-only eval",
            slow: false,
            run,
        }
    }

    /// The harness's own regression test: the registry is well-formed and every built-in
    /// eval passes on a clean temp home.
    #[test]
    fn registry_is_unique_and_every_eval_passes() {
        let all = evals();
        assert!(
            all.len() >= 8,
            "expected at least 8 evals, found {}",
            all.len()
        );
        let mut ids = std::collections::HashSet::new();
        for e in &all {
            assert!(!e.id.is_empty(), "an eval has an empty id");
            assert!(e.id.contains('/'), "eval id `{}` is not `group/name`", e.id);
            assert!(!e.group.is_empty(), "eval `{}` has an empty group", e.id);
            assert!(
                !e.description.is_empty(),
                "eval `{}` has an empty description",
                e.id
            );
            assert!(ids.insert(e.id), "duplicate eval id `{}`", e.id);
            let out = run_one(e);
            assert!(
                out.ok,
                "eval `{}` failed: {}",
                e.id,
                out.error.unwrap_or_default()
            );
        }
    }

    #[test]
    fn selection_by_id_and_filter() {
        let all = evals();
        let wire: Vec<&str> = select(&all, &[], Some("wire/"))
            .unwrap()
            .iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(wire, ["wire/tool-schemas", "wire/handshake"]);

        let group: Vec<&str> = select(&all, &[], Some("ops"))
            .unwrap()
            .iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(group, ["ops/backup-roundtrip", "ops/doctor-lint"]);

        let one = select(&all, &["kernel/turn".into()], None).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].id, "kernel/turn");

        // an explicit id list is narrowed by the filter, not replaced by it
        let both = select(
            &all,
            &["kernel/turn".into(), "kernel/queue-modes".into()],
            Some("queue"),
        )
        .unwrap();
        assert_eq!(
            both.iter().map(|e| e.id).collect::<Vec<_>>(),
            ["kernel/queue-modes"]
        );

        assert!(select(&all, &["nope/nothing".into()], None)
            .unwrap_err()
            .contains("unknown eval id"));
        assert!(select(&all, &[], Some("zzz-no-such-eval"))
            .unwrap()
            .is_empty());
        // every id resolves on its own
        for e in &all {
            assert_eq!(select(&all, &[e.id.to_string()], None).unwrap()[0].id, e.id);
        }
    }

    #[test]
    fn failing_and_panicking_evals_are_reported() {
        let good = eval("test/good", passes);
        let bad = eval("test/bad", fails);
        let boom = eval("test/boom", panics);

        let o = run_one(&bad);
        assert!(!o.ok && o.status() == "fail");
        assert!(o
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("deliberate failure"));

        let o = run_one(&boom);
        assert!(!o.ok, "a panicking eval must be reported, not propagated");
        let msg = o.error.clone().unwrap_or_default();
        assert!(
            msg.contains("panicked") && msg.contains("deliberate panic"),
            "unexpected error: {msg}"
        );

        let opts = RunOpts {
            quiet: true,
            ..Default::default()
        };
        assert_eq!(run_selected(&[&good], &opts).unwrap(), 0);
        assert_eq!(
            run_selected(&[&bad], &opts).unwrap(),
            1,
            "one failure must set the exit code"
        );
        assert_eq!(
            run_selected(&[&boom], &opts).unwrap(),
            1,
            "a caught panic must set the exit code"
        );
        assert_eq!(run_selected(&[&good, &bad], &opts).unwrap(), 1);

        // the summary and the JSON report agree with the outcomes
        let results = vec![run_one(&good), run_one(&bad)];
        assert_eq!(summary_line(&results, 420), "1 passed, 1 failed in 0.4s");
        assert_eq!(summary_line(&results[..1], 5), "1 passed in 0.0s");
        let j = json_report(&results, 420);
        assert_eq!(
            (
                j["passed"].clone(),
                j["failed"].clone(),
                j["duration_ms"].clone()
            ),
            (json!(1), json!(1), json!(420))
        );
        assert_eq!(j["evals"][0]["status"], "pass");
        assert_eq!(j["evals"][1]["status"], "fail");
        assert!(j["evals"][1]["error"]
            .as_str()
            .unwrap_or_default()
            .contains("2 != 3"));
        assert!(j["evals"][0].get("error").is_none());
    }

    #[test]
    fn dispatch_scope_and_subcommands() {
        // main.rs parses `raw[1..]`, so the command itself is not a positional.
        let a = Args::parse(&["list".to_string()]).unwrap();
        assert!(
            dispatch("run", &a, &[]).is_none(),
            "dispatch must ignore foreign commands"
        );
        assert!(dispatch("doctor", &a, &[]).is_none());
        assert_eq!(dispatch("evals", &a, &[]).unwrap().unwrap(), 0);

        let run = Args::parse(&["run".to_string(), "wire/handshake".to_string()]).unwrap();
        assert_eq!(dispatch("evals", &run, &[]).unwrap().unwrap(), 0);

        let bad = Args::parse(&["bogus".to_string()]).unwrap();
        assert!(
            dispatch("evals", &bad, &[]).unwrap().is_err(),
            "an unknown subcommand must be a usage error"
        );

        let unknown = Args::parse(&[
            "evals".to_string(),
            "run".to_string(),
            "no/such".to_string(),
        ])
        .unwrap();
        assert!(
            dispatch("evals", &unknown, &[]).unwrap().is_err(),
            "an unknown eval id must fail"
        );

        let filtered = Args::parse(&[
            "evals".to_string(),
            "run".to_string(),
            "--filter".to_string(),
            "zzz".to_string(),
        ])
        .unwrap();
        assert!(
            dispatch("evals", &filtered, &[]).unwrap().is_err(),
            "an empty filter selection must fail"
        );
    }
}
