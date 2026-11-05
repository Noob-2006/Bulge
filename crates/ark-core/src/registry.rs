//! Self-registration points: the alternative to one giant table per feature.
//!
//! Every subsystem used to be wired in the same few files (`main.rs` dispatch, `ext.rs`,
//! `kernel.rs`, `config.rs`), so two people adding two unrelated features always edited the
//! same lines. Here the *owner* of a feature declares it, once, in its own module:
//!
//! * [`register_tool_provider`] — a factory for the model-facing tools of a subsystem
//!   (skills, memory, web, meetings, kanban, plugins, …). `ark_core` only collects them.
//! * [`register_command_route`] — a CLI command family that owns its own flags
//!   (`ark meet …`), dispatched before the binary's argument parser sees `argv`.
//! * [`register_config_validator`] — the `[section]` of a config file validates itself where
//!   the section is defined, instead of inside `Config::validate`.
//!
//! Wiring: each crate exposes `pub fn register()` and the binary calls those (one line per
//! *crate*, not per feature) from `crates/ark/src/registry_init.rs`. Registration is
//! idempotent: calling it twice replaces the earlier entry by name, so a process may init
//! more than once (tests do) without duplicating tools.
//!
//! Why not link-time registration (`inventory`-style)? It needs a new dependency and an
//! unsafe linker-section trick for a problem a 14-line init list already solves; the
//! dependency budget in `Cargo.toml` is a deliberate constraint (see docs/ARCHITECTURE.md).
//!
//! Context: a provider receives a [`HostEnv`] — the paths it may use and the loaded config as
//! `&dyn Any` (each provider downcasts to the `Config` type it was compiled against). Crates
//! that do not link `ark-kernel` register through a thin adapter in the binary instead of
//! depending on the kernel just to read a section (see docs/ARCHITECTURE.md, "dependency
//! direction").

use crate::tool::Tool;
use std::any::Any;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// What a registered provider may read: the loaded config (downcast it), the workspace and
/// the three ark home directories.
pub struct HostEnv<'a> {
    config: &'a dyn Any,
    pub workspace: PathBuf,
    pub data: PathBuf,
    pub config_dir: PathBuf,
    pub runtime: PathBuf,
}

impl<'a> HostEnv<'a> {
    pub fn new(config: &'a dyn Any, workspace: impl Into<PathBuf>, data: impl Into<PathBuf>, config_dir: impl Into<PathBuf>, runtime: impl Into<PathBuf>) -> HostEnv<'a> {
        HostEnv { config, workspace: workspace.into(), data: data.into(), config_dir: config_dir.into(), runtime: runtime.into() }
    }

    /// The loaded config as the type the caller was compiled against. A provider registered
    /// against a different `Config` type is a programming error, not a runtime condition: the
    /// error names both types so the fix is obvious.
    pub fn config<T: Any>(&self) -> Result<&T, String> {
        self.config.downcast_ref::<T>().ok_or_else(|| format!("the registered config is not `{}`", std::any::type_name::<T>()))
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }
}

/// A factory for one subsystem's tools. `order` places it in the collection order (10 for the
/// low-level file/skills tools, 100+ for optional surfaces) — tools with the same *name* are
/// still deduplicated by the caller (later wins), as before.
pub type ToolFactory = fn(&HostEnv) -> Result<Vec<Arc<dyn Tool>>, String>;

#[derive(Clone)]
pub struct ToolProvider {
    pub name: &'static str,
    pub order: i32,
    pub factory: ToolFactory,
}

static TOOL_PROVIDERS: RwLock<Vec<ToolProvider>> = RwLock::new(Vec::new());

/// Declare a tool provider. Idempotent per `name` (the last registration wins), so calling a
/// crate's `register()` twice cannot duplicate tools.
pub fn register_tool_provider(name: &'static str, order: i32, factory: ToolFactory) {
    let mut g = TOOL_PROVIDERS.write().unwrap();
    g.retain(|p| p.name != name);
    g.push(ToolProvider { name, order, factory });
    g.sort_by(|a, b| a.order.cmp(&b.order).then_with(|| a.name.cmp(b.name)));
}

/// Every registered provider, in collection order.
pub fn tool_providers() -> Vec<ToolProvider> {
    TOOL_PROVIDERS.read().unwrap().clone()
}

/// Run every provider and concatenate the tools. A provider that fails (bad `[web]` table,
/// missing key) is a warning, never a lost tool set: the other subsystems still register.
/// Returns the tools in provider order plus one line per failure.
pub fn collect_tools(env: &HostEnv) -> (Vec<Arc<dyn Tool>>, Vec<String>) {
    let mut tools = Vec::new();
    let mut warnings = Vec::new();
    for p in tool_providers() {
        match (p.factory)(env) {
            Ok(v) => tools.extend(v),
            Err(e) => warnings.push(format!("{}: {e}", p.name)),
        }
    }
    (tools, warnings)
}

/// Forget every provider (tests; nothing in production tears the registry down).
pub fn clear_tool_providers() {
    TOOL_PROVIDERS.write().unwrap().clear();
}

// ───────────────────────── CLI command routes ─────────────────────────

/// Registered routes, in registration order (first match wins).
static ROUTES: RwLock<Vec<RouteEntry>> = RwLock::new(Vec::new());

struct RouteEntry {
    names: &'static str,
    owns: Option<fn(&str) -> bool>,
    run: fn(&str, &[String]) -> Result<i32, String>,
}

/// Declare a command family. `names` is a comma-separated list (`"meet,teams"`) because a
/// `&'static [&'static str]` cannot be built in a `register()` function without a const.
pub fn register_command_route(names: &'static str, owns: Option<fn(&str) -> bool>, run: fn(&str, &[String]) -> Result<i32, String>) {
    let mut g = ROUTES.write().unwrap();
    g.retain(|r| r.names != names);
    g.push(RouteEntry { names, owns, run });
}

/// The handler for `cmd`, if a subsystem claimed it. `Err` from the handler is the command's
/// own failure text (same as `wire::cli`); `None` means "not mine, keep dispatching".
pub fn command_route(cmd: &str, argv: &[String]) -> Option<Result<i32, String>> {
    let sub = argv.first().map(String::as_str).unwrap_or("");
    // Pick the handler under the lock, run it after releasing: handlers may register routes
    // (or route again), and doing that while holding the read lock deadlocks.
    let run = {
        let g = ROUTES.read().unwrap();
        g.iter().find(|r| r.names.split(',').any(|n| n.trim() == cmd) && !r.owns.is_some_and(|f| !f(sub))).map(|r| r.run)
    }?;
    Some(run(cmd, argv))
}

/// Command words a subsystem claimed (help text / tests).
pub fn registered_command_names() -> Vec<&'static str> {
    ROUTES.read().unwrap().iter().flat_map(|r| r.names.split(',').map(|s| s.trim())).filter(|s| !s.is_empty()).collect()
}

pub fn clear_command_routes() {
    ROUTES.write().unwrap().clear();
}

// ───────────────────────── config section validators ─────────────────────────

/// A `[section]`'s own validation: push one message per problem, in the section's words.
pub type SectionValidator = fn(&dyn Any, &mut Vec<String>);

struct ValidatorEntry {
    name: &'static str,
    f: SectionValidator,
}

static VALIDATORS: RwLock<Vec<ValidatorEntry>> = RwLock::new(Vec::new());

/// Declare the validator of a config section. `name` is the section path (`"kanban"`,
/// `"media.vision"`) and is prefixed onto every message by [`validate_config`].
pub fn register_config_validator(name: &'static str, f: SectionValidator) {
    let mut g = VALIDATORS.write().unwrap();
    g.retain(|v| v.name != name);
    g.push(ValidatorEntry { name, f });
    g.sort_by(|a, b| a.name.cmp(b.name));
}

/// Run every section validator against `cfg`; `["kanban: unknown mode `x`", …]`.
pub fn validate_config(cfg: &dyn Any) -> Vec<String> {
    let mut out = Vec::new();
    // Copy the list out first: a validator that registers or validates again must not
    // run while this read lock is held.
    let validators: Vec<(&'static str, SectionValidator)> = VALIDATORS.read().unwrap().iter().map(|v| (v.name, v.f)).collect();
    for (name, f) in validators {
        let mut msgs = Vec::new();
        f(cfg, &mut msgs);
        out.extend(msgs.into_iter().map(|m| if m.starts_with(name) { m } else { format!("{name}: {m}") }));
    }
    out
}

/// Section names with a registered validator (docs/tests).
pub fn validated_sections() -> Vec<&'static str> {
    VALIDATORS.read().unwrap().iter().map(|v| v.name).collect()
}

pub fn clear_config_validators() {
    VALIDATORS.write().unwrap().clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool::{ToolOutput, ToolSpec};
    use serde_json::Value;
    use std::sync::Mutex;

    struct Fixed(&'static str);

    impl Tool for Fixed {
        fn spec(&self) -> ToolSpec {
            ToolSpec { name: self.0.to_string(), description: String::new(), input_schema: serde_json::json!({"type": "object"}), parallel_safe: false, idempotent: false, pinned: false }
        }
        fn effects(&self, _: &crate::ToolCtx, _: &Value) -> Vec<crate::Effect> {
            Vec::new()
        }
        fn call(&self, _: &crate::ToolCtx, _: Value) -> ToolOutput {
            ToolOutput::ok("ok")
        }
    }

    fn provider(_: &HostEnv) -> Result<Vec<Arc<dyn Tool>>, String> {
        Ok(vec![Arc::new(Fixed("alpha"))])
    }

    fn failing(_: &HostEnv) -> Result<Vec<Arc<dyn Tool>>, String> {
        Err("bad [web] table".into())
    }

    fn late(_: &HostEnv) -> Result<Vec<Arc<dyn Tool>>, String> {
        Ok(vec![Arc::new(Fixed("omega"))])
    }

    /// Registrations are ordered by `order`, and re-registering a name replaces it: init may
    /// run twice (tests, daemon restart in-process) without duplicating tools.
    #[test]
    fn providers_are_ordered_and_idempotent() {
        clear_tool_providers();
        register_tool_provider("late", 300, late);
        register_tool_provider("early", 100, provider);
        register_tool_provider("early", 100, provider);
        let names: Vec<&str> = tool_providers().iter().map(|p| p.name).collect();
        assert_eq!(names, ["early", "late"], "sorted by order, no duplicates");
        let env = HostEnv::new(&(), "/ws", "/data", "/cfg", "/run");
        let (tools, warnings) = collect_tools(&env);
        assert_eq!(tools.iter().map(|t| t.spec().name).collect::<Vec<_>>(), ["alpha", "omega"]);
        assert!(warnings.is_empty());
    }

    /// One broken subsystem is a warning; the others still contribute their tools.
    #[test]
    fn a_failing_provider_is_a_warning_not_a_lost_tool_set() {
        clear_tool_providers();
        register_tool_provider("broken", 10, failing);
        register_tool_provider("fine", 20, provider);
        let (tools, warnings) = collect_tools(&HostEnv::new(&(), "/ws", "/d", "/c", "/r"));
        assert_eq!(tools.len(), 1);
        assert_eq!(warnings, ["broken: bad [web] table"]);
    }

    /// The config a provider sees is the caller's own type; asking for another one fails with
    /// a message that names what was asked for instead of panicking.
    #[test]
    fn the_config_downcasts_to_the_callers_type() {
        let cfg = 41u32;
        let env = HostEnv::new(&cfg, "/ws", "/d", "/c", "/r");
        assert_eq!(*env.config::<u32>().unwrap(), 41);
        assert!(env.config::<String>().unwrap_err().contains("String"));
    }

    /// Command routes: first match wins, `owns` filters sub-commands, unknown words fall
    /// through to the binary's own dispatch.
    #[test]
    fn command_routes_dispatch_by_name_and_sub_command() {
        clear_command_routes();
        static SEEN: Mutex<Vec<String>> = Mutex::new(Vec::new());
        fn meet(_: &str, argv: &[String]) -> Result<i32, String> {
            SEEN.lock().unwrap().push(argv.join(" "));
            Ok(7)
        }
        fn memory_extra(sub: &str) -> bool {
            sub != "show"
        }
        register_command_route("meet,teams", None, meet);
        register_command_route("memory", Some(memory_extra), meet);
        assert_eq!(command_route("meet", &["bot".into()]), Some(Ok(7)));
        assert_eq!(command_route("teams", &[]), Some(Ok(7)));
        assert_eq!(command_route("memory", &["review".into()]), Some(Ok(7)));
        assert_eq!(command_route("memory", &["show".into()]), None, "`ark memory show` stays in the binary");
        assert_eq!(command_route("run", &[]), None);
        assert_eq!(SEEN.lock().unwrap().as_slice(), ["bot", "", "review"]);
        let mut names = registered_command_names();
        names.sort();
        assert_eq!(names, ["meet", "memory", "teams"]);
    }

    /// Section validators run in name order and every message is prefixed with its section, so
    /// a user sees `kanban: …` and not a bare sentence.
    #[test]
    fn config_validators_are_prefixed_and_ordered() {
        clear_config_validators();
        fn kanban(cfg: &dyn Any, out: &mut Vec<String>) {
            if cfg.downcast_ref::<u32>() == Some(&1) {
                out.push("unknown mode `x`".into());
                out.push("kanban: second problem".into());
            }
        }
        fn media(_: &dyn Any, out: &mut Vec<String>) {
            out.push("vision.max_bytes must be > 0".into());
        }
        register_config_validator("media", media);
        register_config_validator("kanban", kanban);
        assert_eq!(validated_sections(), ["kanban", "media"]);
        let msgs = validate_config(&1u32);
        assert_eq!(msgs, ["kanban: unknown mode `x`", "kanban: second problem", "media: vision.max_bytes must be > 0"]);
        assert!(validate_config(&2u32).len() == 1, "a valid config yields only the media message");
    }
}
