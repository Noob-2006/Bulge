//! Host wiring: the tools this crate contributes and what it attaches to a running kernel.
//! Called from `crates/seagent/src/wire.rs`. `core` = the skills system itself, `hub` = the hub,
//! catalogs, bundled sync and plugin lifecycle.

use seagent_core::Tool;
use seagent_kernel::config::{Config, Paths};
use seagent_kernel::kernel::Kernel;
use std::path::Path;
use std::sync::Arc;

/// Tools to register before the kernel is built (they replace seagent-tools' builtins by name).
pub fn tools(cfg: &Config, paths: &Paths, ws: &Path) -> Vec<Arc<dyn Tool>> {
    let mut v = crate::core::tools(cfg, paths, ws);
    v.extend(crate::hub::tools(cfg, paths, ws));
    v
}

/// After the kernel exists: lifecycles (skills index, usage, curator), slash commands.
pub fn attach(k: &Kernel, ws: &Path) {
    crate::core::attach(k, ws);
}

/// `seagent skills|skill|hub|bundles|curator …` and `seagent plugins <install|…>`; argv excludes the command.
pub fn cli(cmd: &str, argv: &[String], cfg: &Config, paths: &Paths, ws: &Path) -> Result<i32, String> {
    match cmd {
        "bundles" | "bundle" | "curator" => crate::core::cli(cmd, argv, cfg, paths, ws),
        "plugin" | "plugins" => crate::hub::plugin_cli(argv, cfg, paths, ws),
        _ => crate::hub::cli(argv, cfg, paths, ws),
    }
}

/// Self-registration (`seagent_core::registry`): the skills tools, collected by the host instead of
/// being named in `seagent/src/wire.rs`. Order 100 = before the optional surfaces (memory is 110).
pub fn register() {
    seagent_core::registry::register_tool_provider("skills", 100, |env| {
        let cfg = env.config::<Config>()?;
        let paths = Paths { data: env.data.clone(), config_dir: env.config_dir.clone(), runtime: env.runtime.clone(), ..Default::default() };
        Ok(tools(cfg, &paths, &env.workspace))
    });
}
