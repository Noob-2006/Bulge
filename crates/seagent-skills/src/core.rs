//! Entry points of the skills system proper (stream "skills core").

pub mod blueprints;
pub mod bundles;
pub mod cli;
pub mod confedit;
pub mod curator;
pub mod index;
pub mod invoke;
pub mod ledger;
pub mod lint;
pub mod manage;
pub mod preprocess;
pub mod review;
pub mod search;
pub mod settings;
pub mod setup;
pub mod skilltool;
pub mod slash;
pub mod usage;
pub mod workshop;

use seagent_core::Tool;
use seagent_kernel::config::{Config, Paths};
use seagent_kernel::kernel::Kernel;
use std::path::Path;
use std::sync::Arc;

/// Runs a sub-agent prompt and returns its final reply (surfaces with a kernel only).
pub type Fork<'a> = &'a dyn Fn(&str) -> Result<String, String>;

pub fn tools(cfg: &Config, paths: &Paths, _ws: &Path) -> Vec<Arc<dyn Tool>> {
    // `skill` replaces seagent-tools' builtin: `action=view` renders through this crate (preprocessing,
    // declared env, setup note, plugin skills); `action=list` / `search` read the gated catalog;
    // `patch` / `write_file` / `remove_file` / `operations` write through `core::manage` (security
    // guard, lint, ledger, approval gate); `action=workshop` proposes a SKILL.md. create / update /
    // archive stay the builtin writer.
    vec![skilltool::tool(cfg, paths)]
}

/// Lifecycles (skills index + live delta, usage telemetry, curator tick) and the native
/// slash commands (/skills, /bundles, /curator, /plugins, /<skill>, /<bundle>).
pub fn attach(k: &Kernel, _ws: &Path) {
    let st = settings::Store::new(&k.paths);
    let s = settings::Settings::load(&k.cfg);
    // One index instance per data dir: `/reload-skills` diffs against the prompt it built.
    k.add_lifecycle(index::shared(&k.cfg, &k.paths));
    k.add_lifecycle(Arc::new(usage::UsageTracker { store: st.clone() }));
    k.add_lifecycle(Arc::new(curator::CuratorTick { settings: s.clone(), store: st.clone() }));
    // Background review records candidate procedures per turn (`/curator review` writes them).
    k.add_lifecycle(Arc::new(review::ReviewTick::new(&k.cfg, &k.paths, s)));
    k.add_slash(Arc::new(slash::SkillsSlash));
}

/// `seagent bundles …`, `seagent curator …`.
pub fn cli(cmd: &str, argv: &[String], cfg: &Config, paths: &Paths, _ws: &Path) -> Result<i32, String> {
    let st = settings::Store::new(paths);
    let s = settings::Settings::load(cfg);
    let out = match cmd {
        "bundles" | "bundle" => bundles::cli(&st, argv)?,
        _ => cli::curator_cmd(cfg, paths, &s, &st, argv, None)?,
    };
    println!("{out}");
    Ok(0)
}
