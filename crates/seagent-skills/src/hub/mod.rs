//! The skills hub, catalogs, bundled sync and plugin lifecycle (stream "hub").

pub mod ast_audit;
pub mod cli;
pub mod evaluator;
pub mod http;
pub mod install;
pub mod model;
pub mod plugins;
pub mod sources;
pub mod sync;
pub mod tool;
pub mod verify;
pub mod zip;

use seagent_core::Tool;
use seagent_kernel::config::{Config, Paths};
use std::path::Path;
use std::sync::Arc;

/// The `plugins` tool.
pub fn tools(cfg: &Config, paths: &Paths, _ws: &Path) -> Vec<Arc<dyn Tool>> {
    vec![Arc::new(tool::PluginsTool { cfg: cfg.clone(), paths: paths.clone() })]
}

fn read_line(prompt: &str) -> Option<String> {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return None;
    }
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s).ok()?;
    Some(s.trim().to_string()).filter(|x| !x.is_empty())
}

/// `seagent skills …` / `seagent hub …`.
pub fn cli(argv: &[String], cfg: &Config, paths: &Paths, ws: &Path) -> Result<i32, String> {
    let c = cli::Ctx { cfg, paths, ws, ask: Some(&read_line) };
    println!("{}", cli::run(&c, argv)?);
    Ok(0)
}

/// `seagent plugins install|update|uninstall|search|…`.
pub fn plugin_cli(argv: &[String], cfg: &Config, paths: &Paths, _ws: &Path) -> Result<i32, String> {
    match plugins::cli(cfg, paths, argv) {
        Some(r) => {
            println!("{}", r?);
            Ok(0)
        }
        None => Err(format!("unknown `seagent plugins` subcommand `{}` (catalog, search, marketplace, install, uninstall, enable, disable, inspect, mcps, mcp-install)", argv.first().map(String::as_str).unwrap_or(""))),
    }
}
