//! seagent-browser: the built-in browser toolset. A raw CDP client drives a local
//! Chromium seagent launches itself (managed profiles), the user's Chrome, cloud browsers
//! (Browserbase, Browser Use, Firecrawl), a sandboxed container browser, Lightpanda,
//! or a browser extension relay; Camofox is spoken over its REST API.
//! Ports Hermes' browser_* tools and OpenClaw's `browser` tool (both MIT).

pub mod actions;
pub mod camofox;
pub mod cdp;
pub mod cloud;
pub mod config;
pub mod control;
pub mod engine;
pub mod exec;
/// The Chrome-extension relay is a personal-desktop bridge (gen1-306): built with
/// `--features personal`; otherwise a stub that explains how to get it.
#[cfg(feature = "personal")]
pub mod extension;
#[cfg(not(feature = "personal"))]
#[path = "extension_off.rs"]
pub mod extension;
pub mod keys;
pub mod launch;
pub mod launch_os;
pub mod lease;
pub mod manager;
pub mod openclaw;
pub mod policy;
pub mod sandbox;
pub mod snapshot;
pub mod tools;
pub mod util;
pub mod vault;
pub mod vault_tool;
pub mod view;

pub use config::BrowserConfig;

/// A human holds the Bot Desktop (vault fills and screen actions are refused).
pub fn desktop_lease_human(home: &std::path::Path) -> bool {
    lease::agent_may_act(home).is_err() && home.join("bot-desktop").exists()
}

/// Is some browser reachable without starting anything (for `enabled = "auto"`)?
pub fn available(cfg: &BrowserConfig) -> bool {
    match cfg.backend().as_str() {
        "local" => launch::find_executable(&cfg.executable).is_ok(),
        "lightpanda" => launch::lightpanda_binary().is_some(),
        "sandbox" => sandbox::available(),
        "extension" => cfg.extension_control.enabled,
        _ => true,
    }
}

/// The browser tools for a config: OpenClaw `browser` plus Hermes' browser_* set.
pub fn tools(t: &toml::Table) -> Result<Vec<std::sync::Arc<dyn seagent_core::Tool>>, String> {
    let cfg = BrowserConfig::parse(t)?;
    let on = match cfg.enabled() {
        Some(b) => b,
        None => available(&cfg),
    };
    if !on {
        return Ok(vec![]);
    }
    let cfg = std::sync::Arc::new(cfg);
    let mut v: Vec<std::sync::Arc<dyn seagent_core::Tool>> = vec![std::sync::Arc::new(openclaw::BrowserTool { cfg: cfg.clone() })];
    for n in tools::HERMES_TOOLS {
        if *n == "browser_exec" && !cfg.exec_enabled {
            continue;
        }
        v.push(std::sync::Arc::new(tools::HermesTool { name: n, cfg: cfg.clone() }));
    }
    Ok(v)
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_actions;
#[cfg(test)]
mod tests_runtime;
#[cfg(test)]
mod tests_real;
