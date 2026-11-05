//! Built-in plugins ported from upstream (Hermes `plugins/{disk-cleanup,security-guidance,
//! hermes-achievements}`, MIT). Unlike an installed plugin these ship inside the binary: no
//! process, no protocol, no install step — but the same surface (tools, hooks, a slash command)
//! and the same opt-in rule (all three are off until `[builtin_plugins.<name>] enabled = true`,
//! which `ark plugins enable <name>` writes for you).
//!
//! ```toml
//! [builtin_plugins.disk-cleanup]
//! enabled = true
//! dry_run = true            # never delete, only report
//!
//! [builtin_plugins.security-guidance]
//! enabled = true
//! block = false             # false = warn (append the guidance block), true = refuse the write
//!
//! [builtin_plugins.achievements]
//! enabled = true
//! ```
//!
//! The host adds them in `crates/ark/src/ext.rs` (tools + hooks) and `crates/ark/src/main.rs`
//! (`/disk-cleanup`, `/achievements` registered on the kernel's slash registry).

pub mod achievements;
pub mod disk_cleanup;
pub mod security_guidance;

use ark_core::Tool;
use ark_kernel::config::{Config, Paths};
use ark_kernel::hooks::Hook;
use ark_kernel::slash::Slash;
use std::path::Path;
use std::sync::Arc;

/// Names, one-line descriptions and the upstream they were ported from.
pub const NAMES: [(&str, &str, &str); 3] = [
    ("disk-cleanup", "Track and clean up ephemeral files created during a session", "Hermes plugins/disk-cleanup"),
    ("security-guidance", "Append security warnings to file-write results (or block the write)", "Hermes plugins/security-guidance"),
    ("achievements", "Tiered achievements earned from real session history", "Hermes plugins/hermes-achievements"),
];

/// Is the built-in plugin `name` enabled? Every built-in is opt-in (upstream ships every plugin
/// disabled until `plugins.enabled` lists it).
pub fn enabled(cfg: &Config, name: &str) -> bool {
    cfg.builtin_plugins.get(name).and_then(|t| t.get("enabled")).and_then(|v| v.as_bool()).unwrap_or(false)
}

/// One table of a built-in's settings (`None` when the section is absent).
pub fn settings<'a>(cfg: &'a Config, name: &str) -> Option<&'a toml::Table> {
    cfg.builtin_plugins.get(name).and_then(|v| v.as_table())
}

fn flag(cfg: &Config, name: &str, key: &str, default: bool) -> bool {
    cfg.builtin_plugins.get(name).and_then(|t| t.get(key)).and_then(|v| v.as_bool()).unwrap_or(default)
}

/// `dry_run` for disk-cleanup (`true` = report only; upstream `/disk-cleanup dry-run`).
pub fn dry_run(cfg: &Config) -> bool {
    flag(cfg, "disk-cleanup", "dry_run", false)
}

/// security-guidance `block`: refuse the write instead of appending a warning
/// (upstream env `SECURITY_GUIDANCE_BLOCK=1`).
pub fn guidance_block(cfg: &Config) -> bool {
    flag(cfg, "security-guidance", "block", false)
}

/// Tools the enabled built-ins contribute.
pub fn tools(cfg: &Config, paths: &Paths, _ws: &Path) -> Vec<Arc<dyn Tool>> {
    let mut v: Vec<Arc<dyn Tool>> = Vec::new();
    if enabled(cfg, "disk-cleanup") {
        v.extend(disk_cleanup::tools(cfg, paths));
    }
    if enabled(cfg, "achievements") {
        v.extend(achievements::tools(cfg, paths));
    }
    v
}

/// Hooks the enabled built-ins contribute.
pub fn hooks(cfg: &Config, paths: &Paths) -> Vec<Arc<dyn Hook>> {
    let mut v: Vec<Arc<dyn Hook>> = Vec::new();
    if enabled(cfg, "security-guidance") {
        v.push(Arc::new(security_guidance::Guidance::new(cfg)) as Arc<dyn Hook>);
    }
    if enabled(cfg, "disk-cleanup") {
        v.push(Arc::new(disk_cleanup::CleanupHook::new(cfg, paths)) as Arc<dyn Hook>);
    }
    v
}

/// Slash commands the enabled built-ins contribute (`/disk-cleanup`, `/achievements`).
pub fn slash(cfg: &Config, paths: &Paths) -> Vec<Arc<dyn Slash>> {
    let mut v: Vec<Arc<dyn Slash>> = Vec::new();
    if enabled(cfg, "disk-cleanup") {
        v.push(Arc::new(disk_cleanup::slash(cfg, paths)) as Arc<dyn Slash>);
    }
    if enabled(cfg, "achievements") {
        v.push(Arc::new(achievements::slash(cfg, paths)) as Arc<dyn Slash>);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(tag: &str) -> Paths {
        let d = ark_core::tmp::scratch_path(format!("ark-builtin-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        Paths { data: d.join("data"), config_dir: d.join("config"), runtime: d.join("run"), ..Default::default() }
    }

    fn on(cfg: &mut Config, names: &[&str]) {
        for n in names {
            cfg.builtin_plugins.insert((*n).into(), toml::from_str("enabled = true").unwrap());
        }
    }

    #[test]
    fn builtins_are_opt_in_and_compose_tools_hooks_and_slash() {
        let p = paths("a");
        let ws = ark_core::tmp::scratch("ark-ws");
        let mut cfg = Config::default();
        assert!(tools(&cfg, &p, &ws).is_empty() && hooks(&cfg, &p).is_empty() && slash(&cfg, &p).is_empty(), "off by default");
        for (n, _, _) in NAMES {
            assert!(!enabled(&cfg, n));
        }
        on(&mut cfg, &["disk-cleanup", "security-guidance", "achievements"]);
        for (n, _, _) in NAMES {
            assert!(enabled(&cfg, n), "{n} enabled");
        }
        let t: Vec<String> = tools(&cfg, &p, &ws).iter().map(|t| t.spec().name).collect();
        assert_eq!(t, vec!["disk_cleanup".to_string(), "achievements".to_string()]);
        let h: Vec<String> = hooks(&cfg, &p).iter().map(|h| h.name()).collect();
        assert_eq!(h, vec!["builtin:security-guidance".to_string(), "builtin:disk-cleanup".to_string()]);
        let s: Vec<Vec<String>> = slash(&cfg, &p).iter().map(|s| s.commands().into_iter().map(|(n, _)| n).collect()).collect();
        assert_eq!(s, vec![vec!["disk-cleanup".to_string()], vec!["achievements".to_string()]]);
        // Per-plugin settings: `dry_run` (disk-cleanup) and `block` (security-guidance) default off.
        assert!(!dry_run(&cfg) && !guidance_block(&cfg));
        cfg.builtin_plugins.insert("disk-cleanup".into(), toml::from_str("enabled = true\ndry_run = true").unwrap());
        cfg.builtin_plugins.insert("security-guidance".into(), toml::from_str("enabled = true\nblock = true").unwrap());
        assert!(dry_run(&cfg) && guidance_block(&cfg));
        cfg.builtin_plugins.insert("disk-cleanup".into(), toml::from_str("enabled = false").unwrap());
        assert!(settings(&cfg, "disk-cleanup").is_some() && !enabled(&cfg, "disk-cleanup") && tools(&cfg, &p, &ws).len() == 1);
        assert!(settings(&cfg, "nope").is_none());
    }
}
