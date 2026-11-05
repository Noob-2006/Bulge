//! The binary's whole registration list: one line per *crate* (or per subsystem that owns
//! self-contained wiring), not one line per feature.
//!
//! Everything a feature needs — its tools, its CLI command family, its config validator — is
//! declared by the module that owns it through `ark_core::registry` (see that module's docs).
//! Adding a tool, a command or a config check no longer touches `main.rs`, `ext.rs`,
//! `kernel.rs` or `config.rs`; it touches the feature's own file. This file only says "the
//! following crates are part of this binary".
//!
//! Registration is idempotent (`register_tool_provider` replaces by name), so both `dispatch()`
//! and `wire::tools()` call it: a test that builds tools without dispatching a command still
//! sees them, and a second call in one process cannot duplicate anything.
//!
//! Cross-crate direction: `ark_core` collects, the crate declares. A crate that does not link
//! `ark-kernel` (ark-tools, ark-browser, ark-media) cannot read the kernel `Config`, so its
//! adapter lives in the binary (e.g. `web_cli::register` for `ark_tools::web`) instead of
//! pulling the kernel into it. See docs/ARCHITECTURE.md §"Registration points".

/// Register every subsystem's contributions. Cheap (a few map updates) and idempotent.
pub fn register() {
    // Crates that link ark-kernel and declare their own tools.
    ark_skills::host::register();
    ark_memory::host::register();
    ark_kernel::cronjob::register();
    ark_kernel::kanban::register();
    // The binary's own subsystems.
    crate::exec_cli::register();
    crate::web_cli::register();
    crate::meetings::meet::register();
    crate::meetings::meet::register_hooks();
    crate::plugin_backends::register();
    register_ops();
    // CLI command families whose flags the binary's parser must not see.
    crate::meetings::register_route();
    crate::agentcmds::register_routes();
    crate::control_cli::register_route();
    crate::media_host::register_route();
    crate::message_cli::register_route();
    crate::role_cli::register_route();
}

/// DevOps / SecOps tools (`ark_tools::ops`, `ark_tools::secops`) over the opaque
/// `[integrations]` table: monitoring queries, `deploy`, tickets / incidents, scan reports,
/// OSV, SIEM alerts and compliance checklists. Query and ticket tools appear only for the
/// sections that name an endpoint.
fn register_ops() {
    ark_core::registry::register_tool_provider("ops", 320, |env| {
        let cfg = env.config::<ark_kernel::config::Config>()?;
        Ok(ark_tools::ops::tools_from_value(serde_json::to_value(&cfg.integrations).unwrap_or(serde_json::Value::Null)))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_kernel::config::{Config, Paths};
    use std::path::PathBuf;

    struct Scratch {
        dir: ark_core::tmp::TempDir,
        paths: Paths,
        ws: PathBuf,
    }

    impl Scratch {
        fn new() -> Scratch {
            let dir = ark_core::tmp::TempDir::new("ark-registry");
            let paths = Paths { data: dir.join("data"), config_dir: dir.join("config"), runtime: dir.join("run") };
            std::fs::create_dir_all(&paths.data).unwrap();
            let ws = paths.data.join("ws");
            std::fs::create_dir_all(&ws).unwrap();
            Scratch { dir, paths, ws }
        }
        fn env<'a>(&'a self, cfg: &'a Config) -> ark_core::registry::HostEnv<'a> {
            ark_core::registry::HostEnv::new(cfg, self.ws.clone(), self.paths.data.clone(), self.paths.config_dir.clone(), self.paths.runtime.clone())
        }
    }

    /// The binary registers every subsystem exactly once, in collection order.
    #[test]
    fn every_subsystem_registers_once() {
        register();
        register();
        let names: Vec<&str> = ark_core::registry::tool_providers().iter().map(|p| p.name).collect();
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(names.len(), sorted.len(), "no provider registered twice: {names:?}");
        for name in ["skills", "memory", "cronjob", "kanban", "web", "web-cli", "google-meet", "media-plugin-backends", "xai-code-execution", "ops"] {
            assert!(names.contains(&name), "{name} is registered: {names:?}");
        }
        let order: Vec<i32> = ark_core::registry::tool_providers().iter().map(|p| p.order).collect();
        let mut sorted_order = order.clone();
        sorted_order.sort();
        assert_eq!(order, sorted_order, "providers are collected in order");
    }

    /// The registry produces the tools `wire::tools` used to concatenate by hand, so the
    /// migration is behaviour-preserving: the model sees the same tools.
    #[test]
    fn the_registry_replaces_the_hand_written_wiring() {
        register();
        let s = Scratch::new();
        let cfg = Config::default();
        let (tools, warnings) = ark_core::registry::collect_tools(&s.env(&cfg));
        assert!(warnings.is_empty(), "default config registers cleanly: {warnings:?}");
        let names: Vec<String> = tools.iter().map(|t| t.spec().name).collect();
        for name in ["meet_join", "meet_leave", "memory_search", "web_fetch"] {
            assert!(names.iter().any(|n| n == name), "{name} missing from {names:?}");
        }
        let wired: Vec<String> = crate::wire::tools(&cfg, &s.paths, &s.ws).iter().map(|t| t.spec().name).collect();
        for n in &names {
            assert!(wired.iter().any(|w| w == n), "wire::tools (the legacy entry point) keeps `{n}`");
        }
        drop(s.dir);
    }

    /// The command families a subsystem claims are dispatched by the registry; nothing the
    /// binary handles itself is claimed.
    #[test]
    fn command_families_are_claimed_by_their_owner() {
        register();
        let mut names = ark_core::registry::registered_command_names();
        names.sort();
        names.dedup();
        assert_eq!(names, ["agents", "browser", "capability", "computer-use", "infer", "kanban", "meet", "message", "moa", "role", "roles", "screen", "stt", "teams", "teams-pipeline", "transcripts", "voice"]);
        assert!(ark_core::registry::command_route("run", &[]).is_none(), "`ark run` stays in the binary");
        assert!(ark_core::registry::command_route("doctor", &[]).is_none());
        assert!(ark_core::registry::command_route("meet", &[]).is_some(), "an unknown sub-command is the family's own usage error");
    }

    /// The ops / secops tools reach the model through the registry, driven by `[integrations]`.
    #[test]
    fn ops_tools_follow_the_integrations_table() {
        register();
        let s = Scratch::new();
        let names = |cfg: &Config| ark_core::registry::collect_tools(&s.env(cfg)).0.iter().map(|t| t.spec().name).collect::<Vec<_>>();
        let base = names(&Config::default());
        for n in ["deploy", "scan_report", "osv_query", "compliance_check"] {
            assert!(base.iter().any(|x| x == n), "{n} missing from {base:?}");
        }
        assert!(!base.iter().any(|x| x == "prometheus_query" || x == "jira"));
        let cfg: Config = toml::from_str("[integrations.prometheus]\nurl = \"http://prom:9090\"\n[integrations.jira]\nurl = \"https://jira.example.com\"\ntoken = \"{{secret:JIRA_TOKEN}}\"\n[integrations.wazuh]\nurl = \"https://wazuh:9200\"\n").unwrap();
        let all = names(&cfg);
        for n in ["prometheus_query", "jira", "siem_alerts"] {
            assert!(all.iter().any(|x| x == n), "{n} missing from {all:?}");
        }
        drop(s.dir);
    }
}
