//! Tool profiles and allow/deny groups (OpenClaw `src/agents/tool-catalog.ts`,
//! `tool-policy*.ts`).
//!
//! A profile (`minimal`, `coding`, `messaging`, `full`, and the professional-role profiles
//! `devops`, `secops`, `data`, `itsupport` of `share/roles/presets.toml`) is a base allowlist; `allow`
//! replaces it, `also_allow` extends it, `deny` always wins. Entries may be tool names,
//! `group:<section>` names or `*` globs (`mcp__github__*`). Scoped policies narrow the
//! global one for a provider/model, a channel, or a channel sender — every applicable
//! layer must allow the tool.

use crate::glob::fnmatch;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Layer {
    pub profile: Option<String>,
    pub allow: Vec<String>,
    pub also_allow: Vec<String>,
    pub deny: Vec<String>,
}

/// Where a session's turn comes from, for scoped policies.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Origin {
    /// `provider/model`.
    pub model: String,
    pub channel: Option<String>,
    pub sender: Option<String>,
}

/// Groups over ark's tool names (kernel, builtin and well-known extension tools).
pub fn groups() -> BTreeMap<&'static str, &'static [&'static str]> {
    BTreeMap::from([
        ("group:fs", &["read", "write", "edit", "patch", "glob", "grep"][..]),
        ("group:runtime", &["shell", "run", "job", "process"][..]),
        ("group:web", &["web_fetch", "web_search", "web_extract", "browser"][..]),
        ("group:memory", &["memory", "session_search"][..]),
        ("group:sessions", &["spawn", "ark_session", "ark_session_send", "ark_session_list", "sessions_spawn", "sessions_send", "sessions_list", "session_status"][..]),
        ("group:agents", &["spawn", "acp_delegate", "a2a_send", "a2a_list", "a2a_task"][..]),
        ("group:messaging", &["channel_send", "message"][..]),
        ("group:automation", &["cron", "schedule", "goal_done"][..]),
        ("group:nodes", &["node_invoke"][..]),
        ("group:plan", &["todo", "skill", "ask_user", "tool_describe", "tool_call"][..]),
        ("group:media", &["image", "tts", "pdf", "image_generate", "vision"][..]),
        // Professional-role tools (ark_tools::{data, directory, forge}); present only when configured.
        ("group:data", &["sql_query", "sql_schema"][..]),
        ("group:directory", &["directory_lookup"][..]),
        ("group:forge", &["forge_read", "forge_write"][..]),
    ])
}

/// Built-in profiles. `full` = no restriction (None).
pub fn profile(name: &str) -> Option<Option<Vec<String>>> {
    let g = groups();
    let expand = |names: &[&str]| -> Vec<String> { names.iter().flat_map(|n| g.get(n).map(|v| v.iter().map(|s| s.to_string()).collect()).unwrap_or_else(|| vec![n.to_string()])).collect() };
    Some(match name {
        "minimal" => Some(expand(&["ask_user", "todo", "tool_describe", "tool_call", "session_status"])),
        "coding" => Some(expand(&["group:fs", "group:runtime", "group:web", "group:memory", "group:sessions", "group:agents", "group:plan", "group:media", "group:forge"])),
        "messaging" => Some(expand(&["group:messaging", "group:memory", "group:web", "ask_user", "todo", "tool_describe", "tool_call", "session_status"])),
        // Professional roles (BATCH-next §3). DevOps/SRE: terminal, logs, process control,
        // scheduled checks, monitoring/integration connectors (MCP), sub-agents for parallel triage.
        "devops" => Some(expand(&["group:fs", "group:runtime", "group:web", "group:memory", "group:sessions", "group:agents", "group:plan", "group:automation", "group:forge", "mcp__*"])),
        // Security operations: read and analyse; no messaging, no automation, no remote nodes,
        // no delegation to external agents (offensive tooling is refused by the role policy).
        "secops" => Some(expand(&["group:fs", "group:runtime", "group:web", "group:memory", "group:plan", "group:sessions", "mcp__*"])),
        // Data analysis: files, a runtime for queries/notebooks, charts (media), DB connectors.
        "data" => Some(expand(&["group:fs", "group:runtime", "group:web", "group:memory", "group:plan", "group:media", "group:sessions", "group:data", "mcp__*"])),
        // IT support: ticket replies (messaging), diagnostics (runtime), knowledge base (web/memory).
        "itsupport" => Some(expand(&["group:fs", "group:runtime", "group:web", "group:memory", "group:plan", "group:messaging", "group:sessions", "group:directory", "mcp__*"])),
        "full" => None,
        _ => return None,
    })
}

fn alias(name: &str) -> String {
    match name.to_lowercase().as_str() {
        "bash" | "exec" => "shell".into(),
        "apply_patch" | "apply-patch" => "patch".into(),
        "cron" => "schedule".into(),
        n => n.to_string(),
    }
}

fn matches(entry: &str, tool: &str) -> bool {
    let e = entry.trim().to_lowercase();
    if let Some(members) = groups().get(e.as_str()) {
        return members.contains(&tool);
    }
    let e = alias(&e);
    if e.contains(['*', '?', '[']) {
        fnmatch(&e, tool)
    } else {
        e == tool
    }
}

/// Validate profile names (config load errors instead of silently allowing all).
pub fn validate(layer: &Layer, at: &str) -> Result<(), String> {
    if let Some(p) = &layer.profile {
        if profile(p).is_none() {
            return Err(format!("{at}.profile `{p}`: use minimal, coding, messaging, devops, secops, data, itsupport or full"));
        }
    }
    Ok(())
}

/// Does one layer allow `tool`?
pub fn layer_allows(layer: &Layer, tool: &str) -> bool {
    let tool = alias(tool);
    if layer.deny.iter().any(|d| matches(d, &tool)) {
        return false;
    }
    let base: Option<Vec<String>> = if !layer.allow.is_empty() {
        Some(layer.allow.clone())
    } else {
        layer.profile.as_deref().and_then(|p| profile(p).flatten())
    };
    match base {
        None => true,
        Some(b) => b.iter().chain(layer.also_allow.iter()).any(|a| matches(a, &tool)),
    }
}

/// Every layer that applies to `origin` must allow `tool`.
pub fn allowed(global: &Layer, by_provider: &BTreeMap<String, Layer>, by_channel: &BTreeMap<String, Layer>, by_sender: &BTreeMap<String, Layer>, origin: &Origin, tool: &str) -> bool {
    if !layer_allows(global, tool) {
        return false;
    }
    let provider = origin.model.split('/').next().unwrap_or("");
    for (k, l) in by_provider {
        if (k == &origin.model || k == provider) && !layer_allows(l, tool) {
            return false;
        }
    }
    if let Some(ch) = &origin.channel {
        if let Some(l) = by_channel.get(ch) {
            if !layer_allows(l, tool) {
                return false;
            }
        }
        if let Some(s) = &origin.sender {
            if let Some(l) = by_sender.get(&format!("{ch}:{s}")) {
                if !layer_allows(l, tool) {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_groups_allow_deny() {
        let coding = Layer { profile: Some("coding".into()), ..Default::default() };
        assert!(layer_allows(&coding, "shell") && layer_allows(&coding, "read") && !layer_allows(&coding, "channel_send"));
        let msg = Layer { profile: Some("messaging".into()), also_allow: vec!["read".into()], deny: vec!["web_fetch".into()], ..Default::default() };
        assert!(layer_allows(&msg, "channel_send") && layer_allows(&msg, "read") && !layer_allows(&msg, "web_fetch") && !layer_allows(&msg, "shell"));
        let full = Layer { profile: Some("full".into()), deny: vec!["group:runtime".into(), "mcp__danger__*".into()], ..Default::default() };
        assert!(!layer_allows(&full, "shell") && !layer_allows(&full, "bash"), "alias bash → shell");
        assert!(!layer_allows(&full, "mcp__danger__drop") && layer_allows(&full, "mcp__safe__x"));
        let explicit = Layer { allow: vec!["read".into(), "grep".into()], profile: Some("coding".into()), ..Default::default() };
        assert!(layer_allows(&explicit, "grep") && !layer_allows(&explicit, "write"), "allow replaces the profile");
        assert!(layer_allows(&Layer::default(), "anything"));
        assert!(validate(&Layer { profile: Some("admin".into()), ..Default::default() }, "tools").is_err());
    }

    #[test]
    fn professional_role_profiles() {
        let l = |p: &str| Layer { profile: Some(p.into()), ..Default::default() };
        for p in ["devops", "secops", "data", "itsupport"] {
            assert!(validate(&l(p), "tools").is_ok(), "{p}");
            assert!(layer_allows(&l(p), "read") && layer_allows(&l(p), "shell"), "{p} can read and run");
            assert!(layer_allows(&l(p), "mcp__grafana__query"), "{p} reaches connectors");
            assert!(!layer_allows(&l(p), "node_invoke"), "{p} has no remote nodes");
        }
        assert!(layer_allows(&l("devops"), "schedule") && !layer_allows(&l("secops"), "schedule"));
        assert!(!layer_allows(&l("secops"), "channel_send") && !layer_allows(&l("secops"), "a2a_send"));
        assert!(layer_allows(&l("itsupport"), "channel_send"), "IT support answers tickets");
        assert!(layer_allows(&l("data"), "image"), "charts");
    }

    /// The tools of ark_tools::{data, directory, forge} reach each role through its profile
    /// and no other (the data analyst cannot comment on a pull request, support cannot run SQL).
    #[test]
    fn professional_tools_belong_to_their_role_profile() {
        let l = |p: &str| Layer { profile: Some(p.into()), ..Default::default() };
        let can = |p: &str, t: &str| layer_allows(&l(p), t);
        for t in ["sql_query", "sql_schema"] {
            assert!(can("data", t) && !can("itsupport", t) && !can("coding", t) && !can("secops", t) && !can("devops", t), "{t}");
        }
        assert!(can("itsupport", "directory_lookup") && !can("data", "directory_lookup") && !can("coding", "directory_lookup") && !can("secops", "directory_lookup"));
        for t in ["forge_read", "forge_write"] {
            assert!(can("coding", t) && can("devops", t) && !can("data", t) && !can("itsupport", t) && !can("secops", t) && !can("messaging", t), "{t}");
        }
        assert!(layer_allows(&l("full"), "sql_query"));
    }

    #[test]
    fn scoped_layers_narrow() {
        let g = Layer::default();
        let bp = BTreeMap::from([("ollama".to_string(), Layer { profile: Some("minimal".into()), ..Default::default() })]);
        let bc = BTreeMap::from([("telegram".to_string(), Layer { deny: vec!["group:runtime".into()], ..Default::default() })]);
        let bs = BTreeMap::from([("telegram:42".to_string(), Layer { deny: vec!["write".into()], ..Default::default() })]);
        let o = |m: &str, c: Option<&str>, s: Option<&str>| Origin { model: m.into(), channel: c.map(String::from), sender: s.map(String::from) };
        assert!(allowed(&g, &bp, &bc, &bs, &o("anthropic/x", None, None), "shell"));
        assert!(!allowed(&g, &bp, &bc, &bs, &o("ollama/llama3", None, None), "shell"), "small local model gets minimal");
        assert!(!allowed(&g, &bp, &bc, &bs, &o("anthropic/x", Some("telegram"), Some("7")), "shell"));
        assert!(allowed(&g, &bp, &bc, &bs, &o("anthropic/x", Some("telegram"), Some("7")), "write"));
        assert!(!allowed(&g, &bp, &bc, &bs, &o("anthropic/x", Some("telegram"), Some("42")), "write"));
    }
}
