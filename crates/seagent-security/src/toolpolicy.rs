//! Tool profiles and allow/deny groups (OpenClaw `src/agents/tool-catalog.ts`,
//! `tool-policy*.ts`).
//!
//! A profile (`minimal`, `coding`, `messaging`, `full`, and the professional-role profiles
//! `devops`, `secops`, `data`, `itsupport` of `share/roles/presets.toml`) is a base allowlist; `allow`
//! replaces it, `also_allow` extends it, `deny` always wins. Entries may be tool names,
//! `group:<section>` names or `*` globs (`mcp__github__*`). Scoped policies narrow the
//! global one for a provider/model, a channel, or a channel sender — every applicable
//! layer must allow the tool.

use crate::approvals::{max_ask, min_security, ExecAsk, ExecSecurity};
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
    /// Restrict-only host exec policy for turns on this model/sender
    /// (OpenClaw `tools.byProvider[...].exec.mode`). Only `by_provider` is consulted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecCeiling>,
}

/// A per-model exec ceiling. `mode` is the OpenClaw spelling
/// (`deny` < `allowlist` < `ask`/`auto` < `full`); `security`/`ask` can narrow a
/// mode or stand alone.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExecCeiling {
    pub mode: Option<String>,
    pub security: Option<ExecSecurity>,
    pub ask: Option<ExecAsk>,
}

impl ExecCeiling {
    /// The `(security, ask)` this ceiling imposes, if any field was set.
    pub fn policy(&self) -> Option<(ExecSecurity, ExecAsk)> {
        let base = match self.mode.as_deref().map(str::trim).map(str::to_ascii_lowercase).as_deref() {
            None => None,
            Some("deny") => Some((ExecSecurity::Deny, ExecAsk::Off)),
            Some("allowlist") => Some((ExecSecurity::Allowlist, ExecAsk::Off)),
            // `auto` selects the reviewer in OpenClaw; our reviewer is a session mode,
            // so the restrict-only part here is the allowlist + on-miss policy.
            Some("ask" | "auto") => Some((ExecSecurity::Allowlist, ExecAsk::OnMiss)),
            Some("full") => Some((ExecSecurity::Full, ExecAsk::Off)),
            Some(_) => return None,
        };
        match (base, self.security, self.ask) {
            (None, None, None) => None,
            (base, sec, ask) => {
                let (mut s, mut a) = base.unwrap_or((ExecSecurity::Full, ExecAsk::Off));
                if let Some(x) = sec {
                    s = x;
                }
                if let Some(x) = ask {
                    a = x;
                }
                Some((s, a))
            }
        }
    }
}

/// Compose a model ceiling onto the current exec policy: security takes the minimum,
/// ask the maximum, and a side that denies allowlist misses keeps them denied unless
/// the other side mandates `ask = always`.
pub fn compose_exec_policy(current: (ExecSecurity, ExecAsk), ceiling: (ExecSecurity, ExecAsk)) -> (ExecSecurity, ExecAsk) {
    let (cs, ca) = current;
    let (ss, sa) = ceiling;
    let denies = |s: ExecSecurity, a: ExecAsk| s != ExecSecurity::Full && a == ExecAsk::Off;
    let ask = if ca != ExecAsk::Always && (denies(cs, ca) || denies(ss, sa)) { ExecAsk::Off } else { max_ask(ca, sa) };
    (min_security(cs, ss), ask)
}

/// The strictest `exec` ceiling of every `[tools.by_provider]` layer matching `origin`
/// (`provider` or `provider/model`). `None` = no ceiling.
pub fn exec_ceiling(by_provider: &BTreeMap<String, Layer>, origin: &Origin) -> Option<(ExecSecurity, ExecAsk)> {
    let provider = origin.model.split('/').next().unwrap_or("");
    let mut out: Option<(ExecSecurity, ExecAsk)> = None;
    for (k, l) in by_provider {
        if k != &origin.model && k != provider {
            continue;
        }
        let Some(p) = l.exec.as_ref().and_then(ExecCeiling::policy) else { continue };
        out = Some(match out {
            None => p,
            Some(cur) => compose_exec_policy(cur, p),
        });
    }
    out
}

/// Layers that block `tool` for `origin`, in pipeline order, with the config that fixes each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub layer: String,
    pub config: String,
    pub fix: String,
}

pub fn explain(global: &Layer, by_provider: &BTreeMap<String, Layer>, by_channel: &BTreeMap<String, Layer>, by_sender: &BTreeMap<String, Layer>, origin: &Origin, tool: &str) -> Vec<Block> {
    let mut out = Vec::new();
    let hint = |what: &str| format!("add `{tool}` to {what}.also_allow, remove it from {what}.deny, or widen {what}.profile");
    if !layer_allows(global, tool) {
        out.push(Block { layer: "tools".into(), config: "tools.profile / tools.allow / tools.deny".into(), fix: hint("tools") });
    }
    let provider = origin.model.split('/').next().unwrap_or("");
    for (k, l) in by_provider {
        if (k == &origin.model || k == provider) && !layer_allows(l, tool) {
            let at = format!("tools.by_provider.{k}");
            out.push(Block { layer: at.clone(), config: format!("[{at}]"), fix: hint(&at) });
        }
    }
    if let Some(ch) = &origin.channel {
        if let Some(l) = by_channel.get(ch) {
            if !layer_allows(l, tool) {
                let at = format!("tools.by_channel.{ch}");
                out.push(Block { layer: at.clone(), config: format!("[{at}]"), fix: hint(&at) });
            }
        }
        if let Some(s) = &origin.sender {
            let key = format!("{ch}:{s}");
            if let Some(l) = by_sender.get(&key) {
                if !layer_allows(l, tool) {
                    let at = format!("tools.by_sender.{key}");
                    out.push(Block { layer: at.clone(), config: format!("[{at}]"), fix: hint(&at) });
                }
            }
        }
    }
    out
}

/// Where a session's turn comes from, for scoped policies.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Origin {
    /// `provider/model`.
    pub model: String,
    pub channel: Option<String>,
    pub sender: Option<String>,
}

/// Groups over seagent's tool names (kernel, builtin and well-known extension tools).
pub fn groups() -> BTreeMap<&'static str, &'static [&'static str]> {
    BTreeMap::from([
        ("group:fs", &["read", "write", "edit", "patch", "glob", "grep"][..]),
        ("group:runtime", &["shell", "run", "job", "process"][..]),
        ("group:web", &["web_fetch", "web_search", "web_extract", "browser"][..]),
        ("group:memory", &["memory", "session_search"][..]),
        ("group:sessions", &["spawn", "seagent_session", "seagent_session_send", "seagent_session_list", "sessions_spawn", "sessions_send", "sessions_list", "session_status"][..]),
        ("group:agents", &["spawn", "acp_delegate", "a2a_send", "a2a_list", "a2a_task"][..]),
        ("group:messaging", &["channel_send", "message"][..]),
        ("group:automation", &["cron", "schedule", "goal_done"][..]),
        ("group:nodes", &["node_invoke"][..]),
        ("group:plan", &["todo", "skill", "ask_user", "tool_describe", "tool_call"][..]),
        ("group:media", &["image", "tts", "pdf", "image_generate", "vision"][..]),
        // Professional-role tools (seagent_tools::{data, directory, forge}); present only when configured.
        ("group:data", &["sql_query", "sql_schema"][..]),
        ("group:directory", &["directory_lookup"][..]),
        ("group:forge", &["forge_read", "forge_write"][..]),
        // Professional DevOps / SecOps tools (seagent_tools::ops, seagent_tools::secops).
        ("group:observability", &["prometheus_query", "loki_query", "alertmanager_alerts", "elastic_search", "grafana_query"][..]),
        ("group:deploy", &["deploy"][..]),
        ("group:tickets", &["jira", "servicenow", "pagerduty"][..]),
        ("group:secops", &["scan_report", "osv_query", "siem_alerts", "compliance_check"][..]),
    ])
}

/// Built-in profiles. `full` = no restriction (None).
pub fn profile(name: &str) -> Option<Option<Vec<String>>> {
    let g = groups();
    let expand = |names: &[&str]| -> Vec<String> { names.iter().flat_map(|n| g.get(n).map(|v| v.iter().map(|s| s.to_string()).collect()).unwrap_or_else(|| vec![n.to_string()])).collect() };
    Some(match name {
        "minimal" => Some(expand(&["ask_user", "todo", "tool_describe", "tool_call", "session_status"])),
        // Benchmark floor: a persistent shell, image-capable `read`, and the code tool. No
        // write/edit/glob/skills/subagents, so a run measures the model loop, not the toolbox.
        "benchmark" => Some(expand(&["shell", "read", "run"])),
        "coding" => Some(expand(&["group:fs", "group:runtime", "group:web", "group:memory", "group:sessions", "group:agents", "group:plan", "group:media", "group:forge"])),
        "messaging" => Some(expand(&["group:messaging", "group:memory", "group:web", "ask_user", "todo", "tool_describe", "tool_call", "session_status"])),
        // Professional roles (BATCH-next §3). DevOps/SRE: terminal, logs, process control,
        // scheduled checks, monitoring/integration connectors (MCP), sub-agents for parallel triage.
        "devops" => Some(expand(&["group:fs", "group:runtime", "group:web", "group:memory", "group:sessions", "group:agents", "group:plan", "group:automation", "group:forge", "group:observability", "group:deploy", "group:tickets", "osv_query", "scan_report", "mcp__*"])),
        // Security operations: read and analyse; no messaging, no automation, no remote nodes,
        // no delegation to external agents (offensive tooling is refused by the role policy).
        // Monitoring queries and tickets are in: triage reads alerts and logs and opens tickets;
        // `deploy` is not (changing production is the DevOps role's job).
        "secops" => Some(expand(&["group:fs", "group:runtime", "group:web", "group:memory", "group:plan", "group:sessions", "group:secops", "group:observability", "group:tickets", "mcp__*"])),
        // Data analysis: files, a runtime for queries/notebooks, charts (media), DB connectors.
        "data" => Some(expand(&["group:fs", "group:runtime", "group:web", "group:memory", "group:plan", "group:media", "group:sessions", "group:data", "mcp__*"])),
        // IT support: ticket replies (messaging), diagnostics (runtime), knowledge base (web/memory).
        "itsupport" => Some(expand(&["group:fs", "group:runtime", "group:web", "group:memory", "group:plan", "group:messaging", "group:sessions", "group:directory", "group:tickets", "mcp__*"])),
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
            return Err(format!("{at}.profile `{p}`: use minimal, benchmark, coding, messaging, devops, secops, data, itsupport or full"));
        }
    }
    if let Some(e) = &layer.exec {
        if e.mode.is_some() && e.policy().is_none() {
            return Err(format!("{at}.exec.mode: use deny, allowlist, ask, auto or full"));
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
        let benchmark = Layer { profile: Some("benchmark".into()), ..Default::default() };
        assert!(layer_allows(&benchmark, "shell") && layer_allows(&benchmark, "read") && layer_allows(&benchmark, "run"), "benchmark keeps the minimal loop");
        assert!(!layer_allows(&benchmark, "write") && !layer_allows(&benchmark, "edit") && !layer_allows(&benchmark, "spawn") && !layer_allows(&benchmark, "skill"), "benchmark hides the rest");
        assert!(validate(&benchmark, "tools").is_ok());
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
        // DevOps / SecOps tools land in their roles' profiles (not in the coding profile).
        for t in ["prometheus_query", "loki_query", "alertmanager_alerts", "elastic_search", "grafana_query", "deploy", "jira", "servicenow", "pagerduty"] {
            assert!(layer_allows(&l("devops"), t), "devops: {t}");
        }
        for t in ["scan_report", "osv_query", "siem_alerts", "compliance_check", "jira", "elastic_search"] {
            assert!(layer_allows(&l("secops"), t), "secops: {t}");
        }
        assert!(!layer_allows(&l("secops"), "deploy") && !layer_allows(&l("coding"), "deploy") && !layer_allows(&l("coding"), "siem_alerts"));
        assert!(layer_allows(&l("itsupport"), "channel_send"), "IT support answers tickets");
        assert!(layer_allows(&l("data"), "image"), "charts");
    }

    /// The tools of seagent_tools::{data, directory, forge} reach each role through its profile
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
    fn exec_ceilings_restrict_per_provider_and_model() {
        let l = |mode: &str| Layer { exec: Some(ExecCeiling { mode: Some(mode.into()), ..Default::default() }), ..Default::default() };
        let bp = BTreeMap::from([
            ("ollama".to_string(), l("deny")),
            ("openai/gpt-4o".to_string(), l("ask")),
            ("openai/gpt-4o-mini".to_string(), l("allowlist")),
        ]);
        let o = |m: &str| Origin { model: m.into(), ..Default::default() };
        assert_eq!(exec_ceiling(&bp, &o("ollama/llama3")), Some((ExecSecurity::Deny, ExecAsk::Off)));
        assert_eq!(exec_ceiling(&bp, &o("openai/gpt-4o")), Some((ExecSecurity::Allowlist, ExecAsk::OnMiss)));
        assert_eq!(exec_ceiling(&bp, &o("openai/gpt-4o-mini")), Some((ExecSecurity::Allowlist, ExecAsk::Off)));
        assert_eq!(exec_ceiling(&bp, &o("anthropic/claude")), None);
        // Security minimum, ask maximum; a side that denies misses keeps them denied.
        assert_eq!(compose_exec_policy((ExecSecurity::Full, ExecAsk::Off), (ExecSecurity::Allowlist, ExecAsk::OnMiss)), (ExecSecurity::Allowlist, ExecAsk::OnMiss));
        assert_eq!(compose_exec_policy((ExecSecurity::Allowlist, ExecAsk::OnMiss), (ExecSecurity::Allowlist, ExecAsk::Off)), (ExecSecurity::Allowlist, ExecAsk::Off));
        assert_eq!(compose_exec_policy((ExecSecurity::Allowlist, ExecAsk::Always), (ExecSecurity::Allowlist, ExecAsk::Off)), (ExecSecurity::Allowlist, ExecAsk::Always), "a mandatory always is never dropped");
        let parsed: Layer = serde_json::from_value(serde_json::json!({"exec": {"security": "allowlist", "ask": "always"}})).unwrap();
        assert_eq!(parsed.exec.unwrap().policy(), Some((ExecSecurity::Allowlist, ExecAsk::Always)));
        assert!(validate(&Layer { exec: Some(ExecCeiling { mode: Some("bogus".into()), ..Default::default() }), ..Default::default() }, "tools.by_provider.x").is_err());
    }

    #[test]
    fn explain_names_the_blocking_layer_and_its_fix() {
        let g = Layer::default();
        let bp = BTreeMap::from([("ollama".to_string(), Layer { deny: vec!["shell".into()], ..Default::default() })]);
        let bc = BTreeMap::from([("telegram".to_string(), Layer { deny: vec!["group:runtime".into()], ..Default::default() })]);
        let bs = BTreeMap::from([("telegram:7".to_string(), Layer { deny: vec!["write".into()], ..Default::default() })]);
        let o = Origin { model: "ollama/llama3".into(), channel: Some("telegram".into()), sender: Some("7".into()) };
        let b = explain(&g, &bp, &bc, &bs, &o, "shell");
        assert_eq!(b.len(), 2, "{b:?}");
        assert_eq!(b[0].layer, "tools.by_provider.ollama");
        assert!(b[0].config.contains("[tools.by_provider.ollama]") && b[0].fix.contains("also_allow"));
        assert_eq!(b[1].layer, "tools.by_channel.telegram");
        let b = explain(&g, &bp, &bc, &bs, &o, "write");
        assert_eq!(b.len(), 1, "provider does not deny write and channel runtime does not cover it: {b:?}");
        assert_eq!(b[0].layer, "tools.by_sender.telegram:7");
        assert!(explain(&g, &bp, &bc, &bs, &o, "read").is_empty());
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
