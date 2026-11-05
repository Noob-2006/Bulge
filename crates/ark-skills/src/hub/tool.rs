//! The `plugins` tool (OpenClaw `src/agents/tools/plugins-tool.ts`, MIT): the model can list,
//! inspect and search plugins, and — through the approval gates — install from the catalog,
//! a marketplace or ClawHub, enable, disable or uninstall them. Mutations are `Remote`
//! effects (always confirmed by the person) and report that a restart / new session loads the
//! change; results are capped so a large inventory cannot flood the context.

use super::plugins::Plugins;
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use ark_kernel::config::{Config, Paths};
use serde_json::{json, Value};

const MAX_RESULT: usize = 3840;

pub struct PluginsTool {
    pub cfg: Config,
    pub paths: Paths,
}

fn cap(v: Value) -> ToolOutput {
    let s = serde_json::to_string_pretty(&v).unwrap_or_default();
    if s.len() <= MAX_RESULT {
        return ToolOutput::ok(s);
    }
    let mut cut = MAX_RESULT;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    ToolOutput::ok(format!("{}\n… (truncated; narrow the query)", &s[..cut]))
}

impl Tool for PluginsTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "plugins".into(),
            description: "Inspect, search, install (official catalog, a marketplace `plugin@source`, or `clawhub:<package>`), enable, disable or uninstall plugins. Changes apply to new sessions (or after a daemon restart); do not repeat a completed mutation.".into(),
            input_schema: json!({"type": "object", "properties": {
                "action": {"type": "string", "enum": ["list", "inspect", "search", "install", "enable", "disable", "uninstall"]},
                "pluginId": {"type": "string", "description": "Plugin name / install spec"},
                "query": {"type": "string", "description": "Filter for list/search"},
                "force": {"type": "boolean", "description": "install: accept a caution verdict or replace an installed copy"}
            }, "required": ["action"], "additionalProperties": false}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        match input["action"].as_str().unwrap_or("") {
            "install" => vec![Effect::Remote { dest: input["pluginId"].as_str().unwrap_or("").into(), reason: "installs third-party plugin code and edits config.toml".into() }],
            "enable" | "disable" | "uninstall" => vec![Effect::Write { path: self.paths.user_config() }, Effect::Remote { dest: input["pluginId"].as_str().unwrap_or("").into(), reason: "changes which plugins load".into() }],
            "search" => vec![Effect::Net { dest: "clawhub".into(), payload: input["query"].as_str().unwrap_or("").into() }],
            _ => vec![],
        }
    }

    fn call(&self, _ctx: &ToolCtx, input: Value) -> ToolOutput {
        let pm = Plugins::new(&self.cfg, &self.paths);
        let id = input["pluginId"].as_str().unwrap_or("").trim();
        let need = || if id.is_empty() { Err(ToolOutput::err("pluginId is required for this action")) } else { Ok(id) };
        let q = input["query"].as_str().unwrap_or("");
        let r = match input["action"].as_str().unwrap_or("") {
            "list" => return cap(json!({"plugins": pm.list().into_iter().filter(|p| q.is_empty() || p["name"].as_str().unwrap_or("").contains(q)).collect::<Vec<_>>()})),
            "search" => return cap(json!({"results": pm.search(q, 15)})),
            "inspect" => match need() {
                Ok(i) => return pm.inspect(i).map(cap).unwrap_or_else(|| ToolOutput::err(format!("no plugin `{i}`"))),
                Err(e) => return e,
            },
            "install" => need().map(|i| pm.install(i, input["force"].as_bool().unwrap_or(false))),
            "enable" => need().map(|i| pm.set_enabled(i, true)),
            "disable" => need().map(|i| pm.set_enabled(i, false)),
            "uninstall" => need().map(|i| pm.uninstall(i)),
            other => return ToolOutput::err(format!("unknown action `{other}`")),
        };
        match r {
            Err(e) => e,
            Ok(Ok(t)) => cap(json!({"ok": true, "result": t, "next": "Start a new session (or restart the daemon) to load the change; do not repeat this mutation."})),
            Ok(Err(e)) => ToolOutput::err(e),
        }
    }
}
