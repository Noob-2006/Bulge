//! `session_status` (OpenClaw `src/agents/tools/session-status-tool.ts` + schema): the model asks
//! about a visible session — model, usage, time, state — and may switch its model.
//!
//! Input: `sessionKey` (`"current"`/omitted = the calling session; else a visible session id
//! or unique prefix: the caller, its parent, or its sub-agents), `model` (override;
//! `"default"` resets to the configured default), `changesSince` (state-event sequence),
//! `capabilities` (list the session's available tools and why others are missing).
//! Output follows upstream's `SessionStatusOutputSchema`: `ok`, `sessionKey`, `agentId`,
//! `changedModel`, `stateVersion`, `statusText`, optional `capabilities`, `stateChanges`,
//! `model`, `modelProvider`, `modelOverride`, `origin`/`deliveryContext`.

use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use seagent_kernel::event::EventKind;
use seagent_kernel::kernel::Kernel;
use seagent_kernel::projection::project;
use serde_json::{json, Value};
use std::sync::{Arc, OnceLock};

pub const DESCRIPTION: &str = "Show visible-session model/usage/time/cost/tasks. `sessionKey=\"current\"` for current; UI labels are not keys. `model` overrides; `model=default` resets. Use for active model/session questions. `capabilities=true` lists this session's available tools and why others are missing.";
const MAX_CHANGES: usize = 50;

pub struct SessionStatus {
    pub k: Arc<OnceLock<Kernel>>,
}

fn schema() -> Value {
    json!({"type": "object", "additionalProperties": false, "properties": {
        "sessionKey": {"type": "string", "description": "\"current\" (default) or a visible session id."},
        "model": {"type": "string", "description": "provider/model to use for this session from now on; \"default\" resets."},
        "changesSince": {"type": "integer", "minimum": 0, "description": "Return state changes after this stateVersion."},
        "capabilities": {"type": "boolean", "description": "List available tools and why others are missing."}
    }})
}

/// Resolve `key` from `caller`'s point of view.
pub fn resolve(k: &Kernel, caller: &str, key: Option<&str>) -> Result<String, String> {
    let key = key.map(str::trim).filter(|s| !s.is_empty() && *s != "current").unwrap_or(caller);
    let all = k.store.list();
    let hit: Vec<_> = all.iter().filter(|s| s.id == key).chain(all.iter().filter(|s| s.id != key && s.id.starts_with(key))).collect();
    let s = match hit.as_slice() {
        [] => return Err(format!("Unknown session: {key}")),
        [one, ..] if one.id == key || hit.len() == 1 => *one,
        _ => return Err(format!("Ambiguous session: {key}")),
    };
    let me = all.iter().find(|x| x.id == caller);
    let visible = s.id == caller || s.parent.as_deref() == Some(caller) || me.and_then(|m| m.parent.as_deref()) == Some(s.id.as_str());
    if !visible {
        return Err(format!("Session not visible from session tools: {key}"));
    }
    Ok(s.id.clone())
}

fn summary(kind: &EventKind) -> Option<(&'static str, &'static str, String)> {
    Some(match kind {
        EventKind::Model { model } => ("model_changed", "human", format!("model set to {model}")),
        EventKind::Title { title } => ("title_changed", "human", format!("title set to {title}")),
        EventKind::Thinking { level } => ("thinking_changed", "human", format!("thinking set to {level}")),
        EventKind::Rewind { turns, .. } => ("rewound", "human", format!("rewound {turns} turn(s)")),
        EventKind::Compaction { .. } => ("compacted", "system", "conversation compacted".into()),
        EventKind::TurnEnd { turn, reason, .. } => ("turn_ended", "agent", format!("turn {turn} ended: {reason}")),
        EventKind::Error { message } => ("error", "system", message.chars().take(200).collect()),
        EventKind::Agent { .. } => ("agent_changed", "system", "agent changed".into()),
        EventKind::Tools { .. } => ("tools_changed", "human", "tool policy changed".into()),
        _ => return None,
    })
}

pub fn status(k: &Kernel, caller: &str, input: &Value) -> Result<Value, String> {
    let id = resolve(k, caller, input["sessionKey"].as_str())?;
    let mut changed = false;
    if let Some(m) = input["model"].as_str().map(str::trim).filter(|m| !m.is_empty()) {
        let target = if m == "default" { k.cfg.model.default.clone() } else { m.to_string() };
        let (pid, _) = seagent_kernel::context::split_model(&target);
        k.resolver.provider(pid).map_err(|e| format!("Unknown model {target}: {e}"))?;
        k.set_model(&id, &target).map_err(|e| e.to_string())?;
        changed = true;
    }
    let events = k.store.read(&id).map_err(|e| e.to_string())?;
    let v = project(&events);
    let version = events.last().map(|e| e.seq).unwrap_or(0);
    let running = k.is_running(&id);
    let created = events.first().map(|e| e.ts).unwrap_or(0);
    let updated = events.last().map(|e| e.ts).unwrap_or(0);
    let (pid, mname) = seagent_kernel::context::split_model(&v.model);
    let window = k.resolver.provider(pid).map(|p| p.caps(mname).context_window).unwrap_or(0);
    let ctx = if window > 0 { format!("{} / {window} ({:.0}%)", v.last_input_tokens, v.last_input_tokens as f64 * 100.0 / window as f64) } else { v.last_input_tokens.to_string() };
    let mut st = vec![
        format!("🧭 Session {id}{}", v.title.as_deref().map(|t| format!(" — {t}")).unwrap_or_default()),
        format!("🧠 Model: {}{}", v.model, v.thinking.as_deref().map(|t| format!(" · thinking {t}")).unwrap_or_default()),
        format!("🧮 Tokens: {} in / {} out · context {ctx}", v.usage.input_tokens, v.usage.output_tokens),
        format!("💬 {} messages · {} turns · {} compactions", v.messages.len(), v.turns, v.compactions),
        format!("⏱ {} · created {} · updated {}", if running { "running" } else { "idle" }, super::iso(created), super::iso(updated)),
        format!("📥 Queue: {} · {} waiting", k.queue_for(&id).describe(), k.queued(&id).len()),
    ];
    let kids = k.store.list().into_iter().filter(|s| s.parent.as_deref() == Some(id.as_str())).count();
    if kids > 0 {
        st.push(format!("🤖 Sub-agents: {kids} ({} running)", k.store.list().iter().filter(|s| s.parent.as_deref() == Some(id.as_str()) && k.is_running(&s.id)).count()));
    }
    let mut out = json!({
        "ok": true, "sessionKey": id, "agentId": v.agent.clone().unwrap_or_else(|| "main".into()), "changedModel": changed, "stateVersion": version,
        "statusText": st.join("\n"), "model": mname, "modelProvider": pid, "modelOverride": if v.model != k.cfg.model.default { json!(v.model) } else { Value::Null },
    });
    if let Some(since) = input["changesSince"].as_u64() {
        let all: Vec<Value> = events.iter().filter(|e| e.seq > since).filter_map(|e| summary(&e.kind).map(|(kind, actor, s)| json!({"sequence": e.seq, "kind": kind, "actorType": actor, "occurredAt": e.ts, "summary": s}))).collect();
        let truncated = all.len() > MAX_CHANGES;
        let tail = all[all.len().saturating_sub(MAX_CHANGES)..].to_vec();
        let earliest = events.first().map(|e| e.seq).unwrap_or(0);
        out["stateChanges"] = json!({"events": tail, "truncated": truncated, "earliestAvailableSequence": earliest, "historyGap": since + 1 < earliest});
    }
    if input["capabilities"] == true {
        let mut available = vec![];
        let (mut disabled, mut denied, mut not_allowed) = (vec![], vec![], vec![]);
        let names: Vec<String> = k.tools.iter().map(|t| t.spec().name).collect();
        for n in names {
            if k.cfg.tools.disabled.contains(&n) {
                disabled.push(n);
            } else if v.tool_deny.contains(&n) {
                denied.push(n);
            } else if v.tool_allow.as_ref().is_some_and(|a| !a.contains(&n)) {
                not_allowed.push(n);
            } else {
                available.push(n);
            }
        }
        let mut unavailable = vec![];
        for (reason, tools) in [("disabled in config (tools.disabled)", disabled), ("denied for this session", denied), ("not in this session's tool allowlist", not_allowed)] {
            if !tools.is_empty() {
                unavailable.push(json!({"reason": reason, "tools": tools}));
            }
        }
        out["capabilities"] = json!({"checked": if running || id == caller { "live-session" } else { "local-config" }, "available": available, "unavailable": unavailable});
    }
    if let Some(o) = seagent_kernel::kernel::host_routes().and_then(|h| h.origin(&id)) {
        let ch = o["channel"].as_str().unwrap_or("");
        out["origin"] = json!({"provider": ch});
        let mut d = json!({"channel": ch, "to": o["to"]});
        if !o["thread_id"].is_null() {
            d["threadId"] = o["thread_id"].clone();
        }
        out["deliveryContext"] = d;
    }
    Ok(out)
}

impl Tool for SessionStatus {
    fn spec(&self) -> ToolSpec {
        ToolSpec { name: "session_status".into(), description: DESCRIPTION.into(), input_schema: schema(), parallel_safe: true, idempotent: false, pinned: false }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let Some(k) = self.k.get() else { return ToolOutput::err("session_status is not available in this host") };
        match status(k, &ctx.session_id, &input) {
            Ok(v) => ToolOutput::ok(serde_json::to_string_pretty(&v).unwrap_or_default()),
            Err(e) => ToolOutput::err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::kit;
    use seagent_kernel::kernel::RunOpts;

    #[test]
    fn status_visibility_model_override_changes_and_capabilities() {
        let t = kit();
        let id = t.k.create_session(&t.ws, None, None, Some("main work")).unwrap();
        t.k.submit(&id, "hello", "cli").unwrap();
        t.k.run(&id, RunOpts::default()).unwrap();
        let other = t.k.create_session(&t.ws, None, None, None).unwrap();
        let child = t.k.create_session(&t.ws, None, Some(&id), Some("kid")).unwrap();
        let slot: Arc<OnceLock<Kernel>> = Arc::default();
        let _ = slot.set(t.k.clone());
        let tool = SessionStatus { k: slot };
        let ctx = ToolCtx { workspace: t.ws.clone(), session_id: id.clone(), artifacts: t.ws.clone(), home: t.paths.data.clone(), cancel: seagent_core::Cancel::new(), host: Arc::new(super::super::tests::NoHost), secrets: Arc::new(|s: &str| s.to_string()) };
        let o = tool.call(&ctx, json!({"sessionKey": "current", "changesSince": 0, "capabilities": true}));
        assert!(!o.is_error, "{}", o.content);
        let v: Value = serde_json::from_str(&o.content).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["sessionKey"], id.as_str());
        assert!(v["statusText"].as_str().unwrap().contains("main work") && v["statusText"].as_str().unwrap().contains("Sub-agents: 1"));
        assert_eq!(v["changedModel"], false);
        assert!(v["stateChanges"]["events"].as_array().unwrap().iter().any(|e| e["kind"] == "turn_ended"));
        assert!(v["capabilities"]["available"].as_array().unwrap().iter().any(|n| n == "read"));
        let o = tool.call(&ctx, json!({"sessionKey": child, "model": "echo/other"}));
        let v: Value = serde_json::from_str(&o.content).unwrap();
        assert_eq!(v["changedModel"], true);
        assert_eq!(v["model"], "other");
        assert_eq!(v["modelOverride"], "echo/other");
        let o = tool.call(&ctx, json!({"sessionKey": child, "model": "default"}));
        assert_eq!(serde_json::from_str::<Value>(&o.content).unwrap()["modelOverride"], Value::Null);
        let o = tool.call(&ctx, json!({"sessionKey": other}));
        assert!(o.is_error && o.content.contains("not visible"), "{}", o.content);
        assert!(tool.call(&ctx, json!({"sessionKey": "zzzz"})).content.contains("Unknown session"));
        let o = tool.call(&ctx, json!({"changesSince": 10_000}));
        assert_eq!(serde_json::from_str::<Value>(&o.content).unwrap()["stateChanges"]["events"], json!([]));
    }
}
