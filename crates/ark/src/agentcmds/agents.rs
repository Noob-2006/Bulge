//! `ark agents` — named agents and channel routing bindings (OpenClaw `openclaw agents …`,
//! `src/commands/agents.commands.{add,list,bind,delete,identity}.ts`).
//!
//! `list [--json]`, `add <id> …`, `update <id> …`, `set-identity <id> <text|@file>`,
//! `delete|rm <id>`, `bind <id> <channel[:account]> [--peer KIND:ID]`, `unbind <id> [channel]`,
//! `bindings`, `show <id>`.
//!
//! Everything is stored by `ark_kernel::agents` (`agents.toml` next to `config.toml`, bindings
//! included) so `[agents.<id>]` in `config.toml` keeps working read-only: `ark agents` only ever
//! writes the entries it owns and says so when the target lives in `config.toml` instead.
//! Output is terminal-sanitised (names and identities come from chats).

// `ark agents` is reached through `agentcmds::agent_cli`; until `main.rs` routes to it every item
// below counts as unused. Delete this line once the wiring is in.
#![allow(dead_code)]

use super::sessions::Opts;
use crate::args::Args;
use ark_kernel::agents::{self, AgentDef, Binding};
use ark_kernel::config::{Config, Paths};

pub const USAGE: &str = "\
ark agents <subcommand>
  list [--json]                              every agent (including `main`)
  add <id> [--name N] [--model p/m] [--workspace DIR] [--identity TEXT]
           [--role ROLE] [--allow a,b] [--deny c]
           [--default] [--bind channel[:account] [--peer KIND:ID]]
  update <id> [--name N] [--model p/m] [--workspace DIR] [--identity TEXT]
              [--role ROLE] [--allow a,b] [--deny c] [--default]
  set-identity <id> <text|@file>             replace the persona / standing instructions
  delete|rm <id>                             delete an agent and its bindings (`main` stays)
  bind <id> <channel[:account]> [--peer KIND:ID]
  unbind <id> [channel[:account]]
  bindings [--json]                          every routing binding (user config + agents.toml)
  show <id>                                  the effective settings of one agent

<id>: lowercase letter first, then lowercase letters, digits, `-` or `_` (max 64).
ROLE: a team seed (coordinator, researcher, writer, reviewer: seeds the identity) or an
occupation — ISCO code, 中英文職業名 or preset (devops, swdev, secops, data, itsupport); the
agent then works with that role's rules, tool profile and boundaries (`ark role list`).";

/// Value flags of `ark agents` (OpenClaw's `--identity`, `--peer`, `--allow`, `--deny` are ours:
/// the global parser does not know them, so the dispatcher hands this command its raw arguments).
const VALUE_FLAGS: &[&str] = &["name", "model", "workspace", "identity", "peer", "allow", "deny", "role", "bind", "from"];
const BOOL_FLAGS: &[&str] = &["default", "json", "yes", "quiet", "help", "force"];

/// Drop control characters (OpenClaw `sanitizeTerminalText`).
pub fn safe(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

fn one_line(s: &str) -> String {
    s.split_whitespace().map(|w| w.chars().filter(|c| !c.is_control()).collect::<String>()).collect::<Vec<_>>().join(" ")
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        format!("{}…", s.chars().take(n.saturating_sub(1)).collect::<String>())
    } else {
        s.to_string()
    }
}

/// `ark agents <sub>` (wired from `agentcmds::agent_cli`).
pub fn cli(a: &Args, paths: &Paths) -> Result<String, String> {
    run(&Opts::from_args(a, VALUE_FLAGS, BOOL_FLAGS), paths)
}

/// Same dispatch from raw arguments — `main.rs` routes `ark agents` here before the global
/// `Args` parser, exactly like `ark kanban`, so the OpenClaw flags above are not rejected.
pub fn cli_raw(raw: &[String], paths: &Paths) -> Result<String, String> {
    run(&Opts::parse(raw, VALUE_FLAGS, BOOL_FLAGS)?, paths)
}

/// Effective config: `config.toml` (read-only here) merged under `agents.toml`.
fn config(paths: &Paths) -> Result<Config, String> {
    let user = paths.user_config();
    let user = user.as_path();
    Config::load(Some(user).filter(|p| p.exists()), None, &[])
}

fn csv(v: &str) -> Vec<String> {
    v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

fn bindings_for(cfg: &Config, paths: &Paths, id: &str) -> Vec<Binding> {
    agents::bindings(cfg, paths).into_iter().filter(|b| b.agent == id).collect()
}

fn describe_binding(b: &Binding) -> String {
    let mut s = safe(&b.channel);
    if !b.account.is_empty() {
        s.push_str(&format!(":{}", safe(&b.account)));
    }
    if !b.peer.is_empty() {
        s.push_str(&format!(" → {}{}", if b.peer_kind.is_empty() { String::new() } else { format!("{}:", safe(&b.peer_kind)) }, safe(&b.peer)));
    }
    if !b.user.is_empty() {
        s.push_str(&format!(" user:{}", safe(&b.user)));
    }
    s
}

/// One aligned row of `ark agents list`.
fn line(id: &str, a: &AgentDef, default: &str, bindings: usize) -> String {
    let model = if a.model.trim().is_empty() { "(model.default)".to_string() } else { one_line(&a.model) };
    let ws = if a.workspace.trim().is_empty() { "(session workspace)".to_string() } else { one_line(&a.workspace) };
    let name = if a.name.trim().is_empty() { id.to_string() } else { safe(&a.name) };
    format!(
        "{}{:<12} {:<18} {:<30} {:<26} {:>3} binding{}{}",
        if id == default { "* " } else { "  " },
        clip(&safe(id), 12),
        clip(&name, 18),
        clip(&model, 30),
        clip(&ws, 26),
        bindings,
        if bindings == 1 { "" } else { "s" },
        if id == default { "   (default)" } else { "" }
    )
}

fn summary(cfg: &Config, paths: &Paths, id: &str) -> (AgentDef, Vec<Binding>, bool) {
    let all = agents::all(cfg, paths);
    let def = all.get(id).cloned().unwrap_or_default();
    let default = agents::default_agent(cfg, paths);
    (def, bindings_for(cfg, paths, id), id == default)
}

fn run(o: &Opts, paths: &Paths) -> Result<String, String> {
    std::fs::create_dir_all(&paths.config_dir).map_err(|e| format!("{}: {e}", paths.config_dir.display()))?;
    let sub = o.pos(0).unwrap_or("list");
    match sub {
        "list" | "ls" => {
            let cfg = config(paths)?;
            let all = agents::all(&cfg, paths);
            let binds = agents::bindings(&cfg, paths);
            let default = agents::default_agent(&cfg, paths);
            if o.flag("json") {
                let rows: Vec<serde_json::Value> = all.iter().map(|(id, a)| {
                    serde_json::json!({
                        "id": id,
                        "name": if a.name.trim().is_empty() { id.clone() } else { a.name.clone() },
                        "description": a.description,
                        "model": if a.model.trim().is_empty() { cfg.model.default.clone() } else { a.model.clone() },
                        "workspace": a.workspace,
                        "identity": a.identity,
                        "tools_allow": a.tools_allow,
                        "tools_deny": a.tools_deny,
                        "default": *id == default,
                        "bindings": binds.iter().filter(|b| &b.agent == id).count(),
                        "source": if cfg.agents.contains_key(id) { "config" } else { "agents.toml" },
                    })
                }).collect();
                return serde_json::to_string_pretty(&rows).map_err(|e| e.to_string());
            }
            if all.is_empty() {
                return Ok("no agents — add one with `ark agents add <id> --name … --model …`".into());
            }
            let mut out = vec!["Agents:".to_string()];
            for (id, a) in &all {
                out.push(line(id, a, &default, binds.iter().filter(|b| &b.agent == id).count()));
            }
            out.push(format!("unmatched messages go to `{default}` — bind a channel with `ark agents bind <id> <channel[:account]>`."));
            Ok(out.join("\n"))
        }
        "show" => {
            let id = o.need(1, "id")?;
            let cfg = config(paths)?;
            let all = agents::all(&cfg, paths);
            let Some(def) = all.get(id) else {
                return Err(format!("unknown agent `{}` (try `ark agents list`)", safe(id)));
            };
            let r = agents::resolve(&cfg, paths, id).ok_or_else(|| format!("unknown agent `{}`", safe(id)))?;
            let binds = bindings_for(&cfg, paths, id);
            let mut out = vec![
                format!("agent: {}", r.id),
                format!("name: {}", one_line(&r.name)),
                format!("model: {}", r.model.clone().unwrap_or_else(|| format!("{} (default)", cfg.model.default))),
                format!("workspace: {}", r.workspace.as_ref().map(|w| w.display().to_string()).unwrap_or_else(|| "(the session's workspace)".into())),
                format!("identity: {}", r.identity.clone().map(|i| clip(&one_line(&i), 300)).unwrap_or_else(|| "(none)".into())),
                format!("tools allow: {}", r.tools_allow.as_ref().map(|t| t.join(",")).unwrap_or_else(|| "(all)".into())),
                format!("tools deny: {}", if r.tools_deny.is_empty() { "(none)".to_string() } else { r.tools_deny.join(",") }),
                format!("default: {}", if agents::default_agent(&cfg, paths) == r.id { "yes" } else { "no" }),
            ];
            if !def.role.is_empty() {
                out.push(format!("role: {}", safe(&def.role)));
            }
            out.push(format!("bindings: {}", binds.len()));
            out.extend(binds.iter().map(|b| format!("  {}", describe_binding(b))));
            Ok(out.join("\n"))
        }
        "add" | "create" => cmd_add(o, paths),
        "update" | "set" => cmd_update(o, paths),
        "set-identity" | "identity" => cmd_set_identity(o, paths),
        "delete" | "rm" | "remove" => cmd_delete(o, paths),
        "bind" => cmd_bind(o, paths),
        "unbind" => cmd_unbind(o, paths),
        "bindings" | "routes" => cmd_bindings(o, paths),
        "help" | "--help" => Ok(USAGE.into()),
        other => Err(format!("unknown `agents {other}`\n{USAGE}")),
    }
}

/// `--role`: a team seed as-is, else an occupation resolved to its preset id / pack slug
/// (ISCO code, Chinese or English name); ambiguous or unknown words are an error that lists
/// the choices.
fn occupation(paths: &Paths, raw: &str) -> Result<String, String> {
    let r = raw.trim().to_ascii_lowercase();
    if r.is_empty() || agents::role_identity(&r).is_some() {
        return Ok(r);
    }
    let cfg = config(paths)?;
    crate::role_cli::pick(&cfg, raw).map(|id| id.unwrap_or_default()).map_err(|e| format!("--role: {e}"))
}

fn cmd_add(o: &Opts, paths: &Paths) -> Result<String, String> {
    let id = o.need(1, "id")?;
    if id == "main" {
        return Err("`main` is the built-in default agent (use `ark agents update main …` for its identity)".into());
    }
    let role = occupation(paths, o.val("role").unwrap_or(""))?;
    let identity = match o.val("identity") {
        Some(v) => v.to_string(),
        None => agents::role_identity(&role).unwrap_or_default().to_string(),
    };
    let def = AgentDef {
        name: o.val("name").map(one_line).unwrap_or_else(|| id.to_string()),
        model: o.val("model").unwrap_or("").trim().to_string(),
        workspace: o.val("workspace").unwrap_or("").trim().to_string(),
        identity: identity.trim().to_string(),
        tools_allow: o.val("allow").map(csv).unwrap_or_default(),
        tools_deny: o.val("deny").map(csv).unwrap_or_default(),
        default: o.flag("default"),
        role,
        ..Default::default()
    };
    if !def.model.is_empty() && !def.model.contains('/') {
        return Err(format!("--model `{}`: use provider/model (e.g. anthropic/claude-sonnet-5-5)", def.model));
    }
    agents::add(paths, id, def)?;
    let cfg = config(paths)?;
    let mut added = Vec::new();
    for spec in o.vals("bind") {
        let b = agents::parse_bind(id, &spec, o.val("peer"))?;
        if agents::bind(&cfg, paths, b.clone())? {
            added.push(describe_binding(&b));
        }
    }
    let (a, binds, is_default) = summary(&config(paths)?, paths, id);
    let mut out = vec![format!("created agent `{id}` ({})", one_line(if a.name.is_empty() { id } else { &a.name }))];
    out.push(format!("  model: {}", if a.model.is_empty() { format!("{} (default)", cfg.model.default) } else { a.model.clone() }));
    if !a.workspace.is_empty() {
        out.push(format!("  workspace: {}", one_line(&a.workspace)));
    }
    if !a.identity.is_empty() {
        out.push(format!("  identity: {}", clip(&one_line(&a.identity), 200)));
    }
    out.push(format!("  bindings: {}{}", binds.len(), if added.is_empty() { String::new() } else { format!(" (added {})", added.join(", ")) }));
    if is_default {
        out.push("  this agent is now the default route.".into());
    }
    Ok(out.join("\n"))
}

fn cmd_update(o: &Opts, paths: &Paths) -> Result<String, String> {
    let id = o.need(1, "id")?.to_string();
    let cfg = config(paths)?;
    if cfg.agents.contains_key(&id) {
        return Err(format!("agent `{id}` is declared in config.toml — edit that file (or `ark config set agents.{id}.model …`)"));
    }
    if id == agents::MAIN {
        return Err("`main` is the built-in default agent: its persona and model come from config.toml (`[identity]`, `[agents.main]`)".into());
    }
    if !agents::all(&cfg, paths).contains_key(&id) {
        return Err(format!("unknown agent `{}` (try `ark agents list`)", safe(&id)));
    }
    // Nothing to change?
    let touched = ["name", "model", "workspace", "identity", "allow", "deny", "role"].iter().any(|k| o.val(k).is_some()) || o.flag("default");
    if !touched {
        return Err("nothing to update: pass --name, --model, --workspace, --identity, --role, --allow, --deny or --default".into());
    }
    let mut changes: Vec<String> = Vec::new();
    if let Some(m) = o.val("model").map(str::trim).filter(|m| !m.is_empty()) {
        if !m.contains('/') {
            return Err(format!("--model `{m}`: use provider/model (e.g. anthropic/claude-sonnet-5-5)"));
        }
    }
    let identity = o.val("identity").map(|s| s.trim().to_string());
    let role = o.val("role").map(|r| occupation(paths, r)).transpose()?;
    let name = o.val("name").map(one_line);
    let model = o.val("model").map(|s| s.trim().to_string());
    let workspace = o.val("workspace").map(|s| s.trim().to_string());
    let allow = o.val("allow").map(csv);
    let deny = o.val("deny").map(csv);
    let make_default = o.flag("default");
    if id == "main" && make_default {
        return Err("`main` is already the fallback route; `--default` is for named agents".into());
    }
    agents::update(paths, &id, |a| {
        if let Some(v) = &name {
            a.name = v.clone();
        }
        if let Some(v) = &model {
            a.model = v.clone();
        }
        if let Some(v) = &workspace {
            a.workspace = v.clone();
        }
        if let Some(v) = &identity {
            a.identity = v.trim().to_string();
        }
        if let Some(v) = &allow {
            a.tools_allow = v.clone();
        }
        if let Some(v) = &deny {
            a.tools_deny = v.clone();
        }
        if let Some(v) = &role {
            a.role = v.clone();
        }
        if make_default {
            a.default = true;
        }
    })?;
    for k in ["name", "model", "workspace", "identity", "allow", "deny", "role"] {
        if o.val(k).is_some() {
            changes.push(format!("--{k}"));
        }
    }
    if make_default {
        changes.push("--default".into());
    }
    let (a, binds, is_default) = summary(&config(paths)?, paths, &id);
    let mut out = vec![format!("updated agent `{id}`: {}", changes.join(", "))];
    out.push(format!("  name: {}", one_line(if a.name.is_empty() { &id } else { &a.name })));
    out.push(format!("  model: {}", if a.model.is_empty() { "(model.default)".to_string() } else { one_line(&a.model) }));
    out.push(format!("  workspace: {}", if a.workspace.is_empty() { "(session workspace)".to_string() } else { one_line(&a.workspace) }));
    out.push(format!("  bindings: {}", binds.len()));
    if is_default {
        out.push("  this agent is now the default route.".into());
    }
    Ok(out.join("\n"))
}

fn cmd_set_identity(o: &Opts, paths: &Paths) -> Result<String, String> {
    let id = o.need(1, "id")?;
    if o.pos(2).is_none() {
        return Err("missing <text|@file> (a `@path` reads the identity from that file; an empty string clears it)".into());
    }
    let raw = o.rest(2);
    let text = match raw.trim().strip_prefix('@') {
        Some(path) => {
            let p = ark_core::tool::expand_home(path.trim());
            std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?
        }
        None => raw.clone(),
    };
    let text = text.trim().to_string();
    let cfg = config(paths)?;
    if !agents::all(&cfg, paths).contains_key(id) {
        return Err(format!("unknown agent `{}` (try `ark agents list`)", safe(id)));
    }
    if cfg.agents.contains_key(id) {
        // Declared in config.toml: a persona override in agents.toml would shadow the whole entry,
        // so point at the file the user configured instead of silently rewriting it.
        return Err(format!("agent `{id}` is declared in config.toml — set `agents.{id}.identity` there (or move the agent to `ark agents`)"));
    }
    if id == agents::MAIN {
        return Err("`main` is the built-in default agent: set its persona with `identity` in config.toml".into());
    }
    agents::update(paths, id, |a| {
        a.identity = text.clone();
        if a.name.is_empty() {
            a.name = id.to_string();
        }
    })?;
    Ok(if text.is_empty() {
        format!("cleared the identity of `{id}` (it falls back to the built-in persona)")
    } else {
        format!("identity of `{id}` set ({} characters, {} lines)\n  {}", text.chars().count(), text.lines().count(), clip(&one_line(&text), 200))
    })
}

fn cmd_delete(o: &Opts, paths: &Paths) -> Result<String, String> {
    let id = o.need(1, "id")?;
    if id == "main" {
        return Err("`main` is the built-in default agent and cannot be deleted".into());
    }
    let cfg = config(paths)?;
    if cfg.agents.contains_key(id) {
        return Err(format!("agent `{id}` is declared in config.toml — remove that section to delete it"));
    }
    if !agents::all(&cfg, paths).contains_key(id) {
        return Err(format!("unknown agent `{}` (try `ark agents list`)", safe(id)));
    }
    let n = agents::delete(paths, id)?;
    Ok(if n == 0 {
        format!("deleted agent `{id}` (no bindings)")
    } else {
        format!("deleted agent `{id}` and {n} binding(s)\n  its sessions stay readable under the same agent id")
    })
}

fn cmd_bind(o: &Opts, paths: &Paths) -> Result<String, String> {
    let id = o.need(1, "id")?;
    let spec = o.need(2, "channel[:account]")?;
    let cfg = config(paths)?;
    if !agents::all(&cfg, paths).contains_key(id) {
        return Err(format!("unknown agent `{}` (try `ark agents list`)", safe(id)));
    }
    let b = agents::parse_bind(id, spec, o.val("peer"))?;
    let added = agents::bind(&cfg, paths, b.clone())?;
    Ok(if added {
        format!("bound agent `{id}` → {}\n  messages routed there run as `{id}` (its model, workspace and identity apply).", describe_binding(&b))
    } else {
        format!("agent `{id}` is already bound to {}", describe_binding(&b))
    })
}

fn cmd_unbind(o: &Opts, paths: &Paths) -> Result<String, String> {
    let id = o.need(1, "id")?;
    let cfg = config(paths)?;
    let before = bindings_for(&cfg, paths, id).len();
    if before == 0 {
        return Err(format!("agent `{}` has no bindings (see `ark agents bindings`)", safe(id)));
    }
    let n = agents::unbind(paths, id, o.pos(2))?;
    if n == 0 {
        return Err(format!("agent `{id}` has no binding matching `{}` (see `ark agents bindings`)", safe(o.pos(2).unwrap_or(""))));
    }
    Ok(format!("removed {n} binding(s) from agent `{id}` ({} left)", before - n))
}

fn cmd_bindings(o: &Opts, paths: &Paths) -> Result<String, String> {
    let cfg = config(paths)?;
    let all = agents::bindings(&cfg, paths);
    if o.flag("json") {
        let rows: Vec<serde_json::Value> = all.iter().map(|b| serde_json::json!({"agent": b.agent, "channel": b.channel, "account": b.account, "peer": b.peer, "peer_kind": b.peer_kind, "user": b.user})).collect();
        return serde_json::to_string_pretty(&rows).map_err(|e| e.to_string());
    }
    if all.is_empty() {
        return Ok(format!("no bindings — every channel message goes to `{}`", agents::default_agent(&cfg, paths)));
    }
    let mut out = vec![format!("Bindings ({}):", all.len())];
    for b in &all {
        out.push(format!("  {:<14} {}", clip(&safe(&b.agent), 14), describe_binding(b)));
    }
    out.push(format!("unmatched messages go to `{}`", agents::default_agent(&cfg, paths)));
    Ok(out.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_paths() -> Paths {
        let root = ark_core::tmp::scratch_path(format!("ark-agents-{}", ark_kernel::util::random_hex(8)));
        std::fs::create_dir_all(root.join("config")).unwrap();
        Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run"), ..Default::default() }
    }

    fn r(p: &Paths, v: &[&str]) -> Result<String, String> {
        run(&Opts::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>(), VALUE_FLAGS, BOOL_FLAGS).unwrap(), p)
    }

    #[test]
    fn agents_cli_add_list_bind_unbind_delete() {
        let p = tmp_paths();

        // list always has `main`, marked as the default
        let l = r(&p, &["list"]).unwrap();
        assert!(l.starts_with("Agents:\n* "), "{l}");
        assert!(l.contains("main"), "{l}");
        let j: serde_json::Value = serde_json::from_str(&r(&p, &["list", "--json"]).unwrap()).unwrap();
        assert_eq!(j[0]["id"], "main");
        assert_eq!(j[0]["default"], true);

        // add with every field, plus a channel binding
        let out = r(&p, &["add", "writer", "--name", "Wri\u{1b}ter", "--model", "anthropic/claude-sonnet-5-5", "--workspace", "~/w", "--identity", "You write docs.", "--bind", "telegram"]).unwrap();
        assert!(out.starts_with("created agent `writer` (Writer)"), "{out}");
        assert!(out.contains("bindings: 1"), "{out}");
        let l = r(&p, &["list"]).unwrap();
        assert!(l.contains("writer") && l.contains("anthropic/claude-sonnet-5-5") && l.contains("~/w"), "{l}");
        assert!(l.contains("2 binding") || l.contains("1 binding"), "{l}");

        // duplicate, bad id, reserved id, bad model
        assert!(r(&p, &["add", "writer"]).unwrap_err().contains("already exists"));
        assert!(r(&p, &["add", "Bad-Id"]).unwrap_err().contains("lowercase letter"));
        assert!(r(&p, &["add", "main"]).unwrap_err().contains("built-in default agent"));
        assert!(r(&p, &["add", "m2", "--model", "sonnet"]).unwrap_err().contains("provider/model"));

        // role seeds (OpenClaw `--role`)
        r(&p, &["add", "rev", "--role", "reviewer"]).unwrap();
        let show = r(&p, &["show", "rev"]).unwrap();
        assert!(show.contains("identity: You are a reviewer") && show.contains("role: reviewer"), "{show}");
        assert!(r(&p, &["add", "rev2", "--role", "bogus"]).unwrap_err().contains("--role: no role matches `bogus`"));

        // bind / bindings / unbind
        let b = r(&p, &["bind", "writer", "slack:work", "--peer", "group:C123"]).unwrap();
        assert!(b.contains("bound agent `writer` → slack:work → group:C123"), "{b}");
        assert!(r(&p, &["bind", "writer", "slack:work", "--peer", "group:C123"]).unwrap().contains("already bound"));
        assert!(r(&p, &["bind", "nobody", "slack"]).unwrap_err().contains("unknown agent"));
        let binds = r(&p, &["bindings"]).unwrap();
        assert!(binds.contains("telegram") && binds.contains("slack:work"), "{binds}");
        assert!(r(&p, &["bindings", "--json"]).unwrap().contains("\"agent\": \"writer\""));
        assert!(r(&p, &["unbind", "writer", "telegram"]).unwrap().contains("removed 1 binding(s)"));
        assert!(r(&p, &["unbind", "writer", "telegram"]).unwrap_err().contains("no binding matching"));
        assert!(r(&p, &["unbind", "main"]).unwrap_err().contains("no bindings"));

        // update: model, default, allow/deny, and the "nothing to update" guard
        assert!(r(&p, &["update", "writer"]).unwrap_err().contains("nothing to update"));
        let u = r(&p, &["update", "writer", "--model", "openai/gpt-5", "--default", "--allow", "read,grep", "--deny", "shell"]).unwrap();
        assert!(u.contains("updated agent `writer`: --model, --allow, --deny, --default"), "{u}");
        assert!(u.contains("this agent is now the default route."), "{u}");
        let l = r(&p, &["list"]).unwrap();
        assert!(l.contains("(default)" ) && l.contains("openai/gpt-5"), "{l}");
        let j: serde_json::Value = serde_json::from_str(&r(&p, &["list", "--json"]).unwrap()).unwrap();
        let w = j.as_array().unwrap().iter().find(|a| a["id"] == "writer").unwrap();
        assert_eq!(w["default"], true);
        assert_eq!(w["tools_allow"], serde_json::json!(["read", "grep"]));
        assert_eq!(w["tools_deny"], serde_json::json!(["shell"]));
        let show = r(&p, &["show", "writer"]).unwrap();
        assert!(show.contains("tools allow: read,grep") && show.contains("tools deny: shell") && show.contains("default: yes"), "{show}");

        // set-identity: inline text, then a file, then clearing
        let s = r(&p, &["set-identity", "writer", "Be", "brief."]).unwrap();
        assert!(s.starts_with("identity of `writer` set (9 characters"), "{s}");
        let f = p.data.join("id.txt");
        std::fs::create_dir_all(&p.data).unwrap();
        std::fs::write(&f, "From a file.\nSecond line.").unwrap();
        assert!(r(&p, &["set-identity", "writer", &format!("@{}", f.display())]).unwrap().contains("2 lines"));
        let show = r(&p, &["show", "writer"]).unwrap();
        assert!(show.contains("From a file. Second line."), "{show}");
        assert!(r(&p, &["set-identity", "writer", ""]).unwrap().contains("cleared the identity"));
        assert!(r(&p, &["set-identity", "writer"]).unwrap_err().contains("missing <text|@file>"));
        assert!(r(&p, &["set-identity", "nobody", "x"]).unwrap_err().contains("unknown agent"));

        // errors point at the right surface
        assert!(r(&p, &["delete", "main"]).unwrap_err().contains("cannot be deleted"));
        assert!(r(&p, &["delete", "nobody"]).unwrap_err().contains("unknown agent"));
        assert!(r(&p, &["bogus"]).unwrap_err().contains("unknown `agents bogus`"));
        assert!(r(&p, &["show", "nobody"]).unwrap_err().contains("unknown agent"));

        // delete removes the agent and its bindings, and the sessions stay
        let d = r(&p, &["delete", "writer"]).unwrap();
        assert!(d.starts_with("deleted agent `writer` and 1 binding(s)"), "{d}");
        assert!(!r(&p, &["list"]).unwrap().contains("writer"));
        assert!(!r(&p, &["bindings"]).unwrap().contains("slack"), "its bindings are gone");
        assert!(r(&p, &["delete", "writer"]).unwrap_err().contains("unknown agent"));

        // an agent declared in config.toml is read-only here, and says where to edit it
        std::fs::write(p.user_config(), "[agents.docs]\nname = \"Docs\"\nidentity = \"from config\"\n").unwrap();
        assert!(r(&p, &["list"]).unwrap().contains("Docs"));
        assert!(r(&p, &["update", "docs", "--name", "x"]).unwrap_err().contains("declared in config.toml"));
        assert!(r(&p, &["delete", "docs"]).unwrap_err().contains("declared in config.toml"));
    }

    /// `Args`-based entry point: the flags the global parser knows reach the same place.
    #[test]
    fn args_entry_point_maps_flags() {
        let p = tmp_paths();
        let a = Args::parse(&["add", "helper", "--name", "Helper", "--model", "echo/m", "--json"].iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        let o = Opts::from_args(&a, VALUE_FLAGS, BOOL_FLAGS);
        run(&o, &p).unwrap();
        let all = agents::all(&Config::default(), &p);
        assert!(all.contains_key("helper"));
        assert!(all["helper"].name == "Helper" && all["helper"].model == "echo/m");
        // own flags parse from raw arguments (the dispatcher hands these over unparsed)
        assert!(Opts::parse(&["add".into(), "x".into(), "--identity".into(), "hi".into()], VALUE_FLAGS, BOOL_FLAGS).is_ok());
        assert!(Opts::parse(&["add".into(), "x".into(), "--nope".into()], VALUE_FLAGS, BOOL_FLAGS).is_err());
    }

    /// `--role` takes an occupation (ISCO code / name / preset) as well as the four team seeds,
    /// so a channel binding gives that chat a professional agent.
    #[test]
    fn add_with_an_occupation_role_and_bind_it() {
        let p = tmp_paths();
        let out = r(&p, &["add", "ops", "--role", "2522", "--bind", "telegram"]).unwrap();
        assert!(out.contains("created agent `ops`"), "{out}");
        let a = agents::all(&Config::default(), &p).remove("ops").unwrap();
        assert_eq!((a.role.as_str(), a.identity.as_str()), ("systems-administration", ""));
        assert_eq!(agents::resolve(&Config::default(), &p, "ops").unwrap().role.as_deref(), Some("systems-administration"));
        r(&p, &["add", "sec", "--role", "資安維運"]).unwrap();
        assert_eq!(agents::all(&Config::default(), &p)["sec"].role, "secops");
        r(&p, &["add", "lead", "--role", "coordinator"]).unwrap();
        let lead = agents::all(&Config::default(), &p).remove("lead").unwrap();
        assert!(lead.identity.contains("coordinate") && agents::resolve(&Config::default(), &p, "lead").unwrap().role.is_none());
        let e = r(&p, &["add", "x", "--role", "2149"]).unwrap_err();
        assert!(e.contains("several roles"), "{e}");
        r(&p, &["update", "ops", "--role", "devops"]).unwrap();
        assert_eq!(agents::all(&Config::default(), &p)["ops"].role, "devops");
        let _ = std::fs::remove_dir_all(p.data.parent().unwrap());
    }
}
