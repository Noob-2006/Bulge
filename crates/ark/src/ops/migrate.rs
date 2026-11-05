//! Import another agent's setup into ark (Hermes `claw migrate` / `import-agent`,
//! OpenClaw `migrate` and the setup wizard's migration step):
//!
//! - OpenClaw (`~/.openclaw`, legacy `~/.clawdbot` `~/.moltbot`): `openclaw.json` (JSON5) —
//!   default model, provider keys, MCP servers, Telegram/Discord/Slack channels,
//!   workspace `SOUL.md`/`MEMORY.md`/`USER.md`/daily `memory/*.md`, skills.
//! - Hermes (`~/.hermes`): `config.yaml` (model, mcp_servers), `.env` credentials,
//!   `memories/MEMORY.md` + `USER.md`, `SOUL.md`, `skills/`.
//! - Claude Code: `~/.claude.json` / `~/.claude/settings.json` (mcpServers, model, env).
//! - Codex CLI: `~/.codex/config.toml` (model, model_providers, mcp_servers), `AGENTS.md`.
//!
//! Credentials go to the vault (never the config file). `--dry-run` shows the plan.
//! `ark migrate retired-models` rewrites retired model ids (Hermes `migrate xai`).

use crate::args::Args;
use crate::{usage, R};
use ark_kernel::config::Paths;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

pub const COMMANDS: &[&str] = &["migrate", "import-agent", "claw"];
pub const VALUE_FLAGS: &[&str] = &["path"];
pub const BOOL_FLAGS: &[&str] = &["overwrite"];

#[derive(Debug, Clone, PartialEq)]
pub enum Act {
    Config(String, toml::Value),
    Secret(String, String),
    Memory(&'static str, String),
    Copy(PathBuf, PathBuf),
    Note(String),
}

// ───────────── tolerant parsers ─────────────

/// JSON5 → JSON: comments, trailing commas, single quotes, unquoted keys.
pub fn json5(s: &str) -> Result<Value, String> {
    let c: Vec<char> = s.chars().collect();
    let mut o = String::with_capacity(s.len());
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '/' if c.get(i + 1) == Some(&'/') => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
            }
            '/' if c.get(i + 1) == Some(&'*') => {
                i += 2;
                while i + 1 < c.len() && !(c[i] == '*' && c[i + 1] == '/') {
                    i += 1;
                }
                i += 2;
            }
            q @ ('"' | '\'') => {
                o.push('"');
                i += 1;
                while i < c.len() && c[i] != q {
                    if c[i] == '\\' && i + 1 < c.len() {
                        if c[i + 1] == '\'' {
                            o.push('\'');
                        } else {
                            o.push('\\');
                            o.push(c[i + 1]);
                        }
                        i += 2;
                        continue;
                    }
                    if c[i] == '"' {
                        o.push('\\');
                    }
                    o.push(c[i]);
                    i += 1;
                }
                o.push('"');
                i += 1;
            }
            ',' => {
                let mut j = i + 1;
                while j < c.len() && c[j].is_whitespace() {
                    j += 1;
                }
                if !matches!(c.get(j), Some('}') | Some(']')) {
                    o.push(',');
                }
                i += 1;
            }
            ch if ch.is_alphabetic() || ch == '_' || ch == '$' => {
                let start = i;
                while i < c.len() && (c[i].is_alphanumeric() || c[i] == '_' || c[i] == '$') {
                    i += 1;
                }
                let w: String = c[start..i].iter().collect();
                let mut j = i;
                while j < c.len() && c[j].is_whitespace() {
                    j += 1;
                }
                if c.get(j) == Some(&':') && !matches!(w.as_str(), "true" | "false" | "null") {
                    o.push_str(&format!("\"{w}\""));
                } else {
                    o.push_str(&w);
                }
            }
            ch => {
                o.push(ch);
                i += 1;
            }
        }
    }
    serde_json::from_str(&o).map_err(|e| format!("JSON5: {e}"))
}

fn yaml_scalar(s: &str) -> Value {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2) || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2) {
        let inner = &s[1..s.len() - 1];
        return Value::String(if s.starts_with('"') { serde_json::from_str::<String>(s).unwrap_or_else(|_| inner.to_string()) } else { inner.replace("''", "'") });
    }
    if s.starts_with('[') || s.starts_with('{') {
        if let Ok(v) = json5(s) {
            return v;
        }
    }
    match s {
        "" | "~" | "null" => Value::Null,
        "true" | "yes" | "on" => Value::Bool(true),
        "false" | "no" | "off" => Value::Bool(false),
        _ => s.parse::<i64>().map(Value::from).or_else(|_| s.parse::<f64>().map(Value::from)).unwrap_or_else(|_| Value::String(s.to_string())),
    }
}

fn strip_comment(l: &str) -> &str {
    let mut q: Option<char> = None;
    for (i, ch) in l.char_indices() {
        match (q, ch) {
            (None, '"' | '\'') => q = Some(ch),
            (Some(x), c) if c == x => q = None,
            (None, '#') if i == 0 || l[..i].ends_with(' ') => return &l[..i],
            _ => {}
        }
    }
    l
}

/// Block YAML subset (mappings, sequences, scalars, flow collections, `|`/`>` blocks).
pub fn yaml(s: &str) -> Value {
    let lines: Vec<(usize, String)> = s.lines().filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty() && l.trim() != "---").map(|l| (l.len() - l.trim_start().len(), strip_comment(l).trim_end().to_string())).collect();
    let mut i = 0;
    ynode(&lines, &mut i, 0)
}

fn ynode(l: &[(usize, String)], i: &mut usize, ind: usize) -> Value {
    if *i >= l.len() {
        return Value::Null;
    }
    let base = l[*i].0;
    if base < ind {
        return Value::Null;
    }
    if l[*i].1.trim_start().starts_with("- ") || l[*i].1.trim() == "-" {
        let mut arr = vec![];
        while *i < l.len() && l[*i].0 == base && (l[*i].1.trim_start().starts_with("- ") || l[*i].1.trim() == "-") {
            let rest = l[*i].1.trim_start()[1..].trim_start().to_string();
            if rest.is_empty() {
                *i += 1;
                arr.push(ynode(l, i, base + 1));
            } else if rest.contains(": ") || rest.ends_with(':') {
                // "- key: v" starts an inline mapping at base+2.
                let mut sub: Vec<(usize, String)> = vec![(base + 2, rest)];
                *i += 1;
                while *i < l.len() && l[*i].0 > base {
                    sub.push(l[*i].clone());
                    *i += 1;
                }
                let mut j = 0;
                arr.push(ynode(&sub, &mut j, base + 2));
            } else {
                arr.push(yaml_scalar(&rest));
                *i += 1;
            }
        }
        return Value::Array(arr);
    }
    let mut m = Map::new();
    while *i < l.len() && l[*i].0 == base {
        let line = l[*i].1.trim_start().to_string();
        let Some((k, v)) = line.split_once(':').filter(|(k, _)| !k.contains(' ') || k.starts_with('"')) else {
            *i += 1;
            continue;
        };
        let k = k.trim().trim_matches(['"', '\'']).to_string();
        let v = v.trim();
        *i += 1;
        let val = if v == "|" || v == ">" || v == "|-" || v == ">-" {
            let mut parts = vec![];
            while *i < l.len() && l[*i].0 > base {
                parts.push(l[*i].1.trim().to_string());
                *i += 1;
            }
            Value::String(parts.join(if v.starts_with('|') { "\n" } else { " " }))
        } else if v.is_empty() {
            if *i < l.len() && (l[*i].0 > base || (l[*i].0 == base && l[*i].1.trim_start().starts_with("- "))) {
                let ni = l[*i].0;
                ynode(l, i, ni)
            } else {
                Value::Null
            }
        } else {
            yaml_scalar(v)
        };
        m.insert(k, val);
    }
    Value::Object(m)
}

fn dotenv(p: &Path) -> Vec<(String, String)> {
    std::fs::read_to_string(p).map(|t| crate::ops::envfile::parse(&t)).unwrap_or_default()
}

// ───────────── mapping helpers ─────────────

fn tv(v: &Value) -> Option<toml::Value> {
    Some(match v {
        Value::String(s) => toml::Value::String(s.clone()),
        Value::Bool(b) => toml::Value::Boolean(*b),
        Value::Number(n) => n.as_i64().map(toml::Value::Integer).or_else(|| n.as_f64().map(toml::Value::Float))?,
        Value::Array(a) => toml::Value::Array(a.iter().filter_map(tv).collect()),
        Value::Object(o) => toml::Value::Table(o.iter().filter_map(|(k, v)| tv(v).map(|v| (k.clone(), v))).collect()),
        Value::Null => return None,
    })
}

fn valid_name(n: &str) -> String {
    n.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).take(40).collect()
}

/// An MCP server entry (Claude/OpenClaw/Hermes/Codex share the command/args/env/url shape).
fn mcp(acts: &mut Vec<Act>, name: &str, s: &Value) {
    let n = valid_name(name);
    let mut t = toml::Table::new();
    for (from, to) in [("command", "command"), ("args", "args"), ("cwd", "cwd"), ("url", "url"), ("headers", "headers"), ("timeout", "timeout_secs")] {
        if let Some(v) = s.get(from).and_then(tv) {
            t.insert(to.into(), v);
        }
    }
    if let Some(ty) = s.get("type").or(s.get("transport")).and_then(|v| v.as_str()) {
        if matches!(ty, "http" | "sse" | "streamable-http" | "streamable_http") {
            t.insert("transport".into(), toml::Value::String(if ty == "sse" { "sse".into() } else { "http".into() }));
        }
    }
    if s.get("enabled") == Some(&Value::Bool(false)) || s.get("disabled") == Some(&Value::Bool(true)) {
        t.insert("enabled".into(), toml::Value::Boolean(false));
    }
    // env values that look like credentials move to the vault and become references.
    if let Some(env) = s.get("env").and_then(|e| e.as_object()) {
        let mut e = toml::Table::new();
        for (k, v) in env {
            let Some(v) = v.as_str() else { continue };
            if secretish(k) && !v.contains("{{secret:") && !v.starts_with('$') {
                let sn = format!("MCP_{}_{}", n.to_uppercase().replace('-', "_"), k.to_uppercase());
                acts.push(Act::Secret(sn.clone(), v.to_string()));
                e.insert(k.clone(), toml::Value::String(format!("{{{{secret:{sn}}}}}")));
            } else {
                e.insert(k.clone(), toml::Value::String(v.to_string()));
            }
        }
        t.insert("env".into(), toml::Value::Table(e));
    }
    if t.contains_key("command") || t.contains_key("url") {
        acts.push(Act::Config(format!("mcp.{n}"), toml::Value::Table(t)));
    }
}

fn secretish(k: &str) -> bool {
    let k = k.to_uppercase();
    ["KEY", "TOKEN", "SECRET", "PASSWORD"].iter().any(|w| k.contains(w))
}

/// Provider id ark knows for a model string / base URL.
fn model_ref(m: &str, provider_hint: Option<&str>) -> Option<String> {
    let m = m.trim();
    if m.is_empty() {
        return None;
    }
    if m.contains('/') {
        return Some(m.to_string());
    }
    let p = provider_hint.filter(|p| !p.is_empty()).map(String::from).or_else(|| {
        let l = m.to_lowercase();
        Some(if l.starts_with("claude") { "anthropic" } else if l.starts_with("gpt") || l.starts_with("o1") || l.starts_with("o3") || l.starts_with("o4") || l.starts_with("codex") { "openai" } else if l.starts_with("gemini") { "gemini" } else if l.starts_with("grok") { "xai" } else if l.starts_with("deepseek") { "deepseek" } else { return None }.to_string())
    })?;
    Some(format!("{p}/{m}"))
}

fn md_entries(text: &str) -> Vec<String> {
    let t = text.trim();
    if t.is_empty() {
        return vec![];
    }
    if t.contains("\n§\n") {
        return t.split("\n§\n").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    }
    // Bullet lists become one entry per bullet; prose stays one entry.
    let bullets: Vec<String> = t.lines().filter_map(|l| l.trim().strip_prefix("- ").or_else(|| l.trim().strip_prefix("* "))).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if bullets.len() >= 2 {
        bullets
    } else {
        vec![t.chars().take(4000).collect()]
    }
}

fn skills(acts: &mut Vec<Act>, dir: &Path, dest: &Path) {
    // Skill = a directory holding SKILL.md, possibly nested in category dirs.
    fn walk(d: &Path, depth: u32, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.join("SKILL.md").is_file() {
                out.push(p);
            } else if p.is_dir() && depth < 3 {
                walk(&p, depth + 1, out);
            }
        }
    }
    let mut found = vec![];
    walk(dir, 0, &mut found);
    found.sort();
    for s in found {
        let n = s.file_name().unwrap().to_string_lossy().to_string();
        acts.push(Act::Copy(s.clone(), dest.join("skills").join(&n)));
    }
}

// ───────────── sources ─────────────

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
}

pub fn detect() -> Vec<(&'static str, PathBuf)> {
    let h = home();
    let mut v = vec![];
    for d in [".openclaw", ".clawdbot", ".moltbot"] {
        if h.join(d).join("openclaw.json").exists() || h.join(d).join("clawdbot.json").exists() || h.join(d).join("workspace").is_dir() {
            v.push(("openclaw", h.join(d)));
            break;
        }
    }
    if h.join(".hermes/config.yaml").exists() || h.join(".hermes/.env").exists() {
        v.push(("hermes", h.join(".hermes")));
    }
    if h.join(".claude.json").exists() || h.join(".claude/settings.json").exists() {
        v.push(("claude", h.clone()));
    }
    if h.join(".codex/config.toml").exists() {
        v.push(("codex", h.join(".codex")));
    }
    v
}

pub fn plan_openclaw(root: &Path, data: &Path) -> Result<Vec<Act>, String> {
    let mut acts = vec![];
    let cfgf = ["openclaw.json", "clawdbot.json", "moltbot.json"].iter().map(|f| root.join(f)).find(|p| p.exists());
    let cfg = match &cfgf {
        Some(p) => json5(&std::fs::read_to_string(p).map_err(|e| e.to_string())?)?,
        None => json!({}),
    };
    let env: std::collections::HashMap<String, String> = dotenv(&root.join(".env")).into_iter().collect();
    let secret_in = |v: &Value| -> Option<String> {
        match v {
            Value::String(s) if s.starts_with("${") && s.ends_with('}') => env.get(&s[2..s.len() - 1]).cloned().or_else(|| std::env::var(&s[2..s.len() - 1]).ok()),
            Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
            Value::Object(o) if o.get("source").and_then(|s| s.as_str()) == Some("env") => o.get("id").and_then(|i| i.as_str()).and_then(|i| env.get(i).cloned().or_else(|| std::env::var(i).ok())),
            _ => None,
        }
    };
    let field = |ch: &Value, f: &str| ch.get(f).cloned().or_else(|| ch["accounts"]["default"].get(f).cloned()).unwrap_or(Value::Null);
    let model = cfg["agents"]["defaults"]["model"].clone();
    let primary = model.get("primary").cloned().unwrap_or(model.clone());
    if let Some(m) = primary.as_str().and_then(|m| model_ref(m, None)) {
        acts.push(Act::Config("model.default".into(), toml::Value::String(m)));
    }
    if let Some(fb) = model.get("fallbacks").and_then(|f| f.as_array()) {
        let list: Vec<toml::Value> = fb.iter().filter_map(|f| f.as_str().and_then(|m| model_ref(m, None))).map(toml::Value::String).collect();
        if !list.is_empty() {
            acts.push(Act::Config("model.fallback".into(), toml::Value::Array(list)));
        }
    }
    if let Some(ps) = cfg["models"]["providers"].as_object() {
        for (name, p) in ps {
            let base = p["baseUrl"].as_str().unwrap_or("").to_lowercase();
            let var = if base.contains("openrouter") { "OPENROUTER_API_KEY" } else if base.contains("openai.com") { "OPENAI_API_KEY" } else if base.contains("anthropic") || name == "anthropic" { "ANTHROPIC_API_KEY" } else if base.contains("deepseek") { "DEEPSEEK_API_KEY" } else if base.contains("googleapis") || name == "google" { "GEMINI_API_KEY" } else { "" };
            match (secret_in(&p["apiKey"]), var) {
                (Some(k), v) if !v.is_empty() => acts.push(Act::Secret(v.into(), k)),
                (Some(k), _) => {
                    let sn = format!("{}_API_KEY", valid_name(name).to_uppercase());
                    acts.push(Act::Secret(sn.clone(), k));
                    if !base.is_empty() {
                        acts.push(Act::Config(format!("providers.{}", valid_name(name)), toml::Value::Table([("format".to_string(), toml::Value::String("openai_chat".into())), ("base_url".to_string(), toml::Value::String(p["baseUrl"].as_str().unwrap_or("").into())), ("api_key_env".to_string(), toml::Value::String(sn))].into_iter().collect())));
                    }
                }
                _ => {}
            }
        }
    }
    if let Some(servers) = cfg["mcp"]["servers"].as_object() {
        for (n, s) in servers {
            mcp(&mut acts, n, s);
        }
    }
    for (kind, tok_field, secret) in [("telegram", "botToken", "TELEGRAM_BOT_TOKEN"), ("discord", "token", "DISCORD_BOT_TOKEN"), ("slack", "botToken", "SLACK_BOT_TOKEN")] {
        let ch = &cfg["channels"][kind];
        let Some(tok) = secret_in(&field(ch, tok_field)) else { continue };
        acts.push(Act::Secret(secret.into(), tok));
        let mut t = toml::Table::new();
        t.insert("kind".into(), toml::Value::String(kind.into()));
        t.insert("token".into(), toml::Value::String(format!("{{{{secret:{secret}}}}}")));
        if kind == "slack" {
            if let Some(app) = secret_in(&field(ch, "appToken")) {
                acts.push(Act::Secret("SLACK_APP_TOKEN".into(), app));
                t.insert("app_token".into(), toml::Value::String("{{secret:SLACK_APP_TOKEN}}".into()));
            }
        }
        let allow: Vec<toml::Value> = field(ch, "allowFrom").as_array().map(|a| a.iter().map(|v| toml::Value::String(v.as_str().map(String::from).unwrap_or_else(|| v.to_string()))).collect()).unwrap_or_default();
        if !allow.is_empty() {
            t.insert("allow".into(), toml::Value::Array(allow));
        }
        if let Some(p) = field(ch, "dmPolicy").as_str() {
            t.insert("dm_policy".into(), toml::Value::String(p.into()));
        }
        acts.push(Act::Config(format!("channels.{kind}"), toml::Value::Table(t)));
    }
    let ws = ["workspace", "workspace.default"].iter().map(|w| root.join(w)).find(|p| p.is_dir()).unwrap_or_else(|| root.join("workspace"));
    if let Ok(s) = std::fs::read_to_string(ws.join("SOUL.md")) {
        acts.push(Act::Config("identity".into(), toml::Value::String(s.replace("OpenClaw", "ark").trim().to_string())));
    }
    for (f, target) in [("MEMORY.md", "MEMORY.md"), ("USER.md", "USER.md")] {
        for e in md_entries(&std::fs::read_to_string(ws.join(f)).unwrap_or_default()) {
            acts.push(Act::Memory(target, e));
        }
    }
    if let Ok(rd) = std::fs::read_dir(ws.join("memory")) {
        let mut days: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "md")).collect();
        days.sort();
        for d in days {
            for e in md_entries(&std::fs::read_to_string(&d).unwrap_or_default()) {
                acts.push(Act::Memory("MEMORY.md", e));
            }
        }
    }
    skills(&mut acts, &ws.join("skills"), data);
    skills(&mut acts, &root.join("skills"), data);
    if cfgf.is_none() {
        acts.push(Act::Note("no openclaw.json found; only workspace files were read".into()));
    }
    if cfg["cron"].is_object() || root.join("cron/jobs.json").exists() {
        acts.push(Act::Note("OpenClaw cron jobs are not converted; recreate them with `ark schedule add`".into()));
    }
    Ok(acts)
}

pub fn plan_hermes(root: &Path, data: &Path) -> Result<Vec<Act>, String> {
    let mut acts = vec![];
    let cfg = yaml(&std::fs::read_to_string(root.join("config.yaml")).unwrap_or_default());
    let (model, provider) = match &cfg["model"] {
        Value::String(s) => (s.clone(), cfg["provider"].as_str().map(String::from)),
        Value::Object(o) => (o.get("default").or(o.get("model")).and_then(|v| v.as_str()).unwrap_or("").to_string(), o.get("provider").and_then(|v| v.as_str()).map(String::from)),
        _ => (String::new(), None),
    };
    if let Some(m) = model_ref(&model, provider.as_deref()) {
        acts.push(Act::Config("model.default".into(), toml::Value::String(m)));
    }
    if let Some(servers) = cfg["mcp_servers"].as_object() {
        for (n, s) in servers {
            mcp(&mut acts, n, s);
        }
    }
    for (k, v) in dotenv(&root.join(".env")) {
        if secretish(&k) && !v.is_empty() {
            acts.push(Act::Secret(k, v));
        }
    }
    for (f, target) in [("memories/MEMORY.md", "MEMORY.md"), ("memories/USER.md", "USER.md")] {
        for e in md_entries(&std::fs::read_to_string(root.join(f)).unwrap_or_default()) {
            acts.push(Act::Memory(target, e));
        }
    }
    if let Ok(s) = std::fs::read_to_string(root.join("SOUL.md")) {
        acts.push(Act::Config("identity".into(), toml::Value::String(s.replace("Hermes", "ark").trim().to_string())));
    }
    if let Some(p) = cfg["display"]["personality"].as_str().filter(|p| !p.is_empty()) {
        acts.push(Act::Config("personality".into(), toml::Value::String(p.into())));
    }
    skills(&mut acts, &root.join("skills"), data);
    Ok(acts)
}

pub fn plan_claude(home: &Path, data: &Path) -> Result<Vec<Act>, String> {
    let mut acts = vec![];
    let main = std::fs::read_to_string(home.join(".claude.json")).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()).unwrap_or(json!({}));
    if let Some(s) = main["mcpServers"].as_object() {
        for (n, v) in s {
            mcp(&mut acts, n, v);
        }
    }
    let settings = std::fs::read_to_string(home.join(".claude/settings.json")).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()).unwrap_or(json!({}));
    if let Some(m) = settings["model"].as_str() {
        let m = match m {
            "opus" => "claude-opus-4-1",
            "sonnet" => "claude-sonnet-4-5",
            "haiku" => "claude-haiku-4-5",
            o => o,
        };
        acts.push(Act::Config("model.default".into(), toml::Value::String(format!("anthropic/{m}"))));
    }
    if let Some(env) = settings["env"].as_object() {
        for (k, v) in env {
            if let (true, Some(v)) = (secretish(k), v.as_str()) {
                acts.push(Act::Secret(k.clone(), v.into()));
            }
        }
    }
    let _ = data;
    acts.push(Act::Note("ark already reads ~/.claude/commands, ~/.claude/skills, CLAUDE.md and Claude-compatible hooks in place; nothing to copy".into()));
    Ok(acts)
}

pub fn plan_codex(root: &Path, data: &Path) -> Result<Vec<Act>, String> {
    let mut acts = vec![];
    let cfg: toml::Table = std::fs::read_to_string(root.join("config.toml")).ok().and_then(|s| s.parse().ok()).unwrap_or_default();
    let provider = cfg.get("model_provider").and_then(|v| v.as_str());
    if let Some(m) = cfg.get("model").and_then(|v| v.as_str()).and_then(|m| model_ref(m, provider.or(Some("openai")))) {
        acts.push(Act::Config("model.default".into(), toml::Value::String(m)));
    }
    if let Some(ps) = cfg.get("model_providers").and_then(|v| v.as_table()) {
        for (n, p) in ps {
            let mut t = toml::Table::new();
            let wire = p.get("wire_api").and_then(|v| v.as_str()).unwrap_or("chat");
            t.insert("format".into(), toml::Value::String(if wire == "responses" { "openai_responses".into() } else { "openai_chat".into() }));
            if let Some(b) = p.get("base_url") {
                t.insert("base_url".into(), b.clone());
            }
            if let Some(k) = p.get("env_key") {
                t.insert("api_key_env".into(), k.clone());
            }
            acts.push(Act::Config(format!("providers.{}", valid_name(n)), toml::Value::Table(t)));
        }
    }
    if let Some(s) = cfg.get("mcp_servers").and_then(|v| v.as_table()) {
        for (n, v) in s {
            mcp(&mut acts, n, &serde_json::to_value(v).unwrap_or_default());
        }
    }
    if let Ok(a) = std::fs::read_to_string(root.join("AGENTS.md")) {
        for e in md_entries(&a) {
            acts.push(Act::Memory("USER.md", e));
        }
    }
    skills(&mut acts, &root.join("skills"), data);
    Ok(acts)
}

pub fn plan(source: &str, path: Option<&Path>, data: &Path) -> Result<Vec<Act>, String> {
    let h = home();
    match source {
        "openclaw" | "claw" => plan_openclaw(path.map(Path::to_path_buf).as_deref().unwrap_or(&detect().into_iter().find(|d| d.0 == "openclaw").map(|d| d.1).unwrap_or(h.join(".openclaw"))), data),
        "hermes" => plan_hermes(path.unwrap_or(&h.join(".hermes")), data),
        "claude" | "claude-code" => plan_claude(path.unwrap_or(&h), data),
        "codex" => plan_codex(path.unwrap_or(&h.join(".codex")), data),
        other => Err(format!("unknown source `{other}` (openclaw, hermes, claude, codex)")),
    }
}

pub fn describe(a: &Act) -> String {
    match a {
        Act::Config(k, v) => format!("config  {k} = {}", crate::slash::redact(&format!("x = {}", v.to_string().chars().take(120).collect::<String>())).trim_start_matches("x = ")),
        Act::Secret(n, _) => format!("secret  {n} → vault"),
        Act::Memory(f, e) => format!("memory  {f}: {}", e.chars().take(80).collect::<String>().replace('\n', " ")),
        Act::Copy(s, d) => format!("copy    {} → {}", s.display(), d.display()),
        Act::Note(n) => format!("note    {n}"),
    }
}

/// Apply a plan. Existing config keys are kept unless `overwrite`. Returns a summary.
pub fn apply(paths: &Paths, acts: &[Act], overwrite: bool) -> Result<String, String> {
    let mut text = std::fs::read_to_string(paths.user_config()).unwrap_or_default();
    let cur: toml::Table = text.parse().unwrap_or_default();
    let (mut cfg_n, mut sec_n, mut mem_n, mut copy_n, mut kept) = (0, 0, 0, 0, vec![]);
    std::fs::create_dir_all(&paths.config_dir).map_err(|e| e.to_string())?;
    let vault = ark_kernel::vault::Vault::load(&paths.secrets())?;
    for a in acts {
        match a {
            Act::Config(k, v) => {
                if crate::ops::confcli::get_in(&cur, k).is_some() && !overwrite {
                    kept.push(k.clone());
                    continue;
                }
                text = crate::ops::confcli::edited_text(&text, k, Some(v.clone()))?;
                cfg_n += 1;
            }
            Act::Secret(n, v) => {
                if vault.names().contains(n) && !overwrite {
                    kept.push(n.clone());
                    continue;
                }
                vault.set(n, v)?;
                sec_n += 1;
            }
            Act::Memory(f, e) => {
                let dir = paths.data.join("memory");
                std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                let p = dir.join(f);
                let cur = std::fs::read_to_string(&p).unwrap_or_default();
                if cur.split("\n§\n").any(|x| x.trim() == e.trim()) {
                    continue;
                }
                let new = if cur.trim().is_empty() { e.trim().to_string() } else { format!("{}\n§\n{}", cur.trim_end(), e.trim()) };
                ark_kernel::util::atomic_write(&p, new.as_bytes()).map_err(|e| e.to_string())?;
                mem_n += 1;
            }
            Act::Copy(s, d) => {
                if d.exists() && !overwrite {
                    kept.push(d.display().to_string());
                    continue;
                }
                let mut entries = vec![];
                crate::ops::archive::collect(s, "", &|_| false, &mut entries)?;
                crate::ops::archive::extract(&entries, d)?;
                copy_n += 1;
            }
            Act::Note(_) => {}
        }
    }
    if cfg_n > 0 {
        crate::ops::confcli::write_validated(paths, &text, true)?;
    }
    let mut s = format!("imported {cfg_n} config value(s), {sec_n} secret(s), {mem_n} memory entr(ies), {copy_n} skill(s)");
    if !kept.is_empty() {
        s.push_str(&format!("\nkept existing (use --overwrite to replace): {}", kept.join(", ")));
    }
    Ok(s)
}

/// `ark migrate retired-models [--apply]`.
fn retired(paths: &Paths, apply_it: bool) -> R {
    let text = std::fs::read_to_string(paths.user_config()).unwrap_or_default();
    let (new, notes) = crate::ops::confcli::migrate_text(&text)?;
    let notes: Vec<&String> = notes.iter().filter(|n| !n.starts_with("config_version")).collect();
    if notes.is_empty() {
        println!("no retired models in {}", paths.user_config().display());
        return Ok(0);
    }
    for n in &notes {
        println!("• {n}");
    }
    if apply_it {
        crate::ops::confcli::write_validated(paths, &new, true)?;
        println!("rewrote {} (backup kept)", paths.user_config().display());
    } else {
        println!("dry run — re-run with --apply");
    }
    Ok(0)
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if !COMMANDS.contains(&cmd) {
        return None;
    }
    Some((|| -> R {
        let paths = Paths::from_env();
        // `ark migrate from <src>`, `ark migrate <src>`, `ark import-agent <src>`, `ark claw migrate`.
        let mut src = match cmd {
            "claw" => match a.pos(0) {
                Some("migrate") | None => "openclaw".to_string(),
                Some("cleanup") => {
                    let dirs: Vec<PathBuf> = detect().into_iter().filter(|d| d.0 == "openclaw").map(|d| d.1).collect();
                    for d in dirs {
                        let to = d.with_file_name(format!("{}.migrated-{}", d.file_name().unwrap().to_string_lossy(), ark_kernel::util::unix_now()));
                        if a.flag("yes") {
                            std::fs::rename(&d, &to).map_err(|e| e.to_string())?;
                            println!("archived {} → {}", d.display(), to.display());
                        } else {
                            println!("would archive {} → {} (re-run with --yes)", d.display(), to.display());
                        }
                    }
                    return Ok(0);
                }
                Some(o) => return usage(format!("unknown `claw {o}` (migrate, cleanup)")),
            },
            _ => a.pos(0).unwrap_or("").to_string(),
        };
        if src == "from" {
            src = a.pos(1).unwrap_or("").to_string();
        }
        match src.as_str() {
            "" | "detect" | "list" => {
                let d = detect();
                if d.is_empty() {
                    println!("no other agent found (looked for ~/.openclaw, ~/.hermes, ~/.claude.json, ~/.codex)");
                }
                for (k, p) in d {
                    println!("{k:<9} {}  →  ark migrate from {k} --dry-run", p.display());
                }
                Ok(0)
            }
            "retired-models" | "xai" => retired(&paths, a.flag("apply")),
            s => {
                let acts = plan(s, a.val("path").map(Path::new), &paths.data)?;
                if acts.iter().all(|x| matches!(x, Act::Note(_))) {
                    for x in &acts {
                        println!("{}", describe(x));
                    }
                    println!("nothing to import from {s}");
                    return Ok(0);
                }
                for x in &acts {
                    println!("{}", describe(x));
                }
                if a.flag("dry-run") {
                    println!("dry run — nothing written");
                    return Ok(0);
                }
                println!("{}", apply(&paths, &acts, a.flag("overwrite"))?);
                Ok(0)
            }
        }
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let d = ark_core::tmp::scratch_path(format!("ark-mig-{}", ark_kernel::util::random_hex(6)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn parsers() {
        let v = json5("{\n // c\n a: 1, 'b': 'it\\'s', c: [1,2,], /* x */ d: {e: true,},\n}").unwrap();
        assert_eq!(v, json!({"a": 1, "b": "it's", "c": [1, 2], "d": {"e": true}}));
        let y = yaml("model:\n  default: anthropic/claude-opus\n  provider: anthropic\nmcp_servers:\n  fs:\n    command: npx\n    args: [\"-y\", \"fs\"]\n    env:\n      TOKEN: abc # secret\nlist:\n  - one\n  - k: v\n    z: 2\nblock: |\n  line1\n  line2\nflag: true\n");
        assert_eq!(y["model"]["default"], "anthropic/claude-opus");
        assert_eq!(y["mcp_servers"]["fs"]["args"], json!(["-y", "fs"]));
        assert_eq!(y["mcp_servers"]["fs"]["env"]["TOKEN"], "abc");
        assert_eq!(y["list"], json!(["one", {"k": "v", "z": 2}]));
        assert_eq!(y["block"], "line1\nline2");
        assert_eq!(y["flag"], true);
        assert_eq!(model_ref("claude-x", None).unwrap(), "anthropic/claude-x");
        assert_eq!(model_ref("m", Some("vllm")).unwrap(), "vllm/m");
        assert!(model_ref("mystery", None).is_none());
    }

    #[test]
    fn openclaw_import() {
        let root = tmp();
        std::fs::create_dir_all(root.join("workspace/memory")).unwrap();
        std::fs::create_dir_all(root.join("workspace/skills/weather")).unwrap();
        std::fs::write(root.join("workspace/skills/weather/SKILL.md"), "---\nname: weather\n---\n").unwrap();
        std::fs::write(root.join(".env"), "TG=123:abc\n").unwrap();
        std::fs::write(root.join("openclaw.json"), r#"{
          // json5
          agents: { defaults: { model: { primary: "anthropic/claude-opus-4-6", fallbacks: ["openai/gpt-5"] } } },
          models: { providers: { anthropic: { apiKey: "sk-ant-x" }, local: { baseUrl: "http://localhost:8000/v1", apiKey: "lk" } } },
          mcp: { servers: { gh: { command: "npx", args: ["gh"], env: { GITHUB_TOKEN: "ghp_x" } } } },
          channels: { telegram: { botToken: "${TG}", allowFrom: [42, "@amy"], dmPolicy: "pairing" } },
        }"#).unwrap();
        std::fs::write(root.join("workspace/SOUL.md"), "I am OpenClaw.").unwrap();
        std::fs::write(root.join("workspace/MEMORY.md"), "- likes tea\n- lives in Taipei\n").unwrap();
        std::fs::write(root.join("workspace/memory/2026-01-01.md"), "met Bob").unwrap();
        let p = Paths { data: root.join("ark/data"), config_dir: root.join("ark/config"), runtime: root.join("ark/run") };
        let acts = plan_openclaw(&root, &p.data).unwrap();
        assert!(acts.contains(&Act::Secret("TELEGRAM_BOT_TOKEN".into(), "123:abc".into())));
        assert!(acts.contains(&Act::Secret("ANTHROPIC_API_KEY".into(), "sk-ant-x".into())));
        let out = apply(&p, &acts, false).unwrap();
        assert!(out.contains("skill"), "{out}");
        let cfg = ark_kernel::config::Config::load(Some(&p.user_config()), None, &[]).unwrap();
        assert_eq!(cfg.model.default, "anthropic/claude-opus-4-6");
        assert_eq!(cfg.model.fallback, ["openai/gpt-5"]);
        assert_eq!(cfg.identity, "I am ark.");
        assert_eq!(cfg.mcp["gh"]["env"]["GITHUB_TOKEN"].as_str(), Some("{{secret:MCP_GH_GITHUB_TOKEN}}"));
        assert_eq!(cfg.channels["telegram"]["token"].as_str(), Some("{{secret:TELEGRAM_BOT_TOKEN}}"));
        assert_eq!(cfg.providers["local"]["base_url"].as_str(), Some("http://localhost:8000/v1"));
        let text = std::fs::read_to_string(p.user_config()).unwrap();
        assert!(!text.contains("sk-ant-x") && !text.contains("ghp_x") && !text.contains("123:abc"), "no secrets in config");
        let mem = std::fs::read_to_string(p.data.join("memory/MEMORY.md")).unwrap();
        assert!(mem.contains("likes tea\n§\nlives in Taipei") && mem.contains("met Bob"));
        assert!(p.data.join("skills/weather/SKILL.md").exists());
        // Re-running keeps what exists.
        assert!(apply(&p, &acts, false).unwrap().contains("kept existing"));
    }

    #[test]
    fn hermes_claude_codex_import() {
        let root = tmp();
        std::fs::create_dir_all(root.join("memories")).unwrap();
        std::fs::write(root.join("config.yaml"), "model:\n  default: claude-sonnet-4\n  provider: anthropic\nmcp_servers:\n  time:\n    command: uvx\n    args: [mcp-server-time]\ndisplay:\n  personality: pirate\n").unwrap();
        std::fs::write(root.join(".env"), "ANTHROPIC_API_KEY=sk\nEDITOR=vim\n").unwrap();
        std::fs::write(root.join("memories/USER.md"), "Name is Amy\n§\nPrefers zh-TW").unwrap();
        let acts = plan_hermes(&root, Path::new("/x")).unwrap();
        assert!(acts.contains(&Act::Config("model.default".into(), toml::Value::String("anthropic/claude-sonnet-4".into()))));
        assert!(acts.contains(&Act::Secret("ANTHROPIC_API_KEY".into(), "sk".into())) && !acts.iter().any(|a| matches!(a, Act::Secret(n, _) if n == "EDITOR")));
        assert_eq!(acts.iter().filter(|a| matches!(a, Act::Memory("USER.md", _))).count(), 2);
        assert!(acts.contains(&Act::Config("personality".into(), toml::Value::String("pirate".into()))));
        let home = tmp();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::write(home.join(".claude.json"), r#"{"mcpServers": {"web": {"type": "http", "url": "https://x/mcp", "headers": {"A": "b"}}}}"#).unwrap();
        std::fs::write(home.join(".claude/settings.json"), r#"{"model": "opus", "env": {"OPENAI_API_KEY": "k"}}"#).unwrap();
        let acts = plan_claude(&home, Path::new("/x")).unwrap();
        assert!(acts.iter().any(|a| matches!(a, Act::Config(k, toml::Value::Table(t)) if k == "mcp.web" && t["transport"].as_str() == Some("http"))));
        assert!(acts.contains(&Act::Config("model.default".into(), toml::Value::String("anthropic/claude-opus-4-1".into()))));
        let cx = tmp();
        std::fs::write(cx.join("config.toml"), "model = \"gpt-5-codex\"\n[model_providers.az]\nbase_url = \"https://az/v1\"\nenv_key = \"AZ_KEY\"\nwire_api = \"responses\"\n[mcp_servers.docs]\ncommand = \"docs-mcp\"\n").unwrap();
        let acts = plan_codex(&cx, Path::new("/x")).unwrap();
        assert!(acts.contains(&Act::Config("model.default".into(), toml::Value::String("openai/gpt-5-codex".into()))));
        assert!(acts.iter().any(|a| matches!(a, Act::Config(k, _) if k == "mcp.docs")));
        assert!(acts.iter().any(|a| matches!(a, Act::Config(k, toml::Value::Table(t)) if k == "providers.az" && t["format"].as_str() == Some("openai_responses"))));
    }
}
