//! MCP servers as kernel tools. `Registry::load` serves each server's tool list
//! from a catalog cache, so a session start costs no process spawns or network
//! round-trips; a server is only started when one of its tools is called.

use crate::mcp::{Client, ToolDef};
use crate::{fnv, tool_name, McpServerConfig, Secrets};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const CACHE_VERSION: u32 = 1;
const DESC_MAX: usize = 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromptInfo {
    pub server: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// (name, required)
    #[serde(default)]
    pub arguments: Vec<(String, bool)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Catalog {
    version: u32,
    tools: Vec<ToolDef>,
    resources: bool,
    prompts: Vec<PromptInfo>,
    instructions: Option<String>,
}

pub struct Registry {
    clients: BTreeMap<String, Arc<Client>>,
    catalogs: BTreeMap<String, Catalog>,
    tools: Vec<Arc<dyn Tool>>,
    warnings: Vec<String>,
    cache_dir: PathBuf,
}

fn cache_path(dir: &Path, name: &str, cfg: &McpServerConfig) -> PathBuf {
    // Keyed by the config as written (secret references, not values), so rotating
    // a token doesn't invalidate the catalog but changing the command does.
    let key = fnv(serde_json::to_string(cfg).unwrap_or_default().as_bytes());
    dir.join(format!("mcp-{name}-{key:016x}.json"))
}

fn fetch(c: &Client) -> Result<Catalog, String> {
    let init = c.info()?;
    let caps = init.get("capabilities").cloned().unwrap_or_default();
    let tools = if caps.get("tools").is_some() { c.list_tools()? } else { vec![] };
    let prompts = if caps.get("prompts").is_some() {
        c.list_prompts()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|p| {
                Some(PromptInfo {
                    server: c.name.clone(),
                    name: p.get("name")?.as_str()?.into(),
                    description: p.get("description").and_then(Value::as_str).unwrap_or("").into(),
                    arguments: p
                        .get("arguments")
                        .and_then(Value::as_array)
                        .map(|a| a.iter().filter_map(|x| Some((x.get("name")?.as_str()?.to_string(), x.get("required").and_then(Value::as_bool).unwrap_or(false)))).collect())
                        .unwrap_or_default(),
                })
            })
            .collect()
    } else {
        vec![]
    };
    let instructions = init.get("instructions").and_then(Value::as_str).map(str::to_string);
    Ok(Catalog { version: CACHE_VERSION, tools, resources: caps.get("resources").is_some(), prompts, instructions })
}

fn write_cache(path: &Path, cat: &Catalog) {
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, serde_json::to_vec_pretty(cat).unwrap_or_default()).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

impl Registry {
    /// Build tools for every enabled server. Never fails: a broken server becomes a warning.
    pub fn load(configs: &BTreeMap<String, McpServerConfig>, cache_dir: &Path, secrets: Secrets) -> Registry {
        let mut reg = Registry { clients: BTreeMap::new(), catalogs: BTreeMap::new(), tools: vec![], warnings: vec![], cache_dir: cache_dir.to_path_buf() };
        let mut todo = vec![];
        for (name, cfg) in configs.iter().filter(|(_, c)| c.enabled) {
            match Client::new(name, cfg.clone(), secrets.clone()) {
                Ok(c) => {
                    let path = cache_path(cache_dir, name, cfg);
                    c.set_cache_path(path.clone());
                    let cached = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice::<Catalog>(&b).ok()).filter(|c| c.version == CACHE_VERSION);
                    reg.clients.insert(name.clone(), Arc::new(c));
                    match cached {
                        Some(cat) => {
                            reg.catalogs.insert(name.clone(), cat);
                        }
                        None => todo.push((name.clone(), path)),
                    }
                }
                Err(e) => reg.warnings.push(e),
            }
        }
        // Uncached servers start in parallel so one slow server doesn't serialize startup.
        let fetched: Vec<_> = std::thread::scope(|s| {
            let hs: Vec<_> = todo
                .iter()
                .map(|(name, path)| {
                    let c = reg.clients[name].clone();
                    s.spawn(move || (name.clone(), path.clone(), fetch(&c)))
                })
                .collect();
            hs.into_iter().map(|h| h.join().expect("fetch thread")).collect()
        });
        for (name, path, r) in fetched {
            match r {
                Ok(cat) => {
                    write_cache(&path, &cat);
                    reg.catalogs.insert(name, cat);
                }
                Err(e) => reg.warnings.push(format!("{e} (its tools are unavailable this session)")),
            }
        }
        reg.rebuild();
        reg
    }

    fn rebuild(&mut self) {
        let mut taken = HashSet::new();
        let mut tools: Vec<Arc<dyn Tool>> = vec![];
        for (name, cat) in &self.catalogs {
            let client = self.clients[name].clone();
            tools.extend(bridge_tools(&client, &cat.tools, cat.resources, &mut taken));
        }
        self.tools = tools;
    }

    pub fn tools(&self) -> Vec<Arc<dyn Tool>> {
        self.tools.clone()
    }
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
    pub fn client(&self, name: &str) -> Option<Arc<Client>> {
        self.clients.get(name).cloned()
    }
    /// (server, tool count, running) for status displays.
    pub fn status(&self) -> Vec<(String, usize, bool)> {
        self.clients.iter().map(|(n, c)| (n.clone(), self.catalogs.get(n).map(|k| k.tools.len()).unwrap_or(0), c.is_running())).collect()
    }
    /// Server-provided usage instructions (from `initialize`), for the system prompt.
    pub fn instructions(&self) -> Vec<(String, String)> {
        self.catalogs.iter().filter_map(|(n, c)| c.instructions.clone().filter(|i| !i.trim().is_empty()).map(|i| (n.clone(), i))).collect()
    }

    /// Reconnect a server and rewrite its catalog. Returns the new tool count.
    pub fn refresh(&mut self, name: &str) -> Result<usize, String> {
        let c = self.client(name).ok_or_else(|| format!("no enabled mcp server `{name}`"))?;
        c.shutdown();
        let path = cache_path(&self.cache_dir, name, c.config());
        let _ = std::fs::remove_file(&path);
        let cat = fetch(&c)?;
        write_cache(&path, &cat);
        let n = cat.tools.len();
        self.catalogs.insert(name.into(), cat);
        self.rebuild();
        Ok(n)
    }

    pub fn prompts(&self) -> Vec<PromptInfo> {
        self.catalogs.values().flat_map(|c| c.prompts.clone()).collect()
    }

    pub fn get_prompt(&self, server: &str, name: &str, args: &BTreeMap<String, String>) -> Result<String, String> {
        let c = self.client(server).ok_or_else(|| format!("no enabled mcp server `{server}`"))?;
        if let Some(p) = self.prompts().into_iter().find(|p| p.server == server && p.name == name) {
            let missing: Vec<_> = p.arguments.iter().filter(|(a, req)| *req && !args.contains_key(a)).map(|(a, _)| a.as_str()).collect();
            if !missing.is_empty() {
                return Err(format!("prompt `{name}` needs argument(s): {}", missing.join(", ")));
            }
        }
        c.get_prompt(name, args)
    }
}

/// Tools for one server's catalog (also used by plugins).
pub fn bridge_tools(client: &Arc<Client>, defs: &[ToolDef], resources: bool, taken: &mut HashSet<String>) -> Vec<Arc<dyn Tool>> {
    let allow = client.config().tools.clone();
    let dest = match &client.config().url {
        Some(u) => origin(u),
        None => format!("mcp:{}", client.name),
    };
    let mut out: Vec<Arc<dyn Tool>> = vec![];
    for d in defs.iter().filter(|d| allow.as_ref().is_none_or(|a| a.contains(&d.name))) {
        let mut desc: String = d.description.trim().chars().take(DESC_MAX).collect();
        if desc.is_empty() {
            desc = format!("`{}` from MCP server {}", d.name, client.name);
        }
        let schema = if d.input_schema.is_object() { d.input_schema.clone() } else { json!({"type": "object"}) };
        let spec = ToolSpec { name: tool_name(&client.name, &d.name, taken), description: desc, input_schema: schema, parallel_safe: false, idempotent: d.read_only || d.idempotent, pinned: false };
        out.push(Arc::new(McpTool { client: client.clone(), remote: d.name.clone(), spec, dest: dest.clone(), kind: Kind::Tool }));
    }
    if resources {
        let spec = ToolSpec {
            name: tool_name(&client.name, "resources", taken),
            description: format!("List or read resources of MCP server {}. action=list, or action=read with uri.", client.name),
            input_schema: json!({"type": "object", "properties": {"action": {"type": "string", "enum": ["list", "read"]}, "uri": {"type": "string"}}, "required": ["action"]}),
            parallel_safe: false,
            idempotent: true,
            pinned: false,
        };
        out.push(Arc::new(McpTool { client: client.clone(), remote: String::new(), spec, dest, kind: Kind::Resources }));
    }
    out
}

fn origin(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("https", url));
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host);
    format!("{scheme}://{host}")
}

#[derive(Clone, Copy)]
enum Kind {
    Tool,
    Resources,
}

pub struct McpTool {
    client: Arc<Client>,
    remote: String,
    spec: ToolSpec,
    dest: String,
    kind: Kind,
}

impl McpTool {
    pub fn server(&self) -> &str {
        &self.client.name
    }
    pub fn remote_name(&self) -> &str {
        &self.remote
    }
}

/// Apply secret substitution to every string inside a JSON value (never to the
/// serialized document: a secret containing `"` must not break the JSON).
fn substitute(v: &Value, f: &dyn Fn(&str) -> String) -> Value {
    match v {
        Value::String(s) => Value::String(f(s)),
        Value::Array(a) => Value::Array(a.iter().map(|x| substitute(x, f)).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), substitute(x, f))).collect()),
        other => other.clone(),
    }
}

impl Tool for McpTool {
    fn spec(&self) -> ToolSpec {
        self.spec.clone()
    }
    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        vec![Effect::Net { dest: self.dest.clone(), payload: input.to_string() }]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let r = match self.kind {
            Kind::Tool => {
                let args = if input.is_null() { json!({}) } else { substitute(&input, &*ctx.secrets) };
                self.client.call_tool(&self.remote, args, &ctx.cancel).map(|r| if r.is_error { ToolOutput::err(r.text) } else { ToolOutput::ok(r.text) })
            }
            Kind::Resources => match input.get("action").and_then(Value::as_str) {
                Some("list") => self.client.list_resources().map(|rs| {
                    let lines: Vec<String> = rs
                        .iter()
                        .map(|r| format!("{}  {}", r.get("uri").and_then(Value::as_str).unwrap_or("?"), r.get("name").or_else(|| r.get("description")).and_then(Value::as_str).unwrap_or("")))
                        .collect();
                    ToolOutput::ok(if lines.is_empty() { "(no resources)".into() } else { lines.join("\n") })
                }),
                Some("read") => match input.get("uri").and_then(Value::as_str) {
                    Some(u) => self.client.read_resource(u, &ctx.cancel).map(ToolOutput::ok),
                    None => Ok(ToolOutput::err("action=read needs `uri`")),
                },
                _ => Ok(ToolOutput::err("action must be `list` or `read`")),
            },
        };
        r.unwrap_or_else(ToolOutput::err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_and_substitution() {
        assert_eq!(origin("https://user:pw@api.x.io:8443/mcp?a=1"), "https://api.x.io:8443");
        assert_eq!(origin("http://127.0.0.1:9/mcp"), "http://127.0.0.1:9");
        let f = |s: &str| s.replace("{{secret:T}}", "a\"b");
        let v = substitute(&json!({"k": ["x {{secret:T}}", 1, {"n": "{{secret:T}}"}]}), &f);
        assert_eq!(v, json!({"k": ["x a\"b", 1, {"n": "a\"b"}]}));
    }
}
