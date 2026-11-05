//! Hermes (`hermes-agent`) imports.
//!
//! - `plugins/**/plugin.yaml` — Python plugins (`kind: standalone`, `backend`,
//!   `model-provider`, …) that declare `provides_hooks`, `provides_tools`,
//!   `requires_env`, `platforms`, and register their callbacks from `__init__.py`.
//!   Upstream: `hermes_cli/plugins.py`, `hermes_cli/plugin_validate.py`.
//! - `optional-mcps/<name>/manifest.yaml` — URL-only / stdio MCP catalog entries
//!   (`transport`, `auth`, `tools.default_excluded`, `source`, `post_install`).
//!   Upstream: `hermes_cli/mcp_catalog.py`.
//!
//! Hermes plugins are not MCP servers: nothing in them speaks JSON-RPC, so a
//! generated `hermes_shim.py` wraps the package in seagent's plugin protocol.

use super::{fragment, sanitize_id, secret_env, Imported, Shim};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn strings(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(str::trim).filter(|x| !x.is_empty()).map(String::from).collect(),
        Some(Value::String(s)) => vec![s.trim().to_string()].into_iter().filter(|x| !x.is_empty()).collect(),
        _ => vec![],
    }
}

pub fn import(dir: &Path) -> Result<Imported, String> {
    let root = dir.canonicalize().map_err(|e| format!("{}: {e}", dir.display()))?;
    if root.join("plugin.yaml").is_file() {
        plugin(&root)
    } else if root.join("manifest.yaml").is_file() {
        mcp_entry(&root)
    } else {
        Err(format!("{}: neither plugin.yaml nor manifest.yaml", root.display()))
    }
}

fn plugin(root: &Path) -> Result<Imported, String> {
    let man = root.join("plugin.yaml");
    let text = fs::read_to_string(&man).map_err(|e| format!("{}: {e}", man.display()))?;
    let v = yaml::parse(&text).map_err(|e| format!("{}: {e}", man.display()))?;
    if !v.is_object() {
        return Err(format!("{}: not a mapping", man.display()));
    }
    let dir_name = root.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let name = if s(&v, "name").is_empty() { dir_name.to_string() } else { s(&v, "name").to_string() };
    let id = sanitize_id(&name);
    if id.is_empty() {
        return Err(format!("{}: no usable `name`", man.display()));
    }
    let declared_kind = s(&v, "kind").to_string();
    let hooks = strings(v.get("provides_hooks"));
    let tools = strings(v.get("provides_tools"));
    let requires_env = strings(v.get("requires_env"));
    let optional_env = strings(v.get("optional_env"));
    let platforms = strings(v.get("platforms"));
    let mut capabilities: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    if !declared_kind.is_empty() {
        capabilities.push(format!("kind: {declared_kind}"));
    }
    for k in ["provides_web_providers", "provides_browser_providers", "provides_middleware", "provides_commands"] {
        let items = strings(v.get(k));
        if !items.is_empty() {
            capabilities.push(format!("{k}: {}", items.join(", ")));
        }
    }
    if !platforms.is_empty() {
        capabilities.push(format!("platforms: {}", platforms.join(", ")));
    }

    // Hook names: seagent's canonical event plus the Hermes spelling the plugin exports.
    let mut hook_pairs: Vec<(String, Vec<String>)> = Vec::new();
    for h in &hooks {
        let event = seagent_kernel::hooks::HookEvent::parse(h).map(|e| e.name());
        match event {
            Some(ev) => {
                capabilities.push(format!("hook: {h} → seagent `{ev}`"));
                // Both spellings are candidates: the plugin may export
                // `on_pre_tool_call` (Hermes) or `on_pre_tool` (seagent's name).
                match hook_pairs.iter_mut().find(|(e, _)| *e == ev) {
                    Some((_, names)) => {
                        for n in [h.clone(), ev] {
                            if !names.contains(&n) {
                                names.push(n);
                            }
                        }
                    }
                    None => {
                        let mut names = vec![h.clone()];
                        if *h != ev {
                            names.push(ev.clone());
                        }
                        hook_pairs.push((ev, names));
                    }
                }
            }
            None => {
                capabilities.push(format!("hook: {h}"));
                warnings.push(format!("hook `{h}`: no seagent hook event matches it; the shim never dispatches it (the plugin's registration is ignored)."));
            }
        }
    }
    for t in &tools {
        capabilities.push(format!("tool: {t}"));
    }
    for e in requires_env.iter().chain(optional_env.iter()) {
        capabilities.push(format!("env: {e}"));
    }

    if declared_kind == "model-provider" {
        warnings.push("kind: model-provider: Hermes providers plug into its own registry; in seagent a model provider must answer `seagent/provider.complete` over stdio (`providers` in the initialize result). The shim does not implement it, so the provider will not appear — use a native seagent provider instead.".into());
    }
    if !requires_env.is_empty() {
        warnings.push(format!("requires_env: {} — set them in the vault; the fragment only carries {{{{secret:NAME}}}} references.", requires_env.join(", ")));
    }
    if !platforms.is_empty() {
        warnings.push(format!("platforms ({}): seagent has no per-plugin platform gate; the shim starts on every host.", platforms.join(", ")));
    }

    let python = root.join("__init__.py").is_file();
    let mut skills = Vec::new();
    for rel in ["", "skills"] {
        let p = if rel.is_empty() { root.to_path_buf() } else { root.join(rel) };
        if p.join("SKILL.md").is_file() {
            skills.push(p);
        }
    }

    let (kind, config_toml, shim) = if python {
        let contents = include_str!("shim/hermes_shim.py")
            .replace("__ID__", &json!(id).to_string())
            .replace("__PLUGIN_DIR__", &json!(root.display().to_string()).to_string())
            .replace("__PKG__", &json!(format!("seagent_compat_{}", id.replace('-', "_"))).to_string())
            .replace("__HOOKS__", &json!(hook_pairs).to_string())
            .replace("__TOOLS__", &json!(tools).to_string());
        let mut t = toml::Table::new();
        t.insert("command".into(), "python3".into());
        t.insert("args".into(), toml::Value::Array(vec![toml::Value::String(super::SHIM_PLACEHOLDER.into())]));
        // So the shim can import the package exactly as Hermes does (`from . import x`
        // and sibling modules resolve against the plugin directory).
        t.insert("cwd".into(), root.display().to_string().into());
        if !requires_env.is_empty() {
            t.insert("env".into(), toml::Value::Table(secret_env(&requires_env)));
        }
        warnings.push(format!("runtime: the shim loads the package from {} (the fragment sets `cwd` there); moving or deleting that directory ends the import. The code still runs inside its own Python process — Hermes-only imports (`hermes_cli.*`, `tools.*`, the agent) fail at load time, and such a plugin is then served as an empty plugin (no hooks, no tools) with the error on stderr; the agent is never blocked.", root.display()));
        ("python", Some(fragment(&id, t)?), Some(Shim { file: "hermes_shim.py".into(), contents }))
    } else {
        warnings.push("no `__init__.py`: imported as a declaration only; nothing is started.".into());
        ("declarative", None, None)
    };

    Ok(Imported {
        id,
        name,
        idiom: "hermes".into(),
        description: s(&v, "description").to_string(),
        kind: kind.into(),
        config_toml,
        secrets: requires_env,
        skills,
        mcp_servers: vec![],
        capabilities,
        warnings,
        shim,
    })
}

/// `optional-mcps/<name>/manifest.yaml` → `[mcp.<name>]`.
pub fn optional_mcp(manifest: &Path) -> Result<toml::Table, String> {
    let path = manifest.canonicalize().map_err(|e| format!("{}: {e}", manifest.display()))?;
    let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let v = yaml::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let name = if s(&v, "name").is_empty() {
        path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("").to_string()
    } else {
        s(&v, "name").to_string()
    };
    table_of(&v, &name)
}

fn table_of(v: &Value, name: &str) -> Result<toml::Table, String> {
    if !v.is_object() {
        return Err("manifest is not a mapping".into());
    }
    let ttype = v.get("transport").map(|t| s(t, "type")).unwrap_or_default();
    let mut t = toml::Table::new();
    match ttype {
        "http" | "streamable-http" | "sse" | "" => {
            let url = s(v.get("transport").unwrap_or(&Value::Null), "url");
            if url.is_empty() {
                return Err(format!("`{name}`: transport {ttype:?} has no url"));
            }
            if let Some(var) = url.strip_prefix("${").and_then(|u| u.strip_suffix('}')) {
                // The URL is only known at install time (n8n's instance URL): seagent reads a
                // literal url, so say what to do instead of writing an entry that cannot connect.
                return Err(format!("`{name}`: url `${var}` must be replaced with a real URL before import (set {var}, then `seagent mcp add {name} <url>`)"));
            }
            t.insert("url".into(), url.into());
            if ttype == "sse" {
                t.insert("transport".into(), "sse".into());
            }
        }
        "stdio" => {
            let tr = v.get("transport").unwrap_or(&Value::Null);
            let cmd = s(tr, "command");
            if cmd.is_empty() {
                return Err(format!("`{name}`: stdio transport has no command"));
            }
            t.insert("command".into(), cmd.into());
            let args = strings(tr.get("args"));
            if !args.is_empty() {
                t.insert("args".into(), toml::Value::Array(args.into_iter().map(toml::Value::String).collect()));
            }
            let env = tr.get("env").and_then(Value::as_object);
            if let Some(env) = env {
                let mut et = toml::Table::new();
                for (k, v) in env {
                    et.insert(k.clone(), super::openclaw::secret_ref(v.as_str().unwrap_or("")).into());
                }
                t.insert("env".into(), toml::Value::Table(et));
            }
        }
        other => return Err(format!("`{name}`: unsupported transport `{other}`")),
    }
    if s(v.get("auth").unwrap_or(&Value::Null), "type") == "oauth" {
        t.insert("auth".into(), "oauth".into());
        let o = v.get("auth").and_then(|a| a.get("oauth"));
        if let Some(o) = o.filter(|o| o.is_object()) {
            let mut ot = toml::Table::new();
            if let Some(cid) = o.get("client_id").and_then(Value::as_str).filter(|x| !x.is_empty()) {
                ot.insert("client_id".into(), super::openclaw::secret_ref(cid).into());
            }
            if let Some(sec) = o.get("client_secret").and_then(Value::as_str).filter(|x| !x.is_empty()) {
                ot.insert("client_secret".into(), super::openclaw::secret_ref(sec).into());
            }
            if let Some(p) = o.get("redirect_port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok()) {
                ot.insert("redirect_port".into(), i64::from(p).into());
            }
            let scopes = strings(o.get("scopes"));
            if !scopes.is_empty() {
                ot.insert("scopes".into(), toml::Value::Array(scopes.into_iter().map(toml::Value::String).collect()));
            }
            if !ot.is_empty() {
                t.insert("oauth".into(), toml::Value::Table(ot));
            }
        }
    }
    // `headers:` (a mapping) — values may be `${VAR}` references.
    if let Some(h) = v.get("headers").and_then(Value::as_object) {
        let mut ht = toml::Table::new();
        for (k, val) in h {
            ht.insert(k.clone(), super::openclaw::secret_ref(val.as_str().unwrap_or("")).into());
        }
        if !ht.is_empty() {
            t.insert("headers".into(), toml::Value::Table(ht));
        }
    }
    // `tools.default_excluded` → `exclude_tools`.
    let excluded = strings(v.get("tools").and_then(|t| t.get("default_excluded")));
    if !excluded.is_empty() {
        t.insert("exclude_tools".into(), toml::Value::Array(excluded.into_iter().map(toml::Value::String).collect()));
    }
    Ok(t)
}

/// The prose fields of a manifest: `source` (where the server comes from) and
/// `post_install` (what the user must still do, e.g. `seagent mcp login`).
pub fn optional_mcp_notes(manifest: &Path) -> Result<Vec<String>, String> {
    let path = manifest.canonicalize().map_err(|e| format!("{}: {e}", manifest.display()))?;
    let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let v = yaml::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = Vec::new();
    let src = s(&v, "source");
    if !src.is_empty() {
        out.push(format!("source: {src}"));
    }
    let post = s(&v, "post_install").replace("hermes mcp login", "seagent mcp login").replace("Hermes", "seagent");
    if !post.trim().is_empty() {
        out.push(post.trim().to_string());
    }
    if let Some(env) = v.get("auth").and_then(|a| a.get("env")).and_then(Value::as_array) {
        for e in env {
            let n = s(e, "name");
            if !n.is_empty() {
                out.push(format!("auth env: {n}{} — {{{{{{secret:{n}}}}}}}", if s(e, "prompt").is_empty() { String::new() } else { format!(" ({})", s(e, "prompt")) }));
            }
        }
    }
    Ok(out)
}

/// A `manifest.yaml` directory as an [`Imported`] (no process: MCP servers are
/// started by seagent's MCP client, not by a shim).
fn mcp_entry(root: &Path) -> Result<Imported, String> {
    let man = root.join("manifest.yaml");
    let text = fs::read_to_string(&man).map_err(|e| format!("{}: {e}", man.display()))?;
    let v = yaml::parse(&text).map_err(|e| format!("{}: {e}", man.display()))?;
    let name = sanitize_id(if s(&v, "name").is_empty() { root.file_name().and_then(|n| n.to_str()).unwrap_or("") } else { s(&v, "name") });
    if name.is_empty() {
        return Err(format!("{}: no usable `name`", man.display()));
    }
    let table = table_of(&v, &name)?;
    let mut warnings = optional_mcp_notes(&man).unwrap_or_default();
    if table.get("auth").and_then(|a| a.as_str()) == Some("oauth") {
        warnings.push(format!("OAuth: run `seagent mcp login {name}` once; tokens live in the data dir, not in config."));
    }
    let url = table.get("url").and_then(|u| u.as_str()).unwrap_or("");
    if url.starts_with("http://") && !url.starts_with("http://127.0.0.1") && !url.starts_with("http://localhost") {
        warnings.push(format!("url `{url}` is plain http: credentials and tool traffic are not encrypted, and OAuth discovery usually refuses it — prefer https."));
    }
    let mut capabilities = Vec::new();
    let tt = s(v.get("transport").unwrap_or(&Value::Null), "type");
    if !tt.is_empty() {
        capabilities.push(format!("transport: {tt}"));
    }
    let secrets: Vec<String> = v.get("auth").and_then(|a| a.get("env")).and_then(Value::as_array).into_iter().flatten().filter_map(|e| e.get("name").and_then(Value::as_str).map(String::from)).collect();
    if !secrets.is_empty() {
        capabilities.push(format!("auth env: {}", secrets.join(", ")));
    }
    Ok(Imported {
        id: name.clone(),
        name,
        idiom: "hermes".into(),
        description: s(&v, "description").to_string(),
        kind: "declarative".into(),
        config_toml: None,
        secrets,
        skills: vec![],
        mcp_servers: vec![(name_or_dir(&v, root), table)],
        capabilities,
        warnings,
        shim: None,
    })
}

fn name_or_dir(v: &Value, root: &Path) -> String {
    sanitize_id(if s(v, "name").is_empty() { root.file_name().and_then(|n| n.to_str()).unwrap_or("") } else { s(v, "name") })
}

/// A small YAML reader for the Hermes manifests: block mappings and sequences,
/// plain/quoted scalars, one-line (or bracket-continued) flow `[..]` / `{..}`,
/// `|` / `>` block scalars with chomping, comments. No anchors, tags or multi-doc.
/// `seagent-skills` has the full reader, but it depends on this crate, not the other
/// way round — this is the subset the catalogs use, checked against all of them.
pub(crate) mod yaml {
    use serde_json::{Map, Number, Value};

    struct Line<'a> {
        indent: usize,
        text: &'a str,
        no: usize,
    }

    pub fn parse(src: &str) -> Result<Value, String> {
        let src = src.strip_prefix('\u{feff}').unwrap_or(src);
        let raw: Vec<&str> = src.lines().collect();
        let mut p = Parser { raw, pos: 0 };
        let v = p.block(0)?;
        if let Some(l) = p.peek() {
            return Err(format!("line {}: unexpected content `{}`", l.no, l.text));
        }
        Ok(v)
    }

    /// Strip a trailing ` # comment` outside quotes.
    fn strip_comment(s: &str) -> &str {
        let (mut sq, mut dq) = (false, false);
        let b = s.as_bytes();
        for i in 0..b.len() {
            match b[i] {
                b'\'' if !dq => sq = !sq,
                b'"' if !sq => dq = !dq,
                b'#' if !sq && !dq && (i == 0 || b[i - 1].is_ascii_whitespace()) => return s[..i].trim_end(),
                _ => {}
            }
        }
        s
    }

    struct Parser<'a> {
        raw: Vec<&'a str>,
        pos: usize,
    }

    impl<'a> Parser<'a> {
        /// Next content line (comments, blanks and document markers skipped).
        fn peek(&mut self) -> Option<Line<'a>> {
            loop {
                let line = *self.raw.get(self.pos)?;
                let trimmed = line.trim_end();
                let indent = trimmed.len() - trimmed.trim_start().len();
                let text = strip_comment(&trimmed[indent..]).trim_end();
                if text.is_empty() || text == "---" || text == "..." {
                    self.pos += 1;
                    continue;
                }
                return Some(Line { indent, text, no: self.pos + 1 });
            }
        }

        fn block(&mut self, min: usize) -> Result<Value, String> {
            let Some(first) = self.peek() else { return Ok(Value::Null) };
            if first.indent < min {
                return Ok(Value::Null);
            }
            if first.text == "-" || first.text.starts_with("- ") {
                self.seq(first.indent)
            } else if split_key(first.text).is_some() {
                self.map(first.indent)
            } else {
                // A bare scalar (rare; flow collections are handled in `value`).
                self.pos += 1;
                self.scalar(first.text, first.no)
            }
        }

        fn map(&mut self, indent: usize) -> Result<Value, String> {
            let mut m = Map::new();
            while let Some(l) = self.peek() {
                if l.indent < indent {
                    break;
                }
                if l.indent > indent {
                    return Err(format!("line {}: unexpected indentation", l.no));
                }
                if l.text == "-" || l.text.starts_with("- ") {
                    break;
                }
                let Some((k, rest)) = split_key(l.text) else { break };
                self.pos += 1;
                let v = self.value(rest, indent, l.no)?;
                m.insert(k, v);
            }
            Ok(Value::Object(m))
        }

        fn seq(&mut self, indent: usize) -> Result<Value, String> {
            let mut a = Vec::new();
            while let Some(l) = self.peek() {
                if l.indent != indent || !(l.text == "-" || l.text.starts_with("- ")) {
                    break;
                }
                let rest = l.text.strip_prefix("- ").unwrap_or("").trim();
                self.pos += 1;
                if rest.is_empty() {
                    a.push(self.block(indent + 1)?);
                    continue;
                }
                match split_key(rest) {
                    // `- key: v` starts a mapping whose other keys sit deeper.
                    Some((k, r)) => {
                        let mut m = Map::new();
                        let v = self.value(r, indent + 1, l.no)?;
                        m.insert(k, v);
                        if let Some(n) = self.peek().filter(|n| n.indent > indent) {
                            let child = n.indent;
                            while let Some(n) = self.peek().filter(|n| n.indent == child) {
                                let Some((k2, r2)) = split_key(n.text) else { break };
                                self.pos += 1;
                                let v2 = self.value(r2, child, n.no)?;
                                m.insert(k2, v2);
                            }
                        }
                        a.push(Value::Object(m));
                    }
                    None => a.push(self.scalar(rest, l.no)?),
                }
            }
            Ok(Value::Array(a))
        }

        /// `rest` is what followed `key:` (empty for a nested block).
        fn value(&mut self, rest: &str, indent: usize, no: usize) -> Result<Value, String> {
            if rest.is_empty() {
                return match self.peek() {
                    Some(n) if n.indent > indent => self.block(indent + 1),
                    Some(n) if n.indent == indent && (n.text == "-" || n.text.starts_with("- ")) => self.seq(indent),
                    _ => Ok(Value::Null),
                };
            }
            if let Some((fold, chomp)) = block_header(rest) {
                return Ok(Value::String(self.block_scalar(fold, chomp, indent)));
            }
            if rest.starts_with('[') || rest.starts_with('{') {
                let mut text = rest.to_string();
                while !balanced(&text) {
                    let Some(next) = self.raw.get(self.pos) else { break };
                    text.push(' ');
                    text.push_str(next.trim());
                    self.pos += 1;
                }
                let cs: Vec<char> = text.chars().collect();
                let mut i = 0;
                let v = flow_value(&cs, &mut i)?;
                return Ok(v);
            }
            self.scalar(rest, no)
        }

        fn block_scalar(&mut self, fold: bool, chomp: char, parent: usize) -> String {
            let mut lines: Vec<(usize, &str)> = Vec::new();
            while self.pos < self.raw.len() {
                let line = self.raw[self.pos];
                let trimmed = line.trim_end();
                if trimmed.trim().is_empty() {
                    lines.push((usize::MAX, ""));
                    self.pos += 1;
                    continue;
                }
                let ind = trimmed.len() - trimmed.trim_start().len();
                if ind <= parent {
                    break;
                }
                lines.push((ind, &trimmed[ind..]));
                self.pos += 1;
            }
            // Drop trailing blank lines (chomping is applied below).
            while matches!(lines.last(), Some((usize::MAX, _))) {
                lines.pop();
            }
            let base = lines.iter().filter(|(i, _)| *i != usize::MAX).map(|(i, _)| *i).min().unwrap_or(parent + 1);
            let mut out = String::new();
            let mut blank = 0usize;
            for (ind, text) in &lines {
                if *ind == usize::MAX {
                    blank += 1;
                    continue;
                }
                let text = &text[ind.saturating_sub(base).min(text.len())..];
                if !out.is_empty() {
                    if fold {
                        out.push_str(if blank > 0 { "\n" } else { " " });
                    } else {
                        out.push('\n');
                    }
                    for _ in 0..blank.saturating_sub(if fold { 1 } else { 0 }) {
                        out.push('\n');
                    }
                }
                blank = 0;
                out.push_str(text);
            }
            // Trailing blank lines are dropped for every chomping mode; `|+`
            // (keep them all) does not occur in any manifest we import.
            let _ = chomp;
            if chomp == '-' || out.is_empty() {
                out
            } else {
                out + "\n"
            }
        }

        fn scalar(&self, text: &str, no: usize) -> Result<Value, String> {
            scalar(text, no)
        }
    }

    /// `|`, `|-`, `|+`, `>`, `>-`, `>+` → (folded, chomping char).
    fn block_header(v: &str) -> Option<(bool, char)> {
        let mut cs = v.chars();
        let fold = match cs.next()? {
            '|' => false,
            '>' => true,
            _ => return None,
        };
        let rest: String = cs.collect();
        let chomp = match rest.as_str() {
            "" => ' ',
            "-" => '-',
            "+" => '+',
            _ => return None,
        };
        Some((fold, chomp))
    }

    /// Split `key: value` (or `key:`), respecting quoted keys.
    fn split_key(text: &str) -> Option<(String, &str)> {
        let b = text.as_bytes();
        let mut i = 0;
        let (mut sq, mut dq) = (false, false);
        while i < b.len() {
            match b[i] {
                b'\'' if !dq => sq = !sq,
                b'"' if !sq => dq = !dq,
                // `key:` — a colon ends the key only at the end of the line or before a space.
                b':' if !sq && !dq && (i + 1 == b.len() || b[i + 1] == b' ' || b[i + 1] == b'\t') => {
                    let key = unquote(text[..i].trim());
                    if key.is_empty() {
                        return None;
                    }
                    return Some((key, text[i + 1..].trim()));
                }
                _ => {}
            }
            i += 1;
        }
        None
    }

    fn unquote(s: &str) -> String {
        if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
            return unescape(&s[1..s.len() - 1]);
        }
        if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
            return s[1..s.len() - 1].replace("''", "'");
        }
        s.to_string()
    }

    fn unescape(s: &str) -> String {
        let mut out = String::new();
        let mut cs = s.chars();
        while let Some(c) = cs.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match cs.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('u') => {
                    let hex: String = cs.by_ref().take(4).collect();
                    match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                        Some(c) => out.push(c),
                        None => out.push_str(&hex),
                    }
                }
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        }
        out
    }

    fn scalar(text: &str, no: usize) -> Result<Value, String> {
        let t = text.trim();
        if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
            return Ok(Value::String(unescape(&t[1..t.len() - 1])));
        }
        if t.len() >= 2 && t.starts_with('\'') && t.ends_with('\'') {
            return Ok(Value::String(t[1..t.len() - 1].replace("''", "'")));
        }
        if t.starts_with('[') || t.starts_with('{') {
            let cs: Vec<char> = t.chars().collect();
            let mut i = 0;
            return flow_value(&cs, &mut i);
        }
        Ok(match t {
            "null" | "~" | "Null" | "NULL" | "" => Value::Null,
            "true" | "True" | "TRUE" | "yes" => Value::Bool(true),
            "false" | "False" | "FALSE" | "no" => Value::Bool(false),
            _ => match t.parse::<i64>() {
                Ok(n) => Value::Number(Number::from(n)),
                Err(_) => match t.parse::<f64>() {
                    Ok(f) if f.is_finite() => Number::from_f64(f).map(Value::Number).unwrap_or_else(|| Value::String(t.to_string())),
                    _ => {
                        if t.starts_with('*') || t.starts_with('&') {
                            return Err(format!("line {no}: anchors/aliases are not supported"));
                        }
                        Value::String(t.to_string())
                    }
                },
            },
        })
    }

    fn balanced(s: &str) -> bool {
        let (mut depth, mut sq, mut dq) = (0i32, false, false);
        for c in s.chars() {
            match c {
                '\'' if !dq => sq = !sq,
                '"' if !sq => dq = !dq,
                '[' | '{' if !sq && !dq => depth += 1,
                ']' | '}' if !sq && !dq => depth -= 1,
                _ => {}
            }
        }
        depth <= 0
    }

    fn skip_ws(cs: &[char], i: &mut usize) {
        while *i < cs.len() && (cs[*i].is_whitespace() || cs[*i] == ',') {
            *i += 1;
        }
    }

    fn flow_value(cs: &[char], i: &mut usize) -> Result<Value, String> {
        skip_ws(cs, i);
        match cs.get(*i) {
            Some('[') => {
                *i += 1;
                let mut a = Vec::new();
                loop {
                    skip_ws(cs, i);
                    match cs.get(*i) {
                        Some(']') => {
                            *i += 1;
                            return Ok(Value::Array(a));
                        }
                        None => return Err("unterminated `[`".into()),
                        _ => a.push(flow_value(cs, i)?),
                    }
                }
            }
            Some('{') => {
                *i += 1;
                let mut m = Map::new();
                loop {
                    skip_ws(cs, i);
                    match cs.get(*i) {
                        Some('}') => {
                            *i += 1;
                            return Ok(Value::Object(m));
                        }
                        None => return Err("unterminated `{`".into()),
                        _ => {}
                    }
                    let k = match flow_value(cs, i)? {
                        Value::String(s) => s,
                        other => other.to_string(),
                    };
                    skip_ws(cs, i);
                    if cs.get(*i) == Some(&':') {
                        *i += 1;
                    }
                    let v = flow_value(cs, i)?;
                    m.insert(k, v);
                }
            }
            Some('"') => {
                let mut j = *i + 1;
                let start = j;
                while j < cs.len() && cs[j] != '"' {
                    if cs[j] == '\\' {
                        j += 1;
                    }
                    j += 1;
                }
                let raw: String = cs[start..j.min(cs.len())].iter().collect();
                *i = (j + 1).min(cs.len());
                Ok(Value::String(unescape(&raw)))
            }
            Some('\'') => {
                let mut j = *i + 1;
                let mut raw = String::new();
                while j < cs.len() {
                    if cs[j] == '\'' {
                        if cs.get(j + 1) == Some(&'\'') {
                            raw.push('\'');
                            j += 2;
                            continue;
                        }
                        break;
                    }
                    raw.push(cs[j]);
                    j += 1;
                }
                *i = (j + 1).min(cs.len());
                Ok(Value::String(raw))
            }
            _ => {
                let start = *i;
                while *i < cs.len() && !matches!(cs[*i], ',' | ']' | '}' | ':') {
                    *i += 1;
                }
                let raw: String = cs[start..*i].iter().collect();
                scalar(raw.trim(), 0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::SHIM_PLACEHOLDER;
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/compat").join(name)
    }

    #[test]
    fn compat_hermes_python_plugin_declares_hooks_tools_and_a_shim() {
        let imp = import(&fixture("hermes-python")).unwrap();
        assert_eq!(imp.id, "guard-demo");
        assert_eq!(imp.kind, "python");
        assert_eq!(imp.idiom, "hermes");
        let shim = imp.shim.as_ref().unwrap();
        assert_eq!(shim.file, "hermes_shim.py");
        assert!(!shim.contents.contains("__HOOKS__") && !shim.contents.contains("__PLUGIN_DIR__"), "placeholders are substituted");
        assert!(shim.contents.contains("[\"pre_tool\",[\"pre_tool_call\",\"pre_tool\"]]"), "Hermes hook names map to seagent events");
        assert!(shim.contents.contains("guard_demo_check"), "declared tools are baked in");
        let cfg = imp.config_toml.as_ref().unwrap();
        assert!(cfg.starts_with("[plugins.guard-demo]"), "{cfg}");
        assert!(cfg.contains("command = \"python3\"") && cfg.contains(SHIM_PLACEHOLDER), "{cfg}");
        assert!(cfg.contains("GUARD_DEMO_KEY = \"{{secret:GUARD_DEMO_KEY}}\""), "{cfg}");
        assert_eq!(imp.secrets, vec!["GUARD_DEMO_KEY"]);
        assert!(imp.warnings.iter().any(|w| w.contains("hermes_cli")), "{:?}", imp.warnings);
        assert!(imp.warnings.iter().any(|w| w.contains("experiment_hook") && w.contains("no seagent hook event matches")), "an unknown hook is reported, not mapped to something invented: {:?}", imp.warnings);
        assert!(imp.capabilities.iter().any(|c| c == "tool: guard_demo_check"), "{:?}", imp.capabilities);
        assert!(imp.skills.len() == 1, "the plugin's own SKILL.md is imported: {:?}", imp.skills);
    }

    #[test]
    fn compat_hermes_model_provider_is_flagged_as_unusable() {
        let imp = import(&fixture("hermes-provider")).unwrap();
        assert_eq!(imp.kind, "python", "an __init__.py is present, so a shim is written");
        assert!(imp.capabilities.iter().any(|c| c == "kind: model-provider"), "{:?}", imp.capabilities);
        assert!(imp.warnings.iter().any(|w| w.contains("model-provider") && w.contains("seagent/provider.complete")), "{:?}", imp.warnings);
    }

    #[test]
    fn compat_hermes_hook_only_plugin_maps_every_hook() {
        let imp = import(&fixture("hermes-hooks-only")).unwrap();
        assert_eq!(imp.kind, "declarative");
        assert!(imp.shim.is_none() && imp.config_toml.is_none());
        for c in [
            "hook: pre_tool_call → seagent `pre_tool`",
            "hook: post_tool_call → seagent `post_tool`",
            "hook: on_session_end → seagent `session_end`",
        ] {
            assert!(imp.capabilities.iter().any(|x| x == c), "missing {c}: {:?}", imp.capabilities);
        }
        assert!(imp.warnings.iter().any(|w| w.contains("no `__init__.py`")), "{:?}", imp.warnings);
        assert!(!imp.warnings.iter().any(|w| w.contains("no seagent hook event matches")), "every declared hook maps: {:?}", imp.warnings);
    }

    #[test]
    fn compat_yaml_subset_reads_the_catalog_shapes() {
        // block scalars, flow collections, quoted keys, nested sequences of mappings.
        let v = yaml::parse("a: >-\n  one\n  two\nb: |\n  x\n  y\nc: [1, 'two', {k: v}]\nd:\n  - name: n1\n    secret: false\n  - name: n2\n# c\ne: \"q # not a comment\"\n").unwrap();
        assert_eq!(v["a"], "one two");
        assert_eq!(v["b"], "x\ny\n");
        assert_eq!(v["c"][1], "two");
        assert_eq!(v["c"][2]["k"], "v");
        assert_eq!(v["d"][1]["name"], "n2");
        assert_eq!(v["e"], "q # not a comment");
        assert!(yaml::parse("a: *anchor\n").is_err());
        assert!(yaml::parse("a: [1, 2\n").is_err());
    }

    #[test]
    fn compat_hermes_optional_mcp_oauth_becomes_an_mcp_table() {
        let t = optional_mcp(&fixture("hermes-mcp-oauth/manifest.yaml")).unwrap();
        assert_eq!(t["url"].as_str(), Some("https://mcp.example.com/v2/mcp"));
        assert_eq!(t["auth"].as_str(), Some("oauth"));
        assert_eq!(t["exclude_tools"].as_array().map(|a| a.len()), Some(2));
        assert_eq!(t["oauth"]["client_id"].as_str(), Some("{{secret:DEMO_CLIENT_ID}}"));
        assert_eq!(t["oauth"]["client_secret"].as_str(), Some("{{secret:DEMO_CLIENT_SECRET}}"));
        assert_eq!(t["oauth"]["redirect_port"].as_integer(), Some(27890));
        // It parses as the config seagent actually reads, and validates.
        let parsed: crate::McpServerConfig = toml::Value::Table(t).try_into().unwrap();
        parsed.validate("demo-oauth").unwrap();
        let notes = optional_mcp_notes(&fixture("hermes-mcp-oauth/manifest.yaml")).unwrap();
        assert!(notes.iter().any(|n| n.starts_with("source: https://")), "{notes:?}");
        assert!(notes.iter().any(|n| n.contains("seagent mcp login demo-oauth")), "{notes:?}");
        assert!(notes.iter().any(|n| n.contains("DEMO_CLIENT_ID")), "{notes:?}");
    }

    #[test]
    fn compat_hermes_optional_mcp_stdio_becomes_a_command() {
        let t = optional_mcp(&fixture("hermes-mcp-stdio/manifest.yaml")).unwrap();
        assert_eq!(t["command"].as_str(), Some("npx"));
        assert_eq!(t["args"].as_array().map(|a| a.len()), Some(3));
        assert_eq!(t["env"]["DEMO_TOKEN"].as_str(), Some("{{secret:DEMO_TOKEN}}"));
        assert!(!t.contains_key("auth"));
        let parsed: crate::McpServerConfig = toml::Value::Table(t).try_into().unwrap();
        parsed.validate("demo-stdio").unwrap();
    }

    #[test]
    fn compat_hermes_import_of_a_manifest_dir_is_an_mcp_entry() {
        let imp = import(&fixture("hermes-mcp-oauth")).unwrap();
        assert_eq!(imp.idiom, "hermes");
        assert_eq!(imp.kind, "declarative");
        assert!(imp.shim.is_none());
        assert_eq!(imp.mcp_servers.len(), 1);
        assert_eq!(imp.mcp_servers[0].0, "demo-oauth");
        assert!(imp.warnings.iter().any(|w| w.contains("seagent mcp login demo-oauth")), "{:?}", imp.warnings);
    }

    #[test]
    fn compat_hermes_never_panics_on_broken_input() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-compat-hm-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        for body in ["", "- a\n- b\n", "name: [unclosed\n", "a: *anchor\n", "transport: 3\n", "a:\n  - x\n b: y\n"] {
            fs::write(d.join("plugin.yaml"), body).unwrap();
            let _ = import(&d);
            fs::write(d.join("manifest.yaml"), body).unwrap();
            let _ = import(&d);
            let _ = fs::remove_dir_all(d.join("plugin.yaml"));
        }
        let _ = fs::remove_dir_all(&d);
    }
}
