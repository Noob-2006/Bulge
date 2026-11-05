//! `ark mcp …`: the connector surface — list/test/refresh MCP servers, the model's
//! `mcp__*` tools, OAuth login/logout, presets and the config writers (`add`/`rm`/`enable`).
//!
//! Split out of `main.rs` (audit D3: a file may not grow past 3000 lines); the command
//! family is dispatched from `main.rs`'s match like every other one, and its flags are its
//! own.

use super::*;

pub fn cmd_mcp(a: &Args) -> R {
    let paths = Paths::from_env();
    match a.pos(0).unwrap_or("list") {
        "list" | "ls" => {
            let ws = workspace(a)?;
            let cfg = load_config(a, &ws, &paths)?;
            let vault = load_vault(&paths)?;
            let (cfgs, warn) = ext::mcp_configs(&cfg);
            let reg = ark_plugin::Registry::load(&cfgs, &paths.data.join("mcp-cache"), ext::secrets_fn(&vault));
            if cfgs.is_empty() && warn.is_empty() {
                println!("no MCP servers (add one with `ark mcp add <name> -- <command> args…` or `--url`)");
            }
            for (name, n, running) in reg.status() {
                let c = &cfgs[&name];
                let what = c.url.clone().unwrap_or_else(|| format!("{} {}", c.command.as_deref().unwrap_or(""), c.args.join(" ")));
                println!("{name:<16} {:<8} {n:>3} tools  {}  {}", if !c.enabled { "disabled" } else if running { "running" } else { "lazy" }, if c.url.is_some() { "http " } else { "stdio" }, term::one_line(&what, 60));
            }
            for w in warn.iter().chain(reg.warnings()) {
                println!("! {w}");
            }
            Ok(0)
        }
        "tools" => {
            let c = build_agent(a, approver_for(a, false), false)?;
            let only = a.pos(1);
            for t in &c.k.tools {
                let s = t.spec();
                if let Some(rest) = s.name.strip_prefix("mcp__") {
                    if only.is_none_or(|o| rest.starts_with(&format!("{o}__"))) {
                        println!("{:<40} {}", s.name, term::one_line(s.summary(), 80));
                    }
                }
            }
            Ok(0)
        }
        "test" | "refresh" => {
            let name = a.need(1, "server")?;
            let ws = workspace(a)?;
            let cfg = load_config(a, &ws, &paths)?;
            let vault = load_vault(&paths)?;
            let (cfgs, _) = ext::mcp_configs(&cfg);
            if !cfgs.contains_key(name) {
                return Err(format!("no MCP server `{name}` (see `ark mcp list`)").into());
            }
            let mut reg = ark_plugin::Registry::load(&BTreeMap::from([(name.to_string(), cfgs[name].clone())]), &paths.data.join("mcp-cache"), ext::secrets_fn(&vault));
            let t = Instant::now();
            match reg.refresh(name) {
                Ok(n) => {
                    println!("{name}: ok in {:.1}s · {n} tools", t.elapsed().as_secs_f32());
                    Ok(0)
                }
                Err(e) => Err(format!("{name}: {e}").into()),
            }
        }
        "login" => {
            let name = a.need(1, "server")?;
            let ws = workspace(a)?;
            let cfg = load_config(a, &ws, &paths)?;
            let (cfgs, _) = ext::mcp_configs(&cfg);
            let c = cfgs.get(name).ok_or_else(|| format!("no MCP server `{name}` in config"))?;
            let url = c.url.as_deref().ok_or("OAuth applies to HTTP servers (`url`), not stdio")?;
            if !c.uses_oauth() {
                eprintln!("note: [mcp.{name}] has no `auth = \"oauth\"`; tokens are saved but not used until you add it");
            }
            struct Show(bool);
            impl ark_plugin::oauth::Prompter for Show {
                fn open(&self, url: &str) {
                    println!("在瀏覽器開啟以下網址完成授權：\n\n  {url}\n");
                    if self.0 {
                        let _ = std::process::Command::new("xdg-open").arg(url).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
                    }
                }
                fn device(&self, uri: &str, code: &str, complete: Option<&str>) {
                    println!("請到 {uri} 輸入代碼：{code}");
                    if let Some(c) = complete {
                        println!("（或直接開啟 {c}）");
                    }
                }
            }
            let challenge = ark_plugin::oauth::probe_challenge(url);
            let wait = Duration::from_secs(600);
            let t = if a.flag("device") {
                ark_plugin::oauth::login_device(url, challenge.as_deref(), &c.oauth, &Show(false), wait)
            } else {
                ark_plugin::oauth::login_browser(url, challenge.as_deref(), &c.oauth, &Show(!a.flag("no-browser")), wait)
            }
            .map_err(|e| format!("{name}: login failed: {e}"))?;
            let store = ark_plugin::oauth::Store::new(&paths.data, name);
            store.save(t)?;
            println!("{name}: 已登入，token 存在 {}", store.path().display());
            Ok(0)
        }
        "logout" => {
            let name = a.need(1, "server")?;
            let store = ark_plugin::oauth::Store::new(&paths.data, name);
            let had = store.has_tokens();
            store.clear();
            println!("{name}: {}", if had { "已登出（token 已刪除）" } else { "原本就沒有登入" });
            Ok(0)
        }
        "presets" | "catalog" => {
            if a.pos(1) == Some("show") {
                let n = a.need(2, "preset")?;
                let p = mcp_presets::get(n).ok_or_else(|| format!("no preset `{n}` (see `ark mcp presets`)"))?;
                println!("{} — {}
url: {}
auth: {}
source: {}", p.name, p.description, p.url, p.auth, p.source);
                for e in &p.env {
                    println!("env: {} ({}){}", e.name, e.prompt, if e.secret { " — secret: `ark secrets set` it" } else { " — pass --env" });
                }
                if !p.post_install.is_empty() {
                    println!("
{}", mcp_presets::notes(p));
                }
                return Ok(0);
            }
            let list = match a.pos(1) {
                Some(q) => mcp_presets::search(q),
                None => mcp_presets::catalog().iter().collect(),
            };
            if list.is_empty() {
                println!("no presets match");
            }
            for p in list {
                println!("{:<18} {:<6} {}", p.name, p.auth, term::one_line(&p.description, 80));
            }
            Ok(0)
        }
        "add" => {
            let name = a.need(1, "name")?;
            if !valid_ext_name(name) {
                return usage("name: letters, digits, _ and - only");
            }
            let preset = match a.val("preset") {
                Some(pn) => Some(mcp_presets::get(pn).ok_or_else(|| format!("no preset `{pn}` (see `ark mcp presets`)"))?),
                None => None,
            };
            let user = paths.user_config();
            let text = std::fs::read_to_string(&user).unwrap_or_default();
            if text.lines().any(|l| l.trim() == format!("[mcp.{name}]")) {
                return Err(format!("[mcp.{name}] already exists in {}", user.display()).into());
            }
            let mut block = format!("\n[mcp.{name}]\n");
            if let Some(p) = preset {
                let mut vals = BTreeMap::new();
                for kv in a.vals("env") {
                    let (k, v) = kv.split_once('=').ok_or("--env expects NAME=value")?;
                    if p.env.iter().any(|e| e.name == k.trim() && e.secret) {
                        return Err(format!("{k} is a secret: store it with `ark secrets set {k}`, never on the command line").into());
                    }
                    vals.insert(k.trim().to_string(), v.trim().to_string());
                }
                block = mcp_presets::config_block(name, p, &vals)?;
            } else if let Some(u) = a.val("url") {
                block.push_str(&format!("url = {}\n", toml_str(u)));
                let hs = a.vals("header");
                if !hs.is_empty() {
                    let mut ht = toml::Table::new();
                    for h in hs {
                        let (k, v) = h.split_once('=').ok_or("--header expects Name=value (use {{secret:NAME}} for tokens)")?;
                        ht.insert(k.trim().into(), toml::Value::String(v.trim().into()));
                    }
                    block.push_str(&format!("headers = {}\n", toml::Value::Table(ht)));
                }
            } else {
                let cmd = a.pos(2).ok_or(Fail::Usage("give `--url URL` or `-- <command> args…`".into()))?;
                block.push_str(&format!("command = {}\n", toml_str(cmd)));
                let args: Vec<toml::Value> = a.pos.iter().skip(3).map(|s| toml::Value::String(s.clone())).collect();
                if !args.is_empty() {
                    block.push_str(&format!("args = {}\n", toml::Value::Array(args)));
                }
            }
            // Validate before writing.
            let t: toml::Table = block.parse().map_err(|e| format!("{e}"))?;
            let c: ark_plugin::McpServerConfig = toml::Value::Table(t["mcp"][name].as_table().cloned().unwrap_or_default()).try_into().map_err(|e: toml::de::Error| e.message().to_string())?;
            c.validate(name)?;
            if let Some(d) = user.parent() {
                std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
            }
            std::fs::write(&user, format!("{}{block}", text)).map_err(|e| e.to_string())?;
            println!("added [mcp.{name}] to {} — check it with `ark mcp test {name}`", user.display());
            if let Some(p) = preset {
                for e in p.env.iter().filter(|e| e.secret) {
                    println!("store {} with `ark secrets set {}`", e.name, e.name);
                }
                if p.auth == "oauth" {
                    println!("then sign in with `ark mcp login {name}`");
                }
                if !p.post_install.is_empty() {
                    println!("\n{}", mcp_presets::notes(p));
                }
            }
            Ok(0)
        }
        "rm" | "remove" => {
            let name = a.need(1, "name")?;
            let user = paths.user_config();
            let text = std::fs::read_to_string(&user).map_err(|e| e.to_string())?;
            let header = format!("[mcp.{name}]");
            let mut out = Vec::new();
            let mut skipping = false;
            let mut found = false;
            for l in text.lines() {
                let t = l.trim();
                if t.starts_with('[') {
                    skipping = t == header || t.starts_with(&format!("[mcp.{name}."));
                    found |= skipping;
                }
                if !skipping {
                    out.push(l);
                }
            }
            if !found {
                return Err(format!("no [mcp.{name}] in {}", user.display()).into());
            }
            std::fs::write(&user, out.join("\n") + "\n").map_err(|e| e.to_string())?;
            println!("removed [mcp.{name}]");
            Ok(0)
        }
        "serve" => {
            // Ark's builtin tools as an MCP server on stdio, behind the same gates.
            let ws = workspace(a)?;
            let cfg = load_config(a, &ws, &paths)?;
            let vault = load_vault(&paths)?;
            let mut tools: Vec<Arc<dyn ark_core::Tool>> = ark_tools::builtin_tools().into_iter().filter(|t| !matches!(t.spec().name.as_str(), "spawn" | "ask_user")).collect();
            // Web tools follow `[web]` here too (SSRF allowlist, providers, cache), not the defaults.
            match ark_tools::web::tools_from_value(serde_json::to_value(&cfg.web).unwrap_or(serde_json::Value::Null)) {
                Ok(w) => wire::merge_tools(&mut tools, w),
                Err(e) => eprintln!("ark: warning: {e}"),
            }
            // Conversation tools: drive and approve sessions in the running daemon.
            tools.extend(ark_app::conversations::tools(paths.socket()));
            let (allow_p, allow_e) = (a.flag("allow-privilege") || a.flag("yes"), a.flag("allow-egress") || a.flag("yes"));
            let v2 = vault.clone();
            let gcfg = cfg.gate.clone();
            let judge = move |effects: &[ark_core::Effect]| -> Result<(), String> {
                use ark_kernel::gate::{GateKind, Gates, Verdict};
                match (Gates { cfg: &gcfg, vault: &v2 }).judge(effects) {
                    Verdict::Allow => Ok(()),
                    Verdict::Ask { gate: GateKind::Privilege, .. } if allow_p => Ok(()),
                    Verdict::Ask { gate: GateKind::Egress, .. } if allow_e => Ok(()),
                    Verdict::Ask { gate, reason } | Verdict::Deny { gate, reason } => Err(format!("blocked by the {gate:?} gate: {reason}")),
                }
            };
            let data = paths.data.clone();
            let v3 = vault.clone();
            let ctx = move || ark_core::ToolCtx {
                workspace: ws.clone(),
                session_id: "mcp-serve".into(),
                artifacts: data.join("mcp-serve"),
                home: data.clone(),
                cancel: ark_core::Cancel::new(),
                host: Arc::new(NoHost),
                secrets: ext::secrets_fn(&v3),
            };
            let info = ark_plugin::ServerInfo { name: "ark".into(), version: env!("CARGO_PKG_VERSION").into(), instructions: Some("Ark's file, search, shell and memory tools, plus ark_session_* / ark_pending* to drive and approve sessions in the running ark daemon. Calls pass Ark's privilege and egress gates.".into()) };
            if let Some(relay) = a.val("relay") {
                // Outbound relay instead of stdio: no inbound port, Ed25519-authenticated, grant-scoped.
                let srv = ark_plugin::Server { info: &info, tools: &tools, ctx: &ctx, judge: &judge };
                let handle = |m: &Value| srv.handle(m).and_then(|r| serde_json::from_str(&vault.redact(&r.to_string())).ok());
                let opts = ark_plugin::relay::Opts { relay: relay.to_string(), state: paths.data.join("mcp-relay.json"), name: "ark".into(), version: env!("CARGO_PKG_VERSION").into(), pair: a.flag("pair") };
                ark_plugin::relay::run(&opts, &handle, &ark_core::Cancel::new(), &|l: &str| eprintln!("{l}"))?;
                return Ok(0);
            }
            let stdin = std::io::stdin();
            ark_plugin::serve(&info, &tools, &ctx, &judge, stdin.lock(), RedactingWriter { inner: std::io::stdout(), vault, buf: Vec::new() }).map_err(|e| e.to_string())?;
            Ok(0)
        }
        other => usage(format!("unknown `mcp {other}`")),
    }
}

struct NoHost;
impl ark_core::ToolHost for NoHost {
    fn spawn_agent(&self, _: ark_core::tool::SpawnRequest, _: &ark_core::Cancel) -> Result<String, String> {
        Err("not available over MCP".into())
    }
    fn ask_user(&self, _: &str) -> Result<String, String> {
        Err("not available over MCP".into())
    }
}

/// Line-buffered stdout that strips vault secrets from every reply.
struct RedactingWriter {
    inner: std::io::Stdout,
    vault: Arc<Vault>,
    buf: Vec<u8>,
}
impl Write for RedactingWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(b);
        while let Some(i) = self.buf.iter().position(|&c| c == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=i).collect();
            let s = self.vault.redact(&String::from_utf8_lossy(&line));
            self.inner.write_all(s.as_bytes())?;
        }
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buf.is_empty() {
            let s = self.vault.redact(&String::from_utf8_lossy(&std::mem::take(&mut self.buf)));
            self.inner.write_all(s.as_bytes())?;
        }
        self.inner.flush()
    }
}
