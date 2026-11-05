//! Professional-role tools in the binary (BATCH-next §3): registration of `sql_query` /
//! `sql_schema` (data), `directory_lookup` (IT support) and `forge_read` / `forge_write`
//! (software development), plus `ark pro` to check and try them.
//!
//! The tools live in `ark_tools::{data, directory, forge}`; their settings are the
//! `[integrations.data]`, `[integrations.directory]` and `[integrations.forge]` tables (see
//! those modules for the keys). `[integrations]` is project-gated, so a repository cannot
//! define a database or a forge for itself. The role presets reach the tools through the tool
//! profiles in `ark_security::toolpolicy` (`group:data`, `group:directory`, `group:forge`).
//!
//! ```text
//! ark pro status [--json]                       sources / providers / hosts and whether their secrets are set
//! ark pro sql <source> "<statement>" [--max-rows N]
//! ark pro schema [<source> [<table>]]
//! ark pro lookup <provider> user|group|members|groups_of <query>
//! ark pro forge <host> <owner/repo> issue|pr|pr_files|comments|checks|issues|prs [number]
//! ```
//! `sql`, `lookup` and `forge` run exactly the model's tools (same read-only layers, same limits).

use ark_core::{Tool, ToolCtx};
use ark_kernel::config::{project_config, Config, Paths};
use ark_kernel::vault::Vault;
use serde_json::{json, Value};
use std::sync::Arc;

pub const USAGE: &str = "\
ark pro <subcommand>
  status [--json]                         configured databases / directories / forges and their secrets
  sql <source> \"<statement>\" [--max-rows N]  one read-only statement, as the model's sql_query runs it
  schema [<source> [<table>]]             list sources, tables, or a table's columns
  lookup <provider> user|group|members|groups_of <query>
                                          read-only directory lookup (LDAP / AD / Entra / Okta)
  forge <host> <repo> <kind> [number]     forge_read: issue|pr|pr_files|comments|checks|issues|prs
Settings: [integrations.data] / [integrations.directory] / [integrations.forge]; secrets with `ark secrets set NAME`.";

fn section(cfg: &Config, key: &str) -> Value {
    cfg.integrations.get(key).and_then(|v| serde_json::to_value(v).ok()).unwrap_or(Value::Null)
}

pub fn data_tools(cfg: &Config) -> Result<Vec<Arc<dyn Tool>>, String> {
    ark_tools::data::tools(section(cfg, "data"))
}
pub fn directory_tools(cfg: &Config) -> Result<Vec<Arc<dyn Tool>>, String> {
    ark_tools::directory::tools(section(cfg, "directory"))
}
pub fn forge_tools(cfg: &Config) -> Result<Vec<Arc<dyn Tool>>, String> {
    ark_tools::forge::tools(section(cfg, "forge"), ark_tools::web::http::process_env())
}

pub fn register() {
    ark_core::registry::register_tool_provider("pro-data", 320, |env| data_tools(env.config::<Config>()?));
    ark_core::registry::register_tool_provider("pro-directory", 321, |env| directory_tools(env.config::<Config>()?));
    ark_core::registry::register_tool_provider("pro-forge", 322, |env| forge_tools(env.config::<Config>()?));
    // A malformed table is reported when the config loads, in the section's own words.
    ark_core::registry::register_config_validator("integrations", |cfg, out| {
        let Some(c) = cfg.downcast_ref::<Config>() else { return };
        for key in ["data", "directory", "forge"] {
            if !c.integrations.contains_key(key) {
                continue;
            }
            let v = section(c, key);
            let r = match key {
                "data" => ark_tools::data::DataConfig::from_value(v).map(|_| ()),
                "directory" => ark_tools::directory::DirectoryConfig::from_value(v).map(|_| ()),
                _ => ark_tools::forge::ForgeConfig::from_value(v, &(Arc::new(|_: &str| None) as ark_tools::forge::EnvFn)).map(|_| ()),
            };
            if let Err(e) = r {
                out.push(e);
            }
        }
    });
    ark_core::registry::register_command_route("pro", None, |_, argv| cli(argv));
}

fn secrets_fn(paths: &Paths) -> Arc<dyn Fn(&str) -> String + Send + Sync> {
    let v = Vault::load(&paths.secrets()).unwrap_or_else(|_| Vault::empty());
    Arc::new(move |s: &str| v.substitute(s))
}

struct NoHost;
impl ark_core::ToolHost for NoHost {
    fn spawn_agent(&self, _: ark_core::tool::SpawnRequest, _: &ark_core::Cancel) -> Result<String, String> {
        Err("not available from `ark pro`".into())
    }
    fn ask_user(&self, _: &str) -> Result<String, String> {
        Err("not available from `ark pro`".into())
    }
}

fn tool_ctx(paths: &Paths) -> ToolCtx {
    let ws = std::env::current_dir().unwrap_or_else(|_| paths.data.clone());
    ToolCtx { workspace: ws, session_id: "cli-pro".into(), artifacts: paths.runtime.join("pro-artifacts"), home: paths.data.clone(), cancel: ark_core::Cancel::new(), host: Arc::new(NoHost), secrets: secrets_fn(paths) }
}

fn load_cfg(paths: &Paths) -> Result<Config, String> {
    let ws = std::env::current_dir().unwrap_or_else(|_| paths.data.clone());
    Config::load(Some(&paths.user_config()), Some(&project_config(&ws)), &[])
}

/// Every `{{secret:NAME}}` named anywhere in `v`.
fn secret_names(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => {
            let mut rest = s.as_str();
            while let Some(i) = rest.find("{{secret:") {
                let tail = &rest[i + 9..];
                let name: String = tail.chars().take_while(|c| *c != '}').collect();
                rest = &tail[name.len()..];
                if !name.is_empty() && !out.contains(&name) {
                    out.push(name);
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| secret_names(x, out)),
        Value::Object(m) => m.values().for_each(|x| secret_names(x, out)),
        _ => {}
    }
}

/// The body of `ark pro status`.
pub fn status(cfg: &Config, vault_names: &[String]) -> Value {
    let mut rows = vec![];
    for (key, list) in [("data", "sources"), ("directory", "providers"), ("forge", "hosts")] {
        let sec = section(cfg, key);
        let Some(items) = sec.get(list).and_then(Value::as_object) else { continue };
        for (name, item) in items {
            let mut names = vec![];
            secret_names(item, &mut names);
            let secrets: Vec<Value> = names.iter().map(|n| json!({"name": n, "set": vault_names.contains(n) || std::env::var(n).is_ok()})).collect();
            let missing = secrets.iter().any(|s| s["set"] == json!(false));
            let mut note = Value::Null;
            if key == "data" && item["kind"] == "sqlite" {
                let p = item["path"].as_str().unwrap_or("");
                if !ark_core::tool::expand_home(p).exists() && !std::path::Path::new(p).is_absolute() {
                    note = json!("relative path: resolved against the working directory");
                } else if !ark_core::tool::expand_home(p).exists() {
                    note = json!("file not found");
                }
            }
            rows.push(json!({"area": key, "name": name, "kind": item["kind"], "secrets": secrets, "ready": !missing && note != json!("file not found"), "note": note}));
        }
    }
    json!({"entries": rows})
}

pub fn cli(argv: &[String]) -> Result<i32, String> {
    let paths = Paths::from_env();
    let (out, code) = run(&paths, argv)?;
    if !out.trim().is_empty() {
        println!("{}", out.trim_end());
    }
    Ok(code)
}

fn find(tools: Vec<Arc<dyn Tool>>, name: &str, what: &str) -> Result<Arc<dyn Tool>, String> {
    tools.into_iter().find(|t| t.spec().name == name).ok_or_else(|| format!("no {what} configured (see [integrations.{}])", if name.starts_with("sql") { "data" } else if name.starts_with("directory") { "directory" } else { "forge" }))
}

fn show(o: ark_core::ToolOutput) -> Result<(String, i32), String> {
    Ok((o.content, if o.is_error { 1 } else { 0 }))
}

pub fn run(paths: &Paths, argv: &[String]) -> Result<(String, i32), String> {
    let cfg = load_cfg(paths)?;
    let ctx = tool_ctx(paths);
    let sub = argv.first().map(String::as_str).unwrap_or("status");
    let rest: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
    match sub {
        "status" => {
            let names = Vault::load(&paths.secrets()).map(|v| v.names()).unwrap_or_default();
            let v = status(&cfg, &names);
            if rest.contains(&"--json") {
                return Ok((serde_json::to_string_pretty(&v).unwrap_or_default(), 0));
            }
            let mut s = String::new();
            for r in v["entries"].as_array().cloned().unwrap_or_default() {
                let sec: Vec<String> = r["secrets"].as_array().cloned().unwrap_or_default().iter().map(|x| format!("{} {}", x["name"].as_str().unwrap_or(""), if x["set"] == json!(true) { "set" } else { "MISSING" })).collect();
                s.push_str(&format!("{:<10} {:<16} {:<11} {}{}\n", r["area"].as_str().unwrap_or(""), r["name"].as_str().unwrap_or(""), r["kind"].as_str().unwrap_or(""), if r["ready"] == json!(true) { "ready" } else { "NOT READY" }, if sec.is_empty() { String::new() } else { format!("  [{}]", sec.join(", ")) }));
            }
            if s.is_empty() {
                s = "nothing configured: add [integrations.data.sources.<name>], [integrations.directory.providers.<name>] or [integrations.forge.hosts.<name>] (docs/professional-tools.md)\n".into();
            }
            let hosts_env = ["GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN"].iter().filter(|k| std::env::var(k).is_ok()).count();
            if hosts_env > 0 && section(&cfg, "forge").get("hosts").is_none() {
                s.push_str("forge       (from the environment: GITHUB_TOKEN / GITLAB_TOKEN)\n");
            }
            Ok((s, 0))
        }
        "sql" => {
            let (mut max, mut pos) = (None, vec![]);
            let mut it = rest.iter();
            while let Some(a) = it.next() {
                if *a == "--max-rows" {
                    max = Some(it.next().and_then(|v| v.parse::<u64>().ok()).ok_or("--max-rows needs a number")?);
                } else {
                    pos.push(*a);
                }
            }
            let [source, sql] = pos.as_slice() else { return Err(format!("usage: ark pro sql <source> \"<statement>\" [--max-rows N]\n{USAGE}")) };
            let t = find(data_tools(&cfg)?, "sql_query", "database")?;
            let mut input = json!({"source": source, "sql": sql});
            if let Some(m) = max {
                input["max_rows"] = json!(m);
            }
            show(t.call(&ctx, input))
        }
        "schema" => {
            let t = find(data_tools(&cfg)?, "sql_schema", "database")?;
            let mut input = json!({});
            if let Some(s) = rest.first() {
                input["source"] = json!(s);
            }
            if let Some(tb) = rest.get(1) {
                input["table"] = json!(tb);
            }
            show(t.call(&ctx, input))
        }
        "lookup" => {
            let [provider, kind, query @ ..] = rest.as_slice() else { return Err(format!("usage: ark pro lookup <provider> user|group|members|groups_of <query>\n{USAGE}")) };
            let t = find(directory_tools(&cfg)?, "directory_lookup", "directory")?;
            show(t.call(&ctx, json!({"provider": provider, "kind": kind, "query": query.join(" ")})))
        }
        "forge" => {
            let [host, repo, kind, number @ ..] = rest.as_slice() else { return Err(format!("usage: ark pro forge <host> <repo> <kind> [number]\n{USAGE}")) };
            let t = find(forge_tools(&cfg)?, "forge_read", "forge")?;
            let mut input = json!({"host": host, "repo": repo, "kind": kind});
            if let Some(n) = number.first() {
                input["number"] = json!(n.parse::<u64>().map_err(|_| "number must be an integer")?);
            }
            show(t.call(&ctx, input))
        }
        "help" | "--help" | "-h" => Ok((USAGE.into(), 0)),
        other => Err(format!("unknown `pro {other}`\n{USAGE}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_kernel::config::Paths;

    struct Home {
        dir: ark_core::tmp::TempDir,
        paths: Paths,
    }

    fn home(config_toml: &str) -> Home {
        let dir = ark_core::tmp::TempDir::new("ark-pro");
        let paths = Paths { data: dir.join("data"), config_dir: dir.join("config"), runtime: dir.join("run") };
        std::fs::create_dir_all(&paths.data).unwrap();
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(paths.user_config(), config_toml).unwrap();
        Home { dir, paths }
    }

    fn sales_db(dir: &std::path::Path) -> std::path::PathBuf {
        let p = dir.join("sales.db");
        let c = ark_kernel::sqlindex::rusqlite::Connection::open(&p).unwrap();
        c.execute_batch("CREATE TABLE t(a INTEGER, b TEXT); INSERT INTO t VALUES (1,'x'),(2,'y'),(3,'z');").unwrap();
        p
    }

    fn cfg_with_db(db: &std::path::Path) -> String {
        format!("[integrations.data.sources.sales]\nkind = \"sqlite\"\npath = \"{}\"\ndescription = \"test\"\n[integrations.data]\nmax_rows = 2\n", db.display())
    }

    #[test]
    fn the_registry_hands_the_model_the_tools_the_config_enables() {
        register();
        let h = home("");
        let ws = h.dir.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let names = |cfg: &Config| -> Vec<String> {
            let env = ark_core::registry::HostEnv::new(cfg, ws.clone(), h.paths.data.clone(), h.paths.config_dir.clone(), h.paths.runtime.clone());
            let (tools, warnings) = ark_core::registry::collect_tools(&env);
            assert!(warnings.is_empty(), "{warnings:?}");
            tools.iter().map(|t| t.spec().name).filter(|n| n.starts_with("sql_") || n.starts_with("directory_") || n.starts_with("forge_")).collect()
        };
        assert!(names(&Config::default()).iter().all(|n| !n.starts_with("sql_") && !n.starts_with("directory_")), "no config, no database or directory tools");
        let cfg: Config = toml::from_str(
            "[integrations.data.sources.s]\nkind = \"sqlite\"\npath = \"/x.db\"\n[integrations.directory.providers.d]\nkind = \"okta\"\norg_url = \"https://x.okta.com\"\ntoken = \"{{secret:OKTA}}\"\n[integrations.forge.hosts.gl]\nkind = \"gitlab\"\napi_base = \"https://git.example.com/api/v4\"\n",
        )
        .unwrap();
        let mut n = names(&cfg);
        n.sort();
        assert_eq!(n, ["directory_lookup", "forge_read", "forge_write", "sql_query", "sql_schema"]);
        // A broken table is refused by the config validator, with the section's own message.
        let bad: Config = toml::from_str("[integrations.data.sources.s]\nkind = \"oracle\"\ndsn = \"x://y\"\n").unwrap();
        assert!(ark_core::registry::validate_config(&bad).iter().any(|m| m.contains("oracle")), "{:?}", ark_core::registry::validate_config(&bad));
        assert!(ark_core::registry::validate_config(&cfg).is_empty());
    }

    /// The tier the risk classifier gives a call (the kernel builds its candidate the same way).
    fn tier_of(tool: &dyn Tool, ctx: &ToolCtx, input: &Value) -> ark_security::risk::Tier {
        use ark_core::Effect;
        let mut c = ark_security::risk::Candidate { tool: tool.spec().name, workspace: ctx.workspace.clone(), allowed_hosts: ark_security::risk::dev_hosts(), input: input.clone(), sandboxed: false, ..Default::default() };
        for e in tool.effects(ctx, input) {
            match e {
                Effect::Net { dest, payload } => {
                    let h = ark_kernel::gate::host_of(&dest);
                    if !h.is_empty() {
                        c.hosts.push(h);
                    }
                    if !payload.is_empty() {
                        c.payload = Some(payload);
                    }
                }
                Effect::Remote { dest, .. } => {
                    c.remote = true;
                    let h = ark_kernel::gate::host_of(&dest);
                    if !h.is_empty() {
                        c.hosts.push(h);
                    }
                }
                Effect::Read { path } => c.reads.push(path),
                _ => {}
            }
        }
        ark_security::risk::assess(&c).tier
    }

    #[test]
    fn forge_writes_are_tier_two_even_on_the_development_allowlist_and_reads_are_not() {
        use ark_security::risk::Tier;
        let h = home("");
        let ctx = tool_ctx(&h.paths);
        let cfg: Config = toml::from_str("[integrations.forge.hosts.github]\nkind = \"github\"\n[integrations.forge.hosts.gl]\nkind = \"gitlab\"\napi_base = \"https://git.corp.example/api/v4\"\n").unwrap();
        let tools = forge_tools(&cfg).unwrap();
        let (read, write) = (&tools[0], &tools[1]);
        for (host, repo) in [("github", "o/r"), ("gl", "g/p")] {
            for input in [
                json!({"host": host, "repo": repo, "action": "comment", "number": 1, "body": "hi", "target": "pr"}),
                json!({"host": host, "repo": repo, "action": "review", "number": 1, "verdict": "approve"}),
                json!({"host": host, "repo": repo, "action": "create_pr", "title": "t", "head": "a", "base": "main"}),
                json!({"host": host, "repo": repo, "action": "create_issue", "title": "t"}),
                json!({"host": host, "repo": repo, "action": "update_issue", "number": 1, "state": "closed"}),
            ] {
                assert_eq!(tier_of(write.as_ref(), &ctx, &input), Tier::Impactful, "{input}");
            }
            assert!(tier_of(read.as_ref(), &ctx, &json!({"host": host, "repo": repo, "kind": "issues"})) <= Tier::Recoverable);
        }
    }

    #[test]
    fn sql_reads_are_tier_one_and_never_irreversible() {
        use ark_security::risk::Tier;
        let h = home("");
        let ctx = tool_ctx(&h.paths);
        let db = sales_db(&h.dir);
        let cfg: Config = toml::from_str(&cfg_with_db(&db)).unwrap();
        let t = data_tools(&cfg).unwrap();
        assert!(tier_of(t[0].as_ref(), &ctx, &json!({"source": "sales", "sql": "SELECT 1"})) <= Tier::Recoverable);
    }

    #[test]
    fn ark_pro_status_sql_and_schema_work_from_the_user_config() {
        let h = home("");
        let db = sales_db(&h.dir);
        std::fs::write(h.paths.user_config(), format!("{}[integrations.data.sources.wh]\nkind = \"postgres\"\ndsn = \"{{{{secret:WH_DSN_ARK_TEST}}}}\"\n[integrations.forge.hosts.gl]\nkind = \"gitlab\"\ntoken = \"{{{{secret:GL_TOKEN_ARK_TEST}}}}\"\n", cfg_with_db(&db))).unwrap();
        let (s, code) = run(&h.paths, &["status".into()]).unwrap();
        assert_eq!(code, 0);
        assert!(s.contains("sales") && s.contains("ready") && s.contains("WH_DSN_ARK_TEST MISSING") && s.contains("GL_TOKEN_ARK_TEST MISSING") && s.contains("NOT READY"), "{s}");
        let (j, _) = run(&h.paths, &["status".into(), "--json".into()]).unwrap();
        let v: Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["entries"].as_array().unwrap().len(), 3);

        let (out, code) = run(&h.paths, &["sql".into(), "sales".into(), "SELECT a, b FROM t ORDER BY a".into()]).unwrap();
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("\"row_count\": 2") && out.contains("\"truncated\": true"), "[integrations.data] max_rows = 2 applies: {out}");
        let (out, code) = run(&h.paths, &["sql".into(), "sales".into(), "DELETE FROM t".into()]).unwrap();
        assert_eq!(code, 1);
        assert!(out.contains("refused"), "{out}");
        let (out, _) = run(&h.paths, &["sql".into(), "sales".into(), "SELECT count(*) FROM t".into(), "--max-rows".into(), "1".into()]).unwrap();
        assert!(out.contains("\"3\"") || out.contains(" 3"), "nothing was deleted: {out}");
        let (out, code) = run(&h.paths, &["schema".into(), "sales".into(), "t".into()]).unwrap();
        assert_eq!(code, 0);
        assert!(out.contains("\"b\"") || out.contains("b\""), "{out}");
        assert!(run(&h.paths, &["lookup".into(), "x".into(), "user".into(), "a".into()]).unwrap_err().contains("no directory configured"));
        assert!(run(&h.paths, &["bogus".into()]).is_err());
    }
}
