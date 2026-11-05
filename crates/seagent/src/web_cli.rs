//! `seagent web …`: the web-search command surface, plus the dedicated vendor tools that belong to
//! it. OpenClaw reaches the same data through `openclaw configure --section web`,
//! `openclaw plugins` and the `tools.web` section; seagent's search layer lives in
//! `seagent_tools::web` (`search::resolve` / `search::run`, `providers::all()`), so this module is
//! the thin CLI over it:
//!
//! * `seagent web providers [--json]` — every bundled provider with `id` / `label` / `configured` /
//!   `auto_detect` / `keyless` / env vars, and the route a search would take right now. This is
//!   the command the "No web search provider configured" error already tells users to run.
//! * `seagent web test <query> [--count N] [--json]` — one real search through the resolved route
//!   (keyless search works without any key).
//! * `seagent web fetch <url> [--text] [--json]` — one URL through `web_fetch` (SSRF guard,
//!   Readability → Markdown, Firecrawl fallback); upstream `openclaw infer web fetch`.
//!
//! `tools()` returns the dedicated vendor tools registered with the model
//! (`tavily_search` / `tavily_extract` when Tavily is selected or keyed, `github_read` /
//! `github_search` always), built from the `[web]` table exactly as the other web tools are.
//!
//! Setting the provider stays with `seagent config set web.search.provider <id>` and `seagent setup`
//! (upstream has no non-interactive `web config set` either: `openclaw configure --section web`
//! is the interactive flow).

use seagent_kernel::config::{Config, Paths};
use seagent_kernel::vault::Vault;
use seagent_tools::web::http::{self, WebCtx};
use seagent_tools::web::providers;
use seagent_tools::web::{search, WebConfig};
use seagent_core::Tool;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Instant;

/// One line per subcommand, shown by `seagent help`.
pub const HELP_LINES: &str = "  seagent web providers [--json]          web search providers, their keys, and the route in use
  seagent web test <query> [--count N] [--json]  run one real search through that route
  seagent web fetch <url> [--text] [--json]      fetch one URL (Readability → Markdown, SSRF guard)";

fn help() -> String {
    format!("seagent web — web search setup and diagnostics\n\nUSAGE\n{}\n\nA provider is chosen with `[web.search] provider` (or `seagent setup`); keys are read from\n`[web.providers.<id>] api_key`, the environment, or `{{{{secret:NAME}}}}` in the vault.\n", HELP_LINES)
}

/// `[web]` as a typed config; an empty table means defaults.
pub fn web_config(web: &toml::Table) -> Result<WebConfig, String> {
    let v = if web.is_empty() { Value::Null } else { serde_json::to_value(web).map_err(|e| format!("[web]: {e}"))? };
    WebConfig::from_value(v)
}

/// Resolve one `{{secret:NAME}}` for the `[web]` table.
type SecretsFn = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// A call context for the configured `[web]` table: process environment, then the vault.
pub fn ctx(web: &toml::Table, paths: &Paths) -> Result<WebCtx, String> {
    let mut c = WebCtx::new(Arc::new(web_config(web)?), http::process_env());
    c.secrets = secrets(paths);
    Ok(c)
}

/// Providers, their credential state and the resolved route (the body of `ui.websearch.status`).
pub fn status(web: &toml::Table, env: Option<http::EnvFn>, secrets: Option<SecretsFn>) -> Value {
    let wc = match web_config(web) {
        Ok(w) => w,
        Err(e) => return json!({"error": e, "providers": [], "route": Value::Null}),
    };
    let mut c = WebCtx::new(Arc::new(wc), env.unwrap_or_else(http::process_env));
    if let Some(s) = secrets {
        c.secrets = s;
    }
    let route = search::resolve(&c);
    json!({
        "pinned": c.cfg.search_pin(),
        "route": route.as_ref().map(|r| r.id()).ok(),
        "error": route.err(),
        "providers": providers::all().iter().map(|p| json!({
            "id": p.id(),
            "label": p.label(),
            "configured": p.configured(&c),
            "auto_detect": p.auto_detect(),
            "keyless": p.keyless(),
            "env_vars": p.env_vars(),
            "signup_url": p.signup_url(),
        })).collect::<Vec<_>>(),
    })
}

/// One real search through the resolved route; the rendered, model-facing JSON.
pub fn search_once(web: &toml::Table, paths: &Paths, query: &str, count: usize) -> Result<Value, String> {
    let c = ctx(web, paths)?;
    let route = search::resolve(&c)?;
    let r = search::parse_request(&json!({"query": query, "count": count}), c.cfg.search.max_results.max(1))?;
    let started = Instant::now();
    match search::run(&c, &route, &r) {
        Ok(o) => Ok(search::render(&o, &r.query, started.elapsed())),
        Err((code, msg)) => Err(format!("{msg} ({code})")),
    }
}

/// `{{secret:NAME}}` substitution over the on-disk vault (a missing / unreadable vault means
/// "no secrets", never an error here).
fn secrets(paths: &Paths) -> Arc<dyn Fn(&str) -> String + Send + Sync> {
    let v = Vault::load(&paths.secrets()).unwrap_or_else(|_| Vault::empty());
    Arc::new(move |s: &str| v.substitute(s))
}

fn providers_cmd(argv: &[String], web: &toml::Table, paths: &Paths) -> Result<i32, String> {
    let as_json = argv.iter().any(|a| a == "--json");
    let v = status(web, None, Some(secrets(paths)));
    if as_json {
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return Ok(0);
    }
    // The listing itself is `seagent_tools::web::cli::render` (credentials, availability, autodetect
    // and the keyless ring); this module adds the route line, JSON and `test`.
    match ctx(web, paths) {
        Ok(c) => {
            print!("{}", seagent_tools::web::cli::render(&c));
            if let Some(e) = v["error"].as_str() {
                println!("\nsearch would fail: {e}");
            }
        }
        Err(e) => println!("[web]: {e}"),
    }
    println!("\nselect one with: seagent config set web.search.provider <id>   (or `seagent setup`)");
    Ok(0)
}

fn test_cmd(argv: &[String], web: &toml::Table, paths: &Paths) -> Result<i32, String> {
    let as_json = argv.iter().any(|a| a == "--json");
    let mut count = 5usize;
    let mut words: Vec<String> = vec![];
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "--count" {
            count = argv.get(i + 1).and_then(|n| n.parse().ok()).filter(|n| (1..=100).contains(n)).ok_or("--count must be an integer from 1 to 100")?;
            i += 2;
            continue;
        }
        if let Some(n) = a.strip_prefix("--count=") {
            count = n.parse().ok().filter(|n| (1..=100).contains(n)).ok_or("--count must be an integer from 1 to 100")?;
            i += 1;
            continue;
        }
        if !a.starts_with("--") {
            words.push(a.clone());
        }
        i += 1;
    }
    let query = words.join(" ").trim().to_string();
    if query.is_empty() {
        return Err("usage: seagent web test <query> [--count N] [--json]".into());
    }
    let v = search_once(web, paths, &query, count)?;
    if as_json {
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return Ok(0);
    }
    match v["kind"].as_str() {
        Some("answer") => {
            println!("{}", v["content"].as_str().unwrap_or_default());
            for c in v["citations"].as_array().cloned().unwrap_or_default() {
                println!("  - {}", c["url"].as_str().unwrap_or_default());
            }
        }
        _ => {
            let rows = v["results"].as_array().cloned().unwrap_or_default();
            if rows.is_empty() {
                println!("no results (provider {})", v["provider"].as_str().unwrap_or("?"));
            }
            for (i, r) in rows.iter().enumerate() {
                println!("{}. {}", i + 1, r["title"].as_str().unwrap_or("(no title)"));
                println!("   {}", r["url"].as_str().unwrap_or(""));
                let snippet = r["snippet"].as_str().unwrap_or("");
                if !snippet.is_empty() {
                    println!("   {}", crate::term::one_line(snippet, 200));
                }
            }
            println!("\nprovider: {} · {} ms", v["provider"].as_str().unwrap_or("?"), v["tookMs"].as_u64().unwrap_or(0));
        }
    }
    Ok(0)
}

/// One URL through the `web_fetch` pipeline (SSRF guard, blocklist, Readability → Markdown,
/// PDF, the Firecrawl fallback): upstream `openclaw infer web fetch --url <url> [--format]`.
fn fetch_cmd(argv: &[String], web: &toml::Table, paths: &Paths) -> Result<i32, String> {
    let as_json = argv.iter().any(|a| a == "--json");
    let mut text_mode = false;
    let mut url = String::new();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--json" => {}
            "--text" | "-t" => text_mode = true,
            // `--format text|markdown`: upstream's `extractMode` hint.
            "--format" => {
                text_mode = match argv.get(i + 1).map(String::as_str) {
                    Some("text") => true,
                    Some("markdown") => false,
                    other => return Err(format!("--format must be `markdown` or `text`, got `{}`", other.unwrap_or(""))),
                };
                i += 1;
            }
            "--url" => {
                url = argv.get(i + 1).cloned().ok_or("--url needs a value")?;
                i += 1;
            }
            other if other.starts_with("--") => return Err(format!("unknown `seagent web fetch` flag `{other}`\n\n{}", help())),
            other => url = other.to_string(),
        }
        i += 1;
    }
    if url.trim().is_empty() {
        return Err("usage: seagent web fetch <url> [--text | --format text|markdown] [--json]".into());
    }
    let c = ctx(web, paths)?;
    let req = seagent_tools::web::fetch::Request::get(url.trim(), text_mode);
    let doc = seagent_tools::web::fetch::fetch_document(&c, &req).map_err(|e| e.message())?;
    if as_json {
        let v = json!({
            "url": url.trim(),
            "final_url": doc.final_url,
            "status": doc.status,
            "content_type": doc.content_type,
            "title": doc.title,
            "extractor": doc.extractor,
            "chars": doc.text.chars().count(),
            "degraded": doc.degraded,
            "warning": doc.warning,
            "text": doc.text,
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return Ok(0);
    }
    if let Some(t) = doc.title.as_deref().filter(|t| !t.is_empty()) {
        println!("{t}");
    }
    println!("{}", doc.final_url);
    println!(
        "{} · {} · {} {}",
        doc.status,
        if doc.extractor.is_empty() { "direct" } else { doc.extractor.as_str() },
        doc.text.chars().count(),
        if text_mode { "chars (text)" } else { "chars (markdown)" }
    );
    if let Some(w) = doc.warning.as_deref().filter(|w| !w.is_empty()) {
        println!("{}", crate::term::one_line(w, 300));
    }
    println!();
    println!("{}", doc.text);
    Ok(0)
}

/// `seagent web <subcommand>` (`argv` excludes `web`). The global `-w/--workspace` flag is accepted
/// anywhere (main.rs already loaded the config for it) and ignored here.
pub fn cli(argv: &[String], paths: &Paths, cfg: &Config) -> Result<i32, String> {
    let mut args: Vec<String> = vec![];
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "-w" || a == "--workspace" {
            i += 2;
            continue;
        }
        if a.starts_with("--workspace=") {
            i += 1;
            continue;
        }
        args.push(a.clone());
        i += 1;
    }
    let argv = &args[..];
    let sub = argv.first().map(String::as_str).unwrap_or("");
    let rest = if argv.is_empty() { argv } else { &argv[1..] };
    match sub {
        "" | "help" | "--help" | "-h" => {
            print!("{}", help());
            Ok(0)
        }
        "providers" | "list" => providers_cmd(rest, &cfg.web, paths),
        "test" | "search" => test_cmd(rest, &cfg.web, paths),
        "fetch" | "get" => fetch_cmd(rest, &cfg.web, paths),
        other => Err(format!("unknown `seagent web` subcommand `{other}`\n\n{}", help())),
    }
}

/// Dedicated vendor tools for the model, from the `[web]` table: `tavily_search` /
/// `tavily_extract` (Tavily selected or keyed) and `github_read` / `github_search` (always).
pub fn tools(cfg: &Config) -> Vec<Arc<dyn Tool>> {
    // An invalid `[web]` table is a warning, never a lost tool: the defaults still carry the
    // credential-gated tools (as `wire::tools` does for the rest of the web set).
    let web = match web_config(&cfg.web) {
        Ok(w) => Arc::new(w),
        Err(e) => {
            eprintln!("seagent: warning: {e}");
            Arc::new(WebConfig::default())
        }
    };
    let env = http::process_env();
    let mut out = seagent_tools::web::vendor_tools::tools(web.clone(), env.clone());
    out.extend(seagent_tools::web::github::tools(web, env));
    out
}

/// Self-registration (`seagent_core::registry`) for the whole web surface:
///
/// * `[web]` — `web_fetch` / `web_search` / `web_extract` / `x_search` / `firecrawl_*`
///   (replaces the default-config `web_fetch` builtin with the configured one);
/// * `tavily_search` / `tavily_extract` (Tavily selected or keyed) and `github_read` /
///   `github_search` (no credential needed): OpenClaw `extensions/tavily`, `extensions/github`.
///
/// An invalid `[web]` table makes its own provider fail; `collect_tools` reports that as a
/// warning and the other subsystems keep their tools.
pub fn register() {
    seagent_core::registry::register_tool_provider("web", 300, |env| {
        let cfg = env.config::<Config>()?;
        seagent_tools::web::tools_from_value(serde_json::to_value(&cfg.web).unwrap_or(serde_json::Value::Null)).map_err(|e| e.to_string())
    });
    seagent_core::registry::register_tool_provider("web-cli", 310, |env| {
        let cfg = env.config::<Config>()?;
        Ok(tools(cfg))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn paths() -> Paths {
        let root = seagent_core::tmp::scratch_path(format!("seagent-webcli-{}", seagent_kernel::util::random_hex(6)));
        std::fs::create_dir_all(root.join("data")).unwrap();
        std::fs::create_dir_all(root.join("config")).unwrap();
        Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run"), ..Default::default() }
    }

    /// A one-shot HTTP server answering every request with `body`.
    fn serve(body: &'static str) -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf);
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        url
    }

    fn table(s: &str) -> toml::Table {
        s.parse().unwrap()
    }

    /// A one-shot server answering every request with `body` and `ct`.
    fn serve_as(ct: &'static str, body: &'static str) -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf);
                let head = format!("HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = s.write_all(head.as_bytes());
                let _ = s.write_all(body.as_bytes());
            }
        });
        url
    }

    /// `seagent web fetch <url>` (upstream `openclaw infer web fetch`): a real page, `--json`, a
    /// `--format` hint, and the refusals (no URL, unknown flag, the metadata floor).
    #[test]
    fn fetch_command_renders_a_page_and_refuses_bad_targets() {
        let p = paths();
        let page = "<html><head><title>SE Agent Page</title></head><body><nav>menu</nav>\
             <article><h1>Heading</h1><p>First paragraph of the article body.</p>\
             <p>Second paragraph with more detail.</p></article><footer>foot</footer></body></html>";
        let url = serve_as("text/html; charset=utf-8", page);
        let web = table("allow_private_urls = true\n[fetch]\ncache_ttl_minutes = 0.0\n");
        assert_eq!(fetch_cmd(&[format!("{url}/doc")], &web, &p).unwrap(), 0);
        assert_eq!(fetch_cmd(&["--url".into(), format!("{url}/doc"), "--json".into()], &web, &p).unwrap(), 0);
        assert_eq!(fetch_cmd(&[format!("{url}/doc"), "--format".into(), "text".into()], &web, &p).unwrap(), 0);
        // Arguments.
        assert!(fetch_cmd(&[], &web, &p).unwrap_err().contains("usage: seagent web fetch"));
        assert!(fetch_cmd(&["--bogus".into(), "http://a.example/".into()], &web, &p).unwrap_err().contains("unknown `seagent web fetch` flag"));
        assert!(fetch_cmd(&["http://a.example/".into(), "--format".into(), "pdf".into()], &web, &p).unwrap_err().contains("--format must be"));
        // The cloud metadata endpoint is refused even with `allow_private_urls = true`.
        let e = fetch_cmd(&["http://169.254.169.254/latest/meta-data/".into()], &web, &p).unwrap_err();
        assert!(e.to_lowercase().contains("blocked") || e.to_lowercase().contains("refus"), "{e}");
    }

    #[test]
    fn providers_status_lists_flags_and_the_route() {
        let web = table("[search]\nprovider = \"searxng\"\n[providers.searxng]\nbase_url = \"http://127.0.0.1:1\"\n");
        let v = status(&web, Some(Arc::new(|_: &str| None)), None);
        assert_eq!(v["pinned"].as_str(), Some("searxng"));
        assert_eq!(v["route"].as_str(), Some("searxng"));
        let list = v["providers"].as_array().unwrap();
        let by = |id: &str| list.iter().find(|p| p["id"] == id).cloned().unwrap();
        assert_eq!(by("searxng")["configured"].as_bool(), Some(true));
        assert_eq!(by("tavily")["configured"].as_bool(), Some(false));
        assert_eq!(by("exa")["keyless"].as_bool(), Some(true), "the anonymous ring is key-free");
        assert_eq!(by("tavily")["env_vars"][0].as_str(), Some("TAVILY_API_KEY"));
        // No provider and no keyless fallback: the error names the command this module implements.
        let bare = status(&table("keyless_fallback = false\n"), Some(Arc::new(|_: &str| None)), None);
        assert_eq!(bare["route"], Value::Null);
        assert!(bare["error"].as_str().unwrap().contains("seagent web providers"), "{bare}");
        let bad = status(&table("[bogus]\n"), None, None);
        assert!(bad["error"].as_str().unwrap().contains("[web]"));
        assert_eq!(bad["providers"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn providers_command_prints_text_and_json() {
        let p = paths();
        let web = table("[search]\nprovider = \"tavily\"\n");
        assert_eq!(providers_cmd(&[], &web, &p).unwrap(), 0);
        assert_eq!(providers_cmd(&["--json".to_string()], &web, &p).unwrap(), 0);
    }

    #[test]
    fn test_command_runs_a_real_search_through_the_configured_provider() {
        let url = serve(r#"{"results":[{"title":"Hit","url":"https://hit.example/1","content":"snippet here"}]}"#);
        let p = paths();
        let web = table(&format!("keyless_fallback = false\n[search]\nprovider = \"searxng\"\n[providers.searxng]\nbase_url = \"{url}\"\n"));
        let v = search_once(&web, &p, "cli probe", 3).unwrap();
        assert_eq!(v["provider"].as_str(), Some("searxng"));
        assert_eq!(v["results"][0]["url"].as_str(), Some("https://hit.example/1"));
        assert_eq!(test_cmd(&["cli".into(), "probe".into(), "--json".into()], &web, &p).unwrap(), 0);
        assert_eq!(test_cmd(&["--count=2".into(), "probe".into()], &web, &p).unwrap(), 0);
    }

    #[test]
    fn test_command_reports_the_missing_provider_error() {
        let p = paths();
        // A pin to a name no provider has is a strict error, never a silent fallback (and it
        // never leaves the machine).
        let web = table("[search]\nprovider = \"nope\"\n");
        let e = search_once(&web, &p, "q", 3).unwrap_err();
        assert!(e.contains("no web search provider has that name"), "{e}");
        // Without any provider the error tells the user to run `seagent web providers`.
        let bare = table("keyless_fallback = false\n");
        assert!(status(&bare, Some(Arc::new(|_: &str| None)), None)["error"].as_str().unwrap().contains("seagent web providers"));
        assert!(test_cmd(&[], &web, &p).unwrap_err().contains("usage: seagent web test"));
        assert!(test_cmd(&["--count".into(), "0".into(), "q".into()], &web, &p).unwrap_err().contains("--count"));
    }

    #[test]
    fn cli_dispatch_and_help() {
        let p = paths();
        let cfg = Config::default();
        assert_eq!(cli(&[], &p, &cfg).unwrap(), 0);
        assert_eq!(cli(&["--help".into()], &p, &cfg).unwrap(), 0);
        assert_eq!(cli(&["providers".into(), "--json".into()], &p, &cfg).unwrap(), 0);
        assert!(cli(&["bogus".into()], &p, &cfg).unwrap_err().contains("unknown `seagent web` subcommand"));
        // `fetch` is dispatched too (it just needs a URL).
        assert!(cli(&["fetch".into()], &p, &cfg).unwrap_err().contains("usage: seagent web fetch"));
        assert!(help().contains("seagent web fetch"));
        // The global `-w/--workspace` flag is accepted anywhere and ignored.
        assert_eq!(cli(&["-w".into(), "/tmp".into(), "providers".into(), "--json".into()], &p, &cfg).unwrap(), 0);
        assert_eq!(cli(&["providers".into(), "--workspace=/tmp".into()], &p, &cfg).unwrap(), 0);
    }

    /// The host tool set (`wire::tools`) really carries the four names.
    #[test]
    fn registered_with_the_host_tool_set() {
        let p = paths();
        let ws = seagent_core::tmp::scratch_path(format!("seagent-webcli-ws-{}", seagent_kernel::util::random_hex(6)));
        std::fs::create_dir_all(&ws).unwrap();
        let cfg = Config { web: table("[search]\nprovider = \"tavily\"\n"), ..Default::default() };
        let all = crate::wire::tools(&cfg, &p, &ws);
        let names: Vec<String> = all.iter().map(|t| t.spec().name).collect();
        for n in ["tavily_search", "tavily_extract", "github_read", "github_search"] {
            assert_eq!(all.iter().filter(|t| t.spec().name == n).count(), 1, "{n} registered once, got {names:?}");
        }
        // Merged into the builtin set they neither collide with nor disable `web_fetch` /
        // `web_search`: upstream's github/tavily tools are additions, not replacements.
        let mut merged = seagent_tools::builtin_tools();
        crate::wire::merge_tools(&mut merged, all);
        let merged_names: Vec<String> = merged.iter().map(|t| t.spec().name).collect();
        for n in ["web_fetch", "web_search", "tavily_search", "tavily_extract", "github_read", "github_search"] {
            assert_eq!(merged.iter().filter(|t| t.spec().name == n).count(), 1, "{n} exactly once after the merge: {merged_names:?}");
        }
    }

    /// The four vendor tools reach the model from the `[web]` table alone.
    #[test]
    fn tools_follow_the_web_table() {
        let mut cfg = Config::default();
        let names = |cfg: &Config| -> Vec<String> { tools(cfg).iter().map(|t| t.spec().name).collect() };
        assert_eq!(names(&cfg), vec!["github_read", "github_search"], "github needs no credential");
        cfg.web = table("[search]\nprovider = \"tavily\"\n");
        assert_eq!(names(&cfg), vec!["tavily_search", "tavily_extract", "github_read", "github_search"]);
        cfg.web = table("[providers.tavily]\napi_key = \"{{secret:TAVILY_API_KEY}}\"\n");
        assert_eq!(names(&cfg).len(), 4);
        cfg.web = table("[bogus]\n");
        assert_eq!(names(&cfg), vec!["github_read", "github_search"], "an invalid [web] table must not lose the other tools");
    }
}
