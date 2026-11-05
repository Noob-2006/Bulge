//! Web tools: `web_search`, `web_extract`, `web_fetch`, `x_search`, plus link understanding
//! for inbound channel messages. Hermes `tools/web_tools*.py` + `plugins/web/*` and OpenClaw
//! `src/agents/tools/web-*.ts` + `extensions/*` (web providers), ported onto one config.

pub mod cache;
pub mod cli;
pub mod code_execution;
pub mod config;
pub mod content;
pub mod extract;
pub mod fetch;
pub mod github;
pub mod html;
pub mod http;
pub mod keyless;
pub mod links;
pub mod markdown;
pub mod pdf;
pub mod policy;
pub mod providers;
pub mod readability;
pub mod search;
pub mod ssrf;
pub mod truncate;
pub mod vendor_tools;
pub mod xsearch;

#[cfg(test)]
pub mod testutil;

pub use config::WebConfig;
pub use extract::WebExtract;
pub use fetch::WebFetch;
pub use search::WebSearch;
pub use xsearch::XSearch;

use ark_core::Tool;
use std::sync::Arc;

/// A credential for `id` is configured (`[web.providers.<id>] api_key`, a vault placeholder
/// counts) or present in the environment. Registration-time probe: vault values resolve at call time.
fn has_credential(cfg: &WebConfig, env: &http::EnvFn, id: &str, vars: &[&str]) -> bool {
    cfg.provider(id).get("api_key").and_then(|v| v.as_str()).is_some_and(|k| !k.trim().is_empty()) || vars.iter().any(|v| env(v).is_some_and(|x| !x.trim().is_empty()))
}

/// The model-facing web tools for one `[web]` config (OpenClaw `createOpenClawTools` web
/// section, Hermes `toolsets.web`): `web_fetch`, `web_search`, `web_extract` when enabled;
/// `x_search` when enabled and an xAI key is configured; `firecrawl_search` /
/// `firecrawl_scrape` when Firecrawl is selected or has a key / self-hosted URL.
pub fn tools(cfg: Arc<WebConfig>, env: http::EnvFn) -> Vec<Arc<dyn Tool>> {
    let mut out: Vec<Arc<dyn Tool>> = vec![];
    if cfg.fetch.enabled {
        out.push(Arc::new(WebFetch { cfg: cfg.clone(), env: env.clone() }));
    }
    if cfg.search.enabled {
        out.push(Arc::new(WebSearch { cfg: cfg.clone(), env: env.clone() }));
    }
    if cfg.extract.enabled {
        out.push(Arc::new(WebExtract { cfg: cfg.clone(), env: env.clone() }));
    }
    if cfg.x_search.enabled && has_credential(&cfg, &env, "xai", providers::xai::ENV) {
        out.push(Arc::new(XSearch { cfg: cfg.clone(), env: env.clone() }));
    }
    let firecrawl = cfg.selects("firecrawl") || has_credential(&cfg, &env, "firecrawl", &["FIRECRAWL_API_KEY"]) || cfg.provider("firecrawl").get("base_url").is_some() || ["FIRECRAWL_API_URL", "FIRECRAWL_BASE_URL"].iter().any(|v| env(v).is_some());
    if firecrawl {
        out.push(Arc::new(providers::firecrawl::FirecrawlSearchTool { cfg: cfg.clone(), env: env.clone() }));
        out.push(Arc::new(providers::firecrawl::FirecrawlScrapeTool { cfg: cfg.clone(), env: env.clone() }));
    }
    out
}

/// [`tools`] from the raw `[web]` table (JSON; `Null` = defaults) with the process environment.
pub fn tools_from_value(web: serde_json::Value) -> Result<Vec<Arc<dyn Tool>>, String> {
    Ok(tools(Arc::new(WebConfig::from_value(web)?), http::process_env()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::env_of;
    use serde_json::json;

    fn names(cfg: serde_json::Value, env: &[(&str, &str)]) -> Vec<String> {
        tools(Arc::new(WebConfig::from_value(cfg).unwrap()), env_of(env)).iter().map(|t| t.spec().name).collect()
    }

    #[test]
    fn registration_follows_config_and_credentials() {
        assert_eq!(names(json!({}), &[]), vec!["web_fetch", "web_search", "web_extract"]);
        assert_eq!(names(json!({}), &[("XAI_API_KEY", "xai-k")]), vec!["web_fetch", "web_search", "web_extract", "x_search"]);
        assert_eq!(names(json!({"providers":{"xai":{"api_key":"{{secret:XAI_API_KEY}}"}},"x_search":{"enabled":false}}), &[]), vec!["web_fetch", "web_search", "web_extract"]);
        assert_eq!(names(json!({"providers":{"xai":{"api_key":"{{secret:XAI_API_KEY}}"}}}), &[]).last().unwrap(), "x_search");
        assert_eq!(names(json!({"search":{"provider":"firecrawl"},"fetch":{"enabled":false},"extract":{"enabled":false}}), &[]), vec!["web_search", "firecrawl_search", "firecrawl_scrape"]);
        assert!(names(json!({}), &[("FIRECRAWL_API_KEY", "fc-k")]).contains(&"firecrawl_scrape".to_string()));
        assert!(tools_from_value(json!({"bogus": 1})).is_err());
        for t in tools(Arc::new(WebConfig::from_value(json!({"search":{"provider":"firecrawl"}})).unwrap()), env_of(&[("XAI_API_KEY", "k")])) {
            let s = t.spec();
            assert_eq!(s.input_schema["type"], "object", "{}", s.name);
            assert!(!s.description.is_empty());
        }
    }

    /// The registered `web_search` reaches each bundled backend through config alone
    /// (`[web.search] provider` + `[web.providers.<id>] base_url`), against fake servers.
    #[test]
    fn registered_web_search_reaches_backends() {
        use crate::web::testutil::{search_memo_guard, FakeServer};
        let _memo = search_memo_guard();
        let c = crate::testutil::ctx("web-registered");
        let cases: Vec<(&str, &str, &str, String, &str)> = vec![
            ("searxng", "GET /search", "application/json", json!({"results":[{"title":"S","url":"https://s.example/1","content":"c"}]}).to_string(), ""),
            ("brave", "GET /res/v1/web/search", "application/json", json!({"web":{"results":[{"title":"B","url":"https://b.example/1","description":"d"}]}}).to_string(), "BRAVE_API_KEY"),
            ("tavily", "POST /search", "application/json", json!({"results":[{"title":"T","url":"https://t.example/1","content":"c"}]}).to_string(), "TAVILY_API_KEY"),
            ("exa", "POST /search", "application/json", json!({"results":[{"title":"E","url":"https://e.example/1","text":"c"}]}).to_string(), "EXA_API_KEY"),
        ];
        for (id, route, ct, body, key) in cases {
            cache::search_memo().clear();
            let srv = FakeServer::start(vec![(route, 200, ct, body)]);
            let cfg = json!({"search":{"provider":id},"keyless_rescue":false,"providers":{id:{"base_url":srv.url.clone()}}});
            let env: Vec<(&str, &str)> = if key.is_empty() { vec![] } else { vec![(key, "test-key-123456")] };
            let all = tools(Arc::new(WebConfig::from_value(cfg).unwrap()), env_of(&env));
            let ws = all.iter().find(|t| t.spec().name == "web_search").unwrap();
            let o = ws.call(&c, json!({"query": format!("registered {id}")}));
            assert!(!o.is_error && o.content.contains(&format!("\"provider\": \"{id}\"")), "{id}: {}", o.content);
            assert_eq!(srv.requests().len(), 1, "{id}");
        }
    }
}
