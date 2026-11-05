//! Live web-provider smoke tests (gen1-307): one real request per search provider.
//!
//! Every other web test talks to `web::testutil::FakeServer`. These hit the real APIs, so they
//! are `#[ignore]` **and** need both the opt-in and the provider's own key:
//!
//! ```sh
//! SEAGENT_LIVE_PROVIDERS=1 BRAVE_API_KEY=… TAVILY_API_KEY=… \
//!   cargo test -p seagent-tools --test live_web_providers -- --ignored --test-threads=1
//! # or: tests/real/live_providers.sh
//! ```
//!
//! A provider without a key prints `SKIPPED <provider>: <VAR> not set` and passes. Nothing is
//! sent anywhere without `SEAGENT_LIVE_PROVIDERS=1`. Each case costs one search request.

use seagent_core::{Cancel, ToolCtx, ToolHost};
use serde_json::{json, Value};
use std::sync::Arc;

struct NoHost;
impl ToolHost for NoHost {
    fn spawn_agent(&self, _: seagent_core::tool::SpawnRequest, _: &Cancel) -> Result<String, String> {
        Err("no".into())
    }
    fn ask_user(&self, _: &str) -> Result<String, String> {
        Err("no".into())
    }
}

fn key(vars: &[&str]) -> Option<String> {
    vars.iter().find_map(|v| std::env::var(v).ok().filter(|x| !x.trim().is_empty()))
}

/// `Some(())` when this provider should run now; prints why not otherwise.
fn gate(provider: &str, vars: &[&str]) -> Option<()> {
    if std::env::var("SEAGENT_LIVE_PROVIDERS").ok().as_deref() != Some("1") {
        eprintln!("SKIPPED {provider}: set SEAGENT_LIVE_PROVIDERS=1 to call real provider APIs");
        return None;
    }
    if key(vars).is_none() {
        eprintln!("SKIPPED {provider}: {} not set", vars.join(" / "));
        return None;
    }
    Some(())
}

fn search(provider: &str) -> Value {
    let dir = seagent_core::tmp::TempDir::new("seagent-live-web");
    let tools = seagent_tools::web::tools_from_value(json!({"search": {"provider": provider}})).unwrap();
    let t = tools.iter().find(|t| t.spec().name == "web_search").expect("web_search");
    let ctx = ToolCtx { workspace: dir.path().into(), session_id: "live".into(), artifacts: dir.path().join("art"), home: dir.path().into(), cancel: Cancel::new(), host: Arc::new(NoHost), secrets: Arc::new(|s: &str| s.to_string()) };
    let o = t.call(&ctx, json!({"query": "Rust programming language official site", "count": 3}));
    assert!(!o.is_error, "{provider}: {}", o.content);
    let v: Value = serde_json::from_str(&o.content).unwrap_or_else(|_| json!({"raw": o.content}));
    let text = v.to_string();
    assert!(text.contains("http"), "{provider}: no result URLs: {}", &text[..text.len().min(600)]);
    eprintln!("{provider}: ok ({} bytes)", text.len());
    v
}

macro_rules! live {
    ($name:ident, $provider:literal, [$($var:literal),+]) => {
        #[test]
        #[ignore]
        fn $name() {
            if gate($provider, &[$($var),+]).is_some() {
                search($provider);
            }
        }
    };
}

live!(live_brave, "brave", ["BRAVE_API_KEY", "BRAVE_SEARCH_API_KEY"]);
live!(live_tavily, "tavily", ["TAVILY_API_KEY"]);
live!(live_exa, "exa", ["EXA_API_KEY"]);
live!(live_firecrawl, "firecrawl", ["FIRECRAWL_API_KEY"]);
live!(live_perplexity, "perplexity", ["PERPLEXITY_API_KEY", "OPENROUTER_API_KEY"]);
live!(live_parallel, "parallel", ["PARALLEL_API_KEY"]);
live!(live_xai, "xai", ["XAI_API_KEY"]);

/// The keyless default needs no key, only the opt-in.
#[test]
#[ignore]
fn live_duckduckgo_keyless() {
    if std::env::var("SEAGENT_LIVE_PROVIDERS").ok().as_deref() != Some("1") {
        eprintln!("SKIPPED duckduckgo: set SEAGENT_LIVE_PROVIDERS=1");
        return;
    }
    search("duckduckgo");
}
