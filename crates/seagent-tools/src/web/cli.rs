//! `seagent web providers`: the `[web]` backends and whether each one can serve a call now
//! (OpenClaw `/tools/web` status view, Hermes `plugins/web` listing). Read-only: no network.

use super::http::WebCtx;
use super::keyless;
use super::providers::{self, WebProvider};

/// One backend as the CLI shows it.
pub struct Row {
    pub id: &'static str,
    pub label: &'static str,
    /// Supports `web_extract` / URL content, not just search.
    pub extract: bool,
    /// Where the credential comes from, or what is missing.
    pub credential: String,
    /// Anonymous free tier (keyless ring member).
    pub keyless: bool,
    /// `[web]` roles this backend is pinned to (`search`, `extract`, `fetch`).
    pub selected: Vec<&'static str>,
    /// Configured, a keyless-ring member, or usable without a key → a call would go out now.
    pub ready: bool,
    /// Position in autodetect order (0 = none: keyless / opt-in only).
    pub autodetect: usize,
}

fn credential(c: &WebCtx, p: &'static dyn WebProvider) -> String {
    if c.opt(p.id(), "api_key").is_some() {
        return format!("key: [web.providers.{}] api_key", p.id());
    }
    let vars = p.env_vars();
    if let Some(v) = vars.iter().find(|v| c.var(v).is_some()) {
        return format!("key: ${v}");
    }
    if vars.is_empty() {
        "no key needed".to_string()
    } else {
        format!("key: missing ({})", vars.join(", "))
    }
}

fn selected_roles(c: &WebCtx, id: &str) -> Vec<&'static str> {
    let mut v = vec![];
    for (role, pin) in [("search", c.cfg.search_pin()), ("extract", c.cfg.extract_pin()), ("fetch", c.cfg.fetch.provider.trim().to_ascii_lowercase())] {
        if let Some(p) = providers::get(&pin) {
            if p.id() == id {
                v.push(role);
            }
        }
    }
    v
}

pub fn rows(c: &WebCtx) -> Vec<Row> {
    let mut auto = 0;
    providers::all()
        .iter()
        .map(|p| {
            let keyless = p.keyless() && keyless::available(c, p.id());
            let ready = p.configured(c) || keyless;
            let at = if p.auto_detect() && p.configured(c) {
                auto += 1;
                auto
            } else {
                0
            };
            Row {
                id: p.id(),
                label: p.label(),
                extract: p.supports_extract(),
                credential: credential(c, *p),
                keyless,
                selected: selected_roles(c, p.id()),
                ready,
                autodetect: at,
            }
        })
        .collect()
}

/// The header line: what search / extract / fetch resolve to right now.
fn routing(c: &WebCtx) -> String {
    let pick = |pin: String| -> String {
        if let Some(p) = providers::get(&pin) {
            return p.id().to_string();
        }
        if !pin.is_empty() {
            return format!("{pin} (unknown)");
        }
        match super::search::resolve(c) {
            Ok(r) => format!("{} (autodetect)", r.id()),
            Err(_) => "keyless".to_string(),
        }
    };
    let extract = match (c.cfg.extract_pin().as_str(), super::extract::resolve(c)) {
        ("", Ok(r)) => format!("{} (autodetect)", r.id()),
        (_, Ok(r)) => r.id().to_string(),
        (_, Err(e)) => e,
    };
    let fetch = match c.cfg.fetch.provider.trim() {
        "" => "auto (Firecrawl fallback when configured)",
        p => p,
    };
    format!("search: {}  ·  extract: {extract}  ·  fetch: {fetch}\n", pick(c.cfg.search_pin()))
}

pub fn render(c: &WebCtx) -> String {
    let mut out = format!("web providers ({})\n", providers::all().len());
    out.push_str(&routing(c));
    // Longest label / credential keeps the columns aligned.
    let listed = rows(c);
    let w = providers::all().iter().map(|p| p.label().len()).max().unwrap_or(20).min(40);
    let cw = listed.iter().map(|r| r.credential.len()).max().unwrap_or(20).min(60);
    out.push_str(&format!("{:<13} {:<w$} {:<8} {:<cw$} {}\n", "id", "label", "supports", "credential", "state", w = w, cw = cw));
    for r in listed {
        let supports = if r.extract { "search+" } else { "search" };
        let mut state = if r.ready { "ready".to_string() } else { "not configured".to_string() };
        if r.keyless {
            state.push_str(", keyless tier");
        }
        if r.autodetect > 0 {
            state.push_str(&format!(", autodetect #{}{}", r.autodetect, if r.autodetect == 1 { " ← used" } else { "" }));
        }
        if !r.selected.is_empty() {
            state.push_str(&format!(", selected for {}", r.selected.join("+")));
        }
        out.push_str(&format!("{:<13} {:<w$} {:<8} {:<cw$} {}\n", r.id, r.label, supports, r.credential, state, w = w, cw = cw));
    }
    out.push_str(&format!("\nkeyless ring: {} (round-robin, last resort; web.keyless_fallback = {})\n", keyless::RING.join(", "), c.cfg.keyless_fallback));
    out.push_str(&format!("cache: {} (search memo in memory, extract/fetch on disk; TTL {}s)\n", if c.cfg.cache_enabled { "on" } else { "off" }, c.cfg.ttl_secs()));
    out.push_str("Configure with [web.search] provider, [web.extract] provider and [web.providers.<id>] api_key / base_url; `local` = seagent's own readable fetch.\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::wctx;
    use serde_json::json;

    #[test]
    fn lists_every_backend_with_credential_and_availability() {
        let c = wctx(json!({}), &[("BRAVE_API_KEY", "brave-k")]);
        let listed = rows(&c);
        assert_eq!(listed.len(), providers::all().len());
        assert_eq!(listed.iter().map(|r| r.id).collect::<Vec<_>>(), providers::all().iter().map(|p| p.id()).collect::<Vec<_>>());
        let row = |id: &str| listed.iter().find(|r| r.id == id).unwrap();
        assert_eq!(row("brave").credential, "key: $BRAVE_API_KEY");
        assert!(row("brave").ready && row("brave").autodetect == 1, "the first configured provider is the autodetect pick");
        assert_eq!(row("tavily").credential, "key: missing (TAVILY_API_KEY)");
        assert!(!row("tavily").ready);
        assert_eq!(row("duckduckgo").credential, "no key needed");
        assert!(row("duckduckgo").ready && row("duckduckgo").autodetect == 0);
        assert!(row("exa").keyless && row("exa").ready, "keyless ring members can serve without a key");
        assert!(row("tavily").extract && !row("brave").extract, "only the URL backends list extract");
        // A pinned backend is shown as selected; config credentials count.
        let c = wctx(json!({"search":{"provider":"exa"},"extract":{"provider":"tavily"},"providers":{"exa":{"api_key":"ex-key"}}}), &[]);
        let listed = rows(&c);
        let row = |id: &str| listed.iter().find(|r| r.id == id).unwrap();
        assert_eq!(row("exa").selected, vec!["search"]);
        assert_eq!(row("exa").credential, "key: [web.providers.exa] api_key");
        assert!(row("exa").ready && row("exa").keyless, "a keyed ring member keeps its anonymous free tier");
        assert_eq!(row("tavily").selected, vec!["extract"]);
        let text = render(&c);
        assert!(text.contains("web providers (") && text.contains("search: exa") && text.contains("extract: tavily"), "{text}");
        assert!(text.contains("keyless ring: exa, parallel, firecrawl, keenable"), "{text}");
        for p in providers::all() {
            assert!(text.contains(p.id()), "{} missing from the listing", p.id());
        }
    }

    #[test]
    fn keyless_and_disabled_states() {
        let c = wctx(json!({"keyless_fallback":false}), &[]);
        let listed = rows(&c);
        assert!(!listed.iter().any(|r| r.id == "exa" && r.keyless), "keyless ring off");
        assert!(render(&c).contains("web.keyless_fallback = false"));
        let c = wctx(json!({"extract":{"provider":"local"},"search":{"provider":"nope"}}), &[]);
        let text = render(&c);
        assert!(text.contains("extract: local"), "{text}");
        assert!(text.contains("nope (unknown)"), "{text}");
    }
}
