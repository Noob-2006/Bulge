//! Web search / extract backends. One file per vendor; each implements `WebProvider`
//! against the vendor's documented HTTP API. The registry order is the autodetect order
//! (OpenClaw `autoDetectOrder`, Hermes `_autodetect_backend`).

use super::http::WebCtx;
use serde::Serialize;

pub mod brave;
pub mod codex;
pub mod deepseek;
pub mod duckduckgo;
pub mod exa;
pub mod firecrawl;
pub mod gemini;
pub mod keenable;
pub mod kimi;
pub mod minimax;
pub mod ollama;
pub mod openai_native;
pub mod parallel;
pub mod perplexity;
pub mod searxng;
pub mod tavily;
pub mod xai;

/// What the model asked for. `count` is already clamped to 1..=100.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SearchRequest {
    pub query: String,
    pub count: usize,
    pub country: Option<String>,
    pub language: Option<String>,
    /// `day` | `week` | `month` | `year` (or Brave `pd`/`pw`/… / `YYYY-MM-DDtoYYYY-MM-DD`).
    pub freshness: Option<String>,
    pub date_after: Option<String>,
    pub date_before: Option<String>,
    pub search_lang: Option<String>,
    pub ui_lang: Option<String>,
    pub domain_filter: Vec<String>,
    pub max_tokens: Option<u64>,
    pub max_tokens_per_page: Option<u64>,
    /// Provider-specific arguments (`categories`, `topic`, `search_depth`, …) passed through as given.
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl SearchRequest {
    pub fn extra_str(&self, k: &str) -> Option<String> {
        self.extra.get(k).and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Hit {
    pub title: String,
    pub url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub snippet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    #[serde(rename = "siteName", skip_serializing_if = "Option::is_none")]
    pub site_name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Citation {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SearchOutput {
    /// A ranked result list (Brave, Tavily, Exa, …).
    Results(Vec<Hit>),
    /// A synthesized answer with sources (Gemini grounding, Kimi, Grok, Perplexity Sonar, …).
    Answer { content: String, citations: Vec<Citation> },
}

/// One extracted page. `error` set = this URL failed (others may have succeeded).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Page {
    pub url: String,
    pub title: String,
    pub content: String,
    pub error: Option<String>,
    /// The URL that was requested when `url` is a redirect target.
    pub source_url: Option<String>,
}

impl Page {
    pub fn ok(url: &str, title: &str, content: &str) -> Page {
        Page { url: url.into(), title: title.into(), content: content.into(), ..Default::default() }
    }
    pub fn err(url: &str, e: impl Into<String>) -> Page {
        Page { url: url.into(), error: Some(e.into()), ..Default::default() }
    }
}

pub trait WebProvider: Send + Sync {
    /// Config id (`web.search.provider = "<id>"`).
    fn id(&self) -> &'static str;
    fn label(&self) -> &'static str;
    /// Other names accepted in config (`brave-free`, `ddgs`, …).
    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }
    /// Env vars carrying the credential, first set wins (also looked up in the vault).
    fn env_vars(&self) -> &'static [&'static str] {
        &[]
    }
    /// Usable without network I/O: credential or endpoint configured.
    fn configured(&self, c: &WebCtx) -> bool;
    /// Picked by autodetect when configured (keyless or local-only providers say no).
    fn auto_detect(&self) -> bool {
        true
    }
    /// Member of the anonymous keyless ring (Hermes `KEYLESS`).
    fn keyless(&self) -> bool {
        false
    }
    /// Optional filters this provider honours (`country`, `language`, `freshness`, `date_after`,
    /// `date_before`, `search_lang`, `ui_lang`, `domain_filter`, `max_tokens`, `max_tokens_per_page`).
    fn filters(&self) -> &'static [&'static str] {
        &[]
    }
    /// The URL the search request goes to (shown to the egress gate).
    fn endpoint(&self, c: &WebCtx) -> String;
    fn search(&self, c: &WebCtx, r: &SearchRequest) -> Result<SearchOutput, String>;
    fn supports_extract(&self) -> bool {
        false
    }
    /// Extract page contents; per-URL failures are `Page::err`, a whole-call failure is `Err`.
    fn extract(&self, _c: &WebCtx, _urls: &[String]) -> Result<Vec<Page>, String> {
        Err(format!("{} is a search-only backend and cannot extract URL content", self.label()))
    }
    /// This call would go through the anonymous keyless ring (so a failure means the ring
    /// already failed and a rescue is pointless).
    fn routes_keyless(&self, c: &WebCtx) -> bool {
        self.keyless() && super::keyless::use_keyless(c, self.id(), c.key(self.id(), self.env_vars()).as_deref())
    }
    /// Signup / docs URL for setup hints.
    fn signup_url(&self) -> &'static str {
        ""
    }
}

/// Every bundled provider in autodetect order.
pub fn all() -> &'static [&'static dyn WebProvider] {
    static ALL: &[&dyn WebProvider] = &[
        &brave::Brave,
        &minimax::Minimax,
        &gemini::Gemini,
        &xai::Xai,
        &kimi::Kimi,
        &perplexity::Perplexity,
        &firecrawl::Firecrawl,
        &exa::Exa,
        &tavily::Tavily,
        &parallel::Parallel,
        &keenable::Keenable,
        &deepseek::DeepSeek,
        &duckduckgo::DuckDuckGo,
        &ollama::Ollama,
        &searxng::Searxng,
        &openai_native::OpenAiNative,
        &codex::Codex,
    ];
    ALL
}

pub fn get(id: &str) -> Option<&'static dyn WebProvider> {
    let id = id.trim().to_ascii_lowercase();
    all().iter().copied().find(|p| p.id() == id || p.aliases().contains(&id.as_str())).or_else(|| registered().into_iter().find(|p| names(*p).iter().any(|n| n == &id)))
}

// ── runtime registration (Hermes `PluginContext.register_web_search_provider`) ─────────────────

/// Backends added at runtime by plugins (Hermes `agent/web_search_provider.py`
/// `register_web_search_provider()`): one `WebProvider` per `plugins/web/<name>/`. Bundled names —
/// both ids and aliases — are reserved and always win, and `all()` (the autodetect order) is never
/// extended, so a registered backend is only used when config names it (`[web.search] provider` or
/// `[web.extract] provider` = its id).
fn dynamic() -> &'static std::sync::RwLock<Vec<&'static dyn WebProvider>> {
    static DYN: std::sync::OnceLock<std::sync::RwLock<Vec<&'static dyn WebProvider>>> = std::sync::OnceLock::new();
    DYN.get_or_init(|| std::sync::RwLock::new(Vec::new()))
}

/// Lower-cased names a provider answers to (its id + aliases), trimmed; empty entries dropped.
fn names(p: &dyn WebProvider) -> Vec<String> {
    std::iter::once(p.id()).chain(p.aliases().iter().copied()).map(|n| n.trim().to_ascii_lowercase()).filter(|n| !n.is_empty()).collect()
}

fn bundled(name: &str) -> bool {
    all().iter().any(|p| names(*p).iter().any(|n| n == name))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Register a provider at runtime (a plugin backend): leaked so the table keeps `&'static`.
pub fn register(p: Box<dyn WebProvider>) -> Result<(), String> {
    let id = p.id().trim().to_ascii_lowercase();
    if !valid_name(&id) {
        return Err(format!("invalid web search provider id `{}`: expected a non-empty trimmed id matching [a-z0-9_-]", p.id()));
    }
    let mut aliases: Vec<String> = p.aliases().iter().map(|n| n.trim().to_ascii_lowercase()).filter(|n| !n.is_empty() && n != &id).collect();
    aliases.dedup();
    for n in std::iter::once(&id).chain(aliases.iter()) {
        if !valid_name(n) {
            return Err(format!("invalid web search provider name `{n}` for `{id}`: expected [a-z0-9_-]"));
        }
        if bundled(n) {
            return Err(format!("web search provider name `{n}` is reserved by a bundled backend; bundled ids and aliases cannot be registered"));
        }
    }
    let mut reg = dynamic().write().unwrap_or_else(|e| e.into_inner());
    for other in reg.iter() {
        if other.id().trim().eq_ignore_ascii_case(&id) {
            continue;
        }
        if let Some(n) = names(&**other).into_iter().find(|n| n == &id || aliases.contains(n)) {
            return Err(format!("web search provider name `{n}` is already registered by `{}`", other.id()));
        }
    }
    reg.retain(|q| !q.id().trim().eq_ignore_ascii_case(&id));
    reg.push(Box::leak(p));
    Ok(())
}

/// Providers registered at runtime, in registration order. Never part of `all()`.
pub fn registered() -> Vec<&'static dyn WebProvider> {
    dynamic().read().unwrap_or_else(|e| e.into_inner()).clone()
}

// ── shared filter helpers (OpenClaw web-search-provider-common.ts) ─────────────

pub const DOCS: &str = "https://docs.openclaw.ai/tools/web";

/// `day/week/month/year` ⇄ Brave `pd/pw/pm/py`; Brave also takes `YYYY-MM-DDtoYYYY-MM-DD`.
pub fn normalize_freshness(value: &str, provider: &str) -> Option<String> {
    let v = value.trim().to_ascii_lowercase();
    let pairs = [("pd", "day"), ("pw", "week"), ("pm", "month"), ("py", "year")];
    if let Some((short, long)) = pairs.iter().find(|(s, l)| *s == v || *l == v) {
        return Some(if provider == "brave" { short } else { long }.to_string());
    }
    if provider == "brave" {
        if let Some((a, b)) = v.split_once("to") {
            if valid_iso_date(a) && valid_iso_date(b) && a <= b {
                return Some(format!("{a}to{b}"));
            }
        }
    }
    None
}

pub fn valid_iso_date(s: &str) -> bool {
    let p: Vec<&str> = s.split('-').collect();
    if p.len() != 3 || p[0].len() != 4 || p[1].len() != 2 || p[2].len() != 2 || !p.iter().all(|x| x.chars().all(|c| c.is_ascii_digit())) {
        return false;
    }
    let (y, m, d): (i32, u32, u32) = (p[0].parse().unwrap(), p[1].parse().unwrap(), p[2].parse().unwrap());
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    (1..=12).contains(&m) && d >= 1 && d <= days[(m - 1) as usize]
}

/// ISO `YYYY-MM-DD` or Perplexity `M/D/YYYY` → ISO.
pub fn normalize_iso_date(v: &str) -> Option<String> {
    let t = v.trim();
    if let [m, d, y] = t.split('/').collect::<Vec<_>>()[..] {
        if y.len() == 4 && (1..=2).contains(&m.len()) && (1..=2).contains(&d.len()) {
            let iso = format!("{y}-{m:0>2}-{d:0>2}");
            return valid_iso_date(&iso).then_some(iso);
        }
        return None;
    }
    valid_iso_date(t).then(|| t.to_string())
}

/// ISO → Perplexity `M/D/YYYY`.
pub fn iso_to_mdy(iso: &str) -> Option<String> {
    let p: Vec<&str> = iso.split('-').collect();
    if p.len() != 3 {
        return None;
    }
    Some(format!("{}/{}/{}", p[1].parse::<u32>().ok()?, p[2].parse::<u32>().ok()?, p[0]))
}

/// Parsed time filters, or a provider-facing validation message.
#[derive(Debug, Default, PartialEq)]
pub struct TimeFilters {
    pub freshness: Option<String>,
    pub date_after: Option<String>,
    pub date_before: Option<String>,
}

pub fn parse_time_filters(r: &SearchRequest, provider: &str) -> Result<TimeFilters, String> {
    let mut t = TimeFilters::default();
    if let Some(f) = r.freshness.as_deref().filter(|f| !f.trim().is_empty()) {
        t.freshness = Some(normalize_freshness(f, provider).ok_or_else(|| {
            if provider == "brave" {
                "freshness must be day, week, month, or year (or pd/pw/pm/py, or YYYY-MM-DDtoYYYY-MM-DD).".to_string()
            } else {
                "freshness must be day, week, month, or year.".to_string()
            }
        })?);
        if r.date_after.is_some() || r.date_before.is_some() {
            return Err("freshness and date_after/date_before cannot be used together. Use either freshness (day/week/month/year) or a date range (date_after/date_before), not both.".into());
        }
    }
    if let Some(a) = r.date_after.as_deref().filter(|a| !a.trim().is_empty()) {
        t.date_after = Some(normalize_iso_date(a).ok_or("date_after must be YYYY-MM-DD format.")?);
    }
    if let Some(b) = r.date_before.as_deref().filter(|b| !b.trim().is_empty()) {
        t.date_before = Some(normalize_iso_date(b).ok_or("date_before must be YYYY-MM-DD format.")?);
    }
    if let (Some(a), Some(b)) = (&t.date_after, &t.date_before) {
        if a > b {
            return Err("date_after must be before date_before.".into());
        }
    }
    Ok(t)
}

/// Hostname of a URL (for `siteName`).
pub fn site_name(url: &str) -> Option<String> {
    super::ssrf::parse_url(url).ok().map(|u| u.host).filter(|h| !h.is_empty())
}

/// Plain hit with siteName filled in.
pub fn hit(title: &str, url: &str, snippet: &str) -> Hit {
    Hit { title: title.trim().into(), url: url.trim().into(), snippet: snippet.trim().into(), published: None, site_name: site_name(url) }
}

/// `Authorization: Bearer <key>` header pair.
pub fn bearer(key: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {key}"))
}

/// Missing-credential message shared by keyed providers.
pub fn missing_key(label: &str, env: &str, url: &str) -> String {
    if url.is_empty() {
        format!("{label} needs an API key: set {env} or [web.providers] api_key.")
    } else {
        format!("{label} needs an API key: set {env} or [web.providers] api_key. Get one at {url}")
    }
}

/// URL-citation annotations + `citations` arrays from OpenAI/xAI Responses payloads.
pub fn responses_text_and_citations(v: &serde_json::Value) -> (String, Vec<Citation>) {
    let mut text = v.get("output_text").and_then(|t| t.as_str()).unwrap_or("").trim().to_string();
    let mut cites: Vec<Citation> = Vec::new();
    let mut parts = Vec::new();
    for item in v.get("output").and_then(|o| o.as_array()).into_iter().flatten() {
        if item.get("type").and_then(|t| t.as_str()) != Some("message") {
            continue;
        }
        for c in item.get("content").and_then(|c| c.as_array()).into_iter().flatten() {
            if matches!(c.get("type").and_then(|t| t.as_str()), Some("output_text" | "text")) {
                if let Some(t) = c.get("text").and_then(|t| t.as_str()) {
                    parts.push(t.trim().to_string());
                }
                for a in c.get("annotations").and_then(|a| a.as_array()).into_iter().flatten() {
                    if a.get("type").and_then(|t| t.as_str()) == Some("url_citation") {
                        let url = super::http::s(a, "url");
                        if !url.is_empty() && !cites.iter().any(|x| x.url == url) {
                            let title = super::http::s(a, "title");
                            cites.push(Citation { url, title: (!title.is_empty()).then_some(title) });
                        }
                    }
                }
            }
        }
    }
    if text.is_empty() {
        text = parts.into_iter().filter(|p| !p.is_empty()).collect::<Vec<_>>().join("\n\n");
    }
    for c in v.get("citations").and_then(|c| c.as_array()).into_iter().flatten() {
        let url = c.as_str().map(str::to_string).unwrap_or_else(|| super::http::s(c, "url"));
        if !url.is_empty() && !cites.iter().any(|x| x.url == url) {
            cites.push(Citation { url, title: None });
        }
    }
    (text, cites)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plugin-supplied backend: answers locally, no network, never autodetected.
    struct Fake;

    impl WebProvider for Fake {
        fn id(&self) -> &'static str {
            "fake-acme"
        }
        fn label(&self) -> &'static str {
            "Fake Acme"
        }
        fn aliases(&self) -> &'static [&'static str] {
            &["acme-free"]
        }
        fn configured(&self, _c: &WebCtx) -> bool {
            true
        }
        fn auto_detect(&self) -> bool {
            false
        }
        fn endpoint(&self, _c: &WebCtx) -> String {
            "http://127.0.0.1:9/search".into()
        }
        fn search(&self, _c: &WebCtx, _r: &SearchRequest) -> Result<SearchOutput, String> {
            Ok(SearchOutput::Results(vec![Hit { title: "ok".into(), url: "https://example.test/".into(), ..Default::default() }]))
        }
    }

    /// Same id as `Fake`: the later registration replaces it.
    struct Fake2;

    impl WebProvider for Fake2 {
        fn id(&self) -> &'static str {
            "fake-acme"
        }
        fn label(&self) -> &'static str {
            "Fake Acme 2"
        }
        fn aliases(&self) -> &'static [&'static str] {
            &["acme-free"]
        }
        fn configured(&self, _c: &WebCtx) -> bool {
            true
        }
        fn auto_detect(&self) -> bool {
            false
        }
        fn endpoint(&self, _c: &WebCtx) -> String {
            "http://127.0.0.1:9/search".into()
        }
        fn search(&self, _c: &WebCtx, _r: &SearchRequest) -> Result<SearchOutput, String> {
            Ok(SearchOutput::Results(vec![Hit { title: "ok".into(), url: "https://example.test/".into(), ..Default::default() }]))
        }
    }

    /// A would-be registration under a name the bundled table owns.
    struct Reserved(&'static str);

    impl WebProvider for Reserved {
        fn id(&self) -> &'static str {
            self.0
        }
        fn label(&self) -> &'static str {
            "Reserved"
        }
        fn configured(&self, _c: &WebCtx) -> bool {
            false
        }
        fn endpoint(&self, _c: &WebCtx) -> String {
            String::new()
        }
        fn search(&self, _c: &WebCtx, _r: &SearchRequest) -> Result<SearchOutput, String> {
            Err("unused".into())
        }
    }

    #[test]
    fn dynamic_registration_resolves_by_id_and_alias() {
        register(Box::new(Fake)).expect("register");
        for name in ["fake-acme", "FAKE-ACME", " fake-acme ", "acme-free", "ACME-FREE"] {
            assert_eq!(get(name).map(|p| p.id()), Some("fake-acme"), "{name}");
        }
        assert_eq!(get("fake-acme").unwrap().label(), "Fake Acme");
        assert!(registered().iter().any(|p| p.id() == "fake-acme"));
        // `all()` stays the bundled autodetect order.
        assert!(!all().iter().any(|p| p.id() == "fake-acme"));
        // Replace an earlier registration with the same id.
        register(Box::new(Fake2)).expect("replace");
        assert_eq!(get("fake-acme").unwrap().label(), "Fake Acme 2");
        assert_eq!(registered().iter().filter(|p| p.id() == "fake-acme").count(), 1);
    }

    #[test]
    fn dynamic_registration_rejects_bundled_names() {
        for name in ["brave", "Brave", "ddgs", "duckduckgo", "searxng"] {
            let e = register(Box::new(Reserved(name))).unwrap_err();
            assert!(e.contains("reserved"), "{name}: {e}");
        }
        // An alias colliding with a bundled alias is rejected too.
        let e = register(Box::new(ReservedAlias)).unwrap_err();
        assert!(e.contains("reserved"), "{e}");
    }

    /// id is free, alias is not.
    struct ReservedAlias;

    impl WebProvider for ReservedAlias {
        fn id(&self) -> &'static str {
            "fake-two"
        }
        fn label(&self) -> &'static str {
            "Fake Two"
        }
        fn aliases(&self) -> &'static [&'static str] {
            &["ddgs"]
        }
        fn configured(&self, _c: &WebCtx) -> bool {
            false
        }
        fn endpoint(&self, _c: &WebCtx) -> String {
            String::new()
        }
        fn search(&self, _c: &WebCtx, _r: &SearchRequest) -> Result<SearchOutput, String> {
            Err("unused".into())
        }
    }

    /// End to end: `{"search":{"provider":"fake-acme"}}` selects the plugin backend.
    #[test]
    fn dynamic_provider_serves_web_search() {
        use ark_core::Tool;
        register(Box::new(Fake)).expect("register");
        let cfg = serde_json::json!({"search":{"provider":"fake-acme"},"keyless_fallback":false,"keyless_rescue":false,"cache_ttl_minutes":0,"providers":{"fake-acme":{}}});
        let t = crate::web::WebSearch { cfg: std::sync::Arc::new(crate::web::WebConfig::from_value(cfg).unwrap()), env: crate::web::testutil::env_of(&[]) };
        let c = crate::testutil::ctx("websearch-dynamic");
        let o = t.call(&c, serde_json::json!({"query":"dynamic seam probe","count":1}));
        assert!(!o.is_error, "{}", o.content);
        assert!(o.content.contains("https://example.test/"), "{}", o.content);
        // Registered backends are never autodetected: an empty config still picks the keyless ring.
        assert_eq!(crate::web::search::resolve(&crate::web::testutil::wctx(serde_json::json!({}), &[])).unwrap().id(), "keyless");
    }

    #[test]
    fn registry_ids_unique_and_resolvable() {
        let mut seen = std::collections::HashSet::new();
        for p in all() {
            assert!(seen.insert(p.id()), "{}", p.id());
            for a in p.aliases() {
                assert!(seen.insert(a), "{a}");
            }
            assert_eq!(get(p.id()).unwrap().id(), p.id());
            assert!(!p.label().is_empty());
        }
        assert!(get("nope").is_none());
    }

    #[test]
    fn time_filters() {
        assert_eq!(normalize_freshness("week", "brave").as_deref(), Some("pw"));
        assert_eq!(normalize_freshness("pm", "perplexity").as_deref(), Some("month"));
        assert_eq!(normalize_freshness("2024-01-01to2024-02-01", "brave").as_deref(), Some("2024-01-01to2024-02-01"));
        assert!(normalize_freshness("2024-02-01to2024-01-01", "brave").is_none());
        assert!(normalize_freshness("2024-01-01to2024-02-01", "perplexity").is_none());
        assert_eq!(normalize_iso_date("3/7/2025").as_deref(), Some("2025-03-07"));
        assert!(normalize_iso_date("2025-02-30").is_none() && normalize_iso_date("2024-02-29").is_some());
        assert_eq!(iso_to_mdy("2025-03-07").as_deref(), Some("3/7/2025"));
        let r = |f: Option<&str>, a: Option<&str>, b: Option<&str>| SearchRequest { freshness: f.map(Into::into), date_after: a.map(Into::into), date_before: b.map(Into::into), ..Default::default() };
        assert!(parse_time_filters(&r(Some("day"), Some("2025-01-01"), None), "brave").unwrap_err().contains("cannot be used together"));
        assert!(parse_time_filters(&r(None, Some("2025-02-01"), Some("2025-01-01")), "brave").unwrap_err().contains("before"));
        assert!(parse_time_filters(&r(Some("fortnight"), None, None), "perplexity").unwrap_err().contains("freshness"));
        assert_eq!(parse_time_filters(&r(None, Some("1/2/2025"), None), "perplexity").unwrap().date_after.as_deref(), Some("2025-01-02"));
    }

    #[test]
    fn responses_payload_parsing() {
        let v = serde_json::json!({"output":[{"type":"web_search_call"},{"type":"message","content":[{"type":"output_text","text":"Answer.","annotations":[{"type":"url_citation","url":"https://a.com","title":"A"},{"type":"url_citation","url":"https://a.com"}]}]}],"citations":["https://b.com"]});
        let (t, c) = responses_text_and_citations(&v);
        assert_eq!(t, "Answer.");
        assert_eq!(c, vec![Citation { url: "https://a.com".into(), title: Some("A".into()) }, Citation { url: "https://b.com".into(), title: None }]);
        assert_eq!(hit(" T ", "https://x.org/p", "s").site_name.as_deref(), Some("x.org"));
    }
}
