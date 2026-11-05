//! `[tools.tool_search]`: BM25 search over the tool index (Hermes `tool_search`,
//! OpenClaw deferred tool catalog). Unpinned tools are reached through
//! `tool_describe` / `tool_call`; this lets the model find them by keyword instead of
//! scanning the whole index.

use seagent_core::ToolSpec;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// `[tools.tool_search]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ToolSearchConfig {
    /// Offer the BM25 `tool_search` query over unpinned tools (default true).
    pub enabled: bool,
    /// Maximum hits returned per query (default 5).
    pub max_results: usize,
    /// BM25 term-frequency saturation (default 1.2).
    pub k1: f64,
    /// BM25 length normalisation (default 0.75).
    pub b: f64,
}

impl Default for ToolSearchConfig {
    fn default() -> Self {
        ToolSearchConfig { enabled: true, max_results: 5, k1: 1.2, b: 0.75 }
    }
}

/// Lower-cased alphanumeric tokens; `snake_case` / `kebab-case` names also split into parts
/// (the whole name is kept as a token too, so exact-name queries rank first).
pub fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for word in s.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '-')).filter(|w| !w.is_empty()) {
        let w = word.to_lowercase();
        let parts: Vec<&str> = w.split(['_', '-']).filter(|p| !p.is_empty()).collect();
        if parts.len() > 1 {
            out.extend(parts.iter().map(|p| p.to_string()));
        }
        let joined = w.trim_matches(['_', '-']).to_string();
        if !joined.is_empty() {
            out.push(joined);
        }
    }
    out
}

/// One search hit.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub name: String,
    pub summary: String,
    pub score: f64,
}

/// An immutable BM25 index over tool names + descriptions.
#[derive(Debug, Clone, Default)]
pub struct Index {
    docs: Vec<(String, String, HashMap<String, u32>, usize)>,
    df: HashMap<String, u32>,
    avg_len: f64,
}

impl Index {
    pub fn new(specs: &[ToolSpec]) -> Index {
        let mut docs = Vec::with_capacity(specs.len());
        let mut df: HashMap<String, u32> = HashMap::new();
        let mut total = 0usize;
        for s in specs {
            // The name counts twice: it is the strongest signal.
            let mut toks = tokenize(&s.name);
            toks.extend(tokenize(&s.name));
            toks.extend(tokenize(&s.description));
            let mut tf: HashMap<String, u32> = HashMap::new();
            for t in &toks {
                *tf.entry(t.clone()).or_default() += 1;
            }
            for t in tf.keys() {
                *df.entry(t.clone()).or_default() += 1;
            }
            total += toks.len();
            docs.push((s.name.clone(), s.summary().to_string(), tf, toks.len()));
        }
        let avg_len = if docs.is_empty() { 0.0 } else { total as f64 / docs.len() as f64 };
        Index { docs, df, avg_len }
    }

    pub fn len(&self) -> usize {
        self.docs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }

    /// Top hits for `query` (score > 0), best first; ties break by name.
    pub fn search(&self, query: &str, cfg: &ToolSearchConfig) -> Vec<Hit> {
        let q = tokenize(query);
        if q.is_empty() || self.docs.is_empty() {
            return vec![];
        }
        let n = self.docs.len() as f64;
        let mut hits: Vec<Hit> = self
            .docs
            .iter()
            .filter_map(|(name, summary, tf, len)| {
                let mut score = 0.0;
                for t in &q {
                    let Some(&f) = tf.get(t) else { continue };
                    let df = *self.df.get(t).unwrap_or(&0) as f64;
                    let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
                    let f = f as f64;
                    let norm = 1.0 - cfg.b + cfg.b * (*len as f64) / self.avg_len.max(1.0);
                    score += idf * f * (cfg.k1 + 1.0) / (f + cfg.k1 * norm);
                }
                (score > 0.0).then(|| Hit { name: name.clone(), summary: summary.clone(), score })
            })
            .collect();
        hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.name.cmp(&b.name)));
        hits.truncate(cfg.max_results.max(1));
        hits
    }
}

/// Render hits as the tool's text result.
pub fn render(hits: &[Hit]) -> String {
    if hits.is_empty() {
        return "No matching tools. Try other keywords, or read the tool index.".into();
    }
    let mut s = String::new();
    for h in hits {
        s.push_str(&format!("- {}: {}\n", h.name, h.summary));
    }
    s.push_str("Use tool_describe for full schemas, then tool_call.");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str, d: &str) -> ToolSpec {
        ToolSpec { name: name.into(), description: d.into(), input_schema: serde_json::json!({}), parallel_safe: false, idempotent: false, pinned: false }
    }

    #[test]
    fn tokenize_splits_snake_case() {
        assert_eq!(tokenize("web_fetch URL"), vec!["web", "fetch", "web_fetch", "url"]);
        assert!(tokenize("  ,, ").is_empty());
    }

    #[test]
    fn bm25_ranks_relevant_tools_first() {
        let idx = Index::new(&[
            spec("web_fetch", "Fetch a URL over HTTP and return text."),
            spec("memory", "Persistent memory across sessions."),
            spec("cron", "Schedule recurring jobs. Runs a prompt at a time."),
        ]);
        let cfg = ToolSearchConfig::default();
        let hits = idx.search("fetch http page", &cfg);
        assert_eq!(hits[0].name, "web_fetch");
        assert_eq!(hits.len(), 1);
        assert_eq!(idx.search("memory", &cfg)[0].name, "memory");
        assert!(idx.search("zzz", &cfg).is_empty());
        assert!(idx.search("", &cfg).is_empty());
        let capped = idx.search("a", &ToolSearchConfig { max_results: 1, ..cfg });
        assert!(capped.len() <= 1);
        assert!(render(&hits).contains("web_fetch: Fetch a URL over HTTP and return text"));
        assert!(render(&[]).starts_with("No matching"));
    }

    #[test]
    fn config_defaults_and_unknown_keys() {
        let c: ToolSearchConfig = toml::from_str("max_results = 3").unwrap();
        assert!(c.enabled);
        assert_eq!(c.max_results, 3);
        assert!(toml::from_str::<ToolSearchConfig>("bogus = 1").is_err());
    }
}
