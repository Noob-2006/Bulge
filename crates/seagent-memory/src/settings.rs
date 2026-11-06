//! `[memory.*]` sub-tables, parsed with unknown-key checks. Every default below is the
//! upstream default unless the doc comment says otherwise.

use seagent_kernel::config::MemoryConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn parse<T: for<'de> Deserialize<'de> + Default>(t: &toml::Table, key: &str) -> Result<T, String> {
    if t.is_empty() {
        return Ok(T::default());
    }
    toml::Value::Table(t.clone()).try_into().map_err(|e| format!("[memory.{key}]: {e}"))
}

/// `[memory.search.embedding]` (and `[memory.vector.embedding]`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct EmbeddingSettings {
    /// openai | gemini (google) | mistral | voyage | bedrock | deepinfra | github-copilot |
    /// llama-cpp | lmstudio | ollama | omlx | openai-compatible | local | none | auto.
    /// `auto` (default): openai when an OpenAI key is available, else `none` (FTS-only).
    pub provider: String,
    /// Empty = the provider's default model.
    pub model: String,
    /// Empty = the provider's documented endpoint.
    pub base_url: String,
    /// May contain `{{secret:NAME}}` or `env:NAME`; empty = the provider's env var.
    pub api_key: String,
    pub headers: HashMap<String, String>,
    /// Requested output dimensions (OpenAI `dimensions`, Gemini `outputDimensionality`, Bedrock).
    pub dimensions: Option<usize>,
    pub input_type: Option<String>,
    pub query_input_type: Option<String>,
    pub document_input_type: Option<String>,
    /// Bedrock region (default `AWS_REGION` / `us-east-1`).
    pub region: String,
    /// Max inputs per request (0 = provider default: 96 for most remote APIs, 1 for Bedrock non-Cohere).
    pub max_batch: usize,
    /// Per-request timeout seconds (default 60).
    pub timeout_secs: u64,
    /// Allow an embedding endpoint that resolves to a private/LAN address (`ollama`; default
    /// true: an operator-configured on-prem GPU host is the usual setup). Loopback and
    /// `localhost` are always allowed; cloud-metadata hosts never are.
    pub allow_private: bool,
}

impl Default for EmbeddingSettings {
    fn default() -> Self {
        EmbeddingSettings { provider: "auto".into(), model: String::new(), base_url: String::new(), api_key: String::new(), headers: HashMap::new(), dimensions: None, input_type: None, query_input_type: None, document_input_type: None, region: String::new(), max_batch: 0, timeout_secs: 60, allow_private: true }
    }
}

/// `[memory.search.multimodal]`: index image/audio files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct MultimodalSettings {
    pub enabled: bool,
    /// `image`, `audio` or `all` (default all when enabled).
    pub modalities: Vec<String>,
    /// Max bytes of one media file (default 10 MiB).
    pub max_file_bytes: u64,
}

impl Default for MultimodalSettings {
    fn default() -> Self {
        MultimodalSettings { enabled: false, modalities: vec!["all".into()], max_file_bytes: 10 * 1024 * 1024 }
    }
}

/// `[memory.search]` (OpenClaw memory-search.ts).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct SearchSettings {
    pub enabled: bool,
    /// `memory` (MEMORY.md, USER.md, DREAMS.md, memory/**.md) and/or `sessions` (transcripts).
    pub sources: Vec<String>,
    /// Extra Markdown files or directories to index.
    pub extra_paths: Vec<String>,
    /// Team knowledge bases (srv-037): `team id` (or `org:<id>` for an organization-wide base)
    /// → files / directories. Indexed into the same SQLite index, tagged with the tenant, and
    /// only retrievable by sessions and principals of that team / organization.
    pub team_paths: std::collections::BTreeMap<String, Vec<String>>,
    pub max_results: usize,
    pub min_score: f64,
    pub vector_weight: f64,
    pub text_weight: f64,
    pub candidate_multiplier: usize,
    pub mmr: bool,
    pub mmr_lambda: f64,
    pub temporal_decay: bool,
    pub half_life_days: f64,
    pub chunk_tokens: usize,
    pub chunk_overlap: usize,
    /// Embedding cache LRU bound (default 50 000).
    pub cache_max_entries: usize,
    /// `auto` | `on` | `off`: include `Source: path#line` citations.
    pub citations: String,
    pub embedding: EmbeddingSettings,
    pub multimodal: MultimodalSettings,
}

impl Default for SearchSettings {
    fn default() -> Self {
        SearchSettings {
            enabled: true,
            // srv-059: past sessions are searchable by default (chat Q&A over old sessions).
            sources: vec!["memory".into(), "sessions".into()],
            extra_paths: vec![],
            team_paths: Default::default(),
            max_results: 6,
            min_score: 0.35,
            vector_weight: 0.7,
            text_weight: 0.3,
            candidate_multiplier: 4,
            mmr: true,
            mmr_lambda: 0.7,
            temporal_decay: true,
            half_life_days: 30.0,
            chunk_tokens: 400,
            chunk_overlap: 80,
            cache_max_entries: 50_000,
            citations: "auto".into(),
            embedding: EmbeddingSettings::default(),
            multimodal: MultimodalSettings::default(),
        }
    }
}

/// `[memory.active]` (OpenClaw active-memory types.ts).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ActiveSettings {
    /// Default false in seagent: every recall-intent turn spends one aux-model call (upstream enables it with the plugin).
    pub enabled: bool,
    /// `escalate` (recall agent only for questions about the past), `always`, `off`.
    pub mode: String,
    /// `message` | `recent` | `full`: how much conversation the recall agent sees.
    pub query_mode: String,
    /// balanced | strict | contextual | recall-heavy | precision-heavy | preference-only.
    pub prompt_style: String,
    pub prompt_override: String,
    pub prompt_append: String,
    pub max_summary_chars: usize,
    pub recent_user_turns: usize,
    pub recent_assistant_turns: usize,
    pub recent_user_chars: usize,
    pub recent_assistant_chars: usize,
    pub timeout_ms: u64,
    pub cache_ttl_ms: u64,
    pub circuit_breaker_max_timeouts: u32,
    pub circuit_breaker_cooldown_ms: u64,
    /// Recall model (`provider/model`); empty = aux model.
    pub model: String,
    /// "Remember across conversations": also recall from other sessions' transcripts.
    pub remember_across_conversations: bool,
}

impl Default for ActiveSettings {
    fn default() -> Self {
        ActiveSettings {
            enabled: false,
            mode: "escalate".into(),
            query_mode: "recent".into(),
            prompt_style: "balanced".into(),
            prompt_override: String::new(),
            prompt_append: String::new(),
            max_summary_chars: 220,
            recent_user_turns: 2,
            recent_assistant_turns: 1,
            recent_user_chars: 220,
            recent_assistant_chars: 180,
            timeout_ms: 15_000,
            cache_ttl_ms: 15_000,
            circuit_breaker_max_timeouts: 3,
            circuit_breaker_cooldown_ms: 60_000,
            model: String::new(),
            remember_across_conversations: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct LightPhase {
    pub enabled: bool,
    pub lookback_days: u32,
    pub limit: usize,
    pub dedupe_similarity: f64,
}
impl Default for LightPhase {
    fn default() -> Self {
        LightPhase { enabled: true, lookback_days: 2, limit: 100, dedupe_similarity: 0.9 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DeepPhase {
    pub enabled: bool,
    pub limit: usize,
    pub min_score: f64,
    pub min_recall_count: u32,
    pub min_unique_queries: usize,
    pub recency_half_life_days: f64,
    pub max_age_days: f64,
    pub max_promoted_snippet_tokens: usize,
}
impl Default for DeepPhase {
    fn default() -> Self {
        DeepPhase { enabled: true, limit: 10, min_score: 0.75, min_recall_count: 3, min_unique_queries: 3, recency_half_life_days: 14.0, max_age_days: 30.0, max_promoted_snippet_tokens: 160 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RemPhase {
    pub enabled: bool,
    pub lookback_days: u32,
    pub limit: usize,
    pub min_pattern_strength: f64,
}
impl Default for RemPhase {
    fn default() -> Self {
        RemPhase { enabled: true, lookback_days: 7, limit: 10, min_pattern_strength: 0.75 }
    }
}

/// `[memory.dreaming]` (OpenClaw memory-host-sdk dreaming.ts).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DreamingSettings {
    pub enabled: bool,
    /// Cron expression of the sweep (light → REM → deep), default `0 3 * * *`.
    pub frequency: String,
    /// `separate` (DREAMS.md report blocks), `inline` (daily note), `both`.
    pub storage_mode: String,
    /// Write a dream-diary narrative with the aux model.
    pub narrative: bool,
    pub model: String,
    pub light: LightPhase,
    pub deep: DeepPhase,
    pub rem: RemPhase,
}
impl Default for DreamingSettings {
    fn default() -> Self {
        DreamingSettings { enabled: true, frequency: "0 3 * * *".into(), storage_mode: "separate".into(), narrative: true, model: String::new(), light: LightPhase::default(), deep: DeepPhase::default(), rem: RemPhase::default() }
    }
}

/// `[memory.vector]` (OpenClaw memory-lancedb config.ts).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct VectorSettings {
    /// Register memory_recall / memory_store / memory_forget.
    pub enabled: bool,
    pub auto_recall: bool,
    pub auto_capture: bool,
    pub capture_max_chars: usize,
    pub recall_max_chars: usize,
    pub custom_triggers: Vec<String>,
    /// Defaults to `[memory.search.embedding]`; with no provider a local hashed embedding is used.
    pub embedding: Option<EmbeddingSettings>,
}
impl Default for VectorSettings {
    fn default() -> Self {
        VectorSettings { enabled: true, auto_recall: true, auto_capture: false, capture_max_chars: 500, recall_max_chars: 1000, custom_triggers: vec![], embedding: None }
    }
}

/// `[memory.flush]` (OpenClaw flush-plan.ts): pre-compaction durable-note extraction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct FlushSettings {
    pub enabled: bool,
    pub model: String,
    /// Transcript chars handed to the flush model (default 12 000).
    pub max_chars: usize,
}
impl Default for FlushSettings {
    fn default() -> Self {
        FlushSettings { enabled: true, model: String::new(), max_chars: 12_000 }
    }
}

/// One named knowledge store: its own vault directory and agent ACL.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct WikiStore {
    /// Store directory; empty is refused (a named store must say where it lives).
    pub path: String,
    /// Agent ids allowed to read/write this store (empty = every agent).
    pub agents: Vec<String>,
}

/// `[memory.wiki]` (OpenClaw memory-wiki + extensions/knowledge ACL/history).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct WikiSettings {
    pub enabled: bool,
    /// Vault directory; empty = `<data>/memory/wiki`.
    pub vault_path: String,
    /// `obsidian` | `native`.
    pub render_mode: String,
    /// `wiki` | `memory` | `all` default corpus of wiki_search.
    pub search_corpus: String,
    pub create_backlinks: bool,
    pub create_dashboards: bool,
    /// Index DREAMS.md / daily notes / MEMORY.md as bridge sources.
    pub bridge: bool,
    /// This agent's id; empty = `$SEAGENT_AGENT`. Used by the default store's `agents` ACL.
    pub agent_id: String,
    /// Agent ids allowed on the default store (empty = every agent).
    pub agents: Vec<String>,
    /// Extra named stores (`[memory.wiki.stores.<name>]`), scoped to their own agents.
    pub stores: std::collections::BTreeMap<String, WikiStore>,
    /// Keep a page snapshot under `.seagent-wiki/history/` before every mutation.
    pub history: bool,
    /// Snapshots kept per page.
    pub history_max: usize,
}
impl Default for WikiSettings {
    fn default() -> Self {
        WikiSettings { enabled: true, vault_path: String::new(), render_mode: "obsidian".into(), search_corpus: "wiki".into(), create_backlinks: true, create_dashboards: true, bridge: false, agent_id: String::new(), agents: vec![], stores: Default::default(), history: true, history_max: 50 }
    }
}

/// `[memory.standing]`: keyword-triggered reminders (OpenClaw `memory-core/standing-intents`),
/// scoped to a conversation/sender/channel, with cooldown, max fires and expiry. Off by default:
/// enabling it makes the prefetch turn inspect the user message for triggers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct StandingSettings {
    pub enabled: bool,
    pub max_intents: usize,
    /// Default cooldown between two fires of one intent.
    pub cooldown_secs: u64,
    pub max_fires: u32,
}
impl Default for StandingSettings {
    fn default() -> Self {
        StandingSettings { enabled: false, max_intents: 50, cooldown_secs: 3_600, max_fires: 3 }
    }
}

/// `[memory.recall_gate]` (OpenClaw `extensions/knowledge` recall gate): before the reply,
/// shortlist knowledge pages by keyword, score each independently with the aux/decision model,
/// and inject only what clears the threshold. `shadow` runs the same pass and logs it without
/// injecting; `live` injects. Off by default.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RecallGateSettings {
    /// `off` | `shadow` | `live`.
    pub mode: String,
    /// `keyword` (the measured shortlist); `model` is not implemented yet and is refused.
    pub candidates: String,
    /// Page text is injected at or above this probability.
    pub high_threshold: f64,
    /// Pointer-only tier; `None` = off.
    pub medium_threshold: Option<f64>,
    /// When set, all scores below this add a one-line "memory unnecessary" hint.
    pub skip_hint_below: Option<f64>,
    /// Whole-gate budget (the scoring call).
    pub timeout_ms: u64,
    /// Most pages scored per turn.
    pub max_candidates: usize,
    /// Characters of page body injected per high page.
    pub page_chars: usize,
    /// Whole injection budget, header included.
    pub max_inject_chars: usize,
    /// Wiki store to read; empty = default vault.
    pub store: String,
    /// `provider/model`; empty = aux model.
    pub model: String,
}
impl Default for RecallGateSettings {
    fn default() -> Self {
        RecallGateSettings { mode: "off".into(), candidates: "keyword".into(), high_threshold: 0.75, medium_threshold: None, skip_hint_below: None, timeout_ms: 1_500, max_candidates: 10, page_chars: 2_800, max_inject_chars: 6_000, store: String::new(), model: String::new() }
    }
}

/// `[memory.rewrite]` (Hermes plugins/memory/query_rewrite.py).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RewriteSettings {
    pub enabled: bool,
    pub model: String,
}

/// `[memory.byterover]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ByteroverSettings {
    pub auto_extract: bool,
    /// `brv` binary; empty = PATH / ~/.brv-cli/bin/brv / /usr/local/bin/brv / ~/.npm-global/bin/brv.
    pub binary: String,
    /// Context-tree directory; empty = `<data>/byterover`.
    pub cwd: String,
    /// Optional cloud-sync key (passed as BRV_API_KEY).
    pub api_key: String,
}
impl Default for ByteroverSettings {
    fn default() -> Self {
        ByteroverSettings { auto_extract: true, binary: String::new(), cwd: String::new(), api_key: String::new() }
    }
}

/// `[memory.retaindb]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RetaindbSettings {
    /// Empty = `RETAINDB_API_KEY`.
    pub api_key: String,
    /// Empty = `RETAINDB_BASE_URL` or https://api.retaindb.com.
    pub base_url: String,
    /// Empty = `RETAINDB_PROJECT` or `default`.
    pub project: String,
    pub user_id: String,
    pub agent_id: String,
}
impl Default for RetaindbSettings {
    fn default() -> Self {
        RetaindbSettings { api_key: String::new(), base_url: String::new(), project: String::new(), user_id: "default".into(), agent_id: "seagent".into() }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Settings {
    pub provider: String,
    pub search: SearchSettings,
    pub active: ActiveSettings,
    pub dreaming: DreamingSettings,
    pub vector: VectorSettings,
    pub flush: FlushSettings,
    pub wiki: WikiSettings,
    pub recall_gate: RecallGateSettings,
    pub standing: StandingSettings,
    pub rewrite: RewriteSettings,
    pub byterover: ByteroverSettings,
    pub retaindb: RetaindbSettings,
}

impl Settings {
    pub fn from_config(c: &MemoryConfig) -> Result<Settings, String> {
        let s = Settings {
            provider: c.provider.clone(),
            search: parse(&c.search, "search")?,
            active: parse(&c.active, "active")?,
            dreaming: parse(&c.dreaming, "dreaming")?,
            vector: parse(&c.vector, "vector")?,
            flush: parse(&c.flush, "flush")?,
            wiki: parse(&c.wiki, "wiki")?,
            recall_gate: parse(&c.recall_gate, "recall_gate")?,
            standing: parse(&c.standing, "standing")?,
            rewrite: parse(&c.rewrite, "rewrite")?,
            byterover: parse(&c.byterover, "byterover")?,
            retaindb: parse(&c.retaindb, "retaindb")?,
        };
        s.validate()?;
        Ok(s)
    }

    pub fn validate(&self) -> Result<(), String> {
        let one_of = |v: &str, ok: &[&str], key: &str| if ok.contains(&v) { Ok(()) } else { Err(format!("[memory] {key} = `{v}`: use one of {}", ok.join(", "))) };
        one_of(&self.active.mode, &["escalate", "always", "off"], "active.mode")?;
        one_of(&self.active.query_mode, &["message", "recent", "full"], "active.query_mode")?;
        one_of(&self.active.prompt_style, &["balanced", "strict", "contextual", "recall-heavy", "precision-heavy", "preference-only"], "active.prompt_style")?;
        one_of(&self.dreaming.storage_mode, &["inline", "separate", "both"], "dreaming.storage_mode")?;
        one_of(&self.search.citations, &["auto", "on", "off"], "search.citations")?;
        one_of(&self.wiki.render_mode, &["obsidian", "native"], "wiki.render_mode")?;
        one_of(&self.wiki.search_corpus, &["wiki", "memory", "all"], "wiki.search_corpus")?;
        one_of(&self.recall_gate.mode, &["off", "shadow", "live"], "recall_gate.mode")?;
        one_of(&self.recall_gate.candidates, &["keyword"], "recall_gate.candidates")?;
        if !(0.0..=1.0).contains(&self.recall_gate.high_threshold) {
            return Err("[memory] recall_gate.high_threshold must be between 0 and 1".into());
        }
        for (k, v) in [("medium_threshold", self.recall_gate.medium_threshold), ("skip_hint_below", self.recall_gate.skip_hint_below)] {
            if v.is_some_and(|x| !(0.0..=1.0).contains(&x)) {
                return Err(format!("[memory] recall_gate.{k} must be between 0 and 1"));
            }
        }
        for s in &self.search.sources {
            one_of(s, &["memory", "sessions"], "search.sources")?;
        }
        if !(0.0..=1.0).contains(&self.search.min_score) {
            return Err("[memory] search.min_score must be between 0 and 1".into());
        }
        if self.search.multimodal.enabled && !crate::embed::supports_multimodal(&self.search.embedding) {
            return Err("memory.search.multimodal requires a provider adapter that supports multimodal embeddings for the configured model (gemini with gemini-embedding-2)".into());
        }
        if let Some(d) = self.search.embedding.dimensions {
            if self.search.embedding.provider == "gemini" && !(128..=3072).contains(&d) {
                return Err(format!("Invalid outputDimensionality {d} for gemini. Use an integer between 128 and 3072."));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_unknown_keys() {
        let s = Settings::from_config(&MemoryConfig::default()).unwrap();
        assert_eq!(s.search.max_results, 6);
        assert_eq!(s.search.min_score, 0.35);
        assert_eq!((s.search.vector_weight, s.search.text_weight), (0.7, 0.3));
        assert_eq!((s.search.chunk_tokens, s.search.chunk_overlap), (400, 80));
        assert_eq!(s.dreaming.deep.min_score, 0.75);
        assert_eq!(s.active.timeout_ms, 15_000);
        assert_eq!((s.recall_gate.mode.as_str(), s.recall_gate.high_threshold, s.recall_gate.timeout_ms), ("off", 0.75, 1_500));
        assert!(!s.standing.enabled && s.standing.max_intents == 50 && s.standing.cooldown_secs == 3_600);
        assert_eq!(s.vector.capture_max_chars, 500);
        let mut c = MemoryConfig { search: toml::from_str("max_results = 3\n[embedding]\nprovider = \"ollama\"").unwrap(), ..Default::default() };
        let s = Settings::from_config(&c).unwrap();
        assert_eq!((s.search.max_results, s.search.embedding.provider.as_str()), (3, "ollama"));
        c.search = toml::from_str("bogus = 1").unwrap();
        assert!(Settings::from_config(&c).unwrap_err().contains("bogus"));
        let c = MemoryConfig { active: toml::from_str("mode = \"sometimes\"").unwrap(), ..Default::default() };
        assert!(Settings::from_config(&c).unwrap_err().contains("active.mode"));
        let mut c = MemoryConfig { search: toml::from_str("[multimodal]\nenabled = true").unwrap(), ..Default::default() };
        assert!(Settings::from_config(&c).unwrap_err().contains("multimodal"));
        c.search = toml::from_str("[multimodal]\nenabled = true\n[embedding]\nprovider = \"gemini\"\nmodel = \"gemini-embedding-2\"").unwrap();
        assert!(Settings::from_config(&c).is_ok());
    }

    #[test]
    fn whole_config_parses_memory_tables() {
        let cfg: seagent_kernel::config::Config = toml::from_str("[memory]\nprovider = \"byterover\"\nwrite_approval = true\n[memory.dreaming]\nenabled = false\n[memory.dreaming.deep]\nlimit = 2\n").unwrap();
        let s = Settings::from_config(&cfg.memory).unwrap();
        assert!(cfg.memory.write_approval && !s.dreaming.enabled && s.dreaming.deep.limit == 2);
        assert!(toml::from_str::<seagent_kernel::config::Config>("[memory]\nnope = 1").is_err(), "deny_unknown_fields kept");
    }
}
