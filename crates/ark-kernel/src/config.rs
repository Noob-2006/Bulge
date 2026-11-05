//! Layered TOML config: built-in defaults → user → project (`.ark/config.toml`)
//! → `--set key=value` overrides. `dump()` prints the effective result.

use crate::gate::GateConfig;
use crate::ledger::{Budget, Price};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct Config {
    pub model: ModelConfig,
    /// Provider overrides / additions, passed through to the model layer.
    pub providers: BTreeMap<String, toml::Table>,
    /// USD per million tokens, keyed by `provider/model`.
    pub prices: BTreeMap<String, Price>,
    pub pricing: PricingConfig,
    pub budget: Budget,
    pub runner: RunnerConfig,
    /// `[limits]`: per-agent / global spend, process and disk caps (0 = off).
    pub limits: LimitsConfig,
    pub compaction: CompactionConfig,
    pub gate: GateConfig,
    pub schedule: ScheduleConfig,
    pub tools: ToolsConfig,
    pub learn: LearnConfig,
    pub checkpoint: CheckpointConfig,
    /// Extra persona / standing instructions appended to the identity segment.
    pub identity: String,
    /// Lifecycle hooks (shell commands, Claude Code–compatible protocol).
    pub hooks: Vec<crate::hooks::HookConfig>,
    /// `[hooks_extra]`: first-use consent, bundled hooks, outbound webhooks, session auto-reset,
    /// Gmail watcher — parsed by the `ark` crate (crates/ark/src/hooks_ext.rs documents the keys).
    pub hooks_extra: toml::Table,
    /// MCP servers / connectors, plugins and channels: parsed by their crates.
    pub mcp: BTreeMap<String, toml::Table>,
    pub plugins: BTreeMap<String, toml::Table>,
    pub channels: BTreeMap<String, toml::Table>,
    /// ACP: editor-side options and external ACP agents ark can drive: parsed by ark-app.
    pub acp: toml::Table,
    /// App server (web/desktop UI, OpenAI-compatible API, nodes, A2A): parsed by ark-app.
    pub app: toml::Table,
    /// Built-in browser tools (`[browser]`): parsed by ark-browser.
    pub browser: toml::Table,
    /// Media capabilities (`[media]`: vision, documents, image/video/music generation, TTS,
    /// STT, voice mode, calls, meetings): parsed by ark-media.
    pub media: toml::Table,
    /// The agent's own headless desktop (`[bot_desktop]`: geometry, memory floor): read by
    /// `ark screen` / `ark computer-use` (ark-browser).
    pub bot_desktop: toml::Table,
    /// Web tools (`[web]`: search provider, extract backend, link understanding): parsed by
    /// ark-tools (`ark_tools::web::config::WebConfig`).
    pub web: toml::Table,
    /// Execution backends and sandbox (`[exec]`): parsed by ark-tools (`ark_tools::exec::ExecConfig`).
    pub exec: toml::Table,
    /// Workspace file policy (`[files]`): parsed by ark-tools.
    pub files: toml::Table,
    /// Local desktop control (`[computer_use]`): parsed by ark-app.
    pub computer_use: toml::Table,
    /// Legal/compliance switches (see docs/compliance-tw.md).
    pub compliance: ComplianceConfig,
    /// Workspaces whose `.ark/config.toml` may define the keys in `PROJECT_GATED`.
    pub trusted_projects: Vec<String>,
    /// A plugin that assembles / compacts context (OpenClaw context engine). Empty = ark's own.
    pub context_engine: String,
    pub memory: MemoryConfig,
    /// Proxy / NO_PROXY / CA bundle / provider host policy for model traffic: parsed by the model layer.
    pub network: toml::Table,
    /// `[auxiliary.<task>]` blocks: per-task model routes, fallback chains, timeouts and extra
    /// bodies for context compaction, review, titles, vision, approvals, sampling and friends
    /// (Hermes `auxiliary.<task>`, `agent/auxiliary_task_config.py`). Parsed by the model layer.
    pub auxiliary: BTreeMap<String, toml::Table>,
    /// Approval modes, floors, exec allowlist, elevated, forwarding (docs/parity-agent/security.md).
    pub approvals: ark_security::approvals::ApprovalsConfig,
    /// URL / path / env / plugin / threat-scan policy.
    pub security: ark_security::SecurityConfig,
    /// Language servers for post-edit diagnostics: parsed by ark-tools (`ark_tools::lsp::LspConfig`).
    pub lsp: toml::Table,
    /// ShareGPT trajectory auto-save after `ark run` (Hermes `--save_trajectories`).
    pub trajectory: TrajectoryConfig,
    /// Hugging Face agent-trace upload (`ark session upload-trace`).
    pub trace: TraceConfig,
    /// Sub-agent delegation limits and behaviour (`delegate_task`, `sessions_spawn`).
    pub delegation: crate::subagents::DelegationConfig,
    /// Named agents (`[agents.<id>]`); `<config>/agents.toml` (managed by `ark agents`) adds more.
    pub agents: BTreeMap<String, crate::agents::AgentDef>,
    /// Channel → agent routing (`[[bindings]]`).
    pub bindings: Vec<crate::agents::Binding>,
    /// Decision provider for `decision_evaluate`.
    pub decision: crate::decision::DecisionConfig,
    /// `llm_task` defaults and model policy.
    pub llm_task: crate::decision::LlmTaskConfig,
    /// Mixture-of-Agents presets (`/moa`, `ark moa`).
    pub moa: crate::moa::MoaConfig,
    /// `[context]`: prompt-side context features (see crates/ark-kernel/src/ctxstate.rs).
    pub context: crate::ctxstate::ContextConfig,
    /// `[display]`: presentation (UI language for approval prompts, notices and CLI headings).
    pub display: DisplayConfig,
    /// `[skills]` (gating, hub sources, guard, curator, usage, bundles …). Parsed with
    /// documented defaults and unknown-key checks by ark-skills (`crates/ark-skills/src/config.rs`).
    pub skills: toml::Table,
    /// Schema version of the user file (`ark config migrate` bumps it).
    pub config_version: i64,
    /// Selected personality preset (`/personality`); "" = none.
    pub personality: String,
    /// Custom personalities `name = "system prompt"`, overlaying the built-ins.
    pub personalities: BTreeMap<String, String>,
    /// `[role]`: the occupation the default agent works as (`ark role use`), the L0 core
    /// switch, an extra roles directory and the active-scan allowlist (crate::roles).
    pub role: crate::roles::RoleConfig,
    /// Scheduled backups (`ark backup`).
    pub backup: BackupConfig,
    /// Self-update source (`ark update`).
    pub update: UpdateConfig,
    /// OpenTelemetry export (`ark telemetry`).
    pub telemetry: TelemetryConfig,
    /// Multi-agent Kanban board and its dispatcher (see `kanban::KanbanConfig`).
    pub kanban: crate::kanban::KanbanConfig,
    /// Agent work surfaces (llm-task, lobster, diffs, canvas host, dashboards, progress cards,
    /// gateway tool, team reports, file transfer): parsed by ark-app (`surfaces::SurfacesConfig`).
    pub surfaces: toml::Table,
    /// Automation extras (cron delivery defaults, prompt scan, external cron provider, suggestions): parsed by `automation`.
    pub automation: toml::Table,
    /// Proactive heartbeat runs (interval, active hours, delivery): parsed by the heartbeat module.
    pub heartbeat: toml::Table,
    /// Outbound webhooks (`[[webhooks.outbound]]`, Hermes `hooks.outbound`): parsed by the hooks module.
    pub webhooks: toml::Table,
    /// Canvas host / A2UI / dashboards: parsed by the canvas module.
    pub canvas: toml::Table,
    /// Meeting bots (Google Meet, Teams, Zoom, Slack huddles): parsed by the meetings module.
    pub meetings: toml::Table,
    /// Lobster-style workflows and llm-task: parsed by the workflows module.
    pub workflows: toml::Table,
    /// GitHub / team-report / visitor-access integrations: parsed by their modules.
    pub integrations: toml::Table,
    /// Built-in plugins ported from upstream (`[builtin_plugins.<name>] enabled, dry_run, block …`):
    /// parsed by ark-plugin (`crates/ark-plugin/src/builtin/mod.rs`).
    pub builtin_plugins: toml::Table,
    /// `[audit]`: unified audit stream rotation and SIEM export (see `governance`).
    pub audit: crate::governance::AuditConfig,
    /// `[quotas]`: spend per user / team per period.
    pub quotas: crate::governance::QuotaConfig,
    /// `[alerts]`: where spend / quota alerts are pushed.
    pub alerts: crate::governance::AlertsConfig,
    /// What `/etc/ark` contributed (never read from or written to a file).
    #[serde(skip)]
    pub managed: crate::managed::Managed,
}

/// `[display]`: user-facing presentation (Hermes `display.language`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DisplayConfig {
    /// UI language for ark's own strings (approval prompts, notices, `/help` and `/status`
    /// headings). A code, an alias (`chinese`, `jp`, `zh-TW`…) or an id a plugin pack /
    /// `$ARK_HOME/locales/<lang>.yaml` supplies. "" = follow `ARK_LANGUAGE`, else English.
    pub language: String,
}

/// `[trajectory]`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrajectoryConfig {
    /// Append every `ark run` to trajectory_samples.jsonl / failed_trajectories.jsonl.
    pub save: bool,
    /// Directory for those files. Empty = the current directory (as upstream).
    pub dir: String,
}

/// `[trace]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TraceConfig {
    /// Dataset created under the token owner's namespace.
    pub dataset: String,
    /// Hub endpoint (`HF_ENDPOINT` equivalent).
    pub endpoint: String,
    /// Create the dataset private (traces carry prompts, paths and tool output).
    pub private: bool,
    /// Vault secret holding the write token.
    pub token_secret: String,
}

impl Default for TraceConfig {
    fn default() -> Self {
        TraceConfig { dataset: "ark-traces".into(), endpoint: "https://huggingface.co".into(), private: true, token_secret: "HF_TOKEN".into() }
    }
}

/// `[telemetry]`: OTLP/HTTP JSON export of traces (turns, model steps, tool calls),
/// metrics (tokens, tool calls, errors) and logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    pub enabled: bool,
    /// Collector base URL; `/v1/traces`, `/v1/metrics`, `/v1/logs` are appended.
    pub endpoint: String,
    /// Extra request headers (`{{secret:NAME}}` allowed), e.g. an API key.
    pub headers: BTreeMap<String, String>,
    pub service_name: String,
    /// Fraction of turns traced (0.0–1.0); metrics and logs are always sent.
    pub sample_ratio: f64,
    pub traces: bool,
    pub metrics: bool,
    pub logs: bool,
    /// Flush interval.
    pub flush_secs: u64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        TelemetryConfig { enabled: false, endpoint: "http://127.0.0.1:4318".into(), headers: BTreeMap::new(), service_name: "ark".into(), sample_ratio: 1.0, traces: true, metrics: true, logs: true, flush_secs: 5 }
    }
}

/// `[update]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpdateConfig {
    /// GitHub-compatible releases API of the repository (`…/repos/<owner>/<repo>`).
    pub url: String,
    /// stable | lts | beta | dev
    pub channel: String,
    /// Check for a newer release when the daemon starts (prints a notice, never installs).
    pub check_on_start: bool,
    /// The maintained `lts` line, `MAJOR.MINOR` (e.g. "1.4"): the lts channel follows the newest
    /// stable release of that line and never jumps to a newer minor. Empty = releases whose notes
    /// carry an `LTS` line.
    pub lts_series: String,
    /// Ed25519 public key (`release-key.pub.pem` text, or base64 of the raw 32 bytes) that
    /// `SHA256SUMS.sig` must verify against. Set = `ark update` refuses a release without a
    /// valid signature; empty = checksum + TLS only (a notice says so).
    pub verify_key: String,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        UpdateConfig { url: "https://api.github.com/repos/ark-agent/ark".into(), channel: "stable".into(), check_on_start: false, lts_series: String::new(), verify_key: String::new() }
    }
}

/// `[backup]`: archives of config + data written by the daemon on a timer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackupConfig {
    pub enabled: bool,
    pub every_hours: u64,
    /// Destination directory; "" = `<data>/backups`.
    pub dir: String,
    pub keep_daily: u32,
    pub keep_weekly: u32,
    pub keep_monthly: u32,
    pub include_sessions: bool,
    /// Leave `secrets.toml` and `.env` out of scheduled archives.
    pub exclude_secrets: bool,
}

impl Default for BackupConfig {
    fn default() -> Self {
        BackupConfig { enabled: false, every_hours: 24, dir: String::new(), keep_daily: 7, keep_weekly: 4, keep_monthly: 6, include_sessions: true, exclude_secrets: false }
    }
}


/// `[memory]`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MemoryConfig {
    /// A plugin serving the `memory` tool (Hermes memory provider). Empty = MEMORY.md / USER.md.
    /// `byterover` / `retaindb` select the providers bundled in ark-memory.
    pub provider: String,
    /// Character budget of MEMORY.md (default 4000).
    pub memory_char_limit: Option<usize>,
    /// Character budget of USER.md (default 4000).
    pub user_char_limit: Option<usize>,
    /// Stage the agent's memory writes for approval (`ark memory review`) instead of committing (default false).
    pub write_approval: bool,
    /// The sub-tables below are parsed (with unknown-key checks and documented defaults) by
    /// ark-memory's `Settings::from_config`; see crates/ark-memory/src/settings.rs.
    /// `[memory.search]`: memory_search sources, hybrid weights, MMR, decay, `[memory.search.embedding]`.
    pub search: toml::Table,
    /// `[memory.active]`: pre-reply bounded recall (OpenClaw active-memory).
    pub active: toml::Table,
    /// `[memory.dreaming]`: background consolidation phases.
    pub dreaming: toml::Table,
    /// `[memory.vector]`: memory_recall / memory_store / memory_forget store, auto-recall/capture.
    pub vector: toml::Table,
    /// `[memory.flush]`: pre-compaction memory flush.
    pub flush: toml::Table,
    /// `[memory.wiki]`: compiled wiki vault.
    pub wiki: toml::Table,
    /// `[memory.rewrite]`: recall query rewrite.
    pub rewrite: toml::Table,
    /// `[memory.byterover]` / `[memory.retaindb]`: bundled external providers.
    pub byterover: toml::Table,
    pub retaindb: toml::Table,
}

/// `[compliance]`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ComplianceConfig {
    /// `"government"`: public-sector profile — providers and hosts in the PRC are refused
    /// (行政院 2025-02 限制公務機關使用 DeepSeek 等「危害國家資通安全產品」).
    pub profile: String,
    /// Delete sessions (logs, transcripts) not updated for this many days. 0/None = keep.
    pub retention_days: Option<u32>,
    /// Per-class retention (sessions, audit, broker, logs, exports) — see `governance`.
    pub retention: crate::governance::RetentionConfig,
    /// PII masking at rest and in exports.
    pub pii: ark_security::pii::PiiConfig,
    /// Data classification of this install / project (`public`, `internal`, `confidential`, …).
    pub data_class: String,
    /// Which models each data class may use: `confidential = ["anthropic/*", "local/*"]`.
    pub classes: BTreeMap<String, Vec<String>>,
}

/// Model providers whose data is processed in the PRC, and their API hosts.
pub const PRC_PROVIDERS: &[&str] = &["deepseek", "qwen", "dashscope", "kimi", "moonshot", "zhipu", "glm", "minimax", "doubao", "volcengine", "baichuan", "hunyuan", "qianfan", "siliconflow", "stepfun", "yi", "xiaomi"];
pub const PRC_HOSTS: &[&str] = &[
    "deepseek.com", "dashscope.aliyuncs.com", "aliyuncs.com", "moonshot.cn", "bigmodel.cn", "minimax.chat", "minimaxi.com", "volces.com", "volcengine.com",
    "baichuan-ai.com", "tencentcloudapi.com", "baidubce.com", "siliconflow.cn", "stepfun.com", "lingyiwanwu.com", "xiaomimimo.com",
];

/// Keys that run programs or open listeners. A cloned repo must not get them
/// for free: they are dropped from a project config unless the user trusts it.
pub const PROJECT_GATED: &[&str] = &["hooks", "hooks_extra", "mcp", "plugins", "channels", "providers", "app", "acp", "browser", "media", "bot_desktop", "web", "exec", "files", "computer_use", "trusted_projects", "context_engine", "memory", "network", "webhooks", "kanban", "meetings", "workflows", "integrations", "automation", "heartbeat", "surfaces", "audit", "quotas", "alerts"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelConfig {
    /// `provider/model`, e.g. `anthropic/claude-sonnet-5-5`.
    pub default: String,
    /// Tried in order when the default fails with a retryable/auth error.
    pub fallback: Vec<String>,
    /// Cheap model for compaction, titles and memory review. Empty = default.
    pub aux: String,
    /// Model for spawned sub-agents. Empty = default.
    pub subagent: String,
    pub max_tokens: u32,
    pub temperature: Option<f32>,
    /// Default reasoning level for new sessions: off|minimal|low|medium|high|xhigh|max ("" = provider default).
    pub thinking: String,
    /// Fast mode / service tier: "" (normal) | "fast" (priority) | "ultrafast" | "flex" | "auto" | "cold".
    pub fast: String,
    /// `fast = "auto"`/`"cold"`: how long a user turn runs fast.
    pub fast_auto_seconds: u64,
    /// OpenAI text verbosity: "" | low | medium | high.
    pub verbosity: String,
    /// Ask OpenAI-style providers for strict (schema-enforced) tool arguments.
    pub strict_tools: bool,
    /// Short names for models: `/model fast` → `aliases.fast`.
    pub aliases: BTreeMap<String, String>,
    /// When non-empty, sessions may only switch to these models (`provider/model`, `provider/*`).
    pub allow: Vec<String>,
    /// Per-task auxiliary models (compaction, review, sampling, title, vision…); unset → `aux`.
    pub tasks: BTreeMap<String, String>,
    /// Explicit context window in tokens. Unset = whatever the provider/models.dev advertises;
    /// set = this wins and every surface labels it " (pinned)" (Hermes `model.context_length`).
    #[serde(default)]
    pub context_length: Option<u64>,
    /// Ask before selecting a model whose input/output price exceeds these (USD per million tokens).
    pub confirm_input_usd: f64,
    pub confirm_output_usd: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PricingConfig {
    /// Fetch live prices from models.dev when the cache is missing or a day old.
    pub auto_refresh: bool,
    /// models.dev mirror (Hermes `models_dev.url`); empty = the official api.json.
    #[serde(default)]
    pub models_dev_url: String,
}

impl Default for PricingConfig {
    fn default() -> Self {
        PricingConfig { auto_refresh: true, models_dev_url: String::new() }
    }
}

/// `[limits]`: per-agent and global resource caps (section C8). Every cap is optional and
/// **0 = off**, so an unconfigured ark behaves exactly as before. Enforcement lives in
/// `crate::limits` (warn at `warn_at`, pause the affected session at 100%) and the process
/// count is read from the reaper registry (`crate::reaper`), not from a second bookkeeper.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// USD spend of one session (all its turns); 0 = no cap.
    pub per_agent_spend_usd: f64,
    /// USD spend of all ark sessions in the last hour; 0 = no cap.
    pub hourly_spend_usd: f64,
    /// USD spend of all sessions ever recorded; 0 = no cap.
    pub global_spend_usd: f64,
    /// Live process groups registered for one session; 0 = no cap.
    pub max_processes_per_agent: usize,
    /// Disk held by one session (its data dir + sandbox scratch); 0 = no cap.
    pub disk_mb_per_agent: u64,
    /// Disk held by the whole ark data dir; 0 = no cap.
    pub disk_mb_total: u64,
    /// Warn at this fraction of any cap (0.8 = 80%), pause at 100%.
    pub warn_at: f64,
    /// How often the runtime checks (`crate::limits::check`); 0 disables checking.
    pub check_interval_secs: u64,
    /// How often the daemon sweeps orphaned process groups; 0 = off.
    pub reap_interval_secs: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            per_agent_spend_usd: 0.0,
            hourly_spend_usd: 0.0,
            global_spend_usd: 0.0,
            max_processes_per_agent: 0,
            disk_mb_per_agent: 0,
            disk_mb_total: 0,
            warn_at: 0.8,
            check_interval_secs: 60,
            reap_interval_secs: 300,
        }
    }
}

impl LimitsConfig {
    /// Is any cap configured? A config with none never pauses anything.
    pub fn enabled(&self) -> bool {
        self.per_agent_spend_usd > 0.0
            || self.hourly_spend_usd > 0.0
            || self.global_spend_usd > 0.0
            || self.max_processes_per_agent > 0
            || self.disk_mb_per_agent > 0
            || self.disk_mb_total > 0
    }
    pub fn validate(&self) -> Result<(), String> {
        for (k, v) in [("per_agent_spend_usd", self.per_agent_spend_usd), ("hourly_spend_usd", self.hourly_spend_usd), ("global_spend_usd", self.global_spend_usd)] {
            if !(v.is_finite() && v >= 0.0) {
                return Err(format!("limits.{k} must be a non-negative number of USD (0 = off)"));
            }
        }
        if !(0.1..=1.0).contains(&self.warn_at) {
            return Err("limits.warn_at must be a fraction in 0.1..=1.0 (0.8 = warn at 80%)".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RunnerConfig {
    pub max_steps_per_turn: u64,
    pub max_retries: u32,
    pub retry_base_ms: u64,
    pub retry_max_ms: u64,
    /// Tool outputs larger than this are spilled to an artifact file.
    pub spill_bytes: usize,
    /// Same tool + same input this many times in a row → watchdog notice.
    pub repeat_limit: usize,
    pub max_spawn_depth: u32,
    /// Auto-continue when the model stops on max_tokens.
    pub max_continuations: u32,
    /// Parallel tool calls per step.
    pub max_parallel_tools: usize,
    /// Input arriving while a turn runs: steer | followup | collect | interrupt (`/queue`, `/busy`).
    pub busy_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CompactionConfig {
    /// Compact when the prompt exceeds this fraction of the context window.
    pub threshold: f64,
    /// Prune old tool outputs first when above this fraction.
    pub prune_threshold: f64,
    /// Most recent tool results never pruned.
    pub keep_tool_results: usize,
    /// C11: long tool results older than `keep_tool_results` are clipped to this many
    /// characters (head + tail, with a `context_fetch` pointer that brings the full output
    /// back on demand) before every request. 0 = off. Default 2000 (srv-041 benchmark).
    pub max_tool_result_chars: usize,
    /// Most recent messages kept verbatim by summarisation.
    pub keep_messages: usize,
    /// Hermes micro-compaction: after each turn fold the oldest un-absorbed exchange into a
    /// rolling summary (default false: every pass breaks the prompt cache).
    pub micro_compact: bool,
    /// Run the micro pass every N turns (default 1).
    pub micro_compact_every_n_turns: u32,
    /// Re-summarise the rolling summary once it reaches this many tokens (default 2000).
    pub micro_compact_defrag_threshold_tokens: u64,
    /// Server-side ("native") compaction: `[compaction.native]` (Hermes
    /// `agent/native_compaction.py`). Off by default; ark's own pass stays the fallback.
    pub native: NativeCompactionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct NativeCompactionConfig {
    /// Let an OpenAI Responses route compact its own context (`context_management`)
    /// instead of relying only on the local summariser.
    pub enabled: bool,
    /// Input tokens before the server compacts. 0 = automatic: follow the local trigger
    /// (context window × `compaction.threshold`) minus a safety margin.
    pub threshold_tokens: u64,
}

/// Native compaction fires this far below the local trigger so the server gets the first shot,
/// and never below this floor (Hermes `LOCAL_TRIGGER_SAFETY_MARGIN` / `1024`).
const NATIVE_SAFETY_MARGIN: u64 = 8_192;
const NATIVE_MIN_THRESHOLD: u64 = 1_024;
/// Fallback when the context window is unknown (Hermes `DEFAULT_COMPACT_THRESHOLD`).
const NATIVE_DEFAULT_THRESHOLD: u64 = 200_000;

impl CompactionConfig {
    /// Server-side compaction threshold in tokens, or `None` when it is off.
    ///
    /// `window_tokens` is the model's context window: automatic mode stays strictly below the
    /// local trigger, and an explicit `threshold_tokens` is clamped to that ceiling so native
    /// compaction always fires before ark would summarise locally.
    pub fn native_threshold(&self, window_tokens: u64) -> Option<u64> {
        if !self.native.enabled {
            return None;
        }
        if window_tokens == 0 {
            return Some(match self.native.threshold_tokens {
                0 => NATIVE_DEFAULT_THRESHOLD,
                n => n.max(NATIVE_MIN_THRESHOLD),
            });
        }
        let local = (window_tokens as f64 * self.threshold).round().max(0.0) as u64;
        let upper = if local > NATIVE_SAFETY_MARGIN {
            local - NATIVE_SAFETY_MARGIN
        } else {
            local * 8 / 10
        }
        .max(NATIVE_MIN_THRESHOLD);
        let t = match self.native.threshold_tokens {
            0 => upper,
            n => n.min(upper),
        };
        Some(t.max(NATIVE_MIN_THRESHOLD))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScheduleConfig {
    /// Fixed UTC offset used for cron expressions (Taiwan = 480).
    pub utc_offset_minutes: i32,
    pub tick_secs: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ToolsConfig {
    pub disabled: Vec<String>,
    /// Force these to ship full schemas.
    pub pinned: Vec<String>,
    /// Force these behind progressive disclosure.
    pub unpinned: Vec<String>,
    /// `[tools.tool_search]`: BM25 search over the tool index (Hermes tool_search).
    pub tool_search: crate::toolsearch::ToolSearchConfig,
    /// Tool profile (OpenClaw): minimal | coding | messaging | devops | secops | data | itsupport | full. Unset = full.
    pub profile: Option<String>,
    /// Replaces the profile's tool list (names, `group:<x>`, globs).
    pub allow: Vec<String>,
    pub also_allow: Vec<String>,
    /// Always wins.
    pub deny: Vec<String>,
    /// Narrower policies per `provider` or `provider/model`, per channel, per `channel:sender`.
    pub by_provider: BTreeMap<String, ark_security::toolpolicy::Layer>,
    pub by_channel: BTreeMap<String, ark_security::toolpolicy::Layer>,
    pub by_sender: BTreeMap<String, ark_security::toolpolicy::Layer>,
}

impl ToolsConfig {
    pub fn layer(&self) -> ark_security::toolpolicy::Layer {
        ark_security::toolpolicy::Layer { profile: self.profile.clone(), allow: self.allow.clone(), also_allow: self.also_allow.clone(), deny: self.deny.clone() }
    }
    pub fn permits(&self, origin: &ark_security::toolpolicy::Origin, tool: &str) -> bool {
        ark_security::toolpolicy::allowed(&self.layer(), &self.by_provider, &self.by_channel, &self.by_sender, origin, tool)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LearnConfig {
    /// Background review after each turn proposes memory entries (staged, not applied).
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CheckpointConfig {
    pub enabled: bool,
    /// Skip snapshotting workspaces with more files than this.
    pub max_files: usize,
    /// Snapshots kept per workspace; older ones are rewritten away (0 = unlimited).
    pub max_snapshots: usize,
    /// Ceiling on the whole store; the oldest snapshot per workspace is dropped round-robin (0 = off).
    pub max_total_size_mb: u64,
    /// Files larger than this are not snapshotted (0 = no filter).
    pub max_file_size_mb: u64,
    /// Background sweep from the daemon: stale stores and the size cap (never orphans).
    pub auto_prune: bool,
    /// Workspaces untouched this long are deleted by prune.
    pub retention_days: u32,
    /// The background sweep runs at most this often.
    pub min_interval_hours: u32,
}

impl Default for ModelConfig {
    fn default() -> Self {
        ModelConfig {
            default: "anthropic/claude-sonnet-5-5".into(),
            fallback: vec![],
            aux: String::new(),
            subagent: String::new(),
            max_tokens: 8192,
            temperature: None,
            thinking: String::new(),
            fast: String::new(),
            fast_auto_seconds: 60,
            verbosity: String::new(),
            strict_tools: false,
            aliases: BTreeMap::new(),
            allow: vec![],
            tasks: BTreeMap::new(),
            context_length: None,
            confirm_input_usd: 20.0,
            confirm_output_usd: 100.0,
        }
    }
}
impl Default for RunnerConfig {
    fn default() -> Self {
        RunnerConfig { max_steps_per_turn: 200, max_retries: 5, retry_base_ms: 1000, retry_max_ms: 60_000, spill_bytes: 16_000, repeat_limit: 3, max_spawn_depth: 2, max_continuations: 3, max_parallel_tools: 8, busy_mode: "steer".into() }
    }
}
impl Default for CompactionConfig {
    fn default() -> Self {
        CompactionConfig { threshold: 0.75, prune_threshold: 0.5, keep_tool_results: 6, max_tool_result_chars: 2000, keep_messages: 8, micro_compact: false, micro_compact_every_n_turns: 1, micro_compact_defrag_threshold_tokens: 2000, native: NativeCompactionConfig::default() }
    }
}
impl Default for ScheduleConfig {
    fn default() -> Self {
        ScheduleConfig { utc_offset_minutes: 480, tick_secs: 30 }
    }
}
impl Default for CheckpointConfig {
    fn default() -> Self {
        CheckpointConfig { enabled: true, max_files: 20_000, max_snapshots: 20, max_total_size_mb: 500, max_file_size_mb: 10, auto_prune: true, retention_days: 7, min_interval_hours: 24 }
    }
}

impl CheckpointConfig {
    pub fn limits(&self) -> crate::checkpoint::Limits {
        crate::checkpoint::Limits { max_snapshots: self.max_snapshots, max_file_bytes: self.max_file_size_mb * 1024 * 1024 }
    }
}

impl Config {
    pub fn aux_model(&self) -> &str {
        if self.model.aux.is_empty() {
            &self.model.default
        } else {
            &self.model.aux
        }
    }
    pub fn subagent_model(&self) -> &str {
        if self.model.subagent.is_empty() {
            &self.model.default
        } else {
            &self.model.subagent
        }
    }
    pub fn price(&self, model: &str) -> Option<Price> {
        self.prices.get(model).copied().or_else(|| crate::ledger::fallback_price(model))
    }
    /// `alias` → `provider/model` (unknown names pass through).
    pub fn resolve_model<'a>(&'a self, m: &'a str) -> &'a str {
        self.model.aliases.get(m).map(String::as_str).unwrap_or(m)
    }
    /// Ordered candidates for an auxiliary task: its own `[auxiliary.<task>]` route, then an
    /// explicit `[model.tasks]` entry (aliases resolved), then the task's fallback chain, the
    /// `aux` model, the default and the main `[model] fallback` chain.
    pub fn task_plan(&self, task: &str) -> Vec<String> {
        let mut plan: Vec<String> = Vec::new();
        plan.extend(ark_model::aux::plan(&self.auxiliary, task, &self.model.aux, &self.model.default, &self.model.fallback));
        if let Some(m) = self.model.tasks.get(task).filter(|m| !m.is_empty()) {
            plan.insert(0, self.resolve_model(m).to_string());
        }
        let mut seen: Vec<String> = Vec::new();
        plan.retain(|m| {
            let m = self.resolve_model(m).to_string();
            if seen.contains(&m) {
                return false;
            }
            seen.push(m);
            true
        });
        plan.iter().map(|m| self.resolve_model(m).to_string()).collect()
    }

    /// Model for an auxiliary task (`[auxiliary.<task>]`, `[model.tasks]`, else `aux`, else the
    /// default), skipping providers a failed auxiliary call has held out (see
    /// `ark_model::aux::mark_down`).
    pub fn task_model(&self, task: &str) -> String {
        let plan = self.task_plan(task);
        ark_model::aux::pick(&plan).unwrap_or_else(|| self.aux_model().to_string())
    }

    /// Endpoint health for auxiliary routing: the providers a failed call held out.
    pub fn aux_holdouts(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for task in self.auxiliary.keys().chain(self.model.tasks.keys()) {
            for m in self.task_plan(task) {
                if let Some((p, _)) = m.split_once('/') {
                    if ark_model::aux::down(p) && !v.iter().any(|x| x == p) {
                        v.push(p.to_string());
                    }
                }
            }
        }
        v
    }
    /// Whether `model.allow` permits switching to `m`.
    pub fn model_allowed(&self, m: &str) -> bool {
        let a = &self.model.allow;
        let listed = a.is_empty() || a.iter().any(|p| p == m || p.strip_suffix("/*").is_some_and(|pre| m.split('/').next() == Some(pre))) || m == self.model.default;
        listed && crate::governance::class_allows(&self.compliance, m).is_ok()
    }

    /// The whole system → user → project → `--set` stack, with `/etc/ark` policy applied.
    pub fn load_with_system(system: &[PathBuf], user: Option<&Path>, project: Option<&Path>, sets: &[String]) -> Result<Config, String> {
        Self::load_layers(system, user, project, sets)
    }

    /// Load and merge layers. Missing files are fine; malformed ones are errors.
    pub fn load(user: Option<&Path>, project: Option<&Path>, sets: &[String]) -> Result<Config, String> {
        Self::load_layers(&crate::managed::system_files(), user, project, sets)
    }

    fn load_layers(system: &[PathBuf], user: Option<&Path>, project: Option<&Path>, sets: &[String]) -> Result<Config, String> {
        // ent-063: the system layer is the base, and its locked keys are re-applied last.
        let (sys, locked, sys_files) = crate::managed::load_system(system)?;
        let mut merged = sys.clone();
        let mut dropped = Vec::new();
        for (layer, p) in [(0, user), (1, project)] {
            let Some(p) = p.filter(|p| p.exists()) else { continue };
            let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            let mut t: toml::Table = text.parse().map_err(|e| format!("{}: {e}", p.display()))?;
            if layer == 1 && !project_trusted(&merged, p) {
                for k in PROJECT_GATED {
                    if t.remove(*k).is_some() {
                        dropped.push(*k);
                    }
                }
                // `context.pre_verify` runs commands: same rule as `hooks`.
                if t.get_mut("context").and_then(|c| c.as_table_mut()).and_then(|c| c.remove("pre_verify")).is_some() {
                    dropped.push("context.pre_verify");
                }
            }
            merge(&mut merged, t);
        }
        let mut notes: Vec<String> = vec![];
        if !dropped.is_empty() {
            notes.push(format!("ignoring {} from untrusted project config (add the workspace to `trusted_projects` in your user config)", dropped.join(", ")));
        }
        for s in sets {
            let (k, v) = s.split_once('=').ok_or_else(|| format!("--set expects key=value, got `{s}`"))?;
            set_path(&mut merged, k.trim(), parse_value(v.trim()))?;
        }
        let overridden = crate::managed::enforce(&mut merged, &sys, &locked);
        if !overridden.is_empty() {
            notes.push(format!("{} locked by system policy ({}); your value is ignored", overridden.join(", "), sys_files.join(", ")));
        }
        for n in &notes {
            eprintln!("ark: {n}");
        }
        let mut cfg: Config = toml::Value::Table(merged).try_into().map_err(|e: toml::de::Error| format!("config: {}", e.message()))?;
        cfg.managed = crate::managed::Managed { files: sys_files, locked, overridden };
        if cfg.compliance.profile == "government" {
            for h in PRC_HOSTS {
                if !cfg.gate.egress_deny.iter().any(|x| x == h) {
                    cfg.gate.egress_deny.push(h.to_string());
                }
            }
        }
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), String> {
        match self.compliance.profile.as_str() {
            "" | "default" => {}
            "government" => {
                for m in std::iter::once(&self.model.default).chain(self.model.fallback.iter()).chain([&self.model.aux, &self.model.subagent].into_iter().filter(|s| !s.is_empty())) {
                    let p = m.split('/').next().unwrap_or("");
                    if PRC_PROVIDERS.contains(&p) {
                        return Err(format!("compliance.profile = \"government\": model `{m}` is provided from the PRC and is not allowed for public-sector use"));
                    }
                }
            }
            other => return Err(format!("compliance.profile `{other}`: use \"government\" or leave it empty")),
        }
        // ent-093: every configured model has to be approved for this install's data class.
        if !self.compliance.data_class.trim().is_empty() {
            for m in std::iter::once(&self.model.default).chain(self.model.fallback.iter()).chain([&self.model.aux, &self.model.subagent].into_iter().filter(|s| !s.is_empty())) {
                crate::governance::class_allows(&self.compliance, self.resolve_model(m))?;
            }
        }
        if !matches!(self.quotas.period.as_str(), "month" | "day") {
            return Err(format!("quotas.period `{}`: use month or day", self.quotas.period));
        }
        if !matches!(self.model.thinking.as_str(), "" | "off" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max") {
            return Err(format!("model.thinking `{}`: use off, minimal, low, medium, high, xhigh or max", self.model.thinking));
        }
        if !matches!(self.model.fast.as_str(), "" | "normal" | "off" | "fast" | "priority" | "on" | "ultrafast" | "flex" | "auto" | "cold") {
            return Err(format!("model.fast `{}`: use fast, ultrafast, flex, auto, cold or leave empty", self.model.fast));
        }
        if !matches!(self.model.verbosity.as_str(), "" | "low" | "medium" | "high") {
            return Err(format!("model.verbosity `{}`: use low, medium or high", self.model.verbosity));
        }
        for (k, v) in &self.model.aliases {
            if !v.contains('/') {
                return Err(format!("model.aliases.{k} must be `provider/model`, got `{v}`"));
            }
        }
        let resolved = self.resolve_model(&self.model.default);
        if !resolved.contains('/') {
            return Err(format!("model.default must be `provider/model`, got `{}`", self.model.default));
        }
        for m in self.model.fallback.iter().chain([&self.model.aux, &self.model.subagent].into_iter().filter(|s| !s.is_empty())).chain(self.model.tasks.values()) {
            if !self.resolve_model(m).contains('/') {
                return Err(format!("model `{m}` must be `provider/model`"));
            }
        }
        let c = &self.compaction;
        if !(0.1..=0.98).contains(&c.threshold) || !(0.05..=c.threshold).contains(&c.prune_threshold) {
            return Err("compaction: need 0.05 <= prune_threshold <= threshold <= 0.98".into());
        }
        if crate::queue::Mode::parse(&self.runner.busy_mode).is_none() {
            return Err(format!("runner.busy_mode `{}`: use steer, followup, collect or interrupt", self.runner.busy_mode));
        }
        if self.runner.max_parallel_tools == 0 || self.runner.max_steps_per_turn == 0 {
            return Err("runner: max_parallel_tools and max_steps_per_turn must be > 0".into());
        }
        self.limits.validate()?;
        ark_security::toolpolicy::validate(&self.tools.layer(), "tools")?;
        for (scope, m) in [("tools.by_provider", &self.tools.by_provider), ("tools.by_channel", &self.tools.by_channel), ("tools.by_sender", &self.tools.by_sender)] {
            for (k, l) in m {
                ark_security::toolpolicy::validate(l, &format!("{scope}.{k}"))?;
            }
        }
        if !(-720..=840).contains(&self.schedule.utc_offset_minutes) {
            return Err("schedule.utc_offset_minutes out of range".into());
        }
        // Section owners validate their own table (`ark_core::registry`): `[kanban]` in
        // `kanban`, and so on. Empty until the binary's `registry_init` has run, so library
        // callers keep exactly the checks above.
        if let Some(msg) = ark_core::registry::validate_config(self).into_iter().next() {
            return Err(msg);
        }
        Ok(())
    }

    pub fn dump(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }
}

pub(crate) fn merge_tables(base: &mut toml::Table, over: toml::Table) {
    merge(base, over)
}

fn merge(base: &mut toml::Table, over: toml::Table) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(toml::Value::Table(b)), toml::Value::Table(o)) => merge(b, o),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

fn set_path(t: &mut toml::Table, path: &str, v: toml::Value) -> Result<(), String> {
    let parts: Vec<&str> = path.split('.').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(format!("bad key `{path}`"));
    }
    let mut cur = t;
    for p in &parts[..parts.len() - 1] {
        let e = cur.entry(p.to_string()).or_insert_with(|| toml::Value::Table(toml::Table::new()));
        cur = e.as_table_mut().ok_or_else(|| format!("`{p}` is not a table"))?;
    }
    cur.insert(parts[parts.len() - 1].to_string(), v);
    Ok(())
}

/// `--set` values: TOML literal when it parses (numbers, bools, arrays), else string.
fn parse_value(s: &str) -> toml::Value {
    format!("v = {s}").parse::<toml::Table>().ok().and_then(|mut t| t.remove("v")).unwrap_or_else(|| toml::Value::String(s.to_string()))
}

/// `project` is `<ws>/.ark/config.toml`; trust is listed by workspace path.
fn project_trusted(user: &toml::Table, project: &Path) -> bool {
    let Some(ws) = project.parent().and_then(Path::parent).and_then(|w| w.canonicalize().ok()) else { return false };
    user.get("trusted_projects").and_then(|v| v.as_array()).is_some_and(|a| a.iter().filter_map(|v| v.as_str()).any(|t| Path::new(t).canonicalize().is_ok_and(|t| t == ws)))
}

/// Unix socket paths are capped at 107 bytes and the runtime dir holds
/// `call-<16 hex>.sock`, so a deep home moves its runtime dir somewhere short.
/// The replacement is derived from the original path, so daemon and clients agree.
const RUNTIME_MAX: usize = 80;

fn short_runtime(dir: PathBuf) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    if dir.as_os_str().len() <= RUNTIME_MAX {
        return dir;
    }
    // FNV-1a: stable across builds, unlike DefaultHasher.
    let h = dir.as_os_str().as_bytes().iter().fold(0xcbf29ce484222325u64, |h, b| (h ^ *b as u64).wrapping_mul(0x100000001b3));
    let tag = format!("ark-{:012x}", h & 0xffff_ffff_ffff);
    if let Some(r) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|r| r.is_absolute() && r.as_os_str().len() + tag.len() < RUNTIME_MAX) {
        return r.join(tag);
    }
    // Shared /tmp: our own 0700 directory, refusing one someone else planted.
    let uid = unsafe { libc::getuid() };
    let base = PathBuf::from(format!("/tmp/ark-{uid}"));
    let _ = std::fs::DirBuilder::new().mode(0o700).create(&base);
    match std::fs::symlink_metadata(&base) {
        Ok(m) if m.is_dir() && m.uid() == uid && m.mode() & 0o077 == 0 => base.join(tag),
        _ => dir, // fails later with a clear "path too long" rather than trusting a foreign dir
    }
}

/// Filesystem layout. `ARK_HOME` overrides everything (tests, portable installs).
#[derive(Debug, Clone)]
pub struct Paths {
    pub data: PathBuf,
    pub config_dir: PathBuf,
    pub runtime: PathBuf,
}

impl Paths {
    pub fn from_env() -> Paths {
        if let Some(h) = std::env::var_os("ARK_HOME") {
            let h = PathBuf::from(h);
            return Paths { data: h.join("data"), config_dir: h.join("config"), runtime: short_runtime(h.join("run")) };
        }
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"));
        let xdg = |var: &str, def: &str| std::env::var_os(var).map(PathBuf::from).filter(|p| p.is_absolute()).unwrap_or_else(|| home.join(def));
        let data = xdg("XDG_DATA_HOME", ".local/share").join("ark");
        let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(|r| PathBuf::from(r).join("ark")).unwrap_or_else(|| data.join("run"));
        Paths { data, config_dir: xdg("XDG_CONFIG_HOME", ".config").join("ark"), runtime: short_runtime(runtime) }
    }
    pub fn user_config(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }
    pub fn secrets(&self) -> PathBuf {
        self.config_dir.join("secrets.toml")
    }
    pub fn sessions(&self) -> PathBuf {
        self.data.join("sessions")
    }
    pub fn socket(&self) -> PathBuf {
        self.runtime.join("arkd.sock")
    }
    pub fn skills_dirs(&self, workspace: &Path) -> Vec<PathBuf> {
        let mut v = vec![workspace.join(".ark/skills"), workspace.join(".claude/skills"), workspace.join(".agents/skills"), self.data.join("skills")];
        if let Some(h) = std::env::var_os("HOME") {
            v.push(PathBuf::from(h).join(".claude/skills"));
        }
        v
    }
}

pub fn project_config(workspace: &Path) -> PathBuf {
    workspace.join(".ark/config.toml")
}

pub const SAMPLE: &str = r#"# ark configuration — every key is optional.
[model]
default = "anthropic/claude-sonnet-5-5"   # provider/model
fallback = ["openrouter/anthropic/claude-sonnet-5-5"]
aux = ""        # cheap model for compaction / review, e.g. "deepseek/deepseek-chat"
max_tokens = 8192

[budget]        # per session; omit for unlimited
# max_tokens = 2000000
# max_cost_usd = 5.0

# [limits]      # per-agent / global resource caps, 0 = off (see `ark doctor`)
# per_agent_spend_usd = 5.0
# hourly_spend_usd = 20.0
# global_spend_usd = 200.0
# max_processes_per_agent = 16
# disk_mb_per_agent = 2048
# disk_mb_total = 20480
# warn_at = 0.8              # warn at 80 %, pause the affected session at 100 %
# check_interval_secs = 60
# reap_interval_secs = 300   # orphaned process-group sweep, 0 = off

[gate]          # only two gates: privilege (sudo & system changes) and egress (data leaving)
privilege = "ask"   # ask | deny | allow
egress = "ask"
egress_allow = ["github.com"]
egress_deny = []

[schedule]
utc_offset_minutes = 480   # cron timezone (UTC+8)

# [network]     # proxy = "http://proxy:3128", no_proxy = ["10.0.0.0/8"], ca_file = "/etc/ssl/corp.pem"

[approvals]     # manual | smart | auto | off  (floors such as `deny` always apply)
mode = "manual"
deny = []           # command globs that never run, even under --yolo
# [approvals.exec]  security = "full" | "allowlist" | "deny"; ask = "off" | "on-miss" | "always"

[security]
workspace_only = false

# [role]        # professional role (`ark role use`): ISCO occupation or preset
# active = "swdev"           # devops | swdev | secops | data | itsupport | a pack slug; "" = L0 core only
# core = true                # the L0 professional core in every identity
# scan_targets = ["10.0.0.0/24"]   # where a secops role may run active scanners

# [providers.myvllm]
# format = "openai_chat"
# base_url = "http://localhost:8000/v1"
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn auxiliary_tasks_route_fall_back_and_skip_held_out_providers() {
        let root = std::env::temp_dir().join(format!("ark-aux-{}", crate::util::random_hex(6)));
        std::fs::create_dir_all(&root).unwrap();
        let user = root.join("user.toml");
        std::fs::write(
            &user,
            r#"
[model]
default = "anthropic/claude-sonnet-5-5"
aux = "anthropic/claude-haiku-4-5"
fallback = ["openai/gpt-5.4-mini"]
[auxiliary.vision]
provider = "dashscope"
model = "qwen3.7-plus"
fallback = ["zai/glm-5.3"]
[auxiliary.compression]
provider = "groq"
model = "llama-3.3-70b"
[auxiliary.approval]
provider = "auto"
model = "zai/glm-5.3"
"#,
        )
        .unwrap();
        let c = Config::load(Some(&user), None, &[]).unwrap();
        // A pinned task route wins over `aux`, with its own fallback chain before the main one.
        assert_eq!(c.task_plan("vision")[0], "dashscope/qwen3.7-plus");
        assert_eq!(c.task_plan("vision")[1], "zai/glm-5.3");
        assert_eq!(c.task_model("vision"), "dashscope/qwen3.7-plus");
        // Upstream task names configure ark's task too (compaction ↔ auxiliary.compression).
        assert_eq!(c.task_model("compaction"), "groq/llama-3.3-70b");
        // `provider = auto` keeps the task's model and follows the main selection otherwise.
        assert_eq!(c.task_model("approval"), "zai/glm-5.3");
        // Unconfigured tasks follow `aux`, then the default and the main fallback chain.
        let p = c.task_plan("sampling");
        assert_eq!((p[0].as_str(), p[1].as_str(), p[2].as_str()), ("anthropic/claude-haiku-4-5", "anthropic/claude-sonnet-5-5", "openai/gpt-5.4-mini"));
        assert_eq!(c.task_model("sampling"), "anthropic/claude-haiku-4-5");
        // `[model.tasks]` still wins over the auxiliary block, aliases resolved.
        let mut c2 = c.clone();
        c2.model.tasks.insert("compaction".into(), "fast".into());
        c2.model.aliases.insert("fast".into(), "groq/llama-3.1-8b".into());
        assert_eq!(c2.task_model("compaction"), "groq/llama-3.1-8b");
        // A lane a failed call held out is skipped; the task's next candidate serves.
        ark_model::aux::mark_down("dashscope", "rate limit");
        assert_eq!(ark_model::aux::pick(&c.task_plan("vision")).as_deref(), Some("zai/glm-5.3"));
        assert!(c.aux_holdouts().contains(&"dashscope".to_string()));
        ark_model::aux::clear("dashscope");
        assert!(c.aux_holdouts().is_empty());
        assert_eq!(c.task_model("vision"), "dashscope/qwen3.7-plus");
    }

    #[test]
    fn untrusted_project_cannot_add_hooks_or_servers() {
        let root = std::env::temp_dir().join(format!("ark-trust-{}", crate::util::random_hex(6)));
        let ws = root.join("ws");
        std::fs::create_dir_all(ws.join(".ark")).unwrap();
        let user = root.join("user.toml");
        let proj = ws.join(".ark/config.toml");
        std::fs::write(&proj, "identity = \"proj\"\n[[hooks]]\nevent = \"pre_tool\"\ncommand = \"curl evil\"\n[mcp.x]\ncommand = \"evil\"\n[surfaces]\npublic_url = \"https://evil.example\"\n").unwrap();
        std::fs::write(&user, "[mcp.mine]\ncommand = \"ok\"\n").unwrap();
        let c = Config::load(Some(&user), Some(&proj), &[]).unwrap();
        assert_eq!(c.identity, "proj", "harmless keys still apply");
        assert!(c.hooks.is_empty() && !c.mcp.contains_key("x") && c.mcp.contains_key("mine"));
        assert!(c.surfaces.is_empty(), "[surfaces] (tool-returned links) is project-gated too");
        std::fs::write(&user, format!("trusted_projects = [\"{}\"]\n", ws.display())).unwrap();
        let c = Config::load(Some(&user), Some(&proj), &[]).unwrap();
        assert_eq!(c.hooks.len(), 1);
        assert!(c.mcp.contains_key("x"));
        assert_eq!(c.surfaces.get("public_url").and_then(|v| v.as_str()), Some("https://evil.example"), "a trusted project keeps it");
        // A project can't trust itself.
        std::fs::write(&user, "").unwrap();
        std::fs::write(&proj, format!("trusted_projects = [\"{}\"]\n[[hooks]]\nevent = \"pre_tool\"\ncommand = \"x\"\n", ws.display())).unwrap();
        assert!(Config::load(Some(&user), Some(&proj), &[]).unwrap().hooks.is_empty());
    }

    #[test]
    fn deep_runtime_dir_is_shortened_deterministically() {
        let short = PathBuf::from("/home/u/.local/share/ark/run");
        assert_eq!(short_runtime(short.clone()), short);
        let deep = PathBuf::from(format!("/home/u/{}/run", "very-long-directory-name/".repeat(6)));
        let a = short_runtime(deep.clone());
        assert!(a.as_os_str().len() <= RUNTIME_MAX, "{}", a.display());
        assert_eq!(a, short_runtime(deep.clone()), "daemon and client must agree");
        assert_ne!(a, short_runtime(deep.join("other")), "different homes don't share a socket");
        assert!(a.join("call-0123456789abcdef.sock").as_os_str().len() < 108);
    }

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("ark-cfg-{}", crate::util::random_hex(8)));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn layering_and_sets() {
        let d = tmp();
        let u = d.join("u.toml");
        let p = d.join("p.toml");
        fs::write(&u, "[model]\ndefault = \"a/b\"\nmax_tokens = 100\n[gate]\negress_allow=[\"x.com\"]\n").unwrap();
        fs::write(&p, "[model]\nmax_tokens = 200\n").unwrap();
        let c = Config::load(Some(&u), Some(&p), &["budget.max_steps=7".into(), "gate.privilege=deny".into(), "identity=be terse".into()]).unwrap();
        assert_eq!(c.model.default, "a/b");
        assert_eq!(c.model.max_tokens, 200);
        assert_eq!(c.budget.max_steps, Some(7));
        assert_eq!(c.gate.privilege, crate::gate::Mode::Deny);
        assert_eq!(c.gate.egress_allow, ["x.com"]);
        assert_eq!(c.identity, "be terse");
        assert!(c.dump().contains("max_tokens = 200"));
        // Dump must round-trip.
        let again: Config = toml::from_str(&c.dump()).unwrap();
        assert_eq!(again.model.max_tokens, 200);
    }

    #[test]
    fn errors_are_reported_not_ignored() {
        let d = tmp();
        let bad = d.join("bad.toml");
        fs::write(&bad, "[model\n").unwrap();
        assert!(Config::load(Some(&bad), None, &[]).is_err());
        fs::write(&bad, "[model]\ndefualt = \"x/y\"\n").unwrap();
        assert!(Config::load(Some(&bad), None, &[]).unwrap_err().contains("defualt"), "typos are caught");
        assert!(Config::load(None, None, &["model.default=nomodel".into()]).unwrap_err().contains("provider/model"));
        assert!(Config::load(None, None, &["noequals".into()]).is_err());
        assert!(Config::load(None, None, &["a..b=1".into()]).is_err());
        assert!(Config::load(None, None, &["compaction.threshold=2".into()]).is_err());
        assert!(Config::load(None, None, &["model.max_tokens=\"lots\"".into()]).is_err());
    }

    #[test]
    fn sample_config_is_valid() {
        let d = tmp();
        let f = d.join("c.toml");
        fs::write(&f, SAMPLE).unwrap();
        Config::load(Some(&f), None, &[]).unwrap();
    }

    #[test]
    fn missing_files_use_defaults() {
        let c = Config::load(Some(Path::new("/nonexistent/x.toml")), None, &[]).unwrap();
        assert_eq!(c.runner.max_spawn_depth, 2);
        assert_eq!(c.aux_model(), c.model.default);
        assert_eq!((c.checkpoint.max_snapshots, c.checkpoint.max_total_size_mb, c.checkpoint.retention_days), (20, 500, 7));
        assert_eq!(c.checkpoint.limits().max_file_bytes, 10 * 1024 * 1024);
        assert!(!c.trajectory.save && c.trace.private && c.trace.dataset == "ark-traces");
        assert!(!c.compaction.native.enabled && c.compaction.native_threshold(200_000).is_none());
    }

    #[test]
    fn display_language_key_parses_and_defaults_to_following_the_env() {
        let d = tmp();
        let f = d.join("c.toml");
        fs::write(&f, "[display]\nlanguage = \"zh-TW\"\n").unwrap();
        assert_eq!(Config::load(Some(&f), None, &[]).unwrap().display.language, "zh-TW");
        // Unset: empty string (the i18n layer then follows ARK_LANGUAGE, else English).
        assert_eq!(Config::default().display.language, "");
        // A typo in the table is refused like everywhere else.
        fs::write(&f, "[display]\nlangauge = \"ja\"\n").unwrap();
        assert!(Config::load(Some(&f), None, &[]).is_err());
        // It round-trips through the sample dump.
        let c = Config::load(None, None, &["display.language=ja".into()]).unwrap();
        assert_eq!(c.display.language, "ja");
    }

    #[test]
    fn native_compaction_config_clamps_below_the_local_trigger() {
        let d = tmp();
        let f = d.join("c.toml");
        fs::write(&f, "[compaction.native]\nenabled = true\n").unwrap();
        let c = Config::load(Some(&f), None, &[]).unwrap();
        assert!(c.compaction.native.enabled);
        // Automatic: 200k window * 0.75 - 8192.
        assert_eq!(c.compaction.native_threshold(200_000), Some(150_000 - 8_192));
        // Small windows take 80% instead of subtracting the margin.
        assert_eq!(c.compaction.native_threshold(4_000), Some(2_400));
        // An explicit value is clamped below the local trigger, and never under 1024.
        fs::write(&f, "[compaction.native]\nenabled = true\nthreshold_tokens = 180000\n").unwrap();
        assert_eq!(Config::load(Some(&f), None, &[]).unwrap().compaction.native_threshold(200_000), Some(141_808));
        fs::write(&f, "[compaction.native]\nenabled = true\nthreshold_tokens = 5\n").unwrap();
        assert_eq!(Config::load(Some(&f), None, &[]).unwrap().compaction.native_threshold(200_000), Some(1_024));
        // Unknown window falls back to the documented default.
        fs::write(&f, "[compaction.native]\nenabled = true\n").unwrap();
        assert_eq!(Config::load(Some(&f), None, &[]).unwrap().compaction.native_threshold(0), Some(200_000));
        // A typo in the table is refused, like everywhere else in the config.
        fs::write(&f, "[compaction.native]\nenabeld = true\n").unwrap();
        assert!(Config::load(Some(&f), None, &[]).is_err());
    }
}
