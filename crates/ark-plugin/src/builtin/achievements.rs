//! `achievements` (Hermes `plugins/hermes-achievements/`, MIT, originally by [@PCinkusz]) — ported
//! as a built-in ark plugin.
//!
//! Upstream is a dashboard-only plugin: a FastAPI router mounted at
//! `/api/plugins/hermes-achievements/` over a module-level snapshot cache, plus a thread that runs
//! cold scans in the background. This port keeps the ENGINE — the 60 badge catalog, the
//! per-session analysis, tiered/multi-condition evaluation, sticky unlock state, the
//! fingerprint-checkpointed incremental scan and the 120 s snapshot TTL — and drops the FastAPI
//! glue:
//!
//! | upstream route | here |
//! |---|---|
//! | `GET /achievements` | [`data`] (payload) and tool `achievements` / `/achievements` `overview` |
//! | `GET /scan-status` | `data().scan_meta.status` |
//! | `GET /recent-unlocks` | `recent` (tool + slash) |
//! | `GET /sessions/{id}/badges` | `session <id>` (tool + slash) |
//! | `POST /rescan` | `scan` (tool + slash, `force: true`) |
//! | `POST /reset-state` | `reset` (tool + slash) |
//!
//! **Dashboard surface.** ark's app server only mounts HTTP routes for *external* plugin
//! processes (`crates/ark-app/src/server.rs` speaks to plugin processes over the plugin
//! protocol; a built-in has no process at all). So this built-in exposes the identical JSON
//! through [`data`] and the same information as text through the `achievements` tool and
//! `/achievements`; mounting it under `/api/plugins/achievements` would need an ark-app change (a
//! route table for built-ins), which this port deliberately does not make — `data()` is the seam a
//! future ark-app route would call.
//!
//! # Sessions: Hermes SQLite → ark JSONL
//!
//! Upstream scans Hermes' `SessionDB` (SQLite rows carrying `role`, `content`, `tool_name`,
//! `tool_calls`). ark keeps one append-only JSONL log per session, read through
//! [`ark_kernel::store::Store`]: `Store::list()` gives `{id, model, title, created_ms, updated_ms,
//! messages}` and `Store::read(id)` the `Event`s. The mapping is:
//!
//! | Hermes row | ark event |
//! |---|---|
//! | user/assistant message | `EventKind::Message { message, model, .. }` |
//! | assistant `tool_calls[i].function.name` | `EventKind::ToolCalled { name, input, .. }` |
//! | tool result row (`role="tool"`) | `EventKind::ToolSettled { is_error, .. }` (the result *text*
//!   is not in the log, so `is_error` is the error signal) |
//! | session `model` metadata | `Header.model` + every `EventKind::Model { model }` |
//! | — | `EventKind::Error { message }` also counts as an error and joins the analysed text |
//!
//! `full_text` (the regex haystack) is the concatenation of message texts — exactly upstream's
//! `"\n".join(content)`. File paths are additionally harvested from tool *inputs* (upstream
//! appends `json.dumps(tool_calls)` to the blob it runs `FILE_RE` over).
//!
//! # Tool-name mapping
//!
//! Upstream's metric names are counts over Hermes tool names (`_count_tool(sequence, needle)` =
//! "calls whose name contains a needle"). ark's tools are named differently, so each ark name is
//! canonicalised to its Hermes equivalent before the needles are applied
//! (`canonical_tool`); `tool_names` / `distinct_tool_count` keep the *ark* names (what actually
//! ran) so the dashboard shows the truth.
//!
//! | Hermes tool | ark tool(s) | canonical |
//! |---|---|---|
//! | `terminal` | `shell` | `terminal` |
//! | `read_file` | `read` | `read_file` |
//! | `write_file` | `write` | `write_file` |
//! | `patch` | `patch`, `edit`, `apply_patch` | `patch` |
//! | `search_files` | `glob`, `grep` | `search_files` |
//! | `web_search` | `web_search` | `web_search` |
//! | `web_extract` | `web_extract`, `web_fetch` | `web_extract` |
//! | `browser`* | `browser`, `browser_*` | unchanged (needle `browser`) |
//! | `delegate_task` | `spawn`, `acp_delegate` | `delegate_task` |
//! | `process` | `job` | `process` |
//! | `cronjob`* | `cronjob_manage` | `cronjob` |
//! | `image`*/`vision`* | `image_generate`, `view_image`, `vision_analyze` | unchanged (`image`/`vision` needles match) |
//! | `tts`/`text_to_speech` | `text_to_speech`, `voice_call` | unchanged |
//! | `skill` | `skill` | unchanged |
//! | `skill_manage` | none — ark's `skill` tool carries the manage actions | counted from `skill` calls whose `action` is create/update/archive |
//! | `memory`/`mnemosyne` | `memory`, `memory_*` | unchanged (`memory` needle matches) |
//!
//! **Patterns.** Upstream's regexes are used verbatim, with three ark-shaped additions: `FILE_RE`
//! also accepts `.rs`/`.toml`/`.go` (ark projects are Rust), `config_events` also counts
//! `config.toml`/`Cargo.toml`, and `test_events` also counts `cargo test`. Every other alternation
//! (`ERROR_RE`, `PORT_RE`, `INSTALL_RE`, `SUCCESS_RE`, the event patterns) is byte-for-byte
//! upstream's.
//!
//! **What cannot be mapped (and why).**
//! - `skill_manage_events` cannot be a pure name count: ark has no `skill_manage` tool, so it is
//!   the number of `skill` calls with `action` in {create, update, archive} (plus any name
//!   containing `skill_manage`, should a plugin contribute one).
//! - `restart_after_error_events` / `install_*` / `tiny_patch_after_errors_events` are
//!   session-level *text* signals upstream; ark's tool results live in artifacts, not in the event
//!   log, so only message text and `ToolSettled.is_error` can feed them (same for `log_read_*`).
//! - `source` (upstream's session origin: `cli`/`telegram`/…) has no ark analogue; the snapshot's
//!   sessions omit it.
//! - Upstream reads *compaction-archived* history so its stats are monotonic. ark's log keeps the
//!   full event stream (compaction only changes what the model sees) so no archival read exists.
//!
//! # State and durability
//!
//! `$ARK_HOME/data/plugin-data/achievements/` holds, exactly as upstream:
//! - `state.json` — `{"unlocks": {"<id>": {"tier": …, "unlocked_at": <unix>, "evidence": …}}}`. A
//!   floor: an earned badge is never re-locked (rewind/compaction cannot take it away) and
//!   `unlocked_at` is the *first* unlock.
//! - `scan_checkpoint.json` — `schema_version: 2`, per-session stats keyed by a fingerprint of
//!   `(created, last-active, model, title)` so a warm scan only re-analyses changed sessions.
//! - `scan_snapshot.json` — the last computed payload; served for [`SNAPSHOT_TTL_SECONDS`] and
//!   marked `is_stale` after that instead of rescanning on every read.
//!
//! Unlike upstream there is no background scan thread and no partial snapshots: a scan is
//! synchronous, `data()` scans only when no snapshot exists (otherwise it serves the cached one,
//! stale or not) and `scan`/`force` always rescans.

use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use ark_kernel::config::{Config, Paths};
use ark_kernel::event::{Event, EventKind};
use ark_kernel::slash::{Slash, SlashCtx, SlashReply};
use ark_kernel::store::{SessionInfo, Store};
use ark_kernel::util::{atomic_write, fmt_time, unix_now};
use fancy_regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

// ───────────────────────── constants ─────────────────────────

/// `SNAPSHOT_TTL_SECONDS`: how long a computed snapshot is served before it is marked stale
/// (`_cache_is_fresh` / `_is_snapshot_stale`).
pub const SNAPSHOT_TTL_SECONDS: i64 = 120;

/// `_CHECKPOINT_SCHEMA_VERSION`. Schema 1 caches were computed differently upstream; a checkpoint
/// with any other version is ignored (everything is rescanned once).
const CHECKPOINT_SCHEMA_VERSION: u64 = 2;

/// `TIER_NAMES`, in ladder order.
const TIER_NAMES: [&str; 5] = ["Copper", "Silver", "Gold", "Diamond", "Olympian"];

/// Upstream file names (inside `<data>/plugin-data/achievements/`).
const STATE_FILE: &str = "state.json";
const CHECKPOINT_FILE: &str = "scan_checkpoint.json";
const SNAPSHOT_FILE: &str = "scan_snapshot.json";

const SECRET_CRITERIA: &str = "Secret: exact requirement hidden until ark sees the first matching signal. Keep using ark across debugging, tools, memory, skills, plugins, and model workflows to reveal it.";
const SECRET_DESCRIPTION: &str = "Secret achievement: hidden until ark detects the first relevant behavior in your session history.";

/// `ERROR_RE` / `PORT_RE` / `INSTALL_RE` / `SUCCESS_RE` / `FILE_RE`, verbatim.
const ERROR_RE: &str = r"\b(error|failed|failure|traceback|exception|permission denied|not found|eaddrinuse|already in use|timed out|blocked)\b";
const PORT_RE: &str = r"\b(port\s+)?(3000|5173|8000|8080|9119)\b.*\b(in use|already|taken|eaddrinuse)\b|\beaddrinuse\b";
const INSTALL_RE: &str = r"\b(npm|pnpm|yarn|pip|uv)\b.*\b(install|add)\b";
const SUCCESS_RE: &str =
    r#"\b(success|passed|built|compiled|done|exit_code["']?\s*[:=]\s*0|verified|ok)\b"#;
/// Upstream's extension list plus the ones ark's own projects touch (`rs`, `toml`, `go`) — without
/// them every ark edit would be invisible to `files_touched_count`.
const FILE_RE: &str = r"(?:/home/|~/?|\./|/mnt/)[\w./-]+\.(?:py|js|ts|tsx|jsx|css|html|md|json|yaml|yml|svg|sql|sh|rs|toml|go)";

// ───────────────────────── regexes ─────────────────────────

/// Case-insensitive compile (`hits()`/`ERROR_RE.search` are all `re.IGNORECASE` upstream).
fn ci(pattern: &str) -> Regex {
    Regex::new(&format!("(?i){pattern}"))
        .unwrap_or_else(|e| panic!("achievements regex `{pattern}` does not compile: {e}"))
}

/// Every pattern `analyze_messages` uses, compiled once (the Python module compiles them at import).
struct Patterns {
    error: Regex,
    port: Regex,
    install: Regex,
    success: Regex,
    file: Regex,
    bg_true: Regex,
    skill_word: Regex,
    traceback: Regex,
    log_read: Regex,
    permission: Regex,
    restart: Regex,
    env_var: Regex,
    yaml: Regex,
    docker: Regex,
    frontend: Regex,
    css: Regex,
    git: Regex,
    tiny_patch: Regex,
    context: Regex,
    gateway: Regex,
    plugin: Regex,
    rollback: Regex,
    docs: Regex,
    model: Regex,
    openrouter: Regex,
    codex: Regex,
    claude: Regex,
    gemini: Regex,
    local_model: Regex,
    toolset: Regex,
    config: Regex,
    git_history: Regex,
    test: Regex,
    screenshot: Regex,
    release: Regex,
    cache: Regex,
}

impl Patterns {
    fn new() -> Patterns {
        Patterns {
            error: ci(ERROR_RE),
            port: ci(PORT_RE),
            install: ci(INSTALL_RE),
            success: ci(SUCCESS_RE),
            file: ci(FILE_RE),
            bg_true: ci(r"background\s*=\s*true"),
            skill_word: ci(r"\bskill"),
            traceback: ci(r"traceback|exception"),
            log_read: ci(r"gateway\.log|errors\.log|agent\.log|/api/logs|\blogs\b"),
            permission: ci(r"permission denied|eacces|operation not permitted"),
            restart: ci(r"\brestart|reload|kill|start\b"),
            env_var: ci(
                r"missing .*env|api key|environment variable|not configured|unauthorized|auth",
            ),
            yaml: ci(r"yaml|yml|colon|parse error"),
            docker: ci(
                r"docker.*(name|container).*already|container name conflict|Conflict\. The container",
            ),
            frontend: ci(r"\.(css|svg|tsx|jsx)|frontend|tailwind|react"),
            css: ci(r"\.css|tailwind|style|className|visual"),
            git: ci(r"\bgit\s+(commit|push|merge|rebase|status|diff)"),
            tiny_patch: ci(r"one character|single character|typo"),
            context: ci(r"compress|context window|token|cache"),
            gateway: ci(r"gateway|discord|telegram|slack|api_server"),
            plugin: ci(r"plugin|dashboard-plugins|__HERMES_PLUGIN|manifest\.json"),
            rollback: ci(r"rollback|checkpoint"),
            docs: ci(r"docs|documentation|docusaurus|README"),
            model: ci(
                r"model|provider|openrouter|codex|gemini|claude|anthropic|openai|mistral|qwen|deepseek|llama|ollama|vllm|gguf",
            ),
            openrouter: ci(r"openrouter"),
            codex: ci(r"codex"),
            claude: ci(r"claude|anthropic"),
            gemini: ci(r"gemini|google ai|google model"),
            local_model: ci(r"ollama|llama\.cpp|gguf|vllm|local model|open[- ]weight|open weights"),
            toolset: ci(r"toolset|enabled_toolsets|browser tool|terminal tool|file tool|web tool"),
            // upstream pattern + the config files an ark project actually edits (`config.toml`,
            // `Cargo.toml`); plain prose like "not configured" still does not match.
            config: ci(
                r"config\.ya?ml|\b[a-z0-9_-]+config\.(?:js|ts|json|ya?ml)|\.env(?:\b|\.)|manifest\.json|settings\.json|pyproject\.toml|package\.json|Cargo\.toml|config\.toml",
            ),
            git_history: ci(
                r"\bgit\s+(rebase|merge|fetch|pull|push|tag|checkout)|merge conflict|conflict\s*\(|rebase --continue",
            ),
            test: ci(
                r"pytest|unittest|vitest|playwright|npm test|pnpm test|node --check|py_compile|tests? passed|\bOK\b|cargo test",
            ),
            screenshot: ci(r"screenshot|playwright|vision_analyze|browser_vision|\.png|image data"),
            release: ci(r"\bgit\s+tag|release|version bump|changelog|publish|pushed? tag"),
            cache: ci(r"cache hit|prompt caching|cache_read"),
        }
    }
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(Patterns::new)
}

/// `hits(pattern)`: `len(re.findall(pattern, full_text, re.IGNORECASE))`.
fn hits(re: &Regex, text: &str) -> u64 {
    re.find_iter(text).filter_map(|m| m.ok()).count() as u64
}

fn matches(re: &Regex, text: &str) -> bool {
    re.is_match(text).unwrap_or(false)
}

// ───────────────────────── catalog ─────────────────────────

/// One catalog entry (`_ach(...)` upstream). `kind` is derived, exactly as upstream:
/// `requires` non-empty → `multi_condition`; a `max_*` metric is a per-session best
/// (`best_session`); anything else accumulates over the whole history (`lifetime`).
#[derive(Debug, Clone, Copy)]
pub struct Achievement {
    /// Stable unlock-state key. Never rename casually (upstream README).
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub category: &'static str,
    pub icon: &'static str,
    /// `true` → hidden ("???") until the first progress signal.
    pub secret: bool,
    /// `threshold_metric` (empty for multi-condition entries).
    pub metric: &'static str,
    /// Tier thresholds, ascending, one per [`TIER_NAMES`] slot.
    pub tiers: &'static [u64],
    /// `(metric, gte)` pairs.
    pub requires: &'static [(&'static str, u64)],
}

impl Achievement {
    fn kind(&self) -> &'static str {
        if !self.requires.is_empty() {
            "multi_condition"
        } else if self.metric.starts_with("max_") {
            "best_session"
        } else {
            "lifetime"
        }
    }
    fn is_tiered(&self) -> bool {
        !self.metric.is_empty()
    }
}

/// `ACHIEVEMENTS` — the whole catalog, in upstream order (60 entries). Ids are upstream ids.
pub const ACHIEVEMENTS: &[Achievement] = &[
    // ── Agent Autonomy — mostly best-session feats
    ach("let_him_cook", "Let Him Cook", "Let ark run a serious autonomous tool chain in one session.", "Agent Autonomy", "flame", "max_tool_calls_in_session", &[200, 500, 1200, 3000, 8000]),
    ach("autonomous_avalanche", "Autonomous Avalanche", "Accumulate a lifetime avalanche of ark tool calls across sessions.", "Agent Autonomy", "avalanche", "total_tool_calls", &[1000, 3000, 8000, 20000, 50000]),
    ach("toolchain_maxxer", "Toolchain Maxxer", "Use a wide spread of distinct ark tools in one session.", "Agent Autonomy", "nodes", "max_distinct_tools_in_session", &[18, 28, 45, 70, 100]),
    req("full_send", "Full Send", "Terminal, files, and web/browser all get involved in one real run.", "Agent Autonomy", "rocket", &[("max_terminal_calls_in_session", 180), ("max_file_tool_calls_in_session", 120), ("max_web_browser_calls_in_session", 60)]),
    ach("subagent_commander", "Subagent Commander", "Coordinate delegated agent work.", "Agent Autonomy", "branch", "total_delegate_calls", &[5, 40, 100, 1000, 5000]),
    ach("background_process_enjoyer", "Background Process Enjoyer", "Start or control enough long-running processes to deserve the title.", "Agent Autonomy", "daemon", "total_process_calls", &[300, 800, 2000, 6000, 15000]),
    ach("cron_necromancer", "Cron Necromancer", "Raise scheduled autonomous jobs from the dead.", "Agent Autonomy", "clock", "total_cron_calls", &[1000, 3000, 8000, 20000, 50000]),
    // ── Debugging Chaos — higher thresholds + multi-condition events
    ach("red_text_connoisseur", "Red Text Connoisseur", "Encounter enough errors to develop a palate for red text.", "Debugging Chaos", "warning", "total_errors", &[1500, 4000, 10000, 25000, 75000]),
    ach("stack_trace_sommelier", "Stack Trace Sommelier", "Taste tracebacks by the flight, not by the sip.", "Debugging Chaos", "wine", "traceback_events", &[300, 1000, 3000, 8000, 20000]),
    ach("actually_read_the_logs", "Actually Read The Logs", "Inspect logs repeatedly instead of guessing.", "Debugging Chaos", "scroll", "log_read_events", &[1000, 3000, 8000, 20000, 50000]),
    secret(ach("port_3000_taken", "Port 3000 Is Taken", "Discover dev-server port conflict patterns enough times to become numb.", "Debugging Chaos", "plug", "port_conflict_events", &[15, 40, 100, 300, 1000])),
    secret(ach("permission_denied_any_percent", "Permission Denied Any%", "Speedrun into permission walls.", "Debugging Chaos", "lock", "permission_denied_events", &[25, 75, 200, 600, 1500])),
    req("dependency_hell_tourist", "Dependency Hell Tourist", "Package installs fail, then somehow life continues.", "Debugging Chaos", "package_skull", &[("install_error_events", 25), ("install_success_events", 10)]),
    req("the_fix_was_restarting", "The Fix Was Restarting It", "Restart after enough error clusters to call it a technique.", "Debugging Chaos", "restart", &[("restart_after_error_events", 50), ("total_errors", 4000)]),
    secret(ach("forgot_the_env_var", "Forgot The Env Var", "Auth or configuration failed because an environment variable was missing.", "Debugging Chaos", "key", "env_var_error_events", &[5000, 15000, 40000, 100000, 250000])),
    secret(ach("yaml_colon_incident", "YAML Colon Incident", "Configuration syntax bites back.", "Debugging Chaos", "colon", "yaml_error_events", &[1000, 3000, 8000, 20000, 50000])),
    secret(ach("docker_name_collision", "Docker Name Collision", "A container name already exists. Of course it does.", "Debugging Chaos", "container", "docker_conflict_events", &[75, 200, 600, 1500, 4000])),
    // ── Vibe Coding
    ach("supposed_to_be_quick", "This Was Supposed To Be Quick", "A tiny ask becomes an entire expedition.", "Vibe Coding", "melting_clock", "max_messages_in_session", &[300, 600, 1200, 2500, 6000]),
    ach("one_more_small_change", "One More Small Change", "Make enough file edits in one session to invalidate the phrase small change.", "Vibe Coding", "pencil", "max_file_tool_calls_in_session", &[150, 400, 1000, 3000, 8000]),
    ach("vibe_architect", "Vibe Architect", "Touch a broad surface area in one project session.", "Vibe Coding", "blueprint", "max_files_touched_in_session", &[300, 700, 1500, 4000, 10000]),
    ach("pixel_goblin", "Pixel Goblin", "Do sustained frontend, CSS, SVG, or visual tuning.", "Vibe Coding", "pixel", "frontend_activity_events", &[20000, 50000, 120000, 300000, 800000]),
    req("ship_first_ask_later", "Ship First, Ask Later", "Git activity after a serious tool chain.", "Vibe Coding", "ship", &[("git_events", 50), ("max_tool_calls_in_session", 500)]),
    ach("css_exorcist", "CSS Exorcist", "Cast repeated styling demons out of the interface.", "Vibe Coding", "spark_cursor", "css_activity_events", &[10000, 30000, 80000, 200000, 500000]),
    secret(req("one_character_fix", "One Character Fix", "A tiny edit after a pile of errors. Painful. Beautiful.", "Vibe Coding", "needle", &[("tiny_patch_after_errors_events", 5), ("total_errors", 4000)])),
    // ── Hermes Native
    ach("skillsmith", "Skillsmith", "Work with ark skills enough to leave fingerprints.", "ark Native", "hammer_scroll", "skill_events", &[5000, 15000, 40000, 100000, 250000]),
    ach("skill_issue_skill_created", "Skill Issue? Skill Created.", "Create or patch durable procedures instead of repeating yourself.", "ark Native", "anvil", "skill_manage_events", &[25, 75, 200, 600, 1500]),
    ach("memory_keeper", "Memory Keeper", "Persist durable knowledge with memory or Mnemosyne.", "ark Native", "crystal", "memory_events", &[100, 300, 1000, 3000, 8000]),
    ach("memory_palace", "Memory Palace", "Build a serious durable-memory trail.", "ark Native", "palace", "memory_write_events", &[100, 300, 1000, 3000, 8000]),
    ach("context_dragon", "Context Dragon", "Brush against compression, huge context, or token pressure repeatedly.", "ark Native", "dragon", "context_events", &[5000, 15000, 40000, 100000, 250000]),
    ach("gateway_dweller", "Gateway Dweller", "Live through gateway-connected ark workflows.", "ark Native", "antenna", "gateway_events", &[5000, 15000, 40000, 100000, 250000]),
    ach("plugin_goblin", "Plugin Goblin", "Use or develop plugins enough that the dashboard notices.", "ark Native", "puzzle", "plugin_events", &[1000, 3000, 8000, 20000, 50000]),
    secret(ach("rollback_wizard", "Rollback Wizard", "Invoke rollback/checkpoint recovery magic.", "ark Native", "rewind", "rollback_events", &[500, 1500, 4000, 10000, 25000])),
    // ── Research/Web
    ach("rabbit_hole_certified", "Rabbit Hole Certified", "Search or extract enough web content to qualify as a research spiral.", "Research/Web", "spiral", "total_web_calls", &[400, 1200, 3000, 8000, 20000]),
    ach("citation_goblin", "Citation Goblin", "Extract enough web pages to become a tiny librarian.", "Research/Web", "quote", "total_web_extract_calls", &[100, 300, 1000, 3000, 8000]),
    ach("docs_archaeologist", "Docs Archaeologist", "Dig through documentation sources over and over.", "Research/Web", "compass", "docs_activity_events", &[5000, 15000, 40000, 100000, 250000]),
    ach("browser_possession", "Browser Possession", "Possess a browser through automation repeatedly.", "Research/Web", "browser", "browser_calls", &[75, 200, 600, 1500, 4000]),
    // ── Tool Mastery
    ach("terminal_goblin", "Terminal Goblin", "Spend serious time in shell-land.", "Tool Mastery", "terminal", "total_terminal_calls", &[750, 2000, 6000, 15000, 50000]),
    ach("patch_wizard", "Patch Wizard", "Bend files to your will with targeted patches.", "Tool Mastery", "wand", "total_patch_calls", &[250, 750, 2000, 6000, 15000]),
    ach("file_archaeologist", "File Archaeologist", "Dig through the filesystem with reads and searches.", "Tool Mastery", "folder", "total_file_reads_searches", &[750, 2000, 6000, 15000, 50000]),
    ach("image_whisperer", "Image Whisperer", "Use image generation or vision tools enough for visual work.", "Tool Mastery", "eye", "image_vision_calls", &[100, 300, 1000, 3000, 8000]),
    ach("voice_of_the_machine", "Voice Of The Machine", "Use text-to-speech or voice tooling repeatedly.", "Tool Mastery", "wave", "tts_calls", &[10, 30, 100, 300, 800]),
    // ── Model Lore
    ach("model_hopper", "Model Hopper", "Switch or inspect providers/models enough to count as a habit.", "Model Lore", "swap", "model_events", &[10000, 30000, 80000, 200000, 500000]),
    ach("openrouter_enjoyer", "OpenRouter Enjoyer", "Route model work through OpenRouter repeatedly.", "Model Lore", "router", "openrouter_events", &[250, 750, 2000, 6000, 15000]),
    ach("codex_conjurer", "Codex Conjurer", "Summon Codex-flavored assistance often enough for a ritual.", "Model Lore", "codex", "codex_events", &[500, 1500, 4000, 10000, 25000]),
    ach("multi_model_mage", "Multi-Model Mage", "Use a real spread of distinct model names across ark history.", "Model Lore", "prism", "distinct_model_count", &[10, 20, 40, 80, 160]),
    ach("five_model_flight", "Five-Model Flight", "Try at least five distinct LLMs instead of marrying the first model that answers.", "Model Lore", "prism", "distinct_model_count", &[5, 10, 20, 40, 80]),
    ach("provider_polyglot", "Provider Polyglot", "Use models from multiple providers across ark history.", "Model Lore", "swap", "distinct_provider_count", &[2, 3, 5, 8, 12]),
    ach("model_sommelier", "Model Sommelier", "Taste enough model/provider conversations to develop preferences.", "Model Lore", "wine", "model_events", &[250, 750, 2000, 6000, 15000]),
    ach("claude_confidant", "Claude Confidant", "Bring Claude-flavored reasoning into the workflow repeatedly.", "Model Lore", "quote", "claude_events", &[50, 150, 500, 1500, 4000]),
    ach("gemini_cartographer", "Gemini Cartographer", "Map enough Gemini-related workflows to know the terrain.", "Model Lore", "compass", "gemini_events", &[50, 150, 500, 1500, 4000]),
    ach("open_weights_pilgrim", "Open Weights Pilgrim", "Actually chat with local/open-weight models through ark session metadata.", "Model Lore", "terminal", "local_model_chat_sessions", &[1, 3, 10, 30, 100]),
    // ── Workflow Intelligence
    ach("toolset_cartographer", "Toolset Cartographer", "Navigate ark toolsets deliberately instead of treating tools as a blur.", "ark Native", "compass", "toolset_events", &[20, 60, 200, 600, 1500]),
    ach("config_surgeon", "Config Surgeon", "Operate on real config files, manifests, env files, and dashboard settings without flinching.", "ark Native", "key", "config_events", &[100, 300, 1000, 3000, 10000]),
    ach("rebase_acrobat", "Rebase Acrobat", "Handle real git history surgery: rebase, conflict, merge, fetch, push.", "Vibe Coding", "branch", "git_history_events", &[10, 30, 100, 300, 800]),
    ach("test_suite_tamer", "Test Suite Tamer", "Run enough verification commands that green text becomes part of the ritual.", "Tool Mastery", "daemon", "test_events", &[100, 300, 800, 2400, 6000]),
    ach("screenshot_hunter", "Screenshot Hunter", "Capture, inspect, and polish visual proof instead of just claiming it works.", "Tool Mastery", "eye", "screenshot_events", &[50, 150, 500, 1500, 5000]),
    // ── Lifestyle
    ach("marathon_operator", "Marathon Operator", "Accumulate a serious number of ark sessions.", "Lifestyle", "marathon", "session_count", &[75, 200, 500, 1500, 5000]),
    ach("weekend_warrior", "Weekend Warrior", "Run ark on weekends enough times to make it a lifestyle.", "Lifestyle", "calendar", "weekend_sessions", &[25, 75, 200, 600, 1500]),
    ach("night_shift_operator", "Night Shift Operator", "Run sessions during gremlin hours repeatedly.", "Lifestyle", "moon", "night_sessions", &[25, 75, 200, 600, 1500]),
    secret(ach("cache_hit_appreciator", "Cache Hit Appreciator", "Notice or benefit from prompt/cache behavior.", "Lifestyle", "cache", "cache_events", &[100, 300, 1000, 3000, 8000])),
];

/// `_ach(...)` with a tier ladder.
const fn ach(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    category: &'static str,
    icon: &'static str,
    metric: &'static str,
    tiers: &'static [u64],
) -> Achievement {
    Achievement {
        id,
        name,
        description,
        category,
        icon,
        secret: false,
        metric,
        tiers,
        requires: &[],
    }
}

/// `_ach(..., requires=[...])` — a multi-condition badge (no tier ladder, no threshold metric).
const fn req(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    category: &'static str,
    icon: &'static str,
    requires: &'static [(&'static str, u64)],
) -> Achievement {
    Achievement {
        id,
        name,
        description,
        category,
        icon,
        secret: false,
        metric: "",
        tiers: &[],
        requires,
    }
}

/// `_ach(..., secret=True)`.
const fn secret(mut a: Achievement) -> Achievement {
    a.secret = true;
    a
}

pub fn catalog() -> &'static [Achievement] {
    ACHIEVEMENTS
}

pub fn definition(id: &str) -> Option<&'static Achievement> {
    ACHIEVEMENTS.iter().find(|a| a.id == id)
}

// ───────────────────────── session analysis ─────────────────────────

/// Per-session stats — upstream `analyze_messages`' return dict (metric names are the contract),
/// plus the session metadata `scan_sessions` adds to each row.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionStats {
    pub session_id: String,
    pub title: String,
    pub message_count: u64,
    pub tool_call_count: u64,
    pub tool_names: Vec<String>,
    pub distinct_tool_count: u64,
    pub error_count: u64,
    pub terminal_calls: u64,
    pub web_calls: u64,
    pub web_extract_calls: u64,
    pub browser_calls: u64,
    pub web_browser_calls: u64,
    pub patch_calls: u64,
    pub file_reads_searches: u64,
    pub file_tool_calls: u64,
    pub files_touched_count: u64,
    pub delegate_calls: u64,
    pub process_calls: u64,
    pub cron_calls: u64,
    pub image_vision_calls: u64,
    pub tts_calls: u64,
    pub skill_events: u64,
    pub skill_manage_events: u64,
    pub memory_events: u64,
    pub memory_write_events: u64,
    pub port_conflict: bool,
    pub port_conflict_events: u64,
    pub traceback_events: u64,
    pub log_read_events: u64,
    pub permission_denied_events: u64,
    pub install_error_events: u64,
    pub install_success_events: u64,
    pub restart_after_error_events: u64,
    pub env_var_error_events: u64,
    pub yaml_error_events: u64,
    pub docker_conflict_events: u64,
    pub frontend_activity_events: u64,
    pub css_activity_events: u64,
    pub git_events: u64,
    pub tiny_patch_after_errors_events: u64,
    pub context_events: u64,
    pub gateway_events: u64,
    pub plugin_events: u64,
    pub rollback_events: u64,
    pub docs_activity_events: u64,
    pub model_events: u64,
    pub openrouter_events: u64,
    pub codex_events: u64,
    pub claude_events: u64,
    pub gemini_events: u64,
    pub local_model_events: u64,
    pub toolset_events: u64,
    pub config_events: u64,
    pub git_history_events: u64,
    pub test_events: u64,
    pub screenshot_events: u64,
    pub release_events: u64,
    pub cache_events: u64,
    pub model_names: Vec<String>,
    /// `started_at` / `last_active`, unix **seconds** (upstream's SQLite columns).
    pub started_at: u64,
    pub last_active: u64,
}

impl SessionStats {
    fn new(session_id: &str, title: &str) -> SessionStats {
        SessionStats {
            session_id: session_id.to_string(),
            title: title.to_string(),
            ..SessionStats::default()
        }
    }

    /// `stats.update(session_id=…, title=…, started_at=…, last_active=…, source=…)`.
    fn set_meta(&mut self, meta: &SessionInfo) {
        self.session_id = meta.id.clone();
        let title = meta
            .title
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty());
        self.title = title.map(str::to_string).unwrap_or_else(|| {
            if self.title.trim().is_empty() {
                "Untitled session".to_string()
            } else {
                self.title.clone()
            }
        });
        self.started_at = meta.created_ms / 1000;
        self.last_active = meta.updated_ms / 1000;
    }

    /// Add a model name (checkpoint round-trips hand back a list, never a set).
    fn add_model(&mut self, model: &str) {
        let model = model.trim();
        if model.is_empty() || model == "None" {
            return;
        }
        if !self.model_names.iter().any(|m| m == model) {
            self.model_names.push(model.to_string());
            self.model_names.sort();
        }
    }
}

/// Map an ark tool name onto the Hermes name upstream's metrics count (`_count_tool` needles).
///
/// Only names that differ are listed; everything else (`browser_*`, `image_generate`,
/// `vision_analyze`, `text_to_speech`, `memory_*`, `web_search`, `web_extract`, `skill`, …) already
/// contains the needle upstream greps for. `edit`/`apply_patch` fold into `patch` because both are
/// targeted edits; `web_fetch` folds into `web_extract` because fetching a page is extraction.
fn canonical_tool(name: &str) -> &str {
    match name {
        "shell" | "terminal" => "terminal",
        "job" => "process",
        "read" => "read_file",
        "write" => "write_file",
        "edit" | "apply_patch" => "patch",
        "glob" | "grep" => "search_files",
        "spawn" | "acp_delegate" => "delegate_task",
        "cronjob_manage" => "cronjob",
        "web_fetch" => "web_extract",
        other => other,
    }
}

/// Names whose `action` argument makes an ark `skill` call a *manage* operation upstream would
/// have seen as the `skill_manage` tool.
const SKILL_MANAGE_ACTIONS: &[&str] = &[
    "create", "update", "archive", "patch", "delete", "edit", "write", "add", "new",
];

fn collect_files(text: &str, out: &mut BTreeSet<String>) {
    for m in patterns().file.find_iter(text).filter_map(|m| m.ok()) {
        out.insert(m.as_str().to_string());
    }
}

/// Upstream `analyze_messages(session_id, title, messages)` over ark events.
pub fn analyze_events(session_id: &str, title: &str, events: &[Event]) -> SessionStats {
    let mut tool_names: BTreeSet<String> = BTreeSet::new();
    let mut tool_sequence: Vec<String> = Vec::new();
    let mut files_touched: BTreeSet<String> = BTreeSet::new();
    let mut text_parts: Vec<String> = Vec::new();
    let mut error_count: u64 = 0;
    let mut message_count: u64 = 0;
    let mut model_names: BTreeSet<String> = BTreeSet::new();
    let mut skill_manage: u64 = 0;

    for ev in events {
        match &ev.kind {
            EventKind::Message { message, model, .. } => {
                message_count += 1;
                let text = message.text();
                if matches(&patterns().error, &text) {
                    error_count += 1;
                }
                collect_files(&text, &mut files_touched);
                text_parts.push(text);
                if let Some(m) = model.as_deref().filter(|m| !m.trim().is_empty()) {
                    model_names.insert(m.to_string());
                }
            }
            EventKind::ToolCalled { name, input, .. } => {
                tool_names.insert(name.clone());
                tool_sequence.push(name.clone());
                // upstream appends json.dumps(tool_calls) to the blob FILE_RE runs over
                collect_files(&input.to_string(), &mut files_touched);
                if name == "skill" {
                    let action = input
                        .get("action")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase();
                    if SKILL_MANAGE_ACTIONS.contains(&action.as_str()) {
                        skill_manage += 1;
                    }
                }
            }
            // the tool result *text* is not in ark's event log; `is_error` is the error signal
            EventKind::ToolSettled { is_error: true, .. } => error_count += 1,
            EventKind::Error { message } => {
                error_count += 1;
                collect_files(message, &mut files_touched);
                text_parts.push(message.clone());
            }
            EventKind::Model { model } if !model.trim().is_empty() => {
                model_names.insert(model.clone());
            }
            _ => {}
        }
    }

    let full_text = text_parts.join("\n");
    let lower = full_text.to_lowercase();
    let canonical: Vec<&str> = tool_sequence.iter().map(|n| canonical_tool(n)).collect();
    let count = |needles: &[&str]| {
        canonical
            .iter()
            .filter(|n| needles.iter().any(|x| n.contains(x)))
            .count() as u64
    };

    let web_calls = count(&["web_search", "web_extract"]);
    let browser_calls = count(&["browser"]);
    let skill_events = count(&["skill"]) + hits(&patterns().skill_word, &lower);
    let port_conflict = matches(&patterns().port, &full_text);
    let install = matches(&patterns().install, &full_text);
    let p = patterns();

    SessionStats {
        session_id: session_id.to_string(),
        title: title.to_string(),
        message_count,
        tool_call_count: tool_sequence.len() as u64,
        distinct_tool_count: tool_names.len() as u64,
        tool_names: tool_names.into_iter().collect(),
        error_count,
        terminal_calls: count(&["terminal"]),
        web_calls,
        web_extract_calls: count(&["web_extract"]),
        browser_calls,
        web_browser_calls: web_calls + browser_calls,
        patch_calls: count(&["patch"]),
        file_reads_searches: count(&["read_file", "search_files"]),
        file_tool_calls: count(&["read_file", "write_file", "patch", "search_files"]),
        files_touched_count: files_touched.len() as u64,
        delegate_calls: count(&["delegate_task"]),
        process_calls: count(&["process"]) + hits(&p.bg_true, &full_text),
        cron_calls: count(&["cronjob"]),
        image_vision_calls: count(&["image", "vision"]),
        tts_calls: count(&["tts", "text_to_speech"]),
        skill_events,
        skill_manage_events: count(&["skill_manage"]) + skill_manage,
        memory_events: count(&["memory", "mnemosyne"]),
        memory_write_events: count(&["mnemosyne_remember", "memory"]),
        port_conflict,
        port_conflict_events: u64::from(port_conflict),
        traceback_events: hits(&p.traceback, &full_text),
        log_read_events: hits(&p.log_read, &full_text),
        permission_denied_events: hits(&p.permission, &full_text),
        install_error_events: u64::from(install && matches(&p.error, &full_text)),
        install_success_events: u64::from(install && matches(&p.success, &full_text)),
        restart_after_error_events: u64::from(error_count > 0 && matches(&p.restart, &full_text)),
        env_var_error_events: hits(&p.env_var, &full_text),
        yaml_error_events: if matches(&p.error, &full_text) {
            hits(&p.yaml, &full_text)
        } else {
            0
        },
        docker_conflict_events: hits(&p.docker, &full_text),
        frontend_activity_events: hits(&p.frontend, &full_text),
        css_activity_events: hits(&p.css, &full_text),
        git_events: hits(&p.git, &full_text),
        tiny_patch_after_errors_events: u64::from(
            error_count >= 5 && matches(&p.tiny_patch, &full_text),
        ),
        context_events: hits(&p.context, &full_text),
        gateway_events: hits(&p.gateway, &full_text),
        plugin_events: hits(&p.plugin, &full_text),
        rollback_events: hits(&p.rollback, &full_text),
        docs_activity_events: hits(&p.docs, &full_text),
        model_events: hits(&p.model, &full_text),
        openrouter_events: hits(&p.openrouter, &full_text),
        codex_events: hits(&p.codex, &full_text),
        claude_events: hits(&p.claude, &full_text),
        gemini_events: hits(&p.gemini, &full_text),
        local_model_events: hits(&p.local_model, &full_text),
        toolset_events: hits(&p.toolset, &full_text),
        config_events: hits(&p.config, &full_text),
        git_history_events: hits(&p.git_history, &full_text),
        test_events: hits(&p.test, &full_text),
        screenshot_events: hits(&p.screenshot, &full_text),
        release_events: hits(&p.release, &full_text),
        cache_events: hits(&p.cache, &full_text),
        model_names: model_names.into_iter().collect(),
        started_at: 0,
        last_active: 0,
    }
}

// ───────────────────────── aggregation ─────────────────────────

/// `aggregate_stats`'s result: metric name → value.
pub type Aggregate = BTreeMap<String, u64>;

/// Per-session bests: aggregate metric → session stat key (`_SESSION_MAX_METRICS`).
const SESSION_MAX_METRICS: &[(&str, &str)] = &[
    ("max_tool_calls_in_session", "tool_call_count"),
    ("max_distinct_tools_in_session", "distinct_tool_count"),
    ("max_messages_in_session", "message_count"),
    ("max_terminal_calls_in_session", "terminal_calls"),
    ("max_file_tool_calls_in_session", "file_tool_calls"),
    ("max_web_calls_in_session", "web_calls"),
    ("max_web_browser_calls_in_session", "web_browser_calls"),
    ("max_files_touched_in_session", "files_touched_count"),
];

/// Lifetime sums (`_SESSION_SUM_METRICS`).
const SESSION_SUM_METRICS: &[(&str, &str)] = &[
    ("total_errors", "error_count"),
    ("total_tool_calls", "tool_call_count"),
    ("total_terminal_calls", "terminal_calls"),
    ("total_web_calls", "web_calls"),
    ("total_web_extract_calls", "web_extract_calls"),
    ("total_patch_calls", "patch_calls"),
    ("total_file_reads_searches", "file_reads_searches"),
    ("total_delegate_calls", "delegate_calls"),
    ("total_process_calls", "process_calls"),
    ("total_cron_calls", "cron_calls"),
    ("browser_calls", "browser_calls"),
    ("image_vision_calls", "image_vision_calls"),
    ("tts_calls", "tts_calls"),
];

/// `*_events` counters summed under their own name (`_SESSION_EVENT_KEYS`).
const SESSION_EVENT_KEYS: &[&str] = &[
    "traceback_events",
    "log_read_events",
    "port_conflict_events",
    "permission_denied_events",
    "install_error_events",
    "install_success_events",
    "restart_after_error_events",
    "env_var_error_events",
    "yaml_error_events",
    "docker_conflict_events",
    "frontend_activity_events",
    "css_activity_events",
    "git_events",
    "tiny_patch_after_errors_events",
    "skill_events",
    "skill_manage_events",
    "memory_events",
    "memory_write_events",
    "context_events",
    "gateway_events",
    "plugin_events",
    "rollback_events",
    "docs_activity_events",
    "model_events",
    "openrouter_events",
    "codex_events",
    "claude_events",
    "gemini_events",
    "local_model_events",
    "toolset_events",
    "config_events",
    "git_history_events",
    "test_events",
    "screenshot_events",
    "release_events",
    "cache_events",
];

const PROVIDER_MARKERS: &[&str] = &[
    "openai",
    "anthropic",
    "google",
    "gemini",
    "mistral",
    "meta",
    "qwen",
    "deepseek",
    "xai",
    "nous",
    "ollama",
    "groq",
    "openrouter",
    "codex",
];
const LOCAL_MARKERS: &[&str] = &[
    "ollama",
    "llama.cpp",
    "localhost",
    "127.0.0.1",
    "local/",
    "local:",
    "gguf",
    "vllm-local",
];

/// `model_provider(model_name)`.
pub fn model_provider(model_name: &str) -> Option<String> {
    let name = model_name.trim().to_lowercase();
    if name.is_empty() || name == "none" {
        return None;
    }
    if let Some((prefix, _)) = name.split_once('/') {
        return Some(prefix.to_string());
    }
    for provider in PROVIDER_MARKERS {
        if name.contains(provider) {
            return Some(if *provider == "gemini" {
                "google".to_string()
            } else {
                (*provider).to_string()
            });
        }
    }
    let head = name.split(':').next().unwrap_or(&name);
    Some(head.split('-').next().unwrap_or(head).to_string())
}

/// `is_local_model_name(model_name)`.
pub fn is_local_model_name(model_name: &str) -> bool {
    let name = model_name.trim().to_lowercase();
    !name.is_empty() && name != "none" && LOCAL_MARKERS.iter().any(|m| name.contains(m))
}

fn stat_of(stats: &Value, key: &str) -> u64 {
    stats.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// `aggregate_stats(sessions)`: per-session bests, lifetime sums, event counters, model/provider
/// spread and the weekend/night lifestyle counters.
pub fn aggregate_stats(sessions: &[SessionStats]) -> Aggregate {
    let mut agg: Aggregate = BTreeMap::new();
    agg.insert("session_count".to_string(), sessions.len() as u64);
    for (key, _) in SESSION_MAX_METRICS.iter().chain(SESSION_SUM_METRICS.iter()) {
        agg.insert((*key).to_string(), 0);
    }
    for key in [
        "distinct_model_count",
        "distinct_provider_count",
        "local_model_chat_sessions",
        "weekend_sessions",
        "night_sessions",
    ] {
        agg.insert(key.to_string(), 0);
    }
    for key in SESSION_EVENT_KEYS {
        agg.insert((*key).to_string(), 0);
    }

    let mut model_names: BTreeSet<String> = BTreeSet::new();
    let mut providers: BTreeSet<String> = BTreeSet::new();
    for s in sessions {
        let row = serde_json::to_value(s).unwrap_or(Value::Null);
        for (key, stat) in SESSION_MAX_METRICS {
            let slot = agg.entry((*key).to_string()).or_insert(0);
            *slot = (*slot).max(stat_of(&row, stat));
        }
        for (key, stat) in SESSION_SUM_METRICS {
            *agg.entry((*key).to_string()).or_insert(0) += stat_of(&row, stat);
        }
        for key in SESSION_EVENT_KEYS {
            *agg.entry((*key).to_string()).or_insert(0) += stat_of(&row, key);
        }
        for m in &s.model_names {
            if !m.is_empty() && m != "None" {
                model_names.insert(m.clone());
            }
            if let Some(p) = model_provider(m) {
                providers.insert(p);
            }
        }
        if s.model_names.iter().any(|m| is_local_model_name(m)) {
            *agg.entry("local_model_chat_sessions".to_string())
                .or_insert(0) += 1;
        }
        if s.started_at > 0 {
            // time.localtime(...).tm_wday / tm_hour
            if let Some((wday, hour)) = local_clock(s.started_at as i64) {
                if wday >= 5 {
                    *agg.entry("weekend_sessions".to_string()).or_insert(0) += 1;
                }
                if !(6..23).contains(&hour) {
                    *agg.entry("night_sessions".to_string()).or_insert(0) += 1;
                }
            }
        }
    }
    agg.insert("distinct_model_count".to_string(), model_names.len() as u64);
    agg.insert(
        "distinct_provider_count".to_string(),
        providers.len() as u64,
    );
    agg
}

/// `(tm_wday, tm_hour)` with Python's `tm_wday` (Monday=0 … Sunday=6) in the machine's local zone.
fn local_clock(unix_secs: i64) -> Option<(i32, i32)> {
    // SAFETY: `localtime_r` writes into the caller-owned `tm` and takes its own lock internally.
    unsafe {
        let t = unix_secs as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return None;
        }
        // C: Sunday=0 … Saturday=6 → Python: Monday=0 … Sunday=6
        let py_wday = (tm.tm_wday + 6) % 7;
        Some((py_wday, tm.tm_hour))
    }
}

/// `evidence_for(definition, sessions)`: the best session for a `max_*` metric.
pub fn evidence_for(def: &Achievement, sessions: &[SessionStats]) -> Option<Value> {
    let stat = SESSION_MAX_METRICS
        .iter()
        .find(|(k, _)| *k == def.metric)
        .map(|(_, s)| *s)?;
    let best = sessions.iter().max_by_key(|s| {
        let row = serde_json::to_value(s).unwrap_or(Value::Null);
        stat_of(&row, stat)
    })?;
    let row = serde_json::to_value(best).ok()?;
    Some(json!({"session_id": best.session_id, "title": best.title, "value": stat_of(&row, stat)}))
}

// ───────────────────────── evaluation ─────────────────────────

/// `_result(...)`: the uniform evaluation result (same keys, same meanings).
#[derive(Debug, Clone, PartialEq)]
pub struct Eval {
    pub unlocked: bool,
    pub discovered: bool,
    /// `"unlocked" | "discovered" | "secret"`.
    pub state: &'static str,
    pub tier: Option<String>,
    pub progress: u64,
    pub next_tier: Option<String>,
    pub next_threshold: u64,
    pub progress_pct: u64,
}

fn sorted_tiers(def: &Achievement) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = def
        .tiers
        .iter()
        .enumerate()
        .take(TIER_NAMES.len())
        .map(|(i, t)| (TIER_NAMES[i].to_string(), *t))
        .collect();
    v.sort_by_key(|(_, t)| *t);
    v
}

/// `_state(definition, unlocked, any_progress)`: secret badges stay hidden until the first signal.
fn state_of(def: &Achievement, unlocked: bool, any_progress: bool) -> (&'static str, bool) {
    let state = if unlocked {
        "unlocked"
    } else if def.secret && !any_progress {
        "secret"
    } else {
        "discovered"
    };
    (state, any_progress || !def.secret)
}

/// `evaluate_tiered(definition, aggregate)`.
pub fn evaluate_tiered(def: &Achievement, aggregate: &Aggregate) -> Eval {
    let progress = aggregate.get(def.metric).copied().unwrap_or(0);
    let tiers = sorted_tiers(def);
    let achieved = tiers.iter().rfind(|(_, t)| progress >= *t).cloned();
    let next = tiers.iter().find(|(_, t)| progress < *t).cloned();
    let next_threshold = next
        .as_ref()
        .map(|(_, t)| *t)
        .or_else(|| tiers.last().map(|(_, t)| *t))
        .unwrap_or(1);
    let current_threshold = achieved.as_ref().map(|(_, t)| *t).unwrap_or(0);
    let denom = next_threshold.saturating_sub(current_threshold).max(1);
    let pct = if next.is_none() && achieved.is_some() {
        100
    } else {
        let raw = (progress.saturating_sub(current_threshold)) as f64 / denom as f64 * 100.0;
        (raw.floor().max(0.0) as u64).min(99)
    };
    let (state, discovered) = state_of(def, achieved.is_some(), progress > 0);
    Eval {
        unlocked: achieved.is_some(),
        discovered,
        state,
        tier: achieved.map(|(name, _)| name),
        progress,
        next_tier: next.map(|(name, _)| name),
        next_threshold,
        progress_pct: pct,
    }
}

/// `evaluate_requirements(definition, aggregate)`: `progress` is the mean of
/// `min(1, value / threshold)` over all requirements, floored to a percentage.
pub fn evaluate_requirements(def: &Achievement, aggregate: &Aggregate) -> Eval {
    if def.requires.is_empty() {
        let (state, discovered) = state_of(def, false, false);
        return Eval {
            unlocked: false,
            discovered,
            state,
            tier: None,
            progress: 0,
            next_tier: None,
            next_threshold: 1,
            progress_pct: 0,
        };
    }
    let mut parts: Vec<f64> = Vec::with_capacity(def.requires.len());
    let mut any_progress = false;
    let mut complete = true;
    for (metric, gte) in def.requires {
        let value = aggregate.get(*metric).copied().unwrap_or(0);
        let threshold = (*gte).max(1);
        any_progress |= value > 0;
        complete &= value >= *gte;
        parts.push((value as f64 / threshold as f64).min(1.0));
    }
    let mean = parts.iter().sum::<f64>() / parts.len() as f64;
    let pct = (mean * 100.0).floor() as u64;
    let (state, discovered) = state_of(def, complete, any_progress);
    Eval {
        unlocked: complete,
        discovered,
        state,
        tier: None,
        progress: pct,
        next_tier: None,
        next_threshold: 100,
        progress_pct: if complete { 100 } else { pct.min(99) },
    }
}

/// `evaluate_definition(definition, aggregate)`.
pub fn evaluate_definition(def: &Achievement, aggregate: &Aggregate) -> Eval {
    if def.is_tiered() {
        evaluate_tiered(def, aggregate)
    } else {
        evaluate_requirements(def, aggregate)
    }
}

/// `METRIC_LABELS` (plus the ark-flavoured fallback `metric.replace("_", " ")`).
pub fn metric_label(metric: &str) -> String {
    let label = match metric {
        "max_tool_calls_in_session" => "tool calls in one session",
        "max_distinct_tools_in_session" => "distinct ark tools used in one session",
        "max_terminal_calls_in_session" => "terminal calls in one session",
        "max_file_tool_calls_in_session" => "file/search/patch calls in one session",
        "max_web_browser_calls_in_session" => "web search/extract or browser calls in one session",
        "max_messages_in_session" => "messages in one session",
        "max_files_touched_in_session" => "files touched in one session",
        "total_delegate_calls" => "lifetime delegate_task calls",
        "total_process_calls" => "lifetime background process operations",
        "total_cron_calls" => "lifetime scheduled-job operations",
        "total_errors" => "error/failed/traceback messages observed",
        "traceback_events" => "traceback or exception mentions",
        "log_read_events" => "log inspections",
        "port_conflict_events" => "dev-server port conflict detections",
        "permission_denied_events" => "permission-denied errors",
        "install_error_events" => "package-install failures",
        "install_success_events" => "successful package installs after package work",
        "restart_after_error_events" => "restart/reload actions after error clusters",
        "env_var_error_events" => "missing auth/config/environment-variable events",
        "yaml_error_events" => "YAML/config parse incidents",
        "docker_conflict_events" => "Docker/container-name conflicts",
        "frontend_activity_events" => "frontend/CSS/SVG/React activity mentions",
        "css_activity_events" => "CSS, styling, Tailwind, or className activity",
        "git_events" => "git workflow commands",
        "tiny_patch_after_errors_events" => "tiny typo-style fixes after error clusters",
        "skill_events" => "ark skill mentions or tool use",
        "skill_manage_events" => "skill_manage create/patch/delete operations",
        "memory_events" => "memory or Mnemosyne tool events",
        "memory_write_events" => "durable memory writes",
        "context_events" => "context, compression, token, or cache-pressure mentions",
        "gateway_events" => "gateway/API/chat-platform activity",
        "plugin_events" => "dashboard plugin development or usage signals",
        "rollback_events" => "rollback/checkpoint recovery mentions",
        "docs_activity_events" => "documentation/README/docs activity",
        "model_events" => "model/provider-related activity",
        "openrouter_events" => "OpenRouter mentions",
        "codex_events" => "Codex mentions",
        "cache_events" => "prompt-cache/cache-hit mentions",
        "total_web_calls" => "lifetime web_search/web_extract calls",
        "total_web_extract_calls" => "lifetime web_extract calls",
        "browser_calls" => "lifetime browser automation calls",
        "total_tool_calls" => "lifetime ark tool calls",
        "total_terminal_calls" => "lifetime terminal calls",
        "total_patch_calls" => "lifetime targeted patch edits",
        "total_file_reads_searches" => "lifetime read_file/search_files calls",
        "image_vision_calls" => "image generation or vision tool calls",
        "tts_calls" => "text-to-speech or voice tool calls",
        "distinct_model_count" => "distinct model names seen in session metadata",
        "distinct_provider_count" => "distinct model providers inferred from session metadata",
        "claude_events" => "Claude/Anthropic model mentions",
        "gemini_events" => "Gemini/Google model mentions",
        "local_model_events" => "local/open-weight model mentions",
        "local_model_chat_sessions" => "ark sessions whose model metadata is local/open-weight",
        "toolset_events" => "toolset or tool-family mentions",
        "config_events" => "configuration/environment/manifest activity",
        "git_history_events" => "git history operations such as rebase, merge, fetch, push, or tag",
        "test_events" => "test/check/verification command mentions",
        "screenshot_events" => "screenshot, Playwright, PNG, or vision-inspection activity",
        "release_events" => "release, version, publish, or git tag events",
        "session_count" => "ark sessions",
        "weekend_sessions" => "sessions started on weekends",
        "night_sessions" => "sessions started late night or before dawn",
        _ => return metric.replace('_', " "),
    };
    label.to_string()
}

/// `criteria_for(definition)` — the "What counts" text, hidden for an unrevealed secret.
pub fn criteria_for(def: &Achievement, state: &str) -> String {
    if def.secret && state == "secret" {
        return SECRET_CRITERIA.to_string();
    }
    if def.is_tiered() {
        if def.tiers.is_empty() {
            return "Requirement: use ark in the matching workflow.".to_string();
        }
        let ladder: Vec<String> = sorted_tiers(def)
            .iter()
            .map(|(name, t)| format!("{name} {t}"))
            .collect();
        return format!(
            "Requirement: {}. Tier ladder: {}.",
            metric_label(def.metric),
            ladder.join(", ")
        );
    }
    if !def.requires.is_empty() {
        let parts: Vec<String> = def
            .requires
            .iter()
            .map(|(m, gte)| format!("{} ≥ {}", metric_label(m), gte))
            .collect();
        return format!("Requirement: {}.", parts.join("; "));
    }
    "Requirement: complete the matching ark behavior.".to_string()
}

// ───────────────────────── JSON shapes ─────────────────────────

/// One catalog entry as upstream's `_ach` builds it (`kind` derived, `secret` only when true).
fn definition_json(def: &Achievement) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("id".into(), json!(def.id));
    m.insert("name".into(), json!(def.name));
    m.insert("description".into(), json!(def.description));
    m.insert("category".into(), json!(def.category));
    m.insert("kind".into(), json!(def.kind()));
    m.insert("icon".into(), json!(def.icon));
    if def.secret {
        m.insert("secret".into(), json!(true));
    }
    if !def.requires.is_empty() {
        let reqs: Vec<Value> = def
            .requires
            .iter()
            .map(|(metric, gte)| json!({"metric": metric, "gte": gte}))
            .collect();
        m.insert("requirements".into(), Value::Array(reqs));
    } else {
        m.insert("threshold_metric".into(), json!(def.metric));
        let tiers: Vec<Value> = sorted_tiers(def)
            .iter()
            .map(|(name, t)| json!({"name": name, "threshold": t}))
            .collect();
        m.insert("tiers".into(), Value::Array(tiers));
    }
    m
}

/// `{**definition, **result}` + `unlocked_at`/`evidence` + `display_achievement`.
fn item_json(
    def: &Achievement,
    eval: &Eval,
    unlocked_at: Option<u64>,
    evidence: Option<Value>,
) -> Value {
    let mut m = definition_json(def);
    m.insert("unlocked".into(), json!(eval.unlocked));
    m.insert("discovered".into(), json!(eval.discovered));
    m.insert("state".into(), json!(eval.state));
    m.insert("tier".into(), json!(eval.tier));
    m.insert("progress".into(), json!(eval.progress));
    m.insert("next_tier".into(), json!(eval.next_tier));
    m.insert("next_threshold".into(), json!(eval.next_threshold));
    m.insert("progress_pct".into(), json!(eval.progress_pct));
    if eval.unlocked {
        m.insert("unlocked_at".into(), json!(unlocked_at));
        m.insert("evidence".into(), evidence.unwrap_or(Value::Null));
    }
    // display_achievement: a secret keeps its name/description/icon hidden
    if eval.state == "secret" {
        m.insert("name".into(), json!("???"));
        m.insert("description".into(), json!(SECRET_DESCRIPTION));
        m.insert("icon".into(), json!("secret"));
    }
    m.insert("criteria".into(), json!(criteria_for(def, eval.state)));
    Value::Object(m)
}

fn aggregate_json(agg: &Aggregate) -> Value {
    let mut m = Map::new();
    for (k, v) in agg {
        m.insert(k.clone(), json!(v));
    }
    Value::Object(m)
}

// ───────────────────────── durable files ─────────────────────────

/// `<data>/plugin-data/achievements/` — upstream `plugin_data_dir("hermes-achievements")`.
fn data_dir(paths: &Paths) -> PathBuf {
    paths.data.join("plugin-data").join("achievements")
}

fn data_file(paths: &Paths, name: &str) -> PathBuf {
    data_dir(paths).join(name)
}

fn read_json(path: &Path) -> Option<Value> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()
}

fn write_json(path: &Path, value: &Value) {
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    if let Ok(mut text) = serde_json::to_string_pretty(value) {
        text.push('\n');
        let _ = atomic_write(path, text.as_bytes());
    }
}

/// `load_state()`: `{"unlocks": {…}}` (missing/corrupt → empty).
pub fn load_state(paths: &Paths) -> Value {
    match read_json(&data_file(paths, STATE_FILE)) {
        Some(v) if v.get("unlocks").map(Value::is_object).unwrap_or(false) => v,
        _ => json!({"unlocks": {}}),
    }
}

fn save_state(paths: &Paths, state: &Value) {
    write_json(&data_file(paths, STATE_FILE), state);
}

/// `(checkpoint_is_current, sessions)` from `scan_checkpoint.json`.
fn load_checkpoint(paths: &Paths) -> (bool, Map<String, Value>) {
    let Some(v) = read_json(&data_file(paths, CHECKPOINT_FILE)) else {
        return (false, Map::new());
    };
    let current =
        v.get("schema_version").and_then(Value::as_u64) == Some(CHECKPOINT_SCHEMA_VERSION);
    let sessions = v
        .get("sessions")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    (current, sessions)
}

/// `session_fingerprint(meta)`: everything that changes when a session is appended to or renamed.
fn session_fingerprint(meta: &SessionInfo) -> Value {
    json!({
        "started_at": meta.created_ms,
        "last_active": meta.updated_ms,
        "model": meta.model,
        "title": meta.title.clone().filter(|t| !t.trim().is_empty()).unwrap_or_else(|| "Untitled".to_string()),
    })
}

// ───────────────────────── scan ─────────────────────────

/// One scan result (upstream `scan_sessions`' return dict, minus the assembled payload).
struct Scan {
    sessions: Vec<SessionStats>,
    aggregate: Aggregate,
    mode: &'static str,
    sessions_total: u64,
    rescanned: u64,
    reused: u64,
    error: Option<Value>,
}

fn title_of(meta: &SessionInfo) -> String {
    meta.title
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "Untitled session".to_string())
}

/// `scan_sessions()`: read every session through the JSONL store, re-analysing only sessions whose
/// fingerprint changed since the last checkpoint.
fn scan_sessions(paths: &Paths) -> Scan {
    let store = Store::new(paths.sessions());
    let (checkpoint_current, previous) = load_checkpoint(paths);
    let mut reused = 0u64;
    let mut rescanned = 0u64;
    let mut sessions: Vec<SessionStats> = Vec::new();
    let mut checkpoint: Map<String, Value> = Map::new();
    let mut error: Option<Value> = None;

    let metas = store.list();
    let sessions_total = metas.len() as u64;
    for meta in &metas {
        let fingerprint = session_fingerprint(meta);
        let cached = previous
            .get(&meta.id)
            .filter(|c| checkpoint_current && c.get("fingerprint") == Some(&fingerprint))
            .and_then(|c| c.get("stats"))
            .cloned()
            .and_then(|v| serde_json::from_value::<SessionStats>(v).ok());
        let mut stats = match cached {
            Some(stats) => {
                reused += 1;
                stats
            }
            None => {
                rescanned += 1;
                match store.read(&meta.id) {
                    Ok(events) => analyze_events(&meta.id, &title_of(meta), &events),
                    Err(e) => {
                        if error.is_none() {
                            error = Some(json!(format!("could not read session {}: {e}", meta.id)));
                        }
                        SessionStats::new(&meta.id, &title_of(meta))
                    }
                }
            }
        };
        stats.set_meta(meta);
        if !meta.model.trim().is_empty() {
            stats.add_model(&meta.model);
        }
        checkpoint.insert(
            meta.id.clone(),
            json!({"fingerprint": fingerprint, "stats": stats}),
        );
        sessions.push(stats);
    }

    write_json(
        &data_file(paths, CHECKPOINT_FILE),
        &json!({"schema_version": CHECKPOINT_SCHEMA_VERSION, "generated_at": unix_now(), "sessions": checkpoint}),
    );

    let aggregate = aggregate_stats(&sessions);
    Scan {
        sessions,
        aggregate,
        mode: if reused > 0 { "incremental" } else { "full" },
        sessions_total,
        rescanned,
        reused,
        error,
    }
}

// ───────────────────────── snapshot + payload ─────────────────────────

/// `_compute_from_scan`: evaluate every definition against a scan, keeping `state.json` as a floor.
fn compute_from_scan(paths: &Paths, scan: &Scan, run_count: u64, duration_ms: u64) -> Value {
    let now = unix_now();
    let mut state = load_state(paths);
    let mut evaluated: Vec<Value> = Vec::with_capacity(ACHIEVEMENTS.len());
    let (mut unlocked_count, mut discovered_count, mut secret_count) = (0u64, 0u64, 0u64);

    for def in ACHIEVEMENTS {
        let mut eval = evaluate_definition(def, &scan.aggregate);
        let known = state.get("unlocks").and_then(|u| u.get(def.id)).cloned();
        if eval.unlocked && known.is_none() {
            // unlock time is recorded once; `tier` is the first tier that was reached
            let evidence = evidence_for(def, &scan.sessions);
            state["unlocks"][def.id] =
                json!({"tier": eval.tier, "unlocked_at": now, "evidence": evidence});
        }
        let entry = state.get("unlocks").and_then(|u| u.get(def.id)).cloned();
        if let Some(entry) = entry.as_ref() {
            // sticky: state.json is a floor, a badge never flickers back to locked
            if !eval.unlocked {
                eval.unlocked = true;
                eval.discovered = true;
                eval.state = "unlocked";
                if eval.tier.is_none() {
                    eval.tier = entry
                        .get("tier")
                        .and_then(Value::as_str)
                        .map(str::to_string);
                }
            }
        }
        let unlocked_at = entry
            .as_ref()
            .and_then(|e| e.get("unlocked_at"))
            .and_then(Value::as_u64);
        let evidence = entry
            .as_ref()
            .and_then(|e| e.get("evidence"))
            .cloned()
            .or_else(|| evidence_for(def, &scan.sessions));
        if eval.unlocked {
            unlocked_count += 1;
        } else if eval.state == "discovered" {
            discovered_count += 1;
        } else if eval.state == "secret" {
            secret_count += 1;
        }
        evaluated.push(item_json(def, &eval, unlocked_at, evidence));
    }
    save_state(paths, &state);

    let scan_meta = json!({
        "mode": scan.mode,
        "sessions_total": scan.sessions_total,
        "sessions_rescanned": scan.rescanned,
        "sessions_reused": scan.reused,
        "sessions_scanned_so_far": scan.sessions.len(),
        "sessions_expected_total": scan.sessions_total,
        // ark additions (upstream keeps these in the in-memory _SCAN_STATUS instead)
        "run_count": run_count,
        "duration_ms": duration_ms,
    });

    json!({
        "achievements": evaluated,
        "sessions": scan.sessions,
        "aggregate": aggregate_json(&scan.aggregate),
        "scan_meta": scan_meta,
        "error": scan.error.clone().unwrap_or(Value::Null),
        "unlocked_count": unlocked_count,
        "discovered_count": discovered_count,
        "secret_count": secret_count,
        "total_count": evaluated.len(),
        "generated_at": now,
    })
}

/// Serialise scans: `_SCAN_LOCK`.
static SCAN_LOCK: Mutex<()> = Mutex::new(());

/// `_run_scan_and_update_cache` for a synchronous, single-process ark: scan, evaluate, persist.
fn rescan(paths: &Paths) -> Value {
    let _guard = SCAN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let run_count = read_json(&data_file(paths, SNAPSHOT_FILE))
        .and_then(|v| {
            v.get("scan_meta")
                .and_then(|m| m.get("run_count"))
                .and_then(Value::as_u64)
        })
        .unwrap_or(0)
        + 1;
    let started = std::time::Instant::now();
    let scan = scan_sessions(paths);
    let snapshot = compute_from_scan(
        paths,
        &scan,
        run_count,
        started.elapsed().as_millis() as u64,
    );
    write_json(&data_file(paths, SNAPSHOT_FILE), &snapshot);
    snapshot
}

/// `evaluate_all(force)`: `force` rescans; otherwise the persisted snapshot is served as-is (stale
/// or not) and only a first-ever call without any snapshot scans.
fn serve_snapshot(paths: &Paths, force: bool) -> Value {
    if !force {
        if let Some(saved) = read_json(&data_file(paths, SNAPSHOT_FILE)) {
            if saved
                .get("achievements")
                .map(Value::is_array)
                .unwrap_or(false)
            {
                return saved;
            }
        }
    }
    rescan(paths)
}

fn generated_at(snapshot: &Value) -> i64 {
    snapshot
        .get("generated_at")
        .and_then(Value::as_i64)
        .unwrap_or(0)
}

/// `_is_snapshot_stale`: no timestamp, or older than [`SNAPSHOT_TTL_SECONDS`].
fn is_snapshot_stale(snapshot: &Value, now: i64) -> bool {
    let ts = generated_at(snapshot);
    ts <= 0 || now - ts > SNAPSHOT_TTL_SECONDS
}

/// `_scan_status_payload()` (derived from the persisted snapshot; there is no background thread).
fn scan_status(snapshot: &Value, now: i64) -> Value {
    let generated = generated_at(snapshot);
    let meta = snapshot
        .get("scan_meta")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let run_count = meta.get("run_count").and_then(Value::as_u64).unwrap_or(0);
    let duration = meta.get("duration_ms").and_then(Value::as_u64);
    json!({
        "state": "idle",
        "started_at": Value::Null,
        "finished_at": if generated > 0 { json!(generated) } else { Value::Null },
        "last_error": snapshot.get("error").cloned().unwrap_or(Value::Null),
        "last_duration_ms": duration,
        "run_count": run_count,
        "ttl_seconds": SNAPSHOT_TTL_SECONDS,
        "snapshot_generated_at": if generated > 0 { json!(generated) } else { Value::Null },
        "snapshot_age_seconds": if generated > 0 { json!(now - generated) } else { Value::Null },
        "snapshot_stale": is_snapshot_stale(snapshot, now),
    })
}

/// The `/achievements` payload: the snapshot's achievements and counters, plus `is_stale` and the
/// scan status merged into `scan_meta`.
fn payload(snapshot: &Value, now: i64) -> Value {
    let mut scan_meta = snapshot
        .get("scan_meta")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if let Some(obj) = scan_meta.as_object_mut() {
        obj.insert("status".into(), scan_status(snapshot, now));
    }
    json!({
        "achievements": snapshot.get("achievements").cloned().unwrap_or_else(|| json!([])),
        "unlocked_count": snapshot.get("unlocked_count").cloned().unwrap_or_else(|| json!(0)),
        "discovered_count": snapshot.get("discovered_count").cloned().unwrap_or_else(|| json!(0)),
        "secret_count": snapshot.get("secret_count").cloned().unwrap_or_else(|| json!(0)),
        "total_count": snapshot.get("total_count").cloned().unwrap_or_else(|| json!(0)),
        "error": snapshot.get("error").cloned().unwrap_or(Value::Null),
        "generated_at": generated_at(snapshot),
        "is_stale": is_snapshot_stale(snapshot, now),
        "scan_meta": scan_meta,
    })
}

/// The dashboard payload (upstream `GET /api/plugins/hermes-achievements/achievements`).
pub fn data(_cfg: &Config, paths: &Paths) -> Value {
    let snapshot = serve_snapshot(paths, false);
    payload(&snapshot, unix_now())
}

// ───────────────────────── surfaces ─────────────────────────

/// The `achievements` tool (overview / scan / recent / session <id> / reset).
pub fn tools(_cfg: &Config, paths: &Paths) -> Vec<Arc<dyn Tool>> {
    vec![Arc::new(AchievementsTool {
        paths: paths.clone(),
    })]
}

struct AchievementsTool {
    paths: Paths,
}

const HELP: &str = "actions: overview (current badges), scan (rescan every session now), recent (latest 20 unlocks), session (badges earned by one session; needs session_id), reset (clear unlock state, snapshot and checkpoint)";

impl Tool for AchievementsTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "achievements".into(),
            description: "Tiered achievements earned from real session history, scored from this machine's ark sessions. Reports each badge's name, category and state (unlocked, discovered or secret) with progress toward the next tier.".into(),
            input_schema: json!({"type":"object","properties":{
                "action":{"type":"string","enum":["overview","scan","recent","session","reset"]},
                "session_id":{"type":"string","description":"Session id (action=session)"},
                "force":{"type":"boolean","description":"Rescan before answering (same as action=scan)"}},
                "required":[]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }

    /// No gate effects: reads the session log directory and writes only the plugin's own
    /// `plugin-data/achievements` files (same as upstream's `/rescan` behind the dashboard).
    fn effects(&self, _ctx: &ToolCtx, _input: &Value) -> Vec<Effect> {
        Vec::new()
    }

    fn call(&self, _ctx: &ToolCtx, input: Value) -> ToolOutput {
        let action = input
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("overview")
            .trim()
            .to_string();
        let force = input.get("force").and_then(Value::as_bool).unwrap_or(false);
        let session_id = input
            .get("session_id")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty());
        match action.as_str() {
            "" | "overview" | "scan" | "recent" | "reset" | "session" => {
                ToolOutput::ok(dispatch(&self.paths, &action, session_id, force))
            }
            other => ToolOutput::err(format!("unknown action `{other}`\n\n{HELP}")),
        }
    }
}

/// `/achievements [overview|scan|recent|session <id>|reset]`.
pub fn slash(_cfg: &Config, paths: &Paths) -> impl Slash {
    AchievementsSlash {
        paths: paths.clone(),
    }
}

struct AchievementsSlash {
    paths: Paths,
}

impl Slash for AchievementsSlash {
    fn commands(&self) -> Vec<(String, String)> {
        vec![("achievements".into(), "Tiered achievements from real session history (overview|scan|recent|session <id>|reset).".into())]
    }

    fn run(&self, _ctx: &SlashCtx, name: &str, args: &str) -> Option<Result<SlashReply, String>> {
        (name == "achievements").then(|| {
            let args = args.trim();
            let (action, rest) = args
                .split_once(char::is_whitespace)
                .map(|(a, b)| (a, b.trim()))
                .unwrap_or((args, ""));
            let session_id = (action == "session" && !rest.is_empty()).then_some(rest);
            Ok(SlashReply::text(dispatch(
                &self.paths,
                action,
                session_id,
                false,
            )))
        })
    }
}

/// Shared implementation of the tool and the slash command.
fn dispatch(paths: &Paths, action: &str, session_id: Option<&str>, force: bool) -> String {
    match action {
        "" | "overview" => render_overview(&serve_snapshot(paths, force), unix_now()),
        "scan" | "rescan" => {
            let snapshot = serve_snapshot(paths, true);
            format!("Rescanned.\n{}", render_overview(&snapshot, unix_now()))
        }
        "recent" => render_recent(&serve_snapshot(paths, false)),
        "session" => match session_id {
            Some(id) => render_session(&serve_snapshot(paths, false), id.trim()),
            None => "usage: achievements session <session-id>".to_string(),
        },
        "reset" => reset(paths),
        other => format!("unknown action `{other}`\n\n{HELP}"),
    }
}

/// `POST /reset-state`: clear unlocks, drop the snapshot and the checkpoint.
fn reset(paths: &Paths) -> String {
    save_state(paths, &json!({"unlocks": {}}));
    let mut removed = 0;
    for name in [SNAPSHOT_FILE, CHECKPOINT_FILE] {
        if fs::remove_file(data_file(paths, name)).is_ok() {
            removed += 1;
        }
    }
    format!("Achievements reset: unlock state cleared, {removed} cached file(s) removed. Run `scan` to rebuild from session history.")
}

fn u64_of(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0)
}

/// One line per badge: name · category · state (plus tier/progress where there is some).
fn badge_line(item: &Value) -> String {
    let name = item.get("name").and_then(Value::as_str).unwrap_or("?");
    let category = item.get("category").and_then(Value::as_str).unwrap_or("?");
    let state = item.get("state").and_then(Value::as_str).unwrap_or("?");
    let mut line = format!("  [{state}] {name} · {category}");
    if state != "secret" {
        if state == "unlocked" {
            if let Some(tier) = item.get("tier").and_then(Value::as_str) {
                line.push_str(&format!(" · {tier}"));
            }
        }
        if item
            .get("requirements")
            .map(Value::is_array)
            .unwrap_or(false)
        {
            line.push_str(&format!(
                " · {}% of requirements",
                u64_of(item, "progress_pct")
            ));
        } else if state == "unlocked" {
            match item.get("next_tier").and_then(Value::as_str) {
                Some(next) => line.push_str(&format!(
                    " · next {next} at {} ({}%)",
                    u64_of(item, "next_threshold"),
                    u64_of(item, "progress_pct")
                )),
                None => line.push_str(" · max tier"),
            }
        } else {
            line.push_str(&format!(
                " · {}/{} ({}%)",
                u64_of(item, "progress"),
                u64_of(item, "next_threshold"),
                u64_of(item, "progress_pct")
            ));
        }
    }
    line
}

fn render_overview(snapshot: &Value, now: i64) -> String {
    let total = u64_of(snapshot, "total_count");
    let unlocked = u64_of(snapshot, "unlocked_count");
    let discovered = u64_of(snapshot, "discovered_count");
    let secret = u64_of(snapshot, "secret_count");
    let meta = snapshot
        .get("scan_meta")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut out = format!(
        "Achievements: {unlocked}/{total} unlocked · {discovered} discovered · {secret} secret · {} locked\n",
        total.saturating_sub(unlocked + discovered + secret)
    );
    out.push_str(&format!(
        "  scan: {} · {} session(s), {} rescanned, {} reused · snapshot {} ({} ago, run #{})\n",
        meta.get("mode").and_then(Value::as_str).unwrap_or("?"),
        u64_of(&meta, "sessions_total"),
        u64_of(&meta, "sessions_rescanned"),
        u64_of(&meta, "sessions_reused"),
        if is_snapshot_stale(snapshot, now) {
            "stale"
        } else {
            "fresh"
        },
        match generated_at(snapshot) {
            0 => "never".to_string(),
            ts => format!("{}s", (now - ts).max(0)),
        },
        u64_of(&meta, "run_count"),
    ));
    if let Some(a) = snapshot.get("achievements").and_then(Value::as_array) {
        for item in a {
            out.push_str(&badge_line(item));
            out.push('\n');
        }
    }
    out
}

fn render_recent(snapshot: &Value) -> String {
    let mut unlocked: Vec<&Value> = snapshot
        .get("achievements")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter(|i| i.get("unlocked").and_then(Value::as_bool).unwrap_or(false))
                .collect()
        })
        .unwrap_or_default();
    unlocked.sort_by_key(|i| std::cmp::Reverse(u64_of(i, "unlocked_at")));
    if unlocked.is_empty() {
        return "No achievements unlocked yet — keep working and run `scan`.".to_string();
    }
    let mut out = format!("Recent unlocks ({}):\n", unlocked.len().min(20));
    for item in unlocked.iter().take(20) {
        out.push_str(&format!(
            "  {} · {} · {}{}\n",
            item.get("name").and_then(Value::as_str).unwrap_or("?"),
            item.get("category").and_then(Value::as_str).unwrap_or("?"),
            item.get("tier")
                .and_then(Value::as_str)
                .unwrap_or("unlocked"),
            match u64_of(item, "unlocked_at") {
                0 => String::new(),
                ts => format!(" · {}", fmt_time(ts as i64, 0)),
            }
        ));
    }
    out
}

fn render_session(snapshot: &Value, session_id: &str) -> String {
    let Some(sessions) = snapshot.get("sessions").and_then(Value::as_array) else {
        return format!(
            "No session `{session_id}` in the achievements snapshot — run `scan` first."
        );
    };
    let Some(row) = sessions
        .iter()
        .find(|s| s.get("session_id").and_then(Value::as_str) == Some(session_id))
    else {
        return format!(
            "No session `{session_id}` in the achievements snapshot — run `scan` first."
        );
    };
    let stats: SessionStats = match serde_json::from_value(row.clone()) {
        Ok(s) => s,
        Err(e) => return format!("session `{session_id}` stats are unreadable: {e}"),
    };
    // upstream `session_badges`: evaluate the whole catalog against this session alone
    let aggregate = aggregate_stats(std::slice::from_ref(&stats));
    let mut badges: Vec<String> = Vec::new();
    for def in ACHIEVEMENTS {
        let eval = evaluate_definition(def, &aggregate);
        if eval.unlocked {
            let item = item_json(def, &eval, None, None);
            badges.push(format!(
                "  {} · {}{}",
                item["name"].as_str().unwrap_or(def.name),
                item["category"].as_str().unwrap_or(def.category),
                eval.tier.map(|t| format!(" · {t}")).unwrap_or_default()
            ));
        }
    }
    let mut out = format!(
        "Session {session_id} · {} · messages {} · tool calls {} ({} distinct) · errors {} · files touched {}\n",
        stats.title,
        stats.message_count,
        stats.tool_call_count,
        stats.distinct_tool_count,
        stats.error_count,
        stats.files_touched_count
    );
    if badges.is_empty() {
        out.push_str("  no badges earned by this session on its own\n");
    } else {
        out.push_str(&format!("  badges: {}\n", badges.len()));
        for b in badges {
            out.push_str(&b);
            out.push('\n');
        }
    }
    out
}

// ───────────────────────── tests ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_core::tool::SpawnRequest;
    use ark_core::{Cancel, Message, Provider};
    use ark_kernel::event::LOG_VERSION;
    use ark_kernel::kernel::Resolver;

    // ── fixtures ──

    fn root(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ark-achievements-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("data")).unwrap();
        d
    }

    fn paths_of(d: &Path) -> Paths {
        Paths {
            data: d.join("data"),
            config_dir: d.join("cfg"),
            runtime: d.join("run"),
        }
    }

    fn fresh(tag: &str) -> Paths {
        paths_of(&root(tag))
    }

    /// 2023-11-14T22:13:20Z
    const T0: u64 = 1_700_000_000_000;

    fn msg(text: &str) -> EventKind {
        EventKind::Message {
            message: Message::user(text),
            usage: None,
            model: None,
            inbox: None,
        }
    }

    fn called(name: &str, input: Value) -> EventKind {
        EventKind::ToolCalled {
            tool_use_id: format!("tu-{name}"),
            name: name.into(),
            input,
            idempotency_key: "k".into(),
        }
    }

    fn settled(is_error: bool) -> EventKind {
        EventKind::ToolSettled {
            tool_use_id: "tu".into(),
            is_error,
            bytes: 1,
            artifact: None,
            ui_resource: None,
        }
    }

    /// Write `<data>/sessions/<id>/events.jsonl` the way the store lays it out (header at `seq 0`,
    /// then `kinds`), with every timestamp derived from `created_ms` so fingerprints and the
    /// weekend/night counters are deterministic.
    fn write_session(
        paths: &Paths,
        id: &str,
        created_ms: u64,
        model: &str,
        title: &str,
        kinds: Vec<EventKind>,
    ) {
        let dir = paths.sessions().join(id);
        fs::create_dir_all(dir.join("artifacts")).unwrap();
        let header = Event {
            seq: 0,
            ts: created_ms,
            kind: EventKind::Header {
                version: LOG_VERSION,
                session_id: id.into(),
                workspace: "/w".into(),
                model: model.into(),
                parent: None,
                title: Some(title.into()),
            },
        };
        let mut log = String::new();
        log.push_str(&serde_json::to_string(&header).unwrap());
        log.push('\n');
        for (i, kind) in kinds.into_iter().enumerate() {
            let ev = Event {
                seq: i as u64 + 1,
                ts: created_ms + 1_000 * (i as u64 + 1),
                kind,
            };
            log.push_str(&serde_json::to_string(&ev).unwrap());
            log.push('\n');
        }
        fs::write(dir.join("events.jsonl"), log).unwrap();
    }

    fn item_of<'a>(snapshot: &'a Value, id: &str) -> &'a Value {
        snapshot["achievements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["id"] == id)
            .unwrap_or_else(|| panic!("no achievement {id}"))
    }

    /// The first unix second (scanning forward from now) whose *local* weekday/hour matches.
    fn find_local_time(pred: impl Fn(i32, i32) -> bool) -> i64 {
        let mut t = unix_now();
        for _ in 0..24 * 14 {
            if let Some((wday, hour)) = local_clock(t) {
                if pred(wday, hour) {
                    return t;
                }
            }
            t += 3_600;
        }
        panic!("no matching local time in the next two weeks");
    }

    struct NoProvider;
    impl Resolver for NoProvider {
        fn provider(&self, id: &str) -> Result<Arc<dyn Provider>, String> {
            Err(format!("no provider {id}"))
        }
    }

    struct NoHost;
    impl ark_core::ToolHost for NoHost {
        fn spawn_agent(&self, _: SpawnRequest, _: &Cancel) -> Result<String, String> {
            Err("no sub-agents in this test".into())
        }
        fn ask_user(&self, _: &str) -> Result<String, String> {
            Err("nobody to ask".into())
        }
    }

    fn ctx(paths: &Paths) -> ToolCtx {
        ToolCtx {
            workspace: paths.data.clone(),
            session_id: "s1".into(),
            artifacts: paths.data.join("art"),
            home: paths.data.clone(),
            cancel: Cancel::new(),
            host: Arc::new(NoHost),
            secrets: Arc::new(|s: &str| s.to_string()),
        }
    }

    fn slash_ctx(paths: &Paths) -> SlashCtx {
        let mut cfg = Config::default();
        cfg.model.default = "fake/m".into();
        let kernel = ark_kernel::kernel::new_kernel(
            cfg,
            paths.clone(),
            Arc::new(NoProvider),
            vec![],
            Arc::new(ark_kernel::vault::Vault::empty()),
            Arc::new(ark_kernel::approver::Policy {
                allow_privilege: false,
                allow_egress: false,
            }),
        );
        SlashCtx {
            kernel,
            session: Some("s1".into()),
            surface: "cli".into(),
        }
    }

    // ── catalog ──

    #[test]
    fn catalog_ids_are_stable_and_unique() {
        assert_eq!(ACHIEVEMENTS.len(), 60, "upstream ships 60 achievements");
        let mut ids: Vec<&str> = ACHIEVEMENTS.iter().map(|a| a.id).collect();
        ids.sort_unstable();
        let unique = ids.len();
        ids.dedup();
        assert_eq!(
            ids.len(),
            unique,
            "duplicate achievement ids would collide in state.json"
        );

        for a in ACHIEVEMENTS {
            assert!(
                a.id.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "unexpected id shape: {}",
                a.id
            );
            assert!(
                !a.name.is_empty()
                    && !a.description.is_empty()
                    && !a.category.is_empty()
                    && !a.icon.is_empty(),
                "{} is incomplete",
                a.id
            );
            if a.is_tiered() {
                assert_eq!(
                    a.tiers.len(),
                    TIER_NAMES.len(),
                    "{} needs a full Copper→Olympian ladder",
                    a.id
                );
                assert!(
                    a.tiers.windows(2).all(|w| w[0] < w[1]),
                    "{} tiers must ascend",
                    a.id
                );
                assert!(a.requires.is_empty(), "{}", a.id);
            } else {
                assert!(!a.requires.is_empty(), "{} has no requirement", a.id);
                assert!(a.tiers.is_empty(), "{}", a.id);
            }
        }
        // ids are the unlock-state keys: a rename silently re-locks a badge
        for id in [
            "let_him_cook",
            "full_send",
            "port_3000_taken",
            "open_weights_pilgrim",
            "weekend_warrior",
            "cache_hit_appreciator",
        ] {
            assert!(definition(id).is_some(), "missing upstream id {id}");
        }
        for banned in ["fallback_pilot", "browser_sleuth", "release_ritualist"] {
            assert!(
                definition(banned).is_none(),
                "{banned} was removed upstream"
            );
        }
        assert_eq!(ACHIEVEMENTS.iter().filter(|a| a.secret).count(), 8);
        // every metric a badge reads must exist in the aggregate (a typo would silently read 0)
        let aggregate = aggregate_stats(&[]);
        for a in ACHIEVEMENTS {
            let metrics: Vec<&str> = if a.is_tiered() {
                vec![a.metric]
            } else {
                a.requires.iter().map(|(m, _)| *m).collect()
            };
            for metric in metrics {
                assert!(
                    aggregate.contains_key(metric),
                    "{} reads unknown metric {metric}",
                    a.id
                );
                assert_ne!(
                    metric_label(metric),
                    metric.replace('_', " "),
                    "{metric} has no METRIC_LABELS entry"
                );
            }
        }

        assert_eq!(definition("let_him_cook").unwrap().kind(), "best_session");
        assert_eq!(definition("terminal_goblin").unwrap().kind(), "lifetime");
        assert_eq!(definition("full_send").unwrap().kind(), "multi_condition");
        assert!(!definition("full_send").unwrap().is_tiered());
    }

    // ── session analysis (real JSONL store) ──

    #[test]
    fn analyze_counts_tools_errors_and_files() {
        let paths = fresh("analyze");
        write_session(
            &paths,
            "s1",
            T0,
            "anthropic/claude-sonnet",
            "Fix dev server",
            vec![
                msg("the dev server on port 3000 is already in use — please fix it"),
                called("shell", json!({"command": "npm test"})),
                settled(false),
                called("read", json!({"path": "/home/noob/proj/src/main.rs"})),
                settled(false),
                called("edit", json!({"path": "/home/noob/proj/src/lib.rs"})),
                settled(true),
                called("web_search", json!({"query": "port already in use"})),
                settled(false),
                called("grep", json!({"pattern": "TODO"})),
                settled(false),
                EventKind::Model {
                    model: "openai/gpt-5".into(),
                },
            ],
        );

        let snapshot = rescan(&paths);
        let s = &snapshot["sessions"][0];
        assert_eq!(s["session_id"], "s1");
        assert_eq!(s["title"], "Fix dev server");
        assert_eq!(s["message_count"], 1, "only Message events are messages");
        assert_eq!(s["tool_call_count"], 5);
        assert_eq!(s["distinct_tool_count"], 5);
        assert_eq!(
            s["tool_names"],
            json!(["edit", "grep", "read", "shell", "web_search"])
        );
        // ark `shell` counts as Hermes `terminal`
        assert_eq!(s["terminal_calls"], 1);
        assert_eq!(s["web_calls"], 1);
        // read→read_file, grep→search_files
        assert_eq!(s["file_reads_searches"], 2);
        // read→read_file, edit→patch, grep→search_files
        assert_eq!(s["file_tool_calls"], 3);
        assert_eq!(s["patch_calls"], 1);
        // the failed tool call plus the error-bearing user message
        assert_eq!(s["error_count"], 2);
        assert_eq!(
            s["files_touched_count"], 2,
            "paths come from tool inputs too"
        );
        assert_eq!(s["port_conflict"], true);
        assert_eq!(s["port_conflict_events"], 1);
        assert_eq!(
            s["model_names"],
            json!(["anthropic/claude-sonnet", "openai/gpt-5"])
        );
        assert_eq!(s["started_at"], T0 / 1000);
        assert_eq!(s["last_active"], (T0 + 12_000) / 1000);
        assert_eq!(s["test_events"], 0, "no test output text reaches the log");

        let agg = &snapshot["aggregate"];
        assert_eq!(agg["session_count"], 1);
        assert_eq!(agg["max_tool_calls_in_session"], 5);
        assert_eq!(agg["total_tool_calls"], 5);
        assert_eq!(agg["total_errors"], 2);
        assert_eq!(agg["distinct_model_count"], 2);
        assert_eq!(agg["distinct_provider_count"], 2);
        // two providers already earn the first Provider Polyglot tier (Copper = 2)
        assert_eq!(snapshot["unlocked_count"], 1);
        assert_eq!(item_of(&snapshot, "provider_polyglot")["tier"], "Copper");
        assert_eq!(snapshot["total_count"], 60);
    }

    #[test]
    fn weekend_and_night_sessions_are_counted() {
        let paths = fresh("lifestyle");
        let weekend = find_local_time(|wday, hour| wday >= 5 && hour == 12);
        let night = find_local_time(|wday, hour| wday == 0 && hour == 3);
        write_session(
            &paths,
            "weekend",
            weekend as u64 * 1000,
            "m",
            "weekend",
            vec![msg("hi")],
        );
        write_session(
            &paths,
            "night",
            night as u64 * 1000,
            "m",
            "night",
            vec![msg("hi")],
        );

        let agg = rescan(&paths)["aggregate"].clone();
        assert_eq!(agg["session_count"], 2);
        assert_eq!(agg["weekend_sessions"], 1);
        assert_eq!(agg["night_sessions"], 1);
    }

    // ── evaluation ──

    #[test]
    fn tier_ladder_boundaries() {
        let def = definition("let_him_cook").unwrap(); // 200 / 500 / 1200 / 3000 / 8000
        let at = |n: u64| {
            evaluate_tiered(
                def,
                &Aggregate::from([("max_tool_calls_in_session".to_string(), n)]),
            )
        };

        let zero = at(0);
        assert_eq!(
            (
                zero.unlocked,
                zero.state,
                zero.tier.as_deref(),
                zero.next_tier.as_deref()
            ),
            (false, "discovered", None, Some("Copper"))
        );
        assert_eq!(
            (zero.progress, zero.next_threshold, zero.progress_pct),
            (0, 200, 0)
        );

        let almost = at(199);
        assert!(!almost.unlocked);
        assert_eq!(almost.progress_pct, 99, "floor(199/200) capped at 99");

        let copper = at(200);
        assert!(copper.unlocked && copper.discovered);
        assert_eq!(copper.state, "unlocked");
        assert_eq!(copper.tier.as_deref(), Some("Copper"));
        assert_eq!(copper.next_tier.as_deref(), Some("Silver"));
        assert_eq!(copper.next_threshold, 500);
        assert_eq!(
            copper.progress_pct, 0,
            "a fresh tier starts at 0% toward the next one"
        );

        assert_eq!(at(499).progress_pct, 99);
        assert_eq!(at(500).tier.as_deref(), Some("Silver"));
        let top = at(8000);
        assert_eq!(top.tier.as_deref(), Some("Olympian"));
        assert_eq!(top.next_tier, None);
        assert_eq!(top.progress_pct, 100, "the top tier is the only 100%");
        assert_eq!(top.next_threshold, 8000);
        let beyond = at(9_999);
        assert_eq!((beyond.progress, beyond.progress_pct), (9_999, 100));
    }

    #[test]
    fn requirements_progress_is_the_mean_of_parts() {
        let def = definition("full_send").unwrap(); // terminal 180, file 120, web/browser 60
        let partial = evaluate_requirements(
            def,
            &Aggregate::from([
                ("max_terminal_calls_in_session".to_string(), 180),
                ("max_file_tool_calls_in_session".to_string(), 60),
                ("max_web_browser_calls_in_session".to_string(), 0),
            ]),
        );
        assert!(!partial.unlocked);
        assert_eq!(partial.state, "discovered");
        assert_eq!(
            (partial.progress, partial.progress_pct),
            (50, 50),
            "mean(1, 0.5, 0) → 50%"
        );
        assert_eq!(
            (partial.next_threshold, partial.next_tier.as_deref()),
            (100, None)
        );

        let complete = evaluate_requirements(
            def,
            &Aggregate::from([
                ("max_terminal_calls_in_session".to_string(), 180),
                ("max_file_tool_calls_in_session".to_string(), 120),
                ("max_web_browser_calls_in_session".to_string(), 60),
            ]),
        );
        assert!(complete.unlocked);
        assert_eq!(complete.state, "unlocked");
        assert_eq!((complete.progress, complete.progress_pct), (100, 100));

        let over = evaluate_requirements(
            def,
            &Aggregate::from([
                ("max_terminal_calls_in_session".to_string(), 10_000),
                ("max_file_tool_calls_in_session".to_string(), 10_000),
                ("max_web_browser_calls_in_session".to_string(), 10_000),
            ]),
        );
        assert_eq!(
            (over.progress, over.unlocked),
            (100, true),
            "each part is capped at 1"
        );

        // a lifetime-style ratio: 10/25 and 5/10 → mean 0.45
        let deps = definition("dependency_hell_tourist").unwrap();
        let ratio = evaluate_requirements(
            deps,
            &Aggregate::from([
                ("install_error_events".to_string(), 10),
                ("install_success_events".to_string(), 5),
            ]),
        );
        assert_eq!(ratio.progress, 45);
        assert!(!ratio.unlocked);
    }

    #[test]
    fn secret_stays_hidden_until_the_first_signal() {
        let def = definition("port_3000_taken").unwrap();
        let hidden = evaluate_tiered(def, &Aggregate::new());
        assert_eq!(hidden.state, "secret");
        assert!(!hidden.discovered);
        let card = item_json(def, &hidden, None, None);
        assert_eq!(card["name"], "???");
        assert_eq!(card["icon"], "secret");
        assert_eq!(card["description"], SECRET_DESCRIPTION);
        assert_eq!(card["criteria"], SECRET_CRITERIA);
        assert!(!card["description"]
            .as_str()
            .unwrap()
            .contains("port conflict"));

        // the very first matching signal reveals the badge (still locked)
        let revealed = evaluate_tiered(
            def,
            &Aggregate::from([("port_conflict_events".to_string(), 1)]),
        );
        assert_eq!(revealed.state, "discovered");
        assert!(revealed.discovered && !revealed.unlocked);
        let card = item_json(def, &revealed, None, None);
        assert_eq!(card["name"], "Port 3000 Is Taken");
        assert!(card["criteria"]
            .as_str()
            .unwrap()
            .contains("port conflict detections"));

        // requirement-based secrets behave the same
        let secret_req = definition("one_character_fix").unwrap();
        assert_eq!(
            evaluate_requirements(secret_req, &Aggregate::new()).state,
            "secret"
        );
        let revealed = evaluate_requirements(
            secret_req,
            &Aggregate::from([("tiny_patch_after_errors_events".to_string(), 1)]),
        );
        assert_eq!(revealed.state, "discovered");

        // a non-secret badge is discovered from the start
        assert_eq!(
            evaluate_tiered(definition("let_him_cook").unwrap(), &Aggregate::new()).state,
            "discovered"
        );
    }

    #[test]
    fn unlocks_persist_and_keep_the_first_unlocked_at() {
        let paths = fresh("unlock");
        write_session(
            &paths,
            "s1",
            T0,
            "ollama/llama3",
            "local chat",
            vec![msg("hi")],
        );

        let first = rescan(&paths);
        let card = item_of(&first, "open_weights_pilgrim");
        assert_eq!(card["unlocked"], true);
        assert_eq!(card["tier"], "Copper");
        assert_eq!(first["aggregate"]["local_model_chat_sessions"], 1);
        assert_eq!(first["unlocked_count"], 1);

        // pin a known first-unlock time, then rescan twice: it must not be re-stamped
        let mut state = load_state(&paths);
        state["unlocks"]["open_weights_pilgrim"]["unlocked_at"] = json!(1_000u64);
        save_state(&paths, &state);
        let second = rescan(&paths);
        assert_eq!(
            item_of(&second, "open_weights_pilgrim")["unlocked_at"],
            1000
        );
        assert_eq!(second["unlocked_count"], 1);

        // the evidence disappears from history: the badge is a floor, it never re-locks
        fs::remove_dir_all(paths.sessions().join("s1")).unwrap();
        let third = rescan(&paths);
        let card = item_of(&third, "open_weights_pilgrim");
        assert_eq!(card["unlocked"], true);
        assert_eq!(card["discovered"], true);
        assert_eq!(card["state"], "unlocked");
        assert_eq!(card["tier"], "Copper", "the first tier is remembered");
        assert_eq!(
            card["unlocked_at"], 1000,
            "unlocked_at is the first unlock, forever"
        );
        assert_eq!(third["aggregate"]["local_model_chat_sessions"], 0);
        assert_eq!(third["unlocked_count"], 1);
        assert_eq!(
            load_state(&paths)["unlocks"]["open_weights_pilgrim"]["unlocked_at"],
            1000
        );
    }

    // ── scanning: checkpoint + snapshot ──

    #[test]
    fn warm_scan_reuses_the_checkpoint() {
        let paths = fresh("checkpoint");
        write_session(
            &paths,
            "a",
            T0,
            "m",
            "a",
            vec![msg("one"), called("shell", json!({})), settled(false)],
        );
        write_session(&paths, "b", T0 + 60_000, "m", "b", vec![msg("two")]);

        let cold = rescan(&paths);
        assert_eq!(cold["scan_meta"]["mode"], "full");
        assert_eq!(
            (
                cold["scan_meta"]["sessions_rescanned"].as_u64(),
                cold["scan_meta"]["sessions_reused"].as_u64()
            ),
            (Some(2), Some(0))
        );
        assert_eq!(cold["scan_meta"]["sessions_total"], 2);

        let warm = rescan(&paths);
        assert_eq!(warm["scan_meta"]["mode"], "incremental");
        assert_eq!(
            warm["scan_meta"]["sessions_reused"], 2,
            "unchanged sessions come from scan_checkpoint.json"
        );
        assert_eq!(warm["scan_meta"]["sessions_rescanned"], 0);
        assert_eq!(
            warm["aggregate"], cold["aggregate"],
            "reuse must not change the numbers"
        );

        // appending to one session re-analyses exactly that session
        write_session(
            &paths,
            "a",
            T0,
            "m",
            "a",
            vec![
                msg("one"),
                called("shell", json!({})),
                settled(false),
                msg("three"),
            ],
        );
        let mixed = rescan(&paths);
        assert_eq!(
            (
                mixed["scan_meta"]["sessions_reused"].as_u64(),
                mixed["scan_meta"]["sessions_rescanned"].as_u64()
            ),
            (Some(1), Some(1))
        );
        assert_eq!(mixed["aggregate"]["max_distinct_tools_in_session"], 1);
    }

    #[test]
    fn snapshot_is_served_stale_within_the_ttl() {
        let paths = fresh("ttl");
        write_session(&paths, "s1", T0, "m", "s", vec![msg("hi")]);
        let cfg = Config::default();

        // no snapshot yet → the first read scans and persists one
        let first = data(&cfg, &paths);
        assert_eq!(first["total_count"], 60);
        assert_eq!(first["is_stale"], false);
        assert_eq!(first["scan_meta"]["status"]["snapshot_stale"], false);
        assert_eq!(
            first["scan_meta"]["status"]["ttl_seconds"],
            SNAPSHOT_TTL_SECONDS
        );
        assert_eq!(first["scan_meta"]["sessions_rescanned"], 1);
        assert!(data_file(&paths, SNAPSHOT_FILE).is_file());

        // age the snapshot past the TTL: the read serves it (marked stale) instead of rescanning
        let mut snapshot = read_json(&data_file(&paths, SNAPSHOT_FILE)).unwrap();
        snapshot["generated_at"] = json!(unix_now() - SNAPSHOT_TTL_SECONDS - 1);
        write_json(&data_file(&paths, SNAPSHOT_FILE), &snapshot);
        let stale = data(&cfg, &paths);
        assert_eq!(stale["is_stale"], true);
        assert_eq!(stale["scan_meta"]["status"]["snapshot_stale"], true);
        assert!(
            stale["scan_meta"]["status"]["snapshot_age_seconds"]
                .as_i64()
                .unwrap()
                > SNAPSHOT_TTL_SECONDS
        );
        assert_eq!(
            stale["scan_meta"]["sessions_rescanned"], 1,
            "a stale read must not rescan"
        );
        assert_eq!(stale["scan_meta"]["sessions_reused"], 0);

        // `scan`/force refreshes it
        let refreshed = serve_snapshot(&paths, true);
        assert_eq!(refreshed["scan_meta"]["sessions_reused"], 1);
        assert_eq!(data(&cfg, &paths)["is_stale"], false);
    }

    #[test]
    fn reset_clears_state_and_snapshot() {
        let paths = fresh("reset");
        write_session(&paths, "s1", T0, "ollama/llama3", "local", vec![msg("hi")]);
        let before = rescan(&paths);
        assert_eq!(before["unlocked_count"], 1);
        assert!(data_file(&paths, STATE_FILE).is_file());
        assert!(data_file(&paths, CHECKPOINT_FILE).is_file());

        let cfg = Config::default();
        let tool = tools(&cfg, &paths).into_iter().next().unwrap();
        let out = tool.call(&ctx(&paths), json!({"action": "reset"}));
        assert!(!out.is_error, "{}", out.content);
        assert!(out.content.contains("reset"));

        assert_eq!(load_state(&paths)["unlocks"], json!({}));
        assert!(
            !data_file(&paths, SNAPSHOT_FILE).exists(),
            "snapshot must be dropped"
        );
        assert!(
            !data_file(&paths, CHECKPOINT_FILE).exists(),
            "checkpoint must be dropped"
        );

        // a reset only forgets state: the next scan re-derives the badges from the session history
        // (upstream `POST /reset-state` behaves the same — it does not delete the sessions)
        let after = data(&cfg, &paths);
        assert_eq!(after["unlocked_count"], 1);
        assert_eq!(after["total_count"], 60);
        assert_eq!(after["scan_meta"]["mode"], "full", "nothing was cached");
    }

    // ── surfaces ──

    #[test]
    fn tool_and_payload_expose_the_dashboard_shape() {
        let paths = fresh("shape");
        write_session(
            &paths,
            "s1",
            T0,
            "ollama/llama3",
            "Local session",
            vec![
                msg("port 3000 is already in use"),
                called("shell", json!({})),
                settled(false),
            ],
        );
        let cfg = Config::default();

        let payload = data(&cfg, &paths);
        for key in [
            "achievements",
            "unlocked_count",
            "discovered_count",
            "secret_count",
            "total_count",
            "generated_at",
            "is_stale",
            "scan_meta",
            "error",
        ] {
            assert!(payload.get(key).is_some(), "payload missing {key}");
        }
        assert_eq!(payload["total_count"], 60);
        assert_eq!(payload["unlocked_count"], 1);
        let counts = payload["unlocked_count"].as_u64().unwrap()
            + payload["discovered_count"].as_u64().unwrap()
            + payload["secret_count"].as_u64().unwrap();
        assert_eq!(counts, 60, "every badge is unlocked, discovered or secret");

        let achievements = payload["achievements"].as_array().unwrap();
        assert_eq!(achievements.len(), 60);
        let cook = item_of(&payload, "let_him_cook");
        for key in [
            "id",
            "name",
            "description",
            "category",
            "kind",
            "icon",
            "threshold_metric",
            "tiers",
            "unlocked",
            "discovered",
            "state",
            "tier",
            "progress",
            "next_tier",
            "next_threshold",
            "progress_pct",
            "criteria",
        ] {
            assert!(cook.get(key).is_some(), "achievement missing {key}");
        }
        let tier_names: Vec<&str> = cook["tiers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(tier_names, TIER_NAMES);
        assert_eq!(
            item_of(&payload, "full_send")["requirements"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        // the secret got its first signal (a port conflict), so it is revealed but locked
        let port = item_of(&payload, "port_3000_taken");
        assert_eq!(port["state"], "discovered");
        assert_eq!(port["name"], "Port 3000 Is Taken");
        // an untouched secret stays hidden
        assert_eq!(item_of(&payload, "rollback_wizard")["name"], "???");
        assert_eq!(item_of(&payload, "rollback_wizard")["state"], "secret");
        assert!(payload["scan_meta"]["status"].is_object());

        let tool = tools(&cfg, &paths).into_iter().next().unwrap();
        assert_eq!(tool.spec().name, "achievements");
        assert!(tool.spec().input_schema["properties"]["action"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "session"));

        let overview = tool.call(&ctx(&paths), json!({"action": "overview"}));
        assert!(!overview.is_error, "{}", overview.content);
        for needle in [
            "Achievements:",
            "Let Him Cook",
            "Agent Autonomy",
            "[unlocked]",
            "[discovered]",
            "[secret]",
        ] {
            assert!(
                overview.content.contains(needle),
                "overview missing {needle}:\n{}",
                overview.content
            );
        }
        assert!(
            overview
                .content
                .contains("Open Weights Pilgrim · Model Lore · Copper"),
            "{}",
            overview.content
        );

        let scan = tool.call(&ctx(&paths), json!({"action": "scan"}));
        assert!(!scan.is_error);
        assert!(scan.content.starts_with("Rescanned."));
        assert!(scan.content.contains("1 reused"));

        let recent = tool.call(&ctx(&paths), json!({"action": "recent"}));
        assert!(!recent.is_error);
        assert!(recent.content.contains("Open Weights Pilgrim"));

        let session = tool.call(
            &ctx(&paths),
            json!({"action": "session", "session_id": "s1"}),
        );
        assert!(!session.is_error);
        assert!(
            session.content.contains("Session s1"),
            "{}",
            session.content
        );
        assert!(
            session.content.contains("Open Weights Pilgrim"),
            "{}",
            session.content
        );
        let missing = tool.call(
            &ctx(&paths),
            json!({"action": "session", "session_id": "nope"}),
        );
        assert!(missing.content.contains("No session"));
        let bogus = tool.call(&ctx(&paths), json!({"action": "nope"}));
        assert!(bogus.is_error);
        let forced = tool.call(&ctx(&paths), json!({"force": true}));
        assert!(!forced.is_error);
        assert!(
            forced.content.contains("reused"),
            "force rescans: {}",
            forced.content
        );

        let slash = slash(&cfg, &paths);
        assert!(slash
            .commands()
            .iter()
            .any(|(name, _)| name == "achievements"));
        let sc = slash_ctx(&paths);
        let reply = slash
            .run(&sc, "achievements", "")
            .expect("registered command")
            .expect("ok");
        assert!(reply.text.unwrap().contains("Achievements:"));
        let reply = slash
            .run(&sc, "achievements", "session s1")
            .unwrap()
            .unwrap();
        assert!(reply.text.unwrap().contains("Session s1"));
        let reply = slash.run(&sc, "achievements", "reset").unwrap().unwrap();
        assert!(reply.text.unwrap().contains("reset"));
        assert!(slash.run(&sc, "other", "").is_none());
    }
}
