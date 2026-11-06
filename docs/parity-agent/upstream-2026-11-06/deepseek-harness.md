# DeepSeek Harness (dsh) vs SE Agent: gap inventory

Upstream: `deepseek-harness` at `fcc0ad4621` (2026-11-04, release dsh 0.2.2-rc.1). Ours: this repository (branch `agent-parity-and-security`).
Method: read upstream docs and package READMEs, grepped our `crates/`, `share/` and `docs/`. No upstream code was run, built or imported. Line numbers are approximate pointers.

**License:** the root `LICENSE` is MIT, "Copyright (c) 2026 DeepSeek". All 370 `packages/*/*/package.json` files say `"license": "MIT"`. The vendored Cordis (`vendor/`) is MIT, and so is the Python SDK (`python/sdk/pyproject.toml`). Everything below that is worth porting is MIT. We would re-implement it in Rust, so the obligation is to keep the copyright notice in `THIRD_PARTY_NOTICES.md`, the same way we credit OpenClaw and Hermes.

---

## Top 10 worth doing

The first five are mostly cheap changes to how we use the DeepSeek KV cache. On DeepSeek a cache hit costs about 1/50 of a miss (`crates/seagent-model/src/modelsdb.rs:224`: 0.003 vs 0.15 per M tokens), so a bad cache policy dominates the cost of our planned benchmarks.

1. **Make the compaction summary request reuse the warm cache (High, S–M).** dsh replays the conversation's last request byte for byte: same system prompt, same tools, same messages. It then appends only the summary instruction as a trailing message, on the same provider and model. That request hits the warm prefix, so only the instruction and the summary output are paid at full price. Our `compaction.rs::summarise` instead builds a new request: a fresh `"summariser"` system segment, a rendered transcript and the aux model. That request is a full cache miss.
2. **Keep the fork subagent's prefix identical to the parent's (High, S).** A dsh fork child adds no child-only system section or tool schema. The return guidance goes in the first user task message, so the child reuses the parent's KV prefix. Our fork copies the conversation, but it first appends a `subagent` system segment, a `Tools` allow/deny event and identity/role edits (`subagents.rs` ~1297–1327). The prefix therefore differs from the system prompt onward, and the parent's cached prefix cannot be reused.
3. **Trim tool results only under context pressure (High, S).** We clip old tool results on every request (`kernel.rs:989` → `context.rs:218 trim_old_tool_results`). The clip boundary moves in steps of `keep_tool_results` (default 6), so roughly every 6 tool calls an old message is rewritten and the cache misses from that point. dsh's pruner runs only once a compaction trigger qualifies. Below pressure, history stays byte-identical. Suggestion: default to pressure-gated trimming, or make it price-aware, for routes with a cheap cache.
4. **Add a prefix-stability regression test and per-component "KV cache effect" notes (High, S).** 359 upstream READMEs have a "KV Cache effect" section that says whether the component is append-only, prefix-stable or replacing. `llm-deepseek/tests/runtime.e2e.ts` compares real cache reuse. We have no test that request N+1 keeps request N's bytes as a prefix (a grep found none). One kernel test that drives a multi-turn session and asserts the serialized prefix is preserved would protect items 1–3.
5. **Record per-step timing and cache statistics durably (High for benchmarks, M).** `experimental/client-ui-stats` shows, for each turn and step: context and output tokens, cache hit rate, time to first token, model time vs tool time, and output speed. We only have a session-level cache hit rate (`crates/seagent/src/ops/dock.rs:21`, TUI status bar). We do not record TTFT or latency per step (a grep for `first_token`/`ttft` found nothing in the kernel). Benchmark reports need this.
6. **Append system-prompt changes after the cached history (Med–High, M).** On routes that declare `systemPromptUpdate: in-history`, dsh appends a changed system prompt after the cached history instead of rewriting system node 0 (`llm-deepseek` README L53/L85, `core/agent-loop` README L122–164). We do this only for the skills-index delta (`seagent-skills/src/core/index.rs`, per-turn channel). Other prompt changes (role or mode switch, rebuilds) rewrite the head. *Whether the public `api.deepseek.com` supports this is unverified: dsh enables it only for its `deepseek-flash` catalog entry on its Messages route.*
7. **Run the whole execution environment over SSH (High for ops, L).** dsh moves filesystem, subprocess, PTY terminals, sandbox and LSP to a remote host. It uses one OpenSSH alias and an installed helper whose artifact digests are verified before use; the helper's lease cleans up remote state (`packages/ssh/*`, `docs/subsystems/ssh.md`). Our `exec/ssh.rs` spawns one process per call, tar-syncs the workspace both ways, and has no PTY (`supports_pty()` is false). Of everything here, this matters most for a system-engineering agent that operates remote servers.
8. **Make every model request reproducible from the session log (Med, M).** dsh's rule is that anything model-visible is logged. It records `request/header` and `request/context` events at series boundaries, durable `image/offload` decisions, and failed or retried `assistant/attempt` events. Our view is a pure projection of the log (`projection.rs`), but several send-time changes are not logged: `trim_old_tool_results`, the in-memory image-evict latch (`seagent-core/src/imageevict.rs`), thinking `th.apply` and the fast tier. We cannot replay the exact bytes of a past request, which makes it hard to debug a cache miss after a run.
9. **Replay recorded real sessions in tests without an API key (Med, M).** dsh records sessions against the real API, then replays the model streams from the JSONL fixtures through the shipped profiles (`test-support/llm-replay`, `session-snapshot`). A sidecar file injects faults such as stalls and retries. We use fake, oracle and scripted models (`crates/seagent/src/testkit.rs`, `ctxbench.rs`, evalkit `fake.rs`), but we cannot turn a recorded DeepSeek run into a regression fixture.
10. **Add a native DeepSeek Messages route preset (Med, S–M).** It would use `x-api-key`, effort as `output_config.effort` (off/low/high/max), a `thinking: disabled` deployment lock, reasoning passed back verbatim, a 48 h stream idle timeout (`bundle/sdk-minimal/cordis.patch.yml`), Files-API image upload with inline fallback, and optionally mid-conversation `tool_addition`/`tool_removal` blocks with `defer_loading` (beta header `mid-conversation-tool-changes-2026-07-01`). Our `deepseek` preset uses the OpenAI-chat wire (`catalog.rs:111`). *The tool-change blocks and the in-history system prompt are unverified against the public endpoint.*

Runners-up: fresh-context "Ralph" rounds for long tasks (S), a workflow-script fan-out engine (M), a minimal benchmark profile matching dsh's `sdk-minimal` (S), and a typed SDK plus a `run_code`-only mode for our code mode (M).

## Do not port (privacy, relevant to on-prem and enterprise)

These are on by default in dsh's `dsh-base` and also in `sdk-minimal`, the profile `BENCHMARK.md` points benchmarks at (`docs/deepseek-llm-api-wire-extensions.md`):
- **`dsh_session_log`:** each model request uploads the not-yet-sent part of the canonical session log (up to 8 MiB) to the configured `baseURL`. That includes the cwd, system prompts, user and assistant content, tool arguments and results, failed attempts and compaction summaries. Delivery is tracked with `session-log-deepseek/delivery-accepted` watermark events.
- **`dsh_plugin_packages`:** the active npm plugin inventory is sent with each request.
- **Headers on each request:** `x-deepseek-harness-user-id` (a stable anonymous UUID per home), `x-deepseek-harness-session-id`, and `x-deepseek-harness-compact`.
- If we run dsh as a benchmark baseline, disable `session-log-deepseek` (`enabled: false`) and the inventory contributor, or the task data leaves the machine.
- Our `[compliance] profile = "government"` refuses DeepSeek outright (`crates/seagent-kernel/src/config.rs:315–333`). DeepSeek benchmarks must run under a different profile.

---

## dsh architecture and design ideas (short)

- **Everything is a plugin, built on Cordis** (vendored, MIT). Plugins contribute services, typed events and reversible effects to a shared context. The model adapter, tool registry, session log, compaction and the agent loop itself are all replaceable plugins. A running `dsh` is a plugin tree built from layers: **profile** (`web`, `headless`, `sdk`, `sdk-minimal`, `acp`) → ordered **bundles** (`dsh-base` …) → user `cordis.patch.yml` → `--patch` overlays. You can see the tree with `dsh --profile web --dump-config`. HMR reloads config and plugins live.
- **Capability seams.** Each capability has a Service Definition, a Service Provider and a Consumer. Example: the filesystem and subprocess providers share one execution environment, so swapping them for SSH moves Bash, PTY and LSP together.
- **Turn flow.** A turn is a set of steps; a step is one model request plus the tools it calls. Waterfall hooks (`agent/pre-step`, `agent/request`, `llm/stream`, `tools/pre|execute|post`) can intercept a step. Durable events (`turn/*`, `step/*`, `system/message`, `user/message`, `assistant/message|attempt`, `tool/*`) go into an append-only, versioned JSONL session log. Format migrations are adjacent `vN→vN+1` packages and never overwrite an earlier generation.
- **Model-visible means logged.** Every request must be reconstructable from the log. Plugins that change existing messages register pure projections, and a "request series" plus `request/header` marks cache-domain boundaries.
- **Cache discipline is built into the architecture.** Every component documents its KV-cache effect. Runtime context (time, AGENTS.md, tmux) is appended in history, never spliced into the head. System-prompt and tool updates can go in history. Image offload proceeds in byte or count quanta. Compaction reuses the warm prefix. Fork children inherit a byte-identical prefix.
- **Surfaces:** a Web UI (default, `127.0.0.1:3080`), an Electron desktop app, a headless one-shot runner, a JSON-RPC SDK (TypeScript and Python), and an automation-only ACP server. There is no TUI.
- **Safety:** `SAFETY.md` disclaims security outright ("must not be treated as secure or production-ready"). The sandbox covers file effects only (`read-only`, `workspace-write`, `danger-full-access`) through bwrap/Landlock, Seatbelt or Windows ACL, and reports full or partial enforcement. Approval is `ask` or `never`. Auto review is experimental. dsh has no network policy, risk tiers or audit chain. Our governance stack is far ahead of it.
- **Benchmarks:** `benchmarks/` contains UI and session **performance gates** (session open, conversation fold, terminal IO, long-session browser), not agent evals. `BENCHMARK.md` only points to the Python SDK `sdk-minimal` profile: a persistent shell, `read_image` and `working_directory`, with no file tools, skills or subagents, and `danger-full-access`.

---

## Feature table

Status key: **missing**; **partial** (with our path); **have** (with our path). "unverified" marks a claim I could not confirm from code or docs.

### A. Agent loop, context and DeepSeek KV cache

| Feature | Upstream evidence (path) | What it does | SE Agent status | Relevance | Effort |
|---|---|---|---|---|---|
| Compaction summary reuses the warm cache | `packages/compaction/compaction-basic/README.md` (KV Cache effect: "replayed system prompt, tools, and shadowed-region messages match … byte-for-byte") | Summary request = last routed request + trailing instruction, same route | **missing**: `crates/seagent-kernel/src/compaction.rs` `summarise()` uses its own system prompt, a rendered transcript and the aux model | high | S–M |
| Fork child inherits a byte-identical prefix | `packages/subagent/subagent-fork-in-process/README.md`; `.agents/notes/implemented/architecture/2026-08-10-fork-children-stay-one-shot.md` | Fork child gets no extra system section or tool schema; guidance goes in the first user task | **partial**: `crates/seagent-kernel/src/subagents.rs` ~1297–1327 (fork copies messages but appends a `subagent` system segment, a `Tools` event and identity/role edits) | high | S |
| Tool-result pruning only under pressure | `packages/compaction/compaction-tool-result-pruner/README.md` | Head/tail truncation only when a compaction trigger qualifies; full output stays in the log | **partial**: `crates/seagent-kernel/src/context.rs:218` trims on every request in steps of `keep_tool_results` (`kernel.rs:989`), which invalidates the cache every ~6 tool calls | high | S |
| Per-component KV-cache-effect contract and cache-reuse e2e | 359 READMEs with "KV Cache effect"; `packages/llm/llm-deepseek/tests/runtime.e2e.ts` (README L214) | Every component states whether it is append-only, prefix-stable or replacing; e2e measures reuse | **missing**: no prefix-stability test (grep); cache comments in `imgprep.rs`, `hooks/spill.rs`, `skills/core/index.rs` only | high | S |
| System-prompt updates in history | `packages/llm/llm-deepseek/README.md` L53, L85; `packages/core/agent-loop/README.md` L122–164 | A changed system prompt is appended after the cached history on capable routes | **partial**: skills-index delta on the per-turn channel (`crates/seagent-skills/src/core/index.rs`); other changes rewrite the system segments. Endpoint support unverified | high (DeepSeek) | M |
| Mid-conversation tool add/remove blocks (`defer_loading`) | `packages/llm/llm/README.md` L183; `llm-deepseek/README.md` L85 | `tool_addition`/`tool_removal` system blocks plus a beta header keep the tool prefix stable | **partial**: stable pinned set plus `tool_search`/`tool_describe`/`tool_call` indirection (`crates/seagent-kernel/src/toolsearch.rs`). Endpoint support unverified | med | M |
| Request series and `request/header` logging | `docs/architecture.md` (Turn flow, Session log); `packages/core/agent-loop/README.md` L95 | Logs the envelope at cache-domain boundaries; all model input can be reconstructed | **partial**: log projection is pure (`crates/seagent-kernel/src/projection.rs`) but send-time trims, image latch and thinking are not logged | med | M |
| Durable image offload in quanta | `packages/compaction/compaction-image-offload/README.md`; `llm-deepseek/README.md` L67–68, L104 | Oldest images are replaced in byte or count quanta; the decision is a durable `image/offload` event | **have (batched)**, not durable: `crates/seagent-core/src/imageevict.rs` (latch is in memory) | low–med | S |
| Token meter with deterministic replay and image pricing | `packages/llm/token-meter/README.md`; `llm-deepseek/README.md` L180 (14 px patch grid, 3:1 downsampling, 1024 cap) | Pre-request pressure and breakdown from the log, no model call | **have**: `crates/seagent/src/ops/context.rs` (breakdown), `seagent_core::estimate_tokens`; no DeepSeek visual-token formula | low | S |
| Reasoning passed back verbatim | `llm-deepseek/README.md` L176 | Every reasoned turn's chain of thought is sent back | **have**: `crates/seagent-model/src/openai_chat.rs:59–68` (`reasoning_content`) | — | — |
| Cache-hit usage mapping | `llm-deepseek/README.md` L146 | DeepSeek cache-hit metrics mapped into usage | **have**: `openai_chat.rs:194` (`prompt_cache_hit_tokens`) | — | — |
| Time context in history with elapsed time | `packages/context/time-context/README.md` | Durable clock reading plus elapsed time since the last message, at most every 10 min, appended | **partial**: start time is frozen in the system prompt (`crates/seagent-kernel/src/context.rs` ~L116) | low | S |
| Nested AGENTS.md discovered on file operations | `packages/context/agent-instructions/README.md` | Byte-budgeted global and project chains; nested files appended | **have**: `crates/seagent-kernel/src/ctxrun.rs:32`, `context.rs:12` | — | — |
| Context-overflow recovery | `docs/subsystems/compaction.md` | Compact and retry after an overflow error | **have**: `crates/seagent-kernel/src/kernel.rs:997` | — | — |
| Per-model compaction policies | `compaction-basic/README.md` L66–78 (`modelPolicies`, `headroomTokens`, `retainRatio`) | Thresholds per route | **partial**: global `[compaction]` (`crates/seagent-kernel/src/config.rs:482`) | low | S |
| LLM retry at durable step boundaries | `packages/llm/llm-retry/README.md` | Scheduled retries logged before backoff; "always" mode | **partial**: `runner.max_retries` (`config.rs:648`); failed attempts not kept as events | low | S |
| Fail-closed checkpoint before side effects | `packages/session/session-checkpoint-policy/README.md` | Durable write before a model call or tool effect; unknown outcome on crash | **have**: fsync per append (`crates/seagent-kernel/src/store.rs:46`), `recover()` of dangling calls (`kernel.rs:809`) | — | — |
| Session-format migration chain | `docs/session-format-status.md`; `packages/session/session-format-v*-to-v*` | Adjacent version migrations; never overwrite a generation | **partial**: version gate only (`store.rs:29`, `LOG_VERSION`) | low | M |

### B. Tools and execution

| Feature | Upstream evidence (path) | What it does | SE Agent status | Relevance | Effort |
|---|---|---|---|---|---|
| PTC executor ("only `run_code` callable", generated typed SDK) | `packages/core/tool-executor-ptc/README.md`; `packages/ptc-runtime/ptc-runtime-node/README.md`; `experimental/ptc-runtime-python` | Model writes TS/Python against a typed SDK of the tools; per-program call limit; vm/REPL persistence | **partial**: `crates/seagent-kernel/src/coderun.rs` (bash/python, `seagent-call`, `max_tool_calls` 50, `pykernel`); no generated typed SDK or exclusive mode | med | M |
| Workflow scripts (`agent()`, `parallel()`, `pipeline()`, `phase()`) | `packages/workflow/workflow/README.md`, `workflow-ptc` | Sandboxed JS orchestration that fans out to subagents | **partial**: `crates/seagent-app/src/surfaces/lobster.rs` (pipelines), subagent batch tasks (`subagents.rs` `TASK_DEFAULTS`), kanban swarm | med | M |
| Ralph: fresh-context rounds | `packages/experimental/tool-ralph/README.md` | Each round is a new child that sees only the previous bounded report; round cap | **partial**: goals continue in one session (`crates/seagent-kernel/src/automation.rs:415`); kanban goal mode (`kanban/dispatch.rs:349`) | med | S |
| Advisory repeat-tool reminders (3/5/8) | `packages/guard/repeat-tool-reminder/README.md` | Nudges without blocking | **partial**: hard watchdog stop (`kernel.rs:1048–1057`, `repeat_limit` 3) | low | S |
| Cooperative per-tool timeouts | `packages/guard/timeout-policy/README.md` | Tool-declared limit, clear timeout error | **have**: `timeout_secs` in exec, job, coderun | — | — |
| Read-before-write and stale-write guard | `packages/fs/fs-observation-policy/README.md` | Refuse an edit if the file was not read or changed since | **have**: `crates/seagent-tools/src/filestate.rs` | — | — |
| Persistent shell and terminals (send, signal) | `shell/tool-bash-persistent`, `experimental/tool-terminal` | Stateful shell; PTY open/send/read/signal | **have**: `crates/seagent-tools/src/exec/session.rs`, `proc.rs` (write/submit/send-keys), `terminal.rs` | — | — |
| LSP navigation | `packages/lsp/*` | Definitions, references, hover | **have**: `crates/seagent-tools/src/lsp.rs` | — | — |
| Parallel-safe batching with barriers | `core/tool-executor-native/README.md` | Overlap safe calls, keep model order | **have**: `kernel.rs:1753–1776` | — | — |
| Turn deliverables (`present`) and per-turn changed-files card | `packages/deliverables/tool-present`, `workspace-changes` | Lists files changed this turn with line counts and before/after diffs | **partial**: `verify_loop.rs` changed set, shadow-git `checkpoint.rs`, `/diff` (`crates/seagent/src/slash.rs:158`) | low | S |
| `@session` references as untrusted snapshots | `packages/context/session-reference/README.md` | Mention another session; bounded read-only snapshot with an injection warning | **partial**: `crates/seagent-kernel/src/refs.rs` (file/folder/diff/git/url only); session search tools exist | low | S |
| Session-query tools (search, trace, event read) | `experimental/tool-session-query` | Model searches and traces past session events | **have**: `session_search` (`crates/seagent-kernel/src/sqlindex.rs`, `agents.rs`) | — | — |
| tmux pane awareness | `packages/context/tmux-context/README.md` | Tells the model which tmux pane it runs in | **missing** | low | S |
| Workspace runtime-dependencies tool | `packages/skill/tool-workspace-dependencies/README.md` | Reports bundled Python/Node paths | **missing** (not needed: we have no bundled runtimes) | low | S |
| Web search via DeepSeek / Exa / Perplexity | `packages/web/web-search-*` | Search providers | **have**: `crates/seagent-tools/src/web/providers/deepseek.rs` and others | — | — |

### C. Sandboxing, safety and approvals

| Feature | Upstream evidence (path) | What it does | SE Agent status | Relevance | Effort |
|---|---|---|---|---|---|
| SSH execution environment (fs, subprocess, PTY, sandbox, LSP) | `packages/ssh/{ssh,fs-ssh,subprocess-ssh,sandbox-ssh,ssh-helper-runtime}`; `docs/subsystems/ssh.md` | Remote host is the native environment via a digest-verified helper and lease cleanup | **partial**: `crates/seagent-tools/src/exec/ssh.rs` (spawn per call, tar sync, no PTY) | high | L |
| Enforcement reported per call (full/partial) | `docs/subsystems/sandbox.md` | Callers can reject partial enforcement (old Landlock ABI) | **partial**: `landlock_abi()` (`exec/local.rs:737`), `crates/seagent-vm/src/isolation.rs` | low | S |
| Permission presets (sandbox + approval as one mode) | `packages/interaction/permission-presets/README.md` | Named modes; unmatched combinations show as `custom` | **have (CLI)**: `seagent exec-policy preset` (`docs/MANUAL.md` L212) | low | — |
| Auto review before each tool call | `packages/experimental/auto-review/README.md` | Same-model assessment; deny goes to the user | **have**: `crates/seagent-security/src/review.rs` | — | — |
| Approval audit in the session | `packages/interaction/user-approval/README.md` | Each request and outcome logged | **have** (far beyond: tiers, hardline, envelopes, audit seal): `crates/seagent-security/*` | — | — |
| Timed user questions | `packages/interaction/user-questions/README.md` (`askTimed`) | Ask, but let the agent keep working | **unverified** in ours | low | S |

### D. Subagents, teams, planning, goals

| Feature | Upstream evidence (path) | What it does | SE Agent status | Relevance | Effort |
|---|---|---|---|---|---|
| Subagent providers: spawn, fork, ACP, Claude Code, Codex, OAR, dsh-sdk process | `packages/subagent/*`, `experimental/subagent-oar` | One interface over many delegate kinds | **have**: `subagents.rs`, `crates/seagent-app/src/acp_client.rs`; separate-process child only via `workers.rs` (partial) | low | — |
| Agent team task board (CAS ownership) | `packages/team/agent-team/README.md` | Shared tasks across a subagent tree | **have**: `crates/seagent-kernel/src/kanban/`, `coord.rs` | — | — |
| Goals with round cap, CAS and blockers | `packages/goal/*` | Same-session objective; automatic continuation | **have**: `crates/seagent-kernel/src/automation.rs` (`max_rounds`, budget) | — | — |
| Plan mode | `packages/plan/plan-mode/README.md` | `/plan`, approval of the plan | **have**: `crates/seagent-kernel/src/devprompts.rs` | — | — |
| Schedule | `packages/schedule/*` | Timed or recurring prompts | **have**: `cron.rs`, `cronjob/` | — | — |

### E. Hooks, plugins, extensibility

| Feature | Upstream evidence (path) | What it does | SE Agent status | Relevance | Effort |
|---|---|---|---|---|---|
| Codex `hooks.json` bridge | `packages/experimental/hooks-codex/README.md` | Run Codex command hooks unchanged | **missing** (Claude-compatible hooks: **have**, `crates/seagent-kernel/src/hooks.rs:226`) | low | S |
| Claude Code mods bridge | `packages/experimental/claude-code-mods/README.md` | Run CC mods' hook chains and band UI | **missing** | low | M |
| Live plugin and config reload (HMR) and Plugin Manager | `packages/boot/hmr`, `boot/plugin-manager` | Enable or disable plugins without restart | **partial**: skill watcher, plugin catalog; daemon config reports `restart_required` (`docs/ARCHITECTURE.md` §7.4) | low | M |
| Creator mode (model writes and installs UI plugins) | `packages/extensions/*`, `experimental/creation-recommendations` | Runtime self-extension | **missing** (deliberately; conflicts with governance) | low | — |
| Webhook → session (signed GitHub PR review) | `experimental/webhook`, `webhook-github`; `docs/user/guide/github-review.md` | PR ready-for-review creates a read-only review session | **partial**: generic webhook channel (`crates/seagent-channel/src/webhook.rs`) | low | S |
| Forge: bind PRs to sessions | `experimental/forge-session` | Infers a session's PRs from `gh` and `git push` results | **partial**: `crates/seagent-tools/src/forge/github.rs` | low | S |

### F. UI, observability, sessions

| Feature | Upstream evidence (path) | What it does | SE Agent status | Relevance | Effort |
|---|---|---|---|---|---|
| Per-step stats (TTFT, output speed, model vs tool time, cache hit per step) | `packages/experimental/client-ui-stats/README.md` | Statistics tab per turn and step | **partial**: session-level cache hit only (`crates/seagent/src/ops/dock.rs:21`, `seagent-app/src/tui/statusbar.rs`) | high (benchmarks) | M |
| Raw session-log inspector | `experimental/session-inspector`, `inspector` | Tables of raw events and chat nodes | **partial**: transcript exports (`trajectory.rs`), `seagent session` CLI | low | S |
| Turn outline paging | `packages/session/session-turn-outline` | Whole-session outline for long histories | **unverified** | low | S |
| LiveShare (view or write tier via relay) | `experimental/liveshare` | Share a live session with forking | **partial**: read-only `crates/seagent-app/src/session_share.rs` | low | M |
| Reasoning translation | `experimental/client-ui-cot-translation` | Translate displayed chain of thought | **missing** | low | S |
| Local voice input (SenseVoice) | `experimental/speech-to-text-sensevoice` | Local speech to text for the prompt box | **partial**: STT in `crates/seagent-media` (local SenseVoice unverified) | low | M |
| OTel session and product telemetry | `packages/telemetry/otel`, `session-telemetry-otel` | OTLP export channels | **have**: audit export with OTLP (`crates/seagent-security/src/audit_export.rs`) | — | — |
| Reverse-proxy deployment (`--public-url`, trusted hosts, TLS) | `docs/user/guide/public-deployments.md` | Publish the Web UI safely | **have** (plus SAML/SCIM, RBAC): `crates/seagent-app/src/saml.rs`, `scim.rs` | — | — |

### G. Testing, benchmarks, SDK, providers

| Feature | Upstream evidence (path) | What it does | SE Agent status | Relevance | Effort |
|---|---|---|---|---|---|
| Recorded-session replay without a key | `packages/test-support/llm-replay`, `session-snapshot`; `AGENTS.md` (`test:snapshot`) | Replay recorded model streams through shipped profiles; fault sidecar | **partial**: fake/oracle/scripted models (`crates/seagent/src/testkit.rs`, `crates/seagent-kernel/src/ctxbench.rs`, evalkit `fake.rs`) | med | M |
| Scriptable Messages mock server with faults | `packages/test-support/llm-mock-server/README.md` | Stalls, malformed chunks, 429/5xx scripts | **partial (unverified)**: canned SSE in `crates/seagent-model/tests/adapters.rs` | low–med | S |
| Minimal benchmark profile | `packages/bundle/sdk-minimal/cordis.patch.yml`; `BENCHMARK.md` | Persistent shell + `read_image` + cwd only, 1M context, 48 h idle | **partial**: evals `mini` harness (`crates/seagent/src/ops/evalkit/`, `miniswe.rs`), toolsets | med | S |
| Python SDK (JSON-RPC client, runtime wheel) | `python/sdk`, `python/sdk-runtime`; `docs/user/guide/python-sdk.md` | Drive the harness from Python | **missing** (we have ARP JSON-RPC, ACP, A2A and an OpenAI-compatible API) | low–med | M |
| Performance gates | `benchmarks/*` (session-open, conversation-fold, terminal-io, …) | UI and session performance regression gates | **partial**: `ctxbench.rs` (context size only) | low | M |
| DeepSeek native Messages route | `packages/llm/llm-deepseek/README.md` L45–106 | `output_config.effort`, `thinking` lock, `x-api-key`, beta headers | **partial**: OpenAI-chat preset (`crates/seagent-model/src/catalog.rs:111`); generic Anthropic adapter | med | S |
| DeepSeek Files API for images | `llm-deepseek/README.md` L100–104 | Upload once, reference by `file_id`, singleflight, inline fallback, quota eviction | **missing** (inline base64) | low–med | M |
| DeepSeek model listing cache with client-version gate | `llm-deepseek/README.md` L124 | `/models` listing, badges, refusal | **partial**: `crates/seagent-model/src/modelsdb.rs`, `contextpin.rs` | low | S |
| DeepSeek account and balance | `packages/credentials/deepseek-account*` | Account sign-in route | **have (balance)**: `crates/seagent-model/src/accounts.rs:195` | low | — |

---

## Counts

- Rows: **67** feature rows. The Top-10 items are among these rows; the 3 anti-features are listed separately and not counted.
- By status: **missing 10**, **partial 30** (including one partial/unverified), **have 26**, **unverified 2** (`askTimed` equivalent, turn-outline paging).
- By relevance: **high 7** (all are gaps), **med 8**, **low-med 4**, **low 28**, and 20 rows marked "—" (already have, no action).
- Unverified claims: DeepSeek public-endpoint support for in-history system prompts and `tool_addition`/`defer_loading`; our `askTimed` equivalent; turn-outline paging; whether our adapter tests cover fault injection; local SenseVoice.
