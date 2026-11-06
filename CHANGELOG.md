# Changelog

All notable changes to SE Agent are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Security fixes are marked **Security**.

## [Unreleased] — 0.1.0

First public release candidate.

### Added
- Agent kernel: one-shot runs, interactive chat, background daemon (`seagentd`), sessions with
  branching and search, cron schedules, long-running goals, heartbeat, sub-agent fleet.
- Two gates (privilege, data egress) and a four-tier risk model with task envelopes, scoped and
  time-limited grants, hard limits that cannot be disabled, dual-control approvals.
- Isolation: microVMs (Firecracker / QEMU), gVisor, containers, bwrap / Landlock; a graphical
  desktop VM driven by computer use, with the agent's browser running inside it and human
  takeover from the web console.
- Web console for operations: devices, agents, approvals, audit (CSV / HTML export), workspace
  pane with live browser and desktop views.
- 46 chat channels, MCP client and server, ACP, A2A, OpenAI-compatible API, nodes.
- Enterprise: OIDC / SAML login, roles, managed policy files, audit forwarding, change-control
  integration, offline install bundle.
- Packages: one-command installer, deb, rpm, pacman (AUR `seagent-bin`), apk (OpenRC), npm
  wrapper, Nix flake, containers, Helm, Ansible.
- Documentation: install guide with troubleshooting, FAQ, security policy, contribution guide.

Upstream sync (OpenClaw `8a186ad`, Hermes `90d6b98`, DeepSeek Harness `fcc0ad4`; gap reports in
`docs/parity-agent/upstream-2026-11-06/`):

- Approvals: `[tools.by_provider."<provider or provider/model>".exec]` restrict-only exec ceilings
  (`mode = deny|allowlist|ask|auto|full`, or `security`/`ask`) that `/yolo` and `/elevated` cannot
  lift; `seagent tools explain <tool> [--model M] [--channel C] [--sender S]` names the blocking
  policy layer and the key to change; silent auto-approvals append an
  `[approval] auto-approved: allow (<source>) — <reason>` line to the tool result.
- Web console: Approvals page lists standing grants (revocable), edits the global exec policy and
  shows each agent's effective policy; new Security page with listeners, exposure findings,
  token metadata, channels and agent capabilities.
- Prompt cache: optional `[model] system_updates = "in_history"` and `[model] log_requests = true`
  (exact request bytes as `Request` events); per-step TTFT, output speed, model/tool time and cache
  hit rate in `seagent session stats --session <id>`; `/context` labels a defaulted window
  `(fallback)`; compaction summaries keep an `Unverified / Working Hypotheses` section.
- Sub-agents: fork children reuse the parent's system prompt, tools and route (tool limits enforced
  at execution); `[delegation] prefix_stagger_seconds` batch warm-up; hop-capped `agent_message`
  chains (`[delegation] max_hops`, `[gateway.bot_loop_guard] max_hops`, default 4) with duplicate-ask
  refusal and notify-only replies; `ralph` tool for fresh-context rounds
  (`ralph_max_rounds`, `ralph_max_handoff_chars`).
- Hosted rooms: `--purpose`, `--notes`, `--routing everyone|lead|auto`, `--lead`, `rooms update`,
  `rooms continue` (up to 5 extra budgets per discussion).
- Providers: opt-in `deepseek-messages` preset (aliases `deepseek-anthropic`, `deepseek-native`);
  `[decision] backend = "rerank"` for any `/rerank` endpoint; Bedrock ambient AWS credentials
  (env, web identity, shared profile / `credential_process`, ECS, EC2 IMDSv2) and on-demand /
  inference-profile discovery; Gemini service tiers; opt-in `[model] daybreak` on `openai-codex`;
  `qoder` ACP client preset; missing-key errors name the variable and `seagent secrets set`.
- Automation: `[automation] default_deliver`, `default_failure_deliver`, `agent`,
  `[automation.agents.<id>]` and `[automation.creators.<profile>]` delivery defaults; cron
  `deliver = "room:<room-id>"`; `restart_hold_seconds` restores interrupted one-shot claims;
  `scratch_ttl_hours` (24), `worktree_idle_hours` (168), `cleanup_interval_secs`;
  `idle_session_secs` (1800) retires idle session state in `seagentd`; opt-in
  `plugin_auto_update_hours` (0 = off); `run.stopped` audit event and `run_stopped` hook naming who
  stopped a run; `seagent_busy_*` metrics; admin-scope ARP `tools.call` that runs one tool through
  the normal policy, approval and audit path.
- Memory and skills: `deep_research` tool (bounded, quote-verified, no function calling);
  `[memory.recall_gate]` (`off|shadow|live`); `[memory.wiki]` per-store ACLs, page history and
  supersede chains (`wiki_history`, `seagent wiki history`, `--store`); `[memory.standing]` with
  `seagent memory intents`; `seagent skills lock|unlock`; `[skills.workshop] mode = off|propose|auto`
  with `/skills drafts`; `seagent curator diet [--apply]`;
  `[memory.search.embedding] allow_private` (default true) for Ollama endpoints.
- Channels: `ask_user` multiple-choice `options` (buttons where supported, numbered list otherwise);
  `/fork [title]` in a channel opens a sibling thread or topic; terminal `/handoff <channel>[:<chat>]`.
- Terminal: `/undo` lists the files changed since the restoring checkpoint; Esc Esc rewind picker in
  `seagent tui`; inline images (kitty, iTerm2/WezTerm); large pastes collapse (Ctrl+E expands);
  `/new` during a turn keeps the old turn running in the background.
- Tools and testing: `edit` recovers an `old_string` pasted with `read`'s line-number gutter;
  persistent remote shell over the SSH ControlMaster for internal sync scripts (first slice);
  `SEAGENT_MODEL_RECORD` / `SEAGENT_MODEL_REPLAY` keyless provider record/replay; `benchmark` tool
  profile and `seagent evals bench --tool-profile`; `[exec.code] run_code_only`; node.toml
  `[mcp.<server>]` exposes node-hosted MCP tools as node commands (first slice).

### Changed
- The project was renamed from `ark` to SE Agent (`seagent`). `ARK_*` variables, per-user `ark`
  directories, project `.ark/` directories and vault keys stored under the old names keep
  working; the `seagent` package replaces `ark-agent`.
- `seagent migrate` no longer imports credentials by default. Each skipped credential is named;
  pass `--migrate-secrets` for the previous behaviour. The terminal setup wizard asks about
  credentials separately, defaulting to no.
- Old tool results are now trimmed only under context pressure (`[compaction] prune_threshold`);
  set `[compaction] trim_tool_results = "always"` for the previous per-request trimming.
- Compaction summaries use the conversation's own model and replay its cached prefix. `[model] aux`
  no longer takes over compaction; set `[model.tasks] compaction` (or `[auxiliary.compaction]`)
  to use a cheaper model.
- A turn the provider refused on safety grounds stays in the transcript but is no longer sent in
  later requests.
- The bundled `productivity/notion` and `productivity/airtable` skills were removed, as upstream
  did; use the vendors' MCP servers instead.
- `[browser] allow_private_urls = false` is now strict for local browsers too.
- `seagent plugins update` no longer silently accepts a `caution` scan verdict.
- Microsoft Teams proactive conversations use the configured `tenant` before one learned from an
  inbound activity; Slack `list-pins` honours `limit`.

### Security
- A human takeover now stops every browser tool, not only those on the bot desktop.
- Session names longer than 48 characters can no longer map two sessions to one sandbox.
- API keys with control or non-ASCII characters (for example a terminal paste escape) are
  rejected when stored instead of being sent in request headers.
- `test` and `[` are no longer blanket-safe builtins: `-v`/`-R`, `$'…'` quoting and operands with
  `` \ $ ` * ? { } [ ] `` need normal approval (bash evaluates `test -v 'a[$(cmd)]'`).
- Uploading `.env` or `secrets.toml` is classified as tier-3 credential exfiltration; a command
  allowlist entry no longer covers a separate egress or privilege finding in the same command.
- PowerShell / `cmd` deletes, `wmic shadowcopy delete` and forced `Stop-Process` / `Stop-Service`
  are tier 3.
- Channel HTTP follows redirects by hand and checks every hop: only the configured origin may be
  private, cloud metadata is always refused, cross-origin hops drop credentials, and attachment
  downloads are public-only. Feishu card actions from an unknown chat are refused.
- Browser: `open`/`navigate` fence each redirect hop before the request under strict policy
  (Camofox refuses strict http(s) navigation); snapshots mask password, one-time-code and card
  fields.
- Wider secret masking (database connection strings, URL userinfo, `PGPASSWORD`-style variables,
  PGP / PuTTY / age keys, Azure keys, quoted YAML/JSON secrets, `--password`-style flags).
- Config writes (`config set`, `config patch`, console) refuse redaction placeholders such as
  `***` or `[REDACTED …]`.
- Per-skill locks block every agent write path, including shell writes and `seagent skills unlock`
  from the agent's shell.
- `seagent mcp add … -- <command>` prints a consent line with argv, env names and cwd; secret values
  are masked and bidi / zero-width characters escaped.
- Installers run with `umask go-w`, so installed files are never group- or world-writable.
- Read-only ARP callers (`scope:read`, `auditor`) no longer receive host workspace paths in
  session, schedule and goal listings.
- Checkpoints refuse `/`, `$HOME` and its parents, browser profiles and the checkpoint store, and a
  rollback never rewinds the store; xAI OAuth requires a usable token lifetime.
