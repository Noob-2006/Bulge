# Changelog

All notable changes to SE Agent are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Security fixes are marked **Security**.

## [0.2.0-alpha] — 2026-11-13

First alpha of the cross-platform release: one code base for Windows, macOS, Linux, Android and
iOS, with double-click installers and a built-in VM. Feature-complete for daily use; config keys,
command names and the console may still change before 0.2.0. Installers are not code-signed yet.
Platform status (real-device vs build-only) is in the README.

### Added
- **Native Windows** (10 1809+ / 11, x64): per-user `setup.exe` and per-language `.msi`
  (en-US, zh-TW, zh-CN); the shell tool and AppContainer sandbox speak PowerShell (Git Bash when
  present), ConPTY terminals, Job Object process trees, DPAPI / Credential Manager secrets,
  named-pipe IPC, no console window flashes.
- **Built-in VM in every desktop installer**: the reproducible microVM guest image plus the host's
  hypervisor (Windows: QEMU + WHPX, with Hyper-V / VirtualBox fallbacks; Linux: Firecracker;
  macOS: vfkit). `seagent sandbox vm exec -- <cmd>`; `seagent doctor` names the VM provider and
  accelerator; a fallback to a weaker isolation level is never silent.
- **Desktop VM on Windows** with only the bundled QEMU (WHPX): `qemu-img` and the VGA / NIC
  firmware ship in the installer, QMP and the text channel over loopback TCP, no VNC.
- **Virtual display driver** (Windows, optional at install, one UAC prompt): the Bot Desktop
  streams native apps at 30–60 fps; kept across updates.
- **Bot Desktop substitutes**: an isolated `CreateDesktopW` desktop on Windows, the login session on
  macOS; `launch_app` by name (App Execution Aliases on Windows).
- **Live view** of the agent's browser, desktops, desktop VM and terminal in the console: 30 fps
  JPEG 85 at device pixels by default, up to 60 fps, adaptive; patch mode for Chromium / Electron
  apps; Windows.Graphics.Capture and PrintWindow on Windows.
- **macOS**: LaunchAgent service, Seatbelt sandbox, Keychain, pinned Chrome for Testing.
- **Android** (8.0+, arm64): the agent under a Foreground Service, or connect to a computer.
- **iOS**: the full agent runs inside the app process (`seagent::embed`); commands run in an
  in-process WebAssembly sandbox (wasmi + POSIX shell + pinned WASI coreutils, CPython, grep, sed,
  find, xargs); cron / heartbeat through BGProcessingTask.
- **LAN pairing**: Bonjour / NSD discovery, QR or 8-character code, pinned TLS.
- Console: stays signed in silently (device-bound credentials, endless renewal), Settings →
  Connections for every connector, per-tool-call log with a Logs page and `seagent logs
  tools|export`, chat conversation menu, per-chat settings, API keys page, galaxy theme.
- `[desktop_vm] apt_mirror = "auto"`: provisioning measures deb.debian.org, NYCU and several
  country mirrors and uses the fastest (apt still verifies the signed archive).
- `[desktop_vm] timezone = "host"`: the desktop VM's clock follows the host's time zone at every
  boot (IANA name from `TZ` / `/etc/localtime`, or the Windows zone mapped through CLDR); `""`
  keeps UTC, or name a zone.

### Changed
- **License: Apache-2.0** (was MIT). `LICENSE` is the Apache License 2.0 text, a `NOTICE` file
  names the holders; code ported from OpenClaw, Hermes Agent and DeepSeek Harness stays MIT with
  its notices in `THIRD_PARTY_NOTICES.md` (`REUSE.toml`: `Apache-2.0 AND MIT`). The repository
  moved to https://github.com/Noob-2006/SE-Agent.
- Version 0.2.0-alpha. MSI and Android need numeric versions: the MSI is `0.2.0`, Android
  `versionCode` 2000; `ci-config.py` derives both from a `v0.2.0-alpha` tag.
- Desktop VM base image downloads resume with HTTP Range after a dropped connection (and across
  runs); `image_url` accepts Windows paths (`C:\…`, `file:///C:/…`).
- The desktop VM provisioning script changed (mirror, tzdata, time zone): existing images are
  rebuilt on the next `seagent vm desktop build`; `reset` moves a VM onto the new image.
- deb / rpm desktop packages recommend QEMU for the desktop VM; on Linux and macOS a missing QEMU
  names the install command for the host, and Homebrew / MacPorts prefixes are searched even when
  a GUI app's PATH leaves them out.
- The setup wizard picks the default model from the provider's real model list; the daemon comes
  back after setup on Windows.

### Fixed
- Windows desktop VM could not be built (`qemu-img` missing) or started (`-vnc none` needed a
  keymap file the bundle does not ship).
- The fastest apt mirror was ignored: Debian cloud images name the archive in
  `/etc/apt/mirrors/debian.list`.
- `seagent secrets set` kept a PowerShell BOM as part of the secret.
- MSI: the driver step and the launch checkbox run; no install over an existing `setup.exe`.

## [0.1.0] — 2026-11-06 (not published)

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
