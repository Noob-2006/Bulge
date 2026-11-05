---
upstream: "hermes-agent/skills/autonomous-ai-agents/hermes-agent (MIT) — adapted for ark"
name: ark-agent
description: "Run, configure and extend ark: surfaces, config, skills."
version: 1.0.0
author: ark
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [ark, setup, configuration, cli, gateway, skills, memory, providers, mcp]
    category: autonomous-ai-agents
---

# ark

ark is a self-hosted, Linux-first AI agent runtime written in Rust: one binary, few dependencies, built to keep working unattended for hours. It is the same kind of tool as Claude Code, Codex and OpenClaw — a tool-calling agent over your files and shell — and its behaviour is a parity port of Hermes (Python) and OpenClaw (TypeScript), both MIT.

What makes ark different:

- **Only two gates** — privilege (sudo, writes to system paths) and egress (secrets, personal data leaving the machine). Everything else runs without a confirmation prompt.
- **Token discipline** — progressive tool disclosure, a frozen prompt prefix that stays cacheable, automatic compaction, and oversized tool output spilled to files.
- **One protocol everywhere** — ARP (`ark/2`, JSON-RPC 2.0) over a Unix socket, WebSocket and plain HTTP; the web/desktop/PWA UI, the TUI, the ACP bridge, device nodes, A2A and the OpenAI-compatible API all speak it (`docs/arp.md`).
- **46 chat platforms** — Telegram, Discord, Slack, LINE, WhatsApp, Signal, Matrix, Teams, Feishu, DingTalk, WeCom, QQ, Email and more (`docs/parity.md`).
- **Full MCP** — stdio, Streamable HTTP, legacy SSE, OAuth 2.1 (PKCE, dynamic registration, device flow), sampling, elicitation, roots, cost caps; ark can also serve its own tools as an MCP server.

## When to Use

- The user asks what ark is, how to install or run it, or which surface to use.
- You need the right command, config key, path or file: config and secrets, providers and models, sessions, skills, memory, MCP, plugins, channels, delegation.
- You are about to claim ark cannot do something — verify against `ark help` and the tree first.

Don't use for: authoring or porting a SKILL.md (`ark-skill-authoring`), or driving another coding agent CLI (the per-agent skills).

## Scope & Verification

This is an operating guide, not the full manual. If a feature is not mentioned here, that is not evidence it does not exist — check the tree before answering negatively.

Good verification targets, cheapest first:

- `ark help` — every top-level command, plus the flags and exit codes (`0` done · `1` error · `2` usage · `3` budget/limits/stuck · `130` interrupted). The `HELP` string and the dispatch match in `crates/ark/src/main.rs` are authoritative.
- `ark commands` — custom `.ark/commands/`, plugin commands, MCP prompts and the built-in slash commands, with descriptions.
- `ark doctor` — config validity, vault state and permissions, which source each model's key comes from, external binaries, data dir, browser.
- `docs/config-example.toml` — every config key, commented.
- `ark config show` — the config as merged from the user file, the project file and `--set` overrides.

## Quick Start

```bash
cargo build --release
install -m 755 target/release/ark ~/.local/bin/ark

ark setup                        # wizard: provider, key, model, web UI, chat platform
ark run "list the TODOs in this folder"   # one task, to completion (`-` reads stdin)
ark chat                         # line-based conversation; /help lists slash commands
```

`ark setup` writes `~/.config/ark/config.toml`. To skip the wizard: `ark secrets set ANTHROPIC_API_KEY` (or OPENAI / DEEPSEEK / …) and run with the default model.

Long-running service and other surfaces:

```bash
ark daemon start                 # background: schedules, goals, channels, app server
ark daemon status                # is it answering?
ark service install              # start at login (systemd user unit; --launchd on macOS)
ark tui                          # terminal UI
ark app token                    # print the app-server bearer token (or how to make one)
ark app open                     # open the web UI in a browser app window
```

## Key Paths

```
~/.config/ark/config.toml        settings — never secrets
~/.config/ark/secrets.toml       secret vault, written 0600 by `ark secrets set`
<data>/sessions/                 session journal + projection (~/.local/share/ark/sessions)
<data>/memory/MEMORY.md          the agent's own notes (USER.md: facts about you)
<data>/skills/                   user, agent-created and hub-installed skills
<data>/arkd.log                  daemon log
$XDG_RUNTIME_DIR/ark/arkd.sock   daemon socket (CLI, TUI, local scripts)
share/skills/<category>/<name>/SKILL.md   bundled skills (this tree)
```

`<data>` honours `$XDG_DATA_HOME`, `~/.config` honours `$XDG_CONFIG_HOME`, and `ARK_HOME` relocates all of it (`<ARK_HOME>/data`, `<ARK_HOME>/config`, `<ARK_HOME>/run`). Use `ark config path` to print the resolved paths instead of guessing.

## Configuration & Secrets

- Settings live in `~/.config/ark/config.toml`; a project may add `.ark/config.toml`, but `hooks`, `mcp`, `plugins`, `channels`, `providers` and `app` from a project file only apply when the directory is listed in `trusted_projects`.
- Secrets live in the vault (`ark secrets set NAME`, value read from stdin and never from argv). Reference them from config as `{{secret:NAME}}`: the value is substituted at execution time, never enters the model context, and is redacted back to the placeholder in tool output.
- `[gate]` is the two-gate policy: `privilege` and `egress` are `ask | deny | allow`, with `egress_allow` / `egress_deny` host lists. Per-process escapes are `--allow-privilege`, `--allow-egress`, `--yes` and `--yolo`; hardline floors and `[approvals] deny` globs still apply under `--yolo`.
- Read it back with `ark config get gate.egress`, check a file with `ark config validate`.

## Providers & Models

- `[model] default = "provider/model"`, plus `fallback = [...]` and `aux` (the cheap model used for compaction, titles and MCP sampling).
- `ark model` picks or sets the default interactively; `ark models list` lists what is known; `ark providers check` sends a live one-token request to prove the credential works (it costs a call).
- Account logins (`ark login <flow>`, ids such as `openai-codex`, `anthropic`, `github-copilot`, `qwen`) and key pools (`ark auth add`) are separate from the vault: `ark auth status`, `ark fallback list`.
- `ark usage` shows tokens and cost per model; `ark insights` summarises sessions, tools, skills and models.

## Surfaces

- **CLI** — `ark run`, `ark chat`, `ark session …`, `ark send` / `ark attach` / `ark interrupt` against a daemon-hosted session.
- **TUI** — `ark tui`.
- **Web app / PWA** — served by the daemon's app server when `[app] enabled = true`, on `[app] listen` (default `127.0.0.1:8640`), bearer-token protected; installable as a desktop or phone app.
- **ACP** — `ark acp` is an Agent Client Protocol agent on stdio for editors:

  ```json
  { "agent_servers": { "ark": { "command": "ark", "args": ["acp"] } } }
  ```

- **OpenAI-compatible API** — same port: `/v1/models`, `/v1/chat/completions`, `/v1/responses`:

  ```bash
  curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8640/v1/chat/completions \
    -d '{"model":"ark","messages":[{"role":"user","content":"hi"}]}'
  ```

- **Channels** — `[channels.<name>] kind = "telegram"` … in config; `ark channel list` shows policy per channel, `ark channel send <channel> <chat> <text…>` sends. Strangers are refused by default; `dm_policy = "pairing"` gives them a one-time code and `ark pairing approve <channel> <code>` lets them in.
- **Devices** — `ark node --url ws://host:8640/node` runs another machine as a node; approve it on the host with `ark nodes approve <code>`. What a node may run is decided by its own `~/.config/ark/node.toml`.

## Sessions & Context

- `ark session list`, `show <id>`, `resume <id>`, `fork <id>`, `search <query>`, `model <id> <provider/model>`, `rm <id>`.
- Compaction is automatic near the context limit and can be forced: `ark session compact <id>`, or `/compact` in any chat surface (`/compact here 5` keeps the last five exchanges verbatim). Old tool output is pruned before summarisation; `[compaction] threshold`, `prune_threshold`, `keep_tool_results`, `keep_messages` tune it, and `aux` decides how cheap the summary is.
- The skills and memory blocks of the prompt are frozen for cache reasons; a skill installed mid-session is announced by a per-turn delta note instead of a prompt rebuild, so it is usable immediately.
- `ark checkpoint list` / `ark checkpoint restore <id>` roll file edits back.

## Skills

```bash
ark skills list                  # what is loadable, with source and readiness
ark skills view <name>           # frontmatter + body
ark skills search "pdf"          # hub registries
ark skills install <identifier>  # e.g. official/<category>/<name>
ark skills check                 # status of hub-installed skills
ark skills lint <name|path>      # authoring rules (see ark-skill-authoring)
ark skills sync                  # copy bundled skills into <data>/skills, keeping your edits
```

Catalogue: `ark skills audit`, `ark skills update`, `ark skills uninstall`, `ark skills tap add <owner/repo>`, `ark skills ledger`. Inside a session, `/skills <subcommand>` reaches the same command set and `/<skill-name>` loads a skill into the current turn. A skill whose name collides with a built-in slash command is not reachable as `/<name>` (`core/slash.rs` keeps a `RESERVED` list); load it with the `skill` tool (`action=view`) or by reading the `SKILL.md` path printed in the prompt's skill index.

## Memory

The `memory` tool persists across sessions in `<data>/memory/MEMORY.md` (agent notes) and `USER.md` (facts about the user); both are injected into every future session, so keep them small. Actions: `read`, `add`, `patch`, `replace`, `remove`, and batched `operations`. From a shell: `ark memory show`, `ark memory add "<text>" [--user]`, and the review queue `ark memory review` / `accept` / `reject`.

## MCP & Plugins

- `ark mcp list`, `ark mcp tools [server]`, `ark mcp test <server>`, `ark mcp add <name> -- <cmd> …`, `ark mcp add <name> --url <url>`, `ark mcp login <server>` for OAuth (add `--device` on a headless host, `--no-browser` to skip the auto-open), `ark mcp serve` to expose ark's tools to another agent.
- `ark mcp presets [query]` / `presets show <preset>` install a known-good server config.
- Plugins are separate processes speaking an MCP superset over stdio (`docs/plugins.md`): tools, hooks, channels, commands, CLI, routes, UI, providers, services. `ark plugin list` shows what each one provides; plugin CLI commands appear in `ark help`.

## Delegation & Orchestration

- **`spawn` tool** — a sub-agent for a self-contained task, returning only its final answer: `task` (a complete brief), optional `model`, `fork` (inherit this conversation), `tools` (restrict its toolset), `worktree` (isolated git worktree, work kept on a branch). Cheap, bounded by the parent's loop.
- **`ark acp-client <agent> <prompt…|->`** — drive an external ACP agent (claude, codex, gemini, opencode) from ark; `--cwd`, `--permission-mode approve-all|approve-reads|deny-all`, `--session`, `--list`, `--json`.
- **Full processes** — `ark run "<task>"` or `ark chat` in a background job for missions that outlive one agent loop; `ark chat` is line-based, so a plain pipe works and a PTY is not required. Resume with `ark session resume <id>`, steer a daemon-hosted session with `ark send <id> <text>`, watch it with `ark attach <id>`.
- **Scheduled work** — `ark schedule add "<cron>" "<prompt>"` and `ark goal add "<objective>" --rounds N` belong to the daemon; prefer them over a sleeping subprocess.

## Where to Look

| Question | Read |
|---|---|
| Any command, flag, exit code | `ark help`, `crates/ark/src/main.rs` |
| Slash commands in chat/TUI/channels | `ark commands`, `crates/ark/src/slash.rs` |
| Config keys and defaults | `docs/config-example.toml`, `ark config show` |
| Protocol, transports, methods, events | `docs/arp.md` |
| Channel setup, policies, pairing | `docs/channel-guide.md`, `docs/parity.md` |
| Plugins, hooks, plugin UI/CLI | `docs/plugins.md` |
| Skill model, hub, linter | `crates/ark-skills/src`, `docs/parity.md` |
| Compliance knobs (retention, notices, labels) | `docs/compliance-tw.md` |

## Hard Invariants

- **Never break prompt caching** — do not rewrite past context or the system prompt mid-session; the only sanctioned rewrite is compaction.
- **Two gates, not many** — do not add ad-hoc "are you sure?" steps; if a command needs root or sends data out, it hits privilege or egress.
- **Secrets stay in the vault** — reference `{{secret:NAME}}`; never paste a value into config, a prompt, or a log.
- **Settings go in config.toml** — never tell a user to put a non-credential setting in the vault.
- **Verify, do not assume** — `ark help`, `ark commands`, `ark config show` and the source tree outrank this file.

## Adaptation note

This skill is adapted from Hermes' `hermes-agent` skill (MIT). Upstream's 17 `references/*.md` files and 3 `templates/*` files are Hermes-product-specific (themes and skins, petdex mascots, desktop Electron plugins, TUI widgets) and were deliberately not transcribed: ark has no equivalent surfaces, so those files would only document features that do not exist here. Every ark-side fact above comes from this repository — `README.md`, `crates/ark/src/main.rs`, `crates/ark/src/slash.rs`, `crates/ark-skills/src`, and `docs/*.md`; commands were checked against the dispatch table rather than carried over from upstream. Hermes features with no ark equivalent (themes/skins, desktop UI plugins, TUI widget apps, pet mascots, the Electron desktop app — ark ships a web/PWA UI instead) are simply absent here. For authoring skills in this tree, load `ark-skill-authoring`.
