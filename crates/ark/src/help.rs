//! The top-level `ark --help` text (kept apart so main.rs stays a dispatcher).

pub const HELP: &str = "ark — autonomous agent kernel

USAGE
  ark setup                            first-run wizard: provider, key, model, chat platform, owner, systemd service
  ark setup --provider P --model M [--channel telegram|discord --owner ID] [--no-service] [--no-linger]   unattended (ARK_SETUP_* env; secrets via env only)
  ark role list|use|show|verify|diff   professional role: ISCO occupation or preset (devops, swdev, secops, data, itsupport)
  ark run [opts] <prompt…|->           run one task to completion (reads stdin with -)
  ark chat [opts]                      line-based conversation (/help inside)
  ark session list|show|resume|fork|search|compact|model|rm …
  ark session export [id…] [--format md|qmd|html|json] [--out FILE|DIR/] [--no-redact]
  ark session trajectory [id] [--format sharegpt|bundle] [--out PATH] | verify-export <file> [id]
  ark session upload-trace [id] [--dataset NAME] [--public] [--no-redact]   (token: ark secrets set HF_TOKEN)
  ark daemon start|stop|status|run|install
  ark send <session> <text…>           queue input on a daemon-hosted session (starts it)
  ark attach <session> [--from N]      follow a daemon-hosted session live
  ark interrupt <session>              stop a running session
  ark gate list | answer <id> once|session|permanent|deny [reason…]
  ark schedule add <cron> <prompt…> [--reuse] | list | rm|enable|disable|run <id>
  ark goal add <objective…> [--rounds N] | list | show|run|pause|resume|cancel <id> | subgoal <id> [text|remove N|clear]
  ark system event --text <t> [--mode now|next-heartbeat] | heartbeat last|enable|disable | presence
  ark suggestions [accept N | dismiss N | catalog | clear]   suggested automations
  ark web providers [--json] | test <query> [--count N] [--json] | fetch <url> [--text] [--json]   web search providers, route, one fetch
  ark memory show | add <text…> [--user] | review | accept <n|all> | reject <n|all>
  ark index status | sync | rebuild | bench <session>   SQLite index (session FTS, memories, retrieval); rebuildable from the logs
  ark checkpoint list | restore <id> | status | prune [--retention-days N] [--max-size-mb N] [--keep-orphans] [--force] | clear [--force]
  ark sandbox list [--json] | recreate (--all|--session ID|--agent DIR) [--force] | explain [--session ID] [--json]
  ark config path|show|init|get <key>|validate
  ark secrets set <NAME> | list | rm <NAME> | backend | migrate   (value read from stdin, never argv)
  ark providers list | check [provider/model]
  ark mcp presets [query] | presets show <preset> | add <name> --preset <preset> [--env K=V]
  ark model [provider/model]           pick / set the default model (interactive without args)
  ark models status|list [provider]|providers|set <p/m> [--as aux]|aliases add|rm|fallbacks|refresh|pricing <p/m>
  ark login <provider> [--no-browser] [--import] | logout <provider>   account logins (ChatGPT, Claude, Copilot…)
  ark auth add <provider> [--label L] [--priority N] | list | remove | reset | priority | strategy | refresh | status
  ark fallback list | add <p/m> | remove <p/m|n> | clear
  ark usage [--days N] [--session ID] [--account] [--billing] [--json]   tokens and cost per model; --billing: what the provider billed (admin key)
  ark insights [--days N]              sessions, tools, skills, models, sources
  ark mcp list | tools [server] | test <server> | refresh <server> | add <name> (--url U | -- cmd args…) | rm <name> | serve [--relay URL [--pair]] | pins [list|diff|accept|forget <server>]
  ark plugin list                      plugins and what they provide (tools, hooks, channels,
                                       commands, CLI, routes, UI, providers, services…)
  ark <plugin-command> [args…]         a CLI command a plugin adds (listed by `ark help`)
  ark channel list | send <channel> <chat> <text…>
  ark message send|edit|delete|react|poll|pin|thread|read --channel <n> --chat <id> [--thread T]
              [--text …] [--message-id …] [--poll 'question=… options=a,b'] [--json]
                                       message actions (same dispatcher as the `message` tool)
  ark webhook list <channel> | subscribe <channel> <route> [json] | rm <channel> <route> | test <channel> <route> [--payload JSON]
  ark hooks list | test <event> | approve <cmd>|--all | revoke <cmd> | doctor | info|enable|disable <name> | check | install <dir> [--link]
  ark meet <join URL|status|transcript|say TEXT|stop|setup|auth> [--json]   Google Meet bot (captions → transcript)
  ark teams list|show|run|fetch|subscriptions|subscribe|renew-subscription|delete-subscription|maintain-subscriptions|token-health|validate
                                       Microsoft Teams meeting pipeline (Graph transcripts → summaries)
  ark kanban <init|boards|create|list|show|…> [--board <slug>]   multi-agent board (dispatch, stats, log)
  ark worktree list|add|rm|prune|restore   git worktrees for parallel sessions (`/worktree` in chat)
  ark acp                              ACP agent on stdio (for Zed, JetBrains, Neovim…)
  ark acp-client <agent> <prompt…|->   drive an external ACP agent (claude, codex, gemini, opencode…)
                                       [--cwd DIR] [--permission-mode approve-all|approve-reads|deny-all]
                                       [--session ID] [--list] [--json]
  ark commands                         custom /commands, plugin commands and MCP prompts
  ark init [notes…]                    generate or update AGENTS.md from a repo scan
  ark plan <task…>                     write an implementation plan to .ark/plans/ (no execution)
  ark verify [dir] [--detect-only] [--save] [--phase P]… [--skip-start] [--port N] [--timeout S] [--ready-timeout S] [--json]
  ark lsp status|list [--installed-only]|which <server>|check <file>|restart
  ark node --url ws://host:8640/node | --setup-code CODE   run this machine as a device node
  ark nodes list|pending|approve|reject|remove|rename|describe|invoke|queue|events|rotate|setup-code
  ark data export|delete <channel> <sender|chat>
  ark call <tool> [json]               call a tool from inside the `run` tool (alias: ark-call)
  ark status [--full|--all] [--deep] [--json] | sessions | health   what this install is doing, component by component
  ark telemetry status|test [--endpoint URL] [--json]   gateway monitoring: OTLP export posture + one probe span
  ark evals list|run [ID…] [--filter S] [--json] [--verbose]   in-process runtime evals (hermetic, no network/keys)
  ark evals bench|roles|fetch|import|report|compare|collect|swe-score|suites|agents   scored evaluations: benchmarks (SWE-bench, Terminal-Bench, GAIA, OSWorld), model matrix, judge, role scenarios, other agents side by side (docs/evals.md)
  ark distill research|abstract|check|eval|sign|run|team|purge   occupation guidelines from documented practice (docs/evals.md)
  ark tools list|enable|disable [NAME…] [--platform P] | --summary | post-setup KEY [--dry-run]   per-platform tools, backend install hooks
  ark fleet [status|board|files|limits|resume SESSION] [--json]   multi-agent progress: agents, files held, spend, shared board, pauses
  ark docker check [--file Dockerfile] [--json]   lint the container files (multi-stage, USER, HEALTHCHECK, secrets)
  ark doctor | version | help
  ark browser close-profile [--browser NAME] | status | install [--url ZIP] | extension
  ark screen status|start|stop|install [-y]   the headless Bot Desktop screen (Xfce + VNC)
  ark computer-use install|status|doctor|permissions <status|grant>   the cua-driver desktop backend
  ark infer <domain> <action> [--json]  capability CLI: image/audio/tts/video/music list|inspect|generate|…
  ark voice [--continuous|--wake|--no-speak|--no-barge-in|--session ID]|status|live
  ark stt <audio file> [--json]        transcribe one file with the configured provider
  ark transcripts list                 the local transcript store

OPTIONS
  -m, --model provider/model   -w, --workspace DIR      -s, --session ID
  --set key=value (repeatable) --budget-tokens N        --budget-usd X
  --max-steps N                --yes (approve gate prompts)
  --allow-privilege            --allow-egress           --json   -q, --quiet
  --yolo (run/chat/daemon/tui/acp: skip approval prompts for this process; hardline floors
         and deny rules still apply; also ARK_YOLO=1)

EXIT CODES  0 done · 1 error · 2 usage · 3 budget/limits/stuck · 130 interrupted";
