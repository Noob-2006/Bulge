//! The top-level `seagent --help` text (kept apart so main.rs stays a dispatcher).

pub const HELP: &str = "seagent — autonomous agent kernel

USAGE
  seagent setup                            first-run wizard: provider, key, model, chat platform, owner, systemd service
  seagent setup --provider P --model M [--channel telegram|discord --owner ID] [--no-service] [--no-linger]   unattended (SEAGENT_SETUP_* env; secrets via env only)
  seagent role list|use|show|verify|diff   professional role: ISCO occupation or preset (devops, swdev, secops, data, itsupport)
  seagent run [opts] <prompt…|->           run one task to completion (reads stdin with -)
  seagent chat [opts]                      line-based conversation (/help inside)
  seagent session list|show|resume|fork|search|compact|model|rm …
  seagent session export [id…] [--format md|qmd|html|json] [--out FILE|DIR/] [--no-redact]
  seagent session trajectory [id] [--format sharegpt|bundle] [--out PATH] | verify-export <file> [id]
  seagent session upload-trace [id] [--dataset NAME] [--public] [--no-redact]   (token: seagent secrets set HF_TOKEN)
  seagent daemon start|stop|status|run|install
  seagent send <session> <text…>           queue input on a daemon-hosted session (starts it)
  seagent attach <session> [--from N]      follow a daemon-hosted session live
  seagent interrupt <session>              stop a running session
  seagent gate list | answer <id> once|session|permanent|deny [reason…]
  seagent schedule add <cron> <prompt…> [--reuse] | list | rm|enable|disable|run <id>
  seagent goal add <objective…> [--rounds N] | list | show|run|pause|resume|cancel <id> | subgoal <id> [text|remove N|clear]
  seagent system event --text <t> [--mode now|next-heartbeat] | heartbeat last|enable|disable | presence
  seagent suggestions [accept N | dismiss N | catalog | clear]   suggested automations
  seagent web providers [--json] | test <query> [--count N] [--json] | fetch <url> [--text] [--json]   web search providers, route, one fetch
  seagent memory show | add <text…> [--user] | review | accept <n|all> | reject <n|all>
  seagent index status | sync | rebuild | bench <session>   SQLite index (session FTS, memories, retrieval); rebuildable from the logs
  seagent checkpoint list | restore <id> | status | prune [--retention-days N] [--max-size-mb N] [--keep-orphans] [--force] | clear [--force]
  seagent sandbox list [--json] | recreate (--all|--session ID|--agent DIR) [--force] | explain [--session ID] [--json]
  seagent config path|show|init|get <key>|validate
  seagent secrets set <NAME> | list | rm <NAME> | backend | migrate   (value read from stdin, never argv)
  seagent providers list | check [provider/model]
  seagent mcp presets [query] | presets show <preset> | add <name> --preset <preset> [--env K=V]
  seagent model [provider/model]           pick / set the default model (interactive without args)
  seagent models status|list [provider]|providers|set <p/m> [--as aux]|aliases add|rm|fallbacks|refresh|pricing <p/m>
  seagent login <provider> [--no-browser] [--import] | logout <provider>   account logins (ChatGPT, Claude, Copilot…)
  seagent auth add <provider> [--label L] [--priority N] | list | remove | reset | priority | strategy | refresh | status
  seagent fallback list | add <p/m> | remove <p/m|n> | clear
  seagent usage [--days N] [--session ID] [--account] [--billing] [--json]   tokens and cost per model; --billing: what the provider billed (admin key)
  seagent insights [--days N]              sessions, tools, skills, models, sources
  seagent mcp list | tools [server] | test <server> | refresh <server> | add <name> (--url U | -- cmd args…) | rm <name> | serve [--relay URL [--pair]] | pins [list|diff|accept|forget <server>]
  seagent plugin list                      plugins and what they provide (tools, hooks, channels,
                                       commands, CLI, routes, UI, providers, services…)
  seagent <plugin-command> [args…]         a CLI command a plugin adds (listed by `seagent help`)
  seagent channel list | send <channel> <chat> <text…>
  seagent message send|edit|delete|react|poll|pin|thread|read --channel <n> --chat <id> [--thread T]
              [--text …] [--message-id …] [--poll 'question=… options=a,b'] [--json]
                                       message actions (same dispatcher as the `message` tool)
  seagent webhook list <channel> | subscribe <channel> <route> [json] | rm <channel> <route> | test <channel> <route> [--payload JSON]
  seagent hooks list | test <event> | approve <cmd>|--all | revoke <cmd> | doctor | info|enable|disable <name> | check | install <dir> [--link]
  seagent meet <join URL|status|transcript|say TEXT|stop|setup|auth> [--json]   Google Meet bot (captions → transcript)
  seagent teams list|show|run|fetch|subscriptions|subscribe|renew-subscription|delete-subscription|maintain-subscriptions|token-health|validate
                                       Microsoft Teams meeting pipeline (Graph transcripts → summaries)
  seagent kanban <init|boards|create|list|show|…> [--board <slug>]   multi-agent board (dispatch, stats, log)
  seagent worktree list|add|rm|prune|restore   git worktrees for parallel sessions (`/worktree` in chat)
  seagent acp                              ACP agent on stdio (for Zed, JetBrains, Neovim…)
  seagent acp-client <agent> <prompt…|->   drive an external ACP agent (claude, codex, gemini, opencode…)
                                       [--cwd DIR] [--permission-mode approve-all|approve-reads|deny-all]
                                       [--session ID] [--list] [--json]
  seagent commands                         custom /commands, plugin commands and MCP prompts
  seagent init [notes…]                    generate or update AGENTS.md from a repo scan
  seagent plan <task…>                     write an implementation plan to .seagent/plans/ (no execution)
  seagent verify [dir] [--detect-only] [--save] [--phase P]… [--skip-start] [--port N] [--timeout S] [--ready-timeout S] [--json]
  seagent lsp status|list [--installed-only]|which <server>|check <file>|restart
  seagent node --url ws://host:8640/node | --setup-code CODE   run this machine as a device node
  seagent nodes list|pending|approve|reject|remove|rename|describe|invoke|queue|events|rotate|setup-code
  seagent data export|delete <channel> <sender|chat>
  seagent call <tool> [json]               call a tool from inside the `run` tool (alias: seagent-call)
  seagent status [--full|--all] [--deep] [--json] | sessions | health   what this install is doing, component by component
  seagent telemetry status|test [--endpoint URL] [--json]   gateway monitoring: OTLP export posture + one probe span
  seagent evals list|run [ID…] [--filter S] [--json] [--verbose]   in-process runtime evals (hermetic, no network/keys)
  seagent evals bench|roles|fetch|import|report|compare|collect|swe-score|suites|agents   scored evaluations: benchmarks (SWE-bench, Terminal-Bench, GAIA, OSWorld), model matrix, judge, role scenarios, other agents side by side (docs/evals.md)
  seagent distill research|abstract|check|eval|sign|run|team|purge   occupation guidelines from documented practice (docs/evals.md)
  seagent tools list|enable|disable [NAME…] [--platform P] | --summary | post-setup KEY [--dry-run]   per-platform tools, backend install hooks
  seagent fleet [status|board|files|limits|resume SESSION] [--json]   multi-agent progress: agents, files held, spend, shared board, pauses
  seagent ha status|stepdown [--json]      daemon high availability: lease holder, epoch, hand the lease over
  seagent workers status|dispatch SESSION   the leader's worker-process pool ([workers] count)
  seagent cluster status|nodes|sessions|agents | node add NAME URL --token-secret S | node remove NAME
  seagent cluster keygen [--out F] | policy sign FILE --version N [--seed F] [--out F] | policy verify|publish BUNDLE | policy push [--node N]|pull|status
  seagent docker check [--file Dockerfile] [--json]   lint the container files (multi-stage, USER, HEALTHCHECK, secrets)
  seagent doctor | version | help
  seagent browser close-profile [--browser NAME] | status | install [--url ZIP] | extension
  seagent screen status|start|stop|install [-y]   the headless Bot Desktop screen (Xfce + VNC)
  seagent computer-use install|status|doctor|permissions <status|grant>   the cua-driver desktop backend
  seagent infer <domain> <action> [--json]  capability CLI: image/audio/tts/video/music list|inspect|generate|…
  seagent voice [--continuous|--wake|--no-speak|--no-barge-in|--session ID]|status|live
  seagent stt <audio file> [--json]        transcribe one file with the configured provider
  seagent transcripts list                 the local transcript store

OPTIONS
  -m, --model provider/model   -w, --workspace DIR      -s, --session ID
  --set key=value (repeatable) --budget-tokens N        --budget-usd X
  --max-steps N                --yes (approve gate prompts)
  --allow-privilege            --allow-egress           --json   -q, --quiet
  --yolo (run/chat/daemon/tui/acp: skip approval prompts for this process; hardline floors
         and deny rules still apply; also SEAGENT_YOLO=1)

EXIT CODES  0 done · 1 error · 2 usage · 3 budget/limits/stuck · 130 interrupted";
