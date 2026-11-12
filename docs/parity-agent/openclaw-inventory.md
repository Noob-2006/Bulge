# OpenClaw → SE Agent agent-level feature inventory (2026-11-03)

Scope: everything **except** channel platforms, MCP, ACP, A2A and the node wire protocol (already covered in `seagent/docs/parity.md`).
Sources: OpenClaw registries — `src/agents/tool-catalog.ts` (core tools), `extensions/*/openclaw.plugin.json` `contracts` + `registerTool` (plugin tools / providers), `src/auto-reply/commands-registry.shared.ts` + `api.registerCommand` (chat commands), `src/cli/program/core-command-descriptors.ts` + `subcli-command-metadata.ts` (CLI), `src/plugins/hook-types.ts` (hooks), `skills/` (bundled skills), `ui/src/pages` (Control UI).
SE Agent paths are relative to the SE Agent repo root (`crates/...`). Status legend: ✅ present · 🚧 partial · ⬜ missing · N/A (macOS/iOS app or Node-only infra).

SE Agent baseline facts used below (verified by reading code):
- Builtin tools (`crates/seagent-tools/src/lib.rs`): read, write, edit, patch, glob, grep, shell, web_fetch, memory, spawn, ask_user, todo, skill, job.
- Kernel tools (`crates/seagent-kernel/src/kernel.rs`, `context.rs`, `coderun.rs`): `run` (code mode), `session_search`, `goal_done` (goal mode only), `tool_describe` / `tool_call` (progressive disclosure).
- App/channel tools: `channel_send` (`crates/seagent-channel/src/tool.rs`), `node_invoke` (`crates/seagent-app/src/node.rs`), `acp_delegate` (`crates/seagent-app/src/acp_client.rs`), `a2a_*` (`crates/seagent-app/src/a2a.rs`), `seagent_sessions/seagent_session_read/seagent_session_send/seagent_pending*` (only exposed via `seagent mcp serve`, `crates/seagent-app/src/conversations.rs`).
- Kernel always sends `reasoning: None` except where `set_thinking` was set (only reachable from ACP `thought_level`).
- Web UI is 601 lines (`ui/web/*`): token login, session list/create/submit/interrupt, gate approvals, models/tools/nodes/pairing lists, plugin UI panels.

---

## 1. Core agent tools (`src/agents/tool-catalog.ts` CORE_TOOL_DEFINITIONS + runtime-only)

| item | OpenClaw source path | what it does (≤25 words) | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| ls | src/agents/tool-catalog.ts (fs) | List directory entries | ✅ | `read` lists a directory (crates/seagent-tools/src/fs.rs:29) |
| read | src/agents/agent-tools.read.ts | Read file contents (text, images to model, offset/limit) | 🚧 | fs.rs `read` text only; no image/PDF return to model |
| write | src/agents/tool-catalog.ts | Create/overwrite files | ✅ | crates/seagent-tools/src/fs.rs:124 |
| edit | src/agents/tool-catalog.ts | Exact string edits | ✅ | crates/seagent-tools/src/fs.rs:217 |
| apply_patch | src/agents/apply-patch*.ts | Codex `*** Begin Patch` multi-file add/update/delete/move patches with containment | 🚧 | `patch` (fs.rs:373) = atomic multi-edit JSON; no patch-text format, no move/delete |
| exec | src/agents/bash-tools.exec-*.ts | Shell with host=sandbox/gateway/node, pty, background, yieldMs, elevated, env, approvals | 🚧 | `shell` (crates/seagent-tools/src/shell.rs) bash -c + timeout; no pty/yield/background/host routing/elevated; node via `node_invoke system.run` |
| process | src/agents/bash-tools.process.ts | Manage bg exec sessions: list/poll/log/write/send-keys/paste/submit/kill/clear/remove | 🚧 | `job` (crates/seagent-tools/src/job.rs) start/output/wait/kill/list; no stdin write/send-keys/pty |
| code_execution | extensions/xai (tool), catalog runtime | Remote sandboxed analysis (xAI hosted Python) | ⬜ | no hosted code-exec; SE Agent `run` is local (see Code Mode) |
| secrets | src/agents/tools/secrets-tool.ts | Request/list/delete write-only credentials from user | 🚧 | vault + `{{secret:NAME}}` substitution (crates/seagent-kernel/src/vault.rs); no agent tool to request a secret |
| web_search | src/agents/tools/web-search.ts | Provider-routed web search with citations | ⬜ | no web_search tool (only via MCP) |
| web_fetch | src/agents/tools/web-fetch.ts | Guarded fetch (SSRF block), readability/firecrawl extraction, caching, visibility | 🚧 | `web_fetch` (crates/seagent-tools/src/web.rs) GET/POST, HTML→text, egress gate; no SSRF/private-IP block, no readability/cache |
| x_search | extensions/xai | Search X posts via Grok | ⬜ | none |
| memory_search | extensions/memory-core, src/agents/memory-search.ts | Hybrid semantic (vector+FTS) search over memory files/sessions | ⬜ | `memory` tool has no search (crates/seagent-tools/src/memory.rs); `session_search` is substring over transcripts |
| memory_get | extensions/memory-core | Read memory file lines | 🚧 | `memory action=read` reads MEMORY.md/USER.md only |
| personal_instructions | src/agents/tools/personal-instructions-tool.ts | get/set requesting user's personal instructions | 🚧 | `memory file=user` (USER.md) roughly equivalent, not per-sender |
| presence | src/agents/tools/presence-tool.ts | Online people, devices, recent activity, location | ⬜ | none |
| sessions | src/agents/tools/sessions-tool.ts | Session settings: label, pin, archive, groups, patch/stop/clear | ⬜ | no agent tool; CLI `seagent session rm/model` only |
| sessions_create | src/agents/tools/sessions-create-tool.ts | Create independent session, optionally start work | ⬜ | none (spawn is child-only) |
| sessions_list | src/agents/tools/sessions-list-tool.ts | List sessions with filters/recency | 🚧 | `seagent_sessions` only via `seagent mcp serve` (crates/seagent-app/src/conversations.rs); not an in-agent tool |
| sessions_history | src/agents/tools/sessions-history-tool.ts | Read another session's transcript | 🚧 | `seagent_session_read` via mcp serve only |
| sessions_search | src/agents/tools/sessions-search-tool.ts | Search across session transcripts | ✅ | `session_search` (crates/seagent-kernel/src/kernel.rs:177,209) |
| conversations_list | src/agents/tools/conversation-tools.ts | List exact external conversation addresses | ⬜ | `channel_send` lists configured channel names only |
| conversations_send | src/agents/tools/conversation-tools.ts | Send to an exact external conversation | 🚧 | `channel_send` plain text (crates/seagent-channel/src/tool.rs:40) |
| conversations_turn | src/agents/tools/conversation-tools.ts | Send and wait for correlated external reply | ⬜ | none |
| sessions_send | src/agents/tools/sessions-send-tool.ts | Message/steer another session, ping-pong reply flow, A2A delivery | 🚧 | `seagent_session_send` via mcp serve; no in-agent cross-session send |
| sessions_spawn | src/agents/tools/sessions-spawn-tool.ts | Spawn sub-agent/ACP session in background, announce result, sandbox/model/thread options | 🚧 | `spawn` (crates/seagent-tools/src/agent.rs:11) synchronous only, fork/model/tools; `acp_delegate` for ACP |
| agents_wait | src/agents/tools/agents-wait-tool.ts | Wait for background sub-agents | ⬜ | no background spawn |
| sessions_yield | src/agents/tools/sessions-yield-tool.ts | End turn to receive sub-agent results | ⬜ | none |
| subagents | src/agents/tools/subagents-tool.ts | list/cancel/wait background work (subagents, media gen, automations) | ⬜ | none |
| session_status | src/agents/tools/session-status-tool.ts | Model, usage, queue, runtime state; change model | ⬜ | no tool (CLI `/status` in `seagent chat`) |
| suggest_task / dismiss_task | src/agents/tools/task-suggestion-tools.ts | Propose follow-up tasks to operator | ⬜ | none |
| github_identity_status | src/agents/tools/github-identity-status-tool.ts | Inspect effective GitHub identity/credential health | ⬜ | none |
| github_publish | src/agents/tools/github-publish-tool.ts | Publish worktree as draft PR | ⬜ | none |
| browser | extensions/browser/src/browser-tool*.ts | Full browser: status/start/stop/profiles/tabs/open/focus/close/snapshot/screenshot/navigate/console/pdf/upload/dialog/act(click,type,drag,fill,evaluate…) | 🚧 | node `computer.act` v2 CDP actions get_browser_state/navigate/click/type against user-started Chrome (crates/seagent-app/src/node/cdp.rs); no managed profiles, screenshots/pdf/upload/dialog/console |
| screen | src/agents/tools/screen-tool.ts | Drive the operator web UI | ⬜ | none |
| theme | src/agents/tools/theme-tool.ts | List/select/create UI themes | ⬜ | none |
| dashboard | src/agents/tools/dashboard-tool.ts | Read/arrange session dashboard widgets | ⬜ | none |
| terminal | src/agents/tools/terminal-tool.ts | Shared operator terminals list/read/input/resize/close | ⬜ | none |
| portal | src/agents/tools/portal-tool.ts | Expose local web apps through gateway | ⬜ | none |
| canvas | extensions/canvas/src/tool.ts | Present/navigate/eval/snapshot node Canvas, A2UI JSONL | 🚧 | node command `canvas.present {url, html}` (crates/seagent-app/src/node.rs:735); no eval/snapshot/A2UI |
| show_widget | src/canvas/widget-tool.ts | Interactive widget in chat or dashboard | ⬜ | none (plugin UI panels exist but not agent-authored) |
| message | src/agents/tools/message-tool-*.ts | Cross-channel send/react/poll/edit/delete/pin/thread actions with idempotency | 🚧 | `channel_send` text only |
| heartbeat_respond | src/agents/tools/heartbeat-response-tool.ts | Accept heartbeat outcomes | ⬜ | no heartbeat runs |
| automations (cron) | src/agents/tools/cron-tool*.ts | Agent-managed schedules: add/update/remove/list/run/runs/status/wake, announce/webhook delivery | ⬜ | schedules only via CLI `seagent schedule` (crates/seagent-kernel/src/automation.rs); no agent tool |
| gateway | src/agents/tools/gateway-tool.ts | Update OpenClaw; read/patch config/schema; restart | ⬜ | none |
| plugins | src/agents/tools/plugins-tool.ts | Install/enable/reload plugins (official, ClawHub) | ⬜ | none |
| openclaw (delegate) | src/agents/tools/openclaw-delegate-tool.ts | Delegate setup/repair to system agent | ⬜ | none |
| nodes | src/agents/tools/nodes-tool*.ts | Nodes list/describe/invoke, camera/screen/location/notify/photos/notifications | ✅ | `node_invoke` list/describe/invoke (node.rs:798), linux node implements camera/screen/location/notify |
| computer | src/agents/tools/computer-tool*.ts | Desktop control (click, type, key, scroll, drag, zoom, a11y tree, set_value, menus) on gateway or paired computer | 🚧 | node `computer.act` with AT-SPI a11y + CDP (crates/seagent-app/src/node/a11y.rs); no gateway-local tool, no zoom/drag/trajectory replay |
| mobile_ui | src/agents/tools/mobile-ui-tool.ts | Observe/control paired Android app | N/A | tied to OpenClaw Android app |
| agents_list | src/agents/tools/agents-list-tool.ts | List configured agents | ⬜ | SE Agent is single-agent |
| get_goal / create_goal / update_goal | src/agents/tools/goal-tools.ts | Thread goal CRUD from the model | 🚧 | goals via CLI `seagent goal`, model only has `goal_done` (kernel.rs:178) |
| progress_card | src/agents/tools/progress-card-tool.ts | Maintain session progress card | 🚧 | `todo` list (crates/seagent-tools/src/plan.rs:68) is closest; no card rendering |
| ask_user | src/agents/tools/ask-user-tool.ts | Ask user a question, wait | ✅ | crates/seagent-tools/src/agent.rs:60 |
| skill_workshop | src/agents/tools/skill-workshop-tool*.ts | Draft/test/publish skills | 🚧 | `skill action=create/update/archive` (plan.rs:182); no test/publish |
| skills_search | src/agents/tool-catalog.ts | Search installed eligible skills | 🚧 | skills index injected in prompt (crates/seagent-kernel/src/context.rs:73); no search tool |
| skills_read | src/agents/tool-catalog.ts | Read full SKILL.md | ✅ | `skill action=view` (plan.rs) |
| decision_evaluate | src/agents/tools/decision-tool.ts | Typed decision via decision provider | ⬜ | none |
| view_image | src/agents/tools/image-tool.ts | Image understanding with vision model + fallbacks | ⬜ | no tool; images only enter via ACP prompts (crates/seagent-app/src/acp.rs:197) |
| image_generate | src/agents/tools/image-generate-tool.ts | Generate/edit images via providers | ⬜ | none |
| video_generate | src/agents/tools/video-generate-tool.ts | Generate video (async background) | ⬜ | none |
| music_generate | src/agents/tools/music-generate-tool.ts | Generate music | ⬜ | none |
| transcripts | src/agents/tools/transcripts-tool*.ts | Inspect/manage meeting transcript captures | ⬜ | none |
| tts | src/agents/tools/tts-tool.ts | Text-to-speech, voice notes | ⬜ | none |
| pdf | src/agents/tools/pdf-tool.ts | PDF reading/extraction (native provider or text) | ⬜ | none |
| tool_search / tool_describe | src/agents/tool-search*.ts | Deferred tool catalog search + schema reveal | ✅ | `tool_describe`/`tool_call` (crates/seagent-kernel/src/context.rs:153) |
| search / find / grep / glob | src/agents/tool-catalog.ts runtime-only | Code search helpers | ✅ | `glob`, `grep` (crates/seagent-tools/src/search.rs) |
| structured_output | src/agents/tools/structured-output-tool.ts | Force schema-validated final output | ⬜ | none (`--json` prints events only) |
| todo-style planning | (n/a in OC; OC uses progress_card/goals) | — | ✅ | `todo` (plan.rs) — SE Agent extra |
| Code Mode | src/agents/code-mode*.ts, extensions/code-mode-quickjs | Model writes JS calling tools in a sandboxed QuickJS/worker; swarm controller | 🚧 | `run` bash/python + `seagent-call` (crates/seagent-kernel/src/coderun.rs); no JS/QuickJS isolation, no swarm |

## 2. Tools contributed by bundled extensions

| item | OpenClaw source path | what it does (≤25 words) | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| llm-task | extensions/llm-task | JSON-only LLM sub-call tool for workflows | ⬜ | none |
| lobster | extensions/lobster | Typed workflow pipelines with resumable approvals | ⬜ | none |
| diffs | extensions/diffs (+diffs-language-pack) | Read-only diff viewer/renderer for agents | ⬜ | none |
| workboard_* (≈40 tools) | extensions/workboard | Kanban: boards/cards create/claim/move/comment/attach/dispatch/proof/notify, worker protocol | ⬜ | none |
| wiki / wiki_search/get/apply/lint/status | extensions/memory-wiki | Compiled wiki / Obsidian vault knowledge store | ⬜ | none |
| memory_recall / memory_store / memory_forget | extensions/memory-lancedb | LanceDB vector memory, auto-recall/capture | 🚧 | `[memory] provider = "<plugin>"` lets a plugin serve `memory` (crates/seagent-kernel/src/config.rs:51); no vector backend bundled |
| dreaming | extensions/memory-core | Background memory consolidation ("dreaming") | 🚧 | `[learn]` post-turn review stages memory entries (config.rs:144, `seagent memory review`) |
| active-memory | extensions/active-memory | Pre-reply bounded memory retrieval, per-agent Remember | ⬜ | memory snapshot is static in prompt |
| firecrawl_search / firecrawl_scrape | extensions/firecrawl | Search + scrape via Firecrawl | ⬜ | none |
| tavily_search / tavily_extract | extensions/tavily | Tavily search/extract | ⬜ | none |
| github_read / github_search | extensions/github | Public GitHub link previews/reader | ⬜ | none |
| file_fetch / dir_list / dir_fetch / file_write | extensions/file-transfer | Transfer files to/from paired nodes | 🚧 | node `file.fetch` only (node.rs) |
| codex_* (sessions_list/read/send/interrupt, threads, plugins, endpoint_probe) | extensions/codex | Drive Codex app-server sessions | 🚧 | `acp_delegate` drives Codex over ACP (acp_client.rs); no native Codex app-server |
| crabbox | extensions/crabbox | Cloud worker leases + sandbox backend | ⬜ | none |
| autoreview | extensions/autoreview | Review sandbox changes with Auto Review helper | ⬜ | none |
| voice_call | extensions/voice-call | Phone calls via Twilio/Telnyx/Plivo | ⬜ | none |
| google_meet | extensions/google-meet | Join Meet via Chrome/Twilio, transcripts | ⬜ | none |
| teams-meetings / zoom-meetings / slack-huddles | extensions/teams-meetings, zoom-meetings, slack-huddles | Join meetings as browser guest, transcripts | ⬜ | none |
| facetime_call | extensions/facetime | FaceTime realtime voice | N/A | macOS FaceTime |
| onepassword | extensions/onepassword | 1Password SecretRefs + brokered agent access with approvals/audit | ⬜ | vault is local only |
| visitor_invite/list/revoke | extensions/visitor-access | Cloudflare Access visitor grants | ⬜ | none |
| talk_voice | extensions/talk-voice | List/set Talk voice | ⬜ | none |
| mcp_events | extensions/mcp-events | Subscribe MCP events → automations | ✅ | crates/seagent-plugin/src/events.rs |
| local_image | extensions/llama-cpp | Local image gen/understanding via llama.cpp | ⬜ | none |
| feishu_* (doc, wiki, drive, bitable×9, perm, chat, msg…) | extensions/feishu/src | Lark workplace tools | ⬜ | feishu channel exists, no workplace tools |
| whatsapp_login / whatsapp_call | extensions/whatsapp | QR login, voice call | ⬜ | (channel itself in parity.md) |
| zalouser tool | extensions/zalouser | Zalo personal actions | ⬜ | none |
| discussion | extensions/clickclack | ClickClack discussion tool | ⬜ | none |
| qa-lab tools | extensions/qa-lab | QA scenario runner tools | N/A | dev-only QA harness |
| advisor | extensions/advisor | Reviews ongoing work and offers one correction | ⬜ | none |
| agent-guidance | extensions/agent-guidance | Share instruction files across agents | ⬜ | none |
| tokenjuice | extensions/tokenjuice | Compacts exec/bash tool results | 🚧 | spill-to-file for large outputs (`runner.spill_bytes`, config.rs:101); no reducers |
| logbook | extensions/logbook | Periodic screen snapshots → work journal | ⬜ | none |
| team-reports | extensions/team-reports | GitHub/Discord activity reports | ⬜ | none |
| session-share | extensions/session-share | Share session transcripts | ⬜ | none |
| document-extract | extensions/document-extract | Text + page images from document attachments | ⬜ | attachments only saved to `.seagent/inbox` (crates/seagent/src/ext.rs:781) |
| web-readability | extensions/web-readability | Readable article extraction for web_fetch | ⬜ | naive HTML→text |
| cua-computer | extensions/cua-computer | CUA driver computer control (mac/win/linux) | 🚧 | Linux AT-SPI computer.act (node/a11y.rs) |
| linux-node | extensions/linux-node | Notifications, camera, location on Linux nodes | ✅ | crates/seagent-app/src/node.rs:1263-1275 |
| device-pair | extensions/device-pair | Setup codes + pairing approvals | ✅ | `seagent nodes setup-code/approve` (main.rs:2089-2107) |

## 3. Tool backends / capability providers (contracts in openclaw.plugin.json)

| item | OpenClaw source path | what it does (≤25 words) | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| web_search providers: brave, duckduckgo, exa, firecrawl, google, perplexity, parallel, searxng, tavily, xai, moonshot, minimax, deepseek, ollama, codex-native | extensions/*/ (webSearchProviders) | Pluggable search backends | ⬜ | no web_search at all |
| web_fetch providers: firecrawl; extractors: web-readability | extensions/firecrawl, web-readability | Fetch fallbacks/extraction | ⬜ | none |
| image generation: openai, google, fal, comfy, deepinfra, litellm, microsoft-foundry, minimax, openrouter, vydra, xai | extensions/* (imageGenerationProviders), src/image-generation | Image gen backends | ⬜ | none |
| video generation: alibaba, byteplus, comfy, deepinfra, fal, google, kie, minimax, novita, openrouter, pixverse, qwen, runway, together, vydra, xai, zai | src/video-generation, extensions/* | Video gen backends | ⬜ | none |
| music generation: comfy, fal, google, minimax, openrouter | src/music-generation | Music backends | ⬜ | none |
| speech/TTS: openai, elevenlabs, azure-speech, microsoft, google, minimax, inworld, fish-audio, gradium, volcengine, xiaomi, deepinfra, openrouter, vydra, xai, tts-local-cli | src/tts, extensions/* | TTS backends, voice-note output | ⬜ | none |
| media understanding (audio/image/video): openai, anthropic, google, groq, deepgram, mistral, elevenlabs, deepinfra, minimax, moonshot, qwen, zai, xai, openrouter, opencode, senseaudio, codex, llama-cpp | src/media-understanding | Auto-transcribe/describe inbound media | 🚧 | node `talk.ptt` STT via OpenAI-compatible `/audio/transcriptions` (crates/seagent-app/src/node/talk.rs); no inbound-media pipeline |
| realtime transcription: openai, deepgram, elevenlabs, mistral, xai | src/realtime-transcription | Streaming STT websockets | ⬜ | none |
| realtime voice: openai, google, xai | extensions/* (realtimeVoiceProviders), src/talk | Realtime voice agents (Talk) | ⬜ | discord_voice exists (channel); no realtime model voice |
| embeddings: openai, google, mistral, voyage, bedrock, deepinfra, github-copilot, llama-cpp, lmstudio, ollama, omlx | extensions/* (embeddingProviders) | Embeddings for memory search | ⬜ | none |
| decision providers: levanto, onnx, openai, openrouter, subq, typesafe | src/decisions, extensions/* | Typed yes/no/choice/scale decisions | ⬜ | none |
| usage providers: anthropic, openai, openrouter, deepseek, minimax, ollama, venice, xai, xiaomi, zai, github-copilot, clawrouter | extensions/* (usageProviders) | Fetch provider quota/balance | ⬜ | none |
| storage providers: cloudflare R2 | extensions/cloudflare, src/storage | Named remote storage locations | ⬜ | none |
| secret providers: 1Password, HashiCorp Vault, env/file/exec SecretRefs | extensions/onepassword, vault; src/secrets | External secret resolution | 🚧 | local vault + env (crates/seagent-kernel/src/vault.rs); no exec/1P/Vault refs |
| document extractors | extensions/document-extract | Doc→text for attachments | ⬜ | none |
| transcript source providers | discord, google-meet, teams/zoom/slack-huddles | Meeting transcript capture | ⬜ | none |
| worker providers | extensions/crabbox, qa-lab | Cloud workers for sessions | ⬜ | none |
| migration providers: migrate-claude, migrate-hermes, codex | extensions/migrate-* | Import other agents' config/memory/skills | ⬜ | none (seagent reads `.claude/commands`, `.claude/skills` dirs directly) |
| agentToolResultMiddleware | extensions/tokenjuice | Post-process tool results | ✅ | plugin `middleware: ["tool_request","llm_execution"]` (crates/seagent-plugin/src/plugin.rs) |
| codeModeExecutors | extensions/code-mode-quickjs | JS executor for Code Mode | ⬜ | coderun uses host bash/python |

## 4. Models, providers, auth

| item | OpenClaw source path | what it does (≤25 words) | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| Preset: openai | extensions/openai | OpenAI Responses + chat | ✅ | crates/seagent-model/src/lib.rs presets `openai`, `openai-chat` |
| Preset: anthropic | extensions/anthropic | Claude API | ✅ | presets `anthropic` |
| Preset: google (gemini) | extensions/google | Gemini API | ✅ | presets `gemini` |
| Preset: google-vertex / google-gemini-cli | extensions/google | Vertex ADC auth; Gemini CLI OAuth | ⬜ | no GCP auth |
| Preset: anthropic-vertex | extensions/anthropic-vertex | Claude on Vertex | ⬜ | none |
| Preset: amazon-bedrock / bedrock-mantle | extensions/amazon-bedrock* | Bedrock SigV4, discovery, guardrails | ⬜ | no SigV4 |
| Preset: deepseek | extensions/deepseek | DeepSeek | ✅ | presets `deepseek` |
| Preset: openrouter | extensions/openrouter | OpenRouter (+OAuth) | 🚧 | preset present; no OAuth |
| Preset: groq | extensions/groq | Groq | ✅ | preset |
| Preset: xai | extensions/xai | Grok (+device/OAuth) | 🚧 | preset; no OAuth |
| Preset: mistral | extensions/mistral | Mistral | ✅ | preset |
| Preset: together | extensions/together | Together | ✅ | preset |
| Preset: fireworks | extensions/fireworks | Fireworks | ✅ | preset |
| Preset: ollama / ollama-cloud | extensions/ollama | Local + cloud Ollama, discovery | 🚧 | local preset; no cloud preset |
| Preset: lmstudio | extensions/lmstudio | LM Studio | ✅ | preset |
| Preset: vllm | extensions/vllm | vLLM | ✅ | preset |
| Preset: sglang | extensions/sglang | SGLang | 🚧 | custom `[providers.x]` openai_chat; no preset |
| Preset: llama-cpp (managed server) | extensions/llama-cpp | Spawns/manages llama.cpp GGUF servers | ⬜ | can point at existing server via custom provider only |
| Preset: qwen / dashscope / modelstudio / token plans | extensions/qwen | Alibaba Qwen variants | 🚧 | `dashscope` intl preset only |
| Preset: moonshot / kimi-coding | extensions/moonshot, kimi-coding | Kimi (intl/cn, coding plan) | 🚧 | `moonshot` preset; no CN/coding |
| Preset: zai (GLM) | extensions/zai | Z.ai | 🚧 | `zhipu` (bigmodel.cn) preset; no z.ai intl |
| Preset: minimax / minimax-portal | extensions/minimax | MiniMax API + OAuth portal | 🚧 | `minimax` preset; no OAuth/CN |
| Preset: siliconflow | (not in OC) | — | ✅ | SE Agent extra preset |
| Presets: arcee, baseten, cerebras, chutes, cohere, featherless, gmi, huggingface, kilocode, longcat, meta, novita, nvidia, opencode/opencode-go, qianfan, radius, stepfun, synthetic, tencent, venice, vercel-ai-gateway, cloudflare-ai-gateway, litellm, deepinfra, byteplus, volcengine, xiaomi, kie, vydra, fal, clawrouter, copilot-proxy, omlx, microsoft-foundry | extensions/<id> | Additional provider presets with auth choices | 🚧 | each usable as custom `[providers.<id>] format="openai_chat"` (crates/seagent/src/providers.rs); no presets/onboarding entries |
| github-copilot provider | extensions/github-copilot | Copilot models via device OAuth + dynamic headers | ⬜ | none |
| apple-fm | extensions/apple-fm | On-device Apple Intelligence | N/A | macOS |
| OpenAI OAuth (ChatGPT/Codex subscription, device code) | extensions/openai, src/llm/oauth.ts | Login with ChatGPT account | ⬜ | none |
| Anthropic setup-token / Claude CLI creds | extensions/anthropic | Use Claude subscription tokens | ⬜ | none |
| Auth profiles (multi-key, rotation, cooldown, per-agent) | src/agents/auth-profiles/, api-key-rotation.ts | Multiple credentials per provider with failover | 🚧 | one key/provider (env/config/vault); provider cooldown + `model.fallback` (crates/seagent-kernel/src/kernel.rs:122, config.rs:84) |
| Model fallback chains (incl. image fallbacks) | src/agents/model-fallback*.ts | Ordered fallback with cooldowns | ✅ | `model.fallback` (config.rs:84), kernel retries/fallback |
| Aux/utility model | src/agents/utility-model.ts | Cheap model for titles/compaction | ✅ | `model.aux` (config.rs:86) |
| Subagent model | src/agents/agent-scope-config.ts | Model for spawned agents | ✅ | `model.subagent` (config.rs:88) |
| Model catalog (context window, cost, caps, visibility) | src/agents/model-catalog*.ts, src/model-catalog | Rich model metadata registry | 🚧 | heuristic `caps_for` table (crates/seagent-model/src/lib.rs:183); prices from `[prices]` config |
| Model discovery / scan | src/agents/model-scan.ts, models-config.providers.* | List models from provider APIs | ✅ | `list_models` (seagent-model/src/lib.rs:138), `seagent providers check` |
| Model picker / aliases / allowlist | src/model-picker, src/agents/model-selection*.ts | Interactive picker, aliases, allowlists, per-session sticky model | 🚧 | setup picker (crates/seagent/src/setup.rs), `/model` in chat; no aliases/allowlist |
| Thinking levels (off…xhigh, per model defaults) | src/agents/thinking-runtime.ts | Per-session reasoning effort | 🚧 | `thinking_budget` low/medium/high (seagent-model/src/lib.rs:227); settable only via ACP `thought_level` |
| Fast mode / service tiers | src/agents/fast-mode.ts, model-catalog-service-tiers.ts | Priority/flex tiers | ⬜ | none |
| Text verbosity / strict tools (OpenAI) | src/agents/openai-text-verbosity.ts | Provider knobs | ⬜ | none |
| Tool-call repair | packages/tool-call-repair | Fix malformed tool args | ✅ | crates/seagent-kernel/src/normalize.rs |
| Prompt cache tracing / stable prefix | src/agents/cache-trace.ts | Cache-friendly prompt | ✅ | crates/seagent-kernel/src/context.rs (frozen prefix) |
| Provider network policy / egress proxy | src/secrets/egress-proxy, provider-network-policy.ts | Restrict provider hosts, proxy | 🚧 | `compliance.profile=government` host deny list (config.rs:59) |
| Agent harnesses: Codex app-server, Copilot runtime, OpenAI Agents API, Muse CLI, Claude CLI backend | extensions/codex, copilot, agentsapi, muse; src/agents/cli-backends.ts | Run turns on external agent runtimes | 🚧 | `acp_delegate` / `seagent acp-client` drive ACP agents (crates/seagent-app/src/acp_client.rs); not a session runtime |
| Usage/cost accounting | src/agents/usage.ts, src/status | Token/cost per session, footer | ✅ | ledger + budgets (crates/seagent-kernel/src/ledger.rs), `--budget-usd` |

## 5. Chat / slash commands (`src/auto-reply/commands-registry.shared.ts` + plugin `registerCommand`)

SE Agent has three command surfaces: `seagent chat` (/model /compact /status /undo /new /commands /exit, main.rs:542), channels (/new /stop /status /help /forget, crates/seagent/src/ext.rs:821, crates/seagent-channel/src/router.rs:116), and custom Markdown/plugin/MCP-prompt commands (crates/seagent-kernel/src/commands.rs). TUI and web UI have none.

| item | OpenClaw source path | what it does (≤25 words) | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| /help | commands-registry.shared.ts | Show commands | ✅ | chat + channel /help |
| /commands | same | List all slash commands | ✅ | `seagent chat` /commands, `seagent commands` |
| /tools | same | List runtime tools (compact/verbose) | ⬜ | CLI-less; web UI tools.list only |
| /skill <name> | same | Run a skill by name | 🚧 | custom commands only; skills not invokable as /cmd |
| /dashboard | same | Create/update session dashboard | ⬜ | — |
| /learn | same | Draft reusable skill from recent work | ⬜ | `[learn]` is memory-only |
| /loop | same | Loop a prompt at interval; status/stop | ⬜ | `seagent schedule` CLI only |
| /status | same | Show current status | ✅ | chat + channel /status |
| /goal | same | Show/control current goal | ⬜ | CLI `seagent goal` only |
| /diagnostics | same | Explain gateway diagnostics | ⬜ | — |
| /login | same | Connect a model provider from chat | ⬜ | — |
| /openclaw | same | Setup/repair helper | ⬜ | — |
| /allowlist | same | List/add/remove allowlist entries | ⬜ | CLI `seagent pairing` only |
| /approve | same | Approve/deny exec requests | 🚧 | channels: no; `seagent gate answer`, TUI y/a/n, web pending |
| /context | same | Explain context build/usage | ⬜ | — |
| /btw (/side) | same | Side question without changing context | ⬜ | — |
| /export-session | same | Export session to HTML | 🚧 | `seagent session export` Markdown (main.rs:702) |
| /export-trajectory | same | JSONL trajectory bundle | 🚧 | event log is JSONL (crates/seagent-kernel/src/store.rs); no export command |
| /tts | same | Control TTS | ⬜ | — |
| /whoami (/id) | same | Show sender id | ⬜ | — |
| /session | same | Conversation bindings + lifecycle settings | ⬜ | — |
| /subagents | same | Inspect subagent runs | ⬜ | — |
| /acp | same | Spawn/steer/close ACP sessions, set mode/model/cwd/permissions | 🚧 | `seagent acp-client` CLI only |
| /agents | same | List thread-bound agents | ⬜ | — |
| /steer (/tell) | same | Guide active run | 🚧 | messages to a running session steer automatically (kernel.rs:345); no command |
| /followup | same | Run as new turn ignoring queue mode | ⬜ | — |
| /config show/get/set/unset | same | Config from chat | ⬜ | CLI only |
| /mcp show/get/set/unset | same | MCP config from chat | ⬜ | CLI only |
| /plugins list/show/enable/disable | same | Plugin toggles from chat | ⬜ | — |
| /debug | same | Runtime debug overrides | ⬜ | — |
| /usage off/tokens/full/cost | same | Usage footer / cost summary | ⬜ | — |
| /stop | same | Stop current run | ✅ | channel /stop; TUI Ctrl+C |
| /restart | same | Restart OpenClaw | ⬜ | — |
| /update | same | Update and restart | ⬜ | — |
| /activation mention/always | same | Group activation mode | 🚧 | `require_mention` config (crates/seagent-channel/src/access.rs:7); no command |
| /send on/off/inherit | same | Send policy | ⬜ | — |
| /reset | same | Reset current session | 🚧 | /new equivalent |
| /new | same | New session | ✅ | chat + channel /new |
| /name | same | Rename session | ⬜ | — |
| /compact | same | Compact context | 🚧 | `seagent chat` /compact only (main.rs:548) |
| /think (/t) | same | Thinking level | ⬜ | only ACP thought_level |
| /verbose (/v) | same | Verbose tool output | ⬜ | — |
| /trace | same | Plugin trace lines | ⬜ | — |
| /fast | same | Fast mode | ⬜ | — |
| /reasoning | same | Reasoning visibility on/off/stream | ⬜ | — |
| /elevated | same | Elevated mode on/off/ask/full | ⬜ | `--allow-privilege` CLI flag only |
| /exec | same | Session exec defaults (host/security/ask) | ⬜ | — |
| /model | same | Show/set model with scope | 🚧 | `seagent chat` /model (main.rs:544); not in channels |
| /models | same | List providers/models | ⬜ | CLI `seagent providers list` |
| /queue | same | Queue mode (steer/followup/collect/interrupt) | ⬜ | fixed steer behaviour |
| /bash | same | Host shell from chat | ⬜ | — |
| /forget | (not in OC core) | — | ✅ | SE Agent extra (ext.rs:844) |
| /undo | (not in OC) | — | ✅ | SE Agent extra checkpoint restore |
| /active-memory | extensions/active-memory | Toggle active memory | ⬜ | — |
| /dreaming | extensions/memory-core | Control dreaming | ⬜ | — |
| /pair | extensions/device-pair | Device pairing in chat | ⬜ | CLI only |
| /voice | extensions/talk-voice | Voice selection | ⬜ | — |
| /workboard, /card | extensions/workboard | Board commands | ⬜ | — |
| /controlui (miniapp) | extensions/telegram/src/miniapp | Open Control UI as Telegram mini-app | ⬜ | — |
| /reef | extensions/reef | Reef channel command | ⬜ | (channel-specific) |
| /codex | extensions/codex | Codex harness commands | ⬜ | — |
| Custom markdown commands | src/skills/discovery/chat-command-invocation.ts | User-defined commands | ✅ | crates/seagent-kernel/src/commands.rs (`.seagent/commands`, `.claude/commands`) |
| Native command menus (Discord/Slack/Telegram) | channel plugins | Register commands natively | ⬜ | channel layer; not registered |

## 6. CLI commands (`src/cli`, core + sub-CLI descriptors)

| item | OpenClaw source path | what it does (≤25 words) | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| onboard / setup | src/cli/program/register.onboard.ts, src/wizard | Guided setup wizard | 🚧 | `seagent setup` (crates/seagent/src/setup.rs); see §11 for missing steps |
| configure | register.configure.ts | Interactive config sections | ⬜ | — |
| config get/set/patch/unset/file/schema/validate | src/cli/config-cli*.ts | Non-interactive config | 🚧 | `seagent config path/show/init/get/validate` (main.rs:1309-1337); no set/patch/unset/schema |
| claws | src/cli/claws-cli*.ts | Author/add Claws packages | ⬜ | — |
| backup create/verify/restore | register.backup.ts, src/infra/backup-* | Backup archives + SQLite snapshots | ⬜ | — |
| database | register.database.ts | DB compat/ownership/port | N/A | Node SQLite worker infra |
| migrate | register.migrate.ts | Import from other agents | ⬜ | — |
| storage | register.storage.ts | Storage locations | ⬜ | — |
| doctor | src/flows/doctor-* | Health checks + repairs | 🚧 | `seagent doctor` checks config/secrets/model key/bash/git/python/socket/daemon; no repair |
| triage | core-command-descriptors.ts | Sanitized diagnostics → local coding agent | ⬜ | — |
| dashboard | core-command-descriptors.ts | Open Control UI with token | ✅ | `seagent app open` (main.rs:2165) |
| reset | same | Reset config/state | ⬜ | — |
| uninstall | same | Uninstall service + data | 🚧 | `seagent service uninstall` (main.rs:1853); no data wipe |
| message send/read/react/poll/pin/thread/edit/delete/... | src/cli/program/message | Channel actions from CLI | 🚧 | `seagent channel send` text only |
| mcp | src/cli/mcp-cli.ts | MCP config | ✅ | (out of scope; `seagent mcp`) |
| transcripts | register.transcripts.ts | Inspect transcripts | 🚧 | `seagent session show` |
| agent | register.agent-turn.ts | Run one agent turn (gateway or --local) | ✅ | `seagent run` |
| agents add/delete/bind/set-identity | register.agent.ts | Multi-agent management, routing bindings | ⬜ | single agent |
| status | register.status-health-sessions.ts | Channel health + recent recipients | 🚧 | `seagent daemon status`, `seagent channel list` |
| health | same | Gateway health | ✅ | `seagent health` (main.rs:195) |
| audit | register.audit.ts | Activity records / run identity | ⬜ | — |
| sessions (list/cleanup/import) | same | Stored sessions | ✅ | `seagent session list/show/resume/fork/search/export/compact/model/rm` |
| acp | src/cli/acp-cli.ts | ACP bridge | ✅ | `seagent acp` |
| gateway run/status/... | src/cli/gateway-cli | Run/query gateway | ✅ | `seagent daemon run/start/stop/status` |
| daemon install (launchd/systemd/schtasks) | src/cli/daemon-cli, src/daemon | Service management | 🚧 | systemd user unit only (main.rs:1820-1868); no launchd/schtasks |
| logs | src/cli/logs-cli.ts | Tail gateway logs | ⬜ | no log command (stderr/journal) |
| system (events/heartbeat/presence) | src/cli/system-cli.ts | System tools | ⬜ | — |
| models (list/scan/status/set/aliases/fallbacks/auth) | src/cli/models-cli.ts, models-accounts-cli.ts | Model config + auth accounts | 🚧 | `seagent providers list/check` |
| promos | src/cli/promos-cli.ts | ClawHub model offers | ⬜ | — |
| telemetry | src/cli/telemetry-cli.ts | Anonymous telemetry controls | N/A | SE Agent has no telemetry (nothing to control) |
| infer / capability | src/cli/capability-cli | Provider capabilities from CLI (image/tts/stt…) | ⬜ | — |
| approvals / exec-approvals | src/cli/exec-approvals-cli.ts | Approval policy + pending | 🚧 | `seagent gate list/answer` |
| exec-policy | src/cli/exec-policy-cli.ts | Sync exec policy with host approvals | ⬜ | — |
| nodes | src/cli/nodes-cli | Pairing/status/invoke/media | ✅ | `seagent nodes …` (main.rs:2089-2107) |
| devices | src/cli/devices-cli.ts | Device pairing/tokens | ✅ | `seagent nodes approve/rotate` |
| users | src/cli/users-cli.ts | Durable user profiles, email aliases | ⬜ | — |
| node / connect | src/cli/node-cli, connect-cli.ts | Run headless node host | ✅ | `seagent node --url/--setup-code` |
| worker | src/cli/worker-cli.ts | Restricted cloud worker runtime | ⬜ | — |
| sandbox list/recreate/explain | src/cli/sandbox-cli.ts | Manage sandbox containers | ⬜ | no sandbox |
| worktrees | src/cli/worktrees-cli.ts | Managed git worktrees | ⬜ | — |
| attach | src/cli/attach-cli.ts | Attach Claude Code to a session via scoped MCP | 🚧 | `seagent attach` follows session live; `seagent mcp serve` conversations tools |
| tui / terminal / chat / resume | src/cli/tui-cli.ts, resume-cli.ts | Terminal UI | ✅ | `seagent tui`, `seagent chat`, `seagent session resume` |
| cron / automations | src/cli/cron-cli | Manage automations | ✅ | `seagent schedule add/list/rm/enable/disable/run` |
| dns | src/cli/dns-cli.ts | Tailscale + CoreDNS wide-area discovery | ⬜ | — |
| docs | src/cli/docs-cli.ts | Search live docs | ⬜ | — |
| qa | private qa-lab | QA scenarios | N/A | dev harness |
| proxy | src/cli/proxy-cli.ts, src/proxy-capture | Debug proxy capturing provider traffic | ⬜ | — |
| hooks | src/cli/hooks-cli.ts | List/install/enable hooks | ⬜ | hooks via config only |
| webhooks | src/cli/webhooks-cli.ts | Webhook helpers (Gmail Pub/Sub) | 🚧 | `seagent webhook list/subscribe/rm` (MCP-event routes) |
| qr | src/cli/qr-cli.ts | Mobile pairing QR | ✅ | `seagent nodes setup-code` renders QR (crates/seagent-app/src/qr.rs) |
| clawbot | src/cli/clawbot-cli.ts | Legacy aliases | N/A | legacy naming |
| pairing | src/cli/pairing-cli.ts | DM pairing approvals | ✅ | `seagent pairing list/approve/revoke` |
| plugins install/list/inspect/search/update/uninstall/reload/build/marketplace | src/cli/plugins-*.ts | Plugin lifecycle + authoring | 🚧 | `seagent plugin list` only; config-declared plugins |
| channels | src/cli/channels-cli.ts | Channel accounts + login | 🚧 | `seagent channel list/send` |
| directory | src/cli/directory-cli.ts | Look up contact/group IDs | ⬜ | — |
| security audit/fix | src/cli/security-cli.ts, src/security/audit*.ts | Audit config/state foot-guns | ⬜ | — |
| secrets (+store) | src/cli/secrets-cli.ts | Secrets runtime controls | ✅ | `seagent secrets set/list/rm` |
| skills list/info/check/search/install | src/cli/skills-cli.ts, skills-search-cli.ts | Inspect/install skills | ⬜ | no skills CLI |
| update | src/cli/update-cli | Self-update with channels | ⬜ | — |
| completion | src/cli/completion-cli.ts | Shell completion | ⬜ | — |
| data export/delete | (OC n/a) | — | ✅ | SE Agent extra `seagent data` (main.rs:1878) |
| checkpoint / undo | (OC n/a) | — | ✅ | SE Agent extra (crates/seagent-kernel/src/checkpoint.rs) |

## 7. Exec safety, sandbox, approvals, security

| item | OpenClaw source path | what it does (≤25 words) | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| Sandbox mode off / non-main / all | src/agents/sandbox/types.ts | Which sessions run tools in containers | ⬜ | no sandboxing; relies on gates + checkpoints |
| Sandbox scope session / agent / shared | src/agents/sandbox/types.ts | Container lifetime granularity | ⬜ | — |
| Workspace access none / ro / rw | src/agents/sandbox/config.ts | Mount policy for workspace | ⬜ | — |
| Docker backend | src/agents/sandbox/docker*.ts | Docker containers, mounts, users, prune | ⬜ | — |
| Podman backend | src/agents/sandbox/podman-runtime.ts | Podman engine | ⬜ | — |
| SSH remote backend | src/agents/sandbox/ssh-backend.ts, remote-shell-* | Run tools on remote host via SSH | ⬜ | (node `system.run` is the analogue) |
| OpenShell backend | extensions/openshell | NVIDIA OpenShell sandbox | ⬜ | — |
| MXC backend | extensions/mxc | Windows ProcessContainer sandbox | N/A | Windows-only OS sandbox |
| Sandbox browser (noVNC) | src/agents/sandbox/browser*.ts, novnc-auth.ts | Browser inside sandbox, viewable | ⬜ | — |
| Sandbox tool policy | src/agents/sandbox-tool-policy.ts | Tools allowed inside sandbox | ⬜ | — |
| Sandbox env sanitizing / security validation | src/agents/sandbox/sanitize-env-vars.ts, validate-sandbox-security.ts | Strip secrets, refuse dangerous mounts | ⬜ | — |
| Exec approvals (security deny/allowlist/full, ask off/on-miss/always) | src/infra/exec-approval-*.ts, bash-tools.exec-approval-* | Per-binary allowlist, approval prompts | 🚧 | two gates privilege/egress with ask/deny/allow (crates/seagent-kernel/src/gate.rs:14) + shell analyser (shell.rs); no binary allowlist file |
| Approval forwarding to chat channels | src/infra/exec-approval-forwarder*.ts | Approve exec from Telegram/Discord etc. | ⬜ | approvals only via CLI/TUI/web/ACP |
| "Always allow" persistence | exec-approvals store | Remember approvals | 🚧 | per-session "always" (crates/seagent-kernel/src/approver.rs:126); not persisted |
| Exec auto-reviewer (LLM judge) | src/agents/exec-auto-reviewer.ts | Model reviews risky exec before run | ⬜ | — |
| Elevated mode | /elevated, sandbox host escape | Let sandboxed agent run on host | 🚧 | `--allow-privilege` flag only |
| Tool profiles (minimal/coding/messaging/full) + allow/deny groups | src/agents/tool-catalog.ts, tool-policy*.ts | Tool allow/deny per agent/provider/sender/channel | 🚧 | `[tools] disabled/pinned/unpinned` (config.rs:134); no profiles/per-sender policy |
| Tool loop detection | src/agents/tool-loop-*.ts | Detect repeated/no-progress calls | ✅ | `runner.repeat_limit` watchdog (config.rs:103) |
| Tool result size guards | src/agents/tool-result-limits.ts | Truncate/spill outputs | ✅ | spill to artifact file (config.rs:101) |
| Workspace FS policy / path containment | src/agents/tool-fs-policy.ts, workspace-file-mutation-guard.ts | Restrict file ops to workspace | 🚧 | privilege gate on system paths (gate.rs `/etc`,`/usr`…); no workspace-only mode |
| Secret egress protection | src/agents/provider-secret-egress.ts, src/secrets/egress-proxy | Block secrets leaving to wrong hosts | ✅ | egress gate + vault redaction (gate.rs:126, vault.rs) |
| External content wrapping (prompt-injection) | src/security/external-content.ts | Mark untrusted content | ⬜ | — |
| security audit (fs perms, gateway exposure, plugins trust, dangerous flags, deep code safety) | src/security/audit*.ts | Static audit of setup | ⬜ | — |
| opengrep rules | security/opengrep | Repo SAST rules | N/A | repo dev tooling |
| Plugin install policy / trust consent | src/security/install-policy.ts, src/cli/plugin-capability-consent.ts | Consent before installing capabilities | 🚧 | `trusted_projects` gate for project configs (config.rs:42) |
| DM policy (pairing/allowlist/open) | src/security/dm-policy-shared.ts | Inbound access | ✅ | crates/seagent-channel/src/access.rs (in parity scope) |
| Compliance profile / retention / AI label | (OC n/a) | — | ✅ | SE Agent extra `[compliance]` (config.rs:59, daemon.rs:169) |

## 8. Agent runtime features

| item | OpenClaw source path | what it does (≤25 words) | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| Context engine plugins | src/context-engine | Pluggable context assembly/compaction | ✅ | crates/seagent-kernel/src/engine.rs, `context_engine` config |
| Compaction (auto, manual, notifier, replay) | src/agents/compaction*.ts | Summarise history near window limit | ✅ | crates/seagent-kernel/src/compaction.rs (prune + summary + fallback) |
| Memory host SDK (event store, dreaming, multimodal, query) | packages/memory-host-sdk, src/memory-host-sdk | Memory engine contract for plugins | 🚧 | plugin `memory: true` provider (crates/seagent-plugin/src/plugin.rs); no events/multimodal/query API |
| Memory flush before compaction | src/agents/agent-tools.memory-flush.ts | Persist memory pre-compaction | ⬜ | — |
| Project memory / bootstrap files (AGENTS.md, SOUL.md, USER.md, IDENTITY.md, BOOT.md) | src/agents/workspace-bootstrap-*.ts, project-memory-*.ts | Seed workspace persona/instructions | 🚧 | AGENTS.md/CLAUDE.md/.seagent/AGENTS.md loaded (crates/seagent-kernel/src/context.rs:12) + MEMORY.md/USER.md + `identity`; no SOUL/IDENTITY/BOOT seeding |
| Session store + transcript repair | src/agents/session-transcript-repair.ts | Durable sessions | ✅ | crates/seagent-kernel/src/store.rs (crash repair) |
| Crash/restart recovery of runs | src/agents/agent-command-restart-recovery.ts | Resume interrupted runs | ✅ | daemon resumes interrupted sessions (crates/seagent-kernel/src/daemon.rs) |
| Steering queue / queue modes (steer, followup, collect, interrupt) | src/agents/agent-steering-queue.ts | How new messages affect running turn | 🚧 | steer only (kernel.rs:345) |
| Sub-agents (depth, announce, thread-bound, visible) | src/agents/subagents, sessions-spawn-* | Background child agents | 🚧 | sync `spawn`, depth limit `max_spawn_depth` (config.rs:104), budget shared (ledger.rs) |
| Goals (thread goals, rounds) | src/agents/tools/goal-tools.ts | Long-running objective loops | ✅ | goals (crates/seagent-kernel/src/automation.rs, `seagent goal`) |
| Cron/automations (announce, webhook delivery, isolated vs main session, wake) | src/cron | Scheduled agent runs with delivery | 🚧 | cron jobs w/ reuse session (automation.rs:63); no delivery to channel/webhook, no `@at` one-shot? (`@every` supported, cron.rs) |
| Heartbeat (active hours, delivery, prompt contributions) | src/infra/heartbeat-*.ts | Periodic proactive check-ins | ⬜ | — |
| Hooks: before_model_resolve, agent_turn_prepare, before_prompt_build, before_agent_reply, before_agent_run, before_agent_finalize | src/plugins/hook-types.ts | Pre-run hook points | 🚧 | SessionStart/UserPrompt/PreModel (crates/seagent-kernel/src/hooks.rs:21); no prompt-build/model-resolve |
| Hooks: model_call_started/ended, llm_input/llm_output | same | Model call observation | ✅ | PreModel/PostModel |
| Hooks: before/after_compaction | same | Compaction hooks | ✅ | PreCompact/PostCompact |
| Hooks: before/after_tool_call, tool_result_persist | same | Tool hooks | ✅ | PreTool/PostTool (modify/block) |
| Hooks: message_received/sending/sent, reply_payload_sending, inbound_claim, before_dispatch, reply_dispatch | same | Message pipeline hooks | 🚧 | MessageReceived/MessageSending/MessageSent; no claim/dispatch |
| Hooks: session_start/end, before_reset, agent_end | same | Session lifecycle | ✅ | SessionStart/SessionEnd/TurnEnd |
| Hooks: subagent_spawned/progress/ended/delivery_target | same | Subagent lifecycle | 🚧 | SubagentStart/SubagentStop |
| Hooks: gateway_start/stop | same | Gateway lifecycle | 🚧 | DaemonStart (no stop) |
| Hooks: cron_changed/reconciled, skill_changed, heartbeat_prompt_contribution, before_install, resolve_exec_env, channel_pairing_requested, before_message_write | same | Misc hooks | ⬜ | — |
| Bundled hooks: boot-md, bootstrap-extra-files, command-logger, compaction-notifier, session-memory | src/hooks/bundled/* | Ready-made hooks | ⬜ | none bundled |
| Gmail watcher hook | src/hooks/gmail*.ts | Gmail Pub/Sub → agent | ⬜ | — |
| Session auto-reset (idle/daily) | src/hooks/session-auto-reset.ts | Reset sessions on schedule | 🚧 | `retention_days` deletion only |
| Auto-reply pipeline (directives, chunking, typing, block streaming) | src/auto-reply | Channel reply orchestration | 🚧 | crates/seagent-channel/src/chunk.rs, deliver.rs (channel parity) |
| Inline directives (/think, /model inside message) | src/auto-reply/reply/get-reply-directives.ts | Per-message overrides | ⬜ | — |
| Link understanding | src/link-understanding | Auto-fetch/summarise links in inbound messages | ⬜ | — |
| Media understanding pipeline | src/media-understanding | Auto-transcribe audio, describe images/video, extract files | ⬜ | attachments saved as paths only (ext.rs:781) |
| TTS auto-reply (voice notes) | src/tts | Speak replies on channels | ⬜ | — |
| Talk mode (realtime voice) | src/talk | Wake-name, realtime voice sessions | 🚧 | node push-to-talk STT only (node/talk.rs) |
| Polls | src/polls.ts | Normalised poll creation across channels | ⬜ | — |
| Boards (session/GitHub boards, website) | src/boards | Board store + reports | ⬜ | — |
| Meeting bot | src/meeting-bot | Browser-driven meeting participant + audio bridge | ⬜ | — |
| Decisions runtime | src/decisions | Typed decision providers | ⬜ | — |
| Audit log (execution identity, message delivery receipts) | src/audit | Durable activity audit | 🚧 | event-sourced session log (crates/seagent-kernel/src/event.rs); no cross-session audit query |
| Claws (packaged agent bundles from ClawHub) | src/claws | Install agent+skills+cron+MCP bundles | ⬜ | — |
| Flows (channel setup, model picker, doctor, memory/search setup) | src/flows | Guided interactive flows | 🚧 | `seagent setup` covers provider/channel |
| System agent (setup/repair assistant) | src/system-agent | Built-in helper agent for config | ⬜ | — |
| Multi-agent routing / bindings | src/routing | Route channels/accounts/peers to agents | ⬜ | one agent; channel→session router only (crates/seagent-channel/src/router.rs) |
| Projects / git clone registry | src/projects | Register/clone project checkouts | ⬜ | — |
| Worktrees (per-session git worktrees) | src/agents/worktrees, src/cli/worktrees-cli.ts | Isolate session edits | ⬜ | shadow-git checkpoints instead (checkpoint.rs) |
| Workspace checkpoints / undo | (n/a in OC) | — | ✅ | SE Agent extra |
| Session cards / progress cards | src/session-cards | Channel progress summaries | ⬜ | — |
| Snapshot / git backup | src/snapshot | Export/restore state snapshots | ⬜ | — |
| Storage locations (encrypted) | src/storage | Named local/remote storage | ⬜ | — |
| Plugin state store | src/plugin-state | Durable per-plugin blob/KV store | ⬜ | — |
| Proxy capture | src/proxy-capture | MITM capture of provider HTTP for debugging | ⬜ | — |
| Trajectory export | src/trajectory | Training/debug trajectories | 🚧 | JSONL event log exists |
| Diagnostics exporters (OTel, Prometheus) | extensions/diagnostics-otel, diagnostics-prometheus | Metrics/traces export | ⬜ | — |
| Bonjour/mDNS advertisement | extensions/bonjour | LAN discovery of gateway | ⬜ | — |
| IP geolocation | extensions/geolocation | Coarse city for presence | ⬜ | — |
| Policy doctor checks | extensions/policy | Workspace conformance checks | ⬜ | — |
| Personal instructions per user / users registry | src/cli/users-cli.ts, personal-instructions | Multi-user profiles | ⬜ | — |
| Git co-author attribution | src/agents/git-coauthor-*.ts | Add co-author trailers | ⬜ | — |
| GitHub App identity for agent | src/agents/github-app-*.ts | Agent commits as GitHub App | ⬜ | — |
| Image sanitisation/compression | src/agents/image-sanitization.ts | Resize images before model | ⬜ | — |
| Plugin SDK capabilities (tools, channels, providers, commands, CLI, routes, UI, services, hooks, context engine, memory) | src/plugin-sdk, packages/plugin-sdk | Extension API | ✅ | seagent plugin protocol v1 (crates/seagent-plugin/src/plugin.rs) covers same set |
| ClawHub plugin marketplace | src/cli/plugins-marketplace-list-command.ts | Discover/install plugins | ⬜ | — |

## 9. Skills

SE Agent loads `SKILL.md` from `.seagent/skills`, `.claude/skills`, `.agents/skills`, `<data>/skills`, `~/.claude/skills` (crates/seagent-kernel/src/config.rs:372) and ships **no bundled skills**. OpenClaw's skills are SKILL.md + CLI wrappers, so each is "loadable if copied" but not present → ⬜ unless noted.

| item | OpenClaw source path | what it does (≤25 words) | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| Skill loading + index in prompt | src/skills, src/agents/system-prompt-skills.ts | Discover, gate (requires bins/env/os), inject | 🚧 | discovery + index (context.rs:73,112); no requirements gating/eligibility |
| Skill install from ClawHub | skills/clawhub, src/cli/skills-cli.ts | Search/install/update/publish skills | ⬜ | — |
| Skill env/API-key injection | src/skills | Per-skill env & secrets | ⬜ | — |
| 1password | skills/1password | 1Password CLI usage | ⬜ | not bundled |
| apple-notes | skills/apple-notes | Apple Notes via memo | N/A | macOS app |
| apple-reminders | skills/apple-reminders | Reminders via remindctl | N/A | macOS app |
| bear-notes | skills/bear-notes | Bear notes | N/A | macOS app |
| blogwatcher | skills/blogwatcher | RSS/blog monitoring | ⬜ | not bundled |
| blucli | skills/blucli | BluOS control | ⬜ | not bundled |
| camsnap | skills/camsnap | RTSP/ONVIF/webcam capture | ⬜ | not bundled (node camera.snap exists) |
| clawhub | skills/clawhub | ClawHub search/install | ⬜ | — |
| coding-agent | skills/coding-agent | Delegate to Codex/Claude Code/OpenCode | 🚧 | `acp_delegate` tool fills this role |
| control-ui | skills/control-ui | Operate Control UI | N/A | OpenClaw UI-specific |
| diagram-maker | skills/diagram-maker | SVG/Excalidraw diagrams | ⬜ | not bundled |
| eightctl | skills/eightctl | Eight Sleep control | ⬜ | not bundled |
| gemini | skills/gemini | Gemini CLI one-shots | ⬜ | not bundled |
| gh-issues | skills/gh-issues | Issue triage → fix agents → PRs | ⬜ | not bundled |
| gifgrep | skills/gifgrep | GIF search | ⬜ | not bundled |
| github | skills/github | gh CLI usage | ⬜ | not bundled |
| gog | skills/gog | Google Workspace CLI | ⬜ | not bundled |
| goplaces | skills/goplaces | Google Places | ⬜ | not bundled |
| healthcheck | skills/healthcheck | Host hardening audit | ⬜ | not bundled |
| himalaya | skills/himalaya | IMAP/SMTP mail CLI | ⬜ | not bundled |
| mcporter | skills/mcporter | MCP via mcporter | N/A | redundant with SE Agent native MCP |
| meme-maker | skills/meme-maker | Meme generation | ⬜ | not bundled |
| model-usage | skills/model-usage | CodexBar cost logs | N/A | macOS CodexBar app |
| nano-pdf | skills/nano-pdf | Edit PDFs | ⬜ | not bundled |
| node-connect | skills/node-connect | Diagnose node connections | N/A | OpenClaw apps-specific |
| node-inspect-debugger | skills/node-inspect-debugger | Node.js debugging | ⬜ | not bundled |
| notion | skills/notion | Notion API | ⬜ | not bundled |
| obsidian | skills/obsidian | Obsidian vaults | ⬜ | not bundled |
| openai-whisper | skills/openai-whisper | Local Whisper STT | ⬜ | not bundled |
| openai-whisper-api | skills/openai-whisper-api | Whisper API | ⬜ | not bundled |
| openhue | skills/openhue | Philips Hue | ⬜ | not bundled |
| oracle | skills/oracle | Second-model review | ⬜ | not bundled |
| ordercli | skills/ordercli | Foodora orders | ⬜ | not bundled |
| peekaboo | skills/peekaboo | macOS UI automation | N/A | macOS |
| python-debugpy | skills/python-debugpy | Python debugging | ⬜ | not bundled |
| sag | skills/sag | ElevenLabs say | ⬜ | not bundled |
| sherpa-onnx-tts | skills/sherpa-onnx-tts | Offline TTS | ⬜ | not bundled |
| skill-creator | skills/skill-creator | Author SKILL.md | 🚧 | `skill action=create` tool |
| songsee | skills/songsee | Spectrograms | ⬜ | not bundled |
| sonoscli | skills/sonoscli | Sonos control | ⬜ | not bundled |
| spike | skills/spike | Throwaway prototypes | ⬜ | not bundled |
| spotify-player | skills/spotify-player | Spotify control | ⬜ | not bundled |
| summarize | skills/summarize | Summarise URLs/videos/PDFs | ⬜ | not bundled |
| things-mac | skills/things-mac | Things 3 | N/A | macOS app |
| tmux | skills/tmux | Drive tmux panes | ⬜ | not bundled |
| trello | skills/trello | Trello API | ⬜ | not bundled |
| visualize | skills/visualize | Inline visuals / show_widget | ⬜ | needs show_widget |
| weather | skills/weather | Weather via wttr.in | ⬜ | not bundled |
| xurl | skills/xurl | X API CLI | ⬜ | not bundled |
| custodian skills (add-model-provider, cloud-image-bake, configure-channel, diagnose-gateway) | custodian-skills/ | System-agent repair skills | ⬜ | — |

## 10. Control UI (`ui/src/pages`) vs seagent web UI (`ui/web/app.js`, 427 lines)

| item | OpenClaw source path | what it does (≤25 words) | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| Chat (streaming, tool cards, attachments, markdown) | ui/src/pages/chat | Main chat | 🚧 | session.submit + log view; no attachments/tool cards/markdown rendering check |
| Sessions list / new-session | ui/src/pages/sessions, new-session | Browse/create sessions | ✅ | session.list/create (app.js) |
| Approvals / approval / question | ui/src/pages/approvals, approval, question | Pending approvals & ask_user | ✅ | gate.pending/answer |
| Model providers / model-setup | ui/src/pages/model-providers, model-setup | Configure providers & auth | 🚧 | models.list read-only |
| Channels | ui/src/pages/channels | Channel setup/status | ⬜ | — |
| Devices / device / connection | ui/src/pages/devices, device, connection | Nodes & pairing | 🚧 | node.list, node.pair.list (read-only) |
| Plugins / plugin | ui/src/pages/plugins, plugin | Plugin management + plugin pages | 🚧 | plugins.list + plugin UI panels (plugins.ui) |
| Skills / skill-workshop | ui/src/pages/skills, skill-workshop | Browse/author skills | ⬜ | — |
| Cron | ui/src/pages/cron | Manage automations | ⬜ | — |
| Usage | ui/src/pages/usage | Usage/cost dashboards | ⬜ | — |
| Config | ui/src/pages/config | Schema-driven config editor | ⬜ | — |
| Logs / debug / activity | ui/src/pages/logs, debug, activity | Logs, RPC debug, activity feed | ⬜ | — |
| Secrets | ui/src/pages/secrets | Secret store | ⬜ | — |
| Terminal | ui/src/pages/terminal | Shared terminals | ⬜ | — |
| Dashboards / apps / portals | ui/src/pages/dashboards, apps, portals | Widgets, hosted apps | ⬜ | — |
| Workboard | ui/src/pages/workboard | Kanban | ⬜ | — |
| Agents / agents-home | ui/src/pages/agents, agents-home | Multi-agent management | ⬜ | — |
| Claws / lobsterdex | ui/src/pages/claws, lobsterdex | Claw bundles / Lobster workflows | ⬜ | — |
| Memory import | ui/src/pages/memory-import | Import memories | ⬜ | — |
| Meetings | ui/src/pages/meetings | Meeting bot sessions | ⬜ | — |
| Worktrees | ui/src/pages/worktrees | Worktree management | ⬜ | — |
| Cloud workers | ui/src/pages/cloud-workers | Worker leases | ⬜ | — |
| Search | ui/src/pages/search | Global search | ⬜ | — |
| Systems / custodian / labs / about / profile | ui/src/pages/* | System status, repair agent, feature flags, profile | ⬜ | — |
| Browser view / desktop view components | ui/src/components/browser, desktop | Live browser/desktop streams | ⬜ | — |
| i18n (multiple locales) | ui/src/i18n/locales | Localised UI | 🚧 | zh/en strings in CLI/setup; web UI single language |
| Themes | ui/src/assets/themes | Theme switching | 🚧 | galaxy (default, black/navy + gold), crimson, daylight (ui/theme.css) |
| PWA install | — | Installable app | ✅ | ui/web/manifest.webmanifest, sw.js (seagent extra-ish) |

## 11. Ops: onboarding, service, doctor, update

| item | OpenClaw source path | what it does (≤25 words) | seagent status | SE Agent evidence / gap |
|---|---|---|---|---|
| Wizard: security note | src/wizard/setup.security-note.ts | Risk acknowledgement | ⬜ | — |
| Wizard: migration import (other agents) | src/wizard/setup.migration-*.ts | Import Claude/Hermes state | ⬜ | — |
| Wizard: model auth (API key / OAuth / CLI) | src/wizard/setup.model-auth.ts | Provider auth | 🚧 | API key into vault only (setup.rs) |
| Wizard: inference verification | src/wizard/setup.inference-verification.ts | Test call | ✅ | setup.rs:370 "pong" probe |
| Wizard: workspace | src/wizard/setup.workspace.ts | Choose/seed workspace | ⬜ | — |
| Wizard: gateway config + auth | src/wizard/setup.gateway-config.ts, finalize-gateway-auth.ts | Port/bind/token | 🚧 | optional web UI enable (setup.rs) |
| Wizard: service runtime install | src/wizard/setup.service-runtime.ts | Install daemon | ⬜ | separate `seagent service install` |
| Wizard: official plugins / plugin config | src/wizard/setup.official-plugins.ts, plugin-config.ts | Choose plugins | ⬜ | — |
| Wizard: channel setup | src/flows/channel-setup*.ts | Configure chat channels | 🚧 | Telegram/Discord/Slack only (setup.rs:408) |
| Wizard: web search setup | src/flows/search-setup.ts | Pick search provider | ⬜ | — |
| Wizard: memory setup / memory import | src/flows/memory-setup.ts, setup.memory-import.ts | Memory backend | ⬜ | — |
| Wizard: app recommendations / completion | setup.app-recommendations.ts, setup.completion.ts | Suggest apps, shell completion | ⬜ | — |
| Wizard i18n | src/wizard/i18n | Localised wizard | ✅ | zh/en (setup.rs `t()`) |
| Service: systemd | src/daemon/systemd* | Linux service | ✅ | main.rs:1820-1868 (+ sd_notify daemon.rs:413) |
| Service: launchd | src/daemon/launchd*.ts | macOS service | ⬜ | Linux-first |
| Service: schtasks | src/daemon/schtasks*.ts | Windows service | ⬜ | — |
| Restart-storm protection / service audit | src/daemon/restart-storm.ts, service-audit*.ts | Detect crash loops, audit unit | ⬜ | — |
| Doctor: config validation | src/flows/doctor-config-validation-*.ts | Validate config | ✅ | `seagent doctor` config check |
| Doctor: auth health | src/flows/doctor-auth-health.ts | Credential health | ✅ | model key source check |
| Doctor: gateway auth/services/exec credential | src/flows/doctor-gateway-*.ts | Gateway checks | 🚧 | daemon ping + socket path |
| Doctor: model reference check | src/flows/doctor-model-reference-check.ts | Configured models exist | 🚧 | `seagent providers check` |
| Doctor: tool schema check | src/flows/doctor-tool-schema-*.ts | Validate tool schemas per provider | ⬜ | — |
| Doctor: channel maintenance / native status / workspace / removed-state | src/flows/doctor-* | Misc checks | ⬜ | — |
| Doctor: repair flow / lint flow | src/flows/doctor-repair-flow.ts, doctor-lint-flow.ts | Auto-fix | ⬜ | — |
| Doctor: browser permissions | extensions/browser/src/doctor-browser.* | Browser readiness | ⬜ | — |
| Update mechanism (channels stable/beta/dev, npm/git, restart handoff) | src/cli/update-cli, src/infra/update* | Self-update | ⬜ | — |
| Backup + retention | src/infra/backup-*.ts | Scheduled backups | ⬜ | — |
| Logs (file logs, RPC tail) | src/logging, src/cli/logs-cli.ts | Structured logs | ⬜ | stderr only |
| Canvas host (serve widget docs, A2UI) | src/canvas, extensions/canvas/src/host | Host HTML canvases for nodes | ⬜ | — |
| Telegram mini-app Control UI | extensions/telegram/src/miniapp | UI inside Telegram | ⬜ | — |
| Docker image / compose / fly / render deploy | Dockerfile, docker-compose.yml, fly.toml, render.yaml | Deploy targets | 🚧 | Dockerfile, Nix flake, install.sh (no fly/render) |

---

## Counts

| status | count |
|---|---|
| ✅ present | 81 |
| 🚧 partial | 104 |
| ⬜ missing | 290 |
| N/A | 19 |
| **total** | **494** |

(Counts computed by script from the status column of every table row above; ✅ includes ~9 seagent-only extras (rows marked "seagent extra") listed for contrast.)

## ⬜ / 🚧 gaps ordered by user impact

1. ⬜ **web_search tool + providers** (brave/tavily/searxng/duckduckgo/perplexity/exa/…): agents cannot search the web without an MCP server.
2. ⬜ **view_image / image understanding + inbound media understanding** (images, audio transcription, video, documents on channels): attachments only land as file paths.
3. ⬜ **Sandbox (docker/podman/ssh, modes off/non-main/all, scope, workspace access)**: no isolation for untrusted channel users.
4. 🚧 **exec/process parity**: no pty, background-with-yield, stdin write/send-keys, host routing, per-binary approvals allowlist, approval forwarding to chat.
5. ⬜ **Agent-callable cron/automations tool** with delivery (announce to channel / webhook) — schedules are CLI-only and results are not delivered.
6. 🚧 **message tool** (react/poll/edit/delete/pin/thread, explicit targets) — only `channel_send` plain text.
7. 🚧 **browser tool** (managed Chrome profiles, snapshot/screenshot/pdf/upload/dialog/console, act kinds) — only CDP basics through a node.
8. ⬜ **memory_search** (semantic/hybrid, embeddings providers) and active-memory/dreaming; memory is two flat files.
9. ⬜ **Chat commands in channels**: /model, /think, /reasoning, /verbose, /usage, /compact, /reset, /name, /approve, /elevated, /exec, /queue, /context, /btw, /tools, /models, /skill, /goal, /loop, /subagents, /config.
10. ⬜ **OAuth/subscription logins** (OpenAI ChatGPT/Codex, Anthropic setup-token, GitHub Copilot device flow, Gemini CLI, MiniMax/Qwen portals) and 🚧 auth profiles/key rotation.
11. 🚧 **Background sub-agents** (sessions_spawn async, agents_wait, sessions_yield, subagents list/cancel) — spawn is synchronous only.
12. ⬜ **TTS** (tool, auto voice-note replies, 16 providers) and realtime voice/Talk.
13. ⬜ **Self-update mechanism** (`update`, /update, channels) and backup/restore.
14. 🚧 **Control UI breadth**: no config editor, channels, cron, usage, logs, skills, secrets, terminal, dashboards pages.
15. ⬜ **Multi-agent** (agents add/bind, routing bindings, agents_list) and users registry.
16. ⬜ **Heartbeat** proactive runs (active hours, delivery).
17. 🚧 **Thinking level control** outside ACP (/think, config default, per-model defaults); fast mode/service tiers.
18. ⬜ **pdf tool** and document-extract.
19. ⬜ **image_generate / video_generate / music_generate** tools and providers.
20. 🚧 **web_fetch hardening**: SSRF/private-IP block, readability extraction, caching, firecrawl fallback.
21. ⬜ **Skills ecosystem**: no bundled skills, no ClawHub install/search, no requirements gating, no skills CLI, skills not invokable as /commands.
22. ⬜ **Plugin install/marketplace** (plugins install/update/uninstall, ClawHub, consent) — only config-declared plugins.
23. 🚧 **Provider presets** for ~35 OpenClaw providers (cerebras, nvidia, huggingface, venice, vercel/cloudflare gateways, kimi-coding, z.ai intl, stepfun, qianfan…) plus ⬜ Bedrock, Vertex (Gemini/Claude), Copilot.
24. ⬜ **Session-management tools**: sessions (label/pin/archive), sessions_create, session_status, in-agent sessions_list/history/send.
25. ⬜ **security audit** CLI (fs perms, exposure, dangerous flags, plugin trust) and external-content (prompt-injection) wrapping.
26. 🚧 **Doctor depth**: no repair flow, tool-schema check, channel/gateway service audits.
27. ⬜ **Link understanding** (auto-summarise links in inbound messages).
28. ⬜ **Polls**, structured_output, decision_evaluate, llm-task, lobster workflows.
29. ⬜ **Workboard / boards / progress cards / dashboards / show_widget / canvas A2UI** (agent-visible work surfaces).
30. ⬜ **Worktrees / projects / github_publish / GitHub identity** for coding sessions.
31. ⬜ Meeting bots (Google Meet / Teams / Zoom / Slack huddles), voice_call (Twilio/Telnyx/Plivo), transcripts tool.
32. ⬜ Hooks gaps: before_prompt_build, before_model_resolve, cron/skill/install hooks; bundled hooks (session-memory, command-logger, boot-md, compaction-notifier); Gmail watcher.
33. ⬜ Logs CLI / file logging, OTel/Prometheus exporters, proxy-capture.
34. ⬜ Shell completion, `config set/patch/unset/schema`, `configure`, `reset`, `triage`, `docs`, `directory`, `dns`.
35. ⬜ Service managers launchd/schtasks; restart-storm protection.
36. ⬜ 1Password / HashiCorp Vault / exec SecretRefs; agent `secrets` request tool.
37. ⬜ Migration importers (Claude, Hermes) and onboarding steps (security note, workspace seeding, search/memory setup, plugin selection).
38. ⬜ Usage providers (quota/balance) and /usage footer.
39. ⬜ Claws bundles, system agent / openclaw delegate tool, custodian skills.
40. ⬜ Niche extensions: diffs viewer, memory-wiki, advisor, agent-guidance, logbook, team-reports, session-share, visitor-access, onepassword broker, crabbox workers, autoreview, bonjour, geolocation, Feishu workplace tools, presence, theme/screen/terminal/portal tools.
