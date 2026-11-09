# Third-party notices

SE Agent is MIT-licensed. Parts of it were ported (rewritten in Rust) from the projects
below, whose behaviour and protocols they follow. Their licenses apply to those
derived parts; the original notices are reproduced here.

## OpenClaw — MIT License

Copyright (c) 2026 OpenClaw Foundation

Ported: channel adapters (Discord, Slack, Telegram, LINE, Matrix, Mattermost, MS Teams,
Google Chat, Feishu, Signal, iMessage/imsg, IRC, Nostr, Buzz, Twitch, Nextcloud Talk,
Synology Chat, Zalo, Zalo personal, Tlon, X, ClickClack, Reef, Raft, QA channel, SMS,
WhatsApp, A2A), channel contract and access policy (DM pairing, mention gating), ACP
agent behaviour, node protocol, MCP client behaviour, `apply_patch` envelope parser and
tolerant update matcher (crates/seagent-tools/src/patchfmt.rs), `tools.fs.workspaceOnly` containment.
Also: the doctor health-check lint/repair flows and tool-schema rules (`crates/seagent/src/ops/doctor.rs`)
and the setup wizard security note (`crates/seagent/src/ops/wizard.rs`).
Also: the `triage` repair-prompt structure, limits and coding-agent handoff table
(`crates/seagent/src/ops/triage.rs`), the storage marker / `OCSTOR1` encrypted-object format
(`storage.rs`), the debug-proxy query presets and coverage report (`proxy.rs`), and the
wide-area DNS-SD zone layout (`dns.rs`).
Also: the `transcripts` tool, transcript store/summary heuristics and model-notes prompt, and
the manual transcript source (`crates/seagent-media/src/stt/transcripts/`); Deepgram STT request shape.
Also: video/music generation provider request shapes, capability tables (Kie families, DashScope Wan
geometry, Novita/Together/Z.AI/PixVerse limits) and runtime guards (`crates/seagent-media/src/video_gen/`,
`music_gen/`), media-understanding body format and inbound placeholders (`inbound/`), the
capability CLI metadata (`understand/cli.rs`), and the media-understanding provider registry —
provider ids, default models, base URLs and the image/video capability matrix for openai,
anthropic, google, openrouter, deepinfra, minimax, zai, qwen, moonshot, ollama and llama-cpp
(`crates/seagent-media/src/understand/mod.rs`, from `src/media-understanding/`, `extensions/*/media-understanding-provider.ts`
and each extension's `openclaw.plugin.json` `mediaUnderstandingProviderMetadata`).
Also: the voice-call carrier request/webhook shapes, TwiML/Plivo XML and webhook signature
algorithms (`crates/seagent-media/src/phone/`), and the meeting-bot platform URL rules and DOM
selectors for Google Meet, Teams, Zoom and Slack huddles (`crates/seagent-media/src/meeting/`).
Also: the model-provider agent harnesses — the OpenAI Agents API hosted-session flow
(`extensions/agentsapi`) and the Muse Code MSP stdio runtime (`extensions/muse`), both
`crates/seagent-model/src/agentsapi.rs` / `muse.rs`.
Also: exec safe-builtin predicate guards (`test`/`[` dynamic operands, ANSI-C quoting) and
per-provider/model exec ceilings (`crates/seagent-security/src/{approvals,toolpolicy}.rs`,
`crates/seagent-kernel/src/secgate.rs`; upstream `exec-safe-builtins.ts` and
`session-permission-exec-mode.ts`).

Also: Bedrock discovery that hides non-on-demand foundation models and lists inference
profiles (`crates/seagent-model/src/bedrock.rs`, `extensions/amazon-bedrock/discovery.ts`),
the rerank Decision provider (`crates/seagent-kernel/src/decision.rs`,
`extensions/rerank/`), the Gemini service tier mapping and the Qoder ACP preset
(`crates/seagent-model/src/gemini.rs`, `crates/seagent-app/src/acp_client.rs`).

Also: cron delivery/failure-alert defaults and room delivery (`crates/seagent-kernel/src/cronjob/`,
`crates/seagent/src/ops/rooms.rs`), the `run_stopped` hook contract (`crates/seagent-kernel/src/hooks.rs`),
scratch/idle-worktree expiry (`crates/seagent-kernel/src/scratch.rs`, `worktree.rs`), and
node-hosted MCP tool advertisement (`crates/seagent-app/src/node.rs`).

Also: the approvals console's standing-grant rows/history and the security posture page
(`ui/web/ops.js`, `crates/seagent/src/ops/ui_methods.rs`), following
`ui/src/pages/approvals/*` and `ui/src/pages/config/security*`.

## Hermes Agent — MIT License

Copyright (c) 2025 Nous Research

Ported: platform adapters (Telegram, Discord, Slack, WhatsApp bridge and Cloud API,
Signal, Matrix, Mattermost, Email, SMS, DingTalk, Feishu, WeCom, WeCom callback, Weixin,
QQ Bot, Yuanbao, BlueBubbles, Photon, Google Chat, Teams, LINE, IRC, ntfy, SimpleX, Buzz,
Raft, A2A, webhook ingress, MS Graph webhook, relay), the OpenAI-compatible API server,
delivery ledger, pairing store, MCP OAuth/sampling/elicitation behaviour, ACP adapter,
file tools: fuzzy find-and-replace strategies (including the read-tool `N|` gutter recovery) and
escape-drift correction (crates/seagent-tools/src/fuzzy.rs),
checkpoint-store hardening (home/browser-profile refusals, store self-exclusion, excluded-path
size caps, rollback that never rewinds the store; `crates/seagent-kernel/src/checkpoint.rs`, from
`tools/checkpoint_manager.py`),
V4A patch parser (patchfmt.rs), document extraction (extract.rs), read tracking / file-state
registry / write guards / binary-extension lists (filestate.rs), post-write lint (lint.rs).
`bridges/whatsapp/` and `bridges/photon/` contain Hermes sidecar sources (see
`LICENSE.hermes` in each directory).
Also transcribed: the LSP server registry and diagnostics report format (`agent/lsp`,
`crates/seagent-tools/src/lsp.rs`), the verify recipe tables and runner (`agent/verify`, itself
ported from superagent-ai/grok-cli, MIT; `crates/seagent-kernel/src/verify.rs`), the `/init` and
`/plan` prompt texts and the reaction lexicon (`crates/seagent-kernel/src/devprompts.rs`,
`reactions.rs`).
Also transcribed: the FAL video family table and payload rules, xAI edit/extend and
`video_analyze` prompts/limits/error texts (`crates/seagent-media/src/video_gen/hosted.rs`,
`understand/mod.rs`), inbound voice-note markers (`inbound/mod.rs`).
Also: the expanded secret redaction patterns for database connection strings, client env
variables, URL userinfo, non-PEM private keys, Azure keys/SAS, quoted YAML/JSON values and
command-line flags (`crates/seagent-security/src/risk.rs`, from `agent/redact.py` and
`agent/redact_connstr.py`).
Transcribed data: the optional-mcps catalog (`crates/seagent/src/mcp_presets.json`, 65 vendor MCP
manifests), the session-export HTML template and Lucide-style icons
(`crates/seagent/src/export_template.html`, `export_icons.rs`), and the trajectory system prompt
(`crates/seagent-kernel/src/trajectory.rs`).
Ops ports (`crates/seagent/src/ops/`): external secret sources (`secretsrc.rs`, from
`agent/secret_sources`), the toolset distribution table and batch runner (`batch.rs`), the
mini-SWE runner prompts (`miniswe.rs`) and the trajectory compressor summary prompt
(`trajcomp.rs`).
Also: approval provenance lines in tool results, per-finding command consent (an approved
pipe-to-shell rule never hides a credential upload), PowerShell/wmic/Stop-Process approval
rules and the stdio MCP consent line (`crates/seagent-kernel/src/secgate.rs`,
`crates/seagent-security/src/risk.rs`, `crates/seagent/src/mcp_cli.rs`).
Also: the `dump` / `debug share` report layout, paste upload/auto-delete flow (`debugdump.rs`),
the safe console command engine (`console.rs`), worktree audit/prune/restore rules
(`worktree.rs`), the projects store (`project.rs`) and the multiplex preflight (`multiplex.rs`).
Also: idle-session retirement (`crates/seagent-kernel/src/kernel.rs`), busy-arrival metrics
(`crates/seagent-app/src/metrics.rs`), importer credential opt-in (`crates/seagent/src/ops/migrate.rs`)
and opt-in plugin auto-update (`crates/seagent-skills/src/hub/plugins.rs`).
Terminal UX ports (`crates/seagent-app/src/tui/`, `crates/seagent/src/ops/rooms.rs`): the built-in skin
palettes, branding and spinner tables (`skins.json`, from `hermes_cli/skin_engine.py`), the
petdex pet geometry/state taxonomy and sprite-generation prompts (`pets.rs`, from `agent/pet`),
the kaomoji busy-indicator faces (`indicator.rs`, from ui-tui), the rewind picker (`rewind.rs`,
from `ui-tui/src/components/rewindPicker.tsx` and `canonicalRewindPicker.ts`), inline transcript
images (`image.rs`, from `agent/terminal_image.py` / `hermes_cli/cli_inline_images.py`), large-paste
collapse (`paste.rs`, from `ui-tui/src/components/pasteSections.tsx` / `domain/pasteExpand.ts`),
and the hosted-room Discussion policy and member prompt (`rooms.rs`, from
`gateway/hosted_room_discussion.py`).
`/handoff` and `/undo`'s changed-files/checkpoint pointer (`crates/seagent/src/agentcmds/handoff.rs`,
`crates/seagent/src/slash.rs`) follow `hermes_cli/commands.py` and `tools/checkpoint_undo_hint.py`.
Media speech ports (`crates/seagent-media/src/stt/`, `voice/`): the STT provider dispatch,
chunking and whisper.cpp model pins (URLs + SHA-256), the faster-whisper anti-hallucination
settings, the Whisper hallucination phrase list, stop-phrase and TTS-echo guards, voice-mode
silence/barge-in state machines and the wake-word engine wrappers.
Media TTS ports (`crates/seagent-media/src/tts/{tool,commands,prefs,stream}.rs`): the
`text_to_speech` / `talk_voice` tool schemas and provider/voice resolution, the `/tts` and
`/voice` command texts and subcommand sets, the auto-reply policy
(`off|always|inbound|tagged`, length caps, voice-bubble formatting), the per-chat
`/tts chat` / `/voice tts` modes (`off|voice_only|all`, Hermes `gateway/run_voice.py`), and
the sentence-chunked streaming reader (Hermes `tools/tts_tool*.py`, `hermes_cli/commands.py` +
`cli_voice_mixin.py`; OpenClaw `src/agents/tools/tts-tool.ts`, `src/tts/`,
`extensions/talk-voice`, `src/auto-reply/commands-registry*`).
The `/image <path> [prompt]` path/prompt split in `crates/seagent-app/src/clip.rs`
(`split_path_input`) is Hermes `hermes_cli/cli_terminal_input.py::_split_path_input`.
Also: the OpenAI Daybreak opt-in on the Codex subscription route (`crates/seagent-model/src/responses.rs`,
`crates/seagent-kernel/src/config.rs`, from `agent/codex_service_tiers.py`).
Browser/desktop control ports (`crates/seagent-browser/src/control*`): the `/browser` command texts and
system notes, the Bot Desktop launcher script (`control/launcher.sh`, from
`tools/bot_desktop/launcher.sh`), package tables and the cua-driver runtime contract / release pins.
Also: the sandbox-browser container image (`packaging/sandbox-browser`: Dockerfile, entrypoint plus
the Basic-auth CDP relay, from OpenClaw `scripts/docker/sandbox/Dockerfile.browser` and
`scripts/sandbox-browser-entrypoint.sh`) and the bundled browser extension
(`ui/browser-extension`, from `extensions/browser/chrome-extension`).
Also: browser snapshot masking of password, one-time-code and card field values
(`crates/seagent-browser/src/snapshot.rs`, from `extensions/browser/src/browser/sensitive-field-values.ts`)
and the strict-SSRF navigation redirect-hop fence (`crates/seagent-browser/src/{policy,engine,tools}.rs`,
from `navigation-guard.ts` / the Playwright navigation fence).

Also: the delegation prompt-cache warm-up gate (`crates/seagent-kernel/src/subagents.rs`,
from `tools/delegate_tool_prefix_gate.py`), the bot-to-bot chain hop/dedupe/notify-only
rules (`crates/seagent-kernel/src/coord.rs`, from `agent/bot_chain.py`) and hosted-room
lead/auto routing plus Continue (`crates/seagent/src/ops/rooms.rs`, from
`gateway/hosted_room_lead.py`, `hosted_room_router.py` and `hosted_room_context.py`).

## DeepSeek Harness — MIT License

Copyright (c) 2026 DeepSeek

Ported: the DeepSeek Messages route shape (Anthropic-compatible `/v1/messages`, `x-api-key`,
`thinking` plus `output_config.effort`; `crates/seagent-model/src/{catalog,anthropic}.rs`) and
per-step statistics (time to first token, output speed, model vs tool time, per-step cache hit
rate; `crates/seagent-kernel/src/{event,kernel}.rs`, `crates/seagent/src/agentcmds/sessions.rs`).

Ported ideas (rewritten in Rust): compaction that replays the routed request's system prompt,
tools and shadowed-region messages byte for byte and appends only a trailing summary instruction
(`crates/seagent-kernel/src/compaction.rs`, from `packages/compaction/compaction-basic`), and
pressure-gated tool-result pruning (`crates/seagent-kernel/src/context.rs`,
`packages/compaction/compaction-tool-result-pruner`). The exact-request session-log events follow
`packages/core/agent-loop` and `docs/architecture.md` ("model-visible means logged").

Ported: the provider record/replay layer (`crates/seagent-model/src/replay.rs`, from
`packages/test-support/llm-replay` and `session-snapshot`), including exact-request fixture
matching, recorded stream deltas and recorded provider errors. The persistent SSH session
(`crates/seagent-tools/src/exec/ssh.rs`) follows the remote execution environment idea in
`packages/ssh/*` (one long-lived remote shell over a multiplexed connection).

Ported: the fork child's byte-identical parent prefix (no child system section or tool
list edit; guidance in the first user message, restrictions enforced at execution time —
`crates/seagent-kernel/src/subagents.rs`, from `packages/subagent/subagent-fork-in-process`)
and the fresh-context Ralph round loop with a bounded structured handoff and progress
file (`crates/seagent-kernel/src/subagents.rs`, from
`packages/experimental/tool-ralph`).

## libdave — MIT License

Copyright (c) 2024 Discord

Ported: DAVE key fingerprints, pairwise verification fingerprints, displayable codes and
the generic persisted signature key format (`crates/seagent-channel/src/dave.rs`), with
libdave's JS test vectors.

The full MIT license text:

> Permission is hereby granted, free of charge, to any person obtaining a copy of this
> software and associated documentation files (the "Software"), to deal in the Software
> without restriction, including without limitation the rights to use, copy, modify,
> merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
> permit persons to whom the Software is furnished to do so, subject to the following
> conditions:
>
> The above copyright notice and this permission notice shall be included in all copies
> or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
> INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
> PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
> HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
> CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
> THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## WHATWG Encoding Standard index data — BSD 3-Clause License

Copyright © WHATWG (Apple, Google, Mozilla, Microsoft).

`crates/seagent-channel/data/` (Big5, gb18030, jis0208, jis0212, EUC-KR, gb18030 ranges, the
single-byte indexes and the encoding labels) is generated by `tools/gen_charset_tables.py`
from https://encoding.spec.whatwg.org/ index files; `crates/seagent-channel/src/charset.rs`
implements that standard's decoder algorithms.

> Redistribution and use in source and binary forms, with or without modification, are
> permitted provided that the following conditions are met:
>
> 1. Redistributions of source code must retain the above copyright notice, this list of
>    conditions and the following disclaimer.
> 2. Redistributions in binary form must reproduce the above copyright notice, this list
>    of conditions and the following disclaimer in the documentation and/or other
>    materials provided with the distribution.
> 3. Neither the name of the copyright holder nor the names of its contributors may be
>    used to endorse or promote products derived from this software without specific
>    prior written permission.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
> EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
> MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
> THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
> SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
> OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
> INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
> LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
> OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Anthropic claude-plugins-official — Apache License 2.0

The `security-guidance` rule table (`crates/seagent-security/src/guidance.rs`: 25 rule names,
regex/substring triggers, file gates and reminder texts) is transcribed verbatim from
`plugins/security-guidance/hooks/patterns.py` in
https://github.com/anthropics/claude-plugins-official (commit `0bde168`, 2026-05-26), as forked by
Hermes `plugins/security-guidance` (MIT). The plugin glue (scan/dedup/format, warning block
wording and the `SECURITY_GUIDANCE_DISABLE` / `SECURITY_GUIDANCE_BLOCK` switches) follows Hermes'
`__init__.py`, MIT.

> Copyright (c) Anthropic, PBC. and the security-guidance contributors
> Licensed under the Apache License, Version 2.0 (the "License"); you may not use those files
> except in compliance with the License. You may obtain a copy of the License at
> http://www.apache.org/licenses/LICENSE-2.0
>
> Unless required by applicable law or agreed to in writing, software distributed under the
> License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
> either express or implied. See the License for the specific language governing permissions and
> limitations under the License.

## Noto Sans TC (Linux AppImage only) — SIL Open Font License 1.1

Copyright 2014-2021 Adobe (http://www.adobe.com/), with Reserved Font Name 'Source'.

The Linux AppImage of the desktop app bundles `NotoSansTC-VF.ttf` (Noto Sans CJK version 2.004,
`Sans/Variable/TTF/Subset/` of https://github.com/googlefonts/noto-cjk at commit `523d033`, tag
`Sans2.004`; SHA-256 `ac091cc8cd19e848202afc8fe6d3809b4526c8fdbdb4be82da20c4f785949591`), unmodified,
as `usr/share/seagent-desktop/fonts/NotoSansTC-VF.ttf`. The full license text ships next to it as
`OFL.txt` (in the repository: `apps/desktop/src-tauri/fonts/OFL.txt`). The font is fetched at build
time by `apps/desktop/scripts/fetch-cjk-font.sh`; it is not part of the agent or the other installers.

## Rust crates

serde, serde_json, toml, ureq, regex, libc, rustls, ring, webpki-roots, base64 and their
dependencies — MIT and/or Apache-2.0 (webpki-roots: CDLA-Permissive-2.0; ring: ISC-style
plus OpenSSL/BoringSSL notices). Run `cargo tree --format "{p} {l}"` for the full list.

Also: the Tavily plugin's dedicated tools and the GitHub plugin, ported to Rust
(`crates/seagent-tools/src/web/vendor_tools.rs`, `crates/seagent-tools/src/web/github.rs`,
`crates/seagent/src/web_cli.rs`, the `search-setup` step in `crates/seagent/src/setup.rs`):
`extensions/tavily` (both tool schemas, argument validation, the per-tool key errors and the
score / published / answer / failed-URL shaping) and `extensions/github` (`github_read` /
`github_search` schemas, target and search-parameter validation, the reader document with its
33 KiB / 20-comment / 30-file / 100-check limits, PR checks and the bounded job-log tail, and
the API error text) — MIT.

Also: partial ("up to here") compaction, the `/recap` command and OpenAI server-side compaction
(`crates/seagent/src/ops/partial.rs`, `crates/seagent/src/ops/recap.rs`, `crates/seagent-model/src/native_compact.rs`)
are ports of Hermes `hermes_cli/partial_compress.py` + `agent/conversation_compression_manual.py`,
`hermes_cli/session_recap.py` and `agent/native_compaction.py` (argument parsing and limits, the
preview report wording, the recap line layout and preview/escape limits, the native-compaction
eligibility gates, threshold clamp and rejection detection) — MIT.

Also: the Google Meet bot and the Microsoft Teams meeting pipeline
(`crates/seagent/src/meetings/{mod,meet,meet_bot,fakecdp}.rs` and
`crates/seagent/src/meetings/teams/{mod,cli,graph,meetings,models,pipeline,sinks,store,subs}.rs`)
are ports of Hermes `plugins/google_meet` (the `meet_*` tool schemas and messages, the
`--json` CLI, the caption observer JS, the say-queue lock, the session-end cleanup and the
lobby/duration exit reasons) and Hermes `plugins/teams_pipeline` with `tools/microsoft_graph_auth.py`
and `tools/microsoft_graph_client.py` (Graph resource-path parsing, meeting/transcript/recording
resolution, the durable job store buckets and timestamps, the pipeline states and retry classes,
the summary prompt/JSON/heuristic rendering, the Notion/Linear writers, subscription maintenance
and the operator CLI) — MIT.

Also: send-path image preparation (`crates/seagent-kernel/src/imgprep.rs`: the conditional block
ceiling with the 2000 px many-image dimension probe, the batch/floor retire-count step function,
the byte budget, the latched retire set, and the non-vision text stand-in wording) is a port of
Hermes `agent/image_eviction_policy.py` and `agent/vision_message_prep.py` — MIT.

Also: the i18n engine and its catalogs (`crates/seagent-kernel/src/i18n.rs`,
`crates/seagent-kernel/locales/*.json` and the alias / endonym tables) are a port of Hermes
`agent/i18n.py`, `agent/i18n_layers.py` and `agent/i18n_languages.py` (the layer order, language
resolution, alias map, fallback chain and format-argument behaviour) — MIT.

Also: the context host (`crates/seagent-kernel/src/ctxhost.rs` and `crates/seagent-kernel/src/ctxhost/`:
`/context`, `/compact`/`/compress`, `/title`, `/btw`, `/personality`, the background title
generator, SOUL.md seeding, the coding-posture segment and the local toolchain probe) ports
Hermes `hermes_cli/commands.py`, `hermes_cli/partial_compress.py`, `agent/title_generator.py`,
`agent/side_question.py`, `agent/coding_context.py`, `hermes_cli/personality.py`,
`hermes_cli/default_soul.py` and `tools/env_probe.py` (the argument parsing and limits, the
derived/model title stages with their echo and answer-shaped guards, the side-question prompt
and transcript budgets, the personality table, the SOUL.md seed/upgrade rules, the code-workspace
markers and the bounded probe) — MIT.

## Bundled skill corpus — transcribed from Hermes and OpenClaw (MIT)

The Markdown skills shipped under `share/skills/**` and the optional-skills catalog under
`share/optional-skills/index.json` are transcribed or adapted from two MIT-licensed projects.
Each `SKILL.md` carries its origin in the front-matter:

```yaml
upstream: "<repo>/<path> (MIT)"          # verbatim transcription
upstream: "<repo>/<path> (MIT) — adapted for seagent"   # rewritten for seagent's own surfaces
```

Source corpora and what was taken from each:

- **`hermes-agent/skills/**`** (Hermes Agent, NousResearch, MIT) — 55 bundled skills transcribed
  verbatim into `share/skills/<category>/<name>/` together with their `references/`, `scripts/`,
  `templates/` and `assets/` trees, plus two adapted ports
  (`share/skills/autonomous-ai-agents/seagent-agent/` from `autonomous-ai-agents/hermes-agent`, and
  `share/skills/software-development/seagent-skill-authoring/` from
  `software-development/hermes-agent-skill-authoring`). One upstream skill,
  `software-development/inspecting-hermes-desktop-dom`, is **not** transcribed: it documents the
  Hermes Electron desktop app (its dev-server CDP port, `HERMES_DESKTOP_*` variables and
  `data-slot` selectors), which SE Agent does not ship.
- **`hermes-agent/optional-skills/**`** (MIT) — 153 skills are **not vendored**: only the catalog
  `share/optional-skills/index.json` (name, path, description, tags, file list) ships, and the
  content is fetched from the upstream repository on demand by the hub's `official` source.
- **`openclaw/skills/**`** (OpenClaw Foundation, MIT) — 38 skills transcribed verbatim into
  `share/skills/openclaw/` (and the matching category when a Hermes skill of the same name
  already existed). Where both projects ship a skill under the same name (`apple-notes`,
  `apple-reminders`, `github`, `himalaya`, `node-inspect-debugger`, `notion`, `obsidian`,
  `python-debugpy`, `songsee`, `spike`, `xurl`),
  the file carries the Hermes body plus the complete upstream OpenClaw procedure appended
  verbatim under the heading `## OpenClaw procedure (upstream openclaw/skills/<name>, MIT, verbatim)`.
  The macOS-only skills (`apple-notes`, `apple-reminders`, `bear-notes`, `things-mac`,
  `peekaboo`, `model-usage`) are transcribed too, with a `## Platform note` / `## Prerequisites`
  section stating the macOS + binary requirement. Two more are transcribed with their launch
  surface adapted to seagent's `job` / `process` tools: `openclaw/skills/coding-agent` →
  `share/skills/openclaw/coding-agent/` and `openclaw/skills/skill-creator` →
  `share/skills/openclaw/skill-creator/`. skill-creator's upstream `scripts/`
  (`quick_validate.py`, `package_skill.py`) are **Apache-2.0**, Copyright Anthropic, and are
  **not** vendored: `seagent skills lint` and `skill action=workshop operation=validate` replace them.
- **`openclaw/custodian-skills/**`** (MIT) — all four skills (`add-model-provider`,
  `cloud-image-bake`, `configure-channel`, `diagnose-gateway`) transcribed verbatim into
  `share/skills/custodian/`.

Text inside these skills remains under the upstream MIT licences:

- Hermes Agent — MIT, Copyright (c) 2025 Nous Research (see `LICENSE` in the
  `hermes-agent` repository).
- OpenClaw — MIT, Copyright (c) 2026 OpenClaw Foundation.

The Rust code that loads, indexes, gates, syncs and installs these skills
(`crates/seagent-skills/**`) is a port of the same two projects' skill systems and is covered by the
notices above; the catalog files `share/optional-mcps/index.json` and
`share/plugin-catalog/index.json` and `share/blueprints.json` are likewise generated from
Hermes' `optional-mcps/`, `plugin-catalog/` and `cron/blueprint_catalog.py`.

Also: the skills system (`crates/seagent-skills/src/core/{index,preprocess,setup,invoke,slash,skilltool}.rs`,
`crates/seagent-skills/src/skill.rs`) is a port of Hermes `agent/skills_index_delta.py` (the note prefix,
added/removed heads, `accurate again` wording, `: ` row split and the no-index/no-note rule),
`agent/skill_preprocessing.py` (`${HERMES_*}`/`${SEAGENT_*}` tokens, single-line `` !`cmd` `` snippets,
the 4000-character inline-shell cap and the `[inline-shell …]` markers, community-hub provenance
gate), `agent/skill_commands.py` (activation note, stacked/bundle scaffold headers, the 5-skill
stack limit, core-command collision note), `tools/skills_tool.py` (`skill_view` payload: rendered
content, `[Skill config …]` block with declared defaults and `(not set)`, setup note, supporting
files), `tools/skills_tool_setup.py` (`missing env $NAME` note, readiness merge rules),
`tools/env_passthrough.py` (registered names, provider-credential refusal), `tools/skills_tool_plugin.py`
(`plugin:skill` discovery and qualified names) and `hermes_cli/commands.py` (`/skills` delegating to
the hub CLI); plus OpenClaw `src/skills/runtime/env-overrides.ts` (`skills.entries.*.env`/`apiKey`
injection: an externally managed value wins, dangerous names stay blocked) — MIT.

Also: the skill library maintenance modules (`crates/seagent-skills/src/core/{curator,cli,settings,bundles,blueprints,ledger,usage,lint}.rs`) are ports of Hermes `agent/curator.py`, `agent/curator_backup.py`, `hermes_cli/curator.py`, `hermes_cli/bundles.py`, `agent/skill_bundles.py`, `tools/blueprints.py`, `cron/blueprint_catalog.py`, `tools/skill_ledger.py`, `tools/skill_usage.py` and `tools/skill_linter.py` (the lifecycle states and gates, the review prompt and report layout, the snapshot/rollback layout and keep bound, the CLI subcommand sets and messages, the bundle YAML shape and `/`+bundle invocation text, the blueprint catalog slot schema and job-spec mapping, the content-addressed ledger with delta entries and blob GC, and every linter rule, severity and message) — MIT.

Also: the skills security scanner (`crates/seagent-security/src/skills_guard.rs`) is a port of Hermes `tools/skills_guard.py` (the 134-rule threat table and its severities, the trust × verdict `INSTALL_POLICY`, the `.skillignore`/`.clawhubignore` matcher, the structural limits and the report/summary layout, `skills-guard-v10`), with Hermes home paths (`.hermes/config.yaml`, `.hermes/SOUL.md`, `~/.hermes/.env`) mapped to seagent's (`~/.config/seagent/config.toml`, workspace `SOUL.md`, `~/.config/seagent/secrets.toml`); the advisory NVIDIA SkillEvaluator wrapper (`crates/seagent-skills/src/hub/evaluator.rs`) ports `tools/skillevaluator_scan.py` (argv, `-o` report file, timeout, tier ordering, red credential line); and the Python dynamic-import deep audit (`crates/seagent-skills/src/hub/ast_audit.rs`) ports `tools/skills_ast_audit.py` — MIT.

Also: the hub registry adapters (`crates/seagent-skills/src/hub/{sources,http}.rs`) port Hermes `tools/skills_hub_{official,github,clawhub,skillssh,sources,search}.py` (catalog ranking, tap provider labels, GitHub rate-limit/backoff and 401-reject handling, ClawHub exact-slug resolution and owner guards, skills.sh id discovery, well-known/browse.sh/LobeHub metadata, the SSRF/redirect policy) and the install/search layer (`crates/seagent-skills/src/hub/{install,cli,model,zip,sync}.rs`) ports `tools/skills_hub{,_install,_models}.py`, `hermes_cli/skills_hub.py`, `hermes_cli/subcommands/skills.py`, `tools/skills_sync*.py` and OpenClaw `src/skills/lifecycle/clawhub*.ts` / `src/infra/clawhub-spec.ts` (ClawHub `@version` pinning) — MIT.

Also: the plugin lifecycle and built-in plugins (`crates/seagent-plugin/src/builtin/*.rs`) are ports of Hermes
`plugins/disk-cleanup/{__init__.py,disk_cleanup.py}` (tracked.json atomic write + `.bak` restore, the
test/temp/cron-output reseating rules, the prompt-only research/chrome-profile/500 MB buckets, the
HERMES_HOME + `/tmp/hermes-*` scope mapped to seagent's data home + `/tmp/seagent-*`, `cleanup.log` line
formats, `/disk-cleanup` subcommands and help text), Hermes `plugins/security-guidance/{__init__.py,
patterns.py}` (the 25 rules with Anthropic PBC's `claude-plugins-official`
`plugins/security-guidance/hooks/patterns.py` pattern data and reminder text, Apache-2.0, forked by
NousResearch; the warn/block modes and the `⚠️ Security guidance` block) and Hermes
`plugins/hermes-achievements` (`dashboard/plugin_api.py`; MIT, originally by @PCinkusz, vendored in
hermes-agent — the 60-achievement catalog with stable ids, the per-session metrics, the tiered and
multi-condition evaluation, `state.json`/`scan_checkpoint.json`/`scan_snapshot.json` layout and the
`/achievements` payload shape). The plugin stream hooks in `crates/seagent-plugin/src/stream.rs` follow
Hermes `agent/plugin_stream_hooks.py` + `agent/stream_delivery.py` (the `on_stream_start`/
`on_stream_delta`/`on_stream_end` observer names and payload fields, the per-consumer 1024-event
drop-oldest queue that keeps plugin code off the token path, and the opt-in reasoning deltas) — MIT.

Also: `tokenjuice` (`crates/seagent-tools/src/tokenjuice/`) is a port of tokenjuice 0.8.5 (MIT,
github.com/vincentkoc/tokenjuice) as vendored by OpenClaw `extensions/tokenjuice`: the reducer
families (table/search/diff/log/JSON/JSONL), their thresholds (240-char floor, budget/min-gain
ratios), the verbatim-command list and the `[tokenjuice …]` completeness markers — MIT.

Also: the ACP runtime (`crates/seagent-model/src/acp.rs`) is a port of Hermes
`agent/copilot_acp_client.py` + `agent/acp_openai_bridge.py` (the ACP v1 handshake, the
`session/set_config_option` / legacy `session/set_model` model selection, `session/prompt`
streaming updates, the `fs/read_text_file` / `fs/write_text_file` / `session/request_permission`
server→client answers and the deprecated `gh copilot` banner check) — MIT.

Also: per-task auxiliary routing (`crates/seagent-model/src/aux.rs`) follows Hermes
`agent/auxiliary_task_config.py` (route keys travel as one unit) and `agent/auxiliary_health.py`
(the `_FALLBACK_REASONS` classes and their quarantine TTLs); the Nous Portal agent-key slots
(`crates/seagent-model/src/nous.rs`) follow `hermes_cli/auth_nous.py` (`_set_nous_agent_key_from_invoke_jwt`,
`_nous_invoke_jwt_status`, `_agent_key_is_usable`, `_unusable_invoke_jwt_error`) and the
context-length pin (`crates/seagent-model/src/contextpin.rs`) follows `agent/context_pin.py` — MIT.
